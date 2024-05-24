# 精通 JavaScript（一）

> 原文：[`zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3`](https://zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

似乎已经写下了所有需要关于 JavaScript 的东西。坦白说，要找到一个关于 JavaScript 还没有被详尽讨论的话题是困难的。然而，JavaScript 正在迅速变化。ECMAScript 6 有潜力改变这门语言以及我们用它编写的代码方式。Node.js 已经改变了我们用 JavaScript 编写服务器的方式。像 React 和 Flux 这样的新想法将推动语言的下一轮迭代。虽然我们花时间学习新特性，但不可否认的是，必须掌握 JavaScript 的基础理念。这些理念是基础且需要关注。如果你已经是一个有经验的 JavaScript 开发者，你会意识到现代 JavaScript 与大多数人所知的那门语言大相径庭。现代 JavaScript 要求特定的风格纪律和思维的严谨性。工具变得更加强大，并逐渐成为开发工作流程的一个重要组成部分。尽管语言似乎在变化，但它建立在一些非常坚实且恒定的理念之上。这本书强调的就是这些基本理念。

在撰写这本书的过程中，JavaScript 领域的很多事情都在不断变化。幸运的是，我们成功地在这本书中包括了所有重要的相关更新。

《精通 JavaScript》为你提供了对语言基础和一些现代工具和库（如 jQuery、Underscore.js 和 Jasmine）的详细概述。

我们希望你能像我们享受写作一样享受这本书。

# 本书内容概览

第一章，*JavaScript 入门*，专注于语言构造，而不花太多时间在基本细节上。我们将涵盖变量作用域和循环的更复杂部分以及使用类型和数据结构的最佳实践。我们还将涵盖大量的代码风格和推荐的代码组织模式。

第二章，*函数、闭包和模块*，涵盖了语言复杂性的核心。我们将讨论使用函数方面以及在 JavaScript 中对待闭包的不同处理方法的复杂性。这是一个谨慎且详尽的讨论，将为你进一步探索更高级的设计模式做好准备。

第三章，*数据结构及其操作*，详细介绍了正则表达式和数组。数组是 JavaScript 中的一个基本数据类型，本章将帮助你有效地使用数组。正则表达式可以使你的代码简洁—我们将详细介绍如何在你的代码中有效地使用正则表达式。

第四章《面向对象的 JavaScript》，讨论了 JavaScript 中的面向对象。我们将讨论继承和原型链，并专注于理解 JavaScript 提供的原型继承模型。我们还将讨论这个模型与其他面向对象模型的不同之处，以帮助 Java 或 C++ 程序员熟悉这种变化。

第五章《JavaScript 模式》，讨论了常见的设计模式以及如何在 JavaScript 中实现它们。一旦你掌握了 JavaScript 的面向对象模型，理解设计和编程模式就会更容易，写出模块化且易于维护的代码。

第六章《测试与调试》，涵盖了各种现代方法来测试和调试 JavaScript 代码中的问题。我们还将探讨 JavaScript 的持续测试和测试驱动方法。我们将使用 Jasmine 作为测试框架。

第七章《ECMAScript 6》，专注于由 ECMAScript 6 (ES6) 引入的新语言特性。它使 JavaScript 更加强大，本章将帮助你理解新特性以及如何在代码中使用它们。

第八章《DOM 操作与事件》，详细探讨了 JavaScript 作为浏览器语言的部分。本章讨论了 DOM 操作和浏览器事件。

第九章《服务器端 JavaScript》，解释了如何使用 Node.js 在 JavaScript 中编写可扩展的服务器系统。我们将讨论 Node.js 的架构和一些有用的技术。

# 本书你需要什么

本书中的所有示例都可以在任何现代浏览器上运行。对于最后一章，你需要 Node.js。为了运行本书中的示例和样本，你需要以下先决条件：

+   安装有 Windows 7 或更高版本、Linux 或 Mac OS X 的计算机。

+   最新版本的 Google Chrome 或 Mozilla Firefox 浏览器。

+   你选择的文本编辑器。Sublime Text、vi、Atom 或 Notepad++ 都是理想的选择。完全由你决定。

# 本书适合谁

本书旨在为你提供掌握 JavaScript 的必要细节。本书将对以下读者群体有用：

+   有经验的开发者，熟悉其他面向对象语言。本书的信息将使他们能够利用现有的经验转向 JavaScript。

+   有一定经验的 Web 开发者。这本书将帮助他们学习 JavaScript 的高级概念并完善他们的编程风格。

+   初学者想要理解并最终掌握 JavaScript。这本书为他们提供了开始所需的信息。

# 约定

在这本书中，您会发现有一些文本样式用于区分不同类型的信息。以下是一些这些样式的示例及其含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理方式如下所示："首先，`<head>`中的`<script>`标签导入了 JavaScript，而第二个`<script>`标签用于嵌入内联 JavaScript。"

代码块如下所示：

```js
function sayHello(what) {
  return "Hello " + what;
}
console.log(sayHello("world"));
```

当我们要引您注意代码块中的某个特定部分时，相关的行或项目会被加粗：

```js
<head>
 <script type="text/javascript" src="img/script.js"></script>
 <script type="text/javascript">
 var x = "Hello World";
 console.log(x);
 </script>
</head>
```

任何命令行输入或输出都如下所示：

```js
EN-VedA:~$ node
> 0.1+0.2
0.30000000000000004
> (0.1+0.2)===0.3
false

```

**新术语** 和 **重要词汇** 以粗体显示。例如，在菜单或对话框中看到的屏幕上的词，会在文本中这样显示："You can run the page and inspect using Chrome's **Developer Tool**"

### 注意

警告或重要说明以这样的盒子出现。

### 提示

技巧和建议以这样的形式出现。

# 读者反馈

读者对我们书籍的反馈总是受欢迎的。让我们知道您对这本书的看法——您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它帮助我们开发出您会真正从中受益的标题。

要发送给我们一般性反馈，只需电子邮件 `<feedback@packtpub.com>`，并在您消息的主题中提到书的标题。

如果您在某个主题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经成为 Packt 图书的自豪拥有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 的账户上下载本书中的示例代码文件，您购买的 Packt Publishing 所有的书籍都可以。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 注册，以便将文件直接通过电子邮件发送给您。

## 下载本书彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕快照/图表的彩色图片。这些彩色图片将帮助您更好地理解输出中的变化。您可以从 [`www.packtpub.com/sites/default/files/downloads/MasteringJavaScript_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/MasteringJavaScript_ColorImages.pdf) 下载这个文件。

## 勘误

虽然我们已经尽一切努力确保我们内容的准确性，但错误确实会发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——我们将非常感激如果您能向我们报告。通过这样做，您可以节省其他读者不必要的挫折，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误提交表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分已有的错误列表中。

要查看之前提交的错误，请前往 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support) 并在搜索框中输入书籍名称。所需信息将在**错误**部分出现。

## 盗版

互联网上的版权材料盗版是一个持续存在的问题，涉及所有媒体。在 Packt，我们非常严肃地对待我们版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，这样我们可以寻求一个补救措施。

如果您发现可疑的盗版材料，请联系我们 `<copyright@packtpub.com>`并提供链接。

我们感激您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在这本书的任何方面遇到问题，您可以通过 `<questions@packtpub.com>` 联系我们，我们会尽最大努力解决问题。


# 第一章：JavaScript 简介

编写文章的起初几句话总是困难的，尤其是在谈论像 JavaScript 这样的主题时。这种困难主要源于人们对这门语言已经有了太多的说法。自从 Netscape Navigator 的早期阶段以来，JavaScript 就一直是*网络的语言*——如果你愿意，可以说是互联网的通用语。JavaScript 从业余爱好者的工具迅速转变为鉴赏家的武器。

JavaScript 是网络和开源生态系统中最受欢迎的语言。[`githut.info/`](http://githut.info/) 图表记录了过去几年中 GitHub 上活跃仓库的数量以及该语言的整体受欢迎程度。JavaScript 的流行和重要性可以归因于它与浏览器的关联。Google 的 V8 和 Mozilla 的 SpiderMonkey 是分别驱动 Google Chrome 和 Mozilla Firefox 浏览器的极度优化的 JavaScript 引擎。

尽管网络浏览器是 JavaScript 最广泛使用的平台，但现代数据库如 MongoDB 和 CouchDB 使用 JavaScript 作为它们的脚本和查询语言。JavaScript 也在浏览器之外成为了重要的平台。例如，**Node.js** 和 **io.js** 项目提供了强大的平台，用于使用 JavaScript 开发可扩展的服务器环境。一些有趣的项目正在将语言能力推向极限，例如，**Emscripten** ([`kripken.github.io/emscripten-site/`](http://kripken.github.io/emscripten-site/)) 是一个基于**低级虚拟机** (**LLVM**) 的项目，它将 C 和 C++编译成高度优化的 JavaScript，格式为**asm.js**。这允许你在网上以接近本地速度运行 C 和 C++。

JavaScript 围绕坚实的基础构建，例如，函数、动态对象、松散类型、原型继承以及强大的对象字面量表示法。

虽然 JavaScript 建立在坚实的设计原则上，但不幸的是，这门语言不得不随着浏览器一起发展。网络浏览器以支持各种特性和标准的方式而闻名。JavaScript 试图适应浏览器的所有奇思妙想，结果做出了一些非常糟糕的设计决策。这些糟糕的部分（这个术语由 Douglas Crockford 闻名）使这门语言的优点对大多数人来说都显得黯淡。程序员编写了糟糕的代码，其他程序员试图调试这些糟糕代码时噩梦般地努力，这门语言最终获得了坏名声。不幸的是，JavaScript 是最被误解的编程语言之一([`javascript.crockford.com/javascript.html`](http://javascript.crockford.com/javascript.html))。

对 JavaScript 的另一种批评是，它让你在没有成为该语言专家的情况下完成事情。我见过程序员因为想快速完成事情而写出极其糟糕的 JavaScript 代码，而 JavaScript 正好允许他们这样做。我花了很多时间调试一个显然不是程序员的人写的非常糟糕的 JavaScript。然而，语言是一种工具，不能因为草率的编程而受到责备。像所有工艺一样，编程需要极大的奉献和纪律。

# 一段简短的历史

1993 年，**国家超级计算应用中心**（**NCSA**）的**Mosaic**浏览器是第一个流行的网页浏览器之一。一年后，网景通讯公司创建了专有的网页浏览器**Netscape Navigator**。几名原始 Mosaic 作者参与了 Navigator 的开发。

1995 年，网景通讯公司聘请了布兰登·艾奇，承诺让他实现**Scheme**（一种 Lisp 方言）在浏览器中。在这一切发生之前，网景与太阳微系统公司（现在称为甲骨文）联系，希望在导航者浏览器中包含 Java。

由于 Java 的流行和易编程，网景决定脚本语言的语法必须与 Java 相似。这排除了采用现有的如 Python、**工具命令语言**（**TCL**）或 Scheme 等语言。艾奇仅用 10 天就编写了最初的原型（[`www.computer.org/csdl/mags/co/2012/02/mco2012020007.pdf`](http://www.computer.org/csdl/mags/co/2012/02/mco2012020007.pdf)），1995 年 5 月。JavaScript 的第一个代号是**Mocha**，由马克·安德森提出。网景后来将其改为**LiveScript**，出于商标原因。1995 年 12 月初，太阳公司将 Java 商标授权给网景。该语言最终被更名为 JavaScript。

# 如何使用这本书

如果你希望快速完成事情，这本书不会对你有所帮助。这本书将专注于用 JavaScript 正确编码的方法。我们将花很多时间了解如何避免该语言的缺点，并在 JavaScript 中构建可靠且可读的代码。我们将避免该语言的草率特性，以确保你不会习惯它们——如果你已经学会了使用这些习惯来编程，这本书将试图让你改掉这个习惯。我们将重点关注正确的风格和工具，以使你的代码变得更好。

本书中的大多数概念都将是来自现实世界问题的例子和模式。我会坚持让你为每个片段编写代码，以确保你对概念的理解被编程到你的肌肉记忆中。相信我，没有比写大量代码更好的学习编程的方法了。

通常，你需要创建一个 HTML 页面来运行嵌入式 JavaScript 代码，如下所示：

```js
<!DOCTYPE html>
<html>
<head>
 <script type="text/javascript" src="img/script.js"></script>
 <script type="text/javascript">
 var x = "Hello World";
 console.log(x);
 </script>
</head>
<body>
</body>
</html>
```

这个示例代码展示了 JavaScript 嵌入 HTML 页面的两种方式。首先，`<head>`中的`<script>`标签导入了 JavaScript，而第二个`<script>`标签则用于嵌入内联 JavaScript。

### 提示

**下载示例代码**

你可以从[`www.packtpub.com`](http://www.packtpub.com)下载你购买的所有 Packt Publishing 书籍的示例代码文件。如果你在其他地方购买了此书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便让文件直接通过电子邮件发送给你。

你可以将这个 HTML 页面保存到本地并在浏览器中打开。在 Firefox 中，你可以打开**开发者**控制台（Firefox 菜单 | **开发者** | **网络控制台**），你可以在**控制台**标签上看到**"Hello World"**文本。根据你的操作系统和浏览器版本，屏幕可能看起来会有所不同：

![如何使用本书](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00002.jpeg)

你可以使用 Chrome 的**开发者工具**运行并检查页面：

![如何使用本书](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00003.jpeg)

这里一个非常有趣的事情是，在控制台上显示了一个关于我们尝试使用以下代码行导入的缺失`.js`文件的错误：

```js
<script type="text/javascript" src="img/script.js"></script>
```

使用浏览器开发者控制台或像**Firebug**这样的扩展在调试代码错误条件时非常有用。我们将在后面的章节中详细讨论调试技术。

创建这样的 HTML 骨架对本书中的每一个练习来说可能会很繁琐。相反，我们想为 JavaScript 使用一个**读-评估-打印循环**（**REPL**）。与 Python 不同，JavaScript 没有内置的 REPL。我们可以使用 Node.js 作为 REPL。如果你已经在你的电脑上安装了 Node.js，你只需在命令行中输入`node`就可以开始与之实验。你会观察到 Node REPL 错误并不是非常优雅地显示。

让我们看看以下示例：

```js
EN-VedA:~$ node
>function greeter(){
  x="World"l
SyntaxError: Unexpected identifier
 at Object.exports.createScript (vm.js:44:10)
 at REPLServer.defaultEval (repl.js:117:23)
 at bound (domain.js:254:14)
 …

```

在出现此错误之后，你必须重新启动。尽管如此，它还是能让你更快地尝试小段代码。

我个人经常使用的一个工具是**JS Bin**([`jsbin.com/`](http://jsbin.com/)). JS Bin 为你提供了一套很好的工具来测试 JavaScript，比如语法高亮和运行时错误检测。以下是 JS Bin 的屏幕截图：

![如何使用本书](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00004.jpeg)

根据你的喜好，你可以选择一个让你更容易尝试代码示例的工具。无论你使用哪个工具，确保你在这本书中输出了每一个练习。

# Hello World

没有一种编程语言应该没有传统的 Hello World 程序就被发布——这本书为什么应该有任何不同？

请（不要复制和粘贴）在 JS Bin 中输入以下代码：

```js
function sayHello(what) {
  return "Hello " + what;
}
console.log(sayHello("world"));
```

你的屏幕应该看起来像以下样子：

![Hello World](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00005.jpeg)

## JavaScript 概览

简而言之，JavaScript 是一种基于原型的脚本语言，具有动态类型和一流的函数支持。JavaScript 大部分语法借鉴了 Java，但也受到了 Awk、Perl 和 Python 的影响。JavaScript 是大小写敏感的，且对空格不敏感。

### 注释

JavaScript 允许单行或多行注释。其语法与 C 或 Java 类似：

```js
// a one line comment

/* this is a longer, 
   multi-line comment
 */

/* You can't /* nest comments */ SyntaxError */
```

### 变量

变量是值的符号名称。变量的名称，或标识符，必须遵循某些规则。

JavaScript 变量名必须以字母、下划线 (_) 或美元符号 ($) 开头；后续字符还可以是数字 (0-9)。由于 JavaScript 是大小写敏感的，所以字母包括 *A* 至 *Z* （大写）和 *a* 至 *z* （小写）的字符。

你可以在变量名中使用 ISO 8859-1 或 Unicode 字母。

在 JavaScript 中，新变量应该使用 **var** 关键字定义。如果你声明了一个变量但没有给它赋值，那么它默认的类型是未定义。一个糟糕的事情是，如果你不使用 var 关键字声明变量，它们会变成隐式的全局变量。让我重申一下，隐式的全局变量是一件糟糕的事情——我们将在书中讨论变量作用域和闭包时详细讨论这个问题，但重要的是要记住，除非你知道你在做什么，否则你应该总是用 var 关键字声明变量：

```js
var a;      //declares a variable but its undefined
var b = 0;
console.log(b);    //0
console.log(a);    //undefined
console.log(a+b);  //NaN
```

NaN 值是一个特殊值，用来表示实体*不是数字*。

### 常量

你可以使用 **const** 关键字创建一个只读的命名常量。常量名必须以字母、下划线或美元符号开头，并可以包含字母、数字或下划线字符：

```js
const area_code = '515';
```

常量不能通过赋值改变其值，也不能重新声明，并且必须初始化为一个值。

JavaScript 支持标准类型变体：

+   数字

+   字符串

+   布尔值

+   符号（ECMAScript 6 新增）

+   对象：

    +   函数

    +   数组

    +   日期

    +   正则表达式

+   空值

+   未定义

### 数字

**Number** 类型可以表示 32 位整数和 64 位浮点值。例如，以下代码行声明了一个变量来保存整数值，该值由字面量 555 定义：

```js
var aNumber = 555;
```

要定义一个浮点值，你需要包含一个小数点和一个小数点后的一位数字：

```js
var aFloat = 555.0;
```

本质上，在 JavaScript 中并没有所谓的整数。JavaScript 使用 64 位浮点表示，这与 Java 的 double 相同。

因此，你会看到如下内容：

```js
EN-VedA:~$ node
> 0.1+0.2
0.30000000000000004
> (0.1+0.2)===0.3
false

```

我建议你阅读 Stack Overflow 上的详尽回答([`stackoverflow.com/questions/588004/is-floating-point-math-broken`](http://stackoverflow.com/questions/588004/is-floating-point-math-broken))和([`floating-point-gui.de/`](http://floating-point-gui.de/))，它解释了为什么会这样。然而，重要的是要理解浮点数运算应该小心处理。在大多数情况下，你可能不需要依赖小数的极端精确度，但如果需要，你可以尝试使用诸如**big.js**([`github.com/MikeMcl/big.js`](https://github.com/MikeMcl/big.js))之类的库来解决这个问题。

如果你打算编写极其精确的财务系统，你应该将$值表示为分，以避免舍入错误。我曾经参与过的其中一个系统过去将**增值税**（**VAT**）金额四舍五入到两位小数。每天有成千上万的订单，这个每订单的舍入金额变成了一个巨大的会计难题。我们需要彻底重构整个 Java Web 服务堆栈和 JavaScript 前端。

还有一些特殊值也被定义为 Number 类型的部分。前两个是`Number.MAX_VALUE`和`Number.MIN_VALUE`，它们定义了 Number 值集的外部界限。所有 ECMAScript 数字必须在这两个值之间，没有例外。然而，一个计算可能会产生不在这两个值之间的数字。当计算结果大于`Number.MAX_VALUE`时，它被赋予`Number.POSITIVE_INFINITY`的值，意味着它不再有数值。同样，计算结果小于`Number.MIN_VALUE`时，被赋予`Number.NEGATIVE_INFINITY`的值，也没有数值。如果计算返回一个无限值，则结果不能用于任何进一步的计算。你可以使用`isInfinite()`方法来验证计算结果是否为无限值。

JavaScript 的另一个特性是一个特殊的值，称为 NaN（*Not a Number*的缩写）。通常，这发生在从其他类型（字符串、布尔值等）转换失败时。观察 NaN 的以下特性：

```js
EN-VedA:~ $ node
> isNaN(NaN);
true
> NaN==NaN;
false
> isNaN("elephant");
true
> NaN+5;
NaN

```

第二行很奇怪——NaN 不等于 NaN。如果 NaN 是任何数学运算的一部分，结果也变成 NaN。一般来说，避免在任何表达式中使用 NaN。对于任何高级数学运算，你可以使用`Math`全局对象及其方法：

```js
> Math.E
2.718281828459045
> Math.SQRT2
1.4142135623730951
> Math.abs(-900)
900
> Math.pow(2,3)
8

```

你可以使用`parseInt()`和`parseFloat()`方法将字符串表达式转换为整数或浮点数：

```js
> parseInt("230",10);
230
> parseInt("010",10);
10
> parseInt("010",8); //octal base
8
> parseInt("010",2); //binary
2
> + "4"
4

```

使用`parseInt()`时，你应该提供一个明确的基数，以防止在旧浏览器上出现糟糕的惊喜。最后一个技巧就是使用`+`号自动将`"42"`字符串转换为数字`42`。谨慎地处理`parseInt()`的结果与`isNaN()`。让我们看看以下示例：

```js
var underterminedValue = "elephant";
if (isNaN(parseInt(underterminedValue,2))) 
{
   console.log("handle not a number case");
}
else
{
   console.log("handle number case");
}
```

在这个例子中，你无法确定`underterminedValue`变量如果从外部接口设置值可能持有的类型。如果`isNaN()`没有处理，`parseInt()`将引发异常，程序可能会崩溃。

### 字符串

在 JavaScript 中，字符串是 Unicode 字符的序列（每个字符占用 16 位）。字符串中的每个字符可以通过它的索引来访问。第一个字符的索引是零。字符串被`"`或`'`括起来——两者都是表示字符串的有效方式。让我们看以下：

```js
> console.log("Hippopotamus chewing gum");
Hippopotamus chewing gum
> console.log('Single quoted hippopotamus');
Single quoted hippopotamus
> console.log("Broken \n lines");
Broken
 lines
```

最后一行展示了当你用反斜杠`\`转义某些字符字面量时，它们可以作为特殊字符使用。以下是这样一些特殊字符的列表：

+   `\n`: 换行

+   `\t`: 制表符

+   `\b`: 退格

+   `\r`: 回车

+   `\\`: 反斜杠

+   `\'`: 单引号

+   `\"`: 双引号

你可以在 JavaScript 字符串中获得对特殊字符和 Unicode 字面量的默认支持：

```js
> '\xA9'
'©'
> '\u00A9'
'©'

```

关于 JavaScript 字符串、数字和布尔值的一个重要事情是，它们实际上有包装对象围绕它们的原始等价物。以下示例展示了包装对象的使用：

```js
var s = new String("dummy"); //Creates a String object
console.log(s); //"dummy"
console.log(typeof s); //"object"
var nonObject = "1" + "2"; //Create a String primitive 
console.log(typeof nonObject); //"string"
var objString = new String("1" + "2"); //Creates a String object
console.log(typeof objString); //"object"
//Helper functions
console.log("Hello".length); //5
console.log("Hello".charAt(0)); //"H"
console.log("Hello".charAt(1)); //"e"
console.log("Hello".indexOf("e")); //1
console.log("Hello".lastIndexOf("l")); //3
console.log("Hello".startsWith("H")); //true
console.log("Hello".endsWith("o")); //true
console.log("Hello".includes("X")); //false
var splitStringByWords = "Hello World".split(" ");
console.log(splitStringByWords); //["Hello", "World"]
var splitStringByChars = "Hello World".split("");
console.log(splitStringByChars); //["H", "e", "l", "l", "o", " ", "W", "o", "r", "l", "d"]
console.log("lowercasestring".toUpperCase()); //"LOWERCASESTRING"
console.log("UPPPERCASESTRING".toLowerCase()); //"upppercasestring"
console.log("There are no spaces in the end     ".trim()); //"There are no spaces in the end"
```

JavaScript 也支持多行字符串。用`` ` ``（重音符号—[`en.wikipedia.org/wiki/Grave_accent`](https://en.wikipedia.org/wiki/Grave_accent)）括起来的字符串被认为是多行。让我们看以下示例：

```js
> console.log(`string text on first line
string text on second line `);
"string text on first line
string text on second line "

```

这种字符串也被称为模板字符串，可以用于字符串插值。JavaScript 允许使用这种语法进行 Python 式的字符串插值。

通常，你会做类似以下的事情：

```js
var a=1, b=2;
console.log("Sum of values is :" + (a+b) + " and multiplication is :" + (a*b));

```

然而，在字符串插值中，事情变得更加清晰：

```js
console.log(`Sum of values is :${a+b} and multiplication is : ${a*b}`);

```

### 未定义值

JavaScript 用两个特殊值来表示没有意义值——null，当非值是故意的，和 undefined，当值还没有分配给变量。让我们看以下示例：

```js
> var xl;
> console.log(typeof xl);
undefined
> console.log(null==undefined);
true

```

### 布尔值

JavaScript 布尔原语由`true`和`false`关键字表示。以下规则决定什么变成假，什么变成真：

+   假，0，空字符串（""），NaN，null，和未定义被表示为假

+   其他一切都是真

JavaScript 布尔值之所以棘手，主要是因为创建它们的方式行为差异很大。

在 JavaScript 中有两种创建布尔值的方法：

+   你可以通过将一个真或假的字面量赋给一个变量来创建原始的布尔值。考虑以下示例：

    ```js
    var pBooleanTrue = true;
    var pBooleanFalse = false;

    ```

+   使用`Boolean()`函数；这是一个普通函数，返回一个原始的布尔值：

    ```js
    var fBooleanTrue = Boolean(true);
    var fBooleanFalse = Boolean(false);

    ```

这两种方法都返回预期的*真值*或*假值*。然而，如果你使用`new`操作符创建一个布尔对象，事情可能会出得很糟糕。

本质上，当你使用`new`操作符和`Boolean(value)`构造函数时，你不会得到一个原始的`true`或`false`，你得到的是一个对象——不幸的是，JavaScript 认为一个对象是*真值*：

```js
var oBooleanTrue = new Boolean(true);
var oBooleanFalse = new Boolean(false);
console.log(oBooleanTrue); //true
console.log(typeof oBooleanTrue); //object
if(oBooleanFalse){
 console.log("I am seriously truthy, don't believe me");
}
>"I am seriously truthy, don't believe me"

if(oBooleanTrue){
 console.log("I am also truthy, see ?");
}
>"I am also truthy, see ?"

//Use valueOf() to extract real value within the Boolean object
if(oBooleanFalse.valueOf()){
 console.log("With valueOf, I am false"); 
}else{
 console.log("Without valueOf, I am still truthy");
}
>"Without valueOf, I am still truthy"

```

因此，明智的做法是始终避免使用 Boolean 构造函数来创建一个新的 Boolean 对象。这违反了布尔逻辑的基本合同，你应该远离这种难以调试的错误代码。

### instanceof 操作符

使用引用类型存储值的一个问题一直是使用**typeof**操作符，它无论引用的是什么类型的对象，都会返回`object`。为了解决这个问题，你可以使用**instanceof**操作符。让我们看一些例子：

```js
var aStringObject = new String("string");
console.log(typeof aStringObject);        //"object"
console.log(aStringObject instanceof String);    //true
var aString = "This is a string";
console.log(aString instanceof String);     //false

```

第三行返回`false`。当我们讨论原型链时，我们将讨论为什么会这样。

### Date 对象

JavaScript 没有日期数据类型。相反，你可以使用**Date**对象及其方法来处理应用程序中的日期和时间。Date 对象相当全面，包含了许多处理大多数与日期和时间相关用例的方法。

JavaScript 将日期处理方式与 Java 相似。JavaScript 将日期存储为自 1970 年 1 月 1 日 00:00:00 以来的毫秒数。

你可以使用以下声明创建一个 Date 对象：

```js
var dataObject = new Date([parameters]);
```

Date 对象构造函数的参数可以是以下形式：

+   不带参数创建今天的日期和时间。例如，`var today = new Date();`。

+   一个表示日期为`Month day, year hours:minutes:seconds`的字符串。例如，`var twoThousandFifteen = new Date("December 31, 2015 23:59:59");`。如果你省略小时、分钟或秒，值将被设置为`0`。

+   一组表示年份、月份和日期的整数值。例如，`var christmas = new Date(2015, 11, 25);`。

+   一组表示年份、月份、日、时、分和秒的整数值。例如，`var christmas = new Date(2015, 11, 25, 21, 00, 0);`。

以下是一些关于如何在 JavaScript 中创建和操作日期的示例：

```js
var today = new Date();
console.log(today.getDate()); //27
console.log(today.getMonth()); //4
console.log(today.getFullYear()); //2015
console.log(today.getHours()); //23
console.log(today.getMinutes()); //13
console.log(today.getSeconds()); //10
//number of milliseconds since January 1, 1970, 00:00:00 UTC
console.log(today.getTime()); //1432748611392
console.log(today.getTimezoneOffset()); //-330 Minutes

//Calculating elapsed time
var start = Date.now();
// loop for a long time
for (var i=0;i<100000;i++);
var end = Date.now();
var elapsed = end - start; // elapsed time in milliseconds
console.log(elapsed); //71
```

对于任何需要对日期和时间对象进行细粒度控制的严肃应用程序，我们推荐使用诸如**Moment.js**([`github.com/moment/moment`](https://github.com/moment/moment)), **Timezone.js**([`github.com/mde/timezone-js`](https://github.com/mde/timezone-js)), 或**date.js**([`github.com/MatthewMueller/date`](https://github.com/MatthewMueller/date)))这样的库。这些库为你简化了很多重复任务，帮助你专注于其他更重要的事情。

### +操作符

当**+**操作符作为一元操作符使用时，对一个数字没有任何影响。然而，当应用于字符串时，+操作符将其转换为数字，如下所示：

```js
var a=25;
a=+a;            //No impact on a's value  
console.log(a);  //25

var b="70";
console.log(typeof b); //string
b=+b;           //converts string to number
console.log(b); //70
console.log(typeof b); //number
```

程序员经常使用+操作符快速将字符串的数值表示转换为数字。然而，如果字符串字面量不能转换为数字，你会得到稍微不可预测的结果，如下所示：

```js
var c="foo";
c=+c;            //Converts foo to number
console.log(c);  //NaN
console.log(typeof c);  //number

var zero="";
zero=+zero; //empty strings are converted to 0
console.log(zero);
console.log(typeof zero);
```

我们将在文本后面讨论+操作符对其他几种数据类型的影响。

### ++和--操作符

++运算符是将值增加 1 的简写，--运算符是将值减少 1 的简写。Java 和 C 有等效的运算符，大多数人熟悉它们。这个怎么样？

```js
var a= 1;
var b= a++;
console.log(a); //2
console.log(b); //1
```

呃，这里发生了什么？`b`变量不应该有值`2`吗？++和--运算符是可以作为前缀或后缀使用的单目运算符。它们的使用顺序很重要。当++用作前缀形式如`++a`时，它在值从表达式返回之前增加值，而不是像`a++`那样在值返回之后增加。让我们看看以下代码：

```js
var a= 1;
var b= ++a;
console.log(a);  //2
console.log(b);  //2
```

许多程序员使用链式赋值来为多个变量分配单个值，如下所示：

```js
var a, b, c;
a = b = c = 0;
```

这是可以的，因为赋值运算符(=)导致值被赋值。在这个例子中，`c=0`被评估为`0`；这将导致`b=0`也被评估为`0`，因此，`a=0`也被评估。

然而，对前面例子的微小修改将产生非凡的结果。考虑这个：

```js
var a = b = 0;
```

在这个例子中，只有变量`a`是用`var`声明的，而变量`b`被创建成了一个意外的全局变量。（如果你处于严格模式，这将产生一个错误。）在 JavaScript 中，小心你所希望的，你可能会得到它。

### 布尔运算符

JavaScript 中有三个布尔运算符——与(&), 或(|), 非(!)。

在讨论逻辑与和或运算符之前，我们需要了解它们是如何产生布尔结果的。逻辑运算符从左到右求值，并且它们是按照以下短路规则进行测试的：

+   **逻辑与**：如果第一个操作数确定了结果，第二个操作数就不会被评估。

    在下面的示例中，我突出了如果它作为短路评估规则的一部分被执行时的右表达式：

    ```js
    console.log(true  && true); // true AND true returns true
    console.log(true  && false);// true AND false returns false
    console.log(false && true);// false AND true returns false
    console.log("Foo" && "Bar");// Foo(true) AND Bar(true) returns Bar
    console.log(false && "Foo");// false && Foo(true) returns false
    console.log("Foo" && false);// Foo(true) && false returns false
    console.log(false && (1 == 2));// false && false(1==2) returns false
    ```

+   **逻辑或**：如果第一个操作数是真，第二个操作数就不会被评估：

    ```js
    console.log(true  || true); // true AND true returns true
    console.log(true  || false);// true AND false returns true
    console.log(false || true);// false AND true returns true
    console.log("Foo" || "Bar");// Foo(true) AND Bar(true) returns Foo
    console.log(false || "Foo");// false && Foo(true) returns Foo
    console.log("Foo" || false);// Foo(true) && false returns Foo
    console.log(false || (1 == 2));// false && false(1==2) returns false
    ```

    然而，逻辑与和逻辑或也可以用于非布尔操作数。当左操作数或右操作数不是原始布尔值时，与和或运算符不返回布尔值。

现在我们将解释三个逻辑布尔运算符：

+   逻辑与(&&)：如果第一个操作数对象是*假值*，它返回那个对象。如果它是*真值*，第二个操作数对象将被返回：

    ```js
    console.log (0 && "Foo");  //First operand is falsy - return it
    console.log ("Foo" && "Bar"); //First operand is truthy, return the second operand
    ```

+   逻辑或(||)：如果第一个操作数是*真值*，它将被返回。否则，第二个操作数将被返回：

    ```js
    console.log (0 || "Foo");  //First operand is falsy - return second operand
    console.log ("Foo" || "Bar"); //First operand is truthy, return it
    console.log (0 || false); //First operand is falsy, return second operand
    ```

    逻辑或的典型用途是为变量分配默认值：

    ```js
    function greeting(name){
        name = name || "John";
        console.log("Hello " + name);
    }

    greeting("Johnson"); // alerts "Hi Johnson";
    greeting(); //alerts "Hello John"
    ```

    你将在大多数专业的 JavaScript 库中频繁看到这个模式。你应该理解如何使用逻辑或运算符来实现默认值。

+   **逻辑非**：这总是返回一个布尔值。返回的值取决于以下情况：

    ```js
    //If the operand is an object, false is returned.
    var s = new String("string");
    console.log(!s);              //false

    //If the operand is the number 0, true is returned.
    var t = 0;
    console.log(!t);              //true

    //If the operand is any number other than 0, false is returned.
    var x = 11;
    console.log(!x);              //false

    //If operand is null or NaN, true is returned
    var y =null;
    var z = NaN;
    console.log(!y);              //true
    console.log(!z);              //true
    //If operand is undefined, you get true
    var foo;
    console.log(!foo);            //true
    ```

此外，JavaScript 支持类似于 C 的三元运算符，如下所示：

```js
var allowedToDrive = (age > 21) ? "yes" : "no";
```

如果`(age>21)`，`?`后面的表达式将被赋值给`allowedToDrive`变量，否则`:`后面的表达式将被赋值。这相当于一个 if-else 条件语句。让我们看另一个例子：

```js
function isAllowedToDrive(age){
  if(age>21){
    return true;
  }else{
    return false;
  }
}
console.log(isAllowedToDrive(22));
```

在这个例子中，`isAllowedToDrive()`函数接受一个整数参数`age`。根据这个变量的值，我们返回真或假给调用函数。这是一个众所周知且最熟悉的 if-else 条件逻辑。大多数时候，if-else 使代码更容易阅读。对于单一条件的简单情况，使用三元运算符也可以，但如果你看到你正在为更复杂的表达式使用三元运算符，尝试坚持使用 if-else，因为解析 if-else 条件比解析一个非常复杂的三元表达式要容易。

条件语句可以如下嵌套：

```js
if (condition1) {
  statement1
} else if (condition2) {
  statement2
} else if (condition3) {
  statement3
}
..
} else {
  statementN
}
```

纯粹出于审美原因，你可以像下面这样缩进嵌套的`else if`：

```js
if (condition1) {
  statement1
} else
    if (condition2) {
```

不要在条件语句的地方使用赋值语句。大多数时候，它们被使用是因为下面的错误：

```js
if(a=b) {
  //do something
}
```

大多数时候，这是由于错误造成的；意图中的代码是`if(a==b)`，或者更好，`if(a===b)`。当你犯这个错误，并用赋值语句替换条件语句时，你最终会犯一个非常难以发现的错误。然而，如果你真的想在一个 if 语句中使用赋值语句，请确保你的意图非常明确。

一种方法是在你的赋值语句周围加上额外的括号：

```js
if((a=b)){
  //this is really something you want to do
}
```

处理条件执行的另一种方法是使用 switch-case 语句。JavaScript 中的 switch-case 结构与 C 或 Java 中的类似。让我们看以下例子：

```js
function sayDay(day){
  switch(day){
    case 1: console.log("Sunday");
      break;
    case 2: console.log("Monday");
      break;
    default:
      console.log("We live in a binary world. Go to Pluto");
  }
}

sayDay(1); //Sunday
sayDay(3); //We live in a binary world. Go to Pluto
```

这种结构的一个问题是，你有`break`语句在每一个`case`后面；否则，执行将会递归到下一级。如果我们从第一个`case`语句中移除`break`语句，输出将会如下：

```js
>sayDay(1);
Sunday
Monday
```

正如您所看到的，如果我们省略`break`语句，在条件满足后立即中断执行，执行顺序会继续递归到下一级。这可能会导致代码中难以检测到的问题。然而，如果你打算一直递归到下一级，这种写条件逻辑的方式也很流行：

```js
function debug(level,msg){
  switch(level){
    case "INFO": //intentional fall-through
    case "WARN" :  
    case "DEBUG": console.log(level+ ": " + msg);  
      break;
    case "ERROR": console.error(msg);  
  }
}

debug("INFO","Info Message");
debug("DEBUG","Debug Message");
debug("ERROR","Fatal Exception");
```

在这个例子中，我们故意让执行递归，以编写简洁的 switch-case。如果级别是 INFO、WARN 或 DEBUG，我们使用 switch-case 递归到单一点执行。我们省略这个`break`语句。如果你想遵循这种写 switch 语句的模式，请确保你记录你的使用方式，以提高可读性。

switch 语句可以有一个`default`案例，用来处理任何不能被其他案例评估的值。

JavaScript 有一个 while 和 do-while 循环。while 循环让你迭代一系列表达式，直到满足某个条件。以下第一个例子迭代了`{}`内的语句，直到`i<10`表达式为真。记住，如果`i`计数器的值已经大于`10`，循环根本不会执行：

```js
var i=0;
while(i<10){
  i=i+1;
  console.log(i);
}
```

下面的循环会一直执行到无穷大，因为条件总是为真——这可能导致灾难性的后果。你的程序可能会耗尽你所有的内存，或者更糟糕的事情：

```js
//infinite loop
while(true){
  //keep doing this
}
```

如果你想要确保至少执行一次循环，你可以使用 do-while 循环（有时被称为后置条件循环）：

```js
var choice;
do {
  choice=getChoiceFromUserInput();
} while(!isInputValid(input));
```

在这个例子中，我们要求用户输入，直到我们找到有效的用户输入。当用户输入无效时，我们继续要求用户输入。人们总是认为，从逻辑上讲，每个 do-while 循环都可以转换为 while 循环。然而，do-while 循环有一个非常有效的用例，就像我们刚才看到的那样，你希望在循环块执行一次之后才检查条件。

JavaScript 有一个非常强大的循环，类似于 C 或 Java——for 循环。for 循环之所以流行，是因为它允许你在一句话中定义循环的控制条件。

下面的例子会打印五次`Hello`：

```js
for (var i=0;i<5;i++){
  console.log("Hello");
}
```

在循环的定义中，你定义了循环计数器`i`的初始值为`0`，定义了`i<5`的退出条件，最后定义了增量因子。

前面例子中的所有三个表达式都是可选的。如果需要，你可以省略它们。例如，下面的变体都将产生与之前循环相同的结果：

```js
var x=0;
//Omit initialitzation
for (;x<5;x++){
  console.log("Hello");
}

//Omit exit condition
for (var j=0;;j++){
  //exit condition
  if(j>=5){
    break;  
  }else{
    console.log("Hello");
  }
}
//Omit increment
for (var k=0; k<5;){
  console.log("Hello");
  k++;
}
```

你也可以省略这三个表达式，写 for 循环。一个经常使用的有趣习惯是用 for 循环与空语句。下面的循环用于将数组的所有元素设置为`100`。注意循环体内没有主体：

```js
var arr = [10, 20, 30];
// Assign all array values to 100
for (i = 0; i < arr.length; arr[i++] = 100);
console.log(arr);
```

这里的空语句只是我们在 for 循环语句之后看到的那个单一的语句。增量因子也修改了数组内容。我们将在书的后面讨论数组，但在这里，只要看到循环定义本身将数组元素设置为`100`值就足够了。

### 等价

JavaScript 提供了两种等价模式——严格和宽松。本质上，宽松等价在比较两个值时会执行类型转换，而严格等价则不进行任何类型转换的检查。严格等价检查由===完成，而宽松等价检查由==完成。

ECMAScript 6 还提供了`Object.is`方法来进行与===相同的严格等价检查。然而，`Object.is`对 NaN 有特殊的处理：-0 和+0。当*NaN===NaN*和*NaN==NaN*评估为假时，`Object.is(NaN,NaN)`将返回真。

#### 严格等价使用===

严格等价比较两个值而不进行任何隐式的类型转换。以下规则适用：

+   如果值属于不同的类型，它们是不相等的。

+   对于相同类型的非数字值，如果它们的值相同，它们是相等的。

+   对于原始数字，严格等价对于值来说是有效的。如果值相同，===结果为`true`。然而，NaN 不等于任何数字，所以`NaN===<一个数字>`将会是`false`。

严格等价始终是正确的等价检查。始终使用===而不是==作为等价检查的规则：

| 条件 | 输出 |
| --- | --- |
| `"" === "0";` | 错误 |
| `0 === "";` | 错误 |
| `0 === "0";` | 错误 |
| `false === "false";` | 错误 |
| `false === "0";` | 错误 |
| `false === undefined;` | 错误 |
| `false === null;` | 错误 |
| `null === undefined;` | 错误 |

在比较对象时，结果如下：

| 条件 | 输出 |
| --- | --- |
| `{} === {};` | 错误 |
| `new String('bah') === 'bah';` | 错误 |
| `new Number(1) === 1;` | 错误 |
| `var bar = {};``bar === bar;` | 正确 |

以下是在 JS Bin 或 Node REPL 上尝试的进一步示例：

```js
var n = 0;
var o = new String("0");
var s = "0";
var b = false;

console.log(n === n); // true - same values for numbers
console.log(o === o); // true - non numbers are compared for their values
console.log(s === s); // true - ditto

console.log(n === o); // false - no implicit type conversion, types are different
console.log(n === s); // false - types are different
console.log(o === s); // false - types are different
console.log(null === undefined); // false
console.log(o === null); // false
console.log(o === undefined); // false
```

当进行严格等价检查时，你可以使用`!==`来处理**不等于**的情况。

#### 使用==的弱等价

绝对不要诱惑你使用这种等价形式。严肃地说，离这种形式远一点。这种等价形式主要是由于 JavaScript 的弱类型而有很多问题。等价操作符==，首先尝试强制类型然后再进行比较。以下示例展示了它是如何工作的：

| 条件 | 输出 |
| --- | --- |
| `"" == "0";` | 错误 |
| `0 == "";` | 正确 |
| `0 == "0";` | 正确 |
| `false == "false";` | 错误 |
| `false == "0";` | 正确 |
| `false == undefined;` | 错误 |
| `false == null;` | 错误 |
| `null == undefined;` | 正确 |

从这些示例中，可以看出弱等价可能会导致意外的结果。此外，隐式强制类型转换在性能上是有代价的。所以，一般来说，在 JavaScript 中应避免使用弱等价。

## javascript 类型

我们简要讨论了 JavaScript 是一种动态语言。如果你有使用强类型语言如 Java 的先前经验，你可能会对完全缺乏你所熟悉的类型检查感到有些不舒服。纯粹主义者认为 JavaScript 应该声称有**标签**或者也许是**子类型**，但不是类型。尽管 JavaScript 没有传统意义上的**类型**定义，但深入理解 JavaScript 如何处理数据类型和强制类型转换内部是绝对必要的。每个非平凡的 JavaScript 程序都需要以某种形式处理值强制类型转换，所以理解这个概念很重要。

显式强制类型转换发生在当你自己修改类型时。在以下示例中，你将使用`toString()`方法将一个数字转换为字符串并从中提取第二个字符：

```js
var fortyTwo = 42;
console.log(fortyTwo.toString()[1]); //prints "2"
```

这是一个显式类型转换的例子。再次强调，我们在这里使用“类型”这个词是比较宽泛的，因为在声明`fortyTwo`变量时，并没有任何地方强制类型。

然而，强制转换发生的许多不同方式。显式强制转换可能容易理解且 mostly 可靠；但如果你不小心，强制转换可能会以非常奇怪和惊讶的方式发生。

围绕强制转换的混淆可能是 JavaScript 开发者谈论最多的挫折之一。为了确保你心中永远不会有这种混淆，让我们重新回顾一下 JavaScript 中的类型。我们之前谈过一些概念：

```js
typeof 1             === "number";    // true
typeof "1"           === "string";    // true
typeof { age: 39 }   === "object";    // true
typeof Symbol()      === "symbol";    // true
typeof undefined     === "undefined"; // true
typeof true          === "boolean";   // true
```

到目前为止，还不错。我们已经知道了这些，我们刚才看到的一些例子加强了我们对于类型的想法。

从一个类型转换到另一个类型的值的转换称为**类型转换**或显式强制转换。JavaScript 也通过根据某些猜测改变值的类型来进行隐式强制转换。这些猜测使 JavaScript 在几种情况下发挥作用，不幸的是，它默默地、意外地失败了。以下代码段显示了显式和隐式强制转换的情况：

```js
var t=1;
var u=""+t; //implicit coercion
console.log(typeof t);  //"number"
console.log(typeof u);  //"string"
var v=String(t);  //Explicit coercion
console.log(typeof v);  //"string"
var x=null
console.log(""+x); //"null"
```

很容易看出这里发生了什么。当你用`""+t`对数字值`t`（在这个例子中是`1`）进行操作时，JavaScript 意识到你试图将*某种东西*与一个`""`字符串连接起来。因为只有字符串才能与其他字符串连接，所以 JavaScript 前进并把一个数字`1`转换为一个`"1"`字符串，然后将两者连接成一个字符串值。这就是当 JavaScript 被要求隐式转换值时会发生的事情。然而，`String(t)`是一个明确调用数字转换为字符串的。这是一个类型的显式转换。最后的部分令人惊讶。我们正在将`null`与`""`连接——这不应该失败吗？

那么 JavaScript 是如何进行类型转换的呢？一个抽象值如何变成字符串或数字或布尔值？JavaScript 依赖于`toString()`、`toNumber()`和`toBoolean()`方法来进行这些内部转换。

当一个非字符串值被强制转换为字符串时，JavaScript 内部使用`toString()`方法来完成这个转换。所有原始值都有自然的字符串形式——`null`的自然字符串形式是`"null"`，`undefined`的自然字符串形式是`"undefined"`，依此类推。对于 Java 开发者来说，这类似于一个类有一个`toString()`方法，返回该类的字符串表示。我们将看到对象的情况是如何工作的。

所以本质上，你可以做类似以下的事情：

```js
var a="abc";
console.log(a.length);
console.log(a.toUpperCase());
```

```js
As we discussed earlier, JavaScript kindly wraps these primitives in their wrappers by default thus making it possible for us to directly access the wrapper's methods and properties as if they were of the primitives themselves.
```

当任何非数字值需要被转换为数字时，JavaScript 内部使用`toNumber()`方法：`true`变成`1`，`undefined`变成`NaN`，`false`变成`0`，`null`变成`0`。字符串上的`toNumber()`方法与字面转换一起工作，如果这个失败了，方法返回`NaN`。

其他一些情况呢？

```js
typeof null ==="object" //true
```

好吧，`null`是一个对象？是的，一个特别持久的错误使得这成为可能。由于这个错误，你在测试一个值是否为`null`时需要小心：

```js
var x = null;
if (!x && typeof x === "object"){
  console.log("100% null");
}
```

那么可能还有其他具有类型的东西，比如函数呢？

```js
f = function test() {
  return 12;
}
console.log(typeof f === "function");  //prints "true"
```

那么数组呢？

```js
console.log (typeof [1,2,3,4]); //"object"
```

确实如此，它们也是对象。我们将在书的后面详细介绍函数和数组。

在 JavaScript 中，值有类型，变量没有。由于语言的动态特性，变量可以随时持有任何值。

JavaScript 不强制类型，这意味着该语言不坚持变量始终持有与初始类型相同的值。变量可以持有字符串，然后在下一个赋值中持有数字，依此类推：

```js
var a = 1; 
typeof a; // "number"  
a = false; 
typeof a; // "boolean"
```

typeof 操作符总是返回一个字符串：

```js
typeof typeof 1; // "string"
```

## 自动分号插入

尽管 JavaScript 基于 C 风格语法，但它不强制在源代码中使用分号。

然而，JavaScript 并不是一个无分号的语言。JavaScript 语言解析器需要分号来理解源代码。因此，当解析器遇到由于缺少分号而导致的解析错误时，它会自动插入分号。需要注意的是，**自动分号插入**（**ASI**）只有在存在换行符（也称为行 break）时才会生效。分号不会在一行中间插入。

基本上，如果 JavaScript 解析器解析一行，在该行中会发生解析错误（缺少预期的分号）并且它可以插入一个，它会这样做。插入分号的条件是什么？只有当某些语句的末尾和该行的换行符/行 break 之间只有空白字符和/或注释时。

关于 ASI 一直有激烈的争论——一个合理地被认为是设计选择非常糟糕的功能。网络上进行了史诗般的讨论，例如[`github.com/twbs/bootstrap/issues/3057`](https://github.com/twbs/bootstrap/issues/3057)和[`brendaneich.com/2012/04/the-infernal-semicolon/`](https://brendaneich.com/2012/04/the-infernal-semicolon/)。

在判断这些论点的有效性之前，你需要了解 ASI 影响了什么。以下受 ASI 影响的声明：

+   一个空声明

+   一个 var 声明

+   一个表达式声明

+   一个 do-while 声明

+   一个 continue 声明

+   一个 break 声明

+   一个 return 声明

+   一个 throw 声明

ASI 背后的想法是使分号在行的末尾成为可选。这样，ASI 帮助解析器确定语句何时结束。通常，它在分号处结束。ASI 规定，在以下情况下语句也以如下情况结束：

+   换行符（例如，换行符）后面跟着一个非法令牌

+   遇到一个闭合括号

+   文件已达到末尾

让我们看看以下示例：

```js
if (a < 1) a = 1 console.log(a)
```

在 1 之后 console 令牌是非法的，并按照以下方式触发 ASI：

```js
if (a < 1) a = 1; console.log(a);
```

在下面的代码中，大括号内的语句没有用分号终止：

```js
function add(a,b) { return a+b }
```

ASI 为前面的代码创建了一个语法上正确的版本：

```js
function add(a,b) { return a+b; }
```

## JavaScript 风格指南

每种编程语言都会发展出自己的风格和结构。不幸的是，新开发者并没有付出太多努力去学习一门语言的风格细微差别。一旦养成了坏习惯，后来要发展这项技能就非常困难了。为了生成美观、可读且易于维护的代码，学习正确的风格是非常重要的。有很多样式建议。我们将选择最实用的那些。在适用的情况下，我们将讨论合适的样式。让我们设定一些风格基础规则。

### 空白符

虽然空白符在 JavaScript 中并不重要，但正确使用空白符可以使代码更易读。以下指南将帮助你在代码中管理空白符：

+   不要混合空格和制表符。

+   在你编写任何代码之前，选择使用软缩进（空格）或真正的制表符。为了提高可读性，我总是建议你将编辑器的缩进大小设置为两个字符——这意味着两个空格或两个空格表示一个真正的制表符。

+   始终开启*显示不可见字符*设置。这种做法的好处如下：

    +   强制一致性。

    +   消除行尾的空白符。

    +   消除行尾的空白符。

    +   提交和差异更容易阅读。

    +   在可能的情况下使用**EditorConfig** ([`editorconfig.org/`](http://editorconfig.org/))。

### 括号、换行符和括号

如果、否则、for、while 和 try 总是有空格和括号，并且跨越多行。这种风格有助于提高可读性。让我们看看以下的代码：

```js
//Cramped style (Bad)
if(condition) doSomeTask();

while(condition) i++;

for(var i=0;i<10;i++) iterate();

//Use whitespace for better readability (Good)
//Place 1 space before the leading brace.
if (condition) {
  // statements
}

while ( condition ) {
  // statements
}

for ( var i = 0; i < 100; i++ ) {
  // statements
}

// Better:

var i,
    length = 100;

for ( i = 0; i < length; i++ ) {
  // statements
}

// Or...

var i = 0,
    length = 100;

for ( ; i < length; i++ ) {
  // statements
}

var value;

for ( value in object ) {
  // statements
}

if ( true ) {
  // statements
} else {
  // statements
}

//Set off operators with spaces.
// bad
var x=y+5;

// good
var x = y + 5;

//End files with a single newline character.
// bad
(function(global) {
  // ...stuff...
})(this);

// bad
(function(global) {
  // ...stuff...
})(this);↵
↵

// good
(function(global) {
  // ...stuff...
})(this);↵
```

### 引号

无论你更喜欢单引号还是双引号，都不应该有区别；JavaScript 解析它们的方式没有区别。然而，为了保持一致性，同一个项目中不要混合引号。选择一种风格并坚持使用。

### 行尾和空行

空白符可能会使代码差异和更改列表无法辨认。许多编辑器允许你自动删除额外的空行和行尾空格——你应该使用这些功能。

### 类型检查

检查一个变量的类型可以按照如下方式进行：

```js
//String:
typeof variable === "string"
//Number:
typeof variable === "number"
//Boolean:
typeof variable === "boolean"
//Object:
typeof variable === "object"
//null:
variable === null
//null or undefined:
variable == null
```

### 类型转换

如下在语句开头执行类型强制：

```js
// bad
const totalScore = this.reviewScore + '';
// good
const totalScore = String(this.reviewScore);
```

对数字使用`parseInt()`，并且总是需要一个基数来进行类型转换：

```js
const inputValue = '4';
// bad
const val = new Number(inputValue);
// bad
const val = +inputValue;
// bad
const val = inputValue >> 0;
// bad
const val = parseInt(inputValue);
// good
const val = Number(inputValue);
// good
const val = parseInt(inputValue, 10);
```

以下示例向你展示了如何使用布尔值进行类型转换：

```js
const age = 0;  // bad 
const hasAge = new Boolean(age);  // good 
const hasAge = Boolean(age); // good 
const hasAge = !!age;
```

### 条件评估

有关条件语句的样式指南有很多。让我们研究一下以下的代码：

```js
// When evaluating that array has length,
// WRONG:
if ( array.length > 0 ) ...

// evaluate truthiness(GOOD):
if ( array.length ) ...

// When evaluating that an array is empty,
// (BAD):
if ( array.length === 0 ) ...

// evaluate truthiness(GOOD):
if ( !array.length ) ...

// When checking if string is not empty,
// (BAD):
if ( string !== "" ) ...

// evaluate truthiness (GOOD):
if ( string ) ...

// When checking if a string is empty,
// BAD:
if ( string === "" ) ...

// evaluate falsy-ness (GOOD):
if ( !string ) ...

// When checking if a reference is true,
// BAD:
if ( foo === true ) ...

// GOOD
if ( foo ) ...

// When checking if a reference is false,
// BAD:
if ( foo === false ) ...

// GOOD
if ( !foo ) ...

// this will also match: 0, "", null, undefined, NaN
// If you MUST test for a boolean false, then use
if ( foo === false ) ...

// a reference that might be null or undefined, but NOT false, "" or 0,
// BAD:
if ( foo === null || foo === undefined ) ...

// GOOD
if ( foo == null ) ...

// Don't complicate matters
return x === 0 ? 'sunday' : x === 1 ? 'Monday' : 'Tuesday';

// Better:
if (x === 0) {
    return 'Sunday';
} else if (x === 1) {
    return 'Monday';
} else {
    return 'Tuesday';
}

// Even Better:
switch (x) {
    case 0:
        return 'Sunday';
    case 1:
        return 'Monday';
    default:
        return 'Tuesday';
}
```

### 命名

命名非常重要。我敢肯定你遇到过命名简短且难以辨认的代码。让我们研究一下以下代码行：

```js
//Avoid single letter names. Be descriptive with your naming.
// bad
function q() {

}

// good
function query() {
}

//Use camelCase when naming objects, functions, and instances.
// bad
const OBJEcT = {};
const this_is_object = {};
function c() {}

// good
const thisIsObject = {};
function thisIsFunction() {}

//Use PascalCase when naming constructors or classes.
// bad
function user(options) {
  this.name = options.name;
}

const bad = new user({
  name: 'nope',
});

// good
class User {
  constructor(options) {
    this.name = options.name;
  }
}

const good = new User({
  name: 'yup',
});

// Use a leading underscore _ when naming private properties.
// bad
this.__firstName__ = 'Panda';
this.firstName_ = 'Panda';

// good
this._firstName = 'Panda';
```

### eval()方法是邪恶的

```js
eval():
```

```js
console.log(typeof eval(new String("1+1"))); // "object"
console.log(eval(new String("1+1")));        //1+1
console.log(eval("1+1"));                    // 2
console.log(typeof eval("1+1"));             // returns "number"
var expression = new String("1+1");
console.log(eval(expression.toString()));    //2
```

我将避免展示`eval()`的其他用途，并确保你被劝阻得足够，从而远离它。

### 严格模式

ECMAScript 5 有一个严格模式，结果是更干净的 JavaScript，具有更少的危险功能、更多的警告和更逻辑的行为。正常（非严格）模式也称为**松散模式**。严格模式可以帮助你避免一些松散编程实践。如果你正在启动一个新的 JavaScript 项目，我强烈建议你默认使用严格模式。

要开启严格模式，你需要在你的 JavaScript 文件或你的`<script>`元素中首先输入以下行：

```js
'use strict';
```

请注意，不支持 ECMAScript 5 的 JavaScript 引擎将简单地忽略前述语句，并以非严格模式继续执行。

如果你想要为每个函数开启严格模式，你可以这样做：

```js
function foo() {
    'use strict';

}
```

当你与遗留代码库合作时，这很方便，因为在大范围内开启严格模式可能会破坏事物。

如果你正在处理现有的遗留代码，要小心，因为使用严格模式可能会破坏事物。这一点有告诫：

#### 为现有代码启用严格模式可能会破坏它

代码可能依赖于不再可用的功能或与松散模式和严格模式不同的行为。不要忘记你有选项可以向处于松散模式的文件中添加单个严格模式函数。

#### 小心地封装

当你连接和/或压缩文件时，你必须小心，确保严格模式在应该开启的地方没有关闭或相反。两者都可能破坏代码。

以下部分详细解释了严格模式的功能。你通常不需要了解它们，因为你大部分时候会因为不应该做的事情而收到警告。

#### 在严格模式下，变量必须声明

在严格模式下，所有变量都必须显式声明。这有助于防止打字错误。在松散模式下，对未声明变量的赋值将创建一个全局变量：

```js
function sloppyFunc() {
  sloppyVar = 123; 
} sloppyFunc();  // creates global variable `sloppyVar`
console.log(sloppyVar);  // 123
```

在严格模式下，对未声明变量的赋值会抛出异常：

```js
function strictFunc() {
  'use strict';
  strictVar = 123;
}
strictFunc();  // ReferenceError: strictVar is not defined
```

##### 在严格模式下，`eval()`函数更简洁

在严格模式下，`eval()`函数变得不那么怪异：在评估的字符串中声明的变量不再添加到围绕`eval()`的作用域中。

#### 在严格模式下被阻止的功能

不允许使用 with 语句。（我们将在书中稍后讨论这个问题。）在编译时间（加载代码时）你会得到一个语法错误。

在松散模式下，带前导零的整数被解释为八进制（基数 8）如下：

```js
> 010 === 8 true

```

在严格模式下，如果你使用这种字面量，你会得到一个语法错误：

```js
function f() { 
'use strict'; 
return 010 
} 
//SyntaxError: Octal literals are not allowed in 
```

### 运行 JSHint

**JSHint** 是一个程序，用于标记使用 JavaScript 编写的程序中的可疑用法。该项目核心包括本身作为一个库以及作为 Node 模块分发的**命令行界面**（**CLI**）程序。

如果你安装了 Node.js，你可以使用`npm`如下安装 JSHint：

```js
npm install jshint –g

```

```js
test.js file:
```

```js
function f(condition) {
  switch (condition) {
  case 1:
    console.log(1);
  case 2:
    console.log(1);
  }
}
```

当我们使用 JSHint 运行文件时，它将警告我们在 switch case 中缺少`break`语句，如下所示：

```js
>jshint test.js
test.js: line 4, col 19, Expected a 'break' statement before 'case'.
1 error

```

JSHint 可以根据您的需求进行配置。查看[`jshint.com/docs/`](http://jshint.com/docs/)的文档，了解如何根据您的项目需求自定义 JSHint。我广泛使用 JSHint，并建议您开始使用它。您会惊讶地发现，使用这样一个简单的工具，您能够在代码中修正多少隐藏的错误和风格问题。

您可以在项目的根目录下运行 JSHint，并对整个项目进行 lint 检查。您可以在`.jshintrc`文件中放置 JSHint 指令。这个文件可能如下所示：

```js
{
     "asi": false,
     "expr": true,
     "loopfunc": true,
     "curly": false,
     "evil": true,
     "white": true,
     "undef": true,
     "indent": 4
}
```

# 总结

在本章中，我们围绕 JavaScript 语法、类型和风格考虑方面设定了一些基础。我们故意没有讨论其他重要方面，如函数、变量作用域和闭包，主要是因为它们应该在这本书中有自己的独立章节。我相信这一章节帮助你理解了 JavaScript 的一些基本概念。有了这些基础，我们将看看如何编写专业质量的 JavaScript 代码。


# 第二章：函数、闭包和模块

在上一章中，我们故意没有讨论 JavaScript 的某些方面。这些是赋予 JavaScript 其力量和优雅的一些语言特性。如果你是一个中级或高级的 JavaScript 程序员，你可能正在积极使用对象和函数。然而，在许多情况下，开发者在这些基本层面上绊倒，对 JavaScript 核心构造产生了半生不熟或有时错误的理解。由于对 JavaScript 中闭包概念的普遍理解不足，许多程序员无法很好地使用 JavaScript 的功能方面。在 JavaScript 中，对象、函数和闭包之间有很强的相互联系。理解这三个概念之间强烈的关系可以大大提高我们的 JavaScript 编程能力，为我们提供任何类型应用程序开发坚实的基础。

函数是 JavaScript 的基础。理解 JavaScript 中的函数是你武器库中最重要的武器。关于函数最重要的事实是，在 JavaScript 中，函数是第一类对象。它们像任何其他 JavaScript 对象一样被对待。与其他 JavaScript 数据类型一样，它们可以被变量引用，通过字面量声明，甚至可以作为函数参数传递。

就像 JavaScript 中的任何其他对象一样，函数具有以下能力：

+   它们可以通过字面量创建

+   它们可以分配给变量、数组元素和其他对象的属性

+   它们可以作为参数传递给函数

+   它们可以从函数中作为值返回

+   它们可以拥有动态创建和赋值的属性

在本章以及本书的剩余部分，我们将讨论 JavaScript 函数的这些独特能力。

# 函数字面量

JavaScript 中最重要的概念之一是函数是执行的主要单位。函数是你会包裹所有代码的地方，因此它们会给你的程序带来结构。

JavaScript 函数是通过函数字面量声明的。

函数字面量由以下四个部分组成：

+   函数关键字。

+   可选的名称，如果指定，必须是一个有效的 JavaScript 标识符。

+   用括号括起来的参数名称列表。如果函数没有参数，你需要提供空括号。

+   函数体，作为一系列用花括号括起来的 JavaScript 语句。

## 函数声明

下面是一个非常简单的例子，用于展示函数声明的所有组成部分：

```js
function add(a,b){
  return a+b;
}
c = add(1,2);
console.log(c);  //prints 3
```

这种声明以`function`关键词开头，后接函数名。函数名是可选的。如果一个函数没有指定名称，则称其为匿名函数。我们将看到匿名函数是如何使用的。第三部分是一组函数参数，被括号括起来。括号内是一组零个或多个由逗号分隔的参数名称。这些名称将在函数中被定义为变量，并且它们不会初始化为 undefined，而是初始化为函数调用时提供的参数。第四部分是一组用大括号括起来的语句。这些语句是函数的主体。当函数被调用时，它们将被执行。

这种函数声明方法也被称为**函数语句**。当你这样声明函数时，函数的内容将被编译，并且会创建一个与函数同名的对象。

另一种函数声明方式是通过**函数表达式**：

```js
var add = function(a,b){
  return a+b;
}
c = add(1,2);
console.log(c);  //prints 3
```

在这里，我们创建了一个匿名函数并将其赋值给一个`add`变量；这个变量像之前的例子一样用来调用函数。这种函数声明方式的一个问题是，我们无法进行这种函数的递归调用。递归是一种优雅的编程方式，函数调用自己。你可以使用命名的函数表达式来解决这个限制。作为一个例子，参考以下计算给定数字`n`的阶乘的函数：

```js
var facto = function factorial(n) {
  if (n <= 1)
    return 1;
  return n * factorial(n - 1);
};
console.log(facto(3));  //prints 6
```

在这里，你没有创建一个匿名函数，而是创建了一个有名字的函数。现在，因为函数有一个名字，所以它可以递归地调用自己。

最后，你可以创建自调用函数表达式（我们稍后讨论它们）：

```js
(function sayHello() {
  console.log("hello!");
})();
```

一旦定义，一个函数可以在其他 JavaScript 函数中被调用。函数体执行完毕后，调用者代码（执行函数的代码）将继续执行。你还可以将一个函数作为参数传递给另一个函数：

```js
function changeCase(val) {
  return val.toUpperCase();
}
function demofunc(a, passfunction) {
  console.log(passfunction(a));
}
demofunc("smallcase", changeCase);
```

在前面的示例中，我们用两个参数调用`demofunc()`函数。第一个参数是我们想要转换为大写的字符串，第二个参数是`changeCase()`函数的函数引用。在`demofunc()`中，我们通过传递给`passfunction`参数的引用调用`changeCase()`函数。在这里，我们通过将函数引用作为参数传递给另一个函数来传递一个函数引用。这个强大的概念将在书中讨论回调的部分详细讨论。

一个函数可能返回一个值，也可能不返回值。在前面的例子中，我们看到`add`函数向调用代码返回了一个值。除了在函数末尾返回一个值外，显式调用`return`还可以让你有条件地从函数中返回：

```js
var looper = function(x){
  if (x%5===0) {
    return;
  }
  console.log(x)
}
for(var i=1;i<10;i++){
  looper(i);
}
```

```js
1, 2, 3, 4, 6, 7, 8, and 9, and not 5\. When the if (x%5===0) condition is evaluated to true, the code simply returns from the function and the rest of the code is not executed.
```

# 函数作为数据

在 JavaScript 中，函数可以赋值给变量，而变量是数据。你很快就会看到这是一个强大的概念。让我们看以下示例：

```js
var say = console.log;
say("I can also say things");
```

在前面的例子中，我们将熟悉的`console.log()`函数赋值给 say 变量。任何函数都可以赋值给一个变量，正如前面例子所示。给变量添加括号将调用它。此外，你还可以将函数作为参数传递给其他函数。仔细研究下面的例子并在 JS Bin 中键入它：

```js
var validateDataForAge = function(data) {
 person = data();
  console.log(person);
  if (person.age <1 || person.age > 99){
    return true;
  }else{
    return false;
  }
};

var errorHandlerForAge = function(error) {
  console.log("Error while processing age");
};

function parseRequest(data,validateData,errorHandler) {
  var error = validateData(data);
  if (!error) {
    console.log("no errors");
  } else {
    errorHandler();
  }
}

var generateDataForScientist = function() {
  return {
    name: "Albert Einstein",
    age : Math.floor(Math.random() * (100 - 1)) + 1,
  };
};
var generateDataForComposer = function() {
  return {
    name: "J S Bach",
    age : Math.floor(Math.random() * (100 - 1)) + 1,
  };
};

//parse request
parseRequest(generateDataForScientist, validateDataForAge, errorHandlerForAge);
parseRequest(generateDataForComposer, validateDataForAge, errorHandlerForAge);
```

在这个例子中，我们正在将函数作为参数传递给`parseRequest()`函数。我们为两个不同的调用传递了不同的函数，`generateDataForScientist`和`generateDataForComposers`，而其他两个函数保持不变。你可以观察到我们定义了一个通用的`parseRequest()`。它接受三个函数作为参数，这些函数负责拼接具体内容：数据、验证器、和错误处理程序。`parseRequest()`函数是完全可扩展和可定制的，并且因为它将被每个请求调用，所以有一个单一、干净的调试点。我敢肯定你已经开始欣赏 JavaScript 函数所提供的强大功能。

# 作用域

对于初学者来说，JavaScript 的作用域稍微有些令人困惑。这些概念可能看起来很简单；然而，并非如此。存在一些重要的细微差别，必须理解才能掌握这个概念。那么作用域是什么？在 JavaScript 中，作用域指的是代码的当前上下文。

变量的作用域是变量存在的上下文。作用域指定你可以从哪里访问变量，以及在该上下文中你是否可以访问变量。作用域可以是全局定义的或局部定义的。

## 全局作用域

任何你声明的变量默认都在全局作用域中定义。这是 JavaScript 中采取的最令人烦恼的语言设计决策之一。由于全局变量在其他所有作用域中都是可见的，所以任何作用域都可以修改全局变量。全局变量使得在同一个程序/模块中运行松耦合的子程序变得更加困难。如果子程序碰巧有全局变量并且共享相同的名称，那么它们会相互干扰，并且很可能失败，通常以难以诊断的方式失败。这种情况有时被称为命名空间冲突。我们在前一章中讨论了全局作用域，但现在让我们简要地重新访问它，以了解如何最好地避免这种情况。

你可以用两种方法创建全局变量：

+   第一种方法是将 var 声明放在任何函数外部。本质上，任何在函数外部声明的变量都被定义在全局作用域中。

+   第二种方法是在声明变量时省略 var 声明（也称为隐式全局变量）。我认为这是为了方便新程序员而设计的，但结果却成了一个噩梦。即使在函数作用域内，如果你在声明变量时省略了 var 声明，它默认也是在全局作用域中创建的。这很糟糕。你总是应该让你程序运行于**ESLint**或**JSHint**，让他们标记出这样的违规行为。下面的示例展示了全局作用域的行为：

    ```js
    //Global Scope
    var a = 1;
    function scopeTest() {
      console.log(a);
    }
    scopeTest();  //prints 1
    ```

在这里，我们在函数外部声明了一个变量，并在全局作用域中。这个变量在`scopeTest()`函数中可用。如果你在函数作用域（局部）内给全局作用域变量赋新值，全局作用域中的原始值将被覆盖：

```js
//Global Scope
var a = 1;
function scopeTest() {
  a = 2; //Overwrites global variable 2, you omit 'var'
  console.log(a);
}
console.log(a); //prints 1
scopeTest();  //prints 2
console.log(a); //prints 2 (global value is overwritten)
```

## 局部作用域

与大多数编程语言不同，JavaScript 没有块级作用域（作用域限定在周围的括号内）；相反，JavaScript 有函数级作用域。函数内部声明的变量是局部变量，只能在函数内部或该函数内部的函数中访问：

```js
var scope_name = "Global";
function showScopeName () {
  // local variable; only accessible in this function
  var scope_name = "Local";
  console.log (scope_name); // Local
}
console.log (scope_name);     //prints - Global
showScopeName();             //prints – Local
```

## 函数作用域与块作用域

JavaScript 变量的作用域在函数级别。你可以将这看作是一个小气泡被创建出来，防止变量从这个气泡外部被看到。函数为在其内部声明的变量创建这样一个气泡。你可以这样想象气泡：

```js
-GLOBAL SCOPE---------------------------------------------|
var g =0;                                                 |
function foo(a) { -----------------------|                |
    var b = 1;                           |                |
    //code                               |                |
    function bar() { ------|             |                |
        // ...             |ScopeBar     | ScopeFoo       |
    }                ------|             |                |
    // code                              |                |
    var c = 2;                           |                |
}----------------------------------------|                |
foo();   //WORKS                                          |
bar();   //FAILS                                          |
----------------------------------------------------------|
```

JavaScript 使用作用域链来为给定函数建立作用域。通常有一个全局作用域，每个定义的函数都有自己的嵌套作用域。在另一个函数内部定义的任何函数都有一个局部作用域，它与外部函数链接。*源代码中的位置始终定义作用域*。在解析变量时，JavaScript 从最内层的作用域开始向外搜索。有了这个，让我们来看看 JavaScript 中的各种作用域规则。

在前面的粗略绘图视觉中，你可以看到`foo()`函数定义在全局作用域中。`foo()`函数在其局部作用域内有访问`g`变量的权限，因为它在全局作用域中。`a`、`b`和`c`变量在局部作用域内可用，因为它们是在函数作用域内定义的。`bar()`函数也在函数作用域内声明，并在`foo()`函数内可用。然而，一旦函数作用域结束，`bar()`函数就不可用了。你不能从`foo()`函数外部看到或调用`bar()`函数——一个作用域气泡。

现在`bar()`函数也有了自己的函数作用域（气泡），这里有什么可用？`bar()`函数可以访问`foo()`函数以及`foo()`函数的父作用域内创建的所有变量——`a`、`b`和`c`。`bar()`函数还可以访问全局作用域变量`g`。

这是一个强大的想法。花点时间思考一下。我们刚刚讨论了 JavaScript 中全局作用域可以变得多么泛滥和不受控制。那我们为什么不定性地将一段任意代码包裹在一个函数中呢？我们可以将这个作用域气泡隐藏起来，并围绕这段代码创建一个作用域气泡。使用函数包装来创建正确的作用域将有助于我们编写正确的代码，并防止难以检测的错误。

函数作用域和在此作用域内隐藏变量及函数的另一个优点是，你可以避免两个标识符之间的冲突。以下示例展示了这样一个糟糕的情况：

```js
function foo() {
  function bar(a) {
    i = 2; // changing the 'i' in the enclosing scope's for-loop
    console.log(a+i);
  }
  for (var i=0; i<10; i++) {
    bar(i); // infinite loop
  }
}
foo();
```

在`bar()`函数中，我们不知不觉地修改了`i=2`的值。当我们从`for`循环内部调用`bar()`时，`i`变量的值被设置为`2`，我们陷入了无限循环。这是一个命名空间冲突的坏例子。

到目前为止，使用函数作为作用域听起来是实现 JavaScript 模块化和正确性的好方法。嗯，虽然这种技术有效，但实际上并不理想。第一个问题是我们必须创建一个命名函数。如果我们只是为了引入函数作用域而不断创建这样的函数，我们就会污染全局作用域或父作用域。此外，我们必须不断调用这些函数。这引入了大量样板代码，使代码随时间变得不可读：

```js
var a = 1;
//Lets introduce a function -scope
//1\. Add a named function foo() into the global scope
function foo() { 
 var a = 2;
 console.log( a ); // 2
} 
//2\. Now call the named function foo()
foo();
console.log( a ); // 1
```

我们在全局作用域中创建了一个新的函数`foo()`，并通过调用这个函数后来执行代码。

在 JavaScript 中，你可以通过创建立即执行的函数来解决这两个问题。仔细研究和输入以下示例：

```js
var a = 1;
//Lets introduce a function -scope
//1\. Add a named function foo() into the global scope
(function foo() { 
 var a = 2;
 console.log( a ); // 2
})(); //<---this function executes immediately
console.log( a ); // 1
```

请注意，包装函数声明以`function`开头。这意味着，而不是将函数视为标准声明，而是将函数视为函数表达式。

`(function foo(){ })`表达式作为语句意味着`foo`标识符只存在于`foo()`函数的作用域中，而不是在外部作用域。隐藏`foo`名称本身意味着它不会不必要的污染外部作用域。这是非常有用且更好。我们在函数表达式后添加`()`以立即执行它。所以完整的模式如下所示：

```js
(function foo(){ /* code */ })();

```

这种模式如此常见，以至于它有一个名字：**IIFE**，代表**立即调用** **函数表达式**。许多程序员在使用 IIFE 时省略函数名称。由于 IIFE 的主要用途是引入函数作用域，因此实际上并不需要命名函数。我们可以像下面这样写先前的例子：

```js
var a = 1;
(function() { 
 var a = 2;
 console.log( a ); // 2
})(); 
console.log( a ); // 1
```

在这里，我们创建了一个匿名函数作为立即执行的函数表达式（IIFE）。虽然这与先前的命名 IIFE 相同，但使用匿名 IIFE 有几个缺点：

+   由于在堆栈跟踪中看不到函数名称，因此调试此类代码非常困难。

+   你不能对匿名函数使用递归（如我们之前讨论的）

+   过度使用匿名 IIFE 有时会导致代码不可读。

迪奥格斯·克劳福德（Douglas Crockford）和其他一些专家推荐 IIFE 的一小部分变化：

```js
(function(){ /* code */ }());
```

这两种 IIFE 形式都很流行，你将看到大量使用这两种变体的代码。

你可以向 IIFE 传递参数。以下示例展示了如何向 IIFE 传递参数：

```js
(function foo(b) { 
    var a = 2;
    console.log( a + b ); 
})(3); //prints 5
```

## 内联函数表达式

还有一种匿名函数表达式的流行用法，即把函数作为参数传递给其他函数：

```js
function setActiveTab(activeTabHandler, tab){
  //set active tab
  //call handler
  activeTabHandler();
}
setActiveTab( function (){ 
 console.log( "Setting active tab" );
}, 1 );
//prints "Setting active tab"
```

再次，你可以给这个内联函数表达式命名，以确保在调试代码时获得正确的堆栈跟踪。

## 块级作用域

正如我们之前讨论的，JavaScript 没有块作用域的概念。熟悉其他语言（如 Java 或 C）的程序员会觉得这非常不舒服。**ECMAScript 6**（**ES6**）引入了**let** 关键字来引入传统的块作用域。这非常方便，如果你确定你的环境将支持 ES6，你应该总是使用 `let` 关键字。以下代码所示：

```js
var foo = true;
if (foo) {
  let bar = 42; //variable bar is local in this block { }
  console.log( bar );
}
console.log( bar ); // ReferenceError
```

然而，截至目前，ES6 并不被大多数流行浏览器默认支持。

到目前为止，本章应该已经向你充分解释了 JavaScript 中作用域是如何工作的。如果你仍然不清楚，我建议你停在这里，重新阅读本章的早期部分。上网查找你的疑惑，或者在 Stack Overflow 上提出你的问题。总之，一定要确保你对作用域规则没有任何疑惑。

我们很容易认为代码执行是自上而下，逐行进行的。这是大多数 JavaScript 代码执行的方式，但有一些例外。

考虑以下代码：

```js
console.log( a );
var a = 1;
```

如果你说这是无效的代码，当我们调用 `console.log()` 时会得到 `undefined`，你完全正确。然而，这个呢？

```js
a = 1;
var a;
console.log( a );
```

preceding 代码的输出应该是什么？自然会期望 `undefined` 作为 `var a` 语句在 `a = 1` 之后，似乎自然地假设变量被重新定义并分配了默认的 `undefined`。然而，输出将是 `1`。

当你看到 `var a = 1` 时，JavaScript 将其拆分为两个语句：`var a` 和 `a = 1`。第一个语句，声明，在编译阶段处理。第二个语句，赋值，在执行阶段保持原位。

所以，前面的片段实际上将按以下方式执行：

```js
var a;   //----Compilation phase

a = 1;    //------execution phase
console.log( a );
```

第一个片段实际上按以下方式执行：

```js
var a;     //-----Compilation phase

console.log( a );   
a = 1;     //------execution phase  
```

所以，如我们所见，变量和函数声明在编译阶段被移动到代码的顶部——这也被称为**提升**。非常重要记住的是，只有声明本身被提升，而任何赋值或其他可执行逻辑都保持原位。以下片段展示了函数声明是如何被提升的：

```js
foo();
function foo() {
  console.log(a); // undefined
  var a = 1;
}
```

`foo()` 函数的声明被提升，以至于我们能够在定义它之前执行该函数。提升的一个重要方面是它按作用域工作。在 `foo()` 函数内部，变量的声明将被提升到 `foo()` 函数的顶部，而不是程序的顶部。利用提升执行 `foo()` 函数的实际代码如下：

```js
function foo() {
  var a;
  console.log(a); // undefined
  a = 1;
}
```

我们看到了函数声明被提升，但函数表达式不会。下一节解释了这个案例。

# 函数声明与函数表达式

我们看到了定义函数的两种方式。虽然它们都服务于相同的目的，但这些两种声明之间存在差异。查看下面的例子：

```js
//Function expression
functionOne();
//Error
//"TypeError: functionOne is not a function

var functionOne = function() {
  console.log("functionOne");
};
//Function declaration
functionTwo();
//No error
//Prints - functionTwo

function functionTwo() {
  console.log("functionTwo");
}
```

```js
sayMoo() but such a conditional code is not guaranteed to work across all browsers and can result in unpredictable results:
```

```js
// Never do this - different browsers will behave differently
if (true) {
  function sayMoo() {
    return 'trueMoo';
  }
}
else {
  function sayMoo() {
    return 'falseMoo';
  }
}
foo();
```

然而，用函数表达式这样做是完全安全且明智的：

```js
var sayMoo;
if (true) {
  sayMoo = function() {
    return 'trueMoo';
  };
}
else {
  sayMoo = function() {
    return 'falseMoo';
  };
}
foo();
```

如果你好奇想知道为什么不应该在条件块中使用函数声明，请继续阅读；否则，你可以跳过下面的段落。

函数声明只能出现在程序或函数体中。它们不能出现在块（`{ ... }`）中。块只能包含语句，不能包含函数声明。由于这个原因，几乎所有 JavaScript 的实现都有与这个不同的行为。建议*永远*不要在条件块中使用函数声明。

另一方面，函数表达式非常流行。在 JavaScript 程序员中，基于某种条件对函数定义进行分叉是一个非常常见的模式。由于这样的分叉通常发生在同一作用域中，几乎总是需要使用函数表达式。

# `arguments`参数

`arguments`参数包含了所有传递给函数的参数。这个集合有一个名为`length`的属性，包含了参数的数量，单个参数的值可以使用数组索引表示法来获取。好吧，我们有点撒谎。`arguments`参数不是一个 JavaScript 数组，如果你尝试在`arguments`上使用数组方法，你会失败得很惨。你可以把`arguments`看作是一个类似数组结构。这使得能够编写接受不确定数量参数的函数成为可能。下面的片段展示了如何向函数传递可变数量的参数，并使用`arguments`数组遍历它们：

```js
var sum = function () { 
  var i, total = 0;
  for (i = 0; i < arguments.length; i += 1) {
    total += arguments[i];
  }
  return total;
};
console.log(sum(1,2,3,4,5,6,7,8,9)); // prints 45
console.log(sum(1,2,3,4,5)); // prints 15
```

正如我们讨论的，`arguments`参数并不是一个真正的数组；可以像下面这样将其转换为数组：

```js
var args = Array.prototype.slice.call(arguments);
```

一旦转换为数组，你可以随意操作列表。

## 这个参数

每当函数被调用时，除了代表在函数调用中提供的显式参数之外，还会隐式地传递一个名为`this`的参数给函数。它指的是与函数调用隐式相关联的对象，称为**函数上下文**。如果你编过 Java 代码，`this`关键字对你来说会很熟悉；就像 Java 一样，`this`指向定义方法类实例。

有了这些知识，让我们来谈谈各种调用方法。

### 作为函数的调用

如果一个函数不是作为方法、构造函数，或者通过`apply()`或`call()`调用，它就简单地以*函数*的形式调用：

```js
function add() {}
add();
var substract = function() {

};
substract();
```

当一个函数以这种模式调用时，`this`绑定到全局对象。许多专家认为这是一个糟糕的设计选择。自然地，我们可能会认为`this`会被绑定到父上下文。当你处于这种情况时，你可以将`this`的值捕获到另一个变量中。我们稍后重点关注这种模式。

### 作为方法调用

方法是与对象上的属性绑定的函数。对于方法来说，在调用时`this`绑定到调用对象上：

```js
var person = {
  name: 'Albert Einstein',
  age: 66,
  greet: function () {
    console.log(this.name);
  }
};
person.greet();
```

在这个例子中，当调用`greet`时`this`绑定到`person`对象上，因为`greet`是`person`的一个方法。让我们看看这两种调用模式下这种行为是如何表现的。

让我们准备这个 HTML 和 JavaScript harness：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>This test</title>
  <script type="text/javascript">
 function testF(){ return this; }
 console.log(testF()); 
 var testFCopy = testF;
 console.log(testFCopy()); 
 var testObj = {
 testObjFunc: testF
 };
 console.log(testObj.testObjFunc ());
  </script>
</head>
<body>
</body>
</html>
```

在**Firebug**控制台中，你可以看到以下输出：

![作为方法的调用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00006.jpeg)

前两个方法调用都是作为函数调用；因此，`this`参数指向全局上下文（在这个例子中是`Window`）。

接下来，我们定义了一个名为`testObj`的变量，它有一个名为`testObjFunc`的属性，该属性接收对`testF()`的引用——如果你现在还不清楚对象是如何创建的，也不要担心。这样做，我们创建了一个`testObjMethod()`方法。现在，当我们调用这个方法时，我们期望当显示`this`的值时显示函数上下文。

### 作为构造函数的调用

**构造函数**的声明与其他任何函数一样，即将作为构造函数的函数也没有什么特别之处。然而，它们的调用方式却大不相同。

要作为构造函数调用函数，我们在函数调用前加上**new**关键字。当这样做时，`this`绑定到新对象上。

在我们讨论更多之前，让我们先快速介绍一下 JavaScript 中的面向对象。当然，我们将在下一章中详细讨论这个话题。JavaScript 是一种基于原型继承的语言。这意味着对象可以直接从其他对象继承属性。这种语言是无类的。设计为用`new`前缀调用的函数称为构造函数。通常，为了更容易区分，它们使用**帕斯卡命名法**而不是**驼峰命名法**。在下面的例子中，注意`greet`函数使用`this`来访问`name`属性。`this`参数绑定到`Person`上：

```js
var Person = function (name) {
  this.name = name;
};
Person.prototype.greet = function () {
  return this.name;
};
var albert = new Person('Albert Einstein');
console.log(albert.greet());
```

我们将在下一章学习对象时讨论这种特定的调用方法。

### 使用`apply()`和`call()`方法调用

我们之前说过，JavaScript 函数是对象。与其他对象一样，它们也有一些特定的方法。要使用`apply()`方法调用函数，我们向`apply()`传递两个参数：作为函数上下文的对象和一个作为调用参数的数组。`call()`方法的用法类似，不同之处在于参数是直接在参数列表中传递，而不是作为数组。

# 匿名函数

我们在这章的早些时候向你介绍了匿名函数，因为它们是一个关键概念，所以我们将详细介绍它们。对于受 Scheme 启发的语言来说，匿名函数是一个重要的逻辑和结构构建。

匿名函数通常用于函数不需要在稍后引用的情况下。让我们看看匿名函数的一些最流行的使用情况。

## 在创建对象时使用匿名函数

匿名函数可以赋值给对象属性。这样做时，我们可以使用点（`.`）运算符调用该函数。如果你来自 Java 或其他面向对象语言的背景，你会发现这非常熟悉。在这样 languages, a function, which is part of a class is generally called with a notation—`Class.function()`. Let's consider the following example:

```js
var santa = {
  say :function(){ 
    console.log("ho ho ho"); 
  }
}
santa.say();
```

在这个例子中，我们创建了一个具有`say`属性的对象，该属性是一个匿名函数。在这个特定情况下，这个属性被称为方法而不是函数。我们不需要给这个函数命名，因为我们打算将其作为对象属性调用。这是一个流行的模式，应该会派上用场。

## 在创建列表时使用匿名函数

在这里，我们创建了两个匿名函数并将它们添加到一个数组中。（我们稍后会对数组进行详细介绍。）然后，你遍历这个数组并在循环中执行这些函数：

```js
<script type="text/javascript">
var things = [
  function() { alert("ThingOne") },
  function() { alert("ThingTwo") },
];
for(var x=0; x<things.length; x++) {
  things[x]();
}
</script>
```

## 将匿名函数作为另一个函数的参数

这是最流行的模式之一，你会在大多数专业库中找到这样的代码：

```js
// function statement
function eventHandler(event){
  event();
}

eventHandler(function(){
  //do a lot of event related things
  console.log("Event fired");
});
```

你将匿名函数传递给另一个函数。在接收函数中，你执行作为参数传递的函数。如果你正在创建一次性函数，例如对象方法或事件处理程序，这会非常方便。与先声明一个函数然后将其作为两个单独的步骤进行处理相比，匿名函数语法更为简洁。

## 在条件逻辑中使用匿名函数

你可以使用匿名函数表达式来条件性地改变行为。以下示例展示了这种模式：

```js
var shape;
if(shape_name === "SQUARE") {
  shape = function() {
    return "drawing square";
  }
}
else {
  shape = function() {
    return "drawing square";
  }
}
alert(shape());
```

在这里，根据条件，我们将不同的实现分配给`shape`变量。如果使用得当，这种模式非常有用。过度使用可能导致代码难以阅读和调试。

在这本书的后面部分，我们将探讨几种函数式技巧，例如**记忆化**和缓存函数调用。如果你是快速浏览了整个章节后到达这里的，我建议你停一下，思考一下我们迄今为止讨论的内容。最后几页包含了大量信息，所有这些信息需要一段时间才能吸收。我建议你在继续之前重新阅读这一章。下一节将重点介绍闭包和模块模式。

# 闭包

传统上，闭包一直是纯函数式编程语言的一个特性。JavaScript 通过将闭包视为核心语言结构的一部分，显示了它与这类函数式编程语言的亲和力。闭包在主流 JavaScript 库和高级生产代码中越来越受欢迎，因为它们可以帮助你简化复杂操作。你会在经验丰富的 JavaScript 程序员那里听到他们对闭包几乎带有敬畏的谈论——仿佛闭包是超出了普通人智力范围的一些神奇构造。然而，事实并非如此。当你研究这个概念时，你会发现闭包其实非常明显，几乎是不言自明。在你达到闭包的顿悟之前，我建议你多次阅读这一章节，上网查找资料，编写代码，阅读 JavaScript 库，以了解闭包的行为——但不要放弃。

你首先必须认识到的是，闭包在 JavaScript 中无处不在。它并不是语言中一个隐藏的特殊部分。

在我们深入细节之前，让我们快速回顾一下 JavaScript 中的词法作用域。我们详细讨论了在 JavaScript 中如何根据函数级别确定词法作用域。词法作用域基本上决定了所有标识符在哪里以及如何声明，并预测在执行期间它们如何被查找。

简而言之，闭包是当一个函数被声明时创建的上下文，它允许函数访问和操作位于该函数之外的变量。换句话说，闭包允许函数访问在自己声明时处于作用域内的所有变量及其他函数。

让我们通过一些示例代码来理解这个定义：

```js
var outer = 'I am outer'; //Define a value in global scope
function outerFn() { //Declare a a function in global scope
  console.log(outer);
}
outerFn(); //prints - I am outer
```

你期待一些闪亮的东西吗？不，这真的是闭包最普通的情况。我们在全局作用域中声明一个变量，并在全局作用域中声明一个函数。在函数中，我们能够访问在全局作用域中声明的变量——`outer`。所以，本质上，`outerFn()`函数的外部作用域就是一个闭包，并且始终对`outerFn()`可用。这是一个不错的开始，但也许你还不确定为什么这是一件多么伟大的事情。

让我们让事情变得复杂一些：

```js
var outer = 'Outer'; //Variable declared in global scope
var copy;
function outerFn(){  //Function declared in global scope

  var inner = 'Inner'; //Variable has function scope only, can not be
  //accessed from outside 

  function innerFn(){     //Inner function within Outer function, 
    //both global context and outer
    //context are available hence can access 
    //'outer' and 'inner'
    console.log(outer);
    console.log(inner);
  }
  copy=innerFn;          //Store reference to inner function, 
  //because 'copy' itself is declared
  //in global context, it will be available 
  //outside also
}
outerFn();
copy();  //Cant invoke innerFn() directly but can invoke via a 
//variable declared in global scope
```

是什么现象使得在`innerFn()`内部函数执行时，即使它创建的作用域已经消失很久，`inner`变量仍然可用？当我们在`outerFn()`中声明`innerFn()`时，不仅函数声明被定义，而且还创建了一个闭包，它不仅包含函数声明，还包括声明时处于作用域内的所有变量。当`innerFn()`执行时，即使它是在自己声明的作用域消失后执行，它仍然可以通过闭包访问到自己声明时的原始作用域。

让我们继续扩展这个示例，以了解你可以使用闭包做到何种程度：

```js
var outer='outer';
var copy;
function outerFn() {
  var inner='inner';
  function innerFn(param){
    console.log(outer);
    console.log(inner);
 console.log(param);
 console.log(magic);
  }
  copy=innerFn;
}
console.log(magic); //ERROR: magic not defined
var magic="Magic";
outerFn();
copy("copy");
```

在前面的示例中，我们添加了一些东西。首先，我们在`innerFn()`中添加了一个参数——只是为了说明参数也是闭包的一部分。我们有两个重要的点想要强调。

即使在外层作用域中声明变量是在函数声明之后，外层作用域中的所有变量也会被包含在内。这使得`innerFn()`中的行`console.log(magic)`可以正常工作。

然而，在全局作用域中相同的行`console.log(magic)`将失败，因为即使在相同的作用域中，尚未定义的变量也不能引用。

所有这些示例都是为了传达一些关于闭包如何工作的概念。闭包是 JavaScript 语言中的一个突出特性，您可以在大多数库中看到它们。

让我们看看一些关于闭包的流行模式。

# 定时器和回调

在实现定时器或回调时，您需要异步调用处理程序，通常在稍后的时间点。由于异步调用，我们需要从这些函数外部访问变量。考虑以下示例：

```js
function delay(message) {
  setTimeout( function timerFn(){
    console.log( message );
  }, 1000 );
}
delay( "Hello World" );
```

我们将内部`timerFn()`函数传递给内置库函数`setTimeout()`。然而，`timerFn()`对外层`delay()`作用域有闭包，因此它可以引用变量 message。

# 私有变量

闭包经常用来封装一些作为私有变量的信息。JavaScript 不允许像 Java 或 C++这样的编程语言中的封装，但通过使用闭包，我们可以实现类似的封装：

```js
function privateTest(){
 var points=0;
  this.getPoints=function(){
    return points;
  };
  this.score=function(){
    points++;
  };
}

var private = new privateTest();
private.score();
console.log(private.points); // undefined
console.log(private.getPoints());
```

在前面的示例中，我们创建了一个打算作为构造函数调用的函数。在这个`privateTest()`函数中，我们创建了一个名为`var points=0`的变量作为函数作用域变量。这个变量仅在`privateTest()`中可用。此外，我们创建了一个访问器函数（也称为获取器）——`getPoints()`——这个方法允许我们从`privateTest()`外部只读取点变量的一个值，使得这个变量成为函数的私有变量。然而，另一个方法`score()`允许我们不直接从外部访问的情况下修改私有点变量值。这使得我们可以编写代码，以受控的方式更新私有变量。当您编写基于合同和预定义接口控制变量访问的库时，这种模式非常有用。

# 循环和闭包

考虑以下在循环中使用函数的示例：

```js
for (var i=1; i<=5; i++) {
  setTimeout( function delay(){
    console.log( i );
  }, i*100);
}
```

```js
print 1, 2, 3, 4, and 5 on the console at an interval of 100 ms, right? Instead, it prints 6, 6, 6, 6, and 6 at an interval of 100 ms. Why is this happening? Here, we encounter a common issue with closures and looping. The i variable is being updated after the function is bound. This means that every bound function handler will always print the last value stored in i. In fact, the timeout function callbacks are running after the completion of the loop. This is such a common problem that JSLint will warn you if you try to use functions this way inside a loop.
```

我们如何修复这种行为？我们可以在作用域中引入一个函数作用域和局部复制的`i`变量。以下代码片段向您展示了我们如何这样做：

```js
for (var i=1; i<=5; i++) {
  (function(j){
    setTimeout( function delay(){
      console.log( j );
    }, j*100);
  })( i );
}
```

我们在 IIFE 中传递了`i`变量，并将其复制到局部变量`j`中。在每次迭代中引入 IIFE 可以为新迭代创建一个新的作用域，从而更新具有正确值的局部副本。

# 模块

模块用于模仿类，并专注于变量和函数的公共和私有访问。模块有助于减少全局作用域的污染。有效使用模块可以减少大型代码库中的名称冲突。这种模式采取的典型格式如下：

```js
Var moduleName=function() {
  //private state
  //private functions
  return {
     //public state
     //public variables
  }
}
```

要在此前格式中实现此模式，有两个要求：

+   必须有一个外部闭合函数至少执行一次。

+   这个闭合函数必须至少返回一个内部函数。这是创建对私有状态的闭包所必需的——没有它，你根本无法访问私有状态。

检查以下模块示例：

```js
var superModule = (function (){
  var secret = 'supersecretkey';
  var passcode = 'nuke';

  function getSecret() {
    console.log( secret );
  }

  function getPassCode() {
    console.log( passcode );
  }

  return {
    getSecret: getSecret,
    getPassCode: getPassCode
  };
})();
superModule.getSecret();
superModule.getPassCode();
```

这个示例满足两个条件。首先，我们创建一个 IIFE 或命名函数作为外部闭合。定义的变量将保持私有，因为它们在函数作用域内。我们返回公共函数，以确保我们对私有作用域有闭包。在模块模式中使用 IIFE 将实际上导致这个函数的单例实例。如果你想要创建多个实例，你也可以创建作为模块一部分的命名函数表达式。

我们将继续探索 JavaScript 函数方面的各种方面，特别是闭包。这种优雅结构可以有大量的创新用途。理解各种模式的有效方式是研究流行库的代码并在你的代码中实践这些模式。

## 风格上的考虑

正如前章所述，我们将以某些风格上的考虑来结束这次讨论。再次说明，这些通常是公认的指导原则，而非规则——如果你有理由相信其他情况，请随意偏离它们：

+   使用函数声明，而不是函数表达式：

    ```js
    // bad
    const foo = function () {
    };

    // good
    function foo() {
    }
    ```

+   永远不要在非函数块中声明一个函数（if，while 等）。相反，将函数赋值给一个变量。浏览器允许这样做，但它们的解释各不相同。

+   永远不要将参数命名为`arguments`。这将优先于给予每个函数作用域的`arguments`对象。

# 总结

在本章中，我们学习了 JavaScript 函数。在 JavaScript 中，函数扮演着至关重要的角色。我们讨论了函数是如何创建和使用的。我们还讨论了闭包和函数作用域中变量的 scope 的重要概念。我们讨论了函数作为创建可见类和封装的方法。

在下一章中，我们将查看 JavaScript 中的各种数据结构和数据操作技术。
