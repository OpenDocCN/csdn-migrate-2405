# jQuery、Rails 和 Node 的 CoffeeScript 编程（一）

> 原文：[`zh.annas-archive.org/md5/0B0062B2422D4B29BA6F761E6D36A199`](https://zh.annas-archive.org/md5/0B0062B2422D4B29BA6F761E6D36A199)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

JavaScript 是由 Brendan Eich 在 1995 年左右在网景工作时编写的一种古怪的小语言。它是第一种基于浏览器的脚本语言，当时只在网景导航器中运行，但最终它找到了自己的位置，进入了大多数其他的 Web 浏览器。当时，网页几乎完全由静态标记组成。JavaScript（最初名为 LiveScript）的出现是因为需要使页面动态化，并为浏览器开发人员带来完整脚本语言的功能。

语言的许多设计决策都是出于简单和易用的需要，尽管当时有些决策纯粹是出于网景的营销原因。选择“JavaScript”这个名字是为了将它与 Sun Microsystems 的 Java 联系起来，尽管事实上 Sun 与之无关，而且它在概念上与 Java 有很大不同。

除了一种方式，即大部分语法都是从 Java、C 和 C++中借鉴而来，以便让那些熟悉这些语言的程序员感到熟悉。但尽管看起来相似，实际上它在内部是一个非常不同的东西，并且具有与更奇特的语言（如 Self、Scheme 和 Smalltalk）相似的特征。其中包括动态类型、原型继承、一级函数和闭包。

因此，我们最终得到了一种看起来很像当时的一些主流语言，并且可以被迫以与它们非常不同的中心思想行事的语言。这导致它在很多年里被人们误解。很多程序员从未将它视为一种“严肃”的编程语言，因此在编写浏览器代码时，他们没有应用几十年来积累的许多最佳开发实践。

那些深入研究这门语言的人肯定会发现很多奇怪之处。Eich 本人承认，这门语言的原型大约在 10 天内完成，尽管他的成果令人印象深刻，但 JavaScript 并非没有（很多）缺陷。这些缺陷并没有真正有助于提升它的声誉。

尽管存在所有这些问题，JavaScript 仍然成为世界上最广泛使用的编程语言之一，这不仅仅是因为互联网的爆炸和 Web 浏览器的普及。在众多浏览器上的支持似乎是一件好事，但它也因为在语言和 DOM 的实现上的差异而造成了混乱。

大约在 2005 年，AJAX 这个术语被创造出来，用来描述一种 JavaScript 编程风格，这种风格是由浏览器中`XMLHTTPRequest`对象的引入所可能的。这意味着开发人员可以编写客户端代码，直接使用 HTTP 与服务器通信，并在不重新加载页面的情况下更新页面元素。这真的是语言历史上的一个转折点。突然之间，它被用于“严肃”的 Web 应用程序，并且人们开始以不同的方式看待这门语言。

2006 年，John Resig 向世界发布了 jQuery。它旨在简化客户端脚本编写、DOM 操作和 AJAX，以及抽象掉许多浏览器之间的不一致性。它成为了许多 JavaScript 程序员的必备工具。迄今为止，它在全球前 10,000 个网站中被使用了 55%。

2009 年，Ryan Dahl 创建了 Node.js，这是一个基于 Google V8 JavaScript 引擎编写的事件驱动网络应用程序框架。它迅速变得非常流行，特别是用于编写 Web 服务器应用程序。它成功的一个重要因素是，现在你可以在服务器上编写 JavaScript，而不仅仅是在浏览器中。围绕这个框架形成了一个复杂而杰出的社区，目前 Node.js 的未来看起来非常光明。

2010 年初，Jeremy Ashkenas 创建了 CoffeeScript，这是一种编译成 JavaScript 的语言。它的目标是创建更清洁、更简洁、更惯用的 JavaScript，并使其更容易使用语言的更好特性和模式。它摒弃了 JavaScript 的许多语法冗长，减少了行噪音，通常创建了更短更清晰的代码。

受到 Ruby、Python 和 Haskell 等语言的影响，它借用了这些语言的一些强大和有趣的特性。尽管它看起来可能相当不同，但 CoffeeScript 代码通常与生成的 JavaScript 非常接近。它已经成为一夜成功，很快被 Node.js 社区采纳，并被包含在 Ruby on Rails 3.1 中。

Brendan Eich 也表达了对 CoffeeScript 的钦佩，并将其用作他希望在未来版本的 JavaScript 中看到的一些东西的例子。

本书既是对该语言的介绍，也是为什么您应该在尽可能的地方使用 CoffeeScript 而不是 JavaScript 的动机。它还探讨了在浏览器中使用 CoffeeScript 使用 jQuery 和 Ruby on Rails，以及在服务器上使用 Node.js。

# 本书涵盖的内容

第一章，为什么使用 CoffeeScript，介绍了 CoffeeScript 并深入探讨了它与 JavaScript 之间的区别，特别关注 CoffeeScript 旨在改进的 JavaScript 部分。

第二章，运行 CoffeeScript，简要介绍了 CoffeeScript 堆栈以及它通常是如何打包的。您将学习如何在 Windows、Mac 和 Linux 上使用 Node.js 和 npm 安装 CoffeeScript。您将了解 CoffeeScript 编译器（`coffee`）以及熟悉一些有用的工具和日常开发资源。

第三章，CoffeeScript 和 jQuery，介绍了使用 jQuery 和 CoffeeScript 进行客户端开发。我们还开始使用这些技术来实现本书的示例应用程序。

第四章，CoffeeScript 和 Rails，首先简要概述了 Ruby on Rails 及其与 JavaScript 框架的历史。我们介绍了 Rails 3.1 中的 Asset Pipeline 以及它如何与 CoffeeScript 和 jQuery 集成。然后我们使用 Rails 为我们的示例应用程序添加后端。

第五章，CoffeeScript 和 Node.js，首先简要概述了 Node.js，它的历史和哲学。然后演示了使用 Node.js 在 CoffeeScript 中编写服务器端代码有多么容易。然后我们使用 WebSockets 和 Node.js 实现了示例应用程序的最后一部分。

# 你需要什么来阅读本书

要使用本书，您需要一台运行 Windows、Mac OS X 或 Linux 的计算机和一个基本的文本编辑器。在整本书中，我们将从互联网上下载一些我们需要的软件，所有这些软件都将是免费和开源的。

# 这本书适合谁

这本书适合现有的 JavaScript 程序员，他们想了解更多关于 CoffeeScript 的知识，或者有一些编程经验并想了解更多关于使用 CoffeeScript 进行 Web 开发。它还是 jQuery、Ruby on Rails 和 Node.js 的绝佳入门书籍。即使您有这些框架中的一个或多个的经验，本书也会向您展示如何使用 CoffeeScript 使您的体验变得更好。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词显示如下：“您会发现`if`语句的子句不需要用括号括起来”。

代码块设置如下：

```js
gpaScoreAverage = (scores...) ->
   total = scores.reduce (a, b) -> a + b
   total / scores.length 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
create: (e) ->
    $input = $(event.target)
    val = ($.trim $input.val())
```

任何命令行输入或输出都以以下方式书写：

```js
coffee -co public/js -w src/

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中以这种方式出现："页脚将有**清除已完成**按钮"。

### 注意

警告或重要提示会以这样的框出现。

### 提示

提示和技巧会以这种方式出现。


# 第一章：为什么使用 CoffeeScript？

CoffeeScript 编译成 JavaScript，并且紧密遵循其习惯用法。完全可以将任何 CoffeeScript 代码重写为 JavaScript，它们看起来并不会有很大的不同。那么为什么要使用 CoffeeScript 呢？

作为一名有经验的 JavaScript 程序员，你可能认为学习一个全新的语言根本不值得时间和精力。

但最终，代码是给程序员看的。编译器不在乎代码的外观或清晰的含义；它要么运行，要么不运行。我们的目标是作为程序员编写表达性强的代码，这样我们就可以阅读、引用、理解、修改和重写它。

如果代码过于复杂或充满了不必要的仪式，那么理解和维护将会更加困难。CoffeeScript 给了我们一个优势，可以澄清我们的想法并编写更易读的代码。

认为 CoffeeScript 与 JavaScript 非常不同是一种误解。可能在某些地方会有一些极端的语法差异，但本质上，CoffeeScript 旨在打磨 JavaScript 的粗糙边缘，揭示其中隐藏的美丽语言。它引导程序员走向 JavaScript 的所谓“好部分”，并对构成良好 JavaScript 的内容持有坚定的看法。

CoffeeScript 社区的口头禅之一是：“它只是 JavaScript”，我也发现真正理解这种语言的最佳方法是看它是如何生成输出的，实际上生成的代码相当可读和易懂。

在本章中，我们将重点介绍两种语言之间的一些差异，通常关注 JavaScript 中 CoffeeScript 试图改进的内容。

通过这种方式，我不仅想给你一个关于该语言主要特性的概述，还想让你能够在更频繁地使用它后，能够调试生成的代码，以及能够转换现有的 JavaScript。

让我们从 CoffeeScript 修复 JavaScript 中的一些问题开始。

# CoffeeScript 语法

CoffeeScript 的一大优点是，你写的程序通常比在 JavaScript 中写的要短得多，更简洁。部分原因是语言中添加了强大的功能，但它也对 JavaScript 的一般语法进行了一些调整，使其变得相当优雅。它取消了所有的分号、大括号和其他通常导致 JavaScript 中很多“线噪音”的东西。

为了说明这一点，让我们看一个例子。下表的左侧是 CoffeeScript，右侧是生成的 JavaScript：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
fibonacci = (n) ->
 return 0 if n == 0
 return 1 if n == 1
 (fibonacci n-1) + (fibonacci n-2)

alert fibonacci 10
```

|

```js
var fibonacci;

fibonacci = function(n) {
  if (n === 0) {
    return 0;
  }
  if (n === 1) {
    return 1;
  }
  return (fibonacci(n - 1)) + (fibonacci(n - 2));
}; 

alert(fibonacci(10));
```

|

要运行本章中的代码示例，可以使用伟大的**尝试 CoffeeScript**在线工具，网址为[`coffeescript.org`](http://coffeescript.org)。它允许你输入 CoffeeScript 代码，然后在侧边栏显示相应的 JavaScript。你也可以直接从浏览器中运行代码（点击左上角的**运行**按钮）。如果你更喜欢先在计算机上运行 CoffeeScript 来运行示例，请跳到下一章，然后安装好 CoffeeScript 再回来。该工具如下截图所示：

![CoffeeScript 语法](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_01_01.jpg)

起初，这两种语言可能看起来截然不同，但希望随着我们对比差异，你会发现它们仍然是 JavaScript，只是进行了一些小的调整和大量的语法糖。

## 分号和大括号

你可能已经注意到，CoffeeScript 取消了所有行末的分号。如果想要在一行上放两个表达式，仍然可以使用分号。它还取消了代码块的大括号（也称为花括号），比如`if`语句、`switch`和`try..catch`块。

## 空格

你可能想知道解析器如何确定代码块的起始和结束位置。CoffeeScript 编译器通过使用语法空格来实现这一点。这意味着缩进用于分隔代码块，而不是大括号。

这可能是该语言最具争议的特性之一。如果你仔细想想，在几乎所有的语言中，程序员倾向于使用代码块的缩进来提高可读性，那么为什么不将其作为语法的一部分呢？这并不是一个新概念，而是大部分借鉴自 Python。如果你有任何与显著空白语言的经验，你将不会对 CoffeeScript 的缩进感到困扰。

如果不这样做，可能需要一些时间来适应，但这样做可以使代码非常易读和易于扫描，同时减少了很多按键。我敢打赌，如果你花时间克服一些可能存在的初步保留，你可能会喜欢块缩进。

### 注意

块可以使用制表符或空格进行缩进，但要注意一致使用其中一种，否则 CoffeeScript 将无法正确解析您的代码。

## 括号

你会发现`if`语句的子句不需要用括号括起来。`alert`函数也是一样；你会发现单个字符串参数跟在函数调用后面，也没有括号。在 CoffeeScript 中，带参数的函数调用、`if..else`语句的子句以及`while`循环的括号都是可选的。

虽然带参数的函数不需要括号，但在可能存在歧义的情况下使用括号仍然是一个好主意。CoffeeScript 社区提出了一个不错的习惯：将整个函数调用包装在括号中。在下表中显示了在 CoffeeScript 中使用`alert`函数：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
alert square 2 * 2.5 + 1

alert (square 2 * 2.5) + 1
```

|

```js
alert(square(2 * 2.5 + 1));

alert((square(2 * 2.5)) + 1);
```

|

在 JavaScript 中，函数是一等对象。这意味着当你引用一个没有括号的函数时，它将返回函数本身作为值。因此，在 CoffeeScript 中，当调用没有参数的函数时，仍然需要添加括号。

通过对 JavaScript 的语法进行这些小调整，CoffeeScript 可以说已经大大提高了代码的可读性和简洁性，并且还节省了大量的按键。

但它还有一些其他的技巧。大多数写过大量 JavaScript 的程序员可能会同意，最频繁输入的短语之一应该是函数定义`function(){}`。函数确实是 JavaScript 的核心，但也不是没有缺点。

# CoffeeScript 具有出色的函数语法

你可以将函数视为一等对象，也可以创建匿名函数，这是 JavaScript 最强大的特性之一。然而，语法可能非常笨拙，使得代码难以阅读（特别是如果你开始嵌套函数）。但是 CoffeeScript 对此有解决方法。看一下以下代码片段：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
-> alert 'hi there!'
square = (n) -> n * n
```

|

```js
var square;
(function() {
  return alert('hi there!');
});
square = function(n) {
  return n * n;
};
```

|

在这里，我们创建了两个匿名函数，第一个只显示一个对话框，第二个将返回其参数的平方。你可能已经注意到了有趣的`->`符号，并可能已经弄清楚了它的作用。是的，这就是你在 CoffeeScript 中定义函数的方式。我遇到过一些不同的符号名称，但最被接受的术语似乎是一个细箭头或者只是一个箭头。这与粗箭头相对，我们稍后会讨论。

请注意，第一个函数定义没有参数，因此我们可以省略括号。第二个函数有一个参数，括号括起来，放在`->`符号前面。根据我们现在所知道的，我们可以制定一些简单的替换规则，将 JavaScript 函数声明转换为 CoffeeScript。它们如下：

+   用`->`替换`function`关键字

+   如果函数没有参数，去掉括号

+   如果有参数，请将整个参数列表与括号一起移到`->`符号前面

+   确保函数体正确缩进，然后去掉括号

## 不需要返回

您可能已经注意到，在这两个函数中，我们都省略了`return`关键字。默认情况下，CoffeeScript 将返回函数中的最后一个表达式。它将尝试在所有执行路径中执行此操作。CoffeeScript 将尝试将任何语句（返回空值的代码片段）转换为返回值的表达式。CoffeeScript 程序员经常通过说语言的所有内容都是表达式来提到语言的这个特性。

这意味着您不再需要输入`return`，但请记住，这可能会在许多情况下微妙地改变您的代码，因为您总是会返回某些东西。如果需要在最后一个语句之前从函数返回一个值，仍然可以使用`return`。

## 函数参数

函数参数也可以采用可选的默认值。在下面的代码片段中，您将看到指定的可选值被分配在生成的 Javascript 的主体中：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
square = (n=1) ->
  alert(n * n)
```

|

```js
var square;

square = function(n) {
  if (n == null) {
    n = 1;
  }
  return alert(n * n);
};
```

|

在 JavaScript 中，每个函数都有一个类似数组的结构，称为`arguments`，其中为传递给函数的每个参数都有一个索引属性。您可以使用`arguments`向函数传递可变数量的参数。每个参数都将成为 arguments 中的一个元素，因此您不必按名称引用参数。

尽管`arguments`对象在某种程度上类似于数组，但它实际上不是一个“真正”的数组，并且缺少大部分标准数组方法。通常，您会发现`arguments`无法提供检查和操作其元素所需的功能，就像它们与数组一起使用一样。

这迫使许多程序员使用一个小技巧，即使`Array.prototype.slice`复制`argument`对象元素，或者使用`jQuery.makeArray`方法创建一个标准数组，然后可以像正常数组一样使用。

CoffeeScript 借用了从参数创建数组的模式，这些参数由三个点(`...`)表示。这些在下面的代码片段中显示：

**CoffeeScript:**

```js
gpaScoreAverage = (scores...) ->
   total = scores.reduce (a, b) -> a + b
   total / scores.length

alert gpaScoreAverage(65,78,81)
scores = [78, 75, 79]
alert gpaScoreAverage(scores...)
```

**JavaScript:**

```js
var gpaScoreAverage, scores,
  __slice = [].slice;

gpaScoreAverage = function() {
  var scores, total;
  scores = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
  total = scores.reduce(function(a, b) {
    return a + b;
  });
  return total / scores.length;
};

alert(gpaScoreAverage(65, 78, 81));
scores = [78, 75, 79];
alert(gpaScoreAverage.apply(null, scores));
```

注意，在函数定义中，参数后面跟着`...`。这告诉 CoffeeScript 允许可变参数。然后可以使用参数列表或跟随`...`的数组来调用函数。

## var 关键字去哪了？

在 JavaScript 中，通过在声明它们的时候加上`var`关键字来创建局部变量。如果省略它，变量将在全局范围内创建。

您将在这些示例中看到，我们不需要使用`var`关键字，并且 CoffeeScript 在生成的 JavaScript 中创建了实际的变量声明。

如果您是一位经验丰富的 JavaScript 程序员，您可能会想知道如何创建全局变量。简单的答案是您不能。

许多人（可能包括 CoffeeScript 的作者）会认为这是一件好事，因为在大多数情况下应该避免使用全局变量。不过，不用担心，因为有办法创建顶层对象，我们马上就会讲到。但这也巧妙地引出了 CoffeeScript 的另一个好处。

# CoffeeScript 处理作用域更好

看一下下面的 JavaScript 片段。注意，一个名为`salutation`的变量在函数内部以及在第一次调用函数后被定义：

| JavaScript |
| --- |

|

```js
var greet = function(){ 
    if(typeof salutation === 'undefined') 
        salutation = 'Hi!'; 
    console.log(salutation); 
}
greet();
salutation = "Bye!";
greet();
```

|

在 JavaScript 中，当您在声明变量时省略`var`关键字时，它立即成为全局变量。全局变量在所有作用域中都可用，因此可以从任何地方进行覆盖，这经常会变得混乱。

在前面的示例中，`greet`函数首先检查`salutation`变量是否已定义（通过检查`typeof`是否等于`undefined`，这是 JavaScript 中常见的检查变量是否已定义的解决方法）。如果之前没有定义，它将在没有`var`关键字的情况下创建它。这将立即将变量提升到全局作用域。我们可以在代码片段的其余部分看到这种后果。

第一次调用`greet`函数时，将记录字符串**Hi!**。在问候语已更改并再次调用函数后，控制台将记录**Bye!**。因为变量泄露为全局变量，其值在函数作用域之外被覆盖。

这种语言的奇怪“特性”曾经让一些疲惫的程序员头疼不已，因为他们忘记在某个地方包含`var`关键字。即使你想声明一个全局变量，通常也被认为是一个糟糕的设计选择，这就是为什么 CoffeeScript 不允许它的原因。

CoffeeScript 将始终向任何变量声明添加`var`关键字，以确保它不会无意中成为全局声明。事实上，你不应该自己输入`var`，如果你这样做，编译器会报错。

## 顶级变量关键字

当你在 JavaScript 脚本的顶层正常声明一个`var`时，它仍然会全局可用。这也可能在包含大量不同的 JavaScript 文件时造成混乱，因为你可能会覆盖在先前脚本中声明的变量。

在 JavaScript 和随后的 CoffeeScript 中，函数充当闭包，这意味着它们创建自己的变量作用域，并且可以访问它们的封闭作用域变量。

多年来，一个常见的模式开始出现，即库作者将他们的整个脚本包装在一个匿名闭包函数中，然后将其赋值给一个单一变量。

CoffeeScript 编译器做了类似的事情，并且会将脚本包装在一个匿名函数中，以避免泄露其作用域。在下面的示例中，JavaScript 是运行 CoffeeScript 编译器后的输出：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
greet = -> salutation = 'Hi!'
```

|

```js
(var greet;
greet = function() {
  var salutation;
  return salutation = 'Hi!';
}).call(this);
```

|

在这里你可以看到 CoffeeScript 是如何将函数定义包装在自己的作用域中的。

然而，有一些情况下，你可能希望一个变量在整个应用程序中都可用。通常可以通过将属性附加到现有的全局对象来实现这一点。当你在浏览器中时，你可以在全局的`window`对象上创建一个属性。

在浏览器端的 JavaScript 中，`window`对象代表一个打开的窗口。它对所有其他对象都是全局可用的，因此可以用作全局命名空间或其他对象的容器。

当我们谈到对象时，让我们谈谈 JavaScript 的另一个部分，CoffeeScript 使之更好：定义和使用对象。

# CoffeeScript 有更好的对象语法

JavaScript 语言拥有一个奇妙而独特的对象模型，但是创建对象和从中继承的语法和语义一直有些麻烦并且被广泛误解。

CoffeeScript 通过简单而优雅的语法对此进行了清理，不会偏离惯用的 JavaScript。以下代码演示了 CoffeeScript 如何将其类语法编译成 JavaScript：

**CoffeeScript:**

```js
class Vehicle
  constructor: ->   
  drive: (km) -> 
    alert "Drove #{km} kilometres"

bus = new Vehicle()
bus.drive 5
```

**JavaScript:**

```js
var Vehicle, bus;
Vehicle = (function() {
  function Vehicle() {}
  Vehicle.prototype.drive = function(km) {
    return alert("Drove " + km + " kilometres");
  };
  return Vehicle;
})();
bus = new Vehicle();
bus.drive(5);
```

在 CoffeeScript 中，你使用`class`关键字来定义对象结构。在底层，这将创建一个带有添加到其原型的函数方法的函数对象。`constructor: operator`将创建一个构造函数，在使用`new`关键字初始化对象时将被调用。

所有其他函数方法都是使用`methodName: () ->`语法声明的。这些方法是在对象的原型上创建的。

### 注意

你注意到我们的警报字符串中的`#{km}`了吗？这是字符串插值语法，它是从 Ruby 中借鉴过来的。我们将在本章后面讨论这个。

## 继承

那么对象继承呢？虽然这是可能的，但通常在 JavaScript 中这是一个麻烦，大多数程序员甚至不会费心，或者使用具有非标准语义的第三方库。

在这个例子中，您可以看到 CoffeeScript 如何使对象继承优雅：

**CoffeeScript：**

```js
class Car extends Vehicle
  constructor: -> 
    @odometer = 0
  drive: (km) ->
    @odometer += km
    super km
car = new Car
car.drive 5
car.drive 8

alert "Odometer is at #{car.odometer}"
```

**JavaScript：**

```js
Car = (function(_super) {
  __extends(Car, _super);
  function Car() {
    this.odometer = 0;
  }
  Car.prototype.drive = function(km) {
    this.odometer += km;
    return Car.__super__.drive.call(this, km);
  };
  return Car;
})(Vehicle);

car = new Car;
car.drive(5);
car.drive(8);
alert("Odometer is at " + car.odometer);
```

这个例子并不包含编译器将生成的所有 JavaScript 代码，但足以突出有趣的部分。`extends`运算符用于在两个对象及其构造函数之间建立继承链。请注意，使用`super`调用父类变得简单得多。

正如您所看到的，`@odometer`被翻译为`this.odometer`。`@`符号只是`this`的快捷方式。我们将在本章后面进一步讨论它。

## 不知所措？

在我的看来，`class`语法是 CoffeeScript 和它编译的 JavaScript 之间最大的区别。然而，大多数时候它只是起作用，一旦您理解它，您很少需要担心细节。

## 扩展原型

如果您是一位有经验的 JavaScript 程序员，仍然喜欢自己完成所有这些工作，您不需要使用`class`。CoffeeScript 仍然提供了一个有用的快捷方式，通过`::`符号可以访问原型，在生成的 JavaScript 中将被替换为`.prototype`，如下面的代码片段所示：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
Vehicle::stop=->  alert'Stopped'
```

|

```js
Vehicle.prototype.stop(function() {
  return alert('Stopped');
});
```

|

# CoffeeScript 修复的其他一些问题

JavaScript 还有许多其他小的烦恼，CoffeeScript 使得它们更加美好。让我们来看看其中一些。

## 保留字和对象语法

在 JavaScript 中经常需要使用保留字或关键字。这经常发生在 JavaScript 中作为数据的文字对象的键，比如`class`或`for`，然后您需要将其括在引号中。CoffeeScript 会自动为您引用保留字，通常您甚至不需要担心它。

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
tag = 
  type: 'label' 
  name: 'nameLabel'
  for: 'name'
  class: 'label'
```

|

```js
var tag;

tag = {
  type: 'label',
  name: 'nameLabel',
  "for": 'name',
  "class": 'label'
};
```

|

请注意，我们不需要大括号来创建对象文字，这里也可以使用缩进。在使用这种风格时，只要每行只有一个属性，我们也可以省略尾随逗号。

我们还可以以这种方式编写数组文字：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
dwarfs = [
  "Sneezy"
  "Sleepy"
  "Dopey"
  "Doc"
  "Happy"
  "Bashful"
  "Grumpy"
]
```

|

```js
var dwarfs;

dwarfs = ["Sneezy", "Sleepy", "Dopey", "Doc", "Happy", "Bashful", "Grumpy"];
```

|

这些特性结合在一起使得编写 JSON 变得轻而易举。比较以下示例以查看差异：

**CoffeeScript：**

```js
"firstName": "John"
"lastName": "Smith"
"age": 25
"address": 
  "streetAddress": "21 2nd Street"
  "city": "New York"
  "state": "NY"
  "postalCode": "10021"
"phoneNumber": [
  {"type": "home", "number": "212 555-1234"}
  {"type": "fax", "number": "646 555-4567"}
]
```

**JavaScript：**

```js
({
  "firstName": "John",
  "lastName": "Smith",
  "age": 25,
  "address": {
    "streetAddress": "21 2nd Street",
    "city": "New York",
    "state": "NY",
    "postalCode": "10021"
  },
  "phoneNumber": [
    {
      "type": "home",
      "number": "212 555-1234"
    }, {
      "type": "fax",
      "number": "646 555-4567"
    }
  ]
});
```

## 字符串连接

对于一个处理大量字符串的语言来说，JavaScript 一直在从部分构建字符串方面表现得相当糟糕。变量和表达式值通常需要插入到字符串的某个位置，通常通过使用`+`运算符进行连接。如果您曾经尝试在字符串中连接几个变量，您会知道这很快变得繁琐且难以阅读。

CoffeeScript 具有内置的字符串插值语法，类似于许多其他脚本语言，但是专门从 Ruby 中借鉴而来。这在下面的代码片段中显示：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
greet = (name, time) -> 
  "Good #{time} #{name}!"

alert (greet 'Pete', 'morning')
```

|

```js
var greet;

greet = function(name, time) {
  return "Good " + time + " " + name + "!";
};

alert(greet('Pete', 'morning'));
```

|

您可以在`#{}`中写入任何表达式，其字符串值将被连接。请注意，您只能在双引号`""`中使用字符串插值。单引号字符串是文字的，将被准确表示。

## 相等

在 JavaScript 中，等号运算符`==`（及其反向`!=`）充满了危险，很多时候并不会做你期望的事情。这是因为它首先会尝试强制将不同类型的对象在比较之前变成相同的。

它也不是传递的，这意味着它可能根据操作符的左侧或右侧的类型返回不同的`true`或`false`值。请参考以下代码片段：

```js
'' == '0'           // false
0 == ''             // true
0 == '0'            // true

false == 'false'    // false
false == '0'        // true

false == undefined  // false
false == null       // false
null == undefined   // true
```

由于其不一致和奇怪的行为，JavaScript 社区中受尊敬的成员建议完全避免使用它，而是使用身份运算符`===`来代替。如果两个对象的类型不同，这个运算符将始终返回`false`，这与许多其他语言中`==`的工作方式一致。

CoffeeScript 将始终将`==`转换为`===`，将`!=`转换为`!==`，如下所示：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
'' == '0'
0 == ''  
0 == '0' 
false == 'false'
false == '0'    
false == undefined
false == null     
null == undefined 
```

|

```js
'' === '0';
0 === '';
0 === '0';
false === 'false';
false === '0';
false === void 0;
false === null;
null === void 0;
```

|

## 存在运算符

当你想要检查一个变量是否存在并且有值（不是`null`或`undefined`）时，你需要使用这种古怪的习惯用法：

```js
typeof a !== "undefined" && a !== null 
```

CoffeeScript 为此提供了一个很好的快捷方式，即存在运算符`?`，它会在变量不是`undefined`或`null`时返回`false`。

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
broccoli = true;
if carrots? && broccoli?
  alert 'this is healthy'
```

|

```js
var broccoli;

broccoli = true;

if ((typeof carrots !== "undefined" && carrots !== null) && (broccoli != null)) {
  alert('this is healthy');
}
```

|

在这个例子中，由于编译器已经知道`broccoli`是定义的，`?`运算符只会检查它是否有`null`值，而它将检查`carrots`是否`undefined`以及`null`。

存在运算符还有一个方法调用变体：`?.`或者称为"soak"，它允许你在方法链中吞掉`null`对象上的方法调用，如下所示：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
street = person?.getAddress()?.street
```

|

```js
var street, _ref;

street = typeof person !== "undefined" && person !== null ? (_ref = person.getAddress()) != null ? _ref.street : void 0 : void 0;
```

|

如果链中的所有值都存在，你应该得到预期的结果。如果它们中的任何一个应该是`null`或`undefined`，你将得到一个未定义的值，而不是抛出`TypeError`。

尽管这是一种强大的技术，但它也很容易被滥用，并且使代码难以理解。如果你有很长的方法链，可能很难知道`null`或`undefined`值究竟来自哪里。

**迪米特法则**，一个众所周知的面向对象设计原则，可以用来最小化这种复杂性，并改善代码中的解耦。它可以总结如下：

+   你的方法可以直接调用其类中的其他方法

+   你的方法可以直接调用自己字段上的方法（但不能调用字段的字段）

+   当你的方法带有参数时，你的方法可以直接调用这些参数上的方法

+   当你的方法创建本地对象时，该方法可以直接调用本地对象上的方法

### 注意

尽管这不是严格的法则，不应该被打破，但更类似于自然法则，使得遵循它的代码也更简单和更松散耦合。

既然我们已经花了一些时间来讨论 CoffeeScript 修复了 JavaScript 的一些不足和烦恼，让我们再来看看 CoffeeScript 添加的一些其他强大功能；一些是从其他脚本语言借鉴的，一些是这种语言独有的。

# 列表推导

在 CoffeeScript 中，遍历集合的方式与 JavaScript 的命令式方法有很大不同。CoffeeScript 借鉴了函数式编程语言的思想，并使用列表推导来转换列表，而不是迭代地遍历元素。

## while 循环

`while`循环仍然存在，工作方式差不多，只是它可以作为表达式使用，意味着它将返回一个值的数组：

**CoffeeScript:**

```js
multiplesOf = (n, times) -> 
  times++
  (n * times while times -= 1 > 0).reverse()

alert (multiplesOf 5, 10)
```

**JavaScript:**

```js
var multiplesOf;

multiplesOf = function(n, times) {
  times++;
  return ((function() {
    var _results;
    _results = [];
    while (times -= 1 > 0) {
      _results.push(n * times);
    }
    return _results;
  })()).reverse();
};

alert(multiplesOf(5, 10));
```

请注意，在前面的代码中，`while`循环体放在条件的前面。这是 CoffeeScript 中的一个常见习惯，如果循环体只有一行。你也可以在`if`语句和列表推导中做同样的事情。

我们可以通过使用`until`关键字稍微改善前面代码的可读性，它基本上是`while`的否定，如下所示：

**CoffeeScript:**

```js
multiplesOf = (n, times) -> 
  times++
  (n * times until --times == 0).reverse()

alert (multiplesOf 5, 10)
```

**JavaScript:**

```js
var multiplesOf;

multiplesOf = function(n, times) {
  times++;
  return ((function() {
    var _results;
    _results = [];
    while (--times !== 0) {
      _results.push(n * times);
    }
    return _results;
  })()).reverse();
};

alert(multiplesOf(5, 10));
```

`for`语句不像在 JavaScript 中那样工作。CoffeeScript 用列表推导式替换它，这主要是从 Python 语言借鉴来的，也非常类似于您在函数式语言（如 Haskell）中找到的构造。推导式提供了一种更声明性的方式来过滤、转换和聚合集合，或者对每个元素执行操作。最好的方法是通过一些示例来说明它们：

**CoffeeScript:**

```js
flavors = ['chocolate', 'strawberry', 'vanilla']
alert flavor for flavor in flavors

favorites = ("#{flavor}!" for flavor in flavors when flavor != 'vanilla')
```

**JavaScript:**

```js
var favorites, flavor, flavors, _i, _len;

flavors = ['chocolate', 'strawberry', 'vanilla'];

for (_i = 0, _len = flavors.length; _i < _len; _i++) {
  flavor = flavors[_i];
  alert(flavor);
}

favorites = (function() {
  var _j, _len1, _results;
  _results = [];
  for (_j = 0, _len1 = flavors.length; _j < _len1; _j++) {
    flavor = flavors[_j];
    if (flavor !== 'vanilla') {
      _results.push("" + flavor + "!");
    }
  }
  return _results;
})();
```

尽管它们非常简单，但推导式具有非常紧凑的形式，并且在非常少的代码中完成了很多工作。让我们将其分解为单独的部分：

```js
[action or mapping] for [selector] in [collection] when [condition] by [step]
```

理解推导式最好从右向左阅读，从`in`集合开始。`selector`名称是一个临时名称，它在我们遍历集合时赋予每个元素。在`for`关键字前面的子句描述了您希望对`selector`名称执行的操作，可以通过调用带有它作为参数的方法、选择其上的属性或方法，或者赋值来实现。

`when`和`by`保护子句是可选的。它们描述了迭代应该如何被过滤（仅当后续的`when`条件为`true`时才会返回元素），或者使用`by`后跟一个数字来选择集合的哪些部分。例如，`by 2`将返回每个偶数编号的元素。

我们可以通过使用`by`和`when`来重写我们的`multiplesOf`函数：

**CoffeeScript:**

```js
multiplesOf = (n, times) -> 
  multiples = (m for m in [0..n*times] by n)
  multiples.shift()
  multiples

alert (multiplesOf 5, 10)
```

**JavaScript:**

```js
var multiplesOf;

multiplesOf = function(n, times) {
  var m, multiples;
  multiples = (function() {
    var _i, _ref, _results;
    _results = [];
    for (m = _i = 0, _ref = n * times; 0 <= _ref ? _i <= _ref : _i >= _ref; m = _i += n) {
      _results.push(m);
    }
    return _results;
  })();
  multiples.shift();
  return multiples;
};

alert(multiplesOf(5, 10));
```

`[0..n*times]`语法是 CoffeeScripts 的范围语法，它是从 Ruby 中借鉴来的。它将创建一个包含第一个和最后一个数字之间所有元素的数组。当范围有两个点时，它将是包容的，这意味着范围将包含指定的起始和结束元素。如果有三个点（`…`），它将只包含其中的数字。

当我开始学习 CoffeeScript 时，推导式是我需要掌握的最大的新概念之一。它们是一个非常强大的特性，但确实需要一些时间来习惯和思考推导式。每当您感到想要使用较低级别的`while`编写循环结构时，请考虑改用推导式。它们几乎提供了您在处理集合时可能需要的一切，而且与内置的 ECMAScript 数组方法（如`.map()`和`.select()`）相比，它们非常快速。

您可以使用推导式来循环遍历对象中的键值对，使用`of`关键字，如下面的代码所示：

**CoffeeScript:**

```js
ages = 
  john: 25
  peter: 26
  joan: 23

alert "#{name} is #{age} years old" for name, age of ages
```

**JavaScript:**

```js
var age, ages, name;

ages = {
  john: 25,
  peter: 26,
  joan: 23
};

for (name in ages) {
  age = ages[name];
  alert("" + name + " is " + age + " years old");
}
```

# 条件子句和逻辑别名

CoffeeScript 引入了一些非常好的逻辑和条件特性，有些也是从其他脚本语言借鉴来的。`unless`关键字是`if`关键字的反义词；`if`和`unless`可以采用后缀形式，这意味着语句可以放在行的末尾。

CoffeeScript 还为一些逻辑运算符提供了纯英语别名。它们如下：

+   `is` 用于 `==`

+   `isnt` 用于 `!=`

+   `not` 用于 `!`

+   `和` 用于 `&&`

+   `or` 用于 `||`

+   `true`也可以是`yes`或`on`

+   `false`可以是`no`或`off`

将所有这些放在一起，让我们看一些代码来演示它：

**CoffeeScript:**

```js
car.switchOff() if car.ignition is on
service(car) unless car.lastService() > 15000
wash(car) if car.isDirty()
chargeFee(car.owner) if car.make isnt "Toyota"
```

**JavaScript:**

```js
if (car.ignition === true) {
  car.switchOff();
}

if (!(car.lastService() > 15000)) {
  service(car);
}

if (car.isDirty()) {
  wash(car);
}

if (car.make !== "Toyota") {
  chargeFee(car.owner);
}
```

# 数组切片和拼接

CoffeeScript 允许您使用`..`和`...`符号轻松提取数组的部分。`[n..m]`将选择包括`n`和`m`在内的所有元素，而`[n…m]`将仅选择`n`和`m`之间的元素。

`[..]`和`[…]`都将选择整个数组。这些在以下代码中使用：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

alert numbers[0..3]

alert numbers[4...7]

alert numbers[7..]

alert numbers[..]
```

|

```js
var numbers;

numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

alert(numbers.slice(0, 4));

alert(numbers.slice(4, 7));

alert(numbers.slice(7));

alert(numbers.slice(0));
```

|

CoffeeScript 确实喜欢它的省略号。它们被用于 splat、范围和数组切片。以下是一些关于如何识别它们的快速提示：如果`…`紧挨着函数定义或函数调用中的最后一个参数，那么它是 splat。如果它被包含在不索引数组的方括号中，那么它是范围。如果它索引一个数组，那么它是切片。

# 解构或模式匹配

**解构**是许多函数式编程语言中的一个强大概念。实质上，它允许您从复杂对象中提取单个值。它可以简单地允许您一次分配多个值，或者处理返回多个值的函数；如下所示：

**CoffeeScript：**

```js
getLocation = ->
  [
   'Chigaco' 
   'Illinois' 
   'USA'
  ]

[city, state, country] = getLocation()
```

**JavaScript：**

```js
var city, country, getLocation, state, _ref;

getLocation = function() {
  return ['Chigaco', 'Illinois', 'USA'];
};

_ref = getLocation(), city = _ref[0], state = _ref[1], country = _ref[2];
```

当您运行此代码时，您将获得三个变量，`city`，`state`和`country`，它们的值是从`getLocation`函数返回的数组中的相应元素分配的。

您还可以使用解构从对象和哈希中提取值。对象中的数据可以嵌套到任意深度。以下是一个示例：

**CoffeeScript：**

```js
getAddress = ->
   address:
     country: 'USA'
     state: 'Illinois'
     city: 'Chicago'
     street: 'Rush Street'

{address: {street: myStreet}} = getAddress()
alert myStreet
```

**JavaScript：**

```js
var getAddress, myStreet;

getAddress = function() {
  return {
    address: {
      country: 'USA',
      state: 'Illinois',
      city: 'Chicago',
      street: 'Rush Street'
    }
  };
};

myStreet = getAddress().address.street;

alert(myStreet);
```

在这个例子中，`{address: {street: ---}}`部分描述了您的模式，基本上是要找到您需要的信息。当我们将`myStreet`变量放入我们的模式中时，我们告诉 CoffeeScript 将该位置的值分配给`myStreet`。虽然我们可以使用嵌套对象，但我们也可以混合和匹配解构对象和数组，如下面的代码所示：

**CoffeeScript：**

```js
getAddress = ->
   address:
     country: 'USA'
     addressLines: [
       '1 Rush Street'
       'Chicago'
       'Illinois'
     ]

{address: 
  {addressLines: 
    [street, city, state]
  }
} = getAddress()
alert street
```

**JavaScript：**

```js
var city, getAddress, state, street, _ref;

getAddress = function() {
  return {
    address: {
      country: 'USA',
      addressLines: ['1 Rush Street', 'Chicago', 'Illinois']
    }
  };
};

_ref = getAddress().address.addressLines, street = _ref[0], city = _ref[1], state = _ref[2];

alert(street);
```

在前面的代码中，我们从`addressLines`获取的数组值中提取元素并为它们命名。

# => 和 @

在 JavaScript 中，`this`的值指的是当前执行函数的所有者，或者函数是其方法的对象。与其他面向对象的语言不同，JavaScript 还有一个概念，即函数与对象没有紧密绑定，这意味着`this`的值可以随意更改（或者意外更改）。这是语言的一个非常强大的特性，但如果使用不正确也会导致混淆。

在 CoffeeScript 中，`@`符号是`this`的快捷方式。每当编译器看到类似`@foo`的东西时，它将用`this.foo`替换它。

虽然在 CoffeeScript 中仍然可以使用这个，但通常不鼓励这样做，更符合习惯的是使用`@`代替。

在任何 JavaScript 函数中，`this`的值是函数附加到的对象。但是，当您将函数传递给其他函数或重新将函数附加到另一个对象时，`this`的值将发生变化。有时这是您想要的，但通常您希望保留`this`的原始值。

为此，CoffeeScript 提供了`=>`，或者 fat 箭头，它将定义一个函数，但同时捕获`this`的值，以便函数可以在任何上下文中安全调用。在使用回调时特别有用，例如在 jQuery 事件处理程序中。

以下示例将说明这个想法：

**CoffeeScript：**

```js
class Birthday
  prepare: (action) ->
    @action = action

  celebrate: () ->
   @action()

class Person
  constructor: (name) ->
    @name = name
    @birthday = new Birthday()
    @birthday.prepare () => "It's #{@name}'s birthday!"

michael = new Person "Michael"
alert michael.birthday.celebrate() 
```

**JavaScript：**

```js
var Birthday, Person, michael;

Birthday = (function() {

  function Birthday() {}

  Birthday.prototype.prepare = function(action) {
    return this.action = action;
  };

  Birthday.prototype.celebrate = function() {
    return this.action();
  };

  return Birthday;

})();

Person = (function() {

  function Person(name) {
    var _this = this;
    this.name = name;
    this.birthday = new Birthday();
    this.birthday.prepare(function() {
      return "It's " + _this.name + "'s birthday!";
    });
  }

  return Person;

})();

michael = new Person("Michael");

alert(michael.birthday.celebrate());
```

请注意，`birthday`类上的`prepare`函数将`action`函数作为参数传递，以便在生日发生时调用。因为我们使用 fat 箭头传递这个函数，它的作用域将固定在`Person`对象上。这意味着我们仍然可以引用`@name`实例变量，即使它不存在于运行函数的`Birthday`对象上。

# Switch 语句

在 CoffeeScript 中，`switch`语句采用不同的形式，看起来不太像 JavaScript 的受 Java 启发的语法，更像 Ruby 的`case`语句。您不需要调用`break`来避免掉入下一个`case`条件。

它们的形式如下：

```js
switch condition 
  when … then …
   ….
else …
```

在这里，`else`是默认情况。

与 CoffeeScript 中的其他所有内容一样，它们都是表达式，可以分配给一个值。

让我们来看一个例子：

**CoffeeScript：**

```js
languages = switch country
  when 'france' then 'french'
  when 'england', 'usa' then 'english'
  when 'belgium' then ['french', 'dutch']
  else 'swahili'
```

**JavaScript：**

```js
var languages;

languages = (function() {
  switch (country) {
    case 'france':
      return 'french';
    case 'england':
    case 'usa':
      return 'english';
    case 'belgium':
      return ['french', 'dutch'];
    default:
      return 'swahili';
  }
})();
```

CoffeeScript 不强制您添加默认的`else`子句，尽管始终添加一个是一个很好的编程实践，以防万一。

# 链式比较

CoffeeScript 从 Python 借用了链式比较。这基本上允许您像在数学中那样编写大于或小于的比较，如下所示：

| CoffeeScript | JavaScript |
| --- | --- |

|

```js
age = 41

alert 'middle age' if 61 > age > 39
```

|

```js
var age;

age = 41;

if ((61 > age && age > 39)) {
  alert('middle age');
}
```

|

# 块字符串，块注释和字符串

大多数编程书籍都以注释开始，我想以它们结束。在 CoffeeScript 中，单行注释以`#`开头。这些注释不会出现在生成的输出中。多行注释以`###`开头和结尾，并包含在生成的 JavaScript 中。

你可以使用`"""`三重引号将字符串跨越多行。

# 摘要

在本章中，我们从 JavaScript 的角度开始了解 CoffeeScript。我们看到它如何帮助你编写比在 JavaScript 中更短、更清晰、更优雅的代码，并避免许多它的缺陷。

我们意识到，尽管 CoffeeScript 的语法看起来与 JavaScript 有很大不同，但实际上它与生成的输出非常接近。

之后，我们深入了解了一些 CoffeeScript 独特和精彩的功能，比如列表推导、解构赋值和类语法，以及许多方便和强大的功能，比如字符串插值、范围、扩展和数组切片。

我在本章的目标是说服你，CoffeeScript 是 JavaScript 的一个更优秀的替代品，并通过展示它们之间的差异来尝试做到这一点。尽管我之前说过"它只是 JavaScript"，我希望你能欣赏到 CoffeeScript 是一门独立的、现代的语言，受到其他伟大脚本语言的影响。

我仍然可以写很多关于这门语言之美的东西，但我觉得我们已经到了可以深入了解一些真实世界的 CoffeeScript 并欣赏它的时候了。

那么，你准备好了吗？让我们开始吧，安装 CoffeeScript。


# 第二章：运行 CoffeeScript

在本章中，我们将讨论如何在开发环境中安装和运行 CoffeeScript。

CoffeeScript 可以轻松安装在 Mac、Windows 或 Linux 上。根据您希望安装是简单直接还是希望处于前沿状态，有多种方法可以使其运行。在我们开始详细讨论之前，值得知道的是，CoffeeScript 通常不是独立存在的，而是使用一些出色的 JavaScript 工具和框架来实现其功能。让我们简要讨论一下典型的 CoffeeScript 堆栈。

# CoffeeScript 堆栈

在 CoffeeScript 的早期历史中，它的编译器是用 Ruby 编写的。后来，它变成了自托管；语言编译器是用自身编写的。这意味着 CoffeeScript 的编译器是用 CoffeeScript 代码编写的，然后可以编译为 JavaScript，然后可以运行以再次编译 CoffeeScript。令人困惑，不是吗？

不再深入讨论这是一个多么了不起的壮举，这也意味着为了运行 CoffeeScript，我们需要能够在计算机上独立执行 JavaScript，而不需要浏览器。

Node.js，或者简称为 Node，是专为编写网络服务器应用程序而设计的 JavaScript 框架。它是使用 Google 的 V8 构建的，这是一个可以在没有网络浏览器的情况下运行 JavaScript 的引擎，非常适合 CoffeeScript。它已成为安装 CoffeeScript 的首选方式。

将 CoffeeScript 与 Node.js 配对有很多好处。这不仅意味着您可以编译可以在浏览器中运行的 JavaScript，而且还可以获得一个功能齐全的 JavaScript 网络应用程序服务器框架，其中包含了数百个有用的库。

与 Node.js 中的 JavaScript 一样，您可以在服务器上编写和执行 CoffeeScript，使用它来编写 Web 服务器应用程序，甚至将其用作正常的日常系统脚本语言。

### 注意

核心 CoffeeScript 编译器不依赖于 Node，从技术上讲，它可以在任何 JavaScript 环境上执行。但是，使用编译器的 coffee 命令行实用程序是一个 Node.js 包。

CoffeeScript 编译器的工作如下图所示：

![CoffeeScript 堆栈](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_01.jpg)

# Node.js 和 npm

Node.js 有自己的包管理系统，称为 npm。它用于安装和管理在 Node.js 生态系统中运行的包、库及其依赖项。这也是安装 CoffeeScript 的最常见方式，CoffeeScript 本身也作为 npm 包可用。因此，在设置好 Node.js 和 npm 之后，安装 CoffeeScript 实际上非常容易。

根据您的操作系统以及是否需要编译源代码，有不同的安装 Node.js 和 npm 的方法。后续各节将介绍各个操作系统的说明。

### 提示

Node.js 维基包含大量关于在众多平台上安装和运行 Node 的信息。如果在本章中遇到任何问题，您可以查看它，因为它有很多有关故障排除问题的提示，并经常更新；链接是 https://github.com/joyent/node/wiki/Installation。

# Windows 上的 Node.js、npm 和 CoffeeScript

Node.js 社区一直在努力提供良好的本地 Windows 支持，安装非常简单。

要这样做，首先转到 Node.js 网站（nodejs.org），然后单击“下载”按钮。您将看到几个可用的选项，但选择“Windows 安装程序”选项，如下截图所示：

![Windows 上的 Node.js、npm 和 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_02.jpg)

这将下载一个`.msi`文件。一旦下载完成，安装就变得非常简单；只需接受条款并单击“继续”。如果您看到以下屏幕，则已成功安装 Node：

![Windows 上的 Node.js、npm 和 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_03.jpg)

在这一点上，你可能需要注销 Windows 或重新启动，以便更改你的`$PATH`变量生效。完成后，你应该能够打开 DOS 命令提示符并运行以下命令：

```js
node –v 
```

这应该会输出一个版本，这意味着你可以开始了。让我们也检查一下 npm 是否正常工作。同样在命令行工具中，输入以下内容：

```js
npm
```

你应该会看到类似以下截图的内容：

![Windows 上的 Node.js、npm 和 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_04.jpg)

现在，为了继续安装 CoffeeScript，只需输入以下命令：

```js
npm install coffee-script
```

如果一切顺利，你应该会看到类似以下截图的内容：

![Windows 上的 Node.js、npm 和 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_05.jpg)

在这里，我使用了**-g**标志，它为所有用户安装了 npm 包。一旦你安装了 CoffeeScript，我们可以使用**coffee**命令进行测试，如下所示：

![Windows 上的 Node.js、npm 和 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_06.jpg)

这是 CoffeeScript 解释器，正如你所看到的，你可以使用它来即时运行 CoffeeScript 代码。要退出，只需使用*Ctrl* + *C*。

就是这样！在 Windows 上安装 Node.js 非常快速和简单。

# 在 Mac 上安装 CoffeeScript

在 Mac 上安装 Node.js 有两种方式，一种是从 Node.js 网站下载`.pkg`文件，然后使用苹果的安装程序应用进行安装，另一种是使用**Homebrew**命令行包管理器。

最简单的方法是只安装`.pkg`文件，所以我们先来看看这个。安装 Homebrew 可能需要更多的工作，但如果你喜欢在命令行工具上工作并且想要从源代码构建 CoffeeScript，那么这是值得的。

## 使用苹果安装程序

前往 Node.js 网站([nodejs.org](http://nodejs.org))，然后点击**下载**按钮。你会看到一些可用的选项，但选择**Macintosh 安装程序**选项，如下截图所示：

![使用苹果安装程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_02.jpg)

这将下载一个`.pkg`文件。一旦你下载了它，运行安装就会变得非常容易；只需选择你的目的地，接受许可证，并点击**继续**。你应该选择使用**为这台计算机的所有用户安装**选项来为所有用户安装它，如下截图所示：

![使用苹果安装程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_07.jpg)

如果你看到以下屏幕，那么你已经成功安装了 Node：

![使用苹果安装程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_08.jpg)

你还将安装 npm，我们将使用它来安装 CoffeeScript。跳转到*使用 npm 安装 CoffeeScript*部分。

## 使用 Homebrew

许多开发人员更喜欢在 Mac 上使用命令行工具工作，而 Homebrew 包管理器已经变得非常流行。它旨在让你轻松安装不随 Mac OS X 捆绑的 Unix 工具。

如果你喜欢使用 Homebrew 安装 Node.js，你需要在你的系统上安装 Homebrew。你可能还需要 XCode 命令行工具来构建 Node.js 源代码。Homebrew 维基包含了如何在[`github.com/mxcl/homebrew/wiki/installation`](https://github.com/mxcl/homebrew/wiki/installation)上运行它的说明。

如果你已经安装了 Homebrew，你可以使用**brew**命令安装 Node.js，如下截图所示：

![使用 Homebrew](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_09.jpg)

从输出中可以看出，Homebrew 没有安装 npm，没有 npm 我们无法安装 CoffeeScript。要安装 npm，你只需在终端中复制并粘贴以下命令：

```js
curl http://npmjs.org/install.sh |sh
```

安装 npm 后，你应该会看到类似以下屏幕的内容：

![使用 Homebrew](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_10.jpg)

## 使用 npm 安装 CoffeeScript

现在我们已经安装了 npm，我们应该能够安装 CoffeeScript。只需在终端中输入以下命令：

```js
npm install –g coffee-script
```

**-g**标志让 npm 全局安装 CoffeeScript；一旦完成，您现在可以通过使用**coffee**命令来测试 CoffeeScript 是否正常工作，如下面的屏幕截图所示：

![使用 npm 安装 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_11.jpg)

就是这样！在 Mac 上安装 CoffeeScript 非常容易。

# 在 Linux 上安装 CoffeeScript

在 Linux 上安装 Node.js 与 CoffeeScript 的方式取决于您安装了哪个发行版。大多数流行的发行版都有软件包，如果没有，您也可以尝试从源代码构建 CoffeeScript，如下一节所述。

我只有使用基于 Debian 的发行版的软件包管理器的经验，并且已成功使用**apt-get**软件包管理器安装了 Node.js 和 CoffeeScript。但是，您应该能够按照其他发行版的说明进行操作。

在 Ubuntu、MintOS 和 Debian 上有 Node.js 的 apt-get 软件包，但您需要在安装之前为它们添加源。安装每个软件包的说明将在以下部分中探讨。

## Ubuntu 和 MintOS

在命令行实用程序上输入以下内容（您可能需要有足够的权限来使用`sudo`）：

```js
sudo apt-get install python-software-properties
sudo apt-add-repository ppa:chris-lea/node.js
sudo apt-get update
sudo apt-get install nodejs npm 
```

## Debian

在 Debian 上，您通常会登录到 root 终端以安装软件包。登录后，输入以下命令：

```js
echo deb http://ftp.us.debian.org/debian/ sid main > /etc/apt/sources.list.d/sid.list
apt-get update
apt-get install nodejs npm
```

## 其他发行版

Node.js 的维基页面[`github.com/joyent/node/wiki/Installing-Node.js-via-package-manager`](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager)包含了在各种 Linux 和 Unix 发行版上安装的说明，包括 Fedora、openSUSE、Arch Linux 和 FreeDSB。

## 使用 npm 安装 CoffeeScript

在您的软件包管理器完成其任务后，您现在应该已经安装了 Node.js 和 npm。您可以使用 npm **-v**命令来验证这一点。您现在可以使用 npm 安装 CoffeeScript，方法是输入以下命令：

```js
npm install –g coffee-script
```

`-g`标志告诉 npm 全局安装软件包。

以下屏幕截图显示了如何使用**-v**命令安装 CoffeeScript：

![使用 npm 安装 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_12.jpg)

就是这样！在 Linux 上安装 CoffeeScript 非常容易。

# 从源代码构建 Node.js

如果您不想使用软件包管理器或安装程序，或者您的操作系统没有可用的软件包管理器或者您想获取最新版本的 Node.js，那么您也可以从源代码构建 Node.js。不过要注意，这个过程通常充满了危险，因为源代码通常需要系统上的一些依赖项来构建。

## 在 Linux 或 Unix 上构建

要在 Linux 或 Unix 环境中构建，您需要确保已安装以下源依赖项：

+   **Python–Version 2.6 或 Version 2.7**：您可以通过在命令提示符中输入`python --version`来检查是否已安装 Python，并检查安装了哪个版本。

+   **libssl-dev**：这通常可以使用内置软件包管理器安装。它已经安装在 OS X 上。

我将向您展示如何使用最新的源代码构建 Node.js。该源代码是使用流行的 Git 版本控制系统进行管理，并托管在[github.com](http://github.com)的存储库中。要从 github 拉取最新的源代码，您需要确保已安装 Git。通过使用`apt-get`，您可以这样安装它：

```js
apt-get install git-core
```

一旦您具备了这些先决条件，您应该能够构建节点。在命令行工具上输入以下命令：

```js
git clone https://github.com/joyent/node.git
cd node
git checkout v0.6.19 
./configure
make
sudo make install
```

哦！如果一切顺利，您应该能够使用 npm 安装 CoffeeScript：

```js
npm install –g coffee-script
```

## 在 Windows 上构建

尽管在 Windows 上构建 Node.js 是可能的，但我强烈建议您只需运行安装程序。在我在本书中提到的所有安装方式中，这是我没有亲自尝试过的唯一一种。这个例子直接来自 Node 维基（[`github.com/joyent/node/wiki/Installation`](https://github.com/joyent/node/wiki/Installation)）。显然，构建可能需要很长时间。在命令提示符中，输入以下内容：

```js
C:\Users\ryan>tar -zxf node-v0.6.5.tar.gz
C:\Users\ryan>cd node-v0.6.5
C:\Users\ryan\node-v0.6.5>vcbuild.bat release
C:\Users\ryan\node-v0.6.5>Release\node.exe
> process.versions
{ node: '0.6.5',
  v8: '3.6.6.11',
  ares: '1.7.5-DEV',
  uv: '0.6',
  openssl: '0.9.8r' }
>
```

# 使用 CoffeeScript

就是这样。为了获得 CoffeeScript 可能需要安装 Node.js 和 npm，这可能看起来需要很多努力，但您将体验到拥有一个出色的服务器端 JavaScript 框架和良好的命令行工具来编写 CoffeeScript 的强大功能。

既然您已经安装了 CoffeeScript，我们该如何使用它呢？您进入语言的主要入口点是`coffee`命令。

# coffee 命令

这个命令行实用程序就像 CoffeeScript 的瑞士军刀一样。您可以使用它以交互方式运行 CoffeeScript，将 CoffeeScript 文件编译为 JavaScript 文件，执行`.coffee`文件，监视文件或目录，并在文件更改时进行编译，以及其他一些有用的功能。执行该命令很容易，只需输入`coffee`以及一些选项和参数。

要获取所有可用选项的帮助，请使用**-h**或**--help**选项运行`coffee`。有关一些有用选项的列表显示在以下截图中：

![coffee 命令](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_13.jpg)

我们已经看到了**-v**选项，它将打印出 CoffeeScript 的当前版本。

## REPL

执行`coffee`没有参数或使用**-i**选项将使您进入 CoffeeScript 的**REPL**（**Read Eval Print Loop**）。从这里，您可以输入 CoffeeScript 代码，它将立即执行并在控制台中显示其输出。这对于玩转语言、探索一些核心 JavaScript 和 Node.js 库，甚至引入另一个外部库或 API 并能够进行交互式探索非常有用。

我建议你运行 coffee REPL，并尝试我们在上一章中讨论过的一些代码示例。注意每个表达式的输出是在输入后显示的。解释器还足够聪明，可以处理多行和嵌套表达式，比如函数定义。

![REPL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_14.jpg)

在上一张截图中，显示了解释器处理函数定义。

### 提示

要退出 REPL，使用*Ctrl* + *D*或*Ctrl* + *C*。

## 运行 .coffee 文件

在 REPL 中输入足够的代码后，您将会想要开始将您的 CoffeeScript 存储和组织在源文件中。CoffeeScript 文件使用`.coffee`扩展名。您可以通过将其作为参数传递给`coffee`命令来运行`.coffee`文件。文件中的 CoffeeScript 将被编译为 JavaScript，然后使用 Node.js 作为其环境执行。

### 提示

您可以使用任何文本编辑器来编写您的 CoffeeScript。许多流行的编辑器都具有插件或已经添加了对 CoffeeScript 的支持，包括语法高亮、代码补全，甚至允许您直接从编辑器中运行代码。在[`github.com/jashkenas/coffee-script/wiki/Text-editor-plugins`](https://github.com/jashkenas/coffee-script/wiki/Text-editor-plugins)上有一个支持 CoffeeScript 的文本编辑器和插件的全面列表。

## 编译为 JavaScript

要将 CoffeeScript 编译为 JavaScript，我们使用**-c**或**--compile**选项。它接受单个带有文件名或文件夹名的参数，或者多个文件和文件夹名。如果指定一个文件夹，它将编译该文件夹中的所有文件。默认情况下，JavaScript 输出文件将与源文件具有相同的名称，因此`foo.coffee`将编译为`foo.js`。

如果我们想要控制输出的 JavaScript 将被写入的位置，那么我们可以使用**-o**或**--output**选项加上一个文件夹名称。如果您正在指定多个文件或文件夹，那么您还可以使用**-j**或**--join**选项加上一个文件名。这将把输出合并成一个单独的 JavaScript 文件。

## 监视

如果您正在开发一个 CoffeeScript 应用程序，不断运行**--compile**可能会变得乏味。另一个有用的选项是**-w**或**--watch**。这告诉 CoffeeScript 编译器保持运行并监视特定文件或文件夹的任何更改。当与**--compile**结合使用时，这将在每次更改时编译文件。

## 将所有内容放在一起

`coffee`命令的一个很酷的地方是，标志可以组合在一起，创建一个非常有用的构建和开发环境。假设我有一堆 CoffeeScript 文件在一个源文件夹中，我想要在每次文件更改时将它们编译成`js`文件夹中的一个名为`output.js`的单个文件。

您应该能够使用类似以下命令：

```js
coffee –o js/ -j output.js –cw source/
```

这将监视源文件夹中`.coffee`文件的任何更改，并将它们编译并合并成一个名为**output.js**的单个文件，放在**js**文件夹中，如下面的屏幕截图所示：

![将所有内容放在一起](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588OS_02_15.jpg)

# 总结

在这一章中，您已经希望学会了如何在您选择的开发环境中运行 CoffeeScript。您还学会了如何使用`coffee`命令来运行和编译 CoffeeScript。现在您已经掌握了工具，我们将开始编写一些代码，并了解 CoffeeScript 的实际应用。让我们从 JavaScript 开始的地方开始，看看如何在浏览器中编写 CoffeeScript。


# 第三章：CoffeeScript 和 jQuery

**jQuery**是一个跨浏览器兼容的库，旨在简化 HTML 应用程序开发人员的生活。它由 John Resig 于 2006 年首次发布，自那以后已成为世界上最流行的 JavaScript 库，并在数百万个网站中使用。

为什么它变得如此受欢迎？嗯，jQuery 有一些不错的功能，如简单的 DOM 操作和查询、事件处理和动画，以及 AJAX 支持。所有这些结合在一起使得针对 DOM 编程和 JavaScript 编程变得更好。

该库在跨浏览器兼容性和速度方面也经过了高度优化，因此使用 jQuery 的 DOM 遍历和操作函数不仅可以节省您编写繁琐代码的时间，而且通常比您自己编写的代码快得多。

事实证明，jQuery 和 CoffeeScript 非常搭配，结合起来提供了一个强大的工具集，以简洁和表达力的方式编写 Web 应用程序。

在本章中，我们将做以下事情：

+   探索 jQuery 的一些高级功能，并讨论它给您带来了什么

+   学习如何在浏览器中使用 CoffeeScript 和 jQuery

+   使用 jQuery 和 CoffeeScript 构建一个简单的待办事项列表应用程序

让我们首先更详细地讨论 jQuery 库，并发现它的有用之处。

# 查找和更改元素

在 Web 浏览器中，DOM 或文档对象模型是用于与 HTML 文档中的元素进行编程交互的表示。

在 JavaScript 中，您会发现自己需要进行大量的 DOM 遍历，以查找您感兴趣的元素，然后对它们进行操作。

要使用标准的 JavaScript 库来实现这一点，通常需要使用`document.getElementsByName`、`document.getElementById`和`document.getElementsById`方法的组合。一旦您的 HTML 结构开始变得复杂，这通常意味着您将不得不在笨拙和繁琐的迭代代码中组合这些方法。

以这种方式编写的代码通常对 HTML 的结构做出了很多假设，这意味着如果 HTML 发生变化，它通常会中断。

## $函数

使用`$`函数（jQuery 的工厂方法，用于创建 jQuery 类的实例）和大部分库的入口点，许多这种命令式风格的代码变得更简单。

这个函数通常以 CSS 选择器字符串作为参数，该参数可用于根据元素名称、ID、类属性或其他属性值选择一个或多个元素。此方法将返回一个包含与选择器匹配的一个或多个元素的 jQuery 对象。

在这里，我们将使用`$`函数选择文档中所有具有`address`类的`input`标签：

```js
$('input .address')
```

然后，您可以使用多种函数来操作或查询这些元素，通常称为**命令**。以下是一些常见的 jQuery 命令及其用途：

+   `addClass`：这将向元素添加一个 CSS 类

+   `removeClass`：这从元素中删除一个 CSS 类

+   `attr`：这从元素中获取一个属性

+   `hasClass`：这检查元素上是否存在 CSS 类

+   `html`：这获取或设置元素的 HTML 文本

+   `val`：这获取或设置元素的值

+   `show`：这显示一个元素

+   `hide`：这隐藏一个元素

+   `parent`：这获取一个元素的父元素

+   `appendTo`：这附加一个子元素

+   `fadeIn`：这淡入一个元素

+   `fadeout`：这淡出一个元素

大多数命令返回一个 jQuery 对象，可以用来链接其他命令。通过链接命令，您可以使用一个命令的输出作为下一个命令的输入。这种强大的技术让您可以对 HTML 文档的部分进行非常简短和简洁的转换。

假设我们想要突出显示并启用 HTML 表单中的所有`address`输入；jQuery 允许我们做类似于这样的事情：

```js
$('input .address').addClass('highlighted').removeAttr('disabled')
```

在这里，我们再次选择所有具有`address`类的`input`标签。我们使用`addClass`命令为每个标签添加`highlighted`类，并通过链接到`removeAttr`命令来移除`disabled`属性。

# 实用函数

jQuery 还提供了许多实用函数，通常可以改善您日常的 JavaScript 编程体验。这些都是作为全局 jQuery 对象的方法的形式，如`$.methodName`。例如，其中一个最常用的实用程序是`each`方法，可用于迭代数组或对象，并且可以按如下方式调用（在 CoffeeScript 中）：

```js
$.each [1, 2, 3, 4], (index, value) -> alert(index + ' is ' + value)
```

jQuery 的实用方法涵盖了数组和集合的辅助方法，时间和字符串操作，以及许多其他有用的 JavaScript 和与浏览器相关的函数。许多这些函数源自许多 JavaScript 程序员的日常需求。

通常，您会发现一个适用于您自己在编写 JavaScript 或 CoffeeScript 时遇到的常见问题或模式的函数。您可以在[`api.jquery.com/category/utilities/`](http://api.jquery.com/category/utilities/)找到这些函数的详细列表。

# Ajax 方法

jQuery 提供了`$.ajax`方法来执行跨浏览器的 Ajax 请求。传统上，这一直是一个痛点，因为各种浏览器都实现了不同的接口来处理 Ajax。jQuery 处理了所有这些，并提供了一种更简单的基于回调的方式来构建和执行 Ajax 请求。这意味着您可以声明性地指定应该如何进行 Ajax 调用，然后提供函数，jQuery 将在请求成功或失败时回调。

# 使用 jQuery

在浏览器中使用 jQuery 非常简单；您只需要在 HTML 文件中包含 jQuery 库。您可以从他们的网站下载最新版本的 jQuery（[`docs.jquery.com/Downloading_jQuery`](http://docs.jquery.com/Downloading_jQuery)）并引用，或者您可以直接链接到**内容传送网络**（**CDN**）版本的库。

以下是一个示例。这段代码来自优秀的 HTML5 Boilerplate 项目（[`html5boilerplate.com/`](http://html5boilerplate.com/)）。在这里，我们包含了来自 Google CDN 的最新压缩版 jQuery，但如果从 CDN 引用失败，我们也将包含本地版本。

```js
<script src="img/jquery.min.js"></script>
    <script>window.jQuery || document.write('<script src="img/jquery-1.7.2.min.js"><\/script>')
</script>
```

# 在浏览器中使用 CoffeeScript 和 jQuery

在我们开始使用 jQuery 和 CoffeeScript 之前，让我们谈谈如何编写在浏览器中运行的 CoffeeScript 代码。

## 编译 CoffeeScript

为 Web 应用程序编译 CoffeeScript 的最常见方法是运行`coffee`命令，以监视一个或多个 CoffeeScript 文件的更改，然后将它们编译为 JavaScript。然后将输出包含在您的 Web 应用程序中。

例如，我们将组织我们的项目文件夹结构，看起来像以下文件夹结构：

![编译 CoffeeScript](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_03_01.jpg)

'

**src**文件夹是您的 CoffeeScript 文件所在的位置。然后，我们可以启动一个 CoffeeScript 编译器来监视该文件夹，并将 JavaScript 编译到我们的**public/js**文件夹中。

这是 CoffeeScript 命令的样子：

```js
coffee -co public/js -w src/
```

在自己的终端窗口中保持此命令运行，并在保存文件时重新编译您的 CoffeeScript 文件。

### 提示

CoffeeScript 标签

在浏览器中运行 CoffeeScript 的另一种方法是在文档中包含内联的 CoffeeScript，包含在`<script type="text/coffeescript">`标签中，然后在文档中包含压缩的 CoffeeScript 编译器脚本（`coffee-script.js`）。这将编译并运行页面中的所有内联 CoffeeScript。

这并不是为了严肃使用，因为每次加载页面时都会为编译步骤付出严重的性能代价。然而，有时候在浏览器中快速玩一下 CoffeeScript 可能会非常有用，而不需要设置完整的编译器链。

## jQuery 和 CoffeeScript

让我们在我们的 CoffeeScript 文件中放一些东西，看看我们是否可以成功地将其与 jQuery 连接起来。在`src`文件夹中，创建一个名为`app.coffee`的文件，并包含以下代码：

```js
$ -> alert "It works!"
```

这设置了 jQuery 的`$(document).ready()`函数，该函数在应用程序初始化时将被调用。在这里，我们使用了它的简写语法，只需将一个匿名函数传递给`$`函数。

现在，你应该在`public/js`文件夹中有一个`app.js`文件，内容类似于这样：

```js
// Generated by CoffeeScript 1.3.3
(function() {
    alert('It works!');
}).call(this);
```

最后，我们需要在我们应用程序的 HTML 文件中包含这个文件以及 jQuery。在`public/index.html`文件中，添加以下代码：

```js
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
  <title>jQuery and CoffeeScript Todo</title>
  <link rel="stylesheet" href="css/styles.css">
</head>
<body>
  <script src="img/jquery.min.js"></script>
  <script src="img/app.js"></script>
</body>
</html>
```

上面的代码创建了我们的 HTML 骨架，并包含了 jQuery（使用 Google CDN）以及我们的应用程序代码。

### 提示

**下载示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/`](http://www.PacktPub.com/)支持并注册，以便直接通过电子邮件接收文件。

## 测试全部

我们现在应该能够通过在浏览器中打开我们的`index.html`文件来运行我们的应用程序。如果一切顺利，我们应该看到我们的警报弹出窗口，如下面的截图所示：

![测试全部](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_03_02.jpg)

## 运行本地 Web 服务器

虽然我们现在可以从磁盘轻松测试我们的 Web 应用程序，但是很快我们可能想要将其托管在本地 Web 服务器上，特别是如果我们想要开始进行 Ajax。由于我们已经安装了 Node.js，所以运行 Web 服务器应该非常容易，我们现在只需要为静态内容提供服务。幸运的是，有一个 npm 包可以为我们做到这一点；它名为**http-server**，可以在[`github.com/nodeapps/http-server`](https://github.com/nodeapps/http-server)找到。

要安装它，只需运行以下命令：

```js
npm install http-server -g
```

然后，我们通过导航到我们的应用程序文件夹并输入以下内容来执行它：

```js
http-server
```

这将在端口**8080**上托管 public 文件夹中的所有文件。现在，我们应该能够通过使用 URL `http://localhost:8080/`来访问我们托管的站点。

# 我们的应用程序

在本章的其余部分，我们将使用 CoffeeScript 构建一个 jQuery 应用程序。该应用程序是一个待办事项列表应用程序，可用于跟踪您的日常任务以及您如何完成它们。

## TodoMVC

我已经模仿了 TodoMVC 项目的一些源代码来建模应用程序，该项目属于公共领域。该项目展示了不同的 JavaScript MVC 框架，所有这些框架都用于构建相同的应用程序，在评估框架时可能非常有用。如果你想要查看它，可以在[`addyosmani.github.com/todomvc/`](http://addyosmani.github.com/todomvc/)找到。

### 注意

**MVC**，或者模型-视图-控制器，是一种广泛使用的应用程序架构模式，旨在通过将应用程序关注点分为三种领域对象类型来简化代码并减少耦合。我们将在本书的后面更详细地讨论 MVC。

我们将主要基于 TodoMVC 项目来构建我们的应用程序，以获得与之配套的令人赞叹的样式表以及精心设计的 HTML5 结构。然而，大部分客户端 JavaScript 将被重写为 CoffeeScript，并且为了说明的目的将被简化和修改很多。

所以，话不多说，让我们开始吧！

## 我们的初始 HTML

首先，我们将添加一些 HTML，以便我们可以输入待办事项并查看现有项目的列表。在`index.html`中，在包含的`script`标签之前，将以下代码添加到`body`标签中：

```js
<section id="todoapp">
    <header id="header">
      <h1>todos</h1>
      <input id="new-todo" placeholder="What needs to be done?" autofocus>
    </header>
    <section id="main">
      <ul id="todo-list"></ul>
    </section>
    <footer id="footer">
      <button id="clear-completed">Clear completed</button>
    </footer>
  </section> 
```

让我们简要地浏览一下前面标记的结构。首先，我们有一个带有`todoapp`ID 的部分，它将作为应用程序的主要部分。它包括一个`header`标签，用于创建新项目的输入，一个`main`部分，用于列出所有待办事项，以及一个`footer`部分，其中有**清除已完成**按钮。在我们在浏览器中打开这个页面之前，让我们从我们的`app.coffee`文件中删除之前的警报行。

当你导航到这个页面时，它看起来不怎么样。这是因为我们的 HTML 还没有被样式化。下载本章的`styles.css`文件，并将其复制到`public/css`文件夹中。现在它应该看起来好多了。

## 初始化我们的应用程序

大多数 jQuery 应用程序，包括我们的应用程序，都遵循类似的模式。我们创建一个`$(document).ready`处理程序，然后执行页面初始化，通常包括为用户操作挂接事件处理程序。让我们在我们的`app.coffee`文件中这样做。

```js
class TodoApp
  constructor: ->
    @bindEvents()

  bindEvents: ->
    alert 'binding events'

$ ->
  app = new TodoApp()
```

在前面的代码片段中，我们创建了一个名为`TodoApp`的类，它将代表我们的应用程序。它有一个构造函数，调用`bindEvents`方法，目前只显示一个警报消息。

我们设置了 jQuery 的`$(document).ready`事件处理程序来创建我们的`TodoApp`的一个实例。当你重新加载页面时，你应该会看到**绑定事件**的警报弹出窗口。

### 提示

**没有看到预期的输出？**

记得要留意后台运行的咖啡编译器的输出。如果有任何语法错误，编译器会输出错误消息。一旦你修复了它，编译器应该会重新编译你的新 JavaScript 文件。记住，CoffeeScript 对空白很敏感。如果遇到任何你不理解的错误，请仔细检查缩进。

## 添加待办事项

现在我们可以添加事件处理来实际将待办事项添加到列表中。在我们的`bindEvents`函数中，我们将选择`new-todo`输入并处理它的`keyup`事件。我们将绑定它来调用我们类的`create`方法，我们也将去定义它；这在下面的代码片段中显示：

```js
  bindEvents: ->
    $('#new-todo').on('keyup', @create)

  create: (e) ->
    $input = $(this)
    val = ($.trim $input.val())
    return unless e.which == 13 and val
    alert val
    # We create the todo item
```

`$('#new-todo')`函数使用 jQuery 的 CSS 选择器语法来获取具有`new-todo`ID 的输入，`on`方法将`create`方法绑定到它的`'keyup'`事件，每当输入有焦点时按下键时触发。

在`create`函数中，我们可以通过使用`$(this)`函数来获取输入的引用，它将始终返回生成事件的元素。我们将这个赋给`$input`变量。在分配 jQuery 变量时，使用以`$`为前缀的变量名是一种常见的约定。然后我们可以使用`val()`函数获取输入的值，并将其赋给一个本地的`val`变量。

我们可以通过检查`keyup`事件的`which`属性是否等于`13`来判断*Enter*键是否被按下。如果是，并且`val`变量不是`null`，我们可以继续创建待办事项。现在，我们只会使用警报消息输出它的值。

一旦我们创建了项目，我们应该把它放在哪里？在许多传统的 Web 应用程序中，这些数据通常会使用 Ajax 请求存储在服务器上。我们希望现在保持这个应用程序简单，暂时只在客户端保留这些项目。HTML5 规范为我们定义了一个叫做**localStorage**的机制，可以做到这一点。

### 使用 localStorage

`localStorage`是新的 HTML5 规范的一部分，允许你在浏览器中存储和检索对象的本地数据库。接口非常简单；在支持的浏览器中，会存在一个名为`localStorage`的全局变量。这个变量有以下三个重要的方法：

```js
localStorage.setItem(key, value)
localStorage.getItem(key)
localStorage.removeItem(key)
```

`key`和`value`参数都是字符串。存储在`localStorage`变量中的字符串即使在页面刷新时也会保留。在大多数浏览器中，你可以在`localStorage`变量中存储多达 5MB 的数据。

因为我们想将待办事项存储为一个复杂的对象而不是一个字符串，所以在设置和从`localStorage`获取项目时，我们使用了常用的将对象转换为 JSON 对象的技术。为此，我们将在`Storage`类的原型中添加两个方法，然后这些方法将在全局`localStorage`对象上可用。在我们的`app.coffee`文件的顶部添加以下代码片段：

```js
Storage::setObj = (key, obj) ->
  @setItem key, JSON.stringify(obj)

Storage::getObj = (key) ->
  JSON.parse @getItem(key)
```

在这里，我们使用`::`运算符将`setObj`和`getObj`方法添加到`Storage`类中。这些函数通过将对象转换为 JSON 来包装`localStorage`对象的`getItem`和`setItem`方法。

现在我们终于准备好创建我们的待办事项并将其存储在`localStorage`中。

这是我们`create`方法的其余部分：

```js
  create: (e)->
    $input = $(this)
    val = ($.trim $input.val())
    return unless e.which == 13 and val

 randomId = (Math.floor Math.random()*999999)

 localStorage.setObj randomId,{
 id: randomId
 title: val
 completed: false
 }
 $input.val ''

```

为了唯一标识任务，我们将使用最简单的方法，只生成一个大的随机数作为 ID。这不是最复杂的标识文档的方法，您可能不应该在生产环境中使用这种方法。但是，它很容易实现，并且暂时很好地满足了我们的目的。

生成 ID 后，我们现在可以使用我们的`setObj`方法将待办事项放入我们的本地数据库。我们传入了一个从`input`标签值中获取的标题，并将项目默认为未完成。

最后，我们清除了`$input`的值，以便用户可以直观地看到`create`是成功的。

我们现在应该能够测试我们的小应用程序，并查看待办事项是否被存储到`localStorage`中。谷歌 Chrome 开发者工具将允许您在**资源**选项卡中检查`localStorage`。添加几个任务后，您应该能够在这里看到它们，如下面的截图所示：

![使用 localStorage](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_03_03.jpg)

## 显示待办事项

现在我们可以存储一个待办事项列表，如果我们能在屏幕上看到它们就更好了。为此，我们将添加一个`displayItems`方法。这将遍历待办事项的本地列表并显示它们。

在我们的`TodoApp`中添加以下代码，放在`create`方法之后：

```js
displayItems: ->
    alert 'displaying items'
```

现在我们应该能够从`create`方法中调用这个方法，如下面的代码所示：

```js
  create: (e) ->
    $input = $(this)
    val = ($.trim $input.val())
    return unless e.which == 13 and val

    randomId = (Math.floor Math.random()*999999)

    localStorage.setObj randomId,{
      id: randomId
      title: val
      completed: false
    }
    $input.val ''
 @displayItems()

```

让我们运行这段代码看看会发生什么。当我们这样做时，我们会得到以下错误：

**Uncaught TypeError: Object #<HTMLInputElement> has no method 'displayItems'**

这里发生了什么？似乎对`@displayItems()`的调用试图在`HTMLInputElement`的实例上调用该方法，而不是在`TodoApp`上调用。

这是因为 jQuery 会将`this`的值设置为引发事件的元素。当我们将类方法绑定为事件处理程序时，jQuery 实际上会“劫持”`this`，使其不指向类本身。这是在使用 jQuery 和 CoffeeScript 中应该知道的一个重要注意事项。

为了修复它，我们可以在设置`keyup`事件处理程序时使用 CoffeeScript 的 fat 箭头，这将确保`this`的值保持不变。让我们修改我们的`bindEvents`方法，使其看起来类似于以下代码：

```js
  bindEvents: ->
 $('#new-todo').on('keyup',(e) => @create(e))

```

只剩下一件事了；在我们的`createItem`方法中，我们使用`$(this)`来获取引发事件的`input`元素的值。由于切换到了 fat 箭头，现在这将指向我们的`TodoApp`实例。幸运的是，传递的事件参数有一个 target 属性，也指向我们的输入。将`create`方法的第一行更改为以下代码片段：

```js
  create: (e) ->
 $input = $(e.target)
    val = ($.trim $input.val())
```

现在，当我们创建一个项目时，我们应该看到“显示项目”警报，这意味着`displayItems`方法已经正确连接。

我们可以做得更好。由于每次触发`create`方法时都需要查找`$input`标签，我们可以将其存储在一个类变量中，以便可以重复使用。

这个最好放在应用程序启动时。让我们创建一个`cacheElements`方法来做到这一点，并在构造函数中调用它-这在下面的代码中有所突出：

```js
class TodoApp

  constructor: ->
 @cacheElements()
    @bindEvents()

 cacheElements: ->
 @$input = $('#new-todo')

  bindEvents: ->
 @$input.on('keyup',(e) => @create(e))

  create: (e) ->
 val = ($.trim @$input.val())
    return unless e.which == 13 and val

    randomId = (Math.floor Math.random()*999999)

    localStorage.setObj randomId,{
      id: randomId
      title: val
        completed: false
    }
 @$input.val ''
 @displayItems()
```

`cacheElements`调用分配了一个名为`@$input`的类变量，然后在我们的类中使用它。这种`@$`语法一开始可能看起来很奇怪，但它可以用几个按键传达很多信息。

## 显示待办事项

现在我们应该能够显示项目了。在`displayItems`方法中，我们将遍历所有`localStorage`键，并使用它们获取每个对应的待办事项。对于每个项目，我们将向`todo-list` ID 的`ul`元素添加一个`li`子元素。在开始使用`$('#todo-list')`元素之前，让我们像我们对`@$input`所做的那样缓存它的值：

```js
  cacheElements: ->
    @$input = $('#new-todo')
 @$todoList = $('#todo-list')
  displayItems: ->
 @clearItems()
 @addItem(localStorage.getObj(id)) for id in Object.keys(localStorage)

 clearItems: ->
 @$todoList.empty()

 addItem: (item) ->
 html = """
 <li #{if item.completed then 'class="completed"' else ''} data-id="#{item.id}">
 <div class="view">
 <input class="toggle" type="checkbox" #{if item.completed then 'checked' else ''}>
 <label>#{item.title}</label>
 <button class="destroy"></button>
 </div>
 </li> 
 """
 @$todoList.append(html)

```

在这里，我们稍微修改了`displayItems`方法。首先，我们从`$@todoList`中删除任何现有的子列表项，然后我们循环遍历`localStorage`中的每个键，获取具有该键的对象，并将该项目发送到`addItem`方法。

`addItem`方法构建了待办事项的 HTML 字符串表示，然后使用 jQuery 的`append`函数将子元素附加到`$@todoList`。除了标题的标签之外，我们还创建了一个复选框来设置任务为已完成，并创建了一个按钮来删除任务。

注意`li`元素上的`data-id`属性。这是 HTML5 数据属性，它允许您向任何元素添加任意数据属性。我们将使用它将每个`li`链接到`localStorage`对象中的待办事项。

### 注意

虽然 CoffeeScript 可以使构建 HTML 字符串变得更容易一些，但在客户端代码中定义标记很快就会变得繁琐。我们在这里主要是为了说明目的而这样做；最好使用 JavaScript 模板库，比如 Handlebars（[`handlebarsjs.com/`](http://handlebarsjs.com/)）。

这些类型的库允许您在您的标记中定义模板，然后使用特定上下文编译它们，然后为您提供一个漂亮格式的 HTML，然后您可以将其附加到元素上。

最后一件事，现在我们可以在创建项目后显示项目，让我们将`displayItems`调用添加到构造函数中，以便我们可以显示现有的待办事项；这个调用在下面的代码中突出显示：

```js
  constructor: ->
    @cacheElements()
    @bindEvents()
 @displayItems()

```

## 移除和完成项目

让我们连接移除任务按钮。我们为它添加一个事件处理程序如下：

```js
  bindEvents: ->
    @$input.on('keyup',(e) => @create(e))
 @$todoList.on('click', '.destroy', (e) => @destroy(e.target)) 

```

在这里，我们处理`@$todoList`上任何子元素的点击事件，带有`.destroy`类。

我们再次使用胖箭头创建处理程序，调用`@destroy`方法并传入目标，这应该是被点击的**destroy**按钮。

现在，我们需要使用以下代码片段创建`@destroy`方法：

```js
  destroy: (elem) ->
    id = $(elem).closest('li').data('id')
    localStorage.removeItem(id)
    @displayItems()
```

`closest`函数将找到距离按钮最近定义的`li`元素。我们使用 jQuery 的`data`函数检索其`data-id`属性，然后我们可以使用它从`localStorage`中删除待办事项。还要调用一次`@displayItems`来刷新视图。

完成项目将遵循非常相似的模式；也就是说，我们添加一个事件处理程序，如下面的代码中所示：

```js
  bindEvents: ->
    @$input.on('keyup',(e) => @create(e))
    @$todoList.on('click', '.destroy', (e) => @destroy(e.target))
 @$todoList.on('change', '.toggle', (e) => @toggle(e.target))

```

这次我们处理了`'change'`事件，每当选中或取消选中已完成复选框时都会触发。这将调用`@toggle`方法，其代码如下：

```js
  toggle: (elem) ->
    id = $(elem).closest('li').data('id')
    item = localStorage.getObj(id)
    item.completed = !item.completed
    localStorage.setObj(id, item)
```

这个方法还使用`closest`函数来获取待办事项的 ID。它从`localStorage`中加载对象，切换`completed`的值，然后使用`setObj`方法将其保存回`localStorage`。

## 现在轮到你了！

作为最后的练习，我要求您使**清除已完成**按钮起作用。

# 总结

在本章中，我们了解了 jQuery 是什么，以及它的优势和好处是什么。我们还学习了如何将 jQuery 的强大功能与 CoffeeScript 结合起来，以更少的工作量和复杂性编写复杂的 Web 应用程序。jQuery 是一个非常庞大的库，我们只是触及了它所提供的一小部分。我建议您花一些时间学习库本身，并使用 CoffeeScript 进行学习。

接下来，我们将首先看一下如何使用 CoffeeScript 和 Rails 开始与服务器端代码进行交互。
