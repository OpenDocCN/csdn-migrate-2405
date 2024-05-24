# NodeJS 安全指南（一）

> 原文：[`zh.annas-archive.org/md5/91CEAEA2591BB800A796372BF456968C`](https://zh.annas-archive.org/md5/91CEAEA2591BB800A796372BF456968C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Node.js 是使用 JavaScript 构建服务器应用程序的快速增长平台。现在它在生产环境中的使用越来越广泛，Node.js 应用程序将开始受到特定的安全漏洞攻击。保护您的用户将需要了解 Node.js 独有的攻击向量以及与其他 Web 应用程序平台共享的攻击向量。

# 本书涵盖的内容

第一章, *Node.js 简介*，介绍了 Node.js 并解释了它与其他开发平台的不同之处。

第二章, *一般考虑*，介绍了一般的安全考虑，特别是 JavaScript 本身以及 Node.js 应用程序的安全考虑。

第三章, *应用考虑*，涉及了与应用程序相关的安全问题，包括身份验证、授权和错误处理。

第四章, *请求层考虑*，涵盖了特定于请求处理的漏洞，例如**跨站请求伪造**（**CSRF**）。

第五章, *响应层漏洞*，处理了在响应处理期间或之后出现的问题，例如**跨站脚本**（**XSS**）。

为了充分利用本书，您应该在系统上安装 Node.js。有关许多平台的说明，请访问[`nodejs.org/`](http://nodejs.org/)。熟悉 npm 及其命令行用法。它与 Node.js 捆绑在一起，因此不需要额外安装。

# 这本书是为谁准备的

本书旨在帮助开发人员保护其 Node.js 应用程序，无论他们是已经在生产中使用它，还是考虑将其用于下一个项目。了解 JavaScript 是前提条件，建议具有一些 Node.js 的经验，但不是必需的。

# 约定

在本书中，您将找到许多不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“应该注意`EventEmitter`对象在错误事件方面具有非常特定的行为。”

代码块设置如下：

```js
function sayHello(name) {
       "use strict"; // enables strict mode for this function scope
      console.log("hello", name);
}
```

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：Node.js 简介

Node.js 已经开启了服务器端 JavaScript 的时代，这是客户端 JavaScript 在过去几年中经历的复兴的下一个逻辑步骤。虽然 Node.js 不是第一个服务器端 JavaScript 实现，但它肯定成为了最受欢迎的。通过利用 JavaScript 作为一种语言的最佳特性并培养一个充满活力的社区，Node.js 已经成为一个非常受欢迎的平台和框架，而且没有放缓的迹象。关于 Node 是什么的很好描述可以在[`nodejs.org/`](http://nodejs.org/)找到：

> Node.js 是建立在 Chrome 的 JavaScript 运行时之上的平台，用于轻松构建快速、可扩展的网络应用程序。Node.js 使用事件驱动的、非阻塞的 I/O 模型，使其轻量高效，非常适合在分布式设备上运行的数据密集型实时应用程序。

# Node.js 的历史

该项目始于 2009 年，是 Ryan Dahl 的创意。在那一年的 JSConf.eu（欧洲每年举办的会议）上，他做了演讲，改变了 JavaScript 开发的面貌。他的演讲包括了一个完整的 IRC 服务器的令人印象深刻的演示，该服务器用大约 400 行 JavaScript 编写。在他的演讲中，他概述了为什么开始这个项目，为什么 JavaScript 成为其中一个重要部分，以及他在服务器编程领域中希望实现的目标，特别是关于我们如何处理输入和输出（I/O）。

那一年晚些时候，**npm**项目开始了，其目标是管理 Node.js 应用程序的软件包，并创建一个公开可用的注册表，供 Node.js 开发人员之间共享代码。截至 Node.js 的 0.6.3 版本，npm 已经部署并与 Node.js 一起安装，成为事实上的软件包管理器。

# Node.js 的不同之处？

Node.js 与其他平台的不同之处在于它如何处理 I/O。它使用事件循环与异步 I/O 相结合，这使得它能够以轻量级的方式实现高并发性。

通常，当程序需要某种外部输入时，它会以同步的方式进行。以下代码行对任何程序员来说应该非常熟悉：

```js
var results = db.query("SELECT * FROM users");
print(results[0].username);
```

我们在这里所做的一切就是查询 SQL 数据库中所有用户的列表，然后打印出第一个用户的名字。在查询这样的数据库时，需要采取许多中间步骤，例如：

1.  打开到数据库服务器的连接。

1.  将请求通过网络传输到该服务器。

1.  服务器本身需要在接收到请求后处理该请求。

1.  服务器必须通过网络将响应传输回我们的应用程序。

这个列表并没有涵盖所有的细节，因为有比必要的要点更多的因素。通过查看我们的源代码，这被视为瞬时操作，但我们知道得更清楚。我们经常忽视这种浪费的时间，因为它发生得如此之快，以至于我们没有注意到它的发生。考虑以下表格：

| I/O 的成本 |
| --- |
| L1 缓存 | 3 个周期 |
| L2 缓存 | 14 个周期 |
| RAM | 250 个周期 |
| 磁盘 | 41,000,000 个周期 |
| 网络 | 240,000,000 个周期 |

每个 I/O 操作都有一个成本，在使用同步 I/O 的程序中直接支付。在程序可以继续进行之前，可能会有数百万甚至数千万个时钟周期发生。

编写应用程序服务器时，这样的程序一次只能为一个用户提供服务，直到上一个用户的所有 I/O 和处理完成后，才能为下一个用户提供服务。这是不可接受的，所以最简单的解决方案是为每个传入的请求创建一个新的线程，这样它们可以并行运行。

这就是**Apache**网页服务器的工作原理，实现起来并不困难。然而，随着同时用户数量的增加，内存使用量也会增加。每个线程都需要操作系统级别的开销，并且这些开销会迅速累积。此外，在这些线程之间进行上下文切换的开销比预期的更加耗时，进一步加剧了问题。

**nginx**网页服务器使用事件循环来处理进程。通过这样做，它能够同时处理更多的用户，使用更少的资源。事件循环要求将处理的位分解成小块，并在一个单一队列中运行。这消除了创建线程的高成本，来回切换线程之间的开销，并减少了对整个系统的需求。同时，它填补了处理间隙，特别是在等待 I/O 完成时发生的间隙。

Node.js 采用了 nginx 成功使用的事件驱动模型，并为许多类型的应用程序提供了相同的能力。在 Node.js 中，所有 I/O 都是完全异步的，不会阻塞应用程序的其他线程。Node.js API 接受函数参数（通常称为“回调函数”）进行所有 I/O 操作。然后 Node.js 启动该 I/O 操作，并让应用程序外的另一个线程进行处理。完成请求的操作后，事件循环被通知，回调函数被调用并返回结果。

事实证明，等待 I/O 完成是许多应用程序在原始处理时间方面最昂贵的部分。使用 Node.js，等待 I/O 的时间完全与应用程序的其余处理时间分离。你的应用程序只是使用回调函数来处理结果作为简单的事件，并且 JavaScript 的闭包能力保留了函数的上下文，尽管是异步执行的。

如果你要写一个多线程应用程序，你将不得不关注并发问题，比如死锁，这在真实应用程序中很难（甚至不可能）重现和调试。使用 Node.js，你的主要应用逻辑在单个线程上运行，不会出现这样的并发问题，而耗时的 I/O 则由 Node.js 代表你处理。

和其他平台一样，Node.js 有一个 API 供开发者编写他们的应用程序使用。JavaScript 本身缺乏标准库，特别是用于执行 I/O。这实际上成为 Ryan Dahl 选择 JavaScript 的原因之一。因为核心 API 可以从头开始构建，而不需要担心与标准库发生冲突，如果做错了（考虑到 JavaScript 的历史，这并不是一个不合理的假设）。

那个核心库是最小化的，但它包括了基本的模块。这包括但不限于：文件系统访问、网络通信、事件、二进制数据结构和流。其中许多 API 虽然不难使用，但在实现上非常底层。考虑一下这个直接来自 Node.js 网站的“Hello World”演示（附加了注释）：

```js
// one of the core modules
var http = require('http');
// creates an http server, this function is called for each request
http.createServer(function (req, res) {
  // these parameters represent the request and response objects
  // the response is going to use a HTTP status code 200 (OK)
  // the content-type HTTP header is set as well
  res.writeHead(200, {'Content-Type': 'text/plain'});
  // lastly, the response is concluded with simple text
  res.end('Hello World\n');
}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

这个服务器使用**http**核心模块来建立一个简单的网页服务器，向任何请求它的人发送“Hello World”。这是一个简单的例子，但没有注释的话，总共只有六行代码。

Node.js 团队选择保持核心库的范围有限，让开发者社区为其他所有内容创建他们所需的模块，比如数据库驱动程序、单元测试、模板和核心 API 的抽象。为了帮助这个过程，Node.js 有一个叫做 npm 的包管理器。

npm 是处理 Node.js 应用程序安装依赖项的工具。它选择本地捆绑的依赖项，而不是使用单一的全局命名空间。这允许不同的项目拥有自己的依赖项，即使这些项目之间的版本不同。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/supportand`](http://www.packtpub.com/supportand)注册，将文件直接发送到您的电子邮件。

除了允许使用第三方模块外，npm 还使得向注册表贡献成为公开的事务。将模块添加到注册表就像执行一个简单的命令一样，使得进入门槛极低。如今，npm 注册表上列出了超过 42,000 个软件包，并且每天都在快速增长。

注册表增长如此迅速，显然背后有一个充满活力的生态系统。我个人可以证明，Node.js 开发者社区非常友好，极其多产，并且有巨大的热情。

# 保护 Node.js 应用程序

在保护您的应用程序时，有许多因素需要考虑。我们将首先检查 JavaScript 本身，然后分析 Node.js 作为一个平台，并揭示一些与讨论相关的内部信息。之后，我们将调查整个应用程序的考虑因素和模式。最后，我们将调查应用程序请求和响应级别的漏洞。通过本书的最后，您应该对 Node.js 的内部有足够的了解，不仅能够解决我们在这里讨论的问题，还能够理解可能出现在您的应用程序中的任何未来漏洞。

# 摘要

在本章中，我们探讨了 Node.js 项目本身的历史，并介绍了开发环境和社区的背景。在下一章中，我们将首先查看 JavaScript 语言本身的安全功能。


# 第二章：一般考虑

构建安全的 Node.js 应用程序将需要理解它所构建的许多不同层次。从底层开始，我们有定义 JavaScript 组成的语言规范。接下来，虚拟机执行你的代码，并且可能与规范有所不同。在此之后，Node.js 平台及其 API 在操作上有细节会影响你的应用程序。最后，第三方模块与我们自己的代码交互，并且需要进行安全编程实践的审计。

首先，JavaScript 的官方名称是 ECMAScript。国际**欧洲计算机制造商协会**（**ECMA**）在 1997 年首次将这种语言标准化为**ECMAScript**。这个 ECMA-262 规范定义了 JavaScript 作为一种语言的组成，包括它的特性，甚至一些它的错误。甚至一些它的一般古怪之处在规范中保持不变，以保持向后兼容性。虽然我不会说规范本身是必读的，但我会说它是值得考虑的。

其次，Node.js 使用 Google 的**V8**虚拟机来解释和执行你的源代码。在为浏览器开发时，你需要考虑所有其他虚拟机（更不用说版本了），以及可用的功能。在 Node.js 应用程序中，你的代码只在服务器上运行，因此你有更多的自由，并且可以使用 V8 中可用的所有功能。此外，你还可以专门为 V8 引擎进行优化。

接下来，Node.js 处理设置事件循环，并且它会接受你的代码来注册事件的回调并相应地执行它们。在开发应用程序时，你需要注意 Node.js 对异常和其他错误的响应的一些重要细节。

Node.js 之上是开发者 API。这个 API 主要用 JavaScript 编写，允许你作为 JavaScript 开发者自己阅读它，并理解它的工作原理。有许多提供的模块可能会被你使用，了解它们的工作原理对你来说很重要，这样你就可以进行防御性编码。

最后，npm 提供给你访问的第三方模块数量众多，这可能是一把双刃剑。一方面，你有很多选项可以满足你的需求。另一方面，拥有第三方代码可能是一个潜在的安全责任，因为你需要支持和审计每一个这些模块（以及它们自己的依赖项）以寻找安全漏洞。

# JavaScript 安全

JavaScript 本身最大的安全风险之一，无论是在客户端还是现在在服务器端，就是使用`eval()`函数。这个函数，以及类似它的其他函数，接受一个字符串参数，它可以表示一个表达式、语句或一系列语句，并且会像其他 JavaScript 源代码一样被执行。这在下面的代码中有所展示：

```js
// these variables are available to eval()'d code
// assume these variables are user input from a POST request
var a = req.body.a; // => 1
var b = req.body.b; // => 2
var sum = eval(a + "+" + b); // same as '1 + 2'
```

这段代码可以完全访问当前作用域，甚至可以影响全局对象，给它带来了令人担忧的控制权。让我们看看相同的代码，但想象一下如果有人恶意发送任意的 JavaScript 代码而不是一个简单的数字。结果如下所示：

```js
var a = req.body.a; // => 1
var b = req.body.b; // => 2; console.log("corrupted");
var sum = eval(a + "+" + b); // same as '1 + 2; console.log("corrupted");
```

由于这里`eval()`的滥用，我们正在目睹一次“远程代码执行”攻击！当直接在服务器上执行时，攻击者可能会访问服务器文件和数据库。`eval()`有一些情况下可能会有用，但如果用户输入涉及到任何步骤，那么最好尽量避免使用！

JavaScript 还有其他与`eval()`功能等效的功能，除非绝对必要，否则也应该避免使用。首先是`Function`构造函数，它允许你从字符串创建一个可调用的函数，如下面的代码所示：

```js
// creates a function that returns the sum of 2 arguments
var adder = new Function("a", "b", "return a + b");
adder(1, 2); // => 3
```

虽然与`eval()`函数非常相似，但并非完全相同。这是因为它无法访问当前范围。但是，它仍然可以访问全局对象，并且在涉及用户输入时应避免使用。

如果发现自己处于需要执行涉及用户输入的任意代码的情况下，确实有一个安全选项。Node.js 平台的 API 包括一个旨在让您能够在沙盒中编译和运行代码的**vm**模块，以防止操纵全局对象甚至当前范围。

应该注意，vm 模块存在许多已知问题和边缘情况。您应该阅读文档，并了解您所做的一切可能带来的影响，以确保您不会措手不及。

# ES5 功能

ECMAScript5 对 JavaScript 进行了广泛的更改，包括以下更改：

1.  严格模式用于从语言中删除不安全的功能。

1.  属性描述符可控制对象和属性访问。

1.  更改对象可变性的功能。

## 严格模式

严格模式改变了 JavaScript 代码在某些情况下的运行方式。首先，它会在以前是静默的情况下抛出错误。其次，它会删除和/或更改使 JavaScript 引擎优化变得困难或不可能的功能。最后，它禁止了一些可能出现在未来版本 JavaScript 中的语法。

此外，严格模式仅适用于选择加入，并且可以全局应用或应用于单个函数范围。对于 Node.js 应用程序，要全局启用严格模式，请在执行程序时添加`-use_strict`命令行标志。

### 提示

在处理可能使用严格模式的第三方模块时，这可能会对整个应用程序产生负面影响。话虽如此，您可能会要求第三方模块的审核符合严格模式的要求。

通过在函数开头添加`"use strict"`指示符，可以启用严格模式，在任何其他表达式之前，如下面的代码所示：

```js
function sayHello(name) {
    "use strict"; // enables strict mode for this function scope
    console.log("hello", name);
}
```

在 Node.js 中，所有所需的文件都包装在一个处理`CommonJS`模块 API 的函数表达式中。因此，您可以通过简单地将指令放在文件顶部来为整个文件启用严格模式。这不会像在浏览器等环境中那样全局启用严格模式。

严格模式对语法和运行时行为进行了许多更改，但为了简洁起见，我们只讨论与应用程序安全相关的更改。

首先，在严格模式下，通过`eval()`运行的脚本无法向封闭范围引入新变量。这可以防止在运行`eval()`时泄漏新的可能会与现有变量冲突的变量，如下面的代码所示：

```js
"use strict";
eval("var a = true");
console.log(a); // ReferenceError thrown – a does not exist
```

此外，通过`eval()`运行的代码无法通过其上下文访问全局对象。这与其他函数范围的更改类似，不过稍后将对此进行解释，但对于`eval()`来说，这是特别重要的，因为它不能再使用全局对象执行其他黑魔法。

事实证明，`eval()`函数可以在 JavaScript 中被覆盖。可以通过创建一个名为`eval`的新全局变量，并为其分配其他内容来实现。严格模式禁止了这种操作。它更像是一个语言关键字而不是一个变量，尝试修改它将导致语法错误，如下面的代码所示：

```js
// all of the examples below are syntax errors
"use strict";
eval = 1;
++eval;
var eval;
function eval() { }
```

接下来，函数对象更加安全。ECMAScript 的一些常见扩展为每个函数添加了 `function.caller` 和 `function.arguments` 引用，这些引用在函数调用后出现。实际上，您可以通过遍历这些特殊引用来“遍历”特定函数的调用堆栈。这可能会暴露通常看起来超出范围的信息。严格模式只是在尝试读取或写入这些属性时抛出 `TypeError` 备注，如下面的代码所示：

```js
"use strict";
function restricted() {
    restricted.caller;    // TypeError thrown
    restricted.arguments; // TypeError thrown
}
```

接下来，在严格模式下移除了 `arguments.callee`（例如前面显示的 `function.caller` 和 `function.arguments`）。通常，`arguments.callee` 指的是当前函数，但这个神奇的引用也暴露了一种“遍历”调用堆栈的方式，可能会揭示以前隐藏或超出范围的信息。此外，这个对象使得某些优化对 JavaScript 引擎来说变得困难或不可能。因此，当尝试访问时，它也会抛出 `TypeError` 异常，如下面的代码所示：

```js
"use strict";
function fun() {
    arguments.callee; // TypeError thrown
}
```

最后，使用 `null` 或 `undefined` 作为上下文执行的函数不再将全局对象强制转换为上下文。这适用于之前看到的 `eval()`，但更进一步地阻止了在其他函数调用中对全局对象的任意访问，如下面的代码所示：

```js
"use strict";
(function () {
    console.log(this); // => null
}).call(null);
```

严格模式可以帮助使代码比以前更加安全，但 ECMAScript 5 也通过属性描述符 API 包括了访问控制。JavaScript 引擎一直具有定义属性访问的能力，但 ES5 包括了这些 API，将同样的权力赋予应用程序开发人员。

## 对象属性描述符

对象属性具有以下三个隐藏属性，确定对它们可以进行哪些变化：

+   `writable`：如果这是 `false`，意味着属性值不能被更改（换句话说，只读）

+   `enumerable`：如果这是 `false`，意味着该属性在 for in 循环中不会出现

+   `configurable`：如果这是 `false`，意味着该属性不能被删除

在使用对象字面量或赋值定义对象属性时，这是最常见的方法，这三个隐藏属性的默认值都是 `true`。这使得属性在各个方面完全开放修改。然而，有一些新函数允许应用程序开发人员自行设置这些属性，限制对某些对象属性的访问。属性描述符 API 是完全自选的，即使在 ES5 中，对象属性的默认行为也不会改变。

首先，`Object.defineProperty()` 函数允许您在指定的对象上指定单个属性及其访问器描述符。它接受三个参数：目标对象、新属性的名称和前面提到的描述符对象。访问器描述符只是一个包含指定属性的对象，这些属性对应于前面列出的属性。

### 提示

访问器描述符告诉 JavaScript 引擎，要给我们的新属性赋予的访问级别。在使用 `Object.defineProperty()` 及其相关函数时，重要的是要注意，所有描述符属性值默认设置为 `false`。这与基本赋值相比产生了相反的效果。

```js
var o = {};

// the next 2 statements are completely identical in result

o.a = "A";

Object.defineProperty(o, "a", {
    writable: true,
    enumerable: true,
    configurable: true,
    value: "A"
});
```

这两个语句具有相同的结果，后者更加冗长。然而，传统赋值不能影响任何描述符，与后者不同。让我们看看创建“锁定”属性需要什么：

```js
var o = {};

Object.defineProperty(o, "a", {
    value: "A"
});
```

我们刚刚做的是创建了一个不能被写入、删除或枚举的属性，使其不可变。这允许应用程序开发人员控制数据访问，即使在各种代码边界之间共享对象。

访问器描述符提供的最后一个功能是允许开发人员为特定属性创建 getter 和 setter 函数。getter 是一个在访问属性时返回数据的函数，setter 存储通过赋值发送的数据。以下是示例代码：

```js
var person = {
    firstName: "Dominic",
    lastName: "Barnes"
};

Object.defineProperty(person, "name", {
    enumerable: true,
    get: function () {
        return this.firstName + " " + this.lastName;
    },
    set: function (input) {
        var names = input.split(" ");
        this.firstName = names[0];
        this.lastName = names[1];
    }
});

console.log(person.name); // => "Dominic Barnes"
```

这段代码创建了一个包含来自同一对象上的两个其他属性的数据的属性，并且是动态计算的。在许多情况下，可以使用函数来实现相同的效果，但这样可以更好地分离这两个操作，而不需要在对象本身上使用两个单独的函数。

下一个函数`Object.defineProperties()`类似。然而，这个函数只接受两个参数，宿主对象和另一个对象，该对象是多个属性的哈希，其中属性值都是访问器描述符。以下是示例代码：

```js
var letters = {};

Object.defineProperties(letters, {
    a: {
        enumerable: true,
        value: "A"
    },
    b: {
        enumerable: true,
        value: "B"
    }
});

console.log(letters.a); // => "A"
console.log(letters.b); // => "B"
```

这使我们可以将多个属性定义压缩成一个函数调用，这更多的是为了方便。接下来是其中最强大的函数：`Object.create()`函数。这个函数从头开始创建一个全新的对象，并为其分配一个原型。这反映了 JavaScript 的原型性质，我们不会花时间进一步讨论这一点，因为它与本讨论并不特别相关。

这个函数只接受两个参数，新对象的原型（或`null`以完全不继承）和一个属性对象，就像我们在`Object.defineProperties()`中使用的那样，如下面的代码所示：

```js
var constants = Object.create(null, {
    PI: {
        enumerable: true,
        value: 3.14
    },
    e: {
        enumerable: true,
        value: 2.72
    }
});
```

通过将原型设置为`null`，而不是其他对象，我们创建了一个完全普通的对象，它不继承任何东西，甚至不继承自`Object.prototype`对象。这是可取的，因为即使对`Object.prototype`的修改（这本来就是一个坏主意）也不会对使用这种方法创建的对象产生不利影响。

还有一些其他特殊的函数用于改变对象的可访问性。首先是`Object.preventExtensions()`函数，它防止向指定的对象添加新属性，如下面的代码所示：

```js
var o = {
    a: "A",
    b: "B",
    c: "C"
};

o.d = "D"; // works as expected

Object.preventExtensions(o);

o.e = "E"; // will not work
```

正如你所看到的，这允许你配置一个对象，以便其他人无法在你的对象上创建额外的属性。如果在混合中包括严格模式，最后的赋值将抛出错误，而不是悄无声息地失败。另外，应该注意的是，这个操作一旦发生就无法逆转。

接下来是`Object.seal()`函数，它接受一个对象，并防止属性被删除，除了`Object.preventExtensions()`函数的效果。换句话说，这将获取所有现有属性，并将它们的可配置属性设置为`false`。

```js
var o = {
    a: "A",
    b: "B",
    c: "C"
};

delete o.c; // works as expected

Object.seal(o);

delete o.b; // will not work
```

这很强大，因为我们可以保留对象的结构，但仍然允许属性值发生变化。与之前一样，这个操作是不可逆的。此外，添加严格模式会导致抛出异常，而不是允许操作悄无声息地失败。

最后是其中最强大的`Object.freeze()`函数。这个函数应用了与`Object.seal()`相同的效果，并完全锁定了所有属性。没有值可以被改变（即所有可写属性都设置为`false`），并且属性描述符都是不可修改的。这使得对象实际上是不可变的，并阻止所有其他尝试改变对象的任何操作，如下面的代码所示：

```js
var o = {
    a: "A",
    b: "B",
    c: "C"
};

// works as expected
o.a = 1;
delete o.c;

Object.freeze(o);

// will not work
o.a = "A";
delete o.b;
```

冻结对象与其他操作一样，是不可逆转的。在严格模式下，任何尝试写入或更改对象的操作都会引发错误。

# 静态程序分析

跟踪我们在这里讨论的所有事情可能会让人不知所措。当一个团队的人在同一个项目上工作时，问题会变得更加复杂。执行静态分析的工具会获取你的源代码（而不是执行它），并检查你可以配置的特定代码模式。

例如，你可以配置**JSHint**禁止使用`eval()`并要求所有函数使用严格模式。通过让它检查你的源代码，当违反这些规则时，它会提醒你。这可以与版本控制结合使用，以防止不安全的代码被添加到项目的代码库中。此外，它也可以在发布之前使用，以确保所有代码在进入生产环境之前都是安全的。

JSHint 是**JSLint**项目的社区驱动分支。JSLint 持有主观意见，不像许多人所期望的那样可配置，因此创建了 JSHint 来填补这一空白。两者都是很好的工具，我强烈建议你为你的 JS 项目采用其中之一。虽然静态分析不会捕捉一切，但它将通过自动化帮助确保代码的更高质量。

# Node.js 的注意事项

JavaScript 语言内置了异常作为错误处理的构造。当抛出异常时，需要一些代码来检测错误并适当处理。然而，如果异常未被捕获，它将触发一个致命的错误。

在浏览器中，未捕获的异常会立即停止任何执行。这不会导致网页崩溃，但有可能使应用程序处于不稳定的状态。

在 Node.js 中，未捕获的异常将终止应用程序线程。这与其他服务器端编程语言（如 PHP）非常不同，那里类似的错误只会导致单个请求失败。现在，你必须应对整个服务器和应用程序被突然停止的情况。

## 回调错误

你可以采取的第一步是确保以一种预期和可预测的方式抛出错误，以便以后能够有效地捕获。在 Node.js 中，使用回调进行异步操作的惯例是将一个`Error`对象作为第一个参数发送给回调函数。这是 Node.js 核心使用的标准惯例，并且已被社区广泛采用。

```js
var fs = require("fs");

fs.readFile("/some/file", "utf8", function (err, contents) {
    // err will be...
    // null if no error has occurred … or
    // an Error object with information about the error
});
```

上述代码只是将一个文件读取为字符串。这个操作有一个回调，接受两个参数。第一个是一个`Error`对象，但只有在这个 I/O 操作期间发生错误时才会有，比如文件不存在。通过简单地将错误对象作为函数参数传递，这在技术上并不会"抛出"异常。你的应用程序仍然应该处理这些错误，如果可能的话进行纠正。如果发生意外错误，或者无法直接纠正，你应该自己抛出错误，而不是悄悄地吞噬错误，为自己以后创建难以调试的场景。

## EventEmitter 错误处理

Node.js 核心有一个广泛使用的实用对象叫做`EventEmitter`。这是一个可以实例化或继承的对象，允许绑定和发出异步操作的事件。当`EventEmitter`对象遇到错误时，惯例是使用`Error`对象作为参数发出一个错误事件。

```js
var http = require("http");

http.get("http://nodejs.org/", function (res) {
    // res is an EventEmitter that represents the HTTP response

    res.on("data", function (chunk) {
        // this event occurs many times
        // each with a small chunk of the response data
    });

    res.on("error", function (err) {
        // this event occurs if an error occurs during transmission
    });
});
```

上述代码只是向[`nodejs.org/`](http://nodejs.org/)发出一个 HTTP 请求。结果对象是一个代表 HTTP 响应的`EventEmitter`对象。它会发出多个数据事件，当从服务器接收数据时，如果传输过程中发生错误（类似于网络断开连接），则会发出一个`error`事件。

应该注意，`EventEmitter`对象在处理`error`事件时有非常特定的行为。如果你有一个`EventEmitter`对象发出了一个`error`事件，但没有附加的监听器来响应这个事件，那么相应的`Error`对象会被抛出，并且很可能成为一个未捕获的异常。这意味着任何未处理的错误事件都会导致应用程序崩溃，所以在使用`EventEmitter`对象时，始终要绑定一个`error`事件处理程序。

## 未捕获的异常

当发生未捕获的异常时，Node.js 将打印当前堆栈跟踪，然后终止线程。所有 Node.js 应用程序都可以使用一个名为`process`的全局对象。它是一个带有特殊事件`"uncaughtException"`的`EventEmitter`对象，当未捕获的异常被带到主事件循环时会被触发。通过绑定到此事件，您可以设置自定义行为，例如发送电子邮件或写入特殊的日志文件。以下代码中可以看到这一点：

```js
process.on("uncaughtException", function (err) {
    // we're just executing the default behavior
    // but you can implement your own custom logic here instead
    console.error(err);
    console.trace();
    process.exit();
});
```

在前面的代码中，我只是简单地做了 Node.js 默认的事情。如我之前提到的，您可以实现自己的错误记录程序。如果您使用自定义处理程序，需要确保通过`process.exit()`函数自行终止进程。

虽然在发生未捕获的异常后继续应用是可能的，但不建议这样做！根据定义，未捕获的异常中断了应用程序的正常流程，使其处于不稳定和不可靠的状态。如果您简单地忽略错误并继续处理，那么您就会陷入危险的境地。Node.js 文档将此视为拔掉计算机的电源来关闭它。您可能可以做几次，但如果这种情况不断重复，系统将变得越来越不稳定和不可预测。

## 域

虽然`uncaughtException`事件允许我们处理错误，但它仍然相当粗糙。您会失去错误来源的大部分原始上下文，这使得以后调试变得更加困难。从 Node.js v0.8 开始，有一种新的错误处理机制可用，称为**域**。它们是一种将不同的 I/O 操作组合在一起的方式，以便在发生错误时，通过`uncaughtException`事件通知域对象而不是进程对象。这允许您保留错误本身的上下文，并帮助您为将来准备和纠正错误。

除了保留上下文，域还允许您在发生错误时优雅地关闭相关服务。如果您运行着一个 HTTP 服务器，并且一个用户发生了错误，简单地关闭服务器将立即中断当前正在同时使用服务器的其他用户。这对这些用户是不公平的，因此我们需要能够更优雅地关闭我们的服务器。我们应该停止服务器接受新连接，并在关闭服务器之前让当前请求得到满足。

```js
var http = require("http"),
    domain = require("domain"),
    server = http.createServer(),
    counter = 0;
server.on("request", function (req, res) {
    // this domain will cover this entire request/response cycle
    var d = domain.create();
    d.on("error", function (err) {
        // outputs all relevant context for this error
        console.error("Error:", err);

        res.writeHead(500, { "content-type": "text/plain" });
        res.end(err.message);

        // stops the server from accepting new connections/requests
        console.warn("closing server to new connections");
        server.close(function () {
            console.warn("terminating process");
            process.exit(1);
        });
    });

    // adding the req and res objects to the domain allows
    // errors they encounter to be handled by the domain
    // automatically
    d.add(req);
    d.add(res);

    d.run(function () {
        if (++counter === 4) {
            throw new Error("Unexpected Error");
        }

        res.writeHead(200, { "content-type": "text/plain" });
        res.end("Hello World\n");
    });
});

server.listen(3000);
```

前面的代码设置了一个简单的 HTTP 服务器，在发生错误之前会响应四次。对于每个请求，都会创建一个域，可以将其传递给请求处理程序的各个部分，并且可以在域的上下文中运行任何异步操作。在第 4 个请求时，我们将抛出一个`Error`对象。域有一个错误事件处理程序，它输出错误信息、堆栈跟踪，然后继续关闭服务器。首先，它发送当前请求一个错误消息，然后停止接受新请求，并完成服务其队列中的所有当前请求。完成后，进程本身被终止。

从技术上讲，我们可以使用`uncaughtException`事件来实现我在这里演示的内容。但是，如果您在应用程序中并行运行多个服务器（例如，一个 HTTP 服务器和一个 WebSocket 服务器），或者使用集群模块运行多个进程，那么该事件处理程序不一定会给您处理特定于遇到错误的服务器的上下文。事实上，您甚至无法区分`uncaughtException`事件中的不同请求，因为该上下文也会丢失。使用域，您可以更优雅地处理错误，而不会丢失上下文。

Node.js 有一个名为**cluster**的模块，它允许你利用多核环境。它通过生成多个工作进程来实现这一点，这些工作进程共享相同的服务器端口，而`cluster`模块会为你处理这些进程之间的消息传递。如果其中一个工作进程出现错误，域将允许你轻松关闭只有单个服务器和工作进程，同时让其他工作进程继续正常运行。一旦该进程完成清理并退出，你可以生成一个全新的进程来取代它，你的应用程序将因此经历零停机时间。

## 进程监视

说到这一点，事情可能会出错。你不应该忽略未捕获的异常，因为你的应用程序会变得不稳定，并且会泄漏引用和内存。处理未捕获异常的唯一安全方式是停止该进程。这意味着你的服务器将无法提供给其他用户使用。这意味着，如果一个恶意用户能够找到一种方法在你的服务器上触发未捕获的异常，他们实际上正在对其他用户发起拒绝服务攻击。

解决方案是拥有一个可以监视你的应用程序进程并在停止时自动重新启动它的进程监视器。有很多选择，包括一些特定于平台的选项。一些可用的进程监视器包括 forever、mon 和 upstart。关键是你应该实现某种进程监视，这样当出现问题时就不必手动重新启动你的应用程序。

一旦你有了一个进程监视器，一定要配置它将错误记录在某个地方，这样你就可以跟踪，以便纠正应用程序中的有害和致命错误。监视你的应用程序崩溃频率，并尽快纠正错误也是明智的。

# npm 模块（第三方代码）

正如之前提到的，Node.js 最大的特点之一是其充满活力的社区和快速增长的模块注册表。因为 Node.js 核心 API 故意保持小而集中，你可能会整合其他模块，这样你就不必从头开始编写很多东西。

就像你会努力审查你的代码以确保安全实践一样，你也应该积极参与监控你在项目中包含的 npm 模块。npm 上有许多完全开源的项目，通常可以在 GitHub 或其他类似的在线资源上找到。这使得手动查看源代码以寻找突出问题变得很容易。作为最后的手段，你可以检查 npm 在安装依赖时下载的本地包，尽管不能保证获得包的开发环境中的所有内容。

在选择要采用的模块时，寻找包含某种测试套件的模块。如果它们有运行测试，那么你就更容易确定功能是否按设计工作。其次，寻找那些包含一些静态分析的项目，这通常以 JSHint 或 JSLint 的形式出现。查看它们的样式指南或静态分析配置，了解它们遵守的规则。许多这类项目都有某种构建过程，其中可能包括运行自动化测试、静态分析和其他相关工具的方法。

Node.js 开发人员在他们的模块中注重的一个重点是使它们小巧、高度集中和可组合（即它们很容易与其他模块互操作）。因此，它们通常在代码行数和复杂性方面非常小，这使得编写安全和可测试的代码变得更加容易。这在涉及应用程序安全时对 Node.js 平台非常有利。

有一个正在崛起的项目叫做**Node Security Project**，可以在[`nodesecurity.io/`](http://nodesecurity.io/)找到。他们的目标是审计每一个 npm 模块，以查找安全漏洞。他们需要 Node.js 开发人员和安全研究人员来帮助他们，因为他们面临着一项艰巨的任务。如果你已经对保护自己的应用程序感兴趣，你可以将你用来审计你最终使用的模块的时间贡献给这个团队的注册表。这是实现你自己目标的一个很好的方式，同时也为整个 Node.js 社区做出贡献。

# 总结

在本章中，我们研究了适用于 JavaScript 语言本身的安全功能，包括如何使用静态代码分析来检查前面提到的许多问题。此外，我们还研究了 Node.js 应用程序的一些内部工作原理，以及在安全性方面与典型的浏览器开发有何不同。最后，我们简要讨论了 npm 模块生态系统和 Node Security Project，该项目旨在为安全目的审计每一个模块。在下一章中，我们将讨论应用程序的安全考虑。


# 第三章：应用考虑

现在是时候处理真实世界的应用程序了！正如之前提到的，Node.js 平台的杀手功能之一是丰富的模块和快速发展的社区。审计您使用的每个模块以确保安全仍然很重要，但使用模块很可能会成为工作流程中不可或缺的一部分。

由于其巨大的流行度，我将专门编写我的代码示例以针对**Express**应用程序。这应该涵盖今天大多数 Node.js 应用程序，但我们将涵盖的概念适用于任何平台。

# Express 简介

Express 是一个专注于保持小巧但强大的 Node.js 最小化 Web 开发框架。它是建立在另一个称为**Connect**的框架之上的，这是一个用于编写带有小插件（称为中间件）的 HTTP 服务器的平台。

Connect 和 Express 的架构允许您仅使用您需要的内容，而不是其他。这非常好地融入了安全讨论中，因为您不会整合大量不使用的功能，这为可能未经检查的安全漏洞敞开了大门。

Connect 捆绑了 20 多个常用的中间件，增加了日志记录、会话、cookie 解析、请求体解析等功能。在定义 Connect 或 Express 应用程序时，只需按照以下代码添加要使用的中间件：

```js
var connect = require("connect"),
    app = connect(); // create the application

// add a favicon for browsers
app.use(connect.favicon());

// require a simple username/password to access
app.use(connect.basicAuth("username", "password"));

// this middleware simply responds with "Hello World" to every request
// that isn't responded to by previous middleware (i.e. favicon)
app.use(function (req, res) {
    res.end("Hello World");
});

// app is a thin wrapper around Node's http.Server
// so many of the same methods are available
app.listen(3000);

console.log("Server available at http://localhost:3000/");
```

在这里，我们正在创建一个具有三个中间件的应用程序：`favicon`，`basicAuth`和我们自己的自定义中间件。前两个由 Connect 提供，它们都可以进行配置以指定其确切的行为。

### 提示

中间件总是按照附加的顺序执行，这是在确定何时以及何时附加时要记住的事情。

Connect 使用传递风格，这意味着每个中间件函数都被赋予控制权，并且在完成后必须将控制传递给继续中的下一个中间件。在我们这里的应用程序方面，每个中间件都被赋予请求和响应对象，并且对请求的生命周期具有完全控制权。

由于它们按顺序执行，让我们来看看这个应用程序的请求/响应循环是如何运作的。由于中间件具有完全控制权，它可以采取以下三种主要行动之一：

+   直接响应请求，结束继续

+   修改请求或响应对象以供继续中间件使用

+   不做任何操作，只需启动下一层中间件

幸运的是，我们在这里有所有三个的例子！首先，当一个应用程序进入这个服务器时，它会通过`favicon`中间件运行。它检查**统一资源标识符**（**URI**），如果匹配`/favicon.ico`，它会为浏览器响应一个`favicon`图标。如果 URI 不匹配，它就会简单地传递给下一个中间件。

接下来，如果请求继续，就是`basicAuth`中间件。这会提示用户使用**HTTP 基本身份验证**提供用户名和密码组合。如果用户未提供正确的凭据，服务器将以**401（未经授权）**响应并结束请求。如果用户成功提供了正确的用户名和密码，请求对象将被修改以包含用户信息，然后启动下一个中间件。

最后是我们的自定义中间件，这可能是您可能拥有的最简单的中间件。它的作用只是将**Hello World**作为响应主体发送。这意味着无论我们请求什么 URI（当然除了`/favicon.ico`），只要我们提供正确的凭据，我们就会看到**Hello World**。

现在您已经对中间件的工作原理有了基本的了解，让我们继续学习 Express 以及它对 Connect 的增强。Express 通过 Connect 系统添加了路由、HTTP 助手、视图系统、内容协商和其他功能。事实上，Express 应用程序看起来与 Connect 应用程序非常相似，如下面的代码所示：

```js
var express = require('express'),
    app = express();

app.use(express.favicon());
app.use(express.basicAuth("username", "password"));

app.get("/", function (req, res) {
    res.send('Hello World');
});

app.listen(3000);
```

Express 自动在其自己的命名空间中包含 Connect 中间件，因此您可以在不需要显式要求 Connect 的情况下使用它们。此外，它还添加了一些自己的强大功能，特别是我们在这里使用的路由功能。

Express 受到了**Ruby**的**Sinatra** Web 框架的启发。每个 HTTP 动词（`GET`，`POST`等）在应用对象上都有一个相应的函数。在这里，我们说 URL`/`的 HTTP `GET`请求将发送**Hello World**。任何其他 URL 都将得到**404（未找到）**错误，除了`/favicon.ico`，它由 favicon 中间件处理。

Express 是一种极简主义的方法，可以按照您的意愿开发应用程序。它不会将您锁定在 MVC 框架或特定的视图引擎中，并允许您包含任何 npm 模块来为您的应用程序提供动力。

# 身份验证

身份验证是确定用户在尝试通过您的应用程序执行某些操作时是否是他们声称的用户的过程。有许多方法可以实现这一点，我将在这里介绍一些更常见的方法。除了一些例外，我的示例将归结为几个可用的 npm 模块。您可以随时使用其他模块来实现相同的目标。

## HTTP 基本身份验证

第一个是**HTTP 基本身份验证**，它是可用的最简单的技术之一。它允许在 HTTP 请求中提交用户名和密码，并允许服务器在未发送预期凭据时限制访问。

在使用 Web 浏览器时，需要 HTTP 基本身份验证的页面将提示用户输入用户名和密码的对话框。用户输入信息后，浏览器通常会在一段时间内存储这些凭据，而不是在每个页面上不断提示用户。

这种方法的主要优点是非常简单实现。事实上，使用 Connect 可以在一行代码中完成。此外，这种方法完全是无状态的，不需要请求中的任何带外信息。

有一些重要的缺点，首先是它不是保密的。换句话说，基本的 HTTP 请求包括明文的用户名和密码。从技术上讲，它被编码为`base64`，但这不是一种加密方法。因此，这种技术必须与某种加密方法结合使用，例如 HTTPS。否则，请求可以被数据包嗅探器拦截，凭据就不再是秘密了。

此外，这种方法的效率不太理想。当请求页面需要 HTTP 基本身份验证时，服务器实际上必须处理第一次请求两次。在第一次尝试中，请求被拒绝，用户需要提供他们的凭据。在第二次尝试中，凭据与请求一起发送，服务器必须再次处理身份验证。根据用户名和密码的验证方式，这可能是每个请求都会产生不可接受的延迟。

此外，使用此方法时，浏览器没有实现注销的方式，除非关闭浏览器本身。凭据由浏览器存储，用户不会被提示控制存储时间的长短，或者何时应该过期。据我了解，只有 Internet Explorer 提供了这样的功能，但它需要 JavaScript 才能触发。

最后，作为开发者，你无法控制登录界面的外观；这完全取决于浏览器。虽然这可能归结为简单的美学，但可以说它比自定义解决方案更安全。如果你想要实现它，这是非常容易做到的。Connect（以及 Express）提供的捆绑中间件之一就是为了这个目的。它被称为`basicAuth`中间件，可以以多种方式进行配置。

### 提示

在使用中间件时，记住顺序非常重要！确保将身份验证中间件尽早放置在链中，这样你就可以对所有请求进行身份验证，而不是在验证用户身份之前运行不必要的处理。

首先，你可以简单地向中间件提供一个用户名和密码，为你的应用程序提供一个有效的凭据集，如下所示：

```js
app.use(express.basicAuth("admin", "123456"));
```

在这里，我们设置了我们的应用程序需要通过 HTTP 基本认证来要求用户名为`"admin"`，密码为`"123456"`。这是添加这种认证方法的最简单方法。

更高级的用法是提供一个同步回调函数，可以执行稍微复杂的身份验证方案，例如，你可以包含一个包含用户名和密码组合的 JavaScript 对象，以便执行内存查找。这在以下代码中有所体现：

```js
var users = {
    // username: "password"
    admin: "password",
    user: "123456"
};

app.use(express.basicAuth(function (user, pass) {
    return users.hasOwnProperty(user) && users[user] === pass;
}));
```

我们已经设置`basicAuth`来检查我们的`users`对象是否有相应的用户名和密码组合是有效的。如果回调函数返回`true`，则认证成功。否则，认证失败，服务器会做出相应的响应。

我们刚刚使用的两种方法都需要在应用程序源代码中硬编码凭据。最后一种方法很可能是你会使用的方法，如果你使用 HTTP 基本认证的话。这是异步回调验证。这允许你对请求进行验证，例如根据文本文件或数据库等外部来源。参考以下代码：

```js
app.use(express.basicAuth(function (user, pass, done) {
    User.authenticate({ username: user, password: pass }, done);
}));
```

在这个例子中，我们有一个类似的配置，我们使用了一个函数参数。这个函数，与之前的例子不同，有三个参数。它接收用户名和密码，但也接收一个回调函数，当它完成验证凭据时需要执行。出于简洁起见，我没有包括具体的实现细节。

重点是你可以异步执行操作，回调函数有自己的两个参数。按照 Node.js 的风格，如果认证失败，第一个参数是一个`Error`对象。第二个参数是用户的信息，将由中间件添加到`req.user`中，允许后续中间件函数访问用户的信息。

说到底，HTTP 基本认证可能对大多数应用程序来说是不够的。接下来，我们将讨论**HTTP 摘要认证**，它最初被设计为 HTTP 基本认证的继任者。

## HTTP 摘要认证

HTTP 摘要认证旨在比 HTTP 基本认证更安全，因为它不会以明文形式发送凭据。相反，它使用 MD5 单向哈希算法来加密用户的认证信息。值得注意的是，MD5 不再被认为是一种安全的算法，这是这种特定机制的一个缺点。

我只是为了完整起见才包括这个解释。它并不受欢迎，今天很少推荐使用，所以我不会再包括任何更多的细节或例子。

它以与 HTTP 基本认证相同的方式运作。首先，当需要认证时，客户端的初始请求被拒绝，服务器指示客户端需要使用 HTTP 摘要认证。客户端计算用户凭据和服务器认证领域的哈希值。根据规范，还有一些可选的功能可用于改进哈希算法并防止被恶意代理劫持。

HTTP 摘要认证的一个优点是密码不以明文形式在网络上传输。这种认证方法是在一个时代设计的，在那个时代，对所有网络事务运行 HTTPS/SSL 是非常昂贵的，无论是在金钱还是处理能力方面。现在那个时代已经过去，你应该在整个应用程序中一直使用 HTTPS。在这种情况下，HTTP 摘要认证相对于 HTTP 基本认证的优势几乎不存在。

## 介绍 Passport.js

现在，我将介绍一个非常受欢迎的用于 Connect 和 Express 应用程序的认证层项目。该项目是 Passport.js ([`passportjs.org/`](http://passportjs.org/))，实际上是一个旨在提供一致的 API 来进行认证的模块集合，使用许多不同的方法和提供者。本节的其余示例将使用 Passport.js API，并且我将在其中解释一些更常见的协议。

要在应用程序中使用 Passport.js，你需要配置以下三个部分：

1.  认证策略

1.  应用程序中间件

1.  会话（可选）

Passport.js 使用术语“策略”来指代认证请求的一种方法。这可以是用户名和密码，甚至第三方认证，比如 OpenID 或 OAuth。这是你将要配置的第一件事情，它将取决于你选择支持的认证方法。

作为一个起始示例，我们将看一下本地策略，其中你可以接受一个 HTTP `POST`请求，其中包含身份验证所需的用户名和密码，然后根据以下代码对其进行验证：

```js
// module dependencies
var passport = require("passport"),
    LocalStrategy = require("passport-local").Strategy;

// LocalStrategy means we perform the authentication ourselves
passport.use(new LocalStrategy(
    // this callback function performs the authentication check
    function (username, password, done) {
        // this is just a mock API call
        User.findOne({ username: username }, function (err, user) {
            // if a fatal error of some sort occurred, pass that along
            if (err) {
                done(err);
            // if we don't find a valid user
            } else if (!user || !user.validPassword(password)) {
                done(null, false, { message: "Incorrect username and password combination." });

            // otherwise, this was a successful authentication
            } else {
                done(null, user);
            }
        });
    }
));
```

为了简单起见，这不会连接到我们的应用程序，这只是演示了 Passport.js 中间件的 API。我们在这里配置了一个本地策略。这个策略接受一个验证回调，有三个参数：用户名、密码和一个回调函数，一旦认证完成就会被调用。（Passport.js 处理从`POST`请求中提取用户名和密码）回调函数有它自己的三个参数：一个`Error`对象（如果适用），用户的信息（如果适用，如果认证失败则为 false），以及一个选项哈希。

在这种情况下，验证回调调用某种用户 API（具体内容并不重要）来查找与提供的用户名匹配的用户，然后继续进行以下检查：

1.  如果发生致命错误（比如数据库宕机，或者网络断开连接），那么回调将发出`Error`对象作为它唯一的参数，这将被传递到 Passport.js 之外，由你的应用程序处理。

1.  如果该用户名不存在，或者密码无效，那么回调将以`null`作为第一个参数（因为没有错误发生），`false`作为第二个参数（因为认证本身失败了），以及一个具有单个`message`属性的对象，我们可以用它来向用户显示消息（这第三个参数是可选的）。

1.  如果用户通过了这些检查，那么认证就成功了。回调函数首先发出`null`，然后是用户的信息对象。

以这种方式使用回调允许 Passport.js 完全不知道底层实现。现在，让我们继续进行中间件配置步骤。Passport.js 专门设计用于在 Connect 和 Express 应用程序中使用，但它也适用于使用相同中间件风格的任何应用程序。

配置 Passport.js 和您的策略后，您需要附加至少一个中间件来在应用程序中初始化 Passport.js，如下所示的代码：

```js
var express = require("express"),
    app = express();

// application middleware
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.session({ secret: "long random string … " }));

// initialize passport
app.use(passport.initialize());
app.use(passport.session()); // optional session support

// more application middleware
app.use(app.router);
```

这是一个基本的 Express 应用程序，我们附加了两个与 Passport 相关的中间件：初始化和可选的会话支持。请记住，顺序很重要，所以您需要在像`bodyParser`和`session`这样的中间件之后初始化 Passport.js，但在应用程序路由之前。

会话支持中间件是可选的，但对于大多数应用程序来说是建议的，因为这是一个非常常见的用例，并且必须在 Express 自己的`session`中间件之后附加。最后，我们将配置会话支持本身如下所示的代码：

```js
passport.serializeUser(function (user, done) {
    // only store the user's ID in the session (to keep it light)
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    // we can retrieve the user's information based on the ID
    User.findById(id, function (err, user) {
        done(err, user);
    });
});
```

存储所有可用的用户数据，特别是随着并发用户数量的增加，可能会很昂贵。因此，Passport.js 为开发人员提供了一种配置存储到会话中的内容以及检索用户数据的能力的方式（而不是在内存中持续保留）。这并不是必需的，因为使用共享数据库存储会话信息可以缓解这个问题。

在上面的例子中，`serializeUser`函数接收一个回调，当会话被初始化时执行。在这里，我们只将用户的 ID 存储到会话中，使其尽可能轻量，同时仍然为我们提供查找他们信息所需的信息。

相应的`deserializeUser`函数在每个后续请求上被调用，并将相应的用户数据添加到请求对象中。在这种情况下，我们使用一个通用 API 来查找用户，基于他们的 ID，并使用该数据发出回调。

正如您所看到的，配置和使用 Passport.js 非常简单，并且完全符合 Connect 和 Express 的方法论。Passport.js 有超过 120 种策略可用，您可以在他们的网站上找到更多文档和示例（[`passportjs.org/`](http://passportjs.org/)）。

## OpenID

OpenID 是一种用第三方服务在网络上进行身份验证的开放标准。其目的是允许用户在网络上拥有一个单一的身份，然后可以在许多应用程序中使用，而不需要在每个单独的应用程序中注册。OpenID 没有中央管理机构，每个提供商都是独立的，用户可以选择任何他信任的提供商。今天有许多主要的提供商，包括：Google、Yahoo！、PayPal 等。

OpenID 身份验证过程的操作大致如下（这是一个简化的解释）：用户由消费者呈现一个 OpenID 登录表单。用户输入他们提供商的 URL。消费者将用户重定向到他们的提供商，提供商对用户进行身份验证，并询问用户是否应与消费者共享任何信息。然后提供商将用户重定向回消费者，消费者允许用户使用他们的服务。

要在应用程序中包含 OpenID，我们将使用`passport-openid`模块。这个模块是 Passport.js 项目的一流模块，它为您提供了一种实现通用 OpenID 身份验证过程的策略。首先，让我们看看以下所需的 Passport.js 配置：

```js
var passport = require('passport'),
    OpenIDStrategy = require('passport-openid').Strategy;

// configure the OpenID Strategy
passport.use(new OpenIDStrategy(
    {
        // the URL that the provider will redirect the user to
        returnURL: 'http://www.example.com/auth/openid/return',
        // the realm should identify your application to the User
        realm: 'http://www.example.com/'
    },
    // this verify callback has 2 arguments:
    // identifier: the ID for your user (who they claim to be)
    // done: the callback to issue after you've looked the user up
    function (id, done) {
        // this is a generic API, it could be any async operation
        User.findOrCreate({ openId: id }, function (err, user) {
            done(err, user);
        });
    }
));
```

我们已经包含了`passport`和`passport-openid`模块，并配置了 OpenID 策略。配置对象（第一个参数）有两个必需属性：

+   `returnURL`：这是 OpenID 提供商将用户重定向回您的应用程序的 URL。

+   `领域`：这是提供者将向用户显示的内容，以识别您的应用程序

第二个参数是验证回调，只接受两个参数：

+   标识符：这是用户如何在您的应用程序中标识自己

+   `完成`：这是您的应用程序根据标识符查找用户后发出的回调

现在，您需要配置 Express 路由，以处理登录请求，如下面的代码所示：

```js
// this route accepts the user"s login request, passport handles the redirect
// over to the Provider for authentication
app.post("/auth/openid", passport.authenticate("openid"));

// the Provider will redirect back to this URL (based on our earlier
// configuration of the strategy) and it will tell us whether or not
// the authentication was successful
app.get("/auth/openid/return", passport.authenticate("openid", {
    // if successful, we'll redirect the user to the hame page
    successRedirect: "/",
    // otherwise, send back to the login page
    failureRedirect: "/login"
}));
```

我们已经配置了两个路由，第一个路由通过`POST`接收用户的登录请求，Passport.js 负责将用户重定向到提供者。提供者已配置为将用户发送回`returnURL`，该 URL 对应于我们之前配置的第二个路由。

接下来，您需要在登录页面上添加一个 HTML 表单，该表单`POST`到我们之前配置的路由。如下面的代码所示：

```js
<form action="/auth/openid" method="post">
    <div>
        <label>OpenID:</label>
        <input type="text" name="openid_identifier"/><br/>
    </div>
    <div>
        <input type="submit" value="Sign In"/>
    </div>
</form>
```

唯一需要的 HTML 输入是一个具有名称`"openid_identifier"`的输入。每种策略都有自己的要求，因此在实施它们时，请务必阅读每种策略的文档。

我们在这里配置的是使用 Passport.js 的基本 OpenID 身份验证实现。现在，我们将继续配置基本的 OAuth 实现以进行身份验证。

OpenID 旨在允许您的身份由受信任的第三方进行身份验证，而 OAuth 旨在允许用户在不需要向每个单独的方提供凭据的情况下，在不同的应用程序之间共享信息。如果您的应用程序需要与另一个服务共享数据，那么您很可能会从该特定服务中使用 OAuth API。如果您只需要验证身份，OpenID 可能是该服务的首选机制。

## OAuth

OAuth 允许用户在不需要向两个服务共享其用户名和密码的情况下，从一个应用程序共享资源到另一个应用程序。此外，它还具有附加功能，可以提供有限的访问权限。此限制可以基于时间，即在经过一定时间后撤销访问权限。它还可以限制对特定数据集的访问，并可能使用户更多地控制他们决定分享什么。

这个过程通过使用几组不同的密钥（更精确地说是三组）来完成。授权过程的每个阶段都建立在前一组密钥的基础上，以构建下一步的密钥。此外，在每个步骤之间，用户在其他应用程序之间进行重定向，确保用户只向每个应用程序提供所需的最少信息。我在这里给出的解释是简化的，并没有涵盖诸如加密和签名等技术细节。

OAuth 的最佳隐喻是“代客泊车钥匙”。一些豪华汽车配有一把特殊的钥匙，其访问权限受限。我的意思是，这把特殊的钥匙只允许汽车行驶一小段距离，并且只允许代客泊车司机在拥有该钥匙的情况下访问汽车。这与 OAuth 所实现的非常相似，它允许所有者对他们拥有的资源进行临时和有限的访问，同时不放弃对该资源的完全控制。

通常涉及三方：`客户端`、`服务器`和`资源所有者`。客户端将代表资源所有者向服务器请求资源。

要使用 OAuth 规范使用的相同真实世界示例，想象一下简已经将一些个人照片上传到一个照片共享网站，并希望通过另一个在线服务将它们打印出来。

为了打印服务（客户端）能够访问存储在照片服务（服务器）中的照片，他们将需要来自 Jane（资源所有者）的批准。首先，任何客户端应用程序都需要向任何服务器应用程序注册自己，以获取第一组密钥，即客户端密钥。这些密钥被客户端和服务器都知道，并允许服务器首先验证客户端的身份。

Jane 准备好打印她的照片，所以她访问打印服务开始这个过程。她希望从照片服务中获取她的照片，而不是需要将它们上传到另一个服务，所以她告诉打印服务她希望使用照片服务的照片。

现在，打印服务通过安全的 HTTPS 请求将他们的客户端密钥发送给照片服务，以检索一组临时密钥。这些密钥用于在各种重定向中标识指定的授权请求。

一旦检索到临时密钥，打印服务将 Jane 重定向到照片服务。在那里，Jane 需要通过照片服务使用的任何方法验证她的身份。此外，照片服务可以向 Jane 提供选项，以限制授权的持续时间和范围。

一旦完成此验证，Jane 将被重定向回打印服务，并获得临时令牌。她已经授权打印服务访问照片服务，后者现在将临时密钥交换为最后一组密钥，即令牌密钥。

现在，打印服务可以使用这个“访问令牌”根据 Jane 允许的参数从照片服务请求信息，并且可以随时由 Jane 或照片服务撤销。在下面的示例中，我将坚持使用 Facebook 模块，该模块使用 OAuth v2.0，而不是使用通用的`passport-oauth`模块。我选择这条路线是为了避免需要展示当今使用的所有 OAuth 变体，因为每个实现可能都有自己的变体。此外，这里的示例将为您提供足够的 Passport API 介绍，以便您可以将这种方法应用到任何其他提供者。

首先，我们需要安装`passport-facebook`模块，然后根据以下代码配置 Passport.js 策略：

```js
var passport = require('passport'),
    FacebookStrategy = require('passport-facebook').Strategy;

// configuring the Facebook strategy (OAuth v2.0)
passport.use(new FacebookStrategy(
    {
        // developers must register their application with Facebook
        // this is where the ID/Secret are obtained
        clientID: FACEBOOK_APP_ID,
        clientSecret: FACEBOOK_APP_SECRET,

        // this is the URL that Facebook will redirect the user to
        callbackURL: "http://www.example.com/auth/facebook/callback"
    },

    // the verify callback has 4 arguments here:
    // accessToken: the token Facebook uses to verify authentication
    // refreshToken: used to extend the lifetime of the accessToken
    // profile: the user's shared information
    // done: the callback function
    function (accessToken, refreshToken, profile, done) {
        // here is where your application connects the 2 accounts
        User.findOrCreate(..., function (err, user) {
            done(err, user);
        });
    }
));
```

为了使用 Facebook 身份验证，您需要在 Facebook 开发者（[`developers.facebook.com/`](https://developers.facebook.com/)）注册并创建一个应用程序帐户。这对其他服务可能是类似的过程；您需要在他们那边进行某种注册，以便安全地与他们的用户协调。从那里，您可以获取`clientID`和`clientSecret`，并将其放入前面的配置中。您还需要指定一个`callbackURL`，它的行为非常类似于 OpenID 的`returnURL`。

接下来，您需要根据以下代码为您的 Express 应用程序配置路由：

```js
// redirects the User to Facebook for authentication
app.get("/auth/facebook", passport.authenticate("facebook"));

// Facebook will redirect back to this URL based on the strategy configuration
app.get("/auth/facebook/callback", passport.authenticate("facebook", {
    successRedirect: "/",
    failureRedirect: "/login"
}));
```

这与我们为 OpenID 设置的路由非常相似，但有一个主要区别。初始路由不是 HTML 表单`POST`；它是一个简单的 HTTP`GET`。这意味着您可以设置一个简单的 HTML 锚点，将它们指向这个路由，如下所示：

```js
<a href="/auth/facebook">Login with Facebook</a>
```

Passport 将用户发送到 Facebook 进行身份验证。当 Facebook 完成后，它将重定向回第二个路由，您可以根据需要重定向用户（就像 OpenID 实现一样）。

Passport.js 是一个很好的 API，可以抽象出所有您的身份验证需求，所以深入研究它的 API 文档（[`passportjs.org/`](http://passportjs.org/)），并利用他们提供的 120 多种策略的任意组合。

# 授权

授权是确定用户对应用程序中受限资源或操作的访问权限。身份验证专门处理用户是谁，而授权假设我们知道他们是谁，并且必须确定他们可以做什么。Express 为我们提供了一种优雅的方式，将授权直接构建到我们的路由中，这通常是授权发生的地方。

许多人最初没有意识到的是，关于 express 路由的是，您可以在定义路由时传递多个处理程序。它们中的每一个都像任何其他中间件一样，如下面的代码所示：

```js
function restrict(req, res, next) {
    if (req.user) {
        return next();
    } else {
        res.send(403); // Forbidden
    }
}

app.get("/restricted", restrict, function (req, res) {
    res.send("Hello, " + req.user);
});
```

我们的限制函数检查用户数据（假设它由我们的身份验证层设置），如果用户有效，则允许链继续进行。如果用户未登录，它将简单地响应**403（禁止）**。

关键在于，您可以使用多个路由处理程序作为处理预条件的机会，例如检查用户的身份验证状态、他们的角色或关于访问的任何其他规则。其中许多内容高度依赖于您如何构建应用程序以及您如何确定用户可以访问什么。

其中一个更受欢迎的授权方案是基于角色的授权。用户可以拥有任意数量的角色，例如："member"，"moderator"或"admin"。这些角色中的每一个都可以用来确定他们在每个操作上的访问权限。

```js
// dummy user data
var users = [
    { id: 1, name: "dominic", role: "admin" },
    { id: 2, name: "matthew", role: "member" },
    { id: 3, name: "gabriel", role: "member" }
];

// middleware for loading a user based on a :user param in the route
function loadUser(req, res, next) {
    req.userData = users[req.params.user];
    return next();
}

// middleware for restricting a route to only a specified role name
function requireRole(role) {
    // returns a function, closure allows us to access the role variable
    return function (req, res, next) {
        // check if the logged-in user's role is correct
        if (req.user.role === role) {
            return next();
        } else {
            return next(new Error("Unauthorized"));
        }
    };
}

// this route only loads a user's data (so it is loaded via middleware)
app.get("/users/:user", loadUser, function (req, res) {
    res.send(req.user.name);
});

// this route can only be called upon by an admin
app.del("/users/:user", requireRole("admin"), loadUser, function (req, res) {
    res.send("User deleted");
});
```

在上述代码中，我们有一个可用用户的列表。假设我们已经有一个身份验证层，当用户登录时加载用户配置数据，让我们看一下我们定义的两个中间件。

首先，`loadUser`是一个简单的中间件函数，用于为指定的路由加载用户（这可能是与登录用户不同的用户）。在这里，我们只有一个硬编码的列表，但它可以是我们异步进行的数据库调用。

其次，`requireRole`中间件对于不熟悉闭包或一级函数的人来说有点复杂。我们在这里做的是返回中间件函数，而不是简单地使用命名函数。通过闭包，我们可以在返回的函数内部访问`role`参数。这个中间件函数确保经过身份验证的用户具有我们要求的角色。

我们有两个路由，第一个（显示用户数据）是公开的，因此它只是通过中间件加载用户数据，不进行授权检查。第二个路由（删除用户）要求经过身份验证的用户是管理员。如果检查通过，用户的数据将被加载，并且路由将按预期进行。

有许多授权方法可供选择，有许多好的模块可供选择。基于角色的授权，正如我们在这里所展示的，易于在 Express 中实现，并且在逻辑上通常易于理解。与身份验证一样，您的实现取决于您最终如何构建应用程序。我在这里的主要目的是定义授权并向您展示一些示例，以帮助您尽可能将该机制与应用程序的其余部分区分开来。

# 安全日志记录

安全的另一个重要方面是日志记录，或者记录应用程序中的各种事件，以便对异常进行分析。这些异常可以被审查，以便检测攻击者试图绕过安全方法的地方，并且在实际入侵之前检测到这些活动，可以采取进一步的步骤来减轻这些风险。除了安全之外，日志记录还可以帮助检测程序中为用户造成问题的情况，并允许您更轻松地重现和解决这些问题。

您特定的应用程序和环境将驱动您的日志记录方法。通过方法，我指的是记录和存储日志的方式，例如在文件系统中使用平面文件，使用某种数据库，甚至使用第三方日志记录服务。虽然这些方法在项目之间可能有很大的不同，但记录的事件类型和相关信息应该在整个范围内保持相对一致。

**开放式网络应用安全项目**（**OWASP**）在其网站上有一个关于确定日志记录策略的很好的指南（访问[`www.owasp.org/index.php/Logging_Cheat_Sheet`](https://www.owasp.org/index.php/Logging_Cheat_Sheet) 获取更多信息）。他们建议为以下特定类型的事件记录日志：

+   输入验证失败（例如，协议违规，不可接受的编码，无效的参数名称和值）

+   输出验证失败（例如，数据库记录集不匹配和无效数据编码）

+   身份验证成功和失败

+   授权失败

+   会话管理失败（例如，cookie 会话标识值修改）

+   应用程序错误和系统事件（例如，语法和运行时错误，连接问题，性能问题，第三方服务错误消息，文件系统错误，文件上传病毒检测，以及配置更改）

+   应用程序和相关系统的启动和关闭，以及日志初始化（启动和停止）

+   使用更高风险功能（例如，网络连接，添加或删除用户，权限更改，将用户分配给令牌，添加或删除令牌，使用管理权限，应用管理员访问，访问付款卡持有人数据，使用数据加密密钥，密钥更改，创建和删除系统级对象，数据导入和导出，包括基于屏幕的报告，以及提交用户生成的内容，特别是文件上传）

+   法律和其他选择（例如，移动电话功能的权限，使用条款，条款和条件，个人数据使用同意，以及接收营销通讯的许可）

除了他们的建议，OWASP 还将以下事件作为可选事件呈现：

+   排序失败

+   过度使用

+   数据更改

+   欺诈和其他犯罪活动

+   可疑，不可接受或意外行为

+   配置修改

+   应用程序代码文件和/或内存更改

在确定要存储的日志数据时，OWASP 建议避免以下类型的数据：

+   应用程序源代码

+   会话标识值（如果需要跟踪特定会话事件，则考虑替换为哈希值）

+   访问令牌

+   敏感个人数据和某些形式的个人身份信息（PII）

+   身份验证密码

+   数据库连接字符串

+   加密密钥

+   银行账户或付款卡持有人数据

+   比日志系统允许存储的更高安全级别的数据

+   商业敏感信息

+   在相关司法管辖区内收集的非法信息

+   用户选择退出收集的信息，或者未同意收集的信息，例如使用不跟踪，或者同意收集已过期

在某些情况下，以下信息在调查过程中可能有用，但在包含在应用程序日志中之前应仔细审查：

+   文件路径

+   数据库连接字符串

+   内部网络名称和地址

+   非敏感个人数据（例如，个人姓名，电话号码，电子邮件地址）

由于每个应用程序和环境都不同，日志记录的方法也可以多种多样。我们将在这里看一下的 npm 模块旨在提供一个统一的 API，可以使用多种不同的方法，同时取决于上下文，允许您同时使用多种方法。

`winston`模块（[`github.com/flatiron/winston`](https://github.com/flatiron/winston)）提供了一个清晰易用的 API，用于编写日志。此外，它支持许多日志记录方法，包括添加自定义传输的功能。传输可以被描述为给定一组日志的存储或显示机制。

`winston`模块具有内置传输（也称为核心模块），用于将日志记录到控制台、将日志记录到文件以及通过 HTTP 发送日志。除了核心模块外，还有官方支持的传输模块，例如`CouchDB`、`Redis`、`MongoDB`、`Riak`和`Loggly`。最后，`winston` API 也有一个充满活力的社区，目前有超过 23 种不同的自定义传输，包括电子邮件传输和各种云服务，如亚马逊的**SimpleDB**和**Simple Notification Service**（**SNS**）。重点是，您可能需要的任何传输，可能已经有可用的模块，当然您也可以自己编写。

要开始使用`winston`，请通过 npm 安装它，然后您可以立即使用“默认记录器”，如下面的代码所示：

```js
var winston = require('winston');
winston.log("info", "Hello World");
winston.info("Hello Again");
```

这绝对是最快速开始使用`winston`的方法，但默认情况下只使用控制台传输。虽然默认记录器可以通过更多传输和配置进行扩展，但更灵活的方法是创建自己的`winston`实例，可以在应用程序中的各种上下文中使用。如下面的代码所示：

```js
var winston = require("winston");

var logger = new (winston.Logger)({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: 'somefile.log' })
    ]
});
```

在应用程序代码中，我通常将此类模块的样板代码放在它们自己的文件中。从那里，您可以导出一个预配置的对象，可以在整个应用程序中导入和使用，例如，您可以创建一个名为`lib/logger.js`的文件，看起来像下面的内容：

```js
var path = require("path"),
    winston = require("winston");

module.exports = new (winston.Logger)({
    transports: [
        // only logs errors to the console
        new (winston.transports.Console)({
            level: "error"
        }),
        // all logs will be saved to this app.log file
        new (winston.transports.File)({
            filename: path.resolve(__dirname, "../logs/app.log")
        }),
        // only errors will be saved to errors.log, and we can examine 
        // to app.log for more context and details if needed.
        new (winston.transports.File)({
            level: "error",
            filename: path.resolve(__dirname, "../logs/errors.log")
        })
    ]
});
```

然后在应用程序的其他部分中，您可以包含记录器并轻松使用它，如下所示：

```js
var logger = require("./lib/logger");
logger.log("info", "Hello World");
logger.info("Hello Again");
```

此外，`winston`还包括其他高级功能，如自定义日志级别、额外的传输配置和处理未处理的异常。此外，`winston`并不是 Node.js 中唯一可用的日志记录 API，还有其他可供您考虑的替代方案，具体取决于您自己的需求。更不用说开发自己的定制解决方案来完全控制了。

# 错误处理

任何应用程序的重要方面之一是如何处理错误。如前所述，未捕获的异常可能会导致应用程序崩溃，因此能够正确处理错误是开发周期的重要部分。

对自己应用程序中的错误做出响应是关键，因此请参阅第二章，*一般注意事项*，了解如何处理 Node.js 中的错误的一般介绍。在这里，我们将专门处理 Connect 和 Express。

首先，在路由处理程序中不要直接抛出错误。虽然 Express 足够聪明，可以直接在路由处理程序上尝试/捕获错误，但如果您正在执行某种异步操作（这在大多数情况下都是如此），则这对您没有帮助，如下面的代码所示：

```js
app.get("/throw/now", function (req, res) {
    // Express wraps the route handler invocation in try/catch, so
    // this will be handled without crashing the server
    throw new Error("I will not crash the server;
});

app.get("/throw/async", function (req, res) {
    // However, when performing some asynchronous operation
    // time) then you will lose your server if you throw
    setTimeout(function () {
        // try/catch does not work on callbacks/asynchronous code!
        throw new Error("I WILL crash the server");
    }, 100);
});
```

前面两个处理程序都会抛出异常。如前所述，Express 将在`try/catch`中执行处理程序，以处理处理程序本身中抛出的异常。但是，异步代码（例如第二个路由）无法使用典型的 try/catch，最终会变成未捕获的异常。简而言之，在处理错误时不要使用`throw`！

除了传递给处理程序的请求和响应对象之外，还有第三个参数可以像其他中间件一样使用。这通常被称为“next”回调，并且您可以像在中间件中一样使用它，传递给连续中的下一个项目。如下面的代码所示：

```js
app.get("/next", function (req, res, next) {
    // this is the correct way to handle errors, as Express will
    // delegate the error to special middleware
    return next(new Error("I'm passed to Express"));
});
```

如果您使用`Error`对象作为第一个参数执行下一个回调，那么 Connect 将接管该错误并委托给您配置的任何错误处理中间件。当您设置一个接受四个参数的中间件时，它总是被视为错误处理中间件。

```js
// 4 arguments tells Express that the middleware is for errors
// you can have more than 1 if necessary
app.use(function (err, req, res, next) {
    console.trace();
    console.error(err);

    // just responds with a 500 status code and the error message
    res.send(500, err.message);
});
```

这个特殊的错误处理中间件放在应用程序堆栈的最后，如果有必要，您可以设置多个。您可以像其他中间件一样通过 next 传递控制，例如，设置多层错误处理，其中一层可以发送电子邮件，一层可以记录到文件，最后一层可以向用户发送响应。

Connect 还有一个特殊的中间件，您可以利用它来处理错误，而无需硬编码自己的中间件。这是`errorHandler`中间件，当发生错误时，它将自动响应纯文本、JSON 或 HTML（取决于客户端的标头）。这个中间件表达如下：

```js
app.use(express.errorHandler());
```

通常，这个辅助程序只用于开发，因为您的生产应用程序可能在处理错误时需要更多的工作，您需要完全控制。

总之，始终在路由处理程序中使用“next”回调函数来传达错误，永远不要使用 throw。此外，始终通过添加一个带有四个参数的中间件函数来配置某种错误处理中间件。在开发中使用 Connect 的内置处理程序，并为生产环境设置自己的位置。

# 总结

在本章中，我们考虑了适用于应用程序的高级安全性考虑因素，如身份验证、授权和错误处理。在下一章中，我们将研究应用程序请求阶段出现的漏洞。


# 第四章：请求层考虑

一些漏洞出现在应用程序的请求阶段。如前所述，Node.js 默认情况下为您做的很少，让您完全自由地构建满足您需求的服务器。

# 限制请求大小

常常在 Node.js 应用程序中被忽略的一个主要请求处理功能是大小限制。**Express**（可选）处理请求体数据的缓冲和将请求体解析为有意义的数据结构。当请求仍在被满足时，整个请求体的内容都在内存中。如果不设置限制，恶意用户有多种方法来影响您的系统，例如耗尽内存限制，上传占用不必要磁盘空间的文件。

根据您的需求，您需要确定应用程序的合理限制。虽然您的需求可能不同，但您应该始终设置某种限制，Connect 和 Express 为此目的专门提供了一个中间件，称为 limit：

```js
app.use(express.limit("5mb"));
```

此中间件需要尽早添加到堆栈中，否则直到太迟才会被捕获。它需要一个单独的配置，即请求大小的上限。如果发送一个数字，它将被转换为字节数。您还可以发送一个更可读的字符串，例如`"5mb"`或`"1gb"`。

如果超出限制，此中间件将响应**413（请求实体太大）**错误。首先，检查请求的`Content-Length`标头，如果太大，则直接拒绝请求。当然，标头可能是伪造的，甚至不存在，因此中间件还监视传入数据，如果实际请求体大小达到限制，则触发错误。

`bodyParser`中间件用于解析特定内容类型的传入请求体。实际上，`bodyParser`中间件具体来说只是三个不同中间件的简写，即`json`，`urlencoded`和`multipart`。每个中间件对应不同的内容类型。通过限制中间件设置绝对大小是有帮助的，但并不总是足够的。一些请求体应该有不同的限制。

例如，您可能希望允许最多 100MB 的文件上传。但是，同样大小的 JSON 将在`JSON.parse()`函数运行时使您的应用程序停止，因为它是一个阻塞操作。因此，强烈建议除了多部分（因为它处理文件上传）之外，为请求体设置一个更小的限制。

因此，我建议避免使用`bodyParser`中间件，以便更明确，并允许您为每个子中间件设置不同的限制。

```js
// module dependencies
var express = require("express"),
    app = express();

// limiting the allowed size of request bodies (by content-type)
app.use(express.urlencoded({ limit: "1kb" })); // application/x-www-form-urlencoded
app.use(express.json({ limit: "1kb" }));       // application/json
app.use(express.multipart({ limit: "5mb" }));  // multipart/form-data
app.use(express.limit("2kb"));                 // everything else
```

### 提示

像我们在这里讨论的为不同内容类型设置不同限制一样，如果您对中间件的选择顺序不小心，结果可能会出乎意料。

如果首先使用限制中间件，它将导致其他中间件忽略它们自己的大小限制。确保将全局限制中间件放在最后，这样它就可以作为任何其他内容类型的通用处理，而不是由`bodyParser`中间件系列处理。

## 使用流而不是缓冲

Node.js 包含一个名为**streams**的模块，其中包含广泛用于 Node.js 平台自身核心模块的实现。流很像 Unix 管道，它们可以被读取，写入，或者根据上下文甚至两者都可以。我不会在这里详细介绍，但流是 Node.js 的一个杀手功能，您应该尽可能在应用程序和任何 npm 模块中使用它们。

如果您正在实现更多的 RESTful API，例如接受文件上传作为`PUT`请求，那么在请求处理程序中使用流。以下代码显示了处理将请求体放入文件的低效方法：

```js
var fs = require("fs");

// handle a PUT request against /file/:name
app.put("/file/:name", function (req, res, next) {
    var data = "", // data buffer
        filename = req.params.name; // the URL parameter

    req.on("data", function (chunk) {
        data += chunk; // each data event appends to the buffer
    });

    req.on("end", function () {
        // write the buffered data to a file
        fs.writeFile(filename, data, function (err) {
            if (err) return next(err); // handle a write error

            res.send("Upload Successful"); // success message
        });
    });
});
```

在这里，我们将整个请求体缓冲到内存中，然后将其写入磁盘。在小尺寸时，这不是问题，但攻击者可能同时发送许多大型请求体，通过缓冲将自己置于不必要的风险中。在 Node.js 中，使用流来处理数据是一种长期的方法（谢天谢地，更短的方法也是最好的方法！）。

以下代码是相同请求的示例，只是使用流将数据传送到目的地。

```js
var fs = require("fs");

// handle a PUT request against /file/:name
app.put("/file/:name", function (req, res, next) {
    var filename = req.params.name, // the URL parameter
        // open a writable stream for our uploaded data
        destination = fs.createWriteStream(filename);

    // if our destination could not be written to, throw an error
    destination.on("error", next);

    req.pipe(destination).on("end", function () {
        res.send("Upload Successful"); // success message
    });
});
```

我们的示例设置了一个可写流，表示上传数据的目的地。数据将被直接传送到文件中，而不是在内存中缓冲整个请求体。需要注意的是，这个示例没有正确过滤用户输入；这完全是为了专注于示例的主题，不应直接应用于生产代码。

流是在许多情境下处理数据的一种经过验证和有效的模式，并充分利用了 Node.js 的事件驱动模型。

当处理许多同时用户，特别是在出现意想不到的交通高峰时，准备好应对灾难情景是很重要的，其中负载变得过重，超出服务器的处理能力。这也适用于缓解拒绝服务（DoS）攻击，这些攻击试图用比服务器可能处理的更多请求来淹没服务器，使其完全崩溃（或者只是减慢到爬行速度）。

# 监视事件循环的响应性

构建一个在重载下不会崩溃的服务器是可行的。一个有用的模式是监视事件循环的响应性，并立即拒绝一些请求，如果服务器负载过重，无法快速响应。有一个模块叫做 node-toobusy（https://github.com/lloyd/node-toobusy）就是这样做的。

一旦初始化，toobusy 将轮询事件循环，并监视延迟或事件循环中超过预期时间的请求。在应用程序中，您设置一个中间件层，简单地查询监视器，以确定是否将请求添加到服务器的当前处理队列。如果服务器太忙，它将以 503（服务器当前不可用）的方式进行响应，而不是承担超出其满足能力的负载。这种模式允许您继续尽可能多地提供服务请求，而不是使服务器崩溃，如下面的代码所示。

```js
var toobusy = require("toobusy"),
    express = require("express"),
    app = express();

// middleware which blocks requests when we're too busy
app.use(function(req, res, next) {
    if (toobusy()) {
        res.send(503, "I'm busy right now, sorry.");
    } else {
        next();
    }
});

app.get("/", function(req, res) {
    // each request blocks the event loop
    var start = (new Date()).getTime(), now;
    while (((new Date()).getTime() - start) <= 5000); // run for 5 seconds
    res.send("Hello World");
});

var server = app.listen(3000);
process.on("SIGINT", function() {
    server.close();
    // calling .shutdown allows your process to exit normally
    toobusy.shutdown();
    process.exit();
});
```

前面的示例是在 node toobusy 的 github 页面上找到的。它设置了一个使用 toobusy 模块的简单服务器中间件。它还设置了一个阻塞事件循环的单个路由，运行了五秒钟。如果出现一些同时请求足够长时间阻塞事件循环的情况，服务器将开始以 503（服务器当前不可用）错误进行响应，而不是承担超出其承受范围的负载。最后，这还包括了进程的优雅关闭。

这个示例还演示了关于 Node.js 中事件循环的一个非常重要的观点，值得重复。您的代码与事件循环调度器之间的约定是，所有代码应该快速执行，以避免阻塞事件循环的其他代码。这意味着要避免在应用程序代码中进行 CPU 密集型计算，不像前面的示例，在其 while 循环迭代期间阻塞 CPU。

Node.js 在应用程序主要是 I/O 绑定时效果最佳，因此应避免 CPU 密集型操作，比如复杂的计算或非常大的数据集迭代。如果系统需要这样的操作，考虑将阻塞部分作为单独的进程进行分离，以避免占用应用程序的事件循环。

有几种方法可以实现这一点，比如使用 HTML5 Web Worker API for node ([`github.com/pgriess/node-webworker`](https://github.com/pgriess/node-webworker))。此外，一个更基本的方法是利用 Node 的`child_process`模块与**进程间通信**（**IPC**）结合使用。关于 IPC 的具体内容可能严重依赖于您的平台和架构，这超出了本讨论的范围。

# 跨站点请求伪造

**跨站点请求伪造**（**CSRF**）是一种攻击向量，它利用了应用程序对特定用户浏览器的信任。在用户不知情的情况下，应用程序代表用户发出请求，从而使应用程序在假定受信任的用户发出请求的情况下执行某些操作，尽管实际上并非如此。

有许多方法可以实现这一点。一个例子是，一个 HTML 图像标签（例如，`<img>`）以某种方式被注入到页面中，无论是合法的还是非法的，比如通过 XSS，这是我们将在下一章中讨论的一个漏洞。浏览器隐式地向`src`属性中指定的 URL 发送请求，并在 HTTP 请求的一部分中发送任何 cookie。许多跟踪用户身份的应用程序通过包含某种会话标识符的 cookie 来实现，这样对服务器来说，就好像用户发出了请求。

预防措施非常简单；最常见的方法是要求在修改状态的每个请求中包含一个生成的用户特定令牌。事实上，Connect 已经包含了`csrf`中间件，就是为了这个目的。

它通过向当前用户的会话添加一个生成的令牌来工作，该令牌可以作为一个隐藏的输入字段或任何具有副作用的链接中的查询字符串值包含在 HTML 表单中。当处理后续请求时，中间件会检查用户会话中的值是否与请求提交的值匹配，如果不匹配，则会失败并返回**403（禁止）**。

```js
var express = require("express"),
    app = express();

app.use(express.cookieParser()); // required for session support
app.use(express.bodyParser());   // required by csrf
app.use(express.session({ secret: "secret goes here" })); // required by csrf
app.use(express.csrf());

// landing page, just links to the 2 different sample forms
app.get("/", function (req, res) {
    res.send('<a href="/valid">Valid</a> <a href="/invalid">Invalid</a>')
});

// valid form, includes the required _csrf token in the HTML Form (hidden input)
app.get("/valid", function (req, res) {
    var output = "";
    output += '<form method="post" action="/">'
    output += '<input type="hidden" name="_csrf" value="' + req.csrfToken() + '">';
    output += '<input type="submit">';
    output += '</form>';
    res.send(output);
});
// invalid form, does not have the required token
// throws a "Forbidden" error when submitted
app.get("/invalid", function (req, res) {
    var output = "";
    output += '<form method="post" action="/">'
    output += '<input type="submit">';
    output += '</form>';
    res.send(output);
});

// POST target, redirects back to home if successful
app.post("/", function (req, res) {
    res.redirect("/");
});

app.listen(2500);
```

这个示例应用程序有一些定义好的中间件，即`bodyParser`，`cookieParser`和`session`。这些都是`csrf`所需的，这就是为什么它们在顺序中排在第一位。此外，还有一些路由，如下所示：

+   主页，只提供两个示例表单的链接

+   表单操作/目标，只需在成功提交时将用户重定向到主页

+   有效的表单，包括令牌作为隐藏输入，并成功提交

+   无效的表单，不包括令牌，因此在提交时失败（带有(**403 Forbidden)** HTTP 响应）

这种方法可以防止攻击者成功发出虚假请求，因为所需的令牌对于每个表单提交都是不同的。

# 输入验证

在保护许多攻击向量，比如我们将在下一章中处理的 XSS 时，重要的是在接收用户输入时对其进行过滤和清理。这发生在 Web 应用程序的请求阶段，所以我们将在这里进行讨论。一个基本的经验法则是始终验证输入并转义输出。

用于验证用户输入的流行库是 node-validator ([`github.com/chriso/node-validator`](https://github.com/chriso/node-validator))。这个库绝不是唯一的选择，但它是我们在示例中将要使用的选择。

输入验证有几个目标，首先是验证传入的用户输入是否符合我们应用程序及其工作流程的标准；例如，您可能希望确保用户提交有效的电子邮件地址。我指的不是发送电子邮件进行确认以测试电子邮件地址是否真实，而是确保他们一开始就不输入错误的值。另一个例子是确保数字匹配特定范围，比如大于零。

其次，输入过滤旨在防止不良数据进入系统，可能会损害另一个子系统；例如，如果您接受某个数字输入，然后将其传递给另一个子系统进行一些额外的处理，比如报告或其他远程 API。如果您的用户故意或无意地提交其他意外的值，比如符号或字母字符，可能会在未来的操作中造成问题。在很大程度上，计算机是垃圾进，垃圾出，因此我们需要确保我们对任何用户输入都要小心谨慎。

第三，正如之前简要提到的，输入过滤是一种有用的（尽管不完整的）预防措施，可以防止**跨站脚本攻击**（**XSS**）等攻击。在 HTML、CSS 和 JavaScript 中的 XSS 攻击存在访问控制的严重问题，这意味着任何脚本都具有与其他脚本相同的访问权限。这意味着如果攻击者能够找到一种方式将进一步的代码注入到您的页面中，他们将拥有很大程度的控制权，这对您的用户可能是有害的。输入过滤可以通过删除可能巧妙嵌入其他用户输入的恶意代码来帮助。

除了基本的 node-validator 库之外，还有一个中间件插件（express-validator：[`github.com/ctavan/express-validator`](https://github.com/ctavan/express-validator)），专门为 Express.js 制作，我们将在示例中使用它。

我们的第一个示例将是一个接受各种输入的表单，只是为了尽可能地进行演示。考虑以下 HTML 表单：

```js
<form method="post">
    <div>
        <label>Name</label>
        <input type="text" name="name">
    </div>
    <div>
        <label>Email</label>
        <input type="email" name="email">
    </div>
    <div>
        <label>Website</label>
        <input type="url" name="website">
    </div>
    <div>
        <label>Age</label>
        <input type="number" name="age">
    </div>
    <div>
        <label>Gender</label>
        <select name="gender">
            <option>-- choose --</option>
            <option value="M">Male</option>
            <option value="F">Female</option>
        </select>
    </div>

    <button type="submit">Validate</button>
</form>
```

这个示例代码设置了一个带有五个字段的 HTML 表单：`name`，`e-mail`，`website`，`age`和`gender`。用户可以在提供的输入框中输入值，并`POST`到相同的 URL。在处理`POST`请求时，我们将验证数据并给出某种响应。下一个代码示例将是我们的应用程序代码：

```js
// module dependencies
var express = require("express"),
    app = module.exports = express();

app.use(express.bodyParser());           // required by csrf
app.use(require("express-validator")()); // the validation middleware

// an HTML form to be validated
app.get("/", function (req, res) {
    res.sendfile(__dirname + "/views/validate-input.html");
});

/**
 * Validates the input, will either:
 *  - sends a 403 Forbidden response in the event of validation errors
 *  - send a 200 OK response if the data validates successfully
 */
app.post("/", function (req, res, next) {
    // validation
    req.checkBody("name").notEmpty().is(/\w+/);
    req.checkBody("email").notEmpty().isEmail();
    req.checkBody("website").isUrl();
    req.checkBody("age").isInt().min(0).max(100);
    req.checkBody("gender").isIn([ "M", "F" ]);
    // filtering
    req.sanitize("name").trim();
    req.sanitize("email").trim();
    req.sanitize("age").toInt();

    var errors = req.validationErrors(true);

    if (errors) {
        res.json(403, {
            message: "There were validation errors",
            errors: errors
        });
    } else {
        res.json({
            name: req.param("name"),
            email: req.param("email"),
            website: req.param("website"),
            age: req.param("age"),
            gender: req.param("gender")
        });
    }
});
```

这个示例设置了一个基本的 Web 服务器，只有两个路由，一个是`GET /`，它只是发送之前显示的 HTML 表单作为响应。第二个路由是`POST /`，它接受从上述表单提交的数据，并首先根据以下规则进行验证：

| 字段 | 规则 |
| --- | --- |
| `name` | 该字段不能为空。它必须匹配一个正则表达式（这意味着它只能是字母、数字、空格和一些特定符号）。 |
| `e-mail` | 这必须是一个有效的电子邮件地址。 |
| `website` | 这必须是一个有效的 URL。 |
| `age` | 这必须是一个数字。它必须大于或等于 0。它必须小于或等于 100。 |
| `gender` | 这必须是"M"或"F"。 |

除了验证输入，它还根据以下规则执行一些过滤和转换以进行输出：

| 字段 | 规则 |
| --- | --- |
| `name` | 去除前导和尾随空格。 |
| `e-mail` | 去除前导和尾随空格。 |
| `age` | 转换为整数。 |

根据验证的结果，它要么以**403（禁止）**的状态响应，并附带验证错误列表，要么以**200（OK）**的状态响应，并附带过滤后的输入。

这应该表明，向应用程序添加输入验证和过滤非常简单，并且收益是非常值得的。您可以确保数据与各种工作流程的预期格式匹配，并有助于预防性地防范一些攻击向量。

# 摘要

在本章中，我们特别研究了请求漏洞，并提供了一些避免和处理这些漏洞的方法。在下一章中，我们将研究应用程序的响应阶段以及出现的漏洞。


# 第五章：响应层漏洞

您与用户请求的最后交互当然是响应。这里的讨论将集中在应用程序代码的这一部分的漏洞和最佳实践。这将包括**跨站脚本攻击**（**XSS**），一些**拒绝服务**（**DoS**）攻击的向量，甚至各种浏览器用于实施特定安全策略的 HTTP 标头。

# 跨站脚本攻击（XSS）

跨站脚本攻击（XSS）是处理 Web 应用程序时的一个更受欢迎的话题，因为在许多方面，这是 HTML/CSS/JavaScript 的默认行为。具体来说，XSS 是一种攻击向量，用于向 Web 页面注入不受信任且可能恶意的代码。通常，这被视为向您的页面注入 JavaScript 代码的机会，该代码现在可以访问特定 Web 页面中客户端几乎可以访问的任何内容。

默认情况下，JavaScript 在浏览器中以全局范围执行，包括由不受信任的来源注入的代码。这与您自己的受信任代码的行为相同，使其成为具有许多可能性的危险向量。恶意脚本可以找到用户的会话 ID（通常在 cookie 中），并使用 AJAX 将该信息发送给可以劫持用户会话的人。

注入通常来自未经过滤或消毒的用户输入，然后输出到浏览器。考虑以下示例代码：

```js
var express = require("express"),
    app = express();

app.get("/", function (req, res) {
    var output = "";
    output += '<form action="/test">';
    output += '<input name="name" placeholder="enter a name">';
    output += '</form>';

    res.send(output);
});

app.get("/test", function (req, res) {
    res.send("Hello, " + req.query.name);
});

app.listen(3000);
```

这个脚本创建了一个服务器，简单地发送一个 HTML 表单，该表单通过`GET`提交到另一个页面。第二个路由简单地将用户输入的值输出到浏览器。

如果用户输入他们的名字（比如 Dominic），一切都很好，用户在下一页上看到**"Hello, Dominic"**。但是，如果用户输入了其他内容，比如原始 HTML 呢？在这种情况下，它只是将 HTML 与我们自己的 HTML 一起输出，浏览器无法区分。

如果您在该文本字段中输入`<script>alert('hello!');</script>`，那么当您打开下一个页面时，您将看到**"Hello,"**，并且浏览器将触发一个带有**"hello!"**的警报框。这只是一个无害的例子，但这种漏洞有巨大的潜在危害。这些攻击是通过所谓的不受信任的数据完成的，这些数据可能是原始用户输入，存储在数据库中的信息，或者通过远程数据源访问的信息。然后，您的应用程序使用这些不受信任的数据来构造某种命令，然后执行该命令。当命令被操纵以执行开发人员原始意图之外的某些操作时，危险就会出现。

这种类型攻击的原型示例是 SQL 注入，其中不受信任的数据用于更改 SQL 命令。考虑以下代码：

```js
var sql = "SELECT * FROM users WHERE name = '" + username + "'";
```

假设用户名变量来自用户输入，重点是它是我们定义的不受信任的数据。如果用户输入了一些无害的东西，比如`'Dominic'`，那么一切都很好，生成的 SQL 看起来像以下代码：

```js
SELECT * FROM users WHERE name = 'Dominic'
```

如果有人输入了一些不那么无害的东西，比如：`'' OR 1=1`，那么生成的 SQL 就会变成以下样子：

```js
SELECT * FROM users WHERE name = '' OR 1=1
```

这完全改变了查询的含义，而不是限制为具有匹配名称的一个用户，现在返回了每一行。这可能会更加灾难性，考虑值：`''; DROP TABLE users;`，它将生成以下 SQL：

```js
SELECT * FROM users WHERE name = ''; DROP TABLE users;
```

没有任何额外的访问权限，用户已经导致了我们应用程序的严重数据损失，可能会使所有用户无法使用整个应用程序。

事实证明，XSS 是另一种类型的注入攻击，Web 浏览器和它们执行的 HTML、CSS 和 JavaScript 都针对这些类型的攻击进行了优化。我们需要了解每种语言中的许多不同上下文。考虑以下模板：

```js
<h2>User: <%= username %></h2>
```

使用我们不信任的数据，我们可以很容易地通过向该值注入额外的 HTML 来引起麻烦，比如`<script>alert('xss');</script>`，这将生成以下 HTML 代码：

```js
<h2>User: <script>alert('xss');</script></h2>
```

解决方法是在这个上下文中对任何添加到页面的不受信任的数据使用 HTML 转义。这种技术将 HTML 中重要的字符，比如尖括号和引号，转换为它们对应的 HTML 实体；防止它们改变嵌入其中的 HTML 结构。以下表格是这种转换的一个例子：

| 字符 | 实体 |
| --- | --- |
| 小于号 (`<`) | `&lt;` |
| 大于号 (`>`) | `&gt;` |
| 双引号 (`"`) | `&quot;` |
| 单引号 (`'`) | `'`（`&apos;`不是有效的 HTML，应该避免使用） |
| 和号 (`&`) | `&amp;` |
| 斜杠 (`/`) | `/` |

这种转义方法使得攻击者更难改变你的 HTML 结构，这是保护你的网页非常重要的技术。然而，不同的上下文将需要更多的转义技术，我们将很快讨论。

### 提示

许多流行的模板库默认包括自动的 HTML 转义，但有些则不包括。这对于选择模板框架或库对你来说应该是一个重要因素。

HTML 属性可以被注入其他 HTML，用于创建一个新的上下文，比如关闭属性并开始一个新的属性。更进一步，这个注入的 HTML 可以用来关闭 HTML 标签，并在另一个上下文中注入更多的 HTML。考虑以下模板：

```js
<img height=<%= height %> src="img/...">
```

考虑以下用于高度的注入值：`100 onload="javascript:alert('XSS');"`, 这将生成以下 HTML：

```js
<img height=100 onload="javascript:alert('XSS');" src="img/...">
```

结果是注入的 JavaScript 代码。在这种特定的上下文中，像我们之前使用的 HTML 编码是不够的，因为前面仍然是一个完全有效的 HTML。除了我们之前提到的 HTML 转义，你应该要求在所有 HTML 属性周围加上引号，特别是当涉及到不受信任的数据时。为了涵盖所有情况，甚至是未引用的属性，你可以将所有 ASCII 值低于 256 编码为它们的 HTML 实体格式或可用的命名实体，比如`&quot;`。

涉及 URL 的 HTML 属性，比如`href`和`src`，是另一个需要自己编码的上下文。考虑以下模板：

```js
<a href="<%= url %>">Home Page</a>
```

如果用户输入以下数据：`javascript:alert('XSS');`，那么将生成以下 HTML：

```js
<a href="javascript:alert('XSS');">Home Page</a>
```

在这里不适用 HTML 编码，因为前面是有效的 HTML 标记。相反，应该检查一个完全合格的 URL 是否包含意外的协议。在这里，我们使用了`javascript:`，这会让浏览器执行任意代码，就像`eval()`函数一样。最后，输出应该通过内置的 JavaScript 函数`encodeURI()`进行转义，该函数转义 URL 中无效的字符。

我将在这里展示的最后一个例子是在先前提到的属性中部分 URL。使用以下模板：

```js
<a href="/article?page=<%= nextPage %>">Next</a>
```

`nextPage`变量被用作 URL 的一部分，而不是 URL 本身。我们之前提到的`encodeURI()`函数有一个伴侣叫做`encodeURIComponent()`，它转义更多的字符，因为它是用来编码单个查询字符串参数的。

另一个常见的反模式是直接将 JSON 数据注入页面，以在渲染页面的同时在服务器和客户端之间共享数据。考虑以下模板：

```js
<script>
var clientData = <%= JSON.stringify(serverData); %>;
</script>
```

这种特定的技术，虽然方便，也可能导致 XSS 攻击。假设`serverData`对象有一个名为`username`的属性，反映了当前用户的名字。还假设这个值可以由用户设置，而没有任何过滤，直接在用户输入和页面显示之间（当然不应该发生）。

如果用户将他的名字改为`</script><script>alert('XSS')</script>`，那么输出的 HTML 将如下所示：

```js
<script>
var clientData = {"username":"</script><script>alert('XSS');</script>"};
</script>
```

根据 HTML 规范，`</`字符（即使在 JavaScript 字符串中，就像我们这里）将被解释为一个闭合标签，攻击者刚刚创建了一个全新的脚本标签，就像任何其他脚本标签一样，它对页面有完全控制权。

与其直接尝试转义 JSON 数据，减轻这个问题的最佳方法是使用另一种方法来注入你的 JSON 数据：

```js
<script id="serverData" type="application/json">
<%= html_escape(JSON.stringify(data)) %>
</script>

<script>
var dataElement = document.getElementById("serverData");
var dataText = dataElement.textContent || dataElement.innerText; // unescapes the content of the script
var data = JSON.parse(dataText);
 </script>
```

这种方法使用了一个带有预定义 ID 的脚本标签，我们可以用它来检索它。当浏览器遇到它不理解的脚本类型时，它将简单地不执行它，同时将其隐藏在用户面前。这个脚本标签的内容将是我们的 JSON 的 HTML 转义版本，这样可以确保我们没有上下文边界的交叉。

接下来，我们使用另一个脚本（最好是外部文件，但绝不是必需的），其中包含查找我们定义的脚本元素并检索其文本内容的代码。通过使用`textContent/innerText`属性而不是`innerHTML`，我们得到了浏览器为我们执行的额外转义，以防万一。最后，我们通过`JSON.parse`运行 JSON 数据来实际执行 JSON 解码。

虽然这种方法需要更多的宣传，而且比第一个例子要慢一些，但它会更安全，这是一个很好的权衡。

这些例子绝不是一个详尽的列表，但它们应该说明 HTML、CSS 和 JavaScript 各自都有上下文，允许各种类型的代码注入。永远不要相信用户输入，并确保根据上下文使用适当的转义方法。

**开放式 Web 应用安全项目**（**OWASP**）是一个维护维基（[`www.owasp.org/`](http://www.owasp.org/)）的基金会，专门针对所有 Web 应用程序的安全考虑。他们有关于许多攻击向量的文章，包括一个更全面的检查表，用于防止许多更多种类的 XSS 攻击。

# 拒绝服务

**拒绝服务**（**DoS**）攻击可以采用各种形式，但主要目的是阻止用户访问你的应用程序。一种方法是向服务器发送大量请求，占用服务器的资源，阻止合法请求得到满足。

请求洪水通常针对多线程服务器，比如**Apache**。这是因为为每个请求生成一个新线程的过程为同时请求的数量提供了一个容易达到的上限。对于 Node.js 平台的事件循环，这种特定类型的攻击通常不那么有效，尽管这并不意味着它是不可能的。

如果不正确使用事件循环，事件循环仍然可能会暴露应用程序，我无法强调理解它的重要性有多大，同时编写任何 Node.js 应用程序。你的应用程序代码与事件循环的约定是尽可能快地运行。一次只有一个应用程序的部分在运行，所以 CPU 密集型也可能占用资源。这适用于所有情况，但我在这一章中提到它是为了特别解决你的响应处理程序。

如前所述，尽可能使用流，特别是在处理网络请求或文件系统时。处理大块数据可能是耗时的，取决于你如何处理这些数据，使用流可以将这些大操作分解成许多小块，从而在过程中满足其他请求。

# 与安全相关的 HTTP 头

有一些可用的 HTTP 标头可以帮助我们的 Web 应用程序增加一些安全性。我们将看一下一个名为**头盔**的模块，它被编写为一个 Connect/Express 中间件的集合，根据您的配置添加这些标头。我们将检查头盔包括的每个中间件函数，以及它们的效果的简要解释。

## 内容安全策略

首先，头盔支持为 HTML 和 Web 应用程序的一种新的安全机制设置标头，称为**内容安全策略**（**CSP**）。XSS 攻击通过使用其他方法欺骗浏览器传递有害内容来规避**同源策略**（**SOP**）。

对于支持此功能的浏览器，您可以将资源（例如图像、框架或字体）限制为通过白名单域加载。这通过希望阻止访问不受信任的域加载恶意内容，从而限制了 XSS 攻击的影响。

CSP 通过一个或多个`Content-Security-Policy` HTTP 标头传达给浏览器，例如：

```js
Content-Security-Policy: script-src 'self'
```

此标头将指示浏览器要求所有脚本仅从当前域加载。浏览器检测到来自任何其他域的脚本将被直接阻止。

CSP 标头是由分号分隔的一系列指令构成的。实现多个 CSP 限制的标头示例如下：

```js
Content-Security-Policy: script-src 'self'; frame-src 'none'; object-src 'none'
```

此标头指示浏览器仅限制脚本到当前域（与我们之前的示例相同），并且完全禁止使用框架（包括 iframes）和对象。

每个指令都被命名为`*-src`，后面跟着一个以空格分隔的预定义关键字列表（必须用引号括起来）或域 URL。

可用的关键字包括以下内容：

+   `'self'`：这将脚本限制为当前域

+   `'none'`：这限制了所有域（根本不能加载）

+   `'unsafe-inline'`：这允许内联代码（强烈建议避免，稍后讨论）

+   `'unsafe-eval'`：这允许文本到 JavaScript 的机制，如`eval()`（同样强烈不建议）

可用的指令包括以下内容：

+   `connect-src`：这限制了可以通过 XHR 和 WebSockets 连接的域

+   `font-src`：这限制了可以用于下载字体文件的域

+   `frame-src`：这限制了可以加载框架（包括内联框架）的域

+   `img-src`：这限制了可以从中加载图像的域

+   `media-sr`：这限制了视频和音频的来源

+   `object-src`：这允许控制对象的来源（例如 Flash）

+   `script-src`：这限制了可以从中加载脚本的域

+   `style-src`：这限制了可以从中加载样式表的域

+   `default-src`：这充当所有指令的缩写

省略指令会使其策略完全开放（这是默认行为），除非您指定`default-src`指令。

头盔可以根据您传递给中间件的配置为每个支持的用户代理（例如浏览器）构造标头。默认情况下，它将提供以下 CSP 标头：

```js
Content-Security-Policy: default-src 'self'
```

这是一个非常严格的策略，因为它只允许从当前域加载外部资源，而不允许从其他任何地方加载。在大多数情况下，这太过严格，特别是如果您要使用 CDN 或允许外部服务与您自己通信。

您可以通过中间件定义函数来配置头盔，通过添加一个名为`defaultPolicy`的属性，其中包含您的指令作为对象哈希，例如：

```js
app.use(helmet.csp.policy({
    defaultPolicy: {
        "script-src": [ "'self'" ],
        "img-src": [ "'self'", "http://example.com/" ]
    }
}));
```

这将指示头盔发送以下标头：

```js
Content-Security-Policy: script-src 'self'; img-src 'self' http://example.com/
```

这将限制脚本和图像仅限于当前域以及域[`example.com/`](http://example.com/)。

CSP 还包括了一个报告功能，你可以用来审计自己的应用程序并快速检测漏洞。有一个专门用于此目的的`report-uri`指令，告诉浏览器发送违规报告的 URI。参考以下示例代码：

```js
Content-Security-Policy: default-src 'self'; ...; report-uri /my_csp_report_parser;
```

当浏览器发送报告时，它是一个具有以下结构的 JSON 文档：

```js
{
  "csp-report": {
    "document-uri": "http://example.org/page.html",
    "referrer": "http://evil.example.com/",
    "blocked-uri": "http://evil.example.com/evil.js",
    "violated-directive": "script-src 'self' https://apis.google.com",
    "original-policy": "script-src 'self' https://apis.google.com; report-uri http://example.org/my_amazing_csp_report_parser"
  }
}
```

这份报告包括了大部分你需要追踪违规行为的信息，即：

+   `document-uri`：发生违规的页面

+   `blocked-uri`：违规资源

+   `violated-directive`：违反的具体指令

+   `original-policy`：页面的策略（CSP 头的内容）

当刚开始使用 CSP 时，可能不明智立即设置策略并开始阻止。在详细说明应用程序策略的过程中，你可以设置 CSP 以尊重报告模式。

这允许你设置完整的策略，而不是立即阻止用户，你可以简单地接收详细违规报告。这为你提供了在实施之前微调策略的方法。

要启用报告模式，你只需更改 HTTP 头部名称。不再使用我们一直在使用的，而是简单地使用`Content-Security-Policy-Report-Only`，其他一切保持不变：

```js
Content-Security-Policy-Report-Only: default-src 'self'; ...; report-uri /my_csp_report_parser;
```

在 helmet 中，通过在配置对象中包含`reportOnly`参数来启用报告模式：

```js
express.use(helmet.csp.policy({
    reportOnly: true,
    defaultPolicy: {
        "script-src": [ "'self'" ],
        "img-src": [ "'self'", "http://example.com/" ]
    }
}));
```

这设置了我们之前使用的相同策略，只是增加了报告模式。

CSP 是一种出色的安全机制，你应该立即开始使用，尽管浏览器支持并不完全。截至本文撰写时，它是**W3C 候选推荐**，预计浏览器将以快速的速度实现这一功能。

## HTTP 严格传输安全（HSTS）

**HTTP 严格传输安全**（HSTS）是一种机制，向用户代理（例如，Web 浏览器）通信，特定应用程序应仅通过 HTTPS 访问，因为这是加密通信。如果你的应用程序理想情况下只存在于安全连接上，这允许你正式向浏览器声明。

这个头部只有两个参数，`max-age`指令告诉浏览器要尊重配置的时间（以秒为单位），以及`includeSubDomains`指令以相同方式处理当前域的子域。与 CSP 一样，这是通过 HTTP 头部通信的：

```js
Strict-Transport-Security: max-age=15768000
```

这告诉浏览器，大约六个月内，当前域从现在开始应该通过 HTTPS 访问（即使用户通过 HTTP 访问）。这是由 helmet 设置的默认配置，也是最简单的实现方式：

```js
app.use(helmet.hsts());
```

这使用先前说明的配置设置了 HSTS 的中间件，中间件定义函数还接受两个可选参数。首先，`max-age`指令可以设置为一个数字（应以秒表示）。其次，`includeSubDomains`指令可以设置为一个简单的布尔值：

```js
app.use(helmet.hsts(1234567, true));
```

这将设置以下头部：

```js
Strict-Transport-Security: max-age=1234567; includeSubdomains
```

浏览器支持目前并不像 CSP 那样完整，但预计会朝着这个方向前进。与此同时，将其添加到应用程序的安全详细信息中是值得的。

## X-Frame-Options

这个头部控制特定页面是否允许加载到`<frame>`或`<iframe>`元素中。这主要用于防止恶意用户劫持（或“点击劫持”）你的用户，从而欺骗他们执行他们本来没有打算执行的操作。

这是通过另一个 HTTP 头部通信给浏览器的，因此当浏览器加载一个框架/iframe 的 URL 时，它将检查这个头部以确定采取的行动。头部看起来像下面这样：

```js
X-Frame-Options: DENY
```

在这里，我们使用值`DENY`，这是通过头盔配置时的默认值。其他可用选项包括`sameorigin`，它只允许在当前域上加载域。最后一个选项是`allow-from`选项，允许您指定可以在框架中呈现当前页面的 URI 白名单。

在大多数情况下，默认设置应该工作得很好，您可以通过头盔这样设置：

```js
app.use(helmet.xframe());
```

这将添加我们之前看到的标头。要使用`sameorigin`选项进行配置，请使用以下配置：

```js
helmet.xframe('sameorigin');
```

最后，这将设置`allow-from`变体，还为您提供了设置允许的 URI 的第二个参数：

```js
helmet.xframe('allow-from', 'http://example.com');
```

对于这种安全机制，浏览器支持非常好，因此可以立即实施。`allow-from`标头是一个警告，不是均匀支持的，因此在使用之前，请确保根据您的要求研究具体情况。

## X-XSS-Protection

这个下一个标头是特定于 Internet Explorer 的，它启用了 XSS 过滤器。而不是我自己解释，这是来自**Microsoft Developer Network**（**MSDN**）的解释。

### 注意

XSS 过滤器作为 Internet Explorer 8 组件运行，可以查看浏览器中流动的所有请求/响应。当过滤器在跨站点请求中发现可能的 XSS 时，它会在服务器的响应中识别并中和攻击。有关更多信息，请访问：[`msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx)

这个功能可能默认情况下已启用，但是如果用户自己禁用了它或在某些选择区域禁用了它，可以使用类似以下的简单标头来启用它：

```js
X-XSS-Protection: 1; mode=block
```

通过将标头设置为 0，强制禁用 XSS 过滤器，但该配置不通过头盔公开。实际上，它根本没有配置，因此其使用就像这样简单：

```js
app.use(helmet.iexss());
```

## X-Content-Type-Options

这是另一个标头，它阻止某些浏览器的特定行为（目前只有 Internet Explorer 和 Google Chrome 支持此功能）。在这种情况下，即使资源本身设置了有效的`Content-Type`标头，浏览器也会尝试“嗅探”（例如，猜测）返回资源的 MIME 类型。

这可能会导致浏览器被欺骗以执行或呈现开发人员意外的方式的文件，这取决于许多因素可能导致潜在的安全漏洞。关键是您的服务器的`Content-Type`标头应该是浏览器考虑的唯一因素，而不是试图自行猜测。

与前面的例子一样，没有真正的配置可用，以下标头将简单地添加到您的应用程序中：

```js
X-Content-Type-Options: nosniff
```

通过头盔配置此标头：

```js
app.use(helmet.contentTypeOptions());
```

## Cache-Control

头盔提供的最后一个中间件是用于将`Cache-Control`标头设置为`no-store`或`no-cache`。这可以防止浏览器缓存给定的响应。这个中间件也没有配置，并且是通过以下方式包含的：

```js
app.use(helmet.cacheControl());
```

您将使用此中间件和标头来防止浏览器存储和缓存可能包含敏感用户信息的页面。然而，这样做的折衷是当在整体应用程序中应用时，您可能会遇到严重的性能问题。

在处理静态文件和资源（例如样式表和图像）时，此标头只会减慢您的站点速度，并且可能不会增加任何安全性好处。确保小心地在整体应用程序中如何以及何处应用此特定中间件。

头盔模块是向您的应用程序添加这些有用的安全功能的快速方法，这是由 Connect 创建的强大中间件架构启用的。有很多这些安全功能中的许多无法在这里解决，并且可能会在将来发生变化，因此最好熟悉它们所有。

# 总结

在本章中，我们看到了在应用程序处理的响应阶段出现的漏洞，比如 XSS 和 DoS。我们还研究了如何通过防御性编码或利用更新的安全标准和政策来减轻这些特定问题。
