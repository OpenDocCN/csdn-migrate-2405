# 解锁 JavaScript（一）

> 原文：[`zh.annas-archive.org/md5/A343D1C7BB9FB1F5BEAC75A7F1CFB40B`](https://zh.annas-archive.org/md5/A343D1C7BB9FB1F5BEAC75A7F1CFB40B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

JavaScript 是在最不恰当的时候——浏览器大战时期——作为脚本语言诞生的。它被忽视和误解了十年，经历了六个版本。现在看看它！JavaScript 已经成为一种主流编程语言。它在各个方面都有先进的使用：在大型客户端开发、服务器脚本、桌面应用、原生移动编程、游戏开发、数据库查询、硬件控制和操作系统自动化中。JavaScript 获得了许多子集，如 Objective-J、CoffeeScript、TypeScript 等。JavaScript 非常简洁，是一种表达性语言。它具有基于原型的面向对象编程、对象组合和继承、可变参函数、事件驱动编程和非阻塞 I/O 等特点。然而，为了发挥 JavaScript 的真正威力，我们需要对其语言特性有深入的理解。此外，在 JavaScript 开发过程中，我们会注意到它众多的陷阱，我们需要一些技巧来避免它们。以前被称为 EcmaScript Harmony 的项目，最近在名为 EcmaScript 2015 的规范中最终确定，通常被称为 ES6。这不仅将语言提升到下一个层次，还引入了许多需要关注的新技术。

本书旨在引导读者了解 JavaScript 即将推出和现有的特性。它充满了针对常见编程任务的代码食谱。这些任务提供了针对经典 JavaScript（ES5）以及下一代语言（ES6-7）的解决方案。本书关注的不仅仅是浏览器中的语言，还提供了编写高效 JavaScript 的基本知识，用于桌面应用、服务器端软件和原生模块应用。作者的最终目标是不仅描述语言，还要帮助读者改进他们的代码，以提高可维护性、可读性和性能。

# 本书内容涵盖

第一章，*深入 JavaScript 核心*，讨论了提高代码表达性的技术，掌握多行字符串和模板化，以及操作数组和类数组对象的方法。这一章解释了如何利用 JavaScript 原型而不损害代码的可读性。此外，这一章介绍了 JavaScript 的“魔法方法”，并给出了它们的实际使用示例。

第二章，*使用 JavaScript 的模块化编程*，描述了 JavaScript 中的模块化：模块是什么，为什么它们很重要，异步和同步加载模块的标准方法，以及 ES6 模块是什么。这一章展示了如何在服务器端 JavaScript 中使用 CommonJS 模块，以及如何为浏览器预编译它们。它详细介绍了如何将异步和同步方法结合起来，以实现更好的应用程序性能。它还解释了如何使用 Babel.js 为生产环境填充 ES6 模块。

第三章，*DOM 脚本编程与 AJAX*，介绍了文档对象模型（DOM），展示了最小化浏览器重绘的最佳实践，并在操作 DOM 时提高应用程序性能。这一章还比较了两种客户端服务器通信模型：XHR 和 Fetch API。

第四章，*HTML5 APIs*，考虑了浏览器持久化 API，如 Web 存储、IndexDB 和文件系统。它介绍了 Web 组件，并概述了创建自定义组件的过程。这一章描述了服务器到浏览器通信 API，如 SSE 和 WebSockets。

第五章，*异步 JavaScript*，解释了 JavaScript 的非阻塞性质，阐述了事件循环和调用栈。这一章考虑了异步调用链的流行风格以及错误处理。它介绍了 ES7 的 async/await 技术，并给出了使用 Promise API 和 Async.js 库并行和顺序运行任务的例子。它描述了节流和防抖的概念。

第六章，*大型 JavaScript 应用程序架构*，重点是代码可维护性和架构。这一章介绍了 MVC 范式及其变体，MVP 和 MVVM。它还通过 Backbone.js、AngularJS 和 ReactJS 等流行框架的示例，展示了如何实现关注分离。

第七章，*JavaScript 浏览器之外的应用*，解释了如何在 JavaScript 中编写命令行程序以及如何使用 Node.js 构建 Web 服务器。它还涵盖了使用 NW.js 创建桌面 HTML5 应用程序和指导使用 Phongap 开发原生移动应用程序的内容。

第八章，*调试和剖析*，深入探讨了 bug 的检测和隔离。它检查了 DevTools 的容量和 JavaScript 控制台 API 的一些不太知名的功能。

# 您需要什么

只要你有一个现代浏览器和一个文本编辑器，就可以运行书中的示例。然而，使用类似 Firefox Scratchpad 的浏览器工具可能会有所帮助，以直接在浏览器中编辑示例代码。（[`developer.mozilla.org/en-US/docs/Tools/Scratchpad`](https://developer.mozilla.org/en-US/docs/Tools/Scratchpad)）书中还包含了一些依赖于浏览器尚未支持的 ES6/ES7 特性的代码示例。你可以在[`babeljs.io/repl/`](https://babeljs.io/repl/)上使用 Babel.js 的在线沙盒运行这些示例。

你将在涉及 Node.js、NW.js、PhoneGap、JavaScript 框架和 NPM 包的章节中找到详细的设置开发环境和安装所需工具和依赖项的说明。

# 本书适合谁

这本书适合那些已经熟悉 JavaScript 并且想要提高技能以充分利用这门语言的开发者。本书以实践为导向，对于那些习惯于“边做边学”方法的人来说会有帮助，因为主题通过真实示例和教程进行了彻底的讲解。

# 约定

在这本书中，你会发现有许多文本样式用来区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理方式如下所示："我们可以通过使用`include`指令来包含其他上下文。"

代码块如下所示设置：

```js
var res = [ 1, 2, 3, 4 ].filter(function( v ){
 return v > 2;
})
console.log( res ); // [3,4]
```

当我们希望吸引您对代码块的特定部分注意时，相关行或项目以粗体显示：

```js
/**
* @param {Function} [cb] - callback
*/
function fn( cb ) {
 cb && cb();
};
```

任何命令行输入或输出如下所示：

```js
npm install fs-walk cli-color

```

**新术语**和**重要词汇**以粗体显示。例如，在菜单或对话框中出现的屏幕上的词，在文本中如下所示："一旦按下*Enter*，控制台输出**I'm running**。"

### 注意

警告或重要说明如下所示的盒子：

### 技巧

技巧和窍门就像这样出现。

# 读者反馈

读者反馈对我们来说总是受欢迎的。让我们知道你对这本书的看法——你喜欢或不喜欢什么。读者反馈对我们很重要，因为它帮助我们开发出你能真正从中受益的标题。

要给我们发送一般性反馈，只需发送电子邮件`<feedback@packtpub.com>`，并在消息主题中提到书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

您现在拥有了一本 Packt 图书，我们有很多方法可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的账户上下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

## 勘误

尽管我们已经尽一切努力确保我们的内容的准确性，但错误仍然会发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。这样做可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表单**链接，并输入您的勘误详情。一旦您的勘误得到验证，您的提交将被接受，勘误将被上传到我们的网站，或添加到该标题下的现有勘误列表中。

要查看以前提交的勘误，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索字段中输入书籍的名称。所需信息将在**勘误**部分下出现。

## 盗版

互联网上版权材料的盗版是一个持续存在的问题，涵盖所有媒体。在 Packt，我们非常重视我们版权和许可证的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，以便我们可以寻求解决方案。

如有怀疑的侵权材料，请联系我们`<copyright@packtpub.com>`。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在阅读本书时遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽力解决问题。


# 第一章： 深入 JavaScript 核心

你可能用了几年的 iPhone，自认为是个有经验的用户。同时，你在打字时按删除键逐个删除不需要的字符。然而，有一天你发现只需快速摇晃就能一次性删除整条信息。然后你可能会想为什么之前不知道这个技巧。编程也是一样。我们可能会对自己的代码相当满意，直到突然间遇到一个技巧或不太知名的语法特性，让我们重新考虑过去几年所做的全部工作。结果是我们本可以用更简洁、更可读、更可测试、更易维护的方式完成这些工作。所以假设你已经有一定的 JavaScript 经验；然而，这一章将为你提供改进代码的最佳实践。我们将涵盖以下主题：

+   使你的代码可读且具有表现力

+   掌握 JavaScript 中的多行字符串

+   以 ES5 的方式操作数组

+   以一种优雅、可靠、安全和快速的方式遍历对象

+   声明对象的最有效方式

+   了解 JavaScript 中的魔法方法

# 让你的代码可读且具有表现力

有许多实践和启发式方法可以使代码更具可读性、表现力和整洁性。我们稍后讨论这个话题，但在这里我们谈谈语法糖。这个术语意味着一种替代语法，使代码更具表现力和可读性。实际上，我们从一开始就有一些这样的东西在 JavaScript 中。例如，自增/自减和加法/减法赋值运算符继承自 C 语言。`*foo++*`是`*foo = foo + 1*`的语法糖，`*foo += bar*`是`*foo = foo + bar*`的简写形式。此外，还有一些同样的目的的小技巧。

JavaScript 对所谓的**短路**表达式应用逻辑运算。这意味着表达式是从左到右阅读的，但一旦在早期阶段确定了条件结果，表达式的尾部就不会被评估。如果我们有`true || false || false`，解释器会从第一个测试中知道结果无论如何都是`true`。所以`false || false`部分不会被评估，这就为创意开启了道路。

## 函数参数默认值

当我们需要为参数指定默认值时，可以这样操作：

```js
function stub( foo ) {
 return foo || "Default value";
}

console.log( stub( "My value" ) ); // My value
console.log( stub() ); // Default value
```

这里发生了什么？当`foo`是`true`（`not undefined`、`NaN`、`null`、`false`、`0`或`""`）时，逻辑表达式的结果就是`foo`，否则会评估到`Default value`，这就是最终结果。

从 ECMAScript 的第六版（JavaScript 语言的规格）开始，我们可以使用更优美的语法：

```js
function stub( foo = "Default value" ) {
 return foo;
}
```

## 条件调用

在编写代码时，根据条件缩短它：

```js
var age = 20;
age >= 18 && console.log( "You are allowed to play this game" );
age >= 18 || console.log( "The game is restricted to 18 and over" );
```

在前一个示例中，我们使用 AND（`&&`）操作符在左条件为真时调用`console.log`。OR（`||`）操作符相反，如果条件为`假`，则调用`console.log`。

我认为实践中最常见的情况是简写条件，只有在提供时函数才被调用：

```js
/**
* @param {Function} [cb] - callback
*/
function fn( cb ) {
 cb && cb();
};
```

以下是在此的一个更多示例：

```js
/**
* @class AbstractFoo
*/
AbstractFoo = function(){
 // call this.init if the subclass has init method
 this.init && this.init();
};
```

语法糖直到 CoffeeScript 的进步才完全进入 JavaScript 世界，CoffeeScript 是这种语言的一个子集，它源码编译（源码到源码编译）为 JavaScript。实际上，受 Ruby，Python 和 Haskell 启发的 CoffeeScript 为 JavaScript 开发者解锁了箭头函数，展开和其他语法。2011 年，Brendan Eich（JavaScript 的作者）承认 CoffeeScript 影响了他的 EcmaScript Harmony 的工作，该工作在今年夏天的 ECMA-262 6th edition specification 中最终完成。从市场营销的角度来看，规格编写者同意使用新的命名约定，将第 6 版称为 EcmaScript 2015，第 7 版称为 EcmaScript 2016。然而，社区已经习惯了缩写如 ES6 和 ES7。为了进一步避免混淆，在本书中，我们将用这些名称来指代规格。现在我们可以看看这对新的 JavaScript 有什么影响。

## 箭头函数

传统的函数表达式可能如下所示：

```js
function( param1, param2 ){ /* function body */ }
```

当使用箭头函数（也称为胖箭头函数）语法声明表达式时，我们将以更简洁的形式拥有这个 this，如下所示：

```js
( param1, param2 ) => { /* function body */ }
```

在我看来，这样做我们并没有得到太多。但是如果我们需要，比如说，一个数组方法的回调，传统形式如下：

```js
function( param1, param2 ){ return expression; }
```

现在等效的箭头函数变得更短了，如下所示：

```js
( param1, param2 ) => expression
```

我们可能这样在数组中进行过滤：

```js
// filter all the array elements greater than 2
var res = [ 1, 2, 3, 4 ].filter(function( v ){
 return v > 2;
})
console.log( res ); // [3,4]
```

使用数组函数，我们可以以更简洁的形式进行过滤：

```js
var res  = [ 1, 2, 3, 4 ].filter( v => v > 2 );
console.log( res ); // [3,4]
```

除了更短的方法声明语法外，箭头函数还带来了所谓的词法`this`。而不是创建自己的上下文，它使用周围对象的上下文，如下所示：

```js
"use strict";
/**
* @class View
*/   
let View = function(){
 let button = document.querySelector( "[data-bind=\"btn\"]" );
 /**
  * Handle button clicked event
  * @private 
  */
 this.onClick = function(){
   console.log( "Button clicked" );
 };
 button.addEventListener( "click", () => {
   // we can safely refer surrounding object members
   this.onClick(); 
 }, false );
}
```

在前一个示例中，我们为 DOM 事件（`click`）订阅了一个处理函数。在处理器的范围内，我们仍然可以访问视图上下文（`this`），因此我们不需要将处理函数绑定到外部作用域或通过闭包作为变量传递：

```js
var that = this;
button.addEventListener( "click", function(){
  // cross-cutting concerns
  that.onClick(); 
}, false );
```

## 方法定义

如前一部分所述，当声明小型的内联回调函数时，箭头函数非常方便，但总是为了更短的语法而使用它是有争议的。然而，ES6 除了箭头函数之外，还提供了新的替代方法定义语法。老式的方法声明可能如下所示：

```js
var foo = {
 bar: function( param1, param2 ) {
 }
}
```

在 ES6 中，我们可以摆脱函数关键字和冒号。所以前一条代码可以这样做：

```js
let foo = {
 bar ( param1, param2 ) {
 }
}
```

## 剩余操作符

另一种从 CoffeeScript 借用的语法结构作为剩余操作符（尽管在 CoffeeScript 中，这种方法被称为*splats*）来到了 JavaScript。

当我们有几个必需的函数参数和一个未知数量的剩余参数时，我们通常会这样做：

```js
"use strict";
var cb = function() {
 // all available parameters into an array
 var args = [].slice.call( arguments ),
     // the first array element to foo and shift
     foo = args.shift(),
     // the new first array element to bar and shift
     bar = args.shift();
 console.log( foo, bar, args );
};
cb( "foo", "bar", 1, 2, 3 ); // foo bar [1, 2, 3]
```

现在看看这段代码在 ES6 中变得多么有表现力：

```js
let cb = function( foo, bar, ...args ) {
 console.log( foo, bar, args );
}
cb( "foo", "bar", 1, 2, 3 ); // foo bar [1, 2, 3]
```

函数参数不是剩余操作符的唯一应用。例如，我们也可以在解构中使用它，如下所示：

```js
let [ bar, ...others ] = [ "bar", "foo", "baz", "qux" ];
console.log([ bar, others ]); // ["bar",["foo","baz","qux"]]
```

## 展开操作符

同样，我们也可以将数组元素展开为参数：

```js
let args = [ 2015, 6, 17 ],
   relDate = new Date( ...args );
console.log( relDate.toString() );  // Fri Jul 17 2015 00:00:00 GMT+0200 (CEST)
```

ES6 还提供了创建对象和继承的有表现力的语法糖，但我们将稍后在*声明对象的最有效方式*部分中 examine this。

# 掌握 JavaScript 中的多行字符串

多行字符串不是 JavaScript 的一个好部分。虽然它们在其他语言中很容易声明（例如，NOWDOC），但你不能只是将单引号或双引号的字符串保持在多行中。这会导致语法错误，因为 JavaScript 中的每一行都被认为是可能的命令。你可以用反斜杠来表示你的意图：

```js
var str = "Lorem ipsum dolor sit amet, \n\
consectetur adipiscing elit. Nunc ornare, \n\
diam ultricies vehicula aliquam, mauris \n\
ipsum dapibus dolor, quis fringilla leo ligula non neque";
```

这种方法基本有效。然而，一旦你漏掉了一个尾随空格，你就会得到一个语法错误，这不容易被发现。虽然大多数脚本代理支持这种语法，但它并不是 EcmaScript 规范的一部分。

在**EcmaScript for XML**（**E4X**）的时代，我们可以将纯 XML 赋值给一个字符串，这为这些声明打开了一条道路：

```js
var str = <>Lorem ipsum dolor sit amet, 
consectetur adipiscing 
elit. Nunc ornare </>.toString();
```

现在 E4X 已经被弃用，不再被支持。

## 字符串连接与数组连接

我们也可以使用字符串连接。它可能感觉笨拙，但它是安全的：

```js
var str = "Lorem ipsum dolor sit amet, \n" +
 "consectetur adipiscing elit. Nunc ornare,\n" +
 "diam ultricies vehicula aliquam, mauris \n" +
 "ipsum dapibus dolor, quis fringilla leo ligula non neque";
```

你可能会感到惊讶，但字符串连接比数组连接慢。所以以下技术会更快地工作：

```js
var str = [ "Lorem ipsum dolor sit amet, \n",
 "consectetur adipiscing elit. Nunc ornare,\n",
 "diam ultricies vehicula aliquam, mauris \n",
 "ipsum dapibus dolor, quis fringilla leo ligula non neque"].join( "" );
```

## 模板字面量

那么 ES6 呢？最新的 EcmaScript 规范引入了一种新的字符串字面量，模板字面量：

```js
var str = `Lorem ipsum dolor sit amet, \n
consectetur adipiscing elit. Nunc ornare, \n
diam ultricies vehicula aliquam, mauris \n
ipsum dapibus dolor, quis fringilla leo ligula non neque`;
```

现在这个语法看起来很优雅。但还有更多。模板字面量真的让我们想起了 NOWDOC。你可以在字符串中引用作用域内声明的任何变量：

```js
"use strict";
var title = "Some title",
   text = "Some text",
   str = `<div class="message">
<h2>${title}</h2>
<article>${text}</article>
</div>`;
console.log( str );
```

输出如下：

```js
<div class="message">
<h2>Some title</h2>
<article>Some text</article>
</div>
```

如果你想知道何时可以安全地使用这种语法，我有一个好消息告诉你——这个特性已经得到了（几乎）所有主要脚本代理的支持（[`kangax.github.io/compat-table/es6/`](http://kangax.github.io/compat-table/es6/)）。

## 通过转译器实现多行字符串

随着 ReactJS 的发展，Facebook 的 EcmaScript 语言扩展 JSX（[`facebook.github.io/jsx/`](https://facebook.github.io/jsx/)）现在已经真正获得了动力。显然受到之前提到的 E4X 的影响，他们提出了一种没有任何筛选的 XML 样内容的字符串字面量。这种类型支持类似于 ES6 模板的模板插值：

```js
"use strict";
var Hello = React.createClass({
 render: function() {
 return <div class="message">
<h2>{this.props.title}</h2>
<article>{this.props.text}</article>
</div>;
 }
});

React.render(<Hello title="Some title" text="Some text" />, node);
```

另一种声明多行字符串的方法是使用 CommonJS 编译器（[`dsheiko.github.io/cjsc/`](http://dsheiko.github.io/cjsc/)）。在解析'require'依赖关系时，编译器将任何非`.js`/`.json`内容转换为单行字符串：

**foo.txt**

```js
Lorem ipsum dolor sit amet,
consectetur adipiscing elit. Nunc ornare,
diam ultricies vehicula aliquam, mauris
ipsum dapibus dolor, quis fringilla leo ligula non neque
```

**consumer.js**

```js
var str = require( "./foo.txt" );
console.log( str );
```

您可以在第六章中找到 JSX 使用的示例，*大规模 JavaScript 应用程序架构*。

# 以 ES5 方式操作数组

几年前，当 ES5 特性的支持较差（ECMAScript 第五版于 2009 年最终确定）时，像 Underscore 和 Lo-Dash 这样的库变得非常流行，因为它们提供了一套全面的工具来处理数组/集合。今天，许多开发者仍然使用第三方库（包括 jQuery/Zepro）来处理诸如`map`、`filter`、`every`、`some`、`reduce`和`indexOf`等方法，而这些方法在 JavaScript 的本地形式中是可用的。是否需要这些库还取决于您的使用方式，但很可能您不再需要它们。让我们看看现在 JavaScript 中有什么。

## ES5 中的数组方法

`Array.prototype.forEach`可能是数组中最常用的方法。也就是说，它是`_.each`的本地实现，或者是例如`$.each`实用程序的实现。作为参数，`forEach`期望一个`iteratee`回调函数，可选的是您希望执行回调的上下文。它将元素值、索引和整个数组传递给回调函数。大多数数组操作方法都使用相同的参数语法。注意 jQuery 的`$.each`将回调参数顺序颠倒：

```js
"use strict";
var data = [ "bar", "foo", "baz", "qux" ];
data.forEach(function( val, inx ){
  console.log( val, inx ); 
});
```

`Array.prototype.map`通过转换给定数组的元素来生成一个新的数组：

```js
"use strict";
var data = { bar: "bar bar", foo: "foo foo" },
   // convert key-value array into url-encoded string
   urlEncStr = Object.keys( data ).map(function( key ){
     return key + "=" + window.encodeURIComponent( data[ key ] );
   }).join( "&" );

console.log( urlEncStr ); // bar=bar%20bar&foo=foo%20foo
```

`Array.prototype.filter`返回一个数组，该数组由满足回调条件的给定数组值组成：

```js
"use strict";
var data = [ "bar", "foo", "", 0 ],
   // remove all falsy elements
   filtered = data.filter(function( item ){
     return !!item;
   });

console.log( filtered ); // ["bar", "foo"]
```

`Array.prototype.reduce`/`Array.prototype.reduceRight`检索数组中值的产品。该方法期望一个回调函数和可选的初始值作为参数。回调函数接收四个参数：累积值、当前值、索引和原始数组。因此，我们可以通过当前值增加累积值（返回 acc += cur;）来实例化，从而得到数组值的和。

除了使用这些方法进行计算外，我们还可以连接字符串值或数组：

```js
"use strict";
var data = [[ 0, 1 ], [ 2, 3 ], [ 4, 5 ]],
   arr = data.reduce(function( prev, cur ) {
     return prev.concat( cur );
   }),
   arrReverse = data.reduceRight(function( prev, cur ) {
     return prev.concat( cur );
   });

console.log( arr ); //  [0, 1, 2, 3, 4, 5]
console.log( arrReverse ); // [4, 5, 2, 3, 0, 1]
```

`Array.prototype.some`测试给定数组中的任何一个（或一些）值是否满足回调条件：

```js
"use strict";
var bar = [ "bar", "baz", "qux" ],
   foo = [ "foo", "baz", "qux" ],
   /**
    * Check if a given context (this) contains the value
    * @param {*} val
    * @return {Boolean}
    */
   compare = function( val ){
     return this.indexOf( val ) !== -1; 
   };

console.log( bar.some( compare, foo ) ); // true
```

在这个例子中，我们检查`foo`数组中是否有任何一个柱状数组值是可用的。为了可测试性，我们需要将`foo`数组的引用传递给回调函数。这里我们将其作为上下文注入。如果我们需要传递更多的引用，我们会将它们推入一个键值对象中。

正如您可能注意到的，在这个例子中我们使用了`Array.prototype.indexOf`。这个方法的工作方式与`String.prototype.indexOf`相同。如果找到匹配项，则返回匹配项的索引，否则返回-1。

`Array.prototype.every`测试给定数组的每一个值是否满足回调条件：

```js
"use strict";
var bar = [ "bar", "baz" ],
   foo = [ "bar", "baz", "qux" ],
   /**
    * Check if a given context (this) contains the value
    * @param {*} val
    * @return {Boolean}
    */
   compare = function( val ){
     return this.indexOf( val ) !== -1; 
   };

console.log( bar.every( compare, foo ) ); // true
```

如果你仍然关心这些方法在像 IE6-7 这样老旧的浏览器中的支持情况，你可以简单地使用 [`github.com/es-shims/es5-shim`](https://github.com/es-shims/es5-shim) 来补丁它们。

## es6 中的数组方法

在 ES6 中，我们只获得了一些看起来像是现有功能快捷方式的新方法。

`Array.prototype.fill` 用给定值填充数组，如下所示：

```js
"use strict";
var data = Array( 5 );
console.log( data.fill( "bar" ) ); // ["bar", "bar", "bar", "bar", "bar"]
```

`Array.prototype.includes` 明确检查给定值是否存在于数组中。嗯，它和 `arr.indexOf( val ) !== -1` 是一样的，如下所示：

```js
"use strict";
var data = [ "bar", "foo", "baz", "qux" ];
console.log( data.includes( "foo" ) );
```

`Array.prototype.find` 过滤出符合回调条件的单个值。再次说明，这和 `Array.prototype.filter` 能获得的是一样的。唯一的区别是 filter 方法返回一个数组或者一个 null 值。在这种情况下，它返回一个包含单个元素的数组，如下所示：

```js
"use strict";
var data = [ "bar", "fo", "baz", "qux" ],
   match = function( val ){
     return val.length < 3;
   };
console.log( data.find( match ) ); // fo
```

# 优雅、可靠、安全、快速地遍历对象

当我们有一个键值对象（比如说选项）并且需要遍历它时，这是一个常见的情况。下面代码中展示了一种学术上的做法：

```js
"use strict";
var options = {
    bar: "bar",
    foo: "foo"
   },
   key;
for( key in options ) {
 console.log( key, options[ key] );
}
```

上述代码输出如下：

```js
bar bar
foo foo
```

现在让我们想象一下，你文档中加载的任何第三方库都增强了内置的 `Object`：

```js
Object.prototype.baz = "baz";
```

现在当我们运行我们的示例代码时，我们将得到一个额外的不需要的条目：

```js
bar bar
foo foo
baz baz
```

这个问题解决方案是众所周知的，我们必须使用 `Object.prototype.hasOwnProperty` 方法测试键：

```js
//…
for( key in options ) {
 if ( options.hasOwnProperty( key ) ) {
   console.log( key, options[ key] );
 }
}
```

## 安全快速地遍历键值对象

让我们面对现实吧——这个结构是笨拙的，需要优化（我们必须对每个给定的键执行 `hasOwnProperty` 测试）。幸运的是，JavaScript 有 `Object.keys` 方法，它可以获取所有枚举的自身（非继承）属性的字符串值。这让我们得到了一个数组，里面是我们期望的键，我们可以用 `Array.prototype.forEach` 等方式进行迭代：

```js
"use strict";
var options = {
    bar: "bar",
    foo: "foo"
   };
Object.keys( options ).forEach(function( key ){
 console.log( key, options[ key] );
});
```

除了优雅，我们这种方式还能得到更好的性能。为了看看我们获得了多少性能提升，你可以在不同的浏览器上运行这个在线测试，比如：[`codepen.io/dsheiko/pen/JdrqXa`](http://codepen.io/dsheiko/pen/JdrqXa)。

## 枚举数组对象

像 `arguments` 和 `nodeList`（`node.querySelectorAll`、`document.forms`）这样的对象看起来像数组，实际上它们并不是。和数组一样，它们有 `length` 属性，可以在 `for` 循环中进行迭代。以对象的形式，它们可以以前面提到的相同方式进行遍历。但它们没有任何数组操作方法（`forEach`、`map`、`filter`、`some` 等等）。事实是，我们可以很容易地将它们转换为数组，如下所示：

```js
"use strict";
var nodes = document.querySelectorAll( "div" ),
   arr = Array.prototype.slice.call( nodes );

arr.forEach(function(i){
 console.log(i);
});
```

上述代码甚至可以更短：

```js
arr = [].slice.call( nodes )
```

这是一个非常方便的解决方案，但看起来像是一个技巧。在 ES6 中，我们可以用一个专用方法进行相同的转换：

```js
arr = Array.from( nodes );
```

## es6 集合

ES6 引入了一种新类型的对象——可迭代对象。这些对象可以一次获取一个元素。它们与其他语言中的迭代器非常相似。除了数组，JavaScript 还接收了两个新的可迭代数据结构，`Set`和`Map`。`Set`是一个包含唯一值的集合：

```js
"use strict";
let foo = new Set();
foo.add( 1 );
foo.add( 1 );
foo.add( 2 );
console.log( Array.from( foo ) ); // [ 1, 2 ]

let foo = new Set(), 
   bar = function(){ return "bar"; };
foo.add( bar );
console.log( foo.has( bar ) ); // true
```

映射类似于键值对象，但键可以是任意值。这造成了区别。想象一下，我们需要编写一个元素包装器，提供类似 jQuery 的事件 API。通过使用`on`方法，我们不仅可以传递一个处理回调函数，还可以传递一个上下文（`this`）。我们通过`cb.bind(context)`将给定的回调绑定到上下文。这意味着`addEventListener`接收一个与回调不同的函数引用。那么我们如何取消订阅处理程序呢？我们可以通过一个由事件名称和`callback`函数引用组成的键将新引用存储在`Map`中：

```js
"use strict";
/**
* @class
* @param {Node} el
*/
let El = function( el ){
 this.el = el;
 this.map = new Map();
};
/**
* Subscribe a handler on event
* @param {String} event
* @param {Function} cb
* @param {Object} context
*/
El.prototype.on = function( event, cb, context ){
 let handler = cb.bind( context || this );
 this.map.set( [ event, cb ], handler );
 this.el.addEventListener( event, handler, false );
};
/**
* Unsubscribe a handler on event
* @param {String} event
* @param {Function} cb
*/

El.prototype.off = function( event, cb ){
 let handler = cb.bind( context ),
     key = [ event, handler ];
 if ( this.map.has( key ) ) {
 this.el.removeEventListener( event, this.map.get( key ) );
 this.map.delete( key );
 }
};
```

任何可迭代的对象都有方法，`keys`，`values`和`entries`，其中键与`Object.keys`相同，其他方法分别返回数组值和键值对数组。现在让我们看看我们如何遍历可迭代的对象：

```js
"use strict";
let map = new Map()
 .set( "bar", "bar" )
 .set( "foo", "foo" ),
   pair;
for ( pair of map ) {
 console.log( pair );
}

// OR 
let map = new Map([
   [ "bar", "bar" ],
   [ "foo", "foo" ],
]);
map.forEach(function( value, key ){
 console.log( key, value );
});
```

可迭代的对象有数组类似的操作方法。因此我们可以使用`forEach`。此外，它们可以通过`for...in`和`for...of`循环进行迭代。第一个获取索引，第二个获取值。

# 声明对象最有效的方法

我们在 JavaScript 中如何声明一个对象？如果我们需要一个命名空间，我们可以简单地使用一个对象字面量。但当我们需要一个对象类型时，我们需要三思采取什么方法，因为这会影响我们面向对象代码的可维护性。

## 古典方法

我们可以创建一个构造函数并将成员链接到其上下文：

```js
"use strict"; 
/**
 * @class
 */
var Constructor = function(){
   /**
   * @type {String}
   * @public
   */
   this.bar = "bar";
   /**
   * @public
   * @returns {String}
   */
   this.foo = function() {
    return this.bar;
   };
 },
 /** @type Constructor */
 instance = new Constructor();

console.log( instance.foo() ); // bar
console.log( instance instanceof Constructor ); // true
```

我们还可以将成员分配给构造函数原型。结果将与以下相同：

```js
"use strict";
/**
* @class
*/
var Constructor = function(){},
   instance;
/**
* @type {String}
* @public
*/
Constructor.prototype.bar = "bar";
/**
* @public
* @returns {String}
*/
Constructor.prototype.foo = function() {
 return this.bar;
};
/** @type Constructor */
instance = new Constructor();

console.log( instance.foo() ); // bar
console.log( instance instanceof Constructor ); // true
```

在第一种情况下，我们在构造函数体中混合了对象结构和构造逻辑。在第二种情况下，通过重复`Constructor.prototype`，我们违反了**不要重复自己**（**DRY**）原则。

## 私有状态的方法

那么我们还可以用其他方式做什么呢？我们可以通过构造函数函数返回一个对象字面量：

```js
"use strict";
/**
 * @class
 */
var Constructor = function(){
     /**
     * @type {String}
     * @private
     */
     var baz = "baz";
     return {
       /**
       * @type {String}
       * @public
       */
       bar: "bar",
       /**
       * @public
       * @returns {String}
       */
       foo: function() {
        return this.bar + " " + baz;
       }
     };
   },
   /** @type Constructor */
   instance = new Constructor();

console.log( instance.foo() ); // bar baz
console.log( instance.hasOwnProperty( "baz") ); // false
console.log( Constructor.prototype.hasOwnProperty( "baz") ); // false
console.log( instance instanceof Constructor ); // false
```

这种方法的优势在于，构造函数作用域内声明的任何变量都与返回的对象在同一个闭包中，因此，可以通过对象访问。我们可以将这些变量视为私有成员。坏消息是我们将失去构造函数原型。当构造函数在实例化过程中返回一个对象时，这个对象成为整个新表达式的结果。

## 原型链的继承

那么继承呢？古典方法会让子类型原型成为超类型实例：

```js
"use strict";
 /**
 * @class
 */
var SuperType = function(){
       /**
       * @type {String}
       * @public
       */
       this.foo = "foo";
     },
     /**
      * @class
      */
     Constructor = function(){
       /**
       * @type {String}
       * @public
       */
       this.bar = "bar";
     },
     /** @type Constructor */
     instance;

 Constructor.prototype = new SuperType();
 Constructor.prototype.constructor = Constructor;

 instance = new Constructor();
 console.log( instance.bar ); // bar
 console.log( instance.foo ); // foo
 console.log( instance instanceof Constructor ); // true
 console.log( instance instanceof SuperType ); // true  
```

你可能会遇到一些代码，其中实例化时使用`Object.create`而不是新操作符。在这里，你需要知道两者的区别。`Object.create`接受一个对象作为参数，并创建一个以传递的对象为原型的新对象。在某种意义上，这使我们想起了克隆。检查这个，你声明一个对象字面量（proto）并基于第一个对象使用`Object.create`创建一个新的对象（实例）。无论你现在对新生成对象做何更改，它们都不会反映在原始（proto）上。但是，如果你更改原始对象的属性，你会在派生对象（实例）中发现该属性已更改：

```js
"use strict";
var proto = {
 bar: "bar",
 foo: "foo"
}, 
instance = Object.create( proto );
proto.bar = "qux",
instance.foo = "baz";
console.log( instance ); // { foo="baz",  bar="qux"}
console.log( proto ); // { bar="qux",  foo="foo"}
```

## 通过`Object.create`继承原型

与新操作符相比，`Object.create`不调用构造函数。因此，当我们使用它来填充子类型的原型时，我们失去了位于`supertype`构造函数中的所有逻辑。这样，`supertype`构造函数永远不会被调用：

```js
// ...
SuperType.prototype.baz = "baz";
Constructor.prototype = Object.create( SuperType.prototype );
Constructor.prototype.constructor = Constructor;

instance = new Constructor();

console.log( instance.bar ); // bar
console.log( instance.baz ); // baz
console.log( instance.hasOwnProperty( "foo" ) ); // false
console.log( instance instanceof Constructor ); // true
console.log( instance instanceof SuperType ); // true
```

### 通过`Object.assign`继承原型

当寻找最优结构时，我希望通过对象字面量声明成员，但仍保留到原型的链接。许多第三方项目利用自定义函数(*extend*)将结构对象字面量合并到构造函数原型中。实际上，ES6 提供了`Object.assign`本地方法。我们可以像这样使用它：

```js
"use strict";
   /**
    * @class
    */
var SuperType = function(){
     /**
     * @type {String}
     * @public
     */
     this.foo = "foo";
   },
   /**
    * @class
    */
   Constructor = function(){
     /**
     * @type {String}
     * @public
     */
     this.bar = "bar";
   },
   /** @type Constructor */
   instance;

Object.assign( Constructor.prototype = new SuperType(), {
 baz: "baz"
});
instance = new Constructor();
console.log( instance.bar ); // bar
console.log( instance.foo ); // foo
console.log( instance.baz ); // baz
console.log( instance instanceof Constructor ); // true
console.log( instance instanceof SuperType ); // true
```

这看起来几乎就是所需的，除了有一点不便。`Object.assign`简单地将源对象的价值分配给目标对象，而不管它们的类型如何。所以如果你有一个源属性是一个对象（例如，一个`Object`或`Array`实例），目标对象接收一个引用而不是一个值。所以你必须在初始化时手动重置任何对象属性。

## 使用 ExtendClass 的方法

由 Simon Boudrias 提出的`ExtendClass`似乎是一个无懈可击的解决方案([`github.com/SBoudrias/class-extend`](https://github.com/SBoudrias/class-extend))。他的小型库暴露了带有**extend**静态方法的`Base`构造函数。我们使用这个方法来扩展这个伪类及其任何派生类：

```js
"use strict";
   /**
    * @class
    */
var SuperType = Base.extend({
     /**
      * @pulic
      * @returns {String}
      */
     foo: function(){ return "foo public"; },
     /**
      * @constructs SuperType
      */
     constructor: function () {}
   }),
   /**
    * @class
    */
   Constructor = SuperType.extend({
     /**
      * @pulic
      * @returns {String}
      */      
     bar: function(){ return "bar public"; }
   }, {
     /**
      * @static
      * @returns {String}
      */      
     bar: function(){ return "bar static"; }
   }),
   /** @type Constructor */
   instance = new Constructor();

console.log( instance.foo() ); // foo public
console.log( instance.bar() ); // bar public
console.log( Constructor.bar() ); // bar static
console.log( instance instanceof Constructor ); // true
console.log( instance instanceof SuperType ); // true
```

## es6 中的类

tc39（ECMAScript 工作组）对这个问题非常清楚，所以新的语言规范提供了额外的语法来结构对象类型：

```js
"use strict";
class AbstractClass {
 constructor() {
   this.foo = "foo";
 }
}
class ConcreteClass extends AbstractClass {
 constructor() {
   super();
   this.bar = "bar";
 }
 baz() {
   return "baz";
 }
}

let instance = new ConcreteClass();
console.log( instance.bar ); // bar
console.log( instance.foo ); // foo
console.log( instance.baz() ); // baz
console.log( instance instanceof ConcreteClass ); // true
console.log( instance instanceof AbstractClass ); // true
```

这个语法看起来是基于类的，但实际上这只是现有原型的语法糖。你可以检查`ConcreteClass`的类型，它会给你*function*，因为`ConcreteClass`是一个典型的构造器。所以我们在扩展`supertypes`时不需要任何技巧，不需要从子类型中引用`supertype`构造函数，并且我们有一个清晰可读的结构。然而，我们无法以现在的方法相同的 C 语言方式分配属性。这仍在 ES7 的讨论中([`esdiscuss.org/topic/es7-property-initializers`](https://esdiscuss.org/topic/es7-property-initializers))。此外，我们可以在类的正文中直接声明类的静态方法：

```js
class Bar {
 static foo() {
   return "static method";
 }
 baz() {
   return "prototype method";
 }
}
let instance = new Bar();
console.log( instance.baz() ); // prototype method
console.log( Bar.foo()) ); // static method
```

实际上，有很多在 JavaScript 社区的人认为新的语法是从原型面向对象方法的一种偏离。另一方面，ES6 类与大多数现有代码向后兼容。子类现在由语言支持，不需要额外的库来实现继承。我个人最喜欢的是，这种语法允许我们使代码更简洁、更易于维护。

# 如何——JavaScript 中的魔术方法

在 PHP 世界中，有诸如*重载方法*这样的概念，它们也被称为魔术方法（[`www.php.net/manual/en/language.oop5.overloading.php`](http://www.php.net/manual/en/language.oop5.overloading.php)）。这些方法允许我们在访问或修改一个方法的不存在属性时触发一个逻辑。在 JavaScript 中，我们控制对属性（值成员）的访问。想象我们有一个自定义的集合对象。为了保持 API 的一致性，我们想要有一个`length`属性，它包含集合的大小。所以我们就声明一个`getter`（获取长度），每当属性被访问时就会执行所需的计算。在尝试修改属性值时，设置器将抛出一个异常：

```js
"use strict";
var bar = {
 /** @type {[Number]} */
 arr: [ 1, 2 ],
 /**
  * Getter
  * @returns {Number}
  */
 get length () {
   return this.arr.length;
 },
 /**
  * Setter
  * @param {*} val
  */
 set length ( val ) {
   throw new SyntaxError( "Cannot assign to read only property 'length'" );
 }
};
console.log ( bar.length ); // 2
bar.arr.push( 3 );
console.log ( bar.length ); // 3
bar.length = 10; // SyntaxError: Cannot assign to read only property 'length'
```

如果我们想在现有对象上声明 getters/setters，我们可以使用以下方式：

```js
Object.defineProperty:
"use strict";
var bar = {
 /** @type {[Number]} */
 arr: [ 1, 2 ]
};

Object.defineProperty( bar, "length", {
 /**
  * Getter
  * @returns {Number}
  */
 get: function() {
   return this.arr.length;
 },
 /**
  * Setter
  */
 set: function() {
   throw new SyntaxError( "Cannot assign to read only property 'length'" );
 }
});

console.log ( bar.length ); // 2
bar.arr.push( 3 );
console.log ( bar.length ); // 3
bar.length = 10; // SyntaxError: Cannot assign to read only property 'length'
```

`Object.defineProperty`以及`Object.create`的第二个参数指定了属性配置（是否可枚举、可配置、不可变，以及如何访问或修改）。因此，我们可以通过将属性设置为只读来达到类似的效果：

```js
"use strict";
var bar = {};

Object.defineProperty( bar, "length", {
 /**
  * Data descriptor
  * @type {*}
  */
 value: 0,
 /**
  * Data descriptor
  * @type {Boolean}
  */
 writable: false
});

bar.length = 10; // TypeError: "length" is read-only
```

顺便说一下，如果你想要摆脱对象中的属性访问器，你可以简单地移除该属性：

```js
delete bar.length;
```

## ES6 类中的访问器

声明访问器的另一种方式是使用 ES6 类：

```js
"use strict";
/** @class */
class Bar {
 /** @constructs Bar */
 constructor() {
   /** @type {[Number]} */
   this.arr = [ 1, 2 ];
 }
 /**
  * Getter
  * @returns {Number}
  */
 get length() {
   return this.arr.length;
 }
 /**
  * Setter
  * @param {Number} val
  */
 set length( val ) {
    throw new SyntaxError( "Cannot assign to read only property 'length'" );
 }
}

let bar = new Bar();
console.log ( bar.length ); // 2
bar.arr.push( 3 );
console.log ( bar.length ); // 3
bar.length = 10; // SyntaxError: Cannot assign to read only property 'length'
```

除了公共属性，我们还可以控制对静态属性的访问：

```js
"use strict";

class Bar {
   /**
    * @static
    * @returns {String}
    */
   static get baz() {
       return "baz";
   }
}

console.log( Bar.baz ); // baz
```

## 控制对任意属性的访问

所有这些示例都展示了对已知属性的访问控制。然而，可能有一个情况，我想要一个具有类似于`localStorage`的变长接口的自定义存储。这必须是一个具有`getItem`方法以检索存储的值和`setItem`方法以设置它们的存储。此外，这必须与直接访问或设置伪属性（`val = storage.aKey`和`storage.aKey = "value"`）的方式相同。这可以通过使用 ES6 代理实现：

```js
"use strict";
/**
* Custom storage
*/
var myStorage = {
     /** @type {Object} key-value object */
     data: {},
     /**
      * Getter
      * @param {String} key
      * @returns {*}
      */
     getItem: function( key ){
       return this.data[ key ];
     },
     /**
      * Setter
      * @param {String} key
      * @param {*} val
      */
     setItem: function( key, val ){
       this.data[ key ] = val;
     }
   },
   /**
    * Storage proxy
    * @type {Proxy}
    */
   storage = new Proxy( myStorage, {
     /**
      * Proxy getter
      * @param {myStorage} storage
      * @param {String} key
      * @returns {*}
      */
     get: function ( storage, key ) {
       return storage.getItem( key );
     },
     /**
      * Proxy setter
      * @param {myStorage} storage
      * @param {String} key
      * @param {*} val
      * @returns {void}
      */
     set: function ( storage, key, val ) {
       return storage.setItem( key, val );
   }});

storage.bar = "bar";
console.log( myStorage.getItem( "bar" ) ); // bar
myStorage.setItem( "bar", "baz" );
console.log( storage.bar ); // baz
```

# 摘要

本章介绍了如何使用 JavaScript 核心特性达到最大效果的最佳实践和技巧。在下一章中，我们将讨论模块概念，并详细介绍作用域和闭包。下一章将解释作用域上下文及其操作方法。


# 第二章：使用 JavaScript 的模块化编程

总的来说，工程学就是将大型任务分解为小型任务，并在系统中组合这些任务的解决方案。在软件工程中，我们遵循低耦合和高内聚的原则，将代码库分解为模块。在本章中，我们将讨论在 JavaScript 中创建模块的方法，并涵盖以下主题：

+   如何使用模块化的 JavaScript 摆脱困境

+   如何在浏览器中使用异步模块

+   如何在服务器上使用同步模块

+   JavaScript 内置模块系统

+   将 CommonJS 转换为浏览器使用

# 如何使用模块化的 JavaScript 摆脱困境

你有多少数码照片，可能成千上万，或者更多？想象一下，如果你的图片查看器没有分类能力。没有相册，没有书籍，没有分类，什么都没有。它将毫无用处，不是吗？现在假设你有一个 JavaScript 应用程序，它包含在一个文件中，并且它不断增长。当它接近一千行或超过一千行代码时，无论你的代码设计有多好，从可维护性的角度来看，它仍然会变成像那堆未分类照片的巨大列表一样的无用*堆*。我们不应该构建一个单块应用程序，而应该编写几个独立的模块，它们组合在一起形成一个应用程序。因此，我们将复杂问题分解为简单任务。

## 模块

那么，模块是什么呢？模块封装了为特定功能设计的代码。模块还提供了一个接口，声明了模块公开和需要的元素。模块通常打包在一个文件中，这使得它容易定位和部署。一个设计良好的模块意味着低耦合（模块之间的相互依赖程度）和高内聚（模块元素彼此属于的程度）。

模块在 JavaScript 中给我们带来了哪些优势？

### 更清晰的全局作用域

你在 JavaScript 中知道任何在我们任何函数作用域之外进行的赋值都会在全局作用域中创建一个新的成员（在浏览器中是一个内置对象 window，在 Node.js/Io.js 中是 global）。因此，我们总是有意外覆盖已经定义属性的风险。相反，模块中声明的任何内容除非我们明确导出它，否则它将留在这里。

### 将代码打包成文件

在服务器端语言中，应用程序由许多文件组成。这里的一个最佳实践是，一个文件只包含一个类，并且只负责一件事情。此外，完全限定的类名必须反映其文件位置。所以当我们遇到对象问题时，我们可以很容易地推断出在哪里可以找到其源代码。我们可以将 JavaScript 应用程序代码分成不同的脚本，但这些将共享同一个作用域，并且不会给我们任何封装。此外，当脚本异步加载时，内部依赖关系必须解决，这并不容易。但是，如果我们使用模块，每个模块都有一个专门的文件和自己的作用域。模块加载器负责异步依赖关系。

### 重用

想象一下，在项目工作中，你写了一段代码，解决了一个任务——比如提供了一个方便的 API 来管理 cookie。当切换到另一个项目时，你意识到你的 cookie 管理器在那里会很合适。在*意大利面条代码*的情况下，你必须提取组件代码，解耦它，并将其绑定到新位置。如果你将组件作为设计得体的模块编写，你只需拿过来并插入即可。

## 模块模式

嗯，我们知道模块有帮助，并且我们想使用它们。那么，我们在 JavaScript 中如何实现一个模块呢？首先，我们需要将模块代码从全局作用域中分离出来。我们只能通过用函数包装模块代码来实现这一点。这里的一个常见做法是使用**立即执行函数表达式**（**IIFE**）：

```js
IIFE
(function () {
  "use strict";
   // variable defined inside this scope cannot be accessed from outside
}());
```

模块还必须具有与周围环境交互的接口。就像我们通常处理函数一样，我们可以将对象引用作为 IIFE 的参数传递。

```js
Import
(function ( $, Backbone ) {
   "use strict";
  // module body
}( jQuery, Backbone ));
```

你可能也看到过一种模式，即全局对象（window）通过参数传递。这种方式我们不是直接访问全局对象，而是通过引用。有一种观点认为通过局部引用访问更快。这并不完全正确。我准备了一个 Codepen，里面有一些测试，在[`codepen.io/dsheiko/pen/yNjEar`](http://codepen.io/dsheiko/pen/yNjEar)。它显示，在 Chrome（v45）中，局部引用确实快了 20%；然而，在 Firefox（v39）中，这并没有造成任何显著的差异。

你也可以在参数列表中运行模式变体 with `undefined`。没有通过参数传递的参数有一个`undefined`值。所以，我们这样做是为了确保即使在全局`undefined`对象被覆盖的情况下，我们也能在作用域中获得真实的`undefined`对象。

```js
Local References
(function ( window, undefined ) {
   "use strict";
  // module body
}( window ));
```

为了在模块的作用域外暴露模块元素，我们可以简单地返回一个对象。函数调用的结果可以赋值给外部变量，如下所示：

```js
Export
/** @module foo */
var foo = (function () {
  "use strict";
       /**
        * @private
        * @type String
        */
   var bar = "bar",
       /**
        * @type {Object}
        */
       foo = {
         /**
          * @public
          * @type {String}
          */
         baz: "baz",
         /**
          * @public
          * @returns {String}
          */
         qux: function() {
           return "qux";
         }
       };
   return foo;
}());

console.log( foo.baz ); // baz
console.log( foo.qux() ); // qux
```

## 增强

有时我们需要在模块中混合事物。例如，我们有一个提供核心功能的模块，我们希望根据使用上下文插入扩展。假设，我有一个基于伪类声明创建对象的模块。

基本上，在实例化时它自动继承自指定的对象并调用构造方法。在特定的应用程序中，我还希望这也验证对象接口是否符合给定的规范。所以，我在基础模块中插入了这个扩展。是如何做到的？我们将基础模块的引用传递给插件。将保留对原始模块的链接，因此我们可以在插件的作用域中修改它：

```js
/** @module foo */
var foo = (function () {
      "use strict";
           /**
            * @type {Object}
            */
         var foo = {
             /**
              * @public
              * @type {String}
              */
             baz: "baz"
           };
       return foo;
    }()),
    /** @module bar */
    bar = (function( foo ){
      "use strict";
      foo.qux = "qux";
    }( foo || {} ));

console.log( foo.baz ); // baz
console.log( foo.qux ); // qux
```

## 模块标准

我们已经回顾了实现模块的几种方法。然而，在实践中，我们更倾向于遵循一个标准化的 API。这些已经被一个庞大的社区证明，被实际世界的项目采用，并被其他开发者所认可。我们需要牢记的两个最重要的标准是**AMD**和**CommonJS 1.1**，现在我们更愿意看看 ES6 模块 API，这将是下一件大事。

CommonJS 1.1 以同步方式加载模块。模块体在第一次加载后执行一次，导出的对象被缓存。它为服务器端 JavaScript 设计，主要用于 Node.js/Io.js。

AMD 以异步方式加载模块。模块体在第一次加载后执行一次，导出的对象也被缓存。这为浏览器使用而设计。AMD 需要一个脚本加载器。最受欢迎的有 RequireJS、curl、lsjs 和 Dojo。

很快，我们可以期待脚本引擎获得对 JavaScript 内置模块的原生支持。ES6 模块结合了两者的优点。与 CommonJS 类似，它们有紧凑的语法和支持循环依赖，与 AMD 类似，模块异步加载，加载可配置。

# 如何在浏览器中使用异步模块

为了掌握 AMD，我们将做一些例子。我们将需要脚本加载器 RequireJS([`requirejs.org/docs/download.html`](http://requirejs.org/docs/download.html)).所以你可以下载它，然后在 HTML 中指定本地版本，或者给它一个外部链接到 CDN。

首先，让我们看看我们如何创建一个模块并请求它。我们把模块放在`foo.js`文件里。我们使用`define()`调用声明模块作用域。如果我们传递一个对象给这个调用，对象简单地被导出：

**foo.js**

```js
define({
  bar: "bar",
  baz: "baz"
});
```

当我们传递一个函数时，它被调用，其返回值被导出：

**foo.js**

```js
define(function () {
  "use strict";
  // Construction
  return {
    bar: "bar",
    baz: "baz"
  };
});
```

在`foo.js`旁边放置`main.js`。这段代码可以如下描述：当第一个参数（这里只有`foo`，即`./foo.js`）提供的所有模块都被加载并可用时，调用给定的回调。

**main.js**

```js
require( [ "foo" ], function( foo ) {
  "use strict";
  document.writeln( foo.bar );
  document.writeln( foo.baz );
});
```

从 HTML（`index.html`）开始，我们首先加载`RequireJS`，然后是`main.js`：

**index.html**

```js
<script src="img/require.min.js"></script>
<script src="img/main.js" ></script>
```

当我们有一个加载器时，同步加载脚本感觉不对。然而，我们可以用仅有的脚本元素来实现，此外，还可以强制它异步加载：

**index.html**

```js
<script data-main="./main" async 
  src="img/require.min.js"></script>
```

使用`data-main`属性，我们告诉加载器首先加载哪个模块，无论何时模块准备就绪。当我们启动`index.html`时，我们将在`main.js`中导入的`foo`模块属性值。

`index.html`输出异步加载模块的导出内容：

![如何在浏览器中使用异步模块](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00002.jpeg)

现在我们处理更多的依赖关系。所以我们创建了`bar.js`和`baz.js`模块：

**bar.js**

```js
define({
  value: "bar"
});
```

**baz.js**

```js
define({
  value: "baz"
});
```

我们必须修改`foo.js`以访问这些模块：

**foo.js**

```js
define([ "./bar", "./baz" ], function ( bar, baz ) {
  "use strict";
  // Construction
  return {
    bar: bar.value,
    baz: baz.value
  };
});
```

正如您可能注意到的，`require`/`define`依赖列表由模块标识符组成。在我们的案例中，所有模块和 HTML 位于同一目录中。否则，我们需要根据相对路径构建标识符（可以省略`.js`文件扩展名）。如果您路径出错，RequireJS 无法解析依赖，它会发出`Error: Script error for:<module-id>`。这有很大帮助吗？您可以自己改进错误处理。传递给模块作用域回调的函数表达式接收一个异常对象作为参数。这个对象具有特殊属性，如`requireType`（一个包含错误类型的字符串，如`timeout`、`nodefine`、`scripterror`）和`requireModules`（受错误影响的模块 ID 数组）。

```js
require([ "unexisting-path/foo" ], function ( foo ) {
  "use strict";
  console.log( foo.bar );
  console.log( foo.baz );
}, function (err) {
  console.log( err.requireType );
  console.log( err.requireModules );
});
```

在一个良好的设计中，模块众多，并且分配给一个目录树。为了避免每次都进行相对路径计算，您可以一次性配置脚本加载器。因此，加载器将通过指定的别名知道如何找到依赖文件：

**main.js**

```js
require.config({
    paths: {
        foo: "../../module/foo"
    }
});
require( [ "foo" ], function( foo ) {
  "use strict";
  console.log( foo.bar );
  console.log( foo.baz );
});
```

这带来了一个好处。现在如果我们决定更改一个模块文件名，我们不需要修改每个需要它的其他模块。我们只需要更改配置：

**main.js**

```js
require.config({
  paths: {
    foo: "../../module/foo-v0_1_1"
  }
});
require( [ "foo" ], function( foo ) {
  "use strict";
  console.log( foo.bar );
  console.log( foo.baz );
});
```

通过配置，我们也可以解决远程模块。例如，这里我们引用 jQuery，但 RequireJS 从配置中知道模块的端点，因此，从 CDN 加载模块：

**require.config({**

```js
  paths: {
    jquery: "https://code.jquery.com/jquery-2.1.4.min.js"
  }
});

require([ "jquery" ], function ( $ ) {
  // use jQuery
});
```

## 优点和缺点

AMD 方法的优点之一是模块异步加载。这也意味着在部署时，我们不需要上传整个代码库，而只需上传一个模块。由于浏览器可以同时处理多个 HTTP 请求，这种方式可以提高性能。然而，这里有一个巨大的陷阱。并行加载几段代码确实很快。但是实际项目中的模块要多的多。使用目前仍占主导地位的 HTTP/1.1 协议，加载所有这些模块将需要很长时间。与新的 SPDY 和 HTTP/2 标准不同，HTTP/1.1 在下载页面时的并发性处理并不好，如果队列很长，这将导致头阻塞([`http2.github.io/faq/`](https://http2.github.io/faq/))。RequreJS 提供了一个工具([`requirejs.org/docs/optimization.html`](http://requirejs.org/docs/optimization.html))来合并多个模块。这样我们不需要加载每个单独的模块，而只需要几个包。一起打包的依赖关系是同步解析的。因此，可以说在一定程度上我们放弃了 AMD 的主要优点——异步加载。同时，我们仍然需要加载一个通常相当重的脚本加载器，并用`define()`回调包装每个模块。

从我的经验来看，我更倾向于建议你使用与 Common JS 模块同步编译的包，这些包可以在浏览器中使用。

# 如何在服务器上使用同步模块

以下示例需要 Node.js。使用预编译安装器在[`nodejs.org/download/`](https://nodejs.org/download/)安装 Node.js 只需几分钟，甚至通过包管理器在[`github.com/joyent/node/wiki/Installing-Node.js-via-package-manager`](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager)安装更快。

我们将从在模块中放入一个简单的逻辑开始：

**foo.js**

```js
console.log( "I'm running" );
```

现在我们可以调用模块：

**main.js**

```js
require( "./foo" );
```

为了运行示例，我们将打开控制台（在 Windows 上，你可以直接运行`CMD.EXE`，但我建议使用像 CMDER 这样的增强工具，可在[`cmder.net/`](http://cmder.net/)获得）。在控制台中，我们输入以下内容：

```js
node main.js

```

![如何在服务器上使用同步模块](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00003.jpeg)

按下*Enter*键后，控制台输出**I'm running**。所以当请求一个模块时，其主体代码被执行。但如果我们多次请求该模块呢？

**main.js**

```js
require( "./foo" );
require( "./foo" );
require( "./foo" );
```

结果是一样的。只输出了一次**I'm running**。这是因为模块主体代码只在模块首次请求时执行一次。导出的对象（可能由主体代码生成）被缓存，类似于单例：

**foo.js**

```js
var foo = new Date();
```

**main.js**

```js
var first = require( "./foo" ),
    second = require( "./foo" );

console.log( first === second ); // true
```

正如你可能会注意到的，与 AMD 不同，我们模块中不需要任何包装器。但它仍然与全局作用域隔离吗？

**foo.js**

```js
var foo = "foo";
```

**main.js**

```js
require( "./foo" );
console.log( typeof foo ); // undefined
```

模块作用域中定义的任何变量在作用域外不可用。然而，如果你真的希望在暴露的接口后面的模块变量之间共享任何东西，你可以通过一个全局对象来实现（Node.js 类似于浏览器中的 Windows 对象）。

那么关于导出有什么要注意的呢？CommonJS 更倾向于单个导出。我们将 `module.exports` 赋值为一个类型或值的引用，这将是所需函数的缓存返回。如果我们想要多个导出，我们只需导出一个对象：

**foo.js**

```js
// module logic
module.exports = {
  bar: "bar",
  baz: "baz"
};
```

**main.js**

```js
var foo = require("./foo");
console.log( foo.bar ); // bar
console.log( foo.baz ); // baz
```

以下是在 Node.js 中最常见的情况，导出一个对象构造函数：

**foo.js**

```js
var Foo = function(){
  this.bar = "bar";
}

module.exports = Foo;
```

因此，通过一个必需的调用，我们可以获得带有原型的构造函数，并可以创建实例：

**main.js**

```js
var Foo = require("./foo"),
    foo = new Foo();

console.log( foo.bar ); // bar
```

正如我们从 `main` 模块请求 `foo` 模块一样，我们也可以从其他模块请求：

**bar.js**

```js
// module logic
module.exports = "bar";
```

**baz.js**

```js
// module logic
module.exports = "baz";
```

**foo.js**

```js
// module logic
module.exports = {
  bar: require( "./bar" ),
  baz: require( "./baz" )
};
```

**main.js**

```js
var foo = require( "./foo" );
console.log( foo.bar ); // bar
console.log( foo.baz ); // baz
```

但是，如果 Node.js 遇到循环依赖呢？如果我们从被调用模块中请求回调用者，会发生什么？并没有什么戏剧性的事情发生。正如您可能记得的，模块代码只执行一次。所以，如果在 `main.js` 已经执行后，我们还是从 `foo.js` 请求 `main.js`，那么它的主体代码将不再被调用：

**foo.js**

```js
console.log("Runnnig foo.js");
require("./main");
```

**main.js**

```js
console.log("Runnnig main.js");
require("./foo");
```

当我们用 Node.js 运行 `main.js` 时，我们得到以下输出：

```js
Runnnig main.js
Runnnig foo.js
```

## 优点和缺点

CommonJS 拥有简洁而富有表现力的语法。它非常容易使用。单元测试通常编写成在命令行运行，最好是持续集成的一部分。一个设计良好的 CommonJS 模块是一个完美的测试单元，您可以直接从 Node.js 驱动的测试框架（例如，Mocha）中访问，完全脱离应用程序上下文。然而，CommonJS 暗示了同步加载，这不适合在浏览器中使用。如果我们想绕过这个限制，我们必须将模块源代码编译成一个脚本，内部解决模块依赖关系而不加载（参见 *"为浏览器使用编译 CommonJS"*）。

## UMD

如果你希望你的模块既能在浏览器中作为 AMD 使用，又能在服务器上作为 CommonJS 使用，有一个技巧（[`github.com/umdjs/umd`](https://github.com/umdjs/umd)）。通过添加一个包装函数，你可以根据运行时环境动态构建所需的格式的导出。

# JavaScript 的内置模块系统

嗯，AMD 和 CommonJS 都是社区标准，并不是语言规范的一部分。然而，随着 EcmaScript 第六版的推出，JavaScript 拥有了它自己的模块系统。目前，还没有浏览器支持这一特性，因此我们必须安装 Babel.js 编译器来处理例子。

由于 Node.js 已经随 NPM 分发（NPM 是 Node.js 的包管理器），我们现在可以运行以下命令：

```js
npm install babel -g

```

## 命名导出

现在我们可以像下面这样编写一个模块：

**foo.es6**

```js
export let bar = "bar";
export let baz = "baz";
```

在 ES6 中，我们可以导出多个元素。任何用关键字 export 声明的变量或函数都可以被导入：

**main.es6**

```js
import { bar, baz } from "./foo";
console.log( bar ); // bar
console.log( baz ); // baz
```

由于我们目前还没有在浏览器中支持 ES6 模块，我们将将它们转换为 CommonJS 或 AMD。在这里，Babel.js 帮助我们：

```js
babel --modules common *.es6 --out-dir .
```

通过这个命令，我们让 Babel.js 将当前目录下的所有 `*.es6` 文件翻译成 CommonJS 模块。因此，我们可以用 Node.js 运行派生的 `main.js` 模块：

```js
node main.js
```

![命名导出](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00004.jpeg)

同样，我们将 ES6 模块转换为 AMD：

```js
babel --modules amd *.es6 --out-dir .
```

**index.html**

```js
<script data-main="./main" 
  src="img/require.min.js"></script>
```

在前一个示例中，我们在导入语句中列出了我们的命名导出。我们也可以导入整个模块，并将命名导出作为属性引用：

**main.es6**

```js
import * as foo from "./foo"; 
console.log( foo.bar ); // bar
console.log( foo.baz ); // baz
```

## 默认导出

除了默认导出，我们还可以这样做。这是在 Node.js 中通常是如何进行导出的：

**foo.es6**

```js
export default function foo(){ return "foo"; }
```

**main.es6**

```js
import foo from "./foo";
console.log( foo() ); // foo
```

我们导出了一个函数，并在导入时带来了它。这也可以是一个类或一个对象。

在 AMD 中，我们将导出作为回调参数接收，而在 CommonJS 中，作为局部变量。尽管 ES6 没有导出值，但它导出了所谓的绑定（引用），这些引用是不可变的。您可以读取它们的值，但如果您尝试更改它们，您会得到一个类型错误。Babel.js 在编译时触发这个错误：

**foo.es6**

```js
export let bar = "bar";
export function setBar( val ) {
   bar = val;
};
```

**main.es6**

```js
import { bar, setBar } from "./foo";
console.log( bar ); // bar
setBar( "baz" );
console.log( bar ); // baz
bar = "qux"; // TypeError
```

## 模块加载器 API

除了在单独的规范中声明性语法([`github.com/whatwg/loader/`](https://github.com/whatwg/loader/))，ES6 还为我们提供了一个程序化 API。它允许我们以编程方式处理模块并配置模块加载：

```js
System.import( "./foo" ).then( foo => {
  console.log( foo );
})
.catch( err => {
  console.error( err );
});
```

与 Node.js 不同，由于 ES6 模块的声明性特性，需要在顶层引入和导出。所以，这不能是条件性的。然而，有了实用的加载器 API，我们可以采取其他方式：

```js
Promise.all([ "foo", "bar", "baz" ]
    .map( mod => System.import( mod ) )
  )
  .then(([ foo, bar, baz ]) => {
     console.log( foo, bar, baz );
  });
```

在这里，我们定义了一个回调函数，当三个指定的模块都加载完成后才会被调用。

## 结论

AMD 和 CommonJS 都是过渡性标准。一旦 JavaScript 内置模块系统在脚本引擎中获得更广泛的支持，我们实际上就不再需要它们了。ES6 模块异步加载，加载方式可以配置成类似于 AMD。它们还有紧凑且表达性强的语法，并支持类似于 CommonJS 的循环依赖。此外，ES 提供静态模块结构的声明性语法。这种结构可以被静态分析（静态检查、校验、优化等）。ES6 还提供了一个程序化加载器 API。因此，您可以配置模块如何加载以及如何条件性加载模块。另外，ES6 模块可以与宏和静态类型扩展。

虽然一切看起来都很明朗，但仍有一只苍蝇在瓶中。ES6 模块可以预先以同步方式加载（使用`<script type="module"></script>`），但通常会有异步加载，这让我们陷入了与 AMD 相同的陷阱中。HTTP/1.1 上的多次 HTTP 请求对用户响应时间产生了有害影响 ([`developer.yahoo.com/performance/rules.html`](https://developer.yahoo.com/performance/rules.html))。另一方面，SPDY 和 HTTP/2 允许每个 TCP 连接发送多个请求，得到了更广泛的支持，并最终会取代可疑的 HTTP/1.x。此外，W3C 正在制定一个名为*Web 上的打包*的标准 ([`w3ctag.github.io/packaging-on-the-web/`](https://w3ctag.github.io/packaging-on-the-web/))，描述了如何从 URL（哈希）接收归档文件（脚本）。因此，我们将能够将整个目录与模块一起打包成一个归档文件，部署它们，并以与将它们放在目录中相同的方式引用它们。

# 为浏览器环境转换 CommonJS

虽然 HTTP/2 和*Web 上的打包*还在路上，我们需要快速的模块化应用程序。如前所述，我们可以将应用程序代码划分为 CommonJS 模块，并将它们转换为供浏览器使用。最受欢迎的 CommonJS 转换器无疑是 Browserify ([`browserify.org`](http://browserify.org))。这个工具的最初任务是使 Node.js 模块可重用。他们在这一点上做得相当成功。这可能看起来像魔法，但你可以真正地在客户端使用`EventEmitter`和其他一些 Node.js 核心模块。然而，由于主要关注 Node.js 兼容性，该工具为 CommonJS 编译提供的选项太少。例如，如果你想进行依赖项配置，你必须使用一个插件。在实际项目中，你可能会最终使用多个插件，每个插件都有特定的配置语法。因此，总体设置变得过于复杂。相反，我们将在此处探讨另一个名为 CommonJS Compiler ([`github.com/dsheiko/cjsc`](https://github.com/dsheiko/cjsc))的工具。这是一个相当小的实用程序，旨在将 CommonJS 模块带入浏览器。这个工具非常容易配置和使用，这使得它成为一个很好的选择来阐述这个概念。

首先，我们安装`cjsc`：

```js
npm install cjsc -g

```

现在我们可以从*如何在服务器上同步模块*部分中取一个例子，并为浏览器环境转换它：

**bar.js**

```js
// module logic
module.exports = "bar";
```

**foo.js**

```js
// module logic
module.exports = {
  bar: require( "./bar" )};
```

**main.js**

```js
var foo = require( "./foo" );
document.writeln( foo.bar ); // bar
```

起点是`main.js`。因此，我们告诉`cjsc`将这个模块与所有必需的依赖递归地打包到`bundle.js`中：

```js
cjsc main.js -o bundle.js
```

![为浏览器环境转换 CommonJS](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00005.jpeg)

让我们来看看生成的文件。`cjsc`用`custom _require`替换了所有的`require`调用，并将其放在了开头的`_require`函数定义中。这个小技巧让你可以在像 NW.js 这样的 Node.js/Io.js 友好环境中运行编译后的代码，在那里`require`函数仍然需要用于本地包。每个模块都被一个提供模块相关对象（exports 和 modules）以及全局对象的函数作用域（`window`）所包裹。

```js
Compiled Code
_require.def( "main.js", function( _require, exports, module, global )
{
  var foo = _require( "foo.js" );
  console.log( foo.bar ); // bar
  console.log( foo.baz ); // baz
    return module;
  });
```

生成的代码是通用 JavaScript，我们肯定可以从 HTML 中对其进行定位：

**index.html**

```js
<script src="img/bundle.js"></script>
```

我们的源代码仍然是 CommonJS 模块。这意味着我们可以在基于 Node.js 的框架中直接访问它们进行单元测试。Mocha.js 测试的官方网站是[`mochajs.org/`](http://mochajs.org/)：

```js
var expect = require( "chai" ).expect;
describe( "Foo module", function(){
  it( "should bypass the export of bar", function(){
      var foo = require( "./foo" );
      expect( foo ).to.have.property( "bar" );
      expect( foo.bar ).to.eql( "bar" );
  });
});
```

`cjsc`有许多选项。但在实际项目中，每次构建都输入一个长命令行会令人厌烦且效率低下：

```js
cjsc main-module.js -o build.js  --source-map=build/*.map \
 --source-map-root=../src -M --banner="/*! pkg v.0.0.1 */"
```

我们使用像`Grunt`、`Gulp`、`Cake`和`Broccoli`这样的任务运行器的原因就在于此。目前最受欢迎的任务运行器是`Grunt`([`gruntjs.com`](http://gruntjs.com))，它拥有大量的插件可供选择（参见[`sixrevisions.com/web-development/grunt-vs-gulp/`](http://sixrevisions.com/web-development/grunt-vs-gulp/)上的 Grunt 与 Gulp 对比信息图）。因此，我们需要将`grunt`命令行界面全局安装：

```js
npm install -g grunt-cli

```

为了设置一个`Grunt`项目，我们需要两个配置文件，`package.json`([`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json))和`Gruntfile.js`文件。第一个包含有关运行`Grunt`任务的 NPM 包的元数据。第二个用于定义和配置任务。

我们可以从一个非常简洁的`package.json`开始，其中只包含一个任意项目名及其版本，采用语义版本控制([`semver.org/`](http://semver.org/))格式：

**package.json**

```js
{
  "name": "project-name",
  "version": "0.0.1"
}
```

现在我们可以安装所需 NPM 包：

```js
npm install --save-dev grunt
npm install --save-dev grunt-cjsc

```

这样我们就得到了一个本地的 Grunt 和一个 CommonJs 编译器的 Grunt 插件。特殊的`--save-dev`选项在`package.json`部分创建`devDependencies`（如果不存在），并将其填充为已安装的依赖项。例如，当我们从版本控制系统拉取项目源代码时，我们可以通过简单地运行`npm install`来恢复所有依赖项。

在`Gruntfile.js`中，我们必须加载已经安装的`grunt-cjsc`插件，并配置一个名为`cjsc`的任务。实际上，我们将需要至少两个目标，为这个任务提供不同的配置。第一个，`cjsc:debug`，运行`cjsc`以生成未压缩的代码，并提供源映射。第二个，`cjsc:build`，用于准备部署资产。所以我们得到了`bundle.js`中的压缩代码：

**Gruntfile.js**

```js
module.exports = function( grunt ) {
  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON( "package.json" ),
    cjsc: {
      // A target to generate uncompressed code with sources maps
      debug: {
        options: {
          sourceMap: "js/*.map",
          sourceMapRoot: "src/",
          minify: false
        },
        files: { "js/bundle.js": "js/src/main.js" }
      },
      // A target to build project for production
      build: {
        options: {
          minify: true,
          banner: "/*! <%= pkg.name %> - v<%= pkg.version %> - " +
          "<%= grunt.template.today(\"yyyy-mm-dd\") %> */"
        },
        files: { "js/bundle.js": "js/src/main.js" }
      }
    }
  });

  // Load the plugin that provides the task.
  grunt.loadNpmTasks( "grunt-cjsc" );

  // Make it default task
  grunt.registerTask( "default", [ "cjsc:build" ] );

};
```

从配置中，我们可以看到`cjsc`旨在将`js/src/main.js``transpile`成`js/bundle.js`。因此，我们可以将前面示例中的模块复制到`./js/src`。

现在，当一切准备就绪后，我们将运行一个任务。例如，请看以下内容：

```js
grunt cjsc:debug

```

![将 CommonJS 转译以供浏览器使用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00006.jpeg)

如前所述，我们可以使用 `cjsc` 配置依赖映射。我们只需在一个对象字面量中描述依赖项，该字面量可以作为 JSON 文件通过命令行界面提供给 `cjsc`，或注入到 Grunt 配置中：

```js
{
  "jquery": {
    "path": "./vendors/jQuery/jquery.js"
  },
  "underscore": {
    "globalProperty": "_"
  },
  "foo": {
    "path": "./vendors/3rdpartyLib/not-a-module.js",
    "exports": [ "notAModule" ],
    "imports": [ "jquery" ]
  }
}
```

在这里，我们声明了位于 `./vendors/jQuery/jqueiry.js` 的模块的 `jquery` 别名（快捷方式）。我们还说明了一个全局暴露的 `"_"`（Underscore.js）库必须被视为一个模块。最后，我们指定了第三方组件的路径、导出和导入。因此，我们得到了这个在应用（不干预其代码）中作为一个模块的 this，尽管它不是一个模块：

```js
cjsc main.js -o bundle.js --config=cjsc-conig.json
```

或者我们可以使用以下 Grunt 配置：

```js
 grunt.initConfig({
cjsc main.js -o bundle.js --config=cjsc-conig.json
Grunt configuration
 grunt.initConfig({
    cjsc: {
      build: {
        options: {
          minify: true,
          config: require( "fs" ).readFileSync( "./cjsc-conig.json" )
        }
      },
        files: { "js/bundle.js": "js/src/main.js" }
      }
  });
```

## 将 ES6 模块捆绑以实现同步加载

嗯，正如我们在*JavaScript 内置模块系统*部分提到的，ES6 模块将会取代 AMD 和 CommonJS 标准。而且，我们现在就可以写 ES6 代码并将其转译为 ES5。一旦支持 ES6 的脚本代理足够好，我们从理论上可以使用我们的代码。然而，性能呢？实际上，我们可以将 ES6 模块编译成 CommonJS 并然后用 `cjsc` 捆绑它们以供浏览器使用：

**foo.es6**

```js
export let bar = "bar";
export let baz = "baz";
```

**main.es6**

```js
import { bar, baz } from "./foo";
document.writeln( bar ); // bar
document.writeln( baz ); // baz
```

首先，我们将 ES6 编译成 CommonJS 模块：

```js
babel --modules common *.es6 --out-dir .

```

然后，我们将 CommonJS 模块捆绑成一个适合浏览器使用的脚本：

```js
cjsc main.js -o bundle.js -M

```

# 摘要

模块化编程是与面向对象编程紧密相关的一个概念，它鼓励我们为更好的可维护性来结构化代码。特别是，JavaScript 模块保护全局作用域免受污染，将应用程序代码分成多个文件，并允许重用应用程序组件。

目前大多数使用的两个模块 API 标准是 AMD 和 CommonJS。第一个是为浏览器使用而设计的，假设异步加载。第二个是同步的，适用于服务器端 JavaScript。然而，你应该知道 AMD 有的重大缺陷。一个细粒度的应用程序设计，拥有大量的通过 HTTP/1.1 的模块，可能会在应用程序性能方面造成灾难。这是最近将 CommonJS 模块转译为浏览器使用实践日益增多的主要原因。

这两个 API 都应被视为过渡性标准，因为即将到来的 ES6 模块标准旨在取代它们。目前，没有脚本引擎支持这一功能，但有一些转译器（例如，Babel.js）允许将 ES6 模块转译成 CommonJS 或 AMD。
