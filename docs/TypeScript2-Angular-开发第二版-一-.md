# TypeScript2 Angular 开发第二版（一）

> 原文：[`zh.annas-archive.org/md5/81C516831B5BF457C3508E2F3CF1895F`](https://zh.annas-archive.org/md5/81C516831B5BF457C3508E2F3CF1895F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

决定学习 Angular 可能会让人感到非常不知所措。这是因为编写 Angular 应用程序的事实方式是使用一种名为 TypeScript 的超集语言，这是一种相当新的语言。讽刺的是，TypeScript 通过提供严格类型（如 Java 等严格类型语言中所见）简化了编写 Angular 应用程序的方式，从而改善了我们编写的应用程序的预测行为。本书旨在通过解释 TypeScript 的核心概念，帮助初学者/中级 Angular 开发人员了解 TypeScript 或严格类型的基本概念。

# 本书涵盖内容

第一章《从松散类型到严格类型》讨论了 TypeScript 推出之前开发人员面临的问题，以及 TypeScript 解决了哪些问题。我们将通过讨论松散类型及其挑战，展示一些先前如何解决这些挑战的示例，以及为什么 TypeScript 是更好的选择。

第二章《开始使用 Typescript》概述了 TypeScript 的核心概念，并提供了如何设置一个纯 JavaScript 加 TypeScript 项目的实际示例。第一章中的所有松散类型示例将被重写为 TypeScript，以展示 TypeScript 的效率。

第三章《Typescript 本地类型和特性》深入探讨了内置的 TypeScript 严格类型，这些类型与现有的 JavaScript 松散类型相匹配。每种类型都将通过工作示例进行广泛讨论，展示应该如何使用以及应该如何工作。

第四章《使用 Angular 和 TypeScript 快速上手》讨论了 TypeScript 如何应用于 Angular。为此，需要借助 CLI 工具使 Angular 快速上手。在本章中，我们将讨论使 Angular 和 TypeScript 协同工作所需的条件。我们还将介绍在“Hello World”示例中可能找到的基本 Angular 概念。

第五章，*使用 TypeScript 创建高级自定义组件*，讨论了 Web 组件的概念以及 Angular 如何借助 TypeScript 构建 Web 组件。我们将看到如何使用类创建组件，如何使用 TypeScript 接口实现生命周期钩子，并使用 TypeScript 装饰器定义组件元数据。

第六章，*使用 TypeScript 进行组件组合*，讨论了 Angular 是基于组件的。它解释了组件是如何作为构建块组合在一起，以使一个完全功能的应用程序。我们将讨论使用示例和组件交互（数据传输和事件）对组件进行模块化组合。在这样做的过程中，我们将看到 TypeScript 如何用于让我们检查所有这些移动部分。

第七章，*使用类型服务分离关注点*，讨论了允许逻辑存在于组件中是不好的做法。在这种情况下，Angular 允许您通过服务提供 API 方法，这些组件可以使用。我们将讨论 TypeScript 如何帮助我们在这些 API 方法和组件之间创建合同（使用类型）。

第八章，*使用 TypeScript 改进表单和事件处理*，解释了 Angular 表单模块如何使我们能够使用 TypeScript 编写可预测的类型表单，这是从我们的应用程序用户收集数据的完美手段。我们还将看到如何使用类型化的 DOM 事件（例如，点击、鼠标悬停和按键）来响应用户交互。

第九章，*使用 TypeScript 编写模块、指令和管道*，讨论了 Angular 的次要构建模块以及它们如何最好地与 TypeScript 一起使用。您将学习如何在 Angular 中使用类型和装饰器构建自定义指令和管道。

第十章，*SPA 的客户端路由*，解释了单页应用程序（SPA），它是通过使用 JavaScript 而不是服务器来处理路由来构建的。我们将讨论如何使用 Angular 和 TypeScript，可以使用路由器模块仅使用单个服务器路由构建多个视图应用程序。

第十一章，*使用真实托管数据*，深入探讨了使用 Angular 的 HTTP 模块消耗 API 数据。您将学习如何直接从我们的 Angular 应用程序发出 HTTP 请求。从此请求中获取的数据可以由组件呈现。

第十二章，*测试和调试*，涵盖了对 Angular 构建块进行单元测试的推荐实践。这些包括组件、服务、路由等。

# 本书适合谁

本书中涵盖的示例可以在 Windows、Linux 或 macOS PC 上实现。您需要安装 Node 和 npm 来使用 TypeScript，以及一个体面的网络浏览器。

# 这本书适合谁

本书旨在通过解释 TypeScript 的核心概念，帮助初学者/中级 Angular 开发人员了解 TypeScript 或严格类型的知识很少或根本没有的人。对于已经使用过 Angular 1.x 或其他框架并试图转移到 Angular 2.x 的开发人员来说，这也是一本完美的书籍。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以通过使用`include`指令来包含其他上下文。"

代码块设置如下：

```ts
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```ts
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都将按以下方式编写：

```ts
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
/etc/asterisk/cdr_mysql.conf
```

**新术语**和**重要单词**以粗体显示。屏幕上显示的单词，比如菜单或对话框中的单词，会以这种方式出现在文本中："点击“下一步”按钮会将您移动到下一个屏幕。"

警告或重要说明会以这样的框出现。

提示和技巧会以这种方式出现。


# 第一章：从松散类型到严格类型

*JavaScript 是松散类型的。*值得重复一下，*JavaScript 是松散类型的。*注意句子是被动的——我们不能绝对地责怪某人对 JavaScript 的松散类型本质，就像我们不能对 JavaScript 的其他著名故障负责一样。

对松散类型和松散类型语言的详细讨论将有助于理解我们计划用本书解决的问题。

当编程语言是松散类型时，意味着通过变量、函数或适用于语言的任何成员传递的数据*没有*定义的类型。可以声明变量*x*，但它持有的数据类型从未确定。松散类型的语言与强类型的语言相反，后者要求每个声明的成员必须严格定义它可以持有的数据类型。

这些类型被分类为：

+   字符串

+   数字（整数、浮点数等）

+   数据结构（数组、列表、对象、映射等）

+   布尔值（true 和 false）

JavaScript、PHP、Perl、Ruby 等都是松散类型的语言。Java、C、C#是强类型语言的例子。

在松散类型的语言中，一个成员最初可以被定义为字符串。在后续过程中，这个成员可能最终存储一个数字、一个布尔值，甚至一个数据结构。这种不稳定性导致了松散类型语言的含义。

# 术语定义

在继续之前，定义一下您可能在理解松散和严格类型的过程中遇到或将要遇到的常见行话会很有帮助：

+   **成员**：这些是描述数据如何存储和操作的语言特性。变量、函数、属性、类、接口等都是语言可能具有的成员的示例。

+   **声明与定义与赋值**：当一个变量被初始化而没有值时，它被称为*声明*。当它被声明并具有类型时，它被称为*定义*。当变量有一个值，无论是否有类型，它被*赋值*。

+   **类型**：这些用于根据它们被解析和操作的方式对数据进行分类。例如，数字、字符串、布尔值、数组等。

+   **值**：分配给给定成员的数据称为成员的值。

# 松散类型的含义

让我们从一个例子开始，展示松散类型语言的行为方式：

```ts
// Code 1.1

// Declare a variable and assign a value
var x = "Hello";

// Down the line
// you might have forgotten 
// about the original value of x
//
//
// Re-assign the value
x = 1;

// Log value
console.log(x); // 1
```

变量`x`最初被声明并赋予一个字符串值`Hello`。然后`x`被重新赋值为一个数值`1`。一切都没问题；代码被解释执行，当我们将值记录到控制台时，它记录了`x`的最新值，即`1`。

这不仅仅是一个字符串-数字的问题；同样的情况也适用于每一种类型，包括复杂的数据结构：

```ts
// Code 1.2

var isCompleted;

// Assign null
isCompleted = null;
console.log('When null:', isCompleted);

// Re-assign a boolean
isCompleted = false;
console.log('When boolean:', isCompleted);

// Re-assign a string
isCompleted = 'Not Yet!';
console.log('When string:', isCompleted);

// Re-assign a number
isCompleted = 0;
console.log('When number:', isCompleted);

// Re-assign an array
isCompleted = [false, true, 0];
console.log('When array:', isCompleted);

// Re-assign an object
isCompleted = {status: true, done: "no"};
console.log('When object:', isCompleted);

/**
* CONSOLE:
*
* When null: null
* When boolean: false
* When string: Not Yet!
* When number: 0
* When array: [ false, true, 0 ]
* When object: { status: true, done: 'no' }
*/
```

这里需要注意的重要事情不是*值*的变化。而是*类型*的变化。类型的改变不会影响执行。一切都运行正常，我们在控制台中得到了预期的结果。

函数参数和返回类型也不例外。您可以有一个接受字符串参数的函数签名，但是当您或任何其他开发人员在调用函数时传递数字时，JavaScript 将保持沉默：

```ts
function greetUser( username ) {
 return `Hi, ${username}`
}

console.log('Greet a user string: ', greetUser('Codebeast'))
console.log('Greet a boolean: ', greetUser(true))
console.log('Greet a number: ', greetUser(1))

/**
 * CONSOLE:
 *
 * Greet a user string: Hi, Codebeast
 * Greet a boolean: Hi, true
 * Greet a number: Hi, 1
 */
```

如果您来自强类型背景，并且没有使用松散类型语言的经验，那么前面的例子一定会感到奇怪。这是因为在强类型语言中，很难改变特定成员（变量、函数等）的类型。

那么，需要注意的含义是什么？显而易见的含义是，松散类型的成员是不一致的。因此，它们的值类型可以改变，这是您作为开发人员需要注意的事情。这样做会面临一些挑战；让我们来谈谈它们。

# 问题

松散类型很棘手。乍一看，它们似乎很好，很灵活，可以随意更改类型，而不像其他强类型语言那样会出现解释器发出错误的情况。就像任何其他形式的自由一样，这种自由也是有代价的。

主要问题是不一致性。很容易忘记成员的原始类型。这可能导致您处理一个字符串，就好像它仍然是一个字符串，而其值现在是布尔值。让我们看一个例子：

```ts
function greetUser( username ) {
 // Reverse the username
 var reversed = username.split('').reverse().join('');
 return `Hi, ${reversed}`
}

console.log('Greet a correct user: ', greetUser('Codebeast'))

 * CONSOLE:
 *
 * Greet a correct user: Hi, tsaebedoC
 */
```

在前面的例子中，我们有一个根据用户用户名向他们打招呼的函数。在打招呼之前，它首先颠倒用户名。我们可以通过传递用户名字符串来调用该函数。

当我们传递一个布尔值或其他没有`split`方法的类型时会发生什么？让我们来看看：

```ts
// Code 1.4

function greetUser( username ) {
 var reversed = username.split('').reverse().join('');
 return `Hi, ${reversed}`
}

console.log('Greet a correct user: ', greetUser('Codebeast'))

// Pass in a value that doesn't support
// the split method
console.log('Greet a boolean: ',greetUser(true))

 * CONSOLE:
 *
 * Greet a correct user: Hi, tsaebedoC
 * /$Path/Examples/chapter1/1.4.js:2
 * var reversed = username.split('').reverse().join('');
 ^
 * TypeError: username.split is not a function
 */
```

第一条日志输出，打印出一个字符串的问候语，效果很好。但第二次尝试失败了，因为我们传入了一个布尔值。就像 JavaScript 中的*一切*都是对象一样，布尔值没有`split`方法。下面的图片显示了前面示例的清晰输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/a942f086-3e4c-43e5-abca-0f09ed2fec74.jpg)

是的，您可能会认为您是这段代码的作者；为什么在设计函数接收字符串时会传入布尔值？请记住，我们一生中编写的大部分代码都不是由我们维护的，而是由我们的同事维护的。

当另一个开发人员接手`greetUser`并决定将该函数作为 API 使用而不深入挖掘代码源或文档时，他/她很可能不会传入正确的值类型。这是因为*他/她是盲目的*。没有任何东西告诉他/她什么是正确的，什么是错误的。甚至函数的名称也不足以让她传入一个字符串。

JavaScript 发展了。这种演变不仅在内部体验到，而且在其庞大的社区中也有所体现。社区提出了解决 JavaScript 松散类型特性挑战的最佳实践。

# 缓解松散类型问题

JavaScript 没有任何明显的本地解决方案来解决松散类型带来的问题。相反，我们可以使用 JavaScript 的条件来进行各种形式的手动检查，以查看所讨论的值是否仍然是预期类型。

我们将看一些示例，手动检查以保持值类型的完整性。

在 JavaScript 中，*一切都是对象*这句流行的说法并不完全正确（[`blog.simpleblend.net/is-everything-in-javascript-an-object/`](https://blog.simpleblend.net/is-everything-in-javascript-an-object/)）。有*对象*和*原始值*。字符串、数字、布尔值、null、undefined 都是原始值，但在计算过程中只被视为对象。这就是为什么你可以在字符串上调用`.trim()`之类的方法。对象、数组、日期和正则表达式是有效的对象。说对象是对象，这确实让人费解，但这就是 JavaScript。

# typeof 运算符

`typeof`运算符用于检查给定操作数的类型。您可以使用该运算符来控制松散类型的危害。让我们看一些例子：

```ts
// Code 1.5
function greetUser( username ) {
 if(typeof username !== 'string') {
 throw new Error('Invalid type passed');
 };
 var reversed = username.split('').reverse().join('');
 return `Hi, ${reversed}`
}

console.log('Greet a correct user: ', greetUser('Codebeast'))
console.log('Greet a boolean: ',greetUser(true))
```

我们不应该等待系统在传入无效类型时告诉我们错误，而是尽早捕获错误并抛出自定义和更友好的错误，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/2486fb07-13a0-43b5-acdc-5f21028a041b.jpg)

typeof 运算符返回一个表示值类型的字符串。typeof 运算符并不完美，只有在你确定它的工作方式时才应该使用。参见下面的问题：

```ts
function greetUser( user ) {
 if ( typeof user !== 'object' ) {
 throw new Error('Type is not an object');
 }
 return `Hi, ${user.name}`;
}

console.log('Greet a correct user: ', greetUser( {name: 'Codebeast', age: 24 } ))
// Greet a correct user: Hi, Codebeast

console.log('Greet a boolean: ', greetUser( [1, 2, 3] ))
// Greet a boolean: Hi, undefined
```

当第二次调用函数时，你可能期望会抛出错误。但是程序没有通过检查，并在意识到它是未定义之前执行了`user.name`。为什么它通过了这个检查？记住数组是一个对象。因此，我们需要更具体的东西来捕获检查。日期和正则表达式也可能通过了检查，尽管这可能不是本意。

# toString 方法

toString 方法是所有对象和包装对象（原始对象）原型继承的。当你在它们上调用这个方法时，它会返回一个类型的字符串标记。看下面的例子：

```ts
Object.prototype.toString.call([]);  // [object Array]  Object.prototype.toString.call({});  // [object Object]  Object.prototype.toString.call('');  // [object String]  Object.prototype.toString.call(new  Date());  // [object Date]
// etc
```

现在你可以使用这个来检查类型，正如 Todd Motto 所示（[`toddmotto.com/understanding-javascript-types-and-reliable-type-checking/#true-object-types`](https://toddmotto.com/understanding-javascript-types-and-reliable-type-checking/#true-object-types)）：

```ts
var getType = function (elem) {
 return Object.prototype.toString.call(elem).slice(8, -1);
};
var isObject = function (elem) {
 return getType(elem) === 'Object';
};

// You can use the function
// to check types
if (isObject(person)) {
 person.getName();
}
```

前面的例子所做的是检查`toString`方法返回的字符串的一部分，以确定其类型。

# 最后说明

我们之前看到的例子对于简单的类型检查来说有些过度。如果 JavaScript 具有严格的类型特性，我们就不必经历这种压力。事实上，这一章可能根本就不存在。

想象一下 JavaScript 可以做到这一点：

```ts
function greet( username: string ) {
 return `Hi, ${username}`;
}
```

我们不必经历所有那些类型检查的痛苦，因为编译器（以及编辑器）在遇到类型不一致时会抛出错误。

这就是 TypeScript 发挥作用的地方。幸运的是，有了 TypeScript，我们可以编写类似于前面的代码，并将其转译为 JavaScript。

# 总结

在本书中，我们将讨论 TypeScript，不仅用于构建 JavaScript 应用程序，还用于构建 Angular 应用程序。Angular 是一个 JavaScript 框架；因此，除非通过 TypeScript 进行缓解，它将具有讨论的限制特性。

现在你知道手头的问题了，那就做好准备，让我们深入研究 Angular，并探讨 TypeScript 提供的可能解决方案。

目前为止，一切都很顺利！我们已经能够讨论以下关注点，以帮助我们继续前进：

+   理解松散类型

+   松散类型和严格类型之间的区别

+   松散类型编程语言的挑战，包括 JavaScript

+   减轻松散类型的影响


# 第二章：使用 TypeScript 入门

在上一章中，我们讨论了由于 JavaScript 语言的松散类型特性可能遇到的挑战。我们还看到了各种减轻这些挑战的尝试，但没有一种感觉自然。我们还介绍了 TypeScript 作为一种有助于的工具；本章将讨论 TypeScript 如何帮助我们。

TypeScript 的构建块和核心概念是关乎内心的事情，我们需要将它们视为这样。因此，通过实际示例，我们将讨论这些构建块，它们如何一起工作，以及如何将它们集成到您的工作流程中作为 JavaScript 开发人员。但首先，我们需要学习如何设置 TypeScript。

在本章中，我们将涵盖以下主题：

+   创建 TypeScript 环境

+   使用 TypeScript 构建工作示例

+   类型注解

+   ES6 和 TypeScript

# 设置 TypeScript

TypeScript 的设置取决于将要使用的上下文。这是因为只要为环境正确配置，就可以将其集成到任何 JavaScript 工具、库和框架中。现在，我们将专注于最简单和最基本的设置。

要开始使用 TypeScript，需要基本了解 Node 及其包管理器 npm。还需要从 Node 网站安装两者（[`nodejs.org/en/`](https://nodejs.org/en/)）。

安装了 Node 和 npm 后，可以使用命令行工具通过`npm`全局安装 TypeScript：

```ts
npm install -g typescript
```

如果在安装时出现权限警告，可以使用`sudo`命令：

```ts
sudo npm install -g typescript
```

如果安装顺利，将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/b6a24256-5cc2-4a09-802d-3fe013419191.png)

要确认 TypeScript 安装是否成功，可以检查已安装的版本。如果显示版本，则安装成功：

```ts
tsc -v
```

因此，您的计算机上的 TypeScript 实例将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/6be1f19f-0633-4e2e-8ba6-65321d3488d9.png)

# Hello World

TypeScript 文件的扩展名为`.ts`。该扩展名支持 JavaScript 和 TypeScript。这意味着可以在`.ts`文件中编写 JavaScript 代码而不需要 TypeScript。让我们看一个例子。

首先，创建一个带有以下最小引导标记的`index.html`文件：

```ts
<!-- Code 2.1.html -->
<html>
 <head>
 <title>Example 2.1: Hello World</title>
 <!-- Include Bootstrap and custom style -->
 <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
 <link rel="stylesheet" href="2.1.css">
 </head>
 <body>
 <div class="container">
 <div class="col-md-4 col-md-offset-4 main">
 <h3 class="messenger"></h3>
 </div>
 <div class="col-md-4 col-md-offset-4 main">
 <input type="text" class="form-control">
 <button class="button">Greet</button>
 </div>
 </div>
 <!-- Include JavaScript file -->
 <script src="2.1.js"></script>
 </body>
</html>
```

请注意，在结束标记之前添加的 JavaScript 文件*不是*一个`.ts`文件；相反，它是一个带有`.js`扩展名的熟悉的 JavaScript 文件。这并不意味着我们的逻辑将用 JavaScript 编写；事实上，它是一个名为`2.1.ts`的 TypeScript 文件：

```ts
// Code 2.1.ts
(function() {
 var button = document.querySelector('.button');
 var input = document.querySelector('.form-control');
 var messenger = document.querySelector('.messenger');

 button.addEventListener('click', handleButtonClick);

 function handleButtonClick() {
 if(input.value.length === 0) {
 alert('Please enter your name');
 return;
 }
 // Update messanger 
 messenger.innerHTML = 'Hello, ' + input.value;
 }
})();
```

有什么奇怪的地方吗？不，我不这么认为。我们仍然在谈论纯 JavaScript，只是它存在于一个 TypeScript 文件中。这展示了 TypeScript 如何支持纯 JavaScript。

请记住，我们在`index.html`文件中导入的是`2.1.js`，而不是`2.1.ts`。因此，现在是时候生成浏览器可以理解的输出了。这就是我们通过`npm`安装的 TypeScript 编译器派上用场的地方。要编译，进入您的工作目录并在命令行中运行以下命令：

```ts
tsc 2.1.ts
```

*忽略关于值属性的警告。我们很快就会解决这个问题。*

这将生成一个编译后的`2.1.js`文件。正如您可能已经猜到的那样，查看这两者并没有语法差异：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/77a5c5c6-a454-4377-9a43-630acc14f68c.png)

然后，您可以使用 Web 服务器提供生成的资产来提供您的网页。有很多选项可以帮助您完成这一点，但`serve`非常受欢迎和稳定（[`github.com/zeit/serve`](https://github.com/zeit/serve)）。要安装`serve`，运行以下命令：

```ts
npm install -g serve
```

现在，您可以直接使用以下内容托管您的`index`文件：

```ts
serve --port 5000
```

使用`npm`脚本，您可以同时运行这两个命令。首先，初始化`package.json`：

```ts
npm init -y
```

现在，将以下脚本添加到 JSON 中：

```ts
"scripts": {"start": "tsc 2.1.ts -w & serve --port 5000"},
```

我们传入了`-w`选项，因此 TypeScript 可以在`.ts`文件中检测到更改时重新编译。

这就是我们的示例的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/b6fd864a-d2cc-4cce-8012-66d931cb0814.png)

# TypeScript 中的类型注释

值得再次提到的是，在我们刚刚看到的`Hello World`示例中，没有任何不同之处。让我们使用一些特定于 TypeScript 的功能，其中之一就是类型。类型是 TypeScript 存在的原因，除了类型之外的每个功能都只是语法糖。

我们不会详细讨论类型，因为第三章，*Typescript 原生类型和访问器*，涵盖了这一点。我们可以讨论的是类型注释，这是 TypeScript 用来对成员应用严格类型的机制。注释是通过在成员初始化后跟着一个冒号（`:`）和类型（例如，`string`）来实现的，如下所示：

```ts
var firstName: string;
```

让我们看一些带注释的示例：

```ts
var name: string = 'John';
console.log(name); // John

var age: number = 18;
console.log(age); // 18

var siblings: string[] = ['Lisa', 'Anna', 'Wili'];
console.log(siblings); // ['Lisa', 'Anna', 'Wili']

// OR

var siblings: Array<string> = ['Lisa', 'Anna', 'Wili'];
console.log(siblings); // ['Lisa', 'Anna', 'Wili']

// any type supports all other types
// and useful for objects when we are lazy
// to make types with interfaces/class for them

var attributes: any = {legs: 2, hands: 2, happy: true}
```

不仅基本类型，对象、数组和函数也可以被类型化。我们很快就会看到。

我们可以重写之前的`Hello World`例子，以便用类型注释来注释变量和函数。

再看一下这张图片：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/ce477b33-7933-4a1b-b184-65e3607fc256.png)

在 TypeScript 部分（右侧），`value`似乎没有被编辑器识别为 DOM 的属性，因此出现了错误行。但等等，这还是你一直在写的老 JavaScript。这里有什么问题吗？

TypeScript 自带了 DOM 的定义类型。这意味着当我们尝试访问在相应的 DOM 接口中未定义的属性时，它会抛出错误（接口的更多内容稍后再说）。DOM 查询方法`querySelector`以及其他查询方法返回的是`Element`类型（如果没有注释的话会被推断出来）。`Element`类型是基本的，包含有关 DOM 的通用信息，这意味着从`Element`派生的属性和方法将不会被看到。

这不仅在 TypeScript 中有意义，在其他面向对象的语言中也是如此：

```ts
class Base {
 name: string = 'John'
}

class Derived extends Base {
 gender: string = 'male'
}

(new Base()).name // John
(new Base()).gender // throws an error
```

回到我们的例子，让我们看看如何使用注释和转换来解决这个问题：

```ts
// Code 2.2.ts
(function() {
 // 1\. Button type is Element
 var button: Element = document.querySelector('.button');
 // 2\. Input type is HTMLInputElement and we cast accordingly
 var input: HTMLInputElement = <HTMLInputElement>document.querySelector('.form-control');
 // 3\. Messanger is HTMLElement and we cast accordingly
 var messenger: HTMLElement = document.querySelector('.messenger') as HTMLElement;

 // 4\. The handler now takes a function and returns another function (callback)
 button.addEventListener('click', handleButtonClick('Hello,', 'Please enter your name'));

 function handleButtonClick(prefix, noNameErrMsg) {
 // Logic here
 // Should return a function 
 }
})()
```

没有行为上的改变，只是提高了生产力。让我们讨论一下发生了什么：

1.  按钮元素是`Element`类型。这里没有什么特别的，因为 TypeScript 已经内部推断出来了。

1.  输入元素是`HTMLInputElement`类型。因为 TypeScript 将返回值推断为`Element`，所以我们必须将其转换为正确的类型，即`HTMLInputElement`。这是通过在返回值前加上`<>`并传递我们想要转换的接口来完成的。

1.  信使元素是`HTMLElement`类型。我们仍然需要使用相同的原因进行转换，就像在*步骤 2*中看到的那样，但使用了不同的支持语法（`as`）。`HTMLElement`是`Element`的子类型，包括更具体的 DOM 属性/方法（如`innerText`）。

1.  我们不是直接传递回调函数，而是将其包装在一个函数中，这样我们就可以接收参数。

让我们看一下传递给`addEventListener`的方法：

```ts
// Code 2.2.ts
function handleButtonClick(prefix, noNameErrMsg) {
 return function() {
 if(input.value.length === 0) {
 if(typeof noNameErrMsg !== 'string') {
 alert('Something went wrong, and no valid error msg was provided')
 return;
 }
 alert(noNameErrMsg);
 return;
 }

 if(typeof prefix !== 'string') {
 alert('Improper types for prefix or error msg')
 }

 messenger.innerHTML = prefix + input.value;

 }
```

我们添加了很多验证逻辑，只是为了确保我们从参数中得到了正确的类型。我们可以通过使用 TypeScript 注释来简化这个过程：

```ts
// Code 2.3.ts
function handleButtonClick(prefix: string, noNameErrMsg: string) {
 return function(e: MouseEvent) {
 if(input.value.length === 0) {
 alert(noNameErrMsg);
 return;
 }

 messenger.innerHTML = prefix + input.value;

 }
}
```

这样好多了，对吧？类型检查已经处理了不必要的检查。事实上，在传递到浏览器之前，如果你的编辑器（例如 VS Code）支持 TypeScript，当使用无效类型调用方法时，你会得到语法错误。

类型注解帮助我们编写更简洁、更易理解和无 bug 的应用程序。TypeScript 使注解灵活；因此，你不必严格为逻辑中的每个成员提供类型。你可以自由地注解你认为必要的内容，从什么都不注解到全部注解；只需记住，你的注解越严格，你在浏览器中需要做的调试就越少。

# ES6 及更高版本

除了类型注解，TypeScript 还支持 EcamaScript 6（ES6/ES2015）以及其他有用的功能，如枚举、装饰器、可访问级别（private、public 和 protected）、接口、泛型等等

我们将在下一章深入了解一些功能。在那之前，让我们先尝试另一个例子，其中包括一些 ES6 和 TypeScript 特定的功能。我们将构建一个计数器应用程序。这只是一个让你对这些功能感到兴奋的尝试，你将看到 TypeScript 如何带来你一直希望存在于 JavaScript 中的功能。

让我们从一个基本的 HTML 模板开始：

```ts
<!-- Code 2.4.html -->
<div class="container">
 <div class="col-md-6 col-md-offset-3 main">
 <div class="row">
 <div class="col-md-4">
 <button id="decBtn">Decrement--</button>
 </div>
 <div class="col-md-4 text-center" id="counter">0</div>
 <div class="col-md-4">
 <button id="incBtn">Inccrement++</button>
 </div>
 </div>
 </div>
</div>
```

# 用户故事

*用户预期从按钮点击中增加或减少计数器*，基本上，一个初始化为`0`的计数器，一个增加按钮以增加`1`，一个减少按钮以减少`1`。

我们可以将 DOM 操作和事件逻辑组织成类，而不是在代码中到处散落。毕竟，这就是类存在的原因：

```ts
// Code 2.4.ts
class DOM {
 private _incBtn: HTMLElement;
 private _decBtn: HTMLElement;
 private _counter: HTMLElement;

 constructor() {
 this._incBtn = this._getDOMElement('#incBtn');
 this._decBtn = this._getDOMElement('#decBtn');
 this._counter = this._getDOMElement('#counter');
 }

 public _getDOMElement (selector: string) : HTMLElement {
 return document.querySelector(selector) as HTMLElement;
 }

 get incBtn(): HTMLElement {
 return this._incBtn;
 }

 get decBtn(): HTMLElement {
 return this._decBtn;
 }

 get counter(): number {
 return parseInt(this._counter.innerText);
 }

 set counter(value: number) {
 this._counter.innerText = value.toString();
 }
}
```

这就是 JavaScript 看起来像一个结构化语言。让我们花点时间解释一下正在发生的事情：

+   首先，我们创建一个类并声明一些私有属性来保存 HTML DOM 元素的临时状态。像`private`这样的可见性特性只在 TypeScript 中特有，但类在 ES6 中已经存在了。

+   构造函数使用了`_getDOMElement`私有实用方法来查询 DOM 并初始化私有属性的值。

+   `incBtn`和`decBtn`的 getter 用于将这些私有属性的值公开。这是面向对象编程中的常见模式。Getter 被归类为访问器，并在 ES6 中可用。

+   计数器访问器用于通过将它们转换为整数和字符串来设置和检索计数器文本的值。

您第一次尝试运行此应用程序应该会抛出错误，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/96f14b4a-7ccc-4e40-a464-f13f7b922968.png)

这是因为 TypeScript 默认编译为 ES3，但在 ES3 中不支持 getter 和 setter（访问器）。要消除此错误，您可以告诉 TypeScript 编译器您更喜欢 ES5 而不是 ES3：

```ts
"start": "tsc 2.4.ts -w -t es5 & serve --port 5000"
```

`-t`标志，`--target`的别名，告诉 TypeScript 要编译到哪个版本。

`DOMEvent`类要简单得多--只有一个方法在调用时注册所有类型的事件：

```ts
// Code 2.4.ts
class DOMEvents {
 private register(htmlElement: HTMLElement, type:string, callback: (e: Event) => void): void {
 htmlElement.addEventListener(type, callback)
 }
}
```

该方法接受以下内容：

+   要监听事件的元素

+   事件类型（例如`click`，`mouseover`和`dblclick`）作为字符串

+   一个回调方法，返回`void`，但被传递给事件负载

然后该方法使用`addEventListener`注册事件。

最后，我们需要一个示例的入口点。这也将是一个类的形式，该类将依赖于`DOM`和`DOMEvent`类的实例：

```ts
// Code 2.4.ts
class App {
 constructor(public dom:DOM, public domEvents: DOMEvents) {
 this.setupEvents()
 }
 private setupEvents() {
 const buttons = [this.dom.incBtn, this.dom.decBtn];
 buttons.forEach(button => {
 this.domEvents.register(button, 'click', this.handleClicks.bind(this))
 })
 }
 private handleClicks(e: MouseEvent): void {
 const {id} = <HTMLElement>e.target;
 if(id === 'incBtn') {
 this.incrementCounter();
 } else {
 this.decrementCounter();
 }
 }

 private incrementCounter() {
 this.dom.counter++
 }

 private decrementCounter () {
 this.dom.counter--
 }
}
```

让我们讨论前面代码片段的工作原理：

+   构造函数在类初始化时被调用，尝试使用`setupEvents`方法设置事件。

+   `setupEvents`方法遍历 DOM 上的按钮列表，并在每个按钮上调用`DOMEvents register`方法

+   `register`方法作为`HTMLElement`传递给按钮，`click`作为事件类型，`handleClicks`作为事件处理程序。处理程序与正确的上下文`this`绑定。这在 JavaScript 中总是令人困惑；Yehuda Katz 已经以简单的方式解释了它的工作原理，网址为[`yehudakatz.com/2011/08/11/understanding-javascript-function-invocation-and-this/`](http://yehudakatz.com/2011/08/11/understanding-javascript-function-invocation-and-this/)。

+   回调方法根据被点击的按钮的 ID 调用`incrementCounter`或`decrementCounter`。这些方法分别从计数器中加 1 或减 1。

您可以通过创建`App`的实例来初始化应用程序：

```ts
// Code 2.4.ts
(new App(new DOM, new DOMEvents))
```

该图显示了我们新建的时髦计数器应用程序：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/e90ced32-94ab-4ba2-885a-f55901e53335.png)

# 最后说明

重要的是再次指出我们在这些示例中使用的很酷的功能：

+   类

+   访问器

+   可见性

+   箭头函数（回调）：

```ts
var fooFunc = (arg1) => {
 return arg1
}
```

+   `const`关键字用于变量声明，而不是`var`

+   解构：

```ts
const {id} = <HTMLElement>e.target;
```

# 摘要

其中一些功能在 JavaScript 环境中是原生可用的；TypeScript 在此基础上进行了扩展，为开发人员提供更好的体验。这就是为什么它被称为 JavaScript 的超集。

在下一章中，我们将回顾和描述这些功能，并举更多例子让你熟悉工作流程。


# 第三章：Typescript 本机类型和特性

您已经看到了使用 TypeScript 的不同示例。希望现在您知道 TypeScript 作为开发人员可以为您提供什么。在开始使用它构建 Angular 2 应用程序之前，还有一些 TypeScript 核心概念需要学习。本章将涵盖以下 TypeScript 概念：

+   基本类型，如字符串、数字、布尔、数组、void 等

+   函数类型

+   接口

+   装饰器

# 基本类型

让我们重新讨论基本类型。我们将讨论的大多数类型对您来说都很熟悉，但是通过复习会更好地欣赏 TypeScript 提供了什么。另一方面，一些类型在 JavaScript 中不可用，但是在 TypeScript 中是特定的。

# 字符串

字符串在 JavaScript 和 TypeScript 中都可用。它们用于表示文本数据。这些数据在程序中显示为字符串文字。这些文字在大多数编程语言中很容易识别，因为用双引号(`""`)括起来。在 JavaScript（和 TypeScript）中，这些文字用双引号(`""`)和单引号(`''`)表示：

```ts
let text: string = "Hi, I am a string. Now you know!";
```

在上面的片段中，`text`变量存储了这个字符串：`"Hi, I am a string. Now you know!"`。因为 TypeScript 支持 JavaScript 的最新特性，你可以使用新的 ES6 模板文字：

```ts
const outro: string = 'Now you know!';

let text: string = `Hi, I am not just a simple string.
 I am actually a paragraph. ${outro}`;
```

# 数字

数字在 JavaScript 和 TypeScript 中都可用。数字表示 JavaScript 中的浮点数。您可以直接用键盘输入它们，不需要像字符串那样进行任何装饰：

```ts
let whole: number = 6;
let decimal: number = 2.5; let hex: number = 0xf00d; let binary: number = 0b1010; let octal: number = 0o744;
```

# 布尔

布尔类型在 JavaScript 和 TypeScript 中都可用。布尔类型是您在编程语言中遇到的最简单的类型。它们用是或否回答问题，这在 JavaScript 中表示为`true`或`false`：

```ts
let isHappy: boolean = true;
let done: boolean = false;
```

# 数组

数组在 JavaScript 和 TypeScript 中都可用。JavaScript 中的数据结构基本上是用对象和数组表示的。对象是键值对，而数组具有可索引的结构。没有`array`类型，而是为数组中包含的项目提供类型。

您有两种选择。您可以使用`[]`符号对，如下所示：

```ts
let textArray: string[];

textArray = ["java", "kotlin", "typescript", "the rest..."]
```

或者，您可以使用内置的通用类型：

```ts
let numberArray: Array<number> = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
```

# Void

Void 仅在 TypeScript 中可用。`void`类型适用于函数的返回类型（我们很快会讨论这个）。Void 表示函数不会返回任何东西：

```ts
let sum: number = 20

// No return type function
function addToGlobalSum(numToAdd): void { 
 number + numToAdd }

addToGlobalSum(30) 
console.log(number) // 50
```

# Any

Any 仅在 TypeScript 中可用。`any`类型是最灵活的类型。当需要时，它允许您更接近 JavaScript 的松散性质。这种需求可能来自未经类型化的第三方库，如果您不知道属性或方法可能返回的值类型。

这种类型可以存储所有已知的 JavaScript 类型：

```ts
// Stores a string
let name: any = 'John Doe' 

// Stores a number
let age: any = 24

// Stores a boolean
let employed: any = true

// ...even data structures
let person: any[] =['John Doe', 24, true] 
```

# 元组

元组仅在 TypeScript 中可用。它们允许数组中有不同的类型。元组意味着在创建类型时必须定义数组中的固定元素数量。例如，如果我们需要一个包含`string`、`number`和`boolean`的数组，它将如下所示：

```ts
let flexibleArray: [string, number, boolean];

flexibleArray = ['John Doe', 24, true] 
```

当您尝试访问最初未创建的索引时，新索引将以适当的推断类型添加：

```ts
let anotherFlexArray: [string, number];

anotherFlexArray = ['John Doe', 24];

Assign true to index 2
anotherFlexArray[2] = true;

// anotherFlexArray becomes ['John Doe', 24, true]
```

# 枚举

枚举类型仅在 TypeScript 中可用。在某些情况下，您可能只想存储一组数字，无论是连续的还是不连续的。枚举为您提供了一个数值数据结构控制，而无需引入数组或对象的复杂性。

以下示例显示了一个`enum`类型，其中包含从`0`到`2`的数字：

```ts
enum Status {Started, InProgress, Completed}

let status:Status = Status.InProgress // 1
```

枚举是基于`0`的；因此，`Started`为`0`，`InProgress`为`1`，`Completed`为`2`。此外，枚举是灵活的；因此，您可以为起始点提供一个数字，而不是`0`：

```ts
enum Status {Started = 1, InProgress, Completed}

let status:Status = Status.InProgress // 2
```

使用枚举可以编写更具表现力的代码。让我们看看如何在前面示例中使用百分比值来表示状态：

```ts
enum Status {Started = 33, InProgress = 66, Completed = 100}

let status:Status = Status.InProgress + '% done' // 66% done
```

如果您知道实际值，那么很容易找到值的名称：

```ts
enum Status {Started = 33, InProgress = 66, Completed = 100}

let status:string = Status[66] // InProgress

```

# 函数和函数类型

JavaScript 函数是松散类型的，也是语言中最常见的错误来源之一。基本函数看起来像这样：

```ts
function stringToArray(char) {
 return char.split(' ')
}
```

我们有多大把握`char`不是一个数字？嗯，我们可能无法控制使用`stringToArray`的开发人员会传入什么。这就是为什么我们需要使用 TypeScript 严格控制值类型的原因。

函数在声明的两个不同部分使用类型：

1.  函数参数

1.  函数返回值

# 函数参数

您可以告诉 TypeScript 函数应该期望什么类型的值，并且它将严格遵守。以下示例显示了一个接收类型化字符串和数字作为参数的函数：

```ts
// Typed parameters
function stringIndex(char: string, index: number) {
 const arr = char.split(' ')
 return arr[number];
}
```

`char`和`index`参数分别具有`string`和`number`类型。甚至在事情到达浏览器之前，TypeScript 会在您尝试一些愚蠢的事情时提醒您：

```ts
function stringIndex(char: string, index: number) {
 const arr = char.split(' ')
 return arr[number];
}

stringIndex(true, 'silly') // Types don't match
```

当然，函数表达式也不会被忽视：

```ts
const stringIndex = function (char: string, index: number) {
 const arr = char.split(' ')
 return arr[number];
}
```

此外，箭头函数也是可以的：

```ts
const stringIndex = (char: string, index: number) => char.split(' ')[number];
```

# 函数返回值

执行函数时期望的值也可以是严格类型的：

```ts
function stringIndex(char: string, index: number): string {
 const arr = char.split(' ')
 return arr[number];
}
```

从前面的代码片段中可以看出，返回类型位于包含参数的括号之后，也位于函数体的左大括号之前。预期该函数将返回一个字符串。除了字符串之外的任何内容都会报错。

# 可选参数

当函数的参数是严格类型时，当函数需要灵活时，它会感到僵硬。在我们的先前示例中，为什么我们应该传入`index`，如果我们打算在索引丢失的情况下返回整个字符串？

当在调用函数时省略索引参数时，TypeScript 将抛出错误。为了解决这个问题，我们可以将`index`参数声明为可选的：

```ts
function stringIndex(char: string, index?: number): string {
 // Just return string as is
 // if index is not passed in
 if(!index) return char;
 // else, return the index 
 // that was passed in
 const arr = char.split(' ')
 return arr[number];
}
```

参数名称后面的问号告诉 TypeScript，当调用时参数丢失是可以的。要小心处理函数体中未提供参数的情况，如前面的示例所示。

# 接口

接口是我们的代码遵循的合同。这是数据结构必须遵循的协议。这有助于每个实现接口的数据/逻辑免受不当或不匹配类型的影响。它还验证了传入的值的类型和可用性。

在 TypeScript 中，接口用于以下目的：

1.  为 JavaScript 对象创建类型。

1.  为类设置遵循的合同。

我们将讨论接口在我们刚才列出的情景中的应用。

# JavaScript 对象类型的接口

我们同意以下是一个有效的 JavaScript 对象：

```ts
// Option bag
let options = {show: true, container: '#main'};
```

这是有效的 JavaScript 代码，但是松散类型的。一直以来，我们一直在讨论字符串、数字、布尔值，甚至数组。我们还没有考虑对象。

正如您可能已经想象的那样，以下代码片段演示了先前示例的类型化版本：

```ts
// Typed object
let options: {show: boolean, container: string};

// Assing values
options = {show: true, container: '#main'};
```

这是正确的，但实际上，TypeScript 可以使用接口使其更易于维护和理解。以下是我们在 TypeScript 中编写接口的方式：

```ts
interface OptionBag {
 show: boolean,
 container: string
}
```

然后，您可以将`options`变量设置为`OptionBag`类型：

```ts
// Typed object
let options: OptionBag = {show: true, container: '#main'};
```

# 可选属性

不过关于接口的一件事是，接口定义的属性/方法在创建使用该接口类型的值时必须提供。基本上，我是说我们必须严格遵守与接口建立的契约。

因此，以下是不正确的，会抛出错误：

```ts
interface OptionBag {
 show: boolean,
 container: string
}

let options: OptionBag = {show: true}; // Error
```

我们可以将`container`设置为可选的；我们使用问号字面量，就像之前的例子中看到的那样：

```ts
interface OptionBag {
 show: boolean,
 container?: string
}

let options: OptionBag = {show: true}; // No Error
```

不过要小心，要考虑当未提供可选参数时。以下是一个这样做的例子：

```ts
// Get element
function getContainerElement(options: OptionBag):HTMLElement {
 let containerElement: HTMLElement
 if(!options.container) {
 // container was not passed in
 containerElement = document.querySelector('body');
 } else {
 // container was passed in
 containerElement = document.querySelector(options.container);
 }

 return containerElement
}
```

# 只读属性

另一个典型的情况是当你有属性，你打算只赋值一次，就像我们用 ES6 的`const`声明关键字一样。你可以将这些值标记为`readonly`：

```ts
interface StaticSettings {
 readonly width: number,
 readonly height: number
}

// There are no problems here
let settings: StaticSettings = {width: 1500, height: 750}

// ...but this will throw an error
settings.width = 1000
// or
settings.height = 500
```

# 接口作为契约

您可以确保一个类遵循特定的契约，使用接口。我使用契约这个术语，意思是接口中定义的所有属性和方法必须在类中实现。

假设我们有以下`Note`接口：

```ts
interface Note {
 wordCount: number
}
```

要使用类来实现接口，我们在类名后面加上`implements`关键字，然后是我们要实现的接口：

```ts
class NoteTaker implements Note {
 // Implement wordCount from
 // Note interface
 wordCount: number;
 constructor(count: number) {
 this.wordCount = count
 }
}
```

接口不仅定义属性的签名，还接受函数类型作为方法：

```ts
interface Note {
 wordCount: number;
 updateCount(count: number): void
}
```

这可以通过类来实现：

```ts
class NoteTaker implements Note {
 // Implement wordCount from
 // Note interface
 wordCount: number;
 constructor(count: number) {
 this.wordCount = count
 }

 updateCount(count: number): void {
 wordCount += count
 }
}
```

如果`NoteTaker`类中既没有`wordCount`属性也没有`updateCount`方法，TypeScript 会抛出错误。

# 装饰器

在 Angular 2+中引入的最常见特性是**装饰器**。装饰器乍一看令人困惑，因为它们的使用前面有一个不寻常的`@`符号：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/f2d6b017-9e35-49d8-9d9e-85f6a967d310.png)

上面的截图是来自一个 Angular 应用的代码片段。它显示了一个组件装饰器装饰了一个名为`AppComponent`的类。

起初，这可能看起来令人不知所措，因为在 JavaScript 的历史上，我从未见过`@`字面量以这种方式使用。如果我们知道它只是一个可以访问所装饰内容的函数就好了！类、属性、方法和访问器都可以被装饰。让我们讨论如何装饰方法和类

# 装饰方法

假设我们想要让类上的一个方法只读。因此，在创建方法之后，它不能被任何原因覆盖。例如，方法看起来是这样的：

```ts
class Report {
 errPayload;

 // To become readonly
 error() {
 console.log(`The following error occured ${errPayload}`)
 }
}
```

如果我们不想在应用程序的生命周期中覆盖`error`，我们可以编写一个装饰器将描述符的`writable`属性设置为`false`：

```ts
function readonly(target, key, descriptor) {
 descriptor.writable = false;
 return descriptor
}
```

通用签名是方法装饰器接受与`Object.defineProperty`相同的参数。在这种情况下，目标将是类，键将是方法名，这是类的属性，描述符将是`config`对象。

现在我们可以用刚刚创建的`readonly`装饰器装饰`error`方法：

```ts
class Report {
 errPayload;

 // Decorated method 
 @readonly
 error() {
 console.log(`The following error occured ${errPayload}`)
 }
}
```

任何试图改变`error`属性的尝试都将失败：

```ts
const report = new Report()

// This would never work
// because 'error' is read only
report.error = function() {
 console.log('I won't even be called')
}
```

# 装饰类

另一个常常被装饰的成员是类。事实上，在 Angular 中，几乎所有的类（组件、服务、模块、过滤器和指令）都被装饰。这就是为什么理解装饰器的存在是如此重要的原因。

装饰器可用于扩展类的功能，如下例所示：

```ts
// decorator function
function config(target) {
 target.options = {
 id: '#main',
 show: true
 }
}

// class
@config
class App {}

// options added
console.log(App.options) // {id: '#main', show: true}
```

# 装饰器工厂

前面的例子是固定的，因为`options`对象将始终具有相同的值。如果我们需要接收动态值怎么办？当然，这是一个有效的问题，因为`id`属性可能并不总是`#main`。因此，我们需要更灵活一些。

装饰器工厂是返回装饰器的函数，使您能够通过其工厂传递参数给装饰器：

```ts
// decorator factory function
function config(options) {
 // decorator function
 return function(target) {
 target.options = options
 }
}

// class decorator
// with arguments
@config({id: '#main', show: true})
class App {}

// options added
console.log(App.options) // {id: '#main', show: true}
```

# 总结

在前三章中，我们花了时间讨论 TypeScript 的基础知识，目的是在接下来的章节中（其中充满了大量的 Angular 内容）中，TypeScript 将不再是你需要担心的东西。

可以假设基本类型、函数类型、装饰器和接口已经添加到您对 TypeScript 的现有知识中。

在本书的接下来的章节中，我们将深入学习 Angular。如果你已经走到了这一步，那么你已经度过了本书中枯燥的部分，因为从现在开始，我们将用 Angular 2+构建许多有趣的示例。


# 第四章：使用 Angular 和 TypeScript 快速上手

前几章旨在解释 TypeScript 的基本和最常见的特性。在开发 Angular 项目时，这些特性将被广泛使用。在构建 Angular 项目时，TypeScript 是完全可选的，但相信我，只使用 JavaScript 并不是你想要经历 TypeScript 简化开发过程后的选择。

本章介绍了本书中令人兴奋的部分--使用 TypeScript 构建 Angular 应用程序。本章将涵盖以下主题：

+   使用 TypeScript 设置 Angular

+   理解组件基础知识

+   学习关于 Angular 的模板语法

+   一些数据绑定魔法

所有这些令人兴奋的主题都将有很好的示例支持，这样你就可以亲自看到这些东西是如何工作的。让我们开始吧。

# 使用 Angular 和 TypeScript 设置

Angular 并不是一个难以入门的框架。不幸的是，从初学者的角度来看，生态系统可能会用大量术语压倒你。这些术语大多代表了使 Angular 工作的工具，而不是 Angular 本身。Webpack、linters、TypeScript、typings、构建过程等等，都是一些令人困惑的术语，可能会在你开始 Angular 之旅的时候让你望而却步。

因此，Angular 团队构建了一个全能工具，帮助你更少地关注周围的工具，而更多地关注构建你的项目。它被称为 Angular CLI，只需几个 CLI 命令，你就可以构建你的应用程序。如今花在管理 JavaScript 工具上的时间令人担忧，作为一个初学者（甚至是专业人士），你不想陷入那样的混乱中。

要安装 CLI，你需要用 npm 运行以下命令：

```ts
npm install -g @angular/cli
```

当安装完成时，你应该在控制台中看到以下 npm 日志：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/946e872d-eee7-4441-a0a9-c0d0f012e0f4.jpg)

你可以通过运行`help`或`version`命令来检查安装是否成功。

```ts
# Help command
ng help

# Version command
ng version
```

帮助命令将显示通过 CLI 工具可用的命令列表，而版本命令将显示当前安装的版本。如果安装不成功，这些命令都不会打印上述信息。

当你运行`help`命令时，以下是打印的日志详情：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/bf7247b9-de44-45a4-a0fb-de4de21b74de.jpg)

运行版本命令会显示以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/dc697db8-1ae7-48eb-bc71-868ff9c7c23f.jpg)

# 创建一个新的 Angular 项目

安装了 CLI 后，您现在可以在项目中开始使用它。当然，首先要做的是创建一个。CLI 的`new`命令只在项目中使用一次，用于生成项目需要的起始文件和配置：

```ts
ng new hello-angular
```

该命令不仅为您创建项目；它还安装了 npm 依赖项，因此您无需在开始之前运行安装命令：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/7ec491c8-5cfc-4cd4-891b-e99e4ad916ab.jpg)

直接导航到文件夹的根目录并运行`serve`命令：

```ts
ng serve
```

运行命令后，您将获得以下输出，显示您的应用程序成功运行的位置以及您可以访问它的位置。它还显示了捆绑文件，包括样式和脚本。请注意，这里没有 TypeScript 文件；一切都已转换为 JavaScript，以便浏览器理解：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/91490cf5-36b9-4f6b-9033-5a3761714509.png)

您应该在`localhost:4200`看到您闪亮的应用程序正在运行：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/95e887a3-3cac-4afb-bd2b-c0fa550a5de1.png)

# 项目结构

Angular 生成了许多辅助文件，以便测试、构建过程、包管理等。您可以成功构建一个项目，而不必关心这些文件的作用。因此，我们只会展示一些对我们开始很重要的文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/865e8674-9ca1-4184-9a15-976a45e428c3.png)

我们现在应该关注`src`目录。这就是我们的项目文件（组件、服务、模板等）将存放的地方。

# 生成文件

您可以手动添加更多的 TypeScript 文件和模板，但使用 CLI 工具更有效。这是因为 CLI 工具不仅创建文件，还生成了起始片段来表示您尝试创建的文件类型。例如，让我们创建一个引用组件：

```ts
ng generate component quote
# OR
ng g component quote
```

这就是组件命令的样子，其中包含一些生成的代码和文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/d676ed0c-a41f-42c2-93ce-3a4bc118c0a6.png)

该图包括以下内容：

1.  生成过程的 CLI 输出。

1.  生成的组件、模板、CSS 和测试文件。

1.  TypeScript 组件。

CLI 可以用来生成其他 Angular/TypeScript 构建模块，而不仅仅是组件。我们现在不会尝试它；我们将在后续章节中讨论时再这样做。以下表格是在项目的 Github 自述文件中看到的生成命令：

| **脚手架** | **用法** |
| --- | --- |
| 组件 | `ng g component my-new-component` |
| 指令 | `ng g directive my-new-directive` |
| 管道 | `ng g pipe my-new-pipe` |
| 服务 | `ng g service my-new-service` |
| 类 | `ng g class my-new-class` |
| 守卫 | `ng g guard my-new-guard` |
| 接口 | `ng g interface my-new-interface` |
| 枚举 | `ng g enum my-new-enum` |
| 模块 | `ng g module my-module` |

# 基本概念

我们将在本书中深入探讨不同的主题，但大致解释正在发生的事情是个好主意，以便有上下文。

# 组件

您的好奇心可能会导致您打开`app.component.ts`或`quote.component.ts`。如果它们看起来令人不知所措，不要担心；我们将在本书中广泛讨论组件（特别是在接下来的两章中）。

组件是任何 Angular 项目的核心。它们是核心构建模块，其他所有功能都只是为了支持组件。提到的文件包含用 TypeScript 编写的 Angular 组件。这就是`app.component.ts`的样子：

```ts
import { Component } from '@angular/core';  @Component({  
 selector: 'app-root',  
 templateUrl: './app.component.html',  
 styleUrls: ['./app.component.css']  })  export class AppComponent {  title = 'app';  }  
```

组件是带有模板的装饰类。装饰的类型很重要，在这种情况下是`Component`装饰器。从前一章中记得装饰器只是扩展它们装饰的功能的函数。这就是前面例子中发生的事情。

首先，我们从 Angular 的核心模块`@angular/core`中导入这个装饰器。然后我们将装饰器放在我们的`AppComponent`类的正上方。装饰器以一个 JavaScript 对象作为其参数来描述组件。该对象包含以下内容：

+   `selector`：这是组件在应用程序的任何部分中被调用时将被识别为的内容。因为这个组件是您的应用程序的入口点，它将直接在 body 中使用，包括其选择器：

```ts
<!--./src/index.html-->
...
<body>  
 <app-root></app-root>  </body>
...
```

+   `templateUrl`：组件将模板呈现到视图中。我们需要一种方法来告诉组件要呈现哪个模板。这可以通过`template`或`templateUrl`属性实现。`template`属性接受 HTML 内容的字符串，而`templateUrl`接受模板 HTML 文件的 URL。

+   `styleUrls`：这是应用于定义模板的样式 URL 的数组。

实际组件的类（并且正在被装饰）成为与该组件相关的属性和方法的主页。所有这些一起作为一个整体，以创建一个可重用的功能，称为组件。

引用组件看起来非常相似：

```ts
import { Component, OnInit } from '@angular/core';  @Component({  
 selector: 'app-quote',  
 templateUrl: './quote.component.html',  
 styleUrls: ['./quote.component.css']  })  export class QuoteComponent implements OnInit {   
 constructor() { }   
 ngOnInit() {  }  }  
```

唯一明显的区别是它实现了`OnInit`接口，该接口具有一个`ngOnInit`方法，该方法类必须实现。这个方法被称为生命周期钩子，我们很快会讨论它。

# 模板

模板只是常规的 HTML 文件，但通过插值和指令进行了增强。以下是`app.component.html`的当前内容，这是`AppComponent`的模板：

```ts
<div style="text-align:center">  
 <h1>  Welcome to {{title}}!!  </h1>  
 <img width="300" src="...">  </div>  <h2>Here are some links to help you start: </h2>  <ul>  
 <li>  <h2><a target="_blank" href="https://angular.io/tutorial">Tour of Heroes</a></h2>  </li>  
 <li>  <h2><a target="_blank" href="https://github.com/angular/angular-cli/wiki">CLI Documentation</a></h2>  </li>  
 <li>  <h2><a target="_blank" href="http://angularjs.blogspot.ca/">Angular blog</a></h2>  </li>  </ul>  
```

正如您所看到的，这只是普通的 HTML。不过有一件事可能看起来不太熟悉：

```ts
<h1>  Welcome to {{title}}!!  </h1>  
```

用双大括号括起来的`title`文本可能会让您感到困惑。这被称为插值。`title`值是根据组件类上的属性值在运行时解析的。不要忘记我们有一个值为`app`的 title 属性：

```ts
title = 'app';
```

除了像这样绑定值之外，您还可以在模板上执行许多令人惊奇的任务。它们包括以下内容：

+   属性和事件绑定

+   双向绑定

+   迭代和条件

+   样式和类绑定

+   简单表达式

+   管道和指令

与其向您提供与模板和模板语法相关的所有无聊的东西，我们应该讨论它们以及它们与其他即将到来的主题的关系。这样，您可以在示例中看到它们的实际应用，这应该更有趣。

# 组件样式

组件大量地展示了可重用性。实际上，这是您询问使用组件架构的好处时得到的第一个答案。这就是为什么模板和样式被限定在组件范围内，而不是用沉重的 HTML 和 CSS 来污染应用程序的环境的原因。

组件装饰器参数中的`styleUrls`属性接受一个指向要应用于组件的样式的 URL 数组。大多数情况下，您只需要一个文件；因此数组将只包含一个 URL 项，在我们的情况下是`app.component.css`。它目前是空的，但我们可以对其进行实验：

```ts
* {  
 background: red; }
```

`*`选择器应该选择文档中的所有内容。因此，我们说，*选择每个元素并将背景设置为红色*。您可能会对结果感到惊讶：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/772e08c8-0079-46f0-8d01-d142ef190006.png)

注意实际的 body 标签没有样式，这可能并不直观，因为您使用了全局选择器。组件样式被限定在组件内部；因此样式不能泄漏到包含父级。这就是为什么 body 保持为白色，而`AppComponent`模板中的内容为红色的原因。

# 模块

组件用于构建产品中的小型可重用功能。它们与服务、指令、管道等概念一起工作，以实现功能特性。在某些情况下，您可能希望将这些功能从一个项目移动到另一个项目，甚至在一个庞大的项目的不同部分之间移动。因此，您需要一种将它们收集在一起作为功能的方法。这正是模块所做的。

模块是用`NgModule`装饰器装饰的类。装饰器接受一个对象，就像组件装饰器一样。这个对象描述了你需要关联到这个模块的所有功能成员。可能的成员（但不是所有成员）如下：

+   **声明**: 这些包括组件、指令和管道

+   **提供者**: 这些包括可注入的服务

+   **导入**: 这些包括其他导入的模块

+   **引导**: 这是启动应用程序的入口组件

我们已经有一个模块，即`AppModule`：

```ts
import { BrowserModule } from '@angular/platform-browser';  import { NgModule } from '@angular/core';  import { AppComponent } from './app.component';  import { QuoteComponent } from './quote/quote.component';  @NgModule({  
 declarations: [  
 AppComponent,  
 QuoteComponent  
 ],  
 imports: [  
 BrowserModule  
 ],  
 providers: [],  
 bootstrap: [ 
 AppComponent 
 ]  })  export class AppModule { }  
```

让我们花点时间描述一下这个模块中的项目：

+   **声明**: `AppComponent`和`QuoteComponent`是组件。因此，它们属于这个类别。在生成引言组件后，Angular CLI 做的一件了不起的事情是自动将其添加到声明中。如果没有这样做，即使在应用程序的某个地方使用组件选择器，引言组件的内容仍然不会显示，并且您将在控制台中收到错误。

+   **导入**: `BrowserModule`是一个模块。它是一个包含常见浏览器任务的模块，特别是用于模板的指令，如`*ngFor`等。

+   **提供者**: 由于我们还没有任何服务，可以省略提供者，或者将数组留空。

+   **引导**: 应用程序模块是我们的入口模块。因此，它应该定义入口组件，即`AppComponent`。这就是`bootstrap`属性的作用。

# 单元测试

虽然我们不会在本书的最后一章之前涵盖测试，但养成测试的习惯是值得的。这就是为什么我们要在这里探索测试组件的简单性。

基本上，Angular 提供了一个测试组件的抽象层，借助`TestBed`。在你能看到你的组件是否按计划运行之前，你不需要运行整个应用程序。一个简单的测试已经与我们的应用组件的 CLI 脚手架捆绑在一起。它可以在文件旁边找到（这是一个常见且良好的做法），如`app.component.spec.ts`。

让我们查看这个文件的内容：

```ts
import { TestBed, async } from '@angular/core/testing';  import { AppComponent } from './app.component';  describe('AppComponent', () => {

});
```

首先，我们从`@angular/core/testing`导入测试工具和要测试的组件，即`AppComponent`。还创建了一个`describe`块，其中包含了给定功能（`AppComponent`）的测试套件集，但是为空的。

在开始编写测试套件之前，我们需要为组件配置一个临时测试模块。这是在`beforeEach`块中完成的：

```ts
//...
describe('AppComponent', () => {  
 beforeEach(async(() => {  
 TestBed.configureTestingModule({  
 declarations: [  AppComponent  ],  
 }).compileComponents();  
 }));
 // ...
});
```

在实际应用中，我们可以创建`AppModule`，其中`AppComponent`作为声明。在这里，我们只需要一个简单的模块，其中包含`AppComponent`，这要归功于`TestBed`的`configureTestingModule`模块使这成为可能。

接下来，我们可以开始编写对我们想要检查的任何场景的测试套件。首先，让我们检查`AppComponent`是否存在：

```ts
describe('AppComponent', () => {  
 it('should create the app', async(() => {  
 const fixture = TestBed.createComponent(AppComponent);  
 const app = fixture.debugElement.componentInstance;  
 expect(app).toBeTruthy();  
 }));
});
```

在使用`createComponent()`创建组件本身之后，我们首先尝试使用`componentInstance`创建组件的实例。

当我们使用`expect`断言来查看组件是否存在时，实际的检查是完成的，使用`toBeTruthy()`。

我们还可以检查组件属性的内容：

```ts
it(`should have as title 'app'`, async(() => {  
 const fixture = TestBed.createComponent(AppComponent);  
 const app = fixture.debugElement.componentInstance;  
 expect(app.title).toEqual('app');  
}));
```

通过`app`作为组件的一个实例，您可以访问此实例上的属性和方法。我们刚刚测试了`app.title`的初始值是否等于`app`。

最后的测试套件实际上检查了值的 DOM：

```ts
it('should render title in a h1 tag', async(() => {  
 const fixture = TestBed.createComponent(AppComponent);  
 fixture.detectChanges();  
 const compiled = fixture.debugElement.nativeElement; expect(compiled.querySelector('h1').textContent).toContain('Welcome to app!!');  }));
```

请注意，在这个测试套件中调用了`detectChanges`。这会启动模板上的绑定（如果有的话）。然后，我们不是创建一个实例，而是抓住编译后的元素，查询它的`h1`标签，并检查标签的文本内容是否包含`Welcome to app`。

要运行这些测试，请执行以下命令：

```ts
ng test
```

这应该启动 Karma，一个隔离的测试环境。您的测试将运行，并且以下内容将被打印到 CLI：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/f8bea96f-951b-425b-8dfe-e478a1ca9699.png)

您可能想知道为什么最后一行说`4`个测试而不是`3`个；请记住，我们生成的引用组件也有一个单独的测试套件。

# 摘要

在本章中，您学会了如何创建 Angular 项目以及新项目必需的文件。现在您知道如何创建 Angular 项目，并且构建组件等基本构建块，了解了模块的存在原因，如何将简单样式应用到组件，以及 Angular 中的单元测试是什么样子的。

在下一章中，我们将深入探讨更多组件的创建，并看一些示例在实际中的运用。


# 第五章：使用 TypeScript 创建高级自定义组件

在上一章中，我们讨论了组件的创建和使用基础知识。这些知识不足以构建健壮的应用程序。我们需要更深入地了解 Angular 令人兴奋的组件，并看看 TypeScript 如何使与组件一起工作变得更容易。

我们将在展示一些实际示例的同时，讨论以下主题：

+   **生命周期钩子**: 这些是 Angular 中的类方法，您可以连接到它们。通过实现 TypeScript 接口来实现。

+   **ElementRef**: 这涉及使用 ElementRef API 在 Angular 中安全地操作和查询 DOM。

+   **视图封装**: 您将学习如何将作用域样式应用于 Angular 组件，以及如何更改默认行为。

# 生命周期钩子

您在类中创建的大多数方法必须由您在某个地方调用，这是编程中的预期模式。这在 Angular 定义的生命周期钩子中并非如此。这些钩子是您为 Angular 在组件/指令的当前状态下内部调用它们而创建的方法。它们在组件或指令的类中创建。

以下钩子在 Angular 组件中可用：

+   `ngOnChanges`: 记住属性如何绑定到组件。这些属性是响应式的，意味着当它们改变时，视图也会更新。当任何绑定到视图的属性发生变化时，将调用此生命周期方法。因此，您可以在更改反映之前操纵发生的事情。

+   `ngOnInit`: 这是最常见的生命周期。在使用默认属性绑定初始化组件后调用。因此，在第一个`ngOnChanges`之后调用。

+   `ngDoCheck`: 通常，响应性（变更检测）由您处理，但在极端情况下，如果不是这样，您需要自己处理。使用`ngDoCheck`来检测并对 Angular 无法或不会自行检测的变化做出反应。

+   `ngAfterContentInit`: 组件内容初始化后调用。

+   `ngAfterContentChecked`: 在对组件内容进行每次检查后调用。

+   `ngAfterViewInit`: 在基于组件模板初始化视图后调用。

+   `ngAfterViewChecked`: 在检查组件视图和组件的子视图后调用。

+   `ngOnDestroy`: 在组件被销毁之前调用。这是一个清理的好地方。

有些生命周期钩子可能并不立即有意义。你不必担心它们，因为只有在极端情况下才会需要很多这样的钩子。

举个例子可以帮助澄清它们的工作原理。让我们探讨最常见的钩子，即`ngOnInit`。

使用 CLI 命令创建一个新的 Angular 项目。打开应用组件的 TypeScript 文件，并更新导入以包括`OnInit`：

```ts
// Code: 5.1
//./src/app/app.component.ts

import { Component, OnInit } from  '@angular/core';
```

`OnInit`是一个接口，任何打算实现`ngOnInit`的类都应该继承它。这在技术上并不是必需的（参见[`angular.io/guide/lifecycle-hooks#interfaces-are-optional-technically`](https://angular.io/guide/lifecycle-hooks#interfaces-are-optional-technically)）。

现在，你可以让`AppComponent`类实现这个接口：

```ts
// Code: 5.1 //./src/app/app.component.ts

@Component({  selector: 'app-root',  templateUrl: './app.component.html',  styleUrls: ['./app.component.css']  })  export class AppComponent implements OnInit {  title: string = 'Items in Bag';  items: Array<string> = [];  loading: boolean = false;  
 ngOnInit () {  this.loading = true;  
 setTimeout(() => {  this.items = [  'Pen',  'Note',  'Mug',  'Charger',  'Passport',  'Keys'  ]  this.loading = false;  }, 3000)  }  }
```

我们试图模拟一种异步行为，其中的值在将来被解析。这种操作最好在应用程序初始化时完成，这就是为什么我们在`ngOnInit`方法中处理这个操作。一旦组件准备就绪，Angular 就会调用这个钩子，它将在三秒后设置项目数组。

我们甚至可以在值到来之前就将其绑定到视图上。当值可用时，Angular 将始终更新视图：

```ts
<!-- Code: 5.1 -->
<!-- ./src/app/app.component.html --> 
<div style="text-align:center">  
 <h1>  {{title}}!!  </h1>  
 <h4 *ngIf="loading">Please wait...</h4>  
</div>  
<ul>  
 <li *ngFor="let item of items">{{item}}</li>  
</ul>
```

在 Angular 模板中迭代列表时，我们使用`*ngFor` **结构指令**，如前面的例子所示。`*ngIf`结构指令类似于`*ngFor`，但用于根据组件上的布尔属性显示 DOM 元素。

像往常一样，用`ng serve`运行应用程序，你将首先看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/bb26d10d-0b15-4ab2-8574-b58bb9fa3fb3.png)

三秒后，“请稍候...”文本将消失，你将看到你的项目列表：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/2957cb42-5956-494d-80e4-428ed2e7fbb8.png)

# DOM 操作

在 Angular 1.x 中，触及 DOM 似乎是神秘的；不是说你不能，但不知何故它会反过来伤害你。这很讽刺，因为作为网页设计师/开发者，我们所做的就是绘制 DOM，而这是不可能的，如果不对其进行操作。

使用 Angular 2+，这变得非常容易。Angular 抽象了 DOM，并为你提供了浅拷贝来操作。然后它负责在不伤害任何人的情况下将其放回。使用 TypeScript 会更有趣，因为你的编辑器可以为你提示大多数 DOM 属性方法。

# ElementRef

实现 DOM 操作的 API 是`ElementRef`。让我们基于[`www.w3schools.com/howto/howto_js_tabs.asp`](https://www.w3schools.com/howto/howto_js_tabs.asp)上的基本演示构建一个使用这个 API 的选项卡组件。

通过使用 CLI 生成命令生成一个新组件：

```ts
ng g component tab
```

将模板作为子级添加到我们的应用组件中，就在`*ngFor`指令之后：

```ts
<ul>   <li *ngFor="let item of items">{{item}}</li>  
</ul>  

<!--Add tab component to app-->
<app-tab></app-tab>
```

然后，用以下内容替换组件的模板：

```ts
<!--./src/app/tab/tab.component.css-->
<div class="tab">  
 <button class="tablink" (click)="openTab($event, 'London')">London</button> <button class="tablink" (click)="openTab($event, 'Paris')">Paris</button> <button class="tablink" (click)="openTab($event, 'Tokyo')">Tokyo</button> </div>  <div id="London" class="tabcontent">  <h3>London</h3>  <p>London is the capital city of England.</p> </div> <div id="Paris" class="tabcontent">   <h3>Paris</h3>   <p>Paris is the capital of France.</p>  </div> <div id="Tokyo" class="tabcontent">   <h3>Tokyo</h3>   <p>Tokyo is the capital of Japan.</p> </div>
```

你应该在浏览器上看到结果，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/efe4ce64-861d-47e5-8ea6-4df5f97d0c2a.png)

让我们添加一些样式来创建一个选项卡的外观：

```ts
// based on styles from the base sample

/* ./src/app/tab/tab.component.css */
div.tab {
  overflow: hidden;
  border: 1px solid #ccc;
  background-color: #f1f1f1;
  }  div.tab button {
  background-color: inherit;
  float: left;
  border: none;
  outline: none;
  cursor: pointer;
  padding: 14px 16px;
  transition: 0.3s;
  } div.tab button:hover {
  background-color: #ddd;
  }   div.tab button.active {
  background-color: #ccc;
  }   .tabcontent {   padding: 6px 12px;
  border: 1px solid #ccc;
 border-top: none; }
```

有了样式，你应该看到下面截图中显示的结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/d1840279-66f0-47b0-a50b-d394bb9db2f7.png)

现在是开始操作 DOM 的时候了。我们首先需要通过 CSS 默认隐藏所有选项卡内容；然后可以在 TypeScript 中激活它们：

```ts
.tabcontent {  
 display: none;   }
```

# 钩入内容初始化

为了确保能够访问 DOM，我们需要钩入`ngAfterContentInit`生命周期方法。在这个方法中，我们可以使用`ElementRef`来查询 DOM 并操作它：

```ts
import { Component, ElementRef, OnInit, AfterContentInit } from '@angular/core';  @Component({
  selector: 'app-tab',
  templateUrl: './tab.component.html',
  styleUrls: ['./tab.component.css']
  })  export class TabComponent implements OnInit, AfterContentInit {  tabContents: Array<HTMLElement>;
 tabLinks: Array<HTMLElement>;  
 constructor(
  private el: ElementRef
  ) { }

  ngOnInit() {}

  ngAfterContentInit() {
 // Grab the DOM
  this.tabContents = this.el.nativeElement.querySelectorAll('.tabcontent');
  this.tabLinks = this.el.nativeElement.querySelectorAll('.tablink');
   }   }  
```

该类实现了`AfterContentInit`和`OnInit`，展示了如何实现多个接口。然后，我们将按钮声明为`HTMLElement`链接的数组。选项卡内容也是如此。

就在构造函数中，我们创建一个名为`el`的`ElementRef`实例，我们可以用它来与 DOM 交互。`ngAfterContentInit`函数在 DOM 内容准备就绪后被调用，这使它成为处理启动时 DOM 操作的理想候选者。因此，我们在那里获取对 DOM 的引用。

我们需要在加载时显示第一个选项卡并使第一个选项卡链接处于活动状态。让我们扩展`ngAfterContentInit`来实现这一点：

```ts
export class TabComponent implements OnInit, AfterContentInit {
  tabContents: Array<HTMLElement>;
  tabLinks: Array<HTMLElement>;
  constructor(
  private el: ElementRef
  ) { }
  ngOnInit() {}
  ngAfterContentInit() {
  this.tabContents = this.el.nativeElement.querySelectorAll('.tabcontent');
  this.tabLinks = this.el.nativeElement.querySelectorAll('.tablink');

 // Activate first tab

 this.tabContents[0].style.display = "block";
 this.tabLinks[0].className = " active";
 }  }  
```

这将显示第一个选项卡，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/3a5d38ec-7351-49ee-9953-c6d757d60159.png)

# 处理 DOM 事件

最后要做的事情是为点击事件添加事件侦听器并开始切换选项卡。在前面的模板中，我们为每个按钮附加了点击事件：

```ts
<button class="tablink" (click)="open($event, 'London')">London</button> <button class="tablink" (click)="open($event, 'Paris')">Paris</button> <button class="tablink" (click)="open($event, 'Tokyo')">Tokyo</button>
```

`openTab`方法是事件处理程序。让我们实现它：

```ts
export class TabComponent implements OnInit, AfterContentInit {
  tabContents: Array<HTMLElement>;
  tabLinks: Array<HTMLElement>;
  constructor(
  private el: ElementRef
  ) { }

 // ...

 open(evt, cityName) {
  for (let i = 0; i < this.tabContents.length; i++) {
  this.tabContents[i].style.display = "none";
  }
  for (let i = 0; i < this.tabLinks.length; i++) {
  this.tabLinks[i].className = this.tabLinks[i].className.replace(" active", "");
  }
  this.el.nativeElement.querySelector(`#${cityName}`).style.display = "block"; 
 evt.currentTarget.className += " active"; 
 } }  
```

当调用该方法时，我们遍历所有选项卡并隐藏它们。我们还遍历按钮并通过用空字符串替换活动类来禁用它们。然后，我们可以显示我们想要打开的选项卡并激活被点击的按钮。

现在当你点击选项卡按钮时，每个选项卡内容都会显示出来：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/a12abe97-05b9-4f8e-b94b-1872e0b45de8.png)

有不同的方法来解决这个问题，其中一些方法更加高级。我们刚刚展示的例子故意执行 DOM 查询，以向您展示在 Angular 中进行 DOM 操作是多么可能和简单。

# 视图封装

组件可以配置为以不同的方式应用样式。这个概念被称为封装，这就是我们现在要讨论的内容。

使用 CLI 创建另一个项目，并使用以下命令添加一个额外的组件：

```ts
ng g component child
```

然后，通过应用组件将这个新组件添加到视图中：

```ts
// Code 5.2
<!-- ./src/app/app.component.html -->

<div style="text-align:center">   <h1>  This is parent component  </h1>   <app-child></app-child>  </div>  
```

子组件的模板就是这么简单：

```ts
// Code 5.2
<!-- ./src/app/child/child.component.html -->

<h3>This is child component  </h3>  
```

这只是我们需要了解视图封装策略的最低设置。让我们来探索一下。

# 模拟

这是默认策略。通过 HTML 全局应用的任何样式（而不是父组件）以及应用到组件的所有样式都将被反映。在我们的例子中，如果我们针对`h3`并在`style.css`、`app.component.css`和`child.component.css`中应用样式，只有`style.css`和`child.component.css`会被反映。

以下 CSS 是子组件的：

```ts
h3 {  color: palevioletred  }
```

运行上述代码后，子组件视图上的结果如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/abbb916d-1ae6-4aee-9cda-0f950dd9478c.png)

在全局样式和组件本身上应用相同样式到相同元素的情况下，组件样式会覆盖全局样式。例如，假设`style.css`文件如下：

```ts
h3 {
 color: palevioletred }
```

现在考虑`child.component.css`文件如下：

```ts
h3 {
 color: blueviolet }
```

`h3`的颜色将是`blueviolet`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/126071d5-858e-4373-b2e1-6fc6eb4833ef.png)

您可以在组件装饰器中设置这个，尽管这并不是必需的，因为`Emulated`是默认值：

```ts
import { Component, OnInit, ViewEncapsulation } from '@angular/core'; @Component({
 selector: 'app-child',
</span>  templateUrl: './child.component.html',
  styleUrls: ['./child.component.css'],
 // Encapsulation: Emulated
 encapsulation: ViewEncapsulation.Emulated })  export class ChildComponent implements OnInit {   constructor() { }
   ngOnInit() { } } 
```

# 本地

这种策略类似于模拟，但它禁止全局样式进入组件。将全局样式中的样式保持不变，将封装设置为本地：

```ts
@Component({
  selector: 'app-child',
  templateUrl: './child.component.html',
  styleUrls: ['./child.component.css'],
 // Encapsulation: Native
 encapsulation: ViewEncapsulation.Native })
```

即使全局样式将`h3`的颜色设置为`pinkvioletred`，文本颜色仍然是黑色，因为它无法渗透模板：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/be23604f-c652-4997-8932-b8c986da9821.png)

# 无

这是最自由的策略。无论样式设置在哪里--子组件还是父组件--样式都会泄漏到其他组件中：

```ts
@Component({
  selector: 'app-child',
  templateUrl: './child.component.html',
  styleUrls: ['./child.component.css'],
 // Encapsulation: Native
 encapsulation: ViewEncapsulation.None })
```

通过这个设置，您可以通过子组件的样式来为父标签中的`h1`标签设置样式：

```ts
// child component style
h1 {
 color: blueviolet }
```

这在视图中反映出来，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ts2-ng-dev/img/8908367d-7c8c-4bed-ac17-821dbd48db1b.png)

# 摘要

希望讨论的高级主题并不复杂或难以理解。你学会了如何实现生命周期钩子，控制组件范围样式的行为，并在渲染后操作 DOM 内容。

如果你只从这一章中学到了一件事，那就是如何使用 TypeScript 实现生命周期接口，并使用 TypeScript 装饰器配置组件。在下一章中，你将学习组件通信以及组件如何通过属性、事件、视图子元素和内容子元素相互交互。
