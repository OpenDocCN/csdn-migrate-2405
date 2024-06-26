# JavaScript 高级编程（一）

> 原文：[`zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90`](https://zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的内容、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件。

## 关于本书

JavaScript 是 Web 技术的核心编程语言，可用于修改 HTML 和 CSS。它经常被缩写为 JS。JavaScript 经常用于大多数 Web 浏览器的用户界面中进行的处理，如 Internet Explorer，Google Chrome 和 Mozilla Firefox。由于其使浏览器能够完成工作的能力，它是当今最广泛使用的客户端脚本语言。

在本书中，您将深入了解 JavaScript。您将学习如何在 ES6 中使用新的 JavaScript 语法在专业环境中编写 JavaScript，如何利用 JavaScript 的异步特性使用回调和承诺，以及如何设置测试套件并测试您的代码。您将了解 JavaScript 的函数式编程风格，并将所学的一切应用于使用各种 JavaScript 框架和库构建简单应用程序的后端和前端开发。

### 关于作者

**Zachary Shute**在 RPI 学习计算机和系统工程。他现在是位于加利福尼亚州旧金山的一家机器学习初创公司的首席全栈工程师。对于他的公司 Simple Emotion，他管理和部署 Node.js 服务器，MongoDB 数据库以及 JavaScript 和 HTML 网站。

### 目标

+   检查 ES6 中的主要功能，并实现这些功能来构建应用程序

+   创建承诺和回调处理程序以处理异步进程

+   使用 Promise 链和 async/await 语法开发异步流

+   使用 JavaScript 操作 DOM

+   处理 JavaScript 浏览器事件

+   探索测试驱动开发，并使用 JavaScript 代码测试框架构建代码测试。

+   列出函数式编程与其他风格相比的优缺点

+   使用 Node.js 后端框架和 React 前端框架构建应用程序

### 受众

本书旨在针对任何希望在专业环境中编写 JavaScript 的人群。我们期望受众在某种程度上使用过 JavaScript，并熟悉基本语法。本书适合技术爱好者，想知道何时使用生成器或如何有效地使用承诺和回调，或者想加深对 JavaScript 的了解和理解 TDD 的初学开发人员。

### 方法

这本书以易于理解的方式全面解释了技术，同时完美地平衡了理论和练习。每一章都设计为在前一章所学内容的基础上构建。本书包含多个活动，使用真实的商业场景让您练习并应用新技能，使之具有高度相关性。

### 最低硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   处理器：Intel Core i5 或同等处理器

+   内存：4 GB RAM

+   存储：35 GB 可用空间

+   互联网连接

### 软件要求

您还需要提前安装以下软件：

+   操作系统：Windows 7 SP1 64 位，Windows 8.1 64 位或 Windows 10 64 位

+   Google Chrome ([`www.google.com/chrome/`](https://www.google.com/chrome/))

+   Atom IDE ([`atom.io/`](https://atom.io/))

+   Babel ([`www.npmjs.com/package/babel-install`](https://www.npmjs.com/package/babel-install))

+   Node.js 和 Node Package Manager（npm）([`nodejs.org/en/`](https://nodejs.org/en/))

安装说明可以单独提供给大型培训中心和组织。所有源代码都可以在 GitHub 上公开获取，并在培训材料中得到完全引用。

### 安装代码包

将课程的代码包复制到`C:/Code`文件夹中。

### 额外资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/Advanced-JavaScript`](https://github.com/TrainingByPackt/Advanced-JavaScript)。

我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

### 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都显示为以下方式："JavaScript 中声明变量的三种方式：`var`、`let`和`const`。"

代码块设置如下：

```js
var example; // Declare variable
example = 5; // Assign value
console.log( example ); // Expect output: 5
```

任何命令行输入或输出都以以下方式编写：

```js
npm install babel --save-dev
```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："这意味着使用块作用域创建的变量受到**时间死区（TDZ）**的影响。"

### 安装 Atom IDE

1.  要安装 Atom IDE，请在浏览器中转到[`atom.io/`](https://atom.io/)。

1.  点击**下载 Windows 安装程序**以下载名为**AtomSetup-x64.exe**的设置文件。

1.  运行可执行文件。

1.  将`atom`和`apm`命令添加到您的路径中。

1.  在桌面和开始菜单上创建快捷方式。

Babel 会安装到每个代码项目的本地。要在 NodeJs 项目中安装 Babel，请完成以下步骤：

1.  打开命令行界面并导航到项目文件夹。

1.  运行命令`npm init`。

1.  填写所有必填问题。如果您不确定任何提示的含义，可以按“enter”键跳过问题并使用默认值。

1.  运行`npm install --save-dev babel-cli`命令。

1.  运行命令`install --save-dev babel-preset-es2015`。

1.  验证`package.json`中的`devDependencies`字段是否包含`babel-cli`和`babel-presets-es2015`。

1.  创建一个名为`.babelrc`的文件。

1.  在文本编辑器中打开此文件并添加代码`{ "presets": ["es2015"] }`。

### 安装 Node.js 和 npm

1.  要安装 Node.js，请在浏览器中转到[`nodejs.org/en/`](https://nodejs.org/en/)。

1.  点击**下载 Windows（x64）**，以下载推荐给大多数用户的 LTS 设置文件，名为`node-v10.14.1-x64.msi`。

1.  运行可执行文件。

1.  确保在安装过程中选择 npm 软件包管理器捆绑包。

1.  接受许可证和默认安装设置。

1.  重新启动计算机以使更改生效。


# 第一章：介绍 ECMAScript 6

## 学习目标

在本章结束时，您将能够：

+   定义 JavaScript 中的不同作用域并表征变量声明

+   简化 JavaScript 对象定义

+   解构对象和数组，并构建类和模块

+   为了兼容性转译 JavaScript

+   组合迭代器和生成器

在本章中，您将学习如何使用 ECMAScript 的新语法和概念。

## 介绍

JavaScript，通常缩写为 JS，是一种旨在允许程序员构建交互式 Web 应用程序的编程语言。JavaScript 是 Web 开发的支柱之一，与 HTML 和 CSS 一起。几乎每个主要的网站，包括 Google、Facebook 和 Netflix，都大量使用 JavaScript。JS 最初是为 Netscape Web 浏览器于 1995 年创建的。JavaScript 的第一个原型是由 Brendan Eich 在短短的 10 天内编写的。自创建以来，JavaScript 已成为当今最常用的编程语言之一。

在本书中，我们将加深您对 JavaScript 核心及其高级功能的理解。我们将涵盖 ECMAScript 标准中引入的新功能，JavaScript 的异步编程特性，DOM 和 HTML 事件与 JavaScript 的交互，JavaScript 的函数式编程范式，测试 JavaScript 代码以及 JavaScript 开发环境。通过本书所获得的知识，您将准备好在专业环境中使用 JavaScript 构建强大的 Web 应用程序。

## 从 ECMAScript 开始

**ECMAScript**是由**ECMA International**标准化的脚本语言规范。它旨在标准化 JavaScript，以允许独立和兼容的实现。**ECMAScript 6**，或**ES6**，最初于 2015 年发布，并自那时以来经历了几次次要更新。

#### 注意

您可以参考以下链接了解更多关于 ECMA 规范的信息：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Language_Resources`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Language_Resources)。

## 理解作用域

在计算机科学中，**作用域**是计算机程序中名称与实体（如变量或函数）的绑定或关联有效的区域。JavaScript 具有以下两种不同类型的作用域：

+   **函数作用域**

+   **块作用域**

在 ES6 之前，函数作用域是 JavaScript 中唯一的作用域形式；所有变量和函数声明都遵循函数作用域规则。ES6 引入了块作用域，仅由使用新的变量声明关键字`let`和`const`声明的变量使用。这些关键字在*声明变量*部分中有详细讨论。

### 函数作用域

JavaScript 中的**函数作用域**是在函数内部创建的。当声明一个函数时，在该函数的主体内部创建一个新的作用域块。在新函数作用域内声明的变量无法从父作用域访问；但是，函数作用域可以访问父作用域中的变量。

要创建具有函数作用域的变量，必须使用`var`关键字声明变量。例如：

`var example = 5;`

以下代码段提供了函数作用域的示例：

```
var example = 5;
function test() {
  var testVariable = 10;
  console.log( example ); // Expect output: 5
  console.log( testVariable ); // Expect output: 10
}
test();
console.log( testVariable ); // Expect reference error
```

###### 代码段 1.1：函数作用域

**父作用域**只是函数定义的代码段的作用域。这通常是全局作用域；但是，在某些情况下，在函数内部定义函数可能很有用。在这种情况下，嵌套函数的父作用域将是其定义的函数。在前面的代码段中，函数作用域是在函数 test 内创建的作用域。父作用域是全局作用域，即函数定义的地方。

#### 注意

父作用域是定义函数的代码块。它不是调用函数的代码块。

### 函数作用域提升

当使用函数作用域创建变量时，其声明会自动提升到作用域的顶部。**提升**意味着解释器将实体的实例化移动到其声明的作用域顶部，而不管它在作用域块中的定义位置。在 JavaScript 中，使用`var`声明的函数和变量会被提升；也就是说，函数或变量可以在其声明之前使用。以下代码演示了这一点：

```
example = 5; // Assign value
console.log( example ); // Expect output: 5
var example; // Declare variable
```

###### 片段 1.2：函数作用域提升

#### 注意

由于使用`var`声明的提升变量可以在声明之前使用，因此我们必须小心在变量被赋值之前不要使用该变量。如果在变量被赋值之前访问变量，它将返回`undefined`，这可能会导致问题，特别是如果变量在全局作用域中使用。

### 块作用域

在 JavaScript 中，使用花括号（`{}`）创建一个新的块作用域。一对**花括号**可以放置在代码的任何位置以定义一个新的作用域块。if 语句、循环、函数和任何其他花括号对都将有自己的块作用域。这包括与关键字（if、for 等）无关的浮动花括号对。以下片段中的代码是块作用域规则的示例：

```
// Top level scope
function scopeExample() {
  // Scope block 1
  for ( let i = 0; i < 10; i++ ){ /* Scope block 2 */ }
  if ( true ) { /* Scope block 3 */ } else {  /* Scope block 4 */ }
  // Braces without keywords create scope blocks
  { /* Scope block 5 */ } 
  // Scope block 1
}
// Top level scope
```

###### 片段 1.3：块作用域

使用关键字`let`和`const`声明的变量具有**块作用域**。当使用块作用域声明变量时，它不具有与在函数作用域中创建的变量相同的变量提升。块作用域变量不会被提升到作用域的顶部，因此在声明之前无法访问。这意味着使用块作用域创建的变量受到**暂时性死区**（**TDZ**）的影响。TDZ 是指进入作用域和声明变量之间的时间段。它在变量被声明而不是赋值时结束。以下示例演示了 TDZ：

```
// console.log( example ); // Would throw ReferenceError
let example;
console.log( example ); // Expected output: undefined
example = 5;
console.log( example ); // Expected output: 5
```

###### 片段 1.4：暂时性死区

#### 注意

如果在暂时性死区内访问变量，则会抛出运行时错误。这很重要，因为它可以使我们的代码更加健壮，减少由于变量声明而产生的语义错误。

要更好地理解作用域块，请参考以下表格：

![图 1.1：函数作用域与块作用域](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.1.jpg)

###### 图 1.1：函数作用域与块作用域

总之，作用域为我们提供了一种在代码块之间分离变量并限制访问的方式。变量标识符名称可以在作用域块之间重复使用。所有创建的新作用域块都可以访问父作用域，或者它们被创建或定义的作用域。JavaScript 有两种作用域。为每个定义的函数创建一个新的函数作用域。变量可以使用`var`关键字添加到函数作用域，并且这些变量会被提升到作用域的顶部。块作用域是 ES6 的一个新特性。为每组花括号创建一个新的块作用域。使用`let`和`const`关键字将变量添加到块作用域。添加的变量不会被提升，并且受到 TDZ 的影响。

### 练习 1：实现块作用域

要使用变量实现块作用域原则，请执行以下步骤：

1.  创建一个名为`fn1`的函数（`function fn1()`）。

1.  记录字符串为`scope 1`。

1.  创建一个名为`scope`的变量，其值为 5。

1.  记录名为`scope`的变量的值。

1.  在函数内部使用花括号（`{}`）创建一个新的作用域块。

1.  在新的作用域块内，记录名为`scope 2`的字符串。

1.  在作用域块内创建一个名为`scope`的新变量，并赋值为`different scope`。

1.  记录块作用域内变量`scope`的值（scope 2）。

1.  在步骤 5 中定义的作用域块之外（scope 2），创建一个新的作用域块（使用花括号）。

1.  记录名为`scope 3`的字符串。

1.  在作用域块（作用域 3）内创建一个同名的变量（称为 `scope`）并将其赋值为 `第三个作用域`。

1.  记录新变量的值。

1.  调用 `fn1` 并观察其输出

**代码**

index.js：

```
function fn1(){
 console.log('Scope 1');
 let scope = 5;
 console.log(scope);
 {
   console.log('Scope 2');
   let scope = 'different scope';
   console.log(scope);
 }
  {
   console.log('Scope 3');
   let scope = 'a third scope';
   console.log(scope);
 }
}
fn1();
```

[`bit.ly/2RoOotW`](https://bit.ly/2RoOotW)

###### 代码片段 1.5：块实现输出

**结果**

![图 1.2：作用域输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.2.jpg)

###### 图 1.2：作用域输出

您已成功在 JavaScript 中实现了块作用域。

在本节中，我们介绍了 JavaScript 作用域的两种类型，函数作用域和块作用域，以及它们之间的区别。我们演示了如何在每个函数内部创建一个新的函数作用域实例，以及如何在每组花括号内创建块作用域。我们讨论了每种作用域类型的变量声明关键字，`var` 用于函数作用域，`let/const` 用于块作用域。最后，我们介绍了函数作用域和块作用域的变量提升的基础知识。

## 声明变量

基本 JavaScript 使用关键字 `var` 进行**变量声明**。ECMAScript 6 引入了两个新关键字来声明变量；它们是 `let` 和 `const`。在专业 JavaScript 变量声明的世界中，`var` 现在是最薄弱的环节。在本主题中，我们将介绍新关键字 `let` 和 `const`，并解释它们为什么比 `var` 更好。

在 JavaScript 中声明变量的三种方式是使用 `var`、`let` 和 `const`。它们的功能略有不同。这三种变量声明关键字之间的关键区别在于它们处理变量重新分配、变量作用域和变量提升的方式。这三个特性可以简要解释如下：

**变量重新赋值：** 在任何时候改变或重新分配变量的值的能力。

**变量作用域：** 变量可以被访问的代码范围或区域。

**变量提升：** 变量实例化和赋值时间与变量声明的关系。有些变量可以在它们被声明之前使用。

`var` 关键字是在 JavaScript 中用于声明变量的较旧的关键字。所有使用 `var` 创建的变量都可以重新分配，具有函数作用域，并且具有变量提升。这意味着使用 `var` 创建的变量被提升到作用域块的顶部，在那里它们被定义并且可以在声明之前访问。以下代码片段演示了这一点，如下所示：

```
// Referenced before declaration
console.log( example ); // Expect output: undefined
var example = 'example';
```

###### 代码片段 1.6：使用 var 创建的变量被提升

由关键字 `var` 创建的变量不是常量，因此可以随意创建、分配和重新分配值。以下代码演示了 `var` 功能的这一方面：

```
// Declared and assigned
var example = { prop1: 'test' };
console.log( 'example:', example );
// Expect output: example: {prop1: "test"}
// Value reassigned
example = 5;
console.log( example ); // Expect output: 5
```

###### 代码片段 1.7：使用 var 创建的变量不是常量

使用 `var` 创建的变量可以在任何时候重新分配，并且一旦变量被创建，即可在函数中的任何地方访问，甚至是在原始声明点之前。

`let` 关键字与关键字 `var` 类似。如预期的那样，关键字 `let` 允许我们声明一个可以在任何时候重新分配的变量。以下代码中展示了这一点：

```
// Declared and initialized
let example = { prop1: 'test' };
console.log( 'example:', example );
// Expect output: example: {prop1: 'test"}
// Value reassigned
example = 5;
console.log( example ); // Expect output: 5
```

###### 代码片段 1.8：使用 let 创建的变量不是常量

`let` 和 `var` 之间有两个重要的区别。`let` 和 `var` 的区别在于它们的作用域和变量提升属性。使用 `let` 声明的变量的作用域是块级的；也就是说，它们只在匹配的一对花括号（`{}`）内的代码块中定义。

使用 `let` 声明的变量不受变量提升的影响。这意味着在赋值之前访问使用 `let` 声明的变量将引发运行时错误。正如前面讨论的那样，这就是暂时性死区。以下代码示例说明了这一点：

```
// Referenced before declaration
console.log( example );
// Expect ReferenceError because example is not defined
let example = 'example';
```

###### 代码片段 1.9：使用 let 创建的变量不会被提升

最后一个变量声明关键字是`const`。`const`关键字具有与`let`关键字相同的作用域和变量提升规则；使用`const`声明的变量具有块作用域，并且不会被提升到作用域的顶部。这在以下代码中显示：

```
// Referenced before declaration
console.log( example );
// Expect ReferenceError because example is not defined
const example = 'example';
```

###### 片段 1.10：使用 const 创建的变量不会被提升

`const`和`let`之间的关键区别在于`const`表示标识符不会被重新分配。`const`标识符表示对值的只读引用。换句话说，不能更改`const`变量中写入的值。如果更改了使用`const`初始化的变量的值，将抛出`TypeError`。

即使使用`const`创建的变量不能被重新分配，这并不意味着它们是不可变的。如果数组或对象存储在使用`const`声明的变量中，则无法覆盖变量的值。但是，数组内容或对象属性可以更改。可以使用`push()`、`pop()`或`map()`等函数修改数组的内容，并且可以添加、删除或更新对象属性。这在以下代码中显示：

```
// Declared and initialized
const example = { prop1: 'test' };
// Variable reassigned
example = 5;
// Expect TypeError error because variable was declared with const
// Object property updated
example.prop1 = 5;
// Expect no error because subproperty was modified
```

###### 片段 1.11：使用 const 创建的变量是常量但不是不可变的

要更详细地了解不同的关键字，请参考以下表格：

![图 1.3：var、let 和 const 之间的差异](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.3.jpg)

###### 图 1.3：var、let 和 const 之间的差异

现在我们了解了`var`、`let`和`const`之间的细微差别，我们可以决定使用哪一个。在专业世界中，我们应该始终使用`let`和`const`，因为它们提供了`var`的所有功能，并允许程序员对变量的范围和用法进行具体和限制性的定义。

总之，`var`、`let`和`const`都有类似的功能。关键区别在于`const`的性质、作用域和提升。`var`是函数作用域的，不是常量，并且被提升到作用域块的顶部。`let`和`const`都是块作用域的，不会被提升。`let`不是常量，而`const`是常量但不可变的。

### 练习 2：利用变量

为了利用`var`、`const`和`let`变量声明关键字的变量提升和重新分配属性，执行以下步骤：

1.  记录字符串`赋值前提升：`和`hoisted`变量的值。

1.  使用关键字`var`定义一个名为`hoisted`的变量，并将其赋值为`this got hoisted`。

1.  记录字符串`赋值后提升：`和`hoisted`变量的值。

1.  创建一个 try-catch 块。

1.  在`try`块内，记录名为`notHoisted1`的变量的值。

1.  在`catch`块内，给 catch 块`err`参数，然后记录字符串`带错误的未提升 1：`和`err.message`的值。

1.  在 try-catch 块之后，使用关键字`let`创建`notHoisted1`变量，并赋值为`5`。

1.  记录字符串`赋值后 notHoisted1`和`notHoisted1`的值。

1.  创建另一个 try-catch 块。

1.  在`try`块内，记录`notHoisted2`变量的值。

1.  在 catch 块内，给 catch 块`err`参数，然后记录字符串`带错误的未提升 2：`和`err.message`的值。

1.  在第二个 try-catch 块之后，使用关键字`const`创建`notHoisted2`变量，并赋值[`1`,`2`,`3`]。

1.  记录字符串`赋值后 notHoisted2`和`notHoisted2`的值。

1.  定义一个最终的 try catch 块。

1.  在`try`块内，将`notHoisted2`重新分配为`new value`字符串。

1.  在 catch 块内，给 catch 块`err`参数，然后记录字符串`未提升 2 无法更改`。

1.  在 try-catch 块之后，将值`5`推送到`notHoisted2`中的数组中。

1.  记录字符串`notHoisted2 已更新。现在是：`和`notHoisted2`的值。

**代码**

##### index.js:

```
var hoisted = 'this got hoisted';
try{
 console.log(notHoisted1);
} catch(err){}
let notHoisted1 = 5;
try{
 console.log(notHoisted2);
} catch(err){}
const notHoisted2 = [1,2,3];
try{
 notHoisted2 = 'new value';
} catch(err){}
notHoisted2.push(5);
```

###### 片段 1.12：更新对象的内容

[`bit.ly/2RDEynv`](https://bit.ly/2RDEynv)

**结果**

![图 1.4：提升变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.4.jpg)

###### 图 1.4：提升变量

您已成功地利用关键字声明变量。

在本节中，我们讨论了 ES6 中的变量声明以及使用`let`和`const`变量声明关键字相对于`var`变量声明关键字的好处。我们讨论了每个关键字的变量重新赋值属性，变量作用域和变量提升属性。关键字`let`和`const`都在块作用域中`创建`变量，而`var`在函数作用域中创建变量。使用`var`和`let`创建的变量可以随意重新赋值。然而，使用`const`创建的变量不能被重新赋值。最后，使用关键字`var`创建的变量被提升到它们被定义的作用域块的顶部。使用`let`和`const`创建的变量不会被提升。

## 引入箭头函数

**箭头函数**，或**Fat 箭头函数**，是在 ECMAScript 6 中创建函数的新方法。箭头函数简化了函数语法。它们被称为**fat 箭头函数**，因为它们用字符=>表示，这样放在一起看起来像一个粗箭头。JavaScript 中的箭头函数经常在回调链，承诺链，数组方法中使用，在任何需要未注册函数的情况下都会很有用。

JavaScript 中箭头函数和普通函数之间的关键区别在于箭头函数是**匿名**的。箭头函数没有名称，也没有绑定到标识符。这意味着箭头函数是动态创建的，不像普通函数那样有名称。然而，箭头函数可以分配给一个变量以便重用。

创建箭头函数时，我们只需要删除函数关键字，并在函数参数和函数体之间放置一个箭头。箭头函数用以下语法表示：

```
( arg1, arg2, ..., argn ) => { /* Do function stuff here */ }
```

###### 片段 1.13：箭头函数语法

从前面的语法中可以看出，箭头函数是 JavaScript 中更简洁的编写函数的方式。它们可以使我们的代码更简洁，更易读。

箭头函数语法也可能有所不同，取决于几个因素。语法可能会略有不同，具体取决于传递给函数的参数数量以及函数体中的代码行数。特殊的语法条件在以下列表中简要概述：

+   单个输入参数

+   无输入参数

+   单行函数体

+   单个表达式跨多行

+   对象字面量返回值

### 练习 3：转换箭头函数

为了演示通过将标准函数转换为箭头函数来简化语法，执行以下步骤：

1.  创建一个接受参数并返回两个参数之和的函数。将函数保存到名为`fn1`的变量中。

1.  将刚刚创建的函数转换为箭头函数，并保存到另一个名为`fn2`的变量中。

要转换函数，删除`function`关键字。接下来，在函数参数和函数体之间放置一个箭头。

1.  调用两个函数并比较输出。

**代码**

##### index.js:

```
const fn1 = function( a, b ) { return a + b; };
const fn2 = ( a, b ) => { return a + b; };
console.log( fn1( 3 ,5 ), fn2( 3, 5 ) );
```

###### 片段 1.14：调用函数

[`bit.ly/2M6uKwN`](https://bit.ly/2M6uKwN)

**结果**

![图 1.5：比较函数的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.5.jpg)

###### 图 1.5：比较函数的输出

您已成功将普通函数转换为箭头函数。

### 箭头函数语法

如果有多个参数传递给函数，那么我们使用括号来创建函数，括号包围参数就像平常一样。如果我们只有一个参数要传递给函数，我们就不需要在参数周围加括号。

这个规则有一个例外，那就是参数不是简单的标识符。如果我们在函数参数中包含默认值或执行操作，那么我们必须包含括号。例如，如果我们包含默认参数，那么我们将需要在参数周围加上括号。这两条规则如下面的代码所示：

```
// Single argument arrow function
arg1 => { /* Do function stuff here */ }
// Non simple identifier function argument
( arg1 = 10 ) => { /* Do function stuff here */ }
```

###### 片段 1.15：单参数箭头函数

如果我们创建一个没有参数的箭头函数，那么我们需要包括括号，但括号将是空的。如下面的代码所示：

```
// No arguments passed into the function
( ) => { /* Do function stuff here */ }
```

###### 片段 1.16：无参数

箭头函数的语法也可以有所不同，取决于函数的主体。如预期的那样，如果函数的主体是多行的，那么我们必须用花括号括起来。但是，如果函数的主体是单行的，那么我们不需要在函数的主体周围包含花括号。这如下面的代码所示：

```
// Multiple line body arrow function
( arg1, arg2 ) => { 
  console.log( `This is arg1: ${arg1}` );
  console.log( `This is arg2: ${arg2}` );
  /* Many more lines of code can go here */
}
// Single line body arrow function
( arg1, arg2 ) => console.log( `This is arg1: ${arg1}` )
```

###### 片段 1.17：单行体

在使用箭头函数时，如果函数是单行的，我们也可以省略 return 关键字。箭头函数会自动返回该行表达式的解析值。这种语法如下面的代码所示：

```
// With return keyword - not necessary
( num1, num2 ) => { return ( num1 + num2 ) }
// If called with arguments num1 = 5 and num2 = 5, expected output is 10
// Without return keyword or braces
( num1, num2 ) => num1 + num2
// If called with arguments num1 = 5 and num2 = 5, expected output is 10
```

###### 片段 1.18：返回值为单行体

由于单行表达式体的箭头函数可以在没有花括号的情况下定义，我们需要特殊的语法来允许我们将单个表达式分成多行。为此，我们可以将多行表达式放在括号中。JavaScript 解释器会看到括号中的行，并将其视为单行代码。这如下面的代码所示：

```
// Arrow function with a single line body
// Assume numArray is an array of numbers
( numArray ) => numArray.filter( n => n > 5).map( n => n - 1 ).every( n => n < 10 )
// Arrow function with a single line body broken into multiple lines
// Assume numArray is an array of numbers
( numArray ) => (
  numArray.filter( n => n > 5)
          .map( n => n - 1 )
          .every( n => n < 10 )
) 
```

###### 片段 1.19：将单行表达式分成多行

如果我们有一个返回对象字面量的单行箭头函数，我们将需要特殊的语法。在 ES6 中，作用域块、函数主体和对象字面量都是用花括号定义的。由于单行箭头函数不需要花括号，我们必须使用特殊的语法来防止对象字面量的花括号被解释为函数主体花括号或作用域块花括号。为此，我们用括号括起返回的对象字面量。这指示 JavaScript 引擎将括号内的花括号解释为表达式，而不是函数主体或作用域块声明。这如下面的代码所示：

```
// Arrow function with an object literal in the body
( num1, num2 ) => ( { prop1: num1, prop2: num2 } ) // Returns an object
```

###### 片段 1.20：对象字面量返回值

在使用箭头函数时，我们必须注意这些函数被调用的作用域。箭头函数遵循 JavaScript 中的正常作用域规则，但`this`作用域除外。回想一下，在基本的 JavaScript 中，每个函数都被分配一个作用域，即`this`作用域。箭头函数没有被分配一个`this`作用域。它们继承其父级的`this`作用域，并且不能将新的`this`作用域绑定到它们。这意味着，如预期的那样，箭头函数可以访问父函数的作用域，随后访问该作用域中的变量，但`this`的作用域不能在箭头函数中改变。使用`.apply()`、`.call()`或`.bind()`函数修改器都不会改变箭头函数的`this`属性的作用域。如果你处于必须将`this`绑定到另一个作用域的情况，那么你必须使用普通的 JavaScript 函数。

总之，箭头函数为我们提供了简化匿名函数语法的方法。要编写箭头函数，只需省略 function 关键字，并在参数和函数体之间添加一个箭头。

然后可以应用特殊语法来简化箭头函数。如果函数有一个输入参数，那么我们可以省略括号。如果函数主体是单行的，我们可以省略`return`关键字和花括号。然而，返回对象字面量的单行函数必须用括号括起来。

我们还可以在函数体周围使用括号，以便将单行函数体分成多行以提高可读性。

### 练习 4：升级箭头函数

要利用 ES6 箭头函数语法编写函数，请执行以下步骤：

1.  参考`exercises/exercise4/exercise.js`文件并在此文件中执行更新。

1.  使用基本的 ES6 语法转换`fn1`。

在函数参数之前删除函数关键字。在函数参数和函数体之间添加箭头。

1.  使用单语句函数体语法转换`fn2`。

在函数参数之前删除函数关键字。在函数参数和函数体之间添加箭头。

删除函数体周围的花括号`({})`。删除 return 关键字。

1.  使用单个输入参数语法转换`fn3`。

在函数参数之前删除函数关键字。在函数参数和函数体之间添加箭头。

删除函数输入参数周围的括号。

1.  使用无输入参数语法转换`fn4`。

在函数参数之前删除函数关键字。在函数参数和函数体之间添加箭头。

1.  使用对象文字语法转换`fn5`。

在函数参数之前删除函数关键字。在函数参数和函数体之间添加箭头。

删除函数体周围的花括号`({})`。删除 return 关键字。

用括号括起返回的对象。

**代码**

##### index.js：

```
let fn1 = ( a, b ) => { … };
let fn2 = ( a, b ) => a * b;
let fn3 = a => { … };
let fn4 = () => { … };
let fn5 = ( a ) => ( …  );
```

###### 代码段 1.21：箭头函数转换

[`bit.ly/2M6qSfg`](https://bit.ly/2M6qSfg)

**结果**

![图 1.6：转换函数的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.6.jpg)

###### 图 1.6：转换函数的输出

您已成功利用 ES6 箭头函数语法编写函数。

在本节中，我们介绍了箭头函数，并演示了它们如何在 JavaScript 中大大简化函数声明。首先，我们介绍了箭头函数的基本语法：`( arg1, arg2, argn ) => { /* function body */ }`。然后，我们继续介绍了高级箭头函数的五种特殊语法情况，如下列表所述：

+   单个输入参数：`arg1 => { /* function body */ }`

+   无输入参数：`( ) => { /* function body */ }`

+   单行函数体：`( arg1, arg2, argn ) => /* single line */`

+   单个表达式分成多行：`( arg1, arg2, argn ) => ( /* multi line single expression */ )`

+   对象文字返回值：`( arg1, arg2, argn ) => ( { /* object literal */ } )`

## 学习模板文字

**模板文字**是 ECMAScript 6 中引入的一种新形式的字符串。它们由**反引号**符号（`` ` ``），而不是通常的单引号或双引号。模板文字允许您在运行时计算的字符串中嵌入表达式。因此，我们可以很容易地从变量和变量表达式创建动态字符串。这些表达式用美元符号和花括号（`${ expression }`）表示。模板文本语法如以下代码所示:

```
const example = "pretty";
console.log( `Template literals are ${ example } useful!!!` ); 
// Expected output: Template literals are pretty useful!!!
```

###### 代码段 1.22：模板字面量基本语法

在 JavaScript 中，模板字面量像其他字符串一样被转义。要转义模板字面量，只需使用反斜杠（`\`）字符。例如，以下相等性计算结果为真：``\`` === "`",`\t` === "\t"`, and ``\n\r` === "\n\r".

模板字面量允许多行字符串。插入源代码的任何换行符都属于模板字面量，并将在输出中导致换行。简单来说，在模板字面量内，我们可以按下键盘上的**Enter**键并将其拆分成两行。源代码中的换行符将被解析为模板字面量的一部分，并将导致输出中的换行。要使用普通字符串复制这一点，我们必须使用`\n`字符生成新行。使用模板字面量，我们可以在模板字面量源中换行并实现相同的预期输出。示例代码如下所示：

```
// Using normal strings
console.log( 'This is line 1\nThis is line 2' );
// Expected output: This is line 1
// This is line 2
// Using template literals
console.log( `This is line 1
This is line 2` );
// Expected output: This is line 1
// This is line 2
```

###### 代码段 1.23：模板字面量多行语法

### 练习 5：转换为模板字面量

为了演示模板字面量表达式的强大功能，将标准字符串对象转换为模板字面量，执行以下步骤：

1.  创建两个变量，`a` 和 `b`，并将数字保存其中。

1.  用普通字符串记录 `a` 和 `b` 的总和为 `a + b` 等于 `<result>`。

1.  以单个模板字面量的格式记录 `a` 和 `b` 的总和为 `a + b` 等于 `<result>`。

**代码**

##### index.js:

```
let a = 5, b = 10;
console.log( a + ' + ' + b + ' is equal to ' + ( a + b ) );
console.log( `${a} + ${b} is equal to ${a + b}` );
```

###### 代码段 1.24：模板字面量和字符串比较

[`bit.ly/2RD5jbC`](https://bit.ly/2RD5jbC)

**结果**

![图 1.7：记录变量输出的总和](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.7.jpg)

###### 图 1.7：记录变量输出的总和

您已成功将标准字符串对象转换为模板字面量。

模板字面量允许表达式嵌套，即，新的模板字面量可以放置在模板字面量的表达式中。由于嵌套的模板字面量是表达式的一部分，它将被解析为新的模板字面量，并且不会干扰外部模板字面量。在某些情况下，嵌套模板字面量是创建字符串的最简单和最可读的方式。模板字面量嵌套的示例代码如下所示：

```
function javascriptOrCPlusPlus() { return 'JavaScript'; }
const outputLiteral = `We are learning about ${ `Professional ${ javascriptOrCPlusPlus() }` }`
```

###### 代码段 1.25：模板字面量嵌套

**带标记的模板文字**是模板文字的更高级形式。带标记的模板文字可以使用称为**标记函数**的特殊函数进行解析，可以返回一个操作后的字符串或任何其他值。标记函数的第一个输入参数是一个包含字符串值的数组。字符串值表示输入字符串的部分，在每个模板表达式处进行拆分。其余的参数是字符串中模板表达式的值。标记函数不像普通函数那样调用。要调用标记函数，我们忽略模板文字参数周围的括号和空格。以下是此语法的示例：

```
// Define the tag function
function tagFunction( strings, numExp, fruitExp ) { 
  const str0 = strings[0]; // "We have"
  const str1 = strings[1]; // " of "
  const quantity = numExp < 10 ? 'very few' : 'a lot';
  return str0 + quantity + str1 + fruitExp + str2;
}
const fruit = 'apple', num = 8;
// Note: lack of parenthesis or whitespace when calling tag function
const output = tagFunction`We have ${num} of ${fruit}. Exciting!`
console.log( output )
// Expected output: We have very few of apples. Exciting!!
```

###### Snippet 1.26: 带标记的模板文字示例

一个名为`raw`的特殊属性可用于标记模板的第一个参数。此属性返回一个包含每个拆分模板文字的原始、未转义版本的数组。以下是示例代码：

```
function tagFunction( strings ){ console.log( strings.raw[0] ); }
tagFunction`This is line 1\. \n This is line 2.`
// Expected output: "This is line 1\. \n This is line 2." The characters //'\' and 'n' are not parsed into a newline character
```

###### Snippet 1.27: 带标记的模板原始属性

总而言之，模板文字允许简化复杂的字符串表达式。模板文字允许将变量和复杂表达式嵌入字符串中。模板文字甚至可以嵌套到其他模板文字的表达式字段中。如果模板文字在源代码中分为多行，则解释器将将其解释为字符串中的换行并相应地插入一个换行。模板文字还提供了一种使用带标记模板函数解析和操作字符串的新方式。这些函数为您提供了一种通过特殊函数执行复杂的字符串操作的方法。通过带标记的模板函数，可以访问原始字符串，如其输入一样，忽略任何转义序列。

### 练习 6：模板文字转换

您正在为一家房地产公司建立网站。您必须构建一个函数，该函数接受包含属性信息的对象，并返回一个格式化的字符串，说明物业所有者、物业所在地（`address`）以及他们出售的价格。考虑以下对象作为输入：

```
{
  address: '123 Main St, San Francisco CA, USA',
  floors: 2,
  price: 5000000,
  owner: 'John Doe'
}
```

###### Snippet 1.28: 对象输入

要利用模板文本对对象进行漂亮的打印，执行以下步骤：

1.  创建一个名为`parseHouse`的函数，该函数接受一个对象。

1.  从函数返回一个模板文本。使用表达式，将所有者、地址和价格嵌入到格式为`<所有者>在<地址>出售价格为<价格>`的字符串中。

1.  创建一个名为`house`的变量，并将以下对象保存到其中：`{ address: "123 Main St, San Francisco CA, USA", floors: 2, price: 5000000, owner: "John Doe" }`

1.  调用`parseHouse`函数并传入`house`变量。

1.  记录输出。

**代码**

##### index.js:

```
function parseHouse( property ) {
 return `${property.owner} is selling the property at ${property.address} for ${property.price} USD`
}
const house = {
 address: "123 Main St, San Francisco CA, USA",
 floors: 2,
 price: 5000000,
 owner: "John Doe"
};
console.log( parseHouse( house ) );
```

###### Snippet 1.29: 使用表达式的模板文字

[`bit.ly/2RklKKH`](https://bit.ly/2RklKKH)

**结果**

![图 1.8：模板文字输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.8.jpg)

###### 图 1.8：模板文字输出

你已成功利用模板字符串来美化打印输出一个对象。

在这一部分，我们介绍了模板字符串。模板字符串通过允许我们在其中嵌入在运行时被解析的表达式来升级字符串。表达式使用以下语法插入：``${ expression }``。然后，我们向您展示了如何在模板字符串中转义特殊字符，并讨论了编辑器内的模板字符串换行符在输出中作为换行符的解析方式。最后，我们介绍了模板字符串标记和标记函数，这允许我们执行更复杂的模板字符串解析和创建。

## 增强对象属性

ECMAScript 6 作为**ES6 语法糖**的一部分，增加了对象字面量的几个增强功能。ES6 添加了三种简化对象字面量创建的方法。这些简化包括更简洁的语法来从变量初始化对象属性，更简洁的语法定义函数方法，以及计算对象属性名称。

#### 注意

语法糖是一种旨在使表达式更易于阅读和表达的语法。它使语法变得"更甜美"，因为代码可以被简洁地表达。

### 对象属性

初始化对象属性的简写允许您创建更简洁的对象。在 ES5 中，我们需要使用键名和值来定义对象属性，如下代码所示：

```
function getPersionES5( name, age, height ) {
  return {
    name: name,
    age: age,
    height: height
  };
}
getPersionES5( 'Zachary', 23, 195 )
// Expected output: { name: 'Zachary', age: 23, height: 195 }
```

###### 代码片段 1.30：ES5 对象属性

注意函数返回的对象字面量中的重复。我们在对象中将属性命名为变量名导致了重复（`<code>name: name</code>`）。在 ES6 中，我们可以简写每个属性并消除重复。在 ES6 中，我们可以简单地在对象字面量中声明变量，它将创建一个键名匹配变量名和值匹配变量值的属性。以下代码示例：

```
function getPersionES6( name, age, height ) {
  return {
    name,
    age,
    height
  };
}
getPersionES6( 'Zachary', 23, 195 )
// Expected output: { name: 'Zachary', age: 23, height: 195 }
```

###### 代码片段 1.31：ES6 对象属性

正如你所看到的，无论是 ES5 还是 ES6 的示例，都输出了完全相同的对象。但是，在大型对象字面量声明中，使用这种新的简写可以节省大量空间和重复。

### 函数声明

ES6 还为在对象内部声明函数方法添加了一个简写。在 ES5 中，我们必须声明属性名称，然后将其定义为函数。以下示例中有所展示：

```
function getPersonES5( name, age, height ) {
  return {
    name: name,
    height: height,
    getAge: function(){ return age; }
  };
}
getPersonES5( 'Zachary', 23, 195 ).getAge()
// Expected output: 23
```

###### 代码片段 1.32：ES5 函数属性

在 ES6 中，我们可以定义一个函数，但工作量要少得多。与属性声明一样，我们并不需要键值对来创建函数。函数名称变为键名。以下代码示例中有所展示：

```
function getPersionES6( name, age, height ) {
  return {
    name,
    height,
    getAge(){ return age; }
  };
}
getPersionES6( 'Zachary', 23, 195 ).getAge()
// Expected output: 23
```

###### 代码片段 1.33：ES6 函数属性

注意函数声明中的差异。我们省略了函数关键字和属性键名后的冒号。再次，这为我们节省了一些空间并简化了事情。

### 计算属性

ES6 还增加了一种有效的方式来创建属性名称，即通过计算属性表示法。正如我们已经知道的，在 ES5 中，只有一种方式可以使用变量创建属性名称；这是通过方括号表示法，即，`: obj[ expression ] = 'value'`。在 ES6 中，我们可以在对象字面量的声明期间使用相同类型的表示法。这在以下示例中显示：

```
const varName = 'firstName';
const person = {
  [ varName ] = 'John',
  lastName: 'Smith'
};
console.log( person.firstName ); // Expected output: John
```

###### 代码片段 1.34：ES6 计算属性

如前面代码片段所示，`varName` 的属性名称计算为 `firstName`。在访问属性时，我们只需要引用`person.firstName`。在对象字面量中创建计算属性时，不需要在方括号中计算的值是变量；它几乎可以是任何表达式，甚至是函数。下面的代码示例中提供了一个例子：

```
const varName = 'first';
function computeNameType( type ) {
  return type + 'Name';
}
const person = {
  [ varName + 'Name' ] = 'John',
  [ computeNameType( 'last' ) ]: 'Smith'
};
console.log( person.firstName ); // Expected output: John
console.log( person.lastName ); // Expected output: Smith
```

###### 代码片段 1.35：从函数计算属性

在前面代码片段中的示例中，我们创建了两个变量。第一个包含字符串`first`，第二个包含返回字符串的函数。然后，我们创建了一个对象，并使用计算属性表示法来创建动态对象键名。第一个键名等于`firstName`。访问`person.firstName`时，将返回保存的值。第二个键名等于`lastName`。当访问`person.lastName`时，也将返回保存的值。

总之，ES6 增加了三种简化对象字面量声明的方法，即属性表示法，函数表示法和计算属性。为了简化对象中的属性创建，在属性是从变量创建时，我们可以省略键名和冒号。被创建的属性的名称设置为变量名称，值设置为变量的值。要将函数作为对象的属性添加，我们可以省略冒号和函数关键字。被创建的属性名称设置为函数名称，属性的值为函数本身。最后，在对象字面量的声明过程中，我们可以使用计算表达式创建属性名称。我们只需用方括号中的表达式替换键名。这三种简化可以节省我们代码中的空间，并使对象字面量的创建更易于阅读。

### 练习 7：实现增强的对象属性

您正在构建一个简单的 JavaScript 数学包，以发布到**Node Package Manager (NPM)**。您的模块将导出一个包含多个常量和函数的对象。使用 ES6 语法，创建导出对象，并包含以下函数和值：圆周率的值，将英寸转换为英尺的比率，求两个参数的和的函数，以及求两个参数的差的函数。创建对象后，记录该对象的内容。

要使用 ES6 增强的对象属性创建对象，并演示简化的语法，执行以下步骤：

1.  创建一个对象并将其保存到`exportObject`变量中。

1.  创建一个名为`PI`的变量，其中包含圆周率的值（3.1415）。

1.  创建一个名为`INCHES_TO_FEET`的变量，并将英寸到英尺的转换比值保存到其中（0.083333）。

    使用 ES6 增强的属性表示法，从变量`PI`添加一个名为`PI`的属性。从包含英寸到英尺转换比的`INCHES_TO_FEET`变量中添加一个名为`INCHES_TO_FEET`的属性。

    添加一个名为`sum`的函数属性，接受两个输入参数并返回这两个输入参数的和。

    添加一个名为`subtract`的函数属性，接受两个输入参数并返回这两个输入参数的差值。

1.  记录对象`exportObject`。

**代码**

##### index.js:

```
const PI = 3.1415;
const INCHES_TO_FEET = 0.083333;
const exportObject = {
 PI,
 INCHES_TO_FEET,
 sum( n1, n2 ) {
   return n1 + n2;
 },
 subtract( n1, n2 ) {
   return n1 - n2;
 }
};
console.log( exportObject );
```

###### 代码段 1.36：增强的对象属性

[`bit.ly/2RLdHWk`](https://bit.ly/2RLdHWk)

**结果**

![图 1.9：增强的对象属性输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.9.jpg)

###### 图 1.9：增强的对象属性输出

您已成功使用 ES6 增强的对象属性创建对象。

在本节中，我们向您展示了增强的对象属性，这是一种语法糖，可以帮助将对象属性的创建压缩为更少的字符。我们介绍了使用变量和函数初始化对象属性的简写方式，以及计算对象属性的高级特性，即一种在定义对象时内联从计算值创建对象属性名称的方法。

## 解构赋值

**解构赋值**是 JavaScript 中的一种语法，允许您从数组中解压值或从对象的属性中保存值到变量中。这是一个非常方便的特性，因为我们可以直接从数组和对象中提取数据保存到变量中，所有这些都可以在一行代码中完成。它非常强大，因为它使我们能够在同一个表达式中提取多个数组元素或对象属性。

### 数组解构

**数组解构**允许我们提取多个数组元素并将它们保存到变量中。在 ES5 中，我们通过逐个定义每个变量及其数组值来实现这一点。这使得代码冗长并增加编写所需的时间。

在 ES6 中，为了解构数组，我们简单地创建一个包含要分配数据的变量的数组，并将其设置为被解构的数据数组。数组中的值被解开并从左到右分配给左侧数组中的变量，一个数组值对应一个变量。基本数组解构的示例如下代码所示：

```
let names = [ 'John', 'Michael' ];
let [ name1, name2 ] = names;
console.log( name1 ); // Expected output: 'John'
console.log( name2 ); // Expected output: 'Michael'
```

###### 代码段 1.37：基本数组解构

如本例所示，我们有一个姓名数组，并且我们想要将其解构为`name1`和`name2`两个变量。我们只需用括号括起变量`name1`和`name2`，并将该表达式设置为数据数组`names`，然后 JavaScript 将解构`names`数组，并将数据保存到各个变量中。

数据从输入数组中解构为变量，从左到右，按照数组项的顺序。第一个索引变量将始终被分配第一个索引数组项。这引出了一个问题，如果数组项比变量更多怎么办？如果数组项比变量多，那么剩余的数组项将被丢弃，不会被解构为变量。解构是按照数组顺序进行一对一的映射。

如果变量数多于数组项怎么办？如果我们尝试将一个数组解构为一个包含比数据数组中数组元素总数更多变量的数组，那么其中一些变量将被设置为 undefined。数组从左到右进行解构。在 JavaScript 数组中访问不存在的元素将导致返回 undefined 值。这个 undefined 值将保存在变量数组中剩余的变量中。下面的代码展示了这一点：

```
let names = [ 'John', 'Michael' ];
let [ name1 ] = names
let [ name2, name3, name4 ] = names;
console.log( name1 ); // Expected output: 'John'
console.log( name2 ); // Expected output: 'John'
console.log( name3 ); // Expected output: 'Michael'
console.log( name4 ); // Expected output: undefined
```

###### 代码段 1.38：具有不匹配变量和数组项的数组解构

#### 注意

我们在解构数组时必须小心，确保我们不会无意中假设变量将包含一个值。如果数组不够长，变量的值可能被设置为 undefined。

ES6 数组解构允许跳过数组元素。如果我们有一个值的数组，并且只关心第一个和第三个值，我们仍然可以解构数组。要忽略一个值，只需要在表达式的左侧省略该数组索引的变量标识符。这种语法可以用来忽略单个项目、多个项目，甚至是数组中的所有项目。以下代码段中展示了两个示例：

```
let names = [ 'John', 'Michael', 'Jessica', 'Susan' ];
let [ name1,, name3 ] = names;
// Note the missing variable name for the second array item
let [ ,,, ] = names; // Ignores all items in the array
console.log( name1 ); // Expected output: 'John'
console.log( name3 ); // Expected output: 'Jessica'
```

###### 代码段 1.39：具有跳过值的数组解构

数组解构的另一个非常有用的特性是为使用解构创建的变量设置默认值的能力。当我们想要添加默认值时，我们只需在解构表达式的左侧将变量设置为所需的默认值。如果我们在解构的内容中没有包含一个可分配给变量的索引，那么默认值将被使用。下面的代码展示了这一点：

```
let [ a = 1, b = 2, c = 3 ] = [ 'cat', null ]; 
console.log( a ); // Expected output: 'cat'
console.log( b ); // Expected output: null
console.log( c ); // Expected output: 3
```

###### 代码段 1.40：具有跳过值的数组解构

最后，数组解构也可以用于轻松交换变量的值。如果我们希望交换两个变量的值，我们可以简单地将一个数组解构为反向数组。我们可以创建一个包含要反转的变量的数组，并将其设置为相同的数组，但变量顺序改变。这将导致引用被交换。下面的代码展示了这一点：

```
let a = 10;
let b = 5;
[ a, b ] = [ b, a ];
console.log( a ); // Expected output: 5
console.log( b ); // Expected output: 10
```

###### 代码段 1.41：具有跳过值的数组解构

### 练习 8：数组解构

要使用数组解构赋值从数组中提取值，请执行以下步骤：

1.  创建一个包含三个值`1`，`2`和`3`的数组，并将其保存到名为`data`的变量中。

1.  对使用单个表达式创建的数组进行解构。

    将第一个数组值解构为名为`a`的变量。跳过数组的第二个值。

    将第三个值解构为名为`b`的变量。尝试将第四个值解构为名为`c`的变量，如果失败则提供默认值`4`。

1.  记录所有变量的值。

**代码**

##### index.js:

```
const data = [ 1, 2, 3 ];
const [ a, , b, c = 4 ] = data;
console.log( a, b, c );
```

###### 代码片段 1.42：数组解构

[`bit.ly/2D2Hm5g`](https://bit.ly/2D2Hm5g)

**结果**

![图 1.10：解构变量的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.51.jpg)

###### 图 1.10：解构变量的输出

您已成功应用了数组解构赋值从数组中提取值并保存到变量中。

总之，数组解构允许我们快速从数组中提取值并将其保存到变量中。变量按从左到右的顺序逐个分配给数组值。如果变量的数量超过数组项的数量，则变量将被设置为未定义，或者如果指定了默认值，则将设置为默认值。我们可以通过在变量数组中留下一个空位来跳过解构中的数组索引。最后，我们可以使用解构赋值来快速交换单行代码中两个或多个变量的值。

### Rest 和 Spread 运算符

ES6 还为数组引入了两个新的运算符，称为**rest**和**spread**。rest 和 spread 运算符都用三个省略号或句点表示（`...array1`）。rest 运算符用于表示作为数组的无限个参数。spread 运算符用于允许可迭代的对象扩展为多个参数。要确定使用的是哪个运算符，我们必须查看应用参数的项。如果该运算符应用于可迭代的对象（数组，对象等），则是 spread 运算符。如果该运算符应用于函数参数，则是 rest 运算符。

#### 注意

在 JavaScript 中，如果可以逐个遍历某些内容（通常是值或键/值对），则将其视为可迭代的。例如，数组是可迭代的，因为可以逐个遍历数组中的项。对象也被认为是可迭代的，因为可以逐个遍历键/值对。

**rest 运算符**用于表示作为数组的无限个参数。将函数的最后一个参数加上三个省略号时，它将成为一个数组。数组元素由传递到函数中的实际参数提供，其中不包括已在函数的正式声明中分配了单独名称的参数。下面的代码示例展示了 rest 解构的示例：

```
function fn( num1, num2, ...args ) {
  // Destructures an indefinite number of function parameters into the
//array args, excluding the first two arguments passed in.
  console.log( num1 );
  console.log( num2 );
  console.log( args );
}
fn( 1, 2, 3, 4, 5, 6 );
// Expected output
// 1
// 2
// [ 3, 4, 5, 6 ]
```

###### 代码片段 1.43：带有跳过值的数组解构

类似于 JavaScript 函数的**参数对象**，剩余运算符包含函数参数的列表。但是，剩余运算符与参数对象有三个明显的不同之处。正如我们已经知道的那样，参数对象是类似数组的对象，其中包含传递给函数的每个参数。不同之处如下。首先，剩余运算符仅包含在函数表达式中没有单独形式声明的输入参数。

第二，arguments 对象不是**Array**对象的实例。剩余参数是数组的一个实例，这意味着数组函数如`sort()`、`map()`和`forEach()`可以直接应用于它们。

最后，参数对象具有特殊功能，而剩余参数没有。例如，调用者属性存在于参数对象上。

剩余参数可以类似于我们解构数组的方式进行解构。在省略号之前放置单个变量名的替代方法是，我们可以用要填充的变量数组替换它。传递给函数的参数将按预期解构为数组。这在下面的代码中显示：

```
function fn( ...[ n1, n2, n3 ] ) {
  // Destructures an indefinite number of function parameters into the
// array args, which is destructured into 3 variables
  console.log( n1, n2, n3 );
}
fn( 1, 2 ); // Expected output: 1, 2, undefined
```

###### 代码片段 1.44：解构剩余运算符

展开运算符允许可迭代对象（如数组或字符串）扩展为多个参数（用于函数调用）、数组元素（用于数组文字）或键值对（用于对象表达式）。这基本上意味着我们可以将数组扩展为创建另一个数组、对象或调用函数的参数。展开语法的示例如下代码所示：

```
function fn( n1, n2, n3 ) {
  console.log( n1, n2, n3 );
}
const values = [ 1, 2, 3 ];
fn( ...values ); // Expected output: 1, 2, 3
```

###### 代码片段 1.45：展开运算符

在前面的示例中，我们创建了一个简单的函数，它接受三个输入并将它们记录到控制台。我们创建了一个包含三个值的数组，然后使用`spread`运算符调用函数，将值数组解构为函数的三个输入参数。

剩余运算符可以用于解构对象和数组。在解构数组时，如果数组元素多于变量，我们可以使用剩余运算符在解构过程中捕获所有额外的数组元素。在使用剩余运算符时，它必须是数组解构或函数参数列表中的最后一个参数。下面的代码展示了这一点：

```
const [ n1, n2, n3, ...remaining ] = [ 1, 2, 3, 4, 5, 6 ];
console.log( n1 ); // Expected output: 1
console.log( n2 ); // Expected output: 2
console.log( n3 ); // Expected output: 3
console.log( remaining ); // Expected output: [ 4, 5, 6 ]
```

###### 代码片段 1.46：展开运算符

在前面的代码片段中，我们将前三个数组元素解构为`n1`、`n2`和`n3`三个变量。然后，我们使用剩余运算符捕获了剩余的数组元素，并将它们解构为剩下的变量。

总之，rest 和 spread 操作符允许可迭代实体扩展为多个参数。它们在标识符名称之前用三个省略号表示。这使我们可以在函数中捕获参数数组或在解构实体时捕获未使用的项目。当我们使用 rest 和 spread 操作符时，它们必须是传入它们所使用的表达式的最后的参数。

### 对象解构

**对象解构**的用法与数组解构非常相似。对象解构用于从对象中提取数据并将数值赋给新变量。在 ES6 中，我们可以在单个 JavaScript 表达式中实现这一点。要解构对象，我们用大括号（`{}`）括起要解构的变量，并将该表达式赋值给要解构的对象。对象解构的基本示例如下所示：

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
const { firstName, lastName } = obj;
console.log( firstName ); // Expected output: 'Bob'
console.log( lastName ); // Expected output: 'Smith'
```

###### 代码片段 1.47：对象解构

在上面的例子中，我们创建了一个带有`firstName`和`lastName`键的对象。然后将这个对象解构为变量`firstName`和`lastName`。注意变量的名称和对象参数的名称匹配。如下例所示：

#### 注意

在进行基本对象解构时，对象中的参数名称和我们要分配的变量名称必须匹配。如果变量我们尝试解构的变量没有匹配的参数，那么该变量将被设置为 undefined。

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
const { firstName, middleName } = obj;
console.log( firstName ); // Expected output: 'Bob'
console.log( middleName ); // Expected output: undefined
```

###### 代码片段 1.48：没有定义键的对象解构

如我们所见，`middleName`键不存在于对象中。当我们尝试解构该键并将其保存到变量中时，它无法找到数值，变量将被设置为 undefined。

通过高级对象解构语法，我们可以将被提取的键保存到另一个名称的变量中。这是通过在解构符号后面添加冒号和新变量名称来实现的。这在以下代码中显示：

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
const { firstName: first, lastName } = obj;
console.log( first ); // Expected output: 'Bob'
console.log( lastName ); // Expected output: 'Smith'
```

###### 代码片段 1.49：将对象解构为新变量

在上面的例子中，我们可以清楚地看到，我们正在从对象中解构`firstname`键，并将其保存到新变量 first 中。`lastName`键正常解构并保存到一个名为`lastName`的变量中。

与数组解构一样，我们可以解构一个对象并提供默认值。如果提供了默认值，并且我们尝试解构的键不存在于对象中，那么变量将被设置为默认值，而不是 undefined。如下代码所示：

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
const { firstName = 'Samantha', middleName = 'Chris' } = obj;
console.log( firstName ); // Expected output: 'Bob'
console.log( middleName ); // Expected output: 'Chris'
```

###### 代码片段 1.50：带默认值的对象解构

在上面的示例中，我们对尝试从对象解构的变量设置了默认值。指定了 `firstName` 的默认值，但对象中存在 `firstName` 键。这意味着解构并忽略了默认值中存储的 `firstName` 键的值。对象中不存在 `middleName` 键，并且我们指定了在解构时使用的默认值。解构赋值将解构变量设置为默认值 `Chris`，而不是使用 `firstName` 键的未定义值。

当我们提供默认值并将键赋值给新变量名时，我们必须在新变量名后放置默认值赋值。下面的示例展示了这一点：

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
const { firstName: first = 'Samantha', middleName: middle = 'Chris' } = obj;
console.log( first ); // Expected output: 'Bob'
console.log( middle); // Expected output: 'Chris'
```

###### 代码片段 1.51：对象解构为具有默认值的新变量

`firstName` 键存在。`obj.firstName` 的值保存到名为 `first` 的新变量中。`middleName` 键不存在。这意味着新变量 `middle` 被创建并设置为默认值 `Chris`。

### 练习 9：对象解构

使用对象解构的概念从对象中提取数据，执行以下步骤：

1.  创建一个具有字段 `f1`，`f2` 和 `f3` 的对象。将值分别设置为 `v1`，`v2` 和 `v3`。将对象保存到变量 `data` 中。

1.  使用单个语句将此对象解构为变量，如下所示：

    将 `f1` 属性解构为名为 `f1` 的变量。将 `f2` 属性解构为名为 `field2` 的变量。将属性 `f4` 解构为名为 `f4` 的变量，并提供默认值 `v4`。

1.  记录创建的变量。

**代码**

##### index.js：

```
const data = { f1: 'v1', f2: '2', f3: 'v3' };
const { f1, f2: field2, f4 = 'v4' } = data;
console.log( f1, field2, f4 );
```

###### 代码片段 1.52：对象解构

[`bit.ly/2SJUba9`](https://bit.ly/2SJUba9)

**结果**

![图 1.11：创建变量的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.11.jpg)

###### 图 1.11：创建变量的输出

您已成功应用了对象解构的概念，从对象中提取数据。

如果我们在对象解构表达式之前声明变量，JavaScript 需要特殊的语法。我们必须用括号括起整个对象解构表达式。数组解构不需要这样的语法。下面的代码展示了这一点：

```
const obj = { firstName: 'Bob', lastName: 'Smith' };
let firstName, lastName;
( { firstName: first, lastName } = obj );
// Note parentheses around expression
console.log( firstName ); // Expected output: 'Bob'
console.log( lastName ); // Expected output: 'Smith'
```

###### 代码片段 1.53：对象解构为预定义变量

#### 提示

确保以这种方式完成的对象解构在相同或前一行的分号之前。这可以防止 JavaScript 解释器将括号解释为函数调用。

**剩余运算符**也可以用于解构对象。由于对象键是可迭代的，我们可以使用剩余运算符来捕获原始解构表达式中未捕获的剩余键。这与数组类似。我们解构要捕获的键，然后我们可以将剩余运算符添加到一个变量中，并捕获未从对象中解构出来的剩余键/值对。这在下面的示例中显示：

```
const obj = { firstName: 'Bob', middleName: 'Chris', lastName: 'Smith' };
const { firstName, ...otherNames } = obj;
console.log( firstName ); // Expected output: 'Bob'
console.log( otherNames );
// Expected output: { middleName: 'Chris', lastName: 'Smith' }
```

###### 代码片段 1.54: 带有剩余运算符的对象解构

总之，对象解构允许我们快速从对象中提取值并将其保存到变量中。关键名称必须与简单对象解构中的变量名称匹配，然而，我们可以使用更高级的语法将键的值保存到一个新对象中。如果在对象中未定义键，则变量将设置为`false`，除非我们为其提供默认值。我们可以将此保存到预定义的变量中，但是我们必须用括号将解构表达式括起来。最后，剩余运算符可以用于捕获剩余的键值对，并将它们保存在一个新对象中。

对象和数组的解构支持嵌套。嵌套解构可能有点令人困惑，但它是一个强大的工具，因为它允许我们将几行解构代码压缩成一行。

### 练习 10：嵌套解构

要使用嵌套解构概念从嵌套在对象内的数组中解构值，执行以下步骤:

1.  创建一个带有属性`arr`的对象，即设置为包含值`1`、`2`和`3`的数组。将对象保存到变量`data`中。

1.  将数组的第二个值解构为一个变量, 执行以下操作:

    从对象中解构`arr`属性，并将其保存到一个名为`v2`的新变量中，该变量为数组。用数组解构替换`v2`。

    在数组解构中，跳过第一个元素。将第二个元素保存到一个名为`v2`的变量中。

1.  记录变量。

**代码**

##### index.js:

```
const data = { arr: [ 1, 2, 3 ] };
const { arr: [ , v2 ] } = data;
console.log( v2 ); 
```

###### 代码片段 1.55: 嵌套数组和对象解构

[`bit.ly/2SJUba9`](https://bit.ly/2SJUba9)

**结果**

![图 1.12：嵌套解构输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.12.jpg)

###### 图 1.12：嵌套解构输出

您已成功地从对象内的数组中解构了值。

总之，对象和数组的解构是为了缩减代码，允许快速从对象和数组创建变量而引入到 ES6 中的。数组解构通过将一组变量设置为一组项目来表示。对象解构通过将一组变量设置为一组键值对的对象来表示。解构语句可以嵌套以获得更大的效果。 

### 练习 11：实现解构

您已经注册了大学课程，并需要购买课程所需的教材。 您正在构建一个程序，以从书单中抓取数据，并获取每本所需教材的 ISBN 号码。 使用对象和数组嵌套解构来获取课程数组中第一本书的第一本书的 ISBN 值。 课程数组遵循以下格式：

```
[
 {
   title: 'Linear Algebra II',
   description: 'Advanced linear algebra.',
   texts: [ {
     author: 'James Smith',
     price: 120,
     ISBN: '912-6-44-578441-0'
   } ]
 },
 { ... },
 { ... }
]
```

###### Snippet 1.56: 课程数组格式

通过使用嵌套解构来从复杂的数组和对象嵌套中获取数据，执行以下步骤：

1.  将提供的数据结构保存到`courseCatalogMetadata`变量中。

1.  将第一个数组元素解构为名为`course`的变量：

```
    [ course ] = [ … ]
    ```

1.  用对象解构替换`course`变量以将文本字段保存到名为`textbooks`的变量中：

```
    [ { texts: textbooks} ] = [ … ]
    ```

1.  用数组解构替换`textbooks`变量以获取文本数组的第一个元素并将其保存到名为`textbook`的变量中：

```
    [ { texts: [ textbook ] } ] = [ … ]
    ```

1.  用对象解构替换`textbook`变量以获取`ISBN`字段并将其保存到`ISBN`变量中：

```
    [ { texts: [ { ISBN } ] } ] = [ … ]
    ```

1.  记录`ISBN`的值。

**代码**

##### index.js：

```
const courseCatalogMetadata = [
 {
   title: 'Linear Algebra II',
   description: 'Advanced linear algebra.',
   texts: [ {
     author: 'James Smith',
     price: 120,
     ISBN: '912-6-44-578441-0'
   } ]
 }
];
const [ course ] = courseCatalogMetadata;
const [ { texts: textbooks } ] = courseCatalogMetadata;
const [ { texts: [ textbook ] } ] = courseCatalogMetadata;
const [ { texts: [ { ISBN } ] } ] = courseCatalogMetadata;
console.log( course );
console.log( textbooks );
console.log( textbook );
console.log( ISBN );
```

###### Snippet 1.57: 实现解构到代码中

[`bit.ly/2TMlgtz`](https://bit.ly/2TMlgtz)

**结果**

![图 1.13：数组解构输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.13.jpg)

###### 图 1.13：数组解构输出

您已成功使用解构和嵌套解构从数组和对象中获取了数据。

在本节中，我们讨论了数组和对象的解构赋值。 我们演示了如何使用数组和对象的解构赋值简化代码，并允许我们快速从对象和数组中提取值。 解构赋值允许我们从对象和数组中解包值，提供默认值，并在解构时将对象属性重命名为变量。 我们还介绍了两个新操作符——剩余和展开操作符。 剩余运算符用于表示数组的不定数量的参数。 展开运算符用于将可迭代对象分解为多个参数。

## 类和模块

在 ES6 中添加了类和模块。 类作为一种扩展基于原型的继承的方式，并添加了一些面向对象的概念。 模块作为一种组织 JavaScript 中多个代码文件的方式，并扩展了代码的可重用性和文件之间的作用域。

### 类

**类**主要作为语法糖添加到 ECMAScript 6 中，以扩展现有基于原型的继承结构。 类语法不会向 JavaScript 引入面向对象的继承。 JavaScript 中的类继承不像面向对象语言中的类那样工作。

在 JavaScript 中，可以使用关键字 class 来定义一个类。 使用关键字 class，后跟类名和大括号来创建一个类。 在大括号内，我们定义类的所有函数和逻辑。 语法如下：

```
class name { /* class stuff goes here */ }
```

###### Snippet 1.58: 类的语法

一个类可以用**可选函数构造函数**来创建。构造函数如果对 JavaScript 类不是必需的，但是一个类中只能有一个名为构造函数的方法。当实例化类时，会调用构造函数，并可用于设置所有默认的内部值。以下代码显示了一个类声明的示例：

```
class House{
  constructor(address, floors = 1, garage = false) {
    this.address = address;
    this.floors = floors;
    this.garage = garage;
  }
}
```

###### 代码段 1.59：基本类创建

在这个示例中，我们创建了一个名为`House`的类。我们的`House`类有一个`constructor`方法。当我们实例化类时，它调用构造函数。我们的构造函数方法接受三个参数，其中两个具有默认值。构造函数将这些值保存到`this`作用域中的变量中。

关键字 this 映射到每个类实例化。它是一个全局作用域的类对象。它用于在类内全局作用域中为所有函数和变量划定范围。在类的根部添加的每个函数都将添加到`this`作用域中。添加到`this`作用域的所有变量在类内任何函数中都可访问。此外，添加到`this`作用域的任何内容对于类外部是公开可访问的。

### 练习 12：创建自己的类

要创建一个简单的类并演示内部类变量，执行以下步骤：

1.  声明一个名为`Vehicle`的类。

1.  向类添加一个构造函数。使构造函数接收两个变量，`wheels`和`topSpeed`。

1.  在构造函数中，将输入变量保存到`this`作用域中的两个变量中，即`this.wheels`和`this.topSpeed`。

1.  用`wheels = 3`和`topSpeed = 20`实例化该类，并将其保存到`tricycle`变量中。

1.  从保存在`tricycle`中的类中记录`wheels`和`topSpeed`的值。

**代码**

##### index.js:

```
class Vehicle {
  constructor( wheels, topSpeed ) {
    this.wheels = wheels;
    this.topSpeed = topSpeed;
  }
}
const tricycle = new Vehicle( 3, 20 );
console.log( tricycle.wheels, tricycle.topSpeed );
```

###### 代码段 1.60：创建一个类

[`bit.ly/2FrpL8X`](https://bit.ly/2FrpL8X)

**结果**

![图 1.14：创建类的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.14.jpg)

###### 图 1.14：创建类的输出

您已成功创建了一个具有数值的简单类。

我们使用 new 关键字实例化了一个新类的实例。要创建一个新的类，只需声明一个变量并将其设置为表达式`new className()`。当我们实例化一个新类时，传递给类调用的参数将传递到构造函数中，如果存在的话。以下代码显示了一个类实例化的示例：

```
class House{
  constructor(address, floors = 1) {
    this.address = address;
    this.floors = floors;
  }
}
// Instantiate the class
let myHouse = new House( '1100 Fake St., San Francisco CA, USA', 2, false );
```

###### 代码段 1.61：类实例化

在此示例中，类的实例化发生在带有新关键字的行上。此行代码会创建`House`类的新实例并将其保存到`myHouse`变量中。当我们实例化类时，我们提供了`address`、`floors`和`garage`的参数。这些值被传递到构造函数中，然后保存到实例化的类对象中。

要向类中添加函数，我们使用新的 ES6 对象函数声明。快速提醒，当使用新的 ES6 对象函数声明时，可以省略函数关键字和对象键名。当函数添加到对象中时，它会自动附加到`this`范围内。此外，添加到类的所有函数都可以访问`this`范围，并能够调用附加到`this`范围的任何函数和访问任何变量。下面是一个示例：

```
class House{
  constructor( address, floors = 1) {
    this.address = address;
    this.floors = floors;
  }
  getFloors() {
    return this.floors;
  }
}
let myHouse = new House( '1100 Fake St., San Francisco CA, USA', 2 );
console.log( myHouse.getFloors() ); // Expected output: 2
```

###### 代码片段 1.62：创建带有函数的类

从这个例子中，我们可以看到两个函数`getFloors`和`setFloors`是使用 ES6 增强的对象属性语法添加的。这两个函数都可以访问`this`范围内的变量。它们可以获取和设置该范围内的变量，以及调用附加到`this`范围内的函数。

在 ES6 中，我们还可以使用`extends`关键字创建子类。**子类**继承自父类的属性和方法。子类的定义方式是在类名后面加上关键字`extends`和父类的名称。下面是一个子类声明的示例：

```
class House {}
class Mansion extends House {}
```

###### 代码片段 1.63：扩展类

### 类 - 子类

在这个例子中，我们将创建一个名为`House`的类，然后创建一个名为`Mansion`的子类，它扩展了类`House`。当我们创建一个子类时，我们需要注意构造方法的行为。如果我们提供了构造方法，那么我们必须调用`super()`函数。`super`是一个调用父对象的构造函数的函数。如果我们试图在不调用`super`的情况下访问`this`范围，那么我们将得到一个运行时错误，我们的代码将崩溃。可以将父构造函数所需的任何参数通过`super`方法传递进去。如果我们没有为子类指定构造函数，则默认的构造函数行为将自动调用 super 构造函数。下面是一个示例：

```
class House {
  constructor( address = 'somewhere' ) {
    this.address = address;
  }
}
class Mansion extends House {
  constructor( address, floors ) {
    super( address );
    this.floors = floors;
  }
}
let mansion = new Mansion( 'Hollywood CA, USA', 6, 'Brad Pitt' );
console.log( mansion.floors ); // Expected output: 6
```

###### 代码片段 1.64：带有和不带有构造函数的类的扩展

在这个例子中，我们创建了一个扩展了我们的`House`类的子类。`Mansion`子类有一个已定义的构造函数，所以我们必须在访问`this`范围之前调用 super。当我们调用`super`时，我们将地址参数传递给父构造函数，父构造函数会将其添加到`this`范围内。然后`Mansion`的构造函数继续执行并将楼层变量添加到`this`范围内。正如我们从此示例末尾的输出日志中看到的那样，子类的`this`范围还包括父类中创建的所有变量和函数。如果在子类中重新定义变量或函数，它将覆盖父类继承的值或函数。

总之，类使我们能够通过引入一些面向对象的概念来扩展 JavaScript 的基于原型的继承。类使用关键字`class`定义，并使用关键字`new`初始化。类定义时，会创建一个特殊的作用域，称为`this`，用于公开访问类外部的所有项目。我们可以将函数和变量添加到`this`作用域中，以赋予我们的类功能。当实例化类时，会调用构造函数。我们还可以扩展类以创建子类，使用关键字`extends`。如果扩展的类有一个构造函数，则必须调用 super 函数来调用其父类构造函数。子类可以访问父类的方法和变量。

### 模块

几乎每种编程语言都有模块的概念。**模块**是一种允许程序员将代码分解为更小的独立部分、并能够导入和重用的功能。模块对程序的设计至关重要，用于防止代码重复并减小文件大小。在 ES6 之前，原始 JavaScript 中并不存在模块。而且，并非所有 JavaScript 解释器都支持这一特性。

模块是从当前文件引用其他代码文件的一种方式。代码可以分成多个部分，称为**模块**。模块可以让我们将不相关的代码分开，这样我们在大型 JavaScript 项目中就可以拥有更小、更简单的文件。

模块还允许包含的代码快速、轻松地共享，而不会出现任何代码重复。ES6 中的模块引入了两个新关键字，`export`和`import`。这些关键字允许我们在加载文件时公开特定的类和变量。

#### 注意

JavaScript 模块在所有平台上都没有完全支持。在编写本书时，并非所有 JavaScript 框架都能支持模块。确保您发布代码的平台能够支持您编写的代码。

### 导出关键字

模块使用`export`关键字来公开文件中包含的变量和函数。ES6 模块中的所有内容默认都是私有的。唯一使任何内容公开的方式是使用导出关键字。模块可以通过**具名导出**或**默认导出**方式导出属性。具名导出允许模块多次导出。如果正在构建一个导出许多函数和常量的数学模块，则多次导出可能会很有用。默认导出则允许每个模型只有一个单一的导出。如果正在构建一个包含一个单一类的模块，则单一的导出可能会很有用。

使用`export`关键字公开模块的具名内容有两种方式。我们可以通过在变量或函数声明之前加上`export`关键字来逐个导出每个项目，或者我们可以导出一个包含键值对的对象，引用我们想要导出的每个变量和函数。这两种导出方法在以下示例中显示：

```
// math-module-1.js
export const PI = 3.1415;
export const DEGREES_IN_CIRCLE = 360;
export function convertDegToRad( degrees ) {
  return degrees * PI / ( DEGREES_IN_CIRCLE /2 );
}
// math-module-2.js
const PI = 3.1415;
const DEGREES_IN_CIRCLE = 360;
function convertDegToRad( degrees ) {
  return degrees * PI / ( DEGREES_IN_CIRCLE /2 );
}
export { PI, DEGREES_IN_CIRCLE, convertDegToRad };
```

###### 代码片段 1.65：命名导出

在前面的示例中概述的两个模块中，每个模块都导出三个常量变量和一个函数。第一个模块`math-module-1.js`逐个导出每个项目。第二个模块`math-module-2.js`通过对象一次性导出所有导出项。

要将模块的内容作为默认导出，我们必须使用**default** **关键字**。`default`关键字在`export`关键字之后。当我们默认导出一个模块时，我们也可以省略正在导出的类、函数或变量的标识符名称。下面的代码示例中演示了这个例子：

```
// HouseClass.js
export default class() { /* Class body goes here */ }
// myFunction.js
export default function() { /* Function body goes here */ }
```

###### 代码片段 1.66：默认导出

在前面的示例中，我们创建了两个模块。一个模块导出一个类，另一个导出一个函数。请注意在`export`关键字后加入`default`关键字，以及如何省略类/函数的名称。当我们导出一个默认类时，`export`是无名的。当我们导入默认导出模块时，我们导入的对象名称是通过模块的名称派生的。下一节将展示这一点，在那里我们将讨论`import`关键字。

### 导入关键字

`import`关键字允许您导入 JavaScript 模块。导入模块允许您将该模块中的任何项导入到当前的代码文件中。当我们导入一个模块时，我们以`import`关键字开始表达式。然后，我们确定要从模块中导入的部分。然后，我们跟着`from`关键字，最后完成模块文件的路径。`from`关键字和文件路径告诉解释器在哪里找到我们要导入的模块。

#### 注意

ES6 模块可能在所有浏览器版本或 Node.js 版本中都不受全面支持。您可能需要使用诸如 Babel 之类的转译器来在某些平台上运行您的代码。

我们可以使用`import`关键字的四种方式，所有这些方式都在以下代码中展示：

```
// math-module.js
export const PI = 3.1415;
export const DEGREES_IN_CIRCLE = 360;
// index1.js
import { PI } from 'math-module.js'
// index2.js
import { PI, DEGREES_IN_CIRCLE } from 'math-module.js'
// index3.js
import { PI as pi, DEGREES_IN_CIRCLE as degInCircle } from 'math-module.js'
// index4.js
import * as MathModule from 'math-module.js'
```

###### 代码片段 1.67：导入模块的不同方式

在上面代码中展示的代码中，我们创建了一个简单的模块，导出了几个常量和四个导入示例文件。在第一个`import`示例中，我们从模块导出中导入一个单个值，并使其在变量 API 中可以访问。在第二个`import`示例中，我们从模块中导入多个属性。在第三个示例中，我们导入属性并将它们重命名为新的变量名。然后可以从新变量中访问这些属性。在第四个示例中，我们使用了略有不同的语法。星号表示我们要从模块中导入所有导出的属性。当我们使用星号时，我们还必须使用`as`关键字给导入的对象赋予一个变量名。

导入和使用模块的过程通过以下代码片段更好地进行解释：

```
// email-callback-api.js
export function authenticate( … ){ … }
export function sendEmail( … ){ … }
export function listEmails( … ){ … }
// app.js
import * as EmailAPI from 'email-callback-api.js';
const credentials = { password: '****', user: 'Zach' };
EmailAPI.authenticate( credentials, () => {
  EmailAPI.send( { to: 'ceo@google.com', subject: 'promotion', body: 'Please promote me' }, () => {} );'
} );
```

###### 代码片段 1.68：导入模块

要在浏览器中使用导入，我们必须使用`script`标记。模块导入可以内联完成，也可以通过源文件完成。要导入一个模块，我们需要创建一个`script`标记并将 type 属性设置为`module`。如果我们通过源文件进行导入，我们必须将`src`属性设置为文件路径。下面的语法展示了这一点：

```
<script type="module" src="img/module.js"></script>
```

###### 代码片段 1.69：内联浏览器导入

#### 注意

脚本标记是一个 HTML 标记，允许我们在浏览器中运行 JavaScript 代码。

我们还可以内联导入模块。要做到这一点，我们必须省略`src`属性，并直接在脚本标记的主体中编写导入。下面的代码展示了这一点：

```
<script type="module">
  import * as ModuleExample from './path/to/module.js';
</script>
```

###### 代码片段 1.70：在脚本主体中导入浏览器

#### 注意

在浏览器中导入模块时，不支持 ES6 模块的浏览器版本不会运行 type="module"的脚本。

如果浏览器不支持 ES6 模块，我们可以使用`nomodule`属性提供一个回退选项。模块兼容的浏览器会忽略带有`nomodule`属性的脚本标记，因此我们可以使用它来提供回退支持。下面的代码展示了这一点：

```
<script type="module" src="img/es6-module-supported.js"></script>
<script nomodule src="img/es6-module-NOT-supported.js"></script>
```

###### 代码片段 1.71：兼容选项的浏览器导入

在前面的例子中，如果浏览器支持模块，那么第一个脚本标记将被运行，第二个则不会。如果浏览器不支持模块，那么第一个脚本标记将被忽略，第二个将被运行。

模块的最后一个考虑: 要小心构建的任何模块不要有循环依赖。由于模块的加载顺序，JavaScript 中的循环依赖可能在 ES6 转译为 ES5 时导致许多逻辑错误。如果你的模块存在循环依赖，你应该重构你的依赖树，以便所有的依赖都是线性的。例如，考虑依赖链: 模块 A 依赖于 B，模块 B 依赖于 C，模块 C 依赖于 A。这是一个循环模块链，因为通过依赖链，A 依赖于 C，C 依赖于 A。代码应该重新构造，以打破循环依赖链。

### 练习 13：实现类

你被一家汽车销售公司聘用，设计他们的销售网站。你必须创建一个车辆类来存储汽车信息。类必须接受汽车制造商、型号、年份和颜色。汽车应该有一个更改颜色的方法。为了测试这个类，创建一个灰色（颜色）2005（年份）斯巴鲁（制造商）Outback（型号）的实例。记录汽车的变量，更改汽车的颜色，并记录新的颜色。

要构建一个功能类来展示一个类的能力，执行以下步骤：

1.  创建一个`car`类。

    添加一个构造函数，它接受`make`、`model`、`year`和`color`。在构造函数中的内部变量（`this`范围）中保存`make`、`model`、`year`和`color`。

    添加一个名为`setColor`的函数，它接受一个参数 color，并更新内部变量`color`为提供的颜色。

1.  用参数`Subaru`、`Outback`、`2005`和`Grey`来实例化这个类。将这个类保存在`Subaru`变量中。

1.  记录在`Subaru`中存储的类的内部变量，即`make`、`model`、`year`和`color`。

1.  用`Subaru`类方法的`setColor`改变颜色。将颜色设置为`Red`。

1.  记录新的颜色。

**代码**

##### index.js:

```
class Car {
 constructor( make, model, year, color ) {
   this.make = make;
   this.model = model;
   this.year = year;
   this.color = color;
 }
 setColor( color ) {
   this.color = color;
 }
}
let subaru = new Car( 'Subaru', 'Outback', 2005, 'Grey' );
subaru.setColor( 'Red' );
```

###### 代码片段 1.72：完整的类实现

[`bit.ly/2FmaVRS`](https://bit.ly/2FmaVRS)

**结果**

![图 1.15：实现类的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.15.jpg)

###### 图 1.15：实现类的输出

你已经成功构建了一个功能性的类。

在这一部分，我们介绍了 JavaScript 类和 ES6 模块。我们讨论了基于原型的继承结构，并演示了类的基本创建和 JavaScript 类继承的基础知识。在讨论模块时，我们首先展示了如何创建一个模块并导出其中存储的函数和变量。然后，我们展示了如何加载一个模块并导入其中包含的数据。我们以讨论浏览器兼容性并提供支持尚不支持 ES6 模块的浏览器的 HTML 脚本标签选项来结束这个话题。

## 转译

**转译**被定义为源到源的编译。已经写了工具来做这件事，它们被称为转译器。**转译器**接受源代码并将其转换成另一种语言。转译器的重要性有两个原因。首先，不是每个浏览器都支持 ES6 中的每种新语法，其次，许多开发者使用基于 JavaScript 的编程语言，比如 CoffeeScript 或 TypeScript。

#### 注释

ES6 兼容性表可以在[`kangax.github.io/compat-table/es6/`](https://kangax.github.io/compat-table/es6/)找到。

查看 ES6 浏览器兼容性表清楚地告诉我们在支持上存在一些漏洞。转译器允许我们用 ES6 编写我们的代码并将其转换成普通的 ES5，在每个浏览器中都可以运行。确保我们的代码在尽可能多的 Web 平台上正常工作至关重要。对于确保兼容性，转译器可以是一个非常有用的工具。

转译器还允许我们用其他编程语言开发 Web 或服务器端应用程序。像 TypeScript 和 CoffeeScript 这样的语言可能无法在浏览器中原生运行；然而，通过转译器，我们可以用这些语言构建完整的应用程序，并将它们转换成 JavaScript 以便在服务器端或浏览器中执行。

JavaScript 最流行的转译器之一是**Babel**。Babel 是一个旨在协助不同版本 JavaScript 之间的转译的工具。Babel 可以通过 node 包管理器（npm）安装。首先，打开你的终端并进入包含 JavaScript 项目的文件夹。

如果在这个目录中没有`package.json`文件，那么我们必须创建它。可以使用`npm init`命令完成。命令行界面将询问您输入几个条目，以便您填写`package.json`文件的默认值。您可以输入这些值，也可以直接按回车键接受默认值。

要安装 Babel 命令行界面，使用以下命令：`npm install --save-dev babel-cli`。完成后，`package.json`文件的`devDependencies`对象中将会添加`babel-cli`字段：

```
{
 "devDependencies": {
   "babel-cli": "^6.26.0"
 }
}
```

###### 片段 1.73：添加第一个依赖

这个命令只安装了基本的 Babel，没有用于在不同版本的 JavaScript 之间进行转译的插件。要安装插件以转译到 ECMAScript 2015，使用命令`npm install --save-dev babel-preset-es2015`。一旦命令运行完毕，我们的`package.json`文件将包含另一个依赖：

```
"devDependencies": {
 "babel-cli": "^6.26.0",
 "babel-preset-es2015": "^6.24.1"
}
```

###### 片段 1.74：添加第二个依赖

这安装了 ES6 预设。要使用这些预设，我们必须告诉 Babel 使用这些预设进行配置。创建一个名为`.babelrc`的文件。注意文件名中的前导句号。`.babelrc`文件是 Babel 的配置文件。这是我们告诉 Babel 我们将使用哪些预设、插件等的地方。创建完成后，在文件中添加以下内容：

```
{
  "presets": ["es2015"]
}
```

###### 片段 1.75：安装 ES6 预设

### Babel-转译

现在 Babel 已经配置好了，我们必须创建要转译的代码文件。在项目的根目录中，创建一个名为`app.js`的文件。在这个文件中，粘贴以下 ES6 代码：

```
const sum5 = inputNumber  => inputNumber + 5;
console.log( `The sum of 5 and 5 is ${sum5(5)}!`);
```

###### 片段 1.76：粘贴代码

现在 Babel 已经配置好了，我们有了一个要转译的文件，我们需要更新我们的`package.json`文件，为 npm 添加一个转译脚本。在`package.json`文件中添加以下行：

```
"scripts": {
 "transpile": "babel app.js --out-file app.transpiled.js --source-maps"
}
```

###### 片段 1.77：更新 package.json 文件

脚本对象允许我们从 npm 运行这些命令。我们将命名 npm 脚本为`transpile`，它将运行命令链`babel app.js --out-file app.transpiled.js --source-maps`。`App.js`是我们的输入文件。`--out-file`命令指定了编译的输出文件。`App.transpiled.js`是我们的输出文件。最后，`--source-maps`创建了一个源映射文件。这个文件告诉浏览器转译代码的哪一行对应原始源代码的哪几行。这让我们能够直接在原始源文件`app.js`中进行调试。

现在一切都设置好了，我们可以通过在终端窗口输入`npm run transpile`来运行我们的转译脚本。这将把我们的代码从`app.js`转译成`app.transpiled.js`，根据需要创建或更新文件。检查后，我们可以看到`app.transpiled.js`中的代码已转换为 ES5 格式。您可以在两个文件中运行代码，看到输出是一样的。

Babel 有许多插件和不同模块和 JavaScript 发布的预设。有足够的方法设置和运行 Babel，我可以写一整本关于它的书。这只是将 ES6 代码转换为 ES5 的一个小预览。要获取有关 Babel 的完整文档和每个插件用途的信息，请访问文档。

#### 注意

查看 Babel 的主页 [`babeljs.io`](https://babeljs.io)。

总之，转译器允许你做源码到源码的编译。这非常有用，因为它让我们在需要部署在尚不支持 ES6 的平台上时将 ES6 代码编译为 ES5。最受欢迎和最强大的 JavaScript 转译器是 Babel。可以在命令行上设置 Babel 来允许我们使用不同版本的 JavaScript 构建整个项目。

### 练习 14: 转译 ES6 代码

你的办公室团队用 ES6 编写了你的网站代码，但一些用户正在使用的设备不支持 ES6\. 这意味着你必须要么用 ES5 重写整个代码库，要么使用转译器将其转换为 ES5\. 将*升级箭头函数*部分中的 ES6 代码转换为 ES5 并通过 Babel 运行原始代码和转译后的代码并比较输出。

为了演示 Babel 将 ES6 代码转换为 ES5 的能力，请执行以下步骤：

在开始之前，请确保 Node.js 已经安装。

1.  如果尚未安装 Node.js，请安装它。

1.  使用命令行命令 `npm init` 设置一个 Node.js 项目。

1.  将*升级箭头函数*部分的代码放入 `app.js` 文件。

1.  用 `npm install` 安装 Babel 和 Babel ES6 插件。

1.  通过添加一个带有 es2015 预设的 `.babelrc` 文件来配置 Babel。

1.  在 `package.json` 中添加一个调用 Babel 并从 `app.js` 转译到 `app.transpiled.js` 的转译脚本。

1.  运行转译脚本。

1.  运行 `app.transpiled.js` 中的代码。

**Code**

##### package.json:

```
// File 1: package.json
{
 "scripts": {
   "transpile": "babel ./app.js --out-file app.transpiled.js --source-maps"
 },
 "devDependencies": {
   "babel-cli": "^6.26.0",
   "babel-preset-es2015": "^6.24.1"
 }
}
```

###### Snippet 1.78: Package.json 配置文件

[`bit.ly/2FsjzgD`](https://bit.ly/2FsjzgD)

##### .babelrc:

```
// File 2: .babelrc
{ "presets": ["es2015"] }
```

###### Snippet 1.79: Babel 配置文件

[`bit.ly/2RMYWSW`](https://bit.ly/2RMYWSW)

##### app.transpiled.js:

```
// File 3: app.transpiled.js
var fn1 = function fn1(a, b) { … };
var fn2 = function fn2(a, b) { … };
var fn3 = function fn3(a) { … };
var fn4 = function fn4() { … };
var fn5 = function fn5(a) { … };
```

###### Snippet 1.80: 完全转译的代码

[`bit.ly/2TLhuR7`](https://bit.ly/2TLhuR7)

**Outcome**

![图 1.16: 转译后的脚本输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.16.jpg)

###### 图 1.16: 转译后的脚本输出

你已成功实现了 Babel 将代码从 ES6 转换为 ES5 的能力。

在本节中，我们讨论了转译的概念。我们介绍了转译器 Babel，并讨论了如何安装 Babel。我们讨论了设置 Babel 将 ES6 转译为 ES5 兼容代码的基本步骤，并在活动中构建了一个简单的 Node.js 项目，其中包含 ES6 代码来测试 Babel。

## 迭代器和生成器

**迭代器** 和 **生成器** 的最简形式，都是处理集合数据的两种渐进式方式。它们通过跟踪集合的状态而不是集合中的所有项目来提高效率。

### 迭代器

**迭代器**是遍历集合中数据的一种方式。遍历数据结构意味着按顺序遍历每个元素。例如，`for/in`循环是用于遍历 JavaScript 对象中键的方法。当迭代器知道如何从集合中一次访问其项目时，它就是一个迭代器，同时跟踪位置和完成状态。迭代器可用于遍历自定义复杂数据结构或用于遍历可能一次加载不太实际的大数据块。

要创建一个迭代器，我们必须定义一个以集合为参数的函数，并返回一个对象。返回的对象必须具有一个名为`next`的函数属性。当调用`next`时，迭代器将跳到集合中的下一个值，并返回一个具有值和迭代状态的对象。以下是示例迭代器的代码：

```
function createIterator( array ){
  let currentIndex = 0;
  return {
    next(){
      return currentIndex < array.length ?
        { value: array[ currentIndex++ ], done: false} :
        { done: true };
    }
  };
}
```

###### 代码段 1.81：迭代器声明

此迭代器接受一个数组，并返回一个具有单个函数属性`next`的对象。在内部，迭代器跟踪数组和我们当前正在查看的索引。要使用迭代器，我们只需调用`next`函数。调用`next`将导致迭代器返回一个对象，并将内部索引增加一。迭代器返回的对象必须至少具有`value`和`done`两个属性。`value`将包含我们当前查看索引处的值。`Done`将包含一个布尔值。如果布尔值为 true，则我们已经**在**输入集合上完成了遍历。如果为**假**，那么我们可以继续调用`next`函数：

```
// Using an iterator 
let it = createIterator( [ 'Hello', 'World' ] );
console.log( it.next() );
// Expected output: { value: 'Hello', done: false }
console.log( it.next() );
// Expected output: { value: 'World' , done: false }
console.log( it.next() );
// Expected output: { value: undefined, done: true }
```

###### 代码段 1.82：迭代器使用

#### 注意

当迭代器的`finality`属性为真时，不应返回任何新数据。为了演示`iterator.next()`的使用，你可以提供前面代码段中的示例。

总之，迭代器为我们提供了一种遍历可能复杂的数据集合的方法。迭代器跟踪其当前状态，每次调用`iterator.next()`函数时，它都会提供一个具有值和完成状态布尔值的对象。当迭代器到达集合的末尾时，调用`iterator.next()`将返回一个真值完成参数，并且将不再接收新值。

### 生成器

**生成器**提供了一种迭代构建数据集合的方法。生成器可以一次返回一个值，同时暂停执行，直到请求下一个值。生成器跟踪内部状态，每次请求时，它都会返回序列中的新数字。

要创建一个`生成器`，我们必须在函数名前面加上星号，并在函数体中使用`yield`关键字。例如，要创建名为`testGenerator`的生成器，我们可以按如下方式初始化它：

```
function *testGen( data ) { yield 0; }.
```

星号表示这是一个`生成器函数`。`yield`关键字表示正常函数流程的中断，直到生成器函数再次被调用。下面是一个生成器的示例：

```
function *gen() {
 let i = 0;
 while (true){
   yield i++;
 }
}
```

###### 代码段 1.83：生成器创建

我们在前面的代码段中创建的这个`生成器`函数，称为`gen`，有一个名为`i`的内部状态变量。当创建`生成器`时，它会自动初始化一个内部的 next 函数。当第一次调用`next`函数时，执行开始，循环开始，当执行到`yield`关键字时，函数的执行被停止，直到再次调用 next 函数。当调用`next`函数时，程序将返回一个包含值和`done`的对象。

### 练习 15：创建一个生成器

创建一个生成器函数，生成 2n 序列的值，以展示生成器如何构建一组连续的数据，执行以下步骤：

1.  创建一个名为`gen`的`生成器`。

    在标识符名称前面加上一个星号。

1.  在生成器主体内部，执行以下步骤：

    创建一个名为`i`的变量，将初始值设为 1。然后，创建一个无限循环。

    在 while 循环体中，使用`yield` `i`，并将`i`设置为`i * 2`。

1.  初始化`gen`并将其保存到名为`generator`的变量中

1.  多次调用你的`生成器`并记录输出，以查看值的变化。

**代码**

##### index.js：

```
function *gen() {
 let i = 1;
 while (true){
   yield i;
   i = i * 2;
 }
}
const generator = gen();
console.log( generator.next(), generator.next(), generator.next() );
```

###### 代码段 1.84：简单生成器

[`bit.ly/2VK7M3d`](https://bit.ly/2VK7M3d)

**结果**

![图 1.17：调用生成器输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.17.jpg)

###### 图 1.17：调用生成器输出

你已成功创建了一个生成器函数。

与迭代器类似，`done`值包含生成器的完成状态。如果`done`值设置为`true`，那么生成器已经执行完毕，不会再返回新的值。值参数包含了`yield`关键字所在行的表达式的结果。在这种情况下，它将返回`i`的当前值，然后再递增。下面的代码中展示了这一点：

```
let sequence = gen();
console.log(sequence.next());
//Expected output: { value: 0, done: false }
console.log(sequence.next());
//Expected output: { value: 1, done: false }
console.log(sequence.next());
//Expected output: { value: 2, done: false }
```

###### 代码段 1.85：生成器使用

当生成器遇到`yield`关键字时，执行会暂停。这意味着循环会暂停执行。生成器的另一个强大工具是可以通过 next 函数和`yield`关键字传入数据。当将一个值传递给 next 函数时，`yield`表达式的返回值将被设置为传递给 next 的值。下面的代码展示了一个例子：

```
function *gen() {
 let i = 0;
 while (true){
   let inData = yield i++;
   console.log( inData );
 }
}
let sequence = gen();
sequence.next()
sequence.next( 'test1' )
sequence.next()
sequence.next( 'test2' )
// Expected output:
// 'test1'
// undefined
// 'test2'
```

###### 代码段 1.86 Yield 关键字

总之，生成器是构建数据集的迭代方式。它们一次返回一个值，同时跟踪内部状态。当达到`yield`关键字时，内部执行停止并返回一个值。当调用`next`函数时，执行恢复，直到达到`yield`。数据可以通过`next`函数传递给生成器。通过`yield`表达式返回传入的数据。当生成器发出一个值对象，并将`done`参数设置为 true 时，对`generator.next()`的调用不应产生任何新的值。

在最后一个主题 I 中，我们介绍了迭代器和生成器。迭代器遍历数据集合中的数据，并在每一步返回请求的值。一旦它们到达集合的末尾，`done`标志将设置为 true，并且不会再迭代新的项目。生成器是一种生成数据集合的方法。在每一步中，生成器根据其内部状态产生一个新值。迭代器和生成器都在它们的生命周期中跟踪它们的内部状态。

### 活动 1：实现生成器

您被要求构建一个简单的应用程序，根据请求生成斐波那契数列中的数字。该应用程序为每个请求生成序列中的下一个数字，并在给定输入时重置序列。使用生成器生成斐波那契数列。如果将一个值传递给生成器，则重置序列。

使用生成器构建复杂的迭代数据集，执行以下步骤：

1.  查找斐波那契数列。

1.  创建一个生成器，提供斐波那契数列中的值。

1.  如果生成器的`yield`语句返回一个值，则重置序列。

**结果**

![图 1.18：实现生成器输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-js/img/Figure_1.18.jpg)

###### 图 1.18：实现生成器输出

您已成功创建了一个可以用来基于斐波那契数列构建迭代数据集的生成器。

#### 注意

此活动的解决方案可在第 280 页找到。

## 总结

在本章中，我们看到 ECMAScript 是现代 JavaScript 的脚本语言规范。ECMAScript 6，或 ES6，于 2015 年发布。通过本章，我们涵盖了 ES6 的一些关键点及其与以前版本 JavaScript 的区别。我们强调了变量作用域的规则，声明变量的关键字，箭头函数语法，模板文字，增强的对象属性表示法，解构赋值，类和模块，转译和迭代器和生成器。您已经准备好将这些知识应用于您的专业 JavaScript 项目。

在下一章中，我们将学习什么是异步编程语言，以及如何编写和理解异步代码。
