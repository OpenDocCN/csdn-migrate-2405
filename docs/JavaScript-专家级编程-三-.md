# JavaScript 专家级编程（三）

> 原文：[`zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD`](https://zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：模块化 JavaScript

## 学习目标

在本章结束时，您将能够：

+   在 JavaScript 中导入和导出函数和对象以实现代码的可重用性

+   使用 JavaScript ES6 类来减少代码复杂性

+   在 JavaScript 中实现面向对象编程概念

+   使用封装为对象创建私有变量

+   使用 Babel 将 ES6 转换为通用 JavaScript

+   在 JavaScript 中创建和发布 npm 包

+   使用组合性和策略结合模块创建更高级的模块。

在本章中，我们将学习现代 JavaScript 中可重用代码的重要性，以及 ES6 如何引入了用于轻松创建和使用模块的语法。我们将创建一个 JavaScript 模块，可以被 API 的不同端点导入和使用。

## 介绍

在上一章中，我们使用 Node.js 和 Express 构建了一个 API。我们讨论了设计 API 结构、HTTP 方法和**JSON Web Token**（**JWT**）身份验证。在本章中，我们将研究 JavaScript 模块和基于模块的设计的各个方面。

模块对于编程生产力很重要，将软件分解为可重用的模块。模块化设计鼓励开发人员将软件构建成小的、单一焦点的组件。您可能熟悉流行的 UI 库，如 Bootstrap、Material-UI 和 jQuery UI。这些都是一组组件 - 专门构建的最小图形元素，可以在许多情况下使用。

由于广泛使用外部库来处理图形元素和编程方面，大多数开发人员已经熟悉了模块的使用。也就是说，使用模块比创建模块或以模块化方式编写应用程序要容易得多。

#### 注意组件、模块和 ES6 模块

关于这些术语的确切用法和关系有各种不同的观点。在本章中，我们将组件称为可以在网站上使用的视觉小部件。

我们将把一个模块称为在一个文件中编写的源代码，以便在另一个文件中导入和使用。由于大多数组件都存在为可重用代码，通常通过脚本标签导入，我们将把它们视为模块。当然，当您导入 Bootstrap 库时，您导入了所有组件。也就是说，大多数库都提供了编译和导入所需的特定组件的能力 - 例如，[`getbootstrap.com/docs/3.4/customize/`](https://getbootstrap.com/docs/3.4/customize/)。

当我们提到 ES6 模块时，我们指的是 ES6 中添加的特定语法，允许在一个文件中导出一个模块，并在另一个文件中导入它。虽然 ES6 模块是 ES6 标准的一部分，但重要的是要记住它们目前不受浏览器支持。使用它们需要一个预编译步骤，我们将在本章中介绍。

JavaScript 的受欢迎程度和生产力的最近爆炸部分原因是**node 包管理器**（**npm**）生态系统。无论是使用 JavaScript 进行前端还是后端开发，您都可能在某个时候使用 npm。通过简单的`npm install`命令，开发人员可以获得数百个有用的包。

npm 现在已成为互联网上模块化代码的最大来源，超过任何编程语言。npm 现在包含了将近 50 亿个包。

npm 上的所有包本质上都是模块。通过将相关函数分组为一个模块，我们使得该功能可以在多个项目或单个项目的多个方面中重复使用。

所有在 npm 上的优秀包都是以一种使其在许多项目中易于重用的方式构建的。例如，一个很好的日期时间选择器小部件可以在成千上万个项目中使用，节省了许多开发时间，并且可能产生更好的最终产品。

在本节中，我们将讨论模块化的 JavaScript 以及如何通过以模块化的方式编写 JavaScript 来改进我们的代码。这包括导出和导入的基本语法，但除此之外，还有几种模式和技术可用于编写更好的模块，例如在模块开发中有用的面向对象编程的概念。然而，JavaScript 在技术上是原型导向的，这是一种与经典面向对象风格不同的特定风格的面向对象编程，它使用原型而不是类。我们将在本章后面讨论原型和类。

### 依赖关系和安全性

模块是一种强大的技术，但如果不小心使用，它们也可能失控。例如，添加到`node.js`项目中的每个包都包含自己的依赖关系。因此，重要的是要密切关注您正在使用的包，以确保您不会导入任何恶意内容。在网站[`npm.broofa.com`](http://npm.broofa.com)上有一个有用的工具，您可以在那里上传`package.json`文件并获得依赖关系的可视化。

如果我们以*第一章练习 1，使用 Express 创建项目并添加索引路由*中的`package.json`文件为例，它只包含四个`dependencies`：

```js
  "dependencies": {
   "express": "⁴.16.4",
   "express-validator": "⁵.3.1",
   "jwt-simple": "⁰.5.6",
   "mongodb": "³.2.3"
  }
```

然而，当我们上传这个`package.json`文件时，我们可以看到我们的 4 个依赖项在考虑子依赖时激增到了 60 多个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_01.jpg)

###### 图 5.1：package.json 中的 61 个依赖项

这突显了基于模块的设计所带来的风险，以及在制作和使用模块时需要深思熟虑的设计。糟糕编写的包或模块可能会产生意想不到的后果。近年来，有关广泛使用的包变得恶意的报道。例如，`event-stream`包在 2018 年的 2.5 个月内被下载了 800 多万次。发现这个曾经合法的模块已经更新，试图从用户的机器中窃取加密货币。除了安全风险和错误之外，还存在污染全局命名空间或降低父项目性能的风险。

#### 注意 npm audit

作为对恶意依赖或子依赖的情况的回应，npm 添加了一个`audit`命令，可以用来检查包的依赖关系，以查看已知为恶意的模块。在 Node.js 项目的目录中运行`npm audit`来检查项目的依赖关系。当您安装从 GitHub 等地方下载的项目时，该命令也会自动作为`npm install`的一部分运行。

### 模块化的其他成本

与模块化设计相关的其他成本包括：

+   加载多个部分的成本

+   坏模块的成本（安全性和性能）

+   使用的模块总量迅速增加

总的来说，这些成本通常是可以接受的，但应该谨慎使用。当涉及到加载许多模块所带来的开销时，预编译器（如`webpack`和`babel`）可以通过将整个程序转换为单个文件来帮助。

在创建模块或导入模块时需要牢记以下几点：

+   使用模块是否隐藏了重要的复杂性或节省了大量的工作？

+   模块是否来自可信任的来源？

+   它是否有很多子依赖？

以 npm 包`isarray`为例。该包包含一个简单的函数，只是运行：

```js
return toString.call(arr) == '[object Array]';
```

这是一个例子，第一个问题的答案是“使用模块是否隐藏了重要的复杂性？”不是。第二个问题 - “它是来自可信任的来源吗？”并不特别。最后，对于关于子依赖的最后一个问题的回答是不是 - 这是一件好事。鉴于这个模块的简单性，建议根据前面的单行编写自己的函数。

应避免随意安装增加项目复杂性而几乎没有好处的包。如果您考虑到了提到的三点，您可能不会觉得值得导入诸如`isarray`之类的包。

### 审查进口和出口

在上一节中，我们使用了导入和导出，但没有深入讨论这个主题。每当我们创建一个新的路由时，我们都会确保将其放在`routes`文件夹中的自己的文件中。如果您还记得，我们所有的路由文件都以导出`router`对象的行结束：

```js
module.exports = router;
```

我们还使用了 Node.js 内置的`require`函数来使用我们的路由：

```js
let light = require('./routes/devices/light');
```

### 关注点分离

在设计模块时，关键概念之一是**关注点分离**。关注点分离意味着我们应该将软件分成处理程序的单个关注点的部分。一个好的模块将专注于很好地执行单个功能方面。流行的例子包括：

+   MySQL - 一个具有多种方法连接和使用 MySQL 数据库的包

+   Lodash - 一个用于高效解析和处理数组、对象和字符串的包

+   Moment - 一个用于处理日期和时间的流行包

在这些包或我们自己的项目中，通常还会进一步分成子模块。

#### 注意 ES6

在之前的章节中，我们已经使用了一些 ES6 的特性，但是作为提醒，ES6，或者更长的 ECMAScript，是欧洲计算机制造商协会脚本的缩写。ECMA 是负责标准化标准的组织，包括 2015 年标准化的新版本 JavaScript。

## ES6 模块

在使用 Node.js 编写 JavaScript 时，长期以来一直使用内置的`require()`函数来导入模块的能力。由于这个功能很有用，许多前端开发人员开始利用它，通过使用诸如 Babel 之类的编译器对他们的 JavaScript 进行预处理。JavaScript 预编译器处理通常无法在大多数浏览器上运行的代码，并生成一个兼容的新 JavaScript 文件。

由于 JavaScript 中对导入样式函数的需求很大，它最终被添加到了 ES6 版本的语言中。在撰写本文时，大多数浏览器的最新版本几乎完全兼容 ES6。然而，不能认为使用`import`是理所当然的，因为许多设备将继续运行多年前的旧版本。

ES6 的快速标准化告诉我们，未来，ES6 的导入将是最流行的方法。

在上一章中，我们使用了 Node.js 的`require`方法来导入模块。例如，看看这一行：

```js
const express = require('express');
```

另一方面，ES6 的`import`函数具有以下语法：

```js
import React from 'react';
```

ES6 的`import`函数还允许您导入模块的子部分，而不是整个模块。这是 ES6 的`import`相对于 Node.js 的`require`函数的一个能力。导入单个组件有助于节省应用程序中的内存。例如，如果我们只想使用 React 版本的 Bootstrap 中的`button`组件，我们可以只导入那个：

```js
import { Button } from 'reactstrap';
```

如果我们想要导入额外的组件，我们只需将它们添加到列表中：

```js
import { Button, Dropdown, Card } from 'reactstrap';
```

#### 注意 React

如果您曾经使用过流行的前端框架 React，您可能已经看到过这种导入方式。该框架以模块化为重点而闻名。它将交互式前端元素打包为组件。

在传统的纯 JavaScript/HTML 中，项目通常被分成 HTML/CSS/JavaScript，各种组件分散在这些文件中。相反，React 将元素的相关 HTML/CSS/JavaScript 打包到单个文件中。然后将该组件导入到另一个 React 文件中，并在应用程序中用作元素。

### 练习 22：编写一个简单的 ES6 模块

#### 注意

本章有一个起始点目录，可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/start`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/start)找到。

此练习的完成代码可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise22`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise22)找到。

在这个练习中，我们将使用 ES6 语法导出和导入一个模块：

1.  切换到`/Lesson_05/start/`目录；我们将使用这个作为起点。

1.  使用`npm install`安装项目依赖项。

1.  创建`js/light.js`文件，其中包含以下代码：

```js
let light = {};
light.state = true;
light.level = 0.5;
var log = function () {
  console.log(light);
};
export default log;
```

1.  打开名为`js/viewer.js`的文件。这是将在我们页面上运行的 JavaScript。在文件顶部添加：

```js
import light from './light.js';
```

1.  在`js/viewer.js`的底部，添加：

```js
light();
```

1.  `js/viewer.js`已经包含在`index.html`中，所以现在我们可以使用`npm start`启动程序。

1.  在服务器运行时，打开一个 Web 浏览器，转到`localhost:8000`。一旦到达那里，按下*F12*打开开发者工具。

如果您做得没错，您应该在 Google Chrome 控制台中看到我们的对象被记录：

![图 5.2：在 Google Chrome 控制台中记录的对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_02.jpg)

###### 图 5.2：在 Google Chrome 控制台中记录的对象

### JavaScript 中的对象

如果您已经写了一段时间的 JavaScript，您很快就会遇到`object`类型。JavaScript 是使用原型设计的，这是一种基于对象的编程类型。JavaScript 中的对象是一个可以包含多个属性的变量。这些属性可以指向值、子对象，甚至函数。

JavaScript 程序中的每个变量都是对象或原始值。原始值是一种更基本的类型，只包含单个信息片段，没有属性或方法。使 JavaScript 变得更加复杂并使对象变得更加重要的是，即使是最基本的类型，如字符串和数字，一旦分配给变量，也会被包装在对象中。

例如：

```js
let myString = "hello";
console.log(myString.toUpperCase()); // returns HELLO
console.log(myString.length); // returns 5
```

上述代码显示，即使在 JavaScript 中，基本的字符串变量也具有属性和方法。

真正的原始值没有属性或方法。例如，直接声明的数字是原始值：

```js
5.toString(); // this doesn't work because 5 is a primitive integer
let num = 5;
num.toString(); // this works because num is a Number object
```

### 原型

如前所述，JavaScript 是一种基于原型的语言。这是面向对象编程的一种变体，其中使用原型而不是类。原型是另一个对象作为另一个对象的起点。例如，在上一节中，我们看了一个简单的字符串变量：

```js
let myString = "hello";
```

正如我们在上一节中看到的，`myString`带有一些内置函数，比如`toUpperCase()`，以及属性，比如`length`。在幕后，`myString`是从字符串原型创建的对象。这意味着字符串原型中存在的所有属性和函数也存在于`myString`中。

JavaScript 对象包含一个名为`__proto__`属性的特殊属性，该属性包含对象的父原型。为了查看这一点，让我们在 Google Chrome 开发者控制台中运行`console.dir(myString)`：

![图 5.3：JavaScript 中的原型（字符串）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_03.jpg)

###### 图 5.3：JavaScript 中的原型（字符串）

运行该命令返回`String`，一个包含多个方法的对象。内置的`String`对象本身具有原型。接下来，运行`console.dir(myString.__proto__.__proto__)`：

![图 5.4：JavaScript 中的原型（对象）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_04.jpg)

###### 图 5.4：JavaScript 中的原型（对象）

再次运行带有附加`__proto__`属性的命令将返回`null`。JavaScript 中的所有原型最终都指向`null`，这是唯一一个本身没有原型的原型：

![图 5.5：附加 _proto_ 返回 null](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_05.jpg)

###### 图 5.5：附加 _proto_ 返回 null

这种一个原型导致另一个原型，依此类推的关系被称为原型链：

![图 5.6：原型链](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_06.jpg)

###### 图 5.6：原型链

在 JavaScript 中，当你使用变量的属性时，它从当前对象开始查找，如果找不到，就会在父原型中查找。因此，当我们运行`myString.toUpperCase()`时，它首先在`myString`中查找。在那里找不到该名称的方法后，它会检查`String`，在那里找到该方法。如果`String`中没有包含该方法，它将检查`Object`原型，然后达到`null`，此时会返回`not found error`。

JavaScript 提供了重新定义任何原型函数行为的语法，无论是内置的还是用户定义的。可以使用以下命令来实现：

```js
Number.prototype.functionName = function () {
  console.log("do something here");
}
```

在下一个练习中，我们将修改内置的`Number`原型，以赋予它一些额外的功能。请记住，这种技术可以应用于内置和自定义的原型。

### 练习 23：扩展 Number 原型

在这个练习中，我们将看一个例子，扩展 JavaScript 的内置原型`Number`，以包含一些额外的函数。在*步骤 1*之后，看看你是否能自己想出第二个解决方案：

+   double（返回值乘以二）

+   square（返回数字乘以自身）

+   Fibonacci（返回斐波那契序列中的`n`，其中每个数字是前两个数字的和）

+   阶乘（返回 1 和`n`之间所有数字的乘积的结果）

以下是要遵循的步骤：

1.  在一个新的文件夹中，创建一个名为`number.js`的文件。我们将首先向`Number`原型添加一个`double`函数。注意使用`this.valueOf()`来检索数字的值：

```js
Number.prototype.double = function () {
  return this.valueOf()*2;
}
```

1.  接下来，按照相同的模式，我们将为任意数字的平方添加一个解决方案：

```js
Number.prototype.square = function () {
  return this.valueOf()*this.valueOf();
}
```

1.  同样，我们将遵循相同的模式，尽管这个问题的解决方案有点棘手，因为它使用了记忆递归，并且使用了`BigInt`原型：

```js
Number.prototype.fibonacci = function () {
  function iterator(a, b, n) {
   return n == 0n ? b : iterator((a+b), a, (n-1n))
  }
  function fibonacci(n) {
   n = BigInt(n);
   return iterator(1n, 0n, n);
  }
  return fibonacci(this.valueOf());
}
```

#### 注意 BigInt（大整数）

在前面的步骤中，你会注意到我们使用了`BigInt`关键字。`BigInt`和`Number`一样，是 JavaScript 内置的另一个原型。它是 ES6 中的第一个新的原始类型。主要区别在于`BigInt`可以安全处理非常大的数字。`Number`原型在大于`9007199254740991`的值时开始失败。

一个数字可以通过用`BigInt()`包装它或附加`n`来转换为`BigInt`；注意使用`0n`和`1n`。

1.  接下来，我们将使用相同的模式和`BigInt`添加阶乘的解决方案：

```js
Number.prototype.factorial = function () {
  factorial = (n) => {
   n = BigInt(n);
   return (n>1) ? n * factorial(n-1n) : n;
  }
  return factorial(this.valueOf());
}
```

1.  为了演示，定义一个数字并调用函数：

```js
let n = 100;
console.log(
  "for number " + n +"\n",
  "double is " + n.double() + "\n",
  "square is " + n.square() + "\n",
  "fibonacci is " + n.fibonacci() + "\n",
  "factorial is " + n.factorial() + "\n"
);
```

1.  使用 Node.js 运行脚本：

```js
node number.js
```

你应该得到类似以下的结果：

![图 5.7：扩展 JavaScript 内置原型后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_07.jpg)

###### 图 5.7：扩展 JavaScript 内置原型后的输出

### ES6 类

如前所述，基于原型的语言和经典面向对象语言之间的关键区别之一是使用原型而不是类。然而，ES6 引入了内置类。我们将通过创建`Vehicle`原型/类和`Car`原型/类，比较并使用原型语法和 ES6 类语法创建对象。

首先是原型的方式：

```js
function Vehicle(name, color, sound) {
   this.name = name;
   this.color = color;
   this.sound = sound;
   this.makeSound = function() {console.log(this.sound);};
}
var car = new Vehicle("car", "red", "beep");
car.makeSound();
```

然后，使用 ES6 类做同样的事情：

```js
class Vehicle {
   constructor(name, color, sound) {
      this.name = name;
      this.color = color;
      this.sound = sound;
      this.makeSound = () => console.log(this.sound);
   }
}
const car = new Vehicle("car", "red", "beep");
car.makeSound();
```

ES6 类语法允许我们以面向对象的方式编写代码。在语言的较低级别上，类只是用于创建原型的语法样式。

在接下来的部分，我们将讨论使用 ES6 类以面向对象的方式进行编程。

## 面向对象编程（OOP）

重要的是要清楚地区分 JavaScript 对象和面向对象编程（OOP）。这是两个非常不同的东西。JavaScript 对象只是一个包含属性和方法的键值对。另一方面，面向对象编程是一组原则，可以用来编写更有组织和高效的代码。

模块化 JavaScript 并不需要面向对象编程，但它包含许多与模块化 JavaScript 相关的概念。类的使用是面向对象编程的一个基本方面，它允许我们通过创建类和子类来重用代码。

它教导我们以使维护和调试更容易的方式对程序的相关方面进行分组。它侧重于类和子类，使得代码重用更加实际。

从历史上看，面向对象编程成为处理过程代码中常见的混乱、难以阅读的代码（意思不明确的代码）的一种流行方式。通常，无组织的过程代码由于函数之间的相互依赖而变得脆弱和僵化。程序的某一方面的变化可能会导致完全不相关的错误出现。

想象一下我们正在修理一辆汽车，更换前灯导致发动机出现问题。我们会认为这是汽车设计者的糟糕架构。模块化编程拥抱程序的共同方面的分组。

面向对象编程有四个核心概念：

+   抽象

+   封装

+   继承

+   多态

在本章中，我们将看看这四个原则以及如何使用 ES6 语法在 JavaScript 编程语言中使用它们。在本章中，我们将尝试专注于实际应用，但与上述核心概念相关。

### 抽象

抽象是编程中使用的高级概念，也是面向对象编程的基础。它允许我们通过不必处理具体实现来创建复杂系统。当我们使用 JavaScript 时，许多东西默认被抽象化。例如，考虑以下数组和内置的`includes()`函数的使用：

```js
let list = ["car", "boat", "plane"];
let answer = list.includes("car") ? "yes" : "no";
console.log(answer);
```

我们不需要知道在运行`includes()`时使用的算法或代码。我们只需要知道如果数组中包含`car`，它将返回`true`，如果不包含则返回`false`。这是一个抽象的例子。随着 JavaScript 版本的更改，`include()`的内部工作方式可能会发生变化。它可能变得更快或更智能，但因为它已经被抽象化，我们不需要担心程序会出错。我们只需要知道它将返回`true`或`false`的条件。

我们不需要考虑计算机如何将二进制转换为屏幕上的图像，或者按下键盘如何在浏览器中创建事件。甚至构成 JavaScript 语言的关键字本身也是代码。

我们可以查看在使用内置 JavaScript 函数时执行的低级代码，这些代码在浏览器引擎之间会有所不同。使用`JSON.stringify()`。

让我们花一点时间思考抽象对象是什么。想象一下你桌子上的一个苹果，这是一个具体的苹果。它是苹果的一个实例或分类的概念。我们也可以谈论苹果的概念以及什么使苹果成为苹果；哪些属性在苹果中是共同的，哪些是必需的。

当我说“苹果”这个词时，你脑海中会浮现出水果的图片。你想象中的苹果的确切细节取决于你对苹果概念的理解。当我们在计算机程序中定义一个苹果类时，我们正在定义程序如何定义苹果类。就像我们的想象力一样，一个事物的概念可以是具体的或不具体的。它可能只包含一些因素，比如形状和颜色，也可能包含几十个因素，包括重量、产地和口味。

### 类和构造函数

在第一个练习中，我们创建了一个灯模块。虽然它是一个模块，但它不是面向对象的。在本节中，我们将以面向对象的方式重新设计该模块。

类最重要的一个方面是它的构造函数。构造函数是在创建类的实例时调用的内置函数。通常，构造函数用于定义对象的属性。例如，您经常会看到类似于这样的东西：

```js
class Apple {
  constructor(color, weight) {
   this.color = color;
   this.weight = weight;
  }
}
```

传递的参数将保存到实例中以供以后使用。您还可以根据传递的参数添加一些额外的属性。例如，假设我们想通过附加日期时间戳来给我们的苹果一个出生日期。我们可以在我们的构造函数内添加第三行：

```js
  this.birthdate = Date.now();
```

或者我们可能想在灯模块中调用一些其他函数。想象一下，每个进入世界的苹果都有 1/10 的机会是腐烂的：

```js
  this.checkIfRotten();
```

我们的类需要包含一个`checkIfRotten`函数，该函数将`isRotten`属性设置为 10 次中的 1 次为`true`：

```js
checkIfRotten() {
  If (Math.floor(Math.random() * Math.floor(10)) == 0) {
   this.isRotten = true;
  } else {
   this.isRotten = false;
  }
}
```

### 练习 24：将灯模块转换为类

#### 注意

本练习使用本章*练习 22，编写一个简单的 ES6 模块*的最终产品作为起点。完成此练习后的代码状态可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise24`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise24)找到。

让我们回到本章*练习 22，编写一个简单的 ES6 模块*中的灯示例。我们将使用在上一章中为灯模块定义的属性，并在创建时进行分配。此外，我们将编写函数来检查灯属性的格式。如果使用无效的属性值创建了灯，我们将将其设置为默认值。

执行练习的步骤如下：

1.  打开`js/light.js`并删除上一个练习中的代码。

1.  为我们的`Light`类创建一个类声明：

```js
class Light  {
}
```

1.  向类添加`constructor`函数，并从参数中设置属性以及`datetime`属性。我们将首先将参数传递给两个函数以检查正确的格式，而不是直接设置`state`和`brightness`。这些函数的逻辑将在以下步骤中编写：

```js
class Light  {
  constructor(state, brightness) {
   // Check that inputs are the right types
   this.state = this.checkStateFormat(state);
   this.brightness = this.checkBrightnessFormat(brightness);
   this.createdAt = Date.now();
  }
}
```

1.  将`checkStateFormat`和`checkBrightnessFormat`函数添加到类声明中：

```js
  checkStateFormat(state) {
   // state must be true or false
   if(state) {
    return true;
   } else {
    return false;
   }
  }
  checkBrightnessFormat(brightness) {
   // brightness must be a number between 0.01 and 1
   if(isNaN(brightness)) {
    brightness = 1;
   } else if(brightness > 1) {
    brightness = 1;
   } else if(brightness < 0.01) {
    brightness = 0.01;
   }
   return brightness;
  }
```

1.  添加一个`toggle`函数和一个`test`函数，我们将用于调试。这两个函数也应该在类声明内。`toggle`函数将简单地将灯的状态转换为当前状态的相反状态；例如，从开到关，反之亦然：

```js
  toggle() {
   this.state = !this.state;
  }
  test() {
   alert("state is " + this.state);
  }
```

1.  在`js/lightBulb.js`中，在类声明下面，添加一个模块导出，就像我们在上一个练习中所做的那样：

```js
export default Light;
```

1.  打开`js/viewer.js`，并用包含`Light`类实例的变量替换我们在*练习 22，编写一个简单的 ES6 模块*中编写的`light()`行：

```js
let light = new Light(true, 0.5);
```

1.  在`js/viewer.js`中的前一行下面，添加以下代码。此代码将图像的源连接到`state`，并将图像的不透明度连接到`brightness`：

```js
// Set image based on light state
bulb.src = light.state ? onImage : offImage;
// Set opacity based on brightness
bulb.style.opacity = light.brightness;
// Set slider value to brightness
slider.value = light.brightness;
bulb.onclick = function () {
  light.toggle();
  bulb.src = light.state ? onImage : offImage;
}
slider.onchange = function () {
  light.brightness = this.value;
  bulb.style.opacity = light.brightness;
}
```

1.  返回项目目录并运行`npm start`。项目运行后，在浏览器中打开`localhost:8000`。您应该看到灯的新图片，指示它是开启的：![图 5.8：状态为 true 的灯](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_08.jpg)

###### 图 5.8：状态为 true 的灯

打开页面后，单击图像并确保这样做会导致图像更改。还要注意页面底部的输入滑块。尝试更改值以确认这样做是否会更新图像的不透明度。

#### 类的命名约定

在上面的代码中，我们创建了一个`Light`类。请注意，我们使用的是大写的“L”，而不是 JavaScript 中通常使用的驼峰命名法。将类的名称大写是一种常见的做法；有关命名约定的更多详细信息，请参阅 Google 的 JavaScript 样式指南：[`google.github.io/styleguide/javascriptguide.xml#Naming`](https://google.github.io/styleguide/javascriptguide.xml#Naming)。

Camelcase 是 JavaScript 中最流行的命名风格。其他风格包括 snake_case、kebab-case 和 PascalCase。

### 默认属性

使用类时，您最常用的功能之一是默认属性值。通常，您希望创建类的实例，但不关心属性的具体值-例如，不指定参数：

```js
myLight = new Light();
```

`state`和`brightness`都将默认为`undefined`。

根据我们编写的代码，调用没有属性的`light`不会引发错误，因为我们编写了`checkStateFormat`和`checkBrightnessFormat`来处理所有无效值。然而，在许多情况下，您可以通过在构造函数中提供默认值来简化代码，如下所示：

```js
  constructor(state=false, brightness=100) {
```

上述语法不是特定于类`constructor`，可以用于设置任何函数的默认参数，假设您使用的是 ES6、ES2015 或更新版本的 JavaScript。默认参数在 ES2015 之前的版本中不可用。

### 封装

封装是模块只在必要时才公开对象属性的想法。此外，应该使用函数而不是直接访问和修改属性。例如，让我们回到我们的灯模块。在`constructor`函数内部，我们确保首先通过状态检查器运行值：

```js
  constructor(state, brightness) {
   // Check that input has the right format
   this.brightness = this.checkBrightnessFormat(brightness);
  }
```

假设您开发了前面的模块并发布供同事使用。您不必担心他们使用错误的值初始化类，因为如果他们这样做，`checkBrightnessFormat()`将自动更正该值。但是，一旦我们的类的实例存在，其他人就可以直接修改该值，没有任何阻止：

```js
let light = new Light();
light.brightness = "hello";
```

在一个命令中，我们绕过了`Light`类的`checkBrightnessFormat`函数，并且我们有了一个`brightness`值为`hello`的灯。

封装是以使这种情况不可能的方式编写我们的代码的想法。诸如 C#和 Java 之类的语言使封装变得容易。不幸的是，即使在 ES6 更新后，JavaScript 中使用封装也不明显。有几种方法可以做到这一点；其中最受欢迎的方法之一是利用内置的`WeakMap`对象类型，这也是 ES6 的新功能之一。

### WeakMap

**WeakMap**对象是一个键值对集合，其中键是对象。WeakMap 具有一个特殊的特性，即如果 WeakMap 中的键对象被从程序中移除并且没有对它的引用存在，WeakMap 将从其集合中删除关联的键值对。这个删除键值对的过程称为垃圾回收。因此，在使用映射可能导致内存泄漏的情况下，该元素特别有用。

WeakMap 比 Map 更适合的一个例子是，一个脚本跟踪动态变化的 HTML 页面中的每个元素。假设 DOM 中的每个元素都被迭代，我们在 Map 中创建了一些关于每个元素的额外数据。然后，随着时间的推移，元素被添加到 DOM 中并从中删除。使用 Map，所有旧的 DOM 元素将继续被引用，导致存储与已删除的 DOM 元素相关的无用信息，从而导致随着时间的推移内存使用量增加。使用 WeakMap，DOM 元素的删除（它是集合中的键对象）会导致在垃圾回收期间删除集合中的关联条目。

在这里，我们将使用`WeakMap()`。首先，我们创建一个空的`map`变量，然后创建一个带有一些属性的`light`对象。然后，我们将对象本身与一个字符串`kitchen light`关联起来。这不是向`light`添加属性的情况；相反，我们使用对象就像它是地图中的属性名称一样：

```js
var map = new WeakMap();
var light = {state: true, brightness: 100};
map.set(light, "kitchen light");
console.log(map.get(light));
```

另外，需要注意的是，键对象是基于对对象的特定引用。如果我们创建具有相同属性值的第二个灯，那将算作一个新的键：

```js
let light2 = {state: true, brightness: 100};
map.set(light2, "bedroom light");
// above has not changed kitchen light reference
console.log(map.get(light));
```

如果我们更新对象的属性，那不会改变映射：

```js
light.state = false;
// reference does not change
console.log(map.get(light));
```

映射将存在，直到键对象超出范围，或者直到它被设置为 null 并进行垃圾回收；例如：

```js
light = null;
// value will not be returned here
console.log(map.get(light));
```

### 练习 25：封装的 WeakMap

#### 注意

本练习以本章的*练习 24，将灯模块转换为类*的最终产品为起点。完成此练习后的代码状态可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise25`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise25)找到。

在这个练习中，我们将使用`WeakMap`来创建无法直接从模块外部访问的私有变量。执行以下步骤完成练习：

1.  打开`js/light.js`，并在文件顶部添加一个名为`privateVars`的`WeakMap`对象：

```js
let privateVars = new WeakMap();
```

1.  在`js/light.js`中，修改`constructor`函数，使得对象属性通过`set`方法保存到`privateVars`中，而不是直接在对象上：

```js
constructor(state, brightness) { 
  // Parse values
  state = this.checkStateFormat(state);
  brightness = this.checkBrightnessFormat(brightness);
  // Create info object 
  let info = {
   "state": state,
   "brightness": brightness,
   "createdAt": Date.now()
  };
// Save info into privateVars 
  privateVars.set(this, info); 
}
```

1.  现在，在`js/light.js`中，修改`toggle`函数，以便我们从名为`privateVars`的`WeakMap`对象获取状态信息。请注意，当我们设置变量时，我们发送回一个包含所有信息而不仅仅是`state`的对象。在我们的示例中，每个`light`实例都与`WeakMap`关联的单个`info`对象：

```js
toggle() { 
  let info = privateVars.get(this); 
  info.state = !info.state;
  privateVars.set(this, info); 
}
```

1.  我们还需要以类似的方式修改`js/light.js`中的`test`函数。我们将改变发送给用户的`state`的来源，以便在警报中使用`WeakMap`：

```js
test() { 
  let info = privateVars.get(this); 
  alert("state is " + privateVars.get(this).state);
}
```

1.  由于封装夺走了直接更改状态和亮度的能力，我们需要添加允许这样做的方法。我们将从在`js/light.js`中添加`setState`函数开始。请注意，它几乎与我们的`toggle`函数相同：

```js
setState(state) {
  let info = privateVars.get(this);
  info.state = checkStateFormat(state); 
  privateVars.set(this, info); 
}
```

1.  接下来，在`js/light.js`中添加 getter 方法：

```js
getState() {
  let info = privateVars.get(this); 
  return info.state;
}
```

1.  按照最后两个步骤的模式，在`js/light.js`中为`brightness`属性添加 getter 和 setter 函数：

```js
setBrightness(brightness) { 
  let info = privateVars.get(this);
  info.brightness = checkBrightnessFormat(brightness);
  privateVars.set(this, info);
}
getBrightness() { 
  let info = privateVars.get(this);
  return info.brightness;
}
```

1.  我们需要做的最后一个更改是在`js/viewer.js`中。在变量声明下面，将每个对光亮度和状态的引用更改为使用我们创建的 getter 方法：

```js
// Set image based on light state
bulb.src = light.getState() ? onImage : offImage;
// Set opacity based on brightness
bulb.style.opacity = light.getBrightness();
// Set slider value to brightness
slider.value = light.getBrightness();
bulb.onclick = function () {
  light.toggle();
  bulb.src = light.getState() ? onImage : offImage;
}
slider.onchange = function () {
  light.setBrightness(this.value);
  bulb.style.opacity = light.getBrightness();
}
```

1.  使用`npm start`运行代码，并在浏览器中查看`localhost:8000`上的页面项目。检查确保单击图像有效，以及使用输入滑块更改亮度有效：

![图 5.9：使用单击和滑块功能正确呈现网站](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_09.jpg)

###### 图 5.9：使用单击和滑块功能正确呈现网站

### 获取器和设置器

在使用封装时，由于我们不再允许用户直接访问属性，大多数对象最终将具有一些或全部属性的 getter 和 setter 函数：

```js
console.log(light.brightness);
// will return undefined
```

相反，我们专门创建允许获取和设置属性的函数。这些被称为 getter 和 setter，它们是一种流行的设计模式，特别是在诸如 Java 和 C++等语言中。如果您在上一个练习中完成了第 7 步，应该已经为`brightness`添加了 setter 和 getter：

```js
setBrightness(brightness) {
  let info = privateVars.get(this);
  info.brightness = checkBrightnessFormat(state);
  privateVars.set(this, info);
}
getBrightness() {
  let info = privateVars.get(this);
  return info.brightness;
}
```

### 继承

继承是一个类继承另一个类的属性和方法的概念。从另一个类继承的类称为子类，被继承的类称为超类。

正是从术语**超类**中，我们得到了内置的`super()`函数，它可以用于调用子类的超类的构造函数。我们将在本章后面使用`super()`来创建自己的子类。

应该注意的是，一个类既可以是子类，也可以是超类。例如，假设我们有一个模拟不同类型动物的程序。在我们的程序中，我们有一个哺乳动物类，它是动物类的子类，也是狗类的超类。

通过这种方式组织我们的程序，我们可以将所有动物相关的属性和方法放在动物类中。哺乳动物子类包含哺乳动物相关的方法，但不包括爬行动物；例如：

![图 5.10：JavaScript 中的继承](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_10.jpg)

###### 图 5.10：JavaScript 中的继承

这一开始可能听起来很复杂，但通常可以节省大量的编码工作。如果不使用类，我们将不得不将方法从一个动物复制并粘贴到另一个动物中。这就带来了在多个地方更新函数的困难。 

回到我们的智能家居场景，假设我们收到了一个新的彩色灯泡设备。我们希望我们的彩色灯泡具有灯泡中包含的所有属性和函数。此外，彩色灯应该有一个额外的`color`属性，包含一个十六进制颜色代码，一个颜色格式检查器和与改变颜色相关的函数。

我们的代码也应该以一种方式编写，如果我们对底层的`Light`类进行更改，彩色灯泡将自动获得任何添加的功能。

### 练习 26：扩展一个类

#### 注意

本练习使用*练习 25，封装的 WeakMap*的最终产品作为起点。完成此练习后的代码状态可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise26`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise26)找到。

为了扩展上一个练习中编写的`Light`类，我们将创建一个新的`ColorLight`类：

1.  在`/js/colorLight.js`中创建一个新文件。在第一行，我们将导入`./light.js`，这将作为起点：

```js
import Light from './light.js';
```

1.  接下来，我们将为私有变量创建`WeakMap`。然后，我们将为我们的`ColorLight`类创建一个类语句，并使用`extends`关键字告诉 JavaScript 它将使用`Light`作为起点：

```js
let privateVars = new WeakMap();
class ColorLight extends Light {
}
```

1.  在`ColorLight`类语句内部，我们将创建一个新的`constructor`，它使用内置的`super()`函数，运行我们基类`Light`的`constructor()`函数：

```js
class ColorLight extends Light {
  constructor(state=false, brightness=100, color="ffffff") {
   super(state, brightness);
   // Create info object
   let info = {"color": this.checkColorFormat(color)};
   // Save info into privateVars
   privateVars.set(this, info);
  }
}
```

1.  请注意在上述构造函数中，我们调用了`checkColorFormat()`，这是一个检查提供的颜色值是否是有效十六进制值的函数。如果不是，我们将把值设置为白色的十六进制值(#FFFFFF)。该函数应该在`ColorLight`类语句内部：

```js
  checkColorFormat(color) {
   // color must be a valid hex color
   var isHexColor  = /^#[0-9A-F]{6}$/i.test('#'+color);
   if(!isHexColor) {
    // if invalid make white
    color = "ffffff";
   }
   return color;
  }
```

1.  添加 getter 和 setter 函数，就像我们在后面的练习中所做的那样：

```js
  getColor() {
   let info = privateVars.get(this);
   return info.color;
  }
  setColor(color) {
   let info = privateVars.get(this);
   info.color = this.checkColorFormat(color);
   privateVars.set(this, info);
  }
```

1.  在`js/colorLight.js`的底部，添加一个`export`语句以使模块可供导入：

```js
export default ColorLight;
```

1.  在文件顶部打开`js/viewer.js`，并将`Light`导入切换为`ColorLight`。在下面，我们将导入一个预先编写的名为`changeColor.js`的脚本：

```js
import ColorLight from './colorLight.js';
import changeColor from './__extra__/changeColor.js';
```

1.  在`js/viewer.js`中更下面，找到初始化`light`变量的行，并将其替换为以下内容：

```js
let light = new ColorLight(true, 1, "61AD85");
```

1.  在`js/viewer.js`的底部，添加以下内容：

```js
// Update image color
changeColor(light.getColor());
```

1.  再次使用`npm start`启动程序，并在浏览器中转到`localhost:8000`：

如果您按照说明正确操作，现在应该看到灯泡呈浅绿色，如下图所示。尝试打开`js/viewer.js`并更改十六进制值；这样做应该会导致灯泡图像显示不同的颜色：

![图 5.11：change-color 函数应用 CSS 滤镜使灯泡变绿](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_11.jpg)

###### 图 5.11：change-color 函数应用 CSS 滤镜使灯泡变绿

### 多态

多态性就是简单地覆盖父类的默认行为。在 Java 和 C#等强类型语言中，多态性可能需要花费一些精力。而在 JavaScript 中，多态性是直接的。你只需要重写一个函数。

例如，在上一个练习中，我们将`Light`和`ColorLight`类扩展了。假设我们想要获取在`Light`中编写的`test()`函数，并覆盖它，以便不是弹出灯的状态，而是弹出灯的当前颜色值。

因此，我们的`js/light.js`文件将包含以下内容：

```js
  test() {
   let info = privateVars.get(this); 
   alert("state is " + privateVars.get(this).state);
  }
Then all we have to do is create a new function in js/colorLight.js which has the same name, and replace state with color:
  test() { 
   let info = privateVars.get(this); 
   alert("color is " + privateVars.get(this).color);
  }
```

### 练习 27：LightBulb Builder

#### 注意

这个练习使用*Exercise 26, Extending a Class*的最终产品作为起点。完成这个练习后的代码状态可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise27`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise27)找到。

在这个练习中，我们将运用到目前为止学到的概念来增强我们的示例项目。我们将修改项目，使我们能够创建无限个`lightbulb`类的实例，选择颜色、亮度和状态：

1.  打开`js/light.js`，并在`WeakMap`引用的下面添加两个图像源的值：

```js
let onImage = "images/bulb_on.png";
let offImage = "images/bulb_off.png";
```

1.  接下来，在`js/light.js`中，在`info`变量定义的下面，添加以下内容：

```js
   // Create html element
   let div = document.createElement("div");
   let img = document.createElement("img");
   let slider = document.createElement("input");
   // Save reference to element as private variable
   info.div = div;
   info.img = img;
   info.slider = slider;
   this.createDiv(div, img, slider, state, brightness);
```

1.  在`js/light.js`的最后一步中，我们引用了`this.createDiv`。在这一步中，我们将在`js/light.js`的构造函数下面创建该函数。该函数为`Light`类的每个实例创建 HTML：

```js
  createDiv(div, img, slider, state, brightness) {
   // make it so we can access this in a lower scope
   let that = this;
   // modify html
   div.style.width = "200px";
   div.style.float = "left";
   img.onclick = function () { that.toggle() };
   img.width = "200";
   img.src = state ? onImage : offImage;
   img.style.opacity = brightness;
   slider.onchange = function () { that.setBrightness(this.value) };
   slider.type = "range";
   slider.min = 0.01;
   slider.max = 1;
   slider.step = 0.01;
   slider.value = brightness;
   div.appendChild(img);
   div.appendChild(slider);
   // append to document
   document.body.appendChild(div);
  }
```

1.  接下来，在`js/light.js`中，找到`setState`函数，并在函数内添加以下行：

```js
info.img.src = info.state ? onImage : offImage;
```

1.  在`js/light.js`的`toggle`函数中添加相同的行：

```js
info.img.src = info.state ? onImage : offImage;
```

1.  同样地，我们将更新`js/light.js`中的`setBrightness`函数，以根据亮度设置图像的不透明度：

```js
info.img.style.opacity = brightness;
```

1.  `js/light.js`中的最后一个更改是为`img` HTML 对象添加一个 getter 函数。我们将它放在`getBrightness`和`toggle`函数之间：

```js
  getImg() {
   let info = privateVars.get(this);
   return info.img;
  }
```

1.  在`js/colorLight.js`中，我们将导入预先构建的`colorChange`函数。这应该放在你的导入下面的位置，就在`Light`导入的下面：

```js
import changeLight from './__extra__/changeColor.js';
```

1.  接下来，在`js/colorLight.js`中，我们将通过添加以下行来更新构造函数：

```js
   let img = this.getImg();
   img.style.webkitFilter = changeLight(color);
```

1.  在`js/viewer.js`中，删除所有代码并替换为以下内容：

```js
import ColorLight from './colorLight.js';
let slider = document.getElementById("brightnessSlider");
let color = document.getElementById("color");
let button = document.getElementById("build");
button.onclick = function () {
  new ColorLight(true, slider.value, color.value);
}
```

1.  最后的更改是`index.html`；删除`img`和`input`标签，并替换为以下内容：

```js
  <div style="position: 'fixed', top: 0, left: 0">
   <input type="color" id="color" name="head" value="#e66465">
   <input id="brightnessSlider" min="0.01" max="1" step="0.01" type="range"/>
   <button id="build">build</button>
  </div>
```

1.  完成所有更改后，运行`npm start`并在浏览器中打开`localhost:8000`。如果一切都做对了，点击`build`按钮应该根据所选的颜色向页面添加一个新元素：

![图 5.12：创建多个 lightclub 类的实例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_12.jpg)

###### 图 5.12：创建多个 lightclub 类的实例

如你所见，一旦你创建了许多相同的实例，类就真的开始变得非常有用了。在下一节中，我们将看看 npm 包以及如何将我们的`Light`类导出为一个。

## npm 包

**npm 包**是一个已经打包并上传到 npm 服务器的 JavaScript 模块。一旦模块被上传到 npm，任何人都可以快速安装和使用它。

这对你可能不是新鲜事，因为任何使用 Node.js 的人很快就会安装一个包。不太常见的是如何创建和上传一个包。作为开发人员，很容易花费数年的时间而不需要发布一个公共模块，但了解这一点是值得的。这不仅有助于当你想要导出自己的模块时，还有助于阅读和理解你的项目使用的包。

创建 npm 模块的第一步是确保您有一个完整的`package.json`文件。在本地运行项目时，通常不必过多担心诸如**author**和**description**之类的字段。但是，当您准备将模块用于公共使用时情况就不同了。您应该花时间填写与您的软件包相关的所有字段。

以下是包括 npm 推荐的常见属性的表格。其中许多是可选的。有关更多信息和完整列表，请参阅[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)。

至少，元数据应包括名称、版本和描述。此外，大多数软件包将需要一个`dependencies`属性；但是，这应该通过在使用`npm install`安装依赖项时自动生成使用`--save`或`-s`选项：

![图 5.13：npm 属性表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_13.jpg)

###### 图 5.13：npm 属性表

以下表格显示了 npm 的一些更多属性：

![图 5.14：npm 属性表续](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_14.jpg)

###### 图 5.14：npm 属性表续

### npm 链接命令

完成`package.json`并且您想要测试的软件包的第一个版本后，您可以使用`npm link`命令。链接命令将将您的本地 npm 项目与命名空间关联起来。例如，首先导航到要使用本地`npm`软件包的项目文件夹：

```js
cd ~/projects/helloWorld
npm link
```

然后，进入另一个项目文件夹，您想要使用该软件包，并运行`npm link helloWorld`，其中`helloWorld`是您正在测试的软件包的名称：

```js
cd ~/projects/otherProject
npm link helloWorld
```

这两个步骤将使您能够像使用`npm install helloWorld`安装`helloWorld`一样工作。通过这样做，您可以确保在另一个项目中使用时，您的软件包在本地工作。

### Npm 发布命令

一旦您对在本地测试软件包的结果感到满意，您可以使用`npm publish`命令轻松将其上传到 npm。要使用`publish`命令，您首先需要在[`www.npmjs.com/`](https://www.npmjs.com/)上创建一个帐户。一旦您拥有帐户，您可以通过在命令行上运行`npm login`来本地登录。

登录后，发布软件包非常简单。只需导航到您的`project`文件夹并运行`npm publish`。以下是成功上传到 npm 供他人使用的软件包的示例：

![图 5.15：已发布的 npm 软件包示例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_15.jpg)

###### 图 5.15：已发布的 npm 软件包示例

### ESM 与 CommonJS

ESM 是 ECMAScript 模块的缩写，这是 ES6 中模块的标准。因此，您可能会听到将“ES6 模块”称为 ESM。这是因为 ESM 标准在 ES6 成为标准之前就已经在开发中。

您可能已经看到了在上一章中使用的 CommonJS 格式：

```js
const express = require('express');
```

ES6 模块样式中的相同代码将是这样的：

```js
import express from 'express';
```

ES6 模块非常棒，因为它们使 JavaScript 开发人员对其导入有更多控制。但是，重要的是要注意，目前 JavaScript 正处于过渡期。ES6 已经明确规定了 ES6 模块应该如何工作的标准。尽管大多数浏览器已经实现了它，但 npm 仍在使用自己的标准 CommonJS。

也就是说，ES6 的引入正在迅速得到接受。npm 现在附带一个实验性标志，`--experimental-modules`，允许使用 ES6 样式模块。但是，不建议使用此标志，因为它增加了不必要的复杂性，例如必须将文件扩展名从`.js`更改为`.mjs`。

### Babel

使用 ES6 模块与 Node.js 的更常见和推荐的方法是运行 JavaScript 编译器。最流行的编译器是`Babel.js`，它将 ES6 代码编译为可以在任何地方运行的较旧版本的 JavaScript。

Babel 是 Node.js 生态系统中广泛使用的工具。通常，项目使用具有 Babel 和其他捆绑工具（如 webpack）的起始模板。这些起始项目允许开发人员开始使用 ES6 导入，而无需考虑是否需要编译步骤。例如，有 Facebook 的 create-react-app，它会在文件更改时编译和显示您的应用程序。

React 是推动 ES6 的最大社区之一。在 React 生态系统中，标准导入使用的是 ES6。以下内容摘自 React 关于创建组件的文档：

```js
import React, { Component } from 'react';
class Button extends Component {
  render() {
   // ...
  }
}
export default Button; // Don't forget to use export default!
```

注意前面的代码与我们一直在进行的工作之间的相似之处。这是继承的一个例子，其中`Button`继承了`Component`的属性，就像`ColorLight`继承了`Light`的属性一样。React 是一个基于组件的框架，大量使用 ES6 功能，如导入和类。

### webpack

另一个常见的 JavaScript 编译器是 webpack。webpack 接受多个 JavaScript 文件并将它们编译成单个捆绑文件。此外，webpack 可以采取步骤来提高性能，例如缩小代码以减少总大小。在使用模块时，webpack 特别有用，因为每个加载到 HTML 站点中的单独文件都会增加加载时间，因为会产生额外的 HTTP 调用。

使用 webpack，我们可以非常简单地指定要编译的 JavaScript 的入口点，并且它将自动合并任何引用的文件。例如，如果我们想要编译上一个练习中的代码，我们将创建一个`webpack.config.js`文件来指定入口点：

```js
const path = require("path");
module.exports = {
  mode: 'development',
  entry: "./src/js/viewer.js",
  output: {
   path: path.resolve(__dirname, "build"),
   filename: "bundle.js"
  }
};
```

注意上面定义的`entry`；这将是我们程序的起点，webpack 将自动找到所有引用的文件。另一个重要的值要注意的是`output`。这定义了编译器创建的结果捆绑 JavaScript 文件的位置和文件名。

在下一个练习中，我们将使用 Babel 将我们的代码从 ES6 转换为通用 JavaScript。一旦我们转换了我们的 JavaScript，我们将使用 webpack 将生成的文件编译成一个捆绑的 JavaScript 文件。

### 练习 28：使用 webpack 和 Babel 转换 ES6 和包

#### 注意

此练习使用*练习 27，LightBulb Builder*的最终产品作为起点。完成此练习后的代码状态可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise28`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson05/Exercise28)找到。

在这个练习中，我们将使用 Babel 将我们的 ES6 转换为与旧浏览器（如 Internet Explorer）兼容的通用 JavaScript。我们要做的第二件事是运行 webpack 将所有 JavaScript 文件编译成单个文件：

1.  在项目的基础上创建两个新文件夹，一个名为`build`，另一个名为`src`：

```js
mkdir src build
```

1.  将`images`，`index.html`和`js`文件夹移动到新的`src`文件夹中。源文件夹将用于稍后生成`build`文件夹的内容：

```js
mv images index.html js src
```

1.  安装`babel-cli`和`babel preset`作为开发人员依赖项：

```js
npm install --save-dev webpack webpack-cli @babel/core @babel/cli @babel/preset-env
```

1.  在根目录下添加一个名为`.babelrc`的文件。在其中，我们将告诉 Babel 使用预设设置：

```js
{
  "presets": ["@babel/preset-env"]
}
```

1.  在根目录中添加一个名为`webpack.config.js`的 webpack 配置文件：

```js
const path = require("path");
module.exports = {
  mode: 'development',
  entry: "./build/js/viewer.js",
  output: {
   path: path.resolve(__dirname, "build"),
   filename: "bundle.js"
  }
};
```

1.  要从`src`生成`build`文件夹的内容，我们需要向项目添加一个新的脚本命令。打开`package.json`，查找列出脚本的部分。在该部分，我们将添加一个`build`命令，该命令运行 Babel 和 webpack，并将我们的`image`文件复制到`build`文件夹中。我们还将修改`start`命令以引用我们的`build`文件夹，以便在构建后进行测试：

```js
  "scripts": {
   "start": "ws --directory build",
   "build": "babel src -d build && cp -r src/index.html src/images build && webpack --config webpack.config.js"
  },
```

#### 注意

Windows 用户应使用以下命令：

`"build": "babel src -d build && copy src build && webpack --config webpack.config.js"`

1.  为了确保命令已经正确添加，运行命令行上的`npm run build`。你应该会看到这样的输出：![图 5.16：npm run build 输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_16.jpg)

###### 图 5.16：npm run build 输出

1.  接下来，打开`build/index.html`并将`script`标签更改为导入我们新创建的文件`bundle.js`：

```js
<script src="bundle.js"></script>
```

1.  要测试，运行`npm start`并在浏览器中打开`localhost:8000`。你应该会看到与上次练习相同的网站。按几次`build`按钮以确保它按预期工作：![图 5.17：使用构建按钮进行测试运行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_17.jpg)

###### 图 5.17：使用构建按钮进行测试运行

1.  为了双重检查一切是否编译正确，去浏览器中输入`localhost:8000/bundle.js`。你应该会看到一个包含所有我们的 JavaScript 源文件编译版本的大文件：

![图 5.18：所有我们的 JavaScript 源文件的编译版本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_18.jpg)

###### 图 5.18：所有我们的 JavaScript 源文件的编译版本

如果你做的一切都正确，你应该有一个包含所有我们的 JavaScript 代码编译成单个文件的`bundle.js`文件。

### 可组合性和组合模块的策略

我们已经看到模块如何成为另一个模块的扩展，就像`ColorLight`是`Light`的扩展一样。当项目增长时，另一个常见的策略是有模块本身由多个子模块组成。

使用子模块就像在模块文件本身导入模块一样简单。例如，假设我们想要改进我们灯模块中的亮度滑块。也许如果我们创建一个新的`Slider`模块，我们可以在除了`Light`类之外的多种情况下使用它。这是一种情况，我们建议将我们的“高级滑块输入”作为子模块。

另一方面，如果你认为你的新滑块只会在`Light`类中使用，那么将它添加为一个新类只会增加更多的开销。不要陷入过度模块化的陷阱。关键因素在于可重用性和实用性。

### 活动 6：创建带有闪光模式的灯泡

你工作的灯泡公司要求你为他们的产品工作。他们想要一个带有特殊“闪光模式”的灯泡，可以在活动和音乐会上使用。闪光模式的灯允许人们将灯置于闪光模式，并在给定的时间间隔内自动打开和关闭。

创建一个`FlashingLight`类，它扩展了`Light`。该类应该与`Light`相同，只是有一个名为`flashMode`的属性。如果`flashMode`打开，则状态的值应该每五秒切换一次。

创建了这个新组件后，将其添加到`js/index.js`中的包导出，并使用 Babel 编译项目。

执行以下步骤完成活动：

1.  安装`babel-cli`和`babel`预设为开发人员依赖项。

1.  添加`.babelrc`告诉 Babel 使用`preset-env`。

1.  添加一个 webpack 配置文件，指定模式、入口和输出位置。

1.  创建一个名为`js/flashingLight.js`的新文件；它应该作为一个空的 ES6 组件开始，扩展`Light`。

1.  在文件顶部，添加一个`weakMap`类型的`privateVars`变量。

1.  在构造函数中，设置`flashMode`属性并将其保存到构造函数中的`privateVars`中。

1.  为`FlashingLight`对象添加一个 setter 方法。

1.  为`FlashingLight`对象添加一个 getter 方法。

1.  在第 2 行，添加一个空变量，用于在类的全局级别跟踪闪烁计时器。

1.  创建一个引用父类的`lightSwitch()`函数的`startFlashing`函数。这一步很棘手，因为我们必须将它绑定到`setInterval`。

1.  创建一个`stopFlashing`函数，用于关闭计时器。

1.  在构造函数中，检查`flashMode`是否为 true，如果是，则运行`startFlashing`。

1.  在设置`mode`时，还要检查`flashMode` - 如果为 true，则`startFlashing`；否则，`stopFlashing`。

1.  在`index.js`中导入和导出新组件。

1.  通过使用 npm 运行我们的`build`函数来编译代码。

**预期输出**：

![图 5.19：带闪光模式的灯泡](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_05_19.jpg)

###### 图 5.19：带闪光模式的灯泡

#### 注意

这个活动的解决方案可以在第 599 页找到。

## 总结

在本章中，我们探讨了模块化设计的概念，ES6 模块以及它们在 node 中的使用。面向对象设计原则在设计由多个模块层组成的复杂系统的程序时非常有用。

ES6 类允许我们比以前的 JavaScript 版本更轻松地创建类。这些类可以使用`extends`关键字构建。这允许在更复杂的对象之上构建更复杂的对象等等。

我们还看到了新的 ES6 `WeakMap`类型如何允许我们创建私有变量。这种模式限制了将被其他人使用的模块中的错误数量。例如，通过要求更改属性，我们可以在允许更改之前检查格式和值。这就是灯泡示例的情况，我们希望检查`state`在允许设置之前是否为布尔值。我们通过为我们想要向我们代码的其他部分公开的每个私有变量创建 getter 和 setter 方法来实现这一点。

之后，我们谈到了 ES6 模块目前在 Node.js 中没有得到原生支持，尽管像 Facebook 支持的 React 这样的知名项目广泛使用它们。作为解决这一限制的方法，我们安装了 Babel，一个 ES6 到 JavaScript 的编译器，并用它将我们的`src`文件夹转换为最终的构建代码。

我们还谈到了一旦在本地使项目工作，就可以将其转换为可以通过 npm 共享和更新的 npm 包。这个过程涉及使用`npm link`在本地进行测试。然后，一旦满意包的工作方式，使用`npm publish`进行发布。

在下一章中，我们将讨论代码质量以及如何实施自动化测试来防御回归，因为我们更新我们的代码。


# 第七章：代码质量

## 学习目标

在本章结束时，你将能够：

+   确定编写清晰 JavaScript 代码的最佳实践

+   执行代码检查并在你的 node 项目中添加一个检查命令

+   在你的代码上使用单元测试、集成测试和端到端测试方法

+   使用 Git 钩子自动化代码检查和测试

在本章中，我们将专注于提高代码质量，设置测试，并在 Git 提交之前自动运行测试。这些技术可以确保错误或问题能够及早被发现，从而不会进入生产环境。

## 介绍

在上一章中，我们探讨了模块化设计、ES6 模块以及它们在 Node.js 中的使用。我们将我们编译的 ES6 JavaScript 转换为兼容的脚本使用 Babel。

在本章中，我们将讨论代码质量，这是专业 JavaScript 开发的关键品质之一。当我们开始编写代码时，我们往往会专注于解决简单的问题和评估结果。对于大多数开发人员开始的小型项目，很少需要与他人沟通或作为大团队的一部分工作。

随着你参与的项目范围变得更大，代码质量的重要性也增加。除了确保代码能够正常工作，我们还必须考虑其他开发人员将使用我们创建的组件或更新我们编写的代码。

代码质量有几个方面。最明显的是它能够实现预期的功能。这通常说起来容易做起来难。很难满足大型项目的要求。更复杂的是，通常添加新功能可能会导致应用程序的某些现有部分出现错误。通过良好的设计可以减少这些错误，但即便如此，这些类型的故障还是会发生。

随着敏捷开发变得越来越流行，代码变更的速度也在增加。因此，测试比以往任何时候都更加重要。我们将演示如何使用单元测试来确认函数和类的正确功能。除了单元测试，我们还将研究集成测试，以确保程序的所有方面都能正确地一起运行。

代码质量的第二个组成部分是性能。我们代码中的算法可能会产生期望的结果，但它们是否能够高效地实现？我们将看看如何测试函数的性能，以确保算法在处理大量输入时能够在合理的时间内返回结果。例如，你可能有一个排序算法在处理 10 行数据时效果很好，但一旦尝试处理 100 行数据，就需要几分钟的时间。

本章我们将讨论代码质量的第三个方面，即可读性。可读性是衡量人类阅读和理解代码的难易程度。你是否曾经看过使用模糊函数和变量名称或者误导性变量名称编写的代码？在编写代码时，要考虑其他人可能需要阅读或修改它。遵循一些基本准则可以帮助提高可读性。

## 清晰命名

使代码更易读的最简单方法之一是**清晰命名**。尽可能使变量和函数的使用明显。即使是一个人的项目，也很容易在 6 个月后回到自己的代码时，难以记住每个函数的作用。当你阅读别人的代码时，这一点更加明显。

确保你的名称清晰且可读。考虑以下示例，开发人员创建了一个以`yymm`格式返回日期的函数：

```js
function yymm() {
  let date = new Date();
  Return date.getFullYear() + "/" + date.getMonth();
}
```

当我们了解了这个函数的上下文和解释时，它是明显的。但对于第一次浏览代码的外部开发人员来说，`yymm`很容易引起一些困惑。

将模糊函数重命名为使用明显的方式：

```js
function getYearAndMonth() {
  let date = new Date();
  return date.getFullYear() + "/" + date.getMonth();
}
```

当使用正确的函数和变量命名时，编写易读的代码变得容易。再举一个例子，我们想在夜间打开灯：

```js
if(time>1600 || time<600) {
  light.state = true;
}
```

在前面的代码中并不清楚发生了什么。`1600`和`600`到底是什么意思，如果灯的状态是`true`又代表什么？现在考虑将相同的函数重写如下：

```js
if(time.isNight) {
  light.turnOn;
}
```

前面的代码使相同的过程变得清晰。我们不再询问时间是否在 600 和 1600 之间，而是简单地询问是否是夜晚，如果是，我们就打开灯。

除了更易读外，我们还将夜间的定义放在了一个中心位置，`isNight`。如果我们想在 5:00 而不是 6:00 结束夜晚，我们只需要在`isNight`中更改一行，而不是在代码中找到所有`time<600`的实例。

### 规范

在格式化或编写代码的**规范**方面，有两类：行业或语言范例和公司/组织范例。行业或语言特定的规范通常被大多数使用该语言的程序员所接受。例如，在 JavaScript 中，行业范例是使用驼峰命名法来命名变量。

行业范例的良好来源包括 W3 JavaScript 样式指南和 Mozilla MDN Web 文档。

除了行业范例外，软件开发团队或项目通常会有一套更进一步的规范。有时，这些规范被编制成样式指南文件；在其他情况下，这些规范是未记录的。

如果你是一个有着相对庞大代码库的团队的一部分，记录特定的样式选择可能是有用的。这将帮助你考虑你想要保留和强制执行新更新的哪些方面，以及你可能想要更改的哪些方面。它还有助于培训可能熟悉 JavaScript 但不熟悉公司具体规范的新员工。

一个公司特定的样式指南的很好的例子是 Google JavaScript 样式指南([`google.github.io/styleguide/jsguide.html`](https://google.github.io/styleguide/jsguide.html))。它包含一些一般有用的信息。例如，*第 2.3.3 节*讨论了在代码中使用非 ASCII 的问题。它建议如下：

```js
const units = 'μs';
```

最好使用类似于：

```js
const units = '\u03bcs'; // 'μs'
```

没有注释使用`\u03bcs`会更糟。你的代码的意思越明显，越好。

公司通常有一套他们偏爱的库，用于记录日志、处理时间值（例如 Moment.js 库）和测试等。这对于兼容性和代码重用非常有用。例如，如果一个项目已经使用 Bunyan 记录日志，而其他人决定安装 Morgan 等替代库，那么使用不同开发人员使用的执行类似功能的多个依赖项会增加编译项目的大小。

#### 注意：样式指南

值得花时间阅读一些更受欢迎的 JavaScript 样式指南。不要觉得自己必须遵循每一个规则或建议，但要习惯于规则背后的思维方式。一些值得查看的热门指南包括以下内容：

MSDN 样式指南：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide)

### 主观与非主观

在规范方面，"主观"这个术语是你可能会遇到的。在探索现有的库和框架时，你经常会看到诸如"一个主观的框架"之类的短语。在这种情况下，"主观"是规范执行的严格程度的衡量标准：

主观的：严格执行其选择的规范和方法

非主观：不强制执行规范，也就是说，只要代码有效，就可以使用

### Linting

**Linting**是一个自动化的过程，其中代码被检查并根据一套样式指南的标准进行验证。例如，一个设置了 linting 以确保使用两个空格而不是制表符的项目将检测到制表符的实例，并提示开发人员进行更改。

了解 linting 很重要，但它并不是项目的严格要求。当我在一个项目上工作时，我考虑的主要因素是项目的规模和项目团队的规模。

在中长期项目和中大型团队中，Linting 确实非常有用。通常，新人加入项目时会有使用其他样式约定的经验。这意味着你会在文件之间甚至在同一个文件中得到混合的样式。这导致项目变得不太有组织且难以阅读。

另一方面，如果你正在为一个黑客马拉松编写原型，我建议你跳过 linting。它会给项目增加额外的开销，除非你使用一个带有你喜欢的 linting 的样板项目作为起点。

还有一种风险是 linting 系统过于严格，最终导致开发速度变慢。

良好的 Linting 应该考虑项目，并在强制执行通用样式和不太严格之间找到平衡。

### 练习 29：设置 ESLint 和 Prettier 来监视代码中的错误

在这个练习中，我们将安装并设置 ESLint 和 Prettier 来监视我们的代码的样式和语法错误。我们将使用由 Airbnb 开发的流行的 ESLint 约定，这已经成为了一种标准。

#### 注意

这个练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson06/Exercise29/result`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson06/Exercise29/result)找到。

执行以下步骤完成练习：

1.  创建一个新的文件夹并初始化一个`npm`项目：

```js
mkdir Exercise29
cd Exercise29
npm init -y
npm install --save-dev eslint prettier eslint-config-airbnb-base eslint-config-prettier eslint-plugin-jest eslint-plugin-import
```

我们在这里安装了几个开发者依赖项。除了`eslint`和`prettier`之外，我们还安装了由 Airbnb 制作的起始配置，一个与 Prettier 一起工作的配置，以及一个为基于 Jest 的测试文件添加样式异常的扩展。

1.  创建一个`.eslintrc`文件：

```js
{
 "extends": ["airbnb-base", "prettier"],
  "parserOptions": {
   "ecmaVersion": 2018,
   "sourceType": "module"
  },
  "env": {
   "browser": true,
   "node": true,
   "es6": true,
   "mocha": true,
   "jest": true,
  },
  "plugins": [],
  "rules": {
   "no-unused-vars": [
    "error",
    {
      "vars": "local",
      "args": "none"
    }
   ],
   "no-plusplus": "off",
  }
}
```

1.  创建一个`.prettierignore`文件（类似于`.gitignore`文件，这只是列出应该被 Prettier 忽略的文件）。你的`.prettierignore`文件应包含以下内容：

```js
node_modules
build
dist
```

1.  创建一个`src`文件夹，并在其中创建一个名为`square.js`的文件，其中包含以下代码。确保你包含了不合适的制表符：

```js
var square = x => x * x;
	console.log(square(5));
```

1.  在你的 npm `package.json`文件中创建一个`lint`脚本：

```js
  "scripts": {
   "lint": "prettier --write src/**/*.js"
  },
```

1.  接下来，我们将通过从命令行运行新脚本来测试和演示`prettier --write`：

```js
npm run lint
```

1.  在文本编辑器中打开`src/square.js`，你会看到不合适的制表符已被移除：![图 6.1：不合适的制表符已被移除](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_01.jpg)

###### 图 6.1：不合适的制表符已被移除

1.  接下来，回到`package.json`，扩展我们的 lint 脚本，在`prettier`完成后运行`eslint`：

```js
  "scripts": {
   "lint": "prettier --write src/**/*.js && eslint src/*.js"
  },
```

1.  在命令行中再次运行`npm run lint`。你将因`square.js`中的代码格式而遇到一个 linting 错误：

```js
> prettier --write src/**/*.js && eslint src/*.js
src/square.js 49ms
/home/philip/packt/lesson_6/lint/src/square.js
  1:1  error   Unexpected var, use let or const instead  no-var
  2:1  warning  Unexpected console statement          no-console
  2 problems (1 error, 1 warning)
  1 error and 0 warnings potentially fixable with the --fix option.
```

上述脚本产生了一个错误和一个警告。错误是由于在可以使用`let`或`const`的情况下使用`var`。尽管在这种特殊情况下应该使用`const`，因为`square`的值没有被重新赋值。警告是关于我们使用`console.log`，通常不应该在生产代码中使用，因为这会使在发生错误时难以调试控制台输出。

1.  打开`src/example.js`，并按照下图所示，在第 1 行将`var`更改为`const`：![图 6.2：将 var 语句替换为 const](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_02.jpg)

###### 图 6.2：将 var 语句替换为 const

1.  现在再次运行`npm run lint`。现在你应该只会收到警告：

```js
> prettier --write src/**/*.js && eslint src/*.js
src/js.js 48ms
/home/philip/packt/lesson_6/lint/src/js.js
  2:1  warning  Unexpected console statement  no-console
  1 problem (0 errors, 1 warning)
```

在这个练习中，我们安装并设置了 Prettier 以进行自动代码格式化，并使用 ESLint 检查我们的代码是否存在常见的不良实践。

## 单元测试

**单元测试**是一种自动化软件测试，用于检查某个软件中的单个方面或功能是否按预期工作。例如，计算器应用程序可能被分成处理应用程序的图形用户界面（GUI）的函数和负责每种类型的数学计算的另一组函数。

在这样的计算器中，可以设置单元测试来确保每个数学函数按预期工作。这种设置使我们能够快速发现任何由于任何更改而导致的不一致结果或损坏函数。例如，这样一个计算器的测试文件可能包括以下内容：

```js
test('Check that 5 plus 7 is 12', () => {
  expect(math.add(5, 7)).toBe(12);
});
test('Check that 10 minus 3 is 7', () => {
  expect(math.subtract(10, 3)).toBe(7);
});
test('Check that 5 multiplied by 3 is 15', () => {
  expect(math.multiply(5, 3).toBe(15);
});
test('Check that 100 divided by 5 is 20', () => {
  expect(math.multiply(100, 5).toBe(20);
});
test('Check that square of 5 is 25', () => {
  expect(math.square(5)).toBe(25);
});
```

前面的测试将在每次更改代码库时运行，并被检入版本控制。通常，当更新用于多个地方的函数并引发连锁反应导致某些其他函数损坏时，错误会意外地出现。如果发生这样的更改，并且前面的某个语句变为假（例如，5 乘以 3 返回 16 而不是 15），我们将立即能够将新的代码更改与损坏联系起来。

这是一种非常强大的技术，在已经设置好测试的环境中可能被认为是理所当然的。在没有这样一个系统的工作环境中，开发人员的更改或软件依赖项的更新可能会意外地破坏现有的函数并提交到源代码控制中。后来，发现了错误，并且很难将损坏的函数与导致它的代码更改联系起来。

还要记住，单元测试确保某个子单元的功能，但不确保整个项目的功能（其中多个函数一起工作以产生结果）。这就是集成测试发挥作用的地方。我们将在本章后面探讨集成测试。

### 练习 30：设置 Jest 测试以测试计算器应用程序

在这个练习中，我们将演示如何使用 Jest 设置单元测试，Jest 是 JavaScript 生态系统中最流行的测试框架。我们将继续使用计算器应用程序的示例，并为一个接受一个数字并输出其平方的函数设置自动化测试。

#### 注意

此练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson06/Exercise30`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson06/Exercise30)找到。

执行以下步骤以完成练习：

1.  在命令行中，导航到`Exercise30/start`练习文件夹。该文件夹包括一个包含我们将运行测试的代码的`src`文件夹。

1.  通过输入以下命令来初始化一个`npm`项目：

```js
npm init -y
```

1.  使用以下命令安装 Jest，使用`--save-dev`标志（表示该依赖项对开发而非生产是必需的）：

```js
npm install --save-dev jest
```

1.  创建一个名为`__tests__`的文件夹。这是 Jest 查找测试的默认位置：

```js
mkdir __tests__
```

1.  现在我们将在`__tests__/math.test.js`中创建我们的第一个测试。它应该导入`src/math.js`并确保运行`math.square(5)`返回`25`：

```js
const math = require('./../src/math.js');
test('Check that square of 5 is 25', () => {
  expect(math.square(5)).toBe(25);
});
```

1.  打开`package.json`并修改测试脚本，使其运行`jest`。注意以下截图中的`scripts`部分：![图 6.3：修改后的测试脚本，使其运行 Jest](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_03.jpg)

###### 图 6.3：修改后的测试脚本，使其运行 Jest

1.  在命令行中，输入`npm run test`。这应该返回一条消息，告诉我们找到了错误的值，如下面的代码所示：

```js
FAIL  __test__/math.test.js
  ✕ Check that square of 5 is 25 (17ms)
  ● Check that square of 5 is 25
   expect(received).toBe(expected) // Object.is equality
   Expected: 25
   Received: 10
    2 | 
    3 | test('Check that square of 5 is 25', () => {
   > 4 |  expect(math.square(5)).toBe(25);
      |                  ^
    5 | });
    6 | 
    at Object.toBe (__test__/math.test.js:4:26)
Test Suites: 1 failed, 1 total
Tests:     1 failed, 1 total
Snapshots:  0 total
Time:      1.263s
```

这个错误是因为起始代码故意在`square`函数中包含了一个错误。我们没有将数字乘以自身，而是将值加倍。请注意，接收到的答案数量是`10`。

1.  通过打开文件并修复`square`函数来修复错误。它应该像下面的代码一样将`x`相乘，而不是将其加倍：

```js
const square = (x) => x * x;
```

1.  修复了我们的代码后，让我们再次用`npm run test`进行测试。你应该会得到一个成功的消息，如下所示：

![图 6.4：使用 npm run test 进行测试后显示的成功消息](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_04.jpg)

###### 图 6.4：使用 npm run test 进行测试后显示的成功消息

在这个练习中，我们设置了一个 Jest 测试，以确保用输入 5 运行我们的`square`函数返回 25。我们还看了一下当代码中返回错误值时会发生什么，比如返回 10 而不是 25。

## 集成测试

因此，我们已经讨论了单元测试，当项目的代码发生变化时，它们非常有用，可以帮助找到错误的原因。然而，也有可能项目通过了所有的单元测试，但并不像预期的那样工作。这是因为整个项目包含了将我们的函数粘合在一起的额外逻辑，以及静态组件，如 HTML、数据和其他工件。

**集成测试**可以用来确保项目在更高层次上工作。例如，虽然我们的单元测试直接调用`math.square`等函数，但集成测试将测试多个功能一起工作以获得特定结果。

通常，这意味着将多个模块组合在一起，或者与数据库或其他外部组件或 API 进行交互。当然，集成更多部分意味着集成测试需要更长的时间，因此它们应该比单元测试更少地使用。集成测试的另一个缺点是，当一个测试失败时，可能有多种可能性作为原因。相比之下，失败的单元测试通常很容易修复，因为被测试的代码位于指定的位置。

### 练习 31：使用 Jest 进行集成测试

在这个练习中，我们将继续上次 Jest 练习的内容，上次我们测试了`square`函数对 5 的响应是否返回 25。在这个练习中，我们将继续添加一些新的测试，使用我们的函数相互结合：

1.  在命令行中，导航到`Exercise31/start`练习文件夹，并使用`npm`安装依赖项：

```js
npm install
```

1.  创建一个名为`__tests__`的文件夹：

```js
mkdir __tests__
```

1.  创建一个名为`__tests__/math.test.js`的文件。然后，在顶部导入`math`库：

```js
const math = require('./../src/math.js');
```

1.  与上一个练习类似，我们将添加一个测试。然而，这里的主要区别是我们将多个函数组合在一起：

```js
test('check that square of result from 1 + 1 is 4', () => {
  expect(math.square(math.add(1,1))).toBe(4);
});
```

1.  在前面的测试中添加一个计时器来测量性能：

```js
test('check that square of result from 1 + 1 is 4', () => {
  const start = new Date();
  expect(math.square(math.add(1,1))).toBe(4);
  expect(new Date() - start).toBeLessThan(5000);
});
```

1.  现在，通过运行`npm test`来测试一切是否正常运行：

![图 6.5：运行 npm test 以确保一切正常](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_05.jpg)

###### 图 6.5：运行 npm test 以确保一切正常

你应该看到与前面图中类似的输出，每个测试都通过了预期的结果。

应该注意，这些集成测试有点简单。在实际情况下，集成测试结合了我们之前演示的不同来源的函数。例如，当你有多个由不同团队创建的组件时，集成测试可以确保一切都能一起工作。通常，错误可能是由简单的事情引起的，比如更新外部库。

这个想法是你的应用程序的多个部分被集成在一起，这样你就有更大的机会找到哪里出了问题。

### 代码性能斐波那契示例

通常，一个问题有不止一种解决方案。虽然所有的解决方案可能会返回相同的结果，但它们的性能可能不同。例如，考虑获取斐波那契数列的第 n 个数字的问题。斐波那契是一个数学模式，其中序列中的下一个数字是前两个数字的和（1, 1, 2, 3, 5, 8, 13, …）。

考虑以下解决方案，其中斐波那契递归调用自身：

```js
function fib(n) {
  return (n<=1) ? n : fib(n - 1) + fib(n - 2);
}
```

前面的例子说明，如果我们想要递归地得到斐波那契数列的第 n 个数字，那么就得到`n`减一的斐波那契加上`n`减二的斐波那契，除非`n`为 1，此时返回 1。它可以返回任何给定数字的正确答案。然而，随着`n`的增加，执行时间呈指数增长。

要查看这个算法的执行速度有多慢，将`fib`函数添加到一个新文件中，并使用以下方式通过控制台记录结果：

```js
console.log(fib(37));
```

接下来，在命令行中运行以下命令（`time`应该在大多数 Unix 和基于 Mac 的环境中可用）：

```js
time node test.js
```

在特定的笔记本电脑上，我得到了以下结果，表明斐波那契的第 37 位数字是`24157817`，执行时间为 0.441 秒：

```js
24157817
real 0m0.441s
user 0m0.438s
sys 0m0.004s
```

现在打开同一个文件，并将`37`改为`44`。然后再次运行相同的`time node test`命令。在我的情况下，仅增加了 7，执行时间就增加了 20 倍：

```js
701408733
real 0m10.664s
user 0m10.653s
sys 0m0.012s
```

我们可以以更高效的方式重写相同的算法，以增加大数字的速度：

```js
function fibonacciIterator(a, b, n) {
  return n === 0 ? b : fibonacciIterator((a+b), a, (n-1));
}
function fibonacci(n) {
  return fibonacciIterator(1, 0, n);
}
```

尽管看起来更复杂，但由于执行速度快，这种生成斐波那契数的方法更优越。

Jest 测试的一个缺点是，鉴于前面的情景，斐波那契的慢速和快速版本都会通过。然而，在现实世界的应用程序中，慢速版本显然是不可接受的，因为需要快速处理。

为了防范这种情况，您可能希望添加一些基于性能的测试，以确保函数在一定时间内完成。以下是一个示例，创建一个自定义计时器，以确保函数在 5 秒内完成：

```js
test('Timer - Slow way of getting Fibonacci of 44', () => {
  const start = new Date();
  expect(fastFib(44)).toBe(701408733);
  expect(new Date() - start).toBeLessThan(5000);
});
```

#### 注意：Jest 的未来版本

手动为所有函数添加计时器可能有些麻烦。因此，在 Jest 项目中有讨论，以创建更简单的语法来实现之前所做的事情。

要查看与此语法相关的讨论以及是否已解决，请在 GitHub 上的 Jest 的问题＃6947 中查看[`github.com/facebook/jest/issues/6947`](https://github.com/facebook/jest/issues/6947)。

### 练习 32：使用 Jest 确保性能

在这个练习中，我们将使用之前描述的技术来测试获取斐波那契的两种算法的性能：

1.  在命令行中，导航到`Exercise32/start`练习文件夹，并使用`npm`安装依赖项：

```js
npm install
```

1.  创建一个名为`__tests__`的文件夹：

```js
mkdir __tests__
```

1.  创建一个名为`__tests__/fib.test.js`的文件。在顶部，导入快速和慢速的斐波那契函数（这些已经在`start`文件夹中创建）：

```js
const fastFib = require('./../fastFib');
const slowFib = require('./../slowFib');
```

1.  为快速斐波那契添加一个测试，创建一个计时器，并确保计时器运行时间不超过 5 秒：

```js
test('Fast way of getting Fibonacci of 44', () => {
  const start = new Date();
  expect(fastFib(44)).toBe(701408733);
  expect(new Date() - start).toBeLessThan(5000);
});
```

1.  接下来，为慢速斐波那契添加一个测试，同时检查运行时间是否少于 5 秒：

```js
test('Timer - Slow way of getting Fibonacci of 44', () => {
  const start = new Date();
  expect(slowFib(44)).toBe(701408733);
  expect(new Date() - start).toBeLessThan(5000);
});
```

1.  从命令行中，使用`npm test`命令运行测试：

![图 6.6：斐波那契测试的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_06.jpg)

###### 图 6.6：斐波那契测试的结果

注意前面提到的关于计时器的错误响应。函数运行时间的预期结果应该在 5,000 毫秒以下，但在我的情况下，我实际收到了 10,961。根据您的计算机速度，您可能会得到不同的结果。如果您没有收到错误，可能是因为您的计算机速度太快，完成时间少于 5,000 毫秒。如果是这种情况，请尝试降低预期的最大时间以触发错误。

## 端到端测试

虽然集成测试结合了软件项目的多个单元或功能，**端到端测试**更进一步，模拟了软件的实际使用。

例如，虽然我们的单元测试直接调用了`math.square`等函数，端到端测试将加载计算器的图形界面，并模拟按下一个数字，比如 5，然后是平方按钮。几秒钟后，端到端测试将查看图形界面中的结果，并确保它等于预期的 25。

由于开销较大，端到端测试应该更加节制地使用，但它是测试过程中的一个很好的最后一步，以确保一切都按预期工作。相比之下，单元测试运行起来相对快速，因此可以更频繁地运行而不会拖慢开发速度。下图显示了测试的推荐分布：

![图 6.7：测试的推荐分布](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_07.jpg)

###### 图 6.7：测试的推荐分布

#### 注意：集成测试与端到端测试

值得注意的是，什么被认为是集成测试和端到端测试之间可能存在一些重叠。对于测试类型的解释可能会在不同公司之间有所不同。

传统上，测试被分类为单元测试或集成测试。随着时间的推移，其他分类变得流行，如系统测试、验收测试和端到端测试。因此，特定测试的类型可能会有重叠。

## Puppeteer

2018 年，谷歌发布了**Puppeteer** JavaScript 库，大大提高了在基于 JavaScript 的项目上设置端到端测试的便利性。Puppeteer 是 Chrome 浏览器的无头版本，意味着它没有 GUI 组件。这是至关重要的，因为这意味着我们使用完整的 Chrome 浏览器来测试我们的应用，而不是模拟。

Puppeteer 可以通过类似于 jQuery 的语法进行控制，其中可以通过 ID 或类选择 HTML 页面上的元素并与之交互。例如，以下代码打开 Google News，找到一个`.rdp59b`类，点击它，等待 3 秒，最后截取屏幕：

```js
(async() => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('http://news.google.com');
  const more = await page.$(".rdp59b");
  more.click();
  await page.waitFor(3000);
  await page.screenshot({path: 'news.png'});
  await browser.close();
})();
```

请记住，在上面的示例中，我们选择了一个看起来是自动生成的`.rdp59b`类；因此，很可能这个类将来会发生变化。如果类名发生变化，脚本将不再起作用。

如果在阅读本文时，您发现前面的脚本不起作用，我挑战您更新它。在使用 Puppeteer 时，其中一个最好的工具是 Chrome DevTools。我的常规工作流程是转到我为其编写脚本的网站，并右键单击我将要定位的元素，如下图所示：

![图 6.8：在 Chrome 中右键单击进行检查](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_08.jpg)

###### 图 6.8：在 Chrome 中右键单击进行检查

一旦单击**检查**，DOM 资源管理器将弹出，您将能够看到与元素相关的任何类或 ID：

![图 6.9：Chrome DevTools 中的 DOM 资源管理器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_09.jpg)

###### 图 6.9：Chrome DevTools 中的 DOM 资源管理器

#### 注意：Puppeteer 用于 Web 抓取和自动化

除了用于编写端到端测试，Puppeteer 还可以用于 Web 抓取和自动化。几乎可以在普通浏览器中完成的任何事情都可以自动化（只要有正确的代码）。

除了能够通过选择器在页面上选择元素之外，正如我们之前所看到的，Puppeteer 还可以完全访问键盘和鼠标模拟。因此，诸如自动化基于 Web 的游戏和日常任务等更复杂的事情是可能的。一些人甚至成功地使用它绕过了验证码等东西。

### 练习 33：使用 Puppeteer 进行端到端测试

在这个练习中，我们将使用 Puppeteer 手动打开一个基于 HTML/JavaScript 的计算器，并像最终用户一样使用它。我不想针对一个实时网站，因为它的内容经常会发生变化或下线。因此，我在项目文件的`Exercise33/start`中包含了一个 HTML 计算器。

您可以通过使用 npm 安装依赖项，运行`npm start`，然后在浏览器中转到`localhost:8080`来查看它：

![图 6.10：显示使用 Puppeteer 创建的计算器演示的网站](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_10.jpg)

###### 图 6.10：显示使用 Puppeteer 创建的计算器演示的网站

在这个练习中，我们将创建一个脚本，打开网站，按下按钮，然后检查网站的正确结果。我们不仅仅是检查函数的输出，而是列出在网站上执行的操作，并指定要用作我们测试对象的值的 HTML 选择器。

执行以下步骤完成练习：

1.  打开`Exercise33/start`文件夹并安装现有的依赖项：

```js
npm install
```

1.  安装所需的`jest`，`puppeteer`和`jest-puppeteer`包：

```js
npm install --save-dev jest puppeteer jest-puppeteer
```

1.  打开`package.json`并配置 Jest 使用`jest-puppeteer`预设，这将自动设置 Jest 以与 Puppeteer 一起工作：

```js
  "jest": {
   "preset": "jest-puppeteer"
  },
```

1.  创建一个名为`jest-puppeteer.config.js`的文件，并添加以下内容：

```js
module.exports = {
  server: {
   command: 'npm start',
   port: 8080,
  },
}
```

前面的配置将确保在测试阶段之前运行`npm start`命令。它还告诉 Puppeteer 在`port: 8080`上查找我们的 Web 应用程序。

1.  创建一个名为`__tests__`的新文件夹，就像我们在之前的示例中所做的那样：

```js
mkdir __test__
```

1.  在`__tests__`文件夹中创建一个名为`test.test.js`的文件，其中包含以下内容：

```js
describe('Calculator', () => {
  beforeAll(async () => {
   await page.goto('http://localhost:8080')
  })
  it('Check that 5 times 5 is 25', async () => {
   const five = await page.$("#five");
   const multiply = await page.$("#multiply");
   const equals = await page.$("#equals");
   await five.click();
   await multiply.click();
   await five.click();
   await equals.click();
   const result = await page.$eval('#screen', e => e.innerText);
   expect(result).toMatch('25');
  })
})
```

前面的代码是一个完整的端到端测试，用于将 5 乘以 5 并确认界面返回的答案为 25。在这里，我们打开本地网站，按下五，按下乘，按下五，按下等于，然后检查具有 ID 为`screen`的`div`的值。

1.  使用`npm`运行测试：

![图 6.11：运行计算器脚本后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_11.jpg)

###### 图 6.11：运行计算器脚本后的输出

您应该看到一个结果，如前图所示，输出为 25。

### Git 钩子

这里讨论的测试和 linting 命令对于维护和改进代码质量和功能非常有用。然而，在实际开发的热情中，我们的重点是特定问题和截止日期，很容易忘记运行 linting 和测试命令。

解决这个问题的一个流行方法是使用 Git 钩子。Git 钩子是 Git 版本控制系统的一个特性。**Git 钩子**指定要在 Git 过程的某个特定点运行的终端命令。Git 钩子可以在提交之前运行；在用户通过拉取更新时运行；以及在许多其他特定点运行。可以在[`git-scm.com/docs/githooks`](https://git-scm.com/docs/githooks)找到可能的 Git 钩子的完整列表。

对于我们的目的，我们将只关注使用预提交钩子。这将允许我们在提交代码到源代码之前找到任何格式问题。

#### 注意：探索 Git

探索可能的 Git 钩子以及它们通常如何使用的另一个有趣的方法是打开任何 Git 版本控制项目并查看`hooks`文件夹。

默认情况下，任何新的`.git`项目都将在`.git/hooks`文件夹中包含大量的示例。探索它们的内容，并通过使用以下模式重命名它们来触发它们：

`<hook-name>.sample to <hook-name>`

### 练习 34：设置本地 Git 钩子

在这个练习中，我们将设置一个本地 Git 钩子，在我们允许使用 Git 提交之前运行`lint`命令：

1.  在命令行中，导航到`Exercise34/start`练习文件夹并安装依赖项：

```js
npm install
```

1.  将文件夹初始化为 Git 项目：

```js
git init
```

1.  创建`.git/hooks/pre-commit`文件，其中包含以下内容：

```js
#!/bin/sh
npm run lint
```

1.  如果在基于 OS X 或 Linux 的系统上，通过运行以下命令使文件可执行（在 Windows 上不需要）：

```js
chmod +x .git/hooks/pre-commit
```

1.  我们现在将通过进行提交来测试钩子：

```js
git add package.json
git commit -m "testing git hook"
```

以下是前面代码的输出：

![图 6.12：提交到 Git 之前运行的 Git 钩子](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_12.jpg)

###### 图 6.12：提交到 Git 之前运行 Git 钩子

在您的代码提交到源代码之前，您应该看到`lint`命令正在运行，如前面的屏幕截图所示。

1.  接下来，让我们通过添加一些代码来测试失败，这些代码将生成 linting 错误。通过在您的`src/js.js`文件中添加以下行来修改：

```js
      let number = square(5);
```

确保在上一行中保留不必要的制表符，因为这将触发 lint 错误。

1.  重复添加文件并提交的过程：

```js
git add src/js.js
git commit -m "testing bad lint"
```

以下是上述代码的输出：

![图 6.13：提交代码到 git 之前的失败 linting](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_13.jpg)

###### 图 6.13：提交代码到 git 之前的失败 linting

您应该看到`lint`命令像以前一样运行；但是，在运行后，由于 Git 钩子返回错误，代码不会像上次那样被提交。

### 使用 Husky 共享 Git 钩子

要注意的一个重要因素是，由于这些钩子位于`.git`文件夹本身内部，它们不被视为项目的一部分。因此，它们不会被共享到您的中央 Git 存储库供协作者使用。

然而，Git 钩子在协作项目中最有用，新开发人员可能不完全了解项目的约定。当新开发人员克隆项目，进行一些更改，尝试提交，并立即根据 linting 和测试获得反馈时，这是一个非常方便的过程。

`husky`节点库是基于这个想法创建的。它允许您使用一个名为`.huskyrc`的单个配置文件在源代码中跟踪您的 Git 钩子。当新开发人员安装项目时，钩子将处于活动状态，开发人员无需做任何操作。

### 练习 35：使用 Husky 设置提交钩子

在这个练习中，我们将设置一个 Git 钩子，它与*练习 34，设置本地 Git 钩子*中的钩子做相同的事情，但具有可以在团队中共享的优势。通过使用`husky`库而不是直接使用`git`，我们将确保任何克隆项目的人也有在提交任何更改之前运行`lint`的钩子：

1.  在命令行中，导航到`Exercise35/start`练习文件夹并安装依赖项：

```js
npm install
```

1.  创建一个名为`.huskyrc`的文件，其中包含以下内容：

```js
{
  "hooks": {
   "pre-commit": "npm run lint"
  }
}
```

前面的文件是这个练习的最重要部分，因为它确切地定义了在 Git 过程的哪个时刻运行什么命令。在我们的情况下，在将任何代码提交到源代码之前，我们运行`lint`命令。

1.  通过运行`git init`将文件夹初始化为 Git 项目：

```js
git init
```

1.  使用`npm`安装 Husky：

```js
npm install --save-dev husky
```

1.  对`src/js.js`进行更改，以便用于我们的测试提交。例如，我将添加以下注释：![图 6.14：测试提交注释](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_14.jpg)

###### 图 6.14：测试提交注释

1.  现在，我们将运行一个测试，确保它像之前的示例一样工作：

```js
git add src/js.js
git commit -m "test husky hook"
```

以下是上述代码的输出：

![图 6.15：提交测试 husky 钩子后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_15.jpg)

###### 图 6.15：提交测试 husky 钩子后的输出

我们收到关于我们使用`console.log`的警告，但是出于我们的目的，您可以忽略这一点。主要问题是我们已经使用 Husky 设置了我们的 Git 钩子，因此安装项目的任何其他人也将设置好钩子，而不是我们直接在 Git 中设置它们。

#### 注意：初始化 Husky

请注意，`npm install --save-dev husky`是在创建 Git 存储库后运行的。当您安装 Husky 时，它会运行必需的命令来设置您的 Git 钩子。但是，如果项目不是 Git 存储库，则无法运行。

如果您遇到与此相关的任何问题，请在初始化 Git 存储库后尝试重新运行`npm install --save-dev husky`。

### 练习 36：使用 Puppeteer 按文本获取元素

在这个练习中，我们将编写一个 Puppeteer 测试，验证一个小测验应用程序是否正常工作。如果你进入练习文件夹并找到*练习 36*的起点，你可以运行`npm start`来查看我们将要测试的测验：

![图 6.16：Puppeteer 显示一个小测验应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_16.jpg)

###### 图 6.16：Puppeteer 显示一个小测验应用程序

在这个应用程序中，点击问题的正确答案会使问题消失，分数增加一：

1.  在命令行中，导航到`Exercise36/start`练习文件夹并安装依赖项：

```js
npm install --save-dev jest puppeteer jest-puppeteer
```

1.  通过修改`scripts`部分，向`package.json`文件添加一个`test`脚本，使其看起来像下面这样：

```js
  "scripts": {
   "start": "http-server",
   "test": "jest"
  },
```

1.  在`package.json`中添加一个 Jest 部分，告诉 Jest 使用 Puppeteer 预设：

```js
  "jest": {
   "preset": "jest-puppeteer"
  },
```

1.  创建一个名为`jest-puppeteer.config.js`的文件，在其中告诉 Jest 在运行任何测试之前打开我们的测验应用程序：

```js
module.exports = {
  server: {
   command: 'npm start',
   port: 8080,
  },
}
```

1.  创建一个名为`__test__`的文件夹，我们将把我们的 Jest 测试放在其中：

```js
mkdir __test__
```

1.  在名为`quiz.test.js`的文件夹中创建一个测试。它应该包含以下内容来初始化我们的测试：

```js
describe('Quiz', () => {
  beforeAll(async () => {
   await page.goto('http://localhost:8080')
  })
// tests will go here
})
```

1.  接下来，用我们测验中的第一个问题的测试替换前面代码中的注释：

```js
  it('Check question #1', async () => {
   const q1 = await page.$("#q1");
   let rightAnswer = await q1.$x("//button[contains(text(), '10')]");
   await rightAnswer[0].click();
   const result = await page.$eval('#score', e => e.innerText);
   expect(result).toMatch('1');
  })
```

注意我们使用的`q1.$x("//button[contains(text(), '10')]")`。我们不是使用 ID，而是在答案中搜索包含文本`10`的按钮。当解析一个网站时，这可能非常有用，该网站没有在您需要交互的元素上使用 ID。

1.  在最后一步添加了以下测试。我们将添加三个新测试，每个问题一个：

```js
  it('Check question #2', async () => {
   const q2 = await page.$("#q2");
   let rightAnswer = await q2.$x("//button[contains(text(), '36')]");
   await rightAnswer[0].click();
   const result = await page.$eval('#score', e => e.innerText);
   expect(result).toMatch('2');
  })
  it('Check question #3', async () => {
   const q3 = await page.$("#q3");
   let rightAnswer = await q3.$x("//button[contains(text(), '9')]");
   await rightAnswer[0].click();
   const result = await page.$eval('#score', e => e.innerText);
   expect(result).toMatch('3');
  })
  it('Check question #4', async () => {
   const q4 = await page.$("#q4");
   let rightAnswer = await q4.$x("//button[contains(text(), '99')]");
   await rightAnswer[0].click();
   const result = await page.$eval('#score', e => e.innerText);
   expect(result).toMatch('4');
  })
```

注意每个测试的底部都有一个预期结果，比上一个高一个；这是我们在页面上跟踪分数。如果一切正常，第四个测试将找到一个分数为 4。

1.  最后，返回到命令行，以便我们可以确认正确的结果。运行以下`test`命令：

```js
npm test
```

以下是前面代码的输出：

![图 6.17：命令行确认正确的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_17.jpg)

###### 图 6.17：命令行确认正确的结果

如果一切正确，运行`npm test`应该看到四个通过的测试作为响应。

### 活动 7：将所有内容组合在一起

在这个活动中，我们将结合本章的几个方面。从使用 HTML/JavaScript 构建的预先构建的计算器开始，你的任务是：

+   创建一个`lint`命令，使用`eslint-config-airbnb-base`包检查项目是否符合`prettier`和`eslint`，就像在之前的练习中所做的那样。

+   使用`jest`安装`puppeteer`并在`package.json`中创建一个运行`jest`的`test`命令。

+   创建一个 Puppeteer 测试，使用计算器计算 777 乘以 777，并确保返回的答案是 603,729。

+   创建另一个 Puppeteer 测试来计算 3.14 除以 2，并确保返回的答案是 1.57。

+   安装并设置 Husky，在使用 Git 提交之前运行 linting 和测试命令。

执行以下步骤完成活动（高级步骤）：

1.  安装在 linting 练习中列出的开发人员依赖项（`eslint`，`prettier`，`eslint-config-airbnb-base`，`eslint-config-prettier`，`eslint-plugin-jest`和`eslint-plugin-import`）。

1.  添加一个`eslint`配置文件`.eslintrc`。

1.  添加一个`.prettierignore`文件。

1.  在`package.json`文件中添加一个`lint`命令。

1.  打开`assignment`文件夹，并安装使用 Puppeteer 和 Jest 的开发人员依赖项。

1.  通过修改`package.json`文件，添加一个选项告诉 Jest 使用`jest-puppeteer`预设。

1.  在`package.json`中添加一个`test`脚本来运行`jest`。

1.  创建一个`jest-puppeteer.config.js`来配置 Puppeteer。

1.  在`__tests__/calculator.js`创建一个测试文件。

1.  创建一个`.huskyrc`文件。

1.  通过运行`npm install --save-dev husky`安装`husky`作为开发人员依赖项。

**预期输出**

![图 6.18：最终输出显示 calc.test 通过](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_06_18.jpg)

###### 图 6.18：最终输出显示 calc.test 通过

完成任务后，您应该能够运行`npm run` `lint`命令和`npm test`命令，并像前面的截图中一样通过测试。

#### 注意

这个活动的解决方案可以在 602 页找到。

## 总结

在本章中，我们着重介绍了自动化测试的代码质量方面。我们从清晰命名和熟悉语言的行业惯例的基础知识开始。通过遵循这些惯例并清晰地书写，我们能够使我们的代码更易读和可重用。

从那里开始，我们看了一下如何使用一些流行的工具（包括 Prettier、ESLint、Jest、Puppeteer 和 Husky）在 Node.js 中创建 linting 和测试命令。

除了设置测试之外，我们还讨论了测试的类别和它们的用例。我们进行了单元测试，确保单个函数按预期工作，并进行了集成测试，将多个函数或程序的方面结合在一起，以确保它们一起工作。然后，我们进行了端到端测试，打开应用程序的界面并与其进行交互，就像最终用户一样。 

最后，我们看了如何通过 Git 钩子自动运行我们的 linting 和测试脚本。

在下一章中，我们将研究构造函数、promises 和 async/await。我们将使用其中一些技术以一种现代化的方式重构 JavaScript，利用 ES6 中提供的新功能。
