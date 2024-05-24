# JavaScript 函数式编程（一）

> 原文：[`zh.annas-archive.org/md5/14CAB13674AB79FC040D2749FA52D757`](https://zh.annas-archive.org/md5/14CAB13674AB79FC040D2749FA52D757)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

函数式编程是一种强调和使智能化代码编写的风格，可以最大程度地减少复杂性并增加模块化。这是一种通过巧妙地改变、组合和使用函数来编写更清洁的代码的方式。JavaScript 为这种方法提供了一个极好的媒介。互联网的脚本语言 JavaScript 实际上是一种本质上的函数式语言。通过学习如何暴露它作为函数式语言的真实身份，我们可以实现功能强大、更易于维护和更可靠的 Web 应用程序。通过这样做，JavaScript 的奇怪习惯和陷阱将突然变得清晰，整个语言将变得更加有意义。学习如何使用函数式编程将使您成为终身更好的程序员。

本书是为对学习函数式编程感兴趣的新老 JavaScript 开发人员而编写的指南。本书侧重于函数式编程技术、风格的发展以及 JavaScript 库的详细信息，将帮助您编写更智能的代码并成为更好的程序员。

# 本书涵盖的内容

第一章, *JavaScript 函数式一面的力量-演示*，通过使用传统方法和函数式编程来创建一个小型 Web 应用程序来开启本书的节奏。然后比较这两种方法，以突出函数式编程的重要性。

第二章, *函数式编程基础*，向您介绍了函数式编程的核心概念以及内置的 JavaScript 函数。

第三章, *设置函数式编程环境*，探讨了不同的 JavaScript 库以及它们如何优化用于函数式编程。

第四章, *在 JavaScript 中实现函数式编程技术*，解释了 JavaScript 中的函数式范式。它涵盖了几种函数式编程风格，并演示了它们如何在不同场景中使用。

第五章, *范畴论*，详细解释了范畴论的概念，然后在 JavaScript 中实现它。

第六章, *JavaScript 中的高级主题和陷阱*，强调了在 JavaScript 编程中可能遇到的各种缺点，以及成功处理它们的各种方法。

第七章, *JavaScript 中的函数式和面向对象编程*，将函数式编程和面向对象编程与 JavaScript 联系起来，并向您展示这两种范式如何相辅相成并共存。

附录 A, *JavaScript 中函数式编程的常用函数*，包含了在 JavaScript 中执行函数式编程所使用的常用函数。

附录 B, *术语表*，包括本书中使用的术语表。

# 本书需要什么

只需要一个浏览器就可以让您立即开始运行。

# 本书适合谁

如果您是一名对学习函数式编程感兴趣的 JavaScript 开发人员，希望在掌握 JavaScript 语言方面迈出一大步，或者只是想成为一名更好的程序员，那么这本书非常适合您。本指南旨在面向开发响应式前端应用程序、处理可靠性和并发性的服务器端应用程序以及其他各种应用程序的程序员。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以通过使用`include`指令包含其他上下文。"

代码块设置如下：

```js
Function.prototype.partialApply = function() {
  var func = this;
  args = Array.prototype.slice.call(arguments);
  return function() {
    return func.apply(this, args.concat(
      Array.prototype.slice.call(arguments)
    ));
  };
};
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
var messages = ['Hi', 'Hello', 'Sup', 'Hey', 'Hola'];
messages.map(function(s,i){
  return **printSomewhere**(s, i*10, i*10);
}).forEach(document.body.appendChild);
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："单击**下一步**按钮将您移至下一个屏幕。"

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：JavaScript 函数式编程的力量-演示

# 介绍

几十年来，函数式编程一直是计算机科学爱好者的宠儿，因其数学纯粹性和令人费解的特性而备受推崇，这使它隐藏在数据科学家和博士候选人占据的尘封的计算机实验室中。但现在，它正在复兴，这要归功于现代语言，如**Python**、**Julia**、**Ruby**、**Clojure**和——最后但并非最不重要的——**JavaScipt**。

你说 JavaScript？网络的脚本语言？是的！

JavaScript 已被证明是一种重要的技术，它不会很快消失。这在很大程度上是因为它能够通过新的框架和库（如**backbone.js**、**jQuery**、**Dojo**、**underscore.js**等）得到重生和扩展。*这直接关系到 JavaScript 作为一种函数式编程语言的真正身份*。对 JavaScript 的函数式编程的理解将长期受到欢迎，并对任何技能水平的程序员都将是有用的。

为什么这样？函数式编程非常强大、健壮和优雅。它在大型数据结构上非常有用和高效。将 JavaScript——一种客户端脚本语言，作为一种函数式手段来操作 DOM、对 API 响应进行排序或在日益复杂的网站上执行其他任务，可能非常有利。

在本书中，您将学习有关 JavaScript 函数式编程的一切：如何通过函数式编程增强 JavaScript 网络应用程序，如何解锁 JavaScript 的潜在力，以及如何编写更强大、更易于维护、下载速度更快、开销更小的代码。您还将学习函数式编程的核心概念，如何将其应用于 JavaScript，如何避开在使用 JavaScript 作为函数式语言时可能出现的注意事项和问题，以及如何在 JavaScript 中将函数式编程与面向对象编程相结合。

但在我们开始之前，让我们进行一个实验。

# 演示

也许一个快速的演示将是介绍 JavaScript 函数式编程的最佳方式。我们将使用 JavaScript 执行相同的任务——一次使用传统的本地方法，一次使用函数式编程。然后，我们将比较这两种方法。

# 应用程序-电子商务网站

在追求真实世界应用的过程中，假设我们需要为一家邮购咖啡豆公司开发一个电子商务网站应用程序。他们销售几种不同类型和不同数量的咖啡，这两者都会影响价格。

## 命令式方法

首先，让我们按照程序化的路线进行。为了使这个演示接地气，我们将创建保存数据的对象。这允许从数据库中获取值的能力，如果需要的话。但现在，我们假设它们是静态定义的：

```js
// create some objects to store the data.
var columbian = {
  name: 'columbian',
  basePrice: 5
};
var frenchRoast = {
  name: 'french roast',
  basePrice: 8
};
var decaf = {
  name: 'decaf',
  basePrice: 6
};

// we'll use a helper function to calculate the cost 
// according to the size and print it to an HTML list
function printPrice(coffee, size) {
  if (size == 'small') {
    var price = coffee.basePrice + 2;
  }
  else if (size == 'medium') {
    var price = coffee.basePrice + 4;
  }
  else {
    var price = coffee.basePrice + 6;
  }

// create the new html list item
  var node = document.createElement("li");
  var label = coffee.name + ' ' + size;
  var textnode = document.createTextNode(label+' price: $'+price);
  node.appendChild(textnode);
  document.getElementById('products').appendChild(node);
}

// now all we need to do is call the printPrice function
// for every single combination of coffee type and size
printPrice(columbian, 'small');
printPrice(columbian, 'medium');
printPrice(columbian, 'large');
printPrice(frenchRoast, 'small');
printPrice(frenchRoast, 'medium');
printPrice(frenchRoast, 'large');
printPrice(decaf, 'small');
printPrice(decaf, 'medium');
printPrice(decaf, 'large');
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

正如你所看到的，这段代码非常基础。如果这里不只是三种咖啡风格呢？如果有 20 种？50 种？如果除了大小之外，还有有机和非有机的选择。那将极大地增加代码行数！

使用这种方法，我们告诉机器为每种咖啡类型和每种大小打印什么。这基本上就是命令式代码的问题所在。

# 函数式编程

命令式代码告诉机器，逐步地，它需要做什么来解决问题，而函数式编程则试图以数学方式描述问题，以便机器可以做其余的工作。

采用更加函数式的方法，同样的应用可以写成如下形式：

```js
// separate the data and logic from the interface
var printPrice = function(price, label) {
  var node = document.createElement("li");
  var textnode = document.createTextNode(label+' price: $'+price);
  node.appendChild(textnode);
  document.getElementById('products 2').appendChild(node);
}

// create function objects for each type of coffee
var columbian = function(){
  this.name = 'columbian'; 
  this.basePrice = 5;
};
var frenchRoast = function(){
  this.name = 'french roast'; 
  this.basePrice = 8;
};
var decaf = function(){
  this.name = 'decaf'; 
  this.basePrice = 6;
};

// create object literals for the different sizes
var small = {
  getPrice: function(){return this.basePrice + 2},
  getLabel: function(){return this.name + ' small'}
};
var medium = {
  getPrice: function(){return this.basePrice + 4},
  getLabel: function(){return this.name + ' medium'}
};
var large = {
  getPrice: function(){return this.basePrice + 6},
  getLabel: function(){return this.name + ' large'}
};

// put all the coffee types and sizes into arrays
var coffeeTypes = [columbian, frenchRoast, decaf];
var coffeeSizes = [small, medium, large];

// build new objects that are combinations of the above
// and put them into a new array
var coffees = coffeeTypes.reduce(function(previous, current) {
  var newCoffee = coffeeSizes.map(function(mixin) {
    // `plusmix` function for functional mixins, see Ch.7
    var newCoffeeObj = plusMixin(current, mixin);
    return new newCoffeeObj();
  });
  return previous.concat(newCoffee);
},[]);

// we've now defined how to get the price and label for each
// coffee type and size combination, now we can just print them
coffees.forEach(function(coffee){
  printPrice(coffee.getPrice(),coffee.getLabel());
});
```

首先显而易见的是它更加模块化。这使得添加新的大小或新的咖啡类型就像下面的代码片段中所示的那样简单：

```js
var peruvian = function(){
  this.name = 'peruvian'; 
  this.basePrice = 11;
};

var extraLarge = {
  getPrice: function(){return this.basePrice + 10},
  getLabel: function(){return this.name + ' extra large'}
};

coffeeTypes.push(Peruvian);
coffeeSizes.push(extraLarge);
```

咖啡对象和大小对象的数组被“混合”在一起，也就是说，它们的方法和成员变量与一个名为`plusMixin`的自定义函数结合在一起（参见第七章，“JavaScript 中的函数式和面向对象编程”）。咖啡类型类包含成员变量，大小包含计算名称和价格的方法。 “混合”发生在`map`操作中，它对数组中的每个元素应用纯函数，并在`reduce()`操作中返回一个新函数——另一个类似于`map`函数的高阶函数，不同之处在于数组中的所有元素都合并成一个。最后，所有可能的类型和大小组合的新数组通过`forEach()`方法进行迭代。`forEach()`方法是另一个高阶函数，它对数组中的每个对象应用回调函数。在这个例子中，我们将其作为一个匿名函数提供，该函数实例化对象并调用`printPrice()`函数，其中包括对象的`getPrice()`和`getLabel()`方法作为参数。

实际上，我们可以通过移除`coffees`变量并将函数链接在一起使这个例子更加函数化——这是函数式编程中的另一个小技巧。

```js
coffeeTypes.reduce(function(previous, current) {
  var newCoffee = coffeeSizes.map(function(mixin) {
    // `plusMixin` function for functional mixins, see Ch.7
    var newCoffeeObj = plusMixin(current, mixin);
    return new newCoffeeObj();
  });
  return previous.concat(newCoffee);
},[]).forEach(function(coffee) {
  printPrice(coffee.getPrice(),coffee.getLabel());
});
```

此外，控制流不像命令式代码那样自上而下。在函数式编程中，`map()`函数和其他高阶函数取代了`for`和`while`循环，执行顺序的重要性很小。这使得新手更难阅读代码，但一旦掌握了，就会发现其实并不难跟踪，而且会发现它更好。

这个例子只是简单介绍了在 JavaScript 中函数式编程可以做什么。在本书中，你将看到更强大的函数式编程的例子。

# 总结

首先，采用函数式风格的好处是明显的。

其次，不要害怕函数式编程。是的，它经常被认为是以计算机语言形式的纯逻辑，但我们不需要理解**Lambda 演算**就能将其应用到日常任务中。事实上，通过允许我们的程序被分解成更小的部分，它们更容易理解，更简单维护，更可靠。`map()`和`reduce()`函数是 JavaScript 中较少为人知的内置函数，但我们会看一下它们。

JavaScript 是一种脚本语言，交互性强，易于接近。不需要编译。我们甚至不需要下载任何开发软件，你喜欢的浏览器可以作为解释器和开发环境。

感兴趣吗？好的，让我们开始吧！


# 第二章：函数式编程基础

到目前为止，你已经看到了函数式编程可以做些什么的一小部分。但函数式编程到底是什么？什么使一种语言是函数式的而另一种不是？什么使一种编程风格是函数式的而另一种不是？

在本章中，我们将首先回答这些问题，然后介绍函数式编程的核心概念：

+   使用函数和数组进行控制流

+   编写纯函数、匿名函数、递归函数等

+   像对象一样传递函数

+   利用 `map()`、`filter()` 和 `reduce()` 函数

# 函数式编程语言

函数式编程语言是促进函数式编程范式的语言。冒昧地说，我们可以说，如果一种语言包括函数式编程所需的特性，那么它就是一种函数式语言——就是这么简单。在大多数情况下，真正决定一个程序是否是函数式的是编程风格。

## 什么使一种语言是函数式的？

C 语言无法进行函数式编程。Java 语言也无法进行函数式编程（没有大量繁琐的“几乎”函数式编程的变通方法）。这些以及许多其他语言根本就不包含支持函数式编程的结构。它们纯粹是面向对象的，严格来说不是函数式语言。

同时，面向对象编程无法在纯函数式语言中进行，比如 Scheme、Haskell 和 Lisp，仅举几例。

然而，有些语言支持两种模型。Python 就是一个著名的例子，但还有其他的：Ruby、Julia，还有我们感兴趣的 JavaScript。这些语言如何支持两种非常不同的设计模式？它们包含了两种编程范式所需的特性。然而，在 JavaScript 的情况下，函数式特性有些隐藏。

但实际上，情况要复杂一些。那么什么使一种语言是函数式的呢？

| 特征 | 命令式 | 函数式 |
| --- | --- | --- |
| 编程风格 | 执行逐步任务和管理状态变化 | 定义问题是什么以及需要哪些数据转换来实现解决方案 |
| 状态变化 | 重要 | 不存在 |
| 执行顺序 | 重要 | 不重要 |
| 主要流程控制 | 循环、条件和函数调用 | 函数调用和递归 |
| 主要操作单元 | 结构和类对象 | 函数作为一等对象和数据集 |

语言的语法必须允许某些设计模式，比如隐式类型系统和使用匿名函数的能力。基本上，语言必须实现 Lambda 演算。此外，解释器的评估策略应该是非严格的和按需调用（也称为延迟执行），这允许不可变的数据结构和非严格的惰性评估。

## 优势

你可以说，当你最终“领悟”时所经历的深刻启示将使学习函数式编程变得值得。这样的经历将使你成为终身更好的程序员，无论你是否真的成为全职的函数式程序员。

但我们不是在谈论学习冥想；我们在谈论学习一种极其有用的工具，这将使你成为一个更好的程序员。

从形式上讲，使用函数式编程的实际优势是什么？

### 更清晰的代码

函数式程序更清洁、更简单、更小。这简化了调试、测试和维护。

例如，假设我们需要一个将二维数组转换为一维数组的函数。只使用命令式技术，我们可以这样写：

```js
function merge2dArrayIntoOne(arrays) {
  var count = arrays.length;
  var merged = new Array(count); 
  var c = 0;
  for (var i = 0; i < count; ++i) {
    for (var j = 0, jlen = arrays[i].length; j < jlen; ++j) {
      merged[c++] = arrays[i][j];
    }
  }
  return merged
}
```

并且使用函数式技术，可以写成如下形式：

```js
varmerge2dArrayIntoOne2 = function(arrays) {
  return arrays.reduce( function(p,n){
    return p.concat(n);
  });
};
```

这两个函数都接受相同的输入并返回相同的输出。然而，函数示例要简洁清晰得多。

### 模块化

函数式编程迫使将大问题分解为要解决的相同问题的较小实例。这意味着代码更加模块化。模块化的程序具有明确定义，更容易调试，更简单维护。测试更容易，因为每个模块化代码片段都可以潜在地检查正确性。

### 可重用性

由于函数式编程的模块化，函数式程序共享各种常见的辅助函数。您会发现这些函数中的许多函数可以被重用于各种不同的应用程序。

本章后面将介绍许多常见的函数。然而，作为函数式程序员，您将不可避免地编写自己的小函数库，这些函数可以反复使用。例如，一个设计良好的函数，用于搜索配置文件的行，也可以用于搜索哈希表。

### 减少耦合

耦合是程序中模块之间的依赖程度。因为函数式程序员致力于编写独立于彼此的一流、高阶、纯函数，不对全局变量产生副作用，所以耦合大大减少。当然，函数将不可避免地相互依赖。但只要输入到输出的一对一映射保持正确，修改一个函数不会改变另一个函数。

### 数学上的正确性

最后一个是在更理论的层面上。由于其源自 Lambda 演算，函数式程序可以在数学上被证明是正确的。这对需要证明程序的增长率、时间复杂度和数学正确性的研究人员来说是一个巨大优势。

让我们来看看斐波那契数列。尽管它很少用于除了概念验证之外的任何其他用途，但它很好地说明了这个概念。评估斐波那契数列的标准方法是创建一个递归函数，表达式为`fibonnaci(n) = fibonnaci(n-2) + fibonnaci(n–1)`，并且有一个基本情况，即`当 n < 2 时返回 1`，这样可以停止递归并开始在递归调用堆栈的每一步返回的值上进行求和。

这描述了计算序列所涉及的中间步骤。

```js
var fibonacci = function(n) {
  if (n < 2) {
    return 1;
  }
  else {
    return fibonacci(n - 2) + fibonacci(n - 1);
  }
}
console.log( fibonacci(8) );
// Output: 34
```

然而，借助实现惰性执行策略的库，可以生成一个无限序列，该序列陈述了定义整个数字序列的*数学方程*。只有需要计算的数字才会被计算。

```js
var fibonacci2 = Lazy.generate(function() {
  var x = 1,
  y = 1;
  return function() {
    var prev = x;
    x = y;
    y += prev;
    return prev;
  };
}());

console.log(fibonacci2.length());// Output: undefined

console.log(fibonacci2.take(12).toArray());// Output: [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144] 

var fibonacci3 = Lazy.generate(function() {
  var x = 1,
  y = 1;
  return function() {
    var prev = x;
    x = y;
    y += prev;
    return prev;
  };
}());

console.log(fibonacci3.take(9).reverse().first(1).toArray());// Output: [34]
```

第二个例子显然更具数学上的合理性。它依赖于 JavaScript 的`Lazy.js`库。还有其他可以帮助的库，比如`Sloth.js`和`wu.js`。这些将在第三章中进行介绍，*设置函数式编程环境*。

## 非函数式世界中的函数式编程

函数式和非函数式编程可以混合在一起吗？尽管这是第七章的主题，*JavaScript 中的函数式和面向对象编程*，但在我们继续之前，有几件事情需要搞清楚。

本书的目的不是教您如何实现严格遵循纯函数式编程严格要求的整个应用程序。这样的应用程序在学术界之外很少合适。相反，本书将教您如何在应用程序中使用函数式编程设计策略，以补充必要的命令式代码。

例如，如果您需要从某个文本中提取出的前四个只包含字母的单词，可以天真地写成这样：

```js
var words = [], count = 0;
text = myString.split(' ');
for (i=0; count<4, i<text.length; i++) {
  if (!text[i].match(/[0-9]/)) {
    words = words.concat(text[i]);
    count++;
  }
}
console.log(words);
```

相比之下，函数式程序员可能会这样写：

```js
var words = [];
var words = myString.split(' ').filter(function(x){
  return (! x.match(/[1-9]+/));
}).slice(0,4);
console.log(words);
```

或者，通过一个函数式编程工具库，它们甚至可以更简化：

```js
var words = toSequence(myString).match(/[a-zA-Z]+/).first(4);
```

识别可以以更函数式方式编写的函数的关键是查找循环和临时变量，例如前面示例中的`words`和`count`实例。通常我们可以通过用高阶函数替换它们来摆脱临时变量和循环，我们将在本章后面探讨这一点。

### JavaScript 是一种函数式编程语言吗？

我们必须问自己最后一个问题。JavaScript 是一种函数式语言还是非函数式语言？

JavaScript 可以说是世界上最流行但最不被理解的函数式编程语言。JavaScript 是一种穿着 C 样式衣服的函数式编程语言。它的语法无可否认地类似于 C，意味着它使用 C 的块语法和中缀顺序。而且它是存在的最糟糕的命名语言之一。毫不费力地可以想象为什么这么多人会混淆 JavaScript 与 Java 有关；不知何故，它的名字暗示着它应该有关联！但实际上它与 Java 几乎没有共同之处。而且，为了真正巩固 JavaScript 是一种面向对象的语言的想法，诸如 Dojo 和**ease.js**等库和框架一直在努力将其抽象化，并使其适用于面向对象的编程。JavaScript 在 20 世纪 90 年代成熟起来，当时面向对象编程是所有人都在谈论的话题，我们被告知 JavaScript 是面向对象的，因为我们非常希望它是这样。但它并不是。

它的真正身份更与其祖先相一致：Scheme 和 Lisp，两种经典的函数式语言。JavaScript 是一种纯函数式语言。它的函数是一等公民，可以嵌套，具有闭包和组合，并且允许柯里化和单子。所有这些都是函数式编程的关键。以下是 JavaScript 是函数式语言的几个原因：

+   JavaScript 的词法语法包括将函数作为参数传递的能力，具有推断类型系统，并允许匿名函数、高阶函数、闭包等。这些事实对于实现函数式编程的结构和行为至关重要。

+   它不是一种纯粹的面向对象语言，大多数面向对象的设计模式是通过复制原型对象来实现的，这是一种较弱的面向对象编程模型。**欧洲计算机制造商协会脚本**（**ECMAScript**），JavaScript 的正式和标准化实现规范，在规范 4.2.1 中陈述了以下内容：

> *“ECMAScript 不包含像 C++、Smalltalk 或 Java 中那样的适当类，而是支持创建对象的构造函数。在基于类的面向对象语言中，一般来说，状态由实例承载，方法由类承载，继承仅涉及结构和行为。在 ECMAScript 中，状态和方法由对象承载，结构、行为和状态都是继承的。”*

+   它是一种解释性语言。有时被称为“引擎”，JavaScript 解释器通常与 Scheme 解释器非常相似。两者都是动态的，都具有灵活的数据类型，可以轻松组合和转换，都将代码评估为表达式块，并且都类似地处理函数。

也就是说，JavaScript 并不是一种纯函数式语言。缺少的是惰性求值和内置的不可变数据。这是因为大多数解释器是按名称调用而不是按需调用。由于它处理尾调用的方式，JavaScript 也不太擅长递归。然而，所有这些问题都可以通过一点注意来缓解。非严格求值，用于无限序列和惰性求值，可以通过一个名为`Lazy.js`的库来实现。不可变数据可以通过编程技术简单实现，但这需要更多的程序员纪律，而不是依赖语言来处理。递归尾调用消除可以通过一种称为**Trampolining**的方法来实现。这些问题将在第六章中得到解决，*JavaScript 中的高级主题和陷阱*。

关于 JavaScript 是一种函数式语言、面向对象语言、两者都是还是两者都不是，已经进行了许多争论。而且这不会是最后一次辩论。

最终，函数式编程是通过巧妙地改变、组合和使用函数的方式来编写更清晰的代码。JavaScript 为这种方法提供了一个出色的媒介。如果您真的想要充分发挥 JavaScript 的潜力，您必须学会将其用作一种函数式语言。

# 使用函数

|   | *有时，优雅的实现是一个函数。不是一个方法。不是一个类。不是一个框架。只是一个函数。* |   |
| --- | --- | --- |
|   | --*约翰·卡马克，末日游戏的首席程序员* |

函数式编程是将问题分解为一组函数的过程。通常，函数被链接在一起，嵌套在彼此内部，传递并被视为一等公民。如果您使用过 jQuery 和 Node.js 等框架，您可能已经使用了其中一些技术，只是您没有意识到！

让我们从一个小 JavaScript 困境开始。

我们需要编译一个分配给通用对象的值列表。对象可以是任何东西：日期、HTML 对象等等。

```js
var
  obj1 = {value: 1},
  obj2 = {value: 2},
  obj3 = {value: 3};

var values = [];
function accumulate(obj) {
  values.push(obj.value);
}
accumulate(obj1);
accumulate(obj2);
console.log(values); // Output: [obj1.value, obj2.value]
```

它能工作，但它是不稳定的。任何代码都可以修改`values`对象，而不调用`accumulate()`函数。如果我们忘记将空集`[]`分配给`values`实例，那么代码将根本无法工作。

但是，如果变量在函数内声明，它就不能被任何不受控制的代码改变。

```js
function accumulate2(obj) {
  var values = [];
  values.push(obj.value);
  return values;
}
console.log(accumulate2(obj1)); // Returns: [obj1.value]
console.log(accumulate2(obj2)); // Returns: [obj2.value]
console.log(accumulate2(obj3)); // Returns: [obj3.value]
```

它不起作用！只返回最后传入的对象的值。

我们可能可以通过在第一个函数内部嵌套一个函数来解决这个问题。

```js
var ValueAccumulator = function(obj) {
  var values = []
  var accumulate = function() {
    values.push(obj.value);   
  };
  accumulate();
  return values;
};
```

但问题是一样的，现在我们无法访问`accumulate`函数或`values`变量。

我们需要的是一个自调用函数。

## 自调用函数和闭包

如果我们能返回一个函数表达式，该表达式反过来返回`values`数组呢？在函数中声明的变量对函数内的任何代码都是可用的，包括自调用函数。

通过使用自调用函数，我们解决了我们的困境。

```js
var ValueAccumulator = function() {
  var values = [];
  var accumulate = function(obj) {
    if (obj) {
      values.push(obj.value);
      return values;
    }
    else {
      return values;
    }
  };
  return accumulate;
};

//This allows us to do this:
var accumulator = ValueAccumulator();
accumulator(obj1); 
accumulator(obj2); 
console.log(accumulator()); 
// Output: [obj1.value, obj2.value]
```

这都与变量作用域有关。`values`变量对内部的`accumulate()`函数是可用的，即使在作用域外部调用函数时也是如此。这就是闭包。

### 注意

JavaScript 中的闭包是指即使父函数已关闭，也可以访问父作用域的函数。

闭包是所有函数式语言的特性。传统的命令式语言不允许它们。

## 高阶函数

自调用函数实际上是一种高阶函数形式。高阶函数是要么将另一个函数作为输入，要么将一个函数作为输出的函数。

高阶函数在传统编程中并不常见。在命令式编程中，程序员可能会使用循环来迭代数组，而函数式编程者则会采取完全不同的方法。通过使用高阶函数，可以通过将该函数应用于数组中的每个项来对数组进行操作，从而创建一个新数组。

这是函数式编程范式的核心思想。高阶函数允许将逻辑传递给其他函数，就像对象一样。

在 JavaScript 中，函数被视为一等公民，这是 JavaScript 与 Scheme、Haskell 和其他经典函数式语言共享的特点。这听起来很奇怪，但这实际上意味着函数被视为原语，就像数字和对象一样。如果数字和对象可以被传递，那么函数也可以被传递。

为了看到这一点，让我们在前面部分的`ValueAccumulator()`函数中使用一个高阶函数：

```js
// using forEach() to iterate through an array and call a 
// callback function, accumulator, for each item
var accumulator2 = ValueAccumulator();
var objects = [obj1, obj2, obj3]; // could be huge array of objects
objects.forEach(accumulator2);
console.log(accumulator2());
```

## 纯函数

纯函数返回仅使用传递给它的输入计算的值。不能使用外部变量和全局状态，也不能产生副作用。换句话说，它不能改变传递给它的输入变量。因此，纯函数只能用于它们的返回值。

一个简单的例子是数学函数。`Math.sqrt(4)`函数将始终返回`2`，不使用任何隐藏信息，如设置或状态，并且永远不会产生任何副作用。

纯函数是对数学术语“函数”的真正解释，它是输入和输出之间的关系。它们很容易理解，并且可以被很容易地重复使用。因为它们是完全独立的，所以纯函数更有可能被反复使用。

为了说明这一点，比较以下非纯函数和纯函数。

```js
// function that prints a message to the center of the screen
var printCenter = function(str) {
  var elem = document.createElement("div");
  elem.textContent = str;
  elem.style.position = 'absolute';
  elem.style.top = window.innerHeight/2+"px";
  elem.style.left = window.innerWidth/2+"px";
  document.body.appendChild(elem);
};
printCenter('hello world');
// pure function that accomplishes the same thing
var printSomewhere = function(str, height, width) {
  var elem = document.createElement("div");
  elem.textContent = str;
  elem.style.position = 'absolute';
  elem.style.top = height;
  elem.style.left = width;
  return elem;
};
document.body.appendChild(printSomewhere('hello world', window.innerHeight/2)+10+"px",window.innerWidth/2)+10+"px")
);
```

非纯函数依赖于窗口对象的状态来计算高度和宽度，而纯自给自足的函数则要求传入这些值。实际上，这样做可以让消息在任何地方打印，这使得函数更加灵活。

虽然非纯函数可能看起来更容易，因为它自己执行附加而不是返回一个元素，但纯函数`printSomewhere()`及其返回值与其他函数式编程设计技术更配合。

```js
var messages = ['Hi', 'Hello', 'Sup', 'Hey', 'Hola'];
messages.map(function(s,i){
  return printSomewhere(s, 100*i*10, 100*i*10);
}).forEach(function(element) {
  document.body.appendChild(element);
});
```

### 注意

当函数是纯的并且不依赖于状态或环境时，我们不关心它们实际上何时何地被计算。稍后我们将在惰性求值中看到这一点。

## 匿名函数

将函数视为一等公民的另一个好处是匿名函数的出现。

顾名思义，匿名函数是没有名称的函数。但它们不仅仅是这样。它们允许根据需要定义临时逻辑。通常是为了方便起见；如果函数只被引用一次，那么就不需要浪费一个变量名。

一些匿名函数的例子如下：

```js
// The standard way to write anonymous functions
function(){return "hello world"};

// Anonymous function assigned to variable
var anon = function(x,y){return x+y};

// Anonymous function used in place of a named callback function, 
// this is one of the more common uses of anonymous functions.
setInterval(function(){console.log(new Date().getTime())}, 1000);
// Output:  1413249010672, 1413249010673, 1413249010674, ...

// Without wrapping it in an anonymous function, it immediately // execute once and then return undefined as the callback:
setInterval(console.log(new Date().getTime()), 1000)
// Output:  1413249010671
```

在高阶函数中使用匿名函数的更复杂的例子：

```js
function powersOf(x) {
  return function(y) {
    // this is an anonymous function!
    return Math.pow(x,y);
  };
}
powerOfTwo = powersOf(2);
console.log(powerOfTwo(1)); // 2
console.log(powerOfTwo(2)); // 4
console.log(powerOfTwo(3)); // 8

powerOfThree = powersOf(3);
console.log(powerOfThree(3));  // 9
console.log(powerOfThree(10)); // 59049
```

返回的函数不需要被命名；它不能在`powersOf()`函数之外的任何地方使用，因此它是一个匿名函数。

记得我们的累加器函数吗？可以使用匿名函数来重写它。

```js
var
  obj1 = {value: 1},
  obj2 = {value: 2},
  obj3 = {value: 3};

var values = (function() {
  // anonymous function
  var values = [];
  return function(obj) {
    // another anonymous function!
    if (obj) {
      values.push(obj.value);
      return values;
    }
    else {
      return values;
    }
  }
})(); // make it self-executing
console.log(values(obj1)); // Returns: [obj.value]
console.log(values(obj2)); // Returns: [obj.value, obj2.value]
```

太好了！一个纯的、高阶的、匿名的函数。我们怎么会这么幸运呢？实际上，它不仅仅是这样。它还是*自执行*的，如结构`(function(){...})();`所示。匿名函数后面的一对括号会立即调用函数。在上面的例子中，`values`实例被赋值为自执行函数调用的输出。

### 注意

匿名函数不仅仅是一种语法糖。它们是 Lambda 演算的体现。跟我一起来理解一下……Lambda 演算是在计算机或计算机语言出现之前发明的。它只是用于推理函数的数学概念。令人惊讶的是，尽管它只定义了三种表达式：变量引用、函数调用和*匿名函数*，它却是图灵完备的。今天，如果你知道如何找到它，Lambda 演算是所有函数式语言的核心，包括 JavaScript。

因此，匿名函数通常被称为 Lambda 表达式。

匿名函数的一个缺点是它们很难在调用堆栈中识别，这使得调试变得更加棘手。应该谨慎使用它们。

## 方法链

在 JavaScript 中链接方法是相当常见的。如果你使用过 jQuery，你可能已经使用过这种技术。有时被称为“构建器模式”。

这是一种用于简化代码的技术，其中多个函数依次应用于对象。

```js
// Instead of applying the functions one per line...
arr = [1,2,3,4];
arr1 = arr.reverse();
arr2 = arr1.concat([5,6]);
arr3 = arr2.map(Math.sqrt);
// ...they can be chained together into a one-liner
console.log([1,2,3,4].reverse().concat([5,6]).map(Math.sqrt));
// parentheses may be used to illustrate
console.log(((([1,2,3,4]).reverse()).concat([5,6])).map(Math.sqrt) );
```

这只有在函数是对象的方法时才有效。如果你创建了自己的函数，例如，接受两个数组并返回一个将这两个数组合并在一起的数组，你必须将它声明为`Array.prototype`对象的成员。看一下以下代码片段：

```js
Array.prototype.zip = function(arr2) {
  // ...
}
```

这将使我们能够做到以下几点：

```js
arr.zip([11,12,13,14).map(function(n){return n*2});
// Output: 2, 22, 4, 24, 6, 26, 8, 28
```

## 递归

递归很可能是最著名的函数式编程技术。如果你还不知道，递归函数是调用自身的函数。

当一个函数调用*它自己*时，会发生一些奇怪的事情。它既像一个循环，执行相同的代码多次，又像一个函数堆栈。

递归函数必须非常小心地避免无限循环（在这种情况下是无限递归）。因此，就像循环一样，必须使用条件来知道何时停止。这被称为基本情况。

一个例子如下：

```js
var foo = function(n) {
  if (n < 0) {
    // base case
    return 'hello';
  }
  else {
    // recursive case
    foo(n-1);
  }
}
console.log(foo(5));
```

可以将任何循环转换为递归算法，也可以将任何递归算法转换为循环。但是递归算法更适合，几乎是必要的，用于与适合使用循环的情况大不相同的情况。

一个很好的例子是树的遍历。虽然使用递归函数遍历树并不太难，但使用循环会更加复杂，并且需要维护一个堆栈。这与函数式编程的精神相违背。

```js
var getLeafs = function(node) {
  if (node.childNodes.length == 0) {
    // base case
    return node.innerText;
  }
  else {
    // recursive case: 
    return node.childNodes.map(getLeafs);
  }
}
```

### 分而治之

递归不仅仅是一种在没有`for`和`while`循环的情况下进行迭代的有趣方式。一种算法设计，称为分而治之，将问题递归地分解为相同问题的较小实例，直到它们足够小以便解决。

这方面的历史例子是欧几里得算法，用于找到两个数的最大公约数。

```js
function gcd(a, b) {
  if (b == 0) {
    // base case (conquer)
    return a;
  }
  else {
    // recursive case (divide)
    return gcd(b, a % b);
  }
}

console.log(gcd(12,8));
console.log(gcd(100,20));
```

所以从理论上讲，分而治之的工作方式非常优雅，但它在现实世界中有用吗？是的！JavaScript 中用于对数组进行排序的函数并不是很好。它不仅会就地对数组进行排序，这意味着数据是不可变的，而且它也不可靠和灵活。通过分而治之，我们可以做得更好。

归并排序算法使用分而治之的递归算法设计，通过递归地将数组分成较小的子数组，然后将它们合并在一起来高效地对数组进行排序。

在 JavaScript 中的完整实现大约有 40 行代码。然而，伪代码如下：

```js
var mergeSort = function(arr){
  if (arr.length < 2) {
    // base case: 0 or 1 item arrays don't need sorting
    return items;
  }
  else {
    // recursive case: divide the array, sort, then merge
    var middle = Math.floor(arr.length / 2);
    // divide
    var left = mergeSort(arr.slice(0, middle));
    var right = mergeSort(arr.slice(middle));
    // conquer
    // merge is a helper function that returns a new array
    // of the two arrays merged together
    return merge(left, right);
  }
}
```

## 惰性求值

惰性评估，也称为非严格评估、按需调用和延迟执行，是一种等到需要值时才计算函数结果的评估策略，对函数式编程非常有用。很明显，一行代码 `x = func()` 表示要将 `x` 赋值为 `func()` 返回的值。但是 `x` 实际上等于什么并不重要，直到需要它为止。等到需要 `x` 时再调用 `func()` 就是惰性评估。

这种策略可以大大提高性能，特别是在方法链和数组中使用时，这是函数式编程者最喜欢的程序流技术。

惰性评估的一个令人兴奋的好处是存在无限序列。因为直到不能再延迟才实际计算任何东西，所以这是可能的：

```js
// wishful JavaScript pseudocode:
var infinateNums = range(1 to infinity);
var tenPrimes = infinateNums.getPrimeNumbers().first(10);
```

这为许多可能性打开了大门：异步执行、并行化和组合，仅举几例。

然而，有一个问题：JavaScript 本身不执行惰性评估。也就是说，存在着一些用于 JavaScript 的库，可以非常好地模拟惰性评估。这就是《第三章》《设置函数式编程环境》的主题。

# 函数式编程者的工具包

如果你仔细看了到目前为止呈现的几个例子，你会注意到使用了一些你可能不熟悉的方法。它们是 `map()`、`filter()` 和 `reduce()` 函数，对任何语言的函数式程序都至关重要。它们使你能够消除循环和语句，从而使代码更加清晰。

`map()`、`filter()` 和 `reduce()` 函数构成了函数式编程者工具包的核心，这是一组纯的高阶函数，是函数式方法的工作马。事实上，它们是纯函数和高阶函数应该具有的典范；它们接受一个函数作为输入，并返回一个没有副作用的输出。

虽然它们是 ECMAScript 5.1 实现的浏览器的标准，但它们只适用于数组。每次调用时，都会创建并返回一个新数组。现有数组不会被修改。但还有更多，*它们接受函数作为输入*，通常以匿名函数的形式作为回调函数；它们遍历数组并将函数应用于数组中的每个项目！

```js
myArray = [1,2,3,4];
newArray = myArray.map(function(x) {return x*2});
console.log(myArray);  // Output: [1,2,3,4]
console.log(newArray); // Output: [2,4,6,8]
```

还有一点。因为它们只适用于数组，所以不能用于其他可迭代的数据结构，比如某些对象。不用担心，诸如 `underscore.js`、`Lazy.js`、`stream.js` 等库都实现了自己的 `map()`、`filter()` 和 `reduce()` 方法，更加灵活。

## 回调

如果你以前从未使用过回调函数，可能会觉得这个概念有点费解。特别是在 JavaScript 中，因为 JavaScript 允许以多种方式声明函数。

`callback()` 函数用于传递给其他函数以供其使用。这是一种传递逻辑的方式，就像传递对象一样：

```js
var myArray = [1,2,3];
function myCallback(x){return x+1};
console.log(myArray.map(myCallback));
```

为了简化简单的任务，可以使用匿名函数：

```js
console.log(myArray.map(function(x){return x+1}));
```

它们不仅用于函数式编程，还用于 JavaScript 中的许多其他事情。仅举一个例子，这是在使用 jQuery 进行 AJAX 调用时使用的 `callback()` 函数：

```js
function myCallback(xhr){
  console.log(xhr.status); 
  return true;
}
$.ajax(myURI).done(myCallback);
```

注意只使用了函数的名称。因为我们没有调用回调，只是传递了它的名称，所以写成这样是错误的：

```js
$.ajax(myURI).fail(**myCallback(xhr)**);
// or
$.ajax(myURI).fail(**myCallback()**);
```

如果我们调用回调会发生什么？在这种情况下，`myCallback(xhr)` 方法将尝试执行——控制台将打印“undefined”，并返回 `True`。当 `ajax()` 调用完成时，它将以 'true' 作为要使用的回调函数的名称，这将引发错误。

这也意味着我们无法指定传递给回调函数的参数。如果我们需要与`ajax()`调用传递给它的参数不同的参数，我们可以将回调函数包装在匿名函数中：

```js
function myCallback(status){
  console.log(status); 
  return true;
}
$.ajax(myURI).done(function(xhr){myCallback(xhr.status)});
```

## Array.prototype.map()

`map()`函数是这一系列中的头目。它只是在数组中的每个项目上应用回调函数。

### 注意

语法：`arr.map(callback [, thisArg]);`

参数：

+   `回调()`: 此函数为新数组生成一个元素，接收以下参数：

+   `currentValue`：此参数给出正在处理的数组中的当前元素

+   `索引`：此参数给出数组中当前元素的索引

+   `数组`：此参数给出正在处理的数组

+   `thisArg()`: 此函数是可选的。在执行`回调`时，该值将被用作`this`。

示例：

```js
var
  integers = [1,-0,9,-8,3],
  numbers = [1,2,3,4],
  str = 'hello world how ya doing?';
// map integers to their absolute values
console.log(integers.map(Math.abs));

// multiply an array of numbers by their position in the array
console.log(numbers.map(function(x, i){return x*i}) );

// Capitalize every other word in a string.
console.log(str.split(' ').map(function(s, i){
  if (i%2 == 0) {
    return s.toUpperCase();
  }
  else {
    return s;
  }
}) );
```

### 注意

虽然`Array.prototype.map`方法是 JavaScript 中数组对象的标准方法，但它也可以很容易地扩展到您的自定义对象。

```js
MyObject.prototype.map = function(f) {
  return new MyObject(f(this.value));
};
```

## Array.prototype.filter()

`filter()`函数用于从数组中取出元素。回调必须返回`True`（以在新数组中包含该项）或`False`（以删除该项）。使用`map()`函数并返回要删除的项目的`null`值也可以实现类似的效果，但`filter()`函数将从新数组中删除该项，而不是在其位置插入`null`值。

### 注意

语法：`arr.filter(callback [, thisArg]);`

参数：

+   `回调()`: 此函数用于测试数组中的每个元素。返回`True`以保留该元素，否则返回`False`。具有以下参数：

+   `currentValue`：此参数给出正在处理的数组中的当前元素

+   `索引`：此参数给出数组中当前元素的索引

+   `数组`：此参数给出正在处理的数组。

+   `thisArg()`: 此函数是可选的。在执行`回调`时，该值将被用作`this`。

示例：

```js
var myarray = [1,2,3,4]
words = 'hello 123 world how 345 ya doing'.split(' ');
re = '[a-zA-Z]';
// remove all negative numbers
console.log([-2,-1,0,1,2].filter(function(x){return x>0}));
// remove null values after a map operation
console.log(words.filter(function(s){
  return s.match(re);
}) );
// remove random objects from an array
console.log(myarray.filter(function(){
  return Math.floor(Math.random()*2)})
);
```

## Array.prototype.reduce()

有时称为折叠，`reduce()`函数用于将数组的所有值累积为一个值。回调需要返回要执行的逻辑以组合对象。对于数字，它们通常相加以获得总和或相乘以获得乘积。对于字符串，通常将字符串追加在一起。

### 注意

语法：`arr.reduce(callback [, initialValue]);`

参数：

+   `回调()`: 此函数将两个对象合并为一个，并返回。具有以下参数：

+   `previousValue`：此参数给出上一次调用回调时返回的值，或者如果提供了`initialValue`，则给出`initialValue`

+   `currentValue`：此参数给出正在处理的数组中的当前元素

+   `索引`：此参数给出数组中当前元素的索引

+   `数组`：此参数给出正在处理的数组

+   `initialValue()`: 此函数是可选的。用作`回调`的第一个参数的对象。

示例：

```js
var numbers = [1,2,3,4];
// sum up all the values of an array
console.log([1,2,3,4,5].reduce(function(x,y){return x+y}, 0));
// sum up all the values of an array
console.log([1,2,3,4,5].reduce(function(x,y){return x+y}, 0));

// find the largest number
console.log(numbers.reduce(function(a,b){
  return Math.max(a,b)}) // max takes two arguments
);
```

## 荣誉提及

`map()`、`filter()`和`reduce()`函数并不是我们辅助函数工具箱中的唯一函数。还有许多其他函数可以插入到几乎任何功能应用程序中。

### Array.prototype.forEach

本质上是`map()`的非纯版本，`forEach()`遍历数组并在每个项目上应用`回调()`函数。但它不返回任何东西。这是执行`for`循环的更干净的方式。

### 注意

语法：`arr.forEach(callback [, thisArg]);`

参数：

+   `回调()`: 此函数用于对数组的每个值执行。具有以下参数：

+   `currentValue`：此参数给出正在处理的数组中的当前元素

+   `索引`：此参数给出数组中当前元素的索引

+   `数组`：此参数给出正在处理的数组

+   `thisArg`：此函数是可选的。在执行`回调`时，该值将被用作`this`。

示例：

```js
var arr = [1,2,3];
var nodes = arr.map(function(x) {
  var elem = document.createElement("div");
  elem.textContent = x;
  return elem;
});

// log the value of each item
arr.forEach(function(x){console.log(x)});

// append nodes to the DOM
nodes.forEach(function(x){document.body.appendChild(x)});
```

### Array.prototype.concat

在处理数组时，通常需要将多个数组连接在一起，而不是使用`for`和`while`循环。另一个内置的 JavaScript 函数`concat()`可以为我们处理这个问题。`concat()`函数返回一个新数组，不会改变旧数组。它可以连接你传递给它的任意多个数组。

```js
console.log([1, 2, 3].concat(['a','b','c']) // concatenate two arrays);
// Output: [1, 2, 3, 'a','b','c']
```

原始数组不受影响。它返回一个新数组，其中包含两个数组连接在一起。这也意味着`concat()`函数可以链接在一起。

```js
var arr1 = [1,2,3];
var arr2 = [4,5,6];
var arr3 = [7,8,9];
var x = arr1.concat(arr2, arr3);
var y = arr1.concat(arr2).concat(arr3));
var z = arr1.concat(arr2.concat(arr3)));
console.log(x);
console.log(y);
console.log(z);
```

变量`x`、`y`和`z`都包含`[1,2,3,4,5,6,7,8,9]`。

### Array.prototype.reverse

另一个原生 JavaScript 函数有助于数组转换。`reverse()`函数颠倒了一个数组，使得第一个元素现在是最后一个，最后一个是第一个。

然而，它不会返回一个新数组；而是就地改变数组。我们可以做得更好。下面是一个纯方法的实现，用于颠倒一个数组：

```js
var invert = function(arr) {
  return arr.map(function(x, i, a) {
    return a[a.length - (i+1)];
  });
};
var q = invert([1,2,3,4]);
console.log( q );
```

### Array.prototype.sort

与我们的`map()`、`filter()`和`reduce()`方法类似，`sort()`方法接受一个定义数组中对象应如何排序的`callback()`函数。但是，与`reverse()`函数一样，它会就地改变数组。这样做不好。

```js
arr = [200, 12, 56, 7, 344];
console.log(arr.sort(function(a,b){return a–b}) );
// arr is now: [7, 12, 56, 200, 344];
```

我们可以编写一个不会改变数组的纯`sort()`函数，但是排序算法是让人头疼的源泉。需要排序的大型数组应该被组织在专门设计用于此目的的数据结构中：quickStort、mergeSort、bubbleSort 等等。

### Array.prototype.every 和 Array.prototype.some

`Array.prototype.every()`和`Array.prototype.some()`函数都是纯函数和高阶函数，是`Array`对象的方法，用于对数组的元素进行测试，以便返回一个表示相应输入的布尔值的`callback()`函数。如果`callback()`函数对数组中的每个元素都返回`True`，则`every()`函数返回`True`，而`some()`函数返回`True`，如果数组中的一些元素为`True`。

示例：

```js
function isNumber(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

console.log([1, 2, 3, 4].every(isNumber)); // Return: true
console.log([1, 2, 'a'].every(isNumber)); // Return: false
console.log([1, 2, 'a'].some(isNumber)); // Return: true
```

# 摘要

为了理解函数式编程，本章涵盖了一系列广泛的主题。首先，我们分析了编程语言为函数式编程意味着什么，然后评估了 JavaScript 的函数式编程能力。接下来，我们使用 JavaScript 应用了函数式编程的核心概念，并展示了一些 JavaScript 的内置函数用于函数式编程。

尽管 JavaScript 确实有一些用于函数式编程的工具，但其函数式核心仍然大多隐藏，还有很多需要改进的地方。在下一章中，我们将探索几个用于 JavaScript 的库，这些库揭示了其函数式的本质。


# 第三章：设置函数式编程环境

# 介绍

我们是否需要了解高级数学——范畴论、Lambda 演算、多态——才能使用函数式编程编写应用程序？我们是否需要重新发明轮子？对这两个问题的简短回答都是*不*。

在本章中，我们将尽力调查一切可能影响我们在 JavaScript 中编写函数式应用程序的方式。

+   库

+   工具包

+   开发环境

+   编译为 JavaScript 的函数式语言

+   等等

请理解，JavaScript 的函数库当前的格局是非常不确定的。就像计算机编程的所有方面一样，社区可能会在一瞬间发生变化；新的库可能会被采用，旧的库可能会被抛弃。例如，在撰写本书的过程中，流行且稳定的`Node.js`平台已被其开源社区分叉。它的未来是模糊的。

因此，从本章中获得的最重要的概念不是如何使用当前的库进行函数式编程，而是如何使用任何增强 JavaScript 函数式编程方法的库。本章不会专注于只有一两个库，而是将尽可能多地探索所有存在于 JavaScript 中的函数式编程风格。

# JavaScript 的函数库

据说每个函数式程序员都会编写自己的函数库，函数式 JavaScript 程序员也不例外。如今的开源代码共享平台，如 GitHub、Bower 和 NPM，使得分享、合作和发展这些库变得更加容易。存在许多用于 JavaScript 函数式编程的库，从微小的工具包到庞大的模块库不等。

每个库都推广其自己的函数式编程风格。从严格的、基于数学的风格到轻松的、非正式的风格，每个库都不同，但它们都有一个共同的特点：它们都具有抽象的 JavaScript 函数功能，以增加代码重用、可读性和健壮性。

然而，在撰写本文时，尚未有一个库确立为事实上的标准。有人可能会认为`underscore.js`是其中一个，但正如你将在下一节中看到的，最好避免使用`underscore.js`。

## Underscore.js

在许多人眼中，Underscore 已成为标准的函数式 JavaScript 库。它成熟、稳定，并由`Jeremy Ashkenas`创建，他是`Backbone.js`和`CoffeeScript`库背后的人物。Underscore 实际上是 Ruby 的`Enumerable`模块的重新实现，这也解释了为什么 CoffeeScript 也受到 Ruby 的影响。

与 jQuery 类似，Underscore 不修改原生 JavaScript 对象，而是使用一个符号来定义自己的对象：下划线字符"`_`"。因此，使用 Underscore 的方式如下：

```js
var x = _.map([1,2,3], Math.sqrt); // Underscore's map function
console.log(x.toString());
```

我们已经看到了 JavaScript 原生的`Array`对象的`map()`方法，它的工作方式如下：

```js
var x = [1,2,3].map(Math.sqrt);
```

不同之处在于，在 Underscore 中，`Array`对象和`callback()`函数都作为参数传递给 Underscore 对象的`map()`方法(`_.map`)，而不是仅将回调传递给数组的原生`map()`方法(`Array.prototype.map`)。

但 Underscore 不仅仅是`map()`和其他内置函数。它充满了非常方便的函数，比如`find()`、`invoke()`、`pluck()`、`sortyBy()`、`groupBy()`等等。

```js
var greetings = [{origin: 'spanish', value: 'hola'}, 
{origin: 'english', value: 'hello'}];
console.log(_.pluck(greetings, 'value')  );
// Grabs an object's property.
// Returns: ['hola', 'hello']
console.log(_.find(greetings, function(s) {return s.origin == 
'spanish';}));
// Looks for the first obj that passes the truth test
// Returns: {origin: 'spanish', value: 'hola'}
greetings = greetings.concat(_.object(['origin','value'],
['french','bonjour']));
console.log(greetings);
// _.object creates an object literal from two merged arrays
// Returns: [{origin: 'spanish', value: 'hola'},
//{origin: 'english', value: 'hello'},
//{origin: 'french', value: 'bonjour'}]
```

它提供了一种将方法链接在一起的方式：

```js
var g = _.chain(greetings)
  .sortBy(function(x) {return x.value.length})
  .pluck('origin')
  .map(function(x){return x.charAt(0).toUpperCase()+x.slice(1)})
  .reduce(function(x, y){return x + ' ' + y}, '')
  .value();
// Applies the functions 
// Returns: 'Spanish English French'
console.log(g);
```

### 注意

`_.chain()`方法返回一个包装对象，其中包含所有 Underscore 函数。然后使用`_.value`方法来提取包装对象的值。包装对象对于将 Underscore 与面向对象编程混合使用非常有用。

尽管它易于使用并被社区所接受，但`underscore.js`库因迫使你编写过于冗长的代码和鼓励错误的模式而受到批评。Underscore 的结构可能不是理想的，甚至不起作用！

直到版本 1.7.0 发布后不久，Brian Lonsdorf 的演讲*嘿，Underscore，你做错了！*在 YouTube 上发布，Underscore 明确阻止我们扩展`map()`、`reduce()`、`filter()`等函数。

```js
_.prototype.map = function(obj, iterate, [context]) {
  if (Array.prototype.map && obj.map === Array.prototype.map) return obj.map(iterate, context);
  // ...
};
```

### 注意

您可以在[www.youtube.com/watch?v=m3svKOdZij](http://www.youtube.com/watch?v=m3svKOdZij)观看 Brian Lonsdorf 的演讲视频。

在范畴论的术语中，映射是一个同态函子接口（在第五章*范畴论*中有更多介绍）。我们应该能够根据需要为`map`定义一个函子。所以 Underscore 并不是非常函数式的。

由于 JavaScript 没有内置的不可变数据，一个函数库应该小心不要让它的辅助函数改变传递给它的对象。这个问题的一个很好的例子如下所示。片段的意图是返回一个新的`selected`列表，并将一个选项设置为默认值。但实际发生的是`selected`列表被就地改变。

```js
function getSelectedOptions(id, value) {
  options = document.querySelectorAll('#' + id + ' option');
  var newOptions = _.map(options, function(opt){
    if (opt.text == value) {
      opt.selected = true;
      opt.text += ' (this is the default)';
    }
    else {
      opt.selected = false;
    }
    return opt;
  });
  return newOptions;
}
var optionsHelp = getSelectedOptions('timezones', 'Chicago');
```

我们必须在`callback()`函数中插入`opt = opt.cloneNode();`这一行，以便复制传递给函数的列表中的每个对象。Underscore 的`map()`函数作弊以提高性能，但这是以牺牲函数式的*风水*为代价。本地的`Array.prototype.map()`函数不需要这样做，因为它会复制，但它也不能用于`nodelist`集合。

Underscore 可能不太适合数学上正确的函数式编程，但它从来没有打算将 JavaScript 扩展或转换为纯函数式语言。它定义自己为*一个提供大量有用的函数式编程辅助函数的 JavaScript 库*。它可能不仅仅是一堆类似函数式的辅助函数，但它也不是一个严肃的函数库。

是否有更好的库？也许是基于数学的库？

## Fantasy Land

有时，事实比小说更离奇。

**Fantasy Land**是一个功能基础库的集合，也是 JavaScript 中如何实现“代数结构”的正式规范。更具体地说，Fantasy Land 指定了常见代数结构或简称代数的互操作性：单子、幺半群、集合、函子、链等等。它们的名字听起来可能很可怕，但它们只是一组值、一组运算符和一些必须遵守的定律。换句话说，它们只是对象。

它是如何工作的。每个代数都是一个单独的 Fantasy Land 规范，并且可能依赖于需要实现的其他代数。

![Fantasy Land](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/fp-js/img/00002.jpeg)

一些代数规范是：

+   集合：

+   实现反射、对称和传递定律

+   定义`equals()`方法

+   半群

+   实现结合定律

+   定义`concat()`方法

+   幺半群

+   实现右恒等和左恒等

+   定义`empty()`方法

+   函子

+   实现恒等和组合定律

+   定义`map()`方法

清单不断延续。

我们不一定需要确切知道每个代数的用途，但这肯定有所帮助，特别是如果你正在编写符合规范的自己的库。这不仅仅是抽象的胡言乱语，它概述了一种实现称为范畴论的高级抽象的方法。范畴论的完整解释可以在第五章*范畴论*中找到。

Fantasy Land 不仅告诉我们如何实现函数式编程，还为 JavaScript 提供了一组函数模块。然而，许多模块是不完整的，文档也相当稀少。但 Fantasy Land 并不是唯一一个实现其开源规范的库。其他库也有，比如：**Bilby.js**。

## Bilby.js

到底什么是 bilby？不，它不是一个可能存在于 Fantasy Land 中的神话生物。它存在于地球上，是一种奇怪/可爱的鼠和兔的混合物。尽管如此，`bibly.js`库符合 Fantasy Land 的规范。

事实上，`bilby.js`是一个严肃的函数库。正如其文档所述，它是*严肃的，意味着它应用范畴论来实现高度抽象的代码。功能性的，意味着它实现了引用透明的程序*。哇，这真的很严肃。文档位于[`bilby.brianmckenna.org/`](http://bilby.brianmckenna.org/)，并且提供了以下内容：

+   用于特定多态性的不可变多方法

+   函数式数据结构

+   用于函数式语法的运算符重载

+   自动化规范测试（**ScalaCheck**，**QuickCheck**）

迄今为止，符合 Fantasy Land 规范的最成熟的库是`Bilby.js`，它是致力于函数式风格的重要资源。

让我们试一个例子：

```js
// environments in bilby are immutable structure for multimethods
var shapes1 = bilby.environment()
  // can define methods
  .method(
    'area', // methods take a name
    function(a){return typeof(a) == 'rect'}, // a predicate
    function(a){return a.x * a.y} // and an implementation
  )
  // and properties, like methods with predicates that always
  // return true
  .property(
     'name',   // takes a name
     'shape'); // and a function
// now we can overload it
var shapes2 = shapes1
  .method(
    'area', function(a){return typeof(a) == 'circle'},
    function(a){return a.r * a.r * Math.PI} );
var shapes3 = shapes2
  .method(
    'area', function(a){return typeof(a) == 'triangle'},
    function(a){return a.height * a.base / 2} );

// and now we can do something like this
var objs = [{type:'circle', r:5}, {type:'rect', x:2, y:3}];
var areas = objs.map(shapes3.area);

// and this
var totalArea = objs.map(shapes3.area).reduce(add);
```

这是范畴论和特定多态性的实践。再次强调，范畴论将在第五章中全面介绍，*范畴论*。

### 注意

范畴论是函数式程序员最近振奋的数学分支，用于最大程度地抽象和提高代码的实用性。*但有一个主要缺点：很难理解并快速上手。*

事实上，Bilby 和 Fantasy Land 确实在 JavaScript 中推动了函数式编程的可能性。尽管看到计算机科学的发展是令人兴奋的，但世界可能还没有准备好接受 Bibly 和 Fantasy Land 所推动的那种硬核函数式风格。

也许这样一个位于函数式 JavaScript 前沿的宏伟库并不适合我们。毕竟，我们的目标是探索与 JavaScript 相辅相成的函数式技术，而不是建立函数式编程教条。让我们把注意力转向另一个新库，`Lazy.js`。

## Lazy.js

Lazy 是一个实用库，更接近于`underscore.js`库，但采用了惰性求值策略。因此，Lazy 通过函数式计算结果的方式实现了不会立即得到解释的系列。它还拥有显著的性能提升。

`Lazy.js`库仍然非常年轻。但它有很大的动力和社区热情支持。

Lazy 中的一切都是我们可以迭代的序列。由于库控制方法应用的顺序，可以实现许多非常酷的事情：异步迭代（并行编程），无限序列，函数式反应式编程等。

以下示例展示了一些内容：

```js
// Get the first eight lines of a song's lyrics
var lyrics = "Lorem ipsum dolor sit amet, consectetur adipiscing eli
// Without Lazy, the entire string is first split into lines
console.log(lyrics.split('\n').slice(0,3)); 

// With Lazy, the text is only split into the first 8 lines
// The lyrics can even be infinitely long!
console.log(Lazy(lyrics).split('\n').take(3));

//First 10 squares that are evenly divisible by 3
var oneTo1000 = Lazy.range(1, 1000).toArray(); 
var sequence = Lazy(oneTo1000)
  .map(function(x) { return x * x; })
  .filter(function(x) { return x % 3 === 0; })
  .take(10)
  .each(function(x) { console.log(x); });

// asynchronous iteration over an infinite sequence
var asyncSequence = Lazy.generate(function(x){return x++})
  .async(100) // 0.100s intervals between elements
  .take(20) // only compute the first 20  
  .each(function(e) { // begin iterating over the sequence
    console.log(new Date().getMilliseconds() + ": " + e);
  });
```

更多示例和用例在第四章中有详细介绍，*在 JavaScript 中实现函数式编程技术*。

但完全归功于`Lazy.js`库这个想法并不完全正确。它的前身之一，`Bacon.js`库，也是以类似的方式工作。

## Bacon.js

`Bacon.js`库的标志如下：

![Bacon.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/fp-js/img/00003.jpeg)

函数式编程库的有胡子的嬉皮士，`Bacon.js`本身是一个*函数式响应式编程*库。函数式响应式编程意味着使用函数式设计模式来表示具有反应性和不断变化的值，比如屏幕上鼠标的位置或公司股票的价格。就像 Lazy 可以通过在需要时不计算值来创建无限序列一样，Bacon 可以避免在最后一刻之前计算不断变化的值。

在 Lazy 中称为序列的东西在 Bacon 中称为 EventStreams 和 Properties，因为它们更适合处理事件（`onmouseover`，`onkeydown`等）和响应属性（滚动位置，鼠标位置，切换等）。

```js
Bacon.fromEventTarget(document.body, "click")
  .onValue(function() { alert("Bacon!") });
```

Bacon 比 Lazy 要老一点，但它的功能集大约是一半大小，社区的热情也差不多。

## 荣誉提及

在这本书的范围内，有太多的库，无法对它们进行公正的评价。让我们再看看 JavaScript 中的一些函数式编程库。

+   `Functional`

+   可能是 JavaScript 中第一个函数式编程库，`Functional`是一个包括全面的高阶函数支持以及`string` lambda 的库。

+   `wu.js`

+   特别受欢迎的`curryable()`函数，`wu.js`库是一个非常好的函数式编程库。它是第一个（我知道的）实现惰性评估的库，为`Bacon.js`，`Lazy.js`和其他库打下了基础

+   是的，它是以臭名昭著的说唱组合*Wu Tang Clan*命名的

+   `sloth.js`

+   与`Lazy.js`库非常相似，但比它小得多

+   `stream.js`

+   `stream.js`库支持无限流，除此之外没有太多功能

+   绝对微小

+   `Lo-Dash.js`

+   顾名思义，`lo-dash.js`库受到了`underscore.js`库的启发

+   高度优化

+   `Sugar`

+   `Sugar`是 JavaScript 中函数式编程技术的支持库，类似于 Underscore，但在实现方式上有一些关键的不同。

+   在 Underscore 中执行`_.pluck(myObjs, 'value')`，在 Sugar 中只需`myObjs.map('value')`。这意味着它修改了原生 JavaScript 对象，因此有一定风险，可能无法与其他执行相同操作的库（如 Prototype）很好地配合。

+   非常好的文档，单元测试，分析器等。

+   `from.js`

+   一个新的函数库和 JavaScript 的**LINQ**（**语言集成查询**）引擎，支持大部分.NET 提供的相同 LINQ 函数

+   100%的惰性评估和支持 lambda 表达式

+   非常年轻，但文档非常好

+   JSLINQ

+   JavaScript 的另一个函数式 LINQ 引擎

+   比`from.js`库更老，更成熟

+   `Boiler.js`

+   另一个实用库，将 JavaScript 的函数方法扩展到更多的原语：字符串，数字，对象，集合和数组

+   **Folktale**

+   像`Bilby.js`库一样，Folktale 是另一个实现 Fantasy Land 规范的新库。和它的前辈一样，Folktale 也是一个用于 JavaScript 中的函数式编程的库集合。它还很年轻，但可能会有一个光明的未来。

+   **jQuery**

+   看到 jQuery 被提到感到惊讶？尽管 jQuery 不是用于执行函数式编程的工具，但它本身也是函数式的。jQuery 可能是最广泛使用的库之一，它的根源是函数式编程。

+   jQuery 对象实际上是一个单子。jQuery 使用单子定律来实现方法链式调用：

```js
$('#mydiv').fadeIn().css('left': 50).alert('hi!');
```

关于这一点的详细解释可以在第七章中找到，*JavaScript 中的函数式和面向对象编程*。

+   它的一些方法是高阶的：

```js
$('li').css('left': function(index){return index*50});
```

+   从 jQuery 1.8 开始，`deferred.then`参数实现了一种称为 Promises 的函数概念。

+   jQuery 是一个抽象层，主要用于 DOM。它不是一个框架或工具包，只是一种利用抽象来增加代码重用和减少丑陋代码的方法。这难道不正是函数式编程的全部意义吗？

# 开发和生产环境

从编程风格的角度来看，应用程序是在哪种环境中开发和部署的并不重要。但对于库来说却很重要。

## 浏览器

大多数 JavaScript 应用程序都设计为在客户端运行，也就是在客户端的浏览器中。基于浏览器的环境非常适合开发，因为浏览器无处不在，你可以在本地机器上直接编写代码，解释器是浏览器的 JavaScript 引擎，所有浏览器都有开发者控制台。Firefox 的 FireBug 提供非常有用的错误消息，并允许设置断点等，但在 Chrome 和 Safari 中运行相同的代码以交叉参考错误输出通常也很有帮助。即使是 Internet Explorer 也包含开发者工具。

浏览器的问题在于它们以不同的方式评估 JavaScript！虽然不常见，但有可能编写的代码在不同的浏览器中返回非常不同的结果。但通常差异在于它们处理文档对象模型的方式，而不是原型和函数的工作方式。显然，`Math.sqrt(4)`方法对所有浏览器和 shell 都返回`2`。但`scrollLeft`方法取决于浏览器的布局策略。

编写特定于浏览器的代码是浪费时间，这也是为什么应该使用库的另一个原因。

## 服务器端 JavaScript

`Node.js`库已成为创建服务器端和基于网络的应用程序的标准平台。函数式编程可以用于服务器端应用程序编程吗？可以！好吧，但是否存在专为这种性能关键环境设计的函数式库？答案也是：是的。

本章中概述的所有函数式库都可以在`Node.js`库中工作，并且许多依赖于`browserify.js`模块来处理浏览器元素。

### 服务器端环境中的函数式用例

在我们这个充满网络系统的新世界中，服务器端应用程序开发人员经常关注并且理所当然地关注并发性。经典的例子是允许多个用户修改同一个文件的应用程序。但如果他们同时尝试修改它，就会陷入一团糟。这是困扰程序员几十年的*状态维护*问题。

假设以下情景：

1.  一天早晨，亚当打开一个报告进行编辑，但在离开吃午饭前没有保存。

1.  比利打开同样的报告，添加了他的笔记，然后保存了。

1.  亚当从午饭回来，添加了他的笔记到报告中，然后保存了，无意中覆盖了比利的笔记。

1.  第二天，比利发现他的笔记不见了。他的老板对他大喊大叫；每个人都生气了，他们联合起来对那个误入歧途的应用程序开发人员进行了不公正的解雇。

很长一段时间，解决这个问题的方法是创建一个关于文件的状态。当有人开始编辑时，切换锁定状态为*on*，这样其他人就无法编辑它，然后在保存后切换为*off*。在我们的情景中，比利在亚当回来吃午饭之前无法完成工作。如果从未保存（比如说，亚当决定在午饭休息时辞职），那么就永远无法编辑它。

这就是函数式编程关于不可变数据和状态（或缺乏状态）的想法真正可以发挥作用的地方。与其让用户直接修改文件，采用函数式方法，他们会修改文件的副本，也就是一个新的版本。如果他们试图保存该版本，而新版本已经存在，那么我们就知道其他人已经修改了旧版本。危机得以避免。

现在之前的情景会是这样展开的：

1.  一天早晨，亚当打开一个报告进行编辑。但他在午餐前没有保存它。

1.  比利打开相同的报告，添加他的笔记，并将其保存为新的修订版本。

1.  亚当从午餐回来添加他的笔记。当他试图保存新的修订版本时，应用程序告诉他现在存在一个更新的修订版本。

1.  亚当打开新的修订版本，添加了他的笔记，并保存了另一个新的修订版本。

1.  通过查看修订历史，老板发现一切都运行顺利。每个人都很高兴，应用程序开发人员得到了晋升和加薪。

这被称为*事件溯源*。没有明确的状态需要维护，只有事件。这个过程更加清洁，有一个可以审查的明确事件历史。

这个想法和许多其他想法是为什么服务器端环境中的功能性编程正在兴起。

## CLI

尽管 Web 和`node.js`库是两个主要的 JavaScript 环境，一些务实和冒险的用户正在寻找方法在命令行中使用 JavaScript。

将 JavaScript 用作命令行界面（CLI）脚本语言可能是应用函数编程的最佳机会之一。想象一下，当搜索本地文件或将整个 bash 脚本重写为功能性 JavaScript 一行时，能够使用惰性评估。

## 与其他 JavaScript 模块一起使用功能库

Web 应用程序由各种组件组成：框架、库、API 等。它们可以作为依赖项、插件或并存对象一起工作。

+   `Backbone.js`

+   一个具有 RESTful JSON 接口的 MVP（模型-视图-提供者）框架

+   需要`underscore.js`库，Backbone 的唯一硬依赖

+   jQuery

+   `Bacon.js`库具有与 jQuery 混合的绑定

+   Underscore 和 jQuery 非常好地互补了彼此

+   原型 JavaScript 框架

+   提供 JavaScript 与 Ruby 的 Enumerable 最接近的集合函数

+   `Sugar.js`

+   修改本地对象及其方法

+   在与其他库混合使用时必须小心，特别是 Prototype

## 编译为 JavaScript 的功能语言

有时，JavaScript 的内部功能上的 C 样式厚重外观足以让你想切换到另一种功能性语言。好吧，你可以！

+   Clojure 和 ClojureScript

+   闭包是现代 Lisp 实现和功能齐全的功能语言

+   ClojureScript 将 Clojure 转译为 JavaScript

+   CoffeeScript

+   CoffeeScript 既是一种功能性语言的名称，也是一种将该语言转译为 JavaScript 的编译器。

+   CoffeeScript 中的表达式与 JavaScript 中的表达式之间存在一对一的映射

还有许多其他选择，包括 Pyjs，Roy，TypeScript，UHC 等。

# 总结

你选择使用哪个库取决于你的需求。需要功能性反应式编程来处理事件和动态值吗？使用`Bacon.js`库。只需要无限流而不需要其他东西吗？使用`stream.js`库。想要用功能性助手补充 jQuery 吗？试试`underscore.js`库。需要一个结构化环境来进行严肃的特定多态性吗？看看`bilby.js`库。需要一个全面的功能性编程工具吗？使用`Lazy.js`库。对这些选项都不满意吗？自己写一个！

任何库的好坏取决于它的使用方式。尽管本章概述的一些库存在一些缺陷，但大多数故障发生在键盘和椅子之间的某个地方。你需要正确使用库来满足你的需求。

如果我们将代码库导入 JavaScript 环境，也许我们也可以导入想法和原则。也许我们可以借鉴*Python 之禅*，由*Tim Peter*：

> *美丽胜于丑陋*
> 
> *显式胜于隐式*
> 
> *简单胜于复杂*
> 
> *复杂胜于复杂*
> 
> *平面胜于嵌套*
> 
> *稀疏胜于密集*
> 
> *可读性很重要。*
> 
> *特殊情况并不特别到足以打破规则。*
> 
> *尽管实用性胜过纯粹。*
> 
> *错误不应该悄悄地通过。*
> 
> *除非明确要求保持沉默。*
> 
> *面对模棱两可，拒绝猜测的诱惑。*
> 
> *应该有一种——最好只有一种——明显的方法来做到这一点。*
> 
> *尽管这种方式一开始可能不明显，除非你是荷兰人。*
> 
> *现在总比永远好。*
> 
> *尽管永远往往比“现在”更好。*
> 
> *如果实现很难解释，那是个坏主意。*
> 
> *如果实现很容易解释，那可能是个好主意。*
> 
> *命名空间是一个非常好的主意——让我们做更多这样的事情！*


# 第四章：在 JavaScript 中实现函数式编程技术

紧紧抓住你的帽子，因为我们现在真的要进入函数式思维模式了。

在本章中，我们将做以下事情：

+   将所有核心概念整合成一个连贯的范式

+   全面致力于函数式风格时，探索函数式编程所提供的美

+   逐步推进函数式模式的逻辑进展

+   同时，我们将构建一个简单的应用程序，做一些非常酷的事情

在上一章中，当处理 JavaScript 的函数式库时，您可能已经注意到了一些概念，但在《第二章》《函数式编程基础》中没有提到。好吧，这是有原因的！组合、柯里化、部分应用等。让我们探讨为什么以及这些库是如何实现这些概念的。

函数式编程可以采用多种风格和模式。本章将涵盖许多不同的函数式编程风格：

+   数据泛型编程

+   大部分是函数式编程

+   函数响应式编程等

然而，本章将尽可能不偏向任何一种函数式编程风格。不过度倚重某种函数式编程风格，总体目标是展示有比通常被接受的正确和唯一的编码方式更好的方式。一旦你摆脱了对编写代码的先入为主的观念，你就可以随心所欲。当你只是出于喜欢而写代码，而不担心符合传统的做事方式时，那么可能性就是无限的。

# 部分函数应用和柯里化

许多语言支持可选参数，但 JavaScript 不支持。JavaScript 使用一种完全不同的模式，允许将任意数量的参数传递给函数。这为一些非常有趣和不寻常的设计模式留下了空间。函数可以部分或全部应用。

JavaScript 中的部分应用是将值绑定到一个或多个函数参数的过程，返回另一个接受剩余未绑定参数的函数。类似地，柯里化是将具有多个参数的函数转换为接受所需参数的另一个函数的过程。

现在两者之间的区别可能不太明显，但最终会显而易见。

## 函数操作

实际上，在我们进一步解释如何实现部分应用和柯里化之前，我们需要进行复习。如果我们要揭开 JavaScript 厚重的类 C 语法的外表，暴露它的函数式本质，那么我们需要了解 JavaScript 中原始值、函数和原型是如何工作的；如果我们只是想设置一些 cookie 或验证一些表单字段，我们就不需要考虑这些。

### 应用、调用和 this 关键字

在纯函数式语言中，函数不是被调用，而是被应用。JavaScript 也是如此，甚至提供了手动调用和应用函数的工具。而这一切都与 `this` 关键字有关，当然，它是函数的成员所属的对象。

`call()` 函数允许您将 `this` 关键字定义为第一个参数。它的工作方式如下：

```js
console.log(['Hello', 'world'].join(' ')) // normal way
console.log(Array.prototype.join.call(['Hello', 'world'], ' ')); // using call
```

`call()` 函数可以用来调用匿名函数，例如：

```js
console.log((function(){console.log(this.length)}).call([1,2,3]));
```

`apply()` 函数与 `call()` 函数非常相似，但更有用：

```js
console.log(Math.max(1,2,3)); // returns 3
console.log(Math.max([1,2,3])); // won't work for arrays though
console.log(Math.max.apply(null, [1,2,3])); // but this will work
```

根本区别在于，`call()` 函数接受参数列表，而 `apply()` 函数接受参数数组。

`call()`和`apply()`函数允许您编写一次函数，然后在其他对象中继承它，而无需重新编写函数。它们本身也是`Function`参数的成员。

### 注意

这是额外材料，但当您在自身上使用`call()`函数时，一些非常酷的事情可能会发生：

```js
// these two lines are equivalent
func.call(thisValue);
Function.prototype.call.call(func, thisValue);
```

### 绑定参数

`bind()`函数允许您将一个方法应用于一个对象，并将`this`关键字分配给另一个对象。在内部，它与`call()`函数相同，但它链接到方法并返回一个新的绑定函数。

它在回调函数中特别有用，如下面的代码片段所示：

```js
function Drum(){
  this.noise = 'boom';
  this.duration = 1000;
  this.goBoom = function(){console.log(this.noise)};
}
var drum = new Drum();
setInterval(drum.goBoom.bind(drum), drum.duration);
```

这解决了面向对象框架中的许多问题，比如 Dojo，特别是在使用定义自己的处理程序函数的类时维护状态的问题。但我们也可以将`bind()`函数用于函数式编程。

### 提示

`bind()`函数实际上可以自行进行部分应用，尽管方式非常有限。

### 函数工厂

还记得我们在第二章中关于闭包的部分吗，*函数式编程基础*？闭包是使得可能创建一种称为函数工厂的有用的 JavaScript 编程模式的构造。它们允许我们*手动绑定*参数到函数。

首先，我们需要一个将参数绑定到另一个函数的函数：

```js
function bindFirstArg(func, a) {
  return function(b) {
    return func(a, b);
  };
}
```

然后我们可以使用这个函数创建更通用的函数：

```js
var powersOfTwo = bindFirstArg(Math.pow, 2);
console.log(powersOfTwo(3)); // 8
console.log(powersOfTwo(5)); // 32
```

它也可以用于另一个参数：

```js
function bindSecondArg(func, b) {
  return function(a) {
    return func(a, b);
  };
}
var squareOf = bindSecondArg(Math.pow, 2);
var cubeOf = bindSecondArg(Math.pow, 3);
console.log(squareOf(3)); // 9
console.log(squareOf(4)); // 16
console.log(cubeOf(3));   // 27
console.log(cubeOf(4));   // 64
```

在函数式编程中，创建通用函数的能力非常重要。但是有一个聪明的技巧可以使这个过程更加通用化。`bindFirstArg()`函数本身接受两个参数，第一个是函数。如果我们将`bindFirstArg`函数作为函数传递给它自己，我们就可以创建*可绑定*函数。以下示例最能描述这一点：

```js
var makePowersOf = bindFirstArg(bindFirstArg, Math.pow);
var powersOfThree = makePowersOf(3);
console.log(powersOfThree(2)); // 9
console.log(powersOfThree(3)); // 27
```

这就是为什么它们被称为函数工厂。

## 部分应用

请注意，我们的函数工厂示例中的`bindFirstArg()`和`bindSecondArg()`函数只适用于具有确切两个参数的函数。我们可以编写新的函数，使其适用于不同数量的参数，但这将偏离我们的通用化模型。

我们需要的是部分应用。

### 注意

部分应用是将值绑定到一个或多个函数参数的过程，返回一个接受剩余未绑定参数的部分应用函数。

与`bind()`函数和`Function`对象的其他内置方法不同，我们必须为部分应用和柯里化创建自己的函数。有两种不同的方法可以做到这一点。

+   作为一个独立的函数，也就是，`var partial = function(func){...`

+   作为*polyfill*，也就是，`Function.prototype.partial = function(){...`

Polyfills 用于用新函数增加原型，并且允许我们将新函数作为我们想要部分应用的函数的方法来调用。就像这样：`myfunction.partial(arg1, arg2, …);`

### 从左侧进行部分应用

这就是 JavaScript 的`apply()`和`call()`实用程序对我们有用的地方。让我们看一下 Function 对象的可能的 polyfill：

```js
Function.prototype.partialApply = function(){
  var func = this; 
  args = Array.prototype.slice.call(arguments);
  return function(){
    return func.apply(this, args.concat(
      Array.prototype.slice.call(arguments)
    ));
  };
};
```

正如您所看到的，它通过切割`arguments`特殊变量来工作。

### 注意

每个函数都有一个特殊的本地变量称为`arguments`，它是传递给它的参数的类似数组的对象。它在技术上不是一个数组。因此它没有任何数组方法，比如`slice`和`forEach`。这就是为什么我们需要使用 Array 的`slice.call`方法来切割参数。

现在让我们看看当我们在一个例子中使用它时会发生什么。这一次，让我们远离数学，转而做一些更有用的事情。我们将创建一个小应用程序，将数字转换为十六进制值。

```js
function nums2hex() {
  function componentToHex(component) {
    var hex = component.toString(16);
    // make sure the return value is 2 digits, i.e. 0c or 12
    if (hex.length == 1) {
      return "0" + hex;
    }
    else {
      return hex;
    }
  }
  return Array.prototype.map.call(arguments, componentToHex).join('');
}

// the function works on any number of inputs
console.log(nums2hex()); // ''
console.log(nums2hex(100,200)); // '64c8'
console.log(nums2hex(100, 200, 255, 0, 123)); // '64c8ff007b'

// but we can use the partial function to partially apply
// arguments, such as the OUI of a mac address
var myOUI = 123;
var getMacAddress = nums2hex.partialApply(myOUI);
console.log(getMacAddress()); // '7b'
console.log(getMacAddress(100, 200, 2, 123, 66, 0, 1)); // '7b64c8027b420001'

// or we can convert rgb values of red only to hexadecimal
var shadesOfRed = nums2hex.partialApply(255);
console.log(shadesOfRed(123, 0));   // 'ff7b00'
console.log(shadesOfRed(100, 200)); // 'ff64c8'
```

这个例子表明我们可以部分应用参数到一个通用函数，并得到一个新的函数作为返回。*这个第一个例子是从左到右*，这意味着我们只能部分应用第一个、最左边的参数。

### 从右侧进行部分应用

为了从右侧应用参数，我们可以定义另一个 polyfill。

```js
Function.prototype.partialApplyRight = function(){
  var func = this; 
  args = Array.prototype.slice.call(arguments);
  return function(){
    return func.apply(
      this,
      [].slice.call(arguments, 0)
      .concat(args));
  };
};

var shadesOfBlue = nums2hex.partialApplyRight(255);
console.log(shadesOfBlue(123, 0));   // '7b00ff'
console.log(shadesOfBlue(100, 200)); // '64c8ff'

var someShadesOfGreen = nums2hex.partialApplyRight(255, 0);
console.log(shadesOfGreen(123));   // '7bff00'
console.log(shadesOfGreen(100));   // '64ff00'
```

部分应用使我们能够从一个非常通用的函数中提取更具体的函数。但这种方法最大的缺陷是参数传递的方式，即数量和顺序可能是模糊的。模糊从来不是编程中的好事。有更好的方法来做到这一点：柯里化。

## 柯里化

柯里化是将具有多个参数的函数转换为具有一个参数的函数的过程，该函数返回另一个根据需要接受更多参数的函数。形式上，具有 N 个参数的函数可以转换为 N 个函数的*链*，每个函数只有一个参数。

一个常见的问题是：部分应用和柯里化之间有什么区别？虽然部分应用立即返回一个值，而柯里化只返回另一个接受下一个参数的柯里化函数，但根本区别在于柯里化允许更好地控制参数如何传递给函数。我们将看到这是真的，但首先我们需要创建执行柯里化的函数。

这是我们为 Function 原型添加柯里化的 polyfill：

```js
Function.prototype.curry = function (numArgs) {
  var func = this;
  numArgs = numArgs || func.length;

  // recursively acquire the arguments
  function subCurry(prev) {
    return function (arg) {
      var args = prev.concat(arg);
      if (args.length < numArgs) {
        // recursive case: we still need more args
        return subCurry(args);
      }
      else {
        // base case: apply the function
        return func.apply(this, args);
      }
    };
  }
  return subCurry([]);
};
```

`numArgs`参数让我们可以选择指定柯里化函数需要的参数数量，如果没有明确定义的话。

让我们看看如何在我们的十六进制应用程序中使用它。我们将编写一个将 RGB 值转换为适用于 HTML 的十六进制字符串的函数：

```js
function rgb2hex(r, g, b) {
  // nums2hex is previously defined in this chapter
  return '#' + nums2hex(r) + nums2hex(g) + nums2hex(b);
}
var hexColors = rgb2hex.curry();
console.log(hexColors(11)) // returns a curried function
console.log(hexColors(11,12,123)) // returns a curried function
console.log(hexColors(11)(12)(123)) // returns #0b0c7b
console.log(hexColors(210)(12)(0))  // returns #d20c00
```

它将返回柯里化函数，直到传入所有需要的参数。它们按照被柯里化函数定义的左到右的顺序传入。

但是我们可以再进一步，定义我们需要的更具体的函数如下：

```js
var reds = function(g,b){return hexColors(255)(g)(b)};
var greens = function(r,b){return hexColors(r)(255)(b)};
var blues  = function(r,g){return hexColors(r)(g)(255)};
console.log(reds(11, 12))   // returns #ff0b0c
console.log(greens(11, 12)) // returns #0bff0c
console.log(blues(11, 12))  // returns #0b0cff
```

这是使用柯里化的一个好方法。但是，如果我们只想直接对`nums2hex()`进行柯里化，我们会遇到一些麻烦。那是因为该函数没有定义任何参数，它只允许您传入任意数量的参数。因此，我们必须定义参数的数量。我们可以使用 curry 函数的可选参数来设置被柯里化函数的参数数量。

```js
var hexs = nums2hex.curry(2);
console.log(hexs(11)(12));     // returns 0b0c
console.log(hexs(11));         // returns function
console.log(hexs(110)(12)(0)); // incorrect
```

因此，柯里化不适用于接受可变数量参数的函数。对于这样的情况，部分应用更可取。

所有这些不仅仅是为了函数工厂和代码重用的好处。柯里化和部分应用都融入了一个更大的模式，称为组合。

# 函数组合

最后，我们已经到达了函数组合。

在函数式编程中，我们希望一切都是函数。如果可能的话，我们尤其希望是一元函数。如果我们可以将所有函数转换为一元函数，那么就会发生神奇的事情。

### 注意

**一元**函数是只接受一个输入的函数。具有多个输入的函数是**多元**的，但对于接受两个输入的函数，我们通常说是*二元*，对于三个输入的函数，我们说是**三元**。有些函数不接受特定数量的输入；我们称这些为**可变元**。

操纵函数及其可接受的输入数量可以非常具有表现力。在本节中，我们将探讨如何从较小的函数组合新函数：将逻辑的小单元组合成整个程序，这些程序比单独的函数的总和更大。

## 组合

组合函数允许我们从许多简单的通用函数构建复杂的函数。通过将函数视为其他函数的构建块，我们可以构建具有出色可读性和可维护性的模块化应用程序。

在我们定义 `compose()` 的 polyfill 之前，您可以通过以下示例看到它是如何工作的：

```js
var roundedSqrt = Math.round.compose(Math.sqrt)
console.log( roundedSqrt(5) ); // Returns: 2

var squaredDate =  roundedSqrt.compose(Date.parse)
console.log( squaredDate("January 1, 2014") ); // Returns: 1178370 
```

在数学中，`f` 和 `g` 变量的组合被定义为 `f(g(x))`。在 JavaScript 中，这可以写成：

```js
var compose = function(f, g) {
  return function(x) {
    return f(g(x));
  };
};
```

但如果我们就此结束，我们将失去 `this` 关键字的跟踪，还有其他问题。解决方案是使用 `apply()` 和 `call()` 工具。与柯里化相比，`compose()` 的 polyfill 相当简单。

```js
Function.prototype.compose = function(prevFunc) {
  var nextFunc = this;
  return function() {
    return nextFunc.call(this,prevFunc.apply(this,arguments));
  }
}
```

为了展示它的使用，让我们构建一个完全牵强的例子，如下所示：

```js
function function1(a){return a + ' 1';}
function function2(b){return b + ' 2';}
function function3(c){return c + ' 3';}
var composition = function3.compose(function2).compose(function1);
console.log( composition('count') ); // returns 'count 1 2 3'
```

您是否注意到 `function3` 参数被首先应用了？这非常重要。函数是从右到左应用的。

### 序列 - 反向组合

因为许多人喜欢从左到右阅读，所以按照这个顺序应用函数可能是有意义的。我们将这称为序列而不是组合。

要颠倒顺序，我们只需要交换 `nextFunc` 和 `prevFunc` 参数。

```js
Function.prototype.sequence  = function(prevFunc) {
  var nextFunc = this;
  return function() {
    return prevFunc.call(this,nextFunc.apply(this,arguments));
  }
}
```

这使我们现在可以以更自然的顺序调用函数。

```js
var sequences = function1.sequence(function2).sequence(function3);
console.log( sequences('count') ); // returns 'count 1 2 3'
```

## 组合与链

这里有五种不同的 `floorSqrt()` 函数组合实现。它们看起来是相同的，但值得仔细检查。

```js
function floorSqrt1(num) {
  var sqrtNum = Math.sqrt(num);
  var floorSqrt = Math.floor(sqrtNum);
  var stringNum = String(floorSqrt);
  return stringNum;
}

function floorSqrt2(num) {
  return String(Math.floor(Math.sqrt(num)));
}

function floorSqrt3(num) {
  return [num].map(Math.sqrt).map(Math.floor).toString();
}
var floorSqrt4 = String.compose(Math.floor).compose(Math.sqrt);
var floorSqrt5 = Math.sqrt.sequence(Math.floor).sequence(String);

// all functions can be called like this:
floorSqrt<N>(17); // Returns: 4
```

但是有一些关键的区别我们应该了解：

+   显然，第一种方法冗长且低效。

+   第二种方法是一个很好的一行代码，但在应用了几个函数之后，这种方法变得非常难以阅读。

### 注意

说少量代码更好是错的。当有效指令更简洁时，代码更易维护。如果您减少屏幕上的字符数而不改变执行的有效指令，这将产生完全相反的效果——代码变得更难理解，维护性明显降低；例如，当我们使用嵌套的三元运算符，或者在一行上链接多个命令。这些方法减少了屏幕上的 '代码量'，但并没有减少代码实际指定的步骤数。因此，这种简洁性使得代码更易维护的方式是有效地减少指定的指令（例如，通过使用更简单的算法来实现相同结果，或者仅仅用消息替换代码，例如，使用具有良好文档化 API 的第三方库）。

+   第三种方法是一系列数组函数的链，特别是 `map` 函数。这很有效，但在数学上不正确。

+   这是我们的 `compose()` 函数的实际应用。所有方法都被强制成一元的、纯函数，鼓励使用更好、更简单、更小的函数，只做一件事并且做得很好。

+   最后一种方法使用了 `compose()` 函数的反向顺序，这同样有效。

## 使用 compose 进行编程

组合最重要的方面是，除了应用的第一个函数之外，它最适合使用纯 *一元* 函数：只接受一个参数的函数。

应用的第一个函数的输出被发送到下一个函数。这意味着函数必须接受前一个函数传递给它的内容。这是 *类型签名* 的主要影响。

### 注意

类型签名用于明确声明函数接受的输入类型和输出类型。它们最初由 Haskell 使用，在函数定义中由编译器使用。但在 JavaScript 中，我们只是将它们放在代码注释中。它们看起来像这样：`foo :: arg1 -> argN -> output`

示例：

```js
// getStringLength :: String -> Intfunction getStringLength(s){return s.length};
// concatDates :: Date -> Date -> [Date]function concatDates(d1,d2){return [d1, d2]};
// pureFunc :: (int -> Bool) -> [int] -> [int]pureFunc(func, arr){return arr.filter(func)} 
```

为了真正享受组合的好处，任何应用都需要大量的一元、纯函数。这些是组合成更大函数的构建块，反过来又用于制作非常模块化、可靠和易维护的应用程序。

让我们通过一个例子来了解。首先我们需要许多构建块函数。其中一些函数是基于其他函数构建的，如下所示：

```js
// stringToArray :: String -> [Char]
function stringToArray(s) { return s.split(''); }

// arrayToString :: [Char] -> String
function arrayToString(a) { return a.join(''); }

// nextChar :: Char -> Char
function nextChar(c) { 
  return String.fromCharCode(c.charCodeAt(0) + 1); }

// previousChar :: Char -> Char
function previousChar(c) {
  return String.fromCharCode(c.charCodeAt(0)-1); }

// higherColorHex :: Char -> Char
function higherColorHex(c) {return c >= 'f' ? 'f' :
                                   c == '9' ? 'a' :
                                   nextChar(c)}

// lowerColorHex :: Char -> Char
function lowerColorHex(c) { return c <= '0' ? '0' : 
                                   c == 'a' ? '9' : 
                                   previousChar(c); }

// raiseColorHexes :: String -> String
function raiseColorHexes(arr) { return arr.map(higherColorHex); }

// lowerColorHexes :: String -> String
function lowerColorHexes(arr) { return arr.map(lowerColorHex); }
```

现在让我们将其中一些组合在一起。

```js
var lighterColor = arrayToString
  .compose(raiseColorHexes)
  .compose(stringToArray)
  var darkerColor = arrayToString
  .compose(lowerColorHexes)
  .compose(stringToArray)

console.log( lighterColor('af0189') ); // Returns: 'bf129a'
console.log( darkerColor('af0189')  );  // Returns: '9e0078'
```

我们甚至可以将`compose()`和`curry()`函数一起使用。事实上，它们在一起工作得非常好。让我们将柯里化示例与我们的组合示例结合起来。首先我们需要之前的辅助函数。

```js
// component2hex :: Ints -> Int
function componentToHex(c) {
  var hex = c.toString(16);
  return hex.length == 1 ? "0" + hex : hex;
}

// nums2hex :: Ints* -> Int
function nums2hex() {
  return Array.prototype.map.call(arguments, componentToHex).join('');
}
```

首先我们需要制作柯里化和部分应用的函数，然后我们可以将它们组合到我们的其他组合函数中。

```js
var lighterColors = lighterColor
  .compose(nums2hex.curry());
var darkerRed = darkerColor
  .compose(nums2hex.partialApply(255));
Var lighterRgb2hex = lighterColor
  .compose(nums2hex.partialApply());

console.log( lighterColors(123, 0, 22) ); // Returns: 8cff11 
console.log( darkerRed(123, 0) ); // Returns: ee6a00 
console.log( lighterRgb2hex(123,200,100) ); // Returns: 8cd975
```

这就是我们的内容！这些函数读起来非常流畅，而且意义深远。我们被迫从只做一件事的小函数开始。然后我们能够组合具有更多实用性的函数。

让我们来看最后一个例子。这是一个通过可变量来减轻 RBG 值的函数。然后我们可以使用组合来从中创建新的函数。

```js
// lighterColorNumSteps :: string -> num -> string
function lighterColorNumSteps(color, n) {
  for (var i = 0; i < n; i++) {
    color = lighterColor(color);
  }
  return color;
}

// now we can create functions like this:
var lighterRedNumSteps = lighterColorNumSteps.curry().compose(reds)(0,0);

// and use them like this:
console.log( lighterRedNumSteps(5) ); // Return: 'ff5555'
console.log( lighterRedNumSteps(2) ); // Return: 'ff2222'
```

同样，我们可以轻松地创建更多用于创建更浅或更深的蓝色、绿色、灰色、紫色等的函数。*这是构建 API 的一个非常好的方法*。

我们只是刚刚触及了函数组合的表面。组合的作用是夺走 JavaScript 的控制权。通常 JavaScript 会从左到右进行评估，但现在解释器在说“好的，其他东西会处理这个，我只会继续下一个。”现在`compose()`函数控制着评估顺序！

这就是`Lazy.js`、`Bacon.js`等库能够实现诸如惰性评估和无限序列等功能的方式。接下来，我们将看看这些库是如何使用的。

# 大部分是函数式编程

没有副作用的程序算不上是程序。

用不可避免产生副作用的函数式代码来补充我们的代码可以称为“大部分是函数式编程”。在同一个代码库中使用多种范式，并在最优的地方应用它们，是最佳的方法。大部分是函数式编程是即使是纯粹的、传统的函数式程序也是如何建模的：将大部分逻辑放在纯函数中，并与命令式代码进行接口。

这就是我们将要编写自己的一个小应用程序的方式。

在这个例子中，我们有一个老板告诉我们，我们的公司需要一个网页应用来跟踪员工的可用性状态。这家虚构公司的所有员工只有一个工作：使用我们的网站。员工到达工作地点时会签到，离开时会签退。但这还不够，它还需要在内容发生变化时自动更新，这样我们的老板就不必一直刷新页面了。

*我们将使用* `Lazy.js` *作为我们的函数库*。而且我们也会变得懒惰：不用担心处理所有用户的登录和退出、WebSockets、数据库等等，我们只需假装有一个通用的应用对象来为我们做这些，并且恰好具有完美的 API。

所以现在，让我们先把丑陋的部分搞定，也就是那些接口和产生副作用的部分。

```js
function Receptor(name, available){
  this.name = name;
  this.available = available; // mutable state
  this.render = function(){
    output = '<li>';
    output += this.available ? 
      this.name + ' is available' : 
      this.name + ' is not available';
    output += '</li>';
    return output;
  }
}
var me = new Receptor;
var receptors = app.getReceptors().push(me);
app.container.innerHTML = receptors.map(function(r){
  return r.render();
}).join('');
```

这对于只显示可用性列表来说已经足够了，但我们希望它是响应式的，这就带来了我们的第一个障碍。

通过使用`Lazy.js`库将对象存储在一个序列中，直到调用`toArray()`方法才会实际计算任何内容，我们可以利用其惰性来提供一种函数式响应式编程。

```js
var lazyReceptors = Lazy(receptors).map(function(r){
  return r.render();
});
app.container.innerHTML = lazyReceptors.toArray().join('');
```

因为`Receptor.render()`方法返回新的 HTML 而不是修改当前的 HTML，我们只需要将`innerHTML`参数设置为它的输出。

我们还需要相信，我们用于用户管理的通用应用程序将为我们提供回调方法供我们使用。

```js
app.onUserLogin = function(){
  this.available = true;
  app.container.innerHTML = lazyReceptors.toArray().join('');
};
app.onUserLogout = function(){
  this.available = false;
  app.container.innerHTML = lazyReceptors.toArray().join('');
};
```

这样，每当用户登录或退出时，`lazyReceptors`参数将被重新计算，并且可用性列表将以最新的值打印出来。

## 处理事件

但是，如果应用程序没有提供用户登录和注销时的回调怎么办？回调很混乱，很快就会使程序变得混乱。相反，我们可以通过直接观察用户来确定。如果用户关注网页，那么他/她必须是活跃和可用的。我们可以使用 JavaScript 的`focus`和`blur`事件来实现这一点。

```js
window.addEventListener('focus', function(event) {
  me.available = true;
  app.setReceptor(me.name, me.available); // just go with it
  container.innerHTML = lazyReceptors.toArray().join('');
});
window.addEventListener('blur', function(event) {
  me.available = false;
  app.setReceptor(me.name, me.available);
  container.innerHTML = lazyReceptors.toArray().join('');
});
```

等一下，事件也是响应式的吗？它们也可以懒计算吗？在`Lazy.js`库中可以，甚至还有一个方便的方法。

```js
var focusedReceptors = Lazy.events(window, "focus").each(function(e){
  me.available = true;
  app.setReceptor(me.name, me.available);
  container.innerHTML = lazyReceptors.toArray().join('');
});
var blurredReceptors = Lazy.events(window, "blur").each(function(e){
  me.available = false;
  app.setReceptor(me.name, me.available);
  container.innerHTML = lazyReceptors.toArray().join('');
});
```

简单得很。

### 注意

通过使用`Lazy.js`库来处理事件，我们可以创建一个无限序列的事件。每次事件触发时，`Lazy.each()`函数都能再次迭代。

我们的老板到目前为止很喜欢这个应用，但她指出，如果员工在离开前从未注销并关闭页面，那么应用会显示员工仍然可用。

要确定员工在网站上是否活跃，我们可以监视键盘和鼠标事件。假设在 30 分钟没有活动后，他们被视为不可用。

```js
var timeout = null;
var inputs = Lazy.events(window, "mousemove").each(function(e){
  me.available = true;
  container.innerHTML = lazyReceptors.toArray().join('');
  clearTimeout(timeout);
  timeout = setTimeout(function(){
    me.available = false;
    container.innerHTML = lazyReceptors.toArray().join('');
  }, 1800000); // 30 minutes
});
```

`Lazy.js`库让我们很容易地处理事件，将其作为一个可以映射的无限流。这是可能的，因为它使用函数组合来控制执行顺序。

但这里有一个小问题。如果没有用户输入事件可以依附呢？相反，如果有一个属性值一直在变化呢？在下一节中，我们将详细调查这个问题。

# 函数式响应式编程

让我们构建另一种工作方式基本相同的应用程序；一个使用函数式编程来对状态变化做出反应的应用程序。但是，这次应用程序不能依赖事件监听器。

想象一下，你在一家新闻媒体公司工作，你的老板告诉你要创建一个网络应用，用于跟踪选举日政府选举结果。数据不断地流入，因为当地选区提交他们的结果时，页面上要显示的结果是非常反应灵敏的。但我们还需要按地区跟踪结果，因此会有多个对象要跟踪。

与其创建一个大的面向对象的层次结构来建模界面，我们可以将其声明性地描述为不可变数据。我们可以使用纯函数和半纯函数的链式转换，其最终副作用仅是更新绝对必须保留的状态位（理想情况下，不多）。

我们将使用`Bacon.js`库，它将允许我们快速开发**函数式响应式编程**（**FRP**）应用程序。该应用程序一年只会在一天（选举日）使用一次，我们的老板认为它应该花费相应的时间。通过函数式编程和`Bacon.js`这样的库，我们将在一半的时间内完成。

但首先，我们需要一些对象来表示投票区域，比如州、省、地区等。

```js
function Region(name, percent, parties){
  // mutable properties:
  this.name = name;
  this.percent = percent; // % of precincts reported
  this.parties = parties; // political parties

  // return an HTML representation
  this.render = function(){
    var lis = this.parties.map(function(p){
      return '<li>' + p.name + ': ' + p.votes + '</li>';
    });
    var output = '<h2>' + this.name + '</h2>';
    output += '<ul>' + lis.join('') + '</ul>'; 
    output += 'Percent reported: ' + this.percent; 
    return output;
  }
}
function getRegions(data) {
  return JSON.parse(data).map(function(obj){
    return new Region(obj.name, obj.percent, obj.parties);
  });
}
var url = 'http://api.server.com/election-data?format=json';
var data = jQuery.ajax(url);
var regions = getRegions(data);
app.container.innerHTML = regions.map(function(r){
  return r.render();
}).join('');
```

虽然以上内容对于仅显示静态选举结果列表已经足够了，但我们需要一种动态更新区域的方法。是时候煮一些 Bacon 和 FRP 了。

## 响应性

Bacon 有一个函数`Bacon.fromPoll()`，它让我们创建一个事件流，其中事件只是在给定间隔上调用的函数。而`stream.subscribe()`函数让我们*订阅*一个处理函数到流中。因为它是懒惰的，流没有订阅者时实际上不会执行任何操作。

```js
var eventStream = Bacon.fromPoll(10000, function(){
  return Bacon.Next;
});
var subscriber = eventStream.subscribe(function(){
  var url = 'http://api.server.com/election-data?format=json';
  var data = jQuery.ajax(url);
  var newRegions = getRegions(data);	
  container.innerHTML = newRegions.map(function(r){
    return r.render();
  }).join('');
});
```

通过将其放入每 10 秒运行一次的循环中，我们可以完成任务。但这种方法会频繁地 ping 网络，效率非常低下。这并不是很实用。相反，让我们深入了解一下`Bacon.js`库。

在 Bacon 中，有 EventStreams 和 Properties 参数。属性可以被认为是随时间变化的“魔术”变量，以响应事件。它们并不真的是魔术，因为它们仍然依赖于事件流。属性随时间变化，与其 EventStream 相关。

`Bacon.js`库还有另一个技巧。`Bacon.fromPromise()`函数是一种通过*promises*向流发出事件的方法。而且自 jQuery 版本 1.5.0 起，jQuery AJAX 实现了 promises 接口。所以我们只需要编写一个在异步调用完成时发出事件的 AJAX 搜索函数。每当承诺被解决时，它都会调用 EventStream 的订阅者。

```js
var url = 'http://api.server.com/election-data?format=json';
var eventStream = Bacon.fromPromise(jQuery.ajax(url));
var subscriber = eventStream.onValue(function(data){
  newRegions = getRegions(data);
  container.innerHTML = newRegions.map(function(r){
    return r.render();
  }).join('');
}
```

承诺可以被认为是*最终值*；使用`Bacon.js`库，我们可以懒惰地等待最终值。

## 将所有内容整合在一起

现在我们已经涵盖了响应性，我们终于可以玩一些代码了。

我们可以使用纯函数的链式修改订阅者，做一些诸如累加总和和过滤不需要的结果的操作，而且我们都是在我们创建的按钮的`onclick()`处理函数中完成的。

```js
// create the eventStream out side of the functions
var eventStream = Bacon.onPromise(jQuery.ajax(url));
var subscribe = null;
var url = 'http://api.server.com/election-data?format=json';

// our un-modified subscriber
$('button#showAll').click(function() {
  var subscriber = eventStream.onValue(function(data) {
    var newRegions = getRegions(data).map(function(r) {
      return new Region(r.name, r.percent, r.parties);
    });
    container.innerHTML = newRegions.map(function(r) {
      return r.render();
    }).join('');
  });
});

// a button for showing the total votes
$('button#showTotal').click(function() {
  var subscriber = eventStream.onValue(function(data) {
    var emptyRegion = new Region('empty', 0, [{
      name: 'Republican', votes: 0
    }, {
      name: 'Democrat', votes: 0
    }]);
    var totalRegions = getRegions(data).reduce(function(r1, r2) {
      newParties = r1.parties.map(function(x, i) {
      return {
        name: r1.parties[i].name,
        votes: r1.parties[i].votes + r2.parties[i].votes
      };
    });
    newRegion = new Region('Total', (r1.percent + r2.percent) / 2, newParties);
    return newRegion;
    }, emptyRegion);
    container.innerHTML = totalRegions.render();
  });
});

// a button for only displaying regions that are reporting > 50%
$('button#showMostlyReported').click(function() {
  var subscriber = eventStream.onValue(function(data) {
    var newRegions = getRegions(data).map(function(r) {
      if (r.percent > 50) return r;
      else return null;
    }).filter(function(r) {return r != null;});
    container.innerHTML = newRegions.map(function(r) {
      return r.render();
    }).join('');
  });
});
```

美妙之处在于，当用户在按钮之间点击时，事件流不会改变，但订阅者会改变，这使得一切都能顺利运行。

# 总结

JavaScript 是一种美丽的语言。

它的内在美真正闪耀在函数式编程中。这正是赋予它出色可扩展性的力量。它允许可以做很多事情的头等函数，这正是打开函数式大门的原因。概念在彼此之上构建，不断堆叠。

在本章中，我们首先深入了解了 JavaScript 中的函数式范式。我们涵盖了函数工厂、柯里化、函数组合以及使其工作所需的一切。我们构建了一个极其模块化的应用程序，使用了这些概念。然后我们展示了如何使用一些使用这些概念的函数式库，即函数组合，来操纵执行顺序。

在本章中，我们涵盖了几种函数式编程风格：数据通用编程、大部分函数式编程和函数式响应式编程。它们彼此并没有太大的不同，它们只是在不同情况下应用函数式编程的不同模式。

在上一章中，简要提到了范畴论。在下一章中，我们将学习更多关于它是什么以及如何使用它。
