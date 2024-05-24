# 写给 Python 开发者的 JavaScript 实用指南（二）

> 原文：[`zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446`](https://zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分 - 在前端使用 JavaScript

是时候编写代码了！让我们把我们对 JavaScript 的理论知识付诸实践，学习如何在页面上实际使用它。

在本节中，我们将涵盖以下章节：

+   第五章，《你好，世界！以及更多：你的第一个应用程序》

+   第六章，《文档对象模型（DOM）》

+   第七章，《事件，事件驱动设计和 API》

+   第八章，《使用框架和库》

+   第九章，《解读错误消息和性能泄漏》

+   第十章，《JavaScript，前端的统治者》


# 第五章：Hello World 以及更多：你的第一个应用

啊，那个古老的“Hello World!”脚本。虽然非常简单，但它是对任何语言的一个很好的第一次测试。不过，让我们做得更多一点，不仅仅是说 hello；让我们用几个小应用程序来动手。毕竟，编程不仅仅是理论。我们将看一下编码挑战中提出的一个常见问题，以及*我们的程序是如何工作的。

本章将涵盖以下主题：

+   控制台和警报消息的 I/O

+   在函数中处理输入

+   使用对象作为数据存储

+   理解作用域

# 技术要求

从[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers)克隆或下载本书的存储库，并准备查看`Chapter-5`的材料。

# 控制台和警报消息的 I/O

到目前为止，我们已经看到了 JavaScript 如何向用户输出信息。考虑以下代码：

```js
const Officer = function(name, rank, posting) {
  this.name = name
  this.rank = rank
  this.posting = posting
  this.sayHello = () => {
    console.log(this.name)
  }
}

const Riker = new Officer("Will Riker", "Commander", "U.S.S. Enterprise")
```

现在，如果我们执行`Riker.sayHello()`，我们将在控制台中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/31e31351-b7e6-4a17-86a6-6c02c9132141.png)

图 5.1 - 控制台输出

在存储库的`chapter-5`目录中自己看一看：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/console.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/console.html)。

好的，太好了。我们有一些控制台输出，但这不是一个很有效的输出方式，因为用户通常不会打开控制台。有一种方便的输出方法，虽然不适用于完整的网络应用程序，但对于测试和调试目的很有用：`alert()`。以下是一个例子：

```js
const Officer = function(name, rank, posting) {
  this.name = name
  this.rank = rank
  this.posting = posting
  this.sayHello = () => {
    alert(this.name)
  }
}

const Riker = new Officer("Will Riker", "Commander", "U.S.S. Enterprise")

Riker.sayHello()
```

尝试从[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/alert.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/alert.html)运行上述代码。你看到了什么？

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1c244f86-7b66-4680-9d48-0782961ced06.png)

图 5.2 - 警报消息

太棒了！我们有一个那种你可能在网上见过的烦人的小弹出框。当使用不当时，它们可能很烦人，但在适当的时候，它们可以非常有用。

让我们看看一个类似的东西，它将从用户那里得到*输入*([`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/prompt.html`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-5/alerts-and-prompts/prompt.html))：

```js
const Officer = function(name, rank, posting) {
  this.name = name
  this.rank = rank
  this.posting = posting

  this.ask = () => {
    const values = ['name','rank','posting']

    let answer = prompt("What would you like to know about this officer?")
    answer = answer.toLowerCase()

    if (values.indexOf(answer) < 0) {
      alert('Value not found')
    } else {
      alert(this[answer])
    }
  }
}

const Riker = new Officer("Will Riker", "Commander", "U.S.S. Enterprise")

Riker.ask()
```

当你加载页面时，你会看到一个带有输入字段的弹出框。输入`name`、`rank`或`posting`，然后查看结果。如果刷新并输入除这些选项之外的内容，你应该会得到一个值未找到的响应。

啊！但让我们也看看以下一行：

```js
answer = answer.toLowerCase()
```

由于这是前端 JavaScript，我们不知道用户会输入什么，所以我们应该考虑轻微的格式错误。数据净化是另一个话题，所以现在，让我们同意我们可以将整个字符串转换为小写以匹配预期的值。

到目前为止，一切都很好。现在，让我们看看`answer`是如何使用的。

# 在函数中处理输入

如果我们看一下前面的对象，我们会看到以下内容：

```js
if (values.indexOf(answer) < 0) {
  alert('Value not found')
} else {
  alert(this[answer])
}
...

```

由于我们正在处理任意输入，我们首先要做的是检查我们的答案数组，看看所请求的属性是否存在。如果不存在，就会弹出一个简单的错误消息。如果找到了，那么我们可以弹出该值。如果你还记得第三章中的内容，*Nitty-Gritty Grammar*，对象属性可以通过**点表示法**和**括号表示法**来访问。在这种情况下，我们正在使用一个变量作为键，所以我们*不能*这样做，因为它会被解释为键。因此，我们使用括号表示法来访问正确的对象值。

## 练习-斐波那契数列

对于这个练习，构建一个函数来接受一个数字。最终结果应该是斐波那契数列([`en.wikipedia.org/wiki/Fibonacci_number`](https://en.wikipedia.org/wiki/Fibonacci_number))中到指定数字的数字之和。序列的前几个数字是`[1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]`。每个数字都是前两个数字的和；例如，`f[6] = 13`，因为`f[5] = 8`，`f[4] = 5`，因此`f[6] = 8+5 = 13`。你可以在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/fibonacci/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/fibonacci/starter-code)找到起始代码。不要太担心计算数字的最有效算法；只需确保不要硬编码值，而是依赖输入变量和公式。

## 斐波那契数列解决方案

让我们解剖一个可能的解决方案：

```js
function fibonacci(num) {
  let a = 1, b = 0, temp

  while (num >= 0) {
    temp = a
    a = a + b
    b = temp
    num--
  }

  return b
}

let response = prompt("How many numbers?")
alert(`The Fibonacci number is ${fibonacci(response)}`)

```

让我们先看看函数外的行。我们所做的只是简单地询问用户想要计算到序列的哪个点。然后，`response`变量被传递到`alert()`语句作为`fibonacci`的参数，`fibonacci`接受`num`作为参数。从那时起，`while()`循环在`num`上执行，将`num`递减，而`b`的值则根据算法递增，最后返回到我们的警报消息中。

就是这样了！现在，让我们尝试一个变体，因为我们永远不知道我们的用户会输入什么。如果他们输入的是一个字符串而不是一个数字会发生什么？我们应该适应这一点，至少呈现一个错误消息。

让我们来看看这个解决方案：

```js
function fibonacci(num) {
  let a = 1, b = 0, temp

  while (num >= 0) {
    temp = a
    a = a + b
    b = temp
    num--
  }

  return b
}

let response = prompt("How many numbers?")

while (typeof(parseInt(response)) !== "number" || !Number.isInteger(parseFloat(response))) {
  response = prompt("Please enter an integer:")
}

alert(`The Fibonacci number is ${fibonacci(response)}`)
```

你可以在 GitHub 上找到解决方案，网址是[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/fibonacci/solution-code-number-check`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/fibonacci/solution-code-number-check)。

如果我们进入`while()`循环，我们会看到我们的类型匹配魔法。首先，由于`response`本质上是一个字符串，我们决定不要相信类型强制转换，这就是我们之前的解决方案在做的事情。我们使用`parseInt()`方法将`response`直接转换为一个数字。太好了！但这并不能确保我们的用户一开始输入的是一个整数。记住，JavaScript 没有`int`和`float`的概念，所以我们必须进行一些操作，以确保我们的输入是一个整数，方法是使用`Number.isInteger`方法的否定。这确保了我们的输入是一个有效的整数。

在更深入地使用 JSON 之前，让我们看看如何将对象用作数据存储。

# 使用对象作为数据存储

这是一个我在编程面试中见过的有趣问题，以及解决它的最有效方法。它具有昂贵的输入时间，但具有 O(1)的*检索*时间，这通常被认为是算法复杂性成功的度量标准，当你可以预期读取的次数比写入的次数多时。

## 练习-乘法

考虑以下代码（[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/matrix/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/matrix/starter-code)）：

```js
const a = [1, 3, 5, 7, 9]
const b = [2, 5, 7, 9, 14]

// compute the products of each permutation for efficient retrieval

const products = { }

// ...

const getProducts = function(a,b) {
  // make an efficient means of retrieval
  // ...
}

// bonus: get an arbitrary key/value pair. If nonexistent, compute it and store it.
```

那么，在使用对象的范例中，解决方案是什么？让我们来看看，分解一下，然后逆向工程我们使用对象作为数据存储的用法（*剧透警告：*你听说过 NoSQL 吗？）。

## 乘法解决方案

在我们开始之前，让我们将问题分解为两个步骤：给定两个数组，我们首先计算数组中每个项目的乘积，并将它们存储在一个对象中。然后，我们将编写一个函数来检索数组中给定两个数字的乘积。让我们来看看。

### 第一步 - 计算和存储

首先，我们的`makeProducts`函数将以两个数组作为参数。使用数组的`.forEach()`方法，我们将遍历第一个数组中的每个项目，将值命名为`multiplicant`：

```js
const makeProducts = function(array1, array2) {
  array1.forEach( (multiplicant) => {
    if (!products[multiplicant]) {
      products[multiplicant] = { }
    }
    array2.forEach( (multiplier) => {
      if (!products[multiplier]) {
        products[multiplier] = { }
      }
      products[multiplicant][multiplier] = multiplicant * multiplier
      products[multiplier][multiplicant] = products[multiplicant]
       [multiplier]
    })
  })
}
```

现在，我们的最终目标是有一个对象告诉我们“*x*和*y*的乘积是*z*”。如果我们将这个抽象成使用对象作为数据存储，我们可以得到这样的结构：

```js
{
  x: {
    y: z
  },
  y: {
    x: z
  }
}
```

在这个对象结构中，我们只需要指定`x.y`来检索我们的计算，它将是`z`。我们也不想假设一个顺序，所以我们也做相反的：`y.z`。

那么，我们如何构建这个数据对象呢？记住，如果我们不是调用文字键，我们可以使用**方括号表示法**与对象；在这里，我们使用一个变量：

```js
if (!products[multiplicant]) {
    products[multiplicant] = { }
}
```

我们的第一步是检查我们的对象中是否存在`multiplicant`键（在我们之前的理论讨论中是`x`）。如果不存在，将其设置为一个新对象。

现在，在我们的内部循环中，让我们对乘数做同样的事情：

```js
if (!products[multiplier]) {
    products[multiplier] = { }
}
```

太好了！我们已经为`x`和`y`都设置了键。现在，我们只需计算乘积并将其存储在两个位置，如下所示：

```js
products[multiplicant][multiplier] = multiplicant * multiplier
products[multiplier][multiplicant] = products[multiplicant][multiplier]
```

*注意决定将反向键值分配给正向键的值，而不是重新计算乘积*。为什么我们要这样做？事实上，为什么我们要为一个简单的数学运算费这么大劲？原因是：如果我们不是做简单的乘法，而是做一个*远远*更复杂的计算呢？也许一个如此复杂以至于需要一秒或更长时间才能返回的计算？现在我们可以看到，我们希望减少我们的时间，这样我们只需要做一次计算，然后可以重复读取它以获得最佳性能。

构建了这个函数之后，我们将在我们的数组上执行它：

```js
makeProducts(a,b)
```

这很容易调用！

### 第二步 - 检索

现在，让我们编写我们的检索函数：

```js
const getProducts = function(a,b) {
  // make an efficient means of retrieval
  if (products[a]) {
    return products[a][b] || null
  }
  return null
}
```

如果我们看这个逻辑，首先我们确保第一个键存在。如果存在，我们返回`x.y`或者如果`y`不存在则返回`null`。对象很挑剔，如果你试图引用一个不存在的*键*的*值*，你会得到一个错误。因此，我们首先需要存在性检查我们的键。如果键存在*并且*键/值对存在，返回计算出的值；否则，我们返回`null`。注意`return products[a][b] || null`的短路：这是一种有效的方式来表示“返回值或其他东西”。如果`products[a][b]`不存在，它将响应一个假值，然后`OR`操作将接管。高效！

看一下奖励问题的答案的解决方案代码。存在检查和计算的相同原则适用。

# 理解范围

在我们构建一个更大的应用程序之前，让我们讨论一下范围。简而言之，范围定义了我们何时何地可以使用变量或函数。JavaScript 中的范围被分为两个离散的类别：局部和全局。如果我们看看我们之前的乘法程序，我们可以看到有三个变量在任何函数之外；它们挂在我们程序的根级别：

```js
01: const a = [1, 3, 5, 7, 9]
02: const b = [2, 5, 7, 9, 14]
03: 
04: // compute the products of each permutation for efficient retrieval
05: 
06: const products = { }
07: 
08: const makeProducts = function(array1, array2) {
09:     array1.forEach( (multiplicant) => {
10:         if (!products[multiplicant]) {
11:             products[multiplicant] = { }
12:         }
13:         array2.forEach( (multiplier) => {
14:             if (!products[multiplier]) {
15:                 products[multiplier] = { }
16:             }
17:             products[multiplicant][multiplier] = multiplicant * 
                 multiplier
18:             products[multiplier][multiplicant] = products[multiplicant]
                 [multiplier]
19:         })
20:     })
21: }
22: 
23: const getProducts = function(a,b) {
24:     // make an efficient means of retrieval
25:     if (products[a]) {
26:         return products[a][b] || null
27:     }
28:     return null
29: }
30: 
31: makeProducts(a,b)
```

问题中的变量分别在第 1、2 和 6 行：`a`、`b`和`products`。太好了！这意味着我们可以在任何地方使用它们，比如第 10、11、14、15 行，以及更多地方，只要我们在它们被定义之后使用它们。现在，如果我们仔细看，我们还会看到我们在全局作用域中有一些函数：`makeProducts`和`getProducts`。同样，只要它们已经被定义，我们可以在任何地方使用它们。

好的，太好了——这是有道理的，因为 JavaScript 是从上到下读取的。但等等！如果你还记得第三章中的内容，*Nitty-Gritty Grammar*，函数声明被提升到顶部，因此可以在任何地方使用。

让我们重构我们的程序，利用提升和抽象我们的数学来成为理论上的长时间运行的过程。我们还将使用`Promises`作为一个很好的概念介绍。在我们深入研究之前，阅读使用`Promises`可能会有所帮助：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises)。

在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/matrix-refactored`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-5/matrix-refactored)中查看`index.js`。我们将一步一步地分解这个过程。

首先，在浏览器中打开`index.html`。确保你的控制台是打开的。2 秒后，你会在控制台中看到一个简单的消息：9 x 2 = 18。如果你看一下`index.js`中的第 44 行，你会看到它在使用`getProducts`来计算`a[4]`和`b[0]`的乘积，它们分别是`9`和`2`。太棒了！到目前为止，我们的功能与添加了一个感知延迟是一样的。

让我们从头开始：

```js
1: const a = [1, 3, 5, 7, 9]
2: const b = [2, 5, 7, 9, 14]
3: 
4: // compute the products of each permutation for efficient retrieval
5: 
6: const products = {}
7: 
```

到目前为止，我们有相同的代码。那么我们的`makeProducts`函数呢？

```js
08: const makeProducts = async function(array1, array2) {
09:     const promises = []
10:     array1.forEach((multiplicant) => {
11:         if (!products[multiplicant]) {
12:             products[multiplicant] = {}
13:         }
14:         array2.forEach(async (multiplier) => {
15:             if (!products[multiplier]) {
16:                 products[multiplier] = {}
17:             }
18: 
19:             promises.push(new Promise(resolve => 
                 resolve(calculation(multiplicant, multiplier))))
20:             promises[promises.length - 1].then((val) => {
21:                 products[multiplicant][multiplier] = products[
                      multiplier][multiplicant] = val
22:             })
23:         })
24:     })
25:     return promises
26: }
```

嗯。好的，我们有一些相同的部分，但也有一些新的部分。首先，让我们考虑**`async`**。当与一个函数一起使用时，这个关键字意味着这个函数的使用者应该期望*异步行为*，而不是 JavaScript 通常的自上而下的行为。在我们深入研究新的 19-21 行之前，让我们看一下我们的`calculation`函数为什么是异步的：

```js
37: async function calculation(value1, value2) {
38:     await new Promise(resolve => setTimeout(resolve, 2000))
39:     return value1 * value2
40: }
```

这里又是第 37 行的`async`，现在我们在第 38 行看到一个新的关键字：`await`。`async`和`await`是指定我们可以异步工作的一种方式：在第 38 行，我们指定我们在继续之前正在等待这个`promise`**解析**。我们的`promise`在做什么？嗯，事实证明，并不多！它只是使用`setTimeout`延迟 2,000 毫秒。这个延迟旨在模拟一个长时间运行的过程，比如一个 Ajax 调用或者一个需要 2 秒才能完成的复杂过程（甚至是一个不确定的时间量）。

好的，太好了。到目前为止，我们基本上是在欺骗程序，让它期望在继续之前有 2 秒的延迟。让我们看看第 9 行：一个名为`promises`的新数组。现在，回到我们关于*作用域*的想法，你可以注意到我们的数组是在`makeProducts`内部定义的。这意味着这个变量只存在于函数的局部作用域内。与 products 相反，我们无法从这个函数的外部访问 promises。没关系——我们真的不需要。事实上，最好的做法是尽量减少在全局作用域中定义的变量数量。

现在，让我们看一下第 19 行，看起来更加微妙：

```js
promises.push(new Promise(resolve => resolve(calculation(multiplicant, multiplier))))
```

如果我们分解一下，首先我们看到了一些熟悉的东西：我们正在将一些东西推到我们的`promises`数组中。我们正在推送的是一个新的`Promise`，类似于第 38 行，但在这种情况下，我们不是在行内等待它，而是只是说“用`calculation()`的值解析这个`promise`——无论何时发生”。到目前为止，一切都很好。下一部分呢？

```js
20: promises[promises.length - 1].then((val) => {
21:     products[multiplicant][multiplier] = products[multiplier]
         [multiplicant] = val
22: })
```

现在，一些语法糖就出现了：现在我们在`promises`数组中有了我们的`promise`，我们可以使用`[promises.length - 1]`来访问它，因为`length`返回的是从`1`开始的完整长度。`.then()`子句是我们的魔法：它表示一旦`promise`完成，就对结果进行处理。在这种情况下，我们的*处理*是将`val`分配给产品的两个变体。最后，在第 25 行，我们返回`promises`数组。

我们的`getProducts`函数一点都没有改变！我们的检索函数的复杂性保持不变：高效。

这个怎么样？

```js
42: makeProducts(a,b).then((arrOfPromises) => {
43:     Promise.all(arrOfPromises).then(() => {
44:         console.log(`${a[4]} x ${b[0]} = ${getProducts(a[4], b[0])}`)
             // 18
45:     })
46: })
```

我们之前见过`.then`，所以它的参数是`makeProducts`的返回值，即`promises`数组。然后，我们可以在`.then`之前使用`.all()`来有效地表示“当`arrOfPromises`中的所有`promises`都已解决时，然后执行下一个函数”。下一个函数是记录我们的答案。你可以在第 44 行之后添加额外的产品检查；它们将与第 44 行同时返回，因为我们的“计算”中的延迟已经发生。

## 作用域链和作用域树

进一步深入作用域，我们有**作用域链**和**作用域树**的概念。让我们考虑以下例子：

```js
function someFunc() {
  let outerVar = 1;
  function zip() {
    let innerVar = 2;
  }
}
```

`someFunc`有哪些变量可以访问？`zip`有哪些变量可以访问？如果你猜到`someFunc`可以访问`outerVar`，但`zip`可以访问`innerVar`和`outerVar`，那么你是正确的。这是因为这两个变量存在于`zip`的作用域链中，但只有`outerVar`存在于`someFunc`的作用域中。清楚了吗？太好了。让我们看一些图表。

看一下以下代码：

```js
function someFunc() {
  function zip() {
    function foo() {
    }
  }
  function quux() {
  }
}
```

我们可以从上到下构建一个函数的**作用域树**的图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ddbada90-b172-4f3f-9773-c44ecc76904b.png)

图 5.3 - 作用域树

这告诉我们什么？`quux`似乎独立存在于`someFunc`内部的小世界中。它可以访问`someFunc`的变量，但*不能*访问`zip`或`foo`。我们也可以通过**作用域链**从下到上来理解它：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/3346d996-15a3-4f99-81c7-b4813235bfe6.png)

图 5.4 - 作用域链

在这个例子中，我们看一下`foo`可以访问什么。从下到上，我们可以看到它与代码其他部分的关系。

## 闭包

现在，我们将进入**闭包**，这显然是 JavaScript 中一个可怕的话题。然而，基本概念是可以理解的：一个闭包就是一个函数，它在另一个函数内部，可以访问其父函数的作用域链。在这种情况下，它有三个作用域链：自己的作用域链，其中定义了自己的变量；全局的作用域链，其中可以访问全局作用域中的所有变量；以及父函数的作用域。

这是一个我们将解剖的例子：

```js
function someFunc() {
  let bar = 1;

  function zip() {
    alert(bar); // 1
    let beep = 2;

    function foo() {
      alert(bar); // 1
      alert(beep); // 2
    }
  }
}
```

哪些变量可以被哪些函数访问？这里有一个图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/6c9bc35d-24cb-4992-8095-a1804e39a5de.png)

图 5.5 - 闭包

从下到上，`foo`可以访问`beep`和`bar`，而`zip`只能访问`bar`。到目前为止，一切都好，对吧？闭包只是一种描述每个嵌套函数可用作用域的方式。它们本身并不可怕。

## 一个闭包在实践中的基本例子

看一下以下函数：

```js
  function sayHello(name) {
    const sayAlert = function() {
      alert(greeting)
    }

    let greeting = `Hello ${name}`
    return sayAlert
  }

  sayHello('Alice')()
  alert(greeting)
```

首先，让我们看看这个有趣的构造：`sayHello('Alice')()`。由于我们的`sayAlert()`函数是`sayHello`的返回值，我们首先用一个括号对调用`sayHello`，并带上我们的参数，然后用第二对括号调用它的返回值（`sayAlert`函数）。注意`greeting`在`sayHello`的作用域内，当我们调用我们的函数时，我们会得到一个 Hello Alice 的警报。然而，如果我们尝试单独警报`greeting`，我们会得到一个错误。只有`sayAlert`可以访问`greeting`。同样，如果我们试图从函数外部访问`name`，我们会得到一个错误。

# 摘要

为了使我们的程序有用，它们通常依赖于用户或其他函数的输入。通过搭建我们的程序以使其灵活，我们还需要牢记作用域的概念：何时何地可以使用函数或变量。我们还看了一下对象如何用于有效存储数据以便检索。

让我们不要忘记闭包，这个看似复杂的概念实际上只是一种描述作用域的方式。

在下一章中，随着我们开始使用**文档对象模型**（**DOM**）并操纵页面上的信息，而不仅仅是与警报和控制台交互，我们将更多地探索前端。

# 问题

考虑以下代码：

```js
function someFunc() {
  let bar = 1;

  function zip() {
    alert(bar); // 1
    let beep = 2;

    function foo() {
      alert(bar); // 1
      alert(beep); // 2
    }
  }

  return zip
}

function sayHello(name) {
  const sayAlert = function() {
    alert(greeting)
  }

  const sayZip = function() {
    someFunc.zip()
  }

  let greeting = `Hello ${name}`
  return sayAlert
}
```

1.  如何获得警报 Hello Bob？

1.  `sayHello()('Bob')`

1.  `sayHello('Bob')()`

1.  `sayHello('Bob')`

1.  `someFunc()(sayHello('Bob'))`

1.  在前面的代码中，`alert(greeting)`会做什么？

1.  警报问候语。

1.  警报 你好 Alice。

1.  抛出错误。

1.  以上都不是。

1.  我们如何获得警报消息 1？

1.  `someFunc()()`

1.  `sayHello().sayZip()`

1.  `alert(someFunc.bar)`

1.  `sayZip()`

1.  我们如何获得警报消息 2？

1.  `someFunc().foo()`.

1.  `someFunc()().beep`。

1.  我们不能，因为它不在作用域内。

1.  我们不能，因为它没有定义。

1.  我们如何将`someFunc`更改为警报 1 1 2？

1.  我们不能。

1.  在`return zip`后添加`return foo`。

1.  将`return zip`更改为`return foo`。

1.  在`foo`声明后添加`return foo`。

1.  给定前面问题的正确解决方案，我们如何实际获得三个警报 1、1、2？

1.  `someFunc()()()`

1.  `someFunc()().foo()`

1.  `someFunc.foo()`

1.  `alert(someFunc)`

# 进一步阅读

+   MDN - 闭包：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Closures`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Closures)

+   *轻松理解 JavaScript 闭包*：[`javascriptissexy.com/understand-javascript-closures-with-ease/`](http://javascriptissexy.com/understand-javascript-closures-with-ease/)


# 第六章：文档对象模型（DOM）

**文档对象模型**（**DOM**）是浏览器暴露给 JavaScript 的 API，允许 JavaScript 与 HTML 和间接与 CSS 进行通信。由于 JavaScript 的主要能力之一是动态更改页面上的内容，我们应该知道如何做到这一点。这就是 DOM 的作用。

在本章中，我们将学习如何使用这个强大的 API 来读取和更改页面上的内容。我相信你已经看到过不需要重新加载页面就可以更改内容的网站。这些程序使用*DOM 操作*，我们将学习如何使用它。

本章将涵盖以下主题：

+   选择器

+   属性

+   操作

# 技术要求

确保在`Chapter-6`目录中有[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers) 存储库方便使用。

# 使用选择器

到目前为止，我们只使用了`console.log`和警报和提示来输入和输出信息。虽然这些方法对于测试很有用，但并不是你在日常生活中会使用的。我们使用的大多数 Web 应用程序，从搜索到电子邮件，都使用 DOM 与用户交互以获取输入和显示信息。让我们看一个小例子：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/hello`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/hello)。

如果你在浏览器中打开 HTML，我们会看到一个非常简单的页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/a342e927-fbb8-426a-b8d4-39b5c9293115.png)

图 6.1 我们的基本页面

如果我们点击按钮，我们不会得到警报或控制台消息，而是会看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/f04c693f-3d8e-458e-9042-1293872160a7.png)

图 6.2 我们点击后页面的响应！

耶！这是我们第一个**DOM 操作**的实例。

## 解释 DOM 操作

让我们看看支持这个惊人示例的 JavaScript：

```js
document.querySelector('button').addEventListener('click', (e) => {
 document.querySelector('p').innerHTML = `Hello! It is currently ${
  new Date()}.`
})

```

首先要注意的是，我们正在操作`document`对象。`document`是 JavaScript 对浏览器页面的概念。记得我提到过 DOM 是浏览器暴露的 API 吗？这是你访问 DOM 的方式：`document`。

在我们分析 JavaScript 之前，让我们看看 DOM 和 HTML 有什么不同。这是我们页面的 HTML：

```js
<!DOCTYPE html>
<html lang="en" dir="ltr">

<head>
  <meta charset="utf-8">
  <title>Example</title>
</head>

<body>
  <p></p>
  <button>Click me!</button>
  <script src="index.js"></script>
</body>

</html>
```

如果我们现在使用控制台来检查元素而不是控制台，我们会看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/3093173a-07ac-4804-930f-18c516613b2f.png)

图 6.3 我们页面的 DOM

如果你仔细观察并将这个截图与前面的 HTML 进行比较，你不会真的找到任何区别。然而，现在点击按钮，看看`<p>`标签会发生什么：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ecb14272-76ad-4364-8592-af09cd0687a4.png)

图 6.4 点击按钮后

啊！现在我们看到 HTML 和 DOM 之间的区别：在段落标签内添加了文本。如果我们重新加载页面，文本就会消失，我们又回到了起点。所以，我们看到的是什么都没有*在磁盘上*改变，只是*在内存中*改变。DOM 只存在于内存中。你可以在元素视图中通过更改值甚至删除整个**节点**来进行实验。节点是 DOM 对 HTML 标签的反映。你可能会听到*节点*和*标签*互换使用，但在使用 JavaScript 时，使用*节点*是一个好习惯，以保持与 JavaScript 的命名一致，我们稍后会看到。

回到我们的 JavaScript。到目前为止，我们已经讨论了`document`，它是 DOM 对 HTML 的内存解释。我们正在使用的`document`方法是一个强大的方法：`.querySelector()`。这个方法返回与我们传递给方法的参数的*第一个*匹配项。在这种情况下，我们要求`button`。由于页面上只有一个按钮，我们可以简单地使用标签名称。但是，`querySelector`比这更强大，因为我们也可以基于 CSS 选择器进行选择。例如，假设我们的按钮上有一个类，就像这样：

```js
<button class="clickme">Click me!</button>
```

然后我们可以这样访问按钮：

```js
document.querySelector('.clickme')
```

注意`clickme`前面的“`.`”，就像 CSS 选择器一样。同样，当访问具有 ID 的元素时，您将使用“`#`”。

现在我们已经可以访问我们的按钮，我们想对它做*一些*事情。在这种情况下，*一些*是指在点击按钮时采取行动。我们通过添加**事件监听器**来实现这一点。我们将在第七章中更深入地了解事件监听器，所以现在让我们只是浅尝辄止。

这是事件监听器的结构：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/cf03f546-306f-446a-a59a-1511eb529ce1.png)

图 6.5 事件监听器结构

首先，我们的**事件目标**是我们要监听的节点；在这种情况下，我们的目标是按钮。然后我们使用`.addEventListener()`方法，并将`click`**事件**分配为我们要监听的事件。我们事件监听器的第二个参数是一个称为**事件处理程序**的函数。我们可以将实际的**事件对象**传递给我们的处理程序。事件处理程序通常不必是匿名的，但这是常见的做法，除非您需要为多个事件类型重复使用功能。我们的处理程序再次使用`querySelector`来定位`p`节点，并将其`innerHTML`属性设置为包含我们日期的字符串。

关于节点属性：节点的*属性*是 HTML 元素属性在 DOM 中的内存表示。这意味着有很多属性：`className`、`id`和`innerHTML`，只是举几个例子；当我们到达*属性*部分时，我们将更深入地了解它们。因此，这些代码行告诉浏览器：“嘿，当点击这个按钮时，将`p`标签的内容更改为这个字符串。”

现在我们已经俯视了这个问题，让我们深入研究涉及 DOM 操作的每个部分。

## 使用选择器

让我们考虑一个更复杂的页面。我们将打开一个示例页面，并使用为您提供的一些元素：

1.  在浏览器中打开[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/animals`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/animals)中的`index.html`：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/7062a150-3baf-4d78-bee5-b47f64c7150e.png)

图 6.6 动物页面

1.  如果您悬停在橙色按钮上，它将变为青绿色，并且当您单击它时，页面顶部的黑色框将显示动物：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4765b49f-8eaa-427d-b4f0-aadb950d780f.png)

图 6.7 选择的动物

1.  花一分钟玩一下页面，观察它的行为。还要尝试悬停在照片上；会发生什么？

现在让我们来看看 JavaScript。再次，它非常简单，但是我们的故事中有一些新的字符：

```js
01: const images = {
02:   'path': 'images/',
03:   'dog': 'dog.jpg',
04:   'cat': 'cat.jpg',
05:   'elephant': 'elephant.jpg',
06:   'horse': 'horse.jpg',
07:   'panda': 'panda.jpg',
08:   'rabbit': 'rabbit.jpg'
09: }
10: 
11: const buttons = document.querySelectorAll('.flex-item');
12: 
13: buttons.forEach((button) => {
14:   button.addEventListener('click', (e) => {
15:     document.querySelector('img').src = 
         `${images.path}${images[e.target.id]}`
16:   })
17: })
18: 
19: document.querySelector('#image').addEventListener('mouseover', (e) => {
20:   alert(`My favorite picture is ${e.target.src}`)
21: })
```

第 1-9 行包含一个数据存储对象。太棒了！我们在第五章中已经介绍了这种用法，*你的第一个应用程序：你好，世界！以及更多*。

第 11 行介绍了使用选择器的一种新方法：`.querySelectorAll()`。如前所述，当我们使用`.querySelector()`时，我们会得到与我们查询匹配的*第一个*项目。这种方法将返回所有匹配节点的数组。然后，我们可以在第 13 行对它们进行迭代，为每个节点添加一个点击处理程序。在第 15 行，我们定义了我们事件处理程序中的*发生了什么*：将唯一`img`节点的源设置为来自我们数据对象的路径和图像源的连接。

但等等！`e.target`是什么？我们将在第七章 *事件、事件驱动设计和 API*中深入探讨事件，但现在只需要知道`e.target`是*事件目标的 DOM 节点*。因此，在这个例子中，我们正在遍历所有`.flex-item`类的 DOM 节点。在每个节点上，我们正在分配一个事件处理程序，因此`e.target`等于 DOM 节点，`e.target.id`等于其`id`的 HTML 属性。

太棒了。让我们看看第 19 行，我们正在做类似的事情，但这次使用 CSS 选择器`id`——`image`。看一下 HTML：

```js
 <div class="flex-header"><img id="image"/></div>
```

我们看到标签上有一个`image`的 ID，这意味着我们的 DOM 节点也会有这个 ID。现在，当我们移动（或悬停）在图像上时，我们将收到一个警报消息，说明图像文件的本地路径。

如果你对 CSS 不太熟悉，现在你可能会问自己：但是用 JavaScript 把橙色框变成蓝绿色的代码在哪里？哈！这是个陷阱问题！让我们看一下`style.css`文件中的 45-48 行：

```js
.flex-item:hover {
  cursor: pointer;
  background-color: turquoise;
}
```

如果你注意到了项目上的`：hover`伪类，我们可以看到改变光标从箭头到手的 CSS 规则（在大多数用户界面中表示可点击性），以及背景颜色的改变。惊喜！

这不是一本关于 CSS 的书；相反，我们将尽量避免过多的样式依赖。然而，重要的是要注意，通常 CSS 允许我们对 HTML 元素的一些表现方面进行更改。但是我们为什么要在意呢？毕竟，我们正在写*JavaScript*。答案很简单：计算开销。通过 JavaScript 修改元素比通过 CSS 更*昂贵*（也就是说，需要更多的处理能力）。如果你正在操作不需要逻辑的 CSS 属性，请尽可能使用 CSS。但是，如果你需要逻辑（比如在我们的例子中将变量拼接到显示图像中），那么 JavaScript 是正确的选择。

## 使用其他选择器

重要的是要注意，在 ES6 和 HTML5 的一部分之前，`querySelector`和`querySelectorAll`被标准化之前，有其他更常见的选择器，你肯定会在实际中遇到它们。其中一些包括`getElementById`、`getElementsByClassName`和`getElementsByTagName`。现在使用`querySelector`的变体被认为是标准做法，但是和所有 JavaScript 一样，有一个警告：从技术上讲，`querySelector`方法比`getElement`风格的方法稍微昂贵一点。通常情况下，与`querySelector`方法的强大和灵活性相比，这种开销是可以忽略的，但在处理大页面时，这是需要记在心里的事情。

现在，让我们看一看在选择了元素之后我们可以改变*什么*。这些是元素的**属性**。

# 属性

我们已经处理了一些属性：节点的`innerHTML`，图像的`src`和节点的`id`。我们有大量可用的属性，所以让我们来看看 CSS 是如何与 JavaScript 结合的。

光是为了论证，让我们把我们的动物程序改成使用 JavaScript 来改变目标的背景颜色，而不是 CSS（[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/animals-2`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/animals-2)）：

```js
const images = {
  'path': 'images/',
  'dog': 'dog.jpg',
  'cat': 'cat.jpg',
  'elephant': 'elephant.jpg',
  'horse': 'horse.jpg',
  'panda': 'panda.jpg',
  'rabbit': 'rabbit.jpg'
}

const buttons = document.querySelectorAll('.flex-item');

buttons.forEach((button) => {
  button.addEventListener('mouseover', (e) => {
    e.target.style.backgroundColor = 'turquoise'
  })
  button.addEventListener('click', (e) => {
    document.querySelector('img').src = 
     `${images.path}${images[e.target.id]}`
  })
})

document.querySelector('#image').addEventListener('mouseover', (e) => {
  alert(`My favorite picture is ${e.target.src}`)
})
```

如果我们检查我们的 mouseover 处理程序，我们可以注意到两件事：

+   事件的名称是`mouseover`，而不是`hover`。稍后再详细讨论。

+   我们正在修改目标的样式属性，但名称是`backgroundColor`，而不是 CSS 中的`background-color`。

CSS 中属性的驼峰命名规则在 JavaScript 中也是标准的。在实践中，这可能看起来有点违反直觉，因为你不必使用括号表示法和引号来处理属性名称中的连字符（这将被解释为无效的减法语句）。

然而，现在让我们运行程序并悬停在所有框上。你看到颜色从一种颜色变成另一种颜色了吗，就像这样吗？

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/87dd9e77-c927-43c3-bdbf-fe3ea86a36c2.png)

图 6.8 所有的框都改变了！

是的，如果你猜到我们没有包括一个“重置”处理程序，你是对的。我们可以用`mouseout`事件来做到这一点。然而，你看到当你可以使用 CSS 时使用 CSS 是有道理的吗？

当然，没有必要记住 DOM 节点上可用的各种属性，但`id`、`className`、`style`和`dataset`可能是最有用的。

你问的这个`dataset`属性是什么？你可能不熟悉 HTML 中的数据属性，但它们非常方便。考虑 MDN 中的这个例子：

```js
<article id="electric-cars" data-columns="3" data-index-number="12314" data-parent="cars"> ... </article>
```

当你的后端可以将标记插入到 HTML 中，但与 JavaScript 分离时（几乎总是如此，并且可以说是你的结构应该被架构化的方式），`data-`属性就非常方便。要访问`article`的`data-index-number`，我们使用这个：

```js
article.dataset.indexNumber // "12314"
```

再次注意我们的驼峰命名法和`.dataset.`的新用法，而不是`data-`。

我们现在知道足够多的知识来对我们的元素进行更多的激动人心的工作。我们可以用选择器来定位元素并读取元素的属性。接下来，让我们看看**操作**。

# 操作

在使用 JavaScript 通过 DOM 工作时，我们不仅可以读取，还可以*操作*这些属性。让我们通过制作一个小程序来练习操作属性：便利贴创建者。

## 便利贴创建者

我们将制作一个便利贴创建者，它接受颜色和消息，并将带有序号的彩色框添加到 DOM 中。我们的最终产品可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/a6ca44b0-6dea-4b74-aa00-a0579315aa93.png)

图 6.9 最终产品

看一下起始代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/stickies/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/stickies/starter-code)。 [](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-6/stickies/starter-code)

你的目标是重新创建这个功能。这里有两种我们还没有涵盖的方法供你研究：

+   `document.createElement()`

+   `container.appendChild()`

## 解决方案代码

你做得怎么样？让我们看看解决方案代码：

```js
const container = document.querySelector('.container') // set .container to a variable so we don't need to find it every time we click
let noteCount = 1 // inital value

// access our button and assign a click handler
document.querySelector('.box-creator-button').addEventListener('click', () => {
  // create our DOM element
  const stickyNote = document.createElement('div')

  // set our class name
  stickyNote.className = 'box'

  // get our other DOM elements
  const stickyMessage = document.querySelector('.box-color-note')
  const stickyColor = document.querySelector('.box-color-input')

  // get our variables
  const message = stickyMessage.value
  const color = stickyColor.value

  // blank out the input fields
  stickyMessage.value = stickyColor.value = ''

  // define the attributes
  stickyNote.innerHTML = `${noteCount++}. ${message}`
  stickyNote.style.backgroundColor = color

  // add the sticky
  container.appendChild(stickyNote)
})
```

好了！其中一些行不应该是一个谜，但最有趣的是第 7 行（`const stickyNote = document.createElement('div')`）和第 28 行（`container.appendChild(stickyNote)`）。正如之前提到的，这是你需要研究的两种方法，以完成这个程序。第 7 行正在创建一个 DOM 节点——在内存中！我们可以对它进行操作，比如添加内容和样式，然后在第 28 行将其添加到 DOM 中。

# 总结

耶，我们终于进入了 DOM 并对其进行了操作！恭喜你迄今为止的成就！

现在，我们可以通过 JavaScript 动态地改变页面上的内容，而不仅仅是使用警报和控制台消息。以下是我们学到的内容的概述：

+   `querySelector`和`querySelectorAll`是我们进入 DOM 的神奇领域的门户。

+   DOM 只存在于内存中，作为 HTML 在页面加载时的动态表示。

+   这些方法的选择器将使用 CSS 选择器；旧方法不会。

+   节点的属性可以更改，但术语不同。

在下一章中，我们将更多地使用*events*。事件是 JavaScript 程序的核心，让我们学习它们的结构和用法。

# 问题

考虑以下代码：

```js
  <button>Click me!</button>
```

回答以下问题：

1.  选择按钮的正确语法是什么？

1.  `document.querySelector('点击我！')`

1.  `document.querySelector('.button')`

1.  `document.querySelector('#button')`

1.  `document.querySelector('button')`

看看这段代码：

```js
<button>Click me!</button>
<button>Click me two!</button>
<button>Click me three!</button>
<button>Click me four!</button>
```

回答以下问题：

1.  真或假：`document.querySelector('button')` 将满足我们对每个按钮放置点击处理程序的需求。

1.  正确

1.  错误

1.  要将按钮的文本从“点击我！”更改为“先点击我！”，我们应该使用什么？

1.  `document.querySelectorAll('button')[0].innerHTML = "先点击我！"`

1.  `document.querySelector('button')[0].innerHTML = "先点击我！"`

1.  `document.querySelector('button').innerHTML = "先点击我！"`

1.  `document.querySelectorAll('#button')[0].innerHTML = "先点击我！"`

1.  我们可以使用什么方法来添加另一个按钮？

1.  `document.appendChild('button')`

1.  `document.appendChild('<button>')`

1.  `document.appendChild(document.createElement('button'))`

1.  `document.appendChild(document.querySelector('button'))`

1.  我们如何将第三个按钮的类更改为`third`？

1.  `document.querySelector('button')[3].className = 'third'`

1.  `document.querySelectorAll('button')[2].className = 'third'`

1.  `document.querySelector('button[2]').className = 'third'`

1.  `document.querySelectorAll('button')[3].className = 'third'`

# 进一步阅读

有关更多信息，您可以参考以下链接：

+   MDN：*Document* *Object Model (DOM)*：[`developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model`](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model)

+   MDN：*Document.createElement()*：[`developer.mozilla.org/en-US/docs/Web/API/Document/createElement`](https://developer.mozilla.org/en-US/docs/Web/API/Document/createElement)

+   MDN：*Node.appendChild()*：[`developer.mozilla.org/en-US/docs/Web/API/Node/appendChild`](https://developer.mozilla.org/en-US/docs/Web/API/Node/appendChild)


# 第七章：事件，事件驱动设计和 API

在前端应用的核心是*事件*。JavaScript 允许我们监听并对用户和浏览器事件做出反应，以直观地改变用户内容，从而创建优雅的用户界面和体验。我们需要知道如何使用这些被抛出的数据包。浏览器事件是我们的基础 - 它们使我们不仅仅拥有静态应用，而是动态的！通过理解事件，您将成为一个完整的 JavaScript 开发人员。

本章将涵盖以下主题：

+   事件生命周期

+   捕获事件并读取其属性

+   使用 Ajax 和事件来填充 API 数据

+   处理异步性

# 技术要求

准备好使用存储库的`Chapter-7`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7)。

# 事件生命周期

当 JavaScript 中发生事件时，它不仅仅发生并消失 - 它经历了一个*生命周期*。这个生命周期有三个阶段：

+   **捕获**阶段

+   **目标**阶段

+   **冒泡**阶段

考虑以下 HTML：

```js
<!doctype html>
<html>

<head>
  <title>My great page</title>
</head>

<body>
  <button>Click here</button>
</body>

</html>
```

我们可以将其可视化如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/b30b13fc-d9a9-42ba-90f2-9f1e8a9c7acf.png)

图 7.1 - 事件生命周期

现在，还有一件重要的事情需要考虑，那就是事件发生时不仅仅影响到确切的目标，而是整个对象堆栈。在描述捕获、目标和冒泡之前，看一下我们代码的以下表示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9059220b-da02-4e37-9470-532f29aedc52.png)

图 7.2 - 事件分层

如果我们把我们的页面想象成一个分层蛋糕，我们可以看到这个事件（由箭头表示）必须通过我们 DOM 的所有层才能到达按钮。这是我们的**捕获**阶段。当按钮被点击时，事件被*派发*到事件流中。首先，事件查看文档对象。然后它穿过 DOM 的各层直到到达预定目的地：按钮。

现在事件已经到达按钮，我们开始**目标**阶段。事件应该从按钮中捕获的任何信息都将被收集，比如事件类型（比如点击或鼠标悬停）和其他细节，比如光标的*X*/*Y*坐标。

最后，事件在冒泡阶段返回到文档的各层。**冒泡**阶段允许我们通过其父元素在*任何*元素上处理事件。

让我们在实践中看看并稍微玩一下我们的事件。找到以下目录并在浏览器中打开`index.html` - [`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/events`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/events)：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e08b2b13-0d2c-475d-bc0e-6c5eccb8e965.png)

图 7.3 - 事件游乐场

如果我们看一下这个页面并玩几分钟，我们会看到一些东西：

+   右侧的*X*/*Y*坐标将随着我们在页面上移动鼠标而改变。

+   当我们打开控制台时，它将显示有关我们的点击事件以及发生在哪个*阶段*的消息。

让我们看看`index.js`中的代码，网址是[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/events/index.js`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/events/index.js)。

从 1 到 5 行，我们只是设置了一个数据对象，将数字代码映射到一个字符串。到目前为止，一切都很顺利。现在，让我们看看第 32 行，那里写着`document.querySelector('html').addEventListener('click', logClick, true)`。这个可选的布尔参数对我们来说是新的；当它放入事件监听器中时，它只是表示“让我在*捕获*阶段监听”。因此，当我们在页面的任何地方点击时，我们将得到一个点击事件，其中包含信息点击事件在 HTML 上的捕获阶段触发。这个事件之前在未定义处被处理，因为这是对这个事件的第一次遭遇。它还没有冒泡或被定位。

让我们在下一节继续剖析这个例子，了解代码中这些神秘的部分。

# 捕获事件并读取其属性

我们将继续使用我们的`events`游乐场代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/events/index.js`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/events/index.js)。

在 32-34 行，我们注册了三个点击事件监听器，如下所示：

```js
document.querySelector('html').addEventListener('click', logClick, true)
document.querySelector('body').addEventListener('click', logClick)
document.querySelector('button').addEventListener('click', logClick)
```

正如我们讨论过的，第一个事件监听在捕获阶段，因为我们包括了最后的布尔参数。

我们还有三个`mousemove`事件在 16-29 行。让我们看看其中一个：

```js
document.querySelector('button').addEventListener('mousemove', (e) => {
  document.querySelector('#x').value = e.x
  document.querySelector('#y').value = e.y
})
```

我希望大部分都是有意义的-我们正在使用一个新的事件类型`mousemove`，所以这个事件表示“当用户的鼠标移过按钮时，执行这段代码。”就是这么简单。我们要执行的代码是将 ID 为`x`和`y`的输入的值设置为*事件的 x 和 y 值*。这就是事件对象的魔力所在：它携带了*很多*信息。继续在这个函数内添加一行`console.log(e)`，看看记录了什么，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/999173f2-3fb6-47cb-a27d-b6404e7a26df.png)

图 7.4-记录事件

正如预期的那样，每当你的鼠标移动到“点击这里”上时，事件就会触发，并且鼠标事件被记录下来。打开其中一个事件。你会看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2fa91e96-485b-405b-a27b-d0b01e1dc530.png)

图 7.5-鼠标事件

在这里，我们看到了关于事件的大量信息，包括（如预期的那样）我们鼠标在那个时候的*X*和*Y*坐标。这些属性中的许多将会很有用，但特别要注意的是`target`。事件的目标是我们放置事件监听器的节点。从`target`属性中，我们可以得到它的 ID，如果我们有一个事件处理程序用于多个节点，这将会很有用。

你还记得我们在第六章中的便利贴程序，*文档对象模型（DOM）*吗？现在让我们来增强它。

## 重新审视便利贴

让我们从第六章中的便利贴程序*文档对象模型（DOM）*中更仔细地看一下：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/stickies/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/stickies/starter-code)，并包括创建模态窗口的能力，当点击时显示有关便利贴的信息，并能够删除该便利贴，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/0f8a836e-9704-4f27-9788-e787ab513906.png)

图 7.6-新的和改进的便利贴创建者

要成功编写这段代码，你需要使用一个新的 DOM 操作方法：`.remove()`。查看[`developer.mozilla.org/en-US/docs/Web/API/ChildNode/remove`](https://developer.mozilla.org/en-US/docs/Web/API/ChildNode/remove)获取文档。你可能还想看一下`visibility`的 CSS 属性来显示和隐藏模态窗口。

只是为了好玩，我还包括了一个小的 JavaScript 库，用于将颜色选择器用于便利贴颜色字段，作为包含第三方代码的简单示例。您不需要对`jscolor.js`脚本做任何操作；它将自动工作。

## 便利贴 - 解决方案 1

您是否得到了类似以下代码的东西？

```js
01: const container = document.querySelector('.container') // set 
    .container to a variable so we don't need to find it every time 
     we click
02: let noteCount = 1 // inital value
03: const messageBox = document.querySelector('#messageBox')
04: 
05: // access our button and assign a click handler
06: document.querySelector('.box-creator-button').addEventListener(
    'click', () => {
07:   // create our DOM element
08:   const stickyNote = document.createElement('div')
09: 
10:   // set our class name
11:   stickyNote.className = 'box'
12: 
13:   // get our other DOM elements
14:   const stickyMessage = document.querySelector('.box-color-note')
15:   const stickyColor = document.querySelector('.box-color-input')
16: 
17:   // get our variables
18:   const message = stickyMessage.value
19:   const color = stickyColor.style.backgroundColor
20: 
21:   // blank out the input fields
22:   stickyMessage.value = stickyColor.value = ''
23:   stickyColor.style.backgroundColor = '#fff'
24: 
25:   // define the attributes
26:   stickyNote.innerHTML = `${noteCount++}. ${message}`
27:   stickyNote.style.backgroundColor = color
28: 
29:   stickyNote.addEventListener('click', (e) => {
30:     document.querySelector('#color').innerHTML = 
        e.target.style.backgroundColor
31:     document.querySelector('#message').innerHTML = e.target.innerHTML
32: 
33:     messageBox.style.visibility = 'visible'
34: 
35:     document.querySelector('#delete').addEventListener('click', (event) => {
36:       messageBox.style.visibility = 'hidden'
37:       e.target.remove()
38:     })
39:   })
40: 
41:   // add the sticky
42:   container.appendChild(stickyNote)
43: })
44: 
45: document.querySelector('#close').addEventListener('click', (e) => {
46:   messageBox.style.visibility = 'hidden'
47: })
```

您可以在 GitHub 上找到这个代码文件：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/stickies/solution-code-1`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/stickies/solution-code-1)。

这里有一些有趣的部分，比如我们的便利贴单击处理程序从第 29 行开始。大部分内容应该看起来很熟悉，只是增加了一些新的内容。首先，单击处理程序使用事件的目标属性来使用目标的属性设置消息框中的文本。我们不必在 DOM 中搜索以查找我们的属性。事实上，当事件对象已经将信息传递给我们时，这样做将是昂贵和浪费的操作。第 33 行修改了模态窗口的 CSS 以显示它，第 37 行在模态的删除按钮被单击时删除了便利贴。

这个效果相当不错！但是，由于事件生命周期的特性，我们可以使用另一个事件的特性来使我们的代码更加高效：*事件委托*。

## 便利贴 - 解决方案 2 - 事件委托

**事件委托**的原则是在父事件上注册一个事件监听器，让事件传播告诉我们哪个元素被点击了。还记得我们的事件生命周期图和事件传播的层次吗？我们可以利用这一点。看一下第 37 行，如下所示：

```js
container.addEventListener('click', (e) => {
 if (e.target.className === 'box') {
   document.querySelector('#color').innerHTML = 
    e.target.style.backgroundColor
   document.querySelector('#message').innerHTML = e.target.innerHTML
   messageBox.style.visibility = 'visible'
   document.querySelector('#delete').addEventListener('click', (event) => {
     messageBox.style.visibility = 'hidden'
     e.target.remove()
   })
 }
})
```

您可以在 GitHub 上找到这段代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/stickies/solution-code-2/script.js#L37`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/stickies/solution-code-2/script.js#L37)。

在这段代码中，我们已经将点击监听器的附加从便利贴创建逻辑中移除，并将其抽象为附加到整个容器。当单击`container`时，我们检查目标是否具有`box`作为其类。如果是，我们执行我们的逻辑！这是事件监听器更有效的使用，特别是在动态创建的元素上使用时。有些情况下，事件委托将是您的最佳选择，有时任何一种都可以。

但现在我们有另一个问题：每次单击便利贴时，都会向删除按钮添加一个新的单击处理程序。这并不是很高效。看看是否可以重构代码以消除这个问题。

## 便利贴 - 解决方案 3

这是一个可能的解决方案：

```js
let target = {}

...

container.addEventListener('click', (e) => {
  if (e.target.className === 'box') {
    document.querySelector('#color').innerHTML = 
     e.target.style.backgroundColor
    document.querySelector('#message').innerHTML = e.target.innerHTML
    messageBox.style.visibility = 'visible'
    target = e.target
  }
})

document.querySelector('#delete').addEventListener('click', (event) => {
  messageBox.style.visibility = 'hidden'
  target.remove()
})
```

您可以在 GitHub 上找到这个解决方案：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/stickies/solution-code-3/script.js`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-7/stickies/solution-code-3/script.js)。

虽然这使用了一个全局变量，但它仍然更高效。通过将整个程序封装在一个函数或类中，我们可以消除全局变量，但这对于这个概念来说并不重要。

现在是时候看一下 Ajax 以及事件如何与程序的生命周期联系起来了。让我们做一个实验！

# 使用 Ajax 和事件来填充 API 数据

让我们把所有东西都放在一起。在这个实验中，我们将使用 PokéAPI 创建一个简化的宝可梦游戏：[`pokeapi.co/`](https://pokeapi.co/)。

这就是我们的游戏最终的样子：[`sleepy-anchorage-53323.herokuapp.com/`](https://sleepy-anchorage-53323.herokuapp.com/)。请打开网站并尝试一下功能。

请抵制诱惑，暂时不要查看已完成的 JavaScript 文件。

这是当您访问上述 URL 并开始玩游戏时会看到的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/67fb2064-b64e-41a5-9980-d9500f60521d.png)

图 7.7 – 宝可梦游戏

所有的 HTML 和 CSS 都已经为您提供。您将在`main.js`文件中工作：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/starter-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/starter-code)。

如果您不熟悉宝可梦，不用担心！这个游戏的逻辑很基本。（如果您熟悉这些游戏，请原谅这种简化的方法。）

这是我们将要做的事情：

1.  查询 PokéAPI 以获取所有可用的宝可梦。

1.  使用 API 提供的宝可梦名称和 API URL 的值填充选择列表。

1.  完成后，切换 CSS 属性以显示玩家的选择。

1.  允许每个玩家选择他们的宝可梦。

1.  为每个玩家创建功能，让他们使用自己宝可梦的招式对抗对方。

1.  根据从最大可能力量生成的随机数减少另一个玩家的宝可梦生命值。

1.  显示叠加文本，指出它是有效的。

1.  如果招式没有力量属性，显示叠加，表示它不起作用。

1.  当一个宝可梦的生命值为`0`或更低时，显示对手已经晕倒的叠加。

让我们逐步分解起始代码。

## 起始代码

让我们逐步看一下起始代码，因为它引入了我们的 JavaScript 的一个新的构造：类！如果您熟悉 Python 或其他语言中的类，这个 ES6 的介绍将是对 JavaScript 使用的一个受欢迎的提醒。让我们开始：

```js
class Poke {
  ...
}
```

首先，在 JavaScript ES6 中声明一个类时，我们只是创建一个对象！现在，对象的细节与我们习惯的有些不同，但许多原则是相同的。要创建类的实例，我们可以在完成类代码后说`const p = new Poke()`。

之后，有一些类的语法糖，比如构造函数、getter 和 setter。随意研究 JavaScript 中的类，因为它将帮助您实现整体目标。

我已经为您提供了构造函数的起始部分，当您创建一个类的实例时，它将被执行：

```js
constructor() {
    /**
      * Use the constructor as you would in other languages: Set up your 
        instance variables and globals
      */
  }
```

您的构造函数可能需要什么？也许您想要对经常使用的 DOM 元素或事件处理程序进行引用？然后，当然，问题就出现了：我们如何*引用*我们创建的变量？

答案是`this`。当使用一个全局变量到类时，您可以在`this.<variableName>`之前加上它，它将对所有方法可用。这里的好处是：它不是我们整个页面的纯全局变量，而只是我们类的全局变量！如果您回忆一下之前的一些代码示例，我们没有处理那一部分；这是一种处理的方法：

```js
choosePokemon(url, parent) {
…
const moves = data.moves.filter((move) => {
  const mymoves = move.version_group_details.filter((level) => {
    return level.level_learned_at === 1
  })
  return mymoves.length > 0
 })
}
```

由于每个宝可梦在游戏的不同阶段学习多个招式，这是在游戏开始时找到可用招式的逻辑。您不必修改它，但是看一下数组的`.filter()`方法。我们之前没有涉及它，但这是一个有用的方法。MDN 是一个很好的资源：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)。

我们感兴趣的代码的下一部分是**setter**：

```js
set hp(event) {
  ...
  if (event.hp) {
    this[event.player].hp = event.hp
  }

  if (event.damage) {
    this[event.player].hp -= event.damage
  }
  const e = new CustomEvent("hp", {
    detail: {
      player: event.player,
      hp: this[event.player].hp
    }
  })
  document.dispatchEvent(e)
}
```

**setter**是一个处理设置或更改成员变量的类方法。通常与**getter**一起使用，这个概念允许我们在更改（或检索）变量时抽象出所需的操作逻辑。在这种情况下，我们使用一些游戏逻辑来看待生命值。但是然后我们进入了一个新的、美妙的想法：自定义事件。

## 自定义事件

使用`new CustomEvent()`指令，我们可以创建一个新的命名事件在我们的程序中使用。有时，用户交互或页面行为并不能完全满足我们的需求。自定义事件可以帮助满足这种需求。请注意在前面的代码中，`detail`对象包含要传递的事件数据，我们使用`document.dispatchEvent()`将其发送到事件流中。创建自定义事件的事件监听器与使用内置事件一样：使用`.addEventListener()`。我们将要使用`doMove()`函数。

## 解决方案代码

您尝试得怎么样？您可以在这里看到解决实验室的一种可能方式：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code)。

记住，解决编程问题有多种方法，所以如果您的解决方案与提供的方法不匹配，也没关系！主要目的是解决问题。

# 处理异步性

正如我们在使用 API 时所看到的，Ajax 调用的异步性需要一些创造性的方法。在我们的宝可梦游戏中，我们在调用完成时使用了加载旋转器；这是您在现代网络上到处都能看到的方法。让我们看一个游戏中的例子：

```js
toggleLoader() {
  /**
    * As this is visual logic, here's the complete code for this function
    */
  if (this.loader.style.visibility === 'visible' || 
  this.loader.style.visibility === '') {
    this.loader.style.visibility = 'hidden'
  } else {
    this.loader.style.visibility = 'visible'
  }
}
```

*这*部分代码所做的只是切换包含旋转图像的图层的可见性。这都是在 CSS 中（因为它不是技术上的图像，而是 CSS 动画）。让我们看看它是如何使用的：

```js
getPokemon() {
    fetch('https://pokeapi.co/api/v2/pokemon?limit=1000')
      .then((response) => {
        return response.json()
      })
      .then((data) => {
        const pokeSelector = document.querySelector('.pokeSelector.main')

        data.results.forEach((poke) => {
          const option = document.createElement('option')
          option.value = poke.url
          option.innerHTML = poke.name
          pokeSelector.appendChild(option)
        })

        const selector = pokeSelector.cloneNode(true)
        document.querySelector('.pokeSelector.clone').replaceWith(selector)

        this.toggleLoader()

        document.querySelector('#Player1').style.visibility = 'visible'
        document.querySelector('#Player2').style.visibility = 'visible'
      })
  }
```

在这里，我们看到在我们的异步 Promise 调用中使用`.then()`时，当一切都完成时切换加载程序！这是一个很好的小捆绑。如果您想复习如何使用`fetch`和一般的 Ajax 调用，请回顾一下第四章，*数据和您的朋友，JSON*，在*来自前端的 API 调用 - Ajax*部分。

在处理 Ajax 调用固有的异步特性时，重要的是要记住我们不知道调用何时会返回其数据，甚至*是否*会返回！我们可以通过**错误处理**使我们的代码更好。

## 错误处理

看一下这段代码：

```js
fetch('/profile')
  .then(data => {
    if (data.status === 200) {
      return data.json()
    }
    throw new Error("Unable to get Profile.")
  })
  .then(json => {
    console.log(json)
  })
  .catch(error => {
    alert(error)
  })
```

我们在这里有一些常见的嫌疑人：一个`fetch`调用和`.then()`处理我们的结果。现在，看一下`new Error()`和`.catch()`。就像大多数语言一样，JavaScript 有一种明确抛出错误的方法，我们`fetch`链的末尾的`.catch()`将在警报框中向用户呈现错误。在您的 Ajax 调用中包含错误处理总是最佳实践，以防您调用的服务没有响应，没有及时响应或发送错误。我们将在第九章中更多地讨论错误，*解密错误消息和性能泄漏*。

## 星球大战 API 探索实验室

让我们通过一些 Ajax 调用来动手。我们将使用流行的**星球大战 API**（**SWAPI**）：[`swapi.dev/`](https://swapi.dev/)。花几分钟时间熟悉文档和 API 的工作原理。

这是我们将要构建的内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/5ad5025a-4894-47ce-8f0c-07af48682c27.png)

图 7.8 - 星球大战探索

您可以在[`packtpublishing.github.io/Hands-on-JavaScript-for-Python-Developers/chapter-7/swapi/solution-code/`](https://packtpublishing.github.io/Hands-on-JavaScript-for-Python-Developers/chapter-7/swapi/solution-code/)上尝试该功能的功能。在尝试重新创建功能之后，试着抵制浏览解决方案代码的诱惑。

我们的代码应该做到以下几点：

1.  在页面加载时显示加载程序。这个加载程序作为 CSS 动画为您提供。

1.  调用`/people` SWAPI 端点来检索 API 中的所有人。*提示：您需要多次调用 SWAPI 才能获取所有人。*

1.  用人们的名字填充选择列表并隐藏加载器。

1.  当点击 Go 时，再次调用 SWAPI 以检索有关所选人员的详细信息并显示它们（至少是姓名）。

我们的方法将首先填充列表，然后准备用户操作，以便探索同步链接事件和异步动作依赖于用户输入的情况。

起始 HTML 和 CSS 不应该需要更改，我们的起始 JavaScript 文件几乎是空的！您准备好挑战了吗？祝你好运！

### 一个解决方案

如果您查看解决方案代码，您会发现创建此功能的一种方法。让我们来分解一下。

就像在我们的宝可梦游戏中一样，我们将使用一个类。它的构造函数将存储一些各种信息，并添加一个事件侦听器到 Go 按钮：

```js
class SWAPI {
  constructor() {
    this.loader = document.querySelector('#loader')
    this.people = []

    document.querySelector('.go').addEventListener('click', (e) => {
      this.getPerson(document.querySelector('#peopleSelector').value)
    })
  }
```

接下来，我们知道我们将多次调用 SWAPI，我们可以创建一个帮助函数来简化这项工作。它可能需要四个参数：SWAPI API URL，先前结果的数组（如果我们正在分页的话很有用！），以及类似 Promise 的`resolve`和`reject`参数：

```js
  fetchThis(url, arr, resolve, reject) {
    fetch(url)
      .then((response) => {
        return response.json()
      })
      .then((data) => {
        arr = [...arr, ...data.results]
```

最后一行可能是新的。`…`是扩展运算符，它将数组展开为其各个部分。有了这个 ES6 功能，我们就不需要迭代数组来将其连接到另一个数组或进行任何其他重新分配的操作。我们可以简单地展开结果并将它们与现有结果连接起来：

```js
        if (data.next !== null) {
          this.fetchThis(data.next, arr, resolve, reject)
        } else {
          resolve(arr)
        }
```

在许多 API 中，如果数据集很大，只会返回有限的结果，并提供下一页和上一页数据的链接。 SWAPI 的命名规范指定`.next`是要查找的属性，如果有另一页的话。否则，我们可以在我们的`resolve`函数中返回我们的结果：

```js
      })
      .catch((err) => {
        console.log(err)
      })
```

不要忘记错误处理！

```js
  }

  getPeople() {
    new Promise((resolve, reject) => {
        this.fetchThis('https://swapi.dev/api/people', this.people, 
        resolve, reject)
      })
      .then((response) => {
        this.people = response
        const peopleSelector = document.querySelector('#peopleSelector')

        this.people.forEach((person) => {
          const option = document.createElement('option')
          option.value = person.url
          option.innerHTML = person.name
          peopleSelector.appendChild(option)
        })
        this.toggleLoader()
        document.querySelector('#people').style.visibility = 'visible'
      })
      .catch((err) => {
        console.log(err)
      })
  }
```

尝试完整阅读`getPeople()`，以了解它的功能。其中一些是简单的操作，但`new Promise()`是这个函数的核心。我们不是在我们的 API 人员列表上硬编码页数来迭代，而是创建一个使用我们的`fetchThis`函数的新 Promise：

```js
  getPerson(url) {
    this.toggleLoader()
    fetch(url)
      .then((response) => {
        return response.json()
      })
      .then((json) => {
        document.querySelector('#person').style.visibility = 'visible'
        document.querySelector('#person h2').innerHTML = json.name
        this.toggleLoader()
      })
      .catch((err) => {
        console.log(err)
      })
  }
```

理论上，一旦点击按钮，我们可以使用相同的`fetchThis`函数来获取单个人，但仅仅为了我们的示例，这个解决方案将所有内容都处理在一个地方：

```js
  toggleLoader() {
    if (this.loader.style.visibility === 'visible' ||
    this.loader.style.visibility === '') {
      this.loader.style.visibility = 'hidden'
    } else {
      this.loader.style.visibility = 'visible'
    }
  }
}
```

然后，我们只需要实例化我们的类！

```js
const s = new SWAPI().getPeople()
```

此时，我们的程序已经完成并且可以运行！访问页面，您将看到我们的完全运行的页面。帝国皇帝感谢您帮助消灭叛军。我们已经看到了类、基于事件的编程以及我们利用事件的能力。

# 摘要

我们已经了解了事件、它们的生命周期以及事件驱动设计的工作原理。**事件**是由用户的动作（或基于程序逻辑的程序化触发）而触发的，并进入其**生命周期**。在事件生命周期中，我们的程序可以捕获事件对象本身携带的许多信息，例如鼠标位置或目标 DOM 节点。

通过了解 Ajax 如何与事件配合工作，您已经在成为一个完全成熟的 JavaScript 开发人员的道路上迈出了重要的一步。**Ajax**非常重要，因为它是 JavaScript 和外部 API 之间的通道。由于 JavaScript 是无状态的，客户端 JavaScript 没有会话的概念，因此 Ajax 调用在性质上需要是**异步**的；因此引入了诸如`fetch`之类的工具。

恭喜！我们已经涵盖了很多非常密集的材料。接下来是 JavaScript 中的框架和库。

# 问题

回答以下问题以评估您对事件的理解：

1.  这些中哪一个是事件生命周期的第二阶段？

1.  捕获

1.  目标

1.  冒泡

1.  事件对象为我们提供了以下哪些内容？- 选择所有适用的：

1.  触发的事件类型

1.  目标 DOM 节点，如果适用的话

1.  鼠标坐标，如果适用的话

1.  父 DOM 节点，如果适用的话

看看这段代码：

```js
container.addEventListener('click', (e) => {
  if (e.target.className === 'box') {
    document.querySelector('#color').innerHTML = 
     e.target.style.backgroundColor
    document.querySelector('#message').innerHTML = e.target.innerHTML
    messageBox.style.visibility = 'visible'
    document.querySelector('#delete').addEventListener('click', (event) => {
      messageBox.style.visibility = 'hidden'
      e.target.remove()
    })
  }
})
```

1.  在上述代码中使用了哪些 JavaScript 特性？选择所有适用的：

1.  DOM 操作

1.  事件委托

1.  事件注册

1.  样式更改

1.  当容器被点击时会发生什么？

1.  `box` 将可见。

1.  `#color` 将是红色。

1.  1 和 2 都是。

1.  没有足够的上下文。

1.  在事件生命周期的哪个阶段我们通常采取行动？

1.  目标

1.  捕获

1.  冒泡

# 进一步阅读

+   *JavaScript: 理解 DOM 事件生命周期*: [`medium.com/prod-io/javascript-understanding-dom-event-life-cycle-49e1cf62b2ea`](https://medium.com/prod-io/javascript-understanding-dom-event-life-cycle-49e1cf62b2ea)

+   w3schools.com – JavaScript 事件: [`www.w3schools.com/js/js_events.asp`](https://www.w3schools.com/js/js_events.asp)

+   MDN – 事件参考: [`developer.mozilla.org/en-US/docs/Web/Events`](https://developer.mozilla.org/en-US/docs/Web/Events)


# 第八章：与框架和库一起工作

很少有语言存在于一个自包含的、整体的象牙塔中。几乎总是，特别是对于任何现代语言，程序中都会使用第三方代码来增加功能。使用第三方代码，比如库和框架，也是使用 JavaScript 的一个重要部分。让我们来看看我们工具包中一些更受欢迎的开源工具。

本章将涵盖以下主题：

+   jQuery

+   Angular

+   React 和 React Native

+   Vue.js

# 技术要求

准备好使用存储库的`Chapter-8`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8)。由于我们将使用命令行工具，还要准备好你的终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# jQuery

创建或使用 JavaScript 库的主要原因之一是为了简化重复或复杂的任务。毕竟，你不能通过插件或库从根本上*改变*一种语言——你所能做的只是增加或改变现有的功能。

正如我们在第一章中讨论的那样，*JavaScript 进入主流编程*，JavaScript 的早期历史有点像是一个荒野西部的情景。浏览器之间的战争正在全面展开，功能没有标准化，甚至发起一个 Ajax 调用都需要两套不同的代码：一套是为了 Internet Explorer，另一套是为了其他浏览器。

2006 年，由 John Resign 创建了 jQuery。

浏览器之间的标准化不足是创建 jQuery 的动力。从 DOM 操作到 Ajax 调用，jQuery 的语法和结构是一种“一次编写，所有浏览器使用”的范式。随着 ES6 及更高版本的开发，JavaScript*正在*变得更加标准化。然而，有超过十年的 jQuery 代码存在，大多数 JavaScript 重的网站都在使用。由于这些传统应用程序，它仍然非常受欢迎，因此对我们的讨论很重要。它也是开源的，因此使用它不需要许可费。

## jQuery 的优势

考虑以下例子，它们做了同样的事情：

+   **JavaScript ES6**: `document.querySelector("#main").classList.add`

`("red")`

+   **jQuery**: `$("#main").addClass("red");`

正如你所看到的，jQuery 的构造要简短得多。太好了！简洁的代码通常是一件好事。所以，让我们来分解这个例子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/7b3452fc-c3e8-4c49-80e3-05c835b167cc.png)

图 8.1 - jQuery 语法

1.  我们几乎所有的 jQuery 语句都是以`$`开头的。这是许多库中使用的一个惯例，实际上，你可以覆盖美元符号并使用任何你喜欢的东西，所以你可能会看到以`jQuery`开头的例子。

1.  我们的选择器是 CSS 选择器，就像我们在`document.querySelector()`中使用的一样。一个惯例是，如果你要存储通过 jQuery 选择的 DOM 节点以供以后使用，就用美元符号表示。所以，如果我们要将`#main`存储为一个变量，它可能看起来像这样：`const $main = $("#main")`。

1.  jQuery 有自己的一系列函数，通常是内部功能的可读性缩写。

关于 jQuery 的一个有趣的事实：你可以将 jQuery 与原生 JavaScript（即*不使用任何框架或库*）混合使用。事实上，“原生 JavaScript”这个术语是指非 jQuery 代码的一种常用方式。

此外，一些前端库，如 Bootstrap，在 Bootstrap 5 之前，是使用 jQuery 构建的，因此了解其用法可以帮助你了解其他库和框架。这并不是一个*坏*事，但在你探索前端开发的新世界时要注意这一点。

## jQuery 的缺点

使用 jQuery，就像使用任何库一样，需要在客户端上进行额外的下载。截至撰写本文时，jQuery 3.4.1 的压缩版本大小为 88 KB。尽管这在很大程度上可以忽略不计，并且将被浏览器缓存，但请记住，这必须在每个页面上执行和加载，因此不仅要考虑下载大小，还要考虑执行时间。Wes Bos 还有一些关于 ES6 和 jQuery 中作用域的很好的信息：[`wesbos.com/javascript-arrow-functions/`](https://wesbos.com/javascript-arrow-functions/)。

另外，虽然并非所有情况都是如此，但大部分 jQuery 的用法存在是为了标准化 ES5，所以你在网上和示例中看到的大部分代码都是 ES5。

## jQuery 的例子

让我们比较一下我们原始的星球大战探索第七章，“事件、事件驱动设计和 API”([`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/swapi`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/swapi))与 jQuery 版本([`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/swapi-jQuery`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/swapi-jQuery))。

现在，我承认这并不是最优雅的 jQuery 代码，但这样做是有原因的。让我们来分析一下。

首先是 HTML：

| **ES6** | **jQuery** |
| --- | --- |
| 无变化 | 添加`<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>` |

正如我们讨论过的，添加 JavaScript 库或框架本质上需要从本地文件下载另一个文件，并/或者需要额外的处理时间。通常，大小是可以忽略不计的，所以在这种情况下，唯一相关的因素是我们需要添加一行 HTML 来从全局内容传递网络加载 jQuery 文件。

CSS 不会有变化，这是预期的。所以让我们深入 JavaScript：

| **ES6** | **jQuery** |
| --- | --- |

|

```js
class SWAPI {
  constructor() {
    …
  }
}
```

|

```js
var swapi;

$(document).ready(function() {
  swapi = new SWAPI;
});
```

|

好了，现在我们看到了一些主要的区别。正如前面提到的，这并不一定是最理想的 jQuery 程序，但我认为它能传达出要点。首先，虽然 jQuery 和 ES6 是兼容的，但大多数情况下，jQuery 是在 ES6 不可用的地方使用的，或者代码尚未升级到 ES6。你会注意到大多数 jQuery 代码的第一件事是，在行尾使用分号，并使用`var`而不是`let`或`const`。这并不是 jQuery 独有的，而是 ES5 的约定。

ES5 通常使用对象原型的操作，而不是使用类，如下所示：

```js
SWAPI.prototype.constructor = function() {
  this.$loader = $('#loader');
  this.people = [];
};
```

类可以说是更干净的工作方式，因为它们在方法和用法上更加自包含和明确。然而，当 jQuery 流行时，这种约定还不存在，所以我们将使用 ES5 原型继承。

现在让我们一起看看使用 ES6 和 jQuery 进行 Ajax 调用的不同之处：

| **ES6** | **jQuery** |
| --- | --- |

|

```js
fetch(url)
  .then((response) => {
     return response.json()
  })
  .then((json) => {
    … 
  })
```

|

```js
$.get(url)
  .done(function(data) {
     …
  };
```

|

这是一个很好的例子，说明了为什么要使用 jQuery 以及它的创建如何促进了 ES6 的一些简化。在 ES5 中，进行 Ajax 请求需要两种不同的方法——一种是针对 Internet Explorer，另一种是针对其他浏览器——因为请求方法并没有标准化。jQuery 通过在幕后进行浏览器检测和代码切换来帮助开发人员，这样开发人员只需要编写一条语句。然而，使用`fetch`就不再需要这样做了。不过，我们可以看到 jQuery 代码稍微短一些，因为我们没有第一个`.then`函数来返回请求的 JSON。这是设计缺陷还是特性？实际上是后者，因为 API 可能返回许多不同类型的响应。`fetch`方法在幕后为您进行了一些转换，而 jQuery 则希望您基本上知道您的数据是什么以及如何处理它。

W3Schools 在 jQuery 上有很好的示例和参考资料：[`www.w3schools.com/jquery/`](https://www.w3schools.com/jquery/)。

如果您查看 jQuery 版本的其余代码，您会发现许多其他有趣的差异示例，但现在——从 jQuery 继续前进！让我们来看看一个完整的*web 框架*：Angular。

# Angular

Angular 由 Google 创建为*AngularJS*。在 2016 年，它被重写为版本 2，使其与 AngularJS 分离。它是开源的框架，而不是库，现在引发了一个问题：**框架**和**库**之间有什么区别？

*库*是一个工具包，用于更轻松地编写您的代码，用于不同的目的。使用建筑类比，库就像一套可以用来组装房子的砖头。相反，*框架*更类似于设计房子所使用的蓝图。它可能使用一些相同的砖头，也可能不使用！主要区别之一是，一般来说，库允许您按照自己想要的方式编写代码，而不会让库对如何构建代码的结构发表意见。另一方面，框架更具有意见，并要求您按照*该*框架的最佳实践来构建代码。这是一个模糊的（有时是过载的）术语，因此对于什么是库和什么是框架存在可以理解的争论。只需搜索*Stack Overflow*，您就会找到竞争性的定义。一个很好的简化陈述是，**框架**可以是一组具有指定使用模式的技术，而**库**更有可能是一种帮助操作数据的技术。

让我们考虑这个图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/fd9b66a9-b387-4586-99af-a7a15553517f.png)

图 8.2 - 框架组成

正如我们所看到的，框架实际上可以由多个库组成。框架的设计模式通常决定了这些库的使用方式和时间。

Angular 使用*TypeScript*，这是一种开源的编程语言。最初由微软开发，它是 JavaScript 的一个超集，具有一些额外的功能，对一些开发人员来说是吸引人的。尽管 TypeScript 被归类为自己的语言，但它是 JavaScript 的超集，因此可以转换为普通 JavaScript，因此在浏览器中运行时不需要额外的工作，除了执行 Angular 构建过程。

## Angular 的优势

Angular，像大多数框架一样，对您的文件结构和代码语法有自己的看法（特别是在混合使用 TypeScript 时）。这可能听起来像一个缺点，但实际上在团队合作中非常重要：您已经有了关于如何处理代码的现有文件结构，这是一件*好*事情。

Angular 也不是独立存在的。它是**技术栈**的一部分，这意味着它是一个从前端到数据库的一揽子解决方案。您可能已经遇到过**MEAN**技术栈这个术语：**MongoDB, Express, Angular, 和 Node.js**。虽然您可以在这个技术栈之外使用 Angular，但它提供了一个易于设置的开发生态系统，被他人广泛理解。

如果您对**Model-View-Controller**（**MVC**）范例不熟悉，现在是熟悉它的好时机。许多技术堆栈跨越多种语言利用这种范例来分离代码库中的关注点。例如，程序中的**模型**与数据源（如数据库和/或 API）的数据获取和操作进行交互，而**控制器**管理模型、数据源和**视图**层之间的交互。**视图**主要控制全栈环境中信息的视觉显示。在全栈 MVC 社区内存在争议，就方法而言，所谓的“模型臃肿，控制器瘦身”方法和相反的方法之间存在争论。现在不重要去讨论这种区别，但您会在社区中看到这种争论。

谈到社区，事实上 Angular 开发人员已经形成了一个临时网络，相互帮助。单单讨论就很有价值，可以帮助您在这个领域中导航。

Angular 还有一些其他优点，比如双向数据绑定（确保模型和视图相互通信）和绑定到 HTML 元素的专门指令，但这些都是现在不重要讨论的细微差别。

## Angular 的缺点

Angular 的主要缺点是其陡峭的学习曲线。除了原始的 AngularJS 和更现代的 Angular 迭代之间的差异之外，Angular 不幸地在开发人员中的流行度正在下降。此外，它*相当*冗长和复杂。根据一些 Angular 开发人员的说法，诸如使用第三方库之类的任务可能会重复。

使用 TypeScript 而不是标准的 ES6 也是一个值得关注的问题。虽然 TypeScript 很有用，但它增加了使用 Angular 的学习曲线。也就是说，Angular 确实非常灵活。

## Angular 的例子

让我们用 Angular 构建一个小的“Hello World”应用程序。我们需要一些工具来开始我们的工作，比如`npm`。参考第二章，*我们可以在服务器端使用 JavaScript 吗？当然可以！*，来安装`npm`及其相关工具。如果您愿意，您也可以按照提供的代码在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/angular-example`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/angular-example)进行操作。

以下是我们的步骤：

1.  首先安装 Angular CLI：`npm install -g @angular-cli`。

1.  使用`ng new example`创建一个新的示例项目。按照提示接受此安装的默认设置。

1.  进入刚刚创建的目录：`cd example`。

1.  启动服务器：`ng serve --open`。

此时，您的网络浏览器应该在`http://localhost:4200/`打开此页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/02598c51-13b8-48aa-929c-53bed1e9d762.png)

图 8.3 - 示例起始页面

好的。这看起来是一个足够简单的页面供我们使用。这是我们的 CLI 创建的文件结构：

```js
.
├── README.md
├── angular-cli.json
├── e2e
│   ├── app.e2e-spec.ts
│   ├── app.po.ts
│   └── tsconfig.json
├── karma.conf.js
├── package-lock.json
├── package.json
├── protractor.conf.js
├── src
│   ├── app
│   │   ├── app.component.css
│   │   ├── app.component.html
│   │   ├── app.component.spec.ts
│   │   ├── app.component.ts
│   │   └── app.module.ts
│   ├── assets
│   ├── environments
│   │   ├── environment.prod.ts
│   │   └── environment.ts
│   ├── favicon.ico
│   ├── index.html
│   ├── main.ts
│   ├── polyfills.ts
│   ├── styles.css
│   ├── test.ts
│   └── tsconfig.json
└── tslint.json
```

让我们看一下生成的代码。打开`src/index.html`。您会看到：

```js
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Example</title>
  <base href="/">

  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
</head>
<body>
  <app-root></app-root>
</body>
</html>
```

就是这样！您看，这只是 Angular 创建我们刚刚查看的页面的模板，然后 JavaScript 完成其余工作。如果您在浏览器中查看页面的源代码，您会看到非常相似的内容，只是有一些脚本调用。所有 JavaScript 都是一次性下载或可能被分块成用于协同使用的块。

## 单页应用程序

值得讨论的是什么是 SPA。我们之前已经提到过这个话题，但现在让我们来看看为什么 Angular（以及我们即将介绍的 React 和 Vue）如此受欢迎和引人注目。想象一个标准的基于 HTML 的网站。它可能有一个一致的页眉、页脚和样式。然而，一个标准的网站需要在每次导航到不同页面时下载（或从本地缓存中提供）这些资产（更不用说检索 HTML 并重新呈现它了）。SPA 通过将所有相关数据打包到一个统一的包中，然后传输到浏览器中来消除这种冗余。浏览器然后解析 JavaScript 并呈现它。结果是一个快速、流畅的体验，基本上消除了页面加载时间的延迟。你已经使用过这些了。如果你使用 Gmail 或大多数现代在线电子邮件系统，你可能已经注意到页面加载时间是可以忽略的，或者最坏的情况下有一个小的加载图标。页面加载时间和表面上浪费的资源和内容重新下载是 SPA 旨在处理的一个问题。

既然我们已经讨论了 SPA 如何帮助提高我们的效率，让我们来看看我们的 Angular 示例背后的 JavaScript。

## JavaScript

首先，让我们打开`src/app/app.component.html`，看看第 2 行：`{{ title }}!`。

嗯，这些花括号是什么？如果你熟悉其他模板语言，你可能会认出这是一个模板标记，旨在在呈现之前被我们的呈现语言替换。那么，替换它的方法是什么？

现在让我们看看`src/app/app.component.ts`：

```js
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'app works!';
}
```

我们可以看到模板引用了`app.component.html`，而我们的`AppComponent`类将`title`指定为`app works!`。这正是我们在浏览器中看到的。欢迎来到模板系统的强大之处！

现在，我们不会深入讨论 Angular 的 SPA 特性，但是请查看[`angular.io/tutorial`](https://angular.io/tutorial)上的 Angular 教程以获取更多详细信息。

现在，让我们继续我们的 React 之旅。

# React 和 React Native

React 最初是由 Facebook 的 Jordan Walke 于 2013 年创建的，迅速发展成为目前使用最广泛的用户界面库之一。与 Angular 相比，React 并不试图成为一个完整的框架，而是专注于 Web 工作流的特定部分。由于 Web 页面本质上是*无状态*的（也就是说，没有真正的信息从页面传递到页面），SPA 旨在将某些状态的片段存储在 JavaScript 内存中，从而使后续视图能够填充数据。React 是这种类型架构如何工作的一个典型例子，同时又不包含整个框架范式。在 MVC 术语中，React 处理视图层。

## React 的优势

由于 React *本身*只处理视图，它依赖于其他库来补充其功能集，比如 React Router 和 Hooks。也就是说，React 的基本架构被设计为模块化，并且有附加组件用于执行工作流的其他部分。目前，了解 React Router、Hooks 或 Redux 并不重要，但要知道 React 只是完整网站中的一个部分。

那么，为什么这是一个优势呢？与一些其他 JavaScript 工具（如 Angular）不同，React 并不试图用自己的规则、法规或语言结构重新发明轮子。它感觉就像你在基本的 JavaScript 中编码，因为在大多数情况下，你确实是！

React 的另一个优势是它如何处理组件和模板。组件只是可重用的代码片段，可以在程序中的多个位置使用不同的数据来填充视图。React 还在[`reactjs.org/tutorial/tutorial.html`](https://reactjs.org/tutorial/tutorial.html)上有一个很好的逐步教程。我们将在*React 示例*部分对此进行分析。现在，当然，我们需要讨论一下缺点。

## React 的缺点

坦率地说，React 的学习曲线（尤其是它的新姐妹技术，如 Redux 和 Hooks，简化了基于状态的管理）是陡峭的。然而，对于社区来说，这甚至不被认为是一个主要的缺点，因为几乎所有的库和框架都是如此。然而，一个主要的缺点是它的快速发展速度。现在，你可能会想：“但是一个不断发展的技术是好事”！这是一个好想法，但在实践中，这可能有点令人生畏，特别是在处理重大变化时。

一些开发人员的另一个不喜欢的地方是在 JavaScript 中混合 HTML 和 JavaScript。它使用一种语法扩展，允许在 JavaScript 中添加 HTML，称为 JSX。对于纯粹主义者来说，将表示层代码混合到逻辑结构中可能会显得陌生和构架反模式。再次强调，JSX 有一个学习曲线。

现在是时候看一个经典的 React 示例应用程序了：井字棋。

## React 示例

您可以按照逐步教程构建此应用程序，网址为[`reactjs.org/tutorial/tutorial.html`](https://reactjs.org/tutorial/tutorial.html)，为了方便使用，您可以使用这个 GitHub 目录 - [`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/react-tic-tac-toe`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/react-tic-tac-toe) - 完整的示例：

1.  克隆存储库并`cd`进入`react-tic-tac-toe`目录。

1.  执行`yarn start`。

不要对新的`yarn`命令感到惊讶。这是一个类似于`npm`的不同的包管理器。

1.  当`yarn start`完成后，它会为您提供一个类似于`http://localhost:3000/`的 URL。在浏览器中打开它。你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/b835bbd5-7d50-4e48-85b0-2cfa2d433f29.png)

图 8.4 - React 井字棋，开始

如果你不熟悉井字棋游戏，逻辑很简单。两名玩家轮流在 3x3 的网格中标记 X 或 O，直到一名玩家在横向、纵向或对角线上有三个标记。

让我们玩吧！如果你点击方框，你可能会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c72eaaa5-a451-4068-8d2c-56d9562eb12a.png)

图 8.5 - React 井字棋，可能的结束状态

请注意，示例还在屏幕右侧的按钮上保持状态历史。您可以通过单击按钮将播放倒带到这些状态中的任何一个。这是 React 如何使用**状态**来保持应用程序各部分的连续性的一个例子。

### 组件

为了说明可重用组件的概念，考虑一下井字棋网格的顶行代码。看一下`src/index.js`。

你应该在第 27 行看到这个：

```js
<div className="board-row">
  {this.renderSquare(0)}
  {this.renderSquare(1)}
  {this.renderSquare(2)}
</div>
```

`renderSquare`是一个相当简单的函数，它呈现 JavaScript XML，或**JSX**。如前所述，JSX 是 JavaScript 的扩展。它在标准 JavaScript 文件中引入了类似 XML 的功能，将 JavaScript 语法与一组 HTML 和 XML 结合起来构建我们一直在谈论的组件。它并不是自己的完全成熟的模板语言，但在某些方面，它实际上可能更强大。

这是`renderSquare`：

```js
renderSquare(i) {
  return (
    <Square
      value={this.props.squares[i]}
      onClick={() => this.props.onClick(i)}
    />
  );
}
```

到目前为止，一切都很好...看起来相当标准...除了一件事。什么是`Square`？那不是 HTML 标签！这就是 JSX 的威力：我们可以定义自己的可重用标签，就像我们一直在谈论的这些精彩的组件一样。把它们想象成我们可以用来组装自己应用程序的 LEGO®积木。从基本的构建块中，我们可以构建一个非常复杂的 SPA。

因此，`Square`只是一个返回标准 HTML 按钮的函数，具有一些属性，例如它的`onClick`处理程序。您可以在代码后面看到这个处理程序的作用：

```js
function Square(props) {
  return (
    <button className="square" onClick={props.onClick}>
      {props.value}
    </button>
  );
}
```

我们只是初步了解了 React，但我希望你已经感受到了它的强大。事实上，它有望成为生态系统中主导的前端框架。在撰写本文时，React 在技术世界的工作机会数量上远远超过了 Angular。

## React Native

谈论 React 而不提及 React Native 是不完整的。原生移动应用程序开发的一个困难之处在于，嗯，原生语言。Android 平台使用 Java，而 iOS 依赖 Swift 作为编程语言。我们不会在这里深入讨论移动开发（或 React Native），但重要的是要注意 React 和 React Native 之间存在重大差异。当我开始尝试 React 时，我以为组件在 React 和 React Native 之间是可重用的。在某种程度上，这是*轻微*正确的，但两者之间的差异超过了相似之处。

Native 的主要优势在于你不需要使用另一种语言；相反，你仍然在使用 JavaScript。话虽如此，Native 还存在额外的复杂性，特别是在处理移动设备的原生功能（如相机）时。因此，我建议您在项目生命周期中慎重考虑使用 React Native，并*不要*假设所有知识都可以从一个项目转移到另一个项目。

接下来，让我们讨论一下 JavaScript 世界的新成员：Vue.js。

# Vue.js

JavaScript 框架生态系统中的另一个新成员是 Vue.js（通常简称为 Vue）。由 Evan You 于 2014 年开发，这是另一个旨在为单页应用程序和用户界面提供高级功能的开源框架。Evan You 认为 Angular 中有值得保留的部分，但还有改进的空间。这是一个值得赞赏的目标！有人可能会说该项目成功做到了这一点，而其他人则认为其他项目更优秀。然而，本章的目标不是对任何技术进行评判，而是让您了解 JavaScript 的各种扩展，以使您的工作更轻松，并更符合现代标准。

与 React 不同，Vue 包含*路由*、*状态*和*构建工具*。它也有一个学习曲线，就像许多类似的技术一样，所以如果您选择探索 Vue，请确保给自己足够的空间和时间来学习。

我们将在官方指南的基本示例中研究 Vue 的基本示例[`vuejs.org/v2/guide/`](https://vuejs.org/v2/guide/)。如果你查看*声明性渲染*部分的课程，你会发现一个 Scrimba 课程。随意观看教程或从[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/vue-tutorial`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-8/vue-tutorial)访问代码，但以下是基础知识。

Vue 的 HTML 看起来与使用花括号标记进行内容替换的任何其他框架非常相似：

```js
<html>
   <head>
       <link rel="stylesheet" href="index.css">
       <script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
   </head>
   <body>

       <div id="app">
           {{ message }}
       </div>

       <script src="index.js"></script>
   </body>
</html>
```

值得注意的是，花括号语法可能会与其他模板系统（如 Mustache）发生冲突，但我们暂时将继续使用内置的 Vue 技术。

由于你有`{{ message }}`标记，让我们看看它的功能。

如果你查看`index.js`文件，你会发现它非常简单：

```js
var app = new Vue({ 
    el: '#app',
    data: {
        message: 'Hello Vue!'
    }
});
```

这种基本结构应该看起来很熟悉：它是一个带有对象作为参数的类的实例化。请注意，数据元素包含一个带有值`Hello Vue`的消息键。这是传递给视图层的`{{ message }}`，因此我们的应用程序呈现我们的消息：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/dbd93645-a1f0-44fc-b42b-7fb6f8b1598d.png)

图 8.6 - Vue 的“Hello World”示例

到目前为止，它的能力似乎与我们探索过的其他工具类似，所以让我们深入探讨其优缺点。

## Vue.js 的特点

由于 Vue 在实践中唯一的竞争对手是 React，也许将这个比较留给你来决定就足够了：[`vuejs.org/v2/guide/comparison.html`](https://vuejs.org/v2/guide/comparison.html)。然而，让我们以更客观的眼光来分析比较的一些要点，因为即使是比较的作者也承认它对 Vue 有偏见（这是可以预料的）：

+   性能：理想情况下，任何框架或库对应用程序的加载时间或实例化时间只会增加可忽略的时间，但实际情况却有所不同。我相信我们都记得多秒级的 Ajax 或 Flash（甚至是 Java servlet！）加载器的日子，但总的来说，这些延迟已经被异步、分步加载模式所缓解。现代 Web 技术的一个标志性细节应该是对用户体验的不显眼和渐进式增强。在这一点上，Vue 在增强用户体验方面做得非常出色。

+   HTML + JavaScript + CSS：Vue 允许技术的混合和匹配，它可以使用标准的 HTML、CSS 和 JavaScript 与 JSX 和 Vue 特定的语法相结合来构建应用程序。这是一个利弊参半的问题，但这是技术的事实。

+   Angular 的思想：与 React 拒绝几乎所有 Angular 约定不同，Vue 从 Angular 中借鉴了一些学习要点。这可能使它成为一个值得考虑的框架，适合想要离开 Angular 的人，尽管对这种方法的价值/效果尚未定论。

现在，让我们来看一个 Vue 的例子。

## Vue.js 示例

让我们使用 Vue CLI 创建一个示例项目：

1.  使用`npm install -g @vue/cli`安装 CLI。

1.  在新目录中执行`vue create vue-example`。对于我们的目的，你可以在每个提示处按*Enter*使用默认选项。

1.  进入目录：`cd vue-example`。

1.  使用`yarn serve`启动程序：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1d33161d-5c7b-4bbc-9880-0ad1eb76c6fb.png)

图 8.7 - Vue 生成器主页

Vue 的 CLI 生成器在`vue-example`目录中为我们创建了许多文件：

```js
.
├── README.md
├── babel.config.js
├── package.json
├── public
│ ├── favicon.ico
│ └── index.html
├── src
│ ├── App.vue
│ ├── assets
│ │ └── logo.png
│ ├── components
│ │ └── HelloWorld.vue
│ └── main.js
└── yarn.lock
```

让我们来看看它为我们创建的部分：

1.  打开`src/App.vue`。我们将在脚本块中看到这个：

```js
import HelloWorld from './components/HelloWorld.vue'

export default {
 name: 'app',
 components: {
   HelloWorld
 }
}
```

我们在浏览器中看不到任何链接，但`import`行告诉我们内容在哪里。

1.  打开`src/components/HelloWorld.vue`。现在，我们在`<template>`节点中看到了页面的内容。随意更改一些标记并尝试不同的变量。

这就是 Vue 的要点！你会发现在学习了 Angular 和 React 之后，Vue 中的概念是一个逻辑的进步，不难掌握。

# 总结

前端框架是强大的工具，但它们并不是可以互换的。每种框架都有其优缺点，你使用它们不仅应该受到当下流行的影响，还应该考虑到社区支持、性能考虑和项目的长期性。选择一个框架是一个需要仔细思考和规划的复杂过程。目前，React 在采用率上有相当大的增长，但随着时间的推移，所有的框架都会受到青睐和抛弃。我们在这里所涵盖的只是每个框架的冰山一角，所以在承诺之前一定要做好你的研究。

在下一章中，我们将探讨调试 JavaScript，因为让我们面对现实吧：我们会犯错误，我们需要知道如何修复它们。

# 进一步阅读

+   浏览器之战：[`en.wikipedia.org/wiki/Browser_wars`](https://en.wikipedia.org/wiki/Browser_wars)

+   jQuery：[`en.wikipedia.org/wiki/JQuery`](https://en.wikipedia.org/wiki/JQuery)

+   理解 ES6 箭头函数对于 jQuery 开发人员：[`wesbos.com/javascript-arrow-functions/`](https://wesbos.com/javascript-arrow-functions/)

+   jQuery 教程和参考：[`www.w3schools.com/jquery/`](https://www.w3schools.com/jquery/)

+   Angular 教程：[`angular.io/tutorial`](https://angular.io/tutorial)

+   React 生态系统导航：[`www.toptal.com/react/navigating-the-react-ecosystem`](https://www.toptal.com/react/navigating-the-react-ecosystem)

+   React 教程：[`reactjs.org/tutorial/tutorial.html`](https://reactjs.org/tutorial/tutorial.html)

+   Vue 指南：[`vuejs.org/v2/guide/`](https://vuejs.org/v2/guide/)

+   Vue 与其他框架的比较：[`vuejs.org/v2/guide/comparison.html`](https://vuejs.org/v2/guide/comparison.html)
