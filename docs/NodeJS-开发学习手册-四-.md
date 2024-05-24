# NodeJS 开发学习手册（四）

> 原文：[`zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF`](https://zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：异步编程中的 promises

在前两章中，我们学习了 Node 中许多重要的异步编程概念。本章是关于 promises 的。自 ES6 以来，JavaScript 中就有了 promises。尽管它们在第三方库中已经存在了相当长的时间，但它们最终进入了核心 JavaScript 语言，这很棒，因为它们是一个真正棒的特性。

在本章中，我们将学习 promise 的工作原理，开始了解它们为什么有用，以及它们为什么甚至存在于 JavaScript 中。我们将看一下一个叫做 axios 的库，它支持 promises。这将让我们简化我们的代码，轻松地创建我们的 promise 调用。我们实际上将在最后一节重新构建整个天气应用程序。

具体来说，我们将研究以下主题：

+   ES6 promises 简介

+   高级 promises

+   使用 promises 的天气应用程序

# ES6 promises 简介

Promises 旨在解决我们的应用程序中存在大量异步代码时出现的许多问题。它们使我们更容易管理我们的异步计算，比如从数据库请求数据。或者在天气应用程序的情况下，比如从 URL 获取数据。

在`app.js`文件中，我们使用回调做了类似的事情：

```js
const yargs = require('yargs');

const geocode = require('./geocode/geocode');
const weather = require('./weather/weather');

const argv = yargs
  .options({
    a: {
      demand: true,
      alias: 'address',
      describe: 'Address to fetch weather for',
      string: true
    }
  })
  .help()
  .alias('help', 'h')
  .argv;

geocode.geocodeAddress(argv.address, (errorMessage, results) => {
  if (errorMessage) {
    console.log(errorMessage);
  } else {
    console.log(results.address);
    weather.getWeather(results.latitude, results.longitude, (errorMessage, weatherResults) => {
      if (errorMessage) {
        console.log(errorMessage);
      } else {
        console.log(`It's currently ${weatherResults.temperature}. It feels like ${weatherResults.apparentTemperature}.`);
      }
    });
  }
});
```

在这段代码中，我们有两个回调：

+   传递给`geocodeAddress`的一个

+   传递给`getWeather`的一个

我们使用这个来管理我们的异步操作。在我们的情况下，这些操作包括从 API 获取数据，使用 HTTP 请求。在这个例子中，我们可以使用 promises 来使代码更加简洁。这正是本章的目标。

在本节中，我们将探讨 promise 的基本概念。我们暂时不会比较和对比回调和 promise，因为有很多微妙之处，不能在不知道 promise 如何工作的情况下描述。因此，在我们讨论它们为什么更好之前，我们将简单地创建一些。

# 创建一个例子 promise

在 Atom 中，我们将在`playground`文件夹中创建一个新文件，并将其命名为`promise.js`。在我们定义 promise 并讨论它们的工作原理之前，我们将通过一个简单的例子来运行，因为这是学习任何东西的最佳方式——通过一个例子并看到它是如何工作的。

首先，我们将通过一个非常基本的例子来开始。我们将坚持核心 promise 功能。

要开始这个非常简单的例子，我们将创建一个名为`somePromise`的变量。这将最终存储 promise 对象。我们将在这个变量上调用各种方法来处理 promise。我们将把`somePromise`变量设置为 promise 构造函数的返回结果。我们将使用`new`关键字创建 promise 的新实例。然后，我们将提供我们想要创建新实例的东西，`Promise`，如下所示：

```js
var somePromise = new Promise
```

现在这个`Promise`函数，实际上是一个函数——我们必须像调用函数一样调用它；也就是说，它需要一个参数。这个参数将是一个函数。我们将使用一个匿名箭头函数(`=>`)，在其中，我们将做所有我们想做的异步工作：

```js
var somePromise = new Promise(() => {

});
```

它将被抽象化，有点像我们在`geocode.js`文件的`geocodeAddress`函数中抽象化 HTTP 请求一样：

```js
const request = require('request');

var geocodeAddress = (address, callback) => {
  var encodedAddress = encodeURIComponent(address);

  request({
    url: `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`,
    json: true
  }, (error, response, body) => {
    if (error) {
      callback('Unable to connect to Google servers.');
    } else if (body.status === 'ZERO_RESULTS') {
      callback('Unable to find that address.');
    } else if (body.status === 'OK') {
      callback(undefined, {
        address: body.results[0].formatted_address,
        latitude: body.results[0].geometry.location.lat,
        longitude: body.results[0].geometry.location.lng
      });
    }
  });
};

module.exports.geocodeAddress = geocodeAddress;
```

`geocodeAddress`函数中的所有复杂逻辑确实需要发生，但`app.js`文件不需要担心它。`app.js`文件中的`geocode.geocodeAddress`函数有一个非常简单的`if`语句，检查是否有错误。如果有错误，我们将打印一条消息，如果没有，我们将继续。同样的情况也适用于 promises。

`new Promise`回调函数将使用两个参数`resolve`和`reject`调用：

```js
var somePromise = new Promise((resolve, reject) => {

});
```

这就是我们管理承诺状态的方式。当我们做出承诺时，我们正在做出承诺；我们在说，“嘿，我会去并且为你获取那个网站的数据。”现在这可能会顺利进行，这种情况下，你会`resolve`承诺，将其状态设置为实现。当一个承诺实现时，它已经出去并且做了你期望它做的事情。这可能是一个数据库请求，一个 HTTP 请求，或者完全不同的东西。

现在当你调用`reject`时，你是在说，“嘿，我们试图完成那件事，但我们就是无法。”所以承诺被认为是被拒绝的。这是你可以设置一个承诺的两种状态——实现或拒绝。就像在`geocode.js`中一样，如果事情顺利进行，我们要么为错误提供一个参数，要么为第二个参数提供一个参数。不过，承诺给了我们两个可以调用的函数。

现在，为了准确说明我们如何使用这些，我们将调用`resolve`。再次强调，这不是异步的。我们还没有做任何事情。所以所有这些都将在终端中实时发生。我们将使用一些数据调用`resolve`。在这种情况下，我将传入一个字符串`嘿。它起作用了！`如下所示：

```js
var somePromise = new Promise((resolve, reject) => {
     resolve('Hey. It worked!');
});
```

现在这个字符串就是承诺实现的价值。这正是某人会得到的。在应用文件中的`geocode.geocodeAddress`函数的情况下，它可能是数据，无论是结果还是错误消息。但在我们的情况下，我们使用`resolve`，所以这将是用户想要的实际数据。当事情顺利进行时，“嘿。它起作用了！”就是他们期望的。

现在你只能给`resolve`和`reject`传递一个参数，这意味着如果你想提供多个信息，我建议你解决或拒绝一个对象，你可以在上面设置多个属性。但在我们的情况下，一个简单的消息“嘿。它起作用了！”就可以了。

# 然后调用承诺方法

现在，为了在承诺被实现或拒绝时实际执行某些操作，我们需要调用一个名为`then`的承诺方法；`somePromise.then`。`then`方法让我们为成功和错误情况提供`回调`函数。这是回调和承诺之间的一个区别。在回调中，我们有一个无论如何都会触发的函数，参数让我们知道事情是否顺利进行。而在承诺中，我们将有两个函数，这将决定事情是否按计划进行。

现在在我们深入添加两个函数之前，让我们先从一个函数开始。在这里，我将调用`then`，传入一个函数。只有在承诺实现时，这个函数才会被调用。这意味着它按预期工作。当它这样做时，它将被调用并传递给`resolve`。在我们的情况下，它是一个简单的`message`，但在数据库请求的情况下，它可以是像用户对象这样的东西。不过，现在我们将坚持使用`message`：

```js
somePromise.then((message) => {

})
```

这将在屏幕上打印`message`。在回调中，当承诺得到实现时，我们将调用`console.log`，打印“成功”，然后作为第二个参数，我们将打印实际的`message`变量：

```js
somePromise.then((message) => {
  console.log('Success: ', message);
})
```

# 在终端中运行承诺示例

现在我们已经有了一个非常基本的承诺示例，让我们使用我们在上一章中安装的`nodemon`从终端运行它。我们将添加`nodemon`，然后进入`playground`文件夹，`/promise.js`。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1baa93e7-2dda-4403-af61-a5918704c603.png)

当我们立即这样做时，我们的应用程序运行并且我们获得成功。“嘿。它起作用了！”这是瞬间发生的。没有延迟，因为我们还没有异步地做任何事情。现在当我们首次探索回调时（参见第五章，*Node.js 中异步编程的基础*），我们使用`setTimeout`来模拟延迟，这正是我们在这种情况下要做的。

在我们的`somePromise`函数中，我们将调用`setTimeout`，传入两个参数：延迟后要调用的函数和以毫秒为单位的延迟。我将选择`2500`，即 2.5 秒：

```js
var somePromise = new Promise((resolve, reject) => {
 setTimeout(() => {

}, 2500);
```

现在在这 2.5 秒之后，然后，只有在这时，我们才希望`resolve`承诺。这意味着我们的函数，我们传递给`then`的函数将在 2.5 秒后才会被调用。因为，正如我们所知，这将在承诺解决之前不会被调用。我将保存文件，这将重新启动`nodemon`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3b7bd22e-6649-463f-b385-3764d2b41738.png)

在终端中，你可以看到我们有延迟，然后`success: Hey it worked!`打印到屏幕上。这 2.5 秒的延迟是由`setTimeout`引起的。延迟结束后（在这种情况下是人为延迟，但以后将是真正的延迟），我们能够用数据`resolve`。

# 承诺中的错误处理

现在有可能事情并不顺利。我们必须在 Node 应用程序中处理错误。在这种情况下，我们不会调用`resolve`，而是会调用`reject`。让我们注释掉`resolve`行，并创建第二行，在这一行中我们调用`reject`。我们将以与调用`resolve`相同的方式调用`reject`。我们必须传入一个参数，在这种情况下，一个简单的错误消息如`无法实现承诺`就可以了。

```js
var somePromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    // resolve('Hey. It worked!');
    reject('Unable to fulfill promise');
  }, 2500);
});
```

现在当我们调用`reject`时，我们告诉承诺它已被拒绝。这意味着我们尝试的事情并不顺利。目前，我们没有处理这一点的参数。正如我们提到的，这个函数只有在事情按预期进行时才会被调用，而不是在出现错误时。如果我保存文件并在终端中重新运行它，我们将得到一个拒绝的承诺：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a5925ae3-0b3a-4186-8be9-73ed7d094396.png)

然而，我们没有一个处理程序，所以什么都不会打印到屏幕上。这将是一个相当大的问题。我们需要对错误消息做些什么。也许我们会警告用户，或者我们会尝试一些其他代码。

如前面的代码输出所示，我们可以看到在重新启动和退出之间没有打印任何内容。为了处理错误，我们将在`then`方法中添加第二个参数。这个第二个参数让我们能够处理承诺中的错误。这个参数将被执行，并用该值调用。在这种情况下，它是我们的消息。我们将创建一个名为`errorMessage`的参数，如下所示：

```js
somePromise.then((message) => {
  console.log('Success: ', message);
}, (errorMessage) => {

});
```

在参数中，我们可以对其进行一些操作。在这种情况下，我们将使用`console.log`将其打印到屏幕上，打印带有冒号和空格的`Error`，然后是被拒绝的实际值：

```js
}, (errorMessage) => {
  console.log('Error: ', errorMessage);
});
```

现在我们已经有了这个，我们可以通过保存文件来刷新事情。现在我们将在终端中看到我们的错误消息，因为我们现在有一个可以做一些事情的地方：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6a3cb6c6-97d1-4630-8932-6e8a8bfaa198.png)

在这里，我们有一个地方可以将消息打印到屏幕上；`无法实现承诺`打印到屏幕上，这正如预期的那样。

# 承诺的优点

我们现在有一个可以被解决或拒绝的承诺。如果它被解决，意味着承诺已经实现，我们有一个处理它的函数。如果它被拒绝，我们也有一个处理它的函数。这是承诺很棒的原因之一。你可以根据承诺是否被解决或拒绝来提供不同的函数。这让你避免了在我们的代码中使用大量复杂的`if`语句，我们需要在`app.js`中管理实际回调是否成功或失败。

现在在承诺中，重要的是要理解你只能`resolve`或`reject`一次承诺。如果你`resolve`了一个承诺，你就不能在以后`reject`它，如果你用一个值`resolve`它，你就不能在以后改变主意。考虑这个例子，我有一个像下面这样的代码；在这里我首先`resolve`然后我`reject`：

```js
var somePromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve('Hey. It worked!');
    reject('Unable to fulfill promise');
  }, 2500);
});

somePromise.then((message) => {
  console.log('Success: ', message);
}, (errorMessage) => {
  console.log('Error: ', errorMessage);
});
```

在这种情况下，我们将看到我们的成功`message`打印到屏幕上。我们永远不会看到`errorMessage`，因为，正如我刚才说的，你只能执行其中一个操作一次。你只能一次`resolve`或一次`reject`。你不能两次都做；你不能两次做任何一种。 

这是回调的另一个巨大优势。没有什么能阻止我们意外地两次调用`callback`函数。例如，让我们考虑`geocode.js`文件。让我们在 geocode 请求调用的`if`块中添加另一行，如下所示：

```js
const request = require('request');

var geocodeAddress = (address, callback) => {
  var encodedAddress = encodeURIComponent(address);

  request({
    url: `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`,
    json: true
  }, (error, response, body) => {
    if (error) {
      callback('Unable to connect to Google servers.');
      callback();
```

这是一个更明显的例子，但它很容易隐藏在复杂的`if-else`语句中。在这种情况下，我们`app.js`中的`callback`函数确实会被调用两次，这可能会给我们的程序带来很大的问题。在 promise 示例中，无论你尝试多少次调用`resolve`或`reject`，这个函数只会被触发一次，这个回调永远不会被调用两次。

我们可以通过再次调用`resolve`来证明这一点。在 promise 示例中，让我们保存文件并进行以下更改：

```js
var somePromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve('Hey. It worked!');
    resolve();
    reject('Unable to fulfill promise');
  }, 2500);
});
```

现在，让我们刷新一下；我们将用我们的消息`Hey. It worked!`来`resolve`，我们永远不会再次触发函数，因为，正如我们所说的，promise 已经解决。一旦将 promise 的状态设置为已满足或已拒绝，就不能再次设置它。

在 promise 的`resolve`或`reject`函数被调用之前，promise 处于一种称为待定的状态。这意味着你正在等待信息返回，或者你正在等待异步计算完成。在我们的例子中，当我们等待天气数据返回时，promise 将被视为待定。当 promise 被满足或拒绝时，它被认为是已解决的。

无论你选择哪一个，你都可以说 promise 已经完成，这意味着它不再是待定的。在我们的例子中，这将是一个已完成的 promise，因为`resolve`就是在这里调用的。这些只是 promise 的一些好处。你不必担心回调被调用两次，你可以提供多个函数——一个用于成功处理，一个用于错误处理。这真的是一个很棒的工具！

现在我们已经快速介绍了 promise 的工作原理，只是基本原理，我们将转向稍微复杂一些的内容。

# 高级 promise

在本节中，我们将探讨使用 promise 的另外两种方法。我们将创建接受输入并返回 promise 的函数。此外，我们将探索 promise 链式调用，这将让我们组合多个 promise。

# 提供 promise 的输入

现在我们在上一节讨论的示例中的问题是，我们有一个 promise 函数，但它不接受任何输入。当我们使用真实世界的 promise 时，这很可能永远不会发生。我们将想要提供一些输入，比如从数据库中获取用户的 ID，请求的 URL，或者部分 URL，例如只有地址组件。

为了做到这一点，我们必须创建一个函数。在这个例子中，我们将创建一个名为`asyncAdd`的函数。

```js
var asyncAdd = () => {

}
```

这将是一个使用`setTimeout`模拟异步功能的函数。实际上，它只是将两个数字相加。但是，它将准确地说明我们需要在本章后面做的事情，以便使用 promise 来获取我们的天气应用程序。

现在在函数中，我们将使用`a`和`b`两个参数，并返回一个 promise：

```js
var asyncAdd = (a, b) => {

};
```

因此，无论谁调用这个`asyncAdd`方法，他们都可以传入输入，但他们也可以得到 promise，以便他们可以使用 then 来同步并等待它完成。在`asyncAdd`函数内部，我们将使用`return`来做到这一点。我们将使用完全相同的`new Promise`语法来`return`一个`new Promise`对象，就像我们创建`somePromise`变量时所做的那样。现在这是相同的函数，所以我们确实需要提供构造函数，该构造函数使用`resolve`和`reject`两个参数进行调用，就像这样：

```js
var asyncAdd = (a, b) => {
 return new Promise((resolve, reject) => {

 });
```

现在我们有一个`asyncAdd`函数，它接受两个数字并返回一个 promise。唯一剩下的事情就是实际模拟延迟，并调用`resolve`。为此，我们将使用`setTimeout`来模拟延迟。然后我们将传入我的`callback`函数，将延迟设置为 1.5 秒，或`1500`毫秒：

```js
return new Promise((resolve, reject) => {
 setTimeout(() => {

 }, 1500)
 });
```

在`callback`函数中，我们将编写一个简单的`if-else`语句，检查`a`和`b`的类型是否都是数字。如果是，太好了！我们将`resolve`这两个数字相加的值。如果它们不是数字（一个或多个），那么我们将`reject`。为此，我们将使用`if`语句和`typeof`运算符：

```js
setTimeout(() => {
  if (typeof a === 'number')
 }, 1500);
```

在这里，我们使用`typeof`对象来获取变量之前的字符串类型。此外，我们检查它是否等于一个数字，这是当我们有一个数字时`typeof`将返回的内容。现在类似于`a`，我们将添加`typeof b`，它也是一个数字：

```js
    if (typeof a === 'number' && typeof b === 'number') {}
```

我们可以将这两个数字相加，解析出值。在`if`语句的代码块内，我们将调用`resolve`，传入`a + b`：

```js
 return new Promise((resolve, reject) => {
   setTimeout(() => {
     if (typeof a === 'number' && typeof b === 'number') { 
       resolve(a + b);
     }
   }, 1500);
```

这将把这两个数字相加，传入一个参数给`resolve`。现在这是一个快乐的路径，当`a`和`b`都是数字时。如果事情不顺利，我们会想要添加`reject`。我们将使用`else`块来做这个。如果前面的条件失败，我们将通过调用`reject('Arguments must be numbers')`来`reject`：

```js
   if (typeof a === 'number' && typeof b === 'number') { 
     resolve(a + b);
   } else {
     reject('Argumets must be numbers');
   }
```

现在我们有一个`asyncAdd`函数，它接受两个变量`a`和`b`，返回一个 promise，任何调用`asyncAdd`的人都可以添加一个 then 调用到返回结果上，以获得该值。

# 返回 promise

现在这到底是什么样子？为了展示这一点，首先我们将注释掉`promise.js`中`newPromise`变量中的所有代码。接着，我们将调用`asyncAdd`变量，我们将调用`asyncAdd`。我们将像调用任何其他函数一样调用它，传入两个值。请记住，这可以是数据库 ID 或任何其他异步函数的内容。在我们的例子中，它只是两个数字。假设是`5`和`7`。现在这个函数的返回值是一个 promise。我们可以创建一个变量并在该变量上调用 then，但我们也可以直接使用`then`方法，如下所示：

```js
asyncAdd(5, 7).then
```

这正是我们在使用 promise 时要做的事情；我们将添加 then，传入我们的回调。第一个回调是成功的情况，第二个是错误的情况：

```js
ouldasyncAdd(5, 7).then(() => {
}, () => {

});
```

在第二个回调中，我们将得到我们的`errorMessage`，我们可以使用`console.log(errorMessage);`语句将其记录到屏幕上，如下所示：

```js
asyncAdd(5, 7).then(() => {

}, (errorMessage) => {
 console.log(errorMessage);
});
```

如果一个或多个数字实际上不是数字，`error`函数将会触发，因为我们调用了`reject`。如果两个都是数字，我们将得到结果并将其打印到屏幕上，使用`console.log`。我们将添加`res`并在箭头函数（`=>`）内部添加`console.log`语句，并打印带有冒号的字符串`Result`。然后，作为`console.log`的第二个参数，我们将传入实际的数字，这将打印到屏幕上： 

```js
asyncAdd(5, 7).then(() => {
 console.log('Result:', res);
}, (errorMessage) => {
 console.log(errorMessage);
});
```

现在我们已经在适当的位置有了我们的 promise `asyncAdd`函数，让我们在终端中测试一下。为此，我们将运行`nodemon`来启动`nodemon playground/promise.js`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2c8c4cc6-4777-4da8-89e2-6f18d6255ec9.png)

我们将立即得到延迟和结果，`12`打印到屏幕上。这太棒了！我们能够创建一个接受动态输入的函数，但仍然返回一个 promise。

现在请注意，我们已经将通常需要回调的异步函数包装成使用 promise 的形式。这是一个很方便的功能。当你开始在 Node 中使用 promise 时，你会意识到有些东西不支持 promise，而你希望它们支持。例如，我们用来进行 HTTP 请求的 request 库不支持原生的 promise。然而，我们可以将我们的请求调用包装在一个 promise 中，这是我们稍后将要做的。不过，现在我们有一个基本的例子说明了这是如何工作的。接下来，我们想谈谈 promise chaining。

# Promise chaining

Promise chaining 是指多个 promise 按顺序运行的概念。例如，我想要将地址转换为坐标，然后将这些坐标转换为天气信息；这是需要同步两件事情的一个例子。而且，我们可以很容易地使用 promise chaining 来做到这一点。

为了链接我们的 promise，在我们的成功调用中，我们将返回一个新的 promise。在我们的例子中，我们可以通过再次调用`asyncAdd`来`return`一个新的 promise。我将在`res`和`console.log`语句旁边调用`asyncAdd`，传入两个参数：结果，前一个 promise 返回的任何东西，以及某种新的数字；让我们使用`33`：

```js
asyncAdd(5, 7).then((res) => {
 console.log('Result:', res);
 return asyncAdd(res, 33);
```

现在我们返回了一个 promise，所以我们可以通过再次调用`then`方法来添加我的链式操作。`then`方法将在我们关闭前一个`then`方法的括号后被调用。这也将接受一个或多个参数。我们可以传入一个成功处理程序，它将是一个函数，以及一个错误处理程序，它也将是一个函数：

```js
 asyncAdd(5, 7).then((res) => {
   console.log('Result:', res);
   return asyncAdd(res, 33);
 }, (errorMessage) => {
   console.log(errorMessage);
 }).then(() => {

 }, () => {

 })
```

现在我们已经设置好了我们的`then`回调，我们可以填写它们。再一次，我们将得到一个结果；这将是`5`加`7`的结果，即`12`，再加`33`，将是`45`。然后，我们可以打印`console.log ('Should be 45')`。接下来，我们将打印结果变量的实际值：

```js
}).then((res) => {
 console.log('Should be 45', res);
}, () => {
});
```

现在我们的错误处理程序也将是一样的。我们将有`errorMessage`，并使用`console.log`将其打印到屏幕上，打印`errorMessage`：

```js
}).then((res) => {
 console.log('Should be 45', res);
}, (errorMessage) => {
 console.log(errorMessage);
});
```

现在我们有了一些链式操作。我们的第一个`then`回调函数将根据我们第一个`asyncAdd`调用的结果触发。如果顺利进行，第一个将触发。如果进行不顺利，第二个函数将触发。我们的第二个 then 调用将基于`asyncAdd`调用，我们在其中添加`33`。这将让我们将两个结果链接在一起，我们应该得到`45`打印在屏幕上。我们将保存这个文件，这将重新启动`nodemon`中的事情。最终，我们会得到我们的两个结果：`12`和我们的`Should be 45`。如下图所示，我们得到了`Result: 12`和`Should be 45`，打印在屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/51085c19-914c-45d4-9900-831e8209b8ea.png)

# promise 链中的错误处理

现在谈到错误处理时，有一些怪癖；所以，我们将模拟一些错误。首先，让我们模拟第二个`asyncAdd`调用中的错误。我们知道可以通过传入一个非数字的值来实现这一点。在这种情况下，让我们用引号括起`33`：

```js
 asyncAdd(5, 7).then((res) => {
   console.log('Result:', res);
   return asyncAdd(res, '33');
 }, (errorMessage) => {
   console.log(errorMessage);
 }).then((res) => {
   console.log('Should be 45', res);
 }, (errorMessage) => {
   concole.log(errorMessage);
 })
```

这将是一个字符串，我们的调用应该`reject`。现在我们可以保存文件并看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/07962445-c8f8-4784-8512-560de7bf4cec.png)

我们得到`Result: 12`，然后我们得到我们的错误，`Arguments must be numbers`。正如我们所期望的那样，这会打印在屏幕上。我们没有得到`Should be 45`，而是得到了我们的错误消息。

但是，当 promise 链中的早期某个东西被拒绝时，事情就会变得有点棘手。让我们用数字`33`替换`'33'`。然后让我们用字符串`'7'`替换`7`，如下所示：

```js
 asyncAdd(5, '7').then((res) => {
   console.log('Result:', res);
   return asyncAdd(res, 33);
 }, (errorMessage) => {
   console.log(errorMessage);
 }).then((res) => {
   console.log('Should be 45', res);
 }, (errorMessage) => {
   concole.log(errorMessage);
 })
```

这将导致我们的第一个 promise 失败，这意味着我们将永远看不到结果。我们应该看到错误消息打印在屏幕上，但这不会发生：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9144348b-9213-4f2b-89ff-9d3a09e6dff6.png)

当我们重新启动时，确实会将错误消息打印到屏幕上，但然后我们还会得到`Should be 45 undefined`。第二个`console.log`正在运行，因为我们在第二个`asyncAdd`函数中提供了一个错误处理程序。它正在运行错误处理程序。然后它说，*好的，现在事情一定很好，我们运行了错误处理程序。让我们继续进行下一个 then 调用，调用成功案例*。

# catch 方法

要修复错误，我们可以从两个`then`调用中删除我们的错误处理程序，并用一个调用替换它们，即在最底部调用一个不同的方法，我们将称之为`.catch`：

```js
asyncAdd(5, '7').then((res) => {
 console.log('Result:', res);
 return asyncAdd(res, 33);
}).then((res) => {
 console.log('Should be 45', res);
}).catch;
```

catch promise 方法类似于 then，但它只接受一个函数。如下面的代码所示，如果我们的任何 promise 调用失败，我们可以指定一个错误处理程序。我们将获取`errorMessage`并使用`console.log(errorMessage)`将其打印到屏幕上：

```js
asyncAdd(5, '7').then((res) => {
 console.log('Result:', res);
 return asyncAdd(res, 33);
}).then((res) => {
 console.log('Should be 45', res);
}).catch((errorMessage) => {
 console.log(errorMessage)
});
```

不过，如果现在有些模糊，没关系，只要你开始看到我们到底在做什么。我们正在将一个 promise 的结果传递给另一个 promise。在这种情况下，结果的工作方式与预期完全相同。第一个 promise 失败，我们得到了打印到屏幕上的`Arguments must be numbers`。此外，我们没有得到那个破碎的语句，我们尝试打印`45`，但我们得到了 undefined。使用 catch，我们可以指定一个错误处理程序，它将对我们之前的所有失败进行处理。这正是我们想要的。

# 承诺中的请求库

现在正如我之前提到的，有些库支持 promise，而另一些则不支持。请求库不支持 promise。我们将创建一个包装请求并返回 promise 的函数。我们将使用前一章中的`geocode.js`文件中的一些功能。

首先，让我们讨论一下快速设置，然后我们将实际填写它。在`playground`文件夹中，我们可以创建一个新文件来存储这个，名为`promise-2.js`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e237b240-cc2b-44e0-887a-52ae3eba14e2.png)

我们将创建一个名为`geocodeAddress`的函数。`geocodeAddress`函数将接受纯文本地址，并返回一个 promise：

```js
var geocodeAddress = (address) => {

};
```

`geocodeAddress`函数将返回一个 promise。因此，如果我传入一个邮政编码，比如`19146`，我会期望返回一个 promise，我可以附加一个`then`调用。这将让我等待该请求完成。在这里，我将添加一个调用`then`，传入我的两个函数：当 promise 被实现时的成功处理程序和当 promise 被拒绝时的错误处理程序：

```js
geocodeAddress('19146').then(() => {

}, () => {

})
```

现在当事情顺利进行时，我期望得到带有地址、`纬度`和`经度`的`location`对象，当事情进行不顺利时，我期望得到错误消息：

```js
geocodeAddress('19146').then((location) => {

}, (errorMessage) => {

})
```

当错误消息发生时，我们将只是使用`console.log(errorMessage)`将其打印到屏幕上。目前，当事情顺利进行并且成功案例运行时，我们将使用我们的漂亮打印技术，`console.log`打印整个对象。然后，我们将调用`JSON.stringify`，就像我们以前做过很多次一样，传入三个参数——对象，未定义的过滤方法——我们在书中永远不会使用，以及数字`2`作为我们想要用作缩进的空格数：

```js
geocodeAddress('19146').then((location) => {
 console.log(JSON.stringify(location, undefined, 2));
}, (errorMessage) => {
 console.log(errorMessage); 
});
```

这就是我们想要创建的功能正常工作的函数。这个`then`调用应该像前面的代码中显示的那样工作。

要开始，我将通过调用`return new Promise`返回 promise，传入我的构造函数：

```js
var geocodeAddress = (address) => {
 return new Promise(() => {

 });
};
```

在函数内部，我们将添加对请求的调用。让我们提供`resolve`和`reject`参数：

```js
 return new Promise((resolve, reject) => {
 });
};
```

现在我们已经设置好了我们的`Promise`，我们可以在代码顶部加载请求模块，创建一个名为`request`的常量，并将其设置为`require('request')`的返回结果：

```js
const request = require('request');

var geocodeAddress = (address) => {
```

接下来，我们将进入`geocode.js`文件，获取`geocodeAddress`函数内的代码，并将其移动到`promise-2`文件中的构造函数内：

```js
const request = require('request');
var geocodeAddress = (address) => {
 return new Promise((resolve, reject) => {
 var encodedAddress = encodeURIComponent(address);

request({
 url: `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`,
 json: true
 }, (error, response, body) => {
   if (error) {
   callback('Unable to connect to Google servers.');
 } else if (body.status === 'ZERO_RESULTS') {
   callback('Unable to find that address.');
 } else if (body.status === 'OK') {
   callback(undefined, {
     address: body.results[0].formatted_address,
     latitude: body.results[0].geometry.location.lat,
     longitude: body.results[0].geometry.location.lng
     });
    }
   });
 });
};
```

现在我们基本上可以开始了；我们只需要改变一些东西。我们需要做的第一件事是替换我们的错误处理程序。在代码的`if`块中，我们用一个参数调用了我们的`callback`处理程序；相反，我们将调用`reject`，因为如果这段代码运行，我们希望`reject`这个 promise。在下一个`else`块中也是一样的。如果我们得到了`ZERO_RESULTS`，我们将调用`reject`。这确实是一个失败，我们不想假装我们成功了：

```js
if (error) {
   reject('Unable to connect to Google servers.');
 } else if (body.status === 'ZERO_RESULTS') {
   reject('Unable to find that address.');
```

现在在下一个`else`块中，事情进展顺利；在这里我们可以调用`resolve`。此外，我们可以删除第一个参数，因为我们知道`resolve`和`reject`只接受一个参数：

```js
if (error) { 
  reject('Unable to connect to Google servers.');
 } else if (body.status === 'ZERO_RESULTS') {
   reject('Unable to find that address.');
 } else if (body.status === 'OK') {
   resolve(
```

我们可以指定多个值，因为我们在对象上`resolve`了属性。既然我们已经做到了这一点，我们就完成了。我们可以保存我们的文件，重新在终端中运行它，然后测试一下。

# 测试请求库

为了测试，我们将保存文件，进入终端，关闭`promise.js`文件的`nodemon`。我们将运行`promise.js`文件的`node`。它在`playground`文件夹中，名为`promise-2.js`：

```js
node playground/promise-2.js
```

现在，当我们运行这个程序时，我们实际上正在发出 HTTP 请求。如下面的代码输出所示，我们可以看到数据返回的确如我们所期望的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1fa26c34-7594-4433-ac64-700af003a6eb.png)

我们得到了我们的`address`、`latitude`和`longitude`变量。这太棒了！现在让我们测试一下，当我们传入一个无效的地址时会发生什么，比如 5 个零，这是我们以前用来模拟错误的：

```js
const request = require('request');

var geocodeAddress = (address) => {
  return new Promise((resolve, reject) => {
    var encodedAddress = encodeURIComponent(address);

  request({
   url: `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`,
   json: true
 }, (error, response, body) => {
   if (error) {
     reject('Unable to connect to Google servers.');
   } else if (body.status === 'ZERO_RESULTS') {
     reject('Unable to find that address.');
   } else if (body.status === 'OK') {
     resolve({
       address: body.results[0].formatted_address,
       latitude: body.results[0].geometry.location.lat,
       longitude: body.results[0].geometry.location.lng
      });
     }
   });
  });
};
```

我们将保存文件，重新运行程序，屏幕上打印出`无法找到该地址。`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/dd136fb7-56f6-4180-8d82-fb50a1c5e611.png)

这仅仅是因为我们调用了`reject`。我们将在`Promise`构造函数中调用`reject`。我们有我们的错误处理程序，它将消息打印到屏幕上。这是一个将不支持 promise 的库包装成 promise 的示例，创建一个准备好的 promise 函数。在我们的情况下，该函数是`geocodeAddress`。

# 带有 promise 的天气应用程序

在本节中，我们将学习如何使用内置 promise 的库。我们将探索 axios 库，它与 request 非常相似。不过，它使用 promise 而不是像 request 那样使用回调。因此，我们不必将我们的调用包装在 promise 中以获得 promise 功能。我们实际上将在本节中重新创建整个天气应用程序。我们只需要编写大约 25 行代码。我们将完成整个过程：获取地址、获取坐标，然后获取天气。

# 从 app.js 文件中获取天气应用程序代码

要从 app.js 文件中获取天气应用程序代码，我们将复制`app.js`，因为我们在原始的`app.js`文件中配置了`yargs`，我们希望将代码转移到新项目中。没有必要重写它。在`weather`目录中，我们将复制`app.js`，给它一个新的名字，`app-promise.js`。

在`app-promise.js`中，在我们添加任何内容之前，让我们先删除一些东西。我们将删除`geocode`和`weather`变量声明。我们将不需要引入任何文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d3bb21f5-b5b1-4c6a-a140-4ff58de97564.png)

然后我将删除我们`yargs`配置之后的所有内容，这种情况下只有我们对`geocodeAddress`的调用。结果代码将如下所示：

```js
const yargs = require('yargs');

const argv = yargs
 .options({
   a: {
     demand: true,
     alias: 'address',
     describe: 'Address to fetch weather for',
     string: true
   }
 })
 .help()
 .alias('help', 'h')
 .argv;
```

# Axios 文档

现在我们有了一个干净的板子，我们可以开始安装新的库。在运行`npm install`命令之前，我们将看看在哪里可以找到文档。我们可以通过访问以下网址获取：[`www.npmjs.com/package/axios`](https://www.npmjs.com/package/axios)。如下面的截图所示，我们有 axios npm 库页面，我们可以查看有关它的各种信息，包括文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a1b15161-a362-4fa5-a931-7c7d8f79ad9f.png)

在这里我们可以看到一些看起来很熟悉的东西。我们调用了`then`和`catch`，就像我们在 axios 之外使用 promise 时一样。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c120402b-5698-4ec0-8c0a-7b838ad882ac.png)

在这个页面的统计栏中，你可以看到这是一个非常受欢迎的库。最新版本是 0.13.1。这正是我们将要使用的确切版本。当你在项目中使用 axios 时，可以随时访问这个页面。这里有很多非常好的例子和文档。不过，现在我们可以安装它。

# 安装 axios

要安装 axios，在终端中，我们将运行`npm install`；库的名称是`axios`，我们将使用`save`标志指定版本`0.17.1`来更新`package.json`文件。现在我可以运行`install`命令，来安装 axios：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7b94abf0-4c96-4509-b51d-4076e50445e2.png)

# 在`app-promise`文件中进行调用

在我们的`app-promise`文件中，我们可以通过在顶部加载`axios`来开始。我们将创建一个常量叫做`axios`，将其设置为`require('axios')`，如下所示：

```js
const yargs = require('yargs');
const axios = require('axios');
```

既然我们已经准备就绪，我们实际上可以开始在代码中进行调用了。这将涉及我们从地理编码和天气文件中提取一些功能。因此，我们将打开`geocode.js`和`weather.js`文件。因为我们将从这些文件中提取一些代码，比如 URL 和一些错误处理技术。尽管我们会在遇到时讨论它们的不同之处。

我们需要做的第一件事是对地址进行编码并获取地理编码 URL。现在这些操作发生在`geocode.js`中。因此，我们实际上会复制`encodedAddress`变量行，即我们创建编码地址的行，并将其粘贴到`app-promise`文件中，跟在`argv`变量后面。

```js
  .argv;

var encodedAddress = encodeURIComponent(argv.address);
```

现在我们需要稍微调整一下这个。`address`变量不存在；但是我们有`argv.address`。因此，我们将`address`替换为`argv.address`：

```js
var encodeAddress = encodeURIComponent(argv.address);
```

现在我们有了编码后的地址；在我们开始使用 axios 之前，我们需要获取的下一件事是我们想要发出请求的 URL。我们将从`geocode.js`文件中获取。在`app-promise.js`中，我们将创建一个名为`geocodeURI`的新变量。然后，我们将从`geocode.js`中获取 URL，从开头的反引号到结束的反引号，复制并粘贴到`app-promise.js`中，赋值给`geocodeURI`：

```js
var encodedAddress = encodeURIComponent(argv.address);
var geocodeUrl = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`;
```

现在我们在 URL 中使用了编码的`address`变量；这没问题，因为它确实存在于我们的代码中。因此，在这一点上，我们有了我们的`geocodeUrl`变量，我们可以开始制作我们的第一个 axios 请求了。

# 发出 axios 请求

在我们的情况下，我们将获取地址并获取`纬度`和`经度`。为了发出请求，我们将调用 axios 上可用的一个方法，`axios.get`。

```js
var geocodeUrl = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodedAddress}`;

axios.get
```

`get`是让我们发出 HTTP get 请求的方法，这正是我们在这种情况下想要做的。而且，设置起来非常简单。当你期望 JSON 数据时，你所要做的就是传入`geocodeUrl`变量中的 URL。无需提供任何其他选项，比如让它知道它是`JSON`的选项。axios 知道如何自动解析我们的 JSON 数据。`get`返回的实际上是一个 promise，这意味着我们可以使用`.then`来在 promise 被实现或被拒绝时运行一些代码，无论事情进行得好还是糟：

```js
axios.get(geocodeUrl).then()
```

在`then`中，我们将提供一个函数。这将是成功的情况。成功的情况将被调用一个参数，`axios`库建议你将其称为`response`：

```js
axios.get(geocodeUrl).then((response) => {

});
```

从技术上讲，我们可以随意调用任何你喜欢的东西。现在在函数内部，我们将获得与我们在请求库内部获得的所有相同的信息；诸如我们的头部、响应和请求头部，以及正文信息；各种有用的信息。不过，我们真正需要的是`response.data`属性。我们将使用`console.log`打印出来。

```js
axios.get(geocodeUrl).then((response) => {
  console.log(response.data);
});
```

现在我们已经做好了准备，我们可以运行我们的`app-promise`文件，传入一个有效的地址。此外，我们可以看看当我们发出请求时会发生什么。

在命令行（终端）中，我们将首先使用`clear`命令清除终端输出。然后我们可以运行`node``app-promise.js`，传入一个地址。让我们使用一个有效的地址，例如`1301 lombard street, philadelphia`：

```js
node app-promise.js -a '1301 lombard street philadelphia
```

请求发出。我们得到了什么？我们得到了与我们在前几章中使用其他模块时看到的结果对象完全相同的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b9b590ca-3f30-4583-9aa6-d9bad585323b.png)

这种情况下唯一的区别是我们使用了内置的 promises，而不是必须将其包装在 promises 中或使用回调。

# axios 请求中的错误处理

现在除了我们在上一个示例中使用的成功处理程序之外，我们还可以添加一个调用 catch 的调用，让我们捕获可能发生的所有错误。我们将获得错误对象作为唯一的参数；然后我们可以对该错误对象进行处理：

```js
axios.get(geocodeUrl).then((response) => {
 console.log(response.data);
});catch((e) => {

});
```

在函数内部，我们将使用`console.log`来启动事情，打印错误参数：

```js
}).catch((e) => {
 console.log(e)
});
```

现在让我们通过删除 URL 中的点来模拟错误：

```js
var encodedAddress = encodeURIComponent(argv.address);
var geocodeUrl = `https://mapsgoogleapis.com/maps/api/geocode/json?address=${encodedAddress}`;

axios.get(geocodeUrl).then((response) => {
   console.log(response.data);
}).catch((e) => {
   console.log(e)
});
```

我们可以看看当我们重新运行程序时会发生什么。现在我这样做是为了探索`axios`库。我知道会发生什么。这不是我这样做的原因。我这样做是为了向你展示你应该如何处理新的库。当你得到一个新的库时，你想玩弄它的所有不同工作方式。当我们有一个请求失败时，错误参数中究竟会返回什么？这是重要的信息；所以当你编写一个真实的应用程序时，你可以添加适当的错误处理代码。 

在这种情况下，如果我们重新运行完全相同的命令，我们将收到一个错误：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8b892515-a390-41a9-84d2-56b558906ea9.png)

正如你所看到的，屏幕上真的没有什么可打印的。我们有很多非常神秘的错误代码，甚至`errorMessage`属性，通常包含一些好的内容或者没有。然后我们有一个错误代码，后面跟着 URL。相反，我们希望打印一个纯文本的英文消息。

为此，我们将使用一个`if-else`语句，检查代码属性是什么。这是错误代码，在这种情况下是`ENOTFOUND`；我们知道这意味着它无法连接到服务器。在`app-promise.js`中，在错误处理程序内部，我们可以通过使用`if`来添加这个条件：

```js
}).catch((e) => {
 if (e.code === 'ENOTFOUND') {

}
```

如果是这种情况，我们将使用`console.log`在屏幕上打印某种自定义消息：

```js
}).catch((e) => {
  if (e.code === 'ENOTFOUND') {
   console.log('Unable to connect to API servers.');
  } 
  console.log(e);
 });
```

现在我们有了一个处理这种特定情况的错误处理程序。所以我们可以删除我们对`console.log`的调用：

```js
axios.get(geocodeUrl).then((response) => {
  console.log(response.data);
}).catch((e) => {
  if (e.code === 'ENOTFOUND') {
    console.log('Unable to connect to API servers.');
 }
});
```

现在，如果我们保存文件，并从终端重新运行事情，我们应该会得到一个更好的错误消息打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/53f9b560-267b-411e-a2d1-6615e4267ddf.png)

这正是我们得到的：“无法连接到 API 服务器”。现在我会把那个点加回去，这样事情就开始运作了。我们可以担心返回的响应。

# ZERO_RESULT 状态的错误处理

你记得，在 geocode 文件中，有一些事情我们需要做。我们已经处理了与服务器连接相关的错误，但还有另一个待处理的错误，即，如果`body.status`属性等于`ZERO_RESULTS`。在这种情况下，我们想打印一个错误消息。

为此，我们将在`app-promise`中创建我们自己的错误。我们将在`axios.get`函数中抛出一个错误。这个错误将导致它之后的所有代码都不会运行。它将直接进入错误处理程序。

现在我们只想在 status 属性设置为`ZERO_RESULTS`时抛出错误。我们将在`get`函数的顶部添加一个`if`语句来检查“if（response.data.status）”是否等于`ZERO_RESULTS`：

```js
axios.get(geocodeUrl).then((response) => {
  if (response.data.status === 'ZERO_RESULTS') {

  }
```

如果是这种情况，那么事情就变糟了，我们不想继续进行天气请求。我们想运行我们的 catch 代码。为了抛出一个新的错误，让我们的 promise 可以捕获，我们将使用一个称为`throw new Error`的语法。这将创建并抛出一个错误，让 Node 知道出了问题。我们可以提供我们自己的错误消息，对用户来说是可读的：`无法找到该地址`：

```js
axios.get(geocodeUrl).then((response) => {
  if (response.data.status === 'ZERO_RESULTS') {
    throw new Error('Unable to find that address.');
  }
```

这是一个消息，将让用户准确地知道出了什么问题。现在当这个错误被抛出时，相同的 catch 代码将运行。目前，我们只有一个`if`条件，检查代码属性是否为`ENOTFOUND`。所以我们将添加一个`else`子句：

```js
axios.get(geocodeUrl).then((response) => {
 if (response.data.status === 'ZERO_RESULTS') {
   throw new Error('Unable to find that address.');
 }

 console.log(response.data);
}).catch((e) => {
 if (e.code === 'ENOTFOUND') {
   console.log('Unable to connect to API servers.');
 } else {

 }
});
```

在`else`块中，我们可以打印错误消息，这是我们使用`e.`消息属性在 throw `new Error`语法中键入的字符串，如下所示：

```js
axios.get(geocodeUrl).then((response) => {
 if (response.data.status === 'ZERO_RESULTS') {
   throw new Error('Unable to find that address.');
 }

 console.log(response.data);
}).catch((e) => {
  if (e.code === 'ENOTFOUND') {
   console.log('Unable to connect to API servers.');
 } else {
   console.log(e.message);
 }
});
```

如果错误代码不是`ENOTFOUND`，我们将简单地将消息打印到屏幕上。如果我们得到零结果，就会发生这种情况。所以让我们模拟一下，以确保代码能正常工作。在终端中，我们将重新运行之前的命令，传入一个邮政编码。起初，我们将使用一个有效的邮政编码`08822`，我们应该得到我们的数据。然后我们将使用一个无效的邮政编码：`00000`。

当我们用有效地址运行请求时，我们得到这个：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c125c1ba-ce47-4adb-9d2f-6f996c2bf381.png)

当我们用无效的地址运行请求时，我们得到了错误：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3acd268c-c83b-486e-98a9-87c2e2ad37eb.png)

通过调用`throw new Error`，我们立即停止了这个函数的执行。所以`console.log`与`e.message`永远不会打印，这正是我们想要的。现在我们的错误处理程序已经就位，我们可以开始生成天气 URL 了。

# 生成天气 URL

为了生成天气 URL，我们将从`weather`文件中复制 URL，将其带有引号的部分放入`app-promise`文件中。我们将创建一个名为`weatherUrl`的新变量，将其设置为复制的 URL：

```js
url: `https://api.forecast.io/forecast/4a04d1c42fd9d32c97a2c291a32d5e2d/${lat},${lng}`,
```

现在`weatherUrl`确实需要一些信息。我们需要`纬度`和`经度`。我们有两个变量`lat`和`lng`，所以让我们创建它们，从响应对象中获取适当的值，`var lat`和`var lng`：

```js
var lat;
var lng;
url: `https://api.forecast.io/forecast/4a04d1c42fd9d32c97a2c291a32d5e2d/${lat},${lng}`,
```

现在，为了取出它们，我们必须经历挖掘对象的过程。我们以前做过。我们将在响应对象的数据属性中查找，这类似于请求库中的 body。然后我们将进入`results`，获取第一个项目并访问`geometry`属性，然后我们将访问`location.lat`：

```js
var lat = response.data.results[0].geometry.location.lat;
```

现在同样，我们可以为`longitude`变量添加内容：

```js
var lat = response.data.results[0].geometry.location.lat;
var lng = response.data.results[0].geometry.location.lng;
```

现在，在我们发出天气请求之前，我们要打印格式化的地址，因为之前的应用程序也这样做了。在我们的`console.log(response.data)`语句中，我们将进入数据对象获取格式化的地址。这也是在结果数组的第一项上。我们将访问`formatted_address`属性：

```js
var lat = response.data.results[0].geometry.location.lat;
var lng = response.data.results[0].geometry.location.lng;
var weatherUrl = `https://api.forecast.io/forecast/4a04d1c42fd9d32c97a2c291a32d5e2d/${lat},${lng}`;
console.log(response.data.results[0].formatted_address);
```

现在我们的格式化地址已经打印到屏幕上，我们可以通过返回一个新的 promise 来进行第二次调用。这将让我们链接这些调用在一起。

# 链接承诺调用

要开始，我们将返回一个调用`axios.get`，传入 URL。我们刚刚定义了它，它是`weatherUrl`：

```js
 var lat = response.data.results[0].geometry.location.lat;
 var lng = response.data.results[0].geometry.location.lng;
 var weatherUrl = `https://api.forecast.io/forecast/4a04d1c42fd9d32c97a2c291a32d5e2d/${lat},${lng}`;
 console.log(response.data.results[0].formatted_address);
 return axios.get(weatherUrl);
```

现在我们有了这个调用返回，我们可以在之前的`then`调用和 catch 调用之间再添加一个`then`调用，通过调用 then，传递一个函数，就像这样：

```js
 return axios.get(weatherUrl);
}).then(() => {

}).catch((e) => {
 if (e.code === 'ENOTFOUND') {
```

当天气数据返回时，将调用此函数。我们将得到相同的响应参数，因为我们使用相同的方法`axios.get`：

```js
}).then((response) => {
```

在`then`调用中，我们不必担心抛出任何错误，因为我们从未需要访问 body 属性来检查是否出了问题。对于天气请求，如果这个回调运行，那么事情就对了。我们可以打印天气信息。为了完成这个任务，我们将创建两个变量：

+   `temperature`

+   `apparentTemperature`

`temperature`变量将被设置为`response.data`。然后我们将访问`currently`属性。然后我们将访问温度。我们将提取出第二个变量，实际温度或`apparentTemperature`，这是属性名称，`var apparentTemperature`。我们将把这个设置为`response.data.currently.apparentTemperature`：

```js
}).then((response) => {
 var temperature = response.data.currently.temperature;
 var apparentTemperature = response.data.currently.apparentTemperature;
```

现在我们已经将两个东西提取到变量中，我们可以将这些东西添加到`console.log`中。我们选择定义两个变量，这样我们就不必将两个非常长的属性语句添加到`console.log`中。我们可以简单地引用这些变量。我们将添加`console.log`，并在`console.log`语句中使用模板字符串，这样我们可以在引号中插入前面提到的两个值：`当前温度`，然后是`温度`。然后我们可以添加一个句号，`感觉像`，然后是`apparentTemperature`：

```js
}).then((response) => {
 var temperature = response.data.currently.temperature;
 var apparentTemperature = response.data.currently.apparentTemperature;
 console.log(`It's currently ${temperature}. It feels like ${apparentTemperature}.`);
```

现在我们的字符串已经打印到屏幕上，我们可以测试我们的应用程序是否按预期工作。我们将保存文件，在终端中，我们将重新运行两个命令之前的命令，其中我们有一个有效的邮政编码：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/45cf383a-3a5f-4c59-a096-2ba3d38088a0.png)

当我们运行这个代码时，我们得到了`新泽西州`的`Flemington`的天气信息。当前温度是`84`华氏度，但感觉像`90`华氏度。如果我们运行的是一个错误的地址，我们会得到错误消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3b8c8c29-25de-44af-8688-7ebd557f4cc8.png)

所以一切看起来都很棒！使用`axios`库，我们能够像`app-promise`一样链式调用 promise，而不需要做任何太疯狂的事情。`axios get`方法返回一个 promise，所以我们可以直接使用`then`访问它。

在代码中，我们使用`then`一次来处理地理位置数据。我们将地址打印到屏幕上。然后我们返回另一个 promise，在其中我们请求天气。在我们的第二个`then`调用中，我们将天气打印到屏幕上。我们还添加了一个`catch`调用，用于处理任何错误。如果我们的任何一个 promise 出现问题，或者我们抛出错误，`catch`将被触发，将消息打印到屏幕上。

这就是使用 axios 设置 HTTP 请求的 promise 所需的全部内容。人们喜欢 promise 而不是传统回调的一个原因是，我们可以简单地链式调用而不是嵌套。所以我们的代码不会缩进到疯狂的水平。正如我们在上一章的`app.js`中看到的，我们深入了几个缩进级别，只是为了将两个调用组合在一起。如果我们需要添加第三个，情况会变得更糟。有了 promise，我们可以保持一切在同一级别，使我们的代码更容易维护。

# 摘要

在本章中，我们通过一个快速的例子介绍了 promise 的工作原理，只是介绍了非常基础的内容。异步是 Node.js 的一个关键部分。我们介绍了回调和 promise 的基础知识。我们看了一些例子，创建了一个相当酷的天气应用程序。

这就是我们的异步 Node.js 编程的结束，但这并不意味着你必须停止构建天气应用程序。有一些想法可以让你继续这个项目。首先，你可以加载更多的信息。我们从天气 API 得到的响应除了当前温度之外还包含了大量的其他信息。如果你能在其中加入一些东西，比如高/低温度或降水几率，那就太棒了。

接下来，拥有默认位置的能力将是非常酷的。会有一个命令让我设置一个默认位置，然后我可以在没有位置参数的情况下运行天气应用程序来使用默认位置。我们也可以指定一个位置参数来搜索其他地方的天气。这将是一个很棒的功能，它的工作方式有点类似于 Notes 应用程序，我们可以将数据保存到文件系统中。

在下一章中，我们将开始创建异步的网络服务器。我们将制作异步的 API。此外，我们将创建实时的 Socket.IO 应用程序，这也将是异步的。我们将继续创建 Node 应用程序，将其部署到服务器上，使这些服务器对任何具有网络连接的人都可以访问。


# 第八章：Node 中的 Web 服务器

在本章中，我们将涵盖大量令人兴奋的内容。我们将学习如何创建 Web 服务器，以及如何将版本控制集成到 Node 应用程序中。现在，为了完成所有这些工作，我们将看一下一个叫做 Express 的框架。它是最受欢迎的 npm 库之一，原因很充分。它使得诸如创建 Web 服务器或 HTTP API 之类的工作变得非常容易。这有点类似于我们在上一章中使用的 Dark Sky API。

现在大多数课程都是从 Express 开始的，这可能会让人困惑，因为它模糊了 Node 和 Express 之间的界限。我们将通过将 Express 添加到全新的 Node 应用程序来开始。

具体来说，我们将涵盖以下主题：

+   介绍 Express

+   静态服务器

+   渲染模板

+   高级模板

+   中间件

# 介绍 Express

在本节中，您将创建自己的第一个 Node.js Web 服务器，这意味着您将有一种全新的方式让用户访问您的应用程序。而不是让他们从终端运行它并传递参数，您可以给他们一个 URL，他们可以访问以查看您的 Web 应用程序，或者一个 URL，他们可以发出 HTTP 请求以获取一些数据。

这将类似于我们在之前的章节中使用地理编码 API 时所做的。不过，我们将能够创建自己的 API，而不是使用 API。我们还将能够为诸如作品集网站之类的静态网站设置一个静态网站。这两者都是非常有效的用例。现在，所有这些都将使用一个叫做**Express**的库来完成，这是最受欢迎的 npm 库之一。实际上，这是 Node 变得如此受欢迎的原因之一，因为它非常容易制作 REST API 和静态 Web 服务器。

# 配置 Express

Express 是一个直截了当的库。现在有很多不同的配置方式。所以它可能会变得非常复杂。这就是为什么在接下来的几章中我们将使用它的原因。首先，让我们创建一个目录，我们可以在其中存储这个应用程序的所有代码。这个应用程序将是我们的 Web 服务器。

在桌面上，让我们通过在终端中运行`mkdir node-web-server`命令来创建一个名为`node-web-server`的目录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a662a1c0-9b49-4917-b238-f538d270a209.png)

创建了这个目录后，我们将使用`cd`进入其中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6e79ccf4-fe81-4cc3-a8ae-5f3562f4c0b1.png)

我们还将在 Atom 中打开它。在 Atom 中，我们将从桌面打开它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9e35a36f-c099-4baa-848d-27aed99c5b2a.png)

在继续之前，我们将运行`npm init`命令，以便生成`package.json`文件。如下所示，我们将运行`npm init`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3bb36f99-9a07-444b-964e-1082a4c91ba9.png)

然后，我们将通过在以下截图中显示的所有选项中按*enter*来使用默认值。目前没有必要自定义任何选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/409f3209-e35c-4464-95f1-c0b6539ddc61.png)

然后我们将在最后一个语句`Is this ok? (yes)`中输入`yes`，`package.json`文件就位了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cf2525fd-c1cf-4a0b-9431-0784f2bd46f9.png)

# Express 文档网站

如前所述，Express 是一个非常庞大的库。有一个专门的网站专门用于 Express 文档。您可以访问[www.expressjs.com](http://expressjs.com/)查看网站提供的所有内容，而不是简单的`README.md`文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/76c08a9b-7416-4ed5-afd9-b62f9f8ecde0.png)

我们将找到入门、帮助文章等。该网站有一个“指南”选项，可以帮助您执行诸如路由、调试、错误处理和 API 参考之类的操作，因此我们可以准确了解我们可以访问的方法以及它们的作用。这是一个非常方便的网站。

# 安装 Express

现在我们有了我们的`node-web-server`目录，我们将安装 Express，这样我们就可以开始制作我们的 Web 服务器。在终端中，我们将首先运行`clear`命令以清除输出。然后我们将运行`npm install`命令。模块名称是`express`，我们将使用最新版本`@4.16.0`。我们还将提供`save`标志来更新我们的`package.json`文件中的依赖项，如下所示：

```js
npm install express@4.16.0 --save
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/107b4ff8-819a-4a01-ae06-60b1af04e99e.png)

再次，我们将使用`clear`命令来清除终端输出。

现在我们已经安装了`Express`，我们可以在 Atom 中创建我们的 Web 服务器。为了运行服务器，我们需要一个文件。我会把这个文件叫做`server.js`。它将直接放在我们应用程序的根目录中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/bf797c36-afaf-4e5f-aa29-af9a1d4ae371.png)

这是我们将配置各种路由的地方，像网站的根目录，像`/about`这样的页面等。这也是我们将启动服务器的地方，将其绑定到我们机器上的端口。现在我们将部署到一个真正的服务器。稍后我们将讨论这是如何工作的。现在，我们大部分的服务器示例将发生在我们的本地主机上。

在`server.js`中，我们要做的第一件事是通过创建一个常量`express`并将其设置为`require('express')`来加载 Express：

```js
const express = require('express');
```

接下来，我们要做的是创建一个新的 Express 应用程序。为此，我们将创建一个名为 app 的变量，并将其设置为从调用`express`作为函数返回的结果：

```js
const express = require('express');

var app = express();
```

现在我们不需要传递任何参数到`express`中。我们将进行大量的配置，但这将以不同的方式进行。

# 创建一个应用程序

为了创建一个应用程序，我们只需要调用这个方法。在变量`app`旁边，我们可以开始设置所有我们的 HTTP 路由处理程序。例如，如果有人访问网站的根目录，我们将想要发送一些东西回去。也许是一些 JSON 数据，也许是一个 HTML 页面。

我们可以使用`app.get`函数注册一个处理程序。这将让我们为 HTTP get 请求设置一个处理程序。我们必须传入`app.get`的两个参数： 

+   第一个参数将是一个 URL

+   第二个参数将是要运行的函数；告诉 Express 要发送什么回去给发出请求的人的函数

在我们的情况下，我们正在寻找应用程序的根。所以我们可以只使用斜杠（`/`）作为第一个参数。在第二个参数中，我们将使用一个简单的箭头函数（`=>`）如下所示：

```js
const express = require('express');

var app = express();

app.get('/', (req, res) => {

};
```

现在箭头函数（`=>`）将被调用两个参数。这对于 Express 的工作方式非常重要：

+   第一个参数是请求（`req`），存储了关于进来的请求的大量信息。像使用的标头、任何主体信息，或者用请求到路径的方法。所有这些都存储在请求中。

+   第二个参数，respond（`res`），有很多可用的方法，所以我们可以以任何我们喜欢的方式响应 HTTP 请求。我们可以自定义发送回去的数据，还可以设置我们的 HTTP 状态码。

我们将详细探讨这两者。不过现在，我们将使用一个方法，`res.send`。这将让我们响应请求，发送一些数据回去。在`app.get`函数中，让我们调用`res.send`，传入一个字符串。在括号中，我们将添加`Hello Express!`：

```js
app.get('/', (req, res) => {
  res.send('Hello Express!');
});
```

这是 HTTP 请求的响应。所以当有人查看网站时，他们将看到这个字符串。如果他们从应用程序发出请求，他们将得到`Hello Express!`作为主体数据。

现在在这一点上，我们还没有完全完成。我们已经设置了其中一个路由，但是应用程序实际上永远不会开始监听。我们需要做的是调用`app.listen`。`app.listen`函数将在我们的机器上将应用程序绑定到一个端口。在这种情况下，对于我们的本地主机应用程序，我们将使用端口`3000`，这是一个非常常见的用于本地开发的端口。在本章的后面，我们将讨论如何根据您用于将应用程序部署到生产环境的服务器来自定义此设置。不过，像`3000`这样的数字是有效的：

```js
app.get('/', (req, res) => {
  res.send('Hello Express!');
});

app.listen(3000);
```

有了这个设置，我们现在完成了。我们有了我们的第一个 Express 服务器。我们实际上可以从终端运行它，并在浏览器中查看它。在终端中，我们将使用`nodemon server.js`来启动我们的应用程序：

```js
nodemon server.js
```

这将启动应用程序，并且您将看到应用程序从未真正完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/93379da7-8160-4b76-a3f2-f8d4dd461451.png)

现在它正在挂起。它正在等待请求开始进来。使用`app.listen`的应用程序永远不会停止。您必须手动使用*control* + *C*关闭它们，就像我们以前做过的那样。如果您的代码中有错误，它可能会崩溃。但是它通常不会停止，因为我们在这里设置了绑定。它将监听请求，直到您告诉它停止。

现在服务器已经启动，我们可以进入浏览器，打开一个新标签，访问网站，`localhost:`后跟端口`3000`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3cefbc29-a9e1-4959-87bb-6a673b2efa25.png)

这将加载网站的根目录，并且我们指定了该路由的处理程序。Hello Express!显示出来，这正是我们所期望的。现在没有花哨。没有格式。我们只是从服务器向发出请求的客户端发送一个字符串。

# 在浏览器中探索应用程序请求的开发者工具

接下来，我们想打开开发者工具，以便我们可以探索在发出请求时发生了什么。在 Chrome 中，您可以使用设置|更多工具|开发者工具来打开开发者工具：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d408ab4a-be5b-4f3f-a06d-5e760c27780d.png)

或者您可以使用与操作系统的开发者工具一起显示的键盘快捷键。

我强烈建议您记住这个键盘快捷键，因为在使用 Node 时，您将大量使用`开发者工具`。

我们现在将打开开发者工具，它应该看起来与我们运行 Node Inspector 调试器时使用的工具类似。它们有点不同，但是思想是一样的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/54afeb85-d1bd-49b1-8ecb-721dc33b4c82.png)

我们在顶部有一堆标签，然后我们在页面下方有我们特定标签的信息。在我们的情况下，我们想转到网络标签，目前我们什么都没有。因此，我们将在打开标签的情况下刷新页面，我们在这里看到的是我们的本地主机请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/82180d8c-58ad-43c9-9dc7-a91b9f2478b2.png)

这是负责在屏幕上显示 Hello Express!的请求。实际上，我们可以单击请求以查看其详细信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1e91be78-a106-47a6-9285-94d8720ea76d.png)

这个页面一开始可能有点压倒性。有很多信息。在顶部，我们有一些一般信息，例如被请求的 URL，客户端想要的方法；在这种情况下，我们发出了一个 GET 请求，并且返回的状态代码。默认状态代码为 200，表示一切顺利。我们想要指出的是一个响应头。

在响应标头下，我们有一个叫做 Content-Type 的标头。这个标头告诉客户端返回了什么类型的数据。现在这可能是像 HTML 网站、一些文本或一些 JSON 数据，而客户端可能是一个网络浏览器、iPhone、安卓设备或任何其他具有网络功能的计算机。在我们的情况下，我们告诉浏览器返回的是一些 HTML，所以为什么不按照这样的方式进行渲染呢。我们使用了 text/html Content-Type。这是由 Express 自动设置的，这也是它如此受欢迎的原因之一。它为我们处理了很多这样的琐事。

# 将 HTML 传递给 res.send

现在我们有了一个非常基本的例子，我们想要把事情提升到一个新的水平。在 Atom 中，我们实际上可以通过将我们的`Hello Express!`消息放在一个`h1`标签中，直接在 send 中提供一些 HTML。在本节的后面，我们将设置一个包含 HTML 文件的静态网站。我们还将研究模板化以创建动态网页。但现在，我们实际上可以只是将一些 HTML 传递给`res.send`：

```js
app.get('/', (req, res) => {
  res.send('<h1>Hello Express!</h1>');
});

app.listen(3000);
```

我们保存服务器文件，这应该会重新启动浏览器。当我们刷新浏览器时，我们会看到 Hello Express!打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/95e4efcb-addd-43c0-9878-a0052aaf297a.png)

不过这一次，我们把它放在了一个`h1`标签中，这意味着它是由默认的浏览器样式格式化的。在这种情况下，它看起来很漂亮而且很大。有了这个，我们现在可以在网络选项卡中打开请求，我们得到的是和之前完全一样的东西。我们仍然告诉浏览器它是 HTML。这一次唯一的区别是：我们实际上有一个 HTML 标签，所以它会使用浏览器的默认样式进行渲染。

# 发送 JSON 数据回去

我们接下来要看的是如何发送一些 JSON 数据回去。使用 Express 发送 JSON 非常容易。为了说明我们如何做到这一点，我们将注释掉当前对`res.send`的调用，并添加一个新的调用。我们将调用`res.send`，传入一个对象：

```js
app.get('/', (req, res) => {
  // res.send('<h1>Hello Express!</h1>');
  res.send({

  })
});
```

在这个对象上，我们可以提供任何我们喜欢的东西。我们可以创建一个`name`属性，将它设置为任何名字的字符串版本，比如`Andrew`。我们可以创建一个名为`likes`的属性，将它设置为一个数组，并且可以指定一些我们可能喜欢的东西。让我们把`Biking`添加为其中之一，然后再添加`Cities`作为另一个：

```js
  res.send({
    name: 'Andrew',
    likes: [
      'Biking',
      'Cities'
    ]
  });
```

当我们调用`res.send`并传入一个对象时，Express 会注意到。Express 会将其转换为 JSON，并发送回浏览器。当我们保存`server.js`并且 nodemon 刷新时，我们可以刷新浏览器，我们得到的是我的数据使用 JSON 视图格式化的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/265798fa-1fb0-4233-aac6-d8f51e573ef8.png)

这意味着我们可以折叠属性并快速导航 JSON 数据。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a8ab4046-fd65-44d3-bc10-a17341a80e4f.png)

现在 JSON 视图之所以能够捕捉到这一点，是因为我们在上一个请求中探索的 Content-Type 标头实际上发生了变化。如果我打开`localhost`，很多东西看起来都一样。但现在 Content-Type 变成了 application/json Content-Type：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d9205712-9724-496a-8c78-e6b6954bae4f.png)

这个 Content-Type 告诉请求者，它是一个安卓手机、一个 iOS 设备，还是浏览器，JSON 数据正在返回，它应该解析为这样。这正是浏览器在这种情况下所做的。

Express 还可以很容易地设置除根路由之外的其他路由。我们可以在 Atom 中调用`app.get`来探索这一点。我们将调用`app.get`。我们将创建第二个路由。我们将这个叫做`about`：

```js
app.get('/about')

app.listen(3000);
```

注意我们只是使用了`/about`作为路由。保持斜杠的位置很重要，但在那之后你可以输入任何你喜欢的东西。在这种情况下，我们将有一个`/about`页面供某人访问。然后我会提供处理程序。处理程序将接收`req`和`res`对象：

```js
app.get('/about', (req, res) => {

});

app.listen(3000);
```

这将让我们弄清楚是什么样的请求进来了，以及让我们对该请求做出响应。现在，为了说明我们可以创建更多页面，我们将保持响应简单，`res.send`。在字符串内部，我们将打印`About Page`：

```js
app.get('/about', (req, res) => {
  res.send('About Page');
});
```

现在当我们保存`server.js`文件时，服务器将重新启动。在浏览器中，我们可以访问`localhost:3000/about`。在`/about`处，我们现在应该看到我们的新数据，这正是我们得到的，About Page 显示如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8e3f1986-c5ee-4b56-9984-35ec3ad84fab.png)

使用`app.get`，我们可以指定尽可能多的路由。目前我们只有一个`about`路由和一个`/`路由，也被称为根路由。根路由返回一些数据，恰好是 JSON，而 about 路由返回一点 HTML。现在我们已经有了这个设置，并且对于如何在 Express 中设置路由有了一个非常基本的理解，我们希望你创建一个新的路由`/bad`。这将模拟当请求失败时会发生什么。

# JSON 请求中的错误处理

为了显示 JSON 的错误处理请求，我们将调用`app.get`。这个`app.get`将让我们为 get HTTP 请求注册另一个处理程序。在我们的情况下，我们正在寻找的路由将在引号内，即`/bad`。当有人请求这个页面时，我们想要做的将在回调中指定。回调将使用我们的两个参数，`req`和`res`。我们将使用一个箭头函数(`=>`)，这是我到目前为止所有处理程序都使用的：

```js
app.get('/bad', (req, res) => {

  });

app.listen(3000);
```

在箭头函数(`=>`)内部，我们将通过调用`res.send`发送一些 JSON。但我们不是传递一个字符串，或一些字符串 HTML，而是传递一个对象：

```js
app.get('/bad', (req, res) => {
  res.send({

  });
});
```

现在我们已经有了我们的对象，我们可以指定要发送回去的属性。在这种情况下，我们将设置一个`errorMessage`。我们将把我的错误消息属性设置为一个字符串，`无法处理请求`：

```js
app.get('/bad', (req, res) => {
  res.send({
    errorMessage: 'Unable to handle request'
  });
});
```

接下来我们将保存文件，在 nodemon 中重新启动它，并在浏览器中访问它。确保我们的错误消息正确显示。在浏览器中，我们将访问`/bad`，按下*enter*，我们会得到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e824edc3-7898-469e-9ac5-b63ce1f6f5c5.png)

我们的 JSON 数据显示出来了。我们有错误消息，还有消息显示出来：无法处理请求。现在，如果你正在使用 JSON 视图，并且想查看原始的 JSON 数据，你实际上可以点击“查看源代码”，它会在新标签页中显示出来。在这里，我们正在查看原始的 JSON 数据，所有内容都用双引号括起来。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/db28133e-200d-41d9-a6a3-2ba01543c9ed.png)

我将坚持使用 JSON 视图数据，因为它更容易导航和查看。我们现在有一个非常基本的 Express 应用程序正在运行。它在端口`3000`上监听，并且目前有 3 个 URL 的处理程序：当我们获取页面的根目录时，当我们获取`/about`时，以及当我们对`/bad`发出 get 请求时。

# 静态服务器

在这一部分，我们将学习如何设置一个静态目录。因此，如果我们有一个包含 HTML、CSS、JavaScript 和图像的网站，我们可以提供这些内容，而不需要为每个文件提供自定义路由，这将是一个真正的负担。现在设置这个非常简单。但在我们对`server.js`进行任何更新之前，我们需要在项目中创建一些静态资产，这样我们才能提供服务。

# 制作一个 HTML 页面

在这种情况下，我们将制作一个 HTML 页面，我们将能够在浏览器中查看。在我们开始之前，我们需要创建一个新的目录，这个目录中的所有内容都可以通过网络服务器访问，所以重要的是不要在这里放任何你不希望别人看到的东西。

目录中的所有内容都应该是任何人都可以查看的。我们将创建一个公共文件夹来存储所有静态资产，在这里我们将创建一个 HTML 页面。我们将通过创建一个名为`help.html`的文件为我们的示例项目创建一个帮助页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fafc28c3-1bd3-44e4-b17b-4f38525aa727.png)

现在在`help.html`中，我们将创建一个快速的基本 HTML 文件，尽管我们不会涉及 HTML 的所有微妙之处，因为这不是一本真正的 HTML 书。相反，我们将只设置一个基本页面。

我们需要做的第一件事是创建一个`DOCTYPE`，让浏览器知道我们正在使用的 HTML 版本。看起来会像这样：

```js
<!DOCTYPE html>
```

在开标签和感叹号之后，我们会输入大写的`DOCTYPE`。然后，我们提供 HTML5 的实际`DOCTYPE`，最新版本。然后我们可以使用大于号来关闭事物。在下一行，我们将打开我们的`html`标签，以便定义整个 HTML 文件：

```js
<!DOCTYPE html>
<html>
</html>
```

在`html`内部，有两个标签我们将使用：`head`标签让我们配置我们的文档，和`body`标签包含我们想要呈现在屏幕上的所有内容。

# head 标签

我们将首先创建`head`标签：

```js
<!DOCTYPE html>
<html>
  <head>

  </head>
</html>
```

在`head`中，我们将提供两个信息，`charset`和`title`标签：

+   首先，我们必须设置`charset`，让浏览器知道如何呈现我们的字符。

+   接下来我们将提供`title`标签。`title`标签让浏览器知道在标题栏中呈现什么内容，通常是新标签。

如下面的代码片段所示，我们将设置`meta`。在`meta`上，我们将使用等号设置`charset`属性，并提供值`utf-8`：

```js
  <head>
    <meta charset="utf-8">
  </head>
```

对于`title`标签，我们可以将其设置为任何我们喜欢的内容；`Help Page`似乎很合适：

```js
  <head>
    <meta charset="utf-8">
    <title>Help Page</title>
  </head>
```

# body 标签

现在我们的`head`已经配置好，我们可以在网站的正文中添加一些内容。这些内容实际上将在视口内可见。在`head`旁边，我们将打开和关闭`body`标签：

```js
  <body>

  </body>
```

在`body`中，我们将再次提供两个内容：一个`h1`标题和一个`p`段落标签。

标题将与我们在`head`中使用的`title`标签匹配，Help Page，段落将只有一些填充文本——`这里有一些文本`：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Help Page</title>
  </head>
  <body>
    <h1>Help Page</h1>
    <p>Some text here</p>
  </body>
</html>
```

现在我们有一个 HTML 页面，目标是能够在 Express 应用程序中提供此页面，而无需手动配置。

# 在 Express 应用程序中提供 HTML 页面

我们将使用 Express 中间件来在 Express 应用程序中提供我们的 HTML 页面。中间件让我们配置我们的 Express 应用程序的工作方式，并且在整本书中我们将广泛使用它。现在，我们可以将其视为第三方附加组件。

为了添加一些中间件，我们将调用`app.use`。`app.use`接受我们想要使用的中间件函数。在我们的情况下，我们将使用内置的中间件。因此，在`server.js`中，在`app`变量语句旁边，我们将提供`express`对象的函数：

```js
const express = require('express');

var app = express();

app.use();
```

在下一章中，我们将制作自己的中间件，所以很快就会清楚究竟传递了什么。现在，我们将传递`express.static`并将其作为一个函数调用：

```js
var app = express();

app.use(express.static());
```

现在`express.static`需要获取要提供的文件夹的绝对路径。如果我们想要提供`/help`，我们需要提供`public`文件夹的路径。这意味着我们需要指定从硬盘根目录开始的路径，这可能会很棘手，因为您的项目会移动。幸运的是，我们有`__dirname`变量：

```js
app.use(express.static(__dirname));
```

这是由我们探索的包装函数传递给我们文件的变量。`__dirname`变量存储着您项目的目录路径。在这种情况下，它存储着`node-web-server`的路径。我们只需连接`/public`，告诉它使用这个目录作为我们的服务器。我们将使用加号和字符串`/public`进行连接：

```js
app.use(express.static(__dirname + '/public'));
```

有了这个设置，我们现在已经完成了。我们的服务器已经设置好，没有其他事情要做。现在我们应该能够重新启动我们的服务器并访问`/help.html`。我们现在应该能够看到我们的 HTML 页面。在终端中，我们现在可以使用`nodemon server.js`来启动应用程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/16d84c8b-973b-49b3-96b7-8cb4546c7269.png)

一旦应用程序运行起来，我们就可以在浏览器中访问它。我们将首先转到`localhost:3000`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cdc5f64a-0aba-48d4-897e-fd0c14f4e71e.png)

在这里，我们得到了我们的 JSON 数据，这正是我们所期望的。如果我们将该 URL 更改为`/help.html`，我们应该会看到我们的帮助页面渲染：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/63d0b4c0-6781-4689-93e2-96a4b69adc01.png)

这正是我们得到的，我们的帮助页面显示在屏幕上。我们将帮助页面标题设置为标题，然后是一些文本段落作为正文。能够轻松设置静态目录已经使 Node 成为简单项目的首选，这些项目实际上并不需要后端。如果您想创建一个仅用于提供目录的 Node 应用程序，您可以在`server.js`文件中用大约四行代码完成：前三行和最后一行。

# 对`app.listen`的调用

现在我们要讨论的另一件事是对`app.listen(3000)`的调用。`app.listen`确实需要第二个参数。这是可选的。这是一个函数。这将让我们在服务器启动后执行某些操作，因为启动可能需要一点时间。在我们的情况下，我们将为`console.log`分配一条消息：`服务器已在 3000 端口上启动`：

```js
app.listen(3000, () => {
  console.log('Server is up on port 3000');
});
```

现在对于启动应用程序的人来说，服务器实际上已经准备就绪，因为消息将打印到屏幕上。如果我们保存`server.js`，并返回到终端，我们可以看到`服务器已在 3000 端口上启动`打印出来：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3eb224ed-caec-4a93-ac40-e3e77b73a815.png)

回到浏览器，我们可以刷新，得到完全相同的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1340f888-eea5-480e-a997-b060ded511c1.png)

这就是本节的全部内容。我们现在有一个静态目录，可以在其中包含 JavaScript、CSS、图像或任何其他文件类型。

# 渲染模板

在最后几节中，我们看了多种使用 Express 渲染 HTML 的方法。我们将一些 HTML 传递给`response.send`，但显然这并不理想。在字符串中编写标记是真正痛苦的。我们还创建了一个公共目录，可以在其中放置我们的静态 HTML 文件，例如我们的`help`文件，并将其提供给浏览器。这两种方法都很好，但还有第三种解决方案，这将是本节的主题。解决方案是模板引擎。

模板引擎将允许您以动态方式呈现 HTML，我们可以在模板中注入值，例如用户名或当前日期，就像我们在 Ruby 或 PHP 中所做的那样。使用这个模板引擎，我们还将能够为诸如页眉或页脚之类的可重用标记创建可重用的标记，这将在您的许多页面上都是相同的。这个模板引擎，handlebars，将是本节和下一节的主题，所以让我们开始吧。

# 安装 hbs 模块

我们要做的第一件事是安装`hbs`模块。这是 Express 的 handlebars 视图引擎。现在有很多其他 Express 视图引擎，例如 EJS 或 Pug。我们将选择 handlebars，因为它的语法很棒。这是一个很好的开始方式。

现在我们将在浏览器中看到一些内容。首先，我们将访问[handlebarsjs.com](http://handlebarsjs.com/)。这是 handlebars 的文档。它向您展示了如何使用其所有功能，因此如果我们想使用任何内容，我们总是可以在这里学习如何使用它。

现在我们将安装一个包装在 handlebars 周围的模块。它将让我们将其用作 Express 视图引擎。要查看此内容，我们将转到[npmjs.com/package/hbs](https://www.npmjs.com/package/hbs)。

这是所有软件包的 URL 结构。因此，如果您想找到软件包页面，只需键入`npmjs.com/package/软件包名称`。

这个模块非常受欢迎。这是一个非常好的视图引擎。他们有很多文档。我只是想让你知道这也存在。现在我们可以安装并将其集成到我们的应用程序中。在终端中，我们将使用`npm install`安装`hbs`，模块名称是`hbs`，最新版本是`@4.0.1`。我将使用`save`标志来更新`package.json`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/82996805-a5fc-4fbe-9920-db7a0c963951.png)

现在实际上配置 Express 使用这个 handlebars 视图引擎非常简单。我们所要做的就是导入它并在我们的 Express 配置中添加一个语句。我们将在 Atom 中做到这一点。

# 配置 handlebars

在 Atom 中，让我们开始加载 handlebars `const hbs = require hbs`，如所示，从这里我们可以添加一行：

```js
const express = require('express');
const hbs = require('hbs');
```

接下来，让我们调用`app.set`，在那里我们为 Express 静态调用`app.use`：

```js
app.set
app.use(express.static(__dirname + '/public'));
```

这让我们设置一些与 Express 相关的配置。有很多内置的配置。我们稍后会谈论更多。现在，我们要做的是传入一个键值对，其中键是你想要设置的东西，值是你想要使用的值。在这种情况下，我们设置的键是`view engine`。这将告诉 Express 我们想要使用的视图引擎，并且我们将在引号内传入`hbs`：

```js
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
```

这就是我们需要做的一切。

# 我们的第一个模板

现在，为了创建我们的第一个模板，我们想要做的是在项目中创建一个名为`views`的目录。`views`是 Express 用于模板的默认目录。所以我们将添加`views`目录，然后在其中添加一个模板。我们将为我们的关于页面创建一个模板。

在 views 中，我们将添加一个新文件，文件名将是`about.hbs`。`hbs` handlebars 扩展名很重要。确保包含它。

现在 Atom 已经知道如何解析`hbs`文件。在`about.hbs`文件的底部，显示当前语言的地方，使用括号内的 HTML mustache。

Mustache 被用作这种类型的 handlebars 语法的名称，因为当你输入大括号（`{`）时，它们看起来有点像胡须。

我们要做的是开始使用`help.html`的内容并直接复制它。让我们复制这个文件，这样我们就不必重写那个样板，然后我们将它粘贴到`about.hbs`中：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Help Page</title>
  </head>
  <body>
    <h1>Help Page</h1>
    <p>Some text here</p>
  </body>
</html>
```

现在我们可以尝试渲染这个页面。我们将把`h1`标签从帮助页面改为关于页面：

```js
  <body>
    <h1>About Page</h1>
    <p>Some text here</p>
  </body>
```

我们将在稍后讨论如何在此页面内动态渲染内容。在那之前，我们只想让它渲染。

# 获取静态页面进行渲染

在`server.js`中，我们已经有了一个`/about`的根目录，这意味着我们可以渲染我们的 hbs 模板，而不是发送回这个关于页面字符串。我们将删除我们对`res.send`的调用，并将其替换为`res.render`：

```js
app.get('/about', (req, res) => {
  res.render
});
```

Render 将让我们使用我们当前视图引擎设置的任何模板进行渲染`about.hbs`文件。我们确实有关于模板，我们可以将该名称`about.hbs`作为第一个且唯一的参数传递。我们将渲染`about.hbs`：

```js
app.get('/about', (req, res) => {
  res.render('about.hbs');
});
```

这就足以让静态页面渲染。我们将保存`server.js`，在终端中清除输出，然后使用`nodemon server.js`运行我们的服务器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/212008be-1d6d-4b32-bc02-3864d93dace6.png)

一旦服务器运行起来，它就会显示在端口`3000`上。我们可以打开`/about` URL 并查看我们得到了什么。我们将进入 Chrome 并打开`localhost:3000 /about`，当我们这样做时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f1db99d7-ade4-4a43-8694-2a0e3ee4317d.png)

我们得到了我的关于页面的渲染，就像我们期望的那样。我们有一个`h1`标签，显示得很大，我们有一个段落标签，显示如下。到目前为止，我们已经使用了 hbs，但实际上我们还没有使用它的任何功能。现在，我们正在渲染一个动态页面，所以我们可能根本不需要它。我想要做的是讨论一下我们如何在模板中注入数据。

# 在模板中注入数据

让我们想一些我们想要在 handlebars 文件中使动态的东西。首先，我们将使这个`h1`标签动态，以便页面名称传递到`about.hbs`页面中，我们还将添加一个页脚。现在，我们只需将其设置为一个简单的`footer`标签：

```js
    <footer>

    </footer>
  </body>
</html>
```

在`footer`内，我们将添加一个段落，这个段落将包含我们网站的版权。我们只是说版权，然后是年份，2018 年：

```js
    <footer>
      <p>Copyright 2018</p>
    </footer>
```

现在年份也应该是动态的，这样当年份变化时，我们不必手动更新我们的标记。我们将看看如何使 2018 年和关于页面都是动态的，这意味着它们被传递而不是在 handlebars 文件中输入。

为了做到这一点，我们需要做两件事：

+   我们将不得不将一些数据传递到模板中。这将是一个对象，一组键值对，

+   我们将不得不学习如何在 handlebars 文件中提取一些键值对

传递数据非常简单。我们所要做的就是在`server.js`中的`res.render`指定第二个参数。这将接受一个对象，在这个对象上，我们可以指定任何我们喜欢的东西。我们可能有一个`pageTitle`，它被设置为`About Page`：

```js
app.get('/about', (req, res) => {
  res.render('about.hbs', {
    pageTitle: 'About Page'
  });
});
```

我们有一个数据片段被注入到模板中。虽然还没有被使用，但确实被注入了。我们也可以添加另一个，比如`currentYear`。我们将把`currentYear`放在`pageTitle`旁边，并将`currentYear`设置为 JavaScript 构造函数的实际年份。这将看起来像这样：

```js
app.get('/about', (req, res) => {
  res.render('about.hbs', {
    pageTitle: 'About Page',
    currentYear: new Date().getFullYear()
  });
});
```

我们将创建一个新的日期，它将创建一个日期对象的新实例。然后，我们将使用一个叫做`getFullYear`的方法，它返回年份。在这种情况下，它将返回`2018`，就像这样`.getFullYear`。现在我们有了`pageTitle`和`currentYear`。这两者都被传递进来了，我们可以使用它们。

为了使用这些数据，我们在模板内部要使用 handlebars 语法，看起来有点像下面的代码。我们首先在`h1`标签中打开两个大括号，然后关闭两个大括号。在大括号内，我们可以引用我们传入的任何 props。在这种情况下，让我们使用`pageTitle`，在我们的版权段落内，我们将使用双大括号内的`currentYear`：

```js
  <body>
    <h1>{{pageTitle}}</h1>
    <p>Some text here</p>

    <footer>
      <p>Copyright 2018</p>
    </footer>
  </body>
</html>
```

有了这个，我们现在有两个动态数据片段被注入到我们的应用程序中。现在 nodemon 应该在后台重新启动了，所以没有必要手动做任何事情。当我们刷新页面时，我们仍然会得到 About Page，这很好：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c7fde0ed-6f7e-46af-bb85-696c8299893f.png)

这来自我们在`server.js`中定义的数据，我们得到了版权 2018 年。嗯，这个网页非常简单，看起来并不那么有趣。至少你知道如何创建那些服务器并将数据注入到你的网页中。从这里开始，你只需要添加一些自定义样式，让事情看起来不错。

在继续之前，让我们进入 about 文件并替换标题。目前，它说`Help Page`。这是从公共文件夹中留下的。让我们把它改成`Some Website`：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Some Website</title>
  </head>
  <body>
    <h1>{{pageTitle}}</h1>
    <p>Some text here</p>

    <footer>
      <p>Copyright 2018</p>
    </footer>
  </body>
</html>
```

现在我们已经有了这个位置。接下来，我们将创建一个全新的模板，当有人访问我们网站的根目录`/`时，这个模板将被渲染。现在，我们当前渲染一些 JSON 数据：

```js
app.get('/', (req, res) => {
  // res.send('<h1>Hello Express!</h1>');
  res.send({
    name: 'Andrew',
    likes: [
      'Biking',
      'Cities'
    ]
  });
```

我们想要的是用`response.render`来替换这个，渲染一个全新的视图。

# 渲染网站根目录的模板

要开始，我们将复制`about.hbs`文件，这样我们就可以开始根据我们的需求定制它。我们将复制它，并将其命名为`home.hbs`：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Some Website</title>
  </head>
  <body>
    <h1>{{pageTitle}}</h1>
    <p>Some text here</p>

    <footer>
      <p>Copyright 2018</p>
    </footer>
  </body>
</html>
```

从这里开始，大部分事情都将保持不变。我们将保持`pageTitle`不变。我们还将保持`Copyright`和`footer`不变。但我们想要改变的是这个段落。`About Page`作为静态的是可以的，但对于`home`页面，我们将把它设置为，双大括号内的`welcomeMessage`属性：

```js
  <body>
    <h1>{{pageTitle}}</h1>
    <p>{{welcomeMessage}}</p>

    <footer>
      <p>Copyright {{currentYear}}</p>
    </footer>
  </body>
```

现在`welcomeMessage`只能在`home.hbs`上使用，这就是为什么我们在`home.hbs`中指定它而不在`about.hbs`中指定它。

接下来，我们需要在回调函数中调用 response render。这将让我们实际渲染页面。我们将添加`response.render`，传入我们要渲染的模板名称。这个叫做`home.hbs`。然后我们将传入我们的数据：

```js
app.get('/', (req, res) => {
  res.render('home.hbs', {

  })
});
```

现在开始，我们可以传入页面标题。我们将把这个设置为`主页`，然后我们将传入一些通用的欢迎消息 - `欢迎来到我的网站`。然后我们将传入`currentYear`，我们已经知道如何获取`currentYear: new Date()`，并且在日期对象上，我们将调用`getFullYear`方法：

```js
 res.render('home.hbs', {
    pageTitle: 'Home Page',
    welcomeMessage: 'Welcome to my website',
    currentYear: new Date().getFullYear()
  })
```

有了这个设置，我们所需要做的就是保存文件，这将自动使用 nodemon 重新启动服务器并刷新浏览器。当我们这样做时，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/068646af-60ac-4dab-bef7-ba1ef545af9f.png)

我们得到我们的主页标题，我们的欢迎来到我的网站的消息，以及我的 2018 年版权。如果我们去到`/about`，一切看起来仍然很棒。我们有我们的动态页面标题和版权，以及我们的静态`some text here`文本：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ca92f075-3fb3-4cc9-91cc-920d441e035c.png)

有了这个设置，我们现在已经完成了 handlebars 的基础知识。我们看到了这在现实世界的 web 应用中是如何有用的。除了像版权这样的现实例子，您可能使用它的其他原因是为了注入某种动态用户数据 - 诸如用户名和电子邮件或其他任何东西。

现在我们已经基本了解了如何使用 handlebars 创建静态页面，我们将在下一部分中看一些 hbs 的更高级功能。

# 高级模板

在这一部分，我们将学习一些更高级的功能，这些功能可以更容易地渲染我们的标记，特别是在多个地方使用的标记，它将更容易地将动态数据注入到您的网页中。

为了说明我们将要谈论的第一件事，我想打开`about.hbs`和`home.hbs`，你会注意到底部它们都有完全相同的页脚代码如下：

```js
<footer>
  <p>Copyright {{currentYear}}</p>
</footer>
```

我们为两者都有一个小版权消息，它们都有相同的头部区域，即`h1`标签。

现在这并不是问题，因为我们有两个页面，但随着您添加更多页面，更新页眉和页脚将变得非常麻烦。您将不得不进入每个文件并在那里管理代码，但我们将讨论的是另一种叫做 partial 的东西。

# 添加 partials

Partial 是您网站的部分片段。这是您可以在模板中重复使用的东西。例如，我们可能有一个页脚 partial 来渲染页脚代码。您可以在任何需要页脚的页面上包含该 partial。您也可以对页眉做同样的事情。为了开始，我们需要做的第一件事是稍微调整我们的`server.js`文件，让 handlebars 知道我们想要添加对 partials 的支持。

为了做到这一点，我们将在`server.js`文件中添加一行代码，这是我们之前声明视图引擎的地方，它看起来会像这样（`hbs.registerPartials`）：

```js
hbs.registerPartials
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
```

现在`registerPartials`将使用您想要用于所有 handlebar 部分文件的目录，并且我们将指定该目录作为第一个和唯一的参数。再次强调，这确实需要是绝对目录，所以我将使用`__dirname`变量：

```js
hbs.registerPartials(__dirname)
```

然后我们可以连接路径的其余部分，即`/views`。在这种情况下，我希望您使用`/partials`。

```js
hbs.registerPartials(__dirname + '/views/partials')
```

我们将把我们的`partial`文件直接放在`views`文件夹中的一个目录中。现在我们可以在 views 中创建一个名为`partials`的文件夹。

在`partials`中，我们可以放置任何我们喜欢的 handlebars 部分。为了说明它们是如何工作的，我们将创建一个名为`footer.hbs`的文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ba84974e-6997-4b86-8e65-909dd7912add.png)

在`footer.hbs`中，我们将可以访问相同的 handlebars 功能，这意味着我们可以编写一些标记，我们可以注入变量，我们可以做任何我们喜欢的事情。现在，我们将做的是粘贴`footer`标签，粘贴到`footer.hbs`中：

```js
<footer>
  <p>Copyright {{getCurrentYear}}</p>
</footer>
```

现在我们有了我们的`footer.hbs`文件，这就是部分，我们可以在`about.hbs`和`home.hbs`中包含它。为了做到这一点，我们将删除部分中已有的代码，并用两个大括号打开和关闭它。现在，我们不再想要注入数据，而是想要注入一个模板，其语法是添加一个大于符号和一个空格，然后是部分名称。在我们的情况下，该部分称为`footer`，所以我们可以在这里添加它：

```js
    {{> footer}}
  </body>
</html>
```

然后我可以保存`about`并在`home.hbs`中做同样的事情。我们现在有了我们的页脚部分。它在两个页面上都渲染出来了。

# 部分的工作

为了说明这是如何工作的，我将启动我的服务器，默认情况下是`nodemon`；它不会监视你的 handlebars 文件。所以如果你做出了更改，网站不会像你期望的那样渲染。我们可以通过运行`nodemon`，传入`server.js`并提供`-e`标志来解决这个问题。这让我们可以指定我们想要监视的所有扩展名。在我们的情况下，我们将监视服务器文件的 JS 扩展名，逗号后是`hds`扩展名：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/004348dd-260d-4ad0-a181-cc8bbf7a467e.png)

现在我们的应用程序已经启动，我们可以在浏览器中刷新一下，它们应该看起来一样。我们有关于页面和页脚：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ed69beb8-6b66-417f-9b86-80b7f071f7e6.png)

我们的主页上有完全相同的页脚：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cdb964aa-0e0c-4ab4-a6a6-0b566d19f7d7.png)

现在的优势是，如果我们想要更改页脚，我们只需在`footer.hbs`文件中进行更改。

我们可以在我们的`footer`段落标签中添加一些内容。让我们添加一个由`Andrew Mead`创建的小消息，带有一个`-`：

```js
<footer>
 <p>Created By Andrew Mead - Copyright {{CurrentYear}}</p>
</footer>
```

现在，保存文件，当我们刷新浏览器时，我们有了全新的主页页脚：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3f195019-b92c-4349-8791-faa99b8c8804.png)

我们有了关于页面的全新页脚：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c310e4de-e690-44d2-99f9-960964edaa74.png)

它将显示在主页和关于页面上。在这两个页面中都不需要手动做任何事情，这就是部分的真正力量。你有一些代码，想要在网站内重用它，所以你只需创建一个部分，然后在你喜欢的地方注入它。

# 头部部分

现在我们已经有了页脚部分，让我们创建头部部分。这意味着我们需要创建一个全新的文件`header.hbs`。我们将想要在该文件中添加`h1`标签，然后在`about.hbs`和`home.hbs`中渲染部分。两个页面应该看起来一样。

我们将从头部文件夹中创建一个名为`header.hbs`的新文件。

在`header.hbs`中，我们将从我们的网站中取出`h1`标签，粘贴到里面并保存：

```js
<h1>{{pageTitle}}</h1>
```

现在我们可以在`about`和`home`文件中使用这个头部部分。在`about`中，我们需要使用双大括号和大于符号的语法，然后是部分名称`header`。我们将在`home`页面上做完全相同的事情。在`home`页面上，我们将删除我们的`h1`标签，注入`header`并保存文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1d0cfc47-2614-44ef-8e51-d47e70a0c554.png)![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a934ac3e-cb8e-4907-b2a9-e117eedb29c3.png)

现在我们将创建一些略有不同的东西，以便我们可以测试它是否真的在使用部分。我们将在`header.hbs`中的`h1`标签后面输入`123`：

```js
<h1>{{pageTitle}}</h1>123
```

现在所有文件都已保存，我们应该可以刷新浏览器，看到打印的`about`页面上有 123，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9d7c7b9a-77b3-4582-a586-c7f0ec7adf7f.png)

这意味着`header`部分确实起作用，如果我回到`home`页面，一切看起来仍然很棒：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f84e2173-76d2-4852-b033-7ce62f5be9a4.png)

现在我们已经将标题拆分为自己的文件，我们可以做很多事情。我们可以将我们的`h1`标签放入`header 标签`中，这是在 HTML 中声明标题的适当方式。如图所示，我们添加了一个打开和关闭的`header`标签。我们可以取出`h1`，然后将其放在里面：

```js
<header>
 <h1>{{pageTitle}}</h1>
</header>
```

我们还可以向我们网站的其他页面添加一些链接。我们可以通过添加`a`标签为主页添加一个锚标签：

```js
<header>
 <h1>{{pageTitle}}</h1>
 <p><a></a></p>
</header>
```

在`a`标签内，我们将指定我们想要显示的链接文本。我会选择“主页”，然后在`href`属性内部，我们可以指定链接应该带您去的路径，即`/`：

```js
<header>
 <h1>{{pageTitle}}</h1>
 <p><a href="/">Home</a></p>
</header>
```

然后我们可以使用相同的段落标签，复制它并粘贴到下一行，并为`about`页面创建一个链接。我会将页面文本更改为“关于”，链接文本和 URL，而不是转到`/`，将转到`/about`：

```js
<header>
 <h1>{{pageTitle}}</h1>
 <p><a href="/">Home</a></p>
 <p><a href="/about">About</a></p>
</header>
```

现在我们已经对我们的`header`文件进行了更改，并且它将在我们网站的所有页面上都可用。我在`home`页面。如果我刷新它，我会得到主页和关于页面的链接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fc1ba9b1-502f-46ac-af10-ef18c95ff52f.png)

我可以点击“关于”去关于页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/069951c9-aa95-4915-99a5-053cb121590b.png)

同样，我可以点击主页直接返回。现在我们网站内部的所有这些都更容易管理。

# Handlebars 助手

现在在我们继续之前，我想谈谈另一件事，那就是 handlebars 助手。 Handlebars 助手将是我们注册函数以动态创建一些输出的方式。例如，在`server.js`中，我们当前在我们的`app.get`模板中注入当前年份，这实际上并不是必要的。

有一种更好的方法来传递这些数据，并且不需要提供这些数据，因为我们将始终使用完全相同的函数。我们将始终获取新日期`getfullYear`返回值并将其传递。相反，我们将使用部分，并且我们将立即设置我们的部分。现在，部分只不过是您可以从 handlebars 模板内部运行的函数。

我们需要做的就是注册它，我将在`server.js`中执行此操作，从我们设置 Express 中间件的位置继续。如下所示，我们将调用`hbs.register`，并且我们将注册一个助手，因此我们将调用`registerHelper`：

```js
hbs.registerPartials(__dirname + '/views/partials')
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));

hbs.registerHelper();
```

现在`registerHelper`接受两个参数：

+   助手的名称作为第一个参数

+   作为第二个参数运行的函数。

这里的第一个参数将是我们的`getCurrentYear`。我们将创建一个助手，返回当前年份：

```js
hbs.registerHelper('getCurrentYear',);
```

第二个参数将是我们的函数。我将使用箭头函数（`=>`）：

```js
hbs.registerHelper('getCurrentYear', () => {

});
```

我们从此函数返回的任何内容都将在`getCurrentYear`调用的位置呈现。这意味着，如果我们在`footer`内部调用`getCurrentYear`，它将从函数返回年份，并且该数据将被呈现。

在`server.js`中，我们可以通过使用`return`并且具有与我们`app.get`对象完全相同的代码来返回年份：

```js
hbs.registerHelper('getCurrentYear'), () => {
 return new Date().getFullYear()
});
```

我们将创建一个新日期，并调用其`getFullYear`方法。现在我们有了一个助手，我们可以从我们的每一个渲染调用中删除这些数据：

```js
hbs.registerHelper('getCurrentYear, () => {
 return new Date().getFullYear()
});

app.get('/', (req, res) => {
 res.render('home.hbs', {
   pageTitle: 'Home Page',
   welcomeMessage: 'Welcome to my website'
 });
});

app.get('/about', (req, res) => {
 res.render('about.hbs', {
   pageTitle: 'About Page'
 });
});
```

这将非常棒，因为实际上没有必要为每个页面计算它，因为它总是相同的。现在我们已经从渲染的各个调用中删除了这些数据，我们将不得不在`footer.hbs`文件中使用`getCurrentYear`：

```js
<footer>
 <p>Created By Andrew Mead - Copyright {{getCurrentYear}}</p>
</footer>
```

而不是引用当前年份，我们将使用助手`getCurrentYear`，并且不需要任何特殊语法。当您在花括号内使用某些东西时，显然不是部分，handlebars 首先会查找具有该名称的助手。如果没有助手，它将查找具有`getCurrentYear`名称的数据片段。

在这种情况下，它将找到辅助程序，因此一切都将按预期工作。现在我们可以保存`footer.hbs`，返回浏览器，然后刷新。当我刷新页面时，我们仍然在主页上得到版权 2018：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3f8c5249-9726-429a-91a2-e4174faecd99.png)

如果我去关于页面，一切看起来都很好：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9b2adade-57f5-471e-9eb1-6e080dbe07b9.png)

我们可以通过简单地返回其他内容来证明数据是从我们的辅助程序返回的。让我们在`server.js`中注释掉我们的辅助程序代码，并在注释之前，我们可以使用`return test`，就像这样：

```js
hbs.registerHelper('getCurrentYear', () => {
 return 'test';//return new Date().getFullYear()
});
```

现在我们可以保存`server.js`，刷新浏览器，然后我们会看到测试显示如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b006455a-30e6-4c48-89c2-4458f2c4ce80.png)

因此，在版权词之后呈现的数据确实来自该辅助程序。现在我们可以删除代码，以便返回正确的年份。

# 辅助程序中的参数

辅助程序还可以接受参数，这真的很有用。让我们创建一个将成为大写辅助程序的第二个辅助程序。我们将称之为`screamIt`辅助程序，它的工作是获取一些文本，并以大写形式返回该文本。

为了做到这一点，我们将再次调用`hbs.registerHelper`。这个辅助程序将被称为`screamIt`，它将接受一个函数，因为我们确实需要运行一些代码才能做任何有用的事情：

```js
hbs.registerHelper('getCurrentYear', () => {
  return new Date().getFullYear()
});

hbs.registerHelper('screamIt', () => {

});
```

现在`screamIt`将接受要大声喊出的`text`，它将只是调用该字符串的`toUpperCase`方法。我们将返回`text.toUpperCase`，就像这样：

```js
hbs.registerHelper('screamIt', (text) => {
  return text.toUpperCase();
});
```

现在我们可以在我们的文件中实际使用`screamIt`。让我们进入`home.hbs`。在这里，我们在`p`标签中有我们的欢迎消息。我们将删除它，然后大声喊出欢迎消息。为了将数据传递给我们的辅助程序之一，我们首先必须按名称引用辅助程序`screamIt`，然后在空格后，我们可以指定要作为参数传递的任何数据。

在这种情况下，我们将传递欢迎消息，但我们也可以通过键入一个空格并传递一些其他我们无法访问的变量来传递两个参数：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Some Website</title>
  </head>
  <body>
    {{> header}}

    <p>{{screamIt welcomeMessage}}</p>

    {{> footer}}
  </body>
</html>
```

目前，我们将像这样使用它，这意味着我们将调用`screamIt`辅助程序，传入一个参数`welcomeMessage`。现在我们可以保存`home.hbs`，返回浏览器，转到主页，如下所示，我们得到了 WELCOME TO MY WEBSITE 的全大写：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6d8cf895-07da-4939-ac78-a68c68bcae60.png)

使用 handlebars 辅助程序，我们可以创建既不带参数的函数，也带参数的函数。因此，当您需要在网页内部对数据执行某些操作时，可以使用 JavaScript。现在我们已经做到了。

# Express 中间件

在本节中，您将学习如何使用 Express 中间件。Express 中间件是一个很棒的工具。它允许您添加到 Express 现有功能中。因此，如果 Express 没有做您想要做的事情，您可以添加一些中间件并教它如何做这件事。现在我们已经使用了一点中间件。在`server.js`文件中，我们使用了一些中间件，并教 Express 如何从`static`目录中读取，如下所示：

```js
app.use(express.static(__dirname + '/public'));
```

我们调用了`app.use`，这是您注册中间件的方式，然后我们提供了要使用的中间件函数。

现在中间件可以做任何事情。您可以执行一些代码，例如将某些内容记录到屏幕上。您可以对请求或响应对象进行更改。在下一章中，当我们添加 API 身份验证时，我们将这样做。我们将确保发送正确的标头。该标头将期望具有 API 令牌。我们可以使用中间件来确定某人是否已登录。基本上，它将确定他们是否应该能够访问特定路由，我们还可以使用中间件来响应请求。我们可以像在任何其他地方一样，使用`response.render`或`response.send`从中间件发送一些内容回来。

# 探索中间件

为了探索中间件，我们将创建一些基本的中间件。在我们调用`app.use`注册我们的 Express 静态中间件之后，我们将再次调用`app.use`：

```js
app.use(express.static(__dirname + '/public'));

app.use();
```

现在`app.use`是用来注册中间件的方法，它接受一个函数。因此，我们将传递一个箭头函数（`=>`）：

```js
app.use(() =>  {

});
```

`use`函数只接受一个函数。不需要添加任何其他参数。将使用此函数调用请求（`req`）对象，响应（`res`）对象和第三个参数`next`：

```js
app.use((req, res, next) =>  {

});
```

现在请求和响应对象，现在应该看起来很熟悉。这些正是我们注册处理程序时得到的完全相同的参数。`next`参数是让事情变得有点棘手的地方。`next`参数存在是为了告诉 Express 何时完成您的中间件函数，这很有用，因为您可以将尽可能多的中间件注册到单个 Express 应用程序中。例如，我有一些中间件用于提供目录。我们将编写一些日志，将一些请求数据记录到屏幕上，我们还可以编写第三个部分，用于帮助应用程序性能，跟踪响应时间，所有这些都是可能的。

现在在`app.use`函数内部，我们可以做任何我们喜欢的事情。我们可以将一些东西记录到屏幕上。我们可能会进行数据库请求，以确保用户已经通过身份验证。所有这些都是完全有效的，我们使用`next`参数告诉 Express 我们何时完成。因此，如果我们执行一些异步操作，中间件将不会继续。只有当我们调用`next`时，应用程序才会继续运行，就像这样：

```js
app.use((req, res, next) =>  {
  next();
});
```

这意味着如果您的中间件不调用`next`，则每个请求的处理程序都不会触发。我们可以证明这一点。让我们调用`app.use`，传入一个空函数：

```js
app.use((req, res, next) =>  {

});
```

让我们保存文件，在终端中，我们将使用`server.js`运行我们的应用程序，使用`nodemon`：

```js
nodemon server.js
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/786125db-b49b-4204-a886-583995fdfe2e.png)

我将进入浏览器，然后请求主页。我将刷新页面，您可以看到顶部正在尝试加载，但永远不会完成：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/af33b302-3460-4c7e-a230-c3fbf7165343.png)

现在问题不是它无法连接到服务器。它可以很好地连接到服务器。真正的问题是在我们的应用程序内部，我们有一些不调用`next`的中间件。为了解决这个问题，我们只需这样调用`next`：

```js
app.use((req, res, next) => {
  next();
});
```

现在当浏览器内部刷新时，我们得到了我们期望的主页：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ae177c74-2938-4f73-93a5-24a69c4240ba.png)

唯一的区别是现在我们有一个地方可以添加一些功能。

# 创建记录器

在`app.use`内部，我们将开始创建一个记录器，记录所有发送到服务器的请求。我们将存储一个时间戳，以便我们可以看到某人何时请求特定 URL。

在中间件内部开始，让我们获取当前时间。我将创建一个名为`now`的变量，将其设置为`newDate`，创建我们的日期对象的一个新实例，并调用`toString`方法：

```js
app.use((req, res, next) => {
 var now = new Date().toString();
 next();
});
```

`toString`方法创建一个格式良好的日期，一个可读的时间戳。现在我们有了我们的`now`变量，我们可以通过调用`console.log`来开始创建实际的记录器。

让我们调用`console.log`，传入我喜欢的任何内容。让我们在反引号内传入`now`变量，并在后面加上一个冒号：

```js
app.use((req, res, next) => {
  var now = new Date().toString();

  console.log(`${now};`)
  next();
});
```

现在如果我保存我的文件，因为`nodemon`正在运行，终端中的东西将重新启动。当我们再次请求网站并进入终端时，我们应该看到日志：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5019d745-4ca5-4c65-bfd7-5ad13577dc09.png)

目前只是一个时间戳，但我们正在正确的轨道上。现在一切都正常，因为我们调用了`next`，所以在这个`console.log`调用打印到屏幕后，我们的应用程序会继续并提供页面。

在中间件中，我们可以通过探索请求对象添加更多功能。在请求对象上，我们可以访问有关请求的一切内容-HTTP 方法、路径、查询参数以及来自客户端的任何内容。无论客户端是应用程序、浏览器还是 iPhone，所有这些都将在请求对象中可用。现在我们要提取的是 HTTP 方法和路径。

如果您想查看您可以访问的所有内容的完整列表，可以转到[expressjs.com](http://expressjs.com/)，并转到 API 参考：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b8dfc130-d80e-4dc5-a326-3f6e706eff44.png)

我们碰巧使用的是 Express 的 4.x 版本，因此我们将点击该链接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7e612137-1291-4772-b708-fba531456141.png)

在此链接的右侧，我们有请求和响应。我们将查找请求对象，因此我们将点击它。这将引导我们到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/07ed8d23-0f1d-49c2-b06c-4454be7ab31e.png)

我们将使用两个请求属性：`req.url`和`req.method`。在 Atom 中，我们可以开始实现这些，将它们添加到`console.log`中。在时间戳之后，我们将打印 HTTP 方法。稍后我们将使用其他方法。目前我们只使用了`get`方法。在`console.log`中，我将注入`request.method`，将其打印到控制台：

```js
app.use((req, res, next) => {
  var now = new Date().toString();

  console.log(`${now}: ${req.method}`)
  next();
});
```

接下来，我们可以打印路径，以便我们确切知道用户请求的是哪个页面。我将通过注入另一个变量`req.url`来实现：

```js
   console.log(`${now}: ${req.method} ${req.url}`);
```

有了这个，我们现在有一个相当有用的中间件。它获取请求对象，输出一些信息，然后继续让服务器处理该请求。如果我们保存文件并从浏览器重新运行应用程序，我们应该能够进入终端并看到这个新的记录器打印到屏幕上，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ba650386-32a1-40b2-8293-741d8abe62a8.png)

我们有我们的时间戳、HTTP 方法是`GET`，以及路径。如果我们将路径更改为更复杂的内容，例如`/about`，然后我们返回到终端，我们将看到我们访问`req.url`的`/about`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ff7dc6f1-8c40-40b2-a8ea-33cff4af309b.png)

这是一种相当基本的中间件示例。我们可以再进一步。除了只是将消息记录到屏幕上，我们还将把消息打印到文件中。

# 将消息打印到文件

要将消息打印到文件中，让我们在`server.js`文件中加载`fs`。我们将创建一个常量。将其命名为`const fs`，并将其设置为从模块中获取的返回结果：

```js
const express = require('express');
const hbs = require('hbs');
const fs = require('fs');
```

现在我们可以在`app.use`中实现这一点。我们将使用当前在`console.log`中定义的模板字符串。我们将把它剪切出来，而是存储在一个变量中。我们将创建一个名为`log`的变量，将其设置为如下所示的模板字符串：

```js
app.use((req, res, next) => {
  var now = new Date().toString();
  var log = `${now}: ${req.method} ${req.url}`;

  console.log();
  next();
});
```

现在我们可以将`log`变量传递给`console.log`和`fs`方法，以便写入我们的文件系统。对于`console.log`，我们将像这样调用 log：

```js
  console.log(log);
```

对于`fs`，我将调用`fs.appendFile`。现在您记得，`appendFile`允许您添加到文件中。它需要两个参数：文件名和我们要添加的内容。我们将使用的文件名是`server.log`。我们将创建一个漂亮的日志文件，实际内容将只是`log`消息。我们需要添加一件事：我们还希望在每个请求被记录后继续下一行，因此我将连接新行字符，即`\n`：

```js
  fs.appendFile('server.log', log + '\n');
```

如果您使用的是 Node V7 或更高版本，则需要对此行进行微小调整。如下面的代码所示，我们向`fs.appendFile`添加了第三个参数。这是一个回调函数。现在是必需的。

`fs.appendFile('server.log', log + '\n', (err) => {`

`  if (err) {`

`    console.log('Unable to append to server.log.')`

`  }`

`});`如果你没有回调函数，你会在控制台中得到一个弃用警告。现在你可以看到，我们的回调函数在这里接受一个错误参数。如果有错误，我们只是在屏幕上打印一条消息。如果你将你的行改成这样，无论你的 Node 版本如何，你都将是未来的保障。如果你使用的是 Node V7 或更高版本，控制台中的警告将消失。现在警告将会说一些诸如弃用警告。调用异步函数而没有回调是被弃用的。如果你看到这个警告，做出这个改变。

现在我们已经准备就绪，我们可以测试一下。我保存文件，这应该重新启动`nodemon`中的东西。在 Chrome 中，我们可以刷新页面。如果我们回到终端，我们仍然可以得到我的日志，这很棒：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8784f004-8b24-4050-930b-229304d7d367.png)

请注意，我们还有一个对`favicon.ico`的请求。这通常是在浏览器标签中显示的图标。我从以前的项目中缓存了一个。实际上并没有定义图标文件，这完全没问题。浏览器仍然会发出请求，这就是为什么它显示在前面的代码片段中。

在 Atom 中，我们现在有了我们的`server.log`文件，如果我们打开它，我们可以看到所有已经发出的请求的日志：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9f3671b8-59e9-4f0a-87ce-94914298c519.png)

我们有时间戳，HTTP 方法和路径。使用`app.use`，我们能够创建一些中间件，帮助我们跟踪服务器的工作情况。

现在有时候你可能不想调用 next。我们学到了在做一些异步操作后可以调用 next，比如从数据库中读取，但想象一下出了问题。你可以避免调用 next 来阻止移动到下一个中间件。我们想在`views`文件夹中创建一个新的视图。我们将称之为`maintenance.hbs`。这将是一个 handlebars 模板，当网站处于维护模式时将进行渲染。

# 没有 next 对象的维护中间件

我们将从复制`home.hbs`开始制作`maintenance.hbs`文件。在`maintenance.hbs`中，我们将擦除 body 并添加一些标签：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Some Website</title>
 </head>
 <body>

  </body>
</html>
```

如下代码所示，我们将添加一个`h1`标签来向用户打印一条小消息：

```js
 <body>
   <h1></h1>
 </body>
```

我们将使用类似`我们马上回来`的东西：

```js
 <body>
   <h1>We'll be right back</h1>
 </body>
```

接下来，我可以添加一个段落标签：

```js
 <body>
   <h1>We'll be right back</h1>
   <p>

   </p>
 </body>
```

现在我们将能够使用`p`后跟制表符。这是 Atom 中用于创建 HTML 标签的快捷方式。它适用于所有标签。我们可以输入 body 并按*enter*，或者我可以输入`p`并按*enter*，标签就会被创建。

在段落中，我会留下一条小消息：`网站目前正在更新`：

```js
 <p>
   The site is currently being updated.
 </p>
```

现在我们已经准备好了模板文件，我们可以定义我们的维护中间件。这将绕过我们的所有其他处理程序，其中我们渲染其他文件并打印 JSON，而是直接将此模板呈现到屏幕上。我们保存文件，进入`server.js`，并定义该中间件。

就在之前定义的中间件旁边，我们可以调用`app.use`，传入我们的函数。该函数将使用这三个参数：请求（`req`），响应（`res`）和`next`：

```js
app.use((req, res, next) => {

})
```

在中间件中，我们需要做的就是调用`res.render`。我们将添加`res.render`，传入我们想要渲染的文件的名称；在这种情况下，它是`maintenance.hbs`：

```js
app.use((req, res, next) => {
  res.render('maintenance.hbs');
});
```

这就是你需要做的一切来设置我们的主要中间件。这个中间件将阻止它之后的一切执行。我们不调用 next，所以实际的处理程序在`app.get`函数中，它们将永远不会被执行，我们可以测试这一点。

# 测试维护中间件

在浏览器中，我们将刷新页面，然后我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/15cdba39-3814-4d5c-91b8-8469871735bf.png)

我们得到了维护页面。我们可以转到主页，然后得到完全相同的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/31b494e9-7a29-4e75-92d3-bf6a7ad5b1ef.png)

现在还有一个非常重要的中间件部分我们还没有讨论。请记住，在`public`文件夹中，我们有一个`help.html`文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e3635d59-628c-4081-b745-dd4e9fbc077a.png)

如果我们通过在浏览器中访问`localhost:3000/help.html`来查看这个问题，我们仍然会得到帮助页面。我们不会得到维护页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5e1d306a-d8c2-4e18-a5b9-850007ada37c.png)

这是因为中间件是按照调用`app.use`的顺序执行的。这意味着我们首先设置 Express 静态目录，然后设置日志记录器，最后设置`maintenance.hbs`日志记录器：

```js
app.use(express.static(__dirname + '/public'));

app.use((req, res, next) => {
  var now = new Date().toString();
  var log = `${now}: ${req.method} ${req.url}`;

  console.log(log);
  fs.appendFile('server.log', log + '\n');
  next();
});

app.use((req, res, next) => {
  res.render('maintenance.hbs');
});
```

这是一个相当大的问题。如果我们还想使`public`目录文件（如`help.html`）私有，我们将不得不重新调整我们对`app.use`的调用，因为当前 Express 服务器正在 Express 静态中间件内响应，因此我们的维护中间件没有机会执行。

为了解决这个问题，我们将采取`app.use` Express 静态调用，从文件中删除，并在呈现维护文件到屏幕后添加。结果代码将如下所示：

```js
app.use((req, res, next) => {
  var now = new Date().toString();
  var log = `${now}: ${req.method} ${req.url}`;

  console.log(log);
  fs.appendFile('server.log', log + '\n');
  next();
});

app.use((req, res, next) => {
  res.render('maintenance.hbs');
});

app.use(express.static(__dirname + '/public'));
```

现在，无论我们要记录请求的内容，一切都将按预期工作。然后我们将检查是否处于维护模式，如果维护中间件函数已经就位。如果是，我们将呈现维护文件。如果不是，我们将忽略它，因为它将被注释掉或类似的情况，最后我们将使用 Express 静态。这将解决所有这些问题。如果我现在重新渲染应用程序，我会在`help.html`上看到维护页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/68cc0afb-4c03-45d0-b33f-633917f27264.png)

如果我回到网站的根目录，我仍然会看到维护页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/eed3d7c1-d744-4eac-8a19-c6cb715f7e0f.png)

现在，一旦我们完成了维护中间件，我们总是可以将其注释掉。这将使其不再被执行，网站将按预期工作。

这是对 Express 中间件的一个快速潜入。我们将在整本书中更多地使用它。我们将使用中间件来检查我们的 API 请求是否真的经过了身份验证。在中间件内部，我们将进行数据库请求，检查用户是否确实是他们所说的那个人。

# 总结

在本章中，您学习了 Express 以及如何使用它轻松创建网站。我们看了如何设置静态 Web 服务器，因此当我们有整个目录的 JavaScript、图像、CSS 和 HTML 时，我们可以轻松地提供这些内容而无需为每个内容提供路由。这将让我们创建各种应用程序，这将贯穿整本书的内容。

接下来，我们继续学习如何使用 Express。我们看了一下如何呈现动态模板，有点像我们在 PHP 或 Ruby on Rails 文件中所做的那样。我们有一些变量，我们呈现了一个模板并注入了这些变量。然后我们学习了一些关于 handlebars 部分的知识，它让我们可以创建可重用的代码块，比如头部和页脚。我们还学习了关于 Handlebars 助手的知识，这是一种从 handlebars 模板内部运行一些 JavaScript 代码的方法。最后，我们回到了关于 Express 以及如何定制我们的请求、响应和服务器的讨论。

在下一章中，我们将探讨如何将应用程序部署到网络上。
