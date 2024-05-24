# JavaScript Promise 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/4926BE00CFE7847E1AE00737B9B3C169`](https://zh.annas-archive.org/md5/4926BE00CFE7847E1AE00737B9B3C169)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

《JavaScript 承诺精要》是一本关于承诺这一新概念的实用指南。它提供了一个单一资源，替代了关于这个主题的所有分散信息。它详细介绍了将增强我们用 JavaScript 进行异步编程的新标准。这本书是对承诺 API 及其特性的简要但简洁的解释，以及如何在 JavaScript 编程中使用它。它涵盖了 JavaScript 承诺的基本要素，触及了在新学习中最重要的细节，并提供了一些在不同方面非常有用的提示。

承诺在大多数情况下是一个编程概念，提供了一个允许开发人员安排在尚不存在数据和值上执行工作的流程，并允许他们在未来不确定的时间点处理这些值（异步）。它还提供了一个抽象，用于处理与异步 API 的通信。目前，可以通过回调、定时器和事件在 JavaScript 中实现异步调用，但所有这些都有局限性。承诺解决了实际开发中的头痛问题，并允许开发人员与传统的做法相比，以更本地的方式处理 JavaScript 的异步操作。此外，承诺在同步功能和异步函数之间提供了一个直接的对应关系，特别是在错误处理层面。一些库已经开始使用承诺，并提供了承诺的健壮实现。你可以在许多库以及在与 Node.js 和 WinRT 交互时找到承诺。学习承诺的实现细节将帮助你避免在异步 JavaScript 世界中出现的大量问题，并构建更好的 JavaScript API。

# 本书内容概览

第一章，*JavaScript 承诺 – 我为什么要关心？*，介绍了 JavaScript 的异步编程世界以及承诺在这个世界中的重要性。

第二章，*承诺 API 及其兼容性*，带你深入了解承诺 API 的更多细节。我们还将学习当前浏览器对承诺标准的支持情况，并查看实现承诺和承诺类似特性的 JavaScript 库。

第三章，*承诺的链式调用*，向你展示了承诺如何允许轻松地链式调用异步操作以及这涵盖了什么。这一章还涵盖了如何排队异步操作。

第四章, *错误处理*, 涵盖了 JavaScript 中的异常和错误处理。本章还将解释承诺如何使错误处理变得更容易和更好。

第五章, *WinJS 中的承诺*, 探讨了 WinJS.Promise 对象及其在 Windows 应用程序开发中的使用。

第六章, *综合运用——承诺的实际应用*, 向你展示了承诺的实际应用以及我们如何在将学到的一切综合运用的场景中使用承诺。

# 本书需要什么准备

为了实现本书中你将学习的内容，你只需要一个 HTML 和 JavaScript 编辑器。你可以从以下选项中选择：

+   Microsoft Visual Studio Express 2013 for Web：这提供了功能齐全的标记和代码编辑器。

+   WebMatrix：这是运行示例代码的另一种选择。它是一个免费、轻量级、云连接的 Web 开发工具，利用最新的 Web 标准和流行的 JavaScript 库。

+   jsFiddle：这是一个在线 Web 编辑器，允许你编写 HTML 和 JavaScript 代码，并直接在浏览器中运行它。

# 本书适合谁

本书面向所有涉及 JavaScript 编程的开发人员，无论是 Web 开发还是如 Node.js 和 WinRT 等技术，这些技术都大量使用异步 API。此外，本书还针对那些想学习 JavaScript 中异步编程以及新标准将如何让这种体验变得更好的开发人员。简而言之，本书适合所有想要学习异步编程的新手，这个新手的名字叫做 JavaScript Promise。

# 约定

在本书中，你会发现有多种文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理显示如下："我们可以使用`object.addEventListener()`方法实现这种基于事件的技术。"

代码块如下所示：

```js
var testDiv = document.getElementById("testDiv");
testDiv.addEventListener("click", function(){
  // so the testDiv object has been clicked on, now we can do things
    alert("I'm here!");
});
```

**新术语**和**重要词汇**以粗体显示。例如，在屏幕上的菜单或对话框中看到的词汇，在文本中以这种方式出现：“随意命名应用程序，然后点击**确定**。”

### 注意

警告或重要注释以这样的盒子出现。

### 提示

技巧和小窍门像这样出现。

# 读者反馈

我们的读者反馈总是受欢迎的。请告诉我们你对这本书的看法——你喜欢或可能不喜欢的地方。读者反馈对我们开发您真正能从中获得最大收益的标题很重要。

如果您想给我们发送一般性反馈，只需发送一封电子邮件到`<feedback@packtpub.com>`，并通过邮件主题提及书籍标题。

如果您在某个话题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请查看我们网站上的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您已经成为 Packt 书籍的骄傲所有者，我们有很多事情可以帮助您充分利用您的购买。

## 错误

虽然我们已经竭尽全力确保内容的准确性，但错误仍然无法避免。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——如果您能将这些错误告知我们，我们将不胜感激。这样做可以避免其他读者遭受挫折，并帮助我们改进此书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击**错误报告****提交****表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，并且错误将被上传到我们的网站，或添加到该标题下的现有错误列表中。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看现有的错误。

## 盗版

互联网上版权材料的盗版是一个持续存在的问题，涵盖所有媒体。 Packt 对我们版权和许可的保护非常重视。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们可以寻求补救措施。

如果您发现任何疑似盗版的内容，请通过`<copyright@packtpub.com>`联系我们。

我们非常感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在阅读书籍过程中遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽力解决。


# 第一章：JavaScript 承诺 - 我为什么要关心？

曾经从未有过 JavaScript 如此受欢迎的时候。曾经，也许现在对一些人来说，它还是最受误解的编程语言，主要是因为它的名字，但现在它已经跻身最受欢迎的编程语言之列。此外，几乎每台个人电脑上可能都至少有一个 JavaScript 解释器在运行或至少已安装。JavaScript 日益受欢迎的原因完全在于它作为 Web 脚本语言的角色。当它最初被开发时，JavaScript 是设计在 Netscape Navigator 中运行的。在那里取得成功后，它几乎成为了所有网络浏览器中的标准配置，但 JavaScript 已经成长和成熟，现在暴露在大量与 Web 无关的开发中。在第一章中，我们将简要介绍以下内容：

+   异步编程在 JavaScript 中

+   开发者使用传统方法处理异步操作时所面临的问题

+   JavaScript 承诺简介

+   为什么在比较它与常见异步操作方式时，我们应该关心承诺。

# 异步编程在 JavaScript 中的运用

当涉及到 JavaScript 中的异步编程时，有二件事情需要讨论：Web 和编程语言。以浏览器为代表的 Web 环境与桌面环境不同，这也反映在我们为它们编程和编码的方式上。与桌面环境相反，浏览器为需要访问用户界面的所有事物提供了一个线程；在 HTML 术语中，就是 DOM。这种单线程模型对需要访问和修改 UI 元素的应用程序代码产生了负面影响，因为它将该代码的执行限制在同一个线程上。因此，我们将会有阻塞函数和线程，基本上会阻塞 UI，直到该线程执行完毕。这就是为什么，在 Web 开发中，充分利用浏览器提供的任何异步能力至关重要。

让我们回顾一些历史以获得更多背景信息。在过去，网站由完整的 HTML 页面组成，每次用户行动都需要从服务器加载整个网页。这给开发者带来了很多问题，尤其是当编写会影响页面的服务器端代码时。此外，它还导致了用户体验不佳。响应用户行动或 HTML 表单的变化是通过向表单所在的同一页面发送 HTTP `POST`请求来进行的；这导致服务器使用刚刚收到的信息刷新同一页面。整个过程和模型都是低效的，因为它导致页面内容的消失，然后重新出现，而且在慢速互联网环境下，有时内容会在传输过程中丢失。然后浏览器重新加载一个网页，重新发送所有内容，尽管只有部分信息发生了变化；这导致了带宽的浪费，并增加了服务器的负载。此外，它对用户体验产生了负面影响。后来，随着行业内不同方面的努力，异步网络技术开始出现以帮助解决这一局限性。在这一领域中，一个著名的角色是**异步 JavaScript 和 XML**（**AJAX**），这是在客户端用于创建以异步方式进行通信的网络应用程序的一组技术。AJAX 技术允许网络应用程序以异步方式发送和检索服务器上的数据，而不会干扰当前页面的 UI 和行为；基本上，无需重新加载整个页面。实现这一点的核心 API 是`XMLHttpRequest` API。

随着网络技术的发展和浏览器的进步，JavaScript 作为一种网络脚本语言变得越来越重要，使开发者能够访问 DOM，并动态地显示和与网页上呈现的内容进行交互。然而，JavaScript 也是单线程的，这意味着在任何给定时间，任何两条脚本线都不能同时运行；相反，JavaScript 语句是逐行执行的。同样，在浏览器中，JavaScript 与浏览器执行的其他工作负载（从绘制和更新样式到处理用户行动等）共享那个单线。一项活动将延迟另一项。

最初，JavaScript 旨在运行简短、快速的代码片段。主要的应用程序逻辑和计算是在服务器端完成的。自从网页内容的加载从重新加载整个页面改变到客户端以来，异步加载的开发人员开始更频繁地依赖 JavaScript 进行网络开发。现在，我们可以找到用 JavaScript 编写的完整应用程序逻辑，并且已经出现了许多库来帮助开发者这样做。

在网络开发中，我们有以下三个主要组件：

+   HTML 和 CSS

+   文档对象模型（DOM）

+   JavaScript

我将添加第四个在 AJAX 编程中扮演关键角色的组件：

+   XMLHttpRequest API

简要地说，HTML 和 CSS 用于网页的呈现和布局。DOM 用于动态显示和与内容交互。XHR 对象向网络服务器发送 HTTP/HTTPS 请求，并将服务器的响应数据加载回脚本中，中介一种异步通信。最后，JavaScript 允许开发者将所有这些技术结合起来，以创建美观、响应迅速和动态的网页应用程序。

为了克服多线程限制，开发者严重依赖事件和回调，因为这是浏览器将异步编程暴露给应用程序逻辑的方式。

在基于事件的异步 API 中，为给定对象注册一个事件处理程序，当事件被触发时调用该动作。浏览器通常会在不同的线程上执行这个动作，并在适当的时候在主线程上触发事件。

我们可以使用`object.addEventListener()`方法实现这种基于事件的技术。这个方法 simply 在被调用的目标对象上注册一个监听器。事件目标对象可能是一个 HTML 文档中的元素，文档本身，一个窗口，或其他支持事件的对象（如 XHR）。

以下代码展示了使用 HTML 和 JavaScript 创建的简单事件监听器的外观。

以下是 HTML 部分：

```js
<div id='testDiv' style="width:100px; height:100px; background-color:red">/</div>
```

以下是 JavaScript 部分：

```js
var testDiv = document.getElementById("testDiv");
testDiv.addEventListener("click", function(){
   // so the testDiv object has been clicked on, now we can do things
    alert("I'm here!");
});
```

在 HTML 部分，我们在 DOM 中定义了一个带有`testDiv` ID 的`div`元素。在 JavaScript 部分，我们在代码的第一行检索到这个`div`元素，并将其赋值给一个变量。然后，我们在那个对象上添加一个事件监听器，并将其传递给`click`事件，后跟一个匿名函数（一个没有名字的函数）作为监听函数。这个函数将在元素上发生点击事件后调用。

### 小贴士

如果你在包含`div`元素的 HTML 标记之前添加了这段 JavaScript 代码，它将会抛出一个错误。因为当代码针对它执行时，该元素还未被创建，所以代码将无法找到目标对象来调用`addEventListener`。

正如我们在之前的代码示例中看到的那样，`addEventListener`方法的第二个参数本身就是一个包含一些内联代码的函数。我们之所以能在 JavaScript 中这样做，是因为函数是一等对象。这个函数是一个回调。回调函数在 JavaScript 编程中非常重要且广泛应用，因为它们让我们能够异步地做事。

将回调函数作为参数传递给另一个函数，这只是传递了函数定义。因此，在参数中函数并不会立即执行；它会在容器函数体内某个指定点*回调*（因此得名）。这对于执行一些需要时间来完成的操作的脚本非常有用，例如向服务器发送 AJAX 请求或执行一些 IO 活动，而不会在这个过程中阻塞浏览器。

### 提示

如果你对 JavaScript 不熟悉，看到函数作为参数可能会有些不习惯，但不要担心；当你将它们视为对象时，它会变得容易。

一些浏览器 API，如 HTML5 Geolocation，是基于设计回调的。我将使用 Geolocation 的`getCurrentMethod`示例中使用回调函数。代码如下所示：

```js
navigator.geolocation.getCurrentPosition(function(position){  
  alert('I am here, Latitude: ' + position.coords.latitude + ' ' +  
                  '/ Longitude: ' + position.coords.longitude);  
});
```

在上一个示例中，我们简单地调用了`getCurrentPosition`方法，并传递了一个匿名函数，该函数反过来调用了 alert 方法，该方法将用我们请求的结果进行回调。这允许浏览器同步或异步执行此代码；因此，在获取位置时，代码不会阻塞浏览器。

在这个例子中，我们使用了内置浏览器 API，但我们也可以通过以异步方式暴露基本 API，并至少使用回调函数来使应用程序具备异步准备，涉及到 I/O 操作或计算量大的操作，这些操作可能需要花费大量时间。

例如，在回调场景中，检索某些数据的最简单代码如下所示：

```js
getMyData(function(myData){
   alert("Houston, we have : " + myData);
});
```

在之前的 JavaScript 代码中，我们定义了一个`getMyData`函数，该函数接受一个回调函数作为参数，进而执行一个显示我们应 retrieve 的数据的弹窗。实际上，这段代码使得与应用程序 UI 代码保持异步准备；因此，在代码检索数据时，UI 界面不会被阻塞。

让我们将其与非回调场景进行比较；代码如下所示：

```js
// WRONG: this will make the UI freeze when getting the data  
var myData = getMyData();
alert("Houston, we have : " + myData);
```

在上一个示例中，JavaScript 代码将逐行运行，尽管第一行还没有完成，下一行代码也将运行。这样的 API 设计会使代码 UI 阻塞，因为它将冻结 UI，直到数据被检索。此外，如果`getMyData()`函数的执行恰好需要一些时间，例如从互联网获取数据，整个用户体验将不会很好，因为 UI 必须等待这个函数执行完成。

此外，在前面 callback 函数的例子中，我们向包含函数传递了一个匿名函数作为参数。这是使用回调函数的最常见模式。使用回调函数的另一种方式是声明一个有名字的函数，然后将这个函数的名字作为参数传递。在下面的例子中，我们将使用一个有名字的函数。我们将创建一个通用函数，它接受一个字符串参数并在一个 alert 中显示它。我们将其称为 `popup`。然后，我们将创建另一个函数并称之为 `getContent`；这个函数接受两个参数：一个字符串对象和一个回调函数。最后，我们将调用 `getContent` 函数，并在第一个参数中传递一个字符串值，在第二个参数中传递回调函数 `popup`。运行脚本，结果将是一个包含第一个字符串参数值的 alert。以下是为这个例子准备的代码样本：

```js
//a generic function that displays an alert
    function popup(message) {
    alert(message);
    }
//A function that takes two parameters, the last one a callback function
    function getContent(content, callback) {
        callback(content); //call the callback function 
    }
getContent("JavaScript is awesome!", popup);
```

正如我们在 previous example 中所见，由于 callback 函数最终只是一般的函数，所以我们能够向其传递一个参数。我们可以将包含函数中的任何变量作为参数传递给 callback 函数，甚至可以是代码其他部分的全局变量。

总结来说，JavaScript 回调函数非常强大，极大地丰富了网页开发环境，从而使得开发者能够进行异步的 JavaScript 编程。

# 我为什么要关心承诺呢？

承诺与这一切有什么关系呢？好吧，让我们先定义一下承诺。

|   | *承诺代表异步操作的最终结果。* |   |
| --- | --- | --- |
|   | --*Promises/A+ 规格，[`promisesaplus.com/`](http://promisesaplus.com/)* |

所以，一个 Promise 对象代表了一个可能尚未可用的值，但会在未来的某个时刻被解决。

承诺有状态，在任何时刻，它可以处于以下之一的状态：

+   **挂起**：承诺的值尚未确定，其状态可能转变为已实现或已拒绝。

+   **实现**：承诺已成功实现，现在有一个必须不能改变的值。此外，它必须不能从已实现的状态转移到任何其他状态。

+   **拒绝**：承诺从一个失败的操作中返回，并且必须有一个失败的原因。这个原因不能改变，且承诺从这个状态不能转移到其他任何状态。

承诺只能从挂起状态转移到实现状态，或者从挂起状态转移到拒绝状态。然而，一旦一个承诺是实现或拒绝状态，它必须不再转移到任何其他状态，且其值不能改变，因为它是不可变的。

### 提示

承诺的不变特性是*非常重要的*。它帮助避免了监听器产生的意外副作用，这些副作用可能会导致行为上的意外变化，从而使得承诺在不影响调用函数的情况下，可以被传递给其他函数。

从 API 的角度来看，承诺被定义为一个具有`then`属性值为函数的对象。承诺对象有一个主要的`then`方法，它返回一个新的承诺对象。它的语法将如下所示：

```js
then(onFulfilled, onRejected);
```

以下两个参数基本上是在承诺完成时调用的回调函数：

+   `onFulfilled`：当一个承诺被满足时调用此参数

+   `onRejected`：当一个承诺失败时调用此参数

记住，这两个参数都是可选的。此外，非函数值的参数将被忽略，因此始终在执行它们之前检查传递的参数是否为函数可能是一个好习惯。

### 注意

值得注意的是，当你研究承诺时，你可能会遇到两个定义/规格：一个基于 Promises/A+，另一个是基于 CommonJS 的 Promises/A 的较旧的定义。虽然 Promises/A+是基于 CommonJS Promises/A 提案中呈现的概念和 API，但 A+实现与 Promises/A 在几个方面有所不同，正如我们在第二章《承诺 API 及其兼容性》中所见的那样。

`then`方法返回的新承诺在给定的`onFulfilled`或`onRejected`回调完成时被解决。实现反映了一个非常简单的概念：当一个承诺被满足时，它有一个值，当它被拒绝时，它有一个原因。

以下是如何使用承诺的一个简单示例：

```js
promise.then(function (value){
    var result = JSON.parse(data).value;
    }, function (reason) {
    alert(error.message);
});
```

从回调处理程序返回的值是返回承诺的实现值，这使得承诺操作可以连锁进行。因此，我们将会像以下这样：

```js
$.getJSON('example.json').then(JSON.parse).then(function(response) {
    alert("Hello There: ", response);
});
```

嗯，你说对了！前一个代码示例所做的就是在第一个`then()`调用返回的承诺上链第二个`then()`调用。因此，`getJSON`方法将返回一个包含 JSON 返回值的承诺。因此，我们可以在其中调用一个`then`方法，然后调用另一个返回的承诺上的`then`调用。这个承诺包括`JSON.parse`的值。最终，我们将取该值并在一个警告框中显示它。

## 我不能 just 使用回调吗？

回调很简单！我们传递一个函数，它在未来的某个时刻被调用，我们可以异步地做事情。此外，回调是轻量级的，因为我们需要添加额外的库。将函数作为高阶对象的使用已经内置在 JavaScript 编程语言中；因此，我们不需要额外的代码来使用它。

然而，如果不用心处理，JavaScript 中的异步编程可能会迅速变得复杂，尤其是回调。回调函数在嵌套在冗长的代码行中时，往往难以维护和调试。此外，在回调中使用匿名内联函数会使阅读调用堆栈变得非常繁琐。此外，当涉及到调试时，从嵌套的回调集中抛出的异常可能不会正确地传播到链中发起调用的函数，这使得确定错误的确切位置变得困难。而且，基于回调的结构化代码很难展开，就像滚雪球一样展开混乱的代码。我们最终会得到如下代码样本，但规模要大得多：

```js
function readJSON(filename, callback) {
    fs.readFile(filename, function (err, result) {
        if (err) return callback(err);
        try {
            result = JSON.parse(result, function (err, result) {
                fun.readAsync(result, function (err, result) {
                    alert("I'm inside this loop now");
                    });
                alert("I'm here now");
                });
            } catch (ex) {
        return callback(ex);
        }
    callback(null, result);
    });
}
```

### 注意

前面示例中的样本代码是被称为“末日金字塔”的深层嵌套代码的摘录。这样的代码在增长时，会使阅读、结构化、维护和调试变得令人望而却步。

另一方面，承诺提供了一个抽象概念，用于管理与异步 API 的交互，并在与回调和事件处理器的使用相比时，为 JavaScript 中的异步编程提供了一个更管理化的方法。我们可以将承诺视为异步编程的更多模式。

简单来说，承诺模式将使异步编程从广泛采用的延续传递风格转变为一种函数返回一个值（称为承诺），该值代表该特定操作的最终结果。

它允许你从：

```js
call1(function (value1) {
    call2(value1, function(value2) {
        call3(value2, function(value3) {
            call4(value3, function(value4) {
                // execute some code 
            });
        });
    });
});
```

致：

```js
Promise.asynCall(promisedStep1)
.then(promisedStep2)
.then(promisedStep3)
.then(promisedStep4)
.then(function (value4) {
    // execute some code
});
```

如果我们列出使承诺更易于处理的属性，它们将是以下内容：

+   使用更简洁的方法签名时，它更容易阅读

+   它允许我们将多个回调附加到同一个承诺

+   它允许值和错误被传递并冒泡到调用者函数

+   它允许承诺的链式操作

我们可以观察到，承诺通过返回值将功能组合带到同步能力，并通过抛出异常将错误冒泡到异步函数。这些是在同步世界中视为理所当然的能力。

以下示例（伪）代码展示了使用回调来组合相互通信的异步函数和用承诺来做同样事情的区别。

以下是使用回调的示例：

```js
    $("#testInpt").click(function () {
        firstCallBack(function (param) {
            getValues(param, function (result) {
                alert(result);
            });
        });
    });
```

以下是一个将之前的回调函数转换为可以相互链式的承诺返回函数的代码示例：

```js
    $("#testInpt").clickPromise()  // promise-returning function
    .then(firstCallBack)
    .then(getValues)
    .then(alert);
```

正如我们所看到的，承诺提供的平坦链使我们能够拥有比传统的回调方法更容易阅读和维护的代码。

# 总结

在 JavaScript 中，回调函数使我们能够拥有一个更响应灵敏的用户界面，它能够异步响应事件（即用户输入），而不会阻塞应用程序的其他部分。Promise 是一种模式，它允许在异步编程中采用一种标准化的方法，这使得开发者能够编写更易读、更易维护的异步代码。

在下一章中，我们将查看支持 Promise 的浏览器及其与 jQuery 的兼容性。你还将了解到支持类似 Promise 功能的库。


# 第二章：Promise API 及其兼容性

Promises 对于 JavaScript 世界来说是相当新的，但绕过方法已经存在一段时间了。正如我们在上一章所看到的，有方法可以解决 JavaScript 中的异步编程问题，无论是通过事件还是回调。你还了解到为什么 promise 与传统技术不同。

接下来，我们将详细介绍 Promise API。你还将了解 promises 标准的当前浏览器支持，并查看实现 promises 和 promise-like 特性的 JavaScript 库。在本章中，我们将涵盖以下主题：

+   Promise API 及其详细内容

+   浏览器兼容性

+   Promise 实施情况

+   具有 promise 类似特性的库

# 了解 API

在整本书中，我们将主要讨论并使用在 Promises/A+ 规范中定义的 promise。（*[`promisesaplus.com/`](http://promisesaplus.com/)*）Promises/A+ 组织制定了 Promises/A+ 规范，目的是将初始的 Promises/A 规范阐述得更为清晰、测试更为充分。以下是从他们网站引用的一段话：

|   | *Promises/A+ 是基于 CommonJS Promises/A 提案中提出的概念和 `then` API 构建的.* |   |
| --- | --- | --- |
|   | --*[`promisesaplus.com/differences-from-promises-a`](http://promisesaplus.com/differences-from-promises-a)* |

这些差异体现在三个层面：省略、添加和澄清。在省略层面，Promises/A+ 从原始版本中移除了以下功能：

+   **进度处理**：此功能包括一个在操作/promise 仍在进行中时处理的回调函数，即尚未完成或拒绝。它被移除是因为实施者认为，在实践中，这些功能证明是规格不足的，目前在 promise 实施者社区中对其行为没有达成完全一致。

+   **交互式承诺**：这个特性在之前的 Promises/A 提案中是一个扩展的承诺，它基本上为承诺方法支持了两个额外的函数；`get(propertyName)`，从 promise 的目标请求给定的属性，和 `call(functionName, arg1, arg2, ...)`，在 promise 的目标的参数上调用给定的方法/函数。在新的 A+ 规范中，这个特性以及两个函数 `call` 和 `get`，在实现 interoperable promises 所需的基本 API 时被认为是超出范围的。

+   `promise!== resultPromise`：这个特性在旧提案中是一个要求，它指出 promise 的结果不应该等于 promise，例如，`var resultPromise = promise.then(onFulfilled, onRejected)`。实际上，任何实现都可能允许 `resultPromise === promise`，只要实现满足所有要求。

在添加层面上，Promises/A+ 规格书在现有的 Promises/A 提案中增加了以下特性和要求：

+   在 `onFulfilled` 或 `onRejected` 返回一个 thenable 的情况下，包括解决过程的详细规格。

+   传递给 `onRejected` 处理程序的原因，必须是那种情况下抛出的异常。

+   必须异步调用两个处理程序 `onFulfilled` 和 `onRejected`。

+   必须调用两个处理程序 `onFulfilled` 和 `onRejected`。

+   实现必须遵守在相同承诺上连续调用 `then` 方法时处理程序 `onFulfilled` 和 `onRejected` 的确切调用顺序。用更通俗的话来说，这意味着如果像 `promise.then().then()` 这样在同一个承诺上多次调用 `then` 方法，所有这些 `then` 调用中使用的 `onFulfilled` 处理程序必须按照原始调用 `then` 的顺序执行。因此，第一个 `then` 函数中的 `onFulfilled` 回调将首先执行，接着是第二个 `then` 中的 `onFulfilled` 回调，依此类推。在這種情況下，`onRejected` 回调的执行也是如此。是否非常复杂？也许下面的例子可以解释得更好：

    ```js
    var p = [[promise]];
    p.then();
    p.then();
    ```

    前面的代码不同于下面的代码行：

    ```js
    promise.then().then();
    ```

    区别在于 `promise.then()` 可能返回一个不同的承诺。

最后，在澄清的层面上，Promises/A+ 提案对 Promises/A 使用了不同的命名，因为新规格的作者希望反映在承诺实现中已经传播的词汇。这些变化包括以下内容：

+   承诺状态被称为挂起、满足和拒绝，代替未满足、满足和失败。

+   当一个承诺被满足时，承诺有一个 *值*；同样，当一个承诺被拒绝时，它有一个 *原因*。

`then` 方法是 API 中的主要角色。如果一个对象没有指定 `then` 方法来检索和访问其当前或最终值或原因，那么它就不被视为一个承诺，正如我们在上一章所看到的。这个方法需要两个参数，都必须是函数，如下面的例子所示：

```js
promise.then(onFulfilled, onRejected);
```

让我们深入探讨 `then` 的细节和其参数的规格，考虑到之前代码示例中的简单 `then` 方法：

+   `onFulfilled` 和 `onRejected` 两个参数都是可选的。

+   两个参数都必须是函数；否则，它必须被忽略。

+   在同一个 `then` 调用中，两个参数不得调用超过一次。

+   `onFulfilled` 参数必须在承诺被满足后调用，以承诺的值为第一个参数。

+   `onRejected` 参数必须在承诺被拒绝后调用，以拒绝的原因作为其第一个参数。

+   `onFulfilled` 和 `onRejected` 参数不能作为 `this` 值传递，因为如果我们对 JavaScript 代码应用严格模式，这将在处理程序内部被当作未定义处理；在怪异模式中，它将被当作那个 JavaScript 代码的全球对象处理。

+   `then` 方法可以在同一个承诺上被调用多次。

+   当一个承诺被满足时，所有相应的 `onFulfilled` 处理程序必须按照它们发起的 `then` 调用的顺序执行。同样的规则适用于 `onRejected` 回调。

+   `then` 方法必须返回一个承诺，如下所示：

    ```js
    promiseReturned = promise.then(onFulfilled, onRejected);
    ```

+   如果 `onFulfilled` 或 `onRejected` 返回一个值 `x`，承诺解决程序必须被调用以解决值 `x`，如下面的代码所示：

    ```js
    promiseReturned = promise1.then(onFulfilled, onRejected);
    [[Resolve]](promiseReturned, x).
    ```

+   如果 `onFulfilled` 或 `onRejected` 处理程序抛出异常 `e`，`promiseReturned` 必须以 `e` 为拒绝或失败的原因被拒绝。

+   如果 `onFulfilled` 不是一个函数且承诺被满足，`promiseReturned` 必须以相同的值被满足。

+   如果 `onRejected` 不是一个函数且 `promise1` 被拒绝，`promiseReturned` 必须用相同的原因拒绝。

前面列表是对在 Promises/A+ 开放标准中定义和指定的承诺和 `then` 方法的详细规范。我们之前谈到了承诺解决程序，但我们还不知道它是什么。好吧，承诺解决程序基本上是一个抽象操作，它接受一个承诺和一个值作为参数，如下所示：

```js
[[Resolve]](promise, x)]
```

如果 `x` 是一个 thenable，意味着它是一个定义了 `then` 方法的的对象或函数，`resolve` 方法将尝试强制一个承诺假设 `x` 的状态，假设 `x` 至少有点像一个承诺。否则，它将以值 `x` 满足承诺。

承诺解决程序使用的处理 thenables 的技术使得只要承诺暴露出一个符合 Promises/A+ 标准的 `then` 方法，承诺实现就可以可靠地相互工作。此外，它还允许实现*整合*具有合理 `then` 方法的的非标准实现。

| ``` |
| --- |
| ``` |

承诺解决过程允许我们有一个正确的`promise.resolve`实现。它也是保证`then`正确实现所必需的。你可能会注意到承诺解决过程中没有返回值，因为它是一个抽象过程，可以以任何作者认为合适的方式实现。因此，只要能达到最终目标，即把承诺置于与*x*相同的状态，返回值就留给实现者来决定。所以，从概念上讲，它影响承诺的状态转换。

尽管承诺解决过程的实现留给实现者，但它有一些我们想要遵守的规则，如果我们想要在需要运行它时符合该提案。这些规则如下：

1.  如果一个承诺和*x*引用同一个对象，那么在`onRejected`处理程序中，承诺应该以一个`TypeError`作为拒绝的原因。

1.  如果*x*是一个承诺，我们应该采用其当前状态。这个规则允许使用特定于实现的的行为来实际采用已知符合规范的承诺的状态。以下是一些条件：

    +   如果*x*处于待定状态，承诺必须保持待定状态，直到*x*被满足或被拒绝。

    +   如果/当*x*被满足时，承诺应该用*x*具有的相同值被满足。

    +   如果/当*x*被拒绝时，承诺应该用*x*被拒绝的相同原因被拒绝。

1.  如果*x*是一个对象或函数，且不是承诺，则执行以下操作：

    +   当我们想要调用`then`时，方法应该是`x.then`。这是一个必要的防御措施，可以确保在`accessor`属性面前的一致性。这个属性值在我们每次获取它时都可能发生变化。

    +   如果获取`x.then`属性最终抛出了异常`e`，那么该承诺应该用`e`作为原因被拒绝。

    +   如果`then`是一个函数，用*x*调用它，`this`的值为值。第一个参数应该是`resolvePromise`，第二个参数应该是`rejectPromise`。

    +   如果`then`不符合函数的要求，直接用*x*满足承诺。

1.  如果*x*既不是对象也不是函数，承诺应该用*x*来满足。

让我们看看第三条规则。我们发现，如果`then`是函数，第一个参数应该是`resolvePromise`，第二个参数应该是`rejectPromise`，其中以下规则适用：

1.  如果/当用值*z*调用`resolvePromise`时，实现必须运行`[[Resolve]](promise, z)`。

1.  如果/当`rejectPromise`用理由*j*被调用时，实现必须用理由 j 拒绝该承诺。

1.  如果同时调用了处理程序`resolvePromise`和`rejectPromise`，或者在同一参数上多次调用，第一次调用应优先考虑，其他后续调用均忽略。

1.  如果调用`then`导致抛出异常 e，我们有两个条件：

    +   如果`resolvePromise`或`rejectPromise`处理程序已经被调用，我们应该忽略`then`

    +   如果不然，实现应当拒绝该承诺，并以`e`作为返回的原因。

之前那长长的规则列表作为实现者的指导。所以，如果你在自己的公共 API 中实现`then`，这些规则应当适用于你的算法，以符合 Promises/A+标准规范。我向 Brian Cavalier 询问了关于 PRP 的需求，他添加了以下内容：

> **PRP 最重要的方面之一是，它被精心设计，以允许不同的承诺实现以可靠的方式互操作。**

此外，承诺解决程序甚至允许在非符合（略微危险）的 thenables 面前保持正确性。一个例子就是使用`resolve`函数将 jQuery 的承诺版本（不符合 A+标准）转换为非常简单的符合标准的承诺。以下代码说明了这种实现：

```js
// an ajax call that returns jquery promisevar jQueryPromise = $.ajax('/sample.json'); //correct it and convert it to a standard conforming promisevar standardPromise = Promise.resolve(jQueryPromise); 
```

归根结底，Promises/A+的核心目标是提供尽可能简单、最小的规范，以允许不同承诺实现之间的可靠互操作，即使面临危险。

### 注意

为了消除可能产生的任何混淆，承诺解决程序并不完全等同于某些实现在其公共 API 中提供的`promise.resolve`方法。

与 Promises/A+标准的核心目标保持一致，Promises/A+组织创建了一个符合性测试套件，以测试承诺库或 API 实现是否符合 Promises/A+规范。这些测试，可以在[`github.com/promises-aplus/promises-tests`](https://github.com/promises-aplus/promises-tests)找到，通过测试`then`来检查承诺解决程序的正确性。这些测试也旨在为实现是否满足要求并提供更具体的指导和证据，符合标准。

# 浏览器支持和兼容性

JavaScript 与浏览器紧密耦合，承诺也是如此，因为承诺在之前的 ECMAScript 版本中不是一个标准，并且将成为新的 ECMAScript 6 版本的组成部分；它们不会在所有浏览器上得到支持。此外，承诺可以被实现，我们将看到几个库提供类似承诺的功能或暴露承诺能力。在本章剩余的部分，我们将涵盖这两个对于使用承诺至关重要的要点。

## 检查浏览器兼容性

与任何客户端技术一样，JavaScript 是为了与 HTML 页面一起在网页浏览器中使用而专门开发的。它利用浏览器来完成工作，这就是为什么它是一种脚本语言。一旦脚本发送到浏览器，接下来如何处理就取决于浏览器了。这里有很大的依赖性；因此，浏览器兼容性至关重要。

一些浏览器已经有了承诺的实现；在撰写本书时，支持承诺的浏览器选择很少，正如 Kangax 所示的以下 ECMAScript 6 兼容性表所示：

![检查浏览器兼容性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-prms-ess/img/00002.jpeg)

来源：[`kangax.github.io/compat-table/es6/#Promise`](http://kangax.github.io/compat-table/es6/#Promise)

### 注意

**兼容性表格中使用的缩写**

IE 代表 Internet Explorer，FF 代表 Firefox，CH 代表 Chrome，SF 代表 Safari，WK 代表 Webkit，OP 代表 Opera。

正如前表所示，只有最新三个版本的 Firefox（截至版本 29）和 Chrome（截至 32 版本）默认启用承诺。不必担心，因为有一个 polyfill 可以将承诺功能添加到尚不支持它的浏览器中。

### 注意

补丁是一个相对较新的术语，由 Remy Sharp 提出，并在网页开发者社区中流行起来。它代表了一段代码，提供了我们期望浏览器原生提供的技术和行为。我们可以把它当作计算机领域的补丁来思考。

这个施展魔法的 polyfill 并为我们提供承诺支持的功能可以从这个链接下载：[`www.promisejs.org/polyfills/promise-4.0.0.js`](https://www.promisejs.org/polyfills/promise-4.0.0.js)。它基本上为尚未原生实现承诺的浏览器添加了承诺支持。它还可以用于为 Node.js 提供承诺支持。以下代码示例展示了如何在我们的代码文件中包含它：

```js
<script src="img/promise-4.0.0.js"></script>
```

我们展示 ECMAScript 6 兼容性表是因为承诺是 ECMAScript 6 规范的一部分，该规范将承诺作为一等语言特性提供，并且实现基于 Promises/A+ 提案。

## 具有 promise-like 功能的库

承诺的概念在网页开发和 JavaScript 的世界中并不新鲜。开发者可能已经在通过库以非标准化方式在 JavaScript 中遇到或使用过承诺。这些库是承诺概念的实现；其中一些是符合规范的实现，并开始采用承诺模式，而许多则不是。此外，其中一些库不符合 Promises/A+ 标准，这在选择在我们的项目中使用哪些 JavaScript 库时是一个非常重要的要求。

### 提示

开发者可以通过使用合规性测试套件来测试他们实现的库和 API 是否符合 Promises/A+标准。

以下是完全符合 Promises/A+规范的一些库，因此我毫不犹豫地推荐它们：

+   **Q.js**：由 Kris Kowal 和 Domenic Denicola 开发，它是一个功能完备的承诺库，包括适用于 Node.js 的适配器和支持进度处理器的支持。您可以从[`github.com/kriskowal/q`](https://github.com/kriskowal/q)下载。

+   **RSVP.js**：由 Yehuda Katz 开发，它具有非常小巧轻量的承诺库。您可以从[`github.com/tildeio/rsvp.js`](https://github.com/tildeio/rsvp.js)下载。

+   **when.js**：由 Brian Cavalier 开发，它是一个中介库，包括管理预期操作集合的功能。它还具有暴露承诺的进度和取消处理器的功能。您可以从[`github.com/cujojs/when`](https://github.com/cujojs/when)下载。

此外，我们还有`then`([`github.com/then`](https://github.com/then))，这是一组简单的 Promises/A+实现库，符合规范并扩展了一些功能，例如在承诺被满足或拒绝时进行进度处理。

另外，著名的 jQuery 有一个称为 Deferred 的 API——位于[`api.jquery.com/jquery.deferred/`](http://api.jquery.com/jquery.deferred/)，声称与承诺相似。直到版本 1.8，jQuery 的 Deferred 没有从`then`返回新的承诺对象，如规范所要求；因此，依赖 jQuery 的开发人员没有得到承诺模式的全功率和能力。此外，使用此实现编写的许多代码与其他确实符合规范的承诺实现不完全兼容。Deferred 不符合 Promise/A+规范，至少不符合规范的第二部分，该部分指出在执行处理器之一时`then`不会返回新的承诺对象。因此，我们无法实现`then`函数的组合和链式调用，以及由于链断裂而导致的错误冒泡，这两个规范中最重要的点。这使得 jQuery 与众不同且某种程度上不那么有用。尽管如此，如果我们需要使用 jQuery 或其他不遵循规范的库暴露的`promise`对象，我们可以使用前面提到的库之一将非符合规范的承诺转换为符合 A+提案的真实承诺。例如，使用 Q，我们可以有以下代码将 jQuery 承诺转换为标准承诺：

```js
var SpecPromise = Q.when($.get("http://example.com/json"));
```

另一个例子是使用承诺多填充库（[`www.promisejs.org/polyfills/promise-4.0.0.js`](https://www.promisejs.org/polyfills/promise-4.0.0.js)），如下代码所示：

```js
var specPromise = Promise.resolve($.ajax(' http://example.com/json););
```

尽管这些承诺实现遵循标准化的行为，但它们的整体 API 存在差异。

# 摘要

正如我们所看到的，承诺（promises）的概念并不非常新，并且在 JavaScript 中已经存在，通过不同的库实现了不同的实现方式，无论是符合标准的还是其他方式。然而，现在，所有这些努力都在 Promises/A+社区规范中得到了总结，大多数库都符合这个规范。因此，我们现在可以通过包含在 ECMAScript 6 下一个版本中的标准`Promise`类，在 JavaScript 中得到对承诺的内置支持，使得网络平台 API 能够为其异步操作返回承诺。此外，我们深入讲解了承诺 API 和`then`方法，并了解了新标准在当前浏览器中的兼容性。最后，我们简要介绍了几个实现承诺并符合 Promises/A+规范的库。

在下一章中，我们将讲解承诺的链式调用以及如何使用`then`方法来实现它，以启用多个异步操作。


# 第三章：承诺的链式调用

承诺（promises）最重要的特性之一是能够链式调用和管理异步操作的序列。在前一章中，我们学习了承诺 API 的详细信息以及它是如何工作的；特别地，我们看到了`then`方法是如何工作的。我们还了解了当前浏览器对承诺的支持情况以及实现和扩展 JavaScript 承诺的库。在本章中，我们将涵盖以下主题：

+   如何在异步 JavaScript 中实现链式调用

+   使用承诺实现链式调用

+   从回调地狱转换为组织良好的承诺链

# 前所未有的链式调用

如前两章所学习，承诺倾向于将同步编程的力量带入异步函数中。承诺的这种能力包括同步函数的两个关键特性：

+   一个返回值的函数

+   一个抛出异常的函数

这些特性的重要性在于，它们可以用来将一个函数返回的值直接传递给另一个函数——而且不仅仅是一次；这可以转化为将这些函数一个接一个地链式调用的能力，其中这个链中元素之间的绑定关系是每个操作的承诺返回值。现在，第二个特性所暗示的内容非常重要，因为抛出异常可以让我们首先检测到过程是否失败；其次，它允许我们通过任何在链中处理捕获的函数来捕获这些异常，并帮助我们避免在这些问题被这些链式函数丢失。

那么，这在异步世界中是如何体现的呢？

首先，在异步世界中，一个人不能简单地返回值，因为这些值还没有及时准备好。同样，我们也不能抛出异常，基本上是因为没有人在那里接住这些被抛出的异常。因此，开发者们为了解决这个问题，退而求其次地使用了嵌套回调。这让他们能够用带有返回值的函数进行链式调用，但这以可维护性、可读性和额外的代码行数为代价。当代码行数增加，嵌套回调深度增加时，代码在需要编辑或出现错误时变得更加难以维护和调试。此外，嵌套回调对可读性产生负面影响，开发者需要折叠和展开括号以跟踪代码，从而知道回调函数从哪里开始，到哪里结束。

此外，在嵌套回调中捕获错误非常吃力，开发人员需要手动将错误逐层上传递。这种异步编程中的折磨闻名，被称为*回调地狱*；这通常会导致代码看起来像下面的伪代码一样：

```js
function shout(shoutTxt, callbackFunct) {
    alert(shoutTxt);
    callbackFunct("b");
}

shout('First Shout!', function (a) {
    if (a == "a"){
        alert("hey, there is an error!");
    }
    else {
        shout('Shout Again!', function (a) {
            shout('Third shout!', function (a) {
                a = "c";
                if (a == "c") {
                    shout('I am inside the third shout!', function (a) {
                        alert("hey, I can " + a.toString());
                    });
                } else {
                    shout('I am still inside the third shout!', function (a) {
                        alert("Alright I am tired");
                    });
                }
            });
        });
    }
});
```

在前一个例子中，你会注意到`function`和`});`在看似代码金字塔中广泛存在，考虑到我们甚至没有包括错误处理代码。之前的例子在小型规模上展示了*回调地狱*的样子。我们还可以观察到，在 JavaScript 编程中非常流行的嵌套回调——可能会无控制地增长成纠缠在一起且难以维护的代码。所以想象一下，在更复杂的场景中代码会是什么样子。

然而，开发者可以实施一些补救措施，以使嵌套回调更具可读性和可维护性。这些补救措施包括在回调参数中使用命名函数而不是匿名函数。另一个解决方案是将代码分解成更小的块，通过将执行特定任务的代码放入单独的模块中，然后将该模块插入到应用程序代码的其他位置。然而，这些补救措施更多的是一个变通方法，而不是一种标准做法；此外，这些变通方法仍然不足以完全解决异步操作链式调用的概念。

另一方面，Promise 在更多意义上以*开箱即用*的方式提供了我们在同步编程中拥有的功能组合，与 JavaScript 中的异步编程相比。

为什么这么说？因为规范指出，一个 Promise 必须提供一个`then`方法。不仅如此；规范还要求`then`函数，或任何具有合规实现的任何其他函数，应返回一个 Promise。返回的 Promise 如果被满足，则包含一个值；如果被拒绝，则包含一个异常。因此，`then`可以利用返回的 Promise 与另一个`then`函数结合，以组合一个链式调用的链，其中第一个操作的结果将传递给下一个操作，依此类推。此外，这个链在任何时刻都可以被一个拒绝切断，这可以被链中的任何声明异常处理代码的操作处理；换句话说，错误会自动通过该链冒泡上去。

### 提示

一些 Promise 的爱好者认为，Promise 的链式调用是新标准中最棒的部分。

在 JavaScript 编程中，当我们需要执行多个异步操作的场景下，链式调用非常重要。这些场景包括一个操作的工作依赖于前一个操作的结果。此外，可能第一个操作需要在返回结果之前处理一些代码，然后才能将其传递给下一个操作。记住，所有这些都应该在不阻塞其他线程的情况下进行，尤其是 UI 线程。因此，我们需要一种简单、标准的机制来链式这些异步操作，这正是 Promise 提供的内容。

当涉及到链式承诺时，链可以深入到我们想要的程度，因为`then`总是返回一个承诺。然而，如果我们进行如`promise.then(onFullfilled)`的调用，需要注意的是`onFulfilled`函数只能在承诺完成其过程后调用，以承诺的值为第一个参数。因此，如果我们在一个`then`内部返回一个简单值并将其链接到另一个`then`，下一个`then`将以该简单值为参数调用。如果我们想在第一个`then`中返回一个承诺，那么接下来的`then`将不得不等待返回的承诺，并且只有在那个承诺被解决或完成后才会被调用或执行。

让我们通过实际操作来看看这一点。以下是一个非常基础的示例代码，演示了链式承诺：

```js
var promiseObj = function (time) {
    return new Promise(function (resolve) {
        setTimeout(resolve, time);
    });
};

promiseObj(3000).then(function () {
    alert("promise 1");
}).then(function () {
    alert("another promise");
});
```

脚本非常直接，你可以在任何开发环境中编写它，甚至可以在 JSFiddle.net 等在线代码编辑器中编写。首先，通过定义一个`promiseObj`对象来创建一个承诺。这个对象是一个函数，一次接收一个参数，并返回一个新的承诺。

### 提示

请记住，目前并非所有浏览器都支持承诺（promises），正如我们在第二章《承诺 API 及其兼容性》中学到的那样，*承诺 API 及其兼容性*。为了做到这一点，你需要在一个兼容的浏览器中运行或测试 jsFiddle 中的代码。参考这一章节来检查兼容的浏览器。

我们使用`new Promise`来构造承诺。构造函数接受一个匿名函数，该函数将执行工作。这个函数传递一个`resolve`参数，该参数将满足承诺。在这个构造函数内部，我们调用`resolve`参数来执行一个`setTimeout`函数，除了将在给定时间后执行的函数外，还有一个`time`参数。因此，`setTimeout`将解决承诺。

代码的第二部分是发生链式的地方。我们首先调用我们刚刚创建的`promiseObj`；由于它会返回一个承诺，我们可以对它调用`then`。根据定义，`promiseObj`接受传递给`setTimeout`函数的`time`参数（以毫秒为单位）。在这里，我们传递了`3000`（3 秒），并在其中简单地调用了一个`alert()`函数，该函数将在屏幕上弹出，如下面的屏幕截图所示：

![前所未有的链式调用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-prms-ess/img/00003.jpeg)

现在，由于`then`返回一个承诺，我们可以链式调用另一个`then`；这将在承诺解决后执行，并依次执行一个`alert()`函数。虽然上一个例子非常基础，但它展示了我们如何轻松地使用承诺链式异步操作。

让我们尝试将前面看到的嵌套回调示例转换为承诺的链式调用。为了说明目的，我将添加一个 HTML 元素`div`，在承诺传播时用内容填充它。

HTML 部分如下：

```js
<div id="log"></div>
```

JavaScript 部分如下：

```js
var log = document.getElementById('log'); 
var shout = new Promise(function (resolve) {
    log.insertAdjacentHTML('beforeend', '(<small>Promise started </small>)<br/>');
    window.setTimeout( 
    function () {
        resolve('First Shout!'); // fulfill the promise !
    }, 2000);
});

shout.then(function (val) {
    log.insertAdjacentHTML('beforeend', val + '  (<small>Promise fulfilled</small>)<br/>');
    var newVal = 'Shout Again!';
    return newVal;
}).then(function (val) {
    log.insertAdjacentHTML('beforeend', val + ' (<small>Promise fulfilled</small>)<br/>');
    var newVal2 = "Third shout, you're out!";
    return newVal2;}).then(function (val) {
    log.insertAdjacentHTML('beforeend', val + ' (<small>Promise fulfilled</small>)<br/>');
    return val;
});
```

在 HTML 中，我们只有一个带有 ID 为 log 的空`div`元素。在 JavaScript 中，我们首先声明一个名为`log`的变量来持有`div`元素。然后，我们构建一个新的 promise，并将其分配给一个名为`shout`的变量。在这个 promise 对象内部，我们添加了文本以强调我们刚刚开始了 promise。我们承诺的是等待 2 秒（2000 毫秒）后的`shoutText`字符串。再次，我们使用了`window.setTimeout`函数来模拟一个需要一些时间才能完成的异步操作。它在给定时间后通过解决它来满足 promise。

接下来，我们使用`then`方法调用`shout`，在其中定义了当 promise 被满足时它会做什么。在第一个`then`方法中，我们简单地将包含`shoutText`值的`val`参数传递给`log.insertAdjacentHTML`函数。这将在包含文本`Promise fulfilled`的`div`元素的旁边显示该值，字体较小。接着，我们定义了一个新变量`newVal`，给它赋值为`Shout Again!`，然后返回它。继续前进，第二个`then`也显示了从前一个 promise 调用返回的值。我们还定义了一个新变量，给它赋了一个文本值，然后返回它。最后一个`then`调用只是将`val`的值（此时等于`newVal2`）添加到`div`元素的内容中。请注意，`val`持有由 promise 从一次操作传递到下一次操作链中返回的值的内容。

### 提示

这个例子也可以在 JSFiddle.net 上进行测试。

## 顺序链式调用

我们不仅可以将异步操作与 promise 串联，还可以以一种方式将它们串联，使它们按照顺序执行这些操作。正如我们在本章中早些时候所学习的那样，如果一个`then`操作返回一个值，那么随后的`then`将以该值调用，除非第一个`then`返回一个 promise；如果这样，随后的`then`将等待返回的 promise，并且只有在那个 promise 得到满足或拒绝时才会被调用。这个规则允许我们以这样的方式排队这些异步操作，使得每个操作将等待前一个操作完成，从而按顺序运行。让我们看一个更好地解释这个的例子。在这个例子中，我们有一个名为`getData`的函数，它接受一个 JSON 文件并从那个 JSON 文件中获取数据。第一个 JSON 文件有类别，对于每个类别，我们需要按顺序获取每个类别的项目。让我们使用以下代码来完成这个：

```js
getData(jsonCategoryUrl).then(function(data) {
//get the items per category 1 
getItemsPerCategory(data.categories[0]).then(function(items) 
{
        //items are retrieved here
});
  return getData (data.categories[0]); //return category 1
}).then(function(category1) {
   alert("We now have category 1", category1);
//return category 2
return getData (data.categories[1]); 
}).then(function(category2) {
alert("We now have category 2", category2);
//return category 3
return getData (data.categories[2]); 
});
```

之前的代码示例通过`jsonCategoryUrl`函数异步调用来获取一系列分类；之后，我们通过传递`data.categories[0]`参数来请求这些分类中的第一个，然后将第一个分类传递给下一个`then`调用。在这些链式承诺的第二链接中，我们通过传递`data.categories[1]`参数获取第二个分类，并将其传递给最后的`then`调用，反过来又获取第三个分类，`data.categories[2]`。这个例子向我们展示了，如果我们需要一个链式操作，其中一环依赖于或需要等待前一个承诺的结果，我们如何在链式承诺中排队进行异步操作。

这种功能确实使承诺从常规回调模式中脱颖而出。我们可以通过创建一个简短的方法来获取分类，从而优化之前的代码，如下面的代码所示：

```js
//declare categorypromise varvar catPromise;
function getCategory(i) {
//if catPromise have no value get Data else just populate it from value of catPromise.

  catPromise = catPromise || getData(jsonCategoryUrl); 
  return catPromise.then(function(category) {
      //get the items under that category
      return getData(category.Items[i]);
  })
}
getCategory(0).then(function(items) {
alert(items);
    return getCategory(1);
}).then(function(items) {
   alert(items);
});
```

在之前的代码示例中，我们首先声明了一个名为`catPromise`的变量来保存承诺的分类。接下来，我们声明了一个名为`getCategory(i)`的函数，它将`i`的值作为参数；在这个函数内部，我们将`catPromise`设置为通过`getData(jsonCategoryUrl)`函数获取的 JSON 数据；然而，通过使用`||`（或）运算符，我们首先检查`catPromise`对象是否有值，这样我们就不需要再次获取分类的 JSON 文件，只需一次即可。当我们用值`0`调用`getCategory`时，它会获取第一个分类；之后，它会用`getCategory(1)`获取下一个分类，并将其传递给最后的`then`调用。这样，在我们调用`getCategory`之前，我们不会下载分类的 JSON 文件；然而，无论我们再次调用`getCategory`函数多少次，我们都不会需要重新下载分类的 JSON 文件；相反，我们会重复使用它，因为它将在操作序列中再次被调用。由于`getCategory`函数返回另一个承诺对象，它允许你实现承诺流水线，其中第一个操作的结果被传递给随后的一个操作。此外，这个示例展示的重要特性是，如果传递给`then`的函数返回一个新的承诺，那么`then`返回的承诺将不会被履行，直到那个函数返回的承诺被履行，从而在承诺的链中排队进行异步操作。

在此之前，示例清楚地展示了承诺是如何解决传统回调模型及其所生成的金字塔代码的。

# 摘要

承诺是一种很好地解决异步操作复杂性的方法。承诺在 JavaScript 中为异步操作的轻松链式提供了一种很好的机制。它们允许你以比回调模式更好的方式来管理这些操作的序列。

在下一章中，我们将学习如何在承诺中处理错误，了解如何使用承诺来管理异常，并且回顾一些在承诺中处理异步操作过程中出现的错误的例子。


# 第四章：错误处理

像任何编程语言一样，错误和异常是必然会出现的；为了确保代码流畅运行和更容易调试，我们需要抛出和捕获这些异常。用异步 JavaScript 编程处理错误可能很繁琐。然而，承诺为我们提供了一个处理错误的伟大机制，我们将在本章探索。在前一章中，我们学习了异步操作的链式调用。我们还看到了如何从回调地狱转变为更易读和可维护的承诺链。在本章中，我们将涵盖以下主题：

+   承诺中的异常和错误处理

+   如何使用`then`和`catch`方法处理承诺中的错误

# 异常与承诺

在异步 JavaScript 编程中处理异常没有标准或公认的机制，这主要是因为这些异常发生在未来，而且无法确定一个被拒绝的承诺最终是否会得到处理。此外，在异步世界中，我们并不能简单地抛出异常，因为当它们还没有准备好时，没有人去捕获这些错误。因此，为了解决这个问题，创造了一些替代方案。处理错误和异常的常见技术涉及将这些异常手动传递给嵌套回调的链。另一方面，承诺提供了内置的错误处理和冒泡功能。它们通过声明你的函数应该返回一个如果失败则被拒绝的承诺来实现这一点。

在第一章中，我们学习了*JavaScript 承诺 - 我为什么要关心？*的内容，了解到一个承诺可以存在于三种不同的状态：等待中、已兑现和已拒绝。拒绝状态的要求如下：

+   承诺必须不会改变到任何其他状态（等待中或已兑现）

+   承诺必须有一个被拒绝的理由，并且这个理由在承诺内部不能改变

这两个拒绝状态的要求允许错误处理，更重要的是错误组合，即承诺被拒绝的原因会自动沿着承诺链使用`then`方法冒泡上来。承诺允许错误沿着代码链传播，类似于同步异常。此外，它还提供了一种更简洁的方式来处理异步中的错误。

通常，在使用回调方法的异步编程中，我们需要将我们认为不安全的代码块包裹在一个`try` catch 块中。以下代码示例展示了这一点：

```js
try {
    return JSON.parse("json"); //this will cause an error
} catch (error) {
    alert("I have an error with the following details: \n" + error);
}
```

前面的代码示例显示了一个意图提示错误的脚本块。在这个代码块中，我们将`return JSON.parse("json");`包裹在`try`...`catch`块中，并故意通过传递一个无效的 JSON 参数来引起错误。JavaScript 函数`JSON.parse()`用于将 JSON 文本转换为 JavaScript 对象。在我们的例子中，它将尝试解析文本`json`并抛出错误。我们将捕获这个异常，并显示带有该错误详情的警告框。

如果我们把这个脚本运行在一个 HTML 页面或者在线 JavaScript 编辑器中，结果将是一个包含以下消息的警告框：

**我有一个带有以下详情的错误：**

**SyntaxError: Unexpected token j**

我们可以通过这个公共 jsFiddle URL 浏览代码：[`jsfiddle.net/RamiSarieddine/mj6hs0xu/`](http://jsfiddle.net/RamiSarieddine/mj6hs0xu/)

正如我们迄今为止所看到的，promises 要么被满足要么被拒绝，如果 promise 中发生错误。当一个 promise 被拒绝时，它与同步代码中抛出异常类似。一个带有`then`函数的标准 promise 取两个参数`onFulfilled`和`onRejected`，如下面的代码所示：

```js
promise.then(onFulfilled, onRejected)
```

`onRejected`参数是一个将作为错误处理器的函数，当 promise 失败时将被调用。当 promise 中发生错误或异常时，这意味着 promise 被拒绝，并会将引发的错误提供给`onRejected`错误处理程序。当我们调用`onRejected`时，有两个考虑因素，可以总结如下列表，假设我们有一个简单的`promise.then(onFulfilled, onRejected)`：

+   `onRejected`只能在 promise 被拒绝后调用，以其拒绝原因作为其第一个参数

+   `onRejected`必须不会被多次调用

第二个考虑非常直接。`onRejected`函数不会在同一个 promise 上调用多次。第一个考虑断言，如果一个 promise 被拒绝，`onRejected`将不会被调用。

尽管如此，拒绝也隐式地发生，以及在 promise 的构造函数回调中抛出错误的情况。以下代码示例说明了这一点：

```js
var promiseTest = new Promise(function (resolve) {
    // JSON.parse will throw an error because of invalid JSON
    // so this indirectly rejects
    resolve(JSON.parse("json"));
});

promiseTest.then(function (data) {
    alert("It worked!" + data);
}, function (error) { //error handler
    alert(" I have failed you: " + error);
});
```

在前面的代码中，我们定义了一个新的 promise 叫做`promiseTest`，并在那个 promise 上调用`then`。这个 promise 在其构造函数回调中所做的全部事情是解决`JSON.parse()`，我们故意向其传递了一个无效的参数以引起错误。现在，这将在构造函数中抛出一个错误，当我们用`then`方法调用 promise 时，它将间接导致拒绝。如果我们只有一个`onFullfilled`处理程序，我们就无法捕获这个错误。异常将作为拒绝的参数提出，其值为`error`。我们在`promiseTest.then()`的参数中提供了一个`error`处理程序；因此，我们可以捕获并处理这个错误。

您可以通过在[`jsfiddle.net/RamiSarieddine/x2Latjg6/`](http://jsfiddle.net/RamiSarieddine/x2Latjg6/)这个公共 Fiddle 上测试这个示例代码。

### 提示

由于错误会自动冒泡并变成拒绝，因此在 promise 构造函数回调中处理所有与 promise 相关的任务变得非常方便；如果在那里出现任何错误，当调用 promise 时，它将被捕获。

# 使用 promise 处理错误

正如我们所看到的，promise 在异步编程中提供了更丰富的错误处理机制。尽管 Promises/A+规格只处理一个方法，即`.then(onFulfilled, onRejected)`，并没有提供其他方法，但`.then()`的规格为 promise 的互操作性奠定了基础，因此，扩展了包括错误处理在内的 promise 功能。

我们可能会在兼容 Promises/A+的 JavaScript 库中遇到几个错误处理的实现。其中一些扩展包括`catch()`方法，它是建立在基本的`then()`函数之上的。任何人都可以通过以下代码扩展 promise 对象来编写一个`catch()`方法，并将其包含在他们的脚本中：

```js
Promise.prototype.catch = function(onRejected) {
    return this.then(null, onRejected);
};
```

在前一个代码示例中，我们定义了一个名为`catch`的方法，它扩展了当前的`this.then`方法，通过执行`onRejected`处理器并忽略`then`的`onFulfilled`处理器参数来返回一个被拒绝的 promise。在使用中，`catch()`方法将如下所示：

```js
var promiseTest = new Promise(function (resolve) {
    resolve(JSON.parse("json"));
});

promiseTest.then(function (data) {
    alert("It worked: " + data)
}).catch(function(error) {
  alert("I have Failed you! " + error);
});
```

`catch()`函数使我们能够用一个更易读的函数替换错误处理程序，提供更简洁的错误处理方法。

从之前的代码示例中我们可以得出，`catch()`并没有什么独特之处，它只是`then(null, function)`函数的糖衣。此外，Promise/A+规格的一位作者，Brian Cavalier，是这样说的：`catch()`只是`then()`的受限子集。但是，它是否使代码在一般意义上，尤其是在错误处理上更加可读呢？ECMAScript 6.0 将`catch()`作为 promise 规格的必需品，正如我之前所说，现在大多数流行实现都包括了它。

然而，在`then()`和`catch()`的实现之间有一个需要注意的地方，因为`then()`有时会有些误导。为了更好地理解它，来看以下这个例子：

```js
promise.then(handler1, handler2);

promise.then(handler1).catch(handler2);
```

这两行代码包括了`promise`、`then`和`catch`方法，带有两个处理器：`handler1`和`handler2`。这两个调用是不等价的——如果`handler1`中出现错误，第一行不会调用`handler2`。这是因为，如果 promise 被满足，将调用`handler1`，如果 promise 被拒绝，将调用`handler2`。但是，如果`handler1`抛出`error`，`handler2`将不会被调用。

同时，在第二行中，如果任何一个承诺被拒绝或者`handler1`抛出异常，`handler2`将被调用。由于`catch()`仅仅是`then(null, handler)`的糖衣，第二行与以下内容相同，这可以使这个谜题更清晰：

```js
promise.then(handler1).then(null, handler2);
```

前两行代码中不等价的原因是`then()`的工作方式。`then(handler1, handler2)`方法为承诺注册了两个并行的处理程序，这样要么调用`handler1`，要么调用`handler2`，但永远不会两者都调用。另一方面，如果使用`then(handler1).catch(handler2)`，则如果`handler1`拒绝，两个处理程序/函数都将被调用，因为它们代表承诺链中的两个独立步骤。只有当我们有`catch`作为`then`的等价物时，承诺拒绝才会带着拒绝回调转移到后续的`then`方法。

虽然这在一开始看起来可能并不是非常直观，但在提供关于异步编程更容易理解的推理方面非常重要，它使得拒绝承诺变得与同步编程中抛出异常非常相似。在同步世界中，异常不允许执行紧跟在`throw`块后面的代码和最近的`catch`块内的代码，因此`try`块内发生的错误直接转移到`catch`块。

### 注意

`Catch()`函数对于应用程序开发者来说更佳，正如我们所学的，因为它有更好的可读性和直观的错误处理流程，而`promise.then(handler1, handler2)`通常在实现承诺时内部使用。

错误处理机制允许我们编写以安全方式执行任务的函数。让我们来看一个包含使用`catch()`进行错误处理的承诺链，并看看它在流程图中的翻译：

```js
promise1.then(function () {
    return promise2();
}).then(function () {
    return promise3();
}).catch (function (error) {
    return promiseError1();
}).then(function () {
    return promise4();
}, function (error) {
    return promiseError2();
}).catch (function (error) {
    alert("Everything is gonna be alright!");
}).then(function () {
    alert("We are out of here!");
}); 
```

前述承诺链和错误链对应的流程图将如下所示：

![使用承诺处理错误](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-prms-ess/img/00004.jpeg)

绿色的框表示将会被满足的部分；被染成红色的框代表如果承诺被拒绝时的错误处理程序。我们可以通过线条跟随流程，了解哪个被满足，哪个被拒绝，并与之前的代码示例进行比较，以获得关于承诺链中错误如何传播的更好视觉概念。

# 总结

JavaScript 的承诺（promises）提供了一种标准化的错误处理方法，其实现的基础存在于 `then` 方法的规格说明中，该方法可以扩展生成如 `catch` 之类的方法，使得代码更加易读且直观。`then` 函数有两个强大的参数：`onFulfilled` 和 `onRejected`。这些函数参数允许我们处理来自已完成的承诺操作返回的值以及承诺被拒绝时返回的错误。在下一章中，我们将介绍 WinJS 库；我们将学习该库中的承诺对象以及如何在 Windows 开发中使用它。


# 第五章．WinJS 中的承诺

承诺有各种框架的各种实现，所有这些都共享一个共同的基底；这就是承诺的概念。实际上，所有承诺库都以不同的形式提供了一个共同特性，以使使用 JavaScript 进行异步编程更容易、更好。WinJS，Windows 的 JavaScript 库，是具有自己承诺实现的库之一，我们将在本章中探讨。在前一章中，我们学习了在承诺操作期间处理的异常。我们还看到了 JavaScript 承诺配备的强大错误处理机制。此外，我们还学习了如何使用`then`和`catch`方法处理错误。在本章中，我们将涵盖以下主题：

+   介绍 WinJS 命名空间

+   WinJS 中的承诺对象详细说明

+   在 Windows 应用程序开发中使用 WinJS.Promise 的基本示例

# 介绍 WinJS

WinJS 代表 Windows 库 for JavaScript，是由微软开发的 JavaScript 库，最近被开源。这个库旨在允许开发者为 Windows 8（使用 HTML5 和 JavaScript）构建一等和本地质量的 Windows Store 应用程序，如 Skype 和音乐应用程序。它是用 XAML 和 C#，VB.Net 或 C++编程本地应用程序的第二选择。这种选择允许网页开发者利用他们的知识和技能构建商店应用程序。WinJS 库更像是一个综合工具包。它不仅提供了一个丰富的命名空间，而且还包括以下功能：

+   通过 Windows 运行时（WinRT）访问设备硬件

+   提供经过精心设计的 UI 控件，如 ListView、FlipView 和语义缩放，与页面控件一同使用

+   提供了一个坚实的基础，如承诺和数据绑定

此外，WinJS 可以与其他库和框架一起使用在独立的解决方案中。

WinJS 自其创建以来已经发展了很多。最初是专为 Windows Store 应用程序设计的平台，现在支持网页浏览器和其他设备，试图成为跨平台。这一尝试在最新的 WinJS 2.1 版本中得到了巩固，该版本支持 Windows Phone 8.1，现在 WinJS 也用于 Xbox One 应用程序。此外，它现在准备覆盖其他非微软浏览器和设备上的网站和网络应用程序。

### 注意

开源的 WinJS 现在托管在 GitHub 上，通过[`github.com/winjs/winjs/`](https://github.com/winjs/winjs/)，社区成员可以查看库并为其源代码做出贡献。

所有 WinJS 库函数都定义在一个名为 WinJS 的命名空间下。WinJS 命名空间为 JavaScript 提供了特殊功能，包括承诺对象和`xhr`函数。它包括三种成员对象：属性、函数

对象包括以下两个成员：

+   `ErrorFromName`：这只是一个错误对象。

+   承诺对象：这是我们本章讨论的重点。与本书中一直在讨论的承诺对象类似，它基本上提供了一种将工作分配给尚未存在的值的技巧。它为与作为异步暴露的 API 的交互提供了一个抽象机制。

属性包括以下内容：

+   `validation`：这个属性包含一个设置器，用于显示验证过程的结果

函数包括以下三个成员：

+   `log`：这个函数记录输出，并将其写入 Visual Studio 中的 JavaScript 控制台。这个函数可以通过自定义实现扩展，或者使用`WinJS.Utilities.startLog`将其记录到 JavaScript 控制台。

+   `strictProcessing`：这个函数不再需要，因为严格处理默认总是开启的。由于不再需要这个函数，它已被宣布为过时。

+   `xhr`：这个函数只是将`XMLHttpRequest`的调用包装在一个承诺中。

这就总结了 WinJS 命名空间从高层次的视图；WinJS 的代码在`base.js`文件中找到。

# 解释 WinJS.Promise 对象

这个对象是 WinJS 库最重要的方面之一，promise 实例与我们对异步 API 所做的任何事情都有关联。让我们深入了解这个对象的具体细节。就解剖学而言，promise 对象包括以下三种成员类型。

## 构造函数

在 WinJS 的构造函数级别，使用`WinJS.Class.define`函数创建一个类。在这个第一个参数是一个充当构造函数的函数。现在，在`Promise`类的案例中，它使用`WinJS.Class.derive`函数从名为`PromiseStateMachine`的基本类派生，第二个参数是构造函数。在这两种情况下，构造函数可以被命名为任何东西；另外，它们也可以是匿名的。然而，`WinJS.Promise`构造函数的描述与对象描述本身相同。`WinJS.Promise`构造函数接受两个函数参数：`init`和`onCancel`。

当我们声明一个新的承诺对象时，我们需要两个参数：`init`和`onCancel`。这两个参数都是函数。语法如下：

```js
var promiseObj = new WinJS.Promise(init, onCancel);
```

`init`参数是可选的。`init`函数在初始化或构建承诺对象时调用，这包括承诺对象实际要表示的工作的实质性实现。这个实现可以是异步的或同步的，这取决于所需工作的范围和性质。

### 提示

在这里需要注意的是，`init`函数中编写的代码默认并不会使其成为异步。为了确保代码异步运行，我们必须使用异步 API，如 Windows 运行时的异步 API、`setTimeout`、`setImmediate`和`requestAnimationFrame`。

`init`函数在此参数中使用，接受以下三个参数：

+   `completeDispatch`: 当`init`内部的操作已完成时，将调用此参数，从而传递该操作的结果。`init`代码应在操作完成后调用此参数，将操作的结果作为一个参数传递。

+   `errorDispatch`: 当该操作中发生错误时，会调用这个参数，因此，承诺获得错误状态。由于这是一个错误，`errorDispatch`的参数应该是`WinJS.Promise.ErrorFromName`的一个实例。

+   `progressDispatch`: 在操作进行期间，此参数将定期调用。这个函数的参数将包含中间结果。如果承诺中的操作需要支持进度，则使用此参数。

`onCancel`参数是承诺构造函数的第二个参数。这个函数可以被承诺的消费者用来取消任何未完成的工作。然而，在 WinJS 中，承诺并没有义务提供或支持取消。

## 事件

在承诺对象成员类型的列表中，接下来是`Events`。目前，承诺对象有一个名为`onerror`的事件。正如这个名字所示，这个事件发生在承诺处理过程中发生错误时。此外，无论是否在其他地方处理此事件，`onerror`事件都会在任何一个承诺中引发运行时错误。错误处理程序有助于调试，可以用来设置断点和提供错误日志。然而，它最终只能提供关于导致错误的代码或输入的见解和详细信息。这个`onerror`事件提供了一个通用的错误处理机制。在代码中，添加一个通用错误处理程序看起来像如下：

```js
WinJS.Promise.onerror = errorHandler;

function errorHandler(event) {
     // get generic error handling info
     var exc = event.detail.exception;
     var promiseErrored = event.detail.promise;
}
```

代码示例的第一行仅仅是将`errorHandler`函数附加到承诺对象的`onerror`事件。接下来，我们定义了`errorHandler`函数，它接受一个参数`event`；函数所做的就是在这个示例中从事件中检索信息，例如`exception`和`promise`。然后，我们将这些值赋给变量。参数`event`是事件处理程序的`CustomEvent`类型参数；通常它是一个包含有关事件信息的对象。

## 方法

承诺对象的最后一种成员类型是`Methods`，目前`WinJS.Promise`有以下六个方法：

+   `addEventListener`: 这个方法简单地将事件监听器附加到 promise 上。它有三个参数：`eventType`，这是事件的字符串类型名称；`listener`，当事件触发时要调用的函数；`capture`是一个布尔值，用于启用或禁用捕获。这个方法没有返回值，其基本语法如下所示：

    ```js
    promise.addEventListener(eventType, listener, capture);
    ```

+   `removeEventListener`: 这个方法从控件中取出事件监听器。在语法上，它与`addEventListener`方法相似，如下面的代码行所示：

    ```js
    promise.removeEventListener(eventType, listener, capture);
    ```

+   `Cancel`: 这个方法尝试取消 promise。在 promise 支持取消并且尚未完成的情况下，这将导致 promise 进入错误状态，值为 Error("Canceled")。它没有参数和返回值。其基本语法如下所示：

    ```js
    promise.cancel();
    ```

+   `dispatchEvent`: 这个方法简单地分发和触发一个具有指定类型和属性的事件。它有两个参数，并根据是否在事件上调用`preventDefault`返回一个布尔值。这个方法的参数是字符串值类型，包含事件的名称和`eventDetails`，这是一个包含要附加到事件对象的一组额外属性的对象。这个方法的基本语法如下所示：

    ```js
    promise.dispatchEvent(type, eventDetails);
    ```

+   `Then`: 这是 promise 对象最重要的方法。它接受三个函数类型的参数，允许我们在 promise 完成时指定要执行的工作：promise 值已经完成；当 promise 触发错误时将要执行的错误处理，并且未能完成一个值；最后，在 promise 过程中处理工作进度的最后工作。`then`的返回值是一个包含执行`onComplete`函数结果的 promise。在其基本形式中，`then`方法将具有以下语法：

    ```js
    promise.then(onComplete, onError, onProgress);
    ```

    `then`方法的三个参数是函数类型。这些如下所示：

    +   `onComplete`: 当 promise 成功完成并带有值完成时，将调用此处理器。值将作为单个参数传递。`onComplete`返回的值成为`then`方法返回的 promise 的完成值。在执行此函数期间出现错误或异常的情况下，`then`返回的 promise 将进入错误状态。

    +   `onError`: 当 promise 失败并带有错误完成时，将调用此处理器；`onError`返回的值将成为`then`方法返回的 promise 的值。在这里，错误将作为参数传递，而不是像在`onComplete`函数中那样传递值。

    +   `onProgress`: 如果我们需要报告 promise 操作的进度，就使用这个处理器。它有一个参数，是进度数据。请注意，WinJS 中的 promise 不必支持进度。

+   `Done`方法，类似于`Then`，也允许我们在 promise 被解决时指定需要执行的操作，在 promise 失败时的错误处理，以及过程中的进度报告。此外，这个函数将抛出任何本应从`then`返回的错误，作为 promise 在错误状态下的值。与返回一个 promise 的`then`不同，`Done`不返回一个值。这个方法的基本语法如下面的代码行所示：

    ```js
    promise.done(onComplete, onError, onProgress);
    ```

正如我们从前面的代码语法中看到的，`promise.done`在参数上与`promise.then`相似，因为它有函数参数：`onComplete`、`onError`和`onProgress`，实际上它们的行为和作用与`Then`方法中的对应部分是一样的。

`then`和`done`之间有一些区别；最明显的区别是返回值。如前所述，`then`方法返回 promise，而`done`没有返回值，这对 WinJS 承诺的链式调用有直接影响。以下列表总结了这些区别：

+   **在链式调用中**：`Then`允许链式调用多个`then`函数，因为它返回一个 promise。而与`done`相比，我们不能链式调用多个`done`方法，因为它不返回一个值；更具体地说，它返回`undefined`。因此，`done`必须是最终的调用。例如，我们可以有`.then().then().then().then()`等等，而与`done`一起则是`.then().then().done()`。

+   **在错误处理中**：如果没有为`done`提供错误处理程序并且发生了错误（换句话说，就是一个未处理的异常），将抛出一个异常到事件循环中，允许我们在`window.onerror`事件中捕获它，但不在`try`/`catch`块内。因此，`done`函数向调用方法保证抛出任何在该方法内未处理的错误。而与`then`相比，那些产生的未处理异常被默默地捕获并作为 promise 状态的一部分进行遍历，`then`不抛出异常，而是返回一个处于错误状态的 promise。

了解这两个方法之间的区别对于使用它们是至关重要的。然而，对于这两种方法，建议采用扁平化的 promise 链而不是嵌套的链，因为 promise 链的格式使它们更容易阅读，也更容易处理错误。例如，以下样本代码是更可取的：

```js
asyncFunct()
    .then(function () { return asyncFunct1(); })
    .then(function () { return asyncFunct2(); })
    .done(function () { theEnd(); });
```

以下被标记为*不要*之一：

```js
//not very neat!
asyncFunct().then(function () {
    asyncFunct1().then(function () {
            asyncFunct2().done(function () { theEnd(); });
    })
});
```

### 注意

我们链式调用 Windows 运行时（WinRT）返回 promise 的方法，这与链式调用 WinJS 承诺是一样的。

请注意，WinJS 中的承诺符合 CommonJS Promises/A 提案中定义的承诺，并且在本稿撰写之时，WinJS 承诺尚未针对新的 Promises/A+规范进行测试。这对 Windows 应用开发没有影响，因为应用在商店中运行。在浏览器中，WinJS 承诺与 A+承诺之间可能产生的主要区别是，WinJS 承诺不保证承诺的回调函数将异步执行。例如，如果我们用回调函数`a`调用`promise.then(a)`，我们无法确定`a`将以异步还是同步方式调用。而在 Promises/A+规范中，回调函数`a`总是异步调用。这是必须的。规范的作者解释说，不确保异步回调会使承诺更难以推理和调试。尽管如此，正如我之前在章节中提到的，WinJS 本身现在是一个开源项目，托管在 GitHub 上，社区成员和任何感兴趣的人都可以下载 WinJS，构建并将其与 Promises/A+兼容性测试套件进行测试。

接下来，让我们看看如何在 Windows 应用开发中使用 WinJS 的承诺。

## 使用 WinJS 承诺

我们在 Web 上利用承诺来使 UI 更具响应性，并避免通过异步执行工作来阻塞 UI 线程。同样，我们使用 WinJS 承诺以异步处理工作，从而使 Windows 应用的 UI 线程可用于响应用户输入。我们还允许在从服务器和数据库异步获取所需内容的同时，应用程序布局和静态项目正确并及时地加载。为此，WinJS 和 Windows 运行时中的异步 API 以承诺的形式在 JavaScript 中暴露。

让我们来看一个承诺的基本示例。为了跟随并复制以下示例，我们将需要 Visual Studio（ express 版本即可）。我们需要首先创建一个基本的 Windows 应用，类型为 JavaScript。为此，我们需要从 Visual Studio 顶部菜单中选择**文件** | **新建** | **项目**，这将弹出一个包含项目类型的窗口。在那里，我们需要选择**JavaScript** | **商店应用** | **Windows 应用**，这将为我们列出可用的不同 JavaScript Windows 应用模板。对于这个例子，我们可以选择**空白应用**，这是一个单页 Windows 应用的项目，没有预定义的控制或布局。随意命名应用程序，然后单击**确定**。以下屏幕截图说明了所采取的步骤：

![使用 WinJS 承诺](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-prms-ess/img/00005.jpeg)

现在，我们有一个空的 Windows 应用，可以向其中添加一些代码。为此，我们需要导航到`default.html`页面并对其进行修改。打开该页面，并在`body`元素中插入一个`input`元素和一个`div`元素以显示一些结果，按照以下语法进行操作：

```js
<body>
    <p>Content goes here</p>
    <br/>
    <div>
        <input id="urlInput" />
    </div>
 <br/><br/>
    <div id="resultDiv">The result will show here</div>
</body>
```

接下来，我们需要在`input`元素的更改处理程序上附加一些代码，以便在`input`元素的值发生变化时我们可以做一些工作。我们可以通过使用`addEventListener`方法并将其作为`WinJS.Utilities.ready`函数的一部分来实现这一点。在这个函数内部添加事件监听器将允许我们附加的更改处理程序在 DOM 通过`DOMContentLoaded`事件加载后直接调用，这将在页面代码被解析后且所有资源尚未加载之前发生。

导航到位于`js`文件夹内的`default.js`文件。在那里，我们需要在`app.onactivated`事件处理器的末尾添加以下代码：

```js
WinJS.Utilities.ready(function () {
    Var inpt = document.getElementById("urlInput");
    inpt.addEventListener("change", onChangeHandler);
  }, false);
```

在前面的代码中，我们在`WinJS.Utilities.ready`中添加了一个匿名函数代码。在那个匿名函数中，我们首先从 DOM 中获取那个`input`元素，将其分配给一个名为`inpt`的变量，然后在该`inpt`变量上调用`addEventListener`方法，将名为`onChangeHandler`的函数添加到变化事件中。

最后一步将是编写`onChangeHandler`函数的代码。在该函数中，我们将调用`WinJS.xhr`方法，该方法基本上将`XMLHttpRequest`的调用包装起来并暴露为一个承诺。我们可以使用这个方法进行跨域请求和内部网络请求。我们将用户在`input`元素中输入的 URL 传递给`xhr`参数，并相应地更新`resultDiv`元素的结果。`Xhr`是一个异步函数，返回一个承诺；因此，我们可以在这个函数上调用承诺对象的`then`或`done`方法来更新 UI。对于这个例子，我们将调用`then`方法，该方法在`xhr`函数成功完成`XmlHttpRequest`或引发一个错误时被调用。`Then`可以接受三个参数，分别为成功、错误或进度，正如我们在定义中看到的那样。然而，对于这个基本例子，我们将看到如何添加`onCompleted`函数。这个成功处理程序将通过将`resultDiv`元素的背景颜色设置为蓝色并将内部文本设置为`Hooray!`来对`resultDiv`元素应用一些更改。

`onChangeHandler`函数的语法将如下所示：

```js
function onChangeHandler(e) {
            var input = e.target;
            var resDiv = document.getElementById("resultDiv");

            WinJS.xhr({ url: e.target.value }).then(function onCompleted(result) {
                if (result.status === 200) {
                    resDiv.style.backgroundColor = "blue";
                    resDiv.innerText = "Hooray!";
                }
            });
        }}
```

让我们分析一下之前的代码示例。我们首先从`e`参数中获取`input`元素，我们将`resultDiv`元素赋值给变量`resDiv`，然后我们调用`WinJS.xhr`，并传递给它从目标中获取的`input`元素的值。这个值包含了我们在文本框中输入的 URL。接下来，我们在`xhr`函数上调用`then`，并将成功处理程序`onCompleted`传递给`then`，其中包含结果作为参数。这里的成果代表了 HTTP 请求。如果请求的状态是 200，这是 HTTP 请求中的成功状态，我们将对`resultDiv`应用更改。

现在如果我们运行该应用程序，在文本框中输入 URL 后，我们将得到以下结果：

![使用 WinJS promises](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-prms-ess/img/00006.jpeg)

如何在获取结果时报告进度？为了这样做，我们需要在`xhr`函数的`then`调用中编写进度处理程序。我们将把背景颜色改为绿色，直到请求完成并调用`onCompleted`处理程序，这将把背景颜色改为蓝色。我们将修改代码，包括以下代码的进度处理程序：

```js
function onChangeHandler(e) {
    var input = e.target;
    var resDiv = document.getElementById("resultDiv");
    WinJS.xhr({ url: e.target.value }).then(function onCompleted(result) {
        if (result.status === 200) {
            resDiv.style.backgroundColor = "blue";
            resDiv.innerText = "Hooray!";
        }
    }, function myfunction() {
//no error handling here; just passing an empty parameter
    }, function progress(result) { //handle progress here
        if (result.status != 200) {
            resDiv.style.backgroundColor = "green";
        }
    });
}
```

在之前的代码示例中，我们添加了一个空的错误处理程序和一个进度处理程序，作为匿名函数`function progress(result)`，它将检查请求状态是否不是 200，这意味着它还不是成功状态，并把背景颜色设置为绿色。现在我们运行应用程序，并在文本框中输入 URL，我们会注意到`div`元素的背景颜色在一秒左右变为绿色，然后变为蓝色，并更新文本为 Hooray!。

现在，WinJS promises 也可以在浏览器中使用，因为产品团队已经使一些 WinJS 功能能够在 Web 上运行。您可以通过[`try.buildwinjs.com/`](http://try.buildwinjs.com/)上的新在线编辑器查看 WinJS 的实际效果。在任何浏览器中，我们都可以查看和编辑代码，玩转 WinJS，并实时查看结果。

# 摘要

WinJS 提供了一个强大的 promises 实现，我们可以用它来包装任何操作，并有效地利用异步编程为使用 JavaScript 的 Windows 应用提供支持。

在下一章，也是最后一章中，我们将总结前几章中学到的 JavaScript promises 知识，并付诸实践比迄今为止所看到的更成熟的代码示例。


# 第六章：综合运用——承诺在行动

在第五章中，我们介绍了 WinJS 库，并详细了解了 WinJS 承诺对象。我们还快速浏览了如何在 Windows 应用程序开发中使用 WinJS 承诺的基本示例。最后，我们来到了最后一章，在这一章中，我们将把本书关于承诺的学习付诸实践。我们将尝试通过创建一个简单的实现来更深入地了解承诺是如何工作的。创建实现库之后，我们将在一个基本示例中使用它，利用该库执行异步操作。在本章中，我们将介绍以下主题：

+   总结我们已经涵盖和学到的内容

+   在简单的 JavaScript 库中创建承诺实现

# 实现承诺库

承诺已经变得非常流行，这可以从它们的许多独立实现中看出。此外，Promises/A+已经有超过 35 个符合要求的实现，随着 ECMAScript 6 的推出，这个数字还在增长。值得注意的是，JavaScript 中 Promise/A+的日益普及在其他语言中也得到了体现，ActionScript、Python 和 Objective C 中都有许多实现。尽管从语义上讲，由于不同的语言能力，这些实现可能并不一定与 JavaScript 规范中的实现相匹配，但直接将它们与 Promise/A+的 JavaScript 测试套件进行测试是无法验证它们是否符合要求的。然而，提及这些实现并展示所付出的努力是有价值的。

让我们通过一个代码示例来了解承诺的基本实现；这将使我们更好地了解承诺是如何工作的。深入理解事物的工作原理可以提高我们利用代码和当它出错时更轻松、更快地调试的能力。我们将创建一个最小的 JavaScript 库来实现承诺，并从承诺的状态开始编写这个库。我们在第二章中了解到，承诺有三种不同的状态：pending（等待中）、fulfilled（已履行）和 rejected（已拒绝）。

承诺的规范没有为这些状态指定一个值，所以让我们声明它们，并将值分配给一个枚举器，如下面的代码所示：

```js
var promState = {
 pending: 1,
 fulfilled: 2,
 rejected: 3
};
```

这个枚举将允许我们通过名称来调用状态，例如，`promState.fulfilled`。接下来，我们将创建一个对象，它包含了从状态转换到`then`方法的整个承诺逻辑，并解决承诺。让我们称这个对象为`PromiseMe`。

首先，我们需要定义承诺状态的变化及其从一个状态转换到另一个状态的过渡。规范详细说明了状态间转换的一些规则和考虑因素，我们在第二章，*承诺 API 及其兼容性*中进行了深入的讨论。这些规则可以总结如下：

+   承诺在某一时间点只能处于一个状态。

+   当一个承诺从待处理状态转换为其他任何状态，无论是已履行还是已拒绝，它都不能回去。

+   当一个承诺被履行时，它必须有一个值（甚至可以是 undefined），而当它失败时，它必须有一个原因（任何指定承诺被拒绝原因的值）。

在`PromiseMe`对象内部，我们首先定义一个名为`changeMyState`的函数，该函数根据前面的规则处理和管理这个承诺的状态转换，如下面的代码所示：

```js
var PromiseMe = {
    //set default state
 myState: promState.pending,
 changeMyState: function(newState, newValue) {

  // check if we are changing to same state and report it
  if (this.myState == newState) {
   throw new Error("Sorry, But you can't do this to me! You are transitioning to same state: " + newState);
  }

  // trying to get out of the fulfilled or rejected states
  if ( this.myState == promState.fulfilled ||
    this.myState == promState.rejected ) {
   throw new Error("You can't leave this state now: " + this.myState);
  }
  // if promise is rejected with a null reason
  if ( newState == promState.rejected &&
    newValue === null ) {
   throw new Error("If you get rejected there must be a reason. It can't be null!");
  }

  // if there was no value passed with fulfilled
  if (newState == promState.fulfilled &&
    arguments.length < 2 ) {
   throw new Error("I am sorry but you must have a non-null value to proceed to fulfilled!");
  }

  //we passed all the conditions, we can now change the state
  this.myState = newState;
  this.value = newValue;return this.myState;
 }
};
```

对象内的代码首先设置一个名为`myState`的属性，将其值设置为枚举`promState`的待处理值`promState.pending`。随后，我们设置一个名为`changeMyState`的属性，其值为一个匿名函数，该函数接受两个参数：`newState`和`value`。在这个函数中，我们处理状态转换并检查它是否符合规则。在我们继续编写代码之前，有四个检查点：

1.  首先，我们检查我们是否正在转换到同一个状态，并抛出错误。

1.  在第二个检查中，我们确保承诺不是试图从已拒绝或已履行的状态转换，并相应地抛出错误。

1.  第三个检查是针对传递给拒绝的值。如果它是 null，将抛出一个错误，这确保了承诺因除 null 之外的值而被拒绝。我们编写这个检查点，因为根据规范，承诺只接受非 null 值。

1.  最后的检查将是履行状态及其值；我们用`arguments.length < 2`来确定是否有在第二个参数中传递的值；如果没有，我们抛出一个错误。

    ### 提示

    我给错误信息赋予了有意义的措辞，以便更好地理解我们在这些条件下检查的内容。在我们通过所有的条件语句后，我们通过将`changeMyState`方法的`myState`属性设置为通过参数传递的`newState`，来关闭`changeMyState`方法。我们还将值分配给`newValue`参数，并以返回`this.myState`结束，反过来返回承诺的状态。

## 实现 then 方法

在我们的实现中，接下来是`then`方法。这是承诺的核心，也是使承诺变得有用的关键。这个方法允许并实现承诺的链式调用和错误处理。我们将实现一个基本的`then`方法，该方法首先检查承诺的有效性规则。

让我们将`then`方法定义如下：

```js
then: function (onFulfilled, onRejected) {
        // define an array named handlers
        this.handlers = this.handlers || [];
        // create a promise object to return
        var returnedPromise = Object.create(PromiseMe);

        this.handlers.push({
            fulfillPromise: onFulfilled,
            rejectPromise: onRejected,
            promise: returnedPromise
        });
        return returnedPromise;
    }
```

之前代码所做的基本工作是为这个 promise 定义一个`then`方法。`Then`被定义为一个匿名函数，它接受两个参数：`onFulfilled`和`onRejected`。我们为这个 promise 定义一个数组，并初始化为`this.handlers`（如果存在的话）当前数组或一个新的数组（如果不存在）。我们实例化一个新的 promise 并将其存储在`returnedPromise`变量中。我们将`onFulfilled`、`onRejected`和`returnedPromise`存储在数组中，这样我们可以在返回 promise 之后调用这些处理程序。这个函数以返回 promise 结束。

### 注意

根据 Promise/A+规范，`then`方法的规则指出，函数参数：`onFulfilled`和`onRejected`，只能在 promise 被满足或拒绝后调用。这就是为什么在实现中，我们将这两个函数存储在一个数组中，以便我们稍后可以调用它们。

你可能会注意到`handlers`数组包含两个属性：`fulfillPromise`和`rejectPromise`。这两个函数被设置为传递给`then`方法的处理器。让我们定义这两个函数，这样我们稍后就可以在`resolve`方法中使用它们。这些函数是辅助方法，它们允许我们手动改变 promise 的状态。此外，这些函数将调用`changeMyState`方法来改变 promise 的状态，进而返回一个状态。

```js
fulfillPromise: function (value) {
//change state to fulfilled and return a promise with a value
        this.changeMyState(promState.fulfilled, value);
    },
rejectPromise: function (reason) {
//change state to rejected and return a promise rejected with a reason
        this.changeMyState(promState.rejected, reason);
    }
```

## 定义一个解决方法

接下来，我们需要解决 promise 的解析问题。我们需要定义一个解决方法，该方法将处理 promise 并且将根据 promise 的状态来满足它或拒绝它。你可以把`resolve`方法看作是一个内部方法，promise 调用它，并且旨在仅在 promise 被满足时执行`then`调用；从字面上讲，它解决了一个被满足的 promise。实际上，为了满足一个 promise 或拒绝它，你需要调用一个函数，在我们的案例中是`changeMyState`。让我们先根据以下代码为`resolve`方法创建一个基本逻辑：

```js
    resolve: function () {
        // check for pending and exist
        if (this.myState == promState.pending) {
            return false;
        }
```

之前的代码将`resolve`属性分配给一个函数。在这个函数内部，我们首先检查这个 promise 的状态。如果它是 pending 状态，我们返回`false`。在接下来的代码中，我们将遍历包含我们在`then`方法中定义的处理器的数组：

```js
// loop through each then as long as handlers array contains items
while(this.handlers && this.handlers.length) {

//return and remove the first item in array
var handler = this.handlers.shift();
```

在循环内部，我们对数组应用了`shift()`函数。该`shift()`函数允许我们从数组中检索第一个元素并直接删除它。因此，`handler`变量将包含`handlers`数组中的第一个元素，而作为回应，`handlers`数组将包含所有元素减去现在存储在`var` handler 中的第一个元素。

在`resolve`函数中接下来，我们将定义一个名为`doResolve`的变量，其值根据状态要么是`fulfillPromise`函数，要么是`rejectPromise`处理程序，如下面的代码所示：

```js
//set the function depending on the current state
var doResolve = (this.myState == promState.fulfilled ? handler.fulfillPromise : handler.rejectPromise);
```

### 提示

前面的语法使用了三元运算符。它被称为三元运算符，是因为与其他所有需要两个值的运算符不同，这个运算符实际上需要第三个值放在运算符的中间。它就像是一个单条语句的`if`语句的简写形式，其中`if`和`else`子句将不同的值赋给同一个变量，如下面的示例所示：

```js
if (condition == true) result = "pick me"; else result = "No! pick me instead";
```

三元运算符将`if`语句转换为以下单行条件语句：

```js
result = (condition == true) ? "pick me" : "No! pick me instead";
```

我们需要对`doResolve`函数进行一些逻辑检查。如果它不是函数类型或者该函数不存在，那么我们调用`changeMyState`方法来改变承诺的状态并传递状态和值：

```js
//if doResolve is not a function
if (typeof doResolve != 'function') {
handler.promise.changeMyState(this.myState, this.value);

}
```

## 实现 doResolve 函数

这段代码的另一种情况是`doResolve`函数存在，我们需要用值返回承诺，或者用错误拒绝它。所以，我们在`if`条件后跟一个`else`语句来实现这个情况，如下面的代码所示：

```js
else {
//fulfill the promise with value or reject with error
try {
```

根据目前的代码逻辑，我们现在应该有`doResolve`包含`handler.fulfillPromise`或`handler.rejectPromise`函数之一。这两个函数可以手动改变承诺的状态，并接受一个参数，即当前值或当前原因。这两个值都包含在`this.value`变量中。因此，我们将当前值传递给`doResolve`，并将结果赋给一个名为`promiseValue`的变量，如下面的代码行所示：

```js
var promiseValue = doResolve(this.value);
```

接下来，我们需要管理随`promiseValue`返回的承诺。首先，我们检查承诺是否存在，并且是否有一个有效的`then`函数，如下面的代码所示：

```js
// deal with promise returned
        if (promiseValue && typeof promiseValue.then == 'function') {
```

假设我们通过了这个条件，我们可以在其中调用`promiseValue`的`then`方法，因为现在它包含了一个由`doResolve`函数返回的承诺。我们将两个参数传递给它的`then`方法：一个函数参数`onFullfilled`，另一个参数`onRejected`，如下面的代码所示：

```js
//invoke then on the promise
promiseValue.then(function (val) {
    handler.promise.changeMyState(promState.fulfilled, val);
}, function (error) {
    handler.promise.changeMyState(promState.rejected, error);
});
}
```

另一方面，如果`promiseValue`返回的值不是一个承诺，我们将不需要调用`then`方法。相反，我们简单地将状态更改为已兑现，并传递值。我们将处理这个情况，如下面的代码所示：

```js
// if the value returned is not a promise
else {
handler.promise.changeMyState(promState.fulfilled, promiseValue);
}
```

最后，因为我们处于一个`try`语句中，我们将相应地提供一个`catch`语句，以处理操作失败时抛出的任何错误。在那个`catch`语句中，我们将承诺的状态更改为已拒绝，并传递产生的错误。我们还将关闭所有尾随的花括号：

```js
// deal with error thrown
} catch (error) {
handler.promise.changeMyState(promState.rejected, error);
   }
}
}
}
```

解决 promise 包括一些繁琐的检查，但这些是确保 promise 实现与规范保持一致的必要条件。正如你所见，我们在进行中添加了逻辑，开始时只是一个简单的检查，看看我们是否根据 promise 状态运行`onFulfilled`或`onRejected`函数。接着，根据返回值改变它们对应的 promise 状态。

### 提示

请记住，实现需要遵循规范中存在的考虑和规则。在任何时间点，你可以通过查看本书第二章*The Promise API and Its Compatibility*中解释的 Promise API 的详细信息来核对代码。

我们已经接近完成，剩下的是我们还没有解决的两种场景。第一个场景是`onFulfilled`和`onRejected`处理程序必须在事件循环的同一轮中（当`this.handlers && this.handlers.length`时）不得调用。我们进行这个检查是因为`while`正在遍历每个`then`调用。在`then`调用中，promise 要么被解决要么被拒绝。因此，在我们这里，我们有`onFulfilled`和`onRejected`处理程序。为了解决这个问题，我们将在事件循环之后仅将`then`方法添加到数组中。我们可以使用`setTimeout`函数来实现这一点，从而确保我们始终以异步方式运行。让我们在`then`方法中添加`setTimeout`函数，并将存储 promise 处理程序的函数包装起来，如下面的代码所示：

```js
var that = this;setTimeout(function () {
    that.handlers.push({
         fulfillPromise: onFulfilled,
         rejectPromise: onRejected,
         promise: returnedPromise
      });
    that.resolve();
 }, 2);
```

## 包装代码

在这个实现中的最后一步将是指出我们实际上何时解决 promise。我们需要检查两个条件。第一个条件是我们添加`then`方法时，因为 promise 的状态可能已经在那里设置。第二个情况是在`changeMyState`函数中改变 promise 状态。因此，我们需要在`changeMyState`函数的末尾添加一个`this.resolve()`调用。在最终确定实现之前，我们需要做的一切就是将所有代码包裹在一个名为`PromiseMe`的无名函数中。它将使用`Object.create`给我们一个 promise。有了这个，这个 promise 实现的最终代码将如下所示：

```js
var PromiseMe = function () {
    var promState = {
        pending: 1,
        fulfilled: 2,
        rejected: 3
    };
    //check the enumeration of promise states

    var PromiseMe = {
        //set default state
        myState: promState.pending,
        changeMyState: function (newState, newValue) {

            // check 1: if we are changing to same state and report it
            if (this.myState == newState) {
                throw new Error("Sorry, But you can't do this to me! You are transitioning to same state: " + newState);
            }

            // check2: trying to get out of the fulfilled or rejected states
            if (this.myState == promState.fulfilled || this.myState == promState.rejected) {
                throw new Error("You can't leave this state now: " + this.myState);
            }
            // check 3: if promise is rejected with a null reason
            if (newState == promState.rejected && newValue === null) {
                throw new Error("If you get rejected there must be a reason. It can't be null!");
            }
            //check: 4 if there was no value passed with fulfilled
            if (newState == promState.fulfilled && arguments.length < 2) {
                throw new Error("I am sorry but you must have a non-null value to proceed to fulfilled!");
            }

            // we passed all the conditions, we can now change the state
            this.myState = newState;
            this.value = newValue;
            this.resolve();
            return this.myState;
        },
        fulfillPromise: function (value) {
            this.changeMyState(promState.fulfilled, value);
        },
        rejectPromise: function (reason) {
            this.changeMyState(promState.rejected, reason);
        },
        then: function (onFulfilled, onRejected) {
            // define an array named handlers
            this.handlers = this.handlers || [];
            // create a promise object
            var returnedPromise = Object.create(PromiseMe);
            var that = this;
            setTimeout(function () {
                that.handlers.push({
                    fulfillPromise: onFulfilled,
                    rejectPromise: onRejected,
                    promise: returnedPromise
                });
                that.resolve();
            }, 2);

            return returnedPromise;
        },
        resolve: function () {
            // check for pending and exist
            if (this.myState == promState.pending) {
                return false;
            }
            // loop through each then as long as handlers array contains items
            while (this.handlers && this.handlers.length) {
                //return and remove the first item in array
                var handler = this.handlers.shift();

                //set the function depending on the current state
                var doResolve = (this.myState == promState.fulfilled ? handler.fulfillPromise : handler.rejectPromise);
                //if doResolve is not a function
                if (typeof doResolve != 'function') {
                    handler.promise.changeMyState(this.myState, this.value);

                } else {
                    // fulfill the promise with value or reject with error
                    try {
                        var promiseValue = doResolve(this.value);

                        // deal with promise returned
                        if (promiseValue && typeof promiseValue.then == 'function') {
                            promiseValue.then(function (val) {
                                handler.promise.changeMyState(promState.fulfilled, val);
                            }, function (error) {
                                handler.promise.changeMyState(promState.rejected, error);
                            });
                            //if the value returned is not a promise
                        } else {
                            handler.promise.changeMyState(promState.fulfilled, promiseValue);
                        }
                        // deal with error thrown
                    } catch (error) {
                        handler.promise.changeMyState(promState.rejected, error);
                    }
                }
            }
        }
    };
    return Object.create(PromiseMe);
};
```

前面的代码代表了一个小型 JavaScript 库中的基本 promises 实现。它实现了一个具有`t0068en`方法的 promise 对象，考虑到如何根据规范要求解决和拒绝 promise，并在实现中进行必要的检查以避免异常。我们可以使用这个库并开始调用其`PromiseMe`对象及其相应的函数`then`、`fulfillPromise`和`rejectPromise`，以实现一些异步操作。

### 注意

这个实现是一个基本的实现；我们可以扩展它，包括许多可以在 Promises API 之上构建的功能和帮助方法。此外，我们可以构建这个实现，并将其与 Promises/A+兼容性测试套件进行测试，该测试套件可以通过这个链接找到：[`github.com/promises-aplus/promises-tests`](https://github.com/promises-aplus/promises-tests)。

在前面信息框中提供的链接中，我们可以找到完成测试所需的步骤，这些测试需要在 Node.js 环境中运行，我们需要确保 Node.js 已经安装。

## 将承诺付诸行动

我们可以将刚刚编写的这个 promise 的基本实现用于我们的代码中，来处理我们的异步操作。让我们来看一个如何使用这个`PromiseMe`库的例子。可以在`PromiseMe`对象的代码之后添加以下代码：

```js
var multiplyMeAsync = function (val) {
    var promise = new PromiseMe();
    promise.fulfillPromise(val * 2);

    return promise;
};
multiplyMeAsync(2)
    .then(function (value) {
    alert(value);
});
```

在上面的代码中，我们只是创建了一个名为`multiplyMeAsync`的函数，该函数进而将`PromiseMe`实例化给名为`promise`的变量，然后在我们创建的`PromiseMe`对象的`promise`变量上调用`fulfillPromise`方法。`fulfillPromise`方法所做的仅仅是将`val`参数乘以数字 2。随后，我们调用`multiplyAsync`，并将 2 作为其参数的值传递给它；由于它返回一个承诺，我们可以调用其`then`方法。`then`方法有一个单一的处理程序，处理成功并弹出一个带有现在应该为 4 的值的警告。

在 HTML 页面中运行脚本，我们应该会看到一个显示数字 4 的警告。

### 注意

您可以在 jsFiddle 中找到完整的代码并通过[`jsfiddle.net/RamiSarieddine/g8oj4guo/`](http://jsfiddle.net/RamiSarieddine/g8oj4guo/)进行测试。确保浏览器支持承诺。

让我们尝试给这段代码添加一些错误处理。首先，为了简单和可读性，我将创建一个名为`alertResult`的函数来替代`alert(value);`。

因此，我们将有一个如下所示的函数：

```js
var alertResult = function (value) {
    alert(value);
};
```

我们将添加另一个名为`onError`的函数，该函数基本上会带有传递给它的错误消息的警告。该函数将有以下语法：

```js
var onError = function(errorMsg) {
 alert(errorMsg);
};
```

现在，让我们添加一个包含错误处理的函数，通过检测异常并拒绝承诺来包含错误处理。下面的代码显示了这一点：

```js
var divideAsync = function (val) {
    var promise2 = new PromiseMe();
    if (val == 0) {
        promise2.rejectPromise("cannot divide by zero");
    }
    else{
        promise2.fulfillPromise(1 / val);
    }
    return promise2;
};
```

上一个函数所做的仅仅是检查值；如果值为零，函数拒绝承诺；否则，通过将数字 1 除以`val`来履行承诺。为了测试这个，我们将把值 0 传递给`multiplyAsync`，在其`then`调用中调用`divideAsync`，最后在`divideAsync`的`then`方法中调用一个错误函数。代码将如下所示：

```js
multiplyMeAsync(0)
    .then(divideAsync)
    .then(undefined, onError);
```

最终结果将是一个显示“不能除以零”的错误信息。这是因为零被传递给了`divideAsync`，它进而拒绝了承诺，并将错误信息传递给了`onError`处理器。

### 注意

您可以在以下 jsFiddle URL 上找到带有此错误处理场景的更新代码：

请参考以下链接：[`jsfiddle.net/RamiSarieddine/g8oj4guo/15/`](http://jsfiddle.net/RamiSarieddine/g8oj4guo/15/)

总之，承诺为异步操作的复杂性提供了一个非常好的解决方案。承诺提供的抽象让我们能更容易地做很多事情，尤其是使用回调的常见异步模式，具有以下主要特性：

+   一个承诺可以附加到多个回调函数上

+   值和错误会在承诺中传递

# 总结

在前五章中，我们已经学习了关于承诺（promises）的大量知识。我们从 JavaScript 的异步编程开始，了解了承诺在其中的地位，并详细讨论了为什么你应该关心承诺。接下来，我们深入探讨了 Promises API 及其`then`方法。然后，我们了解了目前支持承诺的浏览器和实现类似承诺特性的库。之后，我们覆盖了承诺的链式操作，并详细解释了如何实现以及如何使用承诺链来队列异步操作。第三个主题是错误处理，这是承诺概念中最重要的方面之一。我们退一步看了看 JavaScript 中的异常以及它们如何在承诺中得到处理。我们还学习了作为错误处理一部分的`catch`方法。

现在，承诺已经在 JavaScript 中有了原生支持，这是在网页和客户端开发世界中利用这项技术的焦点时刻。随着技术的发展，更多的浏览器将开始采用承诺作为标准，并在浏览器中实现原生支持。

如果你周围的人一直在谈论 JavaScript 的承诺，现在你知道原因了。这本书是你学习承诺的一个全面的参考点，它帮你节省了在网上找寻零散信息的麻烦。你可以立即开始实现这些学习内容。你随时可以回来查阅这本书，了解 API 的详细信息。从这里开始，你可以开始实现自己的承诺库，并利用其他可用的库，以及深入研究其他实现，如 Node.js。你还可以开始使用承诺来进行数据库、网络或文件服务器上的异步请求。

我希望您喜欢阅读这本书，并且它为您提供了正确的知识、工具和小贴士，以便将学习付诸实践，并开发出利用 JavaScript 承诺力量的一些绝佳应用程序。
