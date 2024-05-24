# 写给 Python 开发者的 JavaScript 实用指南（三）

> 原文：[`zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446`](https://zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：解读错误消息和性能泄漏

当然，没有一个好的语言是完整的，没有一种方法可以检测和诊断代码中的问题。JavaScript 提供了非常强大和直观的丰富错误消息，但在处理错误时有一些注意事项和技巧。

你可能知道，在自己的代码中找到问题（“bug”）是开发人员最沮丧的事件之一。我们以代码能够完成任务为傲，但有时我们没有考虑到边缘和特殊情况。此外，错误消息通过提供重要的诊断信息，给我们在编码过程中提供了重要的信息。幸运的是，有一些工具可以帮助我们理解 JavaScript 中发生的情况。

让我们来探索一下。

本章将涵盖以下主题：

+   错误对象

+   使用调试器和其他工具

+   适应 JavaScript 的性能限制

# 技术要求

准备好在 GitHub 上的`Chapter-9`示例中进行工作，网址为[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-9/`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-9/)。

我们将在浏览器中使用开发者工具，为了说明的目的，指南和截图将来自 Google Chrome。但如果你熟悉其他浏览器中的工具，概念是相似的。如果你还没有这样做，你可能还想在 Chrome 中添加一个 JSON 解析扩展。

本章没有特定的硬件要求。

# 错误对象

让我们看一下[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-9/error-object`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-9/error-object)。打开`index.html`文件并检查 JavaScript 控制台。第一个函数`typoError`被调用并抛出了一个精彩的错误。

它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4597e545-02f8-409c-9027-fb7668083c61.png)

图 9.1 - 错误控制台

现在，让我们看看`index.js`中我们函数的代码：

```js
const typoError = () => {
  cnosole.error('my fault')
}
```

好了！这只是一个简单的拼写错误，我们都犯过：应该是`console.error`而不是`cnosole.error`。如果你在代码中从未犯过拼写错误……你是一个独角兽。我们在控制台中看到的错误消息使我们很容易看到错误是什么，以及它存在于代码的哪一行：第 2 行。现在，有趣的是，在文件末尾调用`typoError()`之后，我们还调用了另一个函数*但它没有触发*。我们知道这是因为（剧透警告）它也抛出了错误，但我们没有看到它们。未捕获的引用错误是一个**阻塞错误**。

在 JavaScript 中，一些错误称为阻塞错误，将停止代码的执行。其他一些称为**非阻塞错误**，以这样的方式进行缓解，即使问题没有解决，代码仍然可以继续执行。处理错误的方法有几种，当面临潜在的错误向量时，你应该这样做。你还记得第七章吗，*事件、事件驱动设计和 API*，我们在`fetch()`调用中使用了`.catch()`块来优雅地处理 Ajax 错误？同样的原则也适用于这里。这显然是一个非常牵强的例子，但让我们继续缓解我们的错误，就像这样：

```js
const typoError = () => {
  try {
    cnosole.error('my fault')
  } catch(e) {
    console.error(e)
  }
}
```

对于拼写错误使用`try/catch`块是杀鸡用牛刀，但让我们假装它是更严重的问题，比如异步调用或来自另一个库的依赖。如果我们现在查看控制台输出，我们会看到我们的第二个函数`fetchAttempt`已经触发，并且也产生了错误。打开`index-mitigated.js`文件和相应的`index-mitigated.html`文件。

你应该在`index-mitigated.html`的控制台中看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ebf1d3e2-50a3-4680-b6fa-0ed70f4143c6.png)

图 9.2 - 非阻塞错误

在这里，我们看到我们的代码并没有在拼写错误处停止；我们已经通过 try/catch 将其变成了一个非阻塞错误。我们看到我们的`fetchAttempt`函数正在触发并给我们一个不同类型的错误：`404 Not Found`。由于我们输入了一个不存在的 URL（故意以`undefined`结尾），之后我们收到了另一个错误：来自我们的 promise 的`SyntaxError`。

乍一看，这个错误可能很难理解，因为它明确地谈到了 JSON 中的意外字符。在第七章中，*事件、事件驱动设计和 API*，我们使用了星球大战 API：`https://swapi.dev/`：

1.  让我们来看一下从`https://swapi.dev/api/people/1/`获取的示例响应的 JSON。这可能是一个很好的时机，确保你的浏览器中有一个 JSON 解析扩展：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/deb08f36-98ab-4536-86c9-fef988c42ba4.png)

图 9.3 - 来自 https://swapi.dev/api/people/1/的 JSON

1.  它是格式良好的 JSON，所以即使我们的错误指定了语法错误，实际上问题并不在于响应数据的语法。我们需要更深入地了解一下。让我们看看我们在 Chrome JavaScript 调试器中从`fetchAttempt`调用中得到的内容。让我们点击这里我们代码中的第二个错误的链接：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/dca8ad30-ba0b-4013-a321-232dbe29b63b.png)

图 9.4 - 跟踪 404 的路径...

然后我们看到这个面板，有红色的波浪线和红色的标记表示错误：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2cff2d02-d8e7-4831-b252-eba0e743201d.png)

图 9.5 - 调试器中的错误

1.  到目前为止，一切都很好。如果你在第 20 行上悬停在红色 X 上，工具提示会告诉我们有 404 错误。

1.  导航到网络选项卡。这个工具跟踪传入和传出的 HTTP 请求。

1.  点击名为 undefined 的调用，然后进入头部面板，就像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/be0217f8-ae58-43b4-901c-2c96ba1fdfb8.png)

图 9.6 - 头部选项卡

啊哈！现在我们知道问题所在了：JSON 错误是有帮助的，但是让我们走错了方向。错误不在于 JSON 本身，而是错误意味着响应根本就不是 JSON！这是一个 HTML 404 错误，所以没有 JSON 数据。我们的问题被确认为在获取一个不存在的地址的 URL 中，因此会呈现一个错误页面，这对于`fetch`的 JSON 解析器来说是没有意义的。

让我们花更多的时间来使用调试工具。

# 使用调试器和其他工具

许多 Web 开发人员选择使用 Google Chrome 作为他们的首选浏览器，因为它提供了丰富的开发工具。如果 Chrome 不是你的首选浏览器，这里有一些具有类似开发工具的浏览器。

## Safari

Safari 默认情况下不带开发者模式，所以如果你使用 Safari，切换到首选项的高级面板中的开发菜单：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/55a1a874-2b1b-403b-85de-b7e8d75fa686.png)

图 9.7 - 在 Safari 中添加开发菜单

现在，你将拥有一个带有工具的开发菜单，这些工具可能会以与 Chrome 略有不同的方式呈现错误消息，但仍然可以访问。

## Internet Explorer 和 Microsoft Edge

真诚地并且只有一点点偏见，我建议*不要*在 JavaScript 开发中使用 Internet Explorer 或 Microsoft Edge。跨浏览器测试很重要，但我发现 IE 和 Edge 提供的开发工具有所欠缺。例如，让我们在 Edge 的开发工具中看一下完全相同的页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/0f6bef7a-8ab0-40ac-9750-869749e6bb52.png)

图 9.8 - Edge JavaScript 控制台

尽管我们用 try/catch 块减轻了错误，Edge 仍然将拼写错误视为阻塞错误。微软浏览器还有其他特殊之处，这些特殊之处可以追溯到我们之前学到的浏览器战争，所以一个好的经验法则是在 Chrome 中开发，然后在微软浏览器中测试，以确保跨浏览器兼容性。

虽然所有主要浏览器都有开发工具，但这里使用的示例将来自 Chrome。让我们更仔细地看看 JavaScript 控制台本身。

## JavaScript 控制台

控制台不仅是查看错误的地方，还可以用来执行代码。这对于快速调试特别有用，特别是在页面上可能包含另一个代码库的情况下。只要从顶层`window`对象访问，控制台就可以访问页面上加载的所有 JavaScript 的*作用域*。我们不希望访问函数的内部变量，但如果浏览器可以访问数据，我们就可以在控制台中访问它。

在`debugger`文件夹中打开`fetch.html`和`fetch.js`文件并查看。这是`fetch.js`文件：

```js
const fetchAttempt = (url) => {
  fetch(url)
    .then((response) => {
        return response
    }).then((data) => {
      if (data.status === 500) {
        console.log("We got a 500 error")
      }
      console.log(data)
      }).catch((error) => {
        throw new Error(error)
    })
}
```

这是一个简单的`fetch`请求，其中 URL 作为参数传递给我们的函数。在我们的 HTML 页面的控制台中，我们实际上可以执行这个函数，就像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2fc08cba-7e2f-4d1a-ba78-fd9ff7195646.png)

图 9.9 - 在控制台中执行代码

当你输入`fetchAttempt('http://httpstat.us/500')`时，你是否注意到控制台给出了自动完成的代码提示？这是另一个有用的工具，用于确定你是否可以访问你正在工作的级别的函数和变量。现在我们看到我们可以在控制台中执行代码，而不必修改我们的 JavaScript 文件。我们从控制台学到了什么？我们的`data.status`确实是`500`，所以我们从第 7 行抛出了控制台错误。从第 9 行，我们得到了我们的响应数据，它明确说明了`500`。可能不用说，但`console.log`，`console.error`和`console.info`函数在调试 JavaScript 时可能非常有价值。经常使用它们，但记得在将代码推送到生产级环境之前将它们删除，因为如果记录大对象或记录太频繁，它们可能会降低站点性能。

JavaScript 的一个棘手之处在于，你可能要处理数百行代码，有时还是来自第三方。幸运的是，大多数浏览器的工具允许在代码中设置*断点*，这会在指定的点中断代码的执行。让我们在控制台中看看我们之前的文件，并设置一些断点。如果我们点击第 7 行的错误，源面板将显示。如果你点击行号，你将设置一个断点，就像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4b98499a-4057-4475-91fe-8b2d90b2cf9d.png)

图 9.10 - 注意第 6 行上的箭头标记

在浏览器报错的那一行之前设置断点通常很有用，以便更彻底地跟踪传递给我们代码的变量。让我们再次运行我们的代码，刷新页面，看看会发生什么：

1.  在第 6 行和第 7 行设置断点。

1.  刷新页面。

1.  导航到控制台并执行我们之前的命令：`fetchAttempt('http://httpstat.us/500')`。

浏览器将再次拉起源选项卡，我们应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/94a2092e-2886-47e6-95b1-64569f3d69ad.png)

图 9.11 - 断点的结果

我们可以看到在作用域选项卡中，我们得到了在执行代码的上下文中定义的变量列表。然后，我们可以使用步骤按钮，如截图所示，继续移动到我们的断点并执行后续的代码行：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4f193063-65a3-4dc1-a12c-b71bf1e23a1c.png)

图 9.12 - 步骤按钮

当我们通过断点时，作用域面板将更新以显示我们当前的上下文，这比显式的`console.log`函数给我们更多的信息。

现在让我们看看如何改进 JavaScript 代码以提高性能的一些想法。

# 适应 JavaScript 的性能限制

与任何语言一样，有写 JavaScript 的方法，也有更好的写法。然而，在其他语言中不那么明显的是，您的代码对网站用户体验的直接影响。复杂、低效的代码可能会使浏览器变慢，消耗 CPU 周期，并且在某些情况下甚至会导致浏览器崩溃。

看一下 Talon Bragg 在[`hackernoon.com/crashing-the-browser-7d540beb0478`](https://hackernoon.com/crashing-the-browser-7d540beb0478)上的这个简单的四行代码片段：

```js
txt = "a";
while (1) {
    txt = txt += "a"; // add as much as the browser can handle
}
```

**警告**：*不要*在浏览器中尝试运行这个代码！如果您对此感到好奇，它最终会在浏览器中创建一个内存不足的异常，导致标签被关闭，并显示页面已经无响应的消息。为什么会这样？我们的`while`循环的条件是一个简单的真值，因此它将继续向字符串文本添加`"a"`，直到分配给该浏览器进程的内存耗尽。根据您的浏览器行为，它可能会崩溃标签、整个浏览器，或者更糟。我们都有不稳定程序的经验（Windows 蓝屏，有人吗？），但通常可以避免浏览器崩溃。除了编码最佳实践，如最小化循环和避免重新分配变量之外，还有一些特定于 JavaScript 的想法需要指出。W3Schools 有一些很有用的例子，可以在[`www.w3schools.com/js/js_performance.asp`](https://www.w3schools.com/js/js_performance.asp)找到，我想特别强调其中的一个。

在标准 JavaScript 应用程序中，最占用内存的操作之一是 DOM 访问。像`document.getElementById("helloWorld")`这样简单的一行代码实际上是一个相当昂贵的操作。作为最佳实践，如果您在代码中要多次使用 DOM 元素，您应该将其保存到一个变量中，并对该变量进行操作，而不是返回到 DOM 遍历。如果回想一下第六章：*文档对象模型（DOM）*，我们将便利贴 DOM 元素存储为一个变量：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-6/stickies/solution-code/script.js#L13`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-6/stickies/solution-code/script.js#L13)。

## 内存面板

不要深入讨论计算机如何分配内存的细节，可以说，编写不当的程序可能会导致内存泄漏，因为它没有正确释放和回收内存，这可能导致程序崩溃。与一些低级语言相反，JavaScript 应该自动进行垃圾回收：自动内存管理的实践，通过销毁不需要的数据片段来释放内存。然而，有些情况下，编写不当的代码可能会导致垃圾回收无法处理的内存泄漏。

由于 JavaScript 在客户端运行，很难准确解释程序中到底发生了什么。幸运的是，有一些工具可以帮助。让我们通过一个将分配大量内存的程序示例来进行演示。看一下这个例子：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-9/memory-leak/index.html.`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-9/memory-leak/index.html)

如果您查看包含的 JavaScript 文件，您会发现它非常简单，但非常强大：

```js
// Based on https://developers.google.com/web/tools/chrome-devtools/memory-problems

let x = []
const grow = (log = false) => {
  x.push(new Array(1000000).join('x'))
  if (log) {
    console.log(x)
  }
}

document.getElementById('grow').addEventListener('click', () => grow())
document.getElementById('log').addEventListener('click', () => grow(true))
```

让我们检查我们的代码，并看看当我们使用这个简单的脚本时会发生什么。请注意，这些说明可能会有所不同，具体取决于您的浏览器和操作系统版本：

1.  在 Chrome 中打开`index.html`页面。

1.  打开开发者工具。

1.  从“更多工具”菜单中，选择性能监视器：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/eb551f2d-5a1e-483e-b680-3d3a26ad2734.png)

图 9.13 - 调查性能监视器

您将看到一个带有移动时间线的面板：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-9/memory-leak/memory-leak.gif.`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/blob/master/chapter-9/memory-leak/memory-leak.gif)

1.  现在，点击几次 Grow 按钮。您应该看到 JavaScript 堆大小增加，可能达到 13MB 范围。但是，随着您不断点击，堆大小不应该超过已经存在的范围。

为什么会这样？在现代浏览器中，意外创建内存泄漏实际上变得有点困难。在这种情况下，Chrome 足够聪明，可以对内存进行一些技巧处理，不会因我们重复操作而导致内存大幅增加。

1.  然而，现在开始点击 Log 按钮几次。您将在控制台中看到输出以及堆大小的增加：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/6b77278a-ca50-4a47-8fca-ef7259a0ee72.png)

图 9.14 - 内存堆调查

注意图表的增长。然而，随着时间的推移，如果停止点击 Log，内存分配实际上会下降。这是 Chrome 智能垃圾回收的一个例子。

# 摘要

我们在编码时都会犯错误，知道如何找到、诊断和调试这些问题是任何语言中的关键技能。在本章中，我们已经看到了 Error 对象和控制台如何为我们提供丰富的诊断信息，包括错误发生的位置、对象上附加的详细信息以及如何阅读它们。不要忘记，有时错误可能在表面上看起来是一种方式（我们在*错误对象*部分的 JSON 错误），不要害怕尝试使用控制台语句和断点来跟踪代码。

由于 JavaScript 在客户端运行，因此重要的是要牢记用户的性能容量。在编写 JavaScript 时有许多最佳实践，例如重用变量（特别是与 DOM 相关的变量），因此请务必确保使您的代码 DRY（不要重复自己）。

在下一章中，我们将结束前端的工作，并了解 JavaScript 真正是前端的统治者。

# 问题

1.  内存问题的根本原因是什么？

1.  您程序中的变量是全局的。

1.  低效的代码。

1.  JavaScript 的性能限制。

1.  硬件不足。

1.  在使用 DOM 元素时，应将对它们的引用存储在本地，而不是始终访问 DOM。

1.  正确

1.  错误

1.  在多次使用时为真

1.  JavaScript 在服务器端进行预处理，因此比 Python 更高效。

1.  正确

1.  错误

1.  设置断点无法找到内存泄漏。

1.  正确

1.  错误

1.  将所有变量存储在全局命名空间中是个好主意，因为它们更有效地引用。

1.  正确

1.  错误

# 进一步阅读

有关更多信息，您可以使用以下链接：

+   使用 Chrome 的分配时间线隔离内存泄漏：[`blog.logrocket.com/isolating-memory-leaks-with-chromes-allocation-timeline-244fa9c48e8e/`](https://blog.logrocket.com/isolating-memory-leaks-with-chromes-allocation-timeline-244fa9c48e8e/)

+   垃圾回收：[`en.wikipedia.org/wiki/Garbage_collection_(computer_science)`](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science))

+   JavaScript 性能：[`www.w3schools.com/js/js_performance.asp`](https://www.w3schools.com/js/js_performance.asp)

+   内存问题：[`developers.google.com/web/tools/chrome-devtools/memory-problems`](https://developers.google.com/web/tools/chrome-devtools/memory-problems)

+   Node.js 内存泄漏检测：[`medium.com/tech-tajawal/memory-leaks-in-nodejs-quick-overview-988c23b24dba`](https://medium.com/tech-tajawal/memory-leaks-in-nodejs-quick-overview-988c23b24dba)


# 第十章：JavaScript，前端的统治者

如果您开始领会 JavaScript 对现代网站和 Web 应用程序功能的重要性，那么您正在走上正确的道路。没有 JavaScript，我们在网页上理所当然的大多数用户界面都不会存在。让我们更仔细地看看 JavaScript 如何将前端整合在一起。我们将使用一些 React 应用程序，并比较和对比 Python 应用程序，以进一步了解 JavaScript 在前端的重要性的原因和方式。

本章将涵盖以下主题：

+   构建交互

+   使用动态数据

+   了解现代应用程序

# 技术要求

准备好使用存储库中`Chapter-10`目录中提供的代码进行工作，网址是[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-10`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-10)。由于我们将使用命令行工具，因此请确保您的终端或命令行 shell 可用。我们需要一个现代浏览器和一个本地代码编辑器。

# 构建交互

让我们看一个简单的**单页应用程序**（**SPA**）：

1.  导航到`chapter-10`中的`simple-reactjs-app`目录（`cd simple-reactjs-app`）。

1.  使用`npm install`安装依赖项。

1.  使用`npm start`运行应用程序。

1.  在`http://localhost:3000`访问应用程序。您会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2ab2abff-d8e7-4629-b096-18ce5772a770.png)

图 10.1 - 简单的 React 应用程序

当您单击详细按钮并检查网络选项卡时，您会发现页面不会重新加载，它只会从服务器加载 JSON 数据。这是单页应用程序功能的一个非常基本的示例：使用最少的服务器使用，用户体验的交互被简化，有助于高效、低开销的工作流程。您可能熟悉其他单页应用程序，如 Gmail、Google 地图和 Facebook，尽管底层技术有所不同。

在互联网技术时代，JavaScript 可能被视为理所当然，但它是这些应用程序工作的基础。没有 JavaScript，我们将有大量的页面重新加载和长时间等待，即使使用 Ajax 也是如此。

让我们通过比较和对比一个基本的 Python 示例和一个现代的 React 应用程序来看看如何使用动态数据。

# 使用动态数据

让我们首先看一个 Python Flask 示例：

1.  导航到`chapter-10`中的`flask`目录（`cd flask`）。

1.  您需要安装一些组件以进行设置。以下说明适用于 Python：

1.  使用`python3 -m venv env`创建虚拟环境。

1.  使用`. env/bin/activate`激活它。

1.  安装要求：`pip3 install -r requirements.txt`。

1.  现在您可以启动应用程序：`python3 app.py`。

1.  在`http://localhost:5000`访问页面。您会看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2ca6bb7c-1df9-4cba-8575-cfb6ee5ad305.png)

图 10.2 - 基本 Flask 应用程序

尝试输入和不输入您的姓名，并观察页面在这样做时重新加载的事实（我添加了时间戳，以便更容易看到页面重新加载可能发生得太快而看不到）。这是一个非常基本的 Flask 应用程序，有更有效的方法可以使用 Python 和 JavaScript 的组合进行验证工作，但在基本水平上，即使使用一些基于 Flask 的表单验证工具，我们所看到的验证和交互也是在后端进行的。每次我们点击提交时，服务器都会被访问。以下截图显示了如果您不输入字符串的服务器端验证：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/8928d486-d5e2-499b-81e1-a0f56af3f9c1.png)

图 10.3 - 基本 Flask 验证

请注意时间戳的更改，表示服务器重新渲染。

通过修改我们简单的 React 应用程序，让我们为我们的表单验证交互做得更好：

1.  导航到`reactjs-app-form`目录：`cd reactjs-app-form`。

1.  安装依赖项：`npm install`。

1.  启动服务器：`npm start`。

1.  在`http://localhost:5000`访问页面。这是我们简单应用的更新版本：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9536ba0a-56b9-4802-bca2-47e41675bbc8.png)

图 10.4 - 具有动态数据的简单应用

现在尝试使用它，并注意如果您更改一个主要字段，左侧的字段也会更改。此外，它会*在您编辑时*保存 JSON，因此如果您刷新页面，您的更改将保留。这要归功于 JavaScript 的强大功能：React 前端正在处理您在应用程序各个部分进行的所有更改，然后 Express 后端正在提供和保存 JSON 文件。在这种情况下，页面上标记的更新是实时发生的。当然，每次编辑时我们都会与服务器进行保存和读取操作，但这是因为应用程序的设计方式。要保持更改，创建一个保存按钮而不是在字段更改时进行保存将是微不足道的。

如果您想使用这个示例，您需要做一些事情：

1.  首先，在新的 shell 窗口中导航到目录（保留之前的实例运行）：`cd client`。

1.  执行`npm install`。

1.  开始程序：`npm start`。

然后，Express 服务器将收集由 React 运行过程创建的构建文件，与已经存在于目录中的预构建文件进行比较。

## 输入验证和错误处理

关于动态数据的一个重要部分是*输入验证*和*错误处理*。请注意，在我们的应用程序中，如果电子邮件字段为空或者我们没有输入有效的电子邮件，它将有一个红色轮廓。否则，它将有一个绿色轮廓。当您输入有效的电子邮件地址并选择下一个字段时，您会发现红色轮廓会在不与服务器交互的情况下（除了保存数据，正如我们之前讨论的那样）变为绿色。这是客户端验证，当创建流畅的用户体验时非常强大：用户不必点击保存并等待服务器响应，以查看他们是否输入了不正确的数据。

在处理电话字段时，您可能已经注意到一个细节：它被限制为数字。如果您查看`client/src/CustomerDetails.js`，我们在这里将类型限制为数字：

```js
<Input name="phone" type="number" value={this.state.customerDetails.data.phone || ''} onChange={this.handleChange} />
```

这里还有一些其他的 React 部分。让我们来看一下`handleChange`函数：

```js
handleChange(event) {
   const details = this.state.customerDetails
   details.data[event.target.name] = event.target.value
   this.validate(event.target)

   this.setState({ customerDetails: details })
   console.log(this.state.customerDetails)

   axios.post(`${CONSTANTS.API_ROOT}/api/save/` + 
   this.state.customerDetails.data.id, details)
     .then(() => {
       this.props.handler();
     })
 }
```

Axios 是一个简化 Ajax 调用的库，我在这里使用它而不是`fetch`只是为了演示。您可能会在 React 工作中看到 Axios 被使用，尽管您始终可以选择使用原始的`fetch`。但是，让我们专注于`this.validate(event.target)`这一行。

这是函数的内容：

```js
validate(el) {
   const properties = (el.name) ? el : el.props

   if (properties.name === 'email') {
     if (validateEmail(properties.value)) {
       this.setState({ validate: { email: true }});
     } else {
       this.setState({ validate: { email: false }});
     }
   }
 }
```

`validateEmail()`是一个神奇的函数！您可以在`client/src/validation.js`中找到它，它使用*正则表达式*来模式匹配输入字符串，以查看它是否看起来像一个正确格式的电子邮件地址。然后，根据函数返回`true`或`false`，我们设置一个验证状态，React 将使用它来设置电子邮件字段的边框颜色。

前端验证和错误处理对于流畅的用户体验非常重要，但这只是故事的一部分。另一部分是安全性。

## 安全和数据

正如您从浏览器中的开发者工具中了解的那样，如果您努力尝试，几乎可以规避任何前端限制。例如，对于我们的电话字段，尽管我们在前端限制了它，但我们总是可以检查 HTML 并输入任何我们想要的值。一个快速的提示是，也很重要在后端验证您的数据，以确保它格式正确。

企业数据泄露和黑客攻击的一个共同点是攻击者利用了系统中的弱点。很少是密码泄露的情况；更常见的是弱加密或甚至是前端问题。我们将在第十七章中进一步讨论安全性和密钥。您可以在[OWASP.org](https://OWASP.org)了解更多信息。

让我们继续回顾我们所学到的东西。

# 理解现代应用程序

在这一点上，毫不奇怪的是，所有现代 Web 应用程序都与 JavaScript 紧密联系在一起。没有它，交互就无法实时发生。服务器端有其位置和重要性，但用户看到和交互的关键是由 JavaScript 控制的。

就像 CSS 是 HTML 的补充一样，JavaScript 是这个组合中的第三个朋友，通过一系列标记和样式创建有意义的体验。作为 Web 应用程序的肌肉，它为我们提供丰富的交互和逻辑，并且是所有单页应用程序的基础。它真的是一个神奇而美丽的工具。

# 总结

通过 JavaScript，我们可以超越“网页”，创建完整的 Web 应用程序。从电子邮件系统到银行，再到电子表格，几乎任何您使用计算机的东西，JavaScript 都可以帮助您。

在下一章中，我们将使用 Node.js 在服务器端使用 JavaScript。我们不会完全抛弃前端，而是会看到它们如何联系在一起。


# 第三部分 - 后端：Node.js vs. Python

现在我们已经看到了 JavaScript 在前端的用法（一个新的，可能令人恐惧的地方），让我们换个角度，转向后端。当在后端使用时，Node.js 与 Python 有更多的共同之处，但也有显著的区别。让我们构建一个应用程序来探索 Node.js 的工作原理。

在本节中，我们将涵盖以下章节：

+   第十一章，*什么是 Node.js?*

+   第十二章，*Node.js vs. Python*

+   第十三章，*使用 Express*

+   第十四章，*React 与 Django*

+   第十五章，*将 Node.js 与前端结合使用*

+   第十六章，*进入 Webpack*


# 第十一章：什么是 Node.js？

现在我们已经研究了 JavaScript 在前端的使用，让我们深入探讨它在“JavaScript 无处不在”范式中的作用，使用 Node.js。我们在第二章，*我们可以在服务器端使用 JavaScript 吗？当然可以！*中讨论了 Node.js，现在是时候更深入地了解我们如何使用它来创建丰富的服务器端应用程序了。

本章将涵盖以下主题：

+   历史和用法

+   安装和用法

+   语法和结构

+   Hello, World!

# 技术要求

准备好在存储库的 `Chapter-11` 目录中使用提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11)。由于我们将使用命令行工具，还需要准备好终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# 历史和用法

Node.js 首次发布于 2009 年，已被行业中的大公司和小公司广泛采用。在 Node.js 中有成千上万的可用包，为用户和开发者社区创造了丰富的生态系统。与任何开源项目一样，社区支持对于技术的采用和长期性至关重要。

从技术角度来看，Node.js 是一个单线程事件循环的运行时环境。在实践中，这意味着它可以处理成千上万个并发连接，而无需在上下文之间切换时产生额外开销。对于那些更熟悉其他架构模式的人来说，单线程可能看起来有些违反直觉，过去它曾被视为 Node.js 感知到的断点的一个例子。然而，可以说 Node.js 系统的稳定性和可靠性已经证明了这种范式是可持续的。有办法增加服务器处理请求的能力，但应该注意的是，这比简单地向问题投入更多硬件资源要复杂一些。如何扩展 Node.js 超出了本书的范围，但涉及到底层库 libuv 的技术。

在撰写本文时，Node.js 最大的优势可能是推动 Twitter。根据 SimilarTech 的数据，其每月 43 亿次访问证明了其强大的力量。现在，我相信 Twitter 团队多年来在推动平台方面做了一些令人难以置信的架构工作，我们很少再看到著名的 Twitter “fail whale”；我认为依赖 Node.js 是一个有助于提供可持续性和可靠性的好事情。

继续使用它！

# 安装和用法

安装 Node.js 的最简单方法是使用 [`nodejs.org`](https://nodejs.org) 提供的安装程序。这些包将指导您在系统上安装 Node.js。确保还安装了 `npm`，Node 的包管理器。您可以参考第三章，*细枝末节的语法*，了解更多安装细节。

让我们试一试：

1.  打开一个终端窗口。

1.  输入 `node`。您将看到一个简单的 `>`，表示 Node.js 正在运行。

1.  输入 `console.log("Hi!")` 并按 *Enter*。

就是这么简单！通过两次按 *Ctrl + C* 或输入 `.exit` 来退出命令提示符。

所以，这相当基础。让我们做一些更有趣的事情。这是 `chapter-11/guessing-game/guessing-game.js` 的内容：

```js
const readline = require('readline')
const randomNumber = Math.ceil(Math.random() * 10)

const rl = readline.createInterface({
 input: process.stdin,
 output: process.stdout
});

askQuestion()

function askQuestion() {
 rl.question('Enter a number from 1 to 10:\n', (answer) => {
   evaluateAnswer(answer)
 })
}

function evaluateAnswer(guess) {
 if (parseInt(guess) === randomNumber) {
   console.log("Correct!\n")
   rl.close()
   process.exit(1)
 } else {
   console.log("Incorrect!")
   askQuestion()
 }
}
```

使用 `node guessing-game.js` 运行程序。从代码中您可能能够看出，程序将在 1 到 10 之间选择一个随机数，然后要求您猜测它。您可以在命令提示符中输入数字来猜测这个数字。

让我们在下一节中分解这个示例。

# 语法和结构

Node.js 的伟大之处在于您已经知道如何编写它！举个例子：

| **JavaScript** | **Node.js** |
| --- | --- |
| **`console.log("Hello!")`** | **`console.log("Hello!")`** |

这不是一个技巧：它是相同的。Node.js 在语法上几乎与基于浏览器的 JavaScript 相同，甚至包括 ES5 和 ES6 之间的区别，正如我们之前讨论过的。根据我的经验，Node.js 中仍然存在大量使用 ES5 风格的代码，因此您会看到使用`var`而不是`let`或`const`的代码，以及大量使用分号。您可以查看第三章，*细枝末节的语法*，了解更多关于这些区别的信息。

在我们的猜数字游戏示例中，我们看到了一个对我们来说是新的东西 - 第一行：

`const readline = require('readline')`

Node.js 是一个*模块化*系统，这意味着并非所有语言的部分都会一次性引入。相反，当发出`require()`语句时，将包含模块。其中一些模块将内置到 Node.js 中，如`readline`，而另一些将通过 npm 安装（更多内容将在后面介绍）。我们使用`readline.createInterface()`方法创建一种使用我们的输入和输出的方式，然后我们猜数字游戏程序的其余代码应该是有些意义的。它只是会一遍又一遍地问问题，直到输入的数字等于程序生成的随机数：

```js
function evaluateAnswer(guess) {
 if (parseInt(guess) === randomNumber) {
   console.log("Correct!\n")
   rl.close()
   process.exit(1)
 } else {
   console.log("Incorrect!")
   askQuestion()
 }
}
```

让我们看一个例子，从文件系统中读取文件，这是我们无法从普通的客户端 Web 应用程序中做到的。

## 客户查找

查看`customer-lookup`目录，[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11/customer-lookup`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11/customer-lookup)，并使用`node index.js`运行脚本。这很简单：

```js
const fs = require('fs')
const readline = require('readline')

const rl = readline.createInterface({
 input: process.stdin,
 output: process.stdout
});

const customers = []

getCustomers()
ask()

function getCustomers() {
 const files = fs.readdirSync('data')

 for (let i = 0; i < files.length; i++) {
   const data = fs.readFileSync(`data/${files[i]}`)
   customers.push(JSON.parse(data))
 }
}

function ask() {
 rl.question(`There are ${customers.length} customers. Enter a number to 
 see details:\n`, (customer) => {
   if (customer > customers.length || customer < 1) {
     console.log("Customer not found. Please try again")
   } else {
     console.log(customers[customer - 1])
   }
   ask()
 })
}
```

其中一些看起来很熟悉，比如`readline`接口。不过，我们正在使用一些新的东西：`const fs = require('fs')`。这是引入文件系统模块，以便我们可以处理存储在文件系统上的文件。如果您查看数据目录，您会发现四个基本的 JSON 文件。

在`getCustomers()`函数中，我们要做三件事：

1.  使用`readdirSync`获取数据目录中文件的列表。在处理文件系统时，您可以以同步或异步方式与系统进行交互，类似于与 API 和 Ajax 进行交互。为了方便起见，在本例中，我们将使用同步文件系统调用。

1.  现在`files`将是数据目录中文件的列表。循环遍历文件并将内容存储在`data`变量中。

1.  将解析后的 JSON 推送到`customers`数组中。

到目前为止一切顺利。`ask()`函数也应该很容易理解，因为我们只是查看用户输入的数字是否存在于数组中，然后返回相关文件中的数据。

现在让我们看看如何在 Node.js 中使用开源项目来实现一个（相当愚蠢的）目标：创建照片的文本艺术表示。

## ASCII 艺术和包

我们将使用 GitHub 存储库中的指令[`www.npmjs.com/package/asciify-image`](https://www.npmjs.com/package/asciify-image)：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/7553f1bb-1fe2-4e98-bde5-4baa497be6b6.png)

图 11.1 - 我的 ASCII 艺术表示！

以下是逐步安装步骤：

1.  创建一个名为`ascii-art`的新目录。

1.  `cd ascii-art`

1.  `npm init`。您可以接受 npm 提供的默认值。

1.  `npm install asciify-image`

现在，让我们来玩一些游戏：

1.  在`ascii-art`目录中放置一张图片，比如一个大小不超过 200 x 200 像素的 JPEG。命名为`image.jpg`。

1.  在目录中创建`index.js`并打开它。

1.  输入此代码：

```js
const asciify = require('asciify-image')

asciify(__dirname + '/image.jpg', { fit: 'box', width: 25, height: 25}, (err, converted) => {
 console.log(err || converted)
})
```

1.  使用`node index.js`执行程序，并查看你美妙的艺术作品！根据你的终端颜色，你可能需要使用一些选项来改变颜色以在浅色背景上显示。这些选项在之前链接的 GitHub 存储库中有文档记录。

我们在这里展示了什么？首先，我们使用 npm 初始化了一个项目，然后安装了一个依赖项。如果你注意到了，运行这些命令为你创建了一些文件和目录。你的目录结构应该看起来接近这样：

```js
.
├── image.jpg
├── index.js
├── node_modules

├── package-lock.json
└── package.json
```

`node_modules`目录里会有更多的文件。如果你熟悉 Git 等源代码控制，你会知道`node_modules`目录应该始终被*忽略*，不要提交到源代码控制。

让我们来看看`package.json`，它看起来会类似于这样：

```js
{
 "name": "ascii-art",
 "version": "1.0.0",
 "description": "",
 "main": "index.js",
 "dependencies": {
   "asciify-image": "⁰.1.5"
 },
 "devDependencies": {},
 "scripts": {
   "test": "echo \"Error: no test specified\" && exit 1"
 },
 "author": "",
 "license": "ISC"
}
```

如果我们稍微分析一下，我们会发现这个 npm 入口点到我们的程序实际上相当简单。有关项目的一些元数据，一个带有版本的依赖对象，以及一些我们可以用来控制我们的项目的脚本。

如果你熟悉 npm，你可能已经使用`npm start`命令来运行一个项目，而不是手动输入`node`。然而，在我们的`package.json`中，我们没有一个启动脚本。让我们添加一个。

修改`scripts`对象看起来像这样：

```js
"scripts": {
   "test": "echo \"Error: no test specified\" && exit 1",
   "start": "node index.js"
 },
```

不要忘记注意你的逗号，因为这是有效的 JSON，如果逗号使用不当，它将会中断。现在，要启动我们的程序，我们只需要输入`npm start`。

这是 npm 脚本的一个非常基本的例子。在 Node.js 中，习惯使用`package.json`来控制所有构建和测试的脚本。你可以按自己的喜好命名你的命令，并像这样执行它们：`npm run my-fun-command`。

对于我们接下来的技巧，我们将从头开始创建一个“Hello, World!”应用程序。然而，它将做的不仅仅是打招呼。

# 你好，世界！

创建一个名为`hello-world`的新目录，并使用`npm init`初始化一个 node 项目，类似于我们之前的做法。在第十三章，*使用 Express*中，我们将使用 Express，一个流行的 Node.js 网络服务器。然而，现在，我们将使用一种非常简单的方法来创建一个页面。

开始你的`index.js`脚本如下：

```js
const http = require('http')

http.createServer((req, res) => {
 res.writeHead(200, {'Content-Type': 'text/plain'})
 res.end("Hello, World!")
}).listen(8080)

```

与`fs`和`readline`一样，`http`内置在 Node 中，所以我们不必使用`npm install`来获取它。相反，这将直接使用。在你的`package.json`文件中添加一个启动脚本：

```js
"scripts": {
   "test": "echo \"Error: no test specified\" && exit 1",
   "start": "node index.js"
 },
```

然后启动它！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/080f19a7-30c4-4f87-b7a9-7e6da46b72fb.png)

图 11.2 - 执行 npm start

好的，我们的输出并不是特别有用，但是如果我们阅读我们的代码，我们可以看到我们已经做到了这一点：“创建一个监听端口`8080`的 HTTP 服务器。发送一个 200 OK 消息并输出'Hello, World!'”。现在让我们打开浏览器并转到[`localhost:8080`](http://localhost:8080)。我们应该看到一个简单的页面向我们问候。

太好了！到目前为止很容易。用*Ctrl* + *C*停止你的服务器，然后让我们继续编码。

如果我们能够使用我们在上一个例子中使用的 ASCII 艺术生成器来要求用户输入，然后在浏览器中显示图像，那该多好啊？让我们试试看。

首先，我们需要运行`npm install asciify-image`，然后让我们尝试这段代码：

```js
const http = require('http')
const asciify = require('asciify-image')

http.createServer((req, res) => {
 res.writeHead(200, {'Content-Type': 'text/html'})
 asciify(__dirname + '/img/image.jpg', { fit: 'box', width: 25, height: 25
  }, (err, converted) => {
   res.end(err || converted)
 })
}).listen(8080)
```

这与我们之前输出到命令行的方式类似，但是我们使用`http`服务器`res`对象来发送一个回复。用`npm start`启动你的服务器，让我们看看我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/f58391fa-224c-4ea7-9119-01b6d66894ee.png)

图 11.3 - 原始输出

好吧，这与我们想要看到的完全不一样。这就是问题所在：我们发送给浏览器的是*ANSI 编码的文本*，而不是实际的 HTML。我们需要做一些工作来转换它。再次退出服务器然后…

等一下。为什么我们必须不断地启动和停止服务器？事实证明，我们*不* *真的*必须这样做。有一些工具可以在文件更改时重新加载我们的服务器。让我们安装一个叫做**supervisor**的工具：

1.  `npm install supervisor`

1.  修改你的`package.json`启动脚本以读取`supervisor index.js`。

现在使用`npm start`启动服务器，当你编码时，服务器将在保存后重新启动，使开发速度更快。

回到代码。我们需要一个将 ANSI 转换为 HTML 的包。使用`npm install`安装`ansi-to-html`，然后让我们开始：

```js
const http = require('http')
const asciify = require('asciify-image')
const Convert = require('ansi-to-html')
const convert = new Convert()

http.createServer((req, res) => {
 res.writeHead(200, {'Content-Type': 'text/html'})
 asciify(__dirname + '/img/image.jpg', { fit: 'box', width: 25, height: 25 
  }, (err, converted) => {
   res.end(convert.toHtml(err || converted))
 })
}).listen(8080)
```

如果刷新浏览器，你会看到我们离成功更近了！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/de16bcff-7512-4268-8e40-11e230153d8e.png)

图 11.4 - 这是 HTML！

现在我们只需要一点 CSS：

```js
const css = `
<style>
body {
 background-color: #000;
}
* {
 font-family: "Courier New";
 white-space: pre-wrap;
}
</style>
`
```

将其添加到我们的`index.js`中，并连接到输出，如下所示：

```js
asciify(__dirname + '/img/image.jpg', { fit: 'box', width: 25, height: 25 }, (err, converted) => {
   res.write(css)
   res.end(convert.toHtml(err || converted))
 })
```

现在刷新，我们应该能看到我们的图片！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/6ca08eed-b3e4-4b0e-8305-121ad05fde11.png)

图 11.5 - ANSI 转 HTML

太棒了！比只打印“Hello, World!”要令人兴奋多了，你不觉得吗？

让我们通过重新访问我们在第七章中的宝可梦游戏来增强我们的 Node.js 技能，*事件，事件驱动设计和 API*，但这次是在 Node.js 中。

## Pokéapi，重访

我们将使用 Pokéapi ([`pokeapi.co`](https://pokeapi.co)) 制作一个小型终端**命令行界面**（**CLI**）游戏。由于我们在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code)中有游戏的基本逻辑，我们只需要开始并将游戏逻辑从前端移植到后端的 Node.js 中完成游戏。

从头开始一个新项目，如下所示：

1.  `mkdir pokecli`

1.  `npm init`

1.  `npm install asciify-image axios terminal-kit`

1.  从[`pokeapi.co`](https://pokeapi.co)复制 Pokéapi 标志到一个新的`img`目录，使用浏览器中的 Save Image。

1.  创建一个新的`index.js`文件。

1.  修改`package.json`，添加一个启动脚本，如下所示：`"start": "node index.js"`。

你的文件结构应该是这样的，减去`node_modules`目录：

```js
.
├── img
│   └── pokeapi_256.png
├── index.js
├── package-lock.json
└── package.json
```

让我们开始在我们的`index.js`上工作。首先，我们需要包括我们正在使用的包：

```js
const axios = require('axios')
const asciify = require('asciify-image')
const term = require('terminal-kit').terminal
```

接下来，由于我们将使用 API 来检索和存储我们的宝可梦，让我们创建一个新对象将它们存储在顶层，这样我们就可以访问它们：

```js
const pokes = {}
```

现在我们将使用 Terminal Kit ([`www.npmjs.com/package/terminal-kit`](https://www.npmjs.com/package/terminal-kit)) 来创建一个比标准的`console.log`输出和`readline`输入更好的 CLI 体验：

```js
function terminate() {
 term.grabInput(false);
 setTimeout(function () { process.exit() }, 100);
}
term.on('key', (name, matches, data) => {
 if (name === 'CTRL_C') {
   terminate();
 }
})
term.grabInput({ mouse: 'button' });
```

我们在这里做的第一件事是创建一个终止函数，它将在停止`term`捕获输入后退出我们的 Node.js 程序，以进行清理。下一个方法指定当我们按下*Ctrl* + *C*时，程序将调用`terminate()`函数退出。*这是我们程序的一个重要部分，因为`term`默认情况下不会在按下 Ctrl + C 时退出。*最后，我们告诉`term`捕获输入。

开始我们的游戏，从 Pokéapi 标志的闪屏开始：

```js
term.drawImage(__dirname + '/img/pokeapi_256.png', {
 shrink: {
   width: term.width,
   height: term.height * 2
 }
})
```

我们可以直接使用`term`而不是`asciify-image`库（不用担心，我们以后会用到）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c7fb371b-261a-4275-bb5f-30662794ae8f.png)

图 11.6 - Pokéapi 闪屏

接下来，编写一个函数，使用 Axios Ajax 库从 API 中检索信息：

```js
async function getPokemon() {
 const pokes = await axios({
   url: 'https://pokeapi.co/api/v2/pokemon?limit=50'
 })

 return pokes.data.results
}
```

Axios ([`www.npmjs.com/package/axios`](https://www.npmjs.com/package/axios)) 是一个使请求比`fetch`更容易的包，通过减少所需的 promise 数量。正如我们在之前的章节中看到的，`fetch`很强大，但确实需要一些 promise 解析的链接。这次，让我们使用 Axios。请注意，该函数是一个`async`函数，因为它将返回一个 promise。

用`start()`函数开始我们的游戏：

```js
async function start() {
 const pokemon = await getPokemon()
}
```

我们将保持简单。请注意，此函数还使用了 async/await 模式，并调用我们的函数，该函数使用 API 检索宝可梦列表。此时，通过使用`console.log()`输出`pokemon`的值来测试我们的程序是一个好主意。您需要在程序中调用`start()`函数。您应该看到 50 只宝可梦的漂亮 JSON 数据。

在我们的`start()`函数中，我们将要求玩家选择他们的宝可梦并显示消息：

```js
term.bold.cyan('Choose your Pokémon!\n')
```

现在我们将使用我们的`pokemon`变量使用`term`创建一个网格菜单，询问我们的玩家他们想要哪个宝可梦，如下所示：

```js
term.gridMenu(pokemon.map(mon => mon.name), {}, async (error, response) => {
   pokes['player'] = pokemon[response.selectedIndex]
   pokes['computer'] = pokemon[(Math.floor(Math.random() *
    pokemon.length))]
})
```

您可以阅读`term`的文档，了解有关网格菜单的选项更多的信息。现在我们应该运行我们的代码，为了做到这一点，在程序的末尾添加对`start()`函数的调用：

```js
start()
```

如果我们用`npm start`运行我们的代码，我们将看到这个新的添加：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/b8ce5459-6acd-49ca-b053-4544769c5316.png)

图 11.7 - 菜单

通过箭头键，我们可以在网格周围导航，并通过按*Enter*来选择我们的宝可梦。在我们的代码中，我们正在为我们的`pokes`对象的两个条目分配值：`player`和`computer`。现在，`computer`将是从我们的`pokemon`变量中随机选择的条目。

我们需要更多的信息来玩我们的宝可梦，所以我们将创建一个辅助函数。将其添加到我们的`start`函数中：

```js
await createPokemon('player')
await createPokemon('computer')
```

现在我们将编写`createPokemon`函数如下：

```js
async function createPokemon(person) {
 let poke = pokes[person]

 const myPoke = await axios({
   url: poke.url,
   method: 'get'
 })
 poke = myPoke.data
 const moves = poke.moves.filter((move) => {
   const mymoves = move.version_group_details.filter((level) => {
     return level.level_learned_at === 1
   })
   return mymoves.length > 0
 })
 const move1 = await axios({
   url: moves[0].move.url
 })
 const move2 = await axios({
   url: moves[1].move.url
 })
 pokes[person] = {
   name: poke.name,
   hp: poke.stats[5].base_stat,
   img: await createImg(poke.sprites.front_default),
   moves: {
     [moves[0].move.name]: {
       name: moves[0].move.name,
       url: moves[0].move.url,
       power: move1.data.power
     },
     [moves[1].move.name]: {
       name: moves[1].move.name,
       url: moves[1].move.url,
       power: move2.data.power
     }
   }
 }
}
```

让我们解释一下这个函数在做什么。首先，我们将从 API 中获取有关我们的宝可梦的信息（一次为玩家，一次为计算机）。由于游戏玩法复杂，宝可梦的移动部分有点复杂。对于我们的目的，我们将简单地为我们的宝可梦在`pokes`对象中分配前两个可能的移动。

对于图像，我们使用了一个小的辅助函数：

```js
async function createImg(url) {
 return asciify(url, { fit: 'box', width: 25 })
   .then((ascii) => {
     return ascii
   }).catch((err) => {
     console.error(err);
   });
}
```

我们几乎完成了我们游戏的开始部分！我们需要在`start`中的`gridMenu`方法中添加几行：

```js
term.gridMenu(pokemon.map(mon => mon.name), {}, async (error, response) => {
   pokes['player'] = pokemon[response.selectedIndex]
   pokes['computer'] = pokemon[(Math.floor(Math.random() * 
    pokemon.length))]
   await createPokemon('player')
   await createPokemon('computer')
   term(`Your ${pokes['player'].name} is so 
    cute!\n${pokes['player'].img}\n`)
   term.singleLineMenu( ['Continue'], (error, response) => {
     term(`\nWould you like to continue against the computer's scary
     ${pokes['computer'].name}? \n ${pokes['computer'].img}\n`)
     term.singleLineMenu( ['Yes', 'No'], (error, response) => {
       term(`${pokes['computer'].name} is already attacking! No time to 
       decide!`)
     })
   })
 })
```

现在我们可以玩了！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/dfe94d19-f122-47cf-8d43-a51ccd88f404.png)

图 11.8 - 介绍你的宝可梦！

程序继续进行计算机选择宝可梦：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/602352a9-38c0-457e-b178-03b787b84a97.png)

图 11.9 - 可怕的敌人宝可梦

目前，我们还没有包括使用移动和生命值进行实际游戏。这可以成为您根据第七章*事件、事件驱动设计和 API**s*的逻辑来完成`play()`函数的挑战。

完整的代码在这里：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11/pokecli`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-11/pokecli)。

恭喜！我们做得比“Hello, World!”要多得多。

# 总结

我们在本章中学到，Node.js 是一种完整的编程语言，能够做几乎所有与后端相关的事情。我们将在第十八章*，Node.js 和 MongoDB*中使用 Node.js 进行数据库操作，但是目前，我们可以放心地说它可以做现代编程语言所期望的事情。

Node.js 的好处在于它的语法和结构*是*普通的 JavaScript！一些术语不同，但总的来说，如果你能读写 JavaScript，你就能读写 Node.js。就像每种语言一样，术语和用法上有差异，但事实是 Node.js 和 JavaScript 是同一种语言！

在下一章中，我们将讨论 Node.js 和 Python 以及在何种情况下使用其中之一是有意义的。

# 进一步阅读

有关更多信息，您可以参考以下内容：

+   libuv：[`en.wikipedia.org/wiki/Libuv`](https://en.wikipedia.org/wiki/Libuv)

+   市场份额和 Web 使用统计：[`www.similartech.com/technologies/nodejs`](https://www.similartech.com/technologies/nodejs)


# 第十二章：Node.js 与 Python

为什么开发人员会选择 Node.js 而不是 Python？它们可以一起工作吗？我们的程序是什么样子的？这些问题等等都是 Python 和 Node.js 之间一些差异的核心，了解何时以及在何处使用特定的语言非常重要。例如，有些任务更适合某种语言，而不适合其他语言，技术人员有责任为适当的语言进行倡导。让我们调查在选择 Node.js 与 Python 时的用例和不同的考虑因素。

本章将涵盖以下主题：

+   Node.js 和 Python 之间的哲学差异

+   性能影响

# 技术要求

准备好使用存储库中`Chapter-12`目录中提供的代码，网址为[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-12`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-12)。由于我们将使用命令行工具，请确保你的终端或命令行 shell 可用。我们需要一个现代浏览器和一个本地代码编辑器。

# Node.js 和 Python 之间的哲学差异

通常会有一个你熟悉、使用并且感到舒适的主要语言。然而，重要的是要意识到并非所有编程语言都是为相同的目的而创建的。这就是为什么使用合适的工具非常重要。就像你不会用小刀来建造房子一样，你可能也不会用台锯来把树枝削成棍子，用于篝火做棉花糖。

如果你在这个行业呆了一段时间，你可能听说过“堆栈”这个术语。在技术上，堆栈是用于创建程序或多个程序的生态系统的技术的架构组合。过去，应用程序往往是大规模的**单体应用**，以“一款应用程序统治它们所有”为思维方式构建的。在今天的世界中，单体应用的使用正在减少，而更多地采用多个更小的应用程序和**微服务**。通过这种方式，工作流程的不同部分可以分布到完全独立的进程中，大大提高了整个系统的稳定性。

让我们以办公软件为例。你肯定不会试图在 Microsoft Excel 中写下你的下一部畅销小说，你可能也不想在 Microsoft Word 中做税务。这些程序之间存在着“关注点分离”。它们在工作流程中很好地协同工作并形成一个统一的整体，但每个程序都有自己的作用。

同样，Web 应用程序中的不同技术部分都有自己的用途和关注点。用于 Web 应用程序的更传统的堆栈之一称为**LAMP**（**Linux, Apache, MySQL 和 PHP**）。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/db3645d2-d9b2-4f38-a070-9ccdccd29948.png)

图 12.1 - LAMP 堆栈

你可以看到，当讨论具体的 Web 应用程序时，我们将 Web 浏览器和客户端堆栈视为已知但未列在 LAMP 缩写中。在这种情况下，LAMP 只是服务器端组件。

随着 Web 的发展，支持它的基础技术及其堆栈也在发展。现在你可能会听到的两种更常见的堆栈是**MEAN**（**MongoDB, Express, Angular 和 Node.js**）和**MERN**（**MongoDB, Express, React 和 Node.js**）。这两者之间唯一的区别是 Angular 与 React。它们在一个稳定的系统中实质上扮演着相同的角色。我们将在第十三章中探讨 Express，这是 Node.js 的普遍 Web 服务器框架，以及在第十八章中探讨 MongoDB，现在让我们专注于“为什么选择 Node.js？”。

在选择项目的语言时，有许多因素需要考虑。其中一些如下：

+   项目类型

+   预算

+   上市时间

+   性能

这些可能听起来是非常基本的因素，但我确实见过选择的技术不适合项目类型的情况。

对于那些沉浸在软件网络端的人来说，选择在后端使用 JavaScript 还是其他语言似乎是一个不言而喻的选择。JavaScript 是现代网络使用的基础，因此听起来，顺理成章地，应该在客户端和服务器端都使用它。

然而，Python 已经存在更长时间，而且在开发社区中肯定已经牢固地占据了一席之地，特别是在数据科学和机器学习的兴起中，Python 占据着主导地位。Flask 和 Django 是出色的 Web 框架，功能强大。那么，为什么我们要使用 Node.js 呢？

决定使用什么技术栈的第一步是了解*项目类型*。在我们今天的讨论范围内，让我们将我们的项目类型限制在合理的用例范围内。我们不会打开物联网/连接设备的潘多拉魔盒，因为这些大多数是用 Java 编写的。让我们也排除机器学习和数据科学作为可能的用例，因为在该领域已经确定 Python 更适合这些用例。然而，实际上有一个关于用 JavaScript 开发桌面和移动应用程序的论点。

首先，让我们考虑一下我们的项目是否是一个 Web 应用程序。在大多数情况下，Node.js 会是一个比 Python 更合理的选择，原因有很多，我们已经探讨过：它的异步性质、上下文切换较少、性能等等。我很难想象出一个使用 Python 后端的 Web 应用程序的充分用例，它会比 Node.js 更优越。我相信一些情况确实存在，但总的来说，即使在处理更大、更复杂的系统时，今天的偏好也不是拥有一个单一的后端应用程序，而是拥有一组*微服务*相互交互，并进行数据交接。

让我们来看一个可能的**高级架构**（**HLA**）图表。如果你正在处理复杂的应用程序，了解系统的 HLA 是非常有用的。即使你只是在应用程序的一部分上积极工作，了解其他系统的需求和结构也是非常宝贵的。在这个例子中，我们有一个可能的电子商务网站架构，还有一个移动应用程序：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/20a02158-e417-4e03-9ba7-4030c0f1aa2a.png)

图 12.2 – 高级架构

我们可以看到可能有多个微服务，包括一些*不是*Node.js 或 JavaScript 的。Python 更适合作为一个微服务，为整体应用程序提供推荐，因为这需要数据分析，而 Python 和 R 在这方面做得比 Node.js 更好。此外，你可以看到在应用程序中，可以有多个不同的数据源，从第三方到不同的数据库类型。

那么，我们的项目呢？我们是在构建一个庞大的生态系统还是其中的一个特定部分？在这个例子中，Web 应用程序、支付服务、账户服务和库存服务都是 Node.js，因为使用设计用于异步通信的技术是有意义的。然而，推荐引擎可以是一个*完全独立的堆栈*，没有任何问题，因为它包含在微服务的整体生态系统中。只要应用程序的各个部分适当地相互通信，每个服务几乎可以是独立的。

为什么这很重要？简单地说，这是使更小、更灵活的团队能够并行工作，创建比单一应用程序更快、更稳定的软件的好方法。让我们来看一个例子：你打开一个大型零售商的网站来购物，但是你没有看到主页，而是看到了以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/b9d914e1-caa8-4471-afec-3467eff199d1.png)图 12.3 – 500！错误，错误，危险，危险！

任何 Web 应用程序开发人员的梦魇：由于代码问题导致的全面中断。相反，如果网站在大部分时间内正常运行，但是在结账时可能会显示“抱歉，我们的支付处理系统目前离线。我们已保存您的购物车以便以后使用。”或者说推荐引擎的 Python 部分崩溃了——我们可以改为提供静态的物品集合。为了创造一个大型微服务生态系统的真实用户体验，重要的是考虑最终用户的立场*以及*业务目标。在我们的电子商务商店的情况下，我们不希望整个应用程序因为一个小错误而崩溃。相反，如果出现问题，我们可以智能地降级体验。这是一个常被称为容错计算的原则的例子，在设计大型应用程序时，将单体应用程序分解为微服务以提高容错性是非常有力的。

在我们讨论预算考虑之前，我想向你展示一些 JavaScript 在桌面领域的强大示例。让我们运行一个示例代码片段，该代码片段在 GitHub 存储库[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-12/electron`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-12/electron)中为您提供：

1.  使用`npm install`安装依赖项。

1.  使用`npm start`运行应用程序。

您应该看到一个*本机应用程序*启动——我们在第七章中创建的 Pokémon 游戏，*事件、事件驱动设计和 API*：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2c52b4b3-7ea6-409b-ba79-1ac55c544328.png)

图 12.4 – 这是一个桌面应用程序！

这是如何发生的？我们利用了一个很棒的工具：Electron。您可以在[`electronjs.org/`](https://electronjs.org/)了解更多关于 Electron 的信息，但要点是它是一个容器工具，用于将 HTML、CSS 和 JavaScript 呈现为桌面应用程序。您可能已经在不知不觉中使用了 Electron：Spotify、Slack 和其他流行的桌面应用程序都是使用 Electron 构建的。

让我们快速看一下内部结构：

```js
.
├── fonts
│   ├── pokemon_solid-webfont.woff
│   └── pokemon_solid-webfont.woff2
├── images
│   └── pokemon-2048x1152.jpg
├── index.html
├── main.js
├── package-lock.json
├── package.json
├── poke.js
├── preload.js
├── renderer.js
└── style.css
```

如果我们将其与第七章中的 PokéAPI 项目进行比较，*事件、事件驱动设计和 API*（[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-7/pokeapi/solution-code)），我们会发现有很多相似之处。

**等等。**

不仅相似……这与我们用于浏览器的代码*完全相同*！`main.js`已重命名为`poke.js`以避免命名冲突，但这只是一个小细节。是的：您刚刚成功地使用现有代码创建了一个桌面应用程序。

所以，回到预算问题：如果你需要一个 Web 应用程序*和*一个桌面应用程序呢？你现在应该已经明白，使用 JavaScript，你可以同时拥有现代 Web 应用程序*和*一个桌面应用程序，只需进行最小的更改。细微之处比我们在这里做的要多一些，但是 Electron 的强大应该是显而易见的。一次编写，多次使用——这不就是 DRY 编码的口头禅吗？

然而，这个论点也有反面。由于 Python 的成熟程度比 Node.js 更长，Python 开发人员的小时费用可能会更具成本效益。然而，我认为这是一个次要的问题。

同样，作为次要关注点，*上市时间*确实是在选择技术时出现的一个问题。不幸的是，这里的数字并不确定。因为 Node.js 是 JavaScript，理论上可以快速迭代开发。然而，Python 的明确和简单的语法有时会更快地编写。这是一个非常难解决的问题，因此最好考虑时间方面的另一个部分：技术债务。技术债务是工程团队的大敌，它简单地意味着以牺牲最佳解决方案为代价，实施了更快的解决方案。此外，技术的淘汰也会导致技术债务。您还记得 Y2K 吗？当发现世界上许多主要应用程序依赖于两位数年份时，人们担心从 1999 年到 2000 年的变化会对计算机系统造成严重破坏。幸运的是，只发生了一些小故障，但技术债务的问题出现了：许多这些系统是用已经变得陈旧的语言编写的。找到程序员来开发这些修复程序是困难且昂贵的。同样，如果您选择一种技术是因为它更快，您可能会发现自己在预算和时间方面付出两三倍于最初投资的代价来重构应用程序以满足持续的需求。

让我们把注意力转向性能。这里有很多要考虑的，所以让我们继续到下一节，讨论为什么在讨论 Node.js 时性能总是需要考虑的。

# 性能影响

当 Node.js 首次开始流行时，人们对其单线程性质表示担忧。单线程意味着一个 CPU，一个 CPU 可能会被大量的流量压倒。然而，大部分情况下，所有这些线程问题都已经被服务器技术、托管和 DevOps 工具的进步所缓解。话虽如此，单线程性质本身也不应该成为阻碍：我们将在稍后讨论为什么*Node 事件循环*在任何关于 Node.js 性能的讨论中扮演着重要角色。

简而言之，要真正在性能上有所区别，我们应该专注于*感知*性能。Python 是一种易于理解、强大、面向对象的编程语言；这是毋庸置疑的。然而，它不会在浏览器中运行。这个位置被 JavaScript 占据了。

为什么这很重要，它与性能有什么关系？简而言之：*Python 无法对浏览器中的更改做出反应*。每次页面 UI 更改时执行 Ajax 请求是可能的，但这对浏览器和服务器在计算上都非常昂贵。此外，您必须使浏览器在每次更改时等待来自服务器的响应，导致非常卡顿的体验。因此，在浏览器中我们能做的越多，越好。在需要与服务器通信之前，使用浏览器中的 JavaScript 来处理逻辑是目标。

在使用 Node.js 的讨论中隐含着您可能从上一节中得出的一个想法：*Node.js 也不在浏览器中运行！*这是真的！然而，Node.js 基于 Chrome 解释器，因此其设计中隐含的是异步性的概念。Node.js 的事件循环是为事件设计的，而事件的内在特性是它们是异步的。

让我们回顾一下第七章中的以下图表，*事件、事件驱动设计和 API*：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e38f207f-a227-44ba-8593-d7d5f6b0d508.png)

图 12.5 - 事件生命周期

如果您还记得，这个图表代表了浏览器事件的三个阶段：捕获、目标和冒泡。DOM 事件特指在浏览器中由用户或程序本身引起的操作、交互或触发器。

同样，Node.js 的事件循环有一个生命周期：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e96702ef-0b7d-41c1-9ed5-2b200396ed79.png)

图 12.6 - Node.js 事件循环

让我们来解释一下。单线程事件循环在 Node 应用程序的生命周期内运行，并接受来自浏览器、其他 API 或其他来源的传入请求，并执行其工作。如果是一个简单的请求或被指定为同步的，它可以立即返回。对于更密集的操作，Node 将注册一个*回调*。记住，这是一个传递给另一个函数以在其完成工作时执行的函数的术语。到目前为止，我们已经在 JavaScript 中广泛使用这些作为*事件处理程序*。Node.js 事件循环提供了一种有效的方式来访问和为我们的应用程序提供数据。

如果你对线程和进程的概念不太熟悉，没关系，因为我们不会在这里深入讨论。然而，指出一些关于 Node 使用进程和线程的事实是很重要的。一些计算机科学家指出，Node 的单线程特性在本质上是不可扩展的，无法承受成熟的 Web 应用程序所需的流量。然而，正如我之前提到的，我们的应用程序并不孤立存在。任何需要设计成可扩展性的应用程序都不会只独自在服务器上运行。随着云技术的出现，比如亚马逊 AWS，很容易整合多个虚拟机、负载均衡器和其他虚拟工具，以适当地分配应用程序的负载。是的，Python 可能更适合作为一个单一盒子应用程序来接收成千上万的传入请求，但是这种性能基准已经过时，不符合当今技术的状态。

## 买方自负

现在我们已经爱上了 Node，让我们回到手头任务的正确工具的想法。Node 并不是解决世界所有计算问题的灵丹妙药。事实上，它特意*不*设计成瑞士军刀。它有它的用途和位置，但它并不试图成为所有人的一切。Java 的“做任何事情”的特性可能被认为是它的弱点，因为虽然你可以编写一次 Java 代码并为几乎任何架构编译它，但为了适应这一点，已经做出了限制、考虑和权衡。Node.js 和 JavaScript 本质上试图留在自己的领域。

那么，有什么问题吗？我们知道 JavaScript 快速、强大、有效和易懂。像任何技术一样，总会有细微差别，JavaScript 和 Node 的一个细微差别就是在一些 Linux 系统中，当你首次以超级用户身份登录时，会出现这样的座右铭：“伴随着伟大的力量而来的是伟大的责任。”尽管这句话的出处模糊不清，但在执行任何对他人有影响的事情时，思考这一点是很重要的。（不要用催眠术做坏事！）

开玩笑的话，异步环境可能会出现非常真实的问题。我们知道，我们可以轻松地通过我们自己的客户端 JavaScript 代码将用户的浏览器崩溃，只需将其放入一个无限循环中。考虑以下代码：

```js
let text = ''

while (1) {
  text += '1'
}
```

很好。如果你在浏览器中运行这个代码，*最好*的情况是浏览器会识别出一个无限循环，并提示你退出脚本，因为页面无响应。第二种情况是浏览器崩溃，最坏的情况是用户的整个机器可能因为内存不足而崩溃。伴随着伟大的力量……

同样，通过不正确地处理状态和事件，我们可以严重影响用户在 Node 中的体验。例如，如果您的前端代码依赖于一个 Node 进程，而该进程从未返回会怎么样？幸运的是，在大多数情况下，内置了 Ajax 保障措施，以防止这种情况发生，即 HTTP 请求将在一定时间后默认关闭并在必要时报错。话虽如此，有许多方法可以强制连接保持打开状态，从而对用户的浏览器造成绝对混乱。有很多正当的理由来做这件事，比如长轮询实时数据，这就是它们存在的原因。另一方面，也有可能意外地给用户造成重大问题。像超时请求这样的故障保护措施存在是为了保护您，但任何优秀的工程师都会告诉您：不要依赖故障保护措施——避免在设计过程中出现错误。

# 总结

Python 很棒。Node 也很棒。两者都很棒。那么为什么我们要进行这次对话呢？虽然这两种技术都很强大和成熟，但每种技术在技术生态系统中都有其作用。并非所有语言都是平等的，也并非所有语言以相同的方式处理问题。

总之，我们已经学到了以下内容：

+   Node.js 是异步的，并且与基于事件的思想很好地配合，比如浏览器中的 JavaScript 对页面事件的反应。

+   Python 已经确立了自己作为数据分析和机器学习领域的领导者，因为它能够快速处理大型数据集。

+   对于 Web 工作，这些技术可能是可以互换的，但是复杂的架构可能会涉及两者（甚至更多）。

在下一章中，我们将开始使用 Express，这是 Node.js 的基础 Web 服务器。我们将创建自己的网站并与它们一起工作。

# 进一步阅读

以下是一些关于这些主题的更多阅读：

+   stateofjs：[`2019.stateofjs.com/`](https://2019.stateofjs.com/)

+   Node.js 与 Python：[`www.similartech.com/compare/nodejs-vs-python`](https://www.similartech.com/compare/nodejs-vs-python)

+   Pattern — 微服务架构：[`microservices.io/patterns/microservices.html`](https://microservices.io/patterns/microservices.html)

+   Amazon API Gateway：[`aws.amazon.com/api-gateway/`](https://aws.amazon.com/api-gateway/)

+   Electron：[`electronjs.org/`](https://electronjs.org/)

+   Y2K bug：[`www.britannica.com/technology/Y2K-bug`](https://www.britannica.com/technology/Y2K-bug)

+   Node.js 多线程：[`blog.logrocket.com/node-js-multithreading-what-are-worker-threads-and-why-do-they-matter-48ab102f8b10/`](https://blog.logrocket.com/node-js-multithreading-what-are-worker-threads-and-why-do-they-matter-48ab102f8b10/)


# 第十三章：使用 Express

正如我们讨论过的，后端的 JavaScript 对于创建 Web 应用程序和利用 JavaScript 在前端和后端都非常有用。与前端交互的服务器端应用程序最基本的工具之一是基本的 Web 服务器。为了提供 API、数据库访问和其他不适合由浏览器处理的功能，我们首先需要设置一个软件来处理这些交互。

Express.js（或者只是 Express）是一个 Web 应用程序框架，被认为是 Node.js 的*事实标准*Web 服务器。它享有很高的流行度和易用性。让我们使用它来构建一个完整的 Web 应用程序。

本章将涵盖以下主题：

+   搭建脚手架：使用`express-generator`

+   路由和视图

+   在 Express 中使用控制器和数据

+   使用 Express 创建 API

# 技术要求

准备好在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13)的 GitHub 存储库中使用代码编辑器和浏览器。在*路由和视图*部分，我们将讨论一些使用代码编辑器的最佳实践。

命令行示例以 macOS/Linux 风格呈现。Windows 用户可能需要查阅文档以了解 Windows 命令行的一些细微差别。

# 搭建脚手架：使用 express-generator

要开始，我们需要再次使用我们的**命令行界面**（**CLI**）。如果你还记得第二章中的内容，*我们可以在服务器端使用 JavaScript 吗？当然可以！*，我们曾经在命令行上查看了 Node 和`npm`。让我们再次检查我们的版本，以便我们可以对我们的应用程序做出一些决定。在你的命令行上运行`node -v`。如果你的版本是 v8.2.0 或更高，你可以选择使用`npx`来安装某些只在项目生命周期中运行一次的包，比如 express-generator。然而，如果你的版本较低，你也可以使用`npm`来安装一次性使用的包以及在你的项目中使用的包。

在本章中，我们将继续使用`npx`，所以如果你需要快速查看`npm`与`npx`的文档，请确保给自己一些时间来做。实质上，要使用`npm`安装一次性包，这些包不应该存在于你的代码库中，例如 Express 生成器或 React 应用程序创建器，你可以在系统上全局安装该包，如下所示：`npm install -g express-generator`。然后，你将使用 Express 运行该程序。然而，这被认为是`npm`的传统用法，因为在今天的环境中，`npx`更受青睐。

让我们从头开始创建我们的 Express 应用程序，以建立肌肉记忆，而不是继续第二章中的内容，*我们可以在服务器端使用 JavaScript 吗？当然可以！*。按照以下步骤开始使用 Express web 服务器：

1.  在一个方便的位置，使用`mkdir my-webapp`创建一个新目录。

1.  使用`cd my-webapp`进入其中。

1.  `npx express-generator --view=hbs` express 生成器将创建多个文件和目录：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/dc47dce1-47bb-4867-adb0-2ff2705a6af6.png)

图 13.1 - 创建我们的 Express 脚手架

我们将设置我们的应用程序使用 Handlebars 作为我们的模板，而不是默认选项 Jade。Express 支持多种模板语言（并且可以扩展使用任何模板语言），但为了方便起见，我们将使用类似于我们在第八章中使用的 React 和 Vue 前端框架的 Handlebars，它使用基本的花括号标记。

1.  使用`npm install`来安装我们的依赖项。（请注意，即使之前使用过`npx`，在这里你也要使用`npm`。）这将需要几秒钟的时间，并将下载许多包和其他依赖项。另一个需要注意的是，你需要互联网连接，因为`npm`会从互联网上检索包。

1.  现在，我们准备使用`npm start`来启动我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e7dee19b-5ea9-410f-9dde-ad6cdc7650b8.png)

图 13.2 - 我们的应用程序开始

1.  好了！现在，让我们在 Web 浏览器中访问我们的 Express 网站：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9c66eb77-2d5f-4557-86ad-a5ad5d2b021d.png)

图 13.3 - Express 欢迎页面

太棒了！现在我们到了这一步，让我们比在第二章中所做的更进一步，*我们可以在服务器端使用 JavaScript 吗？当然可以！*。

## RESTful 架构

许多 Web 应用程序的核心是一个 REST（或 RESTful）应用程序。**REST**是**REpresentational State Transfer**的缩写，它是一种处理大多数 Web 技术固有的**无状态**的设计模式。想象一下一个不需要登录或太多数据的标准网站——只是静态的 HTML 和 CSS，就像我们在之前的章节中创建的那样，但更简单：没有 JavaScript。如果我们从状态的角度来看待这样的网站，我们会发现一堆 HTML 并不知道我们的用户旅程，不知道我们是谁，而且，坦率地说，它也不关心。这样的网站就像印刷材料：你通过观看、阅读和翻页来与它交互。你不会改变它的任何内容。一般来说，你真正修改书的状态的唯一方式就是用书签保存你的位置。老实说，这比基本的 HTML 和 CSS 更具交互性。

为了处理用户和数据，REST 被用作一种功能范式。在处理 API 时，我们已经使用了两个主要的 HTTP 动词：GET 和 POST。这是我们将要使用的两个主要动词，但我们将再看看另外两个：PUT 和 DELETE。

如果你熟悉**创建、读取、更新和删除**（**CRUD**）的概念，这就是标准的 HTTP REST 动词的翻译方式：

| **概念** | **HTTP 动词** |
| --- | --- |
| 创建 | 创建 |
| 读取 | 获取 |
| 更新 | PUT 或 PATCH |
| 删除 | 删除 |

更多信息，你可以查看 Packt REST 教程：[`hub.packtpub.com/what-are-rest-verbs-and-status-codes-tutorial/`](https://hub.packtpub.com/what-are-rest-verbs-and-status-codes-tutorial/)。

现在，可能只使用 GET，或者只使用 GET 和 POST 来创建一个完整的应用程序是可能的，但出于安全和架构的原因，你不会想这样做。现在，让我们同意遵循最佳实践，并在这个已建立的范式内工作。

现在，我们将创建一个 RESTful 应用程序。

# 路由和视图

路由和视图是 RESTful 应用程序的 URL 的基础，它们作为逻辑的路径，以及向用户呈现内容的方式。路由将决定代码的哪些部分对应于应用程序界面的 URL。视图确定显示什么，无论是向浏览器、另一个 API 还是其他编程访问。

为了进一步了解 Express 应用程序的结构，我们可以检查它的路由和视图：

1.  首先，让我们在你喜欢的 IDE 中打开 Express 应用程序。我将使用 VS Code 进行工作。如果你使用 VS Code、Atom、Sublime 或其他具有命令行工具的 IDE，我强烈建议安装它们。例如，使用 Atom，你可以在命令提示符中输入`atom .`来启动多面板 Atom 编辑界面，并在 Atom 中打开该目录。

1.  同样，VS Code 会用`code .`来做到这一点。这是它的样子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/82b8f281-8fb6-454f-bca4-85b3de493b4e.png)

图 13.4 - VS Code

我已经展开了左侧的目录，这样我们就可以看到层次结构的第一层。

1.  打开`app.js`。

你会注意到这段代码的语法是 express-generator 为我们创建的***ES5***，而不是 ES6。暂时，我们不要担心将其转换为 ES6；我们稍后会做。当我们在第一个 Node.js REST 应用程序上工作时，请记住有几种不同的方法可以实现我们的目标，我们将首先采用更冗长的路径来使功能正常工作，然后对其进行迭代，使其更灵活和更 DRY。

1.  现在，你不需要对`app.js`做任何更改，但是花点时间熟悉它的结构。它可能比较陌生的一个方面是文件开头的`require()`语句。类似于前端框架中使用的`import`，`require()`是 Node 的一种方式，用于从其他文件中引入这些部分。在这种情况下，前几行是通过`npm`安装的模块，如下所示：

```js
var express = require('express');
```

请注意，`('express')`前面没有路径。它只是简单地陈述。这表明所引用的模块不是我们代码的本地模块。然而，如果你看一下`indexRouter`的`require`语句，我们会看到它*有*一个路径：`'./routes/index'`。它没有`.js`扩展名，但对于我们的模块使用来说，路径是正确的。

现在，让我们检查一下我们的`routes/index.js`文件。

## 路由

如果你打开`routes/index.js`，你会看到为我们生成的以下几行代码：

```js
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('index', { title: 'Express' });
});

module.exports = router;
```

这里没有太多令人惊讶的地方：正如我们开始了解的那样，Express 文件以`require`语句开头，特别是对于`express`本身。在下一个代码块中，我们开始看到我们的 REST 服务的开端：`GET home page`。看一下注释后面的`router.get()`方法。它*明确*地告诉路由器，当收到 URL 为`/`的 GET 请求时，执行此代码。

我们可以通过在这里添加一些 GET 路径来验证这一事实，只是为了好玩。让我们尝试修改我们的代码如下。在`router.get()`块之后，但在`module.exports`之前，让我们在路由器上注册更多的路由：

```js
/* GET sub page. */
 router.get('/hello', function(req, res, next) {
     res.render('index', { title: 'Hello! This is a route!' });
 });
```

现在，我们必须用*Ctrl + C*停止我们的 Express 服务器，用`npm start`重新启动它，并在`http://localhost:3000/hello`上访问我们的新页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/d2e9833f-53c9-4c6b-ac64-38bb966b920f.png)

图 13.5 - 一个新的路由，打开了网络选项卡，显示我们正在进行 GET 请求

到目前为止，这应该看起来相当基本。现在，让我们做点不一样的事情。让我们使用这个视图并为 Ajax POST 请求创建一个表单：

1.  创建一个名为`public/javascripts/index.js`的新文件。

1.  编写一个基本的`fetch`请求到端点`/hello`，POST JSON 为`{ message: "This is from Ajax" }`，如下所示：

```js
fetch('/hello', {
 method: 'POST',
 body: JSON.stringify({ message: "This is from AJAX" }),
 headers: {
   'Content-Type': 'application/json'
 },
});
```

1.  像这样在`views/index.hbs`中包含这个文件：

```js
<h1>{{title}}</h1>

<p>Welcome to {{title}}</p>

<p id="data">{{ data }}</p>

<script src="/javascripts/index.js"></script>
```

请注意，我们不需要在路径中包含`public`。这是因为 Express 已经理解到`public`中的文件应该静态提供，而不需要 Express 的干预或解析，与必须运行的 Node 文件相反。

1.  如果现在重新加载页面，你不会看到任何令人兴奋的事情发生，因为我们还没有编写处理 POST 请求的路由。编写如下：

```js
/* POST to sub page. */
router.post('/hello', function(req, res, next) {
  res.send(req.body);
});
```

1.  重新加载页面，你会看到... 什么也没有。在网络选项卡中没有 POST，当然也没有渲染。发生了什么？

Node 有几个工具用于在代码更改时重新启动 Express 服务器，以便引擎会自动刷新，而无需我们杀死并重新启动它，就像我们以前做的那样，但这次没有。这些工具随时间而变化，但我喜欢的是 Supervisor：[`www.npmjs.com/package/supervisor`](https://www.npmjs.com/package/supervisor)。只需在项目目录中执行`npm install supervisor`即可在项目中安装它。

1.  现在，打开项目根目录中的`package.json`文件。你应该看到一个类似于这样的文件，但可能有一些版本差异：

```js
{
 "name": "my-webapp",
 "version": "0.0.0",
 "private": true,
 "scripts": {
 "start": "node ./bin/www"
 },
 "dependencies": {
 "cookie-parser": "~1.4.4",
 "debug": "~2.6.9",
 "express": "~4.16.1",
 "hbs": "~4.0.4",
 "http-errors": "~1.6.3",
 "morgan": "~1.9.1",
 "supervisor": "⁰.12.0"
 }
}
```

这是运行`npm install`时安装的核心内容。运行时，您会看到一个`node_modules`目录被创建，并且有许多文件写入其中。

如果您正在使用诸如 Git 之类的版本控制，您将*不*想提交`node_modules`目录。使用 Git，您会在`.gitignore`文件中包含`node_modules`。

1.  我们接下来要做的事情是修改我们的启动脚本，现在使用 Supervisor：

```js
"scripts": {
     "start": "supervisor ./bin/www"
 },
```

要使用它，我们仍然使用`npm start`，要退出它，只需按下*Ctrl + C*。值得注意的是，Supervisor 最适合本地开发工作，而不是生产工作；还有其他工具，比如 Forever，可以用于这个目的。

1.  现在，让我们运行`npm start`，看看会发生什么。您应该看到一些以按下 rs 重新启动进程结束的控制台消息。在大多数情况下，不需要发出`rs`，但如果需要，可以使用它：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/d033f853-fde3-41dc-af2e-2bacba192699.png)

图 13.6 - 来自 Ajax 的响应！

1.  由于我们从前端 JavaScript 发送了`这是来自 AJAX`，我们在响应 HTML 中看到了它的反映！现在，如果我们想要在我们的页面中看到它，我们会在我们的前端 JavaScript 中这样做：

```js
fetch('/hello', {
 method: 'POST',
 body: JSON.stringify({ message: "This is from AJAX" }),
 headers: {
   'Content-Type': 'application/json'
 },
}).then((res) => {
 return res.json();
}).then((data) => {
 document.querySelector('#data').innerHTML = data.message
});
```

我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/82301bb7-1533-4c39-9c64-6445093cb9ce.png)

图 13.7 - 来自 Ajax 的消息！

接下来，让我们了解如何保存数据。

## 保存数据

对于我们的下一步，我们将在本地数据存储中持久化数据，这将是一个简单的本地 JSON 文件：

1.  继续并使用*Ctrl + C*退出 Express。让我们安装一个简单的模块，它可以在本地存储中保存数据：`npm install data-store`。

1.  让我们修改我们的路由以使用它，就像这样：

```js
var express = require('express');
var router = express.Router();

const store = require('data-store')({ path: process.cwd() + '/data.json' });

/* GET home page. */
router.get('/', function(req, res, next) {
 res.render('index', { title: 'Express', data: 
 JSON.stringify(store.get()) });
});

/* GET sub page. */
router.get('/hello', function(req, res, next) {
 res.render('index', { title: 'Hello! This is a route!' });
});

/* POST to sub page. */
router.post('/hello', function(req, res) {
 store.set('message', { message: `${req.body.message} at ${Date.now()}` })

 res.set('Content-Type', 'application/json');
 res.send(req.body);
});

module.exports = router;
```

1.  注意`store`的包含以及在`hello`和`/`路由中的使用。让我们还修改我们的`index.hbs`文件，就像这样：

```js
<h1>{{title}}</h1>
<p>Welcome to {{title}}</p>

<button id="add">Add Data</button>
<button id="delete">Delete Data</button>

<p id="data">{{ data }}</p>
<script src="/javascripts/index.js"></script>

```

1.  我们稍后会使用`删除数据`按钮，但现在我们将使用`添加数据`按钮。在`public/javascripts/index.js`中添加一些保存逻辑，就像这样：

```js
const addData = () => {
 fetch('/hello', {
   method: 'POST',
   headers: {
     'Content-Type': 'application/json'
   },
   body: JSON.stringify({ message: "This is from Ajax" })
 }).then((res) => {
   return res.json()
 }).then((data) => {
     document.querySelector('#data').innerHTML = data.message
 })
}
```

1.  现在我们将添加我们的点击处理程序：

```js
document.querySelector('#add').addEventListener('click', () => {
 addData()
 window.location = "/"
})
```

1.  如果您刷新`/`页面并点击添加数据按钮，您应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ca234daf-da72-4cc8-855e-b339a0a3fc62.png)

图 13.8 - 添加数据

1.  现在，再次刷新该页面。注意消息是持久的。在您的文件系统中，您还应该注意到一个包含数据的`data.json`文件。

现在我们准备使用删除方法更多地工作一下。

## 删除

我们已经探讨了 GET 和 POST，现在是时候处理另一个基础 REST 动词了：**DELETE**。

顾名思义，它的目标是从数据存储中删除数据。我们已经有了我们的按钮来这样做，所以让我们把它连接起来：

1.  在我们的前端 JavaScript 中，我们将添加以下内容：

```js
const deleteData = () => {
 fetch('/', {
   method: 'DELETE',
   headers: {
     'Content-Type': 'application/json'
   },
   body: JSON.stringify({ id: 'message' })
 })
}
document.querySelector('#delete').addEventListener('click', () => {
 deleteData()
 window.location = "/"
})
```

1.  现在，在路由中添加这个路由：

```js
/* DELETE from json and return to home page */
router.delete('/', function(req, res) {
 store.del(req.body.id);

 res.sendStatus(200);
});
```

那应该是我们需要的全部。刷新您的索引页面，并尝试使用添加和删除按钮。相当容易，对吧？在第十八章中，*Node.js 和 MongoDB*，我们将讨论在一个完整的数据库中持久化和操作我们的数据，但现在，我们可以使用 GET、POST 和 DELETE 的知识。我们将使用 PUT 来处理实际数据库。

## 视图

我们在*Routers*部分涉及了视图的操作，现在让我们深入了解一下。应用程序的**视图层**是表示层，这就是为什么它包含我们的前端 JavaScript。虽然并非所有的后端 Node 应用程序都会提供前端，但了解如何使用它是很方便的。每当我设置一个简单的 Web 服务器时，我都会使用 Express 及其对前端和后端功能的功能。

由于我们有多种前端模板语言可供选择，让我们以 Handlebars 作为逻辑和结构的示例。

如果我们愿意，我们可以在我们的前端代码中提供一些条件逻辑。请注意，这个逻辑是由后端渲染的，所以这是一个很好的例子，说明何时在后端渲染数据（对于前端来说更高效），何时通过 JavaScript 来做（这在表面上更灵活）。

让我们修改我们的`views/index.hbs`文件，就像这样：

```js
{{#if data }}
 <p id="data">{{ data }}</p>
{{/if}}
```

让我们还修改`routes/index.js`：

```js
/* GET home page. */
router.get('/', function(req, res, next) {
 res.render('index', { title: 'Express', data: 
 JSON.stringify(Object.entries(store.get()).length > 0 ? store.get() :
  null) });
});
```

现在，我们使用三元运算符来简化我们的显示逻辑。由于我们从存储中获取的数据是 JSON，我们不能简单地测试它的长度：我们必须使用`Object.entries`方法。如果你认为我们可以将`store.get()`保存到一个变量中而不是写两次，你是对的。然而，在这种情况下，我们不需要占用额外的内存空间，因为我们立即返回它而不是对它进行操作。在这种情况下，性能影响是可以忽略不计的，但这是需要记住的一点。

现在，如果我们删除我们的数据，我们会看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/6006a3be-14d2-467f-8bfe-98a2612ade90.png)

图 13.9 - 删除数据后

看起来比看到一个空对象的花括号要少混乱一些。当然，我们可以通过编写更复杂的条件在前端进行条件工作，但为什么在后端可以发送适当的数据时要做这项工作呢？当然，对于这两种情况都有情况，但在这种情况下，最好让每个部分都做自己的工作。

你可以在这里找到我们完成的工作：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/my-webapp`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/my-webapp)。

现在让我们把注意力转向如何使用**控制器**将数据实际传入 Express。

# 控制器和数据：在 Express 中使用 API

正如你可能在网络上听到的那样，Express 很棒，因为它对你如何使用它没有太多的意见，同时，人们说 Express 很难使用，因为它的意见不够明确！虽然 Express 通常不设置为传统的模型-视图-控制器设置，但将功能拆分出路由并放入单独的控制器中可能是有益的，特别是如果你可能在路由之间有类似的功能，并且想要保持代码的 DRY。

如果你对**模型-视图-控制器**（**MVC**）范式不太熟悉，不用担心——我们不会详细讨论它，因为这是一个非常沉重的话题，有着自己的争论和惯例。现在，我们只是定义一些术语：

+   **模型**是应用程序的一部分，处理数据操作，特别是与数据库之间的通信。

+   **控制器**处理来自路由的逻辑（即用户的 HTTP 请求路径）。

+   **视图**是向最终客户端提供标记的表示层，由控制器路由。

这就是 MVC 范式的样子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ef9b36c6-f8f5-4ac2-950c-1e771d5b572d.png)

图 13.10 - MVC 范式

让我们来看一个示例应用程序。在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/controllers`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/controllers)是一个使用 Express 的应用程序。

这是一个使用控制器和模型的 API。正如我们将看到的，这种结构将简化我们的工作流程。这仍然是一个相当简单的例子，但这会让你了解为什么控制器和模型会派上用场。让我们来调查一下：

1.  继续运行`npm install`，然后运行`npm start`来运行应用程序。它应该可以在你的浏览器中访问`http://localhost:3000`，但如果你有其他东西在运行，Node 会警告你并指定一个不同的端口。你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1deb7afc-912a-4f7c-b8bf-cd4c57f43d28.png)

图 13.11 - 我们的示例 Express 应用程序

1.  到目前为止非常简单。继续点击添加用户几次，然后尝试一下功能。这使用后端的随机用户 API 来创建用户并将它们持久化到文件系统数据存储中。

1.  查看`public/javascripts`目录中的客户端 JavaScript。这应该看起来很熟悉。如果我们记得`fetch()`调用的结构，它返回一个 promise，所以我们可以使用`.then()`范式来对我们的事件做出反应。

1.  在`public/javascripts/index.js`中，我们可以看到当我们点击添加用户时创建用户的机制：

```js
document.querySelector('.add-user').addEventListener('click', (e) => {
  fetch('/user', {
    method: 'POST'
  }).then( (data) => {
    window.location.reload()
  })
})
```

这不应该有什么意外：我们在事件处理程序中使用 JavaScript 的`fetch`来调用带有 POST 的`/user`路由。**路由**基本上是 Express（或其他）应用程序中的一个端点：它包含一些逻辑来对事件做出反应。那么，这个逻辑是什么？

1.  打开`routes/user.js`：

```js
var express = require('express');
var router = express.Router();

const UsersController = require('../controllers/users');

/* GET all users. */
router.get('/', async (req, res, next) => {
  res.send(await UsersController.getUsers());
});

/* GET user. */
router.get('/:user', async (req, res, next) => {
  const user = await UsersController.getUser(req.params.user);
  res.render('user', { user: user });
});

/* POST to create user. */
router.post('/', async (req, res, next) => {
  await UsersController.createUser();
  res.send(await UsersController.getUsers());
});

/* DELETE user. */
router.delete('/:user', async (req, res, next) => {
  await UsersController.deleteUser(req.params.user);
  res.sendStatus(200);
});

module.exports = router;
```

首先，让我们将其结构与其他示例进行比较。首先，我们将看到用户控制器的`require()`语句。这里有一个`router.post()`方法语句，它使用`async`/`await`进行对控制器的异步调用。然后，我们的控制器将调用我们的模型来进行数据库工作。

到目前为止，有许多文件和路径需要执行。在我们在代码中迷失之前，让我们看一下前端方法（例如添加用户点击处理程序）如何与我们的 Express 后端通信的图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/5942ab17-e961-4c9f-af8e-4b997e8c8eb0.png)

图 13.14 - 端到端通信

从左到右，从上到下阅读，我们可以看到每个步骤在过程中扮演的角色。对于从 API 检索信息这样基本的事情，它可能*看起来*有点复杂，但这种架构模式的一部分力量在于每个层可以由不同的一方编写和控制。例如，模型层通常由数据库专家掌握，而不是其他类型的后端开发人员。

当您跟踪控制器和模型的代码时，请考虑代码每一层的关注点分离如何使设计更加模块化。例如，我们使用一个 LocalStorage 数据库来存储我们的用户。如果我们想要将 LocalStorage 替换为更强大的系统，比如 MongoDB，我们实际上只需要编辑一个文件：模型。事实上，甚至模型也可以被抽象化为具有统一数据处理程序，然后使用适配器进行特定数据库方法的调用。

这对我们来说可能有点太多了，但接下来让我们把目光转向使用我们刚学到的原则来创建一个星际飞船游戏。我们将使用这个 Node.js 后端来制作 JavaScript 游戏的前端最终项目。

在下一节中，我们将开始创建我们游戏的 API。

# 使用 Express 创建 API

谁不喜欢像《星球大战》或《星际迷航》中的美丽星舰战斗呢？我碰巧是科幻小说的忠实粉丝，所以让我们一起来构建一个使用存储、路由、控制器和模型来跟踪我们游戏过程的 RESTful API。虽然我们将专注于应用程序的后端，但我们将建立一个简单的前端来填充数据和测试。

您可以在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/starship-app`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/starship-app)找到一个正在进行中的示例应用程序。让我们从那里开始，您可以使用以下步骤完成它：

1.  如果您还没有克隆存储库，请克隆它。

1.  进入`cd starship-app`目录并运行`npm install`。

1.  使用`npm start`启动项目。

1.  在浏览器中打开`http://localhost:3000`。如果您已经在端口 3000 上运行任何项目，`start`命令可能会提示您使用其他端口。这是我们的基本前端：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/a585129a-7c90-4082-88c3-2d8e61e294f1.png)

图 13.15 - 星舰舰队

1.  随意添加和销毁飞船，无论是随机还是手动。这将是我们游戏的设置。

1.  现在，让我们解开代码在做什么。这是我们的文件结构：

```js
.
├── README.md
├── app.js
├── bin
│ └── www
├── controllers
│ └── ships.js
├── data
│ └── starship-names.json
├── models
│ └── ships.js
├── package-lock.json
├── package.json
├── public
│ ├── images
│ │ └── bg.jpg
│ ├── javascripts
│ │ └── index.js
│ └── stylesheets
│ └── style.css
├── routes
│ ├── index.js
│ ├── ships.js
│ └── users.js
└── views
 ├── error.hbs
 ├── index.hbs
 └── layout.hbs
```

1.  打开`public/javascripts/index.js`。让我们首先检查随机飞船创建的事件处理程序：

```js
document.querySelector('.random').addEventListener('click', () => {
 fetch('/ships/random', {
   method: 'POST'
 }).then( () => {
   window.location.reload();
 })
})
```

到目前为止一切都很顺利。这应该看起来很熟悉。

1.  让我们来看看这条路线：`/ships/random`。打开`routes/ships.js`（我们可以猜测`/ships/`的路由将在`ships.js`文件中，但我们可以通过阅读`app.js`文件中的路由来确认这一点，因为我们已经学过了）。阅读`/random`路线：

```js
router.post('/random', async (req, res, next) => {
 await ShipsController.createRandom();
 res.sendStatus(200);
});
```

我们首先注意到的是这是一个`async`/`await`结构，因为我们将在前端使用`fetch`，（剧透）后端使用数据库。

1.  让我们接下来看一下控制器方法：

```js
exports.createRandom = async () => {
 return await ShipsModel.createRandom();
}
```

1.  很容易。现在是模型方法：

```js
exports.createRandom = async () => {
 const shipNames = require('../data/starship-names');
 const randomSeed = Math.ceil(Math.random() * 
  shipNames.names.length);

 const shipData = {
   name: shipNames.names[randomSeed],
   registry: `NCC-${Math.round(Math.random()*10000)}`,
   shields: 100,
   torpedoes: Math.round(Math.random()*255+1),
   hull: 0,
   speed: (Math.random()*9+1).toPrecision(2),
   phasers: Math.round(Math.random()*100+1),
   x: 0,
   y: 0,
   z: 0
 };

 if (storage.getItem(shipData.registry) || storage.values('name') 
 == shipData.name) {
   shipData.registry = `NCC-${Math.round(Math.random()*10000)}`;
   shipData.name = shipNames.names[Math.round(Math.random()*
    shipNames.names.length)];
 }
  await storage.setItem(shipData.registry, shipData);
 return;
}
```

好的，这有点复杂，所以让我们来解开这个。前几行只是从一个为你提供的种子文件中选择一个随机名称。我们的`shipData`对象由几个键/值对构成，每个对应于我们新创建的船只的特定属性。之后，我们检查我们的数据库，看看是否已经有一个同名或注册号的船只。如果有，我们将再次随机化。 

然而，与每个应用程序一样，都有改进的空间。这里有一个挑战给你。

## 挑战

你的第一个任务是：你能想出如何改进代码，使得在重新随机化时，优雅地检查*新*随机化是否也存在于我们的数据库中吗？提示：你可能想创建一个单独的辅助函数或两个。

也许你得到了类似于这样的东西（[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/starship-app-solution1`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-13/starship-app-solution1)）：

```js
const eliminateExistingShips = async () => {
 const shipNames = require('../data/starship-names');
 const ships = await storage.values();

 const names = Object.values(ships).map((value, index, arr) => {
   return value.name;
 });

 const availableNames = shipNames.names.filter((val) => {
   return !names.includes(val);
 });

 const unavailableRegistryNumbers = Object.values(ships).map((value, index, 
 arr) => {
   return value.registry;
 });

 return { names: availableNames, unavailableRegistries: 
 unavailableRegistryNumbers };
}
```

并使用它，执行以下命令：

```js
exports.createRandom = async () => {
 const { names, unavailableRegistries } = await eliminateExistingShips();

 const randomSeed = Math.ceil(Math.random() * names.length);

 const shipData = {
   name: names[randomSeed],
   registry: `NCC-${Math.round(Math.random() * 10000)}`,
   shields: 100,
   torpedoes: Math.round(Math.random() * 255 + 1),
   hull: 0,
   speed: (Math.random() * 9 + 1).toPrecision(2),
   phasers: Math.round(Math.random() * 100 + 1),
   x: 0,
   y: 0,
   z: 0
 };

 while (unavailableRegistries.includes(shipData.registry)) {
   shipData.registry = `NCC-${Math.round(Math.random() * 10000)}`;
 }
 await storage.setItem(shipData.registry, shipData);
 return;
}
```

那么，我们在这里做什么呢？首先，让我们看一下`Objects.map`的用法：

```js
const names = Object.values(ships).map((value, index, arr) => {
   return value.name;
});
```

在这里，我们正在使用`ships`对象的`.map()`方法来创建一个*只包含*现有船只名称的新数组。基本上，我们所做的就是将对象的每个名称返回到我们的数组中，所以现在我们有了一个可枚举的数据类型。

接下来，我们想要*消除*已使用的名称，所以我们将使用数组的`.filter()`函数，只有在它不包含在我们之前创建的数组中时才返回该值：

```js
const availableNames = shipNames.names.filter((val) => {
   return !names.includes(val);
});
```

我们与我们的名称一样处理我们的注册号，并返回一个对象。

现在，这里有一个新技巧：解构一个对象。看看这个：

```js
 const { names, unavailableRegistries } = await eliminateExistingShips();
```

我们在这里做的是一举两得地分配两个变量！由于我们的`eliminateExistingShips()`方法返回一个对象，我们可以使用*解构*将其分解为单独的变量。这并不是完全必要的，但它通过减少我们使用点符号的次数来简化我们的代码。

继续。

## 船只属性

这是我们为游戏定义的船只属性及其描述。这个属性表对我们将构建的所有船只都是相同的，无论是随机还是手动：

| **name** | 一个字符串值。 |
| --- | --- |
| **registry** | 一个字符串值。 |
| **shields** | 一个护盾强度的数字，初始化为 100。随着船只受到损害，这个数字会减少。 |
| **torpedos** | 一个数字，表示船只拥有的鱼雷数量。在我们的游戏中，每次发射鱼雷时，这个数字会减少 1。 |
| **hull** | 从 0 开始，一个数字，表示护盾耗尽后船只所承受的船体损伤。当这个数字达到 100 时，船只被摧毁。希望每个人都能到达逃生舱！ |
| **speed** | 从 warp 1 到 9.99，我们的船只有一个可变速度。 |
| **phasers** | 没有战斗相位器的船只是不完整的！定义一个从 1 到 100 的随机数字，以指定船只的相位器造成的伤害。 |
| **x, y, and z** | 我们船只在三维空间中的坐标，从[0,0,0]开始。对于我们的游戏玩法，我们将坐标上限设定为[100,100,100]。我们不希望我们的船只在太空中迷失！ |

对于我们的数据库，我们并没有做任何复杂的事情；我们使用了一个名为`node-persist`的 Node 包。它使用文件系统上的一个目录来存储值。它很基础，但能完成任务。我们将在第十八章 *Node.js 和 MongoDB* 中介绍真正的数据库。请注意，这些方法也是`async`/`await`函数，因为我们期望代码与数据库交互时会有轻微的延迟（在这种情况下，是我们的文件系统）。

好了！由于我们的函数只返回空值，它将触发我们控制器方法的完成，然后返回一个`200 OK`消息到前端。根据我们的前端代码，页面将重新加载，显示我们的新飞船。

这里有第二个改进的空间：你能否使用 DOM 操作在不刷新页面的情况下将你的飞船添加到页面上？你将需要修改整个堆栈的所有级别来实现你的目标，通过将随机值返回到前端。

在你开始之前，让我们问自己一个重要的问题：*在我们当前的结构下这样做是否有意义*？如果你的思维过程导致了一个过于复杂的解决方案，就像我的一样，答案是否定的。很明显，处理 DOM 更新的最佳方式是利用我们拥有的另一个工具：一个框架。我们现在暂且不管它，但在我们的最终项目中第十九章 *将所有内容整合在一起* 中，我们将重新讨论它。

接下来，让我们看看星舰战斗将如何进行。如果我们回到我们的飞船路由，我们会看到这个路由：

```js
router.get('/:ship1/attack/:ship2', async (req, res, next) => {
 const damage = await ShipsController.fire(req.params.ship1, 
 req.params.ship2);
 res.sendStatus(200);
});
```

如果你能从路由的构造中猜出来，路由将以第一艘飞船的名称作为参数（`ship1`），然后是`attack`字符串，然后是第二艘飞船的名称。这是一个 RESTful 路由的例子，以及 Express 如何处理路径参数。在我们的控制器调用中，我们使用这些参数和控制器的`.fire()`方法。在控制器中，我们看到这样的内容：

```js
exports.fire = async (ship1, ship2, weapon) => {
 const target = await ShipsModel.getShip(ship2);
 const source = await ShipsModel.getShip(ship1);
 let damage = calculateDamage(source, target, weapon);

 if (weapon == 'torpedo' && source.torpedoes > 0) {
   ShipsModel.fireTorpedo(ship1);
 } else {
   damage = 0
 }

 return damage;
}
```

现在我们玩得很开心。你可以追踪不同的模型部分，但我想指出使用`calculateDamage`辅助函数。你会在文件的顶部找到它。

对于伤害计算，我们将使用以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/3b45c762-3cf3-4878-8c52-a4aff4b5cd4e.png)

或者，用英语说，“计算目标被源命中的几率是通过从三维空间中两艘飞船之间的距离中减去 100 来计算的，得到 0%到 100%之间的几率。为了计算这个值，将 100 减去*x*、*y*和*z*坐标增量的平方和的平方根四舍五入。”（是的，我不得不查找三维空间距离的计算。如果这对你来说很陌生，不用担心。）

然后，让*R[1]*成为 0 到 100 之间的伪随机值，四舍五入。在 JavaScript 中，就像所有编程语言一样，随机数在技术上只是一个*伪随机*数：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4119f22a-db9d-453c-940d-8f5ae712450b.png)

或者，“源头的相位炮可能造成的伤害是通过将源头的相位功率乘以一个`Math.random()`数四舍五入得到的。”

然而，如果源头发射了鱼雷（并且还有鱼雷剩余），那么*possibledamage* *= 125*。

让*R[2]*成为 0 到 100 之间的伪随机数，四舍五入：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ae1b1b17-36ed-4d42-a26d-4aa9b0f6a930.png)

如果*chance*减去随机数大于 0，伤害将发生为*possibledamage*。否则，不会发生伤害。

好了，现在我们有了计算。你能想出用 JavaScript 代码来实现这个吗？

就是这样：

```js
const calculateDamage = (ship1, ship2, weapon) => {
 const distanceBetweenShips = Math.sqrt(Math.pow(ship2.x - ship1.x, 2) + 
 Math.pow(ship2.y - ship1.y, 2) + Math.pow(ship2.z - ship1.z, 2));
 const chanceToStrike = Math.floor(100-distanceBetweenShips);
 const didStrike = (Math.ceil(Math.random()*100) - chanceToStrike) ? true : 
 false;
 const damage = (didStrike) ? ((weapon == 'phasers') ? 
 Math.ceil(Math.random()*ship1.phasers) : TORPEDO_DAMAGE) : 0;
 return damage;
}
```

为了完成我们的游戏，我们需要创建一个机制来实际发射并在前端注册伤害。

# 总结

本章我们涵盖了很多内容，从路由到控制器再到模型。请记住，并非每个应用都遵循这种范式，但这是一个很好的基准，可以帮助你开始处理后端服务与前端的关系。

我们应该记住，使用`express-generator`可以帮助搭建应用程序，使用`npm`或`npx`。路由和视图是我们应用程序的前线，决定代码的路由和最终客户端所看到的内容（无论是 JSON 还是 HTML）。我们使用 API 来探索 API 的固有异步行为，并创建了*自己的*API！

在下一章中，我们将讨论 Express 与 Django 或 Flask 不同类型的框架。我们还将研究如何连接我们的前端和后端框架。

# 进一步阅读

+   教程：REST 动词和状态码：[`hub.packtpub.com/what-are-rest-verbs-and-status-codes-tutorial/`](https://hub.packtpub.com/what-are-rest-verbs-and-status-codes-tutorial/)

+   如何在 Node 和 Express 中启用 ES6（及更高版本）语法：[`www.freecodecamp.org/news/how-to-enable-es6-and-beyond-syntax-with-node-and-express-68d3e11fe1ab/`](https://www.freecodecamp.org/news/how-to-enable-es6-and-beyond-syntax-with-node-and-express-68d3e11fe1ab/)

+   在 Express 4 中处理 GET 和 POST 请求：[`codeforgeek.com/handle-get-post-request-express-4/`](https://codeforgeek.com/handle-get-post-request-express-4/)

+   如何设计 REST API：[`restfulapi.net/rest-api-design-tutorial-with-example/`](https://restfulapi.net/rest-api-design-tutorial-with-example/)
