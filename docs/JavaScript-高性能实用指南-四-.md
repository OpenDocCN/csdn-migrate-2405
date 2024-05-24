# JavaScript 高性能实用指南（四）

> 原文：[`zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774`](https://zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：工作者-学习专用和共享工作者

在过去的几章中，我们专注于 Node.js 以及如何利用与前端相同的语言编写后端应用程序。我们已经看到了创建服务器、卸载任务和流式传输的各种方法。在这一部分，我们将专注于浏览器的任务卸载方面。

最终，正如我们在 Node.js 中所看到的，我们需要将一些计算密集型任务从主线程转移到单独的线程或进程，以确保我们的应用程序保持响应。服务器不响应的影响可能相当令人震惊，而用户界面不工作的影响对大多数用户来说是非常令人反感的。因此，我们有了 Worker API。

在本章中，我们将专门研究两种工作方式，即专用和共享。总的来说，我们将做以下工作：

+   学会通过 Worker API 将繁重的处理任务转移到工作线程。

+   学习如何通过`postMessage`和`BroadcastChannel` API 与工作线程进行通信。

+   讨论`ArrayBuffer`和`Transferrable`属性，以便我们可以快速在工作者和主线程之间移动数据。

+   查看`SharedWorker`和 Atomics API，看看我们如何在应用程序的多个选项卡之间共享数据。

+   查看利用前几节知识的共享缓存的部分实现。

# 技术要求

完成本章需要以下项目：

+   文本编辑器或 IDE，最好是 VS Code

+   访问 Chrome 或 Firefox

+   计算机并行化知识

+   在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter10)找到的代码。

# 将工作转移到专用工作者

工作者使我们能够将长时间运行的计算密集型任务转移到后台。我们不必再担心我们的事件循环是否被某种繁重的任务填满，我们可以将该任务转移到后台线程。

在其他语言/环境中，这可能看起来像以下内容（这只是伪代码，实际上与任何语言都没有真正联系）：

```js
Thread::runAsync((data) -> {
   for(d : data) { //do some computation }
});
```

虽然这在这些环境中运行良好，但我们必须开始考虑诸如死锁、僵尸线程、写后读等主题。所有这些都可能非常难以理解，通常是可以遇到的最困难的错误之一。JavaScript 没有给我们提供利用类似前述的能力，而是给了我们工作者，这给了我们另一个上下文来工作，我们在那里不会遇到相同的问题。

对于那些感兴趣的人，操作系统或 Unix 编程的书籍可以帮助解决上述问题。这些主题超出了本书的范围，但它们非常有趣，甚至有一些语言正在尝试通过将解决方案构建到语言中来解决这些问题。其中一些例子是 Go（[`golang.org/`](https://golang.org/)），它使用消息传递技术，以及 Rust（[`www.rust-lang.org/`](https://www.rust-lang.org/)），它利用借用检查等概念来最小化这些问题。

首先，让我们以在后台进行工作的示例开始，我们将生成一个`Worker`并让它计算 100 万个数字的总和。为此：

1.  我们在 HTML 文件中添加以下`script`部分：

```js
<script type="text/javascript">
    const worker = new Worker('worker.js');
    console.log('this is on the main thread');
</script>
```

1.  我们为我们的`Worker`创建一个 JavaScript 文件，并添加以下内容：

```js
let num = 0;
for(let i = 0; i < 1000000; i++) {
    num += i;
}
```

如果我们启动 Chrome，我们应该看到打印出两条消息-一条说它在主线程上运行，另一条显示值为 499999500000。我们还应该看到其中一条是由 HTML 文件记录的，另一条是由工作者记录的。我们刚刚生成了一个工作者，并让它为我们做了一些工作！

请记住，如果我们想从我们的文件系统运行 JavaScript 文件而不是服务器，我们需要关闭所有 Chrome 的实例，然后从命令行重新启动它，使用`chrome.exe –-allow-file-access-from-files`。这将使我们能够从文件系统启动我们的外部 JavaScript 文件，而不需要服务器。

让我们继续做一些用户可能想做的更复杂的事情。一个有趣的数学问题是得到一个数字的质因数分解。这意味着，当给定一个数字时，我们将尝试找到组成该数字的所有质数（只能被 1 和它自己整除的数字）。一个例子是 12 的质因数分解，即 2、2 和 3。

这个问题导致了密码学的有趣领域以及公钥/私钥的工作原理。基本的理解是，给定两个相对较大的质数，将它们相乘很容易，但根据时间限制，从它们的乘积中找到这两个数字是不可行的。

回到手头的任务，我们将在用户将数字输入到输入框后生成一个`worker`。我们将计算该数字并将其记录到控制台。所以让我们开始：

1.  我们在 HTML 文件中添加一个输入，并更改代码以在输入框的更改事件上生成一个`worker`：

```js
<input id="in" type="number" />
<script type="text/javascript">
document.querySelector("#in").addEventListener('change', (ev) => {
    const worker = new Worker('worker.js', {name : 
     ev.target.value});
});
</script>
```

1.  接下来，我们将在`worker`中获取我们的名字，并将其用作输入。从那里，我们将运行在[`www.geeksforgeeks.org/print-all-prime-factors-of-a-given-number/`](https://www.geeksforgeeks.org/print-all-prime-factors-of-a-given-number/)找到的质因数分解算法，但转换为 JavaScript。完成后，我们将关闭`worker`：

```js
let numForPrimes = parseInt(self.name);
const primes = [];
console.log('we are looking for the prime factorization of: ', numForPrimes);
while( numForPrimes % 2 === 0 ) {
    primes.push(2);
    numForPrimes /= 2;
}
for(let i = 3; i <= Math.sqrt(numForPrimes); i+=2) {
    while( numForPrimes % i === 0 ) {
        primes.push(i);
        numForPrimes /= i;
    }
}
if( numForPrimes > 2 ) {
    primes.push(numForPrimes);
}
console.log('prime factorization is: ', primes.join(" "));
self.close();
```

如果我们现在在浏览器中运行这个应用程序，我们会看到在每次输入后，我们会在控制台中得到控制台日志消息。请注意，数字 1 没有因子。这是一个数学原因，但请注意数字 1 没有质因数分解。

我们可以对一堆输入运行这个，但如果我们输入一个相对较大的数字，比如`123,456,789`，它仍然会在后台计算，因为我们在主线程上做事情。现在，我们目前通过 worker 的名称向 worker 传递数据。必须有一种方法在 worker 和主线程之间传递数据。这就是`postMessage`和`BroadcastChannel`API 发挥作用的地方！

# 在我们的应用程序中移动数据

正如我们在 Node.js 的`worker_thread`模块中看到的，有一种方法可以与我们的 worker 通信。这是通过`postMessage`系统。如果我们看一下方法签名，我们会发现它需要一个消息，可以是任何 JavaScript 对象，甚至带有循环引用的对象。我们还看到另一个名为 transfer 的参数。我们稍后会深入讨论这一点，但正如其名称所示，它允许我们实际传输数据，而不是将数据复制到 worker。这是一个更快的数据传输机制，但在利用它时有一些注意事项，我们稍后会讨论。

让我们以我们一直在构建的例子为例，并回应从前端发送的消息：

1.  我们将在每次更改事件发生时创建一个新的`worker`并立即创建一个。然后，在更改事件上，我们将通过`postMessage`将数据发送到`worker`：*

```js
const dedicated_worker = new Worker('worker.js', {name : 'heavy lifter'});
document.querySelector("#in").addEventListener('change', (ev) => {
    dedicated_worker.postMessage(parseInt(ev.target.value));
});
```

1.  如果我们现在尝试这个例子，我们将不会从主线程收到任何东西。我们必须响应 worker 的全局描述符`self`上的`onmessage`事件。让我们继续添加我们的处理程序，并删除`self.close()`方法，因为我们想保留它：

```js
function calculatePrimes(val) {
    let numForPrimes = val;
    const primes = [];
    while( numForPrimes % 2 === 0 ) {
        primes.push(2);
        numForPrimes /= 2;
    }
    for(let i = 3; i <= Math.sqrt(numForPrimes); i+=2) {
        while( numForPrimes % i === 0 ) {
            primes.push(i);
            numForPrimes /= i;
        }
    }
    if( numForPrimes > 2 ) {
        primes.push(numForPrimes);
    }
    return primes;
}
self.onmessage = function(ev) {
    console.log('our primes are: ', calculatePrimes(ev.data).join(' '));
}
```

从这个例子中可以看出，我们已经将素数的计算移到了一个单独的函数中，当我们收到消息时，我们获取数据并将其传递给`calculatePrimes`方法。现在，我们正在使用消息系统。让我们继续为我们的示例添加另一个功能。不要打印到控制台，让用户根据他们的输入得到一些反馈：

1.  我们将在输入框下面添加一个段落标签来保存我们的答案：

```js
<p>The primes for the number is: <span id="answer"></span></p>
<script type="text/javascript">
    const answer = document.querySelector('#answer');
    // previous code here
</script>
```

1.  现在，我们将在`worker`的`onmessage`处理程序中添加一些内容，就像我们在`worker`内部所做的那样，以监听来自`worker`的事件。当我们收到一些数据时，我们将用返回的值填充答案：

```js
dedicated_worker.onmessage = function(ev) {
    answer.innerText = ev.data;
}
```

1.  最后，我们将更改我们的`worker`代码，利用`postMessage`方法将数据发送回主线程：

```js
self.onmessage = function(ev) {
    postMessage(calculatePrimes(ev.data).join(' '));
}
```

这也展示了我们不需要添加`self`来调用全局范围的方法。就像窗口是主线程的全局范围一样，`self`是工作线程的全局范围。

通过这个例子，我们已经探讨了`postMessage`方法，并看到了如何在工作线程和生成它的线程之间发送数据，但如果我们有多个选项卡想要进行通信怎么办？如果我们有多个工作线程想要发送消息怎么办？

处理这个问题的一种方法是跟踪所有的工作线程，并循环遍历它们，像下面这样发送数据：

```js
const workers = [];
for(let i = 0; i < 5; i++) {
    const worker = new Worker('test.js', {name : `worker${i}`});
    workers.push(worker);
}
document.querySelector("#in").addEventListener('change', (ev) => {
    for(let i = 0; i < workers.length; i++) {
        workers[i].postMessage(ev.target.value);
    }
});
```

在`test.js`文件中，我们只是控制台记录消息，并说明我们正在引用的工作线程的名称。这可能很快失控，因为我们需要跟踪哪些工作线程仍然存活，哪些已经被移除。处理这个问题的另一种方法是在一个通道上广播数据。幸运的是，我们有一个名为`BroadcastChannel`的 API 可以做到这一点。

正如 MDN 网站上的文档所述（[`developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API`](https://developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API)），我们只需要通过将单个参数传递给它的构造函数来创建一个`BroadcastChannel`对象，即通道的名称。谁先调用它就创建了通道，然后任何人都可以监听它。发送和接收数据就像我们的`postMessage`和`onmessage`示例一样简单。以下是我们先前用于测试界面的代码，而不需要跟踪所有工作线程，只需广播数据出去：

```js
const channel = new BroadcastChannel('workers');
document.querySelector("#in").addEventListener('change', (ev) => {
    channel.postMessage(ev.target.value);
});
```

然后，在我们的`workers`中，我们只需要监听`BroadcastChannel`，而不是监听我们自己的消息处理程序：

```js
const channel = new BroadcastChannel('workers');
channel.onmessage = function(ev) {
    console.log(ev.data, 'was received by', name);
}
```

现在，我们已经简化了在多个工作线程和甚至多个具有相同主机的选项卡之间发送和接收消息的过程。这个系统的优点在于，我们可以根据一些标准让一些工作线程监听一个通道，而让其他工作线程监听另一个通道。然后，我们可以有一个全局通道发送命令，任何工作线程都可以响应。让我们继续对我们的素数程序进行简单的调整。我们将不再将数据发送到单独的工作线程，而是将有四个工作线程；其中两个将处理偶数，另外两个将处理奇数：

1.  我们更新我们的主要代码以启动四个工作线程。我们将根据数字是偶数还是奇数来命名它们：

```js
for(let i = 0; i < 4; i++) {
    const worker = new Worker('worker.js', 
        {name : `worker ${i % 2 === 0 ? 'even' : 'odd'}`}
    );
}
```

1.  我们更改了输入后发生的事情，将偶数发送到偶数通道，将奇数发送到奇数通道：

```js
document.querySelector("#in").addEventListener('change', (ev) => {
    const value = parseInt(ev.target.value);
    if( value % 2 === 0 ) {
        even_channel.postMessage(value);
    } else {
        odd_channel.postMessage(value);
    }
});
```

1.  我们创建三个通道：一个用于偶数，一个用于奇数，一个用于全局发送给所有工作线程：

```js
const even_channel = new BroadcastChannel('even');
const odd_channel = new BroadcastChannel('odd');
const global = new BroadcastChannel('global');
```

1.  我们添加一个新按钮来终止所有工作线程，并将其连接到全局通道上广播：

```js
<button id="quit">Stop Workers</button>
<script type="text/javascript">
document.querySelector('#quit').addEventListener('click', (ev) => {
     global.postMessage('quit');
});
</script>
```

1.  我们更改我们的工作线程以根据其名称处理消息：

```js
const mainChannelName = name.includes("odd") ? "odd" : "even";
const mainChannel = new BroadcastChannel(mainChannelName);
```

1.  当我们在这些通道中的一个上收到消息时，我们会像以前一样做出响应：

```js
mainChannel.onmessage = function(ev) {
    if( typeof ev.data === 'number' )
        this.postMessage(calculatePrimes(ev.data));
}
```

1.  如果我们在全局通道上收到消息，我们检查它是否是`quit`消息。如果是，就终止工作线程：

```js
const globalChannel = new BroadcastChannel('global');
globalChannel.onmessage = function(ev) {
    if( ev.data === 'quit' ) {
        close();
    }
}
```

1.  现在，回到主线程，我们将监听奇数和偶数通道上的数据。当有数据时，我们几乎与以前处理它的方式完全相同：

```js
even_channel.onmessage = function(ev) {
    if( typeof ev.data === 'object' ) {
        answer.innerText = ev.data.join(' ');
    }
}
odd_channel.onmessage= function(ev) {
    if( typeof ev.data === 'object' ) {
        answer.innerText = ev.data.join(' ');
    }
}
```

需要注意的一点是我们的工作线程和主线程如何处理奇数和偶数通道上的数据。由于我们是广播，我们需要确保它是我们想要的数据。在工作线程的情况下，我们只想要数字，在主线程的情况下，我们只想要看到数组。

`BroadcastChannel` API 只能与相同的源一起使用。这意味着我们不能在两个不同的站点之间通信，只能在同一域下的页面之间通信。

虽然这是`BroadcastChannel`机制的一个过于复杂的例子，但它应该展示了我们如何可以轻松地将工作线程与其父级解耦，并使它们易于发送数据而无需循环遍历它们。现在，我们将回到`postMessage`方法，并查看`transferrable`属性以及它对发送和接收数据的意义。

# 在浏览器中发送二进制数据

虽然消息传递是发送数据的一种很好的方式，但在通过通道发送非常大的对象时会出现一些问题。例如，假设我们有一个专用的工作线程代表我们发出请求，并且还从缓存中向工作线程添加一些数据。它可能会有数千条记录。虽然工作线程已经占用了相当多的内存，但一旦我们使用`postMessage`，我们会看到两件事：

+   移动对象所需的时间会很长。

+   我们的内存将大幅增加

这是因为浏览器使用结构化克隆算法来发送数据。基本上，它不仅仅是将数据移动到通道上，而是将对象进行序列化和反序列化，从根本上创建多个副本。除此之外，我们不知道垃圾回收器何时运行，因为我们知道它是不确定的。

我们实际上可以在浏览器中看到复制过程。如果我们创建一个名为`largeObject.js`的工作线程并移动一个巨大的有效负载，我们可以通过利用`Date.now()`方法来测量所需的时间。除此之外，我们还可以利用开发者工具中的记录系统，就像我们在第一章中学到的那样，*网络高性能工具*，来分析我们使用的内存量。让我们设置这个测试案例：

1.  创建一个新的工作线程并分配一个大对象。在这种情况下，我们将使用一个存储对象的 100,000 元素数组：

```js
const dataToSend = new Array(100000);
const baseObj = {prop1 : 1, prop2 : 'one'};
for(let i = 0; i < dataToSend.length; i++) {
    dataToSend[i] = Object.assign({}, baseObj);
    dataToSend[i].prop1 = i;
    dataToSend[i].prop2 = `Data for ${i}`;
}
console.log('send at', Date.now());
postMessage(dataToSend);
```

1.  现在我们在 HTML 文件中添加一些代码来启动这个工作线程并监听消息。我们将标记消息到达的时间，然后对代码进行分析以查看内存增加情况：

```js
const largeWorker = new Worker('largeObject.js');
largeWorker.onmessage = function(ev) {
    console.log('the time is', Date.now());
    const obj = ev.data;
}
```

如果我们现在将其加载到浏览器中并对代码进行分析，我们应该会看到类似以下的结果。消息的时间在 800 毫秒到 1.7 秒之间，堆大小在 80MB 到 100MB 之间。虽然这种情况绝对超出了大多数人的范围，但它展示了这种消息传递方式的一些问题。

解决这个问题的方法是使用`postMessage`方法的可传递部分。这允许我们*发送*一个二进制数据类型通过通道，而不是复制它，通道实际上只是转移对象。这意味着发送方不再能够访问它，但接收方可以。可以这样理解，发送方将数据放在一个保持位置，并告诉接收方它在哪里。此时，发送方不再能够访问它。接收方接收所有数据，并注意到它有一个位置来查找数据。它去到这个位置并获取数据，从而实现数据传输机制。

让我们继续编写一个简单的例子。让我们使用大量数据填充我们的重型工作线程，比如从 1 到 1,000,000 的数字列表：

1.  我们创建一个包含 1,000,000 个元素的`Int32Array`。然后我们在其中添加从 1 到 1,000,000 的所有数字：

```js
const viewOfData = new Int32Array(1000000);
for(let i = 1; i <= viewOfData.length; i++) {
    viewOfData[i-1] = i;
}
```

1.  然后，我们将利用`postMessage`的可传递部分发送这些数据。请注意，我们必须获取基础的`ArrayBuffer`。我们很快会讨论这一点：

```js
postMessage(viewOfData, [viewOfData.buffer]);
```

1.  我们将在主线程上接收数据并输出该数据的长度：

```js
const obj = ev.data;
console.log('data length', obj.byteLength);
```

我们会注意到传输这一大块数据所花费的时间几乎是不可察觉的。这是因为前面的理论，它只是将数据打包并将其放到接收端。

对于类型化数组和`ArrayBuffers`需要额外说明。`ArrayBuffers`可以被视为 Node.js 中的缓冲区。它们是存储数据的最低形式，并直接保存一些数据的字节。但是，为了真正利用它们，我们需要在`ArrayBuffer`上放置一个*视图*。这意味着我们需要赋予`ArrayBuffer`意义。在我们的例子中，我们说它存储有符号的 32 位整数。我们可以在`ArrayBuffer`上放置各种视图，就像我们可以以不同的方式解释 Node.js 中的缓冲区一样。最好的思考方式是，`ArrayBuffer`是我们真正不想使用的低级系统，而视图是赋予底层数据意义的系统。

考虑到这一点，如果我们在工作线程端检查`Int32Array`的字节长度，我们会发现它是零。我们不再可以访问那些数据，正如我们所说的。在继续讨论`SharedWorkers`和`SharedArrayBuffers`之前，我们将修改我们的因式分解程序，利用这个可传递属性发送因子：

1.  我们将几乎使用完全相同的逻辑，只是不再发送我们拥有的数组，而是发送`Int32Array`：

```js
if( typeof ev.data === 'number' ) {
    const result = calculatePrimes(ev.data);
    const send = new Int32Array(result);
    this.postMessage(result, [result.buffer]);
}
```

1.  现在我们将更新接收端代码，以处理发送的`ArrayBuffers`而不仅仅是一个数组：

```js
if( typeof ev.data === 'object' ) {
    const data = new Int32Array(ev.data);
    answer.innerText = data.join(' ');                  
}
```

如果我们测试这段代码，我们会发现它的工作方式是一样的，但我们不再复制数据，而是将其交给主线程，从而使消息传递更快，利用的内存更少。

主要思想是，如果我们只是发送结果或需要尽快完成，我们应该尝试利用可传递系统发送数据。如果我们在发送数据后需要在工作线程中使用数据，或者没有简单的方法发送数据（我们没有序列化技术），我们可以利用正常的`postMessage`系统。

仅仅因为我们可以使用可传递系统来减少内存占用，这可能会导致基于需要应用的数据转换量而增加时间。如果我们已经有二进制数据，这很好，但如果我们有需要移动的 JSON 数据，可能最好的方法是以该形式传输它，而不是经过许多中间转换。

有了所有这些想法，让我们来看看`SharedWorker`系统和`SharedArrayBuffer`系统。这两个系统，特别是`SharedArrayBuffer`，在过去引起了一些问题（我们将在下一节讨论），但如果我们小心使用它们，我们将能够利用它们作为良好的消息传递和数据共享机制的能力。

# 共享数据和工作线程

虽然大多数时候我们希望保持工作线程和应用程序选项卡之间的边界，但有时我们希望只是共享数据，甚至是工作线程。在这种情况下，我们可以利用两个系统，`SharedWorker`和`SharedArrayBuffer`。

`SharedWorker`就像它的名字一样，当一个启动时，就像`BroadcastChannel`一样，当其他人调用创建`SharedWorker`时，它将连接到已经创建的实例。让我们继续做这件事：

1.  我们将为`SharedWorker` JavaScript 代码创建一个新文件。在这里面，放一些通用的计算函数，比如加法和减法：

```js
const add = function(a, b) {
    return a + b;
}
const mult = function(a, b) {
    return a * b;
}
const divide = function(a, b) {
    return a / b;
}
const remainder = function(a, b) {
    return a % b;
}
```

1.  在我们当前某个工作线程的代码中，启动`SharedWorker`：

```js
const shared = new SharedWorker('shared.js');
shared.port.onmessage = function(ev) {
    console.log('message', ev);
}
```

我们已经看到了一个问题。我们的系统显示找不到`SharedWorker`。要使用`SharedWorker`，我们必须在一个窗口中启动它。所以现在，我们将不得不将启动代码移动到我们的主页面。

1.  将启动代码移动到主页面，然后将端口传递给其中一个工作线程：

```js
const shared = new SharedWorker('shared.js');
shared.port.start();
for(let i = 0; i < 4; i++) {
    const worker = new Worker('worker.js', 
        {name : `worker ${i % 2 === 0 ? 'even' : 'odd'}`}
    );
    worker.postMessage(shared.port, [shared.port]);
}
```

我们现在遇到另一个问题。由于我们想要将端口传递给工作线程，并且不希望在主窗口中访问它，所以我们利用了可传递的系统。然而，由于那时我们只有一个引用，一旦我们将它发送给一个工作线程，就无法再次发送。相反，让我们启动一个工作线程，并关闭我们的`BroadcastChannel`系统。

1.  注释掉我们的`BroadcastChannels`和所有的循环代码。让我们只在这个窗口中启动一个工作线程：

```js
const shared = new SharedWorker('shared.js');
shared.port.start();
const worker = new Worker('worker.js');
document.querySelector("#in").addEventListener('change', (ev) => {
    const value = parseInt(ev.target.value);
    worker.postMessage(value);
});
document.querySelector('#quit').addEventListener('click', (ev) => {
    worker.postMesasge('quit');
});
```

1.  有了这些改变，我们将不得不简化我们的专用工作线程。我们将只是像以前一样响应我们消息通道上的事件：

```js
let sharedPort = null;
onmessage = function(ev) {
    const data = ev.data;
    if( typeof data === 'string' ) {
        return close();
    }
    if( typeof data === 'number' ) {
        const result = calculatePrimes(data);
        const send = new Int32Array(result);
        return postMessage(send, [send.buffer]);
    }
    // handle the port
    sharedPort = data;
}
```

1.  现在我们在一个单一的工作线程中有了`SharedWorker`端口，但是这对我们解决了什么问题呢？现在，我们可以同时打开多个选项卡，并将数据发送到每一个选项卡。为了看到这一点，让我们将一个处理程序连接到`sharedPort`：

```js
sharedPort.onmessage = function(ev) {
    console.log('data', ev.data);
}
```

1.  最后，我们可以更新我们的`SharedWorker`，一旦连接发生，就做出响应，如下所示：

```js
onconnect = function(e) {
    let port = e.ports[0];
    console.log('port', port);
    port.onmessage = function(e) {
        port.postMessage('you sent data');
    }
    port.postMessage('you connected');
}
```

有了这个，我们将看到一个消息回到我们的工作线程。我们现在的`SharedWorker`已经运行起来，并且直接与我们的`DedicatedWorker`进行通信！然而，仍然有一个问题：为什么我们没有看到来自我们的`SharedWorker`的日志？嗯，我们的`SharedWorker`存在于与我们的`DedicatedWorker`和主线程不同的上下文中。要访问我们的`SharedWorker`，我们可以转到 URL`chrome://inspect/#workers`，然后定位它。现在，我们没有给它起名字，所以它应该叫做`untitled`，但是当我们点击它下面的`inspect`选项时，我们现在有了一个工作线程的调试上下文。

我们已经将我们的`SharedWorker`连接到 DOM 上下文，并且已经将每个`DedicatedWorker`连接到该`SharedWorker`，但是我们需要能够向每个`DedicatedWorker`发送消息。让我们继续添加这段代码：

1.  首先，我们需要跟踪所有通过`SharedWorker`连接到我们的工作线程。将以下代码添加到我们`onconnect`监听器的底部：

```js
ports.push(port);
```

1.  现在，我们将在我们的文档中添加一些 HTML，这样我们就可以发送`add`、`multiply`、`divide`和`subtract`请求，以及两个新的数字输入：

```js
<input id="in1" type="number" />
<input id="in2" type="number" />
<button id="add">Add</button>
<button id="subtract">Subtract</button>
<button id="multiply">Multiply</button>
<button id="divide">Divide</button>
```

1.  接下来，我们将通过`DedicatedWorker`将这些信息传递给`SharedWorker`：

```js
if( typeof data === 'string' ) {
    if( data === 'quit' ) {
        close();
    } else {
        sharedPort.postMessage(data);
    }
}
```

1.  最后，我们的`SharedWorker`将运行相应的操作，并将其传递回`DedicatedWorker`，后者将数据记录到控制台：

```js
port.onmessage = function(e) {
    const _d = e.data.split(' ');
    const in1 = parseInt(_d[1]);
    const in2 = parseInt(_d[2]);
    switch(_d[0]) {
        case 'add': {
            port.postMessage(add(in1, in2));
            break;
        }
        // other operations removed since they are the same thing
    }
}
```

有了这一切，我们现在可以打开多个应用程序选项卡，它们都共享相同的前置数学系统！对于这种类型的应用程序来说，这有点过度，但是当我们需要在我们的应用程序中执行跨多个窗口或选项卡的复杂操作时，这可能是有用的。这可能是利用 GPU 的东西，我们只想做一次。让我们通过概述`SharedArrayBuffer`来结束本节。然而，要记住的一件事是，`SharedWorker`是所有选项卡持有的单个线程，而`DedicatedWorker`是每个选项卡/窗口的一个线程。虽然共享一个工作线程对于前面解释的一些任务可能是有益的，但如果多个选项卡同时使用它，也可能会减慢其他任务的速度。

`SharedArrayBuffer`允许我们的所有实例共享相同的内存块。就像可传递的对象可以根据将内存传递给另一个工作线程而有不同的所有者一样，`SharedArrayBuffer`允许不同的上下文共享相同的部分。这允许更新在我们的所有实例中传播，并且对于某些类型的数据几乎立即更新，但它也有许多与之相关的缺点。

这是我们在其他语言中最有可能接近`SharedMemory`的方式。要正确使用`SharedArrayBuffer`，我们需要使用 Atomics API。再次强调，不直接深入 Atomics API 背后的细节，它确保操作按正确顺序进行，并且保证在更新时能够更新需要更新的内容，而不会被其他人在更新过程中覆盖。

我们开始进入细节，这些细节可能很难完全理解发生了什么。一个好的理解 Atomics API 的方式是将其想象成一个许多人共享一张纸的系统。他们轮流在上面写字和阅读其他人写下的内容。

然而，其中一个缺点是他们一次只能写一个字符。因此，当他们仍在尝试完成写入单词时，其他人可能会在他们的位置上写入内容，或者有人可能会读取他们的不完整短语。我们需要一个机制，让人们能够在开始写入之前写入他们想要的整个单词，或者在开始写入之前读取整个部分。这就是 Atomics API 的工作。

`SharedArrayBuffer`确实存在一些问题，与浏览器不支持它有关（目前，只有 Chrome 支持它而无需标志），以及我们可能希望使用 Atomics API（由于安全问题，`SharedWorker`无法将其发送到主线程或专用 worker）。

为了设置`SharedArrayBuffer`的基本示例，我们将在主线程和 worker 之间共享一个缓冲区。当我们向 worker 发送请求时，我们将更新 worker 中的数字。更新这个数字应该对主线程可见，因为它们共享缓冲区。

1.  创建一个简单的 worker，并使用`onmessage`处理程序检查是否收到了一个数字。如果是，我们将增加`SharedArrayBuffer`中的数据。否则，数据是来自主线程的`SharedArrayBuffer`。

```js
let sharedPort = null;
let buf = null;
onmessage = function(ev) {
    const data = ev.data;
    if( typeof data === 'number' ) {
        Atomics.add(buf, 0, 1);
    } else {
        buf = new Int32Array(ev.data);
    }
}
```

1.  接下来，在我们的主线程上，我们将添加一个新的按钮，上面写着“增加”。当点击它时，它将向专用 worker 发送一条消息，以增加当前数字。

```js
// HTML
<button id="increment">Increment</button>
<p id="num"></p>

// JavaScript
document.querySelector('#increment').addEventListener('click', () => {
    worker.postMessage(1);
});
```

1.  现在，当 worker 在其端更新缓冲区时，我们将不断检查`SharedArrayBuffer`是否有更新。我们将始终将数字放在前面代码片段中显示的数字段落元素中。

```js
setInterval(() => {
    document.querySelector('#num').innerText = shared;
}, 100);
```

1.  最后，为了开始所有这些，我们将在主线程上创建一个`SharedArrayBuffer`，并在启动后将其发送给 worker：

```js
let shared = new SharedArrayBuffer(4);
const worker = new Worker('worker_to_shared.js');
worker.postMessage(shared);
shared = new Int32Array(shared);
```

通过这样，我们可以看到我们的值现在正在增加，即使我们没有从 worker 发送任何数据到主线程！这就是共享内存的力量。现在，正如之前所述，由于我们无法在主线程上使用`wait`和`notify`系统，也无法在`SharedWorker`中使用`SharedArrayBuffer`，因此我们在 Atomics API 方面受到相当大的限制，但它对于只读取数据的系统可能是有用的。

在这些情况下，我们可能会更新`SharedArrayBuffer`，然后向主线程发送一条消息，告诉它我们已经更新了它，或者它可能已经是一个接受`SharedArrayBuffers`的 Web API，比如 WebGL 渲染上下文。虽然前面的例子并不是很有用，但它展示了如果再次可以在`SharedWorker`中生成和使用`SharedArrayBuffer`的能力，我们可能如何在未来使用共享系统。接下来，我们将专注于构建一个所有 worker 都可以共享的单一缓存。

# 构建一个简单的共享缓存

通过我们学到的一切，我们将专注于一个在报告系统和大多数类型的操作 GUI 中非常普遍的用例——需要添加其他数据的大块数据（有些人称之为装饰数据，其他人称之为属性）。一个例子是我们有一组客户的买入和卖出订单。

这些数据可能以以下方式返回：

```js
{
    customerId : "<guid>",
    buy : 1000000,
    sell : 1000000
}
```

有了这些数据，我们可能想要添加一些与客户 ID 相关联的上下文。我们可以通过两种方式来做到这一点：

+   首先，我们可以在数据库中执行联接操作，为用户添加所需的信息。

+   其次，我们将在此处进行说明的是，在我们获得基本查询时在前端添加这些数据。这意味着当我们的应用程序启动时，我们将获取所有这些归因数据并将其存储在某个后台缓存中。接下来，当我们发出请求时，我们还将向缓存请求相应的数据。

为了实现第二个选项，我们将实现我们之前学到的两种技术，`SharedWorker`和`postMessage`接口：

1.  我们创建一个基本级别的 HTML 文件，其中包含每一行数据的模板。我们不会深入创建 Web 组件，就像我们在第三章中所做的那样，但我们将使用它来根据需要创建我们的表行：

```js
<body>
    <template id="row">
        <tr>
            <td class="name"></td>
            <td class="zip"></td>
            <td class="phone"></td>
            <td class="email"></td>
            <td class="buy"></td>
            <td class="sell"></td>
        </tr>
    </template>
   <table id="buysellorders">
   <thead>
       <tr>
           <th>Customer Name</th>
           <th>Zipcode</th>
           <th>Phone Number</th>
           <th>Email</th>
           <th>Buy Order Amount</th>
           <th>Sell Order Amount</th>
       </tr>
   </thead>
   <tbody>
   </tbody>
   </table>
</body>
```

1.  我们设置了一些指向我们模板和表的指针，以便我们可以快速插入。除此之外，我们可以为即将创建的`SharedWorker`创建一个占位符：

```js
const tableBody = document.querySelector('#buysellorders > tbody');
const rowTemplate = document.querySelector('#row');
const worker = new SharedWorker('<fill in>', {name : 'cache'});
```

1.  有了这个基本设置，我们可以创建我们的`SharedWorker`并为其提供一些基本数据。为此，我们将使用网站[`www.mockaroo.com/`](https://www.mockaroo.com/)。这将允许我们创建大量随机数据，而无需自己考虑。我们可以将数据更改为我们想要的任何内容，但在我们的情况下，我们将选择以下选项：

+   `id`：行号

+   `full_name`：全名

+   `email`：电子邮件地址

+   `phone`：电话

+   `zipcode`：数字序列：`######`

1.  填写了这些选项后，我们可以将格式更改为 JSON，并通过单击“下载数据”进行保存。完成后，我们可以构建我们的`SharedWorker`。与我们的其他`SharedWorker`类似，我们将使用`onconnect`处理程序，并为传入的端口添加一个`onmessage`处理程序：

```js
onconnect = function(e) {
    let port = e.ports[0];
    port.onmessage = function(e) {
        // do something
    }
}
```

1.  接下来，在我们的 HTML 文件中启动我们的`SharedWorker`：

```js
const worker = new SharedWorker('cache_shared.js', 'cache');
```

1.  现在，当我们启动我们的`SharedWorker`时，我们将使用`importScripts`加载文件。这允许我们加载外部 JavaScript 文件，就像我们在 HTML 中使用`script`标签一样。为此，我们需要修改 JSON 文件，将对象指向一个变量并将其重命名为 JavaScript 文件：

```js
let cache = [{"id":1,"full_name":"Binky Bibey","email":"bbibey0@furl.net","phone":"370-576-9587","zipcode":"640069"}, //rest of the data];

// SharedWorker.js
importScripts('./mock_customer_data.js');
```

1.  现在我们已经将数据缓存进来，我们将回应从端口发送来的消息。我们只期望数字数组。这些将对应于与用户关联的 ID。现在，我们将循环遍历字典中的所有项目，看看我们是否有它们。如果有，我们将将它们添加到一个数组中，然后进行响应：

```js
const handleReq = function(arr) {
    const res = new Array(arr.length)
    for(let i = 0; i < arr.length; i++) {
        const num = arr[i];
        for(let j = 0; j < cache.length; j++) {
            if( num === cache[j].id ) {
                res[i] = cache[j];
               break;
            }
        }
    }
    return res;
}
onconnect = function(e) {
    let port = e.ports[0];
    port.onmessage = function(e) {
        const request = e.data;
        if( Array.isArray(request) ) {
            const response = handleReq(request);
            port.postMessage(response);
        }
    }
}
```

1.  因此，我们需要在我们的 HTML 文件中添加相应的代码。我们将添加一个按钮，该按钮将向我们的`SharedWorker`发送 100 个随机 ID。这将模拟当我们发出请求并获得与数据关联的 ID 时的情况。模拟函数如下：

```js
// developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/
// Global_Objects/Math/random

const getRandomIntInclusive = function(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const simulateRequest = function() {
    const MAX_BUY_SELL = 1000000;
    const MIN_BUY_SELL = -1000000;
    const ids = [];
    const createdIds = [];
    for(let i = 0; i < 100; i++) {
        const id = getRandomIntInclusive(1, 1000);
        if(!createdIds.includes(id)) {
            const obj = {
                id,
                buy : getRandomIntInclusive(MIN_BUY_SELL,  
                 MAX_BUY_SELL),
                sell : getRandomIntInclusive(MIN_BUY_SELL, 
                 MAX_BUY_SELL)
            };
            ids.push(obj);
        }
    }
    return ids;
}
```

1.  通过上述模拟，我们现在可以添加我们的请求输入，然后将其发送到我们的`SharedWorker`：

```js
requestButton.addEventListener('click', (ev) => {
    const res = simulateRequest();
    worker.port.postMessage(res);
});
```

1.  现在，我们目前正在向我们的`SharedWorker`发布错误的数据。我们只想发布 ID，但是我们如何将我们的请求与我们的`SharedWorker`的响应联系起来呢？我们需要稍微修改我们的`request`和`response`方法的结构。我们现在将 ID 绑定到我们的消息，这样我们就可以让`SharedWorker`将其发送回给我们。这样，我们就可以在前端拥有请求和与之关联的 ID 的映射。进行以下更改：

```js
// HTML file
const requestMap = new Map();
let reqCounter = 0;
requestButton.addEventListener('click', (ev) => {
    const res = simulateRequest();
    const reqId = reqCounter;
    reqCounter += 1;
    worker.port.postMessage({
        id : reqId,
        data : res
    });
});

// Shared worker
port.onmessage = function(e) {
    const request = e.data;
    if( request.id &&
        Array.isArray(request.data) ) {
        const response = handleReq(request.data);
        port.postMessage({
            id : request.id,
            data : response
        });
    }
}
```

1.  通过这些更改，我们仍然需要确保我们只将 ID 传递给`SharedWorker`。在发送请求之前，我们可以从请求中取出这些 ID：

```js
requestButton.addEventListener('click', (ev) => {
    const res = simulateRequest();
    const reqId = reqCounter;
    reqCounter += 1;
    requestMap.set(reqId, res);
    const attribute = [];
    for(let i = 0; i < res.length; i++) {
        attribute.push(res[i].id);
    }
    worker.port.postMessage({
        id : reqId,
        data : attribute
    });
});
```

1.  现在我们需要处理返回到我们的 HTML 文件中的数据。首先，我们将一个`onmessage`处理程序附加到端口上：

```js
worker.port.onmessage = function(ev) {
    console.log('data', ev.data);
}
```

1.  最后，我们从地图中获取相关的买卖订单，并用返回的缓存数据填充它。完成这些后，我们只需克隆我们的行模板并填写相应的字段：

```js
worker.port.onmessage = function(ev) {
    const data = ev.data;
    const baseData = requestMap.get(data.id);
    requestMap.delete(data.id);
    const attribution = data.data;
    tableBody.innerHTML = '';
    for(let i = 0; i < baseData.length; i++) {
        const _d = baseData[i];
        for(let j = 0; j < attribution.length; j++) {
            if( _d.id === attribution[j].id ) {
                const final = {..._d, ...attribution[j]};
                const newRow = rowTemplate.content.cloneNode(true);
                newRow.querySelector('.name').innerText =  
                 final.full_name;
                newRow.querySelector('.zip').innerText = 
                 final.zipcode;
                newRow.querySelector('.phone').innerText = 
                 final.phone;
                newRow.querySelector('.email').innerText = 
                 final.email;
                newRow.querySelector('.buy').innerText = 
                 final.buy;
                newRow.querySelector('.sell').innerText = 
                 final.sell;
                tableBody.appendChild(newRow);
            }
        }
    }
}
```

通过上面的例子，我们创建了一个任何具有相同域的页面都可以使用的共享缓存。虽然有一些优化（我们可以将数据存储为地图，并将 ID 作为键），但我们仍然会比潜在地等待数据库连接要快一些（特别是当我们在带宽有限的地方时）。

# 总结

整个章节都集中在将任务从主线程转移到其他工作线程上。我们看了只有单个页面才有的专用工作线程。然后我们看了如何在多个工作线程之间广播消息，而不必循环遍历各自的端口。

然后我们看到了如何在同一域上利用`SharedWorker`共享工作线程，还看了如何利用`SharedArrayBuffer`共享数据源。最后，我们实际看了一下如何创建一个任何人都可以访问的共享缓存。

在下一章中，我们将通过利用`ServiceWorker`将缓存和处理请求的概念推进一步。


# 第十一章：服务工作者-缓存和加速

到目前为止，我们已经看过了专用和共享工作线程，它们帮助将计算密集型任务放入后台。我们甚至创建了一个使用`SharedWorker`的共享缓存。现在，我们将看一下服务工作者，并学习它们如何用于为我们缓存资源（如 HTML、CSS、JavaScript 等）和数据，以便我们不必进行昂贵的往返到服务器。

在本章中，我们将涵盖以下主题：

+   了解 ServiceWorker

+   为离线使用缓存页面和模板

+   保存请求以备后用

到本章结束时，我们将能够为我们的 Web 应用程序创建离线体验。

# 技术要求

对于本章，您将需要以下内容：

+   一个编辑器或 IDE，最好是 VS Code

+   谷歌浏览器

+   可以运行 Node.js 的环境

+   本章的代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter11`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter11)找到。

# 了解 ServiceWorker

`ServiceWorker`是一个位于我们的 Web 应用程序和服务器之间的代理。它捕获所做的请求并检查是否有与之匹配的模式。如果有模式匹配，则它将运行与该模式匹配的代码。为`ServiceWorker`编写代码与我们之前查看的`SharedWorker`和`DedicatedWorker`有些不同。最初，我们在一些代码中设置它并下载自身。我们有各种事件告诉我们工作线程所处的阶段。这些按以下顺序运行：

1.  **下载**：`ServiceWorker`正在为其托管的域或子域下载自身。

1.  **安装**：`ServiceWorker`正在附加到其托管的域或子域。

1.  **激活**：`ServiceWorker`已完全附加并加载以拦截请求。

安装事件尤其重要。这是我们可以监听更新的`ServiceWorker`的地方。假设我们想要为我们的`ServiceWorker`推送新代码。如果用户仍在我们决定将该代码推送到服务器时的页面上，他们仍将使用旧的工作线程。有办法终止旧的工作线程并强制它们更新（我们稍后会看到），但它仍将使用旧缓存。

此外，如果我们正在使用缓存来存储被请求的资源，它们将存储在旧缓存中。如果我们要更新这些资源，那么我们要确保清除先前的缓存并开始使用新的缓存。稍后我们将看一个例子，但最好提前了解这一点。

最后，服务工作者将每隔 24 小时更新一次自身，因此如果我们不强制用户更新`ServiceWorker`，他们将在 24 小时时获得这个新副本。这些都是我们在本章示例中要牢记的想法。我们在写出它们时会提醒您。

让我们从一个非常基本的例子开始。按照以下步骤进行：

1.  首先，我们需要一个静态服务器，以便我们可以使用服务工作者。为此，请运行`npm install serve`并将以下代码添加到`app.js`文件：

```js
const handler = require('serve-handler');
const http = require('http');
const server = http.createServer((req, res) => {
    return handler(req, res, {
        public : 'source'
    });
});
server.listen(3000, () => {
    console.log('listening at 3000');
});
```

1.  现在，我们可以从`source`目录中提供所有内容。创建一个基本的 HTML 页面，并让它加载一个名为`BaseServiceWorker.js`的`ServiceWorker`：

```js
<!DOCTYPE html>
<html>
    <head>
        <!-- get some resources -->
    </head>
    <body>
        <script type="text/javascript">
              navigator.serviceWorker.register('./BaseServiceWorker.js', 
             { scope : '/'})
            .then((reg) => {
                console.log('successfully registered worker');
            }).catch((err) => {
                console.error('there seems to be an issue!');
            })
        </script>
    </body>
</html>
```

1.  创建一个基本的`ServiceWorker`，每当发出请求时都会记录到我们的控制台：

```js
self.addEventListener('install', (event) => {
    console.log('we are installed!');
});
self.addEventListener('fetch', (event) => {
    console.log('a request was made!');
    fetch(event.request);
});
```

我们应该在控制台中看到两条消息。一条应该是静态的，说明我们已经正确安装了所有内容，而另一条将说明我们已成功注册了一个工作线程！现在，让我们向我们的 HTML 添加一个 CSS 文件并对其进行服务。

1.  将我们的新 CSS 文件命名为`main.css`并添加以下 CSS：

```js
*, :root {
    margin : 0;
    padding : 0;
    font-size : 12px;
}
```

1.  将此 CSS 文件添加到我们的 HTML 页面的顶部。

有了这个，重新加载页面并查看控制台中显示的内容。注意它没有说明我们已成功发出请求。如果我们不断点击重新加载按钮，可能会在页面重新加载之前看到消息出现。如果我们想看到这条消息，我们可以在 Chrome 中转到以下链接并检查那里的`ServiceWorker`：`chrome://serviceworker-internals`。

我们可能会看到其他服务工作者被加载。很多网站都这样做，这是一种缓存网页的技术。我们将很快更详细地研究这个问题。这就是为什么对于一些应用程序来说，第一次加载可能会很痛苦，而之后它们似乎加载得更快的原因。

页面顶部应该显示一个选项，用于在启动`ServiceWorker`时启动开发工具。请检查此选项。然后，停止/启动工作线程。现在，将打开一个控制台，允许我们调试我们的`ServiceWorker`：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/dcee480a-892e-4485-aca2-9ca2cf3dddd3.png)

虽然这对调试很有用，但如果我们看一下启动此行为的页面，我们会看到一个小窗口，其中显示类似以下内容的信息：

```js
Console: {"lineNumber":2,"message":"we are installed!","message_level":1,"sourceIdentifier":3,"sourceURL":"http://localhost:3000/BaseServiceWorker.js"}
```

每次重新加载页面时都会获取 CSS 文件！如果我们再重新加载几次，应该会有更多这样的消息。这很有趣，但我们肯定可以做得更好。让我们继续缓存我们的`main.css`文件。将以下内容添加到我们的`BaseServiceWorker.js`文件中：

```js
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open('v1').then((cache) => {
            return cache.addAll([
                './main.css'
            ]);
        }).then(() => {
            console.log('we are ready!');
        })
    );
});
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    )
});
```

有了这个，我们引入了一个缓存。这个缓存将为我们获取各种资源。除了这个缓存，我们还引入了事件的`waitUntil`方法。这允许我们延迟`ServiceWorker`的初始化，直到我们从服务器获取了所有想要的数据。在我们的 fetch 处理程序中，我们现在正在检查我们的缓存中是否有资源。如果有，我们将提供该文件；否则，我们将代表页面发出 fetch 请求。

现在，如果我们加载页面，我们会注意到我们只有`we are ready`消息。尽管我们有新的代码，但页面被 Chrome 缓存了，所以它没有放弃我们的旧服务工作者。为了强制添加新的服务工作者，我们可以进入开发者控制台，转到应用程序选项卡。然后，我们可以转到左侧面板，转到`ServiceWorker`部分。应该有一个时间轴，说明有一个`ServiceWorker`正在等待被激活。如果我们点击旁边的文字，说 skipWaiting，我们可以激活新代码。

请点击此选项。看起来好像没有发生任何事情，但是如果我们返回到`chrome://serviceworker-internals`页面，我们会看到有一条消息。如果我们继续重新加载页面，我们会看到我们只有一条消息。这意味着我们已经加载了我们的新代码！

另一种检查我们是否成功缓存了`main.css`文件的方法是限制应用程序的下载速度（特别是因为我们是在本地托管）。返回开发人员工具，点击网络选项卡。在禁用缓存选项附近应该有一个网络速度的下拉菜单。目前，它应该显示我们在线。请将其切换到离线状态：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/15280a71-55c0-412f-9146-916062274e3b.png)

好吧，我们刚刚丢失了我们的页面！在`BaseServiceWorker.js`中，我们应该添加以下内容：

```js
caches.open('v1').then((cache) => {
    return cache.addAll([
        './main.css',
        '/'
    ]);
})
```

现在，我们可以再次将我们的应用程序上线，并让这个新的`ServiceWorker`添加到页面中。添加完成后，将我们的应用程序切换到离线状态。现在，页面可以离线工作！我们将稍后更详细地探讨这个想法，但这给了我们一个很好的预览。

通过这简单的`ServiceWorker`和缓存机制的观察，让我们把注意力转向缓存页面并在`ServiceWorker`中添加一些模板功能。

# 为离线使用缓存页面和模板

正如我们在本章开头所述，Service Worker 的主要用途之一是缓存页面资源以供将来使用。我们在第一个简单的`ServiceWorker`中看到了这一点，但我们应该设置一个更复杂的页面，其中包含更多资源。按照以下步骤进行：

1.  创建一个名为`CacheServiceWorker.js`的全新`ServiceWorker`，并将以下模板代码添加到其中。这是大多数`ServiceWorker`实例将使用的代码：

```js
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open('v1').then((cache) => {
            return cache.addAll([
                // add resources here
            ]);
        }).then(() => {
            console.log('we are ready!');
        })
    );
});
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    )
});
```

1.  更新我们的`index.html`文件，以利用这个新的`ServiceWorker`：

```js
navigator.serviceWorker.register('./CacheServiceWorker.js', { scope : '/'})
    .then((reg) => {
        console.log('successfully registered worker');
    }).catch((err) => {
        console.error('there seems to be an issue!', err);
    })
```

1.  现在，让我们在我们的页面上添加一些按钮和表格。我们很快将利用这些：

```js
<button id="addRow">Add</button>
<button id="remove">Remove</button>
<table>
    <thead>
        <tr>
            <th>Id</th>
            <th>Name</th>
            <th>Description</th>
            <th>Points</th>
        </tr>
    </thead>
    <tbody id="tablebody">
    </tbody>
</table>
```

1.  添加一个 JavaScript 文件，用于处理我们与`interactions.js`页面的所有交互：

```js
const add = document.querySelector('#addRow');
const remove = document.querySelector('#remove');
const tableBody = document.querySelector('#tablebody');
add.addEventListener('click', (ev) => {
    fetch('/add').then((res) => res.json()).then((fin) =>
     tableBody.appendChild(fin));
});
remove.addEventListener('click', (ev) => {
    while(tableBody.firstChild) {
        tableBody.removeChild(tableBody.firstChild);
    }
});
```

1.  将 JavaScript 文件添加到我们的`ServiceWorker`作为预加载：

```js
caches.open('v1').then((cache) => {
    return cache.addAll([
        '/',
        './interactions.js',
        './main.css'
    ]);
}).then(() => {
    console.log('we are ready!');
})
```

1.  将 JavaScript 文件添加到我们的`index.html`文件的底部：

```js
<script src="interactions.js" type="text/javascript"></script>
```

现在，如果我们加载我们的页面，我们应该看到一个简单的表格坐在那里，有一个标题行和一些按钮。让我们继续向我们的页面添加一些基本样式，以使它更容易看到。将以下内容添加到我们在处理`BaseServiceWorker`时添加的`main.css`文件中：

```js
table {
    margin: 15px;
    border : 1px solid black;
}
th {
    border : 1px solid black;
    padding : 2px;
}
button {
    border : 1px solid black;
    padding :5px;
    background : #2e2e2e;
    color : #cfcfcf;
    cursor : pointer;
    margin-left : 15px;
    margin-top : 15px;
}
```

这个 CSS 为我们提供了一些基本的样式。现在，如果我们点击“添加”按钮，我们应该看到以下消息：

```js
The FetchEvent for "http://localhost:3000/add" resulted in a network error response: the promise was rejected.
```

由于我们还没有添加任何代码来处理这个问题，让我们继续在我们的`ServiceWorker`中拦截这条消息。按照以下步骤进行：

1.  将以下虚拟代码添加到我们的`ServiceWorker`的`fetch`事件处理程序中：

```js
event.respondWith(
    caches.match(event.request).then((response) => {
        if( response ) {
            return response
        } else {
            if( event.request.url.includes("/add") ) {
                return new Response(new Blob(["Here is some data"], 
                    { type : 'text/plain'}),
                    { status : 200 });
            }
            fetch(event.request);
        }
    })
)
```

1.  点击“添加”按钮。我们应该看到一个新的错误，说明它无法解析 JSON 消息。将`Blob`数据更改为一些 JSON：

```js
return new Response(new Blob([JSON.stringify({test : 'example', stuff : 'other'})], { type : 'application/json'}), { status : 200 });
```

1.  再次点击“添加”按钮。我们应该得到一个声明，说明我们刚刚传递给处理程序的内容不是`Node`类型。解析我们在“添加”按钮的点击处理程序中得到的数据：

```js
fetch('/add').then((res) => res.json()).then((fin) =>  {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${fin.test}</td>
                    <td>${fin.stuff}</td>
                    <td>other</td>`;
    tableBody.appendChild(tr);
});
```

现在，如果我们尝试运行我们的代码，我们会看到一些有趣的东西：我们的 JavaScript 文件仍然是旧代码。`ServiceWorker`正在使用我们以前的旧缓存。在这里我们可以做两件事。首先，我们可以禁用`ServiceWorker`。或者，我们可以删除旧缓存并用新缓存替换它。我们将执行第二个选项。为此，我们需要在安装监听器中添加以下代码到我们的`ServiceWorker`中：

```js
event.waitUntil(
    caches.delete('v1').then(() => {
        caches.open('v1').then((cache) => {
            return cache.addAll([
                '/',
                './interactions.js',
                './main.css'
            ]);
        }).then(() => {
            console.log('we are ready!');
        });
    })
);
```

现在，我们可以在前端代码中加载模板，但我们将在这里模拟一个服务器端渲染系统。这有一些应用场景，但我想到的主要应用场景是我们在开发中尝试的模板系统。

大多数模板系统需要在我们使用它们之前编译成最终的 HTML 形式。我们可以设置一个*watch*类型的系统，在这个系统中，每当我们更新模板时，这些模板都会被重新加载，但这可能会变得繁琐，特别是当我们只想专注于前端时。另一种方法是将这些模板加载到我们的`ServiceWorker`中，并让它渲染它们。这样，当我们想要进行更新时，我们只需通过`caches.delete`方法删除我们的缓存，然后重新加载它。

让我们设置一个简单的示例，就像前面的示例一样，但模板不是在我们的前端代码中创建的，而是在我们的`ServiceWorker`中。按照以下步骤进行：

1.  创建一个名为`row.template`的模板文件，并用以下代码填充它：

```js
<td>${id}</td>
<td>${name}</td>
<td>${description}</td>
<td>${points}</td>
```

1.  删除我们的`interactions.js`中的模板代码，并用以下代码替换它：

```js
fetch('/add').then((res) => res.text()).then((fin) =>  {
    const row = document.createElement('tr');
    row.innerHTML = fin;
    tableBody.appendChild(row);
});
```

1.  让我们设置一些基本的模板代码。我们不会做任何接近第九章中所做的实际示例-构建静态服务器。相反，我们将循环遍历我们传递的对象，并填写我们的模板的部分，其中我们的键在对象中对应：

```js
const renderTemplate = function(template, obj) {
    const regex = /\${([a-zA-Z0-9]+)\}/;
    const keys = Object.keys(obj);
    let match = null;
    while(match = regex.exec(template)) {
        const key = match[1];
        if( keys.includes(key) ) {
            template = template.replace(match[0], obj[key]);
        } else {
            match = null;
        }
    }
    return template;
}
```

1.  将响应更改为`/add`端点，使用以下代码：

```js
if( event.request.url.includes('/add') ) {
    return fetch('./row.template')
        .then((res) => res.text())
        .then((template) => {
            return new Response(new Blob([renderTemplate(template, 
             add)],{type : 'text/html'}), {status : 200});   
        })
} else if( response ) {
    return response
} else {
    return fetch(event.request);
}
```

现在，我们将从服务器中获取我们想要的模板（在我们的情况下是`row.template`文件），并用我们拥有的任何数据填充它（同样，在我们的情况下，我们将使用存根数据）。现在，我们在`ServiceWorker`中有了模板，并且可以轻松地设置端点以通过这个模板系统。

当我们想要个性化网站的错误页面时，这也可能是有益的。如果我们想要在我们的 404 页面中出现一个随机图像并将其合并到页面中，我们可以在`ServiceWorker`中完成，而不是访问服务器。我们甚至可以在离线状态下这样做。我们只需要实现与此处相同类型的模板化。

有了这些概念，很容易看到我们在拦截请求时的能力以及我们如何使我们的 Web 应用程序在离线时工作。我们将学习的最后一个技术是在离线时存储我们的请求，并在重新联机时运行它们。这种类型的技术可以用于从浏览器中保存或加载文件。让我们来看看。

# 保存请求以便以后使用

到目前为止，我们已经学会了如何拦截请求并从我们的本地系统返回或甚至增强响应。现在，我们将学习如何在离线模式下保存请求，然后在联机时将调用发送到服务器。

让我们继续为此设置一个新的文件夹。按照以下步骤进行：

1.  创建一个名为`offline_storage`的文件夹，并向其中添加以下文件：

+   `index.html`

+   `main.css`

+   `interactions.js`

+   `OfflineServiceWorker.js`

1.  将以下样板代码添加到`index.html`中：

```js
<!DOCTYPE html>
<html>
    <head><!-- add css file --></head>
    <body>
        <h1>Offline Storage</h1>
        <button id="makeRequest">Request</button>
        <table>
            <tbody id="body"></tbody>
        </table>
        <p>Are we online?: <span id="online">No</span>
        <script src="interactions.js"></script>
        <script>
            let online = false;
            const onlineNotification =  
             document.querySelector('#online');
            window.addEventListener('load', function() {
                const changeOnlineNotification = function(status) {
                    onlineNotification.textContent = status ? "Yes" 
                     : "No";
                    online = status;
                }
                changeOnlineNotification(navigator.onLine);
                 navigator.serviceWorker.register('.
                 /OfflineCacheWorker.js', {scope : '/'})
                window.addEventListener('online', () => {
                 changeOnlineNotification(navigator.onLine) });
                window.addEventListener('offline', () => {
                 changeOnlineNotification(navigator.onLine) });
            });
        </script>
    </body>
</html>
```

1.  将以下样板代码添加到`OfflineServiceWorker.js`中：

```js
self.addEventListener('install', (event) => {
    event.waitUntil(   
     // normal cache opening
    );
});
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            // normal response handling
        })
    )
});
```

1.  最后，将以下样板代码添加到`interactions.js`中：

```js
const requestMaker = document.querySelector('#makeRequest');
const tableBody = document.querySelector('#body');
requestMaker.addEventListener('click', (ev) => {
    fetch('/request').then((res) => res.json()).then((fin) => {
        const row = document.createElement('tr');
        row.innerHTML = `
        <td>${fin.id}</td>
        <td>${fin.name}</td>
        <td>${fin.phone}</td>
        <td><button id=${fin.id}>Delete</button></td>
        `
        row.querySelector('button').addEventListener('click', (ev) 
         => {
            fetch(`/delete/${ev.target.id}`).then(() => {
                tableBody.removeChild(row);
            });
        });
        tableBody.appendChild(row);
    })
})
```

将所有这些代码放在一起后，让我们继续更改我们的 Node.js 服务器，使其指向这个新的文件夹位置。我们将通过停止旧服务器并更改`app.js`文件，使其指向我们的`offline_storage`文件夹来实现这一点：

```js
const server = http.createServer((req, res) => {
    return handler(req, res, {
        public : 'offline_storage'
    });
});
```

有了这个，我们可以通过运行`node app.js`重新运行我们的服务器。我们可能会看到我们的旧页面出现。如果是这种情况，我们可以转到开发者工具中的“应用程序”选项卡，并在“服务工作者”部分下点击“注销”选项。重新加载页面后，我们应该看到新的`index.html`页面出现。我们的处理程序目前不起作用，所以让我们在`ServiceWorker`中添加一些存根代码，以处理我们在`interactions.js`中添加的两种 fetch 情况。按照以下步骤进行：

1.  在 fetch 事件处理程序中添加以下支持：

```js
caches.match(event.request).then((response) => {
    if( event.request.url.includes('/request') ) {
        return handleRequest();
    }
})
// below in the global scope of the ServiceWorker
let counter = 0;
let name = 65;
const handleRequest = function() {
    const data = {
        id : counter,
        name : String.fromCharCode(name),
        phone : Math.round(Math.random() * 10000)
    }
    counter += 1;
    name += 1;
    return new Response(new Blob([JSON.stringify(data)], {type : 
     'application/json'}), {status : 200});
}
```

1.  通过确保它正确处理响应，确保它向我们的表中添加一行。重新加载页面并确保在单击请求按钮时添加了新行：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/1636a18d-88bd-4817-8bf2-a68b8cb20cc5.png)

1.  现在我们已经确保该处理程序正在工作，让我们继续为我们的删除请求添加另一个处理程序。我们将在我们的`ServiceWorker`中模拟服务器上的数据库删除：

```js
caches.match(event.request).then((response) => {
    if( event.request.url.includes('/delete') ) {
        return handleDelete(event.request.url);
    }
})
// place in the global scope of the Service Worker
const handleDelete = function(url) {
    const id = url.split("/")[2];
    return new Response(new Blob([id], {type : 'text/plain'}), 
     {status : 200});
}
```

1.  有了这个，让我们继续测试一下，确保我们点击删除按钮时行被删除。如果所有这些都有效，我们将拥有一个可以在线或离线工作的功能应用程序。

现在，我们所需要做的就是为即将发出但由于我们目前处于离线状态而无法发出的请求添加支持。为此，我们将在一个数组中存储请求，并一旦在我们的`ServiceWorker`中检测到我们重新联机，我们将发送所有请求。我们还将添加一些支持，让我们的前端知道我们正在等待这么多请求，如果需要，我们可以取消它们。现在让我们添加这个：

在 Chrome 中，从离线切换到在线会触发我们的**在线**处理程序，但从在线切换到离线似乎不会触发事件。我们可以测试离线到在线系统的功能，但测试另一种情况可能会更加困难。请注意，这种限制可能存在于许多开发系统中，试图解决这个问题可能会非常困难。

1.  首先，将我们大部分的`caches.match`代码移动到一个独立的函数中，如下所示：

```js
caches.match(event.request).then((response) => {
    if( response ) {
        return response
    }
    return actualRequestHandler(event);
})
```

1.  编写独立的函数，如下所示：

```js
const actualRequestHandler = function(req) {
    if( req.request.url.includes('/request') ) {
        return handleRequest();
    }
    if( req.request.url.includes('/delete') ) {
        return handleDelete(req.request.url);
    }
    return fetch(req.request);
}
```

1.  我们将通过轮询处理请求，以查看我们是否重新联机。设置一个每 30 秒工作一次的轮询计时器，并将我们的`caches.match`处理程序更改如下：

```js
const pollTime = 30000;
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            if( response ) {
                return response
            }
            if(!navigator.onLine ) {
                return new Promise((resolve, reject) => {
                    const interval = setInterval(() => {
                        if( navigator.onLine ) {
                            clearInterval(interval);
                            resolve(actualRequestHandler(event));
                        }
                    }, pollTime)
                })
            } else {
                return actualRequestHandler(event);
            }
        })
    )
});
```

我们刚刚做的是为一个 promise 设置了一个返回。如果我们看不到系统在线，我们将每 30 秒轮询一次，以查看我们是否重新联机。一旦我们重新联机，我们的 promise 将清除间隔，并在 resolve 处理程序中实际处理请求。我们可以设置一个在取消请求之前尝试多少次的系统。我们只需要在间隔之后添加一个拒绝处理程序。

最后，我们将添加一种方法来停止当前所有未处理的请求。为此，我们需要一种方法来跟踪我们是否有未处理的请求，并且一种在`ServiceWorker`中中止它们的方法。这将非常简单，因为我们可以很容易地在前端跟踪仍在等待的内容。我们可以通过以下方式添加这个功能：

1.  首先，我们将添加一个显示，显示前端有多少未处理的请求。我们将把这个显示放在我们的在线状态系统之后：

```js
// inside of our index.html
<p>Oustanding requests: <span id="outstanding">0</span></p>

//inside our interactions.js
const requestAmount = document.querySelector('#outstanding');
let numRequests = 0;
requestMaker.addEventListener('click', (ev) => {
    numRequests += 1;
    requestAmount.textContent = numRequests;
    fetch('/request').then((res) => res.json()).then((fin) => {
        // our previous fetch handler
        numRequests -= 1;
        requestAmount.textContent = numRequests;
    });
    // can be setup for delete requests also
});
```

1.  在我们的`index.html`文件中添加一个按钮，用于取消所有未处理的请求。同时，在我们的`interactions.js`文件中添加相应的 JavaScript 代码：

```js
//index.html
<button id="stop">Stop all Pending</button>

//interactions.js
const stopRequests = document.querySelector('#stop');
stopRequests.addEventListener('click', (ev) => {   
    fetch('/stop').then((res) => {
        numRequests = 0;
        requestAmount.textContent = numRequests;
    });
});
```

1.  为停止请求添加相应的处理程序到我们的`ServiceWorker`：

```js
caches.match(event.request).then((response) => {
    if( response ) {
        return response
    }
    if( event.request.url.includes('/stop') ) {
        controller.abort();
        return new Response(new Blob(["all done"], {type :
        'text/plain'}), {status : 200});
    }
    // our previous handler code
})
```

现在，我们将利用一个叫做`AbortController`的东西。这个系统允许我们向诸如 fetch 请求之类的东西发送信号，以便我们可以说我们想要停止等待的请求。虽然这个系统主要用于停止 fetch 请求，但实际上我们可以利用这个信号来停止任何异步请求。我们通过创建一个`AbortController`并从中获取信号来实现这一点。然后，在我们的 promise 中，我们监听信号上的中止事件并拒绝 promise。

1.  添加`AbortController`，如下所示：

```js
const controller = new AbortController();
const signal = controller.signal;
const pollTime = 30000;
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            if( response ) {
                return response
            }
            if( event.request.url.includes('/stop') ) {
                controller.abort();
                return new Response(new Blob(["all done"], {type :
                'text/plain'}), {status : 200});
            }
            if(!navigator.onLine ) {
                return new Promise((resolve, reject) => {
                    const interval = setInterval(() => {
                        if( navigator.onLine ) {
                            clearInterval(interval);
                            resolve(actualRequestHandler(event));
                        }
                    }, pollTime)
                    signal.addEventListener('abort', () => {
                        reject('aborted');
                    })
                });
            } else {
                return actualRequestHandler(event);
            }
        })
    )
});
```

现在，如果我们进入我们的系统，在离线模式下准备一些请求，然后点击取消按钮，我们会看到所有的请求都被取消了！我们本可以把`AbortController`放在我们前端的`interactions.js`文件中的 fetch 请求上，但一旦我们恢复在线，所有的 promise 仍然会运行，所以我们想确保没有任何东西在运行。这就是为什么我们把它放在`ServiceWorker`中的原因。

通过这样做，我们不仅看到了我们可以通过缓存数据来处理请求，还看到了当我们处于不稳定的位置时，我们可以存储这些请求。除此之外，我们还看到了我们可以利用`AbortController`来停止等待的 promise 以及如何利用它们除了停止 fetch 请求之外的其他用途。

# 总结

在本章中，我们了解了服务工作者如何将我们的应用程序从始终在线转变为我们可以创建真正*始终工作*的应用程序的系统。通过保存状态、本地处理请求、本地丰富请求，甚至保存离线使用的请求，我们能够处理我们应用程序的完整状态。

现在我们已经从客户端和服务器端使用 JavaScript 创建了丰富的 Web 应用程序，我们将开始研究一些高级技术，这些技术可以帮助我们创建高性能的应用程序，这些应用程序以前只能通过本机应用程序代码实现。我们可以通过使用 C、C++或 Rust 来实现这一点。

然而，在我们讨论这个之前，一个经常被应用开发者忽视的应用开发的部分是部署过程。在下一章中，我们将介绍一种通过一个流行系统叫做 CircleCI 来建立持续集成和持续开发（CI/CD）的方法。


# 第十二章：构建和部署完整的 Web 应用程序

现在我们已经看到了 JavaScript 的服务器端和客户端代码，我们需要专注于另一个完全不同的问题；也就是说，构建我们的代码以进行部署，并将该代码部署到服务器上。

虽然我们在本地运行了我们的服务器，但我们从未在云环境中运行过，比如亚马逊的 AWS 或微软的 Azure。今天的部署不再像 5 年前那样。以前，我们可以通过**文件传输协议**（**FTP**）将我们的应用程序移动到服务器上。现在，即使对于小型应用程序，我们也使用持续部署系统。

在本章中，我们将探讨以下主题：

+   了解 Rollup

+   集成到 CircleCI

这些主题将使我们能够在典型的开发环境中开发几乎任何应用程序并将其部署。到本章结束时，我们将能够为 Web 应用程序实现典型的构建和部署环境。

让我们开始吧。

# 技术要求

对于本章，您将需要以下内容：

+   能够运行 Node.js 的机器

+   一个文本编辑器或 IDE，最好是 VS Code

+   一个 Web 浏览器

+   GitHub 的用户帐户

+   本章的代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter12`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter12)找到。

# 了解 Rollup

RollupJS 是一个构建工具，它允许我们根据环境的不同方式准备我们的应用程序。在它之前有许多工具（Grunt、Gulp），许多工具正在与它竞争（Webpack、Parcel），并且将来还会有许多工具。我们将专注于 RollupJS 用于我们的特定用例（在第九章中构建我们的静态服务器应用程序的实际示例），但请注意，大多数构建工具在其架构方面是相似的。

RollupJS 给我们的是一种在构建生命周期的不同部分具有*钩子*的方式。大多数应用程序在构建过程中具有以下状态：

+   构建开始

+   依赖注入

+   编译

+   编译后

+   构建结束

这些状态在不同的构建系统中可能有不同的名称，并且有些甚至可能不止这些（正如我们将看到的，RollupJS 有），但这是典型的构建系统。

在大多数情况下，我们需要为我们的 JavaScript 应用程序做以下事情：

+   引入我们的 Node/browser 端需要的任何依赖项

+   将我们的 JavaScript 编译为单个文件（如果针对 HTTP/1）或将其编译为较早版本（如果我们针对更广泛的浏览器支持）

+   将 CSS 编译为单个文件，移动图片等

对于我们的应用程序来说，这将非常容易。在这里，我们将学习如何做以下事情：

+   将我们的 Node.js 代码构建成一个单一的可分发文件

+   准备我们的静态资产，如 CSS/图片

+   将 Rollup 添加到我们的 npm 构建流程中

# 将我们的静态服务器构建成一个单一的可分发文件

首先，我们需要创建一个我们准备好使用的文件夹。为此，可以在我们在第九章中工作的文件夹中工作，*实际示例-构建静态服务器*，或者从本书的 GitHub 存储库中拉取代码。然后运行`npm install -g rollup`命令。这将把 rollup 系统放入我们的全局路径，以便我们可以通过运行`rollup`命令来使用命令行。接下来，我们将创建一个配置文件。为此，我们将在我们的目录的基础（与我们的`package.json`文件的确切位置相同）中添加一个`rollup.config.js`文件，并将以下代码添加到其中：

```js
module.exports = {
    input: "./main.js",
    output: {
        file: "./dist/build.js",
        format: "esm"
    }
}
```

我们已经告诉 Rollup 我们应用程序的起点在`main.js`文件中。Rollup 将遵循这个起点并运行它以查看它依赖于什么。它依赖于什么，它将尝试将其放入一个单一的文件中，并在此过程中删除任何不需要的依赖项（这称为 tree-shaking）。完成后，它将文件放在`dist/build.js`中。

如果我们尝试运行这个，我们会遇到一个问题。在这里，我们正在为类使用私有变量，而 Rollup 不支持这一点，以及我们正在使用的 ESNext 的其他特性。我们还需要更改任何在函数外设置成员变量的地方。这意味着我们需要将`cache.js`更改为以下内容：

```js
export default class LRUCache {
    constructor(num=10) {
        this.numEntries = num;
        this.cache = new Map();
    }
}
```

我们还需要替换`template.js`中的所有构造函数，就像我们在`LRUCache`中所做的那样。

在进行了上述更改后，我们应该看到`rollup`对我们感到满意，并且现在正在编译。如果我们进入`dist/build.js`文件，我们将看到它将所有文件放在一起。让我们继续在我们的配置文件中添加另一个选项。按照以下步骤进行：

1.  运行以下命令将最小化器和代码混淆器插件添加到 Rollup 作为开发依赖项：

```js
> npm install -D rollup-plugin-terser
```

1.  安装了这个之后，将以下行添加到我们的`config.js`文件中：

```js
import { terser } from 'rollup-plugin-terser';
module.exports = {
    input: "./main.js",
    output: {
        file: "./dist/build.js",
        format: "esm",
        plugins: [terser()]
    }
}
```

现在，如果我们查看我们的`dist/build.js`文件，我们将看到一个几乎不可见的文件。这就是我们的应用程序的 Rollup 配置所需的全部内容，但还有许多其他配置选项和插件可以帮助编译过程。接下来，我们将看一些可以帮助我们将 CSS 文件放入更小格式的选项，并查看如果我们使用 Sass 会发生什么以及如何将其与 Rollup 编译。

# 将其他文件类型添加到我们的分发

目前，我们只打包我们的 JavaScript 文件，但大多数应用程序开发人员知道任何前端工作也需要打包。例如，以 Sass ([`sass-lang.com/`](https://sass-lang.com/))为例。它允许我们以一种最大程度地实现可重用性的方式编写 CSS。

让我们继续将我们为这个项目准备的 CSS 转换为 Sass 文件。按照以下步骤进行：

1.  创建一个名为`stylesheets`的新文件夹，并将`main.scss`添加到其中。

1.  将以下代码添加到我们的 Sass 文件中：

```js
$main-color: "#003A21";
$text-color: "#efefef";
/* header styles */
header {
    // removed for brevity
    background : $main-color;
    color      : $text-color;
    h1 {
        float : left;
    }
    nav {
        float : right;
    }
}
/* Footer styles */
footer {
    // removed for brevity
    h2 {
        float : left;
    }
    a {
        float : right;
    }
}
```

前面的代码展示了 Sass 的两个特性，使其更容易使用：

+   它允许我们嵌套样式。我们不再需要单独的`footer`和`h2`部分，我们可以将它们嵌套在一起。

+   它允许使用变量（是的，在 CSS 中我们有它们）。

随着 HTTP/2 的出现，一些文件捆绑的标准已经被淘汰。诸如雪碧图之类的项目不再建议使用，因为 HTTP/2 标准增加了 TCP 多路复用的概念。下载多个较小的文件可能比下载一个大文件更快。对于那些感兴趣的人，以下链接更详细地解释了这些概念：[`css-tricks.com/musings-on-http2-and-bundling/`](https://css-tricks.com/musings-on-http2-and-bundling/)。

Sass 还有很多内容，不仅仅是在他们的网站上可以找到的，比如 mixin，但在这里，我们想专注于将这些文件转换为我们知道可以在前端使用的 CSS。

现在，我们需要将其转换为 CSS 并将其放入我们的原始文件夹中。为此，我们将在我们的配置中添加`rollup-plugin-sass`。我们可以通过运行`npm install -D rollup-plugin-sass`来实现。添加了这个之后，我们将添加一个名为`rollup.sass.config.js`的新 rollup 配置，并将以下代码添加到其中：

```js
import sass from 'rollup-plugin-sass';
module.exports = {
    input: "./main-sass.js",
    output: {
        file: "./template/css/main.css",
        format: "cjs"
    },
    plugins: [
        sass()
    ]
}
```

一旦我们制作了我们的 rollup 文件，我们将需要创建我们目前拥有的`main-sass.js`文件。让我们继续做到这一点。将以下代码添加到该文件中：

```js
import main_sass from './template/stylesheets/main.scss'
export default main_sass;
```

现在，让我们运行以下命令：

```js
> rollup --config rollup.sass.config.js 
```

通过这样做，我们将看到模板文件夹内的`css`目录已经被填充。通过这样做，我们可以看到我们如何捆绑一切，不仅仅是我们的 JavaScript 文件。现在我们已经将 Rollup 的构建系统集成到了我们的开发流程中，我们将看看如何将 Rollup 集成到 NPM 的构建流程中。

# 将 rollup 引入 Node.js 命令

现在，我们可以只是让一切保持原样，并通过命令行运行我们的 rollup 命令，但是当我们将持续集成引入我们的流程时（接下来），这可能会使事情变得更加困难。此外，我们可能有其他开发人员在同一系统上工作，而不是让他们运行多个命令，他们可以运行一个`npm`命令。相反，我们希望将 rollup 集成到各种 Node.js 脚本中。

我们在第九章中看到了这一点，*实际示例-构建静态服务器*，使用了`microserve`包和`start`命令。但现在，我们想要集成两个新命令，称为`build`和`watch`。

首先，我们希望`build`命令运行我们的 rollup 配置。按照以下步骤来实现这一点：

1.  让我们清理一下我们的主目录，并将我们的 rollup 配置移动到一个构建目录中。

1.  这两个都移动后，我们将在`package.json`文件中添加以下行：

```js
"scripts": {
        "start": "node --experimental-modules main.js",
        "build": "rollup --config ./build/rollup.config.js && rollup --config ./build/rollup.sass.config.js",
}
```

1.  通过这一举措，我们可以运行`npm run build`，并在一个命令中看到所有内容都已构建完成。

其次，我们想要添加一个 watch 命令。这将允许 rollup 监视更改，并立即为我们运行该脚本。我们可以通过将以下行添加到我们的`scripts`部分中，轻松地将其添加到我们的`package.json`中：

```js
"watch": "rollup --config ./build/rollup.config.js --watch"
```

现在，如果我们输入`npm run watch`，它将以监视模式启动 rollup。通过这样做，当我们对 JavaScript 文件进行更改时，我们可以看到 rollup 自动重新构建我们的分发文件。

在我们进入持续集成之前，我们需要做的最后一个改变是将我们的主入口点指向我们的分发文件。为此，我们将更改`package.json`文件中的 start 部分，使其指向`dist/build.js`：

```js
"start": "node --experimental-modules dist/build.js"
```

有了这个，让我们继续检查一下，确保一切仍然正常运行，通过运行`npm run start`。我们会发现一些文件没有指向正确的位置。让我们通过对`package.json`文件进行一些更改来修复这个问题：

```js
"config": {
    "port": 50000,
    "key": "../selfsignedkey.pem",
    "certificate": "../selfsignedcertificate.pem",
    "template": "../template",
    "bodyfiles": "../publish",
    "development": true
}
```

有了这个，我们应该准备好了！Rollup 有很多选项，当我们想要集成到 Node 脚本系统时，甚至还有更多选项，但这应该让我们为本章的下一部分做好准备，即集成到 CI/CD 流水线中。我们选择的系统是 CircleCI。

# 集成到 CircleCI

正如我们之前提到的，过去几十年里，现实世界中的开发发生了巨大的变化。从在本地构建所有内容并从我们的开发机器部署到复杂的编排和依赖部署树，我们已经看到了一系列工具的崛起，这些工具帮助我们快速开发和部署。

我们可以利用的一个例子是 CI/CD 工具，比如 Jenkins、Travis、Bamboo 和 CircleCI。这些工具会触发各种钩子，比如将代码推送到远程存储库并立即运行*构建*。我们将利用 CircleCI 作为我们的选择工具。它易于设置，是一个易于使用的开发工具，为开发人员提供了一个不错的免费层。

在我们的情况下，这个构建将做以下三件事：

1.  拉取所有项目依赖项

1.  运行我们的 Node.js 构建脚本

1.  将这些资源部署到我们的服务器上，我们将在那里运行应用程序

设置所有这些可能是一个相当令人沮丧的经验，但一旦我们的应用程序连接起来，它就是值得的。我们将利用以下技术来帮助我们进行这个过程：

+   CircleCI

+   GitHub

考虑到这一点，我们的第一步将是转到 GitHub 并创建一个个人资料，如果我们还没有这样做。只需转到[`github.com/`](https://github.com/)，然后在右上角查找注册选项。一旦我们这样做了，我们就可以开始创建/分叉存储库。

由于这本书的所有代码都在 GitHub 上，大多数人应该已经有 GitHub 账户并了解如何使用 Git 的基础知识。

对于那些在 Git 上挣扎或尚未使用版本控制系统的人，以下资源可能会有所帮助：[`try.github.io/`](https://try.github.io/)。

现在，我们需要将所有代码都在的存储库分叉到我们自己的存储库中。要做到这一点，请按照以下步骤进行操作：

1.  转到本书的 GitHub 存储库[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript)，并单击右上角的选项，将整个存储库分叉。

如果我们不想这样做，我们可以将存储库克隆到本地计算机。（这可能是更好的选择，因为我们只想要`Chapter12`目录的内容。）

1.  无论我们选择哪种选项，都可以将`Chapter12`目录移动到本地计算机的另一个位置，并将文件夹名称更改为`microserve`。

1.  回到 GitHub，创建一个新的存储库。将其设置为私有存储库。

1.  最后，回到我们的本地机器，并使用以下命令删除已经存在的`.git`文件：

```js
> rf -rf .git
```

对于使用 Windows 的人，如果你有 Windows 10 Linux 子系统，可以运行这些命令。或者，你可以下载 Cmder 工具：[`cmder.net/`](https://cmder.net/)。

1.  运行以下命令，将本地系统连接到远程 GitHub 存储库：

```js
> git init
> git add .
> git commit -m "first commit"
> git remote add origin 
  https://github.com/<your_username>/<the_repository>.git
> git push -u origin master
```

1.  命令行将要求输入一些凭据。使用我们设置个人资料时的凭据。

我们的本地文件应该已经连接到 GitHub。现在我们需要做的就是用 CircleCI 设置这个系统。为此，我们需要在 CircleCI 的网站上创建一个账户。

1.  转到[`circleci.com/`](https://circleci.com/)，点击“注册”，然后使用 GitHub 注册。

一旦我们的账户连接上了，我们就可以登录。我们应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/16773d81-f2e9-4221-98b0-5371f74af673.png)

1.  点击“设置项目”以设置我们刚刚设置的存储库。

它应该会检测到我们的存储库中已经有一个 CircleCI 文件，但如果我们愿意，我们也可以从头开始。接下来的指示将是为了从头开始设置 CircleCI。为此，我们可以利用他们提供的 Node.js 模板。然而，我们主要需要做的是在`.circleci`目录中创建`config.yml`文件。我们应该有一个基本的东西，看起来像这样：

```js
version: 2
jobs:
  build:
    docker:
      - image: circleci/node:12.13
    working_directory: ~/repo
    steps:
      - checkout
      - restore_cache:
          keys:
            - v1-dependencies-{{ checksum "package.json" }}
            - v1-dependencies-
      - run: npm install
      - save_cache:
          paths:
            - node_modules
          key: v1-dependencies-{{ checksum "package.json" }}
```

CircleCI 配置文件的执行方式如下：

1.  我们声明要使用 Docker 中的`circleci/node:12.13`镜像

我们不会在这里讨论 Docker，但这是许多公司用来部署和托管应用程序的另一种技术。有关这项技术的更多信息可以在这里找到：[`docs.docker.com/`](https://docs.docker.com/)。

1.  我们希望在`~/repo`中运行所有命令。这将是我们几乎所有基本项目的情况。

1.  接下来，我们将该存储库检入到`~/repo`中。

1.  现在，如果我们还没有为这个存储库设置缓存，我们需要设置一个。这样可以确保我们只在需要时才拉取存储库。

1.  我们需要运行`npm install`命令来拉取所有的依赖项。

1.  最后，我们保存缓存。

这个过程被称为持续集成，因为当我们推送代码时，它会不断地为我们运行构建。如果我们想要，我们可以在 CircleCI 配置文件中添加不同的设置，但这超出了本书的范围。当构建完成时，我们还会通过电子邮件收到通知。如果需要，我们可以在以下位置进行调整：[`circleci.com/gh/organizations/<your_user>/settings`](https://circleci.com/gh/organizations/%3cyour_user%3e/settings)。

有了这个，我们已经创建了一个基本的 CircleCI 文件！现在，如果我们转到我们的仪表板，一旦我们推送这个 CircleCI 配置，它应该运行一个构建。它还应该显示我们之前列出的所有步骤。太棒了！现在，让我们连接我们的构建过程，这样我们就可以真正地使用我们的 CI 系统。

# 添加我们的构建步骤

通过我们的 CircleCI 配置，我们可以在流程中添加许多步骤，甚至添加称为 orbs 的东西。Orbs 本质上是预定义的包和命令，可以增强我们的构建过程。在本节中，我们将添加由 Snyk 发布的一个 orb：[`snyk.io/`](https://snyk.io/)。这将扫描并查找当前在 npm 生态系统中存在的不良包。我们将在设置构建后添加这个。

为了让我们的构建运行并打包成我们可以部署的东西，我们将在我们的 CircleCI 配置中添加以下内容：

```js
- run: npm install
- run: npm run build
```

有了这个，我们的系统将会像在本地运行一样构建。让我们继续尝试一下。按照以下步骤进行：

1.  将我们的配置文件添加到我们的`git`提交中：

```js
> git add .circleci/config.yml
```

1.  将此提交到我们的本地存储库：

```js
> git commit -m "changed configuration"
```

1.  将此推送到我们的 GitHub 存储库：

```js
> git push
```

一旦我们这样做，CircleCI 将启动一个构建。如果我们在 CircleCI 中的项目目录中，我们将看到它正在构建。如果我们点击作业，我们将看到它运行我们所有的步骤-我们甚至会看到它运行我们在文件中列出的步骤。在这里，我们将看到我们的构建失败！

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-hiperf/img/92977eda-b298-4d1d-a1a0-1e23093d7fb9.png)

这是因为当我们安装 Rollup 时，我们将其安装为全局项目。在这种情况下，我们需要将其添加为`package.json`文件中的开发依赖项。如果我们将其添加到我们的`package.json`文件中，我们应该有一个看起来像这样的`devDependency`部分：

```js
"devDependencies": {
    "rollup-plugin-sass": "¹.2.2",
    "rollup-plugin-terser": "⁵.1.2",
    "rollup-plugin-uglify": "⁶.0.3",
    "rollup": "¹.27.5"
}
```

现在，如果我们将这些文件提交并推送到我们的 GitHub 存储库，我们将看到我们的构建通过了！

通过一个通过的构建，我们应该将 Snyk orb 添加到我们的配置中。如果我们前往[`circleci.com/orbs/registry/orb/snyk/snyk`](https://circleci.com/orbs/registry/orb/snyk/snyk)，我们将看到我们需要设置的所有命令和配置。让我们继续修改我们的`config.yml`文件，以引入 Snyk orb。我们将在构建后检查我们的存储库。这应该看起来像这样：

```js
version: 2.1
orbs:
  snyk: snyk/snyk@0.0.8
jobs:  build:
    docker:
      - image: circleci/node:12.13
    working_directory: ~/repo
    steps:
      - checkout
      - run: npm install   
      - snyk/scan     
      - run: npm run build
```

有了上述配置，我们可以继续提交/推送到我们的 GitHub 存储库，并查看我们的构建的新运行。它应该失败，因为除非我们明确声明要运行它们，否则它不允许我们运行第三方 orbs。我们可以通过前往设置并转到安全部分来做到这一点。一旦在那里，继续声明我们要使用第三方 orbs。勾选后，我们可以进行另一个构建，我们将看到我们再次失败！

我们需要注册 Snyk 才能使用他们的 orb。前往 snyk.io 并使用 GitHub 帐户注册。然后，转到“帐户设置”部分。从那里，获取 API 令牌并转到“设置和上下文”部分。

创建一个新的上下文并添加以下环境变量：

```js
SNYK_TOKEN : <Your_API_Key>
```

为了利用 contexts，我们需要稍微修改我们的`config.yml`文件。我们需要添加一个工作流部分，并告诉它使用该上下文运行我们的构建作业。文件应该看起来像下面这样：

```js
version : 2.1
orbs:
    snyk: snyk/snyk@0.0.8
jobs:
  build:
    docker:
      - image: circleci/node:12.13
    working_directory: ~/repo
    steps:
      - checkout
      - restore_cache:
          keys:
            - v1-dependencies-{{ checksum "package.json" }}
            - v1-dependencies-
      - run: npm install
      - snyk/scan     
      - run: npm run build
      - save_cache:
          paths:
            - node_modules
          key: v1-dependencies-{{ checksum "package.json" }}
workflows:
  version: 2
  build_and_deploy:
    jobs:
      - build:
          context: build
```

有了这个变化，我们可以继续将其推送到远程存储库。我们将看到构建通过，并且 Snyk 将安全扫描我们的包！

上下文的概念是为了隐藏配置文件中的 API 密钥和密码。我们不希望将它们放在配置文件中，因为任何人都可以看到它们。相反，我们将它们放在诸如上下文之类的地方，项目的管理员将能够看到它们。每个 CI/CD 系统都应该有这样的概念，并且在有这样的项目时应该使用它。

随着我们的项目构建和扫描完成，我们所需要做的就是将我们的应用程序部署到一台机器上！

# 部署我们的构建

要部署我们的应用程序，我们需要部署到我们自己的计算机上。有许多服务可以做到这一点，比如 AWS、Azure、Netlify 等等，它们都有自己的部署方式。在我们的情况下，我们将部署到 Heroku。

按照以下步骤操作：

1.  如果我们还没有 Heroku 帐户，我们需要去注册一个。前往[`id.heroku.com/login`](https://id.heroku.com/login)，然后在表单底部选择“注册”。

1.  登录新帐户，然后点击右上角的“新建”按钮。

1.  在下拉菜单中，点击“创建新应用程序”。

1.  我们可以随意给应用程序取任何名字。输入一个应用程序名称。

1.  返回到我们的 CircleCI 仪表板，然后进入设置。创建一个名为“deploy”的新上下文。

1.  添加一个名为`HEROKU_APP_NAME`的新变量。这是我们在*步骤 3*中设置的应用程序名称。

1.  返回 Heroku，点击右上角的用户配置文件图标。从下拉菜单中，点击“帐户设置”。

1.  您应该会看到一个名为“API 密钥”的部分。点击“显示”按钮，然后复制显示的密钥。

1.  返回到我们的 CircleCI 仪表板，并创建一个名为`HEROKU_API_KEY`的新变量。值应该是我们在*步骤 8*中得到的密钥。

1.  在我们的`config.yml`文件中添加一个新的作业。我们的作业应该看起来像下面这样：

```js
version : 2.1
orbs:
  heroku: circleci/heroku@0.0.10
jobs:
  deploy:
    executor: heroku/default
    steps:
      - checkout
      - heroku/install
      - heroku/deploy-via-git:
          only-branch: master
workflows:
 version: 2
 build_and_deploy:
 jobs:
   - build:
       context: build
   - deploy
       context: deploy
       requires:
         - build

```

我们在这里做的是向我们的工作流程中添加了一个新的作业，即`deploy`作业。在这里，第一步是向我们的工作流程中添加官方的 Heroku orb。接下来，我们创建了一个名为`deploy`的作业，并按照 Heroku orb 中的步骤进行操作。这些步骤可以在[`circleci.com/orbs/registry/orb/circleci/heroku`](https://circleci.com/orbs/registry/orb/circleci/heroku)找到。

1.  我们需要将我们的构建部署回 GitHub，以便 Heroku 获取更改。为此，我们需要创建一个部署密钥。在命令提示符中运行`ssh-keygen -m PEM -t rsa -C "<your_email>"`命令。确保不要输入密码。

1.  复制刚生成的密钥，然后进入 GitHub 存储库的设置。

1.  在左侧导航栏中点击“部署密钥”。

1.  点击“添加部署密钥”。

1.  添加一个标题，然后粘贴我们在*步骤 12*中复制的密钥。

1.  勾选“允许写入访问”复选框。

1.  返回 CircleCI，点击左侧导航栏中的项目设置。

1.  点击“SSH 权限”，然后点击“添加 SSH 密钥”。

1.  在*步骤 11*中添加我们创建的私钥。确保在主机名部分添加`github.com`。

1.  添加以下行到我们构建作业的`config.yml`文件中：

```js
steps:
  - add_ssh_keys:
  fingerprints:
 - "<fingerprint in SSH settings>"
```

1.  在构建结束时，添加以下步骤：

```js
- run: git push
```

我们将遇到的一个问题是，我们的应用程序希望通过 HTTPS 工作，但 Heroku 需要专业许可证才能实现这一点。要么选择这个（这是一个付费服务），要么更改我们的应用程序，使其只能使用 HTTP。

通过这样做，我们成功地建立了一个几乎可以在任何地方使用的 CI/CD 流水线。我们还增加了一个额外的安全检查，以确保我们部署的代码是安全的。有了这些，我们就能够构建和部署用 JavaScript 编写的 Web 应用程序了！

# 总结

在本章中，我们学习了如何在利用构建环境（如 RollupJS）的同时构建应用程序。除此之外，我们还学习了如何通过 CircleCI 添加 CI 和 CD。

下一章，也是本书的最后一章，将介绍一个名为 WebAssembly 的高级概念。虽然代码不会是 JavaScript，但它将帮助我们了解如何将我们的 Web 应用程序提升到一个新的水平。
