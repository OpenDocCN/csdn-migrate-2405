# 精通 NodeJS（二）

> 原文：[`zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40`](https://zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：在节点和客户端之间流式传输数据

“壶口滴水成河。”

- 佛陀

我们现在更清楚地了解了 Node 的事件驱动、I/O 集中的设计理念如何在其各种模块 API 中体现，为开发提供了一致和可预测的环境。

在本章中，我们将发现如何使用 Node 从文件或其他来源中提取数据，然后使用 Node 进行读取、写入和操作，就像使用 Node 一样容易。最终，我们将学习如何使用 Node 开发具有快速 I/O 接口的网络服务器，支持高并发应用程序，同时在成千上万的客户端之间共享实时数据。

# 为什么使用流？

面对一个新的语言特性、设计模式或软件模块，一个新手开发者可能会开始使用它，因为它是新的和花哨的。另一方面，一个有经验的开发者可能会问，*为什么需要这个？*

文件很大，所以需要流。一些简单的例子可以证明它们的必要性。首先，假设我们想要复制一个文件。在 Node 中，一个天真的实现看起来像这样：

```js
// First attempt
console.log('Copying...');
let block = fs.readFileSync("source.bin");
console.log('Size: ' + block.length);
fs.writeFileSync("destination.bin", block);
console.log('Done.');
```

这非常简单。

调用`readFileSync()`时，Node 会将`source.bin`的内容（一个与脚本相同文件夹中的文件）复制到内存中，返回一个名为`block`的`ByteBuffer`。

一旦我们有了`block`，我们可以检查并打印出它的大小。然后，代码将`block`交给`writeFileSync`，它将内存块复制到一个新创建或覆盖的文件`destination.bin`的内容中。

这段代码假设以下事情：

+   阻塞事件循环是可以的（不是！）

+   我们可以将整个文件读入内存（我们不能！）

正如你在上一章中所记得的，Node 会一个接一个地处理事件，一次处理一个事件。良好的异步设计使得 Node 程序看起来好像同时做了各种事情，既对连接的软件系统又对人类用户来说，同时还为代码中的开发者提供了一个易于理解和抵抗错误的逻辑呈现。这一点尤为真实，尤其是与可能编写来解决相同任务的多线程代码相比。你的团队甚至可能已经转向 Node，以制作一个改进的替代品来解决这样一个经典的多线程系统。此外，良好的异步设计永远不会阻塞事件循环。

阻塞事件循环是不好的，因为 Node 无法做其他事情，而你的一个阻塞代码行正在阻塞。前面的例子，作为一个简单的脚本，从一个地方复制文件到另一个地方，可能运行得很好。它会在 Node 复制文件时阻塞用户的终端。文件可能很小，等待的时间很短。如果不是，你可以在等待时打开另一个 shell 提示符。这样，它与`cp`或`curl`等熟悉的命令并没有什么不同。

然而，从计算机的角度来看，这是相当低效的。每个文件复制不应该需要自己的操作系统进程。

此外，将之前的代码合并到一个更大的 Node 项目中可能会使整个系统不稳定。

你的服务器端 Node 应用程序可能同时让三个用户登录，同时向另外两个用户发送大文件。如果该应用程序执行之前的代码，两个下载将会停滞，三个浏览器会一直旋转。

所以，让我们一步一步地来修复这个问题：

```js
// Attempt the second
console.log('Copying...');
fs.readFile('source.bin', null, (error1, block) => {
  if (error1) {
    throw error1;
  }
  console.log('Size: ' + block.length);
  fs.writeFile('destination.bin', block, (error2) => {
    if (error2) {
      throw error2;
    }
    console.log('Done.');
  });
});
```

至少现在我们不再使用在它们标题中带有*Sync*的 Node 方法。事件循环可以再次自由呼吸。

但是：

+   大文件怎么办？（大爆炸）

+   你那里有一个相当大的金字塔（厄运）

尝试使用一个 2GB（2.0 x 2³⁰，或 2,147,483,648 字节）的源文件来运行之前的代码：

```js
RangeError: "size" argument must not be larger than 2147483647
 at Function.Buffer.allocUnsafe (buffer.js:209:3)
 at tryCreateBuffer (fs.js:530:21)
 at Object.fs.readFile (fs.js:569:14)
 ...
```

如果你在 YouTube 上以 1080p 观看视频，2GB 的流量大约可以让你看一个小时。之前的`RangeError`发生是因为`2,147,483,647`在二进制中是`1111111111111111111111111111111`，是最大的 32 位有符号二进制整数。Node 在内部使用这种类型来调整和寻址`ByteBuffer`的内容。

如果你交给我们可怜的例子会发生什么？更小，但仍然非常大的文件是不确定的。当它工作时，是因为 Node 成功地从操作系统获取了所需的内存。在复制操作期间，Node 进程的内存占用量会随着文件大小而增加。鼠标可能会变成沙漏，风扇可能会嘈杂地旋转起来。承诺会有所帮助吗？：

```js
// Attempt, part III
console.log('Copying...');
fs.readFileAsync('source.bin').then((block) => {
  console.log('Size: ' + block.length);
  return fs.writeFileAsync('destination.bin', block);
}).then(() => {
 console.log('Done.');
}).catch((e) => {
  // handle errors
});
```

不，本质上不是。我们已经扁平化了金字塔，但大小限制和内存问题仍然存在。

我们真正需要的是一些既是异步的，又是*逐步的*代码，从源文件中获取一小部分，将其传送到目标文件进行写入，并重复该循环，直到完成，就像古老的灭火队一样。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/0e4e9db3-d056-41d5-a94f-5edb81573357.jpeg)

这样的设计会让事件循环在整个时间内自由呼吸。

这正是流的作用：

```js
// Streams to the rescue
console.log('Copying...');
fs.createReadStream('source.bin')
.pipe(fs.createWriteStream('destination.bin'))
.on('close', () => { console.log('Done.'); });
```

在实践中，规模化的网络应用通常分布在许多实例中，需要将数据流的处理分布到许多进程和服务器中。在这里，流文件只是一个数据流，被分成片段，每个片段可以独立查看，而不受其他片段的可用性的影响。你可以写入数据流，或者监听数据流，自由动态分配字节，忽略字节，重新路由字节。数据流可以被分块，许多进程可以共享块处理，块可以被转换和重新插入，数据流可以被精确发射和创造性地管理。

回顾我们在现代软件和模块化规则上的讨论，我们可以看到流如何促进独立的共享无事务的进程的创建，这些进程各自完成一项任务，并且组合起来可以构成一个可预测的架构，其复杂性不会妨碍对其行为的准确评估。如果数据接口是无争议的，那么数据映射可以准确建模，而不考虑数据量或路由的考虑。

在 Node 中管理 I/O 涉及管理绑定到数据流的数据事件。Node Stream 对象是`EventEmitter`的一个实例。这个抽象接口在许多 Node 模块和对象中实现，正如我们在上一章中看到的那样。让我们首先了解 Node 的 Stream 模块，然后讨论 Node 中如何通过各种流实现处理网络 I/O；特别是 HTTP 模块。

# 探索流

根据 Bjarne Stoustrup 在他的书《C++程序设计语言》（第三版）中的说法：

“为编程语言设计和实现通用的输入/输出设施是非常困难的... I/O 设施应该易于使用、方便、安全；高效、灵活；最重要的是完整。”

让人不惊讶的是，一个专注于提供高效和简单 I/O 的设计团队，通过 Node 提供了这样一个设施。通过一个对称和简单的接口，处理数据缓冲区和流事件，使实现者不必关心，Node 的 Stream 模块是管理内部模块和模块开发人员异步数据流的首选方式。

在 Node 中，流只是一系列字节。在任何时候，流都包含一个字节缓冲区，这个缓冲区的长度为零或更大：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/2723e2fe-cae1-4f74-ba59-fa5f464f0c2c.jpg)

流中的每个字符都是明确定义的，因为每种类型的数字数据都可以用字节表示，流的任何部分都可以重定向或*管道*到任何其他流，流的不同块可以发送到不同的处理程序，等等。这样，流输入和输出接口既灵活又可预测，并且可以轻松耦合。

Node 还提供了第二种类型的流：对象流。对象流不是通过流动内存块，而是通过 JavaScript 对象传输。字节流传输序列化数据，如流媒体，而对象流适用于解析的结构化数据，如 JSON 记录。

数字流可以用流体的类比来描述，其中个别字节（水滴）被推送通过管道。在 Node 中，流是表示可以异步写入和读取的数据流的对象。

Node 的哲学是非阻塞流，I/O 通过流处理，因此 Stream API 的设计自然地复制了这一一般哲学。事实上，除了以异步、事件方式与流交互外，没有其他方式——Node 通过设计阻止开发人员阻塞 I/O。

通过抽象流接口暴露了五个不同的基类：**Readable**，**Writable**，**Duplex**，**Transform**和**PassThrough**。每个基类都继承自`EventEmitter`，我们知道它是一个可以绑定事件监听器和发射器的接口。

正如我们将要学习的，并且在这里强调的，流接口是一个抽象接口。抽象接口充当一种蓝图或定义，描述了必须构建到每个构造的流对象实例中的特性。例如，可读流实现需要实现一个`public read`方法，该方法委托给接口的`internal _read`方法。

一般来说，所有流实现都应遵循以下准则：

+   只要存在要发送的数据，就向流写入，直到该操作返回`false`，此时实现应等待`drain`事件，表示缓冲的流数据已经清空。

+   继续调用读取，直到收到`null`值，此时等待可读事件再恢复读取。

+   几个 Node I/O 模块都是以流的形式实现的。网络套接字、文件读取器和写入器、`stdin`和`stdout`、zlib 等都是流。同样，当实现可读数据源或数据读取器时，应该将该接口实现为流接口。

重要的是要注意，在 Node 的历史上，Stream 接口在某些根本性方面发生了变化。Node 团队已尽最大努力实现兼容的接口，以便（大多数）旧程序可以继续正常运行而无需修改。在本章中，我们不会花时间讨论旧 API 的具体特性，而是专注于当前的设计。鼓励读者查阅 Node 的在线文档，了解迁移旧程序的信息。通常情况下，有一些模块会用方便、可靠的接口*包装*流。一个很好的例子是：[`github.com/rvagg/through2.`](https://github.com/rvagg/through2)

# 实现可读流

产生数据的流，另一个进程可能感兴趣的，通常使用`Readable`流来实现。`Readable`流保存了实现者管理读取队列、处理数据事件的发射等所有工作。

要创建一个`Readable`流，请使用以下方法：

```js
const stream = require('stream');
let readable = new stream.Readable({
  encoding: "utf8",
  highWaterMark: 16000,
  objectMode: true
});
```

如前所述，`Readable`作为一个基类暴露出来，可以通过三种选项进行初始化：

+   `encoding`：将缓冲区解码为指定的编码，默认为 UTF-8。

+   `highWaterMark`：在停止从数据源读取之前，保留在内部缓冲区中的字节数。默认为 16 KB。

+   `objectMode`：告诉流以对象流而不是字节流的方式运行，例如以 JSON 对象流而不是文件中的字节流。默认为`false`。

在下面的示例中，我们创建一个模拟的`Feed`对象，其实例将继承`Readable`流接口。我们的实现只需要实现`Readable`的抽象`_read`方法，该方法将向消费者推送数据，直到没有更多数据可以推送为止，然后通过推送`null`值来触发`Readable`流发出一个`end`事件：

```js
const stream = require('stream');

let Feed = function(channel) {
   let readable = new stream.Readable({});
   let news = [
      "Big Win!",
      "Stocks Down!",
      "Actor Sad!"
   ];
   readable._read = () => {
      if(news.length) {
         return readable.push(news.shift() + "\n");
      }
      readable.push(null);
   };
   return readable;
};
```

现在我们有了一个实现，消费者可能希望实例化流并监听流事件。两个关键事件是`readable`和`end`。

只要数据被推送到流中，`readable`事件就会被触发。它会提醒消费者通过`Readable`的`read`方法检查新数据。

再次注意，`Readable`实现必须提供一个`private _read`方法，为消费者 API 公开的`public read`方法提供服务。

当我们向`Readable`实现的`push`方法传递`null`值时，`end`事件将被触发。

在这里，我们看到一个消费者使用这些方法来显示新的流数据，并在流停止发送数据时提供通知：

```js
let feed = new Feed();

feed.on("readable", () => {
   let data = feed.read();
   data && process.stdout.write(data);
});
feed.on("end", () => console.log("No more news"));
// Big Win!
// Stocks Down!
// Actor Sad!
// No more news
```

同样，我们可以通过使用`objectMode`选项来实现对象流：

```js
const stream = require('stream');

let Feed = function(channel) {
   let readable = new stream.Readable({
      objectMode : true
   });
   let prices = [{price : 1},{price : 2}];
   readable._read = () => {
      if(prices.length) {
         return readable.push(prices.shift());
      }
      readable.push(null);
   };
   return readable;
};
```

在设置为 objectMode 后，每个推送的块都预期是一个对象。因此，该流的读取器可以假定每个`read()`事件将产生一个单独的对象：

```js
let feed = new Feed();
feed.on("readable", () => {
   let data = feed.read();
   data && console.log(data);
});
feed.on("end", () => console.log("No more news"));
// { price: 1 }
// { price: 2 }
// No more news
```

在这里，我们看到每个读取事件都接收一个对象，而不是缓冲区或字符串。

最后，`Readable`流的`read`方法可以传递一个参数，指示从流的内部缓冲区中读取的字节数。例如，如果希望逐字节读取文件，可以使用类似于以下的例程来实现消费者：

```js
let Feed = function(channel) {
   let readable = new stream.Readable({});
   let news = 'A long headline might go here';
   readable._read = () => {
      readable.push(news);
      readable.push(null);
   };
   return readable;
};
```

请注意，我们将整个新闻推送到流中，并以 null 终止。流已经准备好了整个字节字符串。现在消费者：

```js
feed.on('readable', () => {
   let character;
   while(character = feed.read(1)) {
      console.log(character.toString());
   }
});
// A
// 
// l
// o
// n
// ...
// No more bytes to read
```

在这里，应该清楚的是`Readable`流的缓冲区一次性填满了许多字节，但是却是离散地读取。

# 推送和拉取

我们已经看到`Readable`实现将使用`push`方法来填充用于读取的流缓冲区。在设计这些实现时，重要的是考虑如何管理流的两端的数据量。向流中推送更多数据可能会导致超出可用空间（内存）的复杂情况。在消费者端，重要的是要保持对终止事件的意识，以及如何处理数据流中的暂停。

我们可以将通过网络传输的数据流的行为与水流经过软管进行比较。

与水流经过软管一样，如果向读取流中推送的数据量大于消费者端通过`read`方法有效排出的数据量，就会产生大量背压，导致数据在流对象的缓冲区中开始积累。由于我们正在处理严格的数学限制，`read`方法根本无法通过更快地读取来释放这种压力——可用内存空间可能存在硬性限制，或者其他限制。因此，内存使用可能会危险地增加，缓冲区可能会溢出，等等。

因此，流实现应该意识到并响应`push`操作的响应。如果操作返回`false`，这表明实现应该停止从其源读取（并停止推送），直到下一个`_read`请求被发出。

与上述内容相结合，如果没有更多数据可以推送，但将来预期会有更多数据，实现应该`push`一个空字符串`("")`，这不会向队列中添加任何数据，但确保将来会触发一个`readable`事件。

虽然流缓冲区最常见的处理方式是向其`push`（将数据排队），但有时您可能希望将数据放在缓冲区的前面（跳过队列）。对于这些情况，Node 提供了一个`unshift`操作，其行为与`push`相同，除了在缓冲区放置数据的差异之外。

# 可写流

`Writable`流负责接受某个值（一系列字节，一个字符串）并将数据写入目标。将数据流入文件容器是一个常见的用例。

创建`Writable`流：

```js
const stream = require('stream');
let readable = new stream.Writable({
  highWaterMark: 16000,
  decodeStrings: true
});
```

`Writable`流构造函数可以用两个选项实例化：

+   `highWaterMark`：在写入时流缓冲区将接受的最大字节数。默认值为 16 KB。

+   `decodeStrings`：是否在写入之前将字符串转换为缓冲区。默认为`true`。

与`Readable`流一样，自定义的`Writable`流实现必须实现`_write`处理程序，该处理程序将接收发送给实例的`write`方法的参数。

你应该将`Writable`流视为一个数据目标，比如你正在上传的文件。在概念上，这与`Readable`流中`push`的实现类似，其中一个推送数据直到数据源耗尽，并传递`null`来终止读取。例如，在这里，我们向流写入了 32 个“A”字符，它将把它们记录下来：

```js
const stream = require('stream');

let writable = new stream.Writable({
   decodeStrings: false
});

writable._write = (chunk, encoding, callback) => {
   console.log(chunk.toString());
   callback();
};

let written = writable.write(Buffer.alloc(32, 'A'));
writable.end();

console.log(written);

// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// true
```

这里有两个关键点需要注意。

首先，我们的`_write`实现在写入回调后立即触发`callback`函数，这个回调函数始终存在，无论实例的`write`方法是否直接传递了`callback`。这个调用对于指示写入尝试的状态（失败或成功）非常重要。

其次，调用 write 返回了`true`。这表明在执行请求的写操作后，`Writable`实现的内部缓冲区已经被清空。如果我们发送了大量数据，足以超过内部缓冲区的默认大小，会怎么样呢？

修改前面的例子，以下将返回`false`：

```js
let written = writable.write(Buffer.alloc(16384, 'A'));
console.log(written); // Will be 'false'
```

`write`返回`false`的原因是它已经达到了`highWaterMark`选项的默认值 16 KB（16 * 1,024）。如果我们将这个值改为`16383`，`write`将再次返回`true`（或者可以简单地增加它的值）。

当`write`返回`false`时，你应该怎么做？你肯定不应该继续发送数据！回到我们水管的比喻：当流满时，应该等待它排空后再发送更多数据。Node 的流实现会在安全写入时发出`drain`事件。当`write`返回`false`时，在发送更多数据之前监听`drain`事件。

综合我们所学到的知识，让我们创建一个`highWaterMark`值为 10 字节的`Writable`流。然后设置一个模拟，我们将推送一个大于`highWaterMark`的数据字符串到`stdout`，然后等待缓冲区溢出并在发送更多数据之前等待`drain`事件触发：

```js
const stream = require('stream');

let writable = new stream.Writable({
   highWaterMark: 10
});

writable._write = (chunk, encoding, callback) => {
   process.stdout.write(chunk);
   callback();
};

function writeData(iterations, writer, data, encoding, cb) {
   (function write() {

      if(!iterations--) {
         return cb()
      }

      if (!writer.write(data, encoding)) {
         console.log(` <wait> highWaterMark of ${writable.writableHighWaterMark} reached`);
         writer.once('drain', write);
      }
   })()
}

writeData(4, writable, 'String longer than highWaterMark', 'utf8', () => console.log('finished'));
```

每次写入时，我们都会检查流写入操作是否返回 false，如果是，我们会在再次运行我们的`write`方法之前等待下一个`drain`事件。

你应该小心实现正确的流管理，尊重写事件发出的“警告”，并在发送更多数据之前正确等待`drain`事件的发生。

`Readable` 流中的流体数据可以很容易地重定向到 `Writable` 流。例如，以下代码将接收终端发送的任何数据（`stdin` 是一个 `Readable` 流）并将其回显到目标 `Writable` 流（`stdout`）：`process.stdin.pipe(process.stdout)`。当将 `Writable` 流传递给 `Readable` 流的 pipe 方法时，将触发 **pipe** 事件。类似地，当将 `Writable` 流从 `Readable` 流的目标中移除时，将触发 **unpipe** 事件。要移除 `pipe`，使用以下方法：`unpipe(destination stream)`

# 双工流

**双工流** 既可读又可写。例如，在 Node 中创建的 TCP 服务器公开了一个既可读又可写的套接字：

```js
const stream = require("stream");
const net = require("net");

net.createServer(socket => {
  socket.write("Go ahead and type something!");
  socket.setEncoding("utf8");
  socket.on("readable", function() {
    process.stdout.write(this.read())
  });
})
.listen(8080);
```

执行时，此代码将创建一个可以通过 Telnet 连接的 TCP 服务器：

```js
telnet 127.0.0.1 8080
```

在一个终端窗口中启动服务器，打开一个单独的终端，并通过 telnet 连接到服务器。连接后，连接的终端将打印出 `Go ahead and type something!` ——写入套接字。在连接的终端中输入任何文本（按下 **ENTER** 后）将被回显到运行 TCP 服务器的终端的 `stdout`（从套接字读取），创建一种聊天应用程序。

这种双向（双工）通信协议的实现清楚地展示了独立进程如何形成复杂和响应灵敏的应用程序的节点，无论是在网络上通信还是在单个进程范围内通信。

构造 `Duplex` 实例时发送的选项将合并发送到 `Readable` 和 `Writable` 流的选项，没有额外的参数。实际上，这种流类型简单地承担了两种角色，并且与其交互的规则遵循所使用的交互模式的规则。

`Duplex` 流假定了读和写两种角色，任何实现都需要实现 `­_write` 和 `_read` 方法，再次遵循相关流类型的标准实现细节。

# 转换流

有时需要处理流数据，通常在写入某种二进制协议或其他 *即时* 数据转换的情况下。`Transform` 流就是为此目的而设计的，它作为一个位于 `Readable` 流和 `Writable` 流之间的 `Duplex` 流。

使用与初始化典型 `Duplex` 流相同的选项初始化 `Transform` 流，`Transform` 与普通的 `Duplex` 流的不同之处在于其要求自定义实现仅提供 `_transform` 方法，而不需要 `_write` 和 `_read` 方法。

`_transform` 方法将接收三个参数，首先是发送的缓冲区，然后是一个可选的编码参数，最后是一个回调函数，`_transform` 期望在转换完成时调用。

```js
_transform = function(buffer, encoding, cb) {
  let transformation = "...";
  this.push(transformation);
  cb();
};
```

让我们想象一个程序，它可以将 **ASCII（美国信息交换标准代码）** 代码转换为 ASCII 字符，从 `stdin` 接收输入。您输入一个 ASCII 代码，程序将以对应该代码的字母数字字符作出响应。在这里，我们可以简单地将输入传输到 `Transform` 流，然后将其输出传输回 `stdout`：

```js
const stream = require('stream');
let converter = new stream.Transform();

converter._transform = function(num, encoding, cb) {
   this.push(String.fromCharCode(new Number(num)) + "\n");
   cb();
};

process.stdin.pipe(converter).pipe(process.stdout);
```

与此程序交互可能会产生类似以下的输出：

```js
65 A
66 B
256 Ā
257 ā
```

在本章结束时，将演示一个更复杂的转换流示例。

# 使用 PassThrough 流

这种流是 `Transform` 流的一个简单实现，它只是将接收到的输入字节传递到输出流。如果不需要对输入数据进行任何转换，只是想要轻松地将 `Readable` 流传输到 `Writable` 流，这是很有用的。

`PassThrough`流具有类似于 JavaScript 的匿名函数的好处，使得可以轻松地断言最小的功能而不需要太多的麻烦。例如，不需要实现一个抽象基类，就像对`Readable`流的`_read`方法所做的那样。考虑以下使用`PassThrough`流作为事件间谍的用法：

```js
const fs = require('fs');
const stream = require('stream');
const spy = new stream.PassThrough();

spy
.on('error', (err) => console.error(err))
.on('data', function(chunk) {
    console.log(`spied data -> ${chunk}`);
})
.on('end', () => console.log('\nfinished'));

fs.createReadStream('./passthrough.txt').pipe(spy).pipe(process.stdout);
```

通常，Transform 或 Duplex 流是你想要的（在这里你可以设置`_read`和`_write`的正确实现），但在某些情况下，比如测试中，可以将“观察者”放在流上是有用的。

# 创建一个 HTTP 服务器

HTTP 是建立在请求/响应模型之上的无状态数据传输协议：客户端向服务器发出请求，服务器然后返回响应。由于促进这种快速模式的网络通信是 Node 设计的出色之处，Node 作为一个用于创建服务器的工具包获得了早期广泛的关注，尽管它当然也可以用于做更多的事情。在本书中，我们将创建许多 HTTP 服务器的实现，以及其他协议服务器，并将在更深入的上下文中讨论最佳实践，这些上下文是特定的业务案例。预期你已经有一些类似的经验。出于这两个原因，我们将快速地从一般概述中进入一些更专业的用途。

在最简单的情况下，HTTP 服务器会响应连接尝试，并在数据到达和发送时进行管理。通常使用`http`模块的`createServer`方法创建一个 Node 服务器：

```js
const http = require('http');
let server = http.createServer((request, response) => {
   response.writeHead(200, { 
      'Content-Type': 'text/plain'
   });
   response.write("PONG");
   response.end();
}).listen(8080);

server.on("request", (request, response) => {
   request.setEncoding("utf8");
   request.on("readable", () => console.log(request.read()));
   request.on("end", () => console.log("DONE"));
});
```

`http.createServer`返回的对象是`http.Server`的一个实例，它扩展了`EventEmitter`，在网络事件发生时广播，比如客户端连接或请求。前面的代码是编写 Node 服务器的常见方式。然而，值得指出的是，直接实例化`http.Server`类有时是区分不同服务器/客户端交互的一种有用方式。我们将在接下来的示例中使用这种格式。

在这里，我们创建一个基本的服务器，它只是在连接建立时报告，并在连接终止时报告：

```js
const http = require('http');
const server = new http.Server();
server.on('connection', socket => {
   let now = new Date();
   console.log(`Client arrived: ${now}`);
   socket.on('end', () => console.log(`client left: ${new Date()}`));
});
// Connections get 2 seconds before being terminated
server.setTimeout(2000, socket => socket.end());
server.listen(8080);
```

在构建多用户系统时，特别是经过身份验证的多用户系统，服务器-客户端事务的这一点是客户端验证和跟踪代码的绝佳位置，包括设置或读取 cookie 和其他会话变量，或向在并发实时应用程序中共同工作的其他客户端广播客户端到达事件。

通过添加一个请求的监听器，我们可以得到更常见的请求/响应模式，作为一个`Readable`流进行处理。当客户端 POST 一些数据时，我们可以像下面这样捕获这些数据：

```js
server.on('request', (request, response) => {
   request.setEncoding('utf8');
   request.on('readable', () => {
      let data = request.read();
      data && response.end(data);
   });
});
```

尝试使用**curl**向这个服务器发送一些数据：

```js
curl http://localhost:8080 -d "Here is some data"
// Here is some data
```

通过使用连接事件，我们可以很好地将我们的连接处理代码分开，将其分组到清晰定义的功能域中，正确地描述为响应特定事件执行的功能域。在上面的示例中，我们看到了如何设置一个定时器，在两秒后启动服务器连接。

如果只是想设置在套接字被假定超时之前的不活动毫秒数，只需使用`server.timeout = (Integer)num_milliseconds`。要禁用套接字超时，请传递一个值`0`（零）。

现在让我们看看 Node 的 HTTP 模块如何用于进入更有趣的网络交互。

# 发出 HTTP 请求

网络应用程序通常需要进行外部 HTTP 调用。HTTP 服务器也经常被要求为向其发出请求的客户端执行 HTTP 服务。Node 提供了一个简单的接口来进行外部 HTTP 调用。

例如，以下代码将获取`www.example.org`的 HTML 首页：

```js
const http = require('http');
http.request({ 
   host: 'www.example.org',
   method: 'GET',
   path: "/"
}, function(response) {
   response.setEncoding("utf8");
   response.on("readable", () => console.log(response.read()));
}).end();
```

正如我们所看到的，我们正在使用一个`Readable`流，可以写入文件。

管理 HTTP 请求的一个流行的 Node 模块是 Mikeal Roger 的 request：[`github.com/request/request`](https://github.com/request/request)

因为通常使用`HTTP.request`来`GET`外部页面，Node 提供了一个快捷方式：

```js
http.get("http://www.example.org/", response => {
  console.log(`Status: ${response.statusCode}`);
}).on('error', err => {
  console.log("Error: " + err.message);
});
```

现在让我们看一些更高级的 HTTP 服务器实现，其中我们为客户端执行一般的网络服务。

# 代理和隧道

有时，为一个服务器提供作为代理或经纪人的功能对其他服务器很有用。这将允许一个服务器将负载分发给其他服务器，例如。另一个用途是为无法直接连接到该服务器的用户提供对安全服务器的访问。一个服务器为多个 URL 提供答复是很常见的——使用代理，一个服务器可以将请求转发给正确的接收者。

由于 Node 在其网络接口中具有一致的流接口，我们可以用几行代码构建一个简单的 HTTP 代理。例如，以下程序将在端口`8080`上设置一个 HTTP 服务器，该服务器将通过获取网站的首页并将该页面传送回客户端来响应任何请求：

```js
const http = require('http');
const server = new http.Server();

server.on("request", (request, socket) => {
   console.log(request.url);
   http.request({ 
      host: 'www.example.org',
      method: 'GET',
      path: "/",
      port: 80
   }, response => response.pipe(socket))
   .end();
});

server.listen(8080, () => console.log('Proxy server listening on localhost:8080'));
```

继续启动这个服务器，并连接到它。一旦这个服务器接收到客户端套接字，它就可以自由地从任何可读流中向客户端推送内容，这里，`www.example.org`的`GET`结果被流式传输。一个外部内容服务器管理应用程序的缓存层可能成为代理端点的例子。

使用类似的想法，我们可以使用 Node 的原生`CONNECT`支持创建一个隧道服务。隧道涉及使用代理服务器作为客户端的中间人与远程服务器进行通信。一旦我们的代理服务器连接到远程服务器，它就能在该服务器和客户端之间来回传递消息。当客户端和远程服务器之间无法直接建立连接或不希望建立连接时，这是有利的。

首先，我们将设置一个代理服务器来响应`HTTP` `CONNECT`请求，然后向该服务器发出`CONNECT`请求。代理接收我们客户端的`Request`对象，客户端的套接字本身，以及隧道流的头部（第一个数据包）：

```js
const http = require('http');
const net = require('net');
const url = require('url');
const proxy = new http.Server();

proxy.on('connect', (request, clientSocket, head) => {
  let reqData = url.parse(`http://${request.url}`);
  let remoteSocket = net.connect(reqData.port, reqData.hostname, () => {
    clientSocket.write('HTTP/1.1 200 \r\n\r\n');
    remoteSocket.write(head);
    remoteSocket.pipe(clientSocket);
    clientSocket.pipe(remoteSocket);
   });
}).listen(8080);

let request = http.request({
  port: 8080,
  hostname: 'localhost',
  method: 'CONNECT',
  path: 'www.example.org:80'
});
request.end();

request.on('connect', (res, socket, head) => {
  socket.setEncoding("utf8");
  socket.write('GET / HTTP/1.1\r\nHost: www.example.org:80\r\nConnection: close\r\n\r\n');
  socket.on('readable', () => {
      console.log(socket.read());
   });
  socket.on('end', () => {
    proxy.close();
  });
});
```

一旦我们向运行在端口 8080 上的本地隧道服务器发出请求，它将建立与目的地的远程套接字连接，并保持这个远程套接字和（本地）客户端套接字之间的“桥梁”。远程连接当然只看到我们的隧道服务器，这样客户端可以以某种匿名的方式连接到远程服务（这并不总是一种不正当的做法！）。

# HTTPS、TLS（SSL）和保护您的服务器

Web 应用程序的安全性近年来已成为一个重要的讨论话题。传统应用程序通常受益于主要部署基础的主要服务器和应用程序堆栈中设计成熟的安全模型。出于某种原因，Web 应用程序被允许进入客户端业务逻辑的实验世界，并由一层薄薄的帷幕保护着开放的 Web 服务。

由于 Node 经常部署为 Web 服务器，社区有责任开始确保这些服务器的安全。HTTPS 是一种安全的传输协议——本质上是通过在 SSL/TLS 协议之上叠加 HTTP 协议而形成的加密 HTTP。

# 为开发创建自签名证书

为了支持 SSL 连接，服务器将需要一个正确签名的证书。在开发过程中，简单创建一个自签名证书会更容易，这将允许您使用 Node 的 HTTPS 模块。

这些是创建开发证书所需的步骤。我们创建的证书不会展示身份，就像第三方的证书那样，但这是我们使用 HTTPS 加密所需要的。从终端：

```js
openssl genrsa -out server-key.pem 2048
 openssl req -new -key server-key.pem -out server-csr.pem
 openssl x509 -req -in server-csr.pem -signkey server-key.pem -out server-cert.pem
```

这些密钥现在可以用于开发 HTTPS 服务器。这些文件的内容只需作为选项传递给 Node 服务器即可：

```js
const https = require('https');
const fs = require('fs');
https.createServer({
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem')
}, (req, res) => {
  ...
}).listen(443);
```

在开发过程中，可以从[`www.startssl.com/`](http://www.startssl.com/)获得免费的低保障 SSL 证书，这是自签名证书不理想的情况。此外，[`www.letsencrypt.org`](https://www.letsencrypt.org)已经开始了一个激动人心的倡议，为所有人提供免费证书（更安全的网络）。

# 安装真正的 SSL 证书

为了将安全应用程序从开发环境移出并放入暴露在互联网环境中，需要购买真正的证书。这些证书的价格一年比一年都在下降，应该很容易找到价格合理且安全级别足够高的证书提供商。一些提供商甚至提供免费的个人使用证书。

设置专业证书只需要更改我们之前介绍的 HTTPS 选项。不同的提供商将有不同的流程和文件名。通常，您需要从提供商那里下载或以其他方式接收`private` `.key`文件，已签名的域证书`.crt`文件，以及描述证书链的捆绑文件：

```js
let options = {
  key: fs.readFileSync("mysite.key"),
  cert: fs.readFileSync("mysite.com.crt"),
  ca: [ fs.readFileSync("gd_bundle.crt") ]
};
```

重要的是要注意，`ca`参数必须作为*数组*发送，即使证书的捆绑已经连接成一个文件。

# 请求对象

HTTP 请求和响应消息是相似的，包括以下内容：

+   状态行，对于请求来说，类似于 GET/`index.html` HTTP/1.1，对于响应来说，类似于 HTTP/1.1 200 OK

+   零个或多个头部，对于请求可能包括`Accept-Charset`: `UTF-8 或 From: user@server.com`，对于响应可能类似于`Content-Type: text/html 和 Content-Length: 1024`

+   消息正文，对于响应可能是一个 HTML 页面，对于`POST`请求可能是一些表单数据

我们已经看到了 Node 中 HTTP 服务器接口预期暴露一个请求处理程序，以及这个处理程序将被传递一些形式的请求和响应对象，每个对象都实现了可读或可写流。

我们将在本章后面更深入地讨论`POST`数据和`Header`数据的处理。在此之前，让我们先了解如何解析请求中包含的一些更直接的信息。

# URL 模块

每当向 HTTP 服务器发出请求时，请求对象将包含 URL 属性，标识目标资源。这可以通过`request.url`访问。Node 的 URL 模块用于将典型的 URL 字符串分解为其组成部分。请参考以下图示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/27aa88e6-d9b5-48b5-bdd3-9e3ce3cdd794.png)

我们看到`url.parse`方法是如何分解字符串的，每个部分的含义应该是清楚的。也许很明显，如果`query`字段本身被解析为键/值对会更有用。这可以通过将`true`作为`parse`方法的第二个参数来实现，这将把上面给出的查询字段值更改为更有用的键/值映射：

```js
query: { filter: 'sports', maxresults: '20' }
```

这在解析 GET 请求时特别有用。`url.parse`还有一个与这两个 URL 之间的差异有关的最后一个参数：

+   `http://www.example.org`

+   `//www.example.org`

这里的第二个 URL 是 HTTP 协议的一个（相对较少知道的）设计特性的一个例子：协议相对 URL（技术上是**网络路径引用**），而不是更常见的绝对 URL。

要了解更多关于如何使用网络路径引用来平滑资源协议解析的信息，请访问：[`tools.ietf.org/html/rfc3986#section-4.2`](http://tools.ietf.org/html/rfc3986#section-4.2)。

正在讨论的问题是：`url.parse`将以斜杠开头的字符串视为路径，而不是主机。例如，`url.parse("//www.example.org")`将在主机和路径字段中设置以下值：

```js
host: null,
 path: '//www.example.org'
```

我们实际上想要的是相反的：

```js
host: 'www.example.org',
 path: null
```

为了解决这个问题，将`true`作为`url.parse`的第三个参数传递，这表明斜杠表示主机，而不是路径：

```js
url.parse("//www.example.org", null, true);
```

也有可能开发人员想要创建一个 URL，比如通过`http.request`进行请求时。所述 URL 的各个部分可能分布在各种数据结构和变量中，并且需要被组装。您可以通过将从`url.parse`返回的对象传递给`url.format`方法来实现这一点。

以下代码将创建 URL 字符串`http://www.example.org`：

```js
url.format({
  protocol: 'http:',
  host: 'www.example.org'
});
```

同样，您还可以使用`url.resolve`方法来生成 URL 字符串，以满足需要连接基本 URL 和路径的常见情况：

```js
url.resolve("http://example.org/a/b", "c/d"); //'http://example.org/a/c/d'
url.resolve("http://example.org/a/b", "/c/d"); 
//'http://example.org/c/d'
url.resolve("http://example.org", "http://google.com"); //'http://google.com/'
```

# Querystring 模块

正如我们在`URL`模块中看到的，查询字符串通常需要被解析为键/值对的映射。`Querystring`模块将分解现有的查询字符串为其部分，或者从键/值对的映射中组装查询字符串。

例如，`querystring.parse("foo=bar&bingo=bango")`将返回：

```js
{
  foo: 'bar',
  bingo: 'bango'
}
```

如果我们的查询字符串没有使用正常的`"&"`分隔符和`"="`赋值字符格式化，`Querystring`模块提供了可定制的解析。

`Querystring`的第二个参数可以是自定义的分隔符字符串，第三个参数可以是自定义的赋值字符串。例如，以下将返回与先前给出的具有自定义格式的查询字符串相同的映射：

```js
let qs = require("querystring");
console.log(qs.parse("foo:bar^bingo:bango", "^", ":"));
// { foo: 'bar', bingo: 'bango' }
```

您可以使用`Querystring.stringify`方法组成查询字符串：

```js
console.log(qs.stringify({ foo: 'bar', bingo: 'bango' }));
// foo=bar&bingo=bango
```

与解析一样，`stringify`还接受自定义的分隔符和赋值参数：

```js
console.log(qs.stringify({ foo: 'bar', bingo: 'bango' }, "^", ":"));
// foo:bar^bingo:bango
```

查询字符串通常与`GET`请求相关联，在`?`字符后面看到。正如我们之前看到的，在这些情况下，使用`url`模块自动解析这些字符串是最直接的解决方案。然而，以这种方式格式化的字符串也会在处理`POST`数据时出现，在这些情况下，`Querystring`模块是真正有用的。我们将很快讨论这种用法，但首先，关于 HTTP 头部的一些内容。

# 处理头

向 Node 服务器发出的每个 HTTP 请求可能包含有用的头信息，客户端通常希望从服务器接收类似的包信息。Node 提供了简单的接口来读取和写入头信息。我们将简要介绍这些简单的接口，澄清一些细节。最后，我们将讨论如何在 Node 中实现更高级的头使用，研究 Node 服务器可能需要适应的一些常见网络责任。

典型的请求头将如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/b618caa1-547a-47f7-b781-5baaab74e9b1.png)

头是简单的键/值对。请求键始终小写。在设置响应键时，可以使用任何大小写格式。

读取头很简单。通过检查`request.header`对象来读取头信息，这是头键/值对的一对一映射。要从前面的示例中获取*accept*头，只需读取`request.headers.accept`。

通过设置 HTTP 服务器的`maxHeadersCount`属性，可以限制传入头的数量。

如果希望以编程方式读取头，Node 提供了`response.getHeader`方法，接受头键作为其第一个参数。

当写入头时，请求头是简单的键/值对，我们需要更具表现力的接口。由于响应通常必须发送状态码，Node 提供了一种简单的方法来准备响应状态行和头组的一条命令：

```js
response.writeHead(200, {
  'Content-Length': 4096,
  'Content-Type': 'text/plain'
});
```

要单独设置头，可以使用`response.setHeader`，传递两个参数：头键，然后是头值。

要使用相同名称设置多个头，可以将数组传递给`response.setHeader`。

```js
response.setHeader("Set-Cookie", ["session:12345", "language=en"]);
```

有时，在*排队*后可能需要删除响应头。这可以通过使用`response.removeHeader`来实现，将要删除的头名称作为参数传递。

必须在写入响应之前写入头。在发送响应后写入头是错误的。

# 使用 cookies

HTTP 协议是无状态的。任何给定的请求都没有关于先前请求的信息。对于服务器来说，这意味着确定两个请求是否来自同一个浏览器是不可能的。为了解决这个问题，发明了 cookie。cookie 主要用于在客户端（通常是浏览器）和服务器之间共享状态，存在于浏览器中的小型文本文件。

Cookie 是不安全的。Cookie 信息在服务器和客户端之间以纯文本形式流动。中间存在任意数量的篡改点。例如，浏览器允许轻松访问它们。这是一个好主意，因为没有人希望他们的浏览器或本地机器上的信息被隐藏，超出他们的控制。

尽管如此，cookie 也被广泛用于维护状态信息，或者维护状态信息的指针，特别是在用户会话或其他身份验证方案的情况下。

假设您对 cookie 的一般功能很熟悉。在这里，我们将讨论 Node HTTP 服务器如何获取、解析和设置 cookie。我们将使用一个回显发送 cookie 值的服务器的示例。如果没有 cookie 存在，服务器将创建该 cookie，并指示客户端再次请求它。

考虑以下代码：

```js
const http = require('http');
const url = require('url');
http.createServer((request, response) => {
  let cookies = request.headers.cookie;
  if(!cookies) {
    let cookieName = "session";
    let cookieValue = "123456";
    let numberOfDays = 4;
    let expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + numberOfDays);

    let cookieText = `${cookieName}=${cookieValue};expires=${expiryDate.toUTCString()};`;
    response.setHeader('Set-Cookie', cookieText);
    response.writeHead(302, {'Location': '/'});
    return response.end();
  }

  cookies.split(';').forEach(cookie => {
    let m = cookie.match(/(.*?)=(.*)$/);
    cookies[m[1].trim()] = (m[2] || '').trim();
  });

  response.end(`Cookie set: ${cookies.toString()}`);
}).listen(8080);
```

首先，我们创建一个检查请求头中的 cookie 的服务器：

```js
let server = http.createServer((request, response) => {
  let cookies = request.headers.cookie;
  ...
```

请注意，cookie 存储为`request.headers`的`cookie`属性。如果该域不存在 cookie，我们将需要创建一个，给它命名为`session`，值为`123456`：

```js
if (!cookies) {
  ...
  let cookieText = `${cookieName}=${cookieValue};expires=${expiryDate.toUTCString()};`;
  response.setHeader('Set-Cookie', cookieText);
  response.writeHead(302, {
    'Location': '/'
  });
  return response.end();
}
```

如果我们第一次设置了这个 cookie，客户端被指示再次向同一服务器发出请求，使用 302 Found 重定向，指示客户端再次调用我们的服务器位置。由于现在为该域设置了一个 cookie，随后的请求将包含我们的 cookie，我们将处理它：

```js
cookies.split(';').forEach(cookie => {
 let m = cookie.match(/(.*?)=(.*)$/);
 cookies[m[1].trim()] = (m[2] || '').trim();
});
response.end(`Cookie set: ${cookies.toString()}`);
```

现在，如果你访问`localhost:8080`，你应该看到类似于这样的显示：

```js
Cookie set: AuthSession=c3Bhc3F1YWxpOjU5QzkzRjQ3OosrEJ30gDa0KcTBhRk-YGGXSZnT; io=QuzEHrr5tIZdH3LjAAAC
```

# 理解内容类型

客户端通常会传递一个请求头，指示预期的响应 MIME（多用途互联网邮件扩展）类型。客户端还会指示请求体的 MIME 类型。服务器将类似地提供有关响应体的 MIME 类型的头信息。例如，HTML 的 MIME 类型是 text/html。

正如我们所见，HTTP 响应有责任设置描述其包含的实体的头。同样，`GET`请求通常会指示资源类型，MIME 类型，它期望作为响应。这样的请求头可能看起来像这样：

```js
Accept: text/html
```

接收这样的指令的服务器有责任准备一个符合发送的 MIME 类型的实体主体，如果能够这样做，它应该返回类似的响应头：

```js
Content-Type: text/html; charset=utf-8
```

因为请求还标识了所需的特定资源（例如`/files/index.html`），服务器必须确保返回给客户端的请求资源实际上是正确的 MIME 类型。虽然看起来很明显，由扩展名`html`标识的资源实际上是 MIME 类型 text/html，但这并不确定——文件系统不会阻止将图像文件命名为`html`扩展名。解析扩展名是一种不完美的确定文件类型的方法。我们需要做更多的工作。

UNIX 的`file`程序能够确定系统文件的 MIME 类型。例如，可以通过运行以下命令来确定没有扩展名的文件（例如`resource`）的 MIME 类型：

```js
file --brief --mime resource
```

我们传递参数指示`file`输出资源的 MIME 类型，并且输出应该是简要的（只有 MIME 类型，没有其他信息）。这个命令可能返回类似于`text/plain; charset=us-ascii`的内容。在这里，我们有一个解决问题的工具。

有关文件实用程序的更多信息，请参阅：[`man7.org/linux/man-pages/man1/file.1.html`](http://man7.org/linux/man-pages/man1/file.1.html)

回想一下，Node 能够生成子进程，我们有一个解决方案来准确确定系统文件的 MIME 类型的问题。我们可以使用 Node 的`child_process`模块的 Node 命令`exec`方法来确定文件的 MIME 类型，就像这样：

```js
let exec = require('child_process').exec;
exec("file --brief --mime resource", (err, mime) => {
  console.log(mime);
});
```

这种技术在从外部位置流入的文件进行验证时也很有用。遵循“永远不要相信客户端”的原则，检查文件发布到 Node 服务器的`Content-type`头是否与本地文件系统中存在的接收文件的实际 MIME 类型匹配，这总是一个好主意。

# 处理 favicon 请求

当通过浏览器访问 URL 时，通常会注意到浏览器标签中或浏览器地址栏中有一个小图标。这个图标是一个名为`favicon.ico`的图像，它在每个请求中都会被获取。因此，一个 HTTP GET 请求通常会结合两个请求——一个用于获取 favicon，另一个用于获取请求的资源。

Node 开发人员经常对这种重复的请求感到惊讶。任何一个 HTTP 服务器的实现都必须处理 favicon 请求。为此，服务器必须检查请求类型并相应地处理它。以下示例演示了一种这样做的方法：

```js
const http = require('http');
http.createServer((request, response) => { 
  if(request.url === '/favicon.ico') {
    response.writeHead(200, {
      'Content-Type': 'image/x-icon'
    });
    return response.end();
  }
  response.writeHead(200, {
    'Content-Type': 'text/plain'
  });
  response.write('Some requested resource');
  response.end();

}).listen(8080);
```

这段代码将简单地发送一个空的图像流用于 favicon。如果有一个要发送的 favicon，你可以简单地通过响应流推送这些数据，就像我们之前讨论过的那样。

# 处理 POST 数据

在网络应用程序中使用的最常见的`REST`方法之一是 POST。根据`REST`规范，`POST`不是幂等的，与大多数其他众所周知的方法（`GET`、`PUT`、`DELETE`等）相反。这是为了指出`POST`数据的处理往往会对应用程序的状态产生重大影响，因此应该小心处理。

我们现在将讨论处理最常见类型的通过表单提交的`POST`数据。更复杂的`POST`类型——多部分上传——将在第四章中讨论，*使用 Node 访问文件系统*。

让我们创建一个服务器，该服务器将向客户端返回一个表单，并回显客户端使用该表单提交的任何数据。我们需要首先检查请求的`URL`，确定这是一个表单请求还是表单提交，在第一种情况下返回表单的`HTML`，在第二种情况下解析提交的数据：

```js
const http = require('http');
const qs = require('querystring');

http.createServer((request, response) => {
   let body = "";
   if(request.url === "/") {
      response.writeHead(200, {
         "Content-Type": "text/html"
      });
      return response.end(
         '<form action="/submit" method="post">\
         <input type="text" name="sometext">\
         <input type="submit" value="Send some text">\
         </form>'
      );
   }
}).listen(8080);
```

请注意，我们响应的表单只有一个名为`sometext`的字段。这个表单应该以`sometext=entered_text`的形式将数据 POST 到路径`/submit`。为了捕获这些数据，添加以下条件：

```js
if(request.url === "/submit") {
   request.on('readable', () => {
      let data = request.read();
      data && (body += data);
   });
   request.on('end', () => {
      let fields = qs.parse(body);
      response.end(`Thanks for sending: ${fields.sometext}`);
   });
}
```

一旦我们的`POST`流结束，我们使用`Querystring.parse`解析主体，从中得到一个键/值映射，我们可以从中取出名称为`sometext`的表单元素的值，并向客户端响应我们已经收到他们的数据。

# 使用 Node 创建和流式传输图像

经过对启动和转移数据流的主要策略的讨论，让我们通过创建一个服务来流式传输（恰当地命名为）**PNG**（**可移植网络图形**）图像来实践这个理论。然而，这不会是一个简单的文件服务器。目标是通过将在单独的进程中执行的**ImageMagick**转换操作的输出流管道传输到 HTTP 连接的响应流中来创建 PNG 数据流，其中转换器正在将 Node 运行时中存在的虚拟**DOM**（**文档对象模型**）中生成的另一个**SVG**（**可缩放矢量图形**）数据流进行转换。让我们开始吧。

这个示例的完整代码可以在你的代码包中找到。

我们的目标是使用 Node 根据客户端请求动态生成饼图。客户端将指定一些数据值，然后将生成表示该数据的 PNG。我们将使用**D3.js**库，该库提供了用于创建数据可视化的 Javascript API，以及**jsdom** NPM 包，该包允许我们在 Node 进程中创建虚拟 DOM。此外，我们将使用**ImageMagick**将**SVG（可缩放矢量图形）**表示转换为**PNG（便携式网络图形）**表示。

访问[`github.com/tmpvar/jsdom`](https://github.com/tmpvar/jsdom)了解**jsdom**的工作原理，访问[`d3js.org/`](https://d3js.org/)了解如何使用 D3 生成 SVG。

此外，我们创建的 PNG 将被写入文件。如果未来的请求将相同的查询参数传递给我们的服务，我们将能够立即传送现有的渲染结果，而无需重新生成。

饼图代表一系列百分比，其总和填满圆的总面积，以切片形式可视化。我们的服务将根据客户端发送的值绘制这样的图表。在我们的系统中，客户端需要发送总和为 1 的值，例如.5，.3，.2。因此，当服务器收到请求时，需要获取查询参数，并创建一个将来与相同查询参数映射的唯一键：

```js
let values = url.parse(request.url, true).query['values'].split(",");
let cacheKey = values.sort().join('');
```

在这里，我们看到 URL 模块正在起作用，提取我们的数据值。此外，我们通过首先对值进行排序，然后将它们连接成一个字符串来创建一个键，我们将使用它作为缓存的饼图的文件名。我们对值进行排序的原因是：通过发送.5 .3 .2 和.3 .5 .2 可以得到相同的图表。通过排序和连接，这两者都变成了文件名.2 .3 .5。

在生产应用程序中，需要做更多工作来确保查询格式正确，数学上正确等。在我们的示例中，我们假设正在发送正确的值。

# 创建、缓存和发送 PNG 表示

首先，安装 ImageMagick：[`www.imagemagick.org/script/download.php`](http://www.imagemagick.org/script/download.php)。我们将生成一个 Node 进程来与安装的二进制文件进行交互，如下所示。

在动态构建图表之前，假设已经存在一个存储在变量`svg`中的 SVG 定义，它将包含类似于这样的字符串：

```js
<svg width="200" height="200">
<g transform="translate(100,100)">
<defs>
  <radialgradient id="grad-0" gradientUnits="userSpaceOnUse" cx="0" cy="0" r="100">
  <stop offset="0" stop-color="#7db9e8"></stop>
 ...
```

要将 SVG 转换为 PNG，我们将生成一个子进程来运行 ImageMagick 转换程序，并将我们的 SVG 数据流式传输到该进程的`stdin`，该进程将输出一个 PNG。在接下来的示例中，我们将继续这个想法，将生成的 PNG 流式传输到客户端。

我们将跳过服务器样板代码 -- 只需说明服务器将在 8080 端口运行，并且将有一个客户端调用一些数据来生成图表。重要的是我们如何生成和流式传输饼图。

客户端将发送一些查询字符串参数，指示此图表的`values`（例如 4,5,8，切片的相对大小）。服务器将使用 jsdom 模块生成一个“虚拟 DOM”，其中插入了 D3 图形库，以及一些 javascript（在您的代码包中的`pie.js`），以便获取我们收到的值并使用 D3 绘制 SVG 饼图，所有这些都在服务器端虚拟 DOM 中完成。然后，我们获取生成的 SVG 代码，并使用 ImageMagick 将其转换为 PNG。为了允许缓存，我们使用缓存值形成一个字符串文件名作为 cacheKey 存储这个 PNG，并在写入时将流式传输的 PNG 返回给客户端：

```js
jsdom.env({
   ...
   html : `<!DOCTYPE html><div id="pie" style="width:${width}px;height:${height}px;"></div>`,
   scripts : ['d3.min.js','d3.layout.min.js','pie.js'], 
   done : (err, window) => {
      let svg = window.insertPie("#pie", width, height, values).innerHTML;
      let svgToPng = spawn("convert", ["svg:", "png:-"]);
      let filewriter = fs.createWriteStream(cacheKey);

      filewriter.on("open", err => {
         let streamer = new stream.Transform();
         streamer._transform = function(data, enc, cb) {
            filewriter.write(data);
            this.push(data);
            cb();
         };
         svgToPng.stdout.pipe(streamer).pipe(response);
         svgToPng.stdout.on('finish', () => response.end());

         // jsdom's domToHTML will lowercase element names
         svg = svg.replace(/radialgradient/g,'radialGradient');

         svgToPng.stdin.write(svg);
         svgToPng.stdin.end();
         window.close();
      });
   }
});    
```

回顾我们关于流的讨论，这里发生的事情应该是清楚的。我们使用 jsdom 生成一个 DOM（`window`），运行`insertPie`函数生成 SVG，然后生成两个流：一个用于写入缓存文件，一个用于 ImageMagick 进程。使用`TransformStream`（可读和可写）我们实现了其抽象的`_transform`方法，以期望从 ImageMagick 流的`stdout`输入数据，将该数据写入本地文件系统，然后重新将数据推回流中，然后将其传送到响应流。我们现在可以实现所需的流链接：

```js
svgToPng.stdout.pipe(streamer).pipe(response);
```

客户端接收到一个饼图，并且一个副本被写入到本地文件缓存中。在请求的饼图已经被渲染的情况下，它可以直接从文件系统中进行流式传输。

```js
fs.exists(cacheKey, exists => {
  response.writeHead(200, {
    'Content-Type': 'image/png'
  });
  if (exists) {
    fs.createReadStream(cacheKey).pipe(response);
    return;
  }
 ...
```

如果您启动服务器并将以下内容粘贴到浏览器中：

```js
http://localhost:8080/?values=3,3,3,3,3
```

您应该看到一个饼图显示出来：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/53cbc2e5-db0f-4769-8b62-ea7fddcc0431.png)

虽然有些不自然，但希望这能展示不同进程链如何通过流连接，避免在内存中存储任何中间数据，特别是在通过高流量网络服务器传递数据时尤其有用。

# 摘要

正如我们所了解的，Node 的设计者成功地创建了一个简单、可预测且方便的解决方案，解决了在不同来源和目标之间实现高效 I/O 的挑战性设计问题，同时保持了易于管理的代码。它的抽象流接口促进了一致的可读和可写接口的实例化，以及将这个接口扩展到 HTTP 请求和响应、文件系统、子进程和其他数据通道，使得使用 Node 进行流编程成为一种愉快的体验。

现在我们已经学会了如何设置 HTTP 服务器来处理从许多同时连接的客户端接收的数据流，以及如何向这些客户端提供缓冲流的数据，我们可以开始更深入地参与使用 Node 构建企业级并发实时系统的任务。


# 第四章：使用 Node 访问文件系统

"我们有持久对象——它们被称为文件。"

– Ken Thompson

文件只是一块数据，通常保存在硬盘等硬介质上。文件通常由一系列字节组成，其编码映射到其他模式，如一系列数字或电脉冲。几乎可以有无限数量的编码，其中一些常见的是文本文件、图像文件和音乐文件。文件具有固定长度，要读取它们，必须由某种阅读器解密其字符编码，例如 MP3 播放器或文字处理器。

当文件在传输中，从某个存储设备吸取后通过电缆移动时，它与通过电线运行的任何其他数据流没有区别。它以前的固态只是一个稳定的蓝图，可以轻松且无限地复制。

我们已经看到事件流如何反映了 Node 设计的核心设计原则，其中字节流应该被读取和写入，并被传送到其他流中，发出相关的流事件，如`end`。文件很容易被理解为数据的容器，其中充满了可以部分或完整提取或插入的字节。

除了它们与流的自然相似性之外，文件还显示了对象的特征。文件具有描述访问文件内容的接口的属性——具有属性和相关访问方法的数据结构。

文件系统反映了文件应该如何组织的一些概念——它们如何被识别，它们存储在哪里，如何被访问等等。UNIX 用户常用的文件系统是 UFS（Unix 文件系统），而 Windows 用户可能熟悉 NTFS（新技术文件系统）。

有趣的是，Plan 9 操作系统的设计者（包括 Ken Thompson 在内的一个团队）决定将*所有*控制接口表示为文件系统，以便所有系统接口（跨设备，跨应用程序）都被建模为文件操作。将文件视为一等公民是 UNIX 操作系统也使用的哲学；使用文件作为命名管道和套接字的引用等等，使开发人员在塑造数据流时拥有巨大的力量。

文件对象也是强大的，它们所在的系统公开了必须易于使用、一致且非常快速的基本 I/O 接口。不足为奇，Node 的`file`模块公开了这样的接口。

我们将从这两个角度考虑在 Node 中处理文件：文件数据内容如何流入和流出（读取和写入），以及如何修改文件对象的属性，如更改文件权限。

此外，我们将介绍 Node 服务器的责任，接受文件上传并处理文件请求。通过示例演示目录迭代器和文件服务器，Node 的文件系统 API 的全部范围和行为应该变得清晰。

最后，我们将使用 GitHub 的 Electron 框架将 JavaScript 带回桌面，制作我们自己的桌面应用程序，一个简单的文件浏览器。

# 目录和文件夹的迭代

通常，文件系统将文件分组成集合，通常称为目录。通过目录导航以找到单个文件。一旦找到目标文件，文件对象必须被包装成一个公开文件内容以供读取和写入的接口。

由于 Node 开发通常涉及创建既接受又发出文件数据的服务器，因此应该清楚这个活跃和重要的 I/O 层的传输速度有多重要。正如前面提到的，文件也可以被理解为对象，而对象具有某些属性。

# 文件类型

在 UNIX 系统上通常遇到的有六种类型的文件：

+   **普通文件**：这些文件包含一维字节数组，不能包含其他文件。

+   **目录**：这些也是以特殊方式实现的文件，可以描述其他文件的集合。

+   **套接字**：用于 IPC，允许进程交换数据。

+   **命名管道**：像`ps aux | grep node`这样的命令创建了一个管道，

一旦操作终止，它就会被销毁。命名管道是持久的、可寻址的，并且可以被多个进程用于 IPC。

+   **设备文件**：这些是 I/O 设备的表示，接受数据流的进程；`/dev/null`通常是字符设备文件的一个例子（接受 I/O 的串行数据流），`/dev/sda`是块设备文件的一个例子（允许数据块的随机访问 I/O），代表一个数据驱动器。

+   **链接**：这些是指向其他文件的指针，有两种类型：硬链接和符号链接。硬链接直接指向另一个文件，并且与目标文件无法区分。符号链接是间接指针，并且可以与普通文件区分开。

大多数 Node 文件系统交互只涉及前两种类型，第三种类型只是通过 Node API 间接涉及。对剩余类型的更深入解释超出了本讨论的范围。然而，Node 通过`file`模块提供了完整的文件操作套件，读者应该至少对文件类型的全部范围和功能有一定的了解。

学习命名管道将奖励那些对了解 Node 如何设计以与流和管道一起工作感兴趣的读者。在终端中尝试这个：

```js
$ mkfifo namedpipe
```

如果你得到了当前目录的扩展列表`-ls -l`，将会显示类似于这样的列表：

```js
prw-r--r-- 1 system staff 0 May 01 07:52 namedpipe
```

注意文件模式中的`p`标志（第一个段，带有破折号）。你已经创建了一个命名的`(p)ipe`。现在，输入到同一个终端中，将一些字节推送到命名管道中：

```js
echo "hello" > namedpipe
```

看起来好像进程已经挂起了。其实没有——管道，就像水管一样，必须在两端打开才能完成它们刷新内容的工作。我们已经把一些字节放进去了……现在呢？

打开另一个终端，导航到相同的目录，并输入以下内容：

```js
$ cat namedpipe.
```

`hello`将出现在第二个终端中，作为`namedpipe`的内容被刷新。请注意，第一个终端不再挂起——它已经刷新了。如果你回忆一下第三章中关于 Node 流的讨论，*在节点和客户端之间流式传输数据*，你会注意到与 Unix 管道有些相似之处，这是有意为之的。

# 文件路径

Node 提供的大多数文件系统方法都需要操作文件路径，为此，我们使用`path`模块。我们可以使用这个模块来组合、分解和关联路径。不要手动拆分你自己的路径字符串，也不要使用正则表达式和连接例程，尝试通过将路径操作委托给这个模块来规范化你的代码：

+   在处理源不可信或不可靠的文件路径字符串时，使用`path.normalize`来确保可预测的格式：

```js
const path = require('path'); 
path.normalize("../one////two/./three.html"); 
// -> ../one/two/three.html 
```

+   在构建路径段时，使用`path.join`：

```js
path.join("../", "one", "two", "three.html"); 
// -> ../one/two/three.html 
```

+   使用`path.dirname`来剪切路径中的目录名：

```js
path.dirname("../one/two/three.html"); 
// ../one/two
```

+   使用`path.basename`来操作最终的路径段：

```js
path.basename("../one/two/three.html"); 
// -> three.html 

// Remove file extension from the basename 
path.basename("../one/two/three.html", ".html"); 
// -> three 
```

+   使用`path.extname`从路径字符串的最后一个句点（`.`）开始切片到末尾：

```js
var pstring = "../one/two/three.html"; 
path.extname(pstring); 
// -> .html 
```

+   使用`path.relative`来找到从一个绝对路径到另一个绝对路径的相对路径：

```js
path.relative( 
  '/one/two/three/four',  
  '/one/two/thumb/war' 
); 
// -> ../../thumb/war 
```

+   使用`path.resolve`来将路径指令列表解析为绝对路径：

```js
path.resolve('/one/two', '/three/four'); 
// -> /three/four 
path.resolve('/one/two/three', '../', 'four', '../../five') 
// -> /one/five 
```

将传递给`path.resolve`的参数视为一系列`cd`调用：

```js
cd /one/two/three 
cd ../ 
cd four 
cd ../../five 
pwd 
// -> /one/five 
```

如果传递给`path.resolve`的参数列表未能提供绝对路径，那么当前目录名称也会被使用。例如，假设我们在`/users/home/john/`中：

```js
path.resolve('one', 'two/three', 'four'); 
// -> /users/home/john/one/two/three/four
```

这些参数解析为一个相对路径`one/two/three/four`，因此，它是以当前目录名称为前缀的。

# 文件属性

文件对象公开了一些属性，包括有关文件数据的一组有用的元数据。例如，如果使用 Node 运行 HTTP 服务器，将需要确定通过 GET 请求的任何文件的文件长度。确定文件上次修改的时间在许多类型的应用程序中都有用。

要读取文件的属性，使用`fs.stat`：

```js
fs.stat("file.txt", (err, stats) => { 
  console.log(stats); 
}); 
```

在上面的例子中，`stats`将是描述文件的`fs.Stats`对象：

```js
  dev: 2051, // id of device containing this file 
  mode: 33188, // bitmask, status of the file 
  nlink: 1, // number of hard links 
  uid: 0, // user id of file owner 
  gid: 0, // group id of file owner 
  rdev: 0, // device id (if device file) 
  blksize: 4096, // I/O block size 
  ino: 27396003, // a unique file inode number 
  size: 2000736, // size in bytes 
  blocks: 3920, // number of blocks allocated 
  atime: Fri May 3 2017 15:39:57 GMT-0500 (CDT), // last access 
  mtime: Fri May 3 2017 17:22:46 GMT-0500 (CDT), // last modified 
  ctime: Fri May 3 2017 17:22:46 GMT-0500 (CDT)  // last status change 
```

`fs.Stats`对象公开了几个有用的方法来访问文件属性数据：

+   使用`stats.isFile`来检查标准文件

+   使用`stats.isDirectory`来检查目录

+   使用`stats.isBlockDevice`来检查块设备文件

+   使用`stats.isCharacterDevice`来检查字符类型设备文件

+   在`fs.lstat`之后使用`stats.isSymbolicLink`来查找符号链接

+   使用`stats.isFIFO`来识别命名管道

+   使用`stats.isSocket`来检查套接字

还有两个可用的`stat`方法：

+   `fs.fstat(fd, callback)`: 类似于`fs.stat`，只是传递了文件描述符`fd`而不是文件路径

+   `fs.lstat(path, callback)`: 对符号链接进行`fs.stat`将返回目标文件的`fs.Stats`对象，而`fs.lstat`将返回链接文件本身的`fs.Stats`对象

以下两种方法简化了文件时间戳的操作：

+   `fs.utimes(path, atime, mtime, callback)`: 更改`path`上的文件的访问和修改时间戳。文件的访问和修改时间以 JavaScript `Date`对象的实例存储。例如，`Date.getTime`将返回自 1970 年 1 月 1 日午夜（UTC）以来经过的毫秒数。

+   `fs.futimes(fd, atime, mtime, callback)`: 更改文件描述符`fd`上的访问和修改时间戳；它类似于`fs.utimes`。

有关使用 JavaScript 操作日期和时间的更多信息，请访问：

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date)。

# 打开和关闭文件

Node 项目的一个非正式规则是不要不必要地从现有的操作系统实现细节中抽象出来。正如我们将看到的，文件描述符的引用出现在整个 Node 的文件 API 中。对于**POSIX**（**可移植操作系统接口**），文件描述符只是一个（非负）整数，唯一地引用特定的文件。由于 Node 的文件系统方法是基于 POSIX 建模的，因此文件描述符在 Node 中表示为整数并不奇怪。

回想一下我们讨论过的设备和操作系统的其他元素是如何表示为文件的，那么标准 I/O 流（`stdin`，`stdout`，`stderr`）也会有文件描述符是合理的。事实上，情况就是这样的：

```js
console.log(process.stdin.fd); // 0 
console.log(process.stdout.fd); // 1 
console.log(process.stderr.fd); // 2 

fs.fstat(1, (err, stat) => { 
  console.log(stat); // an fs.Stats object 
}); 
```

文件描述符易于获取，并且是传递文件引用的便捷方式。让我们看看如何通过检查如何执行低级文件打开和关闭操作来创建和使用文件描述符。随着本章的进行，我们将研究更精细的文件流接口。

# fs.open(path, flags, [mode], callback)

尝试在`path`处打开文件。`callback`将接收操作的任何异常作为其第一个参数，并将文件描述符作为其第二个参数。在这里，我们打开一个文件进行读取：

```js
fs.open("path.js", "r", (err, fileDescriptor) => { 
  console.log(fileDescriptor); // An integer, like `7` or `23` 
}); 
```

`flags`接收一个字符串，指示调用者期望在返回的文件描述符上执行的操作类型。它们的含义应该是清楚的。

+   `r`：打开文件进行读取，如果文件不存在则抛出异常。

+   `r+`：打开文件进行读取和写入，如果文件不存在则抛出异常。

+   `w`：打开文件进行写入，如果文件不存在则创建文件，并且如果文件存在则将文件截断为零字节。

+   `wx`：类似于`w`，但以独占模式打开文件，这意味着如果文件已经存在，它将**不会被打开**，打开操作将失败。如果多个进程可能同时尝试创建相同的文件，则这很有用。

+   `w+`：打开文件进行读取和写入，如果文件不存在则创建文件，并且如果文件存在则将文件截断为零字节。

+   `wx+`：类似于`wx`（和`w`），此外还打开文件进行读取。

+   `a`：打开文件进行追加，如果文件不存在则创建文件。

+   `ax`：类似于**a**，但以独占模式打开文件，这意味着如果文件已经存在，它将**不会被打开**，打开操作将失败。如果多个进程可能同时尝试创建相同的文件，则这很有用。

+   `a+`：打开文件进行读取和追加，如果文件不存在则创建文件。

+   `ax+`：类似于`ax`（和`a`），此外还打开文件进行读取。

当操作可能创建新文件时，使用可选的`mode`以八进制数字形式设置此文件的权限，默认为 0666（有关八进制权限的更多信息，请参阅`fs.chmod`）：

```js
fs.open("index.html", "w", 755, (err, fd) => { 
   fs.read(fd, ...); 
}); 
```

# fs.close(fd, callback)

`fs.close(fd, callback)` 方法关闭文件描述符。回调函数接收一个参数，即调用中抛出的任何异常。关闭所有已打开的文件描述符是一个好习惯。

# 文件操作

Node 实现了用于处理文件的标准 POSIX 函数，UNIX 用户会很熟悉。我们不会深入讨论这个庞大集合的每个成员，而是专注于一些常用的例子。特别是，我们将深入讨论打开文件描述符和操作文件数据的方法，读取和操作文件属性，以及在文件系统目录中移动。然而，鼓励读者尝试整套方法，以下列表简要描述了这些方法。请注意，所有这些方法都是异步的，非阻塞文件操作。

# fs.rename(oldName, newName, callback)

`fs.rename(oldName, newName, callback)` 方法将`oldName`处的文件重命名为`newName`。回调函数接收一个参数，即调用中抛出的任何异常。

# fs.truncate(path, len, callback)

`fs.truncate(path, len, callback)` 方法通过`len`字节更改`path`处文件的长度。如果`len`表示比文件当前长度更短的长度，则文件将被截断为该长度。如果`len`更大，则文件长度将通过附加空字节（x00）进行填充，直到达到`len`。回调函数接收一个参数，即调用中抛出的任何异常。

# fs.ftruncate(fd, len, callback)

`fs.ftruncate(fd, len, callback)` 方法类似于`fs.truncate`，不同之处在于不是指定文件，而是将文件描述符作为`fd`传递。

# fs.chown(path, uid, gid, callback)

`fs.chown(path, uid, gid, callback)` 方法更改`path`处文件的所有权。使用此方法设置用户`uid`或组`gid`是否可以访问文件。回调函数接收一个参数，即调用中抛出的任何异常。

# fs.fchown(fd, uid, gid, callback)

`fs.fchown(fd, uid, gid, callback)` 方法与`fs.chown`类似，不同之处在于不是指定文件路径，而是将文件描述符作为`fd`传递。

# fs.lchown(path, uid, gid, callback)

`fs.lchown(path, uid, gid, callback)` 方法与`fs.chown`类似，不同之处在于对于符号链接，更改的是链接文件本身的所有权，而不是引用的链接。

# fs.chmod(path, mode, callback)

`fs.chmod(path, mode, callback)` 方法更改`path`处文件的`mode`（权限）。您正在设置该文件的读取（4）、写入（2）和执行（1）位，可以以八进制数字形式发送：

|  | [r]读取 | [w]写入 | E[x]执行 | 总计 |
| --- | --- | --- | --- | --- |
| 所有者 | **4** | **2** | **1** | **7** |
| 组 | **4** | **0** | **1** | **5** |
| 其他 | **4** | **0** | **1** | **5** |
|  |  |  |  | **chmod(755)** |

您也可以使用符号表示，例如`g+rw`表示组读写，类似于我们之前在`file.open`中看到的参数。有关设置文件模式的更多信息，请参阅：[`en.wikipedia.org/wiki/Chmod`](http://en.wikipedia.org/wiki/Chmod)。

回调函数接收一个参数，在调用中抛出的任何异常。

# fs.fchmod(fd, mode, callback) ----

`fs.fchmod(fd, mode, callback)`方法类似于`fs.chmod`，不同之处在于不是指定文件路径，而是将文件描述符作为`fd`传递。

# fs.lchmod(path, mode, callback)

`fs.lchmod(path, mode, callback)`方法类似于`fs.chmod`，不同之处在于对于符号链接，只会更改链接文件本身的权限，而不会更改引用链接的权限。

# fs.link(srcPath, dstPath, callback)

`fs.link(srcPath, dstPath, callback)`在`srcPath`和`dstPath`之间创建一个硬链接。这是创建指向完全相同文件的许多不同路径的一种方法。例如，以下目录包含一个`target.txt`文件和两个硬链接—`a.txt`和`b.txt`—它们各自指向这个文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/071fe6c3-13e6-4da9-8a4c-5df632547f06.png)

请注意，`target.txt`是空的。如果更改目标文件的内容，链接文件的长度也将更改。考虑更改目标文件的内容：

```js
echo "hello" >> target.txt  
```

这导致了这种新的目录结构，清楚地展示了硬引用：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/a761ddfa-c59c-4fa5-8c97-f744588b811a.png)

回调函数接收一个参数，在调用中抛出的任何异常。

# fs.symlink(srcPath, dstPath, [type], callback)

`fs.symlink(srcPath, dstPath, [type], callback)`方法在`srcPath`和`dstPath`之间创建一个符号链接。与使用`fs.link`创建的硬链接不同，符号链接只是指向其他文件的指针，并且本身不会对目标文件的更改做出响应。默认的链接`type`是文件。其他选项是目录和 junction，最后一个是 Windows 特定类型，在其他系统上被忽略。回调函数接收一个参数，在调用中抛出的任何异常。

将我们在`fs.link`讨论中描述的目录更改与以下内容进行比较：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/e0bc810e-ef05-4e42-af3f-9c69b5d91603.png)

与硬链接不同，当它们的目标文件（在本例中为`target.txt`）更改长度时，符号链接的长度不会改变。在这里，我们看到将目标长度从零字节更改为六字节对任何绑定的符号链接的长度没有影响：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/117fd84c-d6db-404a-b48f-87c81a872b97.png)

# fs.readlink(path, callback)

给定`path`处的符号链接返回目标文件的文件名：

```js
fs.readlink('a.txt', (err, targetFName) => { 
  console.log(targetFName); // target.txt 
}); 
```

# fs.realpath(path, [cache], callback)

`fs.realpath(path, [cache], callback)`方法尝试找到`path`处文件的真实路径。这是查找文件的绝对路径，解析符号链接，甚至清理多余的斜杠和其他格式不正确的路径的有用方法。考虑这个例子：

```js
fs.realpath('file.txt', (err, resolvedPath) => { 
  console.log(resolvedPath); // `/real/path/to/file.txt` 
}); 
```

或者，考虑这个：

```js
fs.realpath('.////./file.txt', (err, resolvedPath) => { 
  // still `/real/path/to/file.txt` 
}); 
```

如果要解析的一些路径段已知，可以传递一个映射路径的`cache`：

```js
let cache = {'/etc':'/private/etc'}; 
fs.realpath('/etc/passwd', cache, (err, resolvedPath) => { 
  console.log(resolvedPath); // `/private/etc/passwd` 
});
```

# fs.unlink(path, callback)

`fs.unlink(path, callback)`方法删除`path`处的文件，相当于删除文件。回调函数接收一个参数，在调用中抛出的任何异常。

# fs.rmdir(path, callback)

`fs.rmdir(path, callback)`方法删除`path`处的目录，相当于删除目录。

请注意，如果目录不为空，这将抛出异常。回调函数接收一个参数，在调用中抛出的任何异常。

# fs.mkdir(path, [mode], callback)

`fs.mkdir(path, [mode], callback)`方法在`path`处创建一个目录。要设置新目录的模式，请使用`fs.chmod`中描述的权限位图。

请注意，如果此目录已经存在，将抛出异常。回调函数接收一个参数，在调用中抛出的任何异常。

# fs.exists(path, callback)

`fs.exists(path, callback)`方法检查`path`处是否存在文件。回调将接收一个布尔值 true 或 false。

# fs.fsync(fd, callback)

在发出写入文件的某些数据的请求和该数据完全存在于存储设备上之间的瞬间，候选数据存在于核心系统缓冲区中。这种延迟通常不相关，但在一些极端情况下，例如系统崩溃，有必要坚持文件反映稳定存储设备上已知状态。

`fs.fsync`将由文件描述符`fd`引用的文件的所有核心数据复制到磁盘

（或其他存储设备）。回调函数接收一个参数，即调用中抛出的任何异常。

# 同步性

方便的是，Node 的`file`模块为我们介绍的每个异步方法提供了同步对应方法，以`Sync`为后缀表示。例如，`fs.mkdir`的同步版本是`fs.mkdirSync`。

同步调用还能够直接返回其结果，无需回调。在第三章中演示了在 HTTPS 服务器中创建流数据跨节点和客户端的过程中，我们既看到了同步代码的一个很好的用例，也看到了直接分配结果而无需回调的示例：

```js
key: fs.readFileSync('server-key.pem'), 
cert: fs.readFileSync('server-cert.pem') 
```

嘿！Node 不是严格执行异步编程吗？阻塞代码不总是错误的吗？鼓励所有开发人员遵循非阻塞设计，并鼓励避免同步编码——如果面临一个同步操作似乎是唯一的解决方案的问题，那么很可能是问题被误解了。然而，确实存在一些需要在执行进一步指令之前完全存在于内存中的文件对象的边缘情况（阻塞操作）。如果这是唯一可能的解决方案（这可能并不是！），Node 给开发人员提供了打破异步传统的权力。

开发人员经常使用的一个同步操作（也许是在不知不觉中）是`require`指令：

```js
require('fs') 
```

在`require`所指向的依赖项完全初始化之前，后续的 JavaScript 指令将不会执行（文件加载会阻塞事件循环）。*Ryan Dahl*在 2013 年 7 月的 Google Tech Talk 上提到，他在引入同步操作（特别是文件操作）到 Node 中遇到了困难：

根据[`www.youtube.com/watch?v=F6k8lTrAE2g`](http://www.youtube.com/watch?v=F6k8lTrAE2g)，

“我认为这是一个可以接受的妥协。几个月来，放弃异步模块系统的纯度让我感到痛苦。但是，我认为这样做是可以的。

……

能够只需插入“require, require, require”而无需执行 onload 回调，这样简化了代码很多……我认为这是一个相对可以接受的妥协。[...]你的程序实际上有两个部分：加载和启动阶段……你并不真的关心它运行得有多快……你将加载模块和其他东西……你的守护进程的设置阶段通常是同步的。当你进入用于处理请求的事件循环时，你需要非常小心。[...]我会给人们同步文件 I/O。如果他们在服务器上这样做……那不会太糟糕，对吧？重要的是永远不要让他们进行同步网络 I/O。”

同步代码的优势在于极其可预测，因为在完成此指令之前不会发生其他任何事情。当启动服务器时，这种情况很少发生，Dahl 建议一点确定性和简单性可以走得更远。例如，服务器初始化时加载配置文件可能是有意义的。

有时，在 Node 开发中使用同步命令的愿望只是在请求帮助；开发人员被深度嵌套的回调结构所压倒。如果曾经面对这种痛苦，请尝试一些在第二章中提到的回调控制库，*理解异步事件驱动编程*。

# 浏览目录

让我们应用我们所学到的知识，创建一个目录迭代器。这个项目的目标是创建一个函数，该函数将接受一个目录路径，并返回一个反映文件目录层次结构的 JSON 对象，其节点由文件对象组成。我们还将使我们的目录遍历器成为一个更强大的基于事件的解析器，与 Node 哲学一致。

要移动到嵌套目录中，必须首先能够读取单个目录。Node 的文件系统库提供了`fs.readdir`命令来实现这一目的：

```js
fs.readdir('.', (err, files) => { 
  console.log(files); // list of all files in current directory 
}); 
```

记住一切都是文件，我们需要做的不仅仅是获取目录列表；我们必须确定文件列表中每个成员的类型。通过添加`fs.stat`，我们已经完成了大部分逻辑：

```js
(dir => { 
  fs.readdir(dir, (err, list) => { 
    list.forEach(file => { 
      fs.stat(path.join(dir, file), (err, stat) => { 
        if (stat.isDirectory()) { 
          return console.log(`Found directory: ${file}`); 
        }
        console.log(`Found file: ${file}`); 
      }); 
    }); 
  }); 
})("."); 
```

这个自执行函数接收一个目录路径参数`(".")`，将该目录列表折叠成一个文件名数组，为其中的每个文件获取一个`fs.Stats`对象，并根据指示的文件类型（目录或非目录）做出决定下一步该做什么。在这一点上，我们也已经映射了一个单个目录。

我们现在必须映射目录中的目录，将结果存储在反映嵌套文件系统树的 JSON 对象中，树上的每个叶子都是一个文件对象。递归地将我们的目录读取器函数路径传递给子目录，并将返回的结果附加为最终对象的分支是下一步：

```js
let walk = (dir, done) => { 
  let results = {}; 
  fs.readdir(dir, (err, list) => { 
    let pending = list.length;    
    if (err || !pending) { 
      return done(err, results); 
    } 
    list.forEach(file => { 
      let dfile = require('path').join(dir, file); 
      fs.stat(dfile, (err, stat) => { 
        if(stat.isDirectory()) { 
          return walk(dfile, (err, res) => { 
            results[file] = res; 
            !--pending && done(null, results); 
          }); 
        }  
        results[file] = stat; 
        !--pending && done(null, results); 
      }); 
    }); 
  }); 
}; 
walk(".", (err, res) => { 
  console.log(require('util').inspect(res, {depth: null})); 
});
```

我们创建一个`walk`方法，该方法接收一个目录路径和一个回调函数，该回调函数在`walk`完成时接收目录图或错误，遵循 Node 的风格。创建一个非常快速的、非阻塞的文件树遍历器，包括文件统计信息，不需要太多的代码。

现在，让我们在遇到目录或文件时发布事件，使任何未来的实现都能够灵活地构建自己的文件系统表示。为此，我们将使用友好的`EventEmitter`对象：

```js
let walk = (dir, done, emitter) => { 
  ... 
  emitter = emitter || new (require('events').EventEmitter); 
  ... 
  if (stat.isDirectory()) { 
    emitter.emit('directory', dfile, stat); 
    return walk(dfile, (err, res) => { 
      results[file] = res; 
      !--pending && done(null, results); 
    }, emitter); 
  }  
  emitter.emit('file', dfile, stat); 
  results[file] = stat; 
  ... 
  return emitter; 
} 
walk("/usr/local", (err, res) => { 
  ... 
}).on("directory", (path, stat) => { 
  console.log(`Directory: ${path} - ${stat.size}`); 
}).on("file", (path, stat) => { 
  console.log(`File: ${path} - ${stat.size}`); 
}); 
// File: index.html - 1024 
// File: readme.txt - 2048 
// Directory: images - 106 
// File images/logo.png - 4096 
// ... 
```

现在我们知道如何发现和处理文件，我们可以开始从中读取和写入。

# 从文件中读取

在我们讨论文件描述符时，我们提到了一种打开文件、获取文件描述符并最终通过该引用推送或拉取数据的方法。读取文件是一个常见的操作。有时，精确管理读取缓冲区可能是必要的，Node 允许逐字节控制。在其他情况下，人们只是想要一个简单易用的无花俏流。

# 逐字节读取

`fs.read`方法是 Node 提供的读取文件的最低级别的方法。

# fs.read(fd, buffer, offset, length, position, callback)

文件由有序字节组成，这些字节可以通过它们相对于文件开头的`position`进行寻址（位置零[0]）。一旦我们有

文件描述符`fd`，我们可以开始读取`length`字节数，并将其插入到`Buffer`对象`buffer`中，插入从给定的缓冲区`offset`开始。例如，要将从可读文件`fd`的位置 309 开始的 8,366 字节复制到

一个从`offset`为 100 开始的`buffer`，我们将使用`fs.read(fd, buffer, 100, 8366, 309, callback)`。

以下代码演示了如何以 512 字节块打开和读取文件：

```js
fs.open('path.js', 'r', (err, fd) => { 
  fs.fstat(fd, (err, stats) => { 
    let totalBytes = stats.size; 
    let buffer = Buffer.alloc(totalBytes); 
    let bytesRead = 0; 
    // Each call to read should ensure that chunk size is 
    // within proper size ranges (not too small; not too large). 
    let read = chunkSize => { 
      fs.read(fd, buffer, bytesRead, chunkSize, bytesRead, (err, numBytes, bufRef) => { 
        if((bytesRead += numBytes) < totalBytes) { 
          return read(Math.min(512, totalBytes - bytesRead)); 
        } 
        fs.close(fd); 
        console.log(`File read complete. Total bytes read: ${totalBytes}`); 
        // Note that the callback receives a reference to the 
        // accumulating buffer  
        console.log(bufRef.toString()); 
      }); 
    } 
    read(Math.min(512, totalBytes)); 
  }); 
}); 
```

生成的缓冲区可以被传送到其他地方（包括服务器响应对象）。也可以使用 Node 的`Buffer`对象的方法进行操作，例如使用`buffer.toString("utf8")`将其转换为 UTF8 字符串。

# 一次获取整个文件

通常，我们只需要获取整个文件，而不需要任何仪式或精细控制。Node 提供了一个快捷方法来实现这一点。

# fs.readFile(path, [options], callback)

获取`path`文件中包含的数据可以在一步中完成：

```js
fs.readFile('/etc/passwd', (err, fileData) => { 
  if(err) { 
    throw err; 
  } 
  console.log(fileData); 
  // <Buffer 48 65 6C 6C 6F ... > 
}); 
```

我们看到`callback`接收一个缓冲区。可能更希望以常见编码（如 UTF8）接收文件数据。我们可以使用`options`对象指定返回数据的编码以及读取模式，该对象有两个可能的属性：

+   **encoding**：一个字符串，如`utf8`，默认为 null（无编码）

+   **flag**：文件模式作为字符串，默认为`r`

修改上一个例子：

```js
fs.readFile('/etc/passwd', (err, { encoding : "utf8" }, fileData) => { 
  ... 
  console.log(fileData); 
  // "Hello ..." 
});
```

# 创建可读流

虽然`fs.readFile`是一种完成常见任务的简单方法，但它有一个重大缺点，即在将文件的任何部分发送到回调之前，需要将整个文件读入内存。对于大文件或未知大小的文件，这不是一个好的解决方案。

在上一章中，我们学习了数据流和`Stream`对象。虽然文件可以很容易和自然地使用可读流处理，但 Node 提供了一个专用的文件流接口，提供了一种紧凑的文件流功能，无需额外的构造工作，比`fs.readFile`提供的更灵活。

# fs.createReadStream(path, [options])

`fs.createReadStream(path, [options])`方法返回`path`文件的可读流对象。然后，您可以对返回的对象执行流操作，例如`pipe()`。

以下选项可用：

+   `flags`：文件模式参数作为字符串。默认为`r`。

+   `encoding`：`utf8`、`ascii`或`base64`之一。默认为无编码。

+   `fd`：可以将`path`设置为 null，而不是传递文件描述符。

+   `mode`：文件模式的八进制表示，默认为 0666。

+   `bufferSize`：内部读取流的块大小，以字节为单位。默认为 64 * 1024 字节。您可以将其设置为任何数字，但内存分配严格受主机操作系统控制，可能会忽略请求。参考：[`groups.google.com/forum/?fromgroups#!topic/nodejs/p5FuU1oxbeY`](https://groups.google.com/forum/?fromgroups#!topic/nodejs/p5FuU1oxbeY)。

+   `autoClose`：是否自动关闭文件描述符（类似于`fs.close`）。默认为 true。如果您正在跨多个流共享文件描述符，则可能希望将其设置为 false 并手动关闭，因为关闭描述符将中断任何其他读取器。

+   `start`：从这个位置开始阅读。默认为 0。

+   `end`：在这个位置停止阅读。默认为文件字节长度。

# 逐行读取文件

逐字节读取文件流对于任何文件解析工作都足够了，但特别是文本文件通常更适合逐行读取，例如读取日志文件时。更准确地说，可以将任何流理解为由换行字符分隔的数据块，通常在 UNIX 系统上是`rn`。Node 提供了一个本地模块，其方法简化了对数据流中的换行分隔块的访问。

# Readline 模块

`Readline`模块有一个简单但强大的目标，即使得逐行读取数据流更容易。其接口的大部分设计是为了使命令行提示更容易，以便更容易设计接受用户输入的接口。

记住 Node 是为 I/O 设计的，I/O 操作通常涉及在可读和可写流之间移动数据，并且`stdout`和`stdin`是与`fs.createReadStream`和`fs.createWriteStream`返回的文件流相同的流接口，我们将看看如何使用这个模块类似地提示文件流以获取一行文本。

要开始使用`Readline`模块，必须创建一个定义输入流和输出流的接口。默认接口选项优先使用作为终端接口。我们感兴趣的选项如下：

+   `input`：必需。正在监听的可读流。

+   `output`：必需。正在写入的可写流。

+   `terminal`：如果输入和输出流都应该像 Unix 终端或**电传打字机**（**TTY**）一样对待，则设置为 true。对于文件，您将其设置为 false。

通过这个系统，读取文件的行变得非常简单。例如，假设有一个列出英语常用单词的字典文件，一个人可能希望将列表读入数组进行处理：

```js
const fs = require('fs'); 
const readline = require('readline'); 

let rl = readline.createInterface({ 
  input: fs.createReadStream("dictionary.txt"), 
  terminal: false 
}); 
let arr = []; 
rl.on("line", ln => { 
  arr.push(ln.trim()) 
}); 
// aardvark 
// abacus 
// abaisance 
// ...  
```

请注意，我们禁用了 TTY 行为，自己处理行而不是重定向到输出流。

正如预期的那样，与 Node I/O 模块一样，我们正在处理流事件。可能感兴趣的事件监听器如下所列：

+   `line`：接收最近读取的行，作为字符串

+   `pause`：每当流被暂停时调用

+   `resume`：每当流恢复时调用

+   `close`：每当流关闭时调用

除了`line`之外，这些事件名称反映了`Readline`方法，使用`Readline.pause`暂停流，使用`Readline.resume`恢复流，使用`Readline.close`关闭流。

# 写入文件

与读取文件一样，Node 提供了丰富的工具集来写入文件。我们将看到 Node 如何使得将文件内容按字节进行定位变得如此简单，就像将连续的数据流导入单个可写文件一样。

# 逐字节写入

`fs.write`方法是 Node 提供的写入文件的最低级别方法。该方法使我们可以精确控制字节将被写入文件的位置。

# fs.write(fd, buffer, offset, length, position, callback)

要将`buffer`中位置 309 和 8,675 之间的字节集合（长度为 8,366）插入到由文件描述符`fd`引用的文件中，从位置 100 开始：

```js
let buffer = Buffer.alloc(8675); 
fs.open("index.html", "w", (err, fd) => { 
  fs.write(fd, buffer, 309, 8366, 100, (err, writtenBytes, buffer) => { 
    console.log(`Wrote ${writtenBytes} bytes to file`); 
    // Wrote 8366 bytes to file 
  }); 
}); 
```

请注意，对于以追加（`a`）模式打开的文件，一些操作系统可能会忽略`position`值，始终将数据添加到文件的末尾。此外，在不等待回调的情况下多次调用`fs.write`对同一文件是不安全的。在这种情况下，请使用`fs.createWriteStream`。

有了这样精确的控制，我们可以智能地构造文件。在下面（有点牵强的）例子中，我们创建了一个基于文件的数据库，其中包含了一个单一团队 6 个月的棒球比分的索引信息。我们希望能够快速查找这个团队在某一天是赢了还是输了（或者没有比赛）。

由于一个月最多有 31 天，我们可以（随机地）在这个文件中创建一个 6 x 31 的数据网格，将三个值中的一个放在每个网格单元中：L（输）、W（赢）、N（未比赛）。为了好玩，我们还为我们的数据库创建了一个简单的**CLI**（**命令行界面**）和一个基本的查询语言。这个例子应该清楚地说明了`fs.read`、`fs.write`和`Buffer`对象是如何精确地操作文件中的字节的：

```js
const fs = require('fs'); 
const readline = require('readline'); 
let cells  = 186; // 6 x 31 
let buffer = Buffer.alloc(cells); 
let rand;
while(cells--) { 
  //  0, 1 or greater 
  rand = Math.floor(Math.random() * 3); 
  //  78 = "N", 87 = "W", 76 = "L" 
  buffer[cells] = rand === 0 ? 78 : rand === 1 ? 87 : 76; 
} 
fs.open("scores.txt", "r+", (err, fd) => { 
  fs.write(fd, buffer, 0, buffer.length, 0, (err, writtenBytes, buffer) => {          
    let rl = readline.createInterface({ 
      input: process.stdin, 
      output: process.stdout 
    }); 

    let quest = () => { 
      rl.question("month/day:", index => { 
        if(!index) { 
          return rl.close(); 
        } 
        let md = index.split('/'); 
        let pos = parseInt(md[0] -1) * 31 + parseInt(md[1] -1); 
        fs.read(fd, Buffer.alloc(1), 0, 1, pos, (err, br, buff) => { 
          let v = buff.toString(); 
          console.log(v === "W" ? "Win!" : v === "L" ? "Loss..." : "No game"); 
          quest(); 
        }); 
      }); 
    }; 
    quest(); 
  }); 
}); 
```

一旦运行，我们只需输入一个月/日对，就可以快速访问该数据单元。为输入值添加边界检查将是一个简单的改进。将文件流通过可视化 UI 可能是一个不错的练习。

# 写入大块数据

对于简单的写操作，`fs.write`可能过于复杂。有时，所需的只是一种创建具有一些内容的新文件的方法。同样常见的是需要将数据追加到文件的末尾，就像在日志系统中所做的那样。`fs.writeFile`和`fs.appendFile`方法可以帮助我们处理这些情况。

# fs.writeFile(path, data, [options], callback)

`fs.writeFile(path, data, [options], callback)`方法将`data`的内容写入到`path`处的文件中。data 参数可以是一个缓冲区或字符串。 

一个字符串。以下选项可用：

+   `编码`：默认为`utf8`。如果数据是一个缓冲区，则忽略此选项。

+   `mode`：文件模式的八进制表示，默认为 0666。

+   `flag`：写入标志，默认为`w`。

使用方法很简单：

```js
fs.writeFile('test.txt', 'A string or Buffer of data', err => { 
  if (err) { 
    return console.log(err); 
  } 
  // File has been written 
}); 
```

# fs.appendFile(path, data, [options], callback)

类似于`fs.writeFile`，不同之处在于`data`被追加到`path`文件的末尾。此外，`flag`选项默认为`a`。

# 创建可写流

如果要写入文件的数据以块的形式到达（例如文件上传时发生的情况），通过`WritableStream`对象接口将数据流式传输提供了更灵活和高效的方式。

# fs.createWriteStream(path, [options])

`fs.createWriteStream(path, [options])`方法返回`path`文件的可写流对象。

以下选项可用：

+   `flags`：文件模式参数作为字符串。默认为`w`。

+   `encoding`：`utf8`、`ascii`或`base64`中的一个。默认为无编码。

+   `mode`：文件模式的八进制表示，默认为 0666。

+   `start`：表示写入应该开始的文件中的位置的偏移量。

例如，这个小程序作为世界上最简单的文字处理器，将所有终端输入写入文件，直到终端关闭：

```js
let writer = fs.createWriteStream("novel.txt", 'w'); 
process.stdin.pipe(writer);
```

# 注意事项

打开文件描述符并从中读取的副作用很小，因此在正常开发中，很少会考虑实际发生了什么。通常情况下，读取文件不会改变它。

在写入文件时，必须解决许多问题，例如：

+   是否有足够的可写存储空间？

+   是否有另一个进程同时访问该文件，甚至擦除它？

+   如果写入操作失败或在流中途被非自然地终止，必须采取什么措施？

我们已经看到了独占写模式标志（`wx`），它可以在多个写入进程同时尝试创建文件的情况下提供帮助。一般来说，对文件进行写入时可能会面临的所有问题的完整解决方案都很难得出，或者简要陈述。Node 鼓励异步编程。然而，特别是在文件系统方面，有时需要同步、确定性的编程。鼓励您牢记这些和其他问题，并尽可能保持 I/O 非阻塞。

# 提供静态文件

任何使用 Node 创建 Web 服务器的人都需要对 HTTP 请求做出智能响应。对于 Web 服务器的资源的 HTTP 请求期望得到某种响应。一个基本的静态文件服务器可能看起来像这样：

```js
http.createServer((request, response) => { 
  if(request.method !== "GET") { 
    return response.end("Simple File Server only does GET"); 
  } 
  fs 
  .createReadStream(__dirname + request.url) 
  .pipe(response); 
}).listen(8000); 
```

该服务器在端口`8000`上服务 GET 请求，期望在相对路径等于 URL 路径段的本地文件中找到。我们看到 Node 是如何简单地让我们流式传输本地文件数据的，只需将`ReadableStream`传输到代表客户端套接字连接的`WritableStream`中。这是在几行代码中安全实现大量功能。

最终，将会添加更多内容，例如处理标准 HTTP 方法的例程，处理错误和格式不正确的请求，设置适当的标头，管理网站图标请求等等。

让我们使用 Node 构建一个相当有用的文件服务器，它将通过流式传输资源来响应 HTTP 请求，并且将遵守缓存请求。在这个过程中，我们将涉及如何管理内容重定向。在本章的后面，我们还将看到如何实现文件上传。请注意，一个完全符合 HTTP 所有特性的 Web 服务器是一个复杂的东西，因此我们正在创建的应该被视为一个良好的开始，而不是终点。

# 重定向请求

有时，客户端会尝试`GET`一个 URL，但该 URL 不正确或不完整，资源可能已经移动，或者有更好的方法来发出相同的请求。其他时候，`POST`可能会在客户端无法知道的新位置创建一个新资源，需要一些响应头信息指向新创建的 URI。让我们看看使用 Node 实现静态文件服务器时可能会遇到的两种常见重定向场景。

重定向基本上需要两个响应头：

+   `Location`：这表示重定向到可以找到内容主体的位置

+   `Content-Location`：这意味着指示请求者将在响应主体中找到实体的原始位置的 URL

此外，这些头还有两个特定的用例：

+   提供有关新创建资源位置的信息

对`POST`的响应

+   通知客户端请求资源的替代位置

对`GET`的响应

`Location`和`Content-Location`头与 HTTP 状态代码有许多可能的配对，特别是**3xx**（重定向）集。实际上，这些头甚至可以在同一个响应中一起出现。鼓励用户阅读 HTTP/1.1 规范的相关部分，因为这里只讨论了一小部分常见情况。

# 位置

使用`201`状态代码响应`POST`表示已创建新资源并将其 URI 分配给`Location`头，客户端可以在将来使用该 URI。请注意，由客户端决定是否以及何时获取此资源。因此，严格来说，这不是重定向。

例如，系统可能通过将新用户信息发布到服务器来创建新帐户，期望接收新用户页面的位置：

```js
    POST /path/addUser HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    name=John&group=friends 
    ...
    Status: 201 
    Location: http://website.com/users/john.html  
```

同样，在接受但尚未完成的情况下，服务器将指示`202`状态。在前面的例子中，如果创建新用户记录的工作已被委托给工作队列，那么这将是情况。

我们将在本章后面看到一个实际的实现，演示这种用法，当我们讨论文件上传时。

# Content-Location

当对具有多个表示形式的资源进行`GET`请求，并且这些表示形式可以在不同的资源位置找到时，应该返回特定实体的`content-location`头。例如，内容格式协商是`Content-Location`处理的一个很好的例子。可能有兴趣检索给定月份的所有博客文章，可能可以在 URL 上找到，比如：`http://example.com/september/`。带有`application/json`的`Accept`头的 GET 请求将以 JSON 格式接收响应。对 XML 的请求将接收该表示形式。

如果正在使用缓存机制，这些资源可能具有替代的永久位置，比如`http://example.com/cache/september.json`或`http://example.com/cache/september.xml`。将通过`Content-Location`发送此附加位置信息，响应对象类似于这样：

```js
    Status: 200 
    Content-Type: application/json
    Content-Location: http://blogs.com/cache/allArticles.json
    ... JSON entity body  
```

在请求的 URL 已经被永久或临时移动的情况下，可以使用`3xx`状态代码组和`Content-Location`来指示此状态。例如，要重定向到已永久移动的 URL，应发送 301 代码：

```js
function requestHandler(request,response) { 
  let newPath = "/thedroids.html"; 
  response.writeHead(301, { 
    'Content-Location': newPath 
  }); 
  response.end(); 
} 
```

# 实施资源缓存

作为一个一般规则，永远不要浪费资源向客户端传递无关的信息。对于 HTTP 服务器，重新发送客户端已经拥有的文件是不必要的 I/O 成本，这是实现 Node 服务器的错误方式，会增加延迟以及支付被挪用的带宽的财务损失。

浏览器维护已经获取的文件的缓存，并且**实体标签**（**ETag**）标识这些文件。ETag 是服务器发送的响应头，用于唯一标识它们返回的实体，比如一个文件。当服务器上的文件发生变化时，该服务器将为该文件发送一个不同的 ETag，允许客户端跟踪文件的更改。

当客户端向服务器请求其缓存中包含的资源时，该请求将包含一个`If-None-Match`头，该头设置为与所述缓存资源相关联的 ETag 的值。`If-None-Match`头可以包含一个或多个 ETag：

```js
If-None-Match : "686897696a7c876b7e" 
If-None-Match : "686897696a7c876b7e", "923892329b4c796e2e"
```

服务器理解这个头部，并且只有在发送的 ETags 中没有一个与当前资源实体标记匹配时，才会返回所请求资源的完整实体主体。如果发送的 ETags 中有一个与当前实体标记匹配，服务器将以 304（未修改）状态进行响应，这应该导致浏览器从其内部缓存中获取资源。

假设我们有一个`fs.Stats`对象可用，使用 Node 可以轻松地管理资源的缓存控制：

```js
let etag = crypto.createHash('md5').update(stat.size + stat.mtime).digest('hex'); 
if(request.headers['if-none-match'] === etag) { 
  response.statusCode = 304; 
  return response.end(); 
} else { 
  // stream the requested resource 
} 
```

我们通过创建当前文件大小和最后修改时间的 MD5 来为当前文件创建一个`etag`，并与发送的`If-None-Match`头进行匹配。如果两者不匹配，资源表示已更改，新版本必须发送回请求的客户端。请注意，应该使用哪种特定算法来创建`etag`并没有正式规定。示例技术对大多数目的应该能够很好地工作。

嘿！`Last-Modified`和`If-Unmodified-Since`呢？这些都是很好的头部，也在缓存文件的情况下很有用。事实上，当响应实体请求时，应该尽可能设置`Last-Modified`头部。我们在这里描述的使用 ETag 的技术将与这些标签类似地工作，实际上，鼓励同时使用 ETags 和这些其他标签。有关更多信息，请参阅：[`www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.3.4`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.3.4)。

# 处理文件上传

很可能任何阅读这句话的人都至少有一次从客户端上传文件到服务器的经历。有些人甚至可能实现了文件上传服务，一个将接收并对多部分数据流执行有用操作的服务器。在流行的开发环境中，这个任务变得非常容易。例如，在 PHP 环境中，上传的数据会自动处理并全局可用，被整洁地解析和打包成文件或表单字段值的数组，而开发人员无需编写一行代码。

不幸的是，Node 将文件上传处理的实现留给开发人员，这是一个具有挑战性的工作，许多开发人员可能无法成功或安全地完成。

幸运的是，Felix Geisendorfer 创建了**Formidable**模块，这是 Node 项目中最重要的早期贡献之一。这是一个广泛实施的企业级模块，具有广泛的测试覆盖范围，它不仅使处理文件上传变得轻而易举，而且可以用作处理表单提交的完整工具。我们将使用这个库来为我们的文件服务器添加文件上传功能。

有关 HTTP 文件上传设计的更多信息，以及开发人员必须克服的棘手实现问题，请参阅[`www.w3.org/TR/html401/interact/forms.html#h-17.13.4.2`](http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.2)中的多部分/表单数据规范，以及 Geisendorfer 关于**Formidable**的构想和演变的分解[`debuggable.com/posts/parsing-file-uploads-at-500-mb-s-with-node-js:4c03862e-351c-4faa-bb67-4365cbdd56cb`](http://debuggable.com/posts/parsing-file-uploads-at-500-mb-s-with-node-js:4c03862e-351c-4faa-bb67-4365cbdd56cb)。

首先，通过 npm 安装`formidable`：

```js
 npm install formidable 
```

现在你可以`require`它：

```js
    let formidable = require('formidable');  
```

我们将假设文件上传将通过路径发布到我们的服务器上

`/uploads/`，并且上传通过一个看起来像这样的 HTML 表单到达：

```js
<form action="/uploads" enctype="multipart/form-data" method="post"> 
Title: <input type="text" name="title"><br /> 
<input type="file" name="upload" multiple="multiple"><br /> 
<input type="submit" value="Upload"> 
</form> 
```

这个表单将允许客户端为上传写一些标题，并选择一个（或多个）文件进行上传。在这一点上，我们服务器的唯一责任是正确检测到何时发出了`POST`请求，并将相关请求对象传递给 Formidable。

我们不会涵盖 formidable API 设计的每个部分，但我们将专注于库公开的关键`POST`事件。由于 formidable 扩展了`EventEmitter`，我们使用`on(eventName,callback)`格式来捕获文件数据、字段数据和终止事件，向客户端发送响应，描述服务器成功处理了什么：

```js
http.createServer((request, response) => { 
  let rm = request.method.toLowerCase(); 
  if(request.url === '/uploads' && rm === 'post') { 
    let form = new formidable.IncomingForm(); 
    form.uploadDir = process.cwd(); 
    let resp = ""; 
    form 
    .on("file", (field, File) => { 
      resp += `File: ${File.name}<br />`; 
    }) 
    .on("field", (field, value) => { 
      resp += `${field}: ${value}<br />`; 
    }) 
    .on("end", () => { 
      response.writeHead(200, {'content-type': 'text/html'}); 
      response.end(resp); 
    }) 
    .parse(request); 
    return; 
  } 
}).listen(8000); 
```

我们在这里看到一个`formidable`实例如何通过其`parse`方法接收`http.Incoming`对象，以及如何使用该实例的`uploadDir`属性设置传入文件的写入路径。该示例将此目录设置为本地目录。真实的实现可能会将目标定位到专用的上传文件夹，甚至将接收到的文件定向到存储服务，通过 HTTP 和`Location`头接收最终的存储位置（也许是通过 HTTP 接收）。

还要注意文件事件回调如何接收 formidable `File`对象作为第二个参数，其中包含重要的文件信息，包括以下内容：

+   **size**：上传文件的大小，以字节为单位

+   `*` **path**：上传文件在本地文件系统上的当前位置，例如

作为`/tmp/bdf746a445577332e38be7cde3a98fb3`

+   **name**：文件在客户端文件系统上存在的原始名称，例如`lolcats.jpg`

+   **type**：文件的 MIME 类型，例如`image/png`

在几行代码中，我们已经实现了大量的`POST`数据管理。Formidable 还提供了处理进度指示器、处理网络错误等工具，读者可以通过访问以下网址了解更多信息：[`github.com/felixge/node-formidable`](https://github.com/felixge/node-formidable)。

# 把所有东西放在一起

回顾我们在上一章中关于 favicon 处理的讨论，并加上我们对文件缓存和文件上传的了解，我们现在可以构建一个简单的文件服务器来处理`GET`和`POST`请求：

```js
http.createServer((request, response) => { 
  let rm = request.method.toLowerCase(); 
  if(rm === "post") { 
    let form = new formidable.IncomingForm(); 
    form.uploadDir = process.cwd(); 
    form 
    .on("file", (field, file) => { 
      // process files 
    }) 
    .on("field", (field, value) => { 
      // process POSTED field data 
    }) 
    .on("end", () => { 
      response.end("Received"); 
    }) 
    .parse(request); 
    return; 
  } 
  // Only GET is handled if not POST
  if(rm !== "get") { 
    return response.end("Unsupported Method"); 
  } 
  let filename = path.join(__dirname, request.url); 
  fs.stat(filename, (err, stat) => { 
      if(err) { 
        response.statusCode = err.errno === 34 ? 404 : 500; 
      return response.end() 
      }  
    var etag = crypto.createHash('md5').update(stat.size + stat.mtime).digest('hex');     
    response.setHeader('Last-Modified', stat.mtime); 
    if(request.headers['if-none-match'] === etag) { 
      response.statusCode = 304; 
      return response.end(); 
    } 
    response.setHeader('Content-Length', stat.size); 
    response.setHeader('ETag', etag); 
    response.statusCode = 200; 
    fs.createReadStream(filename).pipe(response); 
  }); 
}).listen(8000); 
```

注意 404（未找到）和 500（内部服务器错误）状态代码。

`Content-Length`以字节为单位，而不是字符。通常，您的数据将是单字节字符（hello 是五个字节长），但并非总是如此。如果您确定流缓冲区的长度，请使用`Buffer.byteLength`。

# 一个简单的文件浏览器

现在，让我们利用我们对文件和 Node 的了解来做一些真正（希望如此）没有网页可以做到的事情；让我们直接浏览您个人计算机的整个硬盘！为了实现这一点，我们将使用 JavaScript 和 Node 家族的两个强大的最近添加：*Electron*和*Vue.js*。

从终端开始，使用以下命令：

```js
$ mkdir hello_files
$ cd hello_files
$ npm init
$ npm install -S electron
```

默认答案很好，除了入口点——不要输入`index.js`，而是输入`main.js`。完成后，你应该有一个像这样的`package.json`文件：

```js
{
  "name": "hello_files",
  "version": "0.0.1",
  "description": "A simple file browser using Node, Electron, and Vue.js",
  "main": "main.js",
  "dependencies": {
    "electron": "¹.7.9"
  }
}
```

现在，让我们来看看这三个命令：

```js
$ ./node_modules/.bin/electron --version
$ ./node_modules/.bin/electron
$ ./node_modules/.bin/electron .
```

尝试第一个命令，以确保 npm 在您的计算机上获得了一个可用的 Electron 副本。截至目前，当前版本是 v1.7.9。第二个命令将执行 electron "empty"，即在不给它一个应用程序运行的情况下。第三个命令告诉 electron 在这个文件夹中运行应用程序：Electron 将读取`package.json`来查找并运行`main.js`。

或者，您可以使用`-g`全局安装 Electron，然后使用以下命令更轻松地到达可执行文件：

```js
$ npm install -g electron

$ electron --version
$ electron
$ electron .
```

# Electron

让我们运行第二个命令。结果可能会让人惊讶：一个图形窗口出现在您的屏幕上！：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/74646cbc-c5e5-41ff-b207-9d1524a547a4.png)

这是什么？Electron 是什么？让我们以几种方式回答这个问题：对于最终用户，对于开发人员或产品所有者，底层，以及在本章末尾，从 JavaScript 的历史和发展的角度来看。

对于最终用户，Electron 应用程序只是一个普通的桌面应用程序。用户甚至无法知道它是用 Electron 制作的。开箱即用的流程完全相同：用户可以从他们喜欢的应用商店获取应用程序，或者从你的网站下载`setup.exe`。日常体验也是一样的：应用程序在开始菜单或 dock 上有一个图标，菜单在应该的地方，`文件|打开...`对话框——所有用户期望从桌面应用程序中获得的功能。例如，你可能在 Windows 或 macOS 上使用 Slack，并且可能会惊讶地发现 Slack 是用 Electron 制作的。

对于开发人员或产品所有者来说，Electron 是制作桌面应用程序的好方法。开发人员现在可以在桌面上使用他们在网络上学到的现代和强大的技术。你喜欢的所有 npm 模块也可以一起使用。产品所有者喜欢能够在 Windows、Mac 和 Linux 上同时发布 1.0 版本，几乎不需要额外的开发或测试。业务利益相关者喜欢能够让一个 Web 开发人员团队同时负责 Web 和桌面项目，而不是不得不雇佣新的专门的团队（每个目标操作系统一个）来熟悉每个单独的本地桌面堆栈。

在底层，Electron 非常惊人。它由 Chromium 和 Node 的部分组成，从 Chromium 获取页面渲染的能力，从 Node 获取缓冲区、文件和套接字等能力。Chromium 和 Node 都包含 V8，当然在 V8 内部有一个 JavaScript 事件循环。在一项令人印象深刻的工程壮举中，Electron 将这两个事件循环合并在一起，允许单个 JavaScript 事件运行代码，影响屏幕和系统。

Electron 是由 GitHub 制作的，GitHub 也开发了 Atom 文本编辑器。为了使 Atom 像网络一样易于修改，GitHub 使用了网络技术构建了它。意识到其他软件团队可能希望以这种方式构建桌面应用程序，GitHub 首先将他们的工具作为 Atom Shell 发布，并将名称简化为 Electron。

现在我们已经让 Electron 运行起来了，让我们把 Electron 变成我们自己的应用程序。`electron .`命令会让 Electron 查看`package.json`来确定它应该做什么。在那里，我们指向了`main.js`：

```js
// main.js

const electron = require('electron');
const app = electron.app;
const BrowserWindow = electron.BrowserWindow;

const path = require('path');
const url = require('url');

let mainWindow; // Keep this reference so the window doesn't close

function createWindow() {
  mainWindow = new BrowserWindow({width: 800, height: 800});
  mainWindow.loadURL(url.format({
    pathname: path.join(__dirname, 'index.html'),
    protocol: 'file:',
    slashes: true
  }));
  mainWindow.webContents.openDevTools();
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.on('ready', createWindow);

app.on('window-all-closed', () => {
  app.quit();
});
```

你可以想象 Node 正在运行这个文件，尽管实际上运行它的可执行文件是 Electron（当然，Electron 内部包含了 Node 和 V8）。请注意代码如何可以引入熟悉的 Node 模块，比如`path`和`url`，以及一些新的模块，比如`electron`。`main.js`中的代码创建了一个特殊的 Electron 浏览器窗口，宽 800 像素，高 800 像素，并将其导航到`index.html`：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Hello, files</title>
  </head>
  <body>
    <p>
      <input type="button" value="Reload the app after changing the code" onClick="window.location.reload()"/>
    </p>
    <div id="app">
      <p>{{ location }}</p>
      <button @click="up">..</button>
      <listing v-for="file in files" v-bind:key="file.id" v-bind:item="file"></listing>
      <p><img v-bind:src="img/image"/></p>
    </div>
    <script src="img/vue"></script>
    <script>
      require('./renderer.js')
    </script>
  </body>
</html>
```

这看起来也很熟悉，符合我们在网络上的期望。我们将在本章后面讨论 Vue；现在，请注意页面顶部的重新加载`按钮`和末尾的`script`标签。

在开发时，按钮是很有用的。你可以通过点击重新加载按钮来查看对这个页面或它引入的 JavaScript 进行更改后的结果，而不是在命令行重新启动 Electron 进程。Electron 不显示 Chromium 的默认浏览器工具栏，其中包含重新加载按钮，但在 macOS 的菜单栏上有“查看，重新加载”，并且可以更容易地在页面上放置一个重新加载按钮。

要理解末尾的`script`标签，最好先对 Electron 的进程架构有一个基本的了解。

# Electron 进程

由 Chromium 构建，Electron 继承了 Chromium（和 Chrome）的每个标签一个进程的架构。使用 Electron 运行我们的应用程序时，只有一个“标签”：你屏幕上的窗口，但仍然有两个进程。*主*进程代表底层浏览器，你可以从命令行启动它，然后它读取`package.json`，然后运行`main.js`。Electron 的主进程可以创建新的`BrowserWindow`对象，并处理影响桌面应用程序整体生命周期的事件，从启动到关闭。

然而，在 Electron 打开的页面上，另一个进程，*渲染器*进程，运行其中的 JavaScript。只有渲染器进程能够执行与 GUI 相关的任务，比如操作 DOM。

Node 在两个进程中都可用。如果一个模块期望 DOM 存在，它可能无法在主进程中工作。例如，jQuery 在 Electron 的主进程中无法加载，但在渲染器进程中可以正常工作，而 Handlebars 在两者中都可以正常工作。

在某些情况下，一个 Electron 进程中的代码需要执行某个动作或从另一个进程中的代码获取答案，解决方案是 Node 的标准进程间通信工具，稍后在第七章中描述，*使用多个进程*。此外，Electron 方便地将其中一些封装在自己的 API 中。

# 渲染器进程

到目前为止，我们已经看到 Electron 启动，运行`main.js`，并打开`index.html`。总之，整个过程是这样工作的：

Electron 的*主*进程执行以下操作：

+   读取`package.json`，然后告诉它

+   运行`main.js`

这会导致 Electron 启动一个*渲染器*进程来执行此操作：

+   解析 `index.html`，然后

+   运行`renderer.js`

让我们看看那里的代码：

```js
// renderer.js

const Promise = require("bluebird");
const fs = Promise.promisifyAll(require("fs"));
const path = require("path");

Vue.component('listing', {
  props: ['item'],
  template: '<div @click="clicked(item.name)">{{ item.name }}</div>',
  methods: {
    clicked(n) {
      go(path.format({ dir: app.location, base: n }));
    }
  }
});

var app = new Vue({
  el: '#app',
  data: {
    location: process.cwd(),
    files: [],
    image: null
  },
  methods: {
    up() {
      go(path.dirname(this.location));
    }
  }
});

function go(p) {

  if (p.endsWith(".bmp") || p.endsWith(".png") || p.endsWith(".gif") || p.endsWith(".jpg")) {

    // Image
    app.image = "file://" + p; // Show it

  } else {

    // Non-image
    app.image = null;

    // See if it's a directory or not
    fs.lstatAsync(p).then((stat) => {

      if (stat.isDirectory()) {

        // Directory, list its contents
        app.location = p;
        fs.readdirAsync(app.location).then((files) => {
          var a = [];
          for (var i = 0; i < files.length; i++)
            a.push({ id: i, name: files[i] });
          app.files = a;
        }).catch((e) => {
          console.log(e.stack);
        });
      } else {
        // Non-directory, don't go there at all
      }
    }).catch((e) => {
      console.log(e.stack);
    });
  }
}

go(app.location);
```

首先，这段代码引入了 bluebird promise 库，并将其设置为`Promise`。对`Promise.promisifyAll()`的调用创建了诸如`fs.lstatAsync()`之类的函数，这是`fs.lstat()`的 promise 版本。

我们应用的核心逻辑被分解为一个名为`go()`的单个函数，该函数传递给应用程序想要查看的绝对文件系统路径。如果路径是一个图像，应用程序会在页面上显示它。如果路径是一个目录，应用程序会列出文件夹的内容。

为了执行这个逻辑，前面的代码首先简单地查找一个常见的图像文件扩展名。如果不存在，一个异步步骤会使用`fs.lstatAsync()`来查看磁盘，然后能够调用`stat.isDirectory()`。如果是一个目录，另一个 promise 调用`fs.readdirAsync()`会获取目录列表。

这是我们简单的 Electron 文件浏览器的运行情况：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/c9740216-ac9e-4e7f-a15a-74a2a6ef710e.png)

# Vue.js

我们应用的用户体验由*Vue.js*提供支持，这是一个用于构建和轻松更改网页内容的前端 JavaScript 框架。与 React 一样，Vue 允许您对组件进行模板化，将它们放在页面上，并在底层数据发生变化时进行更改。

React 使用 JSX 将 HTML 标记与 JavaScript 代码组合在一起。这需要一个预处理器，比如*Babel*，将 JSX 部分转译成 ES6 JavaScript。在典型的 React 堆栈中，*webpack*管理着一个构建过程，其中包括 Babel，将您的开发文件转换并组合成您将运行、测试和最终部署的文件。webpack 开发服务器会在您编写代码时显示您的网站，甚至在您更改代码时自动刷新。

然而，Vue 不需要一个转译步骤。您可以将它与 webpack 一起使用，但也可以只使用一个脚本标签，就像我们应用程序的`index.html`中的这个一样：

```js
<script src="img/vue"></script>
```

这种灵活性使得使用 Vue 很容易入门，在 Electron 中运行 Vue 也很容易，这也是我们选择它作为这个示例应用程序的原因。

回到`index.html`页面，看看这些行：

```js
<div id="app">
  <p>{{ location }}</p>
  <button @click="up">..</button>
  <listing v-for="file in files" v-bind:key="file.id" v-bind:item="file"></listing&gt;
  <p><img v-bind:src="img/image"/></p>
</div>
<script src="img/vue"></script>
```

此外，在`renderer.js`脚本中，看看这部分：

```js
var app = new Vue({
  el: '#app',
  data: {
    location: process.cwd(),
    files: [],
    image: null
  },
  methods: {
    up() {
      go(path.dirname(this.location));
    }
  }
});
```

在页面中，`<div id="app">`标识`div`作为我们的应用程序，在脚本中，`var app = new Vue({});`创建了连接到并控制*app* `div`的新 JavaScript 对象。`app`内部的数据对象定义了出现在 div 中的值，因此也出现在页面上。例如，`app.location`，通过与上面的`data`对象的一些巧妙的内部链接，显示在`{{ location }}`出现的页面上。Vue 甚至会监视对`data.location`的更改-将其设置为一个新值，页面将自动更新。有了这个能力，Vue 被称为*reactive*。

使用我们刚刚构建的文件浏览器在本地磁盘上浏览一下，并想象一下你现在可以使用 Node 和 Electron 创建的所有桌面应用程序。

在本章的开头，我们问过，“Electron 是什么？”并构思了不同的答案，想象了不同的利益相关者，并考虑了不同的观点。

Electron 让 JavaScript 离 Kris Kowal 在第一章中提到的语言目标更近了一步，即“理解 Node 环境”，这意味着能够在任何地方运行并做任何事情。此外，考虑到 JavaScript 在过去几十年的计算中的地位，它以一些讽刺的方式实现了这一目标。

Brendan Eich 在 1990 年代创建了 JavaScript，用于在个人电脑上运行的浏览器中的网页中脚本化小任务，这些电脑刚刚获得了位图显示和图形操作系统。在那里，JavaScript 被严格限制在浏览器标签的沙盒中。沙盒执行严格的安全要求，并限制了它，不能查看一些文件等。靠近用户和屏幕，JavaScript 可以验证表单数据，并实时更改 CSS。在生命的第一阶段，大多数时候，JavaScript 都在动画化一些文本。

Node 将 JavaScript 带到了服务器，使其远离了图形屏幕，但也使其摆脱了浏览器的限制。在那里，JavaScript 成为了一种能干而完整的系统语言，访问文件和套接字以执行有用和强大的任务。在生命的第二阶段，大多数时候，JavaScript 迁移了数据库。

Electron 将 JavaScript 带回了客户端。就像一个漂泊的封建武士在被流放多年后返回家乡一样，JavaScript 带着 ES6 功能和在服务器荒原上开发的 npm 模块回来了，它与强大的伙伴（有时也是敌人）如 C++和 Java 一起被使用和开发。在桌面上并且拥有 Electron 的支持，它可以在浏览器的受限范围之外使用这些能力。在生命的第三阶段，JavaScript 真的可以做任何事情。

# 总结

在本章中，我们看到了 Node 的 API 是对本地文件系统绑定的全面映射，为开发人员提供了完整的功能范围，同时需要非常少的代码或复杂性。此外，我们还看到文件如何轻松地包装成`Stream`对象，以及这种与 Node 设计的一致性如何简化了不同类型 I/O 之间的交互，比如网络数据和文件之间的交互。使用 Electron，我们构建了一个作为跨平台本地应用程序运行的文件浏览器，为 Node 开发人员打开了一个全新的世界。

我们还学到了一些关于如何使用 Node 构建服务器，以满足常规客户端的期望，轻松实现文件上传和资源缓存。在介绍了 Node 的关键特性之后，现在是时候在构建能够处理成千上万客户端的大型应用程序中使用这些技术了。
