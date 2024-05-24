# JavaScript 高性能实用指南（三）

> 原文：[`zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774`](https://zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：流-理解流和非阻塞 I/O

我们已经涉及了几乎所有帮助我们使用 JavaScript 为服务器编写高性能代码的主题。应该讨论的最后两个主题是流和数据格式。虽然这两个主题可以并驾齐驱（因为大多数数据格式是通过读/写流实现的），但我们将在本章中重点关注流。

流使我们能够编写可以处理数据而不占用大量工作内存并且不阻塞事件队列的系统。对于那些一直按顺序阅读本书的人来说，这可能听起来很熟悉，这是正确的。我们将重点关注 Node.js 提供的四种不同类型的流，以及我们可以轻松扩展的流。从那里，我们将看看如何结合流和生成器来处理具有内置生成器概念的数据。

本章涵盖以下主题：

+   流基础知识

+   可读流

+   可写流

+   双工流

+   转换流

+   附注-生成器和流

# 技术要求

本章的先决条件如下：

+   一个代码编辑器或 IDE，最好是 VS Code

+   可以运行 Node.js 的操作系统

+   在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter07)找到的代码。

# 开始使用流

流是处理无限数据集的行为。这并不意味着它是无限的，但是意味着我们有可能拥有无限的数据源。如果我们从传统的数据处理上下文来思考，通常会经历三个主要步骤：

1.  打开/获取对数据源的访问。

1.  一旦数据源完全加载，就处理数据源。

1.  将计算出的数据输出到另一个位置。

我们可以将其视为**输入和输出**（**I/O**）的基础。我们的大多数 I/O 概念涉及批处理或处理所有或几乎所有数据。这意味着我们提前知道数据的限制。我们可以确保我们有足够的内存、存储空间、计算能力等来处理这个过程。一旦我们完成了这个过程，我们就会终止程序或排队下一批数据。

一个简单的例子如下所示，我们计算文件的行数：

```js
import { readFileSync } from 'fs'
const count = readFileSync('./input.txt', {encoding : 'utf8'})
 .split(/\n|\r\n/g).length;
console.log('number of lines in our file is: ', count);
```

我们从`fs`模块中引入`readFileSync`方法，然后读取`input.txt`文件。从这里开始，我们在`\n`或`\r\n`上拆分，这给我们一个文件所有行的数组。从那里，我们得到长度并将其放在我们的标准输出通道上。这似乎非常简单，而且似乎运行得很好。对于小到中等长度的文件，这很好用，但是当文件变得异常大时会发生什么呢？让我们继续看下去。前往[`loremipsum.io`](https://loremipsum.io)并输入 100 段落。将其复制并粘贴几次到`input.txt`文件中。现在，当我们运行这个程序时，我们可以在任务管理器中看到内存使用量的飙升。

我们将一个大约 3MB 的文件加载到内存中，计算换行符的数量，然后打印出来。这应该仍然非常快，但我们现在开始利用大量内存。让我们用这个文件做一些更复杂的事情。我们将计算文本中单词`lorem`出现的次数。我们可以使用以下代码来实现：

```js
import { readFileSync } from 'fs'
const file = readFileSync('./input.txt', {encoding : 'utf8'});
const re = /\slorem\s/gi;
const matches = file.match(re);

console.log('the number of matches is: ', matches.length);
```

同样，这应该处理得很快，但在处理方式上可能会有一些滞后。虽然在这里使用正则表达式可能会给我们一些错误的结果，但它确实展示了我们在这个文件上进行批处理。在许多情况下，当我们在高速环境中工作时，我们处理的文件可能接近或超过 1GB。当我们处理这些类型的文件时，我们不希望将它们全部加载到内存中。这就是流的作用所在。

许多被认为是大数据的系统正在处理几 TB 的数据。虽然有一些内存应用程序会将大量数据存储在内存中，但这种类型的数据处理大部分使用文件流和使用内存数据源来处理数据的混合。

让我们拿第一个例子来说。我们正在从文件中读取，并尝试计算文件中的行数。嗯，与其考虑整个行数，我们可以寻找表示换行的字符。我们在正则表达式中寻找的字符是换行符（`\n`）或回车加换行（`\r\n`）字符。有了这个想法，我们应该能够构建一个流应用程序，它可以读取文件并计算行数，而不需要完全将文件加载到内存中。

这个例子介绍了利用流的 API。我们将讨论每个流 API 给我们的东西，以及我们如何利用它来实现我们的目的。现在，拿出代码示例并运行它们，看看这些类型的应用是如何工作的。

这可以在以下代码片段中看到：

```js
import { createReadStream } from 'fs';

const newLine = 0x0A;
const readStream = createReadStream('./input.txt');
let counter = 1;
readStream.on('data', (chunk) => {
    for(const byte of chunk) {
        if( newLine === byte ) counter += 1;
    }
}).on('end', () => {
    console.log('number of line in our file is: ', counter);
});
```

我们从`fs`模块中获取一个`Readable`流并创建一个。我们还为 HEX 格式中表示的换行符创建一个常量。然后，我们监听数据事件，以便在数据到达时处理数据。然后，我们处理每个字节，看它是否与换行符相同。如果是，那么我们有一个换行符，否则我们继续搜索。我们不需要明确寻找回车符，因为我们知道它应该后跟一个换行符。

虽然这比将整个文件加载到内存中要慢，但在处理数据时它确实节省了我们相当多的内存。这种方法的另一个好处是这些都是事件。在我们的完整处理示例中，我们占用整个事件循环，直到处理完成。而使用流，我们有事件来处理数据进来。这意味着我们可以在同一个线程上同时运行多个流，而不必太担心阻塞（只要我们在数据块的处理上不花费太多时间）。

通过前面的例子，我们可以看到如何以流的形式编写反例。为了更好地说明问题，让我们继续做到这一点。它应该看起来像下面这样：

```js
const stream = createReadStream('./input.txt');
const buf = Buffer.from('lorem');
let found = 0;
let count = 0;
stream.on('data', (chunk) => {
    for(const byte of chunk) {
        if( byte === buf[found] ) {
            found += 1;
        } else {
            found = 0;
        }
        if( found === buf.byteLength ) {
            count += 1;
            found = 0;
        }
    }
}).on('end', () => {
    console.log('the number of matches is: ', count)
});
```

首先，我们创建一个读取`stream`，就像以前一样。接下来，我们创建一个关键字的`Buffer`形式，我们正在寻找的关键字（在原始字节上工作可能比尝试将流转换为文本更快，即使 API 允许我们这样做）。接下来，我们维护一个`found`计数和一个`actual`计数。`found`计数将告诉我们是否找到了这个单词；另一个计数跟踪我们找到了多少个`lorem`实例。接下来，当数据事件上的一个块到来时，我们处理每个字节。如果我们发现下一个字节不是我们要找的字符，我们会自动将`found`计数返回为`0`（我们没有找到这个特定的文本字符串）。在这个检查之后，我们将看到我们是否找到了完整的字节长度。如果是，我们可以增加计数并将`found`移回`0`。我们将`found`计数器保留在数据事件之外，因为我们以块接收数据。由于它是分块的，`lorem`的一部分可能出现在一个块的末尾，而`lorem`的另一部分可能出现在下一个块的开头。一旦流结束，我们就输出计数。

现在，如果我们运行两个版本，我们会发现第一个实际上捕获了更多的`lorem`。我们为正则表达式添加了不区分大小写的标志。如果我们通过删除末尾的`i`来关闭它，并且我们删除字符序列周围的`\s`，我们将看到我们得到相同的结果。这个例子展示了写流可能比批处理版本更复杂一些，但通常会导致更低的内存使用和更快的代码。

虽然利用内置流（如`zlib`和`fs`模块中的流）可以让我们走得更远，但我们将看到如何成为我们自己自定义流的生产者。我们将每个流都写成一个扩展流类型，以处理我们在上一章中所做的数据框架。

对于那些忘记或跳到本章的人，我们正在通过套接字对所有消息进行框架处理，使用`!!!BEGIN!!!`和`!!!END!!!`标记来告诉我们何时将完整数据流式传输给我们。

# 构建自定义可读流

`Readable`流确切地做了它所声明的事情，它从流源中读取。它根据某些标准输出数据。我们的例子是对 Node.js 文档中显示的简单示例的一种理解。

我们将以计算文本文件中`lorem`的数量为例，但我们将输出在文件中找到`lorem`的位置：

1.  从各自的模块中导入`Readable`类和`createReadStream`方法：

```js
import { Readable } from 'stream'
import { createReadStream } from 'fs'
```

1.  创建一个扩展`Readable`类的类，并设置一些私有变量来跟踪内部状态：

```js
class LoremFinder extends Readable {
    #lorem = Buffer.from('lorem');
    #found = 0;
    #totalCount = 0;
    #startByteLoc = -1;
    #file = null;
}
```

1.  添加一个构造函数，将我们的`#file`变量初始化为`Readable`流：

```js
// inside our LoremFinder class
constructor(opts) {
    super(opts); 
    if(!opts.stream ) { 
        throw new Error("This stream needs a stream to be 
         provided!");
    }
    this.#file = opts.stream;
    this.#file.on('data', this.#data.bind(this)); // will add #data 
     method next
    this.#file.on('end', () => this.push(null)); 
}
```

1.  根据构造函数，我们将利用一个`#data`私有变量，它将是一个函数。我们将利用它来从我们的`#file`流中读取，并检查`lorem`的位置：

```js
// inside of the LoremFinder class
#data = function(chunk) {
    for(let i = 0; i < chunk.byteLength; i++) {
        const byte = chunk[i];
        if( byte === this.#lorem[this.#found] ) {
            if(!this.#found ) {
                this.#startByteLoc = this.#totalCount + i; 
            }
            this.#found += 1;
        } else {
            this.#found = 0;
        }
        if( this.#found === this.#lorem.byteLength ) {
            const buf = Buffer.alloc(4);
            buf.writeUInt32BE(this.#startByteLoc);
            this.push(buf);
            this.#found = 0;
        }
    }
    this.#totalCount += chunk.byteLength;
}
```

我们遍历每个字节，并检查我们当前是否拥有我们在`lorem`单词中寻找的字节。如果我们找到了，并且它是单词的`l`，那么我们设置我们的位置`#startByteLoc`变量。如果我们找到整个单词，我们输出`#startByteLoc`，否则，我们重置我们的查找变量并继续循环。一旦我们完成循环，我们将我们读取的字节数添加到我们的`#totalCount`中，并等待我们的`#data`函数再次被调用。为了结束我们的流并让其他人知道我们已完全消耗了资源，我们输出一个`null`值。

1.  我们添加的最后一部分是`_read`方法。

这将通过`Readable.read`方法或通过挂接数据事件来调用。这是我们如何确保*原始*流（如`FileStream`）被消耗：

```js
// inside of the LoremFinder class
_read(size) {
    this.#file.resume();
}
```

1.  现在我们可以添加一些测试代码来确保这个流正常工作：

```js
const locs = new Set();
const loremFinder = new LoremFinder({
    stream : createReadStream('./input.txt')
});
loremFinder.on('data', (chunk) => {
    const num = chunk.readUInt32BE();
    locs.add(num);
});
loremFinder.on('end', () => {
    console.log('here are all of the locations:');
    for(const val of locs) {
        console.log('location: ', val);
    }
    console.log('number of lorems found is', locs.size);
});
```

通过所有这些概念，我们可以看到我们如何能够消耗原始流并能够用超集流包装它们。现在我们有了这个流，我们可以随时使用管道接口并将其管道到`Writable`流中。让我们将索引写入文件。为此，我们可以做一些简单的事情，比如`loremFinder.pipe(writeable)`。

如果我们打开文件，我们会发现它只是一堆随机数据。原因是我们将所有索引编码到 32 位缓冲区中。如果我们想看到它们，我们可以稍微修改我们的流实现。修改可能如下所示：`this.push(this.#startByteLoc.toString() + "\r\n");`。

通过这种修改，我们现在可以查看`output.txt`文件并查看所有索引。如果我们只是不断地将它们通过各种阶段进行管道传输，代码变得多么可读。

# 理解可读流接口

`Readable`流有一些可用的属性。它们都在 Node.js 文档中有解释，但我们感兴趣的主要是`highWaterMark`和`objectMode`。

`highWaterMark`允许我们声明内部缓冲区在流声明无法再接收任何数据之前应该容纳多少数据。我们实现的一个问题是我们没有处理暂停。如果达到了这个`highWaterMark`，流就会暂停。虽然大多数情况下我们可能不担心这个问题，但它可能会引起问题，通常是流实现者会遇到问题的地方。通过设置更高的`highWaterMark`，我们可以防止这些问题。另一种处理方法是检查运行`this.push`的结果。如果返回`true`，那么我们可以向流写入更多数据，否则，我们应该暂停流，然后在从另一个流得到信号时恢复。流的默认`highWaterMark`大约为 16 KB。

`objectMode` 允许我们构建不基于`Buffer`的流。当我们想要遍历对象列表时，这非常有用。我们可以设置一个管道系统，通过流传递对象并对其执行某种操作，而不是使用`for`循环或`map`函数。我们不仅限于普通的对象，而是几乎可以使用除`Buffer`之外的任何数据类型。关于`objectMode`的一点需要注意的是它改变了`highWaterMark`的计数方式。它不再计算存储在内部缓冲区中的数据量，而是计算直到暂停流之前将存储的对象数量。默认值为`16`，但如果需要，我们可以随时更改它。

有了这两个属性的解释，我们应该讨论一下可用的各种内部方法。对于每种流类型，都有一个我们*需要*实现的方法和一些我们*可以*实现的方法。

对于`Readable`流，我们只需要实现`_read`方法。这个方法给我们一个`size`参数，表示从底层数据源中读取的字节数。我们不总是需要遵循这个数字，但如果需要，它是可用的。

除了`_read`方法，我们需要使用`push`方法。这是将数据推送到内部缓冲区并帮助发出数据事件的方法，正如我们之前所见。正如我们之前所述，`push`方法返回一个布尔值。如果这个值为`true`，我们可以继续使用`push`，否则，我们应该停止推送数据，直到我们的`_read`实现再次被调用。

正如之前所述，当首次实现`Readable`流时，返回值可以被忽略。但是，如果我们注意到数据没有流动或数据丢失，通常的罪魁祸首是`push`方法返回了`false`，而我们继续尝试向流中推送数据。一旦发生这种情况，我们应该通过停止使用`push`方法直到再次调用`_read`来实现暂停。

可读接口的另外两个部分是`_destroy`方法以及如何使我们的流在无法处理的情况下出错。如果有任何低级资源需要释放，应该实现`_destroy`方法。

这可以是使用`fs.open`命令打开的文件句柄，也可以是使用`net`模块创建的套接字。如果发生错误，我们也应该使用它来发出错误事件。

为了处理流可能出现的错误，我们应该通过`this.emit`系统发出错误。如果我们抛出错误，根据文档，可能会导致意外的结果。通过发出错误，我们让流的用户处理错误并根据他们的意愿处理它。

# 实现可读流

根据我们在这里学到的知识，让我们实现我们之前讨论过的帧系统。从我们之前的示例中，我们应该清楚地知道我们如何处理这个问题。我们将持有底层资源，即套接字。然后，我们将找到`!!!BEGIN!!!`缓冲区并让其通过。然后我们将开始存储所持有的数据。一旦我们到达`!!!END!!!`缓冲区，我们将推出数据块。

在这种情况下，我们持有相当多的数据，但它展示了我们如何处理帧。双工流将展示我们如何处理一个简单的协议。示例如下：

1.  导入`Readable`流并创建一个名为`ReadMessagePassStream`的类：

```js
import { Readable } from 'stream';

class ReadMessagePassStream extends Readable {
}
```

1.  添加一些私有变量来保存流的内部状态：

```js
// inside of the ReadMessagePassStream class
#socket = null;
#bufBegin = Buffer.from("!!!START!!!");
#bufEnd = Buffer.from("!!!END!!!");
#internalBuffer = [];
#size = 0;
```

1.  创建一个像之前那样的`#data`方法。我们现在将寻找之前设置的开始和结束帧缓冲区`#bufBegin`和`#bufEnd`：

```js
#data = function(chunk) {
    let i = -1 
    if((i = chunk.indexOf(this.#bufBegin)) !== -1) {
        const tempBuf = chunk.slice(i + this.#bufBegin.byteLength);
        this.#size += tempBuf.byteLength;            
        this.#internalBuffer.push(tempBuf);
    }
    else if((i = chunk.indexOf(this.#bufEnd)) !== -1) {
        const tempBuf = chunk.slice(0, i);
        this.#size += tempBuf.byteLength;
        this.#internalBuffer.push(tempBuf);
        const final = Buffer.concat(this.#internalBuffer);            
        this.#internalBuffer = [];
        if(!this.push(final)) { 
            this.#socket.pause();
        }
    } else {
        this.#size += chunk.byteLength;
        this.#internalBuffer.push(chunk);
    }
}
```

1.  创建类的构造函数以初始化我们的私有变量：

```js
constructor(options) {
    if( options.objectMode ) {
        options.objectMode = false //we don't want it on
    }
    super(options);
    if(!options.socket ) {
        throw "Need a socket to attach to!"
    }
    this.#socket = options.socket;
    this.#socket.on('data', this.#data.bind(this));
    this.#socket.on('end', () => this.push(null));
}
```

一个新的信息是`objectMode`属性，它可以传递到我们的流中。这允许我们的流读取对象而不是原始缓冲区。在我们的情况下，我们不希望发生这种情况；我们希望使用原始数据。

1.  为确保我们的流将启动，请添加`_read`方法：

```js
// inside the ReadMessagePassStream
_read(size) {
    this.#socket.resume();
}
```

有了这段代码，我们现在有了一种处理套接字的方法，而不必在主代码中监听数据事件；它现在包装在这个`Readable`流中。除此之外，我们现在有了将此流传输到另一个流的能力。以下是测试工具代码：

```js
import { createWriteStream } from 'fs';

const socket = createConnection(3333);
const write = createWriteStream('./output.txt');
const messageStream = new ReadMessagePassStream({ socket });
messageStream.pipe(write);
```

我们在本地主机的端口`3333`上托管了一个服务器。我们创建一个`write`流，并将任何数据从我们的`ReadMessagePassStream`传输到该文件。如果我们将其连接到测试工具中的服务器，我们会注意到创建了一个输出文件，其中只包含我们发送的数据，而不包含帧代码。

我们正在使用的帧技术并不总是有效。就像在`lorem`示例中展示的那样，我们的数据可能在任何时候被分块，我们的`!!!START!!!`和`!!!END!!!`可能会出现在其中一个块的边界上。如果发生这种情况，我们的流将失败。我们需要额外的代码来处理这些情况，但这些示例应该提供了实现流代码所需的所有必要思路。

接下来，我们将看一下`Writable`流接口。

# 构建可写流

`Writable`流是我们写入数据的流，它可以连接到`Readable`、`Duplex`或`Transform`流。我们可以使用这些流以分块的方式写入数据，以便消费流可以以分块而不是一次性处理数据。可写流的 API 与`Readable`流非常相似，除了可用的方法。

# 理解可写流接口

可写流为我们提供了几乎与`Readable`流相同的选项，因此我们不会深入讨论。相反，我们将看一下可用于我们的四种方法——一种我们*必须*实现的方法和其余我们*可以*实现的方法：

+   `_write`方法允许我们执行任何类型的转换或数据操作，并为我们提供使用回调的能力。这个回调是信号，表明写流能够接收更多数据。

虽然不是固有的真实情况，但它会从内部缓冲区中弹出数据。然而，对于我们的目的，最好将回调视为处理更多数据的一种方式。

我们可以利用这一点来包装一个更原始的流，并在主数据块之前或之后添加我们自己的数据。我们将在我们的`Readable`流的实际对应物中看到这一点。

+   `_final`方法允许我们在可写流关闭之前执行任何必要的操作。这可能是清理资源或发送我们可能一直保留的任何数据。除非我们保留了诸如文件描述符之类的东西，我们通常不会实现这个方法。

+   `_destroy`方法与`Readable`流相同，应该类似于`_final`方法，只是我们可能会在这个方法上出现错误。

+   `_writev`方法使我们能够同时处理多个块。如果我们对块有某种排序系统，或者我们不在乎块的顺序，我们可以实现这一点。虽然现在可能不明显，但我们将在实现双工流时实现这个方法。用例可能有些有限，但仍然可能有益。

# 实现可写流

以下`Writable`流实现展示了我们的帧方法以及我们如何使用它在我们的数据上放置`!!!START!!!`和`!!!END!!!`帧。虽然简单，但它展示了帧的强大和如何在原始流周围构建更复杂的流：

1.  从流模块导入`Writable`类，并为`WriteMessagePassStream`创建外壳。将其设置为此文件的默认导出：

```js
import { Writable } from 'stream';

export default class WriteMessagePassStream extends Writable {
}
```

1.  添加私有状态变量和构造函数。确保不允许`objectMode`通过，因为我们要处理原始数据：

```js
// inside the WriteMessagePassStream
#socket = null;
#writing = false;
constructor(options) {
  if( options.objectMode ) { 
        options.objectMode = false;
    }
    if(!options.socket ) {
        throw new Error("A socket is required to construct this 
         stream!");
    }
    super(options);
    this.#socket = options.socket;
}
```

1.  向我们的类添加`_write`方法。将如下解释：

```js
_write(chunk, encoding, callback) { 
    if(!this.#writing ) {
        this.#writing = true;
        this.#socket.write("!!!START!!!");
    }
    let i = -1;
    let prevI = 0;
    let numCount = 0;
    while((i = chunk.indexOf([0x00], i)) !== -1) {
        const buf = chunk.slice(prevI, i);
        this.#socket.write(buf);
        this.#socket.write("!!!END!!!");
        if( i !== chunk.byteLength - 1 ) {
            this.#socket.write("!!!START!!!");
        } else {
            return callback();
        }
        numCount += 1;
    }
    if(!numCount ) {
        this.#socket.write(chunk);
    }
    return callback();
}
```

有了这段代码，我们可以看到一些与我们处理可读端类似的地方。一些值得注意的例外包括以下项目：

+   我们实现`_write`方法。再次忽略这个函数的编码参数，但我们应该检查这一点，以防我们得到一个意料之外的编码。chunk 是正在写入的数据，回调是在我们完成对这个块的写入处理时调用的。

+   由于我们正在包装一个套接字，并且我们不希望在发送数据完成后关闭它，我们需要向我们的流发送某种停止信号。在我们的情况下，我们使用简单的`0x00`字节。在更健壮的实现中，我们会利用其他东西，但现在这应该可以工作。

+   无论如何，我们要么使用帧，要么直接写入底层套接字。

+   我们在处理完成后调用回调。在我们的情况下，如果我们设置了`writing`标志，这意味着我们仍然处于一个帧中，我们希望提前返回，否则，我们希望将我们的流置于写入模式，并写出`!!!START!!!`，然后是块。同样，如果我们从不使用回调，我们的流将被无限暂停。回调告诉内部机制从内部缓冲区中拉取更多数据供我们消耗。

有了这段代码，我们现在可以看一下测试工具和我们如何利用它来创建一个服务器并处理实现我们帧上下文的传入`Readable`流：

```js
import { createServer } from 'net'
import WrappedWritableStream from '../writable/main.js'
const server = createServer((con) => {
 console.log('client connected. sending test data');
 const wrapped = new WrappedWritableStream({ socket : con });
 for(let i = 0; i < 100000; i++) {
 wrapped.write(`data${i}\r\n`);
 }
 wrapped.write(Buffer.from([0x00]));
 wrapped.end();
 console.log('finished sending test data');
});
server.listen(3333);
```

我们创建一个服务器，并在本地端口`3333`上监听。每当我们接收到一个连接时，我们用我们的`Writable`流包装它。然后我们发送一堆测试数据，一旦完成，我们写出`0x00`信号告诉我们的流这个帧已经完成，然后我们调用`end`方法告诉我们已经完成了这个套接字。如果我们在第一次之后添加了另一个测试运行，我们可以看到我们的帧系统是如何工作的。让我们继续做这件事。在`wrapped.write(Buffer.from([0x00]))`之后添加以下代码：

```js
for(let i = 0; i < 100000; i++) {
    wrapped.write(`more_data${i}\r\n`);
}
wrapped.write(Buffer.from([0x00]));
```

如果我们达到流的`highWaterMark`，写入流将暂停，直到读取流开始从中消耗。

如果我们现在使用之前的`Readable`流运行测试工具，我们将看到我们正在处理所有这些数据并将其写入文件，而没有任何传输。有了这两种流实现，我们现在可以通过套接字传输数据，而不需要传输任何帧。我们现在可以使用这个系统来实现前一章中的数据传递系统。然而，我们将实现一个`Duplex`流，它将改进这个系统，并允许我们处理多个可写块，这将在下一节中看到。

# 实现双工流

双工流就是这样，可以双向工作。它将`Readable`和`Writable`流合并为一个单一的接口。有了这种类型的流，我们现在可以直接从套接字中导入到我们的自定义流中，而不是像以前那样包装流（尽管我们仍然将其实现为包装流）。

关于`Duplex`流没有更多可以谈论的了，除了一个让新手对流类型感到困惑的事实。有两个单独的缓冲区：一个用于`Readable`，一个用于`Writable`。我们需要确保将它们视为单独的实例。这意味着我们在`_read`方法中使用的变量，在`_write`和`_writev`方法的实现中不应该使用，否则我们可能会遇到严重的错误。

如前所述，以下代码实现了一个`Duplex`流，以及一个计数机制，这样我们就可以利用`_writev`方法。正如在*理解可写流接口*部分所述，`_writev`方法允许我们一次处理多个数据块：

1.  从`stream`模块导入`Duplex`类，并为我们的`MessageTranslator`类添加外壳。导出这个类：

```js
import { Duplex } from 'stream';

export default class MessageTranslator extends Duplex {
}
```

1.  添加所有内部状态变量。每个变量将在接下来的部分中解释：

```js
// inside the MessageTranslator class
#socket = null;
#internalWriteBuf = new Map();
#internalReadHoldBuf = [];
#internalPacketNum = 0;
#readSize = 0;
#writeCounter = 0;
```

1.  为我们的类添加构造函数。我们将在这个构造函数中处理我们的`#socket`的数据事件，而不是像以前那样创建另一个方法：

```js
// inside the MessageTranslator class
constructor(opts) {
    if(!opts.socket ) {
        throw new Error("MessageTranslator stream needs a 
         socket!");
    }
    super(opts);
    this.#socket = opts.socket;
    // we are assuming a single message for each chunk
    this.#socket.on('data', (chunk) => {
        if(!this.#readSize ) {
            this.#internalPacketNum = chunk.readInt32BE();
            this.#readSize = chunk.readInt32BE(4);
            this.#internalReadHoldBuf.push(chunk.slice(8));
            this.#readSize -= chunk.byteLength - 8
        } else {
            this.#internalReadHoldBuf.push(chunk);
            this.#readSize -= chunk.byteLength;
        }
        // reached end of message
        if(!this.#readSize ) {
            this.push(Buffer.concat(this.#internalReadHoldBuf));
            this.#internalReadHoldBuf = [];
        }
    });
}
```

我们将自动假设每个块中有一条消息。这样处理会更容易。当我们获取数据时，我们将读取数据包编号，这应该是数据的前四个字节。然后我们读取消息的大小，这是接下来的`4`个字节数据。最后，我们将剩余的数据推入我们的内部缓冲区。一旦我们完成读取整个消息，我们将把所有内部块放在一起并推送它们出去。最后，我们将重置我们的内部缓冲区。

1.  向我们的类添加`_writev`和`_write`方法。记住，`_writev`方法用于多个数据块，所以我们需要循环遍历它们并将每个写出去：

```js
// inside the MessageTranslator class
_writev(chunks, cb) { 
    for(const chunk of chunks) {
        this.#processChunkHelper(chunk); //shown next
    }
    this.#writeHelper(cb); //shown next
}
_write(chunk, encoding, cb) {
    this.#processChunkHelper(chunk); //shown next
    this.#writeHelper(cb); //shown next
}
```

1.  添加处理块和实际写出的辅助方法。我们将使用数字`-1`作为`4`字节消息，表示我们已经完成了这条消息。

```js
// inside the MessageTranslator class
#processChunkHelper = function(chunk) {
    if(chunk.readInt32BE() === -1) { 
        this.#internalWriteBuf.get(this.#writeCounter).done = true;
        this.#writeCounter += 1;
        this.#internalWriteBuf.set(this.#writeCounter, {buf : [], 
         done : false});
    } else {
        if(!this.#internalWriteBuf.has(this.#writeCounter)) {
            this.#internalWriteBuf.set(this.#writeCounter, {buf : 
             [], done : false}); }
            this.#internalWriteBuf.get(this.#writeCounter)
             .buf.push(chunk);
        }
    }
}
#writeHelper = function(cb) {
    const writeOut = [];
    for(const [key, val] of this.#internalWriteBuf) { 
        if( val.done ) {
            const cBuf = Buffer.allocUnsafe(4);
            const valBuf = Buffer.concat(val.buf);
            const sizeBuf = Buffer.allocUnsafe(4);
            cBuf.writeInt32BE(valBuf.readInt32BE());
            sizeBuf.writeInt32BE(valBuf.byteLength - 4);
            writeOut.push(Buffer.concat([cBuf, sizeBuf, 
             valBuf.slice(4)]));
            val.buf = [];
        }
    }
    if( writeOut.length ) {
        this.#socket.write(Buffer.concat(writeOut));
    }
    cb();
}
```

我们的`#processChunkHelper`方法检查我们是否达到了神奇的`-1` `4`字节消息，表示我们已经完成了消息的写入。如果没有，我们将继续向我们的内部缓冲区（数组）添加。一旦我们到达末尾，我们将把所有数据放在一起，然后转移到下一个数据包。

我们的`#writeHelper`方法将循环遍历所有这些数据包，并检查它们是否有任何一个已经完成。如果有，它将获取数据包编号、缓冲区的大小、数据本身，并将它们全部连接在一起。一旦完成这些操作，它将重置内部缓冲区，以确保我们不会泄漏内存。我们将把所有这些数据写入套接字，然后调用回调函数表示我们已经完成写入。

1.  通过实现我们之前的`_read`方法来完成`Duplex`流。`_final`方法应该只是调用回调函数，因为没有剩余的处理：

```js
// inside the MessageTranslator class
_read() {
    this.#socket.resume();
}
_final(cb) {
    cb(); // nothing to do since it all should be consumed at this 
          // point
}
```

当顺序不重要且我们只是处理数据并可能将其转换为其他形式时，应该真正使用`_writev`。这可能是一个哈希算法或类似的东西。在几乎所有情况下，应该使用`_write`方法。

虽然这个实现有一些缺陷（其中一个是如果我们达到`-1`数字时没有寻找可能的其他数据包），但它展示了我们如何构建一个`Duplex`流，以及处理消息的另一种方式。不建议自己设计在套接字之间传输数据的方案（正如我们将在下一章中看到的），但如果有一个新的规范出来，我们总是可以利用`Duplex`套接字来编写它。

如果我们用我们的测试工具测试这个实现，我们应该得到一个名为`output.txt`的文件，其中包含了双工加上数字消息被写入了 10 万次，以及一个尾随的换行符。再次强调，`Duplex`流只是一个单独的`Readable`和`Writable`流组合在一起，应该在实现数据传输协议时使用。

我们将要看的最后一个流是`Transform`流。

# 实现 Transform 流

在这四个流中，这可能是最有用的，也可能是最常用的流之一。`Transform`流连接了流的可读和可写部分，并允许我们操纵流中传输的数据。这听起来可能类似于`Duplex`。嗯，`Transform`流是`Duplex`流的一种特殊类型！

`Transform`流的内置实现包括`zlib`模块中实现的任何流。基本思想是我们不仅仅是试图将信息从一端传递到另一端；我们试图操纵这些数据并将其转换为其他形式。这就是`zlib`流给我们的。它们压缩和解压数据。`Transform`流将数据转换为另一种形式。这也意味着我们可以使一个转换流成为单向转换；从转换流输出的任何东西都无法被撤销。我们将在这里创建一个这样的`Transform`流，具体地创建一个字符串的哈希。

首先，让我们来看一下`Transform`流的接口。

# 理解 Transform 流接口

我们可以访问两种方法，几乎无论如何我们都想要实现。其中一个让我们可以访问底层数据块，并允许我们对其进行转换。我们使用`_transform`方法来实现这一点。它接受三个参数：我们正在处理的数据块，编码和一个回调，让底层系统知道我们已经准备好处理更多信息。

与`Writable`流的`_write`回调不同的是，回调函数的一个特殊之处是我们可以向其传递数据，以在`Transform`流的可读端发出数据，或者我们可以不传递任何数据，以表示我们想要处理更多数据。这使我们只在需要时发送数据事件，而不是几乎总是需要传递它们。

另一种方法是`_flush`方法。这允许我们完成可能仍在持有的任何数据的处理。或者，它将允许我们在流中发送的所有数据都输出一次。这就是我们将用字符串哈希函数实现的功能。

# 实现 Transform 流

我们的`Transform`流将接收字符串数据并继续运行哈希算法。一旦完成，它将输出计算出的最终哈希值。哈希函数是一种我们将某种形式的输入转换为唯一数据的函数。这个唯一的数据（在我们的例子中是一个数字）不应该容易发生碰撞。碰撞是两个不同值可能得到相同哈希值的概念。在我们的情况下，我们将字符串转换为 JavaScript 中的 32 位整数，因此我们很少发生碰撞，但并非不可能。

以下是示例：

```js
// implemented in stream form from 
// https://stackoverflow.com/questions/7616461/generate-a-hash-from-string-in-javascript
export default class StreamHashCreator extends Transform {
    #currHash = 0; 
    constructor(options={}) {
        if( options.objectMode ) {
            throw new Error("This stream does not support object mode!");
        }
        options.decodeStrings = true;
        super(options);
    }
    _transform(chunk, encoding, callback) {
        if( Buffer.isBuffer(chunk) ) { 
            const str = chunk.toString('utf8');
            for(let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                this.#currHash = ((this.#currHash << 5) - this.#currHash ) 
                 + char;
                this.#currHash |= 0;
            }
        }
        callback(); 
    }
    _flush(callback) {
        const buf = Buffer.alloc(4);
        buf.writeInt32BE(this.#currHash);
        this.push(buf); 
        callback(null);
    }
}
```

前一个流的每个函数都在下面解释：

1.  我们需要持久化的唯一一件事是直到流被销毁的当前哈希码。这将允许哈希函数跟踪我们已经传递给它的内容，并在每次写入后处理数据。

1.  我们在这里进行检查，看我们收到的块是否是一个`Buffer`。由于我们确保打开了`decodeStrings`选项，这意味着我们应该总是得到缓冲区，但检查仍然有帮助。

1.  虽然哈希函数的内容可以在提供的 URL 中看到，但我们需要担心的唯一重要事情是，我们要调用我们的回调，就像我们在实现`Writable`流时所做的那样。

1.  一旦我们准备生成数据，我们就使用`push`方法，就像我们在`Readable`流中所做的那样。记住，`Transform`流只是允许我们操纵输入数据并将其转换为输出的特殊`Duplex`流。我们还可以将代码的最后两行更改为`callback(null, buf)`；这只是我们之前看到的简写。

现在，如果我们对前面的代码运行一些测试用例，我们会发现每个唯一字符串输入都会得到一个唯一的哈希码，但当我们输入完全相同的内容时，我们会得到相同的哈希码。这意味着我们的哈希函数很好，我们可以将其连接到流应用程序中。

# 使用流生成器

到目前为止，我们所看到的一切都展示了我们如何利用 Node.js 中的所有内置系统来创建流应用程序。然而，对于那些一直在按顺序阅读本书的人来说，我们已经讨论了生成器。那些一直在思考它们的人会注意到流和生成器之间有很强的相关性。事实上就是这样！我们可以利用生成器来连接到流 API。

有了这个概念，我们可以构建既可以在浏览器中工作又可以在 Node.js 中工作的生成器，而不需要太多的开销。我们甚至在第六章中看到了如何使用 Fetch API 获取底层流。现在，我们可以编写一个可以与这两个子系统一起工作的生成器。

现在，让我们只看一个`async`生成器的示例，以及我们如何将它们连接到 Node.js 流系统中。示例将是看看我们如何将生成器作为`Readable`流的输入：

1.  我们将建立一个`Readable`流来读取英语字母表的 26 个小写字符。我们可以通过编写以下生成器来轻松实现这一点：

```js
function* handleData() {
    let _char = 97;
    while(_char < 123 ) { //char code of 'z'
        yield String.fromCharCode(_char++);
    }
}
```

1.  当字符代码低于`123`时，我们继续发送数据。然后我们可以将其包装在`Readable`流中，如下所示：

```js
const readable = Readable.from(handleData());
readable.on('data', (chunk) => {
    console.log(chunk);
});
```

如果我们现在运行这段代码，我们会看到控制台中出现字符*a*到*z*。`Readable`流知道它已经结束，因为生成器生成了一个具有两个键的对象。`value`字段给出了`yield`表达式的值，`done`告诉我们生成器是否已经完成运行。

这让可读接口知道何时发送`data`事件（通过我们产生一个值）以及何时关闭流（通过将`done`键设置为`true`）。我们还可以将可读系统的输出管道到可写系统的输出，以链接整个过程。这可以很容易地通过以下代码看到：

```js
(async() => {
    const readable2 = Readable.from(grabData());
    const tempFile = createWriteStream('./temp.txt');
    readable2.pipe(tempFile);
    await once(tempFile, 'finish');
    console.log('all done');
})();
```

通过生成器和`async`/`await`实现流可能看起来是一个好主意，但只有在我们试图将一个已经是`async`/`await`的代码片段与流结合时，我们才应该利用它。始终要追求可读性；利用生成器或`async`/`await`方法很可能会导致代码难以阅读。

通过前面的例子，我们已经将生成器的可读性与利用管道机制发送到文件相结合。随着`async`/`await`和生成器成为 JavaScript 语言中的构造，流很快就会成为一个一流的概念。

# 总结

流是编写高性能 Node.js 代码的支柱之一。它允许我们不阻塞主线程，同时仍然能够处理数据。流 API 允许我们为我们的目的编写不同类型的流。虽然这些流大多数将是转换流的形式，但看到我们如何实现其他三种流也是很好的。

我们将在下一章中看到的最后一个主题是数据格式。处理除了 JSON 之外的不同数据格式将使我们能够与许多大数据提供商进行接口，并能够处理他们喜欢使用的数据格式。我们将看到他们如何利用流来实现所有的格式规范。


# 第八章：数据格式 - 查看除 JSON 之外的不同数据类型

我们几乎已经完成了关于服务器端 JavaScript 的讨论。一个话题似乎鲜为人知，但在与其他系统进行接口或使事情更快时经常出现的话题是以不同格式传输数据。其中最常见的，如果不是最常见的格式就是 JSON。JSON 是非常容易与之进行接口的数据格式之一，特别是在 JavaScript 中。

在 JavaScript 中，我们不必担心不匹配类的 JSON 对象。如果我们使用的是像 Java（或者正在使用 TypeScript 的人）这样的强类型语言，我们将不得不担心以下事项：

+   创建一个模仿 JSON 对象格式的类。

+   创建一个基于嵌套对象数量的嵌套映射结构。

+   根据我们收到的 JSON 创建即时类。

这些都不一定难，但当我们与使用这些语言编写的系统进行接口时，它可能会增加速度和复杂性。使用其他数据格式时，我们可能会获得一些主要的速度优势；不仅可能会获得更小的数据传输量，而且其他语言也能更容易地解析对象。当我们转向基于模式的数据格式时，甚至会获得更多的好处，比如版本控制，这可以使向后兼容更容易。

考虑到所有这些，让我们继续看一下 JSON，并了解一些利弊，以及我们在使用它时得到的损失。除此之外，我们将看一下一个新的自定义格式，我们将为我们的服务创建一个更小的数据传输格式。之后，我们将看一下无模式数据格式，比如 JSON，最后，我们将看一下基于模式的格式。

这一章可能比其他章节都要轻一些，但在开发企业应用程序或与其进行接口时，这是一个非常有用的章节。

本章涵盖的主题如下：

+   使用 JSON

+   JSON 编码

+   JSON 解码

+   查看数据格式

在 TypeScript 中，如果我们愿意，我们可以只使用`any`类型，但这在某种程度上会削弱 TypeScript 的目的。虽然本书不会涉及 TypeScript，但知道它存在，并且很容易看出开发人员在开发后端应用程序时可能会遇到它。

# 技术要求

完成本章需要以下工具：

+   一个编辑器或 IDE，最好是 VS Code

+   支持 Node.js 的操作系统

+   在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter08)找到的代码。

# 使用 JSON

如前所述，JSON 提供了一个易于使用和操作的接口，用于在服务之间发送和接收消息。对于不了解的人来说，JSON 代表**JavaScript 对象表示法**，这也是它与 JavaScript 接口得很好的原因之一。它模仿了 JavaScript 对象的许多行为，除了一些基本类型（例如函数）。这也使得它非常容易解析。我们可以使用内置的`JSON.parse`函数将 JSON 的字符串化版本转换为对象，或者使用`JSON.stringify`将我们的对象转换为其在网络上传输的格式。

那么在使用 JSON 时有哪些缺点呢？首先，当通过网络发送数据时，格式可能会变得非常冗长。考虑一个具有以下格式的对象数组：

```js
{
    "name" : "Bob",
    "birth" : "01/02/1993",
    "address" : {
        "zipcode" : 11111,
        "street" : "avenue of av.",
        "streetnumber" : 123,
        "state" : "CA",
        "country" : "US"
    },
    "contact" : {
        "primary" : "111-222-3333",
        "secondary" : "444-555-6666",
        "email" : "bob@example.com"
    }
}
```

对于那些曾经处理过联系表单或客户信息的人来说，这可能是一个常见的情景。现在，虽然我们应该为网站涉及某种分页，但我们仍然可能一次获取`100`甚至`500`个这样的数据。这可能很容易导致巨大的传输成本。我们可以使用以下代码来模拟这种情况：

```js
const send = new Array(100);
send.fill(json);
console.log('size of over the wire buffer is: ',
 Buffer.from(JSON.stringify(send)).byteLength);
```

通过使用这种方法，我们可以得到对于我们发送的`100`条数据进行字符串化后的缓冲区的字节长度。我们将看到它大约为 22 KB 的数据。如果我们将这个数字增加到`500`，我们可以推断出它将大约为 110 KB 的数据。虽然这可能看起来不像是很多数据，但我们可能会看到这种类型的数据被发送到智能手机上，我们希望限制我们传输的数据量，以免耗尽电池。

我们尚未深入讨论手机和我们的应用程序，尤其是在前端，但这是我们需要越来越意识到的事情，因为我们正在变得越来越像一个远程商业世界。许多用户，即使没有应用程序的移动版本，仍然会尝试使用它。一个个人的轶事是利用为桌面应用程序设计的电子邮件服务，因为移动版本的应用程序中缺少一些功能。我们始终需要意识到我们正在传输的数据量，但移动设备已经使这个想法成为主要目标。

解决这个问题的一种方法是利用某种压缩/解压缩格式。一个相当知名的格式是`gzip`。这种格式非常快速，没有数据质量损失（一些压缩格式有这个问题，比如 JPEG），并且在网页中非常普遍。

让我们继续使用 Node.js 中的`zlib`模块来`gzip`这些数据。以下代码展示了`zlib`中一个易于使用的`gzip`方法，并展示了原始版本和 gzip 版本之间的大小差异：

```js
gzipSync(Buffer.from(JSON.stringify(send))).byteLength
```

现在我们将看到经过 gzip 压缩的版本只有 301 字节，对于 500 长度的数组，我们看到大约 645 字节的 gzip 版本。这是相当节省的！然而，这里有几点需要记住。首先，我们在数组中的每个项目中使用完全相同的对象。压缩算法是基于模式的，因此一遍又一遍地看到完全相同的对象给了我们对原始形式到压缩形式的错误感觉。这并不意味着这不是未压缩与压缩数据之间大小差异的指示，但在测试各种格式时需要牢记这一点。根据各种网站，我们将看到原始数据的 4-10 倍的压缩比（这意味着如果原始数据为 1 MB，我们将看到压缩大小从 250 KB 到 100 KB 不等）。

我们可以创建一个自己的格式，以更紧凑的方式表示数据，而不是使用 JSON。首先，我们将只支持三种项目类型：整数、浮点数和字符串。其次，我们将在消息头中存储所有的键。

模式最好可以描述为传入数据的定义。这意味着我们将知道如何解释传入的数据，而不必寻找特殊的编码符号来告诉我们负载的结束（尽管我们的格式将使用一个结束信号）。

我们的模式将看起来像以下内容：

1.  我们将为消息的头部和主体使用包装字节。头部将用`0x10`字节表示，主体将用`0x11`字节表示。

1.  我们将支持以下类型，它们的转换看起来类似于以下内容：

+   整数：`0x01`后跟一个 32 位整数

+   浮点数：`0x02`后跟一个 32 位整数

+   字符串：`0x03`后跟字符串的长度，后跟数据

这应该足够让我们理解数据格式以及它们可能与仅对 JSON 进行编码和解码有所不同的工作方式。在接下来的两个部分中，我们将看到如何使用流来实现编码器和解码器。

# 实现编码器

我们将使用转换流来实现编码器和解码器。这将为我们提供最大的灵活性，因为我们实际上正在实现流，并且它已经具有我们需要的许多行为，因为我们在技术上正在转换数据。首先，我们需要一些通用的辅助方法，用于编码和解码我们特定数据类型的方法，并将所有这些方法放在一个`helpers.js`辅助文件中。编码函数将如下所示：

```js
export const encodeString = function(str) {
    const buf = Buffer.from(str);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.byteLength);
    return Buffer.concat([Buffer.from([0x03]), len, buf]);
}
export const encodeNumber = function(num) {
    const type = Math.round(num) === num ? 0x01 : 0x02;
    const buf = Buffer.alloc(4);
    buf.writeInt32BE(num);
    return Buffer.concat([Buffer.from([type]), buf]); 
}
```

编码字符串接受字符串并输出将保存解码器工作信息的缓冲区。首先，我们将字符串更改为`Buffer`格式。接下来，我们创建一个缓冲区来保存字符串的长度。然后，我们利用`writeUInt32BE`方法存储缓冲区的长度。

对于那些不了解字节/位转换的人来说，8 位信息（位要么是 1 要么是 0-我们可以提供的最低形式的数据）组成 1 个字节。我们要写入的 32 位整数由 4 个字节组成（32/8）。该方法的 U 部分表示它是无符号的。无符号表示我们只想要正数（在我们的情况下长度只能是 0 或正数）。有了这些信息，我们就可以看到为什么我们为这个操作分配了 4 个字节，以及为什么我们要使用这个特定的方法。有关缓冲区的写入/读取部分的更多信息，请访问[`nodejs.org/api/buffer.html`](https://nodejs.org/api/buffer.html)，因为它深入解释了我们可以访问的缓冲区操作。我们只会解释我们将要使用的操作。

一旦我们将字符串转换为缓冲区格式并获得字符串的长度，我们将写出一个缓冲区，其中`type`作为第一个字节，在我们的情况下是`0x03`字节；字符串的长度，这样我们就知道传入缓冲区的字符串有多长；最后，字符串本身。这个方法应该是两个辅助方法中最复杂的一个，但从解码的角度来看，它应该是有意义的。当我们读取缓冲区时，我们不知道字符串的长度。因此，我们需要在此类型的前缀中有一些信息，以知道实际读取多少。在我们的情况下，`0x03`告诉我们类型是字符串，根据我们之前建立的数据类型协议，我们知道接下来的 4 个字节将是字符串的长度。最后，我们可以使用这些信息来在缓冲区中向前读取，以获取字符串并将其解码回字符串。

`encodeNumber`方法更容易理解。首先，我们检查数字的四舍五入是否等于自身。如果是，那么我们知道我们正在处理一个整数，否则，我们将其视为浮点数。对于不了解的人来说，在大多数情况下，在 JavaScript 中知道这些信息并不太重要（尽管 V8 引擎在知道它正在处理整数时会使用某些优化），但如果我们想要将这种数据格式与其他语言一起使用，那么差异就很重要了。

接下来，我们分配了 4 个字节，因为我们只打算写出 32 位有符号整数。有符号意味着它们将支持正数和负数（再次，我们不会深入探讨两者之间的巨大差异，但对于那些好奇的人来说，如果我们使用有符号整数，我们实际上限制了我们可以在其中存储的最大值，因为我们必须利用其中一个位告诉我们这个数字是正数还是负数）。然后，我们写出最终的缓冲区，其中包括我们的类型，然后是缓冲区格式中的数字。

现在，使用`helper.js`文件中的辅助方法和以下常量进行如下操作：

```js
export const CONSTANTS = {
    object : 0x04,
    number : 0x01,
    floating : 0x02,
    string : 0x03,
    header : 0x10,
    body : 0x11
}
```

我们可以创建我们的`encoder.js`文件：

1.  导入必要的依赖项，并创建我们的`SimpleSchemaWriter`类的框架：

```js
import { Transform } from 'stream';
import { encodeString, encodeNumber } from './helper.js';

export default class SimpleSchemaWriter extends Transform {
}
```

1.  创建构造函数，并确保始终打开`objectMode`：

```js
// inside our SimpleSchemaWriter class
constructor(opts={}) {
    opts.writableObjectMode = true;
    super(opts);
}
```

1.  添加一个私有的`#encode`辅助函数，它将为我们进行底层数据检查和转换：

```js
// inside of our SimpleSchemaWriter class
#encode = function(data) {
    return typeof data === 'string' ?
            encodeString(data) :
            typeof data === 'number' ?
            encodeNumber(data) :
            null;
}
```

1.  编写我们`Transform`流的主要`_transform`函数。该流的详细信息将在下文中解释：

```js
_transform(chunk, encoding, callback) {
    const buf = [];
    buf.push(Buffer.from([0x10]));
    for(const key of Object.keys(chunk)) { 
        const item = this.#encode(key);
        if(item === null) {
            return callback(new Error("Unable to parse!"))
        }
        buf.push(item);
    }
    buf.push(Buffer.from([0x10])); 
    buf.push(Buffer.from([0x11]));
    for(const val of Object.values(chunk)) { 
        const item = this.#encode(val);
        if(item === null) {
            return callback(new Error("Unable to parse!"))
        }
        buf.push(item);
    }
    buf.push(Buffer.from([0x11]));
    this.push(Buffer.concat(buf)); 
    callback();
}
```

总的来说，`transform`函数应该与我们之前实现的`_transform`方法很相似，但有一些例外：

1.  我们编码的第一部分是包装我们的标头（对象的键）。这意味着我们需要写出我们的标头分隔符，即`0x10`字节。

1.  我们将遍历对象的所有键。然后，我们将利用`private`方法`encode`。这个方法将检查键的数据类型，并利用我们之前讨论过的辅助方法之一返回编码。如果它得到一个它不理解的类型，它将返回`null`。然后我们将返回一个`Error`，因为我们的数据协议不理解这种类型。

1.  一旦我们遍历完所有的键，我们将再次写出`0x10`字节，表示我们已经完成了标头，并写出`0x11`字节告诉解码器我们要开始消息的主体部分。（我们可以在这里使用`helpers.js`文件中的常量，而且我们可能应该这样做，但这应该有助于理解底层协议。解码器将利用这些常量来展示更好的编程实践。）

1.  现在我们将遍历对象的值，并将它们通过与标头相同的编码系统运行，并在不理解数据类型时返回一个`Error`。

1.  一旦我们完成了主体部分，我们将再次推送`0x11`字节，表示我们已经完成了主体部分。这将是解码器停止转换此对象并发送出它一直在转换的信号。然后我们将所有这些数据推送到我们`Transform`流的`Readable`部分，并使用回调来表示我们已准备好处理更多数据。

我们的编码方案的整体结构存在一些问题（我们不应该使用单个字节作为包装器，因为它们很容易被我们的编码器和解码器误解），我们应该支持更多的数据类型，但这应该对如何为更常用的数据格式构建编码器有一个很好的理解。

现在，我们无法测试这一点，除了它能正确输出编码外，但一旦我们的解码器运行起来，我们就能测试是否两边得到相同的对象。现在让我们来看看这个系统的解码器。

# 实现解码器

解码器的状态比编码器要复杂得多，这通常是数据格式的特点。当处理原始字节时，尝试从中解析信息通常比以原始格式写出数据更困难。

让我们来看看我们将用来解码支持的数据类型的辅助方法：

```js
import { CONSTANTS } from './helper.js';

export const decodeString = function(buf) {
    if(buf[0] !== CONSTANTS.string) {
        return false;
    }
    const len = buf.readUInt32BE(1);
    return buf.slice(5, 5 + len).toString('utf8');
}
export const decodeNumber = function(buf) {
    return buf.readInt32BE(1);
}
```

`decodeString`方法展示了我们如何处理格式不正确的数据的错误，而`decodeNumber`方法则没有展示这一点。对于`decodeString`方法，我们需要从缓冲区中获取字符串的长度，我们知道这是传入的缓冲区的第二个字节。基于此，我们知道可以通过从缓冲区的第五个字节开始（第一个字节告诉我们这是一个字符串；接下来的四个字节是字符串的长度）获取字符串，并且获取直到达到字符串的长度。然后我们通过`toString`方法运行这个缓冲区。

`decodeNumber`非常简单，因为我们只需要读取告诉我们它是一个数字的第一个字节后面的 4 个字节（再次，我们应该在这里进行检查，但我们保持简单）。这展示了我们需要解码支持的数据类型的两个主要辅助方法。接下来，我们将看一下实际的解码器。它将看起来像下面这样。

如前所述，解码过程有点复杂。这是由于许多原因，如下所述：

+   我们直接处理字节，所以我们需要做相当多的处理。

+   我们正在处理头部和主体部分。如果我们创建了一个非基于模式的系统，我们可能可以编写一个解码器，其状态不像这个解码器中那么多。

+   同样，由于我们直接处理缓冲区，所有数据可能不会一次全部到达，因此我们需要处理这种情况。编码器不必担心这一点，因为我们正在以对象模式操作可写流。

考虑到这一点，让我们来看一下解码流程：

1.  我们将使用与以前的`Transform`流相同类型的设置来设置我们的解码流。我们将设置一些私有变量来跟踪我们在解码器中的状态：

```js
import { Transform } from 'stream'
import { decodeString, decodeNumber, CONSTANTS } from './helper.js'

export default class SimpleSchemaReader extends Transform {
    #obj = {}
    #inHeaders = false
    #inBody = false
    #keys = []
    #currKey = 0
}
```

1.  接下来，我们将在解码过程中使用一个索引。我们不能简单地一次读取一个字节，因为解码过程以不同的速度运行（当我们读取一个数字时，我们要读取 5 个字节；当我们读取一个字符串时，至少要读取 6 个字节）。因此，使用`while`循环会更好：

```js
#decode = function(chunk, index, type='headers') { 
        const item = chunk[index] === CONSTANTS.string ?
            decodeString(chunk.slice(index)) :
            decodeNumber(chunk.slice(index, index + 5));

        if( type === 'headers' ) {
            this.#obj[item] = null;
        } else {
            this.#obj[this.#keys[this.#currKey]] = item;
        }
        return chunk[index] === CONSTANTS.string ?
            index + item.length + 5 :
            index + 5;
    }
    constructor(opts={}) {
        opts.readableObjectMode = true;
        super(opts);
    }
    _transform(chunk, encoding, callback) {
        let index = 0; //1
        while(index <= chunk.byteLength ) {
        }
    }
```

1.  现在，我们要检查当前字节，看它是头部还是主体的分隔标记。这将让我们知道我们是在处理对象键还是对象值。如果我们检测到`headers`标志，我们将设置`#inHeaders`布尔值，表示我们在头部。如果我们在主体中，我们还有更多工作要做：

```js
// in the while loop
const byte = chunk[index];
if( byte === CONSTANTS.header ) { 
    this.#inHeaders = !this.#inHeaders
    index += 1;
    continue;
} else if( byte === CONSTANTS.body ) { 
    this.#inBody = !this.#inBody
    if(!this.#inBody ) { 
        this.push(this.#obj);
        this.#obj = {};
        this.#keys = [];
        this.#currKey = 0;
        return callback();
    } else {
        this.#keys = Object.keys(this.#obj); 
    }
    index += 1;
    continue;
}
if( this.#inHeaders ) { 
    index = this.#decode(chunk, index);
} else if( this.#inBody ) {
    index = this.#decode(chunk, index, 'body');
    this.#currKey += 1;
} else {
    callback(new Error("Unknown state!"));
}
```

1.  接下来，接下来的段落将解释获取每个 JSON 对象的头部和值的过程。

首先，我们将把我们的主体布尔值更改为当前状态的相反值。接下来，如果我们从主体内部到主体外部，这意味着我们已经完成了这个对象。因此，我们可以推出我们当前正在处理的对象，并重置所有内部状态变量（临时对象`#obj`，我们从头部获取的临时`#keys`集合，以及`#currKey`，用于在主体中工作时知道我们正在处理哪个键）。一旦我们完成这些操作，我们就可以运行回调（我们在这里返回，所以我们不会运行更多的主体）。如果我们不这样做，我们将继续循环，并处于一个糟糕的状态。

否则，我们已经浏览了有效负载的头部，并已经到达了每个对象的值。我们将把我们的私有`#keys`变量设置为对象的键（因为在这一点上，头部应该已经从头部获取了所有的键）。我们现在可以开始看到解码过程。

如果我们在头部，我们将运行我们的私有`#decode`方法，并且不使用第三个参数，因为默认情况下是以头部运行该方法。否则，我们将像在主体中一样运行它，并传递第三个参数以说明我们在主体中。此外，如果我们在主体中，我们将增加我们的`#currKey`变量。

最后，我们可以看一下解码过程的核心，`#decode`方法。我们根据缓冲区中的第一个字节获取项目，这将告诉我们应该运行哪个解码辅助方法。然后，如果我们在头部模式下运行此方法，我们将为我们的临时对象设置一个新键，并将其值设置为 null，因为一旦我们到达主体，它将被填充。如果我们在主体模式下，我们将设置与我们正在循环的`#keys`数组中的`#currKey`索引对应的键的值，一旦我们进入主体，我们就会开始循环。

有了这个代码解释，正在发生的基本过程可以总结为几个基本步骤：

1.  我们需要浏览头部并将对象的键设置为这些值。我们暂时将这些键的值设置为 null，因为它们将在以后填充。

1.  一旦我们离开头部部分并进入主体部分，我们可以从临时对象中获取所有键，并且我们在那时进行的解码运行应该对应于数组中当前键索引处的键。

1.  一旦我们离开主体部分，我们将重置所有临时变量的状态，并发送相应的对象，因为我们已经完成了解码过程。

这可能看起来令人困惑，但我们所做的就是将头部与相同索引处的主体元素对齐。如果我们想要将键和值的数组放在一起，这将类似于以下代码：

```js
const keys = ['item1', 'item2', 'item3'];
const values = [1, 'what', 2.2];
const tempObj = {};
for(let i = 0; i < keys.length; i++) {
    tempObj[keys[i]] = null;
}
for(let i = 0; i < values.length; i++) {
    tempObj[keys[i]] = values[i];
}
```

这段代码几乎与之前的缓冲区完全相同，只是我们必须使用原始字节而不是更高级的项目，如字符串、数组和对象。

解码器和编码器都完成后，我们现在可以通过我们的编码器和解码器运行一个对象，看看我们是否得到相同的值。让我们运行以下测试代码：

```js
import encoder from './encoder.js'
import decoder from './decoder.js'
import json from './test.json'

const enc = new encoder();
const dec = new decoder();
enc.pipe(dec);
dec.on('data', (obj) => {
    console.log(obj);
});
enc.write(json);
```

我们将使用以下测试对象：

```js
{
    "item1" : "item",
    "item2" : 12,
    "item3" : 3.3
}
```

我们将看到，当我们将数据通过编码器传输到解码器时，我们将得到相同的对象。现在，我们已经创建了自己的编码和解码方案，但它与 JSON 相比在传输大小上如何？使用这个负载，我们实际上增加了大小！如果我们考虑一下，这是有道理的。我们必须添加所有特殊的编码项（除了数据之外的所有信息，如`0x10`和`0x11`字节），但现在我们开始向我们的列表中添加更多的大型数字项。我们将看到，我们开始击败基本的`JSON.stringify`和`JSON.parse`。

```js
{
    "item1" : "item",
    "item2" : 120000000,
    "item3" : 3.3,
    "item4" : 120000000,
    "item5" : 120000000,
    "item6" : 120000000
}
```

这是因为字符串化的数字被转换成了字符串版本的数字，所以当我们得到大于 5 个字节的数字时，我们开始节省字节（1 个字节用于数据类型，4 个字节用于 32 位数字编码）。对于字符串，我们永远不会节省，因为我们总是添加额外的 5 个字节的信息（1 个字节用于数据类型，4 个字节用于字符串的长度）。

在大多数编码和解码方案中，情况都是如此。它们处理数据的方式取决于传递的数据类型。在我们的情况下，如果我们通过网络发送大量的高度数值化的数据，我们的方案可能效果更好，但如果我们传输字符串，我们将无法从这种编码和解码方案中获益。在我们看一些在野外广泛使用的数据格式时，请记住这一点。

记住，这种编码和解码方案并不是用于实际环境的，因为它充满了问题。然而，它展示了构建数据格式的基本主题。虽然大多数人永远不需要构建数据格式，但了解构建数据格式时发生的情况以及数据格式可能需要根据其主要处理的数据类型专门化其编码和解码方案是很好的。

# 数据格式的一瞥

现在我们已经看过了我们自己的数据格式，让我们继续看看一些目前流行的数据格式。这不是对这些数据格式的详尽了解，而是对数据格式和我们可能在野外发现的内容的介绍。

我们将要查看的第一种数据格式是无模式格式。如前所述，基于模式的格式要么提前发送数据的模式，要么将模式与数据本身一起发送。这通常允许数据以更紧凑的形式传入，同时确保双方同意数据接收方式。另一种形式是无模式，我们通过规范发送数据的新形式，但解码所有信息都是通过规范完成的。

JSON 就是其中一种格式。当我们发送 JSON 时，我们必须对其进行编码，然后在另一端对其进行解码。另一种无模式数据格式是 XML。这两种格式对于 Web 开发人员来说应该非常熟悉，因为我们广泛使用 JSON，并且在组装前端（HTML）时使用一种 XML 形式。

另一种流行的格式是`MessagePack`（[`msgpack.org/index.html`](https://msgpack.org/index.html)）。`MessagePack`是一种以比 JSON 更小的有效载荷而闻名的格式。`MessagePack`的另一个优点是有许多语言为其编写了原生库。我们将看一下 Node.js 版本，但请注意，这可以在前端（浏览器）和服务器上都可以使用。所以让我们开始吧：

1.  我们将使用以下命令通过`npm install`安装`what-the-pack`扩展。

```js
> npm install what-the-pack
```

1.  完成后，我们可以开始使用这个库。通过以下代码，我们可以看到在网络上传输这种数据格式是多么容易。

```js
import MessagePack from 'what-the-pack';
import json from '../schema/test.json';

const { encode, decode } = MessagePack.initialize(2**22);
const encoded = encode(json);
const decoded = decode(encoded);
console.log(encoded.byteLength, Buffer.from(JSON.stringify(decoded)).byteLength);
console.log(encoded, decoded);
```

我们在这里看到的是对`what-the-pack`页面上示例的略微修改版本（[`www.npmjs.com/package/what-the-pack`](https://www.npmjs.com/package/what-the-pack)）。我们导入了该包，然后初始化了该库。该库的一个不同之处在于，我们需要为编码和解码过程初始化一个缓冲区。这就是`initialize`方法中的`2**22`所做的。我们正在初始化一个大小为 2 的 22 次方字节的缓冲区。这样，它可以轻松地切割缓冲区并复制它，而不需要昂贵的基于数组的操作。敏锐的观察者还会注意到的另一件事是，该库不是基于流的。他们很可能这样做是为了在浏览器和 Node.js 之间保持兼容。除了这些小问题，整个库的工作方式与我们想象的一样。

第一个控制台日志向我们展示了编码后的缓冲区比 JSON 版本少了 5 个字节。虽然这确实表明该库给我们提供了更紧凑的形式，但应该注意到，有些情况下`MessagePack`可能不比相应的 JSON 更小。它也可能比内置的`JSON.stringify`和`JSON.parse`方法运行得更慢。记住，一切都是一种权衡。

有很多无模式数据格式，每种格式都有自己的技巧，试图使编码/解码时间更快，使过程中的数据更小。然而，当我们处理企业系统时，我们很可能会看到使用基于模式的数据格式。

有几种定义模式的方法，但在我们的情况下，我们将使用 proto 文件格式。

1.  让我们继续创建一个**proto**文件，以模拟我们之前的`test.json`文件。模式可能看起来像以下内容：

```js
package exampleProtobuf;
syntax = "proto3";

message TestData {
    string item1 = 1;
    int32  item2 = 2;
    float  item3 = 3;
}
```

我们在这里声明的是，这条名为`TestData`的消息将存储在名为`exampleProtobuf`的包中。该包主要用于将类似的项目分组（这在诸如 Java 和 C#等语言中被广泛利用）。语法告诉我们的编码器和解码器，我们将使用的协议是`proto3`。协议还有其他版本，而这个版本是最新的稳定版本。

然后，我们声明一个名为`TestData`的新消息，其中包含三个条目。一个将被称为`item1`，类型为`string`，一个将是称为`item2`的整数，最后一个将是称为`item3`的浮点数。我们还为它们分配了 ID，因为这样可以更容易进行索引和自引用类型（也因为这对于`protobuf`来说是强制性的）。我们不会详细介绍这样做的具体作用，但请注意它可以帮助编码和解码过程。

1.  接下来，我们可以编写一些代码，可以使用它在我们的代码中创建一个`TestData`对象，可以专门处理这些消息。这将看起来像下面这样：

```js
protobuf.load('test.proto', function(err, root) {
    if( err ) throw err;
    const TestTypeProto = 
     root.lookupType("exampleProtobuf.TestData");
    if( TestTypeProto.verify(json) ) {
        throw Error("Invalid type!");
    }
    const message2 = TestTypeProto.create(json);
    const buf2 = TestTypeProto.encode(message2).finish();
    const final2 = TestTypeProto.decode(buf2);
    console.log(buf2.byteLength, 
     Buffer.from(JSON.stringify(final2)).byteLength);
    console.log(buf2, final2);
});
```

请注意，这与我们之前看到的大多数代码类似，除了一些验证和创建过程。首先，库需要读取我们拥有的原型文件，并确保它确实是正确的。接下来，我们根据我们给它的命名空间和名称创建对象。现在，我们验证我们的有效负载并从中创建消息。然后，我们通过特定于此数据类型的编码器运行它。最后，我们解码消息并测试以确保我们得到了与输入相同的数据。

从这个例子中应该注意到两件事。首先，数据大小非常小！这是基于模式/protobuf 的优势之一，超过了无模式数据格式。由于我们提前知道类型应该是什么，我们不需要将该信息编码到消息本身中。其次，我们将看到浮点数并没有返回为 3.3。这是由于精度错误，这是我们应该警惕的事情。

1.  现在，如果我们不想像这样读取原型文件，我们可以在代码中构建消息，就像下面这样：

```js
const TestType = new protobuf.Type("TestType");
TestType.add(new protobuf.Field("item1", 1, "string"));
TestType.add(new protobuf.Field("item2", 2, "int32"));
TestType.add(new protobuf.Field("item3", 3, "float"));
```

这应该类似于我们在原型文件中创建的消息，但我们将逐行查看以显示它与`protobuf`对象相同。在这种情况下，我们首先创建一个名为`TestType`的新类型（而不是`TestData`）。接下来，我们添加三个字段，每个字段都有自己的标签、索引号和存储在其中的数据类型。如果我们通过相同类型的验证、创建、编码、解码过程运行它，我们将得到与之前相同的结果。

虽然这并不是对不同数据格式的全面概述，但它应该有助于识别何时使用无模式（当我们不知道数据可能是什么样子时）以及何时使用模式（当在未知系统之间通信或我们需要减少有效负载大小时）。

# 总结

虽然我们大多数起始应用程序将使用 JSON 在不同服务器之间传递数据，甚至在我们应用程序的不同部分之间传递数据，但应该注意到我们可能不想使用它的地方。通过利用其他数据格式，我们可以确保尽可能地提高应用程序的速度。

我们已经看到了构建自己的数据格式可能涉及的内容，然后我们看了一下当前流行的其他格式。这应该是我们构建高性能 Node.js 服务器应用程序所需的最后一部分信息。虽然我们将使用一些数据格式的库，但我们也应该注意到，我们实际上只使用了 Node.js 自带的原始库。

接下来，我们将看一个实际的静态服务器示例，该服务器缓存信息。从这里开始，我们将利用之前的所有概念来创建一个高可用和高速的静态服务器。


# 第九章：实际示例 - 构建静态服务器

在过去的几章中，我们已经了解了 Node.js 及其提供的功能。虽然我们没有涵盖每个模块或 Node.js 提供的所有内容，但我们已经有了所有的要素来构建一个静态内容/生成器站点。这意味着我们将设置一个服务器来监听请求，并根据该请求构建页面。

为了实现这个服务器，我们需要了解站点生成的工作原理，以及如何将其作为即时操作实现。除此之外，我们还将研究缓存，以便我们不必在每次请求页面时重新编译。总的来说，在本章中，我们将查看并实现以下内容：

+   理解静态内容

+   设置我们的服务器

+   添加缓存和集群

# 技术要求

+   一个文本编辑器或**集成开发环境**（**IDE**），最好是 VS Code

+   支持 Node.js 的操作系统

+   本章的代码可以在以下网址找到：[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter09/microserve`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter09/microserve)。

# 理解静态内容

静态内容就是不变的内容。这可以是 HTML 页面、JavaScript、图像等。任何不需要通过数据库或某些外部系统进行处理的内容都可以被视为静态内容。

虽然我们不会直接实现静态内容服务器，但我们将实现一个即时静态内容生成器。对于不了解的人来说，静态内容生成器是一个构建静态内容然后提供该内容的系统。内容通常由某种模板系统构建。

一些常见的模板系统包括 Mustache、Handlebars.js 和 Jade。这些模板引擎寻找某种标记，并根据一些变量替换内容。虽然我们不会直接查看这些模板引擎，但要知道它们存在，并且它们对于诸如代码文档生成或甚至根据某些 API 规范创建 JavaScript 文件等方面非常有用。

我们将实现自己的模板系统版本，而不是使用其中一个常见格式，以了解模板的工作原理。我们将尽量保持简单，因为我们希望为我们的服务器使用最少的依赖项。我们将使用一个名为`Remarkable`的 Markdown 到 HTML 转换器作为依赖项：[`github.com/jonschlinkert/remarkable`](https://github.com/jonschlinkert/remarkable)。它依赖于两个库，每个库又依赖于一个库，因此我们将导入总共五个库。

虽然即时创建所有页面将使我们能够轻松进行更改，但除非我们处于开发环境中，否则我们不希望一直这样做。为了确保我们不一遍又一遍地构建 HTML 文件，我们将实现一个内存缓存来存储被请求最多的文件。

有了这些，让我们继续开始构建我们的应用程序，通过设置我们的服务器并发送响应。

# 启动我们的应用程序

首先，让我们通过在我们选择的文件夹中创建我们的`package.json`文件来设置我们的项目。我们可以从以下基本的`package.json`文件开始：

```js
{
    "version" : "0.0.1",
    "name"    : "microserver",
    "type"    : "module"
}
```

现在应该相当简单了。主要的是将类型设置为`module`，这样我们就可以在 Node.js 中使用模块。接下来，让我们继续通过在放置`package.json`文件的文件夹中运行`npm install remarkable`来添加`Remarkable`依赖项。有了这个，我们现在应该在我们的`package.json`文件中列出`remarkable`作为一个依赖项。接下来，让我们继续设置我们的服务器。为此，创建一个`main.js`文件并执行以下操作：

1.  导入`http2`和`fs`模块，因为我们将使用它们来启动我们的服务器和读取我们的私钥和证书文件，如下所示：

```js
import http2 from 'http2'
import fs from 'fs'
```

1.  创建我们的服务器并读取我们的密钥和证书文件。我们将在设置主文件后生成这些文件，就像这样：

```js
const server = http2.createSecureServer({
    key: fs.readFileSync('selfsignedkey.pem'),
    cert: fs.readFileSync('selfsignedcertificate.pem')
});
```

1.  通过崩溃我们的服务器来响应错误事件（我们可能应该更好地处理这个问题，但现在这样做就可以了）。我们还将通过简单的消息和状态码`200`（表示一切正常）来处理传入的请求，就像这样：

```js
server.on('error', (err) => {
    console.error(err);
    process.exit();
});
server.on('stream', (stream, headers) => {
    stream.respond({
       'content-type': 'text/html',
        ':status': 200
    });
    stream.end("A okay!");
});
```

1.  最后，我们将开始监听端口`50000`（这里可以使用一个随机端口号）。

现在，如果我们尝试运行这个，我们应该会被类似以下的一个令人讨厌的错误消息所打招呼：

```js
Error: ENOENT: no such file or directory, open 'selfsignedkey.pem'
```

我们还没有生成自签名的私钥和证书。请记住从第六章中了解到，我们不能在不安全的通道（HTTP）上提供任何内容；相反，我们必须使用 HTTPS。为此，我们需要从证书颁发机构获取证书，或者我们需要自己生成一个。从第六章中了解到，我们应该在我们的计算机上安装`openssl`应用程序。

1.  让我们继续通过运行以下命令来生成它，并只需通过命令提示符按*Enter*：

```js
> openssl req -newkey rsa:2048 -nodes -keyout selfsignedkey.pem -x509 -days 365 -out selfsignedcertificate.pem
```

现在我们应该在当前目录中有这两个文件，现在，如果我们尝试运行我们的应用程序，我们应该有一个在端口`50000`上监听的服务器。我们可以通过访问以下地址来检查：`127.0.0.1:50000`。如果一切正常，我们应该看到消息 A okay！

虽然像端口、私钥和证书这样的变量在开发过程中硬编码是可以的，但我们仍然应该将它们移到我们的`package.json`文件中，这样另一个用户可以在一个地方进行更改，而不是必须进入代码并进行更改。让我们继续进行这些更改。在我们的`package.json`文件中，让我们添加以下字段：

```js
"config" : {
    "port" : 50000,
    "key"  : "selfsignedkey.pem",
    "certificate" : "selfsignedcertificate.pem",
    "template" : "template",
    "body_files" : "publish"
},
"scripts" : {
   "start": "node --experimental-modules main.js"   
}
```

`config`部分将允许我们传递各种变量，让包的用户使用`package.json`的`config`部分设置，或者在运行我们的文件时使用`npm config set tinyserve:<variable>`命令设置。正如我们从第五章中看到的，`scripts`部分允许我们访问这些变量，并允许我们的包的用户现在只需使用`npm start`，而不是使用`node --experimental-modules main.js`。有了这个，我们可以通过在我们的`main.js`文件中声明所有这些变量来改变我们的`main.js`文件，就像这样：

```js
const ENV_VARS = process.env;
const port = ENV_VARS.npm_package_config_port || 80;
const key  = ENV_VARS.npm_package_config_key || 'key.pem';
const cert = ENV_VARS.npm_package_config_certificate || 'cert.pem';
const templateDirectory = ENV_VARS.npm_package_config_template || 'template';
const publishedDirectory = ENV_VARS.npm_package_config_bodyFiles || 'body';
```

所有配置变量都可以在我们的`process.env`变量中找到，因此我们在文件顶部声明了一个快捷方式。 然后，我们可以访问各种变量，就像我们在第五章中看到的那样，*切换上下文-没有 DOM，不同的 Vanilla*。 我们还设置了默认值，以防用户没有使用我们声明的`npm start`脚本运行我们的文件。 用户还会注意到我们声明了一些额外的变量。 这些是我们稍后会讨论的变量，但它们涉及到我们要超链接到的位置以及我们是否要启用缓存（开发变量）。 接下来，我们将看一下我们将如何访问我们想要设置的模板系统。

# 设置我们的模板系统

我们将使用 Markdown 来托管我们想要托管的各种内容，但我们将希望在所有文章中使用某些部分。 这些将是我们页面的页眉、页脚和侧边栏等内容。 我们可以将这些内容模板化，而不必将它们插入到我们为文章创建的所有 Markdown 文件中。

我们将把这些部分放在一个在运行时将被知道的文件夹中，通过我们声明的`templateDirectory`变量。 这也将允许我们包的用户更改我们的静态站点服务器的外观和感觉，而无需做任何太疯狂的事情。 让我们继续创建模板部分的目录结构。 这应该看起来像下面这样：

+   **模板**：我们应该在所有页面中查找静态内容

+   **HTML**：我们所有静态 HTML 代码将放在这里

+   **CSS**：我们的样式表将存放在这里

有了这个目录结构，我们现在可以创建一些基本的页眉、页脚和侧边栏 HTML 文件，以及一些基本的**层叠样式表**（**CSS**），以获得一个对每个人都应该熟悉的页面结构。 所以，让我们开始，如下所示：

1.  我们将编写`header` HTML，如下所示：

```js
<header>
    <h1>Our Website</h1>
    <nav>
        <a href="/all">All Articles</a>
        <a href="/contact">Contact Us</a>
        <a href="/about">About Us</a>
    </nav>
</header>
```

有了这个基本结构，我们有了网站的名称，然后是大多数博客网站都会有的一些链接。

1.  接下来，让我们创建`footer`部分，就像这样：

```js
<footer>
    <p>Created by: Me</p>
    <p>Contact: <a href="mailto:me@example.com">Me</a></p>
</footer>
```

1.  再次，相当容易理解。 最后，我们将创建侧边栏，如下所示：

```js
<nav>
    <% loop 5
    <a href="article/${location}">${name}</a>
    %>
</nav>
```

这就是我们的模板引擎发挥作用的地方。 首先，我们将使用`<% %>`字符模式来表示我们要用一些静态内容替换它。 接下来，`loop <number>`将让我们的模板引擎知道我们计划在停止引擎之前循环一定次数的下一个内容。 最后，`<a href="article/${location}">${name}</a>`模式将告诉我们的模板引擎这是我们要放入的内容，但我们将要用我们在代码中传递的对象中的变量替换`${}`标签。

接下来，让我们继续创建我们页面的基本 CSS，如下所示：

```js
*, html {
    margin : 0;
    padding : 0;
}
:root {
   --main-color : "#003A21"; 
   --text-color : "#efefef";
}
/* header styles */
header {
    background : var(--main-color);
    color      : var(--text-color);
}
/* Footer styles */
footer {
    background : var(--main-color);
    color  : var(--text-color);
}
```

由于大部分是样板代码，CSS 文件已经被剪切了。 值得一提的是自定义变量。 使用 CSS，我们可以通过使用模式`--<name> : <content>`声明自定义变量，然后我们可以在 CSS 文件中使用`var()`声明来使用它。 这使我们能够重用变量，如颜色和高度，而无需使用预处理器，如**SASS**。

CSS 变量是有作用域的。 这意味着如果您为`header`部分定义变量，它将仅在`header`部分中可用。 这就是为什么我们决定将我们的颜色放在`:root`伪元素级别，因为它将在整个页面中可用。 只需记住，CSS 变量的作用域类似于我们在 JavaScript 中声明的`let`和`const`变量。

有了我们的 CSS 布局，我们现在可以在我们的`template`文件中编写我们的主 HTML 文件。我们将把这个文件移到 HTML 文件夹之外，因为这是我们想要的主文件，以便把所有东西放在一起。这也会让我们的包的用户知道这是我们将用来组合所有部分的主文件，如果他们想要改变它，他们应该在这里做。现在，让我们创建一个看起来像下面这样的`main.html`文件：

```js
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet"  type="text/css" href="css/main.css" />
    </head>
    <body>
        <% from html header %>
        <% from html sidebar %>
        <% from html footer %>
    </body>
</html>
```

顶部部分应该看起来很熟悉，但是现在我们有了一个新的模板类型。`from`指令让我们知道我们将从其他地方获取这个文件。下一个语句表示它是一个`HTML`文件，所以我们将在`HTML`文件夹中查找。最后，我们看到文件的名称，所以我们知道我们要引入`header.html`文件。

有了所有这些，我们现在可以编写我们将用来构建页面的模板系统。我们将利用`Transform`流来实现我们的模板系统。虽然我们可以利用类似`Writable`流的东西，但是利用`Transform`流更有意义，因为我们根据一些输入条件改变输出。

要实现`Transform`流，我们需要跟踪一些东西，这样我们才能正确处理我们的键。首先，让我们读取并发送适当的块进行处理。我们可以通过实现`transform`方法并输出我们要替换的块来实现这一点。为此，我们将执行以下操作：

1.  我们将扩展一个`Transform`流并设置基本结构，就像我们在第七章中所做的那样，*流-理解流和非阻塞 I/O*。我们还将创建一个自定义类来保存缓冲区的开始和结束位置。这将允许我们知道我们是否在同一个循环中得到了模式匹配的开始。我们以后会需要这个。我们还将为我们的类设置一些私有变量，比如`begin`和`end`模板缓冲区，以及`#pattern`变量等状态变量，如下所示：

```js
import { Transform } from 'stream'
class Pair {
    start = -1
    end = -1
}
export default class TemplateBuilder extends Transform {
    #pattern = []
    #pair = new Pair()
    #beforePattern = Buffer.from("<%")
    #afterPattern = Buffer.from("%>")
    constructor(opts={}) {
        super(opts);
    }
    _transform(chunk, encoding, cb) {
        // process data
    }
}
```

1.  接下来，我们将不得不检查我们的`#pattern`状态变量中是否保存了数据。如果没有，那么我们知道要寻找模板的开始。一旦我们检查到模板语句的开始，我们可以检查它是否实际上在这个数据块中。如果是，我们将`#pair`的`start`属性设置为这个位置，这样我们的循环就可以继续进行；否则，我们在这个块中没有模板，我们可以开始处理下一个块，如下所示：

```js
// inside the _transform function
if(!this.#pattern.length && !this.#pair.start) {
    location = chunk.indexOf(this.#beforePattern, location);
    if( location !== -1 ) {
        this.#pair.start = location;
        location += 2;
    } else {
        return cb();
   }
}
```

1.  要处理另一个条件（我们正在寻找模板的结尾），我们需要处理更多的状态。首先，如果我们的`#pair`变量的`start`不是`-1`（我们设置它），我们知道我们仍在处理当前的块。这意味着我们需要检查我们是否可以在当前块中找到`end`模板缓冲区。如果我们找到了，那么我们可以处理模式并重置我们的`#pair`变量。否则，我们只是将当前块从`#pair`的`start`成员位置推送到我们的`#pattern`持有者的块末端，如下所示：

```js
if( this.#pair.start !== -1 ) {
    location = chunk.indexOf(this.#afterPattern, location);
    if( location !== -1 ) {
        this.#pair.end = location;
        this.push(processPattern(chunk.slice(this.#pair.start,this.#pair.end)));
        this.#pair = new Pair();
    } else {
        this.#pattern.push(chunk.slice(this.#pair.start));
    }
}
```

1.  最后，如果`#pair`的`start`成员被设置，我们检查`end`模板模式。如果我们找不到它，我们只是将整个块推送到`#pattern`数组。如果我们找到它，我们就从它的开头切割块，直到我们找到我们的`end`模板字符串。然后我们将所有这些连接在一起并进行处理。然后我们还将我们的`#pattern`变量重置为什么都不持有，就像这样：

```js
location = chunk.indexOf(this.#afterPattern, location);
if( location !== -1 ) {
    this.#pattern.push(chunk.slice(0, location));
    this.push(processPattern(Buffer.concat(this.#pattern)));
    this.#pattern = [];
} else {
    this.#pattern.push(chunk);
}
```

1.  所有这些都将包装在一个`do`/`while`循环中，因为我们至少要运行这段代码一次，当我们的`location`变量是`-1`时，我们就知道我们已经完成了（这是从`indexOf`检查返回的，当它找不到我们想要的时）。在`do`/`while`循环之后，我们运行回调，告诉我们的流我们已经准备好处理更多数据，如下所示：

```js
do {
  // transformation code
} while( location !== -1 );
cb();
```

将所有这些放在一起，我们现在有一个`transform`循环，应该处理几乎所有情况来获取我们的模板系统。我们可以通过将我们的`main.html`文件传递进去并将以下代码放入我们的`processPattern`方法中来测试这一点，就像这样：

```js
console.log(pattern.toString('utf8'));
```

1.  我们可以创建一个测试脚本来运行我们的`main.html`文件。继续创建一个`test.js`文件，并将以下代码放入其中：

```js
import TemplateStream from './template.js';
const file = fs.createReadStream('./template/main.html');
const tStream = new TemplateStream();
file.pipe(tStream);
```

有了这个，我们应该得到一个漂亮的输出，其中包含我们正在寻找的模板语法，比如`from html header`*.* 如果我们通过`sidebar.html`文件运行它，它应该看起来像下面这样：

```js
loop 5
    <a href="article"/${location}">${name}</a>
```

现在我们知道我们的`Transform`流的模板查找代码是有效的，我们只需要编写我们的处理块系统来处理我们之前的情况。

现在要处理这些块，我们需要知道在哪里查找文件。还记得之前我们在`package.json`文件中声明各种变量吗？现在，我们将利用`templateDirectory`。让我们将其作为流的参数传递进去，就像这样：

```js
#template = null
constructor(opts={}) {
    if( opts.templateDirectory ) {
        this.#template = opts.templateDirectory;
    }
    super(opts);
}
```

现在，当我们调用`processPattern`时，我们可以将块和`template`目录作为参数传递。从这里，我们现在可以实现`processPattern`方法。我们将处理两种情况：当我们找到一个`for`循环和当我们找到一个`find`语句。

要处理`for`循环和`find`语句，我们将按以下步骤进行：

1.  我们将构建一个缓冲区数组，除了`for`循环之外，它将是模板保存的内容。我们可以使用以下代码来实现这一点：

```js
const _process = pattern.toString('utf8').trim();
const LOOP = "loop";
const FIND = "from";
const breakdown = _process.split(' ');
switch(breakdown[0]) {
    case LOOP:
        const num = parseInt(breakdown[1]);
        const bufs = new Array(num);
        for(let i = 0; i < num; i++) {             
           bufs[i] = Buffer.from(breakdown.slice(2).join(''));
        }
        break;
   case FIND:
        console.log('we have a find loop', breakdown);
        break;
   default:
        return new Error("No keyword found for processing! " + 
         breakdown[0]);
}
```

1.  我们将查找循环指令，然后获取第二个参数，它应该是一个数字。如果我们打印出来，我们会看到我们有一堆填满相同数据的缓冲区。

1.  接下来，我们需要确保填写所有的模板字符串位置。这些看起来像`${<name>}`的模式。为此，我们将在这个循环中添加另一个参数，用于指定我们想要使用的变量的名称。让我们将其添加到`sidebar.html`文件中，如下所示：

```js
<% loop 5 articles
    <a href="article/${location}">${name}</a>
%>
```

1.  有了这个，我们现在应该传入一个我们想要在模板系统中使用的变量列表——在这种情况下，一个名为`articles`的数组，其中包含具有`location`和`name`键的对象。这可能看起来像下面这样：

```js
const tStream = new TemplateStream({
    templateDirectory,
    templateVariables : {
        sidebar : [
            {
                location : temp1,
                name     : 'article 1'
            }
        ]
    }
}
```

满足我们`for`循环条件的条件足够多，现在我们可以回到`Transform`流，并将其作为我们在构造函数中要处理的项目之一，并将其发送到我们的`processPattern`方法。一旦我们在这里添加了这些项目，我们将在`for`循环内更新我们的循环情况，使用以下代码：

```js
const num = parseInt(breakdown[1]);
const bufs = new Array(num);
const varName = breakdown[2].trim();
for(let i = 0; i < num; i++) {
    let temp = breakdown.slice(3).join(' ');
    const replace = /\${([0-9a-zA-Z]+)}/
    let results = replace.exec(temp);           
    while( results ) {
        if( vars[varName][i][results[1]] ) {
            temp = temp.replace(results[0], vars[varName][i][results[1]]);
        }
       results = replace.exec(temp);                
    }
    bufs[i] = Buffer.from(temp);
}
return Buffer.concat(bufs);
```

我们的临时字符串包含我们认为是模板的所有数据，而`varName`变量告诉我们在我们传递给`processPattern`的对象中查找的位置以执行我们的替换策略。接下来，我们将使用正则表达式提取变量的名称。这个特定的正则表达式表示查找`${<name>}`模式，同时也表示捕获`<name>`部分的内容。这样我们就可以轻松地获取变量的名称。我们还将继续循环遍历模板，看看是否有更多的正则表达式符合这些条件。最后，我们将用我们存储的变量替换模板代码。

完成所有这些后，我们将所有这些缓冲区连接在一起并返回它们。这对于那段代码来说是很多的；幸运的是，我们的模板的`from`部分要容易处理得多。我们的模板代码的`from`部分只需从我们的`templateDirectory`变量中查找具有该名称的文件，并将其返回为缓冲形式。

它应该看起来像下面这样：

```js
case FIND: {
    const type = breakdown[1];
    const HTML = 'html';
    const CSS  = 'css';
    if(!(type === HTML || type === CSS)) return new Error("This is not a
     valid template type! " + breakdown[1]);
    return fs.readFileSync(path.join(templateDirectory, type, `${breakdown[2]}.${type}`));
}
```

首先，我们从第二个参数中获取文件类型。如果不是`HTML`或`CSS`文件，我们将拒绝它。否则，我们将尝试读取文件并将其发送到我们的流中。

你们中的一些人可能会想知道我们将如何处理其他文件中的模板。现在，如果我们在`main.html`文件上运行我们的系统，我们将得到所有单独的块，但我们的`sidebar.html`文件没有填充。这是我们模板系统的一个弱点。解决这个问题的一种方法是创建另一个函数，它将调用我们的`Transform`流一定次数。这将确保我们为这些单独的部分完成模板。让我们现在就创建这个函数。

这不是处理这个问题的唯一方法。相反，我们可以利用另一个系统：当我们在文件中看到模板指令时，我们将该缓冲区添加到需要处理的项目列表中。这将允许我们的流处理指令，而不是一遍又一遍地循环缓冲区。这会导致它自己的问题，因为有人可能会编写一个无限递归的模板，这将导致我们的流中断。一切都是一种权衡，现在，我们选择编码的简易性而不是使用的简易性。

首先，我们需要从`events`模块中导入`once`函数和从`stream`模块中导入`PassThrough`流。让我们现在更新这些依赖关系，就像这样：

```js
import { Transform, PassThrough } from 'stream'
import { once } from 'events'
```

接下来，我们将创建一个新的`Transform`流，它将带入与以前相同的信息，但现在，我们还将添加一个循环计数器。我们还将响应`transform`事件，并将其推送到一个私有变量，直到我们读取完整的起始模板为止，如下所示：

```js
export class LoopingStream extends Transform {
    #numberOfRolls = 1
    #data = []
    #dir = null
    #vars = null
    constructor(opts={}) {
        super(opts);
        if( 'loopAmount' in opts ) {
            this.#numberOfRolls = opts.loopAmount
        }
        if( opts.vars ) {
            this.#vars = opts.vars;
        }
        if( opts.dir) {
            this.#dir = opts.dir;
        }
    }
    _transform(chunk, encoding, cb) {
        this.#data.push(chunk);
        cb();
    }
    _flush(cb) {
    }
}
```

接下来，我们将使我们的`flush`事件`async`，因为我们将利用一个异步`for`循环，就像这样：

```js
async _flush(cb) {
    let tData = Buffer.concat(this.#data);
    let tempBuf = [];
    for(let i = 0; i < this.#numberOfRolls; i++) {
        const passThrough = new PassThrough();
        const templateBuilder = new TemplateBuilder({ templateDirectory :
        this.#dir, templateVariables : this.#vars });
        passThrough.pipe(templateBuilder);
        templateBuilder.on('data', (data) => {
            tempBuf.push(data);
        });
        passThrough.end(tData);
        await once(templateBuilder, 'end');
        tData = Buffer.concat(tempBuf);
        tempBuf = [];
    }
    this.push(tData);
    cb();
}
```

基本上，我们将把所有的初始模板数据放在一起。然后，我们将通过我们的`TemplateBuilder`运行这些数据，构建一个新的模板来运行。我们利用`await once(templateBuilder, ‘end')`系统让我们以同步的方式处理这段代码。一旦我们完成了计数，我们将输出数据。

我们可以使用旧的测试工具来测试这一点。让我们继续设置它来利用我们的新的`Transform`流，并将数据输出到文件，如下所示：

```js
const file = fs.createReadStream('./template/main.html');
const testOut = fs.createWriteStream('test.html');
const tStream = new LoopingStream({
    dir : templateDirectory,
    vars : { //removed for simplicity sake },
    loopAmount : 2
});
file.pipe(tStream).pipe(testOut);
```

如果我们现在运行这个，我们会注意到`test.html`文件包含了我们完全构建的`template`文件！我们现在有一个可以使用的模板系统。让我们把它连接到我们的服务器上。

# 设置我们的服务器

有了我们的模板系统工作，让我们继续把所有这些连接到我们的服务器上。现在不再简单地回复“一切正常！”，而是用我们的模板回复。我们可以通过运行以下代码轻松实现这一点：

```js
stream.respond({
        'content-type': 'text/html',
        ':status': 200
    });
    const file = fs.createReadStream('./template/main.html');
    const tStream = new LoopingStream({
        dir: templateDirectory,
        vars : { //removed for readability }
},
        loopAmount : 2
    })
    file.pipe(tStream).pipe(stream);
});
```

这应该几乎和我们的测试工具一模一样。如果我们现在转到`https://localhost:50000`，我们应该会看到一个非常基本的 HTML 页面，但我们已经创建了我们的模板文件！如果我们现在进入开发工具并查看源代码，我们会看到一些奇怪的东西。CSS 表明我们加载了我们的`main.css`文件，但文件的内容看起来和我们的 HTML 文件完全一样！

我们的服务器对每个请求都以我们的 HTML 文件进行响应！我们需要做的是一些额外的工作，让我们的服务器能够正确地响应请求。我们将通过将请求的 URL 映射到我们拥有的文件来实现这一点。为了简单起见，我们只会响应 HTML 和 CSS 请求（我们不会发送任何 JavaScript），但是这个系统可以很容易地添加返回类型的图片，甚至文件。我们将通过以下方式添加所有这些：

1.  我们将为我们的文件结尾设置一个查找表，就像这样：

```js
const FILE_TYPES = new Map([
    ['.css', path.join('.', templateDirectory, 'css')],
    ['.html', path.join('.', templateDirectory, 'html')]
]);
```

1.  接下来，我们将使用这个映射根据请求的`headers`来拉取文件，就像这样：

```js
const p = headers[':path'];
for(const [fileType, loc] of FILE_TYPES) {
    if( p.endsWith(fileType) ) {
        stream.respondWithFile(
            path.join(loc, path.posix.basename(p)),
            {
                'content-type': `text/${fileType.slice(1)}`,
                ':status': 200
            }
        );
        return;
    }     
}
```

基本思想是循环遍历我们支持的文件类型，看看我们是否有这些文件。如果有，我们将用文件进行响应，并通过`content-type`头告诉浏览器它是 HTML 文件还是 CSS 文件。

1.  现在，我们需要一种方法来判断请求是否良好。目前，我们可以转到任何 URL，我们将一遍又一遍地得到相同的响应。我们将利用`publishedDirectory`环境变量来实现这一点。根据其中的文件名，这些将是我们的端点。对于每个子 URL 模式，我们将寻找遵循相同模式的子目录。如下所示：

```js
https:localhost:50000/articles/1 maps to <publishedDirectory>/articles/1.md
```

`.md`扩展名表示它是一个 Markdown 文件。这就是我们将编写页面的方式。

1.  现在，让我们让这个映射工作。为此，我们将在我们的`for`循环下面放入以下代码：

```js
try {
    const f = fs.statSync(path.join('.', publishedDirectory, p));
    stream.respond({
        'content-type': 'text/html',
        ':status': 200
    });
    const file = fs.createReadStream('./template/main.html');
    const tStream = new LoopingStream({
        dir: templateDirectory,
        vars : { },
        loopAmount : 2
    })
    file.pipe(tStream).pipe(stream);
} catch(e) {
    stream.respond({
        'content-type': 'text/html',
        ':status' : 404
    });
    stream.end('File Not Found! Turn Back!');
    console.warn('following file requested and not found! ', p);
}
```

我们将用`try`/`catch`块包装我们查找文件的方法(`fs.statSync`)。如果出现错误，这通常意味着我们没有找到文件，我们将向用户发送一个`404`消息。否则，我们将发送我们一直发送的内容：我们的示例`template`。如果我们现在运行服务器，我们将收到以下消息：文件未找到！回头吧！我们在那个目录中什么都没有！

让我们继续创建目录，并添加一个名为`first.md`的文件。如果我们添加这个目录和文件并重新运行服务器，如果我们转到`https://localhost:50000/first`，我们仍然会收到错误消息！我们之所以会收到这个消息，是因为在检查文件时我们没有添加 Markdown 文件扩展名！让我们继续将其添加到`fs.statSync`检查中，如下所示：

```js
const f = fs.statSync(path.join('.', publishedDirectory, `${p}.md`));
```

现在，当我们重新运行服务器时，我们将看到以前的正常模板。如果我们向`first.md`文件添加内容，我们将得不到该文件。现在我们需要将此添加到我们的模板系统中。

还记得在本章开头我们添加了`npm`包`remarkable`吗？现在我们将添加 Markdown 渲染器`remarkable`，以及我们的模板语言将寻找的新关键字，以渲染 Markdown，如下所示：

1.  让我们将`Remarkable`作为一个导入添加到我们的`template.js`文件中，就像这样：

```js
import Remarkable from 'remarkable'
```

1.  我们将寻找以下指令来将 Markdown 文件包含到`<% file <filename> %>`模板中，就像这样：

```js
const processPattern = function(pattern, templateDir, publishDir, vars=null) {
    const process = pattern.toString('utf8').trim();
    const LOOP = "loop";
    const FIND = "from";
    const FILE = "file";
    const breakdown = process.split(' ');
    switch(breakdown[0]) {
      // previous case statements removed for readability
        case FILE: {
            const file = breakdown[1];
            return fs.readFileSync(path.join(publishDir, file));
        }
        default:
            return new Error("Process directory not found! " +  
             breakdown[0]);
    }
}
```

1.  现在，我们需要在构造函数中的`Transform`流的可能选项中添加`publishDir`变量，如下所示：

```js
export default class TemplateBuilder extends Transform {
    #pattern = []
    #publish = null
    constructor(opts={}) {
        super(opts);
        if( opts.publishDirectory ) {
            this.#publish = opts.publishDirectory;
        }
    }
    _transform(chunk, encoding, cb) {
        let location = 0;
        do {
            if(!this.#pattern.length && this.#pair.start === -1 ) {
                // code from before
            } else {
                if( this.#pair.start !== -1 ) {
                        this.push(processPattern(chunk.slice(this.#pair.start,
this.#pair.end), this.#template, this.#publish, this.#vars)); //add publish to our processPattern function
                } 
            } 
        } while( location !== -1 );
    }
}
```

**记住**：为了使其更易于阅读，这些示例中删除了大量代码。要获取完整的示例，请转到本书的代码存储库。

1.  创建一个`LoopingStream`类，它将循环并运行`TemplateBuilder`：

```js
export class LoopingStream extends Transform {
    #publish = null
    constructor(opts={}) {
        super(opts);
        if( opts.publish ) {
            this.#publish = opts.publish;
        }
    }
    async _flush(cb) {
        for(let i = 0; i < this.#numberOfRolls; i++) {
            const passThrough = new PassThrough();
            const templateBuilder = new TemplateBuilder({
                templateDirectory : this.#dir,
                templateVariables : this.#vars,
                publishDirectory  :this.#publish
            });
        }
        cb();
    }
}
```

1.  我们需要使用以下模板化行更新我们的模板：

```js
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet"  type="text/css" href="css/main.css" />
    </head>
    <body>
        <% from html header %>
        <% from html sidebar %>
        <% file first.md %>
        <% from html footer %>
    </body>
</html>
```

1.  最后，我们需要将`publish`目录传递给服务器的流。我们可以通过以下代码进行此操作：

```js
const tStream = new LoopingStream({
        dir: templateDirectory,
        publish: publishedDirectory,
        vars : {
}});
```

有了所有这些，我们应该从服务器那里得到一些不仅仅是我们的基本模板。如果我们向文件中添加了一些 Markdown，我们应该只看到带有我们模板的 Markdown。现在我们需要确保这个 Markdown 被处理。让我们回到我们的转换方法，并调用`Remarkable`方法，以便它处理 Markdown 并以 HTML 的形式返回给我们，如下面的代码块所示：

```js
const MarkdownRenderer = new Remarkable.Remarkable();
const processPattern = function(…) {
      switch(breakdown[0]) {
            case FILE: {
                  const file = breakdown[1];
                  const html =
MarkdownRenderer.render(fs.readfileSync(path.join(publishDir, file)
).toString('utf8'));
            return Buffer.from(html);
            }
      }
}
```

通过这个改变，我们现在有了一个通用的 Markdown 解析器，它使我们能够获取我们的模板文件，并将它们与我们的`main.html`文件一起发送。为了使模板系统和静态服务器正常运行，我们需要做的最后一个改变是，确保`main.html`文件不再具有精确的模板，而是具有我们想要的指令状态，以便在那里放置一个文件，并且我们的模板系统将放置在我们流构造函数中声明的文件。我们可以通过以下更改轻松实现这一点：

1.  在我们的`template.js`文件中，我们将利用一个名为`fileToProcess`的独特变量。我们以与我们通过传递的`vars`获取`sidebar.html`文件要处理的变量相同的方式获取它。如果我们没有来自`fileToProcess`变量的文件，我们将利用我们在`template`指令的第二部分中拥有的文件，如下面的代码块所示：

```js
case FILE: {
    const file = breakdown[1];
    const html =
    MarkdownRenderer.render(fs.readFileSync(path.join(publishDir,  
    vars.fileToProcess || file)).toString('utf8'));
    return Buffer.from(html);
}
```

1.  我们需要将这个变量从我们的服务器传递到流中，就像这样：

```js
const p = headers[':path'];
const tStream = new LoopingStream({
    dir: templateDirectory,
    publish: publishedDirectory,
    vars : {
        articles : [ ],
        fileToProcess : `${p}.md`
    },
    loopAmount : 2
});
```

1.  我们将进行的最后一个改变是改变`html`文件，为我们没有的页面创建一个新的基本 Markdown 文件。这可以让我们为根 URL 创建一个基本页面。我们不会实现这一点，但这是我们可以这样做的一种方式：

```js
<body>
    <% from html header %>
    <% from html sidebar %>
    <% file base.md %>
    <% from html footer %>
</body>
```

有了这个改变，如果我们现在运行我们的服务器，我们就有了一个完全功能的模板系统，支持 Markdown！这是一个了不起的成就！然而，我们需要向我们的服务器添加两个功能，以便它能够处理更多的请求并快速处理相同的请求。这些功能是缓存和集群。

# 添加缓存和集群

首先，我们将通过向我们的服务器添加缓存来开始。我们不希望不断重新编译我们以前已经编译过的页面。为此，我们将实现一个围绕地图的类。这个类将同时跟踪 10 个文件。我们还将实现文件上次使用的时间戳。当我们达到第十一个文件时，我们将看到它不在缓存中，并且我们已经达到了我们可以在缓存中保存的文件的最大数量。我们将用时间戳最早的文件替换编译后的页面。

这被称为**最近最少使用**（**LRU**）缓存。还有许多其他类型的缓存策略，比如**生存时间**（**TTL**）缓存。这种缓存类型将消除在缓存中时间过长的文件。这是一种很好的缓存类型，当我们一遍又一遍地使用相同的文件，但当服务器有一段时间没有被访问时，我们最终希望释放空间。LRU 缓存将始终保留这些文件，即使服务器已经有好几个小时没有被访问。我们可以实现两种缓存策略，但现在我们只实现 LRU 缓存。

首先，我们将创建一个名为`cache.js`的新文件。在这里，我们将执行以下操作：

1.  创建一个新的类。我们不需要扩展任何其他类，因为我们只是在 JavaScript 内置的`Map`数据结构周围编写一个包装器，如下面的代码块所示：

```js
export default class LRUCache {
    #cache = new Map()
}
```

1.  然后我们将有一个构造函数，它将接受我们想要在缓存中存储的文件数量，然后使用我们的策略来替换其中一个文件，就像这样：

```js
#numEntries = 10
constructor(num=10) {
    this.#numEntries = num
}
```

1.  接下来，我们将向我们的缓存添加`add`操作。它将接受我们页面的缓冲形式和我们用来获取它的 URL。键将是 URL，值将是我们页面的缓冲形式，如下面的代码块所示：

```js
add(file, url) {
    const val = {
        page : file,
        time : Date.now()
    }
    if( this.#cache.size === this.#numEntries ) {
        // do something
        return;
    }
    this.#cache.set(url, val);
}
```

1.  然后，我们将实现`get`操作，通过它我们尝试根据 URL 获取文件。如果我们没有它，我们将返回`null`。如果我们检索到一个文件，我们将更新时间，因为这将被视为最新的页面抓取。如下所示：

```js
get(url) {
    const val = this.#cache.get(url);
    if( val ) {
        val.time = Date.now();
        this.#cache.set(url, val);
        return val.page;
    }
    return null;
}
```

1.  现在，我们可以更新我们的`add`方法的`if`语句。如果我们达到了限制，我们将遍历我们的地图，看看最短的时间是什么。我们将删除那个文件，并用新创建的文件替换它，就像这样：

```js
if( this.#cache.size === this.#numEntries ) {
    let top = Number.MAX_VALUE;
    let earliest = null;
    for(const [key, val] of this.#cache) {
        if( val.time < top ) {
            top = val.time;
            earliest = key;
        }
    }
    this.#cache.delete(earliest);
}
```

现在我们已经为我们的文件建立了一个基本的 LRU 缓存。要将其附加到我们的服务器上，我们需要将其放在我们的管道中间：

1.  让我们回到主文件并导入这个文件：

```js
import cache from './cache.js'
const serverCache = new cache();
```

1.  现在我们将稍微改变我们的流处理程序中的逻辑。如果我们注意到 URL 是我们在缓存中有的东西，我们将只是获取数据并将其传送到我们的响应中。否则，我们将编译模板，将其设置在我们的缓存中，并将编译后的版本传送下来，就像这样：

```js
const cacheHit = serverCache.get(p);
if( cacheHit ) {
    stream.end(cacheHit);
} else {
    const file = fs.createReadStream('./template/main.html');
    const tStream = new LoopingStream({
        dir: templateDirectory,
        publish: publishedDirectory,
        vars : { /* shortened for readability */ },
        loopAmount : 2
    });
    file.pipe(tStream);
    tStream.once('data', (data) => {
        serverCache.add(data, p);
        stream.end(data);
    });
}
```

如果我们尝试运行上述代码，我们现在将看到如果我们两次访问相同的页面，我们将从缓存中获取文件；如果我们第一次访问它，它将通过我们的模板流进行编译，然后将其设置在缓存中。

1.  为了确保我们的替换策略有效，让我们将缓存的大小设置为只有`1`，看看如果我们访问一个新的 URL，我们是否不断替换文件，如下所示：

```js
const serverCache = new cache(1);
```

如果我们现在在每个方法被调用时记录我们的缓存，我们将看到当我们访问新页面时，我们正在替换文件，但如果我们停留在同一个页面，我们只是发送缓存的文件回去。

现在我们已经添加了缓存，让我们在服务器上再添加一个部分，这样我们就可以处理大量的连接。我们将添加`cluster`模块，就像我们在第六章中所做的那样，*消息传递-了解不同类型*。我们将按照以下步骤进行：

1.  让我们在`main.js`文件中导入`cluster`模块：

```js
import cluster from 'cluster'
```

1.  现在我们将在主进程中初始化服务器。对于其他进程，我们将处理请求。

1.  现在，让我们改变策略，处理子进程内部的传入请求，就像这样：

```js
if( cluster.isMaster ) {
    const numCpus = os.cpus().length;
    for(let i = 0; i < numCpus; i++) {
        cluster.fork();
    }
    cluster.on('exit', (worker, code, signal) => {
        console.log(`worker ${worker.process.pid} died`);
    });
} else {
    const serverCache = new cache();
    // all previous server logic
}
```

通过这个单一的改变，我们现在可以在四个不同的进程之间处理请求。就像我们在第六章中学到的那样，*消息传递-了解不同类型*，我们可以为`cluster`模块共享一个端口。

# 总结

虽然还有一个部分需要添加（将我们的侧边栏连接到实际文件），但这应该是一个非常通用的模板服务器。需要做的就是修改我们的`FILE`模板，并将其连接到我们模板系统的侧边栏。通过我们对 Node.js 的学习，我们应该能够处理几乎任何类型的服务器端应用程序。我们还应该能够理解像 Express 这样的 Web 服务器是如何从这些基本构建块中创建的。

从这里，我们将回到浏览器，并将书中这部分学到的一些概念应用到接下来的几章中。我们将首先看一下浏览器中的工作线程，即专用工作线程。然后我们将看一下共享工作线程，以及我们如何从这些工作线程中获益，但仍然能够从中获取数据。最后，我们将看一下服务工作者，并看看它们如何帮助我们进行各种优化，比如在浏览器中进行缓存。
