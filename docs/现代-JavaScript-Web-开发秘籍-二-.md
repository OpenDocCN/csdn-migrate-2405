# 现代 JavaScript Web 开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6`](https://zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 Node 进行开发

本章中我们将看到的示例有：

+   检查 Node 的设置

+   使用模块

+   直接使用 Flow 与 Node

+   使用 Flow 与 Node 通过预处理

+   使用 Nodemon 运行您的 Node 代码

+   使用承诺代替错误回调

+   使用流处理请求

+   使用流压缩文件

+   使用数据库

+   使用 exec()执行外部进程

+   使用 spawn()运行命令，并与其通信

+   使用 fork()来运行 Node 命令

# 介绍

我们在第一章的*安装 Node 和 npm*部分安装了`Node`，但那只是为了设置`npm`。`Node`不仅可以用作 Web 服务器，这是最常见的用法，还可以用来编写 shell 命令行或者桌面应用程序，正如我们将在第十三章中看到的那样，*使用 Electron 创建桌面应用程序*。然而，所有这些环境都有一些共同的配置和开发实践，这将是本章的目标。在本章中，我们将开始`Node`的开发。

# 检查 Node 的设置

首先，让我们通过创建一个非常基本的服务器来验证`Node`是否正常工作；我们将在下一章第四章中详细介绍*使用 Node 实现 RESTful 服务*，但现在我们只是想确保一切正常。在其他章节中，我们将更认真地使用`Node`，但这里的目标是验证它是否正常工作。

# 如何做…

稍微超前一点，让我们设置一个非常基本的服务器，通过发送`'Server alive!'`字符串来回答所有请求。为此，我们需要遵循三个步骤：

1.  使用`require()`导入`Node`的`http`模块——我们将在下一节中更多地了解模块；暂时假设`require()`等同于`import`。

1.  然后，使用`createServer()`方法来设置我们的服务器。

1.  之后，提供一个函数，通过发送`text/plain`固定的答案来回答所有请求。

以下代码代表了最基本的服务器，将让我们知道一切是否都正常工作。我将文件命名为`miniserver.js`。粗体字的那一行完成了所有的工作，我们将在下一节中详细讨论：

```js
// Source file: src/miniserver.js

/* @flow */
"use strict";

const http = require("http");

http
 .createServer((req, res) => {
 res.writeHead(200, { "Content-Type": "text/plain" });
 res.end("Server alive!");
 })
 .listen(8080, "localhost");

console.log("Mini server ready at http://localhost:8080/");
```

# 工作原理…

我们写了一个服务器；现在，让我们看看它是如何运行的。通过这个非常简单的项目，我们可以直接运行服务器代码。在本章的后面部分，我们将看到使用 Flow 类型将需要一些额外的预处理；然而，我们现在可以跳过这部分。我们可以使用以下命令行启动我们的服务器：

```js
> node src/miniserver.js
Mini server ready at http://localhost:8080/
```

要验证一切是否正常工作，只需打开浏览器，转到`http://localhost:8080`。以下截图显示了（诚然不是很令人印象深刻的）结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/e2fc0537-00c7-4548-a154-47bd8504509c.png)

我们的极简服务器正在运行，表明我们的 Node 正常工作

既然我们知道一切都正常，让我们开始一些基本技术，这些技术将在书中的其他地方使用。

为什么我们将服务器运行在端口`8080`而不是`80`？要访问低于`1024`的端口，您需要管理员（root）权限。然而，这将使您的服务器非常不安全；如果黑客设法进入服务器，他将在您的机器上拥有最高权限！因此，标准做法是以普通权限在端口`1024`以上（例如`8080`）运行`Node`，并设置反向代理以将流量发送到端口`80`（HTTP）或`443`（HTTPS）。

# 使用模块

在第二章的*在模块中组织代码*部分，我们看到了现代 JS 如何使用模块。然而，对于`Node`，我们有一点挫折：它不是用现代 JS 的方式处理模块的——除非您愿意使用实验性功能！

为什么`Node`不能使用现代的 JS 模块？原因可以追溯到新模块出现之前的几年，那时还不存在`import`和`export`语句，`Node`实现了 CommonJS 模块格式。（我们将在下一节中更多地了解这些模块。）显然，为了与`Node`一起使用的库也是使用了那种格式开发的，现在有无数个遵循这些指南的模块。

然而，自从新的模块标准出现以来，开始施加压力使用新的语法——但这带来了一些问题，不仅仅是调整语言；你可以让*两种*截然不同的模块风格共存吗？（因为，没有人能够神奇地将所有使用 CommonJS 的现有代码转换成新的格式，对吧？）还有一些其他的区别。ES 模块是用于异步方式使用的，而 CommonJS 模块是同步的；在大多数情况下，这并不会造成差异，但也有一些必须考虑的情况。

目前得出的解决方案还不能被认为是最终的。目前（自 8.5 版本以来），你可以通过使用`--experimental-modules`命令行标志来启用 ES 模块。如果你用它来调用 node，它将识别 ES 模块，如果它们的扩展名是`.mjs`而不是普通的`.js`。希望到 10 版本时，这将不再需要，但这并不能保证，而且到那时也有一定的风险，一些细节可能会发生变化！

这个解决方案使用了新的`.mjs`文件扩展名来识别新式模块，因为这个缘故它被戏称为**迈克尔·杰克逊解决方案**，因为这三个单词的首字母。

所以，如果我在一两年后写这本书，我可能会告诉你，只需继续，开始使用`.mjs`文件扩展名，并使用新的模块风格。

有关此功能的当前信息，请参阅[`nodejs.org/api/esm.html`](https://nodejs.org/api/esm.html)。

然而，此时，这并不被认为是一个完全安全的步骤——这个功能在这个时间点上显然被标记为*实验性*——所以让我们继续使用当前（旧的）标准，并学习如何使用老式模块。让我们创建一个数学模块，你可能想用它来进行金融编码，这样我们就可以看到一个从头开始构建的`Node`风格模块。

# 如何做...

对于`Node`模块，导出和导入元素的方式有两个重要的变化。任何文件都可以是一个模块，就像 ES 模块一样。简而言之，为了从一个模块中导入东西，你将不得不使用一个`require()`函数，而模块本身将使用一个`exports`对象来指定它将导出什么。

JS 数学运算符（加法、减法等）不会进行四舍五入，所以让我们编写一个`roundmath.js`模块，它将执行算术运算，但是将结果四舍五入到分，用于想象中的与业务相关的应用程序。首先，我们从启用`Flow`和设置严格模式的两行常见代码开始：

```js
// Source file: src/roundmath.js

/* @flow */
"use strict";

// *continues...*
```

不要忘记在所有模块的代码之前添加`"use strict"`行，就像我们在上一章的*在严格模式下工作*部分中提到的那样。JS 模块在定义上是严格的，但这并不适用于`Node`模块，它们*不*是严格的。

然后，让我们定义我们的函数。为了多样化，我们将有一些内部（不导出）函数，以及一些将被导出的函数：

```js
// ...*continued*

// These won't be exported:

const roundToCents = (x: number): number => Math.round(x * 100) / 100;
const changeSign = (x: number): number => -x;

// The following will be exported:

const addR = (x: number, y: number): number => roundToCents(x + y);

const subR = (x: number, y: number): number => addR(x, changeSign(y));

const multR = (x: number, y: number): number => roundToCents(x * y);

const divR = (x: number, y: number): number => {
    if (y === 0) {
        throw new Error("Divisor must be nonzero");
    } else {
        return roundToCents(x / y);
    }
};

// *continues*...
```

最后，按照通常的惯例，所有的输出将在底部放在一起，这样就很容易看到模块导出的所有内容。与现代的`export`语句不同，你可以将想要导出的内容赋值给一个`exports`对象。如果你想要保持变量或函数私有，你只需要跳过赋值；在我们的例子中，我们只导出了我们编写的六个函数中的四个。

```js
// ...*continued* exports.addR = addR;
exports.subR = subR;
exports.multR = multR;
exports.divR = divR;
```

# 它是如何工作的...

我们如何使用这个模块，它是如何工作的？如果我们想要从其他模块导入一些函数，我们会写如下内容；看看我们如何使用我们设计的一些操作：

```js
// Source file: src/doroundmath.js

/* @flow */
"use strict";

const RM = require("./roundmath.js");

console.log(RM.addR(12.348, 4.221)); // 16.57
console.log(RM.changeSign(0.07)); // error; RM.changeSign is not a function
```

前两行是通常的。然后，我们`require()`我们需要的任何模块；在这种情况下，只有一个。此外，按照惯例，所有这些要求都被分组在一起，从头开始，以便更容易理解模块的需求，而不必浏览整个代码。在我们的例子中，`RM`被分配了`exports`对象，所以你可以引用`RM.addR()`，`RM.subR()`等等，这清楚地告诉读者你正在使用`RM`模块的东西。

如果你想写得更少一些，你可以利用*解构语句*（我们在上一章的*解构数组和对象*部分遇到过）直接将所需的方法分配给单独的变量：

```js
/* @flow */
"use strict";

const { multR, divR } = require("./roundmath.js");

console.log(multR(22.9, 12.4)); // 283.96
console.log(divR(22, 7)); // 3.14
```

最好习惯于只导入你需要的模块。在其他情况下（我们将在后面的章节中看到），我们可以使用工具来删除你实际上没有使用的任何模块，如果你`require()`所有东西，那是不可能的。

# 直接使用 Flow 与 Node

由于我们使用`Flow`，而`Node`实际上并不知道数据类型，如果我们尝试执行我们的数据类型代码，显然会出现问题。对此有两种解决方案：一种不太优雅，但可以加快开发速度，另一种更强大，但需要额外的工作。让我们在这里考虑第一种更简单的解决方案，把第二种留给下一节。

# 如何做到这一点...

碰巧`Flow`提供了两种指定类型的方式：到目前为止我们一直在使用的方式，带有额外的类型标记，以及另一种更冗长的方式，通过注释。当然，JS 并不了解类型定义，所以第一种风格不会起作用，除非我们做额外的工作（正如我们将看到的），但使用注释是完全安全的。

要用注释定义类型，所有`Flow`特定的定义都必须用以`/*:`开头的注释括起来，以通常的`*/`结束，对于简单的基本类型，或者用`/*::`和`*/`来定义其他类型。我们可以回顾一些我们在第二章中看到的例子。简单的情况如下：

```js
// Source file: src/flowcomments.js

let someFlag /*: boolean */;
let greatTotal /*: number */;
let firstName /*: string */;

function toString(x /*: number */) /*: string */ {
    return String(x);
}

let traffic /*: "red" | "amber" | "green" */;

// *continues...*
```

更复杂的定义，包括可选参数、类型和不透明类型、类属性等等，需要更长的注释：

```js
// ...*continued* /*::
type pair<T> = [T, T];
type pairOfNumbers = pair<number>;
type pairOfStrings = pair<string>;

type simpleFlag = number | boolean;

type complexObject = {
    id: string,
    name: string,
    indicator: simpleFlag,
    listOfValues: Array<number>
};
*/

class Person {
 /*::
 first: string;
 last: string;
 */

    constructor(first /*: string */, last /*: string */) {
        this.first = first;
        this.last = last;
    }

    // ...several methods, snipped out
}

// *continues...*
```

你也可以导出和导入数据类型：

```js
// *...continued* /*::
import type { dniType, nameType } from "./opaque_types";
*/

/*::
export type { pairOfNumbers, pairOfStrings };
*/
```

# 它是如何工作的...

为什么以及这是如何工作的？`Flow`能够识别`/*::  ...  */`和`*/**:  ...  */`注释，因此可以很好地完成它的工作。由于`Flow`代码都隐藏在注释中，从 JS 引擎的角度来看，`Flow`部分甚至不存在，因此这种工作方式的明显优势是你可以直接执行你的代码。

为什么你不喜欢这个？显而易见的批评是，代码看起来，委婉地说，很丑陋。如果你习惯于，比如说，`TypeScript`，不得不把所有与类型相关的东西都用注释包起来可能会变得很繁琐，代码也会变得更难阅读。此外，有可能会出现你会输错注释的风险（忘记其中的一个冒号是可能的），然后 Flow 将会忽略你的定义，可能会让 bug 通过。

有没有其他选择？是的，有，但这将需要一些额外的处理，同时给我们使用标准`Flow`符号的好处；让我们现在转向这个。

# 通过预处理使用 Flow 与 Node

使用注释有点过于冗长。如果您更愿意使用直接的类型注释和额外的语句，您将不得不进行一些预处理，以在尝试运行您的`Node`代码之前摆脱`Flow`的装饰。这样做的好处是，所需的处理可以非常高效，并且在开发时几乎不会被注意到；让我们深入研究一下，看看我们如何保留`Flow`定义，同时不破坏我们的`Node`代码。

# 如何做…

我们想要使用更简短、更简洁的`Flow`风格，但`Node`无法执行带有这些附加内容的代码。我们的难题的解决方案很简单：在尝试运行之前，只需删除与`Flow`相关的所有内容！有一个叫做`flow-remove-types`的包可以做到这一点。首先，像往常一样，您需要安装所需的包：

```js
npm install flow-remove-types --save-dev
```

接着，您将需要通过添加一个新的脚本来启用它。我们是在`src/`目录中编写我们的代码，所以让我们将`Flow`清理后的输出发送到`out/`目录。在那个目录中，我们将得到我们将在服务器中使用的代码版本：

```js
"scripts": {
 "build": "flow-remove-types src/ -d out/",
    "addTypes": "flow-typed install",
    "update": "npm install && flow-typed install",
    "flow": "flow",
    .
    .
    .
},
```

最后，我们还应该告诉`Git`忽略`out/`目录。我们已经忽略了`node_modules`和`flow-typed`目录，所以让我们再添加一个：

```js
**/node_modules 
**/flow-typed 
**/out
```

我们指定`**/out`而不是只有`out/`，因为我们在许多项目之间共享一个`Git`存储库，为了这本书。如果像更常见的那样，您为每个项目都有一个单独的存储库，那么您只需指定`out`。

# 它是如何工作的…

从您开始使用`flow-remove-types`起，会有什么变化？首先，显而易见的是，您不能只是用简单的`node src/somefilename.js`来运行您的项目；首先您需要通过`npm run build`来剥离`Flow`。这个命令的效果将是在`out/`中创建一个`src/`中的所有内容的副本，但没有类型声明。然后，您将能够通过`node out/somefilename.js`来运行项目——文件名不会改变。

当`flow-remove-types`包清理您的文件时，它会用空格替换所有类型声明，因此转换后的输出文件的行数完全相同，每个函数的起始行也完全相同，不需要源映射，输出可读性不变。下面的代码显示了在*使用模块*部分中的我们模块的一部分在处理后的样子：

```js
/* @flow */
"use strict";

// These won't be exported:

const roundToCents = (x: number): number => Math.round(x * 100) / 100;

const changeSign = (x: number): number => -x;

// The following will be exported:

const addR = (x: number, y: number): number => roundToCents(x + y);

const subR = (x: number, y: number): number => addR(x, changeSign(y));

const multR = (x: number, y: number): number => roundToCents(x * y);

const divR = (x: number, y: number): number => {
    if (y === 0) {
        throw new Error("Divisor must be nonzero");
    } else {
        return roundToCents(x / y);
    }
};
```

如果您更喜欢较小的输出（毕竟，阅读带有所有这些空格的代码可能有点令人厌烦），您可以生成一个源映射并删除所有空格，方法是通过向构建脚本添加一些参数，或者通过添加一个不同的脚本，如下面的代码片段所示：

```js
"scripts": {
    "build": "flow-remove-types src/ -d out/",
    "buildWithMaps": "flow-remove-types src/ -d out/ --pretty --sourcemaps",
    .
    .
    .
},
```

VSC 中包含的`Node`调试器完全支持源映射，因此生成更简洁的代码不会成为问题。我们将在第五章中更多地了解这一点，*测试和调试您的服务器*。

现在我们有了一种方法来继续使用`Node`和`Flow`，但是运行我们的代码变得稍微复杂了一点；让我们看看我们是否可以解决这个问题！

# 使用 Nodemon 运行您的 Node 代码

到目前为止，我们所做的工作是，每次进行更改后，运行我们更新的`Node`代码都需要执行以下操作：

1.  停止当前版本的代码，如果它仍在运行。

1.  重新运行构建过程以更新`out`目录。

1.  运行新版本的代码。

对于每一个小的更改，做所有这些事情可能会很快变得无聊和令人厌烦。但是，有一个解决方案：我们可以安装一个监视程序，它将监视我们的文件变化，并自动执行这里提到的所有操作，从而使我们摆脱重复的琐事。让我们看看如何设置一个工具来监视变化，并自动执行所有这些步骤。

# 如何做…

我们将要安装和配置`nodemon`，它将为我们处理一切，根据需要运行更新的代码。首先，显然，我们必须安装提到的包。您可以使用`npm install nodemon -g`全局安装，但我宁愿在本地安装：

```js
npm install nodemon --save-dev
```

然后，我们需要添加一对脚本：

+   `npm start`将构建应用程序并运行我们的主文件

+   `npm run nodemon`将开始监视

```js
"scripts": {
    "build": "flow-remove-types src/ -d out/",
    "buildWithMaps": "flow-remove-types src/ -d out/ --pretty --
     sourcemaps",
 "start": "npm run build && node out/doroundmath.js",
 "nodemon": "nodemon --watch src --delay 1 --exec npm start",
    .
    .
    .  
},
```

现在，我们已经准备好监视我们的应用程序进行更改，并根据需要重新启动它！

# 它是如何工作的...

对我们最感兴趣的命令是第二个。当您运行它时，`nodemon`将开始监视，这意味着它将监视您选择的任何目录（在这种情况下是`out`），每当它检测到某个文件更改时，它将等待一秒钟（例如，以确保所有文件都已保存），然后重新运行应用程序。我是如何做到这一点的？

最初，我启动了`nodemon`。当您运行`npm run nodemon`时，项目将被构建然后运行，`nodemon`将继续等待任何更改；请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/bb4c6879-9f4f-494f-b329-4e368b746c39.png)

当您启动 nodemon 时，它会构建项目，运行它，并继续观察是否有任何需要重新启动的更改

之后，我只是添加了一个简单的`console.log()`行，所以文件会被更改；以下截图是结果，显示了重建和重新启动的代码，以及额外的输出行：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/591781d5-b334-44be-8f39-51cbaa44ef65.png)

在观察文件发生任何更改后，nodemon 将重新启动项目。在这种情况下，我刚刚添加了一行日志，用于更改的添加文本。

就是这样。应用程序将自动重新构建和重新启动，而无需我们每次手动重新运行`npm start`；这是一个很大的帮助！

阅读更多关于`nodemon`的信息[`nodemon.io/`](http://nodemon.io/)和[`github.com/remy/nodemon.`](https://github.com/remy/nodemon)

# 使用承诺而不是错误优先的回调

现在，让我们开始考虑在编写服务时会派上用场的几种技术。

`Node`作为一个单线程运行，所以如果每次它需要调用一个服务，或者读取一个文件，或者访问一个数据库，或者进行任何其他 I/O 相关的操作，它都必须等待它完成，那么处理请求将需要很长时间，阻塞其他请求的处理，并且服务器的性能会非常差。相反，所有这些操作都是异步进行的，您必须提供一个回调，当操作完成时将调用该回调；与此同时，`Node`将可用于处理其他客户端的请求。

有许多函数的同步版本，但它们只能应用于桌面工作，而绝不能用于 Web 服务器。

`Node`建立了一个标准，即所有回调都应该接收两个参数：一个错误和一个结果。如果操作以某种方式失败，错误参数将描述原因。否则，如果操作成功，错误将为 null 或 undefined（但无论如何都是*假值*），结果将具有结果值。

这意味着通常的`Node`代码充满了回调，如果回调本身需要另一个操作，那就意味着更多的回调，这些回调本身可能有更多的回调，导致所谓的*回调地狱*。我们不想以这种方式工作，我们希望能够选择现代的承诺，幸运的是，有一种简单的方法可以做到这一点。让我们看看如何通过避免回调来简化我们的代码。

# 如何做…

让我们首先看一下常见的错误优先回调是如何工作的。`fs`（文件系统）模块提供了一个`readFile()`方法，可以读取一个文件，并且可以生成它的文本或错误。我的`showFileLength1()`函数尝试读取一个文件，并列出其长度。与回调一样，我们必须提供一个函数，该函数将接收两个值：可能的错误和可能的结果。

此函数必须检查第一个参数是否为 null。如果不为 null，则意味着存在问题，操作不成功。另一方面，如果第一个参数为 null，则第二个参数具有文件读取操作的结果。以下代码突出了与`Node`回调一起使用的通常编程模式；粗体字的行是关键行：

```js
// Source file: src/promisify.js

/* @flow */
"use strict";

const fs = require("fs");

const FILE_TO_READ = "/home/fkereki/MODERNJS/chapter03/src/promisify.js"; // its own source!

function showFileLength1(fileName: string): void {
    fs.readFile(fileName, "utf8", (err, text) => {
 if (err) {
 throw err;
 } else {
 console.log(`1\. Reading, old style: ${text.length} bytes`);
 }
    });
}
showFileLength1(FILE_TO_READ);

// *continues...*
```

这种编码风格是众所周知的，但实际上并不适合基于 promise 甚至更好的`async`/`await`的现代开发。因此，自`Node`的 8 版本以来，已经有一种方法可以自动将错误优先的回调函数转换为 promise：`util.promisify()`。如果将该方法应用于任何旧式函数，它将变成一个 promise，然后您可以以更简单的方式进行处理。

# 它的工作原理…

`util`模块是`Node`的标准模块，您只需执行以下操作即可使用它：

```js
const util = require("util");
```

`util.promisify()`方法实际上是另一个高阶函数的示例，正如我们在第二章的*使用 JavaScript 现代特性*部分中看到的那样。

使用`util.promisify()`，我们可以使`fs.readFile()`返回一个 promise，然后使用`.then()`和`.catch()`方法进行处理：

```js
// ...*continued*

function showFileLength2(fileName: string): void {
    fs.readFile = util.promisify(fs.readFile); 
    fs
        .readFile(fileName, "utf8")
        .then((text: string) => {
            console.log(`2\. Reading with promises: ${text.length} bytes`);
        })
        .catch((err: mixed) => {
            throw err;
        });
}
showFileLength2(FILE_TO_READ);

// *continues...*
```

您还可以编写`const { promisify } = require("util")`，然后它将变成`fs.readFile = promisify(fs.readFile)`。

这还允许我们使用`async`和`await`；我将使用箭头`async`函数，只是为了多样性：

```js
// ...*continued*

const showFileLength3 = async (fileName: string) => {
    fs.readFile = util.promisify(fs.readFile);

    try {
        const text: string = await fs.readFile(fileName, "utf8");
        console.log(`3\. Reading with async/await: ${text.length} bytes`);
    } catch (err) {
        throw err;
    }
};
showFileLength3(FILE_TO_READ);
```

# 还有更多…

请记住，您并不总是需要`util.promisify()`。这有两个原因：

+   一些库（例如我们已经使用的`axios`）已经返回了 promise，因此您无需做任何事情。

+   其他一些方法（例如`Node`的`http.request()`方法；请参见[`nodejs.org/dist/latest-v9.x/docs/api/http.html#http_http_request_options_callback`](https://nodejs.org/dist/latest-v9.x/docs/api/http.html#http_http_request_options_callback)）具有完全不同的签名，甚至没有错误参数

无论如何，追求标准用法都会有所帮助，因此我们将在本书的其余部分采用基于 promise 的风格。

# 使用流来处理请求

如果您必须处理大量数据集，很明显会引起问题。您的服务器可能无法提供所有所需的内存，或者即使这不会成为问题，所需的处理时间也会超过标准等待时间，导致超时 - 再加上您的服务器会关闭其他请求，因为它将致力于处理您的长时间处理请求。

`Node`提供了一种使用流来处理数据集合的方法，能够在数据流动时处理数据，并将其传输以将功能组合成更小步骤的方式，非常类似于 Linux 和 Unix 的管道。让我们看一个基本示例，如果您有兴趣进行低级`Node`请求处理，可以使用该示例。（正如我们将在下一章中看到的那样，我们将使用更高级的库来完成这项工作。）当请求到来时，其主体可以作为流访问，从而使您的服务器能够处理任何大小的请求。

将发送给客户端的响应也是一个流；我们将在下一节*使用流压缩文件*中看到一个示例。

流可以有四种类型：

+   *可读*：可以（显然！）读取的地方。您可以使用此选项来处理文件，或者如下例所示，获取网络请求的数据。

+   *可写*：可以写入数据的地方。

+   *双工*：可读写，例如网络套接字。

+   *转换*：可以转换读取和写入的双工流；我们将看到一个用于压缩文件的示例。

# 如何做…

让我们编写一些简单的代码来处理请求，并显示所请求的内容。我们的请求处理的主要代码将如下所示：

```js
// Source file: src/process_request.js

const http = require("http");

http
    .createServer((req, res) => {
        // *For PUT/POST methods, wait until the*
        // *complete request body has been read.*

        if (req.method === "POST" || req.method === "PUT") {
            let body = "";

 req.on("data", data => {
 body += data;
 });

 req.on("end", () => processRequest(req, res, body));

        } else {
            return processRequest(req, res, "");
        }
    })
    .listen(8080, "localhost");

// *continues...*
```

`processRequest()`函数将非常简单，仅限于显示其参数。如果您需要更好地理解如何处理请求，这种代码可能会有所帮助，正如我们将在下一章中看到的那样。我们将从 URL 和请求体中获取参数：

```js
// ...*continued*

const url = require("url");
const querystring = require("querystring");

function processRequest(req, res, body) {
 /*
 *Get parameters, both from the URL and the request body*
 */
 const urlObj = url.parse(req.url, true);
 const urlParams = urlObj.query;
 const bodyParams = querystring.parse(body);

 console.log("URL OBJECT", urlObj);
 console.log("URL PARAMETERS", urlParams);
 console.log("BODY PARAMETERS", bodyParams);

 /*
 * Here you would analyze the URL to decide what is required*
 *Then you would do whatever is needed to fulfill the request*
 *Finally, when everything was ready, results would be sent*
 *In our case, we just send a FINISHED message*
 */

 res.writeHead(200, "OK");
 res.end(`FINISHED WITH THE ${req.method} REQUEST`);
}
```

下面我们将看到的代码输出将是请求`url`对象（`req.url`），它的参数以及请求体中的参数。

# 工作原理…

让我们运行刚刚编写的简单服务器，看看它是如何工作的。我们可以使用以下两行构建并运行它：

```js
> npm run build
> node out/process_request.js
```

服务器运行后，我们可以使用`curl`进行测试——我们将在第五章的*从命令行测试简单服务*部分中回到这一点，并且我们将看到我们的`FINISHED...`消息：

```js
> curl "http://127.0.0.1:8080/some/path/in/the/server?alpha=22&beta=9" 
FINISHED WITH THE GET REQUEST

```

URL 周围的引号是必需的，因为`&`字符本身对于 shell 行命令具有特殊含义。

服务器控制台将显示以下输出，但我们现在关心的是 URL 参数，它与`curl`调用中提供的内容匹配：

```js
URL OBJECT Url {
 protocol: null,
 slashes: null,
 auth: null,
 host: null,
 port: null,
 hostname: null,
 hash: null,
 search: '?alpha=22&beta=9',
 query: { alpha: '22', beta: '9' },
 pathname: '/some/path/in/the/server',
 path: '/some/path/in/the/server?alpha=22&beta=9',
 href: '/some/path/in/the/server?alpha=22&beta=9' }
URL PARAMETERS { alpha: '22', beta: '9' }
BODY PARAMETERS {}
```

这很容易，但如果服务请求是`POST`，我们将监听事件来构建请求的`body`。请参考以下：

+   `'data'`在有更多数据需要处理时触发。在我们的情况下，每次事件中我们都会向`body`字符串添加内容，以便构建请求体

+   当没有更多数据时，将触发`'end'`。在这里，我们使用它来识别我们已经获得了完整的请求体，并且现在准备继续处理它。

+   `'close'`（当流关闭时）和`'error'`事件在这里不适用，但也适用于流处理。

如果我们执行`curl -X "POST" --data "gamma=60" --data "delta=FK" "http://127.0.0.1:8080/other/path/"`进行`POST`，传递一对 body 参数，控制台输出将会改变：

```js
URL OBJECT Url {
 protocol: null,
 slashes: null,
 auth: null,
 host: null,
 port: null,
 hostname: null,
 hash: null,
 search: null,
 query: {},
 pathname: '/other/path/',
 path: '/other/path/',
 href: '/other/path/' }
URL PARAMETERS {}
BODY PARAMETERS { gamma: '60', delta: 'FK' }
```

在[`nodejs.org/api/stream.html`](https://nodejs.org/api/stream.html)上阅读更多关于流的信息（大量信息！）。

# 使用流压缩文件

我们可以看到更多使用流的例子，包括多种类型，比如我们想要压缩文件的情况。在这个示例中，我们将使用可读流从源中读取，使用可写流放置压缩后的结果。

# 如何做…

代码非常简单，而且也很短。我们只需要`require`所需的模块，为我们将要读取的文件创建一个输入流，为我们将要创建的文件创建一个输出流，并将第一个流导入到第二个流中；没有比这更简单的了：

```js
// Source file: src/zip_files.js

const zlib = require("zlib");

const fs = require("fs");

const inputStream = fs.createReadStream(
 "/home/fkereki/Documents/CHURCHES - Digital Taxonomy.pdf"
);

const gzipStream = zlib.createGzip();

const outputStream = fs.createWriteStream(
 "/home/fkereki/Documents/CHURCHES.gz"
);

inputStream.pipe(gzipStream).pipe(outputStream);
```

# 工作原理…

我们使用`fs`模块生成两个流：一个可读流，用于读取给定文件（这里是一个固定的文件，但读取任何其他文件也很简单），一个可写流，用于存放压缩后的输出。我们将通过`gzip`模块将输入流导入，该模块将在将输入传递到输出之前对其进行压缩。

我们也可以轻松地创建一个服务器，将压缩文件发送给客户端进行下载。以下是所需的代码；关键区别在于压缩流现在转到`response`流。我们还必须提供一些头信息，以便客户端知道正在发送一个压缩文件：

```js
// Source file: src/zip_send.js

const zlib = require("zlib");
const fs = require("fs");

const http = require("http");

http
    .createServer(function(request, response) {
        // Tell the client, this is a zip file.
 response.writeHead(200, {
 "Content-Type": "application/zip",
 "Content-disposition": "attachment; filename=churches.gz"
 });

        const inputStream = fs.createReadStream(
            "/home/fkereki/Documents/CHURCHES - Digital Taxonomy.pdf"
        );

```

```js
        const gzipStream = zlib.createGzip();

        inputStream.pipe(gzipStream).pipe(response);
    })
    .listen(8080, "localhost");
```

如果您`npm run build`然后`node out/zip_send.js`，打开`127.0.0.1:8080`将会得到以下截图中显示的内容；您将获得要下载的压缩文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/c88deced-a53c-4c57-8b0b-568e86a2f7cd.png)

流也用于压缩并发送文件到浏览器

在[`nodejs.org/api/fs.html`](https://nodejs.org/api/fs.html)上阅读更多关于`fs`的信息，并在[`nodejs.org/api/zlib.html`](https://nodejs.org/api/zlib.html)上阅读更多关于`zlib`的信息。

# 使用数据库

现在让我们看看如何访问数据库，比如`MySQL`，`PostgreSQL`，`MSSQL`，`Oracle`或其他。 (我们将在第四章中需要这个，*使用 Node 实现 RESTful 服务*，当我们开始构建一组服务时。) 经常需要访问数据库，所以这就是我们要做的。我选择了一些地理数据（包括国家，它们的地区以及这些地区的城市），之后我们将添加一些其他内容，以便处理更复杂的例子。

# 准备工作

获取国家列表很容易：我使用了来自[`github.com/datasets/country-codes`](https://github.com/datasets/country-codes)的数据，我将其修剪为只有国家的两个字符代码（如 ISO 3166-1 标准中的那样）和名称。对于地区和城市，我使用了 GeoNames 的数据，来自[`download.geonames.org/export/dump/`](http://download.geonames.org/export/dump/)；特别是我使用了`admin1CodesASCII.txt`，我将其改编为`regions.csv`，以及`cities15000.zip`，我编辑成了`cities.csv`。

如果你想以更清晰的格式查看 CSV 文件，可以查看 VSC 的 EXCEL VIEWER 扩展。

关于这三个表，你需要知道的是：

+   *国家*由两个字母的代码标识（比如*UY*代表乌拉圭，*IN*代表印度），并且有一个名称

+   *地区*属于一个国家，由国家代码加上一个字符串标识；此外，它们有一个名称

+   *城市*由数字代码标识，有一个名称，纬度和经度，人口，并且位于一个国家的一个地区

这就足够开始了；稍后，我们将添加一些更多的表，以便进行更多的实验。我使用了`MariaDB`（`MySQL`的开源分支；参见[`mariadb.com/`](https://mariadb.com/)）和`MySQL WorkBench`（参见[`www.mysql.com/products/workbench/`](https://www.mysql.com/products/workbench/)）来创建表并导入数据，因为这比手工操作更简单！我还创建了一个`fkereki`用户，密码为`modernJS!!`，以便访问这些表。

如果你想使用不同的数据库，比如 PostgreSQL 或 Oracle，下面的代码会非常相似，所以不用太担心处理特定的数据库。如果你使用 ORM，你会看到一些访问数据的与数据库无关的方法，这可能会帮助你真正需要处理不同的数据库产品时。

# 如何做…

为了访问`MariaDB`数据库，我们将从[`github.com/mscdex/node-mariasql`](https://github.com/mscdex/node-mariasql)安装`mariasql`包，然后将其`.query()`方法 promisify，以便更轻松地工作。安装完成后使用`npm install mariasql --save`，不久之后（你会看到一些对象代码被构建），包将被安装。按照接下来提到的步骤进行。

另一个可能性是使用来自[`github.com/steelbrain/mariasql-promise`](https://github.com/steelbrain/mariasql-promise)的`mariasql-promise`，其所有方法都已经返回了 promises。然而，使用这个库获取连接对象并存储以供以后使用更加困难，这就是为什么我选择了原始的库；毕竟，我们只需要修改`.query()`来返回一个 promise。

# 获取连接

首先，让我们定义一些以后会用到的常量；除了`Flow`和严格使用行之外，我们只需要`MariaDB`库，`promisify()`函数，并定义四个常量来访问数据库：

```js
// Source file: src/dbaccess.js

/* @flow */
"use strict";

const mariaSQL = require("mariasql");
const { promisify } = require("util");

const DB_HOST = "127.0.0.1";
const DB_USER = "fkereki";
const DB_PASS = "modernJS!!";
const DB_SCHEMA = "world";

// *continues...*
```

现在，让我们获取一个数据库连接。我们只需创建一个新对象，并`promisify`它的`.query()`方法。`dbConn`变量将作为参数传递给每个需要访问数据库的函数：

```js
// ...*continued*

function getDbConnection(host, user, password, db) {
    const dbConn = new mariaSQL({ host, user, password, db });
    dbConn.query = promisify(dbConn.query);
    return dbConn;
}

const dbConn = getDbConnection(DB_HOST, DB_USER, DB_PASS, DB_SCHEMA); // *continues*...
```

# 执行一些查询

测试连接是否正常工作的一个简单方法是执行一个返回常量值的微不足道的查询；这里真正重要的是，函数应该在不抛出任何异常的情况下工作。我们使用`await`来获取`.query()`方法的结果，这是一个包含所有找到的行的数组；在这种情况下，数组显然只有一行：

```js
// ...*continued*

async function tryDbAccess(dbConn) {
    try {
        const rows = await dbConn.query("SELECT 1960 AS someYear");
        console.log(`Year was ${rows[0].someYear}`);
    } catch (e) {
        console.log("Unexpected error", e);
    }
}

// *continues*...
```

让我们试试其他的东西：比如找出有更多城市的十个国家？我们可以使用`.forEach()`以一个相当不太吸引人的格式列出结果：

```js
// ...*continued*

async function get10CountriesWithMoreCities(dbConn) {
    try {
        const myQuery = `SELECT 
            CI.countryCode, 
            CO.countryName, 
            COUNT(*) as countCities
        FROM cities CI JOIN countries CO 
        ON CI.countryCode=CO.countryCode
        GROUP BY 1 
        ORDER BY 3 DESC 
        LIMIT 10`;

 const rows = await dbConn.query(myQuery);
 rows.forEach(r =>
 console.log(r.countryCode, r.countryName, r.countCities)
 );
    } catch (e) {
        console.log("Unexpected error", e);
    }
}

// *continues...*
```

# 更新数据库

最后，让我们做一些更新。我们将首先添加一个新的（虚构的！）国家；然后我们将检查它是否存在；我们将更新它并检查更改，然后我们将删除它，最后我们将验证它是否已经消失：

```js
// ...*continued*

async function addSeekAndDeleteCountry(dbConn) {
    try {
        const code = "42";
        const name = "DOUGLASADAMSLAND";

        /*
            1\. Add the new country via a prepared insert statement
        */
 const prepInsert = dbConn.prepare(
 "INSERT INTO countries (countryCode, countryName) VALUES (:code, :name)"
 );
 const preppedInsert = prepInsert({ code, name });
        await dbConn.query(preppedInsert);

        /*
            2\. Seek the recently added country, return an array of objects
        */
 const getAdams = `SELECT * FROM countries WHERE countryCode="${code}"`;
        const adams = await dbConn.query(getAdams);
        console.log(
            adams.length,
            adams[0].countryCode,
            adams[0].countryName
        );

        /*
            3\. Update the country, but using placeholders
        */
        await dbConn.query(
            `UPDATE countries SET countryName=? WHERE countryCode=?`,
            ["NEW NAME", code]
        );

        /*
           4\. Check the new data, but returning an array of arrays instead
        */
        const adams2 = await dbConn.query(
            `SELECT * FROM countries WHERE countryCode=?`,
            [code],
            { useArray: true }
        );
        console.log(adams2.length, adams2[0][0], adams2[0][1]);

        /*
            5\. Drop the new country
        */
 await dbConn.query(`DELETE FROM countries WHERE countryCode="42"`);

        /*
            6\. Verify that the country is no more
        */
        const adams3 = await dbConn.query(getAdams);
        console.log(adams3.length);
    } catch (e) {
        console.log("Unexpected error", e);
    }
}

// *continues...*
```

# 将所有内容整合在一起

现在，我们所要做的就是调用这三个函数，以获得一个完整的工作示例：

```js
// ...*continued*

tryDbAccess(dbConn);
get10CountriesWithMoreCities(dbConn);
addSeekAndDeleteCountry(dbConn);
```

最后，我添加了一个脚本来自动运行所有测试，通过执行`npm run start-db`：

```js
"scripts": {
    "build": "flow-remove-types src/ -d out/",
    "buildWithMaps": "flow-remove-types src/ -d out/ --pretty --sourcemaps",
    "start": "npm run build && node out/doroundmath.js",
    "start-db": "npm run build && node out/dbaccess.js",
    .
    .
    .
},
```

让我们分析一下代码的工作原理，并注意一些有趣的地方。

# 它是如何工作的...

运行`tryDbAccess()`并不难理解：常量查询发送到服务器，返回一个包含单行的数组。我们的代码的输出将如下所示：

```js
Year was 1960
```

第二个查询变得更有趣。除了实际编写 SQL 查询的细节（这超出了本书的目标）之外，有趣的是返回的数组，每个数组中都有一个包含所选字段的对象：

```js
IN India 1301
BR Brazil 1203
RU Russian Federation 1090
DE Germany 1061
CN China 810
FR France 633
ES Spain 616
JP Japan 605
IT Italy 575
MX Mexico 556
```

现在，让我们来看最后一个例子。我们看到了几种创建将要执行的语句的方式。

`INSERT`使用了一个准备好的语句。准备好安全查询的一个好方法（意思是，它们不会涉及到 SQL 注入攻击）是使用准备好的字符串。`.prepare()`方法很有趣：给定一个字符串，它返回一个函数，当用实际参数调用时，它本身将返回要在查询中使用的字符串。当然，您也可以手动构建函数，就像我在其他示例中所做的那样——但是这时你必须确保生成的查询是安全的！

`.escape()`方法可以帮助构建一个安全的查询字符串，如果你不想使用`.prepare()`。更多信息请参见[`github.com/mscdex/node-mariasql`](https://github.com/mscdex/node-mariasql)。

接下来的`SELECT`使用了手工创建的字符串（这里没有什么太原创的东西），但`UPDATE`显示了另一种风格：使用`?`符号作为*占位符*。在这种情况下，您还必须提供一个值数组，用于替换占位符；数组中的值的顺序必须与预期的参数匹配，这是非常重要的。

接下来，第二个`SELECT`也使用了占位符，但添加了一个小调整：传递一个带有`useArray:true`选项的对象，函数执行速度会稍快一些，因为它不会为每一行创建对象，而是直接返回数组。然而，这也存在一个问题，因为现在你必须记住数组的每个位置代表什么意思。

代码的结果如预期的那样：首先是一行，显示实际创建了一个国家，带有我们传递的值；然后是相同的记录，但名称已更改，最后是一个零，表明该国家不再存在：

```js
1 '42' 'DOUGLASADAMSLAND'
1 '42' 'NEW NAME'
0
```

# 还有更多...

在这一部分，我们已经通过直接连接，使用表和游标对数据库执行各种操作的几个示例进行了讨论。您还可以考虑使用**对象关系映射**（**ORM**）库，以处理对象：最为人熟知的可能是`Sequelize`（在[`docs.sequelizejs.com/`](http://docs.sequelizejs.com/)），但还有一些其他包（如`TinyORM`、`Objection.js`或`CaminteJS`，只是提到一些仍在开发中的包，没有被放弃）。

# 使用 exec()执行外部进程

如果你正在使用`Node`实现一些服务，可能会有一些情况需要进行一些繁重的处理，正如我们之前提到的，这是一个*不行*，因为你会阻塞所有用户。如果你需要做这种工作，`Node`可以让你将工作卸载到外部进程中，从而使自己空闲并可继续工作。外部进程将以异步方式独立工作，完成后，你将能够处理其结果。有几种方法可以做到这一点；让我们来看看。

运行一个单独命令的第一种选择是`child_process.exec()`方法。这将生成一个 shell，并在其中执行给定的命令。生成的任何输出将被缓冲，当命令执行完成时，将调用一个回调函数，其中包含生成的输出或错误。

让我们看一个通过访问文件系统调用外部进程的例子。

# 如何做到这一点...

一个例子，获取给定路径上所有 JS 文件的目录列表，可能如下所示。（是的，当然你可以和应该使用`fs.readDir()`来做到这一点，但我们想展示如何使用子进程来做到这一点。）

正如本章前面的*使用 Promise 代替错误优先回调*部分所示，我们将`promisify()`调用，以简化编码：

```js
// Source file: src/process_exec.js

const child_process = require("child_process");
const { promisify } = require("util");
child_process.exec = promisify(child_process.exec);

async function getDirectoryJs(path: ?string) {
    try {
 const cmd = "ls -ld -1 *.js";
        const stdout = await child_process.exec(cmd, { cwd: path });
        console.log("OUT", path || "");
        console.log(stdout);
    } catch (e) {
        console.log("ERR", e.stderr);
    }
}
```

# 它是如何工作的...

当我们调用`.exec()`方法时，将创建一个单独的 shell，并在其中运行命令。如果调用成功，将返回输出；否则，将抛出一个具有`.stderr`属性的对象作为异常。可能的一对运行如下：

```js
getDirectoryJs("/home/fkereki/MODERNJS/chapter03/flow-typed/npm");
*OUT /home/fkereki/MODERNJS/chapter03/flow-typed/npm*
*-rw-r--r-- 1 fkereki users 4791 Apr 9 12:52 axios_v0.18.x.js*
*-rw-r--r-- 1 fkereki users 3006 Mar 28 14:51 babel-cli_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 3904 Apr 9 12:52 babel-eslint_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 2760 Apr 9 12:52 babel-preset-env_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 888 Apr 9 12:52 babel-preset-flow_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 518 Apr 9 12:52 eslint-config-recommended_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 14995 Apr 9 12:52 eslint-plugin-flowtype_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 73344 Apr 9 12:52 eslint_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 1889 Mar 28 14:51 fetch_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 188 Apr 9 12:52 flow-bin_v0.x.x.js*
*-rw-r--r-- 1 fkereki users 13290 Apr 9 12:52 flow-coverage-report_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 1091 Apr 9 12:52 flow-remove-types_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 5763 Apr 9 12:52 flow-typed_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 1009 Apr 9 12:52 mariasql_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 0 Mar 28 14:51 moment_v2.3.x.js*
*-rw-r--r-- 1 fkereki users 5880 Apr 9 12:52 nodemon_vx.x.x.js*
*-rw-r--r-- 1 fkereki users 4786 Apr 9 12:52 prettier_v1.x.x.js*

getDirectoryJs("/boot");
*ERR ls: cannot access '*.js': No such file or directory*
```

`.exec()`的第二个参数提供了一个可能选项的对象。在我们的情况下，我们正在指定命令的当前工作目录（`cwd`）。另一个有趣的选项可以让你处理产生大量输出的命令。默认情况下，最大缓冲输出量为 200K；如果你需要更多，你将不得不添加一个对象，其中`maxBuffer`选项设置为更大的值；查看[`nodejs.org/api/child_process.html#child_process_child_process_exec_command_options_callback`](https://nodejs.org/api/child_process.html#child_process_child_process_exec_command_options_callback)了解更多关于这些和其他选项的信息。

你可以执行的命令的复杂性没有限制，但也存在风险。请记住被黑客攻击的可能性：如果你正在根据用户提供的某些输入构建你的命令，你可能会成为命令注入攻击的受害者。想象一下，如果你想构建类似于``ls ${path}``的东西，而用户提供的`path`是`"/; rm -rf *"`，会发生什么？

# 还有更多...

使用`.exec()`对于短命令和少量输出非常好。如果你实际上不需要 shell，你甚至可以使用`.execFile()`更好，它直接运行所需的命令，而不是首先创建一个 shell，然后在其中运行命令。有关更多信息，请参阅[`nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback)。

# 使用 spawn()运行命令，并与其通信

使用`.exec()`很简单，但你只能处理小型输出，并且也无法得到部分答案：让我们更多地了解这一点。想象一下，你正在准备一个大文件要发送给客户端。如果你要用`.exec()`读取该文件，你将无法在读取完整个文件之前开始将文件内容发送给客户端。然而，如果文件太大，这不仅意味着延迟，还可能导致崩溃。使用`.spawn()`给你一个有趣的补充：使用流进行双向通信，与生成的进程。

# 如何做到这一点...

使用`.spawn()`在一般情况下类似于`.exec()`。现在让我们使用一个单独的进程来读取一个目录并将其结果发送回来。我们将使用流传递要处理的路径，并且我们也将通过流获得找到的文件列表。

首先，让我们有主要的代码，它将生成一个进程：

```js
// Source file: src/process_spawn.js

const path = require("path");
const { spawn } = require("child_process");

const child = spawn("node", [path.resolve("out/process_spawn_dir.js")]);

child.stdin.write("/home/fkereki");

child.stdout.on("data", data => {
    console.log(String(data));
});

child.stdout.on("end", () => {
    child.kill();
});
```

最后，我们需要子进程，它将如下所示：

```js
// Source file: src/process_spawn.js

const fs = require("fs");

process.stdin.resume();

process.stdin.on("data", path => {
    // Received a path to process
    fs
        .readdirSync(path)
        .sort((a, b) => a.localeCompare(b, [], { sensitivity: "base" }))
        .filter(file => !file.startsWith("."))
        .forEach(file => process.stdout.write(file + "\n"));

 process.stdout.end();
});
```

# 它是如何工作的...

生成的进程展示了另一种事件的情况。进程保持在那里等待，每当进程通过`stdin`输入接收到任何数据时，就会触发`"data"`事件，就像通过`child.stdin.write("/home/fkereki")`行所做的那样。然后，进程使用`fs.readdirSync()`读取目录，这是一个同步调用，在正常的`Node`代码中不应该使用，但在子进程中是安全的，因为它不会阻塞任何东西。调用的结果被排序，过滤以避免隐藏文件，然后将行写入`stdout`。

与子进程类似，父进程监听来自子进程`stdout`的事件。每当数据到达时（触发`"data"`事件），它会简单地使用`console.log()`记录。当子进程发出信号表示不会再有数据到来时，通过执行`process.stdout.end()`，将触发`"end"`事件，父进程会识别它，并可以做任何想做的事情。

这种生成进程的方式允许父进程和子进程之间进行双向通信，可以用于许多不同的形式。

# 使用 fork()来运行 Node 命令

`Child_process.fork()`方法是`.spawn()`的一个特殊情况，它专门只生成新的`Node`进程。生成的子进程内置了一个通信通道，使得在父进程和子进程之间传递消息变得更简单：你只需使用`.send()`方法发送消息，并在另一侧监听`"message"`事件。让我们看看如何分叉出第二个进程，并与第一个进程进行通信。

# 如何做...

由于上一节的代码使用`.spawn()`来启动一个新的`Node`实例并运行一些代码，很明显我们可以很快简单地调整它，改用`.fork()`。此外，我们不必使用`stdin`和`stdout`进行通信，而是选择使用消息传递。

首先，让我们从父代码开始。它将变成以下内容；关键的差异是使用`.fork()`而不是`.spawn()`，以及发送文件路径给子进程的方式：

```js
// Source file: src/process_fork.js

const path = require("path");
const { fork } = require("child_process");

const child = fork(path.resolve("out/process_fork_dir.js"));

child.send({ path: "/home/fkereki" });

child.on("message", data => {
    console.log(String(data));
});
```

然后，子代码也会显示一些小的变化，接收消息的方式以及向父进程发送数据的方式：

```js
// Source file: src/process_fork_dir.js

const fs = require("fs");

process.on("message", obj => {
    // Received a path to process
    fs
        .readdirSync(obj.path)
        .sort((a, b) => a.localeCompare(b, [], { sensitivity: "base" }))
        .filter(file => !file.startsWith("."))
        .forEach(file => process.send && process.send(file));
});
```

# 它是如何工作的...

使用`.fork()`意味着子进程是一个`Node`进程，所以我们不需要明确地提到它，就像我们在上一节中所做的那样，我们只需要传递要执行的 JS 文件的名称。

第二个差异，正如我们所提到的，是我们不再使用`stdin`和`stdout`进行通信，而是可以`.send()`一个消息（从父到子或反之亦然），并且我们监听`"message"`事件而不是`"data"`事件。

如果你分析代码中突出显示的差异，你会意识到这些差异实际上是非常小的，对于需要运行一个单独的`Node`进程的特殊情况（但并不罕见），`.fork()`更合适，可能也更简单一些。


# 第四章：使用 Node 实现 RESTful 服务

我们将涵盖以下配方：

+   使用 Express 开发服务器

+   添加中间件

+   获取请求参数

+   提供静态文件

+   添加路由

+   实现安全连接

+   使用 Helmet 添加安全保障

+   实现 CORS

+   使用 JWT 添加身份验证

+   将所有内容绑在一起-构建 REST 服务器

# 介绍

在上一章中，我们看了一系列重要的基本 Node 技术。在本章中，我们将使用它们来建立一个基本的`Express`服务器，并在此基础上进行扩展，直到我们能够生成一个适用于**面向服务的架构**（**SOA**）设置的 RESTful 服务器。

# 使用 Express 开发服务器

虽然你可以使用普通的`Node`并做任何事情，但今天`Express`无疑是最常用的`Node`框架，它允许您通过提供大量基本功能来轻松开发服务器。首先，让我们安装它并检查它是否工作，然后继续构建服务等。

在这个配方中，我们将首先进行`Express`的基本安装，以便我们可以在后面的章节中进行更高级的工作。

您可以在[`expressjs.com/`](https://expressjs.com/)了解更多关于`Express`的信息。

# 如何做... 

让我们安装`Express`并确保它可以工作。安装基本上很简单，因为它只是另一个`npm`包，所以你只需要一个简单的命令：

```js
npm install express --save
```

您可以在`npm`命令中添加一个`--verbose`可选参数，以获得更详细的输出并能够看到发生的事情。

接下来，让我们重新做一下上一章的基本测试服务器，但使用`Express`。是的，对于这样一个简单的功能来说，这实在是过度了，但我们只是想检查我们是否以正确的方式设置了一切！参考以下代码：

```js
// Source file: src/hello_world.js

/* @flow */
"use strict";

const express = require("express");

const app = express();

app.get("/", (req, res) => res.send("Server alive, with Express!"));
```

```js
app.listen(8080, () =>
    console.log(
        "Mini server (with Express) ready at http://localhost:8080/!"
    )
);
```

# 它是如何工作的...

运行此服务器与我们非常基本的`Node`服务器几乎相同：

```js
> npm run build
> node out/hello_world.js
Mini server (with Express) ready at http://localhost:8080/!
```

我们可以进行与之前相同的测试，并注意以下内容：

+   访问`/`地址会返回一个`服务器活着`的消息

+   其他路径会产生 404（未找到）错误：

```js
> curl 127.0.0.1:8080
Server alive, with Express!

```

尝试访问其他路径（或`/`，但不是使用`GET`）将返回一个`404`错误和一个 HTML 错误屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/26f05363-d552-4848-9734-5c8e64c40ded.png)

基本的 Express 配置显示了 404（未找到）错误的错误屏幕

关键的一行是`app.get("/", (req, res) => ...)`调用。基本上，在创建了应用程序对象（`app`）之后，您可以指定一个路由（在本例中为`/`），一个 HTTP 方法（例如`.get()`，`.post()`，`.put()`和`.delete()`），以及更多内容。

转到[`expressjs.com/en/4x/api.html#app.METHOD`](https://expressjs.com/en/4x/api.html#app.METHOD)了解更多可用方法。

您还可以使用`.all()`作为每种可能方法的捕获，以及当用户点击特定路径时将被调用的函数。在我们的情况下，无论请求（`req`）是什么，响应（`res`）都是恒定的，但显然您希望为实际服务做更多事情！

毋庸置疑，您肯定会有多个路由，可能不仅处理`GET`方法。您肯定可以添加许多更多的路由和方法，我们将在接下来的章节中介绍更高级的路由。

另一条有趣的线是`app.listen()`，它指定要监听的端口，以及在服务器启动时将执行的函数；在我们的情况下，它只是一个日志消息。

现在我们已经成功运行了服务器，让我们实现一些其他常见的服务器功能。

# 添加中间件

`Express`的所有功能都基于一个关键概念：*中间件*。如果你使用纯粹的 Node，你必须编写一个单一的大型*请求处理程序*来处理服务器可能收到的所有请求。通过使用中间件，`Express`让你将这个过程分解成更小的部分，以一种更加功能化、管道式的方式。如果你需要检查安全性、记录请求、处理路由等等，所有这些都将由适当放置的中间件函数来完成。

首先，让我们了解`Express`与`Node`的区别，看看我们如何添加一些基本的自定义中间件，然后再应用常见需求的通常函数。更多信息请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/e8a129e0-6943-46e0-a7e1-9bb702789148.png)

标准处理，在没有 Express 中间件处理的情况下 - 你的代码必须处理所有的处理

在标准处理中（参见前面的图表），`Node`从互联网客户端获取请求，将它们传递给你的代码进行处理，获取生成的响应，并将其传递给原始客户端。你的代码必须处理所有的东西，基本上相当于一个非常大的函数，处理安全性、加密、路由、错误等等。如果你将`Express`加入其中，这个过程会有所改变：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/62196a34-5120-48f6-8a5e-5d17adbcfbdb.png)

当 Express 被添加时，它通过将请求传递给中间件堆栈来处理响应

在这种情况下，你设置了一系列函数，`Express`会按顺序调用它们，每个函数都处理整个过程的一个特定方面，简化了整体逻辑。此外，你不必直接处理常见问题（比如，CORS 或压缩等），因为有很多`Express`包已经提供了这样的功能；你只需要将它们添加到适当的位置。

为了更好地了解这是如何工作的，在这个示例中，让我们开发一个非常基本的请求日志记录器（我们将在第五章的*使用 Morgan 添加 HTTP 日志记录*部分中深入学习），以及一个错误报告器。

# 准备就绪

如果你想添加一些中间件，你必须将它放在你定义的所有函数中的正确顺序中。例如，如果你想要记录一些东西，你可能希望在任何处理之前就这样做，所以你会在堆栈的顶部或者非常靠近顶部添加这个定义。

中间件函数接收三个参数：传入的 HTTP 请求（我们一直称之为`req`），传出的 HTTP 响应（`res`），以及当你希望继续处理下一个中间件时必须调用的函数（`next()`）。当你的中间件被调用时，它必须要么发送一个响应（使用`res.send()`、`res.sendFile()`或`res.end()`），要么调用`next()`，以便堆栈中的下一个函数有机会产生答案。

错误函数有些不同，它们在我们刚刚列出的三个参数中添加了一个错误（`err`）参数；有四个参数的函数在`Express`眼中标志着它是一个错误处理器。如果一切正常，`Express`会跳过错误中间件，但如果发生错误，`Express`将跳过每个函数，直到它找到第一个可用的错误函数。

让我们跳到最后，查看我们完整的中间件示例，如下所示；我们将在下一节中解释它是如何工作的：

```js
// Source file: src/middleware.js

/* @flow */
"use strict";
const express = require("express");
const app = express();

app.use((req, res, next) => {
    console.log("Logger... ", new Date(), req.method, req.path);
    next();
});

app.use((req, res, next) => {
    if (req.method !== "DELETE") {
        res.send("Server alive, with Express!");
    } else {
        next(new Error("DELETEs are not accepted!"));
    }
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () =>
    console.log(
        "Mini server (with Express) ready at http://localhost:8080/!"
    )
);
```

# 如何做...

让我们从我们的日志记录器开始。我们希望它适用于每个路径，这样我们就可以省略路径。另一种方法是编写`app.use("*", ...)`，它的意思完全相同；我们也将使用它作为示例。您的逻辑可以做任何事情，由于我们想要记录请求，我们可以列出当前时间戳、`request`方法和请求的路径。之后——这是最重要的事情——由于我们还没有处理请求，调用`next()`是强制的，否则请求将陷入处理的困境，永远不会向客户端发送任何内容：

```js
app.use((req, res, next) => {
    console.log("Logger... ", new Date(), req.method, req.path);
    next();
});
```

由于我们希望有一些错误，让我们定义`DELETE`方法不被接受，因此将调用`next()`，但传递一个错误对象；其他请求将只得到一个简单的文本答复。然后，我们的主要请求处理代码可能如下所示：

```js
app.use((req, res, next) => {
 if (req.method === "DELETE") {
 next(new Error("DELETEs are not accepted!"));
    } else {
        res.send("Server alive, with Express!");
    }
});
```

最后，我们的错误处理代码将记录错误，并返回`500`状态：

```js
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});
```

您会注意到需要禁用`no-unused-vars`ESLint 规则。仅通过函数签名识别错误并不是一个很好的做法，如果您将错误处理程序设置在堆栈的末尾，以便没有其他函数可以调用，那么下一个参数将是未使用的，并且会导致错误。有一些关于在即将推出的`Express`版本中解决这种情况的讨论，但目前这一点并不重要。

我们刚刚展示的错误代码，尽管很基本，但实际上可以在您编写的几乎每个 Node 服务器中使用。我们将在我们的示例中使用它。

# 它是如何工作的...

我们已经设置好了一切；现在，让我们看看我们的代码是如何工作的：

```js
> npm run build
> node out/middleware.js
```

我们可以使用一些 curl 请求来测试这个；让我们使用`GET`、`POST`和`DELETE`：

```js
> curl "http://127.0.0.1:8080/some/path/to/get?value=9" 
Server alive, with Express!
> curl -X POST "http://127.0.0.1:8080/a/post/to/a/path" 
Server alive, with Express!
> curl -X DELETE "http://127.0.0.1:8080/try/to/delete?key=22" 
INTERNAL SERVER ERROR
```

记录的输出将如下所示：

```js
Logger... 2018-05-08T00:22:20.192Z GET /some/path/to/get
Logger... 2018-05-08T00:22:44.282Z POST /a/post/to/a/path
Logger... 2018-05-08T00:23:01.888Z DELETE /try/to/delete
Error.... DELETEs are not accepted!
```

现在，我们知道如何编写自己的中间件，但恰好`Express`提供了许多现成的函数。让我们试试它们，看看我们如何在几个常见需求中使用它们。

# 获取请求参数

让我们解决一个基本问题：如何获取请求参数？在我们之前的示例中，在上一章的*使用流处理请求*部分中，我们手动处理了请求流以获取主体，并使用解析函数提取参数。但是，`Express`已经提供了一些中间件，您可以在堆栈中的任何其他函数之前使用，这些函数需要来自主体或 URL 本身的参数。因此，在本教程中，让我们看看如何访问请求参数，这是一个非常基本的需求。

# 如何做...

让我们看看如何访问参数。首先，您必须要求`body-parser`模块，并要求您想要的选项；我们将在下一节中详细介绍：

```js
// Source file: src/get_parameters.js

const bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({ extended: false }));
```

由于您希望在任何处理之前解析参数，因此`app.use()`行将位于堆栈的顶部。

现在，更详细地了解一下，`body-parser`模块提供了四个解析器：

+   *URL 编码的 body 解析器*，就像我们在这里使用的一样，阅读有关使用`extended` true 或 false 的差异。查看[`github.com/expressjs/body-parser`](https://github.com/expressjs/body-parser)获取更多信息。

+   *JSON body 解析器*，如`bodyParser.json()`，用于处理`Content-Type`为`application/json`的请求。

+   *原始 body 解析器*，如`bodyParser.raw()`，默认情况下用于处理`application/octet-stream`内容，尽管可以通过提供`type`选项进行更改。

+   *文本 body 解析器*，如`bodyParser.text()`，用于处理`text/plain`内容。

后三个解析器可能提供额外的选项；查看文档以获取更多信息。但是，请注意，如果您必须处理多部分主体，那么您不能依赖于`body-parser`；请参阅[`github.com/expressjs/body-parser`](https://github.com/expressjs/body-parser)获取一些替代方案，并查看适合您的内容。

# 它是如何工作的...

我们只需要添加几行代码，一切就设置好了。我们可以通过更改前一节中的记录器，或者编写如下代码来看到我们的代码工作：

```js
// Source file: src/get_parameters.js

app.use("*", (req, res) => {
    console.log(req.query, req.body);
    res.send("Server alive, with Express!");
});
```

URL 参数会被`Express`自动分离为`req.query`，`req.body`将被`bodyParser`解析。我们可以尝试一些服务调用，`GET`和`POST`，以涵盖所有情况：

```js
> curl "http://127.0.0.1:8080/birthdays?day=22&month=9&year=1960" 
> curl -X POST --data "name=FK" "http://127.0.0.1:8080/persons" 
```

输出将如下所示：

```js
> node out/get_parameters.js
Mini server (with Express) ready at http://localhost:8080/!
{ day: '22', month: '9', year: '1960' } {}
{} { name: 'FK' }
```

在第一种情况（`GET`）中，我们可以看到`req.query`是一个带有三个查询参数的对象，而在第二种情况（`POST`）中，没有查询参数，但`req.body`提供了我们提供的单个参数（`name`）。

这应该让您相信 Express 的设计的优点，基于中间件堆栈，但让我们通过一些更多的例子来看一下，比如处理静态文件、路由、安全性等等。

# 提供静态文件

我们计划创建一组 REST 服务，但您的服务器很可能还需要提供一些静态文件，比如图片、PDF 等等。原则上，您可以通过手动设置特定路由来处理每个静态资源，然后编写一个函数来读取所需的文件并将其内容流式传输到客户端；我们在前一章的*使用流处理请求*部分做了类似的事情。

然而，这是一个如此常见和重复的任务，`Express`提供了一个更简单的解决方案；让我们看看如何简单地提供静态文件。

更好的解决方案是在您的堆栈中添加另一个服务器，比如 nginx，并让它处理静态文件。标准服务器更擅长处理这种类型的简单请求，并且会让您的 Node 代码空闲下来处理更复杂、更苛刻的任务。

# 如何做...

假设我们想为一个应用程序提供一些国旗图标。我做了以下操作：

1.  我在与输出文件所在的`/out`目录同级别创建了一个`/flags`目录，并在其中创建了一些子目录：`/flags/america/north`，`/flags/america/south`和`/flags/europe`。

1.  我在这些目录中放了一些来自*GoSquared*的免费国旗图标，取自[`www.gosquared.com/resources/flag-icons/`](https://www.gosquared.com/resources/flag-icons/)。为了多样化，这些国旗可以在`/static`路径下访问，实际上并不存在。

1.  我写了以下代码；这是之前的基本服务器，只是添加了一些代码（用粗体字显示）来处理静态文件：

```js
// Source file: src/serve_statics.js

/* @flow */
"use strict";

const express = require("express");
const path = require("path");
const app = express();

app.get("/", (req, res) => res.send("Server alive, with Express!"));

app.use(
 "/static",
 express.static(path.join(__dirname, "../flags"), {
 immutable: true,
 maxAge: "30 days"
 })
);

app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () =>
    console.log(
        "Mini Express static server ready at http://localhost:8080/!"
    )
);
```

如果您想阅读更多关于提供静态文件的信息，请查看 Node 的文档[`expressjs.com/en/starter/static-files.html`](https://expressjs.com/en/starter/static-files.html)。

在这种情况下，`app.use()`得到了一个特殊的函数`express.static()`，它负责发送给定路径中的文件，并带有一些缓存标头；让我们深入了解一下：

+   `app.use()`的第一个参数是用户将选择的路径的基础；请注意，它不需要存在于实际目录中，就像我们之前看到的其他示例一样。顺便说一句，如果我们想接受所有 HTTP 方法，我们可以写`app.use()`。

+   `express.static()`的第一个参数指定了文件所在的路径。我使用`path.join()`函数来找到实际路径：`/flags`与`/out`在同一级别。

+   `express.static()`的第二个参数允许您添加选项；在我们的例子中，我发送了一些缓存标头，以便浏览器知道该文件可以安全地缓存 30 天。

`maxAge`参数的格式可以是`ms`包（[`github.com/zeit/ms`](https://github.com/zeit/ms)）理解的格式，它能够将日期和时间字符串转换为相应的毫秒数，这是 JS 的标准。

# 它是如何工作的...

每当用户指定以`/static`开头的路径时，它会被转换成等效的以`/flags`开头的路径，如果找到文件，它将被发送回来，并包括缓存头。查看以下截图，以了解此示例：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/a4a1be1a-646c-43ea-9144-6db7632119b0.png)

一个静态的标志图标，从一个不存在的路径/static 提供，映射到一个实际的路径

# 还有更多...

如果您想出于某种特定原因发送静态文件，而不使用前一节中显示的方法，您可以使用路由和`res.sendFile()`方法，如下面的代码所示：

```js
// Source file: src/serve_statics_alt.js

/* @flow */
"use strict";

const express = require("express");
const app = express();
const path = require("path");

const flagsPath = path.join(__dirname, "../flags");

app.get("/uruguay", (req, res) =>
 res.sendFile(`${flagsPath}/america/south/UY.png`)
);

app.get("/england", (req, res) =>
 res.sendFile(`${flagsPath}/europe/GB.png`)
);

app.get("/license", (req, res) =>
 res.sendFile(`${flagsPath}/license.txt`)
);

app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () =>
    console.log(
        "Mini Express static server ready at http://localhost:8080/!"
    )
);
```

如果您访问[`127.0.0.1:8080/uruguay`](http://127.0.0.1:8080/uruguay/)，您将得到我的祖国的国旗，而[`127.0.0.1:8080/license`](http://127.0.0.1:8080/license)将检索我选择的图标集的 MIT 许可证；请参见以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/6e7eb6ab-c3f6-4e04-98ad-790ad85067fc.png)

测试发送文本文件的不同路由

当然，如果您有很多静态文件需要提供，您不会使用这种方法，但如果您只有一些文件，那么这种替代解决方案非常有效。

您可能已经注意到，我没有为缓存添加头信息，但这当然是可以做的。在[`expressjs.com/en/api.html#res.sendFile`](https://expressjs.com/en/api.html#res.sendFile)上阅读更多关于`res.sendFile()`的信息，特别是`immutable`和`headers`选项。

# 添加路由

无论您构建什么样的服务器（我们计划构建一个 RESTful 服务器，或者其他任何类型的服务器），您都必须处理路由，`Node`和`Express`提供了简单的方法来做到这一点。

回到我们在上一章*与数据库一起工作*中的数据库，以 RESTful 的方式，我们应该提供以下路由，允许给定的方法：

+   `/countries`（`GET`获取所有国家的列表，`POST`创建一个新的国家）

+   `/countries/someCountryId`（`GET`访问一个国家，`PUT`更新一个国家，`DELETE`删除一个国家）

+   `/regions`（`GET`获取所有国家的所有地区，`POST`创建一个新的地区）

+   `/regions/someCountryId`（`GET`获取给定国家的所有地区）

+   `/regions/someCountryId/someRegionId`（`GET`访问一个地区，`PUT`更新一个地区，`DELETE`删除一个地区）

+   `/cities`（`GET`获取所有城市 - 但由于结果集的大小，我们实际上不会想要允许这样做！—再加上`POST`创建一个新的城市）

+   `/cities/someCityId`（`GET`访问一个城市，`PUT`更新一个城市，`DELETE`删除一个城市）

您还可以允许额外的参数，例如允许对结果集进行分页，或者启用一些过滤，但我们现在关心的是设置路由。您可以在主文件中设置所有必要的路由，就像我们在迄今为止的简短示例中所做的那样，但是随着您开始添加更多的路由，需要一些组织来避免最终得到一个数千行长的主文件。

# 如何做到...

由于`Express`的帮助，我们不需要太多的代码，只需要两行新代码来启用我们的路由；查看以下代码：

```js
// Source file: src/routing.js

/* @flow */
"use strict";

const express = require("express");
const app = express();

const myRouter = require("./router_home.js");
app.use("/", myRouter);

// *eslint-disable-next-line no-unused-vars*
app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () =>
    console.log("Routing ready at http://localhost:8080")
);
```

`router_home.js`模块可以具有路由分支的第一级，如下面的代码所示：

```js
// Source file: src/router_home.js

/* @flow */
"use strict";

const express = require("express");
const routerHome = express.Router();

const routerCountries = require("./router_countries.js");
const routerRegions = require("./router_regions.js");
const routerCities = require("./router_cities.js");

routerHome.use("/countries", routerCountries);
routerHome.use("/regions", routerRegions);
routerHome.use("/cities", routerCities);

module.exports = routerHome;
```

而且，再往下一级，我们将有三个指定下一级的文件。例如，国家的路由将如下所示。您会注意到一个奇怪的额外路由`/URUGUAY`，我只是为了向您展示我们可以有比 RESTful 服务器需要的更多路由！

```js
// Source file: src/router_countries.js

/* @flow */
"use strict";

const express = require("express");
const routerCountries = express.Router();

routerCountries.get("/", (req, res) => {
    res.send(`All countries... path=${req.originalUrl}`);
});

routerCountries.get("/URUGUAY", (req, res) => {
 res.send(`GET UY (Uruguay)... path=${req.originalUrl}`);
});

routerCountries.get("/:country", (req, res) => {
    res.send(`GET Single country... ${req.params.country}`);
});

module.exports = routerCountries;
```

地区路由文件将如下所示，并且我们将跳过城市路由，因为它与国家路由非常相似：

```js
// Source file: src/router_regions.src

/* @flow */
"use strict";

const express = require("express");
const routerRegions = express.Router();

routerRegions.get("/", (req, res) => {
    res.send(`Region GET ALL... `);
});

routerRegions.get("/:country", (req, res) => {
    res.send(`Region GET ALL FOR Country=${req.params.country}`);
});

routerRegions.get("/:country/:id", (req, res) => {
    res.send(`Region GET ${req.params.country}/${req.params.id}`);
});

routerRegions.delete("/:country/:id", (req, res) => {
    res.send(`Region DELETE... ${req.params.country}/${req.params.id}`);
});

routerRegions.post("/", (req, res) => {
    res.send(`Region POST... `);
});

routerRegions.put("/:country/:id", (req, res) => {
    res.send(`Region PUT... ${req.params.country}/${req.params.id}`);
});

module.exports = routerRegions;
```

您可以在[`expressjs.com/en/starter/basic-routing.html`](https://expressjs.com/en/starter/basic-routing.html)和[`expressjs.com/en/guide/routing.html`](https://expressjs.com/en/guide/routing.html)上阅读更多关于`Express`路由的信息。

# 它是如何工作的...

当然，我们所谓的*RESTful 服务器*，至少目前来说，是一个彻头彻尾的笑话，因为它只返回固定的答案，什么都不做，但关键部分基本上都在这里。首先，让我们分析它的结构。当你写`app.use(somePath, aRouter)`时，这意味着所有以给定路径开头的路由都将由提供的路由接管，该路由将负责从给定路径开始的路由。首先，我们写一个从`/`开始的基本路由，然后按路径（`/countries`、`/regions`和`/cities`）拆分路由，为每个路径编写一个路由。这些后续的路由将深入到路径中，直到所有的路由都被映射出来。

要搞清楚：当服务器收到一个请求，比如`/regions/uy`，请求首先由我们的主路由（在`routing.js`）处理，然后传递给主页路由（`router_home.js`），再传递给最终路由（`router_regions.js`），最终在那里处理请求。

现在，让我们来看看路由本身。这里有两种路由：*常量*路由，比如`/countries`，和*变量*路由，比如`/regions/uy/4`，其中包括一些变化的项目，比如在这种情况下的`uy`和`4`。当你写一个路由，比如`/regions/:country/:id`，Express 会提取出变化的部分（这里是`:country`和`:id`），并将它们作为`req.params`对象的属性（`req.params.country`和`req.params.id`）提供，这样你就可以在逻辑中使用它们。

你也可以使用正则表达式来定义路径，但要记住这个笑话：一个程序员有一个问题；一个程序员决定使用正则表达式来解决它；一个程序员现在有*两个*问题。

因此，如果我们在前面的路径上实现一些请求，我们将看到功能路由；我们缺少的只是实际的 RESTful 代码来产生一些有用的结果，但我们将在本章后面讨论到这一点：

```js
> curl "http://127.0.0.1:8080/regions" 
Region GET ALL..

> curl "http://127.0.0.1:8080/regions/uy" 
Region GET ALL FOR Country=uy

> curl -X POST "http://127.0.0.1:8080/regions" 
Region POST... 

> curl -X PUT "http://127.0.0.1:8080/regions/uy/4" 
Region PUT... uy/4

```

当然，尝试一些不允许的方法会产生错误；尝试对`/regions`进行`DELETE`请求，你就会明白我的意思。我们现在知道如何进行任何类型的路由，但我们仍然必须能够接收 JSON 对象，如果需要的话允许 CORS，以及其他一些考虑，所以让我们继续努力，首先通过 HTTPS 启用安全连接。

# 实施安全连接

通过 HTTPS 发送数据而不是 HTTP 是一个很好的安全实践，如果你的服务器必须通过网络发送敏感的、安全的数据，那么这实际上是强制性的。通过与客户端浏览器建立加密连接，可以避免许多种类型的攻击，所以让我们看看如何使用`Node`和`Express`实现安全连接。

在这个示例中，我们将介绍如何启用 HTTPS，以使我们的服务器更加安全。

# 如何做到这一点...

我们想要启用 HTTPS 连接，所以我们需要做一些工作来安装我们需要的一切。

在这个安装过程中的第一步将是获得一个适当验证你拥有的网站的证书。购买它超出了本书的范围，所以让我们通过生成我们自己的自签名证书来解决这个问题——当然，这并不真正安全，但会让我们完成所有必要的配置！

假设我们想设置我们的`www.modernjsbook.com`网站。在 Linux 中工作，你可以通过执行以下命令并回答一些问题来创建必要的证书文件：

```js
openssl req -newkey rsa:4096 -nodes -keyout modernjsbook.key -out modernjsbook.csr openssl x509 -signkey modernjsbook.key -in modernjsbook.csr -req -days 366 -out modernjsbook.crt

```

做完这些之后，你将得到三个文件：一个**证书签名请求**（**CSR**），一个 KEY（私钥），和一个自签名证书（CRT）文件，如下；在现实生活中，一个**证书颁发机构**（**CA**）将是实际的签发者：

```js
> dir
-rw-r--r-- 1 fkereki users 1801 May 14 22:32 modernjsbook.crt
-rw-r--r-- 1 fkereki users 1651 May 14 22:31 modernjsbook.csr
-rw------- 1 fkereki users 3272 May 14 22:31 modernjsbook.key
```

现在，当您设置服务器时，您必须读取这些文件（这些文件应该存放在一个安全的只读目录中，以增加安全性），并将它们的内容作为选项传递。我们将使用`fs`模块来做到这一点，就像之前的例子一样，由于只有在服务器加载时才会读取文件，因此可以使用`fs.readFileSync()`。看一下以下代码：

```js
// Source file: src/https_server.js

/* @flow */
"use strict";

const express = require("express");
const app = express();
const https = require("https");

const fs = require("fs");
const path = require("path");

const keysPath = path.join(__dirname, "../../certificates");

const ca = fs.readFileSync(`${keysPath}/modernjsbook.csr`);
const cert = fs.readFileSync(`${keysPath}/modernjsbook.crt`);
const key = fs.readFileSync(`${keysPath}/modernjsbook.key`);

https.createServer({ ca, cert, key }, app).listen(8443);
```

为什么使用端口`8443`？原因与安全有关，我们在上一章的*检查 Node 设置*部分看到了原因；这与我们使用端口`8080`而不是端口`80`的原因相同。

# 它是如何工作的...

运行上述代码就足以使您的服务器获得加密连接。（当然，如果您使用自签名证书，最终用户将收到有关实际安全性缺失的警告，但您会获得有效的证书，不是吗？）我们可以在以下截图中看到这一结果——请记住，使用真正的证书，用户将不会收到有关您不安全网站的警报！

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/0fea9c51-8b9a-48c8-932e-25aba90d2bb0.png)

安装证书并使用 HTTPS 而不是 HTTP 会生成一个安全的服务器。

当然，由于我们自己制作了证书，Google Chrome 并不真的喜欢这个网站！

我们还可以通过运行*第二个*服务器来强制 HTTP 用户使用 HTTPS，这次使用 HTTP，并将所有流量重定向到我们的第一个安全服务器：

```js
// Source file: src/http_server.js

/* @flow */
"use strict";

const express = require("express");
const app = express();
const http = require("http");

http.createServer(app).listen(8080);

app.use((req, res, next) => {
    if (req.secure) {
        next();
    } else {
 res.redirect(
 `https://${req.headers.host.replace(/8080/, "8443")}${req.url}`
 );
    }
});
```

`Node`服务器只能监听一个端口，因此您需要将此服务器作为单独的实例运行。现在，如果您尝试使用 HTTP 访问服务器，将会自动重定向，这是一个很好的做法！

添加安全连接很简单；让我们继续处理更多安全方面的工作。

# 使用 Helmet 添加安全保障

`Express`是一个非常好的工具，可以构建您的 RESTful 服务器，或者提供任何其他类型的服务。然而，除非您采取一些额外的预防措施，Express 并不适用所有的安全最佳实践，这可能会使您的服务器失败。无论如何，还没有丧失一切，因为有一些软件包可以帮助您进行这些实践，`Helmet`（在[`helmetjs.github.io/`](https://helmetjs.github.io/)）是其中最好的之一。

不要认为`Helmet`——或者其他类似的软件包——是一种可以解决您可能出现的当前和未来安全问题的魔法解药！将其视为朝着正确方向迈出的一步，但您必须时刻关注可能的威胁和安全漏洞，并不要相信任何单一软件包可以管理一切。

# 如何做...

鉴于它与`Express`兼容，`Helmet`也是一个中间件。它的安装和设置相当容易，幸运的是。使用`npm`来处理第一部分：

```js
npm install helmet --save
```

让`Helmet`发挥作用只是在中间件堆栈的顶部添加它而已：

```js
const helmet = require("helmet");
app.use(helmet());
```

你已经准备好了！默认情况下，`Helmet`启用以下安全措施列表，所有这些措施都意味着向请求的响应中添加、更改或删除特定的标头。有关特定标头或选项的更多文档，请查看[`helmetjs.github.io/docs/`](https://helmetjs.github.io/docs)：

| **模块** | **效果** |
| --- | --- |
| `dnsPrefetchControl` | 将`X-DNS-Prefetch-Control`标头设置为禁用浏览器预取（在用户甚至点击链接之前完成的请求），以防止用户的隐私问题，他们可能看起来正在访问实际上并没有访问的页面([`helmetjs.github.io/docs/dns-prefetch-control`](https://helmetjs.github.io/docs/dns-prefetch-control))。 |
| `frameguard` | 将`X-Frame-Options`标头设置为防止页面显示在 iframe 中，从而避免一些可能导致您不知不觉点击隐藏链接的*点击劫持*攻击([`helmetjs.github.io/docs/frameguard/`](https://helmetjs.github.io/docs/frameguard/))。 |
| `hidePoweredBy ` | 移除`X-Powered-By`标头（如果存在），以便潜在的攻击者不会知道服务器的技术，使得针对漏洞的攻击和利用变得更加困难 ([`helmetjs.github.io/docs/hide-powered-by`](https://helmetjs.github.io/docs/hide-powered-by)) |
| `hsts ` | 设置`Strict-Transport-Security`标头，以便浏览器继续使用 HTTPS 而不是切换到不安全的 HTTP。 ([`helmetjs.github.io/docs/hsts/`](https://helmetjs.github.io/docs/hsts/)) |
| `ieNoOpen ` | 设置`X-Download-Options`标头，以防止旧版本的 Internet Explorer 在您的页面中下载不受信任的 HTML ([`helmetjs.github.io/docs/ienoopen`](https://helmetjs.github.io/docs/ienoopen))。 |
| `noSniff` | 设置`X-Content-Type-Options`标头，以防止浏览器尝试*嗅探*（猜测）下载文件的 MIME 类型，以禁用一些攻击 ([`helmetjs.github.io/docs/dont-sniff-mimetype`](https://helmetjs.github.io/docs/dont-sniff-mimetype))。 |
| `xssFilter` | 设置`X-XSS-Protection`标头，以禁用某些形式的**跨站脚本**（**XSS**）攻击，您可能会在点击链接时无意中在页面上运行 JS 代码 ([`helmetjs.github.io/docs/xss-filter`](https://helmetjs.github.io/docs/xss-filter))。 |

您还可以选择启用一些额外的选项，如果它们符合您的要求。有关如何执行此操作的说明，请查看 Helmet 的文档[`helmetjs.github.io/docs/`](https://helmetjs.github.io/docs/)：该软件包现在已更新到 3.12.0 版本，经常更新，简单的`npm install`可能不足以启用新功能。请查看以下表格：

| **模块** | **效果** |
| --- | --- |
| `contentSecurityPolicy`  | 允许您配置`Content-Security-Policy`标头，以指定允许在您的页面上的内容和它们可以从哪里下载 ([`helmetjs.github.io/docs/xss-filter`](https://helmetjs.github.io/docs/xss-filter))。 |
| `expectCt` | 允许您设置`Expect-CT`标头，要求**证书透明度**（**CT**），以检测可能无效的证书或授权机构 ([`helmetjs.github.io/docs/expect-ct/`](https://helmetjs.github.io/docs/expect-ct/))。 |
| `hpkp` | 允许您配置`Public-Key-Pins`标头，以防止一些可能的*中间人攻击*，通过检测可能受损的证书 ([`helmetjs.github.io/docs/hpkp/`](https://helmetjs.github.io/docs/hpkp/))。 |
| `noCache`  | 设置几个标头，以防止用户使用旧的缓存文件版本，尽管有更新版本可用，这些旧版本可能存在漏洞或错误 ([`helmetjs.github.io/docs/nocache/`](https://helmetjs.github.io/docs/nocache/))。 |
| `referrerPolicy`  | 允许您设置`Referrer-Policy`标头，以便浏览器隐藏请求来源的信息，避免一些可能的隐私问题 ([`helmetjs.github.io/docs/referrer-policy`](https://helmetjs.github.io/docs/referrer-policy))。 |

# 它是如何工作的...

关于使用`Helmet`没有更多要说的了。将其添加到中间件堆栈中，并配置要启用或禁用的内容，可能会根据文档中的详细说明提供一些选项，`Helmet`将简单地验证任何响应中包含的标头是否遵循我们在前一节中列出的安全注意事项。

让我们快速检查一下。如果您运行我们的`hello_world.js`服务器，那么[`localhost:8080/`](http://127.0.0.1:8080)的响应将包括以下标头：

```js
Connection: keep-alive
Content-Length: 27
Content-Type: text/html; charset=utf-8
Date: Wed, 16 May 2018 01:57:10 GMT
ETag: W/"1b-bpQ4Q2jOe/d4pXTjItXGP42U4V0"
X-Powered-By: Express
```

相同的结果，但是运行`helmet_world.js`，本质上是相同的代码，但添加了`Helmet`，将显示更多标头，如下面的粗体文本所示：

```js
Connection: keep-alive
Content-Length: 27
Content-Type: text/html; charset=utf-8
Date: Wed, 16 May 2018 01:58:50 GMT
ETag: W/"1b-bpQ4Q2jOe/d4pXTjItXGP42U4V0"
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
```

如果您逐个启用一些可选功能，您将获得更多标头，但是差异是明显的：我们成功地添加了一些安全控制，几乎没有编码！

与所有安全措施一样，有必要遵循 Helmet 的功能，以便您可能添加或删除一些新的中间件选项，并保护您的服务器免受新的威胁。

# 实施 CORS

每当浏览器从服务器请求某些资源时，都会应用一些验证规则。对于这些交互中的许多情况，这些交互只是请求信息，而不会尝试对服务器进行任何形式的更改，因此没有限制，请求总是被允许，如以下情况：

+   *CSS 样式*通过`<link rel="stylesheet">`标签进行请求

+   *图像*通过`<img>`标签进行请求

+   *JS 代码*通过`<script>`标签进行请求

+   *媒体*通过`<audio>`或`<media>`标签进行请求

对于其他类型的请求，**同源策略**或**单一源策略**（**SOP**）限制了只能发送到相同源的请求（意思是协议，如`http://`，主机名，如`modernjsbook.com`，和端口，如`:8080`），拒绝任何不匹配一个或多个源 URL 元素的其他请求。例如，所有 Ajax 请求都将被拒绝。

但是，如果您愿意接受来自一些或所有服务器的请求，您可以应用**跨源资源共享**（**CORS**）来启用此类请求。基本上，CORS 定义了一种交互样式，让服务器决定是否允许跨源请求；而不是阻止每个请求（如 SOP 所暗示的那样）或允许所有请求（这是一个巨大的安全漏洞！），可以应用规则来决定是这样还是那样。

如果您想阅读 CORS 的当前规范，请参阅[`fetch.spec.whatwg.org/`](https://fetch.spec.whatwg.org/)上的 Fetch Living Standard 文档，特别是第 3.2 节。关于 CORS 的一篇好文章可以在[`developer.mozilla.org/en-US/docs/Web/HTTP/CORS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)找到。

# 如何做...

让我们开始启用 CORS。基本上，这只是处理一些请求的问题，通过检查它们的头部数据并向浏览器发送一些其他头部数据，以便它知道可以期望什么。这种类型的过程非常容易通过应用中间件来解决，而且已经存在一个用于此目的的包（`cors`），可以通过以下代码轻松安装：

```js
 npm install cors --save
```

您可以为所有路由或仅为少数路由启用 CORS。第一种方式只需要两行代码（在下面的代码中用粗体标出），告诉`Express`在顶部应用中间件，适用于所有请求：

```js
// Source file: src/cors_server.js

/* @flow */
"use strict";

const express = require("express");
const app = express();

const cors = require("cors");
app.use(cors());

app.get("/", (req, res) => res.send("Server alive, with CORS!"));

app.listen(8080, () =>
    console.log("CORS server ready at http://localhost:8080/!")
);
```

您还可以专门为任何给定的路由启用它。从本章的前面选择一个示例，您可以指定尝试获取城市的 CORS；更改将是最小的：

```js
routerCities.get("/:id", cors(), (req, res) => {
    res.send(`GET City... ${req.params.id}`);
});
```

最后，一些请求需要进行*预检*，这意味着浏览器在发送实际请求之前，将发送一个`OPTIONS`请求来验证原始请求是否可以被接受。要启用此功能，您应该为任何路由启用 CORS，如以下示例中所示，或者在中间件堆栈的开头使用单个`app.options('*', cors())`行进行通用设置：

```js
routerCities.options("/:id", cors()); 
routerCities.delete("/:id", (req, res) => {
    res.send(`DELETE City... ${req.params.id}`);
});
```

# 它是如何工作的...

验证 CORS 是否已启用的最简单方法是使用`curl`或类似工具模拟来自不同来源的调用。（在接下来的章节中，当我们进行一些测试时，我们将看到更多这方面的内容。）我们可以通过编写一个小的网页来简化这个过程，该网页将进行跨域`GET`，添加一个虚拟标头以强制 CORS，并检查网络流量。我们的页面非常简单——完全没有花哨的东西！

```js
// Source file: src/cors_request.html

<html>
<head></head>
<body>
    <script type="text/javascript">
        const req = new XMLHttpRequest();
        req.open('GET', 'http://www.corsserver.com:8080/', true);
        req.onreadystatechange = () => {
            if (req.readyState === 4) {
                if (req.status >= 200 && req.status < 400) {
                    console.log(req.responseText)
                } else {
                    console.warn("Problems!")
                }
            }
        };
        req.setRequestHeader("dummy", "value");
        req.send();
    </script>
</body>
</html>
```

我们将在`www.corsserver.com:8080`上运行我们的 CORS 服务器（实际上我正在我的机器上黑客攻击`/etc/hosts`文件，以便服务器实际上在我的机器上），我们将使用 Web Server for Chrome 来加载和运行我们的页面。查看以下截图以查看执行此操作的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d38f9da2-1c3f-4e63-8beb-bc4706daf2ce.png)

执行简单的跨域 GET 显示我们的服务器收到了一个 OPTIONS 请求，然后是 GET 请求

使用 CORS 比其他替代方案更安全，包括老牌的 JSONP（一种跨域获取信息的方法），因此将其添加到服务器应该是强制性的。然而，正如我们所见，只需使用一点 Express 中间件就可以轻松实现。

# 使用 JWT 添加身份验证

对于任何基于服务器的应用程序，必须解决的一个挑战是身份验证，因此我们的 RESTful 服务器需要一个解决方案。在传统的网页中，可能会使用会话和 cookie，但是如果您使用 API，则无法保证请求来自浏览器；事实上，它们很可能来自另一个服务器。再加上 HTTP 是无状态的，RESTful 服务也应该是如此，我们需要另一种机制，**JSON Web Tokens**（**JWT**）是一个经常使用的解决方案。

JWT 有时被读作*JOT*；请参阅 RFC 的第一部分[`www.rfc-editor.org/info/rfc7519`](https://www.rfc-editor.org/info/rfc7519)。

JWT 的想法是，客户端将首先与服务器交换有效凭据（如用户名和密码），然后得到一个令牌，之后将允许他们访问服务器的资源。令牌是使用密码学方法创建的，比通常的密码要长得多，更加晦涩。但是，令牌足够小，可以作为请求体参数或 HTTP 头发送。

将令牌作为查询参数放在 URL 中是一种糟糕的安全实践！而且，考虑到令牌实际上不是请求的一部分，将其放在请求体中也不太合适，因此选择一个头部；推荐的是`Authorization: Bearer`。

获得令牌后，必须在每个 API 调用中提供它，并且服务器在继续之前将对其进行检查。令牌可能包含有关用户的所有信息，以便服务器无需再次查询数据库来重新验证请求。在这方面，令牌就像您在受限建筑物的前台获得的安全通行证；您必须向安全人员证明您的身份，但之后您只需出示通行证（将被识别和接受）就可以在建筑物内移动，而无需一遍又一遍地进行整个身份验证过程。

查看[`jwt.io/`](https://jwt.io/)，可以使用在线工具处理 JWT，还有关于令牌的大量信息。

我们不会深入讨论 JWT 的创建、格式等细节；如果您感兴趣，可以阅读文档，因为我们将使用库来处理所有这些细节。（我们可能只需记住令牌包括一个*有效载荷*，其中包含一些与客户端或令牌本身相关的*声明*，比如过期或发布日期，并且如果需要可能包含更多信息——但不包括秘密数据，因为令牌可以被读取。）

在这个示例中，让我们创建一个基本服务器，首先能够向有效用户发放 JWT，其次检查特定路由的 JWT 是否存在。

# 如何操作...

让我们看看如何添加身份验证。为了使用 JWT，我们将使用来自[`github.com/auth0/node-jsonwebtoken`](https://github.com/auth0/node-jsonwebtoken)的`jsonwebtoken`。使用以下命令安装它：

```js
npm install jsonwebtoken --save
```

我们的 JWT 代码示例将比以前的示例更大，并且应该分成多个文件。但是，为了使其更清晰，我避免了这样做。首先，我们需要做一些声明，关键行用粗体标出：

```js
// Source file: src/jwt_server.js

/* @flow */
"use strict";

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const validateUser = require("./validate_user.js");

const SECRET_JWT_KEY = "modernJSbook";

app.use(bodyParser.urlencoded({ extended: false }));
```

几乎所有内容都是标准的，除了`validateUser()`函数和`SECRET_JWT_KEY`字符串。后者将用于签署令牌，并且绝对不应该出现在代码本身中！（如果有人能够入侵源代码，你的秘密将会泄露；相反，将密钥设置为环境变量，并从那里获取值。）

至于函数，检查用户是否存在以及他们的密码是否正确是很简单的，可以通过许多方式实现，比如访问数据库、活动目录、服务等。在这里，我们只使用硬编码版本，只接受一个用户。然后，`validate_user.js`源代码非常简单：

```js
// Source file: src/validate_user.js

/* @flow */
"use strict";

/*
 *In real life, validateUser could check a database,*
 *look into an Active Directory, call another service,*
 *etc. -- but for this demo, let's keep it quite*
 *simple and only accept a single, hardcoded user.*
*/

const validateUser = (
    userName: string,
    password: string,
    callback: (?string, ?string) => void) => {
    if (!userName || !password) {
        callback("Missing user/password", null);
    } else if (userName === "fkereki" && password === "modernjsbook") {
        callback(null, "fkereki"); // OK, send userName back
    } else {
        callback("Not valid user", null);
    }
};

module.exports = validateUser;
```

让我们回到我们的服务器。在初始定义之后，我们可以放置不需要令牌的路由。让我们有一个`/public`路由，还有一个`/gettoken`路由用于获取稍后的 JWT。在后者中，我们将查看`POST`是否在其主体中包含`user`和`password`值，并且如果它们是有效用户，通过我们在前面的代码中展示的`validateUser()`函数。任何问题都意味着将发送`401`状态，而如果用户正确，将创建一个在一小时后过期的令牌：

```js
// Source file: src/jwt_server.js

app.get("/public", (req, res) => {
    res.send("the /public endpoint needs no token!");
});

app.post("/gettoken", (req, res) => {
    validateUser(req.body.user, req.body.password, (idErr, userid) => {
 if (idErr !== null) {
 res.status(401).send(idErr);
 } else {
 jwt.sign(
 { userid },
 SECRET_JWT_KEY,
 { algorithm: "HS256", expiresIn: "1h" },
 (err, token) => res.status(200).send(token)
 );
 }
    });
});
```

既然不受保护的路由已经处理完毕，让我们添加一些中间件来验证令牌是否存在。根据 JWT RFC 的预期，我们希望包括一个`Authorization: Bearer somejwttoken`标头，并且必须被接受。如果没有这样的标头，或者它的格式不正确，将发送 401 状态。如果令牌存在，但已过期或有任何其他问题，将发送 403 状态。最后，如果没有问题，`userid`字段将从有效载荷中提取，并附加到请求对象，以便将来的代码能够使用它：

```js
// Source file: src/jwt_server.js

app.use((req, res, next) => {
    // First check for the Authorization header
    const authHeader = req.headers.authorization;
 if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send("No token specified");
    }

    // Now validate the token itself
    const token = authHeader.split(" ")[1];
    jwt.verify(token, SECRET_JWT_KEY, (err, decoded) => {
        if (err) {
            // Token bad formed, or expired, or other problem
            return res.status(403).send("Token expired or not valid");
        } else {
            // Token OK; get the user id from it
            req.userid = decoded.userid;
            // Keep processing the request
            next();
        }
    });
});
```

现在，让我们添加一些受保护的路由（实际上，只有一个，`/private`，仅供本例使用），然后进行错误检查并设置整个服务器：

```js
// Source file: src/jwt_server.js app.get("/private", (req, res) => {
 res.send("the /private endpoint needs JWT, but it was provided: OK!");
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () =>
    console.log("Mini JWT server ready, at http://localhost:8080/!")
);
```

我们完成了！让我们看看这一切是如何结合在一起的。

# 它是如何工作的...

我们可以先测试`/public`和`/private`路由，不需要任何令牌。前者不会引起任何问题，但后者将被我们的令牌测试代码捕捉并拒绝：

```js
> curl "http://localhost:8080/public" 
the /public endpoint needs no token!

> curl "http://localhost:8080/private" 
No token specified

```

现在，让我们尝试获取一个令牌。查看以下代码：

```js
> curl http://localhost:8080/gettoken -X POST -d "user=fkereki&password=modernjsbook" 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI2ODM5MDEwLCJleHAiOjE1MjY4NDI2MTB9.cTwpL-x7kszn7C9OUXhHlkTGhb8Aa7oOGwNf_nhALCs

```

另一种测试方法是转到[`jwt.io/`](https://jwt.io/)并创建一个 JWT，在有效载荷中包括`userid:"fkereki"`，并使用`modernJSbook`作为密钥。不过，你需要自己计算到期日期(`exp`)。

在[`jwt.io`](https://jwt.io)上检查令牌显示以下有效载荷：

```js
{
  "userid": "fkereki",
  "iat": 1526839010,
  "exp": 1526842610
}
```

`iat`属性显示 JWT 是在 2018 年 5 月 20 日下午 2:00 左右发布的，`exp`属性显示令牌设置为一个小时（3,600 秒）后过期。如果我们现在重复对`/private`的 curl 请求，但添加适当的标头，它将被接受。但是，如果你等待（至少一个小时！），结果将不同；JWT 检查中间件将检测到过期的令牌，并产生 403 错误：

```js
> curl "http://localhost:8080/private" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI2ODM5MDEwLCJleHAiOjE1MjY4NDI2MTB9.cTwpL-x7kszn7C9OUXhHlkTGhb8Aa7oOGwNf_nhALCs"
the /private endpoint needs JWT, but it was provided: OK!

```

有了这段代码，我们现在有了一种在我们的 RESTful 服务器中添加身份验证的方法。如果你愿意，你可以进一步添加特定的授权规则，以便一些用户可以访问一些功能，而其他用户将受到限制。现在，让我们尝试将一切整合在一起，并构建一个小型的 REST 服务。

# 将所有内容绑在一起-构建一个 REST 服务器

在这个配方中，让我们至少写一个完整的 RESTful 服务器的部分，用于我们在上一章的“使用数据库”部分开始使用的世界数据库，根据我们在本章前面的“添加路由”部分看到的路由方案。我们将专注于处理地区，但仅仅是为了简洁起见；国家和城市在编码方面非常相似，完整的代码已经提供在本书中。

我们的 REST 服务将发送 JSON 答案并需要令牌进行授权。我们将启用 CORS，以便我们可以从不同的网页访问它们。我们将处理的路由如下：

+   `GET /regions`将提供所有国家的所有地区

+   `GET /regions/:country`将返回给定国家的所有地区

+   `GET /regions/:country/:region`将返回一个单独的地区

+   `DELETE /regions/:country/:region`将允许我们删除给定的地区

+   `POST /regions/:country`将允许我们创建一个新的地区

+   `PUT /regions/:country/:region`将允许我们创建或更新给定的地区

处理国家和城市是非常相似的，只有一两个例外：

+   由于结果集的大小，我们不会接受`GET` `/cities`请求来提供世界上所有的城市；只有`GET` `/cities/:city`将被允许。另一种选择是接受请求，但发送回`405`状态码，`方法不允许`。

+   由于国家代码不能随意分配，我们不允许`POST /countries`。相反，`PUT` `/countries/:country`将需要添加一个新的国家，以及更新现有的国家。

每种类型的请求将产生适当的 HTTP 状态代码；我们将在以下部分看到这一点。此外，`GET`请求将发送 JSON 结果，`POST`请求将发送新创建实体的位置；稍后会详细介绍。

# 如何做到...

让我们看看如何编写我们的服务器。我们将从一些基本代码开始，跳过我们之前看到的部分，比如 CORS 和 JWT 处理：

```js
// Source file: src/restful_server.js

/* @flow */
"use strict";
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const dbConn = require("./restful_db.js");
app.get("/", (req, res) => res.send("Secure server!"));

/*
    Add here the logic for CORS
*/

/*
    Add here the logic for providing a JWT at /gettoken
    and the logic for validating a JWT, as shown earlier
*/
```

处理路由是相当标准的。由于路由简单且少，我们可以将它们放在同一个源文件中；否则，我们将为不同的路由集设置单独的文件。路由的处理程序肯定会放在另一个文件（`"restful_regions.js"`）中，以免混淆主服务器代码。请注意，如果存在，国家和地区代码是 URL 的一部分；每当需要地区的名称时，它会放在主体参数中：

```js
// Source file: src/restful_server.js

const {
    getRegion,
    deleteRegion,
    postRegion,
    putRegion
} = require("./restful_regions.js");

app.get("/regions", (req, res) => getRegion(res, dbConn));

app.get("/regions/:country", (req, res) =>
    getRegion(res, dbConn, req.params.country)
);

app.get("/regions/:country/:region", (req, res) =>
    getRegion(res, dbConn, req.params.country, req.params.region)
);

app.delete("/regions/:country/:region", (req, res) =>
    deleteRegion(res, dbConn, req.params.country, req.params.region)
);

app.post("/regions/:country", (req, res) =>
    postRegion(res, dbConn, req.params.country, req.body.name)
);

app.put("/regions/:country/:region", (req, res) =>
    putRegion(
        res,
        dbConn,
        req.params.country,
        req.params.region,
        req.body.name
    )
);
```

最后，让我们看一些我们已经看到的代码，以完成服务器、错误处理和设置服务器本身：

```js
// Source file: src/restful_server.js

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("Error....", err.message);
    res.status(500).send("INTERNAL SERVER ERROR");
});

/*
   Add here the logic for HTTPS, finishing with: 

    https.createServer({ ca, cert, key }, app);
*/

app.listen(8080, () =>
    console.log("Routing ready at http://localhost:8080")
);
```

让我们继续看看它是如何工作的。我们将在下一节展示处理路由的代码。

# 它是如何工作的...

由于我们有四种请求，让我们适当地分割我们对服务器代码的研究。

# 处理 GET 请求

正如我们之前看到的，有三种可能的路由来处理：

+   `/regions`获取所有国家的所有地区

+   `/regions/UY`获取给定国家的所有地区-在这种情况下是乌拉圭（`UY`）

+   `/regions/UY/11`获取一个国家的特定地区-这里是乌拉圭的地区 11

我们可以通过改变我们将要执行的`SQL SELECT`来以类似的方式处理所有三种情况。然而，处理结果将需要一个特殊情况，正如我们将在下面的代码中注意到的：

```js
// Source file: src/restful_regions.js

const getRegion = async (
    res: any,
    dbConn: any,
    country: ?string,
    region: ?string
) => {
    try {
        res.set("Connection", "close");

        let sqlQuery = "";
        let regions;
        if (country == null) {
            sqlQuery = `
                SELECT rr.* 
                FROM regions rr 
                JOIN countries cc 
                ON cc.countryCode=rr.countryCode
                ORDER BY cc.countryCode, rr.regionCode
            `;
            regions = await dbConn.query(sqlQuery);
        } else if (region == null) {
            sqlQuery = `
                SELECT 1
                FROM countries
                WHERE countryCode=?
            `;

            const countries = await dbConn.query(sqlQuery, [country]);
            if (countries.length === 0) {
                res.status(404).send("Country not found");
                return;
            }

            sqlQuery = `
                SELECT rr.* 
                FROM regions rr 
                JOIN countries cc 
                ON cc.countryCode=rr.countryCode
                WHERE rr.countryCode=?
                ORDER BY rr.regionCode
            `;
            regions = await dbConn.query(sqlQuery, [country]);
        } else {
            sqlQuery = `
                SELECT rr.* 
                FROM regions rr 
                JOIN countries cc 
                ON cc.countryCode=rr.countryCode
                WHERE rr.countryCode=? 
                AND rr.regionCode=?
            `;
            regions = await dbConn.query(sqlQuery, [country, region]);
        }

        if (regions.length > 0 || region === null) {
            res.status(200)
                .set("Content-Type", "application/json")
                .send(JSON.stringify(regions));
        } else {
            res.status(404).send("Not found");
        }
    } catch (e) {
        res.status(500).send("Server error");
    }
};
```

在前面的代码中我们提到的特殊情况是请求类似于`/regions/XYZZY`，并提供了错误的国家代码。在这种情况下，我们可以发送`404`，而不是发送一个空集（这可能意味着该国家存在，因为它似乎没有任何地区），所以第二个`if`语句（提供了国家，但地区不存在）在继续之前进行了特殊检查。

我们可以通过几个示例看到这段代码的工作。不带进一步参数的`/regions`提供了一个相当大的输出（22 MB），因此可能需要添加参数以进行过滤或分页：

我从服务器中删除了 HTTPS、CORS，主要是 JWT 代码，以使示例更容易跟踪。这样做意味着我没有收到额外的标头，并且避免了在每次调用中提供 JWT。是的，我有点作弊，但随书提供的源代码包括所有内容，所以不用担心！

```js
> curl localhost:8080/regions/
[{"countryCode":"AD", "regionCode":"2", "regionName":"Canillo"}, {"countryCode":"AD", "regionCode":"3", "regionName":"Encamp"}, {"countryCode":"AD", "regionCode":"4", "regionName":"La Massana"},
.
.
.
{"countryCode":"ZW", "regionCode":"7", "regionName":"Matabeleland South"}, {"countryCode":"ZW", "regionCode":"8", "regionName":"Masvingo"}, {"countryCode":"ZW", "regionCode":"9", "regionName":"Bulawayo"}]
```

请求特定国家（例如`/regions/UY`）会产生一个与之前收到的答案非常相似的答案，但只包括国家`UY`（乌拉圭）的地区，对单个地区的请求会得到一个单一的对象：

```js
> curl localhost:8080/regions/uy/10 
[{"countryCode":"UY","regionCode":"10","regionName":"Montevideo"}]

```

最后，我们可以尝试一个错误；查看以下截图并注意 404 状态：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/28a633c1-96fa-402a-9210-15273201047a.png)

向我们的 RESTful 服务器请求不存在国家的地区会产生 404 错误

# 处理删除操作

删除一个地区很简单，只是必须事先检查地区是否有任何城市。我们可以通过实现级联删除来解决这个问题，这样当你删除一个地区时，它的所有城市也会被删除，或者我们可能会禁止删除。在我们的情况下，我选择了后者，但可以争论说前者也是有效的，并且不需要非常复杂的逻辑：

为什么我们要自己检查城市，而不是让数据库服务器使用外键来做呢？原因很简单：我想展示一些代码，它超出了一个单一的 SQL 语句。同样的论点也适用于级联删除，你可以用手工编写的 SQL 语句来实现，或者在数据库中设置特殊规则。并且，让我声明，对于实际的应用程序，让数据库来做这项工作实际上是更可取的！

```js
// Source file: src/restful_regions.js

const deleteRegion = async (
    res: any,
    dbConn: any,
    country: string,
    region: string
) => {
    try {
        res.set("Connection", "close");

        const sqlCities = `
            SELECT 1 FROM cities 
            WHERE countryCode=? 
            AND regionCode=? 
            LIMIT 1 
        `;
        const cities = await dbConn.query(sqlCities, [country, region]);
        if (cities.length > 0) {
            res.status(405).send("Cannot delete a region with cities");
            return;
        }

        const deleteRegion = `
                DELETE FROM regions 
                WHERE countryCode=? 
                AND regionCode=?
            `;

        const result = await dbConn.query(deleteRegion, [country, region]);
        if (result.info.affectedRows > 0) {
            res.status(204).send();
        } else {
            res.status(404).send("Region not found");
        }
    } catch (e) {
        res.status(500).send("Server error");
    }
};
```

我们可以以类似的方式进行测试。删除没有城市的地区是有效的，而试图对有城市的地区或不存在的地区进行删除是无效的：

```js
> curl localhost:8080/regions/uy/23 -X DELETE --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8080 (#0) 
> DELETE /regions/uy/23 HTTP/1.1 
*.* .
.
< HTTP/1.1 204 No Content

> curl localhost:8080/regions/uy/10 -X DELETE --verbose
* Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> DELETE /regions/uy/10 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.59.0
> Accept: */*
> 
< HTTP/1.1 405 Method Not Allowed
*.* .
.
Cannot delete a region with cities

> curl localhost:8080/regions/uy/99 --verbose
* Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /regions/uy/99 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.59.0
> Accept: */*
> 
< HTTP/1.1 404 Not Found
*.* .
.
Not found

```

查看可能返回的不同状态代码：

+   如果一个地区被删除没有问题，那么返回 204，并且在这种情况下，不会发送文本响应

+   如果请求的地区不存在，则返回 404

+   如果请求无法被接受（因为地区有城市），则返回 405

当然，你可以改变服务的工作方式，例如，如果提供了某个参数，可以提供级联删除操作，就像`http://some.server/regions/uy/23?cascade=true`。此外，对于一些服务，这个操作可能会在没有要求的情况下发生；用户可能有一组偏好，每当一个用户被删除时，你也应该删除他们的偏好。这将取决于服务的期望语义。

# 处理 PUT 请求

`PUT`请求意味着要更新一个现有资源。在我们的情况下，一个先决条件是指定的地区必须存在；否则，`404`错误是合适的。如果地区存在，那么我们可以更新它并发送`204`状态。如果`MySQL`检测到地区没有发生任何变化，它会让你知道`UPDATE`没有改变任何东西；你可以发送`204`（就像我选择的那样）或者`409`错误，但无论如何，你可以确定地区有你想要的数据。我们还需要进行一些参数检查；在这种情况下，只是为了确保给出了一个名称，但数据验证逻辑可能会更加复杂：

```js
// Source file: src/restful_regions.js

const putRegion = async (
    res: any,
    dbConn: any,
    country: string,
    region: string,
    name: string
) => {
    res.set("Connection", "close");

    if (!name) {
        res.status(400).send("Missing name");
        return;
    }

    try {
        const sqlUpdateRegion = `
            UPDATE regions
            SET regionName=?
            WHERE countryCode=? 
            AND regionCode=? 
        `;

        const result = await dbConn.query(sqlUpdateRegion, [
            name,
            country,
            region
        ]);

        if (result.info.affectedRows > 0) {
            res.status(204).send();
        } else {
            res.status(409).send("Region not updated");
        }
    } catch (e) {
        res.status(500).send("Server error");
    }
};
```

这很容易测试，因为只有两种情况（地区存在或不存在），再加上一个健全性检查，以防名称丢失。让我们首先添加缺失的波浪符号到一个地区；就像以前一样，由于 204 状态代码，不会收到任何内容：

```js
> curl localhost:8080/regions/uy/16 -X PUT -d "name=San Jose" --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8080 (#0) 
> PUT /regions/uy/16 HTTP/1.1 
.
.
.
< HTTP/1.1 204 No Content
```

这两种错误情况（不存在的地区，缺少名称）很快就会被处理。前一种情况是由`MySQL`检测到的，而后一种情况是由最初的`if`语句捕获的：

```js
> curl localhost:8080/regions/uy/xyzzy -X PUT -d "name=Colossal Cave" --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8080 (#0) 
> PUT /regions/uy/xyzzy HTTP/1.1 
*.* .
.
< HTTP/1.1 409 Conflict 
*.* .
.
Region not updated

> curl localhost:8080/regions/uy/10 -X PUT --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8080 (#0) 
> PUT /regions/uy/10 HTTP/1.1 
*.* .
.
< HTTP/1.1 400 Bad Request 
*.* .
.
Missing name

```

处理`PUT`请求只是最简单的情况；让我们通过仔细研究最复杂的请求，即`POST`，来完成对服务器的研究。

# 处理 POST 请求

最后，处理`POST`请求会更加复杂，因为您应该说明要向哪个集合（在这种情况下是一个国家）添加新资源，并且逻辑应该完成所有工作，包括分配一个 ID。这意味着我们的代码会更长，因为我们将添加查找未使用的区域代码的需求。还会有另一个区别：当资源被创建时，新资源的 URI 应该在`Location`头中返回，因此这将是另一个额外的要求。

最后，再次，我们将进行一些数据验证，就像`PUT`请求一样：

```js
// Source file: src/restful_regions.js

const postRegion = async (
    res: any,
    dbConn: any,
    country: string,
    name: string
) => {
    res.set("Connection", "close");

    if (!name) {
        res.status(400).send("Missing name");
        return;
    }

    try {
        const sqlCountry = `
            SELECT 1 
            FROM countries
            WHERE countryCode=? 
        `;
        const countries = await dbConn.query(sqlCountry, [country]);
        if (countries.length === 0) {
            res.status(403).send("Country must exist");
            return;
        }

        const sqlGetId = `
            SELECT MAX(CAST(regionCode AS INTEGER)) AS maxr 
            FROM regions
            WHERE countryCode=? 
        `;
        const regions = await dbConn.query(sqlGetId, [country]);
        const newId =
            regions.length === 0 ? 1 : 1 + Number(regions[0].maxr);

        const sqlAddRegion = `
            INSERT INTO regions SET 
            countryCode=?,
            regionCode=?,
            regionName=?
        `;

        const result = await dbConn.query(sqlAddRegion, [
            country,
            newId,
            name
        ]);
        if (result.info.affectedRows > 0) {
            res.status(201)
                .header("Location", `/regions/${country}/${newId}`)
                .send("Region created");
        } else {
            res.status(409).send("Region not created");
        }
    } catch (e) {
        res.status(500).send("Server error");
    }
};
```

这是需要最多查询的逻辑。我们必须（1）检查国家是否存在，（2）确定该国家的最大区域 ID，然后（3）插入新区域并向用户返回 201 状态。我们可以像对`PUT`做的那样测试这个，所以让我们看一个简单的案例：

```js
> curl localhost:8080/regions/ar -X POST -d "name=NEW REGION" --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8080 (#0) 
> POST /regions/ar HTTP/1.1 
*.
.
.*
< HTTP/1.1 201 Created 
< X-Powered-By: Express 
< Location: /regions/ar/25 
.
.
.
Region created

> curl localhost:8080/regions/ar/25 
[{"countryCode":"ar","regionCode":"25","regionName":"NEW REGION"}]
```

阿根廷有 24 个省，编号从 1 到 24 在`regions`表中，因此如果我们添加一个新的，它应该是#25，并且答案中的`Location`头证明了这一点。（我们只返回路由，没有服务器和端口，但我们可以很容易地添加这些数据。）进行`GET`确认`POST`成功。

# 还有更多...

我们已经使用`Express`建立了一个简单的 RESTful 服务器，但还有更多内容——足够写一本书！让我们通过快速浏览一些您可能想要考虑用于自己项目的想法和工具来结束本章。

# 接受 JSON 数据

在我们的示例中，我们使用了`POST`参数，但也可以接收、解析和处理 JSON 输入。（这可以使调用 REST 服务变得更容易，因为在前端很可能您可以轻松地生成一个带有所需请求参数的对象。）使用`express.json()`作为中间件，请求体将包括来自 JSON 参数的数据。

请访问[`expressjs.com/en/4x/api.html#express.json`](http://expressjs.com/en/4x/api.html#express.json)了解更多信息。

# 添加 PATCH 方法进行部分更新

PUT 方法使您更新完整的实体，但有时您只想影响一些字段，在这种情况下，您可以允许`PATCH`方法。`PATCH`类似于`PUT`，但允许您仅更新一些属性。添加对此方法的支持并不复杂，非常类似于`PUT`逻辑，因此您可以通过相对较少的额外编码提供更强大的服务器。

您可以在[`developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PATCH`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/PATCH)了解更多关于 PATCH 的信息，如果您关心其规范，可以在[`datatracker.ietf.org/doc/rfc5789/`](https://datatracker.ietf.org/doc/rfc5789/)找到。

# 使用 Restify 而不是 Express

虽然`Express`是一个非常受欢迎和广泛使用的软件包，可以用来构建任何类型的服务器，但如果您特别想要一个仅 REST 服务器而没有其他功能，您可以考虑使用其他软件包，比如`Restify`。这种改变的优势与软件包的定位有关，它提供了与`Express`类似的功能，但需要更少的代码来实现 RESTful 部署。`Restify`的一些知名用户是`npm`和 Netflix，但名单还要长得多。

您可以在[`restify.com/`](http://restify.com/)了解更多关于`Restify`的信息。

# 允许过滤、排序和分页

由于 REST 基本上是一种风格，而不是服务的规范，因此有一些方面没有规定，您可以在实现上有一些自由。三个常见的要求是*过滤*（这样您就不会得到所有实体，而只会得到满足某些条件的实体）、*排序*（使实体按某种顺序包含）和*分页*（因为一次显示数百或数千个实体是不切实际的）。当然，这三个要求彼此交互；如果您进行排序和过滤，那么分页应该适用于排序后的过滤数据。

所有这些要求都可以通过添加一些查询参数（或可能的标头）来处理，但您需要花一些时间来了解对您来说最佳的方式：

+   *过滤*可以使用格式进行指定，例如`filter=price[lt]220`，这将指定给定属性（`price`）必须小于（`lt`）某个值（`200`）。构建涉及逻辑运算符（如`and`、`or`和`not`）以及可选括号的更复杂表达式也可以完成，但这会导致服务器进行更复杂的解析和解释。

+   *排序*可以通过参数进行指定，例如`sortby=price,name`，首先按`price`排序，然后按`name`排序。您可以添加其他选项以允许升序或降序排序。

+   *分页*可以通过使用`limit`和`offset`参数来完成，其解释与 SQL `SELECT`语句中使用的相同（有关更多信息，请参见[`dev.mysql.com/doc/refman/8.0/en/select.html`](https://dev.mysql.com/doc/refman/8.0/en/select.html)），或者通过指定页面大小和页面编号。

将这些选项添加到您的 REST 服务器的处理中将使其更加强大，并使客户端能够发送更具体、优化的请求。您可能还需要另一个扩展功能；能够选择额外的相关实体，因此请继续阅读。

# 使用 GraphQL 而不是 REST

REST 服务是标准且易于使用的，但在您不仅需要单个实体，还需要一些相关实体时可能会带来一些开销；例如，您如何获取一个国家及其所有地区？根据我们当前的设计，您必须分别调用并自行连接结果，或者自行扩展您的路由。例如，您可以对`/regions/uy?include=cities`执行此操作，以便服务器将在`UY`的每个地区中添加一个包含其城市的数组。虽然这种解决方案可能适用于我们正在使用的这个小例子，但对于更大、更复杂的数据库，其中表之间以多种方式相关联，这可能很容易失控。

然而，还有另一种选择。`GraphQL`是由 Facebook 开发的数据查询语言，它允许您在客户端定义所需数据的结构；服务器将根据需要生成相应的数据。`GraphQL`允许您通过跟踪引用来构建复杂结构，并将其与最小延迟一起发送，从而在单个请求中获取许多相关资源。您还可以使用工具来帮助您定义数据模式和执行在线查询。

让我们来看一个非常简短的例子，取自 GraphQL 官方网站的文档，网址为[`graphql.org/learn/queries/`](http://graphql.org/learn/queries)。假设有一个*星球大战*电影数据库，您可以编写以下查询，想要获取一些电影中的英雄，以及每个英雄的姓名、出现在其中的电影列表和所有朋友的姓名：

```js
{
    leftComparison: hero(episode: EMPIRE) {
        ...comparisonFields
    }
    rightComparison: hero(episode: JEDI) {
        ...comparisonFields
    }
}

fragment comparisonFields on Character {
    name
    appearsIn
    friends {
        name
    }
}
```

这个查询的结果如下。请注意对象结构如何遵循您在查询中的规范，并且重复字段或外键访问都由`GraphQL`服务器解决，并在单个请求中完成。

```js
{
    data: {
        leftComparison: {
            name: "Luke Skywalker",
            appearsIn: ["NEWHOPE", "EMPIRE", "JEDI"],
            friends: [
                {
                    name: "Han Solo"
                },
                {
                    name: "Leia Organa"
                },
                {
                    name: "C-3PO"
                },
                {
                    name: "R2-D2"
                }
            ]
        },
        rightComparison: {
            name: "R2-D2",
            appearsIn: ["NEWHOPE", "EMPIRE", "JEDI"],
            friends: [
                {
                    name: "Luke Skywalker"
                },
                {
                    name: "Han Solo"
                },
                {
                    name: "Leia Organa"
                }
            ]
        }
    }
}
```

虽然这超出了本章的范围（毕竟我们想要一个符合 REST 原则的服务器），但`GraphQL`是一个非常有效的选择，适用于需要处理复杂的、链接的结构的应用程序，否则这些结构需要太多的处理和通信时间。

要了解有关`GraphQL`的更多信息，请访问官方网站[`graphql.org/`](https://graphql.org/)。

# 实施基于微服务的架构

现在，通过遵循本章的结构，您可以开发一个服务器，从而在 SOA 中工作可能会演变为一个微服务组织，其中服务器不再是一个可以提供多个服务的单片代码，而是作为一组不同的迷你服务器组织，它们之间松散耦合，通过轻量级协议连接，每个服务器都有单一的责任。服务可以由不同的团队创建，甚至可以使用不同的语言或库，只需依赖于遵循给定接口，以便其他服务可以根据需要自由地与它们交互。

这种基于独立较小组件的结构极大地有助于可伸缩性、模块化，甚至开发和测试。如果需要进行更改，其影响将更小，而诸如持续交付和部署等策略也变得可行。开发微服务本身很容易完成，而进行此操作所需的技术主要是本章中所见的技术。只需将一个微服务器的请求添加到另一个微服务器以收集所有所需的信息即可。

关于基于微服务架构的好处，一些很好的起点是 Martin Fowler 在[`martinfowler.com/microservices/`](https://martinfowler.com/microservices/)上的文章，以及 Chris Richardson 在[`microservices.io/patterns/microservices.html`](http://microservices.io/patterns/microservices.html)上的文章。
