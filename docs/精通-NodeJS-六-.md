# 精通 NodeJS（六）

> 原文：[`zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40`](https://zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：将工作组织成模块

“复杂性必须从已经工作的简单系统中增长。”

– 凯文·凯利，“失控”

Node 的简单模块管理系统鼓励开发可持续增长和可维护的代码库。Node 开发人员有幸拥有一个丰富的生态系统，其中包含了清晰定义的具有一致接口的软件包，易于组合，并通过 npm 交付。在开发解决方案时，Node 开发人员会发现许多他们需要的功能片段已经准备就绪，并且可以迅速将这些开源模块组合成更大的、但仍然一致和可预测的系统。Node 的简单且可扩展的模块架构使得 Node 生态系统迅速增长。

在本章中，我们将介绍 Node 如何理解模块和模块路径的细节，如何定义模块，如何在 npm 软件包存储库中使用模块，以及如何创建和共享新的 npm 模块。通过遵循一些简单的规则，您会发现很容易塑造应用程序的结构，并帮助他人使用您创建的内容。

*模块*和*软件包*将被互换使用，以描述由`require()`编译和返回的文件或文件集合。

# 如何加载和使用模块

在我们开始之前，看一下这三个命令：

```js
$ node --version
v8.1.2 $ npm --version
5.5.1 $ npm install npm@latest -g
```

要安装 Node，您可能会在您喜欢的网络浏览器中导航到[`nodejs.org/en/`](https://nodejs.org/en/)，下载适合您操作系统的安装程序应用，并点击一些确定按钮。当您这样做时，您也会得到 npm。然而，npm 经常更新，所以即使您最近更新了 Node，您可能没有最新版本的 npm。

此外，下载和安装新的 Node 安装程序将更新 Node，但并不总是更新 npm，因此使用`npm install npm@latest -g`来确保您拥有最新版本。

Node 的设计者认为，大多数模块应该由开发人员在用户空间开发。因此，他们努力限制标准库的增长。在撰写本文时，Node 的标准模块库包含以下简短的模块列表：

| **网络和 I/O** | **字符串和缓冲区** | **实用工具** |
| --- | --- | --- |

| TTY UDP/Datagram

HTTP

HTTPS

Net

DNS

TLS/SSL

Readline

FileSystem | Path Buffer

Url

StringDecoder

QueryString | Utilities VM

Readline

Domain

Console

Assert |

| **加密和压缩** | **环境** | **事件和流** |
| --- | --- | --- |

| ZLIB Crypto

PunyCode | Process OS

模块 | 子进程集群

Events

Stream |

模块是通过全局的`require`语句加载的，它接受模块名称或路径作为单个参数。作为 Node 开发人员，您被鼓励通过创建新模块或自己的模块组合来增强模块生态系统，并与世界分享它们。

模块系统本身是在 require（`module`）模块中实现的。

# 模块对象

一个 Node 模块只是一个 Javascript 文件。将可能对外部代码有用的函数（以及其他任何东西）引用到 exports 中，如下所示：

```js
// library1.js
function function1a() {
  return "hello from 1a";
}
exports.function1a = function1a;
```

我们现在有一个可以被另一个文件所需的模块。回到我们的主应用程序，让我们使用它：

```js
// app.js
const library1 = require('./library1'); // Require it
const function1a = library1.function1a; // Unpack it
let s = function1a(); // Use it
console.log(s);
```

请注意，不需要使用`.js`后缀。我们将很快讨论 Node 如何解析路径。

让我们将我们的库变得更大一点，扩展到三个函数，如下所示：

```js
// library1.js
exports.function1a = () => "hello from 1a";
exports.function1b = () => "hello from 1b";
exports.function1c = () => "hello from 1c";

// app.js
const {function1a, function1b, function1c} = require('./library1'); // Require and unpack
console.log(function1a());
console.log(function1b());
console.log(function1c());
```

解构赋值，随着 ES6 引入到 JavaScript 中，是一种很好的方式，可以在一行代码中将许多由所需模块导出的函数分配给它们的本地变量。

# 模块、导出和 module.exports

当您检查 Node 模块的代码时，您可能会看到一些模块使用`module.exports`导出它们的功能，而其他模块则简单地使用`exports`：

```js
module.exports.foo = 'bar';
// vs...
exports.foo = 'bar';
```

有区别吗？简短的答案是否定的。在构建代码时，你可以大多数情况下将属性分配给任何一个。上面提到的两种方法都会“做”同样的事情--导出模块的属性'foo'在两种情况下都将解析为'bar'。

更长的答案是它们之间存在微妙的差异，与 JavaScript 引用工作方式有关。考虑模块首先是如何包装的：

```js
// https://github.com/nodejs/node/blob/master/lib/module.js#L92
Module.wrap = function(script) {
    return Module.wrapper[0] + script + Module.wrapper[1];
};

Module.wrapper = [
    '(function (exports, require, module, __filename, __dirname) { ',
    '\n});'
];
```

创建模块时，它将使用上述代码进行包装。这就是如何将 __dirname 和当然 exports 的“全局变量”注入到您的执行范围中的脚本（内容）中的方式：

```js
// https://github.com/nodejs/node/blob/master/lib/module.js#L625
var wrapper = Module.wrap(content);

var compiledWrapper = vm.runInThisContext(wrapper, {
    filename: filename,
    lineOffset: 0,
    displayErrors: true
});

...
result = compiledWrapper.call(this.exports, this.exports, require, this, filename, dirname);
```

回想一下第十章中关于`vm`上下文的讨论，*测试您的应用程序*？`Module`构造函数本身演示了`exports`只是`Module`对象上的一个空对象文字：

```js
// https://github.com/nodejs/node/blob/master/lib/module.js#L70
function Module(id, parent) {
    this.id = id;
    this.exports = {};
    this.parent = parent;
    updateChildren(parent, this, false);
    this.filename = null;
    this.loaded = false;
    this.children = [];
}
```

总结一下，在最终编译中，`module.exports`包含的内容将被返回给`require`：

```js
// https://github.com/nodejs/node/blob/master/lib/module.js#L500
var module = new Module(filename, parent);
...
Module._cache[filename] = module;
...
return module.exports;
```

总之，当您创建一个模块时，实质上是在定义其在此上下文中的导出：

```js
var module = { exports: {} };
var exports = module.exports;
// ...your code, which can apply to either
```

因此，`exports`只是对`module.exports`的引用，这就是为什么在`exports`对象上设置 foo 与在`module.exports`上设置 foo 是相同的。但是，*如果您将`exports`设置为其他内容*，`module.exports`将**不会**反映出这种变化：

```js
function MyClass() {
    this.foo = 'bar';
}

// require('thismodule').foo will be 'bar'
module.exports = new MyClass();

// require('thismodule').foo will be undefined
exports = new MyClass();
```

正如我们在上面看到的，只有`module.exports`被返回；`exports`从未被返回。如果`exports`覆盖了对`module.exports`的引用，那么该值永远不会逃离编译上下文。为了安全起见，只需使用`module.exports`。

Node 的核心模块也是使用标准的`module.exports`模式定义的。您可以通过浏览定义控制台的源代码来查看这一点：[`github.com/nodejs/node/blob/master/lib/console.js`](https://github.com/nodejs/node/blob/master/lib/console.js)。

# 模块和缓存

一旦加载，模块将被缓存。模块是基于其解析后的文件名缓存的，相对于调用模块进行解析。对 require（`./myModule`）的后续调用将返回相同的（缓存的）对象。

为了证明这一点，假设我们有三个（在这种情况下设计不佳的）模块，每个模块都需要另外两个模块：

```js
// library1.js
console.log("library 1 -\\");
const {function2a, function2b, function2c} = require('./library2');
const {function3a, function3b, function3c} = require('./library3');
exports.function1a = () => "hello from 1a";
exports.function1b = () => "hello from 1b";
exports.function1c = () => "hello from 1c";
console.log("library 1 -/");
```

```js
// library2.js
console.log("library 2 --\\");
const {function1a, function1b, function1c} = require('./library1');
const {function3a, function3b, function3c} = require('./library3');
exports.function2a = () => "hello from 2a";
exports.function2b = () => "hello from 2b";
exports.function2c = () => "hello from 2c";
console.log("library 2 --/");
```

```js
// library3.js
console.log("library 3 ---\\");
const {function1a, function1b, function1c} = require('./library1');
const {function2a, function2b, function2c} = require('./library2');
exports.function3a = () => "hello from 3a";
exports.function3b = () => "hello from 3b";
exports.function3c = () => "hello from 3c";
console.log("library 3 ---/");
```

如果没有缓存，需要其中任何一个将导致无限循环。但是，由于 Node 不会重新运行已加载（或当前正在加载）的模块，所以一切正常：

```js
$ node library1.js
library 1 -\
library 2 --\
library 3 ---\
library 3 ---/
library 2 --/
library 1 -/

$ node library2.js
library 2 --\
library 1 -\
library 3 ---\
library 3 ---/
library 1 -/
library 2 --/

$ node library3.js
library 3 ---\
library 1 -\
library 2 --\
library 2 --/
library 1 -/
library 3 ---/
```

但是，请注意，通过不同的相对路径（例如`../../myModule`）访问相同的模块将返回不同的对象；可以将缓存视为由相对模块路径键入。

可以通过`require('module')._cache`获取当前缓存的快照。让我们来看一下：

```js
// app.js
const u = require('util');
const m = require('module');
console.log(u.inspect(m._cache));
const library1 = require('./library1');
console.log("and again, after bringing in library1:")
console.log(u.inspect(m._cache));

{
  'C:\code\example\app.js': Module {
    id: '.',
    exports: {},
    parent: null,
    filename: 'C:\\code\\example\\app.js',
    loaded: false,
    children: [],
    paths:
    [ 'C:\\code\\example\\node_modules',
      'C:\\code\\node_modules',
      'C:\\node_modules' ]
  }
}

and again, after bringing in library1:

{ 
  'C:\code\example\app.js': Module {
    id: '.',
    exports: {},
    parent: null,
    filename: 'C:\\code\\example\\app.js',
    loaded: false,
    children: [ [Object] ],
    paths: [ 
      'C:\\code\\example\\node_modules',
      'C:\\code\\node_modules',
      'C:\\node_modules' 
    ] 
  },
  'C:\code\example\library1.js': Module {
    id: 'C:\\code\\example\\library1.js',
    exports: { 
      function1a: [Function],
      function1b: [Function],
      function1c: [Function] 
    },
    parent: Module {
      id: '.',
      exports: {},
      parent: null,
      filename: 'C:\\code\\example\\app.js',
      loaded: false,
      children: [Array],
      paths: [Array] 
    },
    filename: 'C:\\code\\example\\library1.js',
    loaded: true,
    children: [],
    paths: [ 
      'C:\\code\\example\\node_modules',
      'C:\\code\\node_modules',
      'C:\\node_modules' 
    ] 
  }
}
```

模块对象本身包含几个有用的可读属性：

+   `module.filename`：定义此模块的文件名。您可以在前面的代码块中看到这些路径。

+   `module.loaded`：模块是否正在加载过程中。如果加载完成，则为布尔值 true。在前面的代码中，library1 已经加载完成（true），而 app 仍在加载中（false）。

+   `module.parent`：需要此模块的模块（如果有）。您可以看到 library1 是如何知道 app 需要它的。

+   `module.children`：此模块所需的模块（如果有）。

您可以通过检查`require.main === module`来确定模块是直接执行的（通过`node module.js`）还是通过`require('./module.js')`，在前一种情况下将返回 true。

# Node 如何处理模块路径

由于模块化应用程序组合是 Node 的方式，您经常会看到（并使用）require 语句。您可能已经注意到，传递给 require 的参数可以采用许多形式，例如核心模块的名称或文件路径。

以下伪代码摘自 Node 文档，按顺序描述了解析模块路径时所采取的步骤：

```js
// require(X) from module at path Y
REQUIRE(X) 
  1\. If X is a core module,
    a. return the core module
    b. STOP
  2\. If X begins with '/'
    a. set Y to be the filesystem root
  3\. If X begins with './' or '/' or '../'
    a. LOAD_AS_FILE(Y + X)
    b. LOAD_AS_DIRECTORY(Y + X)
  4\. LOAD_NODE_MODULES(X, dirname(Y))
  5\. THROW "not found"
LOAD_AS_FILE(X)
  1\. If X is a file, load X as JavaScript text. STOP
  2\. If X.js is a file, load X.js as JavaScript text. STOP
  3\. If X.json is a file, parse X.json to a JavaScript Object. STOP
  4\. If X.node is a file, load X.node as binary addon. STOP
LOAD_INDEX(X)
  1\. If X/index.js is a file, load X/index.js as JavaScript text. STOP
  2\. If X/index.json is a file, parse X/index.json to a JavaScript Object. STOP
  3\. If X/index.node is a file, load X/index.node as a binary addon. STOP
LOAD_AS_DIRECTORY(X)
  1\. If X/package.json is a file,
    a. Parse X/package.json, and look for "main" field.
    b. let M = X + ("main" field)
    c. LOAD_AS_FILE(M)
    d. LOAD_INDEX(M)
  2\. LOAD_INDEX(X)
LOAD_NODE_MODULES(X, START)
  1\. let DIRS=NODE_MODULES_PATHS(START)
  2\. for each DIR in DIRS:
    a. LOAD_AS_FILE(DIR/X)
    b. LOAD_AS_DIRECTORY(DIR/X)
NODE_MODULES_PATHS(START)
  1\. let PARTS = path split(START)
  2\. let I = count of PARTS - 1
  3\. let DIRS = []
  4\. while I >= 0,
    a. if PARTS[I] = "node_modules" CONTINUE
    b. DIR = path join(PARTS[0 .. I] + "node_modules")
    c. DIRS = DIRS + DIR
    d. let I = I - 1
  5\. return DIRS
```

文件路径可以是绝对的或相对的。请注意，本地相对路径不会被隐式解析，必须声明。例如，如果你想要从当前目录中要求`myModule.js`文件，至少需要在文件名前加上`./`；`– require('myModule.js')`将不起作用。Node 将假定你要么引用一个核心模块，要么引用`./node_modules`文件夹中的模块。如果两者都不存在，将抛出一个`MODULE_NOT_FOUND`错误。

如前面的伪代码所示，这个`node_modules`查找会从调用模块或文件的解析路径开始向上查找目录树。例如，如果位于`/user/home/sandro/project.js`的文件调用了`require('library.js')`，Node 将按照以下顺序寻找：

```js
/user/home/sandro/node_modules/library.js
/user/home/node_modules/library.js
/user/node_modules/library.js
/node_modules/library.js
```

将文件和/或模块组织到目录中总是一个好主意。有用的是，Node 允许通过它们所在的文件夹的两种方式来引用模块。给定一个目录，Node 首先会尝试在该目录中找到一个`package.json`文件，或者寻找一个`index.js`文件。我们将在下一节讨论`package.json`文件的使用。在这里，我们只需要指出，如果 require 传递了`./myModule`目录，它将寻找`./myModule/index.js`。

如果你设置了`NODE_PATH`环境变量，那么 Node 将使用该路径信息来进行进一步搜索，如果通过正常渠道找不到请求的模块。出于历史原因，还将搜索`$HOME/.node_modules`、`$HOME/.node_libraries`和`$PREFIX/lib/node`。`$HOME`代表用户的主目录，`$PREFIX`通常是 Node 安装的位置。

# 创建一个包文件

正如在讨论 Node 如何进行路径查找时提到的，模块可能包含在一个文件夹中。如果你正在开发一个适合作为别人使用的模块的程序，你应该将该模块组织在它自己的文件夹中，并在该文件夹中创建一个`package.json`文件。

正如我们在本书的示例中所看到的，`package.json`文件描述了一个模块，有用地记录了模块的名称、版本号、依赖关系等。如果你想通过 npm 发布你的包，它必须存在。在本节中，我们将仅概述该文件的一些关键属性，并对一些不常见的属性提供更多详细信息。

尝试`$ npm help json`以获取所有可用 package.json 字段的详细文档，或访问：[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)。

`package.json`文件必须符合 JSON 规范。属性和值必须用双引号引起来，例如。

# 简单初始化

你可以手动创建一个包文件，或者使用方便的`$ npm init`命令行工具，它会询问一些问题并为你生成一个`package.json`文件。让我们来看看其中的一些：

+   **名称**：（必需）这个字符串将被传递给`require()`，以加载你的模块。让它简短和描述性，只使用字母数字字符；这个名称将被用在 URL、命令行参数和文件夹名称中。尽量避免在名称中使用`js`或`node`。

+   **版本**：（必需）npm 使用语义化版本，以下都是有效的：

+   >=1.0.2 <2.1.2

+   2.1.x

+   ~1.2

有关版本号的更多信息，请访问：[`docs.npmjs.com/misc/semver`](https://docs.npmjs.com/misc/semver)。

+   **描述**：当人们在`npmjs.org`上搜索包时，他们将会读到这个。让它简短和描述性。

+   **入口点**（主要）：这是应该设置`module.exports`的文件；它定义了模块对象定义的位置。

+   **关键字**：一个逗号分隔的关键字列表，将帮助其他人在注册表中找到你的模块。

+   **许可证**：Node 是一个喜欢宽松许可证的开放社区。*MIT*和*BSD*在这里都是不错的选择。

您可能还希望在开发模块时将`private`字段设置为`true`。这样可以确保 npm 拒绝发布它，避免意外发布尚未完善或时间敏感的代码。

# 向 package.json 添加脚本

另一个优势是 npm 也可以用作构建工具。包文件中的`scripts`字段允许您设置在某些 npm 命令后执行的各种构建指令。例如，您可能希望最小化 Javascript，或执行一些其他构建依赖项的过程，每当执行`npm install`时，您的模块都需要。可用的指令如下：

+   `prepublish`，`publish`，`postpublish`：通过`npm publish`命令以及在本地`npm install`命令中没有任何参数时运行。

+   `prepublishOnly`：在`npm publish`命令上发布之前运行。

+   `prepare`：在包发布之前和在`npm install`命令中没有任何参数的情况下运行。在`prepublish`之后但在`prepublishOnly`之前运行。

+   `prepack`：在通过`npm pack`或`npm publish`打包 tarball 之前运行，并在安装 git 依赖项时运行。

+   `postpack`：在 tarball 生成并移动到其最终位置后运行。

+   `preinstall`，`install`，`postinstall`：通过`npm install`命令运行。

+   `preuninstall`，`uninstall`，`postuninstall`：通过`npm uninstall`命令运行。

+   `preversion`，`version`，`postversion`：通过`npm version`命令运行。

+   `preshrinkwrap`，`shrinkwrap`，`postshrinkwrap`：通过`npm shrinkwrap`命令运行。

+   `pretest`，`test`，`posttest`：通过`npm test`命令运行。

+   `prestop`，`stop`，`poststop`：通过`npm stop`命令运行。

+   `prestart`，`start`，`poststart`：通过`npm start`命令运行。

+   `prerestart`，`restart`，`postrestart`：通过`npm restart`命令运行。请注意，如果没有提供`restart`脚本，`npm restart`将运行`stop`和`start`脚本。

应该清楚的是，pre-命令将在其主要命令（如`publish`）执行之前运行，而 post-命令将在其主要命令执行之后运行。

# npm 作为一个使用自定义脚本的构建系统

您不仅限于仅使用此预定义的默认脚本命令包。在包文件中扩展脚本集合，例如构建说明，是一种非常常见的做法。考虑以下脚本定义：

```js
"dev": "NODE_ENV=development node --inspect --expose-gc index.js"
```

当通过`npm run dev`命令运行此命令时，我们以调试模式（--inspect）启动一个假设的服务器，并公开垃圾收集器，以便我们可以跟踪其对我们应用程序性能的影响。

这也意味着 npm 脚本在许多情况下可以完全替代更复杂的构建系统，如**gulp**或**webpack**。例如，您可能希望使用**Browserify**来捆绑您的应用程序以进行部署，而该构建步骤很容易在脚本中描述：

```js
"scripts" : {
  "build:browserify" : "browserify -t [babelify --presets [react]] src/js/index.js -o build/app.js"
}
```

执行`npm run build:browserify`后，Browserify 将处理 src/js/index.js 文件，通过一个可以编译 React 代码（**babelify**）的转换器（-t）运行它，并将结果输出（-o）到 build/app.js。

此外，npm 脚本在 npm 的主机系统上运行，因此您可以执行系统命令并访问本地安装的模块。您可能要实现的另一个构建步骤是 JavaScript 文件的最小化，并将编译后的文件移动到目标文件夹：

```js
"build:minify": "mkdir -p dist/js uglify src/js/**/*.js > dist/js/script.min.js"
```

在这里，我们使用 OS 命令 mkdir 创建编译文件的目标文件夹，在一个文件夹中对所有 JavaScript 文件执行最小化（本地安装的）**uglify**模块，并将结果的最小化脚本捆绑重定向到一个单独的构建文件。

现在我们可以向我们的脚本集合添加一个通用的构建命令，并在需要部署新构建时简单地使用`npm run build`：

```js
"build": "npm run build:minify && npm run build:browserify"
```

可以以这种方式链接任意数量的步骤。您可以添加测试，运行文件监视器等。

对于您的下一个项目，考虑使用 npm 作为构建系统，而不是用大型和抽象的系统来复杂化您的堆栈，当它们出现问题时很难调试。例如，公司**Mapbox**使用 npm 脚本来管理复杂的构建/测试流水线：[`github.com/mapbox/mapbox-gl-js/blob/master/package.json`](https://github.com/mapbox/mapbox-gl-js/blob/master/package.json)。

# 注册包依赖项

很可能一个给定的模块本身会依赖于其他模块。这些依赖关系在`package.json`文件中使用四个相关属性声明：

+   `dependencies`：您的模块的核心依赖应该驻留在这里。

+   `devDependencies`：在开发模块时，您可能依赖于一些对于将来使用它的人来说并不必要的模块。通常测试套件会包含在这里。这将为使用您的模块的人节省一些空间。

+   `bundledDependencies`：Node 正在迅速变化，npm 包也在变化。您可能希望将一定的依赖包锁定到一个单独的捆绑文件中，并将其与您的包一起发布，以便它们不会通过正常的`npm update`过程发生变化。

+   `optionalDependencies`：包含可选的模块。如果找不到或安装不了这些模块，构建过程不会停止（与其他依赖加载失败时会停止的情况不同）。然后您可以在应用程序代码中检查此模块的存在。

依赖通常使用 npm 包名称定义，后面跟着版本信息：

```js
"dependencies" : {
  "express" : "3.3.5"
}
```

但是，它们也可以指向一个 tarball：

```js
"foo" : "http://foo.com/foo.tar.gz"
```

您可以指向一个 GitHub 存储库：

```js
"herder": "git://github.com/sandro-pasquali/herder.git#master"
```

它们甚至可以指向快捷方式：

```js
"herder": "sandro-pasquali/herder"
```

这些 GitHub 路径也可用于`npm install`，例如，`npm install sandro-pasquali/herder`。

此外，在只有具有适当身份验证的人才能安装模块的情况下，可以使用以下格式来获取安全存储库：

```js
"dependencies": {
  "a-private-repo":
    "git+ssh://git@github.com:user/repo.git#master"
}
```

通过按类型正确组织您的依赖项，并智能地获取这些依赖项，使用 Node 的包系统应该很容易满足构建需求。

# 发布和管理 NPM 包

当您安装 Node 时，npm 会被自动安装，并且它作为 Node 社区的主要包管理器。让我们学习如何在 npm 存储库上设置帐户，发布（和取消发布）模块，并使用 GitHub 作为替代源目标。

为了发布到 npm，您需要创建一个用户；`npm adduser`将触发一系列提示，要求您的姓名、电子邮件和密码。然后您可以在多台机器上使用此命令来授权相同的用户帐户。

要重置您的 npm 密码，请访问：[`npmjs.org/forgot`](https://npmjs.org/forgot)。

一旦您通过 npm 进行了身份验证，您就可以使用`npm publish`命令发布您的包。最简单的方法是从您的包文件夹内运行此命令。您也可以将另一个文件夹作为发布目标（记住该文件夹中必须存在`package.json`文件）。

您还可以发布一个包含正确配置的包文件夹的 gzipped tar 归档文件。

请注意，如果当前`package.json`文件的`version`字段低于或等于现有已发布包的版本，npm 会抱怨并拒绝发布。您可以使用`--force`参数与`publish`来覆盖此行为，但您可能希望更新版本并重新发布。

要删除一个包，请使用`npm unpublish <name>[@<version>]`。请注意，一旦一个包被发布，其他开发人员可能会依赖于它。因此，强烈建议您不要删除其他人正在使用的包。如果您想要阻止某个版本的使用，请使用 npm deprecate `<name>[@<version>] <message>`。

为了进一步协助协作，npm 允许为一个包设置多个所有者：

+   `npm owner ls <package name>`：列出对模块具有访问权限的用户

+   `npm owner add <user> <package name>`：添加的所有者将拥有完全访问权限，包括修改包和添加其他所有者的能力

+   `npm owner rm <user> <package name>`：删除所有者并立即撤销所有权限

所有所有者都拥有相同的权限—无法使用特殊访问控制，例如能够给予写入但不能删除的权限。

# 全局安装和二进制文件

一些 Node 模块作为命令行程序非常有用。与其要求像`$ node module.js`这样运行程序，我们可能希望在控制台上简单地键入`$ module`并执行程序。换句话说，我们可能希望将模块视为安装在系统 PATH 上的可执行文件，并且因此可以从任何地方访问。使用 npm 可以通过两种方式实现这一点。

第一种最简单的方法是使用`-g（全局）`参数安装包如下：

```js
$ npm install -g module
```

如果一个包旨在作为应该全局安装的命令行应用程序，将`package.json`文件的`preferGlobal`属性设置为`true`是一个好主意。该模块仍将在本地安装，但用户将收到有关其全局意图的警告。

确保全局访问的另一种方法是设置包的`bin`属性：

```js
"name": "aModule",
  "bin" : {
    "aModule" : "./path/to/program"
}
```

当安装此模块时，`aModule`将被理解为全局 CLI 命令。任意数量的此类程序可以映射到`bin`。作为快捷方式，可以映射单个程序，如下所示：

```js
"name": "aModule",
  "bin" : "./path/to/program"
```

在这种情况下，包本身的名称（`aModule`）将被理解为活动命令。

# 其他存储库

Node 模块通常存储在版本控制系统中，允许多个开发人员管理包代码。因此，`package.json`的`repository`字段可用于指向这样的存储库，如果需要合作，可以将开发人员指向这样的存储库。考虑以下示例：

```js
"repository" : {
  "type" : "git",
  "url" : "http://github.com/sandro-pasquali/herder.git"
}
"repository" : {
  "type" : "svn",
  "url" : "http://v8.googlecode.com/svn/trunk/"
}
```

同样，您可能希望使用 bugs 字段将用户指向应该提交错误报告的位置：

```js
"bugs": {
  "url": "https://github.com/sandro-pasquali/herder/issues"
}
```

# 锁定文件

最终，npm install 是一个命令，它从`package.json`构建一个`node_modules`文件夹。但是，它总是生成相同的文件夹吗？答案有时是，我们将在稍后详细介绍。

如果您创建了一个新项目，或者最近将 npm 更新到版本 5，您可能已经注意到熟悉的`package.json`旁边有一个新文件—`package-lock.json`。

里面的内容如下：

```js
{
  "name": "app1",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "align-text": {
      "version": "0.1.4",
      "resolved": "https://registry.npmjs.org/align-text/-/align-text-0.1.4.tgz",
      "integrity": "sha1-DNkKVhCT810KmSVsIrcGlDP60Rc=",
      "dev": true
    },
    "babel-core": {
      "version": "6.25.0",
      "resolved": "https://registry.npmjs.org/babel-core/-/babel-core-6.25.0.tgz",
      "integrity": "sha1-fdQrBGPHQunVKW3rPsZ6kyLa1yk=",
      "dev": true,
      "dependencies": {
        "source-map": {
          "version": "0.5.6",
          "resolved": "https://registry.npmjs.org/source-map/-/source-map-0.5.6.tgz",
          "integrity": "sha1-dc449SvwczxafwwRjYEzSiu19BI=",
          "dev": true
        }
      }
    }
  }
}
```

部分内容会立即变得熟悉。这里是您的项目依赖的 npm 包。依赖项的依赖项会适当地嵌套：`align-text`不需要任何东西，而`babel-core`需要`source-map`。

除了`package.json`之外的真正有用的部分是通过解析和完整性字段提供的。在这里，您可以看到 npm 下载并解压缩以创建`npm_modules`中相应文件夹的确切文件，更重要的是，该文件的加密安全哈希摘要。

使用`package-lock.json`，您现在可以获得一个确切和可重现的`node_modules`文件夹。提交到源代码控制中，您可以在代码审查期间的差异中看到依赖模块版本何时发生了变化。此外，到处都是哈希值，您可以更加确信您的应用程序依赖的代码没有被篡改。

`package-lock.json`在这里；它很长，充满了哈希值，但实际上，您可以忽略它。npm 5 中文件的外观并没有改变您习惯的 npm install 和 npm update 等命令的行为。要解释为什么有帮助，有两个开发人员在遇到该文件时通常会提出的常见问题（或感叹）：

1.  这意味着我的`node_modules`文件夹将由这些哈希值组成，对吗？

1.  为什么我的`package-lock.json`文件一直在变化？

答案是（1）不是，（2）这就是为什么。

当 npm 发现一个包的新版本时，它会下载并更新你的`node_modules`文件夹，就像之前一样。使用 npm 5，它还会更新`package-lock.json`，包括新的版本号和新的哈希值。

此外，大多数情况下，这就是你希望它做的。如果有一个包的新版本是你正在开发的项目所依赖的，你可能希望 npm install 给你最新的版本。

但是，如果你不想让 npm 这样做呢？如果你希望它获取确切的这些版本和确切的这些哈希值的模块呢？要做到这一点，不在`package-lock.json`中，而是回到`package.json`中，并处理语义版本号。看看这三个：

+   `1.2.3`

+   `~1.2.3`

+   `¹.2.3`

`1.2.3`确切表示那个版本，没有更早的，也没有更晚的。`~1.2.3`匹配该版本或任何更新的版本。第三个例子中的插入符号`¹.2.3`将引入该版本或更晚的版本，但保持在 1 版本。插入符号是默认的，很可能已经在你的`package.json`文件中写好了。这是有道理的，因为对第一个数字的更改表示一个可能与先前版本不兼容的主要版本，反过来可能会破坏你之前的代码。

除了这三个常见的例子之外，语义版本和 npm 支持的比较器、运算符、标识符和范围还有一个完整的语言。好奇的读者可以在[`docs.npmjs.com/misc/semver`](https://docs.npmjs.com/misc/semver)查看。但是，请记住保持简单！你现在的合作者和未来的自己会感谢你。

所以，npm 正在改变你的`node_modules`文件夹和`package-lock.json`，因为你告诉它在`package.json`中使用`^`。你可以删除所有的插入符号，让 npm 坚持使用确切的版本，但在你想要这样做的情况下，有一个更好的方法：

```js
$ npm shrinkwrap
```

npm 的`shrinkwrap`命令实际上只是将`package-lock.json`重命名为`npm-shrinkwrap.json`。其重要性在于 npm 后续如何使用这些文件。当发布到 npm 时，`package-lock.json`会留下，因为它可能会随着你正在使用的依赖项的新版本的出现而改变。另一方面，`npm-shrinkwrap.json`旨在与你的模块一起发布。

当 npm 在一个带有`npm-shrinkwrap.json`文件的项目上操作时，`shrinkwrap`文件及其确切的版本和哈希值，而不是`package.json`及其版本范围，决定了 npm 如何构建`node_modules`文件夹。就像上世纪 90 年代商场里软件商店的纸板盒一样，你知道里面的东西是从工厂出来时没有改变的，因为去掉了塑料包装。


# 第十二章：创建你自己的 C++插件

如果同一工作的两个人总是意见一致，那么其中一个是无用的。如果他们总是意见不一致，那么两个都是无用的。

- Darryl F. Zanuck

Node 的一个非常常见的描述是：*NodeJS 允许在服务器上运行 Javascript*。这当然是真的；但也是误导的。Node 的成就在于以这样一种方式组织和链接强大的 C++库，使它们的效率可以被利用，而不需要理解它们的复杂性，所有这些都是通过将本地 C++库链接到*是*Node 的 JavaScript 驱动运行时来实现的。Node 的目标是通过将并发模型包装到一个易于理解的单线程环境中，来抽象出多用户、同时多线程 I/O 管理的复杂性，并且已经被数百万网络开发人员充分理解。

简单来说，当你使用 Node 时，你最终是在使用 C++绑定到你的操作系统，这是一种适用于企业级软件开发的语言，没有人会认真质疑。

这种与 C++程序的本地桥接证明了 Node 不适合企业级的说法是错误的。这些说法混淆了 Javascript 在 Node 堆栈中的实际角色。在 Node 程序中经常使用的 Redis 和其他数据库驱动程序的绑定是 C 绑定——快速，接近*底层*。正如我们所看到的，Node 的简单进程绑定（spawn、exec 等）促进了强大系统库与无头浏览器和 HTTP 数据流的平滑集成。我们能够访问一套强大的本地 Unix 程序，就好像它们是 Node API 的一部分。当然，我们也可以编写自己的插件。

对于成功的消费者技术，这是一些特征的简述，由*Keith Devlin*教授在"*微积分：最成功的技术之一*"([`www.youtube.com/watch?v=8ZLC0egL6pc`](https://www.youtube.com/watch?v=8ZLC0egL6pc))中描述：

+   它应该消除完成任务的困难或单调乏味。

+   它应该易于学习和使用。

+   如果有的话，它应该比流行的方法更容易学习和使用。

+   一旦学会，就可以在没有持续专家指导的情况下使用。用户仍然能够记住和/或推导出大部分或全部规则，以及随着时间的推移与技术的交互。

+   它应该可以在不知道它是如何工作的情况下使用。

希望当你考虑 Node 旨在解决的问题类别和它提供的解决方案形式时，你会很容易地在 Node 所代表的技术中看到上述五个特征。Node 学习和使用起来很有趣，具有一致和可预测的界面。重要的是，“*在幕后*”Node 运行着强大的工具，开发人员只需要理解它们的 API。

令人惊讶的是，Node、V8、libuv 和组成 Node 堆栈的其他库都是开源的，这是一个重要的事实，进一步区别了 Node 与许多竞争对手。不仅可以直接向核心库做出贡献，还可以*剪切和粘贴*代码块和其他例程来用于自己的工作。事实上，你应该把自己成长为更好的 Node 开发人员看作是同时成为更好的 C++程序员的机会。

这不是 C++的入门指南，让你自己去学习。不要感到害怕！C 语言家族使用的形式和习惯用法与你已经习惯使用的 JavaScript 非常相似。语法和流程控制应该看起来非常熟悉。你应该能够轻松理解以下示例的设计和目标，并且可以通过 C++编程来解决不清楚的部分的含义。逐步扩展这些示例是进入 C++编程世界的一个很好的方式。

# 你好，世界

让我们构建我们的第一个插件。为了保持传统，这个插件将生成一个 Node 模块，将打印出“Hello World!”即使这是一个非常简单的例子，但它代表了您将构建的所有后续 C++插件的结构。这使您可以逐步尝试新的命令和结构，以易于理解的步骤增加您的知识。

为了使接下来的步骤起作用，您需要在系统上安装 C/C++编译器和 Python 2.7。在操作系统上构建本机代码的工具是特定于该操作系统的（由维护或拥有它的社区或公司提供）。以下是一些主要操作系统的说明：

+   例如，在 macOS 上，苹果提供了 Xcode，一个集成开发环境（IDE），其中包括一个编译器。

+   对于 Windows，微软的编译器随 Visual Studio 一起提供。还有一个可用于此目的的 npm 包—`npm i -g windows-build-tools`。

+   在 Linux 和其他地方，**GCC，GNU 编译器集合**很常见。还需要**GNU Make**和**Python**。

C++程序员可能会受益于学习 V8 的嵌入方式，网址为：[`github.com/v8/v8/wiki/Embedder%27s-Guide`](https://github.com/v8/v8/wiki/Embedder%27s-Guide)。

编译本地代码时，通常还有另一种软件——构建自动化工具。这个工具指导编译器执行的步骤，将您的源代码转换为本机二进制代码。对于 C 语言，最早的工具之一是 Make。当然，您也可以直接输入编译器，但是 Make 可以让您重新运行相同的一组命令，记录这些命令是什么，并将这些命令传输给另一个开发人员。Make 是在 1976 年 4 月开发的，自那时以来一直在持续使用。

Visual Studio 和 Xcode 不使用像 Make 这样基于脚本的工具。相反，它们将构建步骤和设置保存在二进制文件中，并允许开发人员通过单击复选框和在图形对话框中输入文本来编辑它们。这种方法看起来更友好，但可能更繁琐和容易出错。

为了更方便，谷歌开发了一个名为**GYP**的工具，用于**生成您的项目**。这是一个元构建系统，从您那里（以文本格式）获取信息，并生成本机编译器或 IDE 所需的构建文件。GYP 将为您生成所需的文件，而不是打开 Visual Studio 或 Xcode 并在菜单和复选框上单击。对于任何一个花了一个晚上（或几个晚上）在设置中寻找以修复损坏的本机构建的开发人员来说，GYP 是一种神奇的魔法。

谷歌最初创建了 GYP 来构建 Chrome 和 V8，但作为一个开源项目，一个社区将其带到了一个不断扩大的新用途列表。为了构建本机 Node 插件，Node 团队创建并维护了`node-gyp`，其中包含了谷歌的 GYP。使用上述命令在系统上全局安装`node-gyp`，并通过获取版本来验证它是否存在。您可以在下面的链接中找到`node-gyp`的安装说明：[`github.com/nodejs/node-gyp`](https://github.com/nodejs/node-gyp)

您可能还记得我们在第一章中关于 Unix 设计哲学的讨论，特别是道格·麦克罗伊的指令“*编写处理文本流的程序，因为那是一个通用接口*”。

对于编译器自动化的任务，Make 在 20 世纪 70 年代遵循了这一准则，而苹果和微软在 20 世纪 90 年代打破了这一规则，他们使用了图形 IDE 和二进制项目文件，而现在在这个十年中，谷歌用 GYP 恢复了它。

为了了解我们要去哪里，可能有助于看一下我们最终会得到什么。完成后，我们将拥有一个模块定义文件夹，其中包含一些文件。首先我们将创建的结构如下：

```js
/hello_module
  binding.gyp
  hello.cc
  index.js
```

`/hello_module`模块文件夹包含一个 C++文件（`hello.cc`），GYP 的*指令*文件（`binding.gyp`），以及一个方便的*包装器*（`index.js`），其目的将很快清楚。

创建一个名为`hello.cc`的文件，其中包含以下内容：

```js
#include <node.h>

namespace hello_module {

    using v8::FunctionCallbackInfo;
    using v8::Isolate;
    using v8::Local;
    using v8::Object;
    using v8::String;
    using v8::Value;

    // Our first native function
    void sayHello(const FunctionCallbackInfo<Value>& args) {
      Isolate* isolate = args.GetIsolate();
      args.GetReturnValue().Set(String::NewFromUtf8(isolate, "Hello Node from native code!"));
    }

    // The initialization function for our module
    void init(Local<Object> exports) {
      NODE_SET_METHOD(exports, "sayHello", sayHello);
    }

    // Export the initialization function
    NODE_MODULE(NODE_GYP_MODULE_NAME, init)
}
```

在包含了 Node 的 C 头文件之后，为我们的代码定义了一个命名空间，并声明了我们需要使用的 V8 的各个部分，有三个部分。`void sayHello`函数是我们将要导出的本地函数。在下面，`init`是一个必需的初始化函数，用于设置这将成为的 Node 模块的导出（这里，函数名`"sayHello"`绑定到它的 C++对应部分），`NODE_MODULE()`是一个 C++宏，实际上导出了 GYP 配置为导出的模块。由于它是一个宏，在该行的末尾没有分号。

你正在将 C++代码嵌入 V8 运行时，以便 Javascript 可以绑定到相关的范围。V8 必须对你的代码中进行的所有新分配进行范围限制，因此，你需要将你编写的代码包装起来，扩展 V8。为此，你将看到在接下来的示例中，`Handle<Value>`语法的几个实例，将 C++代码包装起来。将这些包装器与将在初始化函数中定义并推送到`NODE_MODULE`的内容进行比较，应该清楚地表明 Node 是如何通过 V8 桥接绑定到 C++方法的。

要了解更多关于 V8 嵌入 C++代码的信息，请查看：[`github.com/v8/v8/wiki/Getting%20Started%20with%20Embedding`](https://github.com/v8/v8/wiki/Getting%20Started%20with%20Embedding)。

除了`hello.cc`，还要创建一个包含以下代码的`binding.gyp`：

```js
{
 "targets": [
   {
     "target_name": "hello",
     "sources": [ "hello.cc" ]
   }
 ]
} 
```

在你有多个源文件需要编译的情况下，只需将更多的文件名添加到源数组中。

这个清单告诉 GYP 我们希望看到`hello.cc`编译成一个名为`hello.node`的文件（`target_name`）在`/Release`文件夹中的编译二进制代码。现在我们有了 C++文件和编译指令，我们需要编译我们的第一个本地插件！

在`/hello_module`文件夹中运行以下命令：

```js
 $ node-gyp configure
```

基本上，`configure`生成一个 Makefile，`build`命令运行它。在运行`configure`命令之后，你可以查看 GYP 创建的`/build`文件夹，以熟悉它们；它们都是你可以检查的文本文件。在安装了 Xcode 的 Mac 上，它将包含一些文件，包括一个 300 行的 Makefile。如果成功，`configure`命令的输出应该看起来像这样：

```js
$ node-gyp configure
 gyp info it worked if it ends with ok
 gyp info using node-gyp@3.6.2
 gyp info using node@8.7.0 | darwin | x64
 gyp info spawn /usr/bin/python
 gyp info spawn args [ '/usr/local/lib/node_modules/node-gyp/gyp/gyp_main.py',
 gyp info spawn args   'binding.gyp',
 gyp info spawn args   '-f',
 gyp info spawn args   'make',
 gyp info spawn args   '-I',

 ...

 gyp info spawn args   '--generator-output',
 gyp info spawn args   'build',
 gyp info spawn args   '-Goutput_dir=.' ]
 gyp info ok
```

接下来，尝试`build`命令，它会运行这个 Makefile。输出看起来像这样：

```js
$ node-gyp build
 gyp info it worked if it ends with ok
 gyp info using node-gyp@3.6.2
 gyp info using node@8.7.0 | darwin | x64
 gyp info spawn make
 gyp info spawn args [ 'BUILDTYPE=Release', '-C', 'build' ]
     CXX(target) Release/obj.target/hello_native/hello.o
     SOLINK_MODULE(target) Release/hello_native.node
 gyp info ok 
```

现在，你会看到一个新的`/build/Release`文件夹，其中包含（其他内容之间）二进制`hello.node`文件。

要删除`/build`文件夹，可以运行`node-gyp clean`。作为一个构建快捷方式，你可以使用`node-gyp configure build`（一行）来配置和构建一步完成，或者简单地使用`node-gyp rebuild`，它会一次运行`clean configure build`。更多的命令行选项可以在这里找到：[`github.com/nodejs/node-gyp#command-options`](https://github.com/nodejs/node-gyp#command-options)。

现在，始终保持在`/hello_module`文件夹中，创建以下`index.js`文件：

```js
// index.js
module.exports = require('./build/Release/hello');
```

这个文件将作为这个模块的导出程序。根据你如何编写你的 C++代码，你可能会利用这个机会将你的模块的本地接口制作成一个特定于 Node 的 API。现在，让我们直接导出`hello`函数，省去开发者在使用`require`时遵循我们的构建文件夹结构的麻烦。

为了完成"模块化"，为这个模块创建一个`package.json`文件，并将"入口点"值设置为`index.js`：

现在，让我们演示如何在你的代码中使用这个模块。跳到上一级目录，创建一个文件，该文件将需要我们刚刚创建的模块。考虑以下示例：

```js
const {sayHello} = require('./hello_module');
console.log(sayHello())
```

使用解构，我们从我们的模块返回的对象中提取`sayHello`函数。现在，执行这段代码：

```js
$ node hello.js
Hello Node from native code!
```

现在，你既是 C++程序员，也是 Node 扩展程序员了！

注意我们如何以一种微妙而强大的方式使用相同熟悉的`require`语句。它不是引入更多 JavaScript 编写的 Node 模块，而是检测并加载我们新创建的本地附加程序。

# 一个计算器

当然，人们永远不会费心编写一个附加程序来简单地回显字符串。更有可能的是，您希望为您的 Node 程序公开 API 或接口。让我们创建一个简单的计算器，有两种方法：add 和 subtract。在这个例子中，我们将演示如何将参数从 Javascript 传递给附加程序中的方法，并将任何结果发送回来。

这个示例的完整代码将在您的代码包中找到。程序的核心部分可以在这个片段中看到，我们在这里为我们的两种方法定义了一个接口，每种方法都期望接收两个数字作为参数：

```js
#include <node.h>

namespace calculator_module {

  using v8::Exception;
  using v8::FunctionCallbackInfo;
  using v8::Isolate;
  using v8::Local;
  using v8::Number;
  using v8::Object;
  using v8::String;
  using v8::Value;

  void Add(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check argument arity
    if (args.Length() < 2) {
      isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "Must send two argument to #add")));
      return;
    }

    // Check argument types
    if (!args[0]->IsNumber() || !args[1]->IsNumber()) {
      isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "#add only accepts numbers")));
      return;
    }

    // The actual calculation now
    double value = args[0]->NumberValue() + args[1]->NumberValue();
    Local<Number> num = Number::New(isolate, value);

    // Set the return value (using the passed in FunctionCallbackInfo<Value>&)
    args.GetReturnValue().Set(num);
  }

  void Subtract(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    if (args.Length() < 2) {
      isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "Must send two argument to #subtract")));
      return;
    }

    if (!args[0]->IsNumber() || !args[1]->IsNumber()) {
      isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "#subtract only accepts numbers")));
      return;
    }

    double value = args[0]->NumberValue() - args[1]->NumberValue();
    Local<Number> num = Number::New(isolate, value);

    args.GetReturnValue().Set(num);
  }

  void Init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "add", Add);
    NODE_SET_METHOD(exports, "subtract", Subtract);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Init)
}
```

我们可以很快看到两种方法已经被限定范围：`Add`和`Subtract`（`Subtract`几乎与`Add`定义相同，只是操作符有所改变）。在`Add`方法中，我们看到一个`Arguments`对象（让人想起 Javascript 的 arguments 对象），它被检查长度（我们期望两个参数）和参数类型（我们想要数字：`!args[0]->IsNumber() || !args[1]->IsNumber()`）。仔细看看这个方法是如何结束的：

```js
Local<Number> num = Number::New(args[0]->NumberValue() + args[1]->NumberValue());
 return scope.Close(num);
```

虽然似乎有很多事情要做，但实际上非常简单：V8 被指示为一个名为`num`的数字分配空间，以便赋予我们两个数字相加的值。当这个操作完成后，我们关闭执行范围并返回`num`。我们不必担心这个引用的内存管理，因为这是由 V8 自动处理的。

最后，在下面的代码块中，我们不仅看到了这个特定程序如何定义它的接口，而且还看到了 Node 模块和 exports 对象在深层次上是如何关联的：

```js
void Init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("add"),
    FunctionTemplate::New(Add)->GetFunction());
  exports->Set(String::NewSymbol("subtract"),
    FunctionTemplate::New(Subtract)->GetFunction());
 }
```

就像我们的“hello”示例一样，在这里我们看到了新的符号（这些只是字符串类型）`add`和`subtract`，它们代表了我们的新 Node 模块的方法名称。它们的函数签名是使用易于遵循的`FunctionTemplate::New(Add)->GetFunction())`蓝图实现的。

现在很容易从 Node 程序中使用我们的计算器：

```js
let calculator = require('./build/Release/calculator');
console.log(calculator.add(2,3));
console.log(calculator.subtract(3,2));
// 5
// 1
```

仅仅从这个简单的开始，我们就可以实现有用的 C++模块。现在，我们将深入一些，并且我们将从**nan（Node 的本地抽象）**中得到一些帮助。

# 使用 NAN

**nan**（[`github.com/nodejs/nan`](https://github.com/nodejs/nan)）是一个提供帮助程序和宏的头文件集，旨在简化附加程序的创建。根据文档，nan 主要是为了保持您的 C++代码在不同的 Node 版本之间的兼容性而创建的：

由于 V8（以及 Node 核心）的疯狂变化，跨版本保持本地附加程序编译的愉快，特别是从 0.10 到 0.12 到 4.0，是一场小噩梦。这个项目的目标是存储开发本地 Node.js 附加程序所需的所有逻辑，而无需检查`NODE_MODULE_VERSION`并陷入宏纠缠。

在接下来的示例中，我们将使用 nan 来构建一些本地附加程序。让我们使用 nan 重新构建我们的`hello world`示例。

# 你好，nan

为您的项目创建一个文件夹，并添加以下 package.json 文件：

```js
// package.json
{
  "name": "hello",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "build": "node-gyp rebuild",
    "start": "node index.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "nan": "².8.0",
    "node-gyp": "³.6.2"
  },
  "gypfile": true
}
```

我们在这里添加了一些新东西，比如指示存在一个`gypfile`。更重要的是，我们为编译和运行我们的模块创建了一些方便的脚本：`build`和`start`。当然，我们还指出模块的主执行文件是`index.js`（我们很快就会创建）。还要注意，当您`npm install`这个包时，GYP 会注意到`binding.gyp`文件并自动构建 - 一个`/build`文件夹将与安装一起创建。

现在，创建我们的 GYP 绑定文件。注意添加了`include_dirs`。这确保了`nan`头文件对编译器是可用的：

```js
// binding.gyp
{
  "targets": [{
     "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ],
      "target_name": "hello",
      "sources": [
        "hello.cc"
      ]
  }]
}
```

现在，我们重写主 C++文件以利用 nan 的帮助程序：

```js
#include <nan.h>

NAN_METHOD(sayHello) {
    auto message = Nan::New("Hello Node from NAN code!").ToLocalChecked();
    // 'info' is an implicit bridge object between JavaScript and C++
    info.GetReturnValue().Set(message);
}

NAN_MODULE_INIT(Initialize) {
    // Similar to the 'export' statement in Node -- export the sayHello method
    NAN_EXPORT(target, sayHello);
}

// Create and Initialize function created with NAN_MODULE_INIT macro
NODE_MODULE(hello, Initialize);
```

在这里，我们可以看到长长的包含列表是不必要的。代码的其余部分遵循与我们原始示例相同的模式，但现在通过 NAN 前缀的快捷方式运行初始化和函数定义。请注意，我们可以直接在模块对象上键入`sayHello`方法（`NAN_EXPORT(target, sayHello)`），而不需要在`require`语句接收的接口上指定`sayHello`。

最后一步是证明这个模块可以绑定到 Node。创建以下`index.js`文件：

```js
const {Hello} = require('./build/Release/hello');
console.log(Hello());
```

现在，我们要做的就是构建：

```js
$ npm run build
```

然后，我们将运行它：

```js
$ node index.js
// Hello Node from NAN code!
```

# 异步插件

根据 Node 程序的典型模式，插件也实现了异步回调的概念。正如人们可能在 Node 程序中期望的那样，执行昂贵和耗时操作的 C++插件应该理解异步执行函数的概念。

让我们创建一个模块，公开两种最终调用相同函数的方法，但一种是同步调用，另一种是异步调用。这将使我们能够演示如何创建带有回调的本机模块。

我们将把我们的模块分成 4 个文件，分离功能。创建一个新目录，并从上一个示例中复制`package.json`文件（将`name`更改为其他内容），然后添加以下`binding.gyp`文件：

```js
{
  "targets": [
    {
      "target_name": "nan_addon",
      "sources": [
        "addon.cc",
        "sync.cc",
        "async.cc"
      ],
      "include_dirs": ["<!(node -e \"require('nan')\")"]
    }
  ]
}
```

完成后，您的模块文件夹将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/5a0c4968-9de2-4bbb-9b36-ccb770df644d.png)

我们将创建一个包含异步方法（`async.cc`）的文件，一个包含同步方法（`sync.cc`）的文件，每个文件将在`addon.h`中以不同方式调用的公共函数，以及将所有内容“绑定”在一起的主`addon.cc`文件。

在模块文件夹中创建`addons.h`：

```js
// addons.h
using namespace Nan;

int Run (int cycles) {
    // using volatile prevents compiler from optimizing loop (slower)
    volatile int i = 0;
    for (; i < cycles; i++) {}
    return cycles;
}
```

在这个文件中，我们将创建一个“模拟”函数，其责任只是浪费周期（时间）。因此，我们创建一个低效的函数`Run`。使用`volatile`关键字，我们吓唬 V8 使其取消优化这个函数（我们警告 V8 这个值将不可预测地改变，吓跑了优化器）。其余部分将简单地运行请求的周期数并反映它发送的值...慢慢地。这是我们的异步和同步代码都将执行的函数。

要同步执行`Run`，创建以下`sync.cc`文件：

```js
// sync.cc
#include <nan.h>
int Run(int cycles);

// Simple synchronous access to the `Run()` function
NAN_METHOD(RunSync) {
 // Expect a number as first argument
 int cycles = info[0]->Uint32Value();
 int result = Run(cycles);

 info.GetReturnValue().Set(result);
}
```

正如我们之前看到的，`info`将包含传递给此`RunSync`方法的参数。在这里，我们获取请求的周期数，将这些参数传递给`Run`，并返回该函数调用产生的任何内容。

现在，创建我们的异步方法`async.cc`的文件。创建异步代码稍微复杂：

```js
// async.cc
#include <nan.h>

using v8::Local;
using v8::Number;
using v8::Value;
using namespace Nan;

int Run(int cycles);

class Worker : public AsyncWorker {
 public:
  Worker(Callback *callback, int cycles)
    : AsyncWorker(callback), cycles(cycles) {}
  ~Worker() {}

  // This executes in the worker thread.
  // #result is being place on "this" (private.result)
  void Execute () {
    result = Run(cycles);
  }

  // When the async work is complete execute this function in the main event loop
  // We're sending back two arguments to fulfill standard Node callback
  // pattern (error, result) -> (Null(), New<Number>(result))
  void HandleOKCallback () {
    HandleScope scope;
    Local<Value> argv[] = {
        Null()
      , New<Number>(result)
    };
    callback->Call(2, argv);
  }

 private:
  int cycles;
  int result;
};

NAN_METHOD(RunAsync) {
  int cycles = To<int>(info[0]).FromJust();
  Callback *callback = new Callback(To<v8::Function>(info[1]).ToLocalChecked());

  AsyncQueueWorker(new Worker(callback, cycles));
}
```

从底部开始，您会看到我们正在创建一个方法，该方法期望第一个参数（info[0]）是一个整数，该整数被赋给`cycles`。然后我们创建一个新的`Callback`对象作为`callback`，并将`callback`和`cycles`传递给`Worker`构造函数，将结果实例传递给`AsyncQueueWorker`（设置我们的异步方法）。

现在，让我们看看如何配置异步`Worker`。

跳到`Worker`的底部，注意为这个类建立私有属性`cycles`和`result`。在 JavaScript 中，相当于创建一个具有`this.cycles`和`this.result`的本地变量上下文--在接下来的内容中使用的本地变量。

为了满足工作模板，我们需要实现两个关键函数：`Execute`和`HandleOKCallback`。`Execute`在工作线程中执行我们的`Run`函数（来自`addons.h`），并将返回的值赋给`result`。一旦`Run`完成，我们需要将这个结果发送回原始的 JavaScript 回调，我们的 Node 模块接口会发送。`HandleOKCallback`准备参数列表（`argv`），按照标准的错误优先 Node 回调模式的预期：我们将第一个错误参数设置为`Null()`，第二个参数设置为`result`。通过`callback->Call(2, argv)`，原始回调将使用这两个参数进行调用，并相应地进行处理。

最后一步是创建模块导出文件`index.js`：

```js
const addon = require('./build/Release/nan_addon');
const width = 1e9;

function log(type, result, start) {
    const end = Date.now() - start;
    console.log(`${type} returned <${result}> in ${end}ms`)
}

function sync() {
    const start = Date.now();
    const result = addon.runSync(width);
    log('Sync', result, start);
}

function async() {
    const start = Date.now();
    addon.runAsync(width, (err, result) => {
        log('Async', result, start);
    });
}

console.log('1');
async();
console.log('2');
sync();
console.log('3');
```

创建完这个文件后，继续通过`npm run build`（或`node-gyp rebuild`）构建您的模块，并使用`node index.js`执行此文件。您应该在终端中看到类似以下的内容：

```js
1
2
Sync returned <1000000000> in 1887ms
3
Async returned <1000000000> in 1889ms
```

这有什么意义呢？我们正在证明我们可以创建独立于单个 Node 进程线程的 C++函数。如果`addon.runAsync`不是异步运行的，输出将如下所示：

```js
1
Async returned <1000000000> in 1889ms
2
Sync returned <1000000000> in 1887ms
3
```

然而，我们看到运行时记录了 1，`runAsync`进入了线程，记录了 2，然后是同步函数`runSync`，阻塞了事件循环（在同一个单一的 JavaScript 线程中运行）。完成后，这个同步函数宣布了它的结果，循环继续执行下一个指令记录 3，最后，待处理的回调被执行，`runAsync`的结果最后出现。

即使您不是 C++程序员，这里还有很多探索的空间。借助`nan`这些简单的构建模块，您可以构建行为越来越复杂的插件。当然，最大的优势是能够将长时间运行的任务交给操作系统，在一个非常快速的编译语言中运行。您的 Node 项目现在可以充分利用 C++的力量。

# 结束语

能够轻松地将 C++模块与 Node 程序链接起来是一种强大的新范式。因此，可能会有诱惑力，热情洋溢地开始为程序的每个可识别的部分编写 C++插件。虽然这可能是学习的一种有效方式，但从长远来看，这并不一定是最好的主意。尽管通常编译后的 C++运行速度比 JavaScript 代码更快，但要记住 V8 最终是在 JavaScript 代码上使用另一种类型的编译。在 V8 中运行的 JavaScript 非常高效。

此外，我们不希望在高并发环境中设计复杂的交互时失去 JavaScript 的简单组织和可预测的单线程运行时。请记住，Node 的出现部分是为了使开发人员在执行 I/O 时免于使用线程和相关复杂性。因此，请牢记一些规则。

C++模块实际上会更快吗？答案并不总是肯定的。跳转到不同的执行上下文，然后再返回到 V8 需要时间。*Felix Geisendorfer*的演讲描述了他构建快速 MySQL 绑定的工作，提供了一些关于在做出这些决定时应该如何思考的见解，网址为：[`www.youtube.com/watch?v=Kdwwvps4J9A`](http://www.youtube.com/watch?v=Kdwwvps4J9A)。总的来说，除非真的需要做一些深入和昂贵的事情，需要更接近底层，否则应该坚持使用 JavaScript。

拆分代码库如何影响可维护性？虽然很难有任何开发人员建议使用效率低下的代码，但有时微不足道的性能提升并不能克服复杂性的增加，这可能导致更难以找到的错误或在共享或管理代码库时出现困难（包括未来尚未雇佣的团队成员）。

Node 已经将一个美丽的 JavaScript API 与一个非常强大且易于扩展的应用程序堆栈合并在一起。有了将 C++集成到你的应用程序中的能力，没有理由将 Node 排除在下一个项目考虑的技术列表之外。

# 链接和资源

关于编写 Node 插件的额外指南和资源可以在网上找到：

+   Node 的插件文档非常出色：[`nodejs.org/dist/latest-v9.x/docs/api/addons.html`](https://nodejs.org/dist/latest-v9.x/docs/api/addons.html)

+   nan 存储库包含许多示例：[`github.com/nodejs/nan`](https://github.com/nodejs/nan)

+   对于学习 C++的绝佳资源：[`www.learncpp.com/`](http://www.learncpp.com/)

+   当你感到更有信心时，Node 核心模块的源代码是一个很好的地方，可以进行探索和学习：[`github.com/nodejs/node/tree/master/src`](https://github.com/nodejs/node/tree/master/src)
