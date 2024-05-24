# Node API 开发入门指南（一）

> 原文：[`zh.annas-archive.org/md5/2705C5A410800D1F556555A653E1AF27`](https://zh.annas-archive.org/md5/2705C5A410800D1F556555A653E1AF27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

使用相同的框架构建服务器端和客户端应用程序可以节省时间和金钱。本书教你如何使用 JavaScript 和 Node.js 构建高度可扩展的 API，以便与轻量级跨平台客户端应用程序良好配合。它从 Node.js 的基础知识开始，快速地引导您创建一个示例客户端，该客户端与完全经过身份验证的 API 实现配对。

本书平衡了理论和练习，并包含了多个开放式活动，使用真实的商业场景让您练习和应用您新获得的技能。

我们包含了超过 20 个实际活动和练习，涵盖了 9 个主题，以加强您的学习。通过本书，您将具备进行自己的 API 开发项目所需的技能和经验。

# 本书适合对象

本书适合已经了解 JavaScript 并寻求快速简洁的 Node.js API 开发介绍的开发人员。虽然具有其他服务器端技术（如 Python、PHP、ASP.NET、Ruby）的经验会有所帮助，但在开始之前并不一定需要具备后端开发的背景。

# 本书涵盖的内容

第一章，*Node.js 简介*，涵盖了 Node.js 的一些基本概念，基本的 Node.js 代码以及如何从终端运行它，模块系统，其类别以及作为 Node.js 工作核心的异步编程模型，以及实际使 Node.js 运行的原理。

第二章，*构建 API-第一部分*，涵盖了构建基本的 HTTP 服务器，设置 Hapi.js，使用 Hapi.js 框架构建基本 API 以及 Web 应用程序的基本概念。

第三章，*构建 API-第二部分*，涵盖了 Knex.js 的介绍以及如何使用它连接和使用数据库，基本的 CRUD 数据库方法，使用 JWT 机制进行 API 身份验证，CORS 机制，使用 Lab 库测试 API 以及使用 Gulp.js 进行测试自动化。

# 充分利用本书

1.  具有其他服务器端技术经验，如 Python、PHP、ASP.NET 和 Ruby 将有益，但不是必需的。

1.  本书需要计算机系统。最低硬件要求为 1.8 GHz 或更高的奔腾 4（或等效）处理器，4 GB RAM，10 GB 硬盘和稳定的互联网连接。

1.  所需软件包括 Visual Studio Code ([`code.visualstudio.com/`](https://code.visualstudio.com/))，Node.js (8.9.1) ([`nodejs.org/en/`](https://nodejs.org/en/))，MySQL Workbench 6.3 ([`www.mysql.com/products/workbench/`](https://www.mysql.com/products/workbench/))和 MySQL ([`dev.mysql.com/downloads/mysql/`](https://dev.mysql.com/downloads/mysql/))。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com/support](http://www.packtpub.com/support)上登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保您使用最新版本的解压缩或提取文件夹：

+   Windows 需要 WinRAR/7-Zip

+   Mac 需要 Zipeg/iZip/UnRarX

+   Linux 需要 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址是[`github.com/TrainingByPackt/BeginningAPIDevelopmentwithNode.js`](https://github.com/TrainingByPackt/BeginningAPIDevelopmentwithNode.js)。如果代码有更新，将会在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里有一个例子：“完成此设置后，我们使用`server.start`方法启动服务器。”

代码块设置如下：

```js
handler: (request, reply) => 
{
  return reply({ message: 'hello, world' });
}
```

任何命令行输入或输出都是这样写的：

```js
node server.js
```

**粗体**：表示一个新术语、一个重要词或者屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这里有一个例子：“将请求类型更改为 POST。”

**活动**：这些是基于场景的活动，让您可以在整个章节学习过程中实际应用所学知识。它们通常是在真实世界问题或情况的背景下进行。

警告或重要说明会以这种方式出现。


# 第一章：Node.js 简介

本章旨在涵盖 Node.js 中的一些基本概念，为我们后续的 API 开发奠定基础。

让我们从 Node.js 的工作原理和最近的使用情况开始这第一章。然后我们将看一下它的模块系统和异步编程模型。让我们开始吧。

到本章结束时，您将能够：

+   描述 Node.js 的基本工作原理

+   列出 Node.js 在现代软件开发中的应用

+   描述 Node.js 使用的模块系统

+   为应用程序实现基本模块

+   解释 Node.js 中的异步编程基础

+   使用`async`/`await`实现基本应用

# Node.js 的基础知识

Node.js 是一个事件驱动的服务器端 JavaScript 环境。Node.js 使用由谷歌开发用于其 Chrome 浏览器的 V8 引擎来运行 JS。利用 V8 允许 Node.js 提供一个服务器端运行环境，以便以闪电般的速度编译和执行 JS。

Node.js 作为一个单线程进程运行，对*回调*进行操作，永远不会在主线程上阻塞，使其在 Web 应用程序中具有高性能。回调基本上是一个传递给另一个函数的函数，以便在该函数完成后可以调用它。我们将在以后的主题中研究这一点。这被称为**单线程事件循环模型**。其他 Web 技术主要遵循**多线程请求-响应**架构。

以下图表描述了 Node.js 的架构。正如您所看到的，它主要是由 JavaScript 层包装的 C++。我们不会详细介绍每个组件，因为这超出了本章的范围。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00005.gif)

Node 的目标是以一种简单而安全的方式在 JavaScript 中构建高性能和可扩展的网络应用程序。

# Node.js 的应用

Node.js 有以下四个主要应用：

+   **创建 REST API**：我们将在后续章节中更深入地研究这个问题

+   **创建实时服务**：由于 Node 的异步事件驱动编程，它非常适合*反应性*实时服务

+   **构建微服务**：由于 Node.js 的核心非常精简，最适合构建微服务，因为您只会添加实际需要的微服务依赖，而不是其他框架所带来的过剩

+   **工具**：例如，DevOps 自动化等

# 活动：运行基本的 Node.js 代码

**开始之前**

打开 IDE 和终端来实现这个解决方案。

**目标**

学习如何编写基本的 Node.js 文件并运行它。

**场景**

您正在编写一个非常基本的数学库，其中包含方便的数学函数。

**完成步骤**

1.  创建您的项目目录（文件夹），其中将保存本章和其他章节的所有代码。您可以称之为`beginning-nodejs`以简洁。在此目录中，创建另一个名为`lesson-1`的目录，在其中创建另一个名为`activity-a`的目录。所有这些都可以使用以下命令完成：

```js
mkdir -p beginning-nodejs/lesson-1/activity-a
```

1.  在`activity-a`中，使用`touch maths.js`命令创建一个文件。

1.  在此文件中，创建以下函数：

+   `add`：这需要任意两个数字并返回两者的和，例如，`add(2, 5)`返回`7`

+   `sum`：与`add`不同，它接受任意数量的数字并返回它们的总和，例如，`sum(10, 5, 6)`返回`21`

1.  在这些函数之后，编写以下代码作为代码的测试：

```js
console.log(add(10, 6)); // 16
console.log(sum(10, 5, 6)); // 21
```

1.  现在，在终端上，切换到`lesson-1`目录。这是我们在整个章节中将运行大部分代码的地方。

1.  要运行代码，请运行以下命令：

```js
node activity-a/math.js
```

`16`和`21`的值应该在终端上打印出来。

即使您可以配置 IDE，使 Node.js 代码可以通过单击按钮运行，但强烈建议您从终端运行代码，以了解 Node.js 的实际工作方式。

为了统一起见，如果您使用 Windows 机器，则从 Git Bash 终端运行命令。

对于参考解决方案，请使用`Code/Lesson-1/activity-solutions/activity-a`中的`math.js`文件。

# 模块系统

让我们来看看 Node 的模块系统和 Node.js 模块的不同类别。

# 应用程序模块化

像大多数编程语言一样，Node.js 使用模块来组织代码。模块系统允许您组织代码，隐藏信息，并且只使用`module.exports`公开组件的公共接口。

Node.js 使用 CommonJS 规范进行模块系统：

+   每个文件都是自己的模块，例如，在下面的示例中，`index.js`和`math.js`都是模块

+   每个文件都可以使用`module`变量访问当前模块定义

+   当前模块的导出由`module.exports`变量确定

+   要导入模块，请使用全局可用的`require`函数

让我们看一个简单的例子：

```js
// math.js file
function add(a, b) 
{
  return a + b;
}
…
…
module.exports = 
{
  add,
  mul,
  div,
};
// index.js file
const math = require('./math');
console.log(math.add(30, 20)); // 50
```

要调用其他函数，如`mul`和`div`，我们将使用对象解构作为导入模块时的替代方法，例如`const { add } = require('./math');`。

*模块系统*部分的代码文件放置在`Code/Lesson-1/b-module-system`中。

# 模块类别

我们可以将 Node.js 模块分为三类：

+   **内置（本地）模块**：这些是 Node.js 本身附带的模块；您不必单独安装它们。

+   **第三方模块**：这些通常是从软件包存储库安装的模块。 npm 是一个常用的软件包存储库，但您仍然可以在 GitHub、您自己的私有服务器等上托管软件包。

+   **本地模块**：这些是您在应用程序中创建的模块，就像之前给出的示例一样。

# 内置模块

如前所述，这些是可以直接使用而无需进一步安装的模块。您只需要导入它们。它们有很多，但我们将重点介绍一些在构建 Web 应用程序时可能会遇到的模块。

+   `assert`：提供一组断言测试，用于单元测试

+   `缓冲区`：处理二进制数据

+   `child_process`：运行子进程

+   `crypto`：处理 OpenSSL 加密函数

+   `dns`：进行 DNS 查找和名称解析函数

+   `events`：处理事件

+   `fs`：处理文件系统

+   `http`或`https`：用于创建 HTTP(s)服务器

+   `stream`：处理流数据

+   `util`：访问实用程序函数，如 deprecate（用于标记函数为已弃用）、format（用于字符串格式化）、inspect（用于对象调试）等

例如，以下代码使用内置的`fs`模块读取`lesson-1/temp/sample.txt`文件的内容：

```js
const fs = require('fs');
let file = `${__dirname}/temp/sample.txt`;
fs.readFile(file, 'utf8', (err, data) => 
{
  if (err) throw err;
  console.log(data);
});
```

此代码的详细信息将在本章后面讨论异步编程时解释。

# npm - 第三方模块注册表

**Node Package Manager**（**npm**）是 JavaScript 的软件包管理器和全球最大的软件注册表，使开发人员能够发现可重用代码的软件包。

要安装 npm 包，只需在项目目录中运行命令`npm install <package-name>`。我们将在接下来的两章中经常使用这个命令。

让我们看一个简单的例子。如果我们想在项目中使用`request`这样的软件包（库），我们可以在终端中运行以下命令，在项目目录中：

```js
npm install request
```

要在我们的代码中使用它，我们需要导入它，就像导入其他模块一样：

```js
const request = require('request');
request('http://www.example.com', (error, response, body) => 
{
  if (error) console.log('error:', error); // Print the error if one occurred
  else console.log('body:', body); // Print the HTML for the site.
});
```

有关 npm 的更多详细信息，请访问：[`docs.npmjs.com/`](https://docs.npmjs.com/)。最近，一个名为 YARN 的新软件包管理器发布了（[`docs.npmjs.com/`](https://docs.npmjs.com/)），它变得越来越受欢迎。

当您第一次在项目上运行`npm install <module-name>`命令时，`node_modules`文件夹将在项目的根目录下创建。

# 扫描 node_modules

值得注意的是 Node.js 如何解析特定的`required`模块。例如，如果文件`/home/tony/projects/foo.js`有一个 require 调用`require('bar')`，Node.js 按以下顺序扫描文件系统中的`node_modules`。找到的第一个`bar.js`将被返回：

+   /home/tony/projects/node_modules/bar.js

+   /home/tony/node_modules/bar.js

+   /home/node_module/bar.js

+   /node_modules/bar.js

Node.js 在当前文件夹中查找`node_moduels/bar`，然后在每个父文件夹中查找，直到达到当前文件系统树的根目录。

模块`foo/index.js`可以被要求为`foo`，而不需要指定`index`，并且将默认选择它。

# 方便的 npm 命令

让我们深入了解一下 npm，看一些你经常会使用的方便的 npm 命令：

+   npm init：初始化一个 Node.js 项目。这应该在项目的根目录运行，并将创建一个相应的`package.json`文件。这个文件通常有以下部分（键）：

+   `name`：项目的名称。

+   `version`：项目的版本。

+   `description`：项目描述。

+   `main`：项目的入口点，主文件。

+   `scripts`：这将是其他键的列表，其值将是要运行的脚本，例如，`test`，`dev-server`。因此，要运行此脚本，你只需要输入命令，如`npm run dev-server`，`npm run test`等。

+   `dependencies`：项目使用的第三方包及其版本列表。每当你执行`npm install <package-name> --save`时，此列表会自动更新。

+   `devDependencies`：不是生产必需品的第三方包列表，只在开发过程中使用。这通常包括帮助自动化开发工作流程的包，例如，类似 gulp.js 的任务运行器。每当你执行`npm install <package-name> --save-dev`时，此列表会自动更新。

+   `npm install`：这将安装`package.json`文件中指定的所有包。

+   `npm install <package-name> <options>`：

+   使用`--save`选项，安装包并将详细信息保存在`package.json`文件中。

+   使用`--save-dev`选项，安装包并将详细信息保存在`package.json`的`devDependencies`下。

+   使用`--global`选项，在整个系统中全局安装包，而不仅仅在当前系统中。由于权限问题，这可能需要以管理员权限运行命令，例如，`sudo npm install <package-name> --global`。

+   `npm install <package-name>@<version>`，安装包的特定版本。通常，如果未指定版本，将安装最新版本。

+   `npm list`：列出已为项目安装的包，从`node_modules`中安装的内容中读取。

+   `npm uninstall <package-name>`：移除已安装的包。

+   `npm outdated`：列出已过时的已安装包，即已发布更新版本的包。

# 本地模块

我们已经看过了如何从之前的示例中加载本地模块，其中包括`math.js`和`index.js`。

由于**JavaScript 对象表示**（**JSON**）在 Web 中是如此重要，Node.js 已完全将其作为数据格式采纳，甚至在本地也是如此。你可以从本地文件系统加载 JSON 对象，就像加载 JavaScript 模块一样。在模块加载序列期间，每当找不到`file.js`时，Node.js 都会寻找`file.json`。

查看`lesson-1/b-module-system/1-basics/load-json.js`中的示例文件：

```js
const config = require('./config/sample');
console.log(config.foo); // bar
```

在这里，你会注意到一旦*required*，JSON 文件会隐式地转换为 JavaScript 对象。其他语言可能要求你读取文件，或者使用不同的机制将内容转换为数据结构，比如映射、字典等。

对于本地文件，扩展名是可选的，但如果存在冲突，可能需要指定扩展名。例如，如果我们在同一个文件夹中有`sample.js`和`sample.json`文件，`.js`文件将被默认选择；最好指定扩展名，例如：`const config = require('./config/sample.json');`

当您运行`npm install`时，没有指定要安装的模块，npm 将安装项目中`package.json`文件中指定的包列表（在`dependencies`和`devDependencies`下）。如果`package.json`不存在，它将给出一个错误，指示未找到这样的文件。

# 活动：使用上一个 math.js 代码的第三方包

**开始之前**

这个活动将建立在本章的*运行基本 Node.js*活动之上。

**目标**

如果参数是一个数组，对数字求和，如果是多个数组，首先将数组合并成一个再求和。我们将使用`lodash`中的`concat()`函数，这是一个我们将安装的第三方包。

**场景**

我们想创建一个新的函数`sumArray`，它可以对一个或多个数组中的数字进行求和。

**完成步骤**

1.  在`Lesson-1`中，创建另一个名为`activity-b`的文件夹。

1.  在终端上，切换到`activity-b`目录并运行以下命令：

```js
npm init
```

1.  这将带您进入交互式提示符；只需一直按*Enter*，将答案留在建议的默认值。这里的目的是让我们得到一个`package.json`文件，这将帮助我们组织我们安装的包。

1.  由于我们将使用`lodash`，让我们安装它。运行以下命令：

```js
npm install lodash--save
```

请注意，我们在命令中添加了`--save`选项，以便在`package.json`中跟踪安装的包。当您打开步骤 3 中创建的`package.json`文件时，您将看到一个带有详细信息的`dependencies`键。

1.  在`activity-b`目录中创建一个`math.js`文件，并将*Activity*，*Running Basic Node.js*中的`math.js`代码复制到这个文件中。

1.  现在，在`sum`函数之后添加`sumArray`函数。

1.  从要求`lodash`开始，我们在步骤 4 中安装了它，因为我们将在`sumArray`函数中使用它：

```js
const _ = require('lodash');
```

1.  `sumArray`函数应该调用`sum`函数来重用我们的代码。提示：在数组上使用展开运算符。参见以下代码：

```js
function sumArray() 
{
  let arr = arguments[0];
  if (arguments.length > 1) 
  {
    arr = _.concat(...arguments);
  }
  // reusing the sum function
  // using the spread operator (...) since
  // sum takes an argument of numbers
  return sum(...arr);
}
```

1.  在文件末尾，使用`module.exports`导出三个函数，`add`，`sum`和`sumArray`。

1.  在相同的`activity-b`文件夹中，创建一个名为`index.js`的文件。

1.  在`index.js`文件中，*require* `./math.js`，然后继续使用`sumArray`：

```js
// testing
console.log(math.sumArray([10, 5, 6])); // 21
console.log(math.sumArray([10, 5], [5, 6], [1, 3])) // 30
```

1.  在终端上运行以下代码：

```js
node index.js
```

你应该看到`21`和`30`被打印出来。

解决方案文件放在`Code/Lesson-1/activitysolutions/activity-b`。

# 使用 Node.js 进行异步编程

让我们来看看 Node.js 工作原理的核心部分，即异步编程模型。

# 回调

回调是异步执行的函数，或者在以后的某个时间执行的函数。异步程序可能根据先前函数的顺序和速度在不同的时间执行不同的函数，而不是按顺序从上到下逐步执行代码。

由于 JavaScript 将函数视为任何其他对象，我们可以将一个函数作为参数传递给另一个函数，并执行传入的函数，甚至返回它以便以后执行。

我们之前在*模块系统*部分查看`fs`模块时看到了这样一个函数。让我们重新访问一下：

```js
const fs = require('fs');
let file = `${__dirname}/temp/sample.txt`;
fs.readFile(file, 'utf8', (err, data) => 
{
  if (err) throw err;
  console.log(data);
});
```

*使用 Node.js 进行异步编程*的代码文件放置在`Code/Lesson-1/c-async-programming`。

在第 3 行，我们使用`globals`的一个变量部分，`_ _dirname`，它基本上给了我们当前文件（`read-file.js`）所在的目录（文件夹）的绝对路径，从中我们可以访问`temp/sample.txt`文件。

我们讨论的主要内容是第 5 行到第 8 行之间的代码块。就像您将在 Node.js 中遇到的大多数方法一样，它们大多数都将回调函数作为最后一个参数。

大多数回调函数将接受两个参数，第一个是错误对象，第二个是结果。对于前面的情况，如果文件读取成功，错误对象`err`将为 null，并且文件的内容将在数据对象中返回。

让我们分解这段代码，以便更容易理解：

```js
const fs = require('fs');
let file = `${__dirname}/temp/sample.txt`;
const callback = (err, data) => 
{
  if (err) throw err;
  console.log(data);
};
fs.readFile(file, 'utf8', callback);
```

现在，让我们看看异步部分。让我们在前面的代码中添加一行额外的行：

```js
const fs = require('fs');
let file = `${__dirname}/temp/sample.txt`;
const callback = (err, data) => 
{
  if (err) throw err;
  console.log(data);
};
fs.readFile(file, 'utf8', callback);
console.log('Print out last!');
```

看看我们得到了什么打印输出：

```js
Print out last!
 hello,
 world
```

为什么`Print out last!`先出现？这就是异步编程的全部意义。Node.js 仍然在单个线程上运行，第 10 行以非阻塞方式执行并移动到下一行，即`console.log('Print out last!')`。由于前一行需要很长时间，下一行将首先打印。一旦`readFile`过程完成，它将通过回调打印出文件的内容。

# 承诺

承诺是传递异步计算结果的回调的替代方法。首先，让我们先看一下承诺的基本结构，然后简要地看一下使用承诺而不是普通回调的优势。

让我们用承诺重写上面的代码：

```js
const fs = require('fs');
const readFile = (file) => 
{
  return new Promise((resolve, reject) => 
  {
    fs.readFile(file, 'utf8', (err, data) => 
    {
      if (err) reject(err);
      else resolve(data);
    });
  });
}
// call the async function
readFile(`${__dirname}/../temp/sample.txt`)
  .then(data => console.log(data))
  .catch(error => console.log('err: ', error.message));
```

这段代码还可以通过使用`util.promisify`函数进一步简化，该函数采用遵循常见的 Node.js 回调样式的函数，即以`(err, value) => …`回调作为最后一个参数，并返回一个返回承诺的版本：

```js
const fs = require('fs');
const util = require('util');
const readFile = util.promisify(fs.readFile);
readFile(`${__dirname}/../temp/sample.txt`, 'utf8')
  .then(data => console.log(data))
  .catch(error => console.log('err: ', error));
```

从我们迄今为止所见，承诺提供了处理异步代码的标准方式，使其更易读一些。

如果您有 10 个文件，您想要读取它们吗？`Promise.all`来拯救。`Promise.all`是一个方便的函数，可以让您并行运行异步函数。它的输入是一组承诺；其输出是一个用结果数组满足的单个承诺：

```js
const fs = require('fs');
const util = require('util');
const readFile = util.promisify(fs.readFile);
const files = [
  'temp/sample.txt',
  'temp/sample1.txt',
  'temp/sample2.txt',
];
// map the files to the readFile function, creating an
// array of promises
const promises = files.map(file => readFile(`${__dirname}/../${file}`, 'utf8'));
Promise.all(promises)
  .then(data => 
  {
    data.forEach(text => console.log(text));
  })
  .catch(error => console.log('err: ', error));
```

# 异步/等待

这是 Node.js 的最新添加之一，早在 2017 年的 7.6 版本中就已经添加了，提供了一种更好的编写异步代码的方式，使其看起来和行为更像同步代码。

回到我们的文件*读取*示例，假设您想要获取两个文件的内容并按顺序连接它们。这是您可以使用`async`/`await`实现的方法：

```js
const fs = require('fs');
const util = require('util');
const readFile = util.promisify(fs.readFile);
async function readFiles() 
{
  const content1 = await readFile(`${__dirname}/../temp/sample1.txt`);
  const content2 = await readFile(`${__dirname}/../temp/sample2.txt`);
  return content1 + '\n - and - \n\n' + content2;
}
readFiles().then(result => console.log(result));
```

总之，任何返回承诺的异步函数都可以*等待*。

# 活动：使用异步函数转换文本文件

开始之前

您应该已经完成了之前的活动。

目标

读取文件（使用`fs.readFile`），`in-file.txt`，正确格式化名称（使用`lodash`函数`startCase`），然后按字母顺序对名称进行排序，并将它们写入到单独的文件`out-file.txt`（使用`fs.writeFile`）。

场景

我们有一个文件`in-file.txt`，其中包含人们的名字列表。一些名字没有正确的大小写格式，例如，`john doe`应更改为`John Doe`。

完成步骤

1.  在`Lesson-1`中，创建一个名为`activity-c`的文件夹。

1.  在终端上，切换到`activity-c`目录并运行以下命令：

```js
npm init
```

1.  就像在以前的活动中一样，这将带您进入交互提示符；只需按照建议的默认值一路按*Enter*。这里的目的是让我们获得一个`package.json`文件，这将帮助我们组织我们安装的软件包。

1.  由于我们这里也将使用`lodash`，让我们安装它。运行`npm install lodash --save`。

1.  将`student-files`目录中提供的`in-file.txt`文件复制到您的`activity-c`目录中。

1.  在您的`activity-c`目录中，创建一个名为`index.js`的文件，您将在其中编写您的代码。

1.  现在，继续实现一个`async`函数`transformFile`，它将接受文件路径作为参数，按照之前描述的方式进行转换，并将输出写入作为第二个参数提供的输出文件。

1.  在终端上，您应该指示何时正在阅读、写作和完成，例如：

+   “读取文件：in-file.txt”

+   “写入文件：out-file.txt”

+   完成

您应该阅读有关`fs.writeFile`的快速参考文档，因为我们还没有使用它。但是，您应该能够看到它与`fs.readFile`的相似之处，并将其转换为一个 promise 函数，就像我们之前所做的那样。

解决方案文件放置在`Code/Lesson-1/activitysolutions/activity-c`中。

# 摘要

在本章中，我们快速概述了 Node.js，看到了它在幕后的样子。

我们编写了基本的 Node.js 代码，并使用 Node.js 命令从终端运行它。

我们还研究了 Node.js 的模块系统，学习了 Node.js 模块的三个类别，即内置模块、第三方模块（从 npm 注册表安装）和本地模块，以及它们的示例。我们还看了 Node.js 在*require*模块时如何解析模块名称，通过在各个目录中搜索来实现。

然后，我们通过查看 Node.js 工作方式的异步编程模型来结束，这实际上是 Node.js 运行的核心。我们看了您可以编写异步代码的三种主要方式：使用*callbacks*、*Promises*和

新的*async/await*范式。

现在我们已经为使用 Node.js 实现我们的 API 奠定了基础。在构建 API 时，这些概念中的大部分将再次出现。


# 第二章：构建 API - 第一部分

本章旨在介绍使用 Node.js 构建 API。我们将从构建基本的 HTTP 服务器开始，以了解 Node.js 的工作原理。

在本章结束时，您将能够：

+   使用 Node.js 内置的`http`模块实现一个基本的 HTTP 服务器

+   为 API 实现基本的 Hapi.js 设置

+   描述基本的 HTTP 动词及其之间的区别

+   实现使用不同的 HTTP 动词为 API 实现各种路由

+   实现记录 Web 应用程序

+   验证 API 请求

# 构建一个基本的 HTTP 服务器

让我们首先来看一下 Node.js Web 应用程序的基本构建块。内置的`http`模块是其核心。但是，从以下示例中，您还将欣赏到这有多么基本。

将以下代码保存在名为`simple-server.js`的文件中：

```js
const http = require('http');
const server = http.createServer((request, response) => 
{
  console.log('request starting...');
  // respond
  response.write('hello world!');
  response.end();
});
server.listen(5000);
console.log('Server running at http://127.0.0.1:5000');
```

使用`Code/Lesson-2`中的`simple-server.js`文件作为参考。

现在，让我们运行这个文件：

```js
node simple-server.js
```

当我们在浏览器中访问示例中的 URL 时，我们会得到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00006.jpeg)

# 设置 Hapi.js

**Hapi.js**（**HTTP API**），是一个用于构建应用程序和服务的丰富框架，专注于编写可重用的应用程序逻辑。还有许多其他框架；其中值得注意的是 Express.js。但是，从头开始，Hapi.js 被优化用于构建 API，我们将在构建应用程序时很快看到这一点。

# 练习 1：构建一个基本的 Hapi.js 服务器

在这个练习中，我们将构建一个基本的 HTTP 服务器，就像之前那样，但现在使用 Hapi.js。您会注意到大部分事情都是在 Hapi.js 的幕后为我们完成的。但是，Hapi.js 也是建立在`http`模块之上的。

对于接下来的练习，从第三章的第一个练习，《构建 API - 第二部分》，我们将在每个练习中逐步构建。因此，我们可能需要返回并修改以前的文件等：

1.  在您的`Lesson-2`文件夹中，创建一个名为`hello-hapi`的子文件夹。

使用`Code/Lesson-2`中的`exercise-b1`文件夹作为参考。

1.  在终端上，切换到`hello-hapi`文件夹的根目录。

1.  将其初始化为一个基本的 Node.js 项目，并运行以下命令：

```js
npm init -y
```

1.  创建一个名为`server.js`的文件。

1.  通过执行以下命令安装 Hapi.js：

```js
npm install hapi --save
```

1.  在文件中，编写以下代码：

```js
const Hapi = require('hapi');
// create a server with a host and port
const server = new Hapi.Server();
server.connection
({
  host: 'localhost',
  port: 8000,
});
// Start the server
server.start((err) => 
{
  if (err) throw err;
  console.log(`Server running at: ${server.info.uri}`);
});
```

使用`Code/Lesson-2/exercise-b1`中的`server.js`文件作为参考。

让我们试着理解这段代码：

+   我们首先通过要求我们刚刚包含的 Hapi.js 框架来开始。

回想一下我们的子主题，《模块系统》，在第一章，《Node.js 简介》中？我们看了第三方模块——这是其中之一。

+   然后我们通过初始化 Server 类来创建一个服务器，因此是一个新的`Hapi.Server()`。

+   然后将该服务器绑定到特定的主机（`localhost`）和端口（`8000`）。

+   之后，我们创建一个示例路由，`/`。正如您所看到的，对于每个创建的路由，我们必须指定三个主要内容（作为传递给`server.route`方法的对象的键）：

+   `method`：这是该路由的 HTTP 方法。我们将在后面的部分更深入地了解 HTTP 动词的类型。对于我们的示例，我们使用 GET。基本上，正如名称所示，这会从服务器获取资源。

+   `path`：这是服务器上到达特定资源的路径。

+   `handler`：这是一个执行实际获取操作的闭包（匿名函数）。

我们将在我们的主项目中查看另一个额外的关键字，称为`config`。

+   完成此设置后，我们使用`server.start`方法启动服务器。该方法接受一个闭包（回调函数），一旦服务器启动，就会调用该函数。在此函数中，我们可以检查启动服务器时是否发生了任何错误。

1.  通过转到终端并运行以下命令来运行服务器：

```js
node server.js
```

1.  您应该在终端上看到这个打印出来：

```js
Server running at: http://localhost:8000
```

您应该在`http://localhost:8000`看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00007.jpeg)

打开另一个终端，更改目录到相同的项目文件夹，并运行相同的命令，`node server.js`。我们会收到此错误：`Error: listen EADDRINUSE 127.0.0.1:8000`。

我们收到此错误的原因是因为我们的主机上只能运行一个特定端口的服务器。请记住，主机 IP`127.0.0.1`是我们所谓的`localhost`。`if (err) throw err;`是抛出错误的行。

我们可以通过将第二个服务器的端口号更改为`8001`之类的内容来解决此问题。但是，最佳实践是，除了不断更改代码之外，我们可以将端口号作为终端参数传递，即运行应用程序为`node server.js <port-number>`，然后更改我们的代码（在`port`部分）为`port: process.argv[2] || 8000,`。

在这里，我们说，如果端口作为脚本的第一个参数提供，那么使用该端口，否则使用`8000`作为端口号。现在，当您运行：`node server.js 8002`时，服务器应该从`localhost:8002`正常运行。

对于`process.argv`数组，索引`0`是运行脚本的程序，node 和索引`1`是正在运行的脚本，`server.js`。因此，传递给脚本的参数从索引`2`开始计算。您可以稍后在这里阅读有关`process.argv`的更多信息。

# 使用 API 客户端

为了充分利用客户端，能够执行所有请求类型（`GET`，`POST`，`UPDATE`等），我们需要一个 API 客户端。有很多选择，但我们建议使用 Postman ([`www.getpostman.com/`](https://www.getpostman.com/))或 Insomnia ([`insomnia.rest/`](https://insomnia.rest/))。在我们的示例中，我们将使用 Insomnia。

安装 Insomnia 后，添加一个 GET 请求到`http://localhost:8000`：

1.  我们将首先创建一个用于 Insomnia 的*请求*页面，我们将在其中进行所有请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00008.jpeg)

为新请求输入名称：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00009.jpeg)

1.  然后，我们将通过输入路由并单击发送来发出我们的请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00010.jpeg)

当我们将类型从 GET 更改为 POST 并单击发送时，我们会收到 404 错误，因为在我们的服务器上，我们目前只为路由`/`定义了 GET 方法。

# 返回 JSON 字符串

由于我们现在正在构建我们的 API，我们需要一种正式的方式来表示我们的请求中的数据，通过发送或接收它。**JavaScript 对象表示法**（**JSON**）是 REST API 的传统数据交换格式。

关于 JSON 的一件事需要注意的是，它起源于 JavaScript，现在已被广泛采用于其他语言。因此，当涉及到 Node.js 时，您将看到如何使用 JSON 变得如此简单和自然。

# 练习 2：返回 JSON

1.  让我们回到我们的`server.js`文件，从*练习 1*，*构建基本的 Hapi.js* *服务器*。

使用`exercise-b2`文件夹作为`Code/Lesson-2`的参考。

1.  要为我们的`/`路由返回 JSON，我们需要更改的只是我们返回的字符串为一个对象：

```js
handler: (request, reply) => 
{
  return reply({ message: 'hello, world' });
}
```

1.  通过转到运行服务器的终端并按下*Ctrl* + *C*来停止服务器。然后，通过运行以下命令再次启动服务器以生效更改：

```js
node server.js
```

1.  现在返回到 Insomnia 并进行另一个 GET 请求。您可以看到这实际上已更改为 JSON 字符串：

```js
{
  "message": "hello, world"
}
```

这在 Hapi.js 中是开箱即用的，而在某些框架中，例如 Express.js，您必须使用`json`函数进行转换。

# 使用 nodemon 进行开发工作流

您可能已经注意到，在第一个练习中进行更改后，我们不得不返回并停止服务器，然后重新开始。每次更改代码时都这样做变得非常麻烦。幸运的是，工具可以拯救我们。

有一个名为`nodemon`的 Node.js 包，它可以在我们的文件发生更改时自动帮助重新启动服务器。

# 练习 3：使用 nodemon

在这个练习中，我们将介绍一个名为`nodemon`的 Node 模块，我们将使用它来运行我们的 Web 服务器。这使得服务器在我们对其进行更改时可以自动重新加载，因此避免了在我们对服务器进行更改时手动停止服务器并重新启动服务器的繁琐过程：

1.  返回终端并停止服务器（按*Ctrl + C*），然后运行以下命令。

1.  我们需要全局安装这个包（记住您可能需要一些管理权限，所以在 Unix 系统中，您需要以`sudo`身份运行命令）：

```js
npm install --global nodemon
```

1.  安装完成后，我们可以使用`nodemon`运行：

```js
nodemon server.js
```

你应该会得到类似这样的东西：

```js
[nodemon] 1.12.1
[nodemon] to restart at any time, enter `rs`
[nodemon] watching: *.*
[nodemon] starting `node server.js`
Server running at: http://localhost:8000
```

# 设置日志记录

日志记录是任何 Web 应用程序的非常重要的组成部分。我们需要一种方式来保存服务器的历史记录，以便我们随时可以回来查看它是如何处理请求的。

最重要的是，您不希望日志记录成为事后才考虑的事情，只有在您遇到生产错误时才实施，这会使您的 Web 应用程序在您试图找出问题所在时崩溃。

Hapi.js 内置了最小的日志功能，但如果您需要一个广泛的日志功能，一个很好的例子叫做**good**（[`github.com/hapijs/good`](https://github.com/hapijs/good)）。

# 练习 4：设置日志记录

在这个练习中，我们将在我们创建的 Web 服务器上添加一个日志记录机制，以便可以通过日志轻松跟踪每个请求和服务器活动：

1.  让我们回到*练习 2：返回 JSON*的项目。

使用`Code/Lesson-2`中的`exercise-b4`文件夹作为参考。

1.  我们首先需要安装一些将帮助我们记录日志的包（`good`和`good-console`）。运行以下命令：

```js
npm install --save good good-console 
```

`good-console`是我们称之为写入流的东西。有其他与 good 一起工作的写入流，但为简单起见，我们不会去看它们。您可以查看[`github.com/hapijs/good`](https://github.com/hapijs/good)获取更多信息。

1.  然后，我们将修改我们的`server.js`代码来配置我们的日志记录。首先，在 Hapi.js 之后要求好：

```js
const Hapi = require('hapi');
const good = require('good');
```

1.  然后，在启动服务器之前将其注册到服务器上：

```js
// set up logging
const options = {
  ops: {
    interval: 100000,
  },
  reporters: {
    consoleReporters: [
    { module: 'good-console' },
    'stdout',
…
});
```

使用`Code/Lesson-2/exercise-b4`中的`server.js`文件作为参考。

1.  如果您仍在使用`nodemon`运行服务器，现在您将开始在终端上定期看到服务器日志被更新；类似于：

```js
171102/012027.934, [ops] memory: 34Mb, uptime (seconds):
100.387, load: [1.94580078125,1.740234375,1.72021484375]
171102/012207.935, [ops] memory: 35Mb, uptime (seconds):
200.389, load: [2.515625,2.029296875,1.83544921875]
...
```

1.  现在，返回 Insomnia 并尝试在`localhost:8000/`上进行另一个 GET 请求。您将看到已创建一个额外的日志，显示了请求的时间（`时间戳`），路由，方法（`get`），状态代码（`200`）以及请求所花费的时间：

```js
171102/012934.889, [response] http://localhost:8000: get /{} 200 (13ms)
```

当您尝试优化服务器的性能时，所花费的时间非常有用，可以看到哪些请求花费的时间比预期的长。

# 理解请求

让我们来看看请求的概念和不同的 HTTP 请求方法。

# 查看 HTTP 请求方法

设置好服务器后，我们准备开始构建我们的 API。路由基本上构成了实际的 API。

我们将首先查看 HTTP 请求方法（有时称为*HTTP 动词*），然后使用一个简单的*待办事项列表*示例将它们应用到我们的 API 中。我们将查看五个主要的方法：

+   `GET`：请求指定资源的表示。使用`GET`的请求应该只检索数据，不应该用于对资源进行更改。

+   `POST`：用于向指定资源提交条目，通常会导致状态的改变。

+   `PUT`：用请求有效负载替换目标资源的所有当前表示。

+   `DELETE`：删除指定的资源。

+   `PATCH`：用于对资源应用部分修改。

在接下来的练习中，我们将重写之前的代码，其中我们已经将数据硬编码，以便我们可以使用直接来自数据库的真实和动态数据进行操作。

# 练习 5：获取资源列表

1.  让我们回到*练习 4：设置日志记录*的项目。

使用`exercise-c1`文件夹作为你在`Code/Lesson-2`的参考。

1.  因为我们将有各种路由，现在将路由分割到一个单独的文件中以便组织是明智的。在项目中，创建一个名为`routes`的子文件夹。

1.  在创建的文件夹中，创建一个名为`todo.js`的文件。在`todo.js`中，这是我们将为`todo`资源拥有所有路由的地方。这个文件（模块）将导出一个路由列表。

1.  让我们从一个简单的路由开始，它在`GET`请求上返回一个待办事项列表：

```js
const todoList = [
  {
    title: 'Shopping',
    dateCreated: 'Jan 21, 2018',
    list: [
    { 
      text: 'Node.js Books', done: false },
      ...
    ]
  },
  {
];
```

使用`todo.js`文件作为你在`Code/Lesson-2/exercise-c1/routes`的参考。

1.  然后我们回到我们的`server.js`文件，要求`todo`路由模块，并使用`server.route`方法在服务器上注册它：

```js
const routes = {};
routes.todo = require('./routes/todo')
// create a server with a host and port
const server = new Hapi.Server();
server.connection(
{
  host: 'localhost',
  port: process.argv[2] || 8000,
});
server.route(routes.todo);
```

使用`server.js`文件作为你在`Code/Lesson-2/exercise-c1`的参考。

1.  使用 Insomnia，对`http://localhost:8000/todo`发出`GET`请求。你应该看到这个返回：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00011.jpeg)

# 练习 6：获取特定资源

1.  现在，让我们尝试获取一个特定的待办事项。因为我们没有带有 ID 的数据库，我们将把索引视为 ID，`[0]`为`1`，依此类推。

使用`exercise-c1`文件夹作为你在`Code/Lesson-2`的参考。

1.  让我们为此添加一个路由。注意我们使用`{<parameter-key>}`作为将请求参数传递给我们的`route`函数的一种方式，然后通过`request.params.id`获取它：

```js
module.exports = [
 {
 method: 'GET',
 path: '/todo',
 ...
 handler: (request, reply) => {
 const id = request.params.id - 1; 
 // since array is 0-based index
 return reply(todoList[id]);
 }
 },
];
```

使用`todo.js`文件作为你在`Code/Lesson-2/exercise-c1/routes`的参考。

1.  转到 Insomnia，对`http://localhost:8000/todo/1`发出`GET`请求。你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00012.jpeg)

# 练习 7：使用 POST 创建新的待办事项

1.  现在让我们添加一个新的待办事项。这就是`POST`的用武之地。`POST`请求应该始终带有一个负载，这是被*发布*的数据。我们将添加一个新的路由来处理这个：

```js
module.exports = [
  // previous code
  {
    method: 'POST',
    path: '/todo',
    handler: (request, reply) => {
      const todo = request.payload;
      todoList.push(todo);
      return reply({ message: 'created' });
    …
];
```

使用`todo.js`文件作为你在`Code/Lesson-2/exercise-c1/routes`的参考。

1.  关于失眠：

1.  将请求类型改为 POST：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00013.jpeg)

+   1.  将请求体改为 JSON：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00014.jpeg)

+   1.  适当添加请求体和 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00015.jpeg)

1.  当你发送请求时，你应该看到这个作为响应：

```js
{
  "message": "created"
}
```

1.  现在，当你对`http://localhost:8000/todo`发出`GET`请求时，你应该看到新创建的待办事项出现在响应中：

```js
[
...
  {
    "title": "Languages to Learn",
    "dateCreated": "Mar 2, 2018",
```

```js
    "list": 
     [
       "C++",
       "JavaScript"
    ]
  }
]
```

# 练习 8：使用 PUT 更新资源

1.  如果我们想要更新，比如说，第一个待办事项列表，按照惯例，`PUT`要求我们发送整个更新后的待办事项资源。现在让我们创建一个`PUT`路由：

```js
{
  method: 'PUT',
  path: '/todo/{id}',
  handler: (request, reply) => {
    const index = request.params.id - 1;
    // replace the whole resource with the new one
    todoList[index] = request.payload;
    return reply({ message: 'updated' });
  }
}
```

使用`todo.js`文件作为你在`Code/Lesson-2/exercise-c1/routes`的参考。

1.  现在去 Insomnia 发出请求。记得把请求类型改为 PUT：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00016.jpeg)

1.  你应该看到以下响应：

```js
{
  "message": "updated"
}
```

1.  当你在`http://localhost:8000/todo/1`上执行`GET`时，你应该得到更新后的资源：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00017.jpeg)

# 练习 9：使用 PATCH 更新

1.  你会意识到，在我们之前的练习中，我们不得不发布整个资源才能改变其中的一部分。这样做的更好方法是使用`PATCH`，这样负载只包含所需的内容。现在让我们创建一个`PATCH`路由：

```js
{
  method: 'PATCH',
  handler: (request, reply) => 
  {
    …
    Object.keys(request.payload).forEach(key => 
    {
      if (key in todo) 
      {
        todo[key] = request.payload[key];
        …
    return reply({ message: 'patched' });
    },
}
```

使用`todo.js`文件作为你在`Code/Lesson-2/exercise-c1/routes`的参考。

1.  现在，你可以提供任何键和它们的值，它们将分别更新。例如，发出以下请求，只改变第一个待办事项的标题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00018.jpeg)

1.  你应该得到以下响应：

```js
{
  "message": "patched"
}
```

1.  当你在`http://localhost:8000/todo/1`上执行`GET`时，你应该得到更新后的资源：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00019.jpeg)

# 练习 10：使用 DELETE 删除资源

1.  当我们想要删除一个资源时，我们使用`DELETE`方法。让我们创建一个`DELETE`路由：

```js
{
  method: 'DELETE',
  path: '/todo/{id}',
  handler: (request, reply) => {
    const index = request.params.id - 1;
    delete todoList[index]; // replaces with `undefined`
    return reply({ message: 'deleted' });
  },
},
```

使用`exercise-c1`文件夹作为你在`Code/Lesson-2`的参考。

1.  现在去 Insomnia 测试一下——你应该得到这个响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00020.jpeg)

1.  现在尝试访问先前删除的资源-您应该会收到`404`错误。但是，在我们之前的`GET`路由（在*练习 6：获取特定资源*中），我们没有考虑到这一点，所以让我们去修改我们的`GET：/todo/{id}路由`：

```js
{
  method: 'GET',
  path: '/todo/{id}',
  handler: (request, reply) => 
  {
    const id = request.params.id - 1;
    // should return 404 error if item is not found
    if (todoList[id]) return reply(todoList[id]);
    return reply({ message: 'Not found' }).code(404);
  }
}
```

在`Code/Lesson-2/exercise-c1/routes`中使用`todo.js`文件作为您的参考。

如果您从未遇到过状态码`404`，请不要担心。我们将在本节的最后一个小节中介绍主要的状态码。

1.  请记住，服务器将重新加载，因此已删除的资源仍将被带回，因此返回并重复*步骤 2*。

1.  现在，当您对`http://localhost:8000/todo/1`进行`GET`请求时，您应该看到这个：

```js
{
  "message": "Not found"
}
```

关于 Insomnia 的简短结语

您应该能够在历史记录下找到所有以前的请求。单击右上角的时间图标。

# 请求验证

我们需要验证传入的请求，以确保它们符合服务器可以处理的内容。

这是我看到 Hapi.js 在其他框架上闪耀的地方之一。在 Hapi.js 中，您可以将验证作为`route`对象的一部分的配置对象来挂钩。对于验证，我们将使用 Joi 库，它与 Hapi.js 很好地配合。

# 练习 11：验证请求

在这个练习中，我们将看到*请求验证*的概念。我们将为其中一个路由编写一个示例验证，但同样的方法也可以应用于其他路由：

1.  例如，如果我们回到*练习 1：构建基本的 Hapi.js 服务器*中的`POST`路由，我们可以发布一个空的有效载荷，仍然可以获得状态码`200！`显然，我们需要一种验证的方法。

1.  让我们从安装 Joi 开始：

```js
npm install joi --save
```

在`Code/Lesson-2`的`exercise-c2`文件夹中使用。

1.  在`routes/todo.js`文件中，我们需要要求 Joi，然后通过向`route`对象添加`config.validate`键来修改我们的 post 路由：

```js
{
  method: 'POST',
  path: '/todo',
  handler: (request, reply) => 
  {
    const todo = request.payload;
    todoList.push(todo);
    return reply({ message: 'created' });
  },
...
},
```

在`Code/Lesson-2/exercise-c1/routes`中使用`todo.js`文件作为您的参考。

1.  当我们尝试提交一个空的有效载荷时，我们现在会收到错误`400`：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00021.jpeg)

1.  这样，直到我们为待办事项提供一个标题，因为标题是必需的：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00022.jpeg)

Joi 是一个功能齐全的验证库，有许多选项可供使用。在这个练习中，我们只是涉及了一个基本的例子。

您可以通过在验证键及其相应类型中提出相应的键/值对来验证请求的任何部分：

`有效载荷`（用于请求有效载荷，如前面的练习中），`params`（用于请求参数）和`query`（用于查询参数）。

例如，对于请求`GET：/todo/:id`，如果我们想验证 ID 是否为整数，我们将添加这个`config`对象：

`config: {`

`  验证：

{`

`    params：

{`

`      id: Joi.number()`

`    }`

`  }

}`

有关 Joi 的更多详细信息，请访问：[`github.com/hapijs/joi`](https://github.com/hapijs/joi)。

# 总结

本章介绍了使用 Node.js 构建 API 的初始部分。我们首先查看了仅使用内置的 HTTP 模块构建的基本 HTTP 服务器，以便我们能够欣赏 Node.js Web 应用程序的基本构建块。然后我们介绍了使用 Hapi.js 框架做同样的事情。

然后，我们通过示例讨论了各种 HTTP 动词（请求方法），并使用 Hapi.js 构建了我们的基本 API。这些是`GET`，`POST`，`PUT`，`PATCH`和`DELETE`。

我们还介绍了一些 Web 应用程序的基本概念，如日志记录，使用良好的请求验证和 Joi 的使用。


# 第三章：构建 API - 第二部分

本章旨在重新审视以前的实现，这次将我们的数据保存在持久存储（数据库）中。它还将涵盖身份验证，单元测试和托管作为额外的值得了解的概念（但不是必要的）。因此，更加注重使用 knex.js 处理数据库和使用 JWT 对 API 进行身份验证。

在本章结束时，您将能够：

+   使用 Knex.js 实现数据库连接

+   描述常用的 Knex.js 方法

+   使用 Knex.js 重写我们以前的 todo 路由实现

+   使用 JWT 实现 API 身份验证

+   描述为 API 编写单元测试的重要性

+   使用 Lab 对 API 进行基本测试

# 使用 Knex.js 处理数据库

在本节中，我们将介绍与数据库一起工作的基本概念。我们将继续从以前的 todo 项目逐步构建。您可能已经注意到，我们上一个项目中，我们将信息存储在计算机内存中，并且一旦服务器返回，它就会立即消失。在现实生活中，您将希望将这些数据持久存储以供以后访问。

那么，什么是 Knex.js？它是用于关系数据库的 SQL 查询构建器，如 PostgreSQL，Microsoft SQL Server，MySQL，MariaDB，SQLite3 和 Oracle。基本上，使用类似 Knex 的东西，您可以编写一段代码，可以轻松地与提到的任何数据库中的任何一个工作，而不需要额外的努力，只需切换配置。

让我们在解释概念的同时进行练习。

# 练习 12：设置数据库

让我们回到我们在第二章的*练习 11：验证请求*中停下的地方。在这个例子中，我们将使用 MySQL 作为我们的首选数据库。确保您的计算机已设置为使用 MySQL 和 MySQL Workbench：

使用`Code/Lesson-3/exercise-a`文件夹作为参考。

1.  打开 MySQL Workbench。点击+按钮创建一个连接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00023.jpeg)

1.  将连接名称添加为`packt`，用户名添加为`root`，密码（如果有）。点击“测试连接”以查看连接是否正确，然后点击“确定”：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00024.jpeg)

1.  点击确定以创建连接。

1.  现在，点击连接，packt：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00025.jpeg)

1.  通过运行以下查询来创建 todo 数据库，并点击执行图标：

```js
CREATE DATABASE todo;
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00026.jpeg)

1.  本章的文件包含了我们的 todo 示例项目的基本 SQL 模式，几乎与我们在以前的练习中使用的基本 JavaScript 数组类似：

1.  在`Code/Lesson-3`文件夹中，有一个名为`raw-sql.sql`的文件。用您的代码编辑器打开文件并复制文件的内容。

1.  然后，回到 MySQL Workbench。

1.  将您从文件中复制的内容粘贴到文本框中，然后点击执行图标：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00027.jpeg)

1.  1.  当您点击 SCHEMAS 标签右侧的刷新图标并点击表时，您应该会看到创建的表（`todo`，`todo_item`，`user`）的列表如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00028.jpeg)

# 练习 13：连接到数据库

现在我们已经创建了数据库，在这个练习中，我们将使用必要的 npm 包（即`knex`和`mysql`）将我们的应用程序连接到我们的数据库：

1.  在终端上，切换到我们项目的根目录，并运行以下命令：

```js
npm install mysql knex --save
```

1.  让我们创建一个名为`db.js`的文件，并添加以下代码，根据需要适当替换用户和密码：

```js
const env = process.env.NODE_ENV || 'development';
const configs = 
{
  development: 
  {
    client: 'mysql',
    ...
    const Knex = require('knex')(configs[env]);
    module.exports = Knex;
```

您可以在`Code/Lesson-3/exercise-a`中找到`db.js`文件的完整代码。

1.  让我们测试一下我们的配置是否正确。我们将创建一个`test-db.js`文件：

```js
const Knex = require('./db');
Knex.raw('select 1+1 as sum')
.catch((err) => console.log(err.message))
.then(([res]) => console.log('connected: ', res[0].sum));
```

1.  现在，让我们转到终端并运行测试文件：

```js
node test-db.js
```

您应该会得到以下打印：

```js
connected: 2
```

# 练习 14：创建记录

在这个练习中，我们将编写代码来保存 todo 及其*项目*。首先，让我们创建一个虚拟用户，因为我们将在代码中硬编码用户 ID。稍后，在*练习 19：保护所有路由*中，我们将从身份验证详细信息中选择 ID：

1.  返回 MySQL Workbench。 

1.  清除先前的查询并粘贴以下查询，并单击执行图标：

```js
USE todo;
INSERT INTO 'user' ('id', 'name', 'email', 'password')
VALUES (NULL, 'Test User', 'user@example.com',
MD5('u53rtest'));
```

1.  当您点击用户表时，您应该看到以下内容；我们新创建的用户的 ID 为`1`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00029.jpeg)

1.  现在，让我们转到我们的路由文件，`/routes/todo.js`，并修改代码，对于`POST: /todo`路由；将代码更改为如下（只有`handler`正在更改，注意更改为`async`函数）：

1.  让我们从`./db.js`中要求我们的 Knex 实例开始。在要求 Joi 的行后面，添加这个：

```js
const Knex = require('../db');
```

注意两个点，`../db.js`，因为`db.js`在父文件夹中。回想一下我们在第一章中关于在 Node.js 中要求本地模块的主题，*Node.js 简介*。

1.  1.  现在，让我们修改`POST: /todo`路由的处理程序。在这里，我们使用`Knex.insert`方法，并添加一个可选的`.returning`方法，以便我们得到添加的`todo`的 ID：

```js
{
  method: 'POST',
  path: '/todo',
  handler: async (request, reply) => 
  {
    const todo = request.payload;
    todo.user_id = 1; // hard-coded for now
    // using array-destructuring here since the
    // returned result is an array with 1 element
    const [ todoId ] = await Knex('todo')
      .returning('id')
      .insert(todo);
...
  }
},
```

您可以在`Code/Lesson-3/exercise-a/routes`的`todo.js 文件`中找到完整的代码。

与我们在第二章中的先前练习不同，*构建 API - 第一部分*，我们将把`POST: /todo`路由拆分为两个，`POST: /todo`，用于添加 todo 列表，以及`POST: /todo/<id>/item`，用于向列表添加项目。

1.  现在，让我们测试我们新创建的端点。如果您已经停止了服务器，请返回终端并使用`nodemon`再次启动它：

```js
nodemon server.js
```

1.  转到 Insomnia 并进行 post 请求；您应该会得到类似这样的东西（注意返回的`todo_id`，因为我们将在下一个示例中使用它）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00030.jpeg)

1.  现在，让我们添加一个用于添加 todo 项目的路由，`POST: /todo/<id>/item`；因此，在上一个`route`对象旁边，添加这个`route`对象：

```js
{
  method: 'POST',
  path: '/todo/{id}/item',
  handler: async (request, reply) => 
  {
    const todoItem = request.payload;
    todoItem.todo_id = request.params.id;
    const [ id ] = await Knex('todo_item')
      .insert(todoItem);
    return reply({ message: 'created', id: id });
...
},
```

您可以在`Code/Lesson-3/exercise-a/routes`的`todo.js`文件中找到完整的代码。

1.  现在，让我们测试路由，`/todo/1/item`，`1`是我们在步骤 6 中创建的`todo`的 ID：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00031.jpeg)

# 练习 15：从数据库中读取

在这个练习中，我们将编写以下路由：

+   列出特定用户的所有`todo`

+   获取单个 todo 项目的详细信息

+   列出特定 todo 的项目

我们将使用一些`Knex`方法：

+   `Knex('<table_name>')`，这相当于'`SELECT * FROM <table_name>`'

+   `.where()`，用于向查询添加 where 子句

1.  要获取所有 todo 的列表，我们将修改之前的`GET: /todo`路由。在这里，您只想列出特定认证用户的 todo 项目。现在，我们将使用我们硬编码的测试用户：

```js
{
  method: 'GET',
  path: '/todo',
  handler: async (request, reply) => 
  {
    const userId = 1; // hard-coded
    const todos = await Knex('todo')
      .where('user_id', userId);
    return reply(todos);
  },
},
```

1.  让我们修改获取单个`todo`项目的路由，`GET: /todo/<id>`：

```js
{
  method: 'GET',
  path: '/todo/{id}',
  ...
    .where({
    id: id,
    user_id: userId
    });
  if (todo) return reply(todo);
  return reply({ message: 'Not found' }).code(404);
  },
},
```

您可以在`Code/Lesson-3/exercise-a/routes`的`todo.js`文件中找到完整的代码。

我们在这里也使用了数组解构，因为结果（如果有）将是长度为 1 的数组，所以我们从数组中获取第一个且唯一的元素：`const [ todo ] = ...`

1.  现在，让我们添加用于获取特定`todo`的项目列表的路由对象，最好是在我们在*练习 14：创建记录*中添加`todo`项目的路由之后：

```js
{
  method: 'GET',
  path: '/todo/{id}/item',
  handler: async (request, reply) =>
  {
    const todoId = request.params.id;
    const items = await Knex('todo_item')
      .where('todo_id', todoId);
    return reply(items);
  },
},
```

1.  现在，让我们测试路由：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00032.jpeg)

# 练习 16：更新记录

在这个练习中，我们将编写用于更新 todo 标题或 todo 项目的路由，这里我们将介绍一个新的 Knex 方法`.update()`：

1.  让我们从修改之前的`PATCH: /todo/<id>`路由开始。我们还添加了额外的验证，以确保`title`作为`payload`提供：

```js
{
  method: 'PATCH',
  path: '/todo/{id}',
  ...
    title: Joi.string().required(),
    }
  }
  }
},
```

1.  让我们测试路由：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00033.jpeg)

1.  现在，让我们为`/todo/<id>/item`添加另一个`PATCH`路由，这将有助于编辑`todo`项目的文本，并标记`todo`项目是否完成：

```js
{
  method: 'PATCH',
  path: '/todo/{todo_id}/item/{id}',
  handler: async (request, reply) => 
  {
    const itemId = request.params.id;
    ...
    payload: 
    {
      text: Joi.string(),
      done: Joi.boolean(),
    }
  ...
},
```

您可以在`Code/Lesson-3/exercise-a/routes`的`todo.js`文件中找到完整的代码。

1.  这个路由可以一次接受每个负载项（当使用例如 Web 或移动 UI 时，这将是最实际的情况），或者一次接受所有负载项：

1.  例如，将项目从`内罗毕`更改为`尼日利亚`，或者：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00034.jpeg)

1.  1.  标记项目为`done`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00035.jpeg)

1.  当我们通过`GET：/todo/<id>/item`路由再次列出项目时，您将看到更新后的项目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00036.jpeg)

# 练习 17：删除记录

在这个练习中，我们将介绍最后一个重要的 Knex 方法，以完成我们的**创建**，**读取**，**更新**，**删除**（CRUD）之旅，`.delete()`：

1.  让我们添加一个用于删除`todo`项目的路由：

```js
{
  method: 'DELETE',
  path: '/todo/{todoId}/item/{id}',
  handler: async (request, reply) =>
  {
    const id = request.params.id;
    const deleted = await Knex('todo_item')
      .where('id', id)
      .delete();
    return reply({ message: 'deleted' });
  },
},
```

1.  现在，让我们在之前的`todo`（ID 为`1`）上添加一个项目，然后将其删除：

1.  添加项目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00037.jpeg)

1.  1.  现在我们已经有了它的 ID（在这种情况下是`2`），删除它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00038.jpeg)

# 练习 18：清理代码

现在，我们几乎更新了从第二章*,* *构建 API - 第一部分*中获得的所有路由，现在让我们删除所有不再需要的代码：

1.  删除先前硬编码的 todo 列表：

```js
const todoList = [
...
];
```

1.  删除`PUT：/todo/<id>`路由对象：

```js
{
  method: 'PUT',
  path: '/todo/{id}',
  handler: (request, reply) =>
  {
    const index = request.params.id - 1;
    // replace the whole resource with the new one
    todoList[index] = request.payload;
    return reply({ message: 'updated' });
  },
},
```

1.  重新实现`DELETE：/todo/<id>`路由对象，与*练习 17：删除记录*非常相似；区别只是路由：

```js
{
  method: 'DELETE',
  path: '/todo/{id}',
  handler: async (request, reply) =>
  {
    const id = request.params.id;
    const deleted = await Knex('todo')
      .where('id', id)
      .delete();
    return reply({ message: 'deleted' });
  },
},
```

由于我们的 SQL 查询有这样一行，它添加了一个约束，当删除一个`todo`时可能发生，所有属于该`todo`的项目也会被删除：

`CREATE TABLE todo_item(`

`  'id' INT PRIMARY KEY AUTO_INCREMENT,`

`  'text' VARCHAR(50),`

`  'done' BOOLEAN,`

`  'date_created' TIMESTAMP DEFAULT CURRENT_TIMESTAMP,`

`  'todo_id' INT,`

`  FOREIGN KEY (`todo_id`) REFERENCES `todo` (`id`) ON DELETE CASCADE`

`）;`

# 使用 JWT 对 API 进行身份验证

到目前为止，我们一直在使用我们的 API 而没有任何身份验证。这意味着如果这个 API 托管在公共场所，任何人都可以访问任何路由，包括删除我们所有的记录！任何合适的 API 都需要身份验证（和授权）。基本上，我们需要知道谁在做什么，以及他们是否被授权（允许）这样做。

**JSON Web Tokens**（**JWT**）是一种开放的、行业标准的方法，用于在两个参与方之间安全地表示声明。声明是您希望其他人能够读取和/或验证但不能更改的任何数据位。

为了识别/验证用户的 API，用户在请求的标头中放置一个基于标准的令牌（使用 Authorization 键），（在单词*Bearer*之前加上）。我们将很快在实践中看到这一点。

# 练习 19：保护所有路由

在这个练习中，我们将保护我们创建的所有`/todo/*`路由，以便没有经过身份验证的用户可以访问它们。在*练习 21：实施授权*中，我们将区分*未经身份验证*和*未经授权*的用户：

1.  我们将首先安装一个用于 JWT 的 Hapi.js 插件，`hapi-auth-jwt`。转到终端并运行：

```js
npm install hapi-auth-jwt --save
```

使用`Code/Lesson-3/exercise-b`作为您的参考。

1.  我们将修改从`./routes/todo.js`中获取的路由数组，在`server.js`文件中：

1.  首先，从文件顶部要求安装的`hapi-auth-jwt`：

```js
const hapiAuthJwt = require('hapi-auth-jwt');
```

1.  1.  然后，用这个替换旧的一行，`server.route`(`routes.todo`)：

```js
server.register(hapiAuthJwt, (err) => 
{
  server.auth.strategy('token', 'jwt', 
  {
    key: 'secretkey-hash',
    verifyOptions: 
    {
      algorithms: [ 'HS256' ],
...
    // add auth config on all routes
...
});
```

您可以在`Code/Lesson-3/exercise-b`的`server.js`文件中找到完整的代码。

1.  现在，尝试访问任何路由，例如`GET：/todo`；你应该会得到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00039.jpeg)

# 练习 20：添加用户身份验证

现在我们已经保护了所有的待办事项路由，我们需要一种方法来为有效的用户发放令牌以访问 API。用户将他们的电子邮件和密码发送到一个路由(`/auth`)，我们的 API 将返回一个用于每个请求的认证令牌：

1.  在`/routes`文件夹中，创建一个名为`auth.js`的文件。

1.  现在，我们需要另外两个包，`jsonwebtoken`用于签署认证令牌，`md5`用于比较密码，因为你可能还记得，我们之前使用了 MySQL 的`md5`函数来存储用户的密码：

```js
npm install jsonwebtoken md5 --save
```

1.  在`auth.js`文件中，添加以下代码：

```js
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const md5 = require('md5');
const Knex = require('../db');
module.exports =
  {
  method: 'POST',
  path: '/auth',
...
};
```

您可以在`Code/Lesson-3/exercise-b/routes`文件夹中找到`auth.js`文件的完整代码。

1.  现在，让我们在服务器上注册我们的`auth.js`路由。在`server.js`中，在`routes.todo = ...`之后，添加以下代码：

```js
routes.auth = require('./routes/auth');
```

1.  在初始化服务器的行之后，我们可以添加`route`注册：

```js
server.route(routes.auth);
```

1.  现在，让我们尝试我们的路由，`POST: /auth`：

1.  首先，使用不正确的邮箱/密码组合：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00040.jpeg)

1.  1.  然后，使用正确的密码，记住*练习 14：创建记录*，*步骤 2*，我们创建了测试用户和密码：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00041.jpeg)

1.  现在，我们可以复制生成的令牌，并在以后的请求中使用，例如通过添加一个授权头来进行`GET: /todo`请求。因此，请记住，我们从单词`Bearer`开始，然后是一个空格，然后粘贴令牌；这是 JWT 的约定：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00042.jpeg)

1.  现在，我们可以访问路由而不会收到未经授权的响应，就像在第 20 个练习的*步骤 6*中一样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00043.jpeg)

1.  现在，让我们回到`./routes/todo.js`文件中我们之前硬编码用户的地方，并从认证对象中获取它们，即：

```js
const userId = request.auth.credentials.id;
```

回想一下之前的*步骤 3*，当我们签署我们的令牌时，我们提供了用户的详细信息，即`name`，`email`和`id`。这就是我们在`request.auth.credentials.id`中得到`.id`的地方：

`jwt.sign(`

`{`

`  name: user.name,`

`  邮箱：user.email，`

`  id: user.id,`

`},`

`...`

`）;`

1.  现在，让我们回到我们的 phpMyAdmin 网络界面，并创建另一个用户，就像我们在*练习 14：创建记录*，*步骤 2*中所做的一样，并将以下 SQL 粘贴到 SQL 文本区域中：

```js
INSERT INTO 'user' ('id', 'name', 'email', 'password')
VALUES (NULL, 'Another User', 'another@example.com',
MD5('12345'));
```

1.  现在，让我们去做另一个`POST: /auth`请求，使用新用户并获取令牌：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00044.jpeg)

1.  让我们使用这个新令牌通过`POST: /todo`请求创建另一个待办事项清单：

1.  在 Insomnia 中，转到头部部分，删除先前的授权头，并用新的替换它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00045.jpeg)

1.  1.  现在，让我们发出我们的请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00046.jpeg)

1.  1.  通过`GET: /todo`请求，让我们看看新的待办事项清单：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00047.jpeg)

1.  1.  正如您所看到的，新创建的用户只能看到他们创建的内容。就授权而言，我们到目前为止做得很好。然而，让我们尝试并检查属于第一个用户的待办事项 ID`1`的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00048.jpeg)

糟糕！我们可以看到别人的待办事项清单；这是一个安全漏洞。这将引导我们进入这个主题的最后一部分，**授权**。

# 认证与授权

通过认证，我们知道谁在访问我们的 API；通过授权，我们可以告诉谁可以在我们的 API 中访问什么。

# 练习 21：实施授权

在这个练习中，我们将完善我们的 API，以确保用户只有授权才能访问他们的待办事项和待办事项内容：

1.  首先，让我们修复我们在*练习 20：添加用户认证*，*步骤 12*中遇到的漏洞。因此，我们将修改`/routes/todo.js`中的`GET: /todo/<id>`路由对象，首先检查用户是否拥有该待办事项，然后才能访问其内容：

```js
{
  method: 'GET',
  path: '/todo/{id}/item',
  handler: async (request, reply) =>
  {
    const todoId = request.params.id;
    ...
    return reply(items);
  },
},
```

您可以在`Code/Lesson-3/exercise-b/routes`文件夹中找到`todo.js`文件的完整代码。

1.  现在，当我们再次访问`GET: /todo/1/item`时，我们会得到正确的错误消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00049.jpeg)

1.  您可以为以下路由添加额外的授权逻辑：

+   +   `POST`：`/todo/<id>/item`，确保用户不能向不属于他们的待办事项添加项目。

+   `PATCH`：`/todo/<id>`，用户不能对不属于他们的待办事项进行修补。

+   `PATCH`：`/todo/<todoId>/item/<id>`，用户不能对不属于他们的待办事项进行修补。

+   `DELETE`：`/todo/<id>`，用户不能删除不属于他们的待办事项。

+   `DELETE`：`/todo/<todoId>/item/<id>`，用户不能对不属于他们的待办事项进行修补。

跨域资源共享（CORS）是一种机制，它使用额外的 HTTP 头来让用户代理（浏览器）获得许可，以访问来自不同源（域）的服务器上选择的资源，而不是当前使用的站点。例如，当您在另一个域上托管 Web 应用程序前端时，由于浏览器限制，您将无法访问 API。

因此，我们需要明确声明我们的 API 将允许跨域请求。我们将修改`server.js`文件，在我们初始化服务器连接的地方，以启用 CORS：

```js
server.connection(
{
   host: 'localhost',
   port: process.argv[2] || 8000,
   routes:
   {
     cors: true,
   }
});
```

# 使用 Lab 测试您的 API

在本节中，我们将简要介绍为 Hapi.js API 编写单元测试。测试是一个庞大的主题，可能需要一个完整的课程来讲解，但在本节中，我们将介绍一些基本部分，让您能够开始运行。

让我们首先强调为您的 API 编写单元测试的重要性：

+   **可维护性**：这是我认为为软件添加测试最重要的价值。当您有了测试，您可以放心地在几个月后回来修改您的代码，而不必担心您的更新是否会破坏任何东西。

+   需求规格：测试确保您的代码满足要求。对于我们的例子，我们开始时实现了要求，因为我们想传达一些基本概念。但实际上，最好是在实现路由之前先从测试开始。

+   **自动化测试**：您意识到在我们之前的例子中，我们一直在检查我们的 API 客户端（Insomnia）以查看我们的 API 是否正常工作；这可能有点麻烦。有了测试，一旦您编写了正确的测试，您就不必担心这个问题。

Hapi.js 通常使用 Lab（https://github.com/hapijs/lab）作为其测试框架。我们将在下一个练习中为我们的 API 编写一些测试。

# 练习 22：使用 Lab 编写基本测试

在这个练习中，我们将介绍为 Hapi.js web API 编写单元测试的概念，主要使用第三方`lab`模块和内置的`assert`模块。理想情况下，我们应该为我们的测试有一个单独的数据库，但为了简单起见，我们也将分享我们的开发数据库用于测试：

1.  让我们首先安装必要的软件包。请注意，我们使用`--save-dev`，因为测试不需要用于生产，因此它们是*开发依赖项*：

```js
npm install lab --save-dev
```

使用`Code/Lesson-3/exercise-c`作为参考。

1.  在项目的根目录下创建一个`test`文件夹，那里将有我们的测试。由于我们的 API 很简单，我们只会有一个文件包含所有的测试。

1.  在`test`中，创建一个名为`test-todo.js`的文件。

1.  作为设置，`test/test-todo.js`需要我们测试所需的模块：

```js
const assert = require('assert');
// lab set-up
const Lab = require('lab');
const lab = exports.lab = Lab.script();
// get our server(API)
const server = require('../server');
```

在第一行中，我们要求 assert，如果您回忆起第一章中的介绍，这是一个内置模块。或者，您也可以使用其他断言库，如`chai`（https://github.com/chaijs/chai）、`should.js`（https://github.com/tj/should.js）等。

Lab 测试文件必须要求`lab`模块并导出一个测试脚本，如前面的第 4 行所示。我们将在接下来的行中获取 lab 的其余部分；我们很快就会看到它们发挥作用。

1.  由于我们在`test-todo.js`文件的第 6 行中需要服务器，因此我们需要返回到我们的`server.js`文件，并在最后一行导出`server`对象。

```js
module.exports = server;
```

1.  对于 DB 配置，让我们修改我们的`db.js`文件，包括指向开发配置的测试环境配置。在`configs`定义之后添加这一行：

```js
configs.test = configs.development;
```

1.  让我们修改服务器连接设置代码，以便在运行测试时从环境变量设置测试服务器的端口。这允许我们在不同端口上运行测试服务器，而我们的开发服务器正在运行：

```js
server.connection(
{
  host: 'localhost',
  port: process.env.PORT || 8000,
  routes:
  {
    cors: true,
  }
});
```

1.  我们将使用`lab`模块中的一些方法；我们需要使用对象解构来获取它们。在我们的`test-todo.js`文件中添加以下行：

```js
const
{
  experiment,
  test,
  before,
} = lab;
```

1.  让我们从编写一个简单的测试开始，确保`GET: / request`被执行，并返回`{ message: 'hello, world' }`。

```js
experiment('Base API', () => 
{
  test('GET: /', () => 
  {
    const options =
    {
      ...
      assert.equal(response.result.message, 'hello, world');
    });
  });
});
```

您可以在`Code/Lesson-3/exercise-c/test`的`test-todo.js`文件中找到完整的代码。

我们现在看到`experiment`、`test`和`assert.equal`方法在起作用。`experiment`基本上是将测试组合在一起的一种方式，实际测试是在`test`方法的回调函数（称为*测试用例*）中编写的。这里的`assert.equal`只是比较两个值，以确保它们相等，如果不相等，将抛出*断言错误*。

1.  现在，让我们运行我们的测试：

1.  在终端（如果您在其中一个终端上运行 API，请打开一个新的终端），导航到我们项目的根目录并运行以下命令：

```js
PORT=8001 ./node_modules/lab/bin/lab test --leaks
```

我们正在添加一个可选的`--leaks`选项来关闭内存泄漏检测，因为我们现在不需要它。

在命令的开头，我们添加了`PORT=8001`；这是一种向我们的脚本传递环境变量的方式，这就是为什么我们之前在步骤 7 中更改了我们的代码的原因。我们现在在端口`8001`上运行我们的测试服务器，而我们的开发服务器仍在端口`8000`上运行。

1.  1.  当您运行命令时，您应该看到与此类似的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00050.jpeg)

1.  我们可以通过将其添加到我们的`package.json`文件的脚本中来缩短我们的测试命令：

1.  替换以下代码行：

```js
"test": "echo \"Error: no test specified\" && exit 1"
```

1.  1.  使用以下行：

```js
"test": "PORT=8001 ./node_modules/lab/bin/lab test --leaks"
```

1.  1.  现在，回到终端，只需运行：

```js
npm test
```

1.  现在，让我们测试我们的身份验证是否正常工作。添加以下内容

前一个段落之后的部分：

```js
experiment('Authentication', () =>
{
  test('GET: /todo without auth', () =>
  {
    const options =
    {
      method: 'GET',
      url: '/todo'
    };
    server.inject(options, (response) => 
    {
      assert.equal(response.statusCode, 401);
    });
  });
});
```

1.  现在，返回并运行`npm test`。两个测试都应该通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00051.jpeg)

1.  您会意识到我们不得不每隔一段时间回到终端运行测试。这与在 API 客户端（Insomnia）上进行测试一样麻烦；我们需要一些自动化：

1.  我们将需要 gulp.js，并且还需要两个其他的 Gulp 插件。让我们安装它们：

```js
install gulp gulp-shell gulp-watch --save-dev
```

1.  1.  现在，让我们在我们项目的根目录编写一个简单的`gulpfile.js`来自动化我们的测试任务：

```js
const gulp = require('gulp');
const shell = require('gulp-shell');
const watch = require('gulp-watch');
...
gulp.task('test', shell.task('npm test'));
```

您可以在`Code/Lesson-3/exercise-c`的`gulpfile.js`文件中找到完整的代码。

1.  1.  现在，让我们转到`package.json`并在之前的`test`旁边添加另一个`gulp`任务的脚本选项：

```js
"scripts": 
{
  "test": "PORT=8001 ./node_modules/lab/bin/lab test --leaks",
  "test:dev": "./node_modules/.bin/gulp test:dev"
},
```

1.  1.  现在，转到终端，而不是`npm test`，运行以下命令：

```js
npm run test:dev
```

1.  1.  监视任务将被启动，因此，在前面一点中`src`数组中的任何文件进行的更改，测试将自动运行。这意味着您可以继续进行开发工作，并定期检查测试是否全部通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/bg-api-dev-node/img/00052.jpeg)

1.  现在，让我们为`GET: /todo`路由编写一个示例测试。请记住，对于所有经过身份验证的路由，我们需要首先获得令牌，以便我们能够成功发出请求。因此，在任何测试开始之前，我们将需要一个脚本来获取令牌。这就是我们在步骤 8 中得到的`before`函数发挥作用的地方。在我们的`test-todo.js`文件中，添加以下部分：

```js
experiment('/todo/* routes', () => 
{
  const headers = 
  {
    Authorization: 'Bearer ',
  };
  before(() => 
  {
    const options = 
    {
      method: 'POST',
      url: '/auth',
      ...
});
```

您可以在`Code/Lesson-3/exercise-c/test`的`test-todo.js`文件中找到完整的代码。

# 摘要

在本章中，我们探讨了很多内容。我们首先介绍了 Knex.js 以及如何使用它来连接和使用数据库。我们了解了基本的 CRUD 数据库方法。然后，我们介绍了如何对我们的 API 进行身份验证，并防止未经授权的访问，使用 JWT 机制。我们还提到了关于 CORS 的一些重要内容，浏览器如何处理它，以及我们如何在我们的 API 上启用它。最后，我们涉及了关于使用 Lab 库测试我们的 API 的概念。我们还简要介绍了使用 gulp.js 进行测试自动化的概念。

在这本书中，我们首先学习了如何实现必要的模块，使简单的应用程序能够运行起来。然后，我们开始实现异步和等待函数，以高效处理异步代码。在介绍了 Node.js（应用程序构建方面）之后，我们开始构建一个使用 Node.js 的 API。为了做到这一点，我们最初使用了内置模块，然后利用了丰富的 Hapi.js 框架。我们也了解了 Hapi.js 框架的优势。之后，我们学会了如何处理来自 API 客户端的请求，最后，我们通过涉及与数据库的交互来完成了这本书。

这是一个实用的快速入门指南。为了进一步提高您的知识，您应该考虑使用 Node.js 构建实时应用程序。我们在下一节推荐了一些书籍，但请确保您查看我们的网站，以找到其他可能对您感兴趣的书籍！
