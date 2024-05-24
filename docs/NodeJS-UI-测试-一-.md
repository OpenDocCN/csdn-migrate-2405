# NodeJS UI 测试（一）

> 原文：[`zh.annas-archive.org/md5/9825E0A7D182DABE37113602D3670DB2`](https://zh.annas-archive.org/md5/9825E0A7D182DABE37113602D3670DB2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自动化用户界面测试一直是编程的圣杯。现在，使用 Zombie.js 和 Mocha，您可以快速创建和运行测试，使得即使是最小的更改也可以轻松测试。增强您对代码的信心，并在开发过程中最小化使用真实浏览器的次数。

*使用 Node.js 进行 UI 测试*是一本关于如何自动测试您的 Web 应用程序，使其坚如磐石且无 bug 的快速而全面的指南。您将学习如何模拟复杂的用户行为并验证应用程序的正确行为。

您将在 Node.js 中创建一个使用复杂用户交互和 AJAX 的 Web 应用程序；在本书结束时，您将能够从命令行完全测试它。然后，您将开始使用 Mocha 作为框架和 Zombie.js 作为无头浏览器为该应用程序创建用户界面测试。

您还将逐模块创建完整的测试套件，测试简单和复杂的用户交互。

# 本书涵盖内容

第一章 *开始使用 Zombie.js*，帮助您了解 Zombie.js 的工作原理以及可以使用它测试哪些类型的应用程序。

第二章 *创建简单的 Web 应用*，解释了如何使用 Node.js、CouchDB 和 Flatiron.js 创建一个简单的 Web 应用。

第三章 *安装 Zombie.js 和 Mocha*，教您如何使用 Zombie.js 和 Mocha 为 Web 应用程序创建测试环境的基本结构。

第四章 *理解 Mocha*，帮助您了解如何使用 Mocha 创建和运行异步测试。

第五章 *操作 Zombie 浏览器*，解释了如何使用 Zombie.js 创建一个模拟浏览器，可以加载 HTML 文档并对其执行操作。

第六章 *测试交互*，解释了如何在文档中触发事件以及如何测试文档操作的结果。

第七章 *调试*，教会您如何使用 Zombie 浏览器对象和其他一些技术来检查应用程序的内部状态。

第八章 *测试 AJAX*，不包含在本书中，但可以通过以下链接免费下载：

[`www.packtpub.com/sites/default/files/downloads/0526_8_testingajax.pdf`](http://www.packtpub.com/sites/default/files/downloads/0526_8_testingajax.pdf)

# 本书所需内容

要使用本书，您需要一台运行现代主流操作系统（如 Windows、Mac 或 Linux）的个人电脑。

# 本书适合谁

本书适用于使用并在一定程度上了解 JavaScript 的程序员，尤其是具有事件驱动编程经验的人。例如，如果您曾在网页上使用 JavaScript 设置事件回调和进行 AJAX 调用，您将会更容易上手。另外，一些使用 Node.js 的经验也会减轻学习曲线，但不是绝对要求。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄均显示如下：“要从 Node 中访问 CouchDB 数据库，您将使用一个名为`nano`的库。”

代码块设置如下：

```js
browser.visit('http://localhost:8080/form', function() {
  browser
    .fill('Name', 'Pedro Teixeira')
    .select('Born', '1975')
    .check('Agree with terms and conditions')
    .pressButton('Submit', function() {
      assert.equal(browser.location.pathname, '/success');
      assert.equal(browser.text('#message'),
        'Thank you for submitting this form!');
    });
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
  "scripts": {
 "test": "mocha test/users.js",
    "start": "node app.js"
  },...
```

任何命令行输入或输出均按以下格式编写：

```js
$ npm install
...
mocha@1.4.2 node_modules/mocha
...

zombie@1.4.1 node_modules/zombie
...
```

**新术语**和**重要单词**会以粗体显示。屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："点击**下一步**按钮会将您移动到下一个屏幕"。

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：使用 Zombie.js 入门

> "Zombie.js 是一个轻量级的框架，用于在模拟环境中测试客户端 JavaScript 代码。无需浏览器。"

这个定义来自*Zombie.js*文档，网址为[`zombie.labnotes.org`](http://zombie.labnotes.org)

为您的 Web 应用程序自动化测试对于拥有高质量的产品至关重要，但正确执行可能是一种痛苦的经历。这就是为什么大多数时候项目的这一部分从未得到实施。开发人员要么限制自己只测试底层业务逻辑和控制流，要么，如果他们真的想测试用户界面，必须采用复杂的设置，以某种方式连接到真实的浏览器并使用远程脚本对其进行命令。

Zombie.js 为这种情景提供了一个快速简便的替代方案，使您可以仅通过使用 JavaScript 轻松快速地为您的 Web 应用程序创建自动化测试。

本章涵盖的主题有：

+   软件测试的简要历史

+   理解服务器端 DOM

+   Zombie.js 的内部工作原理

在本章结束时，您应该了解 Zombie.js 的工作原理以及可以使用它进行测试的应用程序类型。

# 软件和用户界面测试的简要历史

软件测试是收集有关某种产品或服务质量的信息的必要活动。在传统的软件开发周期中，这项活动被委托给一个唯一工作是在软件中找问题的团队。如果正在向国内终端用户销售通用产品，或者公司正在购买许可的操作系统，则需要进行这种类型的测试。

在大多数定制软件中，测试团队负责手动测试软件，但通常客户必须进行验收测试，以确保软件的行为符合预期。

每当这些团队中的某人在软件中发现新问题时，开发团队就必须修复软件并将其重新放入测试循环中。这意味着每次发现错误时，交付最终版本的软件所需的成本和时间都会增加。此外，问题在开发过程的后期被发现，将会对产品的最终成本产生更大的影响。

此外，软件交付方式在过去几年发生了变化；网络使我们能够轻松交付软件及其升级，缩短了新功能开发和投入使用之间的时间。但一旦交付了产品的第一个版本并有一些客户在使用，你可能会面临一个困境；较少的更新可能意味着产品很快就会过时。另一方面，对软件进行许多更改增加了出现问题的可能性，使您的软件变得有缺陷，这可能会让客户流失。

关于如何缓解交付有缺陷产品的风险并增加按时交付新功能的机会，以及整体产品达到一定的质量标准，有许多版本和迭代的开发过程，但是所有参与软件构建的人都必须同意，越早发现错误越好。

这意味着您应该尽早发现问题，最好是在开发周期中。不幸的是，每次软件更改时都通过手工完全测试软件将会很昂贵。解决方案是自动化测试，以最大化测试覆盖率（应用程序代码的百分比和可能的输入变化）并最小化运行每个测试所需的时间。如果您的测试只需几秒钟就能运行，您就可以负担得起每次对代码库进行单个更改时运行测试。

## 进入自动化时代

测试自动化已经存在了一些年头，甚至在 Web 出现之前就有了。一旦**图形用户界面**（**GUI**）开始变得流行，允许你录制、构建和运行自动化测试的工具开始出现。由于有许多语言和 GUI 库用于构建应用程序，许多涵盖其中一些的工具开始出现。通常它们允许你录制一个测试会话，然后可以自动重现。在这个会话中，你可以自动化指针点击事物（按钮、复选框、窗口上的位置等），选择值（例如从选择框中选择），输入键盘操作并测试结果。

所有这些工具操作起来都相当复杂，而且最糟糕的是，大多数都是特定技术的。

但是，如果你正在构建一个使用 HTML 和 JavaScript 的基于 Web 的应用程序，你有更好的选择。其中最著名的可能是 Selenium，它允许你录制、更改和运行针对所有主要浏览器的测试脚本。

你可以使用 Selenium 来运行测试，但是你至少需要一个浏览器让 Selenium 附加到其中，以便加载和运行测试。如果你尽可能多地使用浏览器来运行测试，你将能够保证你的应用在所有浏览器上都能正确运行。但是由于 Selenium 插入到浏览器并控制它，在尽可能多的浏览器上运行相当复杂的应用的所有测试可能需要一些时间，而你最不希望的就是尽可能少地运行测试。

## 单元测试与集成测试

通常，你可以将自动化测试分为两类，即单元测试和集成测试。

+   **单元测试**：这些测试是选择应用程序的一个小子集（例如一个类或特定对象）并测试该类或对象向应用程序的其余部分提供的接口。通过这种方式，你可以隔离一个特定的组件，并确保它的行为符合预期，以便应用程序中的其他组件可以安全地使用它。

+   **集成测试**：这些测试是将单独的组件组合在一起并作为一个工作组进行测试。在这些测试中，你与用户界面进行交互和操作，用户界面反过来与应用程序的基础块进行交互。你使用 Zombie.js 进行的测试属于这一类。

## Zombie.js 是什么

Zombie.js 允许你在没有真实网络浏览器的情况下运行这些测试。相反，它使用一个模拟的浏览器，在其中存储 HTML 代码并运行你可能在 HTML 页面中有的 JavaScript。这意味着不需要显示 HTML 页面，节省了本来会被渲染的宝贵时间。

然后你可以使用 Zombie.js 来模拟浏览器加载页面，并且一旦页面加载完成，执行某些操作并观察结果。你可以使用 JavaScript 来完成所有这些，而不需要在客户端代码和测试脚本之间切换语言。

# 理解服务器端的 DOM

Zombie.js 运行在 Node.js（[`nodejs.org`](http://nodejs.org)）之上，这是一个可以轻松使用 JavaScript 构建网络服务器的平台。它运行在谷歌快速的 V8 JavaScript 引擎之上，这也是谷歌 Chrome 浏览器的动力来源。

### 注意

在撰写本文时，V8 实现了 JavaScript ECMA 3 标准和部分 ECMA 5 标准。并非所有浏览器都平等地实现了所有版本的 JavaScript 标准的所有功能。这意味着即使你的测试在 Zombie.js 中通过了，也不意味着它们会在所有目标浏览器中通过。

在 Node.js 之上，有一个名为 JSDOM 的第三方模块（[`npmjs.org/package/jsdom`](https://npmjs.org/package/jsdom)），它允许你解析 HTML 文档并在该文档的表示之上使用 API；这使你能够查询和操作它。提供的 API 是标准的**文档对象模型**（**DOM**）。

所有浏览器都实现了 DOM 标准的一个子集，这是由**万维网联盟**（**W3C**）内的一个工作组作为一组推荐来规定的。它们有三个推荐级别。JSDOM 实现了所有三个。

Web 应用程序直接或间接（通过使用诸如 jQuery 之类的工具）使用浏览器提供的 DOM API 来查询和操作文档，从而使您能够创建具有复杂行为的浏览器应用程序。这意味着通过使用 JSDOM，您自动支持大多数现代浏览器支持的任何 JavaScript 库。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/`](http://www.packtpub.com/)support 并注册，以便将文件直接发送到您的电子邮件。

## Zombie.js 是您的无头浏览器

在 Node.js 和 JSDOM 之上是 Zombie.js。Zombie.js 提供类似浏览器的功能和一个可用于测试的 API。例如，Zombie.js 的典型用法是打开浏览器，请求加载某个 URL，填写表单上的一些值并提交，然后查询生成的文档，看看是否有成功消息。

为了更具体，这里是一个简单的 Zombie.js 测试代码的示例：

```js
browser.visit('http://localhost:8080/form', function() {
  browser
    .fill('Name', 'Pedro Teixeira')
    .select('Born', '1975')
    .check('Agree with terms and conditions')
    .pressButton('Submit', function() {
      assert.equal(browser.location.pathname, '/success');
      assert.equal(browser.text('#message'),
        'Thank you for submitting this form!');
    });
});
```

在这里，您正在典型地使用 Zombie.js：加载包含表单的 HTML 页面；填写并提交该表单；然后验证结果是否成功。

### 注意

Zombie.js 不仅可以用于测试您的 Web 应用程序，还可以用于需要像浏览器一样行为的应用程序，例如 HTML 抓取器、爬虫和各种 HTML 机器人。

如果您要使用 Zombie.js 进行任何这些活动，请做一个良好的网络公民，并在道德上使用它。

# 摘要

创建自动化测试是任何软件应用程序开发过程的重要部分。在使用 HTML、JavaScript 和 CSS 创建 Web 应用程序时，您可以使用 Zombie.js 创建一组测试；这些测试加载、查询、操作并为任何给定的网页提供输入。

鉴于 Zombie.js 模拟了浏览器，并且不依赖于 HTML 页面的实际渲染，因此测试运行速度比如果您使用真实浏览器进行测试要快得多。因此，您可以在对应用程序进行任何小的更改时运行这些测试。

Zombie.js 在 Node.js 之上运行，使用 JSDOM 在任何 HTML 文档之上提供 DOM API，并使用简单的 API 模拟类似浏览器的功能，您可以使用 JavaScript 创建您的测试。


# 第二章：创建一个简单的 Web 应用程序

当您到达本章末尾时，您应该能够使用 Node.js、CouchDB 和 Flatiron 创建一个简单的 Web 应用程序。

本章涵盖的主题包括：

+   设置 Node 和 Flatiron

+   创建和处理用户表单

# 定义我们的 Web 应用程序的要求

在我们深入研究 Zombie.js 世界之前，我们需要为我们的测试创建一个目标，即提供待办事项列表的 Web 应用程序。这是这样一个应用程序的顶级要求集：

+   用户可以注册该服务，需要提供电子邮件地址作为用户名和密码。通过提供用户名和密码，用户可以创建一个经过身份验证的会话，该会话将在进一步的交互中识别他。

+   用户可以创建一个待办事项。

+   用户可以查看待办事项列表。

+   用户可以删除待办事项。

为了实现这个应用程序，我们将使用 Node.js，这是一个用 JavaScript 构建网络应用程序的平台，Zombie.js 也使用它。我们还将使用 Flatiron，这是一组组件，将帮助您在 Node.js 之上构建 Web 应用程序。

### 注意

为了保持简单，我们正在使用 Node.js 构建我们的应用程序。但是，Zombie.js 适用于测试使用任何框架构建的应用程序，这些框架利用动态 HTTP 服务器。

还要记住，构建这个 Web 应用程序的目标不是向您展示如何构建 Web 应用程序，而是在已知和简单的域上提供一个可用的应用程序，以便我们可以将其用作我们测试的主题。

在接下来的章节中，您将学习如何安装 Node.js 和 Flatiron，以及如何创建您的待办应用程序服务器。

# 设置 Node.js 和 Flatiron

如果您没有安装最新版本的 Node.js，您将需要安装它。您将需要 Node.js 出于几个原因。我们的 Web 应用程序将使用 Flatiron，它在 Node.js 之上运行。您还需要使用**Node Package Manager**（**NPM**），它与 Node 捆绑在一起。最后，您将需要 Node.js 来安装和运行 Zombie.js 测试。

## 安装 Node.js

1.  要安装 Node.js，请前往 nodejs.org 网站。![安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_01.jpg)

1.  然后点击**下载**按钮，这将打开以下页面：![安装 Node.js](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_02.jpg)

1.  如果您正在运行 Windows 或 Macintosh 系统，请单击相应的安装程序图标。这将下载并启动图形安装程序。

### 从源代码安装 Node

如果您没有运行其中一个系统，并且您在类 Unix 系统上，您可以按照以下步骤从源代码安装 Node.js：

1.  单击源代码图标，将开始下载源代码 tarball。下载完成后，使用终端展开它：

```js
$ tar xvfz node-v0.8.7.tar.gz
```

导航到创建的目录：

```js
$ cd node-v0.8.7
```

1.  配置它：

```js
$ ./configure
```

1.  构建它：

```js
$ make
```

1.  最后安装它：

```js
$ make install
```

如果您没有足够的权限将节点二进制文件复制到最终目标位置，您将需要在命令前加上`sudo`：

```js
$ sudo make install
```

1.  现在您应该已经在系统上安装了 Node.js。尝试运行它：

```js
$ node -v
v0.8.7
```

1.  现在让我们尝试打开 Node 命令行并输入一些内容：

```js
$ node
> console.log('Hello World!');
```

1.  如果您现在按*Enter*键，您应该会得到以下输出：

```js
...
> Hello World!
```

1.  通过安装 Node.js，您还安装了它的忠实伴侣 NPM，Node Package Manager。您可以尝试从终端调用它：

```js
$ npm -v
1.1.48
```

## 安装 Flatiron 并启动您的应用程序

现在您需要安装 Flatiron 框架，这样您就可以开始构建您的应用程序。

1.  使用 NPM 按照以下方式下载和安装 Flatiron：

```js
$ npm install -g flatiron
```

### 注意

再次，如果您没有足够的权限安装 Flatiron，请在最后一个命令前加上`sudo`。

这将全局安装 Flatiron，使`flatiron`命令行实用程序可用。

1.  现在您应该进入一个将拥有应用程序代码的目录。然后，您可以通过执行以下命令为您的 Web 应用程序创建基本的脚手架：

```js
$ flatiron create todo
```

1.  在提示您输入作者的姓名、应用程序描述和主页（可选）后，它将创建一个名为`todo`的目录，其中包含您的应用程序代码的基础。使用以下命令进入该目录：

```js
$ cd todo
```

在那里，您将找到两个文件和三个文件夹：

```js
$ tree
.
├── app.js
├── config
│   └── config.json
├── lib
├── package.json
└── test
```

其中一个文件`package.json`包含应用程序清单，其中，除其他字段外，还包含应用程序依赖的软件包。现在，您将从该文件中删除`devDependencies`字段。

您还需要为名为`plates`的软件包添加一个依赖项，该软件包将用于动态更改 HTML 模板。

此外，您将为一些不需要任何修改的静态文件提供服务。为此，您将使用一个名为`node-static`的包，您还需要将其添加到应用程序清单的依赖项列表中。

到目前为止，您的`package.json`应该看起来像这样：

```js
{
  "description": "To-do App",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "union": "0.3.0",
    "flatiron": "0.2.8",
    "plates": "0.4.x",
    "node-static": "0.6.0"
  },
  "scripts": {
    "test": "vows --spec",
    "start": "node app.js"
  },
  "name": "todo",
  "author": "Pedro",
  "homepage": ""
}
```

1.  接下来，通过以下方式安装这些依赖项：

```js
$ npm install
```

这将在本地的`node_modules`目录中安装所有依赖项，并应该输出类似以下内容：

```js
union@0.3.0 node_modules/union
├── qs@0.4.2
└── pkginfo@0.2.3

flatiron@0.2.8 node_modules/flatiron
├── pkginfo@0.2.3
├── director@1.1.0
├── optimist@0.3.4 (wordwrap@0.0.2)
├── broadway@0.2.5 (eventemitter2@0.4.9, cliff@0.1.8, utile@0.1.2, nconf@0.6.4, winston@0.6.2)
└── prompt@0.2.6 (revalidator@0.1.2, read@1.0.4, utile@0.1.3, winston@0.6.2)

plates@0.4.6 node_modules/plates

node-static@0.6.0 node_modules/node-static
```

### 注意

您不必担心这一点，因为 Node 将能够自动获取这些依赖项。

1.  现在您可以尝试启动您的应用程序：

```js
$ node app.js
```

如果您打开浏览器并将其指向`http://localhost:3000`，您将得到以下响应：

```js
{"hello":"world"}
```

# 创建您的待办事项应用程序

现在，您已经有一个 Flatiron“hello world”示例正在运行，您需要扩展它，以便我们的待办事项应用程序成形。为此，您需要创建和更改一些文件。如果您迷失了方向，您可以随时参考本章的源代码。另外，供您参考，本章末尾包含了项目文件的完整列表。

## 设置数据库

与任何真实应用程序一样，您将需要一种可靠的方式来持久保存数据。在这里，我们将使用 CouchDB，这是一个开源的面向文档的数据库。您可以选择在本地安装 CouchDB，也可以使用互联网上的服务，如 Iris Couch。

如果您选择在本地开发机器上安装 CouchDB，您可以前往[`couchdb.apache.org/`](http://couchdb.apache.org/)，点击**下载**并按照说明进行操作。

如果您更喜欢简单地通过互联网使用 CouchDB，您可以前往[`www.iriscouch.com/`](http://www.iriscouch.com/)，点击**立即注册**按钮并填写注册表格。您应该在几秒钟内拥有一个运行的 CouchDB 实例。

![设置数据库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_03.jpg)

### 注意

截至目前，Iris Couch 是一个免费为小型数据库提供低流量服务的服务，这使其非常适合原型设计这样的应用程序。

## 从 Node 访问 CouchDB

要从 Node 访问 CouchDB 数据库，我们将使用一个名为`nano`的库，您将把它添加到`package.json`文件的依赖项部分：

```js
{
  "description": "To-do App",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "union": "0.3.0",
    "flatiron": "0.2.8",
    "plates": "0.4.6",
    "node-static": "0.6.0",
 "nano": "3.3.0"
  },
  "scripts": {
    "test": "vows --spec",
    "start": "node app.js"
  },
  "name": "todo",
  "author": "Pedro",
  "homepage": ""
}
```

现在，您可以通过在应用程序的根目录运行以下命令来安装此缺少的依赖项：

```js
$ npm install
nano@3.3.0 node_modules/nano
├── errs@0.2.3
├── request@2.9.203.8.0 (request@2.2.9request@2.2.9)
```

这将在`node_modules`文件夹中安装`nano`，使其在构建此应用程序时可用。

要实际连接到数据库，您需要定义 CouchDB 服务器的 URL。如果您在本地运行 CouchDB，则 URL 应类似于`ht` `tp://127.0.0.1:5984`。如果您在 Iris Couch 或类似的服务中运行 CouchDB，则您的 URL 将类似于`https://mytodoappcouchdb.iriscouch.com`。

在任何这些情况下，如果您需要使用用户名和密码进行访问，您应该将它们编码在 URL 中，`http://username:password@mytodoappco` `uchdb.iriscouch.com`

现在应该将此 URL 输入到`config/config.json`文件的配置文件中，`couchdb`键下：

```js
{
  "couchdb": "http://localhost:5984"
}
```

接下来，通过在`lib/couchdb.js`下提供一个简单的模块来封装对数据库的访问：

```js
var nano = require('nano'),
    config = require('../config/config.json');

module.exports = nano(config.couchdb);
```

此模块将用于获取 CouchDB 服务器对象，而不是在整个代码中多次重复`config`和`nano`的操作。

## 应用程序布局

像许多网站现在所做的那样，我们将使用 Twitter Bootstrap 框架来帮助我们使网站看起来和感觉起来简洁而又可观。为此，您将前往 Bootstrap 网站[`twitter.github.com/bootstrap/`](http://twitter.github.com/bootstrap/)，并单击**下载 Bootstrap**按钮：

![应用程序布局](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_04.jpg)

您将收到一个 zip 文件，您应该将其扩展到本地的`public`文件夹中，最终得到这些文件：

```js
$ tree public/
public/
├── css
│   ├── bootstrap-responsive.css
│   ├── bootstrap-responsive.min.css
│   ├── bootstrap.css
│   └── bootstrap.min.css
├── img
│   ├── glyphicons-halflings-white.png
│   └── glyphicons-halflings.png
└── js
    ├── bootstrap.js
    └── bootstrap.min.js
```

您还需要将 jQuery 添加到混合中，因为 Bootstrap 依赖于它。从[`jquery.com`](http://jquery.com)下载 jQuery，并将其命名为`public/js/jquery.min.js`。

## 开发前端

现在我们安装了 Bootstrap 和 jQuery，是时候创建我们应用程序的前端了。

首先，我们将设置布局 HTML 模板，该模板定义了所有页面的外部结构。为了托管所有模板，我们将有一个名为`templates`的目录，其中包含以下内容`templates/layout.html`：

```js
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title id="title"></title>
    <link href="/css/bootstrap.min.css" rel="stylesheet" />
  </head>
  <body>

    <section role="main" class="container">

      <div id="messages"></div>

      <div id="main-body"></div>

    </section>

    <script src="img/jquery.min.js"></script> 
    <script src="img/bootstrap.min.js"></script>

  </body>
</html>
```

此模板加载 CSS 和脚本，并包含消息和主要部分的占位符。

我们还需要一个小模块，该模块获取主要内容和一些其他选项，并将它们应用于此模板。我们将其放在`templates/layout.js`中：

```js
var Plates = require('plates'),
    fs     = require('fs');

var templates = {
  layout : fs.readFileSync(__dirname + '/layout.html', 'utf8'),
  alert  : fs.readFileSync(__dirname + '/alert.html', 'utf8')
};

module.exports = function(main, title, options) {

  if (! options) {
    options = {};
  }

  var data = {
    "main-body": main,
    "title": title,
    'messages': ''
  };

  ['error', 'info'].forEach(function(messageType) {
    if (options[messageType]) {
      data.messages += Plates.bind(templates.alert,
        {message: options[messageType]});
    }
  });

  return Plates.bind(templates.layout, data);
};
```

在 Node.js 中，模块只是一个旨在被其他模块使用的 JavaScript 文件。模块内的所有变量都是私有的；如果模块作者希望向外部世界公开值或函数，它会修改或设置`module.exports`中的特殊变量。

在我们的情况下，这个模块导出一个函数，该函数获取主页面内容的标记，页面标题和一些选项，如信息或错误消息，并将其应用于布局模板。

我们还需要将以下标记文件放在`templates/alert.html`下：

```js
<div class="alert">
  <a class="close" data-dismiss="alert">×</a>
  <p class="message"></p>
</div>
```

现在我们准备开始实现一些要求。

## 用户注册

这个应用程序将为用户提供一个个人待办事项列表。在他们可以访问它之前，他们需要在系统中注册。为此，您需要定义一些 URL，用户将使用这些 URL 来获取我们的用户注册表单并提交它。

现在您将更改`app.js`文件。此文件包含一组初始化过程，包括此块：

```js
app.router.get('/', function () {
  this.res.json({ 'hello': 'world' })
});
```

这个块正在将所有具有`/`URL 的 HTTP 请求路由，并且 HTTP 方法是`GET`到给定的函数。然后，对于具有这两个特征的每个请求，将调用此函数，在这种情况下，您正在回复`{"hello":"world"}`，用户将在浏览器上看到打印出来。

现在我们需要删除这个路由，并添加一些路由，允许用户注册自己。

为此，创建一个名为`routes`的文件夹，您将在其中放置所有路由模块。第一个是`routes/users.js`，将包含以下代码：

```js
var fs      = require('fs'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName),
    Plates  = require('plates'),
    layout  = require('../templates/layout');

var templates = {
  'new' : fs.readFileSync(__dirname +
    '/../templates/users/new.html', 'utf8'),
  'show': fs.readFileSync(__dirname +
    '/../templates/users/show.html', 'utf8')
};

function insert(doc, key, callback) {
  var tried = 0, lastError;

  (function doInsert() {
    tried ++;
    if (tried >= 2) {
      return callback(lastError);
    }

    db.insert(doc, key, function(err) {
      if (err) {
        lastError = err;
        if (err.status_code === 404) {
          couchdb.db.create(dbName, function(err) {
            if (err) {
              return callback(err);
            }
            doInsert();
          });
        } else {
          return callback(err);
        }
      }
      callback.apply({}, arguments);
    });
  }());
}

function render(user) {
  var map = Plates.Map();
  map.where('id').is('email').use('email').as('value');
  map.where('id').is('password').use('password').as('value');
  return Plates.bind(templates['new'], user || {}, map);
}

module.exports = function() {
  this.get('/new', function() {
    this.res.writeHead(200, {'Content-Type': 'text/html'});
    this.res.end(layout(render(), 'New User'));
  });

  this.post('/', function() {

    var res = this.res,
        user = this.req.body;

    if (! user.email || ! user.password) {
      return this.res.end(layout(templates['new'],
        'New User', {error: 'Incomplete User Data'}));
    }

    insert(user, this.req.body.email, function(err) {
      if (err) {
        if (err.status_code === 409) {
          return res.end(layout(render(user), 'New User', {
            error: 'We already have a user with that email address.'}));
        }
        console.error(err.trace);
        res.writeHead(500, {'Content-Type': 'text/html'});
        return res.end(err.message);
      }
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(layout(templates['show'], 'Registration Complete'));
    });
  });

};
```

这个新模块导出一个函数，将绑定两个新路由`GET /new`和`POST /`。这些路由稍后将被附加到`/users`命名空间，这意味着当服务器接收到`GET`请求`/users/new`和`POST`请求`/users`时，它们将被激活。

在`GET /new`路由上，我们将呈现一个包含用户表单的模板。将其放在`templates/users/new.html`下：

```js
<h1>New User</h1>
<form action="/users" method="POST">
  <p>
    <label for="email">E-mail</label>
    <input type="email" name="email" value="" id="email" />
  </p>
  <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password" value="" required/>
  </p>
  <input type="submit" value="Submit" />
</form>
```

我们还需要创建一个`感谢您注册`模板，您需要将其放在`templates/users/show.html`中：

```js
<h1>Thank you!</h1>
<p>Thank you for registering. You can now <a href="/session/new">log in here</a></p>
```

在`POST /`路由处理程序中，我们将进行一些简单的验证，并通过调用名为`insert`的函数将用户文档插入 CouchDB 数据库。此函数尝试插入用户文档，并利用一些巧妙的错误处理。如果错误是“404 Not Found”，这意味着`users`数据库尚未创建，我们将利用这个机会创建它，并自动重复用户文档插入。

您还捕获了 409 冲突的 HTTP 状态码，如果我们尝试插入已存在的键的文档，CouchDB 将返回此状态码。由于我们使用用户电子邮件作为文档键，因此我们通知用户该用户名已经存在。

### 注意

在这里，除了其他简化之外，您将用户密码以明文存储在数据库中。这显然是不推荐的，但由于本书的核心不是如何创建 Web 应用程序，因此这个实现细节与您的目标无关。

现在，我们需要通过更新并在`app.js`文件中的`app.start(3000)`之前添加一行来将这些新路由附加到`/users/` URL 命名空间：

```js
var flatiron = require('flatiron'),
    path = require('path'),
    nstatic = require('node-static'),
    app = flatiron.app;

app.config.file({ file: path.join(__dirname, 'config', 'config.json') });

var file = new nstatic.Server(__dirname + '/public/');

app.use(flatiron.plugins.http, {
  before: [
    function(req, res) {
      var found = app.router.dispatch(req, res);
      if (! found) {
        file.serve(req, res);
      }
    }
  ]
});

app.router.path('/users', require('./routes/users'));

app.start(3000);
```

现在，您可以通过在命令行中输入以下命令来启动应用程序：

```js
$ node app
```

这将启动服务器。然后打开 Web 浏览器，访问`http://localhost:3000/users/new`。您将获得一个用户表单：

![用户注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_05.jpg)

提交电子邮件和密码，您将获得一个确认屏幕：

![用户注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_06.jpg)

此屏幕将向您显示一个链接，指向尚不存在的`/session/new` URL。

现在，您已经准备好实现登录屏幕。

## 登录和会话管理

为了能够保持会话，您的 HTTP 服务器需要能够执行两件事：解析 cookie 和存储会话数据。为此，我们使用两个模块，即`flatware-cookie-parser`和`flatware-session`，您应该将它们添加到`package.json`清单中：

```js
{
  "description": "To-do App",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "union": "0.3.0",
    "flatiron": "0.2.8",
    "plates": "0.4.x",
    "node-static": "0.6.0",
    "nano": "3.3.0",
 "flatware-cookie-parser": "0.1.x",
 "flatware-session": "0.1.x"
  },
  "scripts": {
    "test": "vows --spec",
    "start": "node app.js"
  },
  "name": "todo",
  "author": "Pedro",
  "homepage": ""
}
```

现在，安装缺少的依赖项：

```js
$ npm install
flatware-cookie-parser@0.1.0 node_modules/flatware-cookie-parser

flatware-session@0.1.0 node_modules/flatware-session
```

接下来，在文件`app.js`中向您的服务器添加这些中间件组件：

```js
var flatiron = require('flatiron'),
    path = require('path'),
    nstatic = require('node-static'),
    app = flatiron.app;

app.config.file({ file: path.join(__dirname, 'config', 'config.json') });

var file = new nstatic.Server(__dirname + '/public/');

app.use(flatiron.plugins.http, {
  before: [
 require('flatware-cookie-parser')(),
 require('flatware-session')(),
    function(req, res) {
      var found = app.router.dispatch(req, res);
      if (! found) {
        file.serve(req, res);
      }
    }
  ]
});

app.router.path('/users', require('./routes/users'));
app.router.path('/session', require('./routes/session'));

app.start(3000);
```

我们还需要创建一个`routes/session.js`模块来处理新的会话路由：

```js
var plates  = require('plates'),
    fs      = require('fs'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'users',
    db      = couchdb.use(dbName),
    Plates  = require('plates'),
    layout  = require('../templates/layout');

var templates = {
  'new' : fs.readFileSync(__dirname +
    '/../templates/session/new.html', 'utf8')
};

module.exports = function() {

  this.get('/new', function() {
    this.res.writeHead(200, {'Content-Type': 'text/html'});
    this.res.end(layout(templates['new'], 'Log In'));
  });

  this.post('/', function() {

    var res   = this.res,
        req   = this.req,
        login = this.req.body;

    if (! login.email || ! login.password) {
      return res.end(layout(templates['new'], 'Log In',
        {error: 'Incomplete Login Data'}));
    }

    db.get(login.email, function(err, user) {
      if (err) {
        if (err.status_code === 404) {
          // User was not found
          return res.end(layout(templates['new'], 'Log In',
            {error: 'No such user'}));
        }
        console.error(err.trace);
        res.writeHead(500, {'Content-Type': 'text/html'});
        return res.end(err.message);
      }

      if (user.password !== login.password) {
        res.writeHead(403, {'Content-Type': 'text/html'});
        return res.end(layout(templates['new'], 'Log In',
            {error: 'Invalid password'}));
      }

      // store session
      req.session.user = user;

      // redirect user to TODO list
      res.writeHead(302, {Location: '/todos'});
      res.end();
    });

  });  

};
```

现在，我们需要在`templates/session/new.html`下添加一个视图模板，其中包含登录表单：

```js
<h1>Log in</h1>
<form action="/session" method="POST">
  <p>
    <label for="email">E-mail</label>
    <input type="email" name="email" value="" id="email"/>
  </p>
  <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password" value="" required/>
  </p>
  <input type="submit" value="Log In" />
</form>
```

接下来，如果服务器仍在运行，请停止服务器（按下*Ctrl* + *C*），然后重新启动它：

```js
$ node app.js
```

将浏览器指向`http://localhost:3000/session/new`，并插入您已经注册的用户的电子邮件和密码：

![登录和会话管理](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_07.jpg)

如果登录成功，您将被重定向到`/todos` URL，服务器尚未响应。

接下来，我们将使待办事项列表起作用。

## 待办事项列表

为了显示待办事项列表，我们将使用表格。通过使用 jQuery UI，可以很容易地对待办事项进行排序。启用此功能的简单方法是使用 jQuery UI。仅需此功能，您无需完整的 jQuery UI 库，可以通过将浏览器指向`http://jqueryui.com/download`，取消**交互**元素中除**Sortable**选项之外的所有选项，并单击**Download**按钮来下载自定义构建的 jQuery UI 库。解压缩生成的文件，并将`jquery-ui-1.8.23.custom.min.js`文件复制到`public/js`中。

![待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_08.jpg)

我们需要在`templates.html`或`layout.html`文件中引用此脚本：

```js
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title id="title"></title>
    <link href="/css/bootstrap.min.css" rel="stylesheet" />
  </head>
  <body>

    <section role="main" class="container">

      <div id="messages"></div>

      <div id="main-body"></div>

    </section>

    <script src="img/jquery.min.js"></script> 
 <script src="img/jquery-ui-1.8.23.custom.min.js"></script> 
    <script src="img/bootstrap.min.js"></script>
 <script src="img/todos.js"></script>
  </body>
</html>
```

您还应该在`public/js/todos.js`下添加一个文件，其中包含一些前端交互代码。

现在，我们需要通过首先在`app.js`文件中包含新的路由来响应`/todos` URL：

```js
var flatiron = require('flatiron'),
    path = require('path'),
    nstatic = require('node-static'),
    app = flatiron.app;

app.config.file({ file: path.join(__dirname, 'config', 'config.json') });

var file = new nstatic.Server(__dirname + '/public/');

app.use(flatiron.plugins.http, {
  before: [
    require('flatware-cookie-parser')(),
    require('flatware-session')(),
    function(req, res) {
      var found = app.router.dispatch(req, res);
      if (! found) {
        file.serve(req, res);
      }
    }
  ]
});

app.router.path('/users', require('./routes/users'));
app.router.path('/session', require('./routes/session'));
app.router.path('/todos', require('./routes/todos'));

app.start(3000);
```

然后，我们需要将新的待办事项路由模块放在`routes/todos.js`下：

```js
var fs      = require('fs'),
    couchdb = require('../lib/couchdb'),
    dbName  = 'todos',
    db      = couchdb.use(dbName),
    Plates  = require('plates'),
    layout  = require('../templates/layout'),
    loggedIn = require('../middleware/logged_in')();

var templates = {
  index : fs.readFileSync(__dirname +
    '/../templates/todos/index.html', 'utf8'),
  'new' : fs.readFileSync(__dirname +
    '/../templates/todos/new.html', 'utf8')
};

function insert(email, todo, callback) {
  var tries = 0,
      lastError;

  (function doInsert() {
    tries ++;
    if (tries >= 3) return callback(lastError);

    db.get(email, function(err, todos) {
      if (err && err.status_code !== 404) return callback(err);

      if (! todos) todos = {todos: []};
      todos.todos.unshift(todo);

      db.insert(todos, email, function(err) {
        if (err) {
          if (err.status_code === 404) {
            lastError = err;
            // database does not exist, need to create it
            couchdb.db.create(dbName, function(err) {
              if (err) {
                return callback(err);
              }
              doInsert();
            });
            return;
          }
          return callback(err);
        }
        return callback();
      });
    });
  })();

}

module.exports = function() {

  this.get('/', [loggedIn, function() {

    var res = this.res;

    db.get(this.req.session.user.email, function(err, todos) {

      if (err && err.status_code !== 404) {
        res.writeHead(500);
        return res.end(err.stack);
      }

      if (! todos) todos = {todos: []};
      todos = todos.todos;

      todos.forEach(function(todo, idx) {
        if (todo) todo.pos = idx + 1;
      });

      var map = Plates.Map();
      map.className('todo').to('todo');
      map.className('pos').to('pos');
      map.className('what').to('what');
      map.where('name').is('pos').use('pos').as('value');

      var main = Plates.bind(templates.index, {todo: todos}, map);
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(layout(main, 'To-Dos'));

    });

  }]);

  this.get('/new', [loggedIn, function() {

    this.res.writeHead(200, {'Content-Type': 'text/html'});
    this.res.end(layout(templates['new'], 'New To-Do'));
  }]);

  this.post('/', [loggedIn, function() {

    var req  = this.req,
        res  = this.res,
        todo = this.req.body
    ;

    if (! todo.what) {
      res.writeHead(200, {'Content-Type': 'text/html'});
      return res.end(layout(templates['new'], 'New To-Do',
        {error: 'Please fill in the To-Do description'}));
    }

    todo.created_at = Date.now();

    insert(req.session.user.email, todo, function(err) {

      if (err) {
        res.writeHead(500);
        return res.end(err.stack);
      }

      res.writeHead(303, {Location: '/todos'});
      res.end();
    });

  }]);

  this.post('/sort', [loggedIn, function() {

    var res = this.res,
        order = this.req.body.order && this.req.body.order.split(','),
        newOrder = []
        ;

    db.get(this.req.session.user.email, function(err, todosDoc) {
      if (err) {
        res.writeHead(500);
        return res.end(err.stack);
      }

      var todos = todosDoc.todos;

      if (order.length !== todos.length) {
        res.writeHead(409);
        return res.end('Conflict');
      }

      order.forEach(function(order) {
        newOrder.push(todos[parseInt(order, 10) - 1]);
      });

      todosDoc.todos = newOrder;

      db.insert(todosDoc, function(err) {
        if (err) {
          res.writeHead(500);
          return res.end(err.stack);
        }
        res.writeHead(200);
        res.end();
      });

    });
  }]);

  this.post('/delete', [loggedIn, function() {

    var req = this.req,
        res = this.res,
        pos = parseInt(req.body.pos, 10)
        ;

    db.get(this.req.session.user.email, function(err, todosDoc) {
      if (err) {
        res.writeHead(500);
        return res.end(err.stack);
      }

      var todos = todosDoc.todos;
      todosDoc.todos = todos.slice(0, pos - 1).concat(todos.slice(pos));

      db.insert(todosDoc, function(err) {
        if (err) {
          res.writeHead(500);
          return res.end(err.stack);
        }
        res.writeHead(303, {Location: '/todos'});
        res.end();
      });

    });

  }]);

};
```

该模块响应待办事项索引（`GET /todos`），获取并呈现已登录用户的所有待办事项。将以下模板放在`templates/todos/index.html`下：

```js
<h1>Your To-Dos</h1>

<a class="btn" href="/todos/new">New To-Do</a>

<table class="table">
  <thead>
    <tr>
      <th>#</th>
      <th>What</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="todo-list">
    <tr class="todo">
      <td class="pos"></td>
      <td class="what"></td>
      <td class="remove">
        <form action="/todos/delete" method="POST">
          <input type="hidden" name="pos" value="" />
          <input type="submit" name="Delete" value="Delete" />
        </form>
      </td>
    </tr>
  </tbody>
</table>
```

另一个新路由是`GET /todos/new`，向用户呈现创建新待办事项的表单。此路由使用放置在`templates/todos/new.html`中的新模板：

```js
<h1>New To-Do</h1>
<form action="/todos" method="POST">
  <p>
    <label for="email">What</label>
    <textarea name="what" id="what" required></textarea>
  </p>
  <input type="submit" value="Create" />
</form>
```

`POST /todos`路由通过调用本地的`insert`函数创建新的待办事项，该函数处理了数据库不存在时的错误，并在需要时创建数据库并稍后重试`insert`函数。

索引模板取决于`public/js/todos.js`下放置的客户端脚本的存在：

```js
$(function() {
  $('#todo-list').sortable({
    update: function() {
      var order = [];
      $('.todo').each(function(idx, row) {
        order.push($(row).find('.pos').text());
      });

      $.post('/todos/sort', {order: order.join(',')}, function() {
        $('.todo').each(function(idx, row) {
          $(row).find('.pos').text(idx + 1);
        });
      });

    } 
  });
});
```

此文件激活并处理拖放项目，通过向`/todos/sort` URL 发出 AJAX 调用，传递待办事项的新顺序。

`todos.js`路由模块还处理了每个项目上的**删除**按钮，它通过加载用户的待办事项，删除给定位置的项目并将项目存储回去来处理。

### 注意

到目前为止，您可能已经注意到我们将给定用户的所有待办事项存储在`todos`数据库中的一个文档中。如果所有用户保持待办事项的数量相对较低，这种技术是简单且有效的。无论如何，这些细节对我们的目的并不重要。

为使其工作，我们需要在`middleware/logged_in.js`下提供一个路由中间件。这个中间件组件负责保护一些路由，并在用户未登录时将用户重定向到登录屏幕，而不是执行该路由：

```js
function LoggedIn() {
  return function(next) {
    if (! this.req.session || ! this.req.session.user) {
      this.res.writeHead(303, {Location: '/session/new'});
      return this.res.end();
    }
    next();
  };
}

module.exports = LoggedIn;
```

最后，如果服务器仍在运行，请停止它（按下*Ctrl* + *C*），然后再次启动它：

```js
$ node app.js
```

将浏览器指向`http://localhost:3000/session/new`，并输入您已经注册的用户的电子邮件和密码。然后，您将被重定向到用户的待办事项列表，该列表将开始为空。

![待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_09.jpg)

现在您可以单击**新建待办事项**按钮，获取以下表单：

![待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_10.jpg)

插入一些文本，然后单击**创建**按钮。待办事项将被插入到数据库中，并且更新后的待办事项列表将被呈现：

![待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_11.jpg)

您可以插入任意数量的待办事项。一旦您满意了，您可以尝试通过拖放表格行来重新排序它们。

![待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ui-test/img/0526OS_02_12.jpg)

您还可以单击**删除**按钮来删除特定的待办事项。

# 文件摘要

以下是组成此应用程序的文件列表：

```js
$ tree
.
├── app.js
├── config
│   └── config.json
├── lib
│   └── couchdb.js
├── middleware
│   └── logged_in.js
├── package.json
├── public
│   ├── css
│   │   ├── bootstrap-responsive.css
│   │   ├── bootstrap-responsive.min.css
│   │   ├── bootstrap.css
│   │   └── bootstrap.min.css
│   ├── img
│   │   ├── glyphicons-halflings-white.png
│   │   └── glyphicons-halflings.png
│   └── js
│       ├── bootstrap.js
│       ├── bootstrap.min.js
│       ├── jquery-ui-1.8.23.custom.min.js
│       ├── jquery.min.js
│       └── todos.js
├── routes
│   ├── session.js
│   ├── todos.js
│   └── users.js
├── templates
│   ├── alert.html
│   ├── layout.html
│   ├── layout.js
│   ├── session
│   │   └── new.html
│   ├── todos
│   │   ├── index.html
│   │   └── new.html
│   └── users
│       ├── new.html
│       └── show.html
└── test

13 directories, 27 files
```

# 摘要

在本章中，您学会了如何使用 Node.js、Flatiron.js 和其他一些组件创建一个简单的 Web 应用程序。

这个应用程序将成为我们将来章节中用户界面测试的目标。


# 第三章：安装 Zombie.js 和 Mocha

在本章结束时，您应该能够为使用 Zombie.js 和 Mocha 的应用程序设置测试环境的基本结构。

本章涵盖的主题有：

+   在应用程序清单中设置 Zombie.js 和 Mocha 包

+   设置测试环境

+   运行你的第一个测试

# 更改应用程序清单

现在，您将扩展上一章开始构建的待办事项应用程序，并开始为其提供自我测试的能力。

在应用程序的根目录中，有一个名为`package.json`的文件，您已经修改过，引入了一些应用程序依赖的模块。现在，您需要添加一个新的部分，指定在开发和测试阶段对其他模块的依赖关系。这个部分名为`devDependencies`，只有在`NODE_ENV`环境变量没有设置为`production`时，NPM 才会安装它。这是一个很好的地方，可以介绍那些需要在运行测试时存在的模块的依赖关系。

首先，您需要添加`mocha`和`zombie`模块：

```js
{
  "description": "To-do App",
  "version": "0.0.0",
  "private": true, 
  "dependencies": {
    "union": "0.3.0",
    "flatiron": "0.2.8",
    "plates": "0.4.x",
    "node-static": "0.6.0",
    "nano": "3.3.0",
    "flatware-cookie-parser": "0.1.x",
    "flatware-session": "0.1.x"
  },
 "devDependencies": {
 "mocha": "1.4.x",
 "zombie": "1.4.x"
 },
  "scripts": {
    "test": "vows --spec",
    "start": "node app.js"
  },
  "name": "todo",
  "author": "Pedro",
  "homepage": ""
}
```

然后，您需要使用 NPM 安装这些缺失的依赖项：

```js
$ npm install
...
mocha@1.4.2 node_modules/mocha
...

zombie@1.4.1 node_modules/zombie
...
```

这将在`node_modules`文件夹中安装这两个模块及其内部依赖项，使它们随时可用于您的应用程序。

# 设置测试环境

现在，您需要设置一个测试脚本。首先，您将测试用户注册流程。

但在此之前，为了能够在测试中启动我们的服务器，我们需要对`app.js`文件进行轻微修改：

```js
var flatiron = require('flatiron'),
    path = require('path'),
    nstatic = require('node-static'),
    app = flatiron.app;

app.config.file({ file: path.join(__dirname, 'config', 'config.json') });

var file = new nstatic.Server(__dirname + '/public/');

app.use(flatiron.plugins.http, {
  before: [
    require('flatware-method-override')(),
    require('flatware-cookie-parser')(),
    require('flatware-session')(),
    function(req, res) {
      var found = app.router.dispatch(req, res);
      if (! found) {
        file.serve(req, res);
      }
    }
  ]
});

app.router.path('/users', require('./routes/users'));
app.router.path('/session', require('./routes/session'));
app.router.path('/todos', require('./routes/todos'));

module.exports = app;

if (process.mainModule === module) {
 app.start(3000);
}

```

我们的测试将使用它们自己的服务器，所以在这种情况下，我们不需要`app.js`来为我们运行服务器。最后几行代码导出了应用程序，并且只有在主模块（使用`node`命令行调用的模块）是`app.js`时才启动服务器。由于测试将有一个不同的主模块，所以在运行测试时服务器不会启动。

现在，作为第一个例子，我们将测试获取用户注册表单。我们将把所有与用户路由相关的测试都集中在`test/users.js`文件中。这个文件可以从以下内容开始：

```js
var assert  = require('assert'),
    Browser = require('zombie'),
    app     = require('../app')
    ;

before(function(done) {
  app.start(3000, done);
});

after(function(done) {
  app.server.close(done);
});

describe('Users', function() {

  describe('Signup Form', function() {

    it('should load the signup form', function(done) {
      var browser = new Browser();
      browser.visit("http://localhost:3000/users/new", function() {
        assert.ok(browser.success, 'page loaded');
        done();
      });
    });

  });
});
```

在前面的代码中，我们在顶部包含了`assert`模块（用于验证应用程序是否按预期运行）、`zombie`模块（赋值给`Browser`变量）和`app`模块。`app`模块获取了 Flatiron 应用程序对象，因此您可以启动和停止相应的服务器。

接下来，我们声明，在运行任何测试之前，应该启动应用程序，并且在所有测试完成后，应该关闭服务器。

接下来是一系列嵌套的`describe`调用。这些调用用于为每个测试提供上下文，允许您稍后区分在每个测试之前和之后将发生的设置和拆卸函数。

然后是一个`it`语句，您在其中实现测试。这个语句接受两个参数，即正在测试的主题的描述和在开始测试时将被调用的函数。这个函数得到一个回调函数`done`，在测试完成时调用。这种安排使得异步测试成为可能且可靠。每个测试只有在相应的`done`函数被调用后才结束，这可能是在一系列异步 I/O 调用之后。

然后我们开始创建一个浏览器，并加载用户注册表单的 URL，使用`assert.ok`函数来验证页面是否成功加载。`assert`模块是 Node.js 的核心模块，提供基本的断言测试。在测试代码中，我们放置一些断言来验证一些值是否符合我们的预期。如果任何断言失败，`assert`会抛出一个错误，测试运行器会捕获到这个错误，表示测试失败。

除了基本的`assert.ok`函数之外，如果值不为 true（即通过`x == true`测试），它将抛出错误，该模块还提供了一组辅助函数，以提供更复杂的比较，如`assert.deepEqual`等。有关`assert`模块的更多信息，您可以阅读[`nodejs.org/api/assert.html`](http://nodejs.org/api/assert.html)上的 API 文档。

现在我们需要通过替换`package.json`中 Flatiron 提供的默认值来指定测试命令脚本：

```js
  "scripts": {
 "test": "mocha test/users.js",
    "start": "node app.js"
  },...
```

这指定了当告诉 NPM 运行测试时，NPM 应该执行什么操作。要运行测试，请在命令行上输入以下命令：

```js
$ npm test
```

输出应该是成功的：

```js
...
> mocha test/users.js

  .

  ✔ 1 test complete (284ms)
```

# 摘要

要安装 Mocha 和 Zombie，你需要将它们作为开发依赖项包含在应用程序清单中，然后使用 NPM 安装它们。

一旦这些模块安装好，你可以在名为`test`的目录中为应用程序的每个逻辑组件创建测试文件。每个文件应包含一系列测试，每个测试都应嵌套在`describe`语句中。

您还应该修改应用程序清单，以指定测试脚本，以便可以使用 NPM 运行测试。

在接下来的章节中，我们将不断完善这个测试，并引入一些新的测试，以覆盖我们应用程序的更多使用情况。


# 第四章：理解 Mocha

在上一章中，我们安装并介绍了 Mocha。Mocha 是一个 JavaScript 测试框架，可以在 Node.js 内部或浏览器内部运行。你可以使用它来定义和运行自己的测试。Mocha 会报告测试的结果：哪些测试运行正常，哪些测试失败以及失败发生在哪里。Mocha 依次运行每个测试，等待一个测试完成或超时后再运行下一个。

尽管 Mocha 设计为能够在任何现代浏览器上运行，但我们将仅通过 Node.js 通过命令行来运行它。Mocha 还有其他功能，这将在本章中解释。有关 Mocha 功能的更完整参考，请访问 Mocha 的官方文档网站，[`visionmedia.github.com/mocha/`](http://visionmedia.github.com/mocha/) 了解更多信息。

本章涵盖的主题包括：

+   描述功能并使用断言

+   理解 Mocha 如何执行异步测试

通过本章结束时，你应该能够使用 Mocha 执行异步测试，并理解 Mocha 如何控制测试流程。

# 组织你的测试

有两种策略可以用来组织你的测试。第一种是以某种方式将它们分成单独的文件，每个文件代表应用程序的一个功能或逻辑单元。另一种策略是，可以与第一种策略一起使用，即按功能进行分组。

为应用程序的每个功能单元单独创建一个文件是分离测试关注点的好方法。你应该分析应用程序的结构，并将其分成具有最小重叠量的不同关注点。例如，你的应用程序可能需要处理用户注册 - 这可能是一个功能组。另一个功能组可能是用户登录。如果你的应用程序涉及待办事项列表，你可能希望有一个单独的文件包含该部分的测试。

通过为每个功能组单独创建文件，你可以在处理特定组时独立调用你的测试。这种技术还允许你保持每个文件的行数较低，这在导航和维护测试时很有帮助。

**描述功能**：在定义测试时，你还可以按功能对应用程序功能进行分组。例如，在描述待办事项列表功能时，你可以进一步将这些功能分开如下：

+   创建待办事项

+   删除待办事项

+   显示待办事项列表

+   更改待办事项列表项目的顺序

在我们的测试脚本中，我们将描述先前提到的可测试的待办事项功能。

待办事项测试文件的布局可以如下：

```js
describe('To-do items', function() {

  describe('creating', function() {
    // to-do item creating tests here...
  });

  describe('removing', function() {
    // removing a to-do item tests here...
  });

  describe('showing', function() {
    // to-do item list showing tests here...
  });

  describe('ordering', function() {
    // to-do item ordering tests here...
  });

});
```

你可以嵌套任意多个`describe`语句，尽可能细化测试的范围，但作为一个经验法则，你应该使用两个描述级别：一个用于功能组（例如，待办事项），另一个级别用于每个功能。在每个功能定义内，你可以放置所有相关的测试。

# 使用 before 和 after 钩子

对于任何一组测试，你可以设置某些代码在所有测试之前或之后运行。这对于设置数据库、清理一些状态或一般设置或拆除一些你需要以便运行测试本身的状态非常有用。

在下一个示例中，名为`runBefore`的函数在任何描述的测试之前运行：

```js
describe('some feature', function() {

 before(function runBefore() {
    console.log('running before function...');  });

  it('should do A', function() {
    console.log('test A');
  });

  it('should do B', function() {
    console.log('test B');
  });
});
```

将此文件代码保存为名为`test.js`的文件，并在本地安装 Mocha：

```js
$ npm install mocha
```

运行测试：

```js
$ node_modules/.bin/mocha test.js
```

它应该给出以下输出：

```js
  running before function...
test A
.test B
.

  ✔ 2 tests complete (6ms)
```

类似地，你还可以指定一个函数，在所有测试完成后执行：

```js
describe('some feature', function() {

  after(function runAfter() {
    console.log('running after function...');  });

  it('should do A', function() {
    console.log('test A');
  });

  it('should do B', function() {
    console.log('test B');
  });
});
```

运行此代码会产生以下输出，正如你所期望的那样：

```js
  test A
.test B
.running after function...

  ✔ 2 tests complete (6ms)
```

还可以定义一个函数，在每个测试块之前（或之后）调用，分别使用`beforeEach`和`afterEach`关键字。`beforeEach`关键字的示例用法如下：

```js
describe('some feature', function() {

  beforeEach(function runBeforeEach() {
    console.log('running beforeEach function...');  });

  it('should do A', function() {
    console.log('test A');
  });

  it('should do B', function() {
    console.log('test B');
  });
});
```

如果运行此测试，输出将为：

```js
  running beforeEach function...
test A
.running beforeEach function...
test B
.

  ✔ 2 tests complete (6ms)
```

当然，`afterEach`代码在每次测试执行后调用该函数。

# 使用异步钩子

在任何测试之前运行的这些函数都可以是异步的。如果一个函数是异步的，只需接受一个回调参数，就像这样：

```js
describe('some feature', function() {
  function runBeforeEach(done) {
    console.log('running afterEach function...');
    setTimeout(done, 1000);
  }
  beforeEach(runBeforeEach);

  it('should do A', function() {
    console.log('test A');
  });

  it('should do B', function() {
    console.log('test B');
  });
});
```

运行此测试代码时，您会注意到每次测试运行前有一秒的延迟，如果没有提供回调参数，这一点是不会被观察到的。

## 钩子如何与测试组交互

正如我们所见，在描述范围内，您可以有相应的`before`、`after`、`beforeEach`和`afterEach`钩子。如果您有一个嵌套的`describe`范围，该范围也可以有钩子。除了当前范围上的钩子之外，Mocha 还将调用所有父范围上的钩子。考虑一下这段代码，我们在其中声明了一个两级嵌套：

```js
describe('feature A', function() {

  before(function() {
    console.log('before A');
  });

  after(function() {
    console.log('after A');
  });

  beforeEach(function() {
    console.log('beforeEach A');
  });

  afterEach(function() {
    console.log('afterEach A');
  });

  describe('feature A.1', function() {
    before(function() {
      console.log('before A.1');
    });

    after(function() {
      console.log('after A.1');
    });

    beforeEach(function() {
      console.log('beforeEach A.1');
    });

    afterEach(function() {
      console.log('afterEach A.1');
    });

    it('should do A.1.1', function() {
      console.log('A.1.1');
    });

    it('should do A.1.2', function() {
      console.log('A.1.2');
    });

  });

});
```

运行上述代码时，输出为：

```js
  before A
before A.1
beforeEach A
beforeEach A.1
A.1.1
.afterEach A.1
afterEach A
beforeEach A
beforeEach A.1
A.1.2
.afterEach A.1
afterEach A
after A.1
after A

  ✔ 4 tests complete (16ms)
```

# 使用断言

现在您有一个用于测试代码的地方，您需要一种验证代码是否按预期运行的方法。为此，您需要一个断言测试库。

有许多断言测试库适用于许多编程风格，但在这里，我们将使用 Node.js 已经捆绑的一个，即`assert`模块。它包含了您需要描述每个测试的期望的最小一组实用函数。在每个测试文件的顶部，您需要使用`require`引入断言库：

```js
var assert = require('assert');
```

### 注意

您可以断言任何表达式的“真实性”。“真实”和“虚假”是 JavaScript（以及其他语言）中的概念，其中类型强制转换允许某些值等同于布尔值 true 或 false。一些例子如下：

```js
var a = true;
assert.ok(a, 'a should be truthy');
```

虚假值为：

+   `false`

+   `null`

+   `undefined`

+   空字符串

+   `0`（数字零）

+   `NaN`

所有其他值都为真。

您还可以使用`assert.equal`来进行相等的测试：

```js
var a = 'ABC';
assert.equal(a, 'ABC');
```

您还可以使用`assert.notEqual`来进行不相等的测试：

```js
var a = 'ABC';
assert.notEqual(a, 'ABCDEF');
```

这最后两个测试等同于 JavaScript 的`==`（宽松相等）运算符，这意味着它们适用于布尔值、字符串、`undefined`和`null`，但不适用于对象和数组。例如，这个断言将失败：

```js
assert.equal({a:1}, {a:1});
```

它将失败，因为在 JavaScript 中，没有本地方法来比较两个对象的等价性，从而使以下表达式为假：

```js
{a: 1} == {a:1}
```

要比较对象（包括数组），您应该使用`assert.deepEqual`：

```js
assert.deepEqual({a:1}, {a:1});
assert.deepEqual([0,1], [0,1]);
```

这个函数递归地比较对象，找出它们是否有某种不同。这个函数也可以用于深度嵌套的对象，正如其名称所暗示的那样：

```js
assert.deepEqual({a:[0,1], b: {c:2}}, {a:[0,1], b: {c:2}});
```

您还可以测试深层不相等：

```js
assert.notDeepEqual({a:[0,1], b: {c:2}}, {a:[0,1], b: {c:2, d: 3}});
```

## 更改断言消息

当断言失败时，将抛出一个包含消息的错误，其中打印了预期值和实际值：

```js
> var a = false;
> assert.ok(a)
AssertionError: false == true
    at repl:1:9
    at REPLServer.self.eval (repl.js:111:21)
    at Interface.<anonymous> (repl.js:250:12)
    at Interface.EventEmitter.emit (events.js:88:17)
    at Interface._onLine (readline.js:199:10)
    at Interface._line (readline.js:517:8)
    at Interface._ttyWrite (readline.js:735:14)
    at ReadStream.onkeypress (readline.js:98:10)
    at ReadStream.EventEmitter.emit (events.js:115:20)
    at emitKey (readline.js:1057:12)
```

如果愿意，可以用另一种更具上下文的消息类型替换默认消息类型。通过将消息作为任何断言函数的最后一个参数传入来实现这一点：

```js
var result = 'ABC';
assert.equal(result, 'DEF', 'the result of operation X should be DEF');
```

# 执行异步测试

Mocha 按顺序运行所有测试，每个测试可以是同步的或异步的。对于同步测试，测试回调函数不应接受任何参数，就像前面的例子一样。但由于 Node.js 不会阻塞 I/O 操作，我们需要对每个测试执行 I/O 操作（至少向服务器发出一个 HTTP 请求），因此我们的测试需要是异步的。

要使测试变成异步，测试函数应该接受一个回调函数，就像这样：

```js
it('tests something asynchronous', function(done) {
  doSomethingAsynchronous(function(err) {
    assert.ok(! err);
 done();
  });
});
```

`done`回调函数还接受一个错误作为第一个参数，这意味着您可以直接调用`done`，而不是抛出错误：

```js
it('tests something asynchronous', function(done) {
  doSomethingAsynchronous(function(err) {
    done(err);
  });
});
```

如果不需要测试异步函数的返回值，可以直接传递`done`函数，就像这样：

```js
it('tests something asynchronous', function(done) {
 doSomethingAsynchronous(done);
});
```

**超时**：默认情况下，Mocha 为每个异步测试保留 2 秒。您可以通过向 Mocha 传递`-t`参数来全局更改这个时间：

```js
$ node_modules/.bin/mocha test.js -t 4s
```

在这里，您可以使用以`s`为后缀的秒数，如所示，或者您可以简单地传递毫秒数：

```js
$ node_modules/.bin/mocha test.js -t 4000
```

您还可以通过使用`this.timeout(ms)`来指定任何测试的超时，就像这样：

```js
it('tests something asynchronous', function(done) {
  this.timeout(500); // 500 milliseconds
  doSomethingAsynchronous(done);
});
```

# 总结

Mocha 是一个运行您的测试的框架。您应该根据您想要覆盖的功能区域将测试拆分为几个文件，然后描述每个功能并为每个功能定义必要的测试。

对于这些测试组中的每一个，您可以选择指定要使用`before`、`beforeEach`、`after`和`afterEach`来调用的回调函数。这些回调函数是指定设置和拆卸函数的地方。这些拆卸或设置函数中的每一个都可以是同步的或异步的。此外，这些测试本身也可以通过简单地将回调传递给测试来使其异步运行，一旦测试完成，回调就会被调用。

对于异步测试，Mocha 保留了默认的 2 秒超时，您可以在全局范围或每个测试的基础上进行覆盖。

在接下来的章节中，我们将看到如何开始使用 Zombie.js 来模拟和操纵浏览器。
