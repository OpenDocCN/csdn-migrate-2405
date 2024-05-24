# NuxtJS Web 开发实用指南（七）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五部分：测试和部署

在本节中，我们将编写测试并将 Nuxt 应用程序部署到托管服务器上。我们还将学习如何使用一些 JavaScript 工具保持我们的代码整洁，同时遵守编码标准。

本节包括以下章节：

+   第十三章，编写端到端测试

+   第十四章，使用检查器、格式化程序和部署命令


编写端到端测试

编写测试是 Web 开发的一部分。您的应用程序变得越来越复杂和庞大，您就越需要测试应用程序，否则它将在某个时候出现故障，并且您将花费大量时间修复错误和补丁。在本章中，您将使用 AVA 和 jsdom 为 Nuxt 应用编写端到端测试，并且还将亲身体验使用 Nightwatch 进行浏览器自动化测试。您将学习如何安装这些工具并设置测试环境-让我们开始吧。

本章我们将涵盖的主题如下：

+   端到端测试与单元测试

+   端到端测试工具

+   使用`jsdomn`和 AVA 为 Nuxt 应用编写测试

+   介绍 Nightwatch

+   使用 Nightwatch 为 Nuxt 应用编写测试

# 第十三章：端到端测试与单元测试

通常有两种类型的测试用于 Web 应用程序：单元测试和端到端测试。你可能听说过很多关于单元测试，并且在过去做过一些（或者很多）。单元测试用于测试应用程序的小部分和个体部分，而相反，端到端测试用于测试应用程序的整体功能。端到端测试涉及确保应用程序的集成组件按预期运行。换句话说，整个应用程序在类似于真实用户与应用程序交互的真实场景中进行测试。例如，用户登录页面的简化端到端测试可能涉及以下内容：

1.  加载登录页面。

1.  在登录表单中输入有效的详细信息。

1.  点击“提交”按钮。

1.  成功登录到页面并看到问候消息。

1.  退出系统。

那么单元测试呢？单元测试运行速度快，可以精确识别确切的问题和错误。单元测试的主要缺点是为应用程序的每个方面编写测试非常耗时。而且尽管您的应用程序已通过了单元测试，但整体应用程序仍可能出现故障。

端到端测试可以隐式测试许多方面，并确保您拥有一个正常工作的系统。与单元测试相比，端到端测试运行速度较慢，并且无法明确指出应用程序失败的根本原因。应用程序中看似不重要的部分发生微小变化可能会破坏整个测试套件。

将应用程序的单元测试和端到端测试结合在一起可能是理想和令人信服的，因为这样可以更彻底地测试您的应用程序，但这可能会耗费时间和金钱。在本书中，我们专注于**端到端测试**，因为默认情况下，Nuxt 与端到端测试工具无缝配置，您将在下一节中发现。

# 端到端测试工具

Nuxt 通过将 AVA 和 jsdom Node.js 模块一起使用，使端到端测试变得非常简单和有趣。但在 Nuxt 应用程序中实现并结合它们进行测试之前，让我们深入了解这些 Node.js 模块的每一个，看看它们是如何分开工作的，这样您就可以对这些工具有一个扎实的基本理解。让我们从下一节开始学习 jsdom。

## jsdom

简而言之，`jsdom`是基于 JavaScript 的 W3C 文档对象模型（DOM）在 Node.js 中的实现。但是，这意味着什么？我们需要它做什么？想象一下，您需要在 Node.js 应用程序中从原始 HTML 的服务器端操作 DOM，例如 Express 和 Koa 应用程序，但服务器端没有 DOM，因此您无法做太多事情。这就是 jsdom 拯救我们的时候。它将原始 HTML 转换为在 Node.js 中像客户端 DOM 一样工作的 DOM 片段。然后，您可以使用客户端 JavaScript 库，如 jQuery，在 Node.js 上操作 DOM。以下是用于服务器端应用程序的基本用法示例：

1.  在服务器端应用程序上导入 jsdom：

```js
import jsdom from 'jsdom'
const { JSDOM } = jsdom
```

1.  将任何原始 HTML 字符串传递给`JSDOM`构造函数，您将获得一个 DOM 对象：

```js
const dom = new JSDOM(<!DOCTYPE html><p>Hello World</p>)
console.log(dom.window.document.querySelector('p').textContent)
```

您从前面的代码片段中获得的 DOM 对象具有许多有用的属性，特别是`window`对象，然后您可以开始像在客户端上一样操作传递的 HTML 字符串。现在让我们在**Koa API**上应用这个工具，您在上一章中了解过，并且可以在我们的 GitHub 存储库中的`/chapter-12/nuxt-universal/cross-domain/jwt/axios-module/backend/`中找到，以打印`Hello world`消息。按照以下步骤进行：

1.  通过 npm 安装`jsdom`和 jQuery：

```js
$ npm i jsdom --save-dev
$ npm i jquery --save-dev
```

1.  导入`jsdom`并传递 HTML 字符串，就像我们在前面的基本用法示例中所做的那样：

```js
// src/modules/public/home/_routes/index.js
import Router from 'koa-router'
import jsdom from 'jsdom'

const { JSDOM } = jsdom
const router = new Router()

const html = '<!DOCTYPE html><p>Hello World</p>'
const dom = new JSDOM(html)
const window = dom.window
const text = window.document.querySelector('p').textContent
```

1.  将`text`输出到端点：

```js
router.get('/', async (ctx, next) => {
  ctx.type = 'json'
  ctx.body = {
    message: text
  }
})
```

当您在终端上运行`npm run dev`时，您应该在`localhost:4000/public`看到以 JSON 格式显示的“Hello world”消息（在下面的代码片段中显示）：

```js
{"status":200,"data":{"message":"Hello world"}}
```

1.  在我们的 API 中创建一个`movie`模块，并使用 Axios 从 IMDb 网站获取 HTML 页面，将 HTML 传递给 JSDOM 构造函数，导入 jQuery，然后将其应用于由 jsdom 创建的 DOM 窗口对象如下：

```js
// src/modules/public/movie/_routes/index.js
const url = 'https://www.imdb.com/movies-in-theaters/'
const { data } = await axios.get(url)

const dom = new JSDOM(data)
const $ = (require('jquery'))(dom.window)
```

请注意，Axios 必须通过 npm 在您的项目目录中安装，您可以使用`npm i axios`进行安装。

1.  将 jQuery 对象应用于所有具有`list_item`类的电影，并提取数据（每部电影的名称和放映时间）如下：

```js
var items = $('.list_item')
var list = []
$.each(items, function( key, item ) {
  var movieName = $('h4 a', item).text()
  var movieShowTime = $('h4 span', item).text()
  var movie = {
    name: movieName,
    showTime: movieShowTime
  }
  list.push(movie)
})
```

1.  将`list`输出到端点：

```js
ctx.type = 'json'
ctx.body = {
  list: list
}
```

您应该在`localhost:4000/public/movies`看到以下 JSON 格式的类似电影列表：

```js
{
  "status": 200,
  "data": {
    "list": [{
      "name": " Onward (2020)",
      "showTime": ""
    }, {
      "name": " Finding the Way Back (2020)",
      "showTime": ""
    },
    ...
    ...
    ]
  }
}
```

你可以在我们的 GitHub 存储库的`/chapter-13/jsdom/`中找到这些示例。有关此 npm 包的更多信息，请访问[`github.com/jsdom/jsdom`](https://github.com/jsdom/jsdom)。

您可以看到此工具在服务器端有多有用。它使我们能够像在客户端一样操纵原始 HTML。现在让我们在下一节中继续学习 AVA 的一些基本用法，然后在我们的 Nuxt 应用程序中与**jsdom**一起使用。

## AVA

简而言之，AVA（不是 Ava 或 ava，发音为`/ˈeɪvə/`）是一个用于 Node.js 的 JavaScript 测试运行器。有很多测试运行器：Mocha、Jasmine 和 tape 等。AVA 是现有列表的另一种选择。首先，AVA 很简单。它真的很容易设置。此外，默认情况下它并行运行测试，这意味着您的测试将运行得很快。它适用于前端和后端的 JavaScript 应用程序。总而言之，它绝对值得一试。让我们通过以下步骤开始创建一个简单的基本 Node.js 应用程序：

1.  通过 npm 安装 AVA 并将其保存到`package.json`文件的`devDependencies`选项中：

```js
$ npm i ava --save-dev
```

1.  安装 Babel 核心和其他 Babel 包，以便我们可以在应用程序的测试中编写 ES6 代码：

```js
$ npm i @babel/polyfill
$ npm i @babel/core --save-dev
$ npm i @babel/preset-env --save-dev
$ npm i @babel/register --save-dev
```

1.  在`package.json`文件中配置`test`脚本如下：

```js
// package.json
{
  "scripts": {
    "test": "ava --verbose",
    "test:watch": "ava --watch"
  },
  "ava": {
    "require": [
      "./setup.js",
      "@babel/polyfill"
    ],
    "files": [
      "test/**/*"
    ]
  }
}
```

1.  在根目录中创建一个`setup.js`文件，其中包含以下代码：

```js
// setup.js
require('@babel/register')({
  babelrc: false,
  presets: ['@babel/preset-env']
})
```

1.  在我们的应用程序中的两个单独文件中创建以下类和函数，以便稍后进行测试：

```js
// src/hello.js
export default class Greeter {
  static greet () {
    return 'hello world'
  }
}

// src/add.js
export default function (num1, num2) {
  return num1 + num2
}
```

1.  在`/test/`目录中为测试`/src/hello.js`创建一个`hello.js`测试：

```js
// test/hello.js
import test from 'ava'
import hello from '../src/hello'

test('should say hello world', t => {
  t.is('hello world', hello.greet())
})
```

1.  在`/test/`目录中的另一个文件中创建另一个测试，用于测试`/src/add.js`：

```js
// test/add.js
import test from 'ava'
import add from '../src/add'

test('amount should be 50', t => {
  t.is(add(10, 50), 60)
})
```

1.  在终端上运行所有测试：

```js
$ npm run test
```

您还可以使用`--watch`标志运行测试，以启用 AVA 的观察模式：

```js
$ npm run test:watch
```

如果测试通过，您应该会得到以下结果：

```js
✓ add › amount should be 50
✓ hello › should say hello world

2 tests passed
```

您可以在我们的 GitHub 存储库的`/chapter-13/ava/`中找到前面的示例。有关此 npm 包的更多信息，请访问[`github.com/avajs/ava`](https://github.com/avajs/ava)。

这很容易也很有趣，不是吗？看到我们的代码通过测试总是令人满意的。现在您已经对这个工具有了基本的了解，所以现在是时候在 Nuxt 应用程序中使用 jsdom 来实现它了。让我们在下一节中开始吧。

# 使用 jsdomn 和 AVA 为 Nuxt 应用程序编写测试

您已经独立学习了`jsdom`和`AVA`，并进行了一些简单的测试。现在，我们可以将这两个包合并到我们的 Nuxt 应用程序中。让我们在我们在上一章中创建的 Nuxt 应用程序中安装它们，路径为`/chapter-12/nuxt-universal/cross-domain/jwt/axios-module/frontend/`，使用以下步骤：

1.  通过 npm 安装这两个工具，并将它们保存到`package.json`文件中的`devDependencies`选项中：

```js
$ npm i ava --save-dev
$ npm i jsdom --save-dev
```

1.  安装`Babel`核心和其他 Babel 包，以便我们可以在应用程序中编写 ES6 代码：

```js
$ npm i @babel/polyfill
$ npm i @babel/core --save-dev
$ npm i @babel/preset-env --save-dev
$ npm i @babel/register --save-dev
```

1.  将 AVA 配置添加到`package.json`文件中，如下所示：

```js
// package.json
{
  "scripts": {
    "test": "ava --verbose",
    "test:watch": "ava --watch"
  },
  "ava": {
    "require": [
      "./setup.js",
      "@babel/polyfill"
    ],
    "files": [
      "test/**/*"
    ]
  }
}
```

1.  在根目录中创建一个`setup.js`文件，就像您在上一节中所做的那样，但使用以下代码：

```js
// setup.js
require('@babel/register')({
  babelrc: false,
  presets: ['@babel/preset-env']
})
```

1.  准备以下测试模板，以便在`/test/`目录中编写测试：

```js
// test/tests.js
import test from 'ava'
import { Nuxt, Builder } from 'nuxt'
import { resolve } from 'path'

let nuxt = null

test.before('Init Nuxt.js', async t => {
  const rootDir = resolve(__dirname, '..')
  let config = {}
  try { config = require(resolve(rootDir, 'nuxt.config.js')) } 
   catch (e) {}
  config.rootDir = rootDir
  config.dev = false
  config.mode = 'universal'
  nuxt = new Nuxt(config)
  await new Builder(nuxt).build()
  nuxt.listen(5000, 'localhost')
})

// write your tests here...

test.after('Closing server', t => {
  nuxt.close()
})
```

测试将在`localhost:5000`上运行（或者您喜欢的任何端口）。您应该在生产构建上进行测试，因此在`config.dev`键中关闭开发模式，并在`config.mode`键中使用`universal`，如果您的应用程序同时为服务器端和客户端开发。然后，在测试过程完成后，请确保关闭 Nuxt 服务器。

1.  编写第一个测试，测试我们的主页，以确保在此页面上呈现了正确的 HTML：

```js
// test/tests.js
test('Route / exits and renders correct HTML', async (t) => {
  let context = {}
  const { html } = await nuxt.renderRoute('/', context)
  t.true(html.includes('<p class="blue">My marvelous Nuxt.js 
   project</p>'))
})
```

1.  为`/about`路由编写第二个测试，以确保在此页面上呈现了正确的 HTML。

```js
// test/tests.js
test('Route /about exits and renders correct HTML', async (t) => {
  let context = {}
  const { html } = await nuxt.renderRoute('/about', context)
  t.true(html.includes('<h1>About page</h1>'))
  t.true(html.includes('<p class="blue">Something awesome!</p>'))
})
```

1.  为`/about`页面编写第三个测试，以确保通过服务器端的`jsdom`进行 DOM 操作，文本内容、类名和样式符合预期。

```js
// test/tests.js
test('Route /about exists and renders correct HTML and style', 
async (t) => {

  function hexify (number) {
    const hexChars = 
     ['0','1','2','3','4','5','6','7','8','9','a','b',
      'c','d','e','f']
    if (isNaN(number)) {
      return '00'
    }
    return hexChars[(number - number % 16) / 16] + 
     hexChars[number % 16]
  }

  const window = await nuxt.renderAndGetWindow(
   'http://localhost:5000/about')
  const element = window.document.querySelector('.blue')
  const rgb = window.getComputedStyle(element).color.match(/\d+/g)
  const hex = '' + hexify(rgb[0]) + hexify(rgb[1]) + hexify(rgb[2])

  t.not(element, null)
  t.is(element.textContent, 'Something awesome!')
  t.is(element.className, 'blue')
  t.is(hex, '0000ff')
})
```

如果测试通过`npm run test`，您应该会得到以下结果：

```js
✓ Route / exits and renders correct HTML (369ms)
✓ Route /about exits and renders correct HTML (369ms)
✓ Route /about exists and renders correct HTML and style (543ms)

3 tests passed
```

您可以看到，在我们的第三个测试中，我们创建了一个`hexify`函数，用于将由`Window.getComputedStyle`方法计算的十进制代码（R、G、B）转换为十六进制代码。例如，您将得到`rgb(255, 255, 255)`，对应于您在 CSS 样式中设置为`color: white`的颜色。因此，对于`0000ff`，您将得到`rgb(0, 0, 255)`，应用程序必须将其转换以通过测试。

您可以在我们的 GitHub 存储库的`/chapter-13/nuxt-universal/ava/`中找到这些测试。

干得好。您已经成功为 Nuxt 应用程序编写了简单的测试。我们希望您发现在 Nuxt 中编写测试很容易且有趣。您的测试的复杂性取决于您想要测试什么。因此，首先了解您想要测试的内容非常重要。然后，您可以开始编写一个合理、有意义和相关的测试。

然而，使用 jsdom 与 AVA 测试 Nuxt 应用程序存在一些限制，因为它不涉及浏览器。请记住，jsdom 用于在服务器端将原始 HTML 转换为 DOM，因此我们在前面的练习中使用了 async/await 语句来异步请求页面进行测试。如果您想要使用浏览器来测试您的 Nuxt 应用程序，Nightwatch 可能是一个很好的解决方案，因此我们将在下一节中介绍它。让我们继续。

# 介绍 Nightwatch

Nightwatch 是一个自动化测试框架，为基于 Web 的应用程序提供端到端的测试解决方案。它在幕后使用 W3C WebDriver API（以前称为 Selenium WebDriver）来打开**web 浏览器**，对 DOM 元素执行操作和断言。如果您想要使用浏览器来测试您的 Nuxt 应用程序，这是一个很好的工具。但在 Nuxt 应用程序中使用它之前，让我们按照以下步骤单独使用它来编写一些简单的测试，以便您对其工作原理有一个基本的了解：

1.  通过 npm 安装 Nightwatch，并将其保存到`package.json`文件的`devDependencies`选项中：

```js
$ npm i nightwatch --save-dev
```

1.  通过 npm 安装 GeckoDriver，并将其保存到`package.json`文件的`devDependencies`选项中：

```js
$ npm install geckodriver --save-dev
```

Nightwatch 依赖于 WebDriver，因此我们需要根据您的**目标浏览器**安装特定的 WebDriver 服务器-例如，如果您只想针对 Firefox 编写测试，则需要安装 GeckoDriver。

在本书中，我们专注于针对单个浏览器编写测试。但是，如果您想要并行地针对多个浏览器（如 Chrome、Edge、Safari 和 Firefox）进行测试，那么您需要安装**Selenium Standalone Server**（也称为 Selenium Grid），如下所示：

```js
$ npm i selenium-server --save-dev
```

请注意，在本书中我们将在 Firefox 和 Chrome 上进行测试，因此不会使用`selenium-server`包。

1.  在`package.json`文件的`test`脚本中添加`nightwatch`：

```js
// package.json
{
  "scripts": {
    "test": "nightwatch"
  }
}
```

1.  创建一个`nightwatch.json`文件来配置 Nightwatch 如下：

```js
// nightwatch.json
{
  "src_folders" : ["tests"],

  "webdriver" : {
    "start_process": true,
    "server_path": "node_modules/.bin/geckodriver",
    "port": 4444
  },

  "test_settings" : {
    "default" : {
      "desiredCapabilities": {
        "browserName": "firefox"
      }
    }
  },

  "launch_url": "https://github.com/lautiamkok"
}
```

在这个简单的练习中，我们想要测试 github.com 上特定贡献者**Lau Tiam Kok**的仓库搜索功能，所以我们在这个配置中的`launch_url`选项中设置了`https://github.com/lautiamkok`。

我们将在`/tests/`目录中编写测试，所以我们在`src_folders`选项中指定了目录位置。我们将仅针对 Firefox 进行测试，端口为`4444`，所以我们在`webdriver`和`test_settings`选项中设置了这些信息。

你可以在[`nightwatchjs.org/gettingstarted/configuration/`](https://nightwatchjs.org/gettingstarted/configuration/)找到其余测试设置的选项，比如`output_folder`。如果你想找出 Selenium 服务器的测试设置，请访问[`nightwatchjs.org/gettingstarted/configuration/selenium-server-settings`](https://nightwatchjs.org/gettingstarted/configuration/#selenium-server-settings)。

1.  在项目根目录中创建一个`nightwatch.conf.js`文件，用于将驱动程序路径**动态**设置为服务器路径：

```js
// nightwatch.conf.js
const geckodriver = require("geckodriver")
module.exports = (function (settings) {
  settings.test_workers = false
  settings.webdriver.server_path = geckodriver.path
  return settings
})(require("./nightwatch.json"))
```

1.  在`/tests/`目录中的一个`.js`文件（例如`demo.js`）中准备以下 Nightwatch 测试模板，如下所示：

```js
// tests/demo.js
module.exports = {
  'Demo test' : function (browser) {
    browser
      .url(browser.launchUrl)
      // write your tests here...
      .end()
  }
}
```

1.  在`/tests/`目录中创建一个`github.js`文件，其中包含以下代码：

```js
// tests/github.js
module.exports = {
  'Demo test GitHub' : function (browser) {
    browser
      .url(browser.launchUrl)
      .waitForElementVisible('body', 1000)
      .assert.title('lautiamkok (LAU TIAM KOK) · GitHub')
      .assert.visible('input[type=text][placeholder=Search]')
      .setValue('input[type=text][placeholder=Search]', 'nuxt')
      .waitForElementVisible('li[id=jump-to-suggestion-
        search-scoped]', 1000)
      .click('li[id=jump-to-suggestion-search-scoped]')
      .pause(1000)
      .assert.visible('ul[class=repo-list]')
      .assert.containsText('em:first-child', 'nuxt')
      .end()
  }
}
```

在这个测试中，我们想要断言仓库搜索功能是否按预期工作，所以我们需要确保某些元素和文本内容存在并可见，比如`<body>`和`<input>`元素，以及`nuxt`和`lautiamkok (LAU TIAM KOK) · GitHub`的文本。当你用`npm run test`运行它时，你应该得到以下结果（假设测试通过）：

```js
[Github] Test Suite
===================
Running: Demo test GitHub

✓ Element <body> was visible after 34 milliseconds.
✓ Testing if the page title equals "lautiamkok (LAU TIAM KOK) · 
   GitHub" - 4 ms.
✓ Testing if element <input[type=text][placeholder=Search]> is 
   visible - 18 ms.
✓ Element <li[id=jump-to-suggestion-search-scoped]> was visible 
   after 533 milliseconds.
✓ Testing if element <ul[class=repo-list]> is visible - 25 ms.
✓ Testing if element <em:first-child> contains text: "nuxt"
  - 28 ms.

OK. 6 assertions passed. (5.809s)
```

你可以在我们的 GitHub 仓库的`/chapter-13/nightwatch/`中找到上述测试。有关 Nightwatch 的更多信息，请访问[`nightwatchjs.org/`](https://nightwatchjs.org/)。

与 AVA 相比，Nightwatch 并不那么简洁，因为它需要一些可能会很冗长和复杂的配置，但如果你遵循最简单的`nightwatch.json`文件，它应该能让你很快地开始使用 Nightwatch。所以，让我们在下一节将你刚学到的内容应用到 Nuxt 应用中。

# 使用 Nightwatch 为 Nuxt 应用编写测试。

在这个练习中，我们希望针对**Chrome 浏览器**测试我们在上一章第十二章中创建的用户登录验证和 API 身份验证。我们希望确保用户可以使用他们的凭据登录并按预期获取他们的用户数据。我们将在存放 Nuxt 应用程序的`/frontend/`目录中编写测试，因此我们需要相应地修改`package.json`文件，并按以下步骤编写测试：

1.  通过 npm 安装 ChromeDriver 并将其保存到`package.json`文件中的`devDependencies`选项中：

```js
$ npm install chromedriver --save-dev
```

1.  在`nightwatch.json`文件中将启动 URL 更改为`localhost:3000`，并根据以下代码块中显示的其他设置修改 Nightwatch 配置文件，以便针对 Chrome 进行测试：

```js
// nightwatch.json
{
  "src_folders" : ["tests"],

  "webdriver" : {
    "start_process": true,
    "server_path": "node_modules/.bin/chromedriver",
    "port": 9515
  },

  "test_settings" : {
    "default" : {
      "desiredCapabilities": {
        "browserName": "chrome"
      }
    }
  },

  "launch_url": "http://localhost:3000"
}
```

1.  在项目根目录中创建一个`nightwatch.conf.js`文件，用于将驱动程序路径**动态**设置为服务器路径：

```js
// nightwatch.conf.js
const chromedriver = require("chromedriver")
module.exports = (function (settings) {
  settings.test_workers = false
  settings.webdriver.server_path = chromedriver.path
  return settings
})(require("./nightwatch.json"))
```

1.  在`/tests/`目录中创建一个`login.js`文件，其中包含以下代码：

```js
// tests/login.js
module.exports = {
  'Local login test' : function (browser) {
    browser
      .url(browser.launchUrl + '/login')
      .waitForElementVisible('body', 1000)
      .assert.title('nuxt-e2e-tests')
      .assert.containsText('h1', 'Please login to see the 
       secret content')
      .assert.visible('input[type=text][name=username]')
      .assert.visible('input[type=password][name=password]')
      .setValue('input[type=text][name=username]', 'demo')
      .setValue('input[type=password][name=password]', 
       '123123')
      .click('button[type=submit]')
      .pause(1000)
      .assert.containsText('h2', 'Hello Alexandre!')
      .end()
  }
}
```

这个测试的逻辑与上一节的测试相同。我们希望在登录前后确保登录页面上存在某些元素和文本。

1.  在运行测试之前，在终端上运行 Nuxt 和 API 应用程序，分别在`localhost:3000`和`localhost:4000`上运行，然后在`/frontend/`目录中打开另一个终端并运行`npm run test`。如果测试通过，您应该会得到以下结果：

```js
[Login] Test Suite
==================
Running: Local login test

✓ Element <body> was visible after 28 milliseconds.
✓ Testing if the page title equals "nuxt-e2e-tests" - 4 ms.
✓ Testing if element <h1> contains text: "Please login to see the 
   secret content" - 27 ms.
✓ Testing if element <input[type=text][name=username]> is 
   visible - 25 ms.
✓ Testing if element <input[type=password][name=password]> is 
   visible - 25 ms.
✓ Testing if element <h2> contains text: "Hello Alexandre!" 
  - 75 ms.

OK. 6 assertions passed. (1.613s)
```

请注意，在运行测试之前，您必须同时运行 Nuxt 应用程序和 API。您可以在我们的 GitHub 存储库的`/chapter-13/nuxt-universal/nightwatch/`中找到前面的测试。

做得好。您已经完成了关于为 Nuxt 应用程序编写测试的简短章节。本章中的步骤和练习为您提供了扩展测试的基本基础，使您的应用程序变得更大更复杂。让我们在最后一节总结一下您在本章学到的内容。

# 总结

在本章中，您已经学会了使用 jsdom 进行服务器端 DOM 操作，并分别使用 AVA 和 Nightwatch 编写简单的测试，然后尝试使用这些工具一起在我们的 Nuxt 应用程序上运行端到端测试。您还学会了端到端测试和单元测试之间的区别以及它们各自的优缺点。最后但同样重要的是，您从本章的练习中学到，Nuxt 默认配置完美，可以让您使用 jsdom 和 AVA 轻松编写端到端测试。

在接下来的章节中，我们将介绍如何使用诸如 ESLint、Prettier 和 StandardJS 等代码检查工具来保持我们的代码整洁，以及如何将它们集成和混合到 Vue 和 Nuxt 应用程序中。最后，您将学习 Nuxt 部署命令，并使用它们将您的应用程序部署到实时服务器上。所以，请继续关注。


使用 Linter、Formatter 和部署命令

除了编写测试（无论是端到端测试还是单元测试），代码检查和格式化也是 Web 开发的一部分。所有开发人员，无论您是 Java、Python、PHP 还是 JavaScript 开发人员，都应该了解其领域的编码标准，并遵守这些标准，以保持您的代码清洁、可读，并为将来更好地维护格式化。我们通常用于 JavaScript、Vue 和 Nuxt 应用的工具是 ESLint、Prettier 和 StandardJS。在本章中，您将学习如何安装、配置和使用它们。最后，在构建、测试和检查您的应用程序之后，您将学习 Nuxt 部署命令，以将您的应用程序部署到主机。

本章我们将涵盖以下主题：

+   介绍 linter - Prettier、ESLint 和 StandardJS

+   集成 ESLint 和 Prettier

+   为 Vue 和 Nuxt 应用程序使用 ESLint 和 Prettier

+   部署 Nuxt 应用程序

# 第十四章：介绍 linter - Prettier、ESLint 和 StandardJS

简而言之，linter 是一种分析源代码并标记代码和样式中的错误和错误的工具。这个术语起源于 1978 年的一个名为`lint`的 Unix 实用程序，它评估了用 C 编写的源代码，并由贝尔实验室的计算机科学家 Stephen C. Johnson 开发，用于调试他正在编写的 Yacc 语法。今天，我们在本书中关注的工具是 Prettier、ESLint 和 StandardJS。让我们来看看它们各自的情况。

## Prettier

Prettier 是一个支持许多语言的代码格式化程序，如 JavaScript、Vue、JSX、CSS、HTML、JSON、GraphQL 等。它提高了代码的可读性，并确保您的代码符合它为您设置的规则。它为您的代码行设置了长度限制；例如，看一下以下单行代码：

```js
hello(reallyLongArg(), omgSoManyParameters(), IShouldRefactorThis(), isThereSeriouslyAnotherOne())
```

上面的代码被认为是单行代码过长且难以阅读，因此 Prettier 将为您重新打印成多行，如下所示：

```js
hello(
  reallyLongArg(),
  omgSoManyParameters(),
  IShouldRefactorThis(),
  isThereSeriouslyAnotherOne()
);
```

此外，任何自定义或混乱的样式也会被解析和重新打印，如下例所示：

```js
fruits({ type: 'citrus' },
  'orange', 'kiwi')

fruits(
  { type: 'citrus' },
  'orange',
  'kiwi'
)
```

Prettier 会将其打印并重新格式化为以下更整洁的格式：

```js
fruits({ type: 'citrus' }, 'orange', 'kiwi');

fruits({ type: 'citrus' }, 'orange', 'kiwi');
```

但是，如果 Prettier 在您的代码中找不到分号，它将为您插入分号，就像前面的示例代码一样。如果您喜欢代码中没有分号，您可以关闭此功能，就像本书中使用的所有代码一样。让我们通过以下步骤关闭这个规则：

1.  通过 npm 将 Prettier 安装到您的项目中：

```js
$ npm i prettier --save-dev --save-exact
```

1.  解析特定的 JavaScript 文件：

```js
$ npx prettier --write src/index.js
```

或者，解析递归文件夹中的所有文件：

```js
$ npx prettier --write "src/**/*"
```

甚至尝试解析并行文件夹中的文件：

```js
$ npx prettier --write "{scripts,config,bin}/**/*"
```

在提交任何**原地**更改（注意！）之前，您可以使用其他输出选项，例如以下选项：

+   使用`-c`或`--check`来检查给定的文件是否格式化，并在之后打印一个人性化的摘要消息，其中包含未格式化文件的路径。

+   使用`-l`或`--list-different`来打印与 Prettier 格式不同的文件的名称。

有关此工具的更多信息，请访问[`prettier.io/`](https://prettier.io/)。

现在让我们看看如何在下一节中配置这个工具。

### 配置 Prettier

Prettier 具有许多自定义选项。您可以通过以下选项配置 Prettier：

+   一个 JavaScript 对象中的`prettier.config.js`或`.prettierrc.js`脚本

+   使用`prettier`键的`package.json`文件

+   一个 YAML 或 JSON 中的`.prettierrc`文件，可选扩展名：`.json`，`.yaml`或`.yml`

+   一个 TOML 中的`.prettierrc.toml`文件

即使您可以选择不这样做，但定制 Prettier 是一个好主意。例如，Prettier 默认强制使用双引号，并在语句末尾打印分号。如果我们不想要这些默认设置，我们可以在项目根目录中创建一个`prettier.config.js`文件。让我们在以下步骤中使用 Prettier 在我们创建的 API 中（我们在 GitHub 存储库的`/chapter-14/apps-to-fix/koa-api/`中制作了一份副本）使用此配置：

1.  在我们的项目根目录中创建一个`prettier.config.js`文件，其中包含以下代码：

```js
// prettier.config.js
module.exports = {
  semi: false,
  singleQuote: true
}
```

1.  使用以下命令解析`/src/`目录中的所有 JavaScript 代码：

```js
$ npx prettier --write "src/**/*"
```

如您所见，当您运行`npx prettier --write "src/**/*"`时，所有我们的文件都会在终端上列出：

```js
src/config/google.js 40ms
src/config/index.js 11ms
src/core/database/mysql.js 18ms
src/index.js 8ms
...
```

Prettier 将突出显示已重新打印和格式化的文件。

有关更多格式选项，请查看[`prettier.io/docs/en/options.html`](https://prettier.io/docs/en/options.html)。您可以在我们的 GitHub 存储库的`/chapter-14/prettier/`中找到此示例。

当您如此轻松地看到您的代码被“美化”时，这是相当不错的，不是吗？让我们继续下一个 linter，ESLint，看看它如何在下一节中帮助整理我们的代码。

## ESLint

ESLint 是一个用于 JavaScript 的可插拔代码检查工具。它被设计成所有规则都是完全可插拔的，并允许开发人员自定义代码检查规则。ESLint 附带了一些内置规则，使其从一开始就很有用，但你可以在任何时候动态加载规则。例如，ESLint 禁止对象字面量中的重复键（`no-dupe-keys`），你将会得到以下代码的错误：

```js
var message = {
  text: "Hello World",
  text: "qux"
}
```

根据这个规则的正确代码将如下所示：

```js
var message = {
  text: "Hello World",
  words: "Hello World"
}
```

ESLint 将标记前面的错误，我们将不得不手动修复它。但是，可以在命令行上使用`--fix`选项来自动修复一些更容易在没有人为干预的情况下修复的问题。让我们看看如何在以下步骤中做到这一点：

1.  在你的项目中通过 npm 安装 ESLint：

```js
$ npm i eslint --save-dev
```

1.  设置一个配置文件：

```js
$ ./node_modules/.bin/eslint --init
```

你将被要求回答类似以下的问题列表：

```js
? How would you like to use ESLint? To check syntax, find problems,
  and enforce code style
? What type of modules does your project use? JavaScript modules (import/export)
? Which framework does your project use? None of these
? Where does your code run? (Press <space> to select, <a> to 
  toggle all, <i> to invert selection)Browser
? How would you like to define a style for your project? Use 
  a popular style guide
? Which style guide do you want to follow? Standard (https://github.com/standard/standard)
? What format do you want your config file to be in? JavaScript
...

Successfully created .eslintrc.js file in /path/to/your/project
```

这些问题可能会根据你为每个问题选择的选项/答案而有所不同。

1.  将`lint`和`lint-fix`脚本添加到`package.json`文件中：

```js
"scripts": {
  "lint": "eslint --ignore-path .gitignore .",
  "lint-fix": "eslint --fix --ignore-path .gitignore ."
}
```

1.  创建一个`.gitignore`文件，包含我们希望 ESLint 忽略的路径和文件：

```js
// .gitignore
node_modules
build
backpack.config.js
```

1.  启动 ESLint 进行错误扫描：

```js
$ npm run lint
```

1.  使用`lint-fix`来修复这些错误：

```js
$ npm run lint-fix
```

你可以在[`eslint.org/docs/rules/`](https://eslint.org/docs/rules/)查看 ESLint 规则列表。ESLint 的规则按类别分组：可能的错误、最佳实践、变量、风格问题、ECMAScript 6 等等。默认情况下没有启用任何规则。你可以在配置文件中使用`"extends": "eslint:recommended"`属性来启用报告常见问题的规则，这些规则在列表中有一个勾号（✓）。

有关此工具的更多信息，请访问[`eslint.org/`](https://eslint.org/)。

现在让我们看看如何在下一节中配置这个工具。

### 配置 ESLint

正如我们之前提到的，ESLint 是一个可插拔的代码检查工具。这意味着它是完全可配置的，你可以关闭每个规则，或其中一些规则，或混合自定义规则，使 ESLint 特别适用于你的项目。让我们在我们创建的 API 中使用 ESLint，并选择以下配置之一。有两种方法来配置 ESLint：

+   在文件中直接使用 JavaScript 注释与 ESLint 配置信息，就像下面的例子一样：

```js
// eslint-disable-next-line no-unused-vars
import authenticate from 'middlewares/authenticate'
```

+   使用 JavaScript、JSON 或 YAML 文件来指定整个目录及其所有子目录的配置信息。

使用第一种方法可能会耗费时间，因为您可能需要在每个`.js`文件中提供 ESLint 配置信息，而在第二种方法中，您只需要在`.json`文件中**一次**配置它。因此，在以下步骤中，让我们使用第二种方法来为我们的 API 进行配置：

1.  创建一个`.eslintrc.js`文件，或者在根目录中使用`--init`生成它，其中包含以下规则：

```js
// .eslintrc.js
module.exports = {
  'rules': {
    'no-undef': ['off'],
    'no-console': ['error']
    'quotes': ['error', 'double']
  }
}
```

在这些规则中，我们希望确保执行以下操作：

+   通过将`no-undef`选项设置为`off`来允许未声明的变量(`no-undef`)

+   通过将`no-console`选项设置为`error`来禁止使用控制台(`no-console`)

+   强制使用反引号、双引号或单引号(`quotes`)，将`quotes`选项设置为`error`和`double`

1.  将`lint`和`lint-fix`脚本添加到`package.json`文件中：

```js
// package.json
"scripts": {
  "lint": "eslint --ignore-path .gitignore .",
  "lint-fix": "eslint --fix --ignore-path .gitignore ."
}
```

1.  启动 ESLint 进行错误扫描：

```js
$ npm run lint
```

如果有任何错误，您将收到以下类似的报告：

```js
/src/modules/public/login/_routes/google/me.js 
   36:11  error  A space is required after '{'  object-
          curly-spacing 
   36:18  error  A space is required before '}' object-
          curly-spacing 
```

尽管 ESLint 可以使用`--fix`选项自动修复您的代码，但您仍然需要手动修复一些，就像以下示例中一样：

```js
/src/modules/public/user/_routes/fetch-user.js 
  9:9  error  'id' is assigned a value but never used  
       no-unused-vars 
```

有关配置的更多信息，请查看[`eslint.org/docs/user-guide/configuring`](https://eslint.org/docs/user-guide/configuring)。您可以在我们的 GitHub 存储库的`/chapter-14/eslint/`中找到此示例。

它用户友好，不是吗？它确实是另一个像 Prettier 一样令人敬畏的工具。让我们继续介绍最后一个代码检查器 StandardJS，看看它如何整理我们的代码。

## StandardJS

StandardJS 或 JavaScript 标准样式是 JavaScript 样式指南、代码检查器和格式化程序。它完全是主观的，这意味着它是完全不可定制的 - 不需要配置，因此没有`.eslintrc`、`.jshintrc`或`.jscsrc`文件来管理。它是不可定制和不可配置的。使用 StandardJS 的最简单方法是将其作为 Node 命令行程序全局安装。让我们看看您可以如何在以下步骤中使用此工具：

1.  通过 npm 全局安装 StandardJS：

```js
$ npm i standard --global
```

您还可以为单个项目在本地安装它：

```js
$ npm i standard --save-dev
```

1.  导航到要检查的目录，并在终端中输入以下命令：

```js
$ standard
```

1.  如果您在本地安装了 StandardJS，则使用`npx`来运行它：

```js
$ npx standard
```

您还可以将其添加到`package.json`文件中，如下所示：

```js
// package.json
{
  scripts": {
    "jss": "standard",
    "jss-fix": "standard --fix"
  },
  "devDependencies": {
    "standard": "¹².0.1"
  },
  "standard": {
    "ignore": [
      "/node_modules/",
      "/build/",
      "backpack.config.js"
    ]
  }
}
```

1.  然后，当您使用 npm 运行 JavaScript 项目的代码时，代码将被自动检查：

```js
$ npm run jss
```

要修复任何混乱或不一致的代码，请尝试以下命令：

```js
$ npm run jss-fix
```

尽管 StandardJS 是不可定制的，但它依赖于 ESLint。StandardJS 使用的 ESLint 包如下：

+   `eslint`

+   `standard-engine`

+   `eslint-config-standard`

+   `eslint-config-standard-jsx`

+   `eslint-plugin-standard`

虽然 Prettier 是一个格式化工具，StandardJS 大多是一个类似 ESLint 的 linter。如果你在你的代码上使用`--fix`来修复 StandardJS 或 ESLint，然后再用 Prettier 运行它，你会发现任何长行（这些行被 StandardJS 和 ESLint 忽略）将被 Prettier 格式化。

有关此工具的更多信息，请访问[`standardjs.com/`](https://standardjs.com/)。你还应该查看标准 JavaScript 规则的摘要，网址为[`standardjs.com/rules.html`](https://standardjs.com/rules.html)。你可以在我们的 GitHub 存储库的`/chapter-14/standard/`中找到一个使用 StandardJS 的示例。

然而，如果你正在寻找一个更灵活和可定制的解决方案，介于这些工具之间，你可以为你的项目结合使用 Prettier 和 ESLint。让我们在下一节看看你如何实现这一点。

# 集成 ESLint 和 Prettier

Prettier 和 ESLint 相辅相成。我们可以将 Prettier 集成到 ESLint 的工作流中。这样你就可以使用 Prettier 来格式化你的代码，同时让 ESLint 专注于 linting 你的代码。因此，为了集成它们，首先我们需要从 ESLint 中使用`eslint-plugin-prettier`插件来使用 Prettier。然后我们可以像往常一样使用 Prettier 来添加格式化代码的规则。

然而，ESLint 包含与 Prettier 冲突的格式相关的规则，比如`arrow-parens`和`space-before-function-paren`，在一起使用时可能会引起一些问题。为了解决这些冲突问题，我们需要使用`eslint-config-prettier`配置来关闭与 Prettier 冲突的 ESLint 规则。让我们在以下步骤中看看你如何实现这一点：

1.  通过 npm 安装`eslint-plugin-prettier`和`eslint-config-prettier`：

```js
$ npm i eslint-plugin-prettier --save-dev
$ npm i eslint-config-prettier --save-dev
```

1.  在`.eslintrc.json`文件中启用`eslint-plugin-prettier`的插件和规则：

```js
{
  "plugins": ["prettier"],
  "rules": {
    "prettier/prettier": "error"
  }
}
```

1.  使用`eslint-config-prettier`在`.eslintrc.json`文件中通过扩展 Prettier 的规则来覆盖 ESLint 的规则：

```js
{
  "extends": ["prettier"]
}
```

请注意，值"`prettier`"应该放在`extends`数组的最后，以便 Prettier 的配置可以覆盖 ESLint 的配置。此外，我们可以使用`.eslintrc.js`文件而不是 JSON 文件来进行上述配置，因为我们可以在 JavaScript 文件中添加有用的注释。因此，以下是我们在 ESLint 下使用 Prettier 的配置：

```js
// .eslintrc.js
module.exports = {
  //...
  'extends': ['prettier']
  'plugins': ['prettier'],
  'rules': {
    'prettier/prettier': 'error'
  }
}
```

1.  在`package.json`文件（或`prettier.config.js`文件）中配置 Prettier，以便 Prettier 不会在我们的代码中打印分号，并始终使用单引号：

```js
{
  "scripts": {
    "lint": "eslint --ignore-path .gitignore .",
    "lint-fix": "eslint --fix --ignore-path .gitignore ."
  },
  "prettier": {
    "semi": false,
    "singleQuote": true
  }
}
```

1.  在终端上运行`npm run lint-fix`以一次性修复和格式化我们的代码。之后，您可以使用`npx prettier`命令再次仅使用 Prettier 检查代码：

```js
$ npx prettier --c "src/**/*"
```

然后您应该在终端上获得以下结果：

```js
Checking formatting...
All matched files use Prettier code style!
```

这意味着我们的代码没有格式问题，并且在 Prettier 代码样式中成功编译。将这两个工具结合起来以满足我们的需求和偏好是非常酷的，不是吗？但是您仍然只完成了一半-让我们在下一节中为 Vue 和 Nuxt 应用程序应用这些配置。

您可以在我们的 GitHub 存储库的`/chapter-14/eslint+prettier/`中找到此集成示例。

# 在 Vue 和 Nuxt 应用程序中使用 ESLint 和 Prettier

eslint-plugin-vue 插件是 Vue 和 Nuxt 应用程序的官方 ESLint 插件。它允许我们使用 ESLint 检查`.vue`文件中`<template>`和`<script>`块中的代码，以查找任何语法错误，错误使用 Vue 指令以及违反 Vue 风格指南的 Vue 样式。此外，我们正在使用 Prettier 来强制执行代码格式，因此像我们在上一节中所做的那样安装`eslint-plugin-prettier`和`eslint-config-prettier`以获取我们喜欢的基本特定配置。让我们在以下步骤中解决所有这些问题：

1.  使用 npm 安装`eslint-plugin-vue`插件：

```js
$ npm i eslint-plugin-vue --save-dev
```

您可能会收到一些警告：

```js
npm WARN eslint-plugin-vue@5.2.3 requires a peer of eslint@⁵.0.0
 but none is installed. You must install peer dependencies
  yourself.
npm WARN vue-eslint-parser@5.0.0 requires a peer of eslint@⁵.0.0 
 but none is installed. You must install peer dependencies 
  yourself.
```

忽略它们，因为`eslint-plugin-vue`的最低要求是 ESLint v5.0.0 或更高版本和 Node.js v6.5.0 或更高版本，而您应该已经拥有最新版本。

您可以在[`eslint.vuejs.org/user-guide/installation`](https://eslint.vuejs.org/user-guide/#installation)查看最低要求。除了 Vue 风格指南，您还应该查看[`eslint.vuejs.org/rules/`](https://eslint.vuejs.org/rules/)上的 Vue 规则。

1.  在 ESLint 配置文件中添加`eslint-plugin-vue`插件及其通用规则集：

```js
// .eslintrc.js
module.exports = {
  extends: [
    'plugin:vue/recommended'
  ]
}
```

1.  安装 `eslint-plugin-prettier` 和 `eslint-config-prettier` 并将它们添加到 ESLint 配置文件中：

```js
// .eslintrc.js
module.exports = {
  'extends': [
    'plugin:vue/recommended',
    'plugin:prettier/recommended'
  ],
  'plugins': [
    'prettier'
  ]
}
```

但这些还不够。您可能希望配置一些 Vue 规则以适应您的偏好。让我们在下一节中找出一些默认的 Vue 关键规则，我们可能希望配置。

有关此 `eslint-plugin-vue` 插件的更多信息，请访问 [`eslint.vuejs.org/`](https://eslint.vuejs.org/)。有关 Vue 指令，请访问 [`vuejs.org/v2/api/Directives`](https://vuejs.org/v2/api/#Directives)，有关 Vue 风格指南，请访问 [`vuejs.org/v2/style-guide/`](https://vuejs.org/v2/style-guide/)。

## 配置 Vue 规则

在本书中，我们只想覆盖四个默认的 Vue 规则。您只需要在 `.eslintrc.js` 文件的 `'rules'` 选项中添加首选规则，就像我们在上一节中为 `eslint-plugin-prettier` 插件所做的那样。让我们按照以下步骤进行：

1.  将 `vue/v-on-style` 规则配置为 "`longform`" 如下：

```js
// .eslintrc.js
'rules': {
  'vue/v-on-style': ['error', 'longform']
}
```

`vue/v-on-style` 规则强制在 `v-on` 指令样式上使用 `shorthand` 或 `longform`。默认设置为 `shorthand`，例如：

```js
<template>
  <!-- ✓ GOOD -->
  <div @click="foo"/>

  <!-- ✗ BAD -->
  <div v-on:click="foo"/>
</template>
```

但在本书中，首选 `longform`，如下例所示：

```js
<template>
  <!-- ✓ GOOD -->
  <div v-on:click="foo"/>

  <!-- ✗ BAD -->
  <div @click="foo"/>
</template>
```

有关此规则的更多信息，请访问 [`eslint.vuejs.org/rules/v-on-style.htmlvue-v-on-style`](https://eslint.vuejs.org/rules/v-on-style.html#vue-v-on-style)。

1.  将 `vue/html-self-closing` 规则配置为允许在空元素上使用自闭合符号如下：

```js
// .eslintrc.js
'rules': {
  'vue/html-self-closing': ['error', {
    'html': {
      'void': 'always'
    }
  }]
}
```

空元素是 HTML 元素，在任何情况下都不允许有内容，例如 `<br>`、`<hr>`、`<img>`、`<input>`、`<link>` 和 `<meta>`。在编写 XHTML 时，必须自闭这些元素，例如 `<br/>` 和 `<img src="..." />`。在本书中，即使在 HTML5 中，`/` 字符被认为是可选的，我们也希望允许这样做。

根据 `vue/html-self-closing` 规则，自闭合这些空元素将导致错误，尽管它旨在强制 HTML 元素中的自闭合符号。这相当令人困惑，对吧？在 Vue.js 模板中，我们可以使用以下两种样式来表示没有内容的元素：

+   +   `<YourComponent></YourComponent>`

+   `<YourComponent/>`（自闭合）

根据此规则，第一个选项将被拒绝，如下例所示：

```js
<template>
  <!-- ✓ GOOD -->
  <MyComponent/>

  <!-- ✗ BAD -->
  <MyComponent></MyComponent>
</template>
```

然而，它也拒绝了自闭合的空元素：

```js
<template>
  <!-- ✓ GOOD -->
  <img src="...">

  <!-- ✗ BAD -->
  <img src="..." />
</template>
```

换句话说，在 Vue 规则中，不允许空元素具有自闭合标记。因此，默认情况下，`html.void`选项的值设置为`'never'`。因此，如果您想要允许这些空元素上的自闭合标记，就像本书中一样，那么将值设置为`'always'`。

有关此规则的更多信息，请访问[`eslint.vuejs.org/rules/html-self-closing.htmlvue-html-self-closing`](https://eslint.vuejs.org/rules/html-self-closing.html#vue-html-self-closing)。

1.  将`vue/max-attributes-per-line`规则配置为关闭此规则如下：

```js
// .eslintrc.js
'rules': {
  'vue/max-attributes-per-line': 'off'
}
```

`vue/max-attributes-per-line`规则旨在强制每行一个属性。默认情况下，当两个属性之间有换行时，认为属性在新行中。以下是在此规则下的示例：

```js
<template>
  <!-- ✓ GOOD -->
  <MyComponent lorem="1"/>
  <MyComponent
    lorem="1"
    ipsum="2"
  />
  <MyComponent
    lorem="1"
    ipsum="2"
    dolor="3"
  />

  <!-- ✗ BAD -->
  <MyComponent lorem="1" ipsum="2"/>
  <MyComponent
    lorem="1" ipsum="2"
  />
  <MyComponent
    lorem="1" ipsum="2"
    dolor="3"
  />
</template>
```

然而，此规则与 Prettier 冲突。我们应该让 Prettier 处理这样的情况，这就是为什么我们会关闭这个规则。

有关此规则的更多信息，请访问[`eslint.vuejs.org/rules/max-attributes-per-line.htmlvue-max-attributes-per-line`](https://eslint.vuejs.org/rules/max-attributes-per-line.html#vue-max-attributes-per-line)。

1.  配置`eslint/space-before-function-paren`规则：

```js
// .eslintrc.js
'rules': {
  'space-before-function-paren': ['error', 'always']
}
```

`eslint/space-before-function-paren`规则旨在强制在函数声明的括号前添加一个空格。ESLint 默认行为是添加空格，这也是 StandardJS 中定义的规则。请参阅以下示例：

```js
function message (text) { ... } // ✓ ok
function message(text) { ... } // ✗ avoid

message(function (text) { ... }) // ✓ ok
message(function(text) { ... }) // ✗ avoid
```

然而，在前述规则下，当您使用 Prettier 时，您将会收到以下错误：

```js
/middleware/auth.js
  1:24 error Delete · prettier/prettier
```

我们将忽略 Prettier 的错误，因为我们想要遵循 Vue 中的规则。但是目前，Prettier 还没有选项来禁用这个规则，可以从[`prettier.io/docs/en/options.html`](https://prettier.io/docs/en/options.html)查看。如果因为 Prettier 而删除了空格，您可以通过在 Vue 规则下将值设置为`'always'`来添加回来。

有关此规则的更多信息，请访问[`eslint.org/docs/rules/space-before-function-paren`](https://eslint.org/docs/rules/space-before-function-paren)和[`standardjs.com/rules.html`](https://standardjs.com/rules.html)。

1.  因为 ESLint 默认只针对`.js`文件，所以在 ESLint 命令中使用`--ext`选项（或者 glob 模式）包含`.vue`扩展名，以在终端上运行 ESLint 并使用前述配置。

```js
$ eslint --ext .js,.vue src
$ eslint "src/**/*.{js,vue}"
```

您还可以在`package.json`文件中的`.gitignore`选项中使用自定义命令来运行它，如下所示：

```js
// package.json
"scripts": {
  "lint": "eslint --ext .js,.vue --ignore-path .gitignore .",
  "lint-fix": "eslint --fix --ext .js,.vue --ignore-path 
   .gitignore ."
}

// .gitignore
node_modules
build
nuxt.config.js
prettier.config.js
```

ESLint 将忽略在前面的`.gitignore`片段中定义的文件，同时对所有 JavaScript 和 Vue 文件进行 lint。通过 webpack 进行热重载时对文件进行 lint 是一个好主意。只需将以下片段添加到 Nuxt 配置文件中，以便在保存代码时运行 ESLint：

```js
// nuxt.config.js
...
build: {
 extend(config, ctx) {
    if (ctx.isDev && ctx.isClient) {
      config.module.rules.push({
        enforce: "pre",
        test: /\.(js|vue)$/,
        loader: "eslint-loader",
        exclude: /(node_modules)/
      })
    }
  }
}
```

您可以在我们的 GitHub 存储库的`/chapter-14/eslint-plugin-vue/integrate/`中找到一个使用此插件与 ESLint 的示例。

正如您在本节和前几节中所看到的，将 ESLint 和 Prettier 混合在单个配置文件中可能会有问题。您可能得到的麻烦可能不值得让它们“作为一个团队”一起工作。为什么不尝试在不耦合它们的情况下分别运行它们呢？让我们在下一节中找出如何为 Nuxt 应用程序做到这一点。

## 在 Nuxt 应用程序中分别运行 ESLint 和 Prettier

另一个解决 ESLint 和 Prettier 之间冲突的可能解决方案，特别是在`space-before-function-paren`上，是根本不集成它们，而是分别运行它们来格式化和检查我们的代码。所以让我们在以下步骤中让它们正常工作：

1.  在`package.json`文件中分别为 Prettier 和 ESLint 创建脚本，如下所示：

```js
// package.json
"scripts": {
"prettier": "prettier --check \"
 {components,layouts,pages,store,middleware,plugins}/**/*.{vue,js}
   \"", "prettier-fix": "prettier --write 
   {components,layouts,pages,store,middleware,plugins}
    /**/*.{vue,js}\"", "lint": "eslint --ext .js,.vue 
    --ignore-path .gitignore .",
   "lint-fix": "eslint --fix --ext .js,.vue --ignore-path
     .gitignore ."
}
```

现在我们可以完全忘记`eslint-plugin-prettier`和我们工作流程中的`eslint-config-prettier`配置。我们仍然保留`eslint-plugin-vue`和在本章中已经配置的规则，但是完全从`.eslintrc.js`文件中删除 Prettier：

```js
// .eslintrc.js
module.exports = {
  //...
  'extends': [
    'standard',
    'plugin:vue/recommended',
    // 'prettier' // <- removed this.
  ]
}
```

1.  当我们想要分析我们的代码时，先运行 Prettier，然后运行 ESLint：

```js
$ npm run prettier
$ npm run lint
```

1.  再次，当我们想要修复格式并对我们的代码进行 lint 时，先运行 Prettier，然后运行 ESLint：

```js
$ npm run prettier-fix
$ npm run lint-fix
```

您可以看到，这个解决方案以这种方式使我们的工作流程更清晰和更干净。不再有冲突-一切都很顺利。很好。

您可以在我们的 GitHub 存储库的`/chapter-14/eslint-plugin-vue/separate/`中找到一个分别运行 ESLint 和 Prettier 的示例。

干得好。您已经完成了本章的第一个重要部分。我们希望您将开始或已经开始为您的 Vue 和 Nuxt 应用程序编写美观且易读的代码，并利用这些令人惊叹的格式化程序和代码检查工具。随着本书中关于 Nuxt 的学习接近尾声，我们将在下一节中向您介绍如何部署 Nuxt 应用程序。所以请继续阅读。

# 部署 Nuxt 应用程序

除了代码检查和格式化之外，应用程序部署也是 Web 开发工作流的一部分。我们需要将应用程序部署到远程服务器或主机上，以便公众可以公开访问应用程序。Nuxt 带有内置命令，我们可以使用这些命令来部署我们的应用程序。它们如下：

+   `nuxt`

+   `nuxt build`

+   `nuxt start`

+   `nuxt generate`

`nuxt`命令是您现在在终端上熟悉使用的命令：

```js
$ npm run dev
```

如果您打开使用`create-nuxt-app`脚手架工具安装项目时 Nuxt 生成的`package.json`文件，您会看到这些命令预先配置在`"scripts"`片段中，如下所示：

```js
// package.json
"scripts": {
  "dev": "nuxt",
  "build": "nuxt build",
  "start": "nuxt start",
  "generate": "nuxt generate"
}
```

您可以使用以下 Node.js 命令行在终端上启动命令：

```js
$ npm run <command>
```

`nuxt`命令用于在开发服务器上进行开发，并具有热重新加载功能，而其他命令用于生产部署。让我们看看如何在下一节中使用它们来部署您的 Nuxt 应用。

您还可以在任何这些命令中使用常见参数，例如`--help`。如果您想了解更多信息，请访问[`nuxtjs.org/guide/commandslist-of-commands`](https://nuxtjs.org/guide/commands#list-of-commands)。

## 部署 Nuxt 通用服务器端渲染应用程序

希望通过学习之前的所有章节，您知道自己一直在开发 Nuxt 通用**服务器端渲染**（**SSR**）应用程序。SSR 应用程序是在服务器端呈现应用程序内容的应用程序。这种应用程序需要特定的服务器来运行您的应用程序，例如 Node.js 和 Apache 服务器，而像您使用 Nuxt 创建的通用 SSR 应用程序在服务器端和客户端上都可以运行。这种应用程序也需要特定的服务器。使用 Nuxt 通用 SSR 应用程序可以在终端上使用两个命令进行部署。让我们看看您可以在以下步骤中如何执行此操作：

1.  通过 npm 启动`nuxt build`命令来使用 webpack 构建应用程序并压缩 JavaScript 和 CSS：

```js
$ npm run build
```

您应该获得以下构建结果：

```js
> [your-app-name]@[your-app-name] start /var/path/to/your/app
> nuxt build
ℹ Production build
ℹ Bundling for server and client side
ℹ Target: server 
✓ Builder initialized
✓ Nuxt files generated
...
...
```

1.  通过 npm 启动`nuxt start`命令以生产模式启动服务器：

```js
$ npm run start
```

您应该获得以下启动状态：

```js
> [your-app-name]@[your-app-name] start /var/path/to/your/app
> nuxt start

Nuxt.js @ v2.14.0

> Environment: production
> Rendering: server-side
> Target: server

Memory usage: 28.8 MB (RSS: 88.6 MB)
```

部署 Nuxt 通用 SSR 应用程序只需要两条命令行。这很容易，不是吗？但是，如果您没有 Node.js 服务器来托管您的应用程序，或者出于任何原因，您只想将应用程序部署为静态站点，您可以从 Nuxt 通用 SSR 应用程序生成它。让我们在下一节中了解如何实现这一点。

## 部署 Nuxt 静态生成（预渲染）应用程序

要从 Nuxt 通用 SSR 应用程序生成 Nuxt 静态生成的应用程序，我们将使用我们在前几章中为此练习创建的示例网站。您可以在我们的 GitHub 存储库的`/chapter-14/deployment/sample-website/`中找到此示例。因此，让我们按照以下步骤开始：

1.  确保您的`package.json`文件中有以下`"generate"`运行脚本：

```js
"scripts": {
  "generate": "nuxt generate"
} 
```

1.  将 Nuxt 配置文件中的`target`项目更改为`static`：

```js
// nuxt.config.js
export default {
  target: 'static'
}
```

1.  通过在 Nuxt 配置文件中配置`generate`选项来生成 404 页面：

```js
// nuxt.config.js
export default {
  generate: {
    fallback: true
  }
}
```

Nuxt 不会生成您的自定义 404 页面，也不会生成默认页面。如果您想在静态应用程序中包含此页面，可以在配置文件中的`generate`选项中设置`fallback: true`。

1.  通过 npm 启动`nuxt generate`命令来构建应用程序并为每个路由生成 HTML 文件：

```js
$ npm run generate
```

Nuxt 具有一个爬虫，它会扫描链接并为您自动生成动态路由及其异步内容（使用`asyncData`和`fetch`方法呈现的数据）。因此，您应该按以下方式获取应用程序的每个路由：

```js
ℹ Generating output directory: dist/
ℹ Generating pages with full static mode
✓ Generated route "/contact"
✓ Generated route "/work-nested"
✓ Generated route "/about"
✓ Generated route "/work"
✓ Generated route "/"
✓ Generated route "/work-nested/work-sample-4"
✓ Generated route "/work-nested/work-sample-1"
✓ Generated route "/work-nested/work-sample-3"
✓ Generated route "/work-nested/work-sample-2"
✓ Generated route "/work/work-sample-1"
✓ Generated route "/work/work-sample-4"
✓ Generated route "/work/work-sample-2"
✓ Generated route "/work/work-sample-3"
✓ Client-side fallback created: 404.html
i Ready to run nuxt serve or deploy dist/ directory 
```

请注意，您仍然需要使用`generate.routes`来生成爬虫无法检测到的路由。

1.  如果您查看项目根目录，您应该会发现 Nuxt 生成的`/dist/`文件夹，其中包含部署应用程序到静态托管服务器所需的一切。但在此之前，您可以使用终端上的`nuxt serve`命令从`/dist/`目录测试生产静态应用程序：

```js
$ npm run start
```

您应该在终端上获得以下输出：

```js
Nuxt.js @ v2.14.0 

> Environment: production
> Rendering: server-side
> Target: static
Listening: http://localhost:3000/

ℹ Serving static application from dist/ 
```

1.  现在，您可以将浏览器指向`localhost:3000`，并查看应用程序是否像 SSR 一样运行，但实际上，它是一个静态生成的应用程序。

我们将在下一章回到这个配置，用于部署 Nuxt **单页面应用程序**（**SPA**）应用。您可以看到，选择这种部署方式只需要做一点工作，但完全值得，因为以“静态”方式部署您的应用程序有好处，比如您可以将静态文件托管在静态托管服务器上，这相对便宜于 Node.js 服务器。我们将在下一章向您展示如何在这种服务器上为您的静态站点提供服务，就像**GitHub Pages**一样。尽管以“静态”方式部署 Nuxt 通用 SSR 应用程序有好处，但您必须考虑以下注意事项：

+   给`asyncData`和`fetch`方法的 Nuxt 上下文将失去来自 Node.js 的 HTTP `req`和`res`对象。

+   `nuxtServerInit`操作将不可用于存储。

因此，如果您的 Nuxt 应用程序在上述列表中严重依赖这些项目，那么将 Nuxt 通用 SSR 应用程序生成为静态文件可能不是一个好主意，因为它们是服务器端功能。但是，我们可以在客户端使用客户端 cookie 模仿`nuxtServerInit`操作，我们也将在下一章向您展示。但现在，让我们继续前进到下一节，找出您可以选择的托管服务器类型来托管您的 Nuxt 应用程序。

如果您想了解有关`generate`属性/选项和其他选项的更多信息，例如您可以使用此属性进行配置的`fallback`和`routes`选项，请访问[`nuxtjs.org/api/configuration-generate`](https://nuxtjs.org/api/configuration-generate)。

## 在虚拟专用服务器上托管 Nuxt 通用 SSR 应用程序。

在托管 Node.js 应用程序时，**虚拟专用服务器**（**VPS**）和专用服务器是更好的选择，因为您将完全自由地为您的应用程序设置 Node.js 环境。每当 Node.js 发布新版本时，您也应该更新您的环境。只有使用 VPS 服务器，您才能随时升级和调整您的环境。

如果您正在寻找 Linux 服务器并且希望从头开始安装您需要的基础设施，VPS 提供商如 Linode 或 Vultr 提供了实惠的 VPS 主机定价。这些 VPS 提供商提供给您的是一个空的虚拟机，您可以选择您喜欢的 Linux 发行版，例如 Ubuntu。构建您所需基础设施的过程与在本地机器上刚刚安装 Linux 发行版时安装 Node.js、MongoDB、MySQL 等的过程是一样的。有关这些 VPS 提供商的更多信息，请访问以下链接：

+   [`welcome.linode.com/`](https://welcome.linode.com/) for Linode

+   [`www.vultr.com/`](https://www.vultr.com/) for Vultr

在满足您的要求的 Node.js 环境和基础设施设置好之后，您可以将 Nuxt 应用程序上传到这种类型的主机，然后通过这些主机提供的**安全外壳**（**SSH**）功能在终端上轻松构建和启动应用程序：

```js
$ npm run build
$ npm run start
```

共享主机服务器怎么样？让我们看看下一节中你可以选择的内容。

## 在共享主机服务器上托管 Nuxt 通用 SSR 应用程序

记住，并非所有主机都支持 Node.js，并且与支持 PHP 的共享主机服务器相比，支持 Node.js 的共享主机服务器相对较少。但所有共享主机服务器都是一样的-通常你所能做的事情受到严格限制，你必须遵循提供者制定的严格规则。您可以查看以下共享主机服务器提供商：

+   **Reclaim Hosting**，网址为[`reclaimhosting.com/shared-hosting/`](https://reclaimhosting.com/shared-hosting/)

+   **A2 Hosting**，网址为[`www.a2hosting.com/nodejs-hosting`](https://www.a2hosting.com/nodejs-hosting)

例如，在 Reclaim Hosting 的共享主机服务器上，您很可能无法运行 Nuxt 命令来启动您的应用程序。相反，您需要向服务器提供一个应用程序启动文件，这个文件必须被称为`app.js`并放在您的项目根目录中。

如果您想选择 Reclaim Hosting，您可以使用他们的测试环境[`stateu.org/`](https://stateu.org/)来看看它对您的工作方式。但请记住，高级设置是不可能的。好消息是，Nuxt 提供了一个 Node.js 模块`nuxt-start`，可以在这样的共享主机服务器上以生产模式启动 Nuxt 应用程序。所以让我们在以下步骤中找出如何做：

1.  通过 npm 在本地安装`nuxt-start`：

```js
$ npm i nuxt-start
```

1.  在你的项目根目录中创建一个`app.js`文件，并使用以下代码启动 Nuxt 应用程序：

```js
// app.js
const { Nuxt } = require('nuxt-start')
const config = require('./nuxt.config.js')

const nuxt = new Nuxt(config)
const { host, port } = nuxt.options.server

nuxt.listen(port, host)
```

或者，你可以使用 Express 或 Koa 来启动你的 Nuxt 应用。以下示例假设你正在使用 Express：

```js
// app.js
const express = require('express')
const { Nuxt } = require('nuxt')
const app = express()

let config = require('./nuxt.config.js')
const nuxt = new Nuxt(config)
const { host, port } = nuxt.options.server

app.use(nuxt.render)
app.listen(port, host)
```

在这段代码中，我们导入了`express`和`nuxt`模块以及`nuxt.config.js`文件，然后将 Nuxt 应用程序用作中间件。如果你使用 Koa，情况也是一样的 - 你只需要将 Nuxt 用作中间件。

1.  使用`app.js`文件将 Nuxt 应用程序上传到服务器，并按照主机的说明通过 npm 安装应用程序依赖项，然后运行`app.js`启动你的应用程序。

这就是你需要做的全部。这些共享主机服务器存在一些限制。在这些服务器中，你对 Node.js 环境的控制较少。但是，如果你遵循服务器提供商设定的严格规则，你可以让你的通用 SSR Nuxt 应用程序快速运行起来。

你可以在我们的 GitHub 存储库中的`/chapter-14/deployment/shared-hosting/reclaimhosting.com/`中找到上述示例代码和其他示例代码，用于在 Reclaim Hosting 上托管 Nuxt 通用 SSR 应用程序。

有关`nuxt-start`的更多信息，请访问[`www.npmjs.com/package/nuxt-start`](https://www.npmjs.com/package/nuxt-start)。

你可以看到它并不完美，并且有其局限性，但如果你正在寻找共享主机，这是合理的。如果这对你来说不理想，那么最后的选择是选择静态站点主机，我们将在下一节中看到。

## 在静态站点主机上托管 Nuxt 静态生成的应用程序

通过这种方式，你将失去 Nuxt 的服务器端。但好消息是，有许多流行的主机可以托管静态生成的 Nuxt 应用程序，并且你可以快速在几乎任何在线主机上提供服务。让我们在以下步骤中看看如何做到这一点：

1.  在 Nuxt 配置文件中将`server`更改为`static`作为目标。

```js
// nuxt.config.js
export default {
  target: 'static'
}
```

1.  通过 npm 在本地启动`nuxt generate`命令来生成 Nuxt 应用程序的静态文件：

```js
$ npm run generate
```

1.  将 Nuxt 生成的`/dist/`文件夹中的所有内容上传到主机。

以下列表详细介绍了你可以选择的主机。所有这些主机的部署过程都在 Nuxt 网站上有详细说明。你应该查看 Nuxt FAQ [`nuxtjs.org/faq`](https://nuxtjs.org/faq) 来查看部署示例，并了解如何将静态生成的 Nuxt 应用程序部署到这些特定主机中的任何一个：

+   AWS w/ S3 (Amazon Web Services) at [`nuxtjs.org/faq/deployment-aws-s3-cloudfront`](https://nuxtjs.org/faq/deployment-aws-s3-cloudfront)

+   GitHub Pages at [`nuxtjs.org/faq/github-pages`](https://nuxtjs.org/faq/github-pages)

+   Netlify at [`nuxtjs.org/faq/netlify-deployment`](https://nuxtjs.org/faq/netlify-deployment)

+   Surge at [`nuxtjs.org/faq/surge-deployment`](https://nuxtjs.org/faq/surge-deployment)

在下一章中，我们将指导您在 GitHub Pages 上部署 Nuxt SPA 应用程序。但现在，这是本章关于格式化、检查和部署 Nuxt 通用 SSR 应用程序的结束。让我们总结一下您在本章中学到的内容。

# 摘要

干得好。你已经走了这么远。这是一段相当漫长的旅程。在本章中，我们涵盖了 JavaScript 的检查器和格式化程序，特别是 ESLint，Prettier 和 StandardJS 用于 Nuxt 应用程序以及一般的 JavaScript 应用程序。您已经学会了如何安装和配置它们以满足您的需求和偏好。我们还介绍了部署 Nuxt 应用程序的 Nuxt 命令以及可用于托管 Nuxt 应用程序的选项，无论是通用 SSR 应用程序还是静态生成的站点。

在接下来的章节中，我们将学习如何使用 Nuxt 创建 SPA，并将其部署到 GitHub Pages。您将看到传统 SPA 和 Nuxt 中 SPA（让我们称之为**Nuxt SPA**）之间的细微差别。我们将指导您完成在 Nuxt 中设置 SPA 开发环境的过程，重构您在前几章中创建的通用 SSR Nuxt 身份验证应用程序，并将其转换为 Nuxt SPA 和静态生成的 Nuxt SPA。最后，您将学会将静态生成的 SPA 部署到 GitHub Pages。所以请继续阅读。


# 第六部分：更进一步的领域

在本节中，我们将学习如何在 Nuxt 中做更多事情。我们将学习如何在 Nuxt 中开发单页面应用（SPA），使用 PHP 而不是 JavaScript 来创建跨域和外部 API 数据平台来供养我们的 Nuxt 应用，开发实时应用程序，并在 Nuxt 中使用（无头）CMS 和 GraphQL。

本节包括以下章节：

+   第十五章，使用 Nuxt 创建 SPA

+   第十六章，为 Nuxt 创建一个与框架无关的 PHP API

+   第十七章，使用 Nuxt 创建实时应用

+   第十八章，使用 CMS 和 GraphQL 创建 Nuxt 应用


使用 Nuxt 创建 SPA

在之前的章节中，我们创建了各种 Nuxt 应用程序，以`universal`模式。这些是通用服务器端渲染（SSR）应用程序。这意味着它们是在服务器端和客户端上运行的应用程序。Nuxt 为我们提供了另一种开发**单页面应用程序**（**SPA**）的选项，就像我们可以使用 Vue 和其他 SPA 框架（如 Angular 和 React）一样。在本章中，我们将指导您如何在 Nuxt 中开发、构建和部署 SPA，并了解它与现有的传统 SPA 有何不同。

在这一章中，我们将涵盖以下主题：

+   理解经典 SPA 和 Nuxt SPA

+   安装 Nuxt SPA

+   开发 Nuxt SPA

+   部署 Nuxt SPA

让我们开始吧！

# 第十五章：理解经典 SPA 和 Nuxt SPA

SPA，也称为经典 SPA，是一种应用程序，它在浏览器上加载一次，不需要我们在应用程序的整个生命周期内重新加载和重新渲染页面。这与多页面应用程序（MPA）不同，在多页面应用程序中，每次更改和与服务器的每次数据交换都需要我们重新从服务器到浏览器重新渲染整个页面。

在经典/传统的 SPA 中，提供给客户端的 HTML 相对为空。一旦到达客户端，JavaScript 将动态渲染 HTML 和内容。React、Angular 和 Vue 是创建经典 SPA 的流行选择。然而，不要与 spa 模式的 Nuxt 应用程序混淆（让我们称之为**Nuxt SPA**），尽管 Nuxt 为您提供了使用一行配置开发“SPA”的选项，如下所示：

```js
// nuxt.config.js
export default {
  mode: 'spa'
}
```

Nuxt 的 SPA 模式简单地意味着您失去了 Nuxt 和 Node.js 的服务器端特性，就像我们在第十四章中学到的，在将通用 SSR Nuxt 应用程序转换为静态生成（预渲染）Nuxt 应用程序时，使用了代码检查器、格式化程序和部署命令。对于 spa 模式的 Nuxt 应用程序也是一样-当您使用上述配置时，您的 spa 模式 Nuxt 应用程序将成为纯粹的**客户端应用程序**。

但是，spa 模式 Nuxt 应用程序与您从 Vue CLI、React 或 Angular 创建的经典 SPA 有很大不同。这是因为构建应用程序后，您（经典）SPA 的页面和路由将在运行时由 JavaScript 动态呈现。另一方面，spa 模式 Nuxt 应用程序中的页面将在构建时进行预渲染，并且每个页面中的 HTML 与经典 SPA 一样“空”。这就是事情开始变得混乱的地方。让我们看看以下示例。假设您的 Vue 应用程序中有以下页面和路由：

```js
src
├── favicon.ico
├── index.html
├── components
│ ├── about.vue
│ ├── secured.vue
│ └── ...
└── routes
  ├── about.js
  ├── secured.js
  └── ...
```

您的应用程序将构建到以下分发中：

```js
dist
├── favicon.ico
├── index.html
├── css
│ └── ...
└── js
  └── ...
```

在这里，您可以看到只有`index.html`、`/css/`和`/js/`文件夹构建到`/dust/`文件夹中。这意味着您的应用程序的页面和路由将在运行时由 JavaScript 动态呈现。然而，假设您的 spa 模式 Nuxt 应用程序中有以下页面：

```js
pages
├── about.vue
├── secured.vue
├── ...
└── users
  ├── about.js
  ├── index.vu
  └── _id.vue
```

您的应用程序将构建到以下分发中：

```js
dist
├── index.html
├── favicon.ico
├── about
│ └── index.html
├── secured
│ └── index.html
├── users
│ └── index.html
└── ...
```

正如您所看到的，您应用程序的每个页面和路由都是使用`index.html`文件构建并放置在`/dust/`文件夹中 - 就像您为通用 SSR Nuxt 应用程序生成的静态站点一样。因此，在这里，我们可以说您将构建和部署的 spa 模式 Nuxt 应用程序是一个“静态”SPA，而不是经典的“动态”SPA。当然，您仍然可以使用以下部署命令将您的 spa 模式 Nuxt 应用程序部署为通用 SSR Nuxt 应用程序。这将使其在运行时变得“动态”：

```js
$ npm run build
$ npm run start
```

但是在 Node.js 主机上部署 Nuxt SPA 应用可能会过度，因为您选择 spa 模式 Nuxt 应用程序并且不想为您的 SPA 使用 Node.js 主机，必须有一些充分的理由。因此，将 Nuxt SPA**预渲染**为静态生成的应用程序（让我们称之为**静态生成的 Nuxt SPA**）可能更合理。您可以像通用 SSR Nuxt 应用程序一样轻松地使用`nuxt export`命令预渲染您的 Nuxt SPA。

这就是本章的全部内容：在 spa 模式下开发 Nuxt 应用程序，并在部署到静态托管服务器（如 GitHub Pages）之前生成所需的静态 HTML 文件。因此，让我们开始安装和设置环境。

# 安装 Nuxt SPA

安装 Nuxt SPA 与使用`create-nuxt-app`脚手架工具安装 Nuxt 通用 SSR 相同。让我们开始吧：

1.  通过终端使用 Nuxt 脚手架工具安装 Nuxt 项目：

```js
$ npx create-nuxt-app <project-name>
```

1.  回答出现的问题，并在要求**渲染模式**时选择**单页面应用**选项：

```js
? Project name
? Project description
//...
? Rendering mode:  
  Universal (SSR / SSG)  
> Single Page App 
```

安装完成后，如果您检查项目根目录中的 Nuxt 配置文件，您应该会看到在安装过程中已经为您配置了`mode`选项为 SPA：

```js
// nuxt.config.js
export default {
  mode: 'spa'
}
```

1.  在您的终端中启动 Nuxt 开发模式：

```js
$ npm run dev
```

您应该看到您的终端上**只有**客户端端的代码被编译：

```js
✓ Client
  Compiled successfully in 1.76s
```

您将不再看到在服务器端编译的代码，这是您通常在`universal`模式下看到的 Nuxt 应用程序的代码：

```js
✓ Client
  Compiled successfully in 2.75s

✓ Server
  Compiled successfully in 2.56s
```

如您所见，在 Nuxt 中很容易启动 spa 模式环境。您也可以通过在 Nuxt 配置文件中的`mode`选项中添加`spa`值来**手动**设置 spa 模式。现在，让我们开发一个 Nuxt SPA。

# 开发 Nuxt SPA

在开发 Nuxt SPA 时需要牢记的一个重要事项是，给予`asyncData`和`fetch`方法的 Nuxt 上下文将失去它们的`req`和`res`对象，因为这些对象是 Node.js HTTP 对象。在本节中，我们将创建一个简单的用户登录身份验证，您应该已经熟悉。但是，这一次，我们将在 Nuxt SPA 中进行。我们还将创建一个用于使用动态路由列出用户的页面，就像我们在第四章中学到的那样，*添加视图、路由和过渡*。让我们开始吧：

1.  准备以下`.vue`文件，或者只需从上一章中复制，如下所示：

```js
-| pages/
---| index.vue
---| about.vue
---| login.vue
---| secret.vue
---| users/
-----| index.vue
-----| _id.vue
```

1.  准备具有存储状态、突变、动作和处理用户登录身份验证的索引文件的 Vuex 存储，如下所示：

```js
-| store/
---| index.js
---| state.js
---| mutations.js
---| actions.js
```

在前一章中提到，当我们**静态**生成 Nuxt 通用 SSR 应用程序时，存储中的`nuxtServerInit`动作将会丢失，因此在 Nuxt SPA 中也是一样的-我们在客户端不会有这个服务器动作。因此，我们需要一个客户端`nuxtServerInit`动作来模拟服务器端的`nuxtServerInit`动作。我们接下来将学习如何做到这一点。

## 创建客户端 nuxtServerInit 动作

这些文件中的方法和属性与我们在过去的练习中所拥有的方法和属性相同，除了`nuxtServerInit`动作：

```js
// store/index.js
const cookie = process.server ? require('cookie') : undefined

export const actions = {
  nuxtServerInit ({ commit }, { req }) {
    if (
      req 
      && req.headers 
      && req.headers.cookie 
      && req.headers.cookie.indexOf('auth') > -1
    ) {
      let auth = cookie.parse(req.headers.cookie)['auth']
      commit('setAuth', JSON.parse(auth))
    }
  }
}
```

在 Nuxt SPA 中，没有涉及服务器，因为`nuxtServerInit`只能由 Nuxt 从服务器端调用。因此，我们需要一个解决方案。我们可以使用 Node.js 的`js-cookie`模块在用户登录时在客户端存储经过身份验证的数据，这使其成为替代服务器端 cookie 的最佳选择。让我们学习如何实现这一点：

1.  通过 npm 安装 Node.js 的`js-cookie`模块：

```js
$ npm i js-cookie
```

1.  在存储操作中创建一个名为`nuxtClientInit`（如果愿意，也可以选择其他名称）的自定义方法，以从 cookie 中检索用户数据。然后，在用户刷新浏览器时将其设置回所需的状态。

```js
// store/index.js
import cookies from 'js-cookie'

export const actions = {
  nuxtClientInit ({ commit }, ctx) {
    let auth = cookies.get('auth')
    if (auth) {
      commit('setAuth', JSON.parse(auth))
    }
  }
}
```

正如您可能记得的那样，在刷新页面时，商店的`nuxtServerInit`动作总是在服务器端调用。`nuxtClientInit`方法也是如此；每次在客户端刷新页面时都应该被调用。然而，它不会被**自动**调用，因此我们可以使用插件在 Vue 根实例初始化之前每次调用它。

1.  在`/plugins/`目录中创建一个名为`nuxt-client-init.js`的插件，该插件将通过存储中的`dispatch`方法调用`nuxtClientInit`方法：

```js
// plugins/nuxt-client-init.js
export default async (ctx) => {
  await ctx.store.dispatch('nuxtClientInit', ctx)
}
```

请记住，在 Vue 根实例初始化之前，我们可以在插件中访问 Nuxt 上下文。存储被添加到 Nuxt 上下文中，因此我们可以访问存储操作，而这里我们感兴趣的是`nuxtClientInit`方法。

1.  现在，将此插件添加到 Nuxt 配置文件中以安装该插件：

```js
// nuxt.config.js
export default {
  plugins: [
    { src: '~/plugins/nuxt-client-init.js', mode: 'client' }
  ]
}
```

现在，每次刷新浏览器时，`nuxtClientInit`方法都将被调用，并且在 Vue 根实例初始化之前，状态将被此方法重新填充。正如您所看到的，当我们失去 Nuxt 作为通用 JavaScript 应用程序的全部功能时，模仿`nuxtClientInit`动作并不是一件简单的事情。但是，如果您必须选择 Nuxt SPA，那么我们刚刚创建的`nuxtClientInit`方法可以解决这个问题。

接下来，我们将使用 Nuxt 插件创建一些自定义的 Axios 实例。这应该是您已经非常熟悉的内容。然而，能够创建自定义的 Axios 实例是有用的，因为当需要时，您总是可以回退到**原始**版本的 Axios，即使我们也有**Nuxt Axios 模块**。所以，让我们继续！

## 使用插件创建多个自定义的 Axios 实例

在这个 spa 模式的练习中，我们将需要两个 Axios 实例来对以下地址进行 API 调用：

+   `localhost:4000`用于用户认证

+   `jsonplaceholder.typicode.com`用于获取用户

我们将使用原始的 Axios ([`github.com/axios/axios`](https://github.com/axios/axios))，因为它给了我们灵活性来创建带有一些自定义配置的多个 Axios 实例。让我们开始吧：

1.  通过 npm 安装原始的`axios`：

```js
$ npm i axios
```

1.  在需要的页面上创建一个`axios`实例：

```js
// pages/users/index.vue
const instance = axios.create({
  baseURL: '<api-address>',
  timeout: <value>,
  headers: { '<x-custom-header>': '<value>' }
})
```

但直接在页面上创建`axios`实例并不理想。理想情况下，我们应该能够提取这个实例并在任何地方重用它。通过 Nuxt 插件，我们可以创建提取的 Axios 实例。我们可以遵循两种方法来创建它们。我们将在下一节中看一下第一种方法。

### 在 Nuxt 配置文件中安装自定义的 Axios 插件

在之前的章节中，你学会了我们可以使用`inject`方法创建一个插件，并通过 Nuxt 的`config`文件安装插件。除了使用`inject`方法，值得知道的是我们也可以**直接**将插件注入到 Nuxt 上下文中。让我们看看如何做到这一点：

1.  在`/plugins/`目录下创建一个`axios-typicode.js`文件，导入原始的`axios`，并创建实例，如下所示：

```js
// plugins/axios-typicode.js
import axios from 'axios'

const instance = axios.create({
  baseURL: 'https://jsonplaceholder.typicode.com'
})

export default (ctx, inject) => {
  ctx.$axiosTypicode = instance
  inject('axiosTypicode', instance)
}
```

如你所见，在创建了`axios`实例之后，我们通过 Nuxt 上下文(`ctx`)注入了插件，使用了`inject`方法，然后导出它。

1.  在 Nuxt 配置文件中安装这个插件：

```js
// nuxt.config.js
export default {
  plugins: [
    { src: '~/plugins/axios-typicode.js', mode: 'client' }
  ]
}
```

你必须将`mode`选项设置为`client`，因为我们**只**需要它在客户端。

1.  你可以在任何你喜欢的地方访问这个插件。在这个例子中，我们想在用户索引页面上使用这个插件来获取用户列表：

```js
// pages/users/index.vue
export default {
  async asyncData({ $axiosTypicode }) {
    let { data } = await $axiosTypicode.get('/users')
    return { users: data }
  }
}
```

在这个插件中，我们将自定义的`axios`实例直接注入到 Nuxt 上下文(`ctx`)中，命名为`$axiosTypicode`，这样我们可以使用 JavaScript 解构赋值语法直接调用它作为`$axiosTypicode`。我们还使用`inject`方法注入了插件，所以我们也可以通过`ctx.app`来调用这个插件，如下所示：

```js
// pages/users/index.vue
export default {
  async asyncData({ app }) {
    let { data } = await app.$axiosTypicode.get('/users')
    return { users: data }
  }
}
```

创建自定义的 Axios 插件并不太难，是吗？如果你通过 Nuxt 配置文件安装插件，这意味着它是一个全局的 JavaScript 函数，你可以从任何地方访问它。但如果你不想将它安装为全局插件，你可以跳过在 Nuxt 配置文件中安装它。这就引出了创建 Nuxt 插件的第二种方法。

### 手动导入自定义的 Axios 插件

创建自定义 Axios 实例的另一种方法根本不涉及 Nuxt 配置。我们可以将自定义实例导出为常规的 JavaScript 函数，然后直接在需要它的页面中导入。让我们看看如何做到这一点：

1.  在`/plugins/`目录中创建一个`axios-api.js`文件，导入原始的`axios`，并创建实例，如下所示：

```js
// plugins/axios-api.js
import axios from 'axios'

export default axios.create({
  baseURL: 'http://localhost:4000',
  withCredentials: true
})
```

如您所见，我们不再使用`inject`方法；相反，我们直接导出实例。

1.  现在，我们可以在需要时手动导入它。在这个例子中，我们需要在`login`动作方法中使用它，如下所示：

```js
// store/actions.js
import axios from '~/plugins/axios-api'

async login({ commit }, { username, password }) {
  const { data } = await axios.post('/public/users/login', { 
   username, password })
  //...
}
```

如您所见，我们必须**手动**导入此插件，因为它没有插入到 Nuxt 生命周期中。

1.  导入它并在`token`中间件中设置`Authorization`头部，如下所示：

```js
// middleware/token.js
import axios from '~/plugins/axios-api'

export default async ({ store, error }) => {
  //...
  axios.defaults.headers.common['Authorization'] = Bearer: 
  ${store.state.auth.token}
}
```

尽管在遵循这种方法时我们必须手动导入插件，但至少我们已经将以下设置提取到了一个可以在需要时重用的插件中：

```js
{
  baseURL: 'http://localhost:4000',
  withCredentials: true
}
```

您可以在本书的 GitHub 存储库的`/chapter-15/frontend/`中找到 Nuxt SPA 的代码以及这两种方法。

一旦您创建、测试和 lint 所有代码和文件，您就可以准备部署 Nuxt SPA 了。所以，让我们开始吧！

# 部署 Nuxt SPA

如果我们有一个 Node.js 运行时服务器，我们可以像部署通用 SSR Nuxt 应用程序一样部署 Nuxt SPA。如果没有，那么我们只能将 SPA 部署为静态站点到静态托管服务器，比如 GitHub Pages。您可以按照以下步骤部署静态生成的 Nuxt SPA：

1.  确保在 Nuxt 配置文件的`mode`选项中将值设置为`spa`：

```js
// nuxt.config.js
export default {
  mode: 'spa'
}
```

1.  确保`package.json`文件中有以下运行脚本：

```js
{
  "scripts": {
    "generate": "nuxt generate"
  }
}
```

1.  运行`npm run generate`，就像您为通用 SSR Nuxt 应用程序一样。您应该在终端中看到以下输出：

```js
ℹ Generating output directory: dist/
ℹ Generating pages 
✓ Generated /about
✓ Generated /login
✓ Generated /secret
✓ Generated /users
✓ Generated /
```

在上述输出中，如果您导航到项目内的`/dist/`文件夹，您将在根目录找到一个`index.html`文件，以及在每个子文件夹中找到带有路由名称的`index.html`文件。但是，您将在生成的动态路由中找不到任何页面，比如`/users/1`。这是因为与通用模式相反，在 spa 模式下不会生成动态路由。

此外，如果您在`/dist/`文件夹中打开`index.html`文件，您会发现所有的`index.html`文件都是完全相同的-只是一些“空”的 HTML 元素，类似于经典的 SPA。此外，每个`index.html`文件都不包含自己的元信息，只包含来自`nuxt.config.js`的公共元信息。这些页面的元信息将在运行时进行填充和更新。由于这个原因，对于“静态”SPA 来说，这可能看起来有些违反直觉和“半成品”。除此之外，没有生成静态有效负载。这意味着，如果您在浏览器中导航到`localhost:3000/users`，您会注意到该页面仍然从[`jsonplaceholder.typicode.com/users`](https://jsonplaceholder.typicode.com/users)请求其数据，而不是像通用 SSR Nuxt 应用程序那样从有效负载中获取数据。这是因为 Nuxt 在 spa 模式下不生成静态内容，即使您已经在 Nuxt 配置文件中为目标属性设置了`static`。为了解决这些问题，我们可以从通用模式生成我们需要的静态内容。

1.  在 Nuxt 配置文件中将`mode`选项的`spa`更改为`universal`：

```js
// nuxt.config.js
export default {
  mode: 'universal'
}
```

1.  运行`npm run generate`，这样 Nuxt 将对 API 进行 REST API 调用，以检索用户并将其内容导出到本地静态有效负载。您将看到以下输出：

```js
ℹ Generating output directory: dist/
ℹ Generating pages with full static mode 
✓ Generated /about
✓ Generated /secret
✓ Generated /login
✓ Generated /users
✓ Generated /users/1
✓ Generated /users/2
...
...
✓ Generated /users/10
✓ Generated /
```

请注意，前面的输出中没有生成动态路由。如果您再次导航到`/dist/`文件夹，您会看到`/users/`文件夹现在包含多个文件夹，每个文件夹都有自己的用户 ID。每个文件夹都包含一个包含该特定用户内容的`index.html`文件。现在，每个`index.html`文件都包含自己的独立元信息和在`/dist/_nuxt/static/`中生成的有效负载。

1.  在 Nuxt 配置文件中将`mode`选项的`universal`改回`spa`：

```js
// nuxt.config.js
export default {
  mode: 'spa'
}
```

1.  现在，在终端上运行`npm run build`。您应该会看到以下输出：

```js
Hash: c36ee9714ee9427ac1ff 
Version: webpack 4.43.0 
Time: 5540ms 
Built at: 11/07/2020 07:58:09 
                         Asset       Size  Chunks                         Chunk Names 
../server/client.manifest.json   9.31 KiB          [emitted]               
                      LICENSES  617 bytes          [emitted]               
                app.922dbd1.js     57 KiB       0  [emitted] 
                [immutable] app 
        commons/app.7236c86.js    182 KiB       1  [emitted] 
        [immutable] commons/app 
        pages/about.75fcd06.js  667 bytes       2  [emitted] 
        [immutable] pages/about 
        pages/index.76b5c20.js  784 bytes       3  [emitted] 
        [immutable] pages/index 
        pages/login.09e509e.js   3.14 KiB       4  [emitted]
        [immutable] pages/login 
      pages/secured.f086299.js   1.36 KiB       5  [emitted] 
       [immutable] pages/secured 
    pages/users/_id.e1c568c.js   1.69 KiB       6  [emitted] 
      [immutable] pages/users/_id 
  pages/users/index.b3e7aa8.js    1.5 KiB       7  [emitted]
    [immutable] pages/users/index 
            runtime.266b4bf.js   2.47 KiB       8  [emitted] 
            [immutable] runtime 
+ 1 hidden asset 
Entrypoint app = runtime.266b4bf.js commons/app.7236c86.js app.922dbd1.js 
ℹ Ready to run nuxt generate 
```

1.  忽略“准备运行 nuxt generate”消息。相反，首先使用终端上的`nuxt start`命令从`/dist/`目录中测试您的生产静态 SPA：

```js
$ npm run start
```

您应该会得到以下输出：

```js
Nuxt.js @ v2.14.0

> Environment: production
> Rendering: client-side
> Target: static
Listening: http://localhost:3000/

ℹ Serving static application from dist/ 
```

现在，诸如`localhost:3000/users`之类的路由将不再从[`jsonplaceholder.typicode.com`](https://jsonplaceholder.typicode.com)请求其数据。相反，它们将从`/dist/`文件夹中的有效负载中获取数据，该文件夹位于`/static/`文件夹内。

1.  最后，只需将`/dist/`目录部署到您的静态托管服务器。

如果您正在寻找免费的静态托管服务器，请考虑使用 GitHub Pages。使用此功能，您可以为您的站点获得以下格式的域名：

```js
<username>.github.io/<app-name>
```

GitHub 还允许您使用自定义域名而不是使用他们的域名来提供站点。有关更多信息，请参阅 GitHub 帮助网站的指南：[`help.github.com/en/github/working-with-github-pages/configuring-a-custom-domain-for-your-github-pages-site`](https://help.github.com/en/github/working-with-github-pages/configuring-a-custom-domain-for-your-github-pages-site)。但是，在本书中，我们将向您展示如何在 GitHub 的`github.io`域名上提供站点。我们将在下一节中学习如何做到这一点。

您可以在本书的 GitHub 存储库中的`/chapter-15/frontend/`中找到此部分的代码。

## 部署到 GitHub Pages

GitHub Pages 是 GitHub 提供的静态站点托管服务，用于托管和发布 GitHub 存储库中的静态文件（仅限 HTML、CSS 和 JavaScript）。只要您在 GitHub 上拥有用户帐户并为您的站点创建了 GitHub 存储库，就可以在 GitHub Pages 上托管您的静态站点。

请访问[`guides.github.com/features/pages/`](https://guides.github.com/features/pages/)，了解如何开始使用 GitHub Pages。

您只需要转到 GitHub 存储库的**设置**部分，然后向下滚动到**GitHub Pages**部分。然后，您需要单击**选择主题**按钮，以开始创建静态站点的过程。

将 Nuxt SPA 的静态版本部署到 GitHub Pages 非常简单-您只需要对 Nuxt 配置文件进行一些微小的配置更改，然后使用`git push`命令将其上传到 GitHub 存储库。当您创建 GitHub 存储库并创建 GitHub Pages 时，默认情况下，静态页面的 URL 将以以下格式提供：

```js
<username>.github.io/<repository-name>
```

因此，您需要将此`<repository-name>`添加到 Nuxt 配置文件中`router`基本选项，如下所示：

```js
export default {
  router: {
    base: '/<repository-name>/'
  }
}
```

但是更改基本名称将干扰 Nuxt 应用程序的开发时的`localhost:3000`。让我们学习如何解决这个问题：

1.  在 Nuxt 配置文件中为开发和生产 GitHub Pages 创建一个`if`条件，如下所示：

```js
// nuxt.config.js
const routerBase = process.env.DEPLOY_ENV === 'GH_PAGES' ? {
  router: {
    base: '/<repository-name>/'
  }
} : {}
```

如果在进程环境中`DEPLOY_ENV`选项具有`GH_PAGES`，则此条件只是将`/<repository-name>/`添加到`router`选项的`base`键。

1.  使用`spread`操作符在配置文件中的 Nuxt 配置中添加`routerBase`常量：

```js
// nuxt.config.js
export default {
  ...routerBase
}
```

1.  在`package.json`文件中设置`DEPLOY_ENV='GH_PAGES'`脚本：

```js
// package.json
"scripts": {
  "build:gh-pages": "DEPLOY_ENV=GH_PAGES nuxt build",   
  "generate:gh-pages": "DEPLOY_ENV=GH_PAGES nuxt generate"
}
```

使用这两个 npm 脚本中的一个，`/<repository-name>/`的值不会被注入到你的 Nuxt 配置中，并且在运行`npm run dev`进行开发时不会干扰开发过程。

1.  在 Nuxt 配置文件中，将`mode`选项更改为`universal`，就像在上一节的*步骤 4*中一样，使用`nuxt generate`命令生成静态负载和页面：

```js
$ npm run generate:gh-pages
```

1.  将 Nuxt 配置文件中的`mode`选项从`universal`改回`spa`，就像在上一节的*步骤 6*中一样，使用`nuxt build`命令构建 SPA：

```js
$ npm run build:gh-pages
```

1.  通过你的 GitHub 仓库将 Nuxt 生成的`/dist/`文件夹中的文件推送到 GitHub Pages。

部署 Nuxt SPA 到 GitHub Pages 就是这样。但是，在将静态站点推送到 GitHub Pages 时，请确保在`/dist/`文件夹中包含一个`empty .nojekyll`文件。

Jekyll 是一个简单的、博客感知的静态站点生成器。它将纯文本转换为静态网站和博客。GitHub Pages 在幕后由 Jekyll 提供支持，默认情况下不会构建任何以点“.”、下划线“_”开头或以波浪符“~”结尾的文件或目录。这在为 GitHub Pages 提供静态站点时会成为问题，因为在构建 Nuxt SPA 时，`/_nuxt/`文件夹也会在`/dist/`文件夹内生成；Jekyll 会忽略这个`/_nuxt/`文件夹。为了解决这个问题，我们需要在`/dist/`文件夹中包含一个空的`.nojekyll`文件来关闭 Jekyll。当我们为 Nuxt SPA 构建静态页面时，会生成这个文件，所以确保将它推送到你的 GitHub 仓库中。

干得好 - 你已经完成了本书的另一短章节！如果你想在 Nuxt 中构建 SPA 而不是使用 Vue 或其他框架（如 Angular 和 React），Nuxt SPA 是一个很好的选择。但是，如果你提供需要立即或实时发布的社交媒体等网络服务，静态生成的 Nuxt SPA 可能不是一个好选择。这完全取决于你的业务性质，以及你是想要充分利用 Nuxt 的全能 SSR，还是只想使用 Nuxt 的客户端版本 - Nuxt SPA。接下来，我们将总结本章学到的内容。

# 总结

在本章中，我们学习了如何在 Nuxt 中开发、构建和部署 SPA，并了解了它与经典 SPA 的区别。我们还了解到，Nuxt SPA 可以是开发应用程序的一个很好选择，但是开发 Nuxt SPA 意味着我们将失去`nuxtServerInit`动作和`req`和`res` HTTP 对象。然而，我们可以使用客户端的`js-cookies`（或`localStorage`）和 Nuxt 插件来模拟`nuxtServerInit`动作。最后但并非最不重要的是，我们学习了如何在 GitHub Pages 上发布和提供静态生成的 Nuxt SPA。

到目前为止，在本书中，我们一直在为所有 Nuxt 应用程序和 API 使用 JavaScript。然而，在接下来的章节中，我们将探讨如何进一步使用 Nuxt，以便我们可以使用另一种语言**PHP**。我们将带领您了解 HTTP 消息和 PHP 标准，使用 PHP 数据库框架编写 CRUD 操作，并为 Nuxt 应用程序提供 PHP API。敬请期待！
