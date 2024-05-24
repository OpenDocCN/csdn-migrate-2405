# 现代 JavaScript Web 开发秘籍（五）

> 原文：[`zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6`](https://zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：调试您的应用程序

我们将在这里看到的食谱是：

+   以风格记录

+   使用 React 开发者工具进行调试

+   使用独立工具进行调试

+   使用 redux-logger 记录 Redux

+   使用 Redux 开发者工具调试 Redux

+   连接路由进行调试

# 介绍

在之前的章节中，我们看到了如何开发基本的`React`应用程序，如何增强它以获得更好的用户体验，以及如何扩展它，使其更适用于复杂和大型应用程序范围。然而，所有这些开发肯定需要测试和调试，因此在本章中，我们将涉及调试食谱，在接下来的章节中，我们将涵盖测试。

# 以风格记录

记录仍然是一个非常好的工具，但您不能仅依赖于使用`console.log（）`或`console.error（）`等工具。即使它们可以在短暂的调试运行中完成工作，但如果您计划更严肃地包括日志记录并希望在生产中禁用它，您将不得不追踪每个日志调用，或者*猴子补丁*控制台对象，以便`.log（）`或`.error（）`不起作用，这甚至更糟！

回到第五章的*使用 Winston 添加日志记录*部分，*测试和调试您的服务器*，我们使用`Winston`进行日志记录（还使用了`Morgan`，但那是特定于 HTTP 日志记录，所以不算），该库具有启用我们轻松启动或停止日志记录的功能。没有适用于浏览器的`Winston`版本，但我们可以退回到`debug`，这是一个旧标准（我们在刚才提到的章节末尾的*还有更多...*部分中提到的），它也可以在网络上使用。

您可以在[`github.com/visionmedia/debug`](https://github.com/visionmedia/debug)找到调试的完整文档。请注意，如果愿意，您也可以在`Node`中使用它，尽管我们认为我们之前的选择更好。

# 准备就绪

您可以像在`Node`中使用它一样安装`debug`。

```js
npm install debug --save
```

您还必须决定如何*命名空间*您的日志，因为使用调试可以轻松选择显示哪些消息（如果有的话）和哪些不显示。一些可能的想法是为应用程序中的每个服务使用名称，例如`MYAPP：SERVICE：LOGIN`，`MYAPP：SERVICE：COUNTRIES`，`MYAPP_SERVICE：PDF_INVOICE`等，或者为每个表单使用名称，例如`MYAPP_FORM：NEW_USER`，`MYAPP：FORM：DISPLAY_CART`，`MYAPP：FORM：PAY_WITH_CARD`等，或者为特定组件使用名称，例如`MYAPP：COMPONENT：PERSONAL_DATA`，`MYAPP：COMPONENT_CART`等；您可以根据需要为操作，减速器等列出清单。

有一种方法可以在之后选择显示哪些日志，方法是在`LocalStorage`中存储一个值（我们将在此处介绍），这样您就可以设置：

+   `MYAPP：*`显示来自我的应用程序的所有日志

+   `MYAPP：SERVICE：*`显示所有与服务相关的日志

+   `MYAPP：FORM：`和`MYAPP：COMPONENT：*`显示与某些表单或组件相关的日志，但省略其他日志

+   `MYAPP：SERVICE：COUNTRIES`，`MYAPP：FORM：NEW_USER`和`MYAPP：FORM：PAY_WITH_CARD`来显示与这三个项目相关的日志

您还可以使用`"-"`前缀字符串来排除它。 `MYAPP：ACTIONS：*，-MYAPP：ACTIONS：LOADING`将启用所有操作，但不包括`LOADING`。

您可能会想：为什么在每个地方都包含固定文本`MYAPP：`？关键在于，您可能使用的许多库实际上也使用调试进行日志记录。如果您要说显示所有内容（`*`）而不是`MYAPP：*`，则会在控制台中获得所有这些库的每条消息，这不是您预期的！

您可以自由决定日志的命名，但建立一个结构良好的列表将使您能够稍后选择要显示的日志，这意味着您不必开始乱弄代码以启用或禁用任何给定的消息集。

# 如何做到这一点...

让我们至少在某种程度上复制我们在`Winston`中所拥有的内容，这样如果您进行全栈工作，无论是客户端还是服务器端，都会更容易。我们希望有一个带有`.warn()`和`.info()`等方法的记录器对象，它将以适当的颜色显示给定的消息。此外，我们不希望在生产中显示日志。这将导致我们的代码如下：

```js
// Source file: src/logging/index.js

/* @flow */

import debug from "debug";

constWHAT_TO_LOG = "myapp:SERVICE:*"; // change this to suit your needs
const MIN_LEVEL_TO_LOG = "info"; // error, warn, info, verbose, or debug

const log = {
 error() {},
    warn() {},
    info() {},
    verbose() {},
    debug() {}
};

const logMessage = (
    color: string,
    topic: string,
    message: any = "--",
    ...rest: any
) => {
    const logger = debug(topic);
    logger.color = color;
    logger(message, ...rest);
};

if (process.env.NODE_ENV === "development") {
    localStorage.setItem("debug", WHAT_TO_LOG);

 /* *eslint-disable no-fallthrough* */
    switch (MIN_LEVEL_TO_LOG) {
        case "debug":
            log.debug = (topic: string, ...args: any) =>
                logMessage("gray", topic, ...args);

        case "verbose":
            log.verbose = (topic: string, ...args: any) =>
                logMessage("green", topic, ...args);

        case "info":
            log.info = (topic: string, ...args: any) =>
                logMessage("blue", topic, ...args);

        case "warn":
            log.warn = (topic: string, ...args: any) =>
                logMessage("brown", topic, ...args);

        case "error":
        default:
            log.error = (topic: string, ...args: any) =>
                logMessage("red", topic, ...args);
    }
}

export { log };
```

一些重要的细节：

+   `WHAT_TO_LOG`常量允许您选择应显示哪些消息。

+   `MIN_LEVEL_TO_LOG`常量定义了将被记录的最低级别。

+   日志对象具有每个严重级别的方法，就像 Winston 一样。

+   最后，如果我们不处于开发模式，将返回一个无效的`log`对象；所有对日志方法的调用都将产生完全没有任何输出。

请注意，我们在`switch`语句中使用了 fallthrough（其中没有`break`语句！）来正确构建`log`对象。这并不常见，而且我们不得不在 ESLint 中关闭它！

我们已经有了我们需要的代码；让我们看一个使用它的例子。

# 它是如何工作的…

鉴于日志记录并不是一个复杂的概念，而且我们已经在服务器上看到了它，让我们来看一个非常简短的例子。我们可以更改我们应用程序的`index.js`文件，以包含一些示例日志：

```js
// Source file: src/index.js

.
.
.

import { log } from "./logging";

log.error("myapp:SERVICE:LOGIN", `Attempt`, { user: "FK", pass: "who?" });

log.error("myapp:FORM:INITIAL", "Doing render");

log.info(
    "myapp:SERVICE:ERROR_STORE",
    "Reporting problem",
    "Something wrong",
    404
);

log.warn("myapp:SERVICE:LOGIN");

log.debug("myapp:SERVICE:INFO", "This won't be logged... low level");

log.info("myapp:SERVICE:GETDATE", "Success", {
    day: 22,
    month: 9,
    year: 60
});

log.verbose("myapp:SERVICE:LOGIN", "Successful login");
```

运行我们的应用程序将在控制台中产生以下输出；请参阅下一个截图。您应该验证只有正确的消息被记录：`info`级别及以上，并且只有它们匹配`myapp:SERVICE:*`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/0fe89aca-345f-49af-b3b2-d89d0eff1c53.png)

使用调试可以在控制台中产生清晰、易懂的输出

请注意，根据我们的规范，只显示了与`myapp:SERVICE`相关的消息。

# 使用 React Developer Tools 进行调试

当我们使用`Node`（在第五章中，*测试和调试您的服务器*）时，我们看到了如何进行基本调试，但现在我们将专注于一个`React`-特定的工具，**React Developer Tools**（**RDT**），这些工具专门用于与组件和 props 一起使用。在这个教程中，让我们看看如何安装和使用这个工具包。

# 准备工作

RDT 是 Chrome 或 Firefox 的扩展，可以让您在标准 Web 开发工具中检查组件。我们将在这里使用 Chrome 版本，但是 Firefox 的使用方式类似。您可以通过访问**Chrome Web Store**（[`chrome.google.com/webstore/category/extensions`](https://chrome.google.com/webstore/category/extensions)）并搜索 RDT 来安装该扩展；您想要的扩展是由 Facebook 编写的。单击“添加到 Chrome”按钮，当您打开 Chrome 开发者工具时，您将找到一个新的选项卡，React。

如果您不使用 Chrome 或 Firefox，或者如果您必须测试将显示在 iframe 中的`React`应用程序，您将希望查看工具的独立版本；我们将在*使用独立工具进行调试*部分中介绍它们，就在这一部分之后。

# 如何做…

让我们看看如何在上一章中的*使用 Redux 管理状态*部分中开发的计数器应用程序中使用 RDT。该应用程序很简单，所以我们可以很容易地看到如何使用该工具，但当然您也可以将其应用于非常复杂、充满组件的页面。启动应用程序，打开 Web 开发工具，选择 React 选项卡，如果展开每个组件，您将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/743c34cb-4cd1-4fd1-85c5-1a02994ddf51.png)

Web 开发工具中的 React 选项卡让您访问应用程序的整个组件层次结构

顺便说一下，您可以将该工具与任何使用`React`开发的应用程序一起使用。当工具的小图标变色时，表示可以使用，如果单击它，您将获得有关您是运行开发（红色图标）还是生产（绿色图标）的信息；此截图显示了我们的具体情况：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3ae420c8-6a29-46b5-90d6-a085034f12ef.png)

我们的新工具将检测并与任何 React 开发的应用程序一起工作

# 它是如何工作的…

我们已经安装了我们的调试工具，并将其应用到了我们的应用程序；现在让我们看看它是如何工作的，以及我们可以用它做些什么。

如果您通过点击选择任何特定组件，您可以看到它生成的组件和 HTML 元素。您还可以通过在屏幕上直接选择组件（点击 Memory 标签左侧的最左边的图标），然后点击 React 标签来以更传统的方式选择组件；您点击的元素将被选中。您还可以使用搜索功能查找特定组件；这在大型应用程序中将非常有用，可以避免手动滚动大量 HTML。

每个组件旁边的三角形可能有两种不同的颜色，这取决于它是实际的`React`组件（例如我们的情况下的`<Counter>`或`<ClicksDisplay>`）还是与存储连接的`Redux`。HTML 元素没有任何三角形。

在第三个面板中，您可以看到当前的 props。如果您编辑一个（例如尝试将`count` prop 设置为不同的值），您将立即在左侧看到更改。此外，如果您点击一个按钮，您将看到 prop 值如何更改；在您的应用程序上尝试一下三个按钮。

如果您想与任何组件进行交互，您可能会注意到当前选择的组件旁边有`== $r`。这意味着有一个特殊的 JS 变量，它指向我们的情况下所选择的组件，`<Counter>`。如果您打开 Console 标签，可以通过输入`$r.props`来检查其 props，或者尝试调用各种可用的方法，例如`$r.onAdd1()`，如下一个截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/6bc8ebab-96ed-4077-a15e-929aa0f32746.png)

`$r`变量让您可以使用（和实验）当前选择的组件

有趣的是，在我们的应用程序中，当我们编写它时，`.onAdd1()`方法实际上会分派一个动作，我们可以在截图中看到：一个带有`type:"counter:increment"`和`value:1`的对象，就像我们编写的一样；请参阅上一章中的*定义动作*部分进行检查。

如果您选择`<Provider>`组件，您可以检查应用程序的当前状态。首先您需要选择它（以便`$r`指向它），然后在 Console 标签中，您需要输入`$r.store.getState()`来获得如下一个截图中的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/229f2495-f313-4896-8673-1b225ab6e9bc.png)

通过选择<Provider>组件，您可以检查应用程序的状态

实际上，如果您愿意，甚至可以触发动作；通过输入类似`$r.store.dispatch({type:"counter:increment", value:11})`，您可以完全控制应用程序状态。

# 使用独立工具进行调试

如果您正在使用其他浏览器，如 Safari 或 Internet Explorer，或者由于某些原因无法使用 Chrome 或 Firefox，那么有一个独立版本的工具，您可以在[`github.com/facebook/react-devtools/tree/master/packages/react-devtools`](https://github.com/facebook/react-devtools/tree/master/packages/react-devtools)找到。不过，需要警告的是，对于 Web 开发，您将无法获得完整的功能，因此最好还是使用支持的浏览器！

# 准备就绪

我们想要使用独立工具；让我们看看如何设置它。首先，显然，我们需要安装该软件包。您可以全局安装，但我更喜欢在项目本身内部进行本地工作：

```js
npm install react-devtools --save-dev
```

为了能够运行新命令，您可以使用`npx`（正如我们在书中看到的那样），但更容易的方法是在`package.json`中定义一个新的脚本。添加类似以下内容，您就可以使用`npm run devtools`打开独立应用程序：

```js
"scripts": {
    .
    .
    .
    "devtools": "react-devtools"
}
```

现在你已经设置好了；让我们看看如何使用这个工具。

如果您感兴趣，这个独立应用程序本身是用 JS 编写的，并使用`Electron`转换为桌面应用程序，我们将在本书的第十三章中看到*使用 Electron 创建桌面应用程序*。

# 如何做到这一点…

我们已经得到了独立工具；让我们看看如何使用它。为了以独立方式使用 RDT，您需要在 HTML 代码的顶部添加一行。

```js
<!DOCTYPE html>
<html lang="en">

<head>
 <script src="img/192.168.1.200:8097"></script>
  .
  .
  .
```

然后正常启动应用程序，等它运行起来后，启动独立应用程序。您将看到类似下一个截图的东西。请注意，我们看到了两个单独的窗口：一个带有 RDT，另一个带有应用程序（为了多样性）在 Opera 中；我也可以使用 Safari 或 IE 或任何其他浏览器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/da859f94-64d3-4da9-a779-bf2bc63a38a3.png)

独立的 RDT 让您即使在非 Chrome 或 Firefox 浏览器中运行 React 应用程序也可以进行检查

现在您真的可以开始了；让我们通过查看我们可以（和不能）做什么来完成本节。

有关如何配置独立应用程序的更多详细信息，特别是如果您需要使用不同的端口，请查看官方文档[`github.com/facebook/react-devtools/tree/master/packages/react-devtools`](https://github.com/facebook/react-devtools/tree/master/packages/react-devtools)。对于复杂的情况，您可能需要使用不同的软件包`react-devtools-core`，在[`github.com/facebook/react-devtools/tree/master/packages/react-devtools-core`](https://github.com/facebook/react-devtools/tree/master/packages/react-devtools-core)。

# 它是如何工作的…

这个版本的开发工具让您可以与应用程序交互并查看组件和属性，但是您将受到通过控制台与它们交互的限制，我们将看到。

首先，通过检查在 Opera 窗口中单击按钮是否会自动在 RDT 中看到更改，就可以开始。在一些“添加 1”点击后查看下一个截图以查看结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/98090598-82a8-4e6b-b56b-6e7a7566f9e8.png)

您在 React 应用程序中所做的任何操作都将显示在开发工具中。在这个示例中，我点击了六次“添加 1”，更新后的组件树显示了新值

大多数功能的工作方式与 Chrome 相同。您可以按名称搜索组件，如果右键单击组件，将获得多个选项，包括显示组件名称的所有出现（与搜索一样）或复制其属性；请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/ab13863f-9c53-4bb8-b198-025b5f2a8276.png)

RDT 让您获取有关任何组件的完整信息

但是，请注意，您将无法获得*完整*的值。例如，在前面的示例中，复制的属性如下代码片段所示；我得到了一个字符串描述，而不是一个函数：

```js
{
  "count": 6,
  "dispatch": "[function dispatch]"
}
```

另一个限制是您将无法使用`$r`直接访问对象；这超出了工具的能力。但是，如果您在调试时没有解决方案，至少您将能够看到应用程序的内部工作，这并不是可以随意忽视的！

# 使用 redux-logger 记录 Redux

调试的一个基本工具是使用日志记录器。虽然 JS 已经有足够的日志记录功能可用（我们已经在第五章的*使用 Winston 添加日志记录*部分中提到了`window.console`函数），但是您需要一些帮助来记录`Redux`的操作，这是一个关键要求。当然，您可以在分派任何操作之前添加代码，但那将变得太冗长。相反，我们将考虑添加一些中间件，以记录所有操作；即使我们将在接下来的*使用 Redux 开发者工具调试 Redux*部分中看到更好的工具，这种日志也将非常有用。在这个示例中，让我们看看如何添加`redux-logger`。

我们已经使用了 thunks 的中间件，但是如果您想编写自己的中间件，您可以在[`redux.js.org/advanced/middleware`](https://redux.js.org/advanced/middleware)找到几个示例（包括日志函数）。

# 准备工作

像往常一样，我们的第一步是获取新工具。安装简单明了，与大部分文本中看到的情况相同：

```js
npm install redux-logger --save
```

这将安装新的包，但您必须手动将其添加到您的存储创建代码中；单独使用该包不会产生任何效果。

如果您想了解更多关于`redux-logger`的功能和能力，请查看[`github.com/evgenyrodionov/redux-logger`](https://github.com/evgenyrodionov/redux-logger)。

# 如何做…

设置`redux-logger`需要首先使用`createLogger()`函数创建一个记录器，该函数允许您选择许多选项来自定义记录的输出，然后将生成的记录器作为`Redux`的中间件包含。

在众多可用选项中，这些是最有趣的：

+   `colors` : 如果您希望更改输出的外观。

+   `diff:` : 一个布尔标志，用于决定是否要显示旧状态和新状态之间的差异；还有一个`diffPredicate(getState, action)`函数，你可以用它来决定是否显示差异。

+   `duration` : 一个布尔标志，用于打印处理操作所花费的时间；这主要在异步操作中会很有趣

+   `predicate(getState, action)` : 可以检查动作和当前状态，并返回 true 或 false 来定义是否应该记录动作；这对于限制日志记录到一些动作类型非常有用。

+   `titleFormatter()`、`stateTransformer()`、`actionTransformer()`和其他几个格式化函数。

有关完整的选项集，请查看[`github.com/evgenyrodionov/redux-logger`](https://github.com/evgenyrodionov/redux-logger)。

# 设置我们的计数器应用程序

我们将看到如何在最简单的情况下使用此记录器与我们的计数器应用程序，然后与区域浏览器一起使用，它将添加 thunks 到混合中。您必须使用`applyMiddleware()`函数（我们在*执行异步操作：redux-thunk*部分中已经看到了，当我们开始使用`redux-thunk`时，在第八章中）将记录器添加到流程中：

```js
// Source file: src/counterApp/store.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import { createLogger } from "redux-logger";

import { reducer } from "./counter.reducer.js";

const logger = createLogger({ diff: true, duration: true });
export const store = createStore(reducer, applyMiddleware(logger));
.
.
.
```

当然，您可能只想在开发中启用这个功能，因此前面片段的最后一行应该是以下内容：

```js
export const store =
    process.env.NODE_ENV === "development"
        ? createStore(reducer, applyMiddleware(logger))
        : createStore(reducer);
.
.
.
```

这将设置记录器以访问每个分派的动作，并记录它，包括状态之间的差异和处理时间。我们很快就会看到这是如何工作的，但首先让我们看一下我们的第二个应用程序，它已经有一些中间件。

# 设置我们的区域应用程序

当您想要应用两个或更多个中间件时，您必须指定它们将被应用的顺序。在我们的情况下，记住 thunk 可以是一个对象（fine to list）或一个函数（最终会被调用以产生一个对象），我们必须将我们的记录器放在所有可能的中间件的最后：

```js
// Source file: src/regionsApp/store.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import thunk from "redux-thunk";
import { createLogger } from "redux-logger";

import { reducer } from "./worlds.reducer.js";

const logger = createLogger({ duration: true });

export const store = createStore(reducer, applyMiddleware(thunk, logger));
.
.
.
```

我决定跳过列出差异，因为我们将得到一些有点长的列表（例如 200 多个国家），因此输出将变得太大。现在让我们看看这个日志是如何在实践中工作的。

# 它是如何工作的…

我们将两个应用程序都设置为记录所有操作，没有过滤；我们只需要`npm start`，日志输出将出现在 Web 开发者工具控制台中。

# 记录计数器应用程序

计数器应用程序非常简单：整个状态只有两个数据（当前计数器值和到目前为止的点击次数），因此很容易跟踪测试运行期间发生的情况；请参见下一个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/4040d91b-4ca8-43af-b050-d5ba98a58b2e.png)

计数器应用程序的一个示例运行，但使用 redux-logger 记录所有操作

你可以轻松地跟踪测试运行，并且你将能够看到我们点击每个按钮时分派了哪个操作以及存储的连续值——如果在减速器的逻辑中有任何问题，你可能会发现它们很容易检测到，因为屏幕上显示了所有信息。

# 记录地区应用程序

我们的第二个应用程序更有趣，因为我们正在进行实际的异步请求，要处理的数据量更大，而屏幕显示虽然仍然有点简单，但至少比计数器显示更复杂。当我们启动应用程序时，下拉菜单使用了一个操作来请求整个国家列表，正如你在这个截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3e3c3471-b707-4727-af16-64443064975e.png)

下拉组件分派了一个操作来获取国家（countries:request），并且证明成功（countries:success），返回了一个包含 249 个国家的列表

国家加载完毕后，我决定选择法国（对 2018 年 FIFA 足球世界杯冠军的一个小小的致敬！），然后一些新的操作被触发，如下一张截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/7dab0e5a-6108-4a4d-ba75-5b641266a2d2.png)

选择国家的结果：多个操作被分派并调用了 API

为了显示更小，我压缩了前两个操作，然后扩展了最后一个操作，显示了从我们自己的服务器收到的答案。你可以检查所有地区是否正确显示，尽管按名称排序，因为我们已经按名称对列表进行了排序。

有了这个记录器，你已经有了一个很好的工具来查看`React`+`Redux`应用程序中发生的事情——但我们将添加另一个工具，以更好地工作。

# 使用 Redux 开发者工具调试 Redux

如果你正在使用`React`+`Redux`工作，最好的工具之一就是`Redux`开发者工具（或 DevTools），它提供了一个控制台，让你查看操作和状态，甚至提供了一个“时光机”模式，让你可以来回穿梭，这样你就可以仔细检查一切是否如预期那样。在这个教程中，让我们看看如何使用这个非常强大的工具来帮助调试我们的代码。

如果你想看看 Dan Abramov 在 2015 年 React Europe 的演示，请查看他在[`www.youtube.com/watch?v=xsSnOQynTHs`](https://www.youtube.com/watch?v=xsSnOQynTHs)的演讲。

# 准备就绪

安装所需的`redux-devtools-extension`很容易，但要小心！不要混淆`redux-devtools-extension`包，位于[`github.com/zalmoxisus/redux-devtools-extension`](https://github.com/zalmoxisus/redux-devtools-extension)，与`redux-devtools`，一个类似但不同的包，位于[`github.com/reduxjs/redux-devtools`](https://github.com/reduxjs/redux-devtools)。后者更像是一个“自制”包，需要大量配置，尽管它可以让你为`Redux`创建一个完全定制的监视器，如果你愿意的话。对我们来说，这就是我们需要的：

```js
npm install redux-devtools-extension --save-dev
```

你还需要安装一个 Chrome 扩展程序`Redux Devtools`，它与我们刚刚安装的包一起工作。这个扩展将在 Web 开发者工具中添加一个新选项，我们将看到。

# 如何做…

```js
composeWithDevTools() added function will take care of the necessary connections to make everything work:
```

```js
// Source file: src/regionsApp/store.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import thunk from "redux-thunk";
import { createLogger } from "redux-logger";
import { composeWithDevTools } from "redux-devtools-extension";

import { reducer } from "./worlds.reducer.js";

const logger = createLogger({ duration: true });

export const store = createStore(
    reducer,
    composeWithDevTools(applyMiddleware(thunk, logger))
);
```

如果你运行代码，它将像以前一样工作，但让我们看看添加的调试功能是如何工作的。

# 它是如何工作的…

让我们启动我们的地区应用程序，然后打开 Web 开发者工具并选择 Redux 选项卡。你将得到类似下面截图的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/848f36e9-84ed-4eb2-bc94-bbf8ca07728d.png)

加载应用程序会显示初始状态以及一些操作：请求国家和该请求的成功

这里有很多功能。下面的滑块（你必须点击底部栏上的时钟图标才能看到）可能是最有趣的，因为它可以让你来回穿梭；尝试滑动它，你会看到应用程序的变化。

例如，你可以轻松地看到当国家请求操作被分发时屏幕是什么样子的，但数据返回之前；请参见下一个截图。你会记得为了检查这个，我们不得不添加一个人为的时间延迟；现在，你可以随意检查情况，而无需添加任何特殊代码。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/62796905-cfd8-495a-9794-8ea553c95e3f.png)

通过滑块，你可以看到应用程序在任何以前的时刻是什么样子的

如果你在顶部的下拉列表中选择检查员选项，你可以检查操作和状态。例如，在下一个截图中，你可以检查当从服务器检索到国家列表及其所有数据时分发的操作。你会注意到这种信息与`Redux`日志记录器包生成的信息非常相似，但你可以以更动态的方式处理它。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d3f573f9-1e9d-498b-8596-51c2cf96c89c.png)

检查员功能让你查看操作（如此处）和状态，所以你可以检查发生的一切

让我们再进一步；再次选择法国，我们将看到这些地区进来后状态发生了什么变化。Diff 标签只显示状态中的差异：在我们的情况下，`loadingRegions`的值被重置为 false（当请求地区操作被分发时，它被设置为 true），地区列表得到了它的值（法国的所有地区）。请参见下一个截图。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/85b81bbc-a823-4c88-8694-c84c74b7b8a7.png)

Diff 标签让你快速看到状态变化的属性，进行更快、更简单的分析

我们还没有浏览所有的功能，所以继续点击各处，找到其他可用的功能。例如，底部栏左侧的按钮可以让你打开一个单独的调试窗口，这样你的屏幕就不会那么拥挤了；另一个按钮可以让你创建和分发任何操作，所以继续，尝试一切！

你真的应该尝试使用这个工具，以清晰地了解你可以通过它实现什么，特别是尝试`时光机`功能。你会欣赏到这种结果之所以可能，是因为`React`以状态的方式创建视图，但最终你会注意到缺少了什么；让我们找出是什么，以及如何修复它？

# 连接路由进行调试

我们错过了什么？我们在本章的前几节中尝试的简单应用程序没有包括路由——但如果包括了呢？问题现在显而易见：每当用户导航到新的路由时，状态中没有任何内容来跟踪这种变化，所以时光机功能实际上不会起作用。为了解决这个问题，我们需要让路由信息与存储同步，这样就能恢复我们的调试功能；让我们看看如何做到这一点。

# 准备工作

在之前的`react-router`版本中，一个`react-router-redux`包负责链接路由和状态，但该包最近已被弃用，由`connected-react-router`取而代之，我们将安装它。我提到这一点是因为网络上仍然有许多文章显示了前一个包的用法；要小心：

```js
npm install --save connected-react-router
```

这是解决方案的一半；让这个包工作将（再一次！）需要对存储和应用程序的结构进行更改；让我们看看。

# 如何做…

我们想修改我们的代码，使 Redux 时光机功能能够工作。让我们再次使用我们在第八章中看到的*使用 react-router 添加路由*部分中的基本路由应用程序；我们有路由，还有一个分发一些操作的登录表单，所以我们将能够（在非常小的范围内，同意！）看到在正常应用程序中找到的各种东西。

将有两个地方发生变化：首先，我们将不得不将我们的存储与与路由器相关的`history`对象连接起来，其次，我们将不得不在我们的主代码中添加一个组件。存储更改如下-请注意，我们还在这里添加了与本章其余部分匹配的其他调试工具：

```js
// Source file: src/routingApp/store.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import thunk from "redux-thunk";
import { createLogger } from "redux-logger";
import { composeWithDevTools } from "redux-devtools-extension";
import { connectRouter, routerMiddleware } from "connected-react-router";
import { createBrowserHistory } from "history";

import { reducer } from "./login.reducer";

const logger = createLogger({ duration: true });

export const history = createBrowserHistory();

export const store = createStore(
 connectRouter(history)(reducer),
    composeWithDevTools(
        applyMiddleware(routerMiddleware(history), thunk, logger)
    )
);
```

代码看起来有点晦涩，但基本上：

+   我们创建一个`history`对象，我们需要导出它，因为我们以后会用到它

+   我们用`connectRouter()`包装我们原来的`reducer`，以生成一个新的`reducer`，它将意识到路由器状态

+   我们添加了`routerMiddleware(history)`以允许像`push()`这样的路由方法

然后我们将不得不在我们的主 JSX 中添加一个`<ConnectedRouter>`组件；这将需要我们之前创建的`history`对象：

```js
// Source file: src/App.routing.auth.js

import React, { Component } from "react";
import { Provider } from "react-redux";
import { BrowserRouter, Switch, Route, Link } from "react-router-dom";
import { ConnectedRouter } from "connected-react-router";

import {
    ConnectedLogin,
    AuthRoute
} from "./routingApp";
import { history, store } from "./routingApp/store";

const Home = () => <h1>Home Sweet Home</h1>;
const Help = () => <h1>Help! SOS!</h1>;
.
.
.

class App extends Component<{}> {
    render() {
        return (
            <Provider store={store}>
                <BrowserRouter>
 <ConnectedRouter history={history}>
                        <div>
                            <header>
                                <nav>
                                    <Link to="/">Home</Link>&nbsp;
                                    <Link to="/login">Log 
                                     in</Link>&nbsp;
                                    .
                                    .
                                    .
                                </nav>
                            </header>

                            <Switch>
                              <Route exact path="/" component={Home} />
                              <Route path="/help" component={Help} />
                                .
                                .
                                .
                            </Switch>
                        </div>
 </ConnectedRouter>
                </BrowserRouter>
            </Provider>
        );
    }
}

export default App;
```

现在一切都设置好了；让我们看看这是如何工作的。

要了解更多关于`connected-react-router`的信息，请查看其 GitHub 页面[`github.com/supasate/connected-react-router`](https://github.com/supasate/connected-react-router)；特别是，您可能会对页面底部列出的许多文章中的各种提示和建议感兴趣。

# 它是如何工作的…

现在让我们启动我们的应用程序，并不要忘记从第四章运行我们的服务器，*使用 Node 实现 RESTful 服务*，就像我们以前做的那样。打开`Redux` DevTools，我们看到一个新的动作`@@INIT`，现在状态包括一个新的路由器属性；请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/e01f59d1-f5d3-4a42-9807-cbcee3338a5c.png)

将路由连接到存储后，会出现一些新的动作和状态属性

如果我们点击 Alpha…，我们会看到有两个动作被分派：第一个尝试访问`/alpha`，第二个是我们重定向到`/login`页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/b11bbd6d-5992-4c1d-b2d2-256d78e4fecb.png)

尝试访问受保护的路由会将我们重定向到登录页面

输入用户名和密码后，我们看到我们的 login:request 和 login:success 动作-就像我们启用`Redux`开发者工具以来看到的那样-然后是另一个动作，对应于重定向到`/alpha`页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/8acb7fa1-5e29-474b-86fb-db859607bc33.png)

我们自己的动作与路由器动作交织在一起

但是，现在时间机器功能也对路由启用了；例如，如果您将滑块移回到开头，您将再次看到主页，并且您可以来回移动，视图将适当地反映您之前看到的一切；请查看下一个截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/9b15fe95-47a8-49eb-8f22-96a22251408f.png)

连接了路由器到状态后，现在我们可以使用滑块返回并每次看到正确的页面

现在我们有了一套很好的调试工具；让我们继续进行自动测试，就像我们之前在`Node`中做的那样。


# 第十章：测试您的应用程序

在本章中，我们将涵盖以下配方：

+   使用 Jest 和 Enzyme 测试组件

+   测试 reducers 和映射

+   测试 actions 和 thunks

+   使用快照测试更改

+   测量测试覆盖率

# 介绍

在上一章中，我们处理了调试。现在让我们添加一些单元测试配方，以满足我们开发所需的一切。正如我们以前所见，良好的单元测试不仅有助于开发，还可以作为预防工具，避免回归错误。

# 使用 Jest 和 Enzyme 测试组件

回到第五章，*测试和调试您的服务器*，我们对`Node`代码进行了单元测试，并且我们使用了`Jest`。正如我们所说的，这个包的一个优点是我们也可以将其与`React`（或`React Native`一起使用，我们将在第十一章中查看*使用 React Native 创建移动应用程序*），所以我们之前在本书中学到的一切仍然有效；如果你愿意，快速浏览一下，这样我们就不必在这里重复了。

我们应该测试什么？显然，我们必须为我们的组件编写单元测试，但由于我们一直在使用`Redux`，我们还需要为 reducers、actions 和 thunks 编写测试；我们将在本节和接下来的节中涵盖所有这些主题。其中一些测试将非常简单，而其他一些则需要更多的工作。那么，让我们开始吧！

# 准备就绪

对于`Node`，我们必须自己安装`Jest`，但`create-react-app`已经为我们做了这件事，所以这是一件少了的事情需要担心。（如果你自己创建了`React`应用程序，通过编写自己的配置文件，那么你应该看一下[`jestjs.io/docs/en/getting-started`](https://jestjs.io/docs/en/getting-started)来了解如何继续。）然而，我们还将使用`Enzyme`，这是一个可以简化对组件生成的 HTML 进行断言或操作的包，这与`jQuery`非常相似。

如果你想了解更多关于这些功能，或者如果你有一段时间没有使用`jQuery`了（就像我自己一样！），请阅读有关`cheerio`的信息，这是`Enzyme`使用的包，网址是[`github.com/cheeriojs/cheerio`](https://github.com/cheeriojs/cheerio)。关于`Enzyme`本身，包括其配置，你可以访问其 GitHub 网站[`github.com/airbnb/enzyme`](https://github.com/airbnb/enzyme)。

由于我们使用的是`React`的 16 版本，安装该包的当前方式如下；需要`enzyme-adapter-react-16`附加包来将`Enzyme`与`React`链接起来：

```js
npm install enzyme enzyme-adapter-react-16 --save-dev
```

另一个好处是，我们不需要进行任何特殊配置，因为`create-react-app`也会负责设置一切。然而，如果你决定需要一些特殊的东西，`react-app-rewired`会帮助你：在[`github.com/timarney/react-app-rewired`](https://github.com/timarney/react-app-rewired)上查看更多信息。

我们拥有一切所需的东西；让我们开始测试吧！

# 如何做到这一点...

我们应该测试哪些组件？我们已经使用过连接和未连接的组件，但我们将在这里专注于后者。为什么？连接的组件从`mapStateToProps()`和`mapDispatchToProps()`函数中获取它们的 props 和 dispatch 逻辑；我们可以相信这是这样的，因此我们实际上不需要测试它。如果你愿意，你可以设置一个存储并验证这两个函数是否起作用，但这些测试很容易编写，我不建议你真的需要它们。相反，我们将专注于组件的未连接版本并对其进行全面测试。我们将在这里设置所有的测试，然后我们将看看如何运行它们，以及期望的输出是什么。

# 测试没有事件的组件

我们想要测试一个组件，所以让我们选择一个合适的组件。对于我们的第一个单元测试，让我们使用`<RegionsTable>`组件，它没有处理任何事件；它只是一个显示组件。测试通常与组件同名，但将扩展名从`.js`改为`.test.js`——或者`.spec.js`，但我更喜欢`.test.js`。随便选，只要保持一致。

首先，让我们从考虑我们应该测试什么开始。我们组件的规范说明它的工作方式取决于它接收到的国家列表是空的还是非空的。在第一种情况下，我们可以测试生成的 HTML 文本是否包含*No regions*，在第二种情况下，我们应该验证提供的所有地区是否出现在输出中。当然，你可以想出更详细、更具体的情况，但尽量不要让你的测试太*脆弱*，意思是实现的细微变化会导致测试失败。我描述的测试可能并不涵盖所有情况，但几乎可以肯定，即使你以不同的方式实现组件，测试仍然应该成功。

开始实际测试时，它们都会以类似的方式开始：我们需要导入必要的库，以及要测试的组件，并设置`Enzyme`及其适配器。在下面的代码中，我将突出显示相关的行：

```js
// Source file: src/regionsApp/regionsTable.test.js

/* @flow */

import React from "react";
import Enzyme from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import { RegionsTable } from "./regionsTable.component";

Enzyme.configure({ adapter: new Adapter() });

// *continued...*
```

就像我们之前做的那样，我们将使用`describe()`和`it()`来设置不同的测试用例。要检查空地区列表的情况，我们只需要使用几行代码：

```js
// ...*continues*

describe("RegionsTable", () => {
    it("renders correctly an empty list", () => {
        const wrapper = Enzyme.render(<RegionsTable list={[]} />);
 expect(wrapper.text()).toContain("No regions.");
    });

// *continued*...
```

我们使用`Enzyme.render()`来为我们的组件生成 DOM，使用`.text()`方法生成其文本版本。通过后者，我们只需要验证所需的文本是否出现，因此整个测试非常简短。

我们还有第二个用例，其中我们提供了一个非空的地区列表。代码类似，但显然更长；让我们先看看代码，然后再解释它：

```js
// *...continues*

    it("renders correctly a list", () => {
        const wrapper = Enzyme.render(
            <RegionsTable
                list={[
                    {
                        countryCode: "UY",
                        regionCode: "10",
                        regionName: "Montevideo"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "9",
                        regionName: "Maldonado"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "5",
                        regionName: "Cerro Largo"
                    }
                ]}
            />
        );
 expect(wrapper.text()).toContain("Montevideo");
 expect(wrapper.text()).toContain("Maldonado");
 expect(wrapper.text()).toContain("Cerro Largo");
    });
});
```

逻辑非常相似：渲染组件，生成文本，检查正确的内容是否存在。正如我们所说，你也可以验证每个地区是否在`<li>`元素内，以及它们是否有键等；然而，要记住我们关于脆弱测试的写法，并避免过度规定测试，以便只有一个可能的、特定的组件实现才能通过它们！

# 测试带有事件的组件

现在我们想要测试一个带有事件的组件。为此，`<CountrySelect>`组件会很方便，因为它可以处理一些事件，并且会相应地调用一些回调函数。

首先，让我们看一下初始设置，包括我们将用于不同测试的国家列表：

```js
// Source file: src/regionsApp/countrySelect.test.js

/* @flow */

import React from "react";
import Enzyme from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import { CountrySelect } from "./countrySelect.component";

Enzyme.configure({ adapter: new Adapter() });

const threeCountries = [
    {
        countryCode: "UY",
        countryName: "Uruguay"
    },
    {
        countryCode: "AR",
        countryName: "Argentina"
    },
    {
        countryCode: "BR",
        countryName: "Brazil"
    }
];

// *continued...*
```

现在，我们将为哪些情况编写单元测试？让我们从没有给出国家列表的情况开始：根据我们的要求，在这种情况下，组件将不得不使用一个属性，比如`getCountries()`，来获取必要的数据。我们将再次使用*spy*（我们在第五章的*使用 spy*部分中看到它们）来模拟和测试必要的行为：

```js
// ...*continues*

describe("CountrySelect", () => {
    it("renders correctly when loading, with no countries", () => {
 const mockGetCountries = jest.fn();
 const mockOnSelect = jest.fn();

        const wrapper = Enzyme.mount(
            <CountrySelect
                loading={true}
                onSelect={mockOnSelect}
                getCountries={mockGetCountries}
                list={[]}
            />
        );
        expect(wrapper.text()).toContain("Loading countries");

 expect(mockGetCountries).toHaveBeenCalledTimes(1);
 expect(mockOnSelect).not.toHaveBeenCalled();
    });

// *continued...*
```

我们创建了两个 spy：一个用于`onSelect`事件处理程序，一个用于获取国家列表。测试组件输出是否包含`"Loading countries"`文本很简单；让我们专注于 spy。我们期望组件应该调用获取国家列表的函数（但只调用一次！），并且事件处理程序不应该被调用：最后两个检查就解决了这个问题。

现在，如果提供了一个国家列表，会发生什么？我们可以编写类似的测试，只是验证一个不同之处，即组件没有调用函数来获取（已经给出的）国家；我已经突出显示了相关代码：

```js
// ...*continues*

    it("renders correctly a countries dropdown", () => {
 const mockGetCountries = jest.fn();
 const mockOnSelect = jest.fn();

        const wrapper = Enzyme.mount(
            <CountrySelect
                loading={false}
                onSelect={mockOnSelect}
                getCountries={mockGetCountries}
                list={threeCountries}
            />
        );

        expect(wrapper.text()).toContain("Uruguay");
        expect(wrapper.text()).toContain("Argentina");
        expect(wrapper.text()).toContain("Brazil");

 expect(mockGetCountries).not.toHaveBeenCalled();
 expect(mockOnSelect).not.toHaveBeenCalled();
    });

// *continued...*
```

鉴于我们已经编写的测试，这部分代码应该很容易理解：我们之前已经看到类似的测试，所以这里没有新的东西需要解释。

让我们来到最终、更有趣的情况：我们如何模拟用户选择了某些东西？为此，我们将不得不检测`<CountrySelect>`组件中的`<select>`元素，为此我决定提供一个 name 属性：我在组件原始的`render()`方法中改变了一行，并将其从`<select onChange={this.onSelect}>`改为`<select onChange={this.onSelect} name="selectCountry**"**>`，这样我就有了一种方法来获取元素。当然，你可能会反对以任何方式改变原始组件代码，你也可以非常正确地指出，这使得测试比以前更加脆弱；如果组件以不同的方式重新编码，而不使用`<select>`元素，测试将自动失败，你是对的。这是一个关于测试到何种程度以及需要什么额外负担的判断。

为了完成我们的测试套件，我们要验证正确的事件处理程序是否被调用：

```js
// ...*continues*

    it("correctly calls onSelect", () => {
        const mockGetCountries = jest.fn();
 const mockOnSelect = jest.fn();

        const wrapper = Enzyme.mount(
            <CountrySelect
                loading={false}
 onSelect={mockOnSelect}
                getCountries={mockGetCountries}
                list={threeCountries}
            />
        );

 wrapper
 .find("[name='selectCountry']")
 .at(0)
 .simulate("change", { target: { value: "UY" } });

        expect(mockGetCountries).not.toHaveBeenCalled();
 expect(mockOnSelect).toHaveBeenCalledTimes(1);
 expect(mockOnSelect).toHaveBeenCalledWith("UY");
    });
});
```

我们必须使用一些 DOM 遍历来找到所需的元素，然后使用`.simulate()`来触发事件。由于实际上并没有真正触发任何事件，我们必须提供它可能包含的值，这在我们的情况下是`.target.value`。然后我们可以通过验证事件处理程序是否以正确的值（"UY"）被调用一次来完成我们的测试。

我们已经编写了组件测试；让我们看看它们是如何工作的。

# 它是如何工作的...

运行测试很简单：您只需要使用`npm test`，就像我们为`Node`做的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/2bc5d279-3ef0-42a8-a616-4c933d5cfe2c.png)

Jest 的输出与我们在 Node 中看到的样式相同；快照总数将在后面解释

`Jest`被设置为自动监视更改，因此如果您修改任何文件，测试将再次进行 - `q`命令将停止监视模式，您将不得不使用`a`来运行所有测试，或者`p`和`t`来过滤一些要运行的测试。

我们现在已经看到了如何测试组件。然而，还需要一些额外的工作，因为在我们的示例中，我们还没有处理任何与`Redux`相关的事项，比如分发操作或 thunks；让我们转向其他类型的测试。

# 测试 reducers 和映射

在测试完组件之后，我们现在转向一个更简单的测试集：首先是 reducers；然后是`mapStateToProps()`和`mapDispatchToProps()`等映射。为什么这些测试更容易编写？因为在所有这些情况下，我们都在处理纯函数，没有副作用，它们的输出仅基于它们的输入。我们在本书早期处理了这些类型的函数，当时我们为 Node 进行了测试，所以现在我们将用一个简短的部分来完成。我们唯一需要特别注意的是验证没有函数（例如 reducer）试图修改状态，但除此之外，测试都很简单。在这个配方中，让我们看看我们为 reducers 和映射需要哪些不同类型的测试。

# 如何做...

我们将不得不测试 reducers 和映射，所以让我们首先考虑如何测试 reducer。有两个关键的事情需要验证：首先，给定一个输入状态，它产生一个正确的输出状态，其次，reducer 不修改原始状态。第一个条件是非常明显的，但第二个条件很容易被忽视 - 修改当前状态的 reducer 可能会产生难以发现的错误。

让我们看看我们如何测试我们的国家和地区应用程序的 reducer。首先，由于所有测试都是类似的，我们只会看到其中的一些，针对所有可能的操作中的两个 - 但当然，你想测试*所有*的操作，对吧？我们还将包括另一个测试，以验证对于未知操作，reducer 只返回初始状态，以任何方式都不改变：

```js
// Source file: src/regionsApp/world.reducer.test.js

/* @flow */

import { reducer } from "./world.reducer.js";
import { countriesRequest, regionsSuccess } from "./world.actions.js";

describe("The countries and regions reducer", () => {
    it("should process countryRequest actions", () => {
        const initialState = {
            loadingCountries: false,
            currentCountry: "whatever",
            countries: [{}, {}, {}],
            loadingRegions: false,
            regions: [{}, {}]
        };

        const initialJSON = JSON.stringify(initialState);

        expect(reducer(initialState, countriesRequest())).toEqual({
            loadingCountries: true,
            currentCountry: "whatever",
            countries: [],
            loadingRegions: false,
            regions: [{}, {}]
        });

        expect(JSON.stringify(initialState)).toBe(initialJSON);
    });

    it("should process regionsSuccess actions", () => {
        const initialState = {
            loadingCountries: false,
            currentCountry: "whatever",
            countries: [{}, {}, {}],
            loadingRegions: true,
            regions: []
        };

        const initialJSON = JSON.stringify(initialState);

        expect(
            reducer(
                initialState,
                regionsSuccess([
                    { something: 1 },
                    { something: 2 },
                    { something: 3 }
                ])
            )
        ).toEqual({
            loadingCountries: false,
            currentCountry: "whatever",
            countries: [{}, {}, {}],
            loadingRegions: false,
            regions: [{ something: 1 }, { something: 2 }, { something: 3 }]
        });

        expect(JSON.stringify(initialState)).toBe(initialJSON);
    });

    it("should return the initial state for unknown actions", () => {
        const initialState = {
            loadingCountries: false,
            currentCountry: "whatever",
            countries: [{}, {}, {}],
            loadingRegions: true,
            regions: []
        };
        const initialJSON = JSON.stringify(initialState);

        expect(
            JSON.stringify(reducer(initialState, { actionType: "other" }))
        ).toBe(initialJSON);
        expect(JSON.stringify(initialState)).toBe(initialJSON);
    });
});
```

您是否想知道`Enzyme`，以及为什么我们跳过它？我们只在渲染组件时才需要它，所以对于测试 reducer 或操作（正如我们很快将要做的那样），根本不需要它。

reducer 的每个测试都是相同的，并遵循以下步骤：

1.  定义`initialState`并使用`JSON.stringify()`保存其原始字符串表示。

1.  调用 reducer 并使用`.toEqual()`（一个`Jest`方法，它在对象之间进行深度、递归的相等比较）来验证新状态是否完全匹配您期望的状态。

1.  检查`initialState`的 JSON 表示是否仍然与原始值匹配。

我为国家和地区使用了虚拟值，但如果您想更加小心，您可以指定完整、正确的值，而不是像`{ something:2 }`或`"whatever"`这样的值；这取决于您。

您可能想看看`redux-testkit`在[`github.com/wix/redux-testkit`](https://github.com/wix/redux-testkit)；这个包可以帮助您编写 reducer 测试，自动检查状态是否已被修改。

编写这些测试后，很明显为映射函数编写测试是相同的。例如，当我们设置`<ConnectedRegionsTable>`组件时，我们编写了一个`getProps()`函数：

```js
const getProps = state => ({
    list: state.regions,
    loading: state.loadingRegions
});
```

我们必须导出该函数（当时我们没有这样做，因为它不会在其他地方使用），然后可以执行测试，如下所示：

```js
// Source file: src/regionsApp/regionsTable.connected.test.js

/* @flow */

import { getProps } from "./regionsTable.connected.js";

describe("getProps for RegionsTable", () => {
    it("should extract regions and loading", () => {
        const initialState = {
            loadingCountries: false,
            currentCountry: "whatever",
            countries: [{ other: 1 }, { other: 2 }, { other: 3 }],
            loadingRegions: false,
            regions: [{ something: 1 }, { something: 2 }]
        };
        const initialJSON = JSON.stringify(initialState);

        expect(getProps(initialState)).toEqual({
            list: [{ something: 1 }, { something: 2 }],
            loading: false
        });
        expect(JSON.stringify(initialState)).toBe(initialJSON);
    });
});
```

这是如何工作的？让我们看看运行这些测试时会发生什么。

# 它是如何工作的...

使用`npm test`将产生一个很好的*全部绿色*输出，这意味着所有测试都已通过，就像前一节一样；不需要再次看到。在每个单独的测试中，我们应用了之前描述的技术：设置状态，保存其字符串版本，应用 reducer 或 mapper 函数，检查它是否与您希望它产生的匹配，并检查原始状态是否仍然与保存的版本匹配。

想象一下，有人意外地修改了我们测试的`getProps()`函数，以便它返回地区而不是返回国家列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/2ebf4518-d321-4d02-8e10-d6b3d6077def.png)

通过使用`.toEqual()`方法检测到映射（或 reducer）函数的任何意外更改，

进行产生和预期值的深度比较

因此，这些简单的测试可以帮助您防止意外更改-包括预期值的添加、删除或修改。这是一个很好的安全网！

# 测试操作和 thunks

为了完成我们的测试目标，我们必须看看如何测试操作和 thunks。测试前者在我们迄今为止所做的一切之后真的非常琐碎，因为只需要调用一个操作创建者并检查生成的操作上的字段，但是测试 thunks，这肯定会涉及异步服务调用，并且肯定会分发几个-好吧，这很有趣！

我们将跳过更简单的操作测试（尽管我们将测试它们，正如您将看到的那样），并直接开始编写我们的 thunks 的单元测试。

# 准备工作

我们在这里需要的一个好工具是`redux-mock-store`，这是一个小包，让我们可以使用一个假存储，模仿其所有功能，并提供一些调用，比如`.getActions()`，以检查分发了哪些操作，以什么顺序，带有哪些数据等等。安装很简单，像往常一样：

```js
npm install redux-mock-store --save-dev
```

您可能想知道我们将如何管理模拟 API 服务调用。根据您的架构，如果您的 thunks 直接使用`axios()`或`fetch()`之类的东西来联系服务，那么您肯定需要相应的模拟包。但是，由于我们将这些 API 调用分离到单独的包中，我们可以通过模拟整个调用来很好地完成，以便不会进行任何 AJAX 调用；我们很快就会做到这一点。

请查看`redux-mock-store`的完整文档，网址是 [`github.com/dmitry-zaets/redux-mock-store`](https://github.com/dmitry-zaets/redux-mock-store)。

# 如何做...

我们想要测试动作。让我们看看如何执行这些测试。

由于我们一直在大量使用我们的国家和地区示例，让我们通过测试（至少一部分）其动作和 thunk 来结束：`getCountries()`是一个很好的例子，而且与`getRegions()`非常相似。在这里，记住特定的代码将是很有帮助的，让我们来看一下：

```js
export const getCountries = () => async dispatch => {
 try {
 dispatch(countriesRequest());
 const result = await getCountriesAPI();
 dispatch(countriesSuccess(result.data));
 } catch (e) {
 dispatch(countriesFailure());
 }
};
```

首先，它分发一个动作来标记正在进行的请求。然后，它等待网络服务调用的结果；这将需要模拟！最后，如果调用成功，将分发一个包括接收到的国家列表的动作。在失败的调用上，将分发一个不同的动作，但显示失败。

现在让我们考虑一下-我们如何处理 API 调用？`world.actions.js`源代码直接从一个模块中导入`getCountriesAPI()`，但是`Jest`专门为此提供了一个功能：我们可以模拟一个完整的模块，为我们想要的任何函数提供模拟或间谍，如下所示：

```js
// Source file: src/regionsApp/world.actions.test.js

/* @flow */

import configureMockStore from "redux-mock-store";
import thunk from "redux-thunk";

import {
    getCountries,
    COUNTRIES_REQUEST,
    COUNTRIES_SUCCESS,
    COUNTRIES_FAILURE
} from "./world.actions.js";

import { getCountriesAPI } from "./serviceApi";

let mockPromise;
jest.mock("./serviceApi", () => {
 return {
 getCountriesAPI: jest.fn().mockImplementation(() => mockPromise)
 };

// *continues...*
```

每当`getCountries()`函数调用`getCountriesAPI()`时，我们的模拟模块将被使用，并且将返回一个承诺（`mockPromise`）；我们需要适当地决定这个承诺应该是什么，并且根据我们想要测试失败或成功来做出选择。

现在我们有了拦截 API 调用并使其产生我们想要的任何结果的方法，我们可以继续编写实际的测试。

让我们先处理*快乐路径*，在这种情况下，国家的 API 调用是成功的，没有问题。测试可以以以下方式编写：

```js
// ...*continued*

describe("getCountries", () => {
    it("on API success", async () => {
 const fakeCountries = {
 data: [{ code: "UY" }, { code: "AR" }, { code: "BR" }]
 };
 mockPromise = Promise.resolve(fakeCountries);

        const store = configureMockStore([thunk])({});

        await store.dispatch(getCountries());

        const dispatchedActions = store.getActions();

 expect(getCountriesAPI).toHaveBeenCalledWith();
 expect(dispatchedActions.length).toBe(2);
 expect(dispatchedActions[0].type).toBe(COUNTRIES_REQUEST);
 expect(dispatchedActions[1].type).toBe(COUNTRIES_SUCCESS);
 expect(dispatchedActions[1].listOfCountries).toEqual(
 fakeCountries.data
 );
    });

// *continues...*
```

这段代码的结构是怎样的？

1.  首先，我们定义了一些数据（`fakeCountries`），这些数据将由我们的`mockPromise`返回。

1.  然后，根据`redux-mock-store`的文档，我们创建了一个模拟商店；在我们的情况下，我们只使用了`thunk`中间件，但您可以添加更多。实际上，在我们的原始代码中，我们在`thunk`后面跟着`logger`，但这对我们的测试不相关。

1.  之后，我们`store.dispatch()`了`getCountries()` thunk 并等待其结果。

1.  一切都完成后，我们使用`store.getActions()`来获取实际分发的动作列表。

1.  我们测试我们的`getCountriesAPI()`函数是否被调用；如果没有被调用，我们将陷入严重麻烦！

1.  最后，我们测试了所有分发的动作，检查它们的`type`和其他属性。实际上，这是对动作创建者本身的间接测试！

既然我们已经看过一个成功的案例，让我们假设 API 调用以某种方式失败了。为了模拟这一点，我们所要做的就是为`getCountriesAPI()`调用定义一个不同的承诺来返回：

```js
// ...*continued*

    it("on API failure", async () => {
 mockPromise = Promise.reject(new Error("failure!"));

        const store = configureMockStore([thunk])({});

        await store.dispatch(getCountries());

        const dispatchedActions = store.getActions();

        expect(getCountriesAPI).toHaveBeenCalledWith();
        expect(dispatchedActions.length).toBe(2);
        expect(dispatchedActions[0].type).toBe(COUNTRIES_REQUEST);
        expect(dispatchedActions[1].type).toBe(COUNTRIES_FAILURE);
    });
});

// *continues...*
```

在这种情况下有什么不同？我们的`mockPromise`现在设置为失败，因此第二个分发的动作的测试会有所不同：在这种情况下，我们只会得到一个失败，而不是成功和国家列表-但是测试的其余部分基本相同。

最后，让我们完成一个额外的案例。当我们编写 thunk 时，我们发现我们可以通过`getState()`函数访问当前状态，并根据其内容采取不同的行动。我们本来可以编写我们的`getCountries()`函数，以避免在已经获得国家列表时进行 API 调用，以进行小优化；关键部分将如下所示：

```js
// ...*continued*

export const getCountries = () => async (dispatch, getState) => {
 if (getState().countries.length) {
 // no need to do anything!
 } else {
        try {
            dispatch(countriesRequest());
            const result = await getCountriesAPI();
            dispatch(countriesSuccess(result.data));
        } catch (e) {
            dispatch(countriesFailure());
        }
    }
};

// *continues*...
```

我们如何测试这种情况？不同之处在于我们如何设置商店，以及实际分发了哪些动作：

```js
// ...*continued*

describe("optimized getCountries", () => {
    it("doesn't do unneeded calls", async () => {
        const store = configureMockStore([thunk])({
 countries: [{ land: 1 }, { land: 2 }]
        });

 jest.resetAllMocks();

        await store.dispatch(getCountries());

        expect(getCountriesAPI).not.toHaveBeenCalled();
 expect(store.getActions().length).toBe(0);
    });
});
```

当我们设置存储时，我们可以提供初始值，就像在这种情况下，我们假设一些国家（虚假数据！）已经被加载。一个特殊的要求：我们必须使用`jest.resetAllMocks()`，否则我们将无法检查`getCountriesAPI()`是否被调用 - 因为它*被*调用了，但是由*之前*的测试调用的。然后，在分派 thunk 之后，我们只需检查 API 是否未被调用，并且未分派任何操作：一切正常！

# 它是如何工作的...

运行这些测试并不复杂，只需要`npm test`。我们可以看到我们的两个测试的结果（原始和优化后的`getCountries()`函数），通过的结果表明一切都如预期那样。当您运行单个测试时，输出会更详细，显示每个单独的测试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/a944b54a-a57d-4e97-970b-323c4771c36d.png)

对于操作和 thunk 的测试需要更多的设置，但以相同的方式运行。这次我们运行单个测试，因此获得了更详细的输出。

# 使用快照测试进行更改

到目前为止，我们一直在看组件、事件和操作的自动测试，因此让我们通过考虑一个测试工具来结束本章，这个测试工具并不真正是 TDD 的一部分，而是对事后不希望或不期望的更改的一种保障：*快照*。（在 TDD 中，测试将在编写组件代码之前编写，但您会看到这在这里是不可能的。）快照测试的工作方式如下：您渲染一个 UI 组件，捕获生成了什么 HTML，然后将其与先前存储的参考捕获进行比较。如果两个捕获不匹配，要么有人做了意外的更改，要么更改实际上是预期的。如果是这种情况，您将不得不验证新的捕获是否正确，然后放弃旧的捕获。

# 如何做...

我们可以为所有组件使用快照测试，但对于那些在其属性方面变化的组件来说，这更有趣，因此可以预期不同的行为。我们将使用不同的渲染方式：而不是生成 HTML 元素，我们将使用生成文本输出的渲染器，这样可以轻松存储和比较。

首先，最简单的情况是具有标准固定输出的组件。我们有一些例子：对于我们的`<ClicksDisplay>`组件，测试将写成如下形式：

```js
// Source file: src/counterApp/clicksDisplay.test.js

import React from "react";
import TestRenderer from "react-test-renderer";

import { ClicksDisplay } from "./";

describe("clicksDisplay", () => {
    it("renders correctly", () => {
 const tree = TestRenderer
 .create(<ClicksDisplay clicks={22} />)
 .toJSON();
 expect(tree).toMatchSnapshot();
    });
});
```

基本上，我们导入特殊的`TestRenderer`渲染器函数，使用它为我们的组件生成输出，然后将其与存储的快照进行比较；我们很快就会看到这是什么样子。测试基本上总是相同的：对于我们的`<Counter>`组件，测试代码将是完全类似的：

```js
// Source file: src/counterApp/counter.test.js

import React from "react";
import TestRenderer from "react-test-renderer";

import { Counter } from "./counter.component";

describe("clicksDisplay", () => {
    it("renders correctly", () => {
        const tree = TestRenderer
            .create(<Counter count={9} dispatch={() => null} />)
            .toJSON();
        expect(tree).toMatchSnapshot();
    });
});
```

差异很小；只需提供正确的预期属性，没有其他。让我们继续进行更有趣的案例。

如果您必须使用无法预先确定的属性值来渲染对象（这不太可能），您将不得不使用特殊的*属性匹配器*；您可以在[`jestjs.io/docs/en/snapshot-testing#property-matchers`](https://jestjs.io/docs/en/snapshot-testing#property-matchers)了解更多信息。

当您有组件的输出取决于其属性时，快照测试变得更有趣，因为它们可以让您验证不同的结果是否如预期那样产生。对于我们的国家和地区代码，我们有这样的情况：例如，`<RegionsTable>`组件预期显示区域列表（如果提供了），或者显示"没有区域"文本（如果没有可用的）。我们应该编写这些测试。让我们继续：

```js
// Source file: src/regionsApp/regionsTable.snapshot.test.js

import React from "react";
import TestRenderer from "react-test-renderer";

import { RegionsTable } from "./regionsTable.component";

describe("RegionsTable", () => {
 it("renders correctly an empty list", () => {
        const tree = TestRenderer.create(<RegionsTable list={[]} />).toJSON();
        expect(tree).toMatchSnapshot();
    });

 it("renders correctly a list", () => {
        const tree = TestRenderer
            .create(
                <RegionsTable
                    list={[
                        {
                            countryCode: "UY",
                            regionCode: "10",
                            regionName: "Montevideo"
                        },
                        .
                        .
                        .
                    ]}
                />
            )
            .toJSON();
        expect(tree).toMatchSnapshot();
    });
});
```

我们有两种不同的情况，就像我们之前描述的那样：一个快照将匹配*没有区域*的情况，另一个将匹配如果提供了一些区域的预期情况。对于`<CountrySelect>`组件，代码将类似：

```js
// Source file: src/regionsApp/countrySelect.snapshot.test.js

import React from "react";
import TestRenderer from "react-test-renderer";

import { CountrySelect } from "./countrySelect.component";

describe("CountrySelect", () => {
 it("renders correctly when loading, with no countries", () => {
        const tree = TestRenderer
            .create(
                <CountrySelect
                    loading={true}
                    onSelect={() => null}
                    getCountries={() => null}
                    list={[]}
                />
            )
            .toJSON();
        expect(tree).toMatchSnapshot();
    });

 it("renders correctly a countries dropdown", () => {
        const tree = TestRenderer
            .create(
                <CountrySelect
                    loading={false}
                    onSelect={() => null}
                    getCountries={() => null}
                    list={[
                        {
                            countryCode: "UY",
                            countryName: "Uruguay"
                        },
                        .
                        .
                        .
                    ]}
                />
            )
            .toJSON();
        expect(tree).toMatchSnapshot();
    });
});
```

因此，测试具有多个可能输出的组件并不难，只需要编写多个快照测试；一个简单的解决方案。

最后，为了简化测试，当您的组件本身有更多的组件时，使用浅渲染有助于集中在主要的高级方面，并将内部组件的渲染细节留给其他测试。我们可以像这样快速创建一个虚构的`<CountryAndRegions>`组件，显示我们国家的下拉菜单和地区表：

```js
// Source file: src/regionsApp/countryAndRegions.test.js

import React from "react";
import ShallowRenderer from "react-test-renderer/shallow";

import { CountrySelect } from "./countrySelect.component";
import { RegionsTable } from "./regionsTable.component";

class CountryAndRegions extends React.Component {
    render() {
        return (
            <div>
                <div>
                    Select:
                    <CountrySelect
                        loading={true}
                        onSelect={() => null}
                        getCountries={() => null}
                        list={[]}
                    />
                </div>
                <div>
                    Display: <RegionsTable list={[]} />
                </div>
            </div>
        );
    }
}

describe("App for Regions and Countries", () => {
    it("renders correctly", () => {
        const tree = new ShallowRenderer().render(<CountryAndRegions />);
        expect(tree).toMatchSnapshot();
    });
});

```

请注意，使用`ShallowRenderer`的方式与其他渲染器不同：您必须创建一个新对象，调用其`.render()`方法，而不再使用`.toJSON()`。我们将很快看一下这个新测试与以前的测试有何不同。

# 它是如何工作的...

运行快照与运行其他测试没有什么不同：您运行`Jest`测试脚本，所有测试一起运行。

# 运行测试

如果您像之前一样运行`npm test`，您现在会得到类似以下清单的输出：

```js
 PASS src/regionsApp/countryAndRegions.test.js
 PASS src/counterApp/counter.test.js
 PASS src/regionsApp/countrySelect.test.js
 PASS src/regionsApp/regionsTable.test.js
 PASS src/counterApp/clicksDisplay.test.js

Test Suites: 5 passed, 5 total
Tests:       7 passed, 7 total
Snapshots:   7 passed, 7 total
Time:        0.743s, estimated 1s
Ran all test suites related to changed files.

Watch Usage
 › Press a to run all tests.
 › Press p to filter by a filename regex pattern.
 › Press t to filter by a test name regex pattern.
 › Press q to quit watch mode.
 › Press Enter to trigger a test run.
```

唯一可见的区别是您会得到特定数量的快照（在这种情况下为七个），但还有更多。

# 生成的快照文件

如果您检查源代码目录，您会发现一些新的`__snapshots__`目录，其中包含一些`.snap`文件。例如，在`/regionsApp`目录中，您会发现这个：

```js
> dir
-rw-r--r-- 1 fkereki users 956 Aug 10 20:48 countryAndRegions.test.js
-rw-r--r-- 1 fkereki users 1578 Jul 28 13:02 countrySelect.component.js
-rw-r--r-- 1 fkereki users 498 Jul 25 23:16 countrySelect.connected.js
-rw-r--r-- 1 fkereki users 1301 Aug 10 20:31 countrySelect.test.js
-rw-r--r-- 1 fkereki users 212 Jul 22 21:07 index.js
-rw-r--r-- 1 fkereki users 985 Aug 9 23:45 regionsTable.component.js
-rw-r--r-- 1 fkereki users 274 Jul 22 21:17 regionsTable.connected.js
-rw-r--r-- 1 fkereki users 1142 Aug 10 20:32 regionsTable.test.js
-rw-r--r-- 1 fkereki users 228 Jul 25 23:16 serviceApi.js
drwxr-xr-x 1 fkereki users 162 Aug 10 20:44 __snapshots__
-rw-r--r-- 1 fkereki users 614 Aug 3 22:22 store.js
-rw-r--r-- 1 fkereki users 2679 Aug 3 21:33 world.actions.js
```

对于每个包含快照的`.test.js`文件，您会找到一个相应的`.snap`文件：

```js
> dir __snapshots__/
-rw-r--r-- 1 fkereki users 361 Aug 10 20:44 countryAndRegions.test.js.snap
-rw-r--r-- 1 fkereki users 625 Aug 10 20:32 countrySelect.test.js.snap
-rw-r--r-- 1 fkereki users 352 Aug 10 20:01 regionsTable.test.js.snap
```

这些文件的内容显示了运行时生成的快照。例如，`countrySelect.test.js.snap`文件包括以下代码：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`CountrySelect renders correctly a countries dropdown 1`] = `
<div
  className="bordered"
>
  Country: 
  <select
    onChange={[Function]}
  >
    <option
      value=""
    >
      Select a country:
    </option>
    <option
      value="AR"
    >
      Argentina
    </option>
    <option
      value="BR"
    >
      Brazil
    </option>
    <option
      value="UY"
    >
      Uruguay
    </option>
  </select>
</div>
`;

exports[`CountrySelect renders correctly when loading, with no countries 1`] = `
<div
  className="bordered"
>
  Loading countries...
</div>
`;
```

您可以看到我们两种情况的输出：一个是完整的国家列表，另一个是在加载国家时，等待服务响应到达时的情况。

我们还可以在`countryAndRegions.test.js.snap`文件中看到一个浅层测试：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`App for Regions and Countries renders correctly 1`] = `
<div>
  <div>
    Select:
    <CountrySelect
      getCountries={[Function]}
      list={Array []}
      loading={true}
      onSelect={[Function]}
    />
  </div>
  <div>
    Display: 
    <RegionsTable
      list={Array []}
    />
  </div>
</div>
`;
```

在这种情况下，请注意`<CountrySelect>`和`<RegionsTable>`组件没有展开；这意味着您只在这里测试高级快照，这是期望的。

# 重新生成快照

如果组件发生了变化会发生什么？仅仅为了这个目的，我对一个组件进行了一个非常小的更改。运行测试后，我收到了一个 FAIL 消息，附带了一个比较，这是由通常的`diff`命令生成的：

```js
 FAIL src/regionsApp/countryAndRegions.test.js
  ● App for Regions and Countries › renders correctly

    expect(value).toMatchSnapshot()

 Received value does not match stored snapshot 1.

    - Snapshot
    + Received

    @@ -7,11 +7,11 @@
           loading={true}
           onSelect={[Function]}
         />
       </div>
       <div>
 - Display: 
 + Displays: 
         <RegionsTable
           list={Array []}
         />
       </div>
     </div>

      at Object.it (src/regionsApp/countryAndRegions.test.js:31:22)
          at new Promise (<anonymous>)
      at Promise.resolve.then.el (node_modules/p-map/index.js:46:16)
```

那么，您应该怎么做呢？您应该首先验证更改是否正确，如果是这样，您可以删除`.snap`文件（这样它将在下次重新生成），或者您可以按`u`键，如测试摘要中所示：

```js
Snapshot Summary
 › 1 snapshot test failed in 1 test suite. Inspect your code changes or press `u` to update them.
```

小心！如果您只是重新生成快照而没有验证输出是否正确，那么测试将毫无意义；这是一个非常糟糕的结果！

# 测量测试覆盖率

我们已经在第五章的*测量测试覆盖率*部分看到了如何为`Jest`测试获取覆盖率，因此在这个示例中，我们将简要介绍一些我们将对测试进行的小改动。

# 如何做...

我们想要衡量我们的测试有多彻底，所以让我们看看必要的步骤。在使用`Node`时，我们直接调用了`jest`命令。然而，在这里，由于应用是由`create-react-app`构建的，我们将不得不以稍有不同的方式工作。我们将不得不向`package.json`添加一个新的脚本，以便用额外的参数调用我们的测试：

```js
"scripts": {
    .
    .
    .
    "test": "react-app-rewired test --env=jsdom",
 "coverage": "react-app-rewired test --env=jsdom --coverage --no-cache",
    .
    .
    .
}
```

`--coverage`选项将生成一个覆盖率报告，并生成一个`/coverage`目录，与`Node`一样，`--no-cache`选项将强制 Jest 重新生成所有结果，而不是依赖于先前可能不再有效的缓存值。

我们的`.gitignore`文件包括一行内容为`/coverage`，因此生成的文件不会被推送到 Git 服务器。

# 它是如何工作的...

如果你运行`npm run coverage`，你将得到文本输出和 HTML 输出。前者看起来像下面截图中显示的内容；你必须接受现实中，行是绿色、黄色或红色的，取决于覆盖程度。

在我们的情况下，我们得到了很多红色，因为我们只写了一些测试，而不是进行完整的测试套件；你可以自己完成它，作为读者的练习！

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/a0cb50fd-0796-45ee-8c26-ceb6372e87dc.png)

有色 ASCII 输出显示了我们所有源代码文件的覆盖评估；绿色表示良好的覆盖，黄色表示中等覆盖，

红色表示结果不佳。由于我们只写了一些测试，我们得到了很多红色！

如果你在浏览器中打开`/coverage/lcov-report/index.html`文件，你会得到与`Node`章节中相同类型的结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/a01440be-90b8-4af6-9e6e-9b274b2b22d8.png)

HTML 输出允许您浏览项目的目录和文件。如果您点击特定文件，甚至可以看到哪些行和函数被执行，哪些被测试跳过。

如果你愿意，甚至可以使用`coverageThreshold`配置对象来指定必须达到的覆盖水平，以便测试被认为是足够的；有关更多信息，请参阅[`jestjs.io/docs/en/configuration.html#coveragethreshold-object`](https://jestjs.io/docs/en/configuration.html#coveragethreshold-object)。

我们现在已经完成了与`React`和`Redux`的工作，我们已经看过了如何构建 Web 应用程序，并且使用了之前开发的`Node`服务器后端。让我们继续进行其他类型的开发，首先是移动应用程序，同样也是用 JS！


# 第十一章：使用 React Native 创建移动应用程序

在本章中，我们将看看以下食谱：

+   设置事情

+   添加开发工具

+   使用本机组件

+   适应设备和方向

+   样式和布局您的组件

+   添加特定于平台的代码

+   路由和导航

# 介绍

在过去的几章中，我们向您展示了如何使用`React`构建 Web 应用程序，在本章中，我们将使用一个紧密相关的`React Native`来开发可以在 Android 和 iOS（苹果）手机上运行的本机应用程序。

# 设置事情

对于移动应用程序的开发，有几种可能的方法：

+   *使用本机语言*，例如 Java 或 Kotlin 用于 Android，或 Objective C 或 Swift 用于 iOS，使用每个平台的本机开发工具。这可以确保您的应用程序最适合不同的手机，但需要多个开发团队，每个团队都有特定平台的经验。

+   使用纯网站，用户可以通过手机浏览器访问。这是最简单的解决方案，但应用程序会有一些限制，比如无法访问大多数手机功能，因为它们无法在 HTML 中使用。此外，使用无线连接运行，信号强度可能会有所不同，有时可能会很困难。您可以使用任何框架进行开发，比如`React`。

+   *开发混合应用程序*，这是一个网页，捆绑了一个浏览器，包括一组扩展，以便您可以使用手机的内部功能。对于用户来说，这是一个独立的应用程序，即使没有网络连接也可以运行，并且可以使用大多数手机功能。这些应用程序通常使用 Apache Cordova 或其衍生产品 PhoneGap。

还有第四种风格，由 Facebook 开发的`React Native`，沿用了现有的`React`。`React Native`（从现在开始，我们将缩写为*RN*）不是将组件呈现到浏览器的 DOM，而是调用本机 API 来创建通过您的 JS 代码处理的内部组件。通常的 HTML 元素和 RN 的组件之间存在一些差异，但并不难克服。使用这个工具，您实际上正在构建一个外观和行为与任何其他本机应用程序完全相同的本机应用程序，只是您使用了一种语言 JS，用于 Android 和 iOS 开发。

在这个示例中，我们将设置一个 RN 应用程序，以便我们可以开始尝试开发手机应用程序。

# 如何做...

有三种设置 RN 应用程序的方法：完全手动设置，这是您不想做的；其次，使用`react-native-cli`命令行界面进行打包；或者最后，使用一个与我们已经用于`React`非常相似的包，`create-react-native-app`（从现在开始，我们将称其为*CRAN*）。这两个包之间的一个关键区别是，对于后者，您无法包含自定义的本地模块，如果需要这样做，您将不得不*弹出*项目，这也需要设置其他几个工具。

您可以在[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html)了解更多关于后两种方法的信息，如果您想为弹出做好准备，可以访问[`github.com/react-community/create-react-native-app/blob/master/EJECTING.md`](https://github.com/react-community/create-react-native-app/blob/master/EJECTING.md)。

我们首先要获取一个命令行实用程序，其中包括许多其他包：

```js
npm install create-react-native-app -g
```

之后，我们可以使用只有三个命令的简单项目创建和运行一个简单的项目：

```js
create-react-native-app yourprojectname
cd yourprojectname
npm start
```

您已经准备好了！让我们看看它是如何工作的——是的，我们还有一些配置要做，但检查一下事情是否进行得很顺利是件好事。

# 它是如何工作的...

运行应用程序时，它会在您的机器上的端口`19000`或`19001`启动服务器，您将使用`Expo`应用程序连接到该服务器，您可以在[`expo.io/learn`](https://expo.io/learn)找到该应用程序，适用于 Android 或 iOS。按照屏幕上的说明进行安装：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/515f38da-eefb-46bc-9cea-c7b4cf0818d0.png)

启动应用程序时获得的初始屏幕

当您第一次打开`Expo`应用程序时，它将看起来像以下截图。请注意，手机和您的机器必须在同一本地网络中，并且您的机器还必须允许连接到端口`19000`和`19001`；您可能需要修改防火墙才能使其正常工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/8954ddfd-4485-4498-a9a4-5800a256674b.png)

在加载 Expo 应用程序时，您需要扫描 QR 码以连接到服务器

使用扫描 QR 码选项后，将进行一些同步，很快您将看到您的基本代码运行正常：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3283acff-a484-42cc-9944-4631a406b48b.png)

成功——您的代码已经运行起来了！

此外，如果您修改`App.js`源代码，更改将立即反映在您的设备上，这意味着一切正常！为了确保这一点，摇动手机以启用调试菜单，并确保启用了实时重新加载和热重新加载。您还需要远程 JS 调试以备后用。您的手机应该如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d61a0ed6-b6f7-43ed-b90e-13d4a50bd516.png)

这些设置可以重新加载和调试

# 还有更多...

通过使用`Expo`客户端，CRAN 可以让您为 iOS 开发，即使您没有苹果电脑。（如果您有 Windows 或 Linux 机器，则无法为苹果系统开发；您必须拥有 MacBook 或类似设备；这是苹果的限制。）此外，在实际设备上工作在某些方面更好，因为您可以实际看到最终用户将看到的内容——毫无疑问。

但是，您可能有几个原因希望以不同方式工作，也许是在计算机上使用模拟真实设备的模拟器。首先，您可能很难获得十几个最受欢迎的设备，以便在每个设备上测试您的应用程序。其次，在自己的机器上工作更加方便，您可以轻松进行调试，截图，复制和粘贴等。因此，您可以安装 Xcode 或 Android SDK 以使自己能够使用模拟机器进行工作。

我们不会在这里详细介绍，因为根据您的开发操作系统和目标操作系统有很多组合；相反，让我们指向文档[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html)，在那里您应该点击使用本机代码构建项目，并查看与模拟器一起工作所需的内容。安装完毕后，您将需要`Expo`客户端（与您的实际设备一样），然后您将能够在自己的机器上运行代码。

例如，看一下以下截图中模拟 Nexus 5 的 Android 模拟器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/58237379-2a4d-4820-8922-7acf6d4ec249.png)

在您的屏幕上直接运行的模拟 Nexus 5 Android

使用此模拟器，您将具有与实际设备完全相同的功能。例如，您还可以获得调试菜单，尽管打开它的方式会有所不同；例如，在我的 Linux 机器上，我需要按*Ctrl* + *M*：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/89419e1a-12c7-44da-92af-4c5e72d9d213.png)

所有在手机上可用的功能在模拟设备上也同样可用

使用**Android 虚拟设备**（**AVD**）管理器，您可以为手机和平板电脑创建许多不同的模拟器；使用 Xcode，您也可以获得类似的功能，尽管这仅适用于 macOS 计算机。

# 添加开发工具

现在，让我们更好地配置一下。与之前的章节一样，我们希望使用 ESLint 进行代码检查，`Prettier`进行格式化，`Flow`进行数据类型检查。CRAN 负责包含`Babel`和`Jest`，所以我们不需要为这两个做任何事情。

# 如何做...

与在`React`中需要添加特殊的`rewiring`包才能使用特定配置的情况相反，在 RN 中，我们只需要添加一些包和配置文件，就可以准备好了。

# 添加 ESLint

对于 ESLint，我们需要相当多的包。我们在`React`中使用了大部分，但还有一个特殊的添加，`eslint-plugin-react-native`，它添加了一些 RN 特定的规则：

```js
npm install --save-dev \
 eslint eslint-config-recommended eslint-plugin-babel \
 eslint-plugin-flowtype eslint-plugin-react eslint-plugin-react-native
```

如果你想了解`eslint-plugin-react-native`添加的（实际上很少的）额外规则，请查看其 GitHub 页面[`github.com/Intellicode/eslint-plugin-react-native`](https://github.com/Intellicode/eslint-plugin-react-native)。其中大部分与样式有关，还有一个是用于特定平台代码的，但我们稍后会讨论这个。

我们需要一个单独的`.eslintrc`文件，就像我们在`React`中所做的一样。适当的内容包括以下内容，我已经突出显示了 RN 特定的添加内容：

```js
{
    "parser": "babel-eslint",
    "parserOptions": {
        "ecmaVersion": 2017,
        "sourceType": "module",
        "ecmaFeatures": {
            "jsx": true
        }
    },
    "env": {
        "node": true,
        "browser": true,
        "es6": true,
        "jest": true,
 "react-native/react-native": true
    },
    "extends": [
        "eslint:recommended",
        "plugin:flowtype/recommended",
        "plugin:react/recommended",
 "plugin:react-native/all"
    ],
    "plugins": ["babel", "flowtype", "react", "react-native"],
    "rules": {
        "no-console": "off",
        "no-var": "error",
        "prefer-const": "error",
        "flowtype/no-types-missing-file-annotation": 0
    }
}
```

# 添加 Flow

完成后，`ESLint`已经设置好识别我们的代码，但我们还需要配置`Flow`：

```js
npm install --save-dev flow flow-bin flow-coverage-report flow-typed
```

我们需要在`package.json`的`scripts`部分添加几行：

```js
"scripts": {
    "start": "react-native-scripts start",
    .
    .
    .
 "flow": "flow",
 "addTypes": "flow-typed install"
},
```

然后，我们需要初始化`Flow`的工作目录：

```js
npm run flow init
```

最后，我们可以使用与之前 React 相同的`.flowconfig`文件：

```js
[ignore]
.*/node_modules/.*

[include]

[libs]

[lints]
all=warn
untyped-type-import=off
unsafe-getters-setters=off

[options]
include_warnings=true

[strict]
```

现在我们已经准备好使用`Flow`，所以我们可以继续以我们习惯的方式工作——我们只需要添加`Prettier`来格式化我们的代码，然后我们就可以开始了！

# 添加 Prettier

重新安装`Prettier`并没有太多的事情，我们只需要一个`npm`命令，再加上我们一直在使用的`.prettierrc`文件。对于前者，只需使用以下命令：

```js
npm install --save-dev prettier
```

对于配置，我们可以使用这个`.prettierrc`文件的内容：

```js
{
    "tabWidth": 4,
    "printWidth": 75
}
```

现在，我们准备好了！我们可以检查它是否工作；让我们来做吧。

# 它是如何工作的...

让我们检查一切是否正常。我们将首先查看 CRAN 创建的`App.js`文件，我们可以立即验证工具是否正常工作——因为检测到了一个问题！看一下以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/66dd3473-9ef7-42f3-a8e2-f0a6a54816e6.png)

我们可以验证 ESLint 集成是否正常工作，因为它会突出显示一个问题

失败的规则是来自`eslint-plugin-react-native`的新规则：`no-color-literals`，因为我们在样式中使用了常量，这可能在将来会成为一个维护的头疼。我们可以通过添加一个变量来解决这个问题，并且我们将使用类型声明来确保`Flow`也在运行。新的代码应该如下所示——我已经突出显示了所需的更改：

```js
// Source file: App.original.fixed.js /* @flow */

import React from "react";
import { StyleSheet, Text, View } from "react-native";

export default class App extends React.Component<> {
    render() {
        return (
            <View style={styles.container}>
                <Text>Open up App.js to start working on your app!</Text>
                <Text>Changes you make will automatically reload.</Text>
                <Text>Shake your phone to open the developer menu.</Text>
            </View>
        );
    }
}

const white: string = "#fff";

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: white,
        alignItems: "center",
        justifyContent: "center"
    }
});
```

因此，现在我们已经恢复了所有的工具，我们可以开始实际的代码了！

# 使用原生组件

使用 RN 的工作方式非常类似于使用`React`——有组件、状态、属性、生命周期事件等等，但有一个关键区别：你自己的组件不是基于 HTML，而是基于特定的 RN 组件。例如，你不会使用`<div>`元素，而是使用`<View>`元素，然后 RN 将其映射到 iOS 的`UIView`或 Android 的`Android.View`。视图可以嵌套在视图中，就像`<div>`标签一样。视图支持布局和样式，它们响应触摸事件等等，因此它们基本上等同于`<div>`标签，除了移动环境的行为和特定性。

还有更多的不同之处：组件的属性也与 HTML 的不同，你需要查看文档（在[`facebook.github.io/react-native/docs/components-and-apis`](https://facebook.github.io/react-native/docs/components-and-apis)）来了解每个特定组件的所有可能性。

您不仅限于使用 RN 提供的组件。您可以通过使用其他人开发的本机组件来扩展您的项目；一个一流的来源是令人敬畏的 React Native 列表，网址为[`www.awesome-react-native.com/`](http://www.awesome-react-native.com/)。请注意，您可能需要弹出您的项目才能这样做，因此请查看[`github.com/react-community/create-react-native-app/blob/master/EJECTING.md`](https://github.com/react-community/create-react-native-app/blob/master/EJECTING.md)获取更多信息。

# 准备就绪

让我们首先浏览一下您可能想要使用的 RN 组件和 API 的列表，然后我们将转移到一些实际的代码：

| **RN 组件** | **替代...** | **目的** |
| --- | --- | --- |
| `ActivityIndicator` | 动画 GIF | 用于显示循环加载指示器的组件 |
| `Button` | `button` | 处理触摸（点击）的组件 |
| `DatePickerAndroid` `TimePickerAndroid` | `input type="date"` `input type="time"` | 显示弹出窗口的 API，您可以在其中输入日期和时间；适用于 Android |

| `DatePickerIOS` | `input type="date"` `input type="datetime-local"`

`input type="time"` | 用户可以输入日期和时间的组件；适用于 iOS |

| `FlatList` | - | 仅呈现可见元素的列表组件；用于提高性能 |
| --- | --- | --- |
| `Image` | `img` | 用于显示图像的组件 |
| `Picker` | `select` | 从列表中选择值的组件 |
| `Picker.Item` | `option` | 用于定义列表的值的组件 |
| `ProgressBarAndroid` | - | 用于显示活动的组件；仅适用于 Android |
| `ProgressViewIOS` | - | 用于显示活动的组件；仅适用于 iOS |
| `ScrollView` | - | 可包含多个组件和视图的滚动容器 |
| `SectionList` | - | 类似于`FlatList`，但允许分段列表 |
| `Slider` | `input type="number"` | 从一系列值中选择值的组件 |
| `StatusBar` | - | 管理应用程序状态栏的组件 |
| `StyleSheet` | CSS | 为您的应用程序应用样式 |
| `Switch` | `input type="checkbox"` | 用于接受布尔值的组件 |
| `Text` | - | 用于显示文本的组件 |
| `TextInput` | `input type="text"` | 用键盘输入文本的组件 |
| `TouchableHighlight` `TouchableOpacity` | - | 使视图响应触摸的包装器 |
| `View` | `div` | 应用程序的基本结构特征 |
| `VirtualizedList` | - | `FlatList`的更灵活版本 |
| `WebView` | `iframe` | 用于呈现网络内容的组件 |

还有许多您可能感兴趣的 API；其中一些如下：

| **API** | **描述** |
| --- | --- |
| `Alert` | 显示具有给定标题和文本的警报对话框 |
| `Animated` | 简化创建动画 |
| `AsyncStorage` | `LocalStorage`的替代方案 |
| `Clipboard` | 提供获取和设置剪贴板内容的访问权限 |
| `Dimensions` | 提供设备尺寸和方向变化的访问权限 |
| `Geolocation` | 提供地理位置访问权限；仅适用于已弹出的项目 |
| `Keyboard` | 允许控制键盘事件 |
| `Modal` | 显示在视图上方的内容 |
| `PixelRatio` | 提供设备像素密度的访问 |
| `Vibration` | 允许控制设备振动 |

为了尽可能少出问题，您可能更喜欢避开特定平台的组件和 API，并使用通用的兼容组件。但是，如果您决定使用一些特定于 Android 或 iOS 的元素，请查看[`facebook.github.io/react-native/docs/platform-specific-code`](https://facebook.github.io/react-native/docs/platform-specific-code)了解如何操作的详细信息；这并不复杂。但是请记住，这将变得更难以维护，并且可能会改变一些交互或屏幕设计。

现在，让我们重新访问我们在第六章中为`React`编写的示例，*使用 React 开发*，国家和地区页面，这也将让我们使用`Redux`和异步调用，就像第八章中那样，*扩展你的应用程序*。由于我们使用了`PropTypes`，我们将需要该包。使用以下命令安装它：

```js
npm install prop-types --save
```

然后，我们将不得不重新安装一些包，从`Redux`和相关的开始。实际上，CRAN 已经包括了`redux`和`react-redux`，所以我们不需要这些，但`redux-thunk`没有包括在内。如果你以不同的方式创建了项目，而没有使用 CRAN，你将需要手动安装这三个包。在这两种情况下，以下命令都可以使用，因为`npm`不会安装已经安装的包：

```js
npm install react react-redux redux-thunk --save
```

我们还将在本书中早些时候使用`axios`进行异步调用：

```js
npm install axios --save
```

默认情况下，RN 提供了`fetch`而不是`axios`。然而，RN 包括了`XMLHttpRequest`API，这使我们可以毫无问题地安装`axios`。有关网络处理的更多信息，请查看[`facebook.github.io/react-native/docs/network`](https://facebook.github.io/react-native/docs/network)。

我们的最后一步将是运行我们在第四章中编写的服务器代码，*使用 Node 实现 RESTful 服务*，这样我们的应用程序将能够进行异步调用。转到该章节的目录，然后输入以下命令：

```js
node out/restful_server.js.
```

现在，我们准备好了！现在让我们看看如何修改我们的代码，使其适用于 RN。

# 如何做...

由于 RN 使用自己的组件，你的 HTML 经验将没有多少用处。在这里，我们将看到一些变化，但为了充分利用 RN 的所有可能性，你将需要自己学习它的组件。让我们从`<RegionsTable>`组件开始，它相当简单。我们在第六章的*使用 React 开发*部分看到了它的原始代码；在这里，让我们专注于差异，这些差异都限制在`render()`方法中。之前，我们使用`<div>`标签并在其中显示文本；在这里，使用 RN，我们需要使用`<View>`和`<Text>`元素：

```js
// Source file: src/regionsApp/regionsTable.component.js

.
.
.

render() {
    if (this.props.list.length === 0) {
        return (
 <View>
 <Text>No regions.</Text>
 </View>
        );
    } else {
        const ordered = [...this.props.list].sort(
            (a, b) => (a.regionName < b.regionName ? -1 : 1)
        );

        return (
 <View>
                {ordered.map(x => (
 <View key={x.countryCode + "-" + x.regionCode}>
 <Text>{x.regionName}</Text>
 </View>
                ))}
 </View>
        );
    }
}
```

请注意，在组件的其余部分没有变化，你所有的`React`知识仍然有效；你只需要调整你的渲染方法的输出。

接下来，我们将更改`<CountrySelect>`组件以使用`<Picker>`，这有点类似，但我们需要一些额外的修改。让我们看看我们的组件，突出显示需要进行更改的部分：

```js
// Source file: src/regionsApp/countrySelect.component.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";
import { View, Text, Picker } from "react-native";

export class CountrySelect extends React.PureComponent<{
    dispatch: ({}) => any
}> {
    static propTypes = {
        loading: PropTypes.bool.isRequired,
 currentCountry: PropTypes.string.isRequired,
        list: PropTypes.arrayOf(PropTypes.object).isRequired,
        onSelect: PropTypes.func.isRequired,
        getCountries: PropTypes.func.isRequired
    };

    componentDidMount() {
        if (this.props.list.length === 0) {
            this.props.getCountries();
        }
    }

 onSelect = value => this.props.onSelect(value);

    render() {
        if (this.props.loading) {
            return (
 <View>
 <Text>Loading countries...</Text>
 </View>
            );
        } else {
            const sortedCountries = [...this.props.list].sort(
                (a, b) => (a.countryName < b.countryName ? -1 : 1)
            );

            return (
 <View>
 <Text>Country:</Text>
 <Picker
 onValueChange={this.onSelect}
 prompt="Country"
 selectedValue={this.props.currentCountry}
 >
 <Picker.Item
 key={"00"}
 label={"Select a country:"}
 value={""}
 />
 {sortedCountries.map(x => (
 <Picker.Item
 key={x.countryCode}
 label={x.countryName}
 value={x.countryCode}
 />
 ))}
 </Picker>
 </View>
            );
        }
    }
}
```

很多变化！让我们按照它们发生的顺序来看：

+   一个意外的变化：如果你想让`<Picker>`组件显示其当前值，你必须设置它的`selectedValue`属性；否则，即使用户选择了一个国家，变化也不会在屏幕上显示出来。我们将不得不提供一个额外的属性`currentCountry`，我们将从存储中获取它，这样我们就可以将它用作我们列表的`selectedValue`。

+   当用户选择一个值时触发的事件也是不同的；事件处理程序将直接调用选择的值，而不是使用`event.target.value`来处理事件。

+   我们必须用`<Picker>`替换`<select>`元素，并提供一个`prompt`文本属性，当扩展列表显示在屏幕上时将使用它。

+   我们必须使用`<Item>`元素来表示单个选项，注意要显示的`label`现在是一个属性。

让我们不要忘记连接国家列表到存储时的更改；我们只需要在`getProps()`函数中添加一个额外的属性：

```js
// Source file: src/regionsApp/countrySelect.connected.js

const getProps = state => ({
    list: state.countries,
 currentCountry: state.currentCountry,
    loading: state.loadingCountries
});
```

现在，我们需要做的就是看一下主应用是如何设置的。我们的`App.js`代码将非常简单：

```js
// Source file: App.js

/* @flow */

import React from "react";
import { Provider } from "react-redux";

import { store } from "./src/regionsApp/store";
import { Main } from "./src/regionsApp/main";

export default class App extends React.PureComponent<> {
    render() {
        return (
 <Provider store={store}>
 <Main />
 </Provider>
        );
    }
}
```

这很简单。其余的设置将在`main.js`文件中进行，其中有一些有趣的细节：

```js
// Source file: src/regionsApp/main.js

/* @flow */

import React from "react";
import { View, StatusBar } from "react-native";

import {
    ConnectedCountrySelect,
    ConnectedRegionsTable
} from ".";

export class Main extends React.PureComponent<> {
    render() {
        return (
 <View>
 <StatusBar hidden />
                <ConnectedCountrySelect />
                <ConnectedRegionsTable />
 </View>
        );
    }
}
```

除了在以前使用`<div>`的地方使用`<View>`（这是一个你应该已经习惯的变化）之外，还有一个额外的细节：我们不希望显示状态栏，因此我们使用`<StatusBar>`元素，并确保隐藏它。

好了，就是这样！在编写 RN 代码时，起初你需要努力记住哪些元素相当于你以前熟悉的 HTML 元素，哪些属性或事件发生了变化，但除此之外，你以前的所有知识仍然有效。最后，让我们看看我们的应用程序运行。

# 它是如何工作的...

为了多样化，我决定使用模拟设备，而不是像本章前面那样使用我的手机。在使用`npm start`启动应用程序后，我启动了我的设备，很快就得到了以下结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/7392d569-17d1-45d7-8300-ec9aab4cc490.png)

我们的应用程序刚刚加载，等待用户选择国家

如果用户触摸`<Picker>`元素，将显示一个弹出窗口，列出从我们的 Node 服务器接收到的国家，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d9ed4754-6e5a-417c-a381-c5a689ab6f14.png)

在触摸国家列表时，将显示一个弹出窗口，以便用户选择所需的国家。

当用户实际点击一个国家时，将触发`onValueChange`事件，并在调用服务器后显示区域列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d672fec4-b9a2-4230-b132-7e844a4e3bcb.png)

选择一个国家后，它的区域列表将显示出来，就像我们之前的 HTML React 版本一样

一切都很顺利，并且正在使用原生组件；太棒了！顺便说一句，如果你对我们描述的`selectedValue`问题不太确定，只需省略该属性，当用户选择一个国家时，你将得到一个糟糕的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/11023a1c-172f-4a30-b5ed-70782c1722d7.png)

有一些差异，比如需要存在`selectedValue`属性，否则当前选择的值

不会更新-即使选择了巴西，选择器也不会显示它

在这里，我们通过一个编写 RN 代码的示例，正如我们所看到的，它与简单的`React`代码并没有太大不同，除了我们不能使用 HTML 之外，我们必须依赖不同的元素。

我们已经看到了两种运行我们代码的方式：使用我们的移动设备上的`Expo`客户端，以及在我们的计算机上使用模拟器。要尝试 RN，你可能想看看一些在线游乐场，比如 Snack，[`snack.expo.io/`](https://snack.expo.io/)，[以及`Repl.it`，在](https://snack.expo.io/)[`repl.it/languages/react_native`](https://repl.it/languages/react_native)。在这两种环境中，你可以创建文件，编辑代码，并在线查看你的实验结果。

# 还有更多...

在让你的应用程序运行后的最后一步是创建一个独立的软件包，最好可以通过苹果和谷歌应用商店进行分发。如果你手动创建了你的应用程序，那么这个过程可能会变得有点复杂，你甚至需要一台真正的 macOS 电脑，因为否则你将无法为 iOS 构建：你将不得不阅读如何使用`Xcode`或 Android 开发者工具来制作应用程序，这可能有点复杂。相反，使用 CRAN 应用程序，这个过程可以简化，因为`Expo`提供了一个应用程序构建功能，这样你就不必自己构建。查看[`docs.expo.io/versions/latest/guides/building-standalone-apps.html`](https://docs.expo.io/versions/latest/guides/building-standalone-apps.html)获取具体的说明。

无论你决定如何进行构建过程，都要查看一些建议，以确保你的应用程序将被批准并受到良好的接待。[`docs.expo.io/versions/latest/guides/app-stores.html`](https://docs.expo.io/versions/latest/guides/app-stores.html)。

# 适应设备和方向

当我们在第七章的*增强您的应用程序*中开发了一个响应式和自适应的网页时，我们必须处理窗口大小可能随时改变的可能性，我们的页面内容必须正确地重新定位自己。对于移动设备，屏幕尺寸不会改变，但仍然有可能旋转（从纵向模式到横向模式，反之亦然），因此您仍然必须处理至少一个变化。当然，如果您希望使您的应用程序在所有设备上看起来很好，那么您可能需要考虑屏幕尺寸，以决定如何容纳您的内容。

在这个示例中，我们将介绍一种简单的技术，使您的应用程序能够识别不同的设备类型。这种技术可以很容易地升级，以覆盖特定的屏幕尺寸。

我们稍后将更多地关注样式；目前，我们将专注于让应用程序识别设备类型和方向，然后在下一节中，我们将提供具体的样式示例。

# 如何做...

如果我们希望我们的应用程序适应，我们必须能够在我们的代码中回答几个问题：

+   我们如何知道设备是平板还是手机？

+   我们如何了解它是纵向模式还是横向模式？

+   我们如何编写一个组件，根据设备类型的不同进行不同的渲染？

+   我们如何使一个组件在屏幕方向改变时自动重绘？

现在让我们来讨论所有这些问题。让我们首先看看我们如何了解设备类型和方向。RN 包括一个 API，`Dimensions`，它提供了渲染应用程序所需的屏幕尺寸等数据。那么，我们如何了解设备类型和方向呢？第二个问题更容易：因为没有正方形设备（至少目前没有！），只需查看两个尺寸中哪个更大-如果高度更大，则设备处于纵向模式，否则设备处于横向模式。

然而，第一个问题更难。在屏幕尺寸方面，没有严格的规定来界定手机的结束和平板的开始，但是如果我们查看设备信息并计算形态因子（最长边与最短边的比率），一个简单的规则就出现了：如果计算出的比率为 1.6 或以下，则更可能是平板电脑，而更高的比率则表明是手机。

如果您需要更具体的数据，请查看[`iosres.com/`](http://iosres.com)获取有关 iOS 设备的信息，或查看[`material.io/tools/devices`](https://material.io/tools/devices)和[`screensiz.es`](http://screensiz.es)获取更多设备的信息，特别是用于 Android 的设备，其屏幕尺寸种类更多。

使用以下代码，我们基本上返回了`Dimensions`提供的所有信息，以及一些属性（`.isTablet`和`.isPortrait`）以简化编码：

```js
// Source file: src/adaptiveApp/device.js

/* @flow */

import { Dimensions } from "react-native";

export type deviceDataType = {
    isTablet: boolean,
    isPortrait: boolean,
    height: number,
    width: number,
    scale: number,
    fontScale: number
};

export const getDeviceData = (): deviceDataType => {
    const { height, width, scale, fontScale } = Dimensions.get("screen");

    return {
 isTablet: Math.max(height, width) / Math.min(height, width) <= 1.6,
 isPortrait: height > width,
        height,
        width,
        scale,
        fontScale
    };
};
```

使用上述代码，我们拥有了绘制适合所有设备、尺寸和两种可能方向的视图所需的一切，但我们如何使用这些数据呢？现在让我们来看看这一点，并使我们的应用程序在所有情况下都能适当调整。

有关`Dimensions` API 的更多信息，请阅读[`facebook.github.io/react-native/docs/dimensions`](https://facebook.github.io/react-native/docs/dimensions)。

我们可以直接在组件中使用`getDeviceData()`提供的信息，但这会带来一些问题：

+   因为它们在函数中有一个隐藏的依赖，所以组件将不像以前那样功能强大

+   因此，测试组件将变得更加困难，因为我们必须模拟该函数

+   最重要的是，当方向改变时，设置组件自动重新渲染将不会那么容易

解决这一切的方法很简单：让我们将设备数据放入存储中，然后相关组件（需要改变渲染方式的组件）可以连接到数据。我们可以创建一个简单的组件来实现这一点：

```js
// Source file: src/adaptiveApp/deviceHandler.component.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";
import { View } from "react-native";

class DeviceHandler extends React.PureComponent<{
    setDevice: () => any
}> {
    static propTypes = {
        setDevice: PropTypes.func.isRequired
    };

    onLayoutHandler = () => this.props.setDevice();

    render() {
 return <View hidden onLayout={this.onLayoutHandler} />;
    }
}

export { DeviceHandler };
```

该组件不会显示在屏幕上，因此我们可以将其添加到我们的主视图中的任何位置。连接组件是另一个必要的步骤；当 `onLayout` 事件触发时（意味着设备的方向已经改变），我们将不得不调度一个动作：

```js
// Source file: src/adaptiveApp/deviceHandler.connected.js

/* @flow */

import { connect } from "react-redux";

import { DeviceHandler } from "./deviceHandler.component";
import { setDevice } from "./actions";

const getDispatch = dispatch => ({
 setDevice: () => dispatch(setDevice())
});

export const ConnectedDeviceHandler = connect(
    null,
    getDispatch
)(DeviceHandler);
```

当然，我们需要定义动作和减速器，以及存储。让我们看看如何做到这一点——我们将从动作开始。除了我们假设的应用程序需要的其他动作之外，我们至少需要以下内容：

```js
// Source file: src/adaptiveApp/actions.js

/* @flow */

import { getDeviceData } from "./device";

import type { deviceDataType } from "./device"

export const DEVICE_DATA = "device:data";

export type deviceDataAction = {
    type: string,
    deviceData: deviceDataType
};

export const setDevice = (deviceData?: object) =>
 ({
 type: DEVICE_DATA,
 deviceData: deviceData || getDeviceData()
 }: deviceDataAction); /* *A real app would have many more actions!*
*/
```

我们正在导出一个 thunk，其中将包含 `deviceData`。请注意，通过允许它作为参数提供（或者使用默认值，由 `getDeviceData()` 创建），我们将简化测试；如果我们想模拟横向平板电脑，我们只需提供一个适当的 `deviceData` 对象。

最后，减速器将如下所示（显然，对于真实的应用程序，将会有更多的动作！）：

```js
// Source file: src/adaptiveApp/reducer.js

/* @flow */

import { getDeviceData } from "./device";

import { DEVICE_DATA } from "./actions";

import type { deviceAction } from "./actions";

export const reducer = (
    state: object = {
        // initial state: more app data, plus:
 deviceData: getDeviceData()
    },
    action: deviceAction
) => {
    switch (action.type) {
 case DEVICE_DATA:
 return {
 ...state,
 deviceData: action.deviceData
 };

        /*
  *          In a real app, here there would*
 *be plenty more "case"s*
        */

        default:
            return state;
    }
};
```

现在，我们在存储中有了设备信息，我们可以研究如何编写自适应、响应式的组件。

我们可以通过使用一个非常基本的组件来看如何编写自适应和响应式组件，该组件只是显示它是手机还是平板电脑，以及它当前的方向。拥有所有 `deviceData` 对象的访问权限意味着我们可以做出任何决定：显示什么、显示多少元素、使它们的大小如何等等。我们将使这个示例简短，但应该清楚如何扩展它：

```js
// Source file: src/adaptiveApp/adaptiveView.component.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";
import { View, Text, StyleSheet } from "react-native";

import type { deviceDataType } from "./device";

const textStyle = StyleSheet.create({
    bigText: {
        fontWeight: "bold",
        fontSize: 24
    }
});

export class AdaptiveView extends React.PureComponent<{
    deviceData: deviceDataType
}> {
 static propTypes = {
 deviceData: PropTypes.object.isRequired
 };

 renderHandset() {
        return (
            <View>
                <Text style={textStyle.bigText}>
                    I believe I am a HANDSET currently in
                    {this.props.deviceData.isPortrait
                        ? " PORTRAIT "
                        : " LANDSCAPE "}
                    orientation
                </Text>
            </View>
        );
    }

 renderTablet() {
        return (
            <View>
                <Text style={textStyle.bigText}>
                    I think I am a
                    {this.props.deviceData.isPortrait
                        ? " PORTRAIT "
                        : " LANDSCAPE "}
                    TABLET
                </Text>
            </View>
        );
    }

 render() {
 return this.props.deviceData.isTablet
 ? this.renderTablet()
 : this.renderHandset();
 }
}
```

不要担心 `textStyle` 的定义——很快我们将介绍它的工作原理，但现在我认为接受它定义了粗体、较大的文本应该很容易。

给定 `this.props.deviceData`，我们可以使用 `.isTablet` 属性来决定调用哪个方法（`.renderTablet()` 或 `.renderHandset()`）。在这些方法中，我们可以使用 `.isPortrait` 来决定使用什么布局：竖屏或横屏。最后——虽然我们在示例中没有显示这一点——我们可以使用 `.width` 或 `.height` 来显示更多或更少的组件，或计算组件的大小等等。我们只需要将组件连接到存储，如下所示，就可以了：

```js
// Source file: src/adaptiveApp/adaptiveView.connected.js

/* @flow */

import { connect } from "react-redux";

import { AdaptiveView } from "./adaptiveView.component";

const getProps = state => ({
 deviceData: state.deviceData
});

export const ConnectedAdaptiveView = connect(getProps)(AdaptiveView);
```

现在我们已经拥有了一切需要的东西，让我们看看它是如何工作的！

# 工作原理...

我们已经准备了一个（隐藏的）组件，通过调度一个动作来响应方向的变化以更新存储，我们知道如何编写一个将使用设备信息的组件。我们的主页面可能如下所示：

```js
// Source file: src/adaptiveApp/main.js

/* @flow */

import React from "react";
import { View, StatusBar } from "react-native";

import { ConnectedAdaptiveView } from "./adaptiveView.connected";
import { ConnectedDeviceHandler } from "./deviceHandler.connected";

export class Main extends React.PureComponent<> {
    render() {
        return (
            <View>
                <StatusBar hidden />
 <ConnectedDeviceHandler />
 <ConnectedAdaptiveView />
            </View>
        );
    }
}
```

如果我在（模拟的）Nexus 5 设备上以竖屏模式运行应用程序，我们会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/462a6b6b-3240-49e7-a2eb-49262cd0bed7.png)

我们的设备被识别为一个手机，目前是竖屏（垂直）方向

旋转设备会产生不同的视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/5cabcc8a-cf15-49ce-86e2-0874fd81e69c.png)

当方向改变时，存储会更新，应用程序会适当地重新渲染自己

在我们的设计中，组件从不自己使用 `Dimension` API——因为它们从存储中获取设备信息，所以可以在功能上测试不同设备和方向下的组件行为，而无需模拟任何东西。

# 还有更多...

```js
ESLint react/require-render-return rule to make .render() not to return anything:
```

```js
import React from "react";
import PropTypes from "prop-types";

// eslint-disable-next-line react/require-render-return
class SomethingBase extends React.PureComponent<{
    deviceData: deviceDataType
}> {
    static propTypes = {
        deviceData: PropTypes.object.isRequired
    };

    render() {
 throw new Error("MUST IMPLEMENT ABSTRACT render() METHOD");
 }
}

export { SomethingBase };
```

为了继续，编写单独的 `something.handset.js` 和 `something.tablet.js` 文件，这些文件扩展 `SomethingBase` 来定义 `SomethingHandset` 和 `SomethingTablet` 组件。最后，设置 `something.component.js` 文件，用于检查设备是手机还是平板，并返回 `<SomethingHandset>` 组件或 `<SomethingTablet>` 组件：

```js
import { SomethingTablet } from "./something.tablet";
import { SomethingHandset } from "./something.handset";
import { getDeviceData } from "./device";

export const Something = getDeviceData().isTablet ? SomethingTablet : SomethingHandset;
```

使用这种样式，您可以在代码中使用和连接 `<Something>` 组件，而在内部，它们实际上是当前设备类型的适当版本。

在计算机科学术语中，这被称为*工厂*设计模式，您可以在不实际指定其类的情况下创建对象。

# 样式和布局组件

将 CSS 样式应用到您的应用程序并不困难，但是与 HTML 相比，您将不得不放弃并重新学习一些概念，这些概念在 RN 中与 HTML 中的概念完全不同：

+   在网页中，CSS 样式是全局的，适用于所有标签；在 RN 中，样式是在组件之间局部完成的；没有全局样式。此外，您不需要*选择器*，因为样式直接与组件相关联。

+   没有样式的继承：在 HTML 中，子元素默认继承其父元素的一些样式，但在 RN 中，如果您希望发生这种情况，您将不得不为子元素提供特定的所需样式。但是，如果您希望，您可以`export`样式并在其他地方`import`它们。

+   RN 样式完全是动态的：您可以使用所有 JS 函数来计算您希望应用的任何值。您甚至可以动态更改样式，因此应用程序的背景颜色可以在白天变得更浅，随着时间的推移逐渐变暗。您不需要像 SASS 或 LESS 那样的东西；您可以进行数学计算并使用常量，因为这是纯 JS。

还有一些其他细微的差异：

+   RN 使用*驼峰命名*风格（例如`fontFamily`）而不是 CSS 的*kebab-case*风格（例如`font-family`）；这很容易适应。此外，并非所有通常的 CSS 属性都可能存在（这取决于特定组件），有些可能受到其可能值的限制。

+   RN 只有两种可能的测量单位：百分比或**密度无关像素**（**DP**）。DP 不是来自 Web 的经典屏幕像素；相反，它们适用于每种设备，独立于其像素密度或**每英寸像素**（**ppi**），从而确保所有屏幕具有统一的外观。

+   布局使用 flex 完成，因此定位元素更简单。您可能没有网页可用的所有选项集，但您获得的对于任何类型的布局来说绝对足够。

关于 RN 中的样式有很多内容可供阅读（首先，请参阅[`facebook.github.io/react-native/docs/style`](https://facebook.github.io/react-native/docs/style)进行介绍，以及[`facebook.github.io/react-native/docs/height-and-width`](https://facebook.github.io/react-native/docs/height-and-width)和[`facebook.github.io/react-native/docs/flexbox`](https://facebook.github.io/react-native/docs/flexbox)进行元素的大小和定位），因此，在这里，我们将通过为我们的国家和地区应用程序设置一些具体的示例来查看一些内容。

# 如何做...

让我们尝试稍微增强我们的应用程序。并且，为了完成我们之前看到的关于自适应和响应式显示的内容，我们将为纵向和横向方向提供不同的布局。我们不需要媒体查询或基于列的布局；我们将使用简单的样式。

让我们从为`<Main>`组件创建样式开始。我们将使用我们之前开发的`<DeviceHandler>`；两个组件都将连接到存储。我不想为平板电脑和手机制作特定版本，但我想在纵向和横向方向上显示不同的布局。对于前者，我基本上使用了我之前开发的内容，但对于后者，我决定将屏幕一分为二，在左侧显示国家选择器，右侧显示地区列表。哦，您可能会注意到我选择使用内联样式，即使这不是首选选项；由于组件通常很短，您可以在 JSX 代码中直接放置样式而不会失去清晰度。这取决于您是否喜欢：

```js
// Source file: src/regionsStyledApp/main.component.js

/* @flow */

import React from "react";
import { View, StatusBar } from "react-native";

import {
    ConnectedCountrySelect,
    ConnectedRegionsTable,
    ConnectedDeviceHandler
} from ".";
import type { deviceDataType } from "./device";

 export class Main extends React.PureComponent<{
    deviceData: deviceDataType
}> {
    render() {
 **if (this.props.deviceData.isPortrait) {** .
            . *// portrait view*
            .
 **} else {**            .
            . *// landscape view*
            .
        }
    }
}
```

**当设备处于纵向方向时，我创建了一个占据整个屏幕的`<View>`（`flex:1`），并使用`flexDirection:"column"`垂直设置其组件，尽管这实际上是默认值，所以我可以省略这一步。我没有为`<CountrySelect>`组件指定大小，但我设置了`<RegionsTable>`以占据所有可能的（剩余的）空间。详细代码如下：

```js
// Source file: src/regionsStyledApp/main.component.js

            return (
 <View style={{ flex: 1 }}>
                    <StatusBar hidden />
                    <ConnectedDeviceHandler />
 <View style={{ flex: 1, flexDirection: "column" }}>
                        <View>
                            <ConnectedCountrySelect />
                        </View>
 <View style={{ flex: 1 }}>
                            <ConnectedRegionsTable />
                        </View>
                    </View>
                </View>
            );
```

对于横向方向，需要进行一些更改。我将主视图的内容方向设置为水平（`flexDirection:"row"`），并在其中添加了两个大小相同的视图。对于第一个国家列表，我将其内容设置为垂直并居中，因为我认为这样看起来更好，而不是出现在顶部。对于占据屏幕右侧的地区列表，我没有做任何特别的事情。

```js
// Source file: src/regionsStyledApp/main.component.js

            return (
 <View style={{ flex: 1 }}>
                    <StatusBar hidden />
                    <ConnectedDeviceHandler />
 <View style={{ flex: 1, flexDirection: "row" }}>
                        <View
 style={{
 flex: 1,
 flexDirection: "column",
 justifyContent: "center"
 }}
                        >
                            <ConnectedCountrySelect />
                        </View>
 <View style={{ flex: 1 }}>
                            <ConnectedRegionsTable />
                        </View>
                    </View>
                </View>
            );
```

如果要使组件占据更大的空间，增加其 flex 值；*flex*意味着组件将根据可用空间灵活地扩展或收缩，这些空间按照它们的 flex 值的直接比例共享。如果我想要国家列表占据屏幕的三分之一，将其他两分之一留给地区列表，我会为其设置`flex:1`，并为地区列表设置`flex:2`。当然，您也可以直接设置高度和宽度（无论是 DIP 值还是百分比），就像您在 CSS 中所做的那样。

除了`"center"`之外，如果您想要在视图中分配子组件，还有其他几个选项：

+   `"flex-start"`将它们放在一起，放在父视图的开始位置；在这里，是顶部，因为是垂直对齐的

+   `"flex-end"`的行为类似，但将子组件放置在父视图的末尾（这里是底部）

+   `"space-between"`在子组件之间均匀分割额外的空间

+   `"space-around"`也均匀分割额外的空间，但包括父视图开头和结尾的空间

+   `"space-evenly"`在子组件和分隔空间之间均匀分割所有空间

设置主要的 flex 方向后，您可以使用`alignItems`来指定子组件沿着次要的 flex 方向对齐的方式（如果`flexDirection`是`"row"`，那么次要方向将是`"column"`，反之亦然）。可能的值是`"flex-start"`，`"center"`和`"flex-end"`，意思与刚才给出的类似，或者您可以使用`"stretch"`，它将占据所有可能的空间。

如果您想尝试这些选项，请访问[`facebook.github.io/react-native/docs/flexbox`](https://facebook.github.io/react-native/docs/flexbox)并修改代码示例。您将立即看到您的更改的效果，这是理解每个选项的效果和影响的最简单方法。

现在，让我们来设置地区表的样式。为此，我需要进行一些更改，首先是需要使用`<ScrollView>`而不是普通的`<View>`，因为列表可能太长而无法适应屏幕。另外，为了展示一些样式和常量，我决定使用单独的样式文件。我首先创建了一个`styleConstants.js`文件，其中定义了一个颜色常量和一个简单的全尺寸样式：

```js
// Source file: src/regionsStyledApp/styleConstants.js

/* @flow */

import { StyleSheet } from "react-native";

export const styles = StyleSheet.create({
    fullSize: {
        flex: 1
    }
});

export const lowColor = "lightgray";
```

这里有趣的地方，不是（假定相当简陋的）`fullSize`样式，而是您可以导出样式，或者定义将在其他地方使用的简单 JS 常量。在地区列表中，我导入了样式和颜色：

```js
// Source file: src/regionsStyledApp/regionsTable.component.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";
import { View, ScrollView, Text, StyleSheet } from "react-native";

import type { deviceDataType } from "./device";

import { lowColor, fullSizeStyle } from "./styleConstants";

const ownStyle = StyleSheet.create({
 grayish: {
 backgroundColor: lowColor
 }
});

export class RegionsTable extends React.PureComponent<{
    deviceData: deviceDataType,
    list: Array<{
        regionCode: string,
        regionName: string
    }>
}> {
    static propTypes = {
        deviceData: PropTypes.object.isRequired,
        list: PropTypes.arrayOf(PropTypes.object).isRequired
    };

    static defaultProps = {
        list: []
    };

    render() {
        if (this.props.list.length === 0) {
            return (
 <View style={ownStyle.fullSize}>
                    <Text>No regions.</Text>
                </View>
            );
        } else {
            const ordered = [...this.props.list].sort(
                (a, b) => (a.regionName < b.regionName ? -1 : 1)
            );

            return (
                <ScrollView style={[fullSizeStyle, ownStyle.grayish]}>
                    {ordered.map(x => (
                        <View key={`${x.countryCode}-${x.regionCode}`}>
                            <Text>{x.regionName}</Text>
                        </View>
                    ))}
                </ScrollView>
            );
        }
    }
}
```

在上述代码块中有一些有趣的细节：

+   正如我之前所说，我使用了`<ScrollView>`组件，以便用户可以浏览超出可用空间的列表。`<FlatList>`组件也是一种可能，尽管对于这里相对较短和简单的列表来说，它不会有太大的区别。

+   我使用导入的颜色创建了一个本地样式`grayish`，稍后我会用到。

+   我直接将导入的`fullSize`样式应用到了区域的`<ScrollView>`上。

+   我给第二个`<ScrollView>`应用了多个样式；如果你提供一个样式数组，它们会按照出现的顺序应用。在这种情况下，我得到了一个全尺寸的灰色区域。请注意，只有在存在一些区域时颜色才会被应用；否则颜色不会改变。

请注意，样式可以动态创建，这可以产生有趣的效果。举个例子，基于 RN 文档中的一个例子，你可以根据 prop 改变标题的样式。在下面的代码中，标题的样式会根据`this.props.isActive`的值而改变：

```js
<View>
    <Text
        style={[
            styles.title,
 this.props.isActive
 ? styles.activeTitle
 : styles.inactiveTitle
        ]}
    >
        {this.props.mainTitle}
    </Text>
</View>
```

你可以产生更有趣的结果；记住你可以充分利用 JS 的全部功能，并且样式表可以动态创建，所以你实际上有无限的可能性。

# 它是如何工作的...

我启动了模拟器，尝试了一下代码。在纵向方向时，视图如下截图所示；请注意我向下滚动了，应用程序正确处理了它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/ba75c98a-231f-48d8-b764-6aeb7e902262.png)

我们的样式化应用程序，显示颜色、样式和可滚动视图

如果你改变设备的方向，我们的设备处理逻辑会捕获事件，并且应用程序会以不同的方式呈现。在这里，我们可以看到分屏，左边是居中的元素，右边是可滚动的视图，有灰色的背景：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/959d3015-b0a8-474d-84f6-8ea1f452c282.png)

横向视图得到了不同的布局，这要归功于新的样式规则

我们已经看到了——这只是 RN 提供的许多样式特性的简介，你可以获得与 HTML 和 CSS 相同类型的结果，尽管在这里你确实在使用不同的元素和样式。应用 JS 的全部功能来定义样式的可能性让你不再需要使用诸如 SASS 之类的工具，因为它所带来的所有额外功能已经通过 JS 本身可用。让我们看一个更进一步的样式示例，这次是针对文本的，因为我们考虑如何编写专门针对特定平台的代码。

# 添加特定于平台的代码

使用通用组件对大多数开发来说已经足够了，但你可能想利用一些特定于平台的功能，RN 提供了一种方法来实现这一点。显然，如果你开始沿着这个趋势发展，你可能会面临更大的工作量，并且更难维护你的代码，但如果明智地进行，它可以为你的应用增添一些额外的*亮点*。

在这个示例中，我们将看看如何调整你的应用，使其更适合在任何平台上运行。

# 如何做...

识别你的平台最简单的方法是使用`Platform`模块，其中包括一个属性`Platform.OS`，告诉你当前是在 Android 还是 iOS 上运行。让我们来看一个简单的例子。假设你想在你的应用中使用一些等宽字体。恰好在不同平台上，相关字体系列的名称不同：在 Android 上是`"monospace"`，而在苹果设备上是`"AmericanTypewriter"`（等等）。通过检查`Platform.OS`，我们可以适当地设置样式表的`.fontFamily`属性，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/9d66a972-1aa4-4898-b9af-64b582ac2352.png)

使用`Platform.OS`是检测设备平台的最简单方法

如果你想要不同地选择几个属性，你可能想使用`Platform.select()`：

```js
const headings = Platform.select({
    android: { title: "An Android App", subtitle: "directly from Google" },
    ios: { title: "A iOS APP", subtitle: "directly from Apple" }
});
```

在这种情况下，`headings.title`和`headings.subtitle`将获得适合当前平台的值，无论是 Android 还是 iOS。显然，你可以使用`Platform.OS`来管理这个，但这种样式可能更简洁。

有关 Android 和 iOS 设备上可用字体系列的更多信息，您可以查看[`github.com/react-native-training/react-native-fonts`](https://github.com/react-native-training/react-native-fonts)上的列表。但是，请注意，列表可能会随着版本的变化而改变。

# 它是如何工作的...

为了多样化，我决定在 Snack（在本章前面提到过的[`snack.expo.io/`](https://snack.expo.io/)）中尝试平台检测，因为这比在两台实际设备上运行代码要快得多，也更简单。

我打开了页面，在提供的示例应用程序中，我只是添加了我之前展示的`.fontFamily`更改，并测试了两个平台的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/4aeb80e4-59cd-4d07-8983-a1120078b60d.png)

Snack 模拟器显示了我的应用程序的不同外观，Android（左）和 iOS（右）具有不同的字体

正如我们所看到的，平台差异的问题可以很容易地解决，您的应用程序的最终用户将获得更符合其对颜色、字体、组件、API 等方面期望的东西。

# 还有更多...

我们在这个示例中看到的变化范围相当小。如果您想要一些更大的差异，比如，例如，使用`DatePickerIOS`组件在 iOS 上获取日期，但在 Android 上使用`DatePickerAndroid` API，那么还有另一个功能您应该考虑。

假设您自己的组件名为`AppropriateDatePicker`。如果您分别创建名为`appropriateDatePicker.component.ios.js`和`appropriateDatePicker.component.android.js`的两个文件，那么当您使用`import { AppropriateDatePicker } from "AppropriateDatePicker"`导入您的组件时，`.ios.js`版本将用于苹果设备，`.android.js`版本将用于安卓设备：简单！

有关`Platform`模块和特定于平台的选项的完整描述，请阅读[`facebook.github.io/react-native/docs/platform-specific-code`](https://facebook.github.io/react-native/docs/platform-specific-code)。

# 路由和导航

使用`React`路由器，您只需使用`<Link>`组件从一个页面导航到另一个页面，或者使用方法以编程方式打开不同的页面。在 RN 中，有一种不同的工作方式，`react-navigation`包实际上是事实上的标准。在这里，您定义一个导航器（有几种可供选择），并为其提供应该处理的屏幕（视图），然后忘记它！导航器将自行处理一切，显示和隐藏屏幕，添加选项卡或滑动抽屉，或者其他任何需要的功能，您不必做任何额外的工作！

在这个示例中，我们将重新访问本书前面页面的一个示例，并展示路由的不同写法，以突出风格上的差异。

导航比我们在这里看到的更多。查看[`reactnavigation.org/docs/en/api-reference.html`](https://reactnavigation.org/docs/en/api-reference.html)上的 API 文档以获取更多信息，如果您在 Google 上搜索，请注意，因为`react-navigation`包已经发展，许多网站引用了当前已弃用的旧方法。

# 如何做到...

在本书的`React`部分，我们构建了一个完整的路由解决方案，包括公共和受保护的路由，使用登录视图输入用户的用户名和密码。在移动应用程序中，由于用户受到更多限制，我们可以在开始时启用登录，并在之后启用正常导航。所有与用户名、密码和令牌相关的工作基本上与以前相同，所以现在让我们只关注在 RN 中不同的导航，并忘记常见的细节。

首先，让我们有一些视图——一个带有一些居中文本的空屏幕就可以了：

```js
// Source file: src/routingApp/screens.js

/* @flow */

import React, { Component } from "react";
import {
    Button,
    Image,
    StyleSheet,
    Text,
    TouchableOpacity,
    View
} from "react-native";

const myStyles = StyleSheet.create({
    fullSize: {
        flex: 1
    },
    fullCenteredView: {
        flex: 1,
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center"
    },
    bigText: {
        fontSize: 24,
        fontWeight: "bold"
    },
    hamburger: {
        width: 22,
        height: 22,
        alignSelf: "flex-end"
    }
});

// *continues...*
```

然后，为了简化创建所有所需的视图，让我们有一个`makeSimpleView()`函数，它将生成一个组件。我们将在右上角包括一个*汉堡*图标，它将打开和关闭导航抽屉；稍后我们会详细了解。我们将使用这个函数来创建大多数视图，并添加一个`SomeJumps`额外视图，其中包含三个按钮，允许您直接导航到另一个视图：

```js
// ...*continued*

const makeSimpleView = text =>
    class extends Component<{ navigation: object }> {
        displayName = `View:${text}`;

        render() {
            return (
                <View style={myStyles.fullSize}>
 <TouchableOpacity
 onPress={this.props.navigation.toggleDrawer}
 >
 <Image
 source={require("./hamburger.png")}
 style={myStyles.hamburger}
 />
 </TouchableOpacity>
                    <View style={myStyles.fullCenteredView}>
                        <Text style={myStyles.bigText}>{text}</Text>
                    </View>
                </View>
            );
        }
    };

export const Home = makeSimpleView("Home");
export const Alpha = makeSimpleView("Alpha");
export const Bravo = makeSimpleView("Bravo");
export const Charlie = makeSimpleView("Charlie");
export const Zulu = makeSimpleView("Zulu");
export const Help = makeSimpleView("Help!");

export const SomeJumps = (props: object) => (
    <View style={myStyles.fullSize}>
 <Button
 onPress={() => props.navigation.navigate("Alpha")}
 title="Go to Alpha"
 />
 <Button
 onPress={() => props.navigation.navigate("Bravo")}
 title="Leap to Bravo"
 />
 <Button
 onPress={() => props.navigation.navigate("Charlie")}
 title="Jump to Charlie"
 />
    </View>
);
```

在这里，为了简单起见，鉴于我们没有使用 props 或 state，并且视图足够简单，我使用了`SomeJumps`组件的函数定义，而不是使用类，就像大多数其他示例一样。如果您想重新访问这个概念，请查看[`reactjs.org/docs/components-and-props.html`](https://reactjs.org/docs/components-and-props.html)。

`navigation`属性来自哪里？我们将在下一节中看到更多，但这里可以给出一些解释。每当您创建一个导航器，您都会为其提供一组视图来处理。所有这些视图都将获得一个额外的属性`navigation`，它具有一组您可以使用的方法，例如切换抽屉的可见性，导航到给定屏幕等。在[`reactnavigation.org/docs/en/navigation-prop.html`](https://reactnavigation.org/docs/en/navigation-prop.html)上阅读有关此对象的信息。

现在，让我们创建抽屉本身。这将处理侧边栏菜单并显示所需的任何视图。`createDrawerNavigator()`函数获取一个包含将要处理的屏幕的对象，以及一组选项；在这里，我们只指定了抽屉本身的颜色和宽度（还有很多可能性，详细信息请参阅[`reactnavigation.org/docs/en/drawer-navigator.html`](https://reactnavigation.org/docs/en/drawer-navigator.html)）：

```js
// Source file: src/routingApp/drawer.js

/* @flow */

import { createDrawerNavigator } from "react-navigation";

import {
    Home,
    Alpha,
    Bravo,
    Charlie,
    Zulu,
    Help,
    SomeJumps
} from "./screens";

export const MyDrawer = createDrawerNavigator(
    {
        Home: { screen: Home },
        Alpha: { screen: Alpha },
        Bravo: { screen: Bravo },
        Charlie: { screen: Charlie },
        Zulu: { screen: Zulu },
        ["Get Help"]: { screen: Help },
        ["Some jumps"]: { screen: SomeJumps }
    },
    {
 drawerBackgroundColor: "lightcyan",
 drawerWidth: 140
    }
);
```

`createDrawerNavigation()`的结果本身是一个组件，它将负责显示所选的任何视图，显示和隐藏抽屉菜单等。我们只需要创建主应用程序本身。

接下来，让我们创建可导航的应用程序，因为我们现在有一组视图和一个抽屉导航器来处理它们。我们应用程序的主视图非常简单-查看它的`.render()`方法，你会同意的：

```js
// Source file: App.routing.js

/* @flow */

import React from "react";
import { StatusBar } from "react-native";

import { MyDrawer } from "./src/routingApp/drawer";

class App extends React.Component {
    render() {
        return (
            <React.Fragment>
 <StatusBar hidden />
 <MyDrawer />
            </React.Fragment>
        );
    }
}

export default App;
```

有趣的一点是：由于导航器是组件。如果您愿意，您可以在另一个导航器中包含一个导航器！例如，您可以创建一个`TabNavigator`，并将其包含在抽屉导航器中：当选择相应选项时，您将在屏幕上获得一个选项卡视图，现在由选项卡导航器管理。如果您愿意，您可以以任何希望的方式组合导航器，从而允许非常复杂的导航结构。

# 它是如何工作的...

当您打开应用程序时，将显示初始路由。您可以提供多个选项，例如`initialRouteName`来指定应该显示的第一个视图，`order`来重新排列抽屉项，甚至自定义`contentComponent`如果您想自己绘制抽屉的内容；总而言之，有很多灵活性。您的第一个屏幕应该看起来像下面的样子：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/bc4eddab-0191-4acb-95df-cd124a814ce0.png)

我们的抽屉导航器显示初始屏幕

通常打开抽屉的方式是从左边滑动（尽管也可以设置抽屉从右边滑动）。我们还提供了汉堡图标来切换抽屉的打开和关闭。打开抽屉应该看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/16b3cbf8-1530-4245-b496-879b07e55249.png)

打开的抽屉显示菜单，当前屏幕突出显示，其余屏幕变暗。

单击任何菜单项将隐藏当前视图，并显示所选视图。例如，我们可以选择`Some jumps`屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/afb528b3-850d-4d6f-a81f-28ff8bf36299.png)

选择选项后，抽屉菜单会自动关闭，并显示所选屏幕

在这个特定的屏幕中，我们展示了三个按钮，它们都使用`props.navigation.navigate()`方法来显示不同的屏幕。这表明你的导航不仅限于使用抽屉，而且你也可以以任何你想要的方式直接浏览。

# 还有更多……

在`React`章节中我们没有提到`Redux`，你可能已经注意到了。虽然使用它是可能的，但`react-navigation`的作者们倾向于*不*启用它，在[`reactnavigation.org/docs/en/redux-integration.html`](https://reactnavigation.org/docs/en/redux-integration.html)上你可以读到以下内容：

“警告：在 2018 年秋季发布的 React Navigation 的下一个主要版本中，我们将不再提供任何关于如何与 Redux 集成的信息，它可能会停止工作。在 React Navigation 问题跟踪器上发布的与 Redux 相关的问题将立即关闭。Redux 集成可能会继续工作，但在制定库的任何设计决策时，它将不会被测试或考虑。”

这个警告表明，把空间用于一个可能会突然停止工作的集成并不是一个好主意。如果你想集成`Redux`，请阅读我之前提到的页面，但在更新导航包时要小心，以防止某些功能停止工作。你已经被警告了！**
