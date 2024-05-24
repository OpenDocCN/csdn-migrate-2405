# React17 设计模式最佳实践（四）

> 原文：[`zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F`](https://zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：为了乐趣和利润进行服务器端渲染

构建 React 应用程序的下一步是学习服务器端渲染的工作原理以及它可以给我们带来的好处。**通用应用程序**对于 SEO 更好，并且它们可以在前端和后端之间实现知识共享。它们还可以提高 Web 应用程序的感知速度，通常会导致转化率的提高。然而，将服务器端渲染应用于 React 应用程序是有成本的，我们应该仔细考虑是否需要它。

在本章中，您将看到如何设置服务器端渲染应用程序，并在相关部分结束时，您将能够构建一个通用应用程序，并了解该技术的利弊。

在本章中，我们将涵盖以下主题：

+   理解通用应用程序是什么

+   弄清楚为什么我们可能希望启用服务器端渲染

+   使用 React 创建一个简单的静态服务器端渲染应用程序

+   将数据获取添加到服务器端渲染，并理解脱水/水合等概念

+   使用 Zeith 的**Next.js**轻松创建在服务器端和客户端上运行的 React 应用程序

# 技术要求

完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书籍的 GitHub 存储库中找到本章的代码，网址为[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter09`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter09)。

# 理解通用应用程序

通用应用程序是一种可以在服务器端和客户端上运行相同代码的应用程序。在本节中，我们将看看为什么要考虑使我们的应用程序通用，并学习如何在服务器端轻松渲染 React 组件。

当我们谈论 JavaScript Web 应用程序时，通常会想到存在于浏览器中的客户端代码。它们通常的工作方式是，服务器返回一个空的 HTML 页面，其中包含一个`script`标签来加载应用程序。当应用程序准备就绪时，它会在浏览器内部操作 DOM 以显示 UI 并与用户交互。这已经是过去几年的情况了，对于大量应用程序来说，这仍然是一种行之有效的方式。

在本书中，我们已经看到使用 React 组件创建应用程序是多么容易，以及它们在浏览器中的工作原理。我们还没有看到的是 React 如何在服务器上渲染相同的组件，为我们提供了一个称为**服务器端渲染**（**SSR**）的强大功能。

在深入细节之前，让我们试着理解在服务器和客户端上都渲染应用程序意味着什么。多年来，我们习惯于为服务器和客户端拥有完全不同的应用程序：例如，使用 Django 应用程序在服务器上渲染视图，以及一些 JavaScript 框架，如 Backbone 或 jQuery，在客户端上。这些独立的应用程序通常需要由具有不同技能的两个开发团队进行维护。如果需要在服务器端渲染的页面和客户端应用程序之间共享数据，可以在脚本标签中注入一些变量。使用两种不同的语言和平台，没有办法在应用程序的不同方面共享通用信息，如模型或视图。

自从 Node.js 在 2009 年发布以来，JavaScript 在服务器端也因为诸如**Express**等 Web 应用程序框架而受到了很多关注和流行。在两端使用相同的语言不仅使开发人员可以轻松重用他们的知识，还可以在服务器和客户端之间实现不同的代码共享方式。

特别是在 React 中，同构 Web 应用程序的概念在 JavaScript 社区内非常流行。编写一个**同构应用程序**意味着构建一个在服务器和客户端上看起来相同的应用程序。使用相同的语言编写两个应用程序意味着可以共享大部分逻辑，这开启了许多可能性。这使得代码库更容易理解，并避免不必要的重复。

React 将这个概念推进了一步，为我们提供了一个简单的 API，在服务器上渲染我们的组件，并透明地应用所有必要的逻辑，使页面在浏览器上变得交互（例如，事件处理程序）。

术语*同构*在这种情况下并不适用，因为在 React 的情况下，应用程序是相同的，这就是为什么 React Router 的创始人之一 Michael Jackson 提出了这种模式更有意义的名称：**Universal**。

# 实施 SSR 的原因

SSR 是一个很棒的功能，但我们不应该只是为了它而盲目使用。我们应该有一个真正坚实的理由开始使用它。在本节中，我们将看看 SSR 如何帮助我们的应用程序以及它可以为我们解决什么问题。在接下来的部分中，我们将学习关于 SEO 以及如何提高我们应用程序的性能。

## 实施搜索引擎优化

我们可能希望在服务器端渲染我们的应用程序的一个主要原因是搜索引擎优化（SEO）。

如果我们向主要搜索引擎的网络爬虫提供一个空的 HTML 骨架，它们将无法从中提取任何有意义的信息。如今，Google 似乎能够运行 JavaScript，但存在一些限制，而 SEO 通常是我们业务的关键方面。

多年来，我们习惯于编写两个应用程序：一个用于网络爬虫的 SSR 应用程序，另一个供用户在客户端使用。我们过去这样做是因为 SSR 应用程序无法给我们提供用户期望的交互水平，而客户端应用程序无法被搜索引擎索引。

维护和支持两个应用程序是困难的，使代码库不够灵活，也不够容易更改。幸运的是，有了 React，我们可以在服务器端渲染我们的组件，并以一种易于理解和索引内容的方式为网络爬虫提供我们应用程序的内容。

这不仅对 SEO 有好处，也对社交分享服务有好处。Facebook 或 Twitter 等平台为我们提供了一种定义在页面被分享时显示的片段内容的方式。

例如，使用 Open Graph，我们可以告诉 Facebook，对于特定页面，我们希望显示特定的图片，并使用特定的标题作为帖子的标题。使用仅客户端的应用程序几乎不可能做到这一点，因为从页面中提取信息的引擎使用服务器返回的标记。

如果我们的服务器对所有 URL 返回一个空的 HTML 结构，那么当页面在社交网络上分享时，我们的 Web 应用程序的片段也会是空的，这会影响它们的传播。

## 共同的代码库

我们在客户端没有太多选择；我们的应用程序必须用 JavaScript 编写。有一些语言可以在构建时转换为 JavaScript，但概念并未改变。在服务器端使用相同的语言的能力在维护性和公司内部知识共享方面具有重大优势。

能够在客户端和服务器之间共享逻辑使得在两侧应用任何更改变得容易，而不必做两次工作，这在大多数情况下会导致更少的错误和问题。

维护单一代码库的工作量要少于保持两个不同应用程序最新所需的工作量。你可能考虑在团队中引入服务器端 JavaScript 的另一个原因是前端和后端开发人员之间的知识共享。

在两侧重用代码的能力使得协作更容易，团队使用共同的语言，这有助于更快地做出决策和更改。

## 更好的性能

最后但并非最不重要的是，我们都喜欢客户端应用程序，因为它们快速且响应迅速，但存在一个问题——必须在用户可以在应用程序上采取任何操作之前加载和运行捆绑包。

在现代笔记本电脑或桌面计算机上使用快速互联网连接可能不是问题。然而，如果我们在使用 3G 连接的移动设备上加载一个巨大的 JavaScript 捆绑包，用户必须等待一小段时间才能与应用程序进行交互。这不仅对用户体验不利，而且还会影响转化率。大型电子商务网站已经证明，页面加载时间增加几毫秒可能会对收入产生巨大影响。

例如，如果我们在服务器上用一个空的 HTML 页面和一个`script`标签提供我们的应用程序，并在用户点击任何内容之前向他们显示一个旋转器，那么网站速度的感知性会受到显着影响。

如果我们在服务器端呈现我们的网站，用户在点击页面后立即开始看到一些内容，即使他们在真正做任何事情之前必须等待同样长的时间，他们也更有可能留下来，因为无论如何都必须加载客户端捆绑包。

这种感知性能是我们可以通过使用 SSR 大大改善的，因为我们可以在服务器上输出我们的组件并立即向用户返回一些信息。

## 不要低估复杂性

即使 React 提供了一个简单的 API 来在服务器上渲染组件，创建一个通用应用程序是有成本的。因此，我们应该在启用之前仔细考虑上述原因之一，并检查我们的团队是否准备好支持和维护通用应用程序。

正如我们将在接下来的章节中看到的，渲染组件并不是创建服务器端渲染应用程序所需完成的唯一任务。我们必须设置和维护一个带有其路由和逻辑的服务器，管理服务器数据流等等。潜在地，我们希望缓存内容以更快地提供页面，并执行许多其他任务，这些任务是维护一个完全功能的通用应用程序所必需的。

因此，我的建议是首先构建客户端版本，只有在 Web 应用程序在服务器上完全工作时，您才应该考虑通过启用 SSR 来改善体验。只有在严格必要时才应启用 SSR。例如，如果您需要 SEO 或者需要自定义社交分享信息，您应该开始考虑它。

如果您意识到您的应用程序需要很长时间才能完全加载，并且您已经进行了所有的优化（有关此主题的更多信息，请参阅*第十章*，*改进您的应用程序的性能*），您可以考虑使用 SSR 来为用户提供更好的体验并提高感知速度。现在我们已经了解了什么是 SSR 以及通用应用程序的好处，让我们在下一节中跳入一些 SSR 的基本示例。

# 创建 SSR 的基本示例

现在，我们将创建一个非常简单的服务器端应用程序，以查看构建基本通用设置所需的步骤。这是一个故意简化的设置，因为这里的目标是展示 SSR 的工作原理，而不是提供全面的解决方案或样板，尽管您可以将示例应用程序用作真实应用程序的起点。

本节假设所有关于 JavaScript 构建工具（如 webpack 及其加载程序）的概念都是清楚的，并且需要一点 Node.js 的知识。作为 JavaScript 开发人员，即使您以前从未见过 Node.js 应用程序，也应该很容易跟上本节。

该应用程序将由两部分组成：

+   在服务器端，我们将使用**Express**创建一个基本的 Web 服务器，并为服务器端渲染的 React 应用程序提供一个 HTML 页面

+   在客户端，我们将像往常一样使用`react-dom`渲染应用程序。

在运行之前，应用程序的两侧都将使用 Babel 进行转译，并在运行之前使用 webpack 进行捆绑，这将让我们在 Node.js 和浏览器上都可以使用 ES6 和模块的全部功能。

让我们从创建一个新的项目文件夹开始（您可以称之为`ssr-project`），并运行以下命令来创建一个新的包：

```jsx
npm init
```

创建`package.json`后，是时候安装依赖项了。我们可以从`webpack`开始：

```jsx
npm install webpack
```

完成后，是时候安装`ts-loader`和我们需要使用 React 和 TSX 编写 ES6 应用程序的预设了：

```jsx
npm install --save-dev @babel/core @babel/preset-env @babel/preset-react ts-loader typescript
```

我们还必须安装一个依赖项，这样我们才能创建服务器捆绑包。`webpack`让我们定义一组外部依赖项，这些依赖项我们不想添加到捆绑包中。实际上，在为服务器创建构建时，我们不想将我们使用的所有节点包添加到捆绑包中；我们只想捆绑我们的服务器代码。有一个包可以帮助我们做到这一点，我们可以简单地将其应用到我们的`webpack`配置中的外部条目，以排除所有模块：

```jsx
npm install --save-dev webpack-node-externals
```

太好了。现在是时候在`package.json`的 npm`scripts`部分创建一个条目，这样我们就可以轻松地从终端运行`build`命令了：

```jsx
"scripts": {
  "build": "webpack"
}
```

接下来，您需要在根路径下创建一个`.babelrc`文件：

```jsx
{
  "presets": ["@babel/preset-env", "@babel/preset-react"]
}
```

我们现在必须创建配置文件，名为`webpack.config.js`，以告诉`webpack`我们希望如何捆绑我们的文件。

让我们开始导入我们将用来设置我们的节点外部的库。我们还将为`ts-loader`定义配置，我们将在客户端和服务器端都使用它：

```jsx
const nodeExternals = require('webpack-node-externals')
const path = require('path')

const rules = [{
  test: /\.(tsx|ts)$/,
  use: 'ts-loader',
  exclude: /node_modules/
}]
```

在*第八章*，*使您的组件看起来漂亮*中，我们看到我们必须从配置文件中导出一个配置对象。`webpack`中有一个很酷的功能，它让我们也可以导出一个配置数组，这样我们就可以在同一个地方定义客户端和服务器配置，并同时使用两者。

下面显示的客户端配置应该非常熟悉：

```jsx
const client = {
  entry: './src/client.tsx',
  output: {
    path: path.resolve(__dirname, './dist/public'),
    filename: 'bundle.js',
    publicPath: '/'
  },
  module: {
    rules
  }
}
```

我们告诉`webpack`客户端应用程序的源代码位于`src`文件夹中，并且我们希望生成的输出捆绑包位于`dist`文件夹中。

我们还使用之前使用`ts-loader`创建的对象设置模块加载程序。服务器配置略有不同；我们需要定义不同的`entry`，`output`，并添加一些新的节点，例如`target`，`externals`和`resolve`：

```jsx
const server = {
  entry: './src/server.ts',
  output: {
    path: path.resolve(__dirname, './dist'),
    filename: 'server.js',
    publicPath: '/'
  },
  module: {
    rules
  },
  target: 'node',
  externals: [nodeExternals()],
  resolve: {
    extensions: [".ts", ".tsx", ".js", ".json"],
  },
}
```

正如您所看到的，`entry`，`output`和`module`是相同的，只是文件名不同。

新的参数是`target`，在其中我们指定`node`以告诉`webpack`忽略 Node.js 的所有内置系统包，例如`fs`和`externals`，在其中我们使用我们之前导入的库告诉 webpack 忽略依赖项。

最后，但并非最不重要的，我们必须将配置导出为数组：

```jsx
module.exports = [client, server]
```

配置已经完成。我们现在准备写一些代码，我们将从我们更熟悉的 React 应用程序开始。

让我们创建一个`src`文件夹，并在其中创建一个`app.ts`文件。

`app.ts`文件应该有以下内容：

```jsx
const App = () => <div>Hello React</div>

export default App
```

这里没有什么复杂的；我们导入 React，创建一个`App`组件，它呈现`Hello React`消息，并导出它。

现在让我们创建`client.tsx`，它负责在 DOM 中渲染`App`组件：

```jsx
import { render } from 'react-dom'
import App from './app'

render(<App />, document.getElementById('root'))
```

同样，这应该听起来很熟悉，因为我们导入了 React，ReactDOM 和我们之前创建的`App`组件，并且我们使用`ReactDOM`将其呈现在具有`app`ID 的 DOM 元素中。

让我们现在转移到服务器。

首先要做的是创建一个`template.ts`文件，它导出一个我们将用来返回服务器将返回给浏览器的页面标记的函数：

```jsx
export default body => `
  <!DOCTYPE html>
  <html>
 <head>
 <meta charset="UTF-8">
    </head>
 <body>
 <div id="root">${body}</div>
      <script src="/bundle.js"></script>
 </body>
 </html>`
```

这应该很简单。该函数接受`body`，我们稍后将看到它包含 React 应用程序，并返回页面的骨架。

值得注意的是，即使应用程序在服务器端呈现，我们也会在客户端加载捆绑包。 SSR 只是 React 用来呈现我们应用程序的工作的一半。我们仍然希望我们的应用程序是一个客户端应用程序，具有在浏览器中可以使用的所有功能，例如事件处理程序。

之后，您需要安装`express`，`react`和`react-dom`：

```jsx
npm install express react react-dom @types/express @types/react @types/react-dom
```

现在是时候创建`server.tsx`了，它有更多的依赖项，值得详细探讨：

```jsx
import React from 'react' import express, { Request, Response } from 'express'
import { renderToString } from 'react-dom/server'
import path from 'path'
import App from './App'
import template from './template'
```

我们导入的第一件事是`express`，这个库允许我们轻松创建具有一些路由的 Web 服务器，并且还能够提供静态文件。

其次，我们导入 `React` 和 `ReactDOM` 来渲染 `App`，我们也导入了。请注意 `import` 语句中的 `/server` 路径。我们导入的最后一件事是我们之前定义的模板。

现在我们创建一个 Express 应用程序：

```jsx
const app = express()
```

我们告诉应用程序我们的静态资产存储在哪里：

```jsx
app.use(express.static(path.resolve(__dirname, './dist/public')))
```

您可能已经注意到，路径与我们在 webpack 的客户端配置中用作客户端捆绑输出目的地的路径相同。

然后，这里是使用 React 进行 SSR 的逻辑：

```jsx
app.get('/', (req: Request, res: Response) => {
  const body = renderToString(<App />)
  const html = template(body)
  res.send(html)
})
```

我们告诉 Express 我们想要监听 `/` 路由，当客户端命中时，我们使用 `ReactDOM` 库将 `App` 渲染为字符串。这就是 React 的 SSR 的魔力和简单之处。

`renderToString` 的作用是返回由我们的 `App` 组件生成的 DOM 元素的字符串表示形式；如果我们使用 `ReactDOM` 渲染方法，它将在 DOM 中呈现相同的树。

body 变量的值类似于以下内容：

```jsx
<div data-reactroot="" data-reactid="1" data-react-checksum="982061917">Hello React</div>
```

正如您所看到的，它代表了我们在 `App` 的 `render` 方法中定义的内容，除了一些数据属性，React 在客户端使用这些属性将客户端应用程序附加到服务器端呈现的字符串上。

现在我们有了我们应用程序的 SSR 表示，我们可以使用 `template` 函数将其应用到 HTML 模板中，并在 Express 响应中将其发送回浏览器。

最后，但同样重要的是，我们必须启动 Express 应用程序：

```jsx
app.listen(3000, () => {
  console.log('Listening on port 3000')
})
```

我们现在已经准备好了；只剩下几个操作。第一个是定义 `npm` 的 `start` 脚本并将其设置为运行节点服务器：

```jsx
"scripts": {
  "build": "webpack",
  "start": "node ./dist/server"
}
```

脚本已经准备好了，所以我们可以首先使用以下命令构建应用程序：

```jsx
npm run build 
```

当捆绑包创建完成后，我们可以运行以下命令：

```jsx
npm start
```

将浏览器指向 `http://localhost:3000` 并查看结果。

这里有两件重要的事情需要注意。首先，当我们使用浏览器的查看页面源代码功能时，我们可以看到从服务器返回的应用程序的源代码，如果没有启用 SSR，我们是看不到的。

其次，如果我们打开 DevTools 并安装了 React 扩展，我们可以看到 `App` 组件也在客户端上启动了。

以下截图显示了页面的源代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/4dc6378f-f5e6-42d8-beb2-b015b7bfb582.png)

太棒了！现在您已经使用 SSR 创建了您的第一个 React 应用程序，让我们在下一节中学习如何获取数据。

# **实现数据获取**

前一节的示例应该清楚地解释了如何在 React 中设置通用应用程序。这很简单，主要集中在完成任务上。

然而，在现实世界的应用程序中，我们可能希望加载一些数据，而不是一个静态的 React 组件，例如示例中的`App`。假设我们想在服务器上加载 Dan Abramov 的`gists`并从我们刚刚创建的 Express 应用程序返回项目列表。

在*第六章*的数据获取示例中，我们看到了如何使用`useEffect`来触发数据加载。这在服务器上不起作用，因为组件不会挂载在 DOM 上，生命周期钩子也不会被触发。

之前执行的 Hooks 也不起作用，因为数据获取操作是`async`的，而`renderToString`不是。因此，我们必须找到一种方法在之前加载数据并将其作为 props 传递给组件。

让我们看看如何将上一节的应用程序稍作修改，以便在 SSR 阶段加载`gists`。

首先要做的是更改`App.tsx`以接受`gists`的列表作为`prop`，并在渲染方法中循环遍历它们以显示它们的描述：

```jsx
import { FC } from 'react'

type Gist = {
  id: string
  description: string
}

type Props = {
  gists: Gist[]
}

const App: FC<Props> = ({ gists }) => ( 
  <ul> 
    {gists.map(gist => ( 
      <li key={gist.id}>{gist.description}</li> 
    ))} 
  </ul> 
)

export default App
```

应用我们在上一章学到的概念，我们定义了一个无状态的函数组件，它接收`gists`作为 prop 并循环遍历元素以渲染项目列表。现在，我们必须更改服务器以检索`gists`并将它们传递给组件。

要在服务器端使用**fetch** API，我们必须安装一个名为`isomorphic-fetch`的库，它实现了 fetch 标准。它可以在 Node.js 和浏览器中使用：

```jsx
npm install isomorphic-fetch @types/isomorphic-fetch
```

我们首先将库导入到`server.tsx`中：

```jsx
import fetch from 'isomorphic-fetch'
```

我们想要进行的 API 调用如下：

```jsx
fetch('https://api.github.com/users/gaearon/gists') 
  .then(response => response.json()) 
  .then(gists => {})
```

在这里，`gists`可以在最后的`then`函数中使用。在我们的情况下，我们希望将它们传递给`App`。

因此，我们可以将`/`路由更改如下：

```jsx
app.get('/', (req, res) => { 
  fetch('https://api.github.com/users/gaearon/gists') 
    .then(response => response.json()) 
    .then(gists => { 
      const body = renderToString(<App gists={gists} />)
      const html = template(body)

      res.send(html)
    })
})
```

在这里，我们首先获取`gists`，然后将`App`渲染为字符串，传递属性。

一旦`App`被渲染，并且我们有了它的标记，我们就使用了上一节中使用的模板，并将其返回给浏览器。

在控制台中运行以下命令，并将浏览器指向`http://localhost:3000`。您应该能够看到一个服务器端渲染的`gists`列表：

```jsx
npm run build && npm start
```

确保列表是从 Express 应用程序呈现的，您可以导航到`view-source:http://localhost:3000`，您将看到`gists`的标记和描述。

这很好，看起来很容易，但如果我们检查 DevTools 控制台，我们会看到 Cannot read property 'map' of undefined 错误。我们看到错误的原因是，在客户端，我们再次渲染`App`，但没有将`gists`传递给它。

这一开始可能听起来有些反直觉，因为我们可能认为 React 足够聪明，可以在客户端使用服务器端字符串中呈现的`gists`。但事实并非如此，因此我们必须找到一种方法在客户端也使`gists`可用。

您可以考虑在客户端再次执行 fetch。这样可以工作，但并不是最佳的，因为您最终会触发两个 HTTP 调用，一个在 Express 服务器上，一个在浏览器上。如果我们考虑一下，我们已经在服务器上进行了调用，并且我们拥有所有所需的数据。在服务器和客户端之间共享数据的典型解决方案是在 HTML 标记中脱水数据，并在浏览器中重新水化数据。

这似乎是一个复杂的概念，但实际上并不是。我们现在将看看实现起来有多容易。我们必须做的第一件事是在客户端获取`gists`后将其注入模板中。

为此，我们必须稍微更改模板，如下所示：

```jsx
export default (body, gists) => ` 
  <!DOCTYPE html> 
  <html> 
 <head> 
 <meta charset="UTF-8"> 
    </head> 
 <body> 
 <div id="root">${body}</div> 
      <script>window.gists = ${JSON.stringify(gists)}</script> 
      <script src="/bundle.js"></script> 
    </body> 
 </html> 
`
```

`template`函数现在接受两个参数——应用程序的`body`和`gists`的集合。第一个插入到应用程序元素中，而第二个用于定义一个附加到`window`对象的全局`gists`变量，以便我们可以在客户端中使用它。

在`Express`路由（`server.js`）中，我们只需要更改生成模板的行，传递 body，如下所示：

```jsx
const html = template(body, gists)
```

最后，但同样重要的是，我们必须在`client.tsx`中使用附加到窗口的`gists`，这非常容易：

```jsx
ReactDOM.hydrate( 
  <App gists={window.gists} />, 
  document.getElementById('app') 
)
```

**水化**是在 React 16 中引入的，它在客户端的渲染上类似于渲染，无论 HTML 是否具有服务器呈现的标记。如果以前没有使用 SSR 的标记，那么`hydrate`方法将触发一个警告，您可以使用新的`suppressHydrationWarning`属性来消除它。

我们直接读取`gists`，并将它们传递给在客户端呈现的`App`组件。

现在，再次运行以下命令：

```jsx
npm run build && npm start
```

如果我们将浏览器窗口指向`http://localhost:3000`，错误就消失了，如果我们使用 React DevTools 检查`App`组件，我们可以看到客户端的`App`组件是如何接收`gists`集合的。

由于我们已经创建了我们的第一个 SSR 应用程序，现在让我们在下一节中看看如何通过使用名为 Next.js 的 SSR 框架更轻松地完成这项工作。

# **使用 Next.js 创建 React 应用**

您已经了解了使用 React 进行 SSR 的基础知识，并且可以将我们创建的项目作为真实应用程序的起点。但是，您可能认为有太多样板代码，并且需要了解太多不同的工具才能运行一个简单的通用应用程序。这是一种常见的感觉，称为**JavaScript 疲劳**，正如本书介绍中所述。

幸运的是，Facebook 开发人员和 React 社区中的其他公司正在努力改进 DX，并使开发人员的生活更轻松。到目前为止，您可能已经使用`create-react-app`来尝试前几章的示例，并且应该了解它是如何简化创建 React 应用程序的，而不需要开发人员学习许多技术和工具。

现在，`create-react-app`还不支持 SSR，但有一家名为**Vercel**的公司创建了一个名为**Next.js**的工具，它使得生成通用应用变得非常简单，而不用担心配置文件。它还大大减少了样板代码。

使用抽象化构建应用程序总是非常好的。然而，在添加太多层之前，了解内部工作原理是至关重要的，这就是为什么我们在学习 Next.js 之前先从手动过程开始的原因。我们已经看过了 SSR 的工作原理以及如何将状态从服务器传递到客户端。现在基本概念清楚了，我们可以转向一个隐藏了一些复杂性并使我们编写更少代码来实现相同结果的工具。

我们将创建相同的应用程序，加载 Dan Abramov 的所有`gists`，您将看到由于 Next.js 的原因，代码是多么干净和简单。

首先，创建一个新的项目文件夹（您可以称之为`next-project`）并运行以下命令：

```jsx
npm init
```

完成后，我们可以安装 Next.js 库和 React：

```jsx
npm install next react react-dom typescript @types/react @types/node
```

现在项目已创建，我们必须添加一个`npm`脚本来运行二进制文件：

```jsx
"scripts": { 
  "dev": "next" 
}
```

完美！现在是时候生成我们的`App`组件了。

Next.js 基于约定，其中最重要的约定之一是您可以创建与浏览器 URL 匹配的页面。默认页面是`index`，所以我们可以创建一个名为`pages`的文件夹，并在其中放置一个`index.js`文件。

我们开始导入依赖项：

```jsx
import fetch from 'isomorphic-fetch'
```

再次导入`isomorphic-fetch`，因为我们希望能够在服务器端使用`fetch`函数。

然后我们定义一个名为`App`的组件：

```jsx
const App = () => {

}

export default App
```

然后，我们定义一个名为`getInitialProps`的`static async`函数，这是我们告诉 Next.js 我们想要在服务器端和客户端加载哪些数据的地方。该库将使函数返回的对象在组件内部作为 props 可用。

应用于类方法的`static`和`async`关键字意味着该函数可以在类的实例外部访问，并且该函数会在其主体内部执行`wait`指令。

这些概念非常先进，不属于本章的范围，但如果您对它们感兴趣，可以查看 ECMAScript 提案（[`github.com/tc39/proposals`](https://github.com/tc39/proposals)）。

我们刚刚描述的方法的实现如下：

```jsx
App.getInitialProps = async () => { 
  const url = 'https://api.github.com/users/gaearon/gists'
  const response = await fetch(url)
  const gists = await response.json()

  return { 
    gists 
  }
}
```

我们告诉函数触发 fetch 并等待响应；然后我们将响应转换为 JSON，这将返回一个 promise。当 promise 解析时，我们可以返回带有`gists`的`props`对象。

组件的`render`看起来与前面的非常相似：

```jsx
return ( 
  <ul> 
    {props.gists.map(gist => ( 
       <li key={gist.id}>{gist.description}</li> 
     ))} 
   </ul> 
)
```

在运行项目之前，您需要配置`tsconfig.json`：

```jsx
{
  "compilerOptions": {
    "baseUrl": "src",
    "esModuleInterop": true,
    "module": "esnext",
    "noImplicitAny": true,
    "outDir": "dist",
    "resolveJsonModule": true,
    "sourceMap": false,
    "target": "es6",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "moduleResolution": "node",
    "isolatedModules": true,
    "jsx": "preserve"
  },
  "include": ["src/**/*.ts", "src/**/*.tsx"],
  "exclude": ["node_modules"]
}
```

现在，打开控制台并运行以下命令：

```jsx
npm run dev
```

我们将看到以下输出：

```jsx
> Ready on http://localhost:3000
```

如果我们将浏览器指向该 URL，我们可以看到通用应用程序正在运行。通过 Next.js，设置通用应用程序非常容易，只需几行代码和零配置。

您可能还注意到，如果您在编辑器中编辑应用程序，您将能够立即在浏览器中看到结果，而无需刷新页面。这是 Next.js 的另一个功能，它实现了热模块替换。在开发模式下非常有用。

如果您喜欢本章，请在 GitHub 上给一个星星：[`github.com/zeit/next.js`](https://github.com/zeit/next.js)。

# **摘要**

SSR 之旅已经结束。您现在可以使用 React 创建一个服务器端渲染的应用程序，而且您应该清楚为什么它对您有用。SEO 显然是主要原因之一，但社交分享和性能也是重要因素。您学会了如何在服务器上加载数据并在 HTML 模板中去除水分，以便在浏览器上启动客户端应用程序时使其可用。

最后，您已经了解到像 Next.js 这样的工具如何帮助您减少样板代码，并隐藏一些通常会给代码库带来的服务器端渲染 React 应用程序设置复杂性。

在下一章中，我们将讨论如何提高 React 应用程序的性能。


# 第十章：改善应用程序的性能

Web 应用程序的有效性能对于提供良好的用户体验和提高转化率至关重要。React 库实现了不同的技术来快速渲染我们的组件，并尽可能少地触及**文档对象模型**（**DOM**）。对 DOM 进行更改通常是昂贵的，因此最小化操作的数量至关重要。

然而，有一些特定的情景，React 无法优化这个过程，开发人员需要实现特定的解决方案来使应用程序顺利运行。

在本章中，我们将介绍 React 的基本概念，并学习如何使用一些 API 来帮助库找到更新 DOM 的最佳路径，而不会降低用户体验。我们还将看到一些常见的错误，这些错误可能会损害我们的应用程序并使其变慢。

我们应该避免仅仅为了优化而优化我们的组件，并且重要的是只在需要时应用我们将在接下来的章节中看到的技术。

在本章中，我们将涵盖以下主题：

+   协调的工作原理以及我们如何帮助 React 使用键更好地完成工作

+   常见的优化技术和常见的与性能相关的错误

+   使用不可变数据的含义以及如何做到这一点

+   有用的工具和库，使我们的应用程序运行更快

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter10`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter10)。

# 协调

大多数情况下，React 默认情况下足够快，您无需做任何其他事情来提高应用程序的性能。React 利用不同的技术来优化屏幕上组件的渲染。

当 React 需要显示一个组件时，它会调用其`render`方法以及其子组件的`render`方法。组件的`render`方法返回一棵 React 元素树，React 使用它来决定更新 UI 时必须执行哪些 DOM 操作。

每当组件状态发生变化时，React 都会再次调用节点上的`render`方法，并将结果与 React 元素的先前树进行比较。该库足够聪明，可以找出在屏幕上应用期望的变化所需的最小操作集。这个过程称为**协调**，由 React 透明地管理。由于这一点，我们可以轻松地以声明方式描述我们的组件在特定时间点应该是什么样子，然后让库来处理其余部分。

React 试图在 DOM 上应用尽可能少的操作，因为触及 DOM 是一项昂贵的操作。

然而，比较两个元素树也不是免费的，React 做出了两个假设来减少其复杂性：

+   如果两个元素具有不同的类型，它们将呈现不同的树。

+   开发者可以使用键来标记子元素在不同的渲染调用中保持稳定。

第二点对开发者来说很有趣，因为它给了我们一个工具来帮助 React 更快地渲染我们的视图。

默认情况下，当返回到 DOM 节点的子元素时，React 同时迭代两个子元素列表，每当有差异时，就会创建一个变化。

让我们看一些例子。在将以下两个树之间进行转换时，在子元素末尾添加一个元素将会很好地工作：

```jsx
<ul>
 <li>Carlos</li>
  <li>Javier</li>
</ul>

<ul>
 <li>Carlos</li>
 <li>Javier</li>
 <li>Emmanuel</li>
</ul>
```

两个`<li>Carlos</li>`树与两个`<li>Javier</li>`树匹配，然后它将插入`<li>Emmanuel</li>`树。

如果实现得不够聪明，将元素插入开头会导致性能下降。如果我们看一下示例，当在这两个树之间进行转换时，它的效果非常差：

```jsx
<ul>
 <li>Carlos</li>
  <li>Javier</li>
</ul>

<ul>
  <li>Emmanuel</li>
 <li>Carlos</li>
 <li>Javier</li>
</ul>
```

每个子元素都会被 React 改变，而不是意识到它可以保持子树的连续性，`<li>Carlos</li>`和`<li>Javier</li>`。这可能会成为一个问题。当然，这个问题可以解决，解决方法就是 React 支持的`key`属性。让我们接着看。

# 键

子元素拥有键，这些键被 React 用来匹配后续树和原始树之间的子元素。通过在我们之前的示例中添加一个键，可以使树的转换更加高效：

```jsx
<ul>
 <li key="2018">Carlos</li>
  <li key="2019">Javier</li>
</ul>

<ul>
  <li key="2017">Emmanuel</li>
 <li key="2018">Carlos</li>
 <li key="2019">Javier</li>
</ul>
```

现在 React 知道`2017`键是新的，而`2018`和`2019`键只是移动了。

找到一个键并不难。您将要显示的元素可能已经有一个唯一的 ID。所以键可以直接来自您的数据：

```jsx
<li key={element.id}>{element.title}</li>
```

新的 ID 可以由您添加到您的模型中，或者密钥可以由内容的某些部分生成。密钥只需在其同级中是唯一的；它不必在全局范围内是唯一的。数组中的项目索引可以作为密钥传递，但现在被认为是一种不好的做法。然而，如果项目从未被记录，这可能效果很好。重新排序将严重影响性能。

如果您使用`map`函数渲染多个项目，并且没有指定 key 属性，您将收到此消息：警告：数组或迭代器中的每个子项都应该有一个唯一的“key”属性。

让我们在下一节中学习一些优化技术。

# 优化技术

需要注意的是，在本书中的所有示例中，我们使用的应用程序要么是使用`create-react-app`创建的，要么是从头开始创建的，但始终使用的是 React 的开发版本。

使用 React 的开发版本对编码和调试非常有用，因为它为您提供了修复各种问题所需的所有必要信息。然而，所有的检查和警告都是有成本的，我们希望在生产中避免这些成本。

因此，我们应该对我们的应用程序做的第一个优化是构建捆绑包，将`NODE_ENV`环境变量设置为`production`。这在`webpack`中非常容易，只需使用以下方式中的`DefinePlugin`：

```jsx
new webpack.DefinePlugin({ 
  'process.env': { 
    NODE_ENV: JSON.stringify('production')
  }
})
```

为了实现最佳性能，我们不仅希望使用生产标志来创建捆绑包，还希望将捆绑包拆分为一个用于我们的应用程序，一个用于`node_modules`。

为此，您需要在`webpack`中使用新的优化节点：

```jsx
optimization: {
  splitChunks: {
    cacheGroups: {
      default: false,
      commons: {
        test: /node_modules/,
        name: 'vendor',
        chunks: 'all'
      }
    }
  }
}
```

由于 webpack 4 有两种模式，*开发*和*生产*，默认情况下启用生产模式，这意味着在使用生产模式编译捆绑包时，代码将被最小化和压缩；您可以使用以下代码块指定它：

```jsx
{
  mode: process.env.NODE_ENV === 'production' ? 'production' : 
    'development',
}
```

您的`webpack.config.ts`文件应该如下所示：

```jsx
module.exports = {
  entry: './index.ts',
  optimization: {
    splitChunks: {
      cacheGroups: {
        default: false,
        commons: {
          test: /node_modules/,
          name: 'vendor',
          chunks: 'all'
        }
      }
    }
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: JSON.stringify('production')
      }
    })
  ],
  mode: process.env.NODE_ENV === 'production' ? 'production' : 
    'development'
}
```

有了这个 webpack 配置，我们将得到非常优化的捆绑包，一个用于我们的供应商，一个用于实际应用程序。

# 工具和库

在下一节中，我们将介绍一些技术、工具和库，我们可以应用到我们的代码库中，以监视和改进性能。

## 不可变性

新的 React Hooks，如 React.memo，使用浅比较方法来比较 props，这意味着如果我们将对象作为 prop 传递，并且我们改变了其中一个值，我们将无法获得预期的行为。

事实上，浅比较无法找到属性的变化，组件永远不会重新渲染，除非对象本身发生变化。解决此问题的一种方法是使用**不可变数据**，一旦创建，就无法改变。

例如，我们可以以以下方式设置状态：

```jsx
const [state, setState] = useState({})

const obj = state.obj

obj.foo = 'bar'

setState({ obj })
```

即使更改对象的 foo 属性的值，对象的引用仍然相同，浅比较无法识别它。

我们可以做的是每次改变对象时创建一个新实例，如下所示：

```jsx
const obj = Object.assign({}, state.obj, { foo: 'bar' })

setState({ obj })
```

在这种情况下，我们得到一个新对象，其 foo 属性设置为 bar，并且浅比较将能够找到差异。使用 ES6 和 Babel，还有另一种更优雅地表达相同概念的方法，即使用对象扩展运算符：

```jsx
const obj = { 
  ...state.obj, 
  foo: 'bar' 
}

setState({ obj })
```

这种结构比以前的更简洁，并且产生相同的结果，但在撰写时，需要对代码进行转译才能在浏览器中执行。

React 提供了一些不可变性帮助器，使得使用不可变对象变得更加容易，还有一个名为 immutable.js 的流行库，它具有更强大的功能，但需要您学习新的 API。

## Babel 插件

还有一些有趣的 Babel 插件，我们可以安装并使用它们来提高 React 应用程序的性能。它们使应用程序更快，优化了构建时的代码部分。

第一个是 React 常量元素转换器，它查找所有不根据 props 更改的静态元素，并从 render（或功能组件）中提取它们，以避免不必要地调用 _jsx。

使用 Babel 插件非常简单。我们首先使用 npm 安装它：

```jsx
npm install --save-dev @babel/plugin-transform-react-constant-elements
```

您需要创建.babelrc 文件，并添加一个 plugins 键，其值为我们要激活的插件列表的数组：

```jsx
{ 
  "plugins": ["@babel/plugin-transform-react-constant-elements"] 
}
```

第二个 Babel 插件，我们可以选择使用以提高性能的是 React 内联元素转换，它用更优化的版本替换所有 JSX 声明（或 _jsx 调用），以加快执行速度。

使用以下命令安装插件：

```jsx
npm install --save-dev @babel/plugin-transform-react-inline-elements
```

接下来，您可以轻松地将插件添加到`.babelrc`文件中插件数组中，如下所示：

```jsx
{
  "plugins": ["@babel/plugin-transform-react-inline-elements"] 
}
```

这两个插件应该只在生产环境中使用，因为它们会使在开发模式下调试变得更加困难。到目前为止，我们已经学会了许多优化技术，以及如何使用 webpack 配置一些插件。

# 总结

我们的性能优化之旅已经结束，现在我们可以优化我们的应用程序，以提供更好的用户体验。

在本章中，我们学习了协调算法的工作原理，以及 React 始终试图采用最短的路径来对 DOM 进行更改。我们还可以通过使用键来帮助库优化其工作。一旦找到了瓶颈，你可以应用本章中所见的技术之一来解决问题。

我们已经学会了如何重构和设计组件的结构，以正确的方式提供性能提升。我们的目标是拥有小的组件，以最佳方式执行单一功能。在本章末尾，我们谈到了不可变性，以及为什么重要的是不要改变数据，以使`React.memo`和`shallowCompare`发挥作用。最后，我们介绍了不同的工具和库，可以使您的应用程序更快。

在下一章中，我们将学习使用 Jest、React Testing Library 和 React DevTools 进行测试和调试。


# 第十一章：测试和调试

由于 React 具有组件，因此很容易测试我们的应用程序。有许多不同的工具可以用来创建 React 测试，我们将在这里介绍最流行的工具，以了解它们提供的好处。

**Jest** 是一个由 Facebook 的 Christopher Pojer 和社区内的贡献者维护的*一站式*测试框架解决方案，旨在为您提供最佳的开发者体验。

通过本章结束时，您将能够从头开始创建测试环境，并为应用程序的组件编写测试。

在本章中，我们将讨论以下主题：

+   为什么测试我们的应用程序很重要，以及它们如何帮助开发人员更快地移动

+   如何设置 Jest 环境以使用 Enzyme 测试组件

+   React Testing Library 是什么，以及为什么它对于测试 React 应用程序是*必不可少*的

+   如何测试事件

+   React DevTools 和一些错误处理技术

# 技术要求

为了完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter11`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter11)。

# 了解测试的好处

测试 Web 用户界面一直是一项困难的工作。从单元测试到端到端测试，界面依赖于浏览器、用户交互和许多其他变量，这使得实施有效的测试策略变得困难。

如果您曾经尝试为 Web 编写端到端测试，您将知道获得一致的结果有多么复杂，结果往往受到不同因素（如网络）的影响而产生假阴性。除此之外，用户界面经常更新以改善体验，最大化转化率，或者仅仅添加新功能。

如果测试很难编写和维护，开发人员就不太可能覆盖他们的应用程序。另一方面，测试非常重要，因为它们使开发人员对他们的代码更有信心，这反映在速度和质量上。如果一段代码经过了良好的测试（并且测试编写得很好），开发人员可以确信它可以正常工作并且已经准备好发布。同样，由于测试的存在，重构代码变得更容易，因为测试保证了功能在重写过程中不会改变。

开发人员往往会专注于他们当前正在实现的功能，有时很难知道应用程序的其他部分是否受到这些更改的影响。测试有助于避免回归，因为它们可以告诉我们新代码是否破坏了旧测试。对于编写新功能的更大信心会导致更快的发布。

测试应用程序的主要功能使代码基础更加稳固，每当发现新的 bug 时，都可以重现、修复并通过测试覆盖，以便将来不再发生。

幸运的是，React（以及组件时代）使得测试用户界面变得更加简单和高效。测试组件或组件树是一项较少费力的工作，因为应用程序的每个部分都有其责任和边界。如果组件以正确的方式构建，如果它们是纯净的，并且旨在可组合和可重用，它们可以被测试为简单的函数。

现代工具带给我们的另一个巨大优势是能够使用 Node.js 和控制台运行测试。为每个测试启动浏览器会使测试变慢且不太可预测，降低开发人员的体验；相反，使用控制台运行测试会更快。

在控制台中仅测试组件有时会在实际浏览器中呈现时产生意外行为，但根据我的经验，这种情况很少见。当我们测试 React 组件时，我们希望确保它们能正常工作，并且在给定不同的 props 集合时，它们的输出始终是正确的。

我们可能还希望覆盖组件可能具有的所有各种状态。状态可能会通过单击按钮而改变，因此我们编写测试来检查所有事件处理程序是否按预期进行。

当组件的所有功能都被覆盖时，但我们想要做更多时，我们可以编写测试来验证组件在**边缘情况**下的行为。边缘情况是组件在例如所有 props 都为`null`或出现错误时可能出现的状态。一旦测试编写完成，我们就可以相当有信心地认为组件的行为符合预期。

测试单个组件很好，但这并不能保证一旦它们放在一起，多个经过单独测试的组件仍然能够正常工作。正如我们将在后面看到的，使用 React，我们可以挂载一组组件并测试它们之间的集成。

我们可以使用不同的技术来编写测试，其中最流行的之一是**测试驱动开发**（**TDD**）。应用 TDD 意味着首先编写测试，然后编写代码来通过测试。

遵循这种模式有助于我们编写更好的代码，因为我们被迫在实现功能之前更多地考虑设计，这通常会导致更高的质量。

# 使用 Jest 轻松进行 JavaScript 测试

学习如何以正确的方式测试 React 组件最重要的方法是通过编写一些代码，这就是我们将在本节中要做的事情。

React 文档表示，在 Facebook 他们使用 Jest 来测试他们的组件。然而，React 并不强制您使用特定的测试框架，您可以使用自己喜欢的任何一个而不会有任何问题。为了看到 Jest 的实际效果，我们将从头开始创建一个项目，安装所有依赖项并编写一个带有一些测试的组件。这将很有趣！

首先要做的是进入一个新文件夹并运行以下命令：

```jsx
npm init
```

一旦创建了`package.json`，我们就可以开始安装依赖项，第一个依赖项就是`jest`包本身：

```jsx
npm install --save-dev jest
```

要告诉`npm`我们想要使用`jest`命令来运行测试，我们必须在`package.json`中添加以下脚本：

```jsx
"scripts": { 
  "build": "webpack",
  "start": "node ./dist/server",
  "test": "jest",
  "test:coverage": "jest --coverage"
}
```

要使用 ES6 和 JSX 编写组件和测试，我们必须安装所有与 Babel 相关的包，以便 Jest 可以使用它们来转译和理解代码。

第二组依赖项的安装如下：

```jsx
npm install --save-dev @babel/core @babel/preset-env @babel/preset-react ts-jest
```

如您所知，我们现在必须创建一个`.babelrc`文件，Babel 将使用它来了解我们想要在项目中使用的预设和插件。

`.babelrc`文件如下所示：

```jsx
{ 
  "presets": ["@babel/preset-env", "@babel/preset-react"] 
}
```

现在，是时候安装 React 和`ReactDOM`了，我们需要它们来创建和渲染组件：

```jsx
npm install --save react react-dom
```

设置已经准备好，我们可以针对 ES6 代码运行 Jest 并将我们的组件渲染到 DOM 中，但还有一件事要做。

我们需要安装`@testing-library/jest-dom`和`@testing-library/react`：

```jsx
npm install @testing-library/jest-dom @testing-library/react
```

安装了这些软件包之后，您必须创建`jest.config.js`文件：

```jsx
 module.exports = {
  preset: 'ts-jest',
  setupFilesAfterEnv: ['<rootDir>/setUpTests.ts']
}
```

然后，让我们创建`setUpTests.ts`文件：

```jsx
import '@testing-library/jest-dom/extend-expect'
```

现在，让我们假设我们有一个`Hello`组件：

```jsx
import React, { FC } from 'react'

type Props = {
  name: string
}

const Hello: FC<Props> = ({ name }) => <h1 className="Hello">Hello {name || 'World'}</h1>

export default Hello
```

为了测试这个组件，我们需要创建一个同名文件，但是在新文件中添加`.test`（或`.spec`）后缀。这将是我们的测试文件：

```jsx
import React from 'react' import { render, cleanup } from '@testing-library/react'

import Hello from './index'

describe('Hello Component', () => {
  it('should render Hello World', () => {
    const wrapper = render(<Hello />)
    expect(wrapper.getByText('Hello World')).toBeInTheDocument()
  })

  it('should render the name prop', () => {
    const wrapper = render(<Hello name="Carlos" />)
    expect(wrapper.getByText('Hello Carlos')).toBeInTheDocument()
  });

  it('should has .Home classname', () => {
    const wrapper = render(<Hello />)
    expect(wrapper.container.firstChild).toHaveClass('Hello')
  });

  afterAll(cleanup)
})
```

然后，为了运行`test`，您需要执行以下命令：

```jsx
npm test
```

您应该看到这个结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/bd39fedb-e1f8-4b12-bf54-84be4de6e301.png)

`PASS`标签表示所有测试都已成功通过；如果您至少有一个测试失败，您将看到`FAIL`标签。让我们更改其中一个测试以使其失败：

```jsx
it('should render the name prop', () => {
  const wrapper = render(<Hello name="Carlos" />)
  expect(wrapper.getByText('Hello World')).toBeInTheDocument()
});
```

这是结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/12392022-1665-46d6-8972-36a2bb038acc.png)

正如您所看到的，`FAIL`标签用`X`指定。此外，期望和接收值提供了有用的信息，您可以看到期望的值和接收的值。

如果您想查看所有单元测试的覆盖百分比，您可以执行以下命令：

```jsx
npm run test:coverage
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/101fc17a-5565-4d30-a2ea-77dc069f6219.png)

覆盖还生成了结果的 HTML 版本；它创建了一个名为`coverage`的目录，里面又创建了一个名为`Icov-report`的目录。如果您在浏览器中打开`index.html`文件，您将看到以下 HTML 版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/93b5b5e8-0c27-48db-a971-9a801f198362.png)

现在您已经进行了第一次测试，并且知道如何收集覆盖数据，让我们在下一节中看看如何测试事件。

# 测试事件

事件在任何 Web 应用程序中都很常见，我们也需要测试它们，因此让我们学习如何测试事件。为此，让我们创建一个新的`ShowInformation`组件：

```jsx
import { FC, useState, ChangeEvent } from 'react'

const ShowInformation: FC = () => {
  const [state, setState] = useState({ name: '', age: 0, show: false })

  const handleOnChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target

    setState({
      ...state,
      [name]: value
    })
  }

  const handleShowInformation = () => {
    setState({
      ...state,
      show: true
    })
  }

 if (state.show) {
    return (
      <div className="ShowInformation">
        <h1>Personal Information</h1>

        <div className="personalInformation">
          <p>
            <strong>Name:</strong> {state.name}
          </p>
          <p>
            <strong>Age:</strong> {state.age}
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="ShowInformation">
      <h1>Personal Information</h1>

      <p>
        <strong>Name:</strong>
      </p>

      <p>
        <input name="name" type="text" value={state.name} onChange={handleOnChange} />
      </p>

      <p>
        <input name="age" type="number" value={state.age} onChange={handleOnChange} />
      </p>

      <p>
        <button onClick={handleShowInformation}>Show Information</button>
      </p>
    </div>
  )
}

export default ShowInformation
```

现在，让我们在`src/components/ShowInformation/index.test.tsx`中创建测试文件：

```jsx
import { render, cleanup, fireEvent } from '@testing-library/react'

import ShowInformation from './index'

describe('Show Information Component', () => {
  let wrapper

  beforeEach(() => {
    wrapper = render(<ShowInformation />)
  })

  it('should modify the name', () => {
    const nameInput = wrapper.container.querySelector('input[name="name"]') as HTMLInputElement
    const ageInput = wrapper.container.querySelector('input[name="age"]') as HTMLInputElement

    fireEvent.change(nameInput, { target: { value: 'Carlos' } })
    fireEvent.change(ageInput, { target: { value: 33 } })

    expect(nameInput.value).toBe('Carlos')
    expect(ageInput.value).toBe('33')
  })

  it('should show the personal information when user clicks on the button', () => {
    const button = wrapper.container.querySelector('button')

    fireEvent.click(button)

    const showInformation = wrapper.container.querySelector('.personalInformation')

    expect(showInformation).toBeInTheDocument()
  })

  afterAll(cleanup)
})
```

如果您运行测试并且工作正常，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b2197c2a-99a7-4613-96c0-849c4db68bb5.png)

# 使用 React DevTools

当在控制台中进行测试不够时，我们希望在应用程序在浏览器中运行时检查它，我们可以使用 React DevTools。

您可以在以下网址安装此 Chrome 扩展程序：[`chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi?hl=en`](https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi?hl=en)。

安装后会在 Chrome DevTools 中添加一个名为**React**的选项卡，您可以检查组件的渲染树，以及它们在特定时间点接收到的属性和状态。

Props 和 states 可以被读取，并且可以实时更改以触发 UI 中的更新并立即查看结果。这是一个必不可少的工具，在最新版本中，它有一个新功能，可以通过选中“Trace React Updates”复选框来启用。

启用此功能后，我们可以使用我们的应用程序并直观地看到在执行特定操作时更新了哪些组件。更新的组件会用彩色矩形突出显示，这样就很容易发现可能的优化。

# 使用 Redux DevTools

如果您在应用程序中使用 Redux，您可能希望使用 Redux DevTools 来调试 Redux 流程。您可以在以下网址安装它：[`chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd?hl=es`](https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd?hl=es)。

此外，您需要安装`redux-devtools-extension`包：

```jsx
npm install --save-dev redux-devtools-extension
```

安装了 React DevTools 和 Redux DevTools 后，您需要对它们进行配置。

如果您尝试直接使用 Redux DevTools，它将无法工作；这是因为我们需要将`composeWithDevTools`方法传递到 Redux 存储中；这应该是`configureStore.ts`文件：

```jsx
// Dependencies
import { createStore, applyMiddleware } from 'redux';
import thunk from 'redux-thunk';
import { composeWithDevTools } from 'redux-devtools-extension';

// Root Reducer
import rootReducer from '@reducers';

export default function configureStore({ 
  initialState, 
  reducer 
}) {
  const middleware = [
    thunk
  ];

  return createStore(
    rootReducer,
    initialState,
    composeWithDevTools(applyMiddleware(...middleware))
  );
}
```

这是测试我们的 Redux 应用程序的最佳工具。

# 总结

在本章中，您了解了测试的好处，以及可以用来覆盖 React 组件的框架。

您学会了如何使用 React Testing Library 实现和测试组件和事件，如何使用 Jest 覆盖率，以及如何使用 React DevTools 和 Redux DevTools。在测试复杂组件时，例如高阶组件或具有多个嵌套字段的表单时，牢记常见的解决方案是很重要的。

在下一章中，您将学习如何使用 React Router 在应用程序中实现路由。


# 第十二章：React 路由器

与 Angular 不同，React 是一个库而不是一个框架，这意味着特定功能（例如路由或 PropTypes）不是 React 核心的一部分。相反，路由由一个名为**React Router**的第三方库处理。

在本章中，您将看到如何在应用程序中实现 React 路由器，并在相关部分结束时，您将能够添加动态路由并了解 React 路由器的工作原理。

在本章中，我们将涵盖以下主题：

+   了解`react-router`，`react-router-dom`和`react-router-native`包之间的区别

+   如何安装和配置 React 路由器

+   添加`<Switch>`组件

+   添加`exact`属性

+   向路由添加参数

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter12`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter12)。

# 安装和配置 React 路由器

使用`create-react-app`创建新的 React 应用程序后，您需要做的第一件事是安装 React Router v5.x，使用以下命令：

```jsx
npm install react-router-dom @types/react-router-dom
```

您可能会困惑为什么我们要安装`react-router-dom`而不是`react-router`。React Router 包含`react-router-dom`和`react-router-native`的所有常见组件。这意味着如果您在 Web 上使用 React，您应该使用`react-router-dom`，如果您在使用 React Native，则需要使用`react-router-native`。

`react-router-dom`包最初是为了包含版本 4 而创建的，而`react-router`使用版本 3。`react-router-dom`包在`react-router`上有一些改进。它们在这里列出：

+   改进的`<Link>`组件（渲染`<a>`）。

+   包括`<BrowserRouter>`，它与浏览器`window.history`交互。

+   包括`<NavLink>`，它是一个知道自己是否活动的`<Link>`包装器。

+   包括`<HashRouter>`，它使用 URL 中的哈希来渲染组件。如果您有一个静态页面，您应该使用这个组件而不是`<BrowserRouter>`。

# 创建我们的章节

让我们创建一些部分来测试一些基本路由。我们需要创建四个无状态组件（`About`、`Contact`、`Home`和`Error404`），并将它们命名为它们各自目录中的`index.tsx`。

您可以将以下内容添加到`src/components/Home.tsx`组件中：

```jsx
const Home = () => ( 
  <div className="Home">
    <h1>Home</h1>
 </div>
)

export default Home
```

`src/components/About.tsx`组件可以使用以下内容创建：

```jsx
const About = () => ( 
  <div className="About">
 <h1>About</h1>
 </div>
)

export default About
```

以下是创建`src/components/Contact.tsx`组件的步骤：

```jsx
const Contact = () => ( 
  <div className="Contact">
 <h1>Contact</h1>
 </div>
)

export default Contact
```

最后，`src/components/Error404.tsx`组件创建如下：

```jsx
const Error404 = () => ( 
  <div className="Error404">
 <h1>Error404</h1>
 </div>
)

export default Error404
```

创建所有功能组件后，我们需要修改`index.tsx`文件，以导入我们将在下一步中创建的路由文件：

```jsx
// Dependencies
import { render } from 'react-dom'
import { BrowserRouter as Router } from 'react-router-dom'

// Routes
import AppRoutes from './routes'

render( 
  <Router>
 <AppRoutes />
 </Router>, 
  document.getElementById('root')
)
```

现在，我们需要创建`routes.tsx`文件，在用户访问根路径(`/`)时渲染我们的`Home`组件：

```jsx
// Dependencies
import { Route } from 'react-router-dom'

// Components
import App from './App'
import Home from './components/Home'

const AppRoutes = () => ( 
  <App>
 <Route path="/" component={Home} /> 
 </App>
)

export default AppRoutes
```

之后，我们需要修改`App.tsx`文件，将路由组件渲染为子组件：

```jsx
import { FC, ReactNode } from 'react' 
import './App.css'

type Props = {
  children: ReactNode
}

const App: FC<Props> = ({ children }) => ( 
  <div className="App">
    {children}
  </div> 
)

export default App
```

如果运行应用程序，您将在根目录(`/`)中看到`Home`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/1fe43ab2-7d5b-4a17-8154-8f62e752c41a.png)

现在，当用户尝试访问任何其他路由时，让我们添加`Error404`：

```jsx
// Dependencies
import { Route } from 'react-router-dom'

// Components
import App from './App'
import Home from './components/Home'
import Error404 from './components/Error404'

const AppRoutes = () => (
  <App>
 <Route path="/" component={Home} />
    <Route component={Error404} />
 </App>
)

export default AppRoutes
```

让我们再次运行应用程序。您将看到`Home`和`Error404`组件都被渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/7b470c24-6b43-43d0-8664-440f15b4f3fa.png)

您可能想知道为什么会发生这种情况。这是因为我们需要使用`<Switch>`组件，只有当它匹配路径时才执行一个组件。为此，我们需要导入`Switch`组件，并将其添加为我们路由的包装器：

```jsx
// Dependencies
import { Route, Switch } from 'react-router-dom'

// Components
import App from './App'
import Home from './components/Home'
import Error404 from './components/Error404'

const AppRoutes = () => (
  <App>
    <Switch>
      <Route path="/" component={Home} />
      <Route component={Error404} />
    </Switch>
  </App>
)

export default AppRoutes
```

现在，如果您转到根目录(`/`)，您将看到`Home`组件和`Error404`不会同时执行，但是如果我们转到`/somefakeurl`，我们将看到`Home`组件也被执行，这是一个问题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/4350be0f-ff8f-411b-a9fe-9ddfc02bbd7e.png)

为了解决问题，我们需要在要匹配的路由中添加`exact`属性。问题在于`/somefakeurl`将匹配我们的根路径(`/`)，但是如果我们想非常具体地匹配路径，我们需要在`Home`路由中添加`exact`属性：

```jsx
const AppRoutes = () => (
  <App>
    <Switch>
      <Route path="/" component={Home} exact />
      <Route component={Error404} />
    </Switch>
  </App>
)
```

现在，如果您再次访问`/somefakeurl`，您将能够看到 Error404 组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/ef641b8e-0018-4766-8356-93b8619c1870.png)

现在，我们可以添加其他组件（`About`和`Contact`）：

```jsx
// Dependencies
import { Route, Switch } from 'react-router-dom'

// Components
import App from './App'
import About from './components/About'
import Contact from './components/Contact'
import Home from './components/Home'
import Error404 from './components/Error404'

const AppRoutes = () => (
 <App>
 <Switch>
      <Route path="/" component={Home} exact />
      <Route path="/about" component={About} exact />
      <Route path="/contact" component={Contact} exact />
      <Route component={Error404} />
 </Switch>
 </App>
)

export default AppRoutes
```

现在，您可以访问`/about`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b7201c1f-4873-4de7-b241-350a37f94c68.png)

或者，您现在可以访问`/contact`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/e6eeb5a0-b3f7-4189-9fa7-1a31ae08bf40.png)

现在你已经实现了你的第一个路由，现在让我们在下一节中向路由添加一些参数。

# 向路由添加参数

到目前为止，你已经学会了如何使用 React Router 来进行基本路由（单层路由）。现在，我将向你展示如何向路由添加一些参数并将它们传递到我们的组件中。

在这个例子中，我们将创建一个`Contacts`组件，当我们访问`/contacts`路由时，它将显示联系人列表，但当用户访问`/contacts/:contactId`时，它将显示联系人信息（`name`，`phone`和`email`）。

我们需要做的第一件事是创建我们的`Contacts`组件。让我们使用以下骨架。

让我们使用这些 CSS 样式：

```jsx
.Contacts ul {
  list-style: none;
  margin: 0;
  margin-bottom: 20px;
  padding: 0;
}

.Contacts ul li {
  padding: 10px;
}

.Contacts a {
  color: #555;
  text-decoration: none;
}

.Contacts a:hover {
  color: #ccc;
  text-decoration: none;
}
```

一旦你创建了`Contacts`组件，你需要将它导入到我们的路由文件中：

```jsx
// Dependencies
import { Route, Switch } from 'react-router-dom'

// Components
import App from './components/App'
import About from './components/About'
import Contact from './components/Contact'
import Home from './components/Home'
import Error404 from './components/Error404'
import Contacts from './components/Contacts'

const AppRoutes = () => (
  <App>
    <Switch>
      <Route path="/" component={Home} exact />
      <Route path="/about" component={About} exact />
      <Route path="/contact" component={Contact} exact />
      <Route path="/contacts" component={Contacts} exact />
      <Route component={Error404} />
    </Switch>
  </App>
)

export default AppRoutes
```

现在，如果你去到`/contacts`的 URL，你就能看到`Contacts`组件了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/2f0684f4-fd5b-4559-98d4-9e7f3c73109e.png)

现在`Contacts`组件已经连接到 React Router，让我们将我们的联系人渲染为列表：

```jsx
import { FC, useState } from 'react'
import { Link } from 'react-router-dom'
import './Contacts.css'

type Contact = {
  id: number
  name: string
  email: string
  phone: string
}

const data: Contact[] = [
  {
    id: 1,
    name: 'Carlos Santana',
    email: 'carlos.santana@dev.education',
    phone: '415-307-3112'
  },
  {
    id: 2,
    name: 'John Smith',
    email: 'john.smith@dev.education',
    phone: '223-344-5122'
  },
  {
    id: 3,
    name: 'Alexis Nelson',
    email: 'alexis.nelson@dev.education',
    phone: '664-291-4477'
  }
]

const Contacts: FC = (props) => {
 // For now we are going to add our contacts to our
 // local state, but normally this should come
 // from some service.
  const [contacts, setContacts] = useState<Contact[]>(data)

  const renderContacts = () => (
    <ul>
      {contacts.map((contact: Contact, key) => (
        <li key={contact.id}>
          <Link to={`/contacts/${contact.id}`}>{contact.name}</Link>
        </li>
      ))}
    </ul>
  )

  return (
    <div className="Contacts">
      <h1>Contacts</h1>

      {renderContacts()}
    </div>
  )
}

export default Contacts
```

正如你所看到的，我们正在使用`<Link>`组件，它将生成一个指向`/contacts/contact.id`的`<a>`标签，这是因为我们将在我们的路由文件中添加一个新的嵌套路由来匹配联系人的 ID：

```jsx
const AppRoutes = () => (
  <App>
 <Switch>
      <Route path="/" component={Home} exact />
      <Route path="/about" component={About} exact />
      <Route path="/contact" component={Contact} exact />
      <Route path="/contacts" component={Contacts} exact />
      <Route path="/contacts/:contactId" component={Contacts} exact />
      <Route component={Error404} />
 </Switch>
 </App>
)
```

React Router 有一个特殊的属性叫做`match`，它是一个包含与路由相关的所有数据的对象，如果我们有参数，我们将能够在`match`对象中看到它们：

```jsx
import { FC, useState } from 'react'
import { Link } from 'react-router-dom'
import './Contacts.css'

const data = [
  {
    id: 1,
    name: 'Carlos Santana',
    email: 'carlos.santana@js.education',
    phone: '415-307-3112'
  },
  {
    id: 2,
    name: 'John Smith',
    email: 'john.smith@js.education',
    phone: '223-344-5122'
  },
  {
    id: 3,
    name: 'Alexis Nelson',
    email: 'alexis.nelson@js.education',
    phone: '664-291-4477'
  }
]

type Contact = {
  id: number
  name: string
  email: string
  phone: string
}

type Props = {
  match: any
}

const Contacts: FC<Props> = (props) => {
  // For now we are going to add our contacts to our
 // local state, but normally this should come
 // from some service.
  const [contacts, setContacts] = useState<Contact[]>(data)

 // Let's see what contains the match object.
  console.log(props)

  const { match: { params: { contactId } } } = props

  // By default our selectedNote is false
  let selectedContact: any = false

  if (contactId > 0) {
 // If the contact id is higher than 0 then we filter it from our
 // contacts array.
    selectedContact = contacts.filter(
      contact => contact.id === Number(contactId)
    )[0];
  }

  const renderSingleContact = ({ name, email, phone }: Contact) => (
    <>
      <h2>{name}</h2>
      <p>{email}</p>
      <p>{phone}</p>
    </>
  )

  const renderContacts = () => (
    <ul>
      {contacts.map((contact: Contact, key) => (
        <li key={key}>
          <Link to={`/contacts/${contact.id}`}>{contact.name}</Link>
        </li>
      ))}
    </ul>
  )

  return (
    <div className="Contacts">
      <h1>Contacts</h1>
      {/* We render our selectedContact or all the contacts */}
      {selectedContact
        ? renderSingleContact(selectedContact)
        : renderContacts()}
    </div>
  )
}

export default Contacts
```

`match`属性看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/5e07ca5e-dcbf-4071-91bb-455b6cbd3392.png)

正如你所看到的，`match`属性包含了很多有用的信息。React Router 还包括了对象的历史和位置。此外，我们可以获取我们在路由中传递的所有参数；在这种情况下，我们接收到了`contactId`参数。

如果你再次运行应用程序，你应该能够看到你的联系人就像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/6242d69a-e3df-4538-8e22-73bbc86df9ff.png)

如果你点击约翰·史密斯（他的`contactId`是`2`），你会看到联系人的信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/fdc306b8-aec1-471d-ba18-9e726cb4b6ef.png)

在此之后，你可以在`App`组件中添加一个导航栏来访问所有的路由：

```jsx
import { Link } from 'react-router-dom'
import './App.css'

const App = ({ children }) => (
  <div className="App">
    <ul className="menu">
      <li><Link to="/">Home</Link></li>
      <li><Link to="/about">About</Link></li>
      <li><Link to="/contacts">Contacts</Link></li>
      <li><Link to="/contact">Contact</Link></li>
    </ul>

    {children}
  </div>
)

export default App
```

现在，让我们修改我们的`App`样式：

```jsx
.App {
  text-align: center;
}

.App ul.menu {
  margin: 50px;
  padding: 0;
  list-style: none;
}

.App ul.menu li {
  display: inline-block;
  padding: 0 10px;
}

.App ul.menu li a {
  color: #333;
  text-decoration: none;
}

.App ul.menu li a:hover {
  color: #ccc;
}
```

最后，你会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/ff9aa68e-33e2-4ece-915b-e04e5b403e48.png)

现在你知道如何向你的应用程序添加带有参数的路由了 - 这太棒了，对吧？

# 总结

我们的 React Router 之旅已经结束，现在你知道如何安装和配置 React Router，如何创建基本路由，以及如何向嵌套路由添加参数。

在下一章中，我们将看到如何避免 React 中一些最常见的反模式。


# 第十三章：要避免的反模式

在本书中，您已经学会了在编写 React 应用程序时应用最佳实践。在最初的几章中，我们重新审视了基本概念以建立扎实的理解，然后在接下来的章节中，我们深入了解了更高级的技术。

现在，您应该能够构建可重用的组件，使组件彼此通信，并优化应用程序树以获得最佳性能。然而，开发人员会犯错误，本章就是关于在使用 React 时应避免的常见反模式。

查看常见错误将帮助您避免它们，并有助于您了解 React 的工作原理以及如何以 React 方式构建应用程序。对于每个问题，我们将看到一个示例，展示如何重现和解决它。

在本章中，我们将涵盖以下主题：

+   使用属性初始化状态

+   使用索引作为键

+   在 DOM 元素上扩展属性

# 技术要求

完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter13`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter13)。

# 使用属性初始化状态

在本节中，我们将看到如何使用从父级接收的属性初始化状态通常是一种反模式。我使用“通常”这个词，因为正如我们将看到的，一旦我们清楚了这种方法的问题是什么，我们可能仍然决定使用它。

学习某事的最佳方法之一是查看代码，因此我们将从创建一个简单的组件开始，其中包含一个`+`按钮来增加计数器。

该组件是使用类实现的，如下面的代码片段所示：

```jsx
import { FC, useState } from 'react'

type Props = {
  count: number
}

const Counter: FC<Props> = (props) => {}

export default Counter
```

现在，让我们设置我们的`count`状态：

```jsx
const [state, setState] = useState<any>(props.count)
```

单击处理程序的实现非常简单直接-我们只需将`1`添加到当前的`count`值中，并将结果值存储回`state`中：

```jsx
const handleClick = () => {
  setState({ count: state.count + 1 })
}
```

最后，我们渲染并描述输出，其中包括`count`状态的当前值和增加它的按钮：

```jsx
return (
  <div>
    {state.count}
    <button onClick={handleClick}>+</button>
  </div>
)
```

现在，让我们渲染此组件，将`1`作为`count`属性传递：

```jsx
<Counter count={1} />
```

它的工作正常-每次单击`+`按钮时，当前值都会增加。那么问题是什么呢？

有两个主要错误，如下所述：

+   我们有一个重复的真相来源。

+   如果传递给组件的`count`属性发生更改，则状态不会得到更新。

如果我们使用 React DevTools 检查`Counter`元素，我们会注意到`Props`和`State`具有相似的值：

```jsx
<Counter>
Props
  count: 1
State
  count: 1
```

这使得在组件内部和向用户显示时不清楚当前和可信的值是哪个。

更糟糕的是，点击*+*一次会使值发散。此发散的示例如下代码所示：

```jsx
<Counter>
Props
  count: 1
State
  count: 2
```

在这一点上，我们可以假设第二个值代表当前计数，但这并不明确，可能会导致意外行为，或者在树下面出现错误的值。

第二个问题集中在 React 如何创建和实例化类上。组件的`useState`函数只在创建组件时调用一次。

在我们的`Counter`组件中，我们读取`count`属性的值并将其存储在状态中。如果该属性的值在应用程序的生命周期中发生更改（假设它变为`10`），则`Counter`组件永远不会使用新值，因为它已经被初始化。这会使组件处于不一致的状态，这不是最佳的，并且很难调试。

如果我们真的想要使用 prop 的值来初始化组件，并且我们确信该值将来不会改变呢？

在这种情况下，最佳做法是明确表示并给属性命名，以明确您的意图，例如`initialCount`。例如，让我们以以下方式更改`Counter`组件的 prop 声明：

```jsx
type Props = {
  initialCount: number
}

const Counter: FC<Props> = (props) => {
  const [count, setState] = useState<any>(props.initialCount)
  ...
}
```

如果我们这样使用，很明显父级只有一种方法来初始化计数器，但是`initialCount`属性的任何将来的值都将被忽略：

```jsx
<Counter initialCount={1} />
```

在下一节中，我们将学习有关键的知识。

# 使用索引作为键

在*第十章*，*改进应用程序的性能*中，我们看到了如何通过使用`key`属性来帮助 React 找出更新 DOM 的最短路径。

key 属性在 DOM 中唯一标识元素，并且 React 使用它来检查元素是新的还是在组件属性或状态更改时必须更新。

始终使用键是一个好主意，如果不这样做，React 会在控制台（开发模式下）中发出警告。但是，这不仅仅是使用键的问题；有时，我们决定用作键的值可能会有所不同。实际上，使用错误的键可能会在某些情况下导致意外行为。在本节中，我们将看到其中一个实例。

让我们再次创建一个`List`组件，如下所示：

```jsx
import { FC, useState } from 'react'

const List: FC = () => {

}

export default List
```

然后我们定义我们的状态：

```jsx
const [items, setItems] = useState(['foo', 'bar'])
```

单击处理程序的实现与上一个实现略有不同，因为在这种情况下，我们需要在列表顶部插入一个新项目：

```jsx
const handleClick = () => { 
  const newItems = items.slice()
  newItems.unshift('baz')

  setItems(newItems)
}
```

最后，在`render`中，我们显示列表和`+`按钮，以在列表顶部添加`baz`项目：

```jsx
return ( 
  <div> 
    <ul> 
      {items.map((item, index) => ( 
        <li key={index}>{item}</li> 
      ))} 
    </ul> 

    <button onClick={handleClick}>+</button> 
  </div> 
) 
```

如果您在浏览器中运行组件，将不会看到任何问题；单击`+`按钮会在列表顶部插入一个新项目。但让我们做一个实验。

让我们以以下方式更改`render`，在每个项目旁边添加一个输入字段。然后我们使用输入字段，因为我们可以编辑它的内容，这样更容易找出问题：

```jsx
return ( 
  <div> 
    <ul> 
      {items.map((item, index) => ( 
        <li key={index}> 
          {item} 
          <input type="text" /> 
        </li> 
      ))} 
    </ul> 
    <button onClick={handleClick}>+</button> 
  </div> 
)
```

如果我们在浏览器中再次运行此组件，复制输入字段中项目的值，然后单击*+*，我们将得到意外的行为。

如下截图所示，项目向下移动，而输入元素保持在原位，这样它们的值不再与项目的值匹配：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/1d059f66-fb4c-4ab6-a9bf-feae211546f9.png)

运行组件，单击+，并检查控制台应该给我们所有需要的答案。

我们可以看到的是，React 不是在顶部插入新元素，而是交换了两个现有元素的文本，并将最后一个项目插入到底部，就好像它是新的一样。它这样做的原因是我们将`map`函数的索引用作键。

实际上，即使我们将一个新项目推送到列表顶部，索引始终从`0`开始，因此 React 认为我们更改了现有两个的值，并在索引`2`处添加了一个新元素。行为与根本不使用键属性时相同。

这是一个非常常见的模式，因为我们可能认为提供任何键都是最佳解决方案，但实际情况并非如此。键必须是唯一且稳定的，只能标识一个项目。

为了解决这个问题，我们可以，例如，使用项目的值，如果我们期望它在列表中不重复，或者创建一个唯一标识符。

# 在 DOM 元素上扩展属性

最近，有一种常见的做法被丹·阿布拉莫夫描述为反模式；当您在 React 应用程序中这样做时，它还会触发控制台中的警告。

这是社区中广泛使用的一种技术，我个人在现实项目中多次看到过。我们通常将属性扩展到元素上，以避免手动编写每个属性，如下所示：

```jsx
<Component {...props} />
```

这非常有效，并且通过 Babel 转译为以下代码：

```jsx
_jsx(Component, props)
```

然而，当我们将属性扩展到 DOM 元素时，我们有可能添加未知的 HTML 属性，这是不好的实践。

问题不仅与扩展运算符有关；逐个传递非标准属性也会导致相同的问题和警告。由于扩展运算符隐藏了我们正在传递的单个属性，因此更难以弄清楚我们正在传递给元素的内容。

要在控制台中看到警告，我们可以执行以下基本操作：渲染以下组件：

```jsx
const Spread = () => <div foo="bar" />
```

我们得到的消息看起来像下面这样，因为`foo`属性对于`div`元素是无效的：

```jsx
Unknown prop `foo` on <div> tag. Remove this prop from the element
```

在这种情况下，正如我们所说的，很容易弄清楚我们正在传递哪个属性并将其删除，但是如果我们使用扩展运算符，就像以下示例中一样，我们无法控制从父级传递的属性：

```jsx
const Spread = props => <div {...props} />;
```

如果我们以以下方式使用组件，就不会出现问题：

```jsx
<Spread className="foo" />
```

然而，如果我们做类似以下的事情，情况就不同了。React 会抱怨，因为我们正在向 DOM 元素应用非标准属性：

```jsx
<Spread foo="bar" className="baz" />
```

我们可以使用的一个解决方案来解决这个问题是创建一个名为`domProps`的属性，我们可以安全地将其扩展到组件上，因为我们明确表示它包含有效的 DOM 属性。

例如，我们可以按照以下方式更改`Spread`组件：

```jsx
const Spread = props => <div {...props.domProps} />
```

然后我们可以这样使用它：

```jsx
<Spread foo="bar" domProps={{ className: 'baz' }} />
```

正如我们在 React 中多次看到的那样，明确是一个好的实践。

# 总结

了解所有最佳实践总是一件好事，但有时了解反模式可以帮助我们避免走错路。最重要的是，了解为什么某些技术被认为是不良实践的原因，可以帮助我们理解 React 的工作原理，以及如何有效地使用它。

在本章中，我们介绍了四种不同的使用组件的方式，这些方式可能会影响我们的 Web 应用程序的性能和行为。

针对每一个问题，我们都使用了一个示例来重现问题，并提供了需要应用的更改来解决问题。

我们了解到为什么使用属性来初始化状态可能会导致状态和属性之间的不一致。我们还看到了如何使用错误的键属性可能会对协调算法产生不良影响。最后，我们了解到为什么将非标准属性扩展到 DOM 元素被视为一种反模式。

在下一章中，我们将探讨如何将我们的 React 应用部署到生产环境中。
