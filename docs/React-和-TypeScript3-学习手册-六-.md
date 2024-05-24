# React 和 TypeScript3 学习手册（六）

> 原文：[`zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487`](https://zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：与 GraphQL API 交互

GraphQL 是由 Facebook 维护的用于读取和写入数据的开源 Web API 语言。它允许客户端指定返回的数据，并在单个请求中请求多个数据区域。这种效率和灵活性使其成为 REST API 的一个引人注目的替代方案。GraphQL 还支持读取和写入数据。

在本章中，我们将开始尝试针对 GitHub 进行一些 GraphQL 查询，以熟悉使用*GitHub GraphQL API*资源管理器的语法。我们将探讨如何读取和写入 GraphQL 数据，以及如何精确指定我们希望在响应中返回的数据方式。

然后，我们将在 React 和 TypeScript 应用程序中使用 GitHub GraphQL 服务器，构建一个小应用程序，该应用程序搜索 GitHub 存储库并返回有关其的一些信息。我们将使用上一章关于`axios`的知识与 GitHub GraphQL 服务器进行交互。然后我们将转而使用 Apollo，这是一个使与 GraphQL 服务器交互变得轻而易举的客户端库。

在本章中，我们将涵盖以下主题：

+   GraphQL 查询和变异语法

+   使用 axios 作为 GraphQL 客户端

+   使用 Apollo GraphQL 客户端

+   在 Apollo 中使用缓存数据

# 技术要求

在本章中，我们使用以下技术：

+   **Node.js 和** `npm`：TypeScript 和 React 依赖于这些。我们可以从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)安装它们。如果我们已经安装了这些，请确保`npm`至少是 5.2 版本。

+   **Visual Studio Code**：我们需要一个编辑器来编写 React 和 TypeScript 代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要在 Visual Studio Code 中安装 TSLint (by egamma) 和 Prettier (by Estben Petersen) 扩展。

+   **GitHub**：我们需要一个 GitHub 账户。如果我们还没有账户，可以在以下链接注册：[`github.com/join`](https://github.com/join)。

+   **GitHub GraphQL API Explorer**：我们将使用此工具来玩转 GraphQL 查询和变异的语法。该工具位于[`developer.github.com/v4/explorer/`](https://developer.github.com/v4/explorer/)。

本章中的所有代码片段都可以在[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/10-GraphAPIs`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/10-GraphAPIs)上找到。

# GraphQL 查询和变异语法

在本节中，我们将使用 GitHub GraphQL API 资源浏览器开始熟悉与 GraphQL 服务器交互的语法，从下一节开始阅读数据。

# 阅读 GraphQL 数据

为了读取 GraphQL 数据，我们进行所谓的查询。在本节中，我们将首先介绍基本的 GraphQL 语法，然后讨论如何在查询结果中包含嵌套对象，以及如何通过允许传递参数来创建可重用的查询。

# 基本查询

在本节中，我们将使用 GitHub GraphQL API 资源浏览器来获取有关我们的 GitHub 用户帐户的信息：

1.  让我们在浏览器中打开以下 URL 以打开工具：

[`developer.github.com/v4/explorer/`](https://developer.github.com/v4/explorer/)。

如果我们还没有登录 GitHub 帐户，我们将需要登录。

1.  在左上角的面板中，让我们输入以下内容，然后点击执行查询按钮：

```jsx
query { 
  viewer { 
    name
  }
}
```

这是我们的第一个 GraphQL 查询。以下是一些关键点：

+   我们使用`query`关键字作为查询的前缀。这实际上是可选的。

+   `viewer`是我们想要获取的对象的名称。

+   `name`是我们想要返回的`viewer`中的一个字段。

查询结果将显示在右侧：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/e28c0b49-4f11-4210-95b6-0f3054189947.png)

我们请求的数据以 JSON 对象的形式返回。JSON 包含一个包含`name`字段的`viewer`对象的`data`对象。`name`的值应该是我们的名字，因为这是存储在我们的 GitHub 帐户中的名字。

1.  在结果窗格的右侧有一个文档链接。如果我们点击这个链接，会出现一个文档资源浏览器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/7cbedebe-ec72-4b09-943f-c263da3b8b0f.png)

如果我们点击查询链接，将显示可以查询的所有对象，包括`viewer`，这是我们刚刚查询的对象。如果我们点击进入这个对象，我们将看到`viewer`中可用的所有字段。

1.  让我们将`avatarUrl`添加到我们的查询中，因为这是我们可以使用的另一个字段：

```jsx
query { 
  viewer { 
    name
    avatarUrl
  }
}
```

因此，我们只需在`name`和`avatarUrl`字段之间加上一个换行符，将`avatarUrl`字段添加到`viewer`对象中。如果我们执行查询，我们将看到`avatarUrl`添加到 JSON 结果中。这应该是我们的图像的路径。

因此，我们已经看到了 GraphQL 的灵活性，可以精确指定我们希望在响应中返回哪些字段。在下一节中，我们将进一步指定我们希望返回的嵌套对象。

# 返回嵌套数据

让我们在本节中进行更复杂的查询。我们将搜索 GitHub 存储库，返回有关它的信息，包括它拥有的星星数量以及最近提出的问题作为嵌套数组：

1.  让我们开始输入以下查询并执行它：

```jsx
query { 
  repository (owner:"facebook", name:"react") {
    name
    description
  }
}
```

这次，我们要求`repository`对象，但传递了`owner`和`name`存储库的两个参数。我们要求返回存储库的`name`和`description`。

我们看到返回了我们请求的存储库和字段：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/820b1074-0293-4302-9c53-61794fbc8f16.png)

1.  现在让我们请求存储库的星星数量。为此，我们要求`stargazers`嵌套对象中的`totalCount`字段：

```jsx
query { 
  repository (owner:"facebook", name:"react") {
    name
    description
    stargazers {
 totalCount
 }
  }
}
```

如果我们执行查询，我们会看到返回的结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/66b94c04-5c0b-48b1-8c09-29d091fb8cdd.png)

1.  现在让我们给`stargazers`中的`totalCount`添加一个别名：

```jsx
stargazers {
  stars:totalCount
}
```

如果我们执行查询，我们会看到星星数量返回到我们指定的别名：

```jsx
{
  "data": {
    "repository": {
      "name": "react",
      "description": "A declarative, efficient, and flexible JavaScript library for building user interfaces.",
      "stargazers": {
        "stars": 114998
      }
    }
  }
}
```

1.  让我们继续请求存储库中的最后`5`个问题：

```jsx
{ 
  repository (owner:"facebook", name:"react") {
    name
    description
    stargazers {
      stars:totalCount
    }
    issues(last: 5) {
 edges {
 node {
 id
 title
 url
 publishedAt
 }
 }
 }
  }
}
```

我们通过将`5`传递到最后一个参数来请求`issues`对象。然后，我们请求包含我们感兴趣的问题字段的`edges`对象中的`node`对象。

那么，`edges`和`node`对象是什么？为什么我们不能直接请求我们想要的字段？嗯，这种结构是为了方便基于游标的分页。

如果我们执行查询，我们会得到结果中包含的最后`5`个问题。

因此，GraphQL 允许我们为不同的数据部分进行单个网络请求，只返回我们需要的字段。使用 GitHub REST API 进行类似的操作可能需要多个请求，并且我们会得到比我们需要的更多的数据。在这些类型的查询中，GraphQL 比 REST 更出色。

# 查询参数

我们刚刚进行的查询是硬编码的，用于获取特定存储库的数据。在本节中，我们将在查询中定义变量，这些变量基本上允许将参数传递给它：

1.  我们可以在`query`关键字后的括号中添加查询变量，用逗号分隔。每个参数都通过在分号后声明其类型来定义其名称。这类似于在 TypeScript 函数中使用类型注释定义参数。变量名需要以`$`为前缀。类型后面的`!`表示这是必需的。因此，在我们的情况下，为了执行查询，这两个变量都是必需的。然后可以在查询中引用这些变量，在我们的例子中，这是我们请求存储库对象的地方：

```jsx
query ($org: String!, $repo: String!) { 
  repository (owner:$org, name:$repo) {
    ...
  }
}
```

1.  在执行查询之前，我们需要指定变量值。我们在左下角的查询变量窗格中以 JSON 对象的形式进行此操作：

```jsx
{
  "org": "facebook",
  "repo": "react"
}
```

1.  如果我们执行查询，我们将得到我们请求的存储库的结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/d36c468d-b097-46fb-84b8-70003a910a11.png)

我们现在已经开始习惯从 GraphQL 服务器中读取数据。但是我们如何创建新的数据项或更新数据呢？我们将在下一节中找到答案。

# 编写 GraphQL 数据

现在让我们把注意力转向写入 GraphQL 服务器。我们可以通过所谓的 mutations 来实现这一点。在本节中，我们将创建一个`mutation`来向存储库添加 GitHub 星标：

1.  为了收藏一个存储库，我们需要存储库的`id`。因此，让我们将这个添加到我们一直在工作的查询中：

```jsx
query ($org: String!, $repo: String!) { 
  repository (owner:$org, name:$repo) {
    id
    ...
  }
}
```

1.  让我们复制结果中返回的`id`。React 存储库的`id`如下所示：

```jsx
MDEwOlJlcG9zaXRvcnkxMDI3MDI1MA==
```

1.  现在我们可以写我们的第一个`mutation`：

```jsx
mutation ($repoId: ID!) {
  addStar(input: { starrableId: $repoId }) {
    starrable {
      stargazers {
        totalCount
      }
    }
  }
}
```

以下是关于这个`mutation`的一些关键点：

+   我们用`mutation`关键字作为前缀来定义一个 mutation。

+   我们将要传递给`mutation`的参数放在`mutation`关键字后面的括号中。在我们的例子中，我们为要收藏的存储库`id`设置了一个参数。

+   `addStar`是我们正在调用的`mutation`函数，它有一个名为`input`的参数，我们需要传递给它。

+   `input`实际上是一个对象，其中包含一个名为`starrableId`的字段，我们需要包含它。其值是我们要收藏的存储库`id`，因此我们将其设置为我们的存储库`id`变量`$repoId`。

+   在`mutation`参数之后，我们可以指定我们希望在响应中返回什么。在我们的例子中，我们希望返回存储库上的星星数量。

1.  我们可以在查询变量窗格中指定存储库`id`的参数值：

```jsx
{
  "repoId": "MDEwOlJlcG9zaXRvcnkxMDI3MDI1MA=="
}
```

1.  如果我们执行`mutation`，星星将被添加到存储库中，并且新的总星星数量将被返回：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/752ea09d-7729-43ef-b88a-b1ad8cb04a40.png)

现在我们对 GraphQL 查询和变异都有了很好的掌握。在下一节中，我们将开始从 React 和 TypeScript 应用程序与 GraphQL 服务器进行交互。

# 使用 axios 作为 GraphQL 客户端

与 GraphQL 服务器的交互是通过 HTTP 完成的。我们在第九章中学到，*与 Restful API 交互*，`axios`是一个很好的 HTTP 客户端。因此，在本章中，我们将介绍如何使用`axios`与 GraphQL 服务器进行交互。

为了帮助我们学习，我们将创建一个 React 和 TypeScript 应用程序来返回有关我们 GitHub 帐户的信息。因此，我们的第一个任务是获取一个令牌，以便我们可以访问查询 GitHub GraphQL 服务器并搭建一个 React 和 TypeScript 应用程序。

# 生成 GitHub 个人访问令牌

GitHub GraphQL 服务器需要一个令牌才能与其进行交互。所以，让我们去生成一个个人访问令牌：

1.  让我们登录到我们的 GitHub 帐户，并通过打开头像下的菜单并选择设置来进入我们的设置页面。

1.  在左侧菜单中，我们需要选择开发者设置选项。这将带我们到开发者设置页面。

1.  然后我们可以在左侧菜单中选择个人访问令牌选项。

1.  然后我们将看到一个生成新令牌的按钮，我们可以点击它来生成我们的令牌。点击按钮后，我们可能会被提示输入密码。

1.  在生成令牌之前，我们被要求指定范围。让我们输入一个令牌描述，选中 repo 和 user，然后点击生成令牌按钮。

1.  然后生成的令牌将显示在页面上供我们复制并在我们的 React 应用程序中使用。

既然我们有了我们的令牌，让我们在下一节中搭建一个 React 和 TypeScript 应用程序。

# 创建我们的应用程序

我们将按照通常的步骤来搭建一个 React 和 TypeScript 应用程序：

1.  让我们在我们选择的文件夹中打开 Visual Studio Code 并打开终端。让我们输入以下命令来创建一个新的 React 和 TypeScript 项目：

```jsx
npx create-react-app repo-search --typescript
```

请注意，我们使用的 React 版本至少需要是`16.7.0-alpha.0`版本。我们可以在`package.json`文件中检查这一点。如果`package.json`中的 React 版本小于`16.7.0-alpha.0`，那么我们可以使用以下命令安装这个版本：

```jsx
npm install react@16.7.0-alpha.0
npm install react-dom@16.7.0-alpha.0
```

1.  项目创建后，让我们将 TSLint 作为开发依赖项添加到我们的项目中，并添加一些适用于 React 和 Prettier 的规则：

```jsx
cd repo-search
npm install tslint tslint-react tslint-config-prettier --save-dev
```

1.  现在让我们添加一个包含一些规则的`tslint.json`文件：

```jsx
{
  "extends": ["tslint:recommended", "tslint-react", "tslint-config-
   prettier"],
  "rules": {
    "ordered-imports": false,
    "object-literal-sort-keys": false,
    "jsx-no-lambda": false,
    "no-debugger": false,
    "no-console": false,
  },
  "linterOptions": {
    "exclude": [
      "config/**/*.js",
      "node_modules/**/*.ts",
      "coverage/lcov-report/*.js"
    ]
  }
}
```

1.  如果打开`App.tsx`，会出现一个 linting 错误。所以，让我们通过在`render`方法上添加`public`作为修饰符来解决这个问题：

```jsx
class App extends Component {
  public render() {
    return ( ... );
  }
}
```

1.  现在我们可以使用`npm`安装`axios`：

```jsx
npm install axios
```

1.  在继续开发之前，让我们先启动我们的应用程序：

```jsx
npm start
```

1.  在我们使用`axios`进行第一个 GraphQL 查询之前，让我们在`src`目录中创建一个名为`Header.tsx`的新文件，其中包含以下`import`：

```jsx
import React from "react";
import axios from "axios";
```

这个组件最终将包含我们从 GitHub 获取的姓名和头像。

1.  暂时让我们的`Header`组件返回空值：

```jsx
export const Header: React.SFC = () => {
  return null;
}
```

1.  现在让我们回到`App.tsx`，并导入我们刚刚创建的`Header`组件：

```jsx
import { Header } from "./Header";
```

1.  现在我们可以调整`App.tsx`中的 JSX，包括我们的`Header`组件：

```jsx
<div className="App">
  <header className="App-header">
    <Header />
  </header>
</div>
```

1.  作为本节的最后一个任务，让我们在`App.css`中更改`App-Header`的 CSS 类，以便标题不那么高：

```jsx
.App-header {
  background-color: #282c34;
  min-height: 200px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  color: white;
}
```

# 查询 GraphQL 服务器

现在我们已经有了我们的 React 和 TypeScript 项目，让我们使用`axios`进行 GraphQL 查询：

1.  在`Header.tsx`中，我们将首先为 GraphQL 查询响应和其中的 viewer 数据创建两个接口：

```jsx
interface IViewer {
  name: string;
  avatarUrl: string;
}

interface IQueryResult {
  data: {
    viewer: IViewer;
  };
}
```

1.  让我们在`Header`组件中创建一些状态变量用于`viewer`：

```jsx
const [viewer, setViewer]: [
  IViewer,
  (viewer: IViewer) => void
] = React.useState({name: "", avatarUrl: ""});
```

1.  现在是时候进行 GraphQL 查询了。我们将在组件刚刚挂载时进行这个操作。我们可以使用`useEffect`函数来实现这一点：

```jsx
React.useEffect(() => {
  // TODO - make a GraphQL query 
}, []);
```

我们将一个空数组作为第二个参数传递，这样查询只会在组件挂载时执行，而不是在每次渲染时执行。

1.  然后让我们使用`axios`进行 GraphQL 查询：

```jsx
React.useEffect(() => {
  axios
 .post<IQueryResult>(
 "https://api.github.com/graphql",
 {
 query: `query { 
 viewer { 
 name
 avatarUrl
 }
 }`
 }
 )
}, []);
```

请注意，尽管我们正在读取数据，但我们正在进行 HTTP `POST`。GraphQL 要求我们使用 HTTP `POST`，因为查询的细节在请求体中。

我们还在使用之前使用的接口`IQueryResult`来处理响应数据。

1.  如前所述，我们需要在 HTTP 授权标头中传递我们的令牌。所以，让我们这样做：

```jsx
axios
  .post<IQueryResult>(
    "https://api.github.com/graphql",
    {
      query: `query { 
        viewer { 
          name
          avatarUrl
        }
      }`
    },
    {
 headers: {
 Authorization: "bearer our-bearer-token"
 }
 }
  )
```

显然，我们需要用我们之前从 GitHub 获取的真实令牌来替换。

1.  我们还没有处理响应，所以让我们设置`viewer`状态变量：

```jsx
axios
  .post<IQueryResult>(
    ...
  )
  .then(response => {
```

```jsx
 setViewer(response.data.data.viewer);
 });
```

1.  现在我们已经从 GraphQL 查询中获取了数据，让我们渲染我们的头像和姓名以及我们的应用程序标题：

```jsx
return (
  <div>
 <img src={viewer.avatarUrl} className="avatar" />
 <div className="viewer">{viewer.name}</div>
 <h1>GitHub Search</h1>
 </div>
);
```

1.  让我们将刚刚引用的头像 CSS 类添加到`App.css`中：

```jsx
.avatar {
  width: 60px;
  border-radius: 50%;
}
```

如果我们查看正在运行的应用程序，应该在应用程序标题中看到我们的头像和姓名：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5c79a089-47eb-4047-a948-bf5126dc206f.png)

因此，我们刚刚使用了一个 HTTP 库与 GraphQL 服务器进行交互。所有 GraphQL 请求都是使用 HTTP POST 方法进行的，即使是用于读取数据的请求也是如此。所有 GraphQL 请求也都是发送到同一个端点。我们想要从中获取数据的资源不在 URL 中，而是在请求体中。因此，虽然我们可以使用 HTTP 库，比如`axios`，来查询 GraphQL 服务器，但感觉有点奇怪。

在下一节中，我们将看一下一个 GraphQL 客户端，它将帮助我们以更自然的方式查询 GraphQL 服务器。

# 使用 Apollo GraphQL 客户端

Apollo 客户端是一个用于与 GraphQL 服务器交互的客户端库。它比使用通用 HTTP 库如`axios`有许多优点，比如能够在我们的 JSX 中以声明方式读写数据，并且开箱即用地启用缓存。

在本节中，我们将重构上一节中使用`axios`构建的内容，以使用 Apollo，并且稍微扩展我们的应用程序以包括 GitHub 仓库搜索。

# 安装 Apollo 客户端

我们的第一项工作是将 Apollo 安装到我们的项目中。

1.  要将 Apollo 客户端添加到我们的项目中，让我们通过`npm`安装以下包：

```jsx
npm install apollo-boost react-apollo graphql
```

+   `apollo-boost`包含了我们设置 Apollo 客户端所需的一切

+   `react-apollo`包含了我们将用来与 GraphQL 服务器交互的 React 组件

+   `graphql`是一个核心包，我们将用它来解析 GraphQL 查询

1.  我们还将为`graphql`安装一些 TypeScript 类型：

```jsx
npm install @types/graphql --save-dev
```

1.  我们需要确保 TypeScript 在编译我们的代码时包含`es2015`和`esNext`库。因此，让我们在`tsconfig.json`中添加以下`lib`字段：

```jsx
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["es2015", "dom", "esnext"],
    ...
  },
  ...
}
```

现在我们已经准备好开始使用 Apollo 与 GitHub GraphQL 服务器进行交互了。

# 从 axios 迁移到 Apollo

现在我们已经安装了所有 Apollo 的部分，让我们将我们的`axios`代码迁移到 Apollo。

# 添加 Apollo 提供程序

我们将从`App.tsx`开始，在那里我们将定义我们的 Apollo 客户端并*提供*给`App`组件层次结构下的所有组件：

1.  在`App.tsx`中，让我们导入`apollo-boost`，以及从`react-apollo`导入`ApolloProvider`组件：

```jsx
import ApolloClient from "apollo-boost";
import { ApolloProvider } from "react-apollo";
```

1.  在`App`类组件的上方，让我们创建我们的`ApolloClient`：

```jsx
const client = new ApolloClient({
  uri: "https://api.github.com/graphql",
  headers: {
    authorization: `Bearer our-bearer-token`
  }
});
```

显然，我们需要用我们之前从 GitHub 获取的真实令牌来替换它。

1.  最后一步是使用`ApolloProvider`组件将我们创建的`ApolloClient`提供给应用中的所有其他组件。我们通过将`ApolloProvider`作为根组件，并将`ApolloClient`对象传递给它来实现这一点：

```jsx
public render() {
  return (
    <ApolloProvider client={client}>
      <div className="App">
        <header className="App-header">
          <Header />
        </header>
      </div>
    </ApolloProvider>
  );
}
```

现在`ApolloClient`已经设置好了，我们可以开始与 GraphQL 服务器进行交互了。

# 使用查询组件查询 GraphQL

我们现在要使用`Query`组件来获取我们的 GitHub 姓名和头像，替换`axios`代码：

1.  让我们首先删除`axios`导入语句，而不是有以下导入：

```jsx
import gql from "graphql-tag";
import { Query } from "react-apollo";
```

1.  我们的`IViewer`接口将保持不变，但我们需要稍微调整我们的`IQueryResult`接口：

```jsx
interface IQueryResult {
  viewer: IViewer;
}
```

1.  我们接下来要定义我们的 GraphQL 查询：

```jsx
const GET_VIEWER = gql`
  {
    viewer {
      name
      avatarUrl
    }
  }
`;
```

所以，我们将查询设置为`GET_VIEWER`变量，并在模板文字中定义了我们的查询。然而，在模板文字之前的`gql`函数有点奇怪。模板文字不应该在括号中吗？实际上，这被称为标记模板文字，其中来自核心 GraphQL 库的`gql`函数解析其旁边的模板文字。我们最终得到了一个 Apollo 可以使用和执行的`GET-VIEWER`中的查询。

1.  我们现在要开始定义我们的查询。我们可以直接在 JSX 中使用`react-apollo`中的`Query`组件定义我们的查询。然而，为了增加一些类型安全性，我们将创建一个名为`GetViewerQuery`的新组件，该组件继承自`Query`并将结果类型定义为泛型参数：

```jsx
class GetViewerQuery extends Query<IQueryResult> {}
```

1.  我们不再需要任何状态，所以我们可以删除`viewer`和`setViewer`变量。

1.  我们还可以删除使用`useEffect`函数调用`axios`查询的部分，因为我们现在要在 JSX 中进行查询。

1.  所以，让我们使用我们的`GetViewerQuery`组件来调用我们的查询：

```jsx
return (
  <GetViewerQuery query={GET_VIEWER}>
    {({ data }) => {
      if (!data || !data.viewer) {
        return null;
      }
      return (
        <div>
          <img src={data.viewer.avatarUrl} className="avatar" />
          <div className="viewer">{data.viewer.name}</div>
          <h1>GitHub Search</h1>
        </div>
      );
    }}
  </GetViewerQuery>
);
```

+   我们将我们之前创建的查询作为`query`属性传递给`GetViewerQuery`组件。

+   查询结果在`GetViewerQuery`的 children 函数中返回。

+   children 函数参数包含一个包含`data`属性中数据的对象。我们将这些数据解构到一个`data`变量中。

+   如果没有任何数据，我们会提前退出并返回`null`。

+   如果我们有数据，然后返回我们的头像和姓名的 JSX，引用`data`属性。

如果我们查看我们正在运行的应用程序，它应该与`axios`版本完全相同。如果显示错误，我们可能需要再次`npm start`应用程序。

1.  我们可以从 children 函数参数中获取其他信息。一个有用的信息是数据是否正在加载。让我们使用这个来显示一个加载消息：

```jsx
return (
  <GetViewerQuery query={GET_VIEWER}>
    {({ data, loading }) => {
      if (loading) {
 return <div className="viewer">Loading ...</div>;
 }
      ...
    }}
  </GetViewerQuery>
);
```

1.  我们可以从 children 函数参数中获取的另一个有用的信息是有关发生的错误的信息。让我们使用这个来显示错误消息，如果有的话：

```jsx
return (
  <GetViewerQuery query={GET_VIEWER}>
    {({ data, loading, error }) => {
      if (error) {
 return <div className="viewer">{error.toString()}</div>;
 }
      ...
    }}
  </GetViewerQuery>
);
```

这个 Apollo 实现真的很优雅。`Query`组件如何在组件生命周期的正确时刻进行网络请求，并允许我们向其余的组件树提供数据，真是聪明。

在下一节中，我们将继续使用 Apollo 来增强我们的应用程序。

# 添加一个仓库搜索组件

在这一部分，我们将添加一个组件来搜索 GitHub 仓库并返回一些关于它的信息：

1.  让我们首先创建一个名为`RepoSearch.tsx`的新文件，其中包含以下导入：

```jsx
import * as React from "react";
import gql from "graphql-tag";
import { ApolloClient } from "apollo-boost";
```

1.  我们将以`ApolloClient`作为 prop 传入。因此，让我们为此添加一个接口：

```jsx
interface IProps {
  client: ApolloClient<any>;
}
```

1.  接下来，我们将搭建我们的组件：

```jsx
const RepoSearch: React.SFC<IProps> = props => {
  return null;
}

export default RepoSearch;
```

1.  现在让我们在`App.tsx`中引用这个，首先导入它：

```jsx
import RepoSearch from "./RepoSearch";
```

1.  现在我们可以将其添加到应用程序标题下，传入`ApolloClient`：

```jsx
<ApolloProvider client={client}>
  <div className="App">
    <header className="App-header">
      <Header />
    </header>
    <RepoSearch client={client} />
  </div>
</ApolloProvider>
```

我们的仓库`search`组件现在已经很好地设置好了。在下一节中，我们可以实现一个搜索表单。

# 实现搜索表单

让我们实现一个搜索表单，允许用户提供组织名称和仓库名称：

1.  回到`RepoSearch.tsx`，让我们开始定义搜索字段的状态，从接口开始：

```jsx
interface ISearch {
  orgName: string;
  repoName: string;
}
```

1.  现在我们可以创建一个变量来保存我们的`search`状态，以及一个设置它的函数：

```jsx
const RepoSearch: React.SFC<IProps> = props => {
  const [search, setSearch]: [
 ISearch,
 (search: ISearch) => void
 ] = React.useState({
 orgName: "",
 repoName: ""
 });

  return null;
}
```

1.  让我们在 JSX 中定义`search`表单：

```jsx
return (
  <div className="repo-search">
    <form onSubmit={handleSearch}>
      <label>Organization</label>
      <input
        type="text"
        onChange={handleOrgNameChange}
        value={search.orgName}
      />
      <label>Repository</label>
      <input
        type="text"
        onChange={handleRepoNameChange}
        value={search.repoName}
      />
      <button type="submit">Search</button>
    </form>
  </div>
);
```

我们引用了一些尚未实现的部分。因此，我们将逐一实现这些。

1.  让我们添加在`App.css`中引用的`repo-search`类。我们还将为标签和输入以及搜索按钮添加样式：

```jsx
.repo-search {
  margin: 30px auto;
  width: 300px;
  font-family: Arial;
  font-size: 16px;
  text-align: left;
}

.repo-search label {
  display: block;
  margin-bottom: 3px;
  font-size: 14px;
}

.repo-search input {
  display: block;
  margin-bottom: 10px;
  font-size: 16px;
  color: #676666;
  width: 100%;
}

.repo-search button {
  display: block;
  margin-bottom: 20px;
  font-size: 16px;
}
```

1.  接下来，让我们实现简单更新`search`状态的输入更改处理程序：

```jsx
const handleOrgNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  setSearch({ ...search, orgName: e.currentTarget.value });
};

const handleRepoNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  setSearch({ ...search, repoName: e.currentTarget.value });
};
```

1.  我们需要实现的最后一部分是`search`处理程序：

```jsx
const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();

  // TODO - make GraphQL query
};
```

我们在事件参数上调用`preventDefault`来阻止发生完整的后退。

所以，搜索表单已经开始了。我们将在下一节中实现 GraphQL 查询。

# 实现搜索查询

我们现在到了需要进行 GraphQL 查询来实际搜索的地步：

1.  让我们首先为我们期望从查询中获取的仓库数据创建一个接口：

```jsx
interface IRepo {
  id: string;
  name: string;
  description: string;
  viewerHasStarred: boolean;
  stargazers: {
    totalCount: number;
  };
  issues: {
    edges: [
      {
        node: {
          id: string;
          title: string;
          url: string;
        };
      }
    ];
  };
}
```

这是我们在之前的部分中从 GitHub GraphQL Explorer 中得到的结构。

1.  我们将需要为这个状态设置一个默认值。所以，让我们定义这个：

```jsx
const defaultRepo: IRepo = {
  id: "",
  name: "",
  description: "",
  viewerHasStarred: false,
  stargazers: {
    totalCount: 0
  },
  issues: {
    edges: [
      {
        node: {
          id: "",
          title: "",
          url: ""
        }
      }
    ]
  }
};
```

1.  我们还可以为整个查询结果定义一个接口：

```jsx
interface IQueryResult {
  repository: IRepo;
}
```

1.  现在我们可以使用标记模板字面量来创建查询本身：

```jsx
const GET_REPO = gql`
  query GetRepo($orgName: String!, $repoName: String!) {
    repository(owner: $orgName, name: $repoName) {
      id
      name
      description
      viewerHasStarred
      stargazers {
        totalCount
      }
      issues(last: 5) {
        edges {
          node {
            id
            title
            url
            publishedAt
          }
        }
      }
    }
  }
`;
```

这是我们在之前的部分中在 GitHub GraphQL Explorer 中进行的查询。与以前的查询不同，这个查询有一些参数，我们需要在稍后执行查询时包含这些参数。

1.  我们需要将从查询中获取的数据存储在状态中。所以，让我们创建一个名为`repo`的状态变量，以及一个设置它的函数：

```jsx
const [repo, setRepo]: [
    IRepo,
    (repo: IRepo) => void
  ] = React.useState(defaultRepo);
```

1.  我们还将在状态中存储`search`的任何问题：

```jsx
const [searchError, setSearchError]: [
  string,
  (searchError: string) => void
] = React.useState("");
```

1.  让我们更新`handleSearch`箭头函数，在进行`search`之前清除任何搜索错误状态：

```jsx
const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();

  setSearchError("");
};
```

1.  让我们继续使用作为属性传递的`ApolloClient`来进行查询：

```jsx
const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();

  setSearchError("");

  props.client
 .query<IQueryResult>({
 query: GET_REPO
 });
};
```

1.  这里还有更多的工作要做。首先，我们需要从我们在`search`状态中拥有的值中传递`query`参数，用于组织名称和仓库名称：

```jsx
.query<IQueryResult>({
  query: GET_REPO,
  variables: { orgName: search.orgName, repoName: search.repoName }
})
```

1.  现在是时候在`then`方法中处理响应并将`repo`状态设置为响应中的数据了：

```jsx
props.client
  .query<IQueryResult>( ... )
  .then(response => {
 setRepo(response.data.repository);
 });
```

1.  我们还将在`catch`方法中处理任何错误，并更新`searchError`状态：

```jsx
props.client
  .query<IQueryResult>(...)
  .then(...)
  .catch(error => {
 setSearchError(error.message);
 });
```

如果我们在运行的应用中尝试进行`search`，查询将会正常进行，但我们还没有显示结果。让我们在下一部分中做这件事。

# 渲染搜索结果

让我们渲染从仓库查询中获取的数据：

1.  如果我们有搜索结果，让我们在`search`表单下渲染仓库名称及其星数以及描述：

```jsx
return (
  <div className="repo-search">
    <form ...>
      ...
    </form>
    {repo.id && (
 <div className="repo-item">
 <h4>
 {repo.name}
 {repo.stargazers ? ` ${repo.stargazers.totalCount}
           stars` : ""}
 </h4>
 <p>{repo.description}</p>
 </div>
 )}
  </div>
);
```

1.  我们还将渲染最后的`5`个仓库问题：

```jsx
...
<p>{repo.description}</p>
<div>
 Last 5 issues:
 {repo.issues && repo.issues.edges ? (
 <ul>
 {repo.issues.edges.map(item => (
 <li key={item.node.id}>{item.node.title}</li>
 ))}
 </ul>
 ) : null}
</div>
```

1.  如果出现问题，让我们渲染在状态中捕获的错误消息：

```jsx
{repo.id && (
  ...
)}
{searchError && <div>{searchError}</div>}
```

1.  让我们在`App.css`中为搜索结果中的仓库标题添加一些 CSS：

```jsx
.repo-search h4 {
  text-align: center;
}
```

如果我们搜索一个仓库，现在应该看到有关仓库的信息被渲染出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/9c544071-6f5f-4299-b1fe-60604a62c400.png)

我们现在已经可以使用 Apollo 舒适地查询 GraphQL 服务器了。在下一部分，我们将处理变异。

# 使用 Apollo 实现变异

让我们允许用户在我们的应用中为 GitHub 仓库加星。这将涉及通过 Apollo 发送一个`mutation`：

1.  首先，让我们从`react-apollo`中导入`Mutation`组件：

```jsx
import { Mutation } from "react-apollo";
```

1.  现在让我们创建`mutation`。这是我们之前在 GitHub GraphQL Explorer 中执行的相同查询：

```jsx
const STAR_REPO = gql`
  mutation($repoId: ID!) {
    addStar(input: { starrableId: $repoId }) {
      starrable {
        stargazers {
          totalCount
        }
      }
    }
  }
`;
```

1.  在 JSX 中，在我们渲染描述的地方，让我们放置`Mutation`组件：

```jsx
<p>{repo.description}</p>
<div>
 {!repo.viewerHasStarred && (
 <Mutation
 mutation={STAR_REPO}
 variables={{ repoId: repo.id }}
 >
 {() => (
 // render Star button that invokes the mutation when 
           clicked
 )}
 </Mutation>
 )}
</div> <div>
  Last 5 issues:
  ...
</div>
```

+   只有在`viewer`还没有给存储库添加星标时，我们才渲染`mutation`

+   `Mutation`组件接受我们刚刚定义的 mutation 以及变量，这在我们的情况下是存储库的`id`

1.  `Mutation`组件有一个 children 函数，它给了我们访问`addStar`函数的权限。因此，让我们渲染一个 Star!按钮，当点击时调用`addStar`：

```jsx
<Mutation
    ...
  >
    {(addStar) => (
      <div>
 <button onClick={() => addStar()}>
 Star!
 </button>
 </div>
    )}
  </Mutation>
)}
```

1.  `Mutation`组件还告诉我们`mutation`正在执行，通过 children 函数的第二个参数中的`loading`属性。让我们使用这个来禁用按钮，并通知用户星标正在被添加：

```jsx
<Mutation
  ...
>
  {(addStar, { loading }) => (
    <div>
      <button disabled={loading} onClick={() => addStar()}>
        {loading ? "Adding ..." : "Star!"}
      </button>
    </div>
  )}
</Mutation>
```

1.  `Mutation`组件还告诉我们是否有错误。因此，让我们使用这个并在发生错误时渲染错误：

```jsx
<Mutation
  ...
>
  {(addStar, { loading, error }) => (
    <div>
      <button ...>
        ...
      </button>
      {error && <div>{error.toString()}</div>}
    </div>
  )}
</Mutation>
```

如果我们尝试给存储库添加星标，星标应该会成功添加。我们可以去 GitHub 存储库的[github.com](http://github.com)验证这一点。

现在我们已经实现了查询和`mutation`，我们真正掌握了 Apollo。不过，有一件事情有点奇怪，也许我们已经注意到了。在我们给存储库添加星标后，应用程序中星标的数量没有更新。即使我们再次搜索存储库，星标的数量仍然是我们开始之前的数量。但是，如果我们刷新浏览器并再次搜索存储库，我们会得到正确的星标数量。那么，这是怎么回事呢？我们将在下一节中找出答案。

# 在 Apollo 中使用缓存数据

我们在上一节结束时留下了一个谜。为什么我们在开始搜索后没有得到存储库`search`的最新星标数量？答案是 Apollo 在初始`search`后缓存了存储库数据。当执行相同的查询时，它会从缓存中获取结果，而不是从 GraphQL 服务器获取数据。

让我们再次确认一下：

1.  让我们打开应用程序并在网络选项卡上打开开发者工具，并清除之前的请求：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/d4bd5ab2-fc05-49c9-a31f-82612fa19b0d.png)

1.  让我们进行一次搜索。我们会看到向 GitHub GraphQL 服务器发出了几个请求：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/0230f74a-065e-4dbc-97e3-304efea83194.png)

1.  在开发者工具中，网络选项卡，让我们清除请求，然后在我们的应用程序中再次点击搜索按钮。我们会看到没有网络请求被发出，但数据被渲染出来。所以，数据一定是来自本地缓存。

所以，我们使用`apollo-boost`配置的`ApolloClient`会自动将查询缓存到内存中。在下一节中，我们将学习如何清除缓存，以便我们的应用程序在仓库被加星后显示正确的星星数量。

# 使用`refetchQueries`清除缓存

在`mutation`发生后，我们需要一种清除缓存查询结果的方法。一种方法是在`Mutation`组件上使用`refetchQueries`属性：

1.  让我们试一试。`refetchQueries`属性接受一个包含应该从缓存中移除的具有相应变量值的查询对象数组：

```jsx
<Mutation
  mutation={STAR_REPO}
  variables={{ repoId: repo.id }}
  refetchQueries={[
 {
 query: GET_REPO,
 variables: {
 orgName: search.orgName,
 repoName: search.repoName
 }
 }
 ]}
>
  ...
</Mutation>
```

1.  如果我们现在给一个仓库加星标，星星的数量不会立即更新。然而，如果按下搜索按钮，星星就会更新。

所以，缓存已经清除，但是体验仍然不理想。理想情况下，我们希望在点击“Star！”按钮后立即更新星星的数量。

如果我们仔细思考刚才做的事情，我们正在试图绕过缓存。然而，缓存的存在是为了帮助我们的应用程序表现良好。

所以，这种方法并不理想。用户体验仍然不理想，我们刚刚使我们的应用程序性能下降了。一定有更好的方法！我们将在下一节中探索另一种方法。

# 在 Mutation 后更新缓存

让我们再次仔细思考一下问题：

+   我们在缓存中有关于仓库的一些信息，包括它拥有的星星数量。

+   当我们给仓库加星标时，我们希望看到星星的数量增加了一个。

+   如果我们可以在缓存中将星星的数量增加一个，那会怎么样？这应该能解决问题。

所以，让我们尝试一下，在`mutation`完成后更新缓存：

1.  首先，让我们移除上一节中实现的`refetchQueries`属性。

1.  `Mutation`组件上有一个`update`属性，我们可以利用它来更新缓存。所以，让我们开始实现这个功能：

```jsx
<Mutation
  mutation={STAR_REPO}
  update={cache => {
 // Get the cached data 
 // update the cached data
 // update our state 
 }}
>
  ...
</Mutation>
```

1.  所以，我们需要实现一个箭头函数，更新可用作参数的缓存：

```jsx
<Mutation
  ...
  update={cache => {
 const data: { repository: IRepo } | null = cache.readQuery({
 query: GET_REPO,
 variables: {
 orgName: search.orgName,
 repoName: search.repoName
 }
 });
 if (data === null) {
 return;
 }
 }}
>
  ...
</Mutation>
```

所以，缓存有一个`readQuery`函数，我们可以使用它来获取缓存的数据。如果在缓存中找不到数据，那么我们可以退出函数而不做其他事情。

1.  因此，现在我们从缓存中获取了数据，我们可以增加星星的数量。为此，我们创建一个新对象，并将缓存存储库的属性扩展到其中，并用增加的星星数量和查看者已经为存储库加星的事实覆盖它：

```jsx
update={cache => {
  ...
  if (data === null) {
    return;
  }
  const newData = {
 ...data.repository,    viewerHasStarred: true,
 stargazers: {
 ...data.repository.stargazers,
 totalCount: data.repository.stargazers.totalCount + 1
 }
 };
}}
```

1.  然后，我们可以使用其`writeQuery`函数更新缓存。我们传入带有变量值的查询和要存储在缓存中的新数据：

```jsx
update={cache => {
  ...
  const newData = {
    ...
  };
 cache.writeQuery({
 query: GET_REPO,
 variables: {
 orgName: search.orgName,
 repoName: search.repoName
 },
 data: { repository: newData }
 });
}}
```

1.  还有一件事要做，那就是更新`repo`状态，以便星星的数量立即在屏幕上更新：

```jsx
update={cache => {
  ...
  cache.writeQuery(...);
  setRepo(newData);
}}
```

就是这样。如果我们再次尝试在应用程序中为存储库加星，我们应该会看到星星的数量立即增加。

缓存是 Apollo 提供的伟大功能之一。`Mutation`组件上的`update`属性为我们提供了一种精确更新缓存的方式。`Mutation`组件上的`refetchQueries`属性是一种更粗暴且效率低下的强制更新缓存的方式。

# 总结

GraphQL 比 REST 更出色，因为它允许我们以更少的努力有效地获取所需的数据。GitHub GraphQL Explorer 是一个很好的工具，可以让我们熟悉语法。我们可以向 GraphQL 服务器发出两种主要类型的请求：

+   我们可以执行`query`来读取数据

+   我们可以执行`mutation`来写入数据

查询允许我们指定响应中需要的对象和字段。我们可以使用别名来重命名它们。我们可以通过定义变量来参数化查询。我们可以给变量类型，并在末尾使用`!`来指定每个变量是否是必需的。本章中我们没有涵盖的查询功能还有条件包含字段和强大的分页功能。总之，这是一种非常强大的查询语言！

变异与查询有一些相同的特性，比如能够向它们传递参数。我们可以控制响应中包含的数据，这真是太棒了。

GraphQL 通过 HTTP 运行，使用 HTTP `POST`请求到单个 URL。HTTP 正文包含查询或`mutation`信息。我们可以使用 HTTP 客户端与 GraphQL 服务器交互，但使用专门与 GraphQL 服务器交互的 Apollo 等库可能会更有效率。

React Apollo 是一组与核心 Apollo 库配合使用的 React 组件。它为我们提供了很好的`Query`和`Mutation`React 组件，用于在我们的 JSX 中包含查询和变更，使我们的代码更易于阅读。在我们使用这些组件之前，我们需要设置我们的`ApolloClient`对象，包括 GraphQL 服务器的 URL 和任何凭据。我们还需要在我们的组件树的顶部包含一个`ApolloProvider`组件，高于所有需要 GraphQL 数据的组件。

当我们使用`apollo-boost`搭建项目时，缓存默认开启。`Mutation`组件给了我们`update`和`refetchQueries`属性来管理缓存更新。

总的来说，GraphQL 是与后端交互的一种非常高效的方式，它与 React 和 TypeScript 应用程序非常配合。

因此，到目前为止，我们在这本书中学到了许多关于 React 和 TypeScript 的不同方面。一个我们尚未涉及的重要主题是如何对我们构建的应用进行健壮的测试。我们将在下一章中介绍这个主题。

# 问题

让我们尝试一些问题，来测试我们刚刚学到的知识：

1.  在 GitHub GraphQL Explorer 中，创建一个查询，返回 React 项目中最后五个未解决的问题。在响应中返回问题标题和 URL。

1.  增强最后一个查询，并使返回的问题数量成为一个参数，并将其默认设置为五。

1.  在 GitHub GraphQL Explorer 中创建一个`mutation`来取消对一个已标星的存储库的标星。`mutation`应该以一个必需的存储库`id`作为参数。

1.  GraphQL 查询的哪一部分放在 HTTP 请求中？

1.  GraphQL `mutation`的哪一部分放在 HTTP 请求中？

1.  如何使`react-apollo`的`Query`组件的响应类型安全？

1.  使用`react-boost`搭建项目时，默认情况下是否开启缓存？

1.  我们可以在`Mutation`组件上使用哪个属性来更新本地缓存？

# 进一步阅读

以下链接是关于 GraphQL、React 和 Apollo 的进一步信息的好资源：

+   GraphQL 文档位于[`graphql.org/learn/`](https://graphql.org/learn/)

+   Apollo 文档位于[`www.apollographql.com/docs/`](https://www.apollographql.com/docs/)

+   Apollo 文档中关于 React 部分的链接是[`www.apollographql.com/docs/react/`](https://www.apollographql.com/docs/react/)


# 第十一章：使用 Jest 进行单元测试

构建一个强大的单元测试套件，捕捉真正的错误并在重构代码时不会误报阳性，是我们作为软件开发人员所做的最艰巨的任务之一。Jest 是一个很好的测试工具，可以帮助我们应对这一挑战，我们将在本章中了解到。

也许应用程序中最容易进行单元测试的部分是纯函数，因为没有副作用需要处理。我们将重新访问我们在第七章中构建的验证函数，*使用表单*，并对其进行一些单元测试，以便学习如何对纯函数进行单元测试。

在构建应用程序时，单元测试组件是我们将进行的最常见类型的单元测试。我们将详细了解它，并利用一个库来帮助我们实施测试，在重构代码时不会不必要地中断。

我们将学习什么是快照测试，以及如何利用它来更快地实现我们的测试。快照可以用于测试纯函数以及组件，因此它们是我们非常有用的工具。

模拟是一个具有挑战性的话题，因为如果我们模拟得太多，我们实际上并没有测试我们的应用程序。然而，有一些依赖关系是有意义的，比如 REST API。我们将重新访问我们在第九章中构建的应用程序，*与 Restful API 交互*，以便对其实施一些单元测试并学习有关模拟的知识。

在为我们的应用程序实现一套单元测试时，了解我们已经测试过哪些部分以及哪些部分尚未测试是很有用的。我们将学习如何使用代码覆盖工具来帮助我们快速识别需要更多单元测试的应用程序区域。

本章将涵盖以下主题：

+   测试纯函数

+   测试组件

+   使用 Jest 快照测试

+   模拟依赖关系

+   获取代码覆盖率

# 技术要求

我们在本章中使用以下技术：

+   **Node.js 和`npm`**：TypeScript 和 React 依赖于这些。可以从以下链接安装它们：[`nodejs.org/en/download/`](https://nodejs.org/en/download)。如果您已经安装了这些，请确保`npm`至少是 5.2 版本。

+   **Visual Studio Code**：我们需要一个编辑器来编写我们的 React 和 TypeScript 代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要 TSLint 扩展（由 egamma 提供）和 Prettier 扩展（由 Estben Petersen 提供）。

+   **React 商店**：我们将在我们创建的 React 商店上实现单元测试。这可以在 GitHub 上的以下链接找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/08-ReactRedux%EF%BB%BF`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/08-ReactRedux%EF%BB%BF)。

+   **第九章代码**：我们将在第九章中创建的应用上实现单元测试，*与 RESTful API 交互*。这可以在 GitHub 上的以下链接找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/09-RestfulAPIs/03-AxiosWithClass`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/09-RestfulAPIs/03-AxiosWithClass)。

为了从之前的章节中恢复代码，可以下载`LearnReact17WithTypeScript`存储库，网址为[`github.com/carlrip/LearnReact17WithTypeScript`](https://github.com/carlrip/LearnReact17WithTypeScript)。然后可以在 Visual Studio Code 中打开相关文件夹，并在终端中输入`npm install`来进行恢复。本章中的所有代码片段都可以在以下链接找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/11-UnitTesting`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/11-UnitTesting)。

# 测试纯函数

我们将在本节中开始我们的单元测试之旅，通过对纯函数实现一个单元测试。

纯函数对于给定的参数值集合具有一致的输出值。纯函数仅依赖于函数参数，不依赖于函数外部的任何东西。这些函数也不会改变传递给它们的任何参数值。

这些函数仅依赖于它们的参数值，这使得它们很容易进行单元测试。

我们将在我们构建的 React 商店中的`Form`组件中创建的`required`验证函数上实现一个单元测试。如果还没有，请在 Visual Studio Code 中打开这个项目。

我们将使用 Jest 作为我们的单元测试框架，这在测试 React 应用中非常流行。幸运的是，`create-react-app`工具在创建项目时已经为我们安装和配置了 Jest。因此，Jest 已经准备好在我们的 React 商店项目中使用。

# 创建一个基本的纯函数测试

让我们在项目中创建我们的第一个单元测试，来测试`Form.tsx`中的`required`函数：

1.  首先在`src`文件夹中创建一个名为`Form.test.tsx`的文件。我们将使用这个文件来编写我们的测试代码，以测试`Form.tsx`中的代码。

`test.tsx`扩展名很重要，因为 Jest 在查找要执行的测试时会自动查找具有此扩展名的文件。请注意，如果我们的测试不包含任何 JSX，我们可以使用`test.ts`扩展名。

1.  让我们导入我们想要测试的函数，以及我们需要用于参数值的 TypeScript 类型：

```jsx
import { required, IValues } from "./Form";
```

1.  让我们开始使用 Jest 的`test`函数创建我们的测试：

```jsx
test("When required is called with empty title, 'This must be populated' should be returned", () => {
  // TODO: implement the test
});
```

`test`函数接受两个参数：

+   第一个参数是告诉我们测试是否通过的消息，将显示在测试输出中

+   第二个参数是包含我们的测试的箭头函数

1.  我们将继续调用`required`函数，并使用包含空`title`属性的`values`参数：

```jsx
test("When required called with title being an empty string, an error should be 'This must be populated'", () => {
  const values: IValues = {
 title: ""
 };
 const result = required("title", values);
  // TODO: check the result is correct
});
```

1.  我们在这个测试中的下一个任务是检查`required`函数的结果是否符合我们的期望。我们可以使用 Jest 的`expect`函数来做到这一点：

```jsx
test("When required called with title being an empty string, an error should be 'This must be populated'", () => {
  const values: IValues = {
    title: ""
  };
  const result = required("title", values);
  expect(result).toBe("This must be populated");
});
```

我们将要检查的变量传递给`expect`函数。然后我们在其后链接一个`toBe`匹配函数，它检查`expect`函数的结果是否与`toBe`函数提供的参数相同。

`toBe`是我们可以用来检查变量值的许多 Jest 匹配函数之一。完整的函数列表可以在[`jestjs.io/docs/en/expect`](https://jestjs.io/docs/en/expect)找到。

1.  现在我们的测试完成了，我们可以在终端中输入以下内容来运行测试：

```jsx
npm test
```

这将启动 Jest 测试运行程序的观察模式，这意味着它将持续运行，在更改源文件时执行测试。

Jest 最终会找到我们的测试文件，执行我们的测试，并将结果输出到终端，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5a80eb3d-465a-4d50-861d-6ea156f89e70.png)

1.  让我们更改测试中的预期结果，使测试失败：

```jsx
expect(result).toBe("This must be populatedX");
```

当我们保存测试文件时，Jest 会自动执行测试，并将失败输出到终端，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/a0719956-b0a4-44af-b67b-6a0b84b5f999.png)

Jest 为我们提供了有关失败的宝贵信息。它告诉我们：

+   哪个测试失败了

+   预期结果与实际结果的比较

+   我们测试代码中发生失败的那一行

这些信息帮助我们快速解决测试失败。

1.  在继续之前，让我们纠正我们的测试代码：

```jsx
expect(result).toBe("This must be populated");
```

当我们保存更改时，测试现在应该通过。

# 了解 Jest 观察选项

在 Jest 执行我们的测试后，它会提供以下选项：

```jsx
> Press f to run only failed tests.
> Press o to only run tests related to changed files.
> Press p to filter by a filename regex pattern.
> Press t to filter by a test name regex pattern.
> Press q to quit watch mode.
> Press Enter to trigger a test run.
```

这些选项让我们指定应该执行哪些测试，这对于测试数量增加时非常有用。让我们探索一些这些选项：

1.  如果我们按下*F*，Jest 将只执行失败的测试。在我们的代码中，我们得到确认我们没有失败的测试：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/92898667-2723-4795-8169-2cbe94f29d0b.png)

1.  让我们按下*F*键退出此选项，并返回到所有可用的选项。

1.  现在，让我们按下*P*。这允许我们测试特定文件或与正则表达式模式匹配的文件集合。当提示输入文件名模式时，让我们输入`form`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/0e1a490c-e71c-469c-914e-a5571eb66a0a.png)

我们在`Form.test.tsx`中的测试将会被执行。

1.  我们将保留文件名过滤器并按*T*。这将允许我们通过测试名称添加额外的过滤器。让我们输入`required`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/2d2f150e-883d-487e-8e72-1d83ec81a32c.png)

我们对`required`函数的测试将会被执行。

1.  要清除过滤器，我们可以按*C*。

如果我们收到错误信息——watch 不支持没有 git/hg，请使用--watchAll，这是因为我们的项目不在 Git 存储库中。我们可以通过在终端中输入`git init`命令来解决这个问题。

我们已经很好地掌握了可用于执行测试的选项。

# 为单元测试结果添加结构

随着我们实施更多的单元测试，将单元测试结果添加一些结构是很有用的，这样我们就可以更容易地阅读它们。有一个名为`describe`的 Jest 函数，我们可以用它来将某些测试的结果分组在一起。如果一个函数的所有测试都被分组在一起，可能会更容易阅读测试结果。

让我们这样做，并使用 Jest 中的`describe`函数重构我们之前创建的单元测试：

```jsx
describe("required", () => {
  test("When required called with title being an empty string, an error should be 'This must be populated'", () => {
    const values: IValues = {
      title: ""
    };
    const result = required("title", values);
    expect(result).toBe("This must be populated");
  });
});
```

describe 函数接受两个参数：

+   第一个参数是测试组的标题。我们已经为此使用了我们正在测试的函数名称。

+   第二个参数是包含要执行的测试的箭头函数。我们已经将我们的原始测试放在这里。

当我们保存我们的测试文件时，测试将自动运行，并且我们改进的输出将显示在终端上，测试结果显示在`required`标题下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/30db856d-4fbd-4bd0-8aa9-57bd32a074a8.png)

我们开始熟悉 Jest，已经实现并执行了一个单元测试。在下一节中，我们将继续进行更复杂的单元测试组件的主题。

# 测试组件

组件的单元测试是具有挑战性的，因为组件具有依赖项，如浏览器的 DOM 和 React 库。在我们进行必要的检查之前，我们如何在测试代码中渲染组件？在编写用户交互的代码时，如何触发 DOM 事件，比如点击按钮？

我们将在本节中回答这些问题，通过对我们在 React 商店中创建的`ContactUs`组件进行一些测试来实现。

# 创建一个基本组件测试

我们将首先创建一个单元测试，以验证在不填写字段的情况下提交“联系我们”表单会在页面上显示错误：

1.  我们将对`ContactUs`组件进行单元测试。我们将首先在`src`文件夹中创建一个名为`ContactUs.test.tsx`的文件。

1.  我们将使用`ReactDOM`来渲染`ContactUs`组件的测试实例。让我们导入`React`和`ReactDOM`：

```jsx
import React from "react";
import ReactDOM from "react-dom";
```

1.  我们将模拟表单提交事件，因此让我们从 React 测试工具中导入`Simulate`函数：

```jsx
import { Simulate } from "react-dom/test-utils";
```

1.  现在让我们导入需要测试的组件：

```jsx
import ContactUs from "./ContactUs";
```

1.  我们还需要从`Form.tsx`中导入提交结果接口：

```jsx
import { ISubmitResult } from "./Form";
```

1.  让我们开始使用 Jest 的`test`函数创建我们的测试，并将结果输出到`ContactUs`组。

```jsx
describe("ContactUs", () => {
  test("When submit without filling in fields should display errors", () => {
    // TODO - implement the test
  });
});
```

1.  我们测试实现中的第一个任务是在 DOM 中创建我们的 React 组件：

```jsx
test("When submit without filling in fields should display errors", () => {
  const handleSubmit = async (): Promise<ISubmitResult> => {
 return {
 success: true
 };
 };

 const container = document.createElement("div");
 ReactDOM.render(<ContactUs onSubmit={handleSubmit} />, container);

 // TODO - submit the form and check errors are shown

 ReactDOM.unmountComponentAtNode(container);
});
```

首先，我们创建一个容器`div`标签，然后将我们的`ContactUs`组件渲染到其中。我们还为`onSubmit`属性创建了一个处理程序，它返回成功。测试中的最后一行通过移除测试中创建的 DOM 元素来进行清理。

1.  接下来，我们需要获取对表单的引用，然后提交它：

```jsx
ReactDOM.render(<ContactUs onSubmit={handleSubmit} />, container);

const form = container.querySelector("form");
expect(form).not.toBeNull();
Simulate.submit(form!);

// TODO - check errors are shown

ReactDOM.unmountComponentAtNode(container);
```

以下是一步一步的描述：

+   我们使用`querySelector`函数，传入`form`标签来获取对`form`标签的引用。

+   然后我们通过使用 Jest 的`expect`函数和`not`和`toBeNull`函数链式调用来检查表单是否不是`null`。

+   使用 React 测试工具中的`Simulate`函数来模拟`submit`事件。我们在`form`变量后面使用`!`来告诉 TypeScript 编译器它不是`null`。

1.  我们的最终任务是检查验证错误是否显示：

```jsx
Simulate.submit(form!);

const errorSpans = container.querySelectorAll(".form-error");
expect(errorSpans.length).toBe(2);

ReactDOM.unmountComponentAtNode(container);
```

让我们一步一步来看：

+   我们在容器 DOM 节点上使用`querySelectorAll`函数，传入一个 CSS 选择器来查找应该包含错误的`span`标签

+   然后我们使用 Jest 的`expect`函数来验证页面上显示了两个错误

1.  当测试运行时，它应该成功通过，给我们两个通过的测试：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/7f8227b3-6643-4c54-bfa8-e879a79166c7.png)

在这个测试中，Jest 在一个虚拟 DOM 中渲染组件。表单`submit`事件也是通过标准的 React 测试工具中的`simulate`函数模拟的。因此，为了方便交互式组件测试，需要进行大量的模拟。

还要注意的是，我们在测试代码中引用了内部实现细节。我们引用了一个`form`标签，以及一个`form-error`CSS 类。如果我们以后将此 CSS 类名称更改为`contactus-form-error`，我们的测试将会失败，而我们的应用可能并没有问题。

这被称为**false positive**，并且可以使具有这些测试的代码库非常耗时。

# 使用 react-testing-library 改进我们的测试

react-testing-library 是一组工具，帮助我们为 React 组件编写可维护的测试。它主要帮助我们从测试代码中删除实现细节。

我们将使用这个库来从我们的测试代码中删除 CSS 类引用，以及与 React 事件系统的紧耦合。 

# 安装 react-testing-library

让我们首先通过终端安装`react-testing-library`作为开发依赖：

```jsx
npm install --save-dev react-testing-library
```

几秒钟后，这将被添加到我们的项目中。

# 从我们的测试中删除 CSS 类引用

我们将通过删除对`form-error`CSS 类的依赖来改进我们的测试。相反，我们将通过错误文本获取错误的引用，这是用户在屏幕上看到的，而不是实现细节：

1.  我们将从`react-testing-library`导入一个`render`函数，现在我们将使用它来渲染我们的组件。我们还将导入一个`cleanup`函数，在测试结束时我们将使用它来从 DOM 中移除测试组件：

```jsx
import { render, cleanup} from "react-testing-library";
```

1.  我们可以使用我们刚刚导入的`render`函数来渲染我们的组件，而不是使用`ReactDOM.render`，如下所示：

```jsx
test("When submit without filling in fields should display errors", () => {
  const handleSubmit = async (): Promise<ISubmitResult> => {
    return {
      success: true
    };
  };
  const { container, getAllByText } = render(
 <ContactUs onSubmit={handleSubmit} />
 );

  const form = container.querySelector("form");
  ...
});
```

我们将容器 DOM 节点存储在`container`变量中，还有一个`getallByText`函数，我们将使用它来获取显示的错误的引用。

1.  现在让我们使用`getAllByText`函数来获取页面上显示的错误：

```jsx
Simulate.submit(form!);

const errorSpans = getAllByText("This must be populated");
expect(errorSpans.length).toBe(2);
```

1.  我们要做的最后一项更改是在测试结束时使用我们刚刚导入的`cleanup`函数清理我们的 DOM，而不是`ReactDOM.unmountComponentAtNode`。我们还将在 Jest 的`afterEach`函数中执行此操作。我们完成的测试现在应该如下所示：

```jsx
afterEach(cleanup);

describe("ContactUs", () => {
  test("When submit without filling in fields should display errors", () => {
    const handleSubmit = async (): Promise<ISubmitResult> => {
      return {
        success: true
      };
    };
    const { container, getAllByText } = render(
      <ContactUs onSubmit={handleSubmit} />
    );

    const form = container.querySelector("form");
    expect(form).not.toBeNull();
    Simulate.submit(form!);

    const errorSpans = getAllByText("This must be populated");
    expect(errorSpans.length).toBe(2);
  });
});
```

当测试运行时，它应该仍然正常执行，并且测试应该通过。

# 使用`fireEvent`进行用户交互

我们现在将转而依赖于本机事件系统，而不是 React 的事件系统，后者位于其之上。这使我们更接近测试用户在使用我们的应用时发生的情况，并增加了我们对测试的信心：

1.  让我们首先通过从`react-testing-library`导入语句中添加`fireEvent`函数：

```jsx
import { render, cleanup, fireEvent } from "react-testing-library";
```

1.  我们将在对`render`函数的调用中解构变量时添加`getByText`函数：

```jsx
const { getAllByText, getByText } = render(
  <ContactUs onSubmit={handleSubmit} />
);
```

我们还可以删除解构的`container`变量，因为它将不再需要。

1.  然后，我们可以使用此函数获取对提交按钮的引用。之后，我们可以使用我们导入的`fireEvent`函数来点击按钮：

```jsx
const { getAllByText, getByText } = render(
  <ContactUs onSubmit={handleSubmit} />
);

const submitButton = getByText("Submit");
fireEvent.click(submitButton);

const errorSpans = getAllByText("This must be populated");
expect(errorSpans.length).toBe(2);
```

之前引用`form`标签的代码现在已经被移除。

当测试运行时，它仍然通过。

因此，我们的测试引用用户看到的项目，而不是实现细节，并且不太可能出现意外中断。

# 为有效的表单提交创建第二个测试

现在我们已经掌握了如何编写健壮测试的要领，让我们添加第二个测试，检查当表单填写不正确时是否不显示验证错误：

1.  我们将从我们的`ContactUs`组中创建一个新的测试：

```jsx
describe("ContactUs", () => {
  test("When submit without filling in fields should display errors", () => {
    ...
  });

  test("When submit after filling in fields should submit okay", () => {
 // TODO - render component, fill in fields, submit the form and check there are no errors
 });
});
```

1.  我们将以与第一个测试相同的方式渲染组件，但是解构稍有不同的变量：

```jsx
test("When submit after filling in fields should submit okay", () => {
  const handleSubmit = async (): Promise<ISubmitResult> => {
 return {
 success: true
 };
 };
 const { container, getByText, getByLabelText } = render(
 <ContactUs onSubmit={handleSubmit} />
 );
});
```

现在：

+   我们将需要`container`对象来检查是否显示了任何错误

+   我们将使用`getByText`函数来定位提交按钮

+   我们将使用`getByLabelText`函数来获取对我们输入的引用

1.  我们现在可以使用`getByLabelText`函数获取对名称输入的引用。之后，我们进行一些检查，以验证名称输入确实存在：

```jsx
const { container, getByText, getByLabelText } = render(
  <ContactUs onSubmit={handleSubmit} />
);

const nameField: HTMLInputElement = getByLabelText(
 "Your name"
) as HTMLInputElement;
expect(nameField).not.toBeNull();
```

1.  然后，我们需要模拟用户填写此输入。我们通过调用本机的`change`事件来实现这一点，传入所需的事件参数，其中包括我们的输入值：

```jsx
const nameField: HTMLInputElement = getByLabelText(
  "Your name"
) as HTMLInputElement;
expect(nameField).not.toBeNull();
fireEvent.change(nameField, {
 target: { value: "Carl" }
});
```

我们已经模拟了用户将名称字段设置为`Carl`。

在调用`getByLabelText`后，我们使用类型断言来通知 TypeScript 编译器返回的元素是`HTMLInputElement`类型，这样我们就不会得到编译错误。

1.  然后我们可以按照相同的模式填写电子邮件字段：

```jsx
const nameField: HTMLInputElement = getByLabelText(
  "Your name"
) as HTMLInputElement;
expect(nameField).not.toBeNull();
fireEvent.change(nameField, {
  target: { value: "Carl" }
});

const emailField = getByLabelText("Your email address") as HTMLInputElement;
expect(emailField).not.toBeNull();
fireEvent.change(emailField, {
 target: { value: "carl.rippon@testmail.com" }
});
```

在这里，我们模拟用户将电子邮件字段设置为`carl.rippon@testmail.com`。

1.  然后，我们可以通过点击提交按钮来提交表单，就像我们第一次测试时一样：

```jsx
fireEvent.change(emailField, {
  target: { value: "carl.rippon@testmail.com" }
});

const submitButton = getByText("Submit");
fireEvent.click(submitButton); 
```

1.  我们的最后任务是验证屏幕上没有显示错误。不幸的是，我们不能像上次测试中使用`getAllByText`函数，因为这个函数期望至少找到一个元素，而在我们的情况下，我们期望没有元素。因此，在进行此检查之前，我们将在错误周围添加一个包装的`div`标签。让我们去`Form.tsx`并做这个：

```jsx
{context.errors[name] && context.errors[name].length > 0 && (
 <div data-testid="formErrors">
    {context.errors[name].map(error => (
      <span key={error} className="form-error">
        {error}
      </span>
    ))}
  </div>
)}
```

我们给`div`标签添加了一个`data-testid`属性，我们将在我们的测试中使用它。

1.  让我们回到我们的测试。我们现在可以使用`data-testid`属性定位围绕错误的`div`标签。然后我们可以验证这个`div`标签是`null`，因为没有显示错误：

```jsx
fireEvent.click(submitButton); 

const errorsDiv = container.querySelector("[data-testid='formErrors']");
expect(errorsDiv).toBeNull();
```

当测试在我们的测试套件中运行时，我们会发现现在有三个通过的测试。

不过，引用`data-testid`属性是一个实现细节，对吗？用户看不到或关心`data-testid`属性，这似乎与我们之前说的相矛盾。

这有点是一个实现细节，但它是专门为我们的测试而设计的。因此，实现重构不太可能意外地破坏我们的测试。

在下一节中，我们将添加另一个测试，这次使用 Jest 快照测试。

# 使用 Jest 快照测试

快照测试是 Jest 将渲染组件的所有元素和属性与先前渲染组件的快照进行比较的测试。如果没有差异，那么测试通过。

我们将添加一个测试来验证`ContactUs`组件是否正常渲染，通过使用 Jest 快照测试来检查 DOM 节点：

1.  我们将在`ContactUs`测试组中创建一个标题为“渲染正常”的测试，以与以前相同的方式渲染组件：

```jsx
describe("ContactUs", () => {
  ...
  test("Renders okay", () => {
 const handleSubmit = async (): Promise<ISubmitResult> => {
 return {
 success: true
 };
 };
 const { container } = render(<ContactUs onSubmit={handleSubmit} />);

 // TODO - do the snapshot test
 });
});
```

1.  现在我们可以添加一行来执行快照测试：

```jsx
test("Renders okay", () => {
  const handleSubmit = async (): Promise<ISubmitResult> => {
    return {
      success: true
    };
  };
  const { container } = render(<ContactUs onSubmit={handleSubmit} />);

  expect(container).toMatchSnapshot();
});
```

进行快照测试非常简单。我们将要比较的 DOM 节点传递给 Jest 的`expect`函数，然后在其后链接`toMatchSnapshot`函数。

当测试运行时，我们将在终端中得到快照已被写入的确认，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/40d1d8d8-f581-4f3d-abdd-f860f1e4fa42.png)

1.  如果我们查看我们的`src`文件夹，我们会看到现在包含一个`__snapshots__`文件夹。如果我们查看这个文件夹，我们会看到一个名为`ContactUs.test.tsx.snap`的文件。打开文件，我们会看到以下内容：

```jsx
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`ContactUs Renders okay 1`] = `
<div>
  <form
    class="form"
    novalidate=""
  >
    <div
      class="form-group"
    >
      <label
        for="name"
      >
        Your name
      </label>
      <input
        id="name"
        type="text"
        value=""
      />
    </div>
    ...
  </form>
</div>
`;
```

这个片段中有一些内容被剥离了，但我们明白：我们从传入`toMatchSnapshot`函数的`container`元素中得到了每个 DOM 节点的副本，包括它们的属性。

不过，这个测试与我们的实现紧密耦合。因此，对 DOM 结构或属性的任何更改都将破坏我们的测试。

1.  举个例子，在`Form.tsx`中的`Form`组件中添加一个`div`标签：

```jsx
<form ...>
  <div>{this.props.children}</div>
  ...
</form>
```

当测试运行时，我们将看到确认我们的测试已经失败。Jest 在终端中很好地显示了差异：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/eeb2f477-38cd-460d-bfd0-910b640cf3c6.png)

1.  我们很高兴这是一个有效的改变，所以我们可以按*U*让 Jest 更新快照：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/ee14c380-8e94-4ba6-884f-33891162b018.png)

那么，快照测试是好事还是坏事呢？它们是不稳定的，因为它们与组件的实现紧密耦合。但是它们非常容易创建，当它们出现问题时，Jest 会很好地突出显示问题区域，并允许我们有效地纠正测试快照。它们非常值得一试，看看你的团队是否从中获得价值。

在本章中，我们已经学到了很多关于单元测试 React 和 TypeScript 应用程序的知识。接下来，我们将学习如何模拟依赖关系。

# 模拟依赖

模拟组件的依赖关系可以使组件更容易测试。但是，如果我们模拟了太多东西，测试是否真的在验证组件在我们的真实应用程序中是否能正常工作呢？

确定要模拟的内容是编写单元测试时最困难的任务之一。有一些东西是有意义模拟的，比如 REST API。REST API 是前端和后端之间的一个相当固定的契约。模拟 REST API 也可以让我们的测试运行得又快又顺利。

在这一部分，我们最终将学习如何模拟使用`axios`进行的 REST API 调用。不过首先，我们将学习 Jest 的函数模拟功能。

# 在 Jest 中使用模拟函数

我们将对验证提交“联系我们”表单而未填写字段会导致页面显示错误的测试进行另一个改进。我们将添加一个额外的检查，以确保提交处理程序不会被执行：

1.  让我们回到我们编写的第一个组件测试：`ContactUs.test.tsx`。我们手动创建了一个`handleSubmit`函数，我们在`ContactUs`组件的实例中引用了它。让我们将其更改为 Jest 模拟函数：

```jsx
const handleSubmit = jest.fn();
```

我们的测试将像以前一样正确运行，但这次是 Jest 为我们模拟函数。

1.  现在 Jest 正在模拟提交处理程序，我们可以在测试结束时检查它是否被调用。我们使用`not`和`toBeCalled` Jest 匹配函数来做到这一点：

```jsx
const errorSpans = container.querySelectorAll(".form-error");
expect(errorSpans.length).toBe(2);

expect(handleSubmit).not.toBeCalled();
```

这真的很好，因为我们不仅简化了我们的提交处理程序函数，而且还很容易地添加了一个检查来验证它是否被调用。

让我们继续实施的第二个测试，验证`Contact Us`表单是否被正确提交：

1.  我们将再次更改`handleSubmit`变量以引用 Jest 模拟函数：

```jsx
const handleSubmit = jest.fn();
```

1.  让我们验证提交处理程序是否被调用。我们使用`toBeCalledTimes` Jest 函数传入我们期望函数被调用的次数，这在我们的情况下是`1`：

```jsx
const errorsDiv = container.querySelector("[data-testid='formErrors']");
expect(errorsDiv).toBeNull();

expect(handleSubmit).toBeCalledTimes(1);
```

当测试执行时，它仍应该通过。

1.  还有一个有用的检查我们可以做。我们知道提交处理程序正在被调用，但它是否有正确的参数？我们可以使用`toBeCalledWith` Jest 函数来检查这一点：

```jsx
expect(handleSubmit).toBeCalledTimes(1);
expect(handleSubmit).toBeCalledWith({
 name: "Carl",
 email: "carl.rippon@testmail.com",
 reason: "Support",
 notes: ""
});
```

同样，当测试执行时，它仍应该通过。

因此，通过让 Jest 模拟我们的提交处理程序，我们很快为我们的测试添加了一些有价值的额外检查。

# 使用`axios-mock-adapter`模拟 Axios

我们将转移到我们在第九章中创建的项目，*与 Restful API 交互*。我们将添加一个测试，验证帖子是否正确呈现在页面上。我们将模拟 JSONPlaceholder REST API，这样我们就可以控制返回的数据，使我们的测试可以顺利快速地执行：

1.  首先，我们需要安装`axios-mock-adapter`包作为开发依赖：

```jsx
npm install axios-mock-adapter --save-dev
```

1.  我们还将安装`react-testing-library`：

```jsx
npm install react-testing-library --save-dev
```

1.  项目已经有一个测试文件`App.test.tsx`，其中包括对`App`组件的基本测试。我们将删除测试，但保留导入，因为我们需要这些。

1.  此外，我们将从 react-testing-library 导入一些函数，`axios`和一个`MockAdapter`类，我们将使用它来模拟 REST API 调用：

```jsx
import { render, cleanup, waitForElement } from "react-testing-library";
import axios from "axios";
import MockAdapter from "axios-mock-adapter";
```

1.  让我们在每个测试后添加通常的清理行：

```jsx
afterEach(cleanup);
```

1.  我们将使用适当的描述创建我们的测试，并将其放在`App`组下：

```jsx
describe("App", () => {
  test("When page loads, posts are rendered", async () => {

    // TODO - render the app component with a mock API and check that the posts in the rendered list are as expected
```

```jsx
      });
});
```

请注意，`arrow`函数标有`async`关键字。这是因为我们最终会在测试中进行异步调用。

1.  我们在测试中的第一项工作是使用`MockAdapter`类模拟 REST API 调用：

```jsx
test("When page loads, posts are rendered", async () => {
    const mock = new MockAdapter(axios);
 mock.onGet("https://jsonplaceholder.typicode.com/posts").reply(200, [
 {
 userId: 1,
 id: 1,
 title: "title test 1",
 body: "body test 1"
 },
 {
 userId: 1,
 id: 2,
 title: "title test 2",
 body: "body test 2"
 }
 ]);
});
```

我们使用`onGet`方法来定义调用获取帖子的 URL 时所需的响应 HTTP 状态码和主体。因此，对 REST API 的调用应该返回包含我们的测试数据的两个帖子。

1.  我们需要检查帖子是否正确渲染。为了做到这一点，我们将在`App.tsx`中的无序帖子列表中添加`data-testid`属性。我们只在有数据时才会渲染这个。

```jsx
{this.state.posts.length > 0 && (
  <ul className="posts" data-testid="posts">
    ...
  </ul>
)}
```

1.  在我们的测试中，我们现在可以渲染组件并解构`getByTestId`函数：

```jsx
mock.onGet("https://jsonplaceholder.typicode.com/posts").reply(...);
const { getByTestId } = render(<App />);
```

1.  我们需要检查渲染的帖子是否正确，但这很棘手，因为这些是异步渲染的。我们需要在进行检查之前等待帖子列表被添加到 DOM 中。我们可以使用 react-testing-library 中的`waitForElement`函数来实现这一点：

```jsx
const { getByTestId } = render(<App />);
const postsList: any = await waitForElement(() => getByTestId("posts"));
```

`waitForElement`函数接受一个箭头函数作为参数，然后返回我们正在等待的元素。我们使用`getByTestId`函数获取帖子列表，它使用`data-testid`属性找到它。

1.  然后，我们可以使用快照测试来检查帖子列表中的内容是否正确：

```jsx
const postsList: any = await waitForElement(() => getByTestId("posts"));
expect(postsList).toMatchSnapshot();
```

1.  在我们的测试可以成功执行之前，我们需要在`tsconfig.json`中进行更改，以便 TypeScript 编译器知道我们正在使用`async`和`await`：

```jsx
{
  "compilerOptions": {
    "target": "es5",
    "lib": ["dom", "es2015"],
    ...
  },
  "include": ["src"]
}
```

当测试执行时，将创建快照。如果我们检查快照，它将包含两个包含我们告诉 REST API 返回的数据的列表项。

我们已经了解了 Jest 和 react-testing-library 中一些很棒的功能，这些功能帮助我们编写可维护的纯函数和 React 组件的测试。

然而，我们如何知道我们的应用程序的哪些部分由单元测试覆盖了，更重要的是，哪些部分没有覆盖？我们将在下一节中找出答案。

# 获取代码覆盖率

代码覆盖率是指我们的应用代码有多少被单元测试覆盖。当我们编写单元测试时，我们会对覆盖了哪些代码和哪些代码没有覆盖有一个大致的了解，但随着应用的增长和时间的推移，我们会失去对此的追踪。

Jest 带有一个很棒的代码覆盖工具，所以我们不必记住哪些代码被覆盖了。在本节中，我们将使用这个工具来发现我们在上一节中工作的项目中的代码覆盖情况，我们在那里模拟了`axios`：

1.  我们的第一个任务是添加一个`npm`脚本，该脚本将在打开覆盖跟踪工具时运行测试。让我们添加一个名为`test-coverage`的新脚本，其中包括在执行`react-scripts`时使用`--coverage`选项：

```jsx
"scripts": {
  "start": "react-scripts start",
  "build": "react-scripts build",
  "test": "react-scripts test",
  "test-coverage": "react-scripts test --coverage",
  "eject": "react-scripts eject"
},
```

1.  然后我们可以在终端中运行这个命令：

```jsx
npm run test-coverage
```

几秒钟后，Jest 将在终端上呈现每个文件的高级覆盖统计信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/c426c06b-40a8-412f-9e86-ae592f821802.png)

1.  如果我们查看项目文件结构，我们会看到一个`coverage`文件夹已经添加了一个`lcov-report`文件夹。`lcov-report`文件夹中有一个`index.html`文件，其中包含了每个文件的覆盖率的更详细信息。让我们打开它并看一看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/3db8e56c-d029-4380-bcdd-cab3127e597a.png)

我们看到了与终端中呈现的相同信息。

这四列统计数据的含义是什么？

+   `Statements`列显示了代码中执行了多少个语句

+   `Branches`列显示了代码中条件语句中执行了多少分支

+   `Function`列显示了代码中调用了多少个函数

+   `Line`列显示了代码中执行了多少行。通常，这将与`Statements`数字相同。但是，如果将多个语句放在一行上，它可能会有所不同。例如，以下内容被计为一行，但包含两个语句：

```jsx
let name = "Carl"; console.log(name);
```

1.  我们可以深入到每个文件中找出哪些具体的代码没有被覆盖。让我们点击`App.tsx`链接：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/12137a97-2add-4bdf-88a5-0312a8c06d0a.png)

左侧带有绿色背景的`1x`表示这些代码行已被我们的测试执行了一次。红色高亮显示的代码是我们的测试未覆盖到的代码。

因此，获取覆盖率统计信息和确定我们可能想要实现的其他测试是相当容易的。这是非常值得使用的，可以让我们确信我们的应用程序经过了充分的测试。

# 总结

在本章中，我们学会了如何使用 Jest 测试用 TypeScript 编写的纯函数。我们只需使用我们想要测试的参数执行函数，并使用 Jest 的`expect`函数与 Jest 的匹配器函数之一，比如`toBe`，来验证结果。

我们看了如何与 Jest 的测试运行器交互，以及如何应用过滤器，以便只执行我们关注的测试。我们了解到测试 React 和 TypeScript 组件比测试纯函数更复杂，但 Jest 和 react-testing-library 为我们提供了很大的帮助。

我们还学会了如何使用`render`函数渲染组件，以及如何使用各种函数与检查元素进行交互，比如来自 react-testing-library 的`getByText`和`getLabelByText`。

我们学会了如何使用 react-testing-library 中的`waitForElement`函数轻松测试异步交互。我们现在明白了在测试中不引用实现细节的好处，这将帮助我们构建更健壮的测试。

我们还讨论了 Jest 的巧妙快照测试工具。我们看到这些测试经常会出问题，但也知道它们非常容易创建和更改的原因。

模拟和监视函数的能力是另一个我们现在了解的很棒的 Jest 功能。检查组件事件处理程序的函数是否以正确的参数被调用，确实可以为我们的测试增加价值。

我们讨论了`axios-mock-adapter`库，我们可以用它来模拟`axios` REST API 请求。这使我们能够轻松测试与 RESTful API 交互的容器组件。

我们现在知道如何快速确定我们需要实现的额外测试，以确保我们的应用程序经过了充分的测试。我们创建了一个`npm`脚本命令来实现这一点，使用`react-scripts`和`--coverage`选项。

总的来说，我们现在具有知识和工具，可以使用 Jest 为我们的应用程序稳健地创建单元测试。

Jasmine 和 Mocha 是两个流行的替代测试框架，与 Jest 相比的一个巨大优势是它被`create-react-app`配置为开箱即用。如果我们想使用它们，我们将不得不手动配置 Jasmine 和 Mocha。然而，如果您的团队已经熟悉其中任何一个工具，而不是学习另一个测试框架，那么 Jasmine 和 Mocha 也值得考虑。

Enzyme 是另一个与 Jest 一起用于测试 React 应用程序的流行库。它支持浅渲染，这是一种仅渲染组件中顶层元素而不是子组件的方法。这是值得探索的，但请记住，我们模拟得越多，我们离真相就越远，我们对应用程序是否经过充分测试的信心就越少。

# 问题

1.  假设我们正在实施一个 Jest 测试，并且我们有一个名为`result`的变量，我们想要检查它不是`null`。我们如何使用 Jest 匹配器函数来实现这一点？

1.  假设我们有一个名为`person`的变量，类型为`IPerson`：

```jsx
interface IPerson {
  id: number;
  name: string;
}
```

我们想要检查`person`变量是否为`{ id: 1, name: "bob" }`。我们如何使用 Jest 匹配器函数来实现这一点？

1.  在上一个问题中，我们是否可以使用 Jest 快照测试来进行我们的检查？如果可以，如何实现？

1.  我们实现了一个名为`CheckList`的组件，它从数组中呈现文本列表。每个列表项都有复选框，以便用户可以选择列表项。该组件有一个名为`onItemSelect`的函数属性，当用户通过选中复选框选择项目时会调用该函数。我们正在实施一个测试来验证`onItemSelect`属性是否有效。以下代码行在测试中呈现组件：

```jsx
const { container } = render(<SimpleList data={["Apple", "Banana", "Strawberry"]} onItemSelect={handleListItemSelect} />);
```

如何使用 Jest 模拟函数来处理`handleListItemSelect`并检查它是否被调用？

1.  在上一个问题中的`SimpleList`的实现中，`onItemSelect`函数接受一个名为`item`的参数，该参数是用户选择的`string`值。在我们的测试中，假设我们已经模拟了用户选择`Banana`。我们如何检查`onItemSelect`函数是否被调用，并且参数为`Banana`？

1.  在上述两个问题中的`SimpleList`的实现中，文本使用一个标签显示，该标签使用`for`属性与复选框相关联。我们如何使用 react-testing-library 中的函数来首先定位`Banana`复选框，然后检查它？

1.  在本章中，我们发现从 JSONPlaceholder REST API 渲染帖子的代码覆盖率很低。其中一个未覆盖的领域是在从 REST API 获取帖子时，在`componentDidMount`函数中处理 HTTP 错误代码。创建一个测试来覆盖代码的这一部分。

# 进一步阅读

以下资源对于查找有关单元测试 React 和 TypeScript 应用程序的更多信息很有用：

+   官方的 Jest 文档可以在以下链接找到：[`jestjs.io/`](https://jestjs.io/)

+   React Testing Library GitHub 存储库位于以下链接：[`github.com/kentcdodds/react-testing-library`](https://github.com/kentcdodds/react-testing-library)

+   阅读 Enzyme 的文档，请访问以下链接：[`airbnb.io/enzyme/docs/api/`](https://airbnb.io/enzyme/docs/api/)

+   Jasmine GitHub 页面如下：[`jasmine.github.io/index.html`](https://jasmine.github.io/index.html)

+   Mocha 主页可以在以下网址找到：[`mochajs.org/`](https://mochajs.org/)
