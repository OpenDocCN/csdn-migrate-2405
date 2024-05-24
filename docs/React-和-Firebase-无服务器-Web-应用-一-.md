# React 和 Firebase 无服务器 Web 应用（一）

> 原文：[`zh.annas-archive.org/md5/330929BAB4D0F44DAFAC93D065193C41`](https://zh.annas-archive.org/md5/330929BAB4D0F44DAFAC93D065193C41)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

实时应用程序多年来一直主导着 Web 应用程序领域。实时不仅仅限于在数据可用时立即显示数据；当与交互式体验一起使用时，它展现出真正的力量，用户和系统可以立即相互通信。借助虚拟 DOM 和声明性视图等功能，React 被证明更适合这样的实时应用程序。Firebase 通过让您专注于应用程序的行为和外观，而不会陷入实时开发的更繁琐的部分，使构建和快速原型设计这种应用程序变得更简单。

本书将涵盖 Firebase 的功能，如云存储、云功能、托管和实时数据库集成 React，以开发丰富、协作、实时的应用程序，仅使用客户端代码。我们还可以看到如何使用 Firebase 身份验证和数据库安全规则来保护我们的应用程序。我们还利用 Redux 的力量来组织前端的数据。Redux 试图通过对状态变化施加一定的限制，使状态变化可预测。在本书的最后，您将通过认识 Firebase 的潜力来提高您的 React 技能，从而创建实时无服务器 Web 应用程序。

本书提供的是更多实用的见解，而不仅仅是理论概念，并包括从 hello world 到实时 Web 应用程序的基础到高级示例。

# 本书的受众

本书的理念是帮助开发人员使用 React 和 Firebase 更快地创建实时无服务器应用程序。我们为那些想要使用 Firebase 验证业务理念创建最小可行产品（MVP）的开发人员编写了本书。本书旨在为那些具有 HTML、CSS、React 和 JavaScript 基础到中级知识的开发人员提供实用知识，并希望了解更多关于 React、Redux 和 Firebase 集成的内容。本书还面向那些不想浪费时间搜索数百个 React、Redux 和 Firebase 教程的开发人员，并希望在一个地方拥有真实示例，快速提高生产力。本书适合任何对学习 Firebase 感兴趣的人。

最后，如果您想开发无服务器应用程序，并想了解从设计到托管的端到端过程，并获得逐步说明，那么本书适合您。

# 要充分利用本书

您应该具有 React、HTML、CSS 和 JavaScript 的基本编程经验，才能有利于阅读本书。假定您已经知道**Node Package Manager**（**npm**）如何工作以安装任何依赖项，并且对 ES6 语法有基本了解。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“SUPPORT”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Serverless-Web-Applications-with-React-and-Firebase`](https://github.com/PacktPublishing/Serverless-Web-Applications-with-React-and-Firebase)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```jsx
constructor(props) {
 super(props);
 this.state = {
 value: props.initialValue
 };
 }
```

任何命令行输入或输出都以以下形式书写：

```jsx
node -v
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子："从管理面板中选择系统信息。"

警告或重要说明会出现在这样的形式中。提示和技巧会出现在这样的形式中。

# 联系我们

我们随时欢迎读者的反馈。

**一般反馈**：发送电子邮件至`feedback@packtpub.com`，并在主题中提及书名。如果您对本书的任何方面有疑问，请通过`questions@packtpub.com`与我们联系。

**勘误表**：尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在本书中发现了错误，我们将不胜感激地接受您的报告。请访问[www.packtpub.com/submit-errata](http://www.packtpub.com/submit-errata)，选择您的书籍，点击“勘误提交表格”链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，请向我们提供位置地址或网站名称，我们将不胜感激。请通过`copyright@packtpub.com`与我们联系，并附上材料链接。

如果您有兴趣成为作者：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。阅读并使用本书后，为什么不在购买它的网站上留下评论呢？潜在读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packtpub.com](https://www.packtpub.com/)。


# 第一章：使用 Firebase 和 React 入门

实时 Web 应用程序被认为包括对用户的超快速响应的好处，并且具有高度的互动性，这增加了用户的参与度。在现代 Web 中，有许多可用于开发实时应用程序的框架和工具。JavaScript 是用于构建 Web 应用程序的最流行的脚本语言之一。本书向您介绍了 ReactJS 和 Firebase，这两者在您学习现代 Web 应用程序开发时可能会遇到。它们都用于构建快速、可扩展和实时的用户界面，这些界面使用数据，并且可以随时间变化而无需重新加载页面。

React 以**模型**-**视图**-**控制器**（**MVC**）模式中的视图而闻名，并且可以与其他 JavaScript 库或框架一起在 MVC 中使用。为了管理 React 应用程序中的数据流，我们可以使用 Flux 或 Redux。在本书中，我们还将介绍如何将 redux 与 React 和 firebase 应用程序实现。

Redux 是 Flux 的替代品。它具有相同的关键优势。Redux 与 React 配合特别好，用于管理 UI 的状态。如果你曾经使用过 flux，那么使用 Redux 也很容易。

在开始编码之前，让我们复习一下 ReactJS 的知识，并了解我们可以如何使用 Firebase 及其功能，以了解 Firebase 的强大功能。

以下是本节中我们将涵盖的主题列表：

+   React 简介

+   React 组件生命周期

这将让您更好地理解处理 React 组件。

# React

React 是一个开源的 JavaScript 库，提供了一个视图层，用于将数据呈现为 HTML，以创建交互式 UI 组件。组件通常用于呈现包含自定义 HTML 标记的其他组件的 React 视图。当数据发生变化时，React 视图会高效地更新和重新呈现组件，而无需重新加载页面。它为您提供了一个虚拟 DOM，强大的视图而无需模板，单向数据流和显式突变。这是一种非常系统化的方式，在数据发生变化时更新 HTML 文档，并在现代单页面应用程序中提供了组件的清晰分离。

React 组件完全由 Javascript 构建，因此很容易通过应用程序传递丰富的数据。在 React 中创建组件可以将 UI 分割为可重用和独立的部分，这使得您的应用程序组件可重用、可测试，并且易于关注点分离。

React 只关注 MVC 中的视图，但它也有有状态的组件，它记住了`this.state`中的所有内容。它处理从输入到状态更改的映射，并渲染组件。让我们来看看 React 的组件生命周期及其不同的级别。

# 组件生命周期

在 React 中，每个组件都有自己的生命周期方法。每个方法都可以根据您的要求进行重写。

当数据发生变化时，React 会自动检测变化并重新渲染组件。此外，我们可以在错误处理阶段捕获错误。

以下图片显示了 React 组件的各个阶段：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/03a987fd-5f96-41d6-9c61-adada00864f3.png)

# 方法信息

让我们快速看一下前面的方法。

# constructor()方法

当组件挂载时，React 组件的构造函数首先被调用。在这里，我们可以设置组件的状态。

这是一个在`React.Component`中的构造函数示例：

```jsx
constructor(props) {
 super(props);
 this.state = {
 value: props.initialValue
 };
 }
```

在构造函数中使用`this.props`，我们需要调用`super(props)`来访问和调用父级的函数；否则，你会在构造函数中得到`this.props`未定义，因为 React 在调用构造函数后立即从外部设置实例上的`.props`，但当你在 render 方法中使用`this.props`时，它不会受到影响。

# render()方法

`render()`方法是必需的，用于渲染 UI 组件并检查`this.props`和`this.state`，并返回以下类型之一：

+   **React 元素**

+   **字符串和数字**

+   **门户**

+   **null**

+   **布尔值**

# componentWillMount()方法

此方法在`componentDidMount`之前立即调用。它在`render()`方法之前触发。

# componentDidMount()方法

此方法在组件挂载后立即调用。我们可以使用此方法从远程端点加载数据以实例化网络请求。

# componentWillReceiveProps()方法

当挂载的组件接收到新的 props 时，将调用此方法。此方法还允许比较当前值和下一个值，以确保 props 的更改。

# shouldComponentUpdate()方法

`shouldComponentUpdate()`方法在组件接收到新的 props 和 state 时被调用。默认值是`true`；如果返回`false`，React 会跳过组件的更新。

# componentWillUpdate()方法

`componentWillUpdate()`方法在渲染之前立即被调用，当接收到新的 prop 或 state 时。我们可以使用这个方法在组件更新之前执行操作。

如果`shouldComponentUpdate()`返回`false`，这个方法将不会被调用。

# componentDidUpdate()方法

`componentDidUpdate()`方法在组件更新后立即被调用。这个方法不会在初始渲染时被调用。

类似于`componentWillUpdate()`，如果`shouldComponentUpdate()`返回 false，这个方法也不会被调用。

# componentWillUnmount()方法

这个方法在 React 组件被卸载和销毁之前立即被调用。在这里，我们可以执行任何必要的清理，比如取消网络请求或清理在`componentDidMount`中创建的任何订阅。

# componentDidCatch()方法

这个方法允许我们在 React 组件中捕获 JavaScript 错误。我们可以记录这些错误，并显示另一个备用 UI，而不是崩溃的组件树。

现在我们对 React 组件中可用的组件方法有了清晰的了解。

观察以下 JavaScript 代码片段：

```jsx
<section>
<h2>My First Example</h2>
</section>
<script>
 var root = document.querySelector('section').createShadowRoot();
 root.innerHTML = '<style>h2{ color: red; }</style>' +'<h2>Hello World!</h2>';
</script>
```

现在，观察以下 ReactJS 代码片段：

```jsx
var sectionStyle = {
 color: 'red'
};
var MyFirstExample = React.createClass({
render: function() {
 return (<section><h2 style={sectionStyle}>
 Hello World!</h2></section>
 )}
})
ReactDOM.render(<MyFirstExample />, renderedNode);
```

现在，在观察了前面的 React 和 JavaScript 示例之后，我们将对普通 HTML 封装和 ReactJS 自定义 HTML 标签有一个清晰的了解。

React 不是一个 MVC 框架；它是一个用于构建可组合用户界面和可重用组件的库。React 在 Facebook 的生产阶段使用，并且[instagram.com](https://www.instagram.com/)完全基于 React 构建。

# Firebase

Firebase 平台帮助您开发高质量的应用程序并专注于用户。

Firebase 是由 Google 支持的移动和 Web 应用程序开发平台。它是开发高质量移动和 Web 应用程序的一站式解决方案。它包括各种产品，如实时数据库、崩溃报告、云 Firestore、云存储、云功能、身份验证、托管、Android 测试实验室和 iOS 性能监控，可以用来开发和测试实时应用程序，专注于用户需求，而不是技术复杂性。

它还包括产品，如云消息传递、Google 分析、动态链接、远程配置、邀请、应用索引、AdMob 和 AdWords，这些产品可以帮助您扩大用户群体，同时增加受众的参与度。

Firebase 提供多个 Firebase 服务。我们可以使用 Firebase 命名空间访问每个服务：

+   `firebase.auth()` - 认证

+   `firebase.storage()` - 云存储

+   `firebase.database()` - 实时数据库

+   `firebase.firestore()` - 云 Firestore

我们将在接下来的章节中涵盖所有前述的服务。在本章中，我们将简要地介绍前述产品/服务，以便对 Firebase 平台的所有功能有一个基本的了解。在接下来的章节中，我们将更详细地探索可以与 React 平台集成的与 web 相关的产品。

以下是我们将在本节中涵盖的主题列表：

+   Firebase 及其功能简介

+   Firebase 功能列表以及如何使用它

+   云 Firestore

+   使用 JavaScript 设置 Firebase 项目

+   使用 Firebase 和 JavaScript 创建“Hello World”示例应用程序

正如您所看到的，Firebase 提供了两种类型的云数据库和实时数据库，两者都支持实时数据同步。我们可以在同一个应用程序或项目中同时使用它们。好的，让我们深入了解并了解更多。

# 实时数据库

对于任何实时应用程序，我们都需要一个实时数据库。Firebase 实时数据库是一个云托管的 NoSQL 数据库，可以将数据实时同步到每个连接的客户端。Firebase 数据库使用同步机制，而不是典型的请求-响应模型，它可以在毫秒内将数据同步到所有连接的设备上。另一个关键功能是它的离线功能。Firebase SDK 将数据持久保存在磁盘上；因此，即使用户失去互联网连接，应用程序仍然可以响应。一旦重新建立连接，它会自动同步数据。它支持 iOS、Android、Web、C++和 Unity 平台。我们将在接下来的章节中详细介绍这一点。

Firebase 实时数据库可以在单个数据库中支持约 100,000 个并发连接和每秒 1,000 次写入。

以下屏幕截图显示了左侧 Firebase 中可用的功能列表，我们已经在数据库部分选择了实时数据库。在该部分，我们有四个选项卡可用：

+   数据

+   规则

+   备份

+   用法

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/d483f47d-f69c-41db-8390-b3d6fe253d52.png)

# 数据库规则

Firebase 数据库规则是保护数据的唯一方法。Firebase 为开发人员提供了灵活性和基于表达式的规则语言，具有类似 JavaScript 的语法，用于定义数据的结构、索引方式以及用户何时可以读取和写入数据。您还可以将身份验证服务与此结合，以定义谁可以访问哪些数据，并保护用户免受未经授权的访问。为了验证数据，我们需要在规则中使用`.validate`来单独添加规则。

考虑以下示例：

```jsx
{
"rules": {
".write": true,
"ticket": {
// a valid ticket must have attributes "email" and "status"
".validate": "newData.hasChildren(['email', 'status'])",
"status": {
// the value of "status" must be a string and length greater then 0 and less then 10
".validate": "newData.isString() && newData.val().length > 0 && newData.val().length < 10"
},
"email": {
// the value of "email" must valid with "@"
".validate": "newData.val().contains('@')"
}
}
}
}
```

以下是在“规则”选项卡中应用规则的其他示例代码块：

**默认**：身份验证的规则配置：

```jsx
{
 "rules": {
 ".read": "auth != null",
 ".write": "auth != null"
 }}
```

**公共**：这些规则允许每个人完全访问，即使是您应用的非用户。它们允许读取和写入数据库：

```jsx
{
 "rules": {
 ".read": true,
 ".write": true
 }}
```

**用户**：这些规则授权访问与 Firebase 身份验证令牌中用户 ID 匹配的节点：

```jsx
{
 "rules": {
   "users": {
       "$uid": {
             ".read": "$uid === auth.uid",
             ".write": "$uid === auth.uid"
         }
       }
    }
}
```

**私有**：这些规则配置不允许任何人读取和写入数据库：

```jsx
{
 "rules": {
    ".read": false,
    ".write": false
  }
}
```

我们还可以使用 Firebase 秘钥代码的 REST API 来通过向`/.settings/rules.json`路径发出`PUT`请求来编写和更新 Firebase 应用的规则，并且它将覆盖现有规则。

例如，`curl -X PUT -d '{ "rules": { ".read": true } }'` `'https://docs-examples.firebaseio.com/.settings/rules.json?auth=FIREBASE_SECRET'`。

# 备份

Firebase 允许我们保存数据库的每日备份，但这仅在 Blaze 计划中可用。它还会自动应用安全规则以保护您的数据。

# 用法

Firebase 允许通过分析图表查看数据库的使用情况。它实时显示了我们的 Firebase 数据库中的连接、存储、下载和负载：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/2ba2765c-6d08-445d-82bf-f81e78b2b262.png)

# Cloud Firestore

Cloud Firestore 也是一种云托管的 NoSQL 数据库。您可能会认为我们已经有了实时数据库，它也是一种 NoSQL 数据库，那么为什么我们需要 Firestore 呢？对这个问题的答案是，Firestore 可以被视为提供实时同步和离线支持以及高效数据查询的实时数据库的高级版本。它可以全球扩展，并让您专注于开发应用，而不必担心服务器管理。它可以与 Android、iOS 和 Web 平台一起使用。

我们可以在同一个 Firebase 应用程序或项目中使用这两个数据库。两者都是 NoSQL 数据库，可以存储相同类型的数据，并且具有类似方式工作的客户端库。

如果您想在云 Firestore 处于测试版时尝试它，请使用我们的指南开始使用：

+   转到[`console.firebase.google.com/`](https://console.firebase.google.com/)

+   选择您的项目，`DemoProject`

+   单击左侧导航栏中的数据库，然后选择 Cloud Firestore 数据库：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/ac60a4ce-21da-48e5-9af3-cae9d46762eb.png)

一旦我们选择数据库，它会提示您在创建数据库之前应用安全规则。

# 安全规则

在 Cloud Firestore 中创建数据库和集合之前，它会提示您为我们的数据库应用安全规则。

看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/cfec66de-5807-4a3d-9bc6-9367e52836c9.png)

以下是 Firestore 规则的一些代码示例：

**公共**：

```jsx
service cloud.firestore {
    match /databases/{database}/documents {
           match /{document=**} {
           allow read, write;
        }
    }
}
```

**用户**：

```jsx
service cloud.firestore {
    match /databases/{database}/documents {
        match /users/{userId} {
           allow read, write: if request.auth.uid == userId;
        }
    }
}
```

**私有**：

```jsx
service cloud.firestore {
    match /databases/{database}/documents {
       match /{document=**} {
          allow read, write: if false;
       }
    }
}
```

# 实时数据库和云 Firestore 之间的区别

我们已经看到实时数据库和云 Firestore 都是具有实时数据同步功能的 NoSQL 数据库。因此，让我们根据功能来看看它们之间的区别。

# 数据模型

这两个数据库都是云托管的 NoSQL 数据库，但两个数据库的数据模型是不同的：

| **实时数据库** | **云 Firestore** |
| --- | --- |

|

+   简单的数据非常容易存储。

+   复杂的分层数据在规模上更难组织。

|

+   简单的数据很容易存储在类似 JSON 的文档中。

+   使用子集合在文档中更容易地组织复杂和分层数据。

+   需要较少的去规范化和数据扁平化。

|

# 实时和离线支持

两者都具有面向移动端的实时 SDK，并且都支持本地数据存储，以便离线就绪的应用程序：

| **实时数据库** | **云 Firestore** |
| --- | --- |
| 仅 iOS 和 Android 移动客户端的离线支持。 | iOS、Android 和 Web 客户端的离线支持。 |

# 查询

通过查询从任一数据库中检索、排序和过滤数据：

| **实时数据库** | **云 Firestore** |
| --- | --- |

| **具有有限排序和过滤功能的深度查询：**

+   您只能在一个属性上进行排序或过滤，而不能在一个属性上进行排序和过滤。

+   查询默认是深度的。它们总是返回整个子树。

| **具有复合排序和过滤的索引查询：**

+   您可以在单个查询中链接过滤器并结合过滤和对属性进行排序。

+   为子集合编写浅层查询；您可以查询文档内的子集合，而不是整个集合，甚至是整个文档。

+   查询默认进行索引。查询性能与结果集的大小成正比，而不是数据集的大小。

|

# 可靠性和性能

当我们为项目选择数据库时，可靠性和性能是我们首先考虑的最重要部分：

| **Realtime Database** | **Cloud Firestore** |
| --- | --- |

| **Realtime Database 是一个成熟的产品：**

+   您可以期望从经过严格测试和验证的产品中获得的稳定性。

+   延迟非常低，因此非常适合频繁的状态同步。

+   数据库仅限于单个区域的区域可用性。

| **Cloud Firestore 目前处于 beta 版：**

+   在 beta 产品中的稳定性并不总是与完全推出的产品相同。

+   将您的数据存储在不同地区的多个数据中心，确保全球可扩展性和强大的可靠性。

+   当 Cloud Firestore 从 beta 版毕业时，它的可靠性将比 Realtime Database 更强。

|

# 可扩展性

当我们开发大规模应用程序时，我们必须知道我们的数据库可以扩展到多大程度：

| **Realtime Database** | **Cloud Firestore** |
| --- | --- |
| **扩展需要分片：**在单个数据库中扩展到大约 100,000 个并发连接和每秒 1,000 次写入。超出这一范围需要在多个数据库之间共享数据。 | **扩展将是自动的：**完全自动扩展（在 beta 版之后），这意味着您不需要在多个实例之间共享数据。 |

# 安全性

就安全性而言，每个数据库都有不同的方式来保护数据免受未经授权的用户访问：

**来源**：[`firebase.google.com/docs/firestore/rtdb-vs-firestore?authuser=0`](https://firebase.google.com/docs/firestore/rtdb-vs-firestore?authuser=0)。

| **Realtime Database** | **Cloud Firestore** |
| --- | --- |

| **需要单独验证的级联规则。**

+   Firebase 数据库规则是唯一的安全选项。

+   读写规则会级联。

+   您需要使用`.validate`在规则中单独验证数据。

| **更简单，更强大的移动端、Web 端和服务器端 SDK 安全性。**

+   移动端和 Web 端 SDK 使用 Cloud Firestore 安全规则，服务器端 SDK 使用**身份和访问管理**（**IAM**）。

+   除非使用通配符，否则规则不会级联。

+   数据验证会自动进行。

+   规则可以限制查询；如果查询结果可能包含用户无权访问的数据，则整个查询将失败。

|

截至目前，Cloud Firestore 仅提供测试版；因此，在本书中，我们只关注实时数据库。

# 崩溃报告

崩溃报告服务可帮助您诊断 Android 和 iOS 移动应用中的问题。它会生成详细的错误和崩溃报告，并将其发送到配置的电子邮件地址，以便快速通知问题。它还提供了一个丰富的仪表板，您可以在其中监视应用的整体健康状况。

# 身份验证

Firebase 身份验证提供了一个简单而安全的解决方案，用于管理移动和 Web 应用的用户身份验证。它提供多种身份验证方法，包括使用电子邮件和密码进行传统的基于表单的身份验证，使用 Facebook 或 Twitter 等第三方提供商，以及直接使用现有的帐户系统。

# 用于 Web 的 FirebaseUI 身份验证

Firebase UI 是完全开源的，并且可以轻松定制以适应您的应用程序，其中包括一些库。它允许您快速将 UI 元素连接到 Firebase 数据库以进行数据存储，允许视图实时更新，并且还提供了用于常见任务的简单接口，例如显示项目列表或集合。

FirebaseUI Auth 是在 Firebase 应用程序中添加身份验证的推荐方法，或者我们可以使用 Firebase 身份验证 SDK 手动执行。它允许用户为使用电子邮件和密码、电话号码以及包括 Google 和 Facebook 登录在内的最流行的身份提供者添加完整的 UI 流程。

FirebaseUI 可在[`opensource.google.com/projects/firebaseui`](https://opensource.google.com/projects/firebaseui)上找到。

我们将在接下来的章节中详细探讨身份验证。

# 云函数

云函数允许您拥有无服务器应用程序；您可以在没有服务器的情况下运行自定义应用程序后端逻辑。您的自定义函数可以在特定事件上执行，这些事件可以通过集成以下 Firebase 产品来触发：

+   Cloud Firestore 触发器

+   实时数据库触发器

+   Firebase 身份验证触发器

+   Firebase 的 Google Analytics 触发器

+   云存储触发器

+   云 Pub/Sub 触发器

+   HTTP 触发器

# 它是如何工作的？

一旦编写并部署函数，Google 的服务器立即开始监听这些函数，即监听事件并在触发时运行函数。随着应用程序的负载增加或减少，它会通过快速扩展所需的虚拟服务器实例数量来响应。如果函数被删除、空闲或由您更新，那么实例将被清理并替换为新实例。在删除的情况下，它还会删除函数与事件提供者之间的连接。

这里列出了云函数支持的事件：

+   `onWrite()`: 当实时数据库中的数据被创建、销毁或更改时触发

+   `onCreate()`: 当实时数据库中创建新数据时触发

+   `onUpdate()`: 当实时数据库中的数据更新时触发

+   `onDelete()`: 当实时数据库中的数据被删除时触发

这是一个云函数`makeUppercase`的代码示例：

```jsx
exports.makeUppercase = functions.database.ref('/messages/{pushId}/original')
 .onWrite(event => {
 // Grab the current value of what was written to the Realtime Database.
 const original = event.data.val();
 console.log('Uppercasing', event.params.pushId, original);
 const uppercase = original.toUpperCase();
 // You must return a Promise when performing asynchronous tasks inside a Functions such as
 // writing to the Firebase Realtime Database.
 // Setting an "uppercase" sibling in the Realtime Database returns a Promise.
 return event.data.ref.parent.child('uppercase').set(uppercase);
 });
```

编写云函数后，我们还可以测试和监视我们的函数。

# 云存储

任何移动应用或 Web 应用都需要一个存储空间，以安全且可扩展的方式存储用户生成的内容，如文档、照片或视频。云存储是根据相同的要求设计的，并帮助您轻松存储和提供用户生成的内容。它提供了一个强大的流媒体机制，以获得最佳的最终用户体验。

以下是我们如何配置 Firebase 云存储：

```jsx
// Configuration for your app
 // TODO: Replace with your project's config object
 var config = {
 apiKey: '<your-api-key>',
 authDomain: '<your-auth-domain>',
 databaseURL: '<your-database-url>',
 storageBucket: '<your-storage-bucket>'
 };
 firebase.initializeApp(config);
  // Get a reference to the storage service
 var storage = firebase.storage();
```

```jsx
// Points to the root reference  var storageRef = storage.ref(); // Points to 'images'  var imagesRef = storageRef.child('images');  // Points to 'images/sprite.jpg'  // Note that you can use variables to create child values  var fileName =  'sprite.jpg';  var spaceRef = imagesRef.child(fileName);  // File path is 'images/sprite.jpg'  var path = spaceRef.fullPath // File name is 'sprite.jpg'  var name = spaceRef.name // Points to 'images'  var imagesRef = spaceRef.parent; 
```

`reference.fullPath`的总长度必须在 1 到 1,024 字节之间，不能包含回车或换行字符。

避免使用#、[、]、*或?，因为这些在其他工具（如 Firebase 实时数据库）中效果不佳。

# 托管

Firebase 提供了一个托管服务，您可以通过简单的命令轻松部署您的 Web 应用和静态内容。您的 Web 内容将部署在**全球交付网络**（**GDN**）上，因此无论最终用户的位置如何，都可以快速交付。它为您的域名提供免费的 SSL，以通过安全连接提供内容。它还提供完整的版本控制和一键回滚的发布管理。

# Android 的测试实验室

我们使用不同的 Android API 版本在各种设备上测试我们的 Android 应用程序，以确保最终用户可以在任何 Android 设备上使用我们的应用程序而不会出现任何问题。但是，很难让所有不同的设备都可供测试团队使用。为了克服这些问题，我们可以使用 Test Lab，它提供了云托管基础设施，以便使用各种设备测试应用程序。它还可以轻松收集带有日志、视频和截图的测试结果。它还会自动测试您的应用程序，以识别可能的崩溃。

# 性能监控

Firebase 性能监控专门为 iOS 应用程序的性能测试而设计。您可以使用性能跟踪轻松识别应用程序的性能瓶颈。它还提供了一个自动化环境来监视 HTTP 请求，有助于识别网络问题。性能跟踪和网络数据可以更好地了解您的应用程序的性能。

以下产品类别用于增加用户群体并更好地吸引他们。

# Google Analytics

Google Analytics 是一个非常知名的产品，我认为没有开发人员需要介绍它。Firebase 的 Google Analytics 是一个免费的分析解决方案，用于衡量用户对您的应用的参与度。它还提供有关应用使用情况的见解。分析报告可以帮助您了解用户行为，因此可以更好地做出关于应用营销和性能优化的决策。您可以根据不同的参数生成报告，例如设备类型、自定义事件、用户位置和其他属性。分析可以配置为 Android、iOS 和 C++和 Unity 应用程序。

# 云消息传递

任何实时应用程序都需要发送实时通知。Firebase Cloud Messaging（FCM）提供了一个平台，帮助您实时向应用用户发送消息和通知。您可以免费在不同平台上发送数百亿条消息：Android、iOS 和 Web。我们还可以安排消息的交付 - 立即或在将来。通知消息与 Firebase Analytics 集成，因此无需编码即可监控用户参与度。

以下浏览器支持服务工作者：

+   Chrome：50+

+   Firefox：44+

+   Opera Mobile：37+

```jsx
// Retrieve Firebase Messaging object.
const messaging = firebase.messaging();
messaging.requestPermission()
.then(function() {
 console.log('Notification permission granted.');
 // Retrieve the Instance ID token for use with FCM.
 // ...
})
.catch(function(err) {
 console.log('Unable to get permission to notify.', err);
});
```

FCM SDK 仅在 HTTPS 页面上受支持，因为服务工作者仅在 HTTPS 站点上可用。

# 动态链接

动态链接是帮助您将用户重定向到移动应用程序或 Web 应用程序中特定内容位置的 URL。如果用户在桌面浏览器中打开动态链接，将打开相应的网页，但如果用户在 Android 或 iOS 中打开它，用户将被重定向到 Android 或 iOS 中的相应位置。此外，动态链接在应用之间起作用；如果应用尚未安装，用户将被提示安装应用。动态链接增加了将移动 Web 用户转化为原生应用用户的机会。动态链接作为在线社交网络活动的一部分也增加了应用的安装，并且永久免费。

# 远程配置

在不重新部署应用程序到应用商店的情况下更改应用程序的颜色主题有多酷？是的，通过 Firebase 远程配置，可以对应用程序进行即时更改。您可以通过服务器端参数管理应用程序的行为和外观。例如，您可以根据地区为特定的受众提供一定的折扣，而无需重新部署应用程序。

# 邀请

一般来说，每个人都会向朋友和同事推荐好的应用程序。我们通过复制和粘贴应用链接来做到这一点。然而，由于许多原因，它并不总是有效，例如，链接是针对安卓的，所以 iOS 用户无法打开它。Firebase 邀请使通过电子邮件或短信分享内容或应用推荐变得非常简单。它与 Firebase 动态链接一起工作，为用户提供最佳的平台体验。您可以将动态链接与要分享的内容相关联，Firebase SDK 将为您处理，为您的应用用户提供最佳的用户体验。

# 应用索引

对于任何应用程序，让应用程序安装以及保留这些用户并进行一些参与同样重要。重新吸引已安装您的应用程序的用户，应用索引是一种方法。通过 Google 搜索集成，您的应用链接将在用户搜索您的应用提供的内容时显示。此外，应用索引还可以帮助您改善 Google 搜索排名，以便在顶部搜索结果和自动完成中显示应用链接。

# AdMob

应用开发者的最终目标大多是将其货币化。AdMob 通过应用内广告帮助您实现应用的货币化。您可以有不同类型的广告，比如横幅广告、视频广告，甚至原生广告。它允许您展示来自 AdMob 调解平台或谷歌广告商的广告。AdMob 调解平台具有广告优化策略，旨在最大化您的收入。您还可以查看 AdMob 生成的货币化报告，以制定产品策略。

# AdWords

在当今世界，最好的营销策略之一是在线广告。Google AdWords 帮助您通过广告活动吸引潜在客户或应用用户。您可以将您的 Google AdWords 帐户链接到您的 Firebase 项目，以定义特定的目标受众来运行您的广告活动。

现在我们已经了解了 Firebase 平台的所有产品，我们可以混合匹配这些产品来解决常见的开发问题，并在市场上推出最佳产品。

# 开始使用 Firebase

在我们实际在示例应用程序中使用 Firebase 之前，我们必须通过 Firebase 控制台在[`console.firebase.google.com/`](https://console.firebase.google.com/)上创建我们的 Firebase 项目。打开此链接将重定向您到 Google 登录页面，您将需要登录到您现有的 Google 帐户或创建一个新的帐户。

一旦您成功登录到 Firebase 控制台，您将看到以下截图所示的仪表板：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/08005632-39e7-459f-8cd6-86e3f82d5a0a.png)

我们将通过单击“添加项目”按钮来创建我们的第一个项目。一旦您单击“添加项目”按钮，它将显示一个弹出窗口，询问您的项目名称和组织所在国家。我将其称为`DemoProject`，将国家设置为美国，然后单击“创建项目”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/fb88bf3c-f082-42c6-8a9a-5f0d86f81235.png)

项目创建后，您就可以开始了。您将被重定向到项目仪表板，您可以在其中配置您想要在项目中使用的产品/服务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/33b39356-9f67-4973-905a-713fa55bf80d.png)

接下来，我们将看看如何将这个 Firebase 项目集成到 Web 应用程序中。您的 Web 应用程序可以是任何 JavaScript 或 NodeJS 项目。

首先，我们将使用纯 JavaScript 创建一个示例，然后我们将进一步包含 React。

现在，您需要在系统中创建一个名为`DemoProject`的目录，并在其中创建几个名为`images`、`css`和`js`（JavaScript）的文件夹，以使您的应用程序易于管理。完成文件夹结构后，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/20b83747-0e37-4322-8a97-43205e7a46fc.png)

要将我们的 Firebase 项目集成到 JavaScript 应用程序中，我们需要一个代码片段，必须添加到我们的 JavaScript 代码中。要获取它，请单击“将 Firebase 添加到您的 Web 应用程序”，并注意它生成的初始化代码，它应该看起来像以下代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/b7726c54-087e-4351-8c80-4d3303073cd3.png)

当我们开始使用 ReactJS 或纯 JavaScript 制作应用程序时，我们需要进行一些设置，这仅涉及 HTML 页面并包括一些文件。首先，我们创建一个名为`chapter1`的目录（文件夹）。在任何代码编辑器中打开它。直接在其中创建一个名为`index.html`的新文件，并添加以下 HTML5 Boilerplate 代码：

+   例如，我创建了一个名为`DemoProject`的文件夹

+   在文件夹中创建一个名为`index.html`的文件

+   在你的 HTML 中，添加我们从 Firebase 控制台复制的代码片段：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/9545c90c-3af6-4f46-ab86-d5a785e6422c.png)我更喜欢并建议您在任何类型的 JavaScript 应用程序开发中使用 Visual Studio 代码编辑器，而不是列出的文本编辑器，因为它具有广泛的功能。

现在，我们需要将 Firebase 代码片段复制到 HTML 中：

```jsx
<!doctype html>
<html class="no-js" lang="">
<head>
 <meta charset="utf-8">
 <title>Chapter 1</title>
</head>
<body>
 <!--[if lt IE 8]>
<p class="browserupgrade">You are using an
<strong>outdated</strong> browser.
Please <a href="http://browsehappy.com/">
upgrade your browser</a> to improve your
experience.</p>
<![endif]-->
 <!-- Add your site or application content here -->
 <p>Hello world! This is HTML5 Boilerplate.</p>
 <script src="https://www.gstatic.com/firebasejs/4.6.1/firebase.js"></script>
 <script>
 // Initialize Firebase
 var config = {
 apiKey: "<PROJECT API KEY>",
 authDomain: "<PROJECT AUTH DOMAIN>",
 databaseURL: "<PROJECT DATABASE AUTH URL>",
 projectId: "<PROJECT ID>",
 storageBucket: "",
 messagingSenderId: "<MESSANGING ID>"
 };
 firebase.initializeApp(config);
 </script>
</body>
</html>
```

以下显示了我们数据库中的数据，我们将使用 JavaScript 获取并在 UI 上显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/9399942c-46ab-4989-8a92-8c56fae2a22a.png)

```jsx
//HTML Code to show the message
<p id="message">Hello world! This is HTML5 Boilerplate.</p>
<script>
//Firebase script to get the value from database and replace the "message".
var messageLabel = document.getElementById('message');
 var db = firebase.database();
 db.ref().on("value", function(snapshot) {
 console.log(snapshot.val());
 var object = snapshot.val();
 messageLabel.innerHTML = object.chapter1.example;
 });
</script>

```

在上述代码中，我们使用`on()`方法来检索数据。它以`value`作为事件类型，然后检索数据的快照。当我们向快照添加`val()`方法时，我们将获得要显示在`messageField`中的数据。

让我简要介绍一下 Firebase 中可用的事件，我们可以用它来读取数据。

就目前而言，在数据库规则中，我们允许任何人读取和写入数据库中的数据；否则，它会显示权限被拒绝的错误。将其视为一个例子：

`{`

`   "rules": {`

`      ".read": true,`

`     ".write": true`

`    }`

`}`

# Firebase 事件

如果您可以看到前面的代码，我们已经使用了接收 DataSnapshot 的回调函数，该 DataSnapshot 保存了快照的数据。快照是数据库引用位置在某个特定时间点的数据的图片，如果在引用位置不存在数据，则快照的值返回 null。

# value

最近，我们已经使用了这个宝贵的事件来读取实时数据库中的数据。每当数据发生变化时，都会触发此事件类型，并且回调函数将检索所有数据，包括子数据。

# child_added

每当我们需要检索项目对象列表时，此事件类型将被触发一次，并且每当新对象被添加到我们的数据给定路径时都会触发。与`value`不同，它返回该位置的整个对象，此事件回调作为包含两个参数的快照传递，其中包括新子项和先前子项数据。

例如，如果您想在博客应用程序中的每次添加新评论时检索数据，可以使用`child_added`。

# child_changed

当任何子对象更改时，将触发`child_changed`事件。

# child_removed

当立即子项被移除时，将触发`child_removed`事件。它通常与`child_added`和`child_changed`结合使用。此事件回调包含已移除子项的数据。

# child_moved

当您使用有序数据（如列表项的拖放）时，将触发`child_moved`事件。

现在，让我们快速查看一下我们的完整代码：

```jsx
<!doctype html> <html  class="no-js"  lang=""> <head> <meta  charset="utf-8"> <title>Chapter 1</title><script  src="</span>https://www.gstatic.com/firebasejs/4.6.1/firebase.js"></script> </head> <body><!--[if lt IE 8]> <p class="browserupgrade">You are using an<strong>outdated</strong> browser.Please <a href="http://browsehappy.com/">upgrade your browser</a> to improve yourexperience.
</p> <![endif]--> <!-- Add your site or application content here -->
<p  id="message">Hello world! This is HTML5 Boilerplate.</p> <script> // Initialize Firebase var  config  =  {
 apiKey: "<PROJECT API KEY>",
 authDomain: "<PROJECT AUTH DOMAIN>",
 databaseURL: "<PROJECT DATABASE AUTH URL>",
 projectId: "<PROJECT ID>",
 storageBucket: "",
 messagingSenderId: "<MESSANGING ID>"  }; firebase.initializeApp(config); var  messageLabel  =  document.getElementById('message'); var  db  =  firebase.database(); db.ref().on("value",  function(snapshot)  {
 console.log(snapshot.val());
 var object  =  snapshot.val();
 messageLabel.innerHTML  =  object.chapter1.example; });</script> </body> </html>
```

现在，在浏览器中打开`index.html`，让我们看一下结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/e989b866-a12a-4233-b2ef-10bbe437fdd6.png)

在上面的屏幕摘录中，我们可以看到`MessageLabel`上的数据库值和浏览器控制台中的 JavaScript 数据表示。

让我们通过从用户那里获取输入值并将这些值保存在数据库中来进一步扩展此示例。然后，使用事件，我们将在实时中在浏览器中显示这些消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/4d462cc7-ccf3-48cd-9fb5-5ecee3c675c5.png)

如图所示，我在数据库中添加了一个子节点`messages`。现在，我们将在我们的 HTML 中添加表单输入和保存按钮，并在底部在实时中显示用户提交的消息列表。

这是 HTML 代码：

```jsx
<input type="text" id="messageInput" />
 <button type="button" onclick="addData()">Send message</button>
<h2>Messages</h2>
 <p id="list">sdfdf</p>
```

现在，我们将创建`addData()`函数来获取并保存数据到 Firebase：

```jsx
 // Save data to firebase
 function addData() {
 var message = messageInput.value;
   db.ref().child('users').push({
    field: message
  });
  messageInput.value = '';
 }
```

在下一个屏幕截图中，我已经向输入文本添加了一些消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/6a1d1ab3-f606-44ea-b526-dbe561ea0a6c.png)

现在，我们需要将这些消息显示在 HTML 的消息标题底部：

```jsx
// Update list of messages when data is added
db.ref().on('child_added', function(snapshot) {
var data = snapshot.val();
console.log("New Message Added", data);
  snapshot.forEach(function(childSnap) {
    console.log(childSnap.val());
    var message = childSnap.val();
    messages.innerHTML = '\n' + message.field;
  });
});
```

我们已经使用了`child_added`事件，这意味着每当在节点上添加任何子项时，我们都需要获取该值并更新消息列表。

现在，打开你的浏览器并注意输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/ae0a520c-16dd-43d8-9621-8ad9b5ffaba3.png)

看起来很棒。我们现在能够看到用户提交的消息，并且我们的数据也在实时中得到更新。

现在，让我们快速看一下我们的代码是什么样子的：

```jsx
<!doctype html>
<html class="no-js" lang="">
<head>
 <meta charset="utf-8">
 <title>Chapter 1</title>
 <script src="https://www.gstatic.com/firebasejs/4.6.1/firebase.js"></script>
</head>
<body>
 <!-- Add your site or application content here -->
 <p id="message">Hello world! This is HTML5 Boilerplate.</p>
 <input type="text" id="messageInput" />
 <button type="button" onclick="addData()">Send message</button> 
 <h2>Messages</h2>
 <p id="list"></p>
<script>
 // Initialize Firebase
 var config = {
   apiKey: "<PROJECT API KEY>",
   authDomain: "<PROJECT AUTH DOMAIN>",
   databaseURL: "<PROJECT DATABASE AUTH URL>",
   projectId: "<PROJECT ID>",
   storageBucket: "",
   messagingSenderId: "<MESSANGING ID>"
 };
 firebase.initializeApp(config);

 var messageLabel = document.getElementById('message');
 var messageInput = document.getElementById('messageInput');
 var messages = document.getElementById('list'); 
 var db = firebase.database();
 db.ref().on("value", function(snapshot) {
     var object = snapshot.val();
     messageLabel.innerHTML = object.chapter1.example;
    //console.log(object);
 });
// Save data to firebase
 function addData() {
   var message = messageInput.value;
   db.ref().child('messages').push({
   field: message
 });
   messageInput.value = '';
 }
// Update results when data is added
 db.ref().on('child_added', function(snapshot) {
   var data = snapshot.val();
   console.log("New Message Added", data);
   snapshot.forEach(function(childSnap) {
   console.log(childSnap.val());
   var message = childSnap.val();
   messages.innerHTML = '\n' + message.field;
  });
 });
 </script>
</body>
</html>
```

# 总结

我们简单的 Hello World 应用程序和示例看起来很棒，并且正如他们应该的那样工作；所以，让我们回顾一下我们在本章学到的内容。

首先，我们介绍了 React 和 Firebase，以及设置 Firebase 帐户和配置有多么容易。我们还了解了实时数据库和 Firestore 之间的区别。除此之外，我们还学习了如何使用 JavaScript 初始化实时 Firebase 数据库，并开始构建我们的第一个 Hello World 应用程序。我们创建的 Hello World 应用程序演示了 Firebase 的一些基本功能，例如：

+   关于实时数据库和 Firestore

+   实时数据库和 Firestore 之间的区别

+   使用 JavaScript 应用程序创建 Firebase 帐户和配置

+   Firebase 事件（值和`child_data`）

+   将值保存到数据库中

+   从数据库中读取值

在第二章中，*将 React 应用程序与 Firebase 集成*，让我们使用 Firebase 构建一个 React 应用程序。我们将探索更多 React 和 Firebase 的基础知识，并介绍我们将在本书中构建的项目。


# 第二章：将 React 应用程序与 Firebase 集成

在第一章中，*使用 Firebase 和 React 入门*，我们看到了如何将 Firebase 与 JavaScript 集成，并创建了我们的第一个示例应用程序，这给了我们一个关于 Firebase 如何工作的简要概念。现在您已经完成了使用 JavaScript 和 Firebase 创建您的第一个 Web 应用程序，我们将使用 React 和 Firebase 构建帮助台应用程序。

我们将首先设置 React 环境，然后快速查看 JSX 和 React 组件方法。我们还将看到如何在 React 中使用 JSX 创建表单组件，并将这些表单值提交到 Firebase 实时数据库中。

以下是本章我们将关注的要点列表：

+   React 环境设置

+   JSX 和 React Bootstrap 的介绍

+   使用 JSX 创建表单

+   与 React 集成的 Firebase

+   保存和读取实时数据库中的数据

# 设置环境

首先，我们需要创建一个类似于我们在第一章中制作的 Hello World 应用程序的文件夹结构。以下屏幕截图描述了文件夹结构：

！[](Images/07f1cb0e-4dc0-4051-9e18-ee0d5db18194.png)

当我们开始使用 ReactJS 制作应用程序时，我们需要进行一些设置，这仅涉及 HTML 页面和`reactjs`库。一旦我们完成了文件夹结构的创建，我们需要安装我们的两个框架：ReactJS 和 Firebase。只需在页面中包含 JavaScript 和 CSS 文件即可。我们可以通过**内容交付网络**（**CDN**）（例如 Google 或 Microsoft）来实现这一点，但我们将在我们的应用程序中手动获取文件，这样我们就不必依赖于互联网，可以脱机工作。

# 安装 React

首先，我们必须转到[`reactjs.org/`](https://reactjs.org/)，查看我们将在应用程序中使用的最新可用版本：

！[](Images/05b3a56e-23a1-4afb-baef-4d6cb7ee64d4.png)

在撰写本书时，最新可用版本是 v16.0.0。我们将在本章中使用 CDN React 包来构建我们的应用程序：

```jsx
<script crossorigin src="https://unpkg.com/react@16/umd/react.development.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@16/umd/react-dom.development.js"></script>
```

前述版本仅用于开发，不适合生产。要使用经过缩小和优化的生产版本，我们需要使用这些生产包：

```jsx
<script crossorigin src="https://unpkg.com/react@16/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@16/umd/react-dom.production.min.js"></script>
```

如果您想使用不同的版本，请将数字`16`替换为您在应用程序中要使用的版本。让我们在您的 HTML 中包含开发版本 CDN：

```jsx
<!doctype html>
<html class="no-js" lang="">
<head>
    <meta charset="utf-8">
    <title>ReactJs and Firebase - Chapter 2</title>
    <script crossorigin  
     src="https://unpkg.com/react@16/umd/react.development.js">
    </script>
    <script crossorigin src="https://unpkg.com/react-dom@16/umd/react-
     dom.development.js"></script>
</head>
<body>
    <!-- Add your site or application content here -->
    <p>Hello world! This is Our First React App with Firebase.</p>
</body>
</html>
```

# 使用 React

现在我们已经从 ReactJS 中初始化了我们的应用程序，让我们开始编写我们的第一个 Hello World 应用程序，使用`ReactDOM.render()`。`ReactDOM.render`方法的第一个参数是我们要渲染的组件，第二个参数是它应该挂载（附加）到的 DOM 节点。请观察以下代码：

```jsx
ReactDOM.render( ReactElement element, DOMElement container,[function callback] )
```

我们需要将它转换为原始 JavaScript，因为并非所有浏览器都支持 JSX 和 ES6 功能。为此，我们需要使用转译器 Babel，它将在 React 代码运行之前将 JSX 编译为原始 JavaScript。在 head 部分与 React 库一起添加以下库：

```jsx
<script src="https://unpkg.com/babel-standalone@6.15.0/babel.min.js"></script>
```

现在，添加带有 React 代码的脚本标签：

```jsx
<script type="text/babel">
ReactDOM.render(
<h1>Hello, world!</h1>,
document.getElementById('hello')
);
</script>
```

`<script type="text/babel">`标签实际上是在浏览器中执行转换的标签。

JavaScript 的 XML 语法称为**JSX**。我们将更详细地探讨这一点。让我们在浏览器中打开 HTML 页面。如果你在浏览器中看到 Hello, world!，那么我们就在正确的轨道上。请观察以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/3c8f5f0c-ecfb-4e39-9dda-e508da724a13.png)

在上面的截图中，你可以看到它在你的浏览器中显示了 Hello, world!。看起来不错。我们已经成功完成了我们的设置，并用 ReactJS 构建了我们的第一个 Hello World 应用程序。

# React 组件

React 基于模块化构建，具有封装的组件，这些组件管理自己的状态，因此当数据发生变化时，它将高效地更新和渲染您的组件。在 React 中，组件的逻辑是用 JavaScript 编写的，而不是模板，因此您可以轻松地通过应用程序传递丰富的数据并在 DOM 之外管理状态。使用`render()`方法，我们在 React 中渲染一个组件，该组件接受输入数据并返回您想要显示的内容。它可以接受 HTML 标签（字符串）或 React 组件（类）。

让我们快速看一下这两种例子：

```jsx
var myReactElement = <div className="hello" />;
ReactDOM.render(myReactElement, document.getElementById('example'));
```

在这个例子中，我们将 HTML 作为字符串传递给`render`方法，之前我们创建了`<Navbar>`：

```jsx
var ReactComponent = React.createClass({/*...*/});
var myReactElement = <ReactComponent someProperty={true} />;
ReactDOM.render(myReactElement, document.getElementById('example'));
```

在上面的例子中，我们渲染组件只是为了创建一个以大写约定开头的局部变量。在 JSX 中使用大写约定，以避免区分本地组件类和 HTML 标签，因为 JSX 是 JavaScript 的扩展。在 React 中，我们可以以两种方式创建我们的 React 元素或组件：要么使用`React.createElement`的纯 JavaScript，要么使用 React 的 JSX。因此，让我们用 JSX 创建我们的第一个表单组件。

# 在 React 中 JSX 是什么？

JSX 是 JavaScript 语法的扩展，如果你观察 JSX 的语法或结构，你会发现它类似于 XML 编码。使用 JSX，你可以执行预处理步骤，将 XML 语法添加到 JavaScript 中。虽然你当然可以在不使用 JSX 的情况下使用 React，但 JSX 使 React 变得非常干净和可管理。与 XML 类似，JSX 标签具有标签名称、属性和子元素，如果属性值被引号括起来，那个值就成为一个字符串。XML 使用平衡的开放和关闭标签。JSX 类似地工作，它还有助于阅读和理解大量的结构，比 JavaScript 函数和对象更容易。

# 在 React 中使用 JSX 的优势

以下是一些优势的列表：

+   与 JavaScript 函数相比，JSX 非常简单易懂

+   JSX 代码语法对非程序员更加熟悉

+   通过使用 JSX，你的标记变得更有语义、有组织和有意义

# 如何使你的代码整洁清晰

正如我之前所说，这种结构/语法非常容易可视化/注意到，旨在使 JSX 格式的代码更加清晰和易懂，与 JavaScript 语法相比。

以下是一些代码片段的示例，它们将让你清楚地了解 React JavaScript 语法和 JSX：

```jsx
render: function () {
return React.DOM.div({className:"title"},
"Page Title",
React.DOM.hr()
);
}
```

现在，观察以下的 JSX 语法：

```jsx
render: function () {
return <div className="title">
Page Title<hr />
</div>;
}
```

所以现在我们清楚了，对于通常不习惯处理编码的程序员来说，JSX 真的很容易理解，他们可以学习、执行和编写它，就像 HTML 语言一样。

# 使用 JSX 的 React 表单

在开始使用 JSX 创建表单之前，我们必须了解 JSX 表单库。通常，HTML 表单元素输入将它们的值作为显示文本/值，但在 React JSX 中，它们取相应元素的属性值并显示它们。由于我们已经直观地感知到我们不能直接改变 props 的值，所以输入值不会有转变后的值作为展示值。

让我们详细讨论一下。要改变表单输入的值，你将使用 value 属性，然后你会看到没有变化。这并不意味着我们不能改变表单输入的值，但为此，我们需要监听输入事件，然后你会看到值的变化。

以下的例外是不言自明的，但非常重要：

在 React 中，标签内容将被视为值属性。由于 **for** 是 JavaScript 的保留关键字；HTML for 属性应该像 prop 一样被绑定。当您查看下一个示例时，您会更好地理解。现在，是时候学习了，为了在输出中有表单元素，我们需要使用以下脚本，并且还需要用先前编写的代码替换它。

现在，让我们开始为我们的应用程序构建一个 `Add Ticket form`。在根目录中创建一个 `reactForm.html` 文件和一个 <strong>js 文件夹中的 `react-form.js` 文件。以下代码片段只是一个包含 Bootstrap CSS 和 React 的基本 HTML 页面。

以下是我们的 HTML 页面的标记：

```jsx
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Add ticket form with JSX</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
</head>
<body>
    <script crossorigin 
    src="https://unpkg.com/react@16/umd/react.development.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@16/umd/react-
    dom.development.js"></script>
    <script src="https://unpkg.com/babel-
    standalone@6.15.0/babel.min.js"></script>
</body>
</html>
```

在页面底部加载所有脚本是一个很好的做法，在 `<body>` 标签关闭之前，这样可以成功在 DOM 中加载组件，因为当脚本在 `<head>` 部分执行时，文档元素不可用，因为脚本本身在 `<head>` 部分。解决这个问题的最佳方法是在页面底部保留脚本，在 `<body>` 标签关闭之前执行，这样在加载所有 DOM 元素后执行，不会抛出任何 JavaScript 错误。

由于 JSX 类似于 JavaScript，我们不能在 JSX 中使用 `class` 属性，因为它是 JavaScript 中的保留关键字。我们应该在 ReactDOM 组件中使用 `className` 和 `htmlFor` 作为属性名称。

现在，让我们在这个文件中使用 bootstrap 创建一些 HTML 布局

```jsx
 <div class="container">
   <div class="row">
     <nav class="navbar navbar-inverse navbar-static-top" role="navigation">
   <div class="container">
    <div class="navbar-header">
     <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
     <span class="sr-only">Toggle navigation</span>
     <span class="icon-bar"></span>
     <span class="icon-bar"></span>
     <span class="icon-bar"></span>
 </button>
 <a class="navbar-brand" href="#">HelpDesk</a>
 </div>
 <div class="navbar-collapse collapse">
 <ul class="nav navbar-nav">
    <li class="active"><a href="#">Add Ticket</a></li>
 </ul>
 </div>
 </div>
 </nav>
 <div class="col-lg-12">
 <h2>Add Ticket</h2>
 <hr/> 
 <div id="form">
    <!-- Here we'll load load our AddTicketForm component with help of "form" id -->
 </div>
 </div>
 </div>
 </div>
```

在上面的代码中，我们创建了导航并将其包装到 bootstrap 网格类中，以实现组件的响应行为。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/c879b515-17b8-4954-9452-70a2bb02dfcc.png)这是我们在浏览器中的 HTML 外观。

对于我们的 `Add Ticket form` 组件，我们需要以下表单字段以及标签：

+   邮箱：`<input>`

+   问题类型：`<select>`

+   分配部门：`<select>`

+   注释：`<textarea>`

+   按钮：`<button>`

此外，以下是支持的事件列表：

+   `onChange`, `onInput`, 和 `onSubmit`

+   `onClick`, `onContextMenu`, `onDoubleClick`, `onDrag`, 和 `onDragEnd`

+   `onDragEnter` 和 `onDragExit`

+   `onDragLeave`, `onDragOver`, `onDragStart`, `onDrop`, 和 `onMouseDown`

+   `onMouseEnter` 和 `onMouseLeave`

+   `onMouseMove`, `onMouseOut`, `onMouseOver`, 和 `onMouseUp`

让我们快速查看一下我们表单组件的代码在 `react-form.js` 中：

```jsx
class AddTicketForm extends React.Component {
    constructor() {
        super();
        this.handleSubmitEvent = this.handleSubmitEvent.bind(this);
    }
    handleSubmitEvent(event) {
        event.preventDefault();
    }
    render() {
        var style = {color: "#ffaaaa"};
        return ( <form onSubmit = {this.handleSubmitEvent}>
   <div className = "form-group">
      <label htmlFor = "email"> Email <span style = {style}> * </span></label>
      <input type = "text" id = "email" className = "form-control" placeholder = "Enter your email address" required />
   </div>
   <div className = "form-group">
      <label htmlFor = "issueType"> Issue Type <span style = {style}> * </span></label>
      <select className = "form-control" id = "issueType" required>
         <option value = ""> -- -- - Select-- -- < /option> 
         <option value = "Access Related Issue"> Access Related Issue </option>
         <option value = "Email Related Issues"> Email Related Issues </option>
         <option value = "Hardware Request"> Hardware Request</option>
         <option value = "Health & Safety"> Health & Safety </option>
         <option value = "Network"> Network </option> 
         <option value = "Intranet"> Intranet </option> 
         <option value = "Other"> Other </option> 
      </select>
   </div>
   <div className = "form-group">
      <label htmlFor = "department"> Assign Department 
      <span style = {style} > * </span>
      </label>
      <select className="form-control" id="department" required>
         <option value = ""> -- -- - Select-- -- </option> 
         <option value = "Admin" > Admin </option>
         <option value = "HR"> HR </option>
         <option value = "IT"> IT </option> 
         <option value = "Development"> Development </option>
      </select>
   </div>
   <div className = "form-group">
      <label htmlFor = "comments"> Comments 
      <span style = {style}> * </span>
      </label>
      ( <span id = "maxlength"> 200 </span> characters max)
      <textarea className = "form-control" rows = "3" id = "comments" required> </textarea> 
   </div>
   <div className = "btn-group">
      <button type = "submit" className = "btn btn-primary"> Submit </button> 
      <button type = "reset" className = "btn btn-default"> cancel </button> 
   </div>
</form>
            );
        }
    });
ReactDOM.render( <AddTicketForm /> ,
    document.getElementById('form')
);
```

要应用样式或调用`onSubmit()`函数的属性值，而不是使用引号（`""`），我们必须在 JavaScript 表达式中使用一对花括号（`{}`）。这意味着你可以通过用花括号包裹任何 JavaScript 表达式在 JSX 中嵌入它，甚至是一个函数。

在 react 库之后，在 HTML 页面底部添加这个脚本标签

```jsx
<script src="js/react-form.js" type="text/babel"></script>
```

现在，打开你的浏览器，让我们看看我们的 JSX 代码的输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/23a18add-ae14-4e93-9e6d-20eea16be3dc.png)

看起来很棒。我们可以看到我们的表单如预期的那样。

在 React 中创建组件时，第一个字符应该始终大写。例如，我们的`Add Ticket form`组件是`<AddTicketForm></AddTicketForm>`。

对于大型应用程序，这种方法并不推荐；我们不能每次创建表单元素时都把整个 JSX 代码放在一个地方。为了使我们的代码清晰和易于管理，我们应该创建一个可重用的组件，只需在需要使用它的地方给出该组件的引用。

那么让我们看看如何在我们现有的代码中实现这一点，我们将创建一个可重用的文本输入组件：

```jsx
const TextInput = ({
    type,
    name,
    label,
    onChange,
    placeholder,
    value,
    required
}) => {
    return ( <div className = "form-group">
        <label htmlFor = {name} > {label} </label> 
        <div className = "field">
        <input type = {type}  name = {name} className ="form-control" placeholder = {         placeholder} value = {value} onChange = {onChange} required = {required}/> 
</div> 
</div>
    )
}
```

在上面的代码片段中，我们创建了一个对象，它接受与输入属性相关的一些参数，并将这些参数的值分配给属性的值：

```jsx
<TextInput
 type="email"
 name="email"
 label="Email"
 placeholder="Enter your email address"
 required={true}/>
```

现在我们只需要在我们的`render`方法中像这样添加前面的`TextInput`组件，正如你在前面的代码中所看到的，而不是在我们的应用程序中每次都添加标签和输入；这展示了 ReactJS 的强大之处。

# 使用 React-Bootstrap

React-Bootstrap 是一个为 React 重建的开源 JavaScript 框架。它类似于 Bootstrap，我们有现成的组件可以与 React 集成。这是 Bootstrap 框架组件在 React 中的纯重新实现。React-Bootstrap 不依赖于任何其他框架，因为 Bootstrap JS 依赖于 jQuery。通过使用 React-Bootstrap，我们可以确保不会有外部 JavaScript 调用来渲染组件，这可能与`ReactDOM.render`不兼容或需要额外的工作。然而，我们仍然可以实现相同的功能和外观

Twitter Bootstrap，但代码更清晰，更少。

让我们看看如何使用 React-Bootstrap 创建我们的`Add Ticket Form`组件。

首先，按照这里提到的步骤在你的项目中配置 React-Bootstrap：

1.  通过运行以下命令安装 React bootstrap npm 包

+   npm install --save react-bootstrap

1.  如果您正在使用 create-react-app CLI，我们不需要担心 bootstrap CSS；它已经存在，我们不需要包含。

1.  现在，通过使用 import 关键字，我们需要在 React 应用程序中添加对 react-bootstrap 组件的引用。

例如：

+   import Button from 'react-bootstrap/lib/Button';

// 或者

import { Button } from 'react-bootstrap';

# 使用 React-Bootstrap 添加工单表单

现在，您可能会想知道，既然我们已经安装了 React-Bootstrap，并且已经通过使用`import`语句在我们的项目中添加了 React-Bootstrap 的引用，它们不会互相冲突吗？不，它们不会。React-Bootstrap 与现有的 Bootstrap 样式兼容，因此我们不需要担心任何冲突。

查看`Add Ticket`组件渲染方法的代码：

```jsx
<form>
    <FieldGroup id="formControlsEmail" type="email" label="Email 
    address" placeholder="Enter email" />
    <FormGroup controlId="formControlsSelect">
        <ControlLabel>Issue Type</ControlLabel>
        <FormControl componentClass="select" placeholder="select">
            <option value="select">select</option>
            <option value="other">...</option>
        </FormControl>
    </FormGroup>
    <FormGroup controlId="formControlsSelect">
        <ControlLabel>Assign Department</ControlLabel>
        <FormControl componentClass="select" placeholder="select">
            <option value="select">select</option>
            <option value="other">...</option>
        </FormControl>
    </FormGroup>
    <FormGroup controlId="formControlsTextarea">
        <ControlLabel>Textarea</ControlLabel>
        <FormControl componentClass="textarea" placeholder="textarea" 
        />
    </FormGroup>
</form>
```

如您在上述代码中所见，它看起来比 Twitter Bootstrap 组件更清晰，因为我们可以从 React-Bootstrap 中导入单个组件，而不是包含整个库，例如`import { Button } from 'react-bootstrap';`。

以下是支持的表单控件列表：

+   `<FieldGroup>`用于自定义组件

+   `<FormControl>`用于`<input>`，`<textarea>`和`<select>`

+   `<Checkbox>`用于复选框

+   `<Radio>`用于单选按钮

+   `FormControl.Static`（用于静态文本）

+   `HelpBlock`

现在由您决定是使用 React-Bootstrap 还是带有 Bootstrap 样式的普通 JSX 组件。

更多细节，请查看[`react-bootstrap.github.io/components/forms/`](https://react-bootstrap.github.io/components/forms/)。

# 使用 React 的 Firebase

我们已经创建了一个 React 表单，您可以在其中提出 Helpdesk 的工单并保存到 Firebase。为此，现在我们需要在现有应用程序中集成和初始化 Firebase。

它的样子是这样的：

在我们的 HTML 底部添加了脚本标签：

```jsx
<!--Firebase Config -->
<script src="js/firebase-config.js"></script>
<!--ReactJS Form -->
<script type="text/babel" src="js/react-form.js"></script>
```

将现有的 Firebase 配置代码从上一章复制到`firebase-config.js`中：

```jsx
 // Initialize Firebase
 var config = {
 apiKey: "<PROJECT API KEY>",
 authDomain: "<PROJECT AUTH DOMAIN>",
 databaseURL: "<PROJECT DATABASE AUTH URL>",
 projectId: "<PROJECT ID>",
 storageBucket: "",
 messagingSenderId: "<MESSANGING ID>"
 };
 firebase.initializeApp(config);
 var firebaseDb = firebase.database();
```

还要将`Reactjs Form`添加到`react-form.js`中，以使我们的代码看起来干净和可管理：

```jsx
class AddTicketForm extends React.Component {
    constructor() {
        super();
        this.handleSubmitEvent = this.handleSubmitEvent.bind(this);
    }
    handleSubmitEvent(event) {
            event.preventDefault();
            console.log("Email--" + this.refs.email.value.trim());
            console.log("Issue Type--" + 
            this.refs.issueType.value.trim());
            console.log("Department--" + 
            this.refs.department.value.trim());
            console.log("Comments--" + this.refs.comment.value.trim());
        },
        render() {
            return ();
        }
};
```

# 属性和状态

在我们进行实际操作之前，我们应该知道在 React 中状态和属性是什么。在 ReactJs 中，组件使用 JSX 将您的原始数据转换为丰富的 HTML，属性和状态一起构建这些原始数据，以保持您的 UI 一致。好的，让我们确定它到底是什么：

+   属性和状态都是普通的 JS 对象。

+   它们由渲染更新触发。

+   React 通过调用 `setState`（数据，回调）来管理组件状态。这种方法将数据合并到此状态中，并重新渲染组件，以保持我们的 UI 最新。例如，下拉菜单的状态（可见或隐藏）。

+   React 组件属性（属性）随时间不会改变，例如下拉菜单项。有时组件只使用此属性方法获取一些数据并呈现它，这使得您的组件无状态。

+   使用属性和状态一起可以帮助您创建一个交互式应用程序。

将表单数据读取和写入 Firebase 实时数据库。

正如我们所知，ReactJS 组件有自己的属性和类似状态的表单，支持

一些受用户交互影响的属性：

`<input>` 和 `<textarea>`：

| **组件** | **支持的属性** |
| --- | --- |
| `<input>` 和 `<textarea>` | Value, defaultValue |
| `<input>` 复选框或单选框类型 | checked, defaultChecked |
| `<select>` | selected, defaultValue |

在 HTML `<textarea>` 组件中，值是通过 children 设置的，但在 React 中也可以通过 value 设置。`onChange` 属性被所有原生组件支持，例如其他 DOM 事件，并且可以监听所有冒泡变化事件。

正如我们所见，状态和属性将使您能够改变组件的值并处理该组件的状态。

现在，让我们在我们的“添加工单表单”中添加一些高级功能，这些功能可以帮助您获取用户输入的值，并借助 Firebase，我们将这些值保存在数据库中。

# Ref 属性

React 提供了 `ref` 非 DOM 属性来访问组件。ref 属性可以是回调函数，并且它将在组件挂载后立即执行。因此，我们将在我们的表单元素中附加 ref 属性以获取这些值。

在添加 ref 属性后，让我们快速查看一下我们的组件：

```jsx
<div>
   <form ref = "form" onSubmit = {this.handleSubmitEvent}>
      <div className = "form-group">
         <label htmlFor= "email"> Email <span style = {style} > * </span></label>
         <input type = "text" id = "email" className = "form-control" placeholder = "Enter your email address" required ref = "email" />
      </div>
      <div className = "form-group">
         <label htmlFor = "issueType"> Issue Type <span style = {style}> * </span></label>
         <select className = "form-control" id = "issueType" required ref = "issueType">
            <option value = "" > -- -- - Select-- -- </option>
            <option value = "Access Related Issue"> Access Related 
               Issue 
            </option>
            <option value = "Email Related Issues"> Email Related 
               Issues 
            </option>
            <option value = "Hardware Request"> Hardware Request </option>
            <option value = "Health & Safety"> Health & Safety </option>
            <option value = "Network" > Network < /option> 
            <option value = "Intranet"> Intranet </option>
            <option value = "Other"> Other </option>
         </select>
      </div>
      <div className = "form-group">
         <label htmlFor = "department"> Assign Department <span style = {style} > * </span></label>
         <select className = "form-control" id = "department" required ref = "department">
            <option value = ""> -- -- - Select-- -- </option>
            <option value = "Admin"> Admin </option> 
            <option value = "HR"> HR </option>
            <option value = "IT"> IT </option>
            <option value = "Development"> Development </option>
         </select>
      </div>
      <div className = "form-group">
         <label htmlFor = "comments"> Comments <span style = {style
            } > * </span></label>
         ( <span id = "maxlength"> 200 </span> characters max) <textarea className = "form-control" rows = "3" id = "comments" required ref = "comment"> </textarea> 
      </div>
      <div className = "btn-group"><button type = "submit" className = "btn btn-primary"> Submit </button> <button type = "reset" className = "btn btn-default"> cancel </button> </div>
   </form>
</div>
```

现在，让我们打开浏览器，看看我们的组件是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/32fcc449-e14e-4b5c-a31e-c7332613ab06.png)

Firebase 在我们的应用程序中完美运行，因为您可以看到标题底部显示的消息“Hello world! This is My First JavaScript Firebase App”; 这是来自 Firebase 实时数据库

此外，在控制台中，您可以在提交表单时看到这些值。

现在我们需要将这些值保存到数据库中：

```jsx
//React form data object
var data = {
   date: Date(),
   email:this.refs.email.value.trim(),
   issueType:this.refs.issueType.value.trim(),
   department:this.refs.department.value.trim(),
   comments:this.refs.comment.value.trim()
 }
```

我们这样做是为了将“表单”数据对象写入 Firebase 实时数据库；`firebase.database.Reference`是一个异步监听器，用于从 Firebase 检索数据。一旦触发此监听器，它将在初始状态和数据发生更改时触发。

如果我们有权限，我们可以从 Firebase 数据库中读取和写入数据，因为默认情况下，数据库是受限制的，没有人可以在没有设置身份验证的情况下访问它。

`firebaseDb.ref().child('helpdesk').child('tickets').push(data);`

在上述代码中，我们使用`push()`方法将数据保存到 Firebase 数据库中。每当向指定的 Firebase 引用添加新子项时，它都会生成一个唯一键。我们还可以使用`set()`方法将数据保存到指定引用的数据；它将替换该节点路径上的现有数据：

`firebaseDb.ref().child('helpdesk').child('tickets').set(data);`

要在添加数据时检索更新结果，我们需要使用`on()`方法附加监听器，或者在任何情况下，如果我们想要在特定节点上分离监听器，那么我们可以通过调用`off()`方法来实现：

```jsx
 firebaseDb.ref().on('child_added', function(snapshot) {
 var data = snapshot.val();
  snapshot.forEach(function(childSnap) {
    console.log(childSnap.val());
     this.refs.form.reset();
    console.log("Ticket submitted successfully");
  });
 });
```

但是，如果我们想要一次读取它们而不监听更改，我们可以使用`once()`方法：

```jsx
 firebaseDb.ref().once('value').then(function(snapshot){
 });
```

这在我们不期望数据发生任何变化或任何主动监听时非常有用。例如，在我们的应用程序中成功验证用户配置文件数据时，加载用户配置文件数据时。

要更新数据，我们有`update()`方法，要删除数据，我们只需要调用该数据位置的`delete()`方法。

`update()`和`set()`方法都返回一个 Promise，因此我们可以使用它来知道写入是否提交到数据库。

现在，让我们提交表单并在浏览器控制台中查看输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/622b4050-3082-45e9-8003-dd4fc0510600.png)

看起来很棒；现在，让我们来看看我们的 Firebase 数据库：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/dc50aee5-ca2d-4d27-a179-6668239912f8.png)

我们能够看到我们从 ReactJS 表单提交的数据。

现在我们将以表格格式显示这些数据；为此，我们需要创建另一个 React 组件并设置组件的初始状态：

```jsx
constructor(){
    super();
    this.state = {
      tickets:[]
    }
  }
```

现在，使用`componentDidMount()`方法，我们将通过`ref()`调用数据库，迭代对象，并使用`this.setState()`设置组件的状态：

```jsx
componentDidMount()  {
  var  itemsRef  =  firebaseDb.ref('/helpdesk/tickets');
  console.log(itemsRef);
  itemsRef.on('value',  (snapshot)  =>  {
  let  tickets  =  snapshot.val();
  console.log(tickets);
  let  newState  = [];
  for (let  ticket  in  tickets) {
  newState.push({
 id:tickets[ticket],
 email:tickets[ticket].email,
 issueType:tickets[ticket].issueType,
 department:tickets[ticket].department,
 comments:tickets[ticket].comments,
 date:tickets[ticket].date
  });
  }
  this.setState({
 tickets:  newState
  });
  }); },
```

现在我们将在渲染方法内部迭代票务状态并在表格中显示：

```jsx
render() {
  return (<table className="table">
<thead>
<tr> 
    <th>Email</th>
    <th>Issue Type</th> 
    <th>Department</th> 
    <th>Comments</th> 
    <th>Date</th> 
</tr>
</thead>
<tbody>
 {
   this.state.tickets.map((ticket) => 
    { return ( 
    <tr key={ticket.id}> 
        <td>{ticket.email}</td> 
        <td>{ticket.issueType}</td> 
        <td>{ticket.department}</td> 
        <td>{ticket.comments}</td> 
        <td>{ticket.date}</td> 
</tr> )})
 } 
</tbody>
</table>
)}
```

现在，用户可以在实时上查看票据列表，每当数据库中添加新的票据时：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/872c1d5d-a530-40d8-9087-87092a62647b.png)

这是我们 HTML 页面的标记：`viewTickets.html`：

```jsx
 <div class="col-lg-10">
 <h2>View Tickets</h2>
 <hr>
    <div id="table" class="table-responsive">
      <!-- React Component will render here -->
    </div>
 </div>
 </div>
 </div>
```

这是在 Firebase 实时数据库中添加的票据列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/7c74b96e-598d-4ff0-9dc5-c3a8be9f1d3b.png)

# 总结

在本章中，我们看到了 JSX 在 React 中制作自定义组件以及使它们非常简单可视化、理解和编写方面起着重要作用。我们还看到了 props 和 state 在使组件交互以及在 DOM 交互中获取表单字段的值方面起着重要作用。借助`refs`，我们可以调用任何公共方法并向特定的子实例发送消息。

此外，我们通过创建一个`Add Ticket form`来探索了 React-Bootstrap 组件，该表单在所有预期的设备上以及桌面浏览器上都能很好地工作。

此外，我们还看到了在 ReactJS 应用程序中使用 Firebase 实时数据库有多么容易。只需几行代码，我们就可以将数据保存到实时数据库，并实时从数据库中检索票据列表，使我们的应用程序实时化。

在下一章中，我们将在 node.js 环境中进行 React 和 Firebase 设置，以及如何使用 Firebase OAuth 提供程序在我们的应用程序中添加身份验证。我们还将探索用于导航的 React 路由


# 第三章：使用 Firebase 进行认证

在上一章中，我们学习了如何将 Firebase 与 ReactJS 集成，以及如何在 JSX 中创建组件。我们还看到了如何与 DOM 元素交互以获取`onSubmit`表单值，并将其发送到 Firebase 数据库中以在云中存储和同步表单数据。React 使用快速、内部的合成 DOM 来执行差异，并为您计算最有效的 DOM 变化，其中您的组件活动地存在。

在本章中，我们将使用 React 和 JSX 创建一个`login`组件，以使用 Firebase 认证功能来保护我们的帮助台应用程序，该功能只允许授权用户查看和添加新的工单。

以下是本章我们将重点关注的内容列表：

+   使用 Node.js 进行 React 和 Firebase 设置

+   使用 React 和 JSX 创建复合组件

+   Firebase 认证配置

+   自定义认证

+   使用 Facebook 和 Google 进行第三方认证

# 使用 Node.js 进行 React 和 Firebase 设置

之前，我们使用纯 JavaScript 创建了一个 React 应用程序；现在我们需要使用 React 和 Firebase 设置来使用 node 做同样的事情。为此，我们必须在系统中安装 Node.js 和`npm`；如果没有，请先从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)下载 Node.js。安装完成后，运行以下命令以确保 node 和`npm`已正确安装：

对于 node，使用以下命令：

```jsx
node -v
```

对于`npm`，使用以下命令：

```jsx
npm -v
```

命令的输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/c9177530-5920-4bb6-a7c5-c0db7e000ac3.png)

现在我们需要安装`create-react-app`模块，它提供了初始和默认设置，并让我们快速启动 React 应用程序。在 CMD 中运行以下命令，它将全局安装`create-react-app`模块（即在命令后加上`-g`或`--global`）：

```jsx
npm install -g create-react-app 
or 
npm i -g create-react-app
```

安装完成后，在需要创建项目的本地目录中运行下一个命令；这将为 React 生成无需构建配置的快速启动项目：

```jsx
create-react-app <project-name> 
or
create-react-app login-authentication
```

安装完成后，我们的文件夹结构如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/14f5b27a-0d25-48c3-bced-3c36f661653d.png)

在这里，我们已经完成了 React 的设置；现在，我们安装`firebase npm`包并集成我们现有的应用程序。

运行以下命令安装`firebase npm`包：

```jsx
npm install firebase --save
```

安装 firebase 后，在`src`文件夹内创建一个名为 firebase 的文件夹。

在`src`文件夹中，创建一个名为`firebase-config.js`的文件，其中将托管我们项目的配置详细信息：

```jsx
import  firebase  from  'firebase'; const  config  = {  apiKey:  "AIzaSyDO1VEnd5VmWd2OWQ9NQuh-ehNXcoPTy-w",
  authDomain:  "demoproject-7cc0d.firebaseapp.com",
  databaseURL:  "https://demoproject-7cc0d.firebaseio.com",
  projectId:  "demoproject-7cc0d",
  storageBucket:  "demoproject-7cc0d.appspot.com",
  messagingSenderId:  "41428255556" }; firebase.initializeApp(config); export  default  firebase;
```

同样，我们需要在节点中集成我们现有的组件视图票和`addTicket`，使用导入和导出关键字，并使用`npm`命令，我们需要安装 React 和 firebase 模块及其依赖项。

这是您的`package.json`应该看起来的样子：

```jsx
//package.json
{
 "name": "login-authentication",
 "version": "0.1.0",
 "private": true,
 "dependencies": {
 "firebase": "⁴.8.0",
 "react": "¹⁶.2.0",
 "react-dom": "¹⁶.2.0",
 "react-router-dom": "⁴.2.2",
 "react-scripts": "1.0.17",
 "react-toastr-basic": "¹.1.14"
 },
 "scripts": {
 "start": "react-scripts start",
 "build": "react-scripts build",
 "test": "react-scripts test --env=jsdom",
 "eject": "react-scripts eject"
 }
}
```

此外，在集成现有应用程序后，应用程序文件夹结构如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/fca7a632-68f0-47ec-b404-0be0a1903c43.png)

# 用于身份验证的 Firebase 配置

Firebase 身份验证是一个非常令人印象深刻的功能，可以通过安全规则授予用户读/写访问权限。我们还没有在我们的帮助台应用程序中涵盖或添加安全规则。Firebase 让我们能够使用其自己的电子邮件/密码和 OAuth 2 集成来进行 Google、Facebook、Twitter 和 GitHub 的认证。我们还将把我们自己的身份验证系统与 Firebase 集成，以便让用户访问帮助台应用程序，并允许用户在我们的系统上创建帐户。

让我们来看看用于身份验证的 Firebase 提供程序列表，并执行以下步骤来为我们的应用程序启用 Firebase 身份验证：

1.  打开[`firebase.google.com`](http://firebase.google.com)并使用您的凭据登录

1.  点击左侧的 DEVELOP 选项卡内的身份验证选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/36b9e9a4-e023-43e0-97f8-e40802f235a0.png)

在上述截图中，如果您能看到，我们在身份验证部分有四个可用的选项卡，并且我们已经启用了提供商的身份验证，其中包括自定义的电子邮件/密码选项，我们可以添加到用户选项卡和 Google 身份验证。

+   用户：在这里，我们可以管理并添加多个用户的电子邮件 ID 和密码，以便使用各种提供程序进行身份验证，而无需编写任何服务器端代码。

+   登录方式：在此部分，我们可以看到 Firebase 中可用的提供程序列表。我们还可以管理授权域，防止用户使用相同的电子邮件地址和登录配额。

+   模板：此功能允许我们自定义 Firebase 发送的电子邮件模板，当用户使用电子邮件和密码注册时。我们还可以自定义密码重置、电子邮件地址更改和短信验证的模板。

在本章中，我们将涵盖以下三种身份验证方式：

+   脸书

+   谷歌

+   电子邮件/密码

# 使用 Facebook 进行身份验证

要向我们的帮助台应用程序添加 Facebook 身份验证，如果您还没有 Facebook 帐户，您需要在 Facebook 上创建一个帐户。否则，我们需要登录到 Facebook 开发者论坛[`developers.facebook.com/apps`](https://developers.facebook.com/apps)。一旦我们登录，它会显示应用程序列表和一个“添加新应用程序”按钮，用于创建身份验证的新应用程序 ID。参考以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/cd96aa89-2743-46cb-b29b-68d3b7c1474f.png)

点击“添加新应用程序”按钮；它会显示弹出窗口以添加应用程序的名称。然后，点击“创建应用程序 ID”，它会将您重定向到我们应用程序的仪表板：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/6176e422-b29a-428d-be05-13d79bf80418.png)这是 Facebook 开发者应用程序仪表板的屏幕截图。图像的目的只是显示 Facebook 提供的 API 或产品列表，以与任何 Web 应用程序集成。

现在，我们需要选择 Facebook 登录进行设置：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/621e6610-baf7-496c-8307-ec7377a94f9a.png)

如果您能看到上述的屏幕截图，我们需要为客户端 OAuth 设置。为此，我们首先需要启用嵌入式浏览器 OAuth 登录功能以控制 OAuth 登录的重定向，然后复制有效的 OAuth 重定向 URL，当我们在 Firebase 中启用 Facebook 提供程序时，我们可以获得它。

要在 Firebase 中启用 Facebook 身份验证，我们需要从 Facebook 应用程序仪表板复制**应用程序 ID**和**应用程序密钥**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/46baa329-f0cf-4c14-a87a-e0e7a78d8b24.png)

然后，将这些复制的值放入 firebase 输入字段中，复制重定向 URI，并将其粘贴到客户端 OAuth 设置中。还要启用 Facebook 身份验证，然后点击“保存”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/9d6bcc9f-bde3-4c45-9f71-cc4840a94f9b.png)

这是我们在 Facebook 开发者论坛和 Firebase 中进行 Facebook 身份验证的最后一件事情。

点击保存，并注意提供程序的状态现在已启用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/a92cc442-34ba-4446-9ea7-6ffe92b50130.png)

现在，点击部分左侧的数据库，转到规则面板；它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/cf946010-0267-4b9d-9295-59470d4f2885.png)图像的目的是显示实时数据库部分和规则选项卡下的选项卡列表。在这里，我们可以添加数据库的安全规则来保护我们的数据，并借助模拟器来验证它是否按预期工作。

在我们的应用程序中，以前每个人都有权访问我们的应用程序和数据库以读取和写入数据。现在，我们将更改前面的规则配置，以便只有经过授权的用户才能访问应用程序并向我们的数据库写入数据。查看给定的代码并发布更改：

```jsx
{
 "rules": {
 ".read": "auth != null",
 ".write": "auth != null"
 }
}
```

# 使用 React 创建登录表单进行身份验证

就像我们为 Firebase 和 Facebook 的身份验证配置以及启用其他提供程序的功能一样，现在我们将在 react 中创建一个登录表单，以确保应用程序始终验证用户是否已登录；它将重定向用户到登录页面。因此，让我们创建一个登录页面，并配置 React 路由以根据路径 URL 重定向用户。

打开 firebase 文件夹中的`firebase-config.js`并导出以下不同提供程序的对象，以便我们可以在整个应用程序中访问这些对象：

```jsx
export  const  firebaseApp  =  firebase.initializeApp(config); export  const  googleProvider  =  new  firebase.auth.GoogleAuthProvider(); export  const  facebookProvider  =  new  firebase.auth.FacebookAuthProvider();
```

在上述代码中，`new firebase.auth.GoogleAuthProvider()`将为我们提供通过 Google API 对用户进行身份验证的方法。

同样，`new firebase.auth.FacebookAuthProvider()`将为我们提供通过 Facebook API 对用户进行身份验证的方法。

打开`app.js`并将以下代码添加到构造函数中以初始化应用程序的状态：

```jsx
constructor() { super();   this.state  = {  authenticated :  false,
  data:''
 } }
```

在这里，我们将 authenticated 的默认值设置为 false，因为这是应用程序的初始状态，用户尚未通过 Firebase 进行身份验证；数据的默认值在组件的初始状态下为空。当用户登录时，我们将更改这些状态。

首先，让我们在`login.js`中创建`Login`组件，并在`constructor()`中设置该组件的初始状态：

```jsx
 constructor() {
 super();
   this.state = {
     redirect: false
   }
 }
```

我们在初始状态下将重定向的默认值设置为`false`，但每当用户登录和退出时，它都会更改：

```jsx
if(this.state.redirect === true){
 return <Redirect to = "/" />
 }
 return (
 <div className="wrapper">
 <form className="form-signin" onSubmit={(event)=>{this.authWithEmailPassword(event)}} ref={(form)=>{this.loginForm = form}}> 
 <h2 className="form-signin-heading">Login</h2>
 <input type="email" className="form-control" name="username" placeholder="Email Address" ref={(input)=>{this.emailField = input}} required />
 <input type="password" className="form-control" name="password" placeholder="Password" ref={(input)=>{this.passwordField = input}} required /> 
 <label className="checkbox">
 <input type="checkbox" value="remember-me" id="rememberMe" name="rememberMe"/> Remember me
 </label>
 <button className="btn btn-lg btn-primary btn-block btn-normal" type="submit">Login</button> 
 <br/> 
<!-- Here we will add the buttons for google and facebook authentication
 </form>
 </div>
 );
```

在`render`方法中，我们将检查状态并将用户重定向到不同的路由`<Redirect>`。它将覆盖历史堆栈中的当前路由，就像服务器端重定向（HTTP 3xx）一样。

以下是我们可以与`Redirect`组件一起使用的属性列表：

+   `to:String`：我们还使用的重定向 URL。

+   `to:Object`：带有参数和其他配置（例如状态）的位置 URL。考虑以下示例：

```jsx
<Redirect to={{
 pathname: '/login',
 search: '?utm=your+selection',
 state: { referrer: currentLocation }
}}/>
```

+   `: bool`：当为 true 时，重定向将在历史记录中推送一个新条目，而不是替换当前条目。

+   `from: string`：要重定向的旧 URL。这只能用于匹配`<Switch>`内的位置。考虑这个例子：

```jsx
<Switch>
 <Redirect from='/old-url' to='/new-url'/>
 <Route path='/new-url' component={componentName}/>
</Switch>
```

所有上述的`<Redirect>`功能只在 React Router V4 中可用。

我们已经为我们的登录表单添加了 JSX，并绑定了方法和 ref 属性以访问表单值。我们还添加了 Facebook 和 Google 身份验证的按钮。只需看看以下代码：

```jsx
 <!-- facebook button that we have bind with authWithFacebook()-->
<button className="btn btn-lg btn-primary btn-facebook btn-block" type="button" onClick={()=>{this.authWithFacebook()}}>Login with Facebook</button> 
```

```jsx
<!-- Google button which we have bind with authWithGoogle()-->
 <button className="btn btn-lg btn-primary btn-google btn-block" type="button" onClick={()=>{this.authWithGoogle()}}>Login with Google</button>
```

在`app.js`中，我们已经配置了一个路由器，就像这样：

```jsx
<Router>
<div className="container"> {
this.state.authenticated
?
(
<React.Fragment>
<Header authenticated = {this.state.authenticated}/>
<Route path="/" render={() => (<Home userInfo = {this.state.data} />)} />
<Route path="/view-ticket" component={ViewTicketTable}/>
<Route path="/add-ticket" component={AddTicketForm}/>
</React.Fragment>
)
:
(
<React.Fragment>
<Header authenticated = {this.state.authenticated}/>
<Route exact path="/login" component={Login}/>
</React.Fragment>
)
}
</div>
</Router>
```

在上面的代码中，我们使用的是 React Router 版本 4，这是一个完全重写的用于 react 包的路由器。在以前的 React 路由器版本中，他们使用了非常困难的配置，这将很难理解，而且我们还需要创建一个单独的组件来管理布局。在路由器 V4 中，一切都作为一个组件工作。

在 React 路由器 V4 中，我们需要从 react-router-dom 中导入，而不是从 V3 中的 react-router。如果路由路径匹配，`<Router>`组件和所有其他子组件都会被渲染。

使用`<React.Fragment>`标签，我们可以包装任何 JSX 组件，而不会在 DOM 中添加另一个节点。

在 V4 react 路由器中，不再有`<IndexRoute>`；使用`<Route exact>`将会做同样的事情。

现在我们将更改包含导航的标题组件，并添加登录和注销链接：

```jsx
class Header extends Component {
render() {
 return (
 <div className="navbar navbar-inverse firebase-nav" role="navigation">
 {
 this.props.authenticated
 ?
 (
 <React.Fragment>
 <ul className="nav navbar-nav">
 <li className="active"><Link to="/">Home</Link></li>
 <li><Link to="/view-ticket">Tickets</Link></li>
 <li><Link to="/add-ticket">Add new ticket</Link></li>
 </ul>
 <ul className="nav navbar-nav navbar-right">
 <li><Link to="/logout">Logout</Link></li>
 </ul>
 </React.Fragment>
 ):(
 <React.Fragment>
 <ul className="nav navbar-nav navbar-right">
 <li><Link to="/login">Register/Login</Link></li>
 </ul>
 </React.Fragment>
 )
 }
 </div>
 );
 }
}
```

如果我们使用 React 路由器，这是必要的。让我们在导航中添加`<link>`而不是`<a>`标签，并用`to`替换`href`属性。在 V4 中，我们还可以使用`<NavLink>`；它的工作方式与`<Link>`相同，但可以添加额外的样式。看看这段代码：

```jsx
<li><NavLink to="/view-ticket/" activeClassName="active" activeStyle={{fontWeight: 'bold', color: red'}} exact strict>Tickets</NavLink></li>
```

根据身份验证，我们将更新导航以显示登录和注销链接。

通过在命令提示符中运行以下命令再次启动服务器：

```jsx
npm start
```

一旦服务器启动，打开浏览器快速查看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/f45b9ea6-6056-4209-9ebf-d5e7fed704ba.png)

如果你只看一下上面的屏幕摘录并注意地址栏，我尝试打开另一个 URL 来查看票据，但除了标题登录链接外，什么都没有显示；所以现在，如果我们点击登录，它将呈现登录表单。请参考以下截图；它应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/b8432ea6-e507-4764-bbca-61c82fcc3060.png)

令人惊讶的是，我们的登录表单看起来很棒，正如预期的那样。

有关 react 路由器的更多信息，您可以查看[`reacttraining.com/react-router/web/api`](https://reacttraining.com/react-router/web/api)。

# 使用 Facebook 进行身份验证

每个按钮的`onClick`将指向三个函数，这些函数将对用户进行身份验证。Facebook 身份验证方法将处理我们与 Firebase 的身份验证，如下所示：

```jsx
 authWithFacebook(){
 console.log("facebook");
 firebaseApp.auth().signInWithPopup(facebookProvider).then((result,error)=>{
 if(error){
   console.log("unable to sign in with facebook");
 }
 else{
   this.setState({redirect:true})
 }}).catch((error)=>{
        ToastDanger(error.message);
    })
 }
```

在这里，我们从 firebase `auth`模块调用`signInWithPopup()`方法，并传递 facebook 提供程序。

为了在 UI 上显示错误消息，我们使用 React Toaster 模块，并将这些消息传递给它（在使用之前不要忘记安装和导入 React Toaster 模块）。我们还需要将`authWithFacebook()`方法绑定到构造函数中。`npm install --save react-toastr-basic`

`//在 app.js 中导入容器`

从' react-toastr-basic '导入 ToastrContainer;

`//在 render 方法内部`

`<ToastrContainer />`

```jsx
constructor() {
 super();
 this.authWithFacebook = this.authWithFacebook.bind(this);
 this.state = {
  redirect: false,
  data:null
 }}
```

现在，当我们点击“使用 Facebook 登录”按钮时，它将打开一个弹出窗口，让我们选择使用 Facebook 帐户登录，如下所示：

！[](Images/f88be669-622c-4468-838c-7dd194946679.png)

`signInWithPopup()`具有一个 promise API，允许我们在其上调用`.then()`并传递回调。此回调将提供一个包含用户的所有信息的名为`user`的对象，其中包括他们刚刚成功登录的姓名、电子邮件和用户照片 URL。我们将使用`setState()`将此对象存储在状态中，并在 UI 上显示用户的姓名、电子邮件和照片：

！[](Images/c4e5d1f7-b041-4aa4-886e-6efcd4205989.png)

# 使用 Google 进行身份验证

同样，我们可以在我们的应用程序中配置 Google 身份验证；只需将以下代码添加到`authWithGoogle()`方法中，它将打开用于使用 Google 登录的弹出窗口：

```jsx
 authWithGoogle(){
 console.log("Google");      
 googleProvider.addScope('profile');
 googleProvider.addScope('email');
 firebaseApp.auth().signInWithPopup(googleProvider).then((result,error)=>{
   if(error){
     console.log("unable to sign in with google");
    }
   else{
     this.setState({redirect:true,data:result.user})
   }}).catch((error)=>{
        ToastDanger(error.message);
     })
}
```

如您所见，我已添加了我们想要从身份验证提供程序请求的额外 OAuth 2.0 范围。要添加范围，请调用添加范围。我们还可以使用`firebase.auth().languageCode = 'pt'`来定义语言代码。如果我们想要在请求中发送特定的自定义参数，可以调用`setCustomParamter()`方法。考虑这个例子：

```jsx
provider.setCustomParameters({
 'login_hint': 'admin'
});
```

因此，一旦您点击“使用 Google 登录”按钮，它将触发弹出窗口以与 Google 进行身份验证：

！[](Images/6f3179e5-4f9f-4951-b3af-5182f374eeee.png)

因此，如果您已经登录并尝试使用不同提供者的相同电子邮件 ID 登录，它会抛出错误，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/a2cae460-9223-4599-86d8-64cb7b80c31e.png)

好的，现在让我们看看如何处理这些类型的错误。

# 处理帐户存在的错误

考虑到我们已经在 firebase 设置中启用了“每个电子邮件地址一个帐户”的选项。如前面的截图所示，当我们尝试使用提供者（Google）登录已经存在于 firebase 中的具有不同提供者（如 Facebook）的电子邮件时，它会抛出上述错误——`auth/account-exists-with-different-credential`——我们可以在前面的截图中看到。为了处理这个错误并完成对所选提供者的登录，用户必须首先登录到现有的提供者（Facebook），然后链接到前面的 AuthCredential（带有 Google ID 令牌）。重写`authWithFacebook()`方法后，我们的代码如下：

```jsx
if (error.code === 'auth/account-exists-with-different-credential') {
 // Step 2.
 var pendingCred = error.credential;
 // The provider account's email address.
 var email = error.email;
 // Get registered providers for this email.
 firebaseApp.auth().fetchProvidersForEmail(email).then(function(providers) {
 // Step 3.
 // If the user has several providers,
 // the first provider in the list will be the "recommended" provider to use.
 if (providers[0] === 'password') {
 // Asks the user his password.
 // In real scenario, you should handle this asynchronously.
 var password = promptUserForPassword(); // TODO: implement promptUserForPassword to open the dialog to get the user entered password.
 firebaseApp.auth().signInWithEmailAndPassword(email, password).then(function(user) {
 // Step 4.
 return user.link(pendingCred);
 }).then(function() {
 // Google account successfully linked to the existing Firebase user.
 });
 }
 })}
```

要了解更多错误代码列表，请访问[`firebase.google.com/docs/reference/js/firebase.auth.Auth#signInWithPopup`](https://firebase.google.com/docs/reference/js/firebase.auth.Auth#signInWithPopup)。

# 管理刷新时的登录

目前，每次刷新页面时，我们的应用都会忘记用户已经登录。但是，Firebase 有一个事件监听器——`onAuthStateChange()`——可以在应用加载时检查身份验证状态是否已更改，以及用户上次访问应用时是否已经登录。如果是，那么您可以自动将其重新登录。

我们将把这个方法写在`app.js`的`componentDidMount()`中。只需查看以下代码：

```jsx
 componentWillMount() {
   this.removeAuthListener = firebase.auth().onAuthStateChanged((user) 
   =>{
    if(user){
     console.log("App user data",user);
     this.setState({
       authenticated:true,
       data:user.providerData
     })
  }
 else{
   this.setState({
     authenticated:false,
     data:''
 })}
 })}
```

此外，在`componentWillUnmount()`中，我们将删除该监听器以避免内存泄漏：

```jsx
 componentWillUnmount(){
   this.removeAuthListener();
 }
```

现在，如果您刷新浏览器，它不会影响应用程序的状态；如果您已经登录，它将保持不变。

使用 Facebook API 或其他方式登录后，我们需要在 UI 中显示用户信息。为此，如果再次查看路由器组件，我们将使用`userInfo`属性将此用户信息发送到`Home`组件中：

```jsx
<Route path="/" render={() => (<Home userInfo = {this.state.data} />)} />
```

在`Home`组件的渲染方法中，我们将迭代包含成功登录到系统的用户数据的`userInfo`属性：

```jsx
render() {
 var userPhoto = {width:"80px",height:"80px",margintop:"10px"}; 
 return (
 <div>
 {
 this.props.userInfo.map((profile)=> {
 return (
 <React.Fragment key={profile.uid}>
 <h2>{ profile.displayName } - Welcome to Helpdesk Application</h2>
 <div style={userPhoto}>
 <img src = { profile.photoURL } alt="user"/>
 <br/>
 <span><b>Eamil:</b></span> {profile.email }
 </div>
 </React.Fragment>
 )})
 }
 </div>
 )}
```

在`Logout()`方法中，我们将简单地调用 firebase auth 中的`signOut()`方法；通过使用 Promise API，我们从应用程序状态中删除用户数据。现在`this.state.data`等于 null，用户将看到登录链接而不是注销按钮。它应该是这样的：

```jsx
constructor() {
 super();
  this.state = {
    redirect: false,
    data:''
  }
 }
 componentWillMount(){
   firebaseApp.auth().signOut().then((user)=>{
     this.setState({
      redirect:true,
      data: null
   })
 })}
 render() {
 if(this.state.redirect === true){
 return <Redirect to = "/" />
 }
 return (
 <div style={{textAlign:"center",position:"absolute",top:"25%",left:"50%"}}>
 <h4>Logging out...</h4>
 </div>);
 }
```

# 使用电子邮件和密码进行身份验证

在 Firebase 中，我们还可以将您自己的身份验证系统与 Firebase 身份验证集成，以便用户可以访问数据，而无需强制他们使用现有系统的第三方 API 来创建帐户。Firebase 还允许匿名身份验证会话，通常用于在等待客户端使用永久的`auth`方法进行身份验证时保存少量数据。我们可以配置这个匿名会话，直到用户使用永久的`login`方法登录或清除他们的浏览器缓存的最后几天、几周、几个月，甚至几年。例如，一个购物车应用程序可以为每个将商品添加到购物车的用户创建一个匿名身份验证会话。购物车应用程序将提示用户创建一个帐户以进行结账；在那时，购物车将被持久化到新用户的帐户，并且匿名会话将被销毁。

# 支持的身份验证状态持久性类型

我们可以根据应用程序或用户的要求，在指定的 Firebase 身份验证`instance(.auth())`上使用三种持久性中的一种：

| **Auth 实例** | **值** | **描述** |
| --- | --- | --- |
| `firebase.auth.Auth.Persistence.LOCAL` | 'local' | 它表示即使关闭浏览器窗口或在 React Native 中销毁活动，状态也将被持久化。为此，需要显式注销以清除该状态。 |
| `firebase.auth.Auth.Persistence.SESSION` | 'session' | 在这种情况下，状态将仅持续到当前会话或选项卡，并且在用户进行身份验证的选项卡或窗口关闭时将被清除。 |
| `firebase.auth.Auth.Persistence.NONE` | 'none' | 当我们指定这个时，意味着状态只会存储在内存中，并且在窗口或应用程序刷新时将被清除。 |

考虑这个例子：

```jsx
firebaseApp.auth().setPersistence('session')
 .then(function() {
 // Auth state is now persisted in the current
 // session only. If user directly close the browser window without doing signout then it clear the existing state
 // ...
 // New sign-in will be persisted with session.
 return firebase.auth().signInWithEmailAndPassword(email, password);
 })
 .catch(function(error) {
 // Handle Errors here.
 });
```

让我们创建一个名为`authWithEmailPassword()`的函数，并将以下代码添加到其中：

```jsx
const email = this.emailField.value
const password = this.passwordField.value;
firebaseApp.auth().fetchProvidersForEmail(email).then((provider)=>{
 if(provider.length === 0){
 //Creating a new user
 return firebaseApp.auth().createUserWithEmailAndPassword(email,password);
 } else if(provider.indexOf("password") === -1){
 this.loginForm.reset();
 ToastDanger('Wrong Password. Please try again!!')
 } else {
 //signin user
 return firebaseApp.auth().signInWithEmailAndPassword(email,password);
 }}).then((user) => {
 if(user && user.email){
 this.loginForm.reset();
 this.setState({redirect: true});
 }})
 .catch((error)=>{
 console.log(error);
 ToastDanger(error.message);
 })
```

在上述代码中，首先，我们从表单中获取值。当用户点击提交按钮时，借助`fetchProvidersForEmail(email)`，我们验证电子邮件是否存在于我们当前的 firebase 系统中；如果不存在，它将使用`createUserWithEmailAndPassword()`方法创建一个新用户。如果返回 true，我们将验证密码；如果用户输入了错误的密码，它将提示用户输入错误的密码，否则使用相同的方法—`signInWithEmailAndPassword()`—登录他们，并通过重定向 true 来更新组件的状态。

当我们在`createUserWithEmailAndPassword()`方法中创建新用户时，它会返回以下错误代码：

+   auth/email-already-in-use

+   auth/invalid-email

+   auth/operation-not-allowed（如果在 Firebase 控制台中未启用电子邮件/密码帐户。）

+   auth/weak-password（如果密码不够强大。）

当我们使用`fetchProvidersForEmail(email)`基于电子邮件获取提供程序时，它会返回以下错误代码：

+   auth/invalid-email（如果用户输入了无效的电子邮件）

阅读更多身份验证方法和错误代码的列表，请参考[`firebase.google.com/docs/reference/js/firebase.auth.Auth`](https://firebase.google.com/docs/reference/js/firebase.auth.Auth)。

我们还可以在我们的应用程序中使用以下 firebase 方法来操作用户：

```jsx
var currentUser = firebase.auth().currentUser;
currentUser.updateProfile({
 displayName: “Harmeet Singh”,
 photoURL: “http://www.liferayui.com/g/200/300"
});
currentUser.sendPasswordResetEmail(“harmeetsingh090@gmail.com”); // Sends a temporary password
// Re-authentication is necessary for email, password and delete functions
var credential = firebase.auth.EmailAuthProvider.credential(email, password);
currentUser.reauthenticate(credential);
currentUser.updateEmail(“harmeetsingh090@gmail.com”);
currentUser.updatePassword(“D@#Log123”);
currentUser.delete();
```

成功登录后，我们将被重定向到应用程序仪表板页面，并且我们将能够看到完整的导航，可以添加和查看票务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/svls-webapp-react-frbs/img/5b2ac244-7041-48ac-9302-9098beb44cf0.png)

现在，如果您点击注销按钮，将不会发生任何事情，因为我们还没有创建任何`logout`组件。因此，在注销按钮中，我们需要做的就是简单地调用 firebase 的`signOut()`方法：

```jsx
class Logout extends Component {
 constructor(props) {
 super();
  this.state = {
    redirect: props.authenticated,
    data:''
 }}
 componentWillMount(){
  firebaseApp.auth().signOut().then((user)=>{
    this.setState({
       redirect:true,
       data: null
   })
 })}
 render() {
 if(this.state.redirect === true){
    return <Redirect to = "/" />
 }
 return (
 <div style={{textAlign:"center",position:"absolute",top:"25%",left:"50%"}}>
   <h4>Logging out...</h4>
 </div>
 );
 }}
```

在上述代码中，我们创建了一个组件，并根据组件 props 中传递的值（authenticated）设置了状态；然后，在组件生命周期挂钩方法`componentWillMount()`中，我们调用了`firebaseApp.auth().signout()`方法，该方法登出用户并将其重定向到登录页面，并从状态中删除数据。

# 摘要

在本章中，我们看到了如何借助 Firebase 的身份验证系统使我们的应用程序免受未知用户的侵害。我们还了解了如何在 node 环境中配置 React-Firebase 应用程序，以及如何在 React 中创建登录表单并集成 Firebase 身份验证的登录方法，如 Google、Facebook 和电子邮件/密码。同样，我们也可以在应用程序中集成其他身份验证登录方法。

我们还介绍了根据 Firebase 身份验证错误代码处理身份验证错误的方法，这有助于我们在应用程序中执行操作。为了“持久化”身份验证状态，我们可以使用`firebaseApp.auth().setPersistence('session')`这个方法，它允许我们维护 Firebase 身份验证状态。

在下一章中，我们将探索 Redux 的强大功能，并使用 React、Redux 和 Firebase 创建一个实时的订票应用程序。
