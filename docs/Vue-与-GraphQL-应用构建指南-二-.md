# Vue 与 GraphQL 应用构建指南（二）

> 原文：[`zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD`](https://zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：设置我们的聊天应用程序 - AWS Amplify 环境和 GraphQL

自从 Facebook 在 2012 年推出 GraphQL 以来，它就像飓风一样席卷了网络。大公司开始采用它，而中小型公司也看到了这种基于查询的 API 的潜力。

一开始看起来很奇怪，但随着您开始阅读和体验更多，您就不想再使用 REST API 了。简单性和数据获取能力使前端开发人员的生活变得更轻松，因为他们可以只获取他们想要的内容，而不必受限于只提供单个信息片段的端点。

这是一个漫长的配方的开始，所有的配方都将形成一个完整的聊天应用程序，但您可以在不需要编写整个章节的情况下，在配方中学习有关 GraphQL 和 AWS Amplify 的知识。

在本章中，我们将学习更多关于 AWS Amplify 环境和 GraphQL 的知识，以及如何将其添加到我们的应用程序并使其可用作通信驱动程序。

在本章中，我们将涵盖以下配方：

+   创建您的 AWS Amplify 环境

+   创建您的第一个 GraphQL API

+   将 GraphQL 客户端添加到您的应用程序

+   为您的应用程序创建 AWS Amplify 驱动程序

# 技术要求

在本章中，我们将使用 Node.js、AWS Amplify 和 Quasar Framework。

注意，Windows 用户！您需要安装一个名为`windows-build-tools`的 NPM 包，以便能够安装所需的软件包。要执行此操作，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Quasar Framework，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @quasar/cli
```

要安装 AWS Amplify，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @aws-amplify/cli
```

# 创建您的 AWS Amplify 环境

借助 AWS Amplify 的帮助，我们可以在几分钟内创建一个后端环境，其中包括 NoSQL 数据库、GraphQL 解析器和一个在线存储桶，供我们在开发后部署我们的应用程序。

为了创建 Vue 应用程序，我们将使用 Quasar Framework。这是一个基于 Vue 的框架，提供了开发应用程序所需的所有工具、结构和组件。

在这个配方中，我们将学习如何创建我们的 AWS 账户，在本地配置 AWS Amplify 环境，并使用 Quasar Framework 创建我们的初始项目。

## 准备就绪

这个教程的先决条件是 Node.js 12+。

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

## 如何做...

我们将把这个教程的任务分成四个部分：创建 AWS 账户，配置 AWS Amplify，创建您的 Quasar 项目，以及初始化 AWS Amplify 项目。

### 创建 AWS 账户

在这里，我们将学习如何在 AWS 门户上创建一个账户，以便我们可以访问 AWS 控制台：

1.  转到[`aws.amazon.com`](https://aws.amazon.com)。

1.  在网站上，点击“创建 AWS 账户”按钮。

1.  选择创建一个“专业”账户或一个“个人”账户（因为我们将要探索平台并为自己开发示例应用程序，最好选择“个人”账户）。

1.  现在亚马逊将要求您提供付款信息，以防您的使用超出了免费套餐限制。

1.  现在是确认您的身份的时候 - 您需要提供一个有效的电话号码，亚马逊将用它来发送您需要输入的 PIN 码。

1.  在收到 PIN 码后，您将看到一个成功的屏幕和一个“继续”按钮。

1.  现在您需要为您的账户选择一个计划；您可以选择此教程的“基本计划”选项。

1.  现在您已经完成，可以登录到您的 Amazon AWS 账户控制台。

### 配置 AWS Amplify

让我们配置本地 AWS Amplify 环境，以准备开始开发我们的聊天应用程序：

1.  要设置 AWS Amplify，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> amplify configure
```

1.  浏览器将打开，您需要登录到您的 AWS 控制台账户。

1.  登录后，返回终端并按*Enter*。CLI 将要求您选择您希望应用程序执行的服务器区域。建议在`us-east-1`上运行。

1.  选择区域后，CLI 将要求您为**身份和访问管理**（**IAM**）定义用户名。您可以按*Enter*使用默认值，也可以输入您想要的值（但必须是唯一的）。

1.  现在浏览器将打开以定义您指定的用户的用户详细信息。点击“下一步：权限”按钮转到下一个屏幕。

1.  点击“下一步：标签”按钮转到 AWS 标签屏幕。在这个屏幕上，点击“下一步：审核”按钮来审查您定义的设置。

1.  现在你可以点击“创建用户”按钮来创建用户并转到**访问密钥**屏幕。

1.  最后，在此屏幕上，等待访问密钥 ID 和秘密访问密钥可用。在浏览器中复制访问密钥 ID，粘贴到终端中，然后按“Enter”键。

1.  粘贴访问密钥 ID 后，您必须返回浏览器，点击秘密访问密钥上的“显示”链接，复制该值，粘贴到终端中，然后按“Enter”键。

1.  最后，您需要定义 AWS 配置文件名称（您可以通过按“Enter”键使用默认值）。

您现在已在计算机上设置了 AWS Amplify 环境。

### 创建您的 Quasar 项目

现在我们将创建 Quasar Framework 项目，这将是我们的聊天应用程序：

1.  要创建您的 Quasar Framework 应用程序，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar create chat-app
```

1.  Quasar CLI 将要求输入项目名称；它需要是有效的 npm 软件包名称：

```js
> ? Project name (internal usage for dev) chat-app
```

1.  CLI 将要求输入产品名称（通常用于**渐进式 Web 应用程序**（**PWA**），混合移动应用程序和 Electron 应用程序）：

```js
? Project product name (must start with letter if building mobile 
  apps) Chat App
```

1.  之后，CLI 将要求输入项目描述，这将用于混合应用程序和 PWA：

```js
? Project description A Chat Application
```

1.  现在 CLI 将要求输入项目的作者。通常，这是您的 npm 或 Git 配置的作者：

```js
? Author Heitor Ramon Ribeiro <heitor.ramon@example.com>
```

1.  现在您可以选择 CSS 预处理器。我们将选择`Stylus`（您可以选择最适合您的预处理器）：

```js
? Pick your favorite CSS preprocessor: (can be changed later) 
  Sass with indented syntax (recommended) 
  Sass with SCSS syntax (recommended) 
❯ Stylus 
  None (the others will still be available)
```

1.  Quasar 有两种将组件、指令和插件导入构建系统的方法。您可以通过在`quasar.conf.js`中声明来手动执行，也可以通过自动导入您在代码中使用的组件、指令和插件来自动执行。我们将使用自动导入方法：

```js
? Pick a Quasar components & directives import strategy: (can be changed later) (Use arrow key s)
❯ * Auto-import in-use Quasar components & directives - slightly
    higher compile time; next to minimum bundle size; most 
     convenient 
  * Manually specify what to import - fastest compile time; minimum 
     bundle size; most tedious 
  * Import everything from Quasar - not treeshaking Quasar; biggest 
     bundle size; convenient
```

1.  现在我们必须选择要添加到项目中的默认功能；我们将选择`ESLint`、`Vuex`、`Axios`和`Vue-i18n`：

```js
? Check the features needed for your project: (Press <space> to select, <a> to toggle all, <i> to invert selection) 
❯ ESLint 
 Vuex 
  TypeScript 
 Axios 
 Vue-i18n 
  IE11 support
```

1.  现在您可以选择要在项目中使用的`ESLint`预设；在这种情况下，我们将选择`AirBnB`：

```js
? Pick an ESLint preset: (Use arrow keys) 
  Standard (https://github.com/standard/standard) 
❯ Airbnb (https://github.com/airbnb/javascript) 
  Prettier (https://github.com/prettier/prettier)
```

1.  您需要定义一个 Cordova/Capacitor ID（即使您不构建混合应用程序，也可以使用默认值）：

```js
? Cordova/Capacitor id (disregard if not building mobile apps) 
  org.cordova.quasar.app
```

1.  最后，您可以选择要运行的软件包管理器，并安装您需要运行代码的软件包：

```js
? Should we run `npm install` for you after the project has been 
  created? (recommended) (Use arrow keys) 
  Yes, use Yarn (recommended) 
❯ Yes, use NPM 
  No, I will handle that myself
```

### 初始化 AWS Amplify 项目

要初始化您的 AWS Amplify 项目，请执行以下步骤：

1.  打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify init
```

1.  Amplify CLI 将要求输入项目名称：

```js
? Enter a name for the project: chatapp
```

1.  然后，您需要为您的机器上正在运行的当前项目定义一个环境：

```js
? Enter a name for the environment: dev
```

1.  现在您可以选择您将在项目中使用的默认编辑器：

```js
? Choose your default editor: (Use arrow keys) 
❯ Visual Studio Code
  Atom Editor 
  Sublime Text
  InteliJ IDEA
  Vim (via Terminal, Mac OS only)
  Emac (via Terminal, Mac OS only)
  None
```

1.  您需要决定由 AWS Amplify 托管的项目类型。在我们的情况下，这将是一个 JavaScript 应用程序：

```js
? Choose the type of app that you're building? (recommended) (Use 
   arrow keys) 
  android 
  ios 
❯ javascript
```

1.  对于框架，因为我们将使用 Quasar Framework 作为基础，我们需要从所呈现的框架列表中选择“无”：

```js
? What javascript framework are you using? (recommended) (Use arrow 
  keys) 
  angular 
  ember
  ionic
  react
  react-native
  vue 
❯ none
```

1.  您将需要定义应用程序的源路径；您可以将源目录路径保留为默认值`src`。然后按*Enter*继续：

```js
? Source Directory Path: (src)
```

1.  对于分发目录，由于 Quasar 使用不同类型的路径组织，我们需要将其定义为`dist/spa`：

```js
? Distribution Directory Path: dist/spa
```

1.  AWS Amplify 将在部署之前使用的构建命令，我们将将其定义为`quasar build`：

```js
? Build Command: quasar build
```

1.  对于启动命令，我们需要使用 Quasar 内置的`quasar dev`命令：

```js
? Start Command: quasar dev
```

对于 Windows 用户，由于 Amplify 和 WSL 不兼容，您可能需要将启动命令定义如下：

```js
? Start Command: quasar.cmd dev
```

1.  现在 CLI 会询问我们是否要为此配置使用本地 AWS 配置文件：

```js
? Do you want to use an AWS profile: y
```

1.  我们将选择之前创建的默认配置文件：

```js
? Please choose the profile you want to use: (Use arrow keys) 
❯ default
```

1.  CLI 完成初始化过程后，我们需要向项目添加托管。为此，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify add hosting
```

1.  CLI 会询问您的应用程序的托管过程。选择“使用 Amplify Console 进行托管”，然后按*Enter*继续：

```js
? Select the plugin module to execute 
❯ Hosting with Amplify Console (Managed hosting with custom domains,
  Continuous deployment) 
  Amazon CloudFront and S3 
```

1.  然后 CLI 会询问您部署过程将如何进行；选择“手动部署”，然后按*Enter*继续：

```js
? Choose a type (Use arrow keys)
  Continuous deployment (Git-based deployments) 
❯ Manual deployment 
  Learn more 
```

1.  当您完成所有操作后，要完成此过程，您需要发布它。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify publish
```

1.  您将被问及是否要继续发布，您可以接受。完成所有操作后，浏览器将打开默认的 Quasar Framework 首页：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/bb0ed845-562a-45b8-bb24-0ced0a643194.png)

## 它是如何工作的...

AWS Amplify 是 Web 开发人员的一体化解决方案，提供了一整套工具，从托管应用程序到后端开发。

我们能够快速轻松地构建应用程序并将其上线，完全没有遇到基础设施方面的问题。

在这个步骤中，我们设法创建了我们的 AWS 账户，并为本地开发和网页部署准备好了我们的第一个 AWS Amplify 环境。此外，我们还能够创建了将用作聊天应用程序的 Quasar Framework 项目，并将其部署到 AWS 基础设施中，以准备应用程序的未来发布。

## 另请参阅

+   您可以在[`aws.amazon.com/amplify/`](https://aws.amazon.com/amplify/)找到有关 AWS Amplify 的更多信息。

+   您可以在[`docs.amplify.aws/`](https://docs.amplify.aws/)找到有关 AWS Amplify 框架的更多信息。

+   您可以在[`quasar.dev/`](https://quasar.dev/)找到有关 Quasar Framework 的更多信息。

# 创建您的第一个 GraphQL API

AWS Amplify 提供了在简单步骤和许多附加选项（包括身份验证、部署和环境）的情况下，开箱即用地拥有 GraphQL API 的可能性。这使我们能够仅使用 GraphQL SDL 模式快速开发 API，并且 AWS Amplify 将为连接构建 API、DynamoDB 实例和代理服务器。

在这个步骤中，我们将学习如何使用 AWS Amplify 创建 GraphQL API，并为身份验证添加 AWS Cognito 功能。

## 准备工作

此步骤的先决条件如下：

+   上一个步骤的项目

+   Node.js 12+

所需的 Node.js 全局对象是`@aws-amplify/cli`。

要安装 AWS Amplify，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install -g @aws-amplify/cli
```

在这个步骤中，我们将使用*创建您的 AWS Amplify 环境*步骤中的项目。请先完成该步骤中的说明。

## 如何做...

要启动我们的 GraphQL API，我们将继续使用在*创建您的 AWS Amplify 环境*步骤中创建的项目。

这个步骤将分为两部分：创建 AWS Cognito 和创建 GraphQL API。

### 创建 AWS Cognito 身份验证

为了给我们的 API 和应用程序增加一层安全性，我们将使用 AWS Cognito 服务。这将提供对用户和身份验证的控制作为服务：

1.  要初始化您的 AWS Cognito 配置，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify auth add
```

1.  现在 CLI 会要求您选择用于创建 Cognito 服务的配置类型。这些是预先制定的规则和配置的选择。我们将选择`默认配置`：

```js
Do you want to use default authentication and security configuration: (Use arrow keys) 
❯ Default configuration  Default configuration with Social Provider (Federation)
  Manual configuration
  I want to learn more.
```

1.  之后，您需要选择用户将如何登录；因为我们正在构建一个聊天应用程序，我们将选择`电子邮件`：

```js
Warning: you will not be able to edit these selections.
How do you want users to be able to sign in: (Use arrow keys) 
  Username
❯ Email  Phone Number
  Email and Phone Number
  I want to learn more.
```

1.  对于 AWS Cognito，不需要选择更高级的设置。我们可以通过选择`不，我完成了。`来跳过这一步。

```js
Do you want to configure advanced settings: (Use arrow keys) 
❯ No, I am done.  Yes, I want to make some additional changes.
```

1.  最后，我们需要将这个配置推送到云端。为此，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify auth push
```

1.  您将被问及是否要继续 - 输入`y`，CLI 将发布配置到 AWS Cognito 云：

```js
? Are you sure you want to continue: y 
```

### 创建 GraphQL API

在这部分，我们将把说明分为两部分，首先创建 GraphQL SDL 模式，然后创建 GraphQL API。

#### 创建 GraphQL SDL 模式

要使用 AWS Amplify 创建 GraphQL API，首先需要创建一个 GraphQL SDL 模式。AWS Amplify 将使用该模式生成 API 的数据库和解析器：

1.  在`src`文件夹中创建一个名为`chatApi.graphql`的新文件，并打开它。

1.  创建我们基本的`S3Object`模式类型，这是一个简单的模型，用于管理放置在 AWS S3 存储桶中的文件的存储：

```js
type S3Object {
  bucket: String!
  region: String!
  key: String! } 
```

1.  然后我们将创建我们的`用户类型`。这就像一个带有更多规则附加的数据库模型。这个`类型`将有一个`@auth`规则，只允许所有者，在这种情况下是`用户`，执行`创建`、`更新`和`删除`操作。之后，我们将声明`用户`字段：

```js
type User
@model(subscriptions: null) @auth(rules: [
  { allow: owner, ownerField: "id", queries: null },
  { allow: owner, ownerField: "owner", queries: null },
]) {
  id: ID!
  email: String!
  username: String!
  avatar: S3Object
  name: String
  conversations: [ConversationLink] @connection(name: "UserLinks")
  messages: [Message] @connection(name: "UserMessages", keyField: "authorId")
  createdAt: String
  updatedAt: String }
```

1.  我们的`用户`将与另一个用户进行对话。我们将创建一个`对话类型`，为了保护这个对话，我们将添加一个`@auth`规则，以确保只有这个对话的成员可以看到用户之间交换的消息。在`messages`字段中，我们将创建一个与`消息类型`的`@connection`，并在关联字段中创建一个与`对话链接类型`的`@connection`：

```js
type Conversation
@model(
  mutations: { create: "createConversation" }
  queries: { get: "getConversation" }
  subscriptions: null ) @auth(rules: [{ allow: owner, ownerField: "members" }]) {
  id: ID!
  messages: [Message] @connection(name: "ConversationMessages",
   sortField: "createdAt")
  associated: [ConversationLink] @connection(name: 
   "AssociatedLinks")
  name: String!
  members: [String!]!
  createdAt: String
  updatedAt: String }
```

1.  对于`消息类型`，我们需要添加一个`@auth`装饰器规则，只允许所有者对其进行操作。我们需要创建一个`@connection`装饰器，将`author`字段连接到`用户类型`，并创建一个`@connection`装饰器，将`conversation`字段连接到`对话类型`：

```js
type Message
@model(subscriptions: null, queries: null) @auth(rules: [{ allow: owner, ownerField: "authorId", operations: [create, update, delete]}]) {
  id: ID!
  author: User @connection(name: "UserMessages", keyField: 
   "authorId")
  authorId: String
  content: String!
  conversation: Conversation! @connection(name: "ConversationMessages")
  messageConversationId: ID!
  createdAt: String
  updatedAt: String }
```

1.  现在我们正在使用`type ConversationLink`将对话链接在一起。这个`type`需要`user`字段具有`@connection`装饰器到`User`和`@connection`对话到`type Conversation`：

```js
type ConversationLink
@model(
  mutations: { create: "createConversationLink", update: 
"updateConversationLink" }
  queries: null
  subscriptions: null ) {
  id: ID!
  user: User! @connection(name: "UserLinks")
  conversationLinkUserId: ID
  conversation: Conversation! @connection(name: "AssociatedLinks")
  conversationLinkConversationId: ID!
  createdAt: String
  updatedAt: String }
```

1.  最后，我们需要创建一个`type Subscription`来在 GraphQL API 内部具有事件处理程序。`Subscription`类型会监听并处理特定变化的特定变化，`createConversationLink`和`createMessage`，两者都会在数据库内触发事件：

```js
type Subscription {
  onCreateConversationLink(conversationLinkUserId: ID!): 
   ConversationLink
  @aws_subscribe(mutations: ["createConversationLink"])
  onCreateMessage(messageConversationId: ID!): Message
  @aws_subscribe(mutations: ["createMessage"])
  onCreateUser: User
  @aws_subscribe(mutations: ["createUser"])
  onDeleteUser: User
  @aws_subscribe(mutations: ["deleteUser"])
  onUpdateUser: User
  @aws_subscribe(mutations: ["updateUser"]) }
```

#### 使用 AWS Amplify 创建 GraphQL API

在这里，我们将使用 AWS Amplify API 使用先前创建的 GraphQL 模式来创建我们的 GraphQL API：

1.  要初始化您的 AWS Amplify API 配置，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify add api
```

1.  在这里，CLI 将询问您要创建什么类型的 API。我们将选择`GraphQL`：

```js
? Please select from one of the below mentioned services: (Use arrow 
  keys) 
❯ GraphQL  REST
```

1.  现在 CLI 将要求输入 API 名称（您可以选择）：

```js
? Provide API name: chatapp
```

1.  在这里，我们将选择 API 将使用的身份验证方法。由于我们将使用 AWS Cognito，我们需要选择`Amazon Cognito User Pool`选项：

```js
? Choose the default authorization type for the API: (Use arrow
  keys) 
  API key
❯ Amazon Cognito User Pool  IAM
  OpenID Connect
```

1.  然后 CLI 将询问您是否要在 API 上配置更多设置；我们将选择`No, I am done.`选项：

```js
? Do you want to configure advanced settings for the GraphQL API:
  (Use arrow keys) 
❯ No, I am done.  Yes, I want to make some additional changes.
```

1.  现在我们将被问及是否有注释的 GraphQL 模式；由于我们之前已经编写了一个，我们需要输入`y`：

```js
? Do you have an annotated GraphQL schema?: y
```

1.  在这里，我们需要输入刚刚创建的文件的路径`./src/chatApi.graphql`：

```js
? Provide your schema file path: ./src/chatApi.graphql
```

1.  完成后，我们需要将配置推送到 AWS Amplify。要执行此操作，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify push
```

1.  当询问是否要继续时，输入`y`：

```js
? Are you sure you want to continue?: y
```

1.  CLI 将询问您是否要为新创建的 GraphQL API 生成代码；再次输入`y`：

```js
? Do you want to generate code for your newly created GraphQL API: y
```

1.  在这里，您可以选择 CLI 要使用的语言来创建项目中使用的通信文件。我们将选择`javascript`，但您可以选择最符合您需求的语言：

```js
? Choose the code generation language target: (Use arrow keys) 
❯ javascript
  typescript
  flow
```

1.  CLI 将询问要放置将生成的文件的位置，我们将使用默认值：

```js
? Enter the file name pattern of graphql queries, mutation and
  subscriptions: (src/graphql/***/**.js) 
```

1.  现在 CLI 将询问有关 GraphQL 操作的生成。由于我们正在创建我们的第一个 GraphQL API，我们将选择`y`，因此 CLI 将为我们创建所有文件：

```js
? Do you want to generate/update all possible GraphQL operations - 
  queries, mutations and subscriptions: y 
```

1.  最后，我们可以定义文件中模式的最大深度，我们将使用默认值`2`：

```js
? Enter maximum statement depth [increase from default if your 
  schema is deeply nested]: (2) 
```

1.  当你完成所有的事情后，我们需要将配置发布到 AWS Amplify。要做到这一点，你需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify publish 
```

## 工作原理...

在创建一个带有 AWS Amplify 的 GraphQL API 的过程中，我们需要一个预先构建的模式，用于生成数据库和端点。这个模式是基于 GraphQL SDL 语言的。Amplify 已经在 SDL 中添加了更多的装饰符，这样我们就可以在 API 的开发中拥有更广泛的可能性。

与此同时，我们需要创建一个 AWS Cognito 用户池，用于保存将在应用程序上注册的用户。这是为了在应用程序外部管理和维护身份验证层，并作为一个服务使用，可以提供更多功能，包括双因素身份验证、必填字段和恢复模式。

最后，在一切都完成之后，我们的 API 已经在 AWS Amplify 上发布，并准备好进行开发，具有可以用作开发环境的 URL。

## 另请参阅

+   你可以在[`graphql.org/learn/schema/`](https://graphql.org/learn/schema/)找到更多关于 GraphQL SDL 的信息。

+   你可以在[`docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js`](https://docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js)找到更多关于 AWS Amplify API 的信息。

+   你可以在[`docs.amplify.aws/lib/auth/getting-started/q/platform/js`](https://docs.amplify.aws/lib/auth/getting-started/q/platform/js)找到更多关于 AWS Amplify 身份验证的信息。

# 将 GraphQL 客户端添加到你的应用程序

Apollo Client 目前是 JavaScript 生态系统中最好的 GraphQL 客户端实现。它有一个庞大的社区支持，并得到了大公司的支持。

我们的 AWS Amplify GraphQL API 的实现在后端使用了 Apollo Server，因此 Apollo Client 的使用将是一个完美的匹配。AWS AppSync 也使用他们自己的 Apollo 实现作为客户端，所以我们仍然会使用 Apollo 作为客户端，但不是直接使用。

在这个配方中，我们将学习如何将 GraphQL 客户端添加到我们的应用程序中，以及如何连接到 AWS Amplify GraphQL 服务器来执行查询。

## 准备工作

这个配方的先决条件如下：

+   上一个配方的项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

在这个示例中，我们将使用*创建您的第一个 GraphQL API*示例中的项目。在遵循本示例之前，请按照上一个示例中的步骤进行操作。

## 如何做...

我们将使用 Amplify 客户端将 GraphQL 客户端添加到我们的应用程序中。按照以下步骤创建 GraphQL 驱动程序：

1.  要安装使用 GraphQL 客户端所需的软件包，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install --save graphql aws-amplify graphql-tag aws-appsync
```

1.  在`boot`文件夹中创建一个名为`amplify.js`的新文件，并打开它。

1.  在这个文件中，我们将导入`aws-amplify`包和 AWS Amplify CLI 在配置过程中为我们创建的`aws-exports.js`文件。我们将使用我们拥有的配置来配置 Amplify。为了使 Quasar 引导文件起作用，我们需要导出一个`default`空函数：

```js
import Amplify from 'aws-amplify';   import AwsExports from '../aws-exports';   Amplify.configure(AwsExports);   export default () => {}; 
```

1.  在`root`文件夹中的`quasar.conf.js`文件中，我们需要向`webpack`捆绑器添加新规则。要做到这一点，找到`extendWebpack`函数。在函数的第一行之后，创建两个新规则给捆绑器，第一个规则将添加`graphql-loader`webpack 加载程序，第二个规则将允许捆绑器理解`.mjs`文件：

```js
// The rest of the quasar.conf.js... extendWebpack (cfg) {
  //New rules that need to be added
 cfg.module.rules.push({
  test: /\.(graphql|gql)$/,
  exclude: /node_modules/,
  loader: 'graphql-tag/loader',
  });    cfg.module.rules.push({
  test: /\.mjs$/,
  include: /node_modules/,
  type: 'javascript/auto',
  });
 // Maintain these rules  cfg.module.rules.push({
  enforce: 'pre',
  test: /\.(js|vue)$/,
  loader: 'eslint-loader',
  exclude: /node_modules/,
  options: {
  formatter: 
       require('eslint').CLIEngine.getFormatter('stylish'),
  },
  });    cfg.resolve.alias = {
  ...cfg.resolve.alias,
  driver: path.resolve(__dirname, './src/driver'),
  }; }, // The rest of the quasar.conf.js...
```

1.  现在，在`src/driver`文件夹中创建一个名为`graphql.js`的新文件，并打开它。

1.  在这个文件中，我们需要从`aws-appsync`包中导入`AWSAppSyncClient`，从`aws-amplify`包中导入`Auth`，并从`src`文件夹中的`aws-exports.js`文件中导入`AwsExports`。然后，我们需要使用`aws-exports`的配置实例化`AWSAppSyncClient`，并导出客户端的这个实例化：

```js
import AWSAppSyncClient from 'aws-appsync'; import { Auth } from 'aws-amplify'; import AwsExports from '../aws-exports';   export default new AWSAppSyncClient({
  url: AwsExports.aws_appsync_graphqlEndpoint,
  region: AwsExports.aws_appsync_region,
  auth: {
  type: AwsExports.aws_appsync_authenticationType,
  jwtToken: async () => (await 
      Auth.currentSession()).idToken.jwtToken,
  }, }); 
```

1.  在`quasar.conf.js`文件中的`root`文件夹中，我们需要将新创建的`amplify.js`文件添加到引导序列中，该文件位于`boot`文件夹中。要做到这一点，找到`boot`数组，并在末尾添加文件在`boot`文件夹中的路径作为字符串，不包括扩展名。在我们的情况下，这将是`'amplify'`：

```js
// The rest of the quasar.conf.js... 
boot: [   'axios',
  'amplify' ], // The rest of the quasar.conf.js...  
```

## 它是如何工作的...

我们在全局范围内将`aws-amplify`包添加到我们的应用程序中，并通过新的`graphql.js`文件中的导出条目使其可用于使用。这使得在应用程序中可以使用`AWSAmplifyAppSync`。

使用 Quasar Framework 的引导过程，我们能够在 Vue 应用程序开始在屏幕上呈现之前实例化 Amplify。

## 另请参阅

+   您可以在[`docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js`](https://docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js)找到有关 AWS Amplify AppSync 的更多信息。

+   您可以在[`quasar.dev/quasar-cli/developing-ssr/writing-universal-code#Boot-Files`](https://quasar.dev/quasar-cli/developing-ssr/writing-universal-code#Boot-Files)找到有关 Quasar Framework 引导文件的更多信息。

# 为您的应用程序创建 AWS Amplify 驱动程序

为了与 AWS Amplify 服务进行通信，我们需要使用他们的 SDK。这个过程是重复的，可以合并到我们将要使用的每个 Amplify 服务的驱动程序中。

在这个示例中，我们将学习如何创建通信驱动程序，以及如何使用 AWS Amplify 进行操作。

## 准备工作

这个示例的先决条件如下：

+   上一个示例的项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   @aws-amplify/cli

+   `@quasar/cli`

在这个示例中，我们将使用*将 GraphQL 客户端添加到您的应用程序*示例中的项目。请先完成该示例中的说明。

## 如何做...

在这个示例中，我们将其分为三个部分：第一部分将用于 AWS 存储驱动程序，第二部分将用于 Amplify Auth 驱动程序，最后，我们将看到 Amplify AppSync 实例的创建。

### 创建 AWS Amplify 存储驱动程序

要创建 AWS Amplify 存储驱动程序，我们首先需要创建 AWS Amplify 存储基础设施，并在我们的环境中设置好，之后我们需要创建 AWS Amplify 存储 SDK 与我们的应用程序之间的通信驱动程序。

#### 添加 AWS Amplify 存储

在这部分，我们将向我们的 Amplify 服务列表中添加 AWS S3 功能。这是必需的，这样我们就可以在 AWS S3 云基础设施上保存文件：

1.  首先，我们需要向项目添加 AWS 存储。为此，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹并执行以下命令：

```js
> amplify add storage
```

1.  现在我们需要选择将上传什么内容。我们需要选择`内容（图片、音频、视频等）`：

```js
? Please select from one of the below mentioned services: (Use arrow 
  keys) 
❯ Content (Images, audio, video, etc.)  NoSQL Database
```

1.  我们需要为资源添加一个名称。我们将其称为`bucket`：

```js
? Please provide a friendly name for your resource that will be used 
  to label this category in the project: bucket
```

1.  现在我们需要提供一个 AWS S3 存储桶名称。我们将其称为`chatappbucket`：

```js
? Please provide bucket name: chatappbucket 
```

1.  然后我们需要选择谁可以操作存储桶文件。由于应用程序将仅基于授权，我们需要选择`仅授权用户`：

```js
? Who should have access: (Use arrow keys) 
❯ Auth users only  Auth and guest users
```

1.  现在您需要选择用户在存储桶中的访问级别：

```js
? What kind of access do you want for Authenticated users? 
  create/update
  read
❯ delete
```

1.  当被问及创建自定义 Lambda 触发器时，选择`n`：

```js
? Do you want to add a Lambda Trigger for you S3 Bucket: n
```

1.  最后，我们需要将更改推送到云端。为此，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify push
```

1.  当您完成所有操作后，我们需要将配置发布到 AWS Amplify。为此，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify publish
```

#### 创建 Amplify Storage 驱动程序

在这部分，我们将创建与 Amplify Storage 通信的驱动程序。该驱动程序将处理我们应用程序中的文件上传：

1.  在`src/driver`文件夹中创建一个名为`bucket.js`的新文件并打开它。

1.  从`aws-amplify`包中导入`Storage`类，从`quasar`中导入`uid`函数，以及`AwsExports`：

```js
import { Storage } from 'aws-amplify'; import { uid } from 'quasar'; import AwsExports from '../aws-exports'; 
```

1.  创建一个名为`uploadFile`的异步函数，它接收三个参数：`file`，`name`和`type`。`name`参数的默认值为`uid()`，`type`参数的默认值为`'image/png'`。在这个函数中，我们将调用`Storage.put`函数，传递`name`和`file`作为参数，作为第三个参数，我们将传递一个 JavaScript 对象，其中`contentType`属性定义为接收到的`type`，并且`accept`属性定义为`'**/**'`。上传完成后，我们将返回一个具有`bucket`，`region`和`uploadedFile`属性的 JavaScript 对象：

```js
export async function uploadFile(file, name = uid(), type = 'image/png') {
  try {
  const uploadedFile = await Storage.put(name, file, {
  contentType: type,
  accept: '*/*',
  });    return {
  ...uploadedFile,
  bucket: AwsConfig.aws_user_files_s3_bucket,
  region: AwsConfig.aws_user_files_s3_bucket_region,
  };
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`getFile`的异步函数，它接收`name`参数，默认值为空字符串。在函数内部，我们将返回`Storage.get`，传递`name`参数和设置为`public`级别的选项：

```js
export async function getFile(name = '') {
  try {
  return await Storage.get(name, { level: 'public' });
  } catch (err) {
  return Promise.reject(err);
  } } 
```

1.  最后，导出一个默认的 JavaScript 对象，并将创建的函数`uploadFile`和`getFile`作为属性添加进去：

```js
export default {
  uploadFile,
  getFile, };  
```

### 创建 Amplify Auth 驱动程序

现在我们将创建认证驱动程序。该驱动程序负责处理应用程序中的所有认证请求并获取用户信息：

1.  在`src/driver`文件夹中创建一个名为`auth.js`的新文件并打开它。

1.  在新创建的文件中，从`aws-amplify`包中导入`Auth`类：

```js
import { Auth } from 'aws-amplify';
```

1.  创建一个名为`signIn`的新异步函数。它将接收`email`和`password`作为参数，并且该函数将返回`Auth.signIn`函数，传递`email`和`password`作为参数：

```js
export async function signIn(email = '', password = '') {
  try {
  return Auth.signIn({
  username: email,
  password,
  });
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`signUp`的新异步函数，该函数将接收`email`和`password`作为参数。该函数将返回`Auth.signUp`函数，传递一个带有这些属性的 JavaScript 对象作为参数：`username`、`password`、`attributes`和`validationData`。

`username`属性将是作为参数接收的`email`值。

`password`属性将是作为参数接收的`password`值。

`attributes`属性将是一个带有`email`属性的 JavaScript 对象，该属性将作为参数接收：

```js
export async function signUp(email = '', password = '') {
  try {
  return Auth.signUp({
  username: email,
  password: `${password}`,
  attributes: {
 email,
  },
  validationData: [],
  });
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`validateUser`的新异步函数，该函数将接收`username`和`code`作为参数。该函数等待`Auth.confirmSignUp`函数的响应，将`username`和`code`作为参数传递给该函数，并在完成时返回`true`：

```js
export async function validateUser(username = '', code = '') {
  try {
  await Auth.confirmSignUp(username, `${code}`);    return Promise.resolve(true);
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`resendValidationCode`的新异步函数，该函数将接收`username`作为参数。该函数返回`Auth.resendSignUp`函数，将`username`作为参数：

```js
export async function resendValidationCode(username = '') {
  try {
  return Auth.resendSignUp(username);
  } catch (err) {
  return Promise.reject(err);
  } } 
```

1.  创建一个名为`signOut`的新异步函数，该函数返回`Auth.signOut`函数：

```js
export async function signOut() {
  try {
  return Auth.signOut();
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`changePassword`的新异步函数，该函数将接收`oldPassword`和`newPassword`作为参数。该函数等待获取当前经过身份验证的用户，并返回`Auth.changePassword`函数，将获取的`user`、`oldPassword`和`newPassword`作为参数：

```js
export async function changePassword(oldPassword = '', newPassword = '') {
  try {
  const user = await Auth.currentAuthenticatedUser();
  return Auth.changePassword(user, `${oldPassword}`, `${newPassword}`);
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`getCurrentAuthUser`的新异步函数；该函数将获取当前经过身份验证的用户，并返回一个带有`id`、`email`和`username`属性的 JavaScript 对象：

```js
export async function getCurrentAuthUser() {
  try {
  const user = await Auth.currentAuthenticatedUser();    return Promise.resolve({
  id: user.username,
  email: user.signInUserSession.idToken.payload.email,
  username: user.username,
  });
  } catch (err) {
  return Promise.reject(err);
  } } 
```

### 创建 Amplify AppSync 实例

在经过身份验证的情况下与 AWS Amplify API 通信，我们需要创建一个新的 AWS Amplify AppSync API 实例，其中包含用户身份验证信息：

1.  在`src/driver`文件夹中创建一个名为`appsync.js`的新文件并打开它。

1.  在新创建的文件中，从`aws-amplify`包中导入`Auth`和`API`，从`@aws-amplify/api`包中导入`GRAPHQL_AUTH_MODE`枚举，以及 AWS 配置：

```js
import { Auth, API } from 'aws-amplify'; import { GRAPHQL_AUTH_MODE } from '@aws-amplify/api'; import AwsExports from '../aws-exports';
```

1.  通过执行`API.configure`函数从`aws-amplify`包中配置 API，传递一个 JavaScript 对象作为参数，其中包含`url`、`region`和`auth`的属性。

在`url`属性中，传递 GraphQL 端点 URL 的配置。

在`region`属性中，传递当前正在使用的 AWS 区域的配置。

在`auth`属性中，我们需要传递一个具有两个属性`type`和`jwtToken`的 JavaScript 对象。

我们需要将`type`属性设置为`GRAPHQL_AUTH_MODE.AMAZON_COGNITO_USER_POOLS`。

在`jwtToken`中，我们将传递一个异步函数，该函数将返回当前登录用户的令牌：

```js
API.configure({
  url: awsconfig.aws_appsync_graphqlEndpoint,
  region: awsconfig.aws_appsync_region,
  auth: {
  type: GRAPHQL_AUTH_MODE.AMAZON_COGNITO_USER_POOLS,
  jwtToken: async () => (await Auth.currentSession()).getIdToken().getJwtToken(),
  }, });
```

1.  最后，我们将`API`导出为名为`AuthAPI`的常量：

```js
export const AuthAPI = API;
```

## 工作原理...

在这个示例中，我们学习了如何将应用程序的责任分离为可以在多个领域重复使用而无需重写整个代码的驱动程序。通过这个过程，我们能够创建一个用于 Amplify 存储的驱动程序，可以异步发送文件，并且这些文件被保存在 AWS S3 服务器上的存储桶中。

在我们对 Auth 驱动程序的工作中，我们能够创建一个可以管理 Amplify 身份验证 SDK 并在需要时提供信息并封装特殊功能以使在我们的应用程序中执行任务更容易的驱动程序。

最后，在 Amplify AppSync API 中，我们成功实例化了 API 连接器，并使用了所有需要的身份验证标头，以便应用程序可以在没有任何问题的情况下执行，并且用户可以在请求时访问所有信息。

## 另请参阅

+   在[`docs.amplify.aws/lib/storage/getting-started/q/platform/js`](https://docs.amplify.aws/lib/storage/getting-started/q/platform/js)上查找有关 AWS Amplify Storage 的更多信息。

+   在[`docs.amplify.aws/lib/auth/getting-started/q/platform/js`](https://docs.amplify.aws/lib/auth/getting-started/q/platform/js)上查找有关 AWS Amplify Auth 的更多信息。

+   在[`docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js`](https://docs.amplify.aws/lib/graphqlapi/getting-started/q/platform/js)上查找有关 AWS Amplify AppSync 的更多信息。


# 第四章：创建自定义应用程序组件和布局

要开始我们应用程序的开发，我们需要创建整个应用程序将使用的自定义组件和输入。这些组件将采用无状态的方法创建。

我们将开发`UsernameInput`组件，`PasswordInput`组件，`EmailInput`组件和`AvatarInput`组件。我们还将开发应用程序页面和聊天布局的基本布局，它将包装聊天页面。

在本章中，我们将涵盖以下示例：

+   为应用程序创建自定义输入

+   创建应用程序布局

# 技术要求

在本章中，我们将使用**Node.js**和**Quasar Framework**。

注意，Windows 用户！您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装所需的包。要做到这一点，以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装 Quasar Framework，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @quasar/cli 
```

# 为应用程序创建自定义输入

创建应用程序需要创建大量的表单。所有这些表单都需要输入，这些输入很可能在应用程序中重复出现。

在这个示例中，我们将创建自定义输入表单，我们将在几乎每个表单中使用它们。

创建自定义输入表单的过程有助于开发人员节省调试时间，代码的可重用性和未来的改进。

## 准备工作

这个示例的先决条件如下：

+   最后的示例项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的自定义组件，我们将继续使用在第三章*设置我们的聊天应用程序 - AWS Amplify 环境和 GraphQL*中创建的项目。

## 如何做...

为了更好地重用代码，我们将创建单独的组件来处理应用程序上的自定义表单。在这种情况下，我们将创建六个组件：

+   `UsernameInput`

+   `PasswordInput`

+   `NameInput`

+   `EmailInput`

+   `AvatarInput`

+   `AvatarDisplay`

所以，让我们开始吧。

### 创建 UsernameInput 组件

`UsernameInput`将负责处理用户名的检查和验证，这样我们就不需要在每个需要使用它的页面上重新编写所有规则。

#### 单文件组件`<script>`部分

在这里，我们将创建`UsernameInput`组件的`<script>`部分：

1.  在`src/components`文件夹中创建一个名为`UsernameInput.vue`的新文件，并打开它。

1.  创建一个带有`name`和`props`属性的默认导出的 JavaScript 对象：

```js
export default {
  name: '',
  props: {}, };
```

1.  对于`name`属性，将其定义为`"UsernameInput"`：

```js
name: 'UsernameInput',
```

1.  对于`props`属性，将其定义为一个 JavaScript 对象，并添加一个名为`value`的新属性，它也将是一个具有`type`，`default`和`required`属性的 JavaScript 对象。`type`属性需要定义为`String`，`default`为`''`，`required`为`false`： 

```js
props: {
  value: {
    type: String,
    default: '',
    required: false,
  },
},
```

#### 单文件组件`<template>`部分

在这里，我们将创建`UsernameInput`组件的`<template>`部分：

1.  在`<template>`部分，创建一个`QInput`组件。创建两个动态属性，`value`和`rules`。现在，`value`将绑定到`value`属性，`rules`属性将接收一个数组。数组的第一项是一个函数，用于验证输入，第二项是出现错误时的消息。

1.  将`outlined`和`lazy-rules`属性设置为`true`，并将`label`属性定义为`"Your Username"`。

1.  最后，通过创建一个`v-on`指令，使用`$listeners` Vue API 作为值来为事件创建事件侦听器。

完成所有步骤后，您的最终代码应该像这样：

```js
<template>
  <q-input
  :value="value"
  :rules="[ val => (val && val.length > 5 || 'Please type a valid 
      Username')]"
  outlined
  label="Your Username"
  lazy-rules
  v-on="$listeners"
  /> </template>
```

这是您的组件呈现出来的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/e6398356-c190-45f1-96fa-26d3c7d632a6.png)

### 创建一个 PasswordInput 组件

`PasswordInput`将是一个组件，具有特殊逻辑，通过单击按钮切换密码的可见性。我们将在这个组件中包装这个逻辑，这样每次使用这个组件时就不需要重新编写它。

#### 单文件组件`<script>`部分

在这部分，我们将创建`PasswordInput`组件的`<script>`部分：

1.  在`components`文件夹中创建一个名为`PasswordInput.vue`的新文件，并打开它。

1.  创建一个默认导出的 JavaScript 对象，具有三个属性，`name`，`props`和`data`：

```js
export default {
  name: '',
  props: {},
  data: () => (), };
```

1.  对于`name`属性，将值定义为`"PasswordInput"`：

```js
name: 'PasswordInput',
```

1.  对于`props`属性，添加两个属性，`value`和`label`，都是 JavaScript 对象。每个对象内部应该有三个属性：`type`，`default`和`required`。将`value.type`设置为`String`，`value.default`设置为`''`，`value.required`设置为`false`。然后，将`label.type`设置为`String`，`label.default`设置为`'Your Password'`，`label.required`设置为`false`：

```js
props: {
  value: {
  type: String,
  default: '',
  required: false,
  },
  label: {
  type: String,
  default: 'Your password',
  required: false,
  }, }, 
```

1.  最后，在`data`属性中，添加一个 JavaScript 对象作为返回值，其中`isPwd`值设置为`true`：

```js
data: () => ({
  isPwd: true, }),
```

#### 单文件组件<template>部分

现在我们将创建`PasswordInput`的`<template>`部分。按照以下说明来实现正确的输入组件：

1.  在`<template>`部分，创建一个`QInput`组件，并将`value`，`label`和`rules`属性添加为变量。`value`将绑定到`value`属性，`label`将绑定到`label`属性，`rules`将接收一个函数数组，用于执行对表单输入的基本验证。

1.  对于`type`属性，将其定义为一个变量，并将其设置为对`isPwd`的三元验证，在`"password"`和`"text"`之间切换。

1.  将`outlined`和`lazy-rules`属性设置为`true`。

1.  创建一个`hint`变量属性，并将其定义为三元运算符，它将检查当前值的长度是否匹配最小值大小；否则，它将向用户显示一条消息。

1.  然后，通过创建一个`v-on`指令并使用`$listeners`Vue API 作为值来为事件创建事件侦听器。

1.  在`QInput`模板内部，我们将添加一个子组件，该组件将占据一个命名插槽`v-slot:append`，该插槽将容纳一个`QIcon`组件。

1.  对于`QIcon`组件，定义`name`属性以对`isPwd`变量进行响应，因此当`isPwd`设置为`true`时，它将是`'visibility_off'`，或者当`isPwd`设置为`false`时，它将是`'visibility'`。将`class`属性定义为`"cursor-pointer"`，以便鼠标具有实际鼠标的外观和`"hover hand icon"`，并在`@click`事件侦听器上，我们将设置`isPwd`为当前`isPwd`的相反值。

完成所有步骤后，您的最终代码应该像这样：

```js
<template>
  <q-input
  :value="value"
  :type="isPwd ? 'password' : 'text'"
  :rules="[ val => val.length >= 8 || 'Your password need to have 8
             or more characters', val => val !== null && val !== '' || 
              'Please type your password']"
  :hint=" value.length < 8 ? 'Your password has a minimum of 8 
             characters' : ''"
  :label="label"
  outlined
  lazy-rules
  v-on="$listeners"
  >
  <template v-slot:append>
    <q-icon
      :name="isPwd ? 'visibility_off' : 'visibility'"
      class="cursor-pointer"
      @click="isPwd = !isPwd"
    />
  </template>
  </q-input> </template>
```

这是您的组件呈现的方式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/c6f0729d-0592-4f9b-b117-2ebad5254985.png)

### 创建 NameInput 组件

在我们创建的所有组件中，`NameInput`组件是最简单的，几乎没有改变`QInput`组件的行为，只是添加了验证规则和一些个性化。

#### 单文件组件<script>部分

在这部分，我们将创建`NameInput`组件的`<script>`部分：

1.  创建一个默认导出的 JavaScript 对象，有两个属性：`name`和`props`：

```js
export default {
  name: '',
  props: {},  }; 
```

1.  在`name`属性中，将值定义为`'NameInput'`：

```js
name: 'NameInput',
```

1.  在`props`属性中，添加一个属性`value`，作为一个 JavaScript 对象，里面有三个属性：`type`，`default`和`required`。将`value.type`设置为`String`，`value.default`设置为`**''**`，`value.required`设置为`false`：

```js
props: {
  value: {
  type: String,
  default: '',
  required: false,
  },  },
```

#### 单文件组件<template>部分

在这部分，我们将创建`NameInput`组件的`<template>`部分：

1.  在`<template>`部分，创建一个`QInput`组件，并添加`value`和`rules`属性作为变量。`value`将绑定到`value`属性，`rules`将接收一个函数数组，用于检查表单输入的基本验证。

1.  将`outlined`和`lazy-rules`属性设置为`true`，并将`label`属性定义为`"Your Name"`。

1.  最后，通过创建一个`v-on`指令并将`"$listeners"` Vue API 作为值来为事件创建事件监听器。

完成所有步骤后，你的最终代码应该像这样：

```js
<template>
  <q-input
  :value="value"
  :rules="[ val => (val && val.length > 0
    || 'Please type a valid Name')]"
  outlined
  label="Your Name"
  lazy-rules
  v-on="$listeners"
  /> </template>
```

这是你的组件渲染结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/43ecd588-f672-498b-9372-34fc3df16edf.png)

### 创建 EmailInput 组件

在`EmailInput`组件中，我们需要特别注意规则验证的处理，因为我们需要检查正在输入的电子邮件是否是有效的电子邮件地址。

#### 单文件组件<script>部分

在这部分，我们将创建`EmailInput`组件的`<script>`部分：

1.  创建一个默认导出的 JavaScript 对象，有三个属性：`name`，`props`和`methods`：

```js
export default {
  name: '',
  props: {},
 methods: {}, }; 
```

1.  在`name`属性中，将值定义为`'EmailInput'`：

```js
name: 'EmailInput',
```

1.  在`props`属性中，添加一个属性`value`，作为一个 JavaScript 对象，里面有三个属性：`type`，`default`和`required`。将`value.type`设置为`String`，`value.default`设置为`**'**`，`value.required`设置为`false`：

```js
props: {
  value: {
  type: String,
  default: '',
  required: false,
  },  },
```

1.  在`methods`属性中，我们需要添加一个名为`validateEmail`的新方法，该方法接收一个名为`email`的参数。此方法将通过正则表达式测试接收到的参数，以检查它是否是有效的表达式，并返回结果：

```js
methods: {
  validateEmail(email) {
  const regex = /^(([^\s"(),.:;<>@[\\\]]+(\.[^\s"(),.:;
     <>@[\\\]]+)*)|(".+"))@((\[(?:\d{1,3}\.){3}\d{1,3}])|(([\dA-Za-
 z\-]+\.)+[A-Za-z]{2,}))$/;
  return regex.test(email);
  }, }, 
```

#### 单文件组件<template>部分

在这里，我们将创建`EmailInput`组件的`<template>`部分：

1.  在`<template>`部分，创建一个`QInput`组件，并将`value`和`rules`属性作为变量添加。`value`将绑定到`value`属性，`rules`将接收一个函数数组，用于执行基本验证表单输入的检查。

1.  将`outlined`和`lazy-rules`属性添加为`true`，将`label`属性定义为`"Your E-Mail"`，将`type`属性定义为`"email"`*.*

1.  最后，通过创建一个`v-on`指令并将`"$listeners"`作为值，为事件创建事件侦听器。

完成所有步骤后，您的最终代码应该像这样：

```js
<template>
  <q-input
  :value="value"
  :rules="[ val => (val && val.length > 0 && validateEmail(val)
    || 'Please type a valid E-mail')]"
  outlined
  type="email"
  label="Your E-mail"
  lazy-rules
  v-on="$listeners"
  /> </template>
```

这是您的组件呈现：

！[](assets/20533ea7-b331-4aac-b6d5-2b4f2d0d8743.png)

### 创建 AvatarInput 组件

对于`AvatarInput`组件，我们需要添加使用`AWS-Amplify Storage`API 驱动程序的逻辑。通过这样做，我们可以直接通过组件上传文件，并使逻辑和组件在整个应用程序中更具可重用性。

#### 单文件组件<script>部分

在这部分，我们将创建`AvatarInput`组件的`<script>`部分：

1.  从`quasar`包中导入`uid`和从`'src/driver/bucket'`中导入`uploadFile`：

```js
import { uid } from 'quasar';
import { uploadFile } from 'src/driver/bucket';
```

1.  创建一个默认导出的 JavaScript 对象，具有四个属性，`name`，`props`，`data`和`methods`：

```js
export default {
  name: '',
  props: {},
  data: () => ({})
 methods: {}, };
```

1.  在`name`属性中，将值定义为`"AvatarInput"`：

```js
name: 'AvatarInput',
```

1.  在`props`属性中，添加一个属性`value`，作为 JavaScript 对象，内部有三个属性 - `type`，`default`和`required`。将`value.type`设置为`Object`，将`value.default`设置为返回 JavaScript 对象的工厂函数，将`value.required`设置为`false`：

```js
props: {
  value: {
  type: Object,
  required: false,
  default: () => ({}),
  }, }, 
```

1.  在`data`属性中，我们需要添加六个新属性：`file`，`type`，`name`，`s3file`，`photoUrl`和`canUpload`：

+   `file`属性将是一个数组。

+   `type`，`name`和`photoUrl`将是字符串。

+   `canUpload`属性将是一个布尔值，定义为`false`。

+   `s3file`将是一个具有三个属性的 JavaScript 对象，`key`，`bucket`和`region`，它们都是字符串：

```js
data: () => ({
  file: [],
  type: '',
  name: '',
  s3file: {
  key: '',
  bucket: '',
  region: '',
  },
  photoUrl: '',
  canUpload: false, }),
```

1.  在`methods`属性上，我们需要添加一个名为`uploadFile`的新方法。这个方法将检查是否可以开始上传过程，然后调用`uploadFile`函数，传递`this.file`、`this.name`和`this.type`作为参数。在我们收到上传函数的响应后，我们将使用结果来定义`this.s3File`和`$emit`以及事件`'input'`。最后，我们将`this.canUpload`定义为`false`：

```js
async uploadFile() {
  try {
  if (this.canUpload) {
  const file = await uploadFile(this.file, this.name, 
         this.type);
  this.s3file = file;
  this.$emit('input', file);
  this.canUpload = false;
 } } catch (err) {
  console.error(err);
 } }, 
```

1.  最后，创建一个名为`getFile`的方法，它接收`$event`作为参数。在函数中，我们将把`this.type`定义为`$event.type`，将`this.name`定义为`uid`生成函数和文件名的连接。然后，我们将为`FileReader`实例创建一个监听器，它将把`that.photoURL`设置为读取的结果，并将`that.canUpload`设置为`true`：

```js
getFile($event) {
  this.type = $event.type;
  this.name = `${uid()}-${$event.name}`;
  const that = this;
  const reader = new FileReader();
  reader.onload = ({ target }) => {
  that.photoUrl = target.result;
  that.canUpload = true;
  };
  reader.readAsDataURL(this.file); },
```

#### 单文件组件<template>部分

现在是创建`AvatarInput`组件的`<template>`部分的时候了：

1.  创建一个`QFile`组件，将`v-model`指令绑定到`file`数据属性。将`outlined`和`bottom-slots`属性定义为`true`，并将`label`属性设置为`"Your Avatar"`。对于`class`属性，将其设置为`"q-pr-md"`，最后将`@input`事件监听器设置为目标`getFile`方法：

```js
<q-file
  v-model="file"
  outlined
 bottom-slots label="Your Avatar"
  class="q-pr-md"
  @input="getFile" >
</q-file>
```

1.  在`QFile`组件内部，我们将添加一个直接子组件，它将放置在一个命名为`v-slot:before`的插槽中，并且只有在数据属性中存在任何`photoUrl`时才会显示。在这个插槽中，我们将添加一个`QAvatar`组件，其子组件是一个`HTML img`标签，其中`src`属性绑定到`photoUrl`数据属性：

```js
<template
  v-if="photoUrl"
  v-slot:before >
 <q-avatar>
 <img :src="photoUrl">
 </q-avatar> </template>
```

1.  在我们创建的插槽之后，我们需要创建另一个插槽，现在放置在名为`v-slot:after`的插槽下面，里面有一个`QBtn`组件。`QBtn`将具有以下属性：`round`、`dense`、`flat`、`icon`定义为`"cloud_upload"`，并且`@click`事件监听器绑定到`uploadFile`方法：

```js
<template v-slot:after>
 <q-btn
  round
 dense flat icon="cloud_upload"
  @click="uploadFile"
  /> </template>
```

这是您的组件渲染结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/a28e22e8-4f2a-4a9e-aef7-9680c4f9e122.png)

### 创建 avatar mixin

在这里，我们将创建一个简单的 mixin，它将用于在新的对话组件和联系人页面中显示用户头像，或者如果没有定义头像，则显示用户名的首字母：

1.  在`src`文件夹下创建一个名为`mixins`的新文件夹，然后创建一个名为`getAvatar.js`的文件，并打开它。

1.  从`driver/bucket`文件中导入`getFile`函数。

1.  导出一个带有`methods`属性的`default` JavaScript 对象。在`methods`属性内部，创建一个名为`getAvatar`的新函数。此函数将接收两个参数，`object`和`name`。对于此函数，我们将检查对象是否为`null`，以及是否有一个名字来显示初始字母。如果 JavaScript 对象中有属性，我们将返回`getFile`函数的结果，将`key`属性作为参数传递：

```js
import { uploadFile } from 'src/driver/bucket';   export default {
  methods: {
  async getAvatar(object, name) {
  const baseUrl = 'http://placehold.jp/350/9c27b0/FFFFFF/600x600.png?text=';    if (object === null && !name) return `${baseUrl}%20`;    if (!object && name) return `${baseUrl}${name.split('').shift()}`;    return getFile(object.key);
 }, }, }; 
```

### 创建 AvatarDisplay 组件

`AvatarDisplay`将负责处理用户名的检查和验证，因此我们不需要在每个需要使用它的页面上重新编写所有规则。

#### 单文件组件<script>部分

在这里，我们将创建`AvatarDisplay`组件的`<script>`部分：

1.  在`components`文件夹中创建一个名为`AvatarDisplay.vue`的新文件，并打开它。

1.  创建一个带有以下属性的`export default` JavaScript 对象：`name`，`props`，`mixins`，`beforeMount`，`data`，`watch`，`computed`和`methods`：

```js
import { QImg } from 'quasar'; import getAvatar from 'src/mixins/getAvatar';   export default {
  name: '',
  props: {},
  mixins: [],
  async beforeMount() {},
  data: () => ({}),
  watch: {},
  computed: {},
  methods: {}, };
```

1.  对于`name`属性，将其定义为`"AvatarDisplay"`：

```js
name: 'UsernameInput',
```

1.  对于`props`属性，将其定义为 JavaScript 对象，并添加三个新属性，分别称为`avatarObject`，`name`和`tag`。`avatarObject`属性将是一个具有`type`，`default`和`required`属性的 JavaScript 对象。`name`和`tag`属性需要定义为`String`，`default`为`''`，`required`为`false`。对于`tag`属性，我们将将默认属性设置为`'q-img'`：

```js
props: {
  avatarObject: {
  type: Object,
  required: false,
  default: () => ({}),
  },
  name: {
  type: String,
  required: false,
  default: '',
  },
  tag: {
  type: String,
  required: false,
  default: 'q-img',
  }, },
```

1.  对于`mixins`属性，我们将在数组中添加导入的`getAvatar` mixin：

```js
mixins: [getAvatar],
```

1.  现在，在`data`中返回 JavaScript 对象，我们将创建一个名为`src`的属性，其默认值为`''`：

```js
data: () => ({
  src: '', }),
```

1.  然后对于`computed`属性，创建一个名为 components 的新属性，返回一个三元运算符，检查`tag`属性是否等于`'q-img'`，并返回 Quasar 中导入的`QImg`组件；如果不是，则返回`'img'`标签：

```js
computed: {
  componentIs() {
  return this.tag === 'q-img' ? QImg : 'img';
  }, },
```

1.  在`methods`属性中，创建一个名为`updateSrc`的新方法。在这个方法中，我们将`src`定义为`getAvatar`方法的结果。我们将函数的参数传递给`avatarObject`和`name`属性：

```js
methods: {
  async updateSrc() {
  this.src = await this.getAvatar(this.avatarObject, this.name);
  }, },
```

1.  在`beforeMount`生命周期钩子中，我们将调用`updateSrc`方法：

```js
async beforeMount() {
  await this.updateSrc(); },
```

1.  最后，对于`watch`属性，创建两个属性，`avatarObject`和`name`。对于`avatarObject`属性，将其定义为一个具有两个属性`handler`和`deep`的 Javascript 对象。在`deep`属性中，将其定义为`true`，在`handler`属性上，将其定义为调用`updateSrc`方法的函数。然后在`name`属性上，创建一个`handler`属性，定义为调用`updateSrc`方法的函数：

```js
watch: {
  avatarObject: {
  async handler() {
    await this.updateSrc();
  },
  deep: true,
  },
  name: {
  async handler() {
    await this.updateSrc();
  },
  }, },
```

#### 单文件组件<template>部分

在这里，我们将创建`AvatarDisplay`组件的`<template>`部分：

1.  在`<template>`部分，创建一个`component`元素。创建两个动态属性，`src`和`is`。现在，`src`将绑定到数据`src`，而`is`属性将绑定到`componentIs`计算属性。最后，创建一个`spinner-color`属性，并将其定义为`'primary'`。

完成所有步骤后，您的最终代码应该像这样：

```js
<template>
  <component
  :src="src"
  :is="componentIs"
  spinner-color="primary"
  /> </template>
```

## 它是如何工作的...

在这个示例中，我们学习了如何通过包装 Quasar Framework 的组件并在其上添加自定义逻辑来为我们的应用程序创建自定义组件。

这种技术允许开发独特的组件，可以在应用程序中重复使用，而无需重写逻辑使其正常工作。

对于`Usernameinput`和`Nameinput`，我们在`QInput`组件周围创建了一个包装器，添加了验证规则和文本，以便更轻松地开发和重用组件，而无需添加更多逻辑。

在`PasswordInput`组件中，我们添加了控制密码可见性的逻辑，该逻辑会更改输入的类型，并自定义了`QInput`组件，以便有一个特殊按钮来触发可见性控制。

对于`EmailInput`，我们需要基于正则表达式创建自定义验证规则，检查输入的电子邮件是否是有效的电子邮件，并防止用户意外输入无效的电子邮件。

最后，在`AvatarInput`中，使用`QFile`组件，我们创建了一个自定义输入，当浏览器读取文件并将文件上传到 AWS Amplify Storage 时，自动上传文件，并在文件上传后将文件 URL 返回给应用程序。

## 另请参阅

+   在[`quasar.dev/vue-components/input`](https://quasar.dev/vue-components/input)找到有关 Quasar 输入组件的更多信息。

+   在[`quasar.dev/vue-components/file-picker`](https://quasar.dev/vue-components/file-picker)找到有关 Quasar 文件选择器组件的更多信息。

# 创建应用程序布局

在我们的应用程序中，我们将使用一个基于布局组件的父路由的`vue-router`结构，以及我们正在尝试访问的页面的最终路由。

这种模式改进了我们应用程序的开发，因为我们可以在`vue-router`上创建父子责任划分。

在本教程中，我们将学习如何创建自定义布局，将我们的页面包装在`vue-router`的父子结构中。

## 准备工作

本教程的先决条件如下：

+   最后的教程项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的应用程序自定义布局，我们将继续使用在*为应用程序创建自定义输入*中创建的项目。

## 如何做...

准备好我们的组件后，我们可以开始创建用于用户登录或注册到聊天应用程序或编辑其信息的布局，以及用于聊天消息页面的聊天布局。

### 创建基本布局

在我们的应用程序中，我们将使用一种基本布局的技术。它将成为应用程序所有内容的包装器。此布局将应用在布局执行中没有自定义更改的地方。

#### 单文件组件<script>部分

在这部分，我们将创建基本布局的<script>部分：

1.  在`layouts`文件夹中创建一个名为`Base.vue`的新文件。

1.  使用 JavaScript 对象创建一个`export default`实例，其中`name`属性定义为`'BaseLayout'`：

```js
<script> export default {
  name: 'BaseLayout', }; </script> 
```

#### 单文件组件<template>部分

在这里，我们将创建基本布局的<template>部分：

1.  创建一个`QLayout`组件，其中`view`属性定义为`"hHh Lpr lff"`：

```js
<q-layout view="hHh Lpr lff"> </q-layout>
```

1.  在`QLayout`组件内部，我们需要添加一个带有`elevated`属性的`QHeader`组件：

```js
<q-header elevated> </q-header>
```

1.  在`QHeader`组件中，我们将添加一个`QToolbar`组件，其中包含一个`QToolbarTitle`组件作为子元素，以文本作为插槽占位符：

```js
<q-toolbar>
 <q-toolbar-title>
  Chat App
  </q-toolbar-title> </q-toolbar>
```

1.  在`QHeader`组件之后，创建一个带有`RouterView`组件的`QPageContainer`组件作为直接子元素：

```js
<q-page-container>
 <router-view /> </q-page-container>
```

### 创建聊天布局

对于我们应用程序的经过身份验证的页面，我们将使用不同的页面布局，其中将有按钮供用户注销、管理其用户并浏览应用程序。

#### 单文件组件<script>部分

让我们创建聊天布局的<script>部分：

1.  在`layouts`文件夹中创建一个名为`Chat.vue`的新文件。

1.  从`src/driver/auth.js`中导入`signOut`函数：

```js
import {signOut,} from 'src/driver/auth';
```

1.  创建一个`export default`实例，包括一个 JavaScript 对象，其中包括两个属性：一个名为`name`的属性，定义为`'ChatLayout'`，另一个名为`methods`的属性：

```js
export default {
  name: 'ChatLayout',
  methods: {   }, };
```

1.  在`methods`属性中，添加一个名为`logOff`的新异步函数；在这个函数中，我们将执行`signOut`函数，并在其后重新加载浏览器：

```js
async logOff() {
  await signOut();
  window.location.reload(); }
```

#### 单文件组件<template>部分

在这里，我们将创建聊天布局的`<template>`部分：

1.  创建一个带有`view`属性定义为`"hHh Lpr lff"`的`QLayout`组件：

```js
<q-layout view="hHh Lpr lff"> </q-layout>
```

1.  在`QLayout`组件内部，我们需要添加一个带有`elevated`属性的`QHeader`组件：

```js
<q-header elevated> </q-header> 
```

1.  对于`QHeader`组件，我们将添加一个`QToolbar`组件，其中包含一个`QToolbarTitle`组件作为子元素，文本作为插槽占位符：

```js
<q-toolbar>
 <q-toolbar-title>
  Chat App
  </q-toolbar-title> </q-toolbar>
```

1.  对于`QToolbar`组件，在`QToolbarTitle`组件之前，我们将添加一个带有`dense`、`flat`和`round`属性定义为`true`的`QBtn`组件。在`icon`属性中，我们将添加一个三元表达式，验证`$route.meta.goBack`是否存在，以显示*back*图标或*person*图标。最后，对于`to`属性，我们将做同样的操作，但值将是`$route.meta.goBack`或一个具有`name`属性为`Edit`的 JavaScript 对象。

```js
<q-btn
  dense
  flat
  round
  replace
  :icon="$route.meta.goBack ? 'keyboard_arrow_left' : 'person'"
  :to="$route.meta.goBack ? $route.meta.goBack : {name: 'Edit'}" />
```

1.  在`QToolbarTitle`组件之后，我们将添加一个带有`dense`、`flat`和`round`属性的`QBtn`组件，这些属性被定义为`true`。对于`icon`属性，我们将定义为`exit_to_app`，对于`@click`指令，我们将传递`logOff`方法：

```js
<q-btn
  dense
 flat round icon="exit_to_app"
  @click="logOff" /> 
```

1.  在`QHeader`组件之后，创建一个带有`RouterView`组件作为直接子元素的`QPageContainer`组件：

```js
<q-page-container>
 <router-view /> </q-page-container>
```

## 工作原理...

在这个示例中，我们学习了如何创建我们将在应用程序中使用的布局。这些布局是我们应用程序页面的包装器，使得在需要时可以轻松添加常见项目，如菜单、头部项目和页脚项目，而无需编辑每个页面文件。

对于创建的两种布局，我们使用了常见的`QLayout`、`QHeader`和`QToolbarTitle`组件。这些组件创建了页面的结构，包括布局容器、头部容器和自定义头部工具栏。

最后，对于聊天布局，我们在页眉菜单中添加了两个按钮：一个按钮可以是返回按钮或菜单，具体取决于路由中是否存在该参数；另一个是注销按钮，用户可以用它来从应用程序中注销。

## 另请参阅

+   关于 Quasar Framework `QLayout`组件的更多信息，请访问[`quasar.dev/layout/layout`](https://quasar.dev/layout/layout)。

+   关于 Quasar Framework `QHeader`组件的更多信息，请访问[`quasar.dev/layout/header-and-footer`](https://quasar.dev/layout/header-and-footer)。

+   关于 Quasar Framework `QPage`组件的更多信息，请访问[`quasar.dev/layout/page`](https://quasar.dev/layout/page)。

+   关于 Quasar Framework `QBtn`组件的更多信息，请访问[`quasar.dev/vue-components/button`](https://quasar.dev/vue-components/button)。


# 第五章：创建用户 Vuex 模块、页面和路由

现在，是时候给应用程序一个可识别的面孔了。在本章中，我们将开始开发用户与应用程序之间的交互。

我们将利用我们从前面章节中收集的知识，通过使用自定义业务规则、Vuex 数据存储、特殊应用程序布局和用户可以交互的页面，将这个应用程序变得生动起来。

在本章中，我们将学习如何创建用户 Vuex 模块，以便我们可以存储和管理与用户、用户注册、登录、验证和编辑页面相关的一切。

在本章中，我们将涵盖以下配方：

+   在您的应用程序中创建用户 Vuex 模块

+   为您的应用程序创建用户页面和路由

让我们开始吧！

# 技术要求

在本章中，我们将使用**Node.js**、**AWS Amplify**和**Quasar Framework**。

**注意，Windows 用户！** 您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装所需的软件包。要做到这一点，以管理员身份打开 PowerShell 并执行`> npm install -g windows-build-tools`命令。

要安装**Quasar Framework**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @quasar/cli
```

要安装**AWS Amplify**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @aws-amplify/cli
```

# 在您的应用程序中创建用户 Vuex 模块

现在，是时候开始在我们的应用状态管理器或 Vuex 中存储数据了。在应用上下文中，存储的所有数据都保存在命名空间中。

在这个配方中，我们将学习如何创建用户 Vuex 模块。利用我们从上一章中获得的知识，然后创建动作来创建新用户、更新他们的数据、验证用户、在 Amplify 上登录用户，并列出应用程序中的所有用户。

## 准备工作

本配方的先决条件是 Node.js 12+。

本章所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的用户 Vuex 存储模块，我们将继续使用我们在第四章中创建的项目，即*创建自定义应用程序组件和布局*。

这个食谱将使用 GraphQL 查询和突变完成，以及它们的驱动程序，这些驱动程序是在第三章的*创建您的第一个 GraphQL API*和*为您的应用程序创建 AWS Amplify 驱动程序*食谱中编写的。

## 如何做...

我们将把用户的 Vuex 模块的创建分为五个部分：创建**state**，**mutations**，**getters**和**actions**，然后将模块添加到 Vuex 中。

### 创建用户的 Vuex 状态

要在 Vuex 模块上存储数据，我们需要一个将为我们存储数据的状态。按照以下步骤创建用户状态：

1.  在`store`文件夹中，创建一个名为`user`的新文件夹。在内部，创建一个名为`state.js`的新文件并打开它。

1.  创建一个名为`createState`的新函数，它返回一个 JavaScript 对象，提供`id`，`username`，`email`，`name`，`avatar`，`password`，`loading`，`validated`和`error`属性。`id`，`username`，`email`，`name`和`password`属性将被定义为空字符串，而`loading`和`validated`属性将被定义为`false`。`error`将被定义为`undefined`，`avatar`是一个具有三个属性的 JavaScript 对象-`key`，`bucket`和`region`：

```js
export function createState() {
  return {
  id: '',
  username: '',
  email: '',
  name: '',
  avatar: {
  key: '',
  bucket: '',
  region: '',
  },
  password: '',
  loading: false,
  validated: false,
  error: undefined,
  }; }
```

1.  最后，为了将状态导出为单例并将其作为 JavaScript 对象可用，我们需要`export default`执行`createState`函数：

```js
export default createState();
```

### 创建用户的 Vuex mutations

要在状态上保存任何数据，Vuex 需要一个 mutation。按照以下步骤创建将管理此模块的 mutations 的用户 mutation：

1.  在`store/user`文件夹内创建一个名为`types.js`的新文件并打开它。

1.  在文件中，导出一个默认的 JavaScript 对象，提供`CREATE_USER`，`SET_USER_DATA`，`CLEAR_USER`，`USER_VALIDATED`，`LOADING`和`ERROR`属性。值与属性相同，但格式为字符串。

```js
export default {
  CREATE_USER: 'CREATE_USER',   SET_USER_DATA: 'SET_USER_DATA',
  CLEAR_USER: 'CLEAR_USER',
  USER_VALIDATED: 'USER_VALIDATED',
  LOADING: 'LOADING',
  ERROR: 'ERROR', };
```

1.  在`store/user`文件夹内创建一个名为`mutations.js`的新文件并打开它。

1.  导入新创建的`types.js`文件和`state.js`中的`createState`JavaScript 对象：

```js
import MT from './types';  import { createState } from './state';
```

1.  创建一个名为`setLoading`的新函数，状态作为第一个参数。在内部，我们将设置`state.loading`为`true`：

```js
function setLoading(state) {
 state.loading = true; }
```

1.  创建一个名为`setError`的新函数，以`state`作为第一个参数，并以`error`作为第二个参数，其默认值为`new Error()`。在内部，我们将将`state.error`设置为`error`，将`state.loading`设置为`false`：

```js
function setError(state, error = new Error()) {
 state.error = error;
  state.loading = false; }
```

1.  创建一个名为`createUser`的新函数，以`state`作为第一个参数，并以 JavaScript 对象作为第二个参数。这个 JavaScript 对象将提供`id`、`email`、`password`、`name`和`username`属性。所有属性都将是空字符串。在函数内部，我们将定义`state`属性为函数参数中收到的属性：

```js
function createUser(state, {
 id = '',
  email = '',
  password = '',
  name = '',
  username = '', }) {
 state.username = username;
  state.email = email;
  state.name = name;
  state.id = id;
  state.password = window.btoa(password);
  state.loading = false; }
```

1.  创建一个名为`validateUser`的新函数，以`state`作为第一个参数。在其中，我们将将`state.validated`属性设置为`true`，删除`state.password`属性，并将`state.loading`属性设置为`false`：

```js
function validateUser(state) {
 state.validated = true;
  delete state.password;
  state.loading = false; }
```

1.  创建一个名为`setUserData`的新函数，以`state`作为第一个参数，并以 JavaScript 对象作为第二个参数。这个对象将提供`id`、`email`、`password`、`name`和`username`属性。它们都将是空字符串。`avatar`是一个具有三个属性的 JavaScript 对象：`key`、`bucket`和`region`。在函数内部，我们将定义`state`属性为函数参数中收到的属性：

```js
function setUserData(state, {
 id = '',
  email = '',
  name = '',
  username = '',
  avatar = {
  key: '',
  bucket: '',
  region: '',
  }, }) {
 state.id = id;
  state.email = email;
  state.name = name;
  state.username = username;
  state.avatar = avatar || {
  key: '',
  bucket: '',
  region: '',
  };    delete state.password;    state.validated = true;
  state.loading = false; }
```

1.  创建一个名为`clearUser`的新函数，以`state`作为第一个参数。然后，在其中的函数中，我们将从`createState`函数获取一个新的干净的`state`，并迭代当前的`state`，将`state`属性的值重新定义为默认值：

```js
function clearUser(state) {
  const newState = createState();    Object.keys(state).forEach((key) => {
 state[key] = newState[key];
  }); }
```

1.  最后，导出一个默认的 JavaScript 对象，其中键是导入的变异类型，值是对应于每种类型的函数：

+   将`MT.LOADING`设置为`setLoading`

+   将`MT.ERROR`设置为`setError`

+   将`MT.CREATE_USER`设置为`createUser`

+   将`MT.USER_VALIDATED`设置为`validateUser`

+   将`MT.SET_USER_DATA`设置为`setUserData`

+   将`MT.CLEAR_USER`设置为`clearUser`

```js
export default {
 [MT.LOADING]: setLoading,
  [MT.ERROR]: setError,
  [MT.CREATE_USER]: createUser,
  [MT.USER_VALIDATED]: validateUser,
  [MT.SET_USER_DATA]: setUserData,
  [MT.CLEAR_USER]: clearUser, };  
```

### 创建用户 Vuex getter

要访问存储在状态中的数据，我们需要创建一些“getter”。按照以下步骤为用户模块创建“getter”：

在`getter`函数中，该函数将始终接收到 Vuex`store`的当前`state`作为第一个参数。

1.  在`store/user`文件夹内创建一个名为`getters.js`的新文件。

1.  创建一个名为`getUserId`的新函数，返回`state.id`：

```js
const getUserId = (state) => state.id;
```

1.  创建一个名为`getUserEmail`的新函数，返回`state.email`：

```js
const getUserEmail = (state) => state.email;
```

1.  创建一个名为`getUserUsername`的新函数，返回`state.username`：

```js
const getUserUsername = (state) => state.username;
```

1.  创建一个名为`getUserAvatar`的新函数，返回`state.avatar`：

```js
const getUserAvatar = (state) => state.avatar;
```

1.  创建一个名为`getUser`的新函数，返回一个提供`id`、`name`、`username`、`avatar`和`email`属性的 JavaScript 对象。这些属性的值将对应于`state`：

```js
const getUser = (state) => ({
  id: state.id,
  name: state.name,
  username: state.username,
  avatar: state.avatar,
  email: state.email, });
```

1.  创建一个名为`isLoading`的新函数，返回`state.loading`：

```js
const isLoading = (state) => state.loading;
```

1.  创建一个名为`hasError`的新函数，返回`state.error`：

```js
const hasError = (state) => state.error;
```

1.  最后，导出一个带有创建的函数（`getUserId`、`getUserEmail`、`getUserUsername`、`getUserAvatar`、`getUser`、`isLoading`和`hasError`）作为属性的`default`JavaScript 对象：

```js
export default {
  getUserId,
  getUserEmail,
  getUserUsername,
  getUserAvatar,
  getUser,
  isLoading,
  hasError, };
```

### 创建用户 Vuex 操作

按照以下步骤创建用户 Vuex 操作：

1.  在`store/user`文件夹内创建一个名为`actions.js`的文件并打开它。

1.  首先，我们需要导入这里将要使用的函数、枚举和类。

+   从`aws-amplify`npm 包中导入`graphqlOperation`。

+   从 GraphQL 查询中导入`getUser`和`listUsers`。

+   从 GraphQL 变异中导入`createUser`和`updateUser`。

+   从`driver/auth.js`中导入`signUp`、`validateUser`、`signIn`、`getCurrentAuthUser`和`changePassword`函数。

+   从`driver/appsync`导入`AuthAPI`。

+   从`./types.js`导入 Vuex 变异类型：

```js
import { graphqlOperation } from 'aws-amplify';
import { getUser, listUsers } from 'src/graphql/queries';
import { createUser, updateUser } from 'src/graphql/mutations';
import { AuthAPI } from 'src/driver/appsync';
import {
  signUp,
  validateUser,
  signIn,
  getCurrentAuthUser,
  changePassword,
} from 'src/driver/auth';
import MT from './types';

```

1.  创建一个名为`initialLogin`的新异步函数。此函数将接收一个 JavaScript 对象作为第一个参数。这将提供一个`commit`属性。在这个函数中，我们将获取当前认证的用户，从 GraphQL API 获取他们的数据，并将用户数据提交到 Vuex 存储中：

```js
async function initialLogin({ commit }) {
  try {
  commit(MT.LOADING);    const AuthUser = await getCurrentAuthUser();    const { data } = await AuthAPI.graphql(graphqlOperation(getUser, {
    id: AuthUser.username,
  }));    commit(MT.SET_USER_DATA, data.getUser);    return Promise.resolve(AuthUser);
  } catch (err) {
  commit(MT.ERROR, err);
  return Promise.reject(err);
  } }
```

1.  创建一个名为`signUpNewUser`的新异步函数。此函数将接收一个带有`commit`属性的 JavaScript 对象作为第一个参数。第二个参数也是一个 JavaScript 对象，但具有`email`、`name`和`password`属性。在这个函数中，我们将执行`auth.js`驱动器中的`signUp`函数来注册并在 AWS Cognito 用户池中创建用户，然后将用户数据提交到 Vuex 存储中：

```js
async function signUpNewUser({ commit }, {
  email = '',
  name = '',
  username = '',
  password = '', }) {
  try {
  commit(MT.LOADING);    const userData = await signUp(email, password);    commit(MT.CREATE_USER, {
    id: userData.userSub,
    email,
    password,
    name,
    username,
  });    return Promise.resolve(userData);
  } catch (err) {
  commit(MT.ERROR, err);
  return Promise.reject(err);
  } }
```

1.  创建一个名为`createNewUser`的新异步函数。这个函数将接收一个 JavaScript 对象作为第一个参数，其中包含`commit`和`state`属性。对于第二个参数，函数将接收一个`code`字符串。在这个函数中，我们将从`state`中获取用户数据，并执行`auth.js`驱动器中的`validateUser`函数，以检查用户是否是 AWS Cognito 用户池中的有效用户。然后，我们将执行`auth.js`中的`signIn`函数，将`email`和`password`作为参数传递，需要将`password`转换为加密的 base64 字符串，然后发送到函数。之后，我们将获取经过身份验证的用户数据，并将其发送到 GraphQL API 以创建一个新用户：

```js
async function createNewUser({ commit, state }, code) {
  try {
  commit(MT.LOADING);
  const {
    email,
    name,
    username,
    password,
  } = state;
  const userData = await validateUser(email, code);    await signIn(`${email}`, `${window.atob(password)}`);    const { id } = await getCurrentAuthUser();    await AuthAPI.graphql(graphqlOperation(
    createUser,
    {
      input: {
        id,
        username,
        email,
        name,
      },
    },
  ));    commit(MT.USER_VALIDATED);    return Promise.resolve(userData);
  } catch (err) {
  commit(MT.ERROR, err);
  return Promise.reject(err);
  } }
```

1.  创建一个名为`signInUser`的新异步函数。这个函数将接收一个 JavaScript 对象作为第一个参数，其中包含`commit`和`dispatch`属性。第二个参数也是一个 JavaScript 对象，包含`email`和`password`属性。在这个函数内部，我们将执行`auth.js`驱动器中的`signIn`函数，将`email`和`password`作为参数传递，然后触发`initialLogin` Vuex 动作：

```js
async function signInUser({ commit, dispatch }, { email = '', password = '' }) {
  try {
  commit(MT.LOADING);    await signIn(`${email}`, `${password}`);    await dispatch('initialLogin');    return Promise.resolve(true);
  } catch (err) {
  commit(MT.ERROR);
  return Promise.reject(err);
  } }
```

1.  创建一个名为`editUser`的新异步函数。这个函数将接收一个 JavaScript 对象作为第一个参数，其中包含`commit`和`state`属性。第二个参数也是一个 JavaScript 对象，包含`username`、`name`、`avatar`、`password`和`newPassword`属性。在这个函数内部，我们将合并`state`的值和作为参数接收到的新值。然后将它们发送到 GraphQL API 以更新用户信息。然后，我们将检查是否`password`和`newPasssword`属性都填写了。如果是，我们将执行`auth.js`驱动器中的`changePassword`函数，以在 AWS Cognito 用户池中更改用户的密码：

```js
async function editUser({ commit, state }, {
  username = '',
  name = '',
  avatar = {
  key: '',
  bucket: '',
  region: '',
  },
  password = '',
  newPassword = '', }) {
  try {
  commit(MT.LOADING);    const updateObject = {
    ...{
      name: state.name,
      username: state.username,
      avatar: state.avatar,
    },
    ...{
      name,
      username,
      avatar,
    },
  };    const { data } = await AuthAPI.graphql(graphqlOperation(updateUser,
    { input: { id: state.id, ...updateObject } }));    if (password && newPassword) {
    await changePassword(password, newPassword);
  }    commit(MT.SET_USER_DATA, data.updateUser);    return Promise.resolve(data.updateUser);
  } catch (err) {
  return Promise.reject(err);
  } }
```

1.  创建一个名为`listAllUsers`的新异步函数。这个函数将获取数据库中的所有用户并返回一个列表：

```js
async function listAllUsers() {
  try {
  const {
    data: {
      listUsers: {
        items: usersList,
      },
    },
  } = await AuthAPI.graphql(graphqlOperation(
    listUsers,
  ));    return Promise.resolve(usersList);
  } catch (e) {
  return Promise.reject(e);
  } }
```

1.  最后，我们将导出所有默认创建的函数：

```js
export default {
  initialLogin,
  signUpNewUser,
  createNewUser,
  signInUser,
  editUser,
  listAllUsers, };
```

### 将用户模块添加到 Vuex

按照以下步骤将创建的用户模块导入到 Vuex 状态中：

1.  在`store/user`文件夹内创建一个名为`index.js`的新文件。

1.  导入我们刚刚创建的`state.js`、`actions.js`、`mutation.js`和`getters.js`文件：

```js
import state from './state'; import actions from './actions'; import mutations from './mutations'; import getters from './getters';
```

1.  创建一个带有 JavaScript 对象的`export default`，提供`state`、`actions`、`mutations`、`getters`和`namespaced`（设置为`true`）属性：

```js
export default {
  namespaced: true,
  state,
  actions,
  mutations,
  getters, };
```

1.  打开`store`文件夹中的`index.js`文件。

1.  在`store/user`文件夹中导入新创建的`index.js`：

```js
import Vue from 'vue'; import Vuex from 'vuex'; import user from './user';
```

1.  在新的 Vuex 类实例化中，我们需要添加一个名为`modules`的新属性，并将其定义为 JavaScript 对象。然后，我们需要添加一个新的`user`属性-这将自动用作值，因为它与上一步中导入的 User 模块具有相同的名称：

```js
export default function (/* { ssrContext } */) {
  const Store = new Vuex.Store({
  modules: {
  user,
  },
  strict: process.env.DEV,
  });    return Store; }
```

## 工作原理...

当声明你的 Vuex 存储时，你需要创建三个主要属性：`state`、`mutations`和`actions`。这些属性作为一个单一的结构，通过注入的`$store`原型或导出的`store`变量绑定到 Vue 应用程序。

`state`是一个集中的对象，保存着你的信息，并使其可以被`mutations`、`actions`或`components`使用。改变`state`总是需要通过`mutation`执行同步函数。

`mutation`是一个同步函数，可以改变`state`并被追踪。这意味着在开发时，你可以在 Vuex 存储中时间旅行通过所有执行的`mutations`。

`action`是一个异步函数，可以用来保存业务逻辑、API 调用、分发其他`actions`和执行`mutations`。这些函数是当你需要对 Vuex 存储进行更改时的常见入口点。

Vuex 存储的简单表示可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/f7d5f47b-8fd3-4f9e-99e2-1d7df4243318.png)

在这个示例中，我们创建了 User Vuex 模块。该模块包括了所有的业务逻辑，将帮助我们在应用程序中管理用户，从创建新用户到更新用户。

当我们查看 Vuex actions 时，我们使用 AppSync API 客户端来获取数据并将其发送到我们的 GraphQL API。我们使用了由 Amplify CLI 创建的查询和 mutations。为了能够与 GraphQL API 通信，以便我们可以更新用户，我们从*为应用程序创建 AWS Amplify driver*配方中获取了我们在 Auth Driver 中使用的数据，第三章，*设置我们的聊天应用程序 - AWS Amplify 环境和 GraphQL*。

这些 API 请求由 Vuex mutations 操纵，并存储在 Vuex 状态中，我们可以通过 Vuex getter 访问。

## 另请参阅

+   您可以在[`aws-amplify.github.io/docs/js/api#amplify-graphql-client`](https://aws-amplify.github.io/docs/js/api#amplify-graphql-client)找到有关 Amplify 的 AppSync GraphQL 客户端的更多信息。

+   您可以在[https:/​/​vuex.​vuejs.​org/​](https://vuex.vuejs.org/)找到有关 Vuex 的更多信息。

+   您可以在[`vuex.vuejs.org/guide/modules.html`](https://vuex.vuejs.org/guide/modules.html)找到有关 Vuex 模块的更多信息

# 为您的应用程序创建用户页面和路由

在使用 Vue 应用程序时，您需要一种管理用户位置的方法。您可以使用动态组件来处理这个问题，但最好的方法是通过路由管理。

在这个食谱中，我们将学习如何创建我们的应用程序页面，其中包含每个路由所需的业务规则。然后，我们将使用路由管理来处理一切。

## 准备工作

此食谱的先决条件如下：

+   我们在上一个食谱中创建的项目

+   Node.js 12+

此食谱所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的用户页面和路由，我们将继续使用在*在应用程序上创建用户 Vuex 模块*食谱中创建的项目。

## 如何做...

在这个食谱中，我们将为我们的应用程序创建所有我们需要的用户页面：登录页面、注册页面和用户编辑页面。

### 将对话框插件添加到 Quasar

使用 Quasar 对话框插件，我们需要将其添加到配置文件中。

打开项目根文件夹内的`quasar.conf.js`文件，并找到`framework`属性。然后，在`plugins`属性中，将`'Dialog'`字符串添加到数组中，以便 Quasar 在启动应用程序时加载`Dialog`插件：

```js
framework: {
 ...
  plugins: [
  'Dialog',
 ],
 ...
},
```

### 创建用户登录页面

对于用户登录页面，我们将使用之前创建的两个组件：`PasswordInput`和`EmailInput`。

#### 单文件组件`<script>`部分

现在是创建用户登录页面的`<script>`部分的时候了：

1.  在`src/pages`文件夹中，打开`Index.vue`文件。

1.  从`vuex`包中导入`mapActions`和`mapGetters`函数：

```js
import { mapActions, mapGetters } from 'vuex';
```

1.  创建一个具有五个属性的`export default` JavaScript 对象；即`name`（定义为`'Index'`），`components`，`data`，`computed`和`methods`：

```js
export default {
  name: 'Index',
  components: {
  },
  data: () => ({   }),
  computed: {   },
  methods: {   }, }; 
```

1.  在`components`属性中，添加两个名为`PasswordInput`和`EmailInput`的新属性。将`PasswordInput`定义为一个匿名函数，其返回值为`import('components/PasswordInput')`，并将`EmailInput`定义为一个匿名函数，其返回值为`import('components/EmailInput')`：

```js
components: {
  PasswordInput: () => import('components/PasswordInput'),
  EmailInput: () => import('components/EmailInput'), },
```

1.  在`data`属性中，我们将返回一个提供两个属性`email`和`password`的 JavaScript 对象，它们都将是空字符串：

```js
data: () => ({
  email: '',
  password: '', }),
```

1.  在`computed`属性中，我们将解构`mapGetters`函数，将我们想要的模块的命名空间作为第一个参数（在本例中为`'user'`）。我们将把我们想要导入的`getters`数组（在本例中为`isLoading`）作为第二个参数传递进去：

```js
computed: {
  ...mapGetters('user', [
  'isLoading',
  'getUserId',
  ]), },
```

1.  在`beforeMount`生命周期钩子上，我们将添加一个`if`语句，检查`getUserId`是否为真，并将用户重定向到`Contacts`路由。

```js
async beforeMount() {
  if (this.getUserId) {
  await this.$router.replace({ name: 'Contacts' });
  } }, 
```

1.  最后，在`methods`属性中，我们将解构`mapActions`函数，将我们想要的模块的命名空间（在本例中为`'user'`）作为第一个参数传递进去。对于第二个参数，我们将使用一个包含我们想要导入的`actions`的数组（在这种情况下，这是`signInUser`）。接下来，我们需要添加异步的`onSubmit`方法，该方法将调度`signInUser`并将用户发送到`Contacts`路由，以及`createAccount`方法，该方法将用户发送到`SignUp`路由：

```js
methods: {
  ...mapActions('user', [
  'signInUser',
  ]),
  async onSubmit() {
  try {
    await this.signInUser({
      email: this.email,
      password: this.password,
    });
    await this.$router.push({ name: 'Contacts' });
  } catch (e) {
    this.$q.dialog({
      message: e.message,
    });
  }
  },
  createAccount() {
  this.$router.push({ name: 'SignUp' });
  }, },
```

#### 单文件组件`<template>`部分

现在，我们需要添加`<template>`部分来完成我们的页面：

1.  创建一个名为`QPage`的组件，其`class`属性定义为`"bg-grey-1 flex flex-center"`：

```js
<q-page padding class="bg-grey-1 flex flex-center">
</q-page>
```

1.  在`QPage`组件内部，创建一个`QCard`组件，其`style`属性定义为`"width: 350px"`：

```js
<q-card style="width: 350px">  </q-card> 
```

1.  在`QCard`组件内部，创建一个带有`class`属性定义为`no-margin`的`QCardSection`和一个`h6`子组件：

```js
<q-card-section>
  <h6 class="no-margin">Chat Application</h6>  </q-card-section>
```

1.  现在，创建一个`QCardSection`，其中包含一个`QForm`子组件，其 class 属性定义为`q-gutter-md`。在`QForm`组件内部，创建一个`EmailInput`组件，其`v-model`指令绑定到`data.email`，以及一个`PasswordInput`组件，其`v-model`指令绑定到`data.password`属性：

```js
<q-card-section>
 <q-form
  class="q-gutter-md"
  >
 <email-input
  v-model.trim="email"
  />
 <password-input
  v-model.trim="password"
  />
 </q-form> </q-card-section>
```

1.  然后，创建一个 `QCardActions` 组件，其中定义了一个 `align` 属性为 `right`。在内部，添加一个 `QBtn`，`label` 属性设置为 `"Create new Account"`，`color` 设置为 `primary`，`class` 设置为 `q-ml-sm`，`flat` 设置为 `true`，并且 `@click` 事件监听器绑定到 `createAccount` 方法。接下来，创建另一个 `QBtn` 组件，`label` 属性设置为 `"Login"`，`type` 设置为 `"submit"`，`color` 设置为 `primary`，并且 `@click` 事件监听器绑定到 `onSubmit` 方法：

```js
<q-card-actions align="right">
 <q-btn
  label="Create new account"
  color="primary"
  flat
 class="q-ml-sm"
  @click="createAccount"
  />
 <q-btn
  label="Login"
  type="submit"
  color="primary"
  @click="onSubmit"
  /> </q-card-actions>
```

1.  最后，创建一个 `QInnerLoading` 组件，将 `:showing` 属性绑定到 `computed.isLoading`。这将需要有一个 `QSpinner` 子组件，提供 `size` 属性。将其设置为 `50px`，`color` 设置为 `primary`：

```js
<q-inner-loading :showing="isLoading">
 <q-spinner size="50px" color="primary"/> </q-inner-loading>
```

要运行服务器并查看您的进度，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar dev
```

请记住始终执行命令 `npm run lint --fix`，以自动修复任何代码 lint 错误。

这是页面预览的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/24406191-9d75-4c7f-80f1-f28a74bb3517.png)

### 创建用户注册页面

对于用户注册页面，我们将使用已经创建的四个组件：`NameInput`，`UsernameInput`，`PasswordInput` 和 `EmailInput`。

#### 单文件组件 <script> 部分

在这里，我们将创建用户注册页面的 `<script>` 部分：

1.  在 **`src/pages` ** 文件夹中，创建一个名为 `SignUp.vue` 的新文件并打开它。

1.  从 `vuex` 包中导入 `mapActions` 和 `mapGetters` 函数：

```js
import { mapActions, mapGetters } from 'vuex';
```

1.  创建一个 `export default` JavaScript 对象，提供五个属性：`name`（定义为 `'SignUp'`），`components`，`data`，`computed` 和 `methods`：

```js
export default {
  name: 'SignUp',
 components: {},  data: () => ({   }),
  computed: {   },
  methods: {   }, };
```

1.  在 `components` 属性中，添加四个新属性：`NameInput`，`UsernameInput`，`PasswordInput` 和 `EmailInput`。像这样定义它们：

+   `NameInput` 作为一个匿名函数，返回值为 `import('components/NameInput')`

+   `UsernameInput` 作为一个匿名函数，返回值为 `import('components/UsernameInput')`

+   `PasswordInput` 作为一个匿名函数，返回值为 `import('components/PasswordInput')`

+   `EmailInput` 作为一个匿名函数，返回值为 `import('components/EmailInput')`

这可以在以下代码中看到：

```js
components: {
  PasswordInput: () => import('components/PasswordInput'),
  EmailInput: () => import('components/EmailInput'),
  UsernameInput: () => import('components/UsernameInput'),
  NameInput: () => import('components/NameInput'), }, 
```

1.  在 `data` 属性中，我们将返回一个提供四个属性的 JavaScript 对象 - `name`，`username`，`email` 和 `password` - 其中所有属性都将是空字符串：

```js
data: () => ({
  name: '',
  username: '',
  email: '',
  password: '', }),
```

1.  在`computed`属性中，我们将解构`mapGetters`函数，将我们想要的模块的命名空间（在本例中为`'user'`）作为第一个参数传递。对于第二个参数，我们将使用一个要导入的`getters`数组，这种情况下是`isLoading`：

```js
computed: {
  ...mapGetters('user', [
  'isLoading',
  ]), },
```

1.  最后，对于`methods`属性，首先，我们将解构`mapActions`函数，将我们想要的模块的命名空间（在本例中为`'user'`）作为第一个参数传递。对于第二个参数，我们将传递一个要导入的`actions`数组，这种情况下是`signUpNewUser`。接下来，我们需要添加异步的`onSubmit`方法，它将分发`signUpNewUser`，然后将用户发送到`Validate`路由，以及`onReset`方法，它将清除数据：

```js
methods: {
  ...mapActions('user', [
  'signUpNewUser',
  ]),
  async onSubmit() {
  try {
    await this.signUpNewUser({
      name: this.name,
      username: this.username,
      email: this.email,
      password: this.password,
    });
    await this.$router.replace({ name: 'Validate' });
  } catch (e) {
    this.$q.dialog({
      message: e.message,
    });
  }
  },
  onReset() {
  this.email = '';
  this.password = '';
  }, },
```

#### 单文件组件`<template>`部分

要完成页面，我们需要添加`<template>`部分：

1.  创建一个`QPage`组件，`class`属性定义为`"bg-grey-1 flex flex-center"`：

```js
<q-page padding class="bg-grey-1 flex flex-center">
</q-page>
```

1.  在`QPage`组件内部，创建一个`QCard`组件，`style`属性定义为`"width: 350px"`：

```js
<q-card style="width: 350px">  </q-card>
```

1.  在`QCard`组件内部，创建一个`QCardSection`，其中包含一个`h6`子组件，其中`class`属性定义为`no-margin`：

```js
<q-card-section>
 <h6 class="no-margin">Create a new Account</h6> </q-card-section> 
```

1.  之后，创建一个`QCardSection`，其中包含一个`QForm`子组件，其中`class`属性定义为`q-gutter-md`。在`QForm`组件内部，创建一个`NameInput`组件，`v-model`指令绑定到`data.name`，一个`UsernameInput`组件，`v-model`指令绑定到`data.username`，一个`EmailInput`组件，`v-model`指令绑定到`data.email`，以及一个`PasswordInput`组件，`v-model`指令绑定到`data.password`属性：

```js
<q-card-section>
 <q-form   class="q-gutter-md"
  >
 <name-input
  v-model.trim="name"
  />
 <username-input
  v-model.trim="username"
  />
 <email-input
  v-model.trim="email"
  />
 <password-input
  v-model.trim="password"
  />
 </q-form> </q-card-section>
```

1.  现在，创建一个`QCardActions`组件，`align`属性设置为`right`。在内部，添加一个`QBtn`，`label`属性设置为`"Reset"`，`color`设置为`primary`，`class`设置为`q-ml-sm`，`flat`设置为`true`，`@click`事件监听器绑定到`onReset`方法。然后，创建另一个`QBtn`组件，`label`属性设置为`"Create"`，`type`设置为`"submit"`，`color`设置为`primary`，`@click`事件监听器绑定到`onSubmit`方法：

```js
<q-card-actions align="right">
 <q-btn
  label="Reset"
  type="reset"
  color="primary"
  flat
 class="q-ml-sm"
  @click="onReset"
  />
 <q-btn
  label="Create"
  type="submit"
  color="primary"
  @click="onSubmit"
  /> </q-card-actions>
```

1.  最后，创建一个`QInnerLoading`组件，`:showing`属性绑定到`computed.isLoading`。这将需要一个`QSpinner`子组件。`size`属性需要设置为`50px`，`color`需要设置为`primary`：

```js
<q-inner-loading :showing="isLoading">
 <q-spinner size="50px" color="primary"/> </q-inner-loading> 
```

要运行服务器并查看您的进度，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar dev
```

记得始终执行命令`npm run lint --fix`，自动修复任何代码 lint 错误。

这是页面的预览：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/11952d7a-f53c-4afb-b56b-fd669409c0e8.png)

### 创建用户验证页面。

用户创建了一个账户后，AWS Amplify 将发送一封带有验证 pin 码的电子邮件，我们需要将其发送回来进行验证。这个页面将是验证页面。

#### 单文件组件`<script>`部分

按照以下步骤创建用户验证页面的`<script>`部分：

1.  在`src/pages`文件夹内，创建一个名为`Validate.vue`的新文件并打开它。

1.  从`vuex`包中导入`mapActions`和`mapGetters`函数，以及从`src/driver/auth`导入`resendValidationCode`：

```js
import { mapActions, mapGetters } from 'vuex';
import { resendValidationCode } from 'src/driver/auth';    
```

1.  创建一个`export default`的 JavaScript 对象，提供四个属性：`name`（定义为`'Validate'`）、`data`、`computed`和`methods`：

```js
export default {
  name: 'Validate',   data: () => ({   }),
  computed: {   },
  methods: {   }, };
```

1.  在`data`属性内，我们将返回一个具有空字符串`code`属性的 JavaScript 对象：

```js
data: () => ({
  code: '', }),
```

1.  在`computed`属性内，我们将解构`mapGetters`函数，传递我们想要的模块的命名空间作为第一个参数，例如`'user'`。对于第二个参数，我们将传递一个要导入的`getters`数组，例如`isLoading`和`getUserEmail`：

```js
computed: {
  ...mapGetters('user', [
  'isLoading',
  'getUserEmail',
 ]), }, 
```

1.  最后，在`methods`属性中，我们将解构`mapActions`函数，传递我们想要的模块的命名空间作为第一个参数，例如`'user'`。对于第二个参数，我们将传递一个要导入的`actions`数组，例如`createNewUser`。接下来，我们需要添加异步的`onSubmit`方法，它将分发`createNewUser`并将用户发送到`Index`路由；`resendCode`方法，它将重新发送用户另一个验证代码；以及`onReset`方法，它将重置数据：

```js
methods: {
  ...mapActions('user', [
  'createNewUser',
  ]),
  async onSubmit() {
  try {
    await this.createNewUser(this.code);
    await this.$router.replace({ name: 'Index' });
  } catch (e) {
    console.error(e);
    this.$q.dialog({
      message: e.message,
    });
  }
  },
  async resendCode() {
  await resendValidationCode(this.getUserEmail);
  },
  onReset() {
  this.code = '';
  }, },
```

#### 单文件组件`<template>`部分

按照以下步骤创建用户验证页面的`<template>`部分：

1.  创建一个`QPage`组件，定义`class`属性为`"bg-grey-1 flex flex-center"`：

```js
<q-page padding class="bg-grey-1 flex flex-center">
</q-page>
```

1.  在`QPage`组件内部，创建一个`QCard`组件，定义`style`属性为`"width: 350px"`：

```js
<q-card style="width: 350px">  </q-card>
```

1.  在 `QCard` 组件内，创建一个带有 `h6` 子组件和定义为 `no-margin` 的 `class` 属性的 `QCardSection`。然后，创建一个兄弟元素，其 `class` 属性定义为 `text-subtitle2`：

```js
<q-card-section>
 <h6 class="no-margin">Validate new account</h6>
 <div class="text-subtitle2">{{ getUserEmail }}</div> </q-card-section>
```

1.  创建一个带有两个子组件的 `QCardSection`。这些将是 HTML 元素 `P`：

```js
<q-card-section>
 <p>A validation code were sent to you E-mail.</p>
 <p>Please enter it to validate your new account.</p> </q-card-section>
```

1.  之后，创建一个带有 `QForm` 子组件和定义为 `q-gutter-md` 的 `class` 属性的 `QCardSection`。在 `QForm` 组件内，添加 `QInput` 组件作为子元素。然后，在 `QInput` 组件内，将 `v-model` 指令绑定到 `data.code`。在 `QInput` 的 `rules` 属性内，将 `rules` 值定义为一个验证数组，用于检查是否已输入任何代码。启用 `lazy-rules`，以便它只在一段时间后进行验证：

```js
<q-card-section>
 <q-form
  class="q-gutter-md"
  >
 <q-input
  v-model.trim="code"
  :rules="[ val => val && val.length > 0
  || 'Please type the validation code']"
  outlined
 label="Validation Code"
  lazy-rules
  />
 </q-form> </q-card-section> 
```

1.  现在，创建一个带有 `align` 属性设置为 `right` 的 `QCardActions` 组件。在内部，添加一个 `label` 属性设置为 `"Reset"`、`color` 设置为 `primary`、`class` 设置为 `q-ml-sm`、`flat` 设置为 `true`，并且 `@click` 事件监听器绑定到 `onReset` 方法的 `QBtn`。创建另一个 `label` 属性设置为 `"Re-send code"`、`color` 设置为 `secondary`、`class` 设置为 `q-ml-sm`、`flat` 设置为 `true`，并且 `@click` 事件监听器绑定到 `resendCode` 方法的 `QBtn`。最后，创建一个带有 `label` 属性设置为 `"Validate"`、`type` 设置为 `"submit"`、`color` 设置为 `primary`，并且 `@click` 事件监听器绑定到 `onSubmit` 方法的 `QBtn` 组件：

```js
<q-card-actions align="right">
 <q-btn
  label="Reset"
  type="reset"
  color="primary"
  flat
 class="q-ml-sm"
  />
 <q-btn
  flat
 label="Re-send code"
  color="secondary"
  class="q-ml-sm"
  @click="resendCode"
  />
 <q-btn
  label="Validate"
  type="submit"
  color="primary"
  @click="onSubmit"
  /> </q-card-actions>
```

1.  最后，创建一个带有 `:showing` 属性绑定到 `computed.isLoading` 的 `QInnerLoading` 组件。它应该有一个 `size` 设置为 `50px` 和 `color` 设置为 `primary` 的 `QSpinner` 子组件：

```js
<q-inner-loading :showing="isLoading">
 <q-spinner size="50px" color="primary"/> </q-inner-loading>
```

要运行服务器并查看您的进度，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar dev 
```

记得始终执行命令 `npm run lint --fix`，自动修复任何代码 lint 错误。

这是页面的预览：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/b8f80c2c-f928-4240-9622-205a135d67b7.png)

### 创建用户编辑页面

对于用户编辑页面，我们将使用我们已经创建的四个组件：`NameInput`、`UsernameInput`、`AvatarInput` 和 `PasswordInput`。

#### 单文件组件 <script> 部分

按照以下步骤开始开发用户编辑页面的 `<script>` 部分：

1.  在 `src/pages` 文件夹内，创建一个名为 `Edit.vue` 的新文件并打开它。

1.  从`vuex`包中导入`mapActions`和`mapGetters`函数：

```js
import { mapActions, mapGetters } from 'vuex';
```

1.  创建一个`export default`的 JavaScript 对象，提供四个属性：`name`（定义为`'SignUp'`）、`data`、`computed`和`methods`：

```js
export default {
  name: 'EditUser',
  components: {},   data: () => ({   }),
  created() {},
  computed: {   },
  methods: {   }, };
```

1.  在`components`属性中，添加四个名为`NameInput`、`UsernameInput`、`PasswordInput`、`AvatarInput`的新属性。设置它们如下：

`NameInput`作为一个匿名函数，返回值为`import('components/NameInput')`

`UsernameInput`作为一个匿名函数，返回值为`import('components/UsernameInput')`

`PasswordInput`作为一个匿名函数，返回值为`import('components/PasswordInput')`

`AvatarInput`作为一个匿名函数，返回值为`import('components/AvatarInput')`：

```js
components: {
  AvatarInput: () => import('/components/AvatarInput'),
  PasswordInput: () => import('components/PasswordInput'),
  UsernameInput: () => import('components/UsernameInput'),
  NameInput: () => import('components/NameInput'), },
```

1.  在`data`属性中，我们将返回一个提供五个属性的 JavaScript 对象：`name`、`username`、`avatar`、`email`和`password`。所有这些都将是空字符串：

```js
data: () => ({
  name: '',
  username: '',
  avatar: '',
  password: '',
  newPassword: '', }), 
```

1.  在`created`生命周期钩子中，将`data.name`定义为`getUser.name`，`data.username`定义为`getUser.username`，以及`data.avatar`定义为`getUser.avatar`：

```js
created() {
  this.name = this.getUser.name;
  this.username = this.getUser.username;
  this.avatar = this.getUser.avatar; },
```

1.  在`computed`属性中，我们将解构`mapGetters`函数，传递我们想要的模块的命名空间作为第一个参数，这里是`'user'`。对于第二个参数，我们将传递一个要导入的`getters`数组，这种情况下是`isLoading`：

```js
computed: {
  ...mapGetters('user', [
  'getUser',
  'isLoading',
 ]), },
```

1.  最后，在`methods`属性中，我们将解构`mapActions`函数，传递我们想要的模块的命名空间作为第一个参数，这里是`'user'`。对于第二个参数，我们将传递一个要导入的`actions`数组，这种情况下是`editUser`。接下来，我们需要添加异步的`onSubmit`方法，它将调度`$refs.avatar.uploadFile()`，然后调度`editUser`发送用户到`Chat`路由，以及`onReset`方法，它将清除数据：

```js
methods: {
  ...mapActions('user', [
  'editUser',
  ]),
  async onSubmit() {
  try {
  await this.$refs.avatar.uploadFile();    await this.editUser({
  name: this.name,
  avatar: this.$refs.avatar.s3file,
  username: this.username,
  password: this.password,
  newPassword: this.newPassword,
  });   await this.$router.replace({ name: 'Contacts' });
  } catch (e) {
  this.$q.dialog({
  message: e.message,
  });
  }
 },
  onReset() {
  this.name = this.getUser.name;
  this.username = this.getUser.username;   this.password = '';
  this.newPassword = '';
  }, },
```

#### 单文件组件<template>部分

按照以下步骤创建用户编辑页面的`<template>`部分：

1.  创建一个带有`class`属性定义为`"bg-grey-1 flex flex-center"`的`QPage`组件：

```js
<q-page padding class="bg-grey-1 flex flex-center">
</q-page>
```

1.  在`QPage`组件内部，创建一个带有`style`属性定义为`"width: 350px"`的`QCard`组件：

```js
<q-card style="width: 350px">  </q-card>
```

1.  在`QCard`组件内部，创建一个带有`h6`子组件的`QCardSection`，并且`class`属性定义为`no-margin`：

```js
<q-card-section>
 <h6 class="no-margin">Edit user account</h6> </q-card-section> 
```

1.  之后，创建一个带有`class`属性定义为`q-gutter-md`的`QCardSection`，其中包含一个`QForm`子组件。在`QForm`组件内部，创建一个`AvatarInput`组件，其中`reference`指令定义为`avatar`，`v-model`指令绑定到`data.avatar`，一个`NameInput`组件，其中`v-model`指令绑定到`data.name`，一个`UsernameInput`组件，其中`v-model`指令绑定到`data.username`，一个`EmailInput`组件，其中`v-model`指令绑定到`data.email`，以及一个`PasswordInput`组件，其中`v-model`指令绑定到`data.password`属性：

```js
<q-card-section>
 <q-form
  class="q-gutter-md"
  >
 <avatar-input
  v-model="avatar"
  ref="avatar"
  />
 <name-input
  v-model.trim="name"
  />
 <username-input
  v-model.trim="username"
  />
 <q-separator/>
 <password-input
  v-model.trim="password"
  label="Your old password"
  />
 <password-input
  v-model.trim="newPassword"
  label="Your new password"
  />
 </q-form> </q-card-section> 
```

1.  现在，创建一个带有`align`属性设置为`right`的`QCardActions`组件。在内部，添加一个`label`属性设置为`"Reset"`，`color`设置为`primary`，`class`设置为`q-ml-sm`，`flat`设置为`true`，并且`@click`事件监听器绑定到`onReset`方法的`QBtn`。然后，创建另一个`QBtn`组件，其中`label`属性设置为`"Create"`，`type`设置为`"submit"`，`color`设置为`primary`，并且`@click`事件监听器绑定到`onSubmit`方法：

```js
<q-card-actions align="right">
 <q-btn
  label="Reset"
  type="reset"
  color="primary"
  flat
 class="q-ml-sm"
  @click="onReset"
  />
 <q-btn
  label="Update"
  type="submit"
  color="primary"
  @click="onSubmit"
  /> </q-card-actions> 
```

1.  最后，创建一个`QInnerLoading`组件，其中`:showing`属性绑定到`computed.isLoading`。它应该有一个`QSpinner`子组件，`size`设置为`50px`，`color`设置为`primary`：

```js
<q-inner-loading :showing="isLoading">
 <q-spinner size="50px" color="primary"/> </q-inner-loading>
```

要运行服务器并查看您的进度，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar dev 
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

这是页面的预览：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/2ede7f2f-961d-49d4-89d9-be1b0d4cc045.png)

### 创建应用程序路由

现在我们已经创建了用户页面、组件和布局，我们需要将它们绑定在一起，以便用户可以访问。为此，我们需要创建路由并使其可用，以便用户可以在页面之间导航。按照以下步骤进行操作：

1.  打开`router`文件夹内的`routes.js`文件。

1.  将`routes`常量设置为空数组：

```js
const routes = [];
```

1.  向该数组添加一个具有三个属性`path`、`component`和`children`的 JavaScript 对象。`path`属性是一个字符串，将是一个静态 URL，`component`属性是一个匿名函数，将返回一个带有将要渲染的组件的 WebPack`import`函数，`children`属性是一个将在`path`内渲染的组件数组。每个子组件都是一个具有相同属性的 JavaScript 对象，另外还有一个叫做`name`的新属性。

```js
{
  path: '/',
  component: () => import('layouts/Base.vue'),
  children: [
  {
    path: '',
    name: 'Index',
    meta: {
      authenticated: false,
    },
    component: () => import('pages/Index.vue'),
  },
  ], },
```

1.  现在，对于`/chat`URL，我们需要在`pages`文件夹内创建两个新的占位符页面：`Contacts.vue`和`Messages.vue`。在这些文件内，创建一个带有以下模板的空组件：

```js
<template>
  <div />
</template>
<script>
export default {
  name: 'PlaceholderPage',
};
</script>
```

1.  在`message`路由内，我们需要添加两个特殊参数：`:id`和`path`。这些参数将用于在用户之间获取特定的消息。

```js
{
  path: '/chat',
  component: () => import('layouts/Chat.vue'),
  children: [
  {
    path: 'contacts',
    name: 'Contacts',
    component: () => import('pages/Contacts.vue'),
  },
  {
    path: 'messages/:id/:name',
    name: 'Messages',
    meta: {
      authenticated: true,
      goBack: {
        name: 'Contacts',
      },
    },
    component: () => import('pages/Messages.vue'),
  },
  ], },
```

1.  对于`/user`URL，我们将只创建一个子路由，即`edit`路由。在这个路由内，我们使用`alias`属性，因为`vue-router`需要有一个`path`为空的子路由进行首次子路由渲染。我们还将在我们的应用程序内有一个`/user/edit`路由可用。

```js
{
  path: '/user',
  component: () => import('layouts/Chat.vue'),
  children: [
  {
    path: '',
    alias: 'edit',
    name: 'Edit',
    meta: {
      authenticated: true,
      goBack: {
        name: 'Contacts',
      },
    },
    component: () => import('pages/Edit.vue'),
  },
  ], },
```

1.  最后，对于创建新用户，我们需要添加`/register`URL，其中包括两个子路由：`SignUp`和`Validate`。`SignUp`路由将是注册 URL 上的主要路由，并且当用户进入此 URL 时将直接调用。`Validate`路由只有在用户被重定向到`/register/validate`URL 时才会被调用。

```js
{
  path: '/register',
  component: () => import('layouts/Base.vue'),
  children: [
  {
    path: '',
    alias: 'sign-up',
    name: 'SignUp',
    meta: {
      authenticated: false,
    },
    component: () => import('pages/SignUp.vue'),
  },
  {
    path: 'validate',
    name: 'Validate',
    meta: {
      authenticated: false,
    },
    component: () => import('pages/Validate.vue'),
  },
  ], },
```

### 添加身份验证守卫

为了在用户进入应用程序时验证用户身份令牌，如果令牌有效，或者用户试图访问无权限的路由，我们需要为我们的应用程序创建一个身份验证守卫。

1.  在`src/boot`文件夹内创建一个名为`routeGuard.js`的新文件。

1.  创建一个默认的导出异步函数。在这个参数内，添加一个名为`app`的 JavaScript 对象属性。在函数内部，创建一个常量，使用`app`的对象重构获取`store`属性。然后，创建一个`try/catch`块。在`try`部分，检查`'user/getUserId'`是否存在，如果不存在则调度`'user/initialLogin'`。最后，在`catch`块内，将用户重定向到`Index`路由。

```js
export default async ({ app }) => {
  const { store } = app;    try {
  if (!store.getters['user/getUserId']) {
    await store.dispatch('user/initialLogin');
  }
  } catch {
  await app.router.replace({ name: 'Index' });
  } };  
```

1.  最后，打开项目根文件夹内的`quasar.conf.js`文件，并找到`boot`属性。将`'routerGuard'`项添加到数组中。

```js
boot: [
  'amplify',
  'axios',
  'routeGuard', ],
```

## 它是如何工作的...

在本章中，我们开发了微组件，如`NameInput`，`EmailInput`等，以简化开发宏组件或容器（如页面）的过程。

在这个配方中，我们使用了在上一个配方中开发的组件来创建完整的页面，例如用户登录、用户编辑和用户注册页面。

使用`vue-router`来管理使用自定义布局包装页面的父子过程，我们使用了本书先前配方中创建的布局来为我们的应用程序创建路由。我们使它们可用，以便我们可以像正常的 Web 应用程序一样访问应用程序，具有自定义 URL 和路由。

最后，我们在我们的主初始化 Vue 文件中添加了一些身份验证中间件，以便我们可以重定向已经经过身份验证的用户。这意味着当他们第二次进入应用程序时，他们不需要再次进行身份验证。

## 还有...

现在，您的应用程序已准备好进行用户注册和登录。可以浏览用户注册页面，并从亚马逊收到一封带有验证代码的电子邮件，以便您可以在服务器上验证用户。

要检查您的进程并在本地环境中运行它，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar dev
```

请记住始终执行命令`npm run lint --fix`，以自动修复任何代码 lint 错误。

## 另请参阅

+   您可以在[`router.vuejs.org/guide/essentials/nested-routes.html`](https://router.vuejs.org/guide/essentials/nested-routes.html)找到有关`vue-router`嵌套路由的更多信息。

+   您可以在[`router.vuejs.org/guide/advanced/lazy-loading.html`](https://router.vuejs.org/guide/advanced/lazy-loading.html)找到有关`vue-router`懒加载的更多信息。

+   你可以在[`quasar.dev/vue-components/inner-loading`](https://quasar.dev/vue-components/inner-loading)找到有关 Quasar 框架的`QInnerLoading`组件的更多信息。
