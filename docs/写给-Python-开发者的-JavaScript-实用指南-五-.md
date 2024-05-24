# 写给 Python 开发者的 JavaScript 实用指南（五）

> 原文：[`zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446`](https://zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四部分 - 与数据库通信

我们 JavaScript 全栈体验的最后部分是数据库层。我们将使用 NoSQL 数据存储，因为它们使用类似 JSON 的文档。

在本节中，我们将涵盖以下章节：

+   第十七章，*安全和密钥*

+   第十八章，*Node.js 和 MongoDB*

+   第十九章，*将所有内容整合在一起*


# 第十七章：安全和密钥

安全性并不是一件简单的事情。在设计应用程序时，从一开始就牢记安全性是很重要的。例如，如果您意外地将您的密钥提交到存储库中，您将不得不进行一些技巧，要么从存储库的历史记录中删除它，要么更有可能的是，您将不得不撤销这些凭据并生成新的凭据。

我们不能让我们的数据库凭据在前端 JavaScript 中对世界可见，但是前端可以与数据库进行交互的方法。第一步是实施适当的安全措施，并了解我们可以将凭据放在哪里，无论是前端还是后端。

本章将涵盖以下主题：

+   身份验证与授权

+   使用 Firebase

+   `.gitignore`和凭据的环境变量

# 技术要求

准备好使用存储库的`Chapter-17`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-17`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-17)。由于我们将使用命令行工具，还需要准备您的终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# 身份验证与授权

在我们开始探讨 JavaScript 安全性时，了解**身份验证**和**授权**之间的重要区别至关重要。简而言之，*身份验证*是一个系统确认和承认您是您所说的人的过程。想象一下去商店买一瓶葡萄酒。您可能会被要求提供证明您达到或超过当地法定饮酒年龄的身份证明。店员通过您的身份证对您进行了*身份验证*，以证明*是的，您就是**您**，因为我，店员，已经将您的面孔与身份证中的照片相匹配*。第二种情况是当您乘坐航空公司的飞机时。当您通过安检时，他们也会出于同样的原因检查您的身份证：您是否是您所说的人？

然而，这两种用例最终都与*授权*有关。授权表示：*我知道你就是你所说的那个人*。现在，你是否被允许做你想做的事情？在我们的葡萄酒例子中，如果你在美国年满 21 岁，或者在世界上大多数其他地方年满 18 岁，你就被*授权*消费酒精饮料。现在，机场的安全人员并不真正关心你的年龄有任何真正的原因；他们只关心你是否是你所说的那个人，以及你是否有一张有效的登机牌。然后你就被*授权*进入机场的安全区并登机。

让我们进一步延伸我们的航空公司例子。在当今旅行安全加强的时代，身份验证和授权过程既不是开始也不是结束于安全人员。如果您在线预订商业航班机票，该过程看起来更像是这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/2cfb4f4c-323b-4ea0-9294-f881a660a623.png)

图 17.1 - 航空公司网站的身份验证和授权

在使用航空公司的网站时，您可能拥有一个帐户并被*授权*继续登录，或者您可能已经登录并被*授权*搜索航班。如果您已经登出，您必须*验证*才能搜索航班。要预订航班，您可能需要一些特定的细节，比如签证，以便被*授权*预订该航班。您可能也被列入旅行到某个国家的观察名单或黑名单，因此您的旅程可能会在开始之前就结束。有很多步骤，但其中许多是在幕后发生的；例如，当您输入您的姓名预订机票时，您可能不知道您的姓名已被搜索对全球记录，以查看您是否被授权飞行。您的签证号码可能已被交叉引用，以查看您是否被授权飞往该国家。

就像你需要经过身份验证和授权才能飞行一样，你的网络应用程序也应该被设计成允许身份验证和授权。考虑一下我们在第十五章中的餐厅查找应用，*将 Node.js 与前端结合使用*，它允许我们在 Firebase 中搜索并保存不同的餐厅：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ef4dd2ef-aa5c-4dcd-b4bc-06f34822670c.png)

图 17.2 - 我们的餐厅应用

如果你还记得，我们在实时数据库部分以*开放权限*启动了我们的 Firebase 应用：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/743e5363-57b0-422c-a1f7-a2170c413910.png)

图 17.3 - 我们的 Firebase 安全规则

显然，这对于生产网站来说*不是一个好主意*。因此，为了缓解这个问题，让我们返回 Firebase 并设置一些身份验证和授权！

# 使用 Firebase

为了方便起见，我在 GitHub 存储库的`Chapter-17`目录中复制了我们的餐厅查找应用。不要忘记在第十五章中的餐厅查找应用中的`.env`文件中包含你自己的环境变量。在我们继续之前，花点时间来设置和运行它。

我们需要做的下一件事是去 Firebase 配置它以使用身份验证。在 Firebase 控制台中，访问身份验证部分并设置一个登录方法；例如，你可以设置 Google 身份验证。这里有一系列你可以使用的方法，所以继续添加一个或多个。

接下来，我们将在实时数据库部分设置我们的规则，如下所示：

```js
{
  "rules": {
    "restaurants": {
      "$uid": {
        ".write": "auth != null && auth.uid == $uid",
        ".read": "auth != null && auth.uid == $uid"
      }
    }
  }
}
```

我们在这里说的是，如果经过身份验证的数据不是`null`，并且用户 ID 与你尝试写入和读取的数据库位置的用户 ID 匹配，那么用户就被允许从你的数据库的`restaurants/<user id>`部分读取和写入。

现在我们的规则已经设置好了，让我们尝试保存一个餐厅：

1.  通过在根目录执行`npm start`来启动应用，并访问`http://localhost:3000`。

1.  搜索餐厅。

1.  尝试保存这个餐厅。

1.  见证一个史诗般的失败。

你应该看到一个类似以下的错误页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/5d501fa1-013e-4b2b-9f37-670e0a5b4579.png)

图 17.4 - 错误，错误！

另外，如果我们进入开发者工具并检查网络选项卡的 WS 选项卡（**WS**代表**WebSockets**，这是 Firebase 通信的方式），我们可能会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/99c9094a-e1c5-423b-afe7-d2e1453c136d.png)

图 17.5 - WebSockets 通信检查器

太棒了！我们现在证明了我们的 Firebase 规则起作用，并且不允许保存到`/restaurants/<user_id>`，因为我们没有经过身份验证。是时候设置这个了。

我们要做的第一件事是稍微改变我们的`App.js`脚本。在编写 React 时有一些不同的约定，我们将继续使用基于类的方法。我们的`App.js`脚本将如下所示：

```js
import React from 'react'
import cookie from "react-cookies"

import Finder from './components/finder/Finder'
import SignIn from './components/signIn/SignIn'

import './App.css'

export default class App extends React.Component {
 constructor() {
   super()

   this.state = {
     user: cookie.load("username")
   }

   this.setUser = this.setUser.bind(this)
 }

 setUser(user) {
   this.setState({
     user: user
   })

   cookie.save("username", user)
 }

 render() {
   const { user } = this.state
   return (
     <div className="App">
       { (user) ? <Finder user={user} /> : <SignIn setUser={this.setUser}
     /> }
     </div>
   )
 }
}
```

首先要注意的是，我们包含了一个新的`npm`模块：`react-cookies`。虽然从浏览器中读取 cookie 很容易，但有一些模块可以让它变得更容易一点。当我们检索用户的 ID 时，我们将把它存储在一个 cookie 中，这样浏览器就记住了用户已经经过身份验证。

为什么我们需要使用 cookie？如果你还记得，网络本质上是*无状态*的，所以 cookie 是一种从应用程序的一个部分传递信息到另一个部分，从一个会话到另一个会话的手段。这是一个基本的例子，但重要的是要记住不要在 cookie 中存储任何敏感信息；在身份验证工作流程中，令牌或用户名可能是你想要放入其中的最多的信息。

我们还引入了一个新组件`SignIn`，如果用户变量不存在，也就是说，如果用户没有登录，它会有条件地渲染。让我们来看看这个组件：

```js
import React from 'react'
import { Button } from 'react-bootstrap'
import * as firebase from 'firebase'

const provider = new firebase.auth.GoogleAuthProvider()

export default class SignIn extends React.Component {
 constructor() {
   super()

   this.login = this.login.bind(this)
 }

 login() {
   const self = this

   firebase.auth().signInWithPopup(provider).then(function (result) {
     // This gives you a Google Access Token. You can use it to access the
     // Google API.
     var token = result.credential.accessToken;
     // The signed-in user info.
     self.props.setUser(result.user);
     // ...
   }).catch(function (error) {
     // Handle Errors here.
     var errorCode = error.code;
     var errorMessage = error.message;
     // The email of the user's account used.
     var email = error.email;
     // The firebase.auth.AuthCredential type that was used.
     var credential = error.credential;
     // ...
   });
 }
 render() {
   return <Button onClick={this.login}>Sign In</Button>
 }
}
```

这里有两件事需要注意：

+   我们正在使用`GoogleAuthProvider`来进行我们的`SignIn`机制。如果你在设置 Firebase 时选择了不同的认证方法，这个提供者可能会有所不同，但代码的其余部分应该是相同或相似的。

+   `signInWithPopup`方法几乎直接从 Firebase 文档中复制过来。这里唯一的改变是创建`self`变量，这样我们就可以在另一个方法中保持对`this`的作用域。

当这个被渲染时，如果用户还没有登录，它将是一个简单的按钮，上面写着**登录**。它将激活一个弹出窗口，用你的 Google 账号登录，然后像以前一样继续。不是很可怕，对吧？

接下来，我们需要处理我们的用户。你是否注意到在`App.js`中，我们将`user`传递给了 Finder？这将使在我们的基本应用程序中轻松地传递一个对我们用户的引用，就像在`Finder.jsx`中一样：

```js
getRestaurants() {
   const { user } = this.props

   Database.ref(`/restaurants/${user.uid}`).on('value', (snapshot) => {
     const restaurants = []

     const data = snapshot.val()

     for(let restaurant in data) {
       restaurants.push(data[restaurant])
     }
     this.setState({
       restaurants: restaurants
     })
   })
 }
```

这是在这种情况下唯一改变的方法，如果你仔细看，改变是从`this.props`中解构`user`并在我们的数据库引用中使用它。如果你记得我们的安全规则，我们不得不稍微改变我们的数据库结构，以适应我们认证用户的简单*授权*：

```js
{
  "rules": {
    "restaurants": {
      "$uid": {
        ".write": "auth != null && auth.uid == $uid",
        ".read": "auth != null && auth.uid == $uid"
      }
    }
  }
}
```

我们在安全规则中所说的是，格式为`restaurants.$uid`的节点是我们将存储每个单独用户的餐厅的地方。我们的 Firebase 结构现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/3d6e776b-1525-41b9-8c24-00ab97d6d99e.png)

图 17.6 - 我们的 Firebase 结构可能是这样的一个例子

在这个结构中，我们看到`restaurants`内部的`TT8PYnjX6FP1YikssoHnINIpukZ2`节点。那是认证用户的**uid**（**用户 ID**），在那个节点内，我们找到用户保存的餐厅。

这个数据库结构很简单，但提供了简单的授权。我们的规则规定“给用户 TT8 权限查看和修改他们自己节点内的数据，仅此而已。”

我们之前已经讨论了我们的`.env`变量，所以让我们更深入地看一下它们。我们将把我们的应用部署到 Heroku，创建一个公开可见的网站。

# .gitignore 和凭据的环境变量

由于我们一直在使用`.env`文件，我特意指出这些文件*绝对不应该*提交到仓库中。事实上，一个好的做法是在创建任何敏感文件之前向你的`.gitignore`文件添加一个条目，以确保你永远不会意外提交你的凭据。即使你后来从仓库中删除它，文件历史仍然保留，你将不得不使这些密钥失效（或*循环使用*），以便它们不会在历史中暴露出来。

虽然 Git 的完整部分超出了我们在这里的工作范围，但让我们看一个`.gitignore`文件的例子：

```js
# See https://help.github.com/articles/ignoring-files/ for more about ignoring files.

# dependencies
/node_modules
/.pnp
.pnp.js

# testing
/coverage

# production
/build

# misc
.DS_Store
.env*

npm-debug.log*
yarn-debug.log*
yarn-error.log*
```

其中有几个是由`create-react-app`脚手架创建的条目。特别注意`.env*`。星号（或*星号*，或*通配符*）是一个正则表达式通配符，指定任何以`.env`开头的文件都被忽略。你可以有`.env.prod`，它也会被忽略。**一定要忽略你的凭据文件！**

我还喜欢将`/node_modules`改为`*node_modules*`，以防你有自己的子目录和它们自己的 node 模块。

在`.env`文件中存储变量很方便，但也可以创建内存中的环境变量。为了演示这个功能，我们将把项目部署到 Heroku，一个云应用平台。让我们开始吧：

1.  在[`heroku.com`](https://heroku.com)创建一个新账户。

1.  根据提供的文档安装 Heroku **命令行界面**（**CLI**）。一定要遵循登录说明。

1.  在餐厅查找器目录中初始化一个新的仓库：`git init`。

1.  执行`heroku create --ssh-git`。它会提供你的 Heroku 端点的 Git URL，以及`https://` URL。继续访问 HTTPS URL。你应该会看到一个欢迎消息：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/02fa5a98-733f-46d6-a767-9c4d892a0684.png)

图 17.7 - 哦耶！我们有一个空白的 Heroku 应用程序！

我们现在可以继续组织我们应用的逻辑。

## 重新组织我们的应用

接下来，我们要做的与第十五章中的*将 Node.js 与前端结合*不同的事情，就是稍微重新组织我们的文件。这并不是完全必要的，但在部署生产级别的代码时，它提供了前端和后端之间的一个很好的逻辑区分。我们之前的应用和我们要在这里创建的应用之间还有一个语义上的区别：我们不会提供一个正在运行的开发 React 应用，而是一个静态的生产版本。

如果你还记得，我们之前的餐厅结构是这样的：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/744d7cfd-6930-474e-b548-d96918240d23.png)

图 17.8 – 代理与应用的区别，解释。

我们之前实际上是使用 React 应用作为 Web 服务器，并通过它代理到 Express 后端，以便使用 Yelp API。然而，现在我们将使用 Express 作为主要的 Web 服务器，并提供一个 React 应用的生产级别构建。

我们之前的应用逻辑如下：

```js
IF NOT a React page,
 Serve from proxy
ELSE
 Serve React
```

我们要颠倒这个逻辑，并声明以下内容：

```js
IF NOT an Express route,
 Serve from static build
ELSE
 Serve API
```

下面是要做的事情：

1.  创建一个新的`client`目录。

1.  如果你还有`yarn.lock`文件，请删除它。我们将专注于使用 NPM 而不是`yarn`。

1.  将所有文件移动到 client 目录中，除了 API 目录。

1.  接下来，我们要在根目录下创建一个新的`package.json`：`npm install dotenv express yelp-fusion`。

如果你注意到了，我们还安装了 Express，这是之前没有做的。我们将使用它来更轻松地路由我们的请求。

在我们的`package.json`中，在*根*级别，添加这些脚本：

```js
"postinstall": "cd client && npm install && npm run build",
"start": "node api/api.js"
```

由于我们正在处理 Heroku，我们还可以从`package.json`中删除`proxy`行，因为一切都将在同一服务器上运行，不需要代理。现在，我们的`package.json`中的`postinstall`行怎么样？我们要做的是创建我们应用的*生产就绪*版本。`create-react-app`通过`npm run build`脚本免费为我们提供了这个功能。当我们部署到 Heroku 时，它将运行`npm install`，然后运行`postinstall`，以创建我们的 React 应用的生产版本。

现在我们准备向我们的项目添加一个新的元数据，以便 Heroku 可以提供我们的应用：**Procfile**。

Procfile 会告诉 Heroku 如何处理我们的代码。你的 Procfile 会是这样的：

```js
web: npm start
```

实质上，它所做的就是告诉 Heroku 从哪里开始运行程序：运行`npm start`。

我们的目录结构现在应该是这样的：

```js
.
├── Procfile
├── api
│   └── api.js
├── client
│   ├── README.md
│   ├── package-lock.json
│   ├── package.json
│   ├── public
│   └── src
├── package-lock.json
└── package.json
```

我们接下来的重要步骤是修改我们的`api.js`文件，如下所示：

```js
const yelp = require('yelp-fusion');
const express = require('express');
const path = require('path');

const app = express();

require('dotenv').config();

const PORT = process.env.PORT || 3000;

const client = yelp.client(process.env.YELP_API_Key);
```

到目前为止，这看起来与之前相似，只是增加了 Express。但是看看接下来的一行：

```js
app.use(express.static(path.join(__dirname, '../client/build')));
```

啊哈！这是我们的秘密酱：这行表示使用`client/build`目录作为静态资源，而不是 Node.js 代码。

继续，我们正在定义我们的 Express 路由来处理格式为`/search`的请求：

```js
app.get('/search', (req, res) => {
 const { lat, lng, value } = req.query

 client.search({
   term: value,
   latitude: lat,
   longitude: lng,
   categories: 'Restaurants'
 }).then(response => {
   res.statusCode = 200;
   res.setHeader('Content-Type', 'application/json');
   res.setHeader('Access-Control-Allow-Origin', '*');

   res.write(response.body);
   res.end();
 })
   .catch(e => {
     console.error('error', e)
   })
});
```

对于我们秘密酱的下一部分，如果路由*不*匹配`/search`，将其发送到静态的 React 构建：

```js
app.get('*', (req, res) => {
 res.sendFile(path.join(__dirname + '../client/build/index.html'));
});

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
```

将所有内容添加到你的 Git 仓库：`git add`。现在你可以执行`git status`来确保你的`.env`文件没有被*包含*。

接下来，提交你的代码：`git commit -m "Initial commit`。如果你需要关于 Git 的帮助，Heroku 文档提供了参考资料。接下来，部署到 Heroku：`git push heroku master`。这会花一些时间，因为 Heroku 不仅会使用 Git 部署你的代码，还会创建你的代码的生产版本。

访问构建脚本提供的 URL，希望你会看到一个很棒的错误消息：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/43161e56-8693-4b56-806a-6bb334d483a3.png)

图 17.9 – 哦不！一个错误！实际上这不是坏事！

太好了！这告诉我们的是应用程序正在运行，但我们缺少一些重要的部分：我们的环境变量。对您`.env`文件中的每个条目执行`heroku config:set <entry>`（根目录和`client`中）。

当您刷新页面时，您将看到“登录”按钮。但是，如果您单击它，将不会发生任何事情。它可能会在一秒钟内弹出一个弹出窗口，但不会弹出身份验证窗口。我们需要返回到 Firebase 控制台，将我们的 Firebase URL 添加为*已授权*URL。

在 Firebase 控制台中，转到身份验证部分，并将您的 Heroku URL 输入到已授权域部分。返回到您的 Heroku 应用程序，刷新，然后瞧！身份验证面板可以正常工作。如果您转到 Saved！，甚至会看到您保存的餐馆。

这并不难！Heroku 存储环境变量的方法与我们的`.env`文件并没有太大的不同，但它可以在不需要太多工作的情况下为我们处理。但是，我们还需要配置最后一个部分：我们的搜索*不起作用*。如果您查看控制台错误消息，您应该会看到一条说明拒绝连接到`localhost:3000`的提示。我们需要采取最后一步来将我们的代码从使用`localhost`抽象出来。

在`src/components/search/Search.jsx`中，您可能会认出这种方法：

```js
search(event) {
   const { lng, lat, val } = this.state

   fetch(`http://localhost:3000/businesses/search?value=${val}&lat=${lat}&lng=${lng}`)
     .then(data => data.json())
     .then(data => this.handleSearchResults(data))
 }
```

好了！我们已经将我们的`fetch`调用硬编码为`localhost`和我们的代理路径。让我们将其更改为以下内容：

```js
fetch(`/search?value=${val}&lat=${lat}&lng=${lng}`)
```

提交您的更改并再次推送到 Heroku。在开发过程中，您还可以使用`heroku local web`来生成一个浏览器并测试您的更改，而无需提交和部署。

幸运的话，您应该拥有一个完全功能的前后端应用程序，并且凭据已经安全存储在 Heroku 环境变量中！恭喜！

# 总结

在本章中，我们学习了身份验证、授权以及两者之间的区别。请记住，通常仅执行其中一个是不够的：大多数需要凭据的应用程序需要两者的组合。

Firebase 是一个有用的云存储数据库，您可以将其与现有的登录系统一起使用，不仅可以作为开发资源，还可以扩展到生产级别的使用。最后，请记住这些要点：因为 JavaScript 是客户端的，我们必须以不同的方式保护敏感信息，而不是纯粹的后端应用程序：

1.  进行身份验证和授权以确定谁可以使用哪些资源。

1.  将我们的敏感数据与我们的公共数据分开。

1.  **永远不要将密钥和敏感数据提交到存储库中！**

我们每个人都有责任成为良好的数字公民，但也存在不良行为者。保护自己和您的代码！

在下一章中，我们将把 Node.js 和 MongoDB 联系在一起，以持久化我们的数据。我们将重新审视我们的星际飞船游戏，但这次将使用持久存储。


# 第十八章：Node.js 和 MongoDB

您可能已经听说过**MEAN**堆栈：MongoDB、Express、Angular 和 Node.js，或者**MERN**堆栈：MongoDB、Express、React 和 Node.js。我们尚未讨论的缺失部分是 MongoDB。让我们探讨一下这个 NoSQL 数据库如何可以直接从 Express 中使用。我们将构建我们在第十三章中开始的星际飞船游戏的下一个迭代，*使用 Express*，只是这次使用 MongoDB 并且加入了一些测试！

我们将在本章中涵盖以下主题：

+   使用 MongoDB

+   使用 Jest 进行测试

+   存储和检索数据

+   将 API 连接在一起

# 技术要求

准备好使用存储库的`chapter-18`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-18`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-18)。由于我们将使用命令行工具，还要确保您的终端或命令行 shell 可用。我们需要一个现代浏览器和一个本地代码编辑器。

# 使用 MongoDB

MongoDB 的基本前提是，它与其他类型的结构化键/值对数据库不同的地方在于它是*无模式*的：您可以插入无结构数据的任意**文档**，而不必担心数据库中的另一个条目是什么样子。在 NoSQL 术语中，文档对我们来说已经很熟悉了：一个 JavaScript 对象！

这是一个文件：

```js
{
 "first_name": "Sonyl",
 "last_name": "Nagale",
 "role": "author",
 "mood": "accomplished"
}
```

我们可以看到它是一个基本的 JavaScript 对象；更具体地说，它是 JSON，这意味着它也可以支持嵌套数据。这是一个例子：

```js
{
 "first_name": "Sonyl",
 "last_name": "Nagale",
 "role": "author",
 "mood": "accomplished",
 "tasks": {
  "write": {
   "status": "incomplete"
  },
  "cook": {
   "meal": "carne asada"
  },
  "read": {
   "book": "Le Petit Prince"
  },
  "sleep": {
   "time": "8"
  }
 },
 "favorite_foods": {
  "mexican": ["enchiladas", "burritos", "quesadillas"],
  "indian": ["saag paneer", "murgh makhani", "kulfi"]
 }
}
```

那么这与 MySQL 有什么不同呢？考虑一下这个 MySQL 模式：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/078e1d97-f520-4a0e-bcfb-bd3bbbc984f9.png)

图 18.1 - 一个 MySQL 数据库表结构的示例

如果您熟悉 SQL 数据库，您会知道数据库表中的每个字段类型必须是特定类型的。在从 SQL 类型数据库检索时，我们使用**结构化查询语言**（**SQL**）。正如我们的表结构化一样，我们的查询也是结构化的。

在使用数据库表之前，我们需要创建数据库表，在 SQL 中，建议不要在创建后更改其结构，而不进行一些额外的清理工作。以下是我们将创建我们之前的表的方法：

```js
CREATE TABLE `admins` (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `admin_role_id` int(11) DEFAULT NULL,
 `first_name` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
 `last_name` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
 `username` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
 `email` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
 `phone` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
 `password` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
 `avatar` varchar(100) COLLATE utf8_unicode_ci DEFAULT NULL,
 `admin_role` enum('admin','sub_admin') COLLATE utf8_unicode_ci DEFAULT
  NULL,
 `status` enum('active','inactive','deleted') COLLATE utf8_unicode_ci 
  DEFAULT NULL,
 `last_login` datetime DEFAULT NULL,
 `secret_key` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
 `last_login_ip` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
 `sidebar_status` enum('open','close') COLLATE utf8_unicode_ci DEFAULT
  'open',
 `created` datetime DEFAULT NULL,
 `modified` datetime DEFAULT NULL,
 PRIMARY KEY (`id`),
 KEY `email` (`email`),
 KEY `password` (`password`),
 KEY `admin_role` (`admin_role`),
 KEY `status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
```

现在，对于 MongoDB，我们*不会*构建具有预定义数据类型和长度的表。相反，我们将将 JSON 块插入到我们的数据库中作为**文档**。MongoDB 的理念与我们在第十七章中使用 Firebase 时非常相似，*安全和密钥*，插入 JSON 并对其进行查询，即使有多个嵌套的 JSON 对象，而不是存储、交叉连接和查询多个表。

假设我们有以下两个文档：

```js
{
  "first_name": "Sonyl",
  "last_name": "Nagale",
  "admin_role": "admin",
  "status": "active"
},
{
  "first_name": "Jean-Luc",
  "last_name": "Picard",
  "admin_role": "admin",
  "status": "inactive"
}
```

我们如何将它们插入到我们的数据库中？这将使用 MySQL：

```js
INSERT INTO
    admins(first_name, last_name, admin_role, status)
  VALUES
    ('Sonyl', 'Nagale', 'admin', 'active'),
    ('Jean-Luc', 'Picard', 'admin', 'inactive')
```

使用 MongoDB 的答案实际上比 SQL 要容易得多，因为我们可以轻松地放置数组，而不必担心数据类型或数据排序！我们可以只是把文档塞进去，而不必担心其他任何事情，这更有可能是我们从前端接收到的方式：

```js
db.admins.insertMany([
{
  "first_name": "Sonyl",
  "last_name": "Nagale",
  "admin_role": "admin",
  "status": "active"
},
{
  "first_name": "Jean-Luc",
  "last_name": "Picard",
  "admin_role": "admin",
  "status": "inactive"
}]
)
```

例如，要从前述的`admins`表中获取所有活动管理员，我们在 MySQL 中会写出类似于这样的内容：

```js
SELECT
  first_name, last_name 
FROM 
  admins 
WHERE 
  admin_role = "admin" 
AND 
  status = "active"
```

`first_name`和`last_name`字段被预定义为`VARCHAR`类型（可变字符），最大长度为 50 个字符。`admin_role`和`status`是`ENUM`（枚举类型），具有预定义的可能值（就像站点上的下拉选择列表）。然而，这是我们如何在 MongoDB 中构造我们的查询：

```js
db.admins.find({ status: 'active', admin_role: 'admin'}, { first_name: 1, last_name: 1})
```

我们在这里不会深入研究 MongoDB 的语法，因为这有点超出了本书的范围，我们只会使用简单的查询。话虽如此，在我们开始之前，我们应该了解更多。

以下是我们在制作游戏时将使用的 mongo 命令列表：

+   `find`

+   查找一个

+   `insertOne`

+   `updateOne`

+   `updateMany`

相当容易管理，对吧？我们可以将许多 MongoDB 命令分解为以下一般的句法结构：

`<dbHandle>.<collectionName>.<method>(query, projection)`

在这里，`query` 和 `projection` 是指导我们使用 MongoDB 的对象。例如，在我们前面的语句中，`{ status: 'active', admin_role: 'admin' }` 是我们的查询，指定我们希望这些字段等于这些值。这个例子中的 projection 指定了我们想要返回的内容。

让我们深入我们的项目。

## 入门

我们可以做的第一件事是从 [`MongoDBdb.com`](https://mongodb.com) 下载 MongoDB Community Server。当你安装好后，从我们的 GitHub 仓库中导航到 `chapter-18/starships` 目录，让我们尝试启动它：

```js
npm install
mkdir -p data/MongoDB
mongod --dbpath data/MongoDB
```

如果一切安装正确，你应该会看到一大堆通知消息，最后一条消息类似于 `[initandlisten] waiting for connections on port 27017`。如果一切不如预期，花些时间确保你的安装工作正常。一个有用的工具是 MongoDB Compass，一个连接到 MongoDB 的 GUI 工具。确保检查权限，并且适当的端口是打开的，因为我们将使用端口 `27017`（MongoDB 的默认端口）进行连接。

本章将是一个实验，将我们的星际飞船游戏提升到一个新的水平。这是我们将要构建的内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/d1e3f192-dd3e-4e85-bfab-0aa9736880b6.png)

图 18.2 – 创建我们的舰队

然后，我们将把它连接到 MongoDB，并在这个界面上实际执行游戏：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/a8cc72ad-3d1c-4b9a-8413-94d1bd2be86b.png)

图 18.3 – 攻击敌人！

我们将使用简化版本的 MERN，使用原生 JavaScript 而不是 React，依赖于 Express 以一种比 React 更少受控的方式呈现我们的 HTML。也许 *JEMN stack* 是一个好的名字？

在我们开始编写实际代码之前，让我们检查项目的设置并开始测试！

## 使用 Jest 进行测试

在 `starships` 目录中，你会找到完成的游戏。让我们来剖析一下。

这是目录列表：

```js
.
├── README.md
├── app.js
├── bin
│   └── www
├── controllers
│   └── ships.js
├── jest-MongoDBdb-config.js
├── jest.config.js
├── models
│   ├── MongoDB.js
│   ├── setup.js
│   └── ships.js
├── package-lock.json
├── package.json
├── public
│   ├── images
│   │   └── bg.jpg
│   ├── javascripts
│   │   ├── index.js
│   │   └── play.js
│   └── stylesheets
│       ├── micromodal.css
│       └── style.css
├── routes
│   ├── enemy.js
│   ├── index.js
│   ├── play.js
│   ├── ships.js
│   └── users.js
├── tests
│   ├── setup.model.test.js
│   ├── ships.controller.test.js
│   └── ships.model.test.js
└── views
    ├── enemy.hbs
    ├── error.hbs
    ├── index.hbs
    ├── layout.hbs
    └── play.hbs
```

我们将采取一种与我们其他项目有些不同的方法，在这里实现一个非常轻量级的**测试驱动开发**（**TDD**）循环。TDD 是在编写能够工作的代码之前编写失败的测试的实践。虽然我们没有实现真正的 TDD，但使用测试来引导我们的思维过程是我们将要做的事情。

我们将使用 Jest 作为我们的测试框架。让我们来看一下步骤：

1.  在 `tests` 目录中，创建一个名为 `test.test.js` 的新文件。第一个 `test` 是我们测试套件的名称，以 `.test.js` 结尾的约定表示这是一个要执行的测试套件。在文件中，创建这个测试脚本：

```js
describe('test', () => {
 it('should return true', () => {
   expect(1).toEqual(1)
 });
});
```

1.  使用 `node_modules/.bin/jest test.test.js` 运行测试（确保你已经运行了 `npm install`！）。你将会得到类似以下的测试套件输出：

```js
$ node_modules/.bin/jest test.test.js
 PASS  tests/test.test.js
  test
    ✓ should return true (2ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        0.711s, estimated 1s
Ran all test suites matching /test.test.js/i.
```

我们刚刚编写了我们的第一个测试套件！它简单地说“我期望 1 等于 1。如果是，通过测试。如果不是，测试失败。”对于五行代码来说，相当强大，对吧？好吧，也许不是，但这将为我们的所有其他测试提供支架。

1.  让我们来看一下 MongoDB 模型：`models/mongo.js`*:* 

```js
const MongoClient = require('mongodb').MongoClient;
const client = new MongoClient("mongodb://127.0.0.1:27017", { useNewUrlParser: true, useUnifiedTopology: true });

let db;
```

1.  到目前为止，我们只是在设置我们的 MongoDB 连接。确保你现在仍然有你的 MongoDB 连接运行着：

```js
const connectDB = async (test = '') => {
 if (db) {
   return db;
 }

 try {
   await client.connect();
   db = client.db(`starships${test}`);
 } catch (err) {
   console.error(err);
 }

 return db;
}
```

1.  与所有良好的数据库连接代码一样，我们在一个 *try/catch* 块中执行我们的代码，以确保我们的连接正确建立：

```js
const getDB = () => db

const disconnectDB = () => client.close()

module.exports = { connectDB, getDB, disconnectDB }
```

预览：我们将在测试和模型中使用这个 `MongoDB.js` 文件。`module.exports` 行指定了从这个文件导出并暴露给我们程序的其他部分的函数。我们将在整个程序中一贯使用这个导出指令：当我们想要暴露一个方法时，我们会使用一个导出。

1.  返回到 `test.test.js` 并在文件开头包含我们的 MongoDB 模型：

```js
const MongoDB = require('../models/mongo')
```

1.  现在，让我们在我们的测试套件中变得更加花哨一点。在我们的`describe`方法*内*增加以下代码：

```js
let db

beforeAll(async () => {
   db = await MongoDB.connectDB('test')
})

afterAll(async (done) => {
   await db.collection('names').deleteMany({})
   await MongoDB.disconnectDB()
   done()
})
```

并在我们简单的测试之后添加以下情况：

```js
it('should find names and return true', async () => {
   const names = await db.collection("names").find().toArray()
   expect(names.length).toBeGreaterThan(0)
})
```

然后使用与之前相同的命令运行它：`node_modules/.bin/jest test.test.js`。

这里发生了什么？首先，在我们的测试套件中的每个单独的测试之前，我们正在指定按照我们在 MongoDB 模型中编写的方法连接到数据库。在一切都完成之后，拆除数据库并断开连接。

当我们运行它时会发生什么？一个史诗般的失败！

```js
$ node_modules/.bin/jest test.test.js
 FAIL  tests/test.test.js
  test
    ✓ should return true (2ms)
    ✕ should find names and return true (9ms)

  ● test > should find names and return true

    expect(received).toBeGreaterThan(expected)

    Expected: > 0
    Received:   0

      20 |   it('should find names and return true', async () => {
      21 |     const names = await db.collection("names"
                ).find().toArray()
    > 22 |     expect(names.length).toBeGreaterThan(0)
         |                          ^
      23 |   })
      24 | });

      at Object.<anonymous> (tests/test.test.js:22:26)

Test Suites: 1 failed, 1 total
Tests:       1 failed, 1 passed, 2 total
Snapshots:   0 total
Time:        1.622s, estimated 2s
Ran all test suites matching /test.test.js/i.
```

我们应该期望出现错误，因为我们还没有向名为`names`（或任何其他数据）的集合中*插入*任何信息！欢迎来到 TDD：我们编写了一个在编写代码之前就失败的测试。

显然，我们在这个过程中的下一步是实际插入一些数据！让我们这样做。

# 存储和检索数据

让我们使用我编写的一个测试套件来确保我们的 MongoDB 连接更加健壮，并包括将数据插入数据库，然后测试以确保它存在：

1.  检查`test/setup.model.test.js`：

```js
const MongoDB = require('../models/mongo')
const insertRandomNames = require('../models/setup')

describe('insert', () => {
 let db

 beforeAll(async () => {
   db = await MongoDB.connectDB('test')
 })

 afterAll(async (done) => {
   await db.collection('names').deleteMany({})
   await MongoDB.disconnectDB()
   done()
 })

 it('should insert the random names', async () => {
   await insertRandomNames()

   const names = await db.collection("names").find().toArray()
   expect(names.length).toBeGreaterThan(0)
 })

})
```

1.  如果我们运行`node_modules/.bin/jest setup`，我们会看到成功，因为我们的设置模型中存在`insertRandomNames()`方法。所以让我们来看看我们的设置模型（`models/setups.js`）并看看它是如何填充数据库的：

```js
const fs = require('fs')
const MongoDB = require('./mongo')

let db

const setup = async () => {
 db = await MongoDB.connectDB()
}

const insertRandomNames = async () => {
 await setup()

 const names = JSON.parse(fs.readFileSync(`${__dirname}/../
  data/starship-names.json`)).names

 const result = await db.collection("names").updateOne({ key: 
  "names" }, { $set: { names: names } }, { upsert: true })

 return result
}

module.exports = insertRandomNames
```

1.  还不错！我们有一个导出的方法，根据我提供的“随机”星际飞船名称的 JSON 文件将名称插入到数据库中。文件被读取，然后按以下方式放入数据库中：

```js
db.collection("names").updateOne({ key: "names" }, { $set: { names: names } }, { upsert: true })
```

由于我们并没有深入了解 MongoDB 本身的细节，可以说这行代码的意思是“在`names`集合中（即使它还不存在），将`names`键设置为相等的 JSON。根据需要更新或插入”。

现在，我们可以用我提供的“随机”星际飞船名称的 JSON 文件来填充我们的数据库。执行`npm run install-data`。

到目前为止，一切都很好！在这个项目中有很多文件，所以我们不会遍历*所有*文件；让我们检查一个代表性的样本。

## 模型，视图和控制器

**模型-视图-控制器**（**MVC**）范式是我们在 Express 中使用的。虽然在 Express 中并不是真正必要的，但我发现逻辑上的关注点分离比单一类型的不可区分的文件更有用且更容易使用。在我们走得太远之前，我会提到 MVC 可能被认为是一种过时的模式，因为它确实在层之间创建了一些额外的依赖关系。话虽如此，将逻辑分离为离散的角色的架构范式背后的思想在 MVC 中是合理的。你可能会听到**MV***的使用，这基本上应该被理解为“模型，视图和将它们绑定在一起的任何东西”。在某些框架中，这些天 MV*更受欢迎。

MVC 结构将程序的逻辑分为三个部分：

1.  **模型**处理数据交互。

1.  **视图**处理表示层。

1.  **控制器**处理数据操作，并充当模型和视图之间的粘合剂。

这是设计模式的一个可视化表示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/6dc14b9e-b9c3-44da-bcc4-8f344c7fdb12.png)

图 18.4 - MVC 范例的生命周期

关于这种关注点分离的更重要的部分之一是，视图层和控制器层*永远*不应直接与数据存储交互；这一荣誉是为模型保留的。

现在让我们来看一个视图：

*views/index.hbs*

```js
<h1>Starship Fleet</h1>

<hr />

<h2>Fleet Status</h2>
{{#if ships.length}}
 <table class="table">
   <tr>
     <th>Name</th>
     <th>Registry</th>
     <th>Top Speed</th>
     <th>Shield Strength</th>
     <th>Phaser Power</th>
     <th>Hull Damage</th>
     <th>Torpedo Complement</th>
     <th></th>
   </tr>
 {{#each ships}}
   <tr data-ship="{{this.registry}}">
     <td>{{this.name}}</td>
     <td>{{this.registry}}</td>
     <td>{{this.speed}}</td>
     <td>{{this.shields}}</td>
     <td>{{this.phasers}}</td>
     <td>{{this.hull}}</td>
     <td>{{this.torpedoes}}</td>
     <td><a class="btn btn-primary scuttle">Scuttle Ship</a></td>
   </tr>
 {{/each}}
 </table>
{{else}}
 <p>The fleet is empty. Create some ships below.</p>
{{/if}}
```

Express 控制我们的视图，我们使用 Handlebars 来处理我们的模板逻辑和循环。虽然语法简单，但 Handlebars 功能强大，可以极大地简化我们的生活。在这种情况下，我们正在测试并循环遍历`ships`变量，以创建我们拥有的`ships`的表格，或者发送一条消息说舰队是空的。我们的视图如何获得`ships`？它是通过我们的**控制器**通过我们的**路由**提供给视图的。对于这部分，它看起来是这样的：

*routes/index.js*

```js
var express = require('express');
var router = express.Router();
const ShipsController = require('../controllers/ships');

/* GET home page. */
router.get('/', async (req, res, next) => {
 res.render('index', { ships: await ShipsController.getFleet() });
});

module.exports = router;
```

为什么我们在这里使用`var`而不是`const`或`let`？为什么要使用分号？答案是：在撰写本文时，Express 脚手架工具仍然使用`var`和分号。标准化始终是最佳实践，但在这个例子中，我想引起注意。随时根据新的语法进行标准化。

现在是`getFleet`方法：

*controllers/ships.js*

```js
exports.getFleet = async (enemy = false) => {
 return await ShipsModel.getFleet(enemy)
}
```

因为这是一个简单的例子，我们的控制器除了从模型获取信息外并没有做太多事情，模型查询 MongoDB。让我们来看看：

*models/ships.js*

```js
exports.getFleet = async (enemy) => {
 await setup()

 const fleet = await db.collection((!enemy) ? "fleet" :
 "enemy").find().toArray();
 return fleet.sort((a, b) => (a.name > b.name) ? 1 : -1)
}
```

设置函数规定了与 MongoDB 的连接（注意异步/等待设置！），我们的舰队要么来自敌人，要么来自我们的舰队集合。`return`行包含了一个方便的方法，按字母顺序对舰队进行排序。

在这个例子中，我们将保持控制器相当简单，并依靠模型来完成大部分工作。这是一个风格上的决定，尽管选择应用程序的一边来完成大部分工作是很好的。

现在是时候从头到尾查看程序了。

# 将 API 连接在一起

为了进一步了解游戏玩法，我们将逐步介绍从船只发射鱼雷的步骤：

1.  在`public/javascripts/play.js`中找到前端 JavaScript：

```js
document.querySelectorAll('.fire').forEach((el) => {
 el.addEventListener('click', (e) => {
   const weapon = (e.target.classList.value.indexOf('fire-torpedo') 
   > 0) ? "torpedo" : "phasers"
   const target = e.target.parentNode.getElementsByTagName
   ('select')[0].value
```

1.  在我们的界面上为`fire`按钮创建了一个点击处理程序，并确定了我们的武器和目标船只：

```js
fetch(
`/play/fire?  attacker=${e.target.closest('td').dataset.attacker}&target=${target}&weapon=${weapon}`)
.then(response => response.json())
.then(data => {
```

这一行可能需要一些解释。我们正在从我们的 JavaScript 向我们的 Node 应用程序进行 AJAX 调用，带有特定的查询字符串参数：`attacker`，`target`和`weapon`。我们也期望从我们的应用程序返回 JSON。

1.  记住，我们的反引号允许我们*组合*一个带有`${ }`中变量的字符串：

```js
const { registry, name, shields, torpedoes, hull, scuttled } = data.target
```

1.  我们使用**对象解构**从`data.target`中提取每个信息片段。这比逐个定义它们或甚至使用循环更有效，对吧？

```js
if (scuttled) {
       document.querySelector(`[data-ship=${registry}]`).remove()
       document.querySelectorAll(`option[value=${registry}]`).
        forEach(el => el.remove())

       const titleNode = document.querySelector("#modal-1-title")

       if (data.fleet.length === 0) {
         titleNode.innerHTML = "Your fleet has been destroyed!"
       } else if (data.enemyFleet.length === 0) {
         titleNode.innerHTML = "You've destroyed the Borg!"
       } else {
         titleNode.innerHTML = `${name} destroyed!`
       }

       MicroModal.show('modal-1')
       return
     }
```

1.  如果`scuttled`为`true`，我们的目标船只已被摧毁，因此让我们向用户传达这一点。无论哪种情况，我们都将编辑我们船只的值：

```js
     const targetShip = document.querySelector(`[data-
      ship=${registry}]`)

     targetShip.querySelector('.shields').innerHTML = shields
     targetShip.querySelector('.torpedoes').innerHTML = torpedoes
     targetShip.querySelector('.hull').innerHTML = hull

   })
 })
})
```

这就是前端代码。如果我们查看我们的`app.js`文件，我们可以看到我们对`/play`的 AJAX 调用转到`playRouter`，从`app.use`语句。因此，我们的下一站是路由器：

*routes/play.js*

```js
const express = require('express');
const router = express.Router();
const ShipsController = require('../controllers/ships');

router.get('/', async (req, res, next) => {
 res.render('play', { fleet: await ShipsController.getFleet(), enemyFleet:
  await ShipsController.getFleet(true) });
});

router.get('/fire', async (req, res, next) => {
 res.json(await ShipsController.fire(req.query.attacker, req.query.target, 
  req.query.weapon));
});

module.exports = router;
```

由于我们的 URL 是从`/play/fire`构建的，我们知道第二个`router.get`语句处理我们的请求。继续到控制器及其`fire`方法：

*controllers/ships.js*

```js
exports.fire = async (ship1, ship2, weapon) => {
 let target = await ShipsModel.getShip(ship2)
 const source = await ShipsModel.getShip(ship1)
 let damage = calculateDamage(source, target, weapon)
  target = await ShipsModel.registerDamage(target, damage)

 return { target: target, fleet: await this.getFleet(false), enemyFleet: 
  await this.getFleet(true) }
}
```

在前面的代码中，我们看到了控制器和模型之间的粘合剂。首先，我们获取目标和源船只。你为什么认为我决定在目标上使用`let`，在源上使用`const`？如果你认为目标需要是可变的，你是对的：当我们在目标上使用`registerDamage`方法时，重写变量会比创建新变量更有效。

在查看我们的模型的`registerDamage`方法之前，请注意到迄今为止的返回路径是控制器将返回到返回到我们前端脚本的路由。

继续前进！

*models/ships.js*

```js
exports.registerDamage = async (ship, damage) => {
 const enemy = (!ship.registry.indexOf('NCC')) ? "fleet" : "enemy"
  const target = await db.collection(enemy).findOne({ registry:
   ship.registry })

 if (target.shields > damage) {
   target.shields -= damage
 } else {
   target.shields -= damage
   target.hull += Math.abs(target.shields)
   target.shields = 0
 }

 await db.collection(enemy).updateOne({ registry: ship.registry }, { $set: { shields: target.shields, hull: target.hull } })
  if (target.hull >= 100) {
   await this.scuttle(target.registry)
   target.scuttled = true
 }

 return target
}
```

现在*这里*是我们实际与我们的数据库通信的地方。我们可以看到我们正在检索我们的目标，注册对其护盾和可能对其船体的损坏，将这些值设置在 MongoDB 中，并最终通过控制器将目标船的信息返回到我们的前端 JavaScript。

让我们来看看这一行：

```js
await db.collection(enemy).updateOne({ registry: ship.registry }, { $set: { shields: target.shields, hull: target.hull } })
```

我们将更新集合中的一个项目，以说明它是敌船还是我们的舰队，并设置护盾强度和船体损坏。

## 导出函数

到目前为止，您可能已经注意到一些模型方法，比如`registerDamage`，是以`exports`为前缀的，而其他一些方法，比如`eliminateExistingShips`，则没有。在复杂的 JavaScript 应用程序中，良好的设计方面之一是封装那些不打算在特定上下文之外使用的函数。当以`exports`为前缀时，可以从不同的上下文中调用函数，比如从我们的控制器中。如果它不打算暴露给应用程序的其他部分；本质上，它是一个私有函数。导出变量的概念类似于作用域的概念，我们确保保持应用程序的整洁，并且只公开程序的有用部分。

如果我们看一下`eliminateExistingShips`，我们可以看到它只是一个辅助函数，由`createRandom`使用，以确保我们不会将相同的船只注册编号或名称分配给两艘不同的船只。我们可以在`createRandom`中看到这种用法：

```js
const randomSeed = Math.ceil(Math.random() * names.length);

const shipData = {
  name: (!enemy) ? names[randomSeed] : "Borg Cube",
```

*更多代码...然后：*

```js
while (unavailableRegistries.includes(shipData.registry)) {
  shipData.registry = `NCC-${Math.round(Math.random() * 10000)}`;
}
```

为了确保我们船只的注册编号在我们的舰队中是唯一的，我们将使用`while`循环来不断更新船只的注册编号，直到它不是已经存在的编号。使用`eliminateExistingShips`辅助函数，我们返回并解构已经存在于我们舰队中的名称和注册，以便我们不会创建重复的注册。

我们并不经常使用`while`循环，因为它们经常是程序中的阻塞点，并且很容易被滥用。话虽如此，这是`while`循环的一个很好的用例：它确保我们的程序在船只注册是唯一的情况下才能继续。通过一个随机化乘数为 10,000，很少会出现连续两次或更多次生成重复的随机注册，因此`while`循环是合适的。

因此，导出还是不导出，这是个问题。答案取决于我们是否需要在其直接范围之外使用该函数。如果在程序的其他部分中没有使用该函数，则不应该导出它。在这种情况下，我们需要确定船只的详细信息是否已经存在于舰队中，这在我们的`ships`模型中确实只有用，因此我们将不导出它。

## 改进我们的程序

当您阅读`ships`模型和控制器时，我相信您可以找到改进的地方。例如，我为了了解船只是在我们的舰队还是敌方舰队而编写的开关方式有点死板：它无法容纳在一场战斗中有三个单独的舰队。每个程序员都会创造**技术债务**，或者代码中的小错误或低效。这就需要**重构**，即改变代码使其更好。不要被愚弄以为您曾经写过*完美的程序*——这样的东西是不存在的。改进和持续迭代是编程过程的一部分。

然而，重构有一个重要的警告，那就是通常所谓的**合同**。当设计一个由前端使用的后端，并且不同的团体正在编写系统的不同部分时，重要的是要与彼此和整个程序的前提和需求保持同步。

让我们以前端 JavaScript 代码为例。如果我们枚举它正在使用的端点，我们将看到正在使用四个端点：

+   `/ships`

+   ``/ships/${e.currentTarget.closest('tr').dataset.ship}``

+   `/ships/random`

+   `/play/fire?attacker=${e.target.closest('td').dataset.attacker}&target=${target}&weapon=${weapon}``

至少，在重构后端代码时，我们应该假定有一个合同义务，即不更改这些端点的路径，也不更改要接收的数据类型的期望。

我们可以帮助我们的代码更具未来性，使用一种名为 JSDoc 的松散标准进行*内联文档*。从代码注释创建文档是一种长期以来的做法，为了促进标准，许多语言都存在注释结构。在 API 等情况下，通常会运行一个辅助程序来针对源代码生成独立的文档，通常作为一个小型的 HTML/CSS 微型网站。您可能已经遇到了与类似风格的在线文档无关的程序。有很大的可能性，这些无关的文档站点是通过相同的机制从代码生成的。

为什么在关于 MongoDB 的章节中这很重要？嗯，文档不仅仅是数据库使用的需要；相反，当创建任何具有多个移动部分的程序时，它是重要的。考虑前面列表中的最后一个端点：`/play/fire?attacker=${e.target.closest('td').dataset.attacker}&target=${target}&weapon=${weapon}`。

fire 端点接受三个参数：`attacker`、`target`和`weapon`。但这些参数是什么？它们是什么样子的——是对象？字符串？布尔值？数组？此外，如果我们要接受用户生成的数据，我们需要比以前更加小心，因为**GIGO**：**垃圾进，垃圾出**。如果我们用坏数据填充我们的数据库，我们最好能期望的是一个破碎的程序。事实上，我们最坏的期望是安全**妥协**：数据库或服务器凭据泄露或恶意代码执行。让我们谈谈安全。

## 安全

如果您熟悉 SQL，您可能熟悉一种称为**SQL 注入**的安全漏洞。关于 Web 应用程序安全最佳实践的良好信息可以在[owasp.org](http://owasp.org)找到。**开放 Web 应用程序安全项目**（**OWASP**）是一个社区驱动的倡议，旨在记录和教育用户有关 Web 应用程序中存在的安全漏洞，以便我们可以更有效地对抗恶意黑客。如果您的电子邮件、社交帐户或网站曾被黑客入侵，您就会知道随之而来的痛苦——数字身份盗窃。OWASP 关于 SQL 注入的列表在这里：[`owasp.org/www-community/attacks/SQL_Injection`](https://owasp.org/www-community/attacks/SQL_Injection)。

那么，如果我们使用的是 MongoDB 这种 NoSQL 数据库，为什么要谈论 SQL 呢？因为*MongoDB 中不存在 SQL 注入*。"太好了！"你可能会说，"我的安全问题解决了！"不幸的是，情况并非如此。重构以提高应用程序效率的想法，重构以减轻安全入侵向量是负责任地管理 Web 应用程序的重要部分。我曾在一家公司工作，那家公司被黑客入侵了——原因是因为在 URL 中插入了不到五个字符。这使得黑客能够破坏 Web 应用程序的操作并执行任意的 SQL 命令。对所有用户生成的内容进行消毒和重构是 Web 安全的重要部分。现在，我们还没有为这个应用程序做到这一点，因为我相信你不会黑自己的机器。

等等。我刚刚不是说 MongoDB 中不存在 SQL 注入吗？是的，NoSQL 数据库有它们等效的攻击方法：**代码和命令注入**。因为我们没有对用户输入进行消毒或验证完整性，所以我们的应用程序可能会存储和使用已提交并存储在我们的数据库中的任意代码。虽然本书不涵盖 JavaScript 安全的完整介绍，但请记住这一点。长话短说就是要消毒或验证您的用户生成的输入的有效性。

就这样，让我们结束这一章。只要记住，在野外编写 MongoDB 应用程序时要注意安全！

# 总结

JavaScript 并不孤立存在！MongoDB 是 JavaScript 的绝佳伴侣，因为它设计为面向对象，并依赖于友好的 JavaScript 查询语法。我们已经学习了 TDD 的原则，使用了 MVC 范式，并且扩展了我们的游戏。

在进行编码练习时，一定要考虑使用诸如 MongoDB 这样的数据库时的用例：虽然 MongoDB 的语法不容易受到 SQL 注入的影响，但仍然容易受到其他类型的注入攻击，这可能会危及您的应用程序。

希望我们的星际飞船游戏足够有趣，让您继续开发它。我们的下一个（也是最后一个）章节将汇集 JavaScript 开发原则，并完善我们的游戏。


# 第十九章：将所有内容整合在一起

终于！我们现在可以构建网站的前端和后端，并在两侧使用 JavaScript！为了将所有内容整合在一起，让我们构建一个小型 Web 应用程序，该应用程序使用带有 React 前端和 MongoDB 的 Express API。

对于我们的最终项目，我们将利用我们的技能创建一个基于数据库的旅行日志或旅行日志，包括照片和故事。我们的方法是从最初的视觉布局一直到前端和后端代码。如果您的 HTML/CSS 技能不太好，不用担心：代码已经为您提供了多个实例，因此您可以从任何地方开始处理项目。

本章将涵盖以下主题：

+   项目简介

+   脚手架 - React

+   后端 - 设置我们的 API

+   数据库 - 所有 CRUD 操作

# 技术要求

准备好使用存储库的`chapter-19`目录中提供的代码，网址为[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-19`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-19)。由于我们将使用命令行工具，还需要准备终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# 项目简介

从头到尾开始一个真实的 Web 项目时，重要的是要提前收集**要求**。这可以以许多形式呈现：口头描述，功能的项目列表，视觉线框图，完整的设计文档，或者这些的任何组合。在审查要求时，重要的是要尽可能明确，以减少误传、冗余或被放弃的工作，以及简化的工作流程。对于这个项目，我们将从视觉 comp 开始。

如果您曾经与平面设计师合作过，您可能熟悉术语 comp。视觉 comp，简称*全面布局*，是设计工件，是所需项目最终状态的高保真视觉表示。例如，印刷项目的 comp 将是一个数字文件，其中包含所有所需的资产，可立即发送给打印机使用。对于数字作品，您可能会收到 Adobe Photoshop、XD 或 Sketch 文件，或者许多其他类型的设计文档格式。

让我们先看一下视觉效果，以便随后确定我们的要求：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/781c2632-8646-488c-9b09-baf75f1b05cb.png)

图 19.1 - 主页

我们的应用程序将具有*已登录*和*已注销*状态。注销时，用户将看到封面页面，并可以使用导航按钮浏览旅行日志的条目。作为挑战，在页面加载时显示一个随机条目。

左上角的登录按钮将引导到下一个屏幕，即登录屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/87a4dcee-47fe-43d5-8a46-ce5ae7731142.png)

图 19.2 - 登录

登录页面可以简单也可以复杂。也许输入任何用户名和密码组合都可以工作，或者为了增加挑战，您可以整合 Google 或 Facebook 身份验证。您甚至可以编写自己的身份验证，使用您的数据库存储凭据。

一旦经过身份验证，我们在左侧栏有一个新按钮：仪表板按钮。这是带我们到应用程序的各个部分的地方：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/e5444286-3830-41b0-9a67-c5066473e8f6.png)

图 19.3 - 仪表板

当单击“访问过的国家”按钮时，我们将显示由 D3.js 图形库提供支持的矢量地图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/d9585ee2-43c7-49ee-a756-39fb460bd72c.png)

图 19.4 - 旅行地图

突出显示的国家由数据库提供的 JSON 清单控制。

最后但同样重要的是，用户需要能够撰写条目并插入照片：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/ac1ad9cf-8341-409b-99e1-4477665ec581.png)

图 19.5 - 新条目/编辑条目屏幕

我们将使用一个名为 Quill 的 JavaScript 所见即所得（WYSIWYG）编辑器。

在构建应用程序时，可以随意对其外观和感觉进行一些自定义-使其成为您自己的！您可能还想添加一些其他功能，例如媒体库来管理上传的照片，或者搜索功能。

现在我们已经有了关于我们的视觉布局的想法，让我们开始着手项目的前端。

# 脚手架 - React

我们的项目非常适合使用 React 来进行前端开发，因此让我们为前端制定我们的要求：*一个单一的 React 应用程序，具有可重用的组件和**Hooks 和 context**用于状态保存*。与我们以前使用 React 的方式相比，Hooks 是一个新概念。在 React 16.8 中添加的 Hooks 是允许您在函数组件中操作状态和上下文以进行状态管理的函数。

除了我们手工制作的 React 应用程序，我们还将整合一些额外的预构建库，以简化我们的项目并利用现成的工具。D3.js 是一个强大的图形和数据可视化库，我们将利用它来制作我们的地图。Quill 是一个富文本编辑器，它将允许您使用文本格式编写条目，并上传和放置照片。

由您决定是要从`npx create-react-app`开始，还是使用 GitHub 存储库的`chapter-19`目录中的`Step 1`文件夹中提供的脚手架代码。

我将对要使用的其他包提出一些建议；在项目进行过程中，可以随意添加或删除包。我将使用以下内容：

+   引导（用于布局）

+   `d3`，`d3-queue`和`topojson-client`（用于我们的地图）

+   `node-sass`（使用 Sass 创建更高效的样式表）

+   `quill`和`react-quilljs`（一个所见即所得的编辑器）

+   `react-router-dom`（一个使 URL 路径设置变得容易的 React 扩展）

+   `react-cookie`（一个方便使用 cookie 的包）

如果您从头开始，现在可以使用`create-react-app`脚手架进行设置，或者开始使用`Step 1`目录。在本章的其余部分，将为您提供逐步跟随的说明。

在`Step 1`目录中，您将找到以下内容：

```js
.
├── README.md
├── package-lock.json
├── package.json
├── public
│ ├── favicon.ico
│ ├── index.html
│ ├── logo192.png
│ ├── logo512.png
│ ├── manifest.json
│ ├── robots.txt
│ └── uploads
├── src
│ ├── App.css
│ ├── App.js
│ ├── App.test.js
│ ├── components
│ │ ├── Dashboard
│ │ │ └── Dashboard.js
│ │ ├── Editor
│ │ │ └── Editor.js
│ │ ├── Header
│ │ │ └── Header.js
│ │ ├── Login
│ │ │ └── Login.js
│ │ ├── Main
│ │ │ └── Main.js
│ │ ├── Map
│ │ │ └── Map.js
│ │ └── Toolbar
│ │ ├── Toolbar.js
│ │ ├── dashboard.svg
│ │ └── login.svg
│ ├── index.css
│ ├── index.js
│ ├── logo.svg
│ ├── serviceWorker.js
│ ├── setupTests.js
│ └── styles
│ └── _App.scss
└── yarn.lock
```

这是一个标准的`create-react-app`脚手架，与我们以前所做的有一些不同。让我们来看一个组件：标题。

## 函数组件

这是我们的`Header.js`文件的代码：

```js
import React from 'react'

function Header() {
 return (
   <>
     <h2>Chris Newman's</h2>
     <h1>Travelogue</h1>
   </>
 )
}
export default Header
```

您应该注意到一些事情：首先，文件名以`js`结尾，而不是`jsx`。其次，我们的组件是一个返回 HTML 的函数，而不是扩展`React.Component`的类。虽然在 React 中，基于类和函数的组件都是有效的，但在使用 React 时，特别是使用最新的方法来利用状态和上下文时，函数组件被认为更现代。我们现在不会深入讨论函数和面向对象编程之间的区别，但可以说有一些需要注意的区别。您可以在本章末找到有关这些区别的有用资源。

## 下一步

要将应用程序推进到下一个阶段，考虑我们制定的功能要求。一个很好的下一步可能是实现一个登录系统。在这一点上，您可能既不想也不需要实际验证凭据，因此一个虚拟的登录页面就足够了。您可以在`Login/Login.js`中找到标记。

我们要采取的方法是使用**Hooks**和**context**。由于这是一个相当复杂的主题，我们在这里不会详细介绍所有细节，但有很多文章解释了这些概念。这是其中一个：[`www.digitalocean.com/community/tutorials/react-crud-context-hooks`](https://www.digitalocean.com/community/tutorials/react-crud-context-hooks)。

我们将通过一个上下文示例和一些 Hooks 示例来帮助您入门：

1.  首先，我们需要创建一个`UserContext.js`文件，它将帮助我们在用户交互的整个生命周期中跟踪我们的登录状态。代码本身非常简单：

```js
import React from 'react'

export const loggedIn = false

const UserContext = React.createContext(loggedIn)

export default UserContext
```

1.  React 的**Context API**是一种向多个组件提供有状态信息的方法。注意我说的“提供”？这正是我们接下来需要做的：提供我们的`App.js`上下文。我们将组件包装如下：

```js
import React, { useState } from 'react'
import './styles/_App.scss'
import Main from './components/Main/Main';
import UserContext, { loggedIn } from './components/UserContext'

function App() {

 const loginHook = useState(loggedIn)

 return (
   <UserContext.Provider value={loginHook}>
     <div className="App">
       <Main />
     </div>
   </UserContext.Provider>
 )
}

export default App
```

注意我们如何导入`UserContext`并在`UserContext.Provider`标签中包装我们的`App`组件，并向其提供`loginHook`有状态值，从而传递给其子组件。

1.  我们的`Main.js`文件也需要一些更改。看一下这段代码：

```js
function Main() {
 const [loggedIn, setLoggedIn] = useContext(UserContext)
 const [cookies, setCookie] = useCookies(['logged-in'])
...
```

我们需要从 React 和`react-cookies`中分别导入`useContext`和`useCookies`，然后我们可以使用这些**Hooks**来处理我们的登录状态。除了内部上下文之外，我们还将在 cookie 中存储我们的登录状态，以便返回会话时保持登录状态。我们还需要从 React 中导入`useEffect`作为下一步：

```js
const setOrCheckLoggedIn = (status) => {
   if (cookies['logged-in'] === 'true' || status) {
     setLoggedIn(true)
   }

   if (status && cookies['logged-in'] !== 'true') {
     setCookie('logged-in', true)
   }
 }

 useEffect(() => {
 setOrCheckLoggedIn()
 })
```

您是否还记得在以前的章节中，我们是如何直接使用`componentDidMount()`来对 React 组件的挂载状态做出反应的？使用 React Hooks，我们可以使用`useEffect` Hook 来处理我们组件的状态。在这里，我们将确保我们的用户上下文（`loggedIn`）和`logged-in` cookie 被适当设置。

1.  我们的`setOrCheckLoggedIn`函数还需要传递给其他组件，即`Toolbar`和`Login`。将其设置为`doLogin`属性。

从这一点开始，当我们包括`UserContext`的上下文时，我们可以依赖`loggedIn`状态变量来确定我们的用户是否已登录。例如，我们简单的`Login`组件的逻辑可以利用这些 Hooks 如下：

```js
import React, { useContext } from 'react'
import UserContext from '../UserContext'

const Login = (props) => {

 let [loggedIn, setLoggedIn] = useContext(UserContext)

 const logMeIn = () => {
   loggedIn = !loggedIn
   props.doLogin(loggedIn)
 }

 return (
   <>
     <div className="Login">
       <h1>Log In</h1>

       <p><input type="text" name="username" id="username" /></p>
       <p><input type="password" name="password" id="password"
       /></p>
       <p><button type="submit" onClick={logMeIn}>Go</button></p>
     </div>
   </>
 )
}

export default Login
```

相当简单！首先，我们获取我们的上下文，并在点击`Go`按钮时，翻转上下文。您应该在`Toolbar.js`文件中也加入类似的逻辑，以便登录图标也能处理登出。

现在，我们需要一个后端与我们的前端进行交互，并与 MongoDB 数据库进行交易，该数据库将存储我们的故事条目和可能的用户身份验证数据。还需要创建一个端点来上传图像，因为仅有前端代码是*无法*写入服务器文件系统的。

# 后端 - 设置我们的 API

让我们列出我们需要使我们的旅行日志工作的端点：

+   *读取（GET）：*像大多数 API 一样，我们需要一个端点来读取条目。对于这一点，我们不会强制进行身份验证或登录。

+   *写入（POST）：*此端点将用于创建新的旅行和编辑现有的旅行。

+   *上传（POST）：*我们需要一个端点从我们的前端调用以上传照片。

+   *登录（POST）（可选）：*如果您想自己处理身份验证，创建一个登录端点，可以使用数据库或社交媒体登录端点的凭据。

+   *媒体（GET）（可选）：*有一个列出所有上传到服务器的媒体文件的 API 将是有用的。

+   *国家（GET）（可选）：*为列出您访问过的国家提供一个特定的端点也是一个好主意，以支持您的世界地图。

在工作过程中，您可能会发现自己创建更多的端点，这很正常！从头到尾规划您的 API 总是一个好主意，但如果您需要在途中进行更改以便通过辅助端点或其他部分更轻松地完成工作，那也是可以的。

我们准备好进入我们存储库中的`Step 3`目录了。

## API 作为代理 - 第 3 步

因为我们正在使用 React 前端，我们将重新考虑使用 Express 作为后端，React 代理我们的 API 请求，如下所示：

1.  我们需要做的第一件事是告诉我们的系统通过在我们的`package.json`中添加这一行来使用代理：`"proxy": "http://localhost:5000"`。

1.  添加后，重新启动 React（您会注意到我们的前端主页已经改变；我们马上就会解决这个问题），然后在`api`目录中，执行`npm install`，然后在`api`目录中执行`npm start`。

1.  我们应该测试我们的后端，确保我们的 API 有响应。将这作为一个测试添加到`App.js`文件的导入后：

```js
fetch('/api')
 .then(res => res.text())
 .then(text => console.log(text))
```

这个非常基本的`fetch`调用应该调用我们 API 中的`routes/index.js`组件的`get`方法：

```js
router.get('/', (req, res) => {
 res.sendStatus(200)
})
```

此时，我们的控制台应该显示`OK`。如果你在这个阶段遇到任何问题，最好现在调试它们。

1.  我们知道我们将设置一个数据库来处理我们的数据，但目前，我们可以搭建我们的 API 方法，就像你在`routes/index.js`中看到的那样：

```js
router.get('/article', (req, res) => {
 res.send({ story: "A story from the database" })
})

router.post('/article/edit', (req, res) => {
 res.sendStatus(200)
})

router.post('/media/upload', (req, res) => {
 res.sendStatus(200)
})

router.get('/media', (req, res) => {
 res.send({ media: "A list of media" })
})

router.post('/login', (req, res) => {
 res.sendStatus(200)
})

router.get('/countries', (req, res) => {
 res.send({ countries: "A list of countries" })
})
```

现在我们已经在**步骤 2**中搭建了我们的登录系统，我对`步骤 3`目录进行了一些修改。如前所述，我们的主页有点不同，因为它是旅行日志的首页，用于在用户注销时显示故事。

1.  接下来检查`Story/Story.js`组件：

```js
import React from 'react'

function Story() {

 fetch('/api/article')
   .then(res => res.json())
   .then(json => console.log(json))

 return (
   <div className="Story">
     <h1>Headline</h1>
...
```

是的，另一个虚拟 API 调用到我们的后端！这个调用也是一个简单的 GET 请求，所以让我们做一些更复杂的事情。

1.  继续登录到网站，你会在你的仪表板上看到一些不同的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/316b7bc5-3a97-4cac-a510-5695764d85c1.png)

图 19.6 - 我们的仪表板正在成形...

1.  很好，现在我们有一个完整的仪表板。点击“添加行程”按钮，你将看到一个编辑器，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/906c1808-d284-4f62-beaa-176587980d84.png)

图 19.7 - 我们的文本编辑器

如果你在编辑器中输入富文本并保存它，你会在控制台中看到来自 API 的提交数据的响应。从那里，我们需要与我们的 API 一起工作，将数据保存到我们的数据库中。所以...最后，但并非最不重要的，我们需要设置我们的数据库。

# 数据库 - 所有 CRUD 操作

当然，我们需要一个数据存储库来进行创建、读取、更新和删除功能，所以让我们返回到 MongoDB 来存储这些文档。如果需要刷新你在设置方面的记忆，你可以参考第十八章，*Node.js 和 MongoDB*。

要从头开始设置数据库，有助于考虑你打算使用的数据库结构。虽然 MongoDB 不需要模式，但计划你的 MongoDB 文档仍然是一个好主意，这样你就不会在各个部分之间的功能或命名上随意。

以下是每个集合可能看起来像的一个想法：

```js
settings:  {
  user
    firstname
    lastname
    username
    password
  title
  URL
  media directory
}

entry: {
  title
  location
  date
    month
    day
    year
  body
}

location: {
  city
  region
  country
  latitude
  longitude
  entries
}
```

保持数据库简单是好的，但记住你总是可以扩展它。

# 总结

当然，我不能只是*交给*你一个最终项目，对吧？在这一章中，我们搭建了我们的旅行日志 - 其余的就看你了。还有一些功能尚未完成，以便拥有一个完全功能的项目。毕竟，我们还没有完全遵守我们的视觉设计，对吧？以下是一些关于要实现哪些功能的想法，以完成项目：

+   将信息持久化到数据库。

+   工作在图像上传和保存上。

+   编辑现有文章。

+   创建`countries`端点以填充 D3.js 地图。

+   启用真正的登录。

+   简化用户旅程。

完成后，这个项目将成为你的作品集中的一个作品，展示了*你*，一个 Python 开发者，如何掌握 JavaScript。从数据类型、语法、循环和 Node.js 的开始，到最终创建一个完全功能的项目，你已经走了很长的路。

我由衷地感谢你陪伴我走过这段旅程！继续学习，**长寿繁荣**。

# 进一步阅读

关于函数式编程和面向对象编程之间的区别的有用资源可以在[`www.geeksforgeeks.org/difference-between-functional-programming-and-object-oriented-programming/`](https://www.geeksforgeeks.org/difference-between-functional-programming-and-object-oriented-programming/)找到。


# 第二十章：评估

# 第一章

1.  哪个国际组织维护 JavaScript 的官方规范？

1.  W3C

1.  **Ecma International**

1.  网景

1.  太阳

1.  哪些后端可以与 JavaScript 通信？

1.  PHP

1.  Python

1.  Java

1.  **以上所有**

1.  谁是 JavaScript 的原始作者？

1.  蒂姆·伯纳斯-李

1.  **布兰登·艾奇**

1.  Linus Torvalds

1.  比尔·盖茨

1.  DOM 是什么？

1.  JavaScript 在内存中对 HTML 的表示

1.  允许 JavaScript 修改页面的 API

1.  **以上两者**

1.  以上都不是

1.  Ajax 的主要用途是什么？

1.  与 DOM 通信

1.  DOM 的操作

1.  监听用户输入

1.  **与后端通信**

# 第二章

1.  **真**或假：Node.js 是单线程的。

1.  真或**假**：Node.js 的架构使其不受**分布式拒绝服务**（**DDoS**）攻击的影响。

1.  谁最初创建了 Node.js？

1.  布兰登·艾奇

1.  Linux Torvalds

1.  阿达·洛夫莱斯

1.  **Ryan Dahl**

1.  真或**假**：服务器端的 JavaScript 本质上是不安全的，因为代码在前端暴露。

1.  真或**假**：Node.js 本质上优于 Python。

# 第三章

1.  以下哪个不是有效的 JavaScript 变量声明？

1.  var myVar = 'hello';

1.  const myVar = "hello"

1.  **String myVar = "hello";**

1.  let myVar = "hello"

1.  以下哪个开始了函数声明？

1.  **功能**

1.  const

1.  功能

1.  def

1.  以下哪个不是基本循环类型？

1.  for..in

1.  为

1.  当

1.  **映射**

1.  JavaScript *需要*使用分号进行行分隔：

1.  真

1.  **假**

1.  在 JavaScript 中，空格*永远*不计算：

1.  真

1.  **假**

# 第四章

1.  JavaScript 本质上是：

1.  同步

1.  异步

1.  **两者**

1.  一个`fetch()`调用返回：

1.  `then`

1.  `next`

1.  `最后`

1.  **Promise**

1.  使用原型继承，我们可以（选择所有适用的选项）：

1.  **在基本数据类型中添加方法。**

1.  **从基本数据类型中减去方法。**

1.  重命名我们的数据类型。

1.  将我们的数据转换为另一种格式。

```js
let x = !!1
console.log(x)
```

1.  在给定的代码中，预期的输出是什么？

1.  1

1.  假

1.  0

1.  **真**

```js
const Officer = function(name, rank, posting) {
 this.name = name
 this.rank = rank
 this.posting = posting
 this.sayHello = () => {
 console.log(this.name)
 }
}

const Riker = new Officer("Will Riker", "Commander", "U.S.S. Enterprise")
```

1.  在这段代码中，输出“威尔·莱克”最好的方法是什么？

1.  **`Riker.sayHello() `***

1.  `console.log(Riker.name)`

1.  `console.log(Riker.this.name)`

1.  `Officer.Riker.name()`

# 第五章

考虑以下代码：

```js
function someFunc() {
  let bar = 1;

  function zip() {
    alert(bar); // 1
    let beep = 2;

    function foo() {
      alert(bar); // 1
      alert(beep); // 2
    }
  }

  return zip
}

function sayHello(name) {
  const sayAlert = function() {
    alert(greeting)
  }

  const sayZip = function() {
    someFunc.zip()
  }

  let greeting = `Hello ${name}`
  return sayAlert
}
```

1.  如何获得警报`'你好，鲍勃'`？

1.  `sayHello()('Bob')`

1.  `sayHello('Bob')()`*****

1.  `sayHello('Bob')`

1.  `someFunc()(sayHello('Bob'))`

1.  在上述代码中，`alert(greeting)`会做什么？

1.  警报`'问候'`

1.  警报`'你好，爱丽丝'`

1.  **抛出错误**

1.  以上都不是

1.  我们如何获得警报消息`1`？

1.  `someFunc()()`*****

1.  `sayHello().sayZip()`

1.  `alert(someFunc.bar)`

1.  `sayZip()`

1.  我们如何获得警报消息`2`？

1.  `someFunc().foo()`

1.  `someFunc()().beep`

1.  **我们不能，因为它不在范围内**

1.  我们不能，因为它没有定义

1.  我们如何将`someFunc`更改为警报 1 1 2？

1.  我们不能。

1.  在`return zip`之后添加`return foo`。

1.  将`return zip`更改为`return foo`。

1.  **在`foo`声明之后添加`return foo`**。

1.  在给定上一个问题的正确解决方案的情况下，我们如何实际获得三个警报，即 1、1、2？

1.  `someFunc()()()`*****

1.  `someFunc()().foo()`

1.  `someFunc.foo()`

1.  `alert(someFunc)`

# 第六章

考虑以下代码：

```js
  <button>Click me!</button>
```

1.  选择按钮的正确语法是什么？

1.  document.querySelector('点击我！')

1.  document.querySelector('.button')

1.  document.querySelector('#button')

1.  **document.querySelector('button')**

看看这段代码：

```js
<button>Click me!</button>
<button>Click me two!</button>
<button>Click me three!</button>
<button>Click me four!</button>
```

1.  真或**假**：document.querySelector('button')将满足我们对每个按钮放置点击处理程序的需求。

1.  要将按钮的文本从“点击我！”更改为“先点我！”，我们应该使用什么？

1.  **document.querySelectorAll('button')[0].innerHTML = "先点我！"**

1.  document.querySelector('button')[0].innerHTML = "先点我！"

1.  document.querySelector('button').innerHTML = "先点我！"

1.  document.querySelectorAll('#button')[0].innerHTML = "先点我！"

1.  我们可以使用哪种方法添加另一个按钮？

1.  document.appendChild('button')

1.  document.appendChild('<button>')

1.  **document.appendChild(document.createElement('button'))**

1.  document.appendChild(document.querySelector('button'))

1.  如何将第三个按钮的类更改为“third”？

1.  document.querySelector('button')[3].className = 'third'

1.  **document.querySelectorAll('button')[2].className = 'third'**

1.  document.querySelector('button[2]').className = 'third'

1.  document.querySelectorAll('button')[3].className = 'third'

# 第七章

回答以下问题以衡量您对事件的理解：

1.  以下哪个是事件生命周期的第二阶段？

1.  捕获

1.  **定位**

1.  冒泡

1.  （选择所有正确答案）事件对象为我们提供了什么？

1.  **触发的事件类型**

1.  **目标 DOM 节点（如果适用）**

1.  **鼠标坐标（如果适用）**

1.  父 DOM 节点（如果适用）

看看这段代码：

```js
container.addEventListener('click', (e) => {
  if (e.target.className === 'box') {
    document.querySelector('#color').innerHTML = e.target.style.backgroundColor
    document.querySelector('#message').innerHTML = e.target.innerHTML
    messageBox.style.visibility = 'visible'
    document.querySelector('#delete').addEventListener('click', (event) => {
      messageBox.style.visibility = 'hidden'
      e.target.remove()
    })
  }
})
```

1.  它使用了哪些 JavaScript 特性？选择所有适用的答案：

1.  **DOM 操作**

1.  **事件委托**

1.  **事件注册**

1.  **样式更改**

1.  当容器被点击时会发生什么？

1.  `box` 将可见。

1.  `#color` 将是红色的。

1.  选项 1 和 2 都是。

1.  **没有足够的上下文来说。**

1.  在事件生命周期的哪个阶段我们通常采取行动？

1.  **定位**

1.  捕获

1.  冒泡

# 第九章

1.  内存问题的根本原因是什么？

1.  程序中的变量是全局的。

1.  **低效的代码。**

1.  JavaScript 的性能限制。

1.  硬件不足。

1.  在使用 DOM 元素时，应该将对它们的引用存储在本地，而不是总是访问 DOM。

1.  真

1.  假

1.  **当多次使用它们时为真**

1.  JavaScript 在服务器端进行预处理，因此比 Python 更有效。

1.  真

1.  **假**

1.  设置断点无法找到内存泄漏。

1.  真

1.  **假**

1.  将所有变量存储在全局命名空间中是一个好主意，因为它们更有效地引用。

1.  真

1.  **假**
