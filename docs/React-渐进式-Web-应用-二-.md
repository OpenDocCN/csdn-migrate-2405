# React 渐进式 Web 应用（二）

> 原文：[`zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D`](https://zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Firebase 轻松设置后端

我们的应用程序看起来很漂亮，但它并没有做太多事情。我们有一个登录表单，但用户实际上无法登录。

在本章中，我们将开始处理我们应用程序的后端。在我们的情况下，这意味着设置一个数据库来保存用户及其消息。在一个章节中，我们将涵盖让用户创建帐户和登录所需的一切。我们还将深入研究 React 和组件状态。我们将学到以下内容：

+   Firebase 是什么

+   需要注意的问题和问题

+   如何部署我们的应用程序

+   用户认证（注册和登录）

+   React 生命周期方法

让我们开始吧！

# Firebase 是什么？

构建渐进式 Web 应用程序在很大程度上是一个前端过程。PWA 对于它们如何从后端 API 获取数据并不太关心（除非它影响性能，当然）。我们希望保持我们应用程序的后端设置最小化；为此，我们转向 Firebase。

**Firebase**是 Google 设计的一个项目，旨在帮助开发人员构建应用程序，而不必担心后端基础设施。它采用免费模型，基于后端需要响应的请求数量以及您需要的存储量。对于我们的目的，它非常适合快速开发一个小型原型。当我们的应用扩展时，Chatastrophe 的执行委员会向我们保证，“金钱不是问题”。

Firebase 提供了什么？我们感兴趣的是数据库、托管解决方案和内置认证。除此之外，它还提供了一种称为**Cloud Functions**的东西，这是一些代码片段，会在特定事件的响应中自动运行。一旦我们为我们的应用程序添加推送通知，我们将使用 Cloud Functions。现在，我们想要在我们的登录表单中添加一些身份验证，以便用户可以注册并登录到 Chatastrophe。

如果您有 Google 帐户（例如通过 Google Plus 或 Gmail），您可以使用这些凭据登录 Firebase，或者创建一个新帐户；这就是我们开始所需要的一切。

# Firebase 注意事项

Firebase 是一个有用的工具，但它确实有一些注意事项。

其中一个重要的卖点（尤其是对我们来说）是它的实时数据库。这意味着一个用户对数据的更改会自动推送给所有用户。我们不必检查是否已创建了新的聊天消息；应用程序的每个实例都将立即收到通知。

数据库还具有离线持久性，这意味着我们的用户甚至在离线时也可以阅读他们的消息（如果您记得的话，这满足了我们之前概述的用户故事之一）。Firebase 使用本地缓存来实现这一点。

那么，有什么缺点吗？Firebase 数据库是一个 NoSQL 数据库，具有特定的语法，对于更习惯于 SQL 数据库的开发人员可能会感到奇怪。该过程类似于 SQL 数据库（具有主要的**CRUD**操作--**创建**，**读取**，**更新**和**删除**--适用于数据），但可能不太直观。

Firebase 的另一个要点是，它（在撰写本文时）并未针对像 React 这样构建的**单页应用程序**（**SPAs**）进行优化。我们将不得不做一些变通方法，以使一切在我们的 React 应用程序中顺利运行。

尽管如此，Firebase 将节省我们大量时间，与设置我们自己的后端服务器/托管解决方案相比，这绝对是值得学习的。

# 设置

以下是我们如何开始使用 Firebase：

1.  我们将转到 Firebase 控制台。

1.  从那里，我们将创建一个项目。

1.  我们将为我们可爱的小项目命名。

1.  我们将获得将其集成到我们的应用程序中所需的代码。

1.  我们将将该代码添加到`index.html`中。

1.  我们将使 Firebase 作为全局变量可用。

如果您准备好开始，请这样做：

1.  一旦您创建或登录到您的 Google 帐户，转到[`firebase.google.com/`](https://firebase.google.com/)。在屏幕右上角，您应该看到一个名为 GO TO CONSOLE 的按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00027.jpeg)

1.  从 Firebase 控制台，我们想要添加项目。点击图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00028.jpeg)

1.  对于项目名称，选择`chatastrophe`（全部小写），然后选择您的国家/地区。

1.  一旦完成，Firebase 应该直接带您到项目页面。从那里，点击上面写着 Add Firebase to your web app 的链接：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00029.jpeg)

1.  复制并粘贴它给您的代码到`public/index.html`中，在闭合的`</body>`标签之前：

```jsx
<body>
  <div id="root"></div> 
  <script src="https://www.gstatic.com/firebasejs/4.1.2/firebase.js"></script> 
  <script>  
    // Initialize Firebase  
    var config = {    
      apiKey: /* API KEY HERE */,    
      authDomain: "chatastrophe-77bac.firebaseapp.com",    
      databaseURL: "https://chatastrophe-77bac.firebaseio.com",    
      projectId: "chatastrophe-77bac",    
      storageBucket: "chatastrophe-77bac.appspot.com",    
      messagingSenderId: "85734589405"  
    };  
    firebase.initializeApp(config); 
  </script> 
</body>
```

1.  最后，我们需要使我们的 Firebase 应用程序对我们的应用程序的其余部分可用。在脚本标签的底部，在`firebase.initializeApp(config)`行之前，添加以下内容：

```jsx
window.firebase = firebase;
```

这段代码将我们的 Firebase 设置存储在`window`对象上，这样我们就可以在 JavaScript 的其余部分中访问它。

如果您没有使用源代码控制（例如 GitHub 或 Bitbucket），或者正在使用私有存储库来存储您的代码，您可以跳过到下一节。对于我们其他人，我们需要做一些工作，以确保我们不会向整个世界显示我们的`config.apiKey`（这是一种恶意使用的方法）。

# 隐藏我们的 API 密钥

我们需要将我们的 API 密钥和`messagingSenderId`移动到一个单独的文件中，然后确保该文件没有被检入 Git：

1.  为此，在`public/`中创建一个名为`secrets.js`的文件。在该文件中，放入以下内容：

```jsx
window.apiKey = "YOUR-API-KEY”
messagingSenderId = "YOUR-SENDER-ID"
```

同样，我们利用全局访问的 window 对象来存储密钥。对于那些对 JavaScript 新手来说，请注意滥用 window 对象并不是一个好的做法；只有在绝对必要时才使用它。

1.  要在`index.html`中使用此密钥，我们可以在所有其他脚本标签之前添加以下内容：

```jsx
<script src="/secrets.js"></script>
```

1.  然后，在我们的 Firebase 初始化中：

```jsx
 <script>  
   // Initialize Firebase
   var config = {
     apiKey: window.apiKey,
     // ...rest of config
     messagingSenderId: window.messagingSenderId
   };
```

1.  作为最后一步，我们需要告诉 Git 忽略`secrets.js`文件。您可以通过修改我们项目基础中的`.gitignore`文件来实现这一点，添加以下行：

```jsx
/public/secrets.js
```

搞定了！我们现在可以自由地提交和推送了。

# 部署 Firebase

正如我之前提到的，Firebase 自带了一个内置的部署解决方案。让我们在真实的网络上让我们的应用程序运行起来！以下是如何做到这一点：

1.  为此，我们首先需要安装 Firebase 命令行工具：

```jsx
npm install -g firebase-tools
```

不要忘记`-g`。这个标志会在您的机器上全局安装这些工具。

1.  下一步是登录我们的 Firebase 工具：

```jsx
firebase login
```

1.  为了完成我们的 Firebase 工具设置，我们现在可以将我们的应用初始化为一个 Firebase 项目，类似于我们使用`npm`所做的。确保您从项目文件夹的根目录运行此命令：

```jsx
firebase init
```

在它随后提示您的第一个问题中，使用箭头键和*空格键*来选择 Functions 和 Hosting。我们稍后将使用 Firebase 的 Cloud Functions。不要选择 Database，那是用于在本地配置数据库规则的；我们将依赖于 Firebase 控制台。

您的选择应该如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00030.jpeg)

当它要求默认的 Firebase 项目时，请选择`chatastrophe`（或者您在 Firebase 控制台中命名的项目）。

对于问题“您是否要立即使用 npm 安装依赖项？”，输入 y。

接下来，它会问你要使用哪个文件夹作为你的公共目录。输入`build`，而不是`public`。Firebase 正在询问要使用哪个文件夹来部署你的项目；我们想要我们最终编译的构建，包括我们转译的 JavaScript，因此，我们想要`build`文件夹。

现在让我们转到下一个问题！我们想将我们的应用程序配置为单页面应用程序吗？当然。尽管拒绝覆盖`index.html`（但是，如果你说是，也没关系；每次运行`build`命令时，我们都会重新生成我们的`build/index.html`）。

好的，我们已经准备好部署了。让我们创建一个`npm`脚本，让我们的生活更轻松。

每次部署，我们都希望重新运行我们的`build`命令，以确保我们拥有项目的最新构建。因此，我们的`npm`脚本将结合这两者，添加到我们的`package.json`中：

```jsx
"scripts": {
  "build": "node scripts/copy_assets.js && node_modules/.bin/webpack --config webpack.config.prod.js",
  "start": "node_modules/.bin/webpack-dev-server",
  "deploy": "npm run build && firebase deploy"
},
```

使用`yarn deploy`运行脚本，然后在终端中检查它显示的 URL。如果一切顺利，你的应用程序应该看起来和在开发中一样。打开控制台并检查警告；如果看到任何警告，浏览一下 Webpack 章节，看看是否错过了我们`webpack.config.prod.js`的一些设置（你可以在这里的最终文件中查看：[`github.com/scottdomes/chatastrophe/tree/chapter4`](https://github.com/scottdomes/chatastrophe/tree/chapter4)）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00031.jpeg)

太棒了！我们有一个部署好的应用程序可以与朋友分享。唯一的问题是我们在上一章讨论的问题；它实际上还没有做太多事情。

让我们开始使用 Firebase 添加身份验证流程。

# 使用 Firebase 进行身份验证

为了让用户能够登录/注册我们的应用程序，我们需要做三件事：

1.  在 Firebase 控制台上打开电子邮件验证。

1.  当用户点击按钮时，将电子邮件和密码提交到 Firebase 中。

1.  根据结果注册或登录用户。

让我们打开我们的 Firebase 控制台（[`console.firebase.google.com`](https://console.firebase.google.com)）并开始处理任务＃1：

1.  从我们的 Chatastrophe 项目页面，点击身份验证。

1.  在“登录方法”选项卡下，您可以看到 Firebase 提供的所有选项。这些身份验证解决方案对开发人员来说是巨大的福音，因为配置身份验证可能会很棘手（特别是在使用第三方 API 时，如 Twitter 或 Facebook）。提供适当的安全性需要创建大量基础设施。Firebase 为我们处理了这一切，所以我们只需要担心如何利用他们的系统。

1.  点击电子邮件/密码，然后点击启用和保存。我们的应用现在可以使用电子邮件和密码组合进行注册和登录。如果您想稍后为我们的应用增添一些趣味性，可以尝试实现 Facebook 或 GitHub 登录。

返回应用程序，转到`LoginContainer.js`。目前，当用户提交我们的表单时，我们只是阻止默认提交并注销我们的状态：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  console.log(this.state);
};
```

对于我们的流程，我们将合并注册和登录过程。首先，我们将检查电子邮件和密码字段是否已填写。如果是，我们将尝试登录用户，如果 Firebase 告诉我们该电子邮件对应的用户不存在，我们将自动创建用户并登录。

但是，如果用户存在并且我们收到密码错误的错误，我们将通过在我们的组件中实现更多状态来提醒用户。

这是计划：

```jsx
handleSubmit = (event) => {
 event.preventDefault();
 // Step 1\. Check if user filled out fields
 // Step 2\. If yes, try to log them in.
 // Step 3\. If login fails, sign them up.
}
```

首先，检查字段是否已填写：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  if (this.state.email && this.state.password) {
    // Try to log them in.
  } else {
    // Display an error reminding them to fill out fields.
  }
}
```

立即，我们需要一种方法向用户显示错误，告诉他们他们错过了一个字段。让我们向我们的状态添加一个错误字符串：

```jsx
state = { email: '', password: '', error: ‘’ }
```

每次他们提交表单时，我们将将该错误重置为空字符串，但如果他们错过了一个字段，我们将显示以下文本：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  this.setState({ error: '' });
  if (this.state.email && this.state.password) {
    // Try to log them in.
  } else {
    this.setState({ error: 'Please fill in both fields.' });
  }
}
```

最后，为了显示错误，我们将在按钮上方添加一个`<p>`标签，其中包含错误的`className`：

```jsx
  <input  
    type="password"  
    onChange={this.handlePasswordChange} 
    value={this.state.password} 
    placeholder="Your password" /> 
  <p className="error">{this.state.error}</p> 
  <button className="red light" type="submit">Login</button>
```

好的，尝试提交我们的表单，而不填写任何字段。您可以通过在本地运行应用程序（使用您的开发服务器）或重新部署更改来这样做。您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00032.jpeg)

到目前为止看起来很不错。下一步是尝试登录用户。此时，我们的应用程序没有用户，因此 Firebase 应该返回一个错误。让我们使用我们的电子邮件和密码调用 Firebase，然后在控制台中记录结果。

我们想要使用的方法是`firebase.auth().signInWithEmailAndPassword(email, password)`。这个函数返回一个 JavaScript promise。对于熟悉 promise 的人，可以跳到下一节，但如果不确定的话，值得复习一下。

# 什么是 promise？

JavaScript 的问题在于它经常处理异步操作。这些是代码必须完成的步骤，它们不遵循时间上的线性流动。通常，代码一行一行地运行，但当我们需要调用一个需要随机秒数才能响应的 API 时会发生什么？我们不能停止我们的代码并等待，而且我们仍然有一些代码行需要在调用完成后执行，无论何时。

以前的解决方案是**回调**。如果我们以这种方式使用`firebase.auth().signInWithEmailAndPassword`，它会是这样的：

```jsx
firebase.auth().signInWithEmailAndPassword(email, password, function() {
  // Do something when the sign in is complete.
});
```

我们会传递一个回调函数，当操作完成时调用它。这种方法很好用，但可能会导致一些丑陋的代码：具体来说，一些称为**噩梦金字塔**或**回调地狱**的东西，其中嵌套的回调导致倾斜的代码：

```jsx
firebase.auth().signInWithEmailAndPassword(email, password, function() {
  onLoginComplete(email, password, function() { 
    onLoginCompleteComplete('contrived example', function() {
      anotherFunction('an argument', function () {
        console.log('Help I'm in callback hell!');
      });
    });
  });
});
```

为了使处理异步函数更容易和更清晰，JavaScript 背后的人们实现了 promises。**Promises**有一个简单的语法：将一个函数传递给`.then`语句，当操作成功时调用它，将另一个函数传递给`.catch`语句，当操作失败时调用它：

```jsx
firebase.auth().signInWithEmailAndPassword(email, password)
  .then(() => { // Do something on success })
  .catch(err => { // Do something on failure. })
```

现在，我们的代码很好读，我们知道操作完成时将运行哪些代码。

# 回到认证

由于我们期望返回一个错误（因为我们还没有使用任何电子邮件和密码组合进行注册），我们可以将我们的`then`语句留空，但在我们的`catch`语句中添加一个控制台日志：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  this.setState({ error: '' });
  if (this.state.email && this.state.password) {
    firebase.auth().signInWithEmailAndPassword(this.state.email, this.state.password)
      .then(res => { console.log(res); })
      .catch(err => { console.log(err); })
  } else {
    this.setState({ error: 'Please fill in both fields.' });
  }
}
```

提交您的表单，您应该返回以下错误：

```jsx
{code: "auth/user-not-found", message: "There is no user record corresponding to this identifier. The user may have been deleted."}
```

太好了！这正是我们想要的错误。这是我们在启动注册流程之前将检查的代码。现在，我们将假设所有其他错误都是由于密码不正确：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  this.setState({ error: '' });
  if (this.state.email && this.state.password) {
    firebase.auth().signInWithEmailAndPassword(this.state.email, 
     this.state.password)
      .then(res => { console.log(res); })
      .catch(err => { 
        if (error.code === 'auth/user-not-found') { 
          // Sign up here.
        } else { 
          this.setState({ error: 'Error logging in.' }) ;
        }
      })
 } else {
   this.setState({ error: 'Please fill in both fields.' });
 }
}
```

# 代码清理

我们的`handleSubmit`函数变得有点长，难以跟踪。在继续之前，让我们重新组织一下。

我们将从初始的`if`语句之后的所有内容移到一个名为`login()`的单独函数中，以简化操作：

```jsx
login() {
  firebase
    .auth()
    .signInWithEmailAndPassword(this.state.email, this.state.password)
    .then(res => {
      console.log(res);
    })
    .catch(err => {
      if (err.code === 'auth/user-not-found') {
        this.signup();
      } else {
        this.setState({ error: 'Error logging in.' });
      }
    });
}
```

然后，我们的`handleSubmit`变得更小：

```jsx
handleSubmit = event => {
  event.preventDefault();
  this.setState({ error: '' });
  if (this.state.email && this.state.password) {
    this.login();
  } else {
    this.setState({ error: 'Please fill in both fields.' });
  }
};
```

现在阅读和跟踪起来更容易了。

# 注册

让我们开始注册流程。同样，这是一个相当简单的函数名--`firebase.auth().createUserWithEmailAndPassword(email, password)`。同样，它返回一个 promise。让我们添加`then`和`catch`，但现在将`then`作为控制台日志：

```jsx
signup() {
  firebase
    .auth()
    .createUserWithEmailAndPassword(this.state.email, this.state.password)
    .then(res => {
      console.log(res);
    })
    .catch(error => {
      console.log(error);
      this.setState({ error: 'Error signing up.' });
    });
}
```

尝试登录我们的应用程序，你应该会在控制台看到一个复杂的用户对象。成功！我们创建了我们的第一个用户帐户。如果你尝试使用相同的帐户再次登录，你应该会在控制台看到相同的用户对象。

你可以尝试使用不同的电子邮件和密码组合再次尝试（对于我们的目的来说，它不必是真实的电子邮件），它应该可以顺利工作。

# 保存我们的用户

我们收到的`firebase.auth().signIn`的`user`对象似乎将来会有用。可能会有很多次我们想要访问当前登录用户的电子邮件。让我们将其保存在我们的`App`组件的状态中，这样我们就可以将其传递给任何`Container`组件（一旦我们创建更多的容器）。

有两种可能的方法：我们可以通过 props 从`LoginContainer`将用户对象传递给`App`，并且`App`将一个`handleLogin`函数作为 prop 传递给`LoginContainer`，当用户登录时调用该函数并适当设置`App`的状态。

然而，Firebase 给了我们另一个选择。正如我们之前讨论的，Firebase 数据库是实时的，这意味着数据的更改会自动推送到前端。我们所需要做的就是设置适当的监听函数来等待这些更改并对其进行操作。

# 事件监听器

JavaScript 中的**事件监听器**基本上是这样工作的：我们定义一个事件和一个我们想要在该事件发生时运行的回调。因此，我们可以在代码中提前声明一个函数，然后在稍后触发它，只要指定的事件发生。

以下是监听浏览器窗口调整大小的示例：

```jsx
window.addEventListener('resize', function() { // Do something about resize });
```

Firebase 为我们提供了一个名为`firebase.auth().onAuthStateChanged`的函数。这个函数以一个回调作为参数，然后用用户对象调用它；这对我们来说非常完美！

然而，挑战在于在我们的`App`组件中何时声明这个函数。我们希望它执行以下操作：

```jsx
firebase.auth().onAuthStateChanged((user) => {
  // If there is a user, save it to state.
  // If there is no user, do nothing.
});
```

然而，这会导致一些限制：

+   我们只想注册一次监听器，所以我们不能将其放在`render`方法中（因为 React 更新 DOM 时可能会多次调用）

+   我们需要在注册监听器之前完全加载`App`组件，因为如果你尝试在不存在的组件上`setState`，React 会报错

换句话说，我们需要在特定时间声明`onAuthStateChanged`，也就是在`App`出现在屏幕上后尽快。

# 生命周期方法

幸运的是，在 React 中这样的情况很常见，所以库为我们提供了一个解决方案：一组名为**生命周期方法**的函数。这些方法是所有（基于类的）React 组件的标准功能，并在组件出现、更新和消失时的特定时间点被调用。

React 组件的生命周期如下：

+   应用程序已启动，组件的`render`方法即将被调用

+   组件已呈现并出现在屏幕上

+   组件即将接收新的 props

+   组件已收到新的 props，并将再次调用 render 以响应更新

+   组件已根据新的 props 或状态更改进行了更新

+   组件即将从屏幕上消失

请注意，并非所有这些方法都会在每个组件中发生，但它们在 UI 更新和更改时都很常见。

相应的生命周期方法如下：

+   `componentWillMount`

+   `componentDidMount`

+   `componentWillReceiveProps`

+   `componentWillUpdate`

+   `componentDidUpdate`

+   `componentWillUnmount`

根据上述描述，花点时间想一想我们想要使用哪个生命周期方法来注册我们的`onAuthStateChanged`。

再次强调，我们要找的时间点是在组件首次呈现后。这使得`componentDidMount`成为完美的选择；让我们将其添加到我们的`App`组件中。我们还需要用`user`键初始化我们的状态，稍后我们将使用它：

```jsx
class App extends Component {
 state = { user: null };

 componentDidMount() {

 }

  render() {
    return (
      <div id="container">
        <LoginContainer />
      </div>
    );
  }
}
```

如果您对生命周期方法不清楚，请尝试在您的应用程序中添加所有六个生命周期方法，并在每个方法中使用控制台日志（以及在`render`方法中使用`console.log`），观察您的 React 组件的生命周期。

好的，接下来我们可以添加`onAuthStateChanged`：

```jsx
componentDidMount() { 
  firebase.auth().onAuthStateChanged((user) => {      
    if (user) {        
      this.setState({ user });      
    }    
  }); 
}
```

对`this.setState({ user })`感到困惑吗？这被称为`ES6`属性简写。基本上，当你将一个键分配给一个变量，并且键和变量应该有相同的名称时，你可以节省时间，而不是输入`this.setState({ user: user })`。

注意`if`语句。`onAuthStateChanged`也在用户登出时被调用，此时用户参数将为 null。我们可以将`this.state.user`设置为 null，但让我们保持简单，让用户在状态中持续，直到下一个用户出现。

Firebase 身份验证的另一个好处是它为我们处理了持久登录。这意味着用户不必每次进入我们的应用程序时都要登录；Firebase 会自动加载他们的登录状态，直到他们点击登出（这是我们将来会添加的）。根据这一点，`onAuthStateChanged`将在用户访问我们的应用程序时每次被调用，无论他们是物理登录还是已经登录。因此，如果用户已登录，我们可以依赖于我们的用户对象始终保存在状态中。

你可以在`onAuthStateChanged`的回调中使用`firebase.auth().signOut();`来尝试登出用户。尝试重新登录，然后刷新页面；无论您刷新多少次，您都应该看到用户对象出现，因为您已自动登录。

# 总结

身份验证就是这样！现在，我们的用户可以登录我们的应用程序。下一步是在他们登录后给他们一些事情要做。为此，我们需要更多页面，这将引出我们的下一个主题：使用 React 进行路由。我们如何在 React 组件之间导航？我们如何根据 URL 更改应用程序的内容？所有这些等等都即将到来！


# 第五章：使用 React 进行路由

“我们已经扩展了功能列表。”

你忍住一声叹息，等待。

“我们想给我们的用户一切。他们需要的一切，他们想要的一切，他们可能永远想要的一切。”

“好吧，”你说。“但这只是一个原型…”

“一个用于分析的页面，一个用于他们的个人资料，一个用于他们朋友的分析，一个用于做笔记，一个用于天气。”

你悄悄地走出去，低声重复着，“这只是一个原型。”

# 计划

我们现在已经到达了技术上工作的应用程序的点（允许用户登录），但缺乏真正有用的内容。是时候改变了。

然而，为了这样做，我们需要向我们的应用程序添加额外的页面。你们中的一些人可能听说过**单页应用程序**（**SPA**）这个术语，它用来指代 React 应用程序，因此可能会对更多页面的讨论感到困惑。随着我们进一步深入，我们将涵盖这个区别，然后进入使用 React Router 进行实际路由设置。

我们将学到什么：

+   如何安装和使用 React Router v4

+   如何为其他组件添加额外的路由

+   如何在路由之间移动

# 页面上的页面

幸运的是，理智的头脑占上风，产品主设计师（公司目前雇佣的五名设计师中排名最高的）表示他们只需要原型的三个视图：登录视图（已完成！）、主要聊天视图和用户个人资料视图。

然而，显然我们需要一种强大且可扩展的方法来在我们的应用程序中在不同的屏幕之间切换。我们需要一个良好而坚实的路由解决方案。

传统上，路由一直是关于提供哪些 HTML/CSS/JavaScript 文件的问题。你在[static-site.com](http://static-site.com)上输入 URL，得到主`index.html`，然后转到[static-site.com/resources](http://static-site.com/resources)并得到`resources.html`。

在这个模型中，服务器收到对特定 URL 的请求并返回相应的文件。

然而，越来越多的情况下，路由正在转移到客户端。在 React 世界中，我们只提供我们的`index.html`和`bundle.js`。我们的 JavaScript 从浏览器中获取 URL，然后决定渲染什么 JSX。

因此有了单页应用程序这个术语--从传统模型来看，我们的用户技术上只坐在一个页面上。然而，他们能够在其他视图之间导航，并且以更加流畅的方式进行，而无需从服务器请求更多文件。

我们的顶层容器组件（`App.js`）将始终被渲染，但变化的是其内部渲染的内容。

# React 路由的不同之处

对于一些 React 路由解决方案，模型看起来可能是这样的。

我们将渲染我们的初始屏幕，如下所示：

```jsx
<App>
  <LoginContainer />
</App>
```

这将适用于`chatastrophe.com/login`的 URL。当用户完成登录后，我们将把他们发送到`chatastrophe.com/chat`。在那时，我们将使用以下方式调用`ReactDOM.render`：

```jsx
<App>
  <ChatContainer />
</App>
```

然后，React 的协调引擎将比较旧应用程序和新应用程序，并交换具有更改的组件；在这种情况下，它将`LoginContainer`替换为`ChatContainer`，而不重新渲染`App`。

以下是一个非常简单的示例，使用了一个名为`page.js`的基本路由解决方案：

```jsx
page(‘/’, () => {
  ReactDOM.render(
    <App>
      <ChatContainer />
    </App>.
    document.getElementById('root')
  );
});

page(‘/login’, () => {
 ReactDOM.render(
   <App>
    <LoginContainer />
   </App>.
   document.getElementById('root')
  );
});
```

这个解决方案运行良好。我们能够在多个视图之间导航，而 React 的协调确保没有不必要的重新渲染未更改的组件。

然而，这个解决方案并不是非常符合 React 的特点。每次我们改变页面时，我们都将整个应用程序传递给`ReactDOM.render`，这导致我们的`router.js`文件中有大量重复的代码。我们定义了多个版本的应用程序，而不是精确选择应该在何时渲染哪些组件。

换句话说，这个解决方案强调了路由的整体方法，而不是通过组件分割的方法。

输入`React Router v4`，这是该库的完全重写，它曾经是一个更传统的路由解决方案。不同之处在于现在路由是基于 URL 渲染的组件。

让我们通过重新编写我们之前的示例来详细讨论这意味着什么：

```jsx
ReactDOM.render(
  <Router>
    <App>
      <Route path="/" component={ChatContainer} />
      <Route path="/login" component={LoginContainer} />
    </App>
  </Router>,
  document.getElementById('root')
);
```

现在，我们只调用一次`ReactDOM.render`。我们渲染我们的应用程序，并在其中渲染两个包裹我们两个容器的`Route`组件。

每个`Route`都有一个`path`属性。如果浏览器中的 URL 与该`path`匹配，`Route`将渲染其子组件（容器）；否则，它将不渲染任何内容。

我们从不尝试重新渲染我们的`App`。它应该保持静态。此外，我们的路由解决方案不再与我们的组件分开存放在一个`router.js`文件中。现在，它存在于我们的组件内部。

我们还可以在组件内进一步嵌套我们的路由。在`LoginContainer`内部，我们可以添加两个路由--一个用于`/login`，一个用于`/login/new`--如果我们想要有单独的登录和注册视图。

在这个模型中，每个组件都可以根据当前的 URL 做出渲染的决定。

我会诚实，这种方法有点奇怪，需要时间适应，当我开始使用它时，我一点也不喜欢。对于有经验的开发人员来说，它需要以一种不同的方式思考你的路由，而不是作为一个自上而下的、整个页面决定要渲染什么的决定，现在鼓励你在组件级别做决定，这可能会很困难。

然而，经过一段时间的使用，我认为这种范式正是 React 路由所需要的，将为开发人员提供更多的灵活性。

好了，说了这么多。让我们创建我们的第二个视图--聊天界面--用户可以在这里查看并向全世界的人发送消息（你知道，“全球互联”）。首先，我们将创建一个基本组件，然后我们可以开始使用我们的路由解决方案。

# 我们的 ChatContainer

创建组件现在应该是老生常谈了。我们的`ChatContainer`将是一个基于类的组件，因为我们将需要在后面利用一些生命周期方法（稍后会详细介绍）。

在我们的`components`文件夹中，创建一个名为`ChatContainer.js`的文件。然后，设置我们的骨架：

```jsx
import React, { Component } from 'react';

export default class ChatContainer extends Component {
  render() {
    return (

   );
  }
}
```

让我们继续包装我们的组件，使用组件名称作为`div`的`id`：

```jsx
import React, { Component } from 'react';

export default class ChatContainer extends Component {
  render() {
    return (
      <div id="ChatContainer">
      </div>
    );
  }
}
```

就像在我们的`LoginContainer`顶部一样，我们希望渲染我们美丽的标志和标题供用户查看。如果我们有某种可重用的组件，这样我们就不必重写那段代码了：

```jsx
import React, { Component } from 'react';
import Header from './Header';

export default class ChatContainer extends Component {
  render() {
    return (
      <div id="ChatContainer">
        <Header />
      </div>
    );
  }
}
```

这太美妙了。好吧，让我们在`Header`后面添加`<h1>Hello from ChatContainer</h1>`，然后继续进行路由，这样我们在工作时就可以实际看到我们在做什么。现在，我们的`ChatContainer`是不可见的。要改变这种情况，我们需要设置 React Router。

# 安装 React Router

让我们从基础知识开始。从项目根目录在终端中运行以下命令。

```jsx
yarn add react-router-dom@4.2.2
```

`react-router-dom`包含了我们在应用程序中为用户进行路由所需的所有 React 组件。您可以在[`reacttraining.com/react-router`](https://reacttraining.com/react-router)上查看完整的文档。然而，我们感兴趣的唯一组件是`Route`和`BrowserRouter`。

重要的是要确保您安装的是`react-router-dom`而不是`react-router`。自从发布了第 4 版以后，该软件包已被拆分为各种分支。`React-router-dom`专门用于提供路由组件，这正是我们感兴趣的。请注意，它安装了`react-router`作为对等依赖。

`Route`组件相当简单；它接受一个名为`path`的属性，这是一个字符串，比如`/`或`/login`。当浏览器中的 URL 与该字符串匹配（[`chatastrophe.com/login`](http://chatastrophe.com/login)），`Route`组件渲染通过`component`属性传递的组件；否则，它不渲染任何内容。

与 Web 开发中的任何内容一样，您可以使用`Route`组件的方式有很多额外复杂性。我们稍后会更深入地探讨这个问题。但是，现在，我们只想根据我们的路径是`/`还是`/login`有条件地渲染`ChatContainer`或`LoginContainer`。

`BrowserRouter`更复杂，但对于我们的目的，使用起来会很简单。基本上，它确保我们的`Route`组件与 URL 保持同步（渲染或不渲染）。它使用 HTML5 历史 API 来实现这一点。

# 我们的 BrowserRouter

我们需要做的第一件事是将整个应用程序包装在`BrowserRouter`组件中，然后我们可以添加我们的`Route`组件。

由于我们希望在整个应用程序周围使用路由器，最容易添加它的地方是在我们的`src/index.js`中。在顶部，我们要求以下组件：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter } from 'react-router-dom';
import App from './components/App';
```

然后，我们将我们的`App`作为`BrowserRouter`的子级进行渲染：

```jsx
ReactDOM.render(
  <BrowserRouter>
    <App />
  </BrowserRouter>,
  document.getElementById('root')
);
```

您还应该在我们的热重新加载器配置中执行相同的操作：

```jsx
if (module.hot) {
  module.hot.accept('./components/App', () => {
    const NextApp = require('./components/App').default;
    ReactDOM.render(
      <BrowserRouter>
 <App />
 </BrowserRouter>,
      document.getElementById('root')
    );
  });
}
```

完成！现在我们实际上可以开始添加路由了。

# 我们的前两个路由

在我们的`App`组件中，我们目前无论如何都会渲染`LoginContainer`：

```jsx
render() {
  return (
    <div id="container">
      <LoginContainer />
    </div>
  );
}
```

我们希望改变这个逻辑，以便只渲染`LoginContainer`或者渲染`ChatContainer`。为了做到这一点，让我们在`ChatContainer`中要求它。

我们还需要从`react-router-dom`中要求我们的`Route`组件：

```jsx
import React, { Component } from 'react';
import { Route } from 'react-router-dom';
import LoginContainer from './LoginContainer';
import ChatContainer from './ChatContainer';
import './app.css';
```

我将`Route`导入放在了两个`Container`导入的上面。最佳实践是，你应该在相对导入（从`src`内导入的文件）之前放置绝对导入（从`node_modules`导入）。这样可以保持代码整洁。

现在，我们可以用接受`component`属性的`Route`组件替换我们的容器：

```jsx
render() {
  return (
    <div id="container">
      <Route component={LoginContainer} />
      <Route component={ChatContainer} />
    </div>
  );
}
```

我们将我们的组件属性传递为`LoginContainer`，而不是`<LoginContainer />`。

我们的应用程序重新加载，我们看到...一团糟：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00033.jpeg)

我们目前同时渲染两个容器！糟糕。问题在于我们没有给我们的`Route`一个`path`属性，告诉它们何时渲染（以及何时不渲染）。让我们现在来做。

我们的第一个`Route`，`LoginContainer`，应该在`/login`路由时渲染，因此我们添加了如下路径：

```jsx
<Route path="/login" component={LoginContainer} />
```

当用户在根路径`/`（当前在`localhost:8080/`，或者在我们部署的应用[`chatastrophe-77bac.firebaseapp.com/`](https://chatastrophe-77bac.firebaseapp.com/)）时，我们的另一个容器`ChatContainer`将被显示，因此我们添加了如下路径：

```jsx
<Route path="/" component={ChatContainer} />
```

保存，检查应用程序，你会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00034.jpeg)

好了！我们的`LoginContainer`不再渲染。让我们前往`/login`，确保我们只在那里看到我们的`LoginContainer`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00033.jpeg)

哎呀！

我们在`/login`处同时渲染两个容器。发生了什么？

长话短说，React Router 使用**RegEx**模式来匹配路由并确定要渲染的内容。我们当前的路径（`/login`）匹配了传递给我们登录`Route`的属性，但它也在技术上匹配了`/`。实际上，一切都匹配`/`，这对于你想要在每个页面上渲染一个组件是很好的，但我们希望我们的`ChatContainer`只在路径为`/`（没有其他内容）时才渲染。

换句话说，我们希望在路径精确匹配`/`时渲染`ChatContainer`路由。

好消息是，React Router 已经为这个问题做好了准备；只需在我们的`Route`中添加一个`exact`属性：

```jsx
<Route exact path="/" component={ChatContainer} />
```

前面的内容与写作如下相同：

`<Route exact={true} path="/" component={ChatContainer} />`

当我们检查`/login`时，我们应该只看到我们的`LoginContainer`。太棒了！我们有了我们的前两个路由。

接下来，我们想要做的是强制路由一点；当用户登录时，我们希望将他们重定向到主要的聊天界面。让我们来做吧！

# 登录后重定向

在这里，事情会变得有点棘手。首先，我们要做一些准备工作。

在我们的`LoginContainer`中，当涉及到我们的`signup`和`login`方法时，我们目前只是在`then`语句中`console.log`出结果。换句话说，一旦用户登录，我们实际上什么也没做：

```jsx
signup() {
  firebase.auth().createUserWithEmailAndPassword(this.state.email, this.state.password)
    .then(res => {
      console.log(res);
    }).catch(error => {
      console.log(error);
      this.setState({ error: 'Error signing up.' });
    })
}
```

让我们改变这一点（在`signup`和`login`中），调用另一个方法`onLogin`：

```jsx
login() {
  firebase.auth().signInWithEmailAndPassword(this.state.email, this.state.password)
    .then(res => {
      this.onLogin();
    }).catch((error) => {
      if (error.code === 'auth/user-not-found') {
        this.signup();
      } else {
        this.setState({ error: 'Error logging in.' });
      }
    });
}
```

然后，我们可以定义我们的`onLogin`方法：

```jsx
onLogin() {
  // redirect to '/'
}
```

那么，我们如何重定向到根路径？

我们知道我们的`Route`组件将根据浏览器中的 URL 进行渲染。我们可以确信，如果我们正确修改 URL，我们的应用程序将重新渲染以显示适当的组件。诀窍是从`LoginContainer`内部修改 URL。

正如我们之前提到的，React Router 使用 HTML5 历史 API 在 URL 之间移动。在这个模型中，有一个叫做`history`的对象，其中有一些方法，允许你将一个新的 URL 推入应用程序的当前状态。

所以，如果我们在`/login`，想要去`/`：

```jsx
history.pushState(null, null, ‘/’)
```

React Router 让我们以更简洁的方式与 HTML5 历史对象交互（例如避免空参数）。它的工作方式很简单：通过`Route`（通过`component`属性）传递给的每个组件都会接收到一个叫做`history`的 prop，其中包含一个叫做`push`的方法。

如果这听起来让人困惑，不用担心，一会儿就会清楚了。我们只需要这样做：

```jsx
onLogin() {
  this.props.history.push(‘/’);
}
```

试着去`/login`并登录。你将被重定向到`ChatContainer`。神奇！

当调用`push`时，`history` prop 正在更新浏览器的 URL，然后导致我们的`Route`组件渲染它们的组件（或者不渲染）：

```jsx
History.push -> URL change -> Re-render
```

请注意，这是一个相当革命性的在网站中导航的方式。以前，它是完全不同的：

```jsx
Click link/submit form -> URL change -> Download new page
```

欢迎来到单页面应用的路由世界。感觉不错，是吧？

# 登出

好的，我们已经处理了用户登录，但是当他们想要注销时怎么办？

让我们在`ChatContainer`的顶部建立一个按钮，让他们可以注销。它最适合在`Header`组件中，所以为什么不在那里建立呢？

等等。我们目前在`LoginContainer`的`/login`路径上使用`Header`。如果我们添加一个`Logout`按钮，它也会出现在登录界面上，这会让人感到困惑。我们需要一种方法，只在`ChatContainer`上渲染`Logout`按钮。

我们可以利用`Route history` prop，并使用它来根据 URL 进行 Logout 按钮的条件渲染（如果路径是`/`，则渲染按钮，否则不渲染！）。然而，这可能会变得混乱，对于未来的开发人员来说很难理解，因为我们添加了更多的路由。让我们在想要 Logout 按钮出现时变得非常明确。

换句话说，我们想在`Header`内部渲染 Logout 按钮，但只有当`Header`在`ChatContainer`内部时才这样做。这有意义吗？

这样做的方法是使用 React children。从 HTML 的角度来看，Children 实际上非常容易理解：

```jsx
<div>
  <h1>I am the child of div</h1>
</div>
```

`h1`是`div`的子元素。在 React 组件的情况下，`Parent`组件将接收一个名为`children`的属性，它等于`h1`标签：

```jsx
<Parent>
  <h1>I am the child of Parent</h1>
</Parent>
```

要在`Parent`中渲染它，我们只需要这样做：

```jsx
<div id=”Parent”>
  {this.props.children}
</div>
```

让我们看看这在实际中是如何运作的，希望这样会更有意义（并给你一个它的强大的想法）。

在`ChatContainer`中，让我们用一个开放和关闭的标签替换我们的`<Header />`标签：

```jsx
<Header>
</Header>
```

在其中，我们将定义我们的按钮：

```jsx
<Header>
  <button className="red">Logout</button>
</Header>
```

检查我们的页面，我们会发现没有任何变化。这是因为我们还没有告诉`Header`实际渲染它的`children`。让我们跳到`Header.js`并改变这一点。

在我们的`h1`下面，添加以下内容：

```jsx
import React from 'react';

const Header = (props) => {
  return (
    <div id="Header">
      <img src="/assets/icon.png" alt="logo" />
      <h1>Chatastrophe</h1>
      {props.children}
    </div>
  );
};

export default Header;
```

我们在这里做什么？首先，我们将`props`定义为我们函数组件的参数：

```jsx
const Header = (props) => {
```

所有功能性的 React 组件都将`props`对象作为它们的第一个参数。

然后，在该对象内，我们正在访问`children`属性，它等于我们的按钮。现在，我们的`Logout`按钮应该出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00035.jpeg)

太棒了！如果你检查`/login`路径，你会注意到我们的按钮没有出现。那是因为在`LoginContainer`中，`Header`没有`children`，所以没有东西被渲染。

Children 使 React 组件非常可组合和可重用。

好的，让我们让我们的按钮真正起作用。我们想要调用一个名为`firebase.auth().signOut`的方法。让我们为我们的按钮创建一个调用这个函数的点击处理程序：

```jsx
export default class ChatContainer extends Component {
  handleLogout = () => {
    firebase.auth().signOut();
  };

  render() {
    return (
      <div id="ChatContainer">
        <Header>
          <button className="red" onClick={this.handleLogout}>
            Logout
          </button>
        </Header>
        <h1>Hello from ChatContainer</h1>
      </div>
    );
  }
}
```

现在，当我们按下按钮时，什么也不会发生，但我们已经被登出了。我们缺少登录谜题的最后一块。

当我们的用户注销时，我们希望将他们重定向到登录界面。如果我们有某种方式来告诉 Firebase 授权的状态就好了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00036.jpeg)

这很完美。当我们点击注销按钮后，当我们的用户注销时，Firebase 将使用空参数调用`firebase.auth().onAuthStateChanged`。

换句话说，我们已经拥有了我们需要的一切；我们只需要在我们的`if`语句中添加一个`else`来处理没有找到用户的情况。

流程将是这样的：

1.  当用户点击注销按钮时，Firebase 将登出他们。

1.  然后它将使用空参数调用`onAuthStateChanged`方法。

1.  如果`onAuthStateChanged`被调用时用户为空，我们将使用`history`属性将用户重定向到登录页面。

让我们通过跳转到 `App.js` 来实现这一点。

我们的 `App` 不是 `Route` 的子组件，所以它无法访问我们在 `LoginContainer` 中使用的 `history` 属性，但是我们可以使用一个小技巧。

在 `App.js` 的顶部，添加以下内容到我们的 `react-router-dom` 导入：

```jsx
import { Route, withRouter } from 'react-router-dom';
```

然后，在底部，用这个替换我们的 `export default` 语句：

```jsx
export default withRouter(App);
```

这里发生了什么？基本上，`withRouter` 是一个接受组件作为参数并返回该组件的函数，除了现在它可以访问 `history` 属性。随着我们的学习，我们会更多地涉及到这一点，但让我们先完成这个注销流程。

最后，我们可以填写 `componentDidMount`：

```jsx
componentDidMount() {
  firebase.auth().onAuthStateChanged((user) => {
    if (user) {
      this.setState({ user });
    } else {
      this.props.history.push('/login')
    }
  });
}
```

尝试再次登录并点击注销按钮。你应该直接进入登录界面。神奇！

# 绕道 - 高阶组件

在前面的代码中，我们使用了 `withRouter` 函数（从 `react-router-dom` 导入）来让我们的 `App` 组件访问 `history` 属性。让我们花点时间来谈谈它是如何工作的，因为这是你可以学到的最强大的 React 模式之一。

`withRouter` 是一个**高阶组件**（**HOC**）的例子。这个略显夸张的名字比我最喜欢的解释更好：*构建函数的函数*（感谢 *Tom Coleman*）。让我们看一个例子。

假设你有一个 `Button` 组件，如下所示：

```jsx
const Button = (props) => {
  return (
    <button style={props.style}>{props.text}</button>
  );
};
```

还有，假设我们有这样一种情况，我们希望它有白色文本和红色背景：

```jsx
<Button style={{ backgroundColor: 'red', color: 'white' }} text="I am red!" />
```

随着你的应用程序的发展，你发现你经常使用这种特定的样式来制作按钮。你需要很多红色按钮，带有不同的文本，每次都输入 `backgroundColor` 很烦人。

不仅如此；你还有另一个组件，一个带有相同样式的警报框：

```jsx
<AlertBox style={{ backgroundColor: 'red', color: 'white' }} warning="ALERT!" />
```

在这里，你有两个选择。你想要两个新的组件（`RedAlertBox` 和 `RedButton`），你可以在任何地方使用。你可以按照下面的示例定义它们：

```jsx
const RedButton = (props) => {
  return (
    <Button style={{ backgroundColor: 'red', color: 'white' }} text={props.text} />
  );
};
```

还有：

```jsx
const RedAlertBox = (props) => {
  return (
    <AlertBox style={{ backgroundColor: 'red', color: 'white' }} warning={props.text} />
  );
};
```

然而，有一种更简单、更可组合的方法，那就是创建一个高阶组件。

我们想要实现的是一种方法，可以给一个组件添加红色背景和白色文本的样式。就是这样。我们想要将这些属性注入到任何给定的组件中。

让我们先看看最终结果，然后看看我们的 HOC 会是什么样子。如果我们成功地创建了一个名为 `makeRed` 的 HOC，我们可以像下面这样使用它来创建我们的 `RedButton` 和 `RedAlertBox`：

```jsx
// RedButton.js
import Button from './Button'
import makeRed from './makeRed'

export default makeRed(Button)
```

```jsx
// RedAlertBox.js
import AlertBox from './AlertBox'
import makeRed from './makeRed'

export default makeRed(AlertBox)
```

这样做要容易得多，而且更容易重复使用。我们现在可以重复使用`makeRed`来将任何组件转换为漂亮的红色背景和白色文本。这就是力量。

好了，那么我们如何创建一个`makeRed`函数呢？我们希望将一个组件作为参数，并返回具有其所有分配的 props 和正确样式 prop 的组件：

```jsx
import React from 'react';

const makeRed = (Component) => {
  const wrappedComponent = (props) => {
    return (
      <Component style={{ backgroundColor: 'red', color: 'white' }} {...props} />
    );
  };
  return wrappedComponent;
}

export default makeRed;
```

以下是相同的代码，带有注释：

```jsx
import React from 'react';

// We receive a component constructor as an argument
const makeRed = (Component) => {
  // We make a new component constructor that takes props, just as any component
  const wrappedComponent = (props) => {
    // This new component returns the original component, but with the style applied
    return (
      // But we also use the ES6 spread operator to apply the regular props passed in.
      // The spread operator applies props like the text in <RedButton text="hello" /> 
       to our new component
      // It will "spread" any and all props across our component
      <Component style={{ backgroundColor: 'red', color: 'white' }} {...props} />
    );
  };
  // We return the new constructor, so it can be called as <RedButton /> or <RedAlertBox />
  return wrappedComponent;
}

export default makeRed;
```

最令人困惑的可能是`{...props}`的扩展运算符。扩展运算符是一个有用但令人困惑的 ES6 工具。它允许您获取一个对象（这里是`props`对象）并将其所有键和值应用于一个新对象（组件）：

```jsx
const obj1 = { 1: 'one', 2: 'two' };
const obj2 = { 3: 'three', ...obj1 };
console.log(obj2);
// { 1: 'one', 2: 'two', 3: 'three' }
```

高阶组件是使您的 React 组件更容易重用的下一级工具。我们在这里只是浅尝辄止。有关更多信息，请查看*Tom Coleman*的*Understanding Higher Order Components*，网址为[`medium.freecodecamp.org/understanding-higher-order-components-6ce359d761b`](https://medium.freecodecamp.org/understanding-higher-order-components-6ce359d761b)。

# 我们的第三个路由

正如本章开头所讨论的，Chatastrophe 团队决定要有一个用户个人资料视图。让我们为此做骨架和基本路由。

在`src/components`中，创建一个名为`UserContainer.js`的新文件。在里面，做基本的组件框架：

```jsx
import React, { Component } from 'react';
import Header from './Header';

export default class UserContainer extends Component {
  render() {
    return (
      <div id="UserContainer">
        <Header />
        <h1>Hello from UserContainer</h1>
      </div>
    );
  }
}
```

回到`App.js`，让我们导入我们的新容器并添加`Route`组件：

```jsx
import UserContainer from './UserContainer';

// Inside render, underneath ChatContainer Route
<Route path="/users" component={UserContainer} />
```

等一下！前面的代码为我们的`UserContainer`创建了一个在`/users`的路由，但我们不只有一个用户视图。我们为我们应用程序的每个用户都有一个用户视图。我们需要在`chatastrophe.com/users/1`为用户 1 创建一个路由，在`chatastrophe.com/users/2`为用户 2 创建一个路由，依此类推。

我们需要一种方法来将变量值传递给我们的`path`属性，等于用户的`id`。幸运的是，这样做很容易：

```jsx
<Route path="/users/:id" component={UserContainer} />
```

最棒的部分？现在，在我们的`UserContainer`中，我们将收到一个`props.params.match`对象，等于`{ id: 1 }`或者`id`是什么，然后我们可以使用它来获取该用户的消息。

让我们通过更改`UserContainer.js`中的`h1`来测试一下：

```jsx
<h1>Hello from UserContainer for User {this.props.match.params.id}</h1>
```

然后，前往`localhost:8080/users/1`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00037.jpeg)

如果在嵌套路由中遇到找不到`bundle.js`的问题，请确保您在`webpack.config.js`中的输出如下所示：

```jsx
output: {
 path: __dirname + "/public",
 filename: "bundle.js",
 publicPath: "/"
},
```

很好。现在，还有最后一步。让我们为用户从`UserContainer`返回到主聊天屏幕添加一种方式。

我们可以通过充分利用`Header`的子组件来以一种非常简单的方式做到这一点；只是，在这种情况下，我们可以添加另一个 React Router 组件，使我们的生活变得非常简单。它被称为`Link`，就像 HTML 中的标签一样，但经过了 React Router 的优化。

在`UserContainer.js`中：

```jsx
import { Link } from 'react-router-dom';
```

```jsx
<Header>
  <Link to="/">
    <button className="red">
      Back To Chat
    </button>
  </Link>
</Header>
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00038.jpeg)

当您单击按钮时，应该转到根路由`/`。

# 总结

就是这样！在本章中，我们涵盖了很多内容，以便让我们的应用程序的路由解决方案能够正常运行。如果有任何困惑，我建议您查看 React Router 文档[`reacttraining.com/react-router/`](https://reacttraining.com/react-router/)。接下来，我们将深入学习 React，完成我们的基本应用程序，然后开始将其转换为渐进式 Web 应用程序。


# 第六章：完成我们的应用

是时候完成我们应用的原型了，哦，我们有很多工作要做。

框架已经搭好，所有的路由都设置好了，我们的登录界面也完全完成了。然而，我们的聊天和用户视图目前还是空白的，这就是 Chatastrophe 的核心功能所在。因此，在向董事会展示我们的原型之前，让我们确保它实际上能够工作。

本章我们将涵盖的内容如下：

+   加载和显示聊天消息

+   发送和接收新消息

+   仅在用户个人资料页面上显示特定的聊天消息

+   React 状态管理

# 用户故事进展

让我们简要地检查一下我们在第一章“创建我们的应用结构”中定义的用户故事，看看我们已经完成了哪些。

我们已经完成了以下内容：

用户应该能够登录和退出应用。

以下内容尚未完成，但是它们是我们稍后将构建的 PWA 功能的一部分：

+   用户应该能够在离线时查看他们的消息

+   用户应该在其他用户发送消息时收到推送通知

+   用户应该能够将应用安装到他们的移动设备上

+   用户应该能够在不稳定的网络条件下在五秒内加载应用

这给我们留下了一系列故事，我们需要在我们的原型完成之前完成：

+   用户应该能够实时发送和接收消息

+   用户应该能够查看特定作者的所有消息

这些故事中的每一个都与特定的视图（聊天视图和用户视图）相匹配。让我们从`ChatContainer`开始，开始构建我们的聊天框。

# ChatContainer 框架

我们的聊天视图将有两个主要部分：

+   一个消息显示，列出所有的聊天

+   一个聊天框，用户可以在其中输入新消息

我们可以先添加适当的`div`标签：

```jsx
render() {
  return (
    <div id="ChatContainer">
      <Header>
        <button className="red" onClick={this.handleLogout}>
          Logout
        </button>
      </Header>
      <div id="message-container">

 </div>
 <div id="chat-input">

 </div>
     </div>
   );
}
```

提醒确保你的 ID 和 classNames 与我的相同，以免你的 CSS 不同（甚至更糟）。

我们首先填写输入框。在`div#chat-input`内，让我们放置一个`textarea`，并设置占位符为“添加你的消息…”：

```jsx
<textarea placeholder="Add your message..." />
```

我们将配置它，以允许用户按“Enter”键发送消息，但最好也有一个发送按钮。在`textarea`下面，添加一个`button`，在其中，我们将添加一个`SVG`图标：

```jsx
<div id="chat-input">
  <textarea placeholder="Add your message..." />
  <button>
 <svg viewBox="0 0 24 24">
 <path fill="#424242" d="M2,21L23,12L2,3V10L17,12L2,14V21Z" />
 </svg>
 </button>
</div>
```

确保你的`path fill`和`svg viewBox`属性与提到的相同。

SVG 是一种可以缩放（放大）而不会失真的图像类型。在这种情况下，我们基本上创建了一个框（`svg`标签），然后在`path`标签内绘制一条线。浏览器进行实际绘制，所以永远不会有像素化。

为了 CSS 的目的，让我们也给我们的`div#ChatContainer`添加`inner-container`类：

```jsx
<div id="ChatContainer" className="inner-container">
```

如果一切顺利，你的应用现在应该是这个样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00039.jpeg)

这就是我们聊天视图的基本结构。现在，我们可以开始讨论如何管理我们的数据--来自 Firebase 的消息列表。

# 管理数据流

React 的一个重要原则是所谓的**单向数据流**。

在原型 React 应用中，数据存储在最高级组件的状态中，并通过`props`传递给较低级的组件。当用户与应用程序交互时，交互事件通过 props 通过组件树传递，直到到达最高级组件，然后根据操作修改状态。

应用程序形成一个大循环--数据下传，事件上传，新数据下传。你也可以把它想象成一部电梯，从充满数据的顶层出发，然后再满载事件返回。

这种方法的优势在于很容易跟踪数据的流动。你可以看到数据流向哪里（传递给哪些子组件），以及为什么会改变（作为对哪些事件的反应）。

现在，这种模式在具有数百个组件的复杂应用程序中会遇到问题。在顶层组件中存储所有状态，并通过 props 传递所有数据和事件变得难以控制。

想象一条从顶层组件（`App.js`）到低层组件（比如一个`button`）的大链条。如果有数十个`嵌套`组件，并且`button`需要一个从`App`状态派生的 prop，你将不得不通过每个链条中的每个组件传递这个 prop。谢谢，我不要。

解决这个状态管理问题有很多方法，但大多数都是基于在组件树中创建容器组件的想法；这些组件有状态，并将其传递给有限数量的子组件。现在我们有多部电梯，一些服务于一楼到三楼，另一些服务于五楼到十二楼，依此类推。

我们不会在我们的应用程序中处理任何状态管理，因为我们只有四个组件，但是在你的 React 应用程序扩展时，记住这一点是很好的。

前两个 React 状态管理库是 Redux（[`github.com/reactjs/redux`](https://github.com/reactjs/redux)）和 MobX（[`github.com/mobxjs/mobx`](https://github.com/mobxjs/mobx)）。我对两者都有深入的了解，它们都有各自的优势和权衡。简而言之，MobX 对开发者的生产力更好，而 Redux 对于保持大型应用程序有组织性更好。

为了我们的目的，我们可以将所有状态存储在我们的`App`组件中，并将其传递给子组件。与其将我们的消息存储在`ChatContainer`中，不如将它们存储在`App`中并传递给`ChatContainer`。这立即给了我们一个优势，也可以将它们传递给`UserContainer`。

换句话说，我们的消息存储在`App`的状态中，并通过`props`与`UserContainer`和`ChatContainer`共享。

状态是你的应用程序中的唯一真相，并且不应该重复。在`ChatContainer`和`UserContainer`中存储两个消息数组是没有意义的。相反，将状态保持在必要的高度，并将其传递下去。

长话短说，我们需要在`App`中加载我们的消息，然后将它们传递给`ChatContainer`。将`App`负责发送消息也是有道理的，这样我们所有的消息功能都在一个地方。

让我们从发送我们的第一条消息开始！

# 创建一条消息

与我们的`LoginContainer`一样，我们需要在状态中存储`textarea`的值随着其变化。

我们使用`LoginContainer`的状态来存储该值。让我们在`ChatContainer`中也这样做。

在前面的讨论之后，你可能会想：为什么我们不把所有状态都保存在`App`中呢？有人会主张这种方法，把所有东西都放在一个地方；然而，这将使我们的`App`组件变得臃肿，并要求我们在组件之间传递多个`props`。最好将状态保持在必要的高度，而不是更高；在聊天输入中的新消息只有在完成并提交后才与`App`相关，而在此之前并不相关。

让我们开始设置它。

将此添加到`ChatContainer.js`：

```jsx
state = { newMessage: '' };
```

还要添加一个处理它的方法：

```jsx
handleInputChange = e => {
  this.setState({ newMessage: e.target.value });
};
```

现在，修改我们的`textarea`：

```jsx
<textarea
    placeholder="Add your message..."
    onChange={this.handleInputChange}
    value={this.state.newMessage} 
/>
```

最佳实践说，当 JSX 元素具有两个以上的`props`（或`props`特别长）时，应该将其多行化。

当用户点击发送时，我们希望将消息发送给`App`，然后`App`会将其发送到 Firebase。之后，我们重置字段：

```jsx
handleSubmit = () => {
   this.props.onSubmit(this.state.newMessage);
   this.setState({ newMessage: ‘’ });
};
```

我们还没有在`App`中添加这个`onSubmit`属性函数，但我们很快就可以做到：

```jsx
<button onClick={this.handleSubmit}>
  <svg viewBox="0 0 24 24">
    <path fill="#424242" d="M2,21L23,12L2,3V10L17,12L2,14V21Z" />
  </svg>
</button>
```

然而，我们也希望让用户通过按下*Enter*来提交。我们该怎么做呢？

目前，我们监听`textarea`上的更改事件，然后调用`handleInputChange`方法。在`textarea`上监听其值的更改的属性是`onChange`，但还有另一个事件，即按键按下事件，每当用户按下键时都会发生。

我们可以监听该事件，然后检查按下了什么键；如果是*Enter*，我们就发送我们的消息！

让我们看看它的效果：

```jsx
<textarea
    placeholder="Add your message..."
    onChange={this.handleInputChange}
    onKeyDown={this.handleKeyDown}
    value={this.state.newMessage} />
```

以下是这个事件的处理程序：

```jsx
handleKeyDown = e => {
  if (e.key === 'Enter') {
    e.preventDefault();
    this.handleSubmit();
  }
}
```

事件处理程序（`handleKeyDown`）会自动传入一个事件作为第一个参数。这个事件有一个名为`key`的属性，它是一个指示按键值的字符串。在提交消息之前，我们还需要阻止默认行为（在`textarea`中创建新行）。

你可以使用这种类型的事件监听器来监听各种用户输入，从悬停在元素上到按住 Shift 键点击某物。

在我们转到`App.js`之前，这是`ChatContainer`的当前状态：

```jsx
import React, { Component } from 'react';
import Header from './Header';

export default class ChatContainer extends Component {
  state = { newMessage: '' };

  handleLogout = () => {
    firebase.auth().signOut();
  };

  handleInputChange = e => {
    this.setState({ newMessage: e.target.value });
  };

  handleSubmit = () => {
    this.props.onSubmit(this.state.newMessage);
    this.setState({ newMessage: '' });
  };

  handleKeyDown = e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      this.handleSubmit();
    }
  };

  render() {
    return (
      <div id="ChatContainer" className="inner-container">
        <Header>
          <button className="red" onClick={this.handleLogout}>
            Logout
          </button>
        </Header>
        <div id="message-container" />
        <div id="chat-input">
          <textarea
            placeholder="Add your message..."
            onChange={this.handleInputChange}
            onKeyDown={this.handleKeyDown}
            value={this.state.newMessage}
          />
          <button onClick={this.handleSubmit}>
            <svg viewBox="0 0 24 24">
              <path fill="#424242" d="M2,21L23,12L2,3V10L17,12L2,14V21Z" />
            </svg>
          </button>
        </div>
      </div>
    );
  }
}
```

好的，让我们添加最后一个链接来创建一条消息。在`App.js`中，我们需要为`onSubmit`事件添加一个处理程序，然后将其作为属性传递给`ChatContainer`：

```jsx
// in App.js
handleSubmitMessage = msg => {
  // Send to database
  console.log(msg);
};
```

我们想要将一个等于这个方法的`onSubmit`属性传递给`ChatContainer`，但等一下，我们当前渲染的`ChatContainer`如下：

```jsx
<Route exact path="/" component={ChatContainer} />
```

`ChatContainer`本身是我们`Route`上的一个属性。我们怎么能给`ChatContainer`任何`props`呢？

事实证明，React Router 提供了三种在`Route`内部渲染组件的不同方法。最简单的方法是我们之前选择的路由（哈哈），将其作为名为`component`的属性传递进去。

对于我们的目的来说，还有另一种更好的方法——一个名为`render`的属性，我们通过它传递一个返回我们组件的函数。

在`Route`内部渲染组件的第三种方法是通过一个名为`children`的属性，它接受一个带有`match`参数的函数，该参数根据`path`属性是否与浏览器的 URL 匹配而定义或为 null。函数返回的 JSX 始终被渲染，但您可以根据`match`参数进行修改。

让我们将我们的`Route`切换到这种方法：

```jsx
<Route
  exact
  path="/"
  render={() => <ChatContainer onSubmit={this.handleSubmitMessage} />}
/>
```

前面的例子使用了一个带有隐式返回的 ES6 箭头函数。这与写`() => { return <ChatContainer onSubmit={this.handleSubmitMessage} /> }`或者在 ES5 中写`function() { return <ChatContainer onSubmit={this.handleSubmitMessage} /> }`是一样的。

现在，我们可以将所有我们喜欢的 props 传递给`ChatContainer`。

让我们确保它有效。尝试发送一条消息，并确保你在`App.js`的`handleSubmit`中添加的`console.log`。

如果是这样，太好了！是时候进入好部分了--实际发送消息。

# 向 Firebase 发送消息

要写入 Firebase 数据库，首先我们要获取一个实例，使用`firebase.database()`。类似于`firebase.auth()`，这个实例带有一些内置方法可以使用。

在本书中，我们将处理的是`firebase.database().ref(refName)`。`Ref`代表**引用**，但更好地理解它可能是我们数据的一个类别（在 SQL 数据库中，可能构成一个表）。

如果我们想要获取对我们用户的引用，我们使用`firebase.database().ref(‘/users’)`。对于消息，就是`firebase.database().ref(‘/messages’)`...等等。现在，我们可以以各种方式对这个引用进行操作，比如监听变化（稍后在本章中介绍），或者推送新数据（我们现在要处理）。

要向引用添加新数据，可以使用`firebase.database().ref(‘/messages’).push(data)`。在这个上下文中，可以将`ref`看作一个简单的 JavaScript 数组，我们向其中推送新数据。

Firebase 会接管，将数据保存到 NoSQL 数据库，并向应用程序的所有实例推送一个“value”事件，稍后我们将利用这一点。

# 我们的消息数据

当然，我们希望将消息文本保存到数据库，但我们也希望保存更多的信息。

我们的用户需要能够看到谁发送了消息（最好是电子邮件地址），并能够导航到他们的`users/:id`页面。因此，我们需要保存消息作者的电子邮件地址以及唯一的用户 ID。让我们再加上一个`timestamp`以确保万无一失：

```jsx
// App.js
handleSubmitMessage = msg => {
  const data = {
    msg,
    author: this.state.user.email,
    user_id: this.state.user.uid,
    timestamp: Date.now()
  };
  // Send to database
}
```

前面的例子使用了 ES6 的属性简写来表示消息字段。我们可以简单地写`{ msg }`，而不是`{ msg: msg }`。

在这里，我们利用了将当前用户保存到`App`组件状态中的事实，并从中获取电子邮件和 uid（唯一 ID）。然后，我们使用`Date.now()`创建一个`timestamp`。

好的，让我们发送出去！：

```jsx
handleSubmitMessage = (msg) => {
  const data = {
    msg,
    author: this.state.user.email,
    user_id: this.state.user.uid,
    timestamp: Date.now()
  };
  firebase
      .database()
      .ref('messages/')
      .push(data);
}
```

在我们测试之前，让我们打开 Firebase 控制台[console.firebase.google.com](http://console.firebase.google.com)并转到数据库选项卡。在这里，我们可以实时查看我们的数据库数据的表示，以便检查我们的消息是否被正确创建。

现在，它应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00040.jpeg)

让我们在聊天输入框中输入一条消息，然后按**Enter**。

你应该立即在 Firebase 控制台上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00041.jpeg)

太棒了！我们发送了我们的第一条聊天消息，但是在我们的应用中没有显示任何内容。让我们来解决这个问题。

# 从 Firebase 加载数据

正如我们之前所描述的，我们可以监听数据库中特定引用的更改。换句话说，我们可以定义一个函数，以便在`firebase.database().ref(‘/messages’)`发生更改时运行，就像新消息进来一样。

在我们继续之前，我鼓励你考虑两件事情：我们应该在哪里定义这个监听器，以及这个函数应该做什么。

看看你能否想出一个可能的实现！在你构思了一个想法之后，让我们来实现它。

事实上：我们的应用程序中已经有一个非常相似的情况。我们的`App#componentDidMount`中的`firebase.auth().onAuthStateChanged`监听当前用户的更改，并更新我们`App`的`state.user`。

我们将用我们的消息引用做同样的事情，尽管语法有点不同：

```jsx
class App extends Component {
  state = { user: null, messages: [] }

  componentDidMount() {
    firebase.auth().onAuthStateChanged((user) => {
      if (user) {
        this.setState({ user });
      } else {
       this.props.history.push('/login')
      }
    });
    firebase
 .database()
 .ref('/messages')
 .on('value', snapshot => {
 console.log(snapshot);
 });
  }
```

我们使用`.on`函数来监听数据库中的`'value'`事件。然后我们的回调被称为一个叫做`snapshot`的参数。让我们把这个插入进去，然后发送另一条消息，看看我们的快照是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00042.jpeg)

啊，这不太友好开发者。

快照是数据库结构`/messages`的一个图像。我们可以通过调用`val()`来访问一个更可读的形式：

```jsx
firebase.database().ref('/messages').on('value', snapshot => {
  console.log(snapshot.val());
});
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00043.jpeg)

现在，我们可以得到一个包含每条消息的对象，其中消息 ID 是键。

在这里，我们需要做一些技巧。我们想用消息数组更新我们的`state.messages`，但我们想要将消息 ID 添加到消息对象中（因为消息 ID 目前是`snapshot.val()`中的键）。

如果这听起来让人困惑，希望当我们看到它实际运行时会更清楚。我们将创建一个名为`messages`的新数组，并遍历我们的对象（使用一个叫做`Object.keys`的方法），然后将带有 ID 的消息推入新数组中。

让我们将这个提取到一个新的函数中：

```jsx
class App extends Component {
  state = { user: null, messages: [] }

  componentDidMount() {
    firebase.auth().onAuthStateChanged((user) => {
      if (user) {
        this.setState({ user });
      } else {
       this.props.history.push('/login')
      }
    });
    firebase
      .database()
      .ref('/messages')
      .on('value', snapshot => {
        this.onMessage(snapshot);
      });
  }
```

还有新的方法：

```jsx
  onMessage = snapshot => {
    const messages = Object.keys(snapshot.val()).map(key => {
      const msg = snapshot.val()[key];
      msg.id = key;
      return msg;
    });
    console.log(messages);
  };
```

在我们的 `console.log` 中，我们最终得到了一个带有 ID 的消息数组：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00044.jpeg)

最后一步是将其保存到状态中：

```jsx
onMessage = (snapshot) => {
  const messages = Object.keys(snapshot.val()).map(key => {
    const msg = snapshot.val()[key]
    msg.id = key
    return msg
  });
  this.setState({ messages });
}
```

现在，我们可以将消息传递给 `ChatContainer`，并开始显示它们：

```jsx
<Route
  exact
  path="/"
  render={() => (
    <ChatContainer
      onSubmit={this.handleSubmitMessage}
      messages={this.state.messages}
    />
  )}
/>
```

我们对 `App.js` 进行了许多更改。以下是当前的代码：

```jsx
import React, { Component } from 'react';
import { Route, withRouter } from 'react-router-dom';
import LoginContainer from './LoginContainer';
import ChatContainer from './ChatContainer';
import UserContainer from './UserContainer';
import './app.css';

class App extends Component {
  state = { user: null, messages: [] };

  componentDidMount() {
    firebase.auth().onAuthStateChanged(user => {
      if (user) {
        this.setState({ user });
      } else {
        this.props.history.push('/login');
      }
    });
    firebase
      .database()
      .ref('/messages')
      .on('value', snapshot => {
        this.onMessage(snapshot);
      });
  }

  onMessage = snapshot => {
    const messages = Object.keys(snapshot.val()).map(key => {
      const msg = snapshot.val()[key];
      msg.id = key;
      return msg;
    });
    this.setState({ messages });
  };

  handleSubmitMessage = msg => {
    const data = {
      msg,
      author: this.state.user.email,
      user_id: this.state.user.uid,
      timestamp: Date.now()
    };
    firebase
      .database()
      .ref('messages/')
      .push(data);
  };

  render() {
    return (
      <div id="container">
        <Route path="/login" component={LoginContainer} />
        <Route
          exact
          path="/"
          render={() => (
            <ChatContainer
              onSubmit={this.handleSubmitMessage}
              messages={this.state.messages}
            />
          )}
        />
        <Route path="/users/:id" component={UserContainer} />
      </div>
    );
  }
}

export default withRouter(App);
```

# 显示我们的消息

我们将使用 `Array.map()` 函数来遍历我们的消息数组，并创建一个 `div` 数组来显示数据。

`Array.map()` 自动返回一个数组，这意味着我们可以将该功能嵌入到我们的 JSX 中。这是 React 中的一个常见模式（通常用于显示这样的数据集合），因此值得密切关注。

在我们的 `message-container` 中，我们创建了开头和结尾的花括号：

```jsx
<div id="message-container">
  {

  }
</div>
```

然后，我们在消息数组上调用 `map`，并传入一个函数来创建新的消息 `div`：

```jsx
<div id="message-container">
  {this.props.messages.map(msg => (
    <div key={msg.id} className="message">
      <p>{msg.msg}</p>
    </div>
  ))}
</div>
```

如果一切顺利，你应该看到以下内容，包括你发送的所有消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00045.jpeg)

你甚至可以尝试写一条新消息，然后立即看到它出现在消息容器中。神奇！

关于前面的代码，有几点需要注意：

+   `map` 函数遍历消息数组中的每个元素，并根据其数据创建一个 `div`。当迭代完成时，它会返回一个 `div` 数组，然后作为 JSX 的一部分显示出来。

+   React 的一个怪癖是，屏幕上的每个元素都需要一个唯一的标识符，以便 React 可以正确地更新它。当处理一组相同的元素时，这对 React 来说很困难，就像我们在这里创建的一样。因此，我们必须给每个消息 `div` 一个保证是唯一的 key 属性。

有关列表和键的更多信息，请访问 [`facebook.github.io/react/docs/lists-and-keys.html`](https://facebook.github.io/react/docs/lists-and-keys.html)。

让我们增加一些功能，并在消息下方显示作者姓名，并附带到他们的用户页面的链接。我们可以使用 React Router 的 `Link` 组件来实现；它类似于锚标签（`<a>`），但针对 React Router 进行了优化：

```jsx
import { Link } from 'react-router-dom';
```

然后，在下面添加它：

```jsx
<div id="message-container">
  {this.props.messages.map(msg => (
    <div key={msg.id} className="message">
      <p>{msg.msg}</p>
      <p className="author">
 <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
 </p>
    </div>
  ))}
</div>
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00046.jpeg) `Link` 上的 `to` 属性使用了 ES6 字符串插值。如果你用反引号包裹你的字符串（`` ` ``）而不是引号，您还可以使用`${VARIABLE}`将变量直接嵌入其中。

现在，我们将使我们的消息看起来更好！

# 消息显示改进

在我们转向用户资料页之前，让我们花点时间对消息显示进行一些快速的UI改进。

# 多个用户

如果你尝试注销并使用新用户登录，所有用户的消息都会显示出来，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00047.jpeg)

我的消息和其他用户的消息之间没有区分。经典的聊天应用程序模式是将一个用户的消息放在一侧，另一个用户的消息放在另一侧。我们的CSS已经准备好处理这一点——我们只需要为与当前用户匹配的消息分配“mine”类。

由于我们在`msg.author`中可以访问消息作者的电子邮件，我们可以将其与`App`状态中存储的用户进行比较。让我们将它作为道具传递给`ChatContainer`：

```jsx
<Route
  exact
  path="/"
  render={() => (
    <ChatContainer
      onSubmit={this.handleSubmitMessage}
      user={this.state.user}
      messages={this.state.messages}
    />
  )}
/>
```

然后，我们可以在我们的`className`属性中添加一个条件：

```jsx
<div id="message-container">
  {this.props.messages.map(msg => (
    <div
      key={msg.id}
      className={`message ${this.props.user.email === msg.author &&
 'mine'}`}>
      <p>{msg.msg}</p>
      <p className="author">
        <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
      </p>
    </div>
  ))}
</div>
```

这使用了ES6字符串插值以及短路评估来创建我们想要的效果。这些是花哨的术语，归结为这一点：如果消息作者与`state`中的用户电子邮件匹配，将`className`设置为`message mine`；否则，将其设置为`message`。

它最终应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00048.jpeg)

# 批量显示用户消息

在前面的截图中，你会注意到我们甚至在连续两条消息由同一作者发送时也显示了作者电子邮件。让我们变得狡猾，使得我们将同一作者的消息分组在一起。

换句话说，我们只希望在下一个消息不是由同一作者发送时显示作者电子邮件：

```jsx
<div id="message-container">
  {this.props.messages.map(msg => (
    <div
      key={msg.id}
      className={`message ${this.props.user.email === msg.author &&
        'mine'}`}>
      <p>{msg.msg}</p>
 // Only if the next message's author is NOT the same as this message's    author, return the following:      <p className="author">
        <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
      </p>
    </div>
  ))}
</div>
```

我们如何做到这一点？我们需要一种方法来检查数组中当前消息之后的下一个消息。

幸运的是，`Array.map()`函数将索引作为第二个元素传递给我们的回调函数。我们可以像这样使用它：

```jsx
<div id="message-container">
  {this.props.messages.map((msg, i) => (
    <div
      key={msg.id}
      className={`message ${this.props.user.email === msg.author &&
        'mine'}`}>
      <p>{msg.msg}</p>
      {(!this.props.messages[i + 1] ||
 this.props.messages[i + 1].author !== msg.author) && (
 <p className="author">
 <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
 </p>
 )}
    </div>
  ))}
</div>
```

现在，我们说的是：“如果有下一个消息，并且下一个消息的作者与当前消息的作者不同，显示这个消息的作者。”

然而，在我们的`render`方法中有大量复杂的逻辑。让我们将其提取到一个方法中：

```jsx
<div id="message-container">
  {this.props.messages.map((msg, i) => (
    <div
      key={msg.id}
      className={`message ${this.props.user.email === msg.author &&
        'mine'}`}>
      <p>{msg.msg}</p>
      {this.getAuthor(msg, this.props.messages[i + 1])}
    </div>
  ))}
</div>
```

还有，方法本身：

```jsx
  getAuthor = (msg, nextMsg) => {
    if (!nextMsg || nextMsg.author !== msg.author) {
      return (
        <p className="author">
          <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
        </p>
      );
    }
  };
```

我们的消息现在这样分组：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00049.jpeg)

# 向下滚动

尝试缩小你的浏览器，使消息列表几乎被截断；然后，提交另一条消息。请注意，如果消息超出了消息容器的截断位置，你必须滚动才能看到它。这是糟糕的用户体验。让我们改进它，使得当新消息到达时，我们自动滚动到底部。

在本节中，我们将深入探讨两个强大的React概念：`componentDidUpdate`方法和refs。

让我们先讨论我们想要实现的目标。我们希望消息容器始终滚动到底部，以便最新消息始终可见（除非用户决定向上滚动查看旧消息）。这意味着我们需要在两种情况下使消息容器向下滚动：

+   当第一个组件被渲染时

+   当新消息到达时

让我们从第一个用例开始。我们需要一个我们已经使用过的React生命周期方法。我们将在我们的`ChatContainer`中添加一个`componentDidMount`方法，就像我们在`App`中所做的那样。

让我们来定义它，以及一个`scrollToBottom`方法：

```jsx
export default class ChatContainer extends Component {
  state = { newMessage: '' };

  componentDidMount() {
    this.scrollToBottom();
  }

  scrollToBottom = () => {

  };
```

我们还希望每当新消息到达并出现在屏幕上时触发`scrollToBottom`方法。React为我们提供了另一种处理这种情况的方法——`componentDidUpdate`。每当您的React组件因新的`props`或状态而更新时，都会调用此方法。最好的部分是该方法将前一个`props`作为第一个参数传递，因此我们可以比较它们并找出差异，如下所示：

```jsx
componentDidUpdate(previousProps) {
  if (previousProps.messages.length !== this.props.messages.length) {
    this.scrollToBottom();
  }
}
```

我们查看前一个`props`中的消息数组长度，并与当前`props`中的消息数组长度进行比较。如果它发生了变化，我们就滚动到底部。

好的，看起来都不错。让我们继续让我们的`scrollToBottom`方法工作起来。

# React refs

React中的refs是一种获取特定DOM元素的方式。对于熟悉jQuery的人来说，refs弥合了React通过props创建元素的方法与jQuery从DOM中获取元素并操作它们的方法之间的差距。

我们可以在任何我们想要稍后使用的JSX元素上添加一个`ref`（我们想要稍后引用的元素）。让我们在我们的消息容器上添加一个。`ref`属性总是一个函数，该函数被调用时带有相关元素，然后用于将该元素分配给组件的属性，如下所示：

```jsx
<div
  id="message-container"
  ref={element => {
    this.messageContainer = element;
  }}>
```

在我们的`scrollToBottom`方法内部，我们使用`ReactDOM.findDOMNode`来获取相关元素（别忘了导入react-dom！）：

```jsx
import ReactDOM from 'react-dom';
```

```jsx

scrollToBottom = () => {
  const messageContainer = ReactDOM.findDOMNode(this.messageContainer);
}
```

在下一节中，我们将使得只有在消息加载时才显示我们的消息容器。为此，我们需要一个`if`语句来检查我们的`messageContainer` DOM节点当前是否存在。一旦完成这一步，我们就可以将`messageContainer.scrollTop`（当前滚动到底部的距离）设置为其高度，以便它位于底部：

```jsx
scrollToBottom = () => {
  const messageContainer = ReactDOM.findDOMNode(this.messageContainer);
  if (messageContainer) {
    messageContainer.scrollTop = messageContainer.scrollHeight;
  }
}
```

现在，如果你尝试缩小浏览器窗口并发送一条消息，你应该总是被带到消息容器的底部，以便它自动进入视图。太棒了！

# 加载指示器

Firebase加载速度相当快，但如果我们的用户连接速度较慢，他们将看到一个空白屏幕，直到他们的消息加载完毕，并会想：“我所有的精彩聊天都去哪儿了？”让我们给他们一个加载指示器。

在我们的`ChatContainer`内部，我们只希望在名为`messagesLoaded`的prop为true时显示消息（我们稍后会定义它）。我们将根据该prop的条件来渲染我们的消息容器。我们可以使用一个**三元**运算符来实现这一点。

JavaScript中的三元运算符是一种简短的if-else写法。我们可以写成`true ? // 这段代码 : // 那段代码`，而不是`if (true) { // 这段代码 } else { // 那段代码 }`，这样既简洁又明了。

代码如下所示：

```jsx
// Beginning of ChatContainer
<Header>
  <button className="red" onClick={this.handleLogout}>
    Logout
  </button>
</Header>
{this.props.messagesLoaded ? (
  <div
    id="message-container"
    ref={element => {
      this.messageContainer = element;
    }}>
    {this.props.messages.map((msg, i) => (
      <div
        key={msg.id}
        className={`message ${this.props.user.email === msg.author &&
          'mine'}`}>
        <p>{msg.msg}</p>
        {this.getAuthor(msg, this.props.messages[i + 1])}
      </div>
    ))}
  </div>
) : (
 <div id="loading-container">
 <img src="img/icon.png" alt="logo" id="loader" />
 </div>
)}
<div id="chat-input">
// Rest of ChatContainer
```

花点时间仔细阅读这个，确保你完全理解正在发生的事情。条件语句在React中很常见，因为它们使得条件渲染JSX变得容易。如果一切正确，你应该看到以下内容，带有到标志的脉冲动画：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00050.jpeg)

下一步是在消息加载时更新`messagesLoaded`属性。让我们跳到`App.js`。

这里的逻辑很简单——当我们从Firebase数据库接收到一个消息值时，如果我们之前没有收到过值（换句话说，这是我们收到的第一条消息），我们就知道我们的消息已经首次加载：

```jsx
class App extends Component {
  state = { user: null, messages: [], messagesLoaded: false };
```

```jsx
componentDidMount() {
    firebase.auth().onAuthStateChanged(user => {
      if (user) {
        this.setState({ user });
      } else {
        this.props.history.push('/login');
      }
    });
    firebase
      .database()
      .ref('/messages')
      .on('value', snapshot => {
        this.onMessage(snapshot);
        if (!this.state.messagesLoaded) {
 this.setState({ messagesLoaded: true });
 }
      });
  }
```

```jsx
<Route exact path="/" render={() => (
  <ChatContainer
    messagesLoaded={this.state.messagesLoaded}
    onSubmit={this.handleSubmitMessage}
    messages={this.state.messages}
    user={this.state.user} />
)} />
```

现在，如果你重新加载应用页面，你应该会短暂看到加载指示器（取决于你的互联网连接），然后看到消息显示出来。

这里是到目前为止`ChatContainer`的代码：

```jsx
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import ReactDOM from 'react-dom';
import Header from './Header';

export default class ChatContainer extends Component {
  state = { newMessage: '' };

  componentDidMount() {
    this.scrollToBottom();
  }

  componentDidUpdate(previousProps) {
    if (previousProps.messages.length !== this.props.messages.length) {
      this.scrollToBottom();
    }
  }

  scrollToBottom = () => {
    const messageContainer = ReactDOM.findDOMNode(this.messageContainer);
    if (messageContainer) {
      messageContainer.scrollTop = messageContainer.scrollHeight;
    }
  };

  handleLogout = () => {
    firebase.auth().signOut();
  };

  handleInputChange = e => {
    this.setState({ newMessage: e.target.value });
  };

  handleSubmit = () => {
    this.props.onSubmit(this.state.newMessage);
    this.setState({ newMessage: '' });
  };

  handleKeyDown = e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      this.handleSubmit();
    }
  };

  getAuthor = (msg, nextMsg) => {
    if (!nextMsg || nextMsg.author !== msg.author) {
      return (
        <p className="author">
          <Link to={`/users/${msg.user_id}`}>{msg.author}</Link>
        </p>
      );
    }
  };

  render() {
    return (
      <div id="ChatContainer" className="inner-container">
        <Header>
          <button className="red" onClick={this.handleLogout}>
            Logout
          </button>
        </Header>
        {this.props.messagesLoaded ? (
          <div
            id="message-container"
            ref={element => {
              this.messageContainer = element;
            }}>
            {this.props.messages.map((msg, i) => (
              <div
                key={msg.id}
                className={`message ${this.props.user.email ===       
                                                    msg.author &&
                  'mine'}`}>
                <p>{msg.msg}</p>
                {this.getAuthor(msg, this.props.messages[i + 1])}
              </div>
            ))}
          </div>
        ) : (
          <div id="loading-container">
            <img src="img/icon.png" alt="logo" id="loader" />
          </div>
        )}
        <div id="chat-input">
          <textarea
            placeholder="Add your message..."
            onChange={this.handleInputChange}
            onKeyDown={this.handleKeyDown}
            value={this.state.newMessage}
          />
          <button onClick={this.handleSubmit}>
            <svg viewBox="0 0 24 24">
              <path fill="#424242"  
                d="M2,21L23,12L2,3V10L17,12L2,14V21Z" />
            </svg>
          </button>
        </div>
      </div>
    );
  }
}
```

我们的应用已经接近完成。最后一步是用户资料页面。

# 个人资料页面

对于`UserContainer`的代码将与`ChatContainer`相同，有两个主要区别：

+   我们只想显示与我们从URL参数中获取的ID匹配的消息数组中的消息

+   我们想在页面顶部显示作者的电子邮件，在任何其他消息之前

首先，在`App.js`中，将`UserContainer`路由转换为使用`render`属性，与`ChatContainer`相同，并传递以下属性：

```jsx
<Route
  path="/users/:id"
  render={({ history, match }) => (
    <UserContainer
      messages={this.state.messages}
      messagesLoaded={this.state.messagesLoaded}
      userID={match.params.id}
    />
  )}
/>
```

请注意，React Router自动在我们的`render`方法中提供了历史和匹配`props`，我们在这里使用它们来从URL参数中获取用户ID。

然后，在`UserContainer`中，让我们设置我们的加载指示器。同时，确保你给`UserContainer`一个`className`的`inner-container`用于CSS目的：

```jsx
<div id="UserContainer" className="inner-container">
  <Header>
    <Link to="/">
      <button className="red">Back To Chat</button>
    </Link>
  </Header>
  {this.props.messagesLoaded ? (
 <h1>Messages go here</h1>
 ) : (
 <div id="loading-container">
 <img src="img/icon.png" alt="logo" id="loader" />
 &lt;/div>
 )}
</div>
```

对于显示我们的消息，我们只想显示那些`msg.user_id`等于我们的`props.userID`的消息。我们可以不用`Array.map()`的回调，只需添加一个`if`语句：

```jsx
{this.props.messagesLoaded ? (
 <div id="message-container">
 {this.props.messages.map(msg => {
 if (msg.user_id === this.props.userID) {
 return (
 <div key={msg.id} className="message">
 <p>{msg.msg}</p>
 </div>
 );
 }
 })}
 </div>
) : (
  <div id="loading-container">
    <img src="img/icon.png" alt="logo" id="loader" />
  </div>
)}
```

这应该只显示来自我们正在查看其资料的作者的消息。然而，我们现在需要在顶部显示作者的电子邮件。

挑战在于，我们不会知道用户电子邮件，直到我们已经加载了消息，并且在迭代第一个匹配ID的消息，所以我们不能像之前那样使用`map()`的索引，也不能使用属性。

相反，我们将添加一个`class`属性来跟踪我们是否已经显示了用户电子邮件。

在`UserContainer`顶部声明它：

```jsx
export default class UserContainer extends Component {
  renderedUserEmail = false;

  render() {
    return (
```

然后，我们将在代码中调用一个`getAuthor`方法：

```jsx
<div id="message-container">
  {this.props.messages.map(msg => {
    if (msg.user_id === this.props.userID) {
      return (
        <div key={msg.id} className="message">
          {this.getAuthor(msg.author)}
          <p>{msg.msg}</p>
        </div>
      );
    }
  })}
</div>
```

这个检查是为了看看我们是否已经渲染了作者，如果没有，就返回它：

```jsx
  getAuthor = author => {
    if (!this.renderedUserEmail) {
      this.renderedUserEmail = true;
      return <p className="author">{author}</p>;
    }
  };
```

有点绕路——对于我们的生产应用程序，我们可能想要添加更复杂的逻辑来只加载那个作者的消息。然而，这对于我们的原型来说已经足够了。

这里是`UserContainer`的完整代码：

```jsx
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import Header from './Header';

export default class UserContainer extends Component {
  renderedUserEmail = false;

  getAuthor = author => {
    if (!this.renderedUserEmail) {
      this.renderedUserEmail = true;
      return <p className="author">{author}</p>;
    }
  };

  render() {
    return (
      <div id="UserContainer" className="inner-container">
        <Header>
          <Link to="/">
            <button className="red">Back To Chat</button>
          </Link>
        </Header>
        {this.props.messagesLoaded ? (
          <div id="message-container">
            {this.props.messages.map(msg => {
              if (msg.user_id === this.props.userID) {
                return (
                  <div key={msg.id} className="message">
                    {this.getAuthor(msg.author)}
                    <p>{msg.msg}</p>
                  </div>
                );
              }
            })}
          </div>
        ) : (
          <div id="loading-container">
            <img src="img/icon.png" alt="logo" id="loader" />
          </div>
        )}
      </div>
    );
  }
}
```

# 总结

就是这样！我们已经建立了完整的 React 应用程序。你的朋友对最终产品感到非常高兴，但我们还远未完成。

我们已经建立了一个网络应用程序。它看起来很不错，但它还不是一个渐进式网络应用程序。还有很多工作要做，但这就是乐趣开始的地方。

我们的下一步是开始将这个应用程序转换成 PWA。我们将从研究如何使我们的网络应用程序更像本地应用程序开始，并深入研究近年来最激动人心的网络技术之一--service workers。
