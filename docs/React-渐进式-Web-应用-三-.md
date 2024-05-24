# React 渐进式 Web 应用（三）

> 原文：[`zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D`](https://zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：添加服务工作者

欢迎来到我们迈向渐进式 Web 应用程序世界的第一步。本章将致力于创建我们的第一个服务工作者，这将解锁使 PWA 如此特别的许多功能。

我们之前已经谈到过 PWA 是如何连接 Web 应用和原生应用的。它们通过服务工作者来实现这一点。服务工作者使推送通知和离线访问等功能成为可能。它们是一种令人兴奋的新技术，有许多应用（每年都有越来越多的新应用出现）；如果有一种技术能在未来五年内改变 Web 开发，那就是服务工作者。

然而，足够的炒作；让我们深入了解服务工作者到底是什么。

在本章中，我们将涵盖以下主题：

+   什么是服务工作者？

+   服务工作者的生命周期

+   如何在我们的页面上注册服务工作者

# 什么是服务工作者？

**服务工作者**是一小段 JavaScript 代码，位于我们的应用和网络之间。

你可以把它想象成在我们的应用程序之外运行的脚本，但我们可以在我们的代码范围内与其通信。它是我们应用的一部分，但与其余部分分开。

最简单的例子是在缓存文件的上下文中（我们将在接下来的章节中探讨）。比如说，当用户导航到[`chatastrophe.com`](https://chatastrophe.com)时，我们的应用会获取我们的`icon.png`文件。

服务工作者，如果我们配置好了，将会位于我们的应用和网络之间。当我们的应用请求图标文件时，服务工作者会拦截该请求并检查本地缓存中是否有该文件。如果找到了，就返回该文件；不会进行网络请求。只有在缓存中找不到文件时，才会让网络请求通过；下载完成后，它会将文件放入缓存中。

你可以看到“工作者”这个术语是从哪里来的--我们的服务工作者就像一只忙碌的小蜜蜂。

让我们再看一个例子；推送通知（第九章的预览，*使用清单使我们的应用可安装*）。大多数推送通知都是这样工作的--当发生某个事件（用户发送新的聊天消息）时，消息服务会被通知（在我们的情况下，消息服务由 Firebase 管理）。消息服务会向相关注册用户发送通知（这些用户通过他们的设备进行注册），然后他们的设备创建通知（叮咚！）。

在 Web 应用程序的情况下，这种流程的问题在于，当用户不在页面上时，我们的应用程序会停止运行，因此除非他们的应用程序已经打开，否则我们将无法通知他们，这完全违背了推送通知的初衷。

Service workers 通过始终处于“开启”状态并监听消息来解决了这个问题。现在，消息服务可以提醒我们的 service worker，后者向用户显示消息。我们的应用程序代码实际上并没有参与其中，因此它是否运行并不重要。

这是令人兴奋的事情，但是对于任何新技术来说，都存在一些问题，需要注意一些事情。

# service worker 的生命周期

当用户首次访问您的页面时，service worker 的生命周期就开始了。service worker 被下载并开始运行。当不需要时，它可能会空闲一段时间，但在需要时可以重新启动。

这种**始终开启**的功能是使 service workers 对推送通知有用的原因。它也使 service workers 有点不直观（稍后会详细介绍）。然而，让我们深入了解典型页面上 service worker 的生死。

首先，如果可能的话，service worker 会被安装。所有 service worker 的安装都将从检查用户浏览器是否支持该技术开始。截至目前，Firefox、Chrome 和 Opera 都提供了全面支持，其他浏览器则没有。例如，苹果认为 service workers 是**实验性技术**，这表明他们对整个事情仍然持观望态度。

如果用户的浏览器足够现代化，安装就会开始。脚本（例如`sw.js`）将在特定范围内安装（或者说注册）。在这种情况下，“范围”指的是它所关注的网站路径。例如，全局范围将采用`'/'`，即网站上的所有路径，但您也可以将 service worker 限制为`'/users'`，例如，仅缓存应用程序的某些部分。我们将在缓存章节中更多地讨论范围。

注册后，service worker 被激活。激活事件也会在需要 service worker 时发生，例如，当推送通知到来时。service worker 的激活和停用意味着您不能在 service worker 中保持状态；它只是对事件的反应而运行的一小段代码，而不是一个完整的应用程序。这是一个重要的区别需要记住，以免我们对我们的工作人员要求过多。

服务工作者将处于空闲状态，直到发生事件。目前，服务工作者对两个事件做出反应：`fetch`事件（也称为应用程序的网络请求）和`message`（也称为应用程序代码或消息服务的交互）。我们可以在服务工作者中为这些事件注册监听器，然后根据需要做出反应。

服务工作者代码将在两种情况下更新：已经过去了 24 小时（在这种情况下，它会停止并重新下载一个方法，以防止损坏的代码引起太多烦恼），或者用户访问页面并且`sw.js`文件已更改。每当用户访问应用程序时，服务工作者将其当前代码与站点提供的`sw.js`进行比较，如果有一丁点的差异，就会下载并注册新的`sw.js`。

这是服务工作者的基本技术概述以及它们的工作原理。这可能看起来很复杂，但好消息是使用服务工作者相对直接；您可以在几分钟内启动一个简单的服务工作者，这正是我们接下来要做的！

# 注册我们的第一个服务工作者

记住服务工作者的区别--它们是我们网站的一部分，但在我们的应用程序代码之外运行。考虑到这一点，我们的服务工作者将位于`public/文件夹`中，而不是`src/文件夹`中。

然后，在`public/文件夹`中创建一个名为`sw.js`的文件。现在我们将保持简单；只需在其中添加一个`console.log`：

```jsx
console.log("Service worker running!");
```

真正的工作（注册服务工作者）将在我们的`index.html`中完成。对于这个过程，我们想要做以下事情：

1.  检查浏览器是否支持服务工作者。

1.  等待页面加载。

1.  注册服务工作者。

1.  登出结果。

让我们一步一步地进行。首先，在我们的 Firebase 初始化下面，在`public/index.html`中创建一个空的`script`标签：

```jsx
<body>
  <div id="root"></div>
  <script src="/secrets.js"></script>
  <script src="https://www.gstatic.com/firebasejs/4.1.2/firebase.js"></script>
  <script>
    // Initialize Firebase
    var config = {
      apiKey: window.apiKey,
      authDomain: "chatastrophe-77bac.firebaseapp.com",
      databaseURL: "https://chatastrophe-77bac.firebaseio.com",
      projectId: "chatastrophe-77bac",
      storageBucket: "chatastrophe-77bac.appspot.com",
      messagingSenderId: "85734589405"
    }; 
    window.firebase = firebase;
    firebase.initializeApp(config);
  </script>
  <script>
 // Service worker code here.
 </script>
```

# 检查浏览器支持情况

检查用户的浏览器是否支持服务工作者非常容易。在我们的脚本标签中，我们将添加一个简单的`if`语句：

```jsx
<script>
  if ('serviceWorker' in navigator) {
    // register
  } else {
    console.log('service worker is not supported');
  }
</script>
```

在这里，我们检查`window.navigator`对象是否支持任何服务工作者。导航器还可以使用（通过其`userAgent`属性）来检查用户使用的浏览器，尽管我们在这里不需要。

# 监听页面加载

在页面加载完成之前，我们不想注册我们的 service worker；这没有意义，而且可能会导致复杂性，因此我们将为窗口添加一个`'load'`事件的事件侦听器：

```jsx
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {

    });
  } else {
    console.log('service worker is not supported');
  }
</script>
```

# 注册 service worker

正如我们之前指出的，`window.navigator`有一个`serviceWorker`属性，其存在确认了浏览器对 service worker 的支持。我们还可以使用同一个对象通过其`register`函数来注册我们的 service worker。我知道，这是令人震惊的事情。

我们调用`navigator.serviceWorker.register`，并传入我们的 service worker 文件的路径：

```jsx
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
      navigator.serviceWorker.register('sw.js')
    });
  } else {
    console.log('service worker is not supported');
  }
</script>
```

# 记录结果

最后，让我们添加一些`console.logs`，这样我们就知道注册的结果。幸运的是，`navigator.serviceWorker.register`返回一个 promise：

```jsx
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
      navigator.serviceWorker.register('sw.js').then(function(registration) {
        // Registration was successful
        console.log('Registered!');
      }, function(err) {
        // registration failed :(
        console.log('ServiceWorker registration failed: ', err);
      }).catch(function(err) {
        console.log(err);
      });
    });
  } else {
    console.log('service worker is not supported');
  }
</script>
```

好的，让我们测试一下！重新加载页面，如果一切正常，您应该在控制台中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00051.jpeg)

您还可以通过导航到 DevTools 中的应用程序选项卡，然后转到服务工作者选项卡来检查它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00052.jpeg)

我建议您此时检查重新加载按钮。这样可以确保每次刷新页面时都刷新您的 service worker（记住我们之前讨论的正常 service worker 生命周期）。为什么要采取这种预防措施？我们正在步入缓存代码的世界，浏览器可能会认为您的 service worker 没有改变，而实际上已经改变了。这个复选框只是确保您始终处理最新版本的`sw.js`。

好的，我们已经注册了一个 worker！太棒了。让我们花点时间从我们的`sw.js`中了解 service worker 的生命周期。

# 体验 service worker 生命周期

service worker 体验的第一个事件是`'install'`事件。这是用户第一次启动 PWA 时发生的。标准用户只会经历一次。

要利用这个事件，我们只需要在 service worker 本身添加一个事件侦听器。要在`sw.js`中执行这个操作，我们使用`self`关键字：

```jsx
self.addEventListener('install', function() {
 console.log('Install!');
});
```

当您重新加载页面时，您应该在控制台中看到`'Install!'`出现。事实上，除非您在应用程序|服务工作者下取消选中重新加载选项，否则每次重新加载页面时都应该看到它。然后，您只会在第一次看到它。

接下来是`activate`事件。此事件在服务工作者首次注册时触发，注册完成之前。换句话说，它应该在相同的情况下发生，只是稍后：

```jsx
self.addEventListener('activate', function() {
  console.log('Activate!');
});
```

我们要覆盖的最后一个事件是`'fetch'`事件。每当应用程序发出网络请求时，都会调用此事件。它与一个具有请求 URL 的事件对象一起调用，我们可以将其记录出来：

```jsx
self.addEventListener('fetch', function(event) {
  console.log('Fetch!', event.request);
});
```

添加后，我们应该看到一个非常混乱的控制台：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00053.jpeg)

您现在可以删除服务工作者中的所有`console.logs`，但是我们将在将来使用这些事件监听器中的每一个。

接下来，我们将研究如何连接到 Firebase 消息服务，为推送通知奠定基础。

# 将 Firebase 添加到我们的服务工作者

本章的其余部分目标是将 Firebase 集成到我们的服务工作者中，以便它准备好接收推送通知并显示它们。

这是一个大项目。在下一章结束之前，我们将无法实际显示推送通知。然而，在这里，我们将看到如何将第三方服务集成到服务工作者中，并深入了解服务工作者背后的理论。

# 命名我们的服务工作者

我们将用于向用户设备发送推送通知的服务称为**Firebase Cloud Messaging**，或**FCM**。FCM 通过寻找服务工作者在网络上运行，然后向其发送消息（包含通知详情）。然后服务工作者显示通知。

默认情况下，FCM 会寻找一个名为`firebase-messaging-sw.js`的服务工作者。您可以使用`firebase.messaging().useServiceWorker`来更改，然后传递一个服务工作者注册对象。然而，为了我们的目的，简单地重命名我们的服务工作者会更直接。让我们这样做；在`public/`中更改文件名，并在`index.html`中更改注册：

```jsx
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
      navigator.serviceWorker.register('firebase-messaging-sw.js').then(function(registration) {
        // Registration was successful
        console.log('Registered!');
      }, function(err) {
        // registration failed :(
        console.log('ServiceWorker registration failed: ', err);
      }).catch(function(err) {
        console.log(err);
      });
    });
   } else {
     console.log('service worker is not supported');
   }
</script>
```

完成后，我们可以开始在服务工作者中初始化 Firebase。

让我们再说一遍；服务工作者与您的应用程序代码没有关联。这意味着它无法访问我们当前的 Firebase 初始化。但是，我们可以在服务工作者中重新初始化 Firebase，并且只保留相关的内容--`messagingSenderId`。您可以从 Firebase 控制台或您的`secrets.js`文件中获取您的`messagingSenderId`。

如果您担心安全性，请确保将`public/firebase-messaging-sw.js`添加到您的`.gitignore`中，尽管保持您的`messagingSenderId`私有性并不像保持 API 密钥秘密那样重要。

```jsx
// firebase-messaging-sw.js
firebase.initializeApp({
  'messagingSenderId': '85734589405'
});
```

我们还需要在文件顶部导入我们需要的 Firebase 部分，包括`app`库和`messaging`库：

```jsx
importScripts('https://www.gstatic.com/firebasejs/3.9.0/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/3.9.0/firebase-messaging.js');
```

完成后，我们应该能够`console.log`出`firebase.messaging();`：

```jsx
importScripts('https://www.gstatic.com/firebasejs/3.9.0/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/3.9.0/firebase-messaging.js');
firebase.initializeApp({
  'messagingSenderId': '85734589405'
});console.log(firebase.messaging());
```

您应该看到以下内容：

*！[](../images/00054.jpeg)*

这意味着我们的 Firebase 已经在我们的服务工作者中运行起来了！

如果您仍然看到来自我们旧的`sw.js`的日志，请转到 DevTools 的**应用程序|服务工作者**选项卡，并**取消注册**它。这是服务工作者即使未重新注册也会持续存在的一个很好的例子。

正如前面所解释的，服务工作者是一段始终运行的代码（虽然不完全准确--想想这些工作者的生命周期--这是一个很好的思考方式）。这意味着它将始终等待 FCM 告诉它有消息进来。

但是，现在我们没有收到任何消息。下一步是开始配置何时发送推送通知，以及如何显示它们！

# 摘要

在本章中，我们学习了服务工作者的基础知识，并使其运行起来。我们的下一步是开始使用它。具体来说，我们希望使用它来监听通知，然后将它们显示给用户。通过设置推送通知，让我们再迈出一大步，使我们的 PWA 感觉像一个原生应用程序。


# 第八章：使用服务工作者发送推送通知

在本章中，我们将完成我们应用程序发送推送通知的过程。这个实现有点复杂；它需要许多移动的部分来使事情正常运行（根据我的经验，这对于任何移动或网络上的推送通知实现都是真实的）。令人兴奋的部分是我们可以与许多新的知识领域互动，比如**设备令牌**和**云函数**。

在我们开始之前，让我们花一分钟概述设置推送通知的过程。目前，我们的消息服务工作者已经启动并运行。这个服务工作者将坐在那里等待被调用以显示新通知。一旦发生这种情况，它将处理所有与显示通知有关的事情，所以我们不必担心（至少目前是这样）。

由我们负责的是将消息发送给服务工作者。假设我们的应用程序有 1,000 个用户，每个用户都有一个唯一的设备。每个设备都有一个唯一的令牌，用于将其标识给 Firebase。我们需要跟踪所有这些令牌，因为当我们想要发送通知时，我们需要告诉 Firebase 要发送到哪些设备。

所以，这是第一步 - 设置和维护一个包含我们应用程序使用的所有设备令牌的数据库表。正如我们将看到的，这也必然涉及询问用户是否首先想要通知。

一旦我们保存了我们的令牌，我们就可以告诉 Firebase 监听数据库中的新消息，然后向所有设备（基于令牌）发送消息详细信息的通知。作为一个小的额外复杂性，我们必须确保不向创建消息的用户发送通知。

这个阶段（告诉 Firebase 发送通知）实际上是在我们的应用程序之外进行的。它发生在神秘的“云”中，我们将在那里托管一个函数来处理这个过程；稍后会详细介绍。

我们对这个相当复杂的工程方法将是慢慢来，一次一个部分。确保你仔细跟随代码示例；通知的性质意味着在实现完全之前我们将无法完全测试我们的实现，所以尽力避免途中的小错误。

在本章中，我们将涵盖以下主题：

+   请求显示通知的权限

+   跟踪和保存用户令牌

+   使用云函数发送通知

好了，让我们开始吧！

# 请求权限

正如前面的介绍所解释的，我们在这一章中有很多功能要创建。为了将所有内容放在一个地方，而不会使我们的`App.js`混乱，我们将创建一个单独的 JavaScript 类来管理与通知有关的一切。这是我在 React 中非常喜欢的一种模式，可以提取与任何一个组件无关的功能。在我们的`src/`文件夹中，紧挨着我们的`components`文件夹，让我们创建一个名为`resources`的文件夹，在其中创建一个名为`NotificationResource.js`的文件。

我们的类的基本轮廓如下：

```jsx
export default class NotificationResource {

}
```

我们创建一个 JavaScript 类并导出它。

对于那些不熟悉 JavaScript 类的人（特别是那些熟悉其他语言中的类的人），我鼓励你阅读 MDN 的文章，解释了基础知识，网址为[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes)。

在我们忘记之前，让我们在`App.js`中导入它：

```jsx
import NotificationResource from '../resources/NotificationResource';
```

当我们的应用启动时，我们希望请求用户权限发送通知给他们。请注意，Firebase 会记住用户是否已经接受或拒绝了我们的请求，因此我们不会每次都用弹出窗口打扰他们，只有在他们之前没有被问过的情况下才会这样做。

以下是我们将如何处理这个过程：

1.  当我们的应用挂载时，我们将创建一个`NotificationResource`类的新实例，将 Firebase 消息库传递给它（我们将这个传递进去是为了避免我们不得不在`NotificationResource.js`文件中导入它，因为我们已经在`App.js`中有了对它的访问）。

1.  当`NotificationResource`类首次实例化时，我们将立即使用传递进来的 Firebase 消息库请求用户权限。

如果这些步骤对你来说很清楚，我鼓励你首先尝试自己实现它们。如果你完全困惑于我们将如何做到这一点，不要担心，我们会一一讲解。

好的，让我们从我们的 App 的`componentDidMount`开始。这是我们想要创建`NotificationResource`实例的地方：

```jsx
componentDidMount() {
   this.notifications = new NotificationResource();
```

我们将`NotificationResource`实例设置为`App`的属性；这将允许我们在`App.js`中的其他地方访问它。

正如我们之前所说，我们还希望传入 Firebase 消息库：

```jsx
componentDidMount() {
   this.notifications = new NotificationResource(firebase.messaging());
```

每个 JavaScript 类都自动具有一个`constructor`方法，当创建一个实例时会调用该方法。这就是当我们说`new NotificationResource()`时会调用的方法。我们放在括号里的任何内容都作为参数传递给构造函数。

让我们跳回到`NotificationResource.js`并设置它：

```jsx
export default class NotificationResource {
  constructor(messaging) {
    console.log(“Instantiated!”);
  }
}
```

如果您启动您的应用程序，您应该在`App`挂载时立即在控制台中看到`"Instantiated!"`。

下一步是使用我们的`messaging`库来请求用户的权限发送通知：

```jsx
export default class NotificationResource {
     constructor(messaging) {
       this.messaging = messaging;
 try {
 this.messaging
 .requestPermission()
 .then(res => {
 console.log('Permission granted');
 })
 .catch(err => {
 console.log('no access', err);
 });
 } catch(err) {
 console.log('No notification support.', err);
 }
} } 
```

我们用`messaging`库在`App`中做了与`NotificationResource`相同的事情，也就是将其保存为资源的属性，以便我们可以在其他地方使用它。然后，我们进入`requestPermission`函数。

如果我们回到我们的应用程序，我们会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00055.jpeg)

单击允许，您应该在控制台中看到权限已被授予。

如果您之前使用`localhost:8080`构建了个人项目并允许通知，您将不会看到此弹出窗口。您可以通过单击前面截图中 URL 左侧的图标，并将通知重置为询问，来忘记您之前的偏好设置。

现在我们有了开始跟踪所有用户设备的权限，我们将开始跟踪他们的所有设备令牌。

# 跟踪令牌

**令牌**是用户设备的唯一标识符。它帮助 Firebase 找出应该发送推送通知的位置。为了正确发送我们的通知，我们需要在我们的数据库中保留所有当前设备令牌的记录，并确保它是最新的。

我们可以通过 Firebase 的`messaging`库访问用户设备的令牌。特别有用的是两种方法：`onTokenRefresh`和`getToken`。两者的名称都相当不言自明，所以我们将直接进入实现：

```jsx
 export default class NotificationResource {
     constructor(messaging) {
       this.messaging = messaging;
      try {
        this.messaging
          .requestPermission()
          .then(res => {
            console.log('Permission granted');
          })
         .catch(err => {
          console.log('no access', err);
          });
      } catch(err) {
        console.log('No notification support.', err);
      }
};
   this.messaging.getToken().then(res => {
 console.log(res);
 });
 }

```

当您的应用程序刷新时，您会看到一长串数字和字母。这是您设备的身份。我们需要将其保存到数据库中。

每当令牌更改时，`firebase.messaging().onTokenRefresh`会被调用。令牌可以被我们的应用程序删除，或者当用户清除浏览器数据时，此时会生成一个新的令牌。当这种情况发生时，我们需要覆盖数据库中的旧令牌。关键部分是覆盖；如果我们不删除旧令牌，我们最终会浪费 Firebase 的时间，发送到不存在的设备。

因此，我们有四个步骤要涵盖：

1.  当令牌更改时，获取新令牌。

1.  在数据库中查找现有令牌。

1.  如果存在旧令牌，则替换它。

1.  否则，将新令牌添加到数据库中。

在完成此清单之前，我们将不得不完成一堆中间任务，但让我们先用这个粗略的计划开始。

我们将向我们的`NotificationResource`添加四个函数：`setupTokenRefresh`，`saveTokenToServer`，`findExistingToken`和`registerToken`。您可以看到最后两个函数与我们清单中的最后两个步骤相符。

让我们从`setupTokenRefresh`开始。我们将从构造函数中调用它，因为它将负责注册令牌更改的监听器：

```jsx
   export default class NotificationResource {
     constructor(messaging) {
       this.messaging = messaging;
      try {
        this.messaging
          .requestPermission()
          .then(res => {
            console.log('Permission granted');
          })
         .catch(err => {
          console.log('no access', err);
          });
      } catch(err) {
        console.log('No notification support.', err);
      }
  } 
} 
```

这种模式应该在我们配置了 Firebase 的所有“on”监听器后是熟悉的。

接下来，我们将创建`saveTokenToServer`，并从`setupTokenRefresh`中调用它：

```jsx
 setupTokenRefresh() {
   this.messaging.onTokenRefresh(() => {
     this.saveTokenToServer();
   });
 }

 saveTokenToServer() {
   // Get token
   // Look for existing token
   // If it exists, replace
   // Otherwise, create a new one
 }
```

好的，现在我们可以逐条浏览这些注释了。我们已经知道如何获取令牌：

```jsx
saveTokenToServer() {
   this.messaging.getToken().then(res => {
     // Look for existing token
     // If it exists, replace
     // Otherwise, create a new one
   });
 }
```

接下来，查找现有令牌；我们目前无法访问保存在我们的数据库中的先前令牌（好吧，目前还没有，但以后会有）。

因此，我们需要在数据库中创建一个表来保存我们的令牌。我们将其称为`fcmTokens`以方便。它目前还不存在，但一旦我们向其发送一些数据，它就会存在。这就是 Firebase 数据的美妙之处--您可以向一个不存在的表发送数据，它将被创建并填充。

就像我们在`App.js`中对消息所做的那样，让我们在`NotificationResource`的构造函数中为`/fcmTokens`表添加一个值的监听器：

```jsx
export default class NotificationResource {
  allTokens = [];
 tokensLoaded = false;

  constructor(messaging, database) {
    this.database = database;
    this.messaging = messaging;
         try {
        this.messaging
          .requestPermission()
          .then(res => {
            console.log('Permission granted');
          })
         .catch(err => {
          console.log('no access', err);
          });
      } catch(err) {
        console.log('No notification support.', err);
      }};
    this.setupTokenRefresh();
    this.database.ref('/fcmTokens').on('value', snapshot => {
 this.allTokens = snapshot.val();
 this.tokensLoaded = true;
 });
  }
```

您会注意到我们现在期望将数据库实例传递到构造函数中。让我们回到`App.js`来设置它：

```jsx
componentDidMount() {
   this.notifications = new NotificationResource(
      firebase.messaging(),
      firebase.database()
    );
```

好的，这很完美。

如果您在数据库监听器中`console.log`出`snapshot.val()`，它将为 null，因为我们的`/fcmTokens`表中没有值。让我们开始注册一个：

```jsx
saveTokenToServer() {
   this.messaging.getToken().then(res => {
     if (this.tokensLoaded) {
       const existingToken = this.findExistingToken(res);
       if (existingToken) {
         // Replace existing toke
       } else {
         // Create a new one
       }
     }
   });
 }
```

如果令牌已加载，我们可以检查是否存在现有令牌。如果令牌尚未加载，则不执行任何操作。这可能看起来有点奇怪，但我们希望确保不创建重复的值。

我们如何找到现有的令牌？嗯，在我们的构造函数中，我们将从数据库中加载令牌值的结果保存到`this.allTokens`中。我们只需循环遍历它们，看看它们是否与从`getToken`生成的`res`变量匹配即可：

```jsx
findExistingToken(tokenToSave) {
   for (let tokenKey in this.allTokens) {
     const token = this.allTokens[tokenKey].token;
     if (token === tokenToSave) {
       return tokenKey;
     }
   }
   return false;
 }
```

这个方法的重要部分是`tokenToSave`将是一个字符串（之前看到的随机数字和字母的组合），而`this.allTokens`将是从数据库加载的令牌对象的集合，因此是`this.allTokens[tokenObject].token`的业务。

`findExistingToken`将返回与之匹配的令牌对象的键，或 false。从那里，我们可以更新现有的令牌对象，或者创建一个新的。当我们尝试更新令牌时，我们将看到为什么返回键（而不是对象本身）很重要。

# 将用户附加到令牌

在继续涵盖这两种情况之前，让我们退一步，思考一下我们的推送通知将如何工作，因为我们需要解决一个重要的警告。

当用户发送消息时，我们希望通知每个用户，除了创建消息的用户（那将是令人恼火的），因此我们需要一种方法来向数据库中的每个令牌发送通知，除了属于发送消息的用户的令牌。

我们将如何能够防止这种情况发生？我们如何将用户的消息与用户的令牌匹配起来？

好吧，我们可以在消息对象中访问用户 ID（也就是说，我们总是保存 ID 和消息内容）。如果我们对令牌做类似的操作，并保存用户 ID，这样我们就可以确定哪个用户属于哪个设备了。

这似乎是一个非常简单的解决方案，但这意味着我们需要在`NotificationResource`中访问当前用户的 ID。让我们立即做到这一点，然后回到编写和更新令牌。

# 在 NotificationResource 中更改用户

我们已经有一个处理用户更改的方法在`App.js`中——我们的老朋友`onAuthStateChanged`。让我们连接到那里，并使用它来调用`NotificationResource`中的一个方法：

```jsx
componentDidMount() {
   this.notifications = new NotificationResource(firebase.messaging(), firebase.database());
  firebase.auth().onAuthStateChanged((user) => {
     if (user) {
       this.setState({ user });
       this.listenForMessages();
       this.notifications.changeUser(user);
     } else {
       this.props.history.push('/login')
     }
   });
```

然后，在`NotificationResource`中：

```jsx
changeUser(user) {
   this.user = user;
 }
```

顺便说一下，这有助于解决令牌的另一个问题。如前所述，当生成新令牌时会调用`onTokenRefresh`，要么是因为用户删除了浏览器数据，要么是因为 Web 应用程序删除了先前的令牌。但是，如果我们将用户 ID 与令牌一起保存，我们需要确保在用户更改时更新该 ID，因此我们将不得不在用户更改时调用我们的`saveTokenToServer`方法：

```jsx
changeUser(user) {
   this.user = user;
   this.saveTokenToServer();
 }
```

好的，现在我们可以回到`saveTokenToServer`中的`if`-`else`语句，并开始保存一些令牌。

# 创建一个新令牌

让我们从涵盖后一种情况开始，创建一个新的令牌。我们将创建一个名为`registerToken`的新方法，传入`getToken`调用的结果：

```jsx
saveTokenToServer() {
   this.messaging.getToken().then(res => {
     if (this.tokensLoaded) {
       const existingToken = this.findExistingToken(res);
       if (existingToken) {
         // Replace existing token
       } else {
         this.registerToken(res);
       }
     }
   });
 }
```

然后，我们的新方法：

```jsx
  registerToken(token) {
    firebase
      .database()
      .ref('fcmTokens/')
      .push({
        token: token,
        user_id: this.user.uid
      });
  }
```

我们保存令牌，以及用户 ID。完美。

# 更新现有令牌

我们将类似的方法用于更新令牌，但这次我们需要访问数据库中的现有令牌。

在这里添加一个`console.log`以进行测试：

```jsx
saveTokenToServer() {
   this.messaging.getToken().then(res => {
     if (this.tokensLoaded) {
       const existingToken = this.findExistingToken(res);
       if (existingToken) {
         console.log(existingToken);
       } else {
         this.registerToken(res);
       }
     }
   });
 }
```

然后，尝试使用不同的用户登录和退出应用程序。您应该每次看到相同的`existingToken`键：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00056.jpeg)

我们可以使用这个来获取我们数据库中`fcmToken`表中的现有条目，并更新它：

```jsx
saveTokenToServer() {
  this.messaging.getToken().then(res => {
    if (this.tokensLoaded) {
      const existingToken = this.findExistingToken(res);
      if (existingToken) {
        firebase
 .database()
 .ref(`/fcmTokens/${existingToken}`)
 .set({
 token: res,
 user_id: this.user.uid
 });
      } else {
        this.registerToken(res);
      }
    }
  });
}
```

好了，这是很多内容。让我们再次确认这是否正常工作。转到`console.firebase.com`并检查数据库选项卡。尝试使用两个不同的用户登录和退出应用程序。您应该看到匹配的令牌条目每次更新其用户 ID。然后，尝试在另一台设备上登录（在进行另一个 firebase deploy 之后），然后看到另一个令牌出现。神奇！

现在，我们为使用我们的应用程序的每个设备都有一个令牌表，以及上次与该设备关联的用户的 ID。我们现在准备进入推送通知的最佳部分--实际发送它们。

这是最终的`NotificationResource.js`：

```jsx
export default class NotificationResource {
  allTokens = [];
  tokensLoaded = false;
  user = null;

  constructor(messaging, database) {
    this.messaging = messaging;
    this.database = database;
          try {
        this.messaging
          .requestPermission()
          .then(res => {
            console.log('Permission granted');
          })
         .catch(err => {
          console.log('no access', err);
          });
      } catch(err) {
        console.log('No notification support.', err);
      };
    this.setupTokenRefresh();
    this.database.ref('/fcmTokens').on('value', snapshot => {
      this.allTokens = snapshot.val();
      this.tokensLoaded = true;
    });
  }

  setupTokenRefresh() {
    this.messaging.onTokenRefresh(() => {
      this.saveTokenToServer();
    });
  }

  saveTokenToServer() {
    this.messaging.getToken().then(res => {
      if (this.tokensLoaded) {
        const existingToken = this.findExistingToken(res);
        if (existingToken) {
          firebase
            .database()
            .ref(`/fcmTokens/${existingToken}`)
            .set({
              token: res,
              user_id: this.user.uid
            });
        } else {
          this.registerToken(res);
        }
      }
    });
  }

  registerToken(token) {
    firebase
      .database()
      .ref('fcmTokens/')
      .push({
        token: token,
        user_id: this.user.uid
      });
  }

  findExistingToken(tokenToSave) {
    for (let tokenKey in this.allTokens) {
      const token = this.allTokens[tokenKey].token;
      if (token === tokenToSave) {
        return tokenKey;
      }
    }
    return false;
  }

  changeUser(user) {
    this.user = user;
    this.saveTokenToServer();
  }
}
```

# 发送推送通知

回到本书的开头，当我们初始化 Firebase 时，我们勾选了一个 Functions 选项。这在我们的根目录中创建了一个名为`functions`的文件夹，到目前为止我们已经忽略了它（如果你没有这个文件夹，你可以再次运行`firebase init`，并确保你在第一个问题上都勾选了 Functions 和 Hosting。参考 Firebase 章节了解更多信息）。

`functions`文件夹允许我们使用 Firebase 云函数。这是 Google 如何定义它们的方式：

“Cloud Functions 允许开发人员访问 Firebase 和 Google Cloud 事件，以及可扩展的计算能力来运行响应这些事件的代码。”

这是最简单的定义--在事件发生时运行的代码，超出我们的应用程序之外。我们从我们的应用程序的任何特定实例中提取一些不属于任何特定实例的功能（因为它涉及我们应用程序的所有实例）到云端，并让 Firebase 自动运行它。

让我们打开`functions /index.js`并开始工作。

# 编写我们的云函数

首先，我们可以初始化我们的应用程序，如下所示：

```jsx
const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);
```

云函数=响应事件的代码，那么我们的事件是什么？

我们希望在创建新消息时通知用户。因此，事件是一个新消息，或者更具体地说，是在我们数据库的消息表中创建新条目时。

我们将定义我们的`index.js`的导出为一个名为`sendNotifications`的函数，该函数定义了`/messages`的`onWrite`事件的监听器：

```jsx
exports.sendNotifications = functions.database
  .ref('/messages/{messageId}')
  .onWrite(event => {});
```

本节中的其他所有内容将在事件监听器中进行。

首先，我们从事件中获取快照：

```jsx
 const snapshot = event.data;
```

现在，我们不支持编辑消息；但将来可能会支持。在这种情况下，我们不希望推送通知，因此如果`onWrite`由更新触发（快照具有先前值），我们将提前返回：

```jsx
const snapshot = event.data;
if (snapshot.previous.val()) {
   return;
 }
```

然后，我们将构建我们的通知。我们定义了一个带有嵌套通知对象的对象，其中包含`title`、`body`、`icon`和`click_action`：

```jsx
const payload = {
   notification: {
     title: `${snapshot.val().author}`,
     body: `${snapshot.val().msg}`,
     icon: 'assets/icon.png',
     click_action: `https://${functions.config().firebase.authDomain}`
   }
 };
```

`title`来自与消息关联的用户电子邮件。`body`是消息本身。这两者都包裹在模板字符串中，以确保它们作为字符串输出。这只是一个安全措施！

然后，我们使用我们的应用图标作为通知的图标。请注意路径--图标实际上并不存在于我们的`functions`文件夹中，但由于它将部署到我们应用的根目录（在`build`文件夹中），我们可以引用它。

最后，我们的`click_action`应该将用户带到应用程序。我们通过我们的配置获取域 URL。

下一步是向相关设备发送有效负载。准备好，这将是一大块代码。

# 发送到令牌

让我们写出我们需要采取的步骤：

1.  获取我们数据库中所有令牌的列表。

1.  筛选该列表，仅保留不属于发送消息的用户的令牌。

1.  向设备发送通知。

1.  如果由于无效或未注册的令牌而导致任何设备无法接收通知，则从数据库中删除它们的令牌。

最后一步是定期从我们的数据库中删除无效令牌，以保持清洁。

好的，听起来很有趣。请记住，这一切都在`onWrite`的事件监听器中。以下是第一步：

```jsx
return admin
      .database()
      .ref('fcmTokens')
      .once('value')
      .then(allTokens => {
        if (allTokens.val()) {

        }
      });
```

这使用数据库的`.once`方法来一次性查看令牌表。从那里，如果我们实际上保存了一些令牌，我们就可以继续进行。

为了过滤我们的结果，我们将执行一个与我们的`findExistingToken`方法非常相似的循环：

```jsx
.then(allTokens => {
  if (allTokens.val()) {
    const tokens = [];
 for (let fcmTokenKey in allTokens.val()) {
 const fcmToken = allTokens.val()[fcmTokenKey];
 if (fcmToken.user_id !== snapshot.val().user_id) {
 tokens.push(fcmToken.token);
 }
 }
  }
});
```

我们循环遍历所有令牌，如果`user_id`与消息的`user_id`不匹配，我们将其推送到有效令牌数组中。

到了第三步了；向每个设备发送通知，如下所示：

```jsx
.then(allTokens => {
  if (allTokens.val()) {
    const tokens = [];
    for (let fcmTokenKey in allTokens.val()) {
      const fcmToken = allTokens.val()[fcmTokenKey];
      if (fcmToken.user_id !== snapshot.val().user_id) {
        tokens.push(fcmToken.token);
      }
    }
    if (tokens.length > 0) {
 return admin
 .messaging()
 .sendToDevice(tokens, payload)
 .then(response => {});
 }
  }
});
```

这很简单。我们向`sendToDevice`传递一个令牌数组和我们的有效负载对象。

最后，让我们进行清理：

```jsx
if (tokens.length > 0) {
  return admin
    .messaging()
    .sendToDevice(tokens, payload)
    .then(response => {
      const tokensToRemove = [];
 response.results.forEach((result, index) => {
 const error = result.error;
 if (error) {
 console.error(
 'Failure sending notification to',
 tokens[index],
 error
 );
 if (
 error.code === 'messaging/invalid-registration-token' ||
 error.code ===
 'messaging/registration-token-not-registered'
 ) {
 tokensToRemove.push(
 allTokens.ref.child(tokens[index]).remove()
 );
 }
 }
 });
 return Promise.all(tokensToRemove);
 });
}
```

这段代码应该很容易查看，除了可能会返回`Promise.all`。原因是在每个令牌条目上调用`remove()`会返回一个 promise，我们只需返回所有这些 promise 的解析。

这是最终文件：

```jsx
const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp(functions.config().firebase);

exports.sendNotifications = functions.database
  .ref('/messages/{messageId}')
  .onWrite(event => {
    const snapshot = event.data;
    if (snapshot.previous.val()) {
      return;
    }
    const payload = {
      notification: {
        title: `${snapshot.val().author}`,
        body: `${snapshot.val().msg}`,
        icon: 'assets/icon.png',
        click_action: `https://${functions.config().firebase.authDomain}`
      }
    };
    return admin
      .database()
      .ref('fcmTokens')
      .once('value')
      .then(allTokens => {
        if (allTokens.val()) {
          const tokens = [];
          for (let fcmTokenKey in allTokens.val()) {
            const fcmToken = allTokens.val()[fcmTokenKey];
            if (fcmToken.user_id !== snapshot.val().user_id) {
              tokens.push(fcmToken.token);
            }
          }
          if (tokens.length > 0) {
            return admin
              .messaging()
              .sendToDevice(tokens, payload)
              .then(response => {
                const tokensToRemove = [];
                response.results.forEach((result, index) => {
                  const error = result.error;
                  if (error) {
                    console.error(
                      'Failure sending notification to',
                      tokens[index],
                      error
                    );
                    if (
                      error.code === 'messaging/invalid-registration-token' ||
                      error.code ===
                        'messaging/registration-token-not-registered'
                    ) {
                      tokensToRemove.push(
                        allTokens.ref.child(tokens[index]).remove()
                      );
                    }
                  }
                });
                return Promise.all(tokensToRemove);
              });
          }
        }
      });
  });
```

# 测试我们的推送通知

运行`**yarn deploy**`，然后我们可以测试我们的推送通知。

测试它的最简单方法是简单地打开我们部署的应用程序的一个标签，然后在隐身标签中打开另一个版本（使用 Chrome）。用不同的用户登录到每个标签，当你发送一条消息时，你应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00057.jpeg)

请注意，你不能同时拥有两个标签；你需要打开两个标签，但切换到另一个标签，否则通知不会显示。

# 调试推送通知

如果你遇到任何问题，你可以尝试以下步骤。

# 检查云函数日志

登录到`console.firebase.com`后，在“函数”选项卡下，有一个显示每个函数执行的日志选项卡。任何错误都会显示在这里，还有我们配置的任何旧令牌删除。检查以确保 A）当你发送一条消息时函数实际上正在运行，B）没有干扰发送的任何错误。

# 检查服务工作者

正如我们之前所说，服务工作者应该在其大小的任何字节差异以及在 Chrome DevTools | Application 中检查“重新加载时更新”后更新。然而，即使有了这些步骤，我发现服务工作者经常在重新部署时实际上并没有更新。如果你遇到问题，请在 DevTools 的 Application | Service Workers 标签下的每个实例旁边点击注销。然后，点击每个服务工作者文件的名称，以确保代码与你的`build`文件夹中的代码匹配。

# 检查令牌

确保令牌在数据库中保存和更新正确。不应该有不同用户 ID 的重复。

# 总结

推送通知很棘手。在本章中，我们不得不写很多代码，但很少有基准可以在其中检查。如果你遇到问题，请确保你的所有代码与示例匹配。

一旦您的通知功能正常工作，我们将填补网络应用和本地应用之间的重要差距。现在，是时候迈向本地应用的世界，让用户可以安装我们的应用程序了。


# 第九章：使用清单使我们的应用程序可安装

我们现在开始走向渐进式 Web 应用程序领域。从现在开始，我们的唯一重点将是将我们现有的应用程序变得更快、更时尚和更用户友好。

渐进式 Web 应用程序的一个重要优势是弥合了 Web 应用程序（在浏览器中查看）和本地应用程序（作为独立应用程序启动）之间的差距。接下来的几章，特别是将专注于使我们的 Web 应用程序更像本地应用程序，而不失去 Web 应用程序的所有优势。

Web 应用程序相对于本地应用程序的第一个主要优势是没有安装障碍。如果你创建一个本地应用程序，你需要说服用户在甚至使用你的应用程序之前，投入宝贵的存储空间和带宽。他们必须愿意忍受下载和安装过程。然后他们必须保留它，即使他们并不经常使用它。

Web 应用程序没有这样的障碍。你几乎可以立即使用它们，而且最复杂的 Web 应用程序具有可以与本地应用程序媲美的功能。它们的缺点是什么？嗯，用户必须先导航到他们的浏览器，然后再导航到网页才能使用它。他们没有漂亮整洁的应用程序存在的提醒，从他们手机的主屏幕上盯着他们。

什么是双赢的最佳选择？它将是一个允许用户在安装到他们的设备之前先试用的应用程序，但一旦安装后，它会像本地应用程序一样运行，并在设备的主屏幕上显示图标。

我们如何实现这一点？我们可以通过一个 Web 应用程序清单来实现。

在本章中，我们将涵盖以下内容：

+   什么是 Web 应用程序清单？

+   如何使我们的应用程序可以在 Android 上安装

+   如何使我们的应用程序可以在 iOS 上安装

+   使用 Web 应用程序安装横幅

# 什么是应用程序清单？

在第二章，*使用 Webpack 入门*，当我们设置我们的 Webpack 构建配置时，我们确保我们的构建过程生成了一个资产清单，文件名为`asset-manifest.json`。

这个文件包含了我们的应用程序使用的 JavaScript 文件列表。如果我们愿意，我们可以配置它来列出我们使用的 CSS 和图像文件。

这个资产清单让我们了解了清单的用途--描述应用程序的某个部分。我们的 Web 应用清单类似，但简单地描述了我们的应用程序从更高层面上的全部内容，以一种类似于应用商店对本地应用的描述的方式。

这就是它的外观，随着我们构建文件，我们将更深入地了解，但 Web 应用清单的真正魔力在于它的功能。

在某些浏览器上（本章后面会详细介绍），如果您的 Web 应用包括一个合适的 Web 应用清单，用户可以选择将网页保存到主屏幕上，它会像一个常规应用程序一样出现，并带有自己的启动图标。当他们点击图标时，它将以闪屏启动，并且（尽管是从浏览器运行）以全屏模式运行，因此看起来和感觉像一个常规应用程序。

# 浏览器支持

这就是 Web 应用清单的缺点--它是一种新技术。因此，很少有浏览器实际支持它。截至目前，只有较新版本的安卓 Webview 和 Chrome for Android 具有完全支持。

我预测支持很快会到来，适用于所有新版浏览器，但目前我们该怎么办呢？

简而言之，有办法在旧版浏览器上激活类似的功能。在本章中，我们将介绍如何使用 Web 应用清单（适用于新版浏览器的用户，并为未来做准备）以及 iOS 设备的**polyfill**。

如果您有兴趣覆盖其他设备，可以使用 polyfills，比如**ManUp**（[`github.com/boyofgreen/manUp.js/`](https://github.com/boyofgreen/manUp.js/)）。这些 polyfills 的作用是将不同设备的各种解决方法编译成一个清单文件。

然而，本书是关于 Web 应用的未来，所以我们将向您展示一切您需要为 Web 应用清单的世界做准备。

# 使我们的应用可安装-安卓

谷歌是 PWA 的最大支持者之一，因此他们的 Chrome 浏览器和安卓操作系统对 Web 应用清单最为友好。

让我们通过创建一个清单的过程，以使其与最新版本的 Chrome 兼容。在本章后面，我们将以更手动的方式进行相同的过程，以支持 iOS。

# 清单属性

让我们开始吧！在您的`public/`文件夹中，创建一个名为`manifest.json`的文件，然后添加一个空对象。以下每个都将是该对象的键值对。我们将快速浏览一下每个可用属性：

+   `name`：您的应用程序名称。简单！：

```jsx
"name": "Chatastrophe",
```

+   `short_name`：您的应用程序名称的可读版本。这是在全名无法完全显示时使用，比如在用户的主屏幕上。如果您的应用程序名称是“为什么 PWA 对每个人都很棒”，您可以将其缩短为“PWAs R Great”或其他内容：

```jsx
“short_name”: “Chatastrophe”,
```

+   `icons`：用户设备使用的图标列表。我们将只使用我们当前的徽标，这恰好是图标所需的最大尺寸。

Google 推荐以下一组图标：

+   128x128 作为基本图标大小

+   152x152 适用于 Apple 设备

+   144x144 适用于 Microsoft 设备

+   192x192 适用于 Chrome

+   256x256、384x384 和 512x512 适用于不同的设备尺寸

最后两个包含在资产包中。我们需要我们的设计师为我们的生产版本创建其余部分，但目前还不需要：

```jsx
"icons": [
  {
    "src":"/assets/icon.png",
    "sizes": "192x192",
    "type": "image/png"
  },
  { 
    "src": "/assets/icon-256.png", 
    "sizes": "256x256", 
    "type": "image/png" 
  }, 
  { 
    "src": "/assets/icon-384.png", 
    "sizes": "384x384", 
    "type": "image/png" 
  }, 
  { 
    "src": "/assets/icon-512.png", 
    "sizes": "512x512", 
    "type": "image/png" 
  }
],
```

+   `start_url`：启动 URL 用于分析目的，以便您可以看到有多少用户通过安装的 PWA 访问您的 Web 应用程序。这是可选的，但不会有害。

```jsx
"start_url": "/?utm_source=homescreen",
```

+   `background_color`：背景颜色用于启动我们的应用程序时显示的闪屏的颜色。在这里，我们将其设置为一个漂亮的橙红色：

```jsx
"background_color": "#e05a47",
```

+   `theme_color`：这类似于`background_color`，但在您的应用程序处于活动状态时，它会为 Android 上的工具栏设置样式。一个不错的点缀：

```jsx
"theme_color": "#e05a47",
```

+   `display`：正如我们之前所说，PWA 可以像本机应用程序一样启动，即浏览器栏被隐藏；这就是这个属性的作用。如果您认为让用户能够看到地址栏更好，可以将其设置为“browser”：

```jsx
"display": "standalone"
```

# 其他属性

还有一些属性需要您了解我们的应用程序：

+   `related_applications`：您可以提供与您的 Web 应用程序相关的本机应用程序的列表，并附带下载的 URL；将其与`prefer_related_applications`配对使用。

+   `prefer_related_applications`：一个默认值为 false 的布尔值。如果为 true，则用户将收到有关相关应用程序的通知。

+   `scope`：一个字符串，比如`/app`。如果用户导航到范围之外的页面，应用程序将返回到浏览器中常规网页的外观。

+   `description`：您的应用程序的描述；不是强制性的。

+   `dir`：类型的方向。

+   `lang`：`short_name`的语言。与`dir`配对使用，可用于确保从右到左的语言正确显示。

# 链接我们的清单

就是这样！最后，您的`manifest.json`应该是这样的：

```jsx
{
  "name": "Chatastrophe",
  "short_name": "Chatastrophe",
  "icons": [
    {
      "src":"/assets/icon.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    { 
      "src": "/assets/icon-256.png", 
      "sizes": "256x256", 
      "type": "image/png" 
    }, 
    { 
      "src": "/assets/icon-384.png", 
      "sizes": "384x384", 
      "type": "image/png" 
    }, 
    { 
      "src": "/assets/icon-512.png", 
      "sizes": "512x512", 
      "type": "image/png" 
    }
  ],
  "start_url": "/?utm_source=homescreen",
  "background_color": "#e05a47",
  "theme_color": "#e05a47",
  "display": "standalone"
}
```

然后，您可以像这样从您的`index.html`中链接它：

```jsx
<link rel="manifest" href="/manifest.json">
```

确保您也将其复制到您的`build`文件夹中。

如果一切顺利，并且您使用的是最新版本的 Chrome，您可以通过转到 Chrome Dev Tools 中的“应用程序”选项卡来检查是否正常工作。确保首先重新启动服务器。您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00058.jpeg)

现在来测试一下吧！让我们再次运行我们的部署过程，使用**`yarn deploy`**。完成后，转到您的 Android 设备上的应用程序。为了触发 Web 应用程序安装横幅，您需要访问该站点两次，每次访问之间间隔五分钟：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00059.jpeg)

如果您没有看到安装横幅，您也可以通过转到选项下拉菜单并选择“添加到主屏幕”来安装它。

一旦您点击“添加到主屏幕”，您应该会看到它出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00060.jpeg)

然后，当我们启动时，我们会得到一个漂亮的启动画面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00061.jpeg)

这很可爱。

这就是为 Android 制作可安装的 PWA 的要点。这是一个非常简洁流畅的过程，这要感谢 Google 对 PWA 的倡导，但我们的许多用户无疑会使用 iPhone，因此我们也必须确保我们也支持他们。

# 使我们的应用可安装- iOS

截至撰写本文时，苹果尚未支持渐进式 Web 应用程序。关于这一点有许多理论（他们的盈利能力强大的 App Store 生态系统，与谷歌的竞争，缺乏控制），但这意味着使我们的应用可安装的过程要更加手动化。

让我们明确一点-截至目前，PWA 的最佳体验将是针对使用最新版本 Chrome 的 Android 设备用户。

然而，PWA 也是关于渐进式增强的，这是我们将在后面的章节中更深入地介绍的概念。渐进式增强意味着我们为每个用户在其设备上提供最佳的体验；如果他们可以支持所有新的功能，那很好，否则，我们会尽力利用他们正在使用的工具。

因此，让我们来看看如何使我们的 UX 对于想要将我们的应用保存到主屏幕的 iPhone 用户来说是愉快的。

我们将使用大量的`<meta>`标签来告诉浏览器我们的应用是可安装的。让我们从图标开始：

```jsx
<link rel="apple-touch-icon" href="/assets/icon.png">
```

将以下内容添加到`public/index.html`（在本节的其余部分中，将所有的`meta`标签分组放在`link`标签之上）。这定义了用户主屏幕上的图标。

接下来，我们为页面添加一个标题，这将作为主屏幕上应用程序的名称。在您的`link`标签之后添加这个：

```jsx
<title>Chatastrophe</title>
```

然后，我们需要让 iOS 知道这是一个 Web 应用程序。您可以使用以下`meta`标签来实现：

```jsx
<meta name="apple-mobile-web-app-capable" content="yes">
```

就像我们在 Android 部分中使用`theme_color`一样，我们希望样式化状态栏的外观。默认值是黑色，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00062.jpeg)

另一个选项是 black-translucent，它并不是非常黑，主要是半透明的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00063.jpeg)

使用以下内容添加：

```jsx
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
```

我们要做的最后一件事是设计启动画面；在应用程序启动时出现的内容。

在 iOS 上进行此操作有点手动--您需要提供一个静态图像。

为了完全支持，您需要为每个 iOS 屏幕尺寸提供单独的启动图像，从 iPad 到最小的 iPhone。如果您想看到多个启动图像和图标的绝佳示例，请查看[gist 链接](https://gist.github.com/tfausak/2222823)。这里包括了该 gist 中的启动图像链接：

```jsx
    <!-- iPad retina portrait startup image -->
    <link href="https://placehold.it/1536x2008"
          media="(device-width: 768px) and (device-height: 1024px)
                 and (-webkit-device-pixel-ratio: 2)
                 and (orientation: portrait)"
          rel="apple-touch-startup-image">

    <!-- iPad retina landscape startup image -->
    <link href="https://placehold.it/1496x2048"
          media="(device-width: 768px) and (device-height: 1024px)
                 and (-webkit-device-pixel-ratio: 2)
                 and (orientation: landscape)"
          rel="apple-touch-startup-image">

    <!-- iPad non-retina portrait startup image -->
    <link href="https://placehold.it/768x1004"
          media="(device-width: 768px) and (device-height: 1024px)
                 and (-webkit-device-pixel-ratio: 1)
                 and (orientation: portrait)"
          rel="apple-touch-startup-image">

    <!-- iPad non-retina landscape startup image -->
    <link href="https://placehold.it/748x1024"
          media="(device-width: 768px) and (device-height: 1024px)
                 and (-webkit-device-pixel-ratio: 1)
                 and (orientation: landscape)"
          rel="apple-touch-startup-image">

    <!-- iPhone 6 Plus portrait startup image -->
    <link href="https://placehold.it/1242x2148"
          media="(device-width: 414px) and (device-height: 736px)
                 and (-webkit-device-pixel-ratio: 3)
                 and (orientation: portrait)"
          rel="apple-touch-startup-image">

    <!-- iPhone 6 Plus landscape startup image -->
    <link href="https://placehold.it/1182x2208"
          media="(device-width: 414px) and (device-height: 736px)
                 and (-webkit-device-pixel-ratio: 3)
                 and (orientation: landscape)"
          rel="apple-touch-startup-image">

    <!-- iPhone 6 startup image -->
    <link href="https://placehold.it/750x1294"
          media="(device-width: 375px) and (device-height: 667px)
                 and (-webkit-device-pixel-ratio: 2)"
          rel="apple-touch-startup-image">

    <!-- iPhone 5 startup image -->
    <link href="https://placehold.it/640x1096"
          media="(device-width: 320px) and (device-height: 568px)
                 and (-webkit-device-pixel-ratio: 2)"
          rel="apple-touch-startup-image">

    <!-- iPhone < 5 retina startup image -->
    <link href="https://placehold.it/640x920"
          media="(device-width: 320px) and (device-height: 480px)
                 and (-webkit-device-pixel-ratio: 2)"
          rel="apple-touch-startup-image">

    <!-- iPhone < 5 non-retina startup image -->
    <link href="https://placehold.it/320x460"
          media="(device-width: 320px) and (device-height: 480px)
                 and (-webkit-device-pixel-ratio: 1)"
          rel="apple-touch-startup-image">
```

您可能注意到这些链接不包括任何 iPhone 6 Plus 之后的 iPhone。在撰写本文时，iOS 9 对启动图像的支持有问题，iOS 10 则不支持。虽然这不会影响您的应用程序的用户体验（启动画面本来也只能看一秒钟），但这表明了苹果对 PWA 的支持不完全。希望这在不久的将来会发生改变。

总的来说，将您的应用程序制作成 iOS 可安装的 Web 应用程序并不像`manifest.json`那样花哨或直观，但相当简单。使用**`yarn deploy`**重新部署您的应用程序，然后在 iPhone 上的 Safari 中打开网页。然后，点击分享并添加到主屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00064.jpeg)

它应该会出现在您的主屏幕上，就像普通的应用程序一样，并且在启动时会出现如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00063.jpeg)

这非常漂亮。

最终的`index.html`应该是这样的：

```jsx
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta charset="utf-8">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <link rel="shortcut icon" href="assets/favicon.ico" type="image/x-icon">
    <link rel="manifest" href="/manifest.json">
    <link rel="apple-touch-icon" href="/assets/icon.png">
    <title>Chatastrophe</title>
  </head>
  <body>
    <div id="root"></div>
    <script src="/secrets.js"></script>
    <script src="https://www.gstatic.com/firebasejs/4.3.0/firebase.js"></script>
    <script>
      // Initialize Firebase
      var config = {
        apiKey: window.apiKey,
        authDomain: "chatastrophe-draft.firebaseapp.com",
        databaseURL: "https://chatastrophe-draft.firebaseio.com",
        projectId: "chatastrophe-draft",
        storageBucket: "chatastrophe-draft.appspot.com",
        messagingSenderId: window.messagingSenderId
      };
      window.firebase = firebase;
      firebase.initializeApp(config);
    </script>
  </body>
</html>
```

# 应用安装横幅和您

能够添加到主屏幕是一个很棒的功能，但是我们的用户如何知道我们的应用程序是可安装的，特别是如果他们从未听说过 PWA 呢？

进入**Web App Install Banner**。 以前，应用安装横幅是一种方便的方式来宣传您的原生应用程序-请参阅 Flipboard 的以下示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00065.jpeg)

然而，现在，谷歌正在带头推动 PWA 安装横幅，提示用户添加到主屏幕。 请参阅 Chrome Dev Summit 网站的以下示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00066.jpeg)

该横幅具有使用户意识到您的网站是 PWA 的优势，并且对于那些不熟悉可安装的 Web 应用程序的用户，提供了进入 PWA 世界的入口点。

当您点击上一个屏幕截图中的“添加”时，您的主屏幕上会显示如下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00067.jpeg)

然而，就像本节中的所有内容一样，这是一项新技术。 目前，仅在安卓上的 Chrome 和 Opera for Android 上存在牢固的支持。 此外，两个浏览器上安装横幅将出现的具体标准也是牢固的：

+   该应用程序必须具有 Web 应用程序清单

+   该应用程序必须通过 HTTPS 提供

+   该应用程序必须使用服务工作者

+   该应用程序必须被访问两次，访问之间至少间隔五分钟

我们已经涵盖了前三个条件（Firebase 应用程序会自动通过 HTTPS 部署）。 最后一个标准是尽量减少用户的烦恼。

# 延迟应用程序安装横幅

以下部分仅适用于您拥有安卓设备进行测试，并且安装了最新版本的 Chrome 或 Opera for Android。 您还需要为您的安卓设备设置远程调试，按照以下指南进行操作：[`developers.google.com/web/tools/chrome-devtools/remote-debugging/`](https://developers.google.com/web/tools/chrome-devtools/remote-debugging/)。

我们之前提到的 PWA 的优势之一是用户在决定是否安装之前有机会与您的应用程序进行交互。 如果 Web 应用程序安装横幅显示得太早（在用户与您的应用程序进行积极交互之前），可能会干扰该过程。

在本节中，我们将通过延迟 Web 应用程序安装横幅事件来解决这个问题，直到用户与我们的应用程序进行积极交互。

我们将向我们的`App.js`添加一个事件侦听器，以便在横幅显示事件准备好触发时进行监听。 然后，我们将拦截该事件，并在用户发送消息时保存它。

# 监听事件

Chrome 在显示 Web 应用程序安装横幅之前直接发出`beforeinstallprompt`事件。这就是我们要监听的事件。像我们的其他 Firebase 事件监听器一样，让我们将其添加到我们的`App.js`的`componentDidMount`中。

我们将创建一个名为`listenForInstallBanner`的方法，然后从`componentDidMount`中调用该方法：

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
  this.listenForInstallBanner();
}
```

```jsx
listenForInstallBanner = () => {

};
```

在`listenForInstallBanner`中，我们将做两件事：

1.  为事件注册一个监听器。

1.  当该事件触发时，取消它并将其存储以便以后使用。

将其存储以便以后我们可以在任何时候触发它，也就是当用户发送他们的第一条消息时。

代码如下：

```jsx
listenForInstallBanner = () => {
  window.addEventListener('beforeinstallprompt', (e) => {
    console.log('beforeinstallprompt Event fired');
    e.preventDefault();
    // Stash the event so it can be triggered later.
    this.deferredPrompt = e;
  });
};
```

我们将在`App`实例上存储我们的`deferredPrompt`，以便以后可以获取它。我们将在`handleSubmitMessage`方法中执行这个操作：

```jsx
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
  if (this.deferredPrompt) {
 this.deferredPrompt.prompt();
 this.deferredPrompt.userChoice.then(choice => {
 console.log(choice);
 });
 this.deferredPrompt = null;
 }
};
```

在我们提交消息后，我们触发我们保存的事件。然后，我们记录用户的选择（无论他们是否实际安装了应用程序，我们也可以将其发送到将来选择使用的任何分析工具）。最后，我们删除事件。

好的，让我们测试一下！

将您的 Android 设备连接到计算机上，并在 DevTools 上打开远程调试。我们首先必须部署我们的应用程序，所以点击`yarn deploy`并等待它完成。然后，在您的设备上打开应用程序并输入一条消息；您应该会看到应用程序安装横幅弹出。

如果没有出现，请检查您的代码，或转到 DevTools 的应用程序选项卡，然后单击“添加到主屏幕”按钮。这应该会触发`beforeinstallprompt`事件。

# 总结

Web 应用程序安装横幅仍然是一项新技术，标准仍在不断变化中。有关最新信息，请参阅 Google 关于 Web 应用程序安装横幅的页面-[`developers.google.com/web/fundamentals/engage-and-retain/app-install-banners/`](https://developers.google.com/web/fundamentals/engage-and-retain/app-install-banners/)。也就是说，我希望本章对横幅的可能性和当前技术状态有所帮助。

现在我们已经使我们的应用程序更大更好，是时候精简并专注于性能了。下一章见！


# 第十章：应用外壳

我们上一章讨论了添加主屏幕安装和推送通知，这两者都旨在通过添加功能来改善用户体验，但正如我们在书的开头描述的用户故事一样，这个应用最重要的特性之一是包容性；它是一个面向所有人的聊天应用。

从 Web 应用的角度来看，我们可以更好地重新表述为“任何连接，任何速度”。Web 应用性能的最大障碍是网络请求：在慢速连接下加载数据需要多长时间。

开发人员可能会忽视性能，仅仅因为我们通常在城市中心的空调建筑内快速连接上测试我们的网站。然而，对于像 Chatastrophe 这样的全球应用，我们必须考虑在不发达国家的用户、农村地区的用户以及只有我们十分之一网络速度的用户。我们如何让应用为他们工作？

本节重点讨论性能；具体来说，它是关于优化我们的应用，使其在最恶劣的条件下也能表现良好。如果我们做得好，我们将拥有一个强大的用户体验，适用于任何速度（或缺乏速度）。

在本章中，我们将涵盖以下内容：

+   渐进增强是什么

+   性能的 RAIL 模型

+   使用 Chrome DevTools 来衡量性能

+   将我们的应用外壳从 React 中移出

# 什么是渐进增强？

**渐进增强**是一个简单的想法，但影响深远。它源于提供出色用户体验的愿望，同时又需要性能。如果我们所有的用户都有完美、超快的连接，我们可以构建一个令人难以置信的应用。然而，如果我们所有的用户都有慢速连接，我们必须满足于更简化的体验。

渐进增强说为什么不两者兼得？为什么不两者都有？

我们的受众包括快速连接和慢速连接。我们应该为两者提供服务，并适当地为每个人提供服务，这意味着为最佳连接提供最佳体验，为较差的连接提供更简化（但仍然很棒）的体验，以及介于两者之间的一切。

简而言之，渐进增强意味着随着用户的连接改善，我们的应用会逐渐变得更好，但它始终是有用的和可用的。因此，我们的应用是一种适应连接的应用*。*

您可以想象这正是现代网页加载的方式。首先，我们加载 HTML——内容的基本、丑陋的骨架。然后，我们添加 CSS 使其变得漂亮。最后，我们加载 JavaScript，其中包含使其生动的所有好东西。换句话说，随着网站的加载，我们的应用程序会逐渐变得更好。

渐进增强范式敦促我们重新组织网站的内容，以便重要的内容尽快加载，然后再加载其他功能。因此，如果您使用的是超快速的连接，您会立即得到所有内容；否则，您只会得到使用应用程序所需的内容，其他内容稍后再加载。

因此，在本章中，我们将优化我们的应用程序，尽快启动。我们还将介绍许多工具，您可以使用这些工具来关注性能，并不断增强性能，但是我们如何衡量性能呢？我们可以使用哪些指标来确保我们提供了一个快速的应用程序？RAIL 模型应运而生。

# RAIL 模型

RAIL 是谷歌所称的“以用户为中心的性能模型”。这是一组衡量我们应用性能的指南。我们应该尽量避免偏离这些建议。

我们将使用 RAIL 的原则来加快我们的应用程序，并确保它对所有用户都表现良好。您可以在[`developers.google.com/web/fundamentals/performance/rail`](https://developers.google.com/web/fundamentals/performance/rail)上阅读谷歌关于 RAIL 的完整文档。

RAIL 概述了应用程序生命周期中的四个特定时期。它们如下：

+   响应

+   动画

+   空闲

+   加载

就我个人而言，我认为以相反的顺序来思考它们会更容易（因为这更符合它们的实际顺序），但那样会拼成 LIAR，所以我们可以理解为什么谷歌会回避这一点。无论如何，在这里我们将以这种方式来介绍它们。

# 加载

首先，您的应用程序加载（让光明降临！）。

RAIL 表示，最佳加载时间为一秒（或更短）。这并不意味着您的整个应用程序在一秒内加载完成；而是意味着用户在一秒内看到内容。他们会对当前任务（加载页面）有一定的感知，而不是盯着一片空白的白屏。正如我们将看到的，这并不容易做到！

# 空闲

一旦您的应用程序加载完成，它就是空闲的（在操作之间也会是空闲的），直到用户执行操作。

RAIL 认为，与其让你的应用程序闲置不用（懒惰！），我们应该利用这段时间继续加载应用程序的部分。

我们将在下一章中更详细地看到这一点，但如果我们的初始加载只是我们应用程序的基本版本，我们会在空闲时间加载其他内容（渐进增强！）。

# 动画

动画对我们的目的来说不太相关，但我们将在这里简要介绍一下。基本上，如果动画不以 60 帧每秒的速度执行，用户会注意到动画的延迟。这将对感知性能（用户对应用程序速度的感受）产生负面影响。

请注意，RAIL 还将滚动和触摸手势定义为动画，因此即使你没有动画，如果你的滚动有延迟，你就会有问题。

# 响应

最终（希望非常快！），用户执行一个操作。通常，这意味着点击按钮、输入或使用手势。一旦他们这样做，你有 100 毫秒的时间来提供一个响应，以确认他们的行动；否则，用户会注意到并感到沮丧，也许会重试该操作，从而在后续造成更多问题（我们都经历过这种情况——疯狂地双击和三击）。

请注意，如果需要进行一些计算或网络请求，某些操作将需要更长的时间来完成。你不需要在 100 毫秒内完成操作，但你必须提供一些响应；否则，正如*Meggin Kearney*所说，“行动和反应之间的连接就断了。用户会注意到。”

# 时间轴

正如前面的模型所示，我们的应用程序必须在一定的时间限制内运行。这里有一个方便的参考：

+   16 毫秒：任何动画/滚动的每帧时间。

+   100 毫秒：对用户操作的响应。

+   1000 毫秒以上：在网页上显示内容。

+   1000 毫秒以上：用户失去焦点。

+   10,000 毫秒以上：用户可能会放弃页面。

如果你的应用程序按照这些规范执行，你就处于一个良好的状态（这些并不容易做到，正如我们将看到的）。

# 使用时间轴进行测量

在这一部分，我们将看看如何使用 Chrome DevTools 来分析我们应用程序的性能，这是我们将使用的一些工具中的第一个，用来跟踪我们的应用程序加载和响应的方式。

一旦我们了解了它的性能，我们可以根据 RAIL 原则进行改进。

开发工具当然是一直在不断发展的，所以它们的外观可能会与给定的截图有所不同。然而，核心功能应该保持不变，因此，重要的是要密切关注工作原理。

在 Chrome 中打开部署的 Firebase 应用程序，并打开 DevTools 到性能标签（我建议通过右上角的下拉菜单将工具拖出到单独的窗口中，因为有很多内容要查看）；然后，刷新页面。页面加载完成后，您应该看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00068.jpeg)

这里有很多内容，让我们来分解一下。我们将从摘要标签开始，底部的圆形图表。

# 摘要标签

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00069.jpeg)

中间的数字是我们的应用程序完全加载所花费的时间。您的数字应该与我的类似，根据您的互联网速度会有一些变化。

到目前为止，这里最大的数字是脚本，几乎达到了 1000 毫秒。由于我们的应用程序使用 JavaScript 很多，这是有道理的。我们立刻就能看到我们大部分的优化应该集中在尽快启动我们的脚本上。

另一个重要的数字是空闲时间的数量（几乎与脚本时间一样多）。我们马上就会看到为什么会有这么多空闲时间，但请记住，RAIL 模型建议利用这段时间开始预加载尚未加载的应用程序部分。目前，我们一开始就加载了所有内容，然后启动所有内容，然后坐在那里一会儿。只加载我们需要的内容（从而减少脚本时间），然后在后台加载其余内容（从而减少空闲时间）将更有意义。

# 网络请求

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00070.jpeg)

我们现在将转到网络请求，因为这将有助于解释性能概况的其余部分。

在这里，您可以看到确切加载了什么数据以及何时加载。一开始，我们看到了很多设置文件：Firebase 应用和`messaging`库，我们的`bundle.js`，以及页面的实际文档。

稍后，两个重要的调用是为了用户：登录和加载用户详细信息。我们加载的最后一件事是清单。

这个顺序是有道理的。我们需要加载 Firebase 库和我们的 JavaScript 来启动我们的应用程序。一旦我们这样做，我们就开始登录过程。

接下来发生的事情是，一旦用户登录，我们就会收到来自 Firebase 的消息和数据。正如您所注意到的，这在图表上并没有显示出来，因为它是通过 WebSockets 实时完成的，所以它并不是一个网络请求。然而，它将影响到其余的性能概况，所以请记住这一点。

# 瀑布

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00071.jpeg)

在这里，我们可以详细了解 Chrome 在渲染过程中实际在做什么。

瀑布工具是详细和复杂的，所以我们只能对其进行表面浏览。然而，我们可以从中得出两个见解。首先，我们可以看到所有的空闲时间可视化。大部分是在开始时，这在我们首次加载文档时有些不可避免，但在中间有一个很大的空白，我们可以尝试填补它。

其次，您可以看到应用程序在右侧瀑布图中接收来自 Firebase 的消息。如果您将鼠标悬停在每个块上，实际上可以追踪 Firebase 接收消息并将其状态设置为消息数组的过程。

因此，虽然我们无法在网络请求中看到消息加载，但我们可以在 JavaScript 执行中看到响应。

# 屏幕截图

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00072.jpeg)

这是我最喜欢的性能工具部分，因为它生动地说明了您的应用程序是如何加载的。

正如我们之前所建立的，用户应该在加载您的应用程序后的 1000 毫秒内看到内容。在这里，我们可以看到应用程序上的内容首先出现大约在 400 毫秒左右，所以我们看起来不错，但随着我们的应用程序增长（和我们的脚本负担增加），情况可能会改变，所以现在是尽可能优化的时候了。

# PageSpeed Insights

性能工具非常棒，因为它们让我们深入了解应用程序加载的细节。我们将使用它们来跟踪我们应用程序的性能，但是，如果我们想要更具体、更详细的建议，我们可以转向 Google 提供的**PageSpeed Insights**工具。

转到 PageSpeed Insights（[`developers.google.com/speed/pagespeed/insights/`](https://developers.google.com/speed/pagespeed/insights/)）并输入您部署的应用程序的 URL。几秒钟后，您将收到关于 Chatastrophe 可以改进的建议：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00073.jpeg)

正如你所看到的，我们的移动性能急需帮助。大部分见解都集中在我们的阻塞渲染 JavaScript 和 CSS 上。我鼓励你阅读关于这些问题的描述，并尝试自行解决它们。在下一节中，我们将致力于根据谷歌的规范改进我们的应用程序，使用另一个渐进式 Web 应用程序的秘密武器——应用外壳模式。

# 应用外壳模式

我们应用程序的核心是消息列表和聊天框，用户在其中阅读和编写消息。

这个核心功能依赖于 JavaScript 来工作。我们无法绕过这样一个事实，即在用户通过 Firebase 进行身份验证并加载消息数组之前，我们无法显示消息，但是围绕这两个部分的一切大多是静态内容。在每个视图中都是相同的，并且不依赖于 JavaScript 来工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00074.jpeg)

我们可以将这称为应用外壳——围绕功能性、由 JavaScript 驱动的核心的框架。

由于这个框架不依赖 JavaScript 来运行，实际上我们不需要等待 React 加载和启动所有 JavaScript，然后再显示它——这正是目前正在发生的事情。

现在，我们的外壳是我们的 React 代码的一部分，因此，在调用`ReactDOM.render`并在屏幕上显示之前，我们所有的 JavaScript 都必须加载。

然而，对于我们的应用程序，以及许多应用程序来说，UI 中有一个相当大的部分基本上只是 HTML 和 CSS。此外，如果我们的目标是减少感知加载时间（用户认为加载应用程序需要多长时间）并尽快将内容显示在屏幕上，最好将我们的外壳保持为纯粹的 HTML 和 CSS，即将其与 JavaScript 分离，这样我们就不必等待 React。

回到我们的性能工具，你可以看到加载的第一件事是文档，或者我们的`index.html`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00075.jpeg)

如果我们可以将我们的外壳放在`index.html`中，它将比目前快得多，因为它不必等待捆绑包加载。

然而，在开始之前，让我们进行基准测试，看看我们目前的情况以及这将带来多大的改进。

使用你部署的应用程序，打开我们的性能工具并刷新应用程序（在 DevTools 打开时使用 Empty Cache & Hard Reload 选项，以确保没有意外的缓存发生-按住并按下重新加载按钮来访问它）。然后，看一下那个图像条，看看内容何时首次出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00076.jpeg)

运行测试三次，以确保，并取平均值。对我来说，平均需要 600 毫秒。这是我们要超越的基准。

# 将 shell HTML 从 React 中移出

让我们首先定义我们想要移动到我们的`index.html`中的内容。

在下面的图像中，除了消息和聊天框线之外的所有内容都是我们的应用程序 shell：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00077.jpeg)

这就是我们想要从 React 中移出并转换为纯 HTML 的内容，但在继续之前让我们澄清一些事情。

我们的目标是创建一个快速加载的应用程序部分的版本，这些部分不需要立即使用 JavaScript，但最终，我们的一些 shell 将需要 JavaScript。我们需要在页眉中放置我们的注销按钮，这将需要 JavaScript 来运行（尽管只有在用户经过身份验证后才需要）。

因此，当我们谈论将这些内容从 React 中移出时，我们实际上要做的是有一个纯 HTML 和 CSS 版本的 shell，然后，当 React 初始化时，我们将用 React 版本替换它。

这种方法给了我们最好的两种世界：一个快速加载基础版本，一旦 JS 准备好，我们就会替换掉它。如果这听起来很熟悉，你也可以称之为逐步增强我们的应用程序。

那么，我们如何管理这个替换呢？嗯，让我们从打开我们的`index.html`开始，看看我们的应用程序是如何初始化的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00078.jpeg)

关键是我们的`div#root`。正如我们在`index.js`中看到的那样，那是我们注入 React 内容的地方：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00079.jpeg)

现在，我们将我们的 React 内容嵌入到一个空的`div`中，但让我们尝试一些东西；在里面添加一个`<h1>`：

```jsx
<div id="root">
  <h1>Hello</h1>
</div>
```

然后，重新加载你的应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00080.jpeg)

`<h1>`出现直到我们的 React 准备好，此时它被替换，所以我们可以在`div#root`内添加内容，当 React 准备好时，它将被简单地覆盖；这就是我们的关键。

让我们逐步移动内容，从我们的`App.js`开始，逐渐向下工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00081.jpeg)

我们这里唯一需要的 HTML（或 JSX，目前）是容器。让我们将它复制到`div#root`中：

```jsx
<div id="root">
  <div id="container">
  </div>
</div>
```

然后，在`ChatContainer`（或`LoginContainer`，或`UserContainer`）内部，我们看到有一个`div.inner-container`，也可以移动过去：

```jsx
<div id="root">
  <div id="container">
    <div class="inner-container">
    </div>
  </div>
</div>
```

注意从`className`（对于 JSX）到`class`（对于 HTML）的更改。

然后，我们移动`Header`本身：

```jsx
<div id="root">
  <div id="container">
     <div class="inner-container">
       <div id="Header">
         <img src="/assets/icon.png" alt="logo" />
         <h1>Chatastrophe</h1>
       </div>
     </div>
  </div>
</div>
```

重新加载您的应用程序，您将看到我们的 HTML 的一个非常丑陋的版本在 React 加载之前出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00082.jpeg)

这里发生了什么？嗯，我们的 CSS 是在我们的`App.js`中加载的，在我们的导入语句中，因此直到我们的 React 准备好之前它都不会准备好。下一步将是将相关的 CSS 移动到我们的`index.html`中。

# 将 CSS 移出 React

目前，我们的应用程序没有太多的 CSS，所以理论上，我们可以只是在`index.html`中`<link>`整个样式表，而不是在`App.js`中导入它，但随着我们的应用程序和 CSS 的增长，这将不是最佳选择。

我们最好的选择是内联相关的 CSS。我们首先在`<head>`下方的`<title>`标签右侧添加一个`<style>`标签。

然后，打开`src/app.css`，并剪切（而不是复制）`/* Start initial styles */`和`/* End Initial styles */`注释内的 CSS。

将其放在样式标签内并重新加载应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00083.jpeg)

应用程序看起来完全一样！这是个好消息；在这个阶段，可能不会有明显的加载时间差异。然而，让我们部署然后再次运行我们的性能工具：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00084.jpeg)

正如您所看到的，外壳（带有空白内部）出现在加载指示器出现之前（这表明 React 应用程序已经启动）。这是用户通常会花在空白屏幕上的时间。

# 移动加载指示器

让我们再向前迈进一小步，还将加载指示器添加到我们的应用程序外壳中，以让用户了解发生了什么。

复制`ChatContainer`中的 JSX 并将其添加到我们的`index.html`。然后，重新加载页面：

```jsx
<div id="root">
  <div id="container">
    <div class="inner-container">
      <div id="Header">
        <img src="/assets/icon.png" alt="logo" />
        <h1>Chatastrophe</h1>
      </div>
      <div id="loading-container">
        <img src="/assets/icon.png" alt="logo" id="loader"/>
      </div>
    </div>
  </div>
</div>
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00085.jpeg)

现在，用户可以清楚地感觉到应用程序正在加载，并且会更宽容地对待我们应用程序的加载时间（尽管我们仍然会尽力减少它）。

这是从本章中获得的基本原则：渐进式 Web 应用程序要求我们尽可能多地改善用户体验。有时，我们无法做任何关于加载时间的事情（归根结底，我们的 JavaScript 总是需要一些时间来启动--一旦它启动，它就提供了很好的用户体验），但我们至少可以让用户感受到进展。

良好的网页设计是关于共情。渐进式 Web 应用程序是关于对每个人都持有共情，无论他们从什么条件下访问您的应用程序。

# 总结

在本章中，我们涵盖了性能工具和概念的基本知识，从 RAIL 到 DevTools，再到 PageSpeed Insights。我们还使用了应用程序外壳模式进行了重大的性能改进。在接下来的章节中，我们将继续完善我们应用的性能。

我们下一章将解决最大的性能障碍——我们庞大的 JavaScript 文件。我们将学习如何使用 React Router 的魔力将其拆分成较小的块，并且如何在应用程序的空闲时间加载这些块。让我们开始吧！


# 第十一章：使用 Webpack 对 JavaScript 进行分块以优化性能

正如我们在上一章中讨论的那样，将 React 应用程序转换为渐进式 Web 应用程序的最大问题是 React；更具体地说，它是构建现代 JavaScript 应用程序时固有的大量 JavaScript。解析和运行该 JavaScript 是 Chatastrophe 性能的最大瓶颈。

在上一章中，我们采取了一些措施来改善应用程序的感知启动时间，方法是将内容从 JavaScript 移出并放入我们的`index.html`中。虽然这是一种非常有效的向用户尽快显示内容的方法，但您会注意到，我们并没有做任何实际改变我们的 JavaScript 大小，或者减少初始化所有 React 功能所需的时间。

现在是时候采取行动了。在本章中，我们将探讨如何将我们的 JavaScript 捆绑分割以实现更快的加载。我们还将介绍渐进式 Web 应用程序理论的一个新部分--PRPL 模式。

在本章中，我们将涵盖以下主题：

+   什么是 PRPL 模式？

+   什么是代码拆分，我们如何实现它？

+   创建我们自己的高阶组件

+   按路由拆分代码

+   延迟加载其他路由

# PRPL 模式

在上一章中，我们介绍了一些执行应用程序的基本原则。您希望用户尽可能少地等待，这意味着尽快加载必要的内容，并将其余的应用程序加载推迟到处理器的“空闲”时间。

这两个概念构成 RAIL 指标的'I'和'L'。我们通过应用外壳的概念迈出了改善'L'的一步。现在，我们将把一些'L'（初始加载）移到'I'（应用程序的空闲时间），但在我们这样做之前，让我们介绍另一个缩写。

**PRPL**代表**推送**，**渲染**，**预缓存**，**延迟加载**；这是一个理想应用程序应该如何从服务器获取所需内容的逐步过程。

然而，在我们深入讨论之前，我想警告读者，PRPL 模式在撰写时相对较新，并且随着渐进式 Web 应用程序进入主流，可能会迅速发展。就像我们在本书中讨论的许多概念一样，它依赖于实验性技术，仅适用于某些浏览器。这是尖端的东西。

这就是*Addy Osmani*的说法：

对于大多数现实世界的项目来说，以其最纯粹、最完整的形式实现 PRPL 愿景实际上还为时过早，但采用这种思维方式或从各个角度开始追求这一愿景绝对不为时过早。 ([`developers.google.com/web/fundamentals/performance/prpl-pattern/`](https://developers.google.com/web/fundamentals/performance/prpl-pattern/))

让我们依次解释每个字母代表的意思，以及它对我们和我们的应用程序意味着什么。

# 推送

*Addy Osmani*将 PRPL 的 PUSH 定义如下：

“推送初始 URL 路由的关键资源。”

基本上，这意味着你的首要任务是尽快加载渲染初始路由所需的内容。听起来很熟悉吗？这正是我们在应用程序外壳中遵循的原则。

推送的一个温和定义可以是“在任何其他内容之前，首先加载关键内容。”这个定义与应用程序外壳模式完全吻合，但这并不完全是*Osmani*的意思。

以下部分是对服务器*推送*技术的理论介绍。由于我们无法控制我们的服务器（又名 Firebase），我们不会实施这种方法，但了解对于未来与自己的服务器通信的 PWA 是很有好处的。

如果你看一下我们的`index.html`，你会发现它引用了几个资产。它请求`favicon`，`icon.png`和`secrets.js`。在 Webpack 构建后，它还会请求我们的主 JavaScript `bundle.js`。

网站通常的工作方式是这样的：浏览器请求`index.html`。一旦得到文件，它会遍历并请求服务器上列出的所有依赖项，每个都作为单独的请求。

这里的核心低效性在于`index.html`已经包含了关于它的依赖项的所有信息。换句话说，当它响应`index.html`时，服务器已经“知道”浏览器接下来会请求什么，那么为什么不预期这些请求并发送所有这些依赖项呢？

进入 HTTP 2.0 服务器推送。这项技术允许服务器对单个请求创建多个响应。浏览器请求`index.html`，然后得到`index.html` + `bundle.js` + `icon.png`，依此类推。

正如*Ilya Grigorik*所说，服务器推送“使内联过时”（[`www.igvita.com/2013/06/12/innovating-with-http-2.0-server-push/`](https://www.igvita.com/2013/06/12/innovating-with-http-2.0-server-push/)）。我们不再需要内联我们的 CSS 来节省对服务器的请求；我们可以编写我们的服务器以在单次请求中发送我们初始路由所需的一切。这是令人兴奋的事情；有关更多信息（以及快速教程），请查看上述链接。

# 渲染

在（理想情况下）将所有必要的资源推送到客户端之后，我们渲染我们的初始路由。同样，由于应用程序外壳模式的快速渲染，我们已经涵盖了这一点。

# 预缓存

一旦我们渲染了初始路由，我们仍然需要其他路由所需的资源。预缓存意味着一旦加载了这些资源，它们将直接进入缓存，如果再次请求，我们将从缓存中加载它们。

随着我们进入缓存世界，我们将在下一章中更详细地介绍这一点。

# 延迟加载

这就是本章的重点所在。

我们希望首先加载我们初始路由所需的资源，以尽快完成初始渲染。这意味着不会加载其他路由所需的资源。

在实际操作中，这意味着我们希望首先加载`LoginContainer`（如果用户尚未登录），并推迟加载`UserContainer`。

然而，一旦渲染了初始路由并且用户可以看到登录屏幕，我们希望为未来做好准备。如果他们随后切换到`UserContainer`，我们希望尽快显示它。这意味着一旦加载了初始路由，我们就会在后台加载`UserContainer`资源。

这个过程被称为**延迟加载**-加载不需要立即使用的资源，但将来可能需要。

我们用来做到这一点的工具就是代码拆分。

# 什么是代码拆分？

**代码拆分**是将我们的 JavaScript 文件分割成有意义的块，以提高性能，但为什么我们需要它呢？

嗯，当用户首次访问我们的应用程序时，我们只需要当前所在路由的 JavaScript。

这意味着当它们在`/login`时，我们只需要`LoginContainer.js`及其依赖项。我们不需要`UserContainer.js`，所以我们希望立即加载`LoginContainer.js`并延迟加载`UserContainer.js`。然而，我们当前的 Webpack 设置创建了一个单一的`bundle.js`文件。我们所有的 JavaScript 都被绑在一起，必须一起加载。代码拆分是解决这个问题的一种方法。我们不再是一个单一的庞大的 JavaScript 文件，而是得到了多个 JavaScript 文件，每个路由一个。

因此，我们将得到一个用于`/login`，一个用于`/user/:id`，一个用于`/`的捆绑包。此外，我们还将得到另一个包含所有依赖项的`main`捆绑包。

无论用户首先访问哪个路由，他们都会得到该路由的捆绑包和主要捆绑包。与此同时，我们将在后台加载其他两个路由的捆绑包。

代码拆分不一定要基于路由进行，但对于我们的应用程序来说是最合理的。此外，使用 Webpack 和 React Router 进行这种方式的代码拆分相对来说是比较简单的。

事实上，只要您提供一些基本的设置，Webpack 就会自动处理这个问题。让我们开始吧！

# Webpack 配置

我们之前讨论过的策略是这样的：我们希望根据路由将我们的`bundle.js`拆分成单独的块。

这一部分的目的是做两件事：一是为 JavaScript 的块设置命名约定，二是为条件导入添加支持（稍后会详细介绍）。

打开`webpack.config.prod.js`，让我们进行第一步（这仅适用于`PRODUCTION`构建，因此只修改我们的生产 Webpack 配置；我们不需要在开发中进行代码拆分）。

就目前而言，我们的输出配置如下：

```jsx
output: {
   path: __dirname + "/build",
   filename: "bundle.js",
   publicPath: './'
},
```

我们在`build`文件夹中创建一个名为`bundle.js`的单个 JavaScript 文件。

让我们将整个部分改为以下内容：

```jsx
output: {
   path: __dirname + "/build",
   filename: 'static/js/[name].[hash:8].js',
   chunkFilename: 'static/js/[name].[hash:8].chunk.js',
   publicPath: './'
},
```

这里发生了什么？

首先，我们将我们的 JavaScript 输出移动到`build/static/js`，仅仅是为了组织目的。

接下来，我们在我们的命名中使用了两个变量：`name`和`hash`。`name`变量是由 Webpack 自动生成的，使用了我们的块的编号约定。我们马上就会看到这一点。

然后，我们使用一个`hash`变量。每次 Webpack 构建时，它都会生成一个新的哈希--一串随机字母和数字。我们使用这些来命名我们的文件，这样每次构建都会有不同的文件名。这在下一章中将很重要，因为这意味着我们的用户永远不会遇到应用程序已更新但缓存仍然保留旧文件的问题。由于新文件将具有新名称，它们将被下载，而不是缓存中的任何内容。

接下来，我们将在我们的代码拆分文件（每个路由的文件）后添加一个`.chunk`。这并非必需，但如果您想对块进行任何特殊缓存，建议这样做。

一旦我们的代码拆分完成，所有提到的内容将更加清晰，所以让我们尽快完成吧！然而，在继续之前，我们需要在我们的 Webpack 配置中再添加一件事。

# Babel 阶段 1

正如我们在 Webpack 章节中解释的那样，Babel 是我们用来允许我们使用尖端 JavaScript 功能，然后将其转译为浏览器将理解的 JavaScript 版本的工具。

在本章中，我们将使用另一个尖端功能：条件导入。然而，在开始之前，我们需要更改我们的 Babel 配置。

JavaScript 语言不断发展。负责更新它的委员会称为 TC39，他们根据 TC39 流程开发更新。它的工作方式如下：

+   建议一个新的 JavaScript 功能，此时它被称为“阶段 0”

+   为其工作创建一个提案（“阶段 1”）

+   创建一个实现（“阶段 2”）

+   它被打磨以包含（“阶段 3”）

+   它被添加到语言中

在任何时候，每个阶段都有多个功能。问题在于 JavaScript 开发人员很不耐烦，每当他们听说一个新功能时，即使它处于第 3 阶段、第 2 阶段甚至第 0 阶段，他们也想开始使用它。

Babel 提供了一种方法来做到这一点，即其**stage**预设。您可以为每个阶段安装一个预设，并获得当前处于该阶段的所有功能。

我们感兴趣的功能（条件导入）目前处于第 2 阶段。为了使用它，我们需要安装适当的 babel 预设：

```jsx
yarn add --dev babel-preset-stage-2
```

然后，在两个 Webpack 配置中，将其添加到 module | loaders | JavaScript 测试 | query | presets 下：

```jsx
module: {
  loaders: [
  {
  test: /\.js$/,
  exclude: /node_modules/,
  loader: 'babel-loader',
  query: {
         presets: ['es2015','react','stage-2'],
         plugins: ['react-hot-loader/babel', 'transform-class-properties']
       }
  },
```

记得将其添加到`webpack.config.js`和`webpack.config.prod.js`中。我们在生产和开发中都需要它。

# 条件导入

搞定了这些，现在是时候问一下条件导入是什么了。

目前，我们在每个 JavaScript 文件的顶部导入所有的依赖项，如下所示：

```jsx
import React, { Component } from 'react';
```

我们始终需要 React，所以这个导入是有意义的。它是静态的，因为它永远不会改变，但前面的意思是 React 是这个文件的依赖项，它将始终需要被加载。

目前，在`App.js`中，我们对每个容器都是这样做的：

```jsx
import LoginContainer from './LoginContainer';
import ChatContainer from './ChatContainer';
import UserContainer from './UserContainer';
```

这样做意味着这些容器是`App.js`的依赖，所以 Webpack 将始终将它们捆绑在一起；我们无法将它们分开。

相反，我们希望在需要时有条件地导入它们。

这样做的机制有点复杂，但本质上看起来是这样的：

```jsx
If (path === ‘/login’)
  import('./LoginContainer')
} else if (path === ‘/user/:id’)
  import(‘./UserContainer)
} else {
  import(‘./ChatContainer)
}
```

那么，我们该如何实现呢？

# 高阶组件

我们在第五章中讨论了高阶组件，*使用 React 进行路由*，讨论了来自 React Router 的`withRouter`；现在，我们将构建一个，但首先，让我们快速复习一下。

高阶组件在 React 中是一个非常有用的模式。如果你学会了如何使用它们，你将打开一系列可能性，使得大型代码库易于维护和可重用，但它们并不像常规组件那样直观，所以让我们确保我们充分涵盖它们。

在最基本的层面上，高阶组件是一个返回组件的函数。

想象一下我们有一个`button`组件：

```jsx
function Button(props) {
 return <button color={props.color}>Hello</button>
}
```

如果你更熟悉`class`语法，也可以用这种方式来写：

```jsx
class Button extends Component {
 render() {
   return <button color={this.props.color}>Hello</button>
 }
}
```

我们使用一个颜色属性来控制文本的颜色。假设我们在整个应用程序中都使用这个按钮。通常情况下，我们发现自己将文本设置为红色--大约 50%的时间。

我们可以简单地继续将`color=”red”`属性传递给我们的按钮。在这个假设的例子中，这将是更好的选择，但在更复杂的用例中，我们也可以制作一个高阶组件（正如我们将看到的）。

让我们创建一个名为`RedColouredComponent`的函数：

```jsx
function colorRed(Component) {
  return class RedColoredComppnent extends Component {
    render () {
      return <Component color="red" />
    }
  }
}
```

该函数接受一个组件作为参数。它所做的就是返回一个组件类，然后返回该组件并应用`color=”red”`属性。

然后，我们可以在另一个文件中渲染我们的按钮，如下所示：

```jsx
import Button from './Button';
import RedColouredComponent from './RedColouredComponent';

const RedButton = RedColouredComponent(Button);

function App() {
 return (
   <div>
     <RedButton />
   </div>
 )
}
```

然后，我们可以将任何组件传递给`RedColouredComponent`，从而创建一个红色版本。

这样做打开了新的组合世界--通过高阶组件的组合创建组件。

这毕竟是 React 的本质——用可重用的代码片段组合 UI。高阶组件是保持我们的应用程序清晰和可维护的好方法，但是足够的人为例子，现在让我们自己来做吧！

# AsyncComponent

本节的目标是创建一个帮助我们进行代码拆分的高阶组件。

这个组件只有在渲染时才会加载它的依赖项，或者当我们明确告诉它要加载它时。这意味着，如果我们传递给它`LoginContainer.js`，它只会在用户导航到`/login`时加载该文件，或者我们告诉它加载它时。

换句话说，这个组件将完全控制我们的 JavaScript 文件何时加载，并打开了懒加载的世界。然而，这也意味着每当渲染一个路由时，相关文件将自动加载。

如果这听起来抽象，让我们看看它的实际应用。

在您的`components/`目录中创建一个名为`AsyncComponent.js`的新文件，并添加基本的骨架，如下所示：

```jsx
import React, { Component } from 'react'

export default function asyncComponent(getComponent) {

}
```

`asyncComponent`是一个以导入语句作为参数的函数，我们称之为`getComponent`。我们知道，作为一个高阶组件，它将返回一个`component`类：

```jsx
export default function asyncComponent(getComponent) {
 return class AsyncComponent extends Component {
   render() {
     return (

     )
   }
 }
}
```

`AsyncComponent`的关键将是`componentWillMount`生命周期方法。这是`AsyncComponent`将知道何时去获取依赖文件的时候。这样，组件在需要之前等待，然后加载任何文件。

然而，当我们得到组件后，我们该怎么办呢？简单，将其存储在状态中：

```jsx
  componentWillMount() {
     if (!this.state.Component) {
       getComponent().then(Component => {
         this.setState({ Component });
       });
     }
   }
```

如果我们还没有加载组件，就去导入它（我们假设`getComponent`返回一个`Promise`）。一旦导入完成，将状态设置为导入的组件，这意味着我们的`render`应该是这样的：

```jsx
  render() {
     const { Component } = this.state;
     if (Component) {
       return <Component {...this.props} />;
     }
     return null;
   }
```

所有这些对你来说应该很熟悉，除了`return`语句中的`{...this.props}`。这是 JavaScript 的展开运算符。这是一个复杂的小东西（更多信息请参见[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_operator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_operator)），但在这种情况下，它基本上意味着将`this.props`对象的所有键和值复制到`Component`的`props`上。

通过这种方式，我们可以将 props 传递给`asyncComponent`返回的组件，并将它们传递给`Component`渲染。应用于`AsyncComponent`的每个 prop 都将应用于其`render`函数中的`Component`。

供参考的完整组件如下：

```jsx
import React, { Component } from 'react';

export default function asyncComponent(getComponent) {
 return class AsyncComponent extends Component {
   state = { Component: null };

   componentWillMount() {
     if (!this.state.Component) {
       getComponent().then(Component => {
         this.setState({ Component });
       });
     }
   }

   render() {
     const { Component } = this.state;
     if (Component) {
       return <Component {...this.props} />;
     }
     return null;
   }
 };
}
```

# 路由拆分

让我们回到`App.js`，把它全部整合起来。

首先，我们将消除 App 对这三个容器的依赖。用`AsyncComponent`的导入替换这些导入，使文件顶部看起来像这样：

```jsx
import React, { Component } from 'react';
import { Route, withRouter } from 'react-router-dom';
import AsyncComponent from './AsyncComponent';
import NotificationResource from '../resources/NotificationResource';
import './app.css';
```

接下来，我们将定义三个`load()`函数，每个容器一个。这些是我们将传递给`asyncComponent`的函数。它们必须返回一个 promise：

```jsx
const loadLogin = () => {
 return import('./LoginContainer').then(module => module.default);
};

const loadChat = () => {
 return import('./ChatContainer').then(module => module.default);
};

const loadUser = () => {
 return import('./UserContainer').then(module => module.default);
};
```

看，条件导入的魔力。当调用这些函数时，将导入三个 JavaScript 文件。然后我们从每个文件中获取默认导出，并用它来`resolve()` `Promise`。

这意味着我们可以在`App.js`中重新定义我们的组件，如下所示，在前面的函数声明之后（这些函数声明在文件顶部的导入语句之后）：

```jsx
const LoginContainer = AsyncComponent(loadLogin);
const UserContainer = AsyncComponent(loadUser);
const ChatContainer = AsyncComponent(loadChat);
```

不需要其他更改！您可以保持应用程序的`render`语句完全相同。现在，当我们提到`ChatContainer`时，它指的是`loadChat…`周围的`AsyncComponent`包装器，它在需要时会获取`ChatContainer.js`。

让我们看看它是否有效。运行`yarn build`，并查看输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00086.jpeg)

我们有四个 JavaScript 文件而不是一个。我们有我们的`main.js`文件，其中包含`App.js`加上我们必需的`node_modules`。然后，我们有三个块，每个容器一个。

还要查看文件大小，您会发现我们并没有通过这种代码拆分获得太多好处，主文件减少了几千字节。然而，随着我们的应用程序增长，每个路由变得更加复杂，代码拆分的好处也会随之增加。这有多简单？

# 懒加载

懒加载是我们 PRPL 拼图的最后一块，它是利用应用程序的空闲时间来加载其余的 JavaScript 的过程。

如果您**`yarn deploy`**我们的应用程序并导航到 DevTools 中的网络选项卡，您将看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00087.jpeg)

我们加载我们的主文件，然后加载与当前 URL 相关的任何块，然后停止。

我们在应用程序的空闲时间内没有加载其他路由！我们需要一种方式来触发加载过程，即在初始路由渲染完成后，即`App`挂载后。

我想你知道这将会发生什么。在`App`的`componentDidMount`方法中，我们只需要调用我们的三个加载方法：

```jsx
componentDidMount() {
    this.notifications = new NotificationResource(
      firebase.messaging(),
      firebase.database()
    );
    firebase.auth().onAuthStateChanged(user => {
      if (user) {
        this.setState({ user });
        this.listenForMessages();
        this.notifications.changeUser(user);
      } else {
        this.props.history.push('/login');
      }
    });
    this.listenForMessages();
    this.listenForInstallBanner();
 loadChat();
 loadLogin();
 loadUser();
  }
```

现在，每当我们完成渲染当前路由时，我们也会准备好其他路由。

如果您再次打开 DevTools 的性能选项卡，您将看到网络请求中反映出这一点：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00088.jpeg)

在左边，底部的黄色块是我们加载的`main.js`文件。这意味着我们的应用程序可以开始初始化。在右边，三个黄色块对应我们的三个路由块。我们首先加载需要的块，然后很快加载其他两个块。

我们现在更多地利用了应用程序的空闲时间，分散了初始化应用程序的工作。

# 总结

在本章中，我们涵盖了很多内容，大步迈向了更高性能的应用程序。我们按路由拆分了我们的 JavaScript，并简化了加载过程，以便加载我们需要的内容，并将其推迟到空闲时间。

然而，所有这些实际上只是为下一节铺平了道路。我们需要我们的应用程序在所有网络条件下都能正常运行，甚至在没有任何网络的情况下。我们如何使我们的应用程序在离线状态下工作？

接下来，我们将深入研究缓存的世界，并进一步改善我们应用程序在任何网络条件下的性能，甚至在没有网络的情况下。
