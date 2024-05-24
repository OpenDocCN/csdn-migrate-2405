# React 渐进式 Web 应用（四）

> 原文：[`zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D`](https://zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：准备好进行缓存

我们在应用程序的性能方面取得了巨大进展。我们的 JavaScript 现在根据应用程序的路由拆分成更小的块，并且在我们的应用程序有空闲时间时延迟加载不太重要的部分。我们还引入了渐进增强，尽快向用户展示内容，并学习了如何根据 RAIL 指标分析我们应用程序的性能。

然而，我们的 Web 应用程序仍然存在一个核心的低效问题。如果我们的用户离开我们的页面去其他地方（我知道，他们怎么敢），然后返回，我们又要重复同样的过程：下载`index.html`，下载不同的 JavaScript 包，下载图片等等。

我们要求用户每次访问页面时都下载完全相同的文件，一遍又一遍，而他们的设备有足够的内存来为我们存储这些文件。为什么我们不把它们保存到用户的设备上，然后根据需要检索呢？

欢迎来到缓存。在本章中，我们将涵盖以下内容：

+   什么是缓存？

+   缓存 API

+   在我们的服务工作者中使用缓存 API

+   测试我们的缓存

# 什么是缓存？

缓存是减少网络请求或计算的行为。后端缓存可能包括保存严格计算的结果（比如生成统计数据），这样当客户端第二次请求时，我们就不必再次进行计算。客户端缓存通常包括保存网络请求的响应，这样我们就不必再次发起请求。

正如我们之前所说，**服务工作者**是位于我们应用程序和网络之间的代码片段。这意味着它们非常适合缓存，因为它们可以拦截网络请求并用所请求的文件进行响应，从缓存中获取文件，而不是从服务器获取；节省了时间。

从更广泛的角度来看，你可以将缓存视为不必重复做同样的事情，使用内存来存储结果。

使用渐进式 Web 应用程序进行缓存的好处在于，由于缓存存储在设备内存中，无论网络连接如何，它都是可用的。这意味着无论设备是否连接，都可以访问缓存中存储的所有内容。突然间，我们的网站可以离线访问了。

对于在 Wi-Fi 区域之间切换的移动用户来说，便利因素可能是巨大的，使他们能够快速查看朋友的消息或一组方向（任何曾经没有漫游计划旅行的人都会有这种感觉）。这也不仅仅是纯离线用户的优势；对于网络时断时续或质量低劣的用户来说，能够在网络断断续续时继续工作而不丧失功能性是一个巨大的胜利。

因此，一举两得，我们可以提高我们的应用程序性能，使其对所有用户都可离线使用。然而，在我们开始在 Chatastrophe 中实施缓存之前（希望不会出现灾难），让我们先看一个关于缓存重要性的故事。

# 缓存的重要性

2013 年，美国政府推出了[`healthcare.gov/`](https://healthcare.gov/)，这是一个供公民注册平价医疗法案（也称为**奥巴马医改**）的网站。从一开始，该网站就饱受严重的技术问题困扰。对于成千上万的人来说，它根本无法加载。

公平地说，该网站承受着巨大的压力，在运营的第一个月就有大约 2,000 万次访问（来源-[`www.bbc.com/news/world-us-canada-24613022`](http://www.bbc.com/news/world-us-canada-24613022)），但这种压力是可以预料的。

如果你正在为数百万人注册医疗保健的网站（所有人同时开始），性能可能会是你首要考虑的问题，但最终，[`healthcare.gov/`](https://healthcare.gov/)未能交付。

作为对危机的回应（这威胁到了 ACA 的信誉），政府成立了一个团队来解决问题，有点像复仇者联盟，但是软件开发人员（所以根本不是复仇者联盟）。

考虑到该网站的目标，工程师们震惊地发现[`healthcare.gov/`](https://healthcare.gov/)没有实施基本的缓存。没有。因此，每当用户访问该网站时，服务器都必须处理网络请求并生成回复的信息。

这种缺乏缓存产生了复合效应。第一波用户堵塞了管道，所以第二波用户看到了加载屏幕。作为回应，他们刷新屏幕，发出了越来越多的网络请求，依此类推。

一旦 Devengers 实施了缓存，他们将响应时间缩短了四分之三。从那时起，该网站甚至能够处理高峰时段的流量。

Chatastrophe 可能还没有处理[`healthcare.gov/`](https://healthcare.gov/)级别的流量（但是……），但缓存总是一个好主意。

# 缓存 API

我们将使用**Web 缓存 API**进行缓存。

请注意，Mozilla 开发者网络将缓存 API 定义为**实验性技术**，截至 2017 年 8 月，它仅得到 Chrome、Firefox 和最新版本的 Opera 的支持。

API 规范有一些我们需要讨论的怪癖。首先，你可以在缓存中存储多个缓存对象。这样，我们就能够存储我们的缓存的多个版本，以我们喜欢的任何字符串命名。

也就是说，浏览器对于每个站点可以存储的数据有限制。如果缓存太满，它可能会简单地删除来自该站点的所有数据，因此我们最好存储最少量的数据。

然而，还有一个额外的困难。除非明确删除，否则缓存中的项目永远不会过期，因此如果我们不断尝试将新的缓存对象放入我们的缓存中，最终它会变得太满并删除所有内容。管理、更新和删除缓存对象完全取决于我们。换句话说，我们必须清理自己的混乱。

# 方法

我们将使用五种方法与缓存 API 交互：`open`、`addAll`、`match`、`keys`和`delete`。在接下来的内容中，**Caches**将指的是缓存 API 本身，而**Cache**指的是特定的缓存对象，以区分在单个缓存上调用的方法与 API 本身：

+   `Caches.open()`接受一个缓存对象名称（也称为缓存键）作为参数（可以是任何字符串），并创建一个新的缓存对象，或者打开同名的现有缓存对象。它返回一个`Promise`，并将缓存对象作为参数解析，然后我们可以使用它。

+   `Cache.addAll()`接受一个 URL 数组。然后它将从服务器获取这些 URL，并将结果文件存储在当前的缓存对象中。它的小伙伴是`Cache.add`，它可以用单个 URL 做同样的事情。

+   `Caches.match()`接受一个网络请求作为参数（我们将在接下来看到如何获取它）。它在缓存中查找与 URL 匹配的文件，并返回一个解析为该文件的`Promise`。然后我们可以返回该文件，从而取代向服务器发出请求的需要。它的大哥是`Caches.matchAll()`。

+   `Caches.keys()`返回所有现有缓存对象的名称。然后我们可以通过将它们的键传递给`Caches.delete()`来删除过时的缓存对象。

缓存 API 中的最后一个方法，我们这里不会使用，但可能会感兴趣的是`Caches.put`。这个方法接受一个网络请求并获取它，然后将结果保存到缓存中。如果你想缓存每个请求而不必提前定义 URL，这将非常有用。

# 资产清单

我们的构建过程会自动生成一个`asset-manifest.json`文件，其中列出了我们应用程序包含的每个 JavaScript 文件。它看起来像这样：

```jsx
{
  "main.js": "static/js/main.8d0d0660.js",
  "static/js/0.8d0d0660.chunk.js": "static/js/0.8d0d0660.chunk.js",
  "static/js/1.8d0d0660.chunk.js": "static/js/1.8d0d0660.chunk.js",
  "static/js/2.8d0d0660.chunk.js": "static/js/2.8d0d0660.chunk.js"
}
```

换句话说，我们有一个我们想要缓存的每个 JS 文件的列表。更重要的是，资产清单会使用每个文件的新哈希更新，因此我们不必担心保持其最新。

因此，我们可以使用资产清单中的 URL 以及`Cache.addAll()`方法一次性缓存所有我们的 JavaScript 资产。但是，我们还需要手动将我们的静态资产（图像）添加到缓存中，但是为了这样做，我们将不得不利用我们的服务工作者生命周期方法并进行一些基本设置。

# 设置我们的缓存

在本节中，我们将通过我们的三个主要服务工作者生命周期事件，并在每个事件中单独与我们的缓存进行交互。最终，我们将自动缓存所有静态文件。

不过，要警告一下——在开发中使用缓存，充其量是可以容忍的，最坏的情况下是令人恼火的。我们对着屏幕大喊：“为什么你不更新？”直到我们意识到我们的缓存一直在提供旧代码；这种情况发生在我们每个人身上。在本节中，我们将采取措施避免缓存我们的开发文件，并躲避这个问题，但是在未来，请记住奇怪的错误可能是由缓存引起的。

在计算机科学中只有两件难事：缓存失效和命名事物。- Phil Karlton

另一个方法：

在计算机科学中有两个难题：缓存失效、命名事物和 off-by-1 错误。- Leon Bambrick

# 安装事件

当我们的服务工作者安装时，我们希望立即设置我们的缓存，并开始缓存相关的资产。因此，我们的安装事件的逐步指南如下：

1.  打开相关的缓存。

1.  获取我们的资产清单。

1.  解析 JSON。

1.  将相关的 URL 添加到我们的缓存中，以及我们的静态资产。

让我们打开`firebase-messaging-sw.js`并开始工作！

如果你仍然有`console.log`事件监听器用于安装，很好！删除`console.log`；否则，设置如下：

```jsx
self.addEventListener('install', function() {

});
```

就在这个函数的上面，我们还会将我们的缓存对象名称分配给一个变量：

```jsx
const CACHE_NAME = ‘v1’;
```

这个名称可以是任何东西，但我们希望每次部署时都提高版本，以确保旧的缓存无效，并且每个人都能获得尽可能新鲜的代码。

现在，让我们按照清单来运行。

# 打开缓存

在我们开始正题之前，我们需要谈谈可扩展事件。

一旦我们的服务工作线程被激活和安装，它可能会立即进入“等待”模式--等待必须响应的事件发生。然而，我们不希望它在我们正在打开缓存的过程中进入等待模式，这是一个异步操作。因此，我们需要一种告诉我们的服务工作线程的方法，“嘿，直到缓存被填充，不要认为自己完全安装了。”

我们通过`event.waitUntil()`来实现这一点。这个方法延长了事件的生命周期（在这里是安装事件），直到其中的所有 Promise 都被解决。

它看起来如下所示：

```jsx
self.addEventListener('install', event => {
 event.waitUntil(
   // Promise goes here
 );
});
```

现在我们可以打开我们的缓存。我们的缓存 API 在全局变量 caches 中可用，所以我们可以直接调用`caches.open()`：

```jsx
const CACHE_NAME = 'v1';
self.addEventListener('install', event => {
 event.waitUntil(
   caches.open(CACHE_NAME)
     .then(cache => {
     });
 );
});
```

由于当前不存在名称为'v1'的缓存对象，我们将自动创建一个。一旦获得了该缓存对象，我们就可以进行第二步。

# 获取资产清单

获取资产清单听起来就像它听起来的那样：

```jsx
self.addEventListener('install', event => {
 event.waitUntil(
   caches.open(CACHE_NAME)
     .then(cache => {
       fetch('asset-manifest.json')
         .then(response => {
           if (response.ok) {

           }
         })
     });
 );
});
```

请注意，在开发中我们不应该有 asset-manifest；在继续之前，我们需要确保请求响应是正常的，以免抛出错误。

# 解析 JSON

我们的`asset-manifest.json`返回了一些 JSON，相当令人惊讶。让我们解析一下：

```jsx
self.addEventListener('install', event => {
 event.waitUntil(
   caches.open(CACHE_NAME)
     .then(cache => {
       fetch('asset-manifest.json')
         .then(response => {
           if (response.ok) {
             response.json().then(manifest => {

             });
           }
         })
     });
 );
});
```

现在我们有一个 manifest 变量，它是一个普通的 JavaScript 对象，与`asset-manifest.json`的内容相匹配。

# 将相关的 URL 添加到缓存

由于我们有一个 JavaScript 对象来访问 URL，我们可以挑选我们想要缓存的内容，但在这种情况下，我们想要一切，所以让我们遍历对象并获得一个 URL 数组：

```jsx
response.json().then(manifest => {
  const urls = Object.keys(manifest).map(key => manifest[key]);
})
```

我们还想缓存`index.html`和我们的图标，所以让我们推入`/`和`/assets/icon.png`：

```jsx
response.json().then(manifest => {
  const urls = Object.keys(manifest).map(key => manifest[key]);
  urls.push(‘/’);
  urls.push('/assets/icon.png');
})
```

现在，我们可以使用`cache.addAll()`将所有这些 URL 添加到缓存中。请注意，我们指的是我们打开的特定缓存对象，而不是一般的 caches 变量：

```jsx

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      fetch('asset-manifest.json').then(response => {
        if (response.ok) {
          response.json().then(manifest => {
            const urls = Object.keys(manifest).map(key => manifest[key]);
            urls.push('/');
            urls.push('/assets/icon.png');
            cache.addAll(urls);
          });
        }
      });
    })
  );
});
```

完成！我们已经进行了缓存，但目前还不值得多少，因为我们还没有办法从缓存中检索项目。让我们接着做。

# 获取事件

当我们的应用程序从服务器请求文件时，我们希望在服务工作线程内拦截该请求，并用缓存的文件进行响应（如果存在）。

我们可以通过监听 fetch 事件来实现这一点，如下所示：

```jsx
self.addEventListener('fetch', event => {

});
```

作为参数传递的事件有两个有趣的属性。第一个是`event.request`，它是目标 URL。我们将使用它来查看我们的缓存中是否有该项，但事件还有一个名为`respondWith`的方法，基本上意味着“停止这个网络请求的进行，并用以下内容回应它。”

这里是不直观的部分--我们实质上是在调用`event.respondWith`后立即取消了这个 fetch 事件。这意味着如果我们的缓存中没有该项，我们必须开始另一个 fetch 请求（幸运的是，这不会触发另一个事件监听器；这里没有递归）。这是需要记住的一点。

因此，让我们调用`event.respondWith`，然后使用`caches.match`来查看我们是否有与 URL 匹配的文件：

```jsx
self.addEventListener('fetch', event => {
 event.respondWith(
   caches.match(event.request).then(response => {

   });
 );
});
```

在这种情况下，响应要么是问题文件，要么是空。如果是文件，我们就返回它；否则，我们发起另一个 fetch 请求并返回其结果。以下是一行版本：

```jsx
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
```

就是这样！现在我们资产清单中的文件的所有 fetch 请求都将首先进入缓存，只有在该文件不在缓存中时才会进行实际的网络请求。

# 激活事件

激活事件是我们三个 service worker 事件中发生的第一个，所以可能看起来奇怪我们最后才谈论它，但这是有原因的。

激活事件是我们进行缓存清理时发生的。我们确保清除任何过期的缓存对象，以便我们的浏览器缓存不会变得太混乱并被终止。

为此，我们基本上删除任何名称与`CACHE_NAME`的当前值不匹配的缓存对象。

“但是，Scott，”你说，“如果我们的 service worker 没有正确更新，并且仍然包含旧的`CACHE_NAME`怎么办？”这是一个有效的观点。然而，正如所说的，我们的 service worker 应该在它与上一个 service worker 之间有字节大小的差异时自动更新，所以这不应该成为一个问题。

这次我们的过程不那么密集，但我们仍然来分解一下：

1.  获取缓存名称列表。

1.  循环遍历它们。

1.  删除任何键不匹配`CACHE_NAME`的缓存。

一个快速提醒--如果你想将你的 CSS 保存在一个单独的缓存中，你可以拥有多个缓存。这样做没有真正的好处，但你可能喜欢有组织的东西。一个可行的方法是创建一个`CACHE_NAMES`对象，如下所示：

```jsx
const VERSION = ‘v1’
const CACHE_NAMES = {
 css: `css-${VERSION}`,
 js: `js-${VERSION}`
};
```

然后，在随后的步骤中，我们将不得不迭代该对象；只是要记住的一些事情。

好的，让我们开始工作。

# 获取缓存名称列表

同样，我们必须在完成此异步代码时使用`event.waitUntil()`。这意味着我们最终将不得不返回一个`Promise`给`event.waitUntil()`，这将影响我们编写代码的方式。

首先，我们通过调用`cache.keys()`来获取缓存键的列表，这会返回一个 promise：

```jsx
self.addEventListener('activate', event => {
 event.waitUntil(
   cache.keys().then(keyList => {

   })
 );
});
```

# 循环遍历它们

我们需要遍历每个键，并调用`caches.delete()`，如果它不匹配我们的`CACHE_NAME`。由于我们可能有多个要删除的缓存，并且多次调用`caches.delete()`，它本身返回一个`Promise`，我们将在`keyList`上映射，并使用`Promise.all()`返回一组`Promise`。

它看起来是这样的：

```jsx
self.addEventListener('activate', event => {
 event.waitUntil(
   caches.keys().then(keyList => {
     Promise.all(keyList.map(key => {

     }));
   })
 );
});
```

删除任何键不匹配`CACHE_NAME`的缓存。

一个简单的`if`语句，然后调用`caches.delete()`，我们就完成了：

```jsx
self.addEventListener('activate', event => {
 event.waitUntil(
   caches.keys().then(keyList => {
     Promise.all(
       keyList.map(key => {
         if (key !== CACHE_NAME) {
           return caches.delete(key);
         }
       })
     );
   })
 );
});
```

现在我们的缓存将恰好是我们想要的大小（仅在缓存对象上），并且每次我们的服务工作者激活时都会被检查。

因此，我们的缓存保持更新的机制是固有的。每次更新 JavaScript 时，我们都应该更新服务工作者中的版本。这会导致我们的服务工作者更新，从而重新激活，触发对先前缓存的检查和失效；一个美丽的系统。

# 测试我们的缓存

使用**`yarn start`**快速在本地运行您的应用程序，以检查是否有任何明显的错误（拼写错误等），如果一切正常，请启动**`yarn deploy`**。

打开您的实时应用程序和 Chrome DevTools。在应用程序|服务工作者下关闭更新后重新加载，刷新一次，然后转到网络选项卡。您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00089.jpeg)如果这不起作用，请尝试取消注册应用程序|服务工作者下的任何服务工作者，然后重新加载两次。

关键点是（来自服务工作者）在我们的 JavaScript 文件旁边。我们的静态资产是由我们的服务工作者缓存提供的，如果您滚动到网络选项卡的顶部，您将看到这样的情况：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00090.jpeg)

文档本身是由服务工作者提供的，这意味着我们可以在任何网络条件下运行我们的应用程序，甚至是离线的；让我们试试。点击网络选项卡顶部的离线复选框，然后点击重新加载。

如果一切顺利，我们的应用程序的加载时间不应该有任何区别，即使我们没有网络连接！我们的应用程序仍然可以加载，我们的聊天消息也是如此。

消息加载是 Firebase 数据库的一个好处，不是我们的功劳，但是从缓存中加载文档，这才是真正的成就！

当然，我们的用户体验并没有很好地为离线访问做准备。我们应该有一种方式来通知用户他们当前处于离线状态，也许可以通过某种对话框，但我们将其作为一个目标。

# 总结

我们实现了渐进式梦想——一个可以在任何网络条件下工作的应用程序，包括完全没有网络的情况。缓存是一个复杂的主题，所以为自己的成就鼓掌吧。

然而，在我们过于兴奋并将我们的原型提交给 Chatastrophe 董事会之前，让我们确保我们做对了事情。我们需要一种方式来在我们的项目上盖上一个橡皮图章，上面写着“批准！这是一个渐进式网络应用！”。

幸运的是，一个名为 Google 的小型初创公司已经给了我们一个可以做到这一点的工具。

接下来是对我们完成的渐进式网络应用进行审计，也就是胜利之旅。


# 第十三章：审核我们的应用程序

**审核**是确认我们的渐进式 Web 应用程序是否真正符合 PWA 标准的一种方式。这种审核是我们检查工作并确保我们的应用在 PWA 功能方面尽可能好的重要最后一步。

如前所述，渐进式 Web 应用程序的最大支持者是谷歌。他们的 Chrome 浏览器和 Android 操作系统不仅是所有 PWA 友好的，而且谷歌还非常努力地教育开发人员如何以及为什么构建 PWA。当您进入 PWA 的世界时（超出本书范围），您可能经常会查阅他们的文档。

然而，谷歌提供了另一种引领渐进式网络前进的方式。为了确保您的网页或应用程序的质量，他们发布了一套工具来衡量您的网站是否符合一组标准。他们用来做到这一点的主要工具称为 Lighthouse。

以下是本章将涵盖的内容：

+   Lighthouse 是什么？

+   它遵循哪些标准？

+   DevTools 中的审核标签是什么？

+   运行我们的第一次审核

+   评估读数

+   使用 Lighthouse CLI

# Lighthouse 是什么？

简而言之，**Lighthouse**是一个工具，运行您的网站并告诉您基于一组特定标准它到底有多渐进式。

它通过尝试在各种条件下加载页面（包括 3G 网络和离线），并评估页面的响应方式来实现。它还检查一些 PWA 的常规功能，例如启动画面和服务工作者。

# 标准

以下标准本质上是 Lighthouse 在查看您的应用程序时遵循的一份清单。每个“测试”都是一个简单的是/否。如果您通过所有测试，您将获得 100 分。这就是我们想要的！

以下是 2017 年 8 月的标准列表：

+   **注册服务工作者**：服务工作者是使您的应用能够使用许多渐进式 Web 应用程序功能的技术，例如离线、添加到主屏幕和推送通知。

+   **离线时响应 200**：如果您正在构建渐进式 Web 应用程序，请考虑使用服务工作者，以便您的应用程序可以离线工作。

+   当 JavaScript 不可用时包含一些内容：即使只是警告用户 JavaScript 是必需的，您的应用程序也应在 JavaScript 被禁用时显示一些内容。

+   配置自定义启动画面：您的应用将构建一个默认的启动画面，但满足这些要求可以保证一个高质量的启动画面，让用户从点击主屏幕图标到应用的首次绘制有一个流畅的过渡。

+   使用 HTTPS：所有网站都应该使用 HTTPS 进行保护，即使不处理敏感数据的网站也是如此。HTTPS 可以防止入侵者篡改或被动监听您的应用与用户之间的通信，并且是 HTTP/2 和许多新的网络平台 API 的先决条件。

+   将 HTTP 流量重定向到 HTTPS：如果您已经设置了 HTTPS，请确保将所有 HTTP 流量重定向到 HTTPS。

+   3G 网络下的页面加载速度足够快：如果**交互时间**短于 10 秒，即满足 PWA 基准检查表中的定义（来源--[`developers.google.com/web/progressive-web-apps/checklist`](https://developers.google.com/web/progressive-web-apps/checklist)），则满足此标准。需要进行网络限速（具体来说，预期的 RTT 延迟>=150 RTT）。

+   用户可以被提示安装 Web 应用：虽然用户可以手动将您的网站添加到其主屏幕，但如果满足各种要求并且用户对您的网站有适度的参与度，提示（也称为应用安装横幅）将主动提示用户安装应用。

+   地址栏与品牌颜色匹配：浏览器地址栏可以进行主题设置以匹配您的网站。当用户浏览网站时，``theme-color``元标签将升级地址栏，一旦添加到主屏幕后，清单主题颜色将在整个网站上应用相同的主题。

+   具有带有宽度或初始缩放的<meta name="viewport">标签：添加`viewport`元标签以优化您的应用在移动屏幕上的显示。

+   内容在视口中正确调整大小：如果您的应用内容的宽度与视口的宽度不匹配，您的应用可能没有针对移动屏幕进行优化。

# 审核标签

直到 Chrome 60 发布之前，Lighthouse 只能作为 Chrome 扩展程序或命令行工具的测试版版本。然而，现在它在 Chrome DevTools 中有了自己的位置，在新的**审核标签**中。

在审核标签中，除了 Lighthouse PWA 审核之外，还包括一系列其他基准测试，包括性能和网络最佳实践。我们将专注于 PWA 测试和性能测试，但也可以随意运行其他测试。

审计选项卡的另一个有用功能是能够保存先前的审计，以便在改进应用程序时获得应用程序的历史记录。

好了，说够了。让我们继续进行我们的第一次审计！

# 我们的第一次审计

打开您的 DevTools，导航到审计选项卡，然后单击运行审计。

应该需要几秒钟，然后给您一个关于我们网站外观的简要摘要，鼓掌。我们的渐进式 Web 应用程序有多好呢？：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00091.jpeg)

一点也不糟糕。事实上，在 PWA 类别中没有比这更好的了。给自己一个鼓励，也许是一个成功的高五。让我们评估读数，然后决定是否要继续前进或者争取在所有类别中达到 100%。

请注意，由于 Lighthouse 正在积极开发中，您的分数可能与上述不符合新的标准。在这种情况下，我鼓励您查看 Lighthouse 所抱怨的内容，并看看是否可以解决问题以达到“100”分。

# 评估读数

如果您的结果与前面的不符，有两种可能性：

+   Chrome 添加了我们的应用程序无法满足的新测试。正如我们多次提到的，PWA 是一种不断发展的技术，所以这是完全可能的。

+   您在书中错过了一些步骤；最好的人也会发生这种情况。

无论哪种情况，我都鼓励您进行调查并尝试解决根本问题。谷歌为每个测试标准提供了文档，这是一个很好的起点。

在我们的情况下，我们唯一没有通过的测试是性能。让我们看看我们没有通过的原因：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00092.jpeg)

正如我们在这里看到的，我们的第一个有意义的绘制大约需要三秒钟。请注意，我们的应用程序外壳不被视为有意义的绘制，尽管它确实改善了页面的感知性能。Chrome 足够聪明，知道只有当我们的“登录”表单或“聊天”容器出现时，我们才真正在屏幕上有有意义的内容--用户实际可以使用的东西。

尽管如此，显示有意义的内容需要超过三秒的原因是，我们需要等待我们的 JavaScript 加载，启动，然后加载我们的用户当前是否已登录，然后加载聊天消息或重定向到登录。这是很多后续步骤。

这是一个可以解决的问题吗？也许可以。我们可以设置一些方式，在 React 加载之前找出用户是否已登录（换句话说，将一些 JavaScript 移出我们的主应用程序）。我们可以将`chat`容器和`login`表单都移出 React，以确保它们可以在库加载之前呈现，然后想出一些方法在 React 初始化后替换它们（挑战在于替换输入而不擦除用户已开始输入的任何内容）。

所有提到的挑战都属于优化关键渲染路径的范畴。对于任何想深入了解性能优化的人，我鼓励你去尝试一下。然而，从商业角度来看，这对于一点收益来说是很多（可能有错误）优化。根据先前的基准测试，我们的用户已经在大约 400 毫秒内接收到内容，并且完整的应用程序在三秒多一点的时间内加载完成。请记住，由于缓存，大多数用户在随后的访问中将获得更快的加载时间。

我们较低的性能得分实际上展示了使用诸如 React 之类的庞大 JavaScript 库构建高性能应用程序的成本效益。对于那些对更轻量级替代方案感兴趣的人，在下一章节中查看关于 Preact 的部分，这可能是解决前述问题的一个可能方案。

# 使用 Lighthouse CLI

从审计选项卡运行测试非常简单易行，但我们如何确保在将应用程序推送到线上之前保持应用程序的质量呢？

答案是将 Lighthouse 纳入我们的部署流程，并使用它自动评估我们的构建。这类似于在我们执行`yarn deploy`时运行测试套件。幸运的是，谷歌为此目的提供了 Lighthouse CLI。

让我们使用以下命令进行安装：

```jsx
yarn add --dev lighthouse
```

在这里，我们的目标是在执行`yarn deploy`时在我们的应用程序上运行 Lighthouse。为此，我们必须制作一个自定义部署脚本。

如果打开我们的`package.json`，你会在`scripts`下看到以下内容：

```jsx
 "scripts": {
   "build": "node_modules/.bin/webpack --config webpack.config.prod.js",
   "start": "node_modules/.bin/webpack-dev-server",
   "deploy": "npm run build && firebase deploy"
 },
```

让我们将其更改为以下内容：

```jsx
 "scripts": {
   "build": "node_modules/.bin/webpack --config webpack.config.prod.js",
   "start": "node_modules/.bin/webpack-dev-server",
   "deploy": "npm run build && node scripts/assess.js && firebase deploy"
 },
```

我们将使用 node 来运行一个用 JavaScript 编写的自定义构建脚本。在你的目录根目录下创建`scripts/文件夹`，以及`assess.js`文件。

我们的流程将如下：

1.  在本地提供我们的`build`文件夹，以便在浏览器中运行。

1.  使用 Lighthouse 评估提供的页面。

1.  在控制台记录结果。

让我们添加我们需要用来提供我们的`build`文件夹的包：

```jsx
yarn add --dev serve
```

请注意，鉴于我们永远不会在生产中使用它们，我们将这个和`lighthouse`保存为`dev`依赖项。

# 服务我们的构建文件夹

在我们的新`scripts/assess.js`中，要求`serve`包：

```jsx
const serve = require('serve');
```

我们只想要在端口 5000 上`serve`我们新编译的`build`文件夹，看起来是这样的：

```jsx
const server = serve('./build', {
 port: 5000
});
```

我们可以随时通过运行`server.stop()`来停止服务器。我们会在显示分数后这样做。

# 使用 Lighthouse 来评估提供的页面

现在，让我们在`assess.js`的顶部要求另外两个工具：

```jsx
const lighthouse = require('lighthouse');
const chromeLauncher = require('lighthouse/chrome-launcher');
```

`chromeLauncher`将允许我们打开 Chrome 到目标页面，然后运行 Lighthouse。让我们创建一个名为`launchChromeAndRunLighthouse`的函数来做到这一点：

```jsx
function launchChromeAndRunLighthouse(url, flags= {}, config = null) {

}
```

我们可以选择传入一些标志和配置，这里我们不会使用（标志可以用来在过程展开时打开日志记录）。

在函数内部，我们将启动 Chrome，设置 Lighthouse 运行的端口，然后运行它。最后，我们将停止 Chrome：

```jsx
function launchChromeAndRunLighthouse(url, flags = {}, config = null) {
 return chromeLauncher.launch().then(chrome => {
   flags.port = chrome.port;
   return lighthouse(url, flags, config).then(results =>
     chrome.kill().then(() => results));
 });
}
```

顺便说一句，这个函数直接来自 Lighthouse CLI 文档。

好了，现在是最后一步了。我们将使用我们选择的 URL 运行我们的函数（将其放在文件底部，在`serve`命令下方）：

```jsx
launchChromeAndRunLighthouse('http://localhost:5000', {}).then(results => {
  server.stop();
});
```

一旦我们有了结果，我们就停止服务器，但我们需要正确显示我们的结果。

# 记录结果

结果变量以对象的形式出现。它提供了每个类别的详细分数，但我们只关心有问题的地方。在我们的函数调用之前，让我们添加一个分数截止线：

```jsx
const CUTOFF = 90
launchChromeAndRunLighthouse('http://localhost:5000', {}).then(results => {
```

我们将使用这个来说“只显示得分低于 90/100 的结果”。

登出结果的过程并不是很令人兴奋，所以我们不会在这里深入讨论。以下是完整的文件：

```jsx
const serve = require('serve');
const lighthouse = require('lighthouse');
const chromeLauncher = require('lighthouse/chrome-launcher');

function launchChromeAndRunLighthouse(url, flags = {}, config = null) {
 return chromeLauncher.launch().then(chrome => {
   flags.port = chrome.port;
   return lighthouse(url, flags, config).then(results =>
     chrome.kill().then(() => results));
 });
}

const server = serve('./build', {
 port: 5000
})

const CUTOFF = 90

launchChromeAndRunLighthouse('http://localhost:5000', {}).then(results => {
 score = results.score
 const catResults = results.reportCategories.map(cat => {
   if (cat.score < CUTOFF) {
     cat.audits.forEach(audit => {
       if (audit.score < CUTOFF) {
         const result = audit.result
         if (result.score) {
           console.warn(result.description + ': ' + result.score)
         } else {
           console.warn(result.description)
         }
         if (results.displayValue) {
           console.log('Value: ' + result.displayValue)
         }
         console.log(result.helpText)
         console.log(' ')
       }
     })
   }
   return cat
 })
 catResults.forEach(cat => {
   console.log(cat.name, cat.score)
 })
 server.stop()
});
```

如果您从终端运行`node scripts/assess.js`，您应该会看到一个问题区域的列表，以及每个类别的最终得分。通过运行`yarn deploy`将所有内容汇总在一起，您将在 Firebase 部署之前看到这些分数。

现在我们有了一个简单而干净的方法来随时了解我们应用程序的状态，而不必自己启动网站来测试它。

# 总结

完成！我们对我们的应用进行了全面审查，它在每个类别都表现出色。我们有一个可用的渐进式 Web 应用程序。在本章中，我们了解了 Lighthouse 是什么，以及为什么验证我们的 PWA 很重要。我们还将其作为部署过程的一部分，以确保我们的应用程序继续符合质量标准。现在我们可以认为我们的应用在各个方面都已经完成。

接下来，我们将讨论后续步骤以及增加对 PWA 知识的有用资源，但首先，关于将我们的应用提交给你的朋友和 Chatastrophe 委员会。


# 第十四章：结论和下一步

“……这就是应用程序根据谷歌的评分。正如您所看到的，它符合渐进式 Web 应用的每个标准，这将与我们的全球业务目标很好地契合——”

“是的，是的，”你的朋友挥了挥手。“很酷。很棒。干得好。但枢纽呢？”

“什么？”你问道。

“你没收到备忘录吗？我一个月前就给你公司邮箱发了一封备忘录。”

“我不知道我有公司邮箱。”

“哦。”你的朋友皱起了眉头。“我以为你对技术很在行。”

“但我不知道——”

“没关系。我可以总结一下。公司已经转变了。聊天很棒，但如果我们再进一步呢？如果我们把它变成一个社交网络呢？想象一下——Facebook 的可分享性，Netflix 的视频流和 Uber 的顺风车，所有这些都在一个区块链上……”

当你走向门口时，你的朋友继续说话。

# 下一步

我们已经涵盖了将 React 应用程序转变为 PWA 所需的每一步，但是，像往常一样，还有更多要学习的。

本章分为四个部分。首先，我们将列出一些有用的资源，以继续您的 PWA 之旅。然后，我们将介绍一些重要的库，这些库将帮助自动化 PWA 开发的某些方面，或将您的应用程序提升到更高的水平。第三，我将列出一些我最喜欢的关于开发渐进式 Web 应用的文章。最后，我们将看一下一些可能的扩展目标，以便您在接受挑战后扩展和改进 Chatastrophe。

以下许多资源都是通过两个优秀的存储库发现的：**awesome-pwa** ([`github.com/hemanth/awesome-pwa`](https://github.com/hemanth/awesome-pwa)) 由 GitHub 用户*Hemanth*创建，以及**awesome-progressive-web-apps** ([`github.com/TalAter/awesome-progressive-web-apps`](https://github.com/TalAter/awesome-progressive-web-apps)) 由*TalAter*创建。

我们将看一下以下内容：

+   扩展您知识的学习资源

+   成功 PWA 的案例研究

+   可以从中获得灵感的示例应用程序

+   关于 PWA 崛起的必读文章

+   您可以使用的工具来使未来 PWA 的构建更容易

+   Chatastrophe 的扩展目标

# 学习资源

学习资源如下：

+   **渐进式 Web 应用文档**：谷歌关于渐进式 Web 应用的官方文档。这应该是您的第一站，以了解概念或阅读最佳实践。它还提供了关于 PWA 的好处的摘要，并链接到诸如 Lighthouse 之类的工具。

[`developers.google.com/web/progressive-web-apps/`](https://developers.google.com/web/progressive-web-apps/)

+   **你的第一个渐进式 Web 应用**：一个逐步教程，教你如何构建你的第一个渐进式 Web 应用，或者在你的情况下，你的第二个。如果你想看看没有 React 的情况下构建 PWA 是什么样子，可以看看这个教程。这是非常详细的，涵盖了每个概念。

[`developers.google.com/web/fundamentals/getting-started/codelabs/your-first-pwapp`](https://developers.google.com/web/fundamentals/getting-started/codelabs/your-first-pwapp)

+   **离线 Web 应用**：由 Google 创建并由 Udacity 托管的免费课程，关于离线优先的 Web 应用。内容分为三个部分：为什么优先离线、Service Workers 和缓存。一些部分，比如 service worker 部分，可能会是复习，但这门课程还深入探讨了 IndexedDB 用于本地存储。

[`www.udacity.com/course/offline-web-applications--ud899`](https://www.udacity.com/course/offline-web-applications--ud899)

+   **Service Worker 入门**：Google 对 Service Workers 的介绍。很多代码看起来会很熟悉，因为它们在本书的 service worker 部分中出现过，但它仍然是一个方便的资源。Matt Gaunt 做了很好的工作，解释了基础知识。

[`developers.google.com/web/fundamentals/getting-started/primers/service-workers`](https://developers.google.com/web/fundamentals/getting-started/primers/service-workers)

+   **Service Worker 101**：关于 service workers 的更加生动的指南，这个可爱的资源包含一系列图表，带你了解 service worker 的生命周期等内容。如果你对 service workers 不确定，可以打印出来贴在你的桌子上。

[`github.com/delapuente/service-workers-101`](https://github.com/delapuente/service-workers-101)

+   **开始使用渐进式 Web 应用**：Chrome 开发团队的 *Addy Osmani* 的一篇博客文章（我们将在这个资源部分经常看到他）。这是一个很好的高层次介绍 PWA 的好处，并介绍了一些起步的模板。

[`addyosmani.com/blog/getting-started-with-progressive-web-apps/`](https://addyosmani.com/blog/getting-started-with-progressive-web-apps/)

+   **使用 Push API**：Mozilla 开发者网络关于 Push API 的指南。如果你想在你的 PWA 中使用推送通知，而不依赖于 Firebase Cloud Notifications，就从这里开始。

[`developer.mozilla.org/en-US/docs/Web/API/Push_API/Using_the_Push_API`](https://developer.mozilla.org/en-US/docs/Web/API/Push_API/Using_the_Push_API)

+   **使用缓存 API**：Mozilla 开发者网络对缓存 API 的指南。在这里没有太多新东西，我们在缓存章节中没有涵盖到的，但鉴于缓存 API 的“实验性”状态，回头参考一下是很好的。这项技术可以从目前的状态发展，所以把它作为一个参考。

[`developer.mozilla.org/en-US/docs/Web/API/Cache`](https://developer.mozilla.org/en-US/docs/Web/API/Cache)

+   **通过应用安装横幅增加用户参与度**：应用安装横幅的如何和为什么。一个详尽的常见问题解答了你可能有的任何问题。还有一个关于推迟提示的很棒的教程，你可以用它来巩固我们在第九章中涵盖的概念，*使用清单使我们的应用可安装*。

[`developers.google.com/web/updates/2015/03/increasing-engagement-with-app-install-banners-in-chrome-for-android?hl=en`](https://developers.google.com/web/updates/2015/03/increasing-engagement-with-app-install-banners-in-chrome-for-android?hl=en)

+   **Web 基础-性能**：谷歌关于构建高性能 Web 应用的资源。值得注意的是，谷歌对性能有一个特定的哲学，属于 PWA 模型，但不一定是更好性能的唯一途径。也就是说，对于任何对速度感兴趣的人来说，这是一个很棒的（有时过于技术性的）资源。

[`developers.google.com/web/fundamentals/performance/`](https://developers.google.com/web/fundamentals/performance/)

+   **引入 RAIL：面向用户的性能模型**：这篇文章以“性能建议不胜枚举，是吗？”开篇。这是真实的话，尽管*Paul Irish*和*Paul Lewis*的建议比大多数更好。这篇文章特别关注为什么我们应该遵循这个指标来介绍 RAIL。答案？用户应该放在第一位。

[`www.smashingmagazine.com/2015/10/rail-user-centric-model-performance/`](https://www.smashingmagazine.com/2015/10/rail-user-centric-model-performance/)

+   **渐进式 Web 应用通讯简报**：我的免费通讯，让你了解渐进式 Web 应用的世界，包括教程、文章、有趣的项目等。如果你想要联系我，只需点击下一期的“回复”。我会很乐意收到你的来信。

[`pwa-newsletter.com/`](http://pwa-newsletter.com/)

+   **网站性能优化**：另一个由谷歌和 Udacity 合作的课程，这次是关于优化性能的课程。它介绍了 DevTools 并深入探讨了关键渲染路径等概念。这门课程应该需要大约一周的时间来完成。

[`www.udacity.com/course/website-performance-optimization--ud884`](https://www.udacity.com/course/website-performance-optimization--ud884)

+   **浏览器渲染优化**：这里还有一个！这门课程的副标题是“构建 60 FPS Web 应用”，这是一个值得追求的目标（正如我们的 RAIL 指标建议的那样）。它可以被认为是前面课程的更深入版本。在完成这门课程后，你可以称自己为 Web 性能专家。

[`www.udacity.com/course/browser-rendering-optimization--ud860`](https://www.udacity.com/course/browser-rendering-optimization--ud860)

+   **使用 React 构建渐进式 Web 应用**：*Addy Osmani*再次出现。在这里，他带领我们使用 React 构建 PWA。请注意，这个教程更像是一个概述，而不是一个逐步指南，但在我写这本书时，这对我来说是一个非常宝贵的资源。他还提供了许多链接到其他文章和资源，以进一步扩展你的知识。

>[`medium.com/@addyosmani/progressive-web-apps-with-react-js-part-i-introduction-50679aef2b12`](https://medium.com/@addyosmani/progressive-web-apps-with-react-js-part-i-introduction-50679aef2b12)

+   **Service Worker Cookbook**：关于 service workers 的一切你想知道的东西。说真的，这是一个了不起的资源，会让你很快成为专家。如果你对这项新技术感到兴奋并想深入了解，这是一个很好的机会。

[`serviceworke.rs/`](https://serviceworke.rs/)

+   **将你的网站改造成 PWA**：大多数公司不会立即从头开始构建 PWA。相反，他们会希望将 PWA 功能添加到他们现有的网站或应用中。这是一个很好的入门指南，并附有大量的截图。

[`www.sitepoint.com/retrofit-your-website-as-a-progressive-web-app/`](https://www.sitepoint.com/retrofit-your-website-as-a-progressive-web-app/)

# 案例研究

你需要说服老板尝试渐进式 Web 应用吗？看看以下大公司采用 PWA 的案例研究（Chatastrophe Inc.因破产而被移出列表）。

# 构建 Google I/O 2016 渐进式 Web 应用

Google I/O 2016 应用程序（昵称 IOWA）是使用 Firebase 和 Polymer 构建的。这就是他们的做法。这是一个更加技术性的指南，介绍了几个高级概念；这是一个了解下一级 PWA 的好方法。

[`developers.google.com/web/showcase/2016/iowa2016`](https://developers.google.com/web/showcase/2016/iowa2016)

# AliExpress 案例研究

AliExpress 是俄罗斯访问量最大的电子商务网站。通过转换为 PWA，他们将新用户的转化率提高了 104%。他们还将在网站上花费的时间增加了 74%。这些都是很大的数字，为 PWA 提供了一个有力的商业案例。

[`developers.google.com/web/showcase/2016/aliexpress`](https://developers.google.com/web/showcase/2016/aliexpress)

# eXtra Electronics 案例研究

这对于业务改进来说怎么样--销售额增加了 100%。这就是 eXtra Electronics 通过网络推送通知到达的用户所取得的成就。事实上，网络推送通知现在是 eXtra 最大的留存渠道，超过了电子邮件。更加努力！

[`developers.google.com/web/showcase/2016/extra`](https://developers.google.com/web/showcase/2016/extra)

# Jumia 案例研究

又一个关于网络推送通知的好消息。Jumia 的转化率增加了 9 倍。他们过去会发送电子邮件提醒顾客购物车中剩下的物品，但开启率很低。现在引入了通知。

[`developers.google.com/web/showcase/2016/jumia`](https://developers.google.com/web/showcase/2016/jumia)

# Konga 案例研究

你的用户关心他们的数据限制；不要让他们受苦。Konga 将他们的原生应用与 PWA 进行比较，将数据使用量减少了 92%。最终，用户完成第一笔交易所需的数据减少了 84%。考虑到入门的障碍降低了。

[`developers.google.com/web/showcase/2016/konga`](https://developers.google.com/web/showcase/2016/konga)

# SUUMO 案例研究

通过添加服务工作者和一些其他调整，SUUMO 团队将加载时间减少了 75%。他们还利用了推送通知的热潮，开启率达到了 31%。尝试 PWA 的决定背后的故事可能听起来很熟悉；移动体验很差，所以公司将用户推向原生应用。然而，让他们下载原生应用却很困难，所以他们尝试了 PWA。一个很好的教训--如果你的问题是留存，原生应用可能不是答案。

[`developers.google.com/web/showcase/2016/suumo`](https://developers.google.com/web/showcase/2016/suumo)

# 示例应用程序

想看看真正的渐进式 Web 应用程序是什么样子吗？看看以下任何一个。其中一些还包含 GitHub 的链接，供您查看源代码。

# PWA.rocks

这是一个渐进式 Web 应用程序的集合，也是以下大部分内容的来源。如果您需要灵感，可以将其作为第一站。我还鼓励您将您添加到列表中的任何 PWA 添加到其中。

[`pwa.rocks/`](https://pwa.rocks/)

# Flipboard

Flipboard 是 PWA 领域中最重要的参与者之一，他们的 PWA 应用程序体积小，速度快，而且美观。Flipboard 拥有功能齐全的原生应用程序，但也有 PWA，以便在用户偏好方面进行押注。如果内容丰富的 Flipboard 能够符合 PWA 的性能指南，那么天空就是极限。

[`flipboard.com/`](https://flipboard.com/)

# React Hacker News

这是一个备受欢迎的开发者项目：使用 React 克隆的 Hacker News。作为一个开源项目，ReactHN 是了解如何使用渐进式 Web 应用程序基本原理来管理复杂的前端库的好方法。我们的好朋友*Addy Osmani*再次出马。因此，ReactHN 是一个深入了解 Chrome 开发人员如何使用 JavaScript 库构建 PWA 的内部视角。

[`react-hn.appspot.com`](https://react-hn.appspot.com/#/?_k=5kbr5v)/

# Notes

这是一个很好的、体积小的渐进式 Web 应用程序的例子，值得初学者关注。您可以在网站上直接找到 GitHub 的链接，然后查看*Simon Evans*应用程序的结构。在桌面上，应用程序外壳与内容有明显的区别，这使得概念特别直观。最重要的是，该应用在 Lighthouse 上得分 94 分。

[`sii.im/playground/notes/`](https://sii.im/playground/notes/)

# Twitter

也许你听说过这个。

Twitter 是一个真正全球化应用程序的完美例子。他们的应用程序需要能够被所有大陆的用户在各种条件下访问（只需看看 Twitter 在组织阿拉伯之春中所扮演的角色）。

为了实现全球可访问性，Twitter 团队设法将他们的应用程序减小到 1MB，并添加了本文讨论的所有 PWA 功能：主屏幕安装、推送通知和离线访问。

[`lite.twitter.com/`](https://lite.twitter.com/)

# 2048 Puzzle

2048 拼图游戏的 PWA 实现，最初由 Veewo Studio 创建。它只适用于移动/触摸设备，但它是一个游戏应用程序被制作成 PWA 的例子，它快速、高效且可安装。请注意-对于未经培训的人来说，这个游戏非常容易上瘾。

这个开源项目可以在 GitHub 上找到，所以你可以查看结构（特别是 JavaScript 的结构，需要十个文件来运行游戏）。然而，这个应用的不可告人的秘密是，创作者实际上从未打过这个游戏。

[`2048-opera-pwa.surge.sh/`](https://2048-opera-pwa.surge.sh/)

# 阅读的文章

以下文章涵盖了宣言、教程和清单，都是关于 PWA 的崛起以及构建它们的最佳方法。

# 原生应用注定要失败

JavaScript 大师*Eric Elliott*对渐进式 Web 应用的热情宣言。这是对原生应用成本和 PWA 好处的深入探讨。这是一个很好的材料，可以说服正在辩论是否要构建原生应用的老板和同事。后续文章也很棒。

[`medium.com/javascript-scene/native-apps-are-doomed-ac397148a2c0`](https://medium.com/javascript-scene/native-apps-are-doomed-ac397148a2c0)

# 渐进式 Web 应用的一大堆技巧和窍门

*Dean Hume*的各种 PWA 技巧的大杂烩。看看有趣的东西，比如离线 Google Analytics 和测试服务工作者（随着我们继续前进，会有更多内容）。

[`deanhume.com/Home/BlogPost/a-big-list-of-progressive-web-app-tips-and-tricks/10160`](https://deanhume.com/Home/BlogPost/a-big-list-of-progressive-web-app-tips-and-tricks/10160)

# 测试服务工作者

服务工作者是渐进式 Web 应用功能的核心。我们希望确保它们正常工作。我们如何对它们进行单元测试？

[`medium.com/dev-channel/testing-service-workers-318d7b016b19`](https://medium.com/dev-channel/testing-service-workers-318d7b016b19)

# Twitter Lite 和高性能 React 渐进式 Web 应用的规模

Twitter Lite 工程师之一深入探讨了他们的构建过程、挑战，并在开发 Twitter 的 PWA 版本后提出了建议。这是关于部署大规模 PWA 的最接近的操作指南。

[`medium.com/@paularmstrong/twitter-lite-and-high-performance-react-progressive-web-apps-at-scale-d28a00e780a3`](https://medium.com/@paularmstrong/twitter-lite-and-high-performance-react-progressive-web-apps-at-scale-d28a00e780a3)

# 为什么应用安装横幅仍然存在？

这是一个关于当你不是市场领导者时坚持传统应用程序的成本以及渐进式 Web 应用程序如何解决这个问题的优秀总结。阅读到最后，了解一些从原生应用程序转换为 PWA 的公司的统计数据。

[`medium.com/dev-channel/why-are-app-install-banners-still-a-thing-18f3952d349a`](https://medium.com/dev-channel/why-are-app-install-banners-still-a-thing-18f3952d349a)

# 使用 Vue JS 创建渐进式 Web 应用程序

*Charles Bochet*结合了 VueJS，Webpack 和 Material Design 的元素来构建 PWA。这是一个很好的机会，可以在一个新的库中尝试 PWA 概念。

[`blog.sicara.com/a-progressive-web-application-with-vue-js-webpack-material-design-part-3-service-workers-offline-ed3184264fd1`](https://blog.sicara.com/a-progressive-web-application-with-vue-js-webpack-material-design-part-3-service-workers-offline-ed3184264fd1)

# 将现有的 Angular 应用程序转换为渐进式 Web 应用程序

将常规 Angular 应用程序转换为功能性渐进式 Web 应用程序需要什么？*Coskun Deniz*一步一步地带领我们完成了这些步骤。

[`medium.com/@cdeniz/transforming-an-existing-angular-application-into-a-progressive-web-app-d48869ba391f`](https://medium.com/@cdeniz/transforming-an-existing-angular-application-into-a-progressive-web-app-d48869ba391f)

# 推动 Web 前进

“实际上，任何网站都可以，也应该成为渐进式 Web 应用。”

*Jeremy Keith*在他的文章中提出了“推动 Web”的主要论点，他是对的。使您的应用程序（或静态站点）成为渐进式，是为所有用户提供增强体验。对于任何对跳入 PWA 世界持怀疑态度的人来说，这是一篇很好的阅读。

[`medium.com/@adactio/progressing-the-web-9ab55f63f9fa`](https://medium.com/@adactio/progressing-the-web-9ab55f63f9fa)

# 设计降级-敌对环境的 UX 模式

Chipotle 餐厅如何帮助改进您的网站。本文并不特别讨论 PWA，但与渐进增强的概念完全契合，即您的网站应该适用于所有人，然后根据他们的条件（网络速度，浏览器现代性等）变得越来越好。

[`uxdesign.cc/designed-degradations-ux-patterns-for-hostile-environments-7f308d819e50`](https://uxdesign.cc/designed-degradations-ux-patterns-for-hostile-environments-7f308d819e50)

# 使用应用程序外壳架构实现即时加载 Web 应用程序

对应用程序外壳模式的深入解释。如果你正在开发 PWA，这是必读的。

[`medium.com/google-developers/instant-loading-web-apps-with-an-application-shell-architecture-7c0c2f10c73`](https://medium.com/google-developers/instant-loading-web-apps-with-an-application-shell-architecture-7c0c2f10c73)

# 欺骗用户，让他们觉得你的网站比实际更快

一篇很棒的文章，从用户的角度出发（感知时间与实际时间），然后解释了你可以利用的基本技术，来减少应用的感知加载时间。

[`www.creativebloq.com/features/trick-users-into-thinking-your-sites-faster-than-it-is`](http://www.creativebloq.com/features/trick-users-into-thinking-your-sites-faster-than-it-is)

# 苹果拒绝支持渐进式网络应用对未来的网络是一个损害

一个令人耳目一新的诚实看待在这个时候开发渐进式网络应用的经历，以及与 iOS 相关的挣扎。如果你正在考虑生产 PWA，请阅读这篇文章。

[`m.phillydevshop.com/apples-refusal-to-support-progressive-web-apps-is-a-serious-detriment-to-future-of-the-web-e81b2be29676`](https://m.phillydevshop.com/apples-refusal-to-support-progressive-web-apps-is-a-serious-detriment-to-future-of-the-web-e81b2be29676)

# 工具

希望你将来会构建（许多）更多的渐进式网络应用。以下工具将使这个过程更容易、更快速。

# Workbox

Workbox 是“一组用于渐进式网络应用的 JavaScript 库”。更具体地说，它“使创建最佳服务工作者代码变得容易”，并以最有效的方式维护你的缓存。它很容易集成到 Webpack 中。不幸的是，文档不是很好，定制可能会很困难。

然而，Workbox 有很大的潜力，可以自动化开发的各个方面，并隐藏可能会让新开发者望而却步的复杂性。挑战在于不要用更多的复杂性来取代这种复杂性。

[`github.com/GoogleChrome/workbox`](https://github.com/GoogleChrome/workbox)

# Sw-precache

作为 Workbox 的子集，sw-precache 值得单独讨论。它可以用来自动生成一个服务工作者，以预缓存你的应用程序资产。你所需要做的就是将它纳入你的构建过程（有一个 Webpack 插件），并注册生成的服务工作者。

[`github.com/GoogleChrome/sw-precache`](https://github.com/GoogleChrome/sw-precache)

# Sw-toolbox

不适合初学者！与前面的生成工具不同，sw-toolbox 是一组辅助方法。更令人困惑的是，还有 Google Chrome 团队的 Workbox，采用了更模块化的方法。我给你的建议是，先熟悉直接与服务工作者交互，然后，如果你有一个特定的问题可以通过这些工具之一简化，那就采用它。但是，不要去寻找解决你尚未遇到的问题的工具，但像我说的，看到出现的工具来帮助管理复杂性是令人兴奋的。

[`github.com/GoogleChrome/sw-toolbox`](https://github.com/GoogleChrome/sw-toolbox)

# Offline-plugin

另一个使你的应用程序具有离线功能的插件。这个插件使用服务工作者，但为了更好的支持，会回退到 AppCache API。实现看起来简单而直接。

[`github.com/NekR/offline-plugin`](https://github.com/NekR/offline-plugin)

# Manifest-json

一个工具，可以从命令行自动生成 Web 应用程序清单。我的意思是，我觉得我的清单章节还不错，但如果你更喜欢问答式的方法，那也可以，我想。

开玩笑的，这个工具可能会在 Web App 清单发展并承担更多属性时派上用场。

[`www.npmjs.com/package/manifest-json`](https://www.npmjs.com/package/manifest-json)

# Serviceworker-rails

有一个 Ruby on Rails 项目吗？想让你的资产管道使用服务工作者来缓存资产吗？使用这个宝石。文档是 Rails 如何处理缓存和实现服务工作者方法的有趣概述。

[`github.com/rossta/serviceworker-rails`](https://github.com/rossta/serviceworker-rails)

# Sw-offline-google-analytics

前面提到的 Workbox 的一部分，但专门用于具有离线功能的应用程序的 Google Analytics。使用此软件包在连接可用时发送离线请求到 Google Analytics。

[`www.npmjs.com/package/sw-offline-google-analytics`](https://www.npmjs.com/package/sw-offline-google-analytics)

# Dynamic Service Workers (DSW)

使用 JSON 文件配置你的服务工作者；这是一种非常有趣的服务工作者方法，支持关键功能，如推送通知（尽管只能使用 Google Cloud Messaging）。

[`github.com/naschq/dsw`](https://github.com/naschq/dsw)

# UpUp

在您的网站上添加两个脚本，并使其在离线状态下工作。UpUp 是服务工作者技术的美丽实现，适用于简单的用例。当然，它并不适用于高级用户，但是是向每个人介绍服务工作者技术的绝佳方式。

[`www.talater.com/upup/`](https://www.talater.com/upup/)

# 生成渐进式 Web 应用

从命令行生成渐进式 Web 应用文件结构！这仍然是一个正在进行中的工作。

[`github.com/hemanth/generator-pwa`](https://github.com/hemanth/generator-pwa)

# 渐进式 Web 应用配置

另一个来自 Addy Osmani 的样板文件。如果您要构建非 React PWA，请参考此项目结构。

[`github.com/PolymerLabs/progressive-webapp-config`](https://github.com/PolymerLabs/progressive-webapp-config)

# 延伸目标

Chatastrophe 已经启动，但仍然非常基础。现在我们将讨论一些挑战，您可以选择接受，以拓展您的技能并改进我们的应用。

# 切换到 Preact

Preact 是 React 库的 3 KB 版本。它具有类似的 API 和功能，但没有冗余。使用它而不是 React 将提高我们应用的性能。如果您选择这条路线，请考虑使用 Webpack 别名来简化转换。

[`github.com/developit/preact`](https://github.com/developit/preact)

# 显示在线状态

告诉其他用户另一个用户何时在线。UI 由您决定。

# 显示正在输入

在聊天室中常见的功能，用于向用户指示其他人正在输入。对于 Chatastrophe，挑战将是同时表示多个用户正在输入。

# 包括文件上传

人们想要与朋友分享（可能是表情包）。为他们提供一个文件上传系统。

# 创建聊天室

您的朋友曾经有一个真正全球聊天室的愿景；那个愿景很糟糕。让我们通过允许用户创建聊天室来大大提高 Chatastrophe 的可用性。是否有一种方法可以让用户在离线状态下在房间之间导航并阅读消息？

# 无需 React 即可交互

阻碍我们性能的一个问题是需要 React 在向用户显示交互式站点之前启动。如果我们给他们一个纯 HTML 交互式外壳，然后在加载时切换到 React 版本会怎样？这里的挑战将是避免覆盖用户输入，但您可以赢得一些巨大的性能点。

# 构建自己的后端

在本教程中，我们依赖 Firebase，以便将注意力集中在前端，即 React 开发上。然而，在为 Chatastrophe 设计自己的后端 API 方面，有很大的学习机会。最大的好处是可以对页面进行服务器渲染，以获得额外的性能。

# 结束语

编程很困难。学习也很困难。在学习全新概念的同时使用实验性技术进行编程尤其困难。如果你完成了本书中的教程，甚至只是其中的某些部分，你应该为此感到自豪。

我真诚地希望你在这里学到的东西对你的职业有所帮助。这本书对我来说也是一次激动人心的旅程。当我开始时，我对渐进式 Web 应用程序的世界感到兴奋，但绝不是专家。现在，深入研究渐进式 Web 后，我对可能性比以往任何时候都更加兴奋。我希望你也有同样的感觉。

如果你想要联系我，我会很乐意听到你的反馈、批评、问题，或者只是闲聊。你可以在 Twitter 上找到我，用户名是`@scottdomes`，在 LinkedIn 上找到我，也可以在 Medium 上找到我，用户名同样是`@scottdomes`，或者在我的网站[`scottdomes.com`](http://scottdomes.com)上找到我，我在那里发布关于各种主题的 Web 开发教程。

# 总结

我希望提到的资源对你继续 PWA 之旅有所帮助。PWA 是 Web 开发中令人兴奋的一部分，发展迅速；关注前任作者和创作者将帮助你跟上变化的步伐。

在这本书中，我们涵盖了很多内容：从零到一个 React 应用程序，再从一个 React 应用程序到一个渐进式 Web 应用程序。我们从头开始构建了一个完整的应用程序，并部署到世界上可以看到它。我们还使它快速响应，并能够处理各种类型的连接。

我希望你为最终的应用感到自豪，也希望这本书对你有所帮助。祝你未来的所有 PWA 项目好运，让我们继续推动 Web 的发展。
