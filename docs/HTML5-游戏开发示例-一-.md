# HTML5 游戏开发示例（一）

> 原文：[`zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC`](https://zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML5 承诺成为在线游戏的热门新平台。HTML5 游戏可以在计算机，智能手机和平板电脑上运行，包括 iPhone 和 iPad。成为第一批今天构建 HTML5 游戏的开发人员，并为明天做好准备！

本书将向您展示如何使用最新的 HTML5 和 CSS3 网络标准来构建纸牌游戏，绘画游戏，物理游戏，甚至是通过网络的多人游戏。通过本书，您将通过清晰系统的教程构建六个示例游戏。

HTML5，CSS3 和相关的 JavaScript API 是网络中的最新热门话题。这些标准为我们带来了新的游戏市场，HTML5 游戏。借助它们的新力量，我们可以使用 HTML5 元素，CSS3 属性和 JavaScript 设计在浏览器中玩的游戏。

本书分为九章，每章专注于一个主题。我们将创建六个游戏，并具体学习如何绘制游戏对象，对它们进行动画处理，添加音频，连接玩家，并使用 Box2D 物理引擎构建物理游戏。

# 本书涵盖了什么

第一章，介绍 HTML5 游戏，介绍了 HTML5，CSS3 和相关 JavaScript API 的新功能。它还演示了我们可以使用这些功能制作什么游戏以及它的好处。

第二章，开始 DOM 游戏开发，通过在 DOM 和 jQuery 中创建传统的乒乓球游戏，启动游戏开发之旅。

第三章，在 CSS3 中构建记忆匹配游戏，介绍了 CSS3 的新功能，并讨论了如何在 DOM 和 CSS3 中创建记忆卡匹配游戏。

第四章，使用 Canvas 和绘图 API 构建解开游戏，介绍了一种在网页中绘制游戏并与之交互的新方法，使用新的 Canvas 元素。它还演示了如何使用 Canvas 构建解谜游戏。

第五章，构建 Canvas 游戏大师班，扩展了解开游戏，展示了如何使用 Canvas 绘制渐变和图像。它还讨论了精灵表动画和多层管理。

第六章，为您的游戏添加声音效果，通过使用“音频”元素向游戏添加声音效果和背景音乐。它讨论了网络浏览器之间的音频格式能力，并在本章末创建了一个键盘驱动的音乐游戏。

第七章，使用本地存储存储游戏数据，扩展了 CSS3 记忆匹配游戏，以演示如何使用新的本地存储 API 来存储和恢复游戏进度和最佳记录。

第八章，使用 WebSockets 构建多人画图猜词游戏，讨论了新的 WebSockets API，它允许浏览器与套接字服务器建立持久连接。这允许多个玩家实时一起玩游戏。本章末创建了一个画图猜词游戏。

第九章，使用 Box2D 和 Canvas 构建物理汽车游戏，教授如何将著名的物理引擎 Box2D 集成到我们的 Canvas 游戏中。它讨论了如何创建物理实体，施加力，将它们连接在一起，将图形与物理相关联，并最终创建一个平台卡车游戏。

# 本书需要什么

您需要最新的现代网络浏览器，一个良好的文本编辑器，以及基本的 HTML，CSS 和 JavaScript 知识。

# 这本书适合谁

本书适用于具有 HTML、CSS 和 JavaScript 基本理解，并希望创建在浏览器上运行的 Canvas 或基于 DOM 的游戏的游戏设计师。

# 约定

在本书中，您会经常看到几个标题。

为了清晰地说明如何完成一个过程或任务，我们使用：

# 行动时间标题

1.  动作 1

1.  动作 2

1.  动作 3

指示通常需要一些额外的解释，以便理解，因此它们后面会跟着：

## 刚刚发生了什么？

这个标题解释了您刚刚完成的任务或指示的工作原理。

您还会在本书中找到一些其他学习辅助工具，包括：

## 弹出测验标题

这些是简短的多项选择问题，旨在帮助您测试自己的理解。

## 试试看英雄标题

这些设置了实际的挑战，并为您提供了尝试所学内容的想法。

您还会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们将从`index.html`开始我们的 HTML5 游戏开发之旅。”

代码块设置如下：

```js
// starting game
var date = new Date();
audiogame.startingTime = date.getTime();
// some time later
var date = new Date();
var elapsedTime = (date.getTime() - audiogame.startingTime)/1000;

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
function setupLevelData()
{
var notes = audiogame.leveldata.split(";");
// store the total number of dots
audiogame.totalDotsCount = notes.length;
for(var i in notes)
{
var note = notes[i].split(",");
var time = parseFloat(note[0]);
var line = parseInt(note[1]);
var musicNote = new MusicNote(time,line);
audiogame.musicNotes.push(musicNote);
}
}

```

任何命令行输入或输出都以如下形式书写：

```js
$ ./configure
$ sudo make install

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会出现在文本中，就像这样：“您将获得多用户草图板的介绍页面。右键单击**启动实验**选项，然后选择**在新窗口中打开链接**”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：介绍 HTML5 游戏

> 超文本标记语言 HTML 在过去几十年中一直在塑造互联网。它定义了内容在网页中的结构以及相关页面之间的链接。HTML 从 2 版到 HTML 4.1 版再到 XHTML 1.1 版不断发展。由于这些网络应用程序和社交网络应用程序，HTML 现在正在向 HTML5 迈进。
> 
> **层叠样式表**（**CSS**）定义了网页的视觉呈现方式。它为所有 HTML 元素和它们的状态（如悬停和激活）定义样式。
> 
> JavaScript 是网页的逻辑控制器。它使网页动态化，并在页面和用户之间提供客户端交互。它通过**文档对象模型**（**DOM**）访问 HTML。它通过应用不同的 CSS 样式来重新设计 HTML 元素。

这三个功能为我们带来了新的游戏市场，HTML5 游戏。有了它们的新力量，我们可以使用 HTML5 元素、CSS3 属性和 JavaScript 设计游戏在浏览器中玩耍。

在本章中，我们将：

+   发现 HTML5 中的新功能

+   讨论让我们对 HTML5 和 CSS3 如此兴奋的原因

+   看看其他人如何使用 HTML5 进行游戏设计

+   预览我们将在后面章节中构建的游戏

所以让我们开始吧。

# 在 HTML5 中发现新功能

HTML5 和 CSS3 中引入了许多新功能。在我们开始创建游戏之前，让我们概览一下这些新功能，看看我们如何使用它们来创建游戏。

## 画布

**Canvas**是 HTML5 元素，提供低级别的绘制形状和位图操作功能。我们可以将 Canvas 元素想象成一个动态图像标签。传统的`<img>`标签显示静态图像。无论图像是动态生成的还是静态加载自服务器，图像都是静态的，不会改变。我们可以将`<img>`标签更改为另一个图像源，或者对图像应用样式，但我们无法修改图像的位图上下文本身。

另一方面，Canvas 就像是一个客户端动态的`<img>`标签。我们可以在其中加载图像，在其中绘制形状，并通过 JavaScript 与之交互。

Canvas 在 HTML5 游戏开发中扮演着重要角色。这是本书的主要关注点之一。

## 音频

背景音乐和音效通常是游戏设计中的重要元素。HTML5 通过`audio`标签提供了本地音频支持。由于这一功能，我们不需要专有的 Flash Player 来播放 HTML5 游戏中的音效。我们将在第六章讨论`audio`标签的用法，*使用 HTML5 音频元素构建音乐游戏*。

## 地理位置

**地理位置**让网页获取用户计算机的纬度和经度。多年前，当每个人都在使用台式电脑上网时，这个功能可能并不那么有用。我们并不需要用户的道路级别的位置精度。我们可以通过分析 IP 地址获得大致位置。

如今，越来越多的用户使用强大的智能手机上网。Webkit 和其他现代移动浏览器都在每个人的口袋里。地理位置让我们设计移动应用程序和游戏，以便使用位置信息。

基于位置的服务已经在一些社交网络应用程序中使用，例如 foursquare ([`foursquare.com`](http://foursquare.com))和 Gowalla ([`gowalla.com`](http://gowalla.com))。这种基于位置的社交社区的成功创造了使用位置服务与我们的智能手机的趋势。

## WebGL

WebGL 通过在 Web 浏览器中提供一组 3D 图形 API 来扩展 Canvas 元素。该 API 遵循 OpenGL ES 2.0 的标准。WebGL 为 3D HTML5 游戏提供了一个真正的 3D 渲染场所。然而，在撰写本书时，并非所有浏览器都原生支持 WebGL。目前，只有 Mozilla Firefox 4、Google Chrome 和 WebKit 浏览器的夜间构建版本原生支持它。

为 WebGL 创建游戏的技术与通常的 HTML5 游戏开发有很大不同。在 WebGL 中创建游戏需要处理 3D 模型，并使用类似于 OpenGL 的 API。因此，本书不会讨论 WebGL 游戏开发。

来自 Google Body（[`bodybrowser.googlelabs.com`](http://bodybrowser.googlelabs.com)）的以下屏幕截图演示了他们如何使用 WebGL 显示一个响应用户输入的 3D 人体。

![WebGL](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_01.jpg)

### 提示

LearningWebGL（[`learnwebgl.com`](http://learnwebgl.com)）提供了一系列关于开始使用 WebGL 的教程。如果您想要学习更多关于使用它的知识，这是一个很好的起点。

## WebSocket

WebSocket 是 HTML5 规范的一部分，用于将网页连接到套接字服务器。它为浏览器和服务器之间提供了事件驱动的连接。这意味着客户端不需要每隔一段时间轮询服务器以获取新数据。只要有数据更新，服务器就会将更新推送到浏览器。这个功能的一个好处是游戏玩家几乎可以实时互动。当一个玩家做了什么并将数据发送到服务器时，服务器将向每个其他连接的浏览器广播一个事件，以确认玩家刚刚做了什么。这创造了创建多人 HTML5 游戏的可能性。

### 注意

由于安全问题，Mozilla Firefox 和 Opera 现在暂时禁用了 WebSocket。Safari 和 Chrome 也可能在问题解决之前放弃对 WebSocket 的支持。您可以通过访问以下链接了解更多关于这个问题的信息：[`hacks.mozilla.org/2010/12/websockets-disabled-in-firefox-4/`](http://hacks.mozilla.org/2010/12/websockets-disabled-in-firefox-4/)。

## 本地存储

HTML5 为 Web 浏览器提供了持久的数据存储解决方案。

本地存储可以持久地存储键值对数据。即使浏览器终止，数据仍然存在。此外，数据不仅限于只能由创建它的浏览器访问。它对具有相同域的所有浏览器实例都是可用的。由于本地存储，我们可以在 Web 浏览器中轻松地本地保存游戏状态，如进度和获得成就。

HTML5 还提供了 Web SQL 数据库。这是一个客户端关系数据库，目前受 Safari、Chrome 和 Opera 支持。通过数据库存储，我们不仅可以存储键值对数据，还可以支持 SQL 查询的复杂关系结构。

本地存储和 Web SQL 数据库对我们在创建游戏时本地保存游戏状态非常有用。

除了本地存储，一些其他存储方法现在也得到了 Web 浏览器的支持。这些包括 Web SQL 数据库和 IndexedDB。这些方法支持根据条件查询存储的数据，因此更适合支持复杂的数据结构。

您可以在 Mozilla 的以下链接中找到更多关于使用 Web SQL 数据库和 IndexedDB 的信息：[`hacks.mozilla.org/2010/06/comparing-indexeddb-and-webdatabase/`](http://hacks.mozilla.org/2010/06/comparing-indexeddb-and-webdatabase/)。

## 离线应用程序

通常我们需要互联网连接来浏览网页。有时我们可以浏览缓存的离线网页。这些缓存的离线网页通常会很快过期。通过 HTML5 引入的下一个离线应用程序，我们可以声明我们的缓存清单。这是一个文件列表，将在没有互联网连接时存储以供以后访问。

通过缓存清单，我们可以将所有游戏图形、游戏控制 JavaScript 文件、CSS 样式表和 HTML 文件本地存储。我们可以将我们的 HTML5 游戏打包成桌面或移动设备上的离线游戏。玩家甚至可以在飞行模式下玩游戏。

来自 Pie Guy 游戏（[`mrgan.com/pieguy`](http://mrgan.com/pieguy)）的以下屏幕截图显示了 iPhone 上的 HTML5 游戏，没有互联网连接。请注意离线状态的小飞机符号：

![离线应用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_02.jpg)

# 发现 CSS3 中的新功能

CSS 是演示层，HTML 是内容层。它定义了 HTML 的外观。在使用 HTML5 创建游戏时，尤其是基于 DOM 的游戏，我们不能错过 CSS。我们可能纯粹使用 JavaScript 来创建和设计带有 Canvas 元素的游戏。但是在创建基于 DOM 的 HTML5 游戏时，我们需要 CSS。因此，让我们看看 CSS3 中有什么新内容，以及如何使用新属性来创建游戏。

新的 CSS3 属性让我们可以以不同的方式在 DOM 中进行动画，而不是直接在 Canvas 绘图板上绘制和交互。这使得可以制作更复杂的基于 DOM 的浏览器游戏。

## CSS3 过渡

传统上，当我们对元素应用新样式时，样式会立即更改。CSS3 过渡在目标元素的样式更改期间应用插值。

例如，我们这里有一个蓝色的框，当我们鼠标悬停时想要将其变为红色。我们将使用以下代码片段：

HTML：

```js
<a href="#" class="box"></a>

```

CSS：

```js
a.box {
display:block;
width: 100px;
height: 100px;
background: #00f; /* blue */
border: 1px solid #000;
}
a.box:hover {
background: #f00;
}

```

当我们鼠标悬停时，框立即变为红色。应用了 CSS3 过渡后，我们可以使用特定持续时间和缓动值来插值样式：

```js
a.box {
-webkit-transition: all 5s linear;
}

```

### 提示

**下载本书的示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便直接将文件发送到您的电子邮件。

以下屏幕截图显示了应用过渡的框悬停效果：

![CSS3 过渡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_03.jpg)

### 注意

由于 CSS3 规范仍处于草案阶段，尚未确定，因此来自不同浏览器供应商的实现可能与 W3C 规范有一些细微差异。因此，浏览器供应商倾向于使用供应商前缀来实现其 CSS3 属性，以防止冲突。

Safari 和 Chrome 使用`-webkit-`前缀。Opera 使用`-o-`前缀。Firefox 使用`-moz-`前缀，IE 使用`-ms-`前缀。现在声明 CSS3 属性，例如 box-shadow，可能有点复杂，需要为几个浏览器编写几行相同的规则。我们可以期望在该属性规范确定后，前缀将被消除。

我将在大多数示例中只使用`-webkit-`前缀，以防止在书中放置太多相似的行。更重要的是理解概念，而不是在这里阅读带有不同供应商前缀的相同规则。

## CSS3 变换

CSS3 变换让我们可以缩放元素，旋转元素和平移它们的位置。CSS3 变换分为 2D 和 3D。

我们可以用 translate 重新定位一个元素：

```js
-webkit-transform: translate(x,y);

```

或者使用缩放变换来缩放元素：

```js
-webkit-transform: scale(1.1);

```

我们还可以使用 CSS3 变换来缩放和旋转元素，并结合其他变换：

```js
a.box {
-webkit-transition: all 0.5s linear;
-webkit-transform: translate(100px,50px);
}
a.box:hover {
-webkit-transform: translate(100px,50px) scale(1.1) rotate(30deg);
}

```

以下屏幕截图显示了当我们鼠标悬停时 CSS3 变换效果：

![CSS3 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_04.jpg)

CSS3 变换 3D 进一步将空间扩展到三个轴，目前仅在 Safari 和移动 Safari 上有效。来自[WebKit.org](http://WebKit.org)的以下屏幕截图显示了当我们鼠标悬停时 3D 卡片翻转效果：

![CSS3 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_05.jpg)

## CSS3 动画

CSS3 过渡是一种动画类型。它声明了元素的两种样式之间的插值动画。

CSS3 动画是更进一步的一步。我们可以定义动画的关键帧。每个关键帧包含应在该时刻更改的一组属性。这就像一组应用于目标元素的 CSS3 过渡的序列。

AT-AT Walker ([`anthonycalzadilla.com/css3-ATAT/index-bones.html`](http://anthonycalzadilla.com/css3-ATAT/index-bones.html)) 展示了使用 CSS3 动画关键帧、变换和过渡创建骨骼动画的演示：

![CSS3 动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_06.jpg)

# 学习更多 HTML5 和 CSS3 新功能的细节

来自 Google 的 HTML5Rocks（[`html5rocks.com`](http://html5rocks.com)）提供了一个关于新 HTML5 元素和 CSS3 属性的坚实的快速入门指南。

苹果还展示了在其基于 WebKit 的浏览器中使用 HTML5 可以有多么吸引人（[`apple.com/html5`](http://apple.com/html5)）。

CSS3 Info（[`www.css3.info`](http://www.css3.info)）是一个提供最新 CSS3 新闻的博客。这是一个获取最新 CSS3 规范状态、兼容列表和基本 CSS3 代码的好地方。

# 创建 HTML5 游戏的好处

我们探索了 HTML5 和 CSS3 的一些关键新功能。有了这些功能，我们可以在浏览器上创建 HTML5 游戏。但是为什么我们需要这样做呢？创建 HTML5 游戏有什么好处呢？

## 不需要第三方插件

在现代浏览器中原生支持所有这些功能，我们不需要用户预先安装任何第三方插件才能进行游戏。这些插件不是标准的。它们是专有的，通常需要额外的插件安装，我们可能无法安装。

## 支持 iOS 设备而无需插件

全球数百万的苹果 iOS 设备不支持 Flash Player 等第三方插件。无论苹果出于什么原因不允许 Flash Player 在他们的移动 Safari 上运行，HTML5 和相关的 Web 标准是他们在浏览器中得到的。我们可以通过创建为移动设备优化的 HTML5 游戏来触及这一用户群体。

## 打破传统浏览器游戏的界限

在传统的游戏设计中，我们在一个边界框内构建游戏。我们在电视上玩视频游戏。我们在网页浏览器中玩 Flash 游戏，有一个矩形边界。

有了创意，我们不再受限于矩形游戏舞台。我们可以玩弄所有页面元素，甚至可以使用许多浏览器窗口来组成一个游戏。此外，我们甚至可以只使用 URL 栏来创建一个游戏（[`probablyinteractive.com/url-hunter`](http://probablyinteractive.com/url-hunter)）。这可能听起来有些混乱，但这是因为还没有多少网页这样做。

Photojojo（[`photojojo.com/store/awesomeness/cell-phone-lenses`](http://photojojo.com/store/awesomeness/cell-phone-lenses)）是一个在线摄影商店，在其商店页面上提供了一个有趣的彩蛋功能。页面上有一个带有标题“不要拉”的开关按钮。当用户点击它时，一个橙色的手臂从顶部出现，帧逐帧地进行动画处理。它像一块布一样抓住网页并将整个页面向上拉，创建一个有趣的向下滚动效果。这不是一个游戏，但足够有趣，可以展示我们如何打破界限。

![打破传统浏览器游戏的界限](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_07.jpg)

这里有另一个例子，名为 Twitch（[`reas.com/twitch/`](http://reas.com/twitch/)），来自 Chrome 实验。这是一个迷你游戏集合，玩家必须将球从起点运送到终点。有趣的是，每个迷你游戏都是一个小型浏览器窗口。当球到达该迷你游戏的目的地时，它会被转移到新创建的迷你游戏浏览器中继续旅程。以下截图显示了 Twitch 的整个地图以及各个网页浏览器：

![打破传统浏览器游戏的界限](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_08.jpg)

## 构建 HTML5 游戏

由于 HTML5 和 CSS3 的新功能，我们现在可以在浏览器中创建整个游戏。我们可以控制 DOM 中的每个元素。我们可以使用 CSS3 对每个文档对象进行动画处理。我们有 Canvas 来动态绘制和与之交互。我们有音频元素来处理背景音乐和音效。我们还有本地存储来保存游戏数据和 WebSocket 来创建实时多人游戏。大多数现代浏览器已经支持这些功能。现在是时候制作 HTML5 游戏了。

# 其他人正在玩的 HTML5 游戏

通过观察使用不同技术制作的其他 HTML5 游戏，我们有机会研究不同 HTML5 游戏的表现。

## 匹配游戏

匹配游戏 ([`10k.aneventapart.com/Uploads/300/`](http://10k.aneventapart.com/Uploads/300/)) 展示了一个美丽的匹配游戏，使用了 CSS3 动画和其他视觉增强效果。当您按下 3D 样式的 CSS 按钮时，游戏开始。卡片在背面和正面使用 3D 旋转翻转。正面的图案是从在线画廊动态获取的。

![匹配游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_09.jpg)

## Sinuous

Sinuous ([`10k.aneventapart.com/Uploads/83/`](http://10k.aneventapart.com/Uploads/83/))，10K Apart 的获胜者，向我们展示了一个简单的游戏想法如何通过适当的实现让人上瘾。玩家用鼠标控制空间中的大点。目标是移动点以避开飞来的彗星。听起来很简单，但绝对让人上瘾，是一个“再试一次”的游戏。这个游戏是用 Canvas 标签创建的。玩家还可以在他们的支持 webkit 的移动设备上玩这个游戏，比如 iPhone、iPad 和 Android。

![Sinuous](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_10.jpg)

## 类似于小行星的书签

来自瑞典的网页设计师 Erik 创建了一个有趣的书签。它是一个适用于任何网页的类似小行星的游戏。是的，任何网页。它展示了与任何网页进行交互的一种异常方式。它在您正在阅读的网站上创建了一个飞机。然后您可以使用箭头键驾驶飞机，并使用空格键发射子弹。有趣的是，子弹会摧毁页面上的 HTML 元素。您的目标是摧毁您选择的网页上的所有东西。这个书签是打破通常浏览器游戏界限的又一个例子。它告诉我们，在设计 HTML5 游戏时，我们可以打破常规思维。

该书签可以在以下网址安装：[`erkie.github.com/`](http://erkie.github.com/)。

以下的截图显示了飞机摧毁网页内容的情况：

![类似于小行星的书签](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_11.jpg)

## Quake 2

谷歌演示了第一人称射击游戏 Quake 2 的 WebGL HTML5 移植版。玩家可以使用 WSAD 键四处移动，并用鼠标射击敌人。玩家甚至可以通过 WebSocket 实时进行多人游戏。据谷歌称，HTML5 Quake 2 的每秒帧数可以达到 60 帧。

![Quake 2](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_12.jpg)

Quake 2 移植版可以在 Google Code 上找到：[`code.google.com/p/quake2-gwt-port/`](http://code.google.com/p/quake2-gwt-port/)。

## RumpeTroll

RumpeTroll ([`rumpetroll.com/`](http://rumpetroll.com/)) 是 HTML5 社区的一个实验，每个人都可以通过 WebSocket 连接在一起。我们可以给我们的生物取名字，并通过鼠标点击四处移动。我们还可以输入任何内容开始聊天。此外，由于 WebSocket 插入，我们可以实时看到其他人在做什么。

![RumpeTroll](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_13.jpg)

## Scrabb.ly

Scrabb.ly ([`scrabb.ly`](http://scrabb.ly)) 是一个多人游戏，赢得了 Node.js Knockout 比赛的人气奖。它使用 HTML5 WebSocket 将用户连接在一起。这个在线棋盘游戏是基于 DOM 的，由 JavaScript 驱动。

![Scrabb.ly](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_14.jpg)

### 注意

Node.js (http://nodejs.org) 是一个事件驱动的服务器端 JavaScript。它可以用作连接并发 WebSocket 客户端的服务器。

## Aves Engine

Aves Engine 是由 dextrose 开发的 HTML5 游戏开发框架。它为游戏开发者提供了工具和 API，用于构建自己的等距浏览器游戏世界和地图编辑器。从官方演示视频中捕获的以下截图显示了它是如何创建等距世界的：

![Aves Engine](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_15.jpg)

该引擎还负责 2.5 维等距坐标系统、碰撞检测和其他基本的虚拟世界功能。这个游戏引擎甚至在 iPad 和 iPhone 等移动设备上运行良好。Aves Engine 自首次亮相以来就引起了很多关注，现在已被大型社交游戏公司 Zynga Game Network Inc 收购。

Aves Engine 的视频演示可在 YouTube 上通过以下链接观看：

[`tinyurl.com/dextrose-aves-engine-sneak`](http://tinyurl.com/dextrose-aves-engine-sneak)

# 浏览更多 HTML5 游戏

这些例子只是其中的一部分。以下网站提供了由他人创建的 HTML5 游戏的更新：

+   Canvas Demo ([`canvasdemo.com`](http://canvasdemo.com)) 收集了一系列使用 HTML5 Canvas 标签的应用程序和游戏。它还提供了大量 Canvas 教程资源。这是学习 Canvas 的好地方。

+   HTML5 游戏 ([`html5games.com`](http://html5games.com)) 收集了许多 HTML5 游戏，并将它们组织成不同的类别。

+   Mozilla Labs 在 2011 年初举办了一个 HTML5 游戏设计比赛，许多优秀的游戏被提交到比赛中。比赛现在已经结束，所有参赛作品的列表在以下链接：[`gaming.mozillalabs.com/games/`](http://https://gaming.mozillalabs.com/games/)。

+   HTML5 Game Jam ([`www.html5gamejam.com/games`](http://www.html5gamejam.com/games)) 是一个 HTML5 活动，该网站列出了一系列有趣的 HTML5 游戏，还提供了一些有用的资源。

# 我们将在本书中创建的内容

在接下来的章节中，我们将构建六款游戏。我们将首先创建一个基于 DOM 的乒乓球游戏，可以由同一台机器上的两名玩家进行游戏。然后我们将创建一个带有 CSS3 动画的记忆匹配游戏。之后，我们将使用 Canvas 创建一个解开谜题的游戏。接下来，我们将使用音频元素创建一个音乐游戏。然后，我们将使用 WebSocket 创建一个多人绘画和猜谜游戏。最后，我们将使用 Box2D JavaScript 端口创建一个物理汽车游戏的原型。以下截图是我们将在第三章中构建的记忆匹配游戏的截图，*在 CSS3 中构建记忆匹配游戏*

![我们将在本书中创建的内容](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_01_16.jpg)

# 摘要

在本章中，我们学到了关于 HTML5 游戏的基本信息。

具体来说，我们涵盖了：

+   来自 HTML5 和 CSS3 的新功能。我们已经初步了解了我们将在后续章节中使用的技术。Canvas、音频、CSS 动画等更多新功能被介绍了。我们将有许多新功能可以使用。

+   创建 HTML5 游戏的好处。我们讨论了为什么要创建 HTML5 游戏。我们想要满足网络标准，满足移动设备，并打破游戏的边界。

+   其他人正在玩的 HTML5 游戏。我们列出了使用我们将使用的不同技术创建的几款现有 HTML5 游戏。在创建我们自己的游戏之前，我们可以测试这些游戏。

+   我们还预览了本书中将要构建的游戏。

现在我们已经了解了一些关于 HTML5 游戏的背景信息，我们准备在下一章中创建我们的第一个基于 DOM 的 JavaScript 驱动游戏。


# 第二章：开始使用基于 DOM 的游戏开发

> 在第一章“介绍 HTML5 游戏”中，我们已经对整本书要学习的内容有了一个概念。从本章开始，我们将经历许多通过实践学习的部分，并且我们将在每个部分专注于一个主题。在深入研究尖端的 CSS3 动画和 HTML5 Canvas 游戏之前，让我们从传统的基于 DOM 的游戏开发开始。在本章中，我们将用一些基本技术热身。

在本章中，我们将：

+   准备开发工具

+   设置我们的第一个游戏-乒乓球

+   使用 jQuery JavaScript 库学习基本定位

+   获取键盘输入

+   使用记分的乒乓球游戏

以下屏幕截图显示了本章结束后我们将获得的游戏。这是一个由两名玩家同时使用一个键盘玩的乒乓球游戏：

![开始使用基于 DOM 的游戏开发](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_01.jpg)

所以，让我们开始制作我们的乒乓球。

# 准备开发环境

开发 HTML5 游戏的环境类似于设计网站。我们需要具有所需插件的 Web 浏览器和一个好的文本编辑器。哪个文本编辑器好是一个永无止境的争论。每个文本编辑器都有其自身的优势，所以只需选择您喜欢的即可。对于浏览器，我们将需要一个支持最新 HTML5、CSS3 规范并为我们提供方便的调试工具的现代浏览器。

现在互联网上有几种现代浏览器选择。它们是苹果 Safari（[`apple.com/safari/`](http://apple.com/safari/)）、Google Chrome（[`www.google.com/chrome/`](http://www.google.com/chrome/)）、Mozilla Firefox（[`mozilla.com/firefox/`](http://mozilla.com/firefox/)）和 Opera（[`opera.com`](http://opera.com)）。这些浏览器支持我们在整本书中讨论的大多数功能。我们将使用 Google Chrome 来演示本书中的大多数示例，因为它在 CSS3 过渡和 Canvas 上运行速度快且流畅。

# 为基于 DOM 的游戏准备 HTML 文档

每个网站、网页和 HTML5 游戏都以默认的 HTML 文档开始。此外，文档以基本的 HTML 代码开始。我们将从`index.html`开始我们的 HTML5 游戏开发之旅。

# 安装 jQuery 库的操作时间

我们将从头开始创建我们的 HTML5 乒乓球游戏。这可能听起来好像我们要自己准备所有的东西。幸运的是，至少我们可以使用一个 JavaScript 库来帮助我们。**jQuery**是我们将在整本书中使用的**JavaScript 库**。它将帮助我们简化我们的 JavaScript 逻辑：

1.  创建一个名为`pingpong`的新文件夹。

1.  在`pingpong`目录中创建一个名为`js`的新文件夹。

1.  现在是时候下载 jQuery 库了。转到[`jquery.com/`](http://jquery.com/)。

1.  选择**生产**并单击**下载 jQuery**。

1.  将`jquery-1.4.4.min.js`保存在我们在步骤 2 中创建的`js`文件夹中。

1.  创建一个名为`index.html`的新文档，并将其保存在第一个游戏文件夹中。

1.  在文本编辑器中打开`index.html`并插入一个空的 HTML 模板：

```js
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ping Pong</title>
</head>
<body>
<header>
<h1>Ping Pong</h1>
</header>
<footer>
This is an example of creating a Ping Pong Game.
</footer>
</body>
</html>

```

1.  通过在 body 标签关闭之前添加以下行来包含 jQuery JavaScript 文件：

```js
<script src="img/jquery-1.4.4.min.js"></script>

```

1.  最后，我们必须确保 jQuery 已成功加载。我们将在 body 标签关闭之前并在 jQuery 之后放置以下代码：

```js
<script>
$(function(){
alert("Welcome to the Ping Pong battle.");
});
</script>

```

1.  保存`index.html`并在浏览器中打开它。我们应该看到以下警报窗口显示我们的文本。这意味着我们的 jQuery 已正确设置：

![安装 jQuery 库的操作时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_02.jpg)

## 刚刚发生了什么？

我们刚刚创建了一个基本的带有 jQuery 的 HTML5 页面，并确保 jQuery 已正确加载。

## 新的 HTML5 doctype

在 HTML5 中，`DOCTYPE`和`meta`标签被简化了。

在 HTML4.01 中，我们声明 doctype 的代码如下：

```js
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">

```

这是一行很长的代码，对吧？在 HTML5 中，doctype 声明不能更简单：

```js
<!DOCTYPE html>

```

我们甚至没有在声明中使用 HTML 版本。这意味着 HTML5 将支持以前 HTML 版本的所有现有内容。未来的 HTML 版本也将支持 HTML5 的现有内容。

简化也适用于`meta`标签。现在我们可以使用以下简短的行来定义 HTML 的字符集：

```js
<meta charset=utf-8>

```

## 页眉和页脚

HTML5 带来了许多新功能和改进，其中之一就是语义。HTML5 添加了新元素来改进**语义**。我们刚刚使用了两个，`header`和`footer`。Header 为部分或整个页面提供了标题介绍。因此，我们将`h1`标题放在 header 内。Footer 与其名称相同，包含了部分或整个页面的页脚信息。

### 注意

语义 HTML 意味着标记本身提供了有意义的信息，而不仅仅定义了视觉外观。

## 放置 JavaScript 代码的最佳实践

我们将 JavaScript 代码放在所有页面内容之后和`</body>`标签之前。之所以将代码放在那里而不是放在`<head></head>`部分内，是有原因的。

通常，浏览器会从顶部到底部加载内容并呈现它们。如果将 JavaScript 代码放在`head`部分，那么直到所有 JavaScript 代码加载完毕，文档的内容才会被加载。实际上，如果浏览器在页面中间加载 JavaScript 代码，所有呈现和加载都将被阻塞。这就是为什么我们希望尽可能将 JavaScript 代码放在底部的原因。这样，我们可以以更高的性能提供内容。

在撰写本书时，最新的 jQuery 版本是 1.4.4。这就是为什么我们代码示例中的 jQuery 文件被命名为`jquery-1.4.4.min.js`。这个版本号会有所不同，但使用方式应该是相同的，除非 jQuery 发生了没有向后兼容的重大变化。

## 在页面准备就绪后运行我们的代码

我们需要确保页面在执行我们的 JavaScript 代码之前已经准备就绪。否则，当我们尝试访问尚未加载的元素时，可能会出现错误。jQuery 为我们提供了一种在页面准备就绪后执行代码的方法。以下是代码：

```js
jQuery(document).ready(function(){
// code here.
});

```

实际上，我们刚刚使用的是以下代码：

```js
$(function(){
// code here.
});

```

`$`符号是 jQuery 的快捷方式。当我们调用`$(something)`时，实际上是在调用`jQuery(something)`。

`$(function_callback)`是`ready`事件的另一个快捷方式。

这与以下内容相同：

```js
$(document).ready(function_callback);

```

同样，与以下内容相同：

```js
jQuery(document).ready(function_callback);

```

## 快速测验

1.  哪里是放置 JavaScript 代码的最佳位置？

a. 在`<head>`标签之前

b. 在`<head></head>`元素内

c. 在`<body>`标签之后

d. 在`</body>`标签之前

# 设置乒乓球游戏元素

我们已经准备好了准备工作，现在是设置乒乓球游戏的时候了。

# 行动时间 将乒乓球游戏元素放入 DOM

1.  我们将从 jQuery 安装示例继续。在文本编辑器中打开`index.html`。

1.  然后，在 body 中创建以下游乐场和 DIV 节点中的游戏对象。游乐场内有两个挡板和一个球。此外，游乐场位于游戏内：

```js
<div id="game">
<div id="playground">
<div id="paddleA" class="paddle"></div>
<div id="paddleB" class="paddle"></div>
<div id="ball"></div>
</div>
</div>

```

1.  我们现在已经准备好了游戏对象的结构，现在是给它们应用样式的时候了。将以下样式放在`head`元素内：

```js
<style>
#playground{
background: #e0ffe0;
width: 400px;
height: 200px;
position: relative;
overflow: hidden;
}
#ball {
background: #fbb;
position: absolute;
width: 20px;
height: 20px;
left: 150px;
top: 100px;
border-radius: 10px;
}
.paddle {
background: #bbf;
left: 50px;
top: 70px;
position: absolute;
width: 30px;
height: 70px;
}
#paddleB {
left: 320px;
}
</style>

```

1.  在最后一节中，我们将我们的 JavaScript 逻辑放在了 jQuery 包含之后。随着代码的不断增长，我们将把它放在一个单独的文件中。因此，在`js`文件夹中创建一个名为`html5games.pingpong.js`的文件。

1.  我们准备了 JavaScript 文件。现在是将它们链接到我们的 HTML 文件的时候了。在`index.html`中的`</body>`标签之前放入以下代码：

```js
<script src="img/jquery-1.4.4.js"></script>
<script src="img/html5games.pingpong.js"></script>

```

1.  我们将把游戏逻辑放在`html5games.pingpong.js`中。我们现在唯一的逻辑是以下挡板的初始化代码：

```js
// code inside $(function(){} will run after the DOM is loaded and ready
$(function(){
$("#paddleB").css("top", "20px");
$("#paddleA").css("top", "60px");
});

```

1.  我们将在浏览器中测试设置。在浏览器中打开`index.html`文件，我们应该看到与以下截图类似的屏幕：

![进行操作将乒乓球游戏元素放置在 DOM 中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_03.jpg)

## 刚刚发生了什么？

我们在乒乓球比赛中放了两个球拍和一个球。我们还使用 jQuery 来初始化两个球拍的位置。

## 介绍 jQuery

jQuery 是一个为了轻松浏览 DOM 元素、操作它们、处理事件和创建异步远程调用而设计的 JavaScript 库。

它包含两个主要部分：**选择**和**修改**。选择使用 CSS 选择器语法在网页中选择所有匹配的元素。修改操作修改所选元素，例如添加、删除子元素或样式。使用 jQuery 通常意味着将选择和修改操作链接在一起。

它包含两个主要部分：**选择**和**修改**。选择使用 CSS 选择器语法在网页中选择所有匹配的元素。修改操作修改所选元素，例如添加、删除子元素或样式。使用 jQuery 通常意味着将选择和修改操作链接在一起。

例如，以下代码选择所有具有`box`类的元素并设置 CSS 属性：

```js
$(".box").css({"top":"100px","left":"200px"});

```

## 理解基本的 jQuery 选择器

jQuery 是关于选择元素并对其执行操作。我们需要一种方法来在整个 DOM 树中选择我们需要的元素。jQuery 借用了 CSS 的选择器。选择器提供一组模式来匹配元素。以下表列出了我们在本书中将使用的最常见和有用的选择器：

| 选择器模式 | 含义 | 示例 |
| --- | --- | --- |
| $("Element") | 选择具有给定标签名称的所有元素 | `$("p")`选择所有的 p 标签。`$("body")`选择 body 标签。 |
| $("#id") | 选择具有给定属性 ID 的元素 | 提供以下代码：**<div id="box1"></div>**<div id="box2"></div>`$("#box1")`选择突出显示的元素。 |
| $(".className") | 选择具有给定类属性的所有元素 | 提供以下代码：**<div class="apple"></div>****<div class="apple"></div>**<div class="orange"></div><div class="banana"></div>`$(".apple")`选择具有设置为 apple 的类的突出显示的元素。 |
| $("selector1, selector2, selectorN") | 选择与给定选择器匹配的所有元素 | 提供以下代码：**<div class="apple"></div>****<div class="apple"></div>****<div class="orange"></div>**<div class="banana"></div>`$(".apple, .orange")`选择设置为 apple 或 orange 的突出显示的元素。 |

## 理解 jQuery CSS 函数

jQuery `css`是一个用于获取和设置所选元素的 CSS 属性的函数。

这是如何使用`css`函数的一般定义：

```js
.css(propertyName)
.css(propertyName, value)
.css(map)

```

`css`函数接受以下表中列出的几种类型的参数：

| 函数类型 | 参数定义 | 讨论 |
| --- | --- | --- |
| `.css(propertyName)` | `propertyName`是 CSS 属性 | 该函数返回所选元素的给定 CSS 属性的值。例如，以下代码返回`body`元素的`background-color`属性的值：`$("body").css("background-color")`它只会读取值，而不会修改属性值。 |
| `.css(propertyName, value)` | `propertyName`是 CSS 属性，`value`是要设置的值 | 该函数将给定的 CSS 属性修改为给定的值。例如，以下代码将所有具有`box`类的元素的背景颜色设置为红色：`$(".box").css("background-color","#ff0000")` |
| `.css(map)` | `map`是要更新的属性-值对集合 | 此函数用于同时将多个 CSS 属性设置为相同的选定元素。例如，以下代码将 ID 为`box1`的选定元素的左侧和顶部 CSS 属性都设置为：`$("#box1").css({"left" : "40px","top" : "100px"})` |

## 使用 jQuery 的好处

使用 jQuery 而不是纯 JavaScript 有几个优点，如下所示：

+   使用 jQuery 需要更短的代码来选择 DOM 节点并修改它们

+   更短的代码导致更清晰的代码阅读，这在通常包含大量代码的游戏开发中非常重要

+   编写更短的代码可以提高开发速度

+   使用 jQuery 库使得代码能够支持所有主要浏览器，无需额外的调整；jQuery 包装了纯 JavaScript 代码，并且自己处理跨浏览器的能力

## 使用 jQuery 在 DOM 中操作游戏元素

我们用 jQuery 初始化了球拍游戏元素。我们将进行一个实验，看看如何使用 jQuery 来放置游戏元素。

# 行动时间 使用 jQuery 改变元素的位置

让我们用网格背景检查一下我们的乒乓球游戏元素：

1.  我们将继续我们的乒乓球示例。

1.  我准备了一个网格图像。从以下 URL 下载`pixel_grid.jpg`图像：

[`gamedesign.cc/html5games/pixel_grid.jpg`](http://gamedesign.cc/html5games/pixel_grid.jpg )

1.  在示例目录中创建一个名为`images`的文件夹。

1.  将`pixel_grid.jpg`放入 images 文件夹中。这个图像可以帮助我们稍后检查像素位移。

1.  接下来，在文本编辑器中打开`index.html`文件。

1.  修改`playground` DIV 的`background`属性，包括像下面这样的像素网格图像：

```js
#playground{
background: #e0ffe0 url(images/pixel_grid.jpg);
width: 400px;
height: 200px;
position: relative;
overflow: hidden;
}

```

1.  现在在 web 浏览器中打开`index.html`，我们应该有以下的截图。游戏元素叠加在网格图像的顶部，所以我们可以看到元素的放置位置：

![行动时间 使用 jQuery 改变元素的位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_04.jpg)

## 刚刚发生了什么？

我们通过放置一个名为`pixel_grid.jpg`的图像来开始示例。这是我为了方便调试而创建的图像。图像被分成小网格。每个 10 x 10 的网格形成一个 100 x 100 像素的大块。通过将这个图像作为 DIV 的背景，我们放置了一个标尺，使我们能够测量其子 DIV 在屏幕上的位置。

## 理解绝对位置的行为

当一个 DOM 节点被设置为`absolute`位置时，left 和 top 属性可以被视为**坐标**。我们可以将 left/top 属性视为 X/Y 坐标，Y 正方向向下。以下图表显示了它们之间的关系。左侧是实际的 CSS 值，右侧是我们在编程游戏时的坐标系：

![理解绝对位置的行为](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_05.jpg)

默认情况下，left 和 top 属性是指网页的左上角。当这个 DOM 节点的任何父节点都显式设置了`position`样式时，这个参考点就会不同。left 和 top 属性的参考点变成了那个父节点的左上角。

这就是为什么我们需要将游乐场设置为相对位置，所有游戏元素都在绝对位置内。我们示例中的以下代码片段显示了它们的位置值：

```js
#playground{
position: relative;
}
#ball {
position: absolute;
}
.paddle {
position: absolute;
}

```

## 小测验

1.  使用哪个 jQuery 选择器，如果你想选择所有的标题元素？

a. $("#header")

b. $(".header")

c. $("header")

d. $(header)

# 从玩家那里获取键盘输入

这本书是关于游戏开发的。我们可以将游戏开发看作是以下循环：

1.  游戏状态被可视化显示。

1.  玩家输入他们的命令。

1.  游戏根据玩家的输入在设计好的游戏机制下运行。

1.  再次从步骤 1 开始循环该过程。

在之前的章节中，我们学会了如何用 CSS 和 jQuery 显示游戏对象。接下来我们需要在游戏中获取玩家的输入。在本章中我们将讨论键盘输入。

# 行动时间 通过键盘输入移动 DOM 对象

我们将创建一个传统的乒乓球游戏。左右两侧有两个球拍。球放在操场的中间。玩家可以通过使用*w*和*s*键来控制左球拍的上下移动，使用*箭头上*和*下*键来控制右球拍。我们将专注于键盘输入，将球的移动留到后面的部分：

1.  让我们继续进行`pingpong`目录。

1.  打开`html5games.pingpong.js`文件，其中包含我们的游戏逻辑。我们现在唯一的逻辑是监听按键按下事件并移动相应的球拍上下。用以下代码替换文件中的内容：

```js
var KEY = {
UP: 38,
DOWN: 40,
W: 87,
S: 83
}
$(function(){
// listen to the key down event
$(document).keydown(function(e){
switch(e.which){
case KEY.UP: // arrow-up
// get the current paddle B's top value in Int type
var top = parseInt($("#paddleB").css("top"));
// move the paddle B up 5 pixels
$("#paddleB").css("top",top-5);
break;
case KEY.DOWN: // arrow-down
var top = parseInt($("#paddleB").css("top"));
// move the paddle B down 5 pixels
$("#paddleB").css("top",top+5);
break;
case KEY.W: // w
var top = parseInt($("#paddleA").css("top"));
// move the paddle A up 5 pixels
$("#paddleA").css("top",top-5);
break;
case KEY.S: // s
var top = parseInt($("#paddleA").css("top"));
// move the paddle A drown 5 pixels
$("#paddleA").css("top",top+5);
break;
}
});
keyboard inputkeyboard inputDOM objects, moving});

```

1.  让我们测试游戏的球拍控制。在 Google Chrome 中打开`index.html`。尝试按下*w*键、*s*键和*箭头上*和*下*。两个球拍应该能够根据输入向上或向下移动，但现在它们不能同时移动。

![行动时间 通过键盘输入移动 DOM 对象](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_06.jpg)

## 刚刚发生了什么？

让我们看看我们刚刚使用的 HTML 代码。HTML 页面包含页眉、页脚信息和一个 ID 为`game`的 DIV。游戏节点包含一个名为 playground 的子节点。playground 包含三个子节点，两个球拍和一个球。

我们通常通过准备一个结构良好的 HTML 层次结构来开始 HTML5 游戏开发。HTML 层次结构帮助我们将类似的游戏对象（即一些 DIV）分组在一起。这有点像在 Adobe Flash 中将资产分组到电影剪辑中，如果你以前用过它制作动画的话。我们也可以将其视为游戏对象的图层，以便我们可以轻松地选择和样式化它们。

## 理解键码

键盘上的每个键都被分配一个数字。通过获取该数字，我们可以找出按下了哪个键。我们监听 jQuery 的`keydown`事件监听器。事件触发时，`event`对象包含**键码**。我们可以通过调用`which`函数来获取按下键的键码。

您可以尝试在`keydown`事件监听器中添加一个控制台日志函数，并观察每个键的表示整数：

```js
$(document).keydown(function(e){
console.log(e.which);
keyboard inputkeyboard inputkey code});

```

## 使常量更易读

在我们的例子中，我们使用键码来检查玩家是否按下我们感兴趣的键。以箭头上键为例。它的键码是 38。我们可以简单地将键码与数字直接进行比较，如下所示：

```js
$(document).keydown(function(e){
switch(e.which){
case 38:
// do something when pressed arrow-up
}
}

```

然而，这并不是一种推荐的做法，因为它使游戏代码更难以维护。想象一下，如果以后我们想要将动作从箭头上键映射到另一个键。我们可能不确定 38 是否表示箭头上。相反，我们可以使用以下代码为常量赋予一个有意义的名称：

```js
var KEY = {
UP: 38,
DOWN: 40,
W: 87,
S: 83
}
// listen to the key down event
$(document).keydown(function(e){
switch(e.which){
case KEY.UP:
// do something when pressed arrow-up
}
}

```

通过给 38 命名为`KEY.UP`，我们可以确保代码块与箭头上键相关联，因此在维护游戏时我们可以毫无疑问地进行修改。

## 使用 parseInt 函数将字符串转换为数字

在大多数情况下，我们通过使用格式如**100px**来将左侧和顶部的 CSS 样式应用于 DOM 元素。在设置属性时，我们指定单位。当获取属性的值时也是一样的。当我们调用`$("#paddleA").css("top")`时，我们得到的值是**100px**而不是**100**。这在我们想要对该值进行算术运算时会给我们带来问题。

在大多数情况下，我们通过使用格式如**100px**来将左侧和顶部的 CSS 样式应用于 DOM 元素。在设置属性时，我们指定单位。当获取属性的值时也是一样的。当我们调用`$("#paddleA").css("top")`时，我们得到的值是**100px**而不是**100**。这在我们想要对该值进行算术运算时会给我们带来问题。

在这个例子中，我们想通过将球拍的`top`属性设置为其当前位置减去五个像素来将球拍移动到上方。假设球拍 A 现在的`top`属性设置为 100px。如果我们使用以下表达式来添加五个像素，它会失败并返回`100px5`：

```js
$("#paddleA").css("top") + 5

```

这是因为 JavaScript 执行了`css`函数并得到了"100px"。然后它将"5"附加到"100px"字符串上。

在进行任何数学运算之前，我们需要一种方法来转换"100px"字符串。

JavaScript 为我们提供了`parseInt`函数。

这是如何使用`parseInt`函数的一般定义：

```js
parseInt(string, radix)

```

`parseInt`函数需要一个必需参数和一个可选参数：

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 字符串 | 要解析的字符串 | 该函数解析字符串的第一个数字。如果给定的字符串无法转换为数字，则返回`NaN`，即非数字。它将默认以十六进制解析以"0x"开头的字符串。以下代码是例子：`parseInt("100px")`返回 100。`parseInt("5cm")`返回 5。`parseInt("0xF")`返回 15。 |
| 基数 | 可选。用于指示要使用的数字系统的数字 | 第二个参数强制`parseInt`函数解析给定数字系统中的字符串。例如：`parseInt("0x10")`返回 16`parseInt("0x10",10)`返回 0`parseInt("FF",16)`返回 255 |

## 在控制台面板中直接执行 JavaScript 表达式

你还应该知道，你可以通过直接在控制台窗口中输入 JavaScript 表达式来执行 JavaScript 表达式。控制台窗口是 Google Chrome 开发者工具中的一个工具。(其他浏览器中也有类似的工具)。我们可以通过点击**扳手图标 | 工具 | 开发者工具 | 控制台**来打开控制台。

这是一个方便的方法，在开发过程中，当你不确定一个简单表达式是否有效时，可以快速测试一下。以下截图测试了两个`parseInt`表达式的返回值：

在控制台面板中直接执行 JavaScript 表达式

## 试试吧

有时将字符串转换为整数可能会很棘手。你知道*10 秒 20*的`parseInt`结果是什么吗？*10x10*和*$20.5*呢？

现在是时候打开控制台面板，尝试将一些字符串转换为数字。

## 检查控制台窗口

我们现在正在编写更复杂的逻辑代码。在开发者工具的控制台上保持警惕是一个好习惯。如果代码中包含任何错误或警告，错误消息将会出现在那里。它报告发现的任何错误以及包含错误的代码行。在测试 HTML5 游戏时，保持控制台窗口打开非常有用和重要。我曾经看到很多人因为代码不起作用而束手无策。原因是他们有拼写错误或语法错误，而他们在与代码搏斗数小时后才检查控制台窗口。

以下截图显示了`html5games.pingpong.js`文件的第 25 行存在错误。错误消息是**赋值中的无效左侧**。检查代码后，我发现我在设置 jQuery 中的 CSS `top`属性时错误地使用了等号(=)：

```js
$("#paddleA").css("top"=top+5);
// instead of the correct code:
// $("#paddleA").css("top", top+5);

```

![检查控制台窗口](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_08.jpg)

# 支持多个玩家的键盘输入

以前的输入方法只允许一次输入。键盘输入也不太顺畅。现在想象一下，两个玩家一起玩乒乓球游戏。他们无法很好地控制球拍，因为他们的输入会干扰对方。在本节中，我们将修改我们的代码，使其支持多个键盘输入。

# 行动时间 使用另一种方法监听键盘输入

我们将使用另一种方法来处理按键按下事件。这种方法会更加顺畅，并支持同时进行多个输入：

1.  打开我们在上一节中使用的`html5games.pingpong.js`。

1.  删除我们在那里编写的所有代码。从头开始会更简单。

1.  我们需要一个全局变量数组来存储按键的状态。在打开的 JavaScript 文件中输入以下代码：

```js
var pingpong = {}
pingpong.pressedKeys = [];

```

1.  接下来的事情是页面加载并准备就绪后执行代码。它将监听并标记按下的键。将以下代码放在我们刚刚编写的两行代码之后的 JavaScript 文件中：

```js
$(function(){
// set interval to call gameloop every 30 milliseconds
pingpong.timer = setInterval(gameloop,30);
// mark down what key is down and up into an array called "pressedKeys"
$(document).keydown(function(e){
pingpong.pressedKeys[e.which] = true;
});
$(document).keyup(function(e){
pingpong.pressedKeys[e.which] = false;
});
});

```

1.  我们已经存储了按下的键。我们缺少的是实际移动挡板。我们设置了一个定时器来连续调用一个移动挡板的函数。将以下代码粘贴到`html5games.pingpong.js`文件中：

```js
function gameloop() {
movePaddles();
}
function movePaddles() {
// use our custom timer to continuously check if a key is pressed.
if (pingpong.pressedKeys[KEY.UP]) { // arrow-up
// move the paddle B up 5 pixels
var top = parseInt($("#paddleB").css("top"));
$("#paddleB").css("top",top-5);
}
if (pingpong.pressedKeys[KEY.DOWN]) { // arrow-down
// move the paddle B down 5 pixels
var top = parseInt($("#paddleB").css("top"));
$("#paddleB").css("top",top+5);
}
if (pingpong.pressedKeys[KEY.W]) { // w
// move the paddle A up 5 pixels
var top = parseInt($("#paddleA").css("top"));
$("#paddleA").css("top",top-5);
}
if (pingpong.pressedKeys[KEY.S]) { // s
// move the paddle A down 5 pixels
var top = parseInt($("#paddleA").css("top"));
$("#paddleA").css("top",top+5);
}
}

```

1.  让我们测试一下我们刚刚编写的代码。保存所有文件，然后在 Web 浏览器中打开`index.html`。

1.  尝试按键控制两个挡板。两个挡板应该平稳移动，并且同时响应，没有中断。

## 刚刚发生了什么？

我们使用了另一种方法来捕获键盘输入。我们不是在检测到按键按下后立即执行动作，而是存储哪些键被按下，哪些没有。然后，我们使用 JavaScript 间隔每 30 毫秒检查按下的键。这种方法使我们能够同时知道当时按下的所有键，因此我们可以同时移动两个挡板。

## 更好地声明全局变量

**全局变量**是可以在整个文档中全局访问的变量。在任何函数外声明的变量都是全局变量。例如，在以下示例代码片段中，`a`和`b`是全局变量，而`c`是一个**局部变量**，只存在于函数内部：

```js
var a = 0;
var b = "xyz";
function something(){
var c = 1;
}

```

由于全局变量在整个文档中都可用，如果我们将不同的 JavaScript 库集成到网页中，可能会增加变量名冲突的可能性。作为良好的实践，我们应该将所有使用的全局变量放入一个对象中。

在*行动时间*部分，我们有一个全局数组来存储所有按下的键。我们不仅将这个数组放在全局范围内，而是创建了一个名为`pingpong`的全局对象，并将数组放在其中：

```js
var pingpong = {}
pingpong.pressedKeys = [];

```

将来，我们可能需要更多的全局变量，我们将把它们全部放在`pingpong`对象中。这样可以将名称冲突的机会减少到只有一个名称，`pingpong`。

## 使用 setInterval 函数创建 JavaScript 定时器

按下的键存储在数组中，我们有一个定时器定期循环和检查数组。这可以通过 JavaScript 中的`setInterval`函数来实现。

以下是`setInterval`函数的一般定义：

```js
setInterval(expression, milliseconds)

```

`setInterval`接受两个必需的参数：

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 表达式 | 要执行的函数回调或代码表达式 | 表达式可以是函数回调的引用或内联代码表达式。内联代码表达式需要引号，而函数回调的引用则不需要。例如，以下代码每 100 毫秒调用`hello`函数：setInterval(hello,100);以下代码每 100 毫秒调用带参数的`hi`函数：setInterval("hi('Makzan')",100); |
| 毫秒 | 表达式每次执行之间的持续时间，以毫秒为单位 | 时间间隔的单位是毫秒。因此，将其设置为 1000 意味着每秒运行一次表达式。 |

## 理解游戏循环

我们有一个定时器，每 30 毫秒执行一些与游戏相关的代码，因此这段代码每秒执行 33.3 次。在游戏开发中，这称为**游戏循环**。

在游戏循环中，我们将执行几个常见的事情：

+   处理用户输入，我们刚刚做了

+   更新游戏对象的状态，包括位置和外观

+   检查游戏结束

在游戏循环中实际执行的内容因不同类型的游戏而异，但目的是相同的。游戏循环定期执行，以帮助游戏平稳运行。

# 使用 JavaScript 间隔移动 DOM 对象

现在想象一下，我们可以使小红球在操场上移动。当它击中球拍时，球会弹开。当球通过球拍并击中球拍后面的操场边缘时，玩家将失去得分。所有这些操作都是通过 jQuery 在 HTML 页面中操纵 DIV 的位置。要完成这个乒乓球游戏，我们的下一步是移动球。

# 用 JavaScript 间隔移动球的时间

我们刚刚学习并使用了`setInterval`函数来创建一个定时器。我们将使用定时器每 30 毫秒移动球一点。当球击中操场边缘时，我们还将改变球运动的方向。现在让球动起来：

1.  我们将使用我们上一个示例，监听多个键盘输入，作为起点。

1.  在文本编辑器中打开`html5games.pingpong.js`文件。

1.  我们现在正在移动球，我们需要全局存储球的状态。我们将把与球相关的变量放在`pingpong`对象中：

```js
pingpong.ball = {
speed: 5,
x: 150,
y: 100,
directionX: 1,
directionY: 1
}

```

1.  在每个游戏循环中，我们都会移动球拍。现在我们也会移动球。在`gameloop`函数中添加一个`moveBall`函数调用：

```js
function gameloop() {
moveBall();
movePaddles();
}

```

1.  是时候定义`moveBall`函数了。该函数分为四个部分，它获取当前球的位置，检查操场的边界，在击中边界时改变球的方向，并在所有这些计算之后实际移动球。让我们把以下`moveBall`函数定义放在 JavaScript 文件中：

```js
function moveBall() {
// reference useful variables
var playgroundHeight = parseInt($("#playground").height());
var playgroundWidth = parseInt($("#playground").width());
var ball = pingpong.ball;
// check playground boundary
// check bottom edge
if (ball.y + ball.speed*ball.directionY > playgroundHeight)
{
ball.directionY = -1;
}
// check top edge
if (ball.y + ball.speed*ball.directionY < 0)
{
ball.directionY = 1;
}
// check right edge
if (ball.x + ball.speed*ball.directionX > playgroundWidth)
{
ball.directionX = -1;
}
// check left edge
if (ball.x + ball.speed*ball.directionX < 0)
{
ball.directionX = 1;
}
ball.x += ball.speed * ball.directionX;
ball.y += ball.speed * ball.directionY;
// check moving paddle here, later.
// actually move the ball with speed and direction
$("#ball").css({
"left" : ball.x,
"top" : ball.y
});
}

```

1.  我们已经准备好了每 30 毫秒移动一次球的代码。保存所有文件并在 Google Chrome 中打开`index.html`进行测试。

1.  球拍的工作方式与上一个示例中的相同，球应该在操场上移动。

## 刚刚发生了什么？

我们刚刚成功地使球在操场上移动。我们有一个循环，每 30 毫秒运行一次常规游戏逻辑。在游戏循环中，我们每次移动球五个像素。

球的三个属性是速度和方向 X/Y。速度定义了球在每一步中移动多少像素。方向 X/Y 要么是 1，要么是-1。我们用以下方程移动球：

```js
new_ball_x = ball_x_position + speed * direction_x
new_ball_y = ball_y_position + speed * direction_y

```

方向值乘以移动。当方向为 1 时，球向轴的正方向移动。当方向为-1 时，球向负方向移动。通过切换 X 和 Y 方向，我们可以使球在四个方向上移动。

我们将球的 X 和 Y 与操场 DIV 元素的四个边缘进行比较。这将检查球的下一个位置是否超出边界，然后我们在 1 和-1 之间切换方向以创建弹跳效果。

# 开始碰撞检测

在上一节中移动球时，我们已经检查了操场的边界。现在我们可以用键盘控制球拍并观察球在操场上移动。现在还缺少什么？我们无法与球互动。我们可以控制球拍，但球却像它们不存在一样穿过它们。这是因为我们错过了球拍和移动球之间的碰撞检测。

# 与球拍击球的时间

我们将使用类似的方法来检查碰撞的边界：

1.  打开我们在上一节中使用的`html5games.pingpong.js`文件。

1.  在`moveball`函数中，我们已经预留了放置碰撞检测代码的位置。找到带有`// check moving paddle here`的行。

1.  让我们把以下代码放在那里。该代码检查球是否与任一球拍重叠，并在它们重叠时将球弹开：

```js
// check left paddle
var paddleAX = parseInt($("#paddleA").css("left"))+parseInt($("#paddleA").css("width"));
var paddleAYBottom = parseInt($("#paddleA").css("top"))+parseInt($("#paddleA").css("height"));
var paddleAYTop = parseInt($("#paddleA").css("top"));
if (ball.x + ball.speed*ball.directionX < paddleAX)
{
if (ball.y + ball.speed*ball.directionY <= paddleAYBottom &&
ball.y + ball.speed*ball.directionY >= paddleAYTop)
{
ball.directionX = 1;
}
}
// check right paddle
var paddleBX = parseInt($("#paddleB").css("left"));
var paddleBYBottom = parseInt($("#paddleB").css("top"))+parseInt($("#paddleB").css("height"));
var paddleBYTop = parseInt($("#paddleB").css("top"));
if (ball.x + ball.speed*ball.directionX >= paddleBX)
{
if (ball.y + ball.speed*ball.directionY <= paddleBYBottom &&
ball.y + ball.speed*ball.directionY >= paddleBYTop)
{
ball.directionX = -1;
}
}

```

1.  当球击中操场的左侧或右侧边缘后，我们还需要将球重置在中间区域。删除`check right`和`check left`代码部分中的弹球代码，并粘贴以下代码：

```js
// check right edge
if (ball.x +ball.speed*ball.directionX > playgroundWidth)
{
// player B lost.
// reset the ball;
ball.x = 250;
ball.y = 100;
$("#ball").css({
"left": ball.x,
"top" : ball.y
});
ball.directionX = -1;
}
// check left edge
if (ball.x + ball.speed*ball.directionX < 0)
{
// player A lost.
// reset the ball;
ball.x = 150;
ball.y = 100;
$("#ball").css({
"left": ball.x,
"top" : ball.y
});
ball.directionX = 1;
}

```

1.  在浏览器中测试游戏，现在球在击中左右球拍后会弹开。当击中左右边缘时，它也会重置到操场的中心。

![进行操作，用球拍击球](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_09.jpg)

## 刚刚发生了什么？

我们已经修改了球的检查，使其在与球拍重叠时弹开。此外，当击中左右边缘时，我们将球重新定位到操场的中心。

让我们看看如何检查球和左球拍之间的碰撞。

首先，我们检查球的 X 位置是否小于左球拍的右边缘。右边缘是`left`值加上球拍的`width`。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_10.jpg)

然后，我们检查球的 Y 位置是否在球拍的顶部边缘和底部边缘之间。顶部边缘是`top`值，底部边缘是`top`值加上球拍的`height`。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_11.jpg)

如果球的位置通过了两个检查，我们就会将球弹开。这就是我们检查它的方式，这只是一个基本的碰撞检测。

我们通过检查它们的位置和宽度/高度来确定这两个对象是否重叠。这种类型的碰撞检测对于矩形对象效果很好，但对于圆形和其他形状则不太好。以下截图说明了问题。以下图中显示的碰撞区域是误报。它们的边界框碰撞了，但实际形状并没有重叠。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_12.jpg)

对于特殊形状，我们将需要更高级的碰撞检测技术，我们将在后面讨论。

## 试试吧

我们检查球拍的三个边缘，以确定球是否与它们重叠。如果你玩游戏并仔细观察球的弹跳，你会发现现在它并不完美。球可能会在球拍后面弹跳。思考原因，并修改代码以实现更好的球和球拍的碰撞检测。

# 在 HTML 中动态显示文本

我们在前面的部分实现了基本的游戏机制。我们的乒乓球游戏现在缺少一个计分板，可以显示两名玩家的得分。我们讨论了如何使用 jQuery 来修改所选元素的 CSS 样式。我们是否也可以用 jQuery 来改变所选元素的内容？是的，我们可以。

# 进行操作，显示两名玩家的得分

我们将创建一个基于文本的计分板，并在任一玩家得分时更新得分：

1.  我们正在改进我们现有的游戏，所以我们将上一个示例作为起点。

1.  在文本编辑器中打开`index.html`。我们将添加计分板的 DOM 元素。

1.  在`index.html`的`game` DIV 内部之前添加以下 HTML 代码：

```js
<div id="scoreboard">
<div class="score">Player A : <span id="scoreA">0</span></div>
<div class="score">Player B : <span id="scoreB">0</span></div>
</div>

```

1.  让我们转到 JavaScript 部分。打开`html5games.pingpong.js`文件。

1.  我们需要两个全局变量来存储玩家的得分。在`pingpong`全局对象内添加他们的得分变量：

```js
var pingpong = {
scoreA : 0, // score for player A
scoreB : 0 // score for player B
}

```

1.  我们有一个地方来检查玩家 B 是否输掉了比赛。我们在那里增加了玩家 A 的得分，并用以下代码更新了计分板：

```js
// player B lost.
pingpong.scoreA++;
$("#scoreA").html(pingpong.scoreA);

```

1.  我们在第 6 步中有类似的代码，用于在玩家 A 输掉比赛时更新玩家 B 的得分：

```js
// player A lost.
pingpong.scoreB++;
$("#scoreB").html(pingpong.scoreB);

```

1.  现在是测试我们最新代码的时候了。在 Web 浏览器中打开`index.html`。尝试通过控制两个球拍来玩游戏，并失去一些分数。计分板应该正确计分：

![进行操作，显示两名玩家的得分](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_02_13.jpg)

## 刚刚发生了什么？

我们刚刚使用了另一个常见的 jQuery 函数：`html()`来动态改变游戏内容。

`html()`函数获取或更新所选元素的 HTML 内容。以下是`html()`函数的一般定义：

```js
.html()
.html(htmlString)

```

当我们使用`html()`函数时，如果没有参数，它会返回第一个匹配元素的 HTML 内容。如果带有参数使用，它会将 HTML 内容设置为所有匹配元素的给定 HTML 字符串。

例如，提供以下 HTML 结构：

```js
<p>My name is <span id="myname" class="name">Makzan</span>.</p>
<p>My pet's name is <span id="pet" class="name">

```

以下两个 jQuery 调用都返回 Makzan：

```js
$("#myname").html(); // returns Makzan
$(".name").html(); // returns Makzan

```

然而，在下面的 jQuery 调用中，它将所有匹配的元素设置为给定的 HTML 内容：

```js
$(".name").html("<small>Mr. Mystery</small>")

```

执行 jQuery 命令会产生以下 HTML 结果：

```js
<p>My name is <span id="myname" class="name"><small>Mr. Mystery</small></span></p>
<p>My pet's name is <span id="pet" class="name"><small>Mr. Mystery</small></span></p>

```

## 英雄尝试赢得比赛

我们现在有了得分。看看你是否可以修改游戏，使其在任何玩家得到 10 分后停止。然后显示一个获胜消息。

您可能还想尝试对游戏进行样式设置，使其更具吸引力。给记分牌和游乐场添加一些图像背景怎么样？用两个守门员角色替换球拍？

# 摘要

在本章中，我们学到了许多关于使用 HTML5 和 JavaScript 创建简单乒乓球游戏的基本技术。

具体来说，我们涵盖了：

+   创建我们的第一个 HTML5 游戏——乒乓球

+   使用 jQuery 操作 DOM 对象

+   获取支持多个按键按下的键盘输入

+   检测与边界框的碰撞

我们还讨论了如何创建游戏循环并移动球和球拍。

现在我们已经通过创建一个简单的基于 DOM 的游戏来热身，我们准备使用 CSS3 的新功能创建更高级的基于 DOM 的游戏。在下一章中，我们将创建具有 CSS3 动画、过渡和变换的游戏。


# 第三章：在 CSS3 中构建记忆匹配游戏

> CSS3 引入了许多令人兴奋的功能。在本章中，我们将探索并使用其中一些功能来创建匹配记忆游戏。CSS3 样式显示游戏对象的外观和动画，而 jQuery 库帮助我们定义游戏逻辑。

在本章中，我们将：

+   使用动画转换扑克牌

+   使用新的 CSS3 属性翻转扑克牌

+   创建整个记忆匹配游戏

+   并将自定义网络字体嵌入我们的游戏

所以让我们继续吧。

# 使用 CSS3 过渡移动游戏对象

在*第一章，介绍 HTML5 游戏*中，我们曾经在概述新的 CSS3 功能时，简要了解了 CSS3 过渡模块和变换模块。我们经常希望通过缓和属性来使游戏对象动画化。过渡是为此目的设计的 CSS 属性。想象一下，我们在网页上有一张扑克牌，想要在五秒内将其移动到另一个位置。我们必须使用 JavaScript，设置计时器，并编写自己的函数来每隔几毫秒更改位置。通过使用`transition`属性，我们只需要指定起始和结束样式以及持续时间。浏览器会自动进行缓和和中间动画。

让我们看一些例子来理解它。

# 移动扑克牌的时间

在这个例子中，我们将在网页上放置两张扑克牌，并将它们转换到不同的位置、比例和旋转。我们将通过设置过渡来缓和变换：

1.  在以下层次结构中创建一个新文件夹，其中包含三个文件。现在，`css3transition.css`和`index.html`为空，我们将稍后添加代码。`jquery-1.6.min.js`是我们在上一章中使用的 jQuery 库。![移动扑克牌的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_01.jpg)

1.  在这个例子中，我们使用了两张扑克牌图像。这些图像可以在代码包中找到，或者您可以从[`gamedesign.cc/html5games/css3-basic-transition/images/AK.png`](http://gamedesign.cc/html5games/css3-basic-transition/images/AK.png)和[`gamedesign.cc/html5games/css3-basic-transition/images/AQ.png`](http://gamedesign.cc/html5games/css3-basic-transition/images/AQ.png)下载。

1.  创建一个名为`images`的新文件夹，并将两张卡片图像放在其中。

1.  接下来要做的是编写 HTML，其中包含两个卡片 DIV 元素。当页面加载时，我们将为这两个卡片元素应用 CSS 过渡样式：

```js
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Getting Familiar with CSS3 Transition</title>
<link rel="stylesheet" href="css/css3transition.css" />
</head>
<body>
<header>
<h1>Getting Familiar with CSS3 Transition</h1>
</header>
<section id="game">
<div id="cards">
<div id="card1" class="card cardAK"></div>
<div id="card2" class="card cardAQ"></div>
</div> <!-- #cards -->
</section> <!-- #game -->
<footer>
<p>This is an example of transitioning cards.</p>
</footer>
<script src="img/jquery-1.6.min.js"></script>
<script>
$(function(){
$("#card1").addClass("moveAndScale");
$("#card2").addClass("rotateRight");
});
</script>
CSS3 transition moduleCSS3 transition moduleplaying card, moving</body>
</html>

```

1.  是时候通过 CSS 定义扑克牌的视觉样式了。它包含基本的 CSS 2.1 属性和 CSS3 新属性。新的 CSS3 属性已经突出显示：

```js
body {
background: #aaa;
}
/* defines styles for each card */
.card {
width: 80px;
height: 120px;
margin: 20px;
background: #efefef;
position: absolute;
-webkit-transition: all 1s linear;
}
/* set the card to corresponding playing card graphics */
.cardAK {
background: url(../images/AK.png);
}
.cardAQ {
background: url(../images/AQ.png);
}
/* rotate the applied DOM element 90 degree */
.rotateRight {
-webkit-transform: rotate3d(0,0,1,90deg);
}
/* move and scale up the applied DOM element */
.moveAndScale {
-webkit-transform: translate3d(150px,150px,0) scale3d(1.5, 1.5, 1);
}

```

1.  让我们保存所有文件，并在浏览器中打开`index.html`。两张卡应该如下截图所示进行动画：

![移动扑克牌的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_02.jpg)

## 发生了什么？

我们刚刚通过使用 CSS3 过渡来创建了两个动画效果，以调整`transform`属性。

### 注意

请注意，新的 CSS3 过渡和变换属性尚未最终确定。Web 浏览器支持这些起草但稳定的属性，并带有供应商前缀。在我们的示例中，为了支持 Chrome 和 Safari，我们使用了`-webkit-`前缀。我们可以在代码中使用其他前缀来支持其他浏览器，例如为 Mozilla 使用`-moz-`，为 Opera 使用`-o-`。

这是 CSS 变换的用法：

```js
transform: transform-function1 transform-function2;

```

`transform`属性的参数是函数。有两组函数，2D`transform`函数和 3D。**CSS transform**函数旨在移动、缩放、旋转和扭曲目标 DOM 元素。以下显示了变换函数的用法。

### 2D 变换函数

2D`rotate`函数按给定的正参数顺时针旋转元素，并按给定的负参数逆时针旋转：

```js
rotate(angle)

```

translate 函数通过给定的 X 和 Y 位移移动元素：

```js
translate (tx, ty)

```

我们可以通过调用`translateX`和`translateY`函数来独立地沿 X 或 Y 轴进行平移，如下所示：

```js
translateX(number)
translateY(number)

```

`scale`函数按给定的`sx，sy`向量缩放元素。如果我们只传递第一个参数，那么`sy`将与`sx`的值相同：

```js
scale(sx, sy)

```

此外，我们可以独立地按如下方式缩放 X 和 Y 轴：

```js
scaleX(number)
scaleY(number)

```

### 3D 变换函数

3D 旋转功能通过给定的[x，y，z]单位向量在 3D 空间中旋转元素。例如，我们可以使用`rotate3d(0, 1, 0, 60deg)`将 Y 轴旋转 60 度：

```js
rotate3d(x, y, z, angle)

```

我们还可以通过调用以下方便的函数仅旋转一个轴：

```js
rotateX(angle)
rotateY(angle)
rotateZ(angle)

```

与 2D `translate`函数类似，`translate3d`允许我们在所有三个轴上移动元素：

```js
translate3d(tx, ty, tz)
translateX(tx)
translateY(ty)
translateZ(tz)

```

此外，`scale3d`在 3D 空间中缩放元素：

```js
scale3d(sx, sy, sz)
scaleX(sx)
scaleY(sy)
scaleZ(sz)

```

我们刚讨论的`transform`函数是常见的，我们会多次使用它们。还有一些其他未讨论的`transform`函数。它们是`matrix，skew`和`perspective`。

如果您想找到最新的 CSS 变换工作规范，可以访问 W3C 网站，网址如下。CSS 2D 变换模块（[`dev.w3.org/csswg/css3-3d-transforms/`](http://dev.w3.org/csswg/css3-3d-transforms/)）和 3D 变换模块（[`www.w3.org/TR/css3-2d-transforms/`](http://www.w3.org/TR/css3-2d-transforms/)）。

## 通过使用 CSS3 过渡来缓慢改变样式

CSS3 中有大量新功能。过渡模块是其中之一，对我们在游戏设计中影响最大。

什么是**CSS3 过渡**？W3C 用一句话解释了它：

> CSS 过渡允许 CSS 值中的属性更改在指定的持续时间内平滑发生。

通常，当我们改变元素的任何属性时，属性会立即更新为新值。过渡会减慢更改过程。它在给定的持续时间内创建从旧值到新值的平滑过渡。

这是`transition`属性的用法：

```js
transition: property_name duration timing_function delay.

```

| 参数 | 定义 |
| --- | --- |
| `property_name` | 过渡应用的属性名称。可以设置为`all`。 |
| `Duration` | 过渡所需的持续时间。 |
| `Timing_function` | `timing`函数定义了开始值和结束值之间的插值。默认值是`ease`。通常我们会使用`ease, ease-in, ease-out`和`linear`。 |
| `Delay` | 延迟参数延迟了给定秒数的过渡开始。 |

我们可以在一行中放置几个`transition`属性。例如，以下代码在 0.3 秒内过渡不透明度，0.5 秒内过渡背景颜色：

```js
transition: opacity 0.3s, background-color 0.5s

```

我们还可以使用以下属性单独定义每个过渡属性：

`transition-property，transition-duration，transition-timing-function`和`transition-delay`。

### 提示

**CSS3 模块**

根据 W3C，CSS3 不同于 CSS 2.1，因为 CSS 2.1 只有一个规范。CSS3 分为不同的模块。每个模块都会单独进行审查。例如，有过渡模块，2D/3D 变换模块和弹性盒布局模块。

将规范分成模块的原因是因为 CSS3 的每个部分的工作进度不同。一些 CSS3 功能相当稳定，例如边框半径，而有些尚未定型。通过将整个规范分成不同的部分，它允许浏览器供应商支持稳定的模块。在这种情况下，缓慢的功能不会减慢整个规范。CSS3 规范的目标是标准化网页设计中最常见的视觉用法，而这个模块符合这个目标。

## 试试看

我们已经翻译，缩放和旋转了扑克牌。在示例中尝试更改不同的值怎么样？`rotate3d`函数中有三个轴。如果我们旋转其他轴会发生什么？通过自己尝试代码来熟悉变换和过渡模块。

# 创建翻转卡片效果

现在想象一下，我们不仅仅是移动纸牌，而且还想翻转卡片元素，就像我们翻转真正的纸牌一样。通过使用`rotation transform`函数，现在可以创建翻牌效果。

# 使用 CSS3 翻牌的时间

当我们点击纸牌时，我们将开始一个新项目并创建一个翻牌效果：

1.  让我们继续我们之前的代码示例。

1.  卡片现在包含两个面，一个正面和一个背面。将以下代码替换为 HTML 中的`body`标签：

```js
<section id="game">
<div id="cards">
<div class="card">
<div class="face front"></div>
<div class="face back cardAK"></div>
</div> <!-- .card -->
<div class="card">
<div class="face front"></div>
<div class="face back cardAQ"></div>
</div> <!-- .card -->
</div> <!-- #cards -->
</section> <!-- #game -->
<script src="img/jquery-1.6.min.js"></script>

```

1.  然后将 CSS 外部链接更改为`css3flip.css`文件：

```js
<link rel="stylesheet" href="css/css3flip.css" />

```

1.  现在让我们将样式添加到`css3flip.css`中：

```js
#game {
background: #9c9;
padding: 5px;
}
/* Define the 3D perspective view and dimension of each card. */
.card {
-webkit-perspective: 600;
width: 80px;
height: 120px;
}

```

1.  每张卡上有两个面。我们将晚些时候旋转面。因此，我们通过 CSS3 的`transition`属性定义了面的过渡方式。我们还隐藏了背面的可见性。我们稍后会详细看一下这个属性：

```js
.face {
border-radius: 10px;
width: 100%;
height: 100%;
position: absolute;
-webkit-transition: all .3s;
-webkit-backface-visibility: hidden;
}

```

1.  现在是为每个单独的面样式。正面的 z-index 比背面高：

```js
.front {
background: #966;
z-index: 10;
}
.back {
background: #eaa;
-webkit-transform: rotate3d(0,1,0,-180deg);
z-index: 8;
}

```

1.  当我们翻转卡片时，我们将正面旋转到背面，背面旋转到正面。我们还交换了正面和背面的 z-index：

```js
.card-flipped .front {
-webkit-transform: rotate3d(0,1,0,180deg);
z-index: 8;
}
.card-flipped .back {
-webkit-transform: rotate3d(0,1,0,0deg);
z-index: 10;
}
.cardAK {
background: url(../images/AK.png);
}
.cardAQ {
background: url(../images/AQ.png);
}

```

1.  接下来，我们将在加载 jQuery 库后添加逻辑，以在单击卡片时切换卡片翻转状态：

```js
<script>
$(function(){
$("#cards").children().each(function(index) {
// listen the click event on each card DIV element.
$(this).click(function() {
// add the class "card-flipped".
// the browser will animate the styles between current state and card-flipped state.
$(this).toggleClass("card-flipped");
});
});
});
</script>

```

1.  现在样式和脚本都准备好了。让我们保存所有文件并在 Web 浏览器中预览。单击纸牌翻转它，再次单击翻转回来。

![使用 CSS3 翻牌的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_03.jpg)

## 刚才发生了什么？

我们已经创建了一个通过鼠标单击切换的翻牌效果。该示例利用了几个 CSS 变换属性和 JavaScript 来处理鼠标单击事件。

## 使用 jQuery toggleClass 函数切换类

当鼠标单击卡片时，我们将`card-flipped`类应用于卡片元素。第二次单击时，我们希望删除已应用的`card-flipped`样式，以便卡片再次翻转。这称为**切换类**样式。

jQuery 为我们提供了一个方便的函数，名为`toggleClass`，可以根据类是否应用来自动添加或删除类。

要使用该函数，我们只需将要切换的类作为参数传递。

例如，以下代码向具有 ID`card1`的元素添加或删除`card-flipped`类：

```js
$("#card1").toggleClass("card-flipped");

```

`toggleClass`函数接受一次切换多个类。我们可以传递多个类名，并用空格分隔它们。以下是同时切换两个类的示例：

```js
$("#card1").toggleClass("card-flipped scale-up");

```

## 通过 z-index 控制重叠元素的可见性

通常，网页中的所有元素都是分布和呈现而不重叠的。设计游戏是另一回事。我们总是需要处理重叠的元素并有意隐藏它们（或其中的一部分）。`Z-index`是 CSS 2.1 属性，帮助我们控制多个重叠元素时的可见性行为。

在这个例子中，每张卡片有两个面，正面和背面。两个面放在完全相同的位置。它们彼此重叠。**Z-index**属性定义了哪个元素在顶部，哪个在后面。具有较高 z-index 的元素在较低 z-index 的元素前面。当它们重叠时，具有较高 z-index 的元素将覆盖具有较低 z-index 的元素。以下截图演示了 z-index 的行为：

![通过 z-index 控制重叠元素的可见性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_04.jpg)

在翻牌示例中，我们交换了两个面的 z-index，以确保对应的面在正常状态和翻转状态下都在另一个面的上方。以下代码显示了交换。

在正常状态下，正面的 z-index 较高：

```js
.front {
z-index: 10;
}
.back {
z-index: 8;
}

```

在翻转状态下，正面的 z-index 变为低于背面的 z-index。现在背面覆盖了正面：

```js
.card-flipped .front {
z-index: 8;
}
.card-flipped .back {
z-index: 10;
}

```

## 介绍 CSS 透视属性

CSS3 让我们能够以 3D 形式呈现元素。我们已经能够在 3D 空间中转换元素。`perspective`属性定义了 3D 透视视图的外观。您可以将值视为您观察对象的距离。您越近，观察对象的透视失真就越大。

### 注意

在撰写本书时，只有 Safari 支持 3D 透视功能。Chrome 支持 3D 变换，但不支持`perspective`属性。因此，在 Safari 中效果最佳，在 Chrome 中效果也可以接受。

以下两个 3D 立方体演示了不同的透视值如何改变元素的透视视图：

![介绍 CSS 透视属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_05.jpg)

您可以在 Safari 中输入以下地址查看此实验：

[`gamedesign.cc/html5games/perspective-cube/`](http://gamedesign.cc/html5games/perspective-cube/)

## Have a go hero

立方体是通过将六个面放在一起，并对每个面应用 3D 变换来创建的。它使用了我们讨论过的技术。尝试创建一个立方体并尝试使用`perspective`属性进行实验。

以下网页对创建 CSS3 立方体进行了全面的解释，并讨论了通过键盘控制立方体的旋转：

[`www.paulrhayes.com/2009-07/animated-css3-cube-interface-using-3d-transforms/`](http://www.paulrhayes.com/2009-07/animated-css3-cube-interface-using-3d-transforms/)

## 介绍 backface-visibility

在引入`backface-visibility`之前，页面上的所有元素都向访问者展示它们的正面。实际上，元素的正面或背面没有概念，因为这是唯一的选择。而 CSS3 引入了三个轴的旋转，我们可以旋转一个元素，使其正面朝后。试着看看你的手掌并旋转你的手腕，你的手掌转过来，你看到了手掌的背面。这也发生在旋转的元素上。

CSS3 引入了一个名为`backface-visibility`的属性，用于定义我们是否可以看到元素的背面。默认情况下，它是可见的。以下截图演示了`backface-visibility`属性的两种不同行为。

### 注意

在撰写本书时，只有 Apple Safari 支持`backface-visibility`属性。

![介绍 backface-visibility](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_06.jpg)

### 注意

您可以在官方 Webkit 博客上阅读有关 CSS 3D 变换中不同属性和函数的更详细信息：[`webkit.org/blog/386/3d-transforms/`](http://webkit.org/blog/386/3d-transforms/)。

# 创建一款卡片匹配记忆游戏

我们已经学习了一些 CSS 基本技术。让我们用这些技术制作一个游戏。我们将制作一款纸牌游戏。纸牌游戏利用变换来翻转纸牌，过渡来移动纸牌，JavaScript 来控制逻辑，以及一个名为自定义数据属性的新 HTML5 功能。别担心，我们将逐步讨论每个组件。

## 下载扑克牌的精灵表

在翻牌示例中，我们使用了两种不同的扑克牌图形。现在我们准备整副扑克牌的图形。尽管我们在匹配游戏中只使用了六张扑克牌，但我们准备整副扑克牌，这样我们可以在可能创建的其他扑克牌游戏中重复使用这些图形。

一副牌有 52 张，我们还有一张背面的图形。与使用 53 个单独的文件不同，将单独的图形放入一个大的精灵表文件是一个好的做法。精灵表这个术语来自于一种旧的计算机图形技术，它将一个图形纹理加载到内存中并显示部分图形。

使用大型精灵表而不是分离的图像文件的一个好处是可以减少**HTTP 请求的数量**。 当浏览器加载网页时，它会创建一个新的 HTTP 请求来加载每个外部资源，包括 JavaScript 文件，CSS 文件和图像。 为每个分离的小文件建立新的 HTTP 请求需要相当长的时间。 将图形合并到一个文件中，大大减少了请求的数量，从而提高了在浏览器中加载时游戏的响应性。

将图形放入一个文件的另一个好处是避免文件格式头的开销。 53 张图像精灵表的大小小于每个文件中带有文件头的 53 张不同图像的总和。

以下扑克牌图形是在 Adobe Illustrator 中绘制和对齐的。 您可以从[`gamedesign.cc/html5games/css3-matching-game/images/deck.png`](http://gamedesign.cc/html5games/css3-matching-game/images/deck.png)下载它。

### 注意

以下文章详细解释了为什么以及如何创建和使用 CSS 精灵表：

[`css-tricks.com/css-sprites/`](http://css-tricks.com/css-sprites/)

![下载扑克牌精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_07.jpg)

## 设置游戏环境

图形已准备就绪，然后我们需要在游戏区域上设置一个静态页面，并在游戏区域上准备和放置游戏对象。 这样以后添加游戏逻辑和交互会更容易：

# 执行动作准备卡片匹配游戏的时间

在将复杂的游戏逻辑添加到我们的匹配游戏之前，让我们准备 HTML 游戏结构并准备所有 CSS 样式：

1.  让我们继续我们的代码。 用以下 HTML 替换`index.html`文件：

```js
<!DOCTYPE html>
<html lang=en>
<head>
<meta charset=utf-8>
<title>CSS3 Matching Game</title>
<link rel="stylesheet" href="css/matchgame.css" />
</head>
<body>
<header>
<h1>CSS3 Matching Game</h1>
</header>
<section id="game">
<div id="cards">
<div class="card">
<div class="face front"></div>
<div class="face back"></div>
</div> <!-- .card -->
</div> <!-- #cards -->
</section> <!-- #game -->
<footer>
<p>This is an example of creating a matching game with CSS3.</p>
</footer>
<script src="img/jquery-1.6.min.js"></script>
<script src="img/html5games.matchgame.js"></script>
</body>
</html>

```

1.  为了使游戏更具吸引力，我为游戏桌和页面准备了背景图像。 这些图形资产可以在代码示例包中找到。 背景图像是可选的，它们不会影响匹配游戏的游戏过程和逻辑。

1.  我们还将把扑克牌精灵表图形放入 images 文件夹中。 从[`gamedesign.cc/html5games/css3-matching-game/images/deck.png`](http://gamedesign.cc/html5games/css3-matching-game/images/deck.png)下载`deck.png`文件，并将其保存到 images 文件夹中。

1.  在编写任何逻辑之前，让我们为匹配游戏添加样式。 打开`matchgame.css`并添加以下 body 样式：

```js
body {
text-align: center;
background: #a46740 url(../images/bg.jpg);
}

```

1.  继续向`game`元素添加样式。 它将是游戏的主要区域：

```js
#game {
border-radius: 10px;
border: 1px solid #666;
background: #232 url(../images/table.jpg);
width: 500px;
height: 460px;
margin: 0 auto;
display: box;
box-pack: center;
box-align: center;
}

```

1.  我们将所有卡片元素放入名为`cards`的父 DOM 中。 这样做可以轻松地将所有卡片居中到游戏区域：

```js
#cards {
position: relative;
width: 380px;
height: 400px;
}

```

1.  对于每张卡，我们定义了一个`perspective`属性，以赋予它视觉深度效果：

```js
.card {
-webkit-perspective: 600;
width: 80px;
height: 120px;
position: absolute;
-moz-transition: all .3s;
-webkit-transition: all .3s;
transition: all .3s;
}

```

1.  每张卡上有两个面。 面将稍后旋转，我们将定义过渡属性以动画显示样式更改。 我们还希望确保背面是隐藏的：

```js
.face {
border-radius: 10px;
width: 100%;
height: 100%;
position: absolute;
-webkit-transition-property: opacity, transform, box-shadow;
-webkit-transition-duration: .3s;
-webkit-backface-visibility: hidden;
}

```

1.  然后我们设置正面和背面样式。 它们与翻转卡片示例几乎相同，只是现在我们为它们提供了背景图像和盒子阴影：

```js
.front {
background: #999 url(../images/deck.png) 0 -480px;
z-index: 10;
card matching memory gamecard matching memory gamegame environment, setting up}
.back {
background: #efefef url(../images/deck.png);
-webkit-transform: rotate3d(0,1,0,-180deg);
z-index: 8;
}
.card:hover .face, .card-flipped .face {
-webkit-box-shadow: 0 0 10px #aaa;
}
.card-flipped .front {
-webkit-transform: rotate3d(0,1,0,180deg);
z-index: 8;
}
.card-flipped .back {
-webkit-transform: rotate3d(0,1,0,0deg);
z-index: 10;
}

```

1.  当任何卡被移除时，我们希望将其淡出。 因此，我们声明了一个带有 0 不透明度的 card-removed 类：

```js
.card-removed {
opacity: 0;
}

```

1.  为了从卡牌牌组的精灵表中显示不同的扑克牌图形，我们将卡的背景剪切成不同的背景位置：

```js
.cardAQ {background-position: -880px 0;}
.cardAK {background-position: -960px 0;}
.cardBQ {background-position: -880px -120px;}
.cardBK {background-position: -960px -120px;}
.cardCQ {background-position: -880px -240px;}
.cardCK {background-position: -960px -240px;}
.cardDQ {background-position: -880px -360px;}
.cardDK {background-position: -960px -360px;}

```

1.  我们已经定义了许多 CSS 样式。 现在是 JavaScript 逻辑的时候了。 打开`html5games.matchgame.js`文件，并将以下代码放入其中：

```js
$(function(){
// clone 12 copies of the card
for(var i=0;i<11;i++){
$(".card:first-child").clone().appendTo("#cards");
}
// initialize each card's position
$("#cards").children().each(function(index) {
// align the cards to be 4x3 ourselves.
$(this).css({
"left" : ($(this).width() + 20) * (index % 4),
"top" : ($(this).height() + 20) * Math.floor(index / 4)
});
});
});

```

1.  现在保存所有文件并在浏览器中预览游戏。 游戏应该有很好的样式，并且中央应该出现 12 张卡。 但是，我们还不能点击卡片，因为我们还没有为卡片设置任何交互逻辑。

![执行动作准备卡片匹配游戏的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_08.jpg)

## 刚刚发生了什么？

我们在 HTML 中创建了游戏结构，并对 HTML 元素应用了样式。我们还使用 jQuery 在网页加载和准备好后在游戏区域创建了 12 张卡片。翻转和移除卡片的样式也已准备好，并可以在稍后使用游戏逻辑应用到卡片上。

由于我们为每张卡片使用绝对定位，我们需要自己将卡片对齐到 4x3 的瓷砖中。在 JavaScript 逻辑中，我们通过循环每张卡片并通过计算循环索引来对齐它：

```js
$("#cards").children().each(function(index) {
// align the cards to be 4x3 ourselves.
$(this).css({
"left" : ($(this).width() + 20) * (index % 4),
"top" : ($(this).height() + 20) * Math.floor(index / 4)
});
});

```

JavaScript 中的“%”是**模运算符**，它返回除法后剩下的余数。余数用于在循环卡片时获取列数。以下图表显示了行/列关系与索引号：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_09.jpg)

另一方面，除法用于获取行数，以便我们可以将卡片定位在相应的行上。

以索引 3 为例，3 % 4 是 3。所以索引 3 的卡片在第三列。而 3 / 4 是 0，所以它在第一行。

让我们选择另一个数字来看看公式是如何工作的。让我们看看索引 8。8 % 4 是 0，它在第一列。8 / 4 是 2，所以它在第三行。

## 使用 jQuery 克隆 DOM 元素

在我们的 HTML 结构中，我们只有一张卡片，在结果中，我们有 12 张卡片。这是因为我们在 jQuery 中使用了`clone`函数来克隆卡片元素。克隆目标元素后，我们调用`appendTo`函数将克隆的卡片元素附加为卡片元素的子元素：

```js
$(".card:first-child").clone().appendTo("#cards");

```

## 使用子筛选器在 jQuery 中选择元素的第一个子元素

当我们选择卡片元素并克隆它时，我们使用了以下选择器：

```js
$(".card:first-child")

```

`:first-child`是一个**子筛选器**，选择给定父元素的第一个子元素。

除了`:first-child`，我们还可以使用`:last-child`选择最后一个子元素。

### 注意

您还可以在 jQuery 文档中检查其他与子元素相关的选择器：

[`api.jquery.com/category/selectors/child-filter-selectors/`](http://api.jquery.com/category/selectors/child-filter-selectors/)

## 垂直对齐 DOM 元素

我们将卡片 DIV 放在游戏元素的中心。**CSS3 灵活的盒子布局模块**引入了一种实现**垂直居中对齐**的简单方法。由于这个模块仍在进行中，我们需要应用浏览器供应商前缀。我们将以 Webkit 为例：

```js
display: -webkit-box;
-webkit-box-pack: center;
-webkit-box-align: center;

```

灵活盒模块定义了元素在其容器中有额外空间时的对齐方式。我们可以通过使用`display`，一个 CSS2 属性，值为`box`，一个新的 CSS3 属性值，将元素设置为灵活盒容器的行为。

`box-pack`和`box-align`是两个属性，用于定义它如何在水平和垂直方向上对齐并使用额外的空间。我们可以通过将这两个属性都设置为`center`来使元素居中。

垂直对齐只是灵活盒子布局模块的一小部分。在网页设计中进行布局时非常强大。您可以在 W3C 模块的页面([`www.w3.org/TR/css3-flexbox/`](http://www.w3.org/TR/css3-flexbox/))或 CSS3 Info 网站([`www.css3.info/introducing-the-flexible-box-layout-module/`](http://www.css3.info/introducing-the-flexible-box-layout-module/))上找到更多信息。

## 使用 CSS 精灵和背景位置

**CSS 精灵**表是一个包含许多单独图形的大图像。大的精灵表图像被应用为元素的背景图像。我们可以通过移动固定宽度和高度元素的背景位置来剪裁每个图形。

我们的牌组图像包含总共 53 个图形。为了方便演示背景位置，让我们假设我们有一张包含三张卡片图像的图像，如下面的截图：

使用 CSS 精灵和背景位置

在 CSS 样式中，我们将卡片元素设置为 80 像素宽，120 像素高，背景图像设置为大牌组图像。如果我们想要左上角的图形，我们将背景位置的 X 和 Y 都应用为 0。如果我们想要第二个图形，我们将背景图像移动到左 80 像素。这意味着将 X 位置设置为-80 像素，Y 设置为 0。由于我们有固定的宽度和高度，只有裁剪的 80x120 区域显示背景图像。以下截图中的矩形显示了可视区域：

![使用 CSS 精灵和背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_11.jpg)

# 为匹配游戏添加游戏逻辑

现在让我们想象手中拿着一副真正的牌组并设置匹配游戏。

我们首先在手中洗牌，然后将每张卡片背面朝上放在桌子上。为了更容易玩游戏，我们将卡片排成 4x3 的数组。现在游戏已经准备好了。

现在我们要开始玩游戏了。我们拿起一张卡片并翻转它使其正面朝上。然后我们拿起另一张并将其朝上。之后，我们有两种可能的操作。如果它们是相同的图案，我们就把这两张卡片拿走。否则，我们将它们再次放回背面，就好像我们没有触摸过它们一样。游戏将继续，直到我们配对所有卡片并将它们全部拿走。

在我们脑海中有了逐步的情景之后，代码流程将会更加清晰。实际上，这个例子中的代码与我们玩真正的牌组的过程完全相同。我们只需要将人类语言替换为 JavaScript 代码。

# 执行为匹配游戏添加游戏逻辑的操作

在上一个示例中，我们准备了游戏环境，并决定了游戏逻辑与玩真正的牌组相同。现在是时候编写 JavaScript 逻辑了：

1.  让我们从上一个匹配游戏示例开始。我们已经设计了 CSS，现在是时候在`html5games.matchgame.js`文件中添加游戏逻辑了。

1.  游戏是匹配一对扑克牌。现在我们有 12 张卡片，所以我们需要六对扑克牌。以下全局数组声明了六对卡片图案：

```js
var matchingGame = {};
matchingGame.deck = [
'cardAK', 'cardAK',
'cardAQ', 'cardAQ',
'cardAJ', 'cardAJ',
'cardBK', 'cardBK',
'cardBQ', 'cardBQ',
'cardBJ', 'cardBJ',
];

```

1.  在上一章中，我们在 jQuery 的`ready`函数中排列了卡片。现在我们需要在`ready`函数中准备和初始化更多的代码。将`ready`函数更改为以下代码。更改后的代码已经突出显示：

```js
$(function(){
matchingGame.deck.sort(shuffle);
for(var i=0;i<11;i++){
$(".card:first-child").clone().appendTo("#cards");
}
$("#cards").children().each(function(index) {
$(this).css({
"left" : ($(this).width() + 20) * (index % 4),
"top" : ($(this).height() + 20) * Math.floor(index / 4)
});
// get a pattern from the shuffled deck
var pattern = matchingGame.deck.pop();
// visually apply the pattern on the card's back side.
$(this).find(".back").addClass(pattern);
// embed the pattern data into the DOM element.
$(this).attr("data-pattern",pattern);
// listen the click event on each card DIV element.
$(this).click(selectCard);
});
});

```

1.  与玩真正的牌组类似，我们想要做的第一件事就是洗牌。将以下`shuffle`函数添加到 JavaScript 文件中：

```js
function shuffle() {
return 0.5 - Math.random();
game logic, adding to matching gamegame logic, adding to matching gamesteps}

```

1.  当我们点击卡片时，我们翻转它并安排检查函数。将以下代码附加到 JavaScript 文件中：

```js
function selectCard() {
// we do nothing if there are already two card flipped.
if ($(".card-flipped").size() > 1) {
return;
}
$(this).addClass("card-flipped");
// check the pattern of both flipped card 0.7s later.
if ($(".card-flipped").size() == 2) {
setTimeout(checkPattern,700);
}
}

```

1.  当两张卡片被打开时，执行以下函数。它控制我们是移除卡片还是翻转卡片：

```js
function checkPattern() {
if (isMatchPattern()) {
$(".card-flipped").removeClass("card-flipped").addClass ("card-removed");
$(".card-removed").bind("webkitTransitionEnd", removeTookCards);
} else {
$(".card-flipped").removeClass("card-flipped");
}
}

```

1.  现在是检查图案的函数的时间。以下函数访问已打开卡片的自定义图案属性，并比较它们是否是相同的图案：

```js
function isMatchPattern() {
var cards = $(".card-flipped");
var pattern = $(cards[0]).data("pattern");
var anotherPattern = $(cards[1]).data("pattern");
return (pattern == anotherPattern);
}

```

1.  匹配的卡片淡出后，我们执行以下函数来移除卡片：

```js
function removeTookCards() {
$(".card-removed").remove();
}

```

1.  游戏逻辑现在已经准备好了。让我们在浏览器中打开游戏 HTML 并进行游戏。如果有任何错误，请记得检查开发者工具中的控制台窗口。

![执行为匹配游戏添加游戏逻辑的操作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_12.jpg)

## 刚刚发生了什么？

我们编写了 CSS3 匹配游戏的游戏逻辑。该逻辑为玩牌添加了鼠标点击交互，并控制了图案检查的流程。

## 在 CSS 过渡结束后执行代码

在播放淡出过渡后，我们移除成对的卡片。我们可以通过使用`TransitionEnd`事件来安排在过渡结束后执行的函数。以下是我们代码示例中的代码片段，它向成对的卡片添加了`card-removed`类来开始过渡。然后，它绑定了`TransitionEnd`事件以在 DOM 中完全移除卡片。此外，请注意`webkit`供应商前缀，因为它尚未最终确定：

```js
$(".card-flipped").removeClass("card-flipped").addClass("card-removed");
$(".card-removed").bind("webkitTransitionEnd", removeTookCards);

```

## 延迟执行翻牌的代码

游戏逻辑流程的设计方式与玩一副真正的牌相同。一个很大的区别是我们使用了几个`setTimeout`函数来延迟代码的执行。当点击第二张卡时，我们在以下代码示例片段中安排`checkPattern`函数在 0.7 秒后执行：

```js
if ($(".card-flipped").size() == 2) {
setTimeout(checkPattern,700);
}

```

我们延迟函数调用的原因是为了给玩家时间来记忆卡片模式。这就是为什么我们在检查卡片模式之前延迟了 0.7 秒。

## 在 JavaScript 中对数组进行随机化

JavaScript 中没有内置的数组随机化函数。我们必须自己编写。幸运的是，我们可以从内置的数组排序函数中获得帮助。

以下是`sort`函数的用法：

```js
sort(compare_function);

```

`sort`函数接受一个可选参数。

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| `compare_function` | 定义数组的排序顺序的函数。`compare_function`需要两个参数 | `sort`函数通过使用`compare`函数比较数组中的两个元素。因此，`compare`函数需要两个参数。当`compare`函数返回大于 0 的任何值时，它会将第一个参数放在比第二个参数更低的索引处。当返回值小于 0 时，它会将第二个参数放在比第一个参数更低的索引处。 |

这里的诀窍是我们使用了`compare`函数，该函数返回-0.5 到 0.5 之间的随机数：

```js
anArray.sort(shuffle);
function shuffle(a, b) {
return 0.5 - Math.random();
}

```

通过在`compare`函数中返回一个随机数，`sort`函数以不一致的方式对相同的数组进行排序。换句话说，我们正在洗牌数组。

### 注意

来自 Mozilla 开发者网络的以下链接提供了关于使用`sort`函数的详细解释和示例：

[`developer.mozilla.org/en/JavaScript/Reference/Global_Objects/Array/sort`](http://https://developer.mozilla.org/en/JavaScript/Reference/Global_Objects/Array/sort)

## 使用 HTML5 自定义数据属性存储内部自定义数据

我们可以通过使用**自定义数据属性**将自定义数据存储在 DOM 元素内。我们可以使用`data-`前缀创建自定义属性名称并为其分配一个值。

例如，我们可以在以下代码中将自定义数据嵌入到列表元素中：

```js
<ul id="games">
<li data-chapter="2" data-difficulty="easy">Ping-Pong</li>
<li data-chapter="3" data-difficulty="medium">Matching Game</li>
</ul>

```

这是 HTML5 规范中提出的一个新功能。根据 W3C 的说法，自定义数据属性旨在存储页面或应用程序私有的自定义数据，对于这些数据没有更合适的属性或元素。

W3C 还指出，这个自定义数据属性是“用于网站自己的脚本使用，而不是用于公开可用的元数据的通用扩展机制。”

我们正在编写我们的匹配游戏并嵌入我们自己的数据到卡片元素中，因此，自定义数据属性符合我们的使用方式。

我们使用自定义属性来存储每张卡片内的卡片模式，因此我们可以通过比较模式值在 JavaScript 中检查两张翻转的卡片是否匹配。此外，该模式也用于将扑克牌样式化为相应的图形：

```js
$(this).find(".back").addClass(pattern);
$(this).attr("data-pattern",pattern);

```

## 弹出测验

1.  根据 W3C 关于自定义数据属性的指南，以下哪种说法是正确的？

a. 我们可以创建一个`data-href`属性来存储`a`标签的链接。

b. 我们可能希望在第三方游戏门户网站中访问自定义数据属性。

c. 我们可能希望在每个玩家的 DOM 元素中存储一个`data-score`属性，以便在我们的网页中对排名进行排序。

d. 我们可以在每个玩家的 DOM 元素中创建一个`ranking`属性来存储排名数据。

## 使用 jQuery 访问自定义数据属性

在匹配游戏示例中，我们使用了 jQuery 库中的`attr`函数来访问我们的自定义数据：

```js
pattern = $(this).attr("data-pattern");

```

`attr`函数返回给定属性名称的值。例如，我们可以通过调用以下代码获取所有`a`标签中的链接：

```js
$("a").attr("href");

```

对于 HTML5 自定义数据属性，jQuery 还为我们提供了另一个函数来访问 HTML5 自定义数据属性。这就是`data`函数。

`Data`函数旨在将自定义数据嵌入到 HTML 元素的 jQuery 对象中。它是在 HTML5 自定义数据属性之前设计的。

以下是`data`函数的用法：

```js
.data(key)
.data(key,value)

```

`data`函数接受两种类型的函数：

| 函数类型 | 参数定义 | 讨论 |
| --- | --- | --- |
| `.data(key)` | `key`是命名数据的字符串 | 当只给出键时，`data`函数读取与 jQuery 对象关联的数据并返回相应的值。在最近的 jQuery 更新中，此函数被扩展以支持 HTML5 自定义数据属性。 |
| `.data(key, value)` | `key`是命名数据的字符串`value`是要与 jQuery 对象关联的数据 | 当给出键和值参数时，`data`函数将新的数据条目设置为 jQuery 对象。值可以是任何 JavaScript 类型，包括数组和对象。 |

为了支持 HTML5 自定义数据属性，jQuery 扩展了`data`函数，使其能够访问 HTML 代码中定义的自定义数据。

以下代码解释了我们如何使用`data`函数。

给定以下 HTML 代码：

```js
<div id="target" data-custom-name="HTML5 Games"></div>

```

我们可以通过调用 jQuery 中的`data`函数访问`data-custom-name`属性：

```js
$("#target").data("customName")

```

它将返回"HTML5 Games"。

## 快速测验

1.  给定以下 HTML 代码：

```js
<div id="game" data-score="100"></div>

```

以下哪两个 jQuery 语句读取自定义分数数据并返回 100？

a. $("#game").attr("data-score");

b. $("#game").attr("score");

c. $("#game").data("data-score");

d. $("#game").data("score");

## 试试吧

我们已经创建了 CSS3 匹配游戏。这里缺少什么？游戏逻辑没有检查游戏是否结束。尝试在游戏结束时添加**你赢了**文本。您还可以使用本章讨论的技术来为文本添加动画。

## 制作其他纸牌游戏

这种 CSS3 纸牌方法适用于创建纸牌游戏。卡片上有两面适合翻转。过渡适合移动卡片。通过移动和翻转，我们可以定义玩法规则并充分利用纸牌游戏。

## 试试吧

您能否使用纸牌图形和翻转技术创建另一个游戏？比如扑克？

# 将网络字体嵌入到我们的游戏中

多年来，我们一直在使用有限的字体来设计网页。我们无法使用任何我们想要的字体，因为浏览器从访问者的本地机器加载字体。我们无法控制并确保访问者拥有我们想要的字体。

尽管我们可以将**网络字体**嵌入到 Internet Explorer 5 中，但格式受限，我们必须等到浏览器供应商支持嵌入最常见的 TrueType 字体格式。

想象一下，我们可以通过嵌入不同样式的网络字体来控制游戏的情绪。我们可以使用我们想要的字体设计游戏，并更好地控制游戏的吸引力。让我们尝试将网络字体嵌入到我们的匹配记忆游戏中。

# Time for action Embedding a font from Google Font Directory

**Google 字体目录**是一个列出可免费使用的网络字体的网络字体服务。我们将嵌入从 Google 字体目录中选择的网络字体：

1.  转到 Google 字体目录网站：[`code.google.com/webfonts`](http://code.google.com/webfonts)。

1.  在字体目录中，有一个列出了开源许可的可免费使用的网络字体列表。

1.  选择其中一个并单击字体名称以继续下一步。在此示例中，我使用了**Droid Serif**。

1.  单击字体后，字体目录会显示有关该字体的详细信息。我们可以在那里执行几项操作，例如预览字体、从变体中选择，最重要的是获取字体嵌入代码。

1.  单击**获取代码**选项卡，您将看到以下屏幕截图。它显示了如何将此字体嵌入到我们的网页中的指南：![Time for action Embedding a font from Google Font Directory](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_13.jpg)

1.  复制谷歌提供的`link`标签，并将其粘贴到 HTML 代码中。它应该放在任何其他样式定义之前：

```js
<link href='http://fonts.googleapis.com/css?family=Droid+Serif:regular,bold&subset=latin' rel='stylesheet' type='text/css'>

```

1.  现在我们可以使用字体来为文本设置样式。将 body 的字体系列属性设置为以下代码：

```js
body {
font-family: 'Droid Serif', arial, serif;
}

```

1.  保存所有文件并打开`index.html`文件。浏览器将从谷歌服务器下载字体并嵌入到网页中。注意字体，它们应该被加载并呈现为我们选择的谷歌字体。

![采取行动从谷歌字体目录嵌入字体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_03_14.jpg)

## 刚刚发生了什么？

我们刚刚用一种非常见的网络字体为我们的游戏添加了样式。该字体是通过谷歌字体目录托管和交付的。

### 注意

除了使用字体目录，我们还可以使用@font face 来嵌入我们的字体文件。以下链接提供了一种可靠的方法来嵌入字体：

[`www.fontspring.com/blog/the-new-bulletproof-font-face-syntax`](http://www.fontspring.com/blog/the-new-bulletproof-font-face-syntax)

### 提示

**在嵌入之前检查字体许可证**

通常，字体许可证不包括在网页上的使用。在嵌入字体之前，请务必检查许可证。谷歌字体目录中列出的所有字体都是根据开源许可证授权的，可以在任何网站上使用。

## 选择不同的字体交付服务

Google 字体目录只是其中一个字体交付服务。Typekit ([`typekit.com`](http://typekit.com)) 和 Fontdeck ([`fontdeck.com`](http://fontdeck.com)) 是另外两个提供数百种高质量字体的字体服务，通过年度订阅计划提供。

选择不同的字体交付服务

# 摘要

在本章中，我们学习了使用不同的 CSS3 新属性来创建游戏。

具体来说，我们涵盖了：

+   通过过渡模块转换和动画游戏对象

+   使用透视深度错觉来翻转卡片

+   基于 CSS3 样式和 jQuery 的动画和游戏逻辑创建匹配的记忆游戏

+   从在线字体交付服务中选择和嵌入网络字体

现在我们已经学会了如何使用 CSS3 功能创建基于 DOM 的 HTML5 游戏，我们将在下一章中探索另一种创建 HTML5 游戏的方法，即使用新的 Canvas 标签和绘图 API。
