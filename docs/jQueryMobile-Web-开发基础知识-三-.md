# jQueryMobile Web 开发基础知识（三）

> 原文：[`zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747`](https://zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：创建原生应用程序

在本章中，我们将看看如何将基于 jQuery Mobile 的 Web 应用程序转化为移动设备的原生应用程序。我们将讨论 PhoneGap 框架以及它如何允许您利用设备的硬件。

在本章中，我们将：

+   讨论 PhoneGap 项目及其功能

+   演示如何使用 PhoneGap 的构建服务来创建原生应用程序

# HTML 作为原生应用

对大多数人来说，在诸如 Android 或 iOS 之类的平台上创建原生应用程序需要学习全新的编程语言。虽然学习新语言并扩展技能的范围总是很好，但如果您可以利用现有的 HTML 技能并在移动设备上本地使用它们，那岂不是很酷？

幸运的是，正好有这样一个平台。PhoneGap ([`www.phonegap.com`](http://www.phonegap.com))是一个开源项目，允许您使用 HTML 页面创建原生应用程序。这段代码完全免费，可用于开发 iOS（iPhone 和 iPad）、Android（手机和平板电脑）、Blackberry、WebOS、Windows Phone 7、Symbian 和 Bada 的应用程序。PhoneGap 通过在原生环境中创建一个项目并指向一个 HTML 文件来工作。一旦设置好，您可以利用现有的 HTML、CSS 和 JavaScript 技能来创建应用程序的用户界面和功能。

更好的是，PhoneGap 还为您的 JavaScript 代码提供了额外的 API。这些 API 允许：

+   加速器：允许您的代码检测设备上的基本运动

+   摄像头：允许您的代码与相机配合使用

+   Compass：让您访问设备上的指南针

+   联系人：提供基本的搜索和联系人创建支持

+   文件：读/写访问设备存储

+   地理定位：提供一种检测设备位置的方式

+   媒体：允许基本的视频/音频捕获支持

+   网络：确定设备的网络连接设置

+   通知：创建通知的简单方式（通过弹出窗口、声音或振动）

+   存储：访问一个简单的 SQL 数据库

通过使用这些 API，您可以将普通的 HTML 网站转化为功能强大的类原生应用程序，用户可以下载并安装到他们的设备上。

在我们继续之前，让我们简要了解一下**PhoneGap**。PhoneGap 是 Apache 目前处于孵化状态的开源项目。它已更名为**Cordova**。你可能会听到人们用这两个名字来指代它。在写这本书的时候，大多数人仍然把这个项目称为 PhoneGap，这也是我们将使用的术语。重要的是要记住，PhoneGap 是免费且开源的！

在我们继续之前，让我们快速讨论一下 PhoneGap 应用程序与原生应用程序的比较。在大多数情况下，原生应用程序的性能比使用 PhoneGap 创建的应用程序要快。PhoneGap 并不意味着取代原生开发。但通过允许您使用现有技能并一次部署到多个平台，其好处可能远远超过对性能的任何关注。

## 使用 PhoneGap

创建一个 PhoneGap 项目有两种主要方法。人们使用 PhoneGap 的主要方式是首先使用他们正在为之构建的平台的开发工具。所以，对于一个安卓项目，这涉及使用具有正确插件的 Eclipse 编辑器，而在 iOS 上则涉及使用 XCode。*入门指南* ([`www.phonegap.com/start`](http://www.phonegap.com/start)) 提供了如何为您选择的设备平台设置环境的详细信息：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_1.jpg)

对于每个平台的设置细节对于本书来说太多了（而且只是重复了 PhoneGap 网站上的内容），所以我们将专注于创建原生应用的另一种选项，即 **PhoneGap Build** 服务。PhoneGap Build ([`build.phonegap.com`](https://build.phonegap.com)) 是一个在线服务，简化并自动化了创建原生应用的过程。它允许您简单地上传代码（或使用公共源代码控制存储库）以生成原生二进制文件。更好的是，您可以使用 PhoneGap Build 为所有受支持的平台生成二进制文件。这意味着您可以编写您的代码，并从该网站生成 iPhone、安卓、黑莓和其他版本的代码：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_2.jpg)

PhoneGap Build 服务并不免费。定价计划和其他详情可以在该网站上找到，但幸运的是有一个免费的开发者计划。这就是我们将在本章中使用的服务。让我们开始创建一个账户。（在接下来的屏幕截图和示例中，请确保将细节更改为您自己的特定内容。）

首先点击 **创建账户** 按钮并填写相关细节：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_3.jpg)

注册后，您将返回到 PhoneGap Build 的首页，您不会看到任何类型的确认消息。这有点不幸，但如果您检查您的电子邮件，您应该会看到他们发来的一封验证注册的消息。点击那个链接，您将被带到一个页面，询问您要创建您的第一个 PhoneGap Build 项目：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_4.jpg)

请注意，构建服务支持从新的 Github 存储库、现有的 Git 或 Subversion 存储库或通过上传的 ZIP 或 HTML 文件中的项目种子。此时，让我们离开网站，再回到代码。我们想要从一个非常简单的代码集开始。稍后在本章中我们会做一些更有趣的事情，但现在，我们的目标只是上传一些 HTML 并看看接下来会发生什么。在你从 GitHub 下载的代码中，打开`c12`文件夹，看看`app1`文件夹。其中包含了第四章 *Working with Lists*中一个列表示例的副本。它使用 jQuery Mobile 创建了一个简单的包括缩略图片的四人列表。这并不是太令人兴奋，但对我们目前的目的来说已经足够了。你会注意到已经有一个`app1.zip`文件。

如果你回到网站并选择**上传存档**，然后可以浏览到你从计算机上解压文件的位置并选择那个 ZIP 文件。确保还为应用程序输入一个名称。我选择了`FirstBuildApp`。点击**创建**后，你会被带到包含您所有应用程序的页面，如果您是一个新的构建用户，那里将只包含刚刚创建的一个应用程序。

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_5.jpg)

点击应用程序标题，然后您可以选择下载各种版本的应用程序。信不信由你——你已经能够在大多数平台上下载版本。但使用 iOS 需要你提供额外的细节：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_6.jpg)

如果你看不到**下载**链接而是看到一个**排队**通知，请给构建服务一两分钟来赶上。如果你简单地重新加载页面，最终你就会看到链接显示出来。

真正使用应用程序取决于你选择的平台。对于安卓，你需要确保已启用**允许安装非市场应用程序**设置。该设置的确切措辞和位置将取决于您的设备。这个短语可以在我的 HTC Inspire 设备的**应用**设置中找到。您可以通过在 PhoneGap Build 网站上编辑设置来对应用程序签名。一旦你做过了，你就可以将你的应用程序提交到安卓市场。但由于安卓允许您测试时使用未签名的应用程序，您可以跳过此步骤。如果您下载 APK（表示您的应用程序的实际文件），您可以以几种方式将其放在设备上。安卓 SDK 包括从命令行安装应用程序的工具。最简单的方法是使用你的电子邮件。如果你将文件发给自己，并在设备上检查你的电子邮件，你应该能够在那里安装它。以下屏幕截图显示了我的手机上运行的应用程序：

![使用 PhoneGap](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_7.jpg)

## 添加 PhoneGap 功能

我们刚刚演示了如何使用 PhoneGap Build 服务将 HTML（当然还包括 JavaScript、CSS 和图像）转换为真正的本机应用程序，以适应多个平台。然而，在本章的前面部分提到过，PhoneGap 提供的不仅仅是简单的包装器来将 HTML 转换为本机应用程序。PhoneGap JavaScript API 提供了对许多酷炫的设备中心服务的访问，这些服务可以极大地增强您的应用程序的功能。对于我们的第二个示例，我们将看一下其中一个功能——联系人 API（有关详细信息，请参阅*联系人 API 文档*，可在[`docs.phonegap.com/en/1.4.1/phonegap_contacts_contacts.md.html#Contacts)`](http://docs.phonegap.com/en/1.4.1/phonegap_contacts_contacts.md.html#Contacts)上找到）。

应用程序在`Listing 12-1`中是一个简单的联系人搜索工具。让我们看看代码，然后解释一下其中的内容：

```js
Listing 12-1: index.html
<!DOCTYPE html>
<html>
<head>
<title>Contact Search</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href ="jquery.mobile.min.css" />
<script src="img/jquery.js"></script>
<script src="img/jquery.mobile.min.js"></script>
<script src="img/phonegap-1.4.1.js"></script>
<script>
document.addEventListener("deviceready", onDeviceReady, false);
function onDeviceReady(){
$("#searchButton").bind("touchend", function() {
var search = $.trim($("#search").val());
if(search == "") return;
var opt = new ContactFindOptions();
opt.filter = search;
opt.multiple = true;
navigator.contacts.find(["displayName","emails"], foundContacts, errorContacts, opt);
});
foundContacts = function(matches){
//create results in our list
var s = "";
for (var i = 0; i < matches.length; i++) {
s += "<li>"+matches[i].displayName+"</li>";
}
$("#results").html(s);
$("#results").listview("refresh");
}
errorContacts = function(err){
navigator.notification.alert("Sorry, we had a problem and gave up.", function() {});
}
}
</script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Contact Search</h1>
</div>
<div data-role="content">
<input type="text" id="search" value="adam" />
<button id="searchButton">Search</button>
<ul id="results" data-role="listview" data-inset="true"></ul>
</div>
</div>
</div>
</body>
</html>

```

让我们首先看看应用程序的布局部分，它位于文件的下半部分。您可以看到我们的 jQuery Mobile 页面结构，其中包括一个输入字段、一个按钮和一个空列表。这里的想法是用户将输入要搜索的名称，点击按钮，结果将显示在列表中。以下屏幕截图展示了输出：

![添加 PhoneGap 功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_8.jpg)

现在看一下 JavaScript 代码。我们所做的第一个更改是包含 PhoneGap JavaScript 库：

```js
<script src="img/phonegap-1.4.1.js"></script>

```

此 JavaScript 库可从您从 PhoneGap 下载的 ZIP 文件中获得。即使我们不打算在本地构建我们的应用程序（当然您也可以），我们也需要在发送到 Build 服务的 ZIP 文件中包含 JavaScript 文件。这里有一个棘手的部分。截至 PhoneGap v 1.4.1，每个平台的 JavaScript 文件都是唯一的。这意味着 PhoneGap 支持的每个操作系统都有一个不同的 JavaScript 文件。Build 服务足够智能，可以用适当平台的正确文件替换您的文件引用。如果您使用本书的 Github 存储库中的代码，则是 Android 版本。如果您想将此代码用于 iOS，请务必在本地替换 JavaScript 文件。

下一个有趣的细节是以下代码行：

```js
document.addEventListener("deviceready", onDeviceReady, false);

```

`deviceready`事件是由 PhoneGap 触发的特殊事件。它基本上意味着您的代码现在可以使用高级功能，例如 Contacts API。

在事件处理程序`onDeviceReady`中，我们有一些事情要做。值得注意的第一个函数是搜索按钮的事件处理程序。前几行代码只是获取、修整和验证值。

在确保实际有内容可以搜索后，您可以看到对 Contacts API 的第一个实际使用，如下面的代码片段所示：

```js
var opt = new ContactFindOptions();
opt.filter = search;
opt.multiple = true;
navigator.contacts.find(["displayName","emails"], foundContacts, errorContacts, opt);

```

联系人 API 具有搜索方法。其第一个参数是要搜索和返回的字段数组。在我们的案例中，我们表示我们要针对联系人的姓名和电子邮件值进行搜索。第二个和第三个参数是成功和错误回调。最后一个选项是搜索的选项集。你可以在调用之前看到它被创建。过滤器键仅是搜索词条。默认情况下，联系人搜索返回一个结果，所以我们特别要求多个结果。

现在让我们来看一下成功处理程序：

```js
foundContacts = function(matches){
//create results in our list
var s = "";
for (var i = 0; i < matches.length; i++) {
s += "<li>"+matches[i].displayName+"</li>";
}
$("#results").html(s);
$("#results").listview("refresh");
}

```

联系人搜索的结果将是一个结果数组。记住你只会得到你要求的内容，所以我们的结果对象包含 `displayName` 和 `emails` 属性。目前，我们的代码只是获取 `displayName` 并将其添加到列表中。根据我们从之前的章节学到的知识，我们还知道每当修改列表时，我们需要刷新 jQuery Mobile listview。以下屏幕截图显示了一个示例搜索：

![添加 PhoneGap 功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_12_9.jpg)

# 摘要

在本章中，我们研究了 PhoneGap 开源项目以及它如何允许你使用 HTML、JavaScript 和 CSS 创建多种不同设备的原生应用程序。我们使用 Build 服务并用它来上传我们的代码和下载编译后的原生应用程序。虽然 jQuery Mobile 不是 PhoneGap 的必需品，但两者组合在一起非常强大。

在下一章中，我们将使用这个团队创建我们的最终应用程序，一个功能齐全的 RSS 阅读器。


# 第十三章：成为专家 - 构建一个 RSS 阅读器应用程序

现在您已经了解了 jQuery Mobile 及其功能，是时候构建我们最终的完整应用程序了 —— 一个 RSS 阅读器。

在这一章中，我们将：

+   讨论 RSS 阅读器应用程序及其功能

+   创建应用程序

+   讨论可以添加到应用程序的内容

# RSS 阅读器 —— 应用程序

在深入代码之前，可能有必要快速展示应用程序的最终工作形式，以便您可以看到各个部分及其如何一起工作。RSS 阅读器应用程序就是这样一个应用程序，它旨在获取 RSS 源（例如来自 CNN、ESPN 和其他网站的源），将它们解析为可读数据，并提供一种查看文章的方式。该应用程序将允许您添加和删除源，提供名称和 URL，并提供一种查看源当前条目的方法。

应用程序始于一组基本说明。只有在您运行应用程序而没有任何已知源时才会显示这些说明：

![RSS 阅读器 — 应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_13_1.jpg)

单击 **添加源** 按钮会带您进入一个简单的表单，允许输入名称和 URL。（不幸的是，URL 必须手动输入。幸运的是，现代移动设备支持复制和粘贴。我强烈建议使用这个！）：

![RSS 阅读器 — 应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_13_2.jpg)

添加源后，您将返回到主页。以下截图显示添加了一些源后的视图：

![RSS 阅读器 — 应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_13_3.jpg)

要开始阅读条目，用户只需选择其中一个源。然后，它将获取该源并显示当前的条目：

![RSS 阅读器 — 应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_13_4.jpg)

应用程序的最后部分是入口视图本身。有些博客不会通过 RSS 提供“完整”的入口副本，显然您可能希望在博客本身发表评论。因此，在底部我们提供了一种简单的方法来访问真正的网站，如下图所示：

![RSS 阅读器 — 应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_13_5.jpg)

现在您已经看到了应用程序，让我们来构建它。我们将再次使用 PhoneGap Build 来创建最终结果，但这个应用程序实际上也可以在常规网站上运行。（我们将稍后讨论为什么。）

# 创建 RSS 阅读器应用程序

我们的应用程序从第一个页面 `index.html` 开始。此页面将加载 jQuery 和 jQuery Mobile。它的核心任务是列出您当前的源，但它必须在用户没有任何源时识别出来，并提供一些文本鼓励他们添加他们的第一个源：

```js
Listing 13-1: index.html
<!DOCTYPE html>
<html>
<head>
<title>RSS Reader App</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href ="jquery.mobile/jquery.mobile- 1.1.0.min.css" />
<script src="img/jquery-1.6.4.min.js"></script>
<script src="img/jquery.mobile-1.1.0.min.js"></script>
<script src="img/main.js"></script>
</head>
<body>
<div data-role="page" id="intropage">
<div data-role="header">
<h1>RSS Reader Application</h1>
</div>
<div data-role="content" id="introContent">
<p id="introContentNoFeeds" style="display:none">
Welcome to the RSS Reader Application. You do not currently have any RSS Feeds. Please use the "Add Feed" button below to begin.
</p>
<ul id="feedList" data-role="listview" data-inset="true" data- split-icon="delete"></ul>
<a href ="addfeed.html" data-role="button" data-theme="b">Add Feed</a>
</div>
<div data-role="footer">
<h4>Created with jQuery Mobile</h4>
</div>
</div>
<script>
$("#intropage").bind("pagecreate", function(e) {
init();
});
</script>
</body>
</html>

```

如代码清单前所述，我们需要首先加载 jQuery 和 jQuery Mobile 模板。您可以在前面的代码清单的开头看到这一点。页面的大部分是您在上一章中看到的模板 HTML，所以让我们指出一些具体的内容。

首先注意下导语段落。注意 CSS 来隐藏文本吗？这里的假设是 — 大多数情况下 — 用户不会需要这段文字，因为他们会有订阅源。我们的代码将在必要时处理显示它。

在该段落之后是一个空列表，将显示我们的 feeds。在下面是用于添加新 feeds 的按钮。

最后，我们在最后放了一小段脚本。这创建了一个 jQuery Mobile 页面事件 `pagecreate` 的事件监听器，我们将它与启动我们的应用程序任务相关联。

我们所有的代码（我们的自定义代码）都将存储在 `main.js` 中。这个文件有点大，所以我们只显示与每个部分相关的部分。在阅读本章时，请记住这一点。整个文件可以在书中的示例代码中找到：

```js
Listing 13-2: Portion of main.js
function init() {
//handle getting and displaying the intro or feeds
$("#intropage").live("pageshow",function(e) {
displayFeeds();
});

```

我们从 `main.js` 中的 `init` 函数开始。记住这个函数在首页的 `pagecreate` 上运行。它在页面显示之前运行。这使得它成为一个很好的地方去注册一个函数，用于页面显示时。我们已经将大部分逻辑提取到自己的函数中，所以接下来让我们来看看它。

## `displayFeeds` 函数

`displayFeeds` 处理检索我们的 feeds 并显示它们。逻辑很简单。如果没有 feeds，我们想要显示导语文本：

```js
Listing 13-3: displayFeeds from main.js
function displayFeeds() {
var feeds = getFeeds();
if(feeds.length == 0) {
//in case we had one form before...
$("#feedList").html("");
$("#introContentNoFeeds").show();
} else {
$("#introContentNoFeeds").hide();
var s = "";
for(var i=0; i<feeds.length; i++) {
s+= "<li><a href ='http://feed.html?id="+i+"' data- feed='"+i+"'>"+feeds[i].name+"</a> <a href ='http:// class='deleteFeed' data-feedid='"+i+"'>Delete</a></li>";
}
$("#feedList").html(s);
$("#feedList").listview("refresh");
}
}

```

注意我们还清空了列表。可能用户有 feeds 并删除了它们。通过将列表重置为空字符串，我们确保我们不留下任何东西。如果有 feeds，我们动态创建列表，确保在最后调用 `listview("refresh")` API，请求 jQuery Mobile 对列表进行美化。

## 存储我们的 feeds

那 feeds 是从哪里来的？我们如何存储它们？虽然我们正在使用 PhoneGap 并且可以使用嵌入式 SQLite 数据库实现，但我们可以使用更简单的东西 `localStorage`。`localStorage` 是一个 HTML5 功能，允许你在客户端存储键值对。虽然你不能存储复杂的数据，但你可以在存储之前使用 JSON 序列化来编码复杂的数据。这使得数据的存储非常简单。但请记住 `localStorage` 包含文件存储。当数据发生变化时，您的应用程序需要从文件中读取。尽管我们谈论的是一个简单的 feed 列表，但这些数据应该相对较小：

```js
Listing 13-3: getFeeds, addFeed, and removeFeed
function getFeeds() {
if(localStorage["feeds"]) {
return JSON.parse(localStorage["feeds"]);
} else return [];
}
function addFeed(name,url) {
var feeds = getFeeds();
feeds.push({name:name,url:url});
localStorage["feeds"] = JSON.stringify(feeds);
}
function removeFeed(id) {
var feeds = getFeeds();
feeds.splice(id, 1);
localStorage["feeds"] = JSON.stringify(feeds);
displayFeeds();
}

```

前三个函数代表了我们存储系统的整个封装。`getFeeds` 简单地检查 `localStorage` 的值，如果存在，则处理将 JSON 数据转换为原生 JavaScript 对象。`addFeed` 接受一个 feed 名称和 URL，创建一个简单的对象，并存储 JSON 版本。最后，`removeFeed` 函数简单地处理找到数组中的正确项，删除它，并将其存储回 `localStorage`。

## 添加一个 RSS feed

目前一切顺利。现在让我们看看添加 feed 所需的逻辑。如果你记得，我们用来添加 feed 的链接指向`addfeed.html`。让我们来看看它：

```js
Listing 13-4: addfeed.html
<!DOCTYPE html>
<html>
<head>
<title>Add Feed</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<div data-role="page" id="addfeedpage" data-add-back-btn="true">
<div data-role="header">
<h1>Add Feed</h1>
</div>
<div data-role="content">
<form id="addFeedForm">
<div data-role="fieldcontain">
<label for="feedname">Feed Name:</label>
<input type="text" id="feedname" value="" />
</div>
<div data-role="fieldcontain">
<label for="feedurl">Feed URL:</label>
<input type="text" id="feedurl" value="" />
</div>
<input type="submit" value="Add Feed" data-theme="b">
</div>
<div data-role="footer">
<h4>Created with jQuery Mobile</h4>
</div>
</div>
</body>
</html>

```

除了表单外，这个页面没有太多内容。请注意，我们的表单没有 action。我们在这里不使用服务器。相反，我们的代码将处理表单提交并执行某些操作。还要注意，我们没有按照之前建议的做法——将 jQuery 和 jQuery Mobile 包含在顶部。在桌面应用程序中，这些包含是必需的，因为用户可能会将页面添加到应用程序的主页之外的书签中。由于该代码的最终目标是 PhoneGap 应用程序，我们不必担心这一点。这使得我们的 HTML 文件稍微小了一点。现在让我们返回到`main.js`，看看处理这一逻辑的代码。

以下代码是`main.js`的`init`方法的片段。它处理表单上的按钮点击：

```js
Listing 13-5: Add Feed event registration logic
//Listen for the addFeedPage so we can support adding feeds
$("#addfeedpage").live("pageshow", function(e) {
$("#addFeedForm").submit(function(e) {
handleAddFeed();
return false;
});
});

```

现在我们可以看看`handleAddFeed`了。我已经将这段代码抽象出来，只是为了简化事情：

```js
Listing 13-6: handleAddFeed
function handleAddFeed() {
var feedname = $.trim($("#feedname").val());
var feedurl = $.trim($("#feedurl").val());
//basic error handling
var errors = "";
if(feedname == "") errors += "Feed name is required.\n";
if(feedurl == "") errors += "Feed url is required.\n";
if(errors != "") {
//Create a PhoneGap notification for the error
navigator.notification.alert(errors, function() {});
} else {
addFeed(feedname, feedurl);
$.mobile.changePage("index.html");
}
}

```

在大部分情况下，这里的逻辑应该很容易理解。我们获取 feed 名称和 URL 值，确保它们不为空，并可选地提醒任何错误。如果没有发生错误，那么我们运行之前描述的`addFeed`方法。请注意，我们使用`changePage`API 返回用户到主页。

我在这里特别指出一段代码，处理显示错误的那一行：

```js
navigator.notification.alert(errors, function() {});

```

这一行来自于 PhoneGap API。它为您的设备创建了一个针对移动设备的特定警报通知。你可以把它想象成一个更高级的 JavaScript `alert()` 调用。第二个参数是警报窗口解除时的回调函数。因为我们在那种情况下不需要执行任何操作，所以我们提供了一个什么都不做的空回调。

## 查看 feed

当用户点击查看 feed 时会发生什么？这可能是应用程序中最复杂的部分。我们从 HTML 模板开始，这相当简单，因为大部分工作将在 JavaScript 中完成：

```js
Listing 13-7: feed.html
<!DOCTYPE html>
<html>
<head>
<title>Feed</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<div data-role="page" id="feedpage" data-add-back-btn="true">
<div data-role="header">
<h1></h1>
</div>
<div data-role="content" id="feedcontents">
</div>
<div data-role="footer">
<h4>Created with jQuery Mobile</h4>
</div>
</div>
</body>
</html>

```

这个页面基本上充当一个外壳。请注意，它根本没有真正的内容，只是空的 HTML 元素等待填充。让我们返回到`main.js`，看看这是如何工作的：

```js
Listing 13-8: Feed display handler (part 1)
//Listen for the Feed Page so we can displaying entries
$("#feedpage").live("pageshow", function(e) {
//get the feed id based on query string
var query = $(this).data("url").split("=")[1];
//remove ?id=
query = query.replace("?id=","");
//assume it's a valid ID, since this is a mobile app folks won't be messing with the urls, but keep
//in mind normally this would be a concern
var feeds = getFeeds();
var thisFeed = feeds[query];
$("h1",this).text(thisFeed.name);
if(!feedCache[thisFeed.url]) {
$("#feedcontents").html("<p>Fetching data...</p>");
//now use Google Feeds API
$.get("https://ajax.googleapis.com/ajax/services/feed/ load?v=1.0&num=10&q="+encodeURI(thisFeed.url)+"&callback=?", {}, function(res,code) {
//see if the response was good...
if(res.responseStatus == 200) {
feedCache[thisFeed.url] = res.responseData.feed.entries;
displayFeed( thisFeed.url);
} else {
var error = "<p>Sorry, but this feed could not be loaded:</p><p>"+res.responseDetails+"</p>";
$("#feedcontents").html(error);
}
},"json");
} else {
displayFeed(thisFeed.url);
}
});

```

这段代码片段处理了对`feed.html`上的`pageshow`事件的监听。这意味着每次查看该文件时都会运行该代码，这正是我们想要的，因为它用于每个不同的 feed。这是如何工作的？记得我们的 feeds 列表包括了 feed 本身的标识符：

```js
for(var i=0; i<feeds.length; i++) {
s+= "<li><a href='http://feed.html?id="+i+"' data- feed='"+i+"'>"+feeds[i].name+"</a> <a href='http:// class='deleteFeed' data-feedid='"+i+"'>Delete</a></li>";
}

```

jQuery Mobile 通过数据（"url"）API 为我们提供了对 URL 的访问。由于这会返回整个 URL，而我们只关心问号后的内容，因此我们可以使用一些字符串函数来清理它。最终结果是一个数值查询，我们可以使用它来从我们的 feed 查询中提取数据。在常规的桌面应用程序中，用户很容易搞乱 URL 参数。因此，我们在这里进行一些检查，以确保请求的值确实存在。由于这是一个移动设备上的单用户应用程序，因此不需要担心这个问题。

在我们尝试获取 feed 之前，我们利用了一个简单的缓存系统。在 `main.js` 中的第一行创建了一个空对象：

```js
//used for caching
var feedCache= {};

```

此对象将存储我们的 feeds 结果，以便我们不必不断重新获取它们。这就是为什么有下面这行代码：

```js
if(!feedCache[thisFeed.url]) {

```

在我们执行任何额外的网络调用之前运行。那么我们如何实际获取 feed 呢？Google 有一个很酷的服务叫做 Feed API（[`developers.google.com/feed/`](https://developers.google.com/feed/)）。它允许我们使用 Google 来处理获取 RSS feed 的 XML 并将其转换为 JSON。JavaScript 可以处理 XML，但 JSON 更容易，因为它变成了常规的、简单的 JavaScript 对象。我们有一些错误处理，但如果一切顺利，我们只需缓存结果。最后一部分是对 `displayFeed:` 的调用：

```js
Listing 13-9: displayFeed
function displayFeed(url) {
var entries = feedCache[url];
var s = "<ul data-role='listview' data-inset='true' id='entrylist'>";
for(var i=0; i<entries.length; i++) {
var entry = entries[i];
s += "<li><a href ='entry.html?entry="+i+"&url="+encodeURI(url)+"'>"+ entry.title+"</a></li>";
}
s += "</ul>";
$("#feedcontents").html(s);
$("#entrylist").listview();
}

```

前面的代码块只是迭代了结果 feed。当 Google 解析 feed 中的 XML 时，它转换为我们可以循环的对象数组。虽然 feed 中有许多我们可能感兴趣的属性，但我们只关心标题。注意我们如何构建我们的链接。我们传递数值索引和 URL（我们将在下一部分中使用）。然后，这被呈现为一个简单的 jQuery Mobile listview。

## 创建条目视图

准备好了最后一部分了吗？让我们来看看个别条目的显示。与之前一样，我们将从模板开始：

```js
Listing 13-10: entry.html
<!DOCTYPE html>
<html>
<head>
<title>Entry</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<div data-role="page" id="entrypage" data-add-back-btn="true">
<div data-role="header">
<h1></h1>
</div>
<div data-role="content">
<div id="entrycontents"></div>
<a href ="" id="entrylink" data-role="button">Visit Entry</a>
</div>
<div data-role="footer">
<h4>Created with jQuery Mobile</h4>
</div>
</div>
</body>
</html>

```

与之前的 `feed.html` 类似，`entry.html` 是一个空壳。请注意，标题、内容和链接都是空的。所有这些都将被真实的代码替换。让我们返回到 `main.js` 并查看处理此页面的代码：

```js
Listing 13-11: Entry page event handler
$("#entrypage").live("pageshow", function(e) {
//get the entry id and url based on query string
var query = $(this).data("url").split("?")[1];
//remove ?
query = query.replace("?","");
//split by &
var parts = query.split("&");
var entryid = parts[0].split("=")[1];
var url = parts[1].split("=")[1];
var entry = feedCache[url][entryid];
$("h1",this).text(entry.title);
$("#entrycontents",this).html(entry.content);
$("#entrylink",this).attr("href",entry.link);
});

```

那么这里发生了什么？记得我们传递了一个索引值（点击了哪个条目，第一个，第二个？）和 feed 的 URL。我们从 URL 中解析出这些值。一旦我们知道了 feed 的 URL，我们就可以使用我们的缓存来获取特定的条目。一旦我们有了这个，更新标题、内容和链接就是一件简单的事情了。就是这样！

## 更进一步

现在，您可以从此应用程序中获取代码，并将其上传到 PhoneGap Build 服务，以便在您自己的设备上尝试。但是我们还能做些什么？以下是考虑的一些事项：

+   PhoneGap 提供了一个连接 API（[`docs.phonegap.com/en/1.4.1/phonegap_connection_connection.md.html`](http://docs.phonegap.com/en/1.4.1/phonegap_connection_connection.md.html)），返回设备连接状态的信息。你可以添加对此的支持，以防止用户在设备离线时尝试阅读订阅。

+   虽然我们将用户的订阅存储在`localStorage`中，但从阅读 RSS 条目缓存的数据是临时存储的。你也可以存储这些数据，并在用户离线时使用它。

+   PhoneGap 有一个出色的插件 API，并且已经有很多插件可用（[`github.com/phonegap/phonegap-plugins`](https://github.com/phonegap/phonegap-plugins)）。其中一个插件可以更轻松地发送短信。你可以添加一个选项，通过短信向朋友发送条目标题和链接。我们提到过 PhoneGap 还让你可以使用你的联系人，详细信息请参见联系人 API：[`docs.phonegap.com/en/1.4.1/phonegap_contacts_contacts.md.html`](http://docs.phonegap.com/en/1.4.1/phonegap_contacts_contacts.md.html)。

希望你能明白。这只是 jQuery Mobile 和 PhoneGap 强大功能的一个例子。

# 摘要

在本章中，我们利用了上一章学到的 PhoneGap 知识，创建了一个完整但相当简单的移动应用程序，利用了 jQuery Mobile 来进行设计和交互。
