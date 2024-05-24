# HTML5 移动开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841`](https://zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我如何创建快速响应的移动网站，使其在各种平台上运行？对于开发人员来说，处理各种具有独特屏幕尺寸和性能限制的移动设备的增多是一个重要问题。本书提供了答案。您将学习如何有效地应用最新的 HTML5 移动网络功能，以适应各种移动设备。

*HTML5 移动开发食谱*将向您展示如何规划、构建、调试和优化移动网站。应用最新的适合移动设备的 HTML5 功能，同时发现新兴的移动网络功能，以集成到您的移动网站中。

构建坚固的默认移动 HTML 模板，并了解移动用户交互。利用基于位置的移动特性和移动丰富媒体，使您的网站快速响应。使用调试、性能优化和服务器端调优使您的移动网站完美。本书最后预览了未来移动网络技术。

# 本书内容

第一章, *HTML5 和移动网络*，介绍了 HTML5 和移动网络，以及一些仿真器和模拟器。

第二章, *移动设置和优化*，讨论了各种移动设置和优化，如防止文本调整大小和优化视口宽度。

第三章, *移动事件的交互媒体*，讨论了移动交互，如手势事件。

第四章, *构建快速响应的网站*，讨论了使移动网站快速响应的各种方法。

第五章, *移动设备访问*，讨论了基于位置的移动网络和其他 HTML5 设备特定功能。

第六章, *移动丰富媒体*，讨论了可在移动浏览器上使用的 HTML5 丰富媒体元素。

第七章, *移动调试*，教你如何解决移动屏幕限制并有效地调试移动网站和 Web 应用程序。

第八章, *服务器端调优*，专注于移动网站的服务器端调优。

第九章, *移动性能测试*，教你使用各种工具和技术来提升移动性能。

第十章, *新兴移动网络功能*，讨论了 ECMAScript 5 以及为移动设备添加的特定功能，以实现更多的移动功能和提升性能。

# 本书所需内容

本书中大多数示例只需要一个文本编辑器。您还应该有一个移动设备，如 iPhone、Android、Blackberry 或其他适合测试的设备。虽然最好在真实设备上测试，但如果您没有，也不用担心，因为我们将介绍如何使用仿真器和模拟器进行测试，以防真实设备不可用。

# 本书适合对象

开发人员希望创建快速响应的 HTML5 移动网站，以适应各种移动设备。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码示例如下所示：“`geolocation`是`navigator`对象上的一个新属性。”

代码块设置如下：

```html
var latitude = position.coords.latitude;
var longitude = position.coords.longitude;
var accuracy = position.coords.accuracy;

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
var latitude = position.coords.latitude;
var longitude = position.coords.longitude;
var accuracy = position.coords.accuracy;

```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的词语，比如菜单或对话框中的词语，会以这种方式出现在文本中："在**捕获选项**对话框中点击**开始**按钮开始捕获。"

### 注意

警告或重要提示会以这样的方式显示在一个框中。

### 提示

提示和技巧会显示为这样。


# 第一章：HTML5 和移动网络

在本章中，我们将涵盖：

+   准备好你的移动设备

+   仿真器和模拟器

+   设置移动开发环境

+   在移动网络上使用 HTML5

+   使 HTML5 跨浏览器渲染

+   为移动设计

+   确定你的目标移动设备

+   制定内容适应策略

# 介绍

HTML5 和移动网络都是有前途的技术。两者的历史都相对较短。在本章中，我们将主要涵盖一些基础知识。这是为了帮助你快速开始移动开发，并付出最少的努力。

移动和 HTML5 仍在不断发展，你可能会有很多疑问。我们将解答这些疑问，让你专注于重要的事情。

移动网络发展迅速。我们现在有移动 Safari，这是 iPhone 上使用最广泛的应用之一，让开发人员能够构建高性能的网络应用，并增强用户的浏览体验。你不需要开发者账户来托管和运行移动网站，也不需要从任何应用市场获得批准来推出移动网站，而且你可以随时进行更新，而不必等待批准。这些都是移动网络开发的好处，但与此同时，也存在一些挑战，比如浏览器之间的不一致性，与原生应用相比缺少某些功能，以及安全性。我们无法解决所有问题，但我们肯定可以解决其中一些。在开发移动网站时，我们将看到如何将常规做法与最佳实践区分开来。

市面上有成千上万款智能手机；你不需要每一款都来测试你的应用。事实上，你可能只需要不到 10 款。如果这仍超出你的预算，那么两款设备就足够了。至于其他设备，你可以使用模拟器/仿真器来完成工作。本书重点关注六款 A 级移动设备，特别关注 iPhone、Android 和 Windows Phone：

+   iOS

+   Android

+   Windows Mobile

+   Blackberry v6.0 及以上版本

+   Symbian 60

+   Palm webOS

有两种与设备无关的浏览器也将在本书中介绍。它们是：

+   Opera Mobile

+   Firefox Mobile

其他浏览器不在列表中并不意味着它们不会受到我们在本书中讨论的问题和技术的影响。

## 确定你的目标移动设备

目标浏览器：全部

你不可能为每个移动设备制作一个移动网站。没有人有时间或精力这样做。

跨浏览器移动网络开发可能会很复杂。很难定义工作的范围，正如*John Resig*（jQuery Mobile 的创始人）在他的演示幻灯片中指出的那样，他提出了三个问题：（[`www.slideshare.net/jeresig/testing-mobile-javascript`](http://www.slideshare.net/jeresig/testing-mobile-javascript)）。

+   哪些平台和浏览器最受欢迎？

+   哪些浏览器能够支持现代脚本？

+   我需要哪些设备和模拟器来进行测试？

在构建移动网站时，你必须问自己类似的问题，但不是完全相同的问题，因为记住你的网站应该专门针对你的目标受众。所以你的问题应该是：

+   访问我网站的访客最常用的平台和浏览器是哪些？

+   有多少人从能够支持现代脚本的移动设备访问我的网站？

+   我需要哪些设备和模拟器来进行测试？

### 访问我网站的访客最常用的平台和浏览器是哪些？

现在让我们回答第一个问题。在构建移动网站之前，你必须首先找出你的目标受众是谁，以及他们在访问你网站时使用的移动设备。有许多分析工具可以帮助你回答这些问题。其中之一就是 Google Analytics。你可以在[`www.google.com/analytics/`](http://www.google.com/analytics/)免费注册一个 Google Analytics 账户。

做法非常简单：大多数开发人员对 Google Analytics 并不陌生。您只需从 Google Analytics 网站中包含 JavaScript 片段并嵌入到您的网页中即可。

大多数现代智能手机都可以渲染 JavaScript，因此在桌面站点和移动站点上使用它并没有真正的区别。

### 有多少人通过支持现代脚本的移动设备访问我的网站？

现在让我们回答第二个问题。您可能想要了解的一件事是使用移动浏览器浏览您的网站的人数。您还想了解有多少人使用根本不支持 JavaScript 的旧版移动浏览器。这是因为如果使用低端智能手机的人数比使用高端智能手机的人数更多，那么首先使用 HTML5 可能并不值得（尽管这种可能性非常低）。

因此，如果您的目标不仅是了解使用智能手机的人数，还要了解使用旧版移动电话的人数，Google Analytics for mobile 就可以派上用场。您可以从以下网址下载脚本：

[`code.google.com/mobile/analytics/download.html#Download_the_Google_Analytics_server_side_package`](http://code.google.com/mobile/analytics/download.html#Download_the_Google_Analytics_server_side_package)

Google Analytics for mobile 服务器端包目前支持 JSP、ASPX、Perl 和 PHP。让我们看看 PHP 中的一个示例。您只需将**ACCOUNT ID GOES HERE**更改为您的 GA 帐户 ID。但请记住**用'MO-xx'替换'UA-xx'**。

不幸的是，当您使用服务器端版本时，您不能在同时使用标准的 JavaScript 跟踪代码`ga.js`的页面上使用它。使用服务器端版本意味着您必须放弃 JavaScript 版本。这可能会很烦人，因为 JavaScript 版本提供了许多在服务器端版本中缺失的动态跟踪机制：

```html
<?php
// Copyright 2009 Google Inc. All Rights Reserved.
$GA_ACCOUNT = "ACCOUNT ID GOES HERE";
$GA_PIXEL = "ga.php";
function googleAnalyticsGetImageUrl() {
global $GA_ACCOUNT, $GA_PIXEL;
$url = "";
$url .= $GA_PIXEL . "?";
$url .= "utmac=" . $GA_ACCOUNT;
$url .= "&utmn=" . rand(0, 0x7fffffff);
$referer = $_SERVER["HTTP_REFERER"];
$query = $_SERVER["QUERY_STRING"];
$path = $_SERVER["REQUEST_URI"];
if (empty($referer)) {
$referer = "-";
}
$url .= "&utmr=" . urlencode($referer);
if (!empty($path)) {
$url .= "&utmp=" . urlencode($path);
}
$url .= "&guid=ON";
return $url;
}
?>

```

## Google Analytics 的替代方案

Google Analytics 并不是市场上唯一的移动分析服务。还有其他提供更专业服务的服务。例如，**PercentMobile**是一个托管的移动分析服务，可以清晰地展示您的移动受众和机会。您可以在以下网址了解更多关于这项服务的信息：

[`percentmobile.com/`](http://percentmobile.com/)

### Google Analytics 的准确性

移动设备报告的位置可能并不总是准确；Google Analytics 使用 IP 地址来确定地图叠加报告的用户位置。它们可能存在不准确性，因为移动 IP 来自无线运营商网关，这并不一定与移动用户位于同一位置。

### 服务器加载速度问题

由于服务器端处理，可能会产生一些额外的服务器负载。Google 建议您首先在您的一些页面上测试片段，以确保一切正常，然后再推广到整个网站。

# 设置移动开发工具

目标浏览器：全部

现在，前一个问题仍然没有得到答复：*我需要哪些设备和模拟器来进行测试？*我们将在这里找到答案。

如果您已经确定了要支持的主要移动设备，现在是时候看看如何设置它们了。如果您在各种移动设备上进行测试，移动开发可能会很昂贵。尽管我们有所有这些移动模拟器和仿真器可供测试，但与在真实设备上测试相比，效果并不好。现在让我们看看如何最大程度地覆盖测试并最小化成本。

## 准备就绪

我们在这里要做一些假设。每种情况都不同，但思路是一样的。假设您的桌面上使用的是 Windows 操作系统，但您网站的顶级访问者使用的是 iOS、Android 和 Blackberry。

## 如何做…

你的目标是最大程度地覆盖并最小化成本。这三种设备都有模拟器，但并非所有都支持不同的平台。

| 名称 | 兼容性 |
| --- | --- |
| iOS 模拟器 | Mac |
| Android 模拟器 | Windows, Mac, Linux |
| 黑莓模拟器 | Windows |

正如你所看到的，由于 iOS 模拟器只适用于 Mac，如果你使用的是 Windows 操作系统，最好且唯一的选择是购买 iPhone 进行测试。对于 Android 和黑莓，因为它们都有 Windows 的模拟器，为了节约预算，你可以下载模拟器。

## 它是如何工作的...

1.  列出人们用来浏览你的网站的热门移动设备。

1.  了解你用于开发的机器操作系统。

1.  了解每个设备模拟器与您的开发环境的兼容性。

## 还有更多...

如果你的预算可以支持多个不同操作系统的移动设备，你可以进一步考虑屏幕尺寸和移动设备的 DPI。你可能不需要购买两台高端设备。例如，拥有 iPhone4 和 Android Thunderbolt 并非必要。你可以购买一台低端的 Android 设备来测试你的网站在低端设备上的显示效果。因此，思路是结合操作系统、移动设备和模拟器，以最大程度地覆盖各种场景。

### 设备模拟器/模拟器下载查询表

以下表格显示了用于移动网页设计和开发测试的流行移动设备模拟器的列表：

| 名称 | 类型 | 兼容性 | URL |
| --- | --- | --- | --- |
| iOS | 模拟器 | Mac | [`developer.apple.com/devcenter/ios/index.action#downloads`](http://developer.apple.com/devcenter/ios/index.action#downloads) |
| Android | 模拟器 | Mac, Win, Linux | [`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html) |
| HP webOS | 虚拟机 | Mac, Win, Linux | [`developer.palm.com/index.php?option=com_content&view=article&id=1788&Itemid=55`](http://developer.palm.com/index.php?option=com_content&view=article&id=1788&Itemid=55) |
| Nokia Symbian | 模拟器 | Win | [`www.forum.nokia.com/info/sw.nokia.com/id/ec866fab-4b76-49f6-b5a5-af0631419e9c/S60_All_in_One_SDKs.html`](http://www.forum.nokia.com/info/sw.nokia.com/id/ec866fab-4b76-49f6-b5a5-af0631419e9c/S60_All_in_One_SDKs.html) |
| 黑莓 | 模拟器 | Win | [`us.blackberry.com/developers/resources/simulators.jsp`](http://us.blackberry.com/developers/resources/simulators.jsp) |
| Windows Mobile 7 | 模拟器 | Win | [`www.microsoft.com/downloads/en/details.aspx?FamilyID=04704acf-a63a-4f97-952c-8b51b34b00ce`](http://www.microsoft.com/downloads/en/details.aspx?FamilyID=04704acf-a63a-4f97-952c-8b51b34b00ce) |

### 浏览器模拟器/模拟器下载查询表

除了设备测试工具，我们还有针对平台独立浏览器的工具，特别是 Opera 和 Firefox。这些显示在下表中：

| 名称 | 类型 | 兼容性 | URL |
| --- | --- | --- | --- |
| Opera Mobile | 模拟器 | Mac, Win, Linux | [`www.opera.com/developer/tools/`](http://www.opera.com/developer/tools/) |
| Opera Mini | 模拟器 | Mac, Win, Linux | [`www.opera.com/developer/tools/http://www.opera.com/mobile/demo/`](http://www.opera.com/developer/tools/http://www.opera.com/mobile/demo/) |
| Firefox for Mobile | 模拟器 | Mac, Win, Linux | [`www.mozilla.com/en-US/mobile/download/`](http://www.mozilla.com/en-US/mobile/download/) |

### 远程测试

除了模拟器和模拟器，还有一些测试框架可以让你远程访问真实设备。其中一个工具是**DeviceAnywhere**；一个问题是它不是免费的。

[`www.deviceanywhere.com/`](http://www.deviceanywhere.com/)

# 黑莓模拟器

目标浏览器：黑莓

大多数移动设备模拟器在其网站上遵循说明进行安装和配置，但 BlackBerry 模拟器与其他移动设备模拟器的工作方式不同。对于 Blackberry 设备模拟器，除了下载模拟器外，还需要下载并安装**BlackBerry Email and MDS Services Simulator**以连接到互联网。

## 准备工作

确保您已经选择了一个要从中下载的模拟器：[`us.blackberry.com/developers/resources/simulators.jsp`](http://us.blackberry.com/developers/resources/simulators.jsp)

## 如何做...

首先，转到页面：[`swdownloads.blackberry.com/Downloads/entry.do?code=A8BAA56554F96369AB93E4F3BB068C22&CPID=OTC-SOFTWAREDOWNLOADS&cp=OTC-SOFTWAREDOWNLOADS`](http://swdownloads.blackberry.com/Downloads/entry.do?code=A8BAA56554F96369AB93E4F3BB068C22&CPID=OTC-SOFTWAREDOWNLOADS&cp=OTC-SOFTWAREDOWNLOADS)。在那里，您将看到一个类似以下截图的产品列表：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_14.jpg)

现在选择**BlackBerry Email and MDS Services Simulator Package**，然后点击**下一步**。

下载并安装软件后，您必须先启动服务模拟器，然后再启动 Blackberry 模拟器，以允许其连接到互联网。

以下是 Blackberry 模拟器的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_15.jpg)

# 设置移动开发环境

目标浏览器：所有

在开始移动 Web 开发之前，我们必须先设置开发环境。

## 准备工作

1.  在您的机器上设置本地主机。对于 Windows、Mac 或 Linux，设置它的最简单方法是使用流行且免费的 XAMPP 软件：([`www.apachefriends.org/en/index.html`](http://www.apachefriends.org/en/index.html))。

1.  确保您有无线连接。

1.  您还应该随身携带一个移动设备。否则，使用移动模拟器/仿真器。

1.  确保您的移动设备和桌面在同一个无线网络上。

## 如何做...

1.  创建一个 HTML 文件，并将其命名为`ch01e1.html`，放在您的本地主机的根目录下：

在`ch01r01.html`中，输入以下内容：

```html
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
Main Navigation here
</header>
body content here
<footer>
Footer links here
</footer>
</body>
</html>

```

1.  现在获取您的 IP 地址。如果您使用 Windows，可以在命令提示符中输入以下命令：

```html
ipconfig

```

### 提示

下载本书的示例代码

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便将文件直接发送到您的邮箱

1.  一旦您获得了您的 IP 地址（例如，`192.168.1.16.`），在您的移动浏览器 URL 地址栏中输入它。现在您应该看到页面加载，并显示文本：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_02.jpg)

## 它是如何工作的...

在同一个网络中，您的移动设备可以通过您的桌面 IP 地址访问您的桌面主机。

## 还有更多...

如果您没有移动设备，可以使用其中一个模拟器进行测试。但建议至少有一两台真实的移动设备进行测试。模拟器可以测试大多数事情，但并不是所有事情都能准确测试。

### 在 Safari 桌面上进行测试

如果您的主要目标受众是 iPhone 移动 Safari 用户，您也可以在桌面上进行测试以节省时间。为此，打开 Safari，转到**首选项**，点击**高级**选项卡，勾选**显示开发菜单栏**，如下所示：

![在 Safari 桌面上进行测试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_03.jpg)

现在点击当前页面的显示菜单，选择**开发** | **用户代理** | **移动 Safari 3.1.3 - iPhone：**

![在 Safari 桌面上进行测试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_04.jpg)

### 模拟器/仿真器的社区集合列表

如果您真的没有手机在手边，可以找到一份可用的模拟器和仿真器列表。您可以在 Mobile Boilerplate 项目的 wiki 上找到这个列表：

[`github.com/h5bp/mobile-boilerplate/wiki/Mobile-Emulators-&-Simulators`](http://github.com/h5bp/mobile-boilerplate/wiki/Mobile-Emulators-&-Simulators)

### Firtman 的仿真器/模拟器收藏清单

*Maximiliano Firtman*，一位移动和 Web 开发者，也是一位作者，他在自己的网站上维护着仿真器的清单：

[`www.mobilexweb.com/emulators`](http://www.mobilexweb.com/emulators)

# 在移动网络上使用 HTML5

目标浏览器：所有

现在我们将为你的移动设备创建一个简单的 HTML5 页面。如果你已经有了对旧版本 HTML 的经验，HTML5 应该很容易理解。如果你以前为桌面创建过网页，那么为移动设备创建一个网页对你来说也不难。

## 准备工作

创建一个新文件`ch01e2.html`。

## 如何做到...

将以下代码保存在文件中：

```html
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
hello to the HTML5 world!
</body>
</html>

```

现在在你的移动浏览器中渲染这个页面，你应该看到文本的渲染效果与预期一样。

## 它是如何工作的...

你可以看到，HTML5 和其他 HTML 页面之间唯一的区别是我们使用的**文档类型定义（DTD）**：`<!doctype html>`。

你可能已经看到了`<meta name="viewport" content="width=device-width, initial-scale=1.0">`的代码，并想知道它的作用。它帮助 Mobile Safari 知道页面与设备一样宽。设置`initial-scale=1`告诉浏览器不要放大或缩小。

## 还有更多...

以下是 HTML5 的一点历史：HTML5 有两个草案版本，一个由 W3C 创建，另一个由 WHATWG 创建。W3C 由一个民主性质的团体管理，但在实践中进展缓慢。WHATWG 由*Ian Hickson*（也在 Google 工作）编辑，以及一群不公开的人组成。由于*Ian*做出了大部分决策，WHATWG 的版本进展更快。

### HTML5 和版本号

你可能会想知道为什么 HTML5 在没有版本号的情况下使用声明如此模糊。有很多理由可以证明这一点：

1.  HTML 的版本支持对浏览器并不重要。重要的是功能支持。换句话说，如果浏览器支持你正在使用的 HTML5 功能，即使你将文档声明为 HTML4，它仍将按预期渲染 HTML5 元素。

1.  更容易输入！

### 移动文档类型

你可能会问，使用 HTML5 DTD`<!doctype html>`是否安全。答案是 DTD 是用于验证的，而不是用于浏览器渲染。你接下来可能会问：怪癖模式呢？`<!doctype html>`是确保浏览器以标准模式渲染所需的最低信息。所以你可以放心使用`<!doctype html>`。

你可能已经注意到我们使用`<!doctype html>`而不是`<!DOCTYPE html>`。原因是 HTML5 不区分大小写，但为了与其他 HTML 标签保持一致，我们将在整本书中使用小写。

### 学习 HTML5 的免费资源

有许多关于基本 HTML5 标签的优秀免费书籍和文章。如果你对 HTML5 不熟悉，可以查看以下内容之一：

+   HTML5 Doctor: [`html5doctor.com/`](http://html5doctor.com/)

+   Dive Into HTML5: [`diveintohtml5.org/`](http://diveintohtml5.org/)

+   HTML5 Rocks: [`www.html5rocks.com/`](http://www.html5rocks.com/)

如果你是那种真的想了解某件事的每一个细节的人，你可以阅读官方的 HTML5 规范。

规范的 W3C 版本在：

[`dev.w3.org/html5/spec/Overview.html`](http://dev.w3.org/html5/spec/Overview.html)

HTML Living Standard 的 WHATWG 版本在：

[`www.whatwg.org/specs/web-apps/current-work/multipage/`](http://www.whatwg.org/specs/web-apps/current-work/multipage/)

# 在不同浏览器中渲染 HTML5

目标浏览器：所有

有一些较旧的移动浏览器无法识别 HTML5 元素。问题在于，如果这些元素无法被识别，就无法对其进行样式设置。有许多 shim 来解决这个问题。其中一个是 Modernizr。

## 准备工作

1.  其中一个不识别 HTML5 元素的移动浏览器是 Windows Mobile。如果您没有 Windows Mobile，您可以简单地使用 IE7 来测试，因为它们都是基于相同的引擎。

1.  从网站下载 Modernizr：[`www.modernizr.com/`](http://www.modernizr.com/)。它是由*Faruk Ateş, Paul Irish*和*Alex Sexton*编写的。

## 如何做...

1.  创建一个 HTML 文件，并将其命名为`ch01e3.html`，然后在文件中输入以下代码：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
header, footer {display:block;}
</style>
</head>
<body>
<header>
Main Navigation here
</header>
body content here
<footer>
Footer links here
</footer>
</body>
</html>

```

1.  现在创建另一个包含 Modernizr 的页面，并将其命名为`ch01e4.html:`

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/modernizr-1.7.min.js"></script>
<style>
header, footer {display:block;}
</style>
</head>
<body>
<header>
Main Navigation here
</header>
body content here
<footer>
Footer links here
</footer>
</body>
</html>

```

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_05.jpg)

### 它是如何工作的...

记住，如果您在项目中使用 Modernizr，您应该始终在文件的头部在`<head>`标签的末尾之前包含它。还有其他用于类似目的的 polyfill，并且其中一些列在以下部分。

### 还有更多...

Modernizr 并不是唯一的脚本库助手；还有另外两个值得注意的：

+   **html5shim**由*Remy Sharp, Jonathan Neal & community*编写，可用于打印，以及在：

[`code.google.com/p/html5shim/`](http://code.google.com/p/html5shim/)

+   **innerShiv**由*Joe Bartlett*编写，可用于 innerHTML 使用：

[`jdbartlett.github.com/innershiv/`](http://jdbartlett.github.com/innershiv/)

#### HTML5 CSS 重置

您可能希望在样式表中重置一组新的 CSS HTML5 元素：

```html
article, aside, canvas, details, figcaption, figure,footer, header,
hgroup, menu, nav, section, summary,time, mark, audio, video {
margin: 0;
padding: 0;
border: 0;
font-size: 100%;
font: inherit; vertical-align: baseline;
}

```

#### 在较旧的 IE 中启用块级 HTML5 元素

在您的 CSS 中，您可能希望在 CSS 重置中包含一组块级 HTML5 元素。请注意，并非所有 HTML5 元素都必须显示为块级元素。

以下是一组块级 HTML5 元素的列表：

```html
article, aside, details, figcaption, figure,footer, header, hgroup, menu, nav, section {
display: block;
}

```

#### Modernizr

Modernizr 不仅可以使 HTML5 元素在 CSS 中可样式化。它还有助于检测浏览器中用于呈现的 HTML5 功能支持。在 2.0 版本中，您将有选择自定义下载[`www.modernizr.com/download/`](http://www.modernizr.com/download/)的选项。

# 为移动设备设计

目标浏览器：所有

对于桌面设计，人们倾向于使用固定布局或流式布局。在移动设备上，几乎总是应该使用流式布局。流式布局可以使您的网站对浏览器调整大小做出响应。

## 准备工作

现在在您的文本编辑器中创建两个空的 HTML 文件，一个命名为`ch01r06_a.html`，另一个命名为`ch01r06_b.html`。

## 如何做...

1.  在`ch01r06_a.html`中，输入以下代码并保存文件：

```html
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<script src="img/modernizr-1.7.min.js"></script>
<style>
body, #main ul, #main li, h1 {
margin:0; padding:0;
}
body {
background:#FFFFA6;
}
#container {
font-family:Arial;
width:300px;
margin:0 auto;
}
header, footer {
display:block;
}
#main li{
list-style:none;
height:40px;
background:#29D9C2;
margin-bottom:0.5em;
line-height:40px;
-moz-border-radius: 15px;
-webkit-border-radius: 15px;
border-radius: 15px;
}
#main li a {
color:white;
text-decoration:none;
margin-left:1em;
}
</style>
</head>
<body>
<div id="container">
<header>
<h1>Title here</h1>
</header>
<nav id="main">
<ul>
<li><a href="#">Home</a></li>
<li><a href="#">Contact Us</a></li>
<li><a href="#">Location</a></li>
<li><a href="#">Product</a></li>
<li><a href="#">About</a></li>
</ul>
</nav>
<footer>
Footer links here
</footer>
</div>
</body>
</html>

```

1.  在`ch01r06_b.html`中，输入以下代码并保存文档：

```html
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<script src="img/modernizr-1.7.min.js"></script>
<style>
body, #main ul, #main li, h1 {
margin:0;
padding:0;
}
body {
background:#FFFFA6;
}
#container {
font-family:Arial;
margin:0 10px;
}
header, footer {
display:block;
}
#main li{
list-style:none;
height:40px;
background:#29D9C2;
margin-bottom:0.5em;
line-height:40px;
-moz-border-radius: 15px;
-webkit-border-radius: 15px;
border-radius: 15px;
}
#main li a {
color:white;
text-decoration:none;
margin-left:1em;
}
</style>
</head>
<body>
<div id="container">
<header>
<h1>Title here</h1>
</header>
<nav id="main">
<ul>
<li><a href="#">Home</a></li>
<li><a href="#">Contact Us</a></li>
<li><a href="#">Location</a></li>
<li><a href="#">Product</a></li>
<li><a href="#">About</a></li>
</ul>
</nav>
<footer>
Footer links here
</footer>
</div>
</body>
</html>

```

### 它是如何工作的...

当您在纵向模式下查看这两个网站时，它们看起来几乎一样：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_13.jpg)

现在尝试旋转您的屏幕，看看会发生什么。

正如您现在所看到的，在横向模式下，第一个例子在左右两侧有空白，而第二个例子覆盖了屏幕的大部分空间：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_09.jpg)

第二个例子显示了不同的结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_10.jpg)

这个网站页面在固定布局中看起来非常尴尬，但在流式布局中看起来正常。因此，当您为移动设备设计时，始终记住您的网站应该具有这种灵活性。原因是：

+   移动设备既有纵向模式又有横向模式

+   移动设备的空间非常有限，因此您应该利用屏幕上的每个像素

### 还有更多...

CSS 媒体查询也是响应式设计的重要组成部分。它帮助您灵活设计移动设备。

```html
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<script src="img/modernizr-1.7.min.js"></script>
<style>
body {
margin:0;
padding:0;
background:#FFFFA6;
}
#main section {
display:block;
border:5px solid #29D9C2;
width:60%;
height:120px;
margin:5% auto;
}
@media screen and (min-width: 480px) {
#main {
width:90%;
margin:0 auto;
}
#main > section:first-child {
margin-right:5%;
}
#main section {
float:left;
width:45%;
}
}
</style>
</head>
<body>
<div id="container">
<div id="main">
<section id="top-news"></section>
<section id="sports"></section>
</div>
</div>
</body>
</html>

```

在较窄的屏幕上呈现时，这两个部分将垂直布局，而在较宽的屏幕上呈现时，这两个部分将水平布局。我们用来实现这一点的技术是使用 CSS 媒体查询。就像在这个例子中，我们使用了`@media screen and (min-width: 480px) {..}`，所以它的意思是页面在最小宽度为`480px`的页面上呈现时，其中的样式将被应用：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_11.jpg)

现在让我们在方向模式下看一下，如下所示。这两个框现在是相邻的。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_12.jpg)

#### 首先桌面站点

除了构建纯粹的移动端或桌面端网站的想法，还有其他方式。其中之一是首先构建桌面站点，然后使其在移动端上优雅地降级。

#### 首先移动端站点

另一种方法是首先构建移动端，然后使其在桌面上优雅地呈现。

其中一种方法在 CSS 中使用以下内容：

```html
@media only screen and (min-width: 320px) {
/* Styles */
}
@media only screen and (min-width: 640px) {
/* Styles */
}
@media only screen and (min-width: 800px) {
/* Styles */
}
@media only screen and (min-width: 1024px) {
/* Styles */
}

```

#### 一个网站的方法

第三种方法是拥有一个“一个网站”版本，而不是专注于移动端或桌面端，而是同时专注于两者。

# 定义内容策略

目标浏览器：全部

使用分析工具收集的数据，您可以制定您想要构建的策略。如果您已经有了网站的桌面版本，这将特别有用。

## 准备就绪

确保您的网站上已经嵌入了 JavaScript。

## 如何做...

1.  转到您的分析工具，然后点击左侧导航下的**访客** | **移动设备**：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_06.jpg)

1.  现在，如果您点击**移动设备**，您可以看到人们用来浏览您网站的最常用设备：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_07.jpg)

## 它是如何工作的...

Google Analytics 可以帮助您找出访问您网站的最常用的移动设备，并找出您网站最受欢迎的部分。

## 还有更多...

您还可以确定您的移动站点上最有用的页面是什么。人们对待移动浏览与桌面浏览不同。例如，如果您经营一家销售产品的本地商店，大多数人倾向于在移动设备上浏览**联系我们、位置**和**服务**等页面。相反，在桌面上，人们倾向于搜索**产品目录、关于**和**产品描述**。Google Analytics 可以帮助您找出您网站上访问量最高的部分/页面。除了 Google Analytics，您还可以使用 PercentMobile，就像我们之前看到的那样。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_01_08.jpg)

### 浏览器等级

使用分析服务是决定要支持哪些设备的一种方式。另一种方式是使用浏览器等级来了解您应该针对哪个类别。jQuery Mobile 在[`jquerymobile.com/gbs/.`](http://jquerymobile.com/gbs/.)上有一个出色的网格支持图表。还有一个关于移动浏览器 Web 开发的整体策略的 jQuery Mobile 幻灯片，网址是[`www.slideshare.net/jeresig/testing-mobile-javascript`](http://www.slideshare.net/jeresig/testing-mobile-javascript)。

### 移动矩阵

我一直在与*Jonathan Neal*和许多其他人合作，共同制定智能手机前端矩阵。您可以查看：

[`github.com/h5bp/mobile-boilerplate/wiki/Mobile-Matrices`](http://github.com/h5bp/mobile-boilerplate/wiki/Mobile-Matrices)

它包含了市场上大多数智能手机的信息，它们的屏幕尺寸、DPI 和操作系统。


# 第二章：移动设置和优化

在本章中，我们将涵盖：

+   添加主屏幕按钮图标

+   防止文本调整大小

+   优化视口宽度

+   修复移动 Safari 屏幕缩放

+   从浏览器启动特定于手机的程序

+   启用 iPhone 全屏模式的开始屏幕

+   防止 iOS 在焦点上缩放

+   禁用或限制 WebKit 功能

# 介绍

虽然有许多操作系统（OS）以及设备制造商，但不可避免地可能会出现跨浏览器问题，这会给我们带来很多头疼。但另一方面，我们开发人员喜欢挑战，并着手解决这些问题！

在本章中，我们首先将关注跨浏览器/特定于浏览器的设置和优化，然后继续查看您可能希望在移动开发开始时添加的一些通用/特定于浏览器的功能。

# 添加主屏幕按钮图标

目标设备：iOS、Android、Symbian

在现代智能手机上，屏幕大多是触摸式的。iPhone 通过使设备上的一切都成为“应用程序”而改变了我们对移动设备的看法；即使是短信和电话拨号也像带有主屏幕图标的应用程序一样。对于 HTML 网络应用程序，情况有所不同；用户必须首先进入浏览器应用程序，输入地址，然后启动您的网站。从用户的角度来看，这可能是太麻烦了，因此在某些智能手机上，用户可以将主屏幕图标添加到特定的网络应用程序，以便他们可以直接从主屏幕上的图标启动该特定的网络应用程序网站。

听起来很酷，对吧？是的，但它也存在一些问题。当涉及到触摸图标时，并非所有浏览器的行为都是相同的。在这个教程中，我们将研究每个浏览器的行为以及如何使主屏幕图标尽可能地适用于尽可能多的移动浏览器。

## 准备就绪

首先，您必须从章节代码文件夹中下载图标集。如果您打开文件夹，您应该能够看到以下内容：

```html
apple-touch-icon.png
apple-touch-icon-57x57-precomposed.png
apple-touch-icon-72x72-precomposed.png
apple-touch-icon-114x114-precomposed.png
apple-touch-icon-precomposed.png

```

这些图像将用于不同的设备。

创建一个 HTML 文档，并将其命名为`ch02r01.html`。

## 如何做...

在您的 HTML 文档中，使用以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="http://icons/apple-touch-icon-114x114-precomposed.png">
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="http://icons/apple-touch-icon-72x72-precomposed.png">
<link rel="apple-touch-icon-precomposed" href="http://icons/apple-touch-icon-precomposed.png">
<link rel="shortcut icon" href="http://icons/apple-touch-icon.png">
</head>
<body>
</body>
</html>

```

## 它是如何工作的...

现在让我们来分解代码：

从 iOS 4.2.1 开始，可以使用`sizes`属性为不同的设备分辨率指定多个图标。

```html
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="http://apple-touch-icon-114x114-precomposed.png">

```

对于 iPhone 4 的高分辨率 retina 显示屏，使用 114 x 114 的图标。

```html
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="http://apple-touch-icon-72x72-precomposed.png">

```

对于 iPad，可以使用 72 x 72 的图标。对于非 retina iPhone、Android 2.1+设备，使用 57 x 57 的低分辨率图标。

```html
<link rel="apple-touch-icon-precomposed" href="http://apple-touch-icon-precomposed.png">

```

对于诺基亚 Symbian 60 设备，使用`shortcut icon`在链接关系中告诉设备有关快捷图标的信息。

```html
<link rel="shortcut icon" href="img/l/apple-touch-icon.png">

```

这是 Android 上书签的样子：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_1a.jpg)

## 还有更多...

在看到上一个例子后，您的脑海中一定有一些问题：

+   在`rel`属性中定义多个值不是可能的吗？那么我们能否将最后两行合并成以下内容？

```html
<link rel="shortcut icon apple-touch-icon-precomposed" href="http://apple-touch-icon-precomposed.png">

```

已经测试过，但不知何故移动浏览器无法识别该值。

您可能已经看到人们使用：

```html
<link rel="apple-touch-icon-precomposed" media="screen and (min-resolution: 150dpi)" href="http://apple-touch-icon-114x114-precomposed.png">

```

与*Paul Irish*和*Divya Manian*一起，我们一直在致力于 Mobile Boilerplate ([`www.h5bp.com/mobile`](http://www.h5bp.com/mobile))，为前端移动开发提供了一个坚实的默认设置。在 Mobile Boilerplate 中，我们已经涵盖了所有当前的情景和可能的未来情景：

[`github.com/h5bp/mobile-boilerplate/blob/master/index.html#L21`](http://github.com/h5bp/mobile-boilerplate/blob/master/index.html#L21)

### Everything you always wanted to know about touch icons

这个主题上提出的大多数想法都源自*Mathias Bynens*。他的原始文章*Everything you always wanted to know about touch icons*可以在以下网址找到：[`mathiasbynens.be/notes/touch-icons`](http://mathiasbynens.be/notes/touch-icons)。

### 关于苹果触摸图标的官方文档

有一个官方文档列表，您可以在其中找到有关每个特定设备和浏览器的触摸图标的更多信息：

+   苹果触摸图标：

```html
http://developer.apple.com/library/safari/#documentation/AppleApplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html

```

+   来自 WHATWG 的官方信息：

```html
http://www.whatwg.org/specs/web-apps/current-work/multipage/links.html#rel-icon

```

#### 苹果自定义图标和图像创建指南

关于如何创建触摸图标的指南和文章可以在以下文章中找到：

+   苹果 - *自定义图标和图像创建指南：*

```html
http://developer.apple.com/library/ios/#documentation/userexperience/conceptual/mobilehig/IconsImages/IconsImages.html#//apple_ref/doc/uid/TP40006556-CH14-SW11

```

#### 另请参阅

*在 iPhone 上启用全屏模式的开始屏幕* - 在这个示例中，我们将看到如何在从主屏幕触摸图标启动时添加全屏模式的开始屏幕。

# 防止文本调整大小

目标设备：iOS，Windows Mobile

在像 iPhone 和 Windows Mobile 这样的某些移动设备上，当您将设备从纵向模式旋转到横向模式时，浏览器文本可能会调整大小。这可能会对网页开发人员造成问题，因为我们希望完全控制网站的设计和呈现。

## 准备就绪

创建一个新的 HTML 文件，并将其命名为`ch02r02.html`。输入以下代码：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
<style>
figure, figcaption, header {
display:block;
margin:0 auto;
text-align:center;
}
</style>
</head>
<body>
<header>
HTML5 Logo
</header>
<figure>
<img src="img/HTML5_Badge_128.png" alt="HTML5 Badge" />
<figcaption>
It stands strong and true, resilient and universal as the markup you write.
It shines as bright and as bold as the forward-thinking, dedicated web developers you are.
It's the standard's standard, a pennant for progress.
And it certainly doesn't use tables for layout.
</figcaption>
</figure>
</body>
</html>

```

现在在 iPhone 上以纵向模式呈现此页面，如您所见，它将正常呈现如下：

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_1b.jpg)

现在，如果您将其呈现为横向模式，字体大小将突然增加。正如我们所看到的，当页面更改为横向模式时，文本将被调整大小。这不是期望的行为。以下显示了它的外观：

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_02.jpg)

## 如何做...

您可以按照以下步骤来解决这个问题：

1.  您可以将以下行添加到 CSS 中，然后再次以横向方式呈现页面：

```html
html {
-webkit-text-size-adjust: none;
}

```

1.  如您所见，文本现在看起来正常：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_03.jpg)

## 它是如何工作的...

要解决这个问题，您必须在 WebKit 中添加一个名为`text-size-adjust`的 CSS 属性，并将值分配为`none`以防止自动调整。

将`text-size-adjust`设置为 none 可以解决移动特定网站的问题，但如果我们在桌面屏幕或其他非移动浏览器上呈现此内容，桌面浏览器的文本缩放功能将被禁用。为了防止这种无障碍问题，我们可以将`text-size-adjust`设置为`100%`，而不是`none`。

因此，我们可以调整此示例以：

```html
html {
-webkit-text-size-adjust: 100%;
}

```

## 还有更多...

除了 iPhone 之外，其他设备也有添加文本大小调整属性的方法。

### Windows Mobile

Windows Mobile IE 使用不同的前缀。他们最初添加了 WebKit 前缀。其目的是添加对 WebKit 特定属性的支持，以使网页开发人员的生活变得更加轻松，而不必在页面中添加另一个供应商前缀的 CSS 属性来控制文本的缩放方式。更具体地说，他们直觉到这个属性的最常见用例是将其明确设置为`none`，以告诉浏览器不要缩放文本的特定部分。

在听取社区对这个问题的反馈后（以及在意识到实施其他浏览器供应商的 CSS 属性的更广泛影响时摔了几个跤），他们决定最好只实现`-ms-`前缀版本，而不是`-webkit-`版本。

因此，为了使前面的示例更完整，您可以添加：

```html
html {
-webkit-text-size-adjust: 100%;
-ms-text-size-adjust: 100%;
}

```

### 使其具有未来的保障

为了使事情更具未来性，您可以添加一行没有任何前缀的内容，如下所示：

```html
html {
-webkit-text-size-adjust: 100%;
-ms-text-size-adjust: 100%;
text-size-adjust: 100%;
}

```

### px em，哪个更好？

关于在移动设备上使用 px 与 em 的常见争论在移动设备上不再是一个问题。最初，Yahoo!用户界面使用 ems 的原因是 IE6 不支持像素的页面缩放。在移动设备上，没有这样的问题，即使我们希望页面在桌面浏览器上呈现良好，使用 IE6 的可能性也越来越低，因此在大多数情况下，您可以避免使用 ems 和所有计算的麻烦，而选择使用像素。

# 优化视口宽度

目标设备：跨浏览器

不同的移动设备有不同的默认移动视口宽度。请参考附录 X，了解所有移动设备的默认视口宽度列表。如果你将其保持未设置，在大多数情况下，会导致意外的结果。例如，在 iPhone 上，如果视口宽度保持未设置，它将被渲染为 980 像素。

## 准备就绪

让我们创建一个 HTML 文档并将其命名为`ch02r03.html`。

## 如何做...

以下是我们可以优化视口宽度的方法：

1.  将以下代码添加到`ch02r03.html`并在你的移动浏览器中渲染它：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
</head>
<body>
<header>
HTML5 Logo
</header>
<div id="main">
<h1>Lorem ipsum</h1>
Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
</div>
</body>
</html>

```

这是默认的渲染方式：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_04.jpg)

1.  如果我们渲染这个例子，我们会发现一切都变得非常小。现在，让我们将视口宽度设置为设备宽度：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
</head>
<body>
<header>
HTML5 Logo
</header>
<div id="main">
<h1>Lorem ipsum</h1>
<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
</div>
viewport widthviewport widthoptimizing</body>
</html>

```

现在内容宽度使用屏幕宽度，文本变得可读：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_05.jpg)

## 它是如何工作的...

当我们将视口宽度设置为设备宽度时，它会告诉浏览器不要缩放页面以适应设备区域。因此，对于 iPhone，`device-width`在纵向模式下是 320 像素，在横向模式下是 480 像素。

## 还有更多...

对于一些非常老旧的移动浏览器，`meta`属性是不被识别的。为了处理这些浏览器，你需要使用：

```html
<meta name="HandheldFriendly" content="true">

```

这被旧版本的 Palm OS、AvantGo 和 Blackberry 使用。

```html
<meta name="MobileOptimized" content="320">

```

对于 Microsoft PocketPC，引入了一个`MobileOptimized`属性。

因此，最完整的代码应该是：

```html
<meta name="HandheldFriendly" content="true">
<meta name="MobileOptimized" content="320">
<meta name="viewport" content="width=device-width">

```

### IE for Windows Phone 视口博客文章

在 IE for Windows Phone 团队博客上，有一篇关于*IE Mobile Viewport on Windows Phone 7*的文章。在其中，作者解释了 Windows Phone 7 如何实现“device-width”，以及其他很有用的一般信息。你可以在这里阅读这篇文章：[`blogs.msdn.com/b/iemobile/archive/2010/11/22/the-ie-mobile-viewport-on-windows-phone-7.aspx`](http://blogs.msdn.com/b/iemobile/archive/2010/11/22/the-ie-mobile-viewport-on-windows-phone-7.aspx)。

### Safari 文档

Safari 在开发者文库中有一个参考：[`developer.apple.com/library/safari/#documentation/appleapplications/reference/SafariHTMLRef/Articles/MetaTags.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/reference/SafariHTMLRef/Articles/MetaTags.html)。

### 黑莓文档

有一个黑莓浏览器内容设计指南文档。它解释了黑莓对视口宽度的使用：[`docs.blackberry.com/en/developers/deliverables/4305/BlackBerry_Browser-4.6.0-US.pdf`](http://docs.blackberry.com/en/developers/deliverables/4305/BlackBerry_Browser-4.6.0-US.pdf)。

# 修复移动 Safari 屏幕重新流动比例

目标设备：iOS

移动 Safari 有一个恼人的屏幕重新流动 bug：当你将移动浏览器从纵向模式旋转到横向模式时，文本会突然跳到更大的尺寸。

在我致力于构建 Mobile Boilerplate 的时候，*Jeremy Keith*和我就这个问题进行了长时间的讨论。

修复这个问题的传统方法是向`meta`视口添加以下缩放属性：

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">

```

这个解决方案首先被纳入了 Mobile Boilerplate。*Jeremy*指出这解决了比例跳跃的问题，但同时也导致了另一个可访问性问题：当你设置如上所示的值时，你就不能再放大页面了。对于视力有问题的人来说，放大页面的能力是至关重要的。但如果我们让缩放发生，文本跳跃将会让大多数用户感到恼火。因此，很长一段时间里，这是一个可访问性与可用性的辩论。

我发现了一种可以解决这个问题的方法，我们将在下面讨论。

## 准备就绪

首先，让我们创建一个 HTML 文档并将其命名为`ch02r04.html`，在其中输入以下代码：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<div>
<h1>Lorem ipsum</h1>
<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
</div>
</body>
</html>

```

这个页面在纵向模式下渲染得非常好：

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_06.jpg)

但在横向模式下显示时，情况就不同了：

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_07.jpg)

## 如何做...

我们需要做的就是在用户放大页面时动态重置比例因子为默认值。现在将以下代码放入 HTML 文档中：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<div>
<h1>Lorem ipsum</h1>
<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
</div>
<script>
var metas = document.getElementsByTagName('meta');
var i;
if (navigator.userAgent.match(/iPhone/i)) {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=1.0, maximum-scale=1.0";
}
}
document.addEventListener("gesturestart", gestureStart, false);
}
function gestureStart() {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=0.25, maximum-scale=1.6";
}
}
}
</script>
</body>
</html>

```

现在，如果我们将屏幕从纵向旋转到横向，问题应该不复存在，如果我们放大页面，它将如预期般反应：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_08.jpg)

## 它是如何工作的...

让我们来看看代码是如何工作的。

1.  我们需要知道默认的最小比例和最大比例值。在 iPhone 的官方文档中，它指出最小比例值为 0.25，最大比例值为 1.6。因此，为了替换默认值，我们需要设置：

```html
function gestureStart() {
var metas = document.getElementsByTagName('meta');
var i;
for (i=0; i if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum- scale=0.25, maximum-scale=1.6";
}
}

```

1.  接下来，我们需要知道何时设置这个。这很容易：iPhone 有一个手势事件监听器，我们可以用来定位文档主体。以下是如何做到这一点：

```html
document.addEventListener("gesturestart", gestureStart, false);

```

1.  最后，我们需要确保这仅发生在 iPhone 上。同样，这可以很容易地通过以下方式完成：

```html
if (navigator.userAgent.match(/iPhone/i)) {
document.addEventListener("gesturestart", gestureStart, false);
}

```

### 还有更多...

如果您对 Jeremy 和我的整个故事和讨论感兴趣，您可以在[`www.blog.highub.com/mobile-2/a-fix-for-iphone-viewport-scale-bug/`](http://www.blog.highub.com/mobile-2/a-fix-for-iphone-viewport-scale-bug/)阅读。

尽管这为问题提供了一个解决方案，但一些人会遇到一些问题：

+   一旦用户在文档上做出手势，缩放就会再次启用。因此，如果在那之后更改设备方向，缩放错误仍然会发生。

+   在 iOS4 上报告说，用户只能在开始第二个手势后有效地开始缩放。

#### 稍微改进的版本

*Mathias Bynens*有一个智能编码的修订版本。您可以在这里看到代码

[`gist.github.com/901295`](http://gist.github.com/901295)。

#### 一个更好的版本

*John-David Dalton*有一个更新更好的版本，代码更智能更精简

[`gist.github.com/903131`](http://gist.github.com/903131)。

#### 给 jQuery Mobile 的一句话

*Scott Jehl*来自 jQuery Mobile 提到它可能会在将来的 jQuery Mobile 中实现。目前，您可以在[`gist.github.com/1183357`](http://gist.github.com/1183357)看到他的要点。

# 从浏览器启动特定于手机的程序

目标设备：跨浏览器

可以从移动浏览器启动特定于手机的程序，例如地图、呼叫和短信可以从某些移动设备启动。程序是否可以启动取决于特定设备上本机应用程序的可用性。

## 准备好了

创建一个 HTML 文档，并将其命名为`ch02r05.html.`

## 如何做...

以下是我们如何启动特定于手机的程序：

1.  让我们将以下代码添加到 HTML 文档中：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
HTML5 Logo
</header>
<div>
<h1>Lorem ipsum</h1>
<a href="http://maps.google.com/maps?q=cupertino"> Directions</a>
</div>
</body>
</html>

```

1.  现在在 Palm OS 浏览器中运行此代码，点击地址链接。您将被提示在手机上启动地图应用程序：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_09.jpg)

## 它是如何工作的...

与一些方案不同，地图 URL 不以“maps”方案标识符开头。相反，地图链接被指定为常规 HTTP 链接，但是针对 Google 地图服务器。设备浏览器将能够判断它是否是地图，并使用解析的信息启动程序。

## 还有更多...

您可以做的不仅仅是启动一个应用程序。以下示例显示了您将用于在旧金山和库比蒂诺之间提供驾驶路线的字符串：

```html
<a href="http://maps.google.com/maps?daddr=San+Francisco,+CA&saddr=cupertino">Directions</a>

```

那么，如果浏览器无法启动特定的程序怎么办？没关系！在这种情况下，它将像普通链接一样打开：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_02_10.jpg)

### 移动 Safari URL 方案

可以在这里找到所有与 Mobile Safari 相关的 URL 方案列表：[`developer.apple.com/library/safari/#featuredarticles/iPhoneURLScheme_Reference/Introduction/Introduction.html`](http://developer.apple.com/library/safari/#featuredarticles/iPhoneURLScheme_Reference/Introduction/Introduction.html)。

### 黑莓 URL 方案

所有与黑莓相关的 URL 方案列表可以在以下网址找到：[`docs.blackberry.com/en/developers/deliverables/18169/`](http://docs.blackberry.com/en/developers/deliverables/18169/)。

### 索尼爱立信开发者指南

索尼爱立信开发者可以从 Developer World 网站下载*Web 浏览开发者指南*：[`developer.sonyericsson.com/wportal/devworld/search-downloads?cat=%5B1.706817%2C+1.716594%2C+1.716688%5D&cc=gb&lc=en`](http://developer.sonyericsson.com/wportal/devworld/search-downloads?cat=%5B1.706817%2C+1.716594%2C+1.716688%5D&cc=gb&lc=en)。

# 启用 iPhone 全屏模式的启动屏幕

目标设备：iOS

为了使 Web 应用更像本机应用，iPhone 有一些独特的功能供开发者在 Web 应用上添加。您可以在全屏模式下添加启动屏幕，并为应用定义预加载屏幕。

## 准备工作

下载提供的源代码中的图像，创建一个 HTML 文档，并将其命名为`ch02r06.html`。

## 如何做到的...

以下是我们如何使启动屏幕进入全屏模式：

1.  输入以下 HTML 代码：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<link rel="apple-touch-startup-image" href="img/l/splash.png">
</head>
<body>
<header>
HTML5 Logo
</header>
<div>
Lorem ipsum
</div>
</body>
</html>

```

1.  如果您将该页面添加到书签并从应用图标在浏览器中打开，它将显示为全屏应用。

## 它是如何工作的...

让我们来看一下代码：

```html
<meta name="apple-mobile-web-app-capable" content="yes">

```

这使得网页在从主屏幕图标启动时以全屏模式运行，隐藏了浏览器顶部和底部的地址栏和组件栏。

```html
<meta name="apple-mobile-web-app-status-bar-style" content="black">

```

这个代码是为了给浏览器顶部的状态栏添加样式。

```html
<link rel="apple-touch-startup-image" href="img/l/splash.png">

```

您还可以在应用启动时添加一个启动屏幕，这是在页面仍在加载时显示的预加载屏幕。

## 还有更多...

iPad 和 iPhone 有不同的启动屏幕尺寸，所以如果我们希望网站动态更改启动屏幕，这取决于用于渲染的浏览器。我们可以使用以下 JavaScript 函数来实现：

```html
var filename = navigator.platform === 'iPad' ? 'h/' : 'l/'; document.write('<link rel="apple-touch-startup-image" href="/img/' + filename + 'splash.png" />' );

```

### iOS 4.3 的全屏问题

iOS 4.3 引入了一个他们称之为 JavaScript Nitro Engine 的新功能。这段新代码允许默认的 Safari 浏览器加载页面的速度提高了一倍。然而，这个功能似乎不支持全屏 Web 应用。虽然一些人质疑为什么苹果没有将新的 Safari 功能与其 Web 应用整合在一起，但也有人指出证据表明这可能只是一个 bug。

### Safari 关于 Web 应用的文档

官方文档可以在 Safari 上访问以下网站：

[`developer.apple.com/library/safari/#documentation/appleapplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html)

### Safari 启动图像和触摸图标指南

有关启动图像和触摸图标指南，您可以访问官方 Safari 网站上的自定义图标和图像创建指南：

`http://developer.apple.com/library/safari/#documentation/UserExperience/Conceptual/MobileHIG/IconsImages/IconsImages.html#//apple_ref/doc/uid/TP40006556-CH14`

# 防止 iOS 在焦点上缩放

目标设备：iOS

在 JavaScript 事件 API 中，有一个`form onfocus`事件。当您在 iOS 中点击表单元素时，元素将放大显示在设备屏幕上。对于未设计为响应式或移动特定的网站，这种默认缩放可能有所帮助，但对于移动优化的网站来说，这可能没有那么有用，甚至可能很烦人。为了禁用这种默认行为，我们可以更改 meta viewport 值`onfocus`和`onblur`。

## 准备工作

创建一个 HTML 文档，并将其命名为`ch02r06_b.html`。

## 如何做到的...

以下是我们如何启动一个特定于手机的程序：

1.  让我们将以下代码添加到 HTML 文档中：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<form>
<label>First name:</label> <input type="text" name="fname" /><br />
<label>Last name:</label> <input type="text" name="lname" />
</form>
<script>
var $viewportMeta = $('meta[name="viewport"]');
$('input, select, textarea').bind('focus blur', function(event) {
$viewportMeta.attr('content', 'width=device-width,initial-scale=1,maximum-scale=' + (event.type == 'blur' ? 10 : 1));
});
</script>
</body>
</html>

```

1.  现在，在 iOS 设备中渲染页面，触摸聚焦表单输入字段，您会发现现在输入字段不会放大。

## 它是如何工作的...

现在让我们提取出 JavaScript 部分：

```html
<script>
var $viewportMeta = $('meta[name="viewport"]');
$('input, select, textarea').bind('focus blur', function(event) {
$viewportMeta.attr('content', 'width=device-width,initial-scale=1,maximum-scale=' + (event.type == 'blur' ? 10 : 1));
});
</script>

```

脚本的作用是检测到`onfocus`事件时，我们将最大缩放比例设置为 1，当检测到`onblur`时，我们将其设置为 10。

## 还有更多...

您可以阅读有关原始博客帖子讨论的更多信息：

[`nerd.vasilis.nl/prevent-ios-from-zooming-onfocus/`](http://nerd.vasilis.nl/prevent-ios-from-zooming-onfocus/)

此代码片段已添加到 Mobile Boilerplate：

[`github.com/h5bp/mobile-boilerplate/blob/master/js/mylibs/helper.js`](http://github.com/h5bp/mobile-boilerplate/blob/master/js/mylibs/helper.js)

# 禁用或限制 WebKit 功能

目标设备：WebKit 移动浏览器（Android，iOS）

移动浏览器中存在许多特定设备的问题。通过一些不太为人知的 CSS 技术，我们可以轻松解决这些问题。让我们看看一些问题以及我们如何神奇地解决它们。

## 准备工作

创建一个 HTML 文档并将其命名为`ch02r07.html`。

## 如何做到...

以下是限制 WebKit 功能的示例：

1.  将以下代码添加到 HTML 文档中：

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="apple-mobile-web-app-capable" content="yes">
<style>
.nocallout {-webkit-touch-callout: none;}
#targetarea {width:200px; height:120px; padding-top:80px; background:#ccc; text-align:center; font-size:20px;}
</style>
</head>
<body>
<div id="targetarea" class="nocallout">
<a href="http://www.google.com" target="_blank">Google</a>
</div>
WebKit featuresWebKit featureslimiting</body>
</html>

```

如何做到...

1.  现在，将附加代码输入到 HTML 文档中，

```html
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="apple-mobile-web-app-capable" content="yes">
<style>
.nocallout {-webkit-touch-callout: none;}
#targetarea {width:200px; height:120px; padding-top:80px; background:#ccc; text-align:center; font-size:20px;}
</style>
WebKit featuresWebKit featureslimiting</head>
<body>
<div id="targetarea" class="nocallout">
<a href="http://www.google.com" target="_blank">Google</a>
</div>
</body>
</html>

```

如何做到...

### 它是如何工作的...

如果不设置`webkit-touch-callout`，当您在设备上点击并按住链接时，将会出现提示，询问您是否要在当前页面中打开它，在新页面中打开它或复制，如第一个示例所示。

如果要禁用此功能，可以通过将`webkit-touch-callout`值设置为`none`来实现，如第二个示例所示。

### 还有更多...

您可能还想限制的另一个功能是复制和粘贴。这个功能在网页上是有意义的，但对于大多数应用程序的界面元素来说是不需要的。

```html
<style type="text/css">
.oncopy {
-webkit-user-select: text;
}
</style>

```

#### 更改点击颜色

您可以使用以下规则更改点击颜色：

```html
<style type="text/css">
* {
-webkit-tap-highlight-color: rgba(0,0,0,0);
}
</style>

```

#### 使文本区域内容可编辑

如果要将元素设置为`contenteditable`，可以使用以下 CSS：

```html
textarea.contenteditable {
-webkit-appearance: none;
}

```

#### 窄屏幕的省略号

在移动浏览器上，屏幕要窄得多，因此在显示菜单标题列表时，可能会发生文本溢出。如果发生这种情况，CSS 技巧可以帮助您使用省略号修复文本溢出：

```html
.ellipsis {
text-overflow: ellipsis;
overflow: hidden;
white-space:
white-space:

```


# 第三章：使用移动事件的交互媒体

在本章中，我们将涵盖：

+   使用触摸事件移动元素

+   检测和处理方向事件

+   使用手势事件旋转 HTML 元素

+   使用滑动事件制作轮播图

+   使用手势事件操作图像缩放

# 介绍

移动和桌面之间最大的区别之一是我们与屏幕交互的方式。在桌面屏幕上，我们使用鼠标移动和点击事件来控制交互。在移动屏幕上，交互来自触摸和手势事件。在本章中，我们将看到一些触摸屏独有的事件（例如，双指事件），以及您如何利用这些功能来为移动构建独特的东西。

# 使用触摸事件移动元素

目标设备：跨浏览器

在移动屏幕上，我们使用触摸事件与元素进行交互。因此，我们可以用手指在屏幕上移动 HTML 元素。

## 准备工作

在这个例子中，我们将使用 jQuery。首先，让我们创建一个新的 HTML 文件，并将其命名为`ch03r01.html`。

## 如何做...

在您的 HTML 文档中，使用以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
#square {
width: 100px;
height: 100px;
background:#ccc;
position:absolute;
}
</style>
</head>
<body>
<div id="main">
<div id="square">
</div>
</div>
<script src="img/jquery-1.5.2.min.js"></script>
<script src="img/jquery. mobile-1.0a4.1.min.js"></script>
<script>
$('#square').bind('touchmove',function(e){
e.preventDefault();
var touch = e.originalEvent.touches[0] || e.originalEvent.changedTouches[0];
var elm = $(this).offset();
var x = touch.pageX - elm.left/2;
var y = touch.pageY - elm.top/2;
$(this).css('left', x+'px');
$(this).css('top', y+'px');
});
</script>
</body>
</html>

```

+   现在让我们看看它在 Opera 中的渲染：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_08.jpg)

## 它是如何工作的...

首先，我们注册一个带有`touchmove`事件的正方形`div`。

您可以检测相对于页面的触摸位置，即在我们的例子中是`touch.pageX`和`touch.pageY`。我们使用手指位置减去正方形`div`元素宽度和高度的一半，这样就感觉像我们是以`div`中心作为注册点移动。

```html
var x = touch.pageX - elm.left/2;
var y = touch.pageY - elm.top/2;

```

我们使用 CSS 位置将 x 和 y 值应用于正方形元素。这就是'移动'动作。

```html
$(this).css('left', x+'px');
$(this).css('top', y+'px');

```

## 还有更多...

您可能已经意识到，在这个例子的顶部，有一行如下：

```html
var touch = e.originalEvent.touches[0] || e.originalEvent.changedTouches[0];

```

现在你可能想知道它是做什么的。移动 Safari 不允许将`e.touches`和`e.changedTouches`属性复制到另一个对象上的事件对象。您可以通过使用`e.originalEvent`来解决这个问题。您可以在这里阅读更多关于它的信息：

[`www.the-xavi.com/articles/trouble-with-touch-events-jquery`](http://www.the-xavi.com/articles/trouble-with-touch-events-jquery)。

### jQuery 移动事件

jQuery 移动是一组组件。如果您想深入了解所有与移动相关的事件，您可以在这里找到它们：

[`github.com/shichuan/jquery-mobile/blob/master/js/jquery.mobile.event.js`](http://github.com/shichuan/jquery-mobile/blob/master/js/jquery.mobile.event.js)。

### Zepto

Zepto 是一个比 jQuery 更轻量级的替代品，如果您的主要目标是基于 WebKit 的浏览器，您可以考虑使用它。您可以在这里了解更多信息：

[`github.com/madrobby/zepto`](http://github.com/madrobby/zepto)。

### Safari 关于移动事件处理的指南

官方参考资料，请访问 Safari 的在线指南：

[`developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html)。

## 另请参阅

+   *使用方向事件重绘画布*

+   *使用手势事件旋转 HTML 元素*

+   *使用滑动事件制作轮播图*

+   *使用手势事件操作图像缩放*

# 检测和处理方向事件

目标设备：跨浏览器

在移动浏览器上，如果您的网站是基于流体布局构建的，它不应受方向变化的影响。但对于一个高度互动的网站，有时您可能希望以特殊的方式处理方向变化。

## 准备工作

创建一个新的 HTML 文件，并将其命名为`ch03r02.html`。

## 如何做...

现在让我们开始创建 HTML 和脚本来检测和处理方向事件。

1.  输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
html, body {
padding: none;
margin: none;
}
</style>
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.0/jquery.mobile-1.0.min.css" />
<script src="img/jquery-1.6.4.min.js"></script>
<script src="img/jquery.mobile-1.0.min.js"></script>
</head>
<body>
<div id="a">
</div>
<script>
var metas = document.getElementsByTagName('meta');
var i;
if (navigator.userAgent.match(/iPhone/i)) {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=1.0, maximum-scale=1.0";
}
}
document.addEventListener("gesturestart", gestureStart, false);
}
function gestureStart() {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=0.25, maximum-scale=1.6";
}
}
}
</script>
<script>
$(window).bind('orientationchange',function(event){
updateOrientation(event.orientation);
})
function updateOrientation(orientation) {
$("#a").html("<p>"+orientation.toUpperCase()+"</p>");
}
</script>
</body>
</html>

```

1.  现在，在您的移动浏览器中渲染此代码，并旋转屏幕以在纵向和横向模式下查看。在纵向模式下，文本输出将是'PORTAIT'。![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_03.jpg)

1.  当我们将屏幕旋转到横向模式时，文本将显示为'LANDSCAPE'。![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_04.jpg)

## 它是如何工作的...

通过监听`window.onorientationchange`事件，我们可以在发生时获取`orientationchange`事件；我们将`event.orientation`传递给函数以输出结果。

## 还有更多...

有时，您可能希望锁定屏幕的方向，比如在构建游戏时。对于原生应用程序来说，这很容易，但对于 Web 应用程序来说，这可能有点难以实现。

让我们创建一个只能锁定在横向模式的单页面屏幕。请注意，这只是一个概念验证，要创建真正复杂的应用程序或游戏需要更多的计算和处理。

创建一个文档，并将其命名为`ch03r02_b.html`，然后输入以下代码

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="css/style.css">
<style>
body {
font-family: 'Kranky', serif;
font-size: 36px;
font-style: normal;
font-weight: 400;
word-spacing: 0em;
line-height: 1.2;
}
html {
background:#F1F2CE;
}
html, body, #screen {
padding:0;
margin:0;
}
#screen {
text-align:center;
-moz-transform:rotate(90deg);
-webkit-transform:rotate(90deg);
-o-transform:rotate(90deg);
-ms-transform:rotate(90deg);
}
#screen div {
padding-top:130px;
}
@media screen and (min-width: 321px){
#screen {
text-align:center;
-moz-transform:rotate(0deg);
-webkit-transform:rotate(0deg);
-o-transform:rotate(0deg);
-ms-transform:rotate(0deg);
}
#screen div {
padding-top:70px;
}
}
</style>
</head>
<body>
<div id="screen">
<div id="loader">enter the game</div>
</div>
<script>
var metas = document.getElementsByTagName('meta');
var i;
if (navigator.userAgent.match(/iPhone/i)) {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=1.0, maximum-scale=1.0";
}
}
document.addEventListener("gesturestart", gestureStart, false);
}
function gestureStart() {
for (i=0; i<metas.length; i++) {
if (metas[i].name == "viewport") {
metas[i].content = "width=device-width, minimum-scale=0.25, maximum-scale=1.6";
}
}
}
window.onorientationchange = function() {
update();
}
function update() {
switch(window.orientation) {
case 0: // Portrait
case 180: // Upside-down Portrait
var cWidth = window.innerWidth;
var cHeight = window.innerHeight;
document.getElementById("screen").style.width = cHeight-36+'px';
document.getElementById("screen").style.height = cWidth+'px';
break;
case -90: // Landscape: turned 90 degrees counter-clockwise
case 90: // Landscape: turned 90 degrees clockwise
var cWidth = window.innerWidth;
var cHeight = window.innerHeight;
document.getElementById("screen").style.width = "100%";
document.getElementById("screen").style.height = "auto";
break;
}
}
update();
</script>
</body>
</html>

```

现在，如果您在浏览器中呈现页面，您将看到以下屏幕。在纵向模式下，它建议用户游戏/应用程序是设计为横向模式查看的：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_05.jpg)

当您将屏幕从纵向旋转到横向时，它看起来很正常：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_06.jpg)

在这个例子中，我们使用 CSS3 的`transform:rotate`将屏幕旋转 90 度，以便在纵向模式下查看：

```html
#screen {
text-align:center;
-moz-transform:rotate(90deg);
-webkit-transform:rotate(90deg);
-o-transform:rotate(90deg);
-ms-transform:rotate(90deg);
}

```

用户所处的模式可以通过`window.orientation`确定。有四个值：-90、0、90、180。当度数为-90 和 90 时，设备处于横向模式。当度数为 0 和 180 时，设备处于纵向模式。

```html
switch(window.orientation) {
case 0: // Portrait
case 180: // Upside-down Portrait
//...
break;
case -90: // Landscape: turned 90 degrees counter-clockwise
case 90: // Landscape: turned 90 degrees clockwise
//...
break;
}

```

通过这种方式，您可以确定屏幕的方向。

### Safari 的原生支持

有关官方参考，请访问 Safari 的在线指南：

[`developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html)。

### Web 与原生

尽管移动 Web 正在迎头赶上，但如果您正在开发高度交互式的应用程序，请始终记住，即使是最慢的原生应用程序的性能也比 HTML 应用程序更快。如果您决定使用 HTML5 构建应用程序，还必须牢记所有的黑客和浏览器不一致性。

## 另请参阅

+   *使用触摸事件移动元素*

+   *使用手势事件旋转 HTML 元素*

+   *使用滑动事件创建旋转木马*

+   *使用手势事件缩放图像*

# 使用手势事件旋转 HTML 元素

目标设备：iOS，Android，Symbian

在移动 Safari 上，当人们用两根手指在屏幕上进行旋转时，你可以检测旋转的角度。因此，我们可以使用手指在屏幕上旋转一个元素！

## 准备工作

让我们创建一个 HTML 文档，并将其命名为`ch03r03.html`。

## 如何做...

1.  将以下代码添加到`ch03r03.html`中，并在您的移动浏览器中呈现它：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<style>
#main {
text-align:center;
}
#someElm {
margin-top:50px;
margin-left:50px;
width: 200px;
height: 200px;
background:#ccc;
position:absolute;
}
</style>
</head>
<body>
<div id="main">
<div id="someElm">
</div>
</div>
<script>
var rotation =0 ;
var node = document.getElementById('someElm');
node.ongesturechange = function(e){
var node = e.target;
//alert(e.rotation);
// scale and rotation are relative values,
// so we wait to change our variables until the gesture ends
node.style.webkitTransform = "rotate(" + ((rotation + e.rotation) % 360) + "deg)";
//alert("rotate(" + ((rotation + e.rotation) % 360) + "deg)");
}
node.ongestureend = function(e){
// Update the values for the next time a gesture happens
rotation = (rotation + e.rotation) % 360;
}
</script>
</body>
</html>

```

1.  现在用两根手指旋转框，你会看到类似这样的东西：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_07.jpg)

## 它是如何工作的...

在这个例子中，当触发`ongesturechange`事件时，我们旋转元素。我们通过以下值获取旋转角度：

```html
e.target.rotation

```

## 还有更多...

您可能已经注意到，我们还监听`ongestureend`事件，因为如果用户之前已经旋转过，此脚本将记住上次旋转的角度，并继续从那里旋转。

### Safari 事件处理

有关官方参考，请访问 Safari 的在线指南：

[`developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/reference/safariwebcontent/HandlingEvents/HandlingEvents.html)。

### CSS3 转换

在这个例子中，我们使用了 CSS3 的转换功能。您可以在 WebKit 的博客上找到有关 WebKit 和 CSS 转换的更多信息：

[`www.webkit.org/blog/130/css-transforms/`](http://www.webkit.org/blog/130/css-transforms/).

### 缩放错误修复的缺点

在这个例子中，我们使用了`maximum-scale=1.0`来防止在使用手势事件时进行缩放。这会导致一些无法访问的缺点，因此只有在构建高度交互式的 Web 应用程序时才使用旋转事件。在构建移动网站时尽量避免使用它。

## 另请参阅

+   *使用触摸事件移动元素*

+   *使用方向事件重绘画布*

+   *使用手势事件旋转 HTML 元素*

+   使用手势事件缩放图像

# 使用滑动事件制作一个旋转木马

移动设备的一个常见功能是滑动。当你在照片库中浏览照片时，你可以向左和向右滑动以从一张图片导航到另一张图片。在 Android 设备上，你可以向下滑动解锁手机。在移动浏览器上，你也可以使用滑动。

## 准备工作

首先，让我们创建一个 HTML 文档并命名为`ch03r04.html`。

## 如何做...

1.  输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
html, body {
padding:0;
margin:10px auto;
}
#checkbox {
border:5px solid #ccc;
width:30px;
height:30px;
}
#wrapper {
width:210px;
height:100px;
position:relative;
overflow:hidden;
margin:0 auto;
}
#inner {
position:absolute;
width:630px;
}
#inner div {
width:200px;
height:100px;
margin:0 5px;
background:#ccc;
float:left;
}
.full-circle {
background-color: #ccc;
height: 10px;
-moz-border-radius:5px;
-webkit-border-radius: 5px;
width: 10px;
float:left;
margin:5px;
}
.cur {
background-color: #555;
}
#btns {
width:60px;
margin:0 auto;
}
</style>
</head>
<body>
<div id="main">
<div id="wrapper">
<div id="inner">
<div></div>
<div></div>
<div></div>
</div>
</div>
<div id="btns">
<div class="full-circle cur"></div>
<div class="full-circle"></div>
<div class="full-circle"></div>
</div>
</div>
<script src="img/jquery-1.5.2.min.js"></script>
<script src="img/jquery.mobile-1.0a4.1.min.js"></script>
<script>
var curNum = 0;
$('#wrapper').swipeleft(function () {
$('#inner').animate({
left: '-=210'
}, 500, function() {
// Animation complete.
curNum +=1;
$('.full-circle').removeClass('cur');
$('.full-circle').eq(curNum).addClass('cur');
});
});
$('#wrapper').swiperight(function () {
$('#inner').animate({
left: '+=210'
}, 500, function() {
// Animation complete.
curNum -=1;
$('.full-circle').removeClass('cur');
$('.full-circle').eq(curNum).addClass('cur');
});
});
</script>
</body>
</html>

```

1.  一旦你在页面中输入了代码，左右滑动查看区域，你就可以看到盒子在水平滚动：![How to do it...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_01.jpg)

## 它是如何工作的...

我们在这个例子中使用了一些 HTML5 技术。首先，我们使用 jQuery Mobile 来检测滑动事件。当我们用手指向左或向右滑动页面时，会分配一个事件监听器：

```html
$('#wrapper').swipeleft(function () {
});
$('#wrapper').swiperight(function () {
});

```

当检测到滑动事件时，使用 jQuery 动画`.animate()`来创建移动效果：

```html
$('#inner').animate({
left: '+=210'
}, 500, function() {
// Animation complete.
curNum -=1;
$('.full-circle').removeClass('cur');
$('.full-circle').eq(curNum).addClass('cur');
});

```

## 还有更多...

在这个例子中，我们使用了 CSS3 技术来制作圆形按钮。你可以只用纯 CSS3 画出一个完整的圆：

```html
.full-circle {
background-color: #ccc;
height: 10px;
-moz-border-radius:5px;
-webkit-border-radius: 5px;
border-radius: 5px;
width: 10px;
}

```

在这个例子中，我们定义文档的宽度和高度为 10 像素，边框半径为 5 像素。现在你可以用几行 CSS 代码画出一个完美的圆！

### Zepto 框架和滑动事件

你可以使用 Zepto 框架做类似的事情。它有事件，如`swipe, swipeLeft, swipeRight, swipeUp, swipeDown`。

### YUI 和手势事件

YUI 有手势事件，你可以使用它们来创建滑动事件。你可以在这里阅读更多关于这个的信息：支持向左滑动手势：

[`yuiblog.com/sandbox/yui/3.3.0pr3/examples/event/ swipe-gesture.html`](http://yuiblog.com/sandbox/yui/3.3.0pr3/examples/event/)

### 深入源码

jQuery 移动中的事件是以模块化方式构建的。想要了解 jQuery 如何创建滑动事件的人可以访问：

[`github.com/jquery/jquery-mobile/blob/master/js/jquery.mobile.event.js`](http://github.com/jquery/jquery-mobile/blob/master/js/jquery.mobile.event.js)。与滑动事件相关的部分在：

```html
$.event.special.swipe = {...}

```

垂直、水平和距离阈值被用于事件计算。

## 另请参阅

+   *使用触摸事件移动元素*

+   *使用方向事件重绘画布*

+   *使用手势事件旋转 HTML 元素*

+   *使用手势事件缩放图像*

# 使用手势事件缩放图像

在 iPhone 上，你可以根据缩放检测调整元素的大小。在手势改变时，你可以获得缩放因子的值，并根据它来缩放 HTML 元素。

## 准备工作

创建一个 HTML 文档并命名为`ch03r05.html`。

## 如何做...

输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<style>
#frame {
width:100px;
height:100px;
background:#ccc;
}
</style>
</head>
<body>
<div id="main">
<div id="frame"></div>
</div>
<script src="img/jquery-1.5.2.min.js"></script>
<script src="img/jquery.mobile-1.0a4.1.min.js"></script>
<script>
var width = 100, height = 100;
var node = document.getElementById('frame');
node.ongesturechange = function(e){
var node = e.target;
// scale and rotation are relative values,
// so we wait to change our variables until the gesture ends
node.style.width = (width * e.scale) + "px";
node.style.height = (height * e.scale) + "px";
}
node.ongestureend = function(e){
// Update the values for the next time a gesture happens
width *= e.scale;
height *= e.scale;
}
</script>
</body>
</html>

```

## 它是如何工作的...

在这个例子中，我们使用`ongesturechange`事件来分配我们想要缩放的元素。缩放因子由`e.target.scale:`确定。

```html
width *= e.scale;
height *= e.scale;

```

## 还有更多...

手势事件可能很棘手，因此正确使用它们非常重要。对于双指多点触摸手势，事件发生的顺序如下：

1.  `touchstart` 用于第一根手指。当第一根手指触摸表面时发送。

1.  `gesturestart`。当第二根手指触摸表面时发送。

1.  `touchstart` 用于第二根手指。在第二根手指触摸表面后立即发送`gesturestart`。

1.  `gesturechange` 用于当前手势。当两根手指仍然触摸表面时移动时发送。

1.  `gestureend`。当第二根手指从表面抬起时发送。

1.  `touchend` 用于第二根手指。在第二根手指从表面抬起后立即发送`gestureend`。

1.  `touchend` 用于第一根手指。当第一根手指从表面抬起时发送。

### 官方 iOS Safari 手势事件指南

有一个官方的 iPhone Safari 指南，详细解释了 Safari 上的`GestureEvent`类的细节：

[`developer.apple.com/library/safari/#documentation/UserExperience/Reference/GestureEventClassReference/GestureEvent/GestureEvent.html`](http://developer.apple.com/library/safari/#documentation/UserExperience/Reference/GestureEventClassReference/GestureEvent/GestureEvent.html).

### YUI 手势事件

来自 Yahoo!的 YUI 具有跨浏览器的手势事件解决方案，但只支持单指事件。您可以在以下网址找到更多信息：

[`developer.yahoo.com/yui/3/event/#gestures`](http://developer.yahoo.com/yui/3/event/#gestures).

### Google 地图和手势事件

一个依赖于双指手势事件的网站的例子是移动 Safari 上的 Google 地图：

![Google 地图和手势事件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_03_02.jpg)

## 另请参阅

+   *使用触摸事件移动元素*

+   *使用方向事件重绘画布*

+   *使用手势事件旋转 HTML 元素*

+   *制作一个旋转木马*
