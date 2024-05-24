# HTML5 移动开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841`](https://zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：移动调试

在本章中，我们将涵盖：

+   使用 Opera Dragonfly 进行远程调试

+   使用 weinre 进行远程调试

+   在移动设备上使用 Firebug

+   使用 JS 控制台进行远程调试

+   设置移动 Safari 调试

# 介绍

尽管调试可能需要大量时间，但它是网页开发的重要方面，无论是桌面还是移动。在本章中，我们将介绍一些用于使前端调试更容易，更快速，并使网页开发更高效的移动调试工具。

# 使用 Opera Dragonfly 进行远程调试

目标浏览器：Opera Mobile

由于移动屏幕相对较小，移动调试与桌面调试不同。

## 准备工作

1.  确保您连接到 WiFi 网络。

1.  在[`www.opera.com/`](http://www.opera.com/)下载最新版本的 Opera 桌面浏览器。

1.  在您的移动设备上下载 Opera Mobile。

## 如何做...

1.  在撰写本文时，Opera 的版本为 11.50。一些说明可能会在您阅读本书时发生变化。

1.  在您的桌面上打开 Opera，并从下拉菜单中选择**页面** | **开发者工具** | **Opera Dragonfly**。

1.  您应该会看到一个调试工具出现在页面底部。点击**远程调试配置**，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_01.jpg)

1.  一旦我们点击**远程调试配置**按钮，将会出现一个弹出面板。

1.  在面板上，您可以看到一个文本字段来指定端口号和一个**应用**按钮。默认号码应该是未使用的，并且应该可以正常工作。点击**应用：**![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_06.jpg)

1.  现在打开您的桌面控制台并输入`ipconfig`作为命令。IPv4 地址就是您的 IP 地址。

1.  在移动设备上打开 Opera Mobile，输入`opera:debug`在 URL 地址栏中，我们将到达一个如下的页面：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_02.jpg)

1.  输入您从桌面控制台获取的 IP 地址，然后点击**连接**。现在移动浏览器应该连接到 Dragonfly：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_03.jpg)

## 它是如何工作的...

在 Opera Mobile 上打开一个新标签，访问 Yahoo.com，现在切换到桌面，点击**选择调试上下文**，这是右上角的第四个按钮。从下拉菜单中选择**Yahoo!**开始检查页面！

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_04.jpg)

## 另请参阅

+   *使用 weinre 进行远程调试*

+   *使用 JS 控制台进行远程调试*

# 使用 weinre 进行远程调试

目标浏览器：iOS，Android，Blackberry，webOS

在上一个步骤中，我们看到了如何远程调试 Opera 移动页面。在这个步骤中，我们将看到如何在其他移动设备上进行远程调试。**Weinre**是一个**Web Inspector Remote**。

支持的操作系统包括：

+   Android 2.2 浏览器应用

+   Android 2.2 w/PhoneGap 0.9.2iOS 4.2.x

+   移动 Safari 应用

+   BlackBerry v6.x 模拟器

+   webOS 2.x（未指定版本）

## 准备工作

首先，我们必须从官方网站下载 weinre；有两个版本可用，一个是 PC 版，一个是 Mac 版：

[`github.com/phonegap/weinre/archives/master`](http://github.com/phonegap/weinre/archives/master)

## 如何做...

1.  首先，在控制台中运行`ipconfig`获取您的 IP 地址。

1.  创建一个名为`ch07r01.html`的 HTML 文档。将`192.168.1.11`替换为您自己的 IP 地址：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<header>
<h1>Mobile Cookbook</h1>
</header>
<div id="main">
</div>
<script src="img/target-script-min.js"></script>
</body>
</html>

```

1.  首先，找到下载的`weinre.jar`文件。在我的情况下，路径是`C:\xampp\htdocs\dev\weinre.jar`。其次，获取 IP 地址，在我的情况下是`http://192.168.1.11`。

1.  现在打开控制台并输入以下行：

```html
java -jar path/to/weinre.jar -httpPort 8081 -boundHost http://192.168.1.11

```

1.  要测试是否有效，请访问 URL 地址`http://192.168.1.11:8081/`，应该会出现接近以下截图的页面：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_09.jpg)

## 它是如何工作的...

现在使用您的移动设备访问创建的示例页面：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_10.jpg)

现在，回到桌面，点击**调试客户端用户界面**。不要在标签中打开，而是在新窗口中打开。

你应该能够看到类似以下截图的东西：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_08.jpg)

点击**元素**，现在你可以检查元素（如下图所示）：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_07.jpg)

# 在移动设备上使用 Firebug

目标浏览器：跨浏览器

许多人在 Firefox 和 Chrome 上使用 Firebug，但 Firebug Lite 可以在支持 JavaScript 的任何浏览器上使用。在这个教程中，我们将看到如何使用 Firebug 进行调试。

## 准备工作

创建一个 HTML 文档并将其命名为`ch07r02.html`。

## 如何操作...

1.  在 HTML 中输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<div id="main">
</div>
<script type="text/javascript" src="img/firebug-lite.js"></script>
</body>
</html>

```

1.  在移动浏览器中渲染它：![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_11.jpg)

## 它是如何工作的...

Firebug Lite 是 Firebug 的 JavaScript 版本。以下代码将加载托管在 Firebug 网站上的 Firebug Lite 脚本：

```html
<script type="text/javascript" src="img/firebug-lite.js"></script>

```

你也可以下载脚本并将其添加为本地版本。

你可以访问 HTML、CSS 和 JavaScript，并查看 DOM。控制台可用于 JavaScript 输入。

Firebug Lite 有四个发布渠道：

+   **稳定通道**

+   **调试通道**

+   **Beta 通道**

+   **开发者通道**

我们一直在使用的是稳定通道。其他通道在*还有更多*部分下有解释。

## 还有更多...

除了实时和本地版本，你还可以添加书签。它可能无法在所有浏览器上运行。以下是如何操作的。

1.  点击页面右侧的链接：[`getfirebug.com/firebuglite`](http://getfirebug.com/firebuglite)![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_23.jpg)

1.  这将在移动浏览器的 URL 末尾添加哈希`#javascript:(function..`。

1.  在 Safari 上收藏该页面。

1.  编辑书签的名称为书签的名称，Firebug Lite，Firebug Lite 调试或 Firebug Lite beta。

1.  保存书签后，打开书签菜单，选择**Firebug Lite**，然后点击**编辑**。删除 URL 和`#`，只保留以`javascript:(function`开头的部分。

1.  现在，如果你打开任何网页并点击**Firebug Lite 书签**，一个 Firebug 控制台将出现在页面的右下角。

### 调试通道

调试通道使用与稳定通道相同的版本，但具有不同的预配置，使得调试 Firebug Lite 本身变得更容易。

### Beta 通道

Beta 通道是新功能和修复的地方。它应该是相当稳定的（没有已知的回归），但可能会包含一些错误，一些功能可能不完整。

### 开发者通道

开发者通道是创意和测试的地方。一旦它直接绑定到我们的代码存储库，你将获得可能的最新代码，并且将比其他渠道更频繁地接收更新。但需要注意的是，开发者通道有时可能非常不稳定，初始加载可能会较慢。

# 使用 JS 控制台进行远程 JavaScript 调试

目标浏览器：跨浏览器

如果你只是寻找远程 JavaScript 调试，*Remy Sharp*有一个名为 JavaScript 控制台的很棒的工具。它对于移动调试非常有效。

## 准备工作

访问[`jsconsole.com/`](http://jsconsole.com/)，你会看到下面显示的页面：

![准备工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_13.jpg)

## 如何操作...

1.  在网站上输入`:listen`，你应该看到以下信息消息返回：

**创建连接...**

**连接到"65C1F9F1-6A57-46C0-96BB-35C5B515331F"**

1.  接下来将是一行类似于 JavaScript 的代码：

```html
<script src="img/remote.js?65C1F9F1-6A57-46C0-96BB-35C5B515331F"></script>

```

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_14.jpg)

1.  创建一个 HTML 页面并将其命名为`ch07r04.html`。将以下代码输入到文档中，用你从 jsconsole.com 得到的`<script>...</script>`替换：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
>
<div id="main">
</div>
<script src="img/remote.js?04926BFB-44AB-4979-BAE9-F4A4FA7CE22C"></script>
<script>
for (var i=0; i<10; i++) {
console.log('testing '+i);
}
</script>
</body>
</html>

```

1.  现在，如果我们在移动设备上渲染页面，我们会看到桌面屏幕网页上出现日志消息：![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_12.jpg)

## 它是如何工作的...

在以下循环中，我们使用`console.log`输出一串消息：

```html
<script>
for (var i=0; i<10; i++) {
console.log('testing '+i);
}
</script>

```

从您的 Web 应用程序中对`console.log`的任何调用都将在监听您的密钥的 jsconsole 会话中显示结果。同样，如果您在 jsconsole 会话中运行命令，代码将被注入到您的 Web 应用程序中，并将结果返回给 jsconsole。

## 还有更多...

整个 JavaScript 控制台 Web 应用程序是开源的；如果您想了解更多关于它是如何制作的，请访问：[`github.com/remy/jsconsole`](http://github.com/remy/jsconsole)。

### JS 控制台 iOS 应用

JS Console for iOS，也是由*Remy Sharp*制作的，是一个 JavaScript 控制台，用于测试和检查 JavaScript 的结果，而无需在线或在浏览器中。

### 简单的 iOS 模拟器示例

这段由*Remy Sharp*制作的视频展示了如何在 iOS 上使用 jsconsole.com 进行远程调试 JavaScript。它展示了如何接收日志并发送任意命令：

[`www.youtube.com/watch?v=Y219Ziuipvc&feature=player_embedded`](http://www.youtube.com/watch?v=Y219Ziuipvc&feature=player_embedded)

### 在任何设备上远程调试 JavaScript

在以下视频中，*Remy Sharp*录制了如何使用 jsconsole.com 远程调试任何设备上的任何浏览器的操作步骤：

[`www.youtube.com/watch?v=DSH392Gxaho&feature=player_embedded`](http://www.youtube.com/watch?v=DSH392Gxaho&feature=player_embedded)

# 设置移动 Safari 调试

目标浏览器：iOS

在 iOS 移动 Safari 上，有一个用于调试的内置调试器。

## 准备就绪

拿起 iPhone 并导航到主屏幕。

## 如何做...

1.  找到并打开**设置**应用程序：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_20.jpg)

1.  选择**Safari**：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_15.jpg)

1.  向下滚动以找到底部的**开发人员**选项：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_16.jpg)

1.  默认情况下，**调试控制台**是**关闭**的：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_17.jpg)

1.  现在我们可以将**调试控制台**切换到**打开**：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_18.jpg)

1.  在 Safari 中，查找页面顶部 URL 栏下方的调试控制台摘要信息：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_19.jpg)

1.  点击摘要信息以查看页面上的错误的详细报告。

1.  现在，让我们创建一个 HTML 文档并将其命名为`ch07r05.html`。将以下代码输入到页面中：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<div id="main">
</div>
<script>
for (var i=0; i<3; i++) {
console.log('testing '+i);
}
</script>
</body>
</html>

```

1.  在渲染时，我们可以看到：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_21.jpg)

## 它是如何工作的...

一旦点击**调试控制台**，它将带您到消息屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_07_22.jpg)

以下脚本用于创建调试消息：

```html
<script>
for (var i=0; i<3; i++) {
console.log('testing '+i);
}
</script>

```


# 第八章：服务器端调优

在本章中，我们将涵盖：

+   防止移动转码

+   添加移动 MIME 类型

+   使缓存清单正确显示

+   设置远期过期标头

+   Gzip 压缩

+   实体标签移除

# 介绍

服务器端性能直接影响页面加载速度。适当的服务器配置可以极大地提高客户端加载速度。

在本章中，我们将介绍一些用于使移动网站和应用程序性能更好更快的服务器端配置。一些概念是移动中心的；一些也适用于桌面网络。

有许多服务器最佳实践指南，但有些可能不够全面。在本章中，我们将结合最佳实践，看看如何最大化网站的性能。

# 防止移动转码

目标浏览器：跨浏览器

许多移动运营商使用代理或适配引擎来更改您要提供的网页内容。在许多移动设备上，内置或安装的浏览器使用移动转码器来重新格式化和压缩页面内容。这被称为**移动转码**。如果您不希望内容被更改，必须添加 HTTP 头部以防止移动转码。

## 准备工作

`.htaccess`文件用于在文件目录级别配置 Apache 服务器。配置也可以通过编辑`httpd.conf`来完成。因为许多服务器托管公司不允许访问安装了 Apache 的根目录，所以在这个例子中，我们使用`.htaccess`。这使得在目录级别进行服务器配置更容易，因为与主`httpd.conf`不同，它不需要服务器重新启动。创建或打开一个`.htaccess`文件。

## 如何做...

将以下代码添加到`.htaccess`文件中：

```html
<FilesMatch "\.(php|cgi|pl)$">
Header append Cache-Control "no-transform"
Header append Vary "User-Agent, Accept"
</FilesMatch>

```

将`.htaccess`文件上传到要应用规则的文件夹中。

通过这样做，我们已经防止了移动转码的发生。

## 它是如何工作的...

`FilesMatch`用于仅过滤 CGI 和 PHP 脚本，因为我们不希望将此规则应用于其他文件类型。

```html
<FilesMatch "\.(php|cgi|pl)$">

```

假设启用了 Apache 模块`mod_headers`，我们可以在`FilesMatch`部分中添加头部`Cache-Control "no-transform"`。

```html
Header append Cache-Control "no-transform"

```

## 还有更多...

以下资源可能有助于了解更多关于移动转码的信息。

### Microsoft Internet Information Server (IIS)

如果您正在使用**Microsoft Internet Information Server (IIS)**，可以使用软件界面进行配置。有关如何执行此操作的详细信息可以在以下位置找到：

[`mobiforge.com/developing/story/setting-http-headers-advise-transcoding-proxies`](http://mobiforge.com/developing/story/setting-http-headers-advise-transcoding-proxies)

### 负责任的重新格式化

以下文章提供了一些关于网络运营商进行的内容转码的影响的见解：

[`mobiforge.com/developing/blog/responsible-reformatting`](http://mobiforge.com/developing/blog/responsible-reformatting)

### MBP — Mobile Boilerplate

本章中使用的代码片段也包含在 Mobile Boilerplate 中：

[`github.com/h5bp/mobile-boilerplate/blob/master/.htaccess`](http://github.com/h5bp/mobile-boilerplate/blob/master/.htaccess)

# 添加移动 MIME 类型

目标浏览器：黑莓，塞班

黑莓和诺基亚浏览器支持许多移动专属内容类型。在本主题中，我们将看一些这些移动浏览器使用的 MIME 类型。由于服务器可能默认不识别它们，因此在服务器配置中正确添加它们非常重要。

## 准备工作

`.htaccess`文件用于在文件目录级别配置 Apache 服务器。它使得在目录级别进行服务器配置变得容易。创建或打开一个`.htaccess`文件。

## 如何做...

将以下代码添加到`.htaccess`文件中：

```html
AddType application/x-bb-appworld bbaw
AddType text/vnd.rim.location.xloc xloc
AddType text/x-vcard vcf
AddType application/octet-stream sisx
AddType application/vnd.symbian.install sis

```

将`.htaccess`文件上传到要应用规则的文件夹中。

## 它是如何工作的...

我们使用`AddType:`使移动 MIME 类型可识别：

| 代码 | 描述 |
| --- | --- |
| `AddType application/x-bb-appworld bbaw` | 包含在 BlackBerry App World™商店中找到的应用程序的应用程序 ID 的文本文件。 |
| `AddType text/vnd.rim.location.xloc xloc` | BlackBerry 地图位置文档。 |
| `AddType text/x-vcard vcf` | 一个 vCard 文件，一种用于电子名片的标准文件格式。 |
| `AddType application/octet-stream sisx` | 诺基亚类型 |
| `AddType application/vnd.symbian.install sis` | 诺基亚类型 |

## 还有更多...

有关 BlackBerry 支持的更多移动文件类型，请访问：

[`docs.blackberry.com/en/developers/deliverables/18169/index.jsp?name=Feature+and+Technical+Overview+-+BlackBerry+Browser6.0&language=English&userType=21&category=BlackBerry+Browser&subCategory=`](http://docs.blackberry.com/en/developers/deliverables/18169/index.jsp?name=Feature+and+Technical+Overview+-+BlackBerry+Browser6.0&language=English&userType=21&category=BlackBerry+Browser&subCategory=)

# 使缓存清单正确显示

目标浏览器：跨浏览器

如第六章中所解释的，*移动富媒体*，缓存清单用于离线 Web 应用程序。服务器可能无法识别此文件的扩展名。让我们看看如何添加正确的 MIME 类型。

## 准备工作

创建或打开一个`.htaccess`文件。

## 如何做...

添加以下代码：

```html
AddType text/cache-manifest appcache manifest

```

上传`.htaccess`文件到您希望应用规则的文件夹。

## 它是如何工作的...

缓存清单可以使用`.appcache`或`.manifest`作为其扩展名。通过将这两种类型都添加为`text/cache-manifest`，我们确保无论使用哪种类型，它们都可以正确呈现。

### MBP 移动样板

`.htaccess`规则包含在移动样板中：

[`github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L75`](http://github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L75)

# 设置远期过期标头

目标浏览器：跨浏览器

为文件设置远期过期标头可通过减少不必要的 HTTP 请求来提高站点性能。对于需要加载许多资源的富媒体站点，这可以提高整体性能。有不同的文件类型，根据文件的使用，我们选择不同的过期时间。

## 准备工作

创建或打开一个`.htaccess`文件。

## 如何做...

添加以下代码：

```html
<IfModule mod_expires.c>
ExpiresActive on
ExpiresDefault "access plus 1 month"
ExpiresByType text/cache-manifest "access plus 0 seconds"
ExpiresByType text/html "access plus 0 seconds"
ExpiresByType text/xml "access plus 0 seconds"
ExpiresByType application/xml "access plus 0 seconds"
ExpiresByType application/json "access plus 0 seconds"
ExpiresByType application/rss+xml "access plus 1 hour"
ExpiresByType image/x-icon "access plus 1 week"
ExpiresByType image/gif "access plus 1 month"
ExpiresByType image/png "access plus 1 month"
ExpiresByType image/jpg "access plus 1 month"
ExpiresByType image/jpeg "access plus 1 month"
ExpiresByType video/ogg "access plus 1 month"
ExpiresByType audio/ogg "access plus 1 month"
ExpiresByType video/mp4 "access plus 1 month"
ExpiresByType video/webm "access plus 1 month"
ExpiresByType text/x-component "access plus 1 month"
ExpiresByType font/truetype "access plus 1 month"
ExpiresByType font/opentype "access plus 1 month"
ExpiresByType application/x-font-woff "access plus 1 month"
ExpiresByType image/svg+xml "access plus 1 month"
ExpiresByType application/vnd.ms-fontobject "access plus 1 month"
ExpiresByType text/css "access plus 1 year"
ExpiresByType application/javascript "access plus 1 year"
ExpiresByType text/javascript "access plus 1 year"
<IfModule mod_headers.c>
Header append Cache-Control "public"
</IfModule>
</IfModule>

```

上传`.htaccess`文件到您希望应用规则的文件夹。

## 它是如何工作的...

以下是代码的分解，我们将看到它是如何工作的：

1.  白名单过期规则：

```html
ExpiresDefault "access plus 1 month"

```

1.  `cache.appcache`在 FF 3.6 中需要重新请求：

```html
ExpiresByType text/cache-manifest "access plus 0 seconds"

```

1.  您的文档 HTML 不应该被缓存：

```html
ExpiresByType text/html "access plus 0 seconds"

```

1.  数据不应该被缓存，因为它总是需要被拉取的：

```html
ExpiresByType text/xml "access plus 0 seconds"
ExpiresByType application/xml "access plus 0 seconds"
ExpiresByType application/json "access plus 0 seconds"

```

1.  RSS 订阅更新频率低于正常 API 数据：

```html
ExpiresByType application/rss+xml "access plus 1 hour"

```

1.  Favicon 不能被重命名，所以最好的方法是将其设置为一周后：

```html
ExpiresByType image/x-icon "access plus 1 week"

```

1.  对于诸如图像、视频和音频之类的大型媒体资源，我们可以将日期设置得更久远：

```html
ExpiresByType image/gif "access plus 1 month"
...
ExpiresByType video/webm "access plus 1 month"

```

1.  HTC 文件，如果您使用 HTML5 polyfill - CSS3PIE 会很有用：

```html
ExpiresByType text/x-component "access plus 1 month"

```

1.  安全地将 Webfonts 缓存一个月：

```html
ExpiresByType font/truetype "access plus 1 month"
...
ExpiresByType application/vnd.ms-fontobject "access plus 1 month"

```

1.  对于 CSS 和 JavaScript，我们可以将过期日期设置为一年后：

```html
ExpiresByType text/css "access plus 1 year"
ExpiresByType application/javascript "access plus 1 year"
ExpiresByType text/javascript "access plus 1 year"

```

### 还有更多...

这些都是相当远期的过期标头。它们假定您使用缓存破坏查询参数来控制版本：

```html
<script src="img/script_034543.js" ></script>

```

此外，考虑到过时的代理可能会错误缓存：

[`www.stevesouders.com/blog/2008/08/23/revving-filenames-dont-use-querystring/`](http://www.stevesouders.com/blog/2008/08/23/revving-filenames-dont-use-querystring/)

#### 添加一个 Expires 或 Cache-Control 标头

在 Yahoo!开发者网络中，有关过期规则的解释非常好：

[`developer.yahoo.com/performance/rules.html#expires`](http://developer.yahoo.com/performance/rules.html#expires)

#### MBP 移动样板中的规则

这些规则包含在 Mobile Boilerplate 的`.htacess 文件中：`

[`github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L142`](http://github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L142)

# 使用 Gzip 压缩文件

目标浏览器：跨浏览器

前端开发人员在决定如何减少在网络上传输 HTTP 请求和响应所需的时间方面发挥着重要作用。Gzip 压缩可通过减小 HTTP 响应的大小来减少响应时间。

Gzip 可以大大减小响应大小，通常可减小 70%。Gzip 在现代浏览器中得到广泛支持。

大多数服务器默认只压缩某些文件类型，因此最好定义支持广泛的文本文件的规则，包括 HTML、XML 和 JSON。

## 准备工作

创建或打开一个 `.htaccess` 文件。

## 如何做...

将以下代码添加到 `.htaccess` 中：

```html
<IfModule mod_deflate.c>
<IfModule mod_setenvif.c>
<IfModule mod_headers.c>
SetEnvIfNoCase ^(Accept-EncodXng|X-cept-Encoding|X{15}|~{15}|-{15})$ ^((gzip|deflate)\s,?\s(gzip|deflate)?|X{4,13}|~{4,13}|-{4,13})$ HAVE_Accept-Encoding
RequestHeader append Accept-Encoding "gzip,deflate" env=HAVE_Accept-Encoding
</IfModule>
</IfModule>
<IfModule filter_module>
FilterDeclare COMPRESS
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/html
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/css
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/javascript
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/plain
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $text/x-component
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/javascript
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/json
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/x-javascript
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/xhtml+xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/rss+xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/atom+xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/vnd.ms-fontobject
FilterProvider COMPRESS DEFLATE resp=Content-Type $image/svg+xml
FilterProvider COMPRESS DEFLATE resp=Content-Type $application/x-font-ttf
FilterProvider COMPRESS DEFLATE resp=Content-Type $font/opentype
FilterChain COMPRESS
FilterProtocol COMPRESS DEFLATE change=yes;byteranges=no
</IfModule>
<IfModule !mod_filter.c>
AddOutputFilterByType DEFLATE text/html text/plain text/css application/json
AddOutputFilterByType DEFLATE text/javascript application/javascript application/x-javascript
AddOutputFilterByType DEFLATE text/xml application/xml text/x-component
AddOutputFilterByType DEFLATE application/xhtml+xml application/rss+xml application/atom+xml
AddOutputFilterByType DEFLATE image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype
</IfModule>
</IfModule>

```

将 `.htaccess` 文件上传到要应用规则的文件夹中。

## 它是如何工作的...

以下代码强制对损坏的标头进行通缩，以便检测损坏的模式，`mod_setenvif` 用于执行正则表达式匹配并设置一个环境变量，指示损坏的 Accept-Encoding 标头存在：

```html
SetEnvIfNoCase ^(Accept-EncodXng|X-cept-Encoding|X{15}|~{15}|-{15})$ ^((gzip|deflate)\s,?\s(gzip|deflate)?|X{4,13}|~{4,13}|-{4,13})$ HAVE_Accept-Encoding

```

强制请求标头支持压缩很简单：

```html
RequestHeader append Accept-Encoding "gzip,deflate" env=HAVE_Accept-Encoding

```

压缩 HTML、TXT、CSS、JavaScript、JSON、XML、HTC：

```html
<IfModule filter_module>
FilterDeclare COMPRESS
...
FilterProtocol COMPRESS DEFLATE change=yes;byteranges=no
</IfModule>

```

对于 Apache 2.1 之前的旧版本：

```html
<IfModule !mod_filter.c>
AddOutputFilterByType DEFLATE text/html text/plain text/css application/json
AddOutputFilterByType DEFLATE text/javascript application/javascript application/x-javascript
AddOutputFilterByType DEFLATE text/xml application/xml text/x-component
AddOutputFilterByType DEFLATE application/xhtml+xml application/rss+xml application/atom+xml
AddOutputFilterByType DEFLATE image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype
</IfModule>

```

## 还有更多...

需要注意的是，图像和 PDF 文件不需要进行 Gzip 压缩，因为它们已经默认进行了压缩。对它们进行 Gzip 压缩将浪费 CPU 使用率，甚至会增加文件大小。

### 超越 Gzip

*Marcel Duran* 在 Yahoo! Network 上的一篇关于 Gzip 的文章谈到了最近的研究和服务器端方法：

[`developer.yahoo.com/blogs/ydn/posts/2010/12/pushing-beyond-gzipping/`](http://developer.yahoo.com/blogs/ydn/posts/2010/12/pushing-beyond-gzipping/)

# 移除 ETags

目标浏览器：跨浏览器

ETags 代表 **实体标签**。实体是诸如 CSS 或 JavaScript 文件、图像等组件。实体标签的作用是标识组件的特定版本。您可以在 *Yahoo! Developer Network, 高性能网站：规则 13 配置 ETags* ([`developer.yahoo.com/blogs/ydn/posts/2007/07/high_performanc_11/`](http://developer.yahoo.com/blogs/ydn/posts/2007/07/high_performanc_11/)) 中找到更多详细信息。

如果您的网站由多个服务器托管，例如在内容交付网络上，ETag 的验证机制可能会导致额外的重新获取。验证模型中几乎没有优势，所以最佳实践是只需移除 ETag。

## 准备工作

创建或打开一个 `.htaccess` 文件。

## 如何做...

添加以下代码：

```html
<IfModule mod_headers.c>
Header unset Etag
</IfModule>
FileETag None

```

将 `.htaccess` 文件上传到要应用规则的文件夹中。

## 它是如何工作的...

首先，我们取消当前已配置文件的 ETag：

```html
<IfModule mod_headers.c>
Header unset Etag
</IfModule>

```

其次，我们使用 `FileTag None` 来确保文件的 ETag 被移除：

```html
FileETag None

```

## 还有更多...

以下部分提供了有关 ETags 的更多信息供您参考。

### 在 IIS 服务器上同步 ETag 值

如果您正在运行 IIS 服务器，为了解决问题，您必须同步运行 IIS 5.0 的所有 Web 服务器上的 ETag 值。为此，请使用 `Mdutil.exe` 工具从其中一个 Web 服务器检索 ETag 值。然后，在所有其他 Web 服务器上设置相同的 ETag 值。

更详细的说明可以在以下 Microsoft 支持文章中找到：

[`support.microsoft.com/?id=922733`](http://support.microsoft.com/?id=922733)

### 高性能网站

*Steve Souders* 在他的 *高性能网站* 系列中解释了配置规则：

*高性能网站：规则 13* — *配置 ETags：*

[`developer.yahoo.com/blogs/ydn/posts/2007/07/high_performanc_11/`](http://developer.yahoo.com/blogs/ydn/posts/2007/07/high_performanc_11/)

### David Walsh 博客

*David Walsh*的博客网站包含了 Eric Wendelin 的一篇文章 - *使用.htaccess 改善您的 YSlow 等级*，其中也提到了这个配方中解决的问题：

[`davidwalsh.name/yslow-htaccess`](http://davidwalsh.name/yslow-htaccess)

### MBP - 移动样板

实体标签的移除也包含在移动样板中：

[`github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L211-L218`](http://github.com/h5bp/mobile-boilerplate/blob/master/.htaccess#L211-L218)


# 第九章：移动性能测试

在本章中，我们将介绍：

+   使用 Blaze 测试您的移动设备

+   在线分析移动页面速度

+   PCAP Web 性能分析仪

+   HTTP 存档移动版

+   使用 Jdrop 存储性能数据

# 介绍

在本章中，我们将介绍一些最热门的移动性能测试工具。

像移动调试一样，移动性能测试可能并不像桌面测试那样直接。但是每朵云都有一线阳光。许多开发人员已经找到了解决这些问题的创造性方法。

# 使用 Blaze 测试您的设备的速度

目标浏览器：跨浏览器

如果您想节省时间并快速测试移动站点的性能，了解加载时间和页面资源信息，那么 Blaze 是一个不错的选择。Mobitest 性能工具用于了解移动 Web 性能。它提供以下测试结果：

+   总加载时间

+   单个页面资源的分解

+   渲染视频

+   原始 HTTP 存档（HAR）文件

## 准备就绪

您只需登录[`www.blaze.io/mobile/`](http://www.blaze.io/mobile/)。

## 如何做...

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_01.jpg)

在页面上，您可以看到以下表单，允许您输入 URL。让我们测试**yahoo.com**！

在结果页面的顶部，我们可以从屏幕截图中看到平均加载时间、页面大小和站点的速度排名：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_02.jpg)

以下图表显示了站点的瀑布图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_03.jpg)

## 它是如何工作的...

**使用的设备**

您可能想知道后端使用了什么设备，它们是否是仿真器或模拟器。测试是在使用自定义构建的代理的真实移动设备上运行的。

**加载时间百分位数**

使用内部索引来计算加载时间百分位数。它使用数百个网站来获取站点速度与其他站点的比较。

**测试运行的位置**

测试运行位置在加拿大渥太华。代理通过 WiFi 连接到互联网。撰写时使用的设备有：iPhone、Nexus 和三星 Galaxy S。

要了解更多，请访问：

[`www.blaze.io/mobile/methodology/`](http://www.blaze.io/mobile/methodology/)。

## 还有更多...

可以在以下位置找到一些有用的页面测试工具列表：

[`www.blaze.io/learn/feo-resources/`](http://www.blaze.io/learn/feo-resources/)

### Blaze 博客

除了提供的测试工具，Blaze 还有一个博客，其中有很多关于移动优化的文章，网址是：

[`www.blaze.io/blog/`](http://www.blaze.io/blog/)

### Web 性能优化最佳实践

有关 Web 性能最佳实践的良好提示，请访问 Blaze 优化页面：

[`www.blaze.io/overview/optimizations/`](http://www.blaze.io/overview/optimizations/)

# 在线分析移动页面速度

目标浏览器：跨浏览器

如果您熟悉 Google Page Speed，您会知道有一个 Chrome 扩展程序，用于测试桌面浏览器的加载时间。但是还有一个 Google Page Speed 的 Web 版本，可以用于分析移动性能。

## 准备就绪

访问 Google Page Speed Online：

[`pagespeed.googlelabs.com/`](http://pagespeed.googlelabs.com/)。

## 如何做...

在此示例中，我们将测试 Google 的移动主页：

1.  输入您想要分析的 URL，在我们的例子中，让我们使用**m.google.com:**![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_04.jpg)

1.  单击输入框旁边的下拉列表，并从下拉菜单中选择**获取移动建议**：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_05.jpg)

1.  一旦点击**分析移动性能**，我们将进入以下页面：![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_06.jpg)

## 它是如何工作的...

页面速度得分表示页面可以快多少。对于我们的例子，数字是 100 中的 62。

以下是分析的细节。细节已经分解如下：

+   高优先级：这些建议代表了最大潜在的性能优胜者，而开发工作最少。您应该首先解决这些问题。

+   中等优先级：这些建议可能代表着较小的收益或者更多的工作来实施。

+   低优先级：这些建议代表最小的收益。

+   实验性规则：这些建议是实验性的，但不会影响整体页面速度得分。

+   没有建议的规则：对于这些规则没有建议，因为此页面已经遵循了这些最佳实践。但您仍然可以通过展开左侧可折叠菜单来检查规则。

## 还有更多...

要查看移动性能工具列表，请访问：

[`github.com/h5bp/mobile-boilerplate/wiki/Mobile-Performance-Tools`](http://github.com/h5bp/mobile-boilerplate/wiki/Mobile-Performance-Tools)

### 需要速度

麻省理工技术评论显示了一些关于速度有多重要以及它如何影响您网站访问者的图表和统计数据。文章提到，即使轻微的在线减速也会让人感到沮丧，并给公司带来损失：

[`www.technologyreview.com/files/54902/GoogleSpeed_charts.pdf`](http://www.technologyreview.com/files/54902/GoogleSpeed_charts.pdf)

### 当时间很重要

Gomez Inc 进行了一项关于网站和移动性能期望的全国消费者调查：

[`www.gomez.com/wp-content/downloads/GomezWebSpeedSurvey.pdf`](http://www.gomez.com/wp-content/downloads/GomezWebSpeedSurvey.pdf)

# 使用 PCAP Web 性能分析器分析移动性能

目标浏览器：跨浏览器

PCAP Web 性能分析器允许您更好地控制数据分析。您可以与移动网站/应用程序进行交互，并更准确地获取性能数据。它是由*Bryan McQuade*和*Libo Song*创建的。

## 准备工作

在使用 PCAP Web 性能分析器之前，我们需要先为移动设备捕获 PCAP 文件。我们通过设置一个私人 WiFi 网络，连接移动设备到网络，捕获，然后分析流量来实现。以下是如何做到这一点：

1.  打开**控制面板** | **网络和互联网** | **网络和共享中心**。

1.  选择**设置新的连接或网络**的链接。

1.  选择**设置无线自组网（计算机对计算机）网络**。

1.  接下来，给网络取一个名字（例如 hot1），并勾选**保存此网络**。

1.  返回**网络和共享中心**，点击左侧的**更改适配器设置**链接。

1.  找到您的局域网，右键单击并打开**属性** | **共享选项卡**。

1.  启用共享。

现在我们需要下载 Wireshark，我们可以使用它来选择要捕获的网络流量。我们可以通过以下步骤生成 HAR 文件并将其保存在本地机器上：

1.  从以下网址下载 Wireshark：[`www.wireshark.org/download.html`](http://www.wireshark.org/download.html)。

1.  打开 WireShark。

1.  点击**菜单捕获** | **选项**。

1.  在**选项**对话框中，选择您的无线接口，然后点击**捕获过滤器**。

1.  在**捕获过滤器**对话框中，创建一个新的过滤器（如果您还没有这样做），名称为**TCP 和 UDP 端口 53（DNS）**，过滤字符串为**tcp 或 udp 端口 53**。

1.  选择过滤器，然后关闭对话框。

1.  在**捕获选项**对话框中点击**开始**按钮开始捕获。

1.  完成后保存捕获。

要将移动设备连接到热点，请在移动设备上连接到指定的 WiFi 热点（在我们的示例中为“hot1”）。现在，您在移动设备上访问的任何网站都应该被*tcpdump*捕获。

## 如何做...

在**性能分析器**页面上，选择您保存的 HAR 文件，然后点击**上传**。文件将被处理，并将显示带有瀑布的详细分析：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_09.jpg)

## 它是如何工作的...

它使用开放文件格式 PCAP 和 HAR，以及开源工具 pcap2har、HAR 查看器和页面速度。

## 还有更多...

*Stoyan Stefanov*维护了一个非常有用的关于 Web 和移动性能的网站。

[`calendar.perfplanet.com/2010/mobile-performance-analysis-using-pcapperf/`](http://calendar.perfplanet.com/2010/mobile-performance-analysis-using-pcapperf/)

### HAR 查看器

正如官方描述所说，*HAR Viewer 是一个基于 HTTP 存档格式（HAR）的 HTTP 跟踪日志的可视化 Web 应用程序（PHP + JavaScript）*。该项目托管在 Google Code 上；您可以在以下网址查看：[`code.google.com/p/harviewer/`](http://code.google.com/p/harviewer/)。

### 使用 Page Speed 优化您的移动网站

有一个关于使用 Google 的 Page Speed 的视频。该视频是在 Google I/O 2011 期间拍摄的，由 PACPPERF 的创作者呈现，您可以在以下网址找到：

[`www.google.com/events/io/2011/sessions/use-page-speed-to-optimize-your-web-site-for-mobile.html`](http://www.google.com/events/io/2011/sessions/use-page-speed-to-optimize-your-web-site-for-mobile.html)

### pcap2har

要了解有关 pcap2har 的更多信息，您可以访问 Github 上托管的项目页面：

[`github.com/andrewf/pcap2har`](http://github.com/andrewf/pcap2har)

# 使用 HTTP 存档移动版

目标浏览器：跨浏览器

HTTP 存档移动版跟踪 Web 的构建方式。它提供：

+   **Web 技术趋势：**加载时间，下载大小，性能得分

+   **有趣的统计数据：**流行的脚本，图像格式，错误，重定向

+   **网站性能：**特定 URL 截图，瀑布图，HTTP 头

## 准备工作

登录到[`mobile.httparchive.org/`](http://mobile.httparchive.org/)。

## 如何做...

点击**趋势**，您可以查看诸如 HTML，JavaScript，CSS，图像和 Flash 的传输大小和请求等趋势。以下是 HTML 传输大小和 HTML 请求的图表：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_07.jpg)

点击**统计**，您可以获得许多有趣的统计数据，从最常见的图像格式到最常见的服务器；从具有最多 CSS 的页面到具有最多图像的页面。

以下是显示最受欢迎的 JS 库的图表：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_09_08.jpg)

点击**网站**，您将获得与特定网站相关的所有性能信息，包括 Filmstrip，瀑布图，页面速度，请求，趋势和 HAR 文件的下载。

## 它是如何工作的...

列出的网站是由 Alexa，财富，全球 500 和 Quancast10K 排名最高的网站。

URL 列表提供给`WebPagetest.org`。

使用 JavaScript 从 HAR 文件生成 HTTP 瀑布图。

## 还有更多...

因此，您可能会问为什么我们需要记录这些数据。我们这样做是因为归档并从 Web 性能历史中学习是很重要的。正如*Steve Souders*所说，“*HTTP 存档提供了这一记录。它是网页性能信息的永久存储库，如页面大小，失败的请求和使用的技术。”*（在[`www.stevesouders.com/blog/2011/03/30/announcing-the-http-archive/)`](http://www.stevesouders.com/blog/2011/03/30/announcing-the-http-archive/)）。

### 数据的准确性如何？

如果您想了解数据的准确性，请阅读：[`mobile.httparchive.org/about.php#accuracy`](http://mobile.httparchive.org/about.php#accuracy)关于测量的信息，特别是时间测量。

### 测试方法的限制

尽管测试结果在很大程度上是有用的，但用户需要注意一些限制。有关需要考虑的事项清单，请访问：

[`mobile.httparchive.org/about.php#limitations`](http://mobile.httparchive.org/about.php#limitations)

# 使用 Jdrop 存储性能数据

目标浏览器：跨浏览器

**Jdrop**用于存储移动设备性能数据。JSON 数据存储在云中。

移动设备的屏幕空间较小，这使得分析大量信息变得困难。为了解决这个问题，Jdrop 允许您在大屏幕上分析从移动设备收集的数据。

## 准备工作

登录到 Jdrop [`jdrop.org/`](http://jdrop.org/)。

## 如何做...

在您的移动设备上：

1.  登录到 Jdrop。

1.  安装任何使用 Jdrop 的应用程序。

1.  运行应用程序并将数据保存到 Jdrop。

在您的台式机或笔记本电脑上：

1.  登录 Jdrop。

1.  查看您生成的 JSON 数据。

在移动设备上，开始的最简单方法是将`jdrop-example.js`的内容（可以在[`jdrop.org/jdrop-example.js)`](http://jdrop.org/jdrop-example.js)找到）嵌入到您的书签脚本中。此外，您还必须添加一个“保存到 Jdrop”的链接到您的书签，以调用您的函数。您可以在[`jdrop.org/devdocs`](http://jdrop.org/devdocs)找到带有解释的代码。

**保存到 Jdrop：**

以下是您需要添加“保存到 Jdrop”链接到您的书签的代码。

```html
<a href="javascript:SaveToJdrop('MY APP NAME', myDataObj, '1.1.3', '1.8 secs')">Save to Jdrop</a>

```

**注册您的应用程序：**

目前，注册您的应用程序需要一些手动操作；您必须在 Jdrop 讨论列表（[`groups.google.com/group/jdrop/topics`](http://groups.google.com/group/jdrop/topics)）上发布请求。

这是注册您的应用程序所需的信息：

+   **应用程序名称**（必填）

+   **脚本 URL**（必填）

+   **回调函数**（可选）

+   **格式**（可选）

+   **格式密钥**（可选）

一些信息可能在您阅读此文时发生变化，您可以登录[`jdrop.org/devdocs`](http://jdrop.org/devdocs)检查是否有任何更新。

## 它是如何工作的...

当通过 Google 帐户连接时，您可能想知道为什么 Jdrop 要求访问您的 Google 联系人。这是因为 OAuth 到 Google 需要提到一个要进行身份验证的服务。Jdrop 实际上并不访问您的任何联系人。创建者正在考虑使用 OpenID 而不是 OAuth 来绕过这一步。

## 还有更多...

Jdrop 是由*Steve Souders*和*James Pearce*创建的。

*Steve Souders*对大多数开发者来说并不陌生；要查看他创造的所有奇迹，请访问：

[`stevesouders.com/`](http://stevesouders.com/)。

詹姆斯·皮尔斯（James Pearce）是 Sencha Inc.的开发者关系总监。您可以在他的网站上找到有关移动设备的有趣想法和有用信息：

[`tripleodeon.com/`](http://tripleodeon.com/)。


# 第十章：新兴移动 Web 功能

在本章中，我们将涵盖：

+   `window.onerror`

+   使用 ECMAScript 5 方法

+   新的 HTML5 输入类型

+   内联 SVG

+   `position:fixed`

+   `overflow:scroll`

# 介绍

iOS 5 上的移动 Safari 引入了一系列改进，使移动 Safari 成为最先进的移动浏览器之一。添加了许多尖端的 HTML5 功能——ECMAScript 5 以及移动特定功能——以允许在移动设备上实现更多功能并提高性能：

+   **Web forms**已经被引入，以帮助改善 Web 的用户界面，使界面原型设计更快速、更容易。

+   **内联 SVG**在移动浏览器上具有更大的可扩展性；这对于响应式设计可能非常有用。

+   **ES5**允许更好地控制创建的对象，并且可以在纯 JavaScript 中构建大型和复杂的功能。

+   添加了**移动特定属性**，如滚动 CSS。在移动 Safari 上，实现原生滚动曾经很痛苦，但现在添加了移动特定属性，使得 Web 开发人员能够开发具有与原生应用相同性能的 Web 应用变得轻松。

# window.onerror

目标浏览器：iOS 5

在 iOS 5 中，新增了一个事件处理程序：`window.onerror`。此事件处理程序用于发送到窗口的错误事件。

语法如下：

```html
window.onerror = funcA;

```

## 准备工作

创建一个 HTML 文档并将其命名为`ch10r01.html`。

## 操作步骤...

输入以下代码并在浏览器中进行测试：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<style>
</style>
</head>
<body>
<script>
window.onerror=function(){
alert('An error has occurred!')
}
</script>
<script>
document.write('hello world'
</script>
</body>
</html>

```

您应该看到一个弹出警报，显示发生了错误。

## 它是如何工作的...

出现错误是因为我们没有在`document.write:`中关闭括号：

```html
<script>
document.write('hello world'
</script>

```

如果关闭括号并重试，错误将消失：

```html
<script>
document.write('hello world');
</script>

```

## 还有更多...

默认窗口行为是阻止显示错误对话框。它覆盖了默认行为：

```html
window.onerror = null;

```

### 浏览器对象模型

**浏览器对象模型** **(BOM)**是一组对象，让您可以访问浏览器和计算机屏幕。这些对象可以通过全局对象窗口和`window.screen`访问。要了解更多关于 BOM 的信息，请访问：

[`javascript.about.com/od/browserobjectmodel/Browser_Object_Model.htm`](http://javascript.about.com/od/browserobjectmodel/Browser_Object_Model.htm)

# 使用 ECMAScript 5 方法

目标浏览器：iOS 5

**ECMAScript 5**正在取代 ECMAScript 3.1。ECMAScript 5 为对象交互提供了很大的增强。从 iOS 4 开始，Safari 引入了许多新的 ECMAScript 5 功能；iOS 5 为 ECMAScript 5 提供了更大的支持。

以下是新引入的`Object`方法：

```html
Object.seal/Object.isSealed
Object.freeze/Object.isFrozen
Object.preventExtensions/Object.isExtensible
Function.prototype.bind

```

## 准备工作

创建一个 HTML 文档并将其命名为`ch10r02.html`。

## 操作步骤...

输入以下代码并在浏览器中进行测试：

```html
/*** freeze ***/
var dog = {
eat: function () {},
hair: "black"
};
var o = Object.freeze(dog);
// test if dog is frozen
assert(Object.isFrozen(dog) === true);
// can't alter the property
dog.hair = "yellow";
// can't remove property
delete dog.hair;
// can't add new property
dog.height = "0.5m";
/*** seal ***/
var human = {
eat: function () {},
hair: "black"
};
human.hair = "blonde";
var o = Object.seal(obj);
// changing property works
human.hair = "grey";
// can't convert
Object.defineProperty(obj, "hair", { get: function() { return "green"; } });
// silently doesn't add the property
human.height = "1.80m";
// silently doesn't delete the property
delete human.hair;
// detect if an object is sealed
assert(Object.isSealed(human) === true);
/*** preventExtensions ***/
ECMAScript 5ECMAScript 5testingvar nonExtensible = { removable: true };
Object.preventExtensions(nonExtensible);
Object.defineProperty(nonExtensible, "new", { value: 8675309 }); // throws a TypeError
assert(Object.isExtensible(nonExtensible) === true);
/*** bind ***/
var x = 9;
var module = {
x: 81,
getX: function() { return this.x; }
};
module.getX(); // 81
var getX = module.getX;
getX(); // 9, because in this case, "this" refers to the global object
// create a new function with 'this' bound to module
var boundGetX = getX.bind(module);
boundGetX(); // 81

```

## 它是如何工作的...

**Freeze**

如其名称所示，`freeze`冻结一个对象。不能向`freeze`添加或删除任何内容；甚至不能修改内容。它使对象不可变并返回一个冻结的对象：

```html
// can't alter the property
dog.hair = "yellow";
// can't remove property
delete dog.hair;
// can't add new property
dog.height = "0.5m";

```

要测试对象是否被冻结，请使用`isFrozen:`

```html
// test if dog is frozen
assert(Object.isFrozen(dog) === true);
// silently doesn't add the property
human.height = "1.80m";
// silently doesn't delete the property
ECMAScript 5ECMAScript 5object, freezingdelete human.hair;

```

**Seal**

如果您`seal`一个对象，则无法再添加或删除对象属性。您可能会问，`freeze`和`seal`之间有什么区别？区别在于对于`seal`，您仍然可以更改当前属性的值：

```html
// changing property works
human.hair = "grey";

```

要测试对象是否被封闭，请使用`isSealed:`

```html
// detect if an object is sealed
assert(Object.isSealed(human) === true);

```

**preventExtensions**

默认情况下，对象是可扩展的，但是通过`preventExtensions`，我们可以阻止对象扩展。这意味着不能再向对象中添加新属性。

```html
/*** preventExtensions ***/
var nonExtensible = { removable: true };
Object.preventExtensions(nonExtensible);
Object.defineProperty(nonExtensible, "new", { value: 8675309 }); // throws a TypeError
assert(Object.isExtensible(nonExtensible) === true);

```

**Function.prototype.bind**

另一个非常有用的功能是`bind`。它允许更好地控制`this`值。在我们的示例中，无论如何调用函数，它都会以特定的`this`值调用。

从示例中，我们可以看到有一个全局变量`x`，并且它的值在`module`对象中被修改：

```html
var x = 9;
var module = {
x: 81,
getX: function() { return this.x; }
};
module.getX(); // 81

```

当从对象中提取方法`getX`，然后调用该函数并期望它使用原始对象作为`this`，但此时对象是全局的，因此它返回`9`。

```html
var getX = module.getX;
getX(); // 9, because in this case, "this" refers to the global object

```

通过使用`bind`，我们创建了一个`this`绑定到`module:`的新函数

```html
// create a new function with 'this' bound to module
var boundGetX = getX.bind(module);
boundGetX(); // 81

```

## 还有更多...

默认窗口行为是防止错误对话框显示。它覆盖了默认行为：

```html
window.onerror = null;

```

### MDN 上的文档

`Object.freeze/Object.isFrozen:`

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/freeze`](http://developer.mozilla.org/en/JavaScript/Reference/)

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/isFrozen`](http://developer.mozilla.org/en/JavaScript/Reference/)

`Object.seal/Object.isSealed:`

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/seal`](http://developer.mozilla.org/en/JavaScript/Reference/)

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/isSealed`](http://developer.mozilla.org/en/JavaScript/Reference/)

`preventExtensions/isExtensible:`

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/preventExtensions`](http://developer.mozilla.org/en/JavaScript/Reference/)

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Object/isExtensible`](http://developer.mozilla.org/en/JavaScript/Reference/)

`Function.prototype.bind:`

+   [`developer.mozilla.org/en/JavaScript/Reference/ Global_Objects/Function/bind`](http://developer.mozilla.org/en/JavaScript/Reference/)

# 新的 HTML5 输入类型

目标浏览器：iOS 5

新的输入类型对于 Web 表单是有用的功能。iOS 5 现在支持：`date, datetime, month, time, range`等等。

## 准备工作

创建一个 HTML 文档并将其命名为`ch10r03.html`。

## 如何做...

输入以下代码并在浏览器中测试：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
</head>
<body>
<input type="date">
<input type="datetime">
<input type="month">
<input type="time">
<input type="range">
</body>
</html>

```

## 它是如何工作的...

在 iOS 5 上，`date`和`datetime`将被渲染如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_10_01.jpg)

在 iOS Safari 上渲染后，`month`和`time`输入类型将如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_10_02.jpg)

`slider`输入类型将如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_10_03.jpg)

## 还有更多...

有许多 polyfill 用于使 Web 表单在各种浏览器中工作。`html5slider`是 Firefox 4 及以上版本的 HTML5`<input type="range">`的 JavaScript 实现。您可以在以下网址了解更多信息：

[`github.com/fryn/html5slider`](http://github.com/fryn/html5slider)

# 文本/HTML 中的内联 SVG

目标浏览器：iOS 5

**可伸缩矢量图形（SVG）**可以在支持内联 SVG 的 HTML 文档中使用。

## 准备工作

创建一个 HTML 文档并将其命名为`ch10r04.html`。

## 如何做...

输入以下代码并在浏览器中测试：

```html
<svg width="500" height="220"  version="1.1">
<rect x="2" y="2" width="496" height="216" stroke="#000" stroke-width="2px" fill="transparent"></rect>
</svg>

```

## 它是如何工作的...

HTML 内联 SVG 必须以 MIME 类型`Content-Type: text/xml`呈现。您可以通过以`.xml`而不是`.html`结尾来创建这个。

## 还有更多...

有几种在 HTML 页面中嵌入 SVG 的方法：`<object>, <embed>, <iframe>`。

要了解不同浏览器中对 SVG 的支持，请访问（在*直接将 SVG 代码嵌入 HTML*部分下）：

[`www.w3schools.com/svg/svg_inhtml.asp`](http://www.w3schools.com/svg/svg_inhtml.asp)

### HTML 中的 SVG

Mozilla MDN 有很多关于前端网页和相关信息的有用文章：

[`developer.mozilla.org/en/SVG_In_HTML_Introduction`](http://developer.mozilla.org/en/SVG_In_HTML_Introduction)

# position:fixed

目标浏览器：iOS 5

`position:fixed`现在在 iOS 5 中得到支持。现在更容易为 Web 应用创建固定定位的工具栏。

## 准备工作

创建一个 HTML 文档并将其命名为`ch10r05.html`。

## 如何做...

在 iOS 5 之前，`position:fixed`在移动 Safari 中无法工作。如果我们想要创建一个工具栏或固定定位的页眉或页脚，就需要类似以下的 hack：

```html
<div id="fixedDiv">
</div>
<script>
window.onscroll = function() {
document.getElementById('fixedDiv').style.top =
(window.pageYOffset + window.innerHeight - 25) + 'px';
};
</script>

```

随着 iOS 5 的发布，不再需要这种 hack，我们可以简单地使用 CSS 样式，就像我们通常在其他浏览器中使用的那样：

```html
<style>
#fixedDiv { position:fixed; }
</style>
<div id="fixedDiv">
</div>

```

## 它是如何工作的...

我们将`onscroll`事件注册到`window`对象上，当滚动事件发生时，`div`将始终位于页面底部。

[`developer.mozilla.org/en/SVG_In_HTML_Introduction`](http://developer.mozilla.org/en/SVG_In_HTML_Introduction)

# overflow:scroll

目标浏览器：iOS 5

移动设备和桌面设备之间的一个重要区别是人们与浏览器的交互方式。在桌面浏览器上，可以通过鼠标滚轮或滚动条来进行滚动操作。在移动浏览器上，没有滚动条或鼠标滚轮，因此整个滚动交互都是通过手指操作完成的。很长一段时间内，iOS 不支持`overflow:scroll`，但现在 iOS 5 已经支持了！

## 准备工作

创建一个名为`ch10r06.html`的 HTML 文档。

## 如何做...

现在，如果您想要使一个区域可滚动，请使用以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
div {
width:200px;
height:200px;
margin:0 auto;
border:1px solid black;
overflow: scroll;
-webkit-overflow-scrolling: touch;
}
</style>
</head>
<body>
<div>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
<p>Lorem Ipsum</p>
</div>
</body>
</html>

```

## 它是如何工作的...

通过将`overflow`定义为`scroll`，并将`-webkit-overflow-scrolling`定义为`touch`，可以在移动 Safari 页面上滚动内容，而无需任何额外的代码。

## 还有更多...

在过去的几年中，有许多 hack 用于模拟原生滚动行为。从未发布的苹果网页框架**PastryKit**启发了许多框架这样做。一些著名的框架包括：

+   Sencha touch: [`www.sencha.com/products/touch/`](http://www.sencha.com/products/touch/)

+   `iScroll`: [`cubiq.org/iscroll`](http://cubiq.org/iscroll)

+   Scrollability: [`github.com/joehewitt/scrollability/`](http://github.com/joehewitt/scrollability/)

+   jQuery mobile: [`jquerymobile.com/`](http://jquerymobile.com/)

有一句古话是“假装直到你成功”，现在苹果终于让这成为可能。就性能而言，它非常稳定，可能比以前的任何框架都要好。

### 浏览器碎片化

对于某些企业来说，可能会担心移动浏览器的碎片化。一种方法是支持当前浏览器版本之前的两个版本。另一种方法是
