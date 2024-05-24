# HTML5 样板文件的 Web开发（二）

> 原文：[`zh.annas-archive.org/md5/8C583EAEFA986CBF606CD0A7F72F11BE`](https://zh.annas-archive.org/md5/8C583EAEFA986CBF606CD0A7F72F11BE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：让您的网站更好

网站设计和开发的性质是这样的，不是所有的优化和建议都适用于所有情况。在本章中，我们将看看各种可用的优化工具以及它们最适合的情况，以使 HTML5 Boilerplate 网站加载和呈现更快。

# 为 Internet Explorer 找到最佳体验

Internet Explorer 8 及以下版本对标准和一致的呈现支持非常混乱。根据使用 Internet Explorer 访问您的网站的用户数量，您可能会或不会花费精力优化 Internet Explorer。

## IE 的移动优先样式

**媒体查询**是 CSS 功能，允许您根据特定媒体特征的值应用不同的规则集。例如，如果浏览器的最小宽度为`500`像素，您可以使所有的`h1`元素变成`红色`，如下面的代码所示：

```js
@media only screen and (min-width: 500px) {
h1 { color: red; }
}
```

然而，IE6、IE7 和 IE8 不理解媒体查询，通常用于根据不同的屏幕宽度调整宽度。因此，它们永远不会呈现出您为与某个媒体查询断点匹配的屏幕宽度的浏览器创建的优化样式（在上面的片段中为`min-width: 500px`）。在我们的 Sun and Sand Music Festival 网站中，我们在三个不同的媒体查询中有样式规则，如下面的代码片段所示：

```js
@media only screen and (max-width: 300px){ /*CSS rules */ }

@media only screen and (max-width: 750px) { /*CSS rules */ }

@media only screen and (max-width: 1150px) { /*CSS rules */ }
```

这意味着 IE6、IE7 和 IE8 将呈现样式，就好像这些查询不存在一样！如果您指定的设备宽度规则在最后较小，那么这些规则很可能会覆盖较大设备宽度的规则，导致 Internet Explorer 8 及以下版本上的设计不够理想。

理想情况下，在这种情况下，您只希望 IE 呈现所有样式，并且用户可以滚动，如果必要的话，以便最大宽度的样式规则始终适用。为此，我们可以创建一个单独的`ie.css`文件，它将呈现`main.css`中的所有规则，除了这些规则将不再包含在媒体查询中。

手动完成这项工作很困难，几乎不可能维护。然而，Nicolas Gallagher 写了一个他发明的优雅解决方案，使用 Sass 来导入每个媒体查询断点的单独样式表，并将它们编译成两个单独的样式表；一个没有媒体查询（`ie.css`），另一个有媒体查询（`main.css`）；我们将在下面看到这个。

### ie.scss

`ie.scss`的代码片段如下：

```js
@import "300-up";
@import "750-up";
@import "1150-up" /* Make sure largest is last */
```

### main.scss

`main.scss`的代码片段如下：

```js
@import "base";
@media (min-width:300px) {
    @import "300-up"; }
@media (min-width:750px) {
    @import "750-up"; }
@media (min-width:1150px) {
    @import "1150-up"; }
```

请注意，您需要在与`main.scss`和`ie.scss`相同的父文件夹中分别命名为`300-up.scss`、`750-up.scss`和`1150-up.scss`的每个文件。

在`index.html`页面的`head`标签中，您现在可以编写以下代码：

```js
<!--[if (gt IE 8) | (IEMobile)]><!-->
<link rel="stylesheet" href="/css/style.css">
<!--<![endif]-->

<!--[if (lt IE 9) & (!IEMobile)]>
<linkrel="stylesheet" href="/css/ie.css">
<![endif]-->
```

### 注意

Jake Archibald 还提供了一个更容易编写的解决方案，使用 Sass 在`jakearchibald.github.com/sass-ie/`。它利用了 Sass 3.2 的新功能，并且`main.scss`和`ie.scss`的组合略有不同。这需要对 Sass 有深入的了解，这超出了本书的范围。

## 在 IE6 和 IE7 中使用 jQuery 打印

IE6 和 IE7 不支持所有其他浏览器支持的`:after`伪选择器。这意味着我们的打印样式表，提供所有链接与链接文本一起打印的功能，在 IE6 和 IE7 中将无法工作。您可以简单地使用 jQuery 代码来克服这个问题。

### 注意

Bill Beckelman 在他的博客`beckelman.net/2009/02/16/use-jquery-to-show-a-links-address-after-its-text-when-printing-in-ie6-and-ie7/`上写了一篇关于这个问题的文章。IE 支持自己的专有`onbeforeprint`和`onafterprint`事件，可以用于我们的优势。根据 Bill Beckelman 的工作，我们可以编写我们自己简单的 jQuery 代码来在 IE6 和 IE7 中打印链接 URL。

首先，我们检查`window.onbeforeprint`是否存在，因为这将表明此代码正在一个 IE 浏览器上执行。我们还想验证此浏览器是否支持生成的内容，因为我们只需要在不支持时使用此代码。以下代码片段检查`window.onbeforeprint`事件是否存在：

```js
if (Modernizr.generatedcontent == false &&window.onbeforeprint !== undefined) {
```

然后，我们设置函数在`onbeforeprint`或`onafterprint`发生时执行，如下所示的代码：

```js
window.onbeforeprint = printLinkURLs;
window.onafterprint = hideLinkURLs;
```

然后，我们编写以下函数：

```js
functionprintLinkURLs() {
$("a[href]").each(function() {
$this = $(this);
$this.data("originalText", $this.text());
$this.append(" (" + $this.attr("href") + ")");                
});
}

functionhideLinkURLs() {
  $("a[href]").each (function() {            
     $(this).text($(this).data("originalText"));
  });
}
```

## 在 Internet Explorer 中为禁用的表单元素设置样式

直到 9 版本，Internet Explorer 没有办法指示表单字段是否被禁用，除了使用该字段中的文本的颜色。有时，一个字段只是一个图标而不是文本（或者可能是一个空的输入文本框），在这种情况下，几乎不可能分辨哪些按钮被禁用，哪些没有。

对于 Internet Explorer 7 及以上版本，只需在`main.css`中添加以下规则，即可使禁用的字段显示方式与启用的字段明显不同：

```js
.lt-ie9 input[type='text'][disabled], 
.lt-ie9 textarea[disabled] {
background-color: #EBEBE4;
}
```

如果您需要支持 Internet Explorer 6，则确保在具有`disabled`属性设置的表单元素上添加一个名为`disabled`的类，并将上一个规则修改为以下内容：

```js
.lt-ie9 input.disabled, 
.lt-ie9 textarea.disabled {
background-color: #EBEBE4;
}
```

## 抑制 IE6 图像工具栏

在 IE6 中，当鼠标悬停在所有图像上时，都会显示工具栏。您可以通过在`index.html`文件的`head`标签中添加以下代码来禁用它们：

```js
<metahttp-equiv="imagetoolbar" content="false">
```

# 使用工具更轻松地编写 CSS3

CSS3 处于前沿。一些属性需要所谓的供应商前缀。例如，3D 变换属性`perspective`在不同的浏览器中实现如下：

```js
-webkit-perspective //Safari, Chrome
-ms-perspective // Internet Explorer
perspective // Firefox
```

就在不久之前，Firefox 将此属性实现为`-moz-perspective`，但后来放弃了对`-moz-`前缀的支持。

正如您将意识到的那样，很难跟踪哪个浏览器需要前缀，哪个浏览器不需要，而且不太可行的是，每次浏览器添加或删除对前缀的支持时，都要定期更新我们创建的所有网站。

为了使这更容易，我们可以使用没有这些前缀的抽象，这样一个具有哪个属性需要哪个前缀的更新索引的工具可以将它们转换为所需的最终 CSS。

这正是 Sass（`sass-lang.com`）或 Less（`lesscss.org`）提供的。Sass 是一种语言，带有一个编译器，将用 Sass 编写的代码转换为 Ruby 中的 CSS。Less 是一种类似的语言，但是用 JavaScript 编写。

在这两种情况下，这些语言都是 CSS 语法的扩展，这意味着您可以将现有的 CSS 文件复制到 Sass 或 Less 文件中，并将它们编译为纯 CSS 文件，而不会出现任何错误。

这些语言提供的额外功能包括使用 mixin、变量、函数等。

对于 Sass，**Compass**是一个额外的框架，提供了一个在`compass-style.org/reference/compass/css3`中找到的 CSS3 mixin 的库。Less 有许多选项；最受欢迎和经常更新的可以在 Twitter Bootstrap 中找到，在`twitter.github.com/bootstrap/less.html#mixins`中可用。以下部分向您展示如何在 Sass 和 Less 中创建使用 CSS 变换的规则。

## Sass

Sass 的代码片段如下：

```js
.btn-arrow {
  @include transform(scale(2));
}
```

## Less

Less 的代码片段如下：

```js
.btn-arrow {
.scale(2);
}
```

## 输出的 CSS

输出的 CSS 将如下所示：

```js
.btn-arrow {
-webkit-transform: scale(2);
     -moz-transform: scale(2);
      -ms-transform: scale(2);
       -o-transform: scale(2);
transform: scale(2);
}
```

## 将 HTML5 Boilerplate CSS 转换为 Sass 或 Less

您通常只需将`main.css`文件重命名为`main.scss`或`main.less`，然后开始使用它作为基本的 Sass 或 Less 文件。要将这些文件编译为相应的 Less 或 Sass 文件，您可以使用 GUI-based 浏览器刷新软件，它会自动编译这些文件，比如**LiveReload**(`livereload.com/`)或**Codekit**(`incident57.com/codekit`)。

如果您熟悉命令行，可以安装 Less 或 Sass，并运行它们各自的命令行解释器将文件编译为纯 CSS。

如果您希望使用纯 Sass 或 Less 文件（而不是`main.css`文件的内容）开始，还有 HTML5 Boilerplate 的分支将样式表转换为 Sass。我们将在以下部分看到其中的两个。

### HTML5 Boilerplate Compass 扩展

有一个可用于与 Compass 一起使用的 Compass 扩展，位于`github.com/sporkd/compass-html5-boilerplate`。请注意，它的更新频率不如在 HTML5 Boilerplate 中找到的`main.css`文件。这是广泛模块化的，并将`main.css`文件拆分为多个 Sass 文件。结果 CSS 文件中的 CSS 注释也被删除。

### HTML5 Boilerplate Sass 分支

有一个 Sass 分支的`main.css`经常更新，网址为`github.com/grayghostvisuals/html5-boilerplate/tree/h5bp-scss`，您可以使用它，如果您只想要一个基本的 Sass 文件来开始。这个版本使用 Sass 变量，但不会将文件拆分为单独的文件。

不幸的是，HTML5 Boilerplate 没有最新的 Less 分支。但是，您可以将`main.css`重命名为`main.less`，然后将其用作 Less 文件。

# 打印注意事项

如果您的网页可能会被打印，您可能希望考虑使用可打印的颜色。一些浏览器认为一些颜色太浅，无法打印，并会强制使用较深的颜色进行打印；`merttol.com/articles/code/too-light-for-print.html`上有关于这个有趣怪癖的更多细节。

附录，*您是专家，现在怎么办？*，详细介绍了打印样式背后的推理和原理。

# 查找和使用 polyfills

大多数 HTML5 和 CSS3 功能在不同浏览器中具有不同级别的支持，因此，要么使用 JavaScript 代码在不支持这些功能的浏览器中模拟这些功能，要么提供一个可变的视图。这些代码片段称为 polyfills。

我帮助维护`html5please.com`，这是一个关于一些流行的 HTML5 和 CSS3 功能的 polyfills 的主观列表。

要注意的是，在不支持许多功能的浏览器上使用大量 polyfills 会带来性能损失。

当您使用 polyfills 时，请确保使用 Modernizr 的`load`函数，就像我们在第四章中为 Sun and Sand 音乐节网站的音频 polyfill 所做的那样。这将防止在支持您想要使用的功能的浏览器上不必要地加载 polyfills。

在 Modernizr Wiki 上提供了所有类型 polyfills 的全面列表，网址为`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-browser-Polyfills`。

# 加快您的网站速度

如果您的页面使用了大量资源，比如图片，那么也许预取这些资源会更明智，这样您的页面加载速度会更快。**DNS 预取**就是一种方法。

## DNS 预取

DNS 预取通知浏览器页面加载过程中提前引用的其他域名资源，以便它可以解析这些域名的 DNS 解析。

浏览器必须在域名服务器（DNS）上查找域名，以确定其在互联网上的位置。有时，它必须经过多层域名服务器，这可能非常缓慢，而且并不总是一致的。通过使用 DNS 预取，即使在用户点击链接或加载资源之前，也会对特定域名的 DNS 解析进行处理，并且资源可以更快地获取。

谷歌表示，这可以节省大约 200 毫秒的时间，用于托管在外部域名上的资源。

如果您将资产托管在像亚马逊的 S3 这样的内容交付网络（CDN）上，甚至是引用 Google 的 API 或 Microsoft 的 API CDN，那么在预取这些文件时会更快。

通过在 HTML 文件的`head`标签中编写以下代码来调用 DNS 预取：

```js
<link rel="dns-prefetch" href="//image.cdn.url.example.com">
```

理解预取的浏览器将立即开始尝试解析`href`属性中的链接的 DNS。以下是它在 Amazon S3 上的样子：

```js
<link rel="dns-prefetch" href="//s3.amazonaws.com">
```

目前，Firefox 3.5 及更高版本，Safari 5 及更高版本，以及 IE9 及更高版本支持 DNS 预取。

# 使您的站点在搜索引擎上更加可见

尽管您网站的内容最重要，但确保其他一切都支持更好地在搜索引擎上显示内容也很重要。以下部分解释了一些您可以做到这一点的方法。

## 引导搜索蜘蛛到您的站点地图

站点地图通知搜索引擎站点内页面的存在，否则这些页面是无法发现的；也许它们在站点的其他页面或外部站点上都没有链接。

一些 CMS 提供插件来生成站点地图，列在`code.google.com/p/sitemap-generators/wiki/SitemapGenerators`，或者您可以按照[www.sitemaps.org/protocol.html](http://www.sitemaps.org/protocol.html)上的指南自己编写一个。

一旦编写了站点地图，您可以通过添加以下内容，让搜索引擎蜘蛛在爬行您的网站时发现它：

```js
<linkrel="sitemap" type="application/xml" title="Sitemap" href="/sitemap.xml">
```

您还可以将站点地图提交给各个搜索引擎，而不是在 HTML 页面中链接到站点地图，如果您希望尽可能减小页面大小。

## 实施 X-Robots-Tag 标头

您可能会有一个暂存服务器，例如`staging.example.com`，用于您的站点`example.com`。如果外部站点链接到暂存服务器上的文件（比如您在论坛上询问某些功能不起作用并链接到暂存服务器），即使域名不在`robots.txt`文件中，或者没有`robots.txt`文件，它也可能被搜索引擎索引。

为了防止这种情况，您可以通过将以下代码片段附加并取消注释的方式，将`X-Robots-Tag` HTTP 标头标签添加到暂存服务器上的`.htaccess`文件中：

```js
# ------------------------------------------------------------
# Disable URL indexing by crawlers (FOR DEVELOPMENT/STAGE)
# ------------------------------------------------------------

# Avoid search engines (Google, Yahoo, etc) indexing website's content
# http://yoast.com/prevent-site-being-indexed/
# http://code.google.com/web/controlcrawlindex/docs/robots_meta_tag.html
# Matt Cutt (from Google Webmaster Central) on this topic:
# http://www.youtube.com/watch?v=KBdEwpRQRD0

# IMPORTANT: serving this header is recommended only for
# development/stage websites (or for live websites that don't
# want to be indexed). This will avoid the website
# being indexed in SERPs (search engines result pages).
# This is a better approach than using robots.txt
# to disallow the SE robots crawling your website,
# because disallowing the robots doesn't exactly
# mean that your website won't get indexed (read links above).

# <IfModulemod_headers.c>
#   Header set X-Robots-Tag "noindex, nofollow, noarchive"
#   <FilesMatch "\.(doc|pdf|png|jpe?g|gif)$">
#     Header set X-Robots-Tag "noindex, noarchive, nosnippet"
#   </FilesMatch>
# </IfModule>
```

## 尾部斜杠重定向

搜索引擎将文件夹 URL `http://example.com/foo`和`http://example.com/foo/`视为两个不同的 URL，因此会将内容视为彼此的副本。为了防止这种情况，重写 URL，要么将`http://example.com/foo`改为`http://example.com/foo/`，要么将`http://example.com/foo/`改为`http://example.com/foo`。

我们这样做的方法是编辑 Apache 服务器的`.htaccess`文件，并添加以下重写规则（有关如何编辑`.htaccess`文件的详细信息，请参见第五章，“自定义 Apache 服务器”）。

### 选项 1：将 example.com/foo 重写为 example.com/foo/

以下代码片段帮助我们将`example.com/foo`重写为`example.com/foo/`：

```js
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_URI} !(\.[a-zA-Z0-9]{1,5}|/|#(.*))$
RewriteRule ^(.*)$ $1/ [R=301,L]
```

### 选项 2：将 example.com/foo/重写为 example.com/foo

以下代码片段帮助我们将`example.com/foo/`重写为`example.com/foo`：

```js
RewriteRule ^(.*)/$ $1 [R=301,L]
```

如果您有现有的重写规则，请执行以下步骤，以确保正确设置重写规则。不这样做可能会导致不正确的重定向和 404 错误。

+   备份：在开始添加重定向之前，备份您要添加重定向的`.htaccess`文件。这样，如果因为`.htaccess`文件中的错误而无法访问您的站点，您可以快速返回到备份文件。

+   不要附加或替换现有的重写规则：不要附加或替换您正在使用的 CMS 的现有规则，而是将它们合并在一起。

+   观察重写规则的顺序：确保您先添加斜杠，然后再添加可能重写末尾路径的现有规则。

+   确认`RewriteBase`路径：如果您的网站在子文件夹中，请确保为您的重写规则设置了正确的`RewriteBase`路径。如果您有一个有效的`RewriteBase`路径，请不要删除它。

### 注意

最后，考虑从 Google 的*SEO 入门指南*中实施指南，网址为[`googlewebmastercentral.blogspot.com/2008/11/googles-seo-starter-guide.html`](http://googlewebmastercentral.blogspot.com/2008/11/googles-seo-starter-guide.html)。

# 处理没有 JavaScript 的用户

HTML5 Boilerplate 提供了一个名为`no-js`的类，当 Modernizr 在`html`标签上检测到 JavaScript 时，它会被替换为一个名为`js`的类。使用这个类名，你可以为禁用 JavaScript 时网站的外观制定样式。

在我们的 Sun and Sand Festival 网站上，当 JavaScript 未启用时，点击**Day 2**链接不会产生任何效果。

你可以通过以下方式查看在各种浏览器上禁用 JavaScript 时网站的工作方式：

+   **Firefox**：进入**偏好设置**，点击**内容**，然后取消勾选**启用 JavaScript**复选框。

+   **Chrome**：下载**Chrome Web Developer**扩展，并在扩展内禁用 JavaScript。

+   **Safari**：在**开发**菜单上点击**禁用 JavaScript**菜单项。当你在 Safari 的**偏好设置**窗格的**高级**选项卡上勾选**显示开发**工具栏时，你就可以看到**开发**菜单。

+   **Internet Explorer**：在**设置**菜单中点击**Internet 选项**，然后点击**自定义级别**，勾选**在 Active scripting 中禁用**菜单。

+   **Opera**：点击**快速偏好设置**，取消选择**启用 JavaScript**选项。

让我们确保在 JavaScript 不可用时选项卡不会渲染，并确保整个列表同时显示，如下面的截图所示：

![处理没有 JavaScript 的用户](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_06_01.jpg)

我们可以通过编辑`main.css`来利用`no-js`类来实现这一点。首先，我们需要删除选项卡导航，如下面的代码所示：

```js
.no-js .t-tab__nav {
display: none;
}
```

然后，我们需要确保这两个列表在特定情况下是静态定位，而不是绝对定位在彼此下方，如下面的代码所示：

```js
.no-js .t-tab__body {
position: static;
}
```

我们需要确保在**Day 2**的特定情况下不应用`hidden`类，这样我们就可以一次看到所有的艺术家，如下面的代码所示：

```js
.no-js .t-tab__body.hidden {
display: block !important;
visibility: visible;
}
```

现在，当你重新启用 JavaScript 时，你会注意到选项卡导航出现了，一切都按你的预期运行。

# 优化你的图片

你添加到页面上的每个资源都是对服务器的额外请求，也是浏览器在宣布页面完成之前额外的网络请求。网络请求通常是页面加载中最慢的组件。这在移动设备上特别明显，当在 3G 甚至更低的连接上浏览网站时。你的文件越小，它们就会越快地到达浏览器。

如果可以避免使用大图片，最好不要使用。

## 8 位 PNG 文件

如果考虑使用 GIF 格式的图片，应该始终使用 PNG。PNG 格式的图片要轻得多，体积也小得多。此外，8 位 PNG 文件的体积要小得多。

如果你使用 PNG 格式的图片，应该使用带有完整 alpha 通道的 PNG-8，这样可以兼容 IE6。确保验证最终输出，以确保它们不会太粗糙或像素化。

## 图片优化工具

HTML5 Boilerplate 中有构建工具可以优化图片，我们将在下一章中进行讨论。还有一些独立的工具也值得一看，当你想要一次压缩一堆图片时。如果你希望上传你的图片并对其进行优化，可以在`smushit.com/ysmush.it/`上进行。

### ImageAlpha

如果你有 24 位 PNG 图片，可以使用从`pngmini.com`下载的工具将它们转换为带有完整 alpha 通道的 8 位 PNG 文件。这个工具只适用于 Mac OS X。

在`pngquant.org`上列出了适用于其他操作系统的图形用户界面和命令行工具。

### ImageOptim

如果您想一次优化各种格式的图像，**ImageOptim**将是您最佳的选择。您可以从`imageoptim.com`下载。这也仅适用于 Mac OS X，并利用多个工具执行这些优化。

如果您想在其他系统上使用类似的东西，您可以为每种图像格式下载您需要的特定工具。以下表格列出了一些流行图像格式的工具：

| 格式 | 工具 |
| --- | --- |
| 动画 GIF | `Gifsiclewww.lcdf.org/gifsicle/` |
| JPEG | `Jpegtranjpegclub.org/` |
| PNG | `Pngcrushpmt.sourceforge.net/pngcrush/``Imageworsenerentropymine.com/imageworsener/``Optipngoptipng.sourceforge.net/``PNGOUT advsys.net/ken/utils.htm` |

如果您想了解更多关于使用这些优化工具的信息，请阅读 Stoyan Stefanov 关于网络图像优化的幻灯片，网址为[www.slideshare.net/stoyan/image-optimization-for-the-web-at-phpworks-presentation](http://www.slideshare.net/stoyan/image-optimization-for-the-web-at-phpworks-presentation)。关于 PNG 和 JPEG 图像格式还有更多巧妙的优化方法，可以在*Smashing Magazine*上找到详细信息，网址分别为[www.smashingmagazine.com/2009/07/15/clever-png-optimization-techniques](http://www.smashingmagazine.com/2009/07/15/clever-png-optimization-techniques )和[`www.smashingmagazine.com/2009/07/01/clever-jpeg-optimization-techniques/`](http://www.smashingmagazine.com/2009/07/01/clever-jpeg-optimization-techniques/)。

## 使用图像精灵

对于每个资源进行网络请求需要很长时间。为了使这些更小，您可以将多个图像文件合并为一个单一的图像文件，只需请求一次，并且可以缓存很长时间，以便页面加载速度显著加快。如果您的页面将在互联网连接非常低带宽的设备上查看，这将特别有用。

这意味着，您可以将多个图像合并为一个大图像，并在所有选择器上使用 CSS 背景属性，其中这些图像将被使用。让我们将所有艺术家的图像转换为一个大精灵，并将图像元素替换为背景图像。

以下是我们的最终精灵：

![使用图像精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_06_02.jpg)

让我们替换`index.html`中的图像元素，就像以下这样：

```js
<img width="100" height="100" class="t-media__aside t-image--artist" src="img/artist-tinariwen.png">
```

使用以下内容：

```js
<i class="t-artist__image artist-tinariwen"></i>
```

我们为每位艺术家都这样做。然后，在我们的`style.css`中，我们添加以下代码片段：

```js
.t-artist__image {  
background: url(../img/artists-image.png) top left no-repeat, 
url(../img/bg-artist.png) no-repeat center center;
float: left;  
display: block;  
}
.artist-asa { background-position:  -0px -0px, 0 0; }
.artist-kidjo { background-position:  -0px -100px, 0 0; }
.artist-kuti { background-position:  -100px -0px, 0 0; }
.artist-sangre { background-position:  -100px -100px, 0 0; }
.artist-tinariwen { background-position:  -200px -0px, 0 0; }
.artist-toure { background-position:  -200px -100px, 0 0; }
```

最终页面没有发生任何变化，只是我们现在将这些图像的网络请求数量减少到 1 个而不是 6 个。通过优化最终的精灵，我们甚至可以使这个请求更快。

生成精灵似乎是很多工作，但有许多工具可以帮助完成这项工作。

### 从 Adobe Photoshop 中的 CSS 精灵

使用`arnaumarch.com/en/sprites.html`中记录的说明，您可以使用 Photoshop 中的脚本文件选择一个图像文件夹，并生成使用这些文件中的图像定位和校正为背景图像的相关 CSS 文件。

在使用此工具时，有一些需要注意的事项，如下所述：

+   确保文件夹只包含您想要添加到精灵中的图像

+   生成的 CSS 文件位于用于创建精灵的文件夹内

+   生成的精灵在 Adobe Photoshop 中打开，您需要在将其保存到所选位置之前裁剪它

### 使用 Compass 的 CSS 精灵

Compass——Sass 的框架——可以在编译时将您的图像拼接在一起，并在您的 Sass 文件中引用这些图像，然后在生成的 CSS 文件中将其转换为精灵。

您只需要确保在图像文件夹中设置一个文件夹，以便为每个图像设置正确的名称，如下列表所述（摘自 Compass 文档）：

+   `images/my-icons/new.png`

+   `images/my-icons/edit.png`

+   `images/my-icons/save.png`

+   `images/my-icons/delete.png`

名称`my-icons`可以是您喜欢的任何名称。然后在 Sass 文件中，使用以下代码：

```js
@import "my-icons/*.png";
@include all-my-icons-sprites;
```

在上一步中使用的名称与`my-icons`相同。完成！Compass 会生成一个包含以下代码的 CSS 文件：

```js
.my-icons-sprite,
.my-icons-delete,
.my-icons-edit,
.my-icons-new,
.my-icons-save   { background: url('/images/my-icons-s34fe0604ab.png') no-repeat; }

.my-icons-delete { background-position: 0 0; }
.my-icons-edit   { background-position: 0 -32px; }
.my-icons-new    { background-position: 0 -64px; }
.my-icons-save   { background-position: 0 -96px; }
```

现在，在您的标记中使用适当的类名，以向您的元素添加适当的图像。

### SpriteMe

SpriteME，可在`spriteme.org/`上获得，是一个书签工具，可分析页面上使用的图像并将其制作成精灵。如果您有现有站点要转换为使用精灵，这将是一个很好的起点。

# 增强 Google Analytics

**Google Analytics**可以跟踪多种数据类型，以下是一些易于明显的增强，您可以对您的分析数据进行的。 

## 添加更多跟踪设置

Google Analytics 提供了许多可选设置来进行跟踪，您无需在`.push()`方法上使用；而是可以直接附加到初始数组上。而不是以下内容：

```js
var _gaq = _gaq || [];
_gaq.push(['_setAccount', 'UA-XXXXX-X'']);
_gaq.push(['_trackPageview']);
```

您可以执行以下操作：

```js
var _gaq = [['_setAccount', 'UA-XXXXX-X'],['_trackPageview']];
```

## 匿名化 IP 地址

在一些国家，不得将个人数据转移到法律不那么严格的司法管辖区之外（即从德国到欧盟之外）。因此，使用 Google Analytics 脚本的网站管理员可能需要确保不会将个人（可跟踪的）数据传输到美国。您可以使用`_gat.anonymizeIp`选项来实现。使用时看起来像这样：

```js
var _gaq = [['_setAccount', 'UA-XXXXX-X'], ['_gat._anonymizeIp'], ['_trackPageview']];
```

## 在 Google Analytics 中跟踪 jQuery AJAX 请求

史蒂夫·施瓦茨写道，您可以在`plugins.js`中使用的代码，可以让您跟踪 jQuery AJAX 请求，网址是[www.alfajango.com/blog/track-jquery-ajax-requests-in-google-analytics](http://www.alfajango.com/blog/track-jquery-ajax-requests-in-google-analytics)。以下代码片段显示了该脚本：

```js
/*
 * Log all jQuery AJAX requests to Google Analytics
 * See: http://www.alfajango.com/blog/track-jquery-ajax-requests-in-google-analytics/
 */
if (typeof _gaq !== "undefined" && _gaq !== null) {
  $(document).ajaxSend(function(event, xhr, settings){
    _gaq.push(['_trackPageview', settings.url]);
  });
}
```

## 在 Google Analytics 中跟踪 JavaScript 错误

如果您想要使用 Google Analytics 在页面上跟踪 JavaScript 错误，可以使用以下脚本来实现，在`index.html`页面中定义了 Google Analytics 变量`_gaq`之后添加：

```js
(function(window){
var undefined, 
link = function (href) {
var a = window.document.createElement('a');
a.href = href;
return a;
    };
window.onerror = function (message, file, row) {
var host = link(file).hostname;
    _gaq.push([
      '_trackEvent',
      (host == window.location.hostname || host == undefined || host == '' ? '' : 'external ') + 'error',
message, file + ' LINE: ' + row, undefined, undefined, true
    ]);
  };
}(window));
```

# 总结

在本章中，我们看了如何为 Internet Explorer 的用户提供更好的体验。我们还简要考虑了一些工具，可以帮助我们编写更高效、更健壮的样式表，更易于在 CSS 的最新发展中进行维护。我们看了如何使用 polyfills 编写加载更快、更安全的页面。我们详细了解了在禁用 JavaScript 时如何渲染 Sun and Sand 网站，并将艺术家的图像拼接成精灵并保存在多个网络请求中。

在下一章中，我们将看看如何使用 HTML5 Boilerplate 提供的构建脚本来自动部署我们的网站。 


# 第七章：使用构建脚本自动化部署

我们准备部署我们的网站了！但在我们这样做之前，我们应该确保我们最小化了所有脚本和优化了图像，这样这些页面就可以在全球任何地方尽可能快地加载。我们可以通过在命令行执行脚本来自动化这些任务。让我们看看我们有以下哪些选项。

# 构建脚本

一旦你的项目完成，你想要生成剥离注释并优化快速加载的文件。在软件项目中通常使用软件构建系统来实现类似的目标。HTML5 Boilerplate 的构建脚本提供了针对典型网页开发项目所需的任务范围。

脚本只能在您确认您的项目已准备好部署并且已经经过充分测试后使用。构建脚本只是自动化了去除注释、优化文件和确保文件适合生产的过程。

目前 HTML5 Boilerplate 贡献者积极维护有两种构建脚本；这些在下一节中探讨。

## Ant 构建脚本

Ant 构建脚本是一组在 Apache Ant 构建系统（`ant.apache.org/`）之上工作的文件，这个系统自从 HTML5 Boilerplate 的早期版本以来就一直存在。它提供了各种选项，如下所述：

+   发布文件到测试、开发和生产环境

+   使用**JSHint**或**JSLint**检查你的脚本文件的语法和代码质量，或使用**CSSLint**检查你的样式表

+   合并并压缩所有 JavaScript 文件到一个文件中，并更新 HTML 页面，引用这个新文件

+   通过删除注释、空白字符并压缩内联样式和脚本来清理和整理 HTML 标记

+   合并并压缩所有样式表，并更新 HTML 页面，引用新文件，而不是多个 CSS 文件

+   编译样式预处理器文件，如 Less 或 Sass，生成最终的 CSS 样式表，并更新 HTML 页面中的引用

+   使用来自`optipng.sourceforge.net/`的 OptiPNG 和来自`jpegclub.org/jpegtran/`的 JPEGTran 分别优化`img`文件夹内的 PNG 和 JPEG 图像

+   使用来自`github.com/jsdoc3/jsdoc`的 JSDoc3 从你的脚本构建文档

## Node 构建脚本

一个新的基于 Node 的构建脚本，位于`nodejs.org/`，正在积极开发中。虽然它还没有用于生产，但它提供了很多与 Ant 构建脚本相似的任务，还有一些以下描述的新特性：

+   合并并压缩所有 JavaScript 文件到一个文件中，并更新 HTML 页面，引用这个新文件

+   合并并压缩所有样式表，并更新 HTML 页面，引用新文件，而不是多个 CSS 文件

+   通过删除注释、空白字符并压缩内联样式和脚本来清理和整理 HTML 标记

+   使用 OptiPNG 和 JPEGTran 分别优化`img`文件夹内的 PNG 和 JPEG 图像

监视项目文件的变化，并在它们发生变化时自动运行构建脚本并在浏览器中重新加载打开的页面。

## 使用哪个构建脚本？

根据你熟悉的平台，你可以选择一个而不是另一个。这两个构建脚本都足够稳定，可以用来部署你的生产文件，所以你的选择取决于你最习惯使用哪个。

如果你已经安装了 Ant，那么 Ant 构建脚本可能是一个明显的选择。如果你发现自己经常使用 Node 或者在你的项目中使用它，那么 Node 构建脚本可能是一个好的起点。在本章中，我们将查看如何使用这两个工具，这样你就可以熟练掌握它们中的任何一个。

# 使用 Ant 构建脚本

首先，通过在你的命令行工具中输入以下内容来确认你的系统上是否安装了 Ant：

```java
ant–version
```

如果你还没有安装 Ant，请在进行下一步之前先安装它。

### 注意

Ant 默认安装在 Mac 上，而在大多数 Linux 平台上作为软件包安装。对于 Windows，安装 Ant 稍微复杂一些。你需要从[www.oracle.com/technetwork/java/javase/downloads/index.html](http://www.oracle.com/technetwork/java/javase/downloads/index.html)安装 Java SDK，然后下载`WinAntcode.google.com/p/winant/`并将其安装程序指向`Program Files/Java/jre6/bin/`。

接下来，你需要安装**ant-contrib** ，这是一个为 Ant 提供了许多功能的工具，HTML5 构建脚本使用了这些功能。**WinAnt** 在你使用它在 Windows 上安装 Ant 时会自动安装这个工具。然而，对于 Linux 用户，你可以使用**yum** 作为软件包来安装它。在 Mac 上，你可以安装 MacPorts ([www.macports.org/install.php](http://www.macports.org/install.php))，然后在你通常的命令行工具（通常是终端）中输入以下内容：

```java
sudo port install ant-contrib
```

最后，确保图像优化工具已安装。对于 Mac 用户，你需要确保你有**jpegt** **ran** ([www.ijg.org/](http://www.ijg.org/))和**optipng** (`optipng.sourceforge.net/`)安装在你的路径上。你可以通过在你的命令行终端中输入以下内容来安装这两个文件：

```java
sudoport install jpeg optipng
```

### 注意

`PATH`是一个环境变量，它包含了一系列文件夹，当您输入一个命令时，命令行界面会在这些文件夹中搜索。你可以从[www.cs.purdue.edu/homes/cs348/unix_path.html](http://www.cs.purdue.edu/homes/cs348/unix_path.html)了解如何添加文件夹到路径。

如果你在 Windows 上，Ant 构建脚本项目中包含了这些图像工具所需的二进制文件供你安装。

## 安装构建脚本

在终端（或你的命令行工具）中，我们将导航到我们的项目文件夹并使用 Git 安装构建脚本，如下面的屏幕截图所示：

![安装构建脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_01.jpg)

现在我们必须将构建脚本的文件夹名称从`ant-build-script`更改为`build`，然后才能继续。这可以通过使用以下命令来完成：

```java
mv ant-build-script build
```

完成后，让我们使用以下命令导航到构建脚本文件夹：

```java
cd build
```

现在，让我们执行构建脚本！打开你的命令行工具并输入以下内容：

```java
ant build
```

如果你正确设置了你的构建脚本文件夹，那么你应该得到以下屏幕：

![安装构建脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_02.jpg)

然后，在任务执行后，你应该得到以下输出：

![安装构建脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_03.jpg)

现在，你有一个全新的**发布**文件夹，其中存储了优化后的文件。让我们打开**发布**文件夹中的`index.html`页面，在 Chrome 浏览器中使用 Chrome 开发者工具的**网络**标签，观察加载的文件及其相关大小，看看所有已经优化的内容。

请注意，你必须打开**网络**标签来记录正在请求的文件。

## 缩小后的图片文件

**网络**标签记录了所有用于`index.html`的图片。我们可以看到，在**发布**文件夹中用于`index.html`页面的图片明显比原来的大小要小。

在以下屏幕截图中，屏幕截图的底部部分显示了**发布**文件夹中的图片列表，这些图片明显比我们原始项目中使用的图片要小（列表在屏幕截图的顶部部分）：

![缩小后的图片文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_04.jpg)

## 缩小后的 CSS 文件

我们注意到，在我们使用构建脚本之前，我们的 CSS 文件叫做`main.css`，大约有 21KB，但在使用构建脚本后，文件被重命名，现在几乎是原来大小的一半，如下屏幕截图所示：

![缩小后的 CSS 文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_05.jpg)

## 缩小且更少的 JS 文件

执行构建脚本后，你会注意到`main.js`和`plugin.js`已经合并成了一 个。他们不仅被合并在一起，而且被压缩了，导致最终脚本文件的大小更小。

通过构建脚本生成的`index.html`页面仅调用以下屏幕截图底部部分所示的四种 JavaScript 文件，与原来放在文件夹顶部的五种 JavaScript 文件相比：

![缩小且更少的 JS 文件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_06.jpg)

## 文件中没有注释

**发布**文件夹中的 HTML、CSS 和 JS 文件没有包含 HTML5 Boilerplate 文件中的注释。

## 构建选项

Ant 构建脚本有一些默认不执行的任务，但当你需要时可以为你提供。以下各节解释了这些任务允许你做什么。

### 压缩标记

默认情况下，Ant 构建脚本在优化时不会从`index.html`页面中移除空白字符；如果你也想移除 HTML 文件中的空白字符并对其进行压缩，你可以执行以下操作：

```java
ant minify
```

### 防止图片优化

当执行构建脚本时，你会注意到脚本花在优化图像上的时间最长。如果你仅仅是为了测试最终的生产准备文件而执行构建脚本，那么你就不需要优化图像。在这种情况下，你应该执行以下命令：

```java
ant text
```

### 使用 CSSLint

CSS Lint（`csslint.net`）是一个开源的 CSS 代码质量工具，它对你的代码进行静态分析，并标记出无效或可能导致问题的样式规则。要在你项目的 CSS 文件上使用 CSS Lint，只需输入以下内容：

```java
ant csslint
```

通常，你会看到一大堆警告。CSS Lint 有很多你可以设置的选项。要做到这一点，打开`build`中的`config`文件夹内的`project.properties`文件。通过使用以下命令取消注释这一行：

```java
#tool.csslint.opts =
```

在`=`符号后输入你想与 CSS Lint 一起使用的所有选项并保存。你可以在`github.com/stubbornella/csslint/tree/master/src/rules`中找到可以使用的各种选项。

### 使用 JSHint

JSHint（`jshint.com`）是一个由社区驱动的工具，用于检测你的 JavaScript 代码中的错误和潜在问题，并强制执行你的团队的编码约定。要对你的 JavaScript 文件执行 JSHint，去到你的项目并执行以下操作：

```java
ant jshint
```

执行后，我们会看到一大堆错误被列出来，针对我们的`main.js`。 corrected file 包含在本章的代码中。一旦纠正，你还会注意到有一大堆错误被抛出，针对`plugin.js`中的代码。这是因为我们使用了平滑滚动插件的压缩代码。让我们用项目仓库中的未压缩代码替换它，项目仓库的地址是`github.com/kswedberg/jquery-smooth-scroll/blob/master/jquery.smooth-scroll.js`。

现在，我们得到一大堆错误，所有的错误都在告诉我们需要使用更严格的比较运算符。让我们为当前项目关闭这个选项。我们可以通过打开`build`文件夹内的`config`文件夹中的`project.properties`文件并取消注释以下允许你使用自己的 JSHint 选项的行来实现：

```java
#tool.jshint.opts
```

改为以下代码片段：

```java
tool.jshint.opts = maxerr=25,eqeqeq=false
```

### 注意

更多关于选项的信息可以在 JSHint 网站上的`jshint.com`找到。

我们的错误消失不见了！

### 设置 SHA 文件名

合并和压缩后的 CSS 和 JS 文件名被设置为唯一生成的字符串，这确保了当新的生产构建部署到服务器时，这些文件的高速缓存本地副本永远不会被加载。默认情况下，文件名中使用的字符数为`7`。你可以通过改变`build`文件夹中`config`文件夹内的`project.properties`中的以下行来将其设置为更小或更大的数字：

```java
#hash.length = 7
```

取消注释上一行，然后将`7`改为你喜欢的字符数，使用以下语法：

```java
hash.length = <number of characters you prefer>
```

## 使用 Drupal 或 WordPress

为了确保这些 Ant 构建脚本能如预期般为 Drupal 工作，需要做出一些小修改。请注意，对 HTML 页面进行压缩的帮助不大，因为 Drupal 或 WordPress 会生成大部分的标记。

### 更新 build.xml

你需要对 `build.xml` 文件进行一次小修改，以使其能与 Drupal 或 WordPress 的文件结构协同工作。

在文件中寻找 `<echo message="Minifying any unconcatenatedcss files..."/>`。就在那行代码之后，更改以下内容：

```java
<filesetdir="${dir.source}/${dir.css}/" excludes="${concat-files}" includes="**/*.css"/>
```

以下内容需要更新：

```java
<filesetdir="${dir.source}/${dir.css}/" excludes="${concat-files}, ${dir.build.tools}/**/*.css, ${dir.intermediate}/**/*.css, ${dir.publish}/**/*.css" includes="**/*.css"/>
```

### 设置项目配置属性

在 `build` 文件夹中的 `config` 文件夹里的 `project.properties` 文件中，加入以下代码：

```java
dir.css = .
dir.images = images
file.root.stylesheet = style.css
```

### 设置 JS 文件分隔符

WordPress 或 Drupal 主题需要你将你的标记分割到不同的文件中（例如，对于 WordPress 就是 `footer.php`，对于 Drupal 就是 `footer.tpl.php`）。你需要知道以下代码位于以下哪个文件中：

```java
<!-- scripts concatenated and minified via build script -->
<scriptsrc="img/plugins.js"></script>
<scriptsrc="img/main.js"></script>
<!-- end scripts -->
```

使用文件名（例如，`footer.php`）在 `project.properties` 文件中设置 `file.root.page` 属性，使用以下代码：

```java
file.root.page = <name of file>
```

本章的代码中提供了一个经过修改的构建脚本的示例 Drupal 和 WordPress 主题。

# 使用 Node 构建脚本

Node 构建脚本与 Ant 构建脚本的不同之处在于：

+   它具有普遍的安装性，不需要从一个项目复制到另一个项目。

+   所有项目都应该使用 Node 构建脚本进行初始化。在一个已经开始的项目中添加它要麻烦得多。

Node 构建脚本需要 Node 环境，所以通过输入以下命令验证你是否已经安装了 Node：

```java
node -v
```

如果你还没有安装 Node，可以从 `nodejs.org/` 安装（或者通过 [github.com/joyent/node/wiki/Installing-Node.js-via-package-manager](http://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager) 使用包管理器安装）。

## 使用 Grunt

**Grunt** (`gruntjs.com/`) 是一个基于 Node 的命令行构建工具，这个 Node 构建脚本就是基于它开发的。Node 构建脚本提供了可插入到 Grunt 中的 HTML5 Boilerplate 优化的任务。

这需要你在项目文件夹内使用一个 `package.json` 文件和一个 `grunt.js` 文件，这可以在你初始化项目时设置。

## 安装 Node 构建脚本

在你的命令行工具中，首先通过输入以下命令来安装 Node 构建脚本包：

```java
npm install https://github.com/h5bp/node-build-script/tarball/master -g
```

Node 构建脚本也可以作为更大构建设置的一部分使用。如果你倾向于以不同的方式使用它，请在这里查看所有可能的使用方式：[github.com/h5bp/node-build-script/wiki/install](https://github.com/h5bp/node-build-script/wiki/install)。

安装后，你可以通过初始化来创建你的 HTML5 Boilerplate 项目文件夹。

### 初始化你的项目

你可以选择不同的选项来为你自己设置项目文件夹。让我们用这个来设置一个临时的项目，学习如何使用这个脚本启动你的 HTML5 Boilerplate 项目。

创建一个文件夹，你的 HTML5 Boilerplate 项目应该放在这里。使用命令行工具导航到该文件夹，并输入以下命令：

```java
h5bpinit
```

这将开始为你设置一整套命令行交互，供你选择。它主要用于设置将由 Grunt 使用的包管理信息。

一旦你这样做，你有三个选项可以选择开始设置你想要的文件；这些选项如下：

+   `[D]efault`：HTML5 Boilerplate 的标准文件集合。

+   `[C]ustom`：获取所有标准文件，可以选择重命名`js/`、`css/`或`img/`文件夹。如果你的文件将被用作其他系统（如 Drupal 或 WordPress）的模板，你可能希望这样做。

+   `[S]illy`：提示重命名 HTML5 Boilerplate 中的每个文件夹/文件。除非你是语义完美主义者，否则你不太可能使用这个选项。

在你选择想要进行的安装类型之后，还会问更多问题。注意，如果你按*Enter*，括号内显示的默认值将被设置。

这将然后从 Github 仓库下载 HTML5 Boilerplate 的最新版本，作为你的起点。

### 使用 Node 构建脚本与现有项目一起工作

不可能不可能使用脚本与现有项目一起工作，只是有点繁琐。项目正在进行中，以实现在`github.com/h5bp/node-build-script/issues/55`中使用此脚本，但在此之前，以下是我们如何与我们的 Sun and Sand 网站一起使用它的方法：

1.  首先，创建一个临时文件夹，然后从命令行执行 Node 构建脚本，按照早前的部分描述初始化一个空项目。

1.  然后，只将`package.json`和`grunt.js`复制到你的项目文件夹中。

你可以在`nimbu.in/h5bp-book/chapter-7-node-init/`文件夹中查看实际的代码来看到这个操作。

## 使用 Node 构建脚本构建你的项目

在命令行工具中导航到你在上一节初始化的 Sun and Sand 项目文件夹，并输入以下命令：

```java
h5bpbuild:default
```

这将合并文件，结果与 Ant 构建脚本一样，发布在`publish`文件夹中。你也可以像使用 Ant 构建脚本一样使用这些其他的构建选项。

### 文本

如果你想在构建项目时省略图像压缩，请使用以下命令：

```java
h5bpbuild:text
```

### 最小化

如果你还想最小化 HTML 文件，请使用以下命令：

```java
h5bpbuild:minify
```

结果与 Ant 构建脚本找到的结果类似；下面的屏幕截图显示了压缩过程的结果：

![最小化](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_07.jpg)

有一些额外的选项是 Ant 构建脚本所没有的。

### 服务器

这将打开一个本地服务器实例，你可以立即预览你的网站。当想测试使用协议相关 URL 链接到文件的页面时，这个功能很有用。要实现这一点，只需在你的命令行工具中进入你的项目文件夹，并输入以下命令：

```java
h5bp server
```

你会看到为`publish`文件夹和`intermediate`文件夹都启动了服务器，如下面的屏幕截图所示：

![服务器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_07_08.jpg)

然后，打开`http://localhost:3001`来查看发布的网站。

### 连接

使用这个命令，你可以看到在你做出项目中的任何资产更改后，它会在打开的浏览器中自动刷新页面。这节省了你手动刷新页面以查看更改的麻烦。要实现这一点，只需在你的命令行工具中进入你的项目文件夹，并输入以下命令：

```java
h5bp connect
```

## 与 Drupal 或 WordPress 一起使用

使用 Node 构建脚本初始化一个 HTML5 Boilerplate 项目，然后将其转换为为 Drupal 或 WordPress 构建的模板是相当简单的。首先，确保在执行`h5bp init`时选择`Custom`选项。然后，在设置文件夹时，将`inc`设为样式表所在的文件夹，将`images`设为包含模板图片的文件夹的名称。当你再次被提示时，输入相同的值，项目框架将会为你生成。确保你用你的模板文件替换`index.html`。

一旦完成上述步骤，打开你项目文件夹中的`grunt.js`文件，并确认通过以下代码，样式表的文件夹被设置为父文件夹：

```java
css: {
      'style.css': ['*.css']
    },
```

确保只有 JavaScript 文件和样式表在文件名前加上 SHA 文件名，通过编辑或删除被重命名的图片来实现。这可以通过以下代码完成：

```java
rev: {
js: 'js/**/*.js',
css: '*.css',
},
```

脚本还需要知道`images`文件夹的新位置。我们可以通过设置图像的源和目标文件夹来实现，如下面的代码片段所示：

```java
img: {
dist: {
src: 'images',
dest: 'images'
      }
    },
```

# 下一步

一旦我们对`publish`文件夹中的生产文件感到满意，然后我们可以将其移动到我们的托管提供商那里，以替换使我们的网站运行的文件。

理想情况下，你会使用版本控制系统来做这件事，这样在极不可能的情况下更新使得某些页面无法访问时，你可以快速回滚更新。

如果你只是为 Drupal 或 WordPress 创建一个模板，那么将此移动到服务器上的 WordPress 文件夹中，该服务器位于版本控制系统之下可能会有所帮助。

或者，你可以压缩你的项目，然后将文件复制到服务器上，在那里它们可以被解压缩并使用。Node 构建脚本提供了一个这样做选项。在你的命令行工具中进入你的项目文件夹，并输入以下命令：

```java
h5bptar –-input publish –-output <project-name>.tgz
```

使用能最好地描述你项目的名称，而不是`<project-name>`。然后，将`<project-name>.tgz`文件复制到你的服务器上，并将其解压到你希望文件所在的文件夹。

# 总结

在本章，我们学习了如何使用 HTML5 Boilerplate 团队提供的两种构建脚本。我们还查看了如何将它们都与 Drupal 或 WordPress 模板一起使用。我们还探讨了文件构建完成后我们可以做什么。

在下一章，我们将探讨一些高级任务，你现在知道如何使用 HTML5 Boilerplate 创建和部署项目后，可以尝试这些任务。


# 附录 A.你现在是一名专家，接下来做什么？

我们已经准备好我们的网站了。我们学会了如何编写它的代码，使用构建脚本来构建它，以及将其部署到生产环境中，这样它就能顺利上线。你已经有效地掌握了 HTML5 Boilerplate 的学习。如果你对成为一个更好的网页开发者感兴趣，你可以花时间去了解网络相关的其他有用部分！让我们一起探索其中的一些。

# 为你的代码编写单元测试

我们为我们的网站编写了一些 JavaScript 代码。虽然浏览器会告诉我们代码是否编写错误，但没有办法告诉我们代码是否如预期工作。也许有些边缘情况我们没有考虑到。代码应该尽可能健壮，并处理所有预期的用例和大多数错误条件。你可以通过编写测试来测试你的代码调用的每个函数，从而确保这是可能的。

单元测试可以被认为是你的代码中最小的可测试部分。当你编写单元测试时，你确保代码的每个部分都正确运行。开始编写单元测试的最简单方法是使用测试套件。

`QUnit.js`是一个流行的基于浏览器的测试套件，用于在浏览器中测试你的代码。让我们在我们的为阳光与沙滩音乐节网站编写的代码中使用它。

## 创建测试环境

让我们在我们的项目中创建一个`tests`文件夹。

然后，我们从`code.jquery.com/qunit/qunit-1.9.0.js`下载`QUnit.js`，并从`code.jquery.com/qunit/qunit-1.9.0.css`下载相关的 CSS 文件`qunit.css`。这些文件的最新版本可以在`github.com/jquery/qunit`找到。

我们现在通过在`tests`文件夹中创建一个`tests.html`页面来创建一个测试环境，并具有以下代码：

```java
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Tests for Sun n' Sand Festival Code</title>
<link rel="stylesheet" href="qunit-1.9.0.css">
</head>
<body>
<div id="qunit"></div>
<div id="qunit-fixture"></div>
<script src="img/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="img/jquery-1.7.2.min.js"><\/script>')</script>
<script src="img/qunit-1.9.0.js"></script>
<script src="img/main.js"></script>
<script src="img/test.js"></script>
</body>
</html>
```

在这段代码中，我们包括了我们的`main.js`文件，这个文件是我们网站所使用的。我们将测试我们为显示阵容而编写的标签代码。

现在，我们将创建一个`test.js`文件，我们将在其中编写我们代码的所有测试。

由于我们的测试依赖于用于标签的标记，让我们从`index.html`中复制不含内容的标记到`tests.html`。

如果我们按原样执行这个测试，我们会得到一个全局失败的错误。如果你打开浏览器开发者工具的控制台，你应该会看到以下的错误：

```java
Uncaught TypeError: Object [object Object] has no method 'smoothScroll'
```

这是因为我们从`main.js`中调用插件，但我们在这里没有包含这些插件，因为我们不是在测试它们。我们可以在 QUnit 没有被使用的情况下，只测试插件和框架的存在，如以下代码片段所示：

```java
if(window.QUnit == undefined) {
  $('.js-scrollitem').smoothScroll();
  if(Modernizr.svg === false) {
    $('img[src$=".svg"]').each(function() {
      this.src = /(.*)\.svg$/.exec(this.src)[1] + '.png';
    });
  }

  if (Modernizr.generatedcontent === false && window.onbeforeprint !== undefined) {
    window.onbeforeprint = printLinkURLs;
    window.onafterprint = hideLinkURLs;
  }

  Modernizr.load({
    test: Modernizr.audio,
    nope: {
      'mediaelementjs': 'js/vendor/mediaelement/mediaelement-and-player.min.js'
},
    callback: {
    'mediaelementjs': function() {
      $('audio').mediaelementplayer();
    }
  } 
 });
}
```

确保你移除生产代码中的条件—`if(window.QUnit == undefined)`。

现在，让我们写一个测试，以确认当一个导航标签被点击时，正确的类被应用于它，使用以下的代码片段：

```java
$('.js-tabitem').each(function() {
  var $this = $(this);
  $this.trigger('click');
  test( "navigation tabs", function() {
    ok($this.hasClass('t-tab__navitem--active'), 
   'The clicked navigation item has the correct active class applied');
  });
});
```

`test()`函数是 QUnit 测试套件中可用的函数。第一个参数是文本的标题，第二个参数是你想要执行的实际测试函数。

我们还使用`ok()`，这是 QUnit 测试套件中的一个断言。断言是单元测试的基本元素，在这里你测试你的代码执行结果是否返回期望的值。QUnit 有不同种类的断言，具体请参阅`api.qunitjs.com/category/assert/`。

在`ok()`函数中，我们传递给这个函数的第一个参数是一个表达式，该表达式计算结果为真或假。第二个参数是在断言执行时你希望显示的信息。

现在，让我们通过以下代码段来测试非活动导航项是否不包含使导航项显示为活动的类名：

```java
$('.js-tabitem').not(this).each(function() {
  ok(!$(this).hasClass('t-tab__navitem--active'),
    'Inactive item does not have active class');
});
```

现在让我们执行这些测试！在你的浏览器中打开`tests.html`页面。你应该会看到类似下面的截图：

![创建测试环境](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_App_01.jpg)

你还可以执行更复杂的测试！详细了解 QUnit 请访问他们的在线食谱本`qunitjs.com/cookbook/`。

### 你应该知道的神秘默认设置

为了得出 HTML5 Boilerplate 中的默认设置，进行了大量的研究。了解不同浏览器的行为以及我们为何选择这些默认设置是非常有趣的。

## 元 UTF-8

`meta`元素代表页面的任何元数据信息。在`<head>`元素中设置`<meta charset="utf-8">`将确保在没有关于页面编码的其他信息时，浏览器以 UTF-8 编码解析页面。

需要注意的是，大多数浏览器只在页面的前 512 字节内寻找字符编码元数据。因此，如果你在`<head>`元素中有大量的数据，你需要确保这个元元素出现在其他一切之前。

在没有`charset`编码信息的情况下，浏览器必须猜测应应用哪种`charset`编码。HTML5 规范概述了所有浏览器必须实现的嗅探算法，具体请参阅[www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html#encoding-sniffing-algorithm](http://www.whatwg.org/specs/web-apps/current- work/multipage/parsing.html#encoding-sniffing-algorithm)。不幸的是，旧版浏览器有自己猜测字符编码的机制。

在 Internet Explorer 7 及以下版本的情况下，默认的字符编码偏好通常设置为`Auto Select`。这意味着浏览器扫描页面的内容以检测最适合的字符编码。在 Internet Explorer 中，如果在页面的前 4096 个字符内找到一个 UTF-7 字符串，它将假设页面使用 UTF-7 编码，你的页面将变得容易受到使用 UTF-7 编码的跨站脚本攻击。因此，在`index.html`页面顶部使用`meta`元素声明。

请注意，如果你的服务器发送了一个编码不同的 HTTP 头，那么这将优先考虑。确保你的服务器设置为在 HTTP 头中提供正确的`charset`编码。

## HTML Doctype

在 HTML 和 CSS 标准化之前，大多数标记和样式在任何一个浏览器中都无法一致地渲染。但是当我们有了关于标记应该如何编写的标准，越来越多的开发者开始采用这些标准时，浏览器不得不面对的问题是在互联网上的哪些页面符合这些标准，哪些页面不符合。

文档类型（Doctype）的发明是为了让开发者能够通知浏览器使用较新的标准模式来渲染页面。没有 Doctype 声明，浏览器将使用所谓的**怪异模式**（浏览器以前在标准成为可接受做法之前渲染页面的方式）来渲染页面。在 IE6 中，在 Doctype 上方有一个注释或 XML 命名空间声明会导致页面也以怪异模式渲染。在 2000 年代初建议使用带有 XML 命名空间声明的 XHTML Doctype 时，这将在 Internet Explorer 中引起重大问题。

并非所有的 Doctype 声明都在标准模式下渲染。使用标准模式的最简单方法是使用最小的推荐 Doctype，`<!doctype html>`。在 Doctype 声明中可以使用任何大写或小写的混合（例如，`<!DoCtYpE hTmL>`）。

## 清除解决方案的详细信息

`clearfix`CSS 类用于确保浮动元素适合其父容器。这个想法的第一次探索发生在 2002 年，并在[www.positioniseverything.net/easyclearing.html](http://www.positioniseverything.net/easyclearing.html)的文章中进一步阐述。

`clearfix`选择器按照以下方式工作：

```java
.clearfix:after {
  content: ".";
  display: block;
  height: 0;
  clear: both;
  visibility: hidden;
}
.clearfix { zoom: 1; } /* IE 5.5/6/7 */
```

这种方法最大的问题是，边距在所有浏览器上的一致性坍缩。Theirry Koblentz 在[www.tjkdesign.com/lab/clearfix/new-clearfix.html](http://www.tjkdesign.com/lab/clearfix/new-clearfix.html)上写了更多关于它。

蒂埃里·科布伦茨在 2010 年更新了这种方法，引入了`:before`和`:after`伪元素的使用，在[www.yuiblog.com/blog/2010/09/27/clearfix-reloaded-overflowhidden-demystified/](http://www.yuiblog.com/blog/2010/09/27/clearfix-reloaded-overflowhidden-demystified/)的一篇文章中进行了更新。这两个伪元素如下所示：

```java
.clearfix:before,
.clearfix:after {
  content: ".";
  display: block;
  height: 0;
  overflow: hidden;
}
.clearfix:after {clear: both;}
.clearfix {zoom: 1;} /* IE < 8 */
```

使用两个伪元素防止了在使用`clearfix`类时不一致的边距合并问题。

2011 年，尼古拉斯·加利亚尔发现了一种替代方法，如果我们的目标浏览器是 IE6 及以上版本和其他现代浏览器，将大大减少`clearfix`类的代码行数，他在`nicolasgallagher.com/micro-clearfix-hack/`的文章中解释了这一点。尼古拉斯的代码如下所示：

```java
.cf:before,
.cf:after {
    content: " ";
    display: table;
}

.cf:after {
    clear: both;
}

/**
 * For IE 6/7 only
 * Include this rule to trigger hasLayout and contain floats.
 */
.cf {
    *zoom: 1;
}
```

在这种方法中，使用`display: table`会在伪元素内创建一个匿名表格单元（有关这意味着什么的更多信息可以在规范[www.w3.org/TR/CSS2/tables.html#anonymous-boxes](http://www.w3.org/TR/CSS2/tables.html#anonymous-boxes)中找到），这防止了顶端边距的合并。`content`属性不需要任何内容在其中工作，但这种方法使用一个空格字符来克服当在可编辑元素上使用时的 Opera 错误。

这就是`clearfix`类的发展过程！正如你所看到的，为了制作可能跨越主要浏览器平台的最佳`clearfix`类，进行了大量的研究和开发。

## 打印样式做什么？

HTML5 Boilerplate 样式表带有一组在用户打印您的页面时非常有用的默认样式。设计一个页面在打印时的外观是我们在设计网页时大多数不会考虑的事情，而 HTML5 Boilerplate 为您提供了一组良好的默认值，因此您大多数时候不需要考虑（然而，这样做是一个好的实践）。

### 打印媒体查询

我们将所有的打印样式内嵌在一个名为“print”的 CSS 媒体查询中。当用户选择打印页面时，这个媒体查询会被匹配，在这种情况下应用这些样式规则。我们在下面的代码片段中展示了所有的规则都声明在`@media print`查询内：

```java
@media print {
  a, a:visited { text-decoration: underline; }
  /* More Styles below */
}
```

### 优化颜色和背景

然后我们确保优化页面，使其在打印时最易读，并确保我们不会浪费太多的打印墨水打印不必要的图片、颜色和文字。这意味着我们确保移除所有背景图片或图片，这些图片对于所有元素来说只是稍微不同的白色或透明色。我们还确保所有的颜色都是黑色，因为这意味着打印机不需要混合任何墨水，因此可以更快地打印。我们还移除了阴影，因为这会使文字更难读。

我们针对这些更新的最后一条规则如下：

```java
* {
        background: transparent !important;
        color: #000 !important; /* Black prints faster: h5bp.com/s */
        box-shadow:none !important;
        text-shadow: none !important;
    }
```

### 更好的链接

现在很少有设计师使用 `text-decoration: underline` 来为页面上的链接设置样式。通常，人们使用颜色来指示某物是链接。然而，在打印时，下划线更容易辨认，尤其是当你无法控制打印机和渲染它们的颜色时。因此，我们让所有链接（活动或已访问）通过以下代码片段使用下划线样式：

```java
    a,
    a:visited {
        text-decoration: underline;
    }
```

在打印时提供实际链接的参考也会很有帮助，因为用户如果从打印的页面阅读并希望访问链接，没有办法导航到该链接。我们通过在 CSS 中使用 `attr()` 函数来实现。`attr()` 返回当前规则将应用于的元素的属性的值。在这种情况下，由于我们将其应用于链接，我们可以使用 `attr()` 来获取链接的 `href` 属性的值并打印它们。当它们作为 `content` 属性的值使用时，使用空格字符将字符串连接在一起。我们还希望确保如果链接有标题，我们也打印出来，因为标题只有在悬停在链接上时才可见。所有这些在 CSS 中表达出来就像以下的代码片段：

```java
    a[href]:after {
        content: " (" attr(href) ")";
    }

    abbr[title]:after {
        content: " (" attr(title) ")";
    }
```

但是，这意味着即使是链接到同一页面其他位置的链接或用于 JavaScript 操作（带有 `javascript:` 前缀）的链接也会以同样的方式呈现！所以，我们需要确保我们不对这些链接这样做。

为此，我们使用属性选择器，它允许我们选择具有以特定值开始、结束或包含的属性的元素。通过使用选择器 `a[href^="javascript:"]:after`，我们确保我们只选择具有 `href` 属性的链接的 `:after` 伪元素，该属性的值以 `javascript:` 字符串开头。

同样，我们也选择所有 `href` 属性以 `#` 字符开头的链接，因为这意味着这样的链接是内联链接，链接到同一页面内的另一个位置。

然后我们确保对 these links 中的 pseudo-elements 不渲染任何内容。规则看起来像以下的代码片段：

```java
    .ir a:after,
    a[href^="javascript:"]:after,
    a[href^="#"]:after {
        content: "";
    }
```

请注意，这些规则不适用于 IE6，如果必须在 IE6 中提供此功能，您可能需要使用提供此功能的 JavaScript。

### 在同一页面内渲染所有代码和引用

有时，您的打印页面可能包含引用或代码，作为读者，当代码（或引用）本可以在一个页面内无任何中断地包含时，需要不断参考之前的页面是很烦人的。为此，我们可以使用 CSS `page-break-inside` 属性，它允许您告诉浏览器您更愿意让这些元素在两页之间断开还是保持在同一页面上。下面的代码片段显示了此代码：

```java
pre,
    blockquote {
        border: 1px solid #999;
        page-break-inside: avoid;
    }
```

请注意，Firefox 不支持 `page-break-inside`，但在所有其他浏览器中都可以使用。

### 更好地渲染表格

默认情况下，将标题放在`thead`标签内将确保当表格跨两页时，标题会重复。然而，目前只有 Firefox 和 Opera 支持这一点。在 IE 中，你可以这样做，但你必须明确指出，如下面的代码片段所示：

```java
    thead {
        display: table-header-group; /* h5bp.com/t */
    }
```

### 更好地渲染图像

理想情况下，我们想要防止表格行和图像跨页断裂，因此我们使用现在熟悉的`page-break-inside`属性来告诉浏览器我们的偏好，如下面的代码片段所示：

```java
    tr,
    img {
        page-break-inside: avoid;
    }
```

当图像超出页面或打印时被裁剪而在网站上以完整形式显示时，它也不太好看。因此，我们将最大宽度限制为与页面本身一样宽，不超过此宽度，如下面的代码片段所示：

```java
    img {
        max-width: 100% !important;
    }
```

### 页面边距

`@page`规则允许你在打印时修改页面的属性。除了 Firefox 之外，所有浏览器都支持这个规则。这个规则将页边距设置为每页`0.5 cm`，如下面的代码片段所示：

```java
    @page {
        margin: 0.5cm;
    }
```

### 孤儿和寡妇的最优设置

**孤儿**是指出现在页面底部的文本行。**寡妇**是指出现在页面顶部的那些。我们确保文本行不要以留下比所需更少的行在底部或顶部的方式断裂。这将创造一个更易读的体验。以下代码片段用于此目的：

```java
    p,
    h2,
    h3 {
        orphans: 3;
        widows: 3;
    }
```

### 保持标题与内容在一起

如果标题出现在一页的底部，而其对应的内容却出现在下一页，这将使得内容难以阅读。为了告诉浏览器避免这样做，我们可以使用`page-break-after`设置，如下面的代码片段所示：

```java
    h2,
    h3 {
        page-break-after: avoid;
    }
}
```

## 协议相关 URL 是什么？

在 HTML5 Boilerplate 中，当我们提到 jQuery 时，我们是这样提到的：

```java
<script src="img/jquery.min.js">
</script>
```

请注意，我们没有在 URL 前面加上`http`或`https`；相反，它以`//`开头。这些被称为协议相关 URL，当你想在 HTTP 或 HTTPS 环境中使用一个协议无关的资源时，它们很有用。

当你使用 HTTPS 提供页面时，浏览器在页面加载使用 HTTP 协议的资产和资源时会抛出警告和错误。为了防止这种情况，你需要确保你使用 HTTPS 协议来请求所有资产。如果你使用相对 URL 来引用页面所在的父文件夹中的资产，这通常不是问题。然而，如果你在引用像 jQuery 的 CDN URL（前面提到）这样的外部 URL，那么你需要确保在页面使用 HTTPS 协议时使用`https`，而在页面使用 HTTP 协议时使用`http`前缀。

而不是用 JavaScript 来做这个决定，简单地省略协议可以确保浏览器在请求那个外部 URL 时使用当前的协议。在这种情况下，如果这个页面以 HTTPS 的形式提供，即`https://example.com`，那么请求的 URL 将是[`ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js`](https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js)。

您可以在`paulirish.com/2010/the-protocol-relative-url/`了解更多关于这个内容。

## 使用条件注释

历史上，IE6、IE7 和 IE8 是拥有最多 bug 和样式渲染不一致的浏览器。有多种方法可以向 IE8 及以下版本提供样式，以下是其中几种。

### 浏览器样式 hack

最常用的技术是在 CSS 样式规则中使用 hack，这些规则只针对一个浏览器。

对于 IE6 及以下版本，使用以下代码片段：

```java
* html #uno  { color: red }
```

对于 IE7，使用以下代码片段：

```java
*:first-child+html #dos { color: red }
```

对于 IE8，使用以下代码片段：

```java
@media \0screen {
   #tres { color: red }
}
```

还有更多针对两个或更多浏览器（或排除两个或更多浏览器）的 hack，全部列在`paulirish.com/2009/browser-specific-css-hacks/`这篇文章中。

这些 hack 的问题在于，首先它们利用浏览器解析技术的漏洞。如果浏览器修复了这些解析错误，它们可能就无法工作。幸运的是，我们不必担心 IE6 和 IE7 等旧浏览器。

这些 hack 也不易读，如果没有注释，就无法理解它们针对哪些浏览器。

这些方法的优势在于你可以保持你的样式规则在一起，而且你不需要为需要 hack 的浏览器提供单独的样式表。

### 服务器端浏览器检测

当它们向服务器发起请求时，浏览器会随请求发送一个 User Agent 字符串。服务器可以根据它们对 User Agent 字符串的解释提供不同的资源。例如，如果一个浏览器用以下的 User Agent 字符串将自己标识为 IE6：

```java
Mozilla/4.0 (compatible; MSIE 6.0; Windows XP)
```

然后，服务器可以回传一个不同的样式表给 IE6。虽然这看起来是一个简单、容易的解决方案，但问题出现在浏览器撒谎的时候。历史上，浏览器从未准确声称自己是哪个浏览器，因此，很可能会向一个浏览器发送错误的样式表。

这也涉及到一点服务器端的处理开销，以根据浏览器的 User Agent 设置处理请求，因此这不是向 IE8 及以下版本提供不同样式表的理想方式。

### 基于条件注释的样式表

条件注释是 IE9 及以下版本能理解的具有特殊语法的 HTML 注释。以下是一个条件注释的示例：

```java
<!--[if lt IE 9]>
<p>HTML Markup here</p>
<!--<![endif]-->
```

所有浏览器（除了 IE9 及以下版本）都会忽略这些条件注释内的内容。IE9 及以下版本会尝试解释这些注释内的`if`条件，并根据 IE 浏览器的版本号是否与`if`条件中的版本号匹配来选择性地渲染内容。

之前的示例将在所有 8、7、6 及以下版本的 IE 上渲染`p`标签。

条件注释完美地针对老版本的 IE，HTML5 Boilerplate 就是这么做的。使用它们有两种方法。第一种是基于匹配条件注释输出一个单独的样式表，如下面的代码片段所示：

```java
<!--[if lt IE 9]>
<link rel="stylesheet" href="/css/legacy.css">
<![endif]-->
```

这将使 IE8 及以下使用`legacy.css`，其他浏览器将忽略这段代码。

独立样式表的问题在于，在开发样式时，您需要针对两个不同的样式表，偶尔 IE 特定的样式表可能会被遗忘。

有些人只为 IE8 及以下提供一个非常基础的体验，如下面的代码片段所示：

```java
<!--[if ! lte IE 6]><!-->
/* Stylesheets for browsers other than Internet Explorer 6 */
<!--<![endif]-->
<!--[if lte IE 6]>
<link rel="stylesheet" href="http://universal-ie6-css.googlecode.com/files/ie6.1.1.css" media="screen, projection">
<![endif]-->
```

但 HTML5 Boilerplate 更喜欢一个更可读且针对性的方法，使用类名向所有浏览器提供最佳可能的样式，我们接下来会看到。

### 基于条件注释的类名

前一个条件注释方法的迭代将是基于条件注释在根元素上附加类名，如下面的代码片段所示：

```java
<!--[if IE 8]>
<html class="no-js lt-ie9">
<![endif]-->
```

然后，在您的样式表中，您可以使用它在 IE8 及以下设置样式，如下所示：

```java
.lt-ie9 h1 { color: red }
```

您可以在`paulirish.com/2008/conditional-stylesheets-vs-css-hacks-answer-neither/`上阅读更多关于这个解决方案的信息。

这个解决方案不需要单独的样式表，但允许你编写可读的类名，表明样式表中为何存在该样式规则。这是我们在 HTML5 Boilerplate 中采用的解决方案，并推荐使用。

## 什么是元标签 x-ua-compatible？

`x-ua-compatible`是一个头部标签，用于定义 Internet Explorer 如何渲染您的页面。它声明了 Internet Explorer 应使用哪种模式来渲染您的页面。这主要针对那些在 Internet Explorer 9 及以后版本中因对标准支持更好而断裂的老网站。它可以以两种方式设置。

### HTML 页面中的元标签

在这种情况下，我们只需在 HTML 页面的`<head></head>`标签之间添加一个`meta`标签，如下所示：

```java
<head>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7" >
</head>
```

### HTTP 头响应自服务器

在 Apache 中，在`.htaccess`文件中编写以下内容，会使服务器对那个父文件夹的任何请求发送`X-UA-Compatible` HTTP 头作为响应：

```java
LoadModule headers_module modules/mod_headers.so
Header set X-UA-Compatible "IE=EmulateIE7"
```

我们推荐这种设置其值的方法，因为 HTTP 头值会覆盖通过`meta`标签设置的任何值。此外，在`html`元素上使用 IE 条件注释的`meta`标签会导致忽略这个`meta`标签。`X-UA-Compatible`头可以有以下值。

#### Edge

这将使用可用的最新渲染模式。例如，在 Internet Explorer 10 中，它将是 IE10。我们总是希望使用最新的渲染模式，因为这意味着我们能够访问最新的、最符合标准的浏览器版本。这就是为什么它是 HTML5 Boilerplate 中的默认选项。

#### IE9

这将只使用 IE9 模式来渲染页面。例如，当您使用这种模式时，如果这个页面在 Internet Explorer 10 中被查看，它将使用 IE9 模式来渲染页面。

#### IE8

这将渲染页面，好像它是在 Internet Explorer 8 上查看的一样。

#### IE7

这种模式会以 Internet Explorer 7 以标准模式渲染内容的方式渲染页面。

#### 模拟 IE9

这种模式告诉 Internet Explorer 使用`<!DOCTYPE>`指令来确定如何渲染内容。标准模式下的指令在 IE9 模式下显示，怪异模式下的指令在 IE5 模式下显示。所有模拟模式与之前的模式不同，都尊重`<!DOCTYPE>`指令。

#### 模拟 IE8

这种模式告诉 Internet Explorer 使用`<!DOCTYPE>`指令来确定如何渲染内容。标准模式下的指令在 IE8 模式下显示，怪异模式下的指令在 IE5 模式下显示。与 IE8 模式不同，模拟 IE8 模式尊重`<!DOCTYPE>`指令。

#### 模拟 IE7

这种模式告诉 Internet Explorer 使用`<!DOCTYPE>`指令来确定如何渲染内容。标准模式下的指令在 Internet Explorer 7 的标准模式下显示，而在 IE5 模式下显示怪异模式下的指令。与 IE7 模式不同，模拟 IE7 模式尊重`<!DOCTYPE>`指令。对于许多网站来说，这是首选的兼容性模式。

#### IE5

这种模式会以 Internet Explorer 7 在怪异模式下显示内容的方式渲染内容。您可以在 MSDN 文档`msdn.microsoft.com/en-us/library/cc288325(v=VS.85).aspx`上了解这些模式。

# 贡献

如果你喜欢这个项目到目前为止所看到的内容，你可能想要贡献！为 HTML5 Boilerplate 做出贡献在你的学习和理解中即使做出最小的更改也是有益的。贡献有两种方式，如下所述：

+   报告问题

+   提交拉取请求

## 报告问题

如果您在 HTML5 Boilerplate 的文件中发现了一个错误或者是不正确的内容，那么您可以提交一个问题，任何贡献者都可以查看并看看是否可以解决。

诀窍是找出是否是 HTML5 Boilerplate 的问题，或者是项目代码引起的。您可以通过开始安装 HTML5 Boilerplate 的干净版本并验证错误是否仍然发生来验证这是否是 HTML5 Boilerplate 的问题。

如果遇到 HTML5 Boilerplate 的问题，在提交问题时，请确保它没有被报告过。GitHub 问题页面`github.com/h5bp/html5-boilerplate/issues`列出了所有开放的问题。在顶部的**搜索**栏中搜索您遇到的问题。很可能它已经被修复，但修复还没有推送到稳定分支。

如果问题全新的，那么确保你通过一个减少的测试用例以一种明显的方式隔离问题（Chris Coyier 在`css-tricks.com/reduced-test-cases/`中撰写了关于减少测试用例的内容）。当你提交一个 bug 报告时，确保它易于理解，这样我们才能找到一个快速的解决方案。理想情况下，你的 bug 报告应该包含以下内容：

+   一个简短且描述性的标题

+   问题的概述以及此 bug 发生的浏览器/操作系统

+   如果可能的话，重现 bug 的步骤

+   一个减少的测试用例的 URL（你可以在`jsfiddle.net`或`codepen.io`上托管一个）

+   可能引起 bug 的代码行以及其他与 bug 相关的信息

理想情况下，一个 bug 报告应该是自包含的，这样贡献者不需要再次与你联系以了解关于 bug 的更多信息，而可以专注于解决它。

按照这个流程提交一个 bug 报告本身就是了解如何找出你编写的标记、样式或脚本中错误的的学习过程。

## 拉取请求

如果你有关于如何改进 HTML5 Boilerplate 的想法，或者有修补现有问题的补丁，改进或新功能，你可以提交所谓的**pull 请求**。Pull 请求是一组你可以提交给 HTML5 Boilerplate GitHub 存储库进行审查的更改，以便可以让核心贡献者审查并如果认为有用的话将其合并到 HTML5 Boilerplate 中。

开始贡献的一个好方法是找到一个你认为可以解决的小问题，分叉 GitHub 项目（在`help.github.com/articles/fork-a-repo`上了解这意味着什么），在你的更改上工作并提交一个 pull 请求。

如果你的贡献改变了大量代码并极大地改变了项目的性质，首先考虑在 GitHub 项目上打开一个 issues。

以下是要开始创建拉取请求的步骤：

+   分叉项目。

+   克隆你的分叉（在终端中，输入`git clone https://github.com/<your-username>/html5-boilerplate.git`并按*Enter*）。

+   在终端中添加一个上游远程（输入`git remote add upstream https://github.com/h5bp/html5-boilerplate.git`并按*Enter*）。

+   从上游获取最新更改（例如，通过在终端中输入`git pull upstream master`并按*Enter*）。

+   创建一个新的主题分支来包含你的功能、更改或修复（`git checkout -b <topic-branch-name>`）。

+   确保你的更改遵守项目整个中使用的当前编码约定；也就是说，缩进、准确的注释等。

+   将你的更改逻辑上分组提交；使用 Git 的交互式重置功能（关于此功能的更多信息请访问 `help.github.com/articles/interactive-rebase`）来在公开之前整理你的提交。请遵守这些 Git 提交信息指南（访问 `tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html`），否则你的拉取请求很可能不会被合并到主项目。

+   将上游分支合并（或重置）到你的主题分支。

+   将你的主题分支推送到你的分叉（`git push origin <topic-branch-name>`）。

+   用清晰的标题和描述打开一个拉取请求。请提到你测试了哪些浏览器。

这可能看起来像是很多工作，但它使你的拉取请求显著更容易理解且更快合并。此外，你的代码成为了你所做工作的文档，任何想要知道为什么某个部分是这样的都可以回溯到你的提交并确切了解原因。

在 HTML5 样板代码上工作将帮助你开始采用协作开发的最佳实践，你可以将这些实践带回你的工作场所或任何其他协作工作中。
