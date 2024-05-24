# HTML5 移动开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841`](https://zh.annas-archive.org/md5/56F859C9BE97C2D5085114D92EAD4841)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：构建快速响应的网站

在本章中，我们将涵盖：

+   使用基本的 HTML5 标记构建页面

+   使用 CSS3 功能进行渐进增强

+   应用响应式设计与媒体查询

+   使用动态加载

+   应用用户代理检测

+   在主页上添加移动书签气泡

+   使用文本区域和自动增长表单构建联系页面

+   制作具有即时响应的按钮

+   隐藏 WebKit chrome

+   构建移动站点地图

# 介绍

在移动设备上，带宽并不总是像在台式电脑上那样好。如果您在一个慢速的 3G 网络上，加载速度可能比在 Wi-Fi 热点上慢得多。即使对于 Wi-Fi 连接，许多移动浏览器的处理速度也比台式电脑慢。因此，当我们创建移动站点时，它们必须快速且响应迅速。

从本章开始，我们还将开始介绍 HTML5 功能。HTML5 是一组技术，包括语义、新的 CSS 规则和属性，以及新的 JavaScript API，可用于构建结构更好的网页和功能强大的 Web 应用程序。以下是八个主要的 HTML5 功能：

+   语义

+   离线和存储

+   设备访问

+   连接

+   多媒体

+   3D、图形和效果

+   性能和集成

+   CSS3

并非所有这些功能都是专门针对移动设备的；有些与移动 Web 更相关，而有些则更适用于移动和桌面 Web。我们将讨论每个功能，并看看它们如何最好地帮助我们的移动开发。

基于使用新的语义标记和 CSS3 创建的示例，我们将讨论充分利用移动浏览器提供的内容以及如何使用这些独特功能构建网站的许多方法。

# 使用 HTML5 语义构建页面

目标设备：跨浏览器

HTML5 引入了更丰富的标签集；这些标签赋予结构以含义。语义是 HTML5 的一个基本方面。

我们不会在这里介绍所有标签，但会涵盖一些最常用的标签。

## 准备工作

首先，让我们创建一个新的 HTML 文件，并将其命名为`ch04r01.html`。让我们创建一个关于音乐的虚构网站。

## 如何做...

在我们的 HTML 文档中，输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>first.fm</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
</style>
</head>
<body>
<header>
<h1>first.fm</h1>
</header>
<div id="main">
<h2>Pages</h2>
<nav>
<ul>
<li class="list"><a href="http://music.html">Music</a></li>
<li><a href="radio.html">Radio</a></li>
<li><a href="http://events.html">Events</a></li>
<li><a href="http://charts.html">Charts</a></li>
<li><a href="community.html">Community</a></li>
<li><a href="help.html">Help</a></li>
<li><a href="http://about.html">About</a></li>
</ul>
</nav>
</div>
<footer>
<small>&copy; 2011 first.fm</small>
</footer>
</body>
</html>

```

## 它是如何工作的...

`header`元素通常用于`h1`到`h6`元素；它可以出现在整个页面的头部或任何块级元素的头部。它通常包含标题、副标题或标语。

`<header>`元素：

```html
<header>
</header>

```

`nav`元素表示文档的导航。`nav`元素是一个包含指向其他文档或当前文档内部部分的链接的部分。

页面上并非所有链接组都需要在`nav`元素中。只有主要或次要导航链接的组。特别是，页脚通常会有指向站点各个关键部分的链接列表，但在这种情况下，页脚元素更合适。

`<nav>`元素：

```html
<nav>
<ul class="list">
<li class="list"><a href="http://music.html">Music</a></li>
</ul>
</nav>

```

`footer`元素表示文档或文档部分的“页脚”。页脚元素通常包含有关其封闭部分的元数据，例如谁写的、相关文档的链接、版权数据等。页脚中给出的部分的联系信息应使用地址元素进行标记。

`<footer>`元素：

```html
<footer>
<small>&copy; 2011 first.fm</small>
</footer>

```

`small`元素可用于小字体。它不打算呈现页面的主要焦点。`small`元素不应用于长段落或文本部分。它只用于版权信息等短文本。

`<small>`元素：

```html
<small>&copy; 2011 first.fm</small>

```

## 还有更多...

语义不仅仅是更丰富的标签集。我们需要的不仅仅是更有意义的标签。为了扩展标签之外，我们还可以添加机器可读的额外语义；浏览器、脚本或机器人可以理解的数据，为程序和用户提供更有用的、数据驱动的 Web。这些语义是：**RDFa（属性中的资源描述框架）、Microdata**和**Microformats**。

### RDFa

RDFa 提供了一组可机器读取的 HTML 属性。通过使用 RDFa，作者可以将现有的可读信息转换为可机器读取的数据，而无需重复内容。最新的规范可以在此处找到：

[`www.w3.org/TR/rdfa-in-html/`](http://www.w3.org/TR/rdfa-in-html/)。

### 微数据

微数据使用属性来定义数据的名称-值对组。您可以在此处了解更多信息：[`html5doctor.com/microdata/`](http://html5doctor.com/microdata/)。

您可以通过阅读 W3C 工作草案来深入了解微数据：[`www.w3.org/TR/microdata/`](http://www.w3.org/TR/microdata/)。

您还可以阅读 W3C 编辑草案：[`dev.w3.org/html5/md/`](http://dev.w3.org/html5/md/)。

### 微格式

微格式首先设计为人类，其次为机器。目前有 34 个微格式规范，其中一些已发布，一些是草案。您可以在此处了解更多信息：[`html5doctor.com/microformats/`](http://html5doctor.com/microformats/)。

## 另请参阅

+   *在移动 Web 上使用 HTML5*在第一章中，*HTML5 和移动 Web*

+   *在第一章中使 HTML5 跨浏览器呈现*，*HTML5 和移动 Web*

# 使用 CSS3 功能进行渐进增强

目标设备：跨浏览器

CSS3 通过各种样式和效果增强 Web 应用程序和网站。使用 CSS3，可以创建一组无图像的丰富 UI。在移动设备上，更少的图像意味着更快的加载，这是提高性能的一种方式。由于大多数现代智能手机浏览器都广泛支持 CSS3，并且有用于回退的 polyfills（polyfills 用作回退，使 HTML5 功能在不支持 HTML5 的浏览器上工作），因此开始使用 CSS3 不仅安全而且必要！

![使用 CSS3 功能进行渐进增强](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_10.jpg)

## 准备就绪

让我们设计前面示例中创建的页面。首先复制`ch04r01.html`，并将其重命名为`ch04r02.html`。

## 如何做...

添加以下样式规则：

```html
<style>
body {
margin:0;
padding:0;
font-family:Arial;
background:#ccc;
}
header {
text-shadow: 0 1px #000;
background: #ff3019; /* Old browsers */
background: -moz-linear-gradient(top, #ff3019 0%, #cf0404 20%, #ff3019 100%); /* FF3.6+ */
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#ff3019), color-stop(20%,#cf0404), color-stop(100%,#ff3019)); /* Chrome,Safari4+ */
background: -webkit-linear-gradient(top, #ff3019 0%,#cf0404 20%,#ff3019 100%); /* Chrome10+,Safari5.1+ */
background: -o-linear-gradient(top, #ff3019 0%,#cf0404 20%,#ff3019 100%); /* Opera11.10+ */
background: -ms-linear-gradient(top, #ff3019 0%,#cf0404 20%,#ff3019 100%); /* IE10+ */
filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#ff3019', endColorstr='#ff3019',GradientType=0 ); /* IE6-9 */
background: linear-gradient(top, #ff3019 0%,#cf0404 20%,#ff3019 100%); /* W3C */
}
h1 {
padding:0.5em 0.2em;
margin:0;
font-size: 18px;
color:white;
}
h2 {
text-shadow: 0 1px #FFFFFF;
background: #eeeeee; /* Old browsers */
background: -moz-linear-gradient(top, #eeeeee 0%, #cccccc 100%); /* FF3.6+ */
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#eeeeee), color-stop(100%,#cccccc)); /* Chrome,Safari4+ */
background: -webkit-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* Chrome10+,Safari5.1+ */
background: -o-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* Opera11.10+ */
background: -ms-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* IE10+ */
filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#eeeeee', endColorstr='#cccccc',GradientType=0 ); /* IE6-9 */
background: linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* W3C */
padding:0.5em 0.2em;
margin:0;
font-size: 16px;
color:#000;
}
nav ul {
border-top:1px solid #fff;
list-style-type: none;
padding:0;
margin:0;
}
nav li {
padding:0.5em 0.2em;
margin:0;
background:#AFAFAF;
border-bottom:1px solid #fff;
}
nav li a {
height:20px;
display:block;
text-decoration:none;
color:white;
}
</style>

```

通过在浏览器中运行此代码，我们可以看到：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_07.jpg)

## 它是如何工作的...

在此示例中，我们使用 CSS3 渐变来设计标题元素。传统上，要创建像前面的示例一样的渐变，人们必须使用 Photoshop 或 Illustrator，但现在您可以纯粹使用 CSS 来创建它！

```html
background: #eeeeee; /* Old browsers */
background: -moz-linear-gradient(top, #eeeeee 0%, #cccccc 100%); /* FF3.6+ */
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#eeeeee), color-stop(100%,#cccccc)); /* Chrome,Safari4+ */
background: -webkit-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* Chrome10+,Safari5.1+ */
background: -o-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* Opera11.10+ */
background: -ms-linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* IE10+ */
filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#eeeeee', endColorstr='#cccccc',GradientType=0 ); /* IE6-9 */
background: linear-gradient(top, #eeeeee 0%,#cccccc 100%); /* W3C */

```

通过查看上述每条规则，我们可以看到不同的浏览器使用不同的 CSS 规则来处理渐变。为了确保跨浏览器兼容性，有六种不同的变体。您可能会想：“哦，天哪，照顾每个浏览器真的很耗时。”别担心，这条规则不是手动输入的。**终极 CSS 渐变生成器**来拯救！ColorZilla 的强大类似于 Photoshop 的 CSS 渐变编辑器可以帮助您轻松创建 CSS3 渐变：

[`www.colorzilla.com/gradient-editor/`](http://www.colorzilla.com/gradient-editor/)

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_08.jpg)

## 还有更多...

如果考虑 IE9 及以下版本，可以使用 CSS3 PIE（[`css3pie.com/`](http://css3pie.com/)）来提供支持。

下载`PIE.htc`后，将其包含在 CSS 中：

```html
-pie-background: linear-gradient(top, #eeeeee 0%,#cccccc 100%); /*PIE*/
behavior: url(PIE.htc);

```

支持的功能包括：

+   边框半径

+   盒阴影

+   边框图像

+   CSS3 背景（`-pie-background`）

+   渐变

+   RGBA 颜色值

+   PIE 自定义属性

### 了解 CSS3 渐变

*Jeffrey Way*，nettuts 的编辑，有一篇关于 CSS3 渐变的优秀文章。您可以在此处查看：[`net.tutsplus.com/tutorials/html-css-techniques/quick-tip-understanding-css3-gradients/.`](http://net.tutsplus.com/tutorials/html-css-techniques/quick-tip-understanding-css3-gradients/.)

### CSS3，请！

*CSS3 Please!*，由*Paul Irish*编写，提供了有关渐变和许多其他 CSS3 功能的最新语法：[`css3please.com/`](http://css3please.com/)。

## 另请参阅

+   *在移动 Web 上使用 HTML5*在第一章中

# 应用响应式设计

目标设备：跨浏览器

响应式设计是近期移动开发中最重要的概念之一。它强调浏览器应该对屏幕/浏览器调整大小做出不同的渲染。移动优先的响应式设计可以使页面在桌面浏览器上优雅地降级。

*那么为什么我们需要响应式网页设计呢？*

当我们在桌面网页上应用固定布局时，根据浏览器屏幕尺寸，屏幕左侧或右侧通常会出现空白。移动浏览器也有不同的尺寸，并且视口空间有限，每个像素都很重要，因此利用屏幕上的每个像素非常重要，因此需要使用响应式设计来消除页面左侧或右侧的不必要的空白。

*媒体查询如何帮助响应式设计？*

媒体查询用于根据屏幕尺寸更新样式内容，因此对于相同的 HTML 元素，可以应用两个单独的规则。渲染哪一个取决于浏览器视口的大小。

## 准备工作

在本示例中，我们将使用名为`respond.js`的 HTML5 填充。它是由*Scott Jehl*（来自 jQuery Mobile 团队）创建的。它位于源代码的`ch04_code/js`中。

## 操作步骤...

首先，让我们创建一个名为`ch04r03.html`的 HTML 文档。

在 HTML 中输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>first.fm</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="css/style.css?v=1">
<script>Modernizr.mq('(min-width:0)') || document.write("<script src='js/respond.min.js'>\x3C/script>")</script>
</head>
<body>
<header>
<h1>first.fm</h1>
</header>
<div id="main">
<h2>Pages</h2>
<nav>
<ul class="list clearfix">
<li class="list"><a href="http://music.html">Music</a></li>
<li class="list"><a href="radio.html">Radio</a></li>
<li class="list"><a href="http://events.html">Events</a></li>
<li class="list"><a href="http://charts.html">Charts</a></li>
<li class="list"><a href="community.html">Community</a></li>
<li class="list"><a href="help.html">Help</a></li>
<li class="list"><a href="http://about.html">About</a></li>
</ul>
</nav>
</div>
<footer>
<small>&copy; 2011 first.fm</small>
</footer>
</body>
</html>

```

如果您在移动设备上渲染页面，这个页面看起来会和前面的示例一模一样。但是如果您在桌面浏览器上渲染它，它会看起来和下面的类似：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_11.jpg)

## 工作原理...

在文件顶部，我们使用**Modernizr**首先检测当前浏览器是否支持媒体查询。如果不支持，我们将加载`respond.min.js`：

```html
<script>Modernizr.mq('(min-width:0)') || document.write("<script src='js/respond.min.js'>\x3C/script>")</script>

```

在撰写本文时，您需要在规则的末尾添加`/*/mediaquery*/`注释才能使其工作。这在`respond.js`的未来版本中可能会得到改进：

```html
@media only screen and (min-width: 800px) {
}/*/mediaquery*/

```

## 还有更多...

在 Mobile Boilerplate 网站上，我进一步解释了媒体查询，并且您可以在以下网址找到幻灯片：[`html5boilerplate.com/mobile/`](http://html5boilerplate.com/mobile/)。

*Andy Clarke*创建了基于响应式设计理念的*320 and up*。您可以在以下网址下载：[`stuffandnonsense.co.uk/projects/320andup/`](http://stuffandnonsense.co.uk/projects/320andup/)。

# 优化填充脚本加载

目标设备：跨浏览器

脚本加载对于任何浏览器都很重要，但对于移动设备来说更重要，因为带宽较低。Modernizr 带有一个动态加载解决方案。

## 准备工作

首先，让我们创建一个 HTML 文档，命名为`ch03r04.html`。

## 操作步骤...

在代码编辑器中输入以下代码，并运行它。

```html
<!doctype html>
<html>
<head>
<title>first.fm</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/modernizr.custom.54685.js"></script>
<style>
</style>
</head>
<body>
<header>
<h1>Your Location</h1>
</header>
<div id="main">
Your Geo Location is: <span id="geo"></span>
</div>
<script src="img/jquery.js"></script>
<script>
yepnope({
test : Modernizr.geolocation,
nope : ['js/geolocation.js'],
complete: function () { navigator.geolocation.getCurrentPosition(function(position) {
document.getElementById('geo').innerHTML = position.coords.latitude+", "+position.coords.longitude;
});
}
});
</script>
</body>
</html>

```

## 工作原理...

在撰写本文时，Modernizr 2.0 预览版处于 Beta 1 阶段。在这个测试版中，有两个很棒的新功能。一个是您可以选择自定义要检测的功能。另一个很棒的功能是您可以使用`yepnope.js`（也被称为*Alex Sexton*和*Ralph Holzmann*的`Modernizr.load`）。`Yepnope.js`提供了一个动态 JavaScript 加载器，您可以在本章的*还有更多*部分了解更多信息。

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_01.jpg)

使用 Modernizr，我们可以首先检测当前用户代理中是否已存在某个功能：

```html
test : Modernizr.geolocation

```

如果不存在，我们将使用`yepnope`加载`shim geolocation.js`。加载完成后，我们可以附加纬度和经度：

```html
yepnope({
test : Modernizr.geolocation,
nope : ['js/geolocation.js'],
complete: function () {
...
});

```

## 还有更多...

有一些可选资源对开发人员很有帮助。Modernizr 测试套件就是其中之一。它有助于开发人员一目了然地了解某个设备支持哪些功能。您可以在以下网址了解更多信息：

[`modernizr.github.com/Modernizr/test/index.html`](http://modernizr.github.com/Modernizr/test/index.html)。

### yepnope

yepnope 是一个异步条件资源加载器，速度超快，允许您仅加载用户需要的脚本。要了解更多信息，请访问：[`yepnopejs.com/`](http://yepnopejs.com/)。

## 另请参阅

+   *使用 CSS3 功能进行渐进增强*

# 应用用户代理检测

目标设备：跨浏览器

在开发移动站点时，具有用户代理检测是很有用的。这可以帮助您编写重定向脚本，或者帮助您确定是否要基于用户代理加载/不加载某些内容。

## 准备工作

首先，让我们看看如何根据用户代理检测告诉用户是否可以从一个站点重定向到另一个站点。有几种方法可以做到这一点：您可以在服务器配置中执行此操作，也可以在服务器端编程语言中执行此操作，或者可以从前端 JavaScript 中执行此操作。

## 如何做...

您可以从以下位置下载重定向脚本：[`detectmobilebrowser.com/`](http://detectmobilebrowser.com/)。它带有许多不同版本。在本示例中，让我们使用 Apache 配置`.htaccess`。

## 它是如何工作的...

下载文件并打开后，您会看到以下脚本：

```html
RewriteEngine On
RewriteBase /
RewriteCond %{HTTP_USER_AGENT} android|avantgo|blackberry|blazer|compal|
....
|up\.(browser|link)|vodafone|wap|windows\ (ce|phone)|xda|xiino [NC,OR]
RewriteCond %{HTTP_USER_AGENT} ^(1207|6310|6590|
....
|your|zeto|zte\-) [NC]
RewriteRule ^$ http://example.com/mobile [R,L]

```

要将桌面站点重定向到移动站点，可以将`http://example.com/mobile`更改为您的站点地址。

## 还有更多...

用户代理检测不仅在重定向站点时有用，还在尝试确定是否应基于用户代理加载某些内容时有用。

在构建 Mobile Boilerplate 站点时，我使用了检测脚本的 JavaScript 版本来确定站点是否应根据用户代理（移动或桌面）呈现嵌入内容：

```html
if(!jQuery.browser.mobile) {
...
}

```

使用此桌面浏览器脚本，幻灯片将被加载并显示如下：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_02.jpg)

在移动版本中，它不会显示：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_03.jpg)

### 移动浏览器检测方法

移动 tuts 上的一篇文章解释了移动浏览器检测的不同方法：[`mobile.tutsplus.com/tutorials/mobile-web-apps/mobile-browser-detection/`](http://mobile.tutsplus.com/tutorials/mobile-web-apps/mobile)。

# 将移动书签气泡添加到主页

目标设备：iOS

在前几章中，我们已经谈到了在某些移动设备上为您的站点添加书签的能力。尽管这是一个非常酷的功能，使 Web 应用程序更接近本机应用程序，但它也存在一个问题：没有 API 可以用来调用书签操作，因此许多用户根本不知道手机上有这样一个功能。为了解决这个问题，一些框架使用 CSS 和 JavaScript 提供了书签气泡。该脚本将在 Web 应用程序页面底部添加一个促销气泡，要求用户将 Web 应用程序添加到其设备的主屏幕上。

## 准备工作

如前所述，许多框架提供了此功能，但为了简单起见，让我们使用一个独立的框架。Google 发布了一个名为*The Mobile Bookmark Bubble*的开源库来完成这项任务。首先，让我们在以下位置下载它：[`code.google.com/p/mobile-bookmark-bubble/`](http://code.google.com/p/mobile-bookmark-bubble/)。

## 如何做...

该库附带一个`sample.js`。只需在创建的任何网页中包含`bookmark_bubble.js`和`sample.js`，然后您会看到以下内容：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_04.jpg)

## 它是如何工作的...

该库使用 HTML5 本地存储来跟踪促销是否已经显示，以避免不断地纠缠用户。该库的当前实现专门针对 Mobile Safari，这是 iPhone 和 iPad 设备上使用的 Web 浏览器。

## 另请参阅

*在第二章中启用 iPhone 全屏模式*。

# 构建带有文本区域和自动增长表单的联系人页面

目标设备：跨浏览器

在像短信这样的原生应用中，文本区域会自动增长。在移动 Web 上，如果创建一个文本区域，您会意识到它是固定大小的。当您输入的文本行数超过文本区域的高度时，很难看到文本。在这个例子中，我们将看到如何创建一个在您输入更多行时自动增长的文本区域。

## 准备工作

首先，让我们创建一个名为`ch04r05.html`的 HTML 文档。在这个例子中，我们将在 Mobile Boilerplate 中使用`helper.js`：[`github.com/h5bp/mobile-boilerplate`](http://github.com/h5bp/)

## 如何做...

在文件中输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>first.fm</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
#contact {width:220px; height:40px;}
</style>
</head>
<body>
<header>
<h1>Contact Form</h1>
</header>
<div id="main">
<p>Type the message to see it autogrow</p>
<textarea id="contact">
</textarea>
</div>
<script src="img/jquery.js"></script>
<script src="img/helper.js"></script>
<script>
var contact = document.getElementById("contact");
MBP.autogrow(contact);
</script>
</body>
</html>

```

以下是 Palm webOS 中呈现方式的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_12.jpg)

## 它是如何工作的...

在脚本中，我们有一个键盘事件监听器。这将检测文本区域的高度是否已更改。我们测量内容的高度，如果已更改，我们将更改文本区域的 CSS 样式以增加高度。

## 还有更多...

这个原始概念来自 Google 的 Code 博客。您可以在这里阅读更多关于它的信息：[`googlecode.blogspot.com/2009/07/gmail-for-mobile-html5-series.html`](http://googlecode.blogspot.com/2009/07/gmail-for-mobile-html5)。

## 参见

+   *使用即时响应制作按钮*

# 使用即时响应制作按钮

目标设备：iOS，Android

在移动设备浏览器上，按钮响应可能会比原生应用稍慢。在移动浏览器上，有一个`touchstart`事件。通过检测这个事件而不是点击事件，可以使点击更快。

## 准备工作

在这个例子中，我们将使用 Mobile Boilerplate 中的一个函数。创建一个名为`ch04r06.html`的文件。

## 如何做...

以下代码将创建一个带有提交按钮的表单：

```html
<!doctype html>
<html>
<head>
<title>first.fm</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
#contact {
width:220px; height:40px;
}
</style>
</head>
<body>
<header>
<h1>Contact Form</h1>
</header>
<div id="main">
<textarea id="contact"></textarea><br />
<button id="btn">INSTANT button!!!</button><br />
<span id="result"></span>
</div>
<footer>
<small>&copy; 2011 first.fm</small>
</footer>
<script src="img/jquery.js"></script>
<script src="img/helper.js"></script>
<script>
var btn = document.getElementById("btn");
MBP.fastButton(btn,showForm);
function showForm() {
$("#result").html("Thank you for submitting, we will get back to you shortly!");
}
</script>
</body>
</html>

```

## 它是如何工作的...

以下是快速按钮函数的摘录，我们将在这里看到函数是如何工作的。

在顶部，我们定义了主要函数。只有在支持`addEventListener`的情况下才会使用它，它监听`touchstart`和`click`事件：

```html
MBP.fastButton = function (element, handler) {
this.element = element;
this.handler = handler;
if (element.addEventListener) {
element.addEventListener('touchstart', this, false);
element.addEventListener('click', this, false);
}
};
MBP.fastButton.prototype.handleEvent = function(event) {
switch (event.type) {
case 'touchstart': this.onTouchStart(event); break;
case 'touchmove': this.onTouchMove(event); break;
case 'touchend': this.onClick(event); break;
case 'click': this.onClick(event); break;
}
};

```

`onTouchStart`方法用于监听`touchmove`和`touchend`事件。`stopPropagation`用于停止事件在监听器中的传播，以便它停止冒泡：

```html
MBP.fastButton.prototype.onTouchStart = function(event) {
event.stopPropagation();
this.element.addEventListener('touchend', this, false);
document.body.addEventListener('touchmove', this, false);
this.startX = event.touches[0].clientX;
this.startY = event.touches[0].clientY;
this.element.style.backgroundColor = "rgba(0,0,0,.7)";
};

```

`touchmove`用于测试用户是否在拖动。如果用户拖动超过 10 像素，我们将重置它：

```html
MBP.fastButton.prototype.onTouchMove = function(event) {
if(Math.abs(event.touches[0].clientX - this.startX) > 10 || Math.abs(event.touches[0].clientY - this.startY) > 10) {
this.reset();
}
};

```

以下代码防止幽灵点击并调用实际的点击处理程序：

```html
MBP.fastButton.prototype.onClick = function(event) {
event.stopPropagation();
this.reset();
this.handler(event);
if(event.type == 'touchend') {
MBP.preventGhostClick(this.startX, this.startY);
}
this.element.style.backgroundColor = "";
};
MBP.fastButton.prototype.reset = function() {
this.element.removeEventListener('touchend', this, false);
document.body.removeEventListener('touchmove', this, false);
this.element.style.backgroundColor = "";
};

```

## 还有更多...

您可以在 Google 的博客上阅读有关快速按钮的更多信息。它详细解释了这个想法背后的背景和理论：[`code.google.com/mobile/articles/fast_buttons.html`](http://code.google.com/mobile/articles/)。

## 参见

*使用文本区域和自动增长表单构建联系页面*

# 隐藏 WebKit chrome

目标设备：iOS，Android

iOS 和 Android 上移动 Safari 的 URL 栏使用了大量空间。许多开发人员会在页面加载时隐藏它，因为移动房地产有限。每个像素都很重要，通过隐藏 URL 栏，可以帮助您利用屏幕上的每个像素，最大化显示区域。

## 准备工作

首先，让我们创建一个名为`ch04r07.html`的 HTML 文档。

## 如何做...

输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
html,body,header,footer{
padding:0;
margin:0;
}
header{
height:40px;
background:#BFB840;
display:block;
}
#main{
height:350px;
background:#F2CB67;
}
footer{
height:40px;
background:#DB5E31;
display:block;
}
</style>
</head>
<body>
<header>
header
</header>
<div id="main">
main
</div>
<footer>
footer
</footer>
<script src="img/jquery.js"></script>
<script src="img/helper.js"></script>
<script>
//MBP.hideUrlBar();
</script>
</body>
</html>

```

现在，如果您在浏览器中呈现它，它将看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_05.jpg)

现在取消以下行的注释：

```html
MBP.hideUrlBar();

```

再次呈现内容，您会看到 chrome 现在被隐藏，允许页脚显示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_04_06.jpg)

## 它是如何工作的...

以下是 Boilerplate 中的脚本：

```html
MBP.hideUrlBar = function () {
var win = window,
doc = win.document;
// If there's a hash, or addEventListener is undefined, stop here
if( !location.hash || !win.addEventListener ){
//scroll to 1
window.scrollTo( 0, 1 );
var scrollTop = 1,
//reset to 0 on bodyready, if needed
bodycheck = setInterval(function(){
if( doc.body ){
clearInterval( bodycheck );
scrollTop = "scrollTop" in doc.body ? doc.body.scrollTop : 1;
win.scrollTo( 0, scrollTop === 1 ? 0 : 1 );
}
}, 15 );
win.addEventListener( "load", function(){
setTimeout(function(){
//reset to hide addr bar at onload
win.scrollTo( 0, scrollTop === 1 ? 0 : 1 );
}, 0);
}, false );
}
};

```

它检测 URL 中是否有任何哈希。如果有，我们将停止运行脚本，因为这意味着有一个内联锚点。如果没有任何哈希，我们将等待一秒，如果没有滚动，Android 使用 1 像素的 y 位置进行隐藏，而在 iOS 中为 0。脚本对两者进行了规范化。它是由*Scott Jehl*制作的：[`gist.github.com/1183357`](http://gist.github.com/1183357)。

它也包含在 Mobile Boilerplate 中：[`github.com/h5bp/mobile-boilerplate/blob/master/js/mylibs/helper.js`](http://github.com/h5bp/mobile-boilerplate/blob/master/js/mylibs/helper.js)。

## 另请参阅

*使用文本区域和自动增长表单构建联系页面*

# 构建移动站点地图

目标设备：跨浏览器

许多开发人员熟悉 Google 站点地图。作为最大的搜索引擎，确保它获取我们的内容非常重要。为了移动 SEO 目的，Google 提出了**移动站点地图**。Google 建议人们将其移动站点地图更新为下面描述的格式。

## 准备工作

首先，让我们创建一个 XML 文档并将其命名为`sitemap.xml`。

## 如何做...

我们可以将以下代码添加到 XML 文档中。对于您拥有的特定网站，URL 应该是您页面的 URL：

```html
<?xml version="1.0" encoding="UTF-8" ?>
<urlset 
>
<url>
<loc>http://mobile.example.com/article100.html</loc>
<mobile:mobile/>
</url>
</urlset>

```

所有 URL 都包含在`<loc></loc>`中。

确保您已包含`<mobile:mobile/>`。否则，站点将无法被正确爬取。

## 它是如何工作的...

站点地图遵循特定的模式；上述 XML 模式用于告诉 Google 搜索引擎移动网页的位置。通常，如果网站使用 CMS 系统构建，应该有一种自动生成 URL 的方法，并且它们都应该在`<loc></loc>`中列出。

## 还有更多...

移动站点地图不能包含仅限桌面的 URL。但是，它可以包含桌面和移动内容。

对于具有专用移动内容和专用 URL 的网站，您可以将用户从`example.com`重定向到`m.example.com`。在这种情况下，对用户和 Googlebot-Mobile 都使用 301 重定向。

如果您从`example.com`提供所有类型的内容，则 Google 不认为这是欺骗。

### Google 和移动友好的站点构建

在 Google 网站管理员网站上，有一篇关于如何使网站移动友好的博客文章：[`googlewebmastercentral.blogspot.com/2011/02/making-websites-mobile-friendly.html`](http://googlewebmastercentral.blogspot.com/2011/02/making-websites-mobile-friendly.html)。

### Google 和移动站点索引

Google 网站管理员网站上还有另一篇博客，讨论如何帮助 Google 索引您的移动站点：[`googlewebmastercentral.blogspot.com/2009/`](http://googlewebmastercentral.blogspot.com/2009/)


# 第五章：移动设备访问

在本章中，我们将涵盖：

+   获取您的位置

+   处理跨浏览器地理位置

+   根据您的地理位置显示地图

+   实时定位

+   `DeviceOrientation`事件

+   使用 foursquare 的地理位置

# 介绍

在所有 HTML5 类中，与移动开发最相关的类之一必须是设备访问。

这是 W3C HTML5 Movement 网站上设备访问的官方描述([`www.w3.org/html/logo/`](http://www.w3.org/html/logo/))：

> 从地理位置 API 开始，Web 应用程序可以呈现丰富的、设备感知的功能和体验。令人难以置信的设备访问创新正在被开发和实施，从音频/视频输入访问到麦克风和摄像头，再到诸如联系人和事件之类的本地数据，甚至倾斜方向。

您可以在以下网址找到描述和徽标：[`www.w3.org/html/logo/ #the-technology`](http://www.w3.org/html/logo/)。

基于位置的社交网络，如 foursquare，对业务运作方式和人们的动员方式产生了深远影响。如果 Groupon 发布了基于位置的新优惠，可能会从根本上改变消费者行为和零售业的运作方式。Google 地图使用实时地理位置和 GPRS 来帮助人们和车辆导航。将会有越来越多基于这种设备访问技术构建的令人兴奋的创新。

在本章中，我们将研究地理位置 API 和 DeviceOrientation API，解决跨浏览器问题，并看看我们如何将设备访问与流行的基于位置的服务一起使用。

# 获取您的位置

目标浏览器：Android、iOS、webOS、Opera、Firefox

使用地理位置 API，我们可以返回当前位置的纬度、经度和精度等值：

+   纬度和经度：这些属性是地理坐标，以十进制度数指定

+   精度：表示纬度和经度坐标的精度级别，以米为单位指定

## 准备就绪

让我们创建一个 HTML 文档，并获取纬度和经度以及精度。首先，让我们创建一个新的 HTML 文件，并将其命名为`ch05r01.html`。

## 如何做...

将以下代码输入到 HTML 文档中：

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
<div id="someElm">
</div>
</div>
<script src="img/jquery-1.5.2.min.js"></script>
<script>
function getLocation() {
navigator.geolocation.getCurrentPosition(showInfo);
}
function showInfo(position) {
var latitude = position.coords.latitude;
var longitude = position.coords.longitude;
var accuracy = position.coords.accuracy;
$('#someElm').html('latitude: '+latitude+'<br />longitude: '+longitude+'<br />accuracy: '+accuracy);
}
getLocation();
</script>
</body>
</html>

```

当您首次渲染它时，您将收到以下消息提示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_02.jpg)

地理位置支持是可选的。没有浏览器会自动将设备的物理位置发送到服务器。相反，它会在执行发送设备位置的程序之前征求您的许可。浏览器可以记住您的偏好，以防止它再次从同一网站弹出。

现在按下允许分享位置的按钮。然后，您将在屏幕上看到显示的位置数据如下：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_03.jpg)

## 它是如何工作的...

`navigator`是 JavaScript 程序员所熟悉的对象。它通常用于用户代理检测：`navigator.userAgent`。

`geolocation`是`navigator`对象上的一个新属性：`navigator.geolocation`。

`getCurrentPosition`是`navigator.geolocation`的一个方法。在这个例子中，我们将函数`showInfo`作为第一个参数执行：

```html
navigator.geolocation.getCurrentPosition(showInfo);

```

在`showInfo`函数中，我们从`position`参数返回三个值，即`纬度、经度`和`精度`：

```html
var latitude = position.coords.latitude;
var longitude = position.coords.longitude;
var accuracy = position.coords.accuracy;

```

## 还有更多...

那么，前面提到的属性是地理位置 API 可能返回的全部吗？从理论上讲，可以返回更多的信息，但实际上，只有选定的浏览器会返回额外的信息。

# 处理跨浏览器地理位置

目标浏览器：跨浏览器

地理位置在所有移动浏览器上都不起作用，即使对于支持它的浏览器，它们的 API 也可能与标准不同。iOS 和 Android 使用标准。已知具有不同 API 的浏览器包括 Blackberry、Nokia 和 Palm。幸运的是，我们有一个移动中心的地理位置填充——**geo-location-javascript**。它具有非标准的 Blackberry 和 webOS 技巧，以帮助规范不同的 API 行为。

## 准备工作

下载本章附带的资源，并创建一个`js`文件夹。将`geo.js`放入`js`文件夹中。现在创建一个名为`ch05r02.html`的 HTML 文档。

## 如何做...

将以下代码输入 HTML 文档中：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/gears_init.js" type="text/javascript" charset="utf-8"></script>
<script src="img/geo.js" type="text/javascript" charset="utf-8"></script>
</head>
<body>
<div id="main">
<div id="someElm">
</div>
</div>
<script src="img/jquery-1.5.2.min.js"></script>
<script>
if(geo_position_js.init()){
geo_position_js.getCurrentPosition(success_callback,error_callback,{enableHighAccuracy:true,options:5000});
}
else{
$('#someElm').html("Functionality not available");
}
function success_callback(p)
{
$('#someElm').html('latitude: '+p.coords.latitude+'<br />longitude: '+p.coords.longitude+'<br />accuracy: '+p.coords.accuracy);
}
function error_callback(p)
{
$('#someElm').html('error='+p.message);
}
</script>
</body>
</html>

```

在 Opera 中进行测试，您应该能够看到以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_05.jpg)

## 它是如何工作的...

在 HTML 文档的顶部，我们链接到`gears_init.js`。如果浏览器没有默认支持的地理位置 API，但安装了 Gears，则 Gears API 可能会返回地理位置数据。对于具有地理位置 API 但使用不同方法的浏览器，将使用第二个脚本`geo.js`来规范化 API。

如果`geo_position_js.init()`返回 true，则意味着我们以某种方式能够获取地理位置数据。在这种情况下，我们将继续下一步。我们使用`geo_position_js.getCurrentPosition`作为方法，而不是使用`navigator.geolocation.getCurrentPosition`：

```html
geo_position_js.getCurrentPosition(showInfo,error_callback,{enableHighAccuracy:true,options:5000});

```

## 还有更多...

这是一个额外的资源，可以帮助您获取地理位置信息。

### YQL Geo 库

YQL Geo 库提供了一种替代方法，即基于 IP 地址的地理位置。这是一个轻量级库，与 Yahoo 服务相关联。它可以：

+   从文本中获取地理位置

+   从纬度/经度获取位置信息

+   从特定 URL 获取所有地理位置

+   从 IP 号码获取地点

# 根据您的地理位置显示地图

目标浏览器：跨浏览器

Google Maps API V3 已经设计成在移动设备上快速加载并在移动设备上运行良好。特别是，我们专注于为 iPhone 和运行 Android 操作系统的手机等先进移动设备开发。移动设备的屏幕尺寸比桌面上的典型浏览器小。此外，它们通常具有特定于这些设备的特定行为，例如 iPhone 上的“捏合缩放”。

## 准备工作

让我们创建一个在您的移动设备上显示的地图。首先，让我们创建一个名为`ch05r03.html`的 HTML 文档。

## 如何做...

输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
<script type="text/javascript" src="img/js?sensor=true"></script>
<script src="img/gears_init.js"></script>
<script src="img/geo.js"></script>
<style>
html {
height: auto;
}
body {
height: auto;
margin: 0;
padding: 0;
}
#map_canvas {
height: auto;
position: absolute;
bottom:0;
left:0;
right:0;
top:0;
}
</style>
</head>
<body>
<div id="map_canvas"></div>
<script src="img/jquery-1.5.2.min.js"></script>
<script>
var initialLocation;
var siberia = new google.maps.LatLng(60, 105);
var newyork = new google.maps.LatLng(40.69847032728747, -73.9514422416687);
var browserSupportFlag = new Boolean();
var map;
var infowindow = new google.maps.InfoWindow();
function initialize() {
var myOptions = {
zoom: 12,
mapTypeId: google.maps.MapTypeId.ROADMAP
};
map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);
if(geo_position_js.init()){
browserSupportFlag = true;
geo_position_js.getCurrentPosition(function(position) {
initialLocation = new google.maps.LatLng(position.coords.latitude,position.coords.longitude);
contentString = "you are here";
map.setCenter(initialLocation);
infowindow.setContent(contentString);
infowindow.setPosition(initialLocation);
infowindow.open(map);
});
}
}
function detectBrowser() {
var useragent = navigator.userAgent;
var mapdiv = document.getElementById("map_canvas");
if (useragent.indexOf('iPhone') != -1 || useragent.indexOf('Android') != -1) {
mapdiv.style.width = '100%';
mapdiv.style.height = '100%';
} else {
mapdiv.style.width = '600px';
mapdiv.style.height = '800px';
}
}
detectBrowser();
initialize();
</script>
</body>
</html>

```

在您的移动浏览器中呈现如下：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_06.jpg)

## 它是如何工作的...

现在让我们来分解代码，看看每个部分的作用：

1.  iPhone 具有捏合缩放功能，Google Maps API V3 对此事件有特殊处理。因此，您可以设置以下元标记，以确保用户无法调整 iPhone 的大小。运行软件版本 1.5（杯子蛋糕）的 Android 设备也支持这些参数：

```html
<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />

```

1.  将包含地图的`<div>`设置为 100%的宽度和高度属性：

```html
mapdiv.style.width = '100%';
mapdiv.style.height = '100%';

```

1.  您可以通过检查 DOM 中的`navigator.userAgent`属性来检测 iPhone 和 Android 设备：

```html
function detectBrowser() {
var useragent = navigator.userAgent;
var mapdiv = document.getElementById("map_canvas");
if (useragent.indexOf('iPhone') != -1 || useragent.indexOf('Android') != -1 ) {
mapdiv.style.width = '100%';
mapdiv.style.height = '100%';
} else {
mapdiv.style.width = '600px';
mapdiv.style.height = '800px';
}
}

```

1.  指定传感器参数，使用传感器确定用户位置的应用程序在加载 Maps API JavaScript 时必须传递`sensor=true`。

```html
<script type="text/javascript" src="img/js?sensor=true"></script>

```

使用 Google Maps API 需要指示您的应用程序是否使用传感器（例如 GPS 定位器）来确定用户的位置。这对于移动设备尤为重要。在包含 Maps API JavaScript 代码时，应用程序必须将所需的传感器参数传递给`<script>`标记，指示您的应用程序是否使用传感器设备。

### 提示

请注意，即使我们针对的设备不使用传感器设备，我们仍然必须传递此参数，并将其值设置为`false`。

1.  我们将地理位置坐标解析到地图 API 的`LatLng`方法中：

```html
initialLocation = new google.maps.LatLng(position.coords.latitude,position.coords.longitude);

```

### 还有更多...

您可以在官方文档页面了解更多关于 Google Maps JavaScript API V3 的信息：

[`code.google.com/apis/maps/documentation/javascript/`](http://code.google.com/apis/maps/documentation/javascript/)

#### HTML5 地理位置教程

Mobile tuts 有一篇关于移动地理位置的优秀文章，名为*HTML5 Apps: Positioning with Geolocation*。您可以在以下链接阅读：

*HTML5 Apps: Positioning with Geolocation*

[`mobile.tutsplus.com/tutorials/mobile-web-apps/html5-geolocation/`](http://mobile.tutsplus.com/tutorials/mobile-web-apps/html5-geolocation/)

# 实时显示位置

目标浏览器：跨浏览器

除了`getCurrentPosition`，地理位置 API 还有另一个名为`watchPosition`的方法。当调用时，它执行两个重要的操作：

1.  它返回一个标识监视操作的值。

1.  它异步地开始监视操作。

## 准备工作

让我们创建一个名为`ch05r04.html`的 HTML 文档。

## 如何做...

将以下代码输入文档中：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
<style>
html {
height: auto;
}
body {
height: auto;
margin: 0;
padding: 0;
}
#map_canvas {
height: auto;
position: absolute;
bottom:0;
left:0;
right:0;
top:0;
}
</style>
</head>
<body>
<div id="map_canvas"></div>
<script type="text/javascript" src="img/js?sensor=true"></script>
<script src="img/jquery-1.5.2.min.js"></script>
<script>
var watchProcess = null;
var initialLocation;
var map;
var infowindow = new google.maps.InfoWindow();
var myOptions = {
zoom: 12,
mapTypeId: google.maps.MapTypeId.ROADMAP
};
map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);
navigator.geolocation.getCurrentPosition(function(position) {
updatePos(position.coords.latitude,position.coords.longitude,position.coords.accuracy);
});
initiate_watchlocation();
function initiate_watchlocation() {
if (watchProcess == null) {
watchProcess = navigator.geolocation.watchPosition(handle_geolocation_query, handle_errors);
}
}
function stop_watchlocation() {
if (watchProcess != null)
{
navigator.geolocation.clearWatch(watchProcess);
watchProcess = null;
}
}
locationdisplaying, in real timefunction handle_errors(error)
{
switch(error.code)
{
case error.PERMISSION_DENIED: alert("user did not share geolocation data");
break;
case error.POSITION_UNAVAILABLE: alert("could not detect current position");
break;
case error.TIMEOUT: alert("retrieving position timedout");
break;
default: alert("unknown error");
break;
}
}
function handle_geolocation_query(position) {
updatePos(position.coords.latitude,position.coords.longitude,position.coords.accuracy);
}
function updatePos(lat,long,acc) {
var text = "Latitude: " + lat + "<br/>" + "Longitude: " + long + "<br/>" + "Accuracy: " + acc + "m<br/>";
initialLocation = new google.maps.LatLng(lat,long);
contentString = text;
map.setCenter(initialLocation);
infowindow.setContent(contentString);
infowindow.setPosition(initialLocation);
infowindow.open(map);
}
</script>
</body>
</html>

```

这是它将如何呈现的：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_04.jpg)

## 它是如何工作的...

以下函数将启动位置监视：

```html
function initiate_watchlocation() {
if (watchProcess == null) {
watchProcess = navigator.geolocation.watchPosition(handle_geolocation_query, handle_errors);
}
}

```

`navigator.geolocation.watchPosition`将在执行时返回成功或错误。在成功函数中，您可以解析纬度和经度：

```html
navigator.geolocation.watchPosition(handle_geolocation_query, handle_errors);

```

当位置正在被监视时，`handle_geolocation_query`用于获取当前位置并解析到更新位置函数中：

```html
function handle_geolocation_query(position) {
updatePos(position.coords.latitude,position.coords.longitude,position.coords.accuracy);
}

```

# 使用 DeviceOrientation 事件

目标浏览器：iOS

`DeviceOrientation`事件是设备访问的重要方面。它包括设备运动事件和设备方向事件。不幸的是，这些事件目前只在 iOS 中受支持。

## 准备工作

创建一个名为`ch05r05.html`的 HTML 文档。

## 如何做...

将以下代码输入文档中：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
<script type="text/javascript" src="img/js?sensor=true"></script>
<style>
#no {
display: none;
}
#ball {
width: 20px;
height: 20px;
border-radius: 10px;
background-color: red;
position:absolute;
top: 0px;
left: 0px;
}
</style>
</head>
<body>
<div id="content">
<h1>Move the Ball</h1>
<div id="yes">
<p>Move your device to move the ball.</p>
<div id="ball"></div>
</div>
<div id="no">
Your browser does not support Device Orientation and Motion API. Try this sample with iPhone, iPod or iPad with iOS 4.2+.</div>
</div>
<script>
// Position Variables
var x = 0;
var y = 0;
// Speed - Velocity
var vx = 0;
var vy = 0;
// Acceleration
var ax = 0;
var ay = 0;
var delay = 10;
var vMultiplier = 0.01;
if (window.DeviceMotionEvent==undefined) {
document.getElementById("no").style.display="block";
document.getElementById("yes").style.display="none";
} else {
window.ondevicemotion = function(event) {
ax = event.accelerationIncludingGravity.x;
ay = event.accelerationIncludingGravity.y;
}
setInterval(function() {
DeviceOrientation eventusingvy = vy + -(ay);
vx = vx + ax;
var ball = document.getElementById("ball");
y = parseInt(y + vy * vMultiplier);
x = parseInt(x + vx * vMultiplier);
if (x<0) { x = 0; vx = 0; }
if (y<0) { y = 0; vy = 0; }
if (x>document.documentElement.clientWidth-20) { x = document.documentElement.clientWidth-20; vx = 0; }
if (x>document.documentElement.clientWidth-20) { x = document.documentElement.clientWidth-20; vx = 0; }
if (y>document.documentElement.clientHeight-20) { y = document.documentElement.clientHeight-20; vy = 0; }
ball.style.top = y + "px";
ball.style.left = x + "px";
}, delay);
}
</script>
</body>
</html>

```

## 它是如何工作的...

这段代码是由*Maximiliano Firtman*制作的（[`www.mobilexweb.com/blog/safari-ios-accelerometer-websockets-html5`](http://www.mobilexweb.com/blog/safari-ios-accelerometer-websockets-html5)）。在示例中，我们使用了`accelerationIncludingGravity`。它返回设备的总加速度值，包括用户加速度和重力。

三个值 x，y，z 分别代表每个轴上的加速度（以 m/s² 为单位）：

```html
window.ondevicemotion = function(event) {
event.accelerationIncludingGravity.x
event.accelerationIncludingGravity.y
event.accelerationIncludingGravity.z
}

```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_05_07.jpg)

## 还有更多...

这是一个显示当前对`DeviceOrientationEvent`和`DeviceMotionEvent`支持的表格：

| 属性 | 描述 | 返回值 | 类 | 支持 |
| --- | --- | --- | --- | --- |
| `acceleration` | *用户给设备的加速度。* | *x，y，z（以 m/s² 为单位）* | `DeviceMotion Event` | *iPhone 4 / iPod Touch 4G* |
| `acceleration IncludingGravity` | *设备的总加速度，包括用户加速度和重力。* | *x，y，z（以 m/s² 为单位）* | `DeviceMotion Event` | *iPhone3 / iPod Touch 3G* |
| `interval` | *自上次设备运动事件以来的毫秒间隔。* | *毫秒* | `DeviceMotion Event` | *iPhone3 / iPod Touch 3G* |
| `rotationRate` | *设备的旋转速率。* | *alpha，beta 和 gamma（值在 0 到 360 之间）* | `DeviceMotionEvent` | *iPhone 4 / iPod Touch 4G* |
| `alpha` | *设备框架绕其 z 轴旋转的角度。* | *值在 0 到 360 之间。* | `DeviceOrientation Event` | *iPhone 4 / iPod Touch 4G* |
| `beta` | *设备框架绕其 x 轴旋转的角度。* | *值在-180 到 180 之间。* | `DeviceOrientation Event` | *iPhone 4 / iPod Touch 4G* |
| `gamma` | *设备框架绕其 y 轴旋转的角度。* | *值在-90 到 90 之间。* | `DeviceOrientation Event` | *iPhone 4 / iPod Touch 4G* |

### 设备方向事件规范

[`dev.w3.org/geo/api/spec-source-orientation.html`](http://dev.w3.org/geo/api/spec-source-orientation.html)

### Safari 官方指南

`DeviceOrientation`事件规范：

[`developer.apple.com/library/safari/#documentation/SafariDOMAdditions/Reference/DeviceMotionEventClassRef/DeviceMotionEvent/DeviceMotionEvent.html`](http://developer.apple.com/library/safari/#documentation/SafariDOMAdditions/Reference/DeviceMotionEventClassRef/DeviceMotionEvent/DeviceMotionEvent.html)

`DeviceOrientationEvent`类参考：

[`developer.apple.com/library/safari/#documentation/SafariDOMAdditions/Reference/DeviceOrientationEventClassRef/DeviceOrientationEvent/DeviceOrientationEvent.html`](http://developer.apple.com/library/safari/#documentation/SafariDOMAdditions/Reference/DeviceOrientationEventClassRef/DeviceOrientationEvent/DeviceOrientationEvent.html)

# 使用 foursquare 的地理位置

目标浏览器：跨浏览器

近年来，基于地理位置的社交网络网站 foursquare 变得越来越受欢迎。它影响了许多企业的工作方式和消费者的行为。用户使用移动网站、移动应用程序或短信在各个地方“签到”。

## 准备工作

第三方开发人员已发布了许多用于从各种编程语言访问 foursquare API 的库。其中之一是 Marelle。它基于 jQuery，用 coffeescript 编写。别担心，那只是 JavaScript。

## 如何做...

转到 Marelle 的 GitHub 页面（[`praized.github.com/marelle/`](http://praized.github.com/marelle/)）并下载最新版本。有两个示例，一个是登录，另一个是签到。

这是登录脚本的样子：

```html
// Supply your foursquare client id
var FSQUARE_CLIENT_ID = 'FOURSQUARE_CLIENT_ID';
// on DOM ready...
$(function() {
// setup with your key and a callback function which
// receives the Marelle Object ( "M" in this example )
$.Marelle( FSQUARE_CLIENT_ID ).done( function( M ){
// grab an authentication promise
var authpromise = M.authenticateVisitor();
// handle logged-in visitor
var authsuccess = function(visitor){
M.signoutButton( document.body );
console.log(visitor)
/*
I think the single entry point is through the visitor
*/
venuepromise = visitor.getVenues()
// venuepromise.then etc..etc...
};
// handle non visitor
var authfailure = function() {
M.signinButton( document.body );
};
// wait for promise to resolve
authpromise.then(authsuccess,authfailure)
}).fail(function(){
consoloe.log('Marelle could not be loaded.')
});
});

```

## 它是如何工作的...

它是如何工作的：

1.  首先触发 Marelle 初始化`$.Marelle(clientID)`，它会返回一个承诺：

```html
$.Marelle( FSQUARE_CLIENT_ID )

```

1.  然后我们使用`$.Marelle.authenticateVisitor()`获取认证承诺：

```html
$.Marelle( FSQUARE_CLIENT_ID ).done( function( M ){
var authpromise = M.authenticateVisitor();
});

```

1.  根据认证的结果，`authpromise.then()`用于执行`authsuccess`或`authfailure`：

```html
authpromise.then(authsuccess,authfailure)

```

1.  如果认证成功，它会将“断开连接”按钮附加到提供的选择器：

```html
M.signoutButton( document.body );

```

1.  可以返回推荐场所的列表，添加或搜索场所：

```html
venuepromise = visitor.getVenues()

```

1.  如果认证失败，它会将“连接”按钮附加到提供的选择器：

```html
M.signinButton( document.body );

```

### 还有更多..

可以在以下网址找到 foursquare API 的列表：

[`developer.foursquare.com/docs/libraries.html`](http://developer.foursquare.com/docs/libraries.html)


# 第六章：移动丰富媒体

在本章中，我们将涵盖：

+   从移动浏览器播放音频

+   在移动设备上流式传输视频

+   使用 Appcache 进行离线查看

+   使用 Web Storage 进行 Feed 或电子邮件应用程序

+   使用 web workers 进行大量计算工作

+   创建类似 Flash 的导航，使用会话和历史 API

# 介绍

使用 HTML5，您可以构建丰富的媒体应用程序以在移动设备上显示。使用 HTML5 的方式有无限种，唯一的限制是想象力。

在之前的章节中，我们已经涵盖了 HTML5 的语义命名、CSS3 和设备访问类别。在本章中，我们将介绍另外三个类别：

+   **多媒体**—越来越多的人在移动设备上播放视频和音频，我们将看到如何在移动设备上嵌入这些元素。

+   **离线和存储**—离线是移动设备的重要功能，因为连接在移动设备上并不一直稳定。存储对于移动设备存储数据以减少用户每次访问页面时的获取是有用的。

+   **性能和集成**—在 iOS 和 Blackberry 上支持 web workers，我们可以在移动浏览器上获得更好的性能。

# 在移动设备上播放音频

目标浏览器：iOS、Android、Blackberry、webOS、Opera Mobile、Firefox Mobile

多媒体包括音频和视频。在移动设备上播放音频可能会有些棘手。在移动浏览器上有一些支持的音频格式—Ogg Vorbis、MP3 和 WAV。这些格式的问题之一是并非所有浏览器都支持它们。

## 准备工作

创建一个 HTML 文档并将其命名为`ch06r01.html`。

## 如何做...

在文档中输入以下代码：

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
<audio src="img/snake_charmer.mp3" controls preload="auto" autobuffer>
</audio>
</div>
</body>
</html>

```

现在在浏览器中渲染时，您将看到一个音乐播放器显示如下，当您按下播放时，音乐应该会流式传输：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_05.jpg)

## 它是如何工作的...

使用音频标签非常简单。音频被包含在`<audio></audio>`标签中。

`controls` 告诉音频元素显示可视控件，如暂停、播放等。

`autobuffer`让浏览器处理缓冲和流式传输。`autobuffer`属性具有布尔值。如果它在音频标签中；音频将自动缓冲。`preload=auto`使流式传输在播放之前甚至预加载。

在移动设备上音频流式传输的一个问题是格式支持。下表显示了支持比较：

| 浏览器 | Ogg Vorbis | MP3 | WAV |
| --- | --- | --- | --- |
| Android WebKit | Yes | Yes |   |
| Opera Mobile |   | Yes |   |
| Firefox Mobile | Yes |   | Yes |
| iOS Safari |   | Yes | Yes |

如表所示，支持一直不够一致。这对于跨浏览器音频流式传输可能会很麻烦。您可以使用多个轨道来解决这个问题。如果浏览器无法识别第一个源标签中的轨道，它将尝试下一个。正如我们从前面的表中所看到的，最广泛支持的格式是 MP3。

它在大多数移动浏览器中都受支持，除了 Firefox。对于 Firefox，我们可以使用 Ogg，因此以下代码更适用于跨移动浏览器：

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
<audio controls preload="auto" autobuffer>
<source src="img/snake_charmer.mp3" />
<source src="img/snake_charmer.ogg" />
</audio>
</div>
</body>
</html>

```

## 还有更多...

您可能会问，'那些不支持 HTML5 音频标签的浏览器怎么办？' 有音频 polyfills，但一般来说，我不认为在移动音频中使用 polyfills 有意义。一个原因是因为这些 polyfills 是使用 Flash 制作的，而 Flash Lite 只支持有限的移动设备，如塞班。一个解决方案是在音频标签之前简单地包含一个链接。它不会被支持音频标签的浏览器渲染，但会显示在不支持音频标签的浏览器上。您可以通过在音频标签关闭之前添加一个下载链接来实现：

```html
<div id="main">
<audio controls preload="auto" autobuffer>
<a href="http://resources/snake_charmer.mp3">play or download here</a>
</audio>
</div>

```

现在，如果您在 Windows Phone 上渲染此内容，将显示如下：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_06.jpg)

如果您点击链接，它将简单地由系统的默认音乐播放器打开：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_07.jpg)

### W3C 音频工作组

当前的音频元素缺乏客户端 API。W3C 音频工作组（[`www.w3.org/2011/audio/`](http://www.w3.org/2011/audio/)）成立以解决这个问题。该 API 将支持高级交互应用程序所需的功能，包括在脚本中直接处理和合成音频流的能力。您可以订阅参与讨论：`<public-audio-request@w3.org>`。

# 在移动设备上流媒体视频

目标浏览器：iOS、Android、Blackberry、webOS、Opera Mobile、Firefox Mobile

从桌面平台访问最多的网站之一是视频网站，如[`www.youtube.com`](http://www.youtube.com)和[`www.vimeo.com`](http://www.vimeo.com)。它们有为移动设备优化的版本。视频流是移动设备的重要组成部分。人们喜欢在移动设备上观看视频，尤其是 YouTube 上的短视频。它们需要更少的时间来缓冲，观看完也不需要花费太多时间。那么视频在移动设备上是如何工作的呢？让我们首先创建一个示例。

## 准备工作

创建一个名为`ch06r02.html`的 HTML 文档。

## 如何做...

将以下代码输入 HTML 文档中：

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
<video id="movie" width="320" height="240" preload controls>
<source src="img/test.mp4" />
<source src="img/pr6.webm" type='video/webm; codecs="vp8, vorbis"' />
<source src="img/pr6.ogv" type='video/ogg; codecs="theora, vorbis"' />
<object width="320" height="240" type="application/x-shockwave-flash"data=" http://releases.flowplayer.org/swf/flowplayer-3.2.1.swfflowplayer-3.2.1.swf"> data="flowplayer-3.2.1.swf">
<param name="movie" value=" http://releases.flowplayer.org/swf/flowplayer-3.2.1.swf" />
<param name="allowfullscreen" value="true" />
<param name="flashvars" value='config={"clip": {"url":http://diveintohtml5.info/i//test.mp4", "autoPlay":false, "autoBuffering":true}}' />
<p>Download video as <a href=" http://diveintohtml5.info/i/pr6.mp4">MP4</a>, <a href=" http://diveintohtml5.info/i/pr6.webm">WebM</a>, or <a href=" http://diveintohtml5.info/i/pr6.ogv">Ogg</a>.</p>
</object>
</video>
<p>Try this page in Safari 4! Or you can <a href=" http://diveintohtml5.info/i//test.mp4">download the video</a> instead.</p>
</div>
</body>
</html>

```

现在，如果您在移动浏览器中打开它，您应该看到视频播放器已呈现。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_08.jpg)

## 它是如何工作的...

代码的一部分取自*Mark Pilgrim 的 Dive into HTML5*。您一定会想，这是一项非常艰巨的工作来让视频工作！在这里，让我们看看每个部分的作用。iOS 和 Android 都支持 H.264（`mp4`）格式，添加`webm`和`ogv`版本以确保它也可以在其他桌面和移动设备上呈现。

如果您有多个`<source>`元素，iOS 只会识别第一个。由于 iOS 设备只支持 H.264+AAC+MP4，您必须始终首先列出您的 MP4。这个错误在 iOS 4.0 中已经修复。因此，在这个例子中，我们将`test.mp4`列为第一个。

```html
<source src="img/test.mp4" />
<source src="img/pr6.webm" type='video/webm; codecs="vp8, vorbis"' />
<source src="img/pr6.ogv" type='video/ogg; codecs="theora, vorbis"' />

```

以下是添加的 Flash 回退，以确保不支持 HTML5 视频的站点可以播放视频：

```html
<object width="320" height="240" type="application/x-shockwave-flash"data=" http://releases.flowplayer.org/swf/flowplayer-3.2.1.swfflowplayer-3.2.1.swf"> data="flowplayer-3.2.1.swf">
<param name="movie" value=" http://releases.flowplayer.org/swf/flowplayer-3.2.1.swf" />
<param name="allowfullscreen" value="true" />
<param name="flashvars" value='config={"clip": {"url": "resources http://diveintohtml5.info/i//test.mp4", "autoPlay":false, "autoBuffering":true}}' />
<p>Download video as <a href="test.mp4">MP4</a>, <a href="test.webm">WebM</a>, or <a href="test.ogv">Ogg</a>.</p>
</object>

```

## 还有更多...

*Mark Pilgrim 的 Dive into HTML5*详细介绍了在不同浏览器上呈现视频时遇到的问题。您可以在以下网址阅读：[`diveintohtml5.info/video.html`](http://diveintohtml5.info/video.html)

Android 2.3 之前的版本在 HTML5 视频方面存在一些问题。`<source>`元素上的 type 属性让早期版本的 Android 感到困惑。让它识别视频源的唯一方法是讽刺的是完全省略 type 属性，并确保您的 H.264+AAC+MP4 视频文件的名称以`.mp4`扩展名结尾。您仍然可以在其他视频源上包括 type 属性，因为 H.264 是 Android 2.2 支持的唯一视频格式。这个错误在 Android 2.3 中已经修复。

`controls`属性不受支持。包括它不会产生任何不良影响，但 Android 不会为视频显示任何用户界面控件。您需要提供自己的用户界面控件。至少，您应该提供一个脚本，当用户点击时开始播放视频。这个错误在 Android 2.3 中也已经修复。

# 使用离线缓存

目标浏览器：iOS、Android、Opera Mobile、webOS、Firefox Mobile

除了设备访问之外，离线缓存是移动设备最重要的功能之一。桌面浏览和移动浏览之间最大的区别之一是移动用户总是在行动。与通常使用单一稳定连接的桌面浏览不同，移动浏览可能在移动中进行，在 3G 和 WiFi 之间切换，并在隧道等地方完全离线。离线缓存可以帮助解决因与互联网断开连接而引起的问题。

| 设备 | 支持 |
| --- | --- |
| iOS | 是的（3.2+） |
| Android | 是的（2.1+） |
| Windows Mobile | 否 |
| Blackberry v6.0 及以上 | 否 |
| Symbian 60 | 否 |
| Palm webOS | 是的 |
| Opera Mobile | 是的 |
| Firefox Mobile | 是的 |

## 准备工作

让我们创建一个文本文件并将其命名为`default.appcache`。

## 如何做...

在我们刚刚创建的`default.appcache`文件中，输入以下内容：

```html
CACHE MANIFEST
# version 1
img/apple-touch-icon.png
#img/splash.png
NETWORK:
#http://example.com/api/
FALLBACK:

```

现在创建一个 HTML 文档并将其命名为`ch06r03.html:`

```html
<!doctype html>
<html manifest="default.appcache">
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<img src="img/apple-touch-icon.png" alt="Apple Touch Icon" />
</body>
</html>

```

现在如果你加载页面，禁用互联网连接并重新加载页面。你会发现页面仍然加载。

## 它是如何工作的...

`CACHE MANIFEST`下的任何内容都包括了将被缓存以供离线查看的文件。包含缓存清单文件的文件将自动包含在内，这意味着：

```html
CACHE MANIFEST
# version 1
img/apple-touch-icon.png
#img/splash.png

```

`NETWORK`部分列出了所有你不希望被缓存的 URL。这些是每次重新加载页面时应该加载的文件。这类文件的一个例子是 API 调用。你不希望浏览器缓存动态 API 返回。如果你所有的 API 调用都来自同一个前缀，你不必把它们都包括进来。相反，你只需要包括**前缀**。例如，如果你有以下 URL 列表：

```html
http://example.com/api/?loc=paris
http://example.com/api/?loc=london

```

不要一次添加到列表中，你可以只添加一个：

```html
NETWORK:
http://example.com/api/

```

`FALLBACK`部分是用于列出页面 URL 替换的网络 URL，当浏览器离线或远程服务器不可用时使用。

## 还有更多...

你可能会问为什么我们使用`.appcache`而不是`.manifest`作为扩展名？这是因为`.appcache`是由 WHATWG 推荐的。由于它是一个标准，并且没有浏览器支持的问题，最好使用`.appcache`。

你可能还想知道的一件事是这些扩展是否被浏览器识别。不用担心，以下的`AddType`将帮助`.appcache`和`.manifest`以正确的 MIME 类型呈现。将以下内容添加到`.htaccess`文件中：

```html
AddType text/cache-manifest appcache manifest

```

### Appcache facts

要了解更多关于 Appcache 的信息，可以访问*Appcache Facts*网站（[`appcachefacts.info/`](http://appcachefacts.info/)）。它有关于 Appcache 的许多有用和宝贵的信息。它还维护了一个链接列表，链接到探索 Appcache 的网站：

+   深入了解 HTML5 让我们离线: ([`diveintohtml5.info/offline.html`](http://diveintohtml5.info/offline.html))

+   Google Code 博客 使用 AppCache 启动离线: ([`googlecode.blogspot.com/2009/04/gmail-for-mobile-html5-series-using.html`](http://googlecode.blogspot.com/2009/04/gmail-for-mobile-html5-series-using.html))

+   HTML5 Rocks 使用应用程序缓存的初学者指南: ([`www.html5rocks.com/tutorials/appcache/beginner/`](http://www.html5rocks.com/tutorials/appcache/beginner/))

+   MDN 文档中心 火狐浏览器中的离线资源: ([`developer.mozilla.org/en/offline_resources_in_firefox`](https://developer.mozilla.org/en/offline_resources_in_firefox))

+   Safari 开发者文库 在客户端存储数据: ([`developer.apple.com/library/safari/#documentation/appleapplications/reference/SafariWebContent/Client-SideStorage/Client-SideStorage.html`](http://developer.apple.com/library/safari/#documentation/appleapplications/reference/SafariWebContent/Client-SideStorage/Client-SideStorage.html))

+   缓存清单验证器在线验证器，JSON(P)验证 API 和`TextMate`包：[(http://manifest-validator.com/)](http://(http://manifest-validator.com/))

### WHATWG 的官方描述

如果你想深入了解规范，可以阅读 HTML Living Standard 的官方描述：

[`www.whatwg.org/specs/web-apps/current-work/multipage/ offline.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/)

# 在移动设备上使用 Web 存储

目标浏览器：跨浏览器

Web 存储对离线应用非常有用，特别是新闻订阅或电子邮件 Web 应用。当人们谈论 Web 存储时，他们通常指的是`localStorage`部分。它是一个键/值持久性系统。除了 Web 存储，还有两个 HTML5 存储功能；它们是**索引数据库 API**和**Web SQL 数据库**。

让我们来看看 Web 存储、索引数据库和 Web SQL 数据库的优缺点。

| 存储类型 | 优点 | 缺点 |
| --- | --- | --- |
| *Web Storage* | *简单易用的 API**受主要浏览器支持* | *没有数据隐私* |
| *索引数据库* | *没有类似 SQL 的结构化存储* | *大多数移动浏览器尚不支持**没有 SQL（显然）* |
| *Web SQL Database* | *快速**功能丰富的 SQL 实现**受主要新移动浏览器支持* | *W3C 工作组已经将其暂停了标准* |

从移动浏览器支持的角度来看，Web Storage 得到了最广泛的支持，其次是 Web SQL 数据库。

Web SQL 数据库具有比 Web Storage 更好的功能集。因此，在这个示例中，我们将专注于 Web Storage 和 Web SQL 数据库，而不是索引数据库（至少目前是这样）。

## 准备工作

创建一个 HTML 文档并将其命名为`ch06r04.html`。

## 如何做...

首先，输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/modernizr.custom.54685.js"></script>
</head>
<body>
<section>
<p>Values are stored on <code>keyup</code></p>
<p>Content loaded from previous sessions:</p>
<div id="previous"></div>
</section>
<section>
<div>
<label for="local">localStorage:</label>
<input type="text" name="local" value="" id="local" />
</div>

```

现在我们要添加 JavaScript 部分：

```html
<script>
var addEvent = (function () {
if (document.addEventListener) {
return function (el, type, fn) {
if (el && el.nodeName || el === window) {
el.addEventListener(type, fn, false);
} else if (el && el.length) {
for (var i = 0; i < el.length; i++) {
addEvent(el[i], type, fn);
}
}
};
} else {
return function (el, type, fn) {
if (el && el.nodeName || el === window) {
el.attachEvent('on' + type, function () { return fn.call(el, window.event); });
} else if (el && el.length) {
for (var i = 0; i < el.length; i++) {
addEvent(el[i], type, fn);
}
}
};
}
})();
function getStorage(type) {
var storage = window[type + 'Storage'],
delta = 0,
li = document.createElement('li');
if (!window[type + 'Storage']) return;
if (storage.getItem('value')) {
delta = ((new Date()).getTime() - (new Date()).setTime(storage.getItem('timestamp'))) / 1000;
li.innerHTML = type + 'Storage: ' + storage.getItem('value') + ' (last updated: ' + delta + 's ago)';
} else {
li.innerHTML = type + 'Storage is empty';
}
document.querySelector('#previous').appendChild(li);
}
getStorage('local');
addEvent(document.querySelector('#local'), 'keyup', function () {
localStorage.setItem('value', this.value);
localStorage.setItem('timestamp', (new Date()).getTime());
});
</script>

```

现在在文件的末尾，让我们关闭 HTML 文档：

```html
</section>
</body>
</html>

```

`localStorage`甚至可以在 Dolphin 中使用，这是三星使用的浏览器，可以安装在任何安卓设备上。在 Dolphin 浏览器中渲染页面时，您可以输入任何单词。在这种情况下，如果您输入"hullo world"，一旦您点击刷新，它将显示这些信息：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_03.jpg)

## 它是如何工作的...

正如前面提到的，它真的就是值/键对，您可以使用`set`和`get`方法存储数据。

要设置数据，您可以使用`setItem`方法：

```html
localStorage.setItem('value', this.value);

```

要获取数据，您可以使用：

```html
storage.getItem('value')

```

寻找一个 polyfill？jQuery Offline 是一个不错的离线存储插件。它使用 HTML5 的`localStorage` API 进行持久化。您可以在不支持`localStorage`的浏览器上使用相同的 API。jQuery Offline 将简单地回退到每次向服务器发出请求。您可以在[`github.com/wycats/jquery-offline`](http://github.com/wycats/jquery-offline)了解更多信息。

## 还有更多...

Web SQL 数据库是`localStorage`的替代方案，受到使用 SQL 的人的喜爱。*Remy Sharp*在 github 上有一个非常好的演示，展示了如何使用 Web SQL 数据库。您可以在[`html5demos.com/database`](http://html5demos.com/database)了解更多信息。

### Web Storage 可移植层

Web Storage 可移植层库允许您轻松为支持 HTML5 数据库或 Gears 的浏览器编写离线存储代码。

Gears 是由 Google 开发的早期离线存储系统。它在 IE6 和 IE Mobile 4.0.1 等浏览器上受到支持，但已不再开发。

您可以在以下网址了解更多关于这个库的信息：[`google-opensource.blogspot.com/2009/05/web-storage-portability-layer-common.html`](http://google-opensource.blogspot.com/2009/05/web-storage-portability-layer-common.html)。

### HTML5 存储之争

您可以在以下网址了解更多关于 localStorage vs. IndexedDB vs. Web SQL 的信息：[`csimms.botonomy.com/2011/05/html5-storage-wars-localstorage-vs-indexeddb-vs-web-sql.html`](http://csimms.botonomy.com/2011/05/html5-storage-wars-localstorage-vs-indexeddb-vs-web-sql.html)。

# 使用 Web Workers

目标浏览器：Opera Mobile，Firefox Mobile，iOS5，黑莓

大多数具有 Java/Python/.NET 背景的程序员应该熟悉多线程或并发编程。曾经有人嘲笑 JavaScript 缺乏高级线程，但随着 HTML5 的出现，其 API 已经扩展以允许并发，大大增加了其有效能力！JavaScript 不再只是一种脚本语言。随着越来越多使用 JavaScript 创建的复杂任务，它在处理繁重的前端计算时必须表现得更好。

| 设备 | 支持 |
| --- | --- |
| iOS | 是（5.0+） |
| 安卓 | 否 |
| Windows Mobile | 否 |
| 黑莓 | 是（6.0+） |
| 塞班 | 否 |
| Palm webOS | 否 |
| Opera Mobile | 是 |
| Firefox Mobile | 是 |

## 准备工作

让我们创建一个 JavaScript 文件并将其命名为`math.js`。

## 如何做...

将以下代码输入到文档中：

```html
/* math.js */
function addNumbers(x,y) {
return x + y;
}
function minNumbers(x,y) {
return x - y;
}
/*
Add an eventlistener to the worker, this will
be called when the worker receives a message
from the main page.
*/
this.onmessage = function (event) {
var data = event.data;
switch(data.op) {
case 'mult':
postMessage(minNumbers(data.x, data.y));
break;
case 'add':
postMessage(addNumbers(data.x, data.y));
break;
default:
postMessage("Wrong operation specified");
}
};

```

现在，让我们创建一个 HTML 文档并将其命名为`ch06r05.html`。将以下代码输入到 HTML 文件中：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/modernizr.custom.54685.js"></script>
</head>
<body onload="loadDeals()">
<input type="text" id="x" value="6" />
<br />
<input type="text" id="y" value="3" />
<br />
<input type="text" id="output" />
<br />
<input type="button" id="minusButton" value="Subtract" />
<input type="button" id="addButton" value="Add" />
<script>
if (Modernizr.webworkers){
alert('hi');
}
/* Create a new worker */
arithmeticWorker = new Worker("js/math.js");
/*
Add an event listener to the worker, this will
be called whenever the worker posts any message.
*/
arithmeticWorker.onmessage = function (event) {
document.getElementById("output").value = event.data;
};
/* Register events for buttons */
document.getElementById("minusButton").onclick = function() {
/* Get the values to do operation on */
x = parseFloat(document.getElementById("x").value);
y = parseFloat(document.getElementById("y").value);
message = {
'op' : 'min',
'x' : x,
'y' : y
};
arithmeticWorker.postMessage(message);
}
document.getElementById("addButton").onclick = function() {
/* Get the values to do operation on */
x = parseFloat(document.getElementById("x").value);
y = parseFloat(document.getElementById("y").value);
message = {
'op' : 'add',
'x' : x,
'y' : y
};
arithmeticWorker.postMessage(message);
}
</script>
</body>
</html>

```

在移动浏览器中呈现此页面时，我们可以看到三个字段和两个用于计算的按钮。在以下示例截图中，我输入了 6 和 3，然后按下**添加**按钮，看到 9 显示为结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_01.jpg)

## 它是如何工作的...

我们可以将`math.js`分为三个部分：

+   实际的数学函数

+   从主文件（HTML 文档）获取事件

+   将信息发送到主文件（HTML 文档）

实际的数学函数相当容易理解，`addNumbers`是一个用于加法的函数，`minNumbers`用于减法：

```html
/* math.js */
function addNumbers(x,y) {
return x + y;
}
function minNumbers(x,y) {
return x - y;
}

```

接下来是`onmessage`。这是`math.js`从 HTML 文档获取的信息：

```html
this.onmessage = function (event) {
var data = event.data;
...
};

```

一旦`math.js`工作程序从主文件（HTML 文档）获取信息，它将开始进行数学计算，并通过使用`postMessage`将结果发送回主文件：

```html
switch(data.op) {
case 'mult':
postMessage(minNumbers(data.x, data.y));
break;
case 'add':
postMessage(addNumbers(data.x, data.y));
break;
default:
postMessage("Wrong operation specified");
}

```

在 HTML 文档中也有三个部分，如下所示：

+   创建工作程序

+   将信息发送到工作程序进行数学计算

+   通过工作程序完成数学计算

创建工作程序相当容易。通过调用`new Worker("math.js")`来创建：

```html
/* Create a new worker */
arithmeticWorker = new Worker("js/math.js");

```

要向工作程序发送信息，可以使用与`math.js`中解释的相同的`postMessage`方法。消息本身可以是具有名称/值对的对象：

```html
message = {
'op' : 'min',
'x' : x,
'y' : y
};
arithmeticWorker.postMessage(message);

```

完成工作程序完成数学计算后，我们使用与`math.js`中解释的相同的`onmessage`方法获取信息：

```html
arithmeticWorker.onmessage = function (event) {
document.getElementById("output").value = event.data;
};

```

# 使用会话和历史 API 创建类似 Flash 的导航

目标浏览器：跨浏览器

过去，人们不得不使用哈希标签来伪造 URL，以在 SEO 和平滑的页面转换之间进行妥协。现在，有了历史 API，就不再需要这种黑客行为。使用历史 API 和 Ajax 调用，可以动态更新 URL。

| 设备平台 | 支持 |
| --- | --- |
| iOS | 是（4.2+） |
| Android | 是（2.2+） |
| Windows Mobile | 否 |
| Blackberry | 否 |
| Symbian | 是（5.2+） |
| Palm webOS | 否 |
| Opera Mobile | 否 |
| Firefox Mobile | 是 |

## 准备就绪

让我们创建一个 HTML 文档并将其命名为`ch06r06.html`。

## 如何做...

在 HTML 文档中输入以下代码：

```html
<!doctype html>
<html>
<head>
<title>Mobile Cookbook</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="img/modernizr.custom.54685.js"></script>
<style>
section {width:300px; background:#ccc; padding:5px; margin:20px auto;}
html, body, figure {padding:0; margin:0;}
figcaption {display:block;}
</style>
</head>
<body>
<section id="gallery">
<p class="photonav"><a id="photoprev" href="http://ch06r06_b.html">&lt; Previous</a> <a id="photonext" href="http://ch06r06_a.html">Next ></a></p>
<figure id="photo">
<img id="photoimg" src="img/300" alt="Fer" width="300" height="300"><br />
<figcaption>Adagio, 1982</figcaption>
</figure>
</section>
<script src="img/nav.js"></script>
</body>
</html>

```

现在让我们创建另一个文档并将其命名为`ch06r06_a.html`。将以下代码输入其中：

```html
<p class="photonav"><a id="photoprev" href="http://ch06r06_b.html">&lt; Previous</a> <a id="photonext" href="http://ch06r06_b.html">Next ></a></p>
<figure id="photo">
<img id="photoimg" src="img/301" alt="Fer" width="300" height="300">
<figcaption>Aida, 1990</figcaption>
</figure>

```

现在让我们创建另一个文档并将其命名为`ch06r06_b.html`。将以下代码输入文档：

```html
<p class="photonav"><a id="photoprev" href="http://ch06r06_a.html">&lt; Previous</a> <a id="photonext" href="http://ch06r06_a.html">Next ></a></p>
<figure id="photo">
<img id="photoimg" src="img/299" alt="Fer" width="300" height="300">
<figcaption>Air Cat, 2001</figcaption>
</figure>

```

现在让我们创建一个 JavaScript 文件并输入以下代码。将以下代码中的 URL 替换为您自己的 URL：

```html
function supports_history_api() {
return !!(window.history && history.pushState);
}
function swapPhoto(href) {
var req = new XMLHttpRequest();
req.open("GET",
"http://localhost /work/packt/ch06_code/" +
href.split("/").pop(),
false);
req.send(null);
if (req.status == 200) {
document.getElementById("gallery").innerHTML = req.responseText;
setupHistoryClicks();
return true;
}
return false;
}
function addClicker(link) {
link.addEventListener("click", function(e) {
if (swapPhoto(link.href)) {
history.pushState(null, null, link.href);
e.preventDefault();
}
}, true);
}
function setupHistoryClicks() {
addClicker(document.getElementById("photonext"));
addClicker(document.getElementById("photoprev"));
}
window.onload = function() {
if (!supports_history_api()) { return; }
setupHistoryClicks();
window.setTimeout(function() {
window.addEventListener("popstate", function(e) {
swapPhoto(location.pathname);
}, false);
}, 1);
}

```

现在让我们在移动浏览器中呈现页面。当您单击**上一页**或**下一页**按钮时，页面不会刷新。但是，如果您查看 URL，它们已更新：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-mobi-dev-cb/img/1963_06_04.jpg)

## 它是如何工作的...

`history.pushState`用于将新的 URL 推送到浏览器地址栏：

```html
history.pushState(null, null, link.href);

```

实际的页面导航是对服务器的 Ajax 请求，因此页面永远不会重新加载。但是 URL 将使用以下函数进行更新：

```html
function swapPhoto(href) {
var req = new XMLHttpRequest();
req.open("GET",
"http://192.168.1.11:8080/work/packt/ch06_code/" +
href.split("/").pop(),
false);
req.send(null);
if (req.status == 200) {
document.getElementById("gallery").innerHTML = req.responseText;
setupHistoryClicks();
return true;
}
return false;
}

```

## 还有更多...

要了解有关历史 API 的更多信息，您可以深入研究规范：[`www.whatwg.org/specs/web-apps/current-work/multipage/history.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/history.html)

*Mark Pilgrim*在*Dive into HTML5*中有一个很好的详细解释：[`diveintohtml5.info/history.html`](http://diveintohtml5.info/history.html)

您还可以在*Mozilla's MDC Docs*中了解更多信息：[`developer.mozilla.org/en/DOM/Manipulating_the_browser_history`](https://developer.mozilla.org/en/DOM/Manipulating_the_browser_history)

### 放置小猫

想知道小猫图片来自哪里吗？它来自一个名为[`placekitten.com/`](http://placekitten.com/)的网站。这是一个快速简单的服务，用于获取小猫图片，以便在设计或代码中使用它们作为占位符。
