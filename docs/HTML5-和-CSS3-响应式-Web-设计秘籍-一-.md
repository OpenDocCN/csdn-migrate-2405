# HTML5 和 CSS3 响应式 Web 设计秘籍（一）

> 原文：[`zh.annas-archive.org/md5/C01303DDF6D777B47AE9F2BC988AE6B5`](https://zh.annas-archive.org/md5/C01303DDF6D777B47AE9F2BC988AE6B5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*HTML5 和 CSS3 响应式 Web 设计食谱*为开发人员提供了一个新的工具箱，以保持与这种新技能集的联系。使用本书中清晰的说明，您可以应用和创建响应式应用程序，并为您的 Web 项目提供最新的设计和开发优势，以适应移动设备。本书通过实际示例，以轻松易懂的语气呈现了网站增强的实用配方。获得对响应式 Web 设计的真正理解，以及如何为各种设备创建优化的显示。本书的主题包括响应式元素和媒体、响应式排版、响应式布局、使用媒体查询、利用现代响应式框架、开发移动优先的 Web 应用程序、优化响应式内容，以及使用 JavaScript 和 jQuery 实现不显眼的交互。每个配方都包含您可以应用的实际代码行。

# 本书涵盖的内容

第一章，*响应式元素和媒体*，涵盖了优化为移动设备或台式电脑的元素的创建。

第二章，*响应式排版*，教你如何使用流体排版，创建酷炫的文本效果，并通过 HTML5 画布和 CSS3 创建在屏幕上突出的文本。

第三章，*响应式布局*，教你如何创建真正可以在项目中使用的响应式布局。您将学习使用视口和媒体查询，使您的网页项目对不同的视口大小和类型做出响应。

第四章，*使用响应式框架*，教你如何使用新的框架快速可靠地部署具有最新响应式方法和交互的响应式网站，并将旧的静态框架转换为响应式框架。

第五章，*制作移动优先的 Web 应用程序*，教你如何制作移动 Web 版本的 Web 应用程序，使用 jQuery Mobile 进行移动优先优化，以及如何优化桌面视口。

第六章，*优化响应式内容*，教你获取和使用构建和测试响应式网页项目所需的所有工具。

第七章，*不显眼的 JavaScript*，教你如何编写不依赖于网页的 JavaScript，以便为不同设备实现周到的响应交互。

# 本书所需内容

您将需要一个集成开发环境（IDE）；推荐使用 NetBeans 或 Eclipse（内部有获取 IDE 的说明），图像编辑软件如 Photoshop 或 GIMP，Web 主机和本地 Web 服务器如 Apache 或本地托管应用程序如 XAMPP 或 MAMPP。

# 本书适合对象

这本书适用于今天所有的无线互联网设备，适用于寻求提供快速、直观的与最新移动互联网设备交互的创新技术的 Web 开发人员。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“`height: auto`属性用于保持图像的纵横比。”

代码块设置如下：

```html
<p class=”text”>Loremipsum dolor sit amet…</p>
<div class=”img-wrap”>
  <img alt=”robots image” class=”responsive” src=”robots.jpg”>
  <p>Loremipsum dolor sit amet</p>
</div>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
<!DOCTYPE HTML>
<html>
     <head>
          <style>
     .rotate {
/* Chrome, Safari 3.1+*/
-webkit-transform: rotate(-90deg);
/* Firefox 3.5-15 */
-moz-transform: rotate(-90deg);
/* IE9 */
-ms-transform: rotate(-90deg);
/* Opera 10.50-12*/
-o-transform: rotate(-90deg);
/* IE */
transform: rotate(-90deg);
}
          </style>
     </head>
     <body >
          <p class=”rotate”>I think, therefore I am </p>
     </body>
</html>
```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这种方式出现在文本中：“然而，我真正想要的是一个大图像，所以我点击**搜索工具**，然后点击**任意大小**，我将其更改为**大**。”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：响应式元素和媒体

在本章中，您将学习以下内容：

+   使用百分比宽度调整图像大小

+   使用 cookie 和 JavaScript 创建响应式图像

+   使您的视频响应屏幕宽度

+   使用媒体查询调整图像大小

+   使用媒体查询更改您的导航

+   基于尺寸创建响应式填充

+   使 CSS3 按钮在加载元素上发光

# 介绍

响应式网站设计和媒体是自从我还是学生时 ASCII 艺术出现在公告板上以来，对 Web 开发最激动人心的事情之一。HTML5、CSS3 和 jQuery 的新功能为旧网络带来了新生命，以一种让人兴奋的方式为您的应用程序带来了乐趣。本章包含了几个配方，将帮助您创建响应式 HTML 元素和不同的媒体。

有些配方很简单，有些则更具挑战性。**响应式网页设计**元素所使用的所有代码都在本书中提供，因此没有什么是不可能完成的。所有响应式网页设计配方都将帮助您优化您的网站呈现，为您的观众创造一个令人惊叹的响应式网页体验，无论您使用何种设备类型或尺寸。

# 使用百分比宽度调整图像大小

这种方法依赖于客户端编码来调整大图像的大小。它只为客户端提供一张图片，并要求根据浏览器窗口的大小来渲染图像。当您确信客户端有带宽可以下载图像而不会导致页面加载缓慢时，这通常是首选的方法。

## 准备工作

首先，您需要一张图片。要找到高质量的图像，请使用 Google 图像搜索。例如搜索`robots`，搜索结果给我 158,000,000 个结果，这相当不错。但是，我真正想要的是一张大图像，所以我点击**搜索工具**，然后点击**任何尺寸**，将其更改为**大**。我仍然有 496 万张图片可供选择。

图像应调整大小以匹配最大的可视比例。在图像编辑软件中打开它。如果您还没有图像编辑软件，有许多免费的软件，去下载一个。Gimp 是一款功能强大的图像编辑软件，它是开源的，或者可以免费下载。访问[`www.gimp.org`](http://www.gimp.org)获取这款功能强大的开源图像编辑软件。

## 如何做…

一旦您有了图像编辑软件，打开图像并将图像的宽度更改为 300px。保存新图像，然后将图像移动或上传到您的网站目录。

您的 HTML 应包含图像和一些文本，以演示响应效果。如果您没有时间写自己的生活故事，可以回到互联网上从 Ipsum 生成器获取一些示例文本。访问[`www.lipsum.com`](http://www.lipsum.com)生成一个 Ipsum 文本段落。

```html
<p class="text">Loremipsum dolor sit amet…</p>
<div class="img-wrap" >
     <img alt="robots image" class="responsive" src="img/robots.jpg" >
     <p>Loremipsum dolor sit amet</p>
</div>
```

您的 CSS 应包括一个段落类和一个图像类和一个图像包装器。将段落浮动到左侧，并给它一个宽度为`60%`，图像包装器的宽度为`40%`。

```html
p.text {
     float:left;
     width:60%;
}
div.img-wrap{
     float:right;
     width:40%;
}
```

这将创建一个流体布局，但尚未做任何事情来创建一个响应式图像。图像将保持静态宽度为 300px，直到您添加以下 CSS。然后，在 CSS 中为图像添加一个新类。为其分配`max-width`值为`100%`。这允许宽度根据浏览器宽度的变化而调整。接下来，为该类添加一个动态的`height`属性。

```html
img.responsive {
     max-width: 100%;
     height: auto;
}
```

这将创建一个根据浏览器窗口宽度响应的图像，并为观众提供优化版本的图像。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的电子邮件。

## 工作原理…

图像 CSS 的`responsive`属性强制其占据其父元素的 100％。当父元素的宽度发生变化时，图像会填充该宽度。`height: auto`属性用于保持图像的纵横比。

## 另请参阅

+   *使用 cookie 和 JavaScript 的响应式图像*方法

+   *基于大小创建响应式填充的方法*

# 使用 cookie 和 JavaScript 的响应式图像

响应式图像的宽度可以通过复杂的服务器逻辑进行交付。有时，由于要求，您无法通过最简单的方法实现所需的结果。百分比宽度方法依赖于客户端对大型图像文件进行调整大小。此方法提供了服务器端交付您请求的适当大小的图像。它可能减少服务器负载和带宽，并帮助您解决长时间加载的问题，如果您担心加载缓慢会影响您网站的性能。

## 准备工作

这些方法需要您的服务器对其执行某种逻辑功能。首先，它需要您的服务器上有 PHP。它还要求您创建图像的三个不同大小的版本，并根据客户端的请求将它们提供给客户端。

## 如何做…

JavaScript 很简单。它基于您设备的屏幕尺寸创建一个 cookie。当客户端请求服务器的图像时，它会触发 PHP 代码以传递适当的图像。

```html
<script >
     document.cookie = "screen_dimensions=" + screen.width + "x" + screen.height;
</script>
```

现在，在您的服务器上，在 Web 目录中创建一个`images`文件夹，并在其中创建一个名为`index.php`的 PHP 文件，其中包含以下代码：

```html
<?php
 $screen_w = 0;
 $screen_h = 0;
 $img = $_SERVER['QUERY_STRING'];

 if (file_exists($img)) {

   // Get screen dimensions from the cookie
   if (isset($_COOKIE['screen_dimensions'])) {
     $screen = explode('x', $_COOKIE['screen_dimensions']);
     if (count($screen)==2) {
       $screen_w = intval($screen[0]);
       $screen_h = intval($screen[1]);
     }
   }
   if ($screen_width> 0) {

     $theExt = pathinfo($img, PATHINFO_EXTENSION);

     // for Low resolution screen
     if ($screen_width>= 1024) {
       $output = substr_replace($img, '-med', -strlen($theExt)-1, 
     } 

     // for Medium resolution screen
     else if ($screen_width<= 800) {
       $output = substr_replace($img, '-low', -strlen($theExt)-1, 0);
     }

     // check if file exists
     if (isset($output) &&file_exists($output)) {
       $img = $output;
     }
   }

   // return the image file;
   readfile($img);
 }

?>
```

现在，使用您的图像编辑软件打开您的大图像，并创建两个较小的版本。如果原始版本是 300px，则将下面的两个副本分别制作为 200px 和 100px。然后，分别将它们命名为`robot.png`，`robot-med.png`和`robot-low.png`。将这三个图像上传到`images`文件夹中。

最后，在您服务器的文档根目录中放入以下 HTML 文件：

```html
<!doctype html>
<html>
     <head>
          <title>Responsive Images</title>
          <meta charset="utf-8">
          <script>
   document.cookie = "device_dimensions=" + screen.width + "x" + screen.height;
          </script>
     </head>
     <body>
         <img alt="robot image" src="img/index.php?robot.png">
     </body>
</html>
```

您可以在以下截图中看到该方法的实际效果：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_01.jpg)

虽然此方法仅限于为每个屏幕尺寸提供特定图像，并且不是流动动态的，但它在服务器端提供了与 CSS 媒体查询相同的功能。您可以使用 CSS 对提供的图像进行样式设置，或者使用 JavaScript 对其进行动画处理。它可以与各种方法结合使用，以提供响应式内容。

此方法的代码最初由[`www.html.it/articoli/responsive-images-con-i-cookie/`](http://www.html.it/articoli/responsive-images-con-i-cookie/)的聪明人创建。

## 工作原理…

HTML 文件首先创建一个描述您设备屏幕尺寸的 cookie。当图像元素调用 PHP 文件时，它的工作原理类似于 PHP 中的`include`语句。PHP 文件首先检查文件是否存在，然后读取屏幕宽度的 cookie，并传递图像的适当大小版本。

# 使您的视频响应您的屏幕宽度

视频的流媒体也可以是响应式的。您可以轻松地在页面中嵌入 HTML5 视频并使其响应式。`video`标签很容易支持使用百分比宽度。但是，这需要您在您网站的主机上拥有视频源。如果您有这个可用，这很容易。

```html
<style>
video {
     max-width: 100%;
     height: auto;
}
</style>

<video width="320" height="240" controls="controls">
     <source src="img/movie.mp4" type="video/mp4">
     <source src="img/movie.ogg" type="video/ogg">
     Your browser does not support the video tag.
</video>
```

然而，使用视频托管网站，如 YouTube 或 Vimeo，与自己托管它相比有很多优势。首先，存在带宽问题，您的托管服务器可能有带宽或磁盘空间限制。此外，视频托管网站使上传转换为可用的网络视频变得非常容易，而不仅仅是使用您自己的资源。

## 准备工作

视频托管网站允许您在页面中嵌入 iFrame 或对象代码片段以在您的网站上流式传输视频。这不适用于`video`标签内。因此，为了使其响应式，有一种更复杂但仍然简单的方法。

## 如何做…

将视频源片段包装在包含`div`元素的 HTML 中，并在底部给它 50 到 60％的填充和相对位置。然后给它的子元素，视频 iFrame 对象，一个`100%`的宽度和`100%`的高度，并且一个`absolute`位置。这样可以使 iFrame 对象完全填充父元素。

以下是使用`iframe`标签从 Vimeo 获取视频的 HTML 代码：

```html
<div class="video-wrap">
     <iframe src="img/52948373?badge=0" width = "800" height= "450" frameborder="0"></iframe>
</div>
```

以下是使用旧版 YouTube 对象的 HTML 代码：

```html
<div class="video-wrap">
    <object width="800" height="450">
       <param name="movie" value="http://www.youtube.com/v/b803LeMGkCA?version=3&amp;hl=en_US">
         </param>
         <param name="allowFullScreen" value="true"></param>
         <param name="allowscriptaccess" value="always"></param>
         <embed src="img/b803LeMGkCA?version=3&amp;hl=en_US" type="application/x-shockwave-flash" width="560" height="315" allowscriptaccess="always" allowfullscreen="true">
          </embed>
     </object>
</div>
```

两种视频类型使用相同的 CSS：

```html
.video-wrap {
     position:relative;
     padding-bottom: 55%;
     padding-top: 30px;
     height: 0;
     overflow:hidden;
}
.video-wrap iframe,
.video-wrap object,
.video-wrap embed {
     position:absolute;
     top:0;
     width:100%;
     height:100%;
}
```

您可能不希望视频占据整个页面的宽度。在这种情况下，您可以使用`width`和`max-width`限制视频的宽度。然后，用另一个`div`元素包装`video-wrap`元素，并分配一个固定的`width`值和`max-width:100%`。

```html
<div class="video-outer-wrap">
     <div class="video-wrap">
          <iframe src="img/6284199?title=0&byline=0&portrait=0" width="800" height="450" frameborder="0">
          </iframe>
     </div>
</div>

.video-outer-wrap {
     width: 500px;
     max-width:100%;
}
```

这个方法适用于所有现代浏览器。

## 它是如何工作的...

这种方法被称为视频的固有比率，由 Thierry Koblentz 在 A List Apart 上创建。您将视频包裹在具有固有纵横比的元素内，然后给视频一个绝对位置。这样可以锁定纵横比，同时允许尺寸是流体的。

# 使用媒体查询调整图像大小

媒体查询是另一种有用且高度可定制的响应式图像方法。这与通过百分比宽度方法实现的响应式流体宽度不同。您的设计可能需要不同屏幕尺寸范围的特定图像宽度，而流体宽度会破坏您的设计。

## 准备工作

这种方法只需要一个图像，并且使客户端的浏览器重新调整图像而不是服务器。

## 如何做…

HTML 代码很简单，使用标准图像标签，创建一个图像元素，如下所示：

```html
<img alt="robot image" src="img/robot.png">
```

首先从一个简单版本开始，创建一个媒体查询，以检测浏览器窗口的大小，并为大于`1024px`的浏览器屏幕提供更大的图像，为较小的浏览器窗口提供较小的图像。首先是媒体查询，它寻找媒体类型`screen`，然后是屏幕大小。当媒体查询满足时，浏览器将呈现大括号内的 CSS。

```html
@media screen and ( max-width: 1024px ) {…}
@media screen and ( min-width: 1025px ) {…}
```

现在，为图像标签添加一个类。该类将在不同的媒体查询中有不同的响应，如下面的代码行所示：

```html
<img alt="robot image" src="img/robot.png" class="responsive"/>
```

为每个媒体查询添加不同大小的 CSS 类将使浏览器为每个不同大小的浏览器窗口呈现所需的图像大小。媒体查询可以与其他 CSS 类共存。然后，在媒体查询之外，添加一个带有`height:auto`的图像的 CSS 类。这将适用于只添加一行 CSS 的两个媒体查询。

```html
@media screen and ( max-width: 1024px ) {
img.responsive { width: 200px; }
}
@media screen and ( min-width: 1025px) {
img.responsive { width: 300px;}
}
img.responsive { height: auto; }
```

要使图像响应多个范围，可以结合`max-width`和`min-width`媒体查询。要为浏览器窗口大小在`1024px`和`1280px`之间的屏幕添加媒体查询，添加一个媒体查询为屏幕，`1024px`为`min-width`，`1280px`为`max-width`。

```html
@media screen and ( max-width: 1024px ) {
img.responsive { width: 200px; }
}
@media screen and ( min-width:1025px ) and ( max-width: 1280px ) {
img.responsive { width: 300px; }
}
@media screen and ( min-width: 1081px ) {
img.responsive { width: 400px; }
}
img.responsive { height: auto; }
```

使用媒体查询方法可以为许多不同的浏览器窗口大小指定许多不同的图像大小。

## 它是如何工作的...

CSS3 的媒体查询根据浏览器的视口属性给出您的 CSS 逻辑条件，并且可以根据浏览器的窗口属性呈现不同的样式。这个方法利用了这一点，通过为许多不同的浏览器窗口大小设置不同的图像宽度。因此，可以提供响应式图像大小，并且可以以高度精细的方式进行控制。

# 使用媒体查询更改导航

媒体查询不仅可以调整图像大小，还可以向观众提供更加动态的网页。您可以使用媒体查询根据不同的屏幕尺寸显示响应式菜单。

## 准备工作

为了创建一个响应式菜单系统，使用两个不同的菜单，我们将为三种不同的浏览器窗口大小显示一个动态菜单。

## 如何做...

对于较小的浏览器窗口，特别是移动设备和平板电脑，创建一个简单的`select`菜单，它只占用少量的垂直空间。该菜单使用 HTML`form`元素作为导航选项，当选择时触发 JavaScript 代码以加载新页面。

```html
<div class="small-menu">
     <form>
          <select name="URL" onchange="window.location.href=this.form.URL.options[this.form.URL.selectedIndex].value">
              <option value="blog.html">My Blog</option>
              <option value="home.html">My Home Page</option>
              <option value="tutorials.html">My Tutorials</option>
          </select>
     <form>
</div>
```

对于较大的浏览器窗口大小，创建一个可以通过 CSS 进行样式设置的简单`ul`列表元素。这个菜单将从不同的媒体查询中获得不同的布局和外观。这个菜单被添加到与`select`菜单相同的页面之后：

```html
<div class="large-menu">
     <ul>
          <li>
               <a href="blog.html">My Blog</a>
          </li>
          <li>
               <a href="home.html">My Home Page</a>
          </li>
          <li>
               <a href="tutorials.html">My Tutorials</a>
          </li>
     </ul>
</div>
```

为了使菜单具有响应性，为目标浏览器窗口大小创建媒体查询。对于小于`800px`的浏览器窗口，CSS 将仅显示带有`small-menu`类的`div`元素内的`select`表单，对于所有较大的浏览器窗口，CSS 将显示带有`large-menu`类的`div`元素内的`ul`列表。这会在浏览器窗口跨过`801px`的宽度时创建一个效果，页面将在菜单之间切换。

```html
@media screen and ( max-width: 800px ) {
.small-menu { display:inline; }
.large-menu { display:none; }
}
@media screen and ( min-width: 801px ) and ( max-width: 1024px ) {
.small-menu { display:none; }.
.large-menu { display:inline; }
}
@media screen and ( min-width: 1025px ) {
.small-menu { display:none; }
.large-menu { display:inline; }
}
```

对于较大的屏幕尺寸，您可以使用相同的`ul`列表，并进一步使用媒体查询来提供不同的菜单，只需切换 CSS 并使用相同的 HTML 即可。

对于中等大小的菜单，使用 CSS 将列表项显示为水平列表，如下面的代码片段所示：

```html
.large-menu ul{ 
     list-style-type:none; 
}
.large-menu ul li { 
     display:inline; 
}
```

这将把列表转换为水平列表。我们希望这个版本的导航出现在中等大小的浏览器窗口上。将其放在介于`801px`和`1024px`之间的媒体查询中，如下面的代码片段所示：

```html
@media screen and ( min-width: 801px ) and (max-width: 1024px ) {
     .small-menu { 
          display:none; 
     }
.large-menu { 
          display:inline; 
     }
.large-menu ul { 
          list-style-type:none; 
     }
.large-menu ul li {
          display:inline;
     }
}
@media screen and (min-width: 1025px ) {
.small-menu { 
          display:none; 
     }
     .large-menu { 
          display:inline; 
     }
}
```

为了更好地利用响应式导航元素，我们希望菜单列表版本在屏幕宽度变化时移动到不同的布局位置。对于中等宽度，`801px`到`1024px`，菜单保持在页面顶部，并且宽度为`100%`。当屏幕宽度大于`1025px`时，菜单将浮动到其父元素的左侧。在`801px`到`1024px`的媒体查询中，为`large-menu`类添加`100%`的宽度，在`1025px`的媒体查询中，为`large-menu`类添加`20%`的宽度和`float:left`的值。

为了填充页面，我们还将添加一个包裹在`div`元素中的文字段落。您可以返回到 Lorem Ipsum 文本生成器创建占位文本（[`lipsum.com/`](http://lipsum.com/)）。在中等宽度的媒体查询中，给包含段落的元素一个`100%`的宽度。在最大的媒体查询中，给包含段落的元素一个`80%`的宽度，并将其浮动到其父元素的右侧。

```html
<div class="small-menu">
     <form>
          <select name="URL" onchange="window.location.href=this.form.URL.options[this.form.URL.selectedIndex].value">
              <option value="blog.html">My Blog</option>
              <option value="home.html">My Home Page</option>
              <option value="tutorials.html">My Tutorials</option>
          </select>
     <form>
</div>

<div class="large-menu">
     <ul>
          <li>
               <a href="blog.html">My Blog</a>
          </li>
          <li>
               <a href="home.html">My Home Page</a>
          </li>
          <li>
               <a href="tutorials.html">My Tutorials</a>
          </li>
     </ul>
</div>

<div class="content">
     <p>Loremipsum dolor sitamet, consecteturadipiscingelit…</p>
</div>
```

您的样式应该如下所示：

```html
<style>
@media screen and ( max-width: 800px ) {
     .small-menu { 
          display: inline; 
     }
     .large-menu { 
          display: none; 
     }
}
@media screen and ( min-width: 801px ) and ( max-width: 1024px ) {
     .small-menu { 
          display: none; 
     }
     .large-menu { 
          display:inline; 
          width: 100%; 
     }
     .large-menu ul { 
          list-style-type: none; 
     }
     .large-menu ul li { 
          display: inline; 
     }
     .content: { 
          width: 100%; 
     }
}
@media screen and ( min-width: 1025px ) {
     .small-menu { 
          display: none; 
     }
     .large-menu { 
          display: inline; 
          float: left; 
          width: 20%;
     }
     .content{
          float: right;
          width: 80%;
     }
}
</style>
```

最终结果是一个页面，其中包含三种不同版本的导航。当为每个特定的浏览器窗口大小提供优化版本的菜单时，您的受众将感到惊讶。您可以在以下截图中看到导航元素的所有精彩之处：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_02.jpg)

## 它是如何工作的...

每个导航版本都利用了媒体查询 CSS3 属性，以最大化菜单和内容的可用空间。在最小的窗口下，低于`1024px`，导航被整齐地放置在`select`表单元素内。中等窗口，范围从`1025px`到`1280px`，导航是内联的，并横跨页面顶部，后面是内容。最后，在最宽的浏览器宽度下，菜单浮动在左侧，并且只占据水平屏幕空间的 20%，而内容则最大化占据剩余的 80%（右侧）的宽广浏览器窗口。这种技术需要更多的规划和努力，但为了向您的受众提供最佳的观看体验，这是非常值得的。

# 基于大小创建响应式填充

为了补充响应式宽度图像元素，可以添加相对填充。使用静态宽度填充，图像填充可能在较小的浏览器窗口中显得太厚，并且会挤满附近的任何其他元素，或者可能将图像推出屏幕。

## 做好准备

一个很好的开始是对盒模型属性的计算有一些了解。对象占用的总宽度是其实际宽度加上其两侧的填充、边框和边距，或者*2 x (margin + border + padding) + content = total width*。

## 如何做…

对于一个在其正常非响应状态下宽度为 200px 的图像，您的典型填充可能为 8px，因此使用先前的盒模型，公式可以表述如下：

`2 x ( 0 + 0 + 8px ) + 200px = 216px`

要找到填充的百分比，将填充除以总宽度，`8 / 216 = 0.037%`四舍五入为`4%`。

我们之前创建了这个 CSS 和 HTML，当我们创建了响应式百分比宽度的图片时。在图像类中添加`4%`的填充。

```html
<style>
p.text {
      float: left;
      width: 60%;
   }
div.img-wrap{
      float: right;
      margin: 0px;
      width: 38%;
   }
img.responsive {
      max-width: 100%;
      height: auto;
      padding: 4%;
   }
</style>

<p class="text">ipsum dolor sit amet, consecteturadi…</p>
<div class="img-wrap">
     <img alt="robot image" class="responsive" src="img/robot.png">
     <p>ipsum dolor sit amet, consecteturadipiscingelit…</p>
</div>
```

为了帮助您看到实际填充宽度随着更改浏览器窗口大小而改变，将背景颜色（`background-color: #cccccc;`）添加到您的图像 CSS 中。

## 它是如何工作的…

设置为 100%的图像填充将粘附在其父元素的边缘。随着父元素大小的变化，图像填充会相应调整。如果您正确计算了盒模型数学，您的布局将成功响应浏览器窗口的宽度变化。

# 使 CSS3 按钮在加载元素时发光

您的网站，像许多其他网站一样，可能迎合着急的人。如果您的网站有一个可提交的表单，如果您的页面加载新内容的速度不够快，您的用户可能会不耐烦地多次点击“提交”按钮。当它导致多次提交相同数据的表单时，这可能会成为一个问题。

## 做好准备

您可以通过添加一些简单的视觉提示来阻止这种行为，告诉用户幕后正在发生一些事情，并且要有点耐心。如果有点花哨，甚至可能会给他们匆忙的生活带来一点阳光。这个配方不需要任何图像，我们将只使用 CSS 创建一个漂亮的渐变提交按钮。您可能需要暂停一下，去喝杯咖啡，因为这是本章中最长的配方。

## 如何做…

您可以先创建一个带有一些文本框和提交按钮的表单。然后，使表单真的很酷，使用 HTML5 的占位符属性作为标签。即使有了占位符，表单还是相当无聊。

请注意，这在 Internet Explorer 9 中尚不受支持。

```html
<h1>My Form<h1>
<form>
     <ul>
        <li>
          <input type="text" placeholder="Enter your first name"/>
        </li>
        <li>
          <input type="text" placeholder="Enter your last name"/>
        </li>
     </ul>
<input type="submit" name="Submit" value="Submit">
</form>
```

通过添加 CSS 属性，我们可以开始为按钮赋予一些生命：

```html
input[type="submit"] {
     color: white;
     padding: 5px;
     width: 68px;
     height: 28px;
     border-radius: 5px;
     border: 1px;
     font-weight: bold;
     border: 1px groove #7A7A7A;
}
```

这在以下截图中有所说明：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_03.jpg)

当我们添加 CSS3 渐变效果时，按钮甚至可以变得更加闪亮。为了实现这一点，必须为每个浏览器渲染引擎添加不同的 CSS 行：Opera、Internet Explorer、WebKit（Chrome 和 Safari）和 Firefox。您可以通过添加`color`相位和从顶部的`%`位置，每个移位之间用逗号分隔，来添加尽可能多的渐变移位，如下面的代码片段所示：

```html
<style>
input[type="submit"] {
     background: -moz-linear-gradient(top, #0F97FF 0%, #97D2FF 8%,#0076D1 62%, #0076D1 63%, #005494 100%);
     background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#0F97FF), color-stop(8%,#97D2FF)color-stop(50%,#0076D1), color-stop(51%,#0076D1), color-stop(100%,#005494));
     background: -webkit-linear-gradient(top, #0F97FF 0%,#97D2FF 8%,#0076D1 62%,#0076D1 63%,#005494 100%);
     background: -o-linear-gradient(top, #0F97FF 0%,#97D2FF 8%,#0076D1 62%,#0076D1 63%,#005494 100%);
     background: -ms-linear-gradient(top, #0F97FF 0%,#97D2FF 8%,#0076D1 62%,#0076D1 63%,#005494 100%);
     background: linear-gradient(to bottom, #0F97FF 0%,#97D2FF 8%,#0076D1 62%,#0076D1 63%,#005494 100%);filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#0f97ff', endColorstr='#005494',GradientType=0 );
}
</style>
```

这个效果在以下截图中有所说明：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_04.jpg)

CSS 还可以为按钮添加`hover`效果。使用此属性，当指针移动到按钮上时，它看起来就像被按下了。以下 CSS 将帮助您为按钮添加那个深色边框：

```html
input[type="submit"]:hover {
   border: 2px groove #7A7A7A;
}
```

这在以下截图中显示：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_05.jpg)

使用 CSS3 Box Shadows 和 jQuery，我们可以制作一个简单的动画，在您按下**提交**按钮后，围绕按钮出现脉动的光环。使用 jQuery 创建一个事件监听器，监听按钮的`click`事件，在该`click`事件上，对表单按钮元素进行一系列类更改。脚本将向按钮元素添加`partial-fade`类。

### 提示

不要忘记在`head`标签中添加到 jQuery 源的链接：

```html
<scriptsrc="img/jquery-latest.js"></script>
```

然后，在表单关闭后插入以下脚本：

```html
<script >
//Submit Glow
$('input[type="submit"]').click(function() {
$(this).addClass('partial-fade');
   $(this).animate({
      opacity: 0.1
   }, 8).animate({
       opacity: 0.9
   }, 226).animate({
       opacity: .5
   }, 86);
   setTimeout(function () {
      $('input[type="submit"]').removeClass('partial-fade');
   }, 366).animate({
       opacity: 1
   }, 86);
});
</script>
```

要完成按钮在点击时发光，需要在 CSS 文件中添加新的类`partial-fade`，并给它一个 CSS3 Box Shadow 属性，并改变边框属性。

```html
<style>
input[type="submit"].partial-fade {
     border-top: 1px solid #CFF !important;
     border-right: 1px solid #CCF !important;
     border-left: 1px solid #CCF !important;
     border-bottom: 1px solid #6CF !important;
     -webkit-box-shadow: 0 08px 0px #0F97FF, inset 0 0 20px rgba(37, 141, 220, 1);
     -moz-box-shadow: 0 0 8px 0px #0F97FF, inset 0 0 20px rgba(37,141,220,1);
     box-shadow: 0 0 8px 0px #0F97FF, inset 0 0 20px rgba(37, 141, 220, 1);
}
</style>
```

现在，**提交**按钮在按下时会闪烁蓝色。下面的截图显示了最终产品：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_01_06.jpg)

哇！为了这样一个小细节，这个按钮需要做很多工作，但是这样的细节确实会帮助制作出一个看起来很棒的网站。这恰好是我最喜欢用来给我的观众一个惊喜的细节之一。

## 工作原理…

CSS3 背景渐变是一种在各种浏览器中制作出一个看起来很棒的按钮的简单方法。渐变很复杂，每个浏览器目前都需要自己的 CSS 行。您可以通过手动添加百分比和颜色来控制渐变的断点。添加盒阴影、边框和 jQuery 可以在事件触发时给按钮带来有趣的效果。


# 第二章：响应式排版

在本章中，您将学习以下内容：

+   创建流畅、响应式的排版

+   用 canvas 制作文本阴影

+   用 canvas 制作内部和外部阴影

+   用 canvas 旋转您的文本

+   用 CSS3 旋转您的文本

+   用 CSS3 制作 3D 文本

+   用 CSS3 文本遮罩为您的文本添加纹理

+   使用 nth 位置伪类为交替行添加样式

+   在伪元素之前和之后添加字符

+   使用相对字体大小制作按钮

+   为您的字体添加阴影

+   用边框半径弯曲一个角

# 介绍

这一章主要讨论如何制作响应式排版。您将学习为各种类型的设备优化文本的配方，以及装饰文本的方法。涉及的技术只是 CSS3 和 HTML5 的`canvas`元素与 JavaScript。通过响应式排版，您可以为文本应用许多令人兴奋的效果。

完成本章后，您将掌握一些技术，可以让您开始制作令人惊叹的响应式网站。这些配方涵盖了基础知识，但结合一些创造力，它们将使您能够做一些出色的作品。

# 创建流畅、响应式的排版

这个配方是响应式排版的一个简单示例。它将演示新的尺寸单位`REM`的使用。`REM`表示根 EM。这意味着字体的大小是相对于根字体大小而不是父元素的大小，就像`EM`单位一样。

## 准备工作

没有更多讨论，让我们开始这个配方。从我最喜欢的 Ipsum 生成器([`ipsum.com`](http://ipsum.com))获取一些填充文本。生成至少一个段落，并将文本复制到剪贴板中。

## 如何做…

现在，将填充文本粘贴到您的 HTML 文档中，并将其包装在一个段落标记中。给段落元素`class="a"`，然后复制并分配新段落`class="b"`，如下面的代码片段所示：

```html
<p class="a">
     Lorem ipsum dolor sit amet, consectetur adipiscing elit.
<p>

<p class="b">
     ultricies ut viverra massa rutrum. Nunc pharetra, ipsum ut ullamcorper placerat,
<p>
```

接下来，为基本 HTML 的`font-size`属性创建一个样式，然后为静态大小的段落创建一个样式，以便比较字体大小的变化——类似于实验的对照组：

```html
html{font-size:12px;}
p.b{font-size:1rem;}
```

接下来创建两个`@media`查询，一个用于`orientation:portrait`，另一个用于`orientation:landscape`。在`orientation:portrait`媒体查询中，使用`font-size`值为`3rem`为`"a"`类段落元素添加样式。在`orientation:landscape`媒体查询中，使用`font-size`值为`1rem`为`"a"`类段落添加样式。

```html
@media screen and (orientation:portrait){
p.a{font-size:3rem;}
}
@media screen and (orientation:landscape){
p.a{font-size:1rem;}
}
```

现在，当您将浏览器窗口从横向模式调整为纵向模式时，您会看到第一个段落的字体大小从 1:1 的比例变为基本大小，再到基本大小的 3:1。虽然这看起来非常简单，但这个配方可以变化并构建，以创建许多令人印象深刻的响应式排版技巧。

## 它是如何工作的…

当您的浏览器发出请求时，CSS3 的`@media`查询根据视口的宽度返回一些条件样式。它会根据视口大小的变化实时加载或构建（重建）。虽然您的受众中不会有很多人在浏览器中花费大量时间调整您的网站大小，但很容易花费过多时间担心您的网站从一个大小变化到另一个大小。

## 另请参阅

+   *使用相对字体大小制作按钮*配方

# 用 canvas 制作文本阴影

HTML5 为网页设计带来了一个新元素，即`<canvas>`元素。这是用 JavaScript 在网页上实时创建图形的。

## 准备工作

`<canvas>`元素在您的页面上创建一个矩形区域。它的默认尺寸为 300px x 150px。您可以在 JavaScript 中指定不同的设置。这个配方中的代码增长很快，所以您可以在 Packt Publishing 的网站上找到整个代码。

## 如何做…

首先，创建一个带有`<canvas>`元素的简单 HTML 页面：

```html
<!DOCTYPE HTML>
<html>
     <head>

     </head>
     <body>
           <canvas id="thecanvas"></canvas>
     </body>
</html>
```

JavaScript 从 DOM 中获取`canvas`元素。

```html
var canvas = document.getElementById('thecanvas');
```

然后调用`getContext()`方法。`getContext('2d')`方法是内置的 HTML5 对象。它有许多方法可以绘制文本、形状、图像等。

```html
var ctx = canvas.getContext('2d');
```

接下来，开始在 JavaScript 中绘制文本。在这里，我们创建一个代码来绘制水平和垂直阴影偏移、模糊和阴影的颜色。

```html
ctx.shadowOffsetX = 2;   
ctx.shadowOffsetY = 2;
ctx.shadowBlur = 2;
ctx.shadowColor = "rgba(0, 0, 0, 0.5)";
```

文本及其属性是在 JavaScript 中编写的，但可以作为变量从 DOM 中传递：

```html
ctx.font = "20px Times New Roman"; 
ctx.fillStyle = "Black"; 
ctx.fillText("This is the canvas", 5, 30); 
```

回到 HTML，在`body`元素中添加`onload="drawCanvas();"`脚本命令。当页面加载时，JavaScript 会触发并将文本及其阴影绘制到画布上。如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_01.jpg)

## 它是如何工作的…

不要深入 JavaScript 的细节，`canvas`元素提供了一个地方，让设计者可以在页面加载时直接向页面上添加一些内容。`body`元素的`onload="drawCanvas();"`命令触发 JavaScript，将内容绘制到画布上。

## 另请参阅

+   *使用画布旋转文本*食谱

# 使用画布制作内部和外部阴影

这个食谱还使用`canvas`和 JavaScript 在浏览器中绘制文本和效果。使用`canvas`没有直接的方法来制作内发光或内阴影效果，但是使用描边方法，你可以在文本中模拟内部阴影。

## 准备工作

这个食谱从一些已经写好的代码开始。你可以从 Packt Publishing 的网站上下载。这也是你在食谱中创建的相同代码，*使用画布制作文本阴影*。这段代码应该在你的本地计算机上运行，不需要任何特殊的 Web 服务器。你可以在书的网站上在线获取整个代码。

## 如何做…

首先，创建一个带有`<canvas>`元素的简单 HTML 页面。

```html
<html>
  <head>

  </head>
  <body>
    <canvas id="thecanvas"></canvas>
  </body>
</html>
```

JavaScript 从 DOM 中获取`canvas`元素。

```html
var canvas = document.getElementById('thecanvas');
```

然后调用`getContext()`方法。`getContext('2d')`方法是内置的 HTML5 对象。它有许多方法可以绘制文本、形状、图像等。

```html
var context = canvas.getContext('2d');
```

这个脚本使用多种效果组合来制作内部和外部阴影。首先，在左上角添加一个投影，并将其设为黑色，`context.shadowBlur`值为`2`。在此基础上，在`context.fillText`之后，将`context.strokeStyle`和`context.strokeText`添加到画布上下文。

```html
context.shadowOffsetX = -1;   
context.shadowOffsetY = -1;   
context.shadowBlur = 2;   
context.shadowColor = "#888888";   
context.textAlign = "left";
context.font = "33px Times New Roman";  
context.fillStyle = "#666";   
context.fillText("This is the Canvas", 0, 50); 
context.strokeStyle = "#555";
context.strokeText("This is the canvas", 2, 50); 
context.linewidth = 2;
```

文本看起来不是凸起的，而是内凹的，并具有内部发光或阴影效果。该效果显示在下面的截图中：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_03.jpg)

## 它是如何工作的…

正如本食谱开头所述，画布中没有真正的直接方法来制作内部阴影，但有办法使用`context.fillText`和`context.strokeStyle`方法一起使用，可以创建出看起来足够像内部阴影的东西。

# 使用画布旋转文本

HTML5 画布方法不仅可以给文本上色或添加阴影，还可以用来移动或操纵画布区域中的对象。在这个食谱中，我们将旋转画布中的对象。

## 准备工作

这个食谱是在之前的食谱基础上构建的。如果你跳过了它们，没关系，你可以回到之前的食谱参考完整的代码。

## 如何做…

一旦你设置好了之前食谱的画布，旋转的基本步骤就很容易了。在函数的开头添加一个`rotate`方法：

```html
context.rotate(Math.PI/4,0,0);
```

你可能会注意到文本已经旋转出了画布。发生了什么？`rotate`方法旋转整个画布，并不知道其中有什么。

画布的默认大小是 300px x 150px。更改元素的大小属性不会影响画布的大小，但会扭曲在其上绘制的对象。要改变画布和绘制的对象的大小，可以在 JavaScript 中添加`canvas.width`和`canvas.height`属性：

```html
canvas.width=250;
canvas.height=250;
```

此外，由于`canvas`完全旋转自身，而不是文本围绕一个原点旋转，因此文本位置需要重新定位到所需的位置。在这种情况下，更改填充和描边的对象偏移量：

```html
context.fillText("This is the Canvas", 140, 1); 
context.strokeText("This is the Canvas ", 140, 1);
```

如下截图所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_04.jpg)

## 工作原理

JavaScript 使用`rotate`方法来旋转整个`canvas`元素以及其中绘制的所有内容。在使用`canvas`的`rotate`方法时需要一些事先考虑。它很复杂，但是在大型响应式 Web 项目中使用是完美的工具。

## 另请参阅

+   *使用 CSS3 旋转文本* 配方

# 用 CSS3 旋转文本

CSS3 提供了一种简单的方法来旋转文本。`transform:rotate`属性易于实现，并且在项目不需要`canvas`的复杂性时提供了一个简单的解决方案。

## 准备工作

在您的 HTML 文档中写一行文本。做好准备，您将要用 CSS3 旋转它。

## 操作步骤

将文本放在段落标签元素中：

```html
 <p class="rotate">I think, therefore I am</p>
```

然后，添加 CSS `transform`属性来旋转文本。每个浏览器呈现方式都不同，因此每个浏览器都需要自己独特的`transform`属性。但是，每个浏览器都将使用`transform`属性的子属性`rotate`，后跟旋转的度数，如下面的代码片段所示：

```html
<!DOCTYPE HTML>
<html>
     <head>
          <style>
     .rotate {
/* Chrome, Safari 3.1+*/
-webkit-transform: rotate(-90deg);
/* Firefox 3.5-15 */
-moz-transform: rotate(-90deg);
/* IE9 */
-ms-transform: rotate(-90deg);
/* Opera 10.50-12*/
-o-transform: rotate(-90deg);
/* IE */
transform: rotate(-90deg);
}
          </style>
     </head>
     <body >
          <p class="rotate">I think, therefore I am </p>
     </body>
</html>
```

## 工作原理…

`transform` 属性将 2D 或 3D 变换应用于元素。其他可用的属性更改包括 `move`、`skew` 和 `perspective`。

## 另请参阅

+   *使用 canvas 旋转文本* 配方

# 使用 CSS3 制作 3D 文本

在以前的示例中，我们使用`canvas`元素创建了投影阴影、斜角和内部阴影。使用 CSS3，我们可以做到让您的文本真正脱颖而出。使用 CSS3 的`text-shadow`属性，我们可以让您的文本看起来好像是从屏幕上朝向观众突出。

## 准备工作

如果您想要跳过，可以在 Packt Publishing 的网站上在线获取代码。否则，如果您是通过实践学习的类型，让我们制作我们的 3D 文本。我们通过使用 CSS3 阴影效果的组合来创建 3D 效果。

## 操作步骤

在您的 IDE 中，创建一个只有标题的新 HTML 文档。在`head`标签中添加一个`style`部分，并将标题分配为`color:#f0f0f0;`，如下面的代码片段所示：

```html
<style>
     h1{ color: #f0f0f0;}
</style>
```

现在，为其添加一系列七个逐渐增加和减少的 X 和 Y 位置的`text-shadow`属性，从`0px 0px0px #666`到`-6px -6px 0px #666`。

```html
text-shadow: 0px 0px0px #666,
-1px -1px 0px #666, 
-2px -2px 0px #666,
-3px -3px 0px #666,
-4px -4px 0px #666,
-5px -5px 0px #666,
-6px -6px 0px #000,
```

您的标题现在几乎跳出屏幕。好吧，几乎！为了确保它真的脱颖而出，让我们给它一些更多的效果。在屏幕上构建任何 3D 对象时，重要的是要给予一致的光照和阴影。由于这个文本上升，它需要一个阴影。

再添加一系列六个 X 和 Y 位置的`text-shadow`属性，只是这一次给它们正值和一个较浅的颜色（`color:#ccc;`）。

```html
1px 1px 5px #ccc, 
 2px 2px 5px #ccc,
 3px 3px 5px #ccc,
 4px 4px 5px #ccc,
 5px 5px5px #ccc,
 6px 6px 5px #ccc;
```

投影阴影是有道理的，但它看起来仍然有点假，好吧，让我们把它提升到另一个水平；让我们模糊和加深背景上的元素。在`text-shadow`属性中的第三个数字创建了模糊效果，因此按照以下代码中所示添加逐渐增加的模糊：0、0、1、1、2、3 和 5。还要将颜色更改为越往后越暗：`#888`、`#777`、`#666`、`#555`、`#444`、`#333` 和 `#000`。

```html
text-shadow:0px 0px0px #888,
-1px -1px 0px #777, 
-2px -2px 1px #666,
-3px -3px 1px #555,
-4px -4px 2px #444,
-5px -5px 3px #333,
-6px -6px 4px #000,
```

现在您的标题具有真正逼真的 3D 效果。如下截图所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_06.jpg)

## 工作原理

尝试并尝试这个配方的变化，以获得一些非常令人兴奋的排版效果。CSS3 为排版设计带来了全新的兴奋和深度，这是以前很难实现的，而且做得很好。

`text-shadow`属性可以处理多个阴影属性。因此，您可以将它们堆叠在一起，使它们离文本越来越远。这样可以为您的文本创建 3D 效果。

# 使用文本遮罩为您的文本添加纹理

CSS3 还为你提供了使用图像为文本添加图像蒙版纹理的强大功能。以前只能通过使用图像编辑软件创建文本的静态图像来实现这种效果。

## 准备工作

你需要一张图像作为纹理蒙版。使用图像编辑软件创建一个带有 alpha 通道的新图像。如果你没有能够创建带有 alpha 通道的 PNG 图像的图像编辑软件，你可以在[`www.gimp.org`](http://www.gimp.org)下载一个开源的免费图像编辑软件 GIMP。为了快速创建纹理效果，使用散射型刷子在图像顶部附近创建一个纹理区域。

将其保存为 PNG 图像类型，在 web 主机的`images`目录中保留 alpha 通道。

## 如何做…

创建一个包含要应用纹理蒙版的文本的标题元素的 HTML。然后，在其中添加一些文本：

```html
<h1 class="masked">I think, therefore I am</h1>
```

然后，添加你的 CSS 标记。这将包括一个大字体大小（展示你的蒙版纹理！），白色字体颜色，填充和对齐，当然还有图像蒙版属性。

### 提示

请注意，每个浏览器都需要为该属性添加自己的前缀。

```html
 h1.masked{
      font: 140px "Arial";
      color: white;
      -webkit-mask-image: url(images/mask2.png);
      -o-mask-image: url(images/mask2.png);
      -moz-mask-image: url(images/mask2.png);
      mask-image: url(images/mask2.png);
      text-shadow: 0px 0px 10px #f0f0f0;
      width: 100%;
      padding: 12% 0 12%;
      margin:0;
      text-align: center;
     }
```

CSS 效果显示在以下截图中：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_07.jpg)

## 它是如何工作的…

蒙版图像根据蒙版图像的 alpha 值剪切元素的可见部分。当在 CSS 中应用于文本时，它将剪切掉蒙版部分。这与图像编辑软件的 alpha 通道图层的工作方式非常相似。

# 使用 nth 位置伪类样式交替行

CSS3 中的位置伪类提供了简单的 CSS 解决方案，解决了以前需要繁琐解决方案的问题。直到最近，要为列表或表的交替行设置样式，如果你有幸能够在具有某种逻辑的服务器上工作，你至少可以在列表中迭代计数，或者如果不幸的话，你必须手动编号你的行。

## 准备工作

CSS3 的解决方案非常简单。首先，创建你的 HTML 值列表。这不一定需要一个命名空间类，因为你可能希望这是你站点中的一个通用样式：

```html
       <ul>
           <li>
               I think, therefore I am
           </li>
           <li>
               I think before I act
           </li>
           <li>
               I think I can, I think I can
           </li>
       </ul>
```

## 如何做…

为列表项`<li>`添加一个*n*th 位置伪类奇数值的 CSS 属性。给它一个背景颜色和字体颜色的值，这些颜色与你的默认颜色方案明显不同。

```html
  ul{
width:100px;
  }
  li:nth-of-type(odd){
background-color:#333;
color:#f0f0f0;
  }
```

这将自动地为你的列表的奇数行设置样式！以下截图说明了这种效果：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_08.jpg)

现在深呼吸；那么容易！

## 它是如何工作的…

根据[`www.w3.org`](http://www.w3.org)，`:nth-of-type(an+b)`伪类符号表示具有在其之前具有相同扩展元素名称的*an+b-1*个兄弟元素的元素，在文档树中，对于*n*的任何零或正整数值，并且具有父元素。

那是什么意思？这意味着只要它在同一个父元素内具有类似的兄弟元素，你可以输入一个类似*(-n+2)*的公式来为兄弟元素的最后两行设置样式，或者保持简单，奇数或偶数，并通过 CSS 样式这些行。

# 在伪元素之前和之后添加字符

在 CSS 的一个新属性中，似乎失落了一集*The Twilight Zone*，它给了你在内容中添加伪标记的能力。尽管听起来很奇怪，但这种样式有令人惊讶的用例。你可能想在你的内容中加引号，而不必处理额外的编码麻烦来放置引号在你的内容或主题文件中，这当然是明智的做法。或者你可能想加入 Twitter 及其 hash 标签和`@`标记的流行，你可以在你的内容之前加上`#`或`@`符号，只需使用 CSS 标记，如下面的代码行所示：

```html
#I think, therefore I am#
```

## 准备工作

这不需要任何服务器端逻辑或任何花哨的动作。你只需要能够在本地主机上启动页面，看到它的运行情况。

## 如何做...

这只需要使用 CSS 就可以实现，因此你在 HTML 中需要创建的只是一个包裹目标内容的`class`或`id`属性：

```html
<h2 class="hashtag">I think, therefore I am</h2>
```

CSS 标记只是稍微复杂一点，插入的符号遵循内容的边距和填充规则。它使用了*n*th `class:before`和`class:after`伪类。因此，`before`的 CSS 是`.class:before {content:"#";}`。只需用你想要使用的符号替换`#`。对于`after`，用`.class:before{}`替换`.class:after{}`。

```html
.hashtag {
     border:1px solid #ccc;
     display:block;
     width:200px;
     height:10px;
           }
.hashtag:before{
     content:"#";
           }
.hashtag:after{
     content:"#";
           }
```

## 它是如何工作的...

CSS 中的`before`和`after`伪元素生成元素内容之前或之后的内容。请注意，它们不是真正的内容或元素，不能用于标记或 JavaScript 事件触发。

# 使用相对字体大小制作按钮

有几种情况可以使用响应式按钮字体大小。一个很好的例子是你网站的移动版本。当在 iPhone 上查看普通按钮时，它非常小，难以点击。我们最不希望做的就是通过我们对移动设备的忽视来给移动设备用户创造糟糕的体验。

## 准备工作

这个配方的目标是使用新的字体度量`REM`来制作一个响应式按钮字体大小，当在移动设备上查看时会变大。

`REM`是 CSS3 中引入的一个新单位，它代表根`EM`，或者相对于根字体大小。这与相对于父元素的`EM`不同。一种使用它的方法是将某些元素的大小设置为 body 字体的基本大小。

## 如何做...

它可以与`@media`查询一起使用，为你的桌面和移动设备构建一个响应式按钮。下面是具体操作。

首先，创建一个简单的 HTML 页面，包含一些填充文本（[`lipsum.com`](http://lipsum.com)）和一个`input`类型为`submit`的元素。

```html
<div>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum vehicula enim at dolor ultricies ut viverra massa rutrum. Nunc pharetra, ipsum ut ullamcorper placerat,
</p>
     <input type="submit">
</div>
```

接下来，在 HTML 的基本字体大小上添加 CSS，设置为`62.5%`，并为段落添加静态字体大小，作为实验对照组：

```html
html{font-size:62.5%;}
p{font-size:1.4rem;}
```

下一步是为移动设备创建你的`@media`查询，以及两个不同的桌面窗口大小。我添加了一个额外的`@media`查询用于桌面屏幕，所以如果你没有移动设备，你仍然可以看到响应性的效果。

为桌面设备设置两个`@media`查询，分别为`1024px`和`1280px`，为移动设备设置两个，都是`max-device-width:480px`，一个是`orientation:landscape`，另一个是`orientation:portrait`。

```html
@media screen and (min-width:1024px){ } 
@media screen and (min-width:1280px){ } 
@media screen and (max-device-width: 480px) and (orientation:landscape){ } 
@media screen and (max-device-width: 480px) and (orientation:portrait){ } 
```

在你的桌面`@media`查询中，为两者都添加一个`input`元素；并为`min-width:1024px`查询添加一个`font-size:1rem`值，为`min-width:1280px`查询添加一个`font-size:2rem`值。对于这两个查询，添加属性：`width:84px;`和`padding:2%;`。

在移动`@media`查询中，为两者都添加`input`元素。在`orientation:landscape`媒体查询中，分配属性：`font-size:2rem;`和`width:25%;`。在`orientation:portrait`媒体查询中，分配属性：`font-size:2.4rem;`和`width:30%;`。

```html
@media screen and (min-width:1024px){    
           input{
               font-size:1rem;
               width:84px;
               padding:2%;}
       } 
@media screen and (min-width:1280px){    
     input{
          font-size:2rem;
          width:84px;
          padding:2%;
     }
} 
@media screen and (max-device-width: 480px) and 
(orientation:landscape){
     input{
          font-size:2rem;
          width:25%;
          padding:2%;
     }
} 
@media screen and (max-device-width: 480px) and 
(orientation:portrait){  
     input{
          font-size:2.4rem;
          width:30%;
          padding:2%;
     }  
} 
```

现在，当你从移动设备查看这个页面时，你可以看到`REM`大小单位创建了一个相对于基本字体大小的字体。移动设备可能会将字体渲染得非常小，几乎无法阅读，按钮也太小，难以使用。将设备从纵向方向旋转到横向方向，你会看到按钮及其字体大小发生变化。

比较移动设备按钮和桌面版本。你会看到按钮会根据设备类型显示独特的属性。当你在`1024px`和`1280px`之间拖动桌面浏览器窗口时，按钮字体也会发生变化。

## 它是如何工作的...

`REM`字体大小单位创建相对于在`HTML`或`body`元素中声明的基本字体大小的字体大小，或者如果未声明，则相对于字体的内置基本大小。我们编写的`@media`查询为不同的设备和方向提供了新的相对大小。

# 给你的字体添加阴影

使用 CSS3，你可以很容易地为你的文本添加阴影。这个效果可以用来给特殊元素添加突出效果，也可以用在你的`body`文本中，以增强你内容的外观。此外，你可以用它来突出你文本中的链接，帮助它们更加突出。

## 准备工作

CSS3 使这变得很容易，所以不需要太多设置。打开你的开发环境，或者一个记事本程序，然后开始。你也可以在线访问 Packt Publishing 的网页，获取完成的代码并查看其中的内容。

## 如何做...

首先，创建一个文本段落元素；记住你可以从我们喜欢的填充文本生成器[`lipsum.com`](http://lipsum.com)获取。并给文本一个标题头：

```html
<h1>I think therefore I am </h1>
<p>Lorem ipsum dolor sit amet…
</p>
```

在你的段落中，通过在`href`标签中包裹一些单词来插入一些链接：

```html
<h1>I think therefore I am</h1>
<p>Morbi<a href ="#">venenatis</a>Lorem ipsum dolor sit amet… <a href ="#">scelerisque</a> Lorem ipsum dolor sit amet…</p>
```

首先，让我们给你的段落文本添加一个阴影，这是一个简单的 CSS3 `dropshadow`效果，我们可以用在文本上。在你的 CSS 中添加`text-shadow`属性。对于 Internet Explorer，添加`filter`属性。

```html
text-shadow: 1px 1px 2px #333333; 
```

这让你的文本有一个轻微的阴影，使它脱颖而出。对于正文文本，任何超过轻微阴影的效果都会太多。对于你的链接，为了让它们更加突出，我们可以添加多层文本阴影。添加一个类似于前面例子的阴影，然后在逗号后面添加另一个阴影效果。这个例子给链接文本添加了一个浅蓝色的阴影。

```html
text-shadow: 0px 0px 1px blue, 1px 1px 2px #333333; filter: dropshadow(color=blue, offx=1, offy=1);
```

让我们添加一个旧属性，给页面带来新的光芒。让你的链接在伪动作悬停(`:hover`)时闪烁：

```html
p.shadowa:hover{
text-shadow: 0px 0px 8px #ffff00, 2px 2px 3px #666; filter: dropshadow(color=#ffff00, offx=1, offy=1);
}
```

当你悬停在链接上时，这个属性会让段落中的链接闪烁着黄色的光芒。这个效果在下面的截图中有所体现：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_09.jpg)

## 它是如何工作的...

这个食谱是阴影效果的组合。你可以组合多个阴影效果，为你的文本创建逼真的 3D 效果。学习的最佳方法是不断尝试，直到你对你的 3D 效果非常满意。

# 用`border-radius`曲线化一个角

曲线角曾经是网页设计世界的圣杯。它总是可能的，但从来不简单。设计师只能做出有限数量的糟糕选择，来使一个元素拥有曲线角。

## 准备工作

这现在是通过 CSS3 轻松实现的。`border-radius`属性是在元素上创建圆角的简单方法。

## 如何做...

首先创建你的 HTML 元素。这适用于任何可以有边框的元素。所以让我们创建一个段落文本块。你可以在[`lipsum.com`](http://lipsum.com)获取填充文本。

```html
<p class="rounded"> Lorem ipsum dolor sit amet…</p>
```

接下来添加 CSS 来填充段落元素：

```html
.rounded{
           background-color:#ccc;
           width:200px;
           margin:20px;
           padding:20px;
        }
```

然后，为了使角变圆，添加 CSS3 属性`border-radius`。在这个例子中，我使用了`5px`的曲线半径。

```html
border-radius: 5px;
-webkit-background-clip: padding-box; 
background-clip: padding-box;
```

这个属性为你提供了简单和容易的圆角。这对于页面上的浮动元素非常有用。但是如果你只想为菜单元素的顶部角创建圆角怎么办？仍然很容易。

让我们从一个简单的内联列表开始：

```html
<ul class="inline">
     <li class="rounded-top"><a href="#">menu 1</a></li>
     <li class="rounded-top"><a href="#">menu 2</a></li>
     <li class="rounded-top"><a href="#">menu 3</a></li>
     <li class="rounded-top"><a href="#">menu 4</a></li>
</ul>
```

接下来添加 CSS 使列表内联，带有填充和边距：

```html
li.rounded-top{
     display:inline;
     background-color:#ccc;
     margin:3px;
     padding:8px;
}
```

前面例子中的 CSS 为所有角创建了圆角。要有不同的圆角，指定每个角的半径。

```html
      border-radius: 8px 8px 1px 1px;
```

你可以通过指定每个角作为自己的 CSS 属性来实现相同的结果：

```html
border-top-left-radius:8px;
border-top-right-radius:8px;
border-bottom-right-radius:2px;
border-bottom-left-radius:2px;
```

你可以通过添加另一个曲线半径来进一步扩展这一点：

```html
border-top-left-radius:8px 4px;
border-top-right-radius:8px 4px;
border-bottom-right-radius:2px;
border-bottom-left-radius:2px;
```

新的外观如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_02_10.jpg)

为了增加另一个响应级别，尝试用百分比替换曲线半径的条目。回到这个食谱中的第一个例子，将 CSS 更改为具有百分比半径曲线：

```html
border-radius: 1%;
```

## 它是如何工作的...

`border-radius` 属性提供了在元素上绘制曲线的简单方法。这个属性接受四个值，但也可以用只有一个曲线半径的简写格式来书写。


# 第三章：响应式布局

在本章中，你将学习：

+   使用 min-width 和 max-width 属性创建响应式布局

+   使用相对填充控制布局

+   向你的 CSS 添加媒体查询

+   使用媒体查询创建响应式宽度布局

+   使用媒体查询更改图像大小

+   使用媒体查询隐藏元素

+   创建平稳过渡的响应式布局

# 介绍

这一章有一些具有挑战性的示例。响应式布局经常会带来一些困难的挑战，这可能会促使你创造一个很好的解决方案。通过响应式设计方法，你可以做更多的事情，而且更有效率。响应式布局为网页开发引入了全新的挑战领域和新的激动人心的维度。

# 使用 min-width 和 max-width 属性创建响应式布局

许多响应式布局技术可能非常复杂和令人不知所措，但在这个示例中，你将看到应用于三个浮动元素的`min-width`和`max-width`属性的相当简单的布局。通过 CSS 的这个非常简单的响应式布局特性，你可以准备好在各种大小的移动设备和桌面屏幕上显示你的网站。

## 准备工作

在小视口上从多列折叠为一列的浮动元素并不是一个新的技巧。这已经作为 CSS1 的标准属性存在多年了，然而，直到移动设备变得普遍之前，从来没有理由认为它有用。因此，让我们将这个古老的、陈旧的属性与一些其他新鲜的 CSS 属性结合起来，制作一个响应式布局。

## 如何做...

创建一个简单的 HTML 页面，包含在`article`元素中，包含一个`h1`标题和三个元素。第一个元素将包含一个图像，第二个和第三个将包含填充文本。给所有内部元素分配一个`float`类，分别将它们的 ID 分配为`one`、`two`和`three`：

```html
<article>
     <h1>Responsive Layout with min and max width</h1>

     <div class="one float">
        <img src="img/robot.png">
     </div>

     <div class ="two float">Pellentesqueeleifendfacilisisodio ac ullamcorper. Nullamutenimutmassatinciduntluctus...
     </div>

     <div class="three float">Pellentesqueeleifendfacilisisodio ac ullamcorper. Nullamutenimutmassatinciduntluctus. Utnullalibero, …
     </div>
</article>
```

接下来，为`.article`元素创建样式，并分配属性：`width: 100%;`、`max-width: 1280px;`和自动边距。然后，将`h1`标题居中。给`img`元素分配`width: 100%`和`height: auto;`属性，使其对父元素响应。对包含`img`元素的浮动元素，给它一个`min-width`值为`500px`。你也可以给每个浮动元素分配不同的背景颜色，以使它们更加可辨认，但这对布局并不是必要的。对于`.float`类中的所有浮动元素，添加`max-width: 350px`属性，左浮动，并为了清晰的外观，调整文本对齐方式。

```html
<style>
article{
     width: 100%;
     max-width: 1280px;
     margin: 0 auto;
}
h1 {text-align:center;}
img {
     width: 100%;
     height: auto;
}
.one {
     background-color: #333;
     min-width: 500px;
}
.two {background-color:#666}
.three {background-color:#ccc}
.float {
     max-width: 350px;
     float: left;
     text-align: justify;
}
   </style>
```

一旦所有东西都放在一起，你在浏览器中打开 HTML 文档，你会看到布局如何平稳地从三列布局变成两列布局，最后变成单列布局，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_01.jpg)

## 它是如何工作的...

列的`max-width`属性允许它们具有流动但最大宽度。这使得列的布局比静态宽度更加灵活。图像列利用`min-width`属性，因此它可以根据父元素宽度的变化而增长和收缩。最后，整个布局可以通过使用`float`属性从三列平滑地变成一列；一旦元素无法并排浮动，最后一个元素就会跳到新的一行。

# 使用相对填充控制布局

让我们为一个带有评论和评论回复的博客设计一个简单的布局。这可以只使用相对填充来实现。你可能会说，“这太疯狂了！你怎么可能只用填充来控制页面布局？”我们来看看。

## 准备工作

当然，博客比静态 HTML 页面要动态得多，所以这将是你最喜欢的博客软件的评论模板部分的一部分。话虽如此，这个方法非常简单，但却非常有效。所以，去找一些 Ipsum 填充文本，准备好自己吧。

## 如何做…

第一步是创建一个非常简单的博客风格页面，其中评论嵌入在`div`元素中。在你的 HTML body 中，创建一个将包含所有内容的元素，`.content` div。给它一个`h1`标题，一个 Ipsum 填充文本段落，然后跟一个`.comments`元素。在`.comments`元素内，你将构建嵌入式评论布局。

```html
<div class="content">
     <header>Control your layout with relative padding</header>
     <p>
Pellent esque eleifend facilis isodio ac ullam corper. Null amuten imut massat incident luctus. Utnull alibero, el eifend vel ultrices at, volut patquis quam...</p>
     <div class="comments">
          <h2>Comments</h2> No 2 x h1
     </div>
</div>
```

在`.comments`标题下，你将添加你的第一个评论。接下来，在那个评论里，在闭合段落标签后立即添加一个评论：

```html
<aside>
     <h1>Comments</h1>
     <div class="comment">
          <p>
Pellent esque eleifend facilis isodio ac ullam corper. Null amuten imut massat incident luctus. Utnull alibero, et...
          </p>
          <div class="comment">
               <p>
Pellent esque eleifend facilis isodio ac ullam corper. Null amuteni mut massat incident luctus. Ut null alibero, el eifend vel ultrices at, volut patquis quam...
               </p>
          </div>
     </div>
</aside>
```

接着，你可以以同样的方式插入更多的评论到父评论中，或者在父`div`元素之外添加评论，使评论到达父级的父级，一直到原始博客帖子：

```html
<aside>
    <h1>Comments</h1>
      <div class="comment">
        <p>
          Pellent esque el eifend facilis isodio ac ullam corper..
        </p>

      <div class="comment">
        <p>
           Null amuten imut massat incident luctus....
        </p>

      <div class="comment">
        <p>
          Ut null alibero, el eifend velul trices at, volut pat quis quam...
        </p>
      </div>
     </div>
    </div>
   <div class="comment">
       <p>
         Null ameget dui eros, et semper justo. Nun cut condi mentum felis...
       </p>
    </div>
   </div>

</aside>
```

最终，你可以有很多评论和一个漂亮的工作布局，只需使用相对填充就可以构建。

使这个方法生效的 CSS 非常简单。只需添加类：`.content`、`.comments`和`.comment`。在`content`类中添加一些侧边填充，在`comment`中添加更重的左填充。

```html
.content {padding:0 5% 0 5%;}
aside {padding:0 10% 0 20%}
.comment {padding:0 0 0 10%}
```

如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_02.jpg)

## 工作原理…

相对填充属性通过调整自身宽度来响应页面宽度的变化。

# 向你的 CSS 添加媒体查询

在这个方法中，我们将探索媒体查询的强大功能，通过在宇宙中的每个排列和设备上呈现一个简单的网页。好吧，我承认我有点夸张。但我们将创建一个简单的网页，可以响应几种浏览器窗口大小、设备和其他可能的呈现方法。

## 准备工作

仅仅为了这个方法，去购买这里描述的每种设备和变体中的一种。你需要一台新的高清电视，一个智能手机，一个不那么智能的手机，以及至少一台打印机。不可能？好吧，但我只是想帮助你和经济。话虽如此，当然，真正测试每个媒体查询是不可能的，但尽力而为。有惊人的可能性。但在大多数现实场景中，你不太可能需要或关心使用其中大多数。我们至少会尝试覆盖最常用的媒体查询。

我会跳过我认为对你不必要的部分。如果你发现自己在一个项目中需要为这些晦涩的设备之一创建演示文稿，你可以很容易地获取关于这些设备的信息。你永远不知道！WC3 有关于这些设备的详细信息和描述，如果你需要，可以在[`www.w3.org/TR/css3-mediaqueries/`](http://www.w3.org/TR/css3-mediaqueries/)上找到。我将排除示例，仅供参考，包括具有特定颜色限制的许多设备，包括单色、打印、电视和手持设备。你最有可能需要的媒体查询可能是`screen`和`print`。

## 如何做…

创建一个简单的 HTML 页面，包括一个`h1`标题，一个包裹图片的元素，和一个文字段落。如果你没有文本，可以使用 Ipsum 填充文本。它看起来就像下面这样：

```html
<body> 
     <h1>Add Media Query to your CSS</h1>
          <div class="wrap">
               <img src="img/robot.png"/>
Pellent esque el eifend facilisis odio ac ullam corper. Nullam ut enim ut massa tincidunt luctus…
          </div>
</body>
```

接下来创建一系列媒体查询。在下面的列表中，我将简要解释每个查询的作用：

```html
@media print{...}
```

这在打印网页时应用。你可以通过选择**文件** | **打印**，然后查看打印预览来测试这一点。这对用户将其打印为文档阅读的网页非常有用。你可以利用这一点，改变或删除格式，使这个版本尽可能简单。 

```html
@media (orientation: portrait){...}
```

这通常适用于以纵向模式显示文档的任何设备。你可以用它来为移动设备改变不同方向的外观。要小心，因为这也会应用于桌面屏幕，除非你指定它只适用于较小的屏幕或设备。媒体查询方向的其他可能值是横向。

```html
@media (height:500px){...}
```

`height`和`width`媒体查询允许你为特定的屏幕尺寸指定样式。

```html
@media (device-width:500px){...}
```

这个媒体查询将应用样式到任何页面，不管浏览器窗口大小如何，只要在指定尺寸的设备上查看。

```html
@media screen and (device-aspect-ratio: 16/9) {...}
```

这个媒体查询可以用来定义`16/9`比例的屏幕（非打印）的样式。

```html
@media tv {...}
```

这个纵横比只适用于使用电视观看的设备。

```html
@media screen and (max-width:960px){...}
@media screen and (min-width:961px) and (max-width:1280px){...}
@media screen and (min-width:1281px) and (max-width:1336px){...}
@media screen and (min-width:1336px){...}
```

`min-width`和`max-width`媒体查询是最有用的。在这里，你可以为任何窗口大小定义响应式样式，包括小屏幕移动设备。我通常从定义最小的——或移动设备——视口断点开始，并定义它们的样式，然后为最流行的屏幕尺寸创建断点范围，最后使用`min-width`媒体查询应用于最大的屏幕尺寸。

一旦你创建了你认为对当前项目有用的媒体查询，就为媒体查询添加不同值的样式：

```html
@media tv { 
     body {color: blue;} 
     h1 {
          font-weight: bold;
          font-size: 140%;
     }
     img {
          float: left;
          width: 20%;
          border: 2px solid #ccc;
          padding: 2%;
          margin: 2%;
     } 
     p {
          width: 62%;
          float: right;
          font-size: 110%;
          padding: 2%;
     }
} 
@media screen and (max-width: 960px) {
     body {color: #000;} 
     h1 {
          font-weight: bold;
          font-size: 120%;
     } 
     img {
          float: right;
          width: 20%;
          border: 2px solid #ccc;
          padding: 1%;
          margin: 1%;
     } 
     P {
          width: 80%;
          float: left;
          font-size: 60%; 
     } 
}
@media screen and (min-width:961px) and (max-width:1280px) { 
     body {color: #000000;} 
     h1 {
          font-weight: bold;
          font-size: 120%;
     }
     img {
          float: right;
          width: 20%;
          border: 2px solid #ccc;
          padding: 1%;
          margin: 1%;
     } 
     P {
          width: 76%;
          float: left;
          font-size: 60%;
     }
} 
@media screen and (min-width: 1281px) {
     body {color: #000000;} 
     h1 {
          font-weight: bold;
          font-size: 120%;
     } 
     img {
          float: right;
          width: 20%;
          border: 2px solid #ccc;
          padding: 1%;
          margin: 1%;
     } 
     P {
          width: 70%;
          float: left;
          font-size: 100%;
     }
} 
```

页面的最终版本显示在以下截图中：

![操作方法…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_03.jpg)

## 工作原理…

应用这些样式，你会发现不同的设备应用了不同的样式。你可以巧妙地结合一些媒体查询来在你的网站上创建魔术般的响应性。

# 使用媒体查询创建响应式宽度布局

在这个配方中，我们将制作一个简单的响应式宽度布局，它会根据不同的屏幕宽度进行调整。这个布局将是一个很好的起始模板，用于个人博客或新闻杂志，你希望读者评论你的内容和彼此的评论。它甚至可能是一个吸引喷子参与激烈争论的绝佳主题起点。这段话听起来有点傻，抱歉！

## 准备工作

这个模板在动态 CMS 或博客软件中效果很好，但作为一个纯 HTML 页面可能没有太多意义。但大多数主题在呈现方面与 HTML 一样工作。在大多数情况下，你只需用模板标签替换文本和静态导航。这个配方将需要一些填充文本来演示。如果你还没有一些文本可以使用，可以去我们的老朋友 Ipsum 生成器获取一些填充文本。

## 操作方法…

首先，创建一个简单的网页，在`style`元素中创建你的媒体查询。你可以随时链接到外部样式表，但为了简单起见，这个和大多数的配方都包含在你的头部`<style>...</style>`部分的 CSS 中。在屏幕尺寸上包括这些标准断点：`960`，`1024`和`1280`。

```html
<style>
@media screen and (max-width: 960px) {…}
@media screen and (min-width: 961px) and (max-width: 1024px) {…} 
@media screen and (min-width: 1025px) and (max-width: 1280px) {…} 
@media screen and (min-width: 1281px) {…}
</style>
```

第一个媒体查询影响所有窄于`960px`的视口。第二个从`961px`到`1024px`，第三个从`1025px`到`1280px`，最后一个影响所有大于`1281px`的屏幕尺寸。在每个媒体查询中，你将为不同的布局编写 CSS。除了媒体查询之外，还会有一些布局 CSS 以及你的样式呈现，但大多数都会在媒体查询中定义。

接下来的步骤是创建你的 HTML 布局。基本结构从这些基本的`div`元素开始——`nav`，`content`和`comments`：

```html
<body>
  <nav></nav>
  <div class="content"></div>
  <aside class="comments"></aside>
</body>
```

接下来在你的页面中添加一些填充内容。这将有助于演示布局。

在`nav`元素中，添加一个带有示例菜单链接的无序列表。这将作为一个响应式菜单。在页面最窄的宽度上，菜单将垂直显示。在宽度范围从 961px 到 1280px 之间，菜单以水平方式显示在顶部。对于更大的宽度，我们希望菜单返回到垂直显示并返回到左侧。

在前两个媒体查询中，`content`和`comments`元素将向左浮动，但宽度比例不同。在`960px`时，这些元素的宽度应为`90%`。在更大的宽度上，将`content`和`comments`元素分别设置为`60%`和`20%`。

```html
@media screen and (max-width: 960px) {
     .content {width: 90%;}
     .comments {width: 90%;}
}
@media screen and (min-width: 961px) and (max-width: 1280px) {
     .nav ul li {display: inline-block;} 
     .content {width: 60%;}
     .comments {width: 20%;}
@media screen and (min-width: 1281px) {
     .content {width: 60%;}
     .comments {width: 20%;}
}
```

为了使菜单在大屏幕上滑回左侧，我们将使用定位来创建一个三列布局。在`min-width:1281px`媒体查询中，添加`.nav`元素和绝对定位和宽度的样式：

```html
.nav{
     position: absolute;
     top: 20px;
     left: 0px;
     width:144px;
}
```

这几乎是构建响应式布局所需的所有步骤。为了使布局更整洁，让我们为布局添加一些填充。将`.nav`、`.content`和`.comments`元素添加到其他媒体查询中，然后为这些元素添加填充。参考以下 CSS。`min-width:1281px`媒体查询不会为`.nav`元素添加填充，而`.content`和`.comments`元素的填充会减少以适应垂直菜单。

```html
@media screen and (max-width: 960px){
     .nav {padding: 1% 5%;}
     .content,.comments {padding: 1% 5%;}
     .content {width: 90%;}
}
@media screen and (min-width: 961px) and (max-width: 1280px){
     .nav {padding: 1% 5%;}
     .nav ul li {display: inline;}
     .content,.comments {padding: 1% 5%;}
     .content {width: 60%;}
}
@media screen and (min-width: 1281px){
     .nav {
          position: absolute;
          top: 20px;
          left: 0px;
          width: 144px;
     }
     .content,.comments {padding: 1% 1% 1% 0;}
     .content{
          width: 60%;
          margin-left: 144px;
     }
}
```

你也可以按照自己的喜好对内联菜单进行样式设置。现在让我们简单地为`li`元素添加一些边距。在媒体查询之外添加这些元素和样式，`.nav ul li{margin: 2px 10px;}`。

最后，关于内容和评论，将你的占位文本粘贴到`.content`元素内。我还在里面添加了标题和段落标签。我们将对评论做类似的操作。

记住，我们希望允许嵌入式评论，或者允许人们对评论进行评论。评论可能会有继承的层次结构，我们仍然希望在所有浏览器大小下都能看起来不错，所以我们应该添加一些填充。在每个媒体查询的`.comments`元素中添加相对填充，以便随着浏览器窗口变小而占用更少的空间：对于`max-width:960px`媒体查询，填充为`90%`，对于所有更大的尺寸，填充为`20%`。在媒体查询之外，为`.comment`元素添加`padding-left: 8%`，并将`.content`和`.comments`元素向左浮动。你还可以使用`text-align:justify`使文本看起来像一个块。

```html
@media screen and (max-width: 960px) {
     .nav {padding: 1% 5%;}
     .content,.comments {padding: 1% 5%;}
     .content {width: 90%;}
     .comments {width: 90%;}
}@media screen and (min-width: 961px) and (max-width: 1280px) {
     .nav {padding: 1% 5%;}
     .nav ul li {display: inline;}
     .content,.comments {padding: 1% 5%;}
     .content {width: 60%;}
     .comments {width: 20%;}
}
@media screen and (min-width: 1281px) {
     .nav {
          position: absolute;
          top: 20px;
          left: 0;
          width: 144px;
     }
     .content,.comments {padding:1% 1% 1% 0}
     .content {
          width: 60%;
          margin-left: 144px;
     }
     .comments { width: 20%;}
}
.content,.comments {
     float: left;
     text-align: justify;
}
.nav ul li {margin: 2px 10px;}
.comment {padding-left: 8%;}
```

这个 CSS 将使评论和嵌入式评论的填充根据浏览器窗口大小的变化而调整。因此，你的页面的评论部分将显示评论的父子层次结构，以及每个浏览器窗口大小的一致且可操作的布局。你可以在以下截图中看到代码的实际演示：

![如何操作…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_04.jpg)

## 工作原理…

在这个响应式布局中，我们使用了一些不同的技术。首先，媒体查询为我们提供了有限但有用的逻辑，可以针对不同的浏览器窗口大小部署不同的布局技术。其次，流体和浮动元素的大小比例可以轻松调整到新的布局。最后，流体的百分比填充给出了与屏幕大小和布局一致的填充比例。

# 使用媒体查询更改图像大小

在这个教程中，你将学习如何使用 CSS 媒体查询调整图像大小。这在许多情况下都很有用，特别是当你想要下载一个图像并在响应式布局中使用不同尺寸的版本时。

## 准备工作

这是一种可以在客户端处理的尺寸变化的好方法，但要小心不要滥用这种方法，导致客户端下载一个非常大的图像文件并在他们的浏览器中进行大量调整。有更好的方法来做到这一点，在第一章中已经讨论过，*响应式元素和媒体*。

## 如何操作…

我建议创建一个小的 HTML 页面，包括一个`h1`标题，`wrap`元素，以及在`wrap`内部，一个图像和一个文字段落。实际上，在媒体查询中更改图像大小并不需要所有这些额外的东西，但是这将帮助你演示在媒体查询中更改图像大小的用法。

接下来，为最常见的浏览器窗口大小断点创建您的媒体查询：`960px`、`1024px`、`1280px`、`1366px`、`1440px`，最后是`1680px`。在每个媒体查询中，添加您的元素样式。在我的示例中，我在`960px`和`1280px`处创建了媒体查询：

```html
@media screen and (max-width: 960px){ 
     .wrap {padding:0 5%; width: 90%;} 
     .wrap img { 
          width: 90%; 
          height: auto; 
          padding:5%;
     } 
     .wrap p {
          width: 90%;
          padding: 5%;
          text-align: justify;
     } 
} 
@media screen and (min-width: 961px) and (max-width: 1280px) { 
     .wrap {
          padding: 0 5%;
          width: 90%;
     } 
     .wrap img {
          width: 50%; 
          height: auto; 
          max-width: 600px; 
          float: right; 
          } 
     .wrap p {
          width: 50%;
          text-align: justify;
          float: left;
     } 
} 
@media screen and (min-width:1281px) { 
     .wrap {
          padding: 0 5%;
          width: 90%;
      } 
     .wrap img {
          width: 40%; 
          height: auto; 
          max-width: 500px; 
          float: left; 
      } 
     .wrap p {
          width: 60%;
          text-align: justify;
          float: right;
      } 
}
```

现在，当您调整页面大小时，您可以看到图片在浏览器通过各种媒体查询调整大小时的变化。这在下面的截图中有所说明：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_05.jpg)

## 工作原理…

当浏览器调用不同的媒体查询时，元素的`width`和`height`属性会呈现不同的大小。这使您能够为不同的设备优化图像大小。请根据您的判断，如果原始图像太大，可以考虑一些服务器端的调整大小作为替代方法。

# 使用媒体查询隐藏元素

这个教程将向您展示一些非常有用的媒体查询技巧，以使元素根据浏览器窗口的大小消失。有几种不同的方法可以隐藏屏幕上的元素，我将在这个教程中介绍其中三种。

## 准备工作

这种方法可以有很多用例。一个非常有用的用例是在将页面缩小到较小的设备时，使用它来动态切换菜单。您还可以使用它来改变内容区域或侧边内容的显示方式。当您用这些方法进行创意时，可能性是无限的。

## 如何做…

设置一个简单的演示页面。在我的示例中，我编写了一个带有`h1`标题、一张图片，然后两个带有文本的元素的页面。接下来，为这些元素添加一些样式。我为每个元素添加了不同的背景颜色和宽度属性，主要是为了在它们消失时能够保持它们的间隔。

然后在断点处添加您的媒体查询。在示例中，我将在`960px`处添加一个断点。在媒体查询内，我们将看一下一些不同的方法来使元素消失。

在您的第一个媒体查询`max-width: 960px`中，为`img`元素添加`position: absolute`和`left: 5000px`属性；这个样式将把元素移动到屏幕左侧足够远的地方，实际上，它已经消失了。在该媒体查询中添加`display: none`样式到`.bar`元素。这将使元素保持在原位，但使其不可见。这两个元素实际上已经从页面上消失了，只留下标题和`.foo`元素。

在第二个媒体查询中，您将尝试另一种方法来从屏幕上移除一个元素。首先，将`.foo`元素添加到媒体查询中，并给它一个左边距为`5000px`。这将把它从屏幕上移除，但是下一个元素会清除它的垂直空间，留下一个明显的白色空间。然后，将元素浮动到左侧，白色空间将消失。这在下面的代码片段中有所说明：

```html
.foo {
     background-color: #ccc;
     width: 300px;
} 
.bar {
     background-color: blue;
     width: 600px;
     color: white;
} 
@media screen and (max-width: 960px) { 
     img {
          position: absolute;
          left: 5000px;
     } 
     .bar {display: none;} 
} 
@media screen and (min-width: 961px) { 
     .foo {
          float: left;
          margin-left: -5000px;
     } 
}
```

恭喜！在浏览器中打开项目，看看是否像下面的截图一样：

![如何做…](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_06.jpg)

## 工作原理…

绝对定位和浮动都没有高度属性，因此一旦应用到一个元素上，它们将不占据任何垂直空间。这可以是一个特别有用的技巧，用来在页面上移动元素。但当您使用浮动元素进行布局时，可能会出现一些问题。这种行为可以通过在元素后插入一个带有`clear:both`属性的换行来解决。

# 创建一个平滑过渡的响应式布局

在这个教程中，我将指导您创建一个多区域和响应式的首页。这个首页将有一些以不同方式响应的元素；提供丰富的用户体验，呈现出令人印象深刻的布局。我为一家初创公司开发了这个，发现我非常喜欢它，所以我继续进一步开发，与您分享在这个教程中。

## 准备工作

这个配方将是内容丰富网站的主页的良好模板。如果你已经建立了一段时间的内容，这将是完美的登陆页面，并且可以很容易地修改为单个内容页面。如果你刚刚开始建立你的网站，你可以像我为这个配方做的那样去[`lipsum.com`](http://lipsum.com)获取一些生成的文本。

## 如何做到这一点...

这个网站分解成三个 HTML 元素或者页脚，还有两个元素，有时是垂直的，有时是左浮动和右浮动，取决于屏幕宽度。这些元素本身也分成更小的元素。所以，开始创建一个带有顶部包裹元素、中间包裹元素和页脚的基本页面：

```html
<body>
  <header>...</header>
  <div class="content" role="main">...</div>
  <footer>...</footer> 
</body>
```

接下来，我们开始这些项目的 CSS。添加一些基本的 CSS 和以下媒体查询：

```html
body{
     margin: 0;
     padding: 0;
}
footer {width: 100%;}
.clear {clear: both;}
@media screen and (max-width: 1280px) {  
     header, .content {width: 100%;} 
} 
@media screen and (min-width: 1281px) { 
     header {
          float: left; 
          width: 60%;
     } 
     .content {
          float: right; 
          width: 40%;
     }
}
```

在这个基本布局中，`header`和`.content`行在页面宽度小于`1280px`时都占据`100%`的页面宽度。当页面更大时，它们占据各自的`60%`/`40%`分割和`left`和`right`浮动。

接下来让我们构建菜单。这个菜单将利用响应式技巧，使用媒体查询来隐藏和显示两个不同的菜单。基本上，我们将构建两个不同的菜单，然后使用 CSS 来为每个屏幕显示优化的菜单。最小版本将使用多选下拉菜单，而较大的菜单包含两个内联列表。在`top-wrap`元素内部的 HTML 如下所示：

```html
<header>
    <nav>
        <div class="menu small-menu">
             <img src="img/robot-low.png">
             <form>
                <select name="URL" onchange='window.location.href=this.form.URL.options[this.form.URL.selectedIndex].value'>
                 <option value="blog.html">Page 1</option>
                 <option value="home.html">Home Page</option>
                 <option value="tutorials.html">Tutorials</option>
                </select>
             </form>
        </div>

        <div class="menu large-menu">
             <div class="top-menu">
                 <nav>
                   <ul>
                    <li><a href="login.html">Log In</a></li>
                    <li><a href="account.html">My Account</a></li>
                   </ul>
                 </nav>
             </div>
        <div class="bottom-menu"> these should be classes so they can be reused. Plus the names are too specific.
           <nav>
             <a href="#" class="logo">
                <img src="img/robot-low.png">
             </a>
             <ul>
                <li><a href="blog.html">Page 1</a></li>
                <li><a href="home.html">Home Page</a></li>
                <li><a href="tutorials.html">Tutorials</a></li>
                <li> <a href="news.html">News</a> </li>
             </ul>
          </nav>
        </div>
     </div>
    </nav>
</header>
```

为头部元素添加以下 CSS：

```html
nav .small-menu img{
     width:9%;
     height:auto;
     float:left;
     padding:0 2%;
}
nav .small-menu select {
     margin: 3%;
     width: 80%;
}
```

这将显示菜单的两个不同版本，直到我们添加到我们的媒体查询。添加媒体查询以在小浏览器窗口和较大浏览器窗口尺寸上切换显示下拉菜单和较大的内联列表菜单。使用`display`属性来显示和隐藏菜单。

```html
@media screen and (max-width: 600px) {
     nav .small-menu {display: inline;}
     nav .large-menu {display: none;}
}
@media screen and (min-width: 601px) {
     nav .small-menu {display: none;}
     nav .large-menu {display: inline;}
}
```

在菜单下，在闭合的`</header>`标签之前，为网站上显示的大高质量照片创建一个空间。为了防止它成为浪费的空间，让我们把一个搜索框放在它的中间。我们实际上可以使这个搜索表单紧贴图片中心，并对屏幕尺寸的变化做出响应性调整。这在下面的简单代码中有所说明：

```html
<div class="img-search">classes
   <div class="search">
       <form>
         <input type="text" placeholder="Find a Robot">
         <input value="Search" class="search-input" type="submit">
       </form>
   </div>
   <img class="main-img" src='images/robot-wide.png'>
</div>
```

当然，这是 CSS 的魔力。让我们使用一些技巧使搜索表单在同一位置悬停。首先给外部`div`元素一个`100%`的宽度，然后`search`元素将在不同的媒体查询下获得绝对位置和几个不同的属性。这种组合将使搜索表单悬浮在`img`区域的中间。请记住，我们正在向媒体查询添加新的 CSS。以下 CSS 代码仅反映了新增内容，而不是已经存在的内容。如果每次都展开整个 CSS，它会变得相当长。最后，我将包括整个 CSS，以便它以最终状态呈现。

```html
.img-search {width: 100%;}
.search {position: absolute; }
.top-menu {
     height: 33px; 
     background-color: #ccc;
}
.logo img {height: 87px; float: left;}
.top-menu nav li {display: inline-block;} 
.large-menu ul {margin: 0 5px;}
.large-menu li {display: inline;}

@media screen and (max-width: 600px) {
     .search {
          margin-top: 87px;
          left: 22%;}
   }
@media screen and (min-width: 601px) and (max-width: 1280px) {
     .search {
          margin-top: 144px;
          left: 40%;
     }
}
@media screen and (min-width: 1281px) {
     .search {
          margin-top: 144px;
          left: 22%;
     }
}
```

`.img-search`图像元素将获得`100%`的动态宽度和自动高度。这就是大图搜索字段的全部内容。

给下一个元素`.flip-tab`一个`100%`的宽度，以及任何高度或其他你想要的属性。你不必再担心这个了：

```html
<div class="flip-tab"><h3>Look Down Here</h3></div>

.flip-tab {width: 100%; height: 54px; text-align: center;}
```

接下来的元素`.teasers`将获得一个`max-width: 1280px`属性，因此它将自动占据其父元素`top-wrap`的`100%`宽度，限制为`1280px`。这个元素只是三个左浮动的`.teaser`元素的容器。这些`.teaser`元素在不同的媒体查询下会有两组不同的属性集，用于`600px`断点。

```html
<div class="teasers">
     <div class="teaser teaser1">
          <h3>The First Law of Robotics</h3>
               <p>
                    Lorem ipsum dolor sit amet,..
               </p> 
     </div>
     <div class="teaser teaser2"> 
          <h3>The First Law of Robotics</h3>
               <p>
                    Lorem ipsum dolor sit amet,..
               </p> 
     </div>
     <div class="teaser teaser3"> 
          <h3>The First Law of Robotics</h3>
               <p>
                    Lorem ipsum dolor sit amet,..
               </p> 
     </div>
</div>
.teasers {max-width: 1280px;}
.teaser {float: left;}
@media screen and (max-width: 600px) {
     .teaser {width: 100%;}
}
@media screen and (min-width: 601px) {
     .teaser {
          width: 32%;
          min-width: 144px;
     }
}
```

这就结束了你在`header`元素中要做的一切。接下来是`content`元素，它包裹着将在右侧列中浮动的内容。这个元素里面的内容只是一个 60/40 比例的两列浮动，或者如果父元素很窄，每个都是`100%`宽。`content`元素将在断点为`1280px`的媒体查询下有两组不同的属性集。这些元素有一些有限的示例内容。一旦部署了布局，你可以添加更多内容：

```html
<div class="content" role="main">
     <div class="contact-us">

          <div class="form-wrap">
               <legend>Find a Robot</legend> 

               <form>
                    <input type="text" placeholder="Robot Search">
                    <input value="Search" class="search-input" type="submit">
               </form>
          </div>
                <h4>Search or Like Us Locally</h4>
          <ul class="local-like">                  <li><a href="/search/SanFranciso">San Francisco</a><a href="/like/SanFrancisco">Like</a></li>
               <li><a href="/search/LosAngeles">Los Angeles</a><a href="/like/LosAngeles">Like</a></li>
               <li><a href="/search/Austin">Austin</a><a href="/like/Austin">Like</a></li>
              <li><a href="/search/Houston">Houston</a><a href="/like/Houston">Like</a></li>          </ul>
     </div>
     <divclass="cities"> really?
          <p>Loremipsumdolor sitamet, consecteturadipiscingelit. Nunc non felisutmetusvestibulumcondimentumuteueros.Nam id ipsumnibh.Praesent sit ametvelit...
          </p>
     </div>

</div>
```

这个 CSS 更加复杂，但是记住，你可以在线访问整个工作。正如你所看到的，元素会在周围来回移动一下，但是每个断点都会有一个优化的显示。

```html
.contact-us {float: left;}
.cities {float: left;}
@media screen and (max-width: 600px) {
     .contact-us {width: 100%;}
     .cities {width: 100%;}            
}
@media screen and (min-width: 601px) and (max-width: 1280px) {
     .contact-us {width: 40%;}
     .cities {width: 60%;}
}
@media screen and (min-width: 1281px) and (max-width: 1366px) {
     .contact-us {width: 100%;}
     .cities {width: 100%;}
}
@media screen and (min-width: 1367px) {
     .contact-us {width: 40%;}
     .cities {width: 60%;}
}
```

最后，页脚！（页面的结尾！）页脚分解为`100%`宽的外部`<footer>`，然后是一个`footer-wrap`包裹，宽度为`100%`，`max-width`为`1280px`，动态的边距，并且内联块显示。里面有三个元素，它们始终具有`display:inline-block`属性。当显示较小时，这些元素每个都是`100%`宽，否则它们是`33%`宽，左浮动，最小宽度为`144px`：

```html
<footer>
     <div class="footer-wrap">
          <div class="footer-1 footer-third">
               <ul>
               <li><span class=""><a href="#">FaceBook</a></span></li>
               <li><span class=""><a href="#">Google +</a></span></li>
               <li><span class=""><a href="#">Twitter</a></span></li>
               </ul>
          </div>
          <div class="footer-2 footer-third">
               <ul>
                 <li><span class=""><a href="#">Link1</a></span></li>
                 <li><span class=""><a href="#">Privacy Policy</a></span></li>
                 <li><span class=""><a href="#">Terms of Use</a></span></li>
               </ul>
          </div>
          <div class="footer-3 footer-third">
               <ul>
                  <li><span class=""><a href="#">Link1</a></span></li>
                  <li><span class=""><a href="#">Link2</a></span></li>
                  <li><span class=""><a href="#">Link3</a></span></li>
               </ul>
          </div>
    </div>
</footer>

.footer-wrap{ 
     width: 100%;
     max-width: 1280px; 
     margin :0 10%;
     display: inline-block;
}
.footer-third {display: inline-block;}

@media screen and (max-width: 600px) {
     .footer-third {width :100%;}
}
@media screen and (min-width: 601px{
     .footer-third {
          float: left; 
          width: 33%;
             min-width: 144px;
     }
}
```

就像我之前承诺的那样，这里是完整的 CSS 代码：

```html
body{margin:0;padding:0;}
.img-search {width: 100%} 
.search {position:absolute;}
nav .small-menu img{width:9%;height:auto;float:left;padding:0 2%;}
nav .small-menu select {margin: 3%; width: 80%;}
.main-img {width: 100%; height: auto;}
.top-menu {height: 33px; background-color: #ccc;}
.top-menu nav li {display: inline-block;}
.logo img {height: 87px; float: left;}
.large-menu ul {margin: 0 5px;}
.large-menu li {display: inline;}

.flip-tab {width: 100%; height: 54px; text-align: center;}
.teasers {max-width: 1280px;}
.teaser {float:left;}
.contact-us {float:left;}
.cities {float:left;}

footer {width:100%}
.footer-wrap {width: 100%; max-width: 1280px; margin: 0 10%; display: inline-block;}
.footer-third {display:inline-block;}

@media screen and (max-width: 600px) {
 nav .small-menu {display: inline}
 nav .large-menu {display: none}
 .search {margin-top: 87px; left: 22%;}
 .teaser {width: 100%}
 .contact-us {width: 100%;}
 .cities {width: 100%}
 .footer-third {width: 100%}
}
@media screen and (min-width: 601px) and (max-width: 1280px){
     .search {margin-top: 144px; left: 40%}
     .contact-us {width: 40%;}
     .cities {width: 60%}
}
@media screen and (min-width: 601px) {
 nav .small-menu{display: none}
 nav .large-menu{display: inline}
 .teaser {width: 32%; min-width: 144px;}
 .footer-third {float: left; width: 33%; min-width: 144px;}
}
@media screen and (max-width: 1280px) {
 header, .content {width: 100%;}
}
@media screen and (min-width: 1281px) {
 header {float: left; width: 60%;}
 .content {float: right; width: 40%;}
 .search {margin-top: 144px; left:22%;}
}
@media screen and (min-width: 1281px) and (max-width: 1366px){
 .contact-us {width: 100%}
 .cities {width:100%}
 }
@media screen and (min-width: 1367px) {
.contact-us {width: 40%}
.cities {width: 60%}
}
```

这一部分又长又难，感谢你的耐心等待！效果如下截图所示，请与你的输出进行比较：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5c3-rsps-web-dsn-cb/img/5442OT_03_07.jpg)

## 它是如何工作的...

这些 CSS 和媒体查询结合在一起，可以制作一个响应式页脚，可以在所有屏幕尺寸下保持居中，并且可以在小型移动浏览器窗口中折叠。

响应式布局是 Web 开发方法的一个令人兴奋的新领域。响应式方法允许设计师和开发人员为多个设备创建，特别是移动设备，而无需开发原生应用程序。很快，如果还没有的话，你可以期待许多公司希望采用响应式方法来重新设计他们的网站。

## 还有更多...

你使用了一种非常简单的方法，几乎完全使用 CSS 来实现响应式。我要求你进一步挑战自己，通过在*为移动浏览器添加 JavaScript*配方中查看第五章中的*制作移动优先的 Web 应用程序*，添加一个 jQuery 方法，以在移动浏览器中用`<select>`元素替换大菜单。这将防止在菜单中有重复内容时可能导致的潜在搜索引擎惩罚。

首先，剪切`smallMenu` div 元素及其子元素，并将其粘贴到头部的某个地方，或者在`<script> </script>`元素中作为变量`smallMenu`。

```html
var smallMenu = '<div class="menu small-menu">…</div>'
```

接下来编写脚本，将调用以删除`large-menu` div 元素，并将`smallMenu`变量附加到`nav`元素。

```html
$(document).ready(function() {
     $('.large-menu').remove();
     $('nav').append(smallMenu);
});
```

现在，当页面在移动设备上加载时，脚本将用缩小的移动版本替换导航，你不会因为 SEO 而失眠！
