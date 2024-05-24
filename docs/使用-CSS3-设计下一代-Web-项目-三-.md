# 使用 CSS3 设计下一代 Web 项目（三）

> 原文：[`zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3`](https://zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：视频杀死了广播明星

在撰写本文时，使用 CSS 和 HTML`video`元素仍然有点像黑魔法。主要问题是每个浏览器都利用其特定的视频实现技术；其中一些使用 GPU，而其他一些使用用于页面其余部分的相同渲染引擎。在本章中，我们将探讨如何通过利用 SVG 和 CSS 的功能在运行视频上创建面具和效果。以下是我们将涵盖的主题列表：

+   HTML5`video`元素

+   使用 SVG 进行面具处理

+   SVG 动画

+   基于 WebKit 的特定面具属性

+   CSS 滤镜

# HTML5 视频元素

HTML5 规范引入了新的多媒体元素，允许更好地将视频和音频整合到网页中，而无需嵌入外部插件，如 Flash。现在嵌入视频就像写这样简单：

```css
<video src="img/video">
```

但是需要考虑一些注意事项；首先，每个浏览器只支持视频编解码器的一小部分，因此如果我们希望我们的元素能够播放，我们需要至少将我们的视频编码为`mp4`和`webm`，然后使用另一种语法来包含这两种格式，如下所示：

```css
<video>
  <source src="img/video.mp4" type="video/mp4">
  <source src="img/video.webm" type="video/webm">
</video>
```

**Miro**（[`www.mirovideoconverter.com/`](http://www.mirovideoconverter.com/)）是一款很好的免费视频转换软件，适用于 Mac 和 Windows 操作系统。它非常易于使用 - 只需选择所需的输出格式，然后将文件拖放到应用程序窗口中开始转换过程。

一旦设置了我们的`video`元素，我们很快就会发现大多数常见的 CSS3 属性在所有浏览器上对这个元素的形状的影响并不相同。例如，`border-radius`属性；在下面的屏幕截图中，显示了这个属性在各种浏览器中的不同行为（请注意这个属性在不同浏览器中的不同行为）：

![HTML5 视频元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_1.jpg)

基于 WebKit 的浏览器似乎忽略了这个属性，而 Firefox 和 IE9 正确实现了它。这可能是因为 Chrome 和 Safari 使用 GPU 播放视频，因此无法很好地对此内容应用 CSS 修改。

布局引擎之间的这些差异在处理视频和 CSS 时需要谨慎对待。

在这个项目中，我们将使用 CSS 开发一小部分可以在运行时应用于视频的修改。让我们从一些基本的面具开始。

# 面具

**面具**是在我们需要隐藏部分内容时非常有用的工具；它们在视频中更加有用，因为我们可以应用有趣的效果，否则需要一些专门的软件。我们可以使用 HTML5/CSS3 创建面具的几种技术；然而，跨浏览器的支持是不一致的。为了解决这些不一致性，我们将在系列中结合几种技术。

在某种程度上，我们可以使用`border-radius`来遮罩我们的视频，如下所示：

```css
<!doctype html>
<html>

  <head>
    <meta charset="utf-8">
    <title>Masking</title>

    <style>
      video{
        border-radius: 300px;
      }
    </style>

  </head>

  <body>

    <video autoplay muted loop>
      <source src="img/sintel-trailer.mp4">
      <source src="img/sintel-trailer.webm">
    </video>

  </body>

</html>
```

正如你所看到的，这种方法适用于 Firefox 和 IE，但对于基于 WebKit 的浏览器，我们需要使用不同的方法。

如果我们使用 Web 服务器（如 Apache 或 IIS）进行工作，可能需要配置它以使用适当的内容类型提供视频文件。为此，我们可以在项目的根目录（如果使用 Apache）中创建一个`.htaccess`文件，内容如下：

```css
AddType video/ogg .ogv 
AddType video/mp4 .mp4 
AddType video/webm .webm
```

如果我们使用 IIS，还有另一个程序需要遵循。这在[`blog.j6consultants.com.au/2011/01/10/cross-browser-html5-video-running-under-iis-7-5/`](http://blog.j6consultants.com.au/2011/01/10/cross-browser-html5-video-running-under-iis-7-5/)的指南中有详细说明。

自 2008 年以来，WebKit 支持一组管理面具的 CSS 属性。我们将使用`webkit-mask-box-image`选择器将图像面具应用到我们的电影示例中。为此，我们需要一个类似于以下图像中的`300px`黑色圆：

![面具](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_2.jpg)

然后，我们将使用之前介绍的属性将这个黑色圆设置为`video`元素的蒙版。应用后，这个图像的黑色部分将让底层内容可见，而白色部分将完全隐藏内容。当然，灰色可以用来部分隐藏/显示内容。

```css
video{
  border-radius: 300px;
  -webkit-mask-box-image: url(img/circle-mask.png) stretch;
}
```

这是结果：

![蒙版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_3.jpg)

## 更高级的蒙版

目前，我们只能处理基本类型的蒙版，也就是一切可以用`border-radius`属性模拟的东西。但是，如果我们尝试简单地创建一个中心有小圆的蒙版，我们会发现这种组合在以前的技术中是不可行的，因为圆角只能位于元素的一侧。幸运的是，我们可以转向一个更复杂但更强大的方法，涉及 SVG 格式。

Gecko 和 WebKit 都支持 SVG 蒙版，通过不同的 CSS 属性——基于 Gecko 的浏览器使用`mask`属性，而 WebKit 使用`-webkit-mask-image`。

这些属性不仅名称不同，它们的行为也不同：

+   `mask`属性需要链接到一个名为`<mask>`的 SVG 元素，基本上是我们将用来蒙版`html`元素的所有形状的容器

+   另一方面，`-webkit-mask-image`属性需要指向一个包含我们想要用来覆盖视频的所有形状的 SVG 元素

例如，这是我们如何正确实现`mask`属性的：

```css
<!doctype html>
<html>

  <head>
    <meta charset="utf-8">
    <title>svg mask</title>

  </head>

  <body>

    <video autoplay muted loop>
      <source src="img/sintel-trailer.mp4">
      <source src="img/sintel-trailer.webm">
    </video>

 <style>
 video{
 mask: url('#circle');
 }
 </style>

 <svg>
 <defs>
 <mask id="circle">
 <circle cx="427" cy="240" r="100" fill="white"/>
 </mask>
 </defs>
 </svg>

  </body>

</html>
```

这是我们如何处理`-webkit-mask-image`属性的：

```css
<!doctype html>
<html>

  <head>
    <meta charset="utf8">
    <title>svg mask</title>

  </head>

  <body>

    <video autoplay muted loop>
      <source src="img/sintel-trailer.mp4">
      <source src="img/sintel-trailer.webm">
    </video>

 <style>
 video{
 -webkit-mask-image: url('svg/mask-circle.svg');
 }
 </style>

  </body>

</html>
```

在这里，SVG 文件`svg/mask-circle.svg`的定义如下：

```css
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1"  >
 <circle cx="427" cy="240" r="100" fill="white"/>
</svg>
```

在这两种情况下，最终结果是相同的，如下所示：

![更高级的蒙版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_4.jpg)

这种方法的缺点是我们必须创建两个不同的 SVG 片段来适应两种布局引擎。这里有一个小的改进，可以让我们走向更好的解决方案；通过利用`<use>`元素，我们可以在单个 SVG 文件`svg/mask.svg`中满足两种属性的需求，如下所示：

```css
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1"  >
  <defs>
 <mask id="circle">
 <circle id="circle-element" cx="427" cy="240" r="100" fill="white"/>
 </mask>
  </defs>
 <use xlink:href="#circle-element"/>
</svg>
```

通过使用这种方法，我们可以在两个浏览器上获得与之前图像相同的结果，并且只需一个 CSS 语句：

```css
<!doctype html>
<html>

  <head>
    <meta charset="utf-8">
    <title>svg mask</title>

    <style>
 video{
 mask: url('svg/mask.svg#circle');
 -webkit-mask-image: url('svg/mask.svg');
 }
    </style>

  </head>

  <body>

    <video autoplay muted loop>
      <source src="img/sintel-trailer.mp4">
      <source src="img/sintel-trailer.webm">
    </video>

  </body>

</html>
```

干得好！现在我们准备在项目中实现一些蒙版。

# 实现项目

在这个项目中，我们将使用 Sintel 的精美预告片（[`www.sintel.org/about/`](http://www.sintel.org/about/)），这是根据知识共享许可发布的电影。

和往常一样，我们需要一个基本的项目结构，包括一些文件夹（`css`，`img`，`svg`，`js`，`video`）。在这个项目中使用的视频要么可以在 Sintel 网站上找到，要么可以从 Packt 的网站（[www.packtpub.com](http://www.packtpub.com)）下载，以及完成的项目。我们还将使用**Prefix Free**（[`leaverou.github.com/prefixfree/`](http://leaverou.github.com/prefixfree/)），所以让我们下载它并放到`js`文件夹中。

让我们创建一个`index.html`文件开始：

```css
<!doctype html>
<html>

  <head>
    <meta charset="utf8">
    <title>Video killed the radio star</title>

    <link rel="stylesheet" type="text/css" href="http://yui.yahooapis.com/3.5.1/build/cssreset/cssreset-min.css" data-noprefix>
    <link rel="stylesheet" type="text/css" href="css/application.css">

    <script src="img/prefixfree.min.js"></script>

  </head>

  <body>

    <a id="mask" name="mask"></a>
    <a id="mask-stretch" name="mask-stretch"></a>
    <a id="mask-animate" name="mask-animate"></a>
    <a id="mask-animate-webkit" name="mask-animate-webkit"></a>
    <a id="mask-text" name="mask-text"></a>
    <a id="blur-filter" name="blur-filter"></a>
    <a id="grayscale-filter" name="grayscale-filter"></a>

    <video autoplay muted loop>
      <source src="img/sintel-trailer.mp4">
      <source src="img/sintel-trailer.webm">
    </video>

    <ul>
      <li>
        <a href="#">reset</a>
      </li>
 <li>
 <a href="#mask">mask</a>
 </li>
      <li>
        <a href="#mask-animate">animated mask</a>
      </li>
      <li>
        <a href="#mask-animate-webkit">animated mask (webkit)</a>
      </li>
      <li>
        <a href="#mask-text">text mask</a>
      </li>
      <li>
        <a href="#blur-filter">blur filter</a>
      </li>
      <li>
        <a href="#grayscale-filter">grayscale filter</a>
      </li>
    </ul>
  </body>

</html>
```

然后，在`application.css`中，让我们进行一些基本的 CSS 样式以及刚刚介绍的蒙版技术：

```css
html{
  min-height: 100%;
  background-image: linear-gradient(top, black, black 500px, white);
  background-size: cover;
  background-repeat: no-repeat;
}

video{
  display: block;
  margin: 0 auto;
}

ul{
  text-align: center;
  position: absolute;
  bottom : 100px;
  width: 100%;
}

li{
  display: inline;
}

li > a{
  display: inline-block;
  padding: 5px;
  background: #FFF;
  border: 3px solid black;
  text-decoration: none;
  font-family: sans-serif;
  color: black;
  font-size: 10px;
}

/* ==[BEGIN] Masking == */

a[name="mask"]:target ~ video{
 mask: url('../svg/mask.svg#circle');
 -webkit-mask-image: url('../svg/mask.svg');
}
```

一旦按下**mask**按钮，这就是结果：

![实现项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_5.jpg)

## 动画蒙版

SVG 支持通过一些特殊元素进行动画。在本章中，我们将使用最通用的一个`<animate>`。

这是一个例子：

```css
<circle ... >
<animate attributeType="CSS" attributeName="opacity" from="1" to="0" dur="5s" repeatCount="indefinite" />
</circle>
```

包含`<animate>`的元素会根据标签属性中指定的选项描述进行属性动画。在上面的代码中，我们要求浏览器在五秒内将圆的不透明度从完全可见变为隐藏。

因此，如果我们创建一个新的 SVG 文件，命名为`svg/mask-animate.svg`，并使用以下代码，我们将能够在 Gecko 和 WebKit 浏览器上获得一个动画效果：

```css
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1"  >
  <defs>
    <mask id="circle">
      <circle id="circle-element" cx="427" cy="240" r="100" fill="white">
 <animate attributeName="r" values="100;200;100" dur="5s" repeatCount="indefinite" />
      </circle>
    </mask>
  </defs>
  <use xlink:href="#circle-element"/>
</svg>
```

这是我们需要添加到`css/application.css`的 CSS：

```css
a[name="mask-animate"]:target ~ video{
  mask: url('../svg/mask-animate.svg#circle');
  -webkit-mask-image: url('../svg/mask-animate.svg');
}
```

并且这是蒙版在 5 秒动画中增长和缩小的结果：

![动画蒙版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_6.jpg)

# WebKit 特定属性

还有一些与蒙版相关的额外属性，只适用于 WebKit 浏览器；它们的工作方式与它们的`background`属性对应项完全相同，因此以下是原始 WebKit 博客文章中列出的列表：

+   `-webkit-mask`（`background`）：这是所有其他属性的快捷方式

+   `-webkit-mask-attachment`（`background-attachment`）：这定义了蒙版是否应在内容中滚动

+   `-webkit-mask-clip`（`background-clip`）：这指定了蒙版的裁剪区域

+   `-webkit-mask-position`（`background-position`）：此属性指定元素内蒙版的位置

+   `-webkit-mask-origin`（`background-origin`）：这指定了坐标 0,0 应该放置在元素内的位置（例如，在使用`padding-box`作为值的填充区域的开始处）

+   `-webkit-mask-image`（`background-image`）：这指向一个或多个图像或渐变，用作蒙版

+   `-webkit-mask-repeat`（`background-repeat`）：这定义了蒙版是否应重复，以及是在一个方向还是两个方向

+   `-webkit-mask-composite`（`background-composite`）：这指定了两个蒙版在重叠时应该如何合并

+   `-webkit-mask-box-image`（`border-image`）：这指向一个或多个图像或渐变，用作具有相同属性和行为的蒙版来定义边框图像

有了这些新属性，我们可以通过利用 CSS 过渡创建一些额外的效果，例如，我们可以用渐变蒙版我们的电影，然后使用`:hover`，改变它的蒙版位置；以下是 CSS 代码：

```css
a[name="mask-animate-webkit"]:target ~ video{
  -webkit-mask-position: 0 100%;
  -webkit-mask-size: 100% 200%;
  -webkit-mask-image: -webkit-gradient(linear, center top, center bottom, 
      color-stop(0.00,  rgba(0,0,0,1)),
      color-stop(1.00,  rgba(0,0,0,0))
    );
  -webkit-transition: -webkit-mask-position 1s;
}

a[name="mask-animate-webkit"]:target ~ video:hover{
  -webkit-mask-position: 0 0;
}
```

由于这些 WebKit 蒙版属性是在 2008 年创建的，可能自那时以来从未更新过，我们必须使用旧的 WebKit 渐变语法；除此之外，其他一切都很简单，如下图所示：

![WebKit 特定属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_7.jpg)

# 使用文本蒙版

我们可以使用文本来蒙版`video`元素；该过程与我们之前看到的类似，但当然，我们需要制作另一个特定的 SVG 文件，命名为`svg/mask-text.svg`：

```css
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg   width="1000" height="280" version="1.1">
  <defs>
    <mask id="sintel-mask">
 <text x="0" y="300" id="sintel" fill="white" style="color: black;font-size:210px;
 font-family: Blue Highway, Arial Black, sans-serif;">SINTEL</text>
    </mask>
  </defs>
 <text x="0" y="80%" id="sintel" fill="white" style="color: black;font-size:240px;
 font-family: Blue Highway, Arial Black, sans-serif;">SINTEL</text>
</svg>
```

在这里，我们无法利用`<use>`元素，因为蒙版定位和蒙版大小的确定方式之间存在另一个差异。

基于 Gecko 的浏览器只能承受固定坐标，而基于 WebKit 的浏览器可以拉伸蒙版以适应屏幕，如果我们使用`-webkit-mask-box-image`（如本章中最初的示例中所示）而不是`-webkit-mask-image`。

以下是所需的 CSS：

```css
a[name="mask-text"]:target ~ video{
  mask: url('../svg/mask-text.svg#sintel-mask');
  -webkit-mask-box-image: url('../svg/mask-text.svg');
}
```

这是结果的屏幕截图：

![使用文本蒙版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_8.jpg)

# 滤镜

除了蒙版，滤镜是其他强大的修改器，可以应用于元素，以获得各种效果，如模糊、灰度等。当然，也有缺点；在撰写本文时，滤镜支持是不均匀的。以下是一些缺点：

+   IE9 支持使用众所周知的`progid`滤镜的一些效果

+   Firefox 支持在 SVG 片段中声明滤镜

+   Chrome、Safari 和其他基于 WebKit 的浏览器支持最后的 CSS 滤镜规范

+   IE10 尚未确认对这些属性的支持，而且它将放弃对`progid`滤镜的支持

因此，让我们尽可能广泛地实现模糊滤镜。首先，我们将处理非常容易的 WebKit：

```css
-webkit-filter: blur(3px);
```

传递给`blur`函数的参数是效果的像素半径。接下来是 Gecko 支持；为此，我们必须在一个正确完成的 SVG 文件中使用`feGaussianBlur`元素，命名为`svg/filters.svg`：

```css
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg   version="1.1">
  <defs>
    <filter id="blur">
    <feGaussianBlur stdDeviation="3" />
  </filter>
  </defs>
</svg>
```

然后，我们可以使用 Gecko 支持的`filter`属性来引用这个效果：

```css
filter: url('../svg/filters.svg#blur');
```

接下来，我们还可以通过使用`progid`滤镜在 IE9 上实现这种效果：

```css
filter:progid:DXImageTransform.Microsoft.Blur(pixelradius=3);
```

以下是最终的 CSS。请注意，我们添加了一个`:hover`选择器技巧来在鼠标悬停时改变模糊；这实际上只在基于 WebKit 的浏览器上有效，但可以通过遵循先前规则轻松扩展支持：

```css
a[name="blur-filter"]:target ~ video{
  -webkit-filter: blur(3px);
  -webkit-transition: -webkit-filter 1s;      
  filter: url('../svg/filters.svg#blur');
}

.-ms- a[name="blur-filter"]:target ~ video{
  filter:progid:DXImageTransform.Microsoft.Blur(pixelradius=3);
}

a[name="blur-filter"]:target ~ video:hover{
  -webkit-filter: blur(0px);
}
```

我们还必须处理 Gecko 和 IE9 引用相同的`filter`属性但具有非常不同的值。为了解决这个问题，我们可以使用 Lea Verou 的 prefixfree 库在顶级`html`元素上添加的特殊`-ms-`类。

以下是结果：

![滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_9.jpg)

在当前稳定的 Chrome 版本中，`filter`属性似乎无法直接使用。这是因为我们需要在加速元素上启用滤镜。因此，让我们打开一个新标签页，然后在地址栏中输入`about:flags`并启用**GPU 加速的 SVG 和 CSS 滤镜**实验功能。

## 灰度滤镜

让我们再看一个滤镜，灰度！灰度滤镜基本上将目标图像或视频的所有颜色转换为相应的灰度值。

这是完整的 CSS：

```css
/* == [BEGIN] Grayscale filter == */

a[name="grayscale-filter"]:target ~ video{
  -webkit-filter: grayscale(1);
  filter: url('../svg/filters.svg#grayscale');
}

.-ms- a[name="grayscale-filter"]:target ~ video{
  filter:progid:DXImageTransform.Microsoft.BasicImage(grayscale=1);
}
```

这是 SVG 片段：

```css
  <filter id="grayscale">
          <feColorMatrix values="0.3333 0.3333 0.3333 0 0
                                 0.3333 0.3333 0.3333 0 0
                                 0.3333 0.3333 0.3333 0 0
                                 0      0      0      1 0"/>
  </filter>
```

最后，这是从 IE9 中截取的屏幕截图：

![灰度滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_07_10.jpg)

我们的元素可以应用许多其他滤镜；要获取完整列表，我们可以查看：

+   官方滤镜草案规范在[`dvcs.w3.org/hg/FXTF/raw-file/tip/filters/index.html`](https://dvcs.w3.org/hg/FXTF/raw-file/tip/filters/index.html)

+   SVG 规范的**滤镜效果**部分在[`www.w3.org/TR/SVG/filters.html`](http://www.w3.org/TR/SVG/filters.html)

+   MSDN 上的**滤镜**部分在[`msdn.microsoft.com/en-us/library/ms532847(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/ms532847(v=vs.85).aspx)

# 总结

在本章中，我们发现了如何使用 CSS 处理 HTML5 `video`元素；我们了解到浏览器的行为非常不同，因此我们必须实施各种技术以实现兼容性。

我们找出了如何动态添加蒙版 - 静态或动画 - 以及如何创建滤镜，无论是使用 SVG 还是新的 W3C 规范。

在下一章中，我们将学习如何处理复杂的动画。


# 第八章：仪表

在 Web 应用程序开发中，仪表可以用于以视觉或直观的方式显示复杂或动态数据。在本章中，我们将学习如何创建一个完全可定制的动画仪表，可以对实时变化做出响应。我们还将讨论将此类小部件移植到旧的 Web 浏览器中的技术。我们将首先学习一个名为**Compass**的很酷的 SASS 增强功能；这是处理 CSS3 实验前缀的另一种方法。以下是我们将讨论的主题列表：

+   基本仪表结构

+   使用 Compass

+   使用 rem

+   移动箭头

+   动画化箭头

+   处理旧的浏览器

# 基本仪表结构

让我们从一个新项目开始；像往常一样，我们需要创建一个`index.html`文件。这次所涉及的标记非常小而紧凑，我们现在可以立即添加它：

```css
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge" />

  <title>Go Go Gauges</title>

  <link rel="stylesheet" type="text/css" href="css/application.css">
</head>
<body>

 <div data-gauge data-min="0" data-max="100" data-percent="50">
 <div data-arrow></div>
 </div>

</body>
</html>
```

仪表小部件由`data-gauge`属性标识，并使用其他三个自定义数据属性进行定义；即`data-min`，`data-max`和`data-percent`，它们表示范围的最小和最大值以及以百分比值表示的当前箭头位置。

在标有`data-gauge`属性的元素内，我们定义了一个将成为仪表箭头的`div`标记。

要开始样式化阶段，我们首先需要装备一个易于使用并且可以为我们提供生成 CSS 代码的框架。我们决定使用 SASS，与我们在第五章中使用的相同，*图库*，因此我们首先需要安装 Ruby（[`www.ruby-lang.org/en/downloads/`](http://www.ruby-lang.org/en/downloads/)），然后从命令行终端输入以下内容：

```css
gem install sass

```

### 注意

如果您在 Unix/Linux 环境中工作，可能需要执行以下命令：

```css
sudo gem install sass

```

# 安装 Compass

对于这个项目，我们还将使用 Compass，这是一个 SASS 扩展，能够为我们的 SASS 样式表添加一些有趣的功能。

要安装 Compass，我们只需在终端窗口中输入`gem install compass`（或`sudo gem install compass`）。安装过程结束后，我们必须在项目的根文件夹中创建一个名为`config.rb`的小文件，其中包含以下代码：

```css
# Require any additional compass plugins here.

# Set this to the root of your project when deployed:
http_path = YOUR-HTTP-PROJECT-PATH
css_dir = "css"
sass_dir = "scss"
images_dir = "img"
javascripts_dir = "js"

# You can select your preferred output style here (can be overridden via the command line):
# output_style = :expanded or :nested or :compact or :compressed

# To enable relative paths to assets via compass helper functions. Uncomment:
relative_assets = true

# To disable debugging comments that display the original location of your selectors. Uncomment:
# line_comments = false

preferred_syntax = :sass 

```

`config.rb`文件帮助 Compass 了解项目的各种资产的位置；让我们详细了解这些选项：

+   `http_path`：这必须设置为与项目根文件夹相关的 HTTP URL

+   `css_dir`：这包含了生成的 CSS 文件应保存的文件夹的相对路径

+   `sass_dir`：这包含了包含我们的`.scss`文件的文件夹的相对路径

+   `images_dir`：这包含了项目所有图像的文件夹的相对路径

+   `javascripts_dir`：与`images_dir`类似，但用于 JavaScript 文件

还有其他可用的选项；我们可以决定输出的 CSS 是否应该被压缩，或者我们可以要求 Compass 使用相对路径而不是绝对路径。有关所有可用选项的完整列表，请参阅[`compass-style.org/help/tutorials/configuration-reference/`](http://compass-style.org/help/tutorials/configuration-reference/)上的文档。

接下来，我们可以创建刚才描述的文件夹结构，为我们的项目提供`css`，`img`，`js`和`scss`文件夹。最后，我们可以创建一个空的`scss/application.scss`文件，并开始发现 Compass 的美丽。

# CSS 重置和供应商前缀

我们可以要求 Compass 在对其 SCSS 对应文件进行每次更新后重新生成 CSS 文件。为此，我们需要在项目的根目录中使用终端执行以下命令：

```css
compass watch .

```

Compass 提供了一个替代我们在上一个项目中使用的 Yahoo!重置样式表。要包含此样式表，我们只需在`application.scss`文件中添加一个 SASS `include`指令：

```css
@import "compass/reset";

```

如果我们检查`css/application.css`，结果如下（已修剪）：

```css
/* line 17, ../../../../.rvm/gems/ruby-1.9.3-p194/gems/compass-0.12.2/frameworks/compass/stylesheets/compass/reset/_utilities.scss */
html, body, div, span, applet, object, iframe,
h1, h2, h3, h4, h5, h6, p, blockquote, pre,
a, abbr, acronym, address, big, cite, code,
del, dfn, em, img, ins, kbd, q, s, samp,
small, strike, strong, sub, sup, tt, var,
b, u, i, center,
dl, dt, dd, ol, ul, li,
fieldset, form, label, legend,
table, caption, tbody, tfoot, thead, tr, th, td,
article, aside, canvas, details, embed,
figure, figcaption, footer, header, hgroup,
menu, nav, output, ruby, section, summary,
time, mark, audio, video {
  margin: 0;
  padding: 0;
  border: 0;
  font: inherit;
  font-size: 100%;
  vertical-align: baseline;
}

/* line 22, ../../../../.rvm/gems/ruby-1.9.3-p194/gems/compass-0.12.2/frameworks/compass/stylesheets/compass/reset/_utilities.scss */
html {
  line-height: 1;
}

... 
```

还要注意生成的 CSS 如何保留对原始 SCSS 的引用；当需要调试页面中一些意外行为时，这非常方便。

接下来的`@import`指令将处理 CSS3 实验性供应商前缀。通过在`application.scss`文件顶部添加`@import "compass/css3"`，我们要求 Compass 自动为我们提供许多强大的方法来添加实验性前缀；例如，以下代码片段：

```css
.round {
    @include border-radius(4px);
}
```

编译成以下内容：

```css
.round {
    -moz-border-radius: 4px;
    -webkit-border-radius: 4px;
    -o-border-radius: 4px;
    -ms-border-radius: 4px;
    -khtml-border-radius: 4px;
    border-radius: 4px;
}
```

装备了这些新知识，我们现在可以开始部署项目了。

# 使用 rem

对于这个项目，我们想引入`rem`，这是一个几乎等同于`em`的测量单位，但始终相对于页面的根元素。因此，基本上我们可以在`html`元素上定义一个字体大小，然后所有的大小都将与之相关：

```css
html{
  font-size: 20px;
}
```

现在，`1rem`对应`20px`；这种测量的问题在于一些浏览器，比如 IE8 或更低版本，实际上不支持它。为了解决这个问题，我们可以使用以下两种不同的备用测量单位：

+   `em`：好消息是，`em`如果完全调整，与`rem`完全相同；坏消息是，这种测量单位是相对于元素的`font-size`属性而不是相对于`html`。因此，如果我们决定采用这种方法，那么每次处理`font-size`时，我们都必须特别小心。

+   `px`：我们可以使用固定单位像素大小。这种选择的缺点是在旧版浏览器中，我们使得动态改变小部件比例的能力变得更加复杂。

在这个项目中，我们将使用像素作为我们的测量单位。我们之所以决定这样做，是因为`rem`的一个好处是我们可以通过媒体查询改变字体大小属性来轻松改变仪表的大小。这仅在支持媒体查询和`rem`的情况下才可能。

现在，我们必须找到一种方法来解决大部分重复的问题，即必须两次插入包含空格测量单位的语句（`rem`和`px`）。我们可以通过在我们的`application.scss`文件中创建一个 SASS mixin 来轻松解决这个问题（有关 SASS mixin 的更多信息，我们可以参考[`sass-lang.com/docs/yardoc/file.SASS_REFERENCE.html#mixins`](http://sass-lang.com/docs/yardoc/file.SASS_REFERENCE.html#mixins)的规范页面）：

```css
@mixin px_and_rem($property, $value, $mux){
  #{$property}: 0px + ($value * $mux);
  #{$property}: 0rem + $value;
}
```

因此，下次我们可以写成：

```css
#my_style{
width: 10rem;
}
```

我们可以写成：

```css
#my_style{
@include px_and_rem(width, 10, 20);
}
```

除此之外，我们还可以将`px`和`rem`之间的“乘数”系数保存在一个变量中，并在每次调用此函数和`html`声明中使用它；让我们也将这个添加到`application.scss`中：

```css
$multiplier: 20px;

html{
  font-size: $multiplier;
}
```

当然，仍然有一些情况下我们刚刚创建的`@mixin`指令不起作用，这种情况下我们将不得不手动处理这种二重性。

# 仪表的基本结构

现在我们准备至少开发我们仪表的基本结构，包括圆角边框和最小和最大范围标签。以下代码是我们需要添加到`application.scss`中的：

```css
div[data-gauge]{
  position: absolute;

  /* width, height and rounded corners */
  @include px_and_rem(width, 10, $multiplier);
  @include px_and_rem(height, 5, $multiplier);
  @include px_and_rem(border-top-left-radius, 5, $multiplier);
  @include px_and_rem(border-top-right-radius, 5, $multiplier);

  /* centering */
  @include px_and_rem(margin-top, -2.5, $multiplier);
  @include px_and_rem(margin-left, -5,  $multiplier);
  top: 50%;
  left: 50%;

  /* inset shadows, both in px and rem */
box-shadow: 0 0 #{0.1 * $multiplier} rgba(99,99,99,0.8), 0 0 #{0.1 * $multiplier} rgba(99,99,99,0.8) inset;
  box-shadow: 0 0 0.1rem rgba(99,99,99,0.8), 0 0 0.1rem rgba(99,99,99,0.8) inset;

  /* border, font size, family and color */
  border: #{0.05 * $multiplier} solid rgb(99,99,99);	
  border: 0.05rem solid rgb(99,99,99);

  color: rgb(33,33,33);
  @include px_and_rem(font-size, 0.7, $multiplier);
  font-family: verdana, arial, sans-serif;

  /* min label */
  &:before{
    content: attr(data-min);
    position: absolute;
    @include px_and_rem(bottom, 0.2, $multiplier);
    @include px_and_rem(left, 0.4, $multiplier);
  }

  /* max label */
  &:after{
    content: attr(data-max);
    position: absolute;
    @include px_and_rem(bottom, 0.2, $multiplier);
    @include px_and_rem(right, 0.4, $multiplier);
  }
}
```

使用`box-shadow`和`border`，我们无法使用`px_and_rem`混合，因此我们首先使用`px`，然后使用`rem`复制这些属性。

以下截图显示了结果：

![仪表的基本结构](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_1.jpg)

## 刻度标记

如何处理刻度标记？一种方法是使用图像，但另一个有趣的选择是利用多重背景支持，并用渐变创建这些刻度标记。例如，要创建一个垂直标记，我们可以在`div[data-gauge]`选择器中使用以下内容：

```css
linear-gradient(0deg, transparent 46%, rgba(99, 99, 99, 0.5) 47%, rgba(99, 99, 99, 0.5) 53%, transparent 54%)
```

基本上，我们定义了一个非常小的透明渐变和另一种颜色之间的渐变，以获得刻度线。这是第一步，但我们还没有处理每个刻度线必须用不同的角度来定义这个事实。我们可以通过引入一个 SASS 函数来解决这个问题，该函数接受要打印的刻度数，并在达到该数字时迭代，同时调整每个标记的角度。当然，我们还必须处理实验性的供应商前缀，但我们可以依靠 Compass 来处理。

以下是这个功能。我们可以为此和其他与仪表相关的功能创建一个名为`scss/_gauge.scss`的新文件；前导下划线是告诉 SASS 不要将这个`.scss`文件创建为`.css`文件，因为它将被包含在一个单独的文件中。

```css
@function gauge-tick-marks($n, $rest){
  $linear: null;
  @for $i from 1 through $n {
 $p: -90deg + 180 / ($n+1) * $i;
    $linear: append($linear, linear-gradient( $p, transparent 46%, rgba(99,99,99,0.5) 47%, rgba(99,99,99,0.5) 53%, transparent 54%), comma);
  }
  @return append($linear, $rest);  
}
```

我们从一个空字符串开始，添加调用`linear-gradient` Compass 函数的结果，该函数处理基于当前刻度线索引的角度变化。

为了测试这个功能，我们首先需要在`application.scss`中包含`_gauge.scss`：

```css
@import "gauge.scss";
```

接下来，我们可以在`application.scss`中的`div[data-gauge]`选择器中插入函数调用，指定所需的刻度数：

```css
@include background(gauge-tick-marks(11,null));
```

`background`函数也是由 Compass 提供的，它只是处理实验性前缀的另一种机制。不幸的是，如果我们重新加载项目，结果与预期相去甚远：

![刻度线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_2.jpg)

虽然我们可以看到总共有 11 条条纹，但它们的大小和位置都是错误的。为了解决这个问题，我们将创建一些函数来设置`background-size`和`background-position`的正确值。

## 处理背景大小和位置

让我们从`background-size`开始，这是最简单的。由于我们希望每个刻度线的大小恰好为`1rem`，我们可以通过创建一个函数，根据传递的参数的数量打印**1rem 1rem**，来继续进行；因此，让我们将以下代码添加到`_gauge.scss`中：

```css
@function gauge-tick-marks-size($n, $rest){
  $sizes: null;
  @for $i from 1 through $n {
 $sizes: append($sizes, 1rem 1rem, comma);
  }
  @return append($sizes, $rest, comma);
}
```

我们已经注意到了`append`函数；关于它的一个有趣的事情是，这个函数的最后一个参数让我们决定是否使用某个字母来连接正在创建的字符串。其中一个可用的选项是`逗号`，这非常适合我们的需求。

现在，我们可以在`div[data-gauge]`选择器内添加对这个函数的调用：

```css
background-size: gauge-tick-marks-size(11, null);
```

以下是结果：

![处理背景大小和位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_3.jpg)

现在刻度线的大小是正确的，但它们是一个接一个地显示，并且在整个元素上重复。为了避免这种行为，我们可以在上一条指令的下面简单地添加`background-repeat: no-repeat`：

```css
background-repeat: no-repeat;
```

另一方面，为了处理刻度线的位置，我们需要另一个 SASS 函数；这次它更复杂一些，涉及一点三角学。每个渐变必须放在其角度的函数中——x 是该角度的余弦，y 是正弦。`sin`和`cos`函数由 Compass 提供，我们只需要处理一下偏移，因为它们是相对于圆的中心，而我们的 css 属性的原点是在左上角。

```css
@function gauge-tick-marks-position($n, $rest){
  $positions: null;
  @for $i from 1 through $n {
 $angle: 0deg + 180 / ($n+1) * $i;
 $px: 100% * ( cos($angle) / 2 + 0.5 );
 $py: 100% * (1 - sin($angle));
    $positions: append($positions, $px $py, comma);
  }
  @return append($positions, $rest, comma);
}
```

现在我们可以继续在`div[data-gauge]`选择器内添加一行新代码：

```css
background-position: gauge-tick-marks-position(11, null);
```

这就是期待已久的结果：

![处理背景大小和位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_4.jpg)

下一步是创建一个`@mixin`指令来将这三个函数放在一起，这样我们可以将以下内容添加到`_gauge.scss`中：

```css
@mixin gauge-background($ticks, $rest_gradient, $rest_size, $rest_position) {

  @include background-image(
    gauge-tick-marks($ticks, $rest_gradient) 
  );

  background-size: gauge-tick-marks-size($ticks, $rest_size);
  background-position: gauge-tick-marks-position($ticks, $rest_position);
  background-repeat: no-repeat;
}
```

并用一个单独的调用替换我们在本章中放置在`div[data-gauge]`内的内容：

```css
@include gauge-background(11, null, null, null );
```

我们还留下了三个额外的参数来定义`background`、`background-size`和`background-position`的额外值，因此我们可以很容易地添加一个渐变背景：

```css
@include gauge-background(11,
  radial-gradient(50% 100%, circle, rgb(255,255,255), rgb(230,230,230)),
  cover,
  center center
);
```

以下是屏幕截图：

![处理背景大小和位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_5.jpg)

# 创建箭头

要创建一个箭头，我们可以从定义仪表中心的圆形元素开始，该元素容纳箭头。这很容易，也没有真正引入任何新东西；以下是需要嵌套在`div[data-gauge]`选择器内的代码：

```css
  div[data-arrow]{
    position: absolute;
    @include px_and_rem(width, 2, $multiplier);
    @include px_and_rem(height, 2, $multiplier);
    @include px_and_rem(border-radius, 5, $multiplier);
    @include px_and_rem(bottom, -1, $multiplier);
    left: 50%;
    @include px_and_rem(margin-left, -1, $multiplier);
   box-sizing: border-box;

    border: #{0.05 * $multiplier} solid rgb(99,99,99);  
    border: 0.05rem solid rgb(99,99,99);
    background: #fcfcfc;
  }
```

箭头本身是一个更严肃的事情；基本思想是使用线性渐变，只在元素的一半开始添加颜色，然后我们可以旋转元素，以便将指向末端移动到其中心。以下是需要放在`div[data-arrow]`内的代码：

```css
    &:before{
      position: absolute;
      display: block;
      content: '';
      @include px_and_rem(width, 4, $multiplier);
      @include px_and_rem(height, 0.5, $multiplier);
      @include px_and_rem(bottom, 0.65, $multiplier);
      @include px_and_rem(left, -3, $multiplier);
 background-image: linear-gradient(83.11deg, transparent, transparent 49%, orange 51%, orange); 
 background-image: -webkit-linear-gradient(83.11deg, transparent, transparent 49%, orange 51%, orange); 
 background-image: -moz-linear-gradient(83.11deg, transparent, transparent 49%, orange 51%, orange);
 background-image: -o-linear-gradient(83.11deg, transparent, transparent 49%, orange 51%, orange); 

 @include apply-origin(100%, 100%);
 @include transform2d( rotate(-3.45deg));
 box-shadow: 0px #{-0.05 * $multiplier} 0 rgba(0,0,0,0.2);
 box-shadow: 0px -0.05rem 0 rgba(0,0,0,0.2);			@include px_and_rem(border-top-right-radius, 0.25, $multiplier);
 @include px_and_rem(border-bottom-right-radius, 0.35, $multiplier);
    }
```

为了更好地理解这个实现背后的技巧，我们可以暂时在结果中的`&:before`选择器内添加`border: 1px solid red`，然后放大一点：

![创建箭头](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_6.jpg)

## 移动箭头

现在我们想要根据`data-percent`属性值将箭头定位到正确的角度。为了做到这一点，我们必须利用 SASS 的强大功能。理论上，CSS3 规范允许我们使用从属性中获取的值来赋值给一些属性，但实际上，这只有在处理`content`属性时才可能，就像我们在本书中之前看到的那样。

所以我们要做的是创建一个`@for`循环，从`0`到`100`，并在每次迭代中打印一个选择器，该选择器匹配`data-percent`属性的定义值。然后我们将为每个 CSS 规则设置不同的`rotate()`属性。

以下是代码；这次它必须放在`div[data-gauge]`选择器内：

```css
@for $i from 0 through 100 {
  $v: $i;
  @if $i < 10 { 
    $v: '0' + $i;
  }

  &[data-percent='#{$v}'] > div[data-arrow]{
      @include transform2d(rotate(#{180deg * $i/100}));
  }
}
```

如果你对生成的 CSS 数量感到害怕，那么你可以决定调整仪表的增量，例如，调整为`10`：

```css
  @for $i from 0 through 10 {
    &[data-percent='#{$i*10}'] > div[data-arrow]{
      @include transform2d(rotate(#{180deg * $i/10}));
    }
  }
```

以下是结果：

![移动箭头](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_7.jpg)

# 动画仪表

现在我们可以使用 CSS 过渡来使箭头动画化。基本上，我们必须告诉浏览器需要对`transform`属性进行动画处理；必要的 SASS 代码比预期的要长一些，因为 Compass 尚不能为`transition`属性及其值添加前缀（[`github.com/chriseppstein/compass/issues/289`](https://github.com/chriseppstein/compass/issues/289)），所以我们必须手动完成：

```css
  -webkit-transition: -webkit-transform 0.5s;
  -moz-transition: -moz-transform 0.5s;
  -ms-transition: -ms-transform 0.5s;
  -o-transition: -o-transform 0.5s;
  transition: transform 0.5s;
```

当我们将这些 CSS 指令放在`div[data-arrow]`选择器内时，我们会注意到，如果我们改变`data-percentage`属性，例如，使用 Chrome 和它的开发控制台，箭头会以平滑的动画做出响应。

# 整体指示器

一些仪表具有颜色指示器，通常从绿色到红色，与箭头的位置相关联；我们可以得出类似的结果。首先，我们需要定义两个新的自定义数据属性，一个指示指示器从绿色切换到橙色的百分比，另一个指示指示器从橙色切换到红色的百分比。在这里：

```css
<div data-gauge data-min="0" data-max="100" data-percent="50" data-orange-from="60" data-red-from="90">
  <div data-arrow></div>
</div>
```

然后我们需要在`div[data-gauge]`中指定一个默认的背景颜色，比如说`green`：

```css
background-color: green;
```

接下来，我们重新定义背景渐变，使圆周的前 25%透明；这样我们就可以显示（和控制）底层颜色，所以让我们重新编写`gauge-background`调用：

```css
@include gauge-background(11,
 radial-gradient(50% 100%, circle, rgba(255,255,255,0), rgba(255,255,255,0) 25%, rgb(255,255,255) 25%, rgb(230,230,230)),
  cover,
  center center
);
```

现在我们可以使用另一个 Sass 循环来改变`background-color`属性，以符合属性中定义的值。由于我们将在前一个循环中嵌套实现一个循环，我们必须小心，不要使生成的 CSS 的大小增加太多。

为了实现这一点，让我们只考虑`data-orange-from`和`data-red-from`数据属性的十位数。我们需要做的基本上是编写一个 CSS 规则，如果`data-percentage`属性大于或等于`data-orange-from`或`data-red-from`，则激活红色或橙色背景颜色。

以下是完整的循环，包括我们之前用来移动箭头的循环：

```css
@for $i from 0 through 100 {
  $v: $i;
  @if $i < 10 { 
    $v: '0' + $i;
  } 

  &[data-percent='#{$v}'] > div[data-arrow]{
    @include transform2d(rotate(#{180deg * $i/100}));
  }

 @for $k from 0 through 10 {
 @if $i >= $k * 10 {
 &[data-percent='#{$v}'][data-orange-from^='#{$k}']{
 background-color: orange;
 }
 &[data-percent='#{$v}'][data-red-from^='#{$k}']{
 background-color: red;
 }
 }
 }
}
```

以下是结果：

![整体指示器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_8.jpg)

## 减小 CSS 的大小

通过要求 Compass 不在每个规则之前添加指向相应 SASS 规则的注释，可以减少生成的 CSS 的大小。如果我们想要这样做，只需在`config.rb`文件中添加`line_comments = false`，然后在项目的根文件夹中停止并重新启动`compass watch`。

# 添加一些颤动

作为一个额外的功能，我们可以添加一个选项，让箭头在接近 100%时颤动一点。如果存在额外的`data-trembling`属性，我们可以通过添加一个小动画来实现这种行为：

```css
<div data-gauge data-min="0" data-max="100" data-percent="50" data-orange-from="60" data-red-from="90" data-trembling>

```

不幸的是，Compass 没有默认提供 CSS3 动画 mixin，因此我们必须安装一个可以帮助我们的 Compass 插件。在这种情况下，插件称为**compass-animation**（[`github.com/ericam/compass-animation`](https://github.com/ericam/compass-animation)），由 Eric Meyer 创建（[`eric.andmeyer.com/`](http://eric.andmeyer.com/)）。安装方法如下：

```css
gem install animation –pre

```

或者如下：

```css
sudo gem install animation –-pre

```

然后在调用`compass watch`时必须同时包含插件：

```css
compass watch . –r animation

```

在`application.scss`的头部添加：

```css
@import "animation";
```

干得好！现在我们准备定义一个非常简单的动画，修改箭头的旋转角度，引起我们寻找的颤动效果。让我们在`application.scss`的末尾添加几行代码：

```css
@include keyframes(trembling) {
  0% {
      @include transform2d( rotate(-5.17deg));
  }
  100% {
      @include transform2d( rotate(-1.725deg));
  }
}
```

然后，我们需要在`div[data-gauge]`内添加一个新规则，如果`data-trembling`存在，并且`data-percentage`以`8`或`9`开头，或者等于`100`，则激活此动画：

```css
&[data-trembling][data-percent^='8'] > div[data-arrow]:before,
&[data-trembling][data-percent^='9'] > div[data-arrow]:before,
&[data-trembling][data-percent='100'] > div[data-arrow]:before{
 @include animation(trembling 0.2s infinite linear alternate);
}
```

不幸的是，由于 WebKit 浏览器中一些尚未解决的错误，阻止动画应用于`before`和`after`伪选择器，目前只有 Firefox 正确实现了这种行为：

![添加一些颤动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_9.jpg)

# 显示仪表值

如果我们对 HTML 代码进行小修改，就可以轻松显示当前的仪表值：

```css
<div data-gauge data-min="0" data-max="100" data-percent="50" data-orange-from="60" data-red-from="90" data-trembling>
<span>50</span>
  <div data-arrow></div>
</div>
```

以下是要添加到`div[data-gauge]`选择器内的代码：

```css
span{
  display: block;
  color: #DDD;
  @include px_and_rem(font-size, 1.5, $multiplier);
  text-align: center;
  @include px_and_rem(width, 10, $multiplier);
  @include px_and_rem(height, 5, $multiplier);
  @include px_and_rem(line-height, 5, $multiplier);
}
```

结果：

![显示仪表值](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_10.jpg)

# 优雅降级

为了使这个小部件对那些不支持背景渐变的浏览器也有意义，我们必须处理箭头的不同表示。为了检测缺少此功能的位置，我们可以使用 Modernizr 创建一个自定义构建（[`modernizr.com/download/`](http://modernizr.com/download/)），就像我们在前几章中只检查渐变支持一样：

```css
<script src="img/modernizr.js"></script>
```

然后我们可以选择一个纯色背景；箭头当然会变成一个矩形，但我们会保留小部件的含义；让我们在`application.scss`的底部添加这条规则：

```css
.no-cssgradients div[data-gauge]{ 

 div[data-arrow]:before{
 background-color: orange;
 @include transform2d( rotate(0deg));
 box-shadow: none;
 border-radius: 0;
 }
}
```

以下是结果：

![优雅降级](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_11.jpg)

我们可以进一步使用 Compass 将渐变转换为`Base64`编码的 SVG，并在本机不支持渐变的情况下将它们用作回退背景图像。不幸的是，这在使用数值表达角度的渐变（如`23deg`）时不起作用，因此我们将无法重现刻度线。但是，我们可以要求 Compass 转换我们用于背景的`radial-gradient`属性。以下是我们需要在`.no-cssgradients div[data-gauge]`规则内添加的属性：

```css
background-image: -svg(radial-gradient(50% 100%, circle, rgba(255,255,255,0), rgba(255,255,255,0) 35%, rgb(255,255,255) 35%, rgb(230,230,230)));
background-size: cover;
background-position: auto;
```

以下是结果，更接近原始仪表：

![优雅降级](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_12.jpg)

# 在 Internet Explorer 8 中实现仪表

如果我们想支持 Internet Explorer 8，那么我们需要解决`border-radius`和`transform`属性的缺失。

对于`border-radius`，我们可以使用基于 JavaScript 的 polyfill，比如 CSS3 Pie，我们可以从它的网站[`css3pie.com/`](http://css3pie.com/)下载这个 polyfill，然后将`PIE.js`复制到项目的`js`文件夹中。接下来，我们可以在`index.html`中包含这个 JavaScript 文件，以及最新版本的 jQuery 和`js/application.js`，这是一个我们一会儿要用到的空文件：

```css
<!--[if IE 8]>
  <script src="img/jquery-1.8.0.min.js"></script>
  <script src="img/PIE.js"></script>
  <script src="img/application.js"></script>
<![endif]-->
```

通常情况下，CSS3 Pie 会自动检测如何增强给定元素，通过识别要模拟的 CSS3 属性。然而，在这种情况下，我们使用了`border-top-left-radius`和`border-top-right-radius`，而 CSS3 Pie 只支持通用的`border-radius`。我们可以通过在`div[data-gauge]`规则中添加一个带有`-pie`前缀的特殊`border-radius`属性来解决这个问题：

```css
-pie-border-radius: #{5 * $multiplier} #{5 * $multiplier} 0px 0px;

```

接下来，我们需要通过在`js/application.js`中插入几行 JavaScript 代码来激活 CSS3 Pie：

```css
$(function() {
    if (window.PIE) {
 $('div[data-gauge]').each(function() {
 PIE.attach(this);
 });
    }
});
```

以下是结果：

![在 Internet Explorer 8 中实现仪表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_13.jpg)

现在，如果我们想要激活箭头旋转，我们需要模拟`transform`属性。为了实现这种行为，我们可以使用 Louis-Rémi Babé的`jquery.transform.js`（[`github.com/louisremi/jquery.transform.js`](https://github.com/louisremi/jquery.transform.js)）；Louis-Rémi Babé（[`twitter.com/louis_remi`](http://twitter.com/louis_remi)）。

下载完库之后，我们需要将`jquery.transform2d.js`复制到项目的`js`文件夹中。然后在`index.html`中添加必要的`script`元素。为了在 Internet Explorer 8 浏览器中为`html`元素添加不同的类，我们将使用`IE`条件注释来为`html`元素添加不同的类。结果如下：

```css
<!doctype html>
<!--[if IE 8]> <html class="ie8" > <![endif]-->
<!--[if !IE]> --> <html> <!-- <![endif]-->
<head>
  <title>Go Go Gauges</title>
  <script src="img/modernizr.js"></script>
  <link rel="stylesheet" type="text/css" href="css/application.css">
  <!--[if IE 8]>
    <script src="img/jquery-1.8.0.min.js"></script>
 <script src="img/jquery.transform2d.js"></script>
    <script src="img/PIE.js"></script>
    <script src="img/application.js"></script>
  <![endif]-->
</head>
<!-- ...rest of index.html ... -->
```

`jquery.transform2d.js`使得即使在 Internet Explorer 8 浏览器上也能触发`transform`属性，从而增强了 jQuery 提供的`css`功能；以下是一个例子：

```css
$(elem).css('transform', 'translate(50px, 30px) rotate(25deg) scale(2,.5) skewX(-35deg)');
```

因此，我们可以尝试通过调用前述函数添加一些 JavaScript 代码行；这将使`js/application.js`变成如下形式：

```css
$(function() {
    if (window.PIE) {
        $('div[data-gauge]').each(function() {
            PIE.attach(this);

 var angle = Math.round(180 * parseInt($(this).attr('data-percent'),10)/100);
 $('div[data-arrow]',$(this)).css({
 'transform': 'rotate(' + angle + 'deg)'
 });
        });
    }
});
```

不幸的是，结果并不如预期那样好：

![在 Internet Explorer 8 中实现仪表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_14.jpg)

问题在于`div[data-arrow]:before`元素被裁剪在其父元素内。这可以通过在箭头下方绘制一个白色圆盘（现在是一个正方形），并将`div[data-arrow]`调整大小为整个小部件，并且背景透明且没有边框，以便容纳箭头。

为此，我们可以使用`.ie8`类，仅在浏览器为 Internet Explorer 8 时添加一些属性。让我们在`application.scss`中添加几行代码。

```css
.ie8 div[data-gauge]{
  div[data-arrow]{
    width: #{10 * $multiplier};
    height: #{10 * $multiplier};
    margin-top: #{-5 * $multiplier};
    margin-left: #{-5 * $multiplier};
    top: 50%;
    left: 50%;
    background: transparent;
    border: none;
    &:before{
      bottom: 50%;
      margin-bottom: #{-0.25 * $multiplier};
      left: #{1 * $multiplier};
    }
  }
}
```

最后，以下是工作结果：

![在 Internet Explorer 8 中实现仪表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_15.jpg)

# Compass 和 Internet Explorer 10

在撰写本文时，Compass 的最新版本（0.12.0）没有为`linear-gradient`和`radial-gradient`添加`-ms-`实验性前缀。为了解决这个问题并使仪表在 IE10 上顺利工作，我们必须对我们的`.scss`代码进行一些修改。特别是，我们需要按照以下方式修改`_gauge.scss`中的`gauge-tick-marks`函数：

```css
@function gauge-tick-marks($n, $rest, $ms){
  $linear: null;
  @for $i from 1 through $n {
    $p: -90deg + 180 / ($n+1) * $i;
 $gradient: null;
 @if $ms == true {
 $gradient: -ms-linear-gradient( $p, transparent 46%, rgba(99,99,99,0.5) 47%, rgba(99,99,99,0.5) 53%, transparent 54%);
 } @else{
 $gradient: linear-gradient( $p, transparent 46%, rgba(99,99,99,0.5) 47%, rgba(99,99,99,0.5) 53%, transparent 54%);
 }
    $linear: append($linear, $gradient, comma);
  }
 @if $ms == true {
 @return append($linear, #{'-ms-' + $rest} ); 
 } @else{
 @return append($linear, $rest); 
 }
}
```

我们还需要在`_gauge.scss`中修改`gauge-background` mixin：

```css
@mixin gauge-background($ticks, $rest_gradient, $rest_size, $rest_position) {

 @include background-image(
 gauge-tick-marks($ticks, $rest_gradient, false) 
 );

 background-image: gauge-tick-marks($ticks, $rest_gradient, true);

  background-size: gauge-tick-marks-size($ticks, $rest_size);
  background-position: gauge-tick-marks-position($ticks, $rest_position);
  background-repeat: no-repeat;
}
```

最后，我们还需要在`application.scss`中的`:before`中的`div[data-arrow]`中添加额外的 CSS 行：

```css
background-image: -ms-linear-gradient(83.11deg, transparent, transparent 49%, orange 51%, orange);
```

在进行这些小修改之后，我们也可以在 Internet Explorer 10 中欣赏到这个小部件：

![Compass 和 Internet Explorer 10](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_08_16.jpg)

# 总结

绘制仪表可能比预期更困难；如果我们还要考虑支持旧版浏览器，情况就更加复杂。在本章中，我们学习了如何安装和使用 Compass，利用 SASS 语法的强大功能创建复杂的 CSS，并处理优雅降级和填充技术。在下一章中，我们将利用 CSS 动画和 3D 变换的功能创建一个电影预告片。


# 第九章：创建介绍

这个项目的目标是创建一个介绍，一个非交互式的动画，使用文本和视觉效果来呈现产品、概念或其他内容。这个项目让我们有机会探索一些高级动画和 3D 主题，并在创建一些特定函数来处理这种复杂性的同时扩展我们对 Compass 的了解。

本章将涵盖以下主题：

+   新的 flexbox 模型

+   创建关键帧动画

+   连接动画

+   CSS 3D 属性的动画

# 项目描述

我们想要在 3D 场景中放置一些元素，然后穿过它们。为此，我们首先必须创建一个 HTML 结构来容纳这些元素，然后我们必须找到一种聪明的方法来获得所需的效果。但是，在做任何其他事情之前，我们必须定义文件夹结构并初始化项目的基本文件。

与之前的项目一样，我们将使用 SASS 和 Compass，因此我们需要安装 Ruby ([`www.ruby-lang.org/en/downloads/`](http://www.ruby-lang.org/en/downloads/))，然后在终端窗口中输入`gem install compass`（或`sudo gem install compass`）。之后，我们需要在项目的根文件夹中创建一个`config.rb`文件，其中包含 Compass 配置：

```css
# Require any additional compass plugins here.

# Set this to the root of your project when deployed:
http_path = "YOUR-HTTP-PROJECT-PATH"
css_dir = "css"
sass_dir = "scss"
images_dir = "img"
javascripts_dir = "js"

# You can select your preferred output style here (can be overridden via the command line):
# output_style = :expanded or :nested or :compact or :compressed

# To enable relative paths to assets via compass helper functions. Uncomment:
relative_assets = true

# To disable debugging comments that display the original location of your selectors. Uncomment:
line_comments = false

preferred_syntax = :sass
```

干得好！下一步是创建项目所需的文件夹，即`css`、`scss`、`img`和`js`，并定义一个空的`scss/application.scss`文件。然后我们需要从项目的根文件夹启动`compass watch .`，最后创建主 HTML 文档`index.html`。

# 创建 HTML 结构

我们要创建的基本上是一个幻灯片放置在 3D 空间中，动画从一张幻灯片移动到另一张。一个基本的幻灯片结构可以是这样的：

```css
<div data-sequence="1">
  <div data-slide>
    Hello,
  </div>
</div>
```

我们需要两个嵌套的`div`标签来定义这个结构；第一个将覆盖窗口区域的 100%，第二个`div`标签将具有必要的属性来将其内容放在屏幕中央。此外，我们需要设置每个幻灯片，使它们在开始在 3D 空间中移动之前堆叠在彼此上方。

我们可以使用`flexbox` CSS 属性来实现这个结果。事实上，flexbox 具有定义垂直和水平对齐的属性。

让我们根据我们迄今为止所见的内容定义一个基本的 HTML 结构：

```css
<!doctype html>
<html>
<head>
  <title>Movie Trailer</title>
  <link href='http://fonts.googleapis.com/css?family=Meie+Script' rel='stylesheet' type='text/css'>
  <link rel="stylesheet" type="text/css" href="css/application.css">
</head>
<body>
 <div id="viewport">
 <div id="container">

 <div data-sequence="1">
 <div data-slide>
 Hello,
 </div>
 </div>

 <div data-sequence="2">
 <div data-slide>
 this is a demo
 </div>
 </div>

 <div data-sequence="3">
 <div data-slide>
 about the power
 </div>
 </div>

 <div data-sequence="4">
 <div data-slide>
 of CSS 3D 
 </div>
 </div>

 <div data-sequence="5">
 <div data-slide>
 and animations
 </div>
 </div>

 <div data-sequence="6">
 <div data-slide>
 :D
 </div>
 </div>

 </div>
 </div>
</body>
</html>
```

没有任何 CSS 的幻灯片将是这样的：

![创建 HTML 结构](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_1.jpg)

## 创建幻灯片

首先，让我们将每个幻灯片的`position`属性设置为`absolute`，并通过在`scss/application.scss`中编写几行代码将`width`和`height`设置为`100%`：

```css
@import "compass/reset";
@import "compass/css3/box";
@import "compass/css3/transform";

html,body, #viewport, #container{
  height: 100%;
  font-size: 150px;
}

#container{

  & > div{
    width: 100%;
    height: 100%;
    position: absolute;
    top: 0;
    left: 0;    
  } 

  div[data-slide]{
    width: 100%;
    height: 100%;
    text-align: center;

 @include display-box;
 @include box-align(center);
 @include box-pack(center);
  }

}
```

Flexbox 非常方便，由于`box-pack`和`box-align`属性，它基本上在主 Flexbox 方向（默认为水平，但可以通过`box-orient`属性更改）和其垂直方向上设置对齐。

由于这个项目目前只在 Chrome 和 Firefox 上运行（IE10 似乎在使用嵌套的 3D 变换时存在一些问题），我们对这些属性感到满意；否则，我们应该记住，旧的 Flexbox 语法（我们正在使用的 2009 年的语法）不受 Internet Explorer 10 的支持。

微软的最新浏览器只包括对最新的 Flexbox 实现的支持，它有一个相当不同的语法，不幸的是，它目前还不能在基于 Gecko 的浏览器上工作。

在第四章*缩放用户界面*中，我们开发了一个项目，尽管使用了不受支持的 Flexbox 语法，但在 IE10 中也运行得很好。这是因为在那种情况下，我们包含了 Flexie，一个模拟 Flexbox 行为的 polyfill，当旧的 Flexbox 语法不受支持时。

让我们深入了解这种新的 Flexbox 语法的细节，并为了完整起见，让我们将两种语法都添加到这个项目中。

# 新的弹性盒模型

新的灵活布局模型（从这里开始，以及在本章的整个过程中，被称为 Flexbox）旨在像其以前的版本一样，为开发人员提供一种在页面上对齐元素的新方法。

使用这种新的盒模型的元素可以垂直或水平放置，并可以动态交换它们的顺序，还可以根据可用空间“伸缩”它们的大小和位置。

这里有一个例子（在 Internet Explorer 10 上测试）：

```css
<!DOCTYPE html>

<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title></title>

        <style>
            html,body,ul{
                height: 100%;
                margin: 0;
                padding: 0;
            }
 ul{
 display: -ms-flexbox;
 -ms-flex-direction: row-reverse;
 -ms-flex-pack: center;
 -ms-flex-align: center;
 -ms-flex-wrap: wrap;
 }
 li {
 font-size: 70px;
 line-height: 100px;
 text-align: center;
 list-style-type: none;
 -ms-flex: 1 0 200px;
 }

        </style>

    </head>
    <body>

        <ul>
            <li style="background-color: #f9f0f0">A</li>
            <li style="background-color: #b08b8b">B</li>
            <li style="background-color: #efe195">C</li>
            <li style="background-color: #ccdfc4">D</li>
        </ul>

    </body>
</html>
```

这是生成的页面：

![新的弹性盒模型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_2.jpg)

通过之前定义的属性，我们使用了`display: -ms-flexbox`来定义了一个 Flexbox（W3C 的值是`flex`，但每个浏览器都会稍微改变这个值，要么通过添加自定义前缀，要么稍微改变它）。我们使用了`-ms-flex-direction: row-reverse`来反转可视化顺序；这个属性也用于指定我们想要水平还是垂直排列。可用的值有：`row`、`column`、`row-reverse`和`column-reverse`。`-ms-flex-pack`和`-ms-flex-align`属性确定了 Flexbox 子元素在它们的主轴和垂直轴上的对齐方式（如`-ms-flex-direction`所指定的）。

这些属性仍然是 Flexbox IE10 实现的一部分，但最近已被`align-items`和`justify-content`替换，因此在整合时我们也需要注意这一点。

我们使用了`-ms-flex-wrap: wrap`来要求浏览器在主轴上的空间不足以容纳所有元素时将元素放置在多行上。

最后，我们在每个元素上使用了`-ms-flex: 1 0 200px`来指示每个子元素具有正的 flex 因子`1`，因此它们将以相同的速度覆盖空白空间，保持它们的大小相等，负的 flex 因子`0`，和一个首选大小`200px`。

这与我们之前指定的`-ms-flex-wrap`属性一起，创建了一个有趣的响应效果，当浏览器窗口太小无法容纳它们在一行时，元素会移动到新的行：

![新的弹性盒模型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_3.jpg)

## 创建一个示例布局

我们可以利用这个属性来创建一个三列布局，其中两个侧列在没有足够空间的情况下移动到中央列的上方和下方，比如在移动设备上。以下是创建这种布局的代码：

```css
<!DOCTYPE html>

<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title></title>

        <style>
 section {
 min-height: 300px; 
 }

 div {
 display: -ms-flexbox;
 -ms-flex-direction: row;
 -ms-flex-pack: center;
 -ms-flex-wrap: wrap;
 }

 aside, nav {
 -ms-flex: 1 3 180px;
 min-height: 100px;
 }

 nav {
 -ms-flex-order: 1;
 background-color:  #ffa6a6;
 }

 aside {
 -ms-flex-order: 3;
 background-color:  #81bca1;
 }

 section {
 -ms-flex: 3 1 600px;
 -ms-flex-order: 2;
 background-color: #72c776;
 }
        </style>
    </head>
    <body>

        <div>
            <section></section>
            <nav></nav>
            <aside></aside>
        </div>

    </body>
</html>
```

这是结果：

![创建一个示例布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_4.jpg)

如果我们现在调整浏览器窗口大小，我们会注意到`nav`和`aside`元素如何在主内容上下移动，为移动设备创建了一个漂亮的布局。

![创建一个示例布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_5.jpg)

让我们回到我们的项目；我们可以很容易地通过几行 CSS 来支持 Flexbox 的新版本，如下所示：

```css
  div[data-slide]{
    width: 100%;
    height: 100%;
    text-align: center;

    @include display-box;
    @include box-align(center);
    @include box-pack(center);

 display: -ms-flexbox;
 display: -moz-flex;
 display: -webkit-flex;
 display: flex;
 -ms-flex-pack: center;
 -moz-align-items: center;
 -webkit-align-items: center;
 align-items: center;
 -ms-flex-align: center;
 -moz-justify-content: center;
 -webkit-justify-content: center;
 justify-content: center;
  }
```

这是期待已久的结果：

![创建一个示例布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_6.jpg)

# 处理幻灯片

现在我们可以使用一些 3D`transform`属性来移动和旋转 3D 场景中的每个幻灯片。这些变换是绝对任意的，可以根据电影预告片的整体效果进行选择；这里有一个例子：

```css
div{
  &[data-sequence="1"]{
    @include transform(rotateX(45deg));
  }

  &[data-sequence="2"]{
    @include transform(rotateY(45deg) translateY(300px) scale(0.5));
  }

  &[data-sequence="3"]{
    @include transform(rotateX(90deg) translateY(300px) scale(0.5));
  }

  &[data-sequence="4"]{
    @include transform(rotateX(90deg) translateY(300px) translateX(600px) scale(0.5));
  }

  &[data-sequence="5"]{
    @include transform(rotateX(90deg) translateZ(300px) translateY(350px) translateX(600px) scale(0.5));
  }

  &[data-sequence="6"]{
    @include transform(rotateZ(30deg) translateY(500px) translateZ(300px));
  }
}
```

现在，我们需要在幻灯片的父元素上设置一些 3D 标准属性，如`transform-style`和`perspective`：

```css
#viewport{
  @include transform-style(preserve-3d);
  @include perspective(500px);
  overflow: hidden;
  width: 100%;
}

#container{
    @include transform-style(preserve-3d);
}
```

如果我们现在在 Chrome 中运行项目，我们会注意到幻灯片不像之前的截图中堆叠在一起；相反，它们现在都放置在 3D 场景的各个位置（大部分在变换后不可见）：

![处理幻灯片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_7.jpg)

# 移动摄像机

现在，我们将学习如何创建一个摄像机穿过幻灯片的效果；由于我们无法移动用户的视口，我们需要通过移动场景中的元素来模拟这种感觉；这可以通过对`#container`应用一些变换来实现。

要将摄像机移近幻灯片，我们需要应用我们在该幻灯片上使用的确切变换，但使用相反的值并以相反的顺序。因此，例如，如果我们想查看`data-sequence`属性为`3`的帧，我们可以写：

```css
// not to be permanently added to the project
#container{
    @include transform(scale(2) translateY(-300px) rotateX(-90deg));
}
```

这就是结果：

![移动摄像机](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_8.jpg)

动画必须专注于一张幻灯片，保持静止一段时间，然后移动到下一张幻灯片。在创建这种效果时，我们通常面临以下两个主要问题：

+   CSS `keyframes`只接受百分比值，但我们更愿意使用秒作为测量单位（例如，说“在 2 秒内移动到下一张幻灯片，然后保持静止 1 秒”）

+   我们需要为每个幻灯片处理两个`keyframes`规则（移动和静止）；最好为我们处理这个的是有一个函数

我们可以通过使用 SASS 轻松解决这两个问题。首先，我们可以创建一个函数，通过接受动画的总长度来将秒转换为百分比值：

```css
$total_animation_duration: 11.5;
@function sec_to_per($sec, $dur: $total_animation_duration){
 @return 0% + $sec * 100 / $dur;
}

```

这个函数接受两个参数——我们想要从秒转换为百分比的值以及动画的总长度。如果没有提供这个参数，则该值将设置为`$total_animation_duration`变量。

我们可以为这个项目创建的第二个函数接受`move`时间和`still`时间作为参数，并打印必要的关键帧，同时跟踪动画的进展百分比：

```css
$current_percentage: 0%;
@mixin animate_to_and_wait($move, $still ) {

 $move_increment: sec_to_per($move);
 $current_percentage: $current_percentage + $move_increment;

 #{ $current_percentage }{ @content }

 @if $still == end {
 $current_percentage: 100%;
 } @else{
 $still_increment: sec_to_per($still);
 $current_percentage: $current_percentage + $still_increment;
 }

 #{ $current_percentage }{ @content } 

}
```

这个函数的作用基本上是将`$move`参数转换为百分比，并将这个值添加到全局变量`$current_percentage`中，该变量跟踪动画的进展。

然后我们打印一个关键帧，使用我们刚刚计算的百分比，包含 SASS 为我们填充的`@content`变量的值，该值是我们在函数调用后在花括号中放置的内容，例如：

```css
myfunction(arg1, arg2){
  // everything here is placed into @content variable
}
```

如果`$still`等于`end`，我们希望静止阶段持续到动画结束，所以我们将`$current_percentage`变量设置为`100%`；否则，我们将这个变量与我们处理`$move`变量的方式相同，然后打印另一个关键帧。

# 动画乐趣

为了处理 CSS3 动画属性附带的所有实验性前缀，我们可以再次使用 Compass 动画插件（从命令行终端中使用`gem install animation`进行安装，然后从项目的根文件夹中使用`compass watch . -r animation`重新启动 Compass）。

我们还需要在`application.scss`中包含`animation`：

```css
@import "animation";
```

我们还需要编写一个小函数，它包装了动画插件提供的函数，并在每次从一个实验性前缀切换到另一个时重置`$current_percentage`：

```css
@mixin ext_keyframes($name){

  @include with-only-support-for($moz: true) {
    @-moz-keyframes #{$name} { @content; }
    }
    $current_percentage: 0%;
    @include with-only-support-for($webkit: true) {
    	@-webkit-keyframes #{$name} { @content; }
    }
    $current_percentage: 0%;
    @include with-only-support-for {
      @keyframes #{$name} { @content; }
    }
}
```

好！现在我们准备把事情放在一起并定义我们的动画：

```css
/* == [BEGIN] Camera == */
@include ext_keyframes(camera){
 0%{
 @include transform(none);
 }

 @include animate_to_and_wait(0.5, 1.5){ 
 @include transform(scale(2) rotateX(-45deg));
 }

 @include animate_to_and_wait(0.5, 1.5){
 @include transform(scale(2) translateY(-300px) rotateY(-45deg));
 }

 @include animate_to_and_wait(0.5, 1.5){
 @include transform(scale(2) translateY(-300px) rotateX(-90deg));
 }

 @include animate_to_and_wait(0.5, 1.5){
 @include transform(scale(2) translateX(-600px) translateY(-300px) rotateX(-90deg));
 }

 @include animate_to_and_wait(0.5, 1.5){
 @include transform(scale(2) translateX(-600px) translateY(-350px) translateZ(-300px) rotateX(-90deg));
 }

 @include animate_to_and_wait(0.5, end){
 @include transform(scale(2) translateZ(-300px) translateY(-500px) rotateZ(-30deg));
 }
}
/* == [END] Camera == */
```

最后，我们必须向`#container`添加适当的动画属性：

```css
#container{
@include animation(camera #{0s + $total_animation_duration} linear);
@include animation-fill-mode(forwards);
}
```

完成！在浏览器中进行最后一次重新加载就足以充分欣赏动画：

![动画乐趣](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_9.jpg)

## 步骤动画

我们现在将创建一个特殊的动画，它会与每次幻灯片更改同步切换我们项目的背景颜色。由于我们不希望颜色之间有任何淡入淡出效果，我们将引入步骤动画。

步骤动画让我们可以指定在每个声明的关键帧之间放置多少帧；这里有一个例子：

```css
<!DOCTYPE html>

<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title></title>
        <style>
            div {
                width:  100px;
                height: 100px;
                background-color: red;
                position: absolute;
 -webkit-animation: diagonal 3s steps(5) infinite alternate;
            }

            @-webkit-keyframes diagonal {
                from {  
                    top: 0;
                    left: 0; 
                }
                to {  
                    top: 500px;
                    left: 500px; 
                }
            }

        </style>
    </head>
    <body>
        <div></div>
    </body>
</html>
```

如果我们现在在浏览器中运行这个小例子，我们会发现`div`元素的移动不是流畅的，而是由只有五帧组成。我们可以在步骤声明中添加一个特殊关键字`start`或`end`（例如，`step(5, end)`）来要求浏览器在每一步中跳过初始或最终关键帧。好！现在，我们可以将相同的概念应用到我们的介绍项目中。首先，我们需要定义一个改变`background-color`属性的动画：

```css
/* == [BEGIN] bg == */
@include ext_keyframes(bg){
  0%{
    background: green;
  }
  #{sec_to_per(2)}{
    background: darkolivegreen;
  }
  #{sec_to_per(4)}{
    background: violet;
  }
  #{sec_to_per(6)}{
    background: orange;
  }
  #{sec_to_per(8)}{
    background: lightsteelblue;
  }
  #{sec_to_per(10)}{
    background: thistle;
  }
  100%{
    background: pink;
  }
}
/* == [END] bg == */
```

请注意我们如何使用`sec_to_per`函数以便使用秒而不是百分比；接下来，我们只需要使用`animation`属性将`bg`添加到`#viewport`：

```css
#viewport{
  @include animation(bg #{0s + $total_animation_duration} steps(1,start));
  @include animation-fill-mode(forwards);
}
```

这就是结果：

![步骤动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_10.jpg)

# 最后的修饰

现在我们已经定义了一个基本结构，并学会了如何创建一个在 3D 场景中移动的流畅动画，显然，下一步是丰富每个幻灯片，包括图片、视频、图表，以及我们可能需要实现我们目的的一切。

为了做到这一点，我们可以利用本书前几章已经积累的知识；例如，我们可以很容易地为第一张幻灯片定义一个淡入动画，如下所示：

```css
div[data-sequence="1"]{
  @include animation(sequence_1 2s linear);
  @include animation-fill-mode(forwards);
}

/* == [BEGIN] sequence_1 == */
@include ext_keyframes(sequence_1){
  0%{
    color: rgba(0,0,0,0);
  }
}
/* == [END] sequence_1 == */
```

我们还可以向幻灯片添加自定义字体：

```css
div[data-sequence="2"]{
  font-family: 'Meie Script', cursive;
}
```

这是结果：

![最后的修饰](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_09_11.jpg)

# 总结

CSS 动画和 3D 变换可以结合起来创建有趣的效果；当然，当我们转向这些类型的功能时，我们必须接受一些浏览器可能无法支持项目的事实。然而，我们总是可以使用一些特性检测库，比如 Modernizr，来解决这个问题，当这些功能不受支持时提供一些替代的可视化。

在下一章中，我们将完全使用 CSS3 创建一个漂亮的图表库！
