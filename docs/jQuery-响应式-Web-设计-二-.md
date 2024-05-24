# jQuery 响应式 Web 设计（二）

> 原文：[`zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43`](https://zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：准备图片和视频

最近，用于响应式站点的图像准备一直是最受讨论的问题之一，因为 W3C 尚未批准任何技术。与此同时，社区已经创造了一些各具优势的技术，试图解决这个问题。

我们将从基本图像调整开始本章。这个技术可以轻松地被集成到代码中，但移动用户正在等待更好的体验。

但是，在小型设备（如智能手机和平板电脑）上仅仅调整图像大小并不够有效，因为在这些设备上加载高质量的图像可能需要很长时间。稍后，我们将看到图像断点的重要性及其好处。

此外，我们将关注视频，因为它们在 HTML5 之前已经插入到我们的代码中，避免了从固定到响应式的站点转换上出现的问题。

此外，我们将讨论一些可用的 jQuery 插件以及如何使用它们，通过节省开发时间并改善界面。

在本章中，我们将学到：

+   只使用 CSS 的基本图像调整

+   为什么使用图像断点

+   图像标签的工作原理

+   控制图像艺术方向

+   使用 jQuery 插件和图像断点

+   使用 jQuery 插件创建响应式背景

+   处理高密度显示屏

+   使视频元素具有响应性

# 只使用 CSS 进行基本图像调整

以下代码可用于使图像在其父容器调整大小时具有缩放自由度。最大宽度设置为原始尺寸的 100%，其高度可以自动按照相同的图像比例进行调整：

```js
img {
  max-width: 100%;
  height: auto;
}
```

然而，要有效使用这一点，图像必须足够大，以便可以在最大可能的显示器上按比例缩放。然而，为桌面站点优化的图像对于移动互联网速度来说仍然相当沉重。

### 提示

如果你在 DOM 中使用`max-width`或`height`标记来调整 JPG 图像，那么你可能只会在 IE7 或更旧版本的浏览器上看到像素化的图像。然而，有一个简单的代码可以解决这个问题：

```js
img {
  -ms-interpolation-mode: bicubic;
}
```

这个特定的问题在 IE8 中被解决，在 IE9 中变得过时。

# 使用图像断点

适应性图片不仅仅是关于缩放图片的问题。它涉及到其他问题，以及在提供最佳用户体验时需要牢记的变量。诸如以下：

+   屏幕分辨率

+   带宽

+   浏览器窗口宽度

尝试确定发送到浏览器的最佳图像可能与每个变量都独立无关。这就是问题所在。例如，仅仅知道屏幕分辨率的值并不意味着用户有足够的带宽接收高清晰度图片。

因此，基于这些事实，我们将如何在我们的 Web 应用程序中制作一张图片，它需要在许多设备上显示良好的质量，而不会造成巨大的带宽浪费？

![使用图片断点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_02.jpg)

当我们处理位图图像（非矢量化图像，如 SVG）时，理想的解决方案似乎很简单：为每组分辨率提供不同大小的图片，其中每个图片都适用于某些类型的设备。

通常，我们考虑三种不同的屏幕尺寸来覆盖设备的多样性：

+   **480 px**：分辨率标准的智能手机（以移动为先）

+   **1024 px**：iPhone Retina（高像素密度智能手机），平板电脑和分辨率普通的桌面电脑

+   **1600 px**：iPad Retina（高像素密度平板电脑）和分辨率高的桌面电脑

已经有许多技术试图解决这个问题，并提供解决方案来帮助我们为每个场合提供正确的图片。它们都以略有不同的方式工作，根据您的需求，您将选择最符合您项目需求的选择。我们很快就会看到其中一些。

# 图片标签的工作原理

面对为用户提供正确图片的需求，W3C 正在努力研究它们。有一个此项倡议的非官方草案，其中包括了 `<picture>` 标签和不同的来源，以及它在其标准中，以便更容易地对图片进行适应。

### 注意

没有这个标准，浏览器开发人员无法准备好他们的浏览器以良好地渲染它。今天，前端社区正在尝试使用 CSS 和 JavaScript 来完成相同的任务。

这是 W3C 对 `<picture>` 标签的定义：

> "此规范为开发人员提供了声明图像的多个来源的方法，并且通过 CSS 媒体查询，它使开发人员能够控制何时向用户呈现这些图像。"

他们也考虑到了旧版浏览器，这些浏览器将显示一个简单的图片作为备用内容。以下是标签将被使用的示例：

```js
<picture width="500" height="500">
  <source media="(min-width:45em)" srcset="large1.jpg 1x, large2.jpg 2x">
  <source media="(min-width:18em)" srcset="medium1.jpg 1x, medium2.jpg 2x">
  <source srcset="small1.jpg 1x, small2.jpg 2x">
  <img src="img/small1.jpg" alt="">
  <p>Accessible text for all image versions</p>
</picture>
```

我建议查看有关此规范的更新信息，请访问[`picture.responsiveimages.org/`](http://picture.responsiveimages.org/)。

# 对响应式图片的艺术指导的控制

这个话题最近已经讨论了很多。作者应该为不同尺寸的图片提供不同的来源，并根据他们的视觉判断，将主要元素聚焦在该特定断点的图片上。这就是艺术指导。

让我通过这个案例来澄清一下。当图片以较大的尺寸显示时，图片中显示的是船上的夫妇和背景中的河流是有意义的。背景有助于解释他们的位置，但总的来说，它没有提供任何相关信息。现在，看看当我们将图片缩小以适应较小的屏幕时会发生什么。这不是艺术指导。

![响应式图片的艺术方向控制](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_03.jpg)

将其缩小到那个尺寸，你几乎认不出这对夫妇。与其简单地调整图片大小，不如裁剪它以摆脱一些背景并集中在它上面更有意义。最终结果是一张在较小尺寸下效果更好的图片。让我们比较左边的图片（艺术方向）和右边的图片如下：

![响应式图片的艺术方向控制](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_04.jpg)

## 焦点 CSS 框架

焦点点改善了在缩小图像之前对图像最重要部分的聚焦。这样，它允许用户在智能手机上以较大尺寸看到图像的主要部分。所有这些都不需要使用 JavaScript 或 jQuery。

使用焦点，您可以定义一个代表您不想因较小分辨率而错过的部分的区域。被焦点覆盖的部分在缩放时保持可见，无论你将它们缩放到多远。

以下类名允许您裁剪和调整到图像的一个大致区域。请注意，类名中的 X 表示介于一和六之间的数字：

+   **左-X**/**右-X**：这些定义图像在水平方向上将关注多少个单位

+   **上-X**/**下-X**：这些定义图像在垂直方向上将关注多少个单位

+   **纵向**：默认情况下，该值设置为横向。但是如果一个图像的高度大于其宽度，则也添加 `portrait` 类

### 如何做

从[`github.com/adamdbradley/focal-point`](https://github.com/adamdbradley/focal-point)下载 CSS 文件后，让我们将此代码插入到我们 DOM 的 `<head>` 标签中：

```js
<link rel="stylesheet" href="/css/focal-point.min.css">
```

后来，我们可能会看到以下演示中的操作：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_05.jpg)

焦点的原则很简单：想象一个 12 x 12 单位的网格放在图片上：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_06.jpg)

现在，我们假设这个人的头是图片中最重要的部分，并且我们需要将其定义为焦点。即使这个人的脸在图片的右边，当缩小到较小分辨率时，它仍然会保持焦点。

要在技术上定义焦点，我们只需设置图像的两个类。这些类可以水平和垂直地定位焦点。它将从网格的中心开始，如下图所示：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_07.jpg)

以下是专注于人脸的代码：

```js
<div class="focal-point right-3 up-3">
  <div><img src="img/guy.jpg" alt=""></div>
</div>
```

在这个例子中，焦点被定义为从中心向左三个网格单位，然后向上两个单位。`focal-point` 类与图像周围的 div 一样必不可少。

# <picture> 标签的替代解决方案

我们刚刚看到，W3C 正在努力制定标准，尽快标记图片，这将使您能够为您用于查看我们网站的设备提供更合适的视觉内容。

由于这种功能的迫切需要，社区创建了两个 JavaScript 插件，以实现大多数常用浏览器接受的预期结果。它们是 Foresight 和 Picturefill。

## Foresight - 根据屏幕大小选择正确的图像进行显示

Foresight 为网页提供了在请求从服务器请求图像之前，通知用户设备是否能够查看高分辨率图像（例如视网膜显示设备）的功能。

此外，Foresight 会判断用户设备当前的网络连接速度是否足够快，以处理高分辨率图像。根据设备显示和网络连接性，foresight.js 将为网页请求适当的图像。

通过自定义`img source`属性，使用诸如 URI 模板之类的方法，或者在 URI 中查找和替换值，可以形成为您图像的分辨率变体构建的请求，并具体使用新的 CSS `image-set()` 函数的混合实现。

基本格式是`image-set()`函数可能有一个或多个 image-set 变体，每个变体由逗号分隔。每个图像集变体最多可以有三个参数：

+   **URL**：这类似于`background-image:url()`。

+   **比例因子**：比例因子参数用作应用于识别图像密度的图像尺寸的乘法器。一些移动设备的像素比是 1.5 或 2。

+   **带宽**：这可以定义为低带宽或高带宽。

Foresight 还执行快速网络速度测试，以确保用户设备能够处理高分辨率图像，而不会让连接速度慢的用户等待很长时间下载图像。

### 如何做到

让我们访问网站[`github.com/adamdbradley/foresight.js`](https://github.com/adamdbradley/foresight.js)并下载文件。然后，我们将在 DOM 的`<head>`标签中插入以下代码：

```js
<script src="img/foresight.js "></script>
```

让我们看一个真实的例子，下面的代码中我们正在使用移动优先的概念：

```js
.fs-img {
  width:100%;
  font-family: 'image-set( url(-small|-small-2x) 2x high-bandwidth )';
  display:none;
}
```

然后，对于窗口，宽度至少为 600 px 和 800 px：

```js
@media (min-width:600px) {
  .fs-img {
    font-family: 'image-set( url(-small|-medium), url(-small|-medium-2x) 2x high-bandwidth )';
  }
}
@media (min-width:800px) {
  .fs-img {
    font-family: 'image-set( url(-small|-large), url(-small|-large-2x) 2x high-bandwidth )';
    max-width:100%;
  }
}
```

所以，我们用一些词来更好地解释它的工作原理。该代码将查找`<img>`标签的源代码中名称的片段，并将其替换为另一个名称。之后，站点将在其文件中搜索更改后的名称，验证所需的代码是否存在：

```js
<img data-src="img/castle-small.jpg" data-width="240" data-height="157" class="fs-img" src="img/strong>.jpg">
```

### 提示

该引擎用于更改文件名的后缀，使其具有良好的可扩展性，这非常好，因为在创建新的响应式图像时可以避免对代码的大量干预。

如果我们比较这个例子中的图像，查看 KB 的差异，我们将得到 44 KB 的大图像，20 KB 的中图像和 12 KB 的小图像。对于单个图像来说，这不是一个巨大的差异。然而，将其应用到整个站点，可能会大大减少不必要图像的加载。

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_08.jpg)

## Picturefill – 最接近 picture 标签的解决方案

Picturefill 是用于响应式图片的 JavaScript 插件，类似于未来的 `picture` 元素，但现在就可以使用。这个非常轻量级的解决方案使用 `span` 标签而不是 `picture` 或 `image`，以确保其自身的安全性。

Picturefill 本身支持 HD（Retina）图像替换。 Picturefill 还具有良好的性能优势，根据屏幕大小选择正确的图像，而无需下载其他图像。

要获取有关此插件的更多信息，请访问 [`github.com/scottjehl/picturefill`](https://github.com/scottjehl/picturefill)。

### 如何做

下载此解决方案的文件后，让我们将此代码插入到您 DOM 的 `<head>` 标签中：

```js
<script src="img/matchmedia.js"></script>
<script src="img/picturefill.js"></script>
```

这是在 HTML 中要使用的代码。请注意，它要求您指定每个图像及其变体的来源。请参阅以下示例：

```js
<span data-picture="" data-alt="Picture alternative text">
  <span data-src="img/small.jpg"></span>
  <span data-src="img/medium.jpg" data-media="(min-width: 400px)"></span>
  <span data-src="img/large.jpg" data-media="(min-width: 800px)"></span>
  <span data-src="img/extralarge.jpg" data-media="(min-width: 1000px)"></span>
  <!-- Fallback content for non-JS browsers -->
  <noscript>&lt;img src="img/small.jpg" alt="Picture alternative text"&gt;</noscript>
  <img alt="Picture alternative text" src="img/extralarge.jpg">
</span>
```

或许有些项目需要将其作为解决方案（在 HTML 代码中放置整个规范及其图像变体），但如果网站上有很多图像，可能会带来可扩展性问题和网站维护问题。

# 使用 jQuery 插件实现响应式背景图片

对于响应式站点来说，定位背景图并不总是一件容易的事情，因为其正确的显示取决于其内容的行为。

为了澄清，让我展示这个问题的一个示例：

![使用 jQuery 插件实现响应式背景图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_09b.jpg)

问题在于，有时我们会固定内容以保持背景正确，但需要更改。有两个插件对定位此背景非常有帮助：Anystretch 和 Backstretch。

## Anystretch – 轻松拉伸背景

Anystretch 是一个 jQuery 插件，允许您向任何页面或块级元素添加动态调整大小的背景图像。最初，Anystretch 是从 Backstretch 派生出来的。

图像将拉伸以适应页面/元素，并随着窗口大小的更改而自动调整大小。有一些选项可以配置它，例如水平定位、垂直定位、速度、元素定位和数据名称。

此插件的另一个优点是，如果我们在加载 Anystretch 后要更改图像，我们只需要再次进行处理，提供新路径即可。

### 提示

是的，我们可以与 Breakpoints.js 插件一起使用，就像我们在第二章中所看到的*设计响应式布局/网格*，这样就可以更改图像路径并再次使用 Anystretch，如果需要的话。

### 如何做

从 [`github.com/danmillar/jquery-anystretch`](https://github.com/danmillar/jquery-anystretch) 下载文件后，让我们使用以下 HTML 代码来澄清其工作原理：

```js
<div class="div-home stretchMe" data-stretch="img/bg-home.jpg">
  <p>main content</p>
</div>
<div class="div-footer stretchMe" data-stretch="img/bg-footer.jpg">
  <p>footer content</p>
</div>
```

对于这个结构，有两个突出的词语：

+   `stretchMe`：这用于标识那些将由插件处理的元素

+   `data-stretch`：这将通知插件哪个图像可能成为背景

在 DOM 的底部（在 `</body>` 结束标记之前），我们需要包含 jQuery 代码和 Anystretch 脚本。然后，我们将对所有按照 `stretchMe` 类名设置的元素执行插件（只是一个建议的名称）。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.anystretch.min.js"></script>
<script>
$(".stretchMe").anystretch();
</script>
```

这是将插件应用于 div 元素的视觉结果：

![如何操作](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_10b.jpg)

到目前为止，这种方法不错，但是如果使用，将对所有响应式背景应用相同的行为。换句话说，如果我们想要更改特性，我们需要单独调用该函数。

### 提示

如果我们对同一个元素两次调用 `anystretch` 方法，它将替换现有图像并停止先前的处理。

如果我们查看上一个 HTML 代码，会发现一个名为 `div-home` 的类，它可以使用不同的选项执行，例如：

```js
<script>
$(".div-home").anystretch('',{speed:300, positionX:'right', positionY:'bottom'});
</script>
```

### 注意

`speed` 参数将配置在下载图像后淡入图像的时间。默认情况下，`positionX` 和 `positionY` 对齐在中心，但是插件允许我们更改它。

## Backstretch – 创建响应式背景幻灯片

Backstretch 是一个 jQuery 插件，允许用户向任何页面或元素添加动态调整大小的背景图像，它是 Anystretch 插件的基础。

但是，Backstretch 发展了，现在还提供动态调整幻灯片元素的背景图像大小。所有这些背景图像将拉伸以适应页面/元素，并且将随着窗口/元素大小的更改而自动调整大小。

另一个很好的改进是在页面加载后获取将要使用的图像，这样用户就不必等待太长时间才能完成图像的下载。

您可以在 [`github.com/srobbin/jquery-backstretch`](https://github.com/srobbin/jquery-backstretch) 找到要下载的文件。

### 如何操作

在 DOM 底部（在 `</body>` 结束标记之前），我们将包括 jQuery 和 Backstretch 库。然后，我们将执行插件，将 Backstrech 附加到元素的背景上：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.backstretch.min.js"></script>
<script>
$.backstretch("path/bgimage.jpg");
</script>
```

下面是视觉结果：

![如何操作](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_11.jpg)

默认情况下，图像的对齐（垂直和水平）设置为中心，因为对于使用此解决方案的人来说更常见，但是如果需要，我们可以关闭它。另一个包括的选项是 `fade` 参数，用于配置图像淡入的时间。`parameter` 持续时间用于幻灯片，它与每个幻灯片显示之前的时间（以毫秒为单位）有关。

我们还可以将 Backstretch 附加到任何块级元素上。默认情况下，`<body>` 标记将接收此响应式背景。要做到这一点，更好的方法是通过使用以下代码定义一个类来接收此操作，而不是使用上一个代码：

```js
<script>
$(".div-home").backstretch("path/bgimage.jpg");
</script>
```

或者，要启动幻灯片放映，只需提供一个图像数组和幻灯片之间的时间量：

```js
<script>
  $(".div-home").backstretch([
    "path/bgimage1.jpg",
    "path/bgimage2.jpg",
    "path/bgimage3.jpg"    
  ], {duration: 5000});
</script>
```

此插件有很好的文档，并提供了用于更好处理的幻灯片 API。可以在 [`github.com/srobbin/jquery-backstretch#slideshow-api`](https://github.com/srobbin/jquery-backstretch#slideshow-api) 找到它。

# 处理高密度显示屏

屏幕密度指的是物理表面上的设备像素数量。通常以**每英寸像素** (**PPI**) 进行测量。苹果为其双倍密度显示器创造了市场术语**视网膜**。根据苹果官方网站的说法：

> “视网膜显示屏的像素密度非常高，以至于您的眼睛无法区分单个像素。”

换句话说，视网膜显示器的像素密度足够高，以至于人眼无法注意到像素化。但是，由于这些显示器正在广泛实施和使用，因此更加重要的是创建支持这些显示器的网站和应用程序。

在下图中，我们比较了视网膜和标准定义显示器之间的像素。在视网膜显示器中，与传统显示器相比，相同空间内的像素是双倍的：

![处理高密度显示屏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_12.jpg)

### 注意

单词“double”并非所有支持高密度图像的设备所使用的确切值。目前，市场上还有其他屏幕密度，其密度值为 1.5 和 2.25。

## 如何做到

视网膜图像的通常值是普通图像值的两倍。因此，通过使用媒体查询，我们可以测试浏览器是否支持高密度图像。让我们在下面的示例中检查一下：

```js
/* normal sprite image has dimension of 100x100 pixels */
span.bigicon-success {
  background: url(sprite.png) no-repeat -50px 0;
}
@media only screen and (-webkit-min-device-pixel-ratio: 2), only screen and (min-device-pixel-ratio: 2) {
  span.bigicon-success {
    background-image: url(sprite@2x.png);
    /* retina sprite image has dimension of 200x200 pixels */
    background-size: 200px 200px;
  }
}
```

如果浏览器接受，我们会请求另一张图像来显示。然而，这种用法会产生两次图像请求：一次在检查之前，另一次在媒体查询内部。

现在，让我们看看如何使用 Foresight 只发出一次请求。

## 如何使用 Foresight 完成

该插件具有在向用户显示任何图像之前检测设备显示的屏幕密度的能力。

让我们在下面的示例中看看：

```js
.fs-img {
  font-family: 'image-set(url(-small | -small-2x) 2x high-bandwidth)';
}
```

在此示例中，浏览器会检查哪个图像元素具有类`fs-img`，并在显示任何图像之前（Foresight 的默认行为）检查它是否支持视网膜图像；此外，它还可以检查用户是否处于高带宽状态。

请注意，在请求`castle-small.jpg`文件之前，例如，它会查找后缀`-small`并将其替换为`-small-2x`，然后请求文件`castle-small-2x.jpg`。

有一个在线工具可以帮助计算图像在视网膜上查看时应该具有的大小。可在 [`teehanlax.com.s3.amazonaws.com/files/teehanlax_density_converter.html`](http://teehanlax.com.s3.amazonaws.com/files/teehanlax_density_converter.html) 获取。 

# 制作响应式视频元素

在我们的网站开发中使用 HTML5 之前，视频的使用受限于设备对 Adobe Flash Player 的接受。然而，由于 HTML5 中 `<video>` 的大力发展，以及苹果公司在其设备上拒绝 Adobe Flash Player 的立场，这种义务不再存在。

目前，这个元素 `<video>` 在现有设备和现代浏览器（IE9 及以上版本）中得到了很好的接受，使得其在响应式网站上的处理尤其是灵活性更加容易。仅为澄清，以下是 `video` 标签在 DOM 中通常的样子：

```js
<video id="highlight-video" poster="snapshot.jpg" controls>
  <source src="img/video.m4v" type="video/mp4" /> <!-- for Safari -->
  <source src="img/video.ogg" type="video/ogg" /> <!-- for Firefox -->
</video>
```

使视频流畅的 CSS 代码非常简单：

```js
video, iframe {
   max-width: 100%;
   height: auto;
}
```

然而，老旧浏览器和新浏览器之间存在操作差异，并且为了增加内容的可访问性。通常更倾向于使用更安全的方法。这条路就是继续使用嵌入式视频或 `<iframe>` 标签。我们很快就会看到如何使这些视频更具响应性和灵活性。

现在，让我们专注于当前的技术。好消息是，视频提供商如 YouTube 或 Vimeo 已经支持 `<video>` 标签，但这仍然不是默认行为。这个在不同设备上使用的代码可能会成为一个问题，因为我们需要根据每种情况来适应代码。

解决适应性问题的方法是他们创建了 FitVids 插件。

## FitVids – 响应式视频的快速解决方案

FitVids 是一个轻量级的 jQuery 插件，通过创建一个包装器来自动调整我们响应式网页设计中视频宽度的工作，以保持其比例，否则被嵌入的视频的比例将会是这样：

![FitVids – 响应式视频的快速解决方案](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_15.jpg)

目前支持的播放器有 YouTube、Vimeo、Blip.tv、Viddler 和 Kickstarter。但如果需要使用我们自己的播放器，有一个选项可以指定自定义播放器。

### 如何做

在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 jQuery 代码和 FitVids 脚本。然后，我们只需要将其执行附加到元素的类或 ID 上，如下所示：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.fitvids.js"></script>
<script>
$(function () {
  $(".video-wrapper").fitVids();
});
</script>
```

之后，让我们使用这段 HTML 代码只是作为示例来看看它是如何工作的：

```js
<div class="video-wrapper ">
  <iframe width="560" height="315" frameborder="0" allowfullscreen src="img/UM0Cl3wWys0"></iframe>
</div>
```

以下截图显示了使用 FitVids 的 YouTube、Vimeo 和 Viddler 视频的示例：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_13.jpg)

# 练习 – 为特色主页图片创建不同的图像版本

正如我们刚刚看到的，为每个设备加载正确的图像对于我们的响应式网站非常重要。因此，让我们在以下断点中的设计中实践这项技术，展示不同的图像：

+   最大宽度 = 480

+   最大宽度 = 1024

+   最小宽度 = 1025

以下屏幕截图显示了网站以及我正在引用的照片，就像我们在第二章中看到的那样，*设计响应式布局/网格*。对于这个练习，我指的是盒子内突出显示的图像：

![创建首页特色图像的不同版本的练习](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_05_14.jpg)

对于这项活动，我建议使用 Foresight 插件，因为它可以更好地可视化图像源和断点。

### 提示

不要忘记检查您正在使用的特定设备是否支持显示高密度图像。

# 总结

在本章中，我们学习了将固定图像转换为灵活图像的简单方法，但仅仅理解这一点并不足以使它们适应不同的设备。此外，我们还学习了通过使用 Foresight 和 Picturefill 插件向用户提供正确图像的其他方法。当使用 FocalPoint 框架调整图像大小时，我们还控制了艺术方向，将焦点放在图片中的主要元素上。此外，我们还学会了使用 FitVids 插件使视频尺寸变得流动起来而不感到紧张。

在下一章中，我们将了解哪些幻灯片插件适用于响应式网站，学习如何构建它们，更改一些选项和效果，并给用户留下良好的印象。此外，我们还将了解在移动网站上通常使用和实现的手势。


# 第六章：构建响应式图片轮播器

图片轮播器被广泛使用，已经成为非常受欢迎的网络元素。在网站上，通过美丽的过渡和动画、标题和描述以及使用自定义时间，可以在线呈现出一个吸引人的业务展示。此外，一个好的图片轮播器可以展示产品橱窗，吸引用户的注意力，并提高其销售额。

在这一章中我们将学习以下内容：

+   不同类型的响应式图片轮播器

+   引入触摸手势在用户体验中

+   使用 JavaScript 插件实现触摸事件

# 响应式图片轮播器

打开一个网站并在头部区域看到一个图片轮播器是很常见的现象。图片轮播器显示突出内容，在有限的空间内确实非常有用。虽然当通过移动设备查看网站时可用空间更加有限，但轮播器元素仍然能够吸引客户的注意力。

如果与桌面相比，可以用于显示突出内容的区域和用于呈现它的资源的差异真的很大，通常情况下我们不会遇到脚本性能问题，并且每个转换的交互是通过使用箭头标志来切换图片。

当响应式时代开始时，观察了人们通常与图片轮播器互动的方式，并根据渐进增强的概念确定了变化，例如改变每个幻灯片的方式。解决方案是为移动设备的用户提供类似的体验：在支持的设备上对图片轮播器元素进行手势和触摸操作，而不是显示回退。

随着浏览器和技术的不断发展，有许多具有响应特性的图片轮播器插件。我个人最喜欢的插件是 Elastislide、FlexSlider2、ResponsiveSlides、Slicebox 和 Swiper。有很多可用的，找到真正喜欢的一个的唯一方法是尝试它们！

让我们详细了解它们的工作原理。

## Elastislide 插件

Elastislide 是一个响应式图片轮播器，它会根据 jQuery 在任何屏幕尺寸上工作的大小和行为进行调整。这个 jQuery 插件处理了轮播器的结构，包括内部百分比宽度的图片，水平或垂直显示它，以及预定义的最小显示图片数量。

Elastislide 使用 MIT 许可证，可以从 [`github.com/codrops/Elastislide`](https://github.com/codrops/Elastislide) 下载。

当我们实现一个图片轮播器时，仅仅减小容器的尺寸并显示一个水平滚动条并不能优雅地解决小设备的问题。建议是也要调整内部项目的大小。Elastislide 很好地解决了这个调整大小的问题，并定义了我们想要显示的最小元素，而不是仅仅使用 CSS 隐藏它们。

此外，Elastislide 使用了一种名为 jQuery++ 的补充和定制版本的 jQuery 库。jQuery++ 是另一个处理 DOM 和特殊事件非常有用的 JavaScript 库。在这种情况下，Elastislide 使用了一个定制版本的 jQuery++，这使得插件能够在触摸设备上处理**滑动事件**。

### 如何操作

由于我们将在同一个轮播图中看到此插件的四个不同应用，我们将使用相同的 HTML 轮播图结构，只需在执行插件之前修改 JavaScript，指定参数即可：

```js
<ul id="carousel" class="elastislide-list">
  <li><a href="#"><img src="img/image-photo.jpg" /></a></li>
  <li><a href="#"><img src="img/image-sky.jpg" /></a></li>
  <li><a href="#"><img src="img/image-gardem.jpg" /></a></li>
  <li><a href="#"><img src="img/image-flower.jpg" /></a></li>
  <li><a href="#"><img src="img/image-belt.jpg" /></a></li>
  <li><a href="#"><img src="img/image-wall.jpg" /></a></li>
  <li><a href="#"><img src="img/image-street.jpg" /></a></li>
</ul>
```

在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 jQuery 和 jQuery++ 库（此解决方案所需），然后再包含 ElastiSlide 脚本：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquerypp.custom.js"></script>
<script src="img/modernizr.custom.17475.js"></script>
<script src="img/jquery.elastislide.js"></script>
```

然后，在 `<head>` 标签内包含 CSS 样式表：

```js
<link rel="stylesheet" type="text/css" href="css/elastislide.css" />
```

好了，现在我们已经有了展示四个不同示例的基础。对于每个示例，当执行插件脚本时，必须添加不同的参数，以便根据项目需求获得不同的渲染效果。

#### 示例 1 – 至少显示三张图片（默认）

在第一个示例中，我们将看到默认的视觉效果和行为，以及是否在其后放置以下代码，包括 ElastiSlide 插件：

```js
<script type="text/javascript">
$('#carousel').elastislide();
</script>
```

此解决方案提供的默认选项包括：

+   至少显示三个项目

+   滚动效果的速度为 0.5 秒

+   水平方向

+   缓动效果定义为 ease-in-out

+   轮播图将开始显示列表中的第一张图片

下面的截图显示了此代码的实现效果。注意在平板电脑和智能手机上显示的版本之间的差异：

![示例 1 – 至少显示三张图片（默认）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_01.jpg)

#### 示例 2 – 垂直方向，至少显示三张图片

有一个选项可以使轮播图以垂直方向呈现，只需更改一个参数。此外，我们可以加快滚动效果。请记得包含与示例 1 中使用的相同文件，并在 DOM 中插入以下代码：

```js
<script type="text/javascript">
$('#carousel').elastislide({
  orientation: 'vertical',
  speed: 250
});
</script>
```

默认情况下，至少显示三张图片。但是，这个最小值可以根据我们将在下一个示例中看到的情况进行修改：

![示例 2 – 垂直方向，至少显示三张图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_02.jpg)

#### 示例 3 – 固定包装器，至少显示两张图片

在此示例中，我们将定义轮播图中可见项目的最小值，当在小屏幕上查看轮播图时，可以注意到差异，并且图片不会缩小太多。此外，我们还可以定义从第三张图片开始显示的图片。

请记得包含与示例 1 中使用的相同文件，并在包含 ElastiSlide 插件之后执行脚本，提供以下参数并将其定位：

```js
<script>
$('#carousel').elastislide({
  minItems: 2,
  start: 2
});
</script>
```

![示例 3 – 固定包装器，至少显示两张图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_03.jpg)

#### 示例 4 – 图片库中至少显示四张图片

在第四个示例中，我们可以看到许多 JavaScript 实现。然而，此示例的主要目标是展示此插件为我们提供的可能性。通过使用插件回调函数和私有函数，我们可以跟踪点击和当前图像，然后通过创建图像画廊按需处理此图像更改：

```js
<script>
var current = 0;
var $preview = $('#preview');
var $carouselEl = $('#carousel');
var $carouselItems = $carouselEl.children();
var carousel = $carouselEl.elastislide({
  current: current,
  minItems: 4,
  onClick: function(el, pos, evt){
    changeImage(el, pos);
    evt.preventDefault();
  },
  onReady: function(){
    changeImage($carouselItems.eq(current), current);
  }
});
function changeImage(el, pos) {
  $preview.attr('src', el.data('preview'));
  $carouselItems.removeClass('current-img');
  el.addClass('current-img');
  carousel.setCurrent(pos);
}
</script>
```

![示例 4 – 图像画廊中可见的最少四幅图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_04.jpg)

为此，与其他插件相比，ElastiSlide 可能没有太大优势，因为它依赖于我们的额外开发来完成这个画廊。因此，让我们看看下一个插件提供了什么来解决这个问题。

## FlexSlider2 – 完全响应式滑块

FlexSlider2 是一个轻量级的 jQuery 图像滑块插件，包括淡入淡出和滑动动画、移动设备的触摸手势以及一堆可定制的选项。

自从 2011 年发布以来，FlexSlider2 在开发者社区中一直展示着持续的信心，并且一些已知的**CMS**（**内容管理系统**），如 Drupal 和 WordPress，已经导入了此插件以在其系统中使用。

稳定的版本 2.0 也支持使用旧浏览器的用户，自 Safari 4、Chrome 4、Firefox 3.6、Opera 10 和 IE7 开始。同时也支持 Android 和 iOS 设备。

### 如何做

为了查看此插件提供的各种选项，我们将看到以下三个应用示例中最常用的插件选项。我们将从显示滑块的默认布局开始。然后，我们将看到一个使用导航来支持显示大量图像的情况的滑块，最后一个示例中我们将看到另一种配置 FlexSlider2 提供的图像轮播的方式。

您可以在 [`github.com/woothemes/FlexSlider`](https://github.com/woothemes/FlexSlider) 找到可下载的文件；对于附加的插件选项，我们建议您阅读插件官方网站上的完善文档 [`www.woothemes.com/flexslider/`](http://www.woothemes.com/flexslider/) 。

#### 示例 1 – 基本滑块（默认）

让我们从在`<head>`标签内包含 CSS 样式表开始：

```js
<link rel="stylesheet" href="css/flexslider.css" type="text/css">
```

在 DOM 底部（在`</body>`结束标记之前），我们需要包含两个文件：jQuery 库和 FlexSlider2 脚本。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.flexslider.js"></script>
```

到目前为止，第一个示例从这里开始，我们正在定义一个简单的无序列表来定义轮播结构。对此只有两个要求，即将`flexslider`类定义为包装 `<div>` 和将`slides`类定义为`<ul>`。

```js
<div class="flexslider">
  <ul class="slides">
    <li><img src="img/slide-img1.jpg" /></li>
    <li><img src="img/slide-img2.jpg" /></li>
    <li><img src="img/slide-img3.jpg" /></li>
    <li><img src="img/slide-img4.jpg" /></li>
  </ul>
</div>
```

在包含 FlexSlider2 库后，让我们添加以下代码来执行脚本。我们将只显示轮播中普通图像元素的默认外观和行为：

```js
$(document).ready(function() {
  $('.flexslider').flexslider({
    animation: "slide"
  });
});
```

此插件附带的样式在智能手机和桌面版本上看起来很漂亮：

![示例 1 – 基本滑块（默认）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_05.jpg)

#### 示例 2 – 使用轮播滑块作为导航控制器

初始 HTML 结构几乎相同，但现在我们必须为轮播复制幻灯片结构。通过执行 JavaScript 函数，识别这两个元素之间的关系，并连接到期望的行为。

记得包含示例 1 中使用的相同文件，然后将以下代码插入 HTML 代码中。

```js
<div id="slider" class="flexslider">
  <ul class="slides">
    <li><img src="img/slide-img1.jpg" /></li>
    <li><img src="img/slide-img2.jpg" /></li>
    <li><img src="img/slide-img3.jpg" /></li>
    <li><img src="img/slide-img4.jpg" /></li>
  </ul>
</div>
<div id="carousel" class="flexslider">
  <ul class="slides">
    <li><img src="img/slide-img1.jpg" /></li>
    <li><img src="img/slide-img2.jpg" /></li>
    <li><img src="img/slide-img3.jpg" /></li>
    <li><img src="img/slide-img4.jpg" /></li>
  </ul>
</div>
```

要创建这个图片画廊，我们必须通过使用 ID 来识别插件将影响的元素，避免任何行为冲突。将此示例与示例 1 进行比较，在示例 1 中，FlexSlider2 只实例化了一次，我们对插件脚本进行了两次调用。

在以下代码的第一部分中，正在创建图片幻灯片，并补充一些插件提供的其他选项，比如`animation`、`itemWidth`、`itemMargin`和`asNavFor`。

在此代码的第二部分中，正在创建导航控制器：

```js
$(document).ready(function() {
  $('#carousel').flexslider({
    animation: 'slide',
    controlNav: false,
    animationLoop: false,
    slideshow: false,
    itemWidth: 210,
    itemMargin: 5,
    asNavFor: '#slider'
  });
  $('#slider').flexslider({
    animation: "slide",
    controlNav: false,
    animationLoop: false,
    slideshow: false,
    sync: "#carousel"
  });
});
```

### 提示

`asNavFor`选项将`#slider`转换为`#carousel`的缩略图导航。而`sync`选项则创建了一个镜像，将在`#slider`上执行的操作同步到`#carousel`上。例如，如果用户通过滑块导航，轮播项目将跟随操作，显示相同的活动滑块，反之亦然。

非常简单、专业、且实用！因此，让我们看看这个响应式滑块在小设备和桌面上的带导航控制的视觉效果：

![示例 2 – 使用轮播滑块作为导航控制器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_06.jpg)

#### 示例 3 – 轮播设置最小和最大范围

记得包含示例 1 中使用的相同文件，然后将以下代码插入 HTML 代码中。请注意，它使用与第一个示例相同的 HTML 结构：

```js
<div id="slider" class="flexslider">
  <ul class="slides">
    <li><img src="img/slide-img1.jpg" /></li>
    <li><img src="img/slide-img2.jpg" /></li>
    <li><img src="img/slide-img3.jpg" /></li>
    <li><img src="img/slide-img4.jpg" /></li>
  </ul>
</div>
```

然而，为了构建它，我们需要更改 JavaScript 代码，在那里我们会通知不同的参数，如`itemWidth`、`itemMargin`、`minItems`和`maxItems`，如我们将在以下代码中看到的那样：

```js
$(document).ready(function() {
  $('.flexslider').flexslider({
    animation: "slide",
    animationLoop: false,
    itemWidth: 210,
    itemMargin: 5,
    minItems: 2,
    maxItems: 4
  });
});
```

### 注意

`itemWidth`和`itemMargin`选项应该用像素进行度量和定义，但不用担心，插件会处理这个固定单位得很好。

此外，`minItems`和`maxItems`被用来定义根据设备宽度在屏幕上显示的最小/最大元素数量值。在下一个屏幕截图中，我们将看到前面的代码在移动设备和桌面两个版本中的实际应用：

![示例 3 – 设置轮播的最小和最大范围](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_07.jpg)

## ResponsiveSlides – 基本幻灯片中的最佳解决办法

ResponsiveSlides 是一个 jQuery 插件，是一个非常轻量级的解决方案，基本上处于两种不同的模式。它可以自动淡化图像，或者作为具有分页和/或导航以在幻灯片之间淡化的响应式图像容器。

ResponsiveSlides 可以在各种浏览器上执行，包括旧版 IE 和 Android 版本 2.3 及以上。它还为不本地支持的 IE6 和其他浏览器添加了 CSS `max-width`支持。这个属性有助于使其在小屏幕上响应。

这个插件有两个依赖项，分别是 jQuery 库和所有图片必须具有相同的尺寸。

您可以在[`github.com/viljamis/ResponsiveSlides.js`](https://github.com/viljamis/ResponsiveSlides.js)找到可下载的文件以及关于插件选项的更多详细信息。

### 如何做到这一点

在接下来的部分中，您将找到三个示例，其中我们可以看到这个插件提供的主要功能。在第一个示例中，我们将看到哪些文件是必要的，并且 ResponsiveSlides 的默认选项是什么。

在第二个示例中，我们将添加各种参数来检查这个插件如何可以定制化并满足我们项目的需求。

在第三个示例中，我们将通过图片实现额外的导航，方便用户访问并查看他们想要的特定幻灯片。

#### 示例 1

因此，我们将首先在`<head>`标签内包含 ResponsiveSlides 主题的 CSS 文件：

```js
<link rel="stylesheet" href="responsiveslides.css">
```

之后，插件支持使用简单的 HTML 无序列表来制作我们的幻灯片。但是，我们需要为这个`<ul>`定义一个类名，确保插件能够检测到哪个`<ul>`必须被转换：

```js
<ul class="rslides">
  <li><img src="img/slide-img1.jpg" /></li>
  <li><img src="img/slide-img2.jpg" /></li>
  <li><img src="img/slide-img3.jpg" /></li>
  <li><img src="img/slide-img4.jpg" /></li>
</ul>
```

然后，在 DOM 底部（在`</body>`结束标签之前），我们应该包含 jQuery 库和 ResponsiveSlides 脚本。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/responsiveslides.min.js"></script>
```

现在，我们只需在网站加载后为带有`rslides`类的`<ul>`执行 ResponsiveSlides 脚本。让我们在包含 ResponsiveSlides 的代码之后放置这段代码：

```js
<script>
$(function() {
  $(".rslides").responsiveSlides();
});
</script>
```

### 提示

在附带插件文件的`demo.css`文件中，有一堆 CSS 样式表，这些可能帮助我们自定义幻灯片。这个文件不是必需的，但对视觉有很大的区别，可能对进一步的参考有用。

这是插件的默认视觉效果：

![示例 1](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_08.jpg)

#### 示例 2

因此，我们将像之前的示例一样开始，先在`<head>`标签内包含 CSS 文件，然后在 DOM 代码底部（在`</body>`结束标签之前）包含 jQuery 库和 ResponsiveSlides 脚本。

对于这个示例，我们添加了一个包裹幻灯片`slider_container`的 div，帮助我们定位箭头和每个幻灯片的标题文本。如果某些项目需要这个标题文本来解释幻灯片，ResponsiveSlides 可以很好地处理这个特性。

所以，让我们在下一个幻灯片上测试一下：

```js
<div class="slider_container">
  <ul class="rslides" id="slider-example2">
    <li><img src="img/slide-img1.jpg" />
      <p class="caption">This is a caption</p>
    </li>
    <li><img src="img/slide-img2.jpg" />
      <p class="caption"><strong>Other</strong> caption here</p>
    </li>
    <li><img src="img/slide-img3.jpg" />
      <p class="caption">The <u>third</u> caption</p>
    </li>
    <li><img src="img/slide-img4.jpg" />
      <p class="caption">The fourth caption</p>
    </li>
  </ul>
</div>
```

然后，请记得在网站加载后为带有`slider-example2` ID 的`<div>`执行 ResponsiveSlides 脚本，将这段代码放在包含 ResponsiveSlides 的代码之后：

```js
<script>
  $(function() {
    $('#slider-example2').responsiveSlides({
        auto: false,
        pager: false,
        nav: true,
        maxwidth: 540,
        speed: 500,
        namespace: "callbacks",
        before: function () {
          /* before event fired */
        },
        after: function () {
          /* after event fired */
        }
    });
  });
</script>
```

### 提示

也可以通过将 `pager` 选项设置为 `false` 并将 `nav` 选项设置为 `true` 来通知插件仅呈现下一个/上一个箭头而无需分页导航。

在下面的屏幕截图中，我们将看到这个示例的标题和导航箭头样式，这些样式来自于与插件一起提供的 `demo.css`：

![示例 2](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_09.jpg)

#### 示例 3

此示例侧重于创建一个基于缩略图图像和我们之前创建的图像的自定义导航，为用户提供另一种显示幻灯片库的方式。为了构建它，我们将插入其他简单的无序列表，显示缩略图图像并设置一个 ID，以后向插件提供信息：

```js
<ul class="rslides" id="slider-example3">
  <li><img src="img/slide-img1.jpg" /></li>
  <li><img src="img/slide-img2.jpg" /></li>
  <li><img src="img/slide-img3.jpg" /></li>
  <li><img src="img/slide-img4.jpg" /></li>
</ul>
<ul id="pager-example3">
  <li><a href="#"><img src="img/thumb-img1.jpg" /></a></li>
  <li><a href="#"><img src="img/thumb-img2.jpg" /></a></li>
  <li><a href="#"><img src="img/thumb-img3.jpg" /></a></li>
  <li><a href="#"><img src="img/thumb-img4.jpg" /></a></li>
</ul>
```

同样，我们必须确保 CSS 文件将被包含在 `<head>` 标签内，然后在 HTML 代码底部包含 jQuery 库和 ResponsiveSlides 脚本。当我们对 `#slider-example3` 执行 ResponsiveSlides 时，我们将设置 `manualControls` 选项，并指定我们自定义的缩略图图像结构的分页导航 ID，如下所示：

```js
<script>
$("#slider-example3").responsiveSlides({
  manualControls: '#pager-example3'
});
</script>
```

以下截图描述了实现此导航功能的视觉效果：

![示例 3](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_10.jpg)

## Swiper – 高性能触摸图片滑块

Swiper 是一个轻量级的移动触摸滑块，具有硬件加速转换（在支持的情况下）和惊人的本机行为。它旨在用于移动网站，但在现代桌面浏览器上也非常出色。

这个插件成为我最喜欢的两个原因是：它的性能真的很好，特别是在智能手机上，而且它还可以让桌面用户几乎感受到在浏览器中导航时体验到的触摸手势。

您可以从 [`github.com/nolimits4web/Swiper/`](https://github.com/nolimits4web/Swiper/) 下载此解决方案。有关插件选项的更多信息，请访问 [`www.idangero.us/sliders/swiper/api.php`](http://www.idangero.us/sliders/swiper/api.php)。

### 如何实现

因此，我们将从在 `<head>` 标签中引入 JS 和 CSS 文件开始：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/idangerous.swiper-2.2.min.js"></script>
<link rel="stylesheet" href=" css/idangerous.swiper.css">
```

现在，我们将执行 Swiper 脚本，指定 `container` 和 `pagination` 类：

```js
<script>
$(function(){
  var mySwiper = $('.swiper-container').swiper({
    pagination: '.pager',
    paginationClickable: true
  });
});
</script>
```

注意，这个 CSS 文件只是定制了幻灯片动画。即便如此，我们需要添加以下代码来定制幻灯片结构，以满足我们的需求，补充来自 Swiper 的样式：

```js
<style>
.swiper-container {
  width: 70%;
  height: 300px;
}
.pager {
  position: absolute;
  z-index: 20;
  left: 10px;
  bottom: 10px;
}
.swiper-pagination-switch {
  display: inline-block;
  width: 1em;
  height: 1em;
  background: #222;
  margin-right: 5px;
}
</style>
```

然后，该插件支持使用简单的 HTML 无序列表来制作我们的幻灯片。此外，我们需要为该结构定义一些类名，以确保插件的正常运行：

```js
<div class="swiper-container">
  <div class="swiper-wrapper">
    <div class="swiper-slide slide-1">
      <p>Slide 1</p>
    </div>
    <div class="swiper-slide slide-2">
      <p>Slide 2</p>
    </div>
    <div class="swiper-slide slide-3">
      <img src="img/slide-img3.jpg" />
    </div>
    <div class="swiper-slide slide-4">
      <img src="img/slide-img3.jpg" />
    </div>
  </div>
  <div class="pager"></div>
</div>
```

所有滑块结构都由 `swiper-container` 和 `swiper-wrapper` 类包裹。此外，`swiper-slide` 类定义 div 作为幻灯片项，而 `pager` 类指定将显示幻灯片分页的 div。 

插件开发者提供的网站演示采用的视觉效果很漂亮；但是，这些样式不包括在`idangerous.swiper.css`中。它仍然依赖于我们对整个幻灯片的自定义，接下来我们将在以下截图中看到：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_11.jpg)

#### 特色选项

通过分析代码，该插件似乎非常聪明，并且可以快速地渲染到浏览器上。另一个重要的考虑是社区的不断更新，修复了主要和次要的错误。它与其他插件的当前差异是：

+   垂直/水平滑动

+   丰富的 API

+   灵活的配置

+   嵌套的 Swipers

+   3D 流

在插件版本 1.8.5 中，他们引入了 3D 流补充到 Swiper 中。它简单地提供了一个带动态阴影的惊人真实的 3D 画廊，相比其他幻灯片插件有很大的优势。让我们看看如何实现它。

### 在 Swiper 上使用 3D 流样式

由于它是 Swiper 的补充，我们需要包括与前面示例相同的文件，先从`<head>`中的 CSS 开始。然后，追加下面这些新的 JS 和 CSS 文件，用于引用 3D 流样式：

```js
<script src="img/idangerous.swiper.3dflow-2.0.js"></script>
<link rel="stylesheet" href="css/idangerous.swiper.3dflow.css">
```

现在，让我们改变我们之前用于执行 Swiper 的代码。以下代码具有许多参数，这些参数默认情况下附带它，并且它将执行我们的 3D 流脚本：

```js
<script>
$(function(){
  var mySwiper = $('.swiper-container').swiper({
    slidesPerView: 3,
    loop: true,
       tdFlow: {
      rotate: 10,
      stretch: -50,
      depth: 400,
      modifier: 1,
      shadows: true
    }
  });
});
</script>
```

好吧，看看这个补充可能带给幻灯片视觉上的巨大差异。仅仅通过使用 CSS3 Transform，Swiper 插件就可以为我们提供一种自动显示不同幻灯片效果的方式：

![在 Swiper 上使用 3D 流样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_12.jpg)

通过访问网站 [`www.idangero.us/sliders/swiper/plugins/3dflow.php`](http://www.idangero.us/sliders/swiper/plugins/3dflow.php)，我们将找到更多示例和其他 3D 流的用法选项。

## Slicebox - 当使用幻灯片图像时进行切片动画

Slicebox 是一个 jQuery 插件，用于具有优雅回退（用于不支持新 CSS 属性的旧浏览器）的响应式 3D 图像幻灯片。

该插件的视觉效果真的很酷。一旦幻灯片改变，图像就被切成三到五个部分，并且旋转，呈现出令人难以置信的效果。

### 如何做

因此，在从[`github.com/codrops/Slicebox`](https://github.com/codrops/Slicebox)下载插件后，我们将首先在`<head>`标签内包含 CSS 文件：

```js
<link rel="stylesheet" type="text/css" href="css/slicebox.css" />
<link rel="stylesheet" type="text/css" href="css/custom.css" />
```

然而，在插件中有一个缺少的 CSS 包装配置，这需要我们自己来完成：

```js
<style>
.wrapper {
  position: relative;
  max-width: 840px;
  width: 100%;
  padding: 0 50px;
  margin: 0 auto;
}
</style>
```

之后，我们将使用一个简单的 HTML 无序列表来制作我们的幻灯片，并为这个结构定义一些必需的 ID，比如`sb-slider`，`shadow`，`nav-arrows`和`nav-dots`，以及插件用于阅读的命名代码部分：

```js
<div class="wrapper">
  <ul id="sb-slider" class="sb-slider">
  <li>
    <a href="#"><img src="img/slide-img1.jpg" /></a>
    <div class="sb-description"><h3>Creative Lifesaver</h3></div>
  </li>
  <li>
    <a href="#"><img src="img/slide-img2.jpg" /></a>
    <div class="sb-description"><h3>Honest Entertainer</h3></div>
  </li>
  <li>
    <a href="#"><img src="img/slide-img3.jpg" /></a>
    <div class="sb-description"><h3>Brave Astronaut</h3></div>
  </li>
  <li>
    <a href="#"><img src="img/slide-img4.jpg" /></a>
    <div class="sb-description"><h3>Faithful Investor</h3></div>
  </li>
  </ul>
  <div id="shadow" class="shadow"></div>
  <div id="nav-arrows" class="nav-arrows">
    <a href="#">Next</a>
    <a href="#">Previous</a>
  </div>
  <div id="nav-dots" class="nav-dots">
    <span class="nav-dot-current"></span>
    <span></span>
    <span></span>
    <span></span>
  </div>
</div>
```

此外，还有一些辅助类来补充代码，比如`wrapper`（用于包装幻灯片）和`sb-description`（用于显示幻灯片描述）。

在 DOM 的底部（在`</body>`结束标签之前），包括 jQuery 和 Slicebox 库：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.slicebox.js"></script>
```

之后，我们将通过插入下一行代码来执行 Slicebox 脚本。

### 提示

然而，在我看来，这个插件的主要问题是有许多行的代码向我们暴露了。

下面的代码太庞大了，避免出现打字错误，你会发现可以从[`www.packtpub.com/support`](http://www.packtpub.com/support)下载该代码。

这是移动设备和桌面的效果截图：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_13.jpg)

# 引入触摸手势到用户体验

触摸屏设备如今统治着移动平台。大多数智能手机和平板电脑都有许多使用触摸手势的元素，现在这也逐渐应用到我们的桌面开发中。在他的文章*跨设备优化触摸*中，*Luke Wroblewski*说：

> “那么，考虑到所有屏幕尺寸的触摸意味着什么？两个东西：触摸目标尺寸和控件的放置。”

*Luke Wroblewski*强调了响应式触摸设计中要考虑的两个最重要的要点：触摸目标尺寸和控件的放置：

+   **触摸目标尺寸**：它们相对容易实现，任何需要与触摸交互的导航系统都需要有菜单选项，可以被手指不精确的人舒适地使用，以防止意外触碰和错误。一些提到可触摸区域最小尺寸应为 44 像素的文章。

+   **控件的放置**：控件需要以与人们拿着和使用触摸设备的方式相一致的方式放置。智能手机屏幕的底部区域是我们想要放置应用程序的最常见和重要的交互的地方，以便它们可以快速轻松地到达，如下网站示例所示：![引入触摸手势到用户体验](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_14.jpg)

同样地，我们可以看一下平板电脑的姿势，或者人们通常是如何拿着平板电脑的。人们用两只手沿着两侧拿着它们，或者只是在大腿上敲击屏幕：

![引入触摸手势到用户体验](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_15.jpg)

# 使用 JavaScript 插件实现触摸事件

有一些重要的 JavaScript 扩展和插件，允许我们将触摸手势集成到我们的响应式网站中，改善用户交互体验。一些例子包括 QuoJS 和 Hammer。

## QuoJS – 简单的触摸交互库

这是一个微型、模块化、面向对象和简洁的 JavaScript 库，简化了 HTML 文档的遍历、事件处理和 Ajax 交互，用于快速的移动 Web 开发。

请注意，QuoJS 不需要 jQuery 来工作；然而，它是一个简单而好的插件。

这个轻量级插件，在 gzip 压缩后仅有 5-6 KB，使我们能够拥有强大的写作、灵活性和适应性的代码。你可以在[`github.com/soyjavi/QuoJS`](https://github.com/soyjavi/QuoJS)找到可下载的文件，并在[`quojs.tapquo.com/`](http://quojs.tapquo.com/)找到有关一些额外选项的更多详细信息。

QuoJS 有这些手势来帮助我们：

+   单击

+   长按（650ms+）

+   双击

其代码包中还包括了不同类型的滑动、捏和旋转。

### 怎么做

在 DOM 底部（在 `</body>` 结束标签之前），包含 QuoJS 脚本；只有这样，我们才能通过创建事件监听器执行脚本。

在下面的例子中，如果用户将手指放在与工具箱 ID 相等的元素上，我们将实现一个动作。

```js
<script src="img/quo.js"></script>
<script src="img/jquery-1.9.1.min.js"></script>
<script>
$(document).ready(function() {
  $('#toolbox').hold(function() {
    $(this).toggleClass('open-box');
  });
});
</script>
```

QuoJS 在语法中使用`$$`符号，避免与我们可能在网站上使用的`$`jQuery 符号发生冲突。

## Hammer – 一个不错的多点触控库

Hammer 是一个 jQuery 轻量级的多点触控手势库，压缩后只有 3 KB。

Hammer 支持这些手势：

+   轻触

+   双击

+   滑动

+   拖拽

+   捏

+   旋转

每个手势触发有用的事件和插件提供的事件数据。

### 怎么做

首先，让我们从[`github.com/EightMedia/hammer.js`](https://github.com/EightMedia/hammer.js)下载库。在 DOM 底部（在 `</body>` 结束标签之前），包含 Hammer 脚本，然后我们将能够通过创建事件监听器执行脚本：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.hammer.min.js"></script>
```

### 提示

有时，不需要 jQuery 的版本似乎更快，但在所有浏览器中可能不起作用。要切换版本，只需用`hammer.min.js`替换`jquery.hammer.min.js`文件。

让我们看一个例子：

```js
<script>
$(document).ready(function() {
  var hammertime = $(".toucharea").hammer();   
  hammertime.on("touch", "#toolbox", function(ev) {
   $(this).toggleClass('open-box');
  });
});
  </script>
```

在这个例子中，它捕捉了触摸交互，并在对象上应用了`open-box`类。然而，还有许多其他的触摸事件需要处理，更多关于其用法的细节可以在[`github.com/EightMedia/hammer.js/wiki`](https://github.com/EightMedia/hammer.js/wiki)找到。

# 练习 6 – 使用 Swiper 插件创建一个图片幻灯片

只是为了提醒我们，这是我们最初设计的一个截图：

![练习 6 – 使用 Swiper 插件创建一个图片幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_06_16.jpg)

### 提示

这张图片只是一个建议。你可以找到任何图片来替换它。这里的重点是在一个响应式标签内创建一个响应式图片幻灯片。

现在，只需选择每个幻灯片一张图片，并使用 Swiper 解决方案，在每个幻灯片上插入一个标语：

+   灵活性就是一切

+   一些设计良好的动作

+   肌肉控制使身体均匀发展

+   身体健康是幸福的首要条件

正如我们在第四章中所看到的，*设计响应式文本*，高度建议在响应式网站中使用`@font-face`。因此，为了补充这个练习，使用 Google Fonts 提供的免费字体 Titan One 进行标语的自定义。

### 提示

记得在必要时使用 FontSquirrel 工具包。

# 摘要

在本章中，我们已经学习了为响应式网站准备的滑块插件，如 Elastislide、FlexSlider、ResponsiveSlides、Swiper 和 Slicebox。我们还学习了如何构建它们，它们的优点和效果特性。尽管许多这些滑块插件已经实现了手势触摸，正如我们在本章中所见，我们还向您展示了如何使用 QuoJS 和 Hammer 库来整合触摸功能。

在下一章中，我们将看到如何在小宽度设备上处理表格。我们将了解如何实现经常使用的每种技术，例如水平滚动、减少可见列和转换为堆叠表格。


# 第七章：设计响应式表格

HTML 元素表格可能相当宽以显示结构化内容。有时需要将整行数据保留在一起才能使表格有意义。表格默认可以弹性伸缩，但如果它们变得太窄，单元格内容将开始换行；这通常不太干净！

*Garrett Dimon* 提到了一个有趣的话题，关于调整表格宽度以适应不同屏幕尺寸并确保表格内容的含义的难度：

> “数据表在响应式设计方面表现不佳。只是说说而已。”

在本章中，我们将学习创建响应式表格的四种不同方法：

+   可扩展的响应式表格

+   堆叠表格

+   水平溢出

+   完整表格链接

# 响应式表格

下图显示了关于响应式表格的最常见问题，包括：最小表格宽度超过屏幕尺寸和整个表格尺寸（包括文本大小）的减小：

![响应式表格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_08.jpg)

然而，让我们看看解决这个响应式问题的不同方法。

# 可扩展的响应式表格

通过 FooTable，我们可以将 HTML 表格转换为可扩展的响应式表格，允许具有小屏幕尺寸的设备保持相同的内容，唯一的变化是您将不得不优先考虑将要显示的内容。其功能是根据断点隐藏您认为不太重要的列。因此，只有在单击/触摸行时才会显示隐藏的数据。

如果我们更深入地研究这个 jQuery 插件，我们将注意到两个重要特性为良好的代码和开发的便利做出了贡献：**即时定制**（通过来自 DOM 的数据属性）和 **断点设置**（可能与已在网站上使用的断点设置不同）。

接下来的示例中让我们看看如何在 DOM 中定义它。

## 如何做

从 [`github.com/bradvin/FooTable/`](https://github.com/bradvin/FooTable/) 下载插件后，我们将在 `<head>` 标签中包含 CSS 样式表：

```js
<link href="css/themes/footable.metro.css" rel="stylesheet" type="text/css" />
```

默认情况下，FooTable 仅使用两个断点：`phone` 设置为 `480` px，`tablet` 设置为 `1024` px。这些断点值不需要与您可能使用的值相同，因为它取决于表格需要多少空间。此外，如果必要，稍后我们将看到如何更改它。

让我们将以下代码作为示例插入到 HTML 代码中，以便练习插件资源：

```js
<table class="expandable-table">
  <thead>
    <tr>
      <th data-class="expand-icon">Contact name</th>
      <th data-hide="phone">Phone</th>
      <th data-hide="phone,tablet">Email</th>
      <th data-hide="phone" data-ignore="true">Picture</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Bob Builder</td>
      <td>555-12345</td>
      <td>bob@home.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
    <tr>
      <td>Bridget Jones</td>
      <td>544-776655</td>
      <td>bjones@mysite.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
    <tr>
      <td>Tom Cruise</td>
      <td>555-99911</td>
      <td>cruise1@crazy.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
  </tbody>
</table>
```

数据属性有助于理解 FooTable 的功能，只需查看 DOM 就可以知道哪些列会在手机或平板电脑上隐藏。

以下是 FooTable 使用的基本数据属性及其功能：

+   `data-class`：这指定要应用于列中所有单元格的 CSS 类。

+   `data-hide`：定义将在列中隐藏哪些断点。可以通过逗号分隔指定多个断点。

+   `data-ignore`：仅在查看详细信息时隐藏内容。通常与`data-hide`类一起使用，此选项的可接受值可以是`true`或`false`。

有关所有数据属性列表的更多信息，您可以访问[`fooplugins.com/footable/demos/data-attributes.htm`](http://fooplugins.com/footable/demos/data-attributes.htm)。

### 提示

如果我们使用这些数据属性，应该将它们应用在`<th>`元素上，插件将在内部单元格中反映其更改。

在 DOM 的底部（在`</body>`结束标记之前），我们需要包含两个文件：jQuery 和 FooTable 库。之后，插入以下代码来执行脚本：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/footable.min.js"></script>
<script>
  $(function() {
    $(".expandable-table").footable();
  });
</script>
```

如果我们想要更改 FooTable 的断点，只需在执行前面的脚本时指定自己的值，如下面的代码所示：

```js
<script>
  $(function() {
    $(".expandable-table").footable({
 breakpoints: {
 tablet: 768,
 smartphone: 480,
 mini: 320
 }
    });
  });
</script>
```

在下面的屏幕截图中，我们将看到如果单击 Bob 的表行会发生什么。让我们比较一下我们在智能手机和平板电脑上的响应式表格：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_01.jpg)

在此示例中，每个设备上都有一些字段，只有在单击查看特定联系人的更多详细信息时才可见。虽然这种方法可以避免大量数据，但可能很难找到一个联系人，例如，通过电子邮件，因为这需要单击所有联系人才能显示信息。

有一些插件扩展可以解决这个问题。让我们来看看它们。

## 扩展插件

使用 FooTable 作为解决方案的另一个优点是其可扩展性。该插件是模块化的，允许您通过使用插件增加功能，例如排序、过滤和分页。

排序插件提供对表格列中包含的数据进行排序的功能。为此，我们将包含以下脚本文件：

```js
<script src="img/footable.sort.js"></script>
```

然后，我们将为想要启用排序的项目设置`data-sort-initial="true"`，并为不适合排序的项目设置`data-sort-ignore="true"`，例如图像和电话：

```js
<th data-sort-initial="true">Contact name</th>
<th data-sort-ignore="true">Phone</th>
```

在下面的屏幕截图中，我们可以看到箭头图标的插入，这是插件用来对特定表头进行排序的：

![扩展插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_09.jpg)

过滤插件添加了一个搜索字段，允许用户查找他们正在寻找的数据。搜索结果为我们带来了正确的数据，即使它们对观众是隐藏的。为此，让我们在脚本文件中包含以下内容：

```js
<script src="img/footable.filter.js"></script>
```

在页面上添加一个文本输入框（在表格之前或之后），其 ID 为`#filter`，然后在表格元素的`data-filter=#filter`数据属性上指定它。以下是此筛选器的代码：

```js
Filter by: <input id="filter" type="text">
```

在下面的屏幕截图中，筛选内容，仅显示一个项目，即使找到的值被隐藏：

![扩展插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_10.jpg)

此外，分页附加组件可以帮助显示总内容的一部分，默认创建含有 10 个项目的分页。为此，我们需要在脚本文件中包含以下代码：

```js
<script src="img/footable.paginate.js"></script>
```

因此，在上一个表格示例中，在`</tbody>`之后，我们将添加以下代码，用于接收分页。以下 div 中的`pagination`类是必需的，其他类如`pagination-centered`和`hide-if-no-paging`仅为补充：

```js
<tfoot>
<tr>
  <td colspan="4">
    <div class="pagination-centered hide-if-no-paging pagination"></div>
  </td>
</tr>
</tfoot>
```

此外，对于此示例，让我们限制每页两个项目，以查看分页的使用，只需在`table`元素上添加`data-page-size="2"`。效果如下：

![扩展插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_02.jpg)

有关这些附加组件和更多插件选项的详细信息，请参阅[`fooplugins.com/footable-demos/`](http://fooplugins.com/footable-demos/)的完整文档。

尽管此插件看起来非常完善，但在某些情况下，内容需要其他界面。让我们看看堆叠表解决方案。

# 堆叠表

Stackedtable 是一个 jQuery 插件，为我们的响应式表格提供了另一种选项，可从[`johnpolacek.github.io/stacktable.js/`](http:// http://johnpolacek.github.io/stacktable.js/)下载。

此解决方案将创建表格的副本，并将宽表格转换为在小屏幕上效果更好的两列键/值格式。

### Tip

建议仅用于少量行的表格，因为它会大大增加垂直内容。

通过使用简单的媒体查询，我们可以隐藏原始表格并显示堆叠表。让我们看看如何将其付诸实践。

## 如何使用上一个示例中的表格

我们将首先在`<head>`标签内包含 CSS 样式表：

```js
<link href="stacktable.css" rel="stylesheet" />
```

如果我们想要更改断点，目的是将此解决方案用于智能手机，只需进入`stacktable.css`文件并更改`max-width`属性：

```js
@media (max-width: 480px) {
  .large-only { display: none; }
  .stacktable.small-only { display: table; }
}
```

之后，我们将添加上一个解决方案中看到的表格的基础，只需添加一个 ID 和类：

```js
<table id="stack-table" class="large-only">
  <thead>
    <tr>
      <th>Contact name</th>
      <th>Phone</th>
      <th>Email</th>
      <th>Picture</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Bob Builder</td>
      <td>555-12345</td>
      <td>bob@home.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
    <tr>
      <td>Bridget Jones</td>
      <td>544-776655</td>
      <td>bjones@mysite.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
    <tr>
      <td>Tom Cruise</td>
      <td>555-99911</td>
      <td>cruise1@crazy.com</td>
      <td><img src="img/30x30" alt="Profile image" /></td>
    </tr>
  </tbody>
</table>
```

在 DOM 的底部（在`</body>`闭合标签之前），我们需要包含两个文件：`jquery`和`stacktable`库。然后，插入以下代码执行脚本，并指定表格 ID 和一个类来限制堆叠表仅适用于智能手机，如下所需：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/stacktable.js"></script>
<script>
$('#stack-table').stacktable({myClass:'stacktable small-only'});
</script> 
```

以下是两个视图的屏幕截图—用于小设备和桌面：

![如何使用上一个示例中的表格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_03.jpg)

# 水平溢出

此技术通过冻结第一列来实现，使您可以在其下滚动其他列。这样我们保持每行看到第一列的内容，从而允许左滚动，以查看其余内容，以便更容易进行数据比较。

推荐这种表格用于有更多列的表格，并且第一列的内容比其他列更重要。让我们通过在下一个示例中练习来澄清它将是什么样子。

## 如何做

我们将从[`zurb.com/playground/responsive-tables`](http://zurb.com/playground/responsive-tables)下载解决方案。然后创建一个新的 HTML 文件，并在`<head>`标签内包含 CSS 样式表：

```js
<link rel="stylesheet" href="css/responsive-tables.css">
```

现在插入以下 HTML 表格代码，使用比之前更多的列，并添加一个名为`responsive`的类：

```js
<table class="responsive">
<tr>
  <th>Header 1</th>
  <th>Header 2</th>
  <th>Header 3</th>
  <th>Header 4</th>
  <th>Header 5</th>
  <th>Header 6</th>
</tr>
<tr>
  <td>first column important data</td>
  <td>row 1, cell 2</td>
  <td>row 1, cell 3</td>
  <td>row 1, cell 4</td>
  <td>row 1, cell 5</td>
  <td>row 1, cell 6</td>
</tr>
<tr>
  <td>first column important data</td>
  <td>row 2, cell 2</td>
  <td>row 2, cell 3</td>
  <td>row 2, cell 4</td>
  <td>row 2, cell 5</td>
  <td>row 2, cell 6</td>
</tr>
</table>
```

在 DOM 的底部（在`</body>`结束标签之前），我们只需要包含 jQuery 和响应式表格库：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/responsive-tables.js"></script>
```

让我们看一下下面的屏幕截图，显示了这张表格在智能手机和平板电脑上的情况：

![如何做](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_04.jpg)

### 小贴士

当可用屏幕宽度超过 767 像素时，我们的表格开始发生变化。如果我们想修改这个默认值，需要打开`responsive-tables.js`文件，查找数值 767，并进行更改。

从技术上讲，这很容易做到。然而，我们不能低估它在响应式网站上的效率，因为它有助于在小设备上更好地理解表格信息。

## 表头方向翻转

如果您发现我们表格的标题行比第一列更重要，并且在使用小设备时需要保持显示标题行，*David Bushell*通过仅使用 CSS 代码创建了一个有趣的解决方案。

这个 CSS 解决方案将第一列移到另一个地方，不需要任何 JavaScript 库，只需要 CSS3。

让我们从在`<head>`标签内包含 CSS 样式表开始：

```js
<style>
@media only screen and (max-width: 767px) {

.responsive {
  display: block; position: relative; 
}
.responsive thead {
  display: block; float: left;
}
.responsive tbody { 
  display: block; width: auto; position: relative;
  overflow-x: auto; white-space: nowrap;
}
.responsive thead tr {
  display: block;
}
.responsive th {
  display: block; border: 0; border-top: 1px solid #AAA;   
  background: #CCC; border-right: 1px solid #ccc;
  padding: 8px 10px !important;
}
.responsive tbody tr {
  display: inline-block; vertical-align: top;
  border-right: 1px solid #ccc;
}
.responsive td {
  display: block; min-height: 1.25em; border: 0;
}
table.responsive th:first-child, table.responsive td:first-child,
table.responsive td:first-child, table.responsive.pinned td {  
  display: block;
}

}
</style>
```

使用更真实的内容，让我们在 HTML 代码中创建这个表格：

```js
<table class="responsive" cellspacing="0" border="1">
  <thead>
    <tr>
      <th>Doctor names</th>
      <th>Values</th>
      <th>Dates</th>
      <th>Cash Money</th>
      <th>Message</th>
      <th>City</th>
      <th>State</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Dr. Jayhawk</td>
      <td>102</td>
      <td>03/30/1940</td>
      <td>$60.42</td>
      <td>PAID</td>
      <td>Atlanta</td>
      <td>Georgia</td>
    </tr>
    <tr>
      <td>Dr. John Smith</td>
      <td>137</td>
      <td>03/18/1953</td>
      <td>$69.68</td>
      <td>PAID</td>
      <td>Orlando</td>
      <td>Florida</td>
    </tr>
    <tr>
      <td>Dr. Wolverine</td>
      <td>154</td>
      <td>03/29/1976</td>
      <td>$86.68</td>
      <td>PAID</td>
      <td>New Orleans</td>
      <td>Louisiana</td>
    </tr>
    <tr>
      <td>Dr. Tarheel</td>
      <td>113</td>
      <td>03/30/1981</td>
      <td>$63.50</td>
      <td>PAID</td>
      <td>San Antonio</td>
      <td>Texas</td>
    </tr>
  </tbody>
</table>
```

让我们看一下智能手机和平板电脑上的结果：

![表头方向翻转](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_05.jpg)

# 链接到全表

链接到全表是一种不太常用的技术，因为它并不能完全解决情况。它的工作原理是用一个小模拟表来替换原表，然后只创建一个链接以查看完整的表格。

问题仍然存在，但这次用户可以在屏幕上向左/向右滑动以查看所有内容。有一个媒体查询来处理这种机制，只在小屏幕上显示它。

## 如何做

首先，让我们从可下载的代码文件中下载`full-table.css`文件。然后将其插入到 HTML 代码的`<head>`标签内。尽管这是一个 CSS 解决方案，但这段代码太长了，增加了打错字的机会。

让我们重复使用从上一个示例中复制的表格代码，但对表格元素进行修改，如下所示：

```js
<table id="responsive" class="full-table">
```

在 DOM 的底部（在`</body>`结束标签之前），我们需要包含`jquery`库并插入以下代码，根据一个类名来显示/隐藏解决方案：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script>
$(function(){
  $("#responsive").click(function(){
    $("html").toggleClass($(this).attr("class"));
  });
});
</script>
```

在下面的屏幕截图中，我们将看到针对小屏幕的被压缩表格，在点击后将用户引导至完整表格可视化。当屏幕尺寸小于或等于 520 像素时，会出现此效果（如果需要使用 CSS 文件，可以修改此值）。

![如何操作](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_06.jpg)

### 注意

插件在点击后生成水平滚动条，以查看完整宽度的表格。

# 练习 6 – 使用 FooTable jQuery 插件创建响应式价格表格

让我们使用 FooTable jQuery 插件和下面屏幕截图中表格的内容创建一个响应式表格。

### 注意

这个表格的内容并非真实，我们只是用它来练习。

在下面的屏幕截图中，我们可以看到该表格在智能手机和平板电脑上的显示，每个设备使用不同的设计：

![练习 6 – 使用 FooTable jQuery 插件创建响应式价格表格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_07_07.jpg)

您可以首先基于平板电脑的设计创建表格结构，然后使用 FooTable 插件自动化为智能手机实现紧凑的可视化效果。

# 总结

在本章中，我们学习了处理小设备宽度下宽表的四种不同方式。我们重点关注如何实现每种技术，因为它们的使用取决于表格内容的类型。我们刚刚看到的技术有：可扩展响应式表格（FooTable）、堆叠表格、水平溢出和链接到完整表格。

在下一章中，我们将学习如何使用表单，并学习如何实现自动完成、日期选择器和工具提示等功能。


# 第八章：实现响应式表单

使用 HTML5 编码在前端网页开发中的景观发生了巨大变化。通过使用适当的字段类型和本地验证，构建更好的表单的机会更多了，这是 SEO 的最佳情况。所有这些功能正在逐步被所有现代网络浏览器采用。

通过使用 jQuery，我们可以增强页面上的 HTML5 体验，增加补充功能以改善用户体验。

在本章中，我们将学习以下内容：

+   表单输入的类型和属性

+   `autocomplete` 特性

+   `datepicker` 特性

+   `tooltips` 特性

+   使用 IdealForms 的响应式框架

# 表单输入的类型和属性

使用 HTML5 输入类型带来了开发的两个主要优势：减少开发时间和改善用户体验。许多现代浏览器已经采用了这些新的输入类型和属性，整个网络社区都受益于此，促进了其使用的传播。

最常用的 HTML5 输入类型包括`email`、`date`、`tel`、`number`和`time`。此外，HTML5 自带的最常见属性包括`placeholder`、`required`、`autocomplete`和`multiple`。我们将在第十章中看到，*确保浏览器支持*，并不是所有的网络浏览器都以相同的方式支持 HTML5 特性，并且需要 jQuery 的干预来提供适当的支持。

但是，它仍然依赖于 jQuery 技术来显示诸如`autocomplete`等更复杂的验证。通常情况下，jQuery 插件与新的 HTML5 输入类型非常配合，几乎对响应式网站来说是必不可少的。在开始实现功能之前，让我们创建一个基本的表单；这是第一步，将在后续示例中使用。创建一个带有基本标签的空 HTML 站点结构，然后保留 jQuery 包含，很快就会用到它：

```js
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Responsive form</title>
</head>
<body>
<script src="img/jquery-1.9.1.min.js"></script>
</body>
</html>
```

为了逐步学习，每个特性都将独立呈现；只有之前的基本代码将被重复使用。

我们将看到的这些插件并不是服务器端验证的替代品；它们只会让用户体验更好，减少服务器请求，并提供更好的交互界面。

# 带有 Magicsuggest 的自动完成特性

Magicsuggest 是一个灵活的自动建议下拉框，在用户开始在字段中输入时提供建议。使用这个特性将减少打字的必要性，特别是在移动设备上，每输入一个字母都很麻烦。

默认情况下，Magicsuggest 具有一些很好的功能，例如按住 *Ctrl* 键选择多个项目，并在输入文本后使用 *Enter* 键添加新输入。

JSON 数据源用于填充下拉框。这里有一些可用的选项：

+   **没有数据源**：当设置为`null`时，下拉框将不会提供任何建议。如果允许`FreeEntries`设置为`true`（默认值），它仍然可以使用户输入多个条目。

+   **静态源**：它使用 JSON 对象数组、字符串数组甚至单个 CSV 字符串作为数据源。

+   **URL**：我们可以传递组件将获取其 JSON 数据的 URL。数据将使用`POST` AJAX 请求获取，该请求将输入的文本作为查询参数。

+   **函数**：我们可以设置一个返回 JSON 对象数组的函数。函数只需要一个回调函数或返回值就可以成功。

## 如何实现它

让我们从[`nicolasbize.github.io/magicsuggest/`](http://nicolasbize.github.io/magicsuggest/)下载文件。下载后，我们将在已创建的基本代码内的`<head>`标签中包含 JavaScript 和 CSS 文件：

```js
<script src="img/magicsuggest-1.3.1.js"></script>
<link rel="stylesheet" href="css/magicsuggest-1.3.1.css">
```

然后，插入以下代码片段来创建具有这些城市的 JSON 数据，然后执行 Magicsuggest 脚本，如果必要的话，同时给予一些选项：

```js
<script type="text/javascript">
$(document).ready(function() {
  var jsonData = [];
  var cities = 'New York,Los Angeles,Chicago,Houston,Paris,
Marseille,Toulouse,Lyon,Bordeaux, Philadelphia,Phoenix,
San Antonio,San Diego,Dallas'.split(',');
  for(var i=0;i<cities.length;i++) jsonData.push({id:i,name:cities[i]});
  var city = $('#field-city').magicSuggest({
    data: jsonData,
    resultAsString: true,
    maxSelection: 1,
    maxSelectionRenderer: function(){}
  })
});
</script>
```

下一步是在`<body>`标签内添加`city`字段。

```js
<label for="field-city">City: </label>
<input id="field-city" type="text"/>
```

如下截图所示，当点击选择字段时，我们将立即看到建议功能的出现：

![如何实现它](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_01.jpg)

在前面的例子中，我们只实现了基本用法。然而，此插件还有其他有趣的实现方式，可能会在未来符合您的需求，例如：

+   右侧标签选择

+   Gmail 风格组合

+   列过滤器组合

+   使用图像的自定义模板下拉框

# 日期和时间选择器功能

移动用户已经有一个非常熟悉的日期和时间输入界面。然而，我们将学习一个 jQuery 插件，它可能有助于通过在所有设备上显示相同的功能来保持网站的身份。

## Pickadate – 响应式日期/时间选择器

Pickadate 是一个响应式的 jQuery 插件，非常有趣，同时也适用于移动设备，并且轻量级。无论是什么浏览器或设备，都可以提供自定义界面。

这是一种在填写表单时方便插入正确日期的好方法，因为它可以避免打字错误，并向用户提供更好的指导，显示月份的完整日历。

### 怎么做

从[`amsul.ca/pickadate.js/`](http://amsul.ca/pickadate.js/)下载文件后，我们将从已创建的基本代码内的`<head>`标签中开始包含 JavaScript 和 CSS 文件：

```js
<script src="img/picker.js"></script>
<script src="img/picker.date.js"></script>
<script src="img/picker.time.js"></script>
<link rel="stylesheet" href="lib/themes/default.css" id="theme_base">
<link rel="stylesheet" href="lib/themes/default.date.css" id="theme_date">
<link rel="stylesheet" href="lib/themes/default.time.css" id="theme_time">
```

### 提示

如果需要支持旧浏览器，建议包含`legacy.js`文件。

之后，我们需要执行`datepicker`和`timepicker`的脚本。

```js
<script>
$('.js__datepicker').pickadate();
$('.js__timepicker').pickatime();
</script>  
```

下一步是在`<body>`标签内插入一个日期字段和另一个时间字段。插件要求类名需要被突出显示。

```js
<fieldset class="fieldset js__fieldset">
  <div class="fieldset__wrapper">
    <label>Schedule detail:</label>&nbsp;
    <input class="fieldset__input js__datepicker" type="text" placeholder="What date?">&nbsp;&nbsp;
    <input class="fieldset__input js__timepicker" type="text" placeholder="What time?">
  </div>
</fieldset>
```

以下是在智能手机和平板电脑上激活`datepicker`插件的屏幕截图：

![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_02.jpg)

以下是用户点击`时间`字段时的屏幕截图：

![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_03.jpg)

`pickadate`插件非常完善，提供了其扩展以添加对以下支持：

+   翻译（包括从右到左的语言）

+   不同的格式

+   日期/时间限制

您可以在[`amsul.ca/pickadate.js/date.htm#options`](http://amsul.ca/pickadate.js/date.htm#options)找到关于这些扩展的更多信息。

# 工具提示功能

`tooltip`是在网页上元素的标签和输入字段之间常见的一种方式，用于呈现有关元素的附加上下文信息。其作用是提供有关特定字段的更多信息。

随着工具提示作为用户与网页元素交互的一种常见方式，设计和交互良好的工具提示变得更加重要。

通常，将鼠标指针放在元素上即可显示工具提示，并显示消息。由于大多数移动设备没有指针，因此必须通过显示触摸时的工具提示的插件来处理此问题。

## Tooltipster - 现代工具提示功能

Tooltipster 是一个强大而灵活的 jQuery 插件，可让您轻松创建语义化和现代化的工具提示。

### 如何操作

我们将从[`calebjacob.com/tooltipster/`](http://calebjacob.com/tooltipster/)下载 tooltipster 文件，并将 JavaScript 和 CSS 文件包含在已创建的基本代码的`<head>`标签中：

```js
<script src="img/jquery.tooltipster.min.js"></script>
<link rel="stylesheet" href="css/tooltipster.css" />
```

要激活插件，我们将添加`tooltipster`库并将其配置为对具有`.tooltip`类的所有元素执行（在本例中，只有一个实例，但您可以在页面中使用多个）：

```js
<script>
$(function() {
  $('.tooltip').tooltipster();
});
</script>
```

之后，我们将添加一个问号图像，并在我们想要在其上显示工具提示的每个元素上定义`tooltip`类：

```js
<img class="tooltip" title="This is my image's tooltip message!" src="img/question-mark.png" />
```

以下是点击/触摸元素后插件的屏幕截图：

![操作方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_04.jpg)

我们还可以通过编辑`tooltipster.css`文件来修改默认插件主题，或者通过在`script`调用中指定类来覆盖现有主题。

```js
<script>
$(function() {
  $('.tooltip').tooltipster({
    theme: '.my-custom-theme'
  });
});
</script>
```

# 使用 IdealForms 创建响应式表单

IdealForms，位于[`github.com/elclanrs/jq-idealforms`](https://github.com/elclanrs/jq-idealforms)，是一个用于构建和验证响应式 HTML5 表单的框架。此外，它具有键盘支持，在用户转到下一个字段时快速验证，并为大多数浏览器提供占位符支持。

IdealForms 框架还具有分页选项，可在填写大型表单时大大改善用户体验。让我们逐步练习以了解其用法。

## 如何实现它

创建一个新的 HTML 文件，并复制我们在本章开头已经编写的基本代码。然后，我们将在 `<head>` 标签中包含 CSS 样式表。

```js
<link rel="stylesheet" href="css/jquery.idealforms.min.css"/>
```

让我们将以下示例代码插入 HTML 结构中，其界面使用 `<section>` 标签分为两个标签页：

```js
<form id="form">
  <div><h2>Profile form:</h2></div>
```

在第一个标签页中，我们将添加`用户名`、`密码`和`电子邮件`字段：

```js
<section name="First tab">
  <div><label>Username:</label>
  <input id="username" name="username" type="text" /></div>
  <div><label>Password:</label>
  <input id="pass" name="password" type="password" /></div>
  <div><label>E-Mail:</label>
  <input id="email" name="email" data-ideal="required email" type="email" /></div>
</section>
```

在第二个标签页中，我们将添加`文件`、`语言`和`电话`字段。

```js
<section name="Second tab">

  <div><label>Image:</label>
  <input id="file" name="file" multiple type="file" /></div>
  <div id="languages">
  <label>Languages:</label>
  <label><input type="checkbox" name="langs[]" value="English"/>English</label>
  <label><input type="checkbox" name="langs[]" value="Chinese"/>Chinese</label>
  <label><input type="checkbox" name="langs[]" value="Spanish"/>Spanish</label>
  </div>
  <div><label>Phone:</label>
  <input type="tel" name="phone" data-ideal="phone" /></div>
</section>
```

最后，我们将添加一个`提交`按钮。

```js
  <div><hr/></div>
  <div><button type="submit">Submit</button>
</form>
```

在 DOM 底部（在 `</body>` 结束标记之前），我们需要包含 `jquery` 和 `idealforms` 库。

```js
<script src="img/jquery.idealforms.js"></script>
```

然后，插入以下代码，这将执行开始创建一个函数的脚本，该函数在用户填写不正确值时会弹出警告。

```js
<script>
  var options = {
    onFail: function() {
      alert( $myform.getInvalid().length +' invalid fields.' )
    },
```

在这里，我们将设置哪个表单元素将被验证。

```js
    inputs: {
      'password': {
        filters: 'required pass',
      },
      'username': {
        filters: 'required username',
        data: { //ajax: { url:'validate.php' } }
      },
      'file': {
        filters: 'extension',
        data: { extension: ['jpg'] }
      },      'langs[]': {
        filters: 'min max',
        data: { min: 2, max: 3 },
        errors: {
          min: 'Check at least <strong>2</strong> options.',
          max: 'No more than <strong>3</strong> options allowed.'
        }
      }
    }
  };
```

完成验证后，我们将执行`idealforms` JavaScript，加载之前设置的所有验证。

```js
  var $myform = $('#form').idealforms(options).data('idealforms');
</script>
```

就这样！客户端验证已经实现。

以下是在智能手机设备上查看时该框架运行情况的截图：

![如何实现](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_06.jpg)

同一页面可能在桌面上查看，并且默认布局非常适配。

![如何实现](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_07.jpg)

# 练习 8 – 使用 IdealForms 框架创建联系表单

让我们基于先前完整的逐步示例并使用 IdealForms 框架作为此表单基础来创建一个响应式联系表单项目。

所以，和以往一样，让我们开始包括 CSS 文件和以下字段：**姓名**、**电子邮件**、**理想的第一课**（日期），以及如下截图所示的**电话**：

![练习 8 – 使用 IdealForms 框架创建联系表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_08_08.jpg)

日期字段未在 IdealForms 中提及，因为默认情况下，它使用 jQueryUI 解决方案。然而，我建议使用 Pickadate 插件，因为与 jQueryUI 相比，它更轻量级，并且还有助于强化我们之前学到的示例。

# 摘要

在本章中，我们学习了如何通过使用一些 jQuery 插件来完善代码与 HTML5 表单元素很好地配合，例如`autocomplete`的 Magicsuggest，`datepicker`的 Pickadate，以及在必要时的`tooltips`的 Tooltipster。此外，我们还体验了如何使用 IdealForms，一个响应式表单框架，来构建联系表单界面。

在下一章中，我们将使用工具和脚本来测试网站，以确保其在所有设备上的响应性。彻底理解下一章对于检查我们在旧浏览器或移动设备上实现可能出现的错误并进一步修复它们至关重要。此外，测试阶段对于避免客户报告的未来意外非常重要。
