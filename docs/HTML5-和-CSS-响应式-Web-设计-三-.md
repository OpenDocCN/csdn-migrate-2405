# HTML5 和 CSS 响应式 Web 设计（三）

> 原文：[`zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3`](https://zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 SVG 实现分辨率独立性

整本书都在写关于 SVG 的内容。SVG 是响应式网页设计的重要技术，因为它为所有屏幕分辨率提供了清晰和未来可靠的图形资产。

在 Web 上，使用 JPEG、GIF 或 PNG 等格式的图像，其视觉数据保存为固定像素。如果您以固定宽度和高度保存图形，并将图像放大到原始大小的两倍或更多，它们的限制很容易暴露出来。

这是我在浏览器中放大的 PNG 图像截图：

![使用 SVG 实现分辨率独立性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_08.jpg)

你能看到图像明显呈现像素化吗？这是完全相同的图像，保存为矢量图像，以 SVG 格式，并放大到类似的级别：

![使用 SVG 实现分辨率独立性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_09.jpg)

希望差异是显而易见的。

除了最小的图形资产外，尽可能使用 SVG 而不是 JPEG、GIF 或 PNG，将产生分辨率独立的图形，与位图图像相比，文件大小要小得多。

虽然我们将在本章涉及 SVG 的许多方面，但重点将放在如何将它们整合到您的工作流程中，同时还提供 SVG 的可能性概述。

在本章中，我们将涵盖：

+   SVG，简要历史，以及基本 SVG 文档的解剖

+   使用流行的图像编辑软件和服务创建 SVG

+   使用`img`和`object`标签将 SVG 插入页面

+   将 SVG 插入为背景图像

+   直接（内联）将 SVG 插入 HTML

+   重用 SVG 符号

+   引用外部 SVG 符号

+   每种插入方法可能具有的功能

+   使用 SMIL 对 SVG 进行动画处理

+   使用外部样式表对 SVG 进行样式设置

+   使用内部样式对 SVG 进行样式设置

+   使用 CSS 修改和动画 SVG

+   媒体查询和 SVG

+   优化 SVG

+   使用 SVG 定义 CSS 滤镜

+   使用 JavaScript 和 JavaScript 库操纵 SVG

+   实施提示

+   更多资源

SVG 是一个复杂的主题。本章的哪些部分与您的需求最相关将取决于您实际需要的 SVG。希望我能够提供一些快捷方式。

如果您只是想用 SVG 版本替换网站上的静态图形资产，以获得更清晰的图像和/或更小的文件大小，那么请查看使用 SVG 作为背景图像和在`img`标签中的较短部分。

如果您想了解哪些应用程序和服务可以帮助您生成和管理 SVG 资产，请跳转到*使用流行的图像编辑软件和服务创建 SVG*部分，获取一些有用的链接和指引。

如果您想更全面地了解 SVG，或者想要对 SVG 进行动画和操作，最好找个舒服的地方，准备一份您最喜欢的饮料，因为这会是一个相当长的过程。

为了开始我们的理解之旅，请和我一起回到 2001 年。

# SVG 的简要历史

SVG 的首次发布是在 2001 年。这不是笔误。SVG 自 2001 年以来一直存在。虽然它在发展过程中获得了一些关注，但直到高分辨率设备的出现，它们才受到了广泛的关注和采用。以下是来自 1.1 规范的 SVG 介绍（[`www.w3.org/TR/SVG11/intro.html`](http://www.w3.org/TR/SVG11/intro.html)）：

SVG 是一种用 XML 描述二维图形的语言[XML10]。SVG 允许三种类型的图形对象：矢量图形形状（例如，由直线和曲线组成的路径）、图像和文本。

正如其名称所示，SVG 允许将二维图像描述为矢量点的代码。这使它们成为图标、线条图和图表的理想选择。

由于矢量描述了相对点，它们可以按比例缩放到任何大小，而不会失去保真度。此外，就数据而言，由于 SVG 被描述为矢量点，与大小相当的 JPEG、GIF 或 PNG 文件相比，它们往往很小。

现在，浏览器对 SVG 的支持也非常好。Android 2.3 及以上版本，以及 Internet Explorer 9 及以上版本都支持 SVG（[`caniuse.com/#search=svg`](http://caniuse.com/#search=svg)）。

# 作为文档的图形

通常情况下，如果您尝试在文本编辑器中查看图形文件的代码，生成的文本将完全无法理解。

SVG 图形的不同之处在于它们实际上是用一种标记样式语言描述的。SVG 是用**可扩展标记语言**（**XML**）编写的，这是 HTML 的近亲。尽管您可能没有意识到，但 XML 实际上无处不在于互联网上。您使用 RSS 阅读器吗？那就是 XML。XML 是将 RSS 订阅的内容打包起来，使其可以轻松地被各种工具和服务使用的语言。

因此，不仅机器可以读取和理解 SVG 图形，我们也可以。

让我举个例子。看看这个星形图形：

![作为文档的图形](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_10.jpg)

这是一个名为`Star.svg`的 SVG 图形，位于`example_07-01`内。您可以在浏览器中打开此示例，它将显示为星形，或者您可以在文本编辑器中打开它，您可以看到生成它的代码。考虑一下：

```html
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="198px" height="188px" viewBox="0 0 198 188" version="1.1"   >
    <!-- Generator: Sketch 3.2.2 (9983) - http://www.bohemiancoding.com/sketch -->
    <title>Star 1</title>
    <desc>Created with Sketch.</desc>
    <defs></defs>
    <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd" sketch:type="MSPage">
        <polygon id="Star-1" stroke="#979797" stroke-width="3" fill="#F8E81C" sketch:type="MSShapeGroup" points="99 154 40.2214748 184.901699 51.4471742 119.45085 3.89434837 73.0983006 69.6107374 63.5491503 99 4 128.389263 63.5491503 194.105652 73.0983006 146.552826 119.45085 157.778525 184.901699 "></polygon>
    </g>
</svg>
```

这就是生成那个星形 SVG 图形所需的全部代码。

现在，通常情况下，如果您以前从未查看过 SVG 图形的代码，您可能会想知道为什么要这样做。如果您只想在网页上显示矢量图形，那么您确实不需要。只需找到一个可以将矢量艺术作品保存为 SVG 的图形应用程序，就可以了。我们将在接下来的页面中列出其中一些软件包。

然而，虽然只在图形编辑应用程序中使用 SVG 图形是常见且可能的，但如果您需要开始操作和动画化 SVG，了解 SVG 如何拼合以及如何调整它以满足您的需求可能会非常有用。

因此，让我们仔细看看 SVG 标记，并了解其中到底发生了什么。我想让您注意一些关键事项。

## 根 SVG 元素

这里的根 SVG 元素具有`width`、`height`和`viewbox`属性。

```html
 <svg width="198px" height="188px" viewBox="0 0 198 188"
```

这些都在如何显示 SVG 图形中扮演着重要的角色。

希望在这一点上，您理解了“视口”这个术语。它在本书的大多数章节中都被用来描述设备上用于查看内容的区域。例如，移动设备可能有一个 320 像素乘以 480 像素的视口。台式电脑可能有一个 1920 像素乘以 1080 像素的视口。

SVG 的`width`和`height`属性有效地创建了一个视口。通过这个定义的视口，我们可以窥视 SVG 内部定义的形状。就像网页一样，SVG 的内容可能比视口大，但这并不意味着其余部分不存在，它只是隐藏在我们当前的视图之外。

另一方面，视图框定义了 SVG 中所有形状所遵循的坐标系。

您可以将视图框的值 0 0 198 188 看作描述矩形的左上角和右下角区域。前两个值，在技术上称为**min-x**和**min-y**，描述了左上角，而后两个值，在技术上称为宽度和高度，描述了右下角。

具有`viewbox`属性使您可以执行缩放图像等操作。例如，如果像这样在`viewbox`属性中减半宽度和高度：

```html
<svg width="198px" height="188px" viewBox="0 0 99 94"
```

形状将“缩放”以填充 SVG 的宽度和高度。

### 提示

要真正理解视图框和 SVG 坐标系统以及它所提供的机会，我建议阅读 Sara Soueidan 的这篇文章：[`sarasoueidan.com/blog/svg-coordinate-systems/`](http://sarasoueidan.com/blog/svg-coordinate-systems/) 以及 Jakob Jenkov 的这篇文章：[`tutorials.jenkov.com/svg/svg-viewport-view-box.html`](http://tutorials.jenkov.com/svg/svg-viewport-view-box.html)

## 命名空间

这个 SVG 文件为生成它的 Sketch 图形程序定义了一个额外的命名空间（`xmlns`是 XML 命名空间的缩写）。

这些命名空间引用通常只被生成 SVG 的程序使用，因此当 SVG 被用于网络时，它们通常是不需要的。用于减小 SVG 文件大小的优化过程通常会将它们剥离。

## 标题和描述标签

有`title`和`desc`标签，使得 SVG 文档非常易于访问：

```html
<title>Star 1</title>
    <desc>Created with Sketch.</desc>
```

这些标签可以用来描述图形的内容，当它们看不见时。然而，当 SVG 图形用于背景图形时，这些标签可以被删除以进一步减小文件大小。

## 定义标签

在我们的示例代码中有一个空的`defs`标签：

```html
<defs></defs>
```

尽管在我们的示例中为空，但这是一个重要的元素。它用于存储各种可重用内容的定义，如渐变、符号、路径等。

## g 元素

`g`元素用于将其他元素分组在一起。例如，如果你要绘制一辆汽车的 SVG，你可能会将组成整个车轮的形状放在`g`标签内。

```html
<g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd" sketch:type="MSPage">
```

在我们的`g`标签中，我们可以看到之前的 sketch 命名空间在这里被重用。这将帮助图形应用程序再次打开这个图形，但如果这个图像被绑定到其他地方，它就没有进一步的作用了。

## SVG 形状

在这个示例中，最内部的节点是一个多边形。

```html
<polygon id="Star-1" stroke="#979797" stroke-width="3" fill="#F8E81C" sketch:type="MSShapeGroup" points="99 154 40.2214748 184.901699 51.4471742 119.45085 3.89434837 73.0983006 69.6107374 63.5491503 99 4 128.389263 63.5491503 194.105652 73.0983006 146.552826 119.45085 157.778525 184.901699 "></polygon>
```

SVG 具有许多现成的形状可用（`path`、`rect`、`circle`、`ellipse`、`line`、`polyline`和`polygon`）。

## SVG 路径

SVG 路径与 SVG 的其他形状不同，因为它们由任意数量的连接点组成（使你可以自由地创建任何形状）。

所以这就是 SVG 文件的要点，希望现在你对正在发生的事情有了一个高层次的理解。虽然有些人会喜欢手写或编辑 SVG 文件的代码，但更多的人宁愿用图形软件生成 SVG。让我们考虑一些更受欢迎的选择。

# 使用流行的图像编辑软件和服务创建 SVG

虽然 SVG 可以在文本编辑器中打开、编辑和编写，但有许多应用程序提供图形用户界面（GUI），使得如果你来自图形编辑背景，编写复杂的 SVG 图形会更容易。也许最明显的选择是 Adobe 的 Illustrator（PC/Mac）。然而，它对于偶尔使用者来说是昂贵的，所以我个人偏好 Bohemian Coding 的 Sketch（仅限 Mac：[`bohemiancoding.com/sketch/`](http://bohemiancoding.com/sketch/)）。这本身也不便宜（目前为 99 美元），但如果你使用 Mac，这仍然是我推荐的选择。

如果你使用 Windows/Linux 或者正在寻找更便宜的选择，可以考虑免费开源的 Inkscape（[`inkscape.org/en/`](https://inkscape.org/en/)）。它并不是最好看的工具，但它非常有能力（如果你需要任何证明，可以查看 Inkscape 画廊：[`inkscape.org/en/community/gallery/`](https://inkscape.org/en/community/gallery/)）。

最后，有一些在线编辑器。Google 有 SVG-edit ([`svg-edit.googlecode.com/svn/branches/stable/editor/svg-editor.html`](http://svg-edit.googlecode.com/svn/branches/stable/editor/svg-editor.html))。还有 Draw SVG ([`www.drawsvg.org`](http://www.drawsvg.org))，以及 Method Draw，这是 SVG-edit 的一个外观更好的分支（[`editor.method.ac/`](http://editor.method.ac/)）。

## 使用 SVG 图标服务节省时间

前面提到的应用程序都可以让您从头开始创建 SVG 图形。但是，如果您想要的是图标，您可能可以通过从在线图标服务下载 SVG 版本来节省大量时间（对我来说，获得更好的结果）。我个人最喜欢的是[`icomoon.io/`](http://icomoon.io/)也很棒。

为了快速说明在线图标服务的好处，加载 icomoon.io 应用程序会为您提供一个可搜索的图标库（一些免费，一些付费）：

![使用 SVG 图标服务节省时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_01.jpg)

您可以选择您想要的图标，然后单击下载。生成的文件包含 SVG、PNG 和 SVG 符号的图标，用于放置在`defs`元素中（请记住，`defs`元素是用于引用元素的容器元素）。

要自己看一下，请打开`example_07-02`，您可以看到我从[`icomoon.io/`](http://icomoon.io/)选择了五个图标后的下载文件。

# 将 SVG 插入到您的网页中

有许多与 SVG 图像（与常规图像格式 JPEG、GIF、PNG 不同）相关的事情（取决于浏览器），您可以做的事情。可能的范围在很大程度上取决于 SVG 插入到页面的方式。因此，在我们实际可以对 SVG 做些什么之前，我们将考虑我们实际上可以将它们放在页面上的各种方式。

## 使用 img 标签

使用 SVG 图形的最直接方法就是将其插入到 HTML 文档中的方式。我们只需使用一个好老旧的`img`标签：

```html
<img src="img/mySconeVector.svg" alt="Amazing line art of a scone" />
```

这使得 SVG 的行为几乎与任何其他图像相同。关于这点没有更多要说的。

## 使用对象标签

`object`标签是 W3C 推荐的在网页中保存非 HTML 内容的容器（object 的规范位于[`www.w3.org/TR/html5/embedded-content-0.html`](http://www.w3.org/TR/html5/embedded-content-0.html)）。我们可以利用它来像这样将 SVG 插入到我们的页面中：

```html
<object data="img/svgfile.svg" type="image/svg+xml">
    <span class="fallback-info">Your browser doesn't support SVG</span>
</object>
```

`data`或`type`属性是必需的，尽管我总是建议两者都添加。`data`属性是您链接到 SVG 资产的位置，方式与链接到任何其他资产的方式相同。`type`属性描述了与内容相关的 MIME 类型。在这种情况下，`image/svg+xml`是用于指示数据为 SVG 的 MIME（互联网媒体类型）类型。如果您希望使用此容器限制 SVG 的大小，还可以添加`width`和`height`属性。

通过`object`标签插入到页面中的 SVG 也可以通过 JavaScript 访问，这就是以这种方式插入它们的一个原因。但是，使用`object`标签的额外好处是，它为浏览器不理解数据类型时提供了一个简单的机制。例如，如果在不支持 SVG 的 Internet Explorer 8 中查看先前的`object`元素，它将简单地看到消息“您的浏览器不支持 SVG”。您可以使用此空间在`img`标签中提供备用图像。但是，请注意，根据我的粗略测试，浏览器将始终下载备用图像，无论它是否真正需要它。因此，如果您希望您的网站以尽可能短的时间加载（您会的，相信我），这实际上可能不是最佳选择。

### 注意

如果您想使用 jQuery 操作通过`object`标签插入的 SVG，您需要使用本机`.contentDocument` JavaScript 属性。然后，您可以使用 jQuery`.attr`来更改`fill`等内容。

提供备用的另一种方法是通过 CSS 添加`background-image`。例如，在我们上面的示例中，我们的备用 span 具有`.fallback-info`类。我们可以在 CSS 中使用它来链接到合适的`background-image`。这样，只有在需要时才会下载`background-image`。

## 将 SVG 作为背景图像插入

SVG 可以像任何其他图像格式（PNG、JPG、GIF）一样在 CSS 中用作背景图像。在引用它们的方式上没有什么特别之处：

```html
.item {
    background-image: url('image.svg');
}
```

对于不支持 SVG 的旧版浏览器，您可能希望在更广泛支持的格式（通常是 PNG）中包含一个“回退”图像。以下是一种在 IE8 和 Android 2 中实现的方法，因为 IE8 不支持 SVG 或`background-size`，而 Android 2.3 不支持 SVG 并且需要对`background-size`使用供应商前缀：

```html
.item {
    background: url('image.png') no-repeat;
    background: url('image.svg') left top / auto auto no-repeat;
}
```

在 CSS 中，如果应用了两个等效的属性，样式表中较低的属性将始终覆盖上面的属性。在 CSS 中，浏览器总是会忽略它无法理解的规则中的属性/值对。因此，在这种情况下，旧版浏览器会得到 PNG，因为它们无法使用 SVG 或理解未加前缀的`background-size`属性，而实际上可以使用任何一种的新版浏览器会采用下面的规则，因为它覆盖了第一个规则。

您还可以借助 Modernizr 提供回退；这是用于测试浏览器功能的 JavaScript 工具（Modernizr 在第五章中有更详细的讨论，“CSS3-选择器、排版、颜色模式和新功能”）。Modernizr 对一些不同的 SVG 插入方法进行了单独测试，而下一个版本的 Modernizr（撰写时尚未发布）可能会对 CSS 中的 SVG 有更具体的内容。然而，目前您可以这样做：

```html
.item {
    background-image: url('image.png');
}
.svg .item {
    background-image: url('image.svg');
}
```

或者如果更喜欢，可以颠倒逻辑：

```html
.item {
    background-image: url('image.svg');
}
.no-svg .item {
    background-image: url('image.png');
}
```

当功能查询得到更全面的支持时，您也可以这样做：

```html
.item {
    background-image: url('image.png');
}

@supports (fill: black) {
    .item {
        background-image: url('image.svg');
    }
}
```

`@supports`规则在这里起作用，因为`fill`是 SVG 属性，所以如果浏览器理解它，它将采用下面的规则而不是第一个规则。

如果您对 SVG 的需求主要是静态背景图像，比如图标之类的，我强烈建议将 SVG 作为背景图像实现。这是因为有许多工具可以自动创建图像精灵或样式表资产（这意味着将 SVG 作为数据 URI 包含），回退 PNG 资产以及从您创建的任何单个 SVG 生成所需的样式表。以这种方式使用 SVG 得到了很好的支持，图像本身缓存效果很好（因此在性能方面效果很好），而且实现起来很简单。

## 关于数据 URI 的简要说明

如果您阅读前面的部分，并想知道与 CSS 相关的数据**统一资源标识符**（**URI**）是什么意思，它是一种在 CSS 文件本身中包含通常是外部资产（如图像）的方法。因此，我们可能会这样链接外部图像文件：

```html
.external {
  background-image: url('Star.svg');
}
```

我们可以简单地在样式表中包含图像，使用数据 URI，如下所示：

```html
.data-uri {
  background-image: url(data:image/svg+xml,%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%20standalone%3D%22no%22%3F%3E%0A%3Csvg%20width%3D%22198px%22%20height%3D%22188px%22%20viewBox%3D%220%200%20198%20188%22%20version%3D%221.1%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20xmlns%3Axlink%3D%22http%3A%2F%2Fwww.w3.org%2F1999%2Fxlink%22%20xmlns%3Asketch%3D%22http%3A%2F%2Fwww.bohemiancoding.com%2Fsketch%2Fns%22%3E%0A%20%20%20%20%3C%21--%20Generator%3A%20Sketch%203.2.2%20%289983%29%20-%20http%3A%2F%2Fwww.bohemiancoding.com%2Fsketch%20--%3E%0A%20%20%20%20%3Ctitle%3EStar%201%3C%2Ftitle%3E%0A%20%20%20%20%3Cdesc%3ECreated%20with%20Sketch.%3C%2Fdesc%3E%0A%20%20%20%20%3Cdefs%3E%3C%2Fdefs%3E%0A%20%20%20%20%3Cg%20id%3D%22Page-1%22%20stroke%3D%22none%22%20stroke-width%3D%221%22%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%20sketch%3Atype%3D%22MSPage%22%3E%0A%20%20%20%20%20%20%20%20%3Cpolygon%20id%3D%22Star-1%22%20stroke%3D%22%23979797%22%20stroke-width%3D%223%22%20fill%3D%22%23F8E81C%22%20sketch%3Atype%3D%22MSShapeGroup%22%20points%3D%2299%20154%2040.2214748%20184.901699%2051.4471742%20119.45085%203.89434837%2073.0983006%2069.6107374%2063.5491503%2099%204%20128.389263%2063.5491503%20194.105652%2073.0983006%20146.552826%20119.45085%20157.778525%20184.901699%20%22%3E%3C%2Fpolygon%3E%0A%20%20%20%20%3C%2Fg%3E%0A%3C%2Fsvg%3E);
}
```

这并不美观，但它提供了一种消除网络上的单独请求的方法。数据 URI 有不同的编码方法，还有很多工具可以从您的资产创建数据 URI。

如果以这种方式对 SVG 进行编码，我建议避免使用 base64 方法，因为它对 SVG 内容的压缩效果不如文本好。

## 生成图像精灵

我个人推荐的工具，用于生成图像精灵或数据 URI 资产，是 Iconizr（[`iconizr.com/`](http://iconizr.com/)）。它可以完全控制您希望生成的最终 SVG 和回退 PNG 资产。您可以将 SVG 和回退 PNG 文件输出为数据 URI 或图像精灵，甚至包括加载正确资产的必要 JavaScript 片段，如果您选择数据 URI，则强烈推荐使用。

此外，如果您在思考是选择数据 URI 还是图像精灵用于您的项目，我对数据 URI 或图像精灵的利弊进行了进一步研究，您可能会对此感兴趣，如果您面临同样的选择：[`benfrain.com/image-sprites-data-uris-icon-fonts-v-svgs/`](http://benfrain.com/image-sprites-data-uris-icon-fonts-v-svgs/)

虽然我非常喜欢 SVG 作为背景图像，但如果您想要动态地对其进行动画，或者通过 JavaScript 将值注入其中，最好选择将 SVG 数据“内联”插入 HTML。

# 内联插入 SVG

由于 SVG 仅仅是一个 XML 文档，您可以直接将其插入 HTML 中。例如：

```html
<div>
    <h3>Inserted 'inline':</h3>
    <span class="inlineSVG">
        <svg id="svgInline" width="198" height="188" viewBox="0 0 198 188"  >
        <title>Star 1</title>
            <g class="star_Wrapper" fill="none" fill-rule="evenodd">
                <path id="star_Path" stroke="#979797" stroke-width="3" fill="#F8E81C" d="M99 154l-58.78 30.902 11.227-65.45L3.894 73.097l65.717-9.55L99 4l29.39 59.55 65.716 9.548-47.553 46.353 11.226 65.452z" />
            </g>
        </svg>
    </span>
</div>
```

不需要特殊的包装元素，您只需在 HTML 标记中插入 SVG 标记。还值得知道的是，如果在`svg`元素上删除任何`width`和`height`属性，SVG 将会流动地缩放以适应包含元素。

在文档中插入 SVG 可能是最多功能的 SVG 特性。

## 从符号中重复使用图形对象

在本章的前面，我提到我从 IcoMoon（[`icomoon.io`](http://icomoon.io)）中挑选并下载了一些图标。它们是描绘触摸手势的图标：滑动、捏、拖动等等。假设在您正在构建的网站中，您需要多次使用它们。请记住，我提到这些图标有 SVG 符号定义的版本？这就是我们现在要使用的。

在`example_07-09`中，我们将在页面的 SVG 的`defs`元素中插入各种符号定义。您会注意到在 SVG 元素上使用了内联样式：`display:none`，`height`和`width`属性都被设置为零（如果您愿意，这些样式可以在 CSS 中设置）。这样做是为了使这个 SVG 不占用空间。我们只是使用这个 SVG 来容纳我们想要在其他地方使用的图形对象的符号。

因此，我们的标记从这里开始：

```html
<body>
    <svg display="none" width="0" height="0" version="1.1"  >
    <defs>
    <symbol id="icon-drag-left-right" viewBox="0 0 1344 1024">
        <title>drag-left-right</title>
        <path class="path1" d="M256 192v-160l-224 224 224 224v-160h256v-128z"></path>
```

注意`defs`元素内的`symbol`元素？这是我们想要定义形状以供以后重用时使用的元素。

在 SVG 定义了我们工作所需的所有必要符号之后，我们有了所有我们的“正常”HTML 标记。然后，当我们想要使用其中一个符号时，我们可以这样做：

```html
<svg class="icon-drag-left-right">
  <use xlink:href="#icon-drag-left-right"></use>
</svg>
```

这将显示拖动左右图标：

![从符号中重复使用图形对象](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_06.jpg)

这里的魔法是`use`元素。正如您可能已经从名称中猜到的那样，它用于利用已经在其他地方定义的现有图形对象。选择要引用的机制是`xlink`属性，在这种情况下，它引用了我们在标记开头内联的“拖动左右”图标（`#icon-drag-left-right`）的符号 ID。

当您重复使用一个符号时，除非您明确设置了大小（可以通过元素本身的属性或 CSS 设置），否则`use`将被设置为宽度和高度为 100%。因此，要调整我们的图标大小，我们可以这样做：

```html
.icon-drag-left-right {
    width: 2.5rem;
    height: 2.5rem;
}
```

`use`元素可用于重用各种 SVG 内容：渐变、形状、符号等等。

## 内联 SVG 允许在不同的上下文中使用不同的颜色

使用内联 SVG，您还可以做一些有用的事情，比如根据上下文更改颜色，当您需要不同颜色的相同图标的多个版本时，这将非常有用：

```html
.icon-drag-left-right {
    fill: #f90;
}

.different-context .icon-drag-left-right {
    fill: #ddd;
}
```

### 使双色图标继承其父元素的颜色

使用内联 SVG，您还可以玩得很开心，从单色图标创建双色效果（只要 SVG 由多个路径组成），并使用`currentColor`，这是最古老的 CSS 变量。要做到这一点，在 SVG 符号内部，将要成为一种颜色的路径的`fill`设置为`currentColor`。然后在 CSS 中使用颜色值对元素进行着色。对于 SVG 符号中没有填充的路径，设置为`currentColor`，它们将接收填充值。举例说明：

```html
.icon-drag-left-right {
    width: 2.5rem;
    height: 2.5rem;
    fill: #f90;
    color: #ccc; /* this gets applied to the path that has it's fill attribute set to currentColor in the symbol */
}
```

这是同一个符号被重复使用了三次，每次都有不同的颜色和大小：

![使双色图标继承其父元素的颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_07.jpg)

请记住，您可以查看`example_07-09`中的代码。还值得知道的是，颜色不一定要设置在元素本身上，它可以在任何父元素上；`currentColor`将从 DOM 树上的最近的父元素继承一个值。

以这种方式使用 SVG 有很多积极的方面。唯一的缺点是需要在每个要使用图标的页面上包含相同的 SVG 数据。不幸的是，这对性能来说是不好的，因为资产（SVG 数据）不容易被缓存。然而，还有另一种选择（如果您愿意添加一个脚本来支持 Internet Explorer）。

## 从外部来源重用图形对象

与其在每个页面中粘贴一组巨大的 SVG 符号，同时仍然使用`use`元素，不如链接到外部 SVG 文件并获取您想要使用的文档部分。看一下`example-07-10`，和我们在`example_07-09`中的三个图标以这种方式放在页面上：

```html
<svg class="icon-drag-left-right">
    <use xlink:href="defs.svg#icon-drag-left-right"></use>
</svg>
```

重要的是要理解`href`。我们正在链接到外部 SVG 文件（`defs.svg`部分），然后指定我们想要使用的文件中的符号的 ID（`#icon-drag-left-right`部分）。

这种方法的好处是，浏览器会缓存资产（就像任何其他外部图像一样），并且它可以节省我们的标记，不用用充满符号定义的 SVG。缺点是，与内联放置`defs`时不同，对`defs.svg`进行的任何动态更改（例如，如果路径被 JavaScript 操纵）不会在`use`标签中更新。

不幸的是，Internet Explorer 不允许从外部资产引用符号。但是，有一个用于 IE9-11 的 polyfill 脚本，名为**SVG For Everybody**，它允许我们无论如何使用这种技术。请访问[`github.com/jonathantneal/svg4everybody`](https://github.com/jonathantneal/svg4everybody)了解更多信息。

使用那段 JavaScript 时，您可以愉快地引用外部资产，polyfill 将直接将 SVG 数据插入到文档的主体中，以支持 Internet Explorer。

# 您可以使用每种 SVG 插入方法（内联、对象、背景图像和 img）做什么

如前所述，SVG 与其他图形资产不同。它们的行为可能会有所不同，取决于它们被插入到页面的方式。正如我们所见，有四种主要的方式可以将 SVG 放置到页面上：

+   在`img`标签内部

+   在`object`标签内部

+   作为背景图像

+   内联

并且根据插入方法，某些功能将或将不可用。

要了解每种插入方法应该可能做什么，可能更简单的方法是考虑这个表格。

![您可以使用每种 SVG 插入方法（内联、对象、背景图像和 img）做什么](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_02.jpg)

现在有一些需要考虑的注意事项，用数字标记：

+   ***1**：当在对象内部使用 SVG 时，您可以使用外部样式表来为 SVG 设置样式，但您必须从 SVG 内部链接到该样式表

+   ***2**：您可以在外部资产中使用 SVG（可缓存），但在 Internet Explorer 中默认情况下无法工作

+   ***3**：'内联'的 SVG 中样式部分的媒体查询作用于其所在文档的大小（而不是 SVG 本身的大小）

## 浏览器分歧

请注意，SVG 的浏览器实现也有所不同。因此，仅仅因为上面所示的东西应该是可能的，并不意味着它们实际上在每个浏览器中都会出现，或者它们会表现一致！

例如，上表中的结果是基于`example_07-03`中的测试页面。

测试页面的行为在最新版本的 Firefox、Chrome 和 Safari 中是可比较的。然而，Internet Explorer 有时会做一些不同的事情。

例如，在所有支持 SVG 的 Internet Explorer 版本（目前为止，即 9、10 和 11），正如我们已经看到的，不可能引用外部 SVG 源。此外，Internet Explorer 会将外部样式表中的样式应用到 SVG 上，而不管它们是如何插入的（其他浏览器只有在 SVG 通过`object`或内联方式插入时才应用外部样式表中的样式）。Internet Explorer 也不允许通过 CSS 对 SVG 进行任何动画；在 Internet Explorer 中，SVG 的动画必须通过 JavaScript 完成。我再说一遍，给后排的人听：除了 JavaScript，你无法以任何其他方式在 Internet Explorer 中对 SVG 进行动画。

# 额外的 SVG 功能和奇特之处

让我们暂时抛开浏览器的缺陷，考虑一下表中的一些功能实际上允许什么，以及为什么你可能会或不会想要使用它们。

SVG 将始终以查看设备允许的最清晰方式呈现，而不管插入的方式如何。对于大多数实际情况，分辨率独立通常足以使用 SVG。然后只是选择适合你的工作流程和任务的插入方法的问题。

然而，还有其他一些值得知道的功能和奇特之处，比如 SMIL 动画、不同的链接外部样式表的方式、用字符数据分隔符标记内部样式、用 JavaScript 修改 SVG，以及在 SVG 中使用媒体查询。让我们接下来讨论这些。

## SMIL 动画

SMIL 动画（[`www.w3.org/TR/smil-animation/`](http://www.w3.org/TR/smil-animation/)）是一种在 SVG 文档内部定义动画的方法。

SMIL（如果你想知道，发音为“smile”）代表同步多媒体集成语言，是作为在 XML 文档内定义动画的一种方法而开发的（记住，SVG 是基于 XML 的）。

以下是一个基于 SMIL 的动画的示例：

```html
<g class="star_Wrapper" fill="none" fill-rule="evenodd">
    <animate xlink:href="#star_Path" attributeName="fill" attributeType="XML" begin="0s" dur="2s" fill="freeze" from="#F8E81C" to="#14805e" />

    <path id="star_Path" stroke="#979797" stroke-width="3" fill="#F8E81C" d="M99 154l-58.78 30.902 11.227-65.45L3.894 73.097l65.717-9.55L99 4l29.39 59.55 65.716 9.548-47.553 46.353 11.226 65.452z" />
</g>
```

我抓取了我们之前看过的 SVG 的一部分。`g`是 SVG 中的分组元素，这个元素包括一个星形（`id="star_Path"`的`path`元素）和`animate`元素内的 SMIL 动画。这个简单的动画将星星的填充颜色从黄色变为绿色，持续两秒。而且，无论 SVG 是以`img`、`object`、`background-image`还是内联方式放在页面上（不，真的，除了 Internet Explorer 之外的任何最新浏览器中打开`example_07-03`都可以看到）。

### 注意

**Tweening**

如果你还不知道（我不知道），“tweening”作为一个术语只是“inbetweening”的缩写，因为它仅仅表示从一个动画点到另一个动画点的所有中间阶段。

哇！很棒，对吧？嗯，本来可以的。尽管已经成为标准一段时间，看起来 SMIL 的日子已经不多了。

### SMIL 的结束

Internet Explorer 不支持 SMIL。没有。没有。没有。我可以用其他词语来表达，但我相信你明白在这一点上 Internet Explorer 对 SMIL 的支持并不多。

更糟糕的是（我知道，我在这里给你两个枪口），微软也没有引入它的计划。看看平台状态：[`status.modern.ie/svgsmilanimation?term=SMIL`](https://status.modern.ie/svgsmilanimation?term=SMIL)

此外，Chrome 现在已经表示了在 Chrome 浏览器中弃用 SMIL 的意图：[`groups.google.com/a/chromium.org/forum/#!topic/blink-dev/5o0yiO440LM`](https://groups.google.com/a/chromium.org/forum/#!topic/blink-dev/5o0yiO440LM)

麦克风。放下。

### 注意

如果你仍然需要使用 SMIL，Sara Soueidan 在[`css-tricks.com/guide-svg-animations-smil/`](http://css-tricks.com/guide-svg-animations-smil/)写了一篇关于 SMIL 动画的优秀而深入的文章。

幸运的是，我们有很多其他方法可以使 SVG 动画，我们很快就会介绍。所以如果你必须支持 Internet Explorer，请坚持下去。

## 用外部样式表样式化 SVG

可以用 CSS 样式化 SVG。这可以是 SVG 本身中的 CSS，也可以是 CSS 样式表中写所有你的“正常”CSS。

现在，如果你回到本章前面的特性表，你会发现当 SVG 通过`img`标签或作为背景图像（除了 Internet Explorer）包含时，使用外部 CSS 样式化 SVG 是不可能的。只有当 SVG 通过`object`标签或`inline`插入时才可能。

从 SVG 链接到外部样式表有两种语法。最直接的方式是这样的（你通常会在`defs`部分中添加这个）：

```html
<link href="styles.css" type="text/css" rel="stylesheet"/>
```

这类似于 HTML5 之前我们用来链接样式表的方式（例如，注意在 HTML5 中`type`属性不再是必需的）。然而，尽管这在许多浏览器中有效，但这并不是规范定义外部样式表应该如何在 SVG 中链接的方式（[`www.w3.org/TR/SVG/styling.html`](http://www.w3.org/TR/SVG/styling.html)）。这是正确/官方的方式，实际上在 1999 年就为 XML 定义了（[`www.w3.org/1999/06/REC-xml-stylesheet-19990629/`](http://www.w3.org/1999/06/REC-xml-stylesheet-19990629/)）：

```html
<?xml-stylesheet href="styles.css" type="text/css"?>
```

需要在文件中的开头 SVG 元素上方添加。例如：

```html
<?xml-stylesheet href="styles.css" type="text/css"?>
<svg width="198" height="188" viewBox="0 0 198 188"  >
```

有趣的是，后一种语法是唯一在 Internet Explorer 中有效的。所以，当你需要从 SVG 链接到样式表时，我建议使用这种第二种语法以获得更广泛的支持。

你不必使用外部样式表；如果你愿意，你可以直接在 SVG 本身中使用内联样式。

## 使用内部样式样式化 SVG

你可以在 SVG 中放置 SVG 的样式。它们应该放在`defs`元素内。由于 SVG 是基于 XML 的，最安全的做法是包含**Character Data**（**CDATA**）标记。CDATA 标记简单地告诉浏览器，字符数据定界部分内的信息可能被解释为 XML 标记，但不应该。语法是这样的：

```html
<defs>
    <style type="text/css">
        <![CDATA[
            #star_Path {
                stroke: red;
            }
        ]]>
    </style>
</defs>
```

### CSS 中的 SVG 属性和值

注意前面代码块中的`stroke`属性。那不是 CSS 属性，而是 SVG 属性。无论是内联声明还是外部样式表，你都可以使用许多特定的 SVG 属性。例如，对于 SVG，你不指定`background-color`，而是指定`fill`。你不指定`border`，而是指定`stroke-width`。关于 SVG 特定属性的完整列表，请查看这里的规范：[`www.w3.org/TR/SVG/styling.html`](http://www.w3.org/TR/SVG/styling.html)

使用内联或外部 CSS，可以做所有你期望的“正常”CSS 事情；改变元素的外观，动画，转换元素等等。

## 用 CSS 动画 SVG

让我们考虑一个快速的示例，向 SVG 中添加 CSS 动画（记住，这些样式也可以很容易地放在外部样式表中）。

让我们以本章中一直在看的星星示例为例，让它旋转。你可以在`example_07-07`中看到完成的示例：

```html
<div class="wrapper">
    <svg width="198" height="188" viewBox="0 0 220 200"  >
        <title>Star 1</title>
        <defs>
            <style type="text/css">
                <![CDATA[
                @keyframes spin {
                    0% {
                        transform: rotate(0deg);
                    }
                    100% {
                        transform: rotate(360deg);
                    }
                }
                .star_Wrapper {
                    animation: spin 2s 1s;
                    transform-origin: 50% 50%;
                }
                .wrapper {
                    padding: 2rem;
                    margin: 2rem;
                }
                ]]>
            </style>
            <g id="shape">
                <path fill="#14805e" d="M50 50h50v50H50z"/>
                <circle fill="#ebebeb" cx="50" cy="50" r="50"/>
            </g>
        </defs>
        <g class="star_Wrapper" fill="none" fill-rule="evenodd">
            <path id="star_Path" stroke="#333" stroke-width="3" fill="#F8E81C" d="M99 154l-58.78 30.902 11.227-65.45L3.894 73.097l65.717-9.55L99 4l29.39 59.55 65.716 9.548-47.553 46.353 11.226 65.453z"/>
        </g>
    </svg>
</div>
```

如果你在浏览器中加载这个示例，在 1 秒延迟后，星星将在 2 秒内旋转一整圈。

### 提示

注意 SVG 上设置了`50% 50%`的变换原点？这是因为，与 CSS 不同，SVG 的默认`transform-origin`不是`50% 50%`（两个轴的中心），实际上是`0 0`（左上角）。如果不设置这个属性，星星将围绕左上角旋转。

仅使用 CSS 动画就可以对 SVG 进行相当深入的动画处理（嗯，假设您不需要担心 Internet Explorer）。然而，当您想要添加交互性、支持 Internet Explorer 或同步多个事件时，通常最好依赖 JavaScript。好消息是，有很多优秀的库可以使对 SVG 进行动画处理变得非常容易。现在让我们看一个例子。

# 使用 JavaScript 对 SVG 进行动画处理

通过`object`标签或内联插入到页面中的 SVG，可以直接或间接地使用 JavaScript 来操作 SVG。

间接地，我指的是可以使用 JavaScript 在 SVG 上方或上方更改一个类，从而导致 CSS 动画开始。例如：

```html
svg {
    /* no animation */
}

.added-with-js svg {
    /* animation */
}
```

然而，也可以直接通过 JavaScript 来对 SVG 进行动画处理。

如果只需要独立地对一两个元素进行动画处理，可能通过手动编写 JavaScript 代码来减少代码量。然而，如果需要对许多元素进行动画处理或同步元素的动画处理，就可以使用 JavaScript 库。最终，您需要判断是否可以为您试图实现的目标来合理地包含库的重量。

我推荐使用 GreenSock 动画平台（[`greensock.com`](http://greensock.com)）、Velocity.js（[`julian.com/research/velocity/`](http://julian.com/research/velocity/)）或 Snap.svg（[`snapsvg.io/`](http://snapsvg.io/)）来通过 JavaScript 对 SVG 进行动画处理。在下一个示例中，我们将介绍使用 GreenSock 的一个非常简单的示例。

## 使用 GreenSock 对 SVG 进行动画处理的一个简单示例

假设我们想制作一个界面刻度盘，当我们点击按钮时，它会从零开始动画到我们输入的任意值。我们不仅希望刻度盘的描边在长度和颜色上进行动画处理，还希望数字从零到我们输入的值进行动画处理。您可以在`example_07-08`中查看已完成的实现。

因此，如果我们输入了 75，并点击了动画，它会填充到如下所示：

![使用 GreenSock 对 SVG 进行动画处理的简单示例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_05.jpg)

为了简洁起见，我们不列出整个 JavaScript 文件（该文件有很多注释，因此在单独阅读时应该能够理解一些），我们只考虑关键点。

基本思路是我们已经将一个圆作为 SVG 的`<path>`（而不是`<circle>`元素）制作出来。由于它是一个路径，这意味着我们可以使用`stroke-dashoffset`技术对路径进行动画处理。关于这种技术的更多信息，请参见下面的方框中的部分，简而言之，我们使用 JavaScript 来测量路径的长度，然后使用`stroke-dasharray`属性来指定线条的渲染部分的长度和间隙的长度。然后我们使用`stroke-dashoffset`来改变`dasharray`的起始位置。这意味着您可以有效地从路径的“外部”开始描边并进行动画处理。这会产生路径正在被绘制的错觉。

如果要将`dasharray`的动画值设置为静态的已知值，可以通过 CSS 动画和一些试错来相对简单地实现这种效果（关于 CSS 动画的更多内容将在下一章中介绍）。

然而，除了动态值之外，与我们“绘制”线条的同时，我们还希望将描边颜色从一个值淡入到另一个值，并在文本节点中直观地计数到输入值。这相当于同时摸头、搓肚子，并从 10,000 开始倒数。GreenSock 使这些事情变得非常容易（动画部分；它不会搓你的肚子或摸你的头，尽管如果需要，它可以从 10,000 开始倒数）。以下是使 GreenSock 执行所有这些操作所需的 JavaScript 代码行：

```html
// Animate the drawing of the line and color change
TweenLite.to(circlePath, 1.5, {'stroke-dashoffset': "-"+amount, stroke: strokeEndColour});
// Set a counter to zero and animate to the input value
var counter = { var: 0 };
TweenLite.to(counter, 1.5, {
    var: inputValue, 
    onUpdate: function () {
        text.textContent = Math.ceil(counter.var) + "%";
    },
    ease:Circ.easeOut
});
```

实质上，通过`TweenLite.to()`函数，您可以传入要进行动画处理的对象、动画处理应该发生的时间以及要更改的值（以及您希望将其更改为的值）。

GreenSock 网站有出色的文档和支持论坛，因此如果你发现自己需要同时同步多个动画，请确保从你的日程表中抽出一天的时间，熟悉一下 GreenSock。

### 提示

如果你以前没有接触过 SVG 的“线条绘制”技术，那么它是由 Polygon 杂志推广的，当 Vox Media 动画化了 Xbox One 和 Playstation 4 游戏机的几个线条绘制时。你可以在[`product.voxmedia.com/2013/11/25/5426880/polygon-feature-design-svg-animations-for-fun-and-profit`](http://product.voxmedia.com/2013/11/25/5426880/polygon-feature-design-svg-animations-for-fun-and-profit)上阅读原始帖子。

Jake Archibald 在[`jakearchibald.com/2013/animated-line-drawing-svg/`](http://jakearchibald.com/2013/animated-line-drawing-svg/)上也有一个关于这种技术的更详细的解释。

# 优化 SVG

作为尽职的开发人员，我们希望确保资产尽可能小。使用 SVG 的最简单方法是利用可以优化 SVG 文档的自动化工具。除了明显的节约，比如删除元素（例如，去除标题和描述元素），还可以执行一系列微小的优化，这些优化加起来可以使 SVG 资产更加精简。

目前，对于这个任务，我建议使用 SVGO ([`github.com/svg/svgo`](https://github.com/svg/svgo))。如果你以前从未使用过 SVGO，我建议从 SVGOMG ([`jakearchibald.github.io/svgomg/`](https://jakearchibald.github.io/svgomg/))开始。这是 SVGO 的基于浏览器的版本，它使你可以切换各种优化插件，并即时获得文件节省的反馈。

还记得我们在本章开头的例子星形 SVG 标记吗？默认情况下，这个简单的 SVG 大小为 489 字节。通过 SVGO 处理，可以将大小减小到 218 字节，这还保留了`viewBox`。这是节省了 55.42%。如果你使用了大量的 SVG 图像，这些节省可能会真正累积起来。优化后的 SVG 标记如下所示：

```html
<svg width="198" height="188" viewBox="0 0 198 188" ><path stroke="#979797" stroke-width="3" fill="#F8E81C" d="M99 154l-58.78 30.902 11.227-65.45L3.894 73.097l65.717-9.55L99 4l29.39 59.55 65.716 9.548-47.553 46.353 11.226 65.454z"/></svg>
```

在使用 SVGO 之前，要注意 SVGO 的受欢迎程度，许多其他 SVG 工具也使用它。例如，前面提到的 Iconizr ([`iconizr.com/`](http://iconizr.com/))工具默认情况下会将你的 SVG 文件通过 SVGO 运行，然后再创建你的资产，因此请确保你不会不必要地进行双重优化。

# 使用 SVG 作为滤镜

在第六章中，我们看到了 CSS 滤镜效果。然而，它们目前不受 Internet Explorer 10 或 11 的支持。如果你想在这些浏览器中享受滤镜效果，这可能会让人沮丧。幸运的是，借助 SVG 的帮助，我们也可以创建适用于 Internet Explorer 10 和 11 的滤镜，但正如以往一样，这可能并不像你想象的那样简单。例如，在`example_07-05`中，我们有一个页面，其中包含以下标记：

```html
<img class="HRH" src="img/queen@2x-1024x747.png"/>
```

这是英国女王的一张图片。通常，它看起来是这样的：

![使用 SVG 作为滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_03.jpg)

现在，在示例文件夹中还有一个在`defs`元素中定义了滤镜的 SVG。SVG 标记如下：

```html
<svg  version="1.1">
     <defs>
          <filter id="myfilter" x="0" y="0">  
                <feColorMatrix in="SourceGraphic" type="hueRotate" values="90" result="A"/>
                <feGaussianBlur in="A" stdDeviation="6"/>
          </filter>
     </defs>
</svg>
```

在滤镜中，我们首先定义了一个 90 度的色相旋转（使用`feColorMatrix`），然后通过`result`属性将该效果传递给下一个滤镜（`feGaussianBlur`），模糊值为 6。请注意，我在这里故意做得很重。这不会产生一个好的美学效果，但这应该让你毫无疑问地知道效果已经起作用了！

现在，我们可以不将 SVG 标记添加到 HTML 中，而是将其留在原地，并使用与上一章中看到的相同的 CSS 滤镜语法来引用它。

```html
.HRH {
    filter: url('filter.svg#myfilter');
}
```

在大多数现代浏览器（Chrome，Safari，Firefox）中，这是效果：

![使用 SVG 作为滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_07_04.jpg)

遗憾的是，这种方法在 IE 10 或 11 中不起作用。然而，还有另一种实现我们目标的方法，那就是使用 SVG 自己的图像标签将图像包含在 SVG 中。在`example_07-06`中，我们有以下标记：

```html
<svg height="747px" width="1024px" viewbox="0 0 1024 747"  version="1.1">
     <defs>
          <filter id="myfilter" x="0" y="0">  
                <feColorMatrix in="SourceGraphic" type="hueRotate" values="90" result="A"/>
                <feGaussianBlur in="A" stdDeviation="6"/>
          </filter>
     </defs>
     <image x="0" y="0" height="747px" width="1024px"  xlink:href="queen@2x-1024x747.png" filter="url(#myfilter)"></image>
</svg>
```

这里的 SVG 标记与我们在上一个示例中使用的外部`filter.svg`过滤器非常相似，但添加了`height`、`width`和`viewbox`属性。此外，我们要对其应用过滤器的图像是 SVG 中`defs`元素之外的唯一内容。为了链接到过滤器，我们使用`filter`属性并传递我们想要使用的过滤器的 ID（在这种情况下是在上面的`defs`元素中）。

虽然这种方法有点复杂，但它意味着你可以获得 SVG 提供的许多不同的滤镜效果，即使在 Internet Explorer 的 10 和 11 版本中也是如此。

# 关于 SVG 中的媒体查询的说明

所有理解 SVG 的浏览器都应该尊重 SVG 内定义的 CSS 媒体查询。然而，当涉及到 SVG 内的媒体查询时，有一些事情需要记住。

例如，假设你在 SVG 中插入了一个媒体查询，就像这样：

```html
<style type="text/css"><![CDATA[
    #star_Path {
        stroke: red;
    }
    @media (min-width: 800px) {
        #star_Path {
            stroke: violet;
        }
    }
]]></style>
```

而 SVG 在页面上以 200px 的宽度显示，而视口宽度为 1200px。

我们可能期望星星的描边在屏幕宽度为 800px 及以上时是紫色的。毕竟，这就是我们设置媒体查询的方式。然而，当 SVG 通过`img`标签、作为背景图像或嵌入`object`标签放置在页面中时，它对外部 HTML 文档一无所知。因此，在这种情况下，`min-width`意味着 SVG 本身的最小宽度。因此，除非 SVG 本身在页面上以 800px 或更多的宽度显示，否则描边不会是紫色的。

相反，当你内联插入 SVG 时，它会（在某种意义上）与外部 HTML 文档合并。这里的`min-width`媒体查询是根据视口（就像 HTML 一样）来决定何时匹配媒体查询。

为了解决这个特定的问题并使相同的媒体查询行为一致，我们可以修改我们的媒体查询为：

```html
@media (min-device-width: 800px) {
    #star_Path {
        stroke: violet;
    }
}
```

这样，无论 SVG 的大小或嵌入方式如何，它都会根据设备宽度（实际上是视口）进行调整。

## 实施提示

现在我们几乎到了本章的结尾，还有很多关于 SVG 的内容可以讨论。因此，这时我只列出一些无关的注意事项。它们不一定值得详细解释，但我会在这里列出它们的笔记形式，以防它们能让你省去一小时的谷歌搜索：

+   如果你不需要为 SVG 添加动画，可以选择使用图像精灵或数据 URI 样式表。这样更容易提供回退资产，并且从性能的角度来看，它们几乎总是表现更好。

+   尽可能自动化资产创建过程中的许多步骤；这样可以减少人为错误，并更快地产生可预测的结果。

+   要在项目中插入静态 SVG，尽量选择一种交付机制并坚持使用（图像精灵、数据 URI 或内联）。如果以一种方式生成一些资产，以另一种方式生成其他资产，并维护各种实现，这可能会成为负担。

+   SVG 动画没有一个简单的“一刀切”的选择。对于偶尔和简单的动画，使用 CSS。对于复杂的交互式或时间轴样式的动画，还可以在 Internet Explorer 中工作，依赖于像 Greensock、Velocity.js 或 Snap.svg 这样的成熟库。

## 进一步的资源

正如我在本章开头提到的，我既没有空间，也没有知识来传授关于 SVG 的所有知识。因此，我想让你了解以下优秀的资源，它们提供了关于这个主题的额外深度和范围：

+   *SVG Essentials, 2nd Edition* by J. David Eisenberg, Amelia Bellamy-Royds ([`shop.oreilly.com/product/0636920032335.do`](http://shop.oreilly.com/product/0636920032335.do))

+   *Sara Soueidan 的《SVG 动画指南（SMIL）*（[`css-tricks.com/guide-svg-animations-smil/`](http://css-tricks.com/guide-svg-animations-smil/)）

+   *Jeremie Patonnier 的《SVG 内部媒体查询测试*（[`jeremie.patonnier.net/experiences/svg/media-queries/test.html`](http://jeremie.patonnier.net/experiences/svg/media-queries/test.html)）

+   *今天浏览器的 SVG 入门*（[`www.w3.org/Graphics/SVG/IG/resources/svgprimer.html`](http://www.w3.org/Graphics/SVG/IG/resources/svgprimer.html)）

+   *Sara Soueidan 的《理解 SVG 坐标系和变换（第一部分）*（[`sarasoueidan.com/blog/svg-coordinate-systems/`](http://sarasoueidan.com/blog/svg-coordinate-systems/)）

+   *《SVG 滤镜效果实践》*（[`ie.microsoft.com/testdrive/graphics/hands-on-css3/hands-on_svg-filter-effects.htm`](http://ie.microsoft.com/testdrive/graphics/hands-on-css3/hands-on_svg-filter-effects.htm)）

+   Jakob Jenkov 的完整 SVG 教程*（[`tutorials.jenkov.com/svg/index.html`](http://tutorials.jenkov.com/svg/index.html)）

# 总结

在本章中，我们已经涵盖了许多必要的信息，以便开始理解和实施响应式项目中的 SVG。我们考虑了不同的图形应用程序和在线解决方案，以创建 SVG 资产，然后考虑了可能的各种插入方法以及每种方法允许的功能，以及需要注意的各种浏览器特性。

我们还考虑了如何链接到外部样式表，并在同一页面内重复使用 SVG 符号以及在外部引用时。我们甚至研究了如何使用 SVG 制作可以在 CSS 中引用和使用的滤镜，以获得比 CSS 滤镜更广泛的支持。

最后，我们考虑了如何利用 JavaScript 库来帮助动画化 SVG，以及如何借助 SVGO 工具优化 SVG。

在下一章中，我们将研究 CSS 过渡、变换和动画。与 SVG 相关的语法和技术中有许多可以在 SVG 文档中使用和应用的内容，因此也值得阅读该章节。所以，来杯热饮（你值得拥有），我马上就会再见到你。


# 第八章：过渡，变换和动画

在历史上，每当需要移动或在屏幕上动画元素时，这完全是 JavaScript 的专属领域。如今，CSS 可以通过三个主要代理来处理大部分运动工作：CSS 过渡，CSS 变换和 CSS 动画。实际上，只有过渡和动画与运动直接相关，变换只是允许我们改变元素，但正如我们将看到的那样，它们经常是成功运动效果的不可或缺的部分。

为了清楚地理解每个事物的责任，我将提供这个可能过于简化的总结：

+   当您已经有要应用运动的事物的起始状态和结束状态，并且需要一种简单的方法从一个状态过渡到另一个状态时，请使用 CSS 过渡。

+   如果您需要在不影响页面布局的情况下在视觉上转换项目，请使用 CSS 变换。

+   如果您想要在不同的关键点上对元素执行一系列更改，请使用 CSS 动画。

好了，我们最好继续努力，了解如何运用所有这些能力。在本章中，我们将涵盖：

+   CSS3 过渡是什么以及我们如何使用它们

+   如何编写 CSS3 过渡及其简写语法

+   CSS3 过渡时间函数（`ease`，`cubic-bezier`等）

+   响应式网站的有趣过渡效果

+   CSS3 变换是什么以及我们如何使用它们

+   理解不同的 2D 变换（`缩放`，`旋转`，`倾斜`，`平移`等）

+   理解 3D 变换

+   如何使用`keyframes`和 CSS3 进行动画

# CSS3 过渡是什么以及我们如何使用它们

过渡是使用 CSS 创建一些视觉“效果”的最简单方法，用于在一个状态和另一个状态之间进行过渡。让我们考虑一个简单的例子，当悬停时，一个元素从一个状态过渡到另一个状态。

在 CSS 中为超链接设置样式时，常见做法是创建悬停状态；这是一种明显的方式，可以让用户意识到他们悬停在的项目是一个链接。悬停状态对于越来越多的触摸屏设备来说并不重要，但对于鼠标用户来说，它们是网站和用户之间的一个很好且简单的交互。它们也很方便用于说明过渡效果，这就是我们将要开始的地方。

传统上，仅使用 CSS，悬停状态是一个开/关的事情。元素上有一组默认的属性和值，当指针悬停在该元素上时，属性和值会立即更改。然而，正如其名称所示，CSS3 过渡允许我们在一个或多个属性和值之间过渡到其他属性和值。

### 提示

首先要知道的是，您不能从`display: none;`进行过渡。当某物设置为`display: none;`时，它实际上没有在屏幕上“绘制”，因此没有现有状态可以进行过渡。为了创建某物淡入的效果，您必须过渡不透明度或位置值。其次，并非所有属性都可以进行过渡。为了确保您不会尝试不可能的事情，这是可过渡的属性列表：[`www.w3.org/TR/css3-transitions/`](http://www.w3.org/TR/css3-transitions/)

如果您打开`example_08-01`，您会看到`nav`中有一些链接。以下是相关的标记：

```html
<nav>
    <a href="#">link1</a>
    <a href="#">link2</a>
    <a href="#">link3</a>
    <a href="#">link4</a>
    <a href="#">link5</a>
</nav>
```

这是相关的 CSS：

```html
a {
    font-family: sans-serif;
    color: #fff;
    text-indent: 1rem;
    background-color: #ccc;
    display: inline-flex;
    flex: 1 1 20%;
    align-self: stretch;
    align-items: center;
    text-decoration: none;
    transition: box-shadow 1s;
}

a + a {
    border-left: 1px solid #aaa;
}

a:hover {
    box-shadow: inset 0 -3px 0 #CC3232;
}
```

这是两种状态，首先是默认状态：

![CSS3 过渡是什么以及我们如何使用它们](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_01.jpg)

然后这是悬停状态：

![CSS3 过渡是什么以及我们如何使用它们](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_02.jpg)

在这个例子中，当链接悬停时，我们在底部添加了一个红色的阴影（我选择了一个阴影，因为它不会像边框一样影响链接的布局）。通常，悬停在链接上会从第一个状态（没有红线）转换到第二个状态（红线）；这是一个开/关的事情。然而，这一行：

```html
transition: box-shadow 1s;
```

将`box-shadow`从现有状态过渡到悬停状态，持续 1 秒。

### 提示

你会注意到在前面示例的 CSS 中，我们使用了相邻兄弟选择器`+`。这意味着如果一个选择器（在我们的示例中是锚点标签）直接跟在另一个选择器（另一个锚点标签）后面，那么应用封闭的样式。这在这里很有用，因为我们不希望第一个元素有左边框。

请注意，过渡属性应用于元素的原始状态，而不是元素最终的状态。简而言之，在“from”状态上应用过渡声明，而不是“to”状态。这样不同的状态，比如`:active`，也可以有不同的样式设置，并享受相同的过渡。

## 过渡的属性

可以使用最多四个属性声明过渡：

+   `transition-property`：要过渡的 CSS 属性的名称（例如`background-color`、`text-shadow`或`all`以过渡每个可能的属性）。

+   `transition-duration`：过渡应该发生的时间长度（以秒为单位，例如`.3s`、`2s`或`1.5s`）。

+   `transition-timing-function`：过渡在持续时间内如何改变速度（例如`ease`、`linear`、`ease-in`、`ease-out`、`ease-in-out`或`cubic-bezier`）。

+   `transition-delay`：确定过渡开始之前的延迟的可选值。或者，可以使用负值立即开始过渡，但在过渡的“旅程”中间。它以秒为单位，例如`.3s`、`1s`或`2.5s`。

单独使用，各种过渡属性可以创建这样的过渡：

```html
.style {
    /*...(more styles)...*/
    transition-property: all;
    transition-duration: 1s;
    transition-timing-function: ease;
    transition-delay: 0s;
}
```

## 过渡的简写属性

我们可以将这些单独的声明合并成一个简写版本：

```html
transition: all 1s ease 0s;
```

在写简写版本时要注意的一个重要点是，给出的第一个与时间相关的值总是被视为`transition-duration`。第二个与时间相关的值被视为`transition-delay`。我通常更喜欢简写版本，因为我通常只需要定义过渡的持续时间和应该过渡的属性。

这只是一个小问题，但是只定义你实际需要过渡的属性。只设置`all`非常方便，但如果你只需要过渡不透明度，那么只定义不透明度作为过渡属性。否则，你会让浏览器比必要的工作更加艰难。在大多数情况下，这并不是什么大问题，但是如果你希望在老设备上尽可能地提高性能，那么每一点都有帮助。

### 提示

过渡非常受支持，但是要确保你有像 Autoprefixer 这样的工具设置好，以添加任何与你需要支持的浏览器相关的供应商前缀。你也可以在[caniuse.com](http://caniuse.com)上检查哪些浏览器支持各种功能。

**简写版本：**

过渡和 2D 变换在 IE9 及以下版本之外都可以工作，3D 变换在 IE9 及以下版本、Android 2.3 及以下版本以及 Safari 3.2 及以下版本之外都可以工作。

## 在不同的时间段内过渡不同的属性

当一个规则有多个声明的属性时，你不必以相同的方式过渡所有这些属性。考虑这条规则：

```html
.style {
    /* ...(more styles)... */
    transition-property: border, color, text-shadow;
    transition-duration: 2s, 3s, 8s; 
}
```

在这里，我们已经指定了我们希望过渡`border`、`color`和`text-shadow`的`transition-property`。然后在`transition-duration`声明中，我们规定了边框应该在 2 秒内过渡，颜色在 3 秒内过渡，文本阴影在 8 秒内过渡。逗号分隔的持续时间与逗号分隔的过渡属性的顺序相匹配。

## 理解时间函数

当你声明一个过渡时，属性、持续时间和延迟相对简单理解。然而，理解每个时间函数的作用可能会有点棘手。`ease`、`linear`、`ease-in`、`ease-out`、`ease-in-out`和`cubic-bezier`到底是什么？它们实际上都是预定义的三次贝塞尔曲线，本质上与缓动函数相同。或者更简单地说，这是过渡应该如何呈现的数学描述。通常更容易可视化这些曲线，所以我建议你去[`cubic-bezier.com/`](http://cubic-bezier.com/)和[`easings.net/`](http://easings.net/)看一看。

这两个网站都可以让你比较时间函数，并看到每个时间函数的区别。这是[`easings.net`](http://easings.net)的截图——你可以悬停在每条线上演示缓动函数。

![理解时间函数](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_19.jpg)

然而，即使你能闭着眼睛写出自己的三次贝塞尔曲线，对于大多数实际情况来说，这可能并没有太大的区别。原因是，像任何增强功能一样，必须谨慎地使用过渡效果。对于“真实世界”的实现，过长的过渡时间会让网站感觉缓慢。例如，需要 5 秒才能完成过渡的导航链接会让用户感到沮丧，而不是惊叹。速度的感知对我们的用户非常重要，你和我必须集中精力让网站和应用程序尽可能地快。

因此，除非有充分的理由这样做，通常最好在短时间内使用默认的过渡（ease）；我个人偏好最长 1 秒。

## 响应式网站的有趣过渡效果

你是否在成长过程中有过这样的情况，一个父母出门了，另一个父母说了类似这样的话：“好吧，你妈妈/爸爸出门了，我们要在你的早餐麦片上撒满糖，但你要答应他们回来后不告诉他们”？我肯定对我的孩子们做过这样的事。所以这样吧，趁没人注意，让我们玩一点。我不建议在生产中这样做，但是尝试将这个添加到你的响应式项目中。

```html
* {
    transition: all 1s; 
}
```

在这里，我们使用 CSS 通用选择器`*`选择所有内容，然后为所有属性设置 1 秒的过渡时间（1s）。由于我们没有指定时间函数，因此默认情况下将使用 ease，并且如果没有添加替代值，则默认为 0 延迟。效果如何？嗯，尝试调整浏览器窗口大小，大多数东西（链接、悬停状态等）的行为都如你所期望的那样。然而，因为一切都在过渡，这也包括媒体查询中的任何规则，因此随着浏览器窗口的调整，元素会从一种状态流动到另一种状态。这是必要的吗？绝对不是！但是看起来很有趣，可以玩一下！现在，在你妈妈看到之前，删除这条规则！

# CSS3 2D 变换

尽管听起来相似，但 CSS 变换与 CSS 过渡完全不同。可以这样理解：过渡使元素从一种状态平滑地转换到另一种状态，而变换则定义了元素实际上会变成什么样。我自己（虽然有点幼稚）记住这个区别的方式是这样的：想象一个变形金刚机器人，比如大黄蜂。当他变成卡车时，他已经变形了。然而，从机器人到卡车的过程是一个过渡（他正在从一种状态过渡到另一种状态）。

显然，如果你根本不知道奥普蒂默斯·普莱姆是谁或是什么，可以随意忽略最后几句。希望一切很快就会变得清晰起来。

有两组可用的 CSS3 变换：2D 和 3D。 2D 变体在浏览器方面得到了更广泛的实现，并且肯定更容易编写，所以让我们首先看看这些。 CSS3 2D 变换模块允许我们使用以下变换：

+   `缩放`：用于缩放元素（放大或缩小）

+   `平移`：在屏幕上移动元素（上，下，左和右）

+   `rotate`：按指定的角度旋转元素

+   `倾斜`：用于倾斜具有其 x 和 y 坐标的元素

+   `矩阵`：允许您以像素精度移动和形状变换

### 提示

重要的是要记住，变换发生在文档流之外。 任何被转换的元素都不会影响附近未被转换的元素的位置。

让我们尝试各种 2D 转换。 您可以通过在浏览器中打开`example_08-02`来测试这些转换中的每一个。 对所有变换应用了过渡，因此您可以更好地了解发生了什么。

## 缩放

这是`scale`的语法：

```html
.scale:hover {
    transform: scale(1.4);
}
```

在我们的示例中悬停在“缩放”链接上会产生这种效果：

![缩放](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_03.jpg)

我们告诉浏览器，当悬停在此元素上时，我们希望元素的比例放大到原始值的 1.4 倍。

除了我们已经用来放大元素的值之外，通过使用小于 1 的值，我们可以缩小元素； 以下将使元素缩小到其一半大小：

```html
transform: scale(0.5);
```

## 翻译

这是`translate`的语法：

```html
.translate:hover {
    transform: translate(-20px, -20px);
}
```

这是我们的示例中该规则的效果：

![翻译](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_06.jpg)

`translate`属性告诉浏览器按指定的像素或百分比移动元素。 第一个值是*x*轴，第二个值是*y*轴。 括号中给出的正值将使元素向右或向下移动； 负值将使其向左或向上移动。

如果只传递一个值，则应用于*x*轴。 如果要指定一个轴来平移元素，还可以使用`translateX`或`translateY`。

### 使用 translate 将绝对定位的元素居中

`translate`提供了一种非常有用的方法，可以在相对定位的容器内居中绝对定位的元素。 您可以在`example_08-03`中查看此示例。

考虑以下标记：

```html
<div class="outer">
    <div class="inner"></div>
</div>
```

然后是这个 CSS：

```html
.outer {
    position: relative;
    height: 400px;
    background-color: #f90;
}

.inner {
    position: absolute;
    height: 200px;
    width: 200px;
    margin-top: -100px;
    margin-left: -100px;
    top: 50%;
    left: 50%;
}
```

您可能自己做过类似的事情。 当绝对定位元素的尺寸已知（在这种情况下为 200px x 200px）时，我们可以使用负边距将项目“拉回”到中心。 但是，当您想要包含内容并且无法知道其高度时会发生什么？ 变换来拯救。

让我们在内部框中添加一些随机内容：

![使用 translate 将绝对定位的元素居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_04.jpg)

是的，就是那个问题！ 好吧，让我们使用`transform`来解决这个问题。

```html
.inner {
    position: absolute;
    width: 200px;
    background-color: #999;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
}
```

以下是结果：

![使用 translate 将绝对定位的元素居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_05.jpg)

在这里，`top`和`left`定位内部框在其容器内，使内部框的左上角从外部向下 50%处和向右 50%处开始。 然后`transform`在内部元素上起作用，并通过其自身宽度和高度的一半（-50%）在这些轴上定位。 很好！

## 旋转

`rotate`变换允许您旋转元素。 这是语法：

```html
.rotate:hover {
    transform: rotate(30deg);
}
```

在浏览器中，发生了什么：

![旋转](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_07.jpg)

括号中的值应始终为度数（例如，90 度）。 正值始终顺时针应用，使用负值将使元素逆时针旋转。 您还可以通过指定以下值来使元素旋转：

```html
transform: rotate(3600deg);
```

这将使元素在一个完整的圆圈中旋转 10 次。 对于这个特定值的实际用途很少，但是您知道，如果您发现自己为风车公司设计网站，它可能会派上用场。

## 倾斜

如果您在 Photoshop 中工作过一段时间，您可能对`skew`会做什么有一个很好的想法。它允许元素在其一个或两个轴上倾斜。这是我们示例的代码：

```html
.skew:hover {
    transform: skew(40deg, 12deg);
}
```

将其设置为悬停链接会产生以下悬停效果：

![倾斜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_08.jpg)

第一个值是应用于*x*轴的`skew`（在我们的示例中为 40 度），而第二个值（12 度）是应用于*y*轴的。省略第二个值意味着任何值仅仅应用于*x*轴（水平）。例如：

```html
transform: skew(10deg);
```

## 矩阵

有人提到了一部被高估的电影吗？没有？什么？你想了解 CSS3 矩阵，而不是电影？好的。

我不会撒谎。我觉得矩阵变换语法看起来很可怕。这是我们的示例代码：

```html
.matrix:hover {
    transform: matrix(1.678, -0.256, 1.522, 2.333, -51.533, -1.989);
}
```

它基本上允许您将许多其他变换（`scale`、`rotate`、`skew`等）组合成一个声明。前面的声明会在浏览器中产生以下效果：

![矩阵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_09.jpg)

现在，我喜欢挑战，就像其他人一样（除非，你知道，是坐在*暮光之城*电影里），但我相信我们可以一致同意这个语法有点考验。对我来说，当我看规范并意识到它涉及超出我基本水平的数学知识时，情况变得更糟：[`www.w3.org/TR/css3-2d-transforms/`](http://www.w3.org/TR/css3-2d-transforms/)

### 提示

如果您发现自己在 JavaScript 中进行动画工作而没有动画库的帮助，您可能需要更加熟悉矩阵。它是所有其他变换计算出的语法，因此如果您使用 JavaScript 获取动画的当前状态，您需要检查和理解的将是矩阵值。

### 作弊者和蠢蛋的矩阵变换

我绝对不是数学家，所以当需要创建基于矩阵的变换时，我会作弊。如果您的数学技能也不足，我建议您前往[`www.useragentman.com/matrix/`](http://www.useragentman.com/matrix/)。

Matrix Construction Set 网站允许您将元素拖放到您想要的位置，然后在 CSS 文件中包括好的复制和粘贴代码（包括供应商前缀）。

## transform-origin 属性

请注意，使用 CSS 时，默认的变换原点（浏览器用作变换中心的点）位于中间：元素的*x*轴和*y*轴上分别为 50%。这与 SVG 不同，后者默认为左上角（或 0 0）。

使用`transform-origin`属性，我们可以修改变换的起始点。

考虑我们之前的矩阵变换。默认的`transform-origin`是'50% 50%'（元素的中心）。Firefox 开发者工具显示了`transform`是如何应用的：

![transform-origin 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_10.jpg)

现在，如果我们像这样调整`transform-origin`：

```html
.matrix:hover {
   transform: matrix(1.678, -0.256, 1.522, 2.333, -51.533, -1.989);
   transform-origin: 270px 20px;
}
```

然后你可以看到这样的效果：

![transform-origin 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_11.jpg)

第一个值是水平偏移，第二个值是垂直偏移。您可以使用关键字。例如，left 等于 0%水平，right 等于 100%水平，top 等于 0%垂直，bottom 等于 100%垂直。或者，您可以使用长度，使用任何 CSS 长度单位。

如果您在`transform-origin`值中使用百分比，则水平/垂直偏移是相对于元素边界框的高度/宽度的。

如果您使用长度，则值是从元素边界框的左上角开始测量的。

有关`transform-origin`属性的完整信息可以在[`www.w3.org/TR/css3-2d-transforms/`](http://www.w3.org/TR/css3-2d-transforms/)找到。

这涵盖了 2D 变换的基本知识。它们比它们的 3D 兄弟更广泛地实现，并提供了一个比旧方法（如绝对定位）更好的移动元素在屏幕上的方法。

阅读 CSS3 2D Transforms Module Level 3 的完整规范，请访问[`www.w3.org/TR/css3-2d-transforms/`](http://www.w3.org/TR/css3-2d-transforms/)。

### 提示

有关使用`transform`移动元素的好处，请参阅 Paul Irish 的一篇很棒的文章（[`www.paulirish.com/2012/why-moving-elements-with-translate-is-better-than-posabs-topleft/`](http://www.paulirish.com/2012/why-moving-elements-with-translate-is-better-than-posabs-topleft/)），其中提供了一些很好的数据。

此外，关于浏览器如何处理过渡和动画，以及变换为何如此有效的概述，我强烈推荐阅读以下博客文章：[`blogs.adobe.com/webplatform/2014/03/18/css-animations-and-transitions-performance/`](http://blogs.adobe.com/webplatform/2014/03/18/css-animations-and-transitions-performance/)

# CSS3 3D transformations

让我们看看我们的第一个示例。当我们悬停在元素上时翻转的元素。我在这里使用悬停来调用更改，因为这对于说明来说很简单，然而翻转动作也可以通过类更改（通过 JavaScript）或当元素获得焦点时轻松地启动。

我们将有两个这样的元素；一个是水平翻转元素，一个是垂直翻转元素。您可以在`example_08-04`中查看最终示例。图片无法完全传达这种技术，但想法是元素从绿色“面”翻转到红色“面”，并在透视的帮助下产生在 3D 空间中进行翻转的错觉。这是从绿色到红色过渡的一部分效果。

![CSS3 3D transformations](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_12.jpg)

### 提示

值得知道的是，虽然使用 top/left/bottom/right 值绝对定位元素是以像素为单位的，但变换可以在亚像素位置进行插值。

以下是翻转元素的标记：

```html
<div class="flipper">
    <span class="flipper-object flipper-vertical">
        <span class="panel front">The Front</span>
        <span class="panel back">The Back</span>
    </span>
</div>
```

水平翻转元素的唯一区别是标记上的`flipper-horizontal`类，而不是`flipper-vertical`。

由于大多数样式与美学有关，我们只会看一下样式中使翻转效果成为可能的基本要素。有关美学样式，请参考示例中的完整样式表。

首先，我们需要为`.flipper-object`设置一些透视，以便在其中进行翻转。为此，我们使用`perspective`属性。这需要一个长度，试图模拟观看者屏幕到元素 3D 空间边缘的距离。

如果您设置了一个低值，比如 20px 作为透视值，元素的 3D 空间将延伸到距离屏幕仅 20px 的地方；结果是非常明显的 3D 效果。另一方面，设置一个高值将意味着那个想象的 3D 空间的边缘将更远，因此产生一个不太明显的 3D 效果。

```html
.flipper {
    perspective: 400px;
    position: relative;
}
```

我们将相对定位外部元素，以创建`flipper-object`在其中定位的上下文：

```html
.flipper-object {
    position: absolute;
    transition: transform 1s;
    transform-style: preserve-3d;
}
```

除了将`.flipper-object`绝对定位在其最近的相对定位的父元素的左上角（绝对定位元素的默认位置）之外，我们还为变换设置了一个过渡。在 3D 方面，关键的是`transform-styles: preserve-3d`。这告诉浏览器，当我们变换这个元素时，我们希望任何子元素都保持 3D 效果。

如果我们没有在`.flipper-object`上设置`preserve-3d`，我们将永远看不到翻转元素的背面（红色部分）。您可以在[`www.w3.org/TR/2009/WD-css3-3d-transforms-20090320/`](http://www.w3.org/TR/2009/WD-css3-3d-transforms-20090320/)上阅读此属性的规范。

我们翻转元素中的每个“面板”都需要定位在其容器的顶部，但我们也希望确保如果旋转了，我们不会看到它的“后面”（否则我们永远看不到绿色面板，因为它位于红色面板的“后面”）。为此，我们使用`backface-visibility`属性。我们将其设置为隐藏，以便元素的背面被隐藏：

```html
.panel {
    top: 0;
    position: absolute;
    backface-visibility: hidden;
}
```

### 提示

我发现`backface-visibility`在一些浏览器中实际上有一些令人惊讶的副作用。它特别适用于改善旧版 Android 设备上固定位置元素的性能。有关更多信息以及它为什么会产生这种效果，请查看这篇文章：[`benfrain.com/easy-css-fix-fixed-positioning-android-2-2-2-3/`](http://benfrain.com/easy-css-fix-fixed-positioning-android-2-2-2-3/)和这篇文章：[`benfrain.com/improving-css-performance-fixed-position-elements/`](http://benfrain.com/improving-css-performance-fixed-position-elements/)

接下来，我们希望默认情况下翻转我们的后面板（这样当我们翻转整个东西时，它实际上会处于正确的位置）。为此，我们应用了`rotate`变换：

```html
.flipper-vertical .back {
    transform: rotateX(180deg);
}

.flipper-horizontal .back {
    transform: rotateY(180deg);
}
```

现在一切都就绪，我们要做的就是在悬停在外部元素上时翻转整个内部元素：

```html
.flipper:hover .flipper-vertical {
    transform: rotateX(180deg);
}

.flipper:hover .flipper-horizontal {
    transform: rotateY(180deg);
}
```

您可以想象有无数种方式可以使用这些原则。如果您想知道带有一点透视效果的花哨导航效果或离屏菜单可能会是什么样子，我强烈建议您访问 Codrops：[`tympanus.net/Development/PerspectivePageViewNavigation/index.html`](http://tympanus.net/Development/PerspectivePageViewNavigation/index.html)。

### 提示

阅读有关 CSS Transforms Module Level 1 的最新 W3C 发展情况：[`dev.w3.org/csswg/css-transforms/`](http://dev.w3.org/csswg/css-transforms/)。

## transform3d 属性

除了使用透视，我还发现`transform3d`值非常有用。通过单个属性和值，这允许您在 X（左/右）、Y（上/下）和 Z（前/后）轴上移动元素。让我们修改我们的最后一个示例，利用`translate3d`变换。您可以在`example_08-06`中查看此示例。

除了用一点填充设置元素外，我们的上一个示例的唯一变化可以在这里看到：

```html
.flipper:hover .flipper-vertical {
    transform: rotateX(180deg) translate3d(0, 0, -120px);
    animation: pulse 1s 1s infinite alternate both;
}

.flipper:hover .flipper-horizontal {
    transform: rotateY(180deg) translate3d(0, 0, 120px);
    animation: pulse 1s 1s infinite alternate both;
}
```

我们仍然应用变换，但这次，除了我们的旋转之外，我们还添加了`translate3d`。您可以传递给`translate3d`的逗号分隔的“参数”的语法是*x*轴移动、*y*轴移动和*z*轴移动。

在我们的两个示例中，我没有在*x*或*y*轴（左右和上下）移动元素，而是向您移动或远离您。

如果您查看顶部示例，您会看到它在底部按钮后面翻转，并最终离屏幕更近 120 像素（负值实际上将其向您拉回）。

![transform3d 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_12.jpg)

另一方面，底部按钮水平翻转，最终距离您 120 像素。

![transform3d 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_13.jpg)

### 提示

您可以在[`www.w3.org/TR/css3-3d-transforms/`](http://www.w3.org/TR/css3-3d-transforms/)阅读`translate3d`的规范。

### 使用渐进增强的转换

我发现`transform3d`最有用的地方是在屏幕上滑动面板，特别是“离屏”导航模式。如果你打开`example_08-07`，你会看到我创建了一个基本的、逐步增强的离屏模式。

每当您使用 JavaScript 和现代 CSS 功能（如变换）创建交互时，考虑从您想要支持的最低可能设备的角度是有意义的。那么那两个没有 JavaScript 的人怎么办（是的，那些家伙），或者如果 JavaScript 加载或执行时出现问题怎么办？如果某人的设备不支持变换（例如 Opera Mini）怎么办？别担心，通过一点努力，可以确保每种情况下都有一个可用的界面。

在构建这种界面模式时，我发现从最低级别的功能开始，并从那里进行增强是最有用的。因此，首先确定如果没有 JavaScript 可用，某人会看到什么。毕竟，如果显示菜单的方法依赖于 JavaScript，将菜单停放在屏幕外是没有用的。在这种情况下，我们依赖于标记来将导航区域放在正常的文档流中。最坏的情况是，无论视口宽度如何，他们只需滚动页面并点击链接即可：

![使用渐进增强的变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_15.jpg)

如果 JavaScript 可用，对于较小的屏幕，我们将菜单“拉”到左侧。当单击菜单按钮时，我们在`body`标签上添加一个类（使用 JavaScript），并使用这个类作为钩子，通过 CSS 将导航移回视图中。

![使用渐进增强的变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_16.jpg)

对于较大的视口，我们隐藏菜单按钮，仅将导航定位到左侧，并移动主要内容以适应。

![使用渐进增强的变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_17.jpg)

然后我们逐步增强导航显示/隐藏效果。这就是像 Modernizr 这样的工具真正发挥作用的地方；通过向 HTML 标签添加类，我们可以用作样式钩子（Modernizr 在第五章中有更详细的讨论，“CSS3 – 选择器、排版、颜色模式和新功能”）。

首先，对于只支持 translate 变换的浏览器（例如旧版 Android），简单的`translateX`：

```html
.js .csstransforms .navigation-menu {
    left: auto;
    transform: translateX(-200px);
}
```

对于支持`translate3d`的浏览器，我们使用`translate3d`。在支持的情况下，这将表现得更好，因为大多数设备上的图形处理器会卸载它：

```html
.js .csstransforms3d .navigation-menu {
    left: auto;
    transform: translate3d(-200px, 0, 0);
}
```

采用渐进增强方法可以确保尽可能广泛的受众能够从您的设计中获得可用的体验。记住，用户不需要视觉一致性，但他们可能会欣赏功能一致性。

# 使用 CSS3 进行动画制作

如果你曾经使用过 Flash、Final Cut Pro 或 After Effects 等应用程序，那么在使用 CSS3 动画时，你会立即获得优势。CSS3 采用了时间轴应用程序中找到的动画关键帧约定。

动画广泛实现；在 Firefox 5+、Chrome、Safari 4+、Android（所有版本）、iOS（所有版本）和 Internet Explorer 10+中都受支持。CSS3 动画有两个组成部分；首先是`keyframes`声明，然后在`animation`属性中使用该`keyframes`声明。让我们来看看。

在之前的示例中，我们对结合变换和过渡的元素进行了简单的翻转效果。让我们将本章学到的所有技术结合起来，并为之前的示例添加动画。在下一个示例中，`example_08-05`，让我们在元素翻转后添加一个脉动动画效果。

首先，我们将创建一个`keyframes` at-rule：

```html
@keyframes pulse {
  100% {
    text-shadow: 0 0 5px #bbb;
    box-shadow: 0 0 3px 4px #bbb;
  }
}
```

如您所见，在编写`@keyframes`来定义新的`keyframes` at-rule 后，我们为这个特定的动画命名（在这种情况下是 pulse）。

通常最好使用代表动画功能的名称，而不是你打算在哪里使用动画的名称，因为单个`@keyframes`规则可以在项目中使用多次。

在这里，我们使用了一个单一的关键帧选择器：100%。但是，在`keyframes`规则中，您可以设置尽可能多的关键帧选择器（定义为百分比点）。将这些想象成时间轴上的点。例如，在 10%处，使背景变蓝，在 30%处，使背景变紫，在 60%处，使元素半透明。您需要多少就设置多少。还有关键字 from，相当于 0%，to，相当于 100%。您可以这样使用它们：

```html
@keyframes pulse {
  to {
    text-shadow: 0 0 5px #bbb;
    box-shadow: 0 0 3px 4px #bbb;
  }
}
```

但是要注意，WebKit 浏览器（iOS，Safari）并不总是对 from 和 to 值（更喜欢 0%和 100%）很友好，所以我建议坚持使用百分比关键帧选择器。

在这里，您会注意到我们没有费心定义起点。那是因为起点是每个属性已经处于的状态。这是规范的一部分，解释了这一点：[`www.w3.org/TR/css3-animations/`](http://www.w3.org/TR/css3-animations/)

### 注意

如果未指定`0%`或`from`关键帧，则用户代理将使用正在动画化的属性的计算值构造`0%`关键帧。如果未指定`100%`或`to`关键帧，则用户代理将使用正在动画化的属性的计算值构造`100%`关键帧。如果关键帧选择器指定负百分比值或高于`100%`的值，则将忽略该关键帧。

在这个`keyframes` at-rule 中，我们在 100%处添加了 text-shadow 和 box-shadow。然后，我们可以期望`keyframes`应用到元素时，将文本阴影和框阴影动画到定义的程度。但是动画持续多久？我们如何使其重复，反转，以及其他可能性，我希望有答案？这就是我们实际应用`keyframes`动画的方法：

```html
.flipper:hover .flipper-horizontal {
    transform: rotateY(180deg);
    animation: pulse 1s 1s infinite alternate both;
}
```

这里的`animation`属性被用作多个与动画相关的属性的速记。在这个例子中，我们实际上是按顺序声明了要使用的`keyframes`声明的名称（pulse），`animation-duration`（1 秒），动画开始前的延迟（1 秒，以便我们的按钮首先翻转的时间），动画将运行的次数（无限次），动画的方向（交替，所以它先沿着一条路线动画，然后返回另一条路线），以及我们希望`animation-fill-mode`保留在`keyframes`中定义的值，无论是向前还是向后（两者都是）。

速记属性实际上可以接受所有七个动画属性。除了前面示例中使用的属性之外，还可以指定`animation-play-state`。这可以设置为 running 或 paused，以有效地播放和暂停动画。当然，您不需要使用速记属性；有时分别设置每个属性可能更有意义（并且在将来重新访问代码时可能会有所帮助）。以下是各个属性以及在适当的情况下，用管道符号分隔的备用值：

```html
.animation-properties {
    animation-name: warning;
    animation-duration: 1.5s;
    animation-timing-function: ease-in-out;
    animation-iteration-count: infinite;
    animation-play-state: running | paused;
    animation-delay: 0s;
    animation-fill-mode: none | forwards | backwards | both;
    animation-direction: normal | reverse | alternate | alternate-reverse;
}
```

### 注意

您可以在[`www.w3.org/TR/css3-animations/`](http://www.w3.org/TR/css3-animations/)上阅读每个这些动画属性的完整定义。

如前所述，可以简单地在其他元素上重用已声明的`keyframes`，并且具有完全不同的设置：

```html
.flipper:hover .flipper-vertical {
    transform: rotateX(180deg);
    animation: pulse 2s 1s cubic-bezier(0.68, -0.55, 0.265, 1.55) 5 alternate both;
}
```

在这里，`pulse`动画将持续 2 秒，并使用 ease-in-out-back 时间函数（定义为三次贝塞尔曲线）。它在两个方向上各运行五次。这个声明已经应用到示例文件中垂直翻转的元素上。

这只是使用 CSS 动画的一个非常简单的例子。几乎任何东西都可以成为关键帧，可能性非常广泛。阅读有关 CSS3 动画的最新发展，访问[`dev.w3.org/csswg/css3-animations/`](http://dev.w3.org/csswg/css3-animations/)。

## animation-fill-mode 属性

`animation-fill-mode`属性值得特别一提。考虑一个动画，从黄色背景开始，经过 3 秒动画到红色背景。你可以在`example_08-08`中查看。

我们这样应用动画：

```html
.background-change {
  animation: fillBg 3s;
  height: 200px;
  width: 400px;
  border: 1px solid #ccc;
}

@keyframes fillBg {
  0% {
    background-color: yellow;
  }
  100% {
    background-color: red;
  }
}
```

然而，一旦动画完成，`div`的背景将返回到原来的状态。这是因为默认情况下，“动画之外发生的事情，留在动画之外”！为了覆盖这种行为，我们有`animation-fill-mode`属性。在这种情况下，我们可以应用这样的属性：

```html
animation-fill-mode: forwards;
```

这使得项目保留了动画结束时应用的任何值。在我们的例子中，`div`将保留动画结束时的红色背景颜色。有关`animation-fill-mode`属性的更多信息，请参阅：[`www.w3.org/TR/css3-animations/#animation-fill-mode-property`](http://www.w3.org/TR/css3-animations/#animation-fill-mode-property)

![animation-fill-mode 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_08_18.jpg)

# 总结

填写多本书来覆盖 CSS 变换、过渡和动画的可能性是完全可能的。然而，希望通过本章的涉水，你能够掌握基础知识并运用它们。最终，通过拥抱 CSS 的这些新特性和技术，目标是使响应式设计比以往更加精简且丰富，而不是使用 JavaScript 来实现一些更花哨的美学增强。

在本章中，我们学习了 CSS3 过渡是什么以及如何编写它们。我们掌握了像 ease 和 linear 这样的时间函数，然后使用它们创建简单但有趣的效果。然后我们学习了所有关于`scale`和`skew`这样的 2D 变换，以及如何与过渡一起使用它们。我们还简要介绍了 3D 变换，然后学习了 CSS 动画的强大和相对简单。你最好相信我们的 CSS3 技能正在增长！

然而，如果有一个网站设计领域，我尽量避免的，那就是制作表单。我不知道为什么，我总是觉得制作它们是一项乏味且令人沮丧的任务。当我得知 HTML5 和 CSS3 可以比以往更容易地构建、样式化甚至验证（是的，验证！）整个表单过程时，我感到非常高兴。在下一章中，我想与你分享这些知识。


# 第九章：使用 HTML5 和 CSS3 征服表单

在 HTML5 之前，添加诸如日期选择器、占位文本和范围滑块到表单中总是需要 JavaScript。同样，我们无法轻松地告诉用户我们希望他们在某些输入字段中输入什么，例如，我们是希望用户输入电话号码、电子邮件地址还是 URL。好消息是，HTML5 在很大程度上解决了这些常见问题。

本章有两个主要目标。首先，了解 HTML5 表单功能，其次，了解如何使用最新的 CSS 功能为多个设备更简单地布局表单。

在本章中，我们将学习如何：

+   轻松地在相关的表单输入字段中添加占位文本

+   在必要时禁用表单字段的自动完成

+   在提交之前设置某些字段为必填项

+   指定不同的输入类型，如电子邮件、电话号码和 URL

+   为了方便选择数值，创建数字范围滑块

+   将日期和颜色选择器放入表单中

+   学习如何使用正则表达式来定义允许的表单值

+   如何使用 Flexbox 样式化表单

# HTML5 表单

我认为理解 HTML5 表单的最简单方法是通过一个示例表单逐步进行。从最好的日间电视示例中，我有一个之前制作的。需要一个小的介绍。

两个事实：首先，我喜欢电影。其次，我对什么是一部好电影，什么不是有很强烈的意见。

每年奥斯卡提名公布时，我总是忍不住觉得奥斯卡学院选错了电影。因此，我们将从一个 HTML5 表单开始，让影迷们发泄对奥斯卡提名持续不公的不满。

它由几个`fieldset`元素组成，在其中我们包括了大量的 HTML5 表单输入类型和属性。除了标准的表单输入字段和文本区域，我们还有一个数字微调器、一个范围滑块，以及许多字段的占位文本。

在 Chrome 中没有应用样式的情况下是这样的：

![HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_01.jpg)

如果我们“聚焦”在第一个字段上并开始输入文本，占位文本将被移除。如果我们在不输入任何内容的情况下失去焦点（再次点击输入框外部），占位文本将重新出现。如果我们提交表单（没有输入任何内容），则会发生以下情况：

![HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_02.jpg)

令人振奋的消息是，所有这些用户界面元素，包括前面提到的滑块、占位文本和微调器，以及输入验证，都是由浏览器通过 HTML5 原生处理的，而无需 JavaScript。现在，表单验证并不完全跨浏览器兼容，但我们很快就会解决这个问题。首先，让我们了解所有与表单相关的 HTML5 的新功能，以及使所有这些成为可能的机制。一旦我们了解了所有的机制，我们就可以开始着手进行样式设计。

# 理解 HTML5 表单的组成部分

我们的 HTML5 动力表单中有很多内容，让我们来分解一下。表单的三个部分都包裹在一个带有标题的`fieldset`中：

```html
<fieldset>
<legend>About the offending film (part 1 of 3)</legend>
<div>
  <label for="film">The film in question?</label>
  <input id="film" name="film" type="text" placeholder="e.g. King Kong" required>
</div>
```

从前面的代码片段中可以看到，表单的每个输入元素也都包裹在一个带有与每个输入相关联的标签的`div`中（如果我们也想的话，我们也可以用标签元素包装输入）。到目前为止，一切都很正常。然而，在这个第一个输入中，我们刚刚遇到了我们的第一个 HTML5 表单功能。在常见的 ID、名称和类型属性之后，我们有`placeholder`。

## 占位文本

`placeholder`属性看起来是这样的：

```html
placeholder="e.g. King Kong"
```

表单字段内的占位文本是一个如此常见的需求，以至于创建 HTML5 的人们决定它应该成为 HTML 的一个标准特性。只需在输入中包含`placeholder`属性，该值将默认显示，直到字段获得焦点。当失去焦点时，如果没有输入值，它将重新显示占位文本。

### 样式化占位文本

您可以使用`:placeholder-shown`伪选择器样式化`placeholder`属性。请注意，此选择器经历了许多迭代，因此请确保您已设置前缀工具，以提供已实现版本的回退选择器。

```html
input:placeholder-shown {
  color: #333;
}
```

在上一个代码片段中的`placeholder`属性之后，下一个 HTML5 表单功能是`required`属性。

## 必需的

`required`属性看起来像这样：

```html
required
```

在支持 HTML5 的浏览器中，通过在`input`元素内添加布尔值（意味着您只需包含属性或不包含属性），可以指示需要输入值的`required`属性。如果在不包含必要信息的字段提交表单，则应显示警告消息。显示的消息对于使用的浏览器和输入类型都是特定的（在内容和样式上）。

我们已经看到了`required`字段在 Chrome 中的浏览器消息是什么样子。以下截图显示了 Firefox 中相同的消息：

![必需的](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_03.jpg)

`required`值可以与许多输入类型一起使用，以确保输入值。需要注意的例外是`range`、`color`、`button`和`hidden`输入类型，因为它们几乎总是具有默认值。

## 自动聚焦

HTML5 的`autofocus`属性允许表单已经聚焦在一个字段上，准备好接受用户输入。以下代码是一个在`div`中添加了`autofocus`属性的`input`字段的示例：

```html
<div>
  <label for="search">Search the site...</label>
  <input id="search" name="search" type="search" placeholder="Wyatt Earp" autofocus>
</div>
```

在使用此属性时要小心。如果多个字段都添加了`autofocus`属性，则可能会在多个浏览器中引起混乱。例如，如果多个字段都添加了`autofocus`，在 Safari 中，具有`autofocus`属性的最后一个字段在页面加载时会聚焦。然而，Firefox 和 Chrome 在第一个`autofocus`字段被选中时会做相反的操作。

还值得考虑的是，一些用户在加载网页后会使用空格键快速跳过内容。在一个具有自动聚焦输入字段的表单页面上，它会阻止这种功能；相反，它会在聚焦的输入字段中添加一个空格。很容易看出这可能会成为用户的挫折之源。

如果使用`autofocus`属性，请确保它在表单中只使用一次，并确保您了解使用空格键滚动的用户的影响。

## 自动完成

默认情况下，大多数浏览器通过自动填充表单字段的值来帮助用户输入。虽然用户可以在浏览器中打开或关闭此偏好设置，但现在我们还可以指示浏览器在我们不希望表单或字段允许自动完成时。这不仅对于敏感数据（例如银行账号）有用，而且还可以确保用户注意并手动输入内容。例如，对于我填写的许多表单，如果需要电话号码，我会输入一个“欺骗”电话号码。我知道我不是唯一这样做的人（难道不是每个人都这样吗？），但我可以通过在相关输入字段上将`autocomplete`属性设置为关闭来确保用户不输入自动完成的欺骗号码。以下是一个将`autocomplete`属性设置为`off`的字段的代码示例：

```html
<div>
  <label for="tel">Telephone (so we can berate you if you're wrong)</label>
  <input id="tel" name="tel" type="tel" placeholder="1-234-546758" autocomplete="off" required>
</div>
```

我们还可以通过在表单本身上使用属性来设置整个表单（但不是字段集）不自动完成。以下是一个代码示例：

```html
<form id="redemption" method="post" autocomplete="off">
```

## 列表和相关的 datalist 元素

此`list`属性和相关的`datalist`元素允许在用户开始输入字段中的值后向用户呈现多个选择。以下是一个使用`list`属性的代码示例，其中包含一个相关的`datalist`，全部包装在一个`div`中：

```html
<div>
  <label for="awardWon">Award Won</label>
  <input id="awardWon" name="awardWon" type="text" list="awards">
  <datalist id="awards">
    <select>
      <option value="Best Picture"></option>
      <option value="Best Director"></option>
      <option value="Best Adapted Screenplay"></option>
      <option value="Best Original Screenplay"></option>
    </select>
  </datalist>
</div>
```

在`list`属性（`awards`）中给出的值是`datalist`的 ID。这样做可以将`datalist`与输入字段关联起来。虽然在`<select>`元素中包装选项并不是严格必要的，但在为尚未实现该功能的浏览器应用 polyfill 时会有所帮助。

### 注意

令人惊讶的是，到 2015 年中期，iOS、Safari 或 Android 4.4 及以下仍然不支持`datalist`元素（[`caniuse.com/`](http://caniuse.com/)）

您可以在[`www.w3.org/TR/html5/forms.html`](http://www.w3.org/TR/html5/forms.html)上阅读`datalist`的规范。

虽然`input`字段似乎只是一个普通的文本输入字段，但在输入字段时，支持的浏览器下方会出现一个选择框，其中包含来自`datalist`的匹配结果。在下面的截图中，我们可以看到列表的效果（Firefox）。在这种情况下，由于`B`在`datalist`中的所有选项中都存在，所有值都会显示给用户选择：

![列表和相关的 datalist 元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_04.jpg)

然而，当输入`D`时，只有匹配的建议会出现，如下面的截图所示：

![列表和相关的 datalist 元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_05.jpg)

`list`和`datalist`不会阻止用户在输入框中输入不同的文本，但它们确实提供了另一种通过 HTML5 标记添加常见功能和用户增强的好方法。

# HTML5 输入类型

HTML5 添加了许多额外的输入类型，其中包括其他功能，使我们能够限制用户输入的数据，而无需额外的 JavaScript 代码。这些新输入类型最令人欣慰的是，默认情况下，如果浏览器不支持该功能，它们会退化为标准的文本输入框。此外，还有很多很好的 polyfill 可用于使旧版浏览器跟上步伐，我们很快会看到。与此同时，让我们来看看这些新的 HTML5 输入类型以及它们提供的好处。

## email

您可以像这样将输入设置为`email`类型：

```html
type="email"
```

支持的浏览器将期望用户输入与电子邮件地址的语法匹配。在下面的代码示例中，`type="email"`与`required`和`placeholder`一起使用：

```html
<div>
  <label for="email">Your Email address</label>
  <input id="email" name="email" type="email" placeholder="dwight.schultz@gmail.com" required>
</div>
```

当与 required 一起使用时，提交不符合规范的输入将生成警告消息：

![email](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_06.jpg)

此外，许多触摸屏设备（例如 Android、iPhone 等）会根据此输入类型改变输入显示。下面的截图显示了 iPad 上`type="email"`的输入屏幕的外观。请注意，软键盘已添加`@`符号，以便轻松完成电子邮件地址：

![email](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_07.jpg)

## 数字

您可以像这样将输入字段设置为数字类型：

```html
type="number"
```

支持的浏览器期望在此输入数字。支持的浏览器还提供所谓的**微调控件**。这些是微小的用户界面元素，允许用户轻松点击上下来改变输入的值。以下是一个代码示例：

```html
<div>
  <label for="yearOfCrime">Year Of Crime</label>
  <input id="yearOfCrime" name="yearOfCrime" type="number" min="1929" max="2015" required>
</div>
```

以下是在支持的浏览器（Chrome）中的外观截图：

![number](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_08.jpg)

如果不输入数字，不同浏览器的实现方式也不同。例如，Chrome 和 Firefox 在表单提交之前不会做任何操作，然后在字段上方弹出警告。另一方面，Safari 什么也不做，只是让表单被提交。Internet Explorer 11 在焦点离开字段时会清空字段。

### 最小和最大范围

在上一个代码示例中，我们还设置了允许的最小和最大范围，类似于以下代码：

```html
type="number" min="1929" max="2015"
```

超出此范围的数字（应该）会得到特殊处理。

您可能不会感到惊讶，浏览器对`min`和`max`范围的实现是各不相同的。例如，Internet Explorer 11、Chrome 和 Firefox 会显示警告，而 Safari 则什么也不做。

### 更改步进增量

您可以使用`step`属性来改变各种输入类型的微调控件的步进增量（粒度）。例如，每次步进 10 个单位：

```html
<input type="number" step="10">
```

## url

您可以设置输入字段期望输入 URL，如下所示：

```html
type="url"
```

正如您所期望的，`url`输入类型用于 URL 值。与`tel`和`email`输入类型类似；它的行为几乎与标准文本输入完全相同。但是，一些浏览器在提交不正确的值时会向警告消息中添加特定信息。以下是包括`placeholder`属性的代码示例：

```html
<div>
  <label for="web">Your Web address</label>
  <input id="web" name="web" type="url" placeholder="www.mysite.com">
</div>
```

以下截图显示了在 Chrome 中提交不正确输入的 URL 字段时会发生什么：

![url](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_09.jpg)

与`type="email"`一样，触摸屏设备通常根据此输入类型修改输入显示。以下截图显示了 iPad 上`type="url"`屏幕的外观：

![url](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_10.jpg)

注意到*.com*键了吗？因为我们使用了 URL 输入类型，设备会为易于 URL 完成而呈现它们（在 iOS 上，如果您不是要去.com 网站，您可以长按一下以获得其他几个流行的顶级域名）。

## tel

设置输入字段以期望电话号码，如下所示：

```html
type="tel"
```

以下是一个更完整的示例：

```html
<div>
  <label for="tel">Telephone (so we can berate you if you're wrong)</label>
  <input id="tel" name="tel" type="tel" placeholder="1-234-546758" autocomplete="off" required>
</div>
```

尽管在许多浏览器上期望数字格式，甚至是现代的 evergreen 浏览器，如 Internet Explorer 11、Chrome 和 Firefox，它们仅仅表现得像文本输入字段。当输入不正确的值时，它们在字段失去焦点或表单提交时未能提供合适的警告消息。

然而，更好的消息是，与`email`和`url`输入类型一样，触摸屏设备通常会贴心地适应这种输入，通过修改输入显示来方便完成；这是在 iPad 上访问`tel`输入时的外观（运行 iOS 8.2）：

![tel](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_11.jpg)

注意键盘区域中缺少字母字符？这使用户更快地以正确格式输入值。

### 提示

**快速提示**

如果在 iOS Safari 中使用`tel`输入时默认的蓝色电话号码颜色让您感到不适，您可以使用以下选择器进行修改：

```html
a[href^=tel] { color: inherit; }
```

## search

您可以将输入设置为搜索类型，如下所示：

```html
type="search"
```

`search`输入类型的工作方式类似于标准文本输入。以下是一个例子：

```html
<div>
  <label for="search">Search the site...</label>
  <input id="search" name="search" type="search" placeholder="Wyatt Earp">
</div>
```

然而，软件键盘（如移动设备上的键盘）通常提供更贴心的键盘。这是当`search`输入类型获得焦点时出现的 iOS 8.2 键盘：

![search](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_12.jpg)

## pattern

您可以设置输入以期望某种模式输入，如下所示：

```html
pattern=""
```

`pattern`属性允许您通过正则表达式指定应在给定输入字段中允许的数据的语法。

### 注意

**了解正则表达式**

如果您以前从未遇到过正则表达式，我建议从这里开始：[`en.wikipedia.org/wiki/Regular_expressions`](http://en.wikipedia.org/wiki/Regular_expressions)

正则表达式在许多编程语言中被用作匹配可能的字符串的手段。虽然一开始格式可能令人生畏，但它们非常强大和灵活。例如，您可以构建一个正则表达式来匹配密码格式，或选择某种样式的 CSS 类命名模式。为了帮助您构建自己的正则表达式模式并直观地了解它们的工作原理，我建议从像[`www.regexr.com/`](http://www.regexr.com/)这样的基于浏览器的工具开始。

以下代码是一个例子：

```html
<div>
  <label for="name">Your Name (first and last)</label>
  <input id="name" name="name" pattern="([a-zA-Z]{3,30}\s*)+[a-zA-Z]{3,30}" placeholder="Dwight Schultz" required>
</div>
```

我对这本书的承诺如此之深，我在互联网上搜索了大约 458 秒，找到了一个可以匹配名字和姓氏语法的正则表达式。通过在`pattern`属性中输入正则表达式值，支持的浏览器会期望匹配的输入语法。然后，当与`required`属性一起使用时，支持的浏览器会对不正确的输入进行以下处理。在这种情况下，我尝试在没有提供姓氏的情况下提交表单。

同样，浏览器的行为不同。Internet Explorer 11 要求正确输入字段，Safari、Firefox 和 Chrome 什么也不做（它们只是像标准文本输入一样行为）。

## 颜色

想要设置一个输入字段接收十六进制颜色值？您可以这样做：

```html
type="color"
```

`color`输入类型在支持的浏览器中调用颜色选择器（目前仅限 Chrome 和 Firefox），允许用户选择十六进制颜色值。以下代码是一个例子：

```html
<div>
  <label for="color">Your favorite color</label>
  <input id="color" name="color" type="color">
</div>
```

## 日期和时间输入

新的`date`和`time`输入类型的思路是为选择日期和时间提供一致的用户体验。如果你曾经在网上购买活动门票，很可能使用过某种日期选择器。这种功能几乎总是通过 JavaScript（通常是 jQuery UI 库）提供的，但希望能够仅通过 HTML5 标记实现这种常见需求。

### 日期

以下代码是一个例子：

```html
<input id="date" type="date" name="date">
```

与`color`输入类型类似，原生浏览器支持非常有限，在大多数浏览器上默认为标准文本输入框。Chrome 和 Opera 是唯一实现此功能的现代浏览器。这并不奇怪，因为它们都使用相同的引擎（如果您感兴趣，它被称为**Blink**）。

![日期](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_13.jpg)

有各种不同的与`date`和`time`相关的输入类型可用。以下是其他类型的简要概述。

### 月份

以下代码是一个例子：

```html
<input id="month" type="month" name="month">
```

该界面允许用户选择单个月份，并提供年份和月份的输入，例如 2012-06。以下截图显示了它在浏览器中的外观：

![月份](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_13.jpg)

### 周

以下代码是一个例子：

```html
<input id="week" type="week" name="week">
```

当使用`week`输入类型时，选择器允许用户在一年中选择单个星期，并以 2012-W47 格式提供输入。

以下截图显示了它在浏览器中的外观：

![周](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_14.jpg)

### 时间

以下代码是一个例子：

```html
<input id="time" type="time" name="time">
```

`time`输入类型允许使用 24 小时制的值，例如 23:50。

它在支持的浏览器中显示为微调控件，但仅允许相关的时间值。

## 范围

`range`输入类型创建了一个滑块界面元素。以下是一个例子：

```html
<input type="range" min="1" max="10" value="5">
```

以下截图显示了它在 Firefox 中的外观：

![范围](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_15.jpg)

默认范围是从 0 到 100。但是，在我们的示例中指定了`min`和`max`值，将其限制在 1 到 10 之间。

我在使用`range`输入类型时遇到的一个大问题是，当前值从不显示给用户。尽管范围滑块仅用于模糊的数字选择，但我经常希望在值发生变化时显示值。目前，使用 HTML5 没有办法做到这一点。但是，如果您绝对必须显示滑块的当前值，可以通过一些简单的 JavaScript 轻松实现。将前面的示例修改为以下代码：

```html
<input id="howYouRateIt" name="howYouRateIt" type="range" min="1" max="10" value="5" onchange="showValue(this.value)"><span  id="range">5</span>
```

我们添加了两个东西，一个是`onchange`属性，另一个是 ID 为 range 的`span`元素。现在，我们将添加以下简短的 JavaScript 代码：

```html
<script>
  function showValue(newValue)
  {
    document.getElementById("range").innerHTML=newValue;
  }
</script>
```

这只是获取范围滑块的当前值，并在具有 ID 为 range 的元素中显示它（我们的`span`标记）。然后，您可以使用任何您认为合适的 CSS 来更改值的外观。

HTML5 中还有一些其他与表单相关的新功能。您可以在[`www.w3.org/TR/html5/forms.html`](http://www.w3.org/TR/html5/forms.html)阅读完整规范。

# 如何为不支持的浏览器提供 polyfill

所有这些 HTML5 表单的花哨都很好。然而，似乎有两件事严重影响了我们使用它们的能力：支持浏览器实现功能的差异，以及如何处理根本不支持这些功能的浏览器。

如果您需要在较旧或不支持的浏览器中支持某些功能，请考虑使用 Webshims Lib，您可以在[`afarkas.github.com/webshim/demos/`](http://afarkas.github.com/webshim/demos/)下载。这是由 Alexander Farkas 编写的一个 polyfill 库，可以加载表单 polyfills 以使不支持 HTML5 表单功能的浏览器处理。

### 提示

**小心使用 polyfills**

每当您使用 polyfill 脚本时，请务必仔细考虑。虽然它们非常方便，但会增加项目的负担。例如，Webshims 还需要 jQuery，因此如果您以前没有使用 jQuery，则需要另一个依赖项。除非在较旧的浏览器中使用 polyfill 是必不可少的，否则我会避免使用。

Webshims 的方便之处在于它只在需要时添加 polyfills。如果被支持这些 HTML5 功能的浏览器查看，它几乎不会添加任何内容。老旧的浏览器虽然需要加载更多代码（因为它们默认情况下功能较弱），但用户体验类似，尽管相关功能是通过 JavaScript 创建的。

但受益的不仅仅是较旧的浏览器。正如我们所见，许多现代浏览器并没有完全实现 HTML5 表单功能。将 Webshims lib 应用到页面上也可以填补它们功能上的任何空白。例如，Safari 在提交带有必填字段为空的 HTML5 表单时不提供任何警告。用户不会得到有关问题的任何反馈：这几乎不理想。将 Webshims lib 添加到页面后，在上述情况下会发生以下情况。

因此，当 Firefox 无法为`type="number"`属性提供微调器时，Webshims lib 提供了一个合适的、由 jQuery 支持的替代方案。简而言之，这是一个很棒的工具，所以让我们安装并连接这个美丽的小包，然后我们可以继续使用 HTML5 编写表单，放心地知道所有用户都将看到他们需要使用我们的表单（除了那两个使用 IE6 并关闭了 JavaScript 的人——你们知道自己是谁——现在停止吧！）。

首先下载 Webshims lib（[`github.com/aFarkas/webshim/downloads`](http://github.com/aFarkas/webshim/downloads)）并提取包。现在将`js-webshim`文件夹复制到网页的相关部分。为了简单起见，我将其复制到了网站根目录。

现在将以下代码添加到页面的相应部分：

```html
<script src="img/jquery-2.1.3.min.js"></script>
<script src="img/polyfiller.js"></script>
<script>
  //request the features you need:
  webshim.polyfill('forms');
</script>
```

让我们一步一步来。首先，我们链接到本地的 jQuery 库（在[www.jquery.com](http://www.jquery.com)获取最新版本）和 Webshim 脚本：

```html
<script src="img/jquery-2.1.3.min.js"></script>
<script src="img/polyfiller.js"></script>
```

最后，我告诉脚本加载所有需要的 polyfills：

```html
<script>
  //request the features you need:
  webshim.polyfill('forms');
</script>
```

就是这样。现在，相关的 polyfill 会自动添加缺失的功能。太棒了！

# 用 CSS3 样式化 HTML5 表单

我们的表单现在在各种浏览器上都可以正常使用，现在我们需要使其在不同的视口尺寸下更具吸引力。现在，我不认为自己是一个设计师，但通过应用我们在前几章学到的一些技巧，我仍然认为我们可以改善表单的美观度。

### 注意

您可以在`example_09-02`中查看样式化的表单，并且请记住，如果您还没有示例代码，可以在[`rwd.education`](http://rwd.education)获取它。

在这个例子中，我还包括了两个版本的样式表：`styles.css`是包含供应商前缀的版本（通过 Autoprefixer 添加），`styles-unprefixed.css`是原始的 CSS。如果您想查看如何应用任何内容，后者可能更容易查看。

在小视口中应用了一些基本样式后，表单的外观如下：

![用 CSS3 样式化 HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_18.jpg)

在较大的视口中是这样的：

![用 CSS3 样式化 HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_09_17.jpg)

如果你看一下 CSS，你会看到我们在之前的章节中学到的许多技巧。例如，Flexbox（第三章，*流动布局和响应式图片*）已被用于创建元素的统一间距和灵活性；变换和过渡（第八章，*过渡、变换和动画*）使得焦点输入字段增大，准备/提交按钮在获得焦点时垂直翻转。盒阴影和渐变（第六章，*CSS3 的惊人美学*）被用来强调表单的不同区域。媒体查询（第二章，*媒体查询-支持不同的视口*）被用于在不同的视口尺寸下切换 Flexbox 方向，CSS Level 3 选择器（第五章，*CSS3-选择器、排版、颜色模式和新特性*）被用于选择器否定。

我们不会再详细介绍这些技术。相反，我们将专注于一些特殊之处。首先，如何在视觉上指示必填字段（并且额外加分指示已输入值），其次，如何在字段获得用户焦点时创建“填充”效果。

## 指示必填字段

我们可以仅使用 CSS 向用户指示必填输入字段。例如：

```html
input:required {
  /* styles */
}
```

通过该选择器，我们可以为必填字段添加边框或轮廓，或在字段内部添加`background-image`。基本上没有限制！我们还可以使用特定的选择器来仅在输入字段获得焦点时，针对必填的输入字段进行定位。例如：

```html
input:focus:required {
  /* styles */
}
```

然而，这将会应用样式到输入框本身。如果我们想要修改相关的`label`元素上的样式怎么办？我决定我想在标签旁边用一个小星号符号来表示必填字段。但这带来了一个问题。通常，CSS 只允许我们在元素的子元素、元素本身或者元素的一般或相邻兄弟元素上进行更改（当我说状态时，我指的是`hover`、`focus`、`active`、`checked`等）。在下面的例子中，我使用了`:hover`，但这对基于触摸的设备显然是有问题的。

```html
.item:hover .item-child {}
```

通过前面的选择器，当悬停在项目上时，样式将应用到`item-child`。

```html
.item:hover ~ .item-general-sibling {}
```

通过这个选择器，当悬停在项目上时，样式将应用到`item-general-sibling`，如果它与项目在同一 DOM 级别，并跟随在其后。

```html
.item:hover + .item-adjacent-sibling {}
```

在这里，当悬停在项目上时，样式将应用到`item-adjacent-sibling`，如果它是项目的相邻兄弟元素（在 DOM 中紧跟在它后面）。

所以，回到我们的问题。如果我们有一个带有标签和字段的表单，标签在输入框上方（以便给我们所需的基本布局），这让我们有点困扰：

```html
<div class="form-Input_Wrapper">
  <label for="film">The film in question?</label>
  <input id="film" name="film" type="text" placeholder="e.g. King Kong" required/>
</div>
```

在这种情况下，仅使用 CSS，没有办法根据输入是否必填来更改标签的样式（因为它在标记中位于标签之后）。我们可以在标记中切换这两个元素的顺序，但那样我们会得到标签在输入框下面的结果。

然而，Flexbox 让我们能够轻松地在元素的视觉顺序上进行反转（如果你还没有阅读过，请在第三章中了解更多相关内容，*流动布局和响应式图片*）。这使我们可以使用以下标记：

```html
<div class="form-Input_Wrapper">
  <input id="film" name="film" type="text" placeholder="e.g. King Kong" required/>
  <label for="film">The film in question?</label>
</div>
```

然后只需将`flex-direction: row-reverse`或`flex-direction: column-reverse`应用于父元素。这些声明可以颠倒子元素的视觉顺序，使标签在输入框上方（较小的视口）或左侧（较大的视口）显示所需的美学效果。现在我们可以开始实际提供一些必填字段的指示以及它们何时接收到输入。

由于我们修改过的标记，相邻兄弟选择器现在使这成为可能。

```html
input:required + label:after { }
```

这个选择器基本上是说，对于跟随具有`required`属性的输入的每个标签，应用封闭的规则。以下是该部分的 CSS：

```html
input:required + label:after {
  content: "*";
  font-size: 2.1em;
  position: relative;
  top: 6px;
  display: inline-flex;
  margin-left: .2ch;
  transition: color, 1s;
}

input:required:invalid + label:after {
  color: red;
}

input:required:valid + label:after {
  color: green;
}
```

然后，如果你专注于必填输入并输入相关值，星号的颜色会变成绿色。这是一个细微但有用的触摸。

### 注意

除了我们已经看过的所有选择器之外，还有更多的选择器（已实现和正在指定）。要获取最新的列表，请查看 Selectors Level 4 规范的最新编辑草案：[`dev.w3.org/csswg/selectors-4/`](http://dev.w3.org/csswg/selectors-4/)

## 创建背景填充效果

在第六章中，*使用 CSS3 创建令人惊叹的美学*，我们学习了如何生成线性和径向渐变作为背景图像。遗憾的是，无法在两个背景图像之间进行过渡（这是有道理的，因为浏览器实际上将声明光栅化为图像）。但是，我们可以在关联属性的值之间进行过渡，例如`background-position`和`background-size`。我们将利用这一因素，在`input`或`textarea`获得焦点时创建填充效果。

以下是添加到输入的属性和值：

```html
input:not([type="range"]),
textarea {
  min-height: 30px;
  padding: 2px;
  font-size: 17px;
  border: 1px solid #ebebeb;
  outline: none;
  transition: transform .4s, box-shadow .4s, background-position .2s;
  background: radial-gradient(400px circle,  #fff 99%, transparent 99%), #f1f1f1;
  background-position: -400px 90px, 0 0;
  background-repeat: no-repeat, no-repeat;
  border-radius: 0;
  position: relative;
}

input:not([type="range"]):focus,
textarea:focus {
  background-position: 0 0, 0 0;
}
```

在第一个规则中，正在生成一个实心白色径向渐变，但位置偏移不在视图之外。`radial-gradient`之后的 HEX 值是背后的背景颜色，因此提供了默认颜色。当输入获得焦点时，`radial-gradient`的背景位置被设置回默认值，因为我们在设置了背景图像的过渡，所以我们得到了两者之间的漂亮过渡。结果是当输入获得焦点时，出现输入被不同颜色“填充”的外观。

### 注意

不同的浏览器在样式化本机 UI 的部分时都有自己的专有选择器和功能。Aurelius Wendelken 编制了一个令人印象深刻的选择器列表。我制作了自己的副本（或者在 Git 版本控制中称为“分支”），你可以在[`gist.github.com/benfrain/403d3d3a8e2b6198e395`](https://gist.github.com/benfrain/403d3d3a8e2b6198e395)找到。

# 摘要

在本章中，我们学习了如何使用一系列新的 HTML5 表单属性。它们使我们能够使表单比以往任何时候都更易于使用，并且捕获的数据更相关。此外，我们可以在需要时使用 JavaScript polyfill 脚本来未来化这个新的标记，以便所有用户无论其浏览器的能力如何，都能体验相似的表单功能。

我们即将结束我们的响应式 HTML5 和 CSS3 之旅。虽然我们在一起的时间里涵盖了大量内容，但我意识到我永远无法传授你们遇到的每种情况的所有信息。因此，在最后一章中，我想以更高层次的方式来看待响应式网页设计，并尝试提供一些确切的最佳实践，以便让你的下一个/第一个响应式项目有一个良好的开端。
