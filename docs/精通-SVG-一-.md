# 精通 SVG（一）

> 原文：[`zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935`](https://zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书适用于希望在项目中添加可伸缩、设备独立的动画、图像和可视化效果的 Web 开发人员和设计师。可伸缩矢量图形是一种由万维网联盟（W3C）于 1998 年推出的图像文件格式。多年来，它一直因浏览器兼容性差和不友好的 API 而不受重视。在过去几年里，它已成为现代 Web 开发工具包的重要组成部分。SVG 为现代 Web 提供了许多重要功能。例如，在多种设备分辨率的世界中，它提供了一条简单的路径，可以实现高质量的图像缩放，而无需为图像生成多个分辨率，也无需跳过复杂的标记模式。此外，作为基于 XML 的标记，它还允许轻松访问常见的 JavaScript 模式，用于创建高度交互式的界面。

本书将教会你如何使用 SVG 作为静态图像、在 CSS 中、作为 HTML 文档中的元素以及作为动画或可视化的一部分进行编写的基础知识。

# 这本书适合谁

这本书适用于对可伸缩矢量图形感兴趣的 Web 开发人员。它是从前端 Web 开发人员的角度编写的，但任何有 JavaScript、CSS 和基于 XML 的语法经验的人都应该能够理解本书。

不需要有 SVG 的先验经验。

# 本书涵盖的内容

第一章《介绍可伸缩矢量图形》介绍了 SVG 的基础知识，并将向你展示一些使用该格式的基本示例。

第二章《开始使用 SVG 创作》详细介绍了创作 SVG 的基本概念。

第三章《深入挖掘 SVG 创作》介绍了更高级的 SVG 创作概念，包括变换、裁剪和遮罩，以及将 SVG 元素导入文档。

第四章《在 HTML 中使用 SVG》进一步介绍了在 HTML 文档中使用 SVG 元素和 SVG 图像的细节。

第五章《使用 SVG 和 CSS》介绍了在 CSS 中使用 SVG 图像，取代 PNG 和 Gif 在现代 Web 开发工具包中的使用。本章还介绍了使用 CSS 修改 SVG 元素的多种方法。

第六章《JavaScript 和 SVG》通过介绍常见的文档对象模型方法，教会读者基本的 JavaScript SVG 应用程序接口，这些方法允许开发人员访问和操作 SVG 属性。

第七章《常见的 JavaScript 库和 SVG》教授了如何从常见的库和框架（包括 jQuery、AngularJS、Angular 和 ReactJS）中与 SVG 进行交互的基础知识。

第八章《SVG 动画和可视化》介绍了使用 SVG 进行可视化和动画的示例。

第九章《辅助库 Snap.svg 和 SVG.js》介绍了两个当前帮助处理常见 SVG 任务的库：Snap.svg 和 SVG.js。

第十章《使用 D3.js 工作》介绍了 D3 的基本用法，并通过一些简单的示例来激发你对这个强大库的兴趣。

第十一章《优化 SVG 的工具》专注于优化 SVG 的不同工具。

# 为了充分利用本书。

本书假设你具有 HTML、XML、CSS 和 JavaScript 的知识。了解 Node.js 和基于 npm 的开发也会有所帮助。

在开始之前，确保您已安装了 Node.js 会很有帮助。您还需要一个文本编辑器。本书中的示例是使用 Visual Studio Code 编写的，但任何文本编辑器都可以。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择 SUPPORT 选项卡。

1.  点击代码下载和勘误。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-SVG`](https://github.com/PacktPublishing/Mastering-SVG)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包来自我们丰富的书籍和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781788626743_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788626743_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```xml
<svg  width="350" height="150" viewBox="0 0 350 150" version="1.1">
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)"/>
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)" 
     transform="translate(10)" />
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)" 
     transform="translate(75,0)" />
</svg>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```xml
types {
    image/svg+xml svg svgz;
}
```

任何命令行输入或输出都以以下方式编写：

```xml
 $ npx create-react-app react-svg
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中显示为这样。例如："在本文档中，我们创建了一个风格化的字母 R。"

警告或重要说明会显示为这样。

提示和技巧会显示为这样。


# 第一章：介绍可缩放矢量图形

**可缩放矢量图形**（**SVG**）是现代 Web 开发中最强大的组件之一。如果使用得当，它可以解决与图像和用户界面的设计、开发和交付相关的常见问题。

SVG 是一种基于 XML 的标记语言，用于定义图像。就像 HTML 是用于文本一样，SVG 是用于图像的。

SVG 非常灵活。它可以作为独立图像实现，并用作图像的`src`，也可以作为 CSS 中的背景图像，如 PNG、GIF 或 JPG。它也可以直接嵌入到 HTML 页面中，并通过 CSS 或 JavaScript 进行操作，以创建动画、可视化和交互式图表。

因此，如果 SVG 如此重要并且可以做这么多事情，为什么它还没有被更广泛地使用呢？为什么感觉我们只是挖掘了它的表面？为什么它仍然感觉像是一件*新*的东西？

问题是，并不是每个人都知道 SVG 的所有功能，也不是每个了解其功能的人都能以最佳方式实现 SVG 解决方案。本书旨在帮助所有对使用 SVG 感兴趣的人克服这些障碍，掌握这项重要的技术。

SVG 在现代 Web 开发技术中的地位经历了曲折的道路。SVG 于 1999 年发布（比 XHTML 还要早），由于当时主导的 Internet Explorer 浏览器缺乏支持，SVG 在接下来的十年中一直处于低迷状态。几年前，随着 JavaScript 库（如 Raphaël）的出现，为旧版本的 IE 添加了编程回退支持，这项技术开始受到青睐，而这种趋势自那时以来一直在增强。幸运的是，潮流已经完全扭转。所有现代版本的 Internet Explorer 和 Edge 都支持 SVG，所有浏览器制造商都对这项技术给予了强大的支持，包括 Chrome 和 Firefox。

通过本章结束时，您将了解 SVG 在各种形式中的基础知识。您将能够在网页和 CSS 中自信地使用现有的 SVG 图像，并且您将在掌握 SVG 的过程中迈出良好的一步。

本章将涵盖以下主题：

+   SVG 的基本语法和矢量图形介绍

+   将 SVG 用作图像的`src`文件的原因和方法

+   SVG 作为 CSS 背景图像的基本用法

+   直接在文档中嵌入 SVG 的好处和区别

+   Modernizr 和特性检测简介

# 创建一个简单的 SVG 图像

如果您对 HTML 有所了解，那么 SVG 文档的基础对您来说将是熟悉的。所以让我们早点揭开神秘面纱，看一看一个简单的 SVG 文档。

以下代码示例显示了 SVG 的基本结构。第一个元素是标准的`xml`声明，表示接下来的内容应该被解析为 XML 文档。第二个元素是乐趣的开始。它定义了根 SVG 元素（就像 HTML 文档中有一个根 HTML 元素一样）。`height`和`width`定义了文档的固有尺寸。**XML** **Name*S*pace** (**xmlns**)是对定义当前 XML 元素的模式的引用。您将在下一章中更详细地了解`viewBox`。SVG 元素上还有许多其他可能的属性。您将在本书中更多地了解它们。

在这个第一个例子中，在 SVG 元素之后，有一个单独的 SVG `text`元素。`text`元素，就像 SVG 元素一样，有许多可能的属性，你将在阅读本书的过程中了解到。在这种情况下，有四个与元素显示相关的属性。`x`和`y`属性表示文本元素左上角的位置，作为坐标平面上的点。`font-family`映射到同名的常见 CSS 属性，定义应该用于显示文本的特定字体。`font-size`也映射到同名的常见 CSS 属性。

接受*长度值*的属性（在这个例子中是`width`、`height`和`font-size`）是不带单位的（例如`px`、`em`和`%`）。当这些值作为属性呈现时，单位是可选的。如果没有提供单位，这些值被指定为用户空间中的用户单位。你将在本书中了解更多关于 SVG 中值的计算方式。现在，只需记住，在实践中，用户单位将等同于像素。

最后，是`text`元素的内容，简单的消息 Hello SVG：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg width="250" height="100" viewBox="0 0 250 100" version="1.1" xmlns=”http://www.w3.org/2000/svg”>
<text x="0" y="50" font-family="Verdana" font-size="50">
    Hello SVG
  </text>
</svg>
```

保存为`1-1-hello-world.svg`并在浏览器中打开，前面的标记呈现如下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/7752e7ed-47ef-4bd7-8cc1-7eb13657e973.png)

现在你已经看到了 SVG 文档的最基本示例，让我们以各种方式来看一下 SVG 图像和元素的基本用法。

# 使用 SVG 作为内容图像

在这一部分，你将学习 SVG 图像的最基本用法，就像你使用 JPG、PNG 或 GIF 一样，作为`img`元素的`src`。如果你已经做过任何 HTML 工作，那么你会知道如何做到这一点，因为它只是一个图像元素，但你应该开始考虑*所有*你可以使用 SVG 的不同方式，这是一个重要的方式。

看下面的代码示例，`img`元素并没有什么特别之处。有一个指向 SVG 图像的`src`，`height`和`width`定义图像的尺寸，还有一个`alt`属性，为屏幕阅读器和其他图像无法显示的情况提供图像的文本表示：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG - Inserting an SVG Image into an HTML
         Document</title>
    </head>
    <body>
      <img src="img/1-2-circles.svg" width="250" height="250" alt="an image
        showing four circles lined up diagonally across the screen">
    </body>
</html>
```

在浏览器中运行上述代码将呈现如下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/bd57deb3-0707-497a-8937-223ed05604a0.jpg)

可能会有一个小问题，不是所有的 web 服务器默认设置了正确的 SVG MIME 类型。如果 MIME 类型设置不正确，一些浏览器将无法正确显示 SVG 图像。一个常见的例子是，微软的 IIS 可能需要更改特定的配置设置（[`docs.microsoft.com/en-us/iis/manage/managing-your-configuration-settings/adding-ie-9-mime-types-to-iis`](https://docs.microsoft.com/en-us/iis/manage/managing-your-configuration-settings/adding-ie-9-mime-types-to-iis)）才能正确地提供 SVG 图像。正确的 MIME 类型是`image/svg+xml`。

# 用代码绘图

在学习其他基本实现之前，值得更深入地看一下前面的屏幕截图。它不仅仅是像第一个例子那样的文本（毕竟，你可以在 HTML 中完成），它显示了四个圆对角排列在画布上。让我们来看看该图像的源代码，并学习 SVG 中的第一个视觉元素，`circle`元素。

以下代码示例显示了`circle`的操作。它还显示了标记属性值的简单更改如何创建视觉上有趣的图案。其中有五个`circle`元素。所有这些都利用了四个新属性。`cx`和`cy`表示元素在坐标平面上的中心*x*和中心*y*坐标。`r`表示圆的半径。`fill`定义了填充`circle`的颜色。`fill`接受任何有效的 CSS 颜色值（[`developer.mozilla.org/en-US/docs/Web/CSS/color_value`](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value)）。在这种情况下，我们使用了一个**红色**，**绿色**，**蓝色**，**alpha**（**RGBA**）值来填充这个纯红色的变化。前几个值保持不变，而第四个值，alpha，每次从`.125`加倍到`1`（完全不透明）。同样，`cx`，`cy`和`r`每次加倍。这产生了您之前看到的图案。这不是最复杂的 SVG 图像，但它确实向您展示了基本 SVG 元素的使用和理解有多容易：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg width="250" height="250" viewBox="0 0 250 250" version="1.1" >
       <circle cx="12.5" cy="12.5" r="6.25" fill="rgba(255,0,0,.125)">
       </circle>
       <circle cx="25" cy="25" r="12.5" fill="rgba(255,0,0,.25)">
       </circle>
       <circle cx="50" cy="50" r="25" fill="rgba(255,0,0,.5)"></circle>
       <circle cx="100" cy="100" r="50" fill="rgba(255,0,0,.75)">
       </circle>
       <circle cx="200" cy="200" r="100" fill="rgba(255,0,0,1)">
       </circle>
</svg>
```

# 可伸缩的矢量图形

现在您已经看到了使用 SVG 创建的绘图示例，可能有必要花一点时间解释 SVG 中的*VG*以及为什么这使文件格式可*伸缩*。

对于光栅（位图）文件格式，您可能熟悉的格式有 JPG、PNG 或 GIF。您可以将图像数据视为逐像素存储，因此图像中的每个点都存储在文件中，并由浏览器或图形程序逐像素和逐行读取。图像的大小和质量受到创建时的大小和质量的限制。

所有位图文件格式都有优化，限制了实际存储的数据量。例如，GIF 使用 LZ77 算法将冗余像素折叠到一个回指器和参考像素中。想象一下，如果您的图像有`100`个纯黑像素排成一行。该算法将搜索图像以找到相同字节的序列，当遇到序列时，算法将向后搜索文档，以找到该模式的第一个实例。然后，它将用指令（回指器）替换所有这些像素，指示向后搜索多少个字符以及复制多少像素以填充相同字节的数量。在这种情况下，它将是`100`（要搜索的像素）和`1`（要复制的像素）。

矢量图形，另一方面，是由矢量和控制点定义的。为了显著简化，您可以将矢量图形视为描述线条形状的一组数字。它们可能是一组特定的点，也可能是，就像之前的圆的情况一样，一组关于如何创建特定类型对象的指令。`circle`元素并不存储组成圆的每个像素。它存储用于创建圆的*参数*。

为什么这很酷？一个原因是因为它只是一组定义形状的指令，您可以放大或缩小，渲染引擎将根据需要计算新值。因此，矢量图形可以无限缩放而不会失去保真度。

如果这一切对您来说很困惑，不要担心。您与它们一起工作得越多，您就会越熟悉矢量图形的工作方式。与此同时，以下一组示例和图表将有助于说明差异。首先，看看以下标记。它表示四个图像，使用完全相同的 SVG 图像作为源。该图像代表 SVG 标志。尺寸设置为图像的自然大小，然后是`2x`，`4x`和`8x`，图像的自然大小：

```xml
      <img src="img/svg-logo-h.svg" width="195" height="82" alt="The SVG 
       logo at natural dimensions">
      <img src="img/svg-logo-h.svg" width="390" height="164" alt="The SVG 
       logo 2x">
      <img src="img/svg-logo-h.svg" width="780" height="328" alt="The SVG
       logo 4x">
      <img src="img/svg-logo-h.svg" width="1560" height="656" alt="The SVG
       logo 8x">
```

在浏览器中呈现，该标记产生以下结果。请注意，它一直清晰到`8x`，即原始大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/3aeffac4-e935-4440-bc84-9965b1f3c925.png)

现在，再看看相同的标记，这次是 PNG 格式。它遵循相同的模式：

```xml
      <img src="img/svg-logo-h.png" width="195" height="82" alt="The SVG
       logo at 'natural' dimensions">
      <img src="img/svg-logo-h.png" width="390" height="164" alt="The SVG 
       logo 2x">
      <img src="img/svg-logo-h.png" width="780" height="328" alt="The SVG
       logo 4x">
      <img src="img/svg-logo-h.png" width="1560" height="656" alt="The SVG
       logo 8x">
```

但现在，看结果。注意，在自然级别上，SVG 和 PNG 之间没有区别。PNG 中的像素足以匹配 SVG 版本中定义的矢量线。此外，注意随着图像变大，图像变得越来越糟。浏览器无法从位图格式中获取更多信息（更多像素）来填补较大尺寸的细节。它只是放大它拥有的像素，结果非常糟糕（特别是在`8x`级别）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/9c4098b0-00c5-45b6-a830-5c1034876c88.png)

# 在 CSS 中使用 SVG

SVG 的常见用法是作为 CSS 中的背景图像。在**响应式网页设计**（**RWD**）方面，这种方法在文件大小和可伸缩性方面都有好处。在今天的多设备、多形态因素的世界中，能够以一系列设备尺寸和分辨率（包括高像素密度设备）提供高质量图像的能力是非常重要的。虽然对于光栅显示图像有优化的解决方案（以`picture`元素和`srcset`和`sizes`属性的形式）并且你可以使用媒体查询在 CSS 中呈现不同的图像或图像尺寸，但是能够为所有设备做一张图像是非常重要的。CSS 中的 SVG 使我们能够轻松实现这一点

虽然你将在第五章中学习 SVG 和 CSS 的交集，*使用 SVG 和 CSS*，现在让我们看一个基本的例子来激发你的兴趣。

以下页面有一个类为 header 的`div`标签。这里唯一需要注意的是`background`属性的`url`值中引用了一个 SVG 文件：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- Using SVG images in CSS</title>
        <style type="text/css">
            .header {
                color: #ffffff;
                background: url(1-3-gradient.svg) repeat-x;
                width: 500px;
                height: 40px;
                text-align: center;
            }
        </style>
    </head>
    <body>
      <div class="header"><h1>CSS!</h1></div>
    </body>
</html>
```

这段代码在浏览器中运行时会产生以下效果。这个简单的例子与任何其他 CSS 实现没有区别，它将在不损失渐变平滑度的情况下适应最高像素每英寸的显示。这是通过简单地使用 SVG 实现的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/21cd0ee6-a414-4161-8f73-3a59f18fe542.png)

# SVG 中的渐变

当你继续学习基本的 SVG 用法时，我将继续引入 SVG 本身创作的新概念。我将向你介绍的下一个功能是`defs`部分、`gradient`元素和`rect`元素。

以下示例显示了前一个示例中 SVG 元素的源。除了根`svg`元素本身之外，其他所有内容都与前一个示例不同。

首先是`defs`元素。`defs`是一个组织元素，旨在保存以后在文档中使用的图形对象的定义。我们立即遇到了`linearGradient`元素，它定义了（你猜对了！）线性渐变。`x1`、`x2`、`y1`和`y2`定义了渐变的*渐变向量*。你将在第二章中了解更多，*使用 SVG 和 CSS*，但现在只需知道它定义了渐变的方向。默认值是`0`在左边，`1`在右边。将`x2`设置为`0`，`y2`设置为`1`会将角度从水平左到右的渐变改变为垂直上到下的渐变。

渐变的外观实际上是由子`stop`元素定义的。每个都有两个属性，`offset`和`stop-color`。偏移接受百分比或`0`到`1`之间的数字，表示渐变停止在渐变向量的整体上的位置。这个例子是最简单的：`0%`处有一种颜色，`100%`处有另一种颜色。`stop-color`接受任何有效的颜色值：

```xml
<svg width="10" height="40" viewBox="0 0 10 40" version="1.1" >
 <defs>
 <linearGradient id="gradient" x1="0" x2="0" y1="0" y2="1">
 <stop offset="0%" stop-color="#999999"/>
 <stop offset="100%" stop-color="#000000"/>
 </linearGradient>
 </defs>
 <rect x="0" y="0" width="10" height="40" fill="url(#gradient)"/>
</svg>
```

由于这些只是关于如何渲染渐变的说明，在这种情况下可以拉伸和移动背景图像而不会损失保真度。浏览器将计算新值并渲染新的完美渐变。

以下示例显示了对 CSS 的调整，将标题拉伸到浏览器高度的一半（使用`vh`单位），并强制标题背景图像填充可用空间（`background: size: contain`）：

```xml
<!doctype html>
<html lang="en">
 <head>
   <meta charset="utf-8">
   <title>Mastering SVG- Using SVG images in CSS</title>
   <style type="text/css">
  .header {
   color: #ffffff;
   background: url(1-3-gradient.svg) repeat-x;
   width: 500px;
   height: 50vh;
   text-align: center;
   background-size: contain;
  }
  </style>
 </head>
 <body>
   <div class="header"><h1>CSS!</h1></div>
 </body>
</html>
```

如您在以下截图中所见，相同的背景图像可以轻松调整大小。正如您将学到的那样，对 SVG 可以做的任何其他事情也是如此。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/5749eacd-f797-4f7c-ab31-f6a8f8f5fdc6.png)

# 直接在 HTML 文档中嵌入 SVG

在我看来，SVG 最令人兴奋的用途是作为 HTML 文档中的内联元素。虽然您将了解 SVG 图像作为单独的文件格式以及 SVG 图像可以用于开发现代 Web 应用程序的所有方式，但本书的大部分内容将向您展示如何与直接嵌入文档的 SVG 元素进行交互。这很重要，因为无法对外部引用的 SVG 文件的各个元素进行动画或以其他方式进行操作；只有在页面上直接（通过**文档对象模型**（**DOM**））可用 SVG 元素时才可能。

以下示例显示了一个简单的内联 SVG 图像，其中包含三个圆圈，并展示了在使用内联 SVG 时您拥有的最强大的工具之一：CSS！CSS 可以用来以与样式常规 HTML 元素相同的方式来样式化 SVG 元素。这打开了一系列可能性。这里使用的属性可能对您来说是新的，因为它们是特定于 SVG 的，但就像您习惯的`background-color`或`border`属性一样，您可以使用 CSS 调整 SVG 元素的基本外观和感觉。在下一个示例中，CSS 为所有圆圈定义了默认的`fill`颜色，为第二个圆圈添加了`border`，然后更改了第三个圆圈的`fill`颜色。如果您还没有计划如何使用 CSS 来操作 SVG 元素，那么请放心，阅读完第五章之后，您将有很多想法：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG - Using SVG images in CSS</title>
        <style type="text/css">
            circle {
              fill: rgba(255,0,0,1);
            }
            .first {
              opacity: .5;
            }
            .second {
              stroke-width: 3px;
              stroke: #000000;
            }
            .third {
              fill: rgba(0,255,0,.75);
            }
        </style>
    </head>
    <body>
      <svg width="400" height="250" viewBox="0 0 400 250" version="1.1"
       >
        <circle cx="100" cy="100" r="25" class="first"></circle>
        <circle cx="200" cy="100" r="25" class="second"></circle>
        <circle cx="300" cy="100" r="25" class="third"></circle>
        </svg>
    </body>
</html>
```

打开浏览器将显示所有 CSS 的结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/930a3792-57a0-458a-970a-0a0eccb1f858.png)

# 特性检测和 Modernizr

尽管全球网络对 SVG 的整体支持（[`caniuse.com/#search=svg`](https://caniuse.com/#search=svg)）现在非常高，但并不一致，仍然存在不支持 SVG 的浏览器。这就是特性检测库 Modernizr 可以派上用场的地方。如果您的用户群广泛，或者您正在使用更新的（甚至是实验性的）功能，您可以使用 Modernizr 来检测浏览器对重要功能的兼容性，并相应地调整您的代码。

这种工作有两种方式。一种是 Modernizr 可以放置在 HTML 元素上的类。另一种是全局 Modernizr 对象，其中包含所有测试结果作为*布尔值*。在我们继续之前，我将向您展示这两种工具的示例。

Modernizr 项目提供了数百个测试。由于某些测试相当昂贵（在计算所需资源方面），因此在使用 Modernizr 时，您希望仅使用您的应用程序所需的测试。在这种情况下，我创建了一个特定的 Modernizr 构建，用于测试多个 SVG 功能，而不测试其他内容。将此文件添加到 HTML 页面后，将向 HTML 元素添加类，指示对各种 SVG 功能的支持

以下是 Microsoft Edge 中 HTML 元素的输出。 `no-smil`类表示 Edge 不支持**同步多媒体集成语言**（**SMIL**），但支持我们正在测试的其他所有内容：

```xml
<html class=" svg svgclippaths svgforeignobject svgfilters
 no-smil inlinesvg svgasimg" lang="en">
```

最新 Chrome 版本的输出显示支持所有测试功能：

```xml
<htmlclass=" svg svgclippaths svgforeignobject svgfilters smil 
 inlinesvg svgasimg" lang="en" >
```

最后，Internet Explorer 8（IE8）根本不支持 SVG：

```xml
<HTML class=" no-svg no-svgclippaths no-svgforeignobject no-svgfilters 
 no-smil no-inlinesvg no-svgasimg" lang="en">
```

使用这些类可以让您为 IE8 提供 PNG`fallback`功能，例如为 CSS 背景图像提供支持：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- Modernizr</title>
        <style type="text/css">
            .header {
                color: #ffffff;
                background: url(1-3-gradient.svg) repeat-x;
                width: 500px;
                height: 40px;
                text-align: center;
            }
            .no-svg .header {
                background: url(1-3-gradient.png) repeat-x;
              }
        </style>
    </head>
    <body>
      <div class="header"><h1>CSS!</h1></div>
    </body>
</html>
```

正如前面提到的，Modernizr 还公开了一个全局 Modernizr JavaScript 对象，其中包含每个可用测试的布尔值。以下示例显示了如何访问该布尔值，并使用`if`语句对代码进行近似处理，具体取决于 SVG 是否受支持：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- Monderizr JavaScript Object</title>
        <script src="img/modernizr-custom.js"></script>
      </head>
    <body>
      <script>
        if (Modernizr.svg){
          // do things with SVG
        } else {
          //create a non-SVG fallback
        }
      </script>
    </body>
</html>
```

一般来说，本书的其余部分不会专注于老版本浏览器的`回退`，但如果你在需要支持广泛的浏览器和设备的环境中工作，了解它们的存在是很有用的。

# 总结

在本章中，我们学习了关于 SVG 的基础知识，包括几个 SVG 特定的元素，如`circle`，`text`，以及用于创建 SVG 渐变的元素。我们还学习了在 HTML 文档中以及在 CSS 中将 SVG 用作背景图像的几种方法。

我们还学习了关于 Modernizr 特性检测库以及如何使用它为不支持 SVG 或特定 SVG 功能的浏览器创建`回退`。

在第二章中，*开始使用 SVG 进行创作*，你将学习更多关于 SVG 功能的知识，扩展你对创作 SVG 文档的了解。


# 第二章：使用 SVG 进行创作的入门

现在您已经初步了解了 SVG，是时候更深入地了解常见的 SVG 元素及其用法了。本章将重点介绍最常见的 SVG 元素及其用法，深入介绍您已经学习过的一些元素，并介绍您在创建 SVG 图像时将使用的许多其他元素。

本章将涵盖以下主题：

+   基本 SVG 形状

+   SVG 定位系统

+   渐变和图案

+   使用软件程序生成的 SVG 图像，例如 Adobe Illustrator、Inkscape 和 Sketch

# SVG 中的定位

如您在第一章中所见，*介绍可伸缩矢量图形*，SVG 元素使用坐标平面定位系统。SVG 文档中的元素使用*x*和*y*坐标来定位。这对您来说应该很熟悉，因为您在几何课程中或者更具体地说，在网页上使用 CSS 时，您已经习惯了绝对定位的元素。以下代码展示了您已经在圆元素和矩形元素上看到的定位方案的两种变化，圆元素使用(`cx`，*center x)*和(`cy`，*center y)*属性来基于圆的中心放置`circle`元素，而`rect`元素将使用`x`和`y`属性来在坐标平面上放置正方形的左上角：

```xml
     <svg  width="350" height="150"
       viewBox="0 0 350 150" version="1.1"> 
        <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,1)"/> 
        <rect x="200" y="25" width="100" height="100" 
         fill="rga(0,0,255,1)"/> 
      </svg> 
```

在浏览器中呈现的效果如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/076383f9-55e3-4c21-93cc-6f3c730dcbe7.png)

除了使用两个中心属性来基于其中心放置元素，*x*和*y*，这应该看起来就像在 CSS 中定位元素一样。有趣的地方在于`height`和`width`的交集以及 SVG 元素本身的`viewBox`属性的值。

# SVG 中的 viewBox 和视口

`height`和`width`属性定义了 SVG 元素的*视口*。视口可以被视为与浏览器中的视口相同。它定义了 SVG 文档的可见尺寸。底层 SVG 文档的尺寸可以大于视口，并且与 HTML 一样，元素可以完全不在屏幕上。所有可见的内容都在视口的尺寸内。

如果您只设置 SVG 元素的`height`和`width`属性，并且不使用`viewBox`属性，它将以与您在 CSS 中使用的方式相同的方式运行。在前面的例子中，视口坐标系统将以坐标`(0,0)`开始，并以`(350, 150)`结束。

在本书中，坐标将呈现为(`x`值，`y`值)。

在这种情况下，每个用户单位默认为屏幕上的一个像素。

`viewBox`属性允许您更改初始视口坐标系统。通过重新定义该坐标系统，您可以以有趣的方式移动和缩放底层 SVG 文档。让我们看一些例子，而不是试图*描述*可能发生的事情。

到目前为止，我们展示的每个例子都使用了`viewBox`属性，并且它被设置为与视口的`height`和`width`属性的尺寸相匹配。如果我们改变 SVG 元素的`height`和`width`属性，并且不改变`viewBox`以匹配，会发生什么？添加一个新的 SVG 元素，其`height`属性和`width`属性等于原始值的两倍，会创建一个两倍大小的图像的第二个版本：

```xml
     <svg  width="700" height="300" 
       viewBox="0 0 350 150" version="1.1"> 
        <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,1)"/> 
        <rect x="200" y="25" width="100" height="100" 
         fill="rga(0,0,255,1)"/> 
      </svg> 
```

在浏览器中的效果如下。如您所见，视口已经加倍，但由于`viewBox`具有相同的尺寸，`circle`和`rect`元素上的确切坐标仍会创建图像的放大版本。在这种情况下，用户单位不再等同于一个像素，但 SVG 元素内部的计算仍然保持不变：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/8d718d17-2dc6-4d61-bf3f-9615ad69d6a5.png)

您可以将其放大到任意大小，它都会完美呈现。

如果我们调整`viewBox`属性本身会发生什么？`viewBox`属性的值代表什么？

`viewBox`属性有四个参数：`min-x`、`min-y`、`width`和`height`。`min-x`和`min-y`定义了`viewBox`的左上角。现在，`width`和`height`确定了`viewBox`的宽度和高度。调整这些值可以显示它们如何与视口的高度和宽度交互。前两个示例改变了视口坐标系的*x*和*y*位置。第一个示例将其正向偏移了 20%（70 和 30 分别是 SVG 宽度和高度的 20%）。第二个示例将其负向偏移了 20%。第三个示例改变了`viewBox`属性的宽度和高度，将其缩小了一半：

```xml
<svg  width="350" height="150" viewBox="70 30 350 150" version="1.1"> <circle cx="100" cy="75" r="50"
  fill="rgba(255,0,0,1)"/> <rect x="200" y="25" width="100" 
  height="100" fill="rga(0,0,255,1)"/> </svg> 
<svg  width="350" height="150" 
 viewBox="-70 -30 350 150" version="1.1"> <circle cx="100" cy="75" 
 r="50" fill="rgba(255,0,0,1)"/> <rect x="200" y="25" width="100" height="100" fill="rga(0,0,255,1)"/> </svg> 
<svg  width="350" height="150" 
 viewBox="0 0 175 75" version="1.1"> <circle cx="100" cy="75" r="50"
 fill="rgba(255,0,0,1)"/> <rect x="200" y="25" width="100" height="100" 
 fill="rga(0,0,255,1)"/> </svg> 
```

在浏览器中呈现，你可以看到`viewBox`属性的这些变化效果。偏移移动了圆和正方形，使其相对于视口的左上角更接近。将`viewBox`属性的大小缩小一半，并保持`rect`和`circle`的大小不变，实际上使渲染元素的大小加倍。视口保持相同大小，因此`viewBox`属性和相关的用户单位按比例放大了两倍。其中的所有元素都按需放大：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/b93e1b64-083b-4385-9195-4bb01af354d4.png)

以下图表显示了更深入的工作原理（黑色轮廓覆盖层代表`viewBox`视口）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/f15b03dc-6375-46a7-9ca9-5797364429de.png)

在 SVG 中仍有更多关于定位的知识需要学习，但我们将在本书的其余部分逐步解决这些问题。

现在让我们更深入地了解一些构成 SVG 体验的其他元素。

# 引入路径

在 SVG 规范中，最重要的元素是`path`元素。`path`允许您使用作为`d`属性值传递的一系列命令来绘制线条和形状。还记得我提到过 SVG 采用的最大障碍之一是缺乏友好的 API 吗？这个`path`元素很可能是整个规范中最大的痛点。您可能在`d`属性中看到的值可能非常密集且难以阅读。有多难以阅读？看看 SVG 标志中的*S*元素：

```xml
<path id="S" d="M 5.482,31.319 C2.163,28.001 0.109,23.419 0.109,18.358 C0.109,8.232 8.322,0.024 18.443,0.024 C28.569,0.024 36.782,8.232 36.782,18.358 L26.042,18.358 C26.042,14.164 22.638,10.765 18.443,10.765 C14.249,10.765 10.850,14.164 10.850,18.358 C10.850,20.453 11.701,22.351 13.070,23.721 L13.075,23.721 C14.450,25.101 15.595,25.500 18.443,25.952 L18.443,25.952 C23.509,26.479 28.091,28.006 31.409,31.324 L31.409,31.324 C34.728,34.643 36.782,39.225 36.782,44.286 C36.782,54.412 28.569,62.625 18.443,62.625 C8.322,62.625 0.109,54.412 0.109,44.286 L10.850,44.286 C10.850,48.480 14.249,51.884 18.443,51.884 C22.638,51.884 26.042,48.480 26.042,44.286 C26.042,42.191 25.191,40.298 23.821,38.923 L23.816,38.923 C22.441,37.548 20.468,37.074 18.443,36.697 L18.443,36.692 C13.533,35.939 8.800,34.638 5.482,31.319 L5.482,31.319 L5.482,31.319 Z"/> 
```

不知道发生了什么，是不可能解析的，即使知道`d`属性的规则，也很难跟踪。

让我们看一个更简单的例子，以便你能理解语法。在这个文档中，我们创建了一个风格化的字母 R。以下是如何阅读`d`属性的指令：

1.  (M)ove to point `(100,100)`.

1.  画一条(L)线到`(100,300)`。

1.  画一条(L)线到`(150,300)`。

1.  画一条(L)线到`(150,150)`。

1.  从当前点绘制(S)平滑立方贝塞尔曲线到点`(150,175)`，第二个控制点为`(250,150)`。控制点提供用于绘制曲线的方向信息。这个版本的立方贝塞尔`curveto`指令实际上是控制点被反射的简写。在其他格式中，可以定义指向不同方向的多个控制点。这将创建一个更复杂的曲线。

1.  画一条(L)线到`(200,300)`。

1.  画一条(L)线到`(250,300)`。

1.  画一条(L)线到`(225,225)`。

1.  从当前起始点绘制(S)平滑立方贝塞尔曲线到点`(100,100)`，第二个控制点为`(350,100)`：

```xml
<svg  width="500" height="500" viewBox="0 0 500 500" version="1.1"> 
        <path d="M100,100 L100,300 L150,300 L150,150 S250,150,175,200 L200,300 L250,300 L225,225 S350,100,100,100" stroke-width="1" stroke="#003366" fill="#cccccc"></path> 
</svg> 
```

在浏览器中呈现，这些命令产生以下结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1ec9c126-a3cd-4db4-9a18-3d8407a76cb6.png)

这一系列的说明仍然很复杂，甚至没有涉及`path`元素的所有可能选项。好消息是，当您使用 SVG 时，大多数时候这些复杂的`path`将被生成 - 要么由您自己（使用图形 SVG 编辑器），要么通过 JavaScript。因此，实际上，您只需要能够理解说明和它们的用法。您不需要坐在那里逐条解析这些数据指令。

# 更多关于基本形状

现在您已经了解了`path`，让我们来看看 SVG 宇宙中更直接的部分，并且让我们检查一些更基本的形状。您已经了解了`circle`和`rect`。让我们看看一些更基本的形状。

# 线元素

`path`元素允许您使用一长串的说明来绘制您能想象到的任何东西。值得庆幸的是，有许多方便的元素定义了比`path`元素更容易处理的常见形状。其中您将学习的第一个是`line`元素。

以下示例在一个`500`乘`500`的正方形上绘制了一个网格。这里使用的`line`元素需要五个参数：`x1`，`y1`，`x2`，`y2`和`stroke`。*x*和*y*坐标表示线的起点（`x1`，`y1`）和终点（`x2`，`y2）。这个 SVG 文档在一个`500`像素的正方形中绘制了每边`100`像素的网格：

```xml
    <svg version="1.1"  
        width="500" height="500" viewBox="500 500 0 0"> 
        <line stroke="#000000" x1="0" y1="0" x2="0" y2="500" /> 
        <line stroke="#000000" x1="100" y1="0" x2="100" y2="500" /> 
        <line stroke="#000000" x1="200" y1="0" x2="200" y2="500" /> 
        <line stroke="#000000" x1="300" y1="0" x2="300" y2="500" /> 
        <line stroke="#000000" x1="400" y1="0" x2="400" y2="500" /> 
        <line stroke="#000000" x1="500" y1="0" x2="500" y2="500" /> 
        <line stroke="#000000" x1="0" y1="0" x2="500" y2="0" /> 
        <line stroke="#000000" x1="0" y1="100" x2="500" y2="100" /> 
        <line stroke="#000000" x1="0" y1="200" x2="500" y2="200" /> 
        <line stroke="#000000" x1="0" y1="300" x2="500" y2="300" /> 
        <line stroke="#000000" x1="0" y1="400" x2="500" y2="400" /> 
        <line stroke="#000000" x1="0" y1="500" x2="500" y2="500" /> 
      </svg> 
```

在浏览器中呈现，前面的标记产生了以下网格：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/44bd8c61-3400-4e40-8877-2637debf5ddb.png)

顺便说一句，生成这样的网格对生成和调试 SVG 文档很有帮助。在网格上有更细粒度的网格时，您可以更容易地确定屏幕上计算或手动生成的位置。

# 椭圆元素

`ellipse`就像`circle`一样，只是它需要*两个半径*参数，`rx`和`ry`分别代表*x*和*y*的半径。由于需要额外的半径参数，否则我们只会画一个标准的圆：

```xml
      <svg width="250" height="100" viewBox="0 0 250 100" 
         > 
        <ellipse cx="125" cy="50" rx="75" ry="25" 
         fill="rgba(255,127,0,1)"/> 
      </svg> 
```

以下是直接标记的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/75731a0d-fd92-4b16-bf29-fa5b22c9b6dc.png)

# 多边形元素

`polygon`元素创建由多条直线组成的*封闭*形状，从初始`x，y`坐标开始，并以坐标平面上的最终点结束。`points`属性接受坐标平面上的点列表来定义`polygon`元素。`polygon`元素的最终点会自动连接到第一个点。以下代码示例绘制了一个星星：

```xml
<svg width="240" height="240" viewBox="0 0 240 240" 
  > 
        <polygon points="95,95 120,5 150,95 235,95 165,150 195,235
         120,180 50,235 75,150 5,95" fill="rgba(0,0,255,1)"></polygon> 
</svg> 
```

以下显示了前面 SVG 元素的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/cf25a9a8-ae58-4c18-9431-e846e7844f53.png)

对于`polygon`和`polyline`，这只是一个建议，而不是将`x，y`对用逗号分隔的要求。

以下代码在程序上等同于前面的例子（尽管更难阅读）。它呈现了完全相同的形状：

```xml
<svg width="240" height="240" viewBox="0 0 240 240" 
  > 
   <polygon points="95 95 120 5 150 95 235 95 165 150 195 235 120 
     180 50 235 75 150 5 95" fill="rgba(0,0,255,1)"></polygon> 
 </svg> 
```

# 折线元素

`polyline`元素创建由多条直线组成的*开放*形状。`points`属性接受坐标平面上的`x，y`点列表来定义`polyline`。以下代码示例跟踪了天空中龙座的图案：

```xml
<svg width="800" height="600" viewBox="0 0 400 300" 
   > 
   <polyline points="360,60 330,90 295,160 230,220 190,217
    175,180 155,130 155,60 135,30 100,25 90,55 65,170 80,195 
    65,220 35,210 65,170" fill="none" stroke="white" stroke-width="3"> 
    </polyline> 
</svg> 
```

在浏览器中运行，前面的例子看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/35eebdb5-2607-4906-8d0b-913440737686.png)

# 更多关于填充和描边

您已经在大多数示例中看到了它们的使用，现在让我们更全面地了解一下填充和描边。这些表示属性对 SVG 很重要，特别是在动态工作时，因为与编写动态 CSS 相比，直接操作元素要容易得多。

`fill`和`stroke`被统称为`paint`属性。`fill`设置对象的内部颜色，`stroke`设置对象周围绘制的线的颜色。正如您已经看到的，它们可以接受任何有效的 CSS 颜色值。它们还可以接受对*绘画服务器元素*的引用（这些是`hatch`、`linearGradient`、`meshgradient`、`pattern`、`radialGradient`和`solidcolor`），这些元素定义了元素的绘画样式。您已经看到了其中一个（`linearGradient`），很快将了解更常见的支持。然而，在您这样做之前，现在是时候看一看一些控制线条外观和拟合的特定于描边的属性了。

# stroke-dasharray

`stroke-dasharray`属性定义了一个逗号和/或空格分隔的长度或百分比列表，指定了用于描边线的虚线和间隙的交替模式。以下示例显示了几个不同的示例。第一个是一系列 10 像素的开和 5 像素的关。第二个示例根据斐波那契数列打开和关闭像素。第三个系列根据质数系列打开和关闭像素：

```xml
<svg width="400" height="300" viewBox="0 0 400 300" 
  > 
  <rect x="50" y="20" width="300" height="50" fill="none" 
    stroke="#000000" stroke-width="4"  stroke-dasharray="10 5"></rect> 
  <rect x="50" y="80" width="300" height="50" fill="none" 
   stroke="#000000" stroke-width="4"  stroke-dasharray="1, 2, 3, 5, 8, 
    13"></rect> 
  <rect x="50" y="140" width="300" height="50" fill="none" 
    stroke="#000000" stroke-width="4"  stroke-dasharray="2, 3, 5, 7, 
     11, 13, 17, 19"></rect> 
 </svg> 

```

在浏览器中呈现，上述代码产生以下示例：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e2025b07-1ba6-4eba-969d-b3e61f798f48.png)

如果提供的值作为属性的值的数量是奇数，则列表将重复以产生偶数个值。这可能不会产生您期望的模式，因为值可能会从虚线转移到空格，并产生意想不到的结果。在以下示例中，单个值`10`产生`10`开和`10`关，这可能是您预期的结果。另一方面，`"15,10,5"`模式产生`15`开，`10`关，`5`开，`15`关，`10`开和`5`关。如果您期望模式始终将`15`作为“开”，那么这可能会让您感到惊讶。

```xml
 <svg width="400" height="300" viewBox="0 0 400 300"
    > 
    <rect x="50" y="20" width="300" height="50" fill="none" 
     stroke="#000000" stroke-width="4"  stroke-dasharray="10"> 
    </rect> 
    <rect x="50" y="80" width="300" height="50" fill="none" 
      stroke="#000000" stroke-width="4"  stroke-dasharray="15,10,5">
    </rect> 
  </svg> 
```

您可以在浏览器中看到这一点。这可能是您想要的外观，但如果不是，现在您知道原因了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/47f7ec9e-eade-4984-bcb8-bb8df372e6fe.png)

# stroke-dashoffset

`stroke-dashoffset`属性接受正值或负值的长度或百分比，并指定开始渲染虚线的虚线模式的距离。这个偏移量可以在以下代码示例中看到：

```xml
<svg width="400" height="300" viewBox="0 0 400 300"  
 >
 <rect x="50" y="20" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="4" stroke-dasharray="10 10"></rect>
 <rect x="50" y="80" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="4" stroke-dasharray="10 10" stroke- 
  dashoffset="25"></rect>
 <rect x="50" y="140" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="4" stroke-dasharray="10 10" stroke-
  dashoffset="-25"></rect>
</svg>
```

这个属性的效果可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/9f8fde1a-648d-44d7-9e2b-ccd0bcc31383.png)

# stroke-linecap

`stroke-linecap`属性指示在开放线的末端呈现的形状。选项包括`butt`、`round`、`square`和`inherit`。以下代码示例展示了不同的渲染选项。两条红线是为了显示`butt`和`square`之间的区别。`butt`使`stroke`与线的末端齐平。`square`端延伸到线的末端，包括`stroke`的厚度： 

```xml
<svg  width="500" height="400"
   viewBox="0 0 500 400" version="1.1"> 
 <line fill="none" stroke-width="20" stroke="#000000" x1="20" y1="100" 
    x2="450" y2="100" stroke-linecap="butt" /> 
 <line fill="none" stroke-width="20" stroke="#000000" x1="20" y1="200"
    x2="450" y2="200" stroke-linecap="round" /> 
 <line fill="none" stroke-width="20" stroke="#000000" x1="20" y1="300"
    x2="450" y2="300" stroke-linecap="square" /> 
 <line fill="none" stroke-width="2" stroke="rgba(255,0,0,1)" x1="20" 
    y1="0" x2="20" y2="400" /> 
 <line fill="none" stroke-width="2" stroke="rgba(255,0,0,1)" x1="450" 
    y1="0" x2="450" y2="400" /> 
</svg> 
```

这个结果可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1782030a-be88-4926-9da7-50084b773ba7.png)

# stroke-linejoin

`stroke-linejoin`属性定义了`path`和基本形状的拐角的呈现方式。可能的值有`miter`、`round`、`bevel`和`inherit`。`Round`呈现平滑的曲线角，`miter`产生只有一个角的尖边，`bevel`在角上添加一个新的角来创建一个复合角：

```xml
  <svg width="400" height="300" viewBox="0 0 400 300" 
    > 
  <rect x="50" y="20" width="300" height="50" fill="none" 
    stroke="#000000" stroke-width="20"  stroke-linejoin="miter"></rect> 
  <rect x="50" y="100" width="300" height="50" fill="none" 
     stroke="#000000" stroke-width="20"   stroke-linejoin="bevel">  
  </rect> 
  <rect x="50" y="180" width="300" height="50" fill="none" 
     stroke="#000000" stroke-width="20"  stroke-linejoin="round">
   </rect> 
 </svg> 
```

这些选项可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/bb037f61-1dd0-4512-b36d-2b1e7b8b1cd7.png)

# stroke-opacity

`stroke-opacity`属性的作用与您预期的一样。它设置了描边对象的不透明度。以下示例在三个单独的矩形上设置了三种不同的不透明度。您可以看到`stroke`不仅与页面的背景交互，还与矩形的填充区域交互，因为`stroke`位于矩形边缘的中心，并且部分覆盖了填充区域：

在 SVG 元素上没有简单的方法来更改`stroke`属性的定位。在图形程序中，可以将`stroke`属性设置为在框的内部、在框的边缘上居中（这是 SVG 的做法）和在框的外部。在新的 SVG strokes ([`www.w3.org/TR/svg-strokes/`](https://www.w3.org/TR/svg-strokes/))规范中有一个提案来更改`stroke`的对齐方式（称为 stroke-alignment），但目前浏览器中还没有这样的功能。

```xml
<svg width="400" height="300" viewBox="0 0 400 300" 
  >
 <rect x="50" y="20" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="20" stroke-opacity=".25"></rect>
 <rect x="50" y="100" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="20" stroke-opacity=".5"></rect>
 <rect x="50" y="180" width="300" height="50" fill="none"
  stroke="#000000" stroke-width="20" stroke-opacity="1"></rect>
</svg>
```

前面代码的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/08f5190d-b200-48be-813e-03fcba8be4a9.png)

现在我们已经看过了`stroke`的不同选项，是时候看看一些其他填充选项了。这些是我们之前提到的绘图服务器元素。您已经遇到了其中之一，`linearGradient`。您还将了解另外两个常用的，`radialGradient`和`pattern`。

# linearGradient 和 radialGradient

您已经在第一章中看到了`linearGradient`元素，*介绍可伸缩矢量图形*。还有`radialGradient`，它的工作方式基本相同，只是它呈现以中心点为中心辐射的渐变。这两个元素都添加到`defs`部分，每个元素都有一系列带有`offset`和`stop-color`的`stop`，定义了渐变。

然后，它们通过它们的`id`属性作为`rect`的`fill`属性的参数引用：

```xml
<svg width="400" height="300" viewBox="0 0 400 300"  
 >
    <defs>
        <linearGradient id="linear">
            <stop offset="5%" stop-color="green"/>
            <stop offset="95%" stop-color="gold"/>
        </linearGradient>
        <radialGradient id="radial">
            <stop offset="10%" stop-color="gold"/>
            <stop offset="95%" stop-color="green"/>
        </radialGradient>
    </defs>
    <rect x="50" y="20" width="100" height="100" fill="url(#radial)">
    </rect>
    <rect x="200" y="20" width="100" height="100" fill="url(#linear)"> 
    </rect>
</svg>
```

这会产生以下输出：

**![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/bc18b819-7837-4a13-adac-ad5c7c7558ea.png)**

# pattern 元素

我们将要看的最后一个绘图服务器是`pattern`元素。`pattern`允许您定义一个小的图形元素，您可以将其引用为`fill`或`stroke`并在元素上以重复的图案平铺。在这个例子中，我们使用了一个`pattern`元素，它有一个单独的子`polygon`元素，定义了两条对角线，组合在一起创建了一个长图案：

```xml
<svg width="400" height="400" viewBox="0 0 400 400" 
 >
    <pattern id="pattern-example" width="100" height="100"
      patternUnits="userSpaceOnUse">
    <polygon points="0,50 0,100 50,50 100,100 100,75 50,25 0,75" 
      fill="#000000"></polygon>
    </pattern>
    <rect x="0" y="0" width="400" height="400" fill="url(#pattern-
     example)"></rect>
</svg>
```

在浏览器中呈现，这会创建以下锯齿状图案：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/2ef53558-7377-4576-908f-a4f2f59c5d6e.png)

# 创作程序

到目前为止，本书中的所有示例都是手工生成的。在实践中，正如您将在本书中了解到的那样，SVG 通常是由软件生成的。本书的大部分内容将涉及使用基于 Web 的工具和库创建和操作 SVG，但 SVG 图像也可以由桌面绘图应用程序生成。在 Web 上工作时，您经常会使用设计师在应用程序中创建的 SVG 图像，例如 Inkscape ([`inkscape.org/en/`](https://inkscape.org/en/))、Adobe Illustrator ([`www.adobe.com/products/illustrator.html`](https://www.adobe.com/products/illustrator.html))或 Sketch ([`www.sketchapp.com/`](https://www.sketchapp.com/))。这些应用程序非常棒，因为它们允许非技术设计师使用高级绘图工具来创建 SVG 图像。

虽然这不是本书的其余部分的要求，但我建议您找到一些可以用来以这种方式编写 SVG 的工具。虽然您希望学习如何在动态的基于 Web 的环境中使用 SVG，但拥有使用高级绘图工具来更新和操作 SVG 元素的选项是很棒的。多年来，我一直在使用 Adobe Illustrator 和 Inkscape，许多人都喜欢 Sketch，所以这是三个开始的选择。对于刚开始，我建议首先看看 Inkscape。Inkscape 是一个免费的开源软件，发布在 GNU 许可下，从功能的角度来看相当不错，所以是一个很好的默认选择。

无论您选择哪个应用程序（甚至如果您不选择任何应用程序，只是继承了一个 SVG 图像），都要知道这些应用程序存在一些缺点。这些应用程序是为了创作体验而设计的，并不会生成为网络优化的 SVG 图像，因此在将由图形程序创建的 SVG 图像导入到网络项目时，要牢记这一点非常重要。您将在本书的后面学习更多关于优化 SVG 图像的知识，但是您应该从一开始就意识到您将面对的挑战。

看一下以下的屏幕截图。它显示了两个渲染完全相同图像的文件之间的差异。左边的是 Inkscape 输出的 SVG 源文件。右边的文件是经过优化的版本。正如您所看到的，Inkscape 文件中有很多额外的数据。这些数据是应用程序所需的，但在网络上并不需要，因此删除它们可以显著减小文件大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/5571d0a1-6b7a-4b87-9626-045e516d07de.png)

您将在第十一章中学习清理 SVG 文件的工具，*优化 SVG 的工具*。

# 总结

在本章中，您了解了多个 SVG 功能。您了解了`path`，它允许您使用线条和曲线绘制复杂的形状。您还了解了一些基本绘图工具，可以用它们来绘制线条、椭圆、多边形和折线。此外，您还了解了一些描边和填充选项。

最后，您了解了使用软件绘制静态 SVG 的选项，并了解了这样做可能存在的一些缺点。

在第三章中，*深入了解 SVG 创作*，您将继续学习 SVG 创作，增加您已经体验过的工具列表，并允许您创建更复杂的 SVG 图像。


# 第三章：深入挖掘 SVG 创作

到目前为止，在这本书中，你已经接触到了大部分基本的 SVG 功能和元素。只用到目前为止你所体验过的工具，你就可以开始使用 SVG 做一些真正的任务了。也就是说，SVG 还有很多其他功能。本章将开始介绍更高级的 SVG 工具。其中一些技术将在进行动态 SVG 动画和可视化方面发挥重要作用。

本章将涵盖以下主题：

+   转换

+   裁剪和遮罩

+   将内容导入 SVG

+   滤镜效果

+   在网络上提供 SVG

所有这些，以及你已经学到的工具，将为你打下坚实的 SVG 基础。

# 转换

SVG 中的变换允许你以各种方式操纵 SVG 元素，包括缩放、旋转、倾斜和平移（看起来像是移动元素，但并不完全是）。使用变换允许你操纵 SVG 而不改变其固有值（例如高度、宽度、*x*和*y*），这在以动态方式操纵元素时很重要。

本节将逐一介绍常见的变换函数，并附上每个函数的示例。

# 平移

`translate`变换通过指定的`x`和`y`坐标移动 SVG 元素。平移改变了元素坐标系的*原点*。

如果没有提供`y`坐标，它是一个可选参数，假定与提供的`x`参数相等。

下面的示例显示了三个等效的圆。第一个圆没有以任何方式进行变换。第二个圆通过单个参数（`10`）进行了变换，它在*x*轴和*y*轴上分别移动了`10`。第三个在*x*平面上平移了`"75"`像素，在*y*平面上没有平移。在每种情况下，底层元素具有等效的度量，但它们显示方式不同。

*你可能会问，为什么不直接移动元素*。首先，在动态 SVG 中，这是有用的，因为如果你移动元素，你不必跟踪元素的原始位置。你可以通过移除变换来简单地将元素重置为其原始状态：

```xml
<svg  width="350" height="150"
  viewBox="0 0 350 150" version="1.1">
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)"/>
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)" 
     transform="translate(10)" />
    <circle cx="100" cy="75" r="50" fill="rgba(255,0,0,.5)"
     transform="translate(75,0)" />
</svg>
```

你可以在下面的截图中看到输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/17e444b7-49eb-4edd-abdd-c2bd1ac9ca57.png)

# 缩放

`scale`变换通过指定的`x`和`y`坐标对 SVG 元素进行缩放。单位是**因子**，因此传入两个将会使元素的尺寸*加倍*。

与`translate`一样，`y`坐标是可选的，如果没有提供，它被假定为与提供的`x`参数相等。

如果你做过 CSS 变换并缩放了一个元素，你可能会对`scale`的工作方式感到惊讶。即使你没有做过 CSS，你也可能会感到惊讶。

在 SVG 中，缩放是从坐标系的*原点*开始的。请看下面的例子，显示了三个单独的方框。一个根本没有缩放。接下来的两个矩形在两个轴上都缩放了`1.25`倍，然后在*x*轴上缩放了`2`倍，而在*y*轴上没有缩放：

```xml
<svg  width="500" height="500"
 viewBox="0 0 500 500" version="1.1">
    <rect x="100" y="100" width="100" height="100" stroke="blue"
     fill="none"></rect>
    <rect x="100" y="100" width="100" height="100" stroke="red"
     fill="rgba(255,0,0,.5)" transform="scale(1.25)"></rect>
    <rect x="100" y="100" width="100" height="100" stroke="red" 
     fill="rgba(255,0,0,.5)" transform="scale(2,1)"></rect>
</svg>
```

正如你在下面的截图中所看到的，结果是元素的尺寸不仅被缩放，而且与坐标系原点的距离也被缩放了。第一个元素在两个方向上都进行了调整，沿着*x*和*y*平面。第二个元素沿着*x*轴向右移动：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/89065f89-d182-4119-a5c8-cfb864fdf250.png)

与下面的代码相比，显示了 CSS 缩放的工作方式。在 CSS 中使用相同的缩放因子会产生完全不同的结果。CSS 不是从 SVG 文档的原点进行缩放，而是从元素本身的中心点进行缩放。语法可能看起来相似，但结果是不同的：

```xml
<head>
<style type="text/css">
    div {
        position: absolute;
        left: 100px;
        top: 100px;
        width: 100px;
        height: 100px;
        border: 1px solid blue;
    }
    .scale-1-25 {
        transform: scale(1.25);
        border: 1px solid red;
        background: rgba(255,0,0,.5);
    }
    .scale-2-by-1 {
        transform: scale(2,1);
        border: 1px solid red;
        background: rgba(255,0,0,.5);
    }
</style>
</head>
<body>
    <div></div>
    <div class="scale-1-25"></div>
    <div class="scale-2-by-1"></div>
</body>
```

结果可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/cb5c86a8-aee2-44ea-8dd8-d8001f4282bd.png)

如果您想要在 SVG 中产生类似的效果，有一个有趣的技巧可以使用。这个技巧也可以用来说明`transform`属性可以接受多个变换函数。您不仅限于一个。

那么，它是如何工作的呢？正如我所提到的，CSS 变换的原点是*被变换的盒子的中心*。这种技术在 SVG 中复制了相同的原点。

要做到这一点，您需要做一个技巧，即将元素的原点移动到一个新的原点，使其与 CSS 原点匹配。这是它的工作原理。在这种情况下，我们的矩形在坐标系中的位置是`(100, 100)`，边长为`100`像素。因此，盒子的中心点位于`(150, 150)`。通过将元素平移`(150,150)`，将这些元素的原点设置为等同于 CSS 原点的位置。请记住，CSS 原点是盒子的中心点（在变换之前是`(150,150)`），平移元素实际上*改变*了它的原点。

在平移之后，我们应用了缩放。这发生在新的原点`(150,150)`处（再次等同于 CSS 原点），并将正方形分别扩大了`1.25`和`2`。最后，我们将元素*返回*到其*原始*原点`(0,0)`，因为它们是在 CSS 等效原点`(150,150)`处进行操作的，所以缩放后的元素现在被适当地居中了：

```xml
<svg  width="500" height="500"
  viewBox="0 0 500 500" version="1.1">
    <rect x="100" y="100" width="100" height="100" stroke="red"
     fill="rgba(255,0,0,.5)"></rect>
    <rect x="100" y="100" width="100" height="100" stroke="red" 
     fill="rgba(255,0,0,.5)" transform="translate(150 150) scale(1.25)
      translate(-150 -150)"></rect>
    <rect x="100" y="100" width="100" height="100" stroke="red" 
     fill="rgba(255,0,0,.5)" transform="translate(150 150) scale(2,1) 
     translate(-150 -150)"></rect>
</svg>
```

以下插图逐步展示了这是如何工作的：

1.  第一帧显示了起始位置。`100`像素的矩形放置在`(100,100)`，它们的原点是`(0,0)`。

1.  然后它们被平移`(150,150)`。

1.  然后，它们从新的原点`(150,150)`处进行了变换，分别为`1.25`和`(2,1)`。

1.  它们被平移到`(0,0)`，同时保持新的缩放。此时它们的实际原点是`(0,0)`，但它呈现出来好像是 CSS 原点`(150,150)`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/2fe40745-aac9-42d7-a491-1d7f86f3c218.png)

# 旋转

`rotate`变换通过一定角度旋转元素。这个变换有三个参数。第一个是角度数。第二个和第三个参数是定义旋转原点的`x`和`y`坐标。如果元素没有旋转原点，则使用视口的原点。这可以在以下两个代码示例中看到，其中在 SVG 元素上绘制了九个矩形。第一个没有被变换。接下来的八个依次旋转了十度：

```xml
<svg  width="700" height="700" 
  viewBox="0 0 700 700" version="1.1">
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)"/>
    <rect x="600" y="0" width="100" height="100" 
      fill="rgba(255,0,0,.5)" transform="rotate(10)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(20)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(30)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(40)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(50)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(60)"/>
    <rect x="600" y="0" width="100" height="100"
      fill="rgba(255,0,0,.5)" transform="rotate(70)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(80)"/>
</svg>
```

如您在渲染代码的下面截图中所见，它们在整个画布上`arc`，并且视口的`(0,0)`点位于旋转的原点：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/fcce9649-bd12-4c9b-aec6-7911ea408214.png)

与之相比，下面的代码将旋转点更改为视口的中心点，以及`x`轴上的顶部和`y`轴上的顶部：

```xml
<svg  width="700" height="700" viewBox="0 0 700 700" version="1.1">
    <rect x="600" y="0" width="100" height="100" 
      fill="rgba(255,0,0,.5)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(10 350 0)"/>
    <rect x="600" y="0" width="100" height="100"  
     fill="rgba(255,0,0,.5)" transform="rotate(20 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(30 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(40 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(50 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(60 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(70 350 0)"/>
    <rect x="600" y="0" width="100" height="100" 
     fill="rgba(255,0,0,.5)" transform="rotate(80 350 0)"/>
</svg>
```

如您所见，当这段代码在浏览器中渲染时，相同角度的旋转`arc`在视口的右上角四分之一中。*正方形从新的原点辐射出来*：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/7bf754e3-4767-4f4e-8711-0a3ed2e81633.png)

与缩放一样，如果您想要围绕元素的中心点旋转，您可以使用在该部分学到的相同平移技巧。在下面的代码示例中，矩形被平移了相当于它们的中心点`(100,100)`，旋转了`10`度，然后又被平移到了它们的原始原点：

```xml
<svg  width="400" height="400" viewBox="0 0 200 200" version="1.1">
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(10) translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(20) 
    translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(30)
     translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(40) 
    translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100"
     fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(50) 
     translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
     fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(60)
     translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100"
     fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(70) 
      translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(80)
     translate(-100,-100)"/>
    <rect x="50" y="50" width="100" height="100" 
    fill="rgba(255,0,0,.2)" transform="translate(100,100) rotate(90) 
    translate(-100,-100)"/>
</svg>
```

这产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/559236ef-62a0-4117-ae8d-bed164d60639.png)

# 倾斜

`skew`变换通过指定的轴沿角度倾斜元素。与`rotate`和`scale`一样，`skew`基于当前原点。以下代码示例显示了两组元素。一组沿着`x`轴倾斜，另一组沿着`y`轴倾斜。对于每组元素，有一个变换专注于`skew`，然后还有另一个相同量的`skew`变换，也包括平移技术：

```xml
<svg  width="500" height="500" viewBox="0 0 500 500" version="1.1">
    <rect x="100" y="100" width="100" height="100"
     fill="rgba(255,0,0,.1)" transform="skewX(10)"/>
    <rect x="100" y="100" width="100" height="100" stroke="blue"
     fill="none"/>
    <rect x="100" y="100" width="100" height="100" 
    fill="rgba(0,255,0,.1)" transform="translate(150,150) skewX(10) 
    translate(-150,-150)"/>
    <rect x="300" y="300" width="100" height="100" stroke="blue" 
    fill="none"/>
    <rect x="300" y="300" width="100" height="100" 
     fill="rgba(255,0,0,.1)" transform="skewY(10)"/>
    <rect x="300" y="300" width="100" height="100" 
    fill="rgba(0,255,0,.1)" transform="translate(300,300) skewY(10)
     translate(-300,-300)"/>
</svg>
```

你可以在以下截图中看到此代码的输出。蓝色正方形显示了原始位置，然后两个倾斜的元素排列在其上，以显示基于原始原点的倾斜和使用平移技术改变原点到元素中心的差异：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/b0ad4118-aa8d-4415-9869-b479a6e51977.png)

还有另一种选项可以变换元素。你可以使用所谓的*变换矩阵*。矩阵变换很强大（它们可以表示任何其他变换函数），但也很复杂，它们严重依赖数学。由于并非每个人都认为数学很有趣，矩阵变换并不像其他变换函数那样常见。因此，我不打算在这里涵盖它们。实际上，你可以用已经学到的方法做任何你需要做的事情。

# 裁剪和遮罩

裁剪和遮罩允许你在 SVG 文档中减去元素的部分。

剪切路径，使用`clipPath`元素实现，可以使用路径、文本元素和基本形状的任意组合作为简单蒙版的轮廓。这意味着`clipPath`元素轮廓内部的所有内容都是可见的，而外部的所有内容都被裁剪掉。`clipPath`中的每个像素要么是打开的，要么是关闭的。

遮罩，使用`mask`元素实现，可以包含图形、文本和基本形状，作为半透明的遮罩。使用遮罩，每个像素值表示不透明度的程度，可以从完全透明到完全不透明。

# 裁剪

SVG 中的`clipPath`元素允许你从另一个形状中裁剪出一个形状。裁剪使用形状的几何图形来定义被裁剪的区域。它不考虑除形状之外的任何东西，因此`stroke`和`fill`等属性不会改变被裁剪的区域。

以下代码示例显示了一个非常简单但非常有用的`clipPath`元素的使用模式。基本效果是切掉一个复杂元素的一半（我们在第二章中绘制的星星，*开始使用 SVG 进行创作*），以便将其放在另一个相同星星的实例上，创建一个红色和黑色的分割星星设计。虽然你可以创建两个星星的一半并将它们放在一起，但混合和匹配相同元素的实例更加灵活。

让我们看看这是如何工作的。

首先，在`defs`部分，我们创建`clipPath`元素本身。`clipPath`的任何子元素都将捆绑在一起，以创建稍后将使用的裁剪模式。在这种情况下，它是一个简单的矩形，覆盖了画布的一半。它的 ID 是`"box"`。接下来，我们创建了一个星星的可重用实例，我们在第二章中创建了它，*开始使用 SVG 进行创作*。我们给它一个 ID 为`"star"`。在`defs`部分之外，我们把它全部放在一起。使用两个`use`元素的实例，它允许你交换在其他地方定义的元素，我们链接到星星的`polygon`，并将其两次插入文档中，一次填充为红色，一次填充为黑色。请注意，用户元素使用片段标识符来引用多边形。`"#star"`是一个有效的相对 URL，指向本页上特定`id`。第二个变体具有一个`clip-path`属性，它链接到我们的`box`，`clipPath`：

```xml
<svg  width="240" height="240" viewBox="0 0 240 240" version="1.1">
    <defs>
        <clipPath id="box" maskUnits="userSpaceOnUse" x="0" y="0"
         width="240" height="240">
            <rect x="120" y="0" width="240" height="240" fill="red" >
            </rect>
        </clipPath>
        <polygon id="star" points="95,95 120,5 150,95 235,95 165,150 
           195,235 120,180 50,235 75,150 5,95"></polygon>
    </defs>
    <use href="#star" fill="red"></use>
    <use href="#star" fill="black" clip-path="url(#box)"></use>
</svg>
```

该代码的输出可以在以下截图中看到。红色的星星实例暴露为黑色星星的左半部分，该部分被`clipPath`元素中定义的正方形剪切掉：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/97c81615-98f0-4dd4-84a6-f5f6c2dbf40f.png)

# 遮罩

遮罩与裁剪相反，考虑了除了元素简单形状之外的属性。正如前面提到的，您可以利用全透明、半透明或完全不透明的像素。这可以产生有趣的效果。

以下示例显示了如何一起使用多个遮罩。在此示例中，我们大量使用`defs`部分，然后使用不同的可重用元素组合图像。

首先，我们创建两个渐变。一个是线性渐变，有五个步骤，大部分是黑色，中间创建了一个非常强烈的白色带。第二个是径向渐变，中心区域是黑色，周围是一个非常大的白色圆圈。将这些用作遮罩意味着这些渐变中的每个像素都落在从完全不透明（黑色像素）到完全透明（白色像素）和中间可变透明度的连续范围上。

单独看这些渐变：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/61079b70-717a-40af-882b-da2b9e524d40.png)

然后，我们创建一个写着“精通 SVG”的`text`元素，并引入一个`pattern`元素，您将从第二章中认识到它，*开始使用 SVG 进行创作*。

在 SVG 元素的主体中，我们链接到文本元素，使用片段标识符（`#mastering-SVG`）指向`defs`部分中`text`元素的 ID，并使用`mask`属性将两个遮罩应用于它们，`mask`属性的`url`值指向`mask`属性的片段标识符。单独看看这些遮罩如何影响文本元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/a10117ff-c916-432c-81d7-3214ecb82327.png)

将所有内容放在一起，我们将两个文本元素叠放在一起，并在文本框后面添加一个带图案的框：

```xml
<svg  width="500" height="120" viewBox="0 0 500 120" version="1.1">
    <defs>
        <linearGradient id="gradient">
            <stop offset="0" stop-color="black" stop-opacity="1" />
            <stop offset=".25" stop-color="black" stop-opacity="1" />
            <stop offset=".5" stop-color="white" stop-opacity="1" />
            <stop offset=".75" stop-color="black" stop-opacity="1" />
            <stop offset="1" stop-color="black" stop-opacity="1" />
        </linearGradient>
        <radialGradient id="highlight-gradient">
            <stop offset=".25" stop-color="black" stop-opacity="1" />
            <stop offset=".75" stop-color="white" stop-opacity="1" />
        </radialGradient>
        <mask id="gradient-mask" maskUnits="userSpaceOnUse" x="0" y="0"
         width="500" height="240">
            <rect y="0" x="0" width="500" height="120" 
             fill="url(#gradient)"></rect>
        </mask>
        <mask id="highlight-mask" maskUnits="userSpaceOnUse" x="0" 
         y="0" width="500" height="240">
            <rect y="0" x="0" width="500" height="120" 
             fill="url(#highlight-gradient)"></rect>
        </mask>
        <text id="mastering-SVG" x="10" y="75" font-size="72" text-
         anchor="left" font-weight="bold">
            Mastering SVG
        </text>
        <pattern id="pattern-example" width="100" height="100" 
         patternUnits="userSpaceOnUse">
            <rect width="100" height="100" fill="darkred" x="0" y="0">
            </rect>
            <polygon points="0,50 0,100 50,50 100,100 100,75 50,25 
              0,75" fill="rgb(83,1,1)">               
            </polygon>
        </pattern>
    </defs>
    <rect x="0" y="0" width="500" height="120" fill="url(#pattern-
      example)"></rect>
    <use href="#mastering-SVG" fill="gold" mask="url(#gradient-mask)" 
     x="120"></use>
    <use href="#mastering-SVG" fill="red" mask="url(#highlight-mask)"></use>
</svg>
```

在浏览器中运行后，我们得到以下输出。您可以看到两个文本元素中可见的黄色区域和红色区域混合在一起。中心和边缘有完全不透明的颜色区域，与半透明颜色区域混合，其中背景图案透过，位于两者之间：

**![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e27e4130-72de-4c50-9397-e6b4e4a0e322.png)**

本节只是简单介绍了遮罩和裁剪的可能性。在本书的其余部分中，您将继续看到这些强大技术的示例。

# 将图像导入 SVG

除了在 SVG 中批量创建图像之外，还可以将其他图像引入 SVG 文档中。

有几种方法可以做到这一点。一种方法是使用 SVG`image`元素，并以一种您熟悉的方式导入图像，如果您使用过 HTML`img`元素，这种方式对您来说将是熟悉的。在此示例中，我们使用`image`元素。它采用`href`属性，类似于 HTML 中的`img src`，并且具有`height`和`width`属性。与 HTML`img`元素不同，它还接受`x`和`y`位置：

在 HTML 文档的上下文中，HTML`spec`实际上将`IMAGE`定义为`img`的同义词。它只存在于内联 SVG 的上下文中。

```xml
<svg  width="1000" height="485" viewBox="0 0 1000 485" version="1.1">
    <image href="take-2-central-2017.jpg" width="1000" height="485" 
      x="0" y="0" ></image>
    <text x="300" y="400" fill="white" font-family="verdana, helvetica" 
     font-size="36" text-anchor="left">
        REACT @ Central Square 2017
    </text>
</svg>
```

在浏览器中呈现，我们得到了完整的照片图像，SVG 文本元素作为标题：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/49ae51e3-8f84-4773-9162-3a230f6603d6.png)

你也可以使用`image`元素来导入其他 SVG 图像。该技术有一定的限制，限制了导入的 SVG 元素的实用性。它们基本上被视为静态图像，因此诸如进一步导入图像之类的事情是行不通的；你不能在导入的 SVG 图像内导入其他图像。只有*第一个*引用的图像会被导入。要使用导入的 SVG 图像的全部功能，你应该使用`use`元素并指向外部 URL。通过这种技术，你还可以针对导入文档的特定片段。这种技术可以让你创建一个符号库，并通过引用将符号导入到你的 SVG 文档中。

在这个简单的例子中，我们展示了如何使用`use`元素并引用包含文档的片段来正确导入图像。`#image`指向`svg-with-import.svg`中特定元素的`id`元素：

```xml
<svg  width="1000" height="970" viewBox="0 0 1000 970" version="1.1">
<image href="svg-with-import.svg" width="1000" height="485" x="0" y="0"></image>
<use xlink:href="svg-with-import.svg#image" width="1000" height="485" x="0" y="485"></use>
</svg>
```

这个文档顶部的空白处显示了图像加载失败的位置：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/026b2f03-f121-4ed6-9f52-f270fdf0c1d9.png)

要使这个示例在低于 8 版本的 Internet Explorer 中工作，你需要使用一个叫做`svg4everybody`的 polyfill 脚本（[`github.com/jonathantneal/svg4everybody`](https://github.com/jonathantneal/svg4everybody)）。将它插入到你的文档中，在需要使用 SVG 时调用它，它就可以工作。`svg4everybody`还可以在 Safari 6 和 Edge 12 中填充体验。如何修复你的页面在下面的代码示例中显示。你包含文件，然后调用`svg4everybody()`脚本：

```xml
<script src="img/svg4everybody.min.js"></script>
<script>svg4everybody();</script>
```

# 滤镜

滤镜允许你对元素或元素组应用各种效果。滤镜允许你模糊图像，应用照明效果，以及许多其他高级图像处理技术。如果你曾经使用过 Adobe Photoshop 或其他图形处理程序，这些滤镜就像你在那个环境中看到的滤镜一样。

滤镜是在 SVG 文档的`defs`部分中实现的，并作为`filter`元素的一部分进行分组。它们的引用方式与`mask`和`clipPath`元素相同，通过片段 URL。以下示例显示了应用于圆的常见高斯模糊滤镜：

```xml
<svg
 width="300" height="150" viewBox="0 0 300 150">
    <filter id="blurIsm">
        <feGaussianBlur in="SourceGraphic" stdDeviation="5"/>
    </filter>
    <circle cx="75" cy="75" r="50" fill="red"/>
    <circle cx="200" cy="75" r="50" fill="red" filter="url(#blurIsm)"/>
</svg>
```

在浏览器中呈现，你可以看到右侧的模糊圆圈：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/5dc536ec-18c1-480a-b2ee-c4e4f7c6d03f.png)

我不打算在本书中详细介绍滤镜。有很多滤镜；浏览器支持的级别有所不同（有时令人困惑），并且解释起来可能非常复杂。我想向你展示一个，这样你就可以看到基本模式，这个是最简单的。*所有*其他滤镜都遵循相同的一般模式。一个`filter`或一系列滤镜被分组在`defs`部分，并通过`id`元素进行引用。只要知道这个简单的模式，你就可以准备好尝试它们，或者将它们纳入你的项目中。

# 在网络上提供 SVG

在我们进入更多关于 SVG 与 web 技术更广泛的交互方式的细节章节之前，关于 SVG 的最后一点说明：如果你要在网络上提供 SVG，你需要确保它以正确的内容类型提供。浏览器期望以`"image/svg+xml"`媒体类型提供 SVG。如果你遇到 SVG 图像不显示的问题，并且你可以验证它们存在于服务器上，最好检查头部（使用你选择的浏览器调试器的网络选项卡）以查看它们是否被正确提供。如果没有（例如，如果它们是`text/xml`），那么你需要正确设置媒体类型。本节概述了如何在常见的 web 服务器中设置正确的媒体类型。

# Apache

在 Apache 中添加正确的媒体类型就像在你的`.htaccess`文件中添加以下行一样简单：

```xml
AddType image/svg+xml svg svgz
```

# nginx

在 nginx 中添加正确的媒体类型需要你在你的`mime.types`文件中有以下条目：

```xml
types {
    image/svg+xml svg svgz;
}
```

# IIS

在 IIS 中添加正确的媒体类型有两种方式。您可以使用 IIS 管理器（[`docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753281(v=ws.10)`](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753281(v=ws.10))）添加媒体类型，或者您可以将以下条目添加到`web.config`中：

```xml
<configuration>
    <system.webServer>
        <staticContent>
            <remove fileExtension=".svg"/>
            <mimeMap fileExtension=".svg" mimeType="image/svg+xml"/>
            <remove fileExtension=".svgz"/>
            <mimeMap fileExtension=".svgz" mimeType="image/svg+xml"/>
        </staticContent>
    </system.webServer>
</configuration>
```

# 总结

在本章中，您了解了许多更高级的 SVG 功能。您了解了多重变换，这使您能够在不改变 SVG 元素的基本结构的情况下操作它们。这为我们在本书中将继续探讨的许多可能性打开了大门。

您还了解了裁剪和遮罩，这使您能够通过复杂的图形减去图像的部分。这包括使用可变不透明度来操作图像的能力。

此外，您还了解了实现基本 SVG 滤镜以及在常见 Web 服务器上提供 SVG 文件的方法。

在第四章中，*在 HTML 中使用 SVG*，您将了解有关在 HTML 文档中使用 SVG 的一些细节，这是 SVG 真正展现其力量供全世界看到的地方。


# 第四章：在 HTML 中使用 SVG

到目前为止，在本书中，您已经接触到了 SVG 的基本构建块：在 SVG 规范中定义的功能和功能。虽然 SVG 可以独立存在，但当它在现代网络上得到应用时，它真正发挥作用。现在的网络是多设备、多形态和多连接速度的环境，SVG 有助于解决现代网络开发人员面临的许多棘手问题。因此，接下来的几章将重点介绍 SVG 与其他核心技术的集成：HTML、CSS 和 JavaScript。本章非常直接，重点是在 HTML 文档的上下文中使用 SVG。网络上的一切都始于 HTML，因此确保您的 SVG 在 HTML 中正常运行是正确的方法。

您已经学习了如何将 SVG 插入 HTML 文档中作为图像或内联 SVG 元素的基础知识，可以在[第一章](https://cdp.packtpub.com/mastering_svg/wp-admin/post.php?post=29&action=edit) *介绍可伸缩矢量图形*中找到。本章将在此基础上添加一些细节。

在本章中，您将学习以下内容：

+   SVG 和可访问性

+   使用 SVG 图像进行响应式网页设计以及作为响应式图像解决方案的好处

+   在 HTML 文档的上下文中使用内联 SVG 的工作细节

那么，让我们开始吧！

# SVG、HTML 和可访问性

网络可访问性旨在确保残障人士可以访问网站和应用程序。总体目标是提供以这样一种方式提供内容，以便残障用户可以直接访问，或者如果由于其残障（例如，听障用户需要音频内容），无法直接访问，则提供结构良好的替代内容，以传达相同的信息。然后，可以通过**辅助技术**（**AT**）访问这些结构良好的替代内容。辅助技术的最常见示例是*屏幕阅读器*。

所有平台都有屏幕阅读器。您可以使用一些免费应用程序进行测试，包括以下内容：

+   NVDA（Windows）

+   Apple VoiceOver（OS X）

+   Orca（Linux）

对于 SVG 这种视觉格式，重点是在适当的情况下提供描述图像的文本内容。

正如您可能知道的那样，HTML 本身具有辅助功能的工具和最佳实践。除了 HTML 中的工具外，还有一组名为**可访问丰富互联网应用**（**ARIA**）的技术，它定义了使网络和网络应用对残障人士更具可访问性的方法。 ARIA 提供了一组特殊的辅助功能属性，当添加到 HTML 中时，可以提供有关页面或应用程序的辅助功能信息。例如，`role`属性定义了元素的*类型*（文章、菜单或图像）。

正如您在第一章 *介绍可伸缩矢量图形*中看到的，将 SVG 插入 HTML 文档的两种常见方法是作为图像的`src`和作为内联 SVG 元素（或元素）。本节将添加一些关于使用 SVG、HTML 和 ARIA 属性的注意事项，以确保您的内容在使用这两种技术时仍然具有可访问性。

# SVG 作为图像的 src

将 SVG 放入文档的最简单方法是作为`img`元素的`src`。正如您在第一章 *介绍可伸缩矢量图形*中看到的那样，这样做就像引用`*.svg`元素一样简单，就像在`img`元素的`src`属性上引用任何图像一样。

至于可访问性，如果您遵循有关可访问性和图像的最佳实践，您可以继续对 SVG 图像执行相同的操作。alt 属性应该存在，并且如果辅助技术需要，它应该正确描述内容。您可能会想知道为什么您需要这样做，尤其是对于已经在其源中具有描述性文本的 SVG 图像。请注意，SVG 文件中的任何文本内容实际上被屏幕阅读器锁定，因此即使您使用 SVG，作为一种具有描述性的基于标记的图像格式，它在这种情况下至少表现得就像一个常见的位图文件格式。

除了替代文本之外，旧版 Safari（早于 Safari 桌面 9.1.1 版或 iOS 上的 9.3.2 版）有一个小问题需要考虑。在这些旧版本中，除非在 img 元素上设置了 role="img" ARIA 角色，否则 VoiceOver，苹果屏幕阅读器，将不会读取 alt 文本：

```xml
<img src="img/apple.svg" width="300" height="300" alt="an apple" 
 role="img">
```

# 内联 SVG

内联 SVG 为可访问性提供了更广泛的选择。例如，与我们刚讨论的 SVG 作为 img src 的情况不同，如果 SVG 中有一个或多个 text 元素，则该文本可以直接被屏幕阅读器读取。如果文本对图像有适当的描述，那么您已经提供了一个可访问的图像。您无需做其他任何事情。

如果 SVG 中的文本对图像没有描述性，或者图像没有文本，那么您可以利用两个 SVG 元素，即 title 和 desc，提供可访问的文本。这些元素与 aria-labelledby 属性结合使用，提供了一种两级的可访问性方法。以下代码示例显示了这种工作方式的基本原理。图像本身是一个苹果的插图。在浏览器中呈现时，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/02823222-c153-42e5-9c00-010ab9b4b9d3.png)

标记如下。

SVG 元素本身有两个重要的属性。它具有一个 role 为 img 的属性，表示该元素被标识为图形。它还利用了 aria-labelledby 属性，该属性引用了两个单独的 ID，即"apple-title"和"apple-desc"。aria-labelledby 属性在元素本身和其他标签它的元素之间创建了一个关系。

我们首先遇到这两个元素中的第一个元素，即 SVG 元素的第一个子元素，即 title 元素。title 元素可用于为 SVG 元素提供元素的文本描述。它不会直接由浏览器呈现，但应该由屏幕阅读器读取，并且可以呈现为工具提示，就像 alt 属性中的文本在某些浏览器中显示的方式一样。它的 id 是"apple-title"。接下来是可选的 desc 元素。desc 允许您提供图像的更长文本描述。它的 id 是"apple-desc"。它也可以被屏幕阅读器读取，并且不会直接呈现在浏览器中。

有趣的标记的最后一部分是 role="presentation"，它应用于每个子 path 元素。这样做可以将这些元素从可访问性树中排除出去，因此从可访问性的角度来看，SVG 元素被视为一个图形：

```xml
<!doctype html>
<html lang="en">
<head>
 <meta charset="utf-8">
 <title>Mastering SVG- Accessible Inline SVG </title>
</head>
<body>
 <svg  width="300" height="300"
  viewBox="0 0 300 300" version="1.1" role="img" aria-
  labelledby="apple-title apple-desc">
 <title id="apple-title">An Apple</title>
 <desc id="apple-desc">An apple, the sweet, pomaceous fruit, of the
  apple tree.</desc>
 <path role="presentation" style="fill:#784421;stroke:none;stroke-
  width:0.26458332px;stroke-linecap:butt;stroke-linejoin:miter;stroke-
  opacity:1"
  d="m 105.75769,18.053573 c 0,0 46.1131,23.434525 34.01786,50.64881  
  -12.09524,27.214284 15.875,-6.803573 15.875,-6.803573 0,0
   9.07143,-23.434524 -1.5119,-38.55357 -10.58334,-15.1190474 
  -48.38096,-5.291667 -48.38096,-5.291667 z"
 />
 <path role="presentation" style="fill:#ff0000;stroke:none;stroke-
  width:0.26458332px;stroke-linecap:butt;stroke-linejoin:miter;stroke-
  opacity:1"
  d="m 146.65476,61.898812 c 0,0 -139.0952362,-66.5238097
 -127.755951,73.327378 11.339285,139.85118 92.218641,132.57921
  123.220231,124.73214 23.47822,-5.94277 108.10119,52.16071 
  127.00001,-111.125 C 286.06755,2.3982366 146.65476,61.898812 
  146.65476,61.898812 Z"
 />

 <path role="presentation" style="fill:#ffffff;stroke:none;stroke-
  width:0.26458332px;stroke-linecap:butt;stroke-linejoin:miter;stroke-
  opacity:1"
  d="m 183.69643,64.92262 c 0,0 50.21311,5.546816 41.57738,74.83928 
  -2.32319,18.64109 31.75,-34.7738 21.92261,-54.428565 C
  237.36905,65.678572 219.22619,55.851191 183.69643,64.92262 Z"
 />
 </svg>
</body>
</html>
```

本节描述了静态 SVG 图像的可访问性。动态 SVG 还有其他可行的可访问性技术，包括其他 ARIA 属性，例如 ARIA-live 区域。在适用的情况下，您将在以下章节中了解这些内容。也就是说，正确掌握静态 SVG 的基础知识是一个很好的开始，学会使用屏幕阅读器测试 SVG 将使您走上正确的道路。

# SVG 和响应式网页设计

**响应式网页设计**（**RWD**）是一种开发网站和应用程序的技术，利用流体布局网格和 CSS3 媒体查询（[`www.w3.org/TR/css3-mediaqueries/`](https://www.w3.org/TR/css3-mediaqueries/)）来创建可以适应和响应设备或用户代理特征的布局，从而可以伸缩以呈现适用于各种屏幕尺寸的布局，而无需事先了解设备特征。

当 RWD 开始流行起来时，一个迅速浮出水面的问题是难以根据影响最终用户体验的多种变量之一（屏幕分辨率、像素深度和可用带宽）来提供正确大小的图像（文件大小和尺寸）。用户体验。屏幕分辨率、像素深度和可用带宽都结合在一起，使得为用户提供何种大小的图像成为一个复杂的问题。

接下来是多年的追求标记模式，以创建响应式内容图像。*内容图像*是使用`img`标签提供的图像，旨在作为内容呈现。这与仅用于设计的图像相比，后者可以并且应该已经用 CSS 处理。由于媒体查询得到了强有力的支持，CSS 已经提供了许多工具，可以根据多种因素呈现正确的图像。

响应式图像的一些要求如下：

+   **尽可能使用最小的文件大小**：这实际上是核心问题。它以许多方式表现出来。在理想的世界中，我们只会发送渲染图像所需的最小字节数，以达到可接受的质量水平。

+   **利用浏览器预加载程序**：所有现代 Web 浏览器都使用一种技术，其中浏览器会跳过，同时阅读文档并构建 DOM，并阅读文档，寻找可以开始下载的其他资产。

+   为多个分辨率提供正确大小的图像：如果您要为`2048`像素的显示器提供大图像，则希望它是`1600`像素或更大的大图像。另一方面，平板电脑或手机上的大图像可能只需要`320`或`480`像素宽。在这种情况下发送正确数量的数据可以显著提高性能。

+   **为多个像素比设备提供正确的图像**：为了在具有高设备像素比的设备上产生清晰的图像，您需要发送比例更大的文件，这些文件将显示给定 CSS 像素的图像。在标准桌面显示器上清晰的图像会在高像素密度显示器上显示出瑕疵。显然，您可以向所有浏览器发送更高分辨率的图像，但这些像素需要带宽，因此最好只向正确的设备发送正确的图像。

+   **选择不同尺寸的图像或完全不同的图像在不同的断点**：希望能够在不同的方向和屏幕分辨率下显示不同的图像。在大屏幕上，描述亚利桑那州图森的植物的文章中，您可能会使用一个宽图像，显示那里可以找到的各种耐旱植物。在纵向的小屏幕上，由于只显示一英寸高且细节很少，多样性的影响会消失，具有明显垂直宽高比的仙人掌图像可能是更好的选择。

+   **使用设计断点**：围绕媒体查询断点的概念进行了大量开发。它们是 RWD 核心技术之一。图像需要与响应式网站中发生的所有其他设计更改一起进行控制。

那次探索得出的多种解决方案（`picture`元素和`srcset`和`sizes`属性）非常强大。花了一些时间（几年时间和大量的互联网烦恼），但最终，我们在浏览器中获得了为我们提供*正确*图像、*正确*文件大小和*正确*尺寸的一切所需的东西。

这不容易。这是一个复杂的问题，因为它有一个复杂的解决方案。编码是复杂的，理解起来也很复杂，需要生成每个要在网页上呈现的图像的多个版本。

让我们看看新的解决方案是如何工作的，然后我们将看看 SVG（如果由于图像要求而可用）如何使它变得不那么复杂。

# srcset 属性

`srcset`属性是添加到`img`元素的新属性。您可以将其与新的`picture`元素一起使用，我们稍后会这样做。现在，让我们单独看一下。就像我说的，这些东西很复杂，所以值得花时间慢慢建立。

与标准的`src`属性一样，`srcset`属性告诉浏览器从哪里获取要用于`img`元素内容的文件。但与`src`引用的单个图像不同，`srcset`属性呈现了一个逗号分隔的 URL 列表。`srcset`属性还提供了关于图像大小或像素密度的*提示*。

让我们看一个例子来理解这些提示是如何工作的。

在以下示例中，`srcset`属性提示有关设备像素比。在这种情况下，有两个选项。第一个选项是`more-colors-small.jpg`，宽度为`600*350`（600 乘以 350）像素，用于显示标准分辨率。第二个图像`more-colors-large.jpg`，宽度为`1200*700`像素，用于更高分辨率的显示。它仍然以`600*350` *CSS*像素显示，但它有足够的额外图像信息，可以在更高像素密度的显示器上显示得更清晰。

`src`属性作为不支持`srcset`的浏览器的后备：

```xml
<!DOCTYPE html>
   <html lang="en">
     <head>
       <meta charset="utf-8">
     </head>
     <body>
       <img
         srcset="more-colors-small.jpg 1x,
                more-colors-large.jpg 2x"
         src="img/more-colors-small.jpg"
         alt="Many colors!"
         width="600" height="350">
     </body>
 </html>
```

这是设备像素比用例的解决方案。

对于每个支持图像的浏览器，`src`作为后备，对于不支持图像的浏览器，`alt`属性作为后备，这是一个很好的向后兼容的解决方案。

# srcset 和 sizes 属性

为了解决更复杂的用例，`srcset`属性可以与新的`sizes`属性一起使用，使用媒体查询来提供不同的图像源，根据浏览器窗口显示不同的相对尺寸。代码示例说明了这是如何工作的。

在这个例子中，元素以`src`属性作为不支持图像的浏览器的后备。在这种情况下，我选择了一个较小的图像，以确保无论设备或浏览器如何，它都能快速加载。接下来是新的`sizes`属性。`sizes`接受媒体查询/图像大小对（或对列表）。

以下图表分解了组件。第一部分是媒体查询。如果您在 CSS 中使用过媒体查询，这个媒体查询应该很熟悉。如果查询为`true`，则图像大小设置为**60vw**（**视口宽度**（**vw**）的 60%）。如果媒体查询失败，则大小回退到**100vw**的默认大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/bbd2c9a2-3f27-441e-b3a2-757b5ca15f83.png)

可以有任意数量的**媒体查询/大小对**。第一个匹配的媒体查询获胜，如果没有匹配，则使用回退值。

这里的`srcset`属性更加广泛。列表中有一系列宽度在`200`像素到`1600`像素之间的图像。源集中值对的第二部分，而不是指示首选像素密度，提示浏览器图像的像素宽度（200w，400w 等）。浏览器可以根据不同的尺寸和像素密度混合和匹配最佳像素宽度与适当尺寸：

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG - the srcset and sizes attributes </title>
</head>
<body>
    <img src="img/more-colors-400.jpg"
      alt="Many colors!"
      sizes="(min-width: 1024px) 60vw, 100vw"
      srcset="more-colors-200.jpg 200w,
              more-colors-400.jpg 400w,
              more-colors-600.jpg 600w,
              more-colors-1200.jpg 1200w,
              more-colors-1600.jpg 1600w">
  </body>
</html>

```

`size`的长度部分可以用任何有效的 CSS 长度来指定，这增加了这个属性的可能性和复杂性。本章将坚持使用`vw`度量。

# 图片元素

在最初的概念中，`picture`被设计为`img`元素的并行元素，模仿 HTML5 的`video`和`audio`元素的语法。其想法是有一个`picture`元素包裹一系列`source`元素，这些元素将代表图像源的选项。它会包裹一个默认的`img`元素，供不支持的浏览器使用。每个源上的`media`属性将提示浏览器使用正确的源：

```xml
<picture alt="original proposal">
 <source src="img/high-resolution.png" media="min-width:1024px">
 <source src="img/low-resolution.png">
 <img src="img/low-resolution.png" alt="fallback image">
 </picture>
```

出于各种实施相关的原因，这个最初的提案被否决了。`srcset`填补了一些空白，但由于它没有解决所有响应式图像使用案例，规范景观中总是有一个空白。

多年过去了，*最终*，经过多次失败的尝试，`picture`被重新设计和重塑，以填补那个空白。

然而，现在，`picture`不再是`img`的替代品，而是`img`元素的*增强*，以帮助浏览器找出图像源的最佳解决方案。

让我们看一个例子。虽然`srcset`的例子使用了同一图像的不同分辨率版本，但这个`picture`的例子旨在为不同分辨率提供不同的图像。在较大的浏览器窗口中，将显示一个宽度大于高度的图像：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/aaadf6a9-52c3-4e9d-b0d3-4942e8db8ae2.jpg)

在小于 1,024 像素的浏览器窗口中，将使用一个正方形图像：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e1bec99b-43f4-4fc2-a239-7e6ec7a760c9.jpg)

这个标记相对复杂，需要一些解释。

在`head`中，注意到`picturefill.min.js`文件的存在。Picturefill ([`github.com/scottjehl/picturefill`](https://github.com/scottjehl/picturefill))是`picture`元素的 Polyfill ([`remysharp.com/2010/10/08/what-is-a-polyfill`](https://remysharp.com/2010/10/08/what-is-a-polyfill))，为不支持的浏览器提供了 JavaScript 驱动的图片元素支持。

在 HTML 文档的主体中，`picture`元素包裹整个解决方案。它让浏览器知道它应该使用这个`picture`元素来为子`img`元素找到正确的源。然而，我们并不立即进入`img`元素。我们遇到的第一个子元素是`source`元素。

从开发者的角度来看，`source`的工作方式与最初的提案意图相同。如果媒体查询匹配，就使用该`source`。如果不匹配，则转到堆栈中的下一个媒体查询。

在这里，您有一个媒体查询，寻找最小宽度为`1024`像素的页面。如果媒体查询匹配，`srcset`属性用于让浏览器在`600`像素到`1600`像素宽的三个不同源图像中进行选择。由于此图像旨在以`50vw`显示，这将为大多数显示器提供良好的覆盖范围。接下来是备用的`img`元素，它也包含一个`srcset`。如果浏览器不支持`picture`和`source`，或者前面的媒体查询不匹配，您可以在这里使用`srcset`属性来获取此图像的源。`sizes`属性允许您进一步调整小于`1024`像素的范围的显示：

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- picture element </title>
  <script src="img/picturefill.min.js"></script>
</head>
<body>
    <picture>
     <source
      media="(min-width: 1024px)"
      sizes="50vw"
      srcset="more-colors-600.jpg 600w,
        more-colors-1200.jpg 1200w,
        more-colors-1600.jpg 1600w">
       <img src="img/more-colors-square-400.jpg"
         alt="Many colors!" 
         sizes="(min-width: 768px) 60vw, 100vw"
         srcset="more-colors-square-200.jpg 200w,
          more-colors-square-400.jpg 400w,
          more-colors-square-600.jpg 800w,
          more-colors-square-800.jpg 1200w">
      </picture>
  </body>
</html>
```

虽然复杂，这种`picture`模式解决了不同图像尺寸和不同格式的分离艺术指导选择的问题。既然（冗长的）解释已经结束，让我们看看 SVG 如何以更少的标记解决同样的问题。您已经在[第一章](https://cdp.packtpub.com/mastering_svg/wp-admin/post.php?post=29&action=edit)中看到了*介绍可缩放矢量图形*，SVG 图像作为`img`元素的`src`进行缩放。实际上，使用 SVG，响应式图像就像以下代码一样简单：

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- 100% image element </title>
</head>
<body>
    <img src="img/more-colors.svg" width="100%">
  </body>
</html>
```

它允许您无限缩放，而不会丢失保真度或增加额外字节，也不需要`srcset`！有一些方法可以通过 CSS 改进这种简单的解决方案，我们将在下一章中看到，但现在，只需知道这种模式将起作用。从一个 3000 多像素的巨型显示器到一个小巧的功能手机（假设它支持 SVG），前面的标记将很好地进行缩放。

艺术指导用例怎么样？使用 SVG 也更简单。因为我们不必提供图像的多个版本（每个 SVG 图像都可以根据需要进行缩放），艺术指导用例的标记如下。

我们有与之前看到的相同的`picture`元素。有一个子`source`元素，其中包含一个指向大于`1024`像素的浏览器的媒体查询。如果为`true`，则将使用横向图像。然后，有一个子`img`元素，其中`srcset`指向一个正方形图像，`width`为 100%。如果第一个`source`元素上的媒体查询失败，我们就会得到这个图像。

它不像普通的`img`那样简单，但比每个`srcset`中的多个位图图像版本要简单得多。输出两个图像，即可处理最复杂的情况，艺术指导和跨多个屏幕分辨率的缩放：

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- picture element with SVG </title>
  <script src="img/picturefill.min.js"></script>
</head>
<body>
  <picture>
    <source 
      media="(min-width: 1024px)"
      srcset="more-colors.svg">
    <img 
      src="img/more-colors-square.svg" 
      srcset="more-colors-square.svg"
      width="100%">
  </picture>
  </body>
</html>
```

虽然 SVG 并非适用于每种用例，但它是远远最灵活的 RWD 图像格式。从基于一个图像源的简单`width="100%"`技术来缩放图像，到使用`picture`元素更简单地实现艺术指导用例，SVG 在这个多分辨率、多设备的世界中提供了巨大的好处。

# HTML 文档中内联 SVG 的附加细节

正如您已经了解的那样，使用内联 SVG 与 HTML 标记一样简单，通常是您嵌入 SVG 到文档中的最佳（或唯一，在交互式 SVG 的情况下）选项。也就是说，与网络上的任何内容一样，当使用内联 SVG 时，总会有一些边缘情况、注意事项和需要牢记的要点。本节概述了其中两个问题。第一个是尝试利用浏览器的缓存，另一个是要注意在处理 SVG 时 DOM 复杂性可能会大幅增加。

# 缓存

与作为`img`元素的`src`链接的 SVG 图像或通过 CSS 引用的 SVG 图像不同，内联 SVG 无法被缓存并在另一页或单页应用程序的不同视图中引用。虽然最小化 HTTP 请求的数量仍然有性能优势（内联 SVG 通过消除对单独 SVG 文档的请求来实现），但这并不总是最优化的模式。如果您在多个页面上多次使用相同的 SVG 图像，或者多次访问多个站点，那么拥有一个可以被缓存并稍后再次读取的文件将会有益处。这对于更大、更复杂的 SVG 图像尤其如此，它们可能具有较大的下载占用空间。

如果您真的需要使用内联 SVG（例如所有交互式示例），您仍然可以尝试通过使用`use`元素链接到外部库 SVG 元素来以不同的方式利用浏览器缓存。您可能会在前期添加一些 HTTP 请求，但您不必不断下载和解析定义这些可重用组件的内联标记。

而且，考虑可重用组件是思考项目结构的一种好方法，因此这是利用浏览器缓存之外的好处。

# 复杂性

虽然我实际上已经尝试限制您在本书中迄今为止看到的 SVG 代码示例的复杂性，但您已经看到了一些非常繁忙的 SVG 示例。实际上，当处理比一小部分`rect`、`circle`或`text`元素更复杂的任何内容时，SVG 代码的大小和/或可读性可能会迅速下降。这在生成的代码中尤其如此，因为它实际上并不是为了人类消费而设计的。

这种复杂性可能会以两种不同的方式成为问题：创作环境更加复杂，页面的渲染和性能变慢。

# 创作

SVG 文档可能会变得非常庞大，即使是简单的图像也是如此。根据效果的数量和元素的数量，用于绘制 SVG 图像的标记可能会迅速压倒页面上的其他所有内容。因此，值得将大型 SVG 元素保留为单独的文档片段，并根据需要将它们引入您的文档中。根据它们的使用方式，这可能是在包含 SVG 文档内部使用`use`元素，或者可能是使用您选择的页面组合工具导入文档片段的情况。有许多服务器端和/或客户端解决方案可以将标记和文本片段组合在一起（例如，JavaScript 模板解决方案，CMS，博客平台和服务器端脚本语言，如 PHP），因此我不打算创建一个潜在有限用途的示例。我相信您会利用最贴近您心的解决方案。

您仍然必须在检查页面时处理它，但这比在一个 700 行文件中占据 500 行标记的 SVG 插图要好得多，该插图显示了供应链图表或类似内容。

# 文档对象模型

除了创作问题，您还可能遇到非常复杂的 SVG 在浏览器性能方面的问题。这是真实的，无论您以何种方式导入它们，因为即使 SVG 作为`img src`导入，它也不仅仅是一组像素，但如果您已经在 DOM 中进行了大量交互，这种情况可能会更加严重。一般来说，文档中的元素数量直接影响页面的速度和响应性（https://developers.google.com/web/fundamentals/performance/rendering/avoid-large-complex-layouts-and-layout-thrashing）。当页面上有成百上千个潜在的可交互 SVG 元素时，每个元素都需要由浏览器计算（其中一些在内部进行非常复杂的计算）并呈现，事情可能会非常快地变慢。

大多数情况下，您不太可能遇到这种性能问题。至少我希望您不会。然而，这是可能的，因此请将可能性存档，希望您永远不必使用这些知识。

# 总结

在本章中，您了解了在 HTML 文档环境中使用 SVG。首先，您了解了使用内联 SVG 元素和 SVG 图像作为`img`元素的`src`时的 SVG 可访问性。这包括`img`元素的`alt`属性的详细信息，以及内联 SVG 中`title`和`desc`元素的详细信息。

接下来，您了解了响应式图像的解决方案，以及如何使用 SVG 可以极大地简化甚至是最复杂的响应式图像使用情况的实现。最后，您了解了在实际世界中实施这些解决方案时需要注意的内联 SVG 的其他方面。

接下来，我们将看一下 CSS 和 SVG 的重要交集。下一章将建立在我们所学到的一切基础上，并将为您介绍一些强大的新工具，供您添加到 SVG 工具箱中。


# 第五章：使用 SVG 和 CSS

本章将重点介绍 SVG 和 CSS 的交集。虽然 JavaScript 是处理 SVG 最强大的工具，但没有 CSS 的 SVG 不会像现在这样受欢迎。正如你已经了解的那样，SVG 非常适合现代网络，通常是对 RWD 问题的最佳答案。因此，它已经被设计师和开发人员全力以赴地用于为网络生成图像。

对于整个网络来说，这种对 SVG 的偏好是一个很好的选择，应该加以培养。本章将希望说明为什么。

在这一章中，我们将学习以下内容：

+   使用 CSS 背景图像

+   如何优化 SVG 的数据 URI

+   SVG 精灵与图标字体

+   不同的 SVG 嵌入方式如何与 CSS 互动

+   使用常见的 CSS 属性来操作 SVG

+   使用 SVG 特定的 CSS 属性来操作 SVG

+   使用 SVG 的基本 CSS 动画和过渡

# CSS 背景图像

你已经在第一章中看到了使用 CSS 作为背景图像的例子，*介绍可伸缩矢量图形*。本节将为使用 SVG 的这种方式添加一些更多的细节。

在这个最初的基本示例中，我们将一个风格化的字母 R 的 SVG 图像添加为`div`的背景图像。一个重要的方面是设置`background-size`属性。SVG 图像的自然大小是`458`乘以`392`。在这种情况下，它被设置为原来大小的一半，以适应`div`的大小：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Background Images</title>
        <style type="text/css">
          .logo{
            width: 229px;
            height: 196px;
            background: url(icon.svg);
            background-repeat: no-repeat;
            background-size: 229px 196px;
          }
        </style>
    </head>
    <body>
        <div class="logo">
        </div>
    </body>
</html>
```

在浏览器中呈现，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/f9e4f359-a25f-4ec2-aab1-06ecd07114a7.png)

除了提供高像素密度显示（这确实是一个很棒的功能）之外，这并没有比 PNG 提供更多。

在使用相对单位的环境中，你可以利用 SVG 的能力，将`background-size`的值设置为`contain`或`cover`，以真正充分利用 SVG。在下面的例子中，与之前相同的标志被应用为背景图像，旁边还有一些文本。所有的度量都是相对的，使用根 em（rem）单位。背景图像设置为`contain`的`background-size`值。`contain`确保标志将完整地显示，受包含元素的高度和宽度的限制。由于我们使用 SVG 图像作为背景图像，文档的基本字体（因此计算*根 em*）可以从 16 像素（浏览器默认值）缩放到 1600 像素，SVG 背景将能够缩放以匹配：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- Relative Background Images </title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:600" rel="stylesheet"> 
        <style type="text/css">
          .logo{
            width: 14.3rem;
            height: 14.3rem;
            background: url(icon.svg);
            background-repeat: no-repeat;
            background-size: contain;
            background-position-y: 2.5rem;
          }
          h1 {
            font-family: Raleway, sans-serif;
            font-size: 2rem;
          }
        </style>
    </head>
    <body>
      <div class="logo">

      <h1>Rob Larsen</h1>
    </div>
    </body>
</html>
```

在浏览器中呈现，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/04b8f8c6-75a8-4ef7-8070-fe306cc8ecd3.png)

这里没有什么新的东西，但这是现代网页上 SVG 的一个非常重要的用途，值得花一些时间来强调这种模式。

# SVG 背景图像的数据 URL

如果你注重性能，你可能会想知道通过 data: URL 直接在 CSS 中嵌入背景图像的技术。数据 URL 允许你通过特殊的`data: URL`将文件直接嵌入文档中。这种技术允许你节省一个 HTTP 请求。

当使用诸如 JPG 或 PNG 之类的二进制格式时，图像数据需要进行`base64`编码。虽然这对 SVG 图像也适用，但实际上，将 SVG 图像作为 SVG 源嵌入更快（[`css-tricks.com/probably-dont-base64-svg/`](https://css-tricks.com/probably-dont-base64-svg/)）。这是因为除了`base64`编码的数据外，你还可以直接嵌入文本。SVG 当然是一种文本格式。你只需要对 SVG 进行一些处理才能使其正常工作。你应该阅读 Taylor Hunt 的完整文章以获取详细信息（[`codepen.io/tigt/post/optimizing-svgs-in-data-uris`](https://codepen.io/tigt/post/optimizing-svgs-in-data-uris)），但基本步骤如下：

+   使用单引号作为属性值

+   对任何非安全字符（`<`，`>`，`#`等）进行 URL 编码

+   双引号数据 URL

转换初始示例，我们得到的代码如下：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Background Images with Data 
         URLs</title>
        <style type="text/css">
          .logo{
            width: 229px;
            height: 196px;
            background: url("data:image/svg+xml,%3Csvg
xmlns='http://www.w3.org/2000/svg' height='392' width='458'%3E%3Cg  stroke='%23000' stroke-width='14.17'%3E%3Cpath d='M96.42 60.2s14 141.5-58 289l145.5-18.4 55.4-276.7z' fill='%23000012'/%3E%3Cpath d='M145.42 188l108.5 171.6 189.2 24.4-123.4-196z' fill='%23000012'/%3E%3Cpath d='M70.12 43.7s14 141.5-58 289l145.5-18.4 55.4-276.7z' fill='%23e9c21b'/%3E%3Cpath d='M59.02 23.6l116.2 237.2c-.1 0 411.3-239.1-116.2-237.2z' fill='%23000012'/%3E%3Cpath d='M119.12 171.6l108.5 171.6 189.2 24.4-123.4-196z' fill='%233fc4eb'/%3E%3Cpath d='M32.62 7.1l116.2 237.2S560.22 5.2 32.62 7.1z' fill='%2359ea39'/%3E%3C/g%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-size: 229px 196px;
          }
        </style>
    </head>
    <body>
      <div class="logo">
    </div>
    </body>
</html>
```

虽然这实际上是非常简单的手工准备（这里的示例是手工编码的），但如果您想要挤出所有字节，有一些可用的工具可以为您完成这项工作。有一个 node 模块（[`www.npmjs.com/package/mini-svg-data-uri`](https://www.npmjs.com/package/mini-svg-data-uri)）和一个 SASS 函数（[`codepen.io/jakob-e/`](https://codepen.io/jakob-e/)），可以帮助您将此功能构建到您的工作流程中。

# SVG 精灵和图标集

这一部分并不严格涉及 CSS，但讨论了一种常见的基于 CSS 的解决方案的替代方案，用于向应用程序添加图标，因此这似乎是讨论它的最佳地方。

如果您正在阅读本书，您可能对图标字体的概念有所了解，比如 GLYPHICONS（[`glyphicons.com/`](http://glyphicons.com/)）或 Font Awesome（[`fontawesome.com/icons?from=io`](https://fontawesome.com/icons?from=io)）。如果您不了解，它们是字体，而不是表示可以作为语言阅读的字符（就像您现在正在阅读的字符），它们呈现可以用作站点或应用程序图标的不同图像。

例如，您可以使用*Font Awesome*创建视频播放器的界面，而无需设计单个元素。

以下代码示例显示了该实现可能看起来如何。除了 Font Awesome，以下示例还使用了 Bootstrap 样式。

Font Awesome 的基本模式是将图标作为空元素包含。在这种情况下是`i`。每个图标都有两个常见的类：`fa`和`fa-2x`。这些类表示元素是 Font Awesome 图标，并且应该以正常大小的`2x`渲染。之后，使用`fa-`类添加各个图标，表示要使用的图标类型：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- Font Awesome</title>
        <link rel="stylesheet" 
href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <link href="font-awesome.min.css" rel="stylesheet" />
    </head>
    <body>       
        <div style="text-align: center">
            <button class="btn btn-link"><i class="fa fa-2x fa-backward
             "></i></button> 
            <button class="btn btn-link"><i class="fa fa-2x fa-fast-
              backward"></i></button> 
            <button class="btn btn-link"><i class="fa fa-2x fa-play">
             </i></button>
            <button class="btn btn-link"><i class="fa fa-2x fa-fast-
             forward"></i></button> 
            <button class="btn btn-link"><i class="fa fa-2x fa-
             forward"></i></button> 
        </div>

    </body>
</html>
```

在浏览器中呈现如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/d5cedaab-822a-4474-918e-f3d7a4018eb1.png)

这一切都非常清晰易懂。正因为如此，这些图标字体非常受欢迎。我在多个环境中使用过它们，对它们的通用易用性和快速启动能力印象深刻。

也就是说，使用图标字体也有缺点。两个突出的缺点是：

+   可访问性：有方法可以很好地使用图标字体，以便实现可访问性（[`www.filamentgroup.com/lab/bulletproof_icon_fonts.html`](https://www.filamentgroup.com/lab/bulletproof_icon_fonts.html)），但开箱即用，您正在向空元素插入无意义的字符。屏幕阅读器可以读取这些无意义的字符，为依赖 AT 浏览网页的用户创建混乱的体验。

+   语义：空元素是*空的。*使用`i`或`span`的图标字体实际上没有任何含义。

还有其他问题，包括加载 Web 字体的挑剔性以及对阅读障碍用户的问题（[`cloudfour.com/thinks/seriously-dont-use-icon-fonts/`](https://cloudfour.com/thinks/seriously-dont-use-icon-fonts/)）。

好消息是，如果您对更好的语义、更好的可访问性和更直接的实现感兴趣，有一种 SVG 替代图标字体的方法：使用*SVG 精灵*。公平地说，SVG 精灵也不是一个完美的解决方案，因为最优雅的变体需要 IE/Edge 形状的解决方法。但对于某些配置（特别是单页应用程序），SVG 精灵是图标交付的绝佳选择。

让我们看看它是如何工作的。

在本例中，我们将使用 Front Awesome v5，它提供了所有图标的 SVG 版本，以复制先前的控件集。

以下是使用 SVG 精灵实现相同控件的方法。

首先，让我们看一下精灵文件本身的细节。在其中，所有图标都被定义为与 CSS 图标的类名相对应的`symbol`元素。每个`symbol`元素都包括可访问的`title`元素。

集合中的每个图标都在文件`fa-solid.svg`中表示：

```xml
 <symbol id="play" viewBox="0 0 448 512">
    <title id="play-title">play</title>
    <path d="M424.4 214.7L72.4 6.6C43.8-10.3 0 6.1 0 47.9V464c0 37.5 
     40.7 60.1 72.4 41.3l352-208c31.4-18.5 31.5-64.1 0-82.6z"></path>
  </symbol> 

```

在 HTML 文件中，情况略有不同，但总体模式基本相同。我们仍然链接到 Bootstrap 以方便使用。我们不再在`head`中链接来自 Font Awesome 的任何内容。我们只需要一小块 CSS 来调整页面上图标的大小。在实际的示例中，您可能会做更多的样式处理，但目前这已经足够使其正常工作。

在文档的主体部分，我们有一个新的模式。与`button.btn > i.fa`模式不同，我们有`button.btn > svg > use`，其中 use 指向`fa-solid.svg`文件中的特定符号。

除此之外，我们有一个适用于 Internet Explorer 的问题。Internet Explorer 不允许您从外部文档中使用元素。脚本*svg4everybody*填补了这个缺陷，并允许您在 IE 中链接到外部 SVG：

```xml
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- Font Awesome</title>
  <link rel="stylesheet" 
    href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0- 
    beta.3/css/bootstrap.min.css" integrity="sha384-
    Zug+QiDoJOrZ5t4lssLdxGhVrurbmBWopoEl+M6BdEfwnCJZtKxi1KgxUyJq13dy"
    crossorigin="anonymous">
  <style>
    .btn svg{
      height: 2em;
      width: 2em;
      fill: #007bff;
    }
  </style>
</head>
<body>
  <div>
    <button aria-label="rewind" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="fa-solid.svg#backward"></use>
      </svg>
    </button>
    <button aria-label="skip to previous track" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="fa-solid.svg#fast-backward"></use>
      </svg>
    </button>
    <button aria-label="play" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="fa-solid.svg#play"></use>
      </svg>
    </button>
    <button aria-label="skip to next track" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="fa-solid.svg#fast-forward"></use>
      </svg>
    </button>
    <button aria-label="fast forward" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="fa-solid.svg#forward"></use>
      </svg>
    </button>
  </div>
  <script src="img/svg4everybody.min.js"></script>
  <script>svg4everybody();</script>
</body>

</html>
```

我提到了单页面应用程序可能会被不同对待。如果您正在开发单页面应用程序并且想要使用 SVG 图标，您可以在页面中*内联*符号，并且在所有现代浏览器中*使用*它们，而无需任何填充脚本。对于单页面应用程序，您可能已经在文档中内联了 CSS 等内容以节省 HTTP 请求，因此在文档中内联一部分 SVG 可以成为相同过程的一部分。

我不打算详细说明这可能是如何从构建或页面创建的角度工作的，因为有很多种方法可以做到这一点（可以作为构建过程的一部分或通过服务器端模板系统），但输出可能看起来像以下代码示例。

最大的区别是在`body`顶部的内联`svg`元素中定义符号。这增加了页面的复杂性，但节省了 HTTP 请求。因此，如果您正在构建单页面应用程序并且不需要依赖缓存单独的精灵文件，这将会稍微更快一些。

除此之外，引用直接指向同一页面的文档片段，而不是链接到单独的文件。这意味着我们不需要 svg4everybody，而且 Internet Explorer 很乐意支持`use`：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- Font Awesome</title>
  <link rel="stylesheet" 
    href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-
    beta.3/css/bootstrap.min.css" integrity="sha384-
    Zug+QiDoJOrZ5t4lssLdxGhVrurbmBWopoEl+M6BdEfwnCJZtKxi1KgxUyJq13dy"
    crossorigin="anonymous">
  <style>
    .btn svg {
      height: 2em;
      width: 2em;
      fill: #007bff;
    }
  </style>
</head>

<body>
  <svg  style="display:none">
    <defs>
      <symbol id="play" viewBox="0 0 448 512">
        <title id="play-title">play</title>
        <path d="M424.4 214.7L72.4 6.6C43.8-10.3 0 6.1 0 47.9V464c0 
         37.5 40.7 60.1 72.4 41.3l352-208c31.4-18.5 31.5-64.1 0-82.6z"></path>
      </symbol>
      <symbol id="fast-backward" viewBox="0 0 512 512">
        <title id="fast-backward-title">fast-backward</title>
        <path d="M0 436V76c0-6.6 5.4-12 12-12h40c6.6 0 12 5.4 12
         12v151.9L235.5 71.4C256.1 54.3 288 68.6 288 96v131.9L459.5 
         71.4C480.1 54.3 512 68.6 512 96v320c0 27.4-31.9 41.7-52.5
         24.6L288 285.3V416c0 27.4-31.9 41.7-52.5 24.6L64 285.3V436c0 
         6.6-5.4
         12-12 12H12c-6.6 0-12-5.4-12-12z"></path>
      </symbol>
      <symbol id="fast-forward" viewBox="0 0 512 512">
        <title id="fast-forward-title">fast-forward</title>
        <path d="M512 76v360c0 6.6-5.4 12-12 12h-40c-6.6 0-12-5.4-12-
         12V284.1L276.5 440.6c-20.6 17.2-52.5 2.8-52.5-24.6V284.1L52.5 
         440.6C31.9 457.8 0 443.4 0 416V96c0-27.4 31.9-41.7 52.5-
         24.6L224 226.8V96c0-27.4 31.9-41.7 52.5-24.6L448 226.8V76c0-
         6.6 5.4-12 12-12h40c6.6 0 12 5.4 12 12z"></path>
      </symbol>
      <symbol id="forward" viewBox="0 0 512 512">
        <title id="forward-title">forward</title>
        <path d="M500.5 231.4l-192-160C287.9 54.3 256 68.6 256 96v320c0 
         27.4 31.9 41.8 52.5 24.6l192-160c15.3-12.8 15.3-36.4 0-49.2zm-
         256 0l-192-160C31.9 54.3 0 68.6 0 96v320c0 27.4 31.9 41.8 52.5 
         24.6l192-160c15.3-12.8 15.3-36.4 0-49.2z"></path>
      </symbol>
      <symbol id="backward" viewBox="0 0 512 512">
        <title id="backward-title">backward</title>
        <path d="M11.5 280.6l192 160c20.6 17.2 52.5 2.8 52.5-24.6V96c0-
         27.4-31.9-41.8-52.5-24.6l-192 160c-15.3 12.8-15.3 36.4 0 
         49.2zm256 0l192 160c20.6 17.2 52.5 2.8 52.5-24.6V96c0-27.4-
         31.9-41.8-52.5-24.6l-192 160c-15.3 12.8-15.3 36.4 0 49.2z"></path>
      </symbol>
    </defs>
  </svg>
  <div>
    <button aria-label="rewind" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="#backward"></use>
      </svg>
    </button>
    <button aria-label="skip to previous track" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="#fast-backward"></use>
      </svg>
    </button>
    <button aria-label="play" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="#play"></use>
      </svg>
    </button>
    <button aria-label="skip to next track" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="#fast-forward"></use>
      </svg>
    </button>
    <button aria-label="fast forward" class="btn btn-link">
      <svg  role="img">
        <use xlink:href="#forward"></use>
      </svg>
    </button>
  </div>
</body>

</html>
```

与图标字体一样，SVG 精灵可以完全使用 CSS 进行自定义。您已经看到了一个示例，在前面的示例中我们改变了图标的大小和颜色。当您阅读本章的其余部分时，您将会遇到许多使用 CSS 操纵 SVG 的方法。这是一个非常强大的组合！

# 对内联 SVG 进行样式设置

本节将重点介绍您可以使用 CSS 操纵内联 SVG 元素的许多方法。本节不会详尽无遗，但将涵盖您在处理 SVG 时将使用的许多常见属性。

这些属性分为两类：

+   您可能已经熟悉的 CSS 和 HTML 中的 CSS 属性，也适用于 SVG

+   特定于 SVG 本身的 CSS 属性

让我们从熟悉的 CSS 属性开始。

# 使用常见的 CSS 属性来操纵 SVG

本节将重点介绍与 SVG 一起使用的常见 CSS 属性。除了一些例外，您实际上会关注的大多数属性都与文本相关。

# 基本字体属性

如果您已经使用 CSS 工作了一段时间，您可能已经操纵了元素的字体和样式。这些属性对 SVG 元素也是可用的。

以下代码示例显示了四个`text`元素。第一个没有应用任何样式，并显示了 SVG 中`text`元素的默认渲染。接下来的三个元素通过 CSS 样式进行了增强。第一个类`text`添加了优秀的 Raleway 字体（作为 Google 网络字体可用）和一个新的`font-size`（`2em`）。接下来的两个类，`text-italic`和`text-bold`，分别使用`font-style`和`font-weight`进行了增强：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Font Properties</title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:400" rel="stylesheet"> 

        <style type="text/css">
          .text {
            font-family: Raleway, sans-serif;
            font-size: 2em;
          }
          .text-italic {
            font-style: italic;
          }
          .text-bold {
            font-weight: bold;
          }
        </style>
    </head>
    <body>
      <svg  role="img" width="800"
        height="250" viewBox="0 0 800 250">
        <text x="25" y="50">
          Default text format
        </text>
        <text x="25" y="100" class="text">
          font-family: Raleway, sans-serif;
          font-size: 2em;
        </text>
        <text x="25" y="150" class="text text-italic">
          font-style: italic;
        </text>
        <text x="25" y="200" class="text text-bold">
          font-weight: bold;
        </text>
       </svg>
    </body>
</html>
```

在浏览器中呈现，您可以看到以下结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/bd2446b2-db15-4324-8731-57c1a383cef4.png)

如果你在想，简写属性也同样适用。因此，简单地定义一个`font`属性是支持的，如下面的代码示例所示：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Font Shorthand</title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:400" rel="stylesheet"> 
        <style type="text/css">
          .text {
            font: 2em bold Raleway, sans-serif; 
          }
        </style>
    </head>
    <body>
      <svg  role="img" width="800"
       height="250" viewBox="0 0 800 250">
        <text x="25" y="50">
          Default text format
        </text>
        <text x="25" y="100" class="text">
          font: 2em bold Raleway, sans-serif; 
        </text>
       </svg>
    </body>
</html>
```

这在浏览器中呈现如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/3b27ab70-50bb-4be0-8422-6dc36a9e99e8.png)

# 文本属性

在 SVG 中支持的下一组 CSS 属性都与文本块有关。因此，不仅仅是由字体属性定义的单个字形，还有更大的字形组合方式。

以下代码示例展示了其中的几个。第一个类`text`再次更改了`font-family`和`font-size`。

接下来，我们有几个其他类，展示了 SVG 对文本属性的支持。第一个示例展示了对`direction`的支持，它允许您定义在从右到左阅读的语言中正常工作的文本块（例如，波斯语、阿拉伯语和希伯来语）。这个例子简单地将基于英语的属性定义锚定到框的右侧。接下来，我们将`letter-spacing`（跟踪）属性设置为宽敞的`1em`，使用`text-decoration`添加下划线，并将`word-spacing`设置为`2em`：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Text Properties</title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:400" rel="stylesheet"> 

        <style type="text/css">
          .text {
            font-family: Raleway, sans-serif;
            font-size: 1.5em;
          }
          .text-direction {
            direction: rtl;
          }
          .text-letter-spacing {
            letter-spacing: 1em;
          }
          .text-decoration {
            text-decoration: underline;
          }
          .text-word-spacing {
            word-spacing: 2em;
          }
        </style>
    </head>
    <body>
      <svg  role="img" width="500"
       height="300" viewBox="0 0 500 300">
        <text x="475" y="50" class="text text-direction">
          direction: rtl;
        </text>
        <text x="25" y="100" class="text text-letter-spacing">
          letter-spacing: 1em;
        </text>
        <text x="25" y="150" class="text text-decoration">
          text-decoration: underline;
        </text>
        <text x="25" y="200" class="text text-word-spacing">
          word-spacing: 2em;
        </text>

       </svg>
    </body>
</html>
```

在浏览器中呈现，该示例如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/b1833428-1f15-4a59-9831-75cc1435644c.png)

# 杂项 CSS 属性

本节中的最后一个示例显示了对光标、显示和可见性属性的支持。其中，最有用的将是光标。在这个例子中，我们将`rect`元素的`cursor`更改为帮助光标。拖动手柄、调整大小手柄、可点击的指针等都将是交互式 SVG 中常用的值。

接下来，我们使用`display`和`visibility`属性来隐藏元素。虽然在 HTML 中两者之间的区别很明显，在 SVG 中这两个属性之间的实际区别较小。在 HTML 中，使用`display:none`的元素不会影响文档的呈现。它们不会影响文档的整体流程。它们在 DOM 中，并且可以从 JavaScript 中访问，但实际上被呈现引擎忽略。另一方面，使用`visibility:hidden`设置的元素仍然是文档流的一部分。一个高 200 像素的`div`仍然会占据 200 像素。它只是以不可见的方式这样做。

由于 SVG 中的大多数元素都是在坐标系上使用`(x,y)`属性进行定位，因此两者之间的差异可能是微妙的。通常，使用`visibility:hidden`的 SVG 元素没有任何流程中断（`tspan`可能是一个例外），因此在布局上没有实际的区别。唯一的区别在于 JavaScript 事件的处理方式。我们将在后面更深入地研究这一点，既在下一节中，也在后面的 JavaScript 章节中。但根据`pointer-events`属性的设置方式，`visibility:hidden`元素可能仍然通过 JavaScript 事件与用户交互。默认情况下，它们不会，但这仍然是可能的：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Misc Properties</title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:400" rel="stylesheet"> 

        <style type="text/css">
          .help {
            cursor: help;
          }
          .display-none {
            display: none;
          }
          .visibility-hidden {
            visibility: hidden;
          }
        </style>
    </head>
    <body>
      <svg  role="img" width="500" 
        height="300" viewBox="0 0 500 300">
        <rect x="10" y="0" width="100" height="100" fill="red" 
          class="help"></rect>
        <rect x="120" y="120" height="100" width="100" fill="blue" 
          class="display-none"></rect>
        <rect x="240" y="120" height="100" width="100" fill="blue" 
           class="visibility-hidden"></rect>
       </svg>
    </body>
</html>

```

在浏览器中呈现时，当鼠标悬停在元素上时，此示例如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/3ebea4ad-6971-40de-91aa-5b93cc6f53b9.png)

如果您熟悉 CSS，那么您会知道`display`还有其他可能的值。虽然我相信设置 SVG 元素具有另一个`display`值的情况是有效的，但这不是您通常会做的事情，所以我不会在这里讨论这个问题。

# 使用 SVG 特定的 CSS 属性来操作 SVG

本节将讨论您可以用来处理 SVG 的不同 CSS 属性。这些属性中的大多数在以前的章节中已经作为特定 SVG 元素的属性看到了。您会发现这些表现属性的组合以及使用 CSS 在 SVG 元素和 SVG 文档之间共享样式的可能性代表了一个强大的组合。

CSS 属性将覆盖演示属性，但不会覆盖 `style` 属性（这实际上意味着 SVG + CSS 的行为方式与您熟悉的 CSS 特异性工作方式相同）。

# 颜色和绘画属性

这个第一个示例说明了更改元素填充的能力。`fill` 属性接受任何有效的 CSS 颜色值（[`developer.mozilla.org/en-US/docs/Web/CSS/color_value`](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value)），以及指向绘图服务器的链接（例如，在 `defs` 部分中定义的 `pattern`）。`fill-opacity` 更改填充本身的不透明度（就像 `rgba` 颜色定义中的 alpha 值一样），而不是整个元素，就像 CSS 的 `opacity` 属性一样。

在这个例子中，我们定义了四个类。前两个，`red-fill` 和 `blue-fill`，定义了两种不同的主要颜色，红色和蓝色，用于填充。第三个，`half-opacity`，定义了 `50%` 的不透明度。最后一个 `gradient`，定义了填充为 SVG 元素中定义的绘图服务器的链接。

然后，它们与您使用常规 HTML 元素时使用的相同的 `class` 属性一起应用：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Fill Properties</title>
        <link href="https://fonts.googleapis.com/css?
          family=Raleway:400" rel="stylesheet"> 

        <style type="text/css">
          .red-fill {
            fill: red;
          }
          .blue-fill {
            fill: blue;
          }
          .half-opacity{
            fill-opacity: .5;
          }
          .gradient{
            fill: url(#linear);
          }
        </style>
    </head>
    <body>
      <svg  role="img" width="550" 
        height="300" viewBox="0 0 550 300">
          <defs>
            <linearGradient id="linear">
                <stop offset="5%" stop-color="green"/>
                <stop offset="95%" stop-color="gold"/>
            </linearGradient>

        </defs>
        <rect x="10" y="0" width="100" height="100" class="red-fill">
        </rect>
        <rect x="120" y="0" height="100" width="100" class="blue-fill">
        </rect>
        <rect x="230" y="0" height="100" width="100" class="blue-fill 
         half-opacity" ></rect>
        <rect x="340" y="0" height="100" width="100" class="gradient">
        </rect>
       </svg>
    </body>
</html>
```

在浏览器中呈现，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/f8ff0f54-974e-4d07-9667-36978aed3bc8.png)

# 描边属性

另一个非常有用的一组属性，可用于从 CSS 操作 SVG 的属性与描边有关。所有描边属性都可以作为 CSS 属性使用。与 `fill` 属性类似，这些属性在创建一致的界面和可视化方面非常有用。

这个例子展示了作为基本 `stroke` 类的一部分使用 `stroke` 和 `stroke-width` 的用法。这样设置了一个常见的描边样式，以便我们可以将其他描边操作属性应用到我们的示例中。在那之后，我们设置了两个虚线属性，`stroke-dashoffset` 和 `stroke-dasharray`，并将这些属性应用到前两个 `rect` 元素，使用 `stroke-dasharray` 和 `stroke-dashoffset` 类。之后，我们使用 `stroke-linecap-join` 类将 `stroke-linecap` 应用到 `line` 元素。在那之后，我们将 `stroke-linejoin-round` 类应用到最后一个 `rect` 元素。

`property/value` 对匹配了您在 第二章 中学到的相同模式，*开始使用 SVG 进行创作*，当您最初学习这些演示属性时。

所有这些都可以作为 CSS 属性使用，这应该有助于您为 SVG 文档中的元素创建一致可重用的描边模式：

```xml
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Mastering SVG- CSS Stroke Properties</title>
        <link href="https://fonts.googleapis.com/css?
         family=Raleway:400" rel="stylesheet"> 

        <style type="text/css">
            .stroke {
                stroke-width: 10px;
                stroke: royalblue;
            }
            .stroke-dasharray {
                stroke-dasharray: 10;
            }
            .stroke-dashoffset {
                stroke-dashoffset: 25;
            }
            .stroke-linecap-square {
                stroke-linecap: square;
            }
            .stroke-linejoin-round{
                stroke-linejoin: round;
            }
            .stroke-opacity{
                stroke-opacity: .5;
            }
        </style>
    </head>
    <body>
      <svg  width="550" height="300" 
       viewBox="0 0 550 300">
        <rect x="50" y="15" width="300" height="50" fill="none"
        class="stroke stroke-dasharray"></rect>
        <rect x="50" y="80" width="300" height="50" fill="none"
        class="stroke stroke-dasharray stroke-dashoffset"></rect>
        <line x1="50" y1="160" x2="350" y2="160" class="stroke stroke-
          linecap-square"></line>
        <rect x="50" y="180" width="300" height="50" fill="none"
        class="stroke stroke-linejoin-round"></rect>
       </svg>
    </body>
</html>
```

在浏览器中呈现，上述代码产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/392f79ea-a0e4-4cd0-a038-2548045f2cf9.png)

# 文本属性

本节将介绍一些 SVG 特定的文本属性。前几个示例涉及 SVG 中文本的基线。根据您的工作类型，您可能永远不需要调整文本元素的基线（文本行所在的视觉平面）。但是，您可能需要，特别是如果您正在处理多语言布局或复杂的基于文本的插图（如标志）。因此，值得向您介绍这些属性。与基线相关的属性是 `alignment-baseline`、`dominant-baseline` 和 `baseline-shift`。

除此之外，本节还将介绍 `text-anchor` 属性，该属性可以更改 `text` 元素的锚点。

关于基线属性的简要说明，还有更多内容，但以下描述足以为您提供足够的基础，以理解代码示例中发生的情况。这 *可能* 足够让您使用这些属性：

+   `dominant-baseline` 用于调整 `text` 元素的基线

+   `alignment-baseline` 用于调整子元素相对于其父 `text` 元素基线的基线

+   `baseline-shift`可能是最有用的，通过将主基线上移或下移来提供常见的*下标*和*上标*功能

`dominant-baseline`和`alignment-baseline`接受类似的值。这里使用的两个值是*hanging*，它将文本从文本框底部删除，以及*middle*，它将文本垂直居中在文本框底部。在这个示例中，`dominant-baseline`应用于具有两个不同值的`text`元素，而`alignment-baseline`应用于具有两个不同值的两个子`tspan`元素。

在此之后，使用`baseline-shift`的`super`和`sub`值创建了常见的上标和下标模式。

最后，`text-anchor`属性通过应用于视口中间居中的文本元素的三个不同值进行说明。`text-anchor`将文本对齐到文本框中的不同点：`start`，`middle`和句子的`end`。

接下来的代码示例说明了这些基线属性的用法，以及`text-anchor`属性的用法：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- SVG-specific CSS Text Properties</title>
    <link href="https://fonts.googleapis.com/css?family=Raleway:400"
      rel="stylesheet">

    <style type="text/css">
     .text {
         font-family: Raleway, sans-serif;
         font-size: 1.5em;
     }
     .dominant-hanging {
         dominant-baseline: hanging;
     }
     .dominant-middle {
         dominant-baseline: middle;
     }
     .alignment-hanging {
         alignment-baseline: hanging;
     }
     .alignment-middle {
         alignment-baseline: middle;
     }
     .sub {
        baseline-shift: sub;
    }
    .super {
        baseline-shift: super;
    }
    .text-anchor-start{
        text-anchor:start;
    }
    .text-anchor-middle{
        text-anchor:middle;
    }
    .text-anchor-end{
        text-anchor:end;
    }
    </style>
</head>

<body>
    <svg  width="400" height="550"
      viewBox="0 0 400 550">
        <rect width="400" height="25" x="0" y="0" fill="#cccccc" />
        <rect width="400" height="25" x="0" y="25" fill="#efefef" />
        <rect width="400" height="25" x="0" y="50" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="75" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="100" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="125" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="150" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="175" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="200" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="225" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="250" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="275" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="300" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="325" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="350" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="375" fill="#efefef"/>
        <rect width="400" height="25" x="0" y="400" fill="#cccccc"/>
        <rect width="400" height="25" x="0" y="425" fill="#efefef"/>

        <line x1="200" y1="300" x2=
        "200" y2="325" stroke="red"></line>
        <line x1="200" y1="350" x2=
        "200" y2="375" stroke="red"></line>
        <line x1="200" y1="400" x2=
        "200" y2="425" stroke="red"></line>
        <text class="text dominant-hanging" x="50"
          y="25">Hanging</text>
        <text class="text dominant-middle" x="50" y="75">Middle</text>
        <text class="text" x="50" y="125">Text <tspan class="alignment-
         hanging">Hanging</tspan></text>
        <text class="text" x="50" y="175">Text <tspan class="alignment-
         middle">Middle</tspan></text>
        <text class="text" x="50" y="225">Super<tspan
         class="super">sup</tspan></text>
        <text class="text" x="50" y="275">Sub<tspan 
         class="sub">sub</tspan></text>
        <text class="text text-anchor-start" x="200" y="325">Text
          Anchor Start</text>

        <text class="text text-anchor-middle" x="200" y="375">Text
         Anchor Middle</text>

        <text class="text text-anchor-end" x="200" y="425">Text Anchor 
         End </text>

    </svg>
</body>

</html>
```

在浏览器中呈现，这些效果在以下截图中可见：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/7bf69f05-021a-4376-a4e3-29783c150d53.png)

较暗的条带显示了基于文本元素的*x*，*y*位置的初始文本框。您可以看到`hanging`和`middle`如何清楚地移动了字体的基线，相对于*x*，*y*位置。

`text-anchor`示例通过添加一条指示这些文本元素的`(x,y)`位置的线来进行说明。它们放置在 SVG 元素的中心，这说明了该属性对文本元素的影响。

# 合成属性

目前，浏览器对合成属性的支持非常糟糕。在撰写本文时，微软对`clip`属性的支持不完整，而 mask 属性的支持在各个浏览器中都很糟糕。这很不幸，因为它们可以提供强大的选项来定义和重用剪切路径和蒙版。

我要展示的一个有效示例是如何使用 CSS 定义`clip-path`。有两种变体。第一种只是通过`id`引用了一个`clipPath`元素。这很简单，在现代浏览器中可以工作。

第二个示例允许更好地分离关注点。您不必定义一个带有路径的元素来进行剪切，而是可以直接向 CSS 提供多边形坐标。`polygon`，`circle`和`inset`是此属性的可用值。这种语法取代了现在已弃用的`clip`属性。如果您熟悉`clip`，您应该注意几件事。首先，请注意没有`rect`值的直接替代品。值得庆幸的是，正如我们在这里展示的，多边形已经足够替代`rect`。其次，`clip-path`*不需要*将元素绝对定位（尽管在 SVG 中使用此属性时，这并不是一个特别关注的问题）。

多边形值的语法与用于`polygon`元素的`path`属性的语法略有不同。与路径元素的 d 属性的逗号是任意的，仅用于可读性不同，这个 CSS 属性中的点对需要用逗号分隔并且需要单位。否则，它的工作方式与 SVG 中的`polygon`相同。

这个示例通过将点映射为`polygon`来复制`clipPath`示例中看到的矩形：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- CSS Compositing Properties</title>
    <link href="https://fonts.googleapis.com/css?family=Raleway:400" 
      rel="stylesheet">

    <style type="text/css">
      .clip-url{
        clip-path: url(#box);
      }
      .clip-polygon {
        clip-path: polygon(50% 0, 100% 0, 100% 100%, 50% 100%, 50% 0)
      }
    </style>
   </head>
   <body>
     <svg  width="240" height="240"
       viewBox="0 0 240 240" version="1.1">
       <defs>
         <clipPath id="box" maskUnits="userSpaceOnUse" x="0" y="0" 
           width="240" height="240">

             <rect x="120" y="0" width="240" height="240" fill="red" >
             </rect>
         </clipPath>
         <polygon id="star" points="95,95 120,5 150,95 235,95 165,150 
           195,235 120,180 50,235 75,150 5,95"></polygon>
       </defs> 
       <use href="#star" fill="red"></use>
       <use href="#star" fill="black" class="clip-url"></use>
     </svg>
     <svg  width="240" height="240"
        viewBox="0 0 240 240" version="1.1">
      <defs>
        <polygon id="star" points="95,95 120,5 150,95 235,95 165,150 
          195,235 120,180 50,235 75,150 5,95"></polygon>
      </defs> 
      <use href="#star" fill="red"></use>
      <use href="#star" fill="black" class="clip-polygon"></use>
    </svg>
   </body>
</html>

```

在浏览器中呈现，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/91606b93-28e5-4e81-b24c-cc3c041b39d5.png)

正如我所提到的，对`mask`属性的支持存在问题，因此我没有完全实现的示例。有三种定义的模式：

+   第一个与`clip-path`属性类似。您可以定义一个`mask-image`属性，并通过`url`将一个蒙版图像传递给它：

```xml
.mask{
    mask-image: url(mask.svg);
}
```

+   第二个选项是使用片段标识符来使用链接图像的一部分：

```xml
.mask-fragment{
    mask-image: url(mask.svg#fragment);
}
```

+   第三个，也是最有趣的选项，允许您在属性值中创建蒙版：

```xml
.mask-image {
    mask-image: linear-gradient(rgba(0, 0, 0, 1.0), transparent);
}
```

这项技术尚未准备好投入使用，但了解未来的技术发展是很重要的，特别是它将允许您仅使用 CSS 类来重用在一个中心位置定义的蒙版。

# 交互属性

我们要查看的最后一个 CSS 属性是`pointer-events`属性。`pointer-events`属性指示 SVG 元素是否可以成为指针事件的目标（包括所有输入，包括鼠标、笔或触摸输入）。

实现`pointer-events`的基本方法是打开或关闭它们。以下示例展示了这一点。此示例还将包括一点 JavaScript，这样您就可以在第六章 *JavaScript 和 SVG*中提前了解一些关于使用 JavaScript 操纵 SVG 的知识。

在此示例中，我们有两个`rect`元素。其中一个设置了类名`pointer-default`。该类有一个名为`pointer-events`的属性，值为`visiblePainted`。`visiblePainted`是 SVG 元素上`pointer-events`的默认值。它表示元素的整个可见绘制区域应接受鼠标事件。这意味着边框和填充区域都包括在内。

第二个`rect`的类名是`pointer-none`。其单个属性`pointer-events`的值为`none`。这表示该元素不应接收鼠标事件。

页面底部有一个小的 JavaScript 块，展示了该属性的作用。它还说明了在处理 SVG 和 JavaScript 时可能遇到的差异。在其中，我们使用一些核心**文档对象模型**（**DOM**）方法来为每个`rect`元素附加点击事件处理程序。首先，我们使用`document.querySelectorAll`来获取页面上所有`rect`元素的引用。如果您不熟悉它，`querySelectorAll`可以被视为著名的 jQuery 接口的标准化、浏览器原生版本。您传入一个 CSS 选择器，它返回一个包含查询结果的静态`nodeList`。

我们立即通过方便的`forEach`方法循环遍历类似数组的`nodeList`，并为每个节点附加事件处理程序。此事件处理程序旨在在单击方块时更改相邻`text`元素的文本。

如果您习惯使用`innerHTML`来设置文本内容，您会注意到这里使用的是`textContent`属性。为什么呢？因为 SVG 没有`innerHTML`（这是有道理的，因为它不是 HTML）。

在浏览器中运行此代码，您会发现只有默认`pointer-events`值的`rect`单击才会更改文本。设置为`none`的`rect`不会有任何反应：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- CSS Compositing Properties</title>
    <link href="https://fonts.googleapis.com/css?family=Raleway:400" 
      rel="stylesheet">

    <style type="text/css">
      .pointer-default {
        pointer-events: visiblePainted;
      }
      .pointer-none {
        pointer-events: none;
      }

    </style>
   </head>
   <body>
     <svg  width="500" height="250" 
      viewBox="0 0 500 250" version="1.1">
       <rect x="10" y="10" width="100" height="100" class="pointer-
         default" fill="red"></rect>
       <rect x="120" y="10" width="100" height="100" class="pointer-
          none" fill= "red"></rect>
       <text x="10" y="150" id="text"></text>
    </svg>
    <script>
      document.querySelectorAll("rect").forEach(function(element){
        let classname = element.className.baseVal;
        element.addEventListener("click",()=>{
          document.getElementById("text").textContent= `clicked
           ${classname}`
        });
      });
    </script>
   </body>
</html>
```

以下插图显示了点击两个`rect`元素后的页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/ff426ca6-ed41-4900-b59c-42a1565b380d.png)

下表说明了此属性的其他可能值。它们在与 SVG 元素交互的方式上提供了很多控制。根据您计划进行多少精确的交互，您可能最终会利用这种精度：

| 属性 | 定义 |
| --- | --- |
| `visiblePainted` | 如果`visibility`属性设置为`visible`，并且指针位于*painted area*上，则可以将该元素作为目标。使用此值，绘制区域包括`stroke`（如果它设置为除`none`之外的值）和`fill`（如果它设置为除`none`之外的值）。 |
| `visibleFill` | 如果`visibility`属性设置为`visible`，并且指针位于内部（`fill`区域）上，则可以将该元素作为目标，无论`fill`是否设置。 |
| `visibleStroke` | 如果`visibility`属性设置为`visible`，并且指针位于周边（`stroke`区域）上，则可以将该元素作为目标，无论`stroke`是否设置。 |
| `visible` | 如果`visibility`属性设置为`visible`并且指针位于内部或周边，则可以定位元素，无论是否设置了 fill 或 stroke。 |
| `painted` | 如果`visibility`属性设置为`visible`并且指针位于*painted area*上，则可以定位元素。使用此值，绘制区域包括`stroke`（如果设置为除`none`之外的值）和`fill`（如果设置为除`none`之外的值）。不考虑`visibility`属性的值。 |
| `fill` | 如果指针位于内部（`fill`区域），则可以定位元素，无论是否设置了 fill。不考虑`visibility`属性的值。 |
| `stroke` | 如果指针位于周边（`stroke`区域），则可以定位元素，无论是否设置了 fill。不考虑`visibility`属性的值。 |
| `all` | 如果指针位于元素的内部或周边，则可以定位元素。不考虑`stroke`，`fill`和`visibility`属性的值。 |
| `none` | 元素不接收指针事件。 |

# 独立 SVG 图像中的样式

到目前为止，所有的例子都是关于内联 SVG 在 HTML 文档中，你也可以在独立的 SVG 图像中使用 CSS。以下 SVG 图像显示了使用 CSS 来调整多个 SVG `text` 元素的显示。有趣的细节包括包裹在`style`元素中的样式的**字符数据**（`<![CDATA[ ]]>`）块：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/f4f236f0-0d64-4253-9d0d-4b2414e2bf44.png)

如果你没有处理过很多 XML（它现在并不像以前那样常见，所以可能是这种情况），`CDATA`用于指示 XML 解析器，该部分可能包含可被解释为 XML 但不应该的字符。 JavaScript（由于`<`和`>`的普遍存在）是最常见的用例（如果你在 1999 年构建网站，你会知道），但 CSS 也可能陷入同样的陷阱，所以在这里使用它也是很好的。

接下来要注意的是外部样式表的缺失。如果要创建一个将作为`img src`导入或作为 CSS 背景图像的 SVG 图像，它需要完全自包含。

除此之外，这与你可能熟悉的 HTML 和 CSS 组合工作方式非常相似：

```xml
<?xml version="1.0" encoding="UTF-8"?>
    <svg  width="250" height="250" viewBox="0 0 250 250" version="1.1">
    <style>
      <![CDATA[
          text {
            font-family: Verdana, Geneva, sans-serif;
            fill: slategray;
          }
          .palatino{
            font-family: Palatino, "Palatino Linotype", "Palatino LT
            STD", "Book Antiqua", Georgia, serif;
          }
          .big-green{
            fill: forestgreen;
            font-size: 2rem;
            opacity: .75;
          }
          .huge-blue{
            fill: dodgerblue;
            font-size: 4rem;
          }
          .medium-deep-pink{
            fill: deeppink;
            font-size: 1.5rem;
          }
          .bigger {
            font-size: 6rem;
          }
          .text-anchor-middle{
            text-anchor: middle;
          }
          .text-baseline-middle{
            dominant-baseline: middle;
          }
          .half-opacity{
            opacity: .5;
          }
        ]]>
       </style>
          <text x="20" y="20" class="big-green">Styles</text>
          <text x="-10" y="50" class="huge-blue palatino">Styles</text>
          <text x="66" y="40" class="medium-deep-pink half
           opacity">Styles</text>
          <text x="77" y="77" class="big-green">Styles</text>
          <text x="55" y="66">Styles</text>
          <text x="100" y="125" class="medium-deep-pink 
           bigger">Styles</text> 
          <text x="175" y="33" class="big-green">Styles</text>
          <text x="220" y="44" class="huge-blue half-
            opacity">Styles</text>
          <text x="-20" y="244" class="huge-blue bigger half-
            opacity">Styles</text>
          <text x="120" y="120" class="medium-deep-pink">Styles</text>
          <text x="14" y="166" class="big-green palatino">Styles</text>

          <text x="136" y="199" class="huge-blue palatino half-
            opacity">Styles</text>
          <text x="170" y="144" class="huge-blue">Styles</text>
          <text x="-40" y="144" class="huge-blue half-
            opacity">Styles</text>
          <text x="143" y="24" class="big-green">Styles</text> 
          <text x="125" y="125" class="bigger text-anchor-middle text- 
            baseline-middle">Styles</text> 
      </svg>
```

在浏览器中呈现，此图像如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e0bc4eea-e9b3-4b85-aec7-39a2cd30e670.png)

# 使用 SVG 的基本 CSS 动画和过渡

使用 SVG 和 CSS 的最有趣的方式之一是使用 CSS *动画*和*过渡*。

+   **动画**：这允许你为元素分配动画。这些动画被定义为一系列对 CSS 属性的更改。

+   **过渡**：这允许你控制 CSS 属性更改生效所需的时间。它们不是立即改变，而是在状态之间*过渡*。

这些是一组非常强大的功能，并且是 SVG 工具包的重要概念和技术补充。

# CSS 动画

SVG 中的 CSS 动画与 HTML 中的工作方式相同，还可以使用 SVG 特定的属性。

# 基本动画格式

基本模式如下。SVG 很简单。它是一个单独的`rect`元素。CSS 有两个有趣的组件。第一个是类`rect`，它引用了一个属性`animation`。`animation`是一个简写属性，映射到一整套`animation-`属性。在这种情况下，我们设置了其中的两个。映射属性的第一个是`animation-name`，它引用了`@keyframes`动画中定义的动画`movement`。我们设置的第二个是`animation-duration`，我们将其设置为三秒（`3s`）。`@keyframes`动画是魔术发生的地方。在其中，我们设置了两组关键帧。第一组标记了动画的初始（`0%`）和最终状态（`100%`），使用了相同的属性，即 CSS `transform`，设置为`(0,0)`的`translate`函数。这是初始（和最终）状态。我们将在下一个关键帧中对`transform`属性进行动画。在其中，我们设置了动画的中间部分（`50%`），我们将`rect`向右移动 400 像素：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- CSS animation</title>

    <style type="text/css">
    .rect {
      animation: movement 3s;
    }

    @keyframes movement {
      0%, 100% {
        transform: translate(0, 0);
      }
      50% {
        transform: translate(400px, 0);
      }
    }

    </style>
   </head>
   <body>
     <svg  width="500" height="100" 
       viewBox="0 0 500 100" version="1.1">
      <rect x="0" y="0" width="100" height="100" class="rect">
    </svg>
   </body>
</html>
```

效果是矩形慢慢从左到右移动，然后再返回：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/f592bd8f-a4fc-4746-a77f-feb2083f8cab.png)

# 使用动画剪辑路径

从 CSS 的角度来看，SVG 中动画剪辑路径的一个相对简单的例子是非常强大的。使用我们刚学到的`polygon`选项，你可以在两个（或更多）被定义为`clip-path`的形状之间进行动画。如果它们有*相同数量的点*，浏览器将平滑地在动画中定义的位置之间进行动画。

以下示例就展示了这一点。在这个示例中，我们创建了一个类`stars`：

+   `stars`有一个`animation`属性。它引用了样式表中稍后定义的`@keyframe stars`块。

+   第二个参数你已经熟悉了，`animation-duration`。这次又设置为三秒。

+   第三个属性对你来说可能是新的。属性值`infinite`映射到`animation-iteration-count`属性。

+   `animation-iteration-count`接受一个数字，表示动画应该运行的具体次数，或关键字`infinite`，表示动画应该永远播放。

`@keyframes`遵循与之前动画相同的模式。我们有相同的起始和完成状态（0%和 100%）。这些被定义为一个多边形`clip-path`，用于说明一个星星。动画的中点（`50%`）将多边形重新定义为正方形。由于动画状态之间需要等效的点数，这意味着我们需要定义多于四个点来在这些状态之间进行动画：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- CSS animation</title>

    <style type="text/css">
    .stars {
      animation: stars 3s infinite;
    }

    @keyframes stars {
      0%, 100% {
        clip-path: polygon(95px 95px, 120px 5px, 150px 95px, 235px 
         95px, 165px 150px, 195px 235px, 120px 180px, 50px 235px,75px
         150px, 5px 95px)
      }
      50% {
        clip-path: polygon(10px 10px, 120px 10px, 230px 10px, 230px 
        120px, 230px 180px, 230px 230px, 120px 230px, 10px 230px, 10px
        180px, 10px 120px)
      }
    }

    </style>
   </head>
   <body>
     <svg  width="240" height="240"
      viewBox="0 0 500 500" version="1.1">
      <image href="take-2-central-2017.jpg" width="1000" height="500" 
       x="0" y="0" class="stars"></image>
    </svg>
   </body>
</html>
```

以下时间间隔截图显示了动画在运行的三秒内是如何展开的。确保在支持的浏览器中运行，看看这种效果有多有趣：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/19aaa7d0-e34e-42d7-9c8a-ba4621dccb08.png)

# 同时对一个元素进行多个属性的动画和分配多个动画

关于动画还有两件事需要注意：

+   你可以同时对多个 CSS 属性进行动画

+   你也可以将多个动画应用于同一个元素

以下代码示例显示了这两个功能的工作原理。有三个重要部分。第一个是单个类`rect`。它有两个用于`animation`属性的逗号分隔的参数，即动画`box`和`change-color-and-fade`。`box`定义了两个正方形`clip-path`属性，一个距离矩形边缘`50`像素，另一个距离边缘`10`像素。`change-color-and-fade`将背景颜色从红色变为蓝色，不透明度从`.5`变为`1`：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- CSS animation</title>
  <style type="text/css">
    svg {
      background: lightgray;
    }
    .rect {
      animation: box 3s infinite, change-colors-and-fade 3s infinite;
    }
    @keyframes box {
      0%,
      100% {
        clip-path: polygon(50px 50px, 200px 50px, 200px 200px, 50px 
        200px)
      }
      50% {
        clip-path: polygon(10px 10px, 240px 10px, 240px 240px, 10px 
        240px)
      }
    }
    @keyframes change-colors-and-fade {
      0%,
      100% {
        opacity: .5;
        fill: rgb(255, 0, 0);
      }
      50% {
        opacity: 1;
        fill: rgb(0, 0, 255);
      }
    }
  </style>
</head>

<body>
  <svg  width="250" height="250"
   viewBox="0 0 250 250" version="1.1">
    <rect x="0" y="50" width="250" height="50" fill="gray"></rect>
    <rect x="0" y="0" width="250" height="250" class="rect"></rect>
  </svg>
</body>

</html>
```

在浏览器中运行，动画经历以下阶段：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e162bfce-9e69-44cc-bddc-08569c2627f2.png)

# CSS 过渡

本章中我们要看的最后一个 CSS 属性是 CSS `transition`属性。`transition`允许您定义浏览器在属性值更改时的动画方式。属性不会立即改变，而是可以更平滑地过渡。

以下示例展示了这是如何工作的。在示例中，我们有一个小的、单值的条形图，当用户悬停在上面时会填充，显示对目标的虚拟进度。

CSS 中充满了用于定义文本的类。您会注意到本章中学到的许多属性。除了这些属性，您在本章中应该对它们有一定的了解之外，还有一些定义条形图的类，其中一个比另一个更有趣。

第一个`the-bar`定义了条形图的轮廓。第二个`fill-the-bar`定义了条形图的*进度*部分。它没有描边，填充为绿色。对我们来说有趣的部分是`transition`属性。`transition`是一组相关的`transition-`属性的简写。在这种情况下，我们使用了`transition-property`（`transform`）和`transition-duration`（`3s`）。这表示浏览器应该监视此元素上`transform`属性的更改，并在三秒内过渡到该属性的更改。在这个类中，我们还定义了一个`scaleY transform`，值为`1`，并使用`transform-origin`将`transform`锚定到元素的`bottom`。我们需要一个基准的`scaleY`，这样浏览器就有一个匹配的属性来进行动画。`fill-the-bar:hover`将比例改变为`7.5`，根据配置的方式，这将填满条形图的`75%`目标：

```xml
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mastering SVG- CSS Transitions</title>
  <link href="https://fonts.googleapis.com/css?family=Raleway:400" 
   rel="stylesheet">

  <style type="text/css">
    .text {
      font-family: Raleway, sans-serif;
      font-size: 1.5em;
    }

    .smaller-text {
      font-size: 1em;
    }

    .the-bar {
      stroke: black;
      stroke-width: 2px;
      fill: none;
    }

    .fill-the-bar {
      transition: transform 2s;
      transform: scaleY(1);
      transform-origin: bottom;
      stroke: none;
      fill: green;
      cursor: pointer;
    }

    .fill-the-bar:hover {
      transform: scaleY(7.5);
    }

    .dominant-baseline-hanging {
      dominant-baseline: hanging;
    }

    .dominant-baseline-middle {
      dominant-baseline: middle;
    }

    .text-anchor-end {
      text-anchor: end;
    }
  </style>
</head>

<body>
  <svg  width="250" height="500" 
   viewBox="0 0 250 500" version="1.1">
    <text class="text" x="10" y="25">Our Progress</text>
    <text x="90" y="50" class="dominant-baseline-hanging smaller-text
     text-anchor-end">100%</text>
    <text class="text smaller-text text-anchor-end" x="90" y="250">0%
    </text>
    <text class="text smaller-text text-anchor-end dominant-baseline-
     middle" x="90" y="150">50%</text>

    <rect x="100" y="50" height="200" width="50" class="the-bar">
    </rect>
    <rect class="fill-the-bar" x="100" y="230" height="20" width="50" 
     fill="green"></rect>
  </svg>
</body>

</html>
```

在浏览器中运行；过渡效果会慢慢增长，直到填满适当的空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/da3c849a-47d6-4b3b-9915-14ddb28b1bfd.png)

# 总结

在本章中，您学到了很多。CSS 是制作快速、易于维护的现代网站和应用的关键技术之一，了解 SVG 和 CSS 之间的交集是很重要的。

本章以详细介绍了将 SVG 用作 CSS 背景图像的常见用例，包括使用 SVG 数据 URL 的有趣细节。

接下来，您将学习 SVG 精灵和图标集，以及它们可以如何以及为什么可以用来替代当今网页上流行的常见字体图标集。

接下来，您将学习如何对内联 SVG 进行样式设置，包括详细的操作字体和文本行的方式。接着，您将学习许多控制`fill`、`stroke`和元素文本的 SVG 特定属性。之后，您将了解一些尖端的合成属性，比如`clip-path`和`mask-image`，尽管浏览器的支持还不完全到位，但它们非常强大。

之后，您将学习如何使用 CSS 来提高独立 SVG 图像的一致性和编写的便利性。

最后，您将学习如何使用基本的 CSS 动画和过渡效果来增加网站和应用的交互性和动态效果。

接下来，我们将把我们学到的关于将 SVG 放到页面上并确保它看起来正确的所有知识，加上 JavaScript，这样我们就可以开始以越来越有趣的方式与 SVG 进行交互了。
