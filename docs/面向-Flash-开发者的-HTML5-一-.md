# 面向 Flash 开发者的 HTML5（一）

> 原文：[`zh.annas-archive.org/md5/EE4F7F02D625483135EC01062083BBEA`](https://zh.annas-archive.org/md5/EE4F7F02D625483135EC01062083BBEA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《HTML5 for Flash Developers》专门为准备立即投入 HTML5 开发的 Flash 开发人员编写。我们将首先分析组成 HTML5 的每个元素，然后开始学习如何通过比较它们的特性与典型的 Flash 开发来利用它们。

# 本书涵盖的内容

第一章《为什么学习 HTML5？》开始回答了为什么学习如何在 HTML5 中开发可以成为一项非常重要的技能。我们将继续全面概述组成 HTML5 的所有不同技术以及它们的利用方式。

第二章《为战斗做准备》涵盖了为网络准备图像、音频和视频等资产的重要过程。本章还涵盖了 JavaScript 开发的许多重要方面，以及它们与 ActionScript 3 的不同之处。

第三章《可伸缩性、限制和效果》旨在告诉您 HTML5 开发人员在今天为网络开发时经常遇到的许多限制。我们还将首次详细了解最新的层叠样式表 CSS3 的添加。最后，我们将通过查看 HTML5 Web Workers、Web Sockets、Canvas 元素和最终的 WebGL 来概述 HTML 开发的一些最有趣的新添加。

第四章《使用 HTML5 构建强大的应用程序》继续深入研究 JavaScript 开发，旨在以面向对象的方式构建代码。还将进行与 ActionScript 3 类结构、用法和语法的比较，以及一些库和框架的概述，以帮助构建强大的 HTML5 应用程序。

第五章《一次编码，到处发布》探讨了使开发人员能够轻松地针对多个平台进行单个应用程序构建的应用程序和代码库，最大限度地减少开发时间并最大化公众使用。我们将花费大部分时间深入研究 CreateJS 框架及其所有包。最后，我们将介绍 CSS3 媒体查询如何允许在各种屏幕上进行有针对性的元素样式设置。

第六章《HTML5 框架和库》继续深入挖掘在开发下一个 HTML5 应用程序时可用的各种令人惊叹的框架和库。我们首先查看了当今最受欢迎的库之一，即 jQuery。除了 jQuery JavaScript 库，我们还将看看 jQuery Mobile 项目如何将简单的 HTML 文档转换为移动友好的用户界面。最后，我们将查看其他开源项目，如 Google V8、Node.js 和 Three.js。

第七章《选择开发方式》探讨了许多适用于 HTML5 开发人员的流行代码编辑平台。我们将概述大多数开发人员在为网络开发时从编码环境中需要的绝对必需品。我们还将花一些时间了解 Adobe Edge Animate 平台，该平台为创建 HTML5 动画提供了类似 Flash 的用户界面。

第八章《导出到 HTML5》继续查看更多允许您在平台上编写 HTML5 应用程序并直接编译为 HTML5 的软件。我们将概述许多流行的导出到 HTML5 的平台，如 Jangaroo、Haxe 和 Google 的 Dart。

第九章，*避免障碍*，试图展示和讨论许多开发人员在使用 HTML5 的许多新添加时所面临的典型问题。在本章中，我们将开发一个简单的 2D 横向滚动游戏，并检查常见问题发生的位置。

第十章，*发布准备*，通过讨论通常在将 HTML5 应用程序发布到互联网之前执行的许多常见任务，结束了本书。我们将讨论适当的浏览器测试方法以及利用“夜间”网络浏览器版本。我们将讨论许多方法，通过外部应用程序和浏览器插件对 HTML5 内容进行基准测试，以便您检查运行时问题。最后，我们将讨论通过使用 Grunt 等应用程序自动化 Web 开发人员反复执行的流程的方法。

# 您需要为本书准备什么

为了完全理解本书，需要以下软件：

+   符合 HTML5 标准的网络浏览器（Google Chrome，Firefox，Opera 等）。

+   HTML5 友好的文本编辑器（Sublime，Dreamweaver，Aptana 和 Adobe Brackets）

+   访问 Adobe Creative Cloud [`creative.adobe.com/`](https://creative.adobe.com/)

+   Adobe Flash

+   CreateJS 工具包[`www.adobe.com/ca/products/flash/flash-to-html5.html`](http://www.adobe.com/ca/products/flash/flash-to-html5.html)

访问互联网以下载最新版本的开源库和框架。

# 本书的受众

本书专门针对有 Adobe Flash 网页应用程序和游戏开发经验，准备将 HTML5 开发添加到其技能组合中的开发人员。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词如下所示："我们可以通过使用`include`指令来包含其他上下文。"

代码块设置如下：

```html
  this.setX = function(x) { _xVal = x; }
  this.setY = function(y) { _yVal = y; }
  this.currentX = function() { return _xVal; }
  this.currentY = function() { return _yVal; }
  this.currentWidth = function() { return _widthVal; }
  this.currentHeight = function() { return _heightVal; }
```

当我们希望引起您对代码块的特别关注时，相关的行或项目将以粗体显示：

```html
  this.setX = function(x) { _xVal = x; }
  this.setY = function(y) { _yVal = y; }
 this.currentX = function() { return _xVal; }
 this.currentY = function() { return _yVal; }
 this.currentWidth = function() { return _widthVal; }
 this.currentHeight = function() { return _heightVal; }

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词等，会在文本中以这种方式出现："单击**下一步**按钮将您移至下一个屏幕"。

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：为什么选择 HTML5？

在开始之前，重要的是您了解 HTML5 是什么，它是如何工作的，以及它与您作为 Flash 开发人员已经了解的内容有何关联。本书在比较 HTML5 的功能与 Flash 开发人员通常在 Flash 中创建应用程序时习惯使用的功能时，使用 Adobe Flash（CS6）作为参考。因此，要正确地跟随本书中的示例，需要对 Adobe Flash IDE 和 ActionScript 3 有扎实的了解。

在本章中，您将学到：

+   HTML5 实际上是什么，其中包括哪些技术

+   将 HTML5 开发添加到您的技能集中的原因

+   避免从 Flash 开发转换中涉及的初始问题

+   现代浏览器与 HTML5 功能的兼容性

# 理解 HTML5

作为 Flash 开发人员，您可能经常甚至每天都使用 HTML 作为在 Web 上发布编译后的 Adobe Flash SWF 文件的平台。虽然安装了 Flash Player 的 Web 浏览器可以查看独立的 SWF 文件，但将 Flash 内容嵌入 HTML 文档是正常的做法。由于 HTML 的简单语法和可用性，许多甚至不是开发人员的人已经学会了传统的 HTML 开发技术。不幸的是，早期的 HTML 规范在许多在线显示内容的领域存在不足。创建丰富的交互体验、共享多媒体资产或创建基于 Web 的用户界面以更典型的软件方式运行等常见任务变得非常繁琐，甚至不可能。最近，许多 Web 上的这些功能已经使用 HTML5 重新制作，使用户可以以相同的方式访问内容，但不需要使用 Adobe Flash Player 等技术。

构建可以全球访问的高质量基于 Web 的内容是成功产品或服务的关键。Facebook、Google 和 Twitter 都在使用 HTML5 来改善其应用程序的用户体验，并向用户提供内容，而无需第三方插件。越来越多的企业通过利用 HTML5 开发堆栈在桌面和移动 Web 浏览器以及两个平台上的可安装应用程序上进行应用开发，从而节省时间、资源和金钱。

将您的 Flash 开发技能转换为 HTML5 是一个有趣的过程，不仅会为您在职业上开启更多机会，还能让您更好地分析什么工具适合当前的工作。Adobe Flash 在短期内不会消失，但同样可以轻松地说 HTML5 也是如此。

由于许多开发人员从以前与 HTML 无关的 Web 和应用程序开发技术转向 Flash 开发，让我们从 HTML5 堆栈的基本知识开始。

## 什么是 HTML5？

HTML5 是由万维网联盟（[`www.w3.org/`](http://www.w3.org/)）开发的 HTML 标准的第五个也是最新的版本。作为一个新版本，它为现有的 HTML 规范带来了一些新功能，并删除了一些旧的过时功能。许多这些新功能和现有功能开始与 Adobe Flash 中的功能集紧密相似，从而开启了许多不依赖于付费应用程序或浏览器插件（如 Adobe Flash Player）的新的 Web 开发方面。

HTML5 规范的开发仍在进行中，并计划在 2014 年某个时候完成并发布，但今天大多数现代 Web 浏览器已经支持规范的许多功能。

一般来说，对 HTML5 的引用通常涉及到一套功能和技术，不仅涉及到 HTML，还涉及到**层叠样式表**（**CSS**）以及**JavaScript**。如果没有使用 CSS 和 JavaScript，即使是 HTML5 文档，其功能和外观仍然会非常简单。因此，学习 HTML5 实际上是在同时学习三种技术。尽管听起来很繁琐，但 Adobe Flash 的设置方式非常相似。Flash IDE 允许轻松创建、编辑和引用要在应用程序中使用的资产。要将这些资产集成到动态交互式应用程序中，需要使用**ActionScript**。HTML5 与此非常相似，其中 HTML 和 CSS 将是您的 Flash IDE，而 JavaScript 将是 ActionScript 的替代品。考虑到所有这些，让我们继续审查构建 HTML 的标准。

## HTML 标准

**万维网联盟**（[`www.w3.org/`](http://www.w3.org/)）或**W3C**负责创建今天 HTML 开发的标准。这些 Web 开发标准是为了统一开发人员创建网页的语法和功能，以及在 Web 浏览器中集成的功能集，以便在 HTML 中启用这些功能。通过以符合 HTML 规范标准的标记编写 Web 应用程序，开发人员可以更好地确保他们的内容将被正确显示，无论用户选择如何查看它。

## HTML 语法

尽管看起来微不足道，HTML 语法是所有网页的核心。无论是在 HTML 文件中硬编码，从另一个编程语言源编译，还是在应用程序运行时注入到文档中，HTML 语法都是 HTML 页面中使用的资产的蓝图。开发人员对 HTML 语法及其限制的理解越深入，构建应用程序就会越容易。

HTML 语法是使用包裹在尖括号中的标签元素编写的。HTML 标签有两种不同的类型：成对的或空元素。成对的 HTML 标签是最常见的，也是创建 HTML 文档时通常使用的第一种标签样式。`html`标签用于声明 HTML 文档中的内容，并通常位于 HTML 文件的第一行和最后一行：

```html
<html>
  Add your HTML content here.
</html>
```

如前面的例子所示，成对标签打开和关闭一个容器，以便更多的 HTML 元素放置在其中。标签的格式始终相同，成对标签之间唯一的区别是使用斜杠来声明标签正在关闭一个元素。因此，`<html>`将不会与不包含相同内部值的任何标签配对。HTML 标签不区分大小写，在早期，开发人员在编写标签时通常总是使用大写。这种传统现在已经消失，你几乎总是会看到标签以小写形式书写。

空的 HTML 标签是不使用闭合标签写的。例如，在 HTML 文档中放置图像引用时，没有更多的 HTML 元素内容可以放置在该图像中。因此，在 HTML 中，图像引用的格式如`<imgsrc="img/my_image.jpg">`。通过将`src`参数附加到`img`标签中，并将其值设置为图像位置来引用图像。

### 提示

如果您已经成功使用**Adobe Flex**构建任何 Flash 内容并利用**MXML**用户界面标记语言，您可能已经掌握了使用诸如`<imgsrc="img/my_image.jpg" />`这样的语法来关闭空标签元素。在 HTML5 中，这个尾部的斜杠是不需要的，但如果您添加它，仍然会正确呈现您的内容。为了最佳使用情况，请尽量养成在 HTML5 项目中不使用它的习惯。

在调试 HTML 时，HTML 是一个棘手的问题；语法错误的文档不会像传统的 Flash 应用程序一样在加载时显示错误。编写干净简洁的 HTML 是保持无错误、标准、符合规范的网页的关键。有许多应用程序和工具可用于帮助开发干净的 HTML 代码，其中一些将在本书的后面部分介绍。W3C 创建了一个强大的 HTML 语法验证服务，可以检查公开可用的网站的 HTML 错误([`validator.w3.org/`](http://validator.w3.org/))。

## HTML 元素

每个 HTML 规范版本都有一组特定的标签可供开发人员在创建 HTML 文档时使用。W3C 定义的 HTML5 规范中当前的元素列表可以在其语言参考文档中找到([`www.w3.org/TR/html-markup/elements.html`](http://www.w3.org/TR/html-markup/elements.html))。

在 HTML5 规范中，对于媒体集成到网页中，开发人员可以使用一些非常有趣的新元素。例如，通过添加`audio`和`video`标签，现在可以避免嵌入音频或视频时对 Flash 的要求。这些令人兴奋的新媒体标签将在第三章中更深入地介绍，*可伸缩性、限制和效果*。

## 引入样式

层叠样式表或 CSS 是用于为 HTML 元素设置样式的主要方法。与 HTML 一样，在 CSS 中有一组样式列表，您可以将其应用于 HTML 文档中的元素。要了解可用于您的 CSS 属性的想法，请转到[`www.w3schools.com/cssref/`](http://www.w3schools.com/cssref/)查看完整列表。CSS 可以以多种不同的方式应用于 HTML 元素。传统上，CSS 语法存储在外部的`.css`文件中，并从 HTML 文档的`head`元素中引用。但是，CSS 也可以直接附加到 HTML 文档中的元素中，方法是在`body`标记内的几乎任何元素中添加`style`参数：

```html
<imgsrc="img/my_image.jpg" style="border:5px solid #000000;">
```

在上一个示例中，使用`style`参数在图像元素上应用了一个 5 像素宽的黑色边框，该图像在`src`参数中引用。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

如果您的页面中有五个图像，甚至 100 个图像需要应用相同的样式到每个元素，那该怎么办？将完全相同的`style`参数应用于每个图像标记不仅耗时，而且会导致代码过大，可能极难维护或更新。CSS 可以通过使用`class`或`id` HTML 参数来针对单个元素或一组元素：

```html
<div id="photo-gallery">
  <imgsrc="img/photo1.jpg" class="photo">
  <imgsrc="img/photo2.jpg" class="photo">
  <imgsrc="img/photo3.jpg" class="photo">
  <imgsrc="img/photo4.jpg" class="photo">
  <imgsrc="img/photo5.jpg" class="photo">
</div>
```

在前面的示例中，我们尝试在 HTML 文档中显示一组不同的图像。每个图像，使用`img`元素标记引用，并附加了一个值为`photo`的`class`参数。`class` HTML 参数可以在几乎任何可用的元素上使用和重复使用，并允许您引用一组元素，而不是直接修改每个元素。所有图像也都包含在一个`div`元素中。`div`元素用作显示内容的容器。在这种情况下，`div`元素的`id`参数设置为`photo-gallery`。`id` HTML 参数与`class`非常相似，但可以在同一 HTML 文档中重复使用相同的`id`值。

### 提示

通过使用设置为辅助 HTML5 语法的代码编辑应用程序，可以简化编辑 HTML、CSS 和 JavaScript。推荐使用**Aptana**（[`aptana.com/`](http://aptana.com/)）、**Dreamweaver**（[`adobe.com/products/dreamweaver.html`](http://adobe.com/products/dreamweaver.html)）和**Sublime Text**（[`sublimetext.com/`](http://sublimetext.com/)）等应用程序。然而，如果你喜欢简单，可以随意使用其他工具。

考虑到所有这些，编写 CSS 来为这个相册添加样式可以按以下方式完成：

```html
<!DOCTYPE html>
<html>
  <head>
    <title>My Photo Gallery</title>

    <!-- Our Photo Gallery CSS Styles -->
    <style type="text/css">
      body {
        background-color:#000000;
      }

      #photo-gallery {
        width:100%;
      }

      #photo-gallery .photo {
        width:200px;
        border:4px solid #ffffff;
      }
    </style>
  </head>
  <body>
    <div id="photo-gallery">
      <imgsrc="img/photo1.jpg" class="photo">
      <imgsrc="img/photo2.jpg" class="photo">
      <imgsrc="img/photo3.jpg" class="photo">
      <imgsrc="img/photo4.jpg" class="photo">
      <imgsrc="img/photo5.jpg" class="photo">
    </div>
  </body>
</html>
```

现在，我们可以在`head`元素内使用`style`标签来放置原始的 CSS 代码，而不是将`style`参数应用到文档中的每个元素。在前面的例子中，HTML 元素以三种不同的方式被选中。首先，通过使用其十六进制值，将文档的背景颜色设置为黑色。我们通过简单地使用标签引用来选择`body`标签元素。这种选择原始元素的方法可以用于文档中的各种元素，但会影响具有该引用的所有元素。第二种选择方法是查找具有特定 ID 的元素。为了指定使用 ID，需要在 ID 值前面加上`#`。因此，`#photo-gallery`将选择具有`id`参数设置为`photo-gallery`的`div`元素。我们将相册容器的`width`参数设置为`100%`，这是根据查看 HTML 文档时的浏览器宽度计算的。最后，为了为相册中的每个图像添加样式，我们为应用到 HTML 文档的每个图像标签的类添加样式。由于`class` HTML 参数可以应用于 HTML 文档中无限数量的元素，我们可以通过将 CSS 元素选择链接在一起来具体地定位另一个元素中的类。在 CSS 中，通过在类名前面添加`.`来选择类。因此，`#photo-gallery .photo`将仅选择具有`photo`类名的元素，这些元素位于具有`id`为`photo-gallery`的元素内：

![引入风格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_01_01.jpg)

## 交给 JavaScript

仅使用 CSS 来为 HTML 元素添加样式只能让你走得更远。从 Flash 开发者的角度来看，HTML 和 CSS 在效果上等同于 Flash IDE。缺少的是驱动应用程序内交互和功能的代码。在使用 Flash 时，创建强大应用程序时，ActionScript 是首选的武器。在开发 HTML5 内容时，JavaScript 将会发挥作用，使你的 HTML 元素焕发生机。

## 什么是 JavaScript？

JavaScript 自上世纪 90 年代中期就存在，并已成长为最流行的脚本语言之一。JavaScript 通过添加内容修改、动画、3D 图形、表单提交和数据检索等功能，为 HTML 文档增添了生机，而无需重新加载活动的 HTML 文档。这些功能使得 Web 内容更像传统软件应用程序，而不是静态网页。

与 ActionScript 3 不同，JavaScript 是一种真正的脚本语言，因为它不需要预处理或编译就可以运行。就像 HTML 和 CSS 一样，JavaScript 文档的源代码在用户请求时发送到用户端并在客户端执行。因此，与 ActionScript 等技术不同，JavaScript 源代码是公开可见的。

## JavaScript 的作用

回顾我们的`我的照片库`示例，一个重要的缺失功能是查看所选照片的大尺寸。JavaScript 是一个完美的平台，可以通过它的主要用途将交互性带入 HTML 文档。使用现有的代码示例，我们可以通过在页面主体底部添加一个新的`div`元素来扩展其功能，以包含更大的图像视图。这个元素可以是空的，因为我们不希望在页面加载时默认显示照片。最后，我们在`div`标签上设置一个标识符`id="photo-display"`，这将允许我们从 CSS 和 JavaScript 中定位该元素中的内容：

```html
<div id="photo-display"></div>
```

在集成 JavaScript 功能之前，我们需要使用`#photo-display`附加一些 CSS 样式到`div`，以允许所选照片以更高分辨率填充浏览器窗口，这是大多数照片库显示的典型特征。在 CSS 样式中，我们已经为此示例设置了一些样式属性，我们将在`#photo-display`元素中附加一些更多的样式属性：

```html
#photo-display {
  display:none;
  position:absolute;
  top:0;
  width:100%;
  height:100%;
  background-color:#000000;
  text-align:center;
}

#photo-display img {
  margin:auto;
  margin-top:50px;
  max-height:800px;
  border:4px solid #ffffff;
}
```

这个 CSS 将只针对一个特定的`div`，因为我们使用了`#photo-display`语法来定位它。为了开始样式，我们从最重要的参数`display:none`开始，这会在页面加载时隐藏元素。这在我们的情况下是完美的，因为我们不希望在页面加载时看到全屏显示。通过为`#photo-display`元素的样式定义添加`position:absolute`和`top:0`，我们将在 HTML 主体中声明的先前元素的顶部显示该元素。在`#photo-display`上设置的其余样式都很容易理解。CSS 的下一行专门针对具有`photo-display`类的`div`中的`img`元素。我们可以在 CSS 中通过链接标识符来做到这一点。在这种情况下，我们为自定义命名的元素 ID 内的图像标签元素指定这些样式。

在 HTML 和 CSS 中显示所选照片的大尺寸版本后，下一步是添加 JavaScript 代码，以便在用户交互时在`#photo-display`容器中显示所选照片。为了将这个示例整合到一个文件中，我们将在 HTML 的`script`元素中添加 JavaScript：

```html
<!-- Our Photo Gallery JavaScript Source -->
<script>
  var largeImage = new Image();

  // Display a specific photo in the large
  // photo display element.
  var displayPhoto = function(source) {
    // If there is already an image inside the display
    // remove it.
    if(largeImage.src != '') {
      document.getElementById("photo-display").removeChild(largeImage);
    }

    // Update the source location of the image
    largeImage.src = source;
    document.getElementById("photo-display").appendChild(largeImage);

    // Display the large photo element.
    document.getElementById("photo-display").style.display = 'block';
  }

  // Closes the large photo display element.
  var closePhotoDisplay = function() {
    document.getElementById("photo-display").style.display = 'none';
  }
</script>
```

作为 Flash 开发人员，以前的函数语法应该看起来很熟悉。在函数范围内的一个重大变化是变量语法。与 AS3 不同，HTML 以及源变量都不是严格类型的。这适用于 JavaScript 语法中的所有变量，这可能是 Flash 开发人员对 JavaScript 最大的问题之一。

除了对源变量进行一些字符串操作以生成`img` HTML 元素之外，该方法还引用了文档对象。加载到浏览器中的每个 HTML 文档都成为 JavaScript 中可访问的文档对象。JavaScript 中的文档对象具有许多内置属性和方法，可用于访问视图 HTML 文档中的信息和元素。在我们的示例中，我们利用了易于定义的文档对象方法`getElementById()`。正如方法名称所暗示的那样，当提供 HTML 元素的 ID 时，将返回对 HTML 文档中元素的引用，以便在脚本中使用。由于 JavaScript 支持属性的链接，我们可以应用`innerHTML`属性来操作 HTML 元素的内部内容，以及`style`属性来更改元素的 CSS 属性。

为了使用户在查看完照片后能够关闭图像，我们将在示例中添加第二个 JavaScript 函数，以恢复显示照片时所做的所有更改。由于当用户点击新图像时，`photo-display`图像将被更新，我们的`closePhotoDisplay`方法所需做的就是隐藏可见元素，以再次显示完整的照片库：

```html
functionclosePhotoDisplay() {
  document.getElementById("photo-display").style.display = 'none';
}
```

将`#photo-display`元素的`style.display`设置回`none`会隐藏整个元素，并将用户界面恢复到初始状态。

将事件添加到每张照片中可以通过向目标元素附加`onclick`参数来轻松实现。添加如下：

```html
<imgsrc="img/photo1.jpg" class="photo"onclick="displayPhoto('photo1.jpg')">
```

现在，当单击图像时，`onclick`事件将被触发并运行参数中声明的 JavaScript 代码。在这种情况下，我们利用这个机会来调用我们之前编写的 JavaScript 块中的`displayPhoto`方法。在调用中，我们提供所需的源变量，这将是图像文件名作为`String`数据类型。这将允许在`#photo-display`元素中使用正确的图像引用。将所有内容放在一起，我们更新的带有`id="#photo-gallery"`的`div`标签现在看起来像下面这样：

```html
<div id="photo-gallery">
  <imgsrc="img/photo1.jpg" class="photo"onclick="displayPhoto('photo1.jpg')">
  <imgsrc="img/photo2.jpg" class="photo"onclick="displayPhoto('photo2.jpg')">
  <imgsrc="img/photo3.jpg" class="photo"onclick="displayPhoto('photo3.jpg')">
  <imgsrc="img/photo4.jpg" class="photo"onclick="displayPhoto('photo4.jpg')">
  <imgsrc="img/photo5.jpg" class="photo"onclick="displayPhoto('photo5.jpg')">
</div>
```

最后，为了使用户能够关闭`#photo-display`元素中的打开图像，我们将应用一个`onclick`事件来调用我们的`closePhotoDisplay`方法。我们将事件应用于`#photo-display`元素中的图像，而是将其定位到显示本身，允许用户在浏览器中的任何位置单击以关闭显示：

```html
<div id="photo-display" onclick="closePhotoDisplay()"></div>
```

将所有这些代码片段放在一起，画廊源现在看起来像下面这样：

```html
<!DOCTYPE html>
<html>
  <head>
    <title>My Photo Gallery</title>

    <!-- Our Photo Gallery CSS Styles -->
    <style type="text/css">
      body {
        background-color:#000000;
      }

      #photo-gallery {
        width:100%;
      }

      #photo-gallery .photo {
        width:200px;
        border:4px solid #ffffff;
      }

      #photo-display {
        display:none;
        position:absolute;
        top:0;
        width:100%;
        height:100%;
        background-color:#000000;
        text-align:center;
      }

      #photo-display img {
        margin:auto;
        margin-top:50px;
        max-height:800px;
        border:4px solid #ffffff;
      }
    </style>

    <!-- Our Photo Gallery JavaScript Source -->
    <script>
      var largeImage = new Image();

      // Displays a specific photo in the large
      // photo display element.
      var displayPhoto = function(source) {
        // If there is already a image inside the display
        // remove it.
        if(largeImage.src != '') {
          document.getElementById("photo-display").removeChild(largeImage);
        }

        // Update the source location of the image
        largeImage.src = source;
        document.getElementById("photo-display").appendChild(largeImage);

        // Display the large photo element.
        document.getElementById("photo-display").style.display = 'block';
      }

      // Closes the large photo display element.
      var closePhotoDisplay = function() {
        document.getElementById("photo-display").style.display = 'none';
      }
    </script>
  </head>
  <body>
    <div id="photo-gallery">
      <!-- Place all of the images inline with a 'photo' class for CSS manipulation. -->
      <imgsrc="img/photo1.jpg" class="photo"onclick="displayPhoto('photo1.jpg')">
      <imgsrc="img/photo2.jpg" class="photo"onclick="displayPhoto('photo2.jpg')">
      <imgsrc="img/photo3.jpg" class="photo"onclick="displayPhoto('photo3.jpg')">
      <imgsrc="img/photo4.jpg" class="photo"onclick="displayPhoto('photo4.jpg')">
      <imgsrc="img/photo5.jpg" class="photo"onclick="displayPhoto('photo5.jpg')">
    </div>

    <!-- An empty DIV element to contain the user selected photo in large scale. -->
    <div id="photo-display" onclick="closePhotoDisplay()"></div>
  </body>
</html>
```

将文本保存到`.html`文件中，并在 Web 浏览器中启动它，现在将显示出我们所有的辛勤工作。就像以前一样，画廊应该从默认显示图像列表开始。一旦单击图像，选择将传递到`#display-window`元素，并以浏览器宽度的 100％显示：

![JavaScript in action](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_01_02.jpg)

最后，在文档中的任何位置单击将关闭大图像，并将您返回到初始画廊显示。

尽管此示例不包含 HTML5 的新功能，但这是展示 HTML 的一些关键技术和引用 HTML 中资产的一些方法的简单方式。

# 为什么要学习 HTML5？

作为 Flash 开发人员，进入 HTML5 开发领域是一个非常合乎逻辑的步骤，原因有很多。使用 HTML5 构建应用程序可以让您轻松地在桌面或移动设备上接触到用户，而无需插件即可获得丰富的集成和交互式内容。HTML5 开发最有益的一个方面是开发环境的可访问性。由于 HTML5 不需要特殊的编译器或软件来编写代码，开发人员可以自由选择他们喜欢的设置来编写和测试他们的项目。应用程序可以在任何兼容的 Web 浏览器中轻松运行和测试，并且可以在本地进行测试，而无需 Web 服务器。这使得 HTML5 成为 Web 上最易访问和易用的技术之一。

## 一次编写，到处部署

与 Flash 应用程序不同，任何具有现代 Web 浏览器的设备都可以与 HTML5 Web 内容进行交互。因此，借助 CSS 对可视内容进行动态调整，您的 HTML5 应用程序可以在不需要在桌面或移动平台上安装应用程序或依赖的情况下使用。开发人员还可以使用诸如**Phone Gap**（[`phonegap.com/`](http://phonegap.com/)）或**Appcelerator**（[`www.appcelerator.com/`](http://www.appcelerator.com/)）等技术，将其现有的 HTML5 Web 内容轻松转换为打包的移动应用程序，以在所有现代移动操作系统中上市。打包的应用程序可以通过诸如苹果的**App Store**（[`store.apple.com`](http://store.apple.com)）和**Google Play**（[`play.google.com`](https://play.google.com)）等常见移动应用程序服务进行集成和销售。此外，**Microsoft Windows 8**桌面应用程序开发现在支持一整套不同的编程语言，其中之一就是 HTML5（[`msdn.microsoft.com/en-us/library/windows/apps/br211386.aspx`](http://msdn.microsoft.com/en-us/library/windows/apps/br211386.aspx)）。通过将 HTML5 内容打包成可安装的应用程序，开发人员现在可以通过各种应用程序分发渠道轻松地将其作品进行销售。

## 令人兴奋的新功能

正如刚才提到的，HTML5 拥有一系列新的令人兴奋的功能，其中许多将在本书的后续章节中介绍。然而，为了让您更好地理解为什么 HTML5 对 Flash 开发人员和 Web 开发社区如此令人兴奋和重要，这里是一份更详细的一些功能列表。

### canvas - 2D 绘图 API

Flash 开发人员可以在新的`canvas`元素和 2D 绘图 API 中充分发挥他们的编程能力。就像 ActionScript 3 中的绘图 API 一样，`canvas` HTML5 元素允许开发人员在运行时创建动态图形，所有这些都可以通过 JavaScript 完成。转向 HTML5 的 Flash 游戏开发人员通常会在使用 HTML5 时找到他们的家园，因为`canvas`元素是传统 Flash 开发的最接近的表示。

### 媒体播放

Web 开发人员不再需要使用 Flash 或 Quicktime 等平台来开发他们的媒体播放元素。音频和视频现在可以通过`audio`和`video`标签轻松集成到 HTML 文档中。这不仅使播放元素更容易、更便宜地集成到网页中，而且移动设备在其集成浏览器中读取和显示这些元素时也没有问题。

### 离线存储

传统上，当 Web 开发人员需要在用户的计算机上本地保存数据时，他们使用**cookies**。HTML5 添加了一种新的离线存储方法，称为**Web Storage**（[`dev.w3.org/html5/webstorage`](http://dev.w3.org/html5/webstorage)），可以大大增加应用程序的能力，当您需要保存数据以供重复使用时。像客户端用户特定的应用程序配置这样的大量数据现在可以以更安全、更快的方式存储。

现在还可以设置 HTML5 内容在用户离线时可用，方法是利用 HTML5 的**缓存清单**。缓存清单只是一个简单的文本文件，放在您的 Web 服务器上。如果 Web 浏览器支持使用 HTML5 缓存清单（所有现代浏览器目前都支持），则在清单中放置的文件和资产的引用都会被缓存在客户端。根据您的清单是否设置为缓存运行应用程序所需的所有内容，用户可以在离线状态下继续使用应用程序。结合使用 HTML Web 存储将数据存档以在重新连接到互联网时重新发送到 Web 服务器，您可以开发应用程序，使用户可以在连接中断的情况下无缝地使用它们。HTML5 功能的一个完美示例是 Google 的**Gmail**（[`mail.google.com`](https://mail.google.com)）。通过在用户访问时在设备上存档消息数据，例如电子邮件，在用户在地铁地下时打开消息时，仍然可以查看重要信息。

### 文档编辑

许多 HTML5 元素现在允许使用参数`contenteditable="true"`，这允许用户编辑元素内的所有内容。这个功能直接将所见即所得的环境带到了 HTML 内容中。在 HTML5 项目中操作内容时，内联文档编辑对开发人员来说非常方便。

### 拖放

HTML5 元素现在具有可拖动的能力。诸如此类简单但重要的用户体验增强功能，可以带来更多类似应用程序的交互性，传统上需要使用 JavaScript 来构建。就像内联文档编辑一样，在开发过程中将元素设置为可拖动可以帮助找到正确的位置属性。

### 地理定位

地理定位 API 使用户可以允许将其当前位置发送到 HTML5 文档中供 JavaScript 使用。除了在地图应用程序中使用用户位置的明显用途外，地理定位值还可以为允许更交互式用户体验的 Web 文档添加许多新功能。

### 文件 API

HTML5 中的文件 API 允许在处理用户本地计算机上的文件时获得更交互式的体验。现在可以将本地文件拖入浏览器，并在 HTML 文档中预览，而无需将数据上传到 Web 服务器。

### 提示

要更深入地了解 HTML5 中的完整功能集，请访问在线 W3C API 文档（[`www.w3.org/TR/html5/`](http://www.w3.org/TR/html5/)）。

## 移动设备可访问性

随着越来越多的设备集成了互联网功能，需要流畅、多平台的应用程序，可以实现低开销和集成设备访问的需求达到了历史最高点。几乎所有现代移动浏览器已经支持 HTML5 的许多功能，Web 开发人员可以利用这些功能来构建与特定移动平台上许多原生应用程序相媲美的移动应用程序。地理定位、本地文件访问和离线存储等功能使应用程序能够轻松地整合到运行它们的设备硬件中。

### 提示

本书中的任何示例都可以在运行 HTML5 兼容的现代移动设备上运行。如果您有 iPhone、Android 或 Windows 手机，可以在设备上测试示例，查看移动平台如何运行 HTML5 内容。

HTML5 出现的最大推动力之一是移动设备。移动应用程序开发需要与典型应用程序开发略有不同的方法，因为运行应用程序的平台不仅资源较少，而且还需要考虑诸如电池寿命、屏幕分辨率和触摸界面等因素。在开发 Flash 应用程序时处理所有这些要求可能会有些棘手。Flash 应用程序传统上在资源使用上有些沉重，尽管可以进行优化来弥补在移动平台上运行应用程序时的一些问题。

## 移动设备上的 Flash Player

自 iPhone 问世以来，Flash 开发人员不得不面对这样一个事实，即他们基于 Web 的 Flash 内容永远无法在集成的 iOS Web 浏览器中查看。苹果在 2010 年 4 月史蒂夫·乔布斯公开信中明确表明了对 Adobe Flash Player 使用的立场，指出 Flash Player 无法在他们的设备上提供所需的性能。

2012 年 6 月，Adobe 发布了一份关于 Adobe Flash Player 在移动设备上的未来的公开声明。截至 2012 年 8 月 15 日，Android 版 Flash Player 只能在经过认证可以运行 Flash Player 的设备上使用，因为 Adobe 已经暂停了移动版 Flash Player 的开发。运行 Android 4.1+版本的用户将无法在其浏览器中运行 Flash 内容，所有 Web 内容将依赖于 HTML5 中的技术。

随着 Flash Player 从移动市场上被移除，目前 Flash 开发人员创建移动应用程序的唯一资源是使用**Adobe AIR**开发并将他们的工作打包为独立应用程序，而不是在 Web 上运行。

## 建立在现有的技能基础上

Flash 开发人员转向 HTML5 开发时，学习使用纯 HTML、CSS 和 JavaScript 创建令人惊叹的应用程序的技巧会更容易一些。不仅所有关于处理和优化媒体元素的经验都会转移过来，而且他们的 ActionScript 3 技能也将使他们能够充分理解和使用 JavaScript。

## ECMAScript

开发人员投入学习诸如 ActionScript 3 之类的编程语言的时间远非短暂。幸运的是，JavaScript 和 ActionScript 3 都是基于**ECMAScript**脚本语言标准构建的（[`www.ecmascript.org`](http://www.ecmascript.org)）。简而言之，这意味着许多方法、变量和属性的语法设置在外观、感觉和使用上都非常相似。当我们深入挖掘并看到 HTML5 的更多实例时，如果你有 ActionScript 3 的经验，你将立即注意到在使用 JavaScript 时有许多相似之处。

# 避免最初的障碍

所有 Flash 开发人员在转向 HTML5 开发时通常都会遇到相同的问题。大多数问题都源于平台语法之间的差异，以及处理 HTML5 堆栈内每个元素之间的交互。

## 舞台与 DOM

转向 HTML5 开发时最明显的变化之一是缺少了重要的 Flash 舞台。在 HTML5 中处理元素布局、资产动画和交互性都纯粹通过代码来实现。尽管有许多带有拖放式界面的 Web 开发 IDE，为了更好地理解如何构建更干净的网页，本书将涵盖所有手写代码示例。

## 在 DOM 中定位资产

许多 Flash 开发人员在转向 Web 开发时最初遇到的一个最大问题是在 DOM 中定位内容和资产的概念。除非指定，HTML 元素不会简单地使用 X 和 Y 位置值放置在 DOM 中。由于 HTML 文档中的元素默认以内联方式显示，全局 X 和 Y 位置值是无关紧要的。在 DOM 中使用 CSS 定位元素时，而是使用诸如 margin、padding、top、left、right 和 bottom 等属性。如前所述，如果元素被特别设计为绝对位置或在`canvas`元素中使用，则可以使用 X 和 Y 值。除了简单地控制项目中元素放置的问题之外，还有确保可能查看内容的所有 Web 浏览器都按照您的规格显示内容的问题。

## 处理媒体元素

媒体优化是提供 Web 内容的关键。在使用 Flash 时，许多使用的资产是基于矢量的，因此在编译后的 SWF 文件大小上轻量级。Flash SWF 中使用的位图数据在编译期间被压缩，因此自动帮助您最小化文件大小。由于大多数 HTML 文档所做的是引用公开可访问的原始文件，因此每个使用的资产都应该针对最小文件大小进行优化，同时尽可能保持预期的质量接近原始质量。随着本书各章节中涵盖 HTML5 开发的不同方面，将涵盖用于网页中使用的不同类型媒体的许多优化方法。

## 保护您的代码

在 Adobe Flash 中发布内容会输出一个编译后的二进制 SWF 文件，该文件已准备好在兼容的 Flash Player 中播放。应用程序中使用的代码和资产免受窥视，因为应用程序已编译为单个二进制文件。但是在处理 Web 上的代码和资产时，整个游戏都会发生变化。几乎您在 HTML5 项目中创建和交付的所有内容，与任何网站一样，都可以公开查看。

代码混淆是一些开发人员在交付生产级别客户端代码时使用的一种做法。许多网站和应用程序可用于通过以难以阅读的压缩格式重写代码来混淆 JavaScript 代码。尽管这并不是保护代码的绝对方法，但在用户查看文档源代码时，它增加了一定程度的威慑力。

理解客户端代码的使用和限制是编写安全 JavaScript 应用程序的关键。敏感信息不应该硬编码到可以在客户端查看的文档中。第二章，“准备战斗”，比 ActionScript 3 更深入地涵盖了客户端脚本的使用。

## 浏览器和平台兼容性

从 Flash 转向 HTML5 开发时的主要变化之一是需要使用相同的代码库针对多个平台进行开发。在使用 Adobe Flash 开发应用程序时，您最初为应用程序设置 Flash Player 的目标版本。通过将应用程序编译为打包的 SWF，Flash 运行时将无法在任何兼容的 Flash Player 中渲染您的应用程序。由于每个浏览器和平台都倾向于以稍微不同的方式显示 Web 内容，因此在开发 HTML5 内容和应用程序时，必须注意可能用于查看内容的平台和浏览器，以更好地优化查看体验。

可以将浏览器功能检查写入 JavaScript 条件中，以便使那些不支持特定 HTML5 功能的浏览器的用户仍然可以查看你的 HTML5 内容。例如，如果用户访问一个包含 HTML5 视频播放元素的页面，而他的浏览器不支持它，JavaScript 可以选择替代地嵌入 Flash 视频播放应用程序。

### 提示

找到一个不支持 HTML5 的现代 Web 浏览器变得越来越困难。在阅读本书时，选择一个用于测试代码的浏览器时，Firefox（[`www.getfirefox.net/`](http://www.getfirefox.net/)）、Chrome（[`www.google.com/chrome`](http://www.google.com/chrome)）、Safari（[`www.apple.com/safari/`](http://www.apple.com/safari/)）和 Opera（[`www.opera.com/`](http://www.opera.com/)）都是很好的选择，并且可以在线免费使用。

在本书的章节中，将使用许多这些流行的 Web 浏览器来展示内容在外观和使用上有时可能会有所不同。由于浏览器更新和变化的速度很快，尽可能在每个平台的每个浏览器中测试你的网站是 Web 开发的一个非常重要的方面。许多这些 Web 浏览器现在都有内置的开发和调试工具，可以更轻松地优化你的 HTML5 项目。还有其他应用程序和服务可用于简化浏览器测试的痛苦，其中一些将在本书中使用和介绍。

# 总结

在这一章中，我们已经涵盖了 HTML5 技术栈的关键方面，以及如何以简单的方式使用它们。通过创建一个简单的相册网页，我们不仅使用了 HTML、CSS 和 JavaScript，还使用了它们之间引用元素的方法。一些 HTML5 中的新功能也被解释并与传统上在 Flash 资产中创建的功能进行了比较。回顾了 Flash 开发人员转向 Web 开发时的典型问题，让你在发现问题之前就意识到这些问题。希望这一章能进一步激发你对学习 HTML5 更多可能性的兴趣。

W3C 维护的 HTML5 标准的制定是一个有趣但非常深入的话题，这超出了本书的范围。如果你对了解 HTML5 标准的制定和维护更感兴趣，我强烈建议查看并关注 W3C 在其网站上发布的规范和语法开发信息（[`www.w3.org`](http://www.w3.org)）。

在完成平台概述后，我们将继续深入研究 HTML5 技术栈中最重要的方面 JavaScript，以及它与你已经了解的使用 ActionScript 开发的知识的关系。


# 第二章：为战斗做准备

现在您了解了 HTML5 的构成技术，我们可以开始动手了。但在我们开始编写 HTML、CSS 和 JavaScript 之前，我们需要覆盖项目开发的第一步基础知识，即资产准备。没有设计、资产和内容，您的网页将不会很吸引人，或者说，功能不完善。在准备过程中，我们还将深入研究 JavaScript 的语法规范，以及它与 ActionScript 3 的关系，为我们在第三章 *可扩展性、限制和效果*中进行全面开发做准备。

在本章中，我们将涵盖：

+   准备常见资产，如图像、音频和视频，以在 HTML5 文档中使用

+   在浏览器中代码输出和调试

+   JavaScript 的基础知识和与 ActionScript 3 的语法变化

+   JavaScript 在实际操作中的示例以及代码执行的正确方法

# 准备资产

在 Flash 中开发应用程序时，可以通过几种不同的方式将资产（如图像、音频和视频）集成到典型项目中。您可以选择通过直接在 Flash 项目库中导入它们的典型方式来集成资产。将资产添加到 Flash 项目中会导致资产包含到编译的 SWF 文件中。由于所有资产都编译在一个文件中，因此无需从互联网等外部资源获取资产。编译在编译的 Flash 项目中的资产本质上受到保护，不会被获取或被公开引用。

不幸的是，项目库内部引用的资产一旦项目被导出就无法更新或更改。开发应用程序，如视频播放 UI 或照片库，需要动态集成资产，从而产生一个可以无限使用的单个应用程序实例。可以通过请求外部文件来集成外部资产，这些文件在互联网上是公开可访问的。外部集成可以减小应用程序的大小，并且可以修改外部资产而无需进行应用程序更新。不幸的是，如果文件不可用或用户未连接到互联网，则无法集成资产，可能会导致应用程序失败。

外部资产集成是将内容包含到基于 Web 的文档中的标准方式。将被 HTML 文档引用的文件通常放在与嵌入它们的 HTML 文档相同的 Web 服务器上。

资产也可以从互联网上的其他 Web 服务器引用，但内容取决于具有访问权限的开发人员或管理员。开发人员的懒惰或试图降低带宽成本可能导致图像或其他资产被嵌入到外部来源，将带宽费用转移到您自己以外的 Web 服务器。这个过程被称为**热链接**，在 Web 开发社区中被视为不良行为，因为您迫使其他网站所有者承担资产分发的成本。

由于 Web 内容没有像 Flash 中的编译器那样自动优化，Web 开发人员必须自行准备其内容和资产以供 Web 使用。由于 Web 内容根据用户的可变互联网连接速度按需传送，资产的文件大小应尽可能小，以便最终用户能够以尽可能少的延迟进行播放和查看。让我们回顾一下常见资产类型以及为将它们嵌入到我们的 HTML 文档中准备的正确方法。

### 提示

所有用于优化和转换的资产都可以在书籍的可下载示例文件中的`Chapter 02_examples`目录中找到。

## 图像

将图像添加到项目中通常是每个基于 Web 的项目中使用的第一种资产集成技术。Web 上的所有图像通常以 JPEG、PNG 或 GIF 三种不同格式之一出现。每种格式都有特定的用途，应根据设计和功能的要求来使用。尽管这些图像格式在日常使用中很常见，但重要的是要了解每种格式的优缺点，以便将图像优化地集成到 HTML 文档中。

### 注意

可以在 Packt Publishing 网站（[www.packtpub.com](http://www.packtpub.com)）上下载示例文件，跟着本书学习。如果你没有 Photoshop CS6 的副本，可以从[`www.adobe.com/cfusion/tdrc/index.cfm?product=photoshop&loc=en_us&promoid=IICUB`](http://www.adobe.com/cfusion/tdrc/index.cfm?product=photoshop&loc=en_us&promoid=IICUB)免费下载和安装演示版。

考虑一下这张高质量的未压缩 CR2 格式图像，直接从佳能数码单反相机拍摄而来。这张原始图像的大小为 27 兆字节，因此不适合在任何现代 Web 浏览器中查看或嵌入。

![Images](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_01.jpg)

即使 Web 浏览器可以处理将图像放入 HTML 文档中，下载图像所需的时间也将是巨大的。尽管如今普通的高速互联网连接很常见，但不多的用户愿意等待几分钟以上来查看加载网页时的单个图像。因此，在将图像用于 Web 之前，必须对其进行优化。当在 Photoshop 中打开这个 CR2 图像时，Photoshop Camera RAW 窗口将显示照片数据和文件大小，还有图像尺寸。

![Images](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_02.jpg)

看起来用于拍摄这张照片的数码相机以 17.9 百万像素的分辨率保存了这张图像，使得这张图像宽 5184 像素，高 3456 像素。这张图像在 Web 上永远不会以这个分辨率使用，因为它不适合在计算机显示器上，需要缩小才能查看。为了在 Web 上使用图像，需要将其缩小，使其在 Web 上更小更容易查看，但用于显示它的文件仍然是巨大的主版本，加载速度慢。让我们继续通过在 Camera RAW 导入窗口中选择“完成”来在 Photoshop 中打开这个文件。

将网页设计所需的分辨率导出为网页版本的图像是一个很好的做法。在 Photoshop 中，可以通过在“图像”选项卡下选择“图像大小”来轻松地将图像分辨率更改为适合 Web 的合适尺寸。

![Images](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_03.jpg)

在“图像大小”窗口中，我们可以输入一些更现实的值到“宽度”和“高度”参数中，以查看我们可以实现什么样的优化。通过使用 1920 x 1280 这样的值，这仍然是一个非常高分辨率的图像，可以查看预期输出图像源文件大小将显示在“宽度”和“高度”参数上方的文本中。

![Images](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_04.jpg)

在“图像大小”窗口中更新“宽度”和“高度”参数后，生成的文件大小将立即显示在它们的上方。请记住，显示的文件大小变化不会是最终输出大小，因为我们仍然可以使用 JPEG 压缩等技术来优化这个图像源。

### 提示

在为特定网页设计优化图像大小时，通常不需要导出比设计中设置的尺寸更大的图像。如果设计中需要缩略图，最好导出两张图像，一张大一张小，而不是在两种情况下使用同一张图像。

位于**文件**选项卡下的 Photoshop 的**保存为 Web**功能可以说是网页开发人员的好帮手。这个工具允许您轻松地从 Photoshop 中导出图像，特别是为了优化 Web 而设计。无论是为设计增添活力还是将资产转换为单个实例，每当您要从 Photoshop 导出东西供 Web 使用时，这个工具都是实现的最佳方式。

![图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_05.jpg)

单击**保存为 Web**选项将打开一个专用窗口，帮助您选择最佳格式和压缩方法来导出数据。因此，让我们导出这张照片的几个版本，看看在尽量保留图像质量的同时可能的最小文件大小是多少。

将格式类型设置为**JPG**以进行更好的压缩，然后在窗口顶部选择**4-Up**选项卡，以便在图像数据的不同压缩级别之间进行并排比较。尝试调整这些值，看看在看到图像发生显著变化之前，您可以将质量水平降低到多低。在这样做的同时，密切关注预期文件大小，以了解压缩水平如何影响文件大小。

![图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_06.jpg)

随着压缩级别的提高，这张狗照片的背景质量特别受到影响。这是因为长草创造了一个非常动态和繁忙的区域，可以看到像素化。狗身体内的固体颜色区域保持了更多原始质量，因为同一区域的像素颜色非常相似。**保存为 Web**窗口中的另一个有趣特性是每个图像版本的预期下载时间。您可以轻松更改预期带宽级别，以查看将此图像传递到互联网用户可能需要多少时间。

### 提示

由于每个图像都不同，没有单一的完美优化设置。花时间确保每个图像在最小文件大小下看起来最好，将为您带来一个外观更好、加载速度更快的网站。

举例来说，我使用 JPEG 格式以不同的分辨率和压缩级别导出了这张照片。

![图片](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_07.jpg)

正如您从文件列表中看到的，我们最初从数码单反相机直接拍摄了一张 27MB 的照片。在 Photoshop 中使用不同的导出方法，我们可以轻松获得相同图像的较小分辨率版本，文件大小远远低于 500 千字节。考虑到在完全开发的网页中，这张图片可能是众多图片之一，一般的经验法则是尽可能保持每个图像文件的大小。这将使您的内容快速加载，并为您创建的设计正确显示。

当然，正如之前提到的，JPG 并不是网页中唯一可用的图像格式。让我们快速介绍每种格式以及它们各自的特点。

### JPEG

将图像输出为`.jpeg`或更常见的`.jpg`允许进行有损图像压缩，旨在通过丢弃图像内的一些数据来减小文件大小。在 JPEG 格式中保存时使用的压缩量通常由用户定义，允许设计师和开发人员创建比原始文件更小的文件，使其尽可能接近其源。JPEG 格式的主要缺点之一是缺乏透明度支持，因为该格式不包含 alpha 通道。

### PNG

**便携式网络图形**（**PNG**）是一种位图图像格式，在保存图像数据时不使用压缩。PNG 图像非常适合设计和资产图像，因为它们保留了设计中使用的质量和调色板，并且支持透明度。然而，它们通常不用于照片等图像，因为由于图像中的细节数量，生成的文件大小将会太大。

### GIF

心爱的 GIF 文件，或者如今更常见的**动画 GIF**自 1987 年 CompuServe 发布该格式以来一直可供使用。GIF 图像支持 256 种颜色、透明度，以及通过多个图像帧进行动画。尽管直到今天它仍然在 Web 上使用，但由于对动画图像的时间轴控制的缺乏，诸如精灵表（我们将在接下来的章节中更多地介绍）的技术正在变得更受欢迎，用于动画图像的集成。

## 音频

为 Web 准备音频相对来说非常简单，因为大多数 Web 浏览器支持 HTML5 新音频元素中的**MP3**音频格式。除了 MP3，一些浏览器还支持使用**OGG**音频文件。因此，以任一格式导出音频将允许您针对所有现代 HTML5 兼容的浏览器，并确保您的最终用户无论选择何种浏览器查看您的内容，都能听到音频。

### 音频元素

创建`audio`元素，与大多数元素的 HTML 语法一样，都非常简单。与 HTML 元素中传统的源引用的一个主要区别是使用了`source`元素，该元素被包含在`audio`元素中。通过利用这个新的`source`元素，我们可以在同一个元素中引用多个资产，并且只加载与之兼容的第一个文件：

```html
<audio controls>
  <source src="img/horse.ogg" type="audio/ogg">
  <source src="img/horse.mp3" type="audio/mp3">
  Your browser does not support the audio tag.
</audio>
```

如果用户尝试在不支持 HTML5 音频的浏览器中打开此元素，则将显示`audio`元素内的其余内部内容。在这种情况下，我们只显示文本，但您也可以轻松地附加对 Flash 音频播放应用程序的引用或使用 CSS 进行样式化的警告。但是，如果浏览器按照给定的要求一切正常，页面将显示类似以下内容的音频播放 UI：

![音频元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_08.jpg)

音频播放控件用户界面是特定于显示数据的浏览器的。上述图像是 Google Chrome 当前呈现的内部音频播放控件用户界面。可以通过在`audio`标签元素中排除`controls`参数来移除默认音频控件。没有默认控件 UI，您可以使用图像、HTML 和 CSS 构建自己的控件，并使用 JavaScript 进行控制。

## 视频

如第一章 *为什么选择 HTML5？*中所述，将视频集成到 HTML5 文档中现在比以往任何时候都更容易。虽然将视频集成到 HTML5 文档中很简单，但一切都始于为 Web 准备视频。这个过程不仅应该最小化视频文件的大小，还应该使用特定的编解码器对其进行编码，并将其保存在特定的视频容器中。

HTML5 的`video`标签支持包含多种视频容器格式。在尝试支持完整范围的 HTML5 兼容浏览器时，开发人员必须包含对同一视频的多种格式的引用，因为并非每个浏览器都支持所有允许的视频文件类型。因此，对视频容器和编解码器的扎实理解对于网页开发人员来说是必要的，以便将视频正确集成到其文档中。

![视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_09.jpg)

### 视频编解码器

编解码器用于压缩和解压视频，以减小文件大小并允许使用更少的带宽共享大型视频文件。如果不对视频文件进行压缩，用户将不得不等待很长时间才能通过典型的互联网连接传输视频。以高清晰度为例，大约 5 分钟的原始视频可能超过 25GB 的数据。视频编解码器由先进的算法组成，可以删除从一帧到另一帧混合的相似数据。编码视频不是将每个单独的帧存储为单独的图像，而是存储一个通常比原始源材料小得多的专门数据集。为了观看，编码数据需要从精简的数据源解码回可视的基于帧的视频。编解码器是完成这项任务的一体化技术。HTML5 中支持的每个视频容器只支持一个视频编解码器，因此选择一个相当简单。然而，由于视频通常伴随着音频，音频也必须通过特定的音频编解码器运行。

### 视频容器

在尝试将视频嵌入 HTML5 文档时的一个主要问题是支持所有现代浏览器以相同的内容。不幸的是，并非所有兼容 HTML5 的浏览器都支持相同的视频格式。因此，为了支持最广泛的浏览器范围，开发人员必须嵌入多个版本的相同视频文件，以多种格式进行编码。由于这个问题在不久的将来不太可能改变，了解可用的视频容器及其相应的编解码器是准备 HTML5 文档中的视频的重要步骤。

#### MP4

从 Flash 开发者的角度来看，**MP4** 容器应该是最熟悉的，因为它们与 **FLV** 或 **F4V** 文件非常相似。目前，**MPEG-4** 或 MP4 容器受到 Internet Explorer 9+、Google Chrome 和 Safari 的支持，可以嵌入视频元素。MP4 视频必须使用 **H.264** 编解码器进行编码，这也是 Flash 中 FLV 和 F4V 视频所使用的。

#### WebM

WebM 音频和视频格式是由 Google 赞助的项目，旨在为 Web 带来完全开放的多媒体容器和编解码器。WebM 文件受到 Firefox、Google Chrome 和 Opera 的支持。在为 WebM 容器内的视频进行编码时，使用了同样由 Google 拥有的 VP8 视频编解码器。

GG

**OGG** 容器受到 Firefox、Google Chrome 和 Opera 的支持。在为 OGG 容器内的视频进行编码时，使用 **Theora** 编解码器。由于只需使用 MP4 和 WebM 视频即可覆盖所有浏览器，因此在 OGG 格式中进行编码并不是完全必要的。无论如何，将其添加为备用并不会有害；浏览器在源列表中找到的第一个视频文件格式在显示时被利用，所有其他文件都会被忽略并且不会被下载。

### 提示

可以在`Chapter 02_examples`目录中找到示例编码视频文件以及高质量的主视频文件。

### 视频编码软件

有许多在线可用的优秀应用程序可以将您的视频内容编码为与 HTML5 兼容的格式。只要满足容器和编解码器的规范，任何应用程序或方法都可以用于完成任务。为了帮助您快速上手，在本章和本书的其余部分，以下是一些最受欢迎的编码工具和应用程序，供 Web 开发人员使用以快速将视频发布到网络上。

#### Miro 视频转换器

如果您正在寻找一个简单的方法来准备 Web 视频，那么不妨试试 Miro Video Converter，它可以在 Miro 的网站[`www.mirovideoconverter.com`](http://www.mirovideoconverter.com)上找到。这个软件不仅免费和开源，而且还支持以所有 HTML5 兼容格式导出视频和音频。Miro Video Converter 适用于 Windows 和 OS X，可能是为 HTML5 项目准备音频和视频的最简单的方法。

![Miro Video Converter](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_10.jpg)

安装并打开应用程序后，下一步就是简单地将源视频文件拖放到应用程序中进行排队。如果您有多个视频，也可以将它们添加到队列中，所有视频将依次进行编码。

![Miro Video Converter](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_11.jpg)

一旦您需要编码的所有视频都添加到队列中，选择窗口底部的**格式**选项，并在转换器中选择三种可用格式之一。请记住，为了在每个浏览器中启用视频元素播放支持，您需要在每种格式中编码您的视频一次。如果您需要更深入地配置编码作业，Miro Video Converter 允许我们控制基本参数，如宽高比和视频尺寸。

#### Adobe Media Encoder

在其项目中包含视频的 Flash 开发人员可能已经使用了 Adobe Media Encoder。这个方便的软件与 Flash 捆绑在一起，可以轻松地对 Flash 和 HTML5 项目中使用的视频进行编码。不幸的是，该应用程序只能原生输出 Flash 视频格式的 HTML5-ready MP4 视频。

![Adobe Media Encoder](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_12.jpg)

#### Handbrake

如果您无法访问 Adobe Media Encoder，那么免费编码 MP4 视频的下一个最简单的方法就是前往[`handbrake.fr`](http://handbrake.fr)并下载 Handbrake。Handbrake 不仅是开源的，而且还适用于 Windows、OS X 和 Linux，因此很难被忽视。

![Handbrake](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_13.jpg)

#### FFMPEG

最后，我个人最喜欢的是 FFMPEG。如果您像我一样喜欢命令行，那么这个令人惊叹的软件一定适合您。在媒体方面，很难说 FFMPEG 不能用来完成什么。如果您需要高级视频转码，请务必访问[`ffmpeg.org`](http://ffmpeg.org)了解更多信息。

### 视频元素

一旦我们的视频内容已经以必要的格式进行了编码，剩下的就是在 HTML 文档的正文中引用视频。与`audio`元素一样，`video`元素支持在`video`元素内部使用`source`标签来引用多个资产，而不是在标签中使用典型的`src`参数来创建对文件的引用。值得注意的是，如果您只嵌入了单个视频引用，则可以在`video`标签中使用`src`参数，而不是添加`source`标签：

```html
<video width="800" height="600" controls>
  <source src="img/my_video.mp4" type="video/mp4">
  <source src="img/my_video.webm" type="video/webm">
  <source src="img/my_video.ogg" type="video/ogg">
  Your browser does not support the video tag.
</video>
```

与`audio`元素一样，`video`元素允许通过在`video`标签中添加`controls`参数来进行播放控制集成。视频可以通过在`video`标签中添加`autoplay="true"`来在页面加载时自动播放。

现在我们已经准备好所有资产并准备好行动，是时候开始进入开发环境了。由于 Web 浏览器是我们的目标平台，让我们花点时间来了解今天的现代 Web 浏览器在 Web 开发工具方面为我们提供了什么，以帮助我们在开发周期中进行开发。

# 调试和输出方法

随着 HTML5 和其他大量客户端驱动的网页内容的流行，需要一个强大的开发者工具集来方便地调试和测试网页。幸运的是，每个现代浏览器都已经适应或集成了一些非常相似的设置来做到这一点。在这个工具集中最重要的功能之一就是 JavaScript 控制台。JavaScript 控制台对于网页开发者来说就像 Flash 开发者的 Flash 输出窗口一样重要。这是一个非常重要的区域，用于打印初始化应用程序或网站中的数据以及代码中指定的打印语句或值。在 ActionScript 中，通过使用`trace()`函数来将数据打印到输出窗口。在 JavaScript 中，我们利用`console`对象的内置方法来做同样的事情。考虑以下示例：

```html
function calculateSum(a, b) {
  sum = a + b;
  console.log("The sum of " + a + " + " + b + " = " + sum);
}

calculateSum(2, 3);
```

### 提示

这个例子可以在`Chapter 02_examples`目录中的`Console-Example`目录中找到。

这个代码示例创建了一个 JavaScript 函数来计算数字的总和，并使用示例参数调用该方法，以在浏览器控制台中显示输出。与 ActionScript 中的跟踪类似，JavaScript 中的控制台集成在幕后，与实际网页分开。控制台的主要功能是在运行时帮助开发者调试 JavaScript、CSS 或 HTML 属性。开发者控制台不仅可以用于从应用程序中打印数据，还可以用于触发代码中特定函数的执行，而无需特定事件或交互的发生。

控制台同样重要，整个用户界面和交互取决于使用何种浏览器来查看文档。因此，了解在所有流行浏览器中找到和如何使用控制台是帮助您构建健壮代码的重要一步。让我们快速在一些常见的浏览器中运行我们简单的计算总和示例，看看它们如何处理输出。

## 谷歌浏览器

所有版本的谷歌浏览器都内置了开发者工具集，可以通过右键单击网页并在对话框中选择**检查元素**选项来轻松打开。这将显示附加到浏览器窗口底部的开发者工具窗口。选择**控制台**选项卡将显示 JavaScript 控制台，以查看网页的输出。在 Chrome 中打开我们的 JavaScript `calculateSum`函数示例，并打开控制台，应该显示类似下面的图像：

![谷歌浏览器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_14.jpg)

正如你所看到的，`console.log()`调用的输出已经显示出来，还有调用是从哪个文件和行号发出的。即使从简单的角度来看，我相信你已经开始看到这个工具有多么方便，如果你有 100 甚至 1000 行代码在多个文件中处理。与 ActionScript 中的跟踪输出窗口类似，这个工具的另一个亮点是它能够直接从控制台窗口调用进一步的 JavaScript 执行。在控制台中，我们可以继续调用`calculateSum`函数，并直接从控制台传入必要的值来找到新数字的总和。

![谷歌浏览器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_15.jpg)

一些浏览器，比如 Chrome，甚至具有自动完成功能，当你输入方法或属性名称时会展开文本，这是我相信大多数 Flash 开发者希望在 Flash IDE 中拥有的功能。

## 火狐浏览器的 Firebug

由于 Firefox 没有预装强大的开发者工具集，网页开发者的常见选择是安装**Firebug**扩展来启用此功能。可以通过访问[`getfirebug.com`](http://getfirebug.com)在几秒钟内将扩展轻松添加到 Firefox 安装中。安装并激活后，右键单击页面的任何位置，然后选择**使用 Firebug 检查元素**。

![火狐浏览器的 Firebug](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_16.jpg)

这应该感觉非常熟悉，就像我们在 Chrome 中所做的一样。Firebug 是一个几乎所有我认识的开发人员都使用的很棒的项目。所有这些工具集中都有很多很棒的功能，我们将在本书中介绍其中许多功能。由于我们打开了一个非常简单的 HTML 页面，几乎没有什么内容，现在可能是一个很好的时机来查看更原始的网页的 UI 和输出，所以随时随地点击并查看一下。

![Firefox 的 Firebug](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_17.jpg)

## Safari

启用 Safari 中的开发者工具，请打开**首选项**窗口，然后选择**高级**选项卡。选择窗口底部标有**在菜单栏中显示开发菜单**的复选框，然后可以关闭窗口。

![Safari](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_18.jpg)

从这一点开始，您可以像往常一样在任何网页上右键单击，然后选择**检查元素**以显示工具窗口。

![Safari](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_19.jpg)

如果您留意的话，您可能会注意到这个控制台几乎与 Google Chrome 中的控制台相同。当然，它具有命令行集成，就像我们在其他浏览器中看到的那样。

![Safari](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_20.jpg)

## Opera

与 Google Chrome 类似，Opera 中的开发者工具可以通过右键单击网页并选择**检查元素**来轻松访问。一旦开发者工具窗口在浏览器底部打开，选择**控制台**选项卡以打开开发者控制台。最初，控制台将是空白的，没有任何来自当前正在查看的网页的交互。

![Opera](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_21.jpg)

与始终处于活动状态的控制台不同，Opera 决定仅在控制台实际打开时才读取控制台命令。因此，刷新页面将显示控制台交互：

![Opera](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_22.jpg)

## Internet Explorer

从 Internet Explorer 9 开始，微软已经开始在浏览器中直接包含开发人员工具集。可以通过在查看页面时按下*F12*随时打开**开发人员工具**窗口。与 Opera 一样，Internet Explorer 需要刷新页面才能在活动页面上启用控制台的使用，因为当关闭时它保持不活动状态。

![Internet Explorer](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_23.jpg)

当然，就像其他控制台一样，我们可以从命令行调用我们的 JavaScript 方法和变量。

![Internet Explorer](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_02_24.jpg)

# 语法差异

既然我们有一些媒体可以使用，并且浏览器工具也可以使用，让我们开始玩弄 JavaScript 并将其语法与您已经了解的 ActionScript 3 进行比较。

## 变量

与在 ActionScript 3 中声明的变量不同，JavaScript 变量没有严格类型。这将从熟悉的 ActionScript 3 变量声明转换为： 

```html
var myVariable:String = 'abc123';
```

转换为 JavaScript 中的更简单的语法，如下所示：

```html
var myVariable = 'abc123';

```

这种缺乏严格类型称为动态类型。JavaScript 中的变量可以随时用作任何类型。考虑以下示例：

```html
var exampleVar;                      // A undefined variable
exampleVar = "Some example text";    // Variable is now a String
exampleVar = 12345;                  // Variable is now a Number
```

动态类型允许代码更快地编写，因为它需要开发人员的输入更少，但这种开发便利性是以调试大型应用程序为代价的。ActionScript 3 的严格类型允许编译器在导出新版本应用程序之前就捕获问题。JavaScript 不会在本地执行此操作，这可能是先前具有 ActionScript 3 经验的大多数开发人员使用该语言时最大的抱怨之一。

### 变量类型转换

尽管 JavaScript 中的变量没有严格类型，但有方法可以确保变量数据以正确的形式进行所需的操作。可以对变量进行类型转换以确保其格式正确：

```html
myString = String('12345');   // Convert to a String
myBoolean = Boolean('true');  // Convert to Boolean
myNumber = Number('12345');   // Convert to Number
```

## 条件和循环

我们将一起涵盖这两个方面，因为 JavaScript 中的条件和循环语法几乎与 ActionScript 3 中您习惯的一样。`If`，`if... else`和`if... else if`条件与 ActionScript 中的条件没有什么不同：

```html
if(cats > dogs) {
  // Code for cat people...
} else if (cats < dogs) {
  // Code for dog people...
} else {
  // Code for everyone else...
}
```

另外，`switch`语句也可以使用，就像`if`语句一样；语法与 ActionScript 中的完全相同：

```html
switch(animal) {
  case 'cat':
    // Code for cat people...
    break;
  case 'dog':
    // Code for dog people...
    break;
  default:
    // Code for everyone else...
}
```

循环与 ActionScript 中的循环没有什么不同。考虑这些`for`和`while`循环：

```html
for(var n = 0; n < myArray.length; n++) {
  // Code within loop...
}

while(n < 100) {
  // Code within loop...
}

do {
  // Code within loop...
} while(n < 100);
```

## 函数

与 ActionScript 3 一样，JavaScript 中的函数是用大括号（`{}`）括起来的代码块。每个函数都与一个关键字相关联，用于调用函数并运行其中的代码。通常情况下，函数可以将值返回到最初调用的地方。这是通过使用`return`语句来实现的。

JavaScript 函数的语法与 ActionScript 函数非常相似，但不需要严格类型化预期参数和函数返回类型。作为 Flash 开发人员，您的 ActionScript 3 函数可能看起来像下面这样：

```html
function getCoffee (owner:String, milks:int, sugars:int):void {
  // Code...
}
```

这种语法可以很容易地转换为 JavaScript，只需删除变量和返回类型声明，以便 JavaScript 中的相同函数可以写成如下形式：

```html
function getCoffee (owner, milks, sugars) {
  // Code...
}
```

## 对象

从技术上讲，JavaScript 中声明的所有内容都是对象，但是，总有一天你会需要创建自己的自定义对象。可以通过以下两种方式之一来实现。第一种方式，应该非常熟悉 ActionScript 开发人员，如下所示：

```html
player = new Object();
player.name = "John Smith";
player.lives = 5;
player.posX = 10;
player.posY = -30;
```

您还可以通过将它们定义为函数来创建对象，如下所示：

```html
function player(name, lives, posX, posY) {
  player.name = name;
  player.lives = lives;
  player.posX = posX;
  player.posY = posY;
}

var teddyBear = new player("Teddy", 5, 10, 10);
console.log(teddyBear.name);
```

## DOM 事件

集成 DOM 事件允许您使用 JavaScript 处理在 HTML 文档中发生的事件。

### 鼠标事件

DOM 公开了鼠标事件，用于鼠标指针的基本用户交互。通过在 HTML 标记中使用`onclick`事件参数，我们可以在用户单击特定元素时执行 JavaScript：

```html
<img src="img/my-image.jpg" id="my-image" onclick="PLACE YOUR JAVASCRIPT HERE">
```

然而，我们也可以完全从 JavaScript 中定位元素，并在 HTML 源代码之外处理事件处理程序，以保持项目清晰易懂：

```html
document.getElementById("my-image").onclick=function() {
  // Place your JavaScript here...
};
```

当然，您不仅仅局限于鼠标点击事件。事件也可以处理鼠标悬停、鼠标移出、鼠标按下和鼠标释放。在本书的示例中，我们将利用所有这些事件以及扩展它们的方法。

# JavaScript 示例

在涵盖了所有 JavaScript 语法规范之后，让我们将其中一些用于一个工作示例，并看看会发生什么。看一下以下简单的 HTML 文档，其中包含 JavaScript 来对随机数组进行排序：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Insertion Sort - JavaScript Syntax Example</title>

    <script type="text/javascript">
      // Number of elements to sort.
      elementCount = 10000;	
      // The array which will be sorted.
      sortlist = new Array();

      /**
      * Called on button click.
      */
      function init() {
        // Prepare random array for sorting.
        for(i = 0; i < elementCount; i++)
          sortlist.push(i);

        //shuffle(sortlist);
        sortlist.sort(function() {
          return 0.5 - Math.random();
        });

        // Display the random array prior to sorting.
        console.log(sortlist);

        // Start a timer.
        console.time('Iteration Sort Timer');

        // Sort the randomized array.
        insertionSort(sortlist);

        // Stop the timer.
        console.log('Sorted ' + elementCount + ' items.');
        console.timeEnd('Iteration Sort Timer');

        // Display the sorted array.
        console.log(sortlist);
      }

      /**
      * The popular Insertion Sort algorithm.
      */
      function insertionSort(list) {
        // It's always smart to only lookup array size once.
        l = list.length;

        // Loop over supplied list and sort.
        for(i = 0; i < l; i++) {
          save = list[i];
          j = i;

          while(j > 0 && list[j - 1] > save) {
            list[j] = list[j - 1];
            j -= 1;
          }

          list[j] = save;
        }
      }
    </script>
  </head>

  <body>
    <p>
      Click the button below to begin.
      Be sure to open up your browsers developer console.
    </p>
      <button onclick="init()">Start Sorting</button>
  </body>
</html>
```

这个示例涵盖了我们刚刚涵盖的 JavaScript 的许多特性和语法规范。在 HTML 文档的`head`标记中声明的 JavaScript 块中，我们创建了两个函数。第一个函数是我们的初始化方法，用于准备和运行应用程序。第二个函数包含了流行的插入排序算法，它将对我们的随机数组进行排序。为了使两个函数能够使用相同的变量，我们在每个函数的作用域之外创建了`elementCount`和`sortlist`作为全局变量。在 HTML 的`body`标记中是一个`button`元素，它在页面上呈现一个典型的表单按钮元素，当用户单击此按钮时，`onclick`处理程序调用`init`函数。

这个示例并不华丽，但正如我上面提到的，它涵盖了 JavaScript 语法规范的许多不同方面。

# 定时 JavaScript 执行

处理 JavaScript 执行时间的一个重要注意点是确保整个页面在允许 JavaScript 开始执行其代码之前已经完成加载。等待页面加载的原因是为了在尝试操作它们之前允许页面上的所有资产和外部引用加载。如果您的 JavaScript 尝试对不存在的元素执行操作，您的应用程序流程可能会失败。为了避免这个问题，我们可以向 DOM 添加一个事件侦听器，使其仅在页面完全加载并显示后运行。利用 DOM 事件为 JavaScript 提供了一个简单的方法来做到这一点，如下面的代码所示：

```html
window.addEventListener("load", init, false);

var init = function() {
  // Start everything from in here.
}
```

现在，当窗口完成加载过程后，将调用`init`函数，应用程序代码的其余部分可以开始执行。实际上，JavaScript 有许多方法可以在页面加载完成后执行代码。本书的后续章节将使用示例来使用和解释其中许多方法。

# 总结

在本章中，我们花了一些时间来更好地熟悉为我们的 HTML5 项目准备媒体资产所涉及的过程。此外，本章还涵盖了每种典型多媒体格式的准备和集成技术，以及一些流行的软件，可帮助完成这些工作。我们迅速地比较了 ActionScript 3 和 JavaScript 语法，以便更熟悉在编写 JavaScript 时与 ActionScript 3 相比的细微但重要的差异。这使我们完美地准备好进入第三章，“可扩展性、限制和效果”，在那里我们将开始将 HTML5 推到极限，以查看它的限制和缺点，以及它可以做的所有令人惊讶的事情。


# 第三章：可扩展性、限制和效果

准备好用于 HTML5 集成的媒体资产后，让我们继续这个旅程，通过查看 CSS3 和 JavaScript 中一些新的和令人兴奋的对象操作功能，以及它们与 Flash 开发人员熟悉的内容的关系。在本章的过程中，我们将回顾 HTML5 的许多特定功能，这些功能使其获得了广泛的使用和受欢迎程度，变得更像典型的 Flash 开发。

本章将涵盖以下内容：

+   初始开发限制及避免它们的方法

+   一些新的和令人兴奋的 CSS3 新增功能

+   为移动和桌面开发响应式布局

+   使用 CSS 媒体查询为特定显示目标 CSS 样式

+   控制和流式传输音频和视频，以及与 Flash 相比的限制

+   客户端文件集成和操作

+   使用 HTML5 Web Workers 将繁重的进程发送到后台

+   介绍使用 WebSockets 进行服务器端通信

+   了解 Canvas 元素是什么以及它的重要性

+   WebGL 简介及其与 Stage3D 的关系

# HTML5 的限制

如果您现在还没有注意到，您将使用的许多 HTML5 功能都具有故障保护、多个版本或特殊语法，以使您的代码覆盖整个浏览器范围和其中支持的 HTML5 功能集。随着时间的推移和标准的巩固，人们可以假设许多这些故障保护和其他内容显示措施将成熟为所有浏览器共享的单一标准。然而，实际上，这个过程可能需要一段时间，即使在最好的情况下，开发人员仍然可能不得不无限期地利用许多这些故障保护功能。因此，对何时、何地以及为什么使用这些故障保护措施有坚实的理解，将使您能够以一种方式开发您的 HTML5 网页，以便在所有现代浏览器上都能按照预期查看。

为了帮助开发人员克服先前提到的这些问题，许多框架和外部脚本已经被创建并开源，使得在开始每个新项目时，可以拥有更普遍的开发环境，从而节省了开发人员无数的时间。Modernizr（[`modernizr.com`](http://modernizr.com)）已经迅速成为许多 HTML5 开发人员必不可少的补充，因为它包含了许多条件和验证，使得开发人员可以编写更少的代码并覆盖更多的浏览器。Modernizr 通过检查客户端浏览器中 HTML5 中可用的大多数新功能（超过 40 个）并在几毫秒内报告它们是否可用来实现所有这些。这将使您作为开发人员能够确定是否应该显示内容的备用版本或向用户发出警告。

让您的网络内容在所有浏览器中正确显示一直是任何网络开发人员面临的最大挑战，当涉及创建尖端有趣的内容时，挑战通常变得更加艰巨。本章不仅将涵盖许多新的 HTML5 内容操作功能，还将在代码示例中进行演示。为了让您更好地了解这些功能在没有使用第三方集成的情况下是什么样子，我们将暂时避免使用外部库。值得注意的是，这些功能和其他功能在所有浏览器中的外观。因此，请确保在不仅是您喜欢的浏览器中，而且在许多其他流行的选择中测试示例以及您自己的工作。

# 使用 CSS3 进行对象操作

在 CSS3 出现之前，Web 开发人员使用了一长串的内容操作、资源准备和资源呈现技术，以便在每个浏览器中获得他们想要的网页布局。其中大部分技术都被认为是“黑客”技术，因为它们基本上都是一种解决方案，使浏览器能够执行通常不会执行的操作。诸如圆角、投影阴影和变换等功能都不在 Web 开发人员的工具库中，而且要达到想要的效果的过程可能会让人感到无聊。可以理解的是，CSS3 对所有 Web 开发人员的兴奋程度都非常高，因为它使开发人员能够执行比以往更多的内容操作技术，而无需事先准备或特殊的浏览器黑客技术。尽管 CSS3 中可用属性的列表很庞大，但让我们来介绍一些最新和最令人兴奋的属性。

## box-shadow

一些设计师和开发人员说投影阴影已经过时，但在 HTML 元素中使用阴影仍然是许多人的流行设计选择。在过去，Web 开发人员需要进行一些技巧，比如拉伸小的渐变图像或直接在背景图像中创建阴影，以在其 HTML 文档中实现这种效果。CSS3 通过创建`box-shadow`属性来解决了这个问题，允许在 HTML 元素上实现类似投影阴影的效果。

为了提醒我们 ActionScript 3 中是如何实现这种效果的，让我们回顾一下这段代码：

```html
var dropShadow:DropShadowFilter = new DropShadowFilter();
dropShadow.distance = 0;
dropShadow.angle = 45;
dropShadow.color = 0x333333;
dropShadow.alpha = 1;
dropShadow.blurX = 10;
dropShadow.blurY = 10;
dropShadow.strength = 1;
dropShadow.quality = 15;
dropShadow.inner = false;
var mySprite:Sprite = new Sprite();
mySprite.filters = new Array(dropShadow);
```

如前所述，CSS3 中的新`box-shadow`属性允许您相对轻松地附加这些阴影效果，并且具有许多相同的配置属性：

```html
.box-shadow-example {
  box-shadow: 3px 3px 5px 6px #000000;
}
```

尽管在此样式中应用的每个值都没有属性名称，但您可以看到许多值类型与我们在 ActionScript 3 中创建的投影阴影所附加的值相符。

这个`box-shadow`属性被赋予了`.box-shadow-example`类，因此将被应用到任何具有该类名的元素上。通过创建一个带有`box-shadow-example`类的`div`元素，我们可以改变我们的内容，使其看起来像下面这样：

```html
<div class="box-shadow-example">CSS3 box-shadow Property</div>
```

![box-shadow](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_01.jpg)

尽管这个 CSS 属性很容易添加到您的项目中，但它在一行中声明了很多值。让我们按顺序回顾每个值，以便我们更好地理解它们以备将来使用。为了简化属性中每个变量的识别，这些变量已经被更新为不同的值：

```html
box-shadow: 1px 2px 3px 4px #000000;
```

这些变量的解释如下：

+   初始值（`1px`）是阴影的**水平偏移**，或者阴影是向左还是向右。正值将把阴影放在元素的右侧，负偏移将把阴影放在左侧。

+   第二个值（`2px`）是**垂直偏移**，与水平偏移值一样，负数将生成向上的阴影，正数将生成向下的阴影。

+   第三个值（`3px`）是**模糊半径**，控制阴影的模糊程度。声明一个值，例如`0`，将不会产生模糊，显示出一个非常锐利的阴影。放入模糊半径的负值将被忽略，与使用 0 没有任何不同。

+   第四个值（`4px`）也是数字属性的最后一个，是**扩展半径**。扩展半径控制了投影阴影模糊超出初始阴影大小声明的距离。如果使用值`0`，阴影将显示默认的模糊半径并且不会应用任何更改。正数值将产生更模糊的阴影，负值将使阴影模糊变小。

+   最后一个值是十六进制颜色值，表示阴影的颜色。

或者，您可以使用`box-shadow`将阴影效果应用于元素的内部而不是外部。使用 ActionScript 3，可以通过在`DropShadowFiler`对象的参数列表中附加`dropShadow.inner = true;`来实现这一点。在 CSS3 中应用`box-shadow`属性的语法方式非常相似，只需要添加`inset`关键字。例如，考虑以下代码片段：

```html
.box-shadow-example {
  box-shadow: 3px 3px 5px 6px #666666 inset;
}
```

这将产生一个看起来像下面截图的阴影：

![box-shadow](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_02.jpg)

### 提示

本章的代码示例中包含了一个 box-shadow 工具，它将帮助您更好地理解每个属性的影响。

## text-shadow

就像`box-shadow`属性一样，`text-shadow`通过为文本创建相同的投影效果，实现了其名字的含义。

```html
text-shadow: 2px 2px 6px #ff0000;
```

与`box-shadow`一样，`text-shadow`的初始两个值是阴影放置的水平和垂直偏移量。第三个值是可选的模糊大小，第四个值是十六进制颜色：

![text-shadow](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_03.jpg)

## border-radius

就像元素或文本阴影一样，在 CSS3 之前为元素添加圆角是一件苦差事。开发人员通常会附加单独的图像或使用其他对象操作技术来实现这种效果，通常是在典型的正方形或矩形形状元素上。通过在 CSS3 中添加`border-radius`设置，开发人员可以轻松动态地设置元素的角落圆度，只需几行 CSS 代码，而无需像 Flash 中那样使用矢量 9 切片。

由于 HTML 元素有四个角，当附加`border-radius`样式时，我们可以单独针对每个角落，或者一次性针对所有角落。为了轻松地一次性附加边框半径设置到所有角落，我们将创建我们的 CSS 属性如下：

```html
#example {
  background-color:#ff0000; // Red background
  width: 200px;
  height: 200px;
border-radius: 10px;
}
```

前面的 CSS 不仅将 10px 的边框半径附加到`#example`元素的所有角落，还使用了现代浏览器使用的所有属性，我们可以确保这种效果对所有试图查看此内容的用户都是可见的：

![border-radius](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_04.jpg)

如上所述，可以针对元素的每个单独角落，只附加半径到元素的特定部分：

```html
#example {
  border-top-left-radius: 0px; // This is doing nothing
  border-top-right-radius: 5px;
  border-bottom-right-radius: 20px;
  border-bottom-left-radius: 100px;
}
```

前面的 CSS 现在通过将左边框半径设置为`0px`来移除我们的`#example`元素，并为其他每个角落设置了特定的半径。值得注意的是，在这里将边框半径设置为`0`与完全不在 CSS 样式中留下该属性没有任何区别：

![border-radius](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_05.jpg)

## 字体

多年来，在 Flash 中处理自定义字体一直有着起伏。任何需要在其 Flash 应用程序中合并和使用自定义字体的 Flash 开发人员可能都知道选择字体嵌入方法以及确保它对没有在其计算机上安装字体的用户正常工作的痛苦。

CSS3 字体嵌入已经实现了一种“无忧无虑”的方式，可以通过`@font-face`声明将自定义字体包含到 HTML5 文档中：

```html
@font-face {
  font-family: ClickerScript;
  src: url('ClickerScript-Regular.ttf'),
    url('ClickerScript-Regular .otf'),
    url('ClickerScript-Regular .eot');
}
```

CSS 现在可以直接引用您的 TTF、OTF 或 EOT 字体，这些字体可以放在您的 Web 服务器上以实现可访问性。在我们的 CSS 文档中声明了字体源，并为其应用了唯一的`font-family`标识后，我们可以通过使用`font-family`属性在特定元素上开始使用它：

```html
#example {
  font-family: ClickerScript;
}
```

由于我们在`@font-face`属性中声明了特定的字体系列名称，因此以后几乎可以在任何元素上使用该自定义名称。自定义字体可以应用于 HTML 文档中几乎包含文本的任何内容。表单元素，如按钮标签和文本输入，也可以被设计为使用您的自定义字体。您甚至可以使用纯 HTML 和 CSS 重新制作网站标志等资产，并使用原始资产创建时使用的相同自定义字体。

### 可接受的字体格式

与在线资产的许多其他嵌入方法一样，字体需要转换为多种格式，以使所有常见的现代浏览器能够正确显示它们。几乎所有可用的浏览器都能够处理常见的 True Type 字体（.ttf 文件类型）或 Open Type 字体（.otf 文件类型），因此嵌入其中一种格式就足够了。不幸的是，Internet Explorer 9 没有内置对这两种流行格式的支持，需要将字体保存为 EOT 文件格式。

### 外部字体库

在过去几年中，出现了许多优秀的在线服务，使 Web 开发人员可以轻松地准备和嵌入字体到他们的网站中。Google 的 Web 字体存档可在[`www.google.com/webfonts`](http://www.google.com/webfonts)找到，其中托管了一大批开源字体，可以添加到您的项目中，而无需担心许可或付款问题。只需在 HTML 文档中添加几行额外的代码，您就可以开始使用了。

值得一提的另一个很棒的网站是 Font Squirrel，可以在[`www.fontsquirrel.com`](http://www.fontsquirrel.com)找到。与 Google Web Fonts 一样，Font Squirrel 托管了一个大型的网页可用字体存档，并提供了复制粘贴就绪的代码片段，以将它们添加到您的文档中。该网站上的另一个很棒的功能是`@font-face`生成器，它可以让您将现有字体转换为所有网页兼容格式。

在沉迷于将所有喜爱的字体转换为网页可用格式并将它们整合到您的工作中之前，值得注意的是最初随字体附带的最终用户许可协议或 EULA。将许多可用字体转换为网页使用将违反许可协议，并可能在未来给您带来法律问题。

## 不透明度

对于 Flash 开发人员来说，更常见的是“alpha”，设置元素的不透明度不仅可以改变设计的外观和感觉，还可以添加诸如淡入淡出的内容等功能。尽管这个概念看起来很简单，但它相对于 Web 开发人员可用的 CSS 属性列表是相对较新的。设置元素的不透明度非常容易，看起来像下面这样：

```html
#example {
  opacity: 0.5;
}
```

正如您从上面的示例中看到的那样，与 ActionScript 3 一样，不透明度值是介于 0 和 1 之间的数值。上面的示例将以 50%的透明度显示一个元素。CSS3 中的不透明度属性现在在所有主要浏览器中都得到支持，因此在声明时无需担心使用替代属性语法。

## RGB 和 RGBA 着色

在处理 CSS 中的颜色值时，许多开发人员通常会使用十六进制值，类似于`#000000`来声明使用黑色。颜色也可以在 CSS 中以 RGB 表示法实现，通过使用`rgb()`或`rgba()`调用来代替十六进制值。通过方法名称，您可以看到 CSS 中的`rgba`颜色查找还需要第四个参数，它声明颜色的 alpha 透明度或不透明度量。在 CSS3 中使用 RGBA 而不是十六进制颜色有几个好处。假设您刚刚创建了一个`div`元素，它将显示在网页布局中现有内容的顶部。

如果您曾经想要将`div`的背景颜色设置为特定颜色，但希望只有该背景是半透明的，而不是内部内容，那么 RGBA 颜色声明现在可以轻松实现这一点，因为您可以设置颜色的透明度：

```html
#example {
  // Background opacity
  background: rgba(0, 0, 0, 0.5); // Black 50% opacity

  // Box-shadow
  box-shadow: 1px 2px 3px 4px rgba(255, 255, 255, 0.8); // White 80% opacity
```

```html
  // Text opacity
  color: rgba(255, 255, 255, 1); 	// White no transparency
  color: rgb(255, 255, 255);	// This would accomplish the same styling

  // Text Drop Shadows (with opacity)
  text-shadow: 5px 5px 3px rgba(135, 100, 240, 0.5);
}
```

正如在前面的示例中所看到的，您可以在 CSS 语法中的任何需要颜色值的地方自由使用 RGB 和 RGBA 值，而不是十六进制。

## 元素变换

就我个人而言，我发现 CSS3 变换是 CSS 中最令人兴奋和有趣的新功能之一。在 Flash IDE 中以及使用 ActionScript 转换资产一直是非常容易访问和易于实现的。在 CSS 中转换 HTML 元素是 CSS 的一个相对较新的功能，并且仍在逐渐得到所有现代浏览器的全面支持。

变换元素允许您通过打开大量动画和视觉效果的可能性来操纵其形状和大小，而无需事先准备源。当我们提到“变换元素”时，实际上是在描述可以应用于变换的一系列属性，以赋予它不同的特性。如果您以前在 Flash 或可能在 Photoshop 中转换过对象，这些属性可能对您来说很熟悉。

### 翻译

作为一名主要处理 X 和 Y 坐标来定位元素的 Flash 开发人员，CSS3 Translate Transform 属性是放置元素的一种非常方便的方法，它的工作原理与 Flash 相同。`translate`属性接受两个参数，即 X 和 Y 值，用于平移或有效地移动元素：

```html
transform:translate(-25px, -25px);
```

不幸的是，为了使您的变换在所有浏览器中都能正常工作，您需要在附加变换样式时针对每个浏览器进行定位。因此，标准的变换样式和属性现在看起来会像这样：

```html
transform:translate(-25px, -25px);
-ms-transform:translate(-25px, -25px);     /* IE 9 */
-moz-transform:translate(-25px, -25px);    /* Firefox */
-webkit-transform:translate(-25px, -25px); /* Safari and Chrome */
-o-transform:translate(-25px, -25px);      /* Opera */
```

### 旋转

旋转是相当不言自明的，而且非常容易实现。`rotate`属性接受一个参数，用于指定要应用于特定元素的旋转量（以度为单位）：

```html
transform:rotate(45deg);
-ms-transform:rotate(45deg);       /* IE 9 */
-moz-transform:rotate(45deg);      /* Firefox */
-webkit-transform:rotate(45deg);   /* Safari and Chrome */
-o-transform:rotate(45deg);        /* Opera */
```

值得注意的是，尽管提供的值始终意味着度数值，但值必须始终附加**deg**以便正确识别该值。

### 比例

就像`rotate`变换一样，缩放也非常简单。`scale`属性需要两个参数，分别声明 X 和 Y 的缩放量：

```html
transform:scale(0.5, 2);
-ms-transform:scale(0.5, 2);      /* IE 9 */
-moz-transform:scale(0.5, 2);     /* Firefox */
-webkit-transform:scale(0.5, 2);  /* Safari and Chrome */
-o-transform:scale(0.5, 2);       /* Opera */
```

### 倾斜

倾斜元素将导致 X 和 Y 轴的倾斜：

```html
transform:skew(10deg, 20deg);
-ms-transform:skew(10deg, 20deg);      /* IE 9 */
-moz-transform:skew(10deg, 20deg);     /* Firefox */
-webkit-transform:skew(10deg, 20deg);  /* Safari and Chrome */
-o-transform:skew(10deg, 20deg);       /* Opera */
```

以下插图是对使用前述属性倾斜图像的表示：

![倾斜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_06.jpg)

### 矩阵

`matrix`属性将所有前述变换组合成一个属性，并且可以轻松消除源代码中的许多额外 CSS 行：

```html
transform:matrix(0.586, 0.8, -0.8, 0.586, 40, 20);
/* IE 9 */
-ms-transform:matrix(0.586, 0.8, -0.8, 0.586, 40, 20);
/* Firefox */
-moz-transform:matrix(0.586, 0.8, -0.8, 0.586, 40, 20); 
/* Safari and Chrome */  
-webkit-transform:matrix(0.586, 0.8, -0.8, 0.586, 40, 20);
/* Opera */
-o-transform:matrix(0.586, 0.8, -0.8, 0.586, 40, 20); 
```

前面的示例利用了 CSS 变换矩阵属性来在单个调用中应用多个变换样式。`matrix`属性需要六个参数来旋转、缩放、移动和倾斜元素。只有当您实际上需要一次实现所有变换属性时，使用矩阵属性才真正有用。如果您只需要利用元素变换的一个方面，最好只使用该 CSS 样式属性。

### 3D 变换

到目前为止，我们审查过的所有变换属性都是二维变换。CSS3 现在还支持 3D 和 2D 变换。CSS3 3D 变换最好的部分之一是许多设备和浏览器支持硬件加速，从而允许在您的视频卡 GPU 上进行复杂的图形处理。在撰写本书时，只有 Chrome、Safari 和 Firefox 支持 CSS 3D 变换。

### 提示

在开始开发之前，想知道哪些浏览器将支持所有这些出色的 HTML5 功能吗？请访问[`caniuse.com`](http://caniuse.com)查看流行浏览器在一个简单易用的网站上支持哪些功能。

在处理 3D 世界中的元素时，我们使用 Z 坐标，这允许使用一些新的变换属性。

```html
transform:rotateX(angle)
transform:rotateY(angle)
transform:rotateZ(angle)
transform:translateZ(px)
transform:scaleZ(px)
```

让我们从 HTML 元素创建一个 3D 立方体，将所有这些属性放入一个工作示例中。要开始创建我们的 3D 立方体，我们将首先编写包含立方体的 HTML 元素，以及构成立方体本身的元素：

```html
<body>
  <div class="container">
    <div id="cube">
      <div class="front"></div>
      <div class="back"></div>
      <div class="right"></div>
      <div class="left"></div>
      <div class="top"></div>
      <div class="bottom"></div>
    </div>
  </div>
</body>
```

这个 HTML 通过创建每个具有特定类名的六个面的元素，以及整个立方体的容器以及显示所有页面内容的主容器，为我们的立方体创建了一个简单的布局。当然，由于这些容器中没有内部内容，也没有样式，将此 HTML 文件在浏览器中打开将得到一个空白页面。因此，让我们开始编写 CSS，使所有这些元素可见，并将每个元素定位以形成我们的三维立方体。我们将首先设置我们的主容器，这将定位我们的内容并包含我们的立方体面：

```html
.container {
  width: 640px;
  height: 360px;
  position: relative;
  margin: 200px auto;

  /* Currently only supported by Webkit browsers. */
  -webkit-perspective: 1000px;
  perspective: 1000px;
}
#cube {
      width: 640px;
      height: 320px;
      position: absolute;

/* 
Let the transformed child elements preserve 
the 3D transformations: 
*/
  transform-style: preserve-3d;
      -webkit-transform-style: preserve-3d;
      -moz-transform-style: preserve-3d;
}
```

`container`类是我们的主要元素，它包含此示例中的所有其他元素。在附加了宽度和高度后，我们将顶部边距设置为`200px`，以将显示向下推移一点，以便更好地查看页面，并将左右边距设置为自动，这将使该元素在页面中居中对齐。

```html
#cube div {
  display: block;
  position: absolute;
     border: 1px solid #000000;
     width: 640px;
     height: 320px;
     opacity:0.8;
}
```

通过为`#cube div`定义属性，我们为`#cube`元素内的每个`div`元素设置样式。我们还通过将宽度和高度设置为矩形比例来欺骗立方体系统，因为我们的意图是在结构和位置确定后向立方体的每一面添加视频。

附加了基本的立方体面样式后，现在是时候开始变换每个面，形成三维立方体了。我们将从立方体的前面开始，通过在 Z 轴上进行平移，使其靠近视角：

```html
#cube .front  {
-webkit-transform: translateZ(320px);
   -moz-transform: translateZ(320px);
   transform: translateZ(320px);
}
```

为了将这种样式附加到所有现代浏览器中的元素上，我们需要为每个不支持默认`transform`属性的浏览器指定多种语法的属性：

![3D transforms](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_07.jpg)

在附加了 Z 轴平移 320px 后，前面的屏幕截图显示了`.front` div 发生的变化。较大的矩形是`.front` div，现在离我们的视角近了 320px。为了简单起见，让我们对`.back` div 执行相同的操作，将其推离视角 320px：

```html
#cube .back   {
  -webkit-transform:
      rotateX(-180deg) 
      rotate(-180deg) 
      translateZ(320px);
  -moz-transform: 
      rotateX(-180deg) 
      rotate(-180deg) 
      translateZ(320px);
  transform: 
      rotateX(-180deg) 
      rotate(-180deg) 
      translateZ(320px);
}
```

如前面的代码所示，为了正确将`.back`元素移动到位而不使其倒置，我们在 X 轴上将元素翻转 180 度，然后像`.front`一样将 Z 平移 320px。请注意，我们没有在 translate Z 上设置负值，因为元素被翻转了。有了`.back` CSS 样式，我们的立方体应该看起来像下面这样：

![3D transforms](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_08.jpg)

现在可见的最小矩形是具有类名`.back`的元素，最大的是我们的`.front`元素，中间的矩形是剩下的要变换的元素。

为了定位立方体的各个面，我们需要绕 Y 轴旋转侧面元素，使其面向正确的方向。一旦它们旋转到位，我们可以在 Z 轴上平移位置，使其从中心推出，就像我们对前面和后面的面做的那样：

```html
#cube .right {
    -webkit-transform: rotateY(90deg) translateZ( 320px );
    -moz-transform: rotateY(90deg) translateZ( 320px );
    transform: rotateY(90deg) translateZ( 320px );
}
```

![3D transforms](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_09.jpg)

右侧就位后，我们可以对左侧执行相同的操作，但是将其朝相反方向旋转，使其面向另一侧：

```html
#cube .left {
-webkit-transform: rotateY(-90deg) translateZ( 320px );
   -moz-transform: rotateY(-90deg) translateZ( 320px );
   transform: rotateY(-90deg) translateZ( 320px );
}
```

![3D transforms](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_10.jpg)

现在我们已经正确对齐了立方体的四个面，我们可以通过对齐顶部和底部来最终确定立方体的位置。为了正确设置顶部和底部的大小，我们将设置它们自己的宽度和高度，以覆盖`#cube` div 样式中设置的初始值：

```html
#cube .top {
   	width: 640px;
   height: 640px;

   -webkit-transform: rotateX(90deg) translateZ( 320px );
   -moz-transform: rotateX(90deg) translateZ( 320px );
   transform: rotateX(90deg) translateZ( 320px );
}
#cube .bottom {
   	width: 640px;
   height: 640px;

   -webkit-transform: rotateX(-90deg) translateZ( 0px );
   -moz-transform: rotateX(-90deg) translateZ( 0px );
   transform: rotateX(-90deg) translateZ( 0px );
}
```

为了正确定位顶部和底部，我们需要在 X 轴上将`.top`和`.bottom`元素旋转+-90 度，使它们朝上和朝下，只需要在 Z 轴上将顶部平移到正确的高度，以连接所有其他面。

在我们的布局中添加了所有这些变换后，生成的立方体应该如下所示：

![3D 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_11.jpg)

尽管看起来是 3D 的，但由于容器中没有内容，透视并没有很好地展示我们的立方体。因此，让我们在立方体的每一面添加一些内容，比如视频，以更好地可视化我们的工作。在每一面中，让我们添加相同的 HTML5 视频元素代码：

```html
<video width="640" height="320" autoplay="true" loop="true">
  <source src="img/cube-video.mp4" type="video/mp4">
  <source src="img/cube-video.webm" type="video/webm">
  Your browser does not support the video tag.
</video>
```

由于我们尚未添加元素播放控件以显示立方体的更多可见区域，我们的视频元素被设置为在完成后*自动播放*视频以及*循环*播放。现在我们得到了一个正确展示 3D 变换能做什么并且更具视觉吸引力的结果：

![3D 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_12.jpg)

由于我们设置了每个立方体面的不透明度，现在我们可以看到所有四个视频在每一面播放，非常酷！既然我们已经在这里，为什么不再加一点，为这个立方体添加用户交互，这样我们就可以把它转过来，看到每一面的视频。

要执行这种用户交互，我们需要使用 JavaScript 将页面文档上的鼠标坐标转换为立方体的 X 和 Y 3D 旋转。因此，让我们开始创建 JavaScript 来监听鼠标事件：

```html
window.addEventListener("load", init, false);

function init() {
  // Listen for mouse movement
  window.addEventListener('mousemove', onMouseMove, false);
}

function onMouseMove(e) {
  var mouseX = 0;
  var mouseY = 0;

  // Get the mouse position
  if (e.pageX || e.pageY) {
    mouseX = e.pageX;
    mouseY = e.pageY;
  } else if (e.clientX || e.clientY) {
    mouseX = e.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
    mouseY = e.clientY + document.body.scrollTop + document.documentElement.scrollTop;
  }

  console.log("Mouse Position: x:" + mouseX + " y:" + mouseY);
}
```

从上述代码示例中可以看出，当`mousemove`事件触发并调用`onMouseMove`函数时，我们需要运行一些条件语句来正确解析鼠标位置。由于像网页开发的许多其他部分一样，从浏览器中检索鼠标坐标各不相同，我们添加了一个简单的条件来尝试以几种不同的方式收集鼠标 X 和 Y。

鼠标位置准备好被转换为立方体的变换旋转后，我们需要在设置 CSS 样式更新之前完成最后一点准备工作。由于不同的浏览器支持不同语法的 CSS 变换应用，我们需要在 JavaScript 中找出在运行时使用哪种语法，以允许我们的脚本在所有浏览器上运行。以下代码示例就是这样做的。通过设置可能属性值的预定义数组，并尝试检查每个属性的类型作为元素样式属性，我们可以找到哪个元素不是未定义的，并知道它可以用于 CSS 变换样式：

```html
// Get the support transform property
var availableProperties = [
      'transform',
      'MozTransform',
      'WebkitTransform',
      'msTransform',
      'OTransform'
      ];
// Loop over each of the properties
for (var i = 0; i < availableProperties.length; i++) {
  // Check if the type of the property style is a string (ie. valid)
  if (typeof document.documentElement.style[availableProperties[i]] == 'string'){
    // If we found the supported property, assign it to a variable
    // for later use.
        var supportedTranformProperty = availableProperties[i];
      }
}
```

现在我们已经获得了用户的鼠标位置和立方体的 CSS 变换更新的正确语法，我们可以把它们放在一起，最终实现对我们的视频立方体的 3D 旋转控制：

```html
<script>
  var supportedTranformProperty;

  window.addEventListener("load", init, false);

  function init() {
    // Get the support transform property
    var availableProperties = ['transform', 'MozTransform','WebkitTransform', 'msTransform', 'OTransform'];
    for (var i = 0; i < availableProperties.length; i++) {
      if (typeof document.documentElement.style[availableProperties[i]] == 'string'){
                supportedTranformProperty = availableProperties[i];
          }
}

    // Listen for mouse movement
    window.addEventListener('mousemove', onMouseMove, false);
  }

  function onMouseMove(e) {
    // Get the mouse position
    if (e.pageX || e.pageY) {
      mouseX = e.pageX;
      mouseY = e.pageY;
    } else if (e.clientX || e.clientY) {
      mouseX = e.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
      mouseY = e.clientY + document.body.scrollTop + document.documentElement.scrollTop;
}

    // Update the cube rotation
    rotateCube(mouseX, mouseY);
  }

  function rotateCube(posX, posY) {
    // Update the CSS transform styles
  document.getElementById("cube").style[supportedTranformProperty] = 'rotateY(' + posX + 'deg) rotateX(' + posY * -1 + 'deg)';
  }

</script>
```

尽管我们已经尝试允许多浏览器使用此示例，但最好在每个浏览器中打开它，看看类似 3D 变换的重型内部内容是如何运行的。在撰写本书时，所有 WebKit 浏览器都是查看此类内容的简单选择，因为诸如 Firefox 和 Internet Explorer 之类的浏览器以更慢和更低质量的输出渲染此示例：

![3D 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_13.jpg)

## 过渡

使用 CSS3，我们可以在从一种样式更改到另一种样式时添加效果，而无需使用 Flash 动画或 JavaScript：

```html
div {
  transition: width 2s;
  -moz-transition: width 2s;    /* Firefox 4 */
  -webkit-transition: width 2s; /* Safari and Chrome */
  -o-transition: width 2s;      /* Opera */
}
```

如果未指定持续时间，过渡将不会产生任何效果，因为默认值为 0：

```html
div {
  transition: width 2s, height 2s, transform 2s;
  -moz-transition: width 2s, height 2s, -moz-transform 2s;
  -webkit-transition: width 2s, height 2s, -webkit-transform 2s;
  -o-transition: width 2s, height 2s,-o-transform 2s;
}
```

### 提示

值得注意的是，目前 Internet Explorer 不支持 CSS3 过渡。

## 浏览器兼容性

如果你还没有注意到，浏览器兼容性的斗争是网页开发人员工作的最重要方面之一。随着时间的推移，许多出色的服务和应用程序已经被创建，以帮助开发人员以比试错技术更简单的方式克服这些障碍。网站，如[`css3test.com`](http://css3test.com)、[`caniuse.com`](http://caniuse.com)和[`html5readiness.com`](http://html5readiness.com)都是保持 HTML5 规范开发人员和浏览器对所有功能的支持的重要资源。

# 帧速率

一个人会假设，因为你，读者，来自 Flash 开发背景，当开发 HTML5 应用程序时，应该花点时间谈论帧速率或每秒帧数。由于 Flash 应用程序中的每个资源都是基于时间轴模型的，计算每秒显示多少帧时间轴的帧是一个相当简单的计算。然而，组成 HTML5 开发的所有技术在运行时都不依赖于时间轴的使用。因此，计算网页的每秒帧数或 FPS 值并不总是衡量 HTML5 项目性能的准确指标。

### 提示

我们在章节代码示例中找到的 CSS 3D 变换示例包括使用一个名为**Stats.js**的优秀 JavaScript 代码，用于监视每秒帧数以及毫秒数。Stats.js 是一个开源项目，可以在[`github.com/mrdoob/stats.js`](https://github.com/mrdoob/stats.js)找到。

## 为移动设备开发

HTML5 受到现代移动浏览器的全面支持，这是 HTML5 流行的另一个推动力。随着 Flash Player 在所有移动平台上的失去，使用 HTML5 传递内容的使用率达到了历史最高水平，并且每天都在增长。应用程序、框架和模板，如 jQuery Mobile ([`jquerymobile.com`](http://jquerymobile.com))、Phone Gap ([`phonegap.com`](http://phonegap.com))、Appcelerator ([`www.appcelerator.com`](http://www.appcelerator.com))和 Mobile Boilerplate ([`html5boilerplate.com/html5boilerplate.com/dist/mobile`](http://html5boilerplate.com/html5boilerplate.com/dist/mobile))，所有这些都将在第五章中详细介绍，*一次编码，到处发布*，都是专门为帮助网页开发人员构建专门针对移动视图的网页内容而构建的。CSS 可以以响应的方式设置，以便根据用户查看内容的设备和视口配置以优化的格式显示相同的页面内容。

## 响应式布局

“响应式布局”这个术语似乎在 HTML5 开发日益普及的情况下被更频繁地使用。对一些人来说，它已经成为定义良好的 HTML5 开发的关键特性之一的关键词。无论术语如何使用，归根结底，当我们在网页开发中提到“响应式布局”时，我们指的是使用现代网页开发技术来使同一页面内容能够在用户设备和视图分辨率上进行布局和内容的过渡调整。换句话说，确保您的页面内容以优化的方式设置，适用于所有视图分辨率，并且能够在任何一个布局之间进行过渡，而无需刷新页面内容。

## CSS 媒体查询

创建响应式布局时最重要的资产之一是使用 CSS 媒体查询。媒体查询允许您根据用户的设备、分辨率、旋转等目标特定的 CSS 样式。尽可能了解加载 HTML 文档的设备和软件将使您不仅能够指定特定设备和浏览器如何显示内容，还可以使您的代码监视查看方法的实时更改。例如，以下媒体查询示例根据设备旋转更改背景颜色：

```html
@media screen and (orientation:portrait) {
  background-color: #FF0000;
}

@media screen and (orientation:landscape) {
  background-color: #0000FF;
}
```

CSS 媒体查询属性列表很短，但在创建条件时了解可用的内容非常重要。因此，让我们快速回顾一下在编写媒体查询时可以使用的属性：

+   `width`：描述目标显示区域的宽度。

+   `height`：描述目标显示区域的高度。

+   `device-width`：描述输出设备的渲染显示的宽度。

+   `device-height`：描述输出设备的渲染显示的高度。

+   `orientation`：当高度媒体特征的值大于或等于宽度媒体特征的值时，为`portrait`。否则，方向为`landscape`。

+   `aspect-ratio`：定义为`width`媒体特征值与`height`媒体特征值的比率。

+   `device-aspect-ratio`：定义为`device-width`媒体特征值与`device-height`媒体特征值的比率。

+   `color`：描述输出设备颜色组件的每位数。如果设备不是彩色设备，则该值为零。

+   `color-index`：描述输出设备颜色查找表中的条目数。如果设备不使用颜色查找表，则该值为零。

+   `monochrome`：描述单色帧缓冲区中每像素的位数。如果设备不是单色设备，则输出设备值将为`0`。

+   `resolution`：描述输出设备的分辨率，即像素的密度。在查询具有非方形像素的设备时，在`min-resolution`查询中，最不密集的维度必须与指定值进行比较，在`max-resolution`查询中，最密集的维度必须进行比较。没有“min-”或“max-”前缀的`resolution`查询永远不匹配具有非方形像素的设备。

+   **scan**：描述“tv”输出设备的扫描过程。

+   **grid**：用于查询输出设备是否为网格或位图。如果输出设备是基于网格的（例如“tty”终端或仅具有一个固定字体的手机显示器），则值将为`1`。否则，值将为`0`。

# 音频和视频播放控制

正如我们在上一章中看到的，将音频和视频资产与基本控件集成到 HTML5 文档中非常容易。但是，如果您打算以除了直接视频播放元素之外的其他形式使用多媒体，您需要了解用于自定义播放代码集成的可用属性。

## 预加载

默认情况下，在 HTML5 文档中显示音频或视频元素时，其中声明的源资产将被预加载，以便在用户启动播放器时进行即时播放。资产将仅在浏览器认为必要的情况下进行预加载，以实现流畅的不间断播放。要覆盖此设置，我们可以在音频元素中使用`preload`参数来声明用户查看页面时希望预加载的内容。

将`preload`参数设置为`auto`将在页面加载时预加载整个音频，并且可能是用户在页面加载后某个时刻几乎肯定会观看的任何音频的有用补充。使用设置了`preload`参数后，我们的音频元素将如下所示：

```html
<audio controls preload="all">
  <source src="img/my-audio .mp3" type="audio/mpeg">
  <source src="img/my-audio.ogg" type="audio/ogg">
  Your browser does not support the audio element.
</audio>
```

除了预加载所有内容，我们还可以通过设置`preload="none"`而不是`auto`来完全不预加载任何内容。从音频中删除预加载将允许用户在不需要进行不必要的音频下载的情况下浏览您的页面，但会导致用户启动音频播放后加载时间更长。最后，我们还可以通过设置`preload="metadata"`在预加载时仅加载音频元数据。这将允许音频元素查看它即将加载的数据，这在动态添加音频到音频元素并在尝试播放之前需要验证其是否适合播放时非常有用。

## 自动播放

如第二章*准备战斗*中所述，将`autoplay`设置附加到视频元素后，视频将在能够播放而无需停止视频进行进一步缓冲时开始播放。与 HTML 中许多其他元素参数不同，`autoplay`参数不需要值。因此，只需将`autoplay`附加到元素即可完成任务。值得注意的是，几乎所有移动浏览器加载时都会忽略`autoplay`设置。移动浏览器倾向于忽略此设置，以节省无线连接的带宽。

## 循环

将循环设置附加到音频元素后，视频将在每次完成时重新开始。与`autoplay`参数一样，`loop`参数不需要值。如果您只想让视频循环播放特定次数，可以使用设置`loop`参数并在必要时删除它，或者从 JavaScript 控制整个播放以控制视频元素中的循环计数而不使用循环参数。

## 音效

在特定时刻播放音效可以通过使用 HTML5 音频元素和 JavaScript 的多种方式来实现。在其最简单的形式中，播放音效可以实现为以下代码示例所示的方式。

```html
<body>
  <audio src="img/ping.mp3" preload="auto" id="audio-ping">
  </audio>

  <script>
    window.addEventListener("load", init, false);

    function init() {
      window.addEventListener(
          'mousedown', 
          onMouseDown, 
          false
      );
    }

    function onMouseDown(e) {
      document.getElementById('audio-ping').play();
    }
  </script>
</body>
```

当音频元素在 HTML 文档主体内创建时，我们设置`preload="auto"`，这将确保音频尽快完全预加载。我们这样做是为了在需要音效时没有延迟。音频元素还被赋予一个 ID，以便在 JavaScript 中引用。通过窗口加载事件监听器，我们等待页面加载，然后对浏览器窗口中的任何`mousedown`事件应用事件监听器。当这发生时，我们通过 ID 选择我们的音频元素，并调用内置的`play()`方法，从而在每次单击浏览器窗口时播放音频。

## 媒体播放操作

除了前面示例中的`play()`方法外，JavaScript 还可以直接控制音频和视频元素的许多其他方面。如下例所示，音频音量可以设置为`0`到`1`之间的值。

```html
document.getElementById('audio-ping').volume = 0.5; // Set the volume to 50%
```

我们还可以利用其中的以下公开对象来收集元素的所有统计信息：

```html
var media = document.getElementById('audio-ping');
media.seekable.start(); // Start time (seconds)
media.seekable.end(); 	  // End time (seconds)
media.currentTime = 20; // Seeks playback to 20 seconds
// Total amount of seconds the playback has displayed
media.played.end();
```

# 使用文件 API 读取本地文件

将 HTML5 内容带入更类似应用程序的功能集的另一个功能是添加文件 API。用户现在可以以比以往更深入的方式与本地内容进行交互。用户可以以传统的 HTML 表单方式导入文件，或者现在只需将文件拖放到 HTML5 布局中指定的拖放区域。一旦用户向网页提交了文件，您的 JavaScript 文件 API 使用可以允许您在将文件提交到服务器之前查看、编辑和操作文件数据。我们将在接下来的章节中深入探讨文件 API 的许多示例中。

# Web Workers

在过去，当执行处理器密集型 JavaScript 时，浏览器经常会在处理完成并返回结果之前冻结。随着 HTML5 Web Workers 的出现，您现在可以将处理器密集型的 JavaScript 代码作为后台进程来执行，这不会影响活动文档的性能。用户将能够在等待 Web Worker 在后台完成其工作时继续使用网站。

要轻松检查用户的浏览器是否支持 HTML5 Web Workers，我们可以检查`Worker`对象的类型是否未定义或不是：

```html
if(typeof(Worker) == "undefined") {
  // This browser doesn't support Web Workers...
}
```

根据浏览器是否支持 Web Workers 的使用，我们可以随时通过实例化一个新的`Worker`对象和其 JavaScript 源的引用来轻松创建一个新的 worker：

```html
worker = new Worker("worker.js");
```

在前面的示例中，我们创建了一个新的 worker，并将其引用到`worker.js`文件中的源代码。下一步是为当 worker 发布更新时创建事件侦听器。为了创建这个侦听器，我们在`onmessage`属性上创建一个函数，并从`event.data`属性中检索消息：

```html
// Create an event listener for worker updates.
worker.onmessage = function (event) {
  console.log('New worker event - ' + event.data);
};
```

worker 中的代码可以是任何内容，尽管最合理的做法是使其成为通常会在短时间内冻结浏览器的内容。无论您的 worker 正在做什么，为了使回调到您的代码生效，您将使用内置的`postMessage`函数：

```html
postMessage(YOUR_DATA);
```

### 提示

由于您的 Web Worker 代码位于外部文件中，因此它将无法访问其 JavaScript 源中的 window、document 或 parent 对象。

在本章的示例文件中，以及在我们开始构建更大的 JavaScript 项目时，您将在即将到来的章节中找到更多 Web Workers 的用法。

# WebSockets

向您的网页添加服务器端通信以启用诸如多用户交互或推送通知等功能，随着 WebSockets 的出现越来越受欢迎。简而言之，当您需要服务器与客户端进行通信而不需要客户端的请求时，WebSockets 填补了这一空白。

在构建 Flash 应用程序时，通常会使用诸如**实时媒体流协议**（**RTMFP**）或 SmartFoxServer（[`www.smartfoxserver.com`](http://www.smartfoxserver.com)）等技术和框架，以实现基于服务器的多用户应用程序。现在，通过使用 WebSockets，这个概念已经可以实现，这真正证明了 HTML 规范的发展已经走了很远。

在即将到来的章节中，我们将继续深入研究 WebSockets 的更多示例，以及一些其他有趣的方法，用于连接查看您的 HTML5 内容的用户，例如 Socket.io（[`socket.io`](http://socket.io)）、Node.js（[`nodejs.org`](http://nodejs.org)）和 Google V8（[`code.google.com/p/v8`](http://code.google.com/p/v8)）。

# Canvas 元素

在没有至少提及 HTML5 Canvas 元素的情况下，我们无法完成本章。Canvas 允许开发人员使用 Canvas 2D 绘图 API 将图形实时绘制到一个可控制的空白区域中。从 Flash 开发人员的角度来看，理解 Canvas 元素的功能集最简单的方法是，它使用类似于 ActionScript 3 绘图和图形 API 的功能，在 HTML 布局中的一个空白区域中，这与 Flash 舞台非常相似。

为了更好地理解这一切的意义，让我们使用 Canvas 创建一个简单的绘图应用程序。首先，我们需要将 Canvas 元素附加到 HTML 文档的主体中。元素标签内不需要包含任何内容，因为只有在用户尝试从不支持 Canvas 元素的浏览器中查看此内容时才能看到它：

```html
<body>
  <canvas id="example" width="640" height="480" style="border:1px  solid #000000;">
    Your browser does not support the HTML5 Canvas element.
  </canvas>
</body>
```

在这个例子中，Canvas 中添加了两个重要的内容，它们是元素 ID，将在接下来的步骤中在 JavaScript 中使用，以及宽度和高度声明。如果没有在元素中设置宽度和高度，大多数浏览器将以 300px x 150px 渲染 Canvas。为了帮助我们开发这个应用程序，在 Canvas 中添加了 1px 的边框，以便我们准确地看到它在浏览器窗口中的边界。最后，正如前面提到的，Canvas 元素内部的内容只有在浏览器中不支持该元素时才会显示。如果应用程序也被编写为 Flash 应用程序，Flash SWF 的对象嵌入可以用来替代我们在这个例子中使用的文本警告。

下一步是在 JavaScript 中设置对我们的 Canvas 及其 2D 上下文的引用，由于我们在元素上设置了一个 ID，我们可以在我们的代码中轻松地引用它到一个变量中：

```html
var canvas, context; // Variables to hold Canvas references

window.addEventListener("load", init, false);

function init() {
  // Set the canvas reference to a JavaScript variable.
  canvas = document.getElementById('example');

  // Get the 2D canvas context to allow for 2D Drawing API integration
   context = canvas.getContext('2d');
      if(!context) {
        alert("Failed to get canvas context!");
    return;
}

  canvas.addEventListener('mousemove', onMouseMove, false);
  canvas.addEventListener('mousedown', onMouseDown, false);
  canvas.addEventListener('mouseup', onMouseUp, false);
}

function onMouseDown(e) {
  isDrawing = true;
}
function onMouseUp(e) {
  isDrawing = false;
}
```

通过引用我们的 Canvas 并设置鼠标事件监听器来监视用户何时按下鼠标按钮，让我们通过编写我们的`onMouseMove`函数来完成这个例子，以在`isDrawing`变量为`true`时画一条线：

```html
function onMouseMove(e) {
    var x, y;

  if (e.pageX || e.pageY) {
    x = e.pageX;
    y = e.pageY;
  } else if (e.clientX || e.clientY) {
    x = e.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
    y = e.clientY + document.body.scrollTop + document.documentElement.scrollTop;
  }

    if(!isDrawing) {
    // Since the mouse isn't down, just move 
// the context to the latest mouse position.
        context.beginPath();
        context.moveTo(x, y);
  } else {
        // The mouse is down so draw the line to 
// the current mouse position.
        context.lineTo(x, y);
        context.stroke();
  }
}
```

如果您注意到，我们`onMouseMove`函数中的初始代码取自我们的 3D 变换示例，并允许我们在不同的现代浏览器上读取鼠标 X 和 Y 位置。如果您曾在 ActionScript 3 中使用过绘图 API，那么跟随鼠标位置查找的条件应该看起来有点熟悉。假设鼠标按下，我们会画一条线到当前鼠标位置，并设置默认的描边。在这种情况下，默认的描边是 1px 的黑色实线。当鼠标未按下时，我们只是将上下文移动到鼠标位置，但不画任何线条。这样可以让我们不断重置并等待开始新的线条。在浏览器中测试时，这个例子会看起来像这样：

![Canvas 元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_03_14.jpg)

这个例子只是开发人员可以使用的开始，但希望能让您了解它是如何工作的。我们将在下一章继续研究 Canvas 元素。

# Stage3D 与 WebGL

在结束本章之前，应该提到一些关于 WebGL 的可用性以及它与 Adobe Flash 中的 Stage3D 的相似之处和不同之处。WebGL 是一个跨平台的 Web 标准，允许开发人员创建和操作低级 3D 图形，将无插件的 3D 开发带到 Web 上。WebGL 可以在所有现代浏览器中实现和查看，唯一的例外是 Internet Explorer。

### 提示

请注意，微软似乎计划发布支持 WebGL 的 Internet Explorer 11。

WebGL 和 Stage 3D 的关键方面是它们都支持使用硬件加速。这可以在设备和浏览器上查看内容时大大提高图形处理负载的性能，前提是有适当的支持。尽管本书没有足够的空间深入研究 WebGL 的使用，但我们将在第六章中查看一些支持和使用它的框架和库，*HTML5 框架和库*。

### 提示

要了解更多信息并查看您当前的网络浏览器是否支持使用 WebGL，请访问[`get.webgl.org`](http://get.webgl.org)，WebGL 公共维基([`www.khronos.org/webgl/wiki`](http://www.khronos.org/webgl/wiki))，或在[`www.khronos.org/webgl/wiki/Demo_Repository`](http://www.khronos.org/webgl/wiki/Demo_Repository)上查看一些有趣的示例。

# 摘要

虽然在本章的课程中我们已经涵盖了许多有趣的功能，但在接下来的章节中，我们还将看到许多非常酷的 HTML5 新增功能。到目前为止，我们所涵盖的关键思想是 Flash 和 HTML5 之间的特性关系在某种程度上是相似的，但又有所不同。了解什么样的技术能够让你以最佳方式开发应用程序是任何优秀开发者的关键特质。在下一章中，我们将深入探讨 JavaScript 的使用以及在面向对象编程时与 ActionScript 3 的关系。


# 第四章：使用 HTML5 构建健壮的应用程序

自从 ActionScript 3 出现以来，Flash 开发人员已经习惯于以面向对象编程（OOP）范式进行开发。当转换到 JavaScript 时，许多具有 OOP 经验的开发人员可能会对 JavaScript 用于实现相同功能的语法感到不满。然而，对语法的误解可能导致对功能的误解。因此，在本章中，我们将介绍 JavaScript OOP、事件和事件监听器的使用。

在本章中，我们将涵盖以下内容：

+   JavaScript 类结构、用法和语法

+   对象继承

+   类构造函数

+   辅助开发的工具和框架

+   创建自定义事件和监听器

# 编写面向对象的 JavaScript

2006 年，当 Adobe 发布带有 ActionScript 3 支持的 Flash Player 9 时，Flash 开发社区看到了他们开发 Flash 应用程序的一次重大范式转变。在使用 ActionScript 3 之前，开发人员被要求用 ActionScript 2 编写他们的应用程序，这主要用作脚本编程语言。ActionScript 3 被设计为一个真正的面向对象编程语言，具有严格的类型，允许以可重用、更受控制的方式编写代码。

通过使用 ActionScript 3 和为 Flash Player 9 发布的新 ActionScript 虚拟机编译器，Flash 应用程序中的代码不仅以 OOP 结构编写，而且还可以比以前的传统 Flash 应用程序运行快 10 倍。随着时间的推移，Flash 开发人员已经习惯于编写适当的 OOP 结构化代码，这使他们能够轻松地将他们的编程技能转移到其他语言，如 Java、C++或 C#。

在 JavaScript 中使用 OOP 范式起初有点难以理解，因此让我们创建一个在 ActionScript 3 中的示例类结构，并直接将其移植到 JavaScript 中，以查看视觉语法的差异。在这个示例中，我们将创建一个名为`Player`的示例类，它将模拟游戏中角色的基本功能。我们将使用`Player`类来创建我们游戏中所需的任意数量的玩家，并通过构造函数、getter、setter 和公共变量来改变它们的属性，而不是根据功能为我们的游戏中的每个玩家设置单独的代码。为了更好地理解这个概念，请考虑以下代码示例：

```html
package {
public class Player {
    // Private Variables
    private var lives:int; // How many lives our player has.
    private var xPosition:int; // The players X position.
    private var yPosition:int; // The players Y position.

    // Public Variables
    public var name:String = 'John'; // The players name.

    /**
     * The Player constructor. 
     * This function is called when a new Player is     * instantiated.
     *
     * @param playerName: The name to give to our player.
     * @param lives: How many lives to give our player.
     */
    public function Player(playerName:String, playerLives:int = 5):void {
        // Update the player variables with 
        // the supplied parameters.
        name = playerName;
        lives = playerLives;
    }

    /**
     * Return the current amount of lives the player has.
     */
    public function get lives():int {
        return lives;
    }

    /**
     * Move the players x and y position.
     *
     * @param	x: The new X position to move the player to.
     * @param	y: The new Y position to move the player to.
     */
    public function move(x:int, y:int):void {
        // Update the player position variables.
        xPosition = x;
        yPosition = y;

        updatePosition();
    }

    /**
     * The would be the function that actually moves the
     * displayed player display object on the stage. 
     * This would get called every time a players X and Y   
     * position values are updated.
     */
    private function updatePosition():void {
        // Code to update the players display object...
    }
  }
}
```

尽管为了示例目的而简化，这个类示例对于任何有 ActionScript 3 编码经验的开发人员来说应该看起来非常熟悉。在我们的 Flash 项目中声明了这个类，我们可以随时导入它并实例化它。在对象内部声明了可以被父对象调用以操纵特定`Player`对象数据的属性和方法，这是任何类的典型特征。当你准备在你的应用程序中添加一个新的玩家时，我们可以用以下 ActionScript 3 代码实例化一个新对象：

```html
var player:Player = new Player('John', 10);
```

通过将所需的值附加到构造函数中，我们为我们的玩家提供了一个独特的名称，以及这个玩家将拥有多少生命的初始值。现在我们有了我们的新玩家，在我们的想象游戏中可以操纵它。

现在让我们看一下在 JavaScript 中重新编写的相同类：

```html
function Player(playerName, playerLives) {
  // Private variables
  var lives = playerLives;
  var xPosition = 0;
  var yPosition = 0;

  // Public variables
  this.name = playerName;

  // Return the current amount of lives the player has.
  this.lives = function() {
    return lives;
  }

  /**
   * Move the players x and y position.
   *
   * @param	x: The new X position to move the player to.
   * @param	y: The new Y position to move the player to.
   */
  this.move = function(x, y) {
    xPosition = x;
    yPosition = y;

    updatePosition();
  }

  /**
   * The would be the function that actually moves the displayed
   * player display object on the stage. This would get called 
   * every time a players X and Y position values are updated.
   */
  function updatePosition() {
    //
  }
}
```

乍一看，人们会发现没有类声明，这是许多其他编程语言中熟悉的。相反，在 JavaScript 中创建“类”时，使用函数来模拟传统类结构的使用。包声明也从等式中移除，JavaScript 的包含也附加到 HTML 文档中，渲染网页。在逻辑上，可以将所有 JavaScript 类分开放在单独的文件中以便于开发。但是，当将大量 JavaScript 发布到公共托管环境时，为了节省对 Web 服务器的数据请求，应尽可能合并 JavaScript。我们将在第十章中更深入地探讨为生产环境准备 HTML5 项目，*准备发布*。

### 提示

此时必须注意一点。由于缺乏严格的类型和许多其他特定的类结构规则，同样的 JavaScript 功能可以用多种方式编写。在本章的过程中，我已经尽可能地编写了示例，以便让我们更好地检查语法。

## 类语法

在初始的 JavaScript 类示例中，我们比较了 ActionScript 3 的类结构与 JavaScript 在创建面向对象代码时的差异。该示例使用了 JavaScript 中创建类的更传统方法之一，即使用函数代替典型的类声明。

### 函数

到目前为止，我们在代码示例中使用的许多 JavaScript 函数示例已经展示了定义新函数的不同方式。正如我刚才提到的，根据开发人员的舒适程度，他们可能选择以以下一种方式之一在 JavaScript 中编写函数：

```html
function isAlive1() { return true; }
var isAlive2 = function() { return true; };
window.isAlive3 = function() { return true; };

console.log(isAlive1());
console.log(isAlive2());
console.log(isAlive3());
```

在前面的示例中，三个`console.log`输出中的每一个都将产生正确的布尔返回值*true*。值得注意的是，函数定义和函数使用的顺序不需要像前面的代码示例中所示的那样。以下示例将产生完全相同的结果：

```html
console.log(isAlive1());

function isAlive1() { return true; } var isAlive2 = function() { return true; };
window.isAlive3 = function() { return true; };

console.log(isAlive2());
console.log(isAlive3());
```

尝试调用未定义的函数时，将会触发`ReferenceError`错误，并在 JavaScript 控制台中显示。

![函数](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_04_01.jpg)

尽管我们的应用程序可能会继续运行，尽管出现此运行时错误，但这通常意味着我们的代码存在问题。我们可以使用简单的条件来处理代码中的此问题，而不是将默认的`ReferenceError`错误发送到 JavaScript 控制台。

```html
try {
  console.log(isAlive4());
} catch(error) {
  console.log('Failed to call isAlive4() - ' + error);
  // Run alternate code here...
}
```

### 变量范围

正确理解 JavaScript 中变量范围是理解语言核心方面的关键步骤。范围是指变量在代码的其他部分创建时对其可访问性。变量可以根据用于声明它们的语法进行实例化和引用。JavaScript 利用许多人所说的*函数范围*，在其中所有变量和函数的范围都相同。在范围链的顶部是全局变量和函数。与所有编程范式一样，全局意味着一切，全局变量或函数可以在代码的任何其他地方访问。

```html
var name = 'John';

function getName() {
  return name;
}

// Both calls return the name as it is accessible globally.
console.log(name);
console.log(getName());
```

此代码演示了全局变量的使用。由于变量名在使用它的函数范围之上声明，因此运行此代码时不会出现错误。但是，变量也可以在函数内部局部声明。

```html
function getName() {
  var name = 'John';
  return name;
}

console.log(name);     // Error
console.log(getName());   // Success
```

由于 Player 的名称（在这种情况下是 John）是在`getName`函数内创建的，因此无法全局访问该函数之外的任何代码。全局和局部变量的概念虽然简单，但当你开始考虑严格类型的缺乏以及全局和局部变量的确切变量名称时，你可能会感到头晕。不用担心，这是 JavaScript 开发人员在典型学习曲线问题中遇到的另一个问题。但正如之前提到的，掌握 JavaScript 中的变量作用域是每个优秀的 HTML5 开发人员必须具备的基本技能之一。

为了演示一些问题，并允许您完全查看作用域的运行情况，让我们回顾以下示例：

```html
// We will start with a globally scoped variable which is accessible by everything.
var alpha = 'a';

// Global scope example.
function a() {
    console.log(alpha); // Reference the global alpha variable.
}

// Local scope using a supplied variable.
function b(alpha) {
    console.log(alpha); // Reference the supplied alpha variable.
}

// Local scope using a variable created within the function.
function c() {
  var alpha = 'c';
  console.log(alpha);
}

// Update the global object property.
function d() {
    this.alpha = 'd'; // Create an internal object property.
}

function e() {
    var n = 'e';

    this.alpha = function() {
        console.log(n);
    }
};

function f() {};

a();    // A
b('b'); // B
c();    // C

console.log(new d().alpha); // D

var e = new e().alpha();    // E

f.prototype.alpha = 'f';    
console.log(new f().alpha); // F
```

尽管上面的例子是一个不合逻辑的输出字符 A 到 F 的方式，但它展示了许多变量和函数可以被操纵以访问应用程序作用域链中特定区域数据的方式。

### 公共和私有变量和函数

理解 JavaScript 中的变量和函数的下一步是学习如何创建和利用公共和私有成员。与 ActionScript 3 不同，变量不是私有或公共类型的，因此语法稍微难以理解。

#### 局部或私有变量

通过在对象内创建变量时使用`var`关键字声明私有（或局部）变量。结果变量只能在特定对象内部访问，并且需要 getter 和 setter 方法来允许外部操作。这种变量声明方式类似于在 ActionScript 3 中创建变量时使用`private`关键字。面向对象编程开发的一个一般准则是尽可能使用私有变量，因为这将大大减少变量损坏或其他错误使用的问题。

```html
function Example() {
  var foobar = 'abc'; // Only accessible within the Example scope.
}
```

#### 公共变量

通过使用`this.myVariableName`语法声明公共变量或属性。与在 ActionScript 3 中创建变量时使用`public`关键字类似，JavaScript 中的公共变量不仅可以在对象作用域链内的代码中访问，还可以在创建它的对象之外访问。

```html
function Example() {
  this.foobar = 'abc'; // Accessible outside the Example scope.
}
```

#### 私有函数

只能在对象作用域内访问的私有函数可以用几种不同的方式编写。

```html
function Example() {
  function TestOne() {
    return true;
  }

  var testTwo = function() {
    return true;
  };
}
```

先前演示的两个例子都产生了一个私有函数。任何尝试从对象作用域之外调用该函数的尝试都会导致运行时错误。

#### 公共函数

公共或特权函数，像公共变量一样，可以从创建它们的对象之外访问，并使用`this.myFunctionName = function() {...}`语法创建。

```html
function Example() {
  this.test = function() {
    return true;
  }
}
```

### 原型

JavaScript 对象语法中更令人困惑的一个方面是原型对象的使用。正如我们在此之前的示例和解释中所看到的，JavaScript 中的一切都是对象，而每个 JavaScript 对象中都有一个原型属性。

### 提示

如果您在 ActionScript 1 或 ActionScript 2 的时代使用 Flash，您可能熟悉原型对象的概念（[`help.adobe.com/en_US/as2/reference/flashlite/WS5b3ccc516d4fbf351e63e3d118ccf9c47f-7ec2.html`](http://help.adobe.com/en_US/as2/reference/flashlite/WS5b3ccc516d4fbf351e63e3d118ccf9c47f-7ec2.html)）。这个对象在两种编程语言中都被使用，但在 ActionScript 3 发布时被放弃。

为了看到这个概念的运行情况，让我们从简单开始，逐步向更复杂的原型对象用法前进。我们将首先查看一个新空对象的原型对象。

```html
var player = {}; // Create a new empty object.
console.log(Object.getPrototypeOf(player)); // Return the prototype object.
```

在 Web 浏览器中运行此代码将导致 JavaScript 日志，其结果非常接近以下代码，如果不是相同的话：

```html
Object
__defineGetter__: function __defineGetter__() { [native code] }
__defineSetter__: function __defineSetter__() { [native code] }
__lookupGetter__: function __lookupGetter__() { [native code] }
__lookupSetter__: function __lookupSetter__() { [native code] }
constructor: function Object() { [native code] }
hasOwnProperty: function hasOwnProperty() { [native code] }
isPrototypeOf: function isPrototypeOf() { [native code] }
propertyIsEnumerable: function propertyIsEnumerable() { [native code] }
toLocaleString: function toLocaleString() { [native code] }
toString: function toString() { [native code] }
valueOf: function valueOf() { [native code] }
```

这个输出可以让我们更加了解原型对象的真正含义。正如你已经从之前的 ActionScript 3 开发中了解到的，对象变量类型带有许多内置方法来操作其中的内容。查看我们的`Player`对象的原型的输出，你可能会注意到列出了许多这些熟悉的方法和属性。

我们可以使用原型对象随时向对象附加新属性。考虑以下示例，我们创建了一个简化的`Player`对象，并通过原型对象而不是直接在对象本身内部附加移动功能：

```html
function Player(name) {
  this.name = name;
  this.lives = 0;
  this.xPosition = 0;
  this.yPosition = 0;
}

Player.prototype.move = function(x, y) {
  this.xPosition = x;
  this.yPosition = y;
}
```

相同的概念可以用于覆盖默认对象行为。通过修改原型对象的移动属性，对移动方法的任何进一步调用都将导致新附加的行为。

```html
function Player(name) {
  this.name = name;
  this.lives = 0;
  this.xPosition = 0;
  this.yPosition = 0;

  this.move = function(x, y) {
    this.xPosition = x;
    this.yPosition = y;
  }
}

Player.prototype.move = function(x, y) {
  this.xPosition = x + 5;
  this.yPosition = y + 5;
}
```

请记住，这些更改是针对对象本身而不是实例。因此，这些更改将影响到每个“Player”实例，如下所示：

```html
function Player(name) {
  this.name = name;
  this.lives = 0;
  this.xPosition = 0;
  this.yPosition = 0;

  this.move = function(x, y) {
    this.xPosition = x;
    this.yPosition = y;
  }
}

function init() {
  var susan = Player('Susan');
  var john = Player('John');	

  // Modify the move function for ALL Player instances.
  Player.prototype.move = function(x, y) {
    this.xPosition = x + 5;
    this.yPosition = y + 5;
  }
}
```

那么为什么这很重要呢？根据你的应用程序是如何构建的，通过利用原型对象，你可以直接向对象附加共享代码，而无需多次编写相同的代码。代码越少意味着内存占用越少，这将使你在维护项目时更加轻松。

### 实例类型

当你开始在这些示例和自己的 JavaScript 代码中浮动时，添加检查和条件以获取实例类型将证明是一个重要的补充。缺乏严格的类型将要求你编写和维护干净和优化的代码，以使你的应用程序正常工作。考虑一些以下代码片段，以获取有关我们的`Player`对象实例类型的信息：

```html
// Create a player instance
var player = new Player('John');

// Check the type of player.
console.log(typeof(player));

// Output the constructor data from the player.
console.log(player.constructor);

// Check if the player is a Object - returns a Boolean.
console.log(player instanceof Object);
```

对`console.log`方法的每次调用都执行查找`Player`对象实例的不同方式。当我们在 Web 浏览器中运行此代码并打开开发者控制台时，我们会得到以下输出：

![实例类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_04_02.jpg)

初始的`object`输出是对`Player`对象的`typeof()`函数调用的结果。第二个输出是调用`Player`对象的构造函数时返回的代码块。最后，条件控制台调用（`console.log(player instanceof Object)`）在控制台中返回布尔值，让我们知道`instanceof`条件为真。

### 对象字面量

字面量只是在 JavaScript 中定义数组和对象的一种更简短的方法。我们已经使用以下语法在 JavaScript 中创建新对象：

```html
var player = new Object();
var player= Object.create(null);
var player = {};
```

我们可以通过在变量声明中直接创建对象的内部来进一步扩展前面的语法。

```html
var player = {
  name: "John",
  lives: 5,
  xPosition: 0,
  yPosition: 0,
  move: function(x, y) {
    xPosition = x;
    yPosition = y;

    // Update the position display...
  }
}
```

然而，这种`Object`语法在重用方面存在重大问题，因为它的实例在创建时已经存在。由于不需要实例化对象，我们可以通过引用其属性来继续我们的代码。

```html
  player.name = "Susan";
  player.move(5, 5);
```

### 构造函数

正如我们在之前的一些示例中所看到的，与 ActionScript 3 相比，对象构造函数的语法与通常使用的有些不同。由于类只是函数，我们可以直接将通常在构造函数中找到的代码放在类内部。

通过调用对象的`constructor`属性，你可以轻松查找最初创建对象的函数的引用。

```html
console.log(player.constructor);
```

当尝试查找内置对象类型（如数组、字符串或日期）的构造函数时，输出将隐藏内部代码，并显示使用原生代码的警告。

```html
var test = Array();
console.log(test.constructor);
```

这将在浏览器的 JavaScript 控制台中生成以下内容：

```html
function Array() { [native code] }
```

## 继承

通过在现有对象上使用`call()`方法，我们可以将对`this`的引用从对象本身更新到代码中的其他位置。

```html
function Player(name) {
  this.name = name;
  this.age = 20;
}

function John() {
  Player.call(this, 'John');

  this.age += 35;
}

function Jill() {
  this.age += 20;
}
Jill.prototype = new Player('Jill');

function init() {
  var john = new John();
  console.log(john.name + ' is ' + john.age);

  var jill = new Jill();
  console.log(jill.name + ' is ' + jill.age);
}
window.addEventListener("load", init);
```

此示例演示了在新的`John`对象中简单继承`Player`对象。这使我们能够访问`Player`中的内部值，并在`John`类中外部使用它们。在这个例子中，我们让 John 比默认的`Player`大 35 岁。我们还可以使用原型对象来声明对象继承。

```html
function Player(name) {
  this.name = name;
  this.age = 20;
}

function Jill() {
  this.age += 20;
}
Jill.prototype = new Player('Jill');

function init() {
  var jill = new Jill();
  console.log(jill.name + ' is ' + jill.age);
}
window.addEventListener("load", init);
```

创建新的`jill`对象时，它继承了来自`Player`的所有基本属性和函数，因为原型引用已经声明了对象继承。在页面加载时，此示例的输出将显示以下内容：

```html
John is 55
Jill is 40
```

## 列出对象属性

在任何时候，您都可以使用`Object.getOwnPropertyNames()`方法查找对象中可用的属性。在考虑私有和公共语法的情况下，让我们回顾以下示例，查看查找对象属性时的输出：

```html
function Player() {
  // Private variables
  var _this = this; 	// Reference to this object
  var lives;
  var positionX = 0;
  var positionY = 0;
  var playerElement;

  // Public variables
  this.name = '';	// The players name.
  this.age = 10;	// The players age (default = 10).

  this.move = function(x, y) {
    positionX = x;
    positionY = y;

    // Move the player...
  };

  function blink() {
    // Blink players eyes...
  }
}

var player = new Player();
var properties = Object.getOwnPropertyNames(player);

console.log(properties);
```

再次，考虑到公共和私有变量，只有使用关键字`this`创建的变量才能在对象范围之外可见。执行前面的代码示例将提供以下属性名称数组作为输出：

```html
["name", "age", "move"]

```

# 使 JavaScript 中的面向对象编程更容易

对于许多开发人员来说，开发面向对象 JavaScript 所需的所有这些变通和语法更改似乎就像是一长串“黑客”清单。无论您对此事的看法如何，都有许多选项可用于帮助构建具有更传统开发流程的大规模基于 JavaScript 的应用程序。在第六章中，*HTML5 框架和库*，我们将深入研究许多流行的 JavaScript 库和框架，以及它们如何不仅可以加快您的开发时间，还可以在所有现代浏览器和设备上提供更可靠的最终结果。

# JavaScript 事件

与大多数语言一样，事件是真正使应用程序活跃起来的。如果没有事件的使用，程序通常只会从开始到结束运行，而不需要人类交互。JavaScript 事件建立在异步事件模型的基础上。事件可以使用回调结构，例如在 ActionScript 中，来执行一旦事件被触发就执行代码，而不是不断地检查是否满足条件。这方面的一个很好的例子，你可能已经在许多其他示例中看到过：

```html
window.addEventListener("load", init, false);
```

我们在`window`对象上使用此事件监听器，以便让我们的代码确定`window`对象何时完成加载，以便我们可以调用我们的初始方法来开始 JavaScript 操作我们的文档。

## 键盘和鼠标事件

鼠标事件是几乎所有 JavaScript 项目都包含的核心元素之一。虽然我们将在整本书中的示例中使用这些事件，但值得回顾一下不仅是鼠标，还有键盘和触摸事件的整合列表，这样你就可以更好地了解可供您用于输入事件监听的内容。不同的键盘和鼠标事件列举如下：

+   **mousedown：**鼠标按钮已被按下

+   **mouseup：**鼠标按钮已被释放

+   **click：**鼠标按钮已被单击

+   **dblclick：**鼠标按钮已被双击

+   **contextmenu：**已触发某个操作以显示上下文菜单

+   **scrolling：**上下文已在滚动轴上移动

+   **keydown：**键盘键已被按下

+   **keypress：**键盘键已被按下并释放

+   **keyup：**键盘键已被释放

## 触摸事件

触摸事件支持正逐渐接近一套标准；但是，您会注意到根据您正在测试的设备和浏览器的支持和功能集的差异。值得注意的是，就像在触摸界面上运行的 Flash 应用程序一样，您可以使用鼠标事件而没有问题，并且仍然支持实际鼠标的使用。但是，由于鼠标一次只能点击一个点，如果您的应用程序需要多点触控支持，您将不得不开始使用触摸事件结构。在接下来的两章中，我们将进一步探讨在触摸设备上使用 HTML 的方式以及开发的区别。支持的触摸事件如下：

+   touchstart：用户已开始触摸元素

+   touchmove：用户自 touchstart 以来移动了触摸位置

+   touchend：用户已经从元素中移开手指

## 自定义事件

拥有创建自定义事件并将其分派给等待事件监听器的能力，可以进一步扩展应用程序的面向对象编程语法和结构。通常，作为使用 ActionScript 3 的 Flash 开发人员，您会利用`flash events`类来创建自定义事件，以便从一个类到另一个类创建通信流。在其最简单的形式中，它看起来像下面这样：

```html
import flash.events.Event;
import flash.events.EventDispatcher;

var myEvent:Event = new Event("myEvent", false);
dispatchEvent(myEvent);
```

与 ActionScript 3 中的大多数功能一样，为了优化应用程序的文件大小和执行速度，在使用扩展的内部功能时，必须直接导入包。因此，在 ActionScript 3 中创建和分派事件时，我们应该始终导入`Event`和`EventDispatcher`类，之后我们可以用提供为字符串的自定义事件类型实例化一个新事件。当事件被分派时，将需要一个事件监听器来执行进一步的代码，以完成应用程序中的事件序列。我相信您非常清楚，ActionScript 3 中的典型事件监听器描述如下语法：

```html
addEventListener("myEvent", myCustomEventHandeler, false, 0, true);
```

使用与所有事件监听器设置相同的 ActionScript 3 语法，自定义事件类型再次以字符串形式提供给标识符。提供的第二个参数始终是一旦此监听器触发将要调用的函数。最后三个参数控制事件控制和内存清理的冒泡和弱引用。

幸运的是，JavaScript 中自定义事件的设置和结构与一些明显的区别非常相似。考虑这个工作示例，与我们刚刚审查过的内容以及您已经了解的 ActionScript 3 中的事件相比。

```html
function init() {
  // Create an event listener
  document.addEventListener("myEvent", myEventHandeler, false);

  // Create our custom event
  var myEvent = document.createEvent("Event");

  // initEvent(event type, allow bubbling, allow prevented)
  myEvent.initEvent("myCustomEvent", true, true);
  myEvent.customData = "We can add more data into our event easily!";
  document.dispatchEvent(myEvent);
}

function myEventHandeler(event) {
  console.log('The custom event has been dispatched - ' + event);
  console.log('And retrieve our appended data - ' + event.customData);
}

window.addEventListener("load", init);
```

除了缺少导入的类之外，这个事件示例在任何 Flash 开发人员眼中应该看起来非常熟悉。与本书中大多数示例一样，我们等待窗口加载一个我们到目前为止经常看到的事件监听器。在`init`函数中，我们首先创建我们的事件监听器。在这种情况下，我们将监听器附加到文档；但是，这可以附加到代码中的任何对象。请注意，不仅创建新事件监听器的方法完全相同（`addEventListener`），而且初始两个参数的语法也是相同的。提供的最后一个布尔值控制事件冒泡，我们稍后将回顾。`init`函数中的剩余代码包含我们的事件实例化以及该事件的分派。再次感谢 ECMAScript 的荣耀，自定义事件的语法和结构几乎是相同的。

在 JavaScript 中使用`createEvent()`方法创建我们的事件类型时，事件模块的可用性取决于浏览器的 DOM 级别支持。在撰写本书时，大多数浏览器都在向全面支持 DOM 级别 3 事件迈进，其中包括 UIEvent、DOMFocus、DOMActivate、Event、MouseEvent、MutationEvent、TextEvent、KeyboardEvent 和 HTMLEvent。您可以通过访问[`www.w3.org/TR/DOM-Level-3-Events/`](http://www.w3.org/TR/DOM-Level-3-Events/)来查看当前可用或未来指定的 DOM 级别 3 事件的完整列表。

`addEventListener`方法的第三个参数指定注册的事件处理程序是否捕获指定的事件。如果事件处理程序捕获事件，那么每次事件发生在元素或其后代上时，事件处理程序都将被调用。

## 事件冒泡

当事件被分派时，它将遵循对象的父树直到绝对父对象，直到它被处理或停止。这种行为称为事件冒泡，它也存在于 ActionScript 3 和 JavaScript 事件结构中。在 Flash 项目中，事件将一直冒泡到主对象或在大多数情况下是舞台。在 JavaScript 中，事件将冒泡到文档对象。

在下面的例子中，我们将研究如何通过控制事件的传播来处理文档和对象上的`mousedown`事件：

```html
function init() {
  // Add a mouse click listener to the document.
  document.addEventListener("mousedown", onDocumentClick, false);

  // Add a mouse click listener to the box element.
  var box = document.getElementById('box');
  box.addEventListener("mousedown", onBoxClick, false);
}

function onDocumentClick(event) {
  console.log('The document has been clicked - ' + event);
}

function onBoxClick(event) {
  console.log('The box has been clicked. - ' + event);

  // Stop this event from reaching the document object
  // and calling the document level event listener.
  event.stopPropagation();
}

window.addEventListener("load", init);
```

这个 JavaScript 片段为文档中的元素以及文档本身都应用了`mousedown`事件监听器。如果用户在页面中的元素上点击，那么两个事件监听器都会被调用，导致两个不同的处理程序处理相同的鼠标点击。虽然在某些应用程序中这可能很方便，但处理这个问题的自然方式是通过使用`stopPropagation()`方法停止事件冒泡的流程，从而只允许调用单个处理程序。

在 JavaScript 中处理事件传播与在 ActionScript 3 中所习惯的方式是相同的。在事件流的任何时刻，您都可以通过调用`stopPropagation()`或`stopImmediatePropagation()`方法轻松地停止事件的传播。如果您熟悉 ActionScript 3 开发中的这些方法，您将知道它们在本质上几乎是相同的。唯一的区别是`stopImmediatePropagation()`调用会阻止事件流到达当前节点中的任何其他事件侦听器。

# 把所有东西放在一起

归根结底，所有这些代码示例只是定义了 JavaScript 功能的各个部分。继续使用本章节中一直在使用的`Player`类概念，我们对我们的示例“游戏中的玩家”类结构进行了一些润色。

```html
function Game() {
  // An array to hold all our player objects
  var players = new Array();

  // Game Constructor
  // Reference to the game element in the document.
  var gameElement = document.getElementById('game'); 

  // Get the game element size.
  var gameElementWidth = gameElement.offsetWidth;
  var gameElementHeight = gameElement.offsetHeight;

  // Be sure to update these values if the window is 
  // to ever be resized.
  window.onresize = function() {
    console.log("NOTICE: Browser Resize: " + gameElementWidth + " x " + gameElementHeight);
    gameElementWidth = gameElement.offsetWidth;
    gameElementHeight = gameElement.offsetHeight;
  };

  // Player Class.
  function Player(name) {
    this.name = name;

    // Create the element for the player.
    var playerElement = document.createElement("div");
    playerElement.class = 'element';
    playerElement.style.position = "absolute";
    playerElement.style.left = Math.floor((Math.random() * gameElementWidth - 100) + 1) + 'px';	// Random position within viewabled bounds
    playerElement.style.top = Math.floor((Math.random() * gameElementHeight - 100) + 1) + 'px';
    playerElement.style.color = "#000000";
    playerElement.style.display = "block";
    playerElement.style.padding = "5px";
    playerElement.style.border = "1px solid #000000";
    playerElement.style.width = "100px";
    playerElement.style.height = "100px";
    playerElement.innerHTML = this.name;
    gameElement.appendChild(playerElement);

    // Move this players X and Y positions.
    this.move = function(x, y) {
      playerElement.style.left = x + "px";
      playerElement.style.top = y + "px";
    }

    // Return the current position of this player 
    // as a object.
    this.getPostion = function() {
      var position = {};
      position.x = parseInt(playerElement.style.left);
      position.y = parseInt(playerElement.style.top);
      return position;
    }
  }

  // Public Methods
  this.addNewPlayer = function(name) {
    // Check if this player name is already created
    var l = players.length;
    for(var i = 0; i < l; i++) {
      if(name == players[i].name) {
        console.log('Error: Player with the name ' + name + ' already exsits.');
        return;
      }
    }

    // Create the new player instance
    var player = new Player(name);

    // Add a reference to the global players array.
    players.push(player);
  }

  this.getPlayer = function(name) {
    // Check if this player name is already created
    var l = players.length;
    for(var i = 0; i < l; i++) {
      if(name == players[i].name) {
        return players[i];
      }
    }

    return false;
  }
}

function init() {
  // Create the game instance.
  var game = new Game();

  // For this game we will automatically create two players.
  game.addNewPlayer('Jack');
  // Try to add another Jack to view name check.
  game.addNewPlayer('Jack'); 
  game.addNewPlayer('Jill');

  document.addEventListener('keydown', onKeyDown);

  // Called when the user presses a key on the keyboard.
  function onKeyDown(event) {
    // The key that was just pressed (ID).
    var key = event.keyCode; 

    // Lookup the player to reference.
    var player = game.getPlayer('Jack'); 

    // Make sure the player exsists.
    if(player == false) return;

    // Get the players current position.
    var position = player.getPostion();

    // Forward
    if(key == 38) player.move(position.x, position.y - 10);

    // Backwards
    if(key == 40) player.move(position.x, position.y + 10);

    // Left
    if(key == 37) player.move(position.x - 10, position.y);

    // Right
    if(key == 39) player.move(position.x + 10, position.y);
  }
}

window.addEventListener("load", init);
```

尽管这仍然是一个简单的例子，展示了在一个单一包中可能具备的许多我们在本章中看到的特性：

![把所有东西放在一起](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_04_03.jpg)

# 总结

尽管本章涵盖了 JavaScript 开发中对象的语法和结构的主要概念，但实际上我们可以写一整本书来讨论这个主题。话虽如此，我们将继续在本书中涵盖这些以及更多 JavaScript 开发的高级方面。正如本章的介绍中所提到的，许多高级 JavaScript 开发中呈现的差异和范式变化可能对一些 Flash 开发人员来说有些令人生畏。然而，一旦您掌握了这些核心概念中的大部分，其他的拼图就会变得轻而易举地拼合在一起。在下一章中，我们将探讨一些可用于将现有 Flash 内容移植到 HTML5 的工具。

### 提示

寻找更高级的 JavaScript 语法和结构技巧？您可以查看 Packt Publishing 出版的这些书籍，*Object-Oriented JavaScript* by *Stoyan Stefanov*，*Learning jQuery, Third Edition* by *Jonathan Chaffer* and *Karl Swedberg*，以及*jQuery for Designers: Beginner's Guide* by *Natalie MacLees*。
