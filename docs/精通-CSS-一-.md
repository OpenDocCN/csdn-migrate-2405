# 精通 CSS（一）

> 原文：[`zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7`](https://zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML、CSS 和 JavaScript 是网络的三种核心语言。你对它们三者了解得越多，你就会越好。在这三者中，CSS 的作用是作为网络的展示语言。它描述了诸如颜色、字体和页面布局等内容。

本书有一些基本先决条件。我希望你了解如何编写 HTML，并了解基本的 CSS，包括样式化字体、添加边距、填充和背景颜色等，以及十六进制颜色代码是什么。在接下来的章节中，我将介绍一些基本概念，如盒模型、显示属性和样式表类型。我还会涉及少量 JavaScript 和 jQuery。你不需要任何关于这些的先前知识，但你将在本书中有所涉猎。

现在，让我们来看一下我们将要构建的最终网站。为了学习 CSS，我们将完成构建以下关于鲨鱼的 HTML5 网站。我说*完成*构建这个网站，是因为基本的 HTML 和 CSS 已经就位，你可以从本书的下载包中下载它们。我们将添加我将向你展示的所有东西，以及更多。这个网站采用了模块化和可重用的 CSS，你将在本书中学到。该网站首先将使用浮动进行布局，然后我们将使用 flexbox 重写布局。我们还会为文本使用 Web 字体：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00005.jpeg)

导航功能包括使用 CSS 动画的下拉菜单：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00006.jpeg)

该网站还具有一个带有 CSS 渐变的行动号召按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00007.jpeg)

该网站是完全响应式的。当我们调整浏览器大小时，可以看到我们的两列布局转变为单列布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00008.jpeg)

此外，我们的菜单会变成专为移动设备设计的菜单：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00009.jpeg)

如果我们向下滚动一点，我们会看到使用 CSS 过渡的幽灵按钮。它已经准备好适用于苹果的视网膜显示屏等高分辨率设备：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00010.jpeg)

网站上的大部分图像都使用 SVG：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00011.jpeg)

在页面的最底部，我们使用了一个图标字体：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00012.jpeg)

因此，你会学到一些非常酷的东西。为了充分利用它，我建议你跟着我一起编码。

# 本书涵盖的内容

第一章，*CSS 基础*，介绍了掌握 CSS 所必需的基本概念。

第二章，*加速*，讨论了 Sublime 文本编辑器；CSS 重置，用于重置浏览器中的默认样式；以及后代选择器。

第三章，*使用浮动创建页面布局*，深入探讨了浮动。我们将介绍浮动的基本用法，然后使用浮动创建布局，并了解浮动可能引起的常见问题以及如何解决。

第四章，*使用模块化、可重用的 CSS 类和 CSS3 创建按钮*，涵盖了模块化 CSS 和多个类，并使用 CSS3 为我们的按钮添加过渡、悬停状态、变换和渐变。

第五章，*创建主导航和下拉菜单*，解释了我们主要导航的功能和展示。

第六章，*变得响应式*，介绍了响应式网页设计的基础知识，并解释了如何将其实现，将我们的静态网站转变为移动网站。

第七章，*Web 字体*，讨论了`@font-face`规则的基本语法、字体服务、使用场景以及 Web 字体和图标字体的提供者。

第八章，*HiDPI 设备的工作流程*，涵盖了为准备图像以适应 Retina 而使用 SVG 和`srcset`属性等技术的技术。

第九章，*Flexbox*，*第一部分*，介绍了 Flexbox 模块，涵盖了基本实现和属性。

第十章，*Flexbox*，*第二部分*，更深入地介绍了 Flexbox，构建了一个新的产品列表和更高级的属性。

第十一章，*总结*，总结了本书中涵盖的 CSS 概念，并提供了一些关于其他可以探索的 CSS 功能的信息。

# 您需要为这本书做好准备

在整本书中，我一直使用 Chrome 作为我的浏览器，因为它的 DevTools 等原因，但其他浏览器也有类似的工具。我们将使用 DevTools 直接在浏览器中探索代码。

我也一直在使用 macOS。如果您是 Windows 用户，而我在书中提到命令（*cmd*）键，您应该假装我是在提到*Ctrl*键。除此之外，我认为这不会成为问题。

我使用的文本编辑器是*Sublime Text 3*。我应该说 Sublime 并不是唯一一个好的文本编辑器。还有其他像 Atom 和 Visual Studio Code 这样的编辑器，它们可以做很多相同的事情。

尽管这本书是关于掌握 CSS，但没有 HTML，我们无法做太多事情。因此，我们将在 HTML 中进行相当多的工作。我们的目标是使用非常干净、语义化的 HTML；这是我们的目标。

# 这本书是为谁准备的

这本书是为希望在其网站项目中掌握 CSS 最佳实践的网页设计师和开发人员而写的。您应该已经知道如何处理网页，并准备使用 CSS 来掌握网站呈现。

# 约定

在这本书中，您会发现一些区分不同信息类型的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："要更改文本大小，请使用`font-size`属性。"

代码块设置如下：

```css
h2 {
  font-size: 26px;
  font-style: italic;
  color: #eb2428;
  margin-bottom: 10px;
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```css
h2 {
 font-size: 26px;
 font-style: italic;
 color: #eb2428;
 margin-bottom: 10px;
} 
```

任何命令行输入或输出都以以下形式书写：

```css
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample/etc/asterisk/cdr_mysql.conf

```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的形式出现在文本中："单击“下一步”按钮将您移至下一个屏幕。"

警告或重要说明会以这样的形式出现在方框中。

提示和技巧会出现在这样的形式中。


# 第一章：CSS 基础

在这第一章中，*CSS 基础*，我们将看一下掌握 CSS 所必需的基本概念。你将学习到在网页开发中的最佳实践。

在网页开发的世界中，事物经常变化。例如，在过去，表格是布局网页的首选技术。但今天，使用表格进行布局绝对不是你想要做的事情。浮动一直是创建布局的最常见方式，也是我们首先要学习的内容。在过去的一年左右，flexbox 开始取代浮动进行布局，我们将在本书的后期学习 flexbox。CSS 正在进步，其他新的布局模块被设计来取代浮动进行页面布局。网格布局和 CSS 区域可能是未来的发展方向。由于前端网页开发领域的事物迅速发展，我们的关键是我们不能停止学习 CSS。一般来说，一旦停止学习，你的知识将很快过时。我的目的是教授能够长期受益的概念和技术。

在本章的两个部分中，我们将回顾对网页设计和 CSS 至关重要的核心概念。我们将首先回顾如何创建 CSS 中最基本的东西-规则集-并讨论我们可以写这些规则集的不同位置。

# 规则集的解剖和三种类型的样式表

我们现在对这本书的内容和我们将要构建的网站有了更多的了解。在我们开始深入研究更高级的主题之前，让我们回顾一下一些 CSS 基础知识。在本书中，我会使用诸如选择器、属性和值等术语，你需要确切理解这些术语的含义，以便跟上进度。我们将首先回顾一个规则集，然后再看看我们可以写这些规则集的三个不同位置。所以让我们开始吧。

# 解剖规则集

让我们跳到一个 CSS 文件中，看看下面代码块中的一个规则集。它是针对`h2`-一个二级标题。它设置了`font-size`为`26px`，`font-style`为`italic`，`color`为红色，`margin-bottom`为`10px`：

```css
h2 { 
  font-size: 26px; 
  font-style: italic; 
  color: #eb2428; 
  margin-bottom: 10px; 
} 
```

所以这里没有什么可怕的！不过让我们来解剖一下：

```css
selector { 
  property: value; 
  property: value;
  property: value;
} 
```

在上面的代码中，`h2`是*选择器*。我们选择页面上的一个元素来定位我们的样式规则。`h2`选择器可以是`p`、`li`、`div`、`a`或者我们想要定位的任何 HTML 元素。它也可以是一个类、一个 ID 或一个元素属性，我稍后会谈到。接下来，我们在花括号内有属性和值。从开花括号到闭花括号是*声明块*。你可以在花括号内有尽可能多的属性。`font-size`、`color`、`font-style`和`margin`只是你可以使用的许多不同属性中的一部分。每个属性都有一个对应的值。在每个属性和值之间，你必须有一个冒号。值之后是一个分号，这也是必需的。每个属性和值被称为一个声明。所以声明块是花括号内的所有内容，声明是包括属性和值的单行。但实际上，在规则集的解剖中有三个重要的事情需要记住：选择器、属性和值。现在让我们看看我们可以在哪里写这些规则集。

# 外部样式表

目前，我们将规则集写在外部样式表中。你可以看到它实际上是一个独立的文件：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00013.jpeg)

在屏幕左侧的文件夹结构中，你可以看到它在一个名为`css`的文件夹中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00014.jpeg)

除了`嵌入`样式表之外。外部样式表是编写样式的最佳位置；它是一个单独的文件，链接到每个 HTML 页面。外部样式表可以控制整个网站，这是首选样式表的主要原因。在`index.html`文件的`<head></head>`标签之间的任何位置；这是您可以链接到外部样式表的地方：

```css
<head>
  <link rel="stylesheet" href="css/style.css"> 
</head>
```

`href`属性指向文件的位置。这里它指向`css`文件夹，然后是一个名为`style.css`的文件。还有一个`rel`属性，基本上表示这是一个`stylesheet`。在过去，您可能已经看到`text/css`作为`type`属性的值，如下面的代码块所示，但在 HTML5 中这不再是必需的：

```css
<head>
  <link rel="stylesheet" href="css/style.css" type="text/css"> 
</head>
```

您可能还看到了自关闭标签上的结束斜杠，比如`link`元素，但在 HTML5 中，这个斜杠不再是必需的。因此，包括它或排除它对您的网站没有任何影响。

# 嵌入样式表

除了使用最佳类型的样式表，外部样式表，我们还可以在 HTML 文档的头部编写我们的规则集。这被称为**嵌入样式表**。有很多原因不这样做。主要的两个原因是它阻碍了工作流程，而且它只控制站点的单个页面。我们要做的就是在`head`标签中创建这些开放和关闭的`<style>`标签：

```css
<head>
  <style> 

  </style> 
</head>
```

在这个开放的`<style>`标签内的任何位置，我们可以开始添加我们的规则集，这将只影响这一页：

```css
<head>
  <style> 
    h2 { 
      font-size: 50px; 
   } 
  </style> 
</head>
```

再次强调，这不是编写样式的最佳位置。将它们保留在外部样式表中，99%的时间都是最好的选择，但您可以选择将样式嵌入到文档的`head`标签中。

# 内联样式表

最后，第三种样式表是内联样式表。它实际上不是样式表-更像是*内联样式*。我们可以在 HTML 元素内部实际上写一个`style`属性：

```css
<h2 style=""> 
```

内联样式与使用传统规则集的外部和嵌入样式表有些不同；这里没有选择器，也没有完整的规则集，因为您是在 HTML 标记内部编写它。我们可以输入`font-size`为`10px`。我们以与规则集相同的方式编写属性和值，并且应该用分号结束：

```css
<h2 style="font-size: 10px;"> 
```

我们还可以更改颜色并用分号结束：

```css
<h2 style="font-size: 10px; color: deeppink;"> 
```

保存这个，刷新网站，你就可以看到结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00015.jpeg)

这绝对是编写样式的最低效方式。然而，在 HTML 元素中直接编写 CSS 会赋予它最大的权重，并且会覆盖所有针对相同元素的嵌入样式和所有外部样式，除非使用`!important`关键字。在第四章，*使用模块化、可重用的 CSS 类和 CSS3 创建按钮*中的*特异性规则*部分，我深入探讨了级联和其他因素，这些因素使某些规则的权重更大，并覆盖其他规则。

好的，现在我们已经创建了一个规则集，并学会了规则集的每个部分的名称，特别是选择器、属性和值。这些信息对您来说将是有帮助的，因为我经常会使用这些术语。我们还回顾了可以创建样式表的三种不同位置：外部、嵌入在`<head>`标签中，以及内联，直接在元素内部。再次强调，外部样式表是最有效的，因为它可以控制整个网站。这是我写 CSS 的唯一位置。接下来，我们将回顾另外两个核心概念：盒模型和`display`属性。

# 盒模型和块与内联元素

在这一部分，我们将回顾 CSS 的另外两个基础：盒模型和块级与内联元素。充分掌握这两个概念是以后掌握 CSS 的关键。首先，我们将回顾盒模型，然后我们将看看它与块级元素的关系。接着我们将讨论内联元素的特点。

# 盒模型

**盒模型**定义了页面上元素的宽度和高度。要确定一个元素占据的水平空间，你需要将`content` + `padding-left` + `padding-right` + `border-left` + `border-right` + `margin-left` + `margin-right`相加：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00016.jpeg)

所以让我们通过查看我们网站上的`h1`来实际看一下。这是蓝色文字，上面写着“Old Chompy”。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00017.jpeg)

这是使这个标题看起来像这样的规则集：

```css
h1 { 
  font-size: 40px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae 
} 
```

让我们添加以下属性，给它一个`width`、`padding`、`border`和`margin`。以及一个显眼的`background-color`：

```css
h1 { 
  font-size: 40px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae 
 background-color: black; 
 width: 300px; 
 padding: 50px; border: 10px solid blue; margin: 50px; 
}
```

现在我们的标题看起来是这样的。一个大盒子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00018.jpeg)

所以这个元素的盒模型现在有这 5 个属性；从前面的屏幕截图中可以看出，这个`h1`看起来真的像一个盒子。我们可以看到`10px`的边框，`margin`在`border`外面是`50px`，填充在边框和文本之间是`50px`。然后填充内部的宽度是`300px`。所以这个元素的宽度实际上是*300 + 20 + 100 + 100*，总共是`520px`。所以即使我们在 CSS 文件中定义了`width`属性为`300px`，这个元素实际占据的空间是`520px`。

现在，这是传统的盒模型。我可以使用`box-sizing`属性和`border-box`值修改这个传统的盒模型。所以让我们使用`box-sizing`属性，看看它如何影响网站。将属性和值添加到`h1`声明块的底部，如下所示：

```css
h1 { 
  font-size: 40px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae 
  background-color: black; 
  width: 300px; 
  padding: 50px; 
  margin: 50px; 
  border: 10px solid blue;
  box-sizing: border-box;
}
```

如下截图所示，`border-box`将从`width`和`height`计算中减去`padding`和`border`。如果我将`300px`作为我的`width`，那么我指定的`300px`将减去`20px`的边框和`100px`的填充。这是一个更直观的盒模型，它与 Internet Explorer 8 及更高版本兼容，以及所有其他主要浏览器。这个元素现在占据的最终水平空间从`520px`变成了`400px`。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00019.jpeg)

# 块级元素与内联元素

让我们稍微谈谈块级元素。标题 1（`h1`）、标题 2（`h2`）、段落（`p`）、列表项（`li`）和`div`都是自然块级元素的例子。块级元素有两个定义特征：它们扩展了整个可用宽度，并且它们强制后面的元素出现在下一行，这意味着它们堆叠在一起。所以让我们从我们的声明块中删除`box-sizing`属性以及`width`属性，以演示如果没有指定宽度，它们将占用整个可用宽度：

```css
h1 { 
  font-size: 40px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae 
  background-color: black; 
  padding: 50px; 
  margin: 50px; 
  border: 10px solid blue;
}
```

保存并刷新网站。你可以在下面的截图中看到，当你将浏览器窗口放大时，它占据了整个可用宽度，除了我们设置的`margin`是四周的`50px`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00020.jpeg)

现在让我们进入 HTML 文件，在 HTML 中再添加两个这样的`h1`标签，并保存：

```css
<section> 
  <h1>Old Chompy</h1> 
  <h1>Old Chompy</h1> 
  <h1&gt;Old Chompy</h1> 
```

这就是它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00021.jpeg)

现在你可以看到这些块级元素如何堆叠在一起：好老的块级元素。

另一方面，内联元素的行为不同。它们水平相邻，并且不占用整个可用宽度。它们只占用它们需要的宽度。一些天然的内联元素是锚点(`<a>`)、`<span>`、`<i>`、`<b>`、`<strong>`和`<em>`标签。

好了，让我进入 HTML 并向页面添加三个`span`标签：

```css
<section> 
  <h1>Old Chompy</h1> 
  <h1>Old Chompy</h1> 
  <h1>Old Chompy</h1> 
  <span>Inline</span> 
  <span>Inline</span> 
  <span>Inline</span> 
```

我还会通常在规则集中针对那些`span`元素并给它们一个绿色的背景，只是为了看到它们的区别：

```css
span { 
  background-color: green; 
} 
```

这是它的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00022.jpeg)

您可以注意到绿色的内联元素是水平排列而不是垂直堆叠。没有什么特别的，但我们可以看到它们不会占用整个可用宽度，它们只会占用它们需要的宽度。

有一些内联元素不会做的事情。它们不会响应`width`或`margin-top`或`margin-bottom`。因此，如果一个元素自然是内联的，并且您给它一个`width`和一个`margin-top`或`margin-bottom`，就像下面的代码所示，它将绝对不会做任何事情：

```css
span { 
  background-color: green;
 width: 1000px;
  margin-top: 1000px; 
} 
```

没有任何变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00022.jpeg)

内联元素只是不遵守这些属性，这些属性对它们没有影响，所以我们将删除它们。

还有一件有趣的事情可以做。有一个`display`属性，允许您将自然的块级元素更改为内联元素，反之亦然。所以让我们在我们的`span`选择器中添加一个`display`属性，值为`block`，并在浏览器中查看。所以，我可以说`display: block`，还可以添加一些`margin-top`：

```css
span { 
  background-color: green; 
 display: block; 
  margin-top: 10px; 
}
```

我们可以看到这些元素现在堆叠在彼此上面，并且现在遵守`margin-top`和`margin-bottom`的值：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00023.jpeg)

`display`属性设置为`block`的元素会遵守我给它的任何`width`值，但它也会占用整个可用宽度。您可以看到它延伸到屏幕的边缘。我们也可以在我们的`h1`选择器上轻松使用`display: inline`属性，将显示的性质从块状更改为内联。最后，我们可以使用`display: none`，这会完全隐藏页面上的元素，并且通常出于各种原因而使用。所以让我们去我们的`h1`声明并说`display: none`：

```css
h1 { 
  font-size: 40px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae; 
  background-color: black; 
  padding: 50px; 
  margin: 50px; 
  border: 10px solid blue; 
 display: none; 
} 
```

现在，如果我们查看我们的网站，那个`h1`是不可见的。它不再是浏览器要向我们展示的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00024.jpeg)

总之，所有元素都符合框模型。框模型会根据`box-sizing`属性的使用方式而略有变化，如果有的话。此外，框模型会根据元素是块级还是内联而变化，这是两种最常见的显示属性。

# 总结

在本章中，我们取得了很多成就。我们已经讨论了 CSS 是 Web 的呈现语言，真正使您的网站看起来像一个网站。我们现在熟悉了我们将要构建的网站和我们将在接下来的章节中使用的工具。我们已经涵盖了诸如规则集、链接到外部样式表和框模型和显示属性等核心概念，这些都是掌握 CSS 所必不可少的。

在下一章中，我们将介绍一些编写 CSS 所必需的工具，例如良好的文本编辑器、CSS 重置和 Chrome 的开发者工具。


# 第二章：加速

为了成为一个优秀的编码人员，你需要加速并学习一些能帮助你成为更好的开发人员的东西。在本章中，我们将看看可以加快工作流程的文本编辑器。然后，我们将看看*CSS 重置*，它重置默认浏览器，使其样式减少到最低，并内置浏览器开发者工具，帮助我们排除代码故障。然后，我们将看看如何使用类和 ID 重命名元素，并使用后代选择器限定我们的选择器。

# 文本编辑器

HTML、CSS 和 JavaScript 可以在任何文本编辑应用程序中编写。这是这三种核心网络语言的伟大之处之一。问题在于，编写 HTML、CSS 和 JavaScript 极易出错。对于 CSS，逗号、分号和大括号需要在正确的位置输入。在大多数情况下，需要完美地遵守特定的语法，否则你的页面将无法按预期渲染。以下是 Mac 上的 TextEdit 的示例。它与 Windows 上的记事本类似，因为它没有许多使编写代码变得容易的功能：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00025.jpeg)

无论如何，让我们在 TextEdit 中写一些代码。我们从 HTML 文档类型开始。之后，我们添加一个 HTML 开放和闭合标签，然后是`head`标签，里面是`title`标签。你很快就会意识到，这是一个相当乏味的过程，也就是在 TextEdit 中编写代码。我们可以在这里写代码，但我们真的得不到任何东西，没有语法高亮，也没有其他任何帮助：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00026.jpeg)

幸运的是，一个好的文本编辑器可以真正为你做一些艰苦的工作。在本章中，我们将看看这样一个文本编辑器，即 Sublime Text 3，以及它具有的一些很好的功能，可以帮助你更好地编写 HTML 和 CSS。首先，我们将看看片段，然后我们将看看语法高亮，接着是代码建议和多个光标。Sublime Text 3 是我选择的文本编辑器，因为它快速且易于使用。我喜欢的一件事是它如何轻松自然地让我编写代码。

# 片段

在 Sublime Text 3 中，你只需在 HTML 文件中输入`html:5`，然后按下*Tab*键，就可以获得 HTML 的基本样板。所以，我们在 TextEdit 中必须输入的所有代码都可以很快地为我们写好：

```css
<!DOCTYPE html> 
<html> 
<head> 
        <title></title> 
</head> 
<body> 

</body> 
</html> 
```

另一件事是，当你输入`div`并按下*Tab*键时，可以自动创建`div`的闭合标签，并将光标放在开放和闭合`div`标签之间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00027.jpeg)

我们可以对任何 HTML 元素做到这一点；只需输入像`p`这样的东西，然后按下*Tab*键，将光标放在中间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00028.jpeg)

太棒了！拥有如此简单的东西真的很好。

我们可以再进一步安装 Emmet 包。我强烈鼓励你这样做。这将为您提供更好的代码片段。实际上，之前生成基本 HTML 样板的`html:5`代码片段实际上是一个 Emmet 片段；它不是 Sublime 的标准功能：

```css
<!DOCTYPE html> 
<html> 
<head> 
    <meta charset="UTF-8">     
    <title>Document</title> 
</head> 
<body> 

</body> 
</html> 
```

在 Sublime 中安装包（基本上是插件）的能力，是它如此强大的另一个原因。对于 Sublime 没有默认提供的所有内容，都有一个可用的包。所以，假设你需要 ColdFusion 代码的语法高亮；有一个可用的包可以为你做到这一点。我在我的网站上有一篇文章，介绍了包安装，这非常简单。只需在[richfinelli.com/installing-sublime-package-manager/](http://www.richfinelli.com/installing-sublime-package-manager/)上查看它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00029.jpeg)

到目前为止，这是最好的包，你应该安装的第一件事就是 Emmet。有了 Emmet，比如你去到你的 HTML 并输入像这样的东西：

```css
div>ul>li*5>a{link$} 
```

这将扩展为以下内容：

```css
<div>
  <ul>
    <li><a href="">link1</a></li>
    <li><a href="">link2</a></li>
    <li><a href="">link3</a></li>
    <li><a href="">link4</a></li>
    <li><a href="">link5</a></li>
  </ul>
</div>
```

请注意，`$`在第一个`a`中扩展为 1，第二个为 2，依此类推，这可能非常有用。使用类似 CSS 选择器的语法快速编写 HTML 只是 Emmet 允许你做的好事之一。

# 多重光标

使用 Emmet 扩展的`div`标签，让我们来看看 Sublime 的多重光标功能。由于我们有五个列表，我们可能需要在每个列表中输入相同的内容。如果按住*cmd*键并单击代码的不同行，您实际上可以创建多个光标。如图所示，您现在可以在五个不同的位置输入相同的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00030.jpeg)

现在，假设您想在多个光标处输入一些占位文本。首先，输入“lorem5”，或者输入“lorem”后跟任何其他数字，您将获得相应数量的占位“lorem ipsum”文本：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00031.jpeg)

然后，只需按下*Tab*，它将自动扩展到我们的情况下，即 5 个字的 lorem ipsum 文本，如图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00032.jpeg)

# 语法高亮

让我们暂时切换到我们的 CSS。另一个将使我们的工作更加轻松的功能是语法高亮。请注意，所有规则集都遵循一种颜色方案。选择器是红色的，属性是蓝色的，值是紫色的。它们将开始嵌入到您的潜意识中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00033.jpeg)

Sublime Text 为您做的是，它微妙地指出了您的错误。我经常在需要冒号的地方输入了分号。这将导致您的 CSS 无法工作。尽管如此，语法高亮告诉我有些地方不对，因为如下截图所示，颜色方案发生了变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00034.jpeg)

很容易发现颜色差异，但如果您不寻找它，很难看出冒号和分号之间的区别：

# 代码建议

有一些很酷的功能可用，比如代码完成和代码建议。因此，如果您开始输入类似`border-`的内容，您将获得所有以`border`开头的不同属性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00035.jpeg)

在这种情况下，我正在寻找`border-radius`，所以我可以直接转到该建议并按下*Tab*，它会自动为我完成任务：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00036.jpeg)

我喜欢这个文本编辑器的原因还有很多，我就不一一列举了。它的价格是 70 美元，但有一个无限免费试用版，您可以用来确定您是否喜欢它——相信我，您会喜欢的。现在我并不是说 Sublime 是您应该使用或尝试的唯一文本编辑器。还有其他好的编辑器，比如 Visual Studio Code，Atom，Adobe Brackets 等。如果您使用的是其他大部分我所说的功能，并且对您有用的东西，那就坚持使用它。只是确保您不要使用记事本或文本编辑器来编写代码，因为那将非常痛苦和低效。

良好的文本编辑器对于编写良好的 HTML 和 CSS 至关重要，并将使我们的生活更加轻松。接下来，您将了解 CSS 重置以及它们如何帮助我们为编写 CSS 创建一个非常好的起点。

# CSS 重置

在上一节中，您了解了良好文本编辑器的强大功能。在本节中，我们将使用该文本编辑器来探索一种称为*CSS 重置*的东西。开始网站需要放置并且通常是您网站样板的一部分的许多部分。我称这些部分为您的“基础层”。这个*基础层*的一个重要部分是 CSS 重置。重置允许您消除浏览器在默认浏览器样式方面的不一致，并一般上消除所有默认浏览器样式。它允许*您*更轻松地使用 CSS 提供*您*手工制作的样式。在本节中，我们将首先加载 CSS 重置，然后检查该重置并看看它在做什么。最后，我们将添加和自定义重置以满足我们的需求。

# 加载 Eric Meyer 的 CSS 重置

有几种不同的重置可供选择，但我已经迷上了 CSS 大师 Eric Meyer 的重置。让我们从[meyerweb.com/eric/tools/css/reset/](http://meyerweb.com/eric/tools/css/reset/)获取它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00037.jpeg)

所以，向下滚动一点，找到重置的顶部，然后只需突出显示所有代码，直到你到达闭合大括号：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00038.jpeg)

切换到 Sublime，打开你的样式表，然后粘贴进去：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00039.jpeg)

在保存之前，让我们打开我们网站的 `index.html` 文件。你可以用 Sublime 做的一件事是：如果你右键点击你的 HTML 文件，你可以选择在浏览器中打开，它会打开你的默认浏览器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00040.jpeg)

在我的情况下，是 Chrome。所以这就是没有重置的网站会是什么样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00041.jpeg)

正如你在下一个截图中看到的，我们添加的所有 CSS 实际上移除了我们的一点点样式。这就是为什么我们称它为重置。所有文本看起来都一样——没有边距，没有填充，什么都没有。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00042.jpeg)

# 检查 CSS 重置

在我们的样式表的顶部，有一个 CSS 注释，归功于 Eric Meyer 的重置。我们会留下这个注释：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00043.jpeg)

接下来，我们有大部分的重置。这一大块代码模糊地提醒了你在 第一章 中学到的规则集，*CSS 基础*。它实际上只是一个带有非常长选择器的规则集。选择器中用逗号分隔了几乎每个 HTML 元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00044.jpeg)

这意味着所有这些元素都将从声明块中接收相同的样式：

```css
... {
  margin: 0; 
  padding: 0; 
  border: 0; 
  font-size: 100%; 
  font: inherit; 
  vertical-align: baseline; 
}
```

正如你在这个声明块的前三个声明中看到的，`margin`、`padding` 和 `border` 都被设置为 `0`。使用值 `0` 和使用 `0px` 是一样的，只是少了两个字符。如果值是零，你就不需要指定像素。这将从所有元素中移除默认的 margin、padding 和 border。在这些声明的下面，我们有 `font-size` 属性，它是 `100%`。这一行是一个指令，使所有字体都是浏览器默认的，基本上就是 `16px`，因为大多数桌面浏览器的默认字体大小是 `16px`。

在这个声明块下面，我们有新的 HTML5 元素，我们将它们的显示设置为块级。这允许一些不认识这些新元素的旧浏览器现在将它们视为块级元素。这使得 HTML5 可以在一些旧浏览器中工作：

```css
/* HTML5 display-role reset for older browsers */ 
article, aside, details, figcaption, figure,  
footer, header, hgroup, menu, nav, section { 
    display: block; 
} 
```

接下来，我们有一个新的选择器和声明，将 `line-height` 设置为 `1`：

```css
body { 
  line-height: 1; 
} 
```

`line-height` 属性向下级联，这意味着如果我们在一个元素上设置它，例如 `body`，它将被继承到它包含的所有其他元素。值 `1` 是一个无单位的值，所以 `1` 将等于字体的大小。值 `1.2` 将是字体大小的 1.2 倍。所以，如果 `font-size` 是 `16px`，`line-height` 是 `1`，那么 `line-height` 将等于 `16px`。如果 `line-height` 设置为 `2`，你的字体大小是 `16px`，那么 `line-height` 将等于 `32px`。

接下来在样式表中是有序和无序列表，我们从 `ul`、`ol` 中移除了项目符号和编号，通过级联的方式也会应用到 `li` 中：

```css
ol, ul { 
    list-style: none; 
} 
```

在此之下，你会看到重置为 `blockquote` 和 `q` 元素设置了一些默认值。我很少使用块引用，而且这个重置有点长，所以通常我会删除这部分重置。但如果你经常使用这些元素，那就保留它：

```css
blockquote, q { 
    quotes: none; 
} 
blockquote:before, blockquote:after, 
q:before, q:after { 
    content: ''; 
    content: none; 
} 
```

接下来，我们重置了 2 个 `table` 属性：`border-collapse` 和 `border-spacing`：我从未深入研究过，但最终处理了一些微妙的表格不一致，你在任何现代桌面浏览器中都看不到。

```css
table { 
    border-collapse: collapse; 
    border-spacing: 0; 
} 
```

这基本上就是 CSS 重置的解剖。这个重置应该是你的 CSS 基础层的一部分，让你开始。我们现在将看看如何添加和自定义它。

# 自定义 CSS 重置

让我们更新`body`元素上的`line-height`和`font-family`属性，这将建立所谓的“垂直韵律”，并使`Arial`成为所有元素的默认`font-family`：

```css
body { 
    line-height: 1.4; 
    font-family: Arial, Helvetica, sans-serif; 
} 
```

然后你会看到它如何影响文本，主要是在文本的行之间添加一些垂直空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00045.jpeg)

为所有这些默认值尽早建立是很好的；这样，你就不必一遍又一遍地为 CSS 中的每个元素描述`line-height`和`font-family`。请注意，并非所有属性都像`font-family`和`line-height`那样被子元素继承；只有某些属性具有这种效果，主要是文本级别的属性才会表现出这种行为。在这种情况下，我们在`body`元素上设置了这些属性，但它们被级联到了`h1`、`h2`和我们的`p`，使它们都具有`Arial`的`font`和`line-height`为`1.4`。

我想在我们的重置中再添加几个规则集。让我们在重置的底部留出一些空间。我想要添加的第一个是`clearfix`，如下一段代码所示。我现在不打算详细介绍`clearfix`。我将在第三章中详细解释它，*使用浮动创建页面布局*。这个默认值对于清除浮动非常有帮助；我们将需要它：

```css
/* micro clear fix */ 
.grouping:before, 
.grouping:after { 
    content: " "; 
    display: table;  
} 
.grouping:after { 
    clear: both;  
} 
```

接下来我们要做的是为媒体元素设置`max-width`，以确保响应式媒体。我将在第六章中更详细地讨论这个问题，*成为响应式*：

```css
img, iframe, video, object { 
  max-width: 100%;  
} 
```

最后，我想取消对`strong`和`b`元素的重置，并确保它们确实具有`bold`的`font-weight`：

```css
strong, b { 
    font-weight: bold;  
} 
```

所以关于重置就是这样。现在，转到我们的 HTML，我想详细说明两个不在重置中的基础层的部分：

```css
<!doctype html> 
<html lang="en"> 
<head> 
    <meta charset="UTF-8"> 
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"> 

<!-- description --> 
    <title>Section 2-Ramping Up - Mastering CSS</title> 

<!-- stylesheets --> 
    <link rel="stylesheet" href="css/style.css"> 

<!-- stylesheets for older browsers -->       
    <!-- ie6/7 micro clearfix --> 
    <!--[if lte IE 7]> 
        <style> 
        .grouping { 
            *zoom: 1; 
        } 
        </style> 
    <![endif]--> 
    <!--[if IE]> 
        <script   src="img/html5.js"></script> 
    <![endif]--> 
</head> 
```

首先，我们有一个处理`IE 7`的`clearfix`，如下面的代码所示。你不需要知道这到底是在做什么，但你可能想知道它使`clearfix`在 IE7 中工作。如果你不支持较旧版本的 IE，你可以省略这部分。同样，我们将在第三章中详细讨论`clearfix`，*使用浮动创建页面布局*：

```css
<!-- stylesheets for older browsers -->       
    <!-- ie6/7 micro clearfix --> 
    <!--[if lte IE 7]> 
        <style> 
        .grouping { 
            *zoom: 1; 
        } 
        </style> 
    <![endif]--> 
    <!--[if IE]> 
        <script 
         src="img/
         html5.js"></script> 
    <![endif]--> 
```

如果我们放大这段代码，它恰好是一个嵌入样式表。你可以看到有一个开头和结尾的`style`标签，中间有一个规则集：

```css
<style> 
  .grouping { 
    *zoom: 1; 
  } 
</style> 
```

在嵌入样式表之外，紧接着开头的`style`标签的那一行是所谓的`IE`条件注释，它说：“如果低于或等于`IE 7`，请看下面的规则。”

```css
<!--[if lte IE 7]> 
```

在规则集下面，我们有一个指向 HTML5 Shiv 库的`script`，它使旧版本的 IE 能够理解更新的 HTML5 元素：

```css
<!--[if IE]> 
    <script 
     src="img/
     html5.js"></script> 
<![endif]--> 
```

这也是在 IE 条件注释中，但它是针对所有版本的 IE。实际上，IE 10 及更高版本不再支持 IE 条件注释，因此这个脚本只支持 IE9 及更低版本；然而，它确保我们的 HTML5 元素在较旧的浏览器中得到支持。同样，如果你不支持这些较旧的浏览器，也可以省略这部分。

在本节中，我们剖析了我们的 CSS 重置以及如何准备好基础层来编写代码。现在，让我们来看看*Chrome DevTools*部分。

# Chrome DevTools

到目前为止，我们所做的大部分 CSS 都相当简单。我们尝试的时候，所有的东西都能一次成功，但这并不总是发生。通常，CSS 不起作用，我总是在想我错过了什么。我的编辑器中的语法高亮虽然有帮助，但并不能阻止我忽略错误。通常，是一个小错误导致某些东西不起作用，很难找到错误并修复它。在本节中，我们将简单地看一下如何打开 DevTools。然后，我们将在检查器中修改一些 CSS，最后查看控制台以找到错误。

# 如何打开开发者工具

要打开 Chrome 的 DevTools，您只需右键单击或 *Ctrl* + 单击页面的任何部分。您将获得一个上下文菜单，如下截图所示。当您选择“检查元素”选项时，您将进入一个全新的技术世界：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00046.jpeg)

通常情况下，DevTools 会占据屏幕的下半部分。如下截图所示，左侧是浏览器渲染的 HTML，技术上称为 DOM。右侧是所有样式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00047.jpeg)

如果您在左侧悬停在某个元素上，它会在顶部突出显示。因此，如果您悬停在 `h2` 上或单击它，它会突出显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00048.jpeg)

如果您悬停在 `<section>` 上或单击它，它会在顶部突出显示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00049.jpeg)

# 更改检查器内的 CSS

在检查器的右侧，您将看到您在 DOM 中突出显示的任何元素的所有样式。您甚至可以单击其中任何属性或值并更改它们。因此，如果您单击 `font-size` 旁边的 `26px`，您可以将其增加到您想要的任何值。这将立即在浏览器中更新，非常酷：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00050.jpeg)

您甚至可以取消选中某些属性并立即看到更改。因此，如下截图所示，如果您在 DOM 中单击 `h2` 元素，然后在右侧取消颜色和下边距，这对 `h2` 元素的更改会立即生效。只需重新选中它们即可添加它们回来：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00051.jpeg)

如果您单击最后一个元素-在这种情况下是 `margin-bottom` 并按 *Tab*，它将允许您输入新的属性和值。因此，添加 `margin-left` 为 `-40px`，看看效果；这将将此 `h2` 向左移动 `40px`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00052.jpeg)

现在这些不是永久更改。一旦刷新浏览器，这些样式就会消失；但是，如果您想保留我们正在尝试的这些更改，可以复制此规则集并将其粘贴到您的代码中。它甚至告诉我们当前样式表中的此规则集位于样式表的第 86 行。如果您将鼠标悬停在那里，它将准确告诉您该文件在您网站文件夹中的位置：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00053.jpeg)

# 使用控制台查找错误

到目前为止，我们只是在探索 Chrome DevTools 的冰山一角。例如，有时添加图像可能会有些棘手。因此，让我们通过在 HTML 中输入以下图像标签来将其添加到页面上，放在 `h2` 上方：

```css
<img src="img/sharkey.png" alt="sharky"> 
```

如果我们保存并刷新网站，我们会发现图像根本没有显示出来，所以肯定有问题。刷新页面后，DevTools 中会出现一个带有数字一的红色错误图标。如下截图所示，这里有一个错误：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00054.jpeg)

要查看错误是什么，请单击“控制台”选项卡。您会看到 `sharkey.png` 文件找不到：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00055.jpeg)

这是很有用的信息。它告诉您这不是与权限相关的问题。这不是 403；它只是找不到它正在寻找的文件。因此，我会打开我的 `images` 文件夹，并确保图像在文件夹中，在这种情况下，我们假设它在那里。但是，唯一的问题是，它正在寻找的文件拼写不同：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00056.jpeg)

它正在寻找 `sharkey`，S-H-A-R-K-E-Y，而实际文件只是 S-H-A-R-K-Y，所以很容易修复。现在您知道问题出在哪里，只需在您的 HTML 中更改名称即可：

```css
<img src="img/sharky.png" alt="sharky"> 
```

如果您保存后刷新浏览器，此图像应该会显示出来：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00057.jpeg)

所以这两个东西，元素检查器和控制台，在实验和故障排除代码方面都非常有用。我的最大建议是，如果你的 HTML、CSS 和 JavaScript 不像你期望的那样工作，只需打开 DevTools，看看底层。很可能你会整天都打开 DevTools。我还要补充一点，Firefox、Safari 和 IE 都有类似任务的 DevTools，对于这些浏览器的故障排除同样有用。我们只是触及了开发者工具可以做的一小部分。查看我的博客文章，了解如何使用 Chrome DevTools 进行 HTML 和 CSS 故障排除的更多信息；网址是[www.richfinelli.com/troubleshooting-html-and-css](http://www.richfinelli.com/troubleshooting-html-and-css)。

它解释了如何创建新的选择器，以及如何访问计算值而不是声明的值，这在调试 CSS 规则和确定哪些规则优先级时非常有用。它还介绍了设备仿真模式等内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00058.jpeg)

现在你知道如何使用 Chrome DevTools，它是你故障排除 HTML 和 CSS 的王牌。接下来，你将学习如何重命名元素，这是 CSS 真正发挥作用的地方。

# 重命名元素——类和 ID

重命名元素是 CSS 的一个强大功能。让我为你设置一下。到目前为止，CSS 一直很好，因为我们能够保持一致。例如，所有的标题 1 都是蓝色，字体大小为 20 像素，但是如果你想让你的`h1`看起来不同呢？这就是重命名和分类元素真正有用的地方。在这一部分，你将学习如何根据类和 ID 重命名和样式化元素。我们将看看这将如何在我们的鲨鱼网站上得到回报，首先是类，然后是 ID。

# 类

看一下`index.html`文件。你会看到页面中有几个 HTML5 的`<section>`标签：一个在初始部分，一个在次要部分，一个在替代部分，总共有三个。其中一个如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00059.jpeg)

在第二个`<section>`中，有三个`div`标签，每个标签中都有一个`img`、`h2`、`p`和一个`a`标签。所以这个 HTML 并不复杂。最后一个部分看起来很像第一个部分；它只有`h1`和`h2`元素以及几个段落。然而，这里有个难题：我们希望页面底部的`h1`与网站的主`h1`元素不同。解决方法是添加一个类和基于这个类的样式。所以，在替代部分的`h1`元素内，我们将添加类属性。我们将输入`class=""`，并输入任何我们认为合适的名称或缩写：

```css
<h1 class="">Feeding Frenzy</h1> 
```

编程和计算机科学中最困难的工作是命名事物。这个名字应该有足够的意义，这样如果另一个人遇到你的代码并且想要接着你的工作，他们不会完全迷失。所以，在我们的例子中，我们将使用`alt-headline`。类是区分大小写的，所以我建议你使用小写，并用破折号分隔单词，这是 CSS 中常见的命名约定。如果你使用空格，它会被视为两个类，这并不是我们想要做的事情：

```css
<h1 class="alt-headline">Feeding Frenzy</h1> 
```

所以我们将保存我们的 HTML 并跳到我们的 CSS。

在`h1`下面，我们将添加我们的类名，前面加上一个句点作为选择器。输入`.alt-headline`并添加一个字体大小为 40px：

```css
h1 { 
  font-size: 70px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae; 
} 
.alt-headline { 
  font-size: 40px; 
} 
```

在保存之前，我们将把 CSS 窗口缩小，这样我们就可以在代码旁边看到我们的网站。滚动到你的网站上的`h1`，你会在左侧的预览中看到它当前是`70px`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00060.jpeg)

当你保存 CSS 时，`h1`变成了`40px`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00061.jpeg)

我把这个新的规则集放在原始的`h1`规则集下面，你可能会认为因为它是第二个，它会覆盖上面的那个。实际上并不是这里发生的事情。即使我把这个规则集移到`h1`上面，它仍然是`40px`。这是因为当作为选择器使用时，类比元素具有更大的权重：

```css
.alt-headline { 
  font-size: 40px; 
} 
h1 { 
  font-size: 70px; 
  line-height:1.4; 
  font-weight: bold; 
  color: #0072ae; 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00062.jpeg)

为了保险起见，让我们保留原始`h1`选择器下面的`alt-headline`规则集。

# 分类多个元素

类也用于对多个元素进行分类。如果你想要改变中间部分的`h2`标签，使其与页面其他地方的`h2`标签相似但不同，使用类将是完美的选择。让我们进入我们的 HTML，在`secondary-section`中的所有`div`标签中添加一个类，并称之为`column-title`。转到`The Octopus`，`The Crab`和`The Whale`标题，并使用 Sublime 的多光标浏览器功能为每个标题添加`class="column-title"`。例如，`The Octopus`标题应该是这样的：

```css
<h2 class="column-title">The Octopus</h2> 
```

然后，我们去到我们的 CSS，在`h2`下面添加`.column-title`。然后添加一些属性和值。添加`font-style`为`normal`；你想要去掉`italic`。我们的颜色是蓝色，`#0072ae`，我们将使`font-weight`为粗体：

```css
.column-title { 
  font-style: normal; 
  color: #0072ae; 
  font-weight: bold; 
} 
```

保存这个，转到浏览器，你会看到现在每个图像下面的`h2`标签与你在网站其他地方看到的`h2`标签不同：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00063.jpeg)

底部和顶部的`h2`标签仍然是红色的，而且是斜体的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00064.jpeg)

类可以非常有用，用于命名和分类你想要看起来相同的相同元素组。接下来，让我们使用 ID 重命名一个元素。

# ID

滚动到我们网站的顶部，在我们的 HTML 中，转到`h1`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00065.jpeg)

让我们给第一个`h1`标签一个特殊的 ID，叫做`main-site-title`：

```css
<h1 id="main-site-title">Old Chompy</h1> 
```

有了一个 ID，你也可以在引号内使用任何你想要的名称，只要它有意义。切换到 CSS，滚动到我们的`alt-headline`类的下面。这就是我们将添加`main-site-title`的地方。编写类和 ID 的主要区别在于，我们用句点开头的类和用数字符号或井号或井号（你想叫它什么都可以）开头的 ID：

```css
#main-site-title 
```

在这种情况下，我们可以说颜色是不同的：`深粉色`。保存并刷新网站以查看效果：

```css
#main-site-title{ 
  color: deeppink; 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00066.jpeg)

你可以看到这只改变了 Old Chompy 的`h1`，即具有 ID 的那个。

# 我们应该使用类还是 ID？

现在，你可能会想，类和 ID 之间有什么区别？嗯，首先要说的是，ID 的权重比类更大，确切地说是 10 倍。保持你的选择器轻量级是可扩展、可重用的 CSS 的关键之一。权重更大到底意味着什么？这意味着它更具体，ID 将覆盖任何类。我们将深入研究﻿第四章中的特异性规则和权重，*使用模块化、可重用的 CSS 类和 CSS3 创建按钮*。现在，只需知道当目标相同元素时，ID 将覆盖类。第二点是，ID 是唯一的，因此，它只能在页面上使用一次。鉴于这两点，主要是第一点，作为编码标准，我很少使用 ID 进行样式设置，因为类几乎总是足够的。

使用简单类重命名元素是如此强大，可能是 CSS 中最有用的东西。虽然命名类有时可能有点棘手，但重要的是要使名称语义化或有意义。例如，如果您正在命名您的博客文章容器，将其命名为"blog-post-container"是可以的，因为这完美地描述了它是什么。ID 虽然有其时机和地点，但并不像类那样有用。在大多数情况下最好只使用类来保持您的特异性低。在下一节中，您将学习如何使用后代选择器根据其上下文来定位元素。

# 后代选择器

如你在上一节中学到的，使用类重命名元素是 CSS 中非常强大的功能。然而，这并不是定位特定类型元素的唯一方法。后代选择器允许您基于其祖先元素来定位页面上的元素。这通常是必要的，因为您只想根据元素的上下文应用边距或新字体。您可以使用后代选择器来获取上下文，而无需每次都在每个元素上放置一个类。我将首先解释父元素、兄弟元素和子元素是什么，以及祖先和后代元素是什么。如果我们想要使用后代选择器，我们需要对这些清楚明了。接下来，我们将使用后代选择器的一个实际示例，并通过计算后代选择器的权重来结束。

# 父元素、子元素和兄弟元素

让我们去我们的 HTML，看看`secondary-section`中这个嵌套良好的 HTML 代码。所以基本上，我们这里有一个`section`标签和三个在该部分内部的`div`标签：

```css
<section>
  <div>
    <figure>
      <img src="img/octopus-icon.png" alt="Octopus">
    </figure>
    <h2 class="column-title">The Octopus</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Tenticals</a>
  </div>
  <div>
    <figure>
      <img src="img/crab-icon.png" alt="Crab">
    </figure>
    <h2 class="column-title">The Crab</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Crabby</a>
  </div>
  <div>
    <figure>
      <img src="img/whale-icon.png" alt="Whale">
    </figure>
    <h2 class="column-title">The Whale</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Stuart</a>
  </div>
</section>
```

所以`<div>`是`<section>`的子元素，而`<section>`是父元素。换句话说，`<div>`是`<section>`的后代，`<section>`是`<div>`的祖先。`<figure>`也是`<section>`的后代，`<img>`是`<section>`的后代。请注意，`<figure>`、`<h2>`和`<p>`在 HTML 中处于同一级别，因此它们是兄弟元素，它们也都是`<section>`的后代。这就是它的复杂程度；没有叔叔、没有阿姨，也没有远房表兄弟。

# 创建后代选择器

在上一节中，*重命名元素-类和 ID*，我们给所有`<h2>`添加了一个类，因为我们知道 HTML 中`secondary-section`的`<h2>`标签与所有其他`<h2>`标签不同。所以我们可能也想要将这个区域中的其他元素也设置为不同。这是我们可以做到最好的方式。不要在`<h2>`标签上放置类，而是在`section`标签上放置它，并从那里使用后代选择器。让我们去掉所有`<h2>`标签中的`class="column-title"`。在`section`元素上，让我们添加一个新的类，即`secondary-section`：

```css
<section class="secondary-section">
  <div>
    <figure>
      <img src="img/octopus-icon.png" alt="Octopus">
    </figure>
    <h2>The Octopus</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Tenticals</a>
  </div>
  <div>
    <figure>
      <img src="img/crab-icon.png" alt="Crab">
    </figure>
    <h2>The Crab</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Crabby</a>
  </div>
  <div>
    <figure>
      <img src="img/whale-icon.png" alt="Whale">
    </figure>
    <h2>The Whale</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Stuart</a>
  </div>
</section>
```

保存这个，您会看到`<h2>`标签失去了它们的蓝色粗体颜色，因为在 CSS 中，我们仍然在定位已经不存在的`.column-title`类：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00067.jpeg)

现在我要做的是进入 CSS，找到`.column-title`类，更新它：

```css
.secondary-section h2 {
  font-style: normal;
  color: #eb2428;
  margin-bottom: 10px;
}
```

这就是我们的后代选择器。如果我们保存并刷新，我们会看到它将那些`<h2>`标签改回我们想要的蓝色、粗体和非斜体的`font-style`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00068.jpeg)

所以下面 CSS 中显示的`.secondary-section`选择器是一个后代选择器。它定位了所有在`secondary-section`内部的`h2`：

```css
.secondary-section h2 { 
  font-style: normal; 
  color: #0072ae; 
  font-weight: bold; 
} 
```

如果我们回头看一下 HTML，您会看到`h2`确实在`secondary-section`中：

```css
<section class="secondary-section"> 
    <div> 
        <figure> 
            <img src="img/octopus-icon.png" alt="Octopus"> 
        </figure> 
        <h2>The Octopus</h2> 
```

现在我们可以更进一步。进入 CSS，在我们现有的`.secondary-section h2`规则集下面，键入`.secondary-section p`。这将定位我们`secondary-section`内部的段萌。添加一个深粉色的颜色，保存并刷新，您会看到现在所有的段落都是粉色的：

```css
.secondary-section p { 
  color: deeppink; 
} 
```

它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00069.jpeg)

我们也可以对我们的`image`标签进行同样的操作。如果您回顾一下 HTML，我们的`image`标签位于`div`标签内，而`div`标签位于`figure`标签内。

```css
<section class="secondary-section"> 
    <div> 
        <figure> 
            <img src="img/octopus-icon.png" alt="Octopus"> 
        </figure> 
```

切换回我们的 CSS，我们可以输入选择器`.secondary-section div figure img`，然后我们添加一个`10px`的实线边框，颜色为灰色：

```css
.secondary-section div figure img { 
  border: 10px solid #333; 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00070.jpeg)

虽然我们可以看到它起作用了，并且我们在网站上的图像周围有了灰色边框，但我们的选择器比我们需要的更具体。我们可以只输入`img`而不是`div`和`figure`，边框仍然会存在：

```css
.secondary-section img { 
   border: 10px solid #333; 
} 
```

使用这样一个非常长的选择器还有另一个问题。以下选择器的权重更大，可能会覆盖您不希望覆盖的其他样式：

```css
.secondary-section div figure img { 
   border: 10px solid #333; 
} 
```

这违反了保持代码轻量级的原则。特异性是我真的想要强调的东西；不要用非常长的选择器过度使用它。事实上，作为一个经验法则，尽量不要超过三级深；当然也有例外，但在编写 CSS 时要记住这一点。原因是计算 CSS 选择器的权重是一门确切的科学，我将在后面的章节中详细介绍。我至少想现在介绍一下，这样我们就可以开始熟悉它。

# 计算选择器的权重

一个类值为 10 分，所以`.secondary-section`值为 10 分。像`p`或`div`这样的普通元素值为 1 分。因此，`.secondary-section p`选择器值为 11 分。`.secondary-section div figure img`选择器值为 13 分。让我们在值为 13 分的选择器下面创建另一个选择器，我们有`.secondary-section img`。然后，让我们将`border-color`改为`blue`：

```css
.secondary-section div figure img { 
   border: 10px solid #333; 
} 
.secondary-section img { 
 border: 10px solid blue; 
}
```

当我们保存时，我们的边框将保持灰色，因为我们最后一个选择器的点数仅为 11；它被前一个选择器的 13 点的点数击败了。这就是这些较长的后代选择器的问题，它们的权重更重：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00071.jpeg)

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00072.jpeg)

ID 的点值为 100 分，这就是为什么我建议不要使用它们。它们有太多不必要的权重，使特异性水平飙升。分配点值听起来有点像在视频游戏中记分，但不同之处在于您希望尽量保持在这个游戏中的点值低。如果您这样做，您将能够编写更简单的 CSS。

# BEM

保持特异性低的一种技巧是完全避免使用后代选择器，而是使用*BEM*。BEM 代表*块元素修饰符*，是 CSS 的命名约定。其思想是使用特定的命名约定为您最终要样式化的每个元素添加一个类。这样，每个元素的特异性得分为 10，因此每个元素的特异性相同。除此之外还有很多内容，我建议您在[`getbem.com/`](http://getbem.com/)上了解更多。我倾向于使用 BEM 方法，但这并不意味着后代选择器完全需要避免。我认为它们有时机和地方。我的建议是保持您的后代选择器合理，并避免超过 3 级的较长后代选择器。

# 总结

在本章中，您了解了良好文本编辑器的特性，讨论了 CSS 重置，探索了 Chrome 的 DevTools 的故障排除功能，并学习了如何使用类重命名元素。在本章的最后一节中，您了解了后代选择器。

下一章是关于使用浮动创建多列层并了解浮动引起的问题的解决方案。


# 第三章：使用浮动创建页面布局

为了在所有浏览器中创建支持的多列布局，我们将使用浮动。浮动乍看起来非常简单，但对它们有一些不直观的怪癖，如果不完全理解可能会引起一些挫折。这可能是因为浮动的真正起源不是用于布局，而是为了实现文本围绕图像轻松流动的常见杂志技术。因此，在本章中，我们将深入研究浮动。我们将介绍浮动的基本用法，然后通过使用浮动创建布局（并在后续部分中解决浮动引起的头痛）

# 浮动介绍-围绕图像流动的文本

让我们从介绍浮动开始这一章。我们将讨论浮动的最初目的，然后是它们引起的基本问题以及如何清除浮动后面的元素。在本节中，我们还将开始制作一个关于鲨鱼电影的新 HTML 页面，您可以在书籍下载包中找到。

# 鲨鱼电影页面

这里有一个关于鲨鱼电影的新 HTML 页面。如果您查看此页面，您会看到一个图像位于标题的顶部，文本的顶部，并且链接的顶部；当您向下滚动时，您会看到每个电影都有三个类似的部分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00073.jpeg)

HTML 非常简单。有三个部分，每个部分都有一个`wrapper`类的`div`标记，用于居中内容。在`wrapper`类中，有一个包含图像的锚点标记。在锚点标记下面是一个包含标题和一些段落文本的`h1`标记。然后是一个锚点标记，这是一个链接以了解更多信息。以下是第一部分的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00074.jpeg)

# 浮动的最初目的

让我们看一下最终项目，如下图所示。我们希望将图像浮动到左侧，并使标题和文本围绕它流动：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00075.jpeg)

让我们在 CSS 中定位该图像。我们不是在选择器中定位图像，而是实际上定位图像的容器，即具有`figure`类的锚点标记：

```css
<a href="#" class="figure"> 
```

我不想只将`.figure`类作为我的选择器目标，因为我可能会在其他图像容器上使用这个类，并且可能不希望它们全部浮动。因此，让我们基于其父级使用后代选择器。其父级位于部分顶部，具有多个类：`content-block`，`style-1`和`wave-border`：

```css
<section id="jaws" class="content-block style-1 wave-border"> 
```

这是一种模块化的方法，我们将在下一节中更详细地介绍。我们正在寻找的主要类是`content-block`。`style-1`和`style-2`类只控制两种不同的颜色方案，`wave-border`添加了波浪的重复背景图像到第一部分的顶部。最后，在我们的 CSS 中，我们的选择器将是`.content-block .figure`，因此我们正在针对任何具有`content-block`类的元素中具有`figure`类的元素进行定位：

```css
.content-block .figure { 
  margin: 30px; 
} 
```

因此，在这个规则集下，我们将在`margin`属性下输入`float: left`：

```css
.content-block .figure { 
  margin: 30px; 
 float: left 
} 
```

当我们刷新页面时，我们看到一切都按计划进行。这几乎太简单了。我们在所有三个部分几乎完全实现了我们的目标：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00076.jpeg)

让我们在我们的 CSS 中为`h1`和`p`添加背景颜色，只是为了看看这里发生了什么。我们将为`h1`赋予`deeppink`的背景颜色，并通过`content-block`为`p`赋予`green`的背景颜色：

```css
.content-block h1 { 
  color: #fff; 
  background-color: deeppink; 
} 
.content-block p { 
  font-family: Georgia, 'Times New Roman' sans-serif; 
  background-color: green; 
} 
```

以下是前面代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00077.jpeg)

注意背景是如何在图像后面的。文本向右流动，但元素本身不再将浮动元素，即图像，视为正常流的一部分。当它们的显示属性受到影响时，浮动元素本身会发生变化。例如，浮动的锚点标签，或者真的是一个 class 为`figure`的锚点，开始像块级元素一样行事。它现在会响应宽度和上下边距；正如我们所见，它已经响应了下边距。然而，它不一定会强制换行。让我们将它向右浮动，它应该有一个非常相似的效果：

```css
.content-block .figure { 
  margin: 30px; 
  float: right; 
} 
```

以下是上述代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00078.jpeg)

# 使用 clear 属性解决浮动的基本问题

我们可以使用`clear`属性来阻止浮动元素下面的元素表现异常。例如，让我们给段落添加`clear`属性。我们将添加`clear: both`，它清除左右两侧的浮动元素：

```css
.content-block p { 
  font-family: Georgia, 'Times New Roman' sans-serif; 
  background-color: green; 
  clear: both; 
} 
```

现在，当您刷新时，您会看到段落文本坐在浮动元素下面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00079.jpeg)

我们也可以对`h1`做同样的事情，它会位于下面：

```css
.content-block .figure { 
  margin: 30px; 
  float: right; 
} 
.content-block h1 { 
  color: #fff; 
  background-color: deeppink; 
 clear: right; 
} 
```

我们也可以直接说`clear: right`，因为在它上面的浮动是向右浮动的。

保存 CSS 并查看网站后，您会看到它起作用了。`h1`标签也位于`.figure`下面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00080.jpeg)

然而，如果您在`h1`的规则集中输入`clear: left`，它不一定会起作用，因为这里没有左浮动的元素：

```css
.content-block h1 { 
  color: #fff; 
  background-color: deeppink; 
  clear: left; 
} 
```

以下是上述代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00081.jpeg)

在这里，`None`是`float`和`clear`的默认值。因此，我们可以在这两个上说`clear: none`，它将恢复到添加`clear`属性之前的状态：

```css
.content-block h1 { 
  color: #fff; 
  background-color: deeppink; 
  clear: none; 
} 
.content-block p { 
  font-family: Georgia, 'Times New Roman' sans-serif; 
  background-color: green; 
  clear: none; 
} 
```

以下是上述代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00082.jpeg)

然而，由于`clear: none`是默认值，您可以从这两个选择器中删除整个属性；这将对网站产生相同的影响。我几乎从不使用 clear left 和 clear right；`both`值似乎在大多数情况下都足够了。

在本节中，我们看到了浮动元素的传统用法，以及浮动元素下面的元素如何围绕浮动元素流动。这可以使用`clear`属性来停止。这种技术很有用，但老实说，浮动对于构建多列布局更有用。现在让我们来看看。

# 创建多列布局

浮动设计用于围绕图像流动文本。然而，浮动也是构建多列布局的最常见方式。在本节中，我们将看看如何将元素浮动到彼此旁边以创建页面布局。

所以，我们目前在 HTML 中次要部分有三个 class 为`column`的`div`标签：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00083.jpeg)

以下截图展示了最终的网站。这是我们的目标。我们希望有三个相等的列，之间有一个小的间距或边距：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00084.jpeg)

在我们当前的网站中，列是堆叠在彼此上面的。现在，我们有简单的行，所以我们想使用浮动来解决这个问题。在我们最终的网站中，我们希望将所有内容都居中在页面的中间，但现在，我们所有的内容都从浏览器窗口的一边到几乎是浏览器窗口的另一边：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00085.jpeg)

让我们通过居中我们的`div`标签来修复这个问题。

# 居中一个元素

我们真正需要做的是将整个内容包裹在一个`div`标签中；所以让我们这样做。进入 HTML 文件。在开放的`section`标签下一行，添加`<div class="wrapper">`。并在关闭的`section`标签之前，用`</div>`关闭它：

```css
<section class="secondary-section"> 
    <div class="wrapper">
        <div>...</div>
        <div>...</div>
        <div>...</div>
    </div> 
</section>
```

现在，切换到 CSS 文件。`.wrapper`标签将是一个更可重用的类。为了居中任何元素，我们会给它一个 margin，并且我们会使用两值语法：上和下将是零，左和右将是自动。我们还必须给它一个宽度为`960px`。没有宽度，你真的无法使用这种 margin 技术来居中它：

```css
.wrapper { 
  margin: 0 auto; 
  width: 960px; 
} 
```

好了，我们完成了；所有的内容现在应该都居中在这个包裹器内：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00086.jpeg)

就像我说的，`wrapper`类很好而且可重用。我会在网站的任何地方使用`wrapper`类来居中一组元素。

# 浮动列

所以，回到我们的业务顺序：在我们的主页上浮动这三列。为了做到这一点，我想给每个`div`标签一个`column`类，这样我们就可以对其进行样式设置。所以，在 HTML 中，让我们去到次要部分的每个`div`标签，并使用 Sublime Text 的多重光标功能一次性给它们都添加`class="column"`：

```css
<section class="secondary-section"> 
    <div class="wrapper">
        <div class="column">...</div>
        <div class="column">...</div>
        <div class="column">...</div>
    </div> 
</section>
```

在我的 CSS 中，我已经用一个大的注释标注了这部分 CSS，我鼓励你也这样做。

在这个注释下面，我们将针对`.column`并应用`float: left`。宽度将是`320px`。

```css
/**************** 
3 columns 
****************/ 
.column { 
  float: left; 
  width: 320px; 
} 
```

理想情况下，每当你浮动元素时，尝试添加一个宽度。如果所有三列都是`320px`，那将恰好加起来是 960 像素，正好适应那个包裹器的宽度。如果我们使用的数字加起来超过 960 像素，那么不是所有的三个`div`标签都会适应那个空间。其中一个会换行到底部，所以它们不会都在一行上。重要的是，所有浮动的`div`标签的宽度永远不要超过父`div`标签的宽度。所以保存这个并刷新网站：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00087.jpeg)

看起来所有三列都浮动在一起。这个效果还不错，只是列之间没有任何间距。所以让我们回到我们的代码，给它一个`margin-left`属性，值为`30px`。保存并刷新浏览器：

```css
.column { 
  float: left; 
  width: 320px; 
  margin-left: 30px; 
} 
```

以下是前面代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00088.jpeg)

我们得到了`30px`的边距，但我们的第三列也因为无法适应允许的宽度而漂移到了底部。

让我们通过将列的宽度减小到每个`300px`来修复这个问题：

```css
.column { 
  float: left; 
  width: 300px; 
  margin-left: 30px; 
} 
```

现在如果你看浏览器，你也会看到我们不需要在第一列上添加`margin-left`。我们不需要在空白处旁边添加左边距：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00089.jpeg)

让我们去掉第一列的左边距。我们可以通过使用一个叫做`first child`的伪类来定位那个单独的`.column`属性。

# 使用伪类定位`.column`

添加`.column:first-child`选择器将定位到列元素的第一次出现。我们将把`margin-left`添加为零。当我们保存这个时，我们得到了三个相等的列，每个都有一个`margin-left`，除了第一个：

```css
.column:first-child { 
  margin-left: 0; 
} 
```

以下是前面代码块的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00090.jpeg)

这种技术对于两列、四列或任意数量的列都同样适用。

# 折叠的容器

所以，列的一切都很好，除了如果你尝试向下滚动页面，你会发现我们离底部非常紧。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00091.jpeg)

让我们看看当我们为包裹所有内容的容器`secondary-section`添加`margin-bottom`属性时会发生什么：假设`margin-bottom: 40px`：

```css
/**************** 
3 columns 
****************/ 
.secondary-section { 
  margin-bottom: 40px; 
} 
```

如果我们保存这个，它在浏览器中实际上什么也没做。内容仍然紧贴着底部。让我进一步说明这个问题。如果我有一个绿色的背景颜色，那么你会期望整个背景都是绿色的：

```css
.secondary-section { 
  margin-bottom: 40px; 
  background-color: green; 
} 
```

然而，如果我们添加前面的代码并保存，背景颜色并没有变成绿色。所以，让我们实际检查一下这个元素。使用 Chrome 的 DevTools 在浏览器中检查`secondary-section`。我们会看到`margin-bottom`和`background-color`都在被应用的过程中。但我们在页面上看不到任何绿色的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00092.jpeg)

当您将鼠标悬停在`secondary-section`元素上时，您将看到它在屏幕上以桃红色突出显示的空间（如果您正在查看打印副本，则将以不同的灰色阴影显示）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00093.jpeg)

容器实际上已经坍塌了。当父元素内的所有元素都被浮动时，就会发生这种情况：容器坍塌，浮动被带出正常流，容器没有高度。

让我们看看我们能做些什么来解决这个问题。

# 解决浮动的问题

好的，让我们看看我们的问题。您已经学会了如何将堆叠的行转换为水平列，以实现多列布局，但是我们围绕浮动元素的包含元素已经完全坍塌并且失去了高度，因为它内部的所有元素都被浮动了。作为一个坍塌的元素，它看起来不像是响应`margin-bottom`属性或我们分配给它的`background-color`。因此，在本节中，我们将看看四种不同的方法来解决这个坍塌，并尝试理解处理它的最佳方法。首先，我们将使用`clear`方法，然后是`overflow: hidden`方法，然后是`float`方法，最后是最优选的方法：`clearfix` hack。

# 使用清除方法

让我们使用`clear`属性来解决这个问题。在`secondary-section`的末尾，我们将向一个新的`div`添加一个`clear`类，使用以下代码：

```css
<div class="clear"></div> 
```

接下来，我们将进入我们的 CSS，在全局样式保留区域，在针对`wrapper`类的规则集下面；这是我们将创建`clear`选择器并添加`clear: both`的地方：

```css
/***************
Global
***************/
::-moz-selection {
  background-color: #eb2428; 
}
::selection {
  background-color: #eb2428; 
}
.wrapper {
  margin: 0 auto;
  width: 960px;
}
.clear {
 clear: both;
}
```

因此，如果我们保存并返回到浏览器，我们的背景颜色将是绿色，底部间距为`50px`。一切都运行得很好：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00094.jpeg)

然而，我们在页面上添加了额外的非语义标记。我们甚至可能因此而受到 SEO 的扣分。让我们探索其他方法来做到这一点，而不添加额外的标记。去掉我们刚刚添加到 HTML 中的额外标记：

```css
<div class="clear"></div> <!-- delete this -->
```

我们的坍塌将返回。现在我们将无法再看到绿色的背景；这就是我们知道坍塌存在的方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00095.jpeg)

# 使用 overflow 属性和 hidden 值

我们将看看的下一种方法是`overflow: hidden`。转到您的 CSS 并找到`.secondary-section`类。我们可以做的是添加值为`hidden`的`overflow`属性：

```css
.secondary-section { 
  margin-bottom: 50px; 
  background-color: #7EEEAF; 
  overflow: hidden; 
} 
```

`overflow: hidden`是一个真正的 hack。它从来不是用来修复坍塌的容器的；它是用来隐藏任何溢出其容器的内容图像或文本的。然而，神奇的是，`overflow: hidden`也清除了坍塌。如果我们保存我们的 CSS 并转到我们的网站，我们将看到这一点，因为背景现在是绿色的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00096.jpeg)

`overflow: hidden`的一个小问题是，您可能希望内容溢出容器，例如下拉菜单或工具提示。`overflow: hidden` hack 将隐藏溢出内容 - 没有什么意外！这是一个解决方案，但并不总是理想的。例如，在我们确切的情况下，我们可能希望这只章鱼有点从容器中爬出来。让我们进入 Chrome DevTools 并给它`margin-top: -50px`。如您所见，现在图像的顶部不再显示，溢出被隐藏了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00097.jpeg)

所以这对我们来说不是一个好的解决方案。让我们从我们的 CSS 文件中删除`overflow: hidden`声明，并看看下一种方法：`float`方法。

# 浮动方法

我们可以通过将容器浮动到左侧或右侧来防止元素坍塌。让我们这样做；让我们向我们的`secondary-section`添加`float: left`或`float: right`。任何一个都可以：

```css
.secondary-section { 
  margin-bottom: 50px; 
  background-color: #7EEEAF; 
  float: left; 
} 
```

一旦我们保存了这个，我们会看到我们有绿色的背景，所以坍塌不再发生，但明显的问题是我们已经向左浮动了。我们希望这个 div 居中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00098.jpeg)

这种方法显然有一个明显的缺点。有些情况和一些情况下它可能是一个完美的解决方案，但在这种情况下，有一个明显的问题：我们不再居中。从你的 CSS 中删除`float: left`，并探索我的最喜欢，我认为最好的解决方案：**clearfix hack**。

# clearfix hack

如果我们看一下下面的 CSS，在我们的重置之后，这些规则集构成了我们的**clearfix**：

```css
/* clearfix */ 
.grouping:before, 
.grouping:after { 
  content: " "; 
  display: table;  
} 
.grouping:after { 
  clear: both; 
} 
```

这段代码实际上是我们 CSS 的基础层。基本上，这样做是在任何具有`grouping`类的元素之前和之后创建一个伪元素。这个伪元素有一个空白内容和显示设置为表。然后我们在代码块下面有`after`伪元素，它有`clear`属性设置，并清除它之前的任何浮动。

有时你可能会看到`clearfix`作为类名，而不是`grouping`。我倾向于使用`grouping`，因为我认为这更有意义；你在某种程度上在分组元素，这更有语义。不过这并不重要；`clearfix`和`grouping`都能做同样的事情。

好了，这已经在 CSS 中了，所以我们除了去 HTML 中的`secondary-section`，只需添加这个`grouping`类。所以我们给它添加了第二个类：

```css
<section class="secondary-section grouping"> 
```

当我们保存并刷新时，我们有了我们的容器；坍塌已经解决了。在下一张截图中，我们看到了背景颜色和底部边距。我们在这里的情况非常好：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00099.jpeg)

clearfix 在 IE8 中可以工作，但在 IE7 中不行，除非你添加一个 IE 特定的样式表。这实际上是放在索引中的。所以在`index.html`的头部，我有这个样式表，如下一张截图所示，专门为 IE7。它的作用是给 grouping 一个`1`的缩放。这会触发旧版本的 IE 中的`hasLayout`，从而清除坍塌：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00100.jpeg)

如果这对你来说没有太多意义，不要担心；它不一定要有。不过，知道这可以让 clearfix hack 在旧版本的 IE 中工作。总的来说，这是非常深的浏览器支持，而且非常容易使用，这是许多前端开发人员首选的清除坍塌浮动的方法。这绝对是我解决问题的最喜欢的方法。

在这一节中，你学会了使用以下方法来修复由浮动引起的父元素坍塌：

1.  一个空的清除 div。

1.  `overflow: hidden`。

1.  通过浮动父元素。这三种方法都有效，但都有轻微到严重的缺陷。

1.  具有非常深的支持、易于使用和语义化风格的 clearfix hack 往往是最佳方法。我在每个项目中都使用它。它可以轻松解决浮动的最大问题之一：坍塌。我喜欢 clearfix hack 的另一点是它是一种非常模块化的 CSS 方法。只需在你的标记中的任何地方添加`clearfix`类，你就可以摆脱坍塌的容器。

# 总结

在本章中，我们讨论了传统的浮动元素的使用：围绕图像流动文本。然后我们看了看使用浮动来构建多列布局。最后，我们学会了如何解决使用浮动时出现的问题。我们发现 clearfix hack 是修复浮动坍塌的最佳方法。在下一章中，我们将扩展模块化 CSS，使用模块化方法创建现代按钮。


# 第四章：使用模块化、可重用的 CSS 类和 CSS3 创建按钮

拥有模块化和可重用的 CSS 使其组织有序且简洁，从而避免出现让你抓狂的情况。如果能够在标记中的任何位置使用其类并且不需要这些类被父元素限定为后代选择器，那么 CSS 就是“可重用”的。术语“模块化”指的是通过向其添加另一个类来为按钮添加变化的能力，以便一个元素可以有两个类，这两个类可以组合在一起形成非常不同的东西。

一个很好的例子是如何编写模块化和可重用的 CSS：创建按钮。然而，这个概念应该应用到网站的所有组件中。在本章中，我们有很多内容要讨论。在前两节中，我们将介绍模块化 CSS 和多个类，然后我们将转变话题，讨论选择器如何在特异性规则部分互相覆盖。然后，我们将深入研究 CSS3 的过渡、变换和渐变，并逐步介绍创建和样式化一个大的呼吁行动按钮的每个步骤。

# 使用模块化 CSS 创建按钮

在这一部分，我们将创建具有模块化 CSS 类的按钮。我们将找出模块化 CSS 究竟是什么，以及为什么它很有用。首先，让我们看一下我们将要创建的最终网站，并探索我们将使用的不同按钮类型。

# 不同的按钮类型

在顶部，我们有一个巨大的“立即订阅”呼吁行动按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00101.jpeg)

在首页向下滚动一点，我们会发现这些带有漂亮悬停状态的“幽灵”按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00102.jpeg)

在电影页面上，我们有相同的标准按钮。它只是颜色不同，并且位置有点不同。这出现在所有三个电影部分中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00103.jpeg)

因此，在这一部分，我们将在所有三列的底部构建这些标准按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00104.jpeg)

# 构建标准按钮

我们的起点让我们走了很长一段路，但应该相当容易：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00105.jpeg)

让我们跳转到我们次要部分的 HTML 中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00106.jpeg)

我将在每个列底部的三个锚元素中添加`button`类。

```css
<a href="#" class="button">Tenticals &raquo;</a>
```

现在，跳到我们 CSS 的底部，让我们为我们的新部分添加一个巨大的注释，并命名为“按钮”。

```css
/****************
Buttons
****************/
```

这是我们所有按钮样式的地方。

我们要做的是创建`.button`选择器。所有共享的样式属性都将放在这里。我们不会在按钮选择器中放置任何定位属性，因为按钮可以放置在任何位置：

```css
/****************
Buttons
****************/
.button {
}
```

让我们从添加边框开始。我们将选择两像素实线和深灰色。我们将把相同的颜色应用于文本：

```css
.button {
   border: 2px solid #333;
   color: #333;
}
```

保存并刷新浏览器后，它开始略微类似按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00107.jpeg)

现在我们需要添加一些填充。让我们回到我们的 CSS，并使用两个值的填充快捷方式：`10px`用于顶部和底部，`0px`用于左右。这是因为我们最终会将文本居中。让我们还将显示属性更改为`block`，因为这些是内联元素，我们希望它们的行为像块级元素一样：

```css
.button{
   border: 2px solid #333;
   color: #333;
   padding: 10px 0;
 display: block;
}
```

保存这个，刷新浏览器，看看效果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00108.jpeg)

正如你所看到的，我们现在必须添加一些文本级属性。首先，让我们添加一个字体系列。我们将选择典型的`sans-serif`堆栈：`Arial, Helvetica, sans-serif`。然后，使用`text-align`属性将文本对齐到元素的中心。我们还将把`font-weight`设置为`bold`，然后使用另一个叫做`letter-spacing`的属性，并添加一个值`1.5px`。如果你不熟悉`letter-spacing`属性，它基本上就是你所想的——它在每个字母之间创建了水平空间：

```css
/****************
Buttons
****************/
.button{
  border: 2px solid #333;
  color: #333;
  padding: 10px 0;
  display: block;
  font-family: Arial, Helvetica, sans-serif;
  text-align: center;
 font-weight: bold;
 letter-spacing: 1.5px;
}
```

保存并刷新网站后，我们将拥有我们的按钮元素。目前还没有悬停状态；我们将在另一节中介绍：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00109.jpeg)

如果您现在转到电影页面，您将看到那里的“了解更多”链接，也需要成为按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00110.jpeg)

让我们跳到`shark-movies.html`文件中的标记，并做同样的事情。在每个电影部分底部的每个锚点标签中添加`button`类：

```css
<a href="" class="button">Learn More</a>
```

保存并刷新，您将立即得到一个按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00111.jpeg)

它有点起作用；我们有一个按钮，但不完全。它们看起来像按钮，但颜色不对，太宽，而且没有定位到右侧。此外，文本与背景的对比度不佳，特别是在较暗的部分。因此，我们需要做一些修复，因为这些按钮与主页上的按钮不同，主页上的按钮是全宽的。

让我们现在修复这些按钮，看看如何更加模块化，并添加多个类以变化按钮。

# 多个类

总结一下，到目前为止，您已经学会了如何创建一个可以在网页的任何地方重复使用的类，以创建一个按钮。然而，按钮在网站上往往会有所不同。例如，您可能会有像“确定”、“关闭”、“取消”、“提交”和“添加到购物车”等按钮。所有这些按钮都有不同的含义，因此它们的颜色或样式略有不同。在某些情况下，例如我们的电影和索引页面，按钮最终会因页面布局的差异而有所不同。在本节中，我们将变得更加模块化，并学习如何使用多个类来改变我们按钮的外观。我们将看一些多个类如何为我们提供一些便利，以便在整个网站上样式化我们的按钮。

以下截图展示了最终的网站。我们希望按钮看起来像“了解更多”按钮。它们向右浮动，是白色的，有白色边框，宽度更窄：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00112.jpeg)

目前我们的网站情况如下。我们的按钮是深灰色的，并且宽度全屏，但不符合我们的要求：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00113.jpeg)

# 更改按钮的宽度

首先，让我们通过创建一个名为`button-narrow`的新类来解决宽度问题。在我们的 CSS 中，在上一节创建的`.button`规则集下面，创建一个名为`.button-narrow`的新类。非常简单，宽度将是`25%`：

```css
/****************
Buttons
****************/
.button {
  border: 2px solid #333;
  color: #333;
  padding: 10px 0;
  display: block;
  font-family: Arial, Helvetica, sans-serif;
  text-align: center;
  font-weight: bold;
  letter-spacing: 1.5px;
}
.button-narrow {
 width: 25%;
}
```

保存这个。接下来，转到`shark-movies.html`文件。转到每个带有`button`类的三个锚点标签。我只会展示“了解更多”按钮的代码，但对于所有按钮，代码更改都是相同的：

```css
<a href="" class="button ">Learn More</a>
```

让我们将新的`button-narrow`类添加到这些元素中：

```css
<a href="" class="button button-narrow">Learn More</a>
```

保存后，转到浏览器，您会看到所有三个部分的按钮现在都变得更小了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00114.jpeg)

让我们再进一步，创建另一个名为`button-alt`的类，用于控制边框和字体颜色。

# 更改按钮的边框和字体颜色

让我们也将`button-alt`类添加到这 3 个“了解更多”按钮中。

```css
<a href="" class="button button-narrow button-alt">Learn More</a>
```

现在转到 CSS，并在我们的`.button-narrow`选择器下方输入`.button-alt`作为我们的新选择器。我选择`button-alt`作为类，因为这是另一种按钮颜色。然后，指定`color`为白色，`border-color`为白色：

```css
.button-alt {
  color: #fff;
  border-color: #fff;
}
```

保存后，转到网站，您会看到我们几乎到达目标了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00115.jpeg)

# 定位按钮

最后一件事是按钮的位置。它目前位于左侧，需要位于右侧。当然，我们可以创建一个名为`button-right`的类，将按钮浮动到右侧。然而，将元素浮动到左侧或右侧是非常常见的，甚至在按钮之外也是如此。最好将类名保持更通用，例如`float right`和`float left`。这样，我们可以将任何东西浮动到右侧或左侧。在我的情况下，在 CSS 的`Buttons`部分之前，我有我的全局样式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00116.jpeg)

在全局列表下面，我将复制我的标准模块化样式库：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00117.jpeg)

这是我多年来建立的基本样板的一部分，其中包括`float-left`、`float-right`、`clear`、`bold`、`hidden`和一些其他常见的模块化类。您可以在下载包中看到完整的列表。这些可以在整个网站中重复使用。现在，在`shark-movies.html`文件中，让我们简单地将`float-right`类添加到我们的三个锚标签中：

```css
<a href="" class="button button-narrow button-alt float-right">Learn More</a>
```

保存并刷新鲨鱼电影网站。您现在将看到按钮向右浮动：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00118.jpeg)

我还应该指出，我们每个部分周围的容器不会坍塌。让我们进入 DevTools 看看原因。以下截图中突出显示的具有`content-block`类的部分之所以没有坍塌，是因为我向其中添加了 clearfix `grouping`类：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00119.jpeg)

如果我将这个删除并从那一行中删除`grouping`，您将看到坍塌会发生。因为我们有这个`grouping`类，我们确保这个部分不会坍塌：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00120.jpeg)

因此，总之，我们遵循了一种非常模块化和可重用的方法来构建我们的按钮，并创建了一些可以用来改变按钮样式的模块化按钮相关类。我们还有其他方法可以做到这一点。我可以使用后代选择器来根据它们的父级样式化按钮。这样，content-block 内的所有按钮将始终向右浮动，并且是白色而不是深灰色。如果除了内容块之外的其他区域也提供了相同的替代按钮样式，这将是一个不错的选择。接下来，让我们谈谈为什么需要一种模块化、可重用和轻量级的 CSS 方法。我们将通过讨论特异性规则来做到这一点。

# 特异性规则

我们开始了解到，CSS 的模块化方法使我们能够将类作为 CSS 的小块，可以在网页的任何地方使用来为任何元素设置样式。这使得编写 CSS 非常方便。然而，这仅在 CSS 保持轻量级时才有效。正如您将在本节中了解到的，每个 CSS 选择器都可以在一个规模上进行衡量，最重的选择器将赢得两个竞争选择器之间的样式战。因此，我将首先解释不同选择器的权重以及它们如何相互推翻。然后，我们将稍微讨论一下通用选择器和`!important`声明如何适用于选择器的权重。

# 不同选择器的权重

所有选择器都被分配了一个权重，最重的选择器在存在冲突的 CSS 规则时优先。在构建网站时，通常会出现一种情况，即通用样式会在不同情况下被更具体的样式覆盖。在样式表顶部的全局区域中，为所有段落元素设置了一个非常广泛的样式：

```css
p {
  font-size: 16px;
  line-height: 1.6;
  margin-bottom: 20px;
}
```

字体大小为`16px`。有一个`line-height`属性为`1.6`和`margin-bottom`为`20px`。自然地，我可能想要在不同情况下覆盖`line-height`或`margin-bottom`。让我们尝试使用选择器`.content-block p`来覆盖它：

```css
p {
  font-size: 16px;
  line-height: 1.6;
  margin-bottom: 20px;
}
.content-block p {

}
```

这是一个后代选择器。现在让我们添加`line-height`为`1.8`和`margin-bottom`为`40px`：

```css
.content-block p {
 line-height: 1.8;
 margin-bottom: 40px
}
```

切换到网站上查看原始设置。这个后代选择器应该针对主文本区域中的任何内容或段落文本：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00121.jpeg)

当我们保存我们的 CSS 并刷新网站时，我们会得到更多的行高和底部边距，就像你在下面的截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00122.jpeg)

那么每个选择器的权重是多少呢？嗯，你可以认为内联样式值为 1000 分，ID 值为 100 分，类值为 10 分，元素值为 1 分。在我们一直在看的例子中，单个`p`元素选择器的值只有 1 分，而`.content-block p`，它是一个类和一个元素，值为 11 分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00123.jpeg)

这个分数系统决定了哪个选择器会获胜。在这种情况下，这两个选择器都是针对段落元素的；然而，因为`.content-block p`值为 11 分，它将击败它上面的规则集，因为作为元素选择器，它只值 1 分：

```css
p {
  font-size: 16px;
  line-height: 1.6;
  margin-bottom: 20px;
}
.content-block p {
  line-height: 1.8;
  margin-bottom: 40px
}
```

ID 的权重是 100 分，是类的 10 倍。在我们的`shark-movies.html`文件中，你可以看到《大白鲨》的第一部分有`jaws` ID：

```css
<section id="jaws" class="content-block style-1 wave-border grouping">
```

现在让我们切换回我们的样式表，并创建一个新的规则集，如下所示：

```css
#jaws p {
  line-height: 3;
}
```

当我们刷新浏览器时，你会看到`line-height`为`3`生效了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00124.jpeg)

我们使用的 ID 值为 101 分的选择器将覆盖具有类和元素值仅为 11 分的选择器，以及仅具有 1 分元素值的选择器。ID 的权重，在我的情况下意味着我倾向于在可以的情况下远离它们进行样式设置。ID 也比类更不灵活；它们在页面上只能使用一次。我真的尽量避免使用它们，因为它们不太可重用。

另一件要避免的事情是内联样式，我们可以认为它值 1000 分。内联样式将击败一切，包括具有 ID 的选择器。让我们再次定位段落来演示这一点。我们将直接进入`shark-movies.html`文件，并实际添加一个内联样式。在`jaws`部分的`h1`选择器下面，我们有我们的段落，所以让我们给它添加我们的内联样式。我们将输入`style="line-height: 1"`：

```css
<p style="line-height: 1">
```

当我们保存这个时，我们会返回到我们的网站并刷新浏览器。一旦我们这样做，我们会看到`line-height`使用了内联样式，因为它的权重更大。它比我们样式表中的所有其他选择器都要重：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00125.jpeg)

那么什么能击败内联样式呢？你还有一个王牌：`!important`声明。

# !important 声明

让我们看看`!important`声明是如何工作的。我们回到 CSS 中的这个元素选择器，它只是一个段落：

```css
p {
  font-size: 16px;
  line-height: 1.6;
  margin-bottom: 20px;
}
```

我们可以进入`line-height`值本身，然后在该行的末尾添加`!important`。行高将增加到`1.6`：

```css
p {
  font-size: 16px;
  line-height: 1.6 !important;
  margin-bottom: 20px;
}
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00126.jpeg)

让我们检查一下这个段落，确保它实际上使用了`!important`声明。正如你在 Chrome 的 DevTools 中看到的那样，值为 1 的内联样式被划掉了；我们可以看到值为 101 分的 ID 与一个元素也被划掉了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00127.jpeg)

如果我们再往下滚动一点，我们会看到我们的类加上被划掉的元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00128.jpeg)

再往下滚动一点，你会看到它确实是使用了带有`!important`声明的元素选择器的`line-height`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00129.jpeg)

添加`!important`声明实际上可以被认为值为 10,000 分，击败了所有类、ID 和内联样式的那个属性。就像你想远离内联样式和 ID 一样，你也想远离使用`!important`声明，除非你有一个非常好的理由。还有另一个选择器的权重小于 1 分：通用选择器。

# 通用选择器

通用选择器只是一个星号。它值为零，因此只有在没有其他选择器竞争时才起作用。在我们的 CSS 中去掉`!important`声明。在我们的其他规则集之上，让我们添加一个`*`作为选择器，并添加`font-size`为`9px`和`line-height`为`.5`：

```css
* {
  font-size: 9px;
  line-height: .5;
}
```

从技术上讲，这个星号应该应用于每个元素，除非定义了更具体的内容。任何东西都能打败`*`选择器。现在当您转到网站时，您会发现一旦去掉`!important`声明，您就会回到内联样式的`line-height`属性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00130.jpeg)

在 DevTools 中，我们可以看到通用选择器最终被划掉了。它没有应用于这段文字或实际上任何东西。它在页面上没有被应用太多：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00131.jpeg)

由于它的权重很少，很多时候你会看到通用选择器被用作原始重置。您可以将`margin: 0`和`padding: 0`的属性和值添加到通用选择器中，并将其放在样式表的顶部。这将真正将每个元素的边距和填充重置为零：

```css
* {
  margin: 0;
  padding: 0;
}
```

让我们重新审视一下显示不同选择器权重的图表。您已经学会了将`!important`视为价值 10000 分，通用选择器视为价值零分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00132.jpeg)

# 点系统的现实

但实际上，我描述的点系统并不完全真实。假设您有这样一个选择器，包括 11 个元素：`div div p p p p p p p p p { ... }`。使用我已经描述的系统，这值得 11 分。我已经描述了类选择器的值为 10 分。然而，长元素选择器永远不会打败一个单一的类：`.i-beat-any-number-of-elements`。因此从技术上讲，元素的值为 0,0,0,1，类的值为 0,0,1,0，ID 的值为 0,1,0,0，内联样式的值为 1,0,0,0。但是！停顿以强调。如果您创建了一个由超过 10 个元素组成的选择器，那么您将会有非常糟糕的体验。那将是一个非常糟糕的主意，我建议您尽量不要超过 3 或 4 个。因此，与其认为元素的值为 0,0,0,1，类的值为 0,0,1,0，我们可以根据我之前描述的术语来思考，其中类的值为 10 分，元素的值为 1 分，依此类推。

另外，重要的是要记住，以任何合理的规模编写 CSS 都更容易，因为您可以轻松地创建模块化的可重用类，形式为按钮。创建现代网站的一个重要部分是在必要时覆盖样式；您不希望这变得困难。我强烈建议您坚持使用类和元素选择器，并且在使用`!important`声明时要非常保守；完全避免内联样式和 ID。

# 过渡

了解 CSS 的特异性以及选择器如何相互覆盖可以在使用 CSS 时减轻很多挫折感。现在我们对此有了更好的理解，让我们回到我们的项目，完成我们一直在工作的按钮的样式。按钮如果没有流畅的悬停状态和平滑的过渡就是不完整的。我们将通过使用伪选择器`:hover`来开始本节。然后，我们将通过过渡使其平滑，最后讨论供应商前缀何时是必要的。

# 创建悬停状态

目前，我们网站上的按钮是幽灵按钮。它们没有背景颜色，有深灰色边框或深灰色文本，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00133.jpeg)

我们想要创建一个按钮，当悬停时，它将具有深灰色背景颜色，并显示白色文本。因此，让我们使用`:hover`伪类来实现这一点。在第一个现有的`.button`规则集下，添加一个名为`.button:hover`的新选择器。添加`background-color: #333`，并将文本颜色设置为白色：

```css
/****************
Buttons
****************/
.button {
 border: 2px solid #333;
 color: #333;
 padding: 10px 0;
 display: block;
 font-family: Arial, Helvetica, sans-serif;
 text-align: center;
 font-weight: bold;
 letter-spacing: 1.5px;
}
.button:hover {
 background-color: #333;
 color: #fff;
}
```

注意我没有使用十六进制代码的全部六个字符。如果所有六个字符都相同，只使用三个字符也是可以的。现在如果我们保存并刷新，当我们将鼠标悬停在按钮上时，我们将有悬停状态：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00134.jpeg)

然而，悬停状态的过渡非常突然；它立即发生。因此，下一步是使用 CSS3 过渡属性来平滑地从无悬停到悬停的状态变化。

# 使用过渡属性

我们可以选择要过渡的属性、过渡的持续时间和过渡的时间函数。所有三个属性都可以分别列出为`transition-property`、`transition-duration`和`transition-timing-function`；然而，使用简写似乎是最简单的方法。因此，我们将在`.button`规则集中输入`transition`作为一个新属性，并使用`.25s`，或四分之一秒。我们将指定要过渡的所有属性。我们将使用`linear`时间函数：

```css
.button {
  border: 2px solid #333;
  color: #333;
  padding: 10px 0;
  display: block;
  text-align: center;
  font-weight: bold;
  letter-spacing: 1.5px;
  font-family: Arial, Helvetica, sans-serif;
  transition: .25s all linear;
}
```

现在当我们在浏览器中查看时，当你将鼠标移到每个按钮上时，变化会更加渐进：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00135.jpeg)

从深灰色过渡到白色文本以及背景颜色和边框需要 0.25 秒。四分之一秒似乎刚刚好，但你可以尝试更快或更慢的过渡。你可以将其更改为十分之一秒，那也很好，非常快，几乎立即。你可以将其更改为一秒，那将慢十倍，可能太慢了。我发现 0.2 到 0.3 秒似乎是过渡的“金发女孩区”。

在`0.25s`之后我们添加的下一个值是`all`：

```css
transition: .25s all linear;
```

这可以设置为你想要过渡的某个属性，或者所有属性。因此，如果你愿意，你可以将其设置为`color`：

```css
transition: .25s color linear;
```

只有文本颜色会过渡。如果你尝试这样做，你会看到按钮的深灰色背景立即过渡，但文本颜色会在 0.25 秒内过渡：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00136.jpeg)

如果我们愿意，我们可以添加一个逗号分隔的属性列表进行过渡。在这种情况下，我正在过渡`color`和`background-color`。这样做的一个原因是，如果你需要过渡多个属性，但不是每个属性。

```css
 transition: .25s color linear, .25s background-color linear;
```

因此，背景颜色和文本颜色将以相同的速度过渡。我们使用`all`关键字更有效地实现了这一点，以过渡文本颜色和背景颜色。然而，在某些情况下，保持属性的过渡速度与其他属性不同可能是有用的。让我们将`background-color`的过渡时间函数更改为 1.25 秒：

```css
transition: .25s color linear, 1.25s background-color linear;
```

现在，文本颜色的过渡速度将比背景颜色的过渡速度更快。在我们目前的情况下，这并不是特别有用，所以让我们改回到之前的方式：

```css
 transition: .25s all linear;
```

在我们的情况下，时间函数设置为`linear`。我们还可以使用`ease`、`ease-in`、`ease-out`和`ease-in-out`：

```css
transition: .25s all ease-in-out;
```

对于我们正在使用的短过渡，线性方法或默认方法都可以正常工作；任何一种都可以正常工作。在这种非常快的过渡中，实际上很难区分`ease`、`ease-in`、`ease-in-out`和`linear`之间的区别。我建议尝试每一种方法，以确定哪一种最适合你的需求。你可能需要改变过渡的持续时间才能清楚地看到效果。

好的，所以当悬停时，过渡为我们的按钮添加了一个很好的体验层。我们还可以过渡活动和焦点状态。焦点是当用户使用*Tab*键而不是将鼠标指针悬停在按钮上时，按钮的状态。我喜欢使所有悬停状态与焦点状态相同。这很容易通过添加逗号来添加选择器来实现。所以就像我们有`.button:hover`一样，我们可以做`.button:focus`：

```css
.button:focus,
.button:hover {
  background-color: #333;
  color: #fff;
}
```

如果您添加这个，焦点状态也会被触发。当您按*Tab*键和*Shift* + *Tab*键从一个按钮移动到另一个按钮时，它们的悬停状态也将是它们的焦点状态。出于可访问性原因，这是很好的。

# 供应商前缀

如前所述，过渡是 CSS3 的一个属性。所有现代（主要）浏览器都支持它们：Chrome、Firefox、Safari、Internet Explorer 和 Edge。旧版浏览器，如 IE9 及以下版本，不支持它们。它们仍然会得到悬停状态，但没有任何过渡，会显得突兀。这并不是一个问题，因为过渡通常不是您网站的核心功能，而更多的是一个附加的体验层。不过，它们是 CSS3，我们可以通过包括供应商前缀版本来更多地利用它们。传统上，`-webkit-`前缀用于 Safari 和 Chrome；`-moz-`用于 Firefox 和`-o-`用于 Opera。然而，Firefox 和 Opera 现在也使用`-webkit-`，所以从技术上讲，您不需要`-moz-`和`-o-`，就像您以前需要它们一样；然而，对于这些浏览器的旧版本，您仍然可以包括它们：

```css
-webkit-transition: .25s all ease-in-out;
-moz-transition: .25s all ease-in-out;
-o-transition: .25s all ease-in-out;
transition: .25s all ease-in-out;
```

或者您可以通过一半的 CSS，仍然让 99%的用户看到您的过渡效果，只需使用`-webkit-`供应商前缀：

```css
-webkit-transition: .25s all ease-in-out;
transition: .25s all ease-in-out;
```

过渡是 CSS3 的一个很棒的特性，它为用户体验增加了一个额外的层次。到目前为止，我们已经为我们的按钮创建了一个悬停状态，并使用过渡效果来平滑状态变化。然后，我们添加了供应商前缀以支持旧版浏览器。接下来，我们将看看 CSS3 的另一个特性：变换。

# 变换

与过渡一样，变换是 CSS3 的一个特性。不过它们得到了更多的支持，因为所有主要的浏览器，包括 IE9 及以上版本，都提供了支持。变换允许您做一些事情，包括旋转、缩放和平移。在本节中，我们将看一些实际的例子。首先，我们将为我们的按钮应用一个比例，然后我们将进行平移，然后是对旋转值的独特使用。

# 将比例应用到我们的按钮

让我们从我们在 CSS 中留下的按钮继续下去。在过渡下面，让我们添加一个 transform。我们将添加`transform: scale(.9, .9)`，就像这样：

```css
-o-transition: .25s all ease-in-out;
transition: .25s all ease-in-out;
transform: scale(.9,.9);
```

请注意，通过使用`.9`作为宽度和高度的值，我们实际上使我们的按钮变小了，原始尺寸的九分之一：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00137.jpeg)

让我们再次将`scale`属性添加到按钮的悬停/焦点状态，以获得更整洁的交互：

```css
.button:focus,
.button:hover {
  background-color: #333;
  color: #fff;
  transform: scale(1.1, 1.1);
}
```

比例值是一个 css 函数，分别采用宽度和高度。1.1 表示原始尺寸的 1.1 倍。

当您保存并刷新时，您会看到当您悬停在按钮上时，按钮实际上会变得更大。这是一个很好的平滑过渡，因为我们已经应用了过渡属性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00138.jpeg)

# 使用 translate 函数

让我们再进一步，也使用`translate`函数。这将添加到与我们刚刚编写的`transform: scale`代码相同的行或声明中。`translate`函数可以将元素移动到左侧、右侧、顶部或底部。正如您在下一行代码中所看到的，第一个值是左右移动的值。但我们不打算将其向左或向右移动，所以我们将使用`0`。第二个值是上下移动的值。我实际上会将其向上推`-5px`。如果我使用正值，那将会将其向下推：

```css
transform: scale(1.1,1.1) translate(0, -5px);
```

现在当我们刷新并悬停在按钮上时，我们会看到它确实稍微向上移动了，确切地说是五个像素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00139.jpeg)

请注意，我用一个空格分隔了两个函数。这里的语法非常重要：

```css
transform: scale(1.1,1.1) translate(0, -5px);
```

你可能会自然地在这里添加一个逗号，但如果我实际上在两个函数`scale`和`translate`之间添加逗号，我们将得不到任何关于`transform`的交互，因为这个语法是不正确的：

```css
transform: scale(1.1,1.1), translate(0, -5px); /* don't use a comma to separate transforms :-( */
```

# 使用旋转值

还有另一个变换函数，我想介绍一下，但如果我们给这些按钮添加更多的装饰，它们将会分散注意力。相反，让我们在电影页面上的电影图像上添加一个非常有趣的悬停效果。每个电影标题旁边的图像实际上是指向电影的外部链接：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00140.jpeg)

然而，我希望在悬停时发生视觉交互，这真的表明这是一个超链接，或者至少让用户知道有一些可以执行的操作。让我们使用`transform: rotate()`来实现这一点。

这是我们在最终网站中的目标。一个白色框架，里面有一张图像，悬停效果是在这个白色框架内旋转：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00141.jpeg)

正如你在下图中所看到的，当你悬停在图像上时，图像会旋转并略微放大——即使图像放大了，它也不会溢出其父容器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00142.jpeg)

我们需要有一个元素来包裹我们的图像，以实现这一点。我们确实有这个——一个带有`figure`类的锚标签，它是每个图像的父元素。这就是我们将添加这个厚厚的白色边框的地方。我们需要在`a`标签中添加`overflow: hidden`，因为当我们对图像进行缩放和旋转时，溢出隐藏可以防止它从容器中弹出。

让我们开始工作。`.content-block .figure`选择器已经存在，所以让我们首先给它添加白色边框。我会稍后再添加`overflow: hidden`。首先，让我们将`border`属性设置为`10px`，`solid`和`white`：

```css
.content-block .figure {
  float: left;
  margin: 30px;
  border: 10px solid #fff;
}
```

在我们刷新当前网站之前，它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00140.jpeg)

当我们刷新浏览器时，我们得到了白色边框：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00143.jpeg)

正如你所看到的，我们得到了图像底部和边框之间的间隙。我们可以通过两种方式来纠正这个问题。我们可以设置容器的高度与图像的高度完全一致；我们可以使用`height`属性来实现这一点，但这并不是最好的解决方案。或者，我们可以将图像浮动到左侧。为此，我们可以使用`float`属性，因为这是足够简单和更强大的解决方案。但是，我们要针对的是`.content-block .figure`内部的图像本身。所以让我们这样做，并将其浮动到左侧。

```css
.content-block .figure img {
  float: left;
}
```

现在刷新浏览器，我们将看到这样可以消除图像和边框之间的间隙：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00144.jpeg)

我们还将在图像上添加`rotate`和`scale`。`rotate`函数与`scale`和`transition`有些不同，因为它在函数内部不需要两个参数。它只需要一个：你想要旋转的角度。在我们的例子中，这是`15deg`。所以我们将创建一个新的选择器，用于悬停在图像上：

```css
.content-block .figure img {
  float: left;
}
.content-block .figure img:hover {
 transform: rotate(15deg);
}
```

接下来，在水平方向和垂直方向分别添加缩放：`1.25`，记住*不要*在两个函数之间添加逗号。这是这个代码：

```css
.content-block .figure img {
  float: left;
}
.content-block .figure img:hover {
  transform: rotate(15deg) scale(1.25, 1.25);
}
```

保存所有这些，转到网站，现在当你悬停时，图像会立即从容器中弹出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00145.jpeg)

让我们在`parent .figure`选择器中添加`overflow:hidden`。这正是`overflow:hidden`的用途：

```css
.content-block .figure {
  float: left;
  margin: 30px;
  border: 10px solid #fff;
  overflow: hidden;
}
.content-block .figure img {
  float: left;
}
.content-block .figure img:hover {
  transform: rotate(15deg) scale(1.25, 1.25);
}
```

当我们现在去网站，我们看到它工作正常。我们得到了旋转，我们得到了稍微放大并且更加包含在其容器内而没有溢出的缩放：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00146.jpeg)

然而，从默认状态到悬停状态的变化仍然太突然了。让我们添加一个`transition`属性，以使其更加平滑。我们希望将过渡效果添加到图像的非悬停状态。让我们添加一个四分之一秒的过渡效果：

```css
.content-block .figure img {
  float: left;
  transition: .25s all ease-in-out;
}
```

现在我们从默认状态平稳过渡到悬停状态：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00142.jpeg)

# 添加供应商前缀和:focus 状态

我们要做的最后一件事是为我们的`transform`和`transition`属性添加供应商前缀。就像过渡一样，我将添加声明的`-webkit-`前缀版本，以支持较旧版本的 Chrome、Safari、Firefox 和 Opera。而且我还将添加`-ms-`前缀版本，以支持 Internet Explorer 9。

```css
.content-block .figure img {
  float: left;
  -webkit-transition: .25s all ease-in-out;
  transition: .25s all ease-in-out;
}
.content-block .figure img:hover {
 -webkit-transform: rotate(15deg) scale(1.25, 1.25);
 -ms-transform: rotate(15deg) scale(1.25, 1.25);
  transform: rotate(15deg) scale(1.25, 1.25);
}
```

也许值得强调的是，使用`transform`属性时，我添加了`-ms-`供应商前缀。碰巧 IE9 将支持变换，如果您为其提供`-ms-`前缀：

```css
-ms-transform: rotate(15deg) scale(1.25, 1.25);
```

但是，我没有使用过渡来做这个，因为添加`-ms-`供应商前缀不会有任何区别，因为 IE9 根本就不支持过渡。

让我们也添加`:focus`状态，以使其更具网络可访问性：

```css
.content-block .figure img {
  float: left;
  -webkit-transition: .25s all ease-in-out;
  transition: .25s all ease-in-out;
}
.content-block .figure img:hover,
.content-block .figure img:focus {
  -webkit-transform: rotate(15deg) scale(1.25, 1.25);
  -ms-transform: rotate(15deg) scale(1.25, 1.25);
  transform: rotate(15deg) scale(1.25, 1.25);
}
```

好的，这就结束了我们对过渡和变换的简要介绍。通过添加不同类型的变换以及过渡来平滑转换，我们将我们的体验层提升到了另一个水平。还有其他可用的变换，我们没有介绍，比如`skew`、`translate x`、`translate y`、`scale x`、`scale y`等。还有真正将其提升到另一个水平的 3D 变换，这绝对值得探索，因为浏览器支持已经变得更好了。接下来，我们将继续通过为站点上的主要呼吁行动按钮进行样式设置来继续我们的样式培训。

# 设计呼吁行动的按钮

在这一章中，我们在样式化按钮方面取得了长足的进步。现在是时候再添加一个了。在最终站点中，我们还有一个需要构建的主页呼吁行动按钮。在本节中，让我们逐步介绍样式化呼吁行动按钮的每个步骤。首先，我们将添加 HTML，然后正确定位它并添加适当的 CSS；最后，我们将为其添加一个漂亮的悬停效果。

这是我们当前的站点：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00147.jpeg)

以下是我们的最终目标站点，我们将创建 Go Premium 呼吁行动按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00148.jpeg)

# 添加 HTML

让我们将标记添加到我们的`index.html`文件中。在`Intro Section`中使用一个按钮的锚标记，文本为`Go Premium`：

```css
<!-- 
===============
Intro Section
===============
-->
<section>
  <div class="wrapper">
    <h1>Old Chompy</h1>
    <h2>Dedicated to sharks and other aquatic species</h2>
    <p>Lorem ipsum dolor ...</p>
    <a href="#">Go Premium</a>
  </div><!-- end wrapper -->
</section><!-- end section -->
```

在此下方，添加一个`p`标记，其中列出了您需要尽快单击的原因，即将成为巨大的呼吁行动按钮。这个段落标记也将有一个锚点，以了解有关我们虚构的高级产品的更多信息：

```css
<!-- 
===============
Intro Section
===============
-->
<section>
  <div class="wrapper">
    <h1>Old Chompy</h1>
    <h2>Dedicated to sharks and other aquatic species</h2>
    <p>Lorem ipsum dolor ...</p>
    <a href="#">Go Premium</a>    <p>So many awesome features when you go premium. <a href="#">Learn more &raquo;</a></p>
  </div><!-- end wrapper -->
</section><!-- end section -->
```

现在我们真的在这个顶部部分创建了一个两列布局。我们需要将内容的左侧块浮动到左侧，将内容的高级部分浮动到右侧。这样做的最佳方法是将两者都包装在一个具有唯一类名的`div`标记中，为每个添加宽度，并将它们都浮动。所以首先添加标记：

```css
<section>
    <div class="wrapper">
 <div class="intro-content">
            <h1>Old Chompy</h1>
            <h2>Dedicated to sharks and other aquatic species</h2>
            <p>Lorem ipsum dolor ...</p>
 </div><!-- end of intro-content -->
 <div class="go-premium">
            <a href="#">Go Premium</a>
            <p>So many awesome features when you go premium. <a href="#">Learn more &raquo;</a></p>
 </div><!-- end of go-premium -->
    </div><!-- end wrapper -->
</section><!-- end section -->
```

当我们应用这个并查看我们的网站时，我们看到呼吁行动的按钮位于我们期望的位置，直接在介绍内容下面，因为我们还没有添加特定于布局的 CSS：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00149.jpeg)

让我们深入研究 CSS 并进行更改。

# 使用 CSS 定位

在这里对于我们来说，定位应该不是什么新鲜事。只需在我们的 CSS 中创建一个`Go Premium`部分，其中包含以下规则集：

```css
/****************
Go Premium
****************/
.intro-content {
  width: 360px;
  margin-right: 60px;
  float: left;
}
.go-premium {
  width: 300px;
  float: left;
}
```

我们的`.intro-content`和`.go-premium`区域都有定义的固定宽度。我们还应该在介绍内容上添加`margin-right`，以在两者之间添加一些空间。它们都向左浮动。所以这段代码真正实现的是这样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00150.jpeg)

我们在左侧获取我们的介绍性内容，右侧是我们的`Go Premium`内容。然而，我们在这里有一些问题。高级内容在页面上太高了，然后在下面，我们的内容侵入并流向介绍内容的右侧。这就是我们面临的浮动不清除的问题。

顶部边距应该解决我们的第一个问题，所以在`.go-premium`选择器中添加`margin-top`为`125px`：

```css
.go-premium {
  width: 360px;
  float: left;
  margin-top: 125px;
}
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00151.jpeg)

我们的第二个问题是内容实际上围绕浮动元素流动，并且在我们的 Go Premium 按钮上方有点侵入。我们可以在包裹整个顶部部分的容器上使用清除浮动 hack 类来解决这个问题。查看我们`index.html`文件中的介绍部分。整个顶部部分，包括介绍内容和 go premium，都包裹在一个包装器内：

```css
<section>
    <div class="wrapper">
        <div class="intro-content">
            <h1>Old Chompy</h1>
            <h2>Dedicated to sharks and other aquatic species</h2>
            <p>Lorem ipsum dolor ...</p>
        </div><!-- intro-content -->
        <div class="go-premium">
            <a href="#">Go Premium</a>
            <p>So many awesome features when you go premium. <a     
            href="#">Learn more   
            &raquo;</a></p>
        </div><!-- end of go-premium -->
    </div><!-- end wrapper -->
</section><!-- end section -->
```

让我们在这个包装器中添加清除浮动的 hack，使用我们的`grouping`类，这将解决我们网站上的问题：

```css
<div class="wrapper grouping">
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00152.jpeg)

# 按钮样式

让我们继续样式化按钮。为了样式化目的，让我们给我们的 go premium 锚点添加一个`call-to-action`类：

```css
<a class="call-to-action" href="#">Go Premium</a>
```

快速查看最终网站，这就是我们在 Go Premium 按钮上的目标。有一个白色边框，白色文本，蓝色渐变，并且周围有足够的填充：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00153.jpeg)

悬停状态去除了渐变，并将文本颜色和边框颜色更改为蓝色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00154.jpeg)

请注意，我们将无法使用上面图片中的确切网络字体。我们暂时将使用纯蓝色背景代替渐变，因为我们将在下一节回到它，并在本书的后面再次添加渐变和字体。

在 CSS 中，在`.go-premium`规则集下面，添加一个`.call-to-action`选择器和一个 2 像素的白色实线边框。我们还将使文本颜色为白色，背景颜色为蓝色。在顶部和底部添加`25px`的填充，左右位置为零，因为我们最终会将文本居中：

```css
/****************
Go Premium
****************/
.intro-content {
  width: 360px;
  margin-right: 60px;
  float: left;
}
.go-premium {
  width: 300px;
  float: left;
}
.call-to-action {
 border: 2px solid #fff;
 color: #fff;
 background-color: #0072ae;
 padding: 25px 0;
}
```

现在我们的按钮看起来有点奇怪，因为锚点是内联元素，它的填充没有向下推挤下面的文本。这就是内联元素的工作方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00155.jpeg)

最简单的解决方法是将显示更改为`block`：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  background-color: #0072ae;
  padding: 25px 0;
  display: block;
}
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00156.jpeg)

我们需要将文本对齐到中心并添加圆角。像这样添加：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  background-color: #0072ae;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
}
```

我们不再需要为边框半径添加供应商前缀，因为这个 CSS3 属性规范比变换和过渡属性更成熟。刷新浏览器，你会看到我们的按钮开始变得非常漂亮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00157.jpeg)

现在我们可以增加字体大小和字重：

```css
font-size: 22px;
font-weight: bold;
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00158.jpeg)

我们的按钮看起来很棒。让我们添加悬停样式。在 CSS 中添加`:hover`和`:focus`选择器。我们需要将边框和文本的颜色从白色更改为蓝色；`border-color`会处理这个问题。使用关键字`none`的`background`属性将去除背景颜色：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  background-color: #0072ae;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
}
.call-to-action:hover,
.call-to-action:focus {
 border-color: #0072ae; 
 color: #0072ae; 
 background: none;
}
```

如果我们现在转到我们的网站，并悬停或聚焦在我们的按钮上，我们将看到呼吁行动按钮的不同处理方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00159.jpeg)

最后，让我们添加一个过渡效果，使状态变化更加微妙。在我们的 CSS 中，为按钮的非悬停状态添加`transition: all .25s ease-in-out`和供应商前缀：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  background-color: #0072ae;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
  font-size: 22px;
  font-weight: bold;
  -webkit-transition: all .25s ease-in-out;
 transition: all .25s ease-in-out;
}
```

添加了过渡效果后，我们有了一个完全样式的呼吁行动按钮（减去正确的网络字体和渐变）。

我们现在已经定位了我们的呼吁行动区域，并将按钮本身样式化得非常棒。接下来，让我们完成呼吁行动按钮，并学习更多关于 CSS 渐变的知识。

# 渐变

我们的大呼吁行动按钮几乎完成了。我们只需要添加一个渐变，就像变换、过渡和边框半径一样，这是 CSS3 中的一个特性。

# 使用终极 CSS 渐变生成器

由于渐变规范和语法有些冗长，并且在各个浏览器之间不一致，使用它的最简单方法是通过一个可以为我们创建 CSS 输出的应用程序。通常，我会避开诸如此类的东西，因为我更喜欢编写自己的代码，但是我会为渐变做个例外。最终的 CSS 渐变生成器似乎对我非常有效。该网站是[www.colorzilla.com/gradient-editor/](http://www.colorzilla.com/gradient-editor/)。我们要实现的渐变相当简单。它从顶部的浅蓝色到底部的深蓝色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00160.jpeg)

让我们去[www.colorzilla.com/gradient-editor/](http://www.colorzilla.com/gradient-editor/)。该工具默认为以下内容。右上角甚至有一个预览：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00161.jpeg)

默认情况下有四个颜色停止点，我们只需要两个。因此，点击渐变条中间的两个停止点并删除它们。单击颜色停止点会显示一组新的控件，包括删除按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00162.jpeg)

我们的渐变条应该如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00163.jpeg)

现在双击第一个停止点。您的屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00164.jpeg)

现在我们输入要使用的颜色，即`33D3FF`，然后点击确定。整体上是一个很好的类似 Photoshop 的界面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00165.jpeg)

现在，双击第二个颜色停止点，并添加`00718e`颜色：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00166.jpeg)

这种颜色和渐变看起来像我们一直在追求的。但是我们可以稍微移动颜色停止点，改变渐变。我将它拖到大约三分之一的位置：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00167.jpeg)

我们还可以通过更改大小为 370 x 100 来调整预览显示的高度，使其更像我们实际的 CTA 按钮的高度：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00168.jpeg)

CSS 输出就在预览栏下面。我们只需点击复制即可复制它。切换到我们的 CSS 文件，并将其粘贴到我们的 CTA 选择器内：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  background-color: #0072ae;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
  font-size: 22px;
  font-weight: bold;
  -webkit-transition: all .25s ease-in-out;
  transition: all .25s ease-in-out;
  /* Permalink - use to edit and share this gradient: 
  http://colorzilla.com/gradient-editor/#33d3ff+0,00718e+73 */
 background: #33d3ff; /* Old browsers */
 background: -moz-linear-gradient(top, #33d3ff 0%, #00718e 73%); 
  /* FF3.6-15 */
 background: -webkit-gradient(top, #33d3ff 0%,#00718e 73%); 
  /* Chrome10-25,Safari5.1-6 */
 background: -webkit-linear-gradient(to bottom, #33d3ff 0%,#00718e 73%);      
  /* W3C, IE10+, FF16+, Chrome26+, Opera12+, Safari7+ */
 background: -o-linear-gradient(top, #33d3ff 0%, #0071ae 72%); 
  /* Opera 11.10+ */
 background: -ms-linear-gradient(top, #33d3ff 0%, #0071ae 72%); 
  /* IE10+ */
 background: linear-gradient(to bottom, #33d3ff 0%, #0071ae 72%); 
  /* W3C */
 filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#33d3ff', endColorstr='#00718e',GradientType=0 ); 
/* IE6-9 */
}
```

# 最终渐变生成器的 CSS 输出

最终的渐变生成器创建了八个不同的属性。哇！第一个只是旧版浏览器的背景颜色，不支持渐变的语法：

```css
background: #33d3ff; /* Old browsers */
```

实际上，我们想将其更改为`#0072AE`，因为这是我们网站的官方品牌颜色。因此添加并删除前面在声明中提到的`background-color: #0072AE`属性：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
  font-size: 22px;
  font-weight: bold;
  -webkit-transition: all .25s ease-in-out;
  transition: all .25s ease-in-out;
  /* Permalink - use to edit and share this gradient: 
  http://colorzilla.com/gradient-editor/#33d3ff+0,00718e+73 */
 background: #0072ae; /* Old browsers */
  background: -moz-linear-gradient(top, #33d3ff 0%, #00718e 73%); 
  /* FF3.6-15 */
  background: -webkit-gradient(top, #33d3ff 0%,#00718e 73%); 
  /* Chrome10-25,Safari5.1-6 */
  background: -webkit-linear-gradient(to bottom, #33d3ff 0%,#00718e 73%);      
  /* W3C, IE10+, FF16+, Chrome26+, Opera12+, Safari7+ */
  background: -o-linear-gradient(top, #33d3ff 0%, #0071ae 72%); 
  /* Opera 11.10+ */
  background: -ms-linear-gradient(top, #33d3ff 0%, #0071ae 72%); 
  /* IE10+ */
  background: linear-gradient(to bottom, #33d3ff 0%, #0071ae 72%); 
  /* W3C */
  filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#33d3ff', endColorstr='#00718e',GradientType=0 ); 
/* IE6-9 */
}
```

这是大量生成的 CSS。如果我们仔细看一些这些，我想知道有多少人在使用 Firefox 3-15，考虑到当前版本是 55？同样，对于 Chrome 10-25，当前版本是 60？

```css
background: -moz-linear-gradient(top, #33d3ff 0%, #00718e 73%); 
 /* FF3.6-15 */
background: -webkit-gradient(top, #33d3ff 0%,#00718e 73%); 
 /* Chrome10-25,Safari5.1-6 */
```

此外，Chrome 和 Firefox 都是无限期更新的浏览器，这意味着它们会在不提示用户的情况下自动更新自己。

因此，我需要对所有这些前缀版本进行第二意见。让我们看看“Autoprefixer CSS Online”对此的看法，[`autoprefixer.github.io/`](https://autoprefixer.github.io/)。Autoprefixer 自称为管理供应商前缀的工具。它根据当前浏览器的流行度和对供应商前缀的支持来添加缺少的前缀并删除过时的前缀。

我将在 Autoprefixer 工具的左侧输入非前缀声明，它将根据我提供的浏览器流行度标准输出需要的供应商前缀。我希望我的渐变在市场份额大于 0.1%的所有浏览器中显示。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00169.jpeg)

现在剩下的只有`-webkit-`供应商前缀和非前缀或 W3C 标准版本：

```css
background: -webkit-linear-gradient(top, #33d3ff 0%,#0071ae 76%,#0071ae 76%);     
background: linear-gradient(to bottom, #33d3ff 0%,#0071ae 76%,#0071ae 76%); }
```

因此，让我们更新我们的规则集：

```css
.call-to-action {
  border: 2px solid #fff;
  color: #fff;
  padding: 25px 0;
  display: block;
  text-align: center;
  border-radius: 10px;
  font-size: 22px;
  font-weight: bold;
  -webkit-transition: all .25s ease-in-out;
  transition: all .25s ease-in-out;
 background: -webkit-linear-gradient(top, #33d3ff 0%,#0071ae   
  76%,#0071ae 76%);     
  background: linear-gradient(to bottom, #33d3ff 0%,#0071ae 76%,#0071ae 
  76%); }
}
```

我不知道你，但我对我们刚刚做的事情感到非常满意！

我们将保存这个并转到我们的按钮。在浏览器刷新之前，您可以看到它是纯色的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00170.jpeg)

当我们刷新时，我们得到了我们的渐变，如下图所示。这非常好。它将在拥有超过 0.1%市场份额的所有浏览器中运行。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00171.jpeg)

并且要非常清楚，我并没有说 1%的市场份额。我说的是 0.1%的市场份额。

在本节中，我们成功地为呼吁行动的按钮添加了样式，并使用了一个处理繁重工作的程序来应用渐变，这让我们能够更快地工作。

# 总结

在本章中，您学会了如何使用模块化 CSS 创建按钮，并使用多个类来改变按钮的外观。您还了解了 CSS 的特异性如何工作，以及选择器如何相互覆盖。您现在知道如何保持 CSS 的轻量和可管理性。最后，您学会了如何使用过渡、悬停状态、变换和渐变来为我们的按钮添加样式。

在下一章中，我们将继续创建我们的主要导航工具。通过这样做，您将学习有关 CSS 定位、CSS3 伪类、CSS3 动画以及如何纯粹使用 CSS 创建下拉菜单。这非常有趣！
