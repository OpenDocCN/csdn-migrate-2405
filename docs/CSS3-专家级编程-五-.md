# CSS3 专家级编程（五）

> 原文：[`zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610`](https://zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：邮件客户端基础知识

本章是关于构建邮件客户端和创建正确结构的基本方面。因为为邮件客户端构建正确的结构并不容易，而且仍然与 HTML 结构的老派思维有关，只有少数教程展示了如何从头到尾完成。为什么？让我们开始吧！

在本章中，我们将涵盖：

+   为邮件客户端创建一个简单的结构

+   了解邮件客户端中可能和不可能的事情

+   比较最知名的邮件客户端，包括 Outlook 和 Gmail

+   回到基于表格的 HTML 结构的老派思维

# 测试您的邮件客户端

由于需要在计算机上安装一堆邮件客户端，测试电子邮件的过程变得复杂。这当然与您需要安装以下操作系统有关：

+   Microsoft Outlook 2007/2010/2013

+   Microsoft Outlook 2003/Express

+   Microsoft Outlook.com

+   iPhone 邮件

+   Apple Mail

+   Gmail

+   雅虎电子邮件

这一大堆邮件客户端相当长，测试所有这些邮件客户端将会有问题。但您可以在工作流程中使用一些电子邮件测试工具。有一些在线工具的列表，例如 Litmus，稍后将在本章中介绍。

# 回到表格

表格结构是构建防弹电子邮件模板的最流行方法。它看起来像是从过去传来的。所以，让我们带来过去的风味，让我们开始创建正确的结构：

```css
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta name="viewport" content="width=device-width"/>
    <meta name="format-detection" content="telephone=no">
    <title>Untitled Document</title>
</head>
<body>
<style type="text/css">
    .class {} /* here will be your code */
</style>
<table width="100%" border="0" cellspacing="0" cellpadding="0">
    <!-- HERE your content -->
</table>
</body>
</html>
```

你可能会问，“但 HTML5 声明在哪里？为什么样式没有包含在`rel`标签的链接中？”这是因为电子邮件客户端中包含的旧 HTML 解释器以及使用较新的`doctype`可能会导致兼容性问题。目前，我们有一个骨架。让我们开始编写样式：

那么为什么我们要使用代码的这一部分？

```css
<meta name="format-detection" content="telephone=no">
```

这段代码与 iOS 特定问题有关。它改变了输入电话号码的行为，该电话号码（在 iOS 上）被检测并更改为一个交互链接，您可以点击并开始拨打电话。

## 重置样式

在 CSS 代码中，有很多代码应该用于重置所有浏览器上的行为。同样的情况也发生在邮件客户端中。有一堆声明应该附加到您的样式部分，并且将帮助您提供防弹邮件客户端。那么我们可以添加什么作为重置器？

```css
body {
    margin: 0;
    padding: 0;
    min-width: 100% !important;
}
```

删除边距和填充的第一个声明非常重要。这个声明来自标准的互联网浏览器。正如你所看到的，`min-width`也出现了。如代码中所述，这是非常重要的一行！在值中，有`100% !important`。是的！值和`!important`之间没有空格。以下代码是邮件客户端的`重置`样式的一部分：

```css
body,
table,
td,
a {
    -webkit-text-size-adjust: 100%; // IOS specific
-ms-text-size-adjust: 100%; // Windows mobile
}

.ExternalClass {
    width: 100%;
}

.ExternalClass,
.ExternalClass p,
.ExternalClass span,
.ExternalClass font,
.ExternalClass td,
.ExternalClass div {
    line-height: 100%;
}
```

什么是`ExternalClass`？这个类与将在 Outlook 或 Hotmail 中显示的模板有关。将这一大堆类设置到您的`<style>`标签中是一个很好的方法。这将最小化可能在特定邮件客户端上出现的问题。以下代码包含 mso-前缀。这意味着它与 Microsoft Office 有关。

```css
table {
    mso-table-lspace: 0pt;
    mso-table-rspace: 0pt;
}
```

这段代码与 Microsoft Outlook 有关。它将重置边框中的额外空间：

```css
#outlook a{
    padding:0;
}

h1,
h2,
h3,
h4,
h5,
h6 {
    color: <your_color>!important;
}

h1 a,
h2 a,
h3 a,
h4 a,
h5 a,
h6 a {
    color: <your_color>!important;
}

h1 a:active,
h2 a:active,
h3 a:active,
h4 a:active,
h5 a:active,
h6 a:active {
    color: <your_color>!important;
}

h1 a:visited,
h2 a:visited,
h3 a:visited,
h4 a:visited,
h5 a:visited,
h6 a:visited {
    color: <your_color>!important;
}

img{
    -ms-interpolation-mode:bicubic;
    border: 0;
    height: auto;
    line-height: 100%;
    outline: none;
    text-decoration: none;
}
```

# 通过媒体查询定位特定设备

要构建一个防弹邮件客户端，您将需要为一些特定的邮件客户端和设备使用特定的代码。这更难做，因为调试存在问题（没有很好的调试器/检查器来实时检查行为）。我们需要哪些设备？让我们创建一个列表：

+   带有视网膜和非视网膜显示器的 iPad 或 iPhone

+   Android 设备：

+   低密度（像素比小于 1）

+   中密度（像素比等于 1）

+   高密度（像素比大于 1）

```css
@media only screen and (max-device-width: 480px) {
}
```

这个集合将匹配平板电脑和小屏幕：

```css
@media only screen and (min-device-width: 768px) and (max-device-width: 1024px) {
}
```

视网膜显示器是 iOS 设备（如 iPhone、iPod 和 iPad）所知的。可以使用这个媒体查询来定位这些设备：

```css
@media only screen and (-webkit-min-device-pixel-ratio: 2) {
}
```

针对低密度 Android 布局：

```css
@media only screen and (-webkit-device-pixel-ratio: .75) {
}
```

针对中密度 Android 布局：

```css
@media only screen and (-webkit-device-pixel-ratio: 1) {
}
```

针对高密度 Android 布局：

```css
@media only screen and (-webkit-device-pixel-ratio: 1.5) {
}
```

如果你想要针对 Outlook 2007 和 2010，你需要使用 HTML 条件结构。它看起来像这样：

```css
<!--[if gte mso 9]>
<style>
    /* Your code here */
</style>
<![endif]-->
```

## 电子邮件模板中的 CSS 属性

重要的是要记住你可以使用哪些属性以及有哪些例外。这些知识将使你免于许多紧张的情况。让我们列举一下：

| 属性 | 特定客户端/设备的问题 |
| --- | --- |
| `direction` | - |
| `font` | - |
| `font-family` | - |
| `font-style` | - |
| `font-variant` | - |
| `font-size` | - |
| `font-weight` | - |
| `letter-spacing` | - |
| `line-height` | (iOS) 默认字体大小为 13px |
| `text-align` | (Outlook) 不要将 line-height 附加到`TD`元素。建议将此属性附加到`P`元素。 |
| `text-decoration` | - |
| `text-indent` | - |
| `background` | (Outlook) 不支持背景图片 |
| `background-color` | - |
| `border` | - |
| `padding` | (Outlook) 不支持元素的填充:`<p>``<div>``<a>` |
| `width` | (Outlook) 不支持元素的宽度:`<p>``<div>``<a>` |
| `list-style-type` | - |
| `border-collapse` | - |
| `table-layout` | - |

你可以看到，有很多属性在所有电子邮件客户端上的工作方式都不同。这是一个大问题，但是有了基本的知识，你就会知道哪些元素可以用 CSS 描述。邮件发送者中最大的问题是定位，这是不受支持的。所以例如，在大多数情况下，当文本溢出某些图像时，你需要使用包含文本的图像。

## 响应式电子邮件模板

这本书的这一部分可能会引发一场大讨论，因为在所有电子邮件客户端中都不可能构建响应式电子邮件。这是一个可以用作电子邮件模板基础的工作草案：

```css
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
<head>
    <title>Our responsive template</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
    <style type="text/css">
        @media screen and (max-width: 525px) {
            .wrapper {
                width: 100% !important;
            }

            .content {
                padding: 10px 5% 10px 5% !important;
                text-align: left;
            }
        }
</style>
</head>
<body style="margin: 0 !important;
padding: 0 !important;">

<table border="0"
       cellpadding="0"
       cellspacing="0"
       width="100%">
    <tr>
        <td bgcolor="#ffffff"
            align="center"
            style="padding: 10px;">
            <table border="0"
                   cellpadding="0"
                   cellspacing="0"
                   width="500"
                   class="wrapper">
                <tr>
                    <td>
                        <table width="100%"
                               border="0"
                               cellspacing="0"
                               cellpadding="0">
                            <tr>
                                <td align="left"
                                    style="font-size: 40px;
                font-family: Helvetica, Arial, sans-serif;
   color: #000000;
                padding-top: 10px;"
                                 class="content">Header of our mailer
                                </td>
                            </tr>
                            <tr>
                                <td align="left"
                                    style="padding: 20px 0 0 0;
              font-size: 16px;
              line-height: 25px;
              font-family: Helvetica, Arial, sans-serif;
              color: #000000;
              padding-bottom: 30px;"
class="content">Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed
                                    varius, leo a ullamcorper feugiat, ante purus sodales justo, a faucibus libero lacus
                                    a est. Aenean at mollis ipsum.
                                </td>
                            </tr>
                            <tr>
                                <td align="center" class="content">
                                    <table width="100%"
                                           border="0"
                                           cellspacing="0"
                                           cellpadding="0">
                                        <tr>
                                            <td align="left">
                                                <table
                                                      border="0"
                                                      cellspacing="0"
                                                      cellpadding="0">
                                            <tr>
                                              <td align="center"
                                              bgcolor="#000"><a href="#"
                                              target="_blank"
                                              style="font-size: 20px;
                        font-family: Helvetica, Arial, sans-serif;
                        color: #ffffff;
                        text-decoration: none;
                        color: #ffffff;
                        text-decoration: none;
                        padding: 10px 20px;
    display: inline-block;">
                                                    Lorem ipsum click
                                                        </a>
                                                        </td>
                                                    </tr>
                                                </table>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>

        </td>
    </tr>

</table>

</body>
</html>
```

你可以看到，有很多代码...但是当我们想要将其与普通网站进行比较时，效果并不是很好。以下截图显示了在宽度大于 520px 的桌面浏览器中的外观：

![响应式电子邮件模板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00148.jpeg)

在较小的浏览器（小于 520px）中，你会看到这个：

![响应式电子邮件模板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00149.jpeg)

# 内联电子邮件模板

在推送项目之前，对电子邮件模板进行内联处理是一个非常重要的过程，当你使用单独的 CSS 文件或者 CSS 代码写在`<style>`部分时—[`foundation.zurb.com/e-mails/inliner-v2.html`](http://foundation.zurb.com/e-mails/inliner-v2.html)。

# 电子邮件模板开发提示

与前端开发相关的其他流程一样，这应该从准备好的设计开始。真正的网页设计师知道一个好网站的边界在哪里，也应该知道与邮件发送者相关的边界在哪里。在全局电子邮件创建过程中有很多限制。这就是为什么参与这个过程的设计师应该知道可以在 HTML 电子邮件模板中使用的功能。

## ZURB 的电子邮件模板框架 INK

这个开发过程更简单，有一些收集了经过测试的代码片段的框架。ZURB 在创建了伟大的前端框架 Foundation 之后，为电子邮件模板创建了 INK 作为框架。关于这个框架的完整信息，建议访问[`foundation.zurb.com/e-mails.html`](http://foundation.zurb.com/e-mails.html)。

![ZURB 的电子邮件模板框架 INK](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00150.jpeg)

基于 INK 创建的电子邮件模板非常适合开发人员。该框架收集了许多易于使用的组件，如网格系统、按钮、缩略图，你可以轻松地添加到你的模板中。此外，还有一系列可调参数，如间距、全局填充和边距。为了更深入地了解 ZURB INK2 框架，建议查看官方文档：[`foundation.zurb.com/emails/docs/`](http://foundation.zurb.com/emails/docs/)。

# 在 Litmus 上进行测试

当您想要收集所有测试环境时，电子邮件模板的测试就会变得非常复杂。使用 Litmus 会更容易，它会在大多数已知的电子邮件客户端中对您的电子邮件模板进行截图。

使用 Litmus 进行测试

创建模板后，您需要复制 HTML 代码并将其粘贴到系统中。如果您的电子邮件中有一些托管在某个服务器上的图片，您可以发送电子邮件到 Litmus 中的您的账户。Litmus 在应用程序端创建了您专用的电子邮件地址。当您发送电子邮件到此地址时，您可以在 Litmus 中测试此电子邮件。

使用 Litmus 进行测试

如您在上面的屏幕上所见，您可以在大多数已知的电子邮件客户端中检查您的代码。截图是在 Litmus 账户的试用版本上制作的，因此一些视图未被激活。

# 总结

准备防弹电子邮件模板是一个复杂的过程。为什么？正如您所见，HTML 和 CSS 在您熟悉的标准网络浏览器中表现得非常奇怪，不太符合逻辑。当然，所有这些过程都可以被描述，并且有一个工作流程可以帮助您在不紧张的情况下构建邮件发送程序。电子邮件模板带来的限制清单非常长，但对基础知识的良好掌握和电子邮件模板开发经验可以使您成为这个前端领域的专家。

在下一章中，我们将讨论 CSS 代码的可扩展性和模块化。您将更多地了解方法论和命名约定。让我们开始吧！


# 第十二章：可扩展性和模块化

在本章中，我们将介绍在创建模块化和可扩展代码的过程中最知名的 CSS 方法论。这是一个非常有趣的主题，因为有很多方法论。每种方法论都有其优缺点。在本章中，我们将对它们有一个基本的了解。

我们将涵盖以下主题：

+   构建可扩展和模块化的代码

+   CSS 方法论

+   SMACSS

+   BEM

+   OOCSS

+   如何选择正确的方法论？

# 构建可扩展和模块化的代码

构建良好代码的过程对每个开发者来说都是独特的。但是你如何构建易扩展的 CSS 代码？此外，这段代码需要是模块化的。

方法论中最重要的是命名约定。你可以为你的项目使用适当的方法论，但你也可以错误地使用它并附加不良的类名。你是否曾经见过类似这样的项目，其中类名和定义类似于这样的：

```css
.padding-0 {
    padding: 10px;
}
```

正如你所看到的，类名被创建为使用值`0`进行填充，但最终它的值不等于`0`。这可以是一个不良的命名约定的例子。还有更多不良使用名称的例子：

```css
.marginTop10 {
    padding-top: 50px;
}
```

方法论中的第二个重要事项是文档中类/元素的结构和嵌套级别。一些来源说，最大嵌套级别不应大于五，而其他人说三。为了可读性，代码应该具有完全平坦的结构（只有一级）。

让我们来看看流行的 CSS 方法论，学习它们的最佳特点。

# CSS 方法论

CSS 方法论的目的是使构建代码的过程更可预测和更有组织。最知名的方法论如下：

+   **可扩展和模块化的 CSS 架构**（**SMACSS**）

+   **面向对象的 CSS**（**OOCSS**）

+   **块元素修饰符**（**BEM**）

每种方法论都有不同的特点。让我们看看这些流行的方法论能提供什么。

## SMACSS

SMACSS 是由 Jonathan Snook 创建的。它更像是一个框架而不是一个方法论：

![SMACSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00153.jpeg)

有关该项目的官方网站，请访问[`smacss.com/`](https://smacss.com/)。

SMACSS 基于以下规则：

+   基本规则

+   布局规则

+   模块规则

+   状态规则

+   主题规则

### 基本规则

基本规则与相关元素：

+   标题（`h1`-`h6`）

+   链接（`a`，`a:hover`，`a:active`）

+   表单（`form`，`input`）

所有这些规则都与 HTML 元素相关，不应该需要`!important`语句。

### 布局规则

布局规则与结构中的主要块相关，例如这些：

+   `header`

+   `footer`

+   `content`

+   `side` `menu`

+   `article`

这些元素的描述如下：

CSS：

```css
#header {
    display: inline-block;
}

#footer {
    display: inline-block;
    padding: 10px;
}
```

### 模块规则

模块规则与网站上的组件或块相关。让我们以先前为博客文章创建的结构的一个示例片段为例。在这里，我们将更好地了解如何在这种特定情况下使用 SMACSS 模块：

![模块规则](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00154.jpeg)

要在 CSS 中描述它，我们需要使用基于以下内容的选择器：

```css
.module > element / class
```

让我们为其构建一个 HTML：

```css
<article class="article">
    <img src="img/#">
    <h1>Lorem ipsum dolor sit amet, consecteur adisiciping elit</h1>
    <p> Lorem ipsum … </p>
    <a href="#">Read more</a>
</article>
```

让我们基于模块规则创建选择器：

```css
.article >img {
    /* Image in top */
}

.article > h1 {
    /* Post header */
}

.article > p {
    /* Post excerpt */
}

.article > a {
    /* Read more button */
}
```

创建所有这些是相当容易和明显的。

### 状态规则

状态规则与元素的状态相关。有许多可能的状态规则类。以下是可能的规则列表：

+   `is-collapsed`

+   `is-error`

+   `is-active`

+   `is-tab-active`

描述状态规则最简单的方法是通过一个简单的导航示例：

```css
<nav>
    <ul>
        <li class="is-active"><a href="#">Home</a>
            <ul>
                <li><a href="#">Home 1.1</a></li>
                <li><a href="#">Home 1.2</a></li>
            </ul>
        </li>
        <li><a href="#">About</a></li>
        <li><a href="#">Contact</a></li>
        <ul>
</nav>
```

要描述当前活动的菜单中的元素，可以使用类`is-active`。这种约定易于阅读，并为你提供了正确的类名的机会。

### 主题规则

主题规则与特定视图相关。例如，你创建了一个带有元素的页面：

HTML 如下：

```css
<body>
    <div class="alert">
        Alert
    </div>
</body>
```

我们最初所知道的是`.alert`是一个窗口，需要粘在浏览器上，就像一个灯箱窗口一样。

CSS（在`alert.css`中）如下：

```css
.alert {
    width: 300px;
    height: 300px;
    position: fixed;
    left: 50%;
    top: 50%;
    transform: translate(-50%, -50%);
}
```

现在我们需要为这个`.alert`（在`theme.css`中）添加一个特定的主题：

```css
.alert {
    background: red;
    color: black;
}
```

正如我们在`alert.css`中看到的，我们将静态元素的定义保留在`theme.css`中不会改变。保留在`theme.css`中的主题规则是为我们的组件进行主题设置；在这种情况下，它是一个`alert`窗口。

### SMACSS 摘要

由于以下原因，SMACSS 是一个非常好的方法：

+   它有收集主要元素定义的基本规则

+   它有描述元素状态的状态规则，使用`is-`约定

+   它在 CSS 中使用主要元素的 ID

## OOCSS

OOCSS 是由 Nicole Sullivan 发起的一个项目或方法：

![OOCSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00155.jpeg)

访问项目的官方网站[`oocss.org/`](http://oocss.org/)获取更多信息。

OOCSS 的主要原则如下：

+   分离结构和皮肤

+   分离容器和内容

这是什么意思？让我们试着深入挖掘一下。

这意味着最好描述嵌套在另一个元素中的元素时，使用一个单独的类，而不是嵌套在容器中。当你创建这样的代码时：

```css
<div class="product">
    <h1>Name of product</h1>
    <p>Description</p>
</div>
```

你不应该基于选择器来编写你的 CSS：

```css
.product h1 {}
.product p {}
```

而不是在标记中进行小改变：

```css
<div class="product">
    <h1 class="product-name">Name of product</h1>
    <p class="product-desc">Description</p>
</div>
```

然后用选择器在 CSS 中描述它：

```css
.product-name {}
.product-desc {}
```

它让你有可能将类`.product-name`移动到 HTML 结构中的任何元素，视觉特性也会随之改变，如描述的那样。这给了你更多的灵活性和可重用的代码。

### 在我们的示例中使用 OOCSS

让我们尝试在我们的示例代码中使用 OOCSS 来描述博客文章：

```css
<article class="article">
    <img src="img/#" class="article-image">
    <h1 class="article-h1">Lorem ipsum dolor sit amet, consecteur adisiciping elit</h1>
    <p class="article-p"> Lorem ipsum … </p>
    <a href="#" class="article-btn">Read more</a>
</article>
```

在你的 CSS 中，它会是这样的：

```css
.article { /**/}
.article-image { /**/ }
.article-h1 { /**/ }
.article-p { /**/ }
.article-btn { /**/ }
```

### OOCSS 摘要

让我们总结一下 OOCSS：

+   你可以在 HTML 中任何地方重用类，而不需要考虑它是在哪个模块中描述的

+   这种方法非常成熟

## 块元素修饰符（BEM）

下一个方法是由 Yandex 构建的。在 BEM 方法中，每个元素都用一个类来描述。由于平面 CSS 结构，不需要嵌套。命名约定基于：

![块元素修饰符（BEM）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00156.jpeg)

访问项目的官方网站[`en.bem.info/`](https://en.bem.info/)获取更多信息。

### 在我们的示例中使用 BEM

让我们尝试在我们的示例代码中使用 BEM 来描述博客文章：

```css
<article class="article">
    <img src="img/#" class="article__image">
    <h1 class="article__h1">Lorem ipsum dolor sit amet, consecteur adisiciping elit</h1>
    <p class="article__p"> Lorem ipsum … </p>
    <a href="#" class="article__btn">Read more</a>
</article>
```

现在在你的 CSS 中，它会是这样的：

```css
.article { /**/}
.article__image { /**/ }
.article__h1 { /**/ }
.article__p { /**/ }
.article__btn { /**/ }
```

### 在 SASS 中使用 BEM

在 SASS 中构建 BEM 代码不应该很难。让我们尝试描述前面代码中的代码：

```css
.article
  &__image
    /* Image in top */

  &__h1
    /* Post header */

  &__p
    /* Post paragraph */

  &__btn
    /* Post button */
```

### 如何使用修饰符？

前面的代码示例是基于 BEM 方法中的块和元素。我们如何添加`M`及其修饰符？我们什么时候可以使用它？让我们想象一下，我们有两篇文章：一篇文章左侧有一张图片，第二篇文章右侧有一张图片。使用 BEM 方法，我们可以使用一个修饰符。让我们拿上一个 CSS 代码并附加修饰符：

```css
.article { /**/}
.article__image { /**/ }
.article__h1 { /**/ }
.article__p { /**/ }
.article__btn { /**/ }

.article--imgleft { /**/}
.article--imgleft__image { /**/ }
.article--imgleft__h1 { /**/ }
.article--imgleft__p { /**/ }
.article--imgleft__btn { /**/ }
```

正如我们所看到的，修饰符被定义为`imgleft`，并使用两个破折号添加到块中。修饰符可以帮助你避免为新块创建新代码。它可以像在 CSS 中实现的装饰器一样工作。

# 你应该使用哪种方法？

这是一个非常好的问题。毫无疑问，你需要使用适合你的方法。但哪一种适合？最好的 CSS 方法是可以轻松调试的方法。什么时候呢？毫无疑问，当你不需要深入挖掘时，比如，一个元素有 10 条规则。在 CSS 中最好的可读性是当规则严格与页面上的元素相关联时。

# 也许是你自己的方法？

是的！如果你想为你的项目创建一些新的东西，创建你自己的方法。但是，不要重复造轮子，也不要试图重命名已知的方法来构建你自己的方法。对这三种方法的深入理解可能是你创建一个符合你要求的小型未命名混搭的关键。

# 摘要

现在应该更容易选择适合您的代码/项目的正确方法论了。在本章中，我们熟悉了 CSS 方法论，并试图定义它们的方法。最重要的是要理解它们，并知道如何将它们应用到您的代码中。这在调试其他代码的过程中可能会有用。

在下一章中，我们将专注于 CSS 代码优化。我们将使用`Gulp.js`来准备您的代码进行测试和最终优化项目。


# 第十三章：代码优化

本章是关于一般创建代码过程和与每个步骤相关的过程。这个过程有几个一般阶段，我们将研究如何在每个阶段优化代码。

在本章中，我们将涵盖以下主题：

+   在创建的每个步骤中进行代码优化

+   如何在你的代码库中保持代码

+   如何优化 SASS 代码

+   如何在 CSS/SASS 代码中使用简写形式

+   如何准备代码以用于生产

# 自我优化

优化过程是在你开始编写代码时开始的。在编写代码时意识到可以优化的内容以及它在编写代码时应该如何出现是至关重要的。在编写过程之后，当你开始优化时，重构和重组代码可能会非常困难。但是构建代码并自动附加优化过程是很容易的。在编写代码时可以执行哪些过程？

+   使用简写形式

+   省略使用`!important`

+   省略使用 ID

## 在将代码发布之前的几个步骤

在代码创建过程中，有一些可重复的步骤：

+   编写代码

+   测试代码

+   将代码发布

这些过程有时是可重复的，特别是当它们与 Eric Ries 的《精益创业》方法论和多阶段项目相关时。在将代码发布之前，你需要记住这几个步骤：

+   检查是否使用了简写形式

+   检查元素/声明是否重复

+   检查元素/声明是否在 HTML 中使用（僵尸选择器）

+   检查`!important`的出现（如果可能的话，尝试省略它们）

+   检查代码是否被压缩

这个列表非常基础。在接下来的章节中，我们将运行优化过程和用法，检查所有可能性。

## 使用简写形式

在编写和构建过程中，简写形式有助于压缩代码。在 CSS 中使用简写形式，你可以节省很多字符，使代码更加精简。让我们来看一下简写形式的概述。

### 填充/边距的简写形式

你写填充和边距时有多少次使用了完整形式？你有多少次看到别人的代码没有使用填充和边距的简写形式而感到紧张？是的！它可能会让你紧张，因为这是对 CSS 的浪费！让我们从 SASS 中对元素填充的简单描述开始：

```css
.element
  padding:
    top: 10px
    right: 20px
    bottom: 30px
    left: 40px
```

它会给你类似这样的 CSS 代码：

```css
.element {
    padding-top: 10px;
    padding-right: 20px;
    padding-bottom: 30px;
    padding-left: 40px;
}
```

以下是用 CSS 简要描述它的方法：

```css
.element 
  padding: 10px 20px 30px 40px
```

一般来说，填充可以描述如下：

```css
padding: top right bottom left
```

你也可以用同样的方法处理边距：

```css
.element
margin:
    top: 10px
    right: 20px
    bottom: 30px
    left: 40px
```

它会给你类似这样的 CSS 代码：

```css
.element {
    margin-top: 10px;
    margin-right: 20px;
    margin-bottom: 30px;
    margin-left: 40px;
}
```

以下是用 CSS 简要描述它的方法：

```css
.element
margin: 10px 20px 30px 40px
```

一般来说，边距可以描述如下：

```css
margin: top right bottom left
```

让我们用另一个例子：

```css
.element
  margin:
    top: 10px
    right: 20px
    bottom: 10px
    left: 20px
```

编译为 CSS：

```css
.element {
  margin-top: 10px;
  margin-right: 20px;
  margin-bottom: 10px;
  margin-left: 20px; 
}
```

正如你所看到的，有两对值。当上边距/填充的值在底部值中重复，并且左值等于右值时，你可以使用简写版本：

```css
.element
  margin: 10px 20px
```

当编译为 CSS 时，它看起来像这样：

```css
.element {
  margin: 10px 20px; 
}
```

如你所见，这个版本是被压缩的，最终基于这个模式：

```css
margin: top_bottom_value left_right_value
```

### 边框的简写形式

让我们从边框的基本描述开始，然后我们可以扩展它：

```css
.element
    border:
    style: solid
    color: #000
    width: 10px
```

这是编译后的 CSS：

```css
.element {
  border-style: solid;
  border-color: #000;
  border-width: 10px; 
}
```

这个类将在框周围创建一个边框，它将是实心的，宽度为`10px`，颜色为黑色。因此，让我们创建一个包括所有边框（上、右、下和左）的类，定义样式颜色和宽度：

```css
.element
  border:
    top:
      style: solid
      color: #000
      width: 1px

    right:
      style: solid
      color: #f00
      width: 2px

    bottom:
      style: solid
      color: #0f0
      width: 3px

    left:
      style: solid
      color: #00f
      width: 4px
```

CSS：

```css
.element {
  border-top-style: solid;
  border-top-color: #000;
  border-top-width: 1px;

  border-right-style: solid;
  border-right-color: #f00;
  border-right-width: 2px;

  border-bottom-style: solid;
  border-bottom-color: #0f0;
  border-bottom-width: 3px;

  border-left-style: solid;
  border-left-color: #00f;
  border-left-width: 4px; 
}
```

因此，如果你想让这个代码变得更短一点，你可以使用全局定义的边框简写。代码如下：

```css
.element
  border: 1px solid #000
```

CSS：

```css
.element {
  border: 1px solid #000; 
}
```

和方向。代码将看起来像这样：

```css
.element
border:
    top: 1px dotted #000
    right: 2px solid #f00
    bottom: 3px dashed #0f0
    left: 4px double #00f
```

编译：

```css
.element {
    border-top: 1px dotted #000;
    border-right: 2px solid #f00;
    border-bottom: 3px dashed #0f0;
    border-left: 4px double #00f;
}
```

有一种方法可以以与我们定义填充和边框相同的方式来描述样式/宽度/颜色：

```css
.element
  border:
    style: dotted solid dashed double
    width: 1px 2px 3px 4px
    color: #000 #f00 #0f0 #00f
```

编译：

```css
.element {
    border-style: dotted solid dashed double;
    border-width: 1px 2px 3px 4px;
    border-color: #000 #f00 #0f0 #00f;
}
```

现在，让我们收集关于`border-radius`的信息。边框半径的全局定义如下：

SASS：

```css
.element
  border-radius: 5px
```

CSS：

```css
.element {
    border-radius: 5px;
}
```

在另一行和另一个值中描述每个角：

```css
.element
  border:
    top:
      left-radius: 5px
      right-radius: 6px
    bottom:
      left-radius: 7px
      right-radius: 8px
```

CSS：

```css
.element {
  border-top-left-radius: 5px;
  border-top-right-radius: 6px;
  border-bottom-left-radius: 7px;
  border-bottom-right-radius: 8px; 
}
```

现在，前面的代码可以用以下方式描述得更短：

```css
.element
  border-radius: 5px 6px 7px 8px
```

CSS：

```css
.element {
  border-radius: 5px 6px 7px 8px;
}
```

### 字体样式中的简短形式

字体在每个段落标题链接中都有描述。如您所见，在代码中这么多重复出现的情况下使用简写是很好的。在这里，我们对一个示例元素的字体和行高进行了简单描述：

```css
.element
font:
    size: 12px
    family: Arial
    weight: bold
  line-height: 1.5
```

CSS：

```css
.element {
  font-size: 12px;
  font-family: Arial;
  font-weight: bold;
  line-height: 1.5; 
}
```

让我们基于模式使用简短形式：

```css
font: font_family font_size/line_height font_weight
```

通过这种简短的形式，我们在 SASS 中的五行（在 CSS 中的四行）被改为了一行：

```css
.element
  font: Arial 12px/1.5 bold
```

编译后，代码如下：

```css
.element {
  font: Arial 12px/1.5 bold; 
}
```

### 背景的简短形式

背景是最常用的 CSS 特性之一。背景的主要用途是：

```css
.element
  background:
    color: #000
    image: url(path_to_image.extension)
    repeat: no-repeat
    attachment: fixed
    position: top left
```

这段代码将给我们以下输出：

```css
.element {
  background-image: url(path_to_image.extension);
  background-repeat: no-repeat;
  background-attachment: fixed;
  background-position: top left; 
}
```

这是很多代码！简短形式按照这个顺序描述：

```css
background-color
background-image
background-repeat
background-attachment
background-position
```

例子：

```css
background: url color repeating attachment position-x position-y;
```

如果我们想用这种简短形式描述我们的元素，我们只需要这样做：

```css
.element
  background: #000 url(path_to_image.extension) no-repeat fixed top left
```

在 SASS 编译成 CSS 后，我们将得到以下结果：

```css
.element {
  background: #000 url(path_to_image.extension) no-repeat fixed top left; 
}
```

## 检查重复

在创建 CSS 代码时，您需要注意代码的重复。对于专业开发人员来说，代码可能看起来有点奇怪，但我们可以把它当作代码审查过程的一个很好的样本。让我们来分析一下。

HTML：

```css
<section>
    <a class="button">click it</a>
    <a class="buttonBlue">click it</a>
    <a class="buttonGreen">click it</a>
</section>
```

CSS：

```css
section .button {
    padding: 5px 10px; /* Repeated padding */
    font-size: 12px; /* Repeated font size */
    color: white; /* Repeated color */
    background: black;
}

section .buttonBlue {
    padding: 5px 10px; /* Repeated padding */
    font-size: 12px; /* Repeated font size */
    color: white; /* Repeated color */
    background: blue;
}

section .buttonGreen {
    padding: 5px 10px; /* Repeated padding */
    font-size: 12px; /* Repeated font size */
    color: white; /* Repeated color */
    background: green;
}
```

如您所见，重复部分已经被注释，现在我们将创建一个通用类：

```css
section .button {
    padding: 5px 10px;
    font-size: 12px;
    color: white;
    background: black;
}

section button.button_blue {
    background: blue;
}

section button.button_green {
    background: green;
}
```

我们需要在 HTML 代码中追加一些小的改变：

```css
<section>
    <a class="button">click it</a>
    <a class="button button_blue">click it</a>
    <a class="button button_green">click it</a>
</section>
```

在 SASS 中将其最小化：

```css
section
  .button
    padding: 5px 10px
    font-size: 12px
    color: white
    background: black

    &.button_blue
      background: blue

    &.button_green
      background: green
```

这是另一种处理重复的方法，而不改变标记：

```css
article .h1 {
    font-family: Arial; /* Repeated font family */
    padding: 10px 0 15px 0; /* Repeated padding */
    font-size: 36px;
    line-height: 1.5; /* Repeated line height */
    color: black; /* Repeated color */
}

article .h2 {
    font-family: Arial; /* Repeated font family */
    padding: 10px 0 15px 0; /* Repeated padding */
    font-size: 30px;
    line-height: 1.5; /* Repeated line height */
    color: black; /* Repeated color */
}

article .h3 {
    font-family: Tahoma; /* Oryginal font family */
    padding: 10px 0 15px 0; /* Repeated padding */
    font-size: 24px;
    line-height: 1.5; /* Repeated line height */
    color: black; /* Repeated color */
}
```

让我们收集重复的部分：

```css
font-family: Arial; 
padding: 10px 0 15px 0; 
line-height: 1.5; 
color: black; 
```

让我们添加一个将在自定义元素`.h3`中被覆盖的值：

```css
font-family: Tahoma;
```

现在，让我们描述选择器并在单独的选择器中覆盖值：

```css
article .h1,
article .h2,
article .h3 {
    padding: 10px 0 15px 0;
    line-height: 1.5;
    color: black;
    font-family: Arial;
}

article .h1 {
    font-size: 36px;
}

article .h2 {
    font-size: 30px;
}

article .h3 {
    font-size: 24px;
    font-family: Tahoma;
}
```

让我们将其改为 SASS 代码：

```css
article
.h1,
  .h2,
  .h3
    padding: 10px 0 15px 0
    line-height: 1.5
      color: black
    font:
      family: Arial

  .h1
    font:
      size: 36px

  .h2
    font:
      size: 30px

  .h3
    font:
      size: 24px
      family: Tahoma
```

让我们用`@extend`做同样的事情：

```css
article
  .h1
    padding: 10px 0 15px 0
    line-height: 1.5
    color: black
    font:
      family: Arial
      size: 36px

  .h2
    @extend .h1
    font:
      size: 30px

  .h3
    @extend .h1
    font:
      size: 24px
      family: Tahoma
```

当您自己创建代码时，检查重复的过程很容易，但当您与其他开发人员一起工作或者在一个由其他人开始的项目上工作时，这可能会更难。这个过程使代码变得更短，因此它可以被视为代码优化的过程。通过这些技术，您可以对代码进行追加更改。

# 总结

在本章中，我们讨论了 CSS 代码优化的过程。有了这些知识，您可以最小化您的代码，并且在创建代码时考虑优化过程。这些知识将使您成为一个更加明智的前端开发人员，了解代码如何可以在瞬间被最小化。

在下一章中，我们将讨论您可以在 CSS 和前端项目中使用的最终自动化！


# 第十四章：最终自动化和流程优化

在这最后一章中，我们将讨论在创建 CSS 代码过程中重复流程的最终自动化。有很多流程可以自动化，但是意识到它是否可以做到以及使用的工具的知识是必不可少的。在本章中，我们将专注于工具以及如何在 Gulp 任务运行器中实现自动化。

在本章中，我们将涵盖以下主题：

+   视网膜和移动设备上的图像

+   如何识别未使用的 CSS

+   如何压缩代码

+   如何从页面列表中制作截图以便快速概览

+   如何使用 Jade 模板的基础知识并将其编译到 Gulp 中

# Gulp

在本书的开头，我介绍了 Gulp 作为 SASS 的入门。但是仅仅使用 Gulp 来编译 SASS 可能是浪费时间的。在本章中，我们将向 Gulp 添加更多任务，这些任务可以作为前端开发人员使用，并将帮助你优化你的代码。

# Jade 作为你的模板引擎

在大型项目的情况下编写 HTML 文件可能会有问题。页面的可重复元素的维护，比如主导航页脚边栏，在需要处理 10 个文件时可能会成为一个问题。每次你想要更改页脚中的内容，你都需要更新 10 个文件。当一个项目有 50 个模板时，情况会变得更加复杂。你可以开始使用 PHP 或任何包含重复代码部分的文件的语言，或者使用其中一个模板语言。有多种模板系统。以下是一些知名和时髦的模板系统：

+   手柄

+   HAML

+   Jade

+   Slim

让我们专注于 Jade。为什么？因为有以下功能：

+   混合支持

+   主模板

+   文件的部分化

+   缩进的语法（类似于 SASS）

## 安装和使用 Jade

Jade 是通过 node 包管理器安装的。你可以用以下命令安装它：

```css
npm install jade --global
```

如果你想编译一些文件，只需要调用 HTML 文件如下：

```css
jade filename.html
```

更多信息，我建议你查看 Jade 模板系统的官方文档[`jade-lang.com/`](http://jade-lang.com/)。

## Jade 的基础知识

理论介绍很重要，但让我们试着将代码的这部分描述成 Jade：

```css
<nav>
   <ul>
       <li><a href="#">Home</a></li>
       <li><a href="#">About</a></li>
       <li><a href="#">Contact</a></li>
   </ul>
</nav>
```

在 Jade 中，它会是这样的：

```css
nav
   ul
       li
           a(href="#") Home
       li
           a(href="#") About
       li
           a(href="#") Contact
```

你可以看到，你不需要考虑标准的 HTML 问题“我的标签关闭了吗？”缩进会跟踪标签的开启和关闭。你想要附加到标签中的每个文本都会出现在标签描述（名称和属性）后的空格后。让我们看一下代码的这部分：

```css
a(href="#") Home
```

这部分代码将被编译成：

```css
<a href="#">Home</a>
```

如你所见，在 Jade 中，属性（`href`）出现在元素名称（`a`）之后，用括号括起来。让我们看一下我们将要翻译成 Jade 的 HTML 代码的下一部分：

```css
<head>
    <meta charset="utf-8">
    <title>Page title</title>
    <link rel="stylesheet" href="css/main.css" media="screen" title="no title" charset="utf-8">
</head>
```

这部分代码将在所有页面上重复出现，因为它包含了我们 HTML 的`head`标签。在 Jade 中，它会是这样的：

```css
head
   meta(charset="utf-8")
   title Page title
   link(rel="stylesheet", href="css/main.css", media="screen", title="no title", charset="utf-8")
```

在这里你可以看到如何向 HTML 元素添加更多属性。在`link`元素中，括号中的每个属性都用逗号分隔。

代码的下一部分与带有类和 ID 的 DOM 元素有关：

```css
<main id="main">
   <article class="main--article">
       <a href="#">
           <img src="img/error_log.png" alt=""/>
           <span class="comments"></span>
       </a>
       <h3>Lorem ipsum dolor sit amet, consectetur adipisicing elit</h3>
       <p>
           sed do eiusmod tempor incididunt ut labore et dolore
       </p>
       <a href="#" class="readmore">Read more</a>
   </article>
</main>
```

在 Jade 中，代码看起来是这样的：

```css
main#main
   article.main--article
       a(href="#")
           img(src="img/error_log.png", alt="Error log")
           .comments
       h3 Lorem ipsum dolor sit amet
       p sed do eiusmod tempor incididunt ut labore et dolore 
       a(href="#").readmore Read more
```

你可以看到，你不需要描述这部分：

```css
<main id="main">
```

这是写成这样的：

```css
main(id="main")
```

在 Jade 中有一个简短的形式：

```css
main#main
```

类似的情况也适用于类：

```css
<article class="main--article">
```

你也可以使用一个简短的形式：

```css
article.main--article
```

这种简短的方法使 Jade 易于理解，因为它基于 CSS 中使用的选择器。

## Jade 中的混合

Jade 中的混合很有用，特别是当网页上有一些可重复的元素时。例如，可能是一些带有`href`的小元素`a`：

```css
mixin link(href, name)
   a(href= href)=name
```

现在我们需要做的就是将它添加到你的模板中：

```css
+link("url", "Your link")
```

在你编译的文件中，你会看到：

```css
<a href="url">Your link</a>
```

## 在 Jade 中包含和扩展功能

如前所述，我们可以将代码的部分保存在单独的文件中。这样做的最简单方法是使用`include`方法。假设我们已经在文件`navigation.jade`中定义了主要的`nav`，并且我们希望在我们的模板中添加其内容。代码如下：

文件名是：`navigation.jade`

```css
nav
   ul
       li
           a(href="#") Home
       li
           a(href="#") About
       li
           a(href="#") Contact
```

文件名是：`template.jade`

```css
doctype html
html
   head
       meta(charset="utf-8")
       title Page title
       link(rel="stylesheet", href="css/main.css", media="screen", title="no title", charset="utf-8")

   body
       include _navigation.jade
```

当您编译`template.jade`时，您将得到：

```css
<!DOCTYPE html>
<html>
<head>
   <meta charset="utf-8">
   <title>Page title</title>
   <link rel="stylesheet" href="css/main.css" media="screen" title="no title" charset="utf-8">
</head>
<body>
<nav>
   <ul>
       <li><a href="#">Home</a></li>
       <li><a href="#">About</a></li>
       <li><a href="#">Contact</a></li>
   </ul>
</nav>
</body>
</html>
```

这是一个很好的时机来使用可以扩展的主布局。这可以通过代码操作来完成。第一次操作必须在主模板中进行 - 定义一个将在我们的 HTML 文件中交换的块。第二次需要在将代表最终 HTML 文件的文件中完成 - 指定将扩展的主模板。代码如下：

文件名是：`master.jade`

```css
doctype html
html
   head
       meta(charset="utf-8")
       title Page title
       link(rel="stylesheet", href="css/main.css", media="screen", title="no title", charset="utf-8")

   body
       include _navigation.jade
       block content
```

文件名是：`index.jade`

```css
extends master

block content
   h1 Content
```

编译后的文档：

```css
<!DOCTYPE html>
<html>
<head>
   <meta charset="utf-8">
   <title>Page title</title>
   <link rel="stylesheet" href="css/main.css" media="screen" title="no title" charset="utf-8">
</head>
<body>
<nav>
   <ul>
       <li><a href="#">Home</a></li>
       <li><a href="#">About</a></li>
       <li><a href="#">Contact</a></li>
   </ul>
</nav>
<h1>Content</h1>
</body>
</html>
```

## 在 gulp.js 中使用 Jade

要在`gulpfile.js`中创建或添加 Jade 任务，您需要使用`npm`安装特定的包：`gulp-jade`。要这样做，请使用以下命令：

```css
npm install --save gulp-jade
```

然后，您需要在`gulpfile.js`中定义一个新任务，并为模板添加一个监视器，该模板将存储在`src/jade`目录中。以下是来自本书第一章的扩展`gulpfile.js`的清单：

```css
var gulp = require('gulp'),
   sass = require('gulp-sass'),
   jade = require('gulp-jade');

gulp.task('sass', function () {
   return gulp.src('src/css/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(gulp.dest('dist/css/main.css'));
});

gulp.task('jade', function() {
   gulp.src('src/jade/*.jade')
       .pipe(jade())
       .pipe(gulp.dest('dist/'));
});

gulp.task('default', function () {
   gulp.watch('src/sass/*.sass', ['sass']);
   gulp.watch('src/jade/*.jade', ['jade']);
});
```

它会表现如何？每当您更改`src/jade`文件夹中的任何文件时，编译后的文件将会出现在`dist`文件夹中。当然，如果您愿意，这种结构可以更改；这只是使用示例。随意更改它！

# UnCSS

有多少次你面对过这样的情况：HTML 中没有使用某些类/选择器，但在 CSS 代码中有描述？每当您的项目更改或重新设计时，这种情况都会发生。例如，您的任务是删除某些部分并在 HTML 代码中添加几行。因此，您将添加一些 CSS 代码，然后删除其中的一些。但您确定 CSS 代码不包含未使用的 CSS 代码部分吗？UnCSS 将帮助您完成此任务。要安装它，您需要执行此命令：

```css
npm install -g uncss
```

让我们来看看在`npm`命令中使用的标志：

| 标志 | 描述 |
| --- | --- |
| `-g` | 全局安装 |
| `--save` | 本地安装这些包将出现在`package.json`的`dependencies`部分。这些包是在生产中运行应用程序所需的。 |
| `--save-dev` | 本地安装这些包将出现在`package.json`的`devDependencies`部分。这些包是用于开发和测试过程的。 |

## 在 Gulp 中集成 UnCSS

首先，我们需要通过`npm`安装`gulp-uncss`：

```css
npm install --save gulp-uncss
```

现在，我们需要在`gulpfile.js`中添加新的任务。我们需要在项目中创建一个测试阶段，该阶段将存储在`test`目录中。您需要这些新任务来基于`uncss`进行处理：

```css
gulp.task('clean-css-test', function () {
   return gulp.src('test/css/main.css', {read: false})
       .pipe(rimraf({force: true}));
});

gulp.task('jade-test', function() {
   return gulp.src('src/jade/templates/*.jade')
       .pipe(jade())
       .on('error', gutil.log)
       .pipe(gulp.dest('test/'));
});

gulp.task('sass-test',['clean-css-test'], function () {
   return gulp.src('src/sass/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(gulp.dest('test/css/'));
});

gulp.task('uncss',['jade-test', 'sass-test'], function () {
   return gulp.src('test/css/main.css')
       .pipe(uncss({
           html: ['test/**/*.html']
       }))
       .pipe(gulp.dest('./test/uncss'));
});
```

要运行`uncss`任务，您需要使用以下命令：

```css
gulp uncss
```

此命令将执行以下任务：

+   将 Jade 文件编译到`test`文件夹中

+   从`test`文件夹中删除旧的 CSS 文件

+   将 SASS 文件编译到`test`文件夹中

+   运行`uncss`任务，并将文档保存为`test/uncss`文件夹中仅使用的 CSS 部分

现在我们需要实时测试。我们将准备一个简短的测试环境。

以下是文件的结构：

```css
├── jade
│   ├── master_templates
│   │   └── main.jade
│   ├── partials
│   │   ├── footer.jade
│   │   └── navigation.jade
│   └── templates
│       ├── about.jade
│       ├── contact.jade
│       └── index.jade
└── sass
    └── main.sass
```

代码如下：

文件名是：`main.jade`

```css
doctype html
html
   head
       meta(charset="utf-8")
       title Page title
       link(rel="stylesheet", href="css/main.css", media="screen", title="no title", charset="utf-8")

   body
       include ../partials/navigation
       block content
       include ../partials/footer
```

文件名是：`navigation.jade`

```css
nav
   ul
       li
           a(href="#") Home
       li
           a(href="#") About
       li
           a(href="#") Contact
```

文件名是：`footer.jade`

```css
footer
   p Copyright fedojo.com
```

文件名是：`index.jade`

```css
extends ../master_templates/main

block content
   .main
       p Test of INDEX page
```

文件名是：`about.jade`

```css
extends ../master_templates/main

block content
   .main
       h1 Test of ABOUT page
```

文件名是：`contact.jade`

```css
extends ../master_templates/main

block content
   .main
       h1 Test of CONTACT page
```

文件名是：`main.sass`

```css
body
background: #fff

p
color: #000

.header
background: #000
color: #fff

.footer
background: #000
color: #fff

header
background: #000
color: #fff

footer
background: #000
color: #fff
```

现在，让我们检查这个过程对我们是否有利。这是从 SASS 编译的文件：

```css
body {
 background: #fff; 
}

p {
 color: #000; 
}

.header {
 background: #000;
 color: #fff;
 }

.footer {
 background: #000;
 color: #fff; 
}

header {
 background: #000;
 color: #fff; 
}

footer {
 background: #000;
 color: #fff; 
}
```

此文件由`uncss`检查，它查看了所有模板（`index.html`，`about.html`和`contact.html`）：

```css
body {
 background: #fff;
}

p {
 color: #000;
}

footer {
 background: #000;
 color: #fff;
}
```

我们的新命令是用 Gulp 构建的，删除了所有不必要的 CSS 声明。

# 压缩 CSS

缩小文件的过程主要应该用于生产代码。在开发过程中，对缩小的文件进行操作会很困难，因此我们只需要为生产代码进行缩小。可以通过添加适当的标志（`--compressed`）来启用 SASS 或 Compass 编译中的缩小。我们还将使用一个外部工具，在 `uncss` 过程之后对代码进行缩小。现在我们需要安装 `gulp-clean-css`：

```css
npm install --save gulp-clean-css
```

现在，缩小 `uncss` 过程的结果。我们将创建一个 `prod` 目录，其中存储项目的最终版本。现在让我们导入 `gulp-clean-css`：

```css
cleanCSS = require('gulp-clean-css')
```

让我们在 `gulpfile.js` 中创建所需的部分：

```css
gulp.task('clean-css-production', function () {
   return gulp.src('prod/css/main.css', {read: false})
       .pipe(rimraf({force: true}));
});

gulp.task('sass-production',['clean-css-production'], function () {
   return gulp.src('src/sass/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(uncss({
           html: ['prod/**/*.html']
       }))
       .pipe(cleanCSS())
       .pipe(gulp.dest('prod/css/'));
});

gulp.task('jade-production', function() {
   return gulp.src('src/jade/templates/*.jade')
       .pipe(jade())
       .pipe(gulp.dest('prod/'));
});

gulp.task('production',['jade-production', 'sass-production']);
```

# 最终的自动化工具

现在我们需要将之前创建的所有任务汇总到一个文件中。`gulp` 项目的核心是两个文件：`package.json`，它汇总了所有项目依赖，以及 `gulpfile`，你可以在其中存储所有任务。以下是任务：

文件名是：`package.json`

```css
{
 "name": "automatizer",
 "version": "1.0.0",
 "description": "CSS automatizer",
 "main": "gulpfile.js",
 "author": "Piotr Sikora",
 "license": "ISC",
 "dependencies": {
   "gulp": "latest",
   "gulp-clean-css": "latest",
   "gulp-jade": "latest",
   "gulp-rimraf": "latest",
   "gulp-sass": "latest",
   "gulp-uncss": "latest",
   "gulp-util": "latest",
   "rimraf": "latest"
 }
}
```

文件名是：`gulpfile.json`

```css
var gulp = require('gulp'),
   sass = require('gulp-sass'),
   jade = require('gulp-jade'),
   gutil = require('gulp-util'),
   uncss = require('gulp-uncss'),
   rimraf = require('gulp-rimraf'),
   cleanCSS = require('gulp-clean-css');

gulp.task('clean-css-dist', function () {
   return gulp.src('dist/css/main.css', {read: false})
       .pipe(rimraf({force: true}));
});

gulp.task('clean-css-test', function () {
   return gulp.src('test/css/main.css', {read: false})
       .pipe(rimraf({force: true}));
});

gulp.task('sass',['clean-css-dist'], function () {
   return gulp.src('src/sass/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(gulp.dest('dist/css/'));
});

gulp.task('jade', function() {
   return gulp.src('src/jade/templates/*.jade')
       .pipe(jade())
       .pipe(gulp.dest('dist/'));
});

gulp.task('jade-test', function() {
   return gulp.src('src/jade/templates/*.jade')
       .pipe(jade())
       .on('error', gutil.log)
       .pipe(gulp.dest('test/'));
});

gulp.task('sass-test',['clean-css-test'], function () {
   return gulp.src('src/sass/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(gulp.dest('test/css/'));
});

gulp.task('uncss',['jade-test', 'sass-test'], function () {
   return gulp.src('test/css/main.css')
       .pipe(uncss({
           html: ['test/**/*.html']
       }))
       .pipe(gulp.dest('test/uncss'));
});

gulp.task('clean-css-production', function () {
   return gulp.src('prod/css/main.css', {read: false})
       .pipe(rimraf({force: true}));
});

gulp.task('sass-production',['clean-css-production'], function () {
   return gulp.src('src/sass/main.sass')
       .pipe(sass().on('error', sass.logError))
       .pipe(uncss({
           html: ['prod/**/*.html']
       }))
       .pipe(cleanCSS())
       .pipe(gulp.dest('prod/css/'));
});

gulp.task('jade-production', function() {
   return gulp.src('src/jade/templates/*.jade')
       .pipe(jade())
       .pipe(gulp.dest('prod/'));
});

gulp.task('production',['jade-production', 'sass-production']);

gulp.task('default', function () {
   gulp.watch('src/sass/*.sass', ['sass']);
   gulp.watch('src/jade/*.jade', ['jade']);
});
```

# 总结

在本章中，我们讨论了 Jade 模板系统的基础知识。我们看到了如何将其添加到前端开发人员的工作流程中。基于模板系统，你现在可以将 UnCSS 包含到你的流程中，并从 CSS 文件中删除不必要的代码。然后我们对最终结果进行了缩小，并创建了生产代码。

你可以将这个自动化工具视为项目的起点，并根据自己的项目进行调整。你也可以添加新功能并不断完善它。
