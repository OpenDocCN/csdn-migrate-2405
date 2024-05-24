# 精通响应式 Web 设计（四）

> 原文：[`zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B`](https://zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：响应式网页设计的有意义的排版

正如我在 Dayton Web Developers 会议上的一次演讲中所说的：

> *"有了稳固的排版比例，甚至可能不需要在网站上使用任何图片。"*

排版的力量一定是网页设计中最被低估的资产之一。诚然，我们看到越来越多的设计中，排版已经得到了充分考虑，在创建网站或应用程序预期氛围方面发挥了重要作用。

在本章中，我们的重点将放在从排版角度考虑 RWD 所需考虑的一些方面、技巧和窍门上。

我们将讨论：

+   像素、ems 或 rems 用于排版？

+   计算相对字体大小。

+   为和谐的排版创建模块化比例。

+   使用模块化比例进行排版。

+   网络字体及其对 RWD 的影响。

+   使用`FitText.js`进行流式标题大小。

+   使用`FlowType.js`来提高可读性。

# 像素、ems 或 rems 用于排版？

很难决定是使用像素、ems 还是 rems 进行排版。这是一个风格问题。一些网页设计师/开发人员仍然使用像素作为声明字体大小的单位。这样做只是更容易理解这些大小。

在设置像素字体大小方面的问题基本上出现在旧版 IE 上，如果用户因为任何原因想要放大页面，文本将保持在给定的像素大小不变。

现在，对于现代浏览器来说，这已经是过去的事情了。当你在任何现代浏览器中放大，如果放大到足够大，它将触发媒体查询，因此显示站点的移动版本。

基于像素的字体大小设置的另一个问题是很难进行缩放和维护。这基本上意味着我们需要在每个媒体查询中重复声明许多元素的字体大小。

另一方面，我们有相对单位，ems 和 rems，这基本上是设置我们的字体大小的推荐方式。

然而，ems 的问题在于我们必须跟踪（在脑海中、在 CSS/HTML 注释中或在某个文本文件中）父容器的大小，这很容易变成字体管理的噩梦。ems 中的字体大小取决于其父容器的字体大小。因此，如果我们有不同级别的嵌套容器，情况可能会变得非常复杂，因为跟踪父容器的字体大小并不容易。

但后来出现了*rem*。Rem 代表*根 em*。*根*是`<html>`元素。

Rems 基本上融合了两者的优点：我们可以使用相对单位 ems 声明 rems 中的字体大小，但又能像使用像素一样轻松理解。使用 rems 的唯一问题是旧版浏览器不支持这个单位，因此需要考虑基于像素的字体大小回退值。这就是一个简短的 Sass mixin 出现并拯救一天的地方。

但在尝试任何 Sass 技巧之前，让我们先从本章的核心策略开始。

# 计算相对字体大小

还记得我们在第三章中提到的 RWD 魔法公式吗，*Mobile-first or Desktop-first?*：

（目标 ÷ 上下文）x 100 = 结果%

还有另一个类似的魔法公式，用于计算相对字体大小（ems），当字体大小已经以像素设置时。唯一的区别是我们不乘以 100。

这就是那个公式：

目标 ÷ 上下文 = 结果

*目标*是以像素定义的字体大小。*上下文*是在父容器中定义的字体大小。*结果*是以 ems 定义的值。

以下是一个示例，假设父容器中的字体大小，在这个例子中是 body，为 16px：

```html
header {
    font: 30px Arial, "Helvetica Neue", Helvetica, sans-serif;
}
```

要计算相对字体大小，我们使用以下公式：

*30px ÷ 16px = 1.875em*。

因此，我们的 CSS 规则将如下所示：

```html
header {
    font: 1.875em Arial, "Helvetica Neue", Helvetica, sans-serif;
}
```

我们需要为设计中的每个字体大小都这样做。

在理解数学方面是可以的。然而，真正的价值在于创造这些基于像素的值的思考过程。这就是模块比例的价值所在。

# 创建和谐的排版模块比例

模块比例是由 Tim Brown 创建的。有不同的方法来创建用于排版的模块比例。在我们的例子中，我们将使用两个基本数字和一个比例来创建一个模块比例。这些数字的乘积创建了一个在所有值之间和谐和成比例的比例。

最著名的比例是*黄金比例*，也被称为*黄金分割*，*神圣比例*等等。它的值是*1.618*。

现在，为了避免不必要的数学计算，黄金比例是基于斐波那契数列的：1, 1, 2, 3, 5, 8, 13, 21 等等。

这些数字有以下的模式：下一个数字是前两个数字相加的结果。例如：

0 + **1** = 1 + **1** = 2 + **1** = 3 + **2** = 5 + **3** = 8 + **5** = 13 + **8** = 21…

这里的想法是理解创建一组数字的意图，当它们一起使用时是和谐的。我们将使用相同的方法来创建一个排版比例，以便在我们的项目中使用模块比例网页应用程序，并忘记*手动*计算项目的相对字体大小。

所以让我们来看看由 Tim Brown 和 Scott Kellum 构建的模块比例网页应用程序：[`www.modularscale.com/`](http://www.modularscale.com/)。

一旦网页应用程序打开，我们需要按照以下三个步骤来创建我们的模块比例：

1.  定义第一个基本数字。

1.  定义第二个基本数字。

1.  选择一个比例。

### 提示

模块比例可以用于任何使用某种值的东西，不仅仅是排版。它可以用于`填充`，`边距`，`行高`等等。然而，我们在本章的重点是排版。

## 定义第一个基本数字

定义第一个基本数字的推荐方法是使用正文文本大小，也就是段落中使用的字体大小。但请记住，使用正文文本大小作为第一个基本数字并不是强制性的。我们可以使用我们字体的 x 高度，或者在该字体中的其他长度，我们认为可能是一个很好的起点。

虽然我们可以选择任何字体大小，但让我们从我们都知道所有浏览器使用的默认字体大小开始，即 16px。所以我们在第一个基本字段中输入`16px`。

点击加号图标并添加第二个基本字段。

### 提示

暂时不用担心应用程序的字体大小预览，因为你可以看到，当我们为我们的基本值输入数字时，右侧预览窗格中的字体大小会改变。我们将在下一步中介绍这一点。

## 定义第二个基本数字

第二个基本字段是我称之为*魔术数字*，因为这个数字完全是主观和任意的，但它与我们正在进行的项目紧密相关。

当我说*紧密相关*时，我的意思是例如使用主容器的宽度，例如 960px，980px，1140px 等。或者，它也可以是网格中使用的列数，例如 12 或 16。它也可以是站点最大宽度处的列宽，例如 60px，甚至是间距，比如 20px。

这个*魔术数字*可以是我们想要的任何东西，但它与我们的项目有直接关系。在这个例子中，假设我们的目标是针对最大宽度为 1280px 的屏幕，所以我们的主容器将具有最大宽度为 1140px。所以让我们在第二个基本字段中输入`1140px`。

## 选择一个比例

这就是魔术发生的地方。选择一个比例意味着这个比例将与基本数字相乘，从而创建一个比例相关的值的比例。

这些比例是基于音乐音阶的，列表中还包括黄金比例（1.618），如果我们决定使用它的话。从**比例**下拉菜单中，选择**1:1.618 - 黄金分割**比例。

就是这样！我们现在已经创建了我们的第一个模块比例。

由模块比例提供的字体大小完全和谐，因为它们是相对于彼此的比例值，这些比例值与我们项目直接相关：

+   理想的正文字体大小是 16px

+   我们主容器的最大宽度是 1140px

+   黄金比例是 1.618

我们的排版现在有了坚实的模块基础，让我们使用它。

# 使用模块比例进行排版

如果您点击**表格**视图，所有文本现在都消失了，我们只剩下一系列字体大小，范围从非常小的值到非常大的值。但没关系。这就是模块比例的力量。

这是我们看到的：

![使用模块比例进行排版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_07_01.jpg)

如前面的图像所示，有三列：

+   第一列显示了像素单位的字体大小。

+   第二列显示了 em 单位的字体大小。

+   第三列显示了基准为 16px 时的字体大小。

我们需要专注于第一列和第二列。突出显示的 16px，或 1em 的行，将成为我们段落的字体大小。16px 是大多数浏览器中的默认字体大小。

然后，我们定义我们的标题元素。假设我们只定义`h1`，`h2`和`h3`。这意味着我们将选择大于 16px 的行，具有更大的字体大小：

+   `<h1>`：**39.269px**，即 2.454em

+   `<h2>`：**25.888px**，即 1.618em

+   `<h3>`：**24.57px**，即 1.517em

对于`<small>`元素，如果网站上有任何免责声明，我们选择小于 16px 的字体大小：

`<small>`：**9.889px**，即 0.618em

就是这样！模块比例中的所有数字都是和谐的，当一起使用时将提供清晰的视觉层次结构，以及通过其他方法难以获得的关系。

这里有一个例子。

这是 HTML：

```html
<h1>Meaningful Typography for RWD</h1>
<blockquote>
    <p>"With a solid typographic scale you might even get away with not using a single image on your website."</p>
    <p>— Ricardo Zea</p>
</blockquote>
<h2>Creating a Modular Scale for a Harmonious Typography</h2>
<p>A Modular Scale is a combination of a ratio of two or more numbers, and a base number.</p>
<h3>The Golden Ratio</h3>
<p>The most well-known ratio is the Golden Ratio also known as the Golden Section, Divine Proportion, etc. It's value is 1.618.</p>
```

这是 SCSS：

```html
//Mobile-first Media Query Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
body {
    font:16px/1.4 Arial, "Helvetica Neue", Helvetica, sans-serif;
    @include forLargeScreens(640) {
        font-size: 20px;
    }
}
h1 { font-size: 2.454em; }
h2 { font-size: 1.618em; }
h3 { font-size: 1.517em; }
```

### 提示

注意我也包含了移动优先的 Sass mixin。

这是编译后的 CSS：

```html
body {
    font: 16px/1.4 Arial, "Helvetica Neue", Helvetica, sans-serif;
}
@media (min-width: 40em) {
    body {
        font-size: 20px;
    }
}
h1 {
    font-size: 2.454em;
}
h2 {
    font-size: 1.618em;
}
h3 {
    font-size: 1.517em;
}
```

在小屏幕上（宽 510px）模块比例如下：

![使用模块比例进行排版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_07_02.jpg)

在大屏幕上（宽 850px）也是这样：

![使用模块比例进行排版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_07_03.jpg)

我们在这里唯一可能遇到的问题是我之前提到的关于使用 em 的问题：跟踪父元素的字体大小可能会变成字体管理的噩梦。

使用像素是不可取的，因为在传统浏览器中存在可伸缩性问题。然而，使用 rems 可以保持在“相对字体大小”领域，同时提供基于像素的思维方式，但没有可伸缩性问题。这使我们能够支持不支持 rems 的传统浏览器。

这是我在 CodePen 为此创建的演示：

[`codepen.io/ricardozea/pen/0b781bef63029bff6155c00ff3caed85`](http://codepen.io/ricardozea/pen/0b781bef63029bff6155c00ff3caed85)

## rems-to-pixels Sass mixin

我们只需要一个 Sass mixin，允许我们设置没有特定单位的字体值，mixin 会负责为现代浏览器添加 rem 单位的字体大小，为传统浏览器添加像素单位的字体大小。

这是由 Chris Coyer 创建的 Sass mixin：

```html
//Pixels to Rems Mixin
@mixin fontSize($sizeValue: 1.6) {
    font-size: ($sizeValue * 10) + px;
    font-size: $sizeValue + rem;
}
```

### 提示

我对 mixin 的原始名称进行了小修改，从使用破折号分隔改为驼峰命名法。我这样做的原因是因为在扫描文档时，从类名中更容易找到 mixin 的名称。

用法如下：

```html
@include fontSize(2);
```

这个示例使用了前一章节中使用的相同标记，所以我只会展示 SCSS 和一些截图。

SCSS 如下：

```html
//Mobile-first Media Query Mixin
@mixin forLargeScreens($media) {
    @media (min-width: $media/16+em) { @content; }
}
//Pixels to Rems Mixin
@mixin fontSize($sizeValue: 1.6) {
 font-size: ($sizeValue * 10) + px;
 font-size: $sizeValue + rem;
}
//Base-10 model
html { font-size: 62.5%;
    @include forLargeScreens(640) {
        font-size: 75%;
    }
}
h1 { @include fontSize(3.9269); }
h2 { @include fontSize(2.5888); }
h3 { @include fontSize(2.457); }
p { @include fontSize(1.6); }
```

考虑以下几点：

+   我们将根字体大小设置为 62.5％，将字体大小减小到 10px。这样声明字体值就容易得多。例如，1.2rem 的字体大小等同于 12px，.8rem 等同于 8px，依此类推。

+   在声明 rems 的字体大小时，我们需要将小数点从基于像素的值向左移一位。例如，根据我们的模块化比例，`<h1>`像素大小为 39.269px，所以在声明 rems 的字体大小时，我们声明为 3.9269，*不带单位*。

编译后的 CSS 如下：

```html
html {
    font-size: 62.5%;
}
@media (min-width: 40em) {
    html {
        font-size: 75%;
    }
}
h1 {
    font-size: 39.269px;
    font-size: 3.9269rem;
}
h2 {
    font-size: 25.888px;
    font-size: 2.5888rem;
}
h3 {
    font-size: 24.57px;
    font-size: 2.457rem;
}
p {
    font-size: 16px;
    font-size: 1.6rem;
}
```

这是在小屏幕上（510 像素宽）使用 rems-to-pixels mixin 的模块化比例的样子：

![rems-to-pixels Sass mixin](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_07_04.jpg)

这是在大屏幕上（850 像素宽）的样子：

![rems-to-pixels Sass mixin](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_07_05.jpg)

这是我在 CodePen 上创建的演示：

[`codepen.io/ricardozea/pen/8a95403db5b73c995443720475fdd900`](http://codepen.io/ricardozea/pen/8a95403db5b73c995443720475fdd900)

我们刚刚看到的示例使用了系统字体 Arial。让我们继续使用一些网络字体来提升这些示例的*特色*。

# 网络字体及其对 RWD 的影响

现在几乎必须使用网络字体，我说*几乎*是因为我们需要注意它们对我们项目的影响，如果必要，我们实际上可能根本不使用它们。

在深入研究如何使用网络字体之前，以下是一些可能对你们许多人有帮助的网络字体资源：

+   **Font Squirrel** ([`www.fontsquirrel.com/`](http://www.fontsquirrel.com/))：我已经广泛使用了这项服务并取得了巨大成功。要使用这些字体，你需要下载文件，然后在你的 CSS 中使用`@font-face`。他们有你能找到的最好的网络字体生成工具([`www.fontsquirrel.com/tools/webfont-generator`](http://www.fontsquirrel.com/tools/webfont-generator))

+   **Google Fonts** ([`www.google.com/fonts`](https://www.google.com/fonts))：我不能谈论网络字体资源而不提到 Google Fonts。如果我在 Font Squirrel 上找不到，我就来这里，反之亦然。你可以下载字体文件，或者使用 JavaScript。以下示例中使用的字体是从 Google Fonts 下载的([`github.com/google/fonts/tree/master/ofl/oswald`](https://github.com/google/fonts/tree/master/ofl/oswald))。

+   **Adobe Edge Web Fonts** ([`edgewebfonts.adobe.com/`](https://edgewebfonts.adobe.com/))：这也是一个很棒的工具。这项服务由 TypeKit（第一个网络字体服务）提供支持。我也广泛使用了 TypeKit。但你不能下载字体，必须使用 JavaScript。

现在，让我们看看使用网络字体的利弊：

优点包括：

+   它们有助于突出品牌，并在不同媒体上创建一致性。

+   正确使用时，它们使设计看起来更吸引人。

+   不再需要使用图像替换技术。

+   这使文本保持为 HTML，使内容更易访问和*可索引*。

+   旧版浏览器支持网络字体。

+   免费字体的绝佳资源。

+   所有这些都有助于保持标记更清洁。

缺点包括：

+   它们由于 HTTP 请求或对第三方服务器的依赖而减慢网站/应用的速度。

+   并非所有网络字体在小尺寸和/或大尺寸下都可读。

+   如果需要支持旧版浏览器，则需要管理更多文件。

+   使用字体需要付费：每月、每个字体系列、每种字体样式等等。

+   一些免费字体制作不良。

+   有渲染副作用：

+   **未样式文本的闪烁**（**FOUT**）：在现代浏览器上，当页面加载时，文本首先用系统字体呈现在屏幕上，然后一秒钟后被切换并用网络字体进行样式设置。

+   **不可见文本的闪烁**（**FOIT**）：在旧版浏览器上，当页面加载时，文本是不可见的，但一秒钟后它会用网络字体呈现出来。

还有其他不值得深入的，比如**备用文本的闪烁**和**伪文本的闪烁**（**FOFT**）。

如何解决所有“闪烁文本”的问题不在本节的范围之内。但是，我鼓励您阅读 Zach Leatherman 在 Opera 博客上关于*使用字体加载事件改进@font-face*的文章（[`dev.opera.com/articles/better-font-face/`](https://dev.opera.com/articles/better-font-face/)）。

# 用于实现网络字体的 Sass mixin

要实现网络字体，我们需要在我们的 CSS 中使用`@font-face`指令...嗯，SCSS。

`@font-face`声明块在其原始 CSS 形式中如下所示：

```html
@font-face {
    font-family: fontName;
    src: url('path/to/font.eot'); /*IE9 Compat Modes*/
    src: url('path/to/font.eot?#iefix') format('embedded-opentype'), /*IE6-IE8 */
        url('path/to/font.woff') format('woff'), /*Modern Browsers*/
        url('path/to/font.ttf') format('truetype'), /*Safari, Android, iOS*/
        url('path/to/font.svg#fontName') format('svg'); /*iOS devices*/
    font-weight: normal;
    font-style: normal;
}
```

现在，如果您使用多种样式或字体系列，您需要为每个字体文件重复整个`@font-face`声明块。这不是很干净（不要重复自己）。

### 提示

网络字体在文件大小和服务器请求方面都很昂贵，因此请适度使用网络字体。您使用的越多，您的网站/网络应用程序就会变得越慢。

是的，处理网络字体的 CSS 代码相当庞大，哦天啊。

为了保持理智，让我们将先前的`@font-face` CSS 声明块转换为 Sass mixin：

```html
@mixin fontFace($font-family, $file-path) {
    @font-face {
        font: {
            family: $font-family;
            weight: normal;
            style: normal;
        }
        //IE9 Compat Modes
        src: url('#{$file-path}.eot');
        //IE6-IE8
        src: url('#{$file-path}.eot?#iefix') format('embedded-opentype'),
        //Modern Browsers
        url('#{$file-path}.woff') format('woff'),
        //Safari, Android, iOS
        url('#{$file-path}.ttf') format('truetype'),
        //Safari, Android, iOS
        url('#{$file-path}.svg') format('svg');
    }
}
```

使用一行代码调用字体文件。让我们使用 Oswald 字体：

```html
@include fontFace(oswald-light, '../fonts/oswald-light');
```

在任何元素上使用它只需在字体堆栈的开头添加字体名称，如下所示：

```html
p { font: 2.2rem oswald-bold, Arial, "Helvetica Neue", Helvetica, sans-serif; }
```

如果我们需要包含多个字体文件，只需添加另一行调用 mixin，但指定其他字体名称：

```html
@include fontFace(oswald-light, '../fonts/oswald-light');
@include fontFace(oswald-regular, '../fonts/oswald-regular');

```

前两行代码将编译为以下 CSS：

```html
@font-face {
    font-family: oswald-light;
    font-weight: normal;
    font-style: normal;
    src: url("../fonts/oswald-light.eot");
    src: url("../fonts/oswald-light.eot?#iefix") format("embedded-opentype"), url("../fonts/oswald-light.woff") format("woff"), url("../fonts/oswald-light.ttf") format("truetype"), url("../fonts/oswald-light.svg") format("svg");
}
@font-face {
    font-family: oswald-regular;
    font-weight: normal;
    font-style: normal;
    src: url("../fonts/oswald-regular.eot");
    src: url("../fonts/oswald-regular.eot?#iefix") format("embedded-opentype"), url("../fonts/oswald-regular.woff") format("woff"), url("../fonts/oswald-regular.ttf") format("truetype"), url("../fonts/oswald-regular.svg") format("svg");
}
```

这是一种非常巧妙的方式，只需两行代码就可以创建所有这些 CSS，是吧？然而，如果我们想做正确的事情，让我们分析一下我们在这里做什么：

+   我们支持旧版浏览器：

+   IE8 及以下版本使用`.eot`字体。

+   在 iOS 上的旧版 Safari 和 Android 上使用`.ttf`字体。

+   旧版 iOS 适用于几乎被遗忘的 iPhone 3 及以下版本，使用`.svg`文件。

+   现代浏览器只需要`.woff`字体。根据 CanIUse.com 的数据，`.woff`字体文件有 99%的支持率，除了 Opera Mini 在撰写本书时（[`caniuse.com/#search=woff`](http://caniuse.com/#search=woff)）。

因此，问题是：我们是否可以优雅地降级旧版浏览器和操作系统的体验，并让它们使用系统字体？

当然可以！

在优化 mixin 以仅使用`.woff`字体后，它看起来是这样的：

```html
@mixin fontFace($font-family, $file-path) {
    @font-face {
        font: {
            family: $font-family;
            weight: normal;
            style: normal;
        }
      //Modern Browsers
        src: url('#{$file-path}.woff') format('woff');
    }
}
```

使用方式完全相同：

```html
@include fontFace(oswald-light, '../fonts/oswald-light');
@include fontFace(oswald-regular, '../fonts/oswald-regular');
```

编译后的 CSS 要短得多：

```html
@font-face {
    font-family: oswald-light;
    font-weight: normal;
    font-style: normal;
    src: url("../fonts/oswald-light.woff") format("woff");
}
@font-face {
    font-family: oswald-regular;
    font-weight: normal;
    font-style: normal;
    src: url("../fonts/oswald-regular.woff") format("woff");
}
```

在几个元素上使用它看起来像这样：

```html
h1 { font: 4.1rem oswald-regular, Arial, "Helvetica Neue", Helvetica, sans-serif; }
p { font: 2.4rem oswald-light, Arial, "Helvetica Neue", Helvetica, sans-serif; }
```

仅提供`.woff`字体可以减少我们的文件管理工作量，有助于解放我们的大脑，让我们专注于最重要的事情：构建一个令人难忘的体验。更不用说，它使我们的 CSS 代码更加简洁和可扩展。

但等等，我们让旧版浏览器优雅地降级到系统字体，我们仍然需要为它们定义像素字体大小！

像素到 rems Sass mixin 来拯救！

记得在`<html>`标签中查看十进制模型以便更容易计算：

```html
//Base-10 model
html { font-size: 62.5%; }
```

然后让我们声明字体大小和字体系列：

```html
h1 {
    @include fontSize(4.1);
    font-family: oswald-regular, Arial, "Helvetica Neue", Helvetica, sans-serif;
}
p {
    @include fontSize(2.4);
    font-family: oswald-light, Arial, "Helvetica Neue", Helvetica, sans-serif;
}
```

编译后的 CSS 如下所示：

```html
h1 {
    font-size: 41px;
    font-size: 4.1rem;
    font-family: oswald-regular, Arial, "Helvetica Neue", Helvetica, sans-serif;
}

p {
    font-size: 24px;
    font-size: 2.4rem;
    font-family: oswald-light, Arial, "Helvetica Neue", Helvetica, sans-serif;
}
```

### 提示

我们在同一规则中声明了两个不同的字体大小，因此在这种情况下我们不能使用字体简写。

因此，通过利用两个简单的 Sass mixin 的超能力，我们可以轻松嵌入网络字体，并为我们的字体大小使用 rems，同时为旧版浏览器提供基于像素的字体大小。

这是一个强大可扩展性的很好的例子。

这是我在 CodePen 上创建的演示：

[`codepen.io/ricardozea/pen/9c93240a3404f12ffad83fa88f14d6ef`](http://codepen.io/ricardozea/pen/9c93240a3404f12ffad83fa88f14d6ef)

在不失去任何动力的情况下，让我们转变思路，谈谈如何通过使用 Simple Focus 的强大 FlowType.js jQuery 插件来实现最小行长，从而提高页面的可读性。

# 使用 FlowType.js 增加可读性

最具说服力的编辑原则之一是，最易读的排版的理想行长在 45 到 75 个字符之间。

如果你问我，这是一个相当不错的范围。然而，实际上让你的段落足够长，或者足够短，就像一个“盲人引导盲人”的游戏。我们怎么知道容器的宽度和字体大小的组合是否真正符合 45 到 75 个字符的建议？此外，在小屏幕或中等屏幕上，你怎么知道情况是这样的？

棘手的问题，对吧？

好吧，不用担心，因为有了 FlowType.js，我们可以解决这些问题。

你可以从[`simplefocus.com/flowtype/`](http://simplefocus.com/flowtype/)下载这个插件。

我们需要的第一件事是 HTML，所以这是我们将要使用的标记：

```html
<!DOCTYPE html>
<!--[if IE 8]> <html class="no-js ie8" lang="en"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="en"> <![endif]-->
<!--[if gt IE 9]><!--><html class="no-js" lang="en"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Meaningful Typography for RWD</title>
    <script src="img/"></script>
    <script src="img/flowtype.js"></script>
</head>
<body>
    <main class="main-ctnr" role="main">
        <h1>Meaningful Typography for RWD</h1>
        <blockquote>
            <p>"With a solid typographic scale you might even get away with not using a single image on your website."</p>
            <p>— Ricardo Zea</p>
        </blockquote>
        <p>One of the most compelling editorial principles states that the ideal line length for the most legible typography is between 45 and 75 characters.</p>
    </main>
</body>
</html>
```

一旦你熟悉了 FlowType.js，你可能会开始思考，“如果 FlowType 自动在几乎任何视口宽度下修改字体大小，我觉得我不需要在我的 SCSS 中声明任何字体大小！毕竟，它们将被 FlowType 覆盖。”

好吧，我们确实需要设置字体大小，因为如果 FlowType.js 没有加载，我们将受制于浏览器的默认样式，而我们设计师不想要这样。

说到这里，这是声明必要字体大小的 SCSS：

```html
//Pixels to Rems Mixin
@mixin font-size($sizeValue: 1.6) {
    font-size: ($sizeValue * 10) + px;
    font-size: $sizeValue + rem;
}
//Base-10 model
html { font-size: 62.5%; }
h1 { @include fontSize(3.9269); }
p { @include fontSize(1.6); }
```

这将编译成以下 CSS：

```html
html {
    font-size: 62.5%;
}
h1 {
    font-size: 39.269px;
    font-size: 3.9269rem;
}
p {
    font-size: 16px;
    font-size: 1.6rem;
}
```

这就是魔法发生的地方。我们创建一个 jQuery 函数，可以指定要定位的元素。这个函数可以放在一个单独的 JavaScript 文件中，也可以放在标记中。

在我们的示例中，我们告诉 FlowType.js 将字体的调整应用到`<html>`元素上。由于我们使用相对字体大小单位 rems，所有文本将在任何屏幕宽度下自动调整大小，保持理想的行长度。

这是 jQuery 函数：

```html
$(function() {
    $("html").flowtype();
});
```

## 定义阈值

我们刚刚看到的解决方案存在潜在问题：FlowType.js 将无限期地修改段落的字体大小。换句话说，在小屏幕上，文本将变得非常小，在大屏幕上，文本将变得太大。

我们可以用两种不同的阈值方法或两者结合来解决这个问题。

现在，我们需要澄清的一件事是，这部分需要一些调整和调整，以获得最佳结果，没有特定的值适用于所有情况。

我们将采用以下方法：

+   定义容器或元素的最小和最大宽度。

+   定义容器或元素的最小和最大字体大小。

### 阈值宽度

定义最小和最大宽度将告诉 FlowType.js 在哪些点停止调整大小。

让我们定义宽度阈值：

```html
$(function() {
    $("html").flowtype({
      //Max width at which script stops enlarging
        maximum: 980,
      //Min width at which script stops decreasing
      minimum: 320
   });
});
```

### 提示

我选择的阈值专门适用于这个示例，可能不适用于其他情况。调整和测试，直到你得到适合推荐的每行 45-75 个字符的理想宽度。

### 阈值字体大小

就像宽度阈值一样，定义最小和最大字体大小将告诉 FlowType.js 应该将文本缩放到的最小和最大字体大小。

我们还将使用`fontRatio`变量声明自己的字体大小；数字越大，字体越小，数字越小，字体越大。如果这感觉反直觉，可以这样理解：数字越大，压缩越大（因此变小），数字越小，压缩越小（因此变大）。

调整`fontRatio`值是一个*凭感觉*的练习，所以像没有明天一样调整和测试。

让我们看一下字体大小的值：

```html
$(function() {
 $("html").flowtype({
      //Max width at which script stops enlarging
      maximum: 980,
      //Min width at which script stops decreasing
      minimum: 320,
      //Max font size
      maxFont : 18,
      //Min font size
      minFont : 8,
 //Define own font-size
 fontRatio : 58
   });
});
```

### 提示

在列表中的最后一个值后面不需要包含逗号。

FlowType.js 真的很棒！

这是我在 CodePen 上创建的演示：

[`codepen.io/ricardozea/pen/c2e6abf545dbaa82a16ae84718c79d34`](http://codepen.io/ricardozea/pen/c2e6abf545dbaa82a16ae84718c79d34)

# 总结

所以在这里，我们在 RWD 的排版上升了一个层次。排版还有更多内容吗？当然有！这个令人惊叹的主题本身就是一个完整的行业，没有它我们就不会读到这本书。

现在我们可以说，我们明白为什么使用相对单位进行排版是一个好方法：可伸缩性。此外，使用我们的小魔法公式，我们可以计算设计中每个文本元素的相对字体大小，但为什么要经历这么多麻烦呢？排版的模块化比例在这方面拯救了我们，并为我们的项目注入了令人惊叹的排版和谐。谁知道，也许我们根本不需要使用图片！

品牌现在可以通过网络字体扩展到网络上，但我们需要谨慎考虑它们对我们网站/应用的影响。另外，就现代浏览器而言，我们只需要使用一种文件类型（WOFF 字体文件），这样可以更容易地管理——对于浏览器下载和用户享受都更方便。

FlowType.js 增强了我们的标题和正文文本，同时保持了良好的可读性水平。

现在，RWD 的一个重要部分是（信不信由你）做一些我们多年前做过的事情。在下一章中，我们将保持简单，讨论电子邮件中的 RWD。

是时候回到过去了！


# 第八章：响应式电子邮件

在我们回到过去之后，我们来想一想 90 年代末使用表格进行设计；是的，你没看错，使用表格进行设计。

今天，在创建电子邮件方面并没有任何不同：我们必须使用表格进行布局。为什么？很简单。没有任何战争。那就是电子邮件客户端之间的竞争。

与 1995 年的浏览器之战不同，当时 Netscape 和 Internet Explorer 为市场霸权而战，电子邮件客户端自从有记忆以来就一直过着各自独立的生活，几乎对彼此毫不在意。

由于浏览器之战，我们现在拥有了这样一些非常棒的符合标准的浏览器，它们充满了功能、定制能力、不断的更新等等，使每个人的在线生活变得更加轻松。

另一方面，电子邮件客户端以自己的步伐发展，而且步伐很慢，因为实际上没有任何竞争。此外，绝大多数公司已经与微软的 Outlook 绑定在一起。在 Office 的最新版本中，Outlook 实际上比早期版本更糟糕，因此并没有真正帮助电子邮件领域支持更现代的技术。

此外，有一些相对较新的电子邮件客户端彻底拒绝支持`<style>`元素甚至媒体查询。

但是，无论技术水平如何，电子邮件都是一种非常高效和强大的营销工具，我们需要准备好迟早要使用它。

换句话说，作为一种沟通媒介，电子邮件不会很快消失，我们作为网页设计师/开发人员必须使用表格和内联样式设计电子邮件。

但不要担心，我会向你展示，通过使用 RWD 的基本原则，一点点常识，采用渐进增强，并且始终试图保持简单，设计和实现响应式电子邮件并不困难，而且可以很有趣。

在本章中，我们将讨论以下主题：

+   我们为什么需要担心响应式电子邮件？

+   不要忽视你的分析。

+   响应式电子邮件需要考虑的事项。

+   响应式电子邮件构建。

+   第三方服务。

# 我们为什么需要担心响应式电子邮件？

我们需要担心响应式电子邮件的主要原因很简单：大约 65%的电子邮件是在移动设备（智能手机和平板电脑）上打开的。其余 35%的电子邮件是在桌面上打开的。此外，响应式电子邮件比非响应式电子邮件有更多的参与度。

除此之外，在桌面上打开的电子邮件比在移动设备上打开的电子邮件有更多的参与度。

查看以下文章：

+   *美国近 65%的电子邮件是在移动设备上打开的*：[`www.internetretailer.com/2014/01/23/nearly-65-e-mails-us-are-opened-mobile-devices`](https://www.internetretailer.com/2014/01/23/nearly-65-e-mails-us-are-opened-mobile-devices)

+   *上季度 65%的营销电子邮件是在移动设备上打开的；安卓平板使用量翻了一番*：[`www.phonearena.com/news/65-of-marketing-emails-were-opened-on-a-mobile-device-last-quarter-Android-tablet-use-doubles_id51864`](http://www.phonearena.com/news/65-of-marketing-emails-were-opened-on-a-mobile-device-last-quarter-Android-tablet-use-doubles_id51864)

### 提示

术语*参与*意味着用户点击/轻敲。因此，*更多参与*简单地意味着*更多点击/轻敲*。

# 不要忽视你的分析

在开始推动像素、嵌套表格和样式元素之前，绝对必要的是我们看一下分析数据，全面了解我们将为之创建电子邮件的环境。

这样做将使我们了解：

+   我们的电子邮件是在何时被打开的。

+   哪些日子有更多的开放。

+   哪些时间段有更多的开放。

+   无论季节是否导致更多/更少的开放。

+   哪些设备被用来打开我们的电子邮件。

+   哪些电子邮件客户端被最多/最少使用。

例如，如果分析数据表明 Outlook 2013 很少被使用（这将是很棒的），那么我们可能根本不需要担心这个电子邮件客户端。

如果安卓上的 Yahoo Mail 应用是最常用的应用和平台，那么我们可以放心地使用更高级的 CSS 属性，并逐步增强，知道我们的想法将正确显示。

进行市场份额研究很重要，但最终决定如何制定电子邮件开发策略的是你自己的分析数据。

# 建议构建更好的响应式电子邮件

尽管一些电子邮件客户端在呈现电子邮件方面变得更好了，但还有其他电子邮件客户端并不如他们应该的那样好。这意味着我们需要构建一些基本的东西，并逐步增强以适应更好的电子邮件客户端。

在构建响应式电子邮件时，有一些重要的准则需要考虑：

+   **确定支持 HTML 和 CSS 最少的电子邮件客户端**：了解哪个电子邮件客户端对 HTML 和 CSS 的支持最少将在测试过程中节省我们不必要的麻烦和时间。再次强调，这就是分析数据至关重要的地方。

+   **使用渐进增强**：首先，设计和构建支持 CSS 和 HTML 最少的电子邮件客户端。然后，我们使用这个核心基础来增强设计和体验。

+   **保持在 550px 至 600px 的宽度范围内**：这非常重要，因为大多数电子邮件客户端的预览窗格非常窄。此外，600px 或更少在桌面客户端和网页浏览器上看起来都很好，而且在小屏幕上缩小或响应式时，电子邮件仍然可读。

+   **使用表格进行布局**：大多数电子邮件客户端对 HTML 和 CSS 的支持远远不及网页浏览器，因此使用表格来构建布局仍然是创建电子邮件的方法。

+   **内联 CSS**：许多电子邮件客户端会移除电子邮件的`<head>`部分，因此我们放在那里的任何东西都会被剥离。因此，我们需要内联 CSS 以实现必要的样式。

+   **使用系统字体**：虽然技术上可以使用网络字体，最好还是使用系统字体，这样可以使电子邮件在不同设备和不同电子邮件客户端上尽可能相似。但是，如果你决定使用网络字体，那就去做吧，并始终将它们作为渐进增强过程的一部分使用。

+   **为背景图像提供备用颜色**：使用背景图像并不是很困难。Outlook 是唯一需要特殊标记（条件注释）才能使其工作的客户端。然而，始终提供一个备用的背景颜色，以防图像无法加载。

+   **始终在图像上使用 alt 属性**：如果图像无法加载或加载速度过慢，电子邮件客户端将显示替代文本。确保在`alt`属性中放入一些描述性的内容。与其使用*Logo*，最好使用*公司标志-标语*之类的内容。

+   **不需要先考虑移动端**：因为我们正在进行渐进增强，我们从支持 HTML 和 CSS 最少的电子邮件客户端开始。因此，这个电子邮件客户端很可能不支持媒体查询或`viewport`元标记。因此，移动优先的方法可能并不是最佳选择，至少目前还不是。

+   **使用 HTML5 DOCTYPE**：我们当然可以使用旧的 HTML4 DOCTYPE，但也可以使用 HTML5 DOCTYPE，这总是一个好的措施。

+   **避免使用 HTML5 元素**：尽管我们可以使用 HTML5 DOCTYPE，但对 HTML5 元素的支持实际上几乎不存在。因此，在电子邮件中避免使用 HTML5 元素。

+   **保持简单**：大多数电子邮件的寿命很短，因此制作复杂的布局并不是必要的。创建一个简单的单列布局会节省我们很多麻烦。要着重关注设计本身。这就是一个坚实的排版模块化比例可以发挥奇迹的地方。

# 响应式电子邮件构建

定义电子邮件的特性也是*构建*的一部分，所以让我们来定义这些：

1.  为排版创建一个模块比例。

1.  创建两种设计来帮助预先可视化电子邮件：一种用于大屏幕，一种用于小屏幕。

1.  电子邮件的最大宽度为 600px，最小宽度为 320px。

1.  使用渐进增强。

## 排版的模块比例

为了构建我们的模块比例，我们将使用以下值：

+   **基础一**（16px）：这是我们的基本字体大小。

+   **基础二**（600px）：这是我们电子邮件的最大宽度。

+   **比例**（1.618）：黄金比例。

这个模块比例可以在[`www.modularscale.com/?16,600&px&1.618&web&table`](http://www.modularscale.com/?16,600&px&1.618&web&table)找到。

![排版的模块比例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_01.jpg)

## 设计-大屏幕和小屏幕视图

以下的设计将有助于更好地了解大屏幕和小屏幕上的电子邮件。这是它在 600px 宽时的样子：

![设计-大屏幕和小屏幕视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_02.jpg)

这是电子邮件在最小尺寸（320px 宽）下的样子：

![设计-大屏幕和小屏幕视图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_03.jpg)

让我们立即着手构建一个响应式的电子邮件。

## 设置基本的 HTML 模板

让我们从最基本的模板开始。然后，我们将添加需要的不同元素，以建立一个完整的模板。

以下是 HTML 的第一次尝试，其中包含`<head>`部分的一些初始元素：

+   使用`lang`属性定义文档的语言，我们的情况下是英语。

+   由于我们的设计具有彩色背景，我们需要给`<html>`和`<body>`元素一个 100%的高度。这样两个元素就会延伸到视口的全高度。否则，背景将在电子邮件底部结束，然后页面将显示白色背景。

+   添加一个`<title>`标签。

+   添加以下 meta 标签：

+   字符集 UTF-8

+   视口

+   使 Internet Explorer 使用可能的最新渲染引擎

+   移除 OSX/iOS 中电话号码的自动样式。

+   谁说我们不能使用网络字体？只有少数几个电子邮件客户端支持它们，不支持的将会回退到我们字体堆栈中的系统字体，很可能是 Arial 或 Helvetica。让我们使用 Roboto。

以下是 HTML：

```html
<!DOCTYPE html>
<html lang="en" style="height: 100%;">
<head>
    <title>Mastering RWD with HTML5 and CSS3</title>
 <meta charset="utf-8">
 <!-- Responsive: Tell browsers that this template is optimized for small screens -->
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <!-- IE: Make IE use its best rendering engine rather than Compatibility View mode -->
 <meta http-equiv="X-UA-Compatible" content="IE=edge">
 <!-- OSX/iOS: Remove auto styling of phone numbers -->
 <meta name="format-detection" content="telephone=no">
 <!-- Webfont from Google Fonts -->
 <link href='http://fonts.googleapis.com/css?family=Roboto:300,500' rel='stylesheet'>
</head>
<body style="height: 100%;">

</body>
</html>
```

### 使用 CSS 重置来规范显示

让我们添加必要的 CSS 重置样式，以帮助在尽可能多的电子邮件客户端上保持相对统一的显示。

以下列表概述了我们将在多个电子邮件客户端上*重置*（也称为*规范化*）的确切内容：

+   **Outlook（所有版本）**：

+   强制它提供“在浏览器中查看”链接。

+   使其保持任何自定义行高的定义。

+   删除`<table>`元素左右两侧的空格。

+   修复填充问题。

+   **OSX/iOS/Windows Mobile**：

+   修复字体小的时候自动增加字体大小到 13px 的问题。

+   **Yahoo**：

+   修复段落问题。

+   **IE**：

+   修复调整大小的图像问题。

+   **Hotmail/Outlook.com**：

+   使其以全宽度显示电子邮件。

+   强制它显示正常的行间距。

+   **所有电子邮件客户端**：

+   移除链接图像周围的边框。

以下是嵌入的 CSS：

```html
<!DOCTYPE html>
<html lang="en" style="height: 100%;">
<head>
    <title>Mastering RWD with HTML5 and CSS3</title>
    <meta charset="utf-8">
    <!-- Responsive: Tell browsers that this template is optimized for small screens -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- IE: Make IE use its best rendering engine rather than Compatibility View mode -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!-- OSX/iOS: Remove auto styling of phone numbers -->
    <meta name="format-detection" content="telephone=no">
    <!-- Webfont from Google Fonts -->
    <link href='http://fonts.googleapis.com/css?family=Roboto:300,500' rel='stylesheet'>
    <style>
        /*Force Outlook to provide a "View in Browser" link.*/
 #outlook a { padding: 0; }
        body {
            width: 100% !important;
            margin: 0;
            padding: 0;
            /*Outlook: Make Outlook maintain any custom line heights defined.*/
 mso-line-height-rule: exactly;
 /*OSX/iOS/Windows Mobile: Fix automatic increasing of font size to 13px when fonts are small.*/
 -webkit-text-size-adjust: 100%;
 -ms-text-size-adjust: 100%;
 }
 /*Yahoo: Fix paragraph issue*/
 p { margin: 1em 0; }
 /*Outlook: Remove spaces on left and right side of a table elements.*/
 table {
 mso-table-lspace:0pt;
 mso-table-rspace:0pt;
 }
 /*Outlook 07, 10: Fix padding issue.*/
 table td { border-collapse: collapse; }
 img {
 outline: none;
 text-decoration: none;
 /*IE: Make resized images look fine.*/
 -ms-interpolation-mode: bicubic;
 }
 /*Remove border around linked images.*/
 a img { border: none; }
 /*Prevent Webkit and Windows Mobile platforms from changing default font sizes, while not breaking desktop design.*/
 /*Force Hotmail to display e-mails at full width.*/
 .ExternalClass{ width:100%; }
 /*Force Hotmail to display normal line spacing.*/
 .ExternalClass,
 .ExternalClass p,
 .ExternalClass span,
 .ExternalClass font,
 .ExternalClass td,
 .ExternalClass div {
 line-height: 100%;
 }
    </style>
</head>
<body style="height: 100%;">

</body>
</html>
```

有了这个基本模板，让我们开始添加内容。

### 添加电子邮件内容

构建电子邮件基本上是一种“你必须做你必须做的事情！”的心态。换句话说，我们必须做任何我们必须做的事情，以便使事物显示为我们想要的样子。有时，我们必须使用不间断空格（`&nbsp;`）来分隔事物，使用`<br>`标签使事物进入下一行，甚至使用多个`<br>`标签在元素之间创建空间。

然而，这并不意味着我们要把学到的所有好东西都抛到脑后，绝对不是。

让我们尽可能地保持清洁和简洁，必要时进行嵌套，并在需要时添加必要的样式。

### 提示

为了优化空间并帮助专注于重要部分，我们将只处理`<body>`标签内的标记。

#### 创建一个 100%宽度的包裹表格

这是我们最外层的表格容器，始终将其作为一个良好的实践。这个表格将允许我们处理我们设计中想要或需要的任何填充，因为在`<body>`标签上添加填充可能不是一种可靠的方法。

如果我们的设计有背景颜色，我们也可以使用这个外部表格来添加背景颜色。我们将给这个外部表格设置 100%的宽度和高度。

我们还在单元格中添加了 20 像素的填充；这将给整个电子邮件留出一些空间，因为它不会触及视口/面板的顶部和底部边缘。代码如下：

```html
<body style="height: 100%;">
 <table width="100%" height="100%" cellpadding="20" cellspacing="0" border="0" bgcolor="#efefef" class="outer-container-table">
 <tr>
 <td align="center"> </td>
 </tr>
 </table>
</body>
```

### 提示

我在电子邮件中为一些元素添加了类，可能并不是立即使用。无论如何，我都会添加这些类，以防将来发生变化，我已经有了这些类，并且可以更快地进行编辑。

#### 创建 600 像素的内部表格

我们使用 HTML 属性`width`声明了这个内部表格的宽度，而不是在内联样式中声明宽度。我们还给这个表格添加了白色背景，这样我们的内容就可以覆盖它，并阻止宽容器的浅灰色背景。

可以使用边框简写添加 1 像素的边框。有人说不要在电子邮件中使用 CSS 简写！然而，在测试了几个电子邮件客户端之后，简写效果非常好。

在顶部添加 10 像素的边距将有助于给电子邮件留出更多空间。代码如下：

```html
<body style="height: 100%;">
    <table width="100%" height="100%" cellpadding="20" cellspacing="0" border="0" bgcolor="#efefef" class="outer-container-table">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="white" align="center" class="inner-container-table" style="margin-top: 10px; border: #999999 1px solid;">
 <tr>
 <td></td>
 </tr>
 </table>
            </td>
        </tr>
    </table>
</body>
```

注意我在`.inner-container-table`的背景颜色上使用了术语*white*？这是因为我想告诉你，你也可以使用 HTML 颜色名称而不是十六进制值。所有电子邮件客户端都支持这个功能。这也更具描述性。

在公开网络上有很多资源列出了所有 HTML 颜色名称，但我特别喜欢这个，因为它将颜色名称按类别分组。因此，在设计中更容易使用：[`html-color-codes.info/color-names/`](http://html-color-codes.info/color-names/)。

#### 添加页眉图像

在空的`<td>`元素中，我们需要做的就是添加调用页眉图像的`<img>`标签。

图像默认为`inline-block`元素。为了避免不需要的行为，请确保图像具有`display: block;`和`width: 100%;`元素，如下所示：

```html
<body style="height: 100%;">
   <table width="100%" cellpadding="0" cellspacing="20" border="0" bgcolor="#efefef" style="height: 100%;" class="outer-container-table">
      <tr>
         <td align="center">
            <table width="580" cellpadding="0" cellspacing="0" border="0" bgcolor="white" align="center" class="inner-container-table" style="margin-top: 10px; border: #999999 1px solid;">
               <tr>
                  <td>
                     <img src="img/header-email-devices.png" alt="Mastering RWD with HTML and CSS3" style="display: block; width: 100%;">
                  </td>
               </tr>
            </table>
         </td>
      </tr>
   </table>
</body>
```

#### 创建内容包装表格及其所有内容

这是大部分魔术发生的地方，因为我们现在正在创建电子邮件的主体，包括页脚。需要注意的几件事：

+   第一个表格的宽度为 88%。我这样做是为了向你展示，如果你愿意，你可以是任意的。此外，你不必每次都使用像素，使用百分比时也可以使用不同于 100%的其他值。

+   在某些部分，我大量使用`<br>`标签。这是因为我希望一些元素之间的间距在我想要的位置。在其他情况下，这将是一个相当糟糕的做法；在电子邮件中，这样做非常有用，也很常见。

+   我们将使用三行：一行用于主标题，一行用于正文，一行用于**呼吁行动**（**CTA**）按钮。这样做将允许我们独立处理每个部分，而无需担心在调试或样式化时影响其他两个部分。

+   页脚将与主要内容结构分开，因此我们可以轻松处理背景图片。

标记如下：

```html
<body style="height: 100%;">
    <table width="100%" height="100%" cellpadding="20" cellspacing="0" border="0" bgcolor="#efefef" class="outer-container-table">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="  white" align="center" class="inner-container-table" style="margin-top: 10px; border: #999999 1px solid;">
                    <tr>
                        <td>
                            <img src="img/header-email-devices.png" alt="Mastering RWD with HTML and CSS3" style="display: block; width: 100%;">
                        </td>
                    </tr>
                    <tr>
 <td align="center">
 <table width="88%" cellpadding="0" cellspacing="0" border="0" align="center" class="content-table">
 <tr>
 <td align="center">
 <table width="100%" cellpadding="10" cellspacing="0" border="0" align="center">
 <tr>
 <td style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 500; font-size: 33.441px; text-align: center;"><br>Mastering RWD<br>with HTML5 and&nbsp;CSS3</td>
 </tr>
 <tr>
 <td>
 <h2 style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 500; font-size: 25.888px;">Responsive Emails</h2>
 <p style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 300; font-size: 16px; line-height: 26px">And here we sare after traveling back in time: think of late 90's and designing with tables, oh yes you read right, designing with&nbsp;tables.</p>
 <p style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 300; font-size: 16px; line-height: 26px"> And today things are not any different when it comes to creating e-mails: we have to use tables for&nbsp;layout.</p>
 <p style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 300; font-size: 16px; line-height: 26px">Why? Simple. There aren't any wars. Email client wars that is&hellip;&nbsp;(continued).</p>
 </td>
 </tr>
 <tr>
 <td style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight:300; font-size: 25.888px; text-align:center;">
 <br>
 <a href="#" target="_blank" style="padding: 20px 30px; border: #663300 2px solid; border-radius: 5px; text-decoration: none; color: white; background: #ff8000;" class="main-cta">Get the Book! &raquo;</a>

 <br><br><br>
 </td>
 </tr>
 </table>
 </td>
 </tr>
 </table>
 </td>
 </tr>
 <tr>
 <td>
 <table width="100%" cellpadding="0" cellspacing="0" border="0" class="footer-table-ctnr" style="background: #666666; background: linear-gradient(#333, #666);">
 <tr>
 <td background="https://s3-us-west-2.amazonaws.com/s.cdpn.io/9988/trianglify-black.png">
 <table width="95%" align="center" cellpadding="30" cellspacing="0" border="0">
 <tr>
 <td style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 300; font-size: 12px; line-height: 20px; color: white;">
 <p style="margin: 0;"><span style="font-weight: 500;">Book:</span> Mastering RWD with HTML5 and&nbsp;CSS3</p>
 <p style="margin: 0;"><span style="font-weight: 500;">Author:</span> Ricardo Zea</p>
 <p style="margin: 0;"><span style="font-weight: 500;">Publisher:</span> Packt Publishing</p>
 <br>
 <p>&copy; All Rights Reserved - <a href="#" style="color: white;">Unsubscribe</a></p>
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
```

到目前为止，电子邮件看起来是这样的：

![创建内容包装表格及其所有内容](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_02.jpg)

我们完成了！我们？还没有，我们还有一些事情要做：

+   为页脚和 CTA 按钮添加 Outlook 2007/2010/2013 条件注释的黑客。

+   添加媒体查询。

+   添加 Outlook 网络字体回退样式。

#### 添加 Outlook 2007/2010/2013 条件注释黑客

就像在基于表格的布局时代的 IE 一样，Outlook 在桌面电子邮件客户端的领域中占据主导地位。因此，在创建电子邮件时，我们不能忽视这个客户端。

这一切都很好，问题在于大多数 Outlook 版本的 HTML 渲染能力非常差，因此通过条件注释进行 HTML hack（不幸的是）是必要的。它们并不难实现；您只需要知道何时实现它们。

条件注释对于背景图像和大型 CTA 按钮非常有用。在我们的示例中，我们都有：页脚中的黑色/灰色三角形背景图案和橙色**获取图书»** CTA（呼吁行动）。

在下面的标记中，您将能够注意到以下几点：

+   条件注释只包裹元素。换句话说，确保您不要包裹比所需更多的元素，否则我们将制造更多问题而不是解决方案。

+   页脚和 CTA 按钮都要求我们在两个地方进行编辑：元素本身和条件注释内部。

+   电子邮件条件注释看起来相当晦涩；它们不遵循任何标准，因为它们是专有技术。把它们看作是渐进增强的一部分而不是一部分。它们是一种彻头彻尾的 hack。

+   编辑条件注释并不太困难。可定制的部分要么是内联 CSS 属性/值，要么是图像的`src`属性——这些都不是我们以前没有见过的。

### 提示

为了清晰起见并涵盖本书的范围，我只会向您展示两个包含在条件注释中的部分。

##### 页脚背景图像的条件注释

这就是 HTML 的样子：

```html
<td background="https://s3-us-west-2.amazonaws.com/s.cdpn.io/9988/trianglify-black.png">
 <!--[if gte mso 9]>
 <v:rect  strokecolor="none" style="width: 600px; height: 184px;">
 <v:fill type="frame" src="img/trianglify-black.png"></v:fill>
 </v:rect>
 <v:shape style="position: absolute; width: 600px; height: 184px;">
 <![endif]-->
   <table width="95%" align="center" cellpadding="30" cellspacing="0" border="0">
      <tr>
         <td style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight: 300; font-size: 12px; line-height: 20px; color: white;">
            <p style="margin: 0;"><span style="font-weight: 500;">Book:</span> Mastering RWD with HTML5 and&nbsp;CSS3</p>
            <p style="margin: 0;"><span style="font-weight: 500;">Author:</span> Ricardo Zea</p>
            <p style="margin: 0;"><span style="font-weight: 500;">Publisher:</span> Packt Publishing</p>
            <br>
            <p>&copy; All Rights Reserved - <a href="#" style="color: white;">Unsubscribe</a></p>
         </td>
      </tr>
   </table>
   <!--[if gte mso 9]>
 </v:shape>
 <![endif]-->
</td>
```

##### CTA 按钮的条件注释

以下片段改编自 Eli Dickinson 在 IndustryDive.com 的文章*如何制作出色的 HTML 电子邮件按钮*（[`www.industrydive.com/blog/how-to-make-html-email-buttons-that-rock/`](http://www.industrydive.com/blog/how-to-make-html-email-buttons-that-rock/)）。

以下是标记的样子：

```html
<td style="font-family: Roboto, Arial, Helvetica, san-serif; font-weight:300; font-size: 25.888px; text-align: center;">
    <br>
  <!--[if mso]>
 <v:roundrect   href="http:#" style="height: 60px; width: 300px; v-text-anchor: middle;" arcsize="10%" stroke="f" fillcolor="#ff8000">
 <center style="color: #ffffff; font-family: Roboto, Arial, Helvetica, san-serif; font-weight:300; font-size: 25.888px;">
 Get the Book! &raquo;
 </center>
 </v:roundrect>
 <![endif]-->
 <![if !mso]>
     <a href="#" target="_blank" style="padding: 20px 30px; border: #663300 2px solid; border-radius: 5px; text-decoration: none; color: white; background: #ff8000;" class="main-cta">Get the Book! &raquo;</a>
 <![endif]-->
  <br><br><br>
</td>
```

#### 添加媒体查询

在这封电子邮件中使用的媒体查询代码量很少。这是在创建任何 HTML 或 CSS 之前具有坚实的功能基础的结果。

使这封电子邮件成为坚实构建的因素如下所列：

+   设置排版模块化比例。

+   保持布局为单列。

+   首先为最棘手的电子邮件客户端构建。

+   使用渐进增强。

+   知道何时应用条件注释。

媒体查询就像这里显示的那样简单：

```html
/*Responsive Styles*/
@media (max-width: 380px) {
    .main-cta { padding:10px 30px !important; white-space: nowrap !important; }
}
@media (max-width: 600px) {
    .inner-container-table { width: 95% !important; }
    .footer-table-ctnr td { padding: 10px 0 10px 5px !important; }
}
```

### 提示

由于内联样式的特异性高于`<style>`标签中的样式，我们需要在值的末尾添加`!important`声明，以覆盖这些内联样式。

以下是我们在媒体查询中看到的内容：

+   由于我们采用了桌面优先的方法，我们使用`max-width`属性。

+   我们在 380px 处看到一个媒体查询，因为在这个宽度下，橙色 CTA 在小屏幕上看起来有点厚。因此，我们将上下填充从 20px 减少到 10px。

+   我们还添加了`white-space: nowrap !important;`元素，以防止按钮换行到第二行。

+   一旦视口达到 600px，我们将使`inner-container-table`的宽度为 95%。这将使电子邮件在两侧留有一些填充，使其能够*呼吸*，而不会在如此狭小的空间中感到*受限*。

+   然后，我们将减少页脚表格的填充。这有助于更充分地利用可用空间，同时保持每行信用在一行内。

#### Outlook 网络字体回退样式

Outlook 不会使用字体堆栈中的任何回退字体。它只会使用 Times New Roman，有时这并不是我们想要的。

因此，在条件注释中使用特定样式来针对 Outlook 是解决这个问题的方法。这个样式应该放在主嵌入样式表的`</style>`标签之后。

这是它的样子：

```html
<!--[if mso]>
    <style>
    /* Make Outlook fallback to Arial rather than Times New Roman */
    h1, h2, p { font-family: Arial, sans-serif; }
    </style>
<![endif]-->
```

就是这样！真的就是这样。这是我在 CodePen 上创建的演示：[`codepen.io/ricardozea/pen/d11a14e6f5eace07d93beb559b771263`](http://codepen.io/ricardozea/pen/d11a14e6f5eace07d93beb559b771263)

##### 各种电子邮件客户端的屏幕截图

此电子邮件已在以下电子邮件客户端和平台上进行了测试：

+   桌面：

+   Outlook 2010

+   Gmail

+   雅虎邮件

+   Outlook.com

+   移动（iPhone）：

+   邮件应用

+   Gmail 应用（*移动友好*视图）

+   Gmail 应用（原始视图）

+   雅虎邮件应用

+   移动（Android）：

+   Gmail 应用

以下是电子邮件在各种桌面和移动客户端上的图像：

![各种电子邮件客户端的屏幕截图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_04.jpg)

在这里，一些电子邮件客户端，无论是桌面还是移动设备，实际上都能够使用我们使用的网络字体 Roboto。其余的使用了字体堆栈中的 Arial，这正是我们的计划。

令人惊讶的是，在桌面上，Outlook 2010 是唯一能够呈现 Roboto 的电子邮件客户端，尽管字体看起来比实际粗，但它仍然是唯一的。

在移动设备上，iPhone 的邮件应用和 Android 上的 Gmail 是能够使用 Roboto 的。

# 第三方服务

在构建响应式电子邮件时，我们必须补充我们的技巧、黑客和对电子邮件客户端的怪癖和故障的广泛理解，以及可以让我们更快地测试、优化我们的工作流程、提高我们的效率并学习更多现代技术的工具。

有很多工具，就像有很多网页设计师一样；我们要提到的工具与本书的主题密切相关。而且，所有这些工具都是免费的。让我们来看看。

## Litmus's PutsMail

我必须承认，这个工具的名称并不是很描述性，也没有提到这个工具有多有用。使用 Litmus's PutsMail，我们可以将电子邮件发送到任何我们想要进行测试和调试的账户。只需点击一个按钮，PutsMail 就可以将电子邮件发送到几乎任意数量的电子邮件账户。

PutsMail 允许我们做以下事情：

+   添加任何电子邮件以发送测试

+   添加主题行

+   粘贴我们的 HTML

一旦我们做好了这些准备，我们只需点击发送电子邮件的按钮，然后就可以在所有设备上进行测试了。不需要在电子邮件管理平台中登录和使用繁琐的界面。

我使用这个工具发送了您在前面几段中看到的所有电子邮件客户端屏幕截图的图像。

优点是：

+   它非常容易使用，并且学习曲线非常低。

+   与一些电子邮件管理服务不同，PutsMail 立即发送测试邮件。

+   添加和删除电子邮件非常容易。

+   除了测试常规 HTML 电子邮件，它还允许您测试纯文本和 Apple Watch 版本。

+   如果需要，它可以内联 CSS。

+   标记在 HTML 字段中得到了清晰的突出显示。

+   它是免费的。

缺点是：

+   有时您需要删除一封电子邮件并再次添加才能接收测试。

+   每个电子邮件营销服务对发送电子邮件时会剥离或保留标记的规则都不同。因此，PutsMail 的规则可能与其他电子邮件营销提供商的规则不同。

Litmus's PutsMail 可以在以下网址找到：[`putsmail.com/`](https://putsmail.com/)。

## CSS 内联工具

编写内联 CSS 是一项相当繁琐的任务：如果我们的段落具有`font-family: Arial, Helvetica, san-serif; font-style: italic; font-weight: bold; font-size: 18px;`，那么我们必须将所有这些属性复制并粘贴到每个段落中。或者，我们必须复制并粘贴相同的段落，并更改其中的文本。

甚至不要考虑使用字体速记。那么属性的更改呢？现在我们必须在每个段落中进行更改。查找和替换可能会有风险，这意味着需要更多的时间进行测试。这就是 CSS 内联工具的作用！

使用 CSS 内联工具，我们可以在电子邮件模板的`<head>`部分中的`<style>`标签中编写我们的 CSS，就像创建普通网页时所做的那样。完成后，我们将电子邮件模板上传到 CSS 内联工具中。该工具将自动*内联*CSS 到每个对应的 HTML 标签中。

所以如果我们有以下段落：

```html
<p class="note__important">CSS inliners are an awesome tool!</p>
```

然后，我们在`<head>`部分的`<style>`标签中写入这个：

```html
<style>
    p.note__important {
        font-family: Arial, Helvetica, san-serif;
        font-style: italic;
        font-weight: bold;
        font-size: 18px;
    }
</style>
```

CSS inliner 将执行以下操作：

```html
<p class="note__important" style="font-family: Arial, Helvetica, san-serif;font-style: italic;font-weight: bold;font-size: 18px;" >CSS inliners are an awesome tool!</p>
```

优点如下：

+   我们可以在电子邮件模板的`<head>`部分的`<style>`标签中包含所有样式，就像在常规网页构建中一样。

+   使用 CSS inliner 很简单：粘贴您的标记，按下内联按钮，完成。

+   这导致重复任务大大减少，因为在`<style>`标签中放置一个类就足够了——工具会完成其余工作。

+   大多数 CSS inliner 是免费的。

缺点如下：

+   测试电子邮件非常耗时，因此使用 CSS inliner 创建测试电子邮件会增加额外的步骤。

Litmus 的 PutsMail 是一个例外，因为它在发送测试电子邮件时有内联 CSS 的选项。

+   CSS inliner 有不同的写样式的方式：有些在分号后添加空格，而其他则不添加。这可能与个人的风格一致，也可能不一致。

一些最受欢迎的 CSS inliner 如下：

+   MailChimp（[`templates.mailchimp.com/resources/inline-css/`](http://templates.mailchimp.com/resources/inline-css/)）

+   Campaign Monitor（[`inliner.cm/`](http://inliner.cm/)）

+   Dialect 的 Premailer（[`premailer.dialect.ca/`](http://premailer.dialect.ca/)）

+   Zurb 的 Inliner（[`zurb.com/ink/inliner.php`](http://zurb.com/ink/inliner.php)）

## 高级电子邮件框架

谁说我们不能使用 Sass、Grunt 和 Node.js 等现代和更先进的技术构建电子邮件？

对于那些有点更懂技术并且热爱前端开发的人来说，这些电子邮件框架可以极大地加快速度。

优点如下：

+   这些技术提高了开发和测试阶段的速度。

+   这些技术在本地机器上运行；这意味着一切都比使用第三方基于 Web 的服务执行得快得多。

+   如果您是熟悉这些技术的前端开发人员，学习使用任何电子邮件框架会更容易。

+   一些电子邮件框架允许我们重用组件，类似于使用包含，比如头部和页脚等。

+   在一些电子邮件框架中，创建纯文本电子邮件是一个选项。

+   每当我们使用开源项目时，我们都在帮助同行的网络专业人士发展他们的职业，以及这些项目周围的任何社区，使网络变得更好。

+   有来自开发者和项目贡献者生态系统的支持。

+   这些技术是免费的。

缺点如下：

+   如果不熟悉这些前端技术，学习曲线可能会很陡峭。

+   这需要事先了解和理解多个前端技术。

一些电子邮件框架如下：

+   Nathan Rambeck 的 Email Lab（[`github.com/sparkbox/email-lab`](https://github.com/sparkbox/email-lab)）它使用以下内容：

+   Node.js

+   Grunt

+   Bundler

+   Sass

+   Ruby

+   Premailer

+   Nodemailer

+   Handlebars/Assemble

+   Alex Ilhan 的 Zenith（[`github.com/Omgitsonlyalex/ZenithFramework`](https://github.com/Omgitsonlyalex/ZenithFramework)）

您可以在 Litmus 找到教程[`litmus.com/community/learning/23-getting-started-with-sass-in-email`](https://litmus.com/community/learning/23-getting-started-with-sass-in-email)。它使用以下内容：

+   Sass

+   Compass

+   Premailer

+   Lee Munroe 的 Grunt Email Workflow（[`github.com/leemunroe/grunt-email-workflow`](https://github.com/leemunroe/grunt-email-workflow)）

它使用以下内容：

+   Grunt

+   Ruby

+   Node.js

+   Sass

+   Premailer

+   Mailgun（可选）

+   Litmus（可选）

+   Rackspace Cloud（可选）

## 响应式电子邮件模板服务

我一直相信亲自动手是学习的最佳方式。然而，在电子邮件世界中，亲自动手意味着花费大量时间以一种不再是良好实践的方式处理 HTML 和 CSS。使用表格进行布局（并非使用浮动更好），内联 CSS，处理古怪的电子邮件客户端等等，比必要的测试和调试花费了更多的时间，以及其他一切好东西。

加快速度的方法是使用第三方电子邮件模板，因为作者已经至少在很大程度上为我们做了繁重的工作。让我们来看看使用第三方响应式电子邮件模板的利弊。

优点是：

+   很可能已经进行了彻底的测试；这极大地减少了我们自己的测试时间。

+   如果我们对布局满意，我们只需要用我们自己的内容替换即可。

+   一些电子邮件模板服务甚至允许您在编辑后发送电子邮件本身。

+   有些服务不需要作者了解任何 HTML 或 CSS 就能创建响应式电子邮件。

+   下载电子邮件模板是一些电子邮件模板服务提供的选项。

+   大多数响应式电子邮件模板都是免费下载的。

+   一些付费的拖放电子邮件构建服务提供免费帐户，并且在其免费计划中提供了许多功能。

缺点是：

+   尽管很少，我们仍然需要进行一些自己的测试。

+   如果我们想要更改布局，有时是不可能的。这取决于电子邮件模板服务。

+   尽管一些电子邮件模板服务允许我们发送电子邮件，但它们并不提供任何分析或后端，让我们可以看到电子邮件的表现如何。

+   图像优化可能是理想的，也可能不是。没有办法知道。

+   在某些服务中，无法重复使用旧的电子邮件模板，因此如果我们打算使用相同的布局，就必须从头开始编辑一切。

一些常见的响应式电子邮件模板如下：

+   MailChimp 的 Email Blueprints ([`github.com/mailchimp/Email-Blueprints`](https://github.com/mailchimp/Email-Blueprints))

+   Zurb Ink ([`zurb.com/ink/templates.php`](http://zurb.com/ink/templates.php))

+   Litmus 的 Slate ([`litmus.com/resources/free-responsive-email-templates`](https://litmus.com/resources/free-responsive-email-templates))

+   Brian Graves 的 Responsive Email Patterns ([`responsiveemailpatterns.com/`](http://responsiveemailpatterns.com/))

以下是拖放电子邮件构建服务：

+   Stamplia Builder ([`builder.stamplia.com/`](https://builder.stamplia.com/))

+   MailUp 的 BEE Free ([`beefree.io/`](https://beefree.io/))

**BEE**是**Best E-mail Editor**的缩写

## 查看电子邮件的构建方式

这个工具肯定是电子邮件开发和学习中最令人惊奇和有用的工具之一。Litmus 的**Scope**书签允许我们从任何网络邮件客户端中查看电子邮件模板的构建方式。

### 提示

*bookmarklet*是一个 JavaScript 组件，你可以存储在书签中，通常是在书签栏中。当你点击这个*bookmarklet*时，会显示特殊功能。*bookmarklet*本身并不是一个书签；它恰好存储在书签中，但提供的功能与常规书签非常不同。

Scope 的工作方式非常简单：

1.  转到 Scope 网站：[`litmus.com/scope/`](https://litmus.com/scope/)。

1.  将书签拖到浏览器的书签栏中。

1.  打开您的网络邮件并查看任何电子邮件。

1.  在您的书签栏中点击**Scope It**书签。

1.  Scope 网站以*design*模式打开电子邮件。

1.  点击**code**，设计面板将滑开，让我们可以看到所讨论的电子邮件的所有标记。

这对于了解其他人是如何在电子邮件中实现视频、渐变、响应等惊人的事情非常有用。这是一个截图，向我们展示了我们刚刚构建的响应式电子邮件模板在发送到我的 Gmail 帐户并且使用书签工具*scope*后的样子。

在左边是 Litmus 网站上的 Scope 侧面，右边是在 Sublime Text 中打开的文件。它们完全相同...甚至格式都是相同的。令人惊讶的工具！

![看看电子邮件是如何构建的](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_05.jpg)

使用 Litmus 的 Scope 的电子邮件模板

# 摘要

哇，我们成功了！

在关于响应式电子邮件的最后一章中，我们讨论了一些重要的事情，除了构建实际的电子邮件。

我们现在明白了为什么电子邮件在任何营销活动中如此重要，因为越来越多的电子邮件在移动设备上被打开。然而，人们更喜欢在他们的桌面上与电子邮件互动——这是使我们的电子邮件响应式的非常充分的理由。

分析是决定支持哪些电子邮件客户端的关键因素。我们希望明智地利用我们的时间。然后，设置一个基本的 HTML 模板可以走很长一段路，因为我们可以一次又一次地重用这样的模板。

像 CSS 重置、将内容放在 100%宽的表格中，以及创建内部表格这样的事情，基本上是任何电子邮件设计的常用流程。我们现在知道，电子邮件的最大宽度应该是 600 像素。

微软的 Outlook 2007/2010/2013 版本是电子邮件客户端的 IE6：它们对现代 HTML 和 CSS 的支持非常差，但它们是桌面上最流行的电子邮件客户端。因此，使用条件注释来实现漂亮的 CTA 和背景是一个好方法。

此外，为了尽可能高效，使用第三方电子邮件模板和拖放电子邮件构建服务始终是一个选择。

关于响应式电子邮件的最后一句话，我们已经完成了使用 HTML5 和 CSS3 掌握响应式 Web 设计的旅程，还有更多。如果您有任何问题，请随时联系我。我将非常乐意在任何时间、任何地点帮助同行的网络专业人士。

我们现在可以摆出少林寺的功夫宗师释德如和释德阳在第六章中所做的相同姿势了，*在响应式 Web 设计中使用图像和视频*。

嗨呀！

![摘要](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_08_06.jpg)

非常感谢您的阅读，希望您喜欢！
