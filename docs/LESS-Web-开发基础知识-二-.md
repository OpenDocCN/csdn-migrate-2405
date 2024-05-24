# LESS Web 开发基础知识（二）

> 原文：[`zh.annas-archive.org/md5/E32D57C9868AAE081EFB9D0BCBCFBAE6`](https://zh.annas-archive.org/md5/E32D57C9868AAE081EFB9D0BCBCFBAE6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：避免重复造轮子

在前几章中，你学会了如何使用*Less*来编译你的 CSS。*Less*帮助你创建可重用和可维护的 CSS 代码。你已经学会了如何组织你的文件，前一章还向你展示了命名空间的作用，使你的代码具有可移植性。*Less*帮助你编写高效的代码来处理浏览器的不兼容性。*Less*不能单独解决浏览器的不兼容性问题，但可以使你的解决方案可重用，尽管由于这个原因，可重用的混合仍然可能很复杂。在本章中，你将学会你不必自己编写所有这些复杂的代码。有一些预构建混合的库可以帮助你更快地工作并创建更稳定的代码。

本章将涵盖以下主题：

+   背景渐变

+   防止未使用的代码

+   测试你的代码

+   预构建混合的标志性字体

+   Retina.js

# 重新审视背景渐变

还记得第二章中讨论的 CSS3 背景渐变吗，*使用变量和混合*？为了在不同的浏览器上显示更好或相同的渐变，你必须使用特定于供应商的规则。不同的规则集会使你的混合更加复杂。在这种情况下，更复杂也意味着更难以维护。

在实践中，你的混合会随着过时的代码或不再受支持的代码而增长，另一方面，你必须更新你的混合以适应更新的浏览器。当然，我们只能希望新的浏览器版本支持 CSS3 规范，而不需要对代码进行进一步的更改。

**Can I use...**网站([`caniuse.com/`](http://caniuse.com/))提供了 HTML5、CSS3 和 SVG 支持的兼容性表，还有桌面和移动浏览器的兼容性表。它会告诉你，大多数当前浏览器在其当前版本中都支持 CSS 渐变。在撰写本书时，移动设备的 Android 浏览器仍然依赖于`-webkit`供应商规则，而 Opera Mini 根本不支持它。

如果放弃对旧版浏览器的支持，你的混合可以简化为以下代码片段：

```less
  .verticalgradient(@start-color: black; @end-color: white; @start-percent: 0%; @end-percent: 100%) {
    background-image: -webkit-linear-gradient(top, @start-color @start-percent, @end-color @end-percent);
    background-image: linear-gradient(to bottom, @start-color @start-percent, @end-color @end-percent);
    background-repeat: repeat-x;
 }
```

前面的代码还放弃了对 IE8 和 IE9 的支持。如果你选择支持这些浏览器，你必须添加额外的 IE 特定规则。**Can I use…**网站还向你展示了最常见浏览器的市场份额。在某些情况下，只为旧版浏览器提供功能支持而不指望所有浏览器看起来完全一样也是有用的。例如，一个没有高级动画的导航结构仍然可以帮助用户浏览你的网站。使用旧版浏览器的人并不总是期望最新的技术。这些技术也并不总是有附加值。旧版浏览器大多不运行在最新的硬件上；在这些浏览器上，对渐变等功能的支持只会减慢你的网站速度，而不会增加任何价值。

## 未使用代码

即使在长期运行和不断增长的项目中使用*Less*，也几乎不可能在你的代码中找不到一些未使用的代码。浏览器工具可以帮助检测最终 CSS 中的未使用代码。

### Chrome 的开发者工具

谷歌 Chrome 的开发者工具有一个选项可以找到未使用的 CSS。在谷歌 Chrome 中，导航到**工具** | **开发者工具**，选择**审核**选项卡，然后点击**运行**。

现在使用这个工具来测试前几章的演示代码。

首先，在浏览器中打开`http://localhost/index.html`并运行测试。你会看到以下截图：

![Chrome 的开发者工具](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_01.jpg)

Chrome 的开发者工具显示的未使用代码

未使用代码列表以`less/normalize.less`中定义的一长串样式开始，如第一章中所示，*使用 Less 改进 Web 开发*；这些是**CSS 重置**的样式。

在大多数项目中，每个页面都使用相同的 CSS 代码基础（相同的文件）。因此，您不能总是保证页面只包含真正使用的代码。其中一些代码不会在每个页面上使用，但将必须在其他或未来的页面上使用。Web 浏览器能够缓存 CSS 文件，因此最好使用相同的 CSS 文件来为网站的不同页面设置样式。某些页面将不使用所有缓存的样式规则，这将显示为该页面上未使用的代码。缓存的代码只加载一次并在每个页面上使用。CSS 重置似乎对所有页面都有用，因此您不应更改或删除它。

正如您所看到的，`.centercontent`和`.screen-readeronly`是未使用的。请记住，类被编译到您的 CSS 中，而 mixin 则不是。现在，`.centercontent`和`.screen-readeronly`被定义为类。拥有`.screen-readeronly`类似乎是有用的，但`.centercontent`可以更改为 mixin。

### Firebug CSS 使用附加组件

对于 Firefox，可以使用 Firebug 的附加组件。这将帮助您找到未使用的代码。您可以在[`addons.mozilla.org/en-US/firefox/addon/css-usage/`](https://addons.mozilla.org/en-US/firefox/addon/css-usage/)下载此插件。

# 测试您的代码

您不必自己编写所有的 Less 代码，因为它是可重用和可移植的。在 Web 上可以找到 Less 代码的 mixin 和片段，并在您的项目中（重新）使用。搜索*Less* mixin 背景渐变，您将得到许多有用的结果。尝试找到支持浏览器并满足您要求的代码。如果对 mixin 的浏览器支持有任何疑问，请考虑在 Stackoverflow.com 上提问。始终展示您的代码和您所做的事情；不要只是寻求解决方案。此外，关于*Less*的其他问题也可以在 Stackoverflow.com 上提问。

集成代码片段甚至完整的命名空间将使您的代码测试更加重要。

## 了解 TDD

测试驱动开发（TDD）是软件开发的一种经过验证的方法。在 TDD 中，您为项目中的每一段代码编写测试。在添加或改进功能或重构代码时，更改代码后，所有测试都应该通过。所有测试应该自动运行。虽然可以自动测试 Less 和 CSS 代码，但您需要手动查看不同浏览器和设备上页面的确切外观，尽管其他方面，如正确性和性能可以自动测试。例如，您可以使用 CSS Lint 等工具自动测试您的代码。CSS Lint 验证和测试您的代码，包括性能、可维护性和可访问性等方面。这些工具测试编译后的 CSS 而不是您的 Less 代码。Less Lint Grunt 插件编译您的 Less 文件，通过 CSS Lint 运行生成的 CSS，并输出任何发现的 CSS Lint 错误的冒犯的 Less 行。可以通过访问[`www.npmjs.org/package/grunt-lesslint`](https://www.npmjs.org/package/grunt-lesslint)获取更多信息。

## 关于样式指南的一切

样式指南提供了网站元素的概述，如按钮、导航结构、标题和字体。它展示了正确的呈现和颜色。为您的项目和网站创建样式指南可以帮助您测试您的 Less 代码。样式指南还将帮助项目的其他开发人员和内容发布者。

您现在可能会认为样式指南确实很有用，但也很耗时；因此，接下来将讨论两种工具。这些工具根据您的 *Less*（或编译后的 CSS）代码自动生成样式指南。这两种工具仍然需要一些额外的代码和努力，但不会花费太多时间。几乎总是值得测试您的代码。还要意识到这里的重大收益：您只需测试样式的效果。*Less* 保证您的 CSS 已经有效，并且 *Less* 编译器处理了它的优化。正如承诺的那样，这为您的真正设计任务提供了更多时间。

### 使用 StyleDocco 构建样式指南

StyleDocco 从样式表中生成文档和样式指南文档。StyleDocco 也非常适用于 *Less* 文件。要使用 StyleDocco 创建样式指南，您需要在 *Less* 文件中添加注释。注释应该解释样式的作用，并包含 HTML 示例代码。注释需要用 **Markdown** 编写。Markdown 是一种纯文本格式，可以轻松转换为 HTML。StackOverflow.com 使用 Markdown 发表和评论。您可以使用其帮助指南了解更多信息；您可以通过访问 [`www.stackoverflow.com/editing-help/`](http://www.stackoverflow.com/editing-help/) 找到它。

可以使用以下命令使用 **npm** 安装 StyleDocco：

```less
npm install -g styledocco

```

您已经在 第一章 中了解了 npm，*使用 Less 改进 Web 开发*。安装 StyleDocco 后，您需要在 *Less* 文件中添加 Markdown 注释。

要查看使用 StyleDocco 生成的样式指南示例，请在文本编辑器中打开 `less/nav.less`，并按照下面的代码片段添加 Markdown 描述，然后是 HTML 测试代码：

```less
/* Construct a navigation structure.

    <ul class="nav">
        <li><a href="#">item 1</a></li>
        <li><a href="#">item 2</a></li>
        <li class="active"><a href="#">item 3</a></li>
    </ul>
*/
```

要构建样式指南，请在终端中导航到您的 *Less* 文件夹（`lessc`）并运行以下命令：

```less
styledocco -n "Less Web Development Essentials Styleguide"  --preprocessor "/usr/local/bin/lessc"  --verbose [file path]

```

在上面的示例中，使用 `-n` 设置了样式指南的名称。通常情况下，如果您的文件路径只包含 *Less* 文件，则不必设置 `–preprocessor` 选项。要为您的 *Less* 文件构建样式指南，命令应该如下所示：

```less
styledocco -n "Less Web Development Essentials Styleguide" less/*

```

`styledocco` 命令会生成一个名为 `docs/` 的新文件夹。这个文件夹包含一个 `index.html` 文件，可以在浏览器中打开。最终结果应该看起来像下面的截图：

![使用 StyleDocco 构建样式指南](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_02.jpg)

使用 StyleDocco 构建的样式指南示例

### 使用 tdcss.js 测试您的代码

`tdcss.js` 框架是另一个与 *Less* 配合良好并促进测试驱动开发的样式指南工具。`tdcss.js` 框架可以从 GitHub 免费下载，网址为 [`github.com/jakobloekke/tdcss.js`](https://github.com/jakobloekke/tdcss.js)。另请参阅 [`jakobloekke.github.io/tdcss.js/`](http://jakobloekke.github.io/tdcss.js/) 以获取更多信息。与 StyleDocco 不同，使用 `tdcss.js` 不会更改您的 *Less* 文件。您可以使用项目中相关源代码的片段生成样式指南。例如，您可以使用 HTML 注释样式编码，如 `<!-- : 导航 -->`，将它们分隔开。然后将片段复制并粘贴到一个 HTML 文档中，形成您的样式指南，并包含来自您的 *Less* 代码和 `tdcss.js` 的样式。示例导航的 HTML 文档的 `head` 部分应具有以下结构：

```less
<!-- Your Less code  -->
  <link rel="stylesheet/less" type="text/css" href="less/styles.less" />
  <script type="text/javascript">less = { env: 'development' };</script>
  <script src="img/less.js" type="text/javascript"></script>

<!-- TDCSS -->
<link rel="stylesheet" href="tdcss/tdcss.css" type="text/css" media="screen">
<script src="img/jquery-1.11.0.min.js"></script>
<script src="img/jquery-migrate-1.2.1.min.js"></script>

<script type="text/javascript" src="img/tdcss.js"></script>
<script type="text/javascript">
     $(function(){
         $("#tdcss").tdcss();
     })
</script>
```

body 中的标记如下：

```less
<div id="tdcss">
    <!-- # Navigation -->
    <!-- & Style lists used for navigation. -->
    <!-- : Basic navigation -->
       <ul class="nav">
        <li><a href="#">item 1</a></li>
        <li><a href="#">item 2</a></li>
        <li class="active"><a href="#">item 3</a></li>
       </ul>
</div>
```

通过在浏览器中打开 `http://localhost/tdcss.html` 查看上述代码的结果。最终结果应该看起来像下面的截图：

![使用 tdcss.js 测试您的代码](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_03.jpg)

使用 tdcss.js 构建的样式指南示例

# 预构建的混合

您已经了解了在网络上搜索和找到 mixin。然而，使用和重用经过充分测试的 mixin 将比那更容易。其他开发人员已经构建了完整的库和预构建的 mixin，您可以在项目中使用。这些预构建的 mixin 帮助您编写*Less*代码，而无需考虑使 CSS3 复杂的供应商特定规则。在接下来的章节中，您将了解到五个最常用的库。这些库如下：

+   Less Elements ([`lesselements.com`](http://lesselements.com))

+   Less Hat ([`lesshat.madebysource.com/`](http://lesshat.madebysource.com/))

+   3L ([`mateuszkocz.github.io/3l/`](http://mateuszkocz.github.io/3l/))

+   ClearLess ([`clearleft.github.com/clearless/`](http://clearleft.github.com/clearless/))

+   Preboot ([`markdotto.com/bootstrap/`](http://markdotto.com/bootstrap/))

还可以在[`lesscss.org/usage/#frameworks-using-less`](http://lesscss.org/usage/#frameworks-using-less)找到更全面的 mixin 库列表。

请理解，您不必选择；没有限制您只能使用这些库中的一个。所有这些库都有优缺点；您必须选择最适合您项目需求的库。

全局上，所有库都为您提供一个*Less*文件，其中包含您可以在项目中导入的 mixin。虽然一些库也有一些设置，在所有情况下，`@import "{library-name}";`就足以使其 mixin 可用于您的项目。*Less*没有限制包含多个库，但这样做会导致 mixin 名称冲突的问题。所有具有相同名称的 mixin 将被编译为 CSS（如果它们的参数也匹配）。因此，一些库还具有这些 mixin 的带前缀版本。

与带前缀版本不同，使用命名空间，如第三章中所解释的，*嵌套规则、操作和内置函数*，在大多数情况下提供了更稳定的解决方案，如下面的代码片段所示：

```less
// create a namespace for {library-name}
#{library-name}{@import "{library-name}";}
```

使用`#{library-name} > mixin()`使 mixin 可用。

## 使用 Less Elements 为供应商特定规则提供单行声明

Less Elements 可能是本章讨论的库中最紧凑的一个。紧凑并不意味着它没有用处。这个库的重点是将跨浏览器前缀合并为单一简洁的声明。

还记得本章开头的垂直背景渐变吗？您已经看到，当您支持现代浏览器时，您将需要至少三个声明，包括供应商特定规则。

使用 Less Elements，您可以使用三个参数的单行声明来完成相同的操作，如下面的代码片段所示：

```less
element {
.gradient(#F5F5F5, #EEE, #FFF);
      }
```

第一个参数定义了在不支持渐变的浏览器中使用的回退颜色。渐变从底部到顶部，第二个参数设置底部颜色，第三个参数设置顶部颜色。

前面的*Less*代码最终将编译为以下 CSS：

```less
  element {
  background: #f5f5f5;
  background: -webkit-gradient(linear, left bottom, left top, color-stop(0, #eeeeee), color-stop(1, #ffffff));
  background: -ms-linear-gradient(bottom, #eeeeee, #ffffff);
  background: -moz-linear-gradient(center bottom, #eeeeee 0%, #ffffff 100%);
  background: -o-linear-gradient(#ffffff, #eeeeee);
  filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#ffffff', endColorstr='#eeeeee', GradientType=0);
}
```

在其简单性中，Less Elements 提供了许多有用的 mixin，用于使用**CSS3 技术**构建您的项目。它为所有 CSS3 属性提供了供应商特定规则的单行声明，并通过布局声明扩展了这一点。

`.columns()` mixin 将元素分成列，包括列之间的边框和间隙。`.columns()` mixin 的变量顺序为列宽、列数、列间隙、列边框颜色、列边框样式和列边框宽度。

这个 mixin 可以应用于非替换的块级元素（除表元素外）、表单元格和内联块元素，如`body`或`div`元素。

要将`div`元素分成宽度为 150 像素的三列，您现在可以在*Less*中编写以下代码：

```less
div.threecolumns {
 .columns(40px, 3, 20px, #EEE, solid, 1px);
}
```

前面的代码编译成 CSS，并如下所示：

```less
div.threecolumns {
  -moz-column-width: 150px;
  -moz-column-count: 3;
  -moz-column-gap: 20px;
  -moz-column-rule-color: #eeeeee;
  -moz-column-rule-style: solid;
  -moz-column-rule-width: 1px;
  -webkit-column-width: 150px;
  -webkit-column-count: 3;
  -webkit-column-gap: 20px;
  -webkit-column-rule-color: #eeeeee;
  -webkit-column-rule-style: solid;
  -webkit-column-rule-width: 1px;
  column-width: 150px;
  column-count: 3;
  column-gap: 20px;
  column-rule-color: #eeeeee;
  column-rule-style: solid;
  column-rule-width: 1px;
}
```

您还可以通过在浏览器中加载 `http://localhost/columns.html` 来测试这一点。还请将浏览器窗口从小屏幕调整到全屏幕，以查看这些列默认情况下是响应式的。编译后的 `.div.threecolumns` 类可以与以下 HTML 代码一起使用：

```less
<div class="threecolumns" role="content">Vestibulum at dolor aliquam, viverra ipsum et, faucibus nunc. Nulla hendrerit tellus eu sapien molestie adipiscing. Cras ac tellus sed neque interdum egestas sit amet vel diam. Aenean congue dolor et elit blandit commodo. Pellentesque dapibus tellus eu augue ullamcorper dignissim. Pellentesque pretium a dui a consequat. Curabitur eleifend lectus vel viverra mollis. Sed egestas bibendum tortor mattis fermentum. Suspendisse pellentesque facilisis blandit.</div>
```

前面的代码将产生以下截图：

![使用 Less Elements 为特定供应商的规则使用单行声明](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_04.jpg)

使用 Less Elements 的 columns mixin 构建的多列布局示例

`.columns()` mixin 使用了 **CSS 多列布局模块**。有关此模块的更多信息可以在 [`www.w3.org/TR/css3-multicol/`](http://www.w3.org/TR/css3-multicol/) 找到。不幸的是，大多数现代浏览器对该模块的支持还不够好。

Less Elements 不提供有关编译后的 CSS 的浏览器支持的任何信息。在使用 Less Elements 时，您必须已经意识到了这一点。如前所述，您可以在 [caniuse.com](http://caniuse.com) 网站上检查浏览器支持情况。要找出哪些浏览器支持此多列布局模块，您将需要访问 [`caniuse.com/multicolumn`](http://caniuse.com/multicolumn)。始终检查前面的模块与您的项目的要求是否匹配。此外，此示例向您展示了为什么样式指南非常有用。

## Less Hat – a comprehensive library of mixins

与 Less Elements 不同，**Less Hat** 非常全面。在撰写本书时，Less Hat 包含了 86 个预构建 mixin。Less Hat 还与 CSS Hat 有着密切的关系。CSS Hat 是一款商业许可的工具，可以将 Adobe Photoshop 图层转换为 CSS。

Less Hat mixin 提供了禁用一些特定于浏览器的前缀的可能性。除非您有非常充分的理由这样做，否则不应该使用这个功能。默认情况下，Less Hat 通过将 *Less* 变量设置为 `true` 来使用所有浏览器前缀，如下面的代码所示：

```less
@webkit: true;
@moz: true;
@opera: true;
@ms: true;
@w3c: true;
```

在前面的代码中，`@w3c` 指的是定义了 **W3C 规范** 描述的标准属性名称的非前缀规则。Less Hat 宣传自己具有可以创建无限数量的阴影、渐变和动画的 mixin。**Box-shadow** 就是一个例子。使用 Less Hat，box-shadow mixin 可以写成 `.box-shadow(<offset-x> <offset-y> spread blur-radius color inset, …)`。

要尝试前面的 `.box-shadow` mixin，您可以使用 Less Hat 在 *Less* 中编写如下：

```less
div {
 .box-shadow(30px 30px 5px green inset,-30px -30px 5px blue inset);
}
```

前面的代码编译成以下代码片段：

```less
div {
  -webkit-box-shadow: 30px 30px 5px #008000 inset, -30px -30px 5px #0000ff inset;
  -moz-box-shadow: 30px 30px 5px #008000 inset, -30px -30px 5px #0000ff inset;
  box-shadow: 30px 30px 5px #008000 inset, -30px -30px 5px #0000ff inset;
}
```

要检查这一点，请在浏览器中打开 `http://localhost/boxshadow.html`，您将看到 `.box-shadow` mixin 的结果，如下截图所示：

![Less Hat – a comprehensive library of mixins](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_05.jpg)

Less Hat 的 box-shadow mixin 的效果示例

实际上，Less Elements 的 `.box-shadow()` mixin 不接受多个阴影，但在下一节讨论的 3L 的 mixin 可以处理用逗号分隔的多个阴影。

## 使用预构建 mixin 的 3L 库

**3L** (**Lots of Love for Less**) 是另一个预构建 mixin 集合。除了标准的单行声明，3L 还提供了额外的功能。3L 提供了用于 CSS 重置或规范化的 mixin，如 第一章 中所讨论的 *使用 Less 改进 Web 开发*。您可以在不将它们放在选择器块内的情况下调用这些 mixin，如下所示：

```less
.normalize();

/* OR */
.reset();

/* OR */
.h5bp();
```

在前面的`.h5bp()`重置中，您的 CSS 基于**HTML5 Boilerplate**。HTML5 Boilerplate 是一个专业的前端模板，用于构建快速、健壮和适应性强的 Web 应用程序或站点。您可以通过访问[`html5boilerplate.com/`](http://html5boilerplate.com/)获取有关 Boilerplate 的更多信息。3L 不仅提供了用于 HTML5 Boilerplate 重置的 mixin，还包含了用于 HTML5 Boilerplate 辅助类的 mixin。这些 mixin 包含了清除浮动和用于隐藏内容的 mixin，适用于浏览器或屏幕阅读器。

例如，`.visuallyhidden()`可以用于隐藏浏览器中的内容，但对于屏幕阅读器来说，这些内容是可用的。

### SEO 和 HTML 调试

**SEO**（搜索引擎优化）在现代网页设计中扮演着重要角色。正确和有效的 HTML5 是 SEO 的要求。此外，设置适当的标题，使用关键字的 meta 标签和描述以及图像的 alt 属性将有助于您的网站排名更高。

3L 的`.seo-helper()` mixin 将快速了解网页缺少的元素和属性。

要使用这个 mixin - 在导入 3L 后，您可以在*Less*中编写如下：

```less
html {
.seo-helper();
}
```

使用`.seo-helper()` mixin 后，您的 HTML 页面将包含有关缺少标题或 meta 标签的警告，并在缺少 alt 属性的图像周围显示红色边框，如下面的屏幕截图所示：

![SEO and HTML debugging](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_06.jpg)

3L 的辅助类使缺少的 alt 属性可见

此外，访问`http://localhost/indexseo.html`以获取有关此类如何工作的更多见解。之后，您可以自行判断这个类是否有用。独立于您的判断，`.seo-helper()` mixin 向您展示了*Less*如何可以应用于网站样式之外的功能。

## ClearLess - 另一个预构建 mixin 库

ClearLess 还与 HTML5 Boilerplate 有关。与 3L 一样，ClearLess 提供了用于 HTML5 Boilerplate 和辅助类的 mixin。除此之外，ClearLess 还使用**Modernizr**。Modernizr 是一个 JavaScript 库，用于检测用户浏览器中的 HTML5 和 CSS3 功能。Modernizr 会为检测到的功能在您的 HTML 的`html`元素中添加额外的类。使用 Modernizr，您的`html`元素将如下面的代码片段所示：

```less
<html id="modernizrcom" class="js no-touch postmessage history multiplebgs boxshadow opacity cssanimations csscolumns cssgradients csstransforms csstransitions fontface localstorage sessionstorage svg inlinesvg no-blobbuilder blob bloburls download formdata wf-proximanova1proximanova2-n4-active wf-proximanova1proximanova2-i4-active wf-proximanova1proximanova2-n7-active wf-proximanova1proximanova2-i7-active wf-proximanovacondensed1proximanovacondensed2-n6-active wf-athelas1athelas2-n4-active wf-active" lang="en" dir="ltr">
```

这个类名列表告诉您一个功能是否可用。因此，用于生成前面代码的浏览器支持 box-shadow、opacity 等。使用 Modernizr，您将拥有可以在*Less*代码中使用的条件类。此外，ClearLess 还使用这些类。

除了 Modernizr mixin 外，ClearLess 还有用于图标和**CSS 精灵图像**的 mixin。

CSS 精灵图像是一种至少可以追溯到七年前的技术。网站的图像被添加到单个图像中，即精灵。如果浏览器请求图像，精灵将作为背景图像加载。**SpriteMe** ([`spriteme.org/`](http://spriteme.org/))可以帮助您为您的项目创建精灵。CSS 用于显示包含精灵部分的请求图像。加载一个大的精灵，可以被缓存，而不是几个小图像，将减少浏览器显示页面所需的 HTTP 请求的数量。HTTP 请求越少，页面加载速度就越快。

为了演示这一点，请使用本章的代码包中的*Less*图像的简单精灵（`less-sprite.png`），如下面的屏幕截图所示：

![ClearLess - 另一个预构建 mixin 库](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_07.jpg)

简单精灵图像的示例

要使用精灵图像，您可以在*Less*中编写如下：

```less
#clearless {
@import "clearleft-clearless-63e2363/mixins/all.less";
@sprite-image: "../images/less-sprite.png";
@sprite-grid: 80px; //image height
}

.logo {
    #clearless > .sprite-sized(0,0,200px,80px);
    &:hover {
    #clearless > .sprite-sized(0,1,200px,80px);
    }
}
```

这段代码也可以在`less/sprite.less`中找到。请注意，`#clearless`命名空间有自己的作用域，因此`@sprite-grid`和`@sprite-grid`应该在命名空间内定义。变量通过重新声明进行设置。

前面代码的编译 CSS 将如下所示：

```less
.logo {
  background-image: url("../images/less-sprite.png");
  background-repeat: no-repeat;
  background-position: 0px 0px;
  width: 200px;
  height: 80px;
}
.logo:hover {
  background-image: url("../images/less-sprite.png");
  background-repeat: no-repeat;
  background-position: 0px -80px;
  width: 200px;
  height: 80px;
}
```

加载`http://localhost/index.html`以查看前面代码的效果。

最后，应该提到 ClearLess 定义了一些混合来构建网格。这些混合将在下一节中向您解释，因为它们是从**Preboot**中采用的。

## 使用 Preboot 的预构建混合来构建您的项目

Preboot 最初是由 Mark Otto (`@mdo`)编写的，是一个全面灵活的*Less*实用工具集。Preboot 是 Twitter 的**Bootstrap**的前身。Bootstrap 是用于在 Web 上开发响应式、移动优先项目的前端框架。您将在第六章中了解更多关于 Bootstrap 的内容，*Bootstrap 3、WordPress 和其他应用*。Bootstrap 改进了原始的 Preboot 代码。最后，Bootstrap 中的许多*Less*变量和混合改进被带回到了 Preboot 2 中。

Preboot 带有混合来构建网格系统，因为它与 Bootstrap 有关。这个网格系统创建一个包含 12 列的行。在浏览器中打开从下载的代码包中的`http://localhost/prebootgrid.html`，以查看一个包含两行的示例。第一行网格包含三列，第二行包含两列。这个网格默认是响应式的；您可以通过使用示例网格使浏览器窗口变小来看到这一点。如果屏幕宽度小于 768 像素，网格中的列将堆叠在彼此下面，而不是水平排列。以下代码示例只显示了编译后的 CSS，没有响应式类。

使用 Preboot，您可以在*Less*中编写以下代码：

```less
.col-a-half { 
.make-column(6); 
}
```

前面的代码编译成 CSS 如下（它是非响应式的）：

```less
.col-a-half {
  min-height: 1px;
  padding-left: 15px;
  padding-right: 15px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
  float: left;
  width: 50%;
}
```

在第五章中，*将 Less 集成到您自己的项目中*，您将找到另一个示例，该示例使用了 Preboot 的网格，并更详细地讨论了其响应性特性。

Preboot 设置了一些变量来定义网格，如下面的代码片段所示：

```less
// Grid
// Used with the grid mixins below
@grid-columns:          12;
@grid-column-padding:   15px; // Left and right inner padding
@grid-float-breakpoint: 768px;
```

此外，其他值，如基本颜色，已预先定义如下：

```less
// Brand colors
@brand-primary:           #428bca;
@brand-success:           #5cb85c;
@brand-warning:           #f0ad4e;
@brand-danger:            #d9534f;
@brand-info:              #5bc0de;
```

事实上，Preboot 不是一个完整的 CSS 框架；另一方面，它不仅仅是一个预构建混合的库。

# 使用 Less 将其他技术集成到您的项目中

除了预构建的混合，还有一些其他技术可以轻松集成到您的项目中使用*Less*。

## 使用图标字体

顾名思义，图标字体是作为字体定义的一组图标。图标字体可以替换项目中的图像图标。使用图标字体而不是图像的主要原因，以及它们在这里讨论的原因是，就像任何普通字体一样，图标字体可以完全通过 CSS 进行操作。在您的项目中，您可以使用*Less*设置所使用的图标字体的大小、颜色和阴影。使用图标字体的主要原因是为了提高网站的加载时间；只需要一个 HTTP 请求就可以加载它们。图标字体在不同的分辨率和显示器上看起来也很好。

在本书中，图标字体已经在第三章中使用过，*嵌套规则、操作和内置函数*。这些示例中使用了 CDN 加载 Font Awesome。Font Awesome 还在 GitHub 上提供了一组*Less*文件，网址为[`github.com/FortAwesome/Font-Awesome/tree/master/less`](https://github.com/FortAwesome/Font-Awesome/tree/master/less)。您可以通过以下步骤使用这些文件在项目中集成 Font Awesome：

1.  将`font-awesome/`目录复制到您的项目中。

1.  打开项目的 `font-awesome/less/variables.less` 文件，并编辑 `@fa-font-path` 变量，将其指向字体目录，`@fa-font-path: "../font";`。

1.  在您的主*Less*文件中导入 Font Awesome 的*Less*文件，`@import "font-awesome-4.0.3/less/font-awesome.less";`。

执行前面的步骤后，您可以在 HTML 文档中使用以下代码片段： 

```less
<ul class="fa-ul">
  <li><i class="fa-li fa fa-check-square"></i>List icons (like these)</li>
  <li><i class="fa-li fa fa-check-square"></i>can be used</li>
  <li><i class="fa-li fa fa-spinner fa-spin"></i>to replace</li>
  <li><i class="fa-li fa fa-square"></i>default bullets in lists</li>
</ul>
```

在您的网络浏览器中打开前面的代码将得到以下截图：

![使用图标字体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_08.jpg)

具有 Font Awesome 项目的 HTML 列表

您将在可下载文件的`less/font-awsome.less`中找到前面 HTML 列表的*Less*代码。请检查此文件。您将看到您无需更改 Font Awesome 的原始文件来设置`@fa-font-path`。`@fa-font-path`变量将通过重新声明进行设置，并使用上一次声明获胜的规则，如前面在第二章中所解释的，*使用变量和 mixin*。

您可以通过访问[`fontawesome.io/examples/`](http://fontawesome.io/examples/)找到更多 Font Awesome 用法的例子。

此外，其他图标字体，如 Bootstrap 的 Glyphicons，也可以与*Less*一起使用（请参阅[`github.com/twbs/bootstrap/blob/master/less/glyphicons.less`](https://github.com/twbs/bootstrap/blob/master/less/glyphicons.less)）。但是，在找不到*Less*文件的图标字体的情况下，您现在已经有足够的知识来自己创建所需的*Less*代码。

尝试编写所需的*Less*代码，将 Meteocons ([`www.alessioatzeni.com/meteocons/`](http://www.alessioatzeni.com/meteocons/))集成到您的项目中作为练习，或执行以下步骤：

1.  首先从[`www.alessioatzeni.com/meteocons/res/download/meteocons-font.zip`](http://www.alessioatzeni.com/meteocons/res/download/meteocons-font.zip)下载字体。

1.  在这个压缩文件中，您将找到四个文件：`meteocons-webfont.eot`，`meteocons-webfont.svg`，`meteocons-webfont.ttf`和`meteocons-webfont.woff`。这些是在不同浏览器中显示 Meteocons 所需的不同格式。

1.  将这些文件复制到您项目的`fonts/`文件夹中。您还将找到包含这些字体文件的`stylesheet.css`。此文件包含 Meteocons 的`@fontface`样式。如果您检查 Font Awesome 的*Less*文件，您将找到相同类型的样式。在您的项目中使用字体，需要`@fontface`声明。

现在，您应该记住 Less Hat 预构建的 mixin。Less Hat 具有 fontface mixin，`.font-face(@fontname, @fontfile, @fontweight:normal, @fontstyle:normal)`。

使用此 fontface mixin，您可以将以下代码添加到您的*Less*代码中：

```less
#lesshat {@import "lesshat/lesshat.less";}

@font-face {
#lesshat > .font-face("Meteocons", "../fonts/meteocons-webfont");
}

[data-icon]:before {
        font-family: 'Meteocons';
        content: attr(data-icon);
}
```

前面的代码将编译为以下 CSS：

```less
@font-face {
  font-family: "Meteocons";
  src: url("../fonts/meteocons-webfont.eot");
  src: url("../fonts/meteocons-webfont.eot?#iefix") format("embedded-opentype"), url("../fonts/meteocons-webfont.woff") format("woff"), url("../fonts/meteocons-webfont.ttf") format("truetype"), url("../fonts/meteocons-webfont.svg#Meteocons") format("svg");
  font-weight: normal;
  font-style: normal;
}
[data-icon]:before {
  font-family: 'Meteocons';
  content: attr(data-icon);
}
```

前面的 CSS 代码使您可以使用以下 HTML 代码：

```less
<a href="" data-icon="A">Link</a>
```

在 HTML 中的前面代码将如下截图所示：

![使用图标字体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_09.jpg)

使用 Meteocon 的超链接

之前，您已经看到了如何通过类名添加 Font Awesome 图标。要将此功能添加到 Meteocons，您将需要编写一些*Less*代码。以下图表显示了该字体的每个图标的字母：

![使用图标字体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_04_10.jpg)

气象字体

现在，根据以下方式为每个图标在您的*Less*代码中添加一个类声明：

```less
. meteocons-sun               { &:before { content: "\2a"; } }
```

在前面的示例中，`.meteocons-sun`是您的类名，`\2a`表示类似字符的十六进制值。 2A 十六进制是 42 十进制，`*`（星号）的 ASCII 值为 42。您还可以使用八进制或十进制（对于前 128 个可打印字符）。有时，unicode 的`\u`会被添加，例如在前面的代码中的`\u002a`。

如果您添加这些类声明，您的列表将如下代码片段所示：

```less
.mc-light-sunrise:before {
  content: "\0041";
}
.mc-light-sunshine:before {
  content: "\0042";
}
.mc-light-moon:before {
  content: "\0043";
}
.mc-light-eclipse:before {
  content: "\0044";
}
and so on
```

现在，您已经掌握了图标字体的基础知识，并且可以扩展您的代码。例如，添加以下代码以设置字体的大小：

```less
.mc-2x { font-size: 2em; }
.mc-3x { font-size: 3em; }
.mc-4x { font-size: 4em; }
.mc-5x { font-size: 5em; }
```

在本章的下载部分，您将找到完整的*Less*代码，以便像 Font Awesome 一样在`less/meteocons`中使用 Meteocons。正如您所看到的，大部分 Font Awesome 的代码可以被重用。请访问`http://localhost/indexmeteo.html`以了解如何使用此代码。

## Retina.js

高密度设备的每英寸或每厘米像素比普通显示屏多。苹果为其双倍密度显示屏引入了**Retina**一词。如果您放大图像（或将其放大），它将变得模糊。这是网页设计师在为高密度设备设计时必须解决的问题。您可能想知道这与*Less*有什么关系。 CSS 结合媒体查询（您将在第五章中了解更多关于媒体查询的信息，*将 Less 集成到您自己的项目中*），可以防止您的图像在高密度显示屏上变得模糊。

要理解发生了什么，您必须意识到 CSS 像素实际上是设备独立的。CSS 像素用于在浏览器中给元素赋予物理尺寸。在普通屏幕上，一个 CSS 像素匹配一个设备像素。高密度显示屏比 CSS 像素有更多的设备像素；在 Retina 的情况下，它们的像素数量是 CSS 像素的四倍。更多和更小的像素使人眼无法看到单个像素，并且应该提供更好的用户体验。

Retina 显示屏上的图像宽度为 300 个 CSS 像素，需要 600 个设备像素才能保持相同的物理尺寸。现在，您可以通过使用更高分辨率（CSS 像素）的位图，并通过 HTML 或 CSS 进行缩小，来防止图像模糊。

在普通显示屏上，您的 HTML 将如下所示：

```less
<img src="img/photo300x300.png" width="300px" height="300px">
```

在 Retina 显示屏上，您将使用以下代码片段显示相同的图像：

```less
<img src="img/photo600x600.png" width="300px" height="300px">
```

目前，有一个惯例，即在高密度图像的名称中添加`@2x`，例如`example@2x.png`。

您现在应该明白，您可以使用*Less*编写高效的代码，为这些不同的图像提供正确的 CSS 尺寸。`retina.js`库（[`github.com/imulus/retinajs`](https://github.com/imulus/retinajs)）帮助您处理高密度图像和显示屏；它结合了 JavaScript 和*Less*来编写您的 Retina 代码。

对于普通图像，您必须使用以下代码片段：

```less
<img src="img/my_image.png" data-at2x="http://example.com/my_image@2x.png" />
```

前面的代码将由 JavaScript 处理，但您将需要使用*Less*来设置背景图像。这里，背景不仅指页面背景，还指由 CSS 设置的每个背景。大多数现代设计都使用背景图像进行布局；此外，辅助功能规则要求由 CSS 设置装饰性图像。

使用`retina.js`，您可以在*Less*中编写以下代码：

```less
.logo {
  .at2x('/images/my_image.png', 200px, 100px);
}
```

前面的代码将编译为以下 CSS：

```less
.logo {
  background-image: url('/images/my_image.png');
}

@media all and (-webkit-min-device-pixel-ratio: 1.5) {
  .logo {
    background-image: url('/images/my_image@2x.png');
    background-size: 200px 100px;
  }
}
```

此外，之前提到的其他预构建 mixin 库将具有用于设置 Retina 背景的 mixin。

# 总结

在本章中，您已经学会了如何保持代码清晰，并使用样式指南进行测试。您已经学会了如何使用具有预构建 mixin 的库，这有助于更快、更安全地开发您的*Less*代码。最后但同样重要的是，您已经学会了如何使用*Less*和图标字体，并使您的项目准备好 Retina。

在下一章中，您将学习如何在您的项目中集成*Less*，或者如何从头开始使用*Less*开始一个项目。您还将学习如何组织项目文件并重用旧的 CSS 代码。最后，您将使用媒体查询构建一个响应式网格。


# 第五章：将 Less 集成到你自己的项目中

现在是时候将*Less*集成到你的工作流程和项目中了。在本章中，你将学会迁移你当前的项目或从头开始使用*Less*。将讨论将你的 CSS 代码转换为*Less*代码的技术和工具，最后，你将学会使用*Less*构建和使用响应式网格。

本章将涵盖以下主题：

+   将 CSS 导入到*Less*中

+   将你的项目迁移到*Less*

+   从头开始一个项目

+   媒体查询和响应式设计

+   在你的项目和设计中使用网格

在使用*Less*并看到它如何解决重复代码和无法重用 CSS 的问题时，你可能会想知道何时开始在项目中使用*Less*。尽管这可能是本书中最重要的问题，答案却很简单。你将不得不立刻开始！CSS 的问题可能是你**设计过程**中的一些缺陷。一旦检测到缺陷，就没有理由不立即解决它们。如果你现在不开始，你可能永远不会开始，最终你将花费太多时间调试你的 CSS 代码，而不是在真正的设计任务上工作。

# 将 CSS 导入到 Less 中

正如你现在已经知道的那样，有效的 CSS 也是有效的*Less*代码。CSS 代码可以被导入到*Less*中。有不同的方法来做到这一点。在导入你的 CSS 之后，你可以通过编译器运行结果。这为你提供了一个在当前项目中开始使用*Less*的简单方法。

在开始导入你的 CSS 代码之前，考虑创建一个**样式指南**。样式指南有助于测试你的代码，如第四章中所述，*避免重复造轮子*。还要记住，*Less*是一个**CSS 预处理器**。这意味着你必须在将*Less*代码投入生产之前将其编译成 CSS。客户端编译只应用于测试目的！只是导入你的 CSS 并将其重新编译成 CSS 是没有意义的。导入 CSS 还提供了将现有 CSS 与新编写的*Less*代码结合以及逐步进行*Less*转换的机会。

## 使用@import 规则

之前，你已经看到*Less*中的`@import`规则用于将*Less*文件导入到你的项目中。*Less*中的这个规则是 CSS 中相同规则的扩展版本。

在之前章节的示例中，`@import`规则只用于导入*Less*文件。默认情况下，每个文件只被导入一次。完整的语法如下：

```less
@import (keyword) "filename";
```

有六个关键字可以与这个规则一起使用：`reference`，`inline`，`less`，`css`，`once`和`multiple`。例如，`@import (reference) "file.less"`中的`reference`关键字将使`file.less`中的 mixin 和类可用，而不会将它们编译到生成的 CSS 中。

这可以很容易地通过一个例子来展示。你可以从 Packt 网站([www.packtpub.com](http://www.packtpub.com))下载本书所有章节的示例代码。之前章节的示例布局将在这里再次使用。请记住，这个项目的主文件`styles.less`导入了其他项目文件。现在你可以使用它来重用导航栏。首先创建一个新文件，并将以下代码写入其中：

```less
@import (reference) "styles";
.nav:extend(.nav all){};
```

这两行将编译成以下代码：

```less
.nav {
  list-style: none outside none;
  padding: 0;
}
.nav li a {
  text-decoration: none;
  color: #000000;
  width: 100%;
  display: block;
  padding: 10px 0 10px 10px;
  border: 1px solid #004d00;
  margin-top: -1px;
}
.nav li a:hover {
  color: #ffffff;
  background-color: #004d00;
}
.nav li.active a {
  color: #000000;
  background-color: #00b300;
}
.nav li:first-child a {
  border-radius: 15px 15px 0 0;
}
.nav li:last-child a {
  border-radius: 0 0 15px 15px;
}
```

还要注意，前面的结果包含了原始项目中`variables.less`中定义的值。

`inline`关键字用于导入与*Less*不兼容的代码。虽然*Less*接受标准 CSS，但有时注释和 hack 不会被编译。使用`inline`关键字将 CSS 按原样导入输出。如下面的代码所示，`inline`关键字与`css`关键字有很大的不同。`less`关键字强制导入的代码被编译。使用`@import (less) "styles.css"`时，所有代码将像往常一样被编译。与此同时，`css`关键字强制`@import`作为普通的 CSS 导入。下面的代码显示了`inline`和`css`之间的区别：

```less
@import (css) "styles.css";
```

上述代码的输出如下：

```less
@import "styles.css";
```

在编译的 CSS 代码中，使用`@import`导入的样式表在所有其他规则之前声明。这些样式表可以在**CSS 优先级**中发挥作用，这在第一章中有所讨论，*使用 Less 改进 Web 开发*。因此，您不能应用高级技术，如命名空间，应该在开始时导入未使用*Less*创建的文件。

CSS 2.1 用户代理必须忽略任何出现在块内或在任何非忽略语句之后的`@import`规则，除了`@charset`或`@import`（[`www.w3.org/TR/CSS21/syndata.html#at-rules`](http://www.w3.org/TR/CSS21/syndata.html#at-rules)）。如果导入具有相同名称的文件两次，默认只会编译一个。如果使用`once`关键字，也会发生相同的情况；另一方面，如果使用`multiple`关键字，文件将在输出中被编译两次。下面的代码将为您演示使用`multiple`关键字时的多重输出的示例：

如果`styles.less`文件包含以下代码：

```less
p {
color: red;
}
```

您的*Less*代码如下：

```less
@import (multiple) "style";
@import (multiple) "style";
```

上述代码将输出以下 CSS 代码：

```less
p {
  color: red;
}
p {
  color: red;
}
```

# 迁移您的项目

使用不同的导入规则，您可以在项目中开始使用 Less 而无需更改代码。导入 CSS 后，您可以逐步开始定义变量和使用混合。在开始将其用于生产之前，始终检查新代码的输出。

### 提示

请记住，样式指南可以帮助您管理项目的迁移，也不要忘记在生产环境中使用*Less*之前，在服务器端将其编译为 CSS 代码。

## 组织您的文件

尝试以与前面示例相同的方式组织您的文件。为项目的变量和混合创建单独的文件。如果您的项目之前在`project.css`中定义了样式表，您的主*Less*文件可能如下所示：

```less
@import "reset.less";
@import "variables.less";
@import "mixins.less";
@import (less) "project.css";
```

在上述代码中，您将导入原始的`project.css`；或者，您可以将其重命名为`project.less`。还要注意，您最终将编译一个新的 CSS 文件，该文件将用于您的项目。可以使用相同的名称来命名此文件；确保不要覆盖原始的 CSS 文件。虽然新的 CSS 文件应用相同的样式，但这些文件更有组织性，*Less*保证它们只包含有效的 CSS。编译器还将压缩 CSS 文件。

## 将 CSS 代码转换为 Less 代码

在**迁移**过程中，您可能更喜欢不必一步一步地转换代码。有一些可用的工具可以将 CSS 代码转换为*Less*代码。这些工具应该谨慎使用。**Lessify**可以帮助您将 CSS 代码组织成*Less*代码。Lessify 将相同元素或类的规则放在一起。您可以通过访问[`leafo.net/lessphp/lessify/`](http://leafo.net/lessphp/lessify/)来使用 Lessify。

考虑以下 CSS 代码：

```less
p {
  color: blue;
}
p  a {
  font-size:2em;
}
p a:hover {
  text-decoration: none;
}
```

使用 Lessify 后，前面的 CSS 代码编译成以下*Less*代码：

```less
p {
  color:blue;
  a {
    font-size:2em;
  }
  a:hover {
    text-decoration:none;
  }
}
```

你可以在[`css2less.cc/`](http://css2less.cc/)找到另一个工具叫做 CSS2Less。此外，这个工具只会分组类和元素规则。Lessify 和 Css2Less 在组织你的样式时可能会有所帮助。这两个工具都不支持**媒体查询**。

从迄今为止学到的所有知识来看，通过开发你的*Less*代码来开始项目似乎是一个不错的做法。因此，通过使用*Less*构建样式指南来开始你的项目。

你的`project.less`文件可能如下所示：

```less
@import "reset.less";
@import "variables.less";
@import "mixins.less";
```

将`project.less`文件与客户端`less.js`编译器集成到你的样式指南中。之后，开始添加你的设计元素，或者在你的代码中添加注释。

当你完成了你的样式指南，你可以开始构建最终的 HTML 代码。如果你要构建一个响应式网站，你应该首先确定你将需要哪些**屏幕尺寸**。例如，移动设备、平板和台式机可能是一个不错的选择。

为了更好地理解在流程的这个阶段如何使用*Less*，以下两个部分描述了**CSS 媒体查询**在响应式设计中的作用，并教你如何使用**网格**。

# 媒体查询和响应式设计

媒体查询是 CSS3 模块，自 2012 年 6 月以来一直是 W3C 的候选推荐。媒体查询增加了在媒体查询评估为 true 时仅将样式表应用于 CSS 的可能性。媒体查询评估设备的类型和设备的特性。设备的类型有屏幕、语音和打印等，特性有宽度、**设备宽度**和分辨率等。

如今，屏幕类型和设备宽度在响应式网页设计中扮演着重要的角色。通过使用媒体查询，可以将 CSS 规则限制在指定的屏幕宽度上，从而根据不同的屏幕分辨率改变网站的呈现方式。

一个典型的媒体查询看起来像下面的代码行：

```less
@media  { ... }
```

例如，以下媒体查询在视口宽度大于 767 像素时将字体颜色设置为黑色：

```less
@media screen and (min-width: 768px) {
  color:black;
  //add other style rules here
}
```

在上述代码中，我们可以看到花括号之间的所有样式规则只有在屏幕宽度大于 768 像素时才会应用。这些样式规则将遵循正常的**级联规则**。

## 使你的布局流动

到目前为止，你的布局一直由`@basic-width`定义的固定宽度。流动设计将其宽度定义为视口或浏览器窗口宽度的百分比。

为了使你的布局流动，定义`@basic-width: 900px;`在`less/responsive/project.less`中。这个设定值不再定义你设计的宽度，而是在你的改变后只设置`max-width`变量。

之后，打开`.center-content()` mixin 中的`less/responsive/mixinsresponsive.less`，将`width:@basic-width;`改为`max-width:@basic-width;`。

页眉现在是流动的，无需进一步更改。页脚列也是基于`@basic-width`的，所以你也需要对它们进行更改。

页脚列的宽度由以下代码设置：

```less
width: ((@basic-width/3)-@footer-gutter);
```

请使用以下代码在`less/responsive/footer.less`中更改页脚列的宽度：

```less
width: ~"calc((1/3 * 100%) - @{footer-gutter})";
```

可以通过访问[`caniuse.com/#feat=calc`](http://caniuse.com/#feat=calc)来检查`calc()`函数的浏览器支持情况。还要记住第一章中关于`calc()`和**字符串插值**的说明，*使用 Less 改进 Web 开发*。*Less*代码是无状态的，因此这些宽度计算应该由浏览器中的 CSS 完成。一旦 CSS 加载完成，浏览器就有了真实的像素宽度，因此浏览器可以计算并呈现列的宽度。

最后，你将需要改变`less/contentresponsive.less`并在其中添加媒体查询。如果屏幕宽度小于 500 像素，导航和内容应该在你的布局中堆叠。

首先，通过将宽度设置为`width: 2 / 3 * 100%;`和`width: 1/ 3 * 100%;`，使`#content`和`#sidebar`变为流体。现在，宽度是流体的，您可以添加媒体查询。对于`#content`，您应该将代码更改为以下代码：

```less
  width:  2 / 3 * 100%;
  float:left;
  @media (max-width:500px) {
    width:100%;
    float:none;
  }
```

前面的代码如果屏幕宽度小于 500 像素，则将`#content`的宽度设置为`100%`。它还会删除元素的浮动。您应该对`#sidebar`做同样的操作。

进行这些更改后，屏幕宽度为 500 像素时，导航将堆叠在内容下方。

如何在屏幕宽度小于 500 像素的屏幕上交换导航和内容的位置，可以在`http://localhost/indexresponsivechange.html`中看到。您可以通过两个步骤完成这个过程。首先，在 HTML 文档中交换`#content`和`#sidebar`的内容。打开`http://localhost/indexresponsivechange.html`，并将源代码与`http://localhost/indexresponsive.html`进行比较。进行这些更改后，侧边栏将显示在屏幕的左侧。要将侧边栏移动到右侧，您应该将其浮动设置为`right`而不是`left`，如下面的代码所示：

```less
  //one third of @basic-width
  #sidebar {
   width: 1 / 3 * 100%;
   float:right;
   @media (max-width:500px) {
    width:100%;
    float:none;
   }
  }
```

在小屏幕上，布局现在看起来像以下的截图：

![使您的布局流动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_05_01.jpg)

在手机上您的布局可能会是这样的一个例子

### 在手机上测试您的布局

您肯定也会在手机上检查响应式布局。确保在 HTML 文档的头部添加以下额外的代码行：

```less
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

前面的代码强制移动浏览器在视口中加载您的网站，该视口等于设备的屏幕宽度。默认情况下，移动浏览器会在比屏幕尺寸更大的视口中加载网站。这样做可以让非移动网站在大屏幕上按预期加载。加载网站后，用户可以滚动和放大结果。如果您优化的移动布局在宽度大于 500 像素的视口中加载，媒体查询将无法工作，强制视口调整为设备的屏幕尺寸，从而防止媒体查询不被应用。请注意，这也意味着您将不得不使用屏幕宽度不超过 500 像素的手机测试此示例。您还可以在[`www.responsinator.com/`](http://www.responsinator.com/)等网站上测试您的设计。

### 首先为移动设备编码

如今，先为移动设备编写样式，然后使用媒体查询来调整它们以适应更大的屏幕是很常见的。您可以在示例布局的文件`header.less`和`content.less`中找到编码的移动设备优先原则的示例。还可以打开`less/responsive/footer.less`，看看媒体查询如何添加浮动：

```less
    @media (min-width:501px) {
      float: left;
      width: ((@basic-width/3)-@footer-gutter);
    }
```

这个例子展示了一种**移动设备优先**的编码方式。元素默认堆叠，并在屏幕尺寸增大时变为水平。请注意，诸如 Internet Explorer 8 之类的旧版浏览器不支持媒体查询，并且始终会显示堆叠版本。

# 在您的设计和工作流程中使用网格

前面的媒体查询示例没有使用网格。您可能想知道什么是网格，以及为什么应该使用它。**基于网格的布局**将设计分成一系列大小相等的列和行。内容和图形元素可以根据此布局进行组织。网格有助于为设计创建逻辑和正式的结构。它可以防止原始设计与 HTML 中最终实现之间的不一致，因为设计师和开发人员使用相同的网格。

网格在响应式设计中也很有帮助，因为网格的列可以轻松重新排列以适应不同的屏幕宽度。

在本书的初步章节中，您已经了解了定义布局结构的 CSS 模块。Flex boxes 和 columns 可以用来定义 CSS 布局和网格。尽管这些布局默认情况下是响应式的，或者可以很容易地定义为响应式，但它们还不是定义 CSS 布局的常用方式。如前所述，大多数现代浏览器尚未准备支持这些模块。幸运的是，有其他方法可以使用 CSS 定义网格。

网格的列宽可以定义为网格的百分比或固定宽度。流体网格将其宽度定义为视口的百分比。在流体网格中，列宽随屏幕宽度变化。流体布局可以重新排列内容以占用可用的屏幕宽度，因此用户需要滚动的次数更少。另一方面，设计师对设计的精确表示没有太多控制。因此，大多数响应式网格是流体和固定网格的混合体。

## 网格中 CSS 浮动的作用

CSS 的`float`属性是 CSS 中的一个位置属性；浮动将元素推到屏幕的左侧（或右侧），并允许其他元素围绕它包裹。因此，CSS 的`float`在大多数**CSS 网格**中起着重要作用。

一个示例将帮助您了解这是如何工作的。您将创建一个具有两列的网格。开始编写固定网格的*Less*代码。示例如下：

```less
@grid-container-width: 940px;
@column-number: 2;

.container {
  width: @grid-container-width;
  .row {
    .col {
 float: left;
              width: (@grid-container-width/@column-number);
    }
    .col2{
      width: 100%;
    }
  }
}
```

您可以使用上述代码的编译 CSS 和以下 HTML 代码：

```less
<div class="container">
  <div class="row">
    <div class="col">Column 1</div>
    <div class="col">Column 2</div>
  </div>
  <div class="row">
    <div class="col2">Column 3</div>
  </div>
</div>
```

您可以通过访问本书可下载示例代码中的`http://localhost/grid.html`来检查上述代码的结果。

现在，您有一个固定网格的示例。通过使用以下*Less*代码更改固定宽度，可以使此网格成为流体网格：

```less
@grid-container-width: 100%;
```

在这个网格中，`.container`类包含网格。此容器包含了使用`.row`类定义的行。您只需要定义两个额外的类，因为此网格有两列。第一个类`.col`定义了单列，第二个类`.col2`定义了双列。

### 使您的网格具有响应性

要使网格具有响应性，您必须定义一个或多个断点。断点定义了网站响应以提供合适布局的屏幕宽度；在断点以下或以上，网格可以提供不同的布局。在示例网格中，您可以描述两种情况。在第一种情况下，在断点以下（例如 768 像素），屏幕很小。在小屏幕上（记住手机屏幕），网格的列应该堆叠。在断点以上，对于平板电脑和台式机屏幕，网格应该变为水平，网格行的列将浮动在一起。

在*Less*中，您可以使用以下代码为小屏幕编写第一种情况：

```less
.container {
  width: @grid-container-width;
  .row {
    .col, .col2 {
      width: 100%;
    }
   }
}
```

所有列都占视口的`100%`宽度，没有一个浮动。从最小的屏幕开始编写代码将生成“移动优先”网格。移动优先设计从小屏幕（和移动浏览器）开始，为大屏幕重新排列和添加内容。您已经看到网格在较大屏幕上变为水平。其他示例可能是导航，它有另一种表示，或者图像滑块，它只对桌面用户可见。

现在尝试通过添加媒体查询并在*Less*中定义断点来使您的网格具有响应性，如下所示：

```less
@break-point: 768px;

.container {
  width: @grid-container-width;
  .row {
    .col, .col2 {
      width: 100%;
    }
    @media(min-width: @break-point) {
      .col {
        float: left;
        width: (@grid-container-width/@column-number);
      }
    }
  }
}
```

编译为 CSS 代码的上述代码将如下所示：

```less
.container {
  width: 100%;
}
.container .row .col,
.container .row .col2 {
  width: 100%;
}
@media (min-width: 768px) {
  .container .row .col {
    float: left;
    width: 50%;
  }
}
```

很容易看到现在`.row`类只在宽度大于 768 像素的屏幕上浮动。如果屏幕尺寸小于 786 像素，宽度列将堆叠。

### 清除浮动的作用

在上面的示例中，列通过应用`float:left`而变为水平。`clearfix()`混合在元素渲染后清除元素的浮动，无需额外的标记，因此可以用于网格的`.row`类。使用这些清除可以保证您的元素只在自己的行中浮动。

## 使用更具语义性的策略

在前一节中，您使用`div`元素和 CSS 类构建了一个网格。许多 CSS 框架，如**Twitter 的 Bootstrap**和**ZURB Foundation**，都是以这种方式构建它们的网格。批评者声称这种方法破坏了 HTML5 的语义性质。因此，他们有时甚至将其与使用 HTML 表定义布局的老式方法进行比较。HTML5 引入了语义标签，不仅描述结构，还描述文档的含义。例如，`header`标签是语义的；每个人都知道头部是什么，浏览器知道如何显示它们。

使用混合而不是类可以帮助您使您的网格更具语义。

这样的混合示例是以下*Less*代码：

```less
.make-columns(@number) {
  width: 100%;
  @media(min-width: @break-point) {
    float: left;
    width: (@grid-container-width* ( @number / @grid-columns ));
  }
}
```

上述代码可以使用以下*Less*代码进行编译：

```less
/* variables */
@grid-columns: 12;
@grid-container-width: 800px;
@break-point: 768px;

header,footer,nav{.make-columns(12);}
main{.make-columns(8);}
aside{.make-columns(4);}
```

上述 CSS 代码的 HTML 将如下所示：

```less
<header role="banner"></header>
<nav role="navigation"></nav>
<main role="main">
  <section></section>
</main>
<aside role="complementary"></aside>
<footer role="contentinfo"></footer>
```

请注意，在上述代码中，`@number`设置总宽度为`@number`乘以列宽度，并且上述网格中的列总数将固定为`12`。

## 使用网格类构建您的布局

`.make-columns()`混合也可以用于创建您的网格类，如下面的代码所示：

```less
.make-grid-classes(@number) when (@number>0) {
  .make-grid-classes(@number - 1);
  .col-@{number} {
    .make-columns(@number);
  }
}
.make-grid-classes(12);
```

上述代码将编译为以下 CSS 代码：

```less
.col-1 {
  width: 100%;
}
@media (min-width: 768px) {
  .col-1 {
    float: left;
    width: 66.66666666666666px;
  }
}
.col-2 {
  width: 100%;
}
@media (min-width: 768px) {
  .col-2 {
    float: left;
    width: 133.33333333333331px;
  }
}
…
.col-12 {

  width: 100%;

}

@media (min-width: 768px) {

  .col-12 {

    float: left;

    width: 800px;

  }

}
```

在上述代码中，使用混合来构建网格类是递归调用的。请回顾第三章中已经看到如何使用保护和递归构建循环。

## 构建嵌套网格

如果将`@grid-container-width`设置为`100%`并使您的网格流动，`.make-columns()`混合也可以用于构建嵌套网格。

访问`http://localhost/nestedgrid.html`以查看此类嵌套网格的示例。

在 HTML 中，您可以编写以下代码来创建一个带有标题、内容部分、侧边栏和页脚的页面：

```less
<div class="container">
<header role="banner">header</header>
<section id="content" role="content">
  <div class="content-column">Column 1</div>
  <div class="content-column">Column 2</div>
  <div class="content-column">Column 3</div>
</section>
<aside role="complementary">sidebar</aside>
<footer role="contentinfo">footer</footer>
</div>
```

内容部分将分为三个相等大小的列。要实现上述代码，您可以在*Less*中编写以下代码：

```less
.make-columns(@number) {
  width: 100%;
  @media(min-width: @break-point) {
    float: left;
    width: (@grid-container-width* ( @number / @grid-columns ));
  }
}

/* variables */
@grid-columns: 12;
@grid-container-width: 100%;
@break-point: 768px;

header,footer{.make-columns(12);}
section#content {
  .make-columns(8);
  div.content-column {
    .make-columns(4);
  }
}
#sidebar{.make-columns(4);}
```

在这里，对于`div.content-column`的`.make-columns(4);`语句将创建`33.3%`的宽度（*4 / 12 * 100%*）。33.3%将根据直接父元素进行计算。在这个例子中，`div.content-column`的直接父元素是`section#content`。`section#content` HTML 元素本身将占视口的`66.6%`的宽度（*8 / 12 *100%*）。

### 提示

请注意，如果您在项目中使用上述网格，应将代码分成不同的文件。如果为变量和混合创建不同的文件，您的代码将清晰而干净。

## 替代网格

在前面的示例中，您已经看到了随着屏幕尺寸增加而变为水平的列定义的网格。这些网格使用 CSS 浮动来将列对齐在一起。在某些情况下，主要是对于旧版本的浏览器，这可能会导致像素计算方面的一些问题。这个问题有时被描述为“亚像素舍入”问题。尽管`box-sizing: border-box;`可以解决相关问题，如第一章中所述，*使用 Less 改进 Web 开发*，但可以选择使用不同的网格定义。

CSS 隔离提供了一个解决方案。CSS 隔离并不容易理解。Susy ([`susydocs.oddbird.net/`](http://susydocs.oddbird.net/))将其描述如下：

> 每个浮动都相对于其容器定位，而不是前面的浮动。这有点像一个黑客，会将内容从流中移除，所以我不建议在孤立的浮动上构建整个布局，但在舍入错误真的让你头疼时，它可能非常有用。

CSS 隔离最初是 Zen Grids ([`zengrids.com/`](http://zengrids.com/))的一部分。Zen Grid 的实现是用 SCSS/SASS 编写的。将其重写为*Less*将相对容易；你可以尝试这个作为练习。如果你想尝试这个栅格系统，你也可以从[`github.com/bassjobsen/LESS-Zen-Grid`](https://github.com/bassjobsen/LESS-Zen-Grid)下载一些示例*Less*代码。

# 使用响应式栅格构建你的项目

在前面的示例中，只定义了栅格列。这应该给你一个很好和现实的印象，栅格是如何工作以及如何使用它们的。完整的栅格代码还定义了响应式容器和行类。大多数栅格还会在列之间有所谓的间距。间距（通常是固定的）是分隔列的空间。这也意味着跨越两列的宽度包括一个间距。

在第四章*避免重复造轮子*中，你已经学会了重用*Less*和预构建的 mixin；你也可以对栅格做同样的事情。你不需要自己编写完整的代码。Twitter 的 Bootstrap、Golden Grid System ([`goldengridsystem.com/`](http://goldengridsystem.com/))或 Less Framework 4 ([`lessframework.com/`](http://lessframework.com/))等框架将为你提供所需的所有*Less*代码和 mixin。这些框架中的一些将在第六章*Bootstrap3、WordPress 和其他应用*中进一步讨论。

以下示例将使用 Preboot 的栅格 mixin 来构建项目的栅格。最后，你将重新构建之前使用的布局示例。

## 使用 Preboot 的栅格系统

Preboot 的栅格系统使你能够使用少量变量和 mixin 构建移动优先的栅格布局。正如你之前看到的，你可以使用 Preboot 的 mixin 来创建语义化的栅格或定义更一般的栅格类。

Preboot 定义了栅格的变量，如下所示：

```less
@grid-columns:          12;
@grid-column-padding:   15px;
@grid-float-breakpoint: 768px;
```

在前面的代码片段中，`@grid-column-padding`定义了栅格的间距宽度，正如前面提到的。栅格列采用了移动优先的方法进行编码。这意味着默认情况下，它们在视口宽度等于或大于`@grid-float-breakpoint`时会垂直堆叠并水平浮动。当然，不要忘记`@grid-columns`设置了栅格列的数量。

Preboot 没有提供包含栅格行的容器。你可以自己定义这个变量，以定义你的栅格的最大宽度，如下面的代码所示：

```less
@grid-width: 960px;
```

每个标准栅格系统的部分都有三个可用的 mixin，分别是：

+   `.make-row()`: 为列提供一个包装器，通过负边距对齐它们的内容并清除浮动

+   `grid.make-column(n)`: 用于生成`n`个栅格列，作为可用栅格列的百分比（默认设置为`12`）

+   `.make-column-offset(n)`: 通过边距将列向右推`n`列

现在你可以使用前面的变量和 mixin 与 Preboot 一起制作栅格的可见表示。首先，在 HTML 中定义一些栅格行，如下所示：

```less
<div class="container">
<div class="row">
  <div class="col-12"></div>
</div>
<div class="row">
  <div class="col-11"></div><div class="col-1"></div>
</div>
<div class="row">
  <div class="col-10"></div><div class="col-2"></div>
</div>
<div class="row">
  <div class="col-9"></div><div class="col-3"></div>
</div>
<div class="row">
  <div class="col-6"></div><div class="col-6"></div>
</div>
<div class="row">
  <div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div><div class="col-1"></div>
</div>
</div>
```

这里使用的栅格包含 12 列，你可以看到每行的列数应该总和为 12。

现在你可以编写前面栅格的*Less*代码，其中使用了 Preboot 的 mixin 和变量。同样，你可以将代码分成不同的文件，以保持清晰。

`project.less`文件包含以下*Less*代码，将所有所需的文件导入项目：

```less
@import "../normalize.less";
@import "../basics.less";
#preboot { @import (reference) "preboot-master/less/preboot.less"; }
@import "variables.less";
@import "mixins.less";
@import "grid.less";
@import "styles.less";
```

variables.less 文件包含以下*Less*代码，定义了项目的变量：

```less
@grid-columns:          12;
@grid-column-padding:   30px;
@grid-float-breakpoint: 768px;
@grid-width: 1200px;
```

`mixins.less`文件包含了项目的 mixin：

```less
.make-grid-classes(@number) when (@number>0) {

  .make-grid-classes(@number - 1);
  .col-@{number} {
    #preboot > .make-column(@number);
  }
}
```

请注意这里使用了`#preboot > .make-column(@number);`命名空间。现在循环结构应该对您来说很熟悉了。

`grid.less`文件包含了定义网格类的*Less*代码：

```less
.container {
max-width: @grid-width;
padding: 0 @grid-column-padding;
}
.row {
  #preboot > .make-row()
}
& { .make-grid-classes(12); }
```

上述代码将创建用于您的网格的 CSS 类。请注意，`.container`类将用于设置网格的最大宽度。它还设置了填充，这是需要纠正网格周围的槽口的。每行的填充为`@grid-column-padding`大小的一半。在两行之间，`.containter`类使槽口等于`@grid-column-padding`，但现在，网格的左右两侧只有填充，大小为`@grid-column-padding`的一半。`.row`类通过添加大小为`@grid-column-padding`一半的负边距来纠正这一点。最后，容器的填充防止了这个负边距使网格偏离屏幕。

还请注意`& { .make-grid-classes(12); }`语句中的和符号。这个和符号（引用）保证了继承的`.make-row` mixin 在需要时可见。命名空间 mixin 在全局范围内不可见。这个问题可能在以后的*Less*版本中得到解决。

最后，`styles.less`文件包含了定义样式以使网格列可见的*Less*代码：

```less
.row [class^="col-"]{
  background-color: purple;
  height: 40px;
  border: 2px solid white;
}
```

从`styles.less`编译的 CSS 只用于使网格列可见。如第一章中所述，*使用 Less 改进 Web 开发*，`[class^="col-"]`是一个**CSS 选择器**，选择具有以`col-`开头的类的网格列。每列都有高度（`height`）、背景颜色（`background-color`）和边框（`border`）。此外，在这里，`box-sizing: border-box;`语句确保边框宽度不影响列的宽度。

您可以通过在浏览器中访问`http://localhost/prebootgridclasses.html`来查看最终结果。结果将如下图所示：

![使用 Preboot 的网格系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-05-02.jpg)

Preboot 的 12 列网格的表示

当您看到网格的前面的表示时，您可能会想知道槽口在哪里。如前所述，槽口将由列的填充构成。您可以通过在列中添加一些内容来使其可见。因此，请尝试将以下代码添加到您的 HTML 文件中：

```less
<div class="row">
  <div class="col-6"><p style="background-color:yellow;">make the gutter visible</p></div>
  <div class="col-6"><p style="background-color:yellow;">make the gutter visible</p></div>
</div>
```

将上述代码添加到 HTML 文件后，结果将如下图所示：

![使用 Preboot 的网格系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS-05-03.jpg)

Preboot 的 12 列网格；内容使槽口可见

在前面的图片中，您将看到网格的槽口。还请注意，`.col-6`类只在两侧有槽口，因此`.col-6`的总内容宽度将是 6 列，包括五个槽口。

# 使用网格 mixin 来构建语义布局

在前面的部分中，您使用了 Preboot 的网格 mixin 来构建网格类。在本章的最后一节中，您将使用这些 mixin 来构建语义布局。

您可以使用之前使用的相同示例。在开始之前，您应该撤消在媒体查询示例中所做的更改。您在这里不需要这些媒体查询，因为网格默认是响应式的。

### 注意

您可以通过访问`http://localhost/semanticgrid.html`来观看结果，并且您将在`/less/semanticgrid/`文件夹中找到此示例的 Less 文件。

在当前示例布局中，容器样式应用于 body 元素。现在似乎没有理由添加额外的`div`容器（包装器）。所有现代浏览器都将 body 视为普通的块级元素。如果出于某种原因希望添加额外的包装器，请这样做。例如，出于某种原因添加版权信息到您的布局；当然，body 不允许您在其后添加内容。在这两种情况下，此容器保存网格的行。

打开`/less/semanticgrid/project.less`，并将以下*Less*代码写入其中提到的容器：

```less
body {
  max-width: @basic-width;
  padding: 0 @grid-column-padding;
  margin: 0 auto;
}
```

请注意，在`/less/semanticgrid/variables.less`中，`@basic-width`设置为 900 像素，以明确表明网格在 768 像素处具有断点响应。

在此语义示例中，您将使用在`/less/semanticgrid/variables.less`中定义的仅三列网格，使用以下代码：

```less
/* grid */
@grid-columns:          3;
@grid-column-padding:   30px;
@grid-float-breakpoint: 768px;
```

在`/less/semanticgrid/project.less`中，您可以看到此示例不使用 Preboot 的命名空间。在撰写本书时，最新版本的*Less*不支持在全局范围内使用命名空间的变量。在以后的版本中，您可以期望`#namespace > @variable`起作用，但目前还不起作用。使用命名空间将使命名空间内的设置（例如`@grid-columns`）从全局范围内变得复杂或不可能。

现在，打开`/less/semanticgrid/header.less`。在此文件中，您可以删除旧的`.centercontent`类。

使用 Preboot 的`.make-row()` mixin 使`header`标签像一行一样工作，并在其中使用`.make-column(3)` mixin 调用`h1`。现在，`h1`元素将具有三列的宽度。

对`/less/semanticgrid/content.less`执行相同操作，但在此处使用`.make-column(2)`为内容和`.make-column(1)`为侧边栏。

同样，您将看到在移动版本中，导航位于内容下面，就像之前解释的那样。您可以使用在媒体查询示例中看到的相同技巧来解决此问题。在第六章中，*Bootstrap3，WordPress 和其他应用程序*，您将学习解决此类问题的其他方法。目前，反转 HTML 代码中的侧边栏和内容，以便侧边栏在内容之前。之后，您应该给侧边栏一个`float: right`调用，如以下代码所示：

```less
@media (min-width: @grid-float-breakpoint) {
  float:right;
}
```

最后，您需要更改页脚。请再次为`footer`标签使用`.make-row()`。页脚内的`div`元素，即列，将使用`.make-column(1)`进行样式设置。完成此操作后，您将看到页脚的列相互挨着，之间没有任何空白。请记住，网格的间距在列的内容之间，而不是在列本身之间。

为了解决前面提到的问题，请在`div`元素内部的`p`元素上应用`background-color`，`border-radius`和`box-shadow`，如以下代码所示：

```less
div {
.make-column(1);
p {
  min-height: @footer-height;
  background-color: @footer-dark-color;
  //margin: @footer-gutter (@footer-gutter / 2);
  .border-radius(15px);
  .box-shadow(10px 10px 10px, 70%);
  padding: 10px;
  }
}
```

前面的代码将使栅格之间的间距可见，就像之前看到的那样。网格的间距在列之间添加了一些空白。左列的左侧和右列的右侧也会有间距。这将使页脚列的总可见宽度小于页眉。您可以通过在这些侧面将`div`的填充设置为`0`来去除此间距。再次更改中间列的填充，以再次使三列具有相同的宽度。可以使用以下代码来实现：

```less
div {

  &:first-child {

    padding-left: 0;

  }

  &:nth-child(2) {

    padding-left: 15px;

    padding-right: 15px;

  }

  &:last-child {

    padding-right: 0;

  }

}
```

访问`http://localhost/semanticgrid.html`，查看前面代码的最终结果。调整浏览器窗口大小，以确保它确实是响应式的。

# 扩展您的网格

在前面的例子中，您使用了一个带有一个断点的网格。在断点以下，您的行简单地堆叠。这在许多情况下似乎有效，但有时，也有必要为小屏幕创建一个网格。想象一下，您构建了一个照片库。在大屏幕上，一行中会有四张照片。对于较小的屏幕，照片不应该堆叠，而是一行中显示两张而不是四张。

同样，您可以使用网格类或 mixin 来解决这种情况，以获得更语义化的解决方案。

在这两种情况下，您还应该使您的照片具有响应性。您可以通过为您的图片添加样式来实现这一点。将`max-width`设置为`100%`，将`height`设置为`auto`在大多数情况下都可以奏效。`max-width`变量可以防止图像显示宽于其原始尺寸，并确保它们在其他情况下获得其父元素宽度的 100%。在小屏幕上，这些图像将获得视口宽度的 100%。

要使您的图像默认具有响应性，您可以将以下代码添加到您项目的*Less*代码中：

```less
img {
  display: block;
  height: auto;
  max-width: 100%;
}
```

如果您喜欢通过为源中的每个图像添加一个类来明确地使您的图像具有响应性，您可以使用以下*Less*代码来创建这样一个类：

```less
.responsive-image {
  display: block;
  height: auto;
  max-width: 100%;
}
```

## 为小网格添加网格类

使用网格类时，您必须更改 Preboot 中的原始`.make-column` mixin。这个`.make-columns()` mixin 设置了列的样式并添加了一个媒体查询。`.make-columns()` mixin 中的媒体查询让列在更宽的视口上水平浮动。对于新的小网格，您不需要媒体查询，因为列根本不应该堆叠。

为了实现这一点，您可以将 mixin 拆分为两个新的 mixin，如下面的代码所示：

```less
.make-columns(@columns) {
  // Prevent columns from collapsing when empty
  min-height: 1px;
  // Set inner padding as gutters instead of margin
  padding-left: @grid-column-padding;
  padding-right: @grid-column-padding;
  // Proper box-model (padding doesn't add to width)
  .box-sizing(border-box);
}

.float-columns(@columns) {
  float: left;
  // Calculate width based on number of columns available
  width: percentage(@columns / @grid-columns);
}
```

编写了前面的 mixin 之后，您还应该创建两个 mixin，这两个 mixin 会循环创建您的网格类。

第一个 mixin 应该如下代码所示：

```less
.make-grid-columns(@number) when (@number>0) {

  .make-grid-columns(@number - 1);

  .col-small-@{number},.col-large-@{number} {
    .make-columns(@number)
  }
}
```

前面的 mixin 将通过`grid.less`中的`.make-grid-columns(12);`语句调用。这些 mixin 将编译成以下代码：

```less
.col-small-1,
.col-large-1 {
  min-height: 1px;
  padding-left: 30px;
  padding-right: 30px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
}
.col-small-2,
.col-large-2 {
  min-height: 1px;
  padding-left: 30px;
  padding-right: 30px;
  -webkit-box-sizing: border-box;
  -moz-box-sizing: border-box;
  box-sizing: border-box;
}
```

在这之后，您可以很容易地看到前面的代码可以优化为以下代码：

```less
div[class~="col"] {
  // Prevent columns from collapsing when empty
  min-height: 1px;
  // Set inner padding as gutters instead of margin
  padding-left: @grid-column-padding;
  padding-right: @grid-column-padding;
  // Proper box-model (padding doesn't add to width)
  .box-sizing(border-box);
}
```

第二个 mixin 将如下代码所示：

```less
.float-grid-columns(@number; @grid-size: large;) when (@number>0) {
  .float-grid-columns(@number - 1,@grid-size);
  .col-@{grid-size}-@{number} {
     .float-columns(@number)
  }
}
```

前面的 mixin 将通过以下代码在`grid.less`中调用：

```less
.float-grid-columns(12,small);
@media (min-width: @grid-float-breakpoint) {
  .float-grid-columns(12);
}
```

前面的代码将创建两组网格类。大网格类只有在媒体查询为真时才会应用。您可能会想为什么不能在一个单独的循环中创建这些网格类。这是因为*最后的声明获胜*规则；您应该在小网格类之后定义所有的大网格类。例如，如果`col-large-2`在`col-small-3`之前定义，您就不能使用`<div class="col-small-3 col-large-2">`，因为`col-small-3`会覆盖`col-large-2`的样式。

在创建了前面描述的 mixin 之后，您可以按照以下方式编写您的 HTML 代码：

```less
<div class="row">
  <div class="col-small-6 col-large-3"></div>
  <div class="col-small-6 col-large-3"></div>
  <div class="col-small-6 col-large-3"></div>
  <div class="col-small-6 col-large-3"></div>
</div>
```

前面的代码将在您的屏幕上显示四列。这些列宽度大于 768 像素。该代码还将在较小的屏幕上显示两列。您可以通过访问`http://localhost/prebootgridclassesextend.html`来查看这个例子。

## 在您的语义化代码中应用小网格

如果您选择了语义化的方式来构建您的网格，下面的例子将帮助您在之前构建的布局的页脚中添加一个小网格。您可以在这个例子中再次使用`/less/semanticgrid/content.less`中的文件。

布局在 768 像素处有一个断点。在这个断点以下，即在小屏幕上，页脚应该有三列，在大屏幕上，页脚列应该堆叠。

您可以重用本章前面使用的 Preboot mixin 来构建一个响应式网格，以创建如前所述的页脚列。首先，将 mixin 拆分为两个新的 mixin：一个用于浮动，一个用于样式化列，如下面的代码所示：

```less
.less-make-column(@columns) {
  float: left;
  // Calculate width based on number of columns available
  width: percentage(@columns / @grid-columns);
}
.iscolumn()
{
  // Prevent columns from collapsing when empty
  min-height: 1px;
  // Set inner padding as gutters instead of margin
  padding-left: @grid-column-padding;
  padding-right: @grid-column-padding;
  // Proper box-model (padding doesn't add to width)
  .box-sizing(border-box);
}
```

创建这些 mixin 之后，您可以将它们与媒体查询一起使用，如下所示：

```less
 footer {
  .make-row();
  div {
    .iscolumn();
    .less-make-column(1);
    @media (min-width: @grid-float-breakpoint) {
      .less-make-column(3);
    }
   }
}
```

# 总结

很遗憾，你已经到达了本章的结尾。希望你觉得自己已经能够用*Less*开始自己的项目了。在本章中，你学会了如何在项目中使用*Less*。你还学会了如何使用媒体查询和网格来构建响应式网站。现在你已经准备好在项目中开始使用*Less*了。最后，你将有更多时间来处理真正的设计任务。在下一章中，你将介绍其他使用*Less*的项目和框架。你还将学习如何在自己的项目中使用它们。


# 第六章：Bootstrap 3，WordPress 和其他应用程序

在阅读了前面的章节之后，你应该已经学会了如何使用*Less*构建自己的项目。你将在同样的时间内写出更好的 CSS 并取得更多的成就。你现在绝对已经准备好了最后一步。在本书的最后一章中，你将学习如何在其他知名框架、应用程序和工具中使用*Less*。你将了解到使用*Less*构建更好项目的工具，这些项目可以使用、定制和扩展*Less*。 

本章将涵盖以下主题：

+   Bootstrap 3

+   语义化 UI

+   使用*Less*构建网格

+   WordPress 和*Less*

+   编译*Less*代码的替代编译器

# Bootstrap 3

Bootstrap 3，以前被称为**Twitter 的 Bootstrap**，是用于构建应用程序前端的 CSS 和 JavaScript 框架。Bootstrap 3 中的三指的是这个框架的第三个版本；在本书中提到 Bootstrap 时，指的就是这个第三个版本。Bootstrap 3 与框架早期版本有重要的变化。Bootstrap 3 与早期版本不兼容。

Bootstrap 3 可以用来构建出色的前端。你可以下载完整的框架，包括 CSS 和 JavaScript，并立即开始使用。Bootstrap 还有一个**网格**。Bootstrap 的网格默认是移动优先的，有 12 列。事实上，Bootstrap 定义了四个网格：小于 768 像素的超小网格（手机），768 到 992 像素之间的小网格（平板电脑），992 到 1200 像素之间的中等网格（桌面），最后，大于 1200 像素的大桌面的大网格。在第五章中，*将 Less 集成到您自己的项目中*，你使用 Preboot 的 mixin 构建了一个网格；Bootstrap 的网格以类似的方式工作。

网格、所有其他 CSS 组件和 JavaScript 插件在[`getbootstrap.com/`](http://getbootstrap.com/)上都有描述和文档。

Bootstrap 的默认主题如下截图所示：

![Bootstrap 3](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_01.jpg)

使用 Bootstrap 3 构建的布局示例

过去所有的 Bootstrap 网站看起来都很相似的时代已经远去。Bootstrap 将给你创造创新设计所需的所有自由。

关于 Bootstrap 还有很多要讲，但现在让我们回到*Less*。

## 使用 Bootstrap 的 Less 文件

Bootstrap 的所有 CSS 代码都是用*Less*编写的。你可以下载 Bootstrap 的*Less*文件并重新编译自己的版本的 CSS。*Less*文件可以用于定制、扩展和重用 Bootstrap 的代码。在接下来的章节中，你将学习如何做到这一点。

要下载*Less*文件，请在[`getbootstrap.com/`](http://getbootstrap.com/)上的 Bootstrap 的 GitHub 页面[`github.com/twbs/bootstrap`](https://github.com/twbs/bootstrap)上选择**下载 Zip**在右侧栏。

### 使用 Grunt 构建 Bootstrap 项目

在下载了前面提到的文件之后，你可以使用**Grunt**构建一个 Bootstrap 项目。Grunt 是一个 JavaScript 任务运行器；它可以用于自动化你的流程。Grunt 在执行重复任务时会帮助你，比如代码的缩小、编译、单元测试和代码的 linting。

Grunt 在**node.js**上运行，并使用**npm**，你在安装*Less*编译器时看到了。Node.js 是一个独立的 JavaScript 解释器，建立在谷歌的 V8 JavaScript 运行时上，就像在 Chrome 中使用的那样。Node.js 可以用于轻松构建快速、可扩展的网络应用程序。

当你解压下载的文件时，你会在其中找到`Gruntfile.js`和`package.json`等文件。`package.json`文件包含了作为 npm 模块发布的项目的元数据。`Gruntfile.js`文件用于配置或定义任务和加载 Grunt 插件。Bootstrap Grunt 配置是一个很好的例子，可以向你展示如何为包含 HTML、*Less*（CSS）和 JavaScript 的项目设置自动化测试。这本书无法涵盖所有内容；关于 Grunt.js 的更多信息可以在[`www.packtpub.com/grunt-js-cookbook/book`](http://www.packtpub.com/grunt-js-cookbook/book)上找到*Grunt.js Cookbook*。作为*Less*开发者，对你有趣的部分在下面的章节中提到。

在`package.json`文件中，你会发现 Bootstrap 使用`grunt-contrib-less`来编译它的*Less*文件。在撰写本书时，`grunt-contrib-less`插件使用 less.js 版本 1.7 来编译*Less*。与 Recess（Bootstrap 先前使用的另一个 JavaScript 构建工具）相比，`grunt-contrib-less`也支持源映射。

除了`grunt-contrib-less`，Bootstrap 还使用`grunt-contrib-csslint`来检查编译后的 CSS 是否存在语法错误。`grunt-contrib-csslint`插件还有助于改善浏览器兼容性、性能、可维护性和可访问性。该插件的规则基于面向对象的 CSS 原则（[`www.slideshare.net/stubbornella/object-oriented-css`](http://www.slideshare.net/stubbornella/object-oriented-css)）。你可以通过访问[`github.com/stubbornella/csslint/wiki/Rules`](https://github.com/stubbornella/csslint/wiki/Rules)来获取更多信息。

Bootstrap 大量使用*Less*变量，这些变量可以通过自定义器进行设置。

曾经研究过`Gruntfile.js`源代码的人可能也会找到对`BsLessdocParser` Grunt 任务的引用。这个 Grunt 任务用于基于 Bootstrap 使用的*Less*变量动态构建 Bootstrap 的自定义器。尽管解析*Less*变量来构建文档等过程非常有趣，但这个任务在这里不再讨论。你将在本章后面了解到自定义器。

本节以`Gruntfile.js`中执行*Less*编译的部分结束。`Gruntfile.js`中的以下代码应该让你对这段代码的外观有所了解：

```less
    less: {
      compileCore: {
        options: {
          strictMath: true,
          sourceMap: true,
          outputSourceFiles: true,
          sourceMapURL: '<%= pkg.name %>.css.map',
          sourceMapFilename: 'dist/css/<%= pkg.name %>.css.map'
        },
        files: {
          'dist/css/<%= pkg.name %>.css': 'less/bootstrap.less'
        }
      }
```

最后，让我们来看一下从命令行运行 Grunt 并构建 Bootstrap 的基本步骤。Grunt 将通过 npm 安装。Npm 会检查 Bootstrap 的`package.json`文件，并自动安装列在那里的必要的本地依赖项。

要使用 Grunt 构建 Bootstrap，你需要在命令行上输入以下命令：

```less
> npm install -g grunt-cli
> cd /path/to/extracted/files/bootstrap

```

之后，你可以通过运行以下命令来编译 CSS 和 JavaScript：

```less
> grunt dist

```

这将把你的文件编译到`/dist`目录中。`> grunt test`命令也会运行内置的测试。

### 编译你的 Less 文件

虽然你可以使用 Grunt 构建 Bootstrap，但并不一定非要使用 Grunt。你会在根目录`/bootstrap`内找到一个名为`/less`的单独目录中的*Less*文件。主项目文件是`bootstrap.less`；其他文件将在下一节中解释。你可以像在前面的章节中一样使用`bootstrap.less`。

你可以将`bootstrap.less`与 less.js 一起包含到你的 HTML 中进行测试。

```less
  <link rel="bootstrap/less/bootstrap.less" type="text/css" href="less/styles.less" />
  <script type="text/javascript">less = { env: 'development' };</script>
  <script src="img/less.js" type="text/javascript"></script>
```

当然，你也可以在服务器端编译这个文件，方法如下：

```less
lessc bootstrap.less > bootstrap.css

```

### 深入了解 Bootstrap 的 Less 文件

现在是时候更详细地查看 Bootstrap 的*Less*文件了。`/less`目录包含了一长串文件。您可以通过它们的名称来识别一些文件。您之前已经看到了一些文件，比如`variables.less`、`mixins.less`和`normalize.less`。打开`bootstrap.less`文件，看看其他文件是如何组织的。`bootstrap.less`文件中的注释告诉您，*Less*文件按功能组织，如下面的代码片段所示：

```less
// Core variables and mixins
// Reset
// Core CSS
// Components
```

尽管 Bootstrap 基本上是基于 CSS 的，但一些组件在没有相关的 JavaScript 插件的情况下无法工作。导航栏组件就是一个例子。Bootstrap 的插件需要**jQuery**。您不能使用最新的 2.x 版本的 jQuery，因为这个版本不支持 Internet Explorer 8。

要编译您自己的 Bootstrap 版本，您必须更改`variables.less`中定义的变量。在前面的章节中，您已经学会了不必覆盖原始文件和变量。使用*最后声明胜出*和*延迟加载*规则时，重新声明一些变量将变得很容易。变量的重新声明在第二章中已经讨论过，*使用变量和混合*。

### 使用 Less 创建自定义按钮

默认情况下，Bootstrap 定义了七种不同的按钮，如下截图所示：

![使用 Less 创建自定义按钮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_02.jpg)

Bootstrap 3 的七种不同按钮样式

在开始编写*Less*代码之前，请查看 Bootstrap 按钮的以下 HTML 结构：

```less
<!-- Standard button -->
<button type="button" class="btn btn-default">Default</button>
```

一个按钮有两个类。全局来看，第一个`.btn`类只提供布局样式，第二个`.btn-default`类添加颜色。在这个例子中，您只会改变颜色，按钮的布局将保持不变。

在文本编辑器中打开`buttons.less`文件。在这个文件中，您会找到不同按钮的以下*Less*代码：

```less
// Alternate buttons
// --------------------------------------------------
.btn-default {
  .button-variant(@btn-default-color; @btn-default-bg; @btn-default-border);
}
```

上述代码清楚地表明，您可以使用`.button-variant()`混合来创建自定义按钮。例如，要定义一个自定义按钮，您可以使用以下*Less*代码：

```less
// Customized colored button
// --------------------------------------------------
.btn-colored {
  .button-variant(blue;red;green);
}
```

在上述情况下，如果您想要使用自定义按钮扩展 Bootstrap，可以将您的代码添加到一个新文件中，并将该文件命名为`custom.less`。将`@import custom.less`附加到`bootstrap.less`中的组件列表中将起作用。这样做的缺点是，当更新 Bootstrap 时，您将不得不再次更改`bootstrap.less`；或者，您可以创建一个名为`custombootstrap.less`的文件，其中包含以下代码：

```less
@import "bootstrap.less";
@import "custom.less";
```

前面的步骤使用自定义按钮扩展了 Bootstrap；或者，您还可以通过重新声明其变量来更改默认按钮的颜色。为此，再次创建一个名为`custombootstrap.less`的文件，并将以下代码添加到其中：

```less
@import "bootstrap.less";
//== Buttons
//
//## For each of Bootstrap's buttons, define text, background and border color.
@btn-default-color:             blue;
@btn-default-bg:                 red;
@btn-default-border:           green;
```

在某些情况下，例如，您需要使用 Bootstrap 的按钮样式，而不需要其他任何东西。在这种情况下，您可以在`@import`指令中使用`reference`关键字，如前面在第五章中讨论的那样，*将 Less 集成到您自己的项目中*。

您可以使用以下*Less*代码为您的项目创建一个 Bootstrap 按钮：

```less
@import (reference) "bootstrap.less";
.btn:extend(.btn){};
.btn-colored {
  .button-variant(blue;red;green);
}
```

您可以通过在浏览器中访问`http://localhost/index.html`来查看上述代码的结果。

请注意，根据您使用的 less.js 版本，您可能会在编译输出中找到一些意外的类。**媒体查询**或扩展类有时会破坏旧版本的 less.js 中的引用。

### 使用 Less 自定义 Bootstrap 的导航栏

Bootstrap 的一个重要组件是导航栏。导航栏为网站添加了主要导航。它主要包含标志或品牌名称、搜索框和导航链接。在本书中，导航栏指的是导航栏。典型的 Bootstrap 导航栏将如下截图所示：

![使用 Less 自定义 Bootstrap 的导航栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_03.jpg)

Bootstrap 导航栏的示例

Bootstrap 的导航栏默认是响应式的。在小屏幕尺寸上，上述导航栏将如下截图所示：

![使用 Less 自定义 Bootstrap 的导航栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_04.jpg)

折叠和展开的 Bootstrap 导航栏

除了 CSS 之外，Bootstrap 的响应式导航栏还需要折叠 JavaScript 插件。这个插件应该包含在您的 Bootstrap 版本中。

现在，尝试更改默认导航栏的颜色作为示例。为此，您必须首先打开`variables.less`，以找出哪些变量给导航栏上色，如下所示：

```less
//== Navbar
//
//##

// Basics of a navbar
@navbar-height:                    50px;
@navbar-margin-bottom:             @line-height-computed;
@navbar-border-radius:             @border-radius-base;
@navbar-padding-horizontal:        floor((@grid-gutter-width / 2));
@navbar-padding-vertical:          ((@navbar-height - @line-height-computed) / 2);
@navbar-collapse-max-height:       340px;

@navbar-default-color:             #777;
@navbar-default-bg:                #f8f8f8;
@navbar-default-border:            darken(@navbar-default-bg, 6.5%);

// Navbar links
@navbar-default-link-color:                #777;
@navbar-default-link-hover-color:          #333;
@navbar-default-link-hover-bg:             transparent;
@navbar-default-link-active-color:         #555;
@navbar-default-link-active-bg:            darken(@navbar-default-bg, 6.5%);
@navbar-default-link-disabled-color:       #ccc;
@navbar-default-link-disabled-bg:          transparent;

// Navbar brand label
@navbar-default-brand-color:               @navbar-default-link-color;
@navbar-default-brand-hover-color:         darken(@navbar-default-brand-color, 10%);
@navbar-default-brand-hover-bg:            transparent;

// Navbar toggle
@navbar-default-toggle-hover-bg:           #ddd;
@navbar-default-toggle-icon-bar-bg:        #888;
@navbar-default-toggle-border-color:       #ddd;
```

您已经看到找到这些变量很容易。文件中的注释是找到它们的方便指南。您还会看到变量的有意义和描述性名称是有意义的，就像在第二章中学到的那样，*使用变量和 mixin*。另一方面，您可能会想知道为什么导航栏只有这么多变量。导航栏有许多元素和不同的表现形式，需要用变量来定义。正如前面提到的，Bootstrap 的导航栏默认是响应式的；它会在较小的屏幕上折叠（或者从移动优先的角度来看，它会在较大的屏幕尺寸上变成水平的）。因此，必须为导航栏的折叠和水平版本定义样式。上述代码还设置了导航栏链接和折叠菜单切换按钮的颜色。

就像 Bootstrap 的按钮一样，Bootstrap 的导航栏也是用两个类构建的，如下面的代码片段所示：

```less
<nav class="navbar navbar-default" role="navigation"></nav>
```

在这种情况下，`.navbar`类提供布局样式，第二个`.navbar-default`类添加了颜色和其他变化。`.navbar`类还有一个设置其类型的第三个类。有四种类型的导航栏：默认、固定在顶部、固定在底部和静态顶部。

导航栏类可以在`navbar.less`中找到。导航栏没有 mixin 来构建这些类。*Less*代码提供了两种备用导航栏样式的类：`.navbar-default`和`.navbar-inverse`。

由于没有 mixin 可用，重新声明一些导航栏的变量将是自定义其外观和感觉的最佳选择。或者，您可以复制完整的`.navbar-default`类并用于自定义。Bootstrap 打算每页只使用一个导航栏，因此额外的样式类没有增加的价值。

例如，现在设置如下：

```less
@navbar-default-color:          red;
@navbar-default-bg:              blue;
@navbar-default-border:        yellow;
```

您可以将这些变量声明为`customnavbar.less`，并在该文件中添加`@import "bootstrap.less";`。现在，您可以编译`customnavbar.less`。

您可以通过在浏览器中访问`http://localhost/customnavbar.html`来查看上述代码的结果。

### Bootstrap 的类和 mixin

浏览组件时，您会发现 Bootstrap 是一个非常完整的框架。在编译框架之后，您将拥有构建响应式网站所需的所有类。另一方面，Bootstrap 也可以作为一个库来使用。您已经看到如何只使用按钮。

在`utilities.less`中，您可以找到以下代码：

```less
.clearfix {
  .clearfix();
}
```

上述代码使`.clearfix`类可以直接在您的 HTML 中使用；另一方面，您仍然可以重用`.clearfix()` mixin。您可以在`mixins.less`中找到 Bootstrap 的 mixin。这种严格的 mixin 和类的分离允许您导入`mixins.less`并将这些 mixin 应用到您自己的代码中，而不需要实际创建这些类的输出。

`mixins.less`文件的前面导入将允许您在自己的项目中使用 Bootstrap 的渐变 mixin，如下面的代码片段所示：

```less
@import "bootstrap/mixins.less";
header {
 #gradient > .horizontal(red; blue);
}
```

上述代码将编译为以下 CSS 代码：

```less
header {
  background-image: -webkit-linear-gradient(left, color-stop(#ff0000 0%), color-stop(#0000ff 100%));
  background-image: linear-gradient(to right, #ff0000 0%, #0000ff 100%);
  background-repeat: repeat-x;
  filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#ffff0000', endColorstr='#ff0000ff', GradientType=1);
}
```

如您所见，渐变混合是有命名空间的。还请访问`http://localhost/gradient.html`，以查看前面示例中的背景渐变的外观。

### 使用 Less 主题化 Bootstrap

由于 Bootstrap 的样式是用*Less*构建的，因此很容易为 Bootstrap 的自定义版本设置主题。基本上有两种方法可以集成您的主题的*Less*代码。

第一种方法将所有代码编译为单个 CSS 文件。在大多数情况下，推荐使用此方法，因为加载只需要一个 HTTP 请求。

要使用此方法，使用`@import`语句将您的主题文件导入到`bootstrap.less`中，并重新编译 Bootstrap。或者，创建一个新的项目文件，例如`bootstraptheme.less`，其中包括两者，如下面的代码片段所示：

```less
@import "bootstrap.less";
@import "theme.less";
```

这种方法在*Less*级别上重写了 Bootstrap 的样式，而第二种方法在 CSS 级别上执行相同的操作。在第二种方法中，主题的*Less*代码将被编译成单独的 CSS 文件，这些文件将在 Bootstrap 的 CSS 之后加载。

您的客户端编译的 HTML 将如下所示：

```less
  <link rel="stylesheet/less" type="text/css" href="less/bootstrap/bootstrap.less" />
  <link rel="stylesheet/less" type="text/css" href="less/yourtheme.less" />
  <script type="text/javascript">less = { env: 'development' };</script>
  <script src="img/less.js" type="text/javascript"></script>
```

服务器端编译后，您的 HTML 将如下所示：

```less
  <link type="text/css"  rel="stylesheet" href="css/bootstrap.min.css" />
  <link type="text/css"  rel="stylesheet" href="css/yourtheme.min.css" />
```

这种第二种方法在加载页面时需要额外的 HTTP 请求，但另一方面，它提供了从 CDN 加载 Bootstrap 核心的机会，如下所示：

```less
  <link type="text/css"  rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css" />
  <link type="text/css" rel="stylesheet" href="css/yourtheme.min.css" />
```

### Bootstrap 的 a11y 主题

**A11y**是（网络）可访问性的常用缩写。可访问性在现代网页设计中起着重要作用；然而，许多网站对此关注较少。Bootstrap 的 a11y 主题提供了更好的可访问性与 Bootstrap。

a11y 主题可以从[`github.com/bassjobsen/bootstrap-a11y-theme`](https://github.com/bassjobsen/bootstrap-a11y-theme)下载。您只需编译*Less*文件即可使用该主题。此外，在这种情况下，您可以选择将*Less*代码集成到您的*Less*代码库中，或者编译一个单独的主题 CSS 文件。要了解有关 Bootstrap 的更多无障碍改进，请访问[`github.com/paypal/bootstrap-accessibility-plugin/`](https://github.com/paypal/bootstrap-accessibility-plugin)。请注意，此插件不提供任何*Less*代码，只提供 CSS。

### 1pxdeep 的颜色方案

**1pxdeep**帮助您在项目中使用**相对视觉权重**和**颜色方案**。基于种子颜色，1pxdeep 的`scheme.less`文件生成一个包含 16 种颜色的调色板。每种颜色也以变量的形式定义。这些变量，如`@color1`或`@color4c`，可用于自定义设计。每个颜色变量还定义了一个同名的类，因此您的*Less*代码中的`@color1`和 HTML 中的`.color1`指的是您颜色方案中的同一种颜色。

在项目中实现 1pxdeep 后，更改品牌或颜色方案将像更改种子颜色一样简单。

使用 1pxdeep 和 Bootstrap 的典型`Less`项目文件将如下代码片段所示：

```less
@import "scheme.less"; // color scheme
@import "bootstrap.less"; // bootstrap
@import "1pxdeep.less"; // 1pxdeep theme
@import "style.less"; // your own styles
```

前面的代码重新声明了 Bootstrap 的变量，例如`@brand-primary: hsl(hue(#428bca),@sat,@l-factor);`，并使您能够在`style.less`文件中使用 1pxdeep 的变量，如下面的代码片段所示：

```less
header {
    background-color: @color3;
    h1 {
    color: @color3a;
    }
}
```

1pxdeep 的 CSS 类也可以直接在您的 HTML 代码中使用，如下所示：

```less
<button class="btn btn-default color1">Color 1</button>
```

在 1pxdeep 的网站上，您可以测试不同的种子颜色，以了解它们的外观。请访问[`rriepe.github.io/1pxdeep/`](http://rriepe.github.io/1pxdeep)并感到惊讶。

## 使用 Bootstrap 的自定义工具构建您自己的版本

想要从头开始使用定制版本的 Bootstrap 的人也可以使用 Bootstrap 的自定义工具。您可以通过访问[`getbootstrap.com/customize/`](http://getbootstrap.com/customize/)找到自定义工具。自定义工具允许您选择使用哪些*Less*文件。还可以设置所有 Bootstrap 的*Less*变量。该列表也可以用作在编译自己的版本时 Bootstrap 变量的参考。请注意，使用自定义工具时可以下载的文件不包含任何*Less*文件，因此 Bootstrap 自定义工具中的文件不适合进一步使用*Less*进行定制。

# Semantic UI - 另一个 Less 框架

Semantic 也可以用于构建前端。就像 Bootstrap 一样，它包含 CSS 组件和模块。组件已分为元素、集合和视图。模块不仅需要 CSS，还需要 JavaScript。

Semantic 的名称已经清楚地表明它关注 HTML5 的语义。它还是标签不可知的，这意味着您可以在 UI 元素中使用任何 HTML 标签。

在以下代码中，您将找到一个简短的 HTML 示例，展示了 Semantic 的预期用法：

```less
<main class="ui three column grid">
  <aside class="column">1</aside>
  <section class="column">2</section>
  <section class="column">3</section>
</main>
```

此外，Semantic 也是使用*Less*构建的。完整的源代码，包括*Less*文件，可以从[`github.com/semantic-org/semantic-ui/`](https://github.com/semantic-org/semantic-ui/)下载。

Semantic 处理*Less*的方式与 Bootstrap 和本书中早期看到的大多数示例不同。与之相反，Semantic 源代码也将使用 Grunt 构建，就像前面的 Bootstrap 部分描述的那样。然而，Semantic 不定义变量，也不定义导入和连接不同*Less*文件的主文件。Semantic 的*Less*代码分为不同的模块，其中大多数设置都是硬编码的。

Semantic 处理*Less*的不同方式也意味着，当您的项目完全使用框架时，您将始终需要在更改或扩展*Less*代码后运行完整的 Grunt 任务。另一方面，在您的项目中使用单个 Semantic 组件或模块将非常容易。这些组件和模块不依赖于彼此或全局变量。

请访问示例文件中的`http://localhost/semanticui.html`以查看其工作原理。您会发现，您可以只包含*Less*文件来使用网格或按钮。还要注意，如果您的按钮使用图标（Semantic 包含由 Dave Gandy 设计的 Font Awesome 的完整端口作为其标准图标集），您还应该包含`icon.less`文件。

## 自动添加供应商特定规则的前缀

在使用 Grunt 构建 Semantic 时，任务首先将*Less*文件编译为单个 CSS 文件。在此任务之后，下一个任务运行`grunt-autoprefixer`。`grunt-autoprefixer`插件使用**Can I Use...**数据库（[`caniuse.com/`](http://caniuse.com/)）解析*Less*或 CSS，并添加带有供应商前缀的 CSS 属性。`/build`目录中的*Less*文件也以这种方式添加前缀。您可以通过访问[`github.com/nDmitry/grunt-autoprefixer`](https://github.com/nDmitry/grunt-autoprefixer)了解有关`grunt-autoprefixer`的更多信息。最终任务将捆绑 CSS 和 JavaScript 文件到单个文件中并对其进行缩小。

自动添加前缀对于您未来的项目将非常有趣，因为它使您可以仅使用单行声明编写您的*Less*代码。查看 Semantic 的`Grunt.js`以了解其工作原理。目前，运行任务和自动添加前缀不在本书的范围内。请注意，如果您在项目中使用 Semantic 的单个*Less*文件，您将需要使用`/build`目录中的文件，而不是`/source`目录中的文件。`/build`目录中的*Less*文件已添加前缀，而`/source`目录中的文件没有。

# 使用 Less 构建网格的其他框架

在前面的部分中，您学习了如何使用 Bootstrap 和 Semantic UI 构建完整的前端。在实践中，对于许多项目，只需一个网格就足够了。您已经看到，语义的网格可以轻松编译为单个组件。同样，Bootstrap 的网格也可以使用以下代码片段编译为单个组件：

```less
// Core variables and mixins
@import "variables.less";
@import "mixins.less";
// Reset
@import "normalize.less";
@import "grid.less";
```

或者，您也可以使用另一个网格系统。其中一些在以下部分中简要讨论。

## 使用黄金网格系统构建您的网格

**黄金网格系统**（**GGS**）将屏幕分成 18 个均匀的列。最左边和最右边的列用作网格的外边距；这为您的设计留下了 16 列。有关此网格系统的更多详细信息可以在[`goldengridsystem.com/`](http://goldengridsystem.com/)找到。

GGS 带有一个*Less*文件，用于编译所需的 CSS 以构建网格。

### 注意

**Frameless**网格系统逐列适应，而不是像素逐像素。

由构建 GGS 的同一作者构建的 Frameless 网格系统不是流体的；当达到断点时，网格会添加列。请注意，Bootstrap 的网格工作方式相同。Frameless 带有一个*Less*模板，可以编译以使用网格。此模板包含一个小的 CSS 重置，一些一致性修复，以及一些用于启动 Frameless 网格的基本可自定义变量和函数。有关 Frameless 网格的更多信息可以在[`framelessgrid.com/`](http://framelessgrid.com/)找到。Frameless 的文档很少；但是，您可以在 GitHub 上找到 Frameless 主页的源代码。这将让您了解如何使用它与*Less*。

## 语义网格系统

**语义网格系统**非常基础和有效。设置列和间距宽度后，选择列数并在像素和百分比之间切换；您将在标记中没有任何`.grid_x`类的布局。语义网格系统也是响应式的。它还支持嵌套和推拉，这使您可以对列应用左右缩进。

使用*Less*定义流体布局将像在以下代码片段中所示一样简单：

```less
@import 'grid.less';
@columns: 12;
@column-width: 60;
@gutter-width: 20;

@total-width: 100%; // Switch from pixels to percentages
article {
   .column(9);
}
section {
   .column(3);
}
```

关于语义网格系统的更多信息可以在[`semantic.gs/`](http://semantic.gs/)找到。

# WordPress 和 Less

如今，WordPress 不仅用于博客；它也可以用作内容管理系统来构建网站。

用 PHP 编写的 WordPress 系统已分为核心系统、插件和主题。插件为系统添加了额外的功能，主题处理了使用 WordPress 构建的网站的外观和感觉。插件彼此独立工作。插件也独立于主题，主题大多也不依赖插件。WordPress 主题为网站定义全局 CSS，但每个插件也可以添加自己的 CSS 代码。

WordPress 主题开发人员可以使用*Less*来编译主题和插件的 CSS。

## 使用 Less 的 Roots 主题

**Roots**是一个 WordPress 起始主题。您可以使用 Roots 来构建自己的主题。Roots 基于 HTML5 Boilerplate ([`html5boilerplate.com/`](http://html5boilerplate.com/))和 Bootstrap。还请访问 Roots 主题网站[`roots.io/`](http://roots.io/)。此外，Roots 也可以完全使用 Grunt 构建。有关如何在 WordPress 开发中使用 Grunt 的更多信息，请访问[`roots.io/using-grunt-for-wordpress-theme-development/`](http://roots.io/using-grunt-for-wordpress-theme-development/)。

下载 Roots 后，*Less*文件可以在`assets/less/`目录中找到。这些文件包括 Bootstrap 的*Less*文件，如前所述。`assets/less/app.less`文件导入了主要的 Bootstrap *Less*文件，`bootstrap.less`。

现在，您可以编辑`app.less`来自定义您的主题。更改后，您将需要重新构建 Roots。

Roots 的文档描述了编辑 Bootstrap 的`variables.less`文件作为定制使用 Roots 构建的网站的最简单方法。更多信息请访问[`roots.io/modifying-bootstrap-in-roots/`](http://roots.io/modifying-bootstrap-in-roots/)。

## JBST 内置 Less 编译器

JBST 也是一个 WordPress 入门主题。JBST 旨在与所谓的子主题一起使用。有关 WordPress 子主题的更多信息，请访问[`codex.wordpress.org/Child_Themes`](https://codex.wordpress.org/Child_Themes)。

安装 JBST 后，您将在**仪表板**的**外观**下找到一个*Less*编译器，如下截图所示：

![JBST 内置 Less 编译器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_06.jpg)

JBST 在 WordPress 仪表板中内置的 Less 编译器

内置的*Less*编译器可用于完全定制您的网站与*Less*。Bootstrap 也构成了 JBST 的骨架，并且默认设置是从前面提到的 a11y bootstrap 主题中收集的。

JBST 的*Less*编译器可以以不同的方式使用。

首先，编译器接受任何自定义编写的*Less*（和 CSS）代码。例如，要更改`h1`元素的颜色，只需编辑并重新编译代码如下：

```less
h1 {color: red;}
```

其次，您可以编辑 Bootstrap 的变量并（重新）使用 Bootstrap 的混合器。因此，要设置导航栏的背景颜色并添加自定义按钮，可以在*Less*编译器中使用以下代码：

```less
@navbar-default-bg:              blue;
.btn-colored {
  .button-variant(blue;red;green);
}
```

第三，您可以设置 JBST 内置的*Less*变量，例如：

```less
@footer_bg_color: black;
```

第四，JBST 有自己的一套混合器。要设置自定义字体，可以编辑如下：

```less
.include-custom-font(@family: arial,@font-path, @path: @custom-font-dir, @weight: normal, @style: normal);
```

在上述代码中，参数用于设置字体名称（`@family`）和字体文件的路径（`@path/@font-path`）。`@weight`和`@style`参数设置了字体的属性。更多信息，请访问[`github.com/bassjobsen/Boilerplate-JBST-Child-Theme`](https://github.com/bassjobsen/Boilerplate-JBST-Child-Theme)。

还可以在特殊文件（`wpless2css/wpless2css.less`或`less/custom.less`）中添加更多*Less*代码；这些文件还可以让您选择添加预构建的混合库，例如第四章中讨论的那些，*避免重复造轮子*。通过这个文件添加库后，混合器也可以与内置编译器一起使用。

## Semantic UI WordPress 主题

如前所述，Semantic UI 提供了自己的 WordPress 插件。该插件可以在 GitHub 上找到[`github.com/ProjectCleverWeb/Semantic-UI-WordPress`](https://github.com/ProjectCleverWeb/Semantic-UI-WordPress)。安装并激活此主题后，您可以直接使用 Semantic UI 进行网站。使用默认设置，您的网站将如下截图所示：

![Semantic UI WordPress 主题](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/less-webdev-ess/img/1465OS_06_07.jpg)

使用 Semantic UI WordPress 主题构建的网站

## WordPress 插件和 Less

如前所述，WordPress 插件有自己的 CSS。此 CSS 将作为普通样式表添加到页面中，如下所示：

```less
<link rel='stylesheet' id='plugin-name'  href='//domain/wp-content/plugin-name/plugin-name.css?ver=2.1.2' type='text/css' media='all' />
```

除非插件为其 CSS 提供*Less*文件，否则将很难使用*Less*管理其样式。

### 带有 Less 的 WooCommerce 主题

**WooCommerce**是 WordPress 的一款热门电子商务插件。使用 WooCommerce，您可以很快地建立一个网店。您可以使用*Less*为 WooCommerce 网店设置主题，文档在[`docs.woothemes.com/document/css-structure/`](http://docs.woothemes.com/document/css-structure/)中有记录。

WooCommerce 的*Less*文件应该编译成 CSS 并按照前面描述的方式使用。要为所有样式表创建单个 CSS 文件，您可以考虑将`woocommerce.less`导入到项目的主*Less*文件中，并在主题的`functions.php`文件中使用`define('WOOCOMMERCE_USE_CSS', false);`禁用默认样式。

### WP Less to CSS 插件

**WP Less to CSS**插件可以在[`wordpress.org/plugins/wp-less-to-css/`](http://wordpress.org/plugins/wp-less-to-css/)找到，它可以让您使用*Less*为 WordPress 网站设置样式。如前所述，您可以使用 JBST 的内置编译器输入*Less*代码。此代码将被编译成网站的 CSS。此插件使用 PHP Less 编译器`Less.php`编译*Less*。

# 用于编译 Less 代码的替代编译器

随着*Less*的日益流行，*Less*编译器也被移植到其他语言。这些移植可以用于使用本地语言调用编译*Less*。请记住，这些移植通常会滞后于官方 JavaScript 实现，因此您可能会发现它们缺少最近的*Less*功能。您可能也会意识到，正如第三章中早些时候提到的，*嵌套规则、操作和内置函数*，这些编译器无法编译反引号内的本机 JavaScript 表达式。

## Less.php 编译器

官方*Less*处理器的这个 PHP 移植版本可以在[`lessphp.gpeasy.com/`](http://lessphp.gpeasy.com/)下载。您已经看到了它的用法示例；WP Less to CSS 插件就是用它构建的。`Less.php`还实现了缓存以加快编译速度。

尽管`Less.php`提供了动态创建 CSS 的可能性，但在大多数情况下，您仍应该为生产环境预编译您的 CSS。WordPress 也是用 PHP 编写的，因此在 WordPress 插件的情况下，可以使用*Less*进行编译，而无需使用系统调用。

在下面的代码中，您将找到一个简短的示例，它将向您展示如何在 PHP 编写的网站上编译、自定义和使用 Bootstrap：

```less
<?php
require 'less.php/Cache.php';
Less_Cache::$cache_dir = '/var/www/mysite/writable_folder';
$files = array();
$files['/var/www/mysite/bootstrap/bootstrap.less'] = '/mysite/bootstrap/';
$files['/var/www/mysite/custom/my.less'] = '/mysite/custom/';
$css_file_name = Less_Cache::Get( $files );
echo '<link rel="stylesheet" type="text/css" href="/mysite/writable_folder/'.$css_file_name.'">';
```

[`leafo.net/lessphp/`](http://leafo.net/lessphp/)提供的**lessphp**编译器是另一种 PHP Less 编译器。

## .NET 应用程序的.less 编译器

`.less`编译器是 JavaScript *Less*库在**.NET 平台**上的完整移植。如果您想要静态编译您的文件，可以使用附带的`dotless.Compiler.exe`编译器。您可以通过向`Web.Config`文件添加新的 HTTP 处理程序来使用`.less`来制作您的网页，如下所示：

```less
<add type="dotless.Core.LessCssHttpHandler,dotless.Core" validate="false" path="*.Less" verb="*" />
```

## 开发 Less 的工具列表

在*Less*网站([`lesscss.org/usage/`](http://lesscss.org/usage/))上，您将找到许多其他库、工具和框架来开发*Less*。

# 总结

在本章中，您学会了如何在 Bootstrap 和 Semantic UI 中使用*Less*，还介绍了其他使用*Less*构建的网格和框架。您已经了解了如何在 WordPress 中使用*Less*，最后，您了解了如何为项目使用替代编译器。

这也是本书的最后一章。在本书中，您学会了如何在项目中使用*Less*。您看到了变量、混合和内置函数如何帮助您重用代码。使用*Less*，您可以嵌套您的样式规则，这使得您的代码更直观和可读。阅读本书后，您知道自己不必亲自编写所有代码，而是可以使用他人编写的预构建混合。最后，您学会了如何从头开始使用*Less*启动项目，并将*Less*与 WordPress、Bootstrap 和其他工具集成。现在，您真的准备好开始开发*Less*了。恭喜！您已经使自己能够更好、更快地使用*Less*来开发项目，并为真正的设计任务节省更多时间。
