# jQueryUI 1.10：jQuery 的用户界面库（一）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

现代 Web 应用程序用户界面设计需要快速开发和经过验证的结果。jQuery UI 是 jQuery JavaScript 库的官方插件套件，为您提供了一个坚实的平台，您可以在此平台上最大程度地兼容性、稳定性和最少时间和精力的情况下构建丰富而引人入胜的界面。

jQuery UI 拥有一系列现成的、外观精美的用户界面小部件和一套全面的核心交互助手，设计成以一种一致且开发者友好的方式进行实现。有了所有这些，您需要亲自编写的代码量从构思到完成项目的过程中都大大减少了。

特别为 jQuery UI 版本 1.10 重新修订，本书旨在通过分解每个组件并引导您逐步构建知识的示例，最大限度地提高您对库的体验，从而使您从初学者到高级用户的使用经验变得更加简单易行。

在本书中，您将学习如何初始化每个组件的基本默认实现，然后看到如何轻松地定制其外观并配置其行为以使其适应应用程序的要求。您将查看每个组件 API 提供的配置选项和方法，以了解如何使用它们发挥库的最佳功能。

事件在任何现代 Web 应用中都扮演着关键角色，如果要满足预期的最低交互和响应要求的话。每一章都会展示组件触发的自定义事件以及这些事件如何被拦截和处理。

# 本书涵盖的内容

第一章，*介绍 jQuery UI*，让您了解库的确切内容、从哪里下载以及其中的文件结构。我们还将研究 ThemeRoller，哪些浏览器支持该库，它的许可证情况以及如何简化 API 以使组件具有一致且易于使用的编程模型。

第二章，*CSS 框架和其他实用程序*，详细介绍了广泛的 CSS 框架，该框架通过 Themeroller 提供了丰富的集成主题环境，并允许开发人员轻松提供自己的自定义主题或皮肤。我们还涵盖了新的位置实用程序，并查看了它提供的所有独特功能和一系列配置选项。

第三章，*使用选项卡小部件*，介绍了第一个小部件，即选项卡小部件，这是一种简单但有效的呈现结构化内容的交互式小部件。

第四章, *手风琴组件*，着眼于手风琴组件，另一个用于有效展示内容的组件。交互性强，吸引人，手风琴为任何网页增添了不少价值，其 API 完全开放，可以准确展示它的使用方法。

第五章, *对话框*，专注于对话框组件。对话框的行为方式与标准的浏览器警报相同，但它以一种更不具侵入性和更友好访问者的方式来完成。我们将看看如何对其进行配置和控制以提供最大的益处和吸引力。

第六章, *滑块和进度条组件*，提供了一个不太常用但同样有价值的用户界面工具，用于收集访问者的输入，并向他们展示操作的结果。本章将仔细查看这两个组件的 API，看看它们可以实现的各种方式，并在我们的网络应用中充分利用。

第七章, *日期选择器组件*，着眼于日期选择器。该组件将大量功能打包成一个引人入胜且高度可用的工具，让您的访问者轻松选择日期。我们将看到其 API 可能实现的广泛配置范围，以及看到像换肤和本地化这样常见任务是如何容易实现的。

第八章, *按钮和自动完成组件*，着眼于全新的按钮和最近重新启用的自动完成。长期使用该库的用户将会记得以前版本的库中的自动完成。该组件现在已经全新回归，根据库的最新版本进行了完全更新，本章中我们将看到它如何能够产生巨大的效果。

第九章, *创建菜单*，将向我们展示如何在我们的网站或应用程序中创建并添加菜单。我们将看到，通过最少的代码，我们可以将一堆普通的超链接转变为一个交互式的系统，用于在您的网站中进行导航，这将有助于吸引您网站的访问者，并且轻松找到内容。

第十章, *工作中的工具提示*，将向我们展示如何通过最小的努力，轻松提供基于上下文的支持系统，向最终用户显示重要的消息或反馈。在访问者在您的网站上可能无意中输入不正确信息的情况下，这一点尤为重要；我们可以帮助他们重新回到正确的方向！

第十一章, *拖放*，开始研究低级交互助手，首先解决相关的拖放组件。我们将看看它们如何分别实现以及如何一起使用来增强您的用户界面。

第十二章, *可调整大小组件*，介绍了调整大小组件以及如何与本书中早期看到的对话框小部件一起使用。我们将看到如何将其应用于页面上的任何元素，以便以平滑和吸引人的方式调整其大小。

第十三章, *使用 jQuery UI 进行选择和排序*，着眼于本章的最后两个交互帮助程序；可选择和可排序组件。我们可以使用这些组件在网站或应用程序中选择和排序元素，尽管在处理列表时，可排序组件确实发挥了作用，因为您可以通过拖动项目将它们重新排序到列表中的新位置。这两个组件都可以帮助您为您的站点增加高水平的专业性和交互性，同时模糊了桌面应用程序和基于浏览器的应用程序之间的界限。

第十四章, *UI 特效*，专门介绍了该库中包含的特殊效果。我们将介绍一系列不同的效果，使您能够以多种吸引人和迷人的动画展示、隐藏、移动和摆动元素。

*第十五章*，*小部件工厂*，本书可下载章节提供了对小部件工厂的全面介绍，以及它如何让我们快速轻松地创建自己的 jQuery UI 插件。小部件工厂为您解决了许多常见问题，并且可以极大地提高生产力；它还大大提高了代码重用性，使其非常适合 jQuery UI 以及许多其他有状态的插件。您可以在[`www.packtpub.com/sites/default/files/downloads/2209OS_Chapter_15.pdf`](http://www.packtpub.com/sites/default/files/downloads/2209OS_Chapter_15.pdf)找到本章。

附录, *帮助和支持*，涵盖了下载库的基础知识。它提供了“获取帮助”部分，为读者提供了他们在整本书中的所有问题的答案。 

# 您需要准备什么来阅读本书

您只需要一个简单的文本或代码编辑器和一个浏览器就可以完成本书中大多数示例的工作。一两个更高级的示例依赖于 PHP，但为了方便起见，我已将这些示例包含在本书附带的代码下载中。

# 这本书是为谁准备的

本书是为需要快速学习如何使用 jQuery UI 的前端开发人员或希望了解 jQuery UI 的功能、行为和外观的设计师准备的。要充分利用本书，您应该对 HTML、CSS 和 JavaScript 有很好的工作知识，并且最好熟练使用 jQuery。

# 惯例

在本书中，您会发现一些不同种类信息之间的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“当提示选择解压缩档案的位置时，请选择我们刚创建的`jqueryui`文件夹。”

代码块设置如下：

```js
<link rel="stylesheet"
href="development-bundle/themes/base/jquery.ui.tabs.css">
<link rel="stylesheet"
href="development-bundle/themes/base/jquery.ui.theme.css">
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项将以粗体显示：

```js
$(".ui-positioned-element").position({
 of: ".ui-positioning-element",
 my: "right bottom",
 at: "right bottom"
});
```

**新术语**和**重要单词**以粗体显示。例如，您在屏幕上看到的单词，在菜单或对话框中看到的单词，都会以如下形式出现在文本中：“当我们查看页面并选择**Images**选项卡后，稍等片刻，我们应该看到六张新图片。”

### 注意

警告或重要说明会以此框的形式出现。

### 小贴士

小贴士和技巧会以这种方式出现。


# 第一章：介绍 jQuery UI

欢迎来到*jQuery UI 1.10：* *用于 jQuery 的用户界面库*。这个资源旨在带您从您的第一步到使用 JavaScript UI 小部件和交互助手的高级用法，这些小部件和交互助手是构建在非常流行和易于使用的 jQuery 之上的。

jQuery UI 扩展了基础的 jQuery 库，提供了一套丰富和交互式的小部件以及节省代码的交互助手，旨在增强您的网站和 Web 应用程序的用户界面。jQuery Core 和 UI 都根据严格的编码约定构建，这些约定定期更新，并遵循当前的 JavaScript 设计最佳实践。作为 jQuery 的官方 UI 库，正是对当前 JavaScript 标准的严格遵守使其成为 jQuery 中最好的 UI 库之一。

在本章中，我们将涵盖以下主题:

+   如何获取库的副本

+   如何设置开发环境

+   库的结构

+   主题生成器

+   浏览器支持

+   库的许可形式

+   API 的格式

由于其不断增长的常见 UI 小部件、高度可配置性和出色的实现便利性，jQuery 迅速成为当今最流行的 JavaScript 库之一，被许多知名公司支持和使用，如 Microsoft、WordPress、Adobe 和 Intel。

jQuery UI 运行在 jQuery 之上，因此用于初始化、配置和操作不同组件的语法与 jQuery 具有相同舒适和易用的风格。由于 jQuery 构成了 UI 的基础，我们也可以利用所有出色的 jQuery 功能。该库还受到一系列非常有用的工具的支持，例如提供一系列辅助 CSS 类的 CSS 框架，以及优秀的 ThemeRoller 应用程序，该应用程序允许我们可视化地创建自己的自定义主题，或者从日益增长的预定义主题库中进行选择。我们将在本章稍后查看 ThemeRoller 应用程序。

在本书中，我们将查看构成该库的每个现有组件。我们还将查看它们的配置选项，并尝试它们的方法，以充分理解它们的工作原理和能力。在本书结束时，您将成为 jQuery UI 库中每个小部件配置和使用的专家。当我们添加新的小部件或交互助手时，由于我们实现库中不同组件的一致性，当我们创建自定义组件时，我们将已经具备了基本的工作知识。因此，我们只需要学习任何特定于小部件的功能，以掌握我们希望使用的特定组件。

# 下载该库

本书专门针对 jQuery UI 的版本 1.10，并且需要 jQuery 1.6 或更高版本；在本书中，我们将在代码示例中使用 jQuery 2.0.3。

### 注意

如果你仍然需要支持 IE6，那么可以下载遗留的 jQuery UI 库的版本 1.9.2。你还需要使用 jQuery 1.10 的副本，因为 jQuery 2.0 不支持 IE 6-8。

要获取库的副本，我们应该访问 [`www.jqueryui.com/download`](http://www.jqueryui.com/download) 上的下载构建器。该工具为我们提供了一系列不同的选项，用于构建一个符合我们特定需求的下载包。以下截图显示了 **下载构建器**：

![下载库](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_01.jpg)

我们可以下载完整的当前版本发布或遗留版本的完整包。我们还可以仅选择我们想要的组件并下载自定义包——这在生产环境中特别推荐，因为我们只使用 UI 库的子集；这有助于减少在查看页面时使用的带宽。

页面布局友好且易于使用。它列出了所有不同组件及其各自的分组（**UI 核心**、**交互**和**小部件**），并允许我们从 24 种不同的预设计主题（或不使用主题）中进行选择。页面还提供了有关包的信息（包括其压缩和未压缩大小）。

### 小贴士

如果作为开发人员想要查看 jQuery UI 在源代码控制下的最新快照，那么可以从 GitHub 下载一个副本，该副本可在 [`github.com/jquery/jquery-ui`](https://github.com/jquery/jquery-ui) 上获取。

我们稍后将查看库中找到的不同文件，但现在我们应该下载完整的库。它将包含我们需要的一切，包括 JavaScript 和 CSS 文件，以及依赖于不同组件的当前主题中的任何图像。它甚至包含了 jQuery 的最新版本，因此我们不需要担心单独下载这个。

现在，只需使用页面顶部的自定义 **下载** 链接，然后在接下来的页面上选择 **Smoothness** 作为主题，然后点击 **下载**。我们将在下一章中介绍下载和使用其他主题。

附带本书的代码下载包括每个章节练习文件夹中的 jQuery 2.03 的副本。如果你需要下载新副本，可以这样做——下载新副本的说明在 附录 *帮助与支持* 中。

## 使用托管版本的 jQuery UI

我们不需要下载库以便在生产 Web 应用程序中实现它。jQuery 和 jQuery UI 都托管在 Google、CDNJS、Microsoft 和 MediaTemple（他们为 jQuery UI 提供 CDN）提供的内容交付网络（CDN）上。

在接收大量国际流量的实时站点上，使用 CDN 将有助于确保库文件从距离访问者较近的服务器下载到他们的计算机上。这有助于加快响应速度，并节省我们自己的带宽。但这不推荐用于本地开发！

### 提示

**托管的文件**

如果你想要使用 CDN 链接，那么可以在以下位置找到：

+   谷歌的 CDN：[`code.google.com/apis/libraries/`](http://code.google.com/apis/libraries/)

+   CDNJS 的 CDN：[`cdnjs.com`](http://cdnjs.com)

+   jQuery 的 CDN：[`code.jquery.com`](http://code.jquery.com)

+   微软的 CDN：[`www.asp.net/ajaxlibrary/CDN.ashx`](http://www.asp.net/ajaxlibrary/CDN.ashx)

# 设置开发环境

我们需要一个位置来解压 jQuery UI 库，以便在我们自己的文件中轻松访问它的不同部分。我们应该首先创建一个`project`文件夹，将所有示例文件以及整个库和其他相关资源保存在其中。

在你的`C:`驱动器或你的主目录中创建一个名为`jqueryui`的新文件夹。这将是我们项目的根文件夹，也将是我们在书中制作的所有示例文件的存储位置。

### 注意

这本书附带的代码下载的结构将反映我们正在创建的本地环境。

要解压这个库，你可以使用 Windows Explorer（如果在 PC 上工作），或者像 7-zip 这样的压缩程序。当解压这个库时，请选择我们刚刚创建的`jqueryui`文件夹。如果你是 Mac 用户，你可能需要将`jqueryui-1.10.3.custom`文件夹中的内容复制到我们刚刚创建的新`jqueryui`文件夹中。（我们将在本章的后面介绍`jqueryui`文件夹的结构。）

### 注意

7-zip 是一个类似于 WinZip 或 WinRAR 的开源存档应用程序；我个人觉得它更好、更容易使用。你可以免费从[`www.7-zip.org`](http://www.7-zip.org)下载它。

我们将要查看的代码示例使用其他资源，主要是图像，但偶尔也会使用一些 PHP 文件。在*Packt Publishing*网站上提供的附带代码下载包含我们将使用的所有图像。如果可以的话，你应该从[`www.packtpub.com/support/book/user-interface-library-for-jquery`](http://www.packtpub.com/support/book/user-interface-library-for-jquery)下载这个。你需要在`jqueryui`项目文件夹内创建一个名为`img`的新文件夹，然后将存档中图像文件夹内的所有图像解压到这个新文件夹中。

一旦你解压了`jqueryui`文件夹并添加了任何所需的额外文件夹，你将看到类似于以下屏幕截图的东西——这里我以**第五章**为例，需要创建一个额外的`img`文件夹：

![建立开发环境](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_02.jpg)

代码下载还包含所有示例以及库本身。提供这些文件是希望它们仅用于参考目的。我建议你在阅读时跟随书中的示例，手动创建每个文件，而不是仅仅参考代码下载中的文件。学习编码的最佳方式就是编写代码。

这就是我们需要做的一切，不需要安装任何额外的平台或应用程序，也不需要配置或设置任何内容。只要您有一个浏览器和某种代码或文本编辑器，一切都已准备好开始使用该库进行开发。

有很多可用的编辑器，其中任何一个都可以与 jQuery UI 一起使用，如果您还没有首选的编辑器，那么对于 Windows 用户，您可以尝试 Notepad++（可以从[`www.notepad-plus-plus.org`](http://www.notepad-plus-plus.org)免费下载），或 Sublime Text 2（共享软件，可以从[`www.sublimetext.com/2`](http://www.sublimetext.com/2)下载）。我建议避免使用占用内存过多的集成开发环境，因为它们倾向于过多地促使工作，从而影响使用 jQuery UI 时的学习曲线。

### 注意

对于那些喜欢使用本地 Web 服务器进行开发的人来说，您可以使用像 WAMP（对于 PC）或 MAMP（对于 Mac）这样的东西，如果您还没有将其设置为日常工作流程的一部分。Linux 用户应该找到适合的 Web 服务器，可以从他们的发行版中找到。

# 理解库的结构

让我们花点时间来查看一下库解压后的结构，这样我们就知道在哪里查找特定的工具和文件。这将让我们对其构成和结构有所了解。打开我们解压库的地方的`jqueryui`文件夹。此文件夹的内容应该如下：

+   一个`css`文件夹

+   一个`development-bundle`文件夹

+   一个`js`文件夹

+   一个`index.html`文件

我们可以从以下截图中看到结构是什么样的：

![理解库的结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_03.jpg)

为了使用 jQuery UI，只需知道`js`和`css`文件夹就足够了；这些可以像现在这样直接放入您的站点结构中，并从您的代码中相应地引用相关的压缩文件。

如果您是以开发者身份使用该库，则我建议使用`development-bundle`文件夹；其中包含与各个源文件相同的代码，但以未压缩的格式提供。

## 详细检查文件夹结构

对于大多数人来说，了解 jQuery UI 库的构成并不必要；毕竟，可以将两个关键文件夹简单地放入您的站点中，并相应地引用它们。在这种情况下，您可能希望跳过本节，转到*使用 ThemeRoller*。

如果您的技能更加先进，并且您想更多地了解库的结构，请继续阅读。我建议您在阅读本节时下载 jQuery 的副本，以便更好地理解库的组成。

`css` 文件夹用于存储与库一起提供的完整 CSS 框架。在此文件夹中，将有一个具有我们在构建下载包时选择的主题名称的目录。其中包含一个包含所有 CSS 框架的单个文件，以及一个包含主题使用的所有图像的文件夹。我们还可以将我们将在此 `css` 目录中创建的 `css` 文件存储在其中。

`js` 文件夹包含经过缩小的 jQuery 版本和完整的 jQuery UI 库，其中所有组件都打包到一个文件中。在实际项目中，我们会将 `js` 和 `css` 文件夹放入我们的网站。

索引是一个 HTML 文件，简要介绍了库，并显示了所有小部件以及一些 CSS 类。如果这是您第一次使用该库，您可以查看此文件，以查看我们将在本书中使用的一些内容。

`development-bundle` 目录包含一系列资源，以帮助我们使用库进行开发。它包括以下子目录：

1.  一个 `demos` 文件夹

1.  一个 `docs` 文件夹

1.  一个 `external` 文件夹

1.  一个 `themes` 文件夹

1.  一个 `ui` 文件夹

以下截图显示了文件夹结构的外观：

![详细检查文件夹结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_04.jpg)

目录中还包含许可文件、JSON 源文件、显示库版本及其主要贡献者的文档，以及一个未压缩版本的 jQuery。

`demos` 文件夹包含一系列基本示例，展示所有不同组件的功能。`docs` 文件夹包含每个不同组件的 API 文档。

`external` 文件夹包含一组对开发人员可能有用的工具。它们如下：

+   `globalize` 插件

+   `jshint` 插件

+   `mousewheel` 插件

+   单元测试套件 `qunit`（包括一个 JavaScript 文件和一个 CSS 文件）

`globalize` 插件为 jQuery 提供本地化支持，并可用于在超过 350 种文化中格式化字符串、日期和数字。`jshint` 插件是 `jslint` 插件的一个衍生工具，用于检测 JavaScript 代码中的错误和潜在问题，并强制执行您自己的编码约定。由 Brandon Aaron 设计的 `mousewheel` 插件为您的网站或在线应用程序添加了跨浏览器鼠标滚轮支持。QUnit 框架是 jQuery 的单元测试套件，我们可以使用它来运行我们创建的任何代码的单元测试。

### 提示

要获取有关 QUnit 的更多信息，请访问 [`docs.jquery.com/QUnit`](http://docs.jquery.com/QUnit)。

`themes`文件夹包含默认主题或在下载构建器过程中选择的主题。稍后下载或创建的其他主题也可以存储在这里。

`ui`文件夹包含库的各个组件的单独未压缩源文件。

### 注意

如果您从主页选择**稳定**下载选项，您会发现内容呈现不同——**稳定**下载选项只包含`development-bundle`文件夹的内容，并且默认包含的主题称为**Base**。这在视觉上类似于我们在自定义包中下载的**Smoothness**主题。

# 使用 ThemeRoller

ThemeRoller 是一个使用 jQuery 和 PHP 编写的自定义工具。它允许我们直观地生成自己的 jQuery UI 主题，并将其打包成一个方便下载的存档文件，然后我们可以将其直接放入我们的项目中，无需进行进一步的编码（当然，除了在 HTML `<link>`元素中使用样式表之外）。

[`ui.jquery.com/themeroller`](http://ui.jquery.com/themeroller)上托管的 ThemeRoller 是由 Filament Group, Inc.创建的，并使用了一些发布到开源社区的 jQuery 插件。它可用于为 jQuery UI 1.10 或 jQuery UI 1.9 的传统版本生成主题。

### 提示

**托管主题**

如果我们使用主站点提供的主题之一，甚至不需要下载主题。在生产环境中，您可能更喜欢使用 CDN 版本的主题，就像您可能使用 CDN 链接来引用主库一样。

您可以使用以下链接导入基本或光滑主题：[`code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css`](http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css)。如果您想使用其他主题之一，请将 URL 中的`光滑`替换为您喜欢的主题。

ThemeRoller 肯定是创建自己的 jQuery UI 主题的最全面的工具。我们可以非常快速和轻松地创建一个包含所有所需的样式的完整主题，以便针对组成库的不同小部件进行定位，包括我们将需要的图像。

![使用 ThemeRoller](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_05.jpg)

如果您之前看过`index.html`文件，那么 ThemeRoller 首发页面将会让您立即感到熟悉，因为它显示了页面上所有 UI 小部件，并使用默认的**Smoothness**主题进行美化。

ThemeRoller 页面左侧有一个交互式菜单，用于操作该应用程序。菜单中的每个项目都会展开，让您访问每个部件的可用样式设置，如小部件的**内容**和**可点击**区域，小部件的**标题**和**内容**区域以及其他相关内容，如警告和**错误**消息。

在这里，我们可以轻松创建自定义主题，并且可以在应用于页面上每个小部件的不同可见部分时立即看到更改，如下图所示：

![使用 ThemeRoller](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_01_06.jpg)

如果在创建主题时感觉不太灵感，还有一个预配置主题的画廊，您可以立即使用它来生成一个完全配置的主题。除了方便之外，这些预选主题最好的一点是，当您选择其中一个时，它会加载到左侧菜单中。因此，您可以根据需要轻松进行小调整。

这是创建与现有站点样式匹配的视觉上吸引人的自定义主题的绝佳方法，也是创建自定义皮肤的推荐方法。

安装和使用新主题就像选择或创建它一样简单。上面截图中的 **下载主题** 按钮将我们带回下载生成器，该生成器将新主题的 CSS 和图像集成到下载包中。

如果我们只想要新主题，我们可以取消选择实际组件，只下载主题。下载后，在下载的存档中的 `css` 文件夹中将包含一个以主题名称命名的文件夹。我们只需将此文件夹拖放到我们自己的本地 `css` 文件夹中，然后从我们的页面链接到样式表。

在本书中我们不会详细介绍这个工具。我们将重点放在需要在我们自己的定制样式表中手动覆盖的样式规则上，以手动生成所需的示例外观。

# 将组件类别分类

jQuery UI 库中有三种类型的组件，如下所示：

+   **低级交互助手**：这些组件主要设计用于鼠标事件

+   **小部件**：这些组件在页面上产生可见对象

+   **核心组件**：这些组件是库的其他部分所依赖的组件

让我们花点时间考虑构成每个类别的组件，从核心组件开始。

核心组件包括：

+   核心

+   小部件

+   鼠标

+   定位

核心文件建立了所有组件使用的构造，并添加了一些所有库组件共享的核心功能，例如键盘映射、父级滚动和 z-index 管理器。这个文件不是设计用于独立使用的，并且不暴露任何可以在另一个组件之外使用的功能。

交互助手包括以下组件：

+   可拖动的

+   可放置的

+   可调整大小

+   可选择的

+   可排序

交互助手向任何元素添加基本的基于鼠标的行为；这使您可以创建可排序的列表，在飞行中调整元素的大小（例如对话框）或甚至构建功能（例如基于拖放的购物车）。

较高级别的小部件（在撰写时）包括：

+   折叠菜单

+   自动完成

+   按钮

+   日期选择器

+   对话框

+   菜单

+   进度条

+   滑块

+   标签页

+   菜单

+   工具提示

小部件是将桌面应用程序功能的丰富性带入 Web 的 UI 控件。每个小部件都可以完全自定义，外观和行为。

## 介绍小部件工厂和效果

当使用 jQuery UI 的小部件时，你会遇到小部件工厂。它实际上创建了库公开的所有可见小部件的基础。它实现了所有小部件共享的 API，例如 `create` 和 `destroy` 方法，并提供了事件回调逻辑。它还允许我们创建继承共享 API 的自定义 jQuery UI 小部件。我们将在本章后面详细介绍小部件工厂。

除了这些组件和交互式助手之外，还有一系列 UI 效果，可以在页面上的目标元素上产生不同的动画或过渡效果。这些效果非常适合为我们的页面添加风采和风格。我们将在本书的最后一章中查看这些效果，*UI Effects*。

jQuery UI 简化的 API 的好处在于，一旦你学会了使用所有现有的组件（就像这本书会向你展示的那样），你将能够非常快速地掌握任何新组件。未来版本中还计划添加许多新组件，包括将 jQuery Mobile 合并到库中！

# 浏览器支持

与 jQuery 本身一样，这个版本的 jQuery UI 官方支持当前和上一个版本的浏览器，尽管该库可以在旧版本的主要浏览器上正常工作，包括以下浏览器：IE7+、Firefox 2+、Opera 9+、Safari 3+ 和 Chrome 1+。

### 提示

**对 IE6 和 IE7 的支持**

如前所述，jQuery UI 团队在 UI 1.10 中停止了对 IE6 的支持；尽管如此，你仍然可以通过下载遗留的版本 1.9.2 使用 jQuery UI。IE7 的用户可能会注意到，计划也将放弃对该浏览器的支持；在撰写本文时，这一计划目前计划在版本 1.11 中实现，尽管这尚未确认。

小部件是从语义上正确的 HTML 元素中构建的，根据需要由组件生成。因此，我们不会看到创建或使用过多或不必要的元素。

# 使用本书示例

这个库和标准 JavaScript 一样灵活。我的意思是，通常有多种方法来做同样的事情，或者达到同样的目的。例如，用于不同组件的配置对象中的回调事件通常可以接受函数引用或内联匿名函数，并且可以同样轻松高效地使用它们。

在实践中，建议尽可能保持代码的最小化（无论如何，jQuery 都可以帮助实现这一点）。但为了使示例更易读和理解，我们将尽可能将代码分离为独立的模块。因此，回调函数和配置选项将与调用或使用它们的代码分开定义。

在本书中，我们将把 JavaScript 和 CSS 代码分开存储到不同的文件中；虽然这对开发工作来说有些过分，但对于生产网站来说是可取的。存在外部`js`文件中的脚本可被浏览器缓存，从而大大提高加载速度；而直接写在`<script>`标签中的内联脚本则不能被浏览器缓存。

我还想澄清一点，即本书的整个过程的主要目的是学习如何使用组成 jQuery UI 的不同组件。如果某个示例看起来有点复杂，可能是因为这是暴露特定方法或属性功能的最简单方法，而不是我们编码常规实现所会遇到的情况。

我想在这里补充一下，jQuery UI 库目前正在经历快速扩展、bug 修复和开发阶段。对于这个版本，jQuery 团队正在专注于 bug 修复，以帮助使库尽可能稳定。从长远来看，jQuery UI 团队正在专注于重新设计每个小部件的 API，并计划在未来的版本中添加大量新的小部件，并完成与 jQuery Mobile 已计划的合并。

# 库许可

与 jQuery 一样，jQuery UI 库也是根据 MIT 开源许可发布的。这是一个非常不限制的许可，允许创建者对其制作进行归属，并保留其知识产权，同时不妨碍我们开发者以任何方式在任何类型的网站上使用该库。

MIT 许可明确规定了软件使用者（在本例中是 jQuery UI）可以自由使用、复制、合并、修改、发布、分发、许可和出售。这让我们可以几乎为所欲为地使用库。这个许可所施加的唯一要求是我们必须保持原始的版权和保修声明完整。

这一点很重要。您可以随意使用库。您可以在库的基础上构建应用程序，然后销售这些应用程序或免费提供。您可以将库放入嵌入式系统，例如手机操作系统，并出售它们。但无论做什么，都要保留带有 John Resig 名字的原始文本文件。您还可以在应用程序的帮助文件或文档中逐字复制它。

MIT 许可非常宽松，但因为它本身没有版权，我们可以自由改变它。因此，我们可以要求软件使用者向我们归功，而不是 jQuery 团队，或将代码冒充为我们自己的。

许可证并不限制我们的任何方式，并且与您可能购买并安装在您自己计算机上的软件附带的许可证不同。在大多数情况下，库的许可将不会成为使用它时的考虑因素。但是，插件作者将希望确保其插件以类似的许可发布。

# API 介绍

一旦您使用了库中的任何一个组件，您在使用其他任何组件时会立即感到自如，因为每个组件的方法都以完全相同的方式调用。

每个组件的 API 由一系列不同的方法组成。尽管这些在技术上都是方法，但根据它们的特定功能对它们进行分类可能是有用的。

| 方法类型 | 描述 |
| --- | --- |
| 插件方法 | 此方法用于初始化组件，只是组件名称，后跟括号。我将在本书中始终将其称为插件方法或小部件方法。 |
| 共享 API 方法 | `destroy` 方法可用于任何组件，以完全禁用正在使用的小部件，并且在大多数情况下将底层 HTML 返回到其原始状态。`option` 方法由所有组件使用，用于在初始化后获取或设置任何配置选项。`enable` 和 `disable` 方法由大多数库组件使用，用于启用或禁用组件。所有小部件都公开的 `widget` 方法返回对当前小部件的引用。 |
| 专用方法 | 每个组件都有一个或多个特定于该特定组件的方法，执行特定的功能。 |

方法通过将我们想要调用的方法作为简单字符串传递给组件的 `plugin` 方法，在每个不同的组件中始终一致地调用，该方法接受方法接受的任何参数作为方法名称之后的字符串。

例如，要调用手风琴组件的 `destroy` 方法，我们只需使用以下代码：

```js
$("#someElement").accordion("destroy");
```

看，多么简单！所有不同组件公开的每个方法都以相同简单的方式调用。

一些方法，如标准 JavaScript 函数，接受触发组件不同行为的参数。例如，如果我们想在标签部件中调用 `disable` 方法，则会使用以下代码：

```js
$("#someElement").tabs("disable", 1);
```

`disable` 方法与标签部件一起使用时，接受一个整数，该整数指的是小部件内单个标签的索引。同样，要再次启用该标签，我们将使用以下代码中显示的 `enable` 方法：

```js
$("#someElement").tabs("enable", 1);
```

再次，我们提供了一个参数来修改方法的使用方式。有时，传递给方法的参数在组件之间会有所不同。例如，手风琴部件不会启用或禁用单个手风琴面板，只会启用或禁用整个部件，因此在方法名称之后不需要其他参数。

`option` 方法略微比其他常见方法复杂，但它也更强大，并且使用起来同样简单。该方法用于在组件初始化后获取或设置任何可配置选项。

要在 `getter` 模式中使用 option 方法检索选项的当前值，我们可以使用以下代码：

```js
$("#someElement").accordion("option", "navigation");
```

前面的代码会返回折叠小部件的 `navigation` 选项的当前值。因此，要触发 `getter` 模式，我们只需提供要检索的选项名称。

要改用 `setter` 模式中的 `option` 方法，我们可以提供选项名称和新值作为参数：

```js
$("#someElement").accordion("option", "navigation", true);
```

前面的代码会将 `navigation` 选项的值设置为 `true`。请注意，也可以通过传递对象字面量来一次性设置多个不同的选项给 `option` 方法。例如：

```js
$("#someElement").accordion("option", {
  animate: "bounceslide",
  heightStyle: "fill"
});
```

如您所见，尽管 `option` 方法为我们提供了使用 `get` 和 `set` 配置选项的功能，但其仍保留了其他方法相同易于使用的格式。

## 事件和回调函数

每个组件的 API 还包含丰富的事件模型，允许我们轻松地对不同的交互做出反应。每个组件都公开其自己一组独特的自定义事件，但无论使用哪个事件，其使用方式都相同。

在 jQuery UI 中，我们有两种处理事件的方式。每个组件都允许我们添加在指定事件触发时执行的回调函数，作为配置选项的值。例如，要使用选项卡小部件的 `select` 事件，该事件在每次选择选项卡时触发，我们可以使用以下代码：

```js
var options = {
  select: function() {
  ...
  }
};
$("#myTabs").tabs(options);
```

事件的名称用作 `option` 名称，匿名函数用作 `option` 值。我们将在后面的章节中查看与每个组件一起使用的所有单独事件。

通过使用 jQuery 的 `on()` 方法，另一种处理事件的方式是。要以这种方式使用事件，我们只需指定组件的名称，然后是事件的名称：

```js
$("#someElement").on("tabsselect", function() {
...
});
```

通常，但并非总是，使用 `on()` 方法与回调函数一起使用的回调函数在事件触发后执行，而使用配置选项指定的回调函数在事件触发前直接执行。回调函数在触发事件的 DOM 元素的上下文中调用。例如，在具有多个选项卡的选项卡小部件中，`select` 事件将由实际选择的选项卡触发，而不是整个选项卡小部件。这对我们非常有用，因为它允许我们将事件与特定选项卡关联起来。

一些由 jQuery UI 组件触发的自定义事件是可取消的，如果停止，则可用于阻止某些操作。其中最好的例子（我们将在本书后面介绍）是通过在 `beforeClose` 事件的回调函数中返回 `false` 来阻止对话框小部件关闭：

```js
beforeClose: function() {
  if (readyToClose === false) {
    event.preventDefault();
}
```

如果在此示例中不满足任意条件，则回调函数将返回 `false`，并且对话框将保持打开状态。这是一个非常出色且强大的功能，可以让我们对每个小部件的行为进行精细控制。

## 回调函数参数

使用任何小部件的一个重要特性是其接受回调的能力。我们可以使用回调来运行执行特定任务的匿名函数。例如，我们可以在单击手风琴小部件中的特定标题时每次在屏幕上触发一个警报。

我们向不同事件提供作为回调函数的匿名函数时，这些匿名函数会自动传递两个参数：原始的、扩展的或修改后的事件对象，以及包含有关小部件的有用信息的对象。第二个对象中包含的信息在各组件之间有所不同。举个例子，让我们看看在使用手风琴小部件时可以实现的回调：

```js
$("#myAccordion").accordion({
  activate: function (event, ui) {
    if(ui.newHeader.length > 0){
      alert(ui.newHeader.attr("id"));
    } else {
      // closed
    }
  }
});
```

在这里，我们将参数传递给函数，并使用它们来确定哪个手风琴标题是打开的，然后在屏幕上显示结果。将这些对象传递给我们定义的任何回调函数的原理适用于所有组件；我们将在后续章节中详细介绍这一点。

# 摘要

jQuery UI 消除了构建引人入胜和有效用户界面的困难。它提供了一系列组件，可以快速且轻松地直接使用，并且只需少量配置即可。每个组件都公开了一套完整的属性和方法，以便与您的页面或应用程序集成，如果需要更复杂的配置，则可以利用这些属性和方法。

每个组件都设计为高效、轻量级和语义正确，同时利用了 JavaScript 的最新面向对象特性，并使用了简洁、经过充分测试的框架。与 jQuery 结合使用时，它为任何网页开发者的工具包提供了强大的补充。

到目前为止，我们已经看到了如何获取库，如何设置系统以利用它，以及库的结构。我们还看过如何为不同的小部件添加或自定义主题，如何简单而一致地公开库的功能，以及不同类别的组件。在本章的过程中，我们涵盖了一些重要的主题，但现在我们可以开始使用 jQuery UI 的组件，进行一些真正的编码，首先来看看 CSS 框架。


# 第二章：CSS 框架和其他工具

在 1.7 版中添加，jQuery UI 库包含一个更新的 CSS 框架，可用于有效和一致地为库中提供的每个小部件设置主题。该框架由许多辅助类组成，我们可以在自己的代码中使用，即使我们没有使用库组件。

在本章中，我们将涵盖以下主题：

+   构成框架的文件

+   如何使用框架提供的类

+   如何快速轻松地切换主题

+   覆盖主题

+   使用位置工具

# 处理构成框架的文件

依赖于您选择下载的库的版本，库结构中有两个位置存放着构成框架的 CSS 文件。

以下是它们：

+   `css`: 此文件夹包含完整的 CSS 框架，包括在构建下载包时选择的主题。所有必需的 CSS 已经放置在一个单独的、精简的样式表中，以最小化生产环境中的 HTTP 请求。CSS 文件存储在一个文件夹中，文件夹的名称取决于下载生成器上选择的主题。该框架的此版本将包含下载生成器中选择的所有组件的样式，因此其大小将根据使用的库的多少而变化。

+   `themes`: 框架的另一个版本存在于 `development-bundle` 文件夹中，其中您将找到 `themes` 文件夹。此文件夹中提供了两个主题——基础主题和在下载库时选择的任何主题。基础主题是一个灰色的、中性的主题，与平滑主题在视觉上完全相同。

在每个主题文件夹中，都有构成框架的各个文件。框架的不同组件被分割到各自的文件中：

| 组件 | 用途 |
| --- | --- |

|

```js
jquery.ui.all.css

```

| 在开发中，可以通过使用此文件链接所有主题所需的文件。它包含了 `@import` 指令，引入了 `ui.base.css` 和 `ui.theme.css` 文件。 |
| --- |

|

```js
jquery.ui.base.css

```

| 此文件被 `ui.all.css` 使用。它还包含 `@import` 指令，引入 `ui.core.css` 文件以及每个小部件 CSS 文件。但是，它不包含控制每个小部件外观的主题样式。 |
| --- |

|

```js
jquery.ui.core.css

```

| 此文件提供核心框架样式，如清除辅助程序和通用覆盖。 |
| --- |

|

```js
jquery.ui.accordion.css
jquery.ui.datepicker.css
jquery.ui.button.css
jquery.ui.autocomplete.css
jquery.ui.dialog.css
jquery.ui.progressbar.css
jquery.ui.resizable.css
jquery.ui.selectable.css
jquery.ui.slider.css
jquery.ui.spinner.css
jquery.ui.tabs.css
jquery.ui.menu.css
jquery.ui.tooltip.css
jquery-ui.css

```

| 这些文件是控制每个小部件布局和基本外观的个别源文件。 |
| --- |

|

```js
jquery.ui.theme.css

```

| 此文件包含库中每个小部件的完整视觉主题和目标的所有视觉元素。 |
| --- |

让我们更详细地查看每个文件。

## jquery.ui.all.css

`jquery.ui.all.css`文件使用 CSS 导入，使用`@import`规则读取两个文件——`jquery.ui.base.css`和`jquery.ui.theme.css`文件。这就是文件中存在的所有内容，以及实现完整框架和选定主题所需的所有内容。

从此文件中找到的两个指令中，我们可以看到使小部件功能的框架部分和赋予其视觉外观的主题之间的分隔。

## jquery.ui.base.css

`jquery.ui.base.css`文件还包括仅有的`@import`规则，并且导入了`jquery.ui.core.css`文件以及每个单独的小部件 CSS 文件。此时，我应该提到可调整大小的组件有自己的框架文件，以及每个小部件。

## jquery.ui.core.css

`jquery.ui.core.css`文件为所有组件提供通用样式。它包含以下类：

| 类 | 用途 |
| --- | --- |
| `.ui-helper-hidden` | 这个类通过`display: none`隐藏元素。 |
| `.ui-helper-hidden-accessible` | 这个类通过裁剪元素来隐藏它们，以便元素仍然完全可访问。元素没有被隐藏或定位到屏幕外。 |
| `.ui-helper-reset` | 这是 jQuery UI 的重置机制（它不使用单独的重置样式表），它中和了浏览器通过通用元素应用的边距、填充和其他常见默认样式。有关重置默认浏览器样式的重要性的介绍，请访问：[`sixrevisions.com/css/css-tips/css-tip-1-resetting-your-styles-with-css-reset/`](http://sixrevisions.com/css/css-tips/css-tip-1-resetting-your-styles-with-css-reset/)。 |
| `.ui-helper-clearfix` | `.ui-helper-clearfix`样式应用于容器本身。 |
| `.ui-helper-zfix` | `.ui-helper-zfix`类提供了应用于`<iframe>`元素的规则，以解决使用覆盖时的 z-index 问题。 |
| `.ui-state-disabled` | 这个类将禁用元素的光标设置为默认，并使用`important`指令确保它不会被覆盖。 |
| `.ui-icon` | 这条规则是库用背景图替换元素的文本内容的方法。设置库中的不同图标的背景图像的责任被委托给`jquery.ui.theme.css`文件。 |
| `.ui-widget-overlay` | 这个类设置了显示对话框和其他模态弹出窗口时应用于页面的叠加的基本样式属性。由于叠加使用了图像，因此该类的一些样式也在主题文件中找到。 |

核心文件为框架的其余部分奠定了基础。我们还可以将这些类名赋予我们自己的元素，以在使用库时清除浮动或隐藏元素，并且在使用 ThemeRoller 一致主题的情况下构建新的 jQuery UI 插件时使用。

### 解释各个组件框架文件

库中的每个小部件以及可调整大小的交互助手都有一个控制 CSS 并使小部件正确运行的框架文件。例如，选项卡小部件中的选项卡标题必须向左浮动，以便将它们显示为选项卡。框架文件设置了此规则。当我们在自定义主题中覆盖框架时，这些样式将需要呈现出来。

这些文件很简短，每个组件使用的规则数量尽可能少，以确保其正确运行。通常，文件非常紧凑（通常不超过 15 条样式规则）。Datepicker 源文件是个例外，因为它需要大量规则才能正确运行。

## jquery.ui.theme.css

此文件将根据使用 ThemeRoller 选择或创建的主题进行自定义。

它设置了构成每个小部件的不同元素的所有视觉属性（颜色、图像等）。

在`jquery.ui.theme.css`文件中，有许多注释，其中包含在大括号中的描述性标签。这些称为**占位符**，当主题生成时，ThemeRoller 会自动更新它们之前的 CSS 样式。

这是为完整主题生成的文件，其中包含在使用 ThemeRoller 创建或选择主题时创建的每个小部件的所有可见部分的样式。当在自定义主题中覆盖框架时，主要是这个文件中的规则将被覆盖。

每个小部件都是由一组共同的元素构成的。例如，每个小部件的外部容器都具有名为`ui-widget`的类，而小部件内的任何内容都将放在名为`ui-widget-content`的容器中。正是这种一致的布局和分类约定使得该框架如此有效。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/supportand`](http://www.packtpub.com/supportand)注册，直接将文件发送到您的电子邮件中。

这是框架中使用的最大样式表，其中包含太多类，无法在此完整列出（但现在可以打开它并查看）。以下表格列出了不同类别的类：

| 类别 | 用途 |
| --- | --- |
| 容器 | 此类别为小部件、标题和内容容器设置样式属性。 |
| 交互状态 | 这些类设置了任何可点击元素的默认、悬停和活动状态。 |
| 交互提示 | 此类别为元素应用了视觉提示，包括高亮、错误、禁用、主要和次要样式。 |
| 状态和图像 | 这些类设置了在内容和标题容器中显示的图标的图片，以及包括默认状态、悬停状态、活动状态、高亮状态、焦点状态和错误状态在内的可点击元素的图像。 |
| 图像定位 | 主题中使用的所有图标图像都存储在单个精灵文件中，并通过操作精灵文件的背景位置属性来单独显示它们。这个类别设定了所有个别图标的背景位置。 |
| 角半径 | CSS3 用于为支持的浏览器（如 Firefox 3+，Safari 3+，Chrome 1+，Opera 10+ 和 IE9+）提供圆角。 |
| 叠加 | 在核心 CSS 文件中定义的通用叠加所使用的图像在这里设置，因为它是一个实现了对指定元素的半透明叠加效果的类。 |

jQuery UI 文档中详细介绍了主题 API：[`api.jqueryui.com/category/theming/`](http://api.jqueryui.com/category/theming/)。

# 链接到所需的框架文件

在开发环境中，为了快速主题化所有 jQuery UI 小部件，我们可以使用`jquery.ui.all.css`链接到所有个别文件：

```js
<link rel="stylesheet"
href="development-bundle/themes/smoothness/jquery.ui.all.css">
```

例如，要在测试选项卡小部件等组件时单独使用每个文件，我们将使用以下`<link>`元素：

```js
<link rel="stylesheet"
  href="development-bundle/themes/base/jquery.ui.core.css">
<link rel="stylesheet"
  href="development-bundle/themes/base/jquery.ui.tabs.css">
<link rel="stylesheet"
  href="development-bundle/themes/base/jquery.ui.theme.css">
```

当单独链接到 CSS 资源时，应按以下顺序将其添加到 HTML 页面中：`core.css`，小部件的 CSS 文件，以及`theme.css`文件。

当然，在生产环境中，我们将使用高效的合并文件来最小化对 CSS 文件的 HTTP 请求数量。我们需要链接到合并的`jquery-ui-x.x.x.min.css`样式表，该文件位于`css/themename/`目录中，其中 x.x.x 是您下载的 jQuery UI 的版本号：

```js
<link rel="stylesheet"
  href="css/smoothness/jquery-ui-x.x.x.custom.css">
```

为了更轻松地编码和方便起见，在我们的所有示例中，我们将链接到`development-bundle/themes/base/jquery.ui.all.css`文件。如果您按照上一章节所示解压了库，那么与`css`，`development-bundle`和`js`文件夹一起，先前的 CSS 文件路径将是正确的。如果您使用不同的结构，请相应地修改 CSS 文件的路径。

### 提示

**创建本书的示例**

在本书中，您会注意到我们提到将文件保存在`jqueryui`文件夹中；您可能希望为每个章节创建一个子文件夹，以便代码可以与其他章节分开存储。这在本书附带的代码下载中有所体现。

# 使用框架类

在实现官方 jQuery UI 小部件的同时，我们还可以在部署自定义插件时使用它。

## 与容器一起工作

推荐使用容器，因为这意味着我们编写的小部件或插件将准备好 ThemeRoller，并且更容易为最终开发人员提供主题和定制。让我们看看用我们自己的元素使用框架有多容易。

在文本编辑器中，创建一个新文件并添加以下代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CSS Framework - Containers</title>
  <link rel="stylesheet"
    href="development-bundle/themes/base/jquery.ui.all.css">
</head>
<body>
  <div class="ui-widget">
    <div class="ui-widget-header ui-corner-top">
      <h2>This is a .ui-widget-header container</h2>
    </div>
    <div class="ui-widget-content ui-corner-bottom">
      <p>This is a .ui-widget-content container</p>
    </div>
  </div>
</body>
</html>
```

将此页面保存为`containers.html`，放在我们在第一章创建的`jqueryui`项目文件夹中，*介绍 jQuery UI*，当我们解压缩库时。我们正在从库中的基本开发主题中链接到`jquery.ui.all.css`文件。如果我们要构建更复杂的小部件，我们可能也想链接到`jquery.ui.core.css`文件。

在创建小部件或插件时，使用此文件非常重要，因为它可以让我们验证我们为容器提供的类名是否会获取适当的样式，并向我们保证它们将准备好供 ThemeRoller 使用。我们需要自己应用的任何样式都将放入单独的样式表中，就像库中的每个小部件都有自己的自定义样式表一样。

在这个例子中，我们只使用了几个元素。我们的外部容器被赋予了类名`ui-widget`。

在外部容器内部，我们有两个其他容器。一个是`ui-widget-heading`容器，另一个是`ui-widget-content`容器。我们还为这些元素提供了圆角类的变体：分别是`ui-corner-top`和`ui-corner-bottom`。

在标题和内容容器内部，我们只有一些适当的元素，我们可能想要放入其中，比如标题中的`<h2>`和内容元素中的`<p>`。这些元素将继承一些规则，来自各自的容器，但不会直接由主题文件进行样式设置。

当我们在浏览器中查看这个基本页面时，我们应该看到我们的两个容器元素从主题文件中获取样式，如下面的屏幕截图所示：

![使用容器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_01.jpg)

## 使用交互

让我们看看框架类的更多实际操作。在`containers.html`中，删除带有`<body>`标签的标记，并添加以下内容：

```js
<body>
 <div class="ui-widget">
 <div class="ui-state-default ui-state-active ui-corner-all">
 <a href="#">I am clickable and selected</a>
 </div>
 <div class="ui-state-default ui-corner-all">
 <a href="#">I am clickable but not selected</a>
 </div>
 </div>
</body>
```

我们也要修改标题，以便反映我们在代码中正在创建的内容——删除现有的`<title>`，并替换为以下内容：

```js
<title>CSS Framework - Interaction states</title>
```

将此文件保存为`interactions.html`，放在`jqueryui`项目文件夹中。在这些示例中，我们定义了两个可点击元素，它们由一个容器`<div>`和一个`<a>`元素组成。两个容器都被赋予了类名`ui-state-default`和`ui-corner-all`，但第一个还被赋予了选定状态`ui-state-active`。

这将使我们的可点击元素呈现如下外观：

![使用交互](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_02.jpg)

CSS 框架不提供对`:hover` CSS 伪类的样式。相反，它使用一个类名应用一组样式，该类名是使用 JavaScript 添加的。在闭合`</body>`标签之前，添加以下代码以查看其效果：

```js
<script type="text/javascript" src="img/jquery-2.0.3.js"> </script>
<script>
  $(document).ready(function($){
    $(".ui-widget a").hover(function() {
      $(this).parent().addClass("ui-state-hover");
    }, function() {
      $(this).parent().removeClass("ui-state-hover");    
    });
  });
</script>
```

将此前一个示例文件的变体保存为`interactionsHovers.html`。

### 注意

jQuery 的版本号将随着库的不断发展而更改；我们在本书中始终使用版本 2.03。如果版本不同，请将其替换为您下载的版本。

我们简单的脚本将`ui-state-hover`类名称添加到可点击元素上，当鼠标指针移动到上面时，然后当鼠标指针移开时将其移除。当我们在浏览器中运行页面并悬停在第二个可点击元素上时，我们应该看到`ui-state-hover`样式：

![使用交互](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_03.jpg)

## 添加图标

框架还提供了一系列可用作图标的图像。更改`interactionsHovers.html`中的 ui-widget 容器的内容，使其如下所示：

```js
<div class="ui-widget">
  <div class="ui-state-default ui-state-active ui-corner-all">
 <span class="ui-icon ui-icon-circle-plus"></span>

```

```js
    <a href="#">I am clickable and selected</a>
  </div>
  <div class="ui-state-default ui-corner-all">
 <span class="ui-icon ui-icon-circle-plus"></span>

```

```js
    <a href="#">I am clickable but not selected</a>
  </div>
</div>
```

将此保存为`icons.html`在`jqueryui`目录中。在这个示例中，我们的嵌套`<div>`元素，其具有`ui-icon`和`ui-icon-circle-plus`类，从精灵文件中获得了正确的图标：

![添加图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_04.jpg)

### 注意

如果您还不熟悉精灵是如何工作的，那么值得了解一下这种技术——请参阅[`nerdwith.me/news/css-sprites-for-beginners/`](http://nerdwith.me/news/css-sprites-for-beginners/)，了解如何创建精灵图像的示例。如果您需要创建精灵图像，那么[`csssprites.com/`](http://csssprites.com/)的 CSS Sprites 生成器是一个很好的网站。

如您所见，`ui-state-active`图标与`ui-state-default`图标（以及`ui-state-hover`图标）略有不同。在此示例中，我们没有定位图标，因为这将需要创建一个新的样式表。

本示例的重点是查看如何使用框架的类名称自动添加图标，而无需默认添加任何额外的 CSS 样式。

### 注意

如果我们想要调整定位，我们可以通过添加额外的样式来覆盖`.existing .ui-icon`类，例如`span.ui-icon { float: left; }`，这将将图标重新定位到每个`<span>`中文本的左侧。

### 详细检查图标

现在我们已经看到一些图标的使用，让我们更详细地了解如何使用它们。

图标以精灵图的形式呈现，作为主题的一部分进行下载。在库中的主要`css`文件夹中，您会发现不止一个主题文件夹。根据您需要下载的数量，每个主题库都包含多个由 jQuery UI 使用的精灵图像，用于生成图标，例如我们在前面示例中看到的那些。

查看包含我们图标的图像精灵，它们将看起来像下面这样：

![仔细检查图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_05.jpg)

如果我们检查 DOM 检查器（如 Firebug）中的代码，您将发现至少添加了两种样式，例如：

```js
<span class="ui-icon ui-icon-circle-plus"></span>

```

图标 CSS 的格式通常遵循`.ui-icon-{图标类型}-{图标子描述}-{方向}`；应该注意，如果你在小部件中使用`icon`选项，例如手风琴，则会添加第三个类。

每个图标元素都被赋予一个基本类`.ui-icon`，它将图标的尺寸设置为 16 像素的方块，隐藏内部文本，并使用选择的精灵图像设置背景图像。使用的背景精灵图像将取决于其父容器；例如，在`ui-state-default`容器中的`ui-icon`元素将根据`ui-state-default`的图标颜色进行着色。

### 添加自定义图标

向小部件添加图标不必局限于库中的图标。你可以使用自定义图标。

要做到这一点，我们有两个选项——你可以引用单个文件，或者使用类似的图像精灵；后者更可取，特别是如果你使用多个自定义图标，因为包含它们的精灵在加载后将被缓存。

### 提示

你可以在 [`api.jqueryui.com/theming/icons/`](http://api.jqueryui.com/theming/icons/) 上看到核心 jQuery UI 库中提供的所有图标及其图标类名的完整列表。

为了引用这些图标，你需要添加你自己的自定义样式，覆盖`.ui-icon`类——这是为了确保 jQuery UI 不会尝试应用取消你自己样式的样式。这样一个自定义类的示例如下所示：

```js
.ui-button .ui-icon.you-own-cusom-class {
    background-image: url(your-path-to-normal-image-file.png);
    width: your-icon-width;
    height: your-icon-height; 
}
.ui-button.ui-state-hover .ui-icon.you-own-cusom-class {
    background-image: url(your-path-to-highlighted-image-file.png);
    width: your-icon-width;
    height: your-icon-height;
}
```

我们可以将新样式应用到我们选择的小部件中，就像使用 jQuery UI 按钮的示例所示：

```js
       $('selector-to-your-button').button({
         text: false,
         icons: {
           primary: "you-own-cusom-class"   // Custom icon
         }
       });
```

只要图标格式正确，并且在我们的代码中正确引用，那么我们可以自由地添加任何我们想要的图标；值得在线上搜索选项，因为会有大量可供使用的图标，例如 [`fortawesome.github.io/Font-Awesome/icons/`](http://fortawesome.github.io/Font-Awesome/icons/) 上的 Font Awesome 库，或者可以从 [`icomoon.io/`](http://icomoon.io/) 下载的 IcoMoon。

### 提示

**为什么我的图标会出现在新行上？**

在某些情况下，你可能会发现你的图标出现在小部件中的文本上方或下方的新行中，就像本章早些时候的图标示例所示。这是由于`.ui-icon`类中的`display: block`属性造成的：

为了解决这个问题，你可以使用浮动属性，并将其设置为适当的左、右或中心位置来显示图标。

### 使用自定义图标 - 一则说明

如果你决定使用自定义图标，那么没有任何东西会阻止你这样做，这将打开大量的可能性！你需要注意的是，使用自定义图标需要使用两个类——`base .ui-icon`，然后是你自己的自定义类。这是为了确保图标显示正确，并防止 jQuery UI 尝试覆盖你自己的图标。

如果不注意确保图标的尺寸正确，使用自己的图标可能会与框架内的样式冲突；强烈建议您仔细查看提供的现有图标库，因为 jQuery UI 团队可能已经转换了一些可能有用的内容。另外，线上搜索也可能会有帮助；为 jQuery UI 编写了自定义主题，您可能会找到包含您需要的图标的主题。

## 交互提示

另一组我们可以使用的类是交互提示。我们将看另一个使用这些的例子。在文本编辑器中的新页面中，添加以下代码。这将创建一个表单示例，我们可以在其中看到提示的作用：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CSS Framework - Interaction cues</title>
  <link rel="stylesheet" href="development-bundle/themes/base/jquery.ui.all.css">
  <link rel="stylesheet" href="css/jquery.ui.form.css">
</head>
<body>
  <div class="ui-widget ui-form">
    <div class="ui-widget-content ui-corner-all">
      <div class="ui-widget-header ui-corner-all">
        <h2>Login Form</h2>
      </div>
      <form action="#" class="ui-helper-clearfix">
        <label>Username</label>
        <div class="ui-state-error ui-corner-all">
          <input type="text">
          <div class="ui-icon ui-icon-alert"></div>           
          <p class="ui-helper-reset ui-state-error-text">Required field</p>
        </div>
      </form>
    </div>
  </div>
</body>
</html>
```

将此文件保存为`cues.html`，放在`jqueryui`文件夹中。这次我们链接到一个自定义文件，`jquery.ui.form.css`，我们马上就会创建它。

在页面上，我们有外部小部件容器，具有`ui-form`和`ui-widget`类名。`ui-form`类将用于从`jquery.ui.form.css`样式表中选取我们的自定义样式。在小部件内部，我们有`ui-widget-header`和`ui-widget-content`容器。

在内容部分，我们有一个带有一行元素的`<form>`，一个`<label>`元素，后面跟着一个`<div>`元素，其中硬编码了`ui-state-error`和`ui-corner-all`类名。

在这个`<div>`元素内部，我们有一个标准的`<input>`，一个带有`ui-icon`和`ui-icon-alert`类的`<div>`，以及一个添加了`ui-state-error-text`类名的`<p>`元素。因为`<form>`将有由于我们将在`jquery.ui.form.css`中添加的样式而浮动的子元素，所以我们可以利用`ui-helper-clearfix`类来清除浮动，我们将其添加为一个类名。

现在我们应该创建自定义的`jquery.ui.form.css`样式表。在文本编辑器中的新文件中，添加以下代码：

```js
.ui-form { width: 470px; margin: 0 auto; }
.ui-form .ui-widget-header h2 { margin: 10px 0 10px 20px; }
.ui-form .ui-widget-content { padding: 5px; }
.ui-form label, .ui-form input, .ui-form .ui-state-error,
.ui-form .ui-icon, .ui-form .ui-state-error p { float: left; }
.ui-form label, .ui-state-error p { font-size: 12px; padding: 10px 10px 0 0; }
.ui-form .ui-state-error { padding: 4px; }
.ui-form .ui-state-error p { font-weight: bold; padding-top: 5px; }
.ui-form .ui-state-error .ui-icon { margin:5px 3px 0 4px; }
.ui-helper-clearfix:before, .ui-helper-clearfix:after { margin-top: 10px; } 
```

在我们的`jqueryui`项目文件夹中，有一个名为`css`的文件夹，用于存储框架的单文件生产版本。我们在本书中创建的所有 CSS 文件也将保存在这里以方便使用。将此文件保存为`jquery.ui.form.css`，放在`css`文件夹中。

想象我们有更多的表单元素和一个提交按钮。通过将`ui-state-error`类添加到`<div>`元素，我们可以使用表单验证的错误类，如果提交不成功，将显示图标和文本。以下截图显示页面应该是什么样子的：

![交互提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_06.jpg)

# 快速轻松地切换主题

一旦我们使用基本主题开发了内容，我们可能会决定将主题更改为与我们整体网站主题更好地匹配的主题；幸运的是，CSS 框架使更换主题变得轻松。看看之前的例子，要改变小部件的外观只需选择一个新的主题使用 ThemeRoller（可在[`www.jqueryui.com/themeroller`](http://www.jqueryui.com/themeroller)获得），然后下载新主题。我们可以通过在下载构建器中选择所有组件并单击**下载**来下载新主题以获取新主题。

在下载的存档中，会有一个以所选主题命名的目录，比如**redmond**。我们将`theme`文件夹从存档中拖到`development-bundle\themes`文件夹中，并从我们的页面链接新的主题文件，使我们的表单呈现出全新的外观，如下面的截图所示：

![快速轻松地切换主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_07.jpg)

我用来获得这个截图的主题是 redmond。这个主题使用了各种蓝色的色调，要么是作为背景要么是作为普通文本；选定的选项，比如选项卡标题或小部件中选定的项目将以橙色文本或橙色背景显示。在本书的剩余部分中，我们将使用这个主题，或者我们自己创建的主题。

## 覆盖主题

使用 ThemeRoller 画廊和自定义工具，我们可以生成大量独特的主题。但有时候我们可能需要比使用 ThemeRoller 能够达到的更深层次的定制化；在这种情况下，我们有两个选择。

我们可以要么自己从头创建完整的主题文件，要么创建一个额外的样式表，只覆盖我们需要的`jquery.ui.theme.css`文件中的规则。后者可能是最简单的方法，并且需要编写的代码更少。

现在我们将看一下主题的这个方面。如果你已经为之前的示例更改了基本主题，请切换回`cues.html`的`<head>`中的基本主题。将页面保存为`cuesOverridden.html`，然后创建以下新样式表：

```js
.ui-corner-all { border-radius: 4px; }
.ui-widget-header { font-family: Helvetica; background:   #251e14; border-radius: 4px 4px 0 0; border: 1px solid #362f2d;color: #c7b299; }
.ui-form .ui-widget-header h2 { margin: 0; padding: 5px; font-style: italic; font-weight: normal; }
.ui-form .ui-widget-content { background: #eae2d8; border: 1px solid #362f2d; border-top: 0; width:  500px; padding: 0; }
.ui-widget-content form { padding: 20px; border: 1px solid #f3eadf; border-radius: 0 0 4px 4px; }
.ui-widget-content .ui-state-error-text { color: #9A1B1E; }
.ui-form .ui-state-error { border-radius:  4px 4px 4px 4px; }
```

将其保存为`overrides.css`放在`css`文件夹中。在这个样式表中，我们主要是覆盖了`jquery.ui.theme.css`文件中的规则。这些是简单的样式，我们只是改变了颜色、背景和边框。通过在`cuesOverridden.html`的其他样式表下面添加以下代码行来链接到这个样式表：

```js
<link rel="stylesheet" href="css/overrides.css">
```

我们谦逊的表单现在应该呈现如下截图中所示：

![覆盖主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_08.jpg)

只要我们的样式表出现在`theme`文件之后，并且我们的选择器特异性匹配或超过了`jquery.ui.theme.css`文件中使用的选择器，我们的规则就会优先。对 CSS 选择器权重的长时间讨论超出了本书的范围。但是，简要解释特异性可能是有益的，因为它是覆盖所选主题的关键。CSS 特异性指的是 CSS 选择器的特异性程度——它越具体，权重就越大，随后将覆盖其他选择器应用于其他选择器所针对的元素的规则。例如，考虑以下选择器：

```js
#myContainer .bodyText
.bodyText
```

第一个选择器比第二个选择器更具体，因为它不仅使用了目标元素的类名，还使用了其父容器的 ID。因此，它将覆盖第二个选择器，无论第二个选择器是否在其之后出现。

### 注意

如果您想了解更多关于 CSS 特异性的信息，那么互联网上有许多优秀的文章。作为一个开始，您可能想看看 [`designshack.net/articles/css/what-the-heck-is-css-specificity/`](http://designshack.net/articles/css/what-the-heck-is-css-specificity/)，或者 [`reference.sitepoint.com/ css/specificity`](http://reference.sitepoint.com/ css/specificity)。或者，您可能想完成克里斯·科耶的示例，网址是 [`css-tricks.com/specifics-on-css-specificity/`](http://css-tricks.com/specifics-on-css-specificity/)。

在这个示例中，我们完全控制了我们正在修饰的元素。但是，当与库中的任何小部件或由第三方编写的插件一起工作时，可能会自动生成大量标记，我们无法控制（除非修改实际的库文件本身）。

因此，我们可能需要依赖这种方式来覆盖样式。我们只需在文本编辑器中打开`jquery.ui.theme.css`文件并查看其中使用的选择器即可找到要覆盖的样式。如果未能做到这一点，我们可以使用 Firebug 的 CSS 查看器来查看我们需要覆盖的规则，就像下面的示例一样：

![覆盖主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_09.jpg)

### 提示

**DOM 探查器**

所有现代浏览器都有像 Firebug 这样的 DOM 探查器和 CSS 检查器，可以用来查看 CSS 规则应用的顺序。使用浏览器的 CSS 检查器通常是检查 CSS 顺序的最方便方式。

# 定位实用工具

定位实用工具是一个强大的独立工具，用于将任何元素相对于窗口、文档、特定元素或鼠标指针定位。它在库组件中是独一无二的，因为它不需要`jquery.ui.core.js`或`jquery.effects.core.js`作为依赖项。

它不公开任何独特或自定义的方法（除了`position()`方法），也不触发任何事件，但它确实提供了一系列配置选项，让我们可以使用它。这些选项在下表中列出：

| 选项 | 格式 | 用于 |
| --- | --- | --- |
| at | 字符串 | 指定要对齐的定位元素的边缘。格式为，例如，left bottom。 |
| collision | 字符串 | 当定位元素溢出其容器时，将定位元素移动到替代位置。 |
| my | 字符串 | 指定预期与要定位的元素对齐的定位元素的边缘，例如 right top。 |
| of | 选择器，jQuery，对象，事件对象 | 指定相对于定位元素的元素。当提供选择器或 jQuery 对象时，使用第一个匹配的元素。当提供事件对象时，使用 pageX 和 pageY 属性 |
| using | 函数 | 接受一个函数，实际上定位定位元素。该函数接收一个包含新位置的 top 和 left 值的对象。 |

## 使用位置实用程序

使用位置实用程序非常简单。让我们看几个例子；在您的文本编辑器中创建以下页面：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Position Utility - position</title>
  <link rel="stylesheet" href="css/position.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.position.js"> </script>
  <script>
    $(document).ready(function() {
      (function($) {
        $(".ui-positioned-element").position({
          of: ".ui-positioning-element"
        });
      })(jQuery);
    });
  </script>
</head>
<body>
  <div class="ui-positioning-element">I am being positioned against</div>
  <div class="ui-positioned-element">I am being positioned </div>
</body>
</html>
```

将此保存为`position.html`。在这个例子中，我们还使用了一个非常基本的样式表，其中包含以下样式：

```js
.ui-positioning-element { width: 200px; height: 200px; border: 1px solid #000; }
.ui-positioned-element { width: 100px; height: 100px; border: 1px solid #f00; }
```

将此文件保存在`css`文件夹中，命名为`position.css`。我们正在定位的元素以及我们自身的定位元素可以设置为相对、绝对或静态定位，而不会影响定位元素的行为。如果我们要定位的元素使用其 top、left、bottom 或 right 样式属性移动，我们要定位的元素将考虑到这一点，并且仍然可以正常工作。

在页面上，我们只有两个`<div>`元素：一个是我们要定位的元素，另一个是我们要定位的实际元素。jQuery 本身是一个要求，所以我们在`<head>`元素中链接到它，并且我们还链接到位置实用程序的源文件。正如我之前提到的，当单独使用位置时，我们不需要链接到`jquery.ui.core.js`文件。

我们可以使用的最小配置，就像我们在这个例子中所做的那样，就是设置`of`选项，以指定我们要定位的元素。当我们只设置了这一个选项时，我们要定位的元素会被放置在我们要定位的元素的正中央，如下面的截图所示：

![使用位置实用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_10.jpg)

这本身就非常有用，因为元素不仅在水平方向上居中，而且在垂直方向上也是如此。

通过使用`my`和`at`属性，我们还可以将定位元素的任何边缘放置在我们正在定位的元素的任何边缘上。更改外部函数中的代码，使其显示如下（新/更改的代码以粗体显示）：

```js
$(".ui-positioned-element").position({
 of: ".ui-positioning-element",
 my: "right bottom",
 at: "right bottom"
});
```

以下截图显示了此代码的输出：

![使用定位实用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_11.jpg)

`my`选项指的是正在定位的元素。该选项的值作为字符串的第一部分被提供，它是水平轴，可以设置为左、中或右。第二部分是垂直轴，可以设置为顶部、中部或底部。

`at`选项指的是正在定位的元素的水平和垂直边缘。它还接受与`my`配置选项相同格式的字符串。

## 解释碰撞避免

定位实用程序具有内置的碰撞检测系统，以防止正在定位的元素溢出视口。我们可以使用两种不同的选项来设置检测到碰撞时发生的情况。默认值为`flip`，这会导致元素翻转并将其对齐到已配置的相反边缘。

例如，如果我们将一个`<div>`元素的右边缘定位到另一个元素的左边缘，如果它溢出了视口，它将被翻转，使其右边缘与定位元素的右边缘对齐。

将`position.html`中的配置更改为以下内容：

```js
$(".ui-positioned-element").position({
 of: ".ui-positioning-element",
 my: "right",
 at: "left"
});
```

这将导致以下定位：

![解释碰撞避免](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_12.jpg)

碰撞避免的另一种模式是`fit`，它会尽可能尊重配置的定位，但调整元素的定位，使其保持在视口内。将碰撞选项配置如下：

```js
$(".ui-positioned-element").position({
 collision: "fit",
 of: ".ui-positioning-element",
 my: "right",
 at: "left"
});
```

将此文件保存为`positionFit.html`。这次，元素被尽可能地定位到其预期位置：

![解释碰撞避免](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_13.jpg)

### 提示

我们还可以将`collision`选项的值设置为`none`，以完全禁用碰撞检测，并允许定位元素溢出视口。

# 使用函数进行定位

我们可以将`using`选项设置为一个函数，并手动定位被定位的元素。更改配置，使其显示如下：

```js
$(".ui-positioned-element").position({
  of: ".ui-positioning-element",
 my: "right bottom",
 at: "right bottom",
 using: function(pos) {
 $(this).css({
 backgroundColor: "#fc7676",
 top: pos.top,
 left: pos.left
 });
 }
});
```

将此更改保存为`positionFunction.html`。我们将一个匿名函数作为`using`选项的值提供。此函数作为单个参数传递，该参数是一个包含属性 top 和 left 的对象，这些属性对应于我们正在定位的元素应该具有的值。

如你从这段代码中所见，我们仍然需要手动定位元素，但该函数允许我们对可能需要的元素进行任何预处理。在函数内部，`this`对象被设置为被定位的元素。

# 在实际示例中使用定位小部件

到目前为止，我们已经考虑了使用位置小部件的理论；在转向查看小部件工厂之前，让我们花点时间考虑一下如何在实际情况中使用位置小部件。

一个完美的例子是 jQuery UI 的对话框小部件，配置为作为模态对话框运行。在这里，我们可以使用位置小部件将对话框放置在页面上，相对于按钮当前的位置。

要了解如何做，请将以下代码添加到文本编辑器中的新文件中：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dialog</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.position.js"></script>
  <script src="img/jquery.ui.dialog.js"></script>
  <script src="img/jquery.ui.button.js"></script>
  <script></script>
</head>
<body></body>
</html>
```

我们需要一些标记，因此请在`<body>`标签之间添加以下代码：

```js
<div id="myDialog" title="This is the title!">
  Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
  Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis
  volutpat ligula. Integer vitae felis quis diam laoreet
  ullamcorper. Etiam tincidunt est vitae est.
</div>
Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis
volutpat ligula. Integer vitae felis quis diam laoreet
ullamcorper. Etiam tincidunt est vitae est.
<button id="showdialog">Click me</button>
```

最后，为了将其整合并使其正常工作，请在关闭`</head>`标签之前添加以下脚本作为最后一个条目：

```js
$(document).ready(function($){
  $("#showdialog").button();
  $("#myDialog").dialog({ autoOpen: false, modal: true, });
  $("#showdialog").click(function() {
    $("#myDialog").dialog("open");
  });
  $("#showdialog").position({
    my: "left+20 top+100",
    at: "left bottom",
    of: myDialog
  });
});
```

如果我们在浏览器中预览这个页面，你会发现当点击按钮时，我们无法对背景中的文本进行任何操作：

![在实际例子中使用位置小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_02_14.jpg)

在这里，我们启动了一个 UI 对话框，并将其配置为作为模态对话框运行；`autopen`已设置为`false`，以便在显示页面时不显示对话框。然后，我们创建了一个简单的点击处理程序，在按钮点击时显示对话框；然后调用位置小部件，其中我们设置了`my`和`at`属性，以正确显示对话框相对于按钮的当前位置。

# 小部件工厂

jQuery UI 库中的另一个工具是小部件工厂，它是在 jQuery UI 1.8 版中引入的，并且此后已经经历了一些重要变化。它将允许轻松创建小部件的功能分割成一个单独且独立的实用程序文件。这就是`jquery.ui.widget.js`文件，我们可以使用它轻松创建我们自己的 jQuery UI 插件。就像 jQuery 本身提供`fn.extend()`方法轻松创建插件一样，jQuery UI 也提供了使插件创建更容易的机制，并确保在新插件中保留常见 API 功能。我们将在本书的一个单独章节中更详细地介绍小部件工厂，该章节可以下载。

# 总结

在本章中，我们看到了 CSS 框架如何一致地为每个库组件设置样式。我们查看了组成它的文件以及它们如何共同工作以提供完整的外观和感觉。我们还看到了 ThemeRoller 应用程序与框架的紧密集成程度，并且很容易使用 ThemeRoller 安装或更改主题。我们还看到了如果需要对无法仅通过 ThemeRoller 获得的小部件进行根本性自定义，我们如何可以覆盖主题文件。

该章节还介绍了如何构建与框架兼容并可以利用框架的自定义小部件或插件，以及确保我们的创建可以使用 ThemeRoller。我们还可以利用框架提供的助手类，例如`ui-helper-clearfix`类，来快速实现常见的 CSS 解决方案。

我们还研究了位置实用工具，它允许我们将一个元素的任何边与另一个元素的任何边对齐，为我们提供了一个强大而灵活的定位元素的方式，无论是创建还是操作元素。

在接下来的章节中，我们将开始查看库提供的小部件，从标签小部件开始。


# 第三章：使用标签小部件

现在我们已经正式介绍了 jQuery UI 库、CSS 框架和一些实用工具，我们可以开始查看库中包含的各个组件了。在接下来的七章中，我们将着眼于小部件。这些是一组视觉吸引力强、高度可配置的用户界面小部件。

UI 标签小部件用于在不同元素之间切换可见性，每个元素都包含通过点击其标签标题可以访问的内容。每个内容面板都有自己的标签。标签标题通常显示在小部件顶部，尽管也可以重新定位它们，使它们出现在小部件底部。

标签被结构化成水平排列在一起，而内容部分除了活动面板外都被设置为`display: none`。点击一个标签将突出显示该标签并显示其关联的内容面板，同时确保所有其他内容面板都被隐藏。一次只能打开一个内容面板。可以配置标签使得没有内容面板打开。

在本章中，我们将查看以下主题：

+   小部件的默认实现

+   CSS 框架如何定位标签小部件

+   如何为一组标签应用自定义样式

+   使用它们的选项配置标签

+   内容面板变化的内置转换效果

+   使用它们的方法控制标签

+   由标签定义的自定义事件

+   AJAX 标签

下面的截图标有 jQuery UI 标签组件的不同元素：

![使用标签小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_01.jpg)

# 实现一个标签小部件

标签基于的底层 HTML 元素的结构相对严格，小部件需要一定数量的元素才能工作。标签必须由一个列表元素（有序或无序）创建，每个列表项必须包含一个`<a>`元素。每个链接都需要有一个与链接的`href`属性关联的指定`id`的元素。我们将在第一个示例后澄清这些元素的确切结构。

在文本编辑器中创建一个新文件，创建以下页面：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Tabs</title>
  <link rel="stylesheet" href="development-bundle/themes/base/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"> </script>
  <script src="img/jquery.ui.widget.js"> </script>
  <script src="img/jquery.ui.tabs.js"> </script>
  <script>
    $(document).ready(function($){
    $("#myTabs").tabs();
 });
  </script>  
</head>
<body>
  <div id="myTabs">
    <ul>
      <li><a href="#a">Tab 1</a></li>
      <li><a href="#b">Tab 2</a></li>
    </ul>
    <div id="a">This is the content panel linked to the first tab, it is shown by default.</div>
    <div id="b">This content is linked to the second tab and will be shown when its tab is clicked.</div>
  </div>
</body>
</html>
```

将代码保存为`jqueryui`工作文件夹中的`tabs1.html`。让我们回顾一下使用了什么。默认标签小部件配置需要以下脚本和 CSS 资源：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.tabs.js`

标签小部件通常由若干个标准 HTML 元素构成，以特定方式排列：

+   调用标签方法的外部容器元素

+   列表元素（`<ul>`或`<ol>`）

+   为每个标签的`<li>`元素内的`<a>`元素

+   每个标签的内容面板元素

### 注意

这些元素可以硬编码到页面中，动态添加，或者根据需求可以是两者的混合。

外部容器中的列表和锚元素构成可点击的选项卡标题，用于显示与选项卡关联的内容部分。链接的`href`属性应设置为带`#`前缀的片段标识符。它应与形成其关联的内容部分的`id`属性相匹配。

每个选项卡的内容部分是使用`<div>`元素创建的。`id`属性是必需的，并且将由对应的`<a>`元素进行定位。在此示例中，我们已经使用`<div>`元素作为每个选项卡的内容面板，但只要提供相关配置并且生成的 HTML 有效，就可以使用其他元素。`panelTemplate`和`tabTemplate`配置选项可用于更改用于构建小部件的元素（有关更多信息，请参见本章后面的*配置*部分）。

我们在`<head>`部分的关闭标签之前链接到库中的多个`<script>`资源。脚本可以使用`document.ready()`命令在`<head>`部分加载，或者在样式表和页面元素之后加载。将它们放在最后加载是一种提高页面视觉加载时间的成熟技术，尽管这样做真正带来了多大的性能优势还有待商榷。

连接到 jQuery 后，我们链接到`jquery.ui.core.js`文件，该文件是所有组件（除了效果组件，它们有自己的核心文件）所需的。然后链接到`jquery.ui.widget.js`文件。然后链接到组件的源文件，本例中是`jquery.ui.tabs.js`。

在库中引入的三个必需脚本文件之后，我们可以转向自定义的`<script>`元素，其中包含创建选项卡的代码。我们在 jQuery 的`DOMReady`语句中封装用于创建选项卡的代码；这样做可确保代码仅在页面元素加载并准备好进行操作时才执行。我们还通过 jQuery 对象（`$`）传递来帮助避免与其他基于 JavaScript 的库发生冲突。

在`DOMReady`函数中，我们只需在表示选项卡容器元素的 jQuery 对象上调用`tabs()`小部件方法（具有`id`为`myTabs`的`<ul>`）。当我们在浏览器中运行此文件时，我们应该看到选项卡的外观与本章第一张截图中显示的一样（当然没有注释）。

# 为选项卡小部件添加样式

使用火狐浏览器的 Firebug（或其他通用 DOM 探查器），我们可以看到各种类名添加到不同的底层 HTML 元素中。让我们简要回顾这些类名，并看看它们如何对小部件的整体外观产生影响。以下类名被添加到外部容器`<div>`中：

| 类名 | 目的 |
| --- | --- |
| `ui-tabs` | 允许应用特定于标签的结构 CSS。 |
| `ui-widget` | 设置嵌套元素继承的通用字体样式。 |
| `ui-widget-content` | 提供主题特定的样式。 |
| `ui-corner-all` | 对容器应用圆角。 |

容器中的第一个元素是`<ul>`元素。这个元素获取以下类名：

| 类名 | 目的 |
| --- | --- |
| `ui-tabs-nav` | 允许应用特定于标签的结构 CSS。 |
| `ui-helper-reset` | 中和应用到`<ul>`元素的浏览器特定样式。 |
| `ui-helper-clearfi` | 应用清除浮动，因为这个元素有浮动的子元素。 |
| `ui-widget-header` | 提供特定主题的样式。 |
| `ui-corner-all` | 应用圆角。 |

构成`tab`标题的单独`<li>`元素有以下类名：

| 类名 | 目的 |
| --- | --- |
| `ui-state-default` | 将标签标题应用为标准状态，非活动，非选择，非悬停状态。 |
| `ui-corner-top` | 对元素的顶边应用圆角。 |
| `ui-tabs-selected` | 仅应用于活动标签。在默认实现页面加载时，这将是第一个标签。选择其他标签将从当前选定的标签中移除这个类，并将其应用到新选择的标签。 |
| `ui-state-active` | 对当前选定的标签应用特定主题的样式。这个类名将被添加到当前被选中的标签，就像之前的类名一样。有两个类名的原因是，`ui-tabs-selected`提供了功能性的 CSS，而`ui-state-active`提供了视觉上的装饰样式。 |

每个`<li>`内的`<a>`元素没有任何类名，但它们仍然通过框架应用了结构和特定主题的样式。

最后，包含每个标签内容的面板元素具有以下类名：

| 类名 | 目的 |
| --- | --- |
| `ui-tabs-panel` | 将结构性 CSS 应用于内容面板。 |
| `ui-widget-content` | 应用特定主题的样式。 |
| `ui-corner-bottom` | 对内容面板的底边应用圆角。 |

所有这些类都是自动添加到基础 HTML 元素中的。在编写页面或添加基本标记时，我们不需要手动添加它们。

# 将自定义主题应用于标签

在下一个例子中，我们可以看到如何改变标签的基本外观。我们可以用我们自己的样式规则来覆盖纯粹用于显示目的的任何规则，快速轻松地自定义，而不改变与标签功能或结构相关的规则。

在你的文本编辑器中新建一个非常小的样式表：

```js
#myTabs { min-width: 400px; padding: 5px; border: 1px solid #636363; background: #c2c2c2 none; }
.ui-widget-header { border: 0; background: #c2c2c2 none; font-family: Georgia; }
#myTabs .ui-widget-content { border: 1px solid #aaa; background: #fff none; font-size: 80%; }
.ui-state-default, .ui-widget-content .ui-state-default { border: 1px solid #636363; background: #a2a2a2 none; }
.ui-state-active, .ui-widget-content .ui-state-active { border: 1px solid #aaa; background: #fff none; }
```

这就是我们需要的一切。将文件保存为`tabsTheme.css`在你的`css`文件夹中。如果你将这些类名与之前页面上的表格进行比较，你会发现我们正在覆盖特定主题的样式。因为我们正在覆盖主题文件，我们需要匹配或超越`theme.css`中选择器的特殊性。这就是为什么有时我们会同时针对多个选择器。

在这个示例中，我们覆盖了`jquery.ui.tabs.css`中的一些规则。我们需要使用`jquery.ui.theme.css`中的选择器（`.ui-widget-content`），以及我们容器元素的 ID 选择器，以打败双类选择器`.ui-tabs .ui-tabs-panel`。

在`tabs1.html`的`<head>`中添加对这个新样式表的引用，并将文件另存为`tabs2.html`：

```js
<link rel="stylesheet" href="css/tabsTheme.css">
```

### 注意

确保我们刚刚创建的自定义样式表出现在`jquery.ui.tabs.css`文件之后，因为如果样式表的链接顺序不正确，则无法覆盖我们尝试覆盖的规则。

如果我们在浏览器中查看新页面，它应该显示如下截图：

![将自定义主题应用于选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_02.jpg)

我们的新主题与默认的平滑主题（如第一张截图所示）并没有明显的区别，但我们可以看到，为了适应其环境，更改小部件外观是多么容易，以及需要多少代码。

# 配置选项卡小部件

库中的每个不同组件都有一系列选项，用于控制小部件的哪些功能默认启用。可以将对象文字或对象引用传递给`tabs()`小部件方法以配置这些选项。

可用的选项来配置非默认行为如下表所示：

| 选项 | 默认值 | 用于... |
| --- | --- | --- |
| `active` | `0` | 表示打开的面板。 |
| `collapsible` | `false` | 允许点击活动选项卡时取消选择它，以便隐藏所有内容面板，只显示选项卡标题。 |
| `disabled` | `false` | 在页面加载时禁用小部件。我们还可以传递一个选项卡索引（从零开始）的数组，以便禁用特定的选项卡。 |
| `event` | `"click"` | 指定触发内容面板显示的事件。 |
| `heightStyle` | `content` | 控制选项卡小部件和每个面板的高度。可能的值是`auto`，`fill`和`content`。 |
| `hide` | `null` | 控制是否以及如何动画隐藏面板。 |
| `show` | `null` | 控制是否以及如何动画显示面板。 |

# 使用选项卡

选项卡小部件提供了一些选项，我们可以使用这些选项执行操作，例如选择或禁用选项卡，或添加过渡效果。在接下来的几个示例中，我们将查看其中一些选项，从选择选项卡开始。

## 选择选项卡

让我们看看如何使用这些可配置属性。例如，让我们配置小部件，使得页面加载时显示第二个选项卡。在`tabs2.html`的`<head>`中删除`tabsTheme.css`的链接，并将最终的`<script>`元素更改为以下内容：

```js
<script>
 $(document).ready(function($){
 var tabOpts = {
 active: 1
 };
 $("#myTabs").tabs(tabOpts);
 })
</script>
```

将此保存为`tabs3.html`。不同的选项卡及其关联的内容面板由从零开始的数字索引表示。指定默认打开的不同选项卡与提供其索引号作为`active`属性的值一样容易。现在页面加载时，默认应选择第二个选项卡。

除了更改选定的选项卡外，我们还可以通过为`collapsible`属性提供一个值来指定初始情况下不应选择任何选项卡。将`tabs4.html`中的`<script>`元素更改为以下内容：

```js
<script>
 $(document).ready(function($){
 var tabOpts = {
 active: false,
 collapsible: true
 };
 $("#myTabs").tabs(tabOpts); 
})
</script>
```

这将导致小部件在页面加载时如下所示：

![选择选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_03.jpg)

## 禁用选项卡

您可能希望在满足特定条件之前禁用特定选项卡。通过操纵选项卡的`disabled`属性，这很容易实现。将`tabs4.html`中的`tabOpts`配置对象更改为以下内容：

```js
var tabOpts = {
 disabled: [1]
};
```

将此保存为`jqueryui`文件夹中的`tabs5.html`。在此示例中，我们删除了`active`属性，并将第二个选项卡的索引添加到禁用数组中。我们还可以将其他选项卡的索引以逗号分隔的方式添加到此数组中，以默认禁用多个选项卡。

当页面在浏览器中加载时，第二个选项卡的类名为`ui-widget-disabled`，并且会应用来自`ui.theme.css`的禁用样式。正如下面的截图所示，它不会以任何方式响应鼠标交互：

![禁用选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_04.jpg)

## 添加转换效果

我们可以使用`show`属性轻松添加引人注目的转换效果。当打开或关闭选项卡时，这些效果会显示出来。此选项是使用我们的配置对象内的另一个对象文字（或数组）配置的，该对象启用一个或多个效果。例如，我们可以使用以下配置对象启用淡入淡出效果：

```js
var tabOpts = {
 show: { effect: "toggle", duration: "slow" }
};
```

将此文件保存为`jqueryui`文件夹中的`tabs6.html`。我们创建的`show`对象具有两个属性。第一个属性是在更改选项卡时使用的动画。要使用淡入淡出动画，我们指定`effect`，因为这是要调整的内容。切换效果只是反转其当前设置。如果当前可见，则将其设置为不可见，反之亦然。您可以使用任何一个效果选项，例如`toggle`、`fadeIn`或`slideDown`；我们将在第十四章中更详细地了解效果，*UI Effects*。

第二个属性`duration`指定动画发生的速度。此属性的值为`slow`或`fast`，分别对应`200`和`600`毫秒。任何其他字符串都将导致默认持续时间为`400`毫秒。我们还可以提供一个表示动画应持续的毫秒数的整数。

当我们运行文件时，我们可以看到在选项卡关闭时选项卡内容慢慢淡出，当新的选项卡打开时淡入。两个动画在单个选项卡交互期间发生。为了只在选项卡关闭时显示动画一次，例如，我们需要将`show`对象嵌套在数组中。将`tabs6.html`中的配置对象更改为以下内容：

```js
var tabOpts = {
 show: [{ opacity: "toggle", duration: "slow" }, null]
};
```

当前打开的内容面板的关闭效果包含在数组的第一项中的对象中，而新选项卡的打开动画是第二项。通过将数组的第二项指定为`null`，我们在选择新选项卡时禁用了打开动画。将此保存为`tabs7.html`，并在浏览器中查看结果。

我们还可以通过在第二个数组项上添加另一个对象而不是`null`来指定不同的动画和速度以用于打开和关闭动画。

## 折叠选项卡

默认情况下，单击当前活动的选项卡时不会发生任何事情。但是我们可以更改这一点，使得当选择其选项卡标题时，当前打开的内容面板关闭。将`tabs7.html`中的配置对象更改为以下内容：

```js
var tabOpts = {
 collapsible: true
};
```

保存此版本为`tabs8.html`。此选项允许关闭所有内容面板，就像在前面的`selected`属性中提供`null`时那样。单击停用的标签将选择该标签并显示其关联的内容面板。再次单击相同的选项卡会关闭它，将小部件缩小，以便只有选项卡标题可见。

# 使用选项卡事件

选项卡小部件定义了一系列有用的选项，允许您添加回调函数以在检测到小部件公开的特定事件时执行不同的操作。下表列出了能够在事件上接受可执行函数的配置选项：

| 事件 | 当...时触发 |
| --- | --- |
| `add` | 添加了一个新选项卡。 |
| `disable` | 选项卡已禁用。 |
| `enable` | 选项卡已启用。 |
| `load` | 选项卡的远程数据加载完毕。 |
| `remove` | 移除了一个选项卡。 |
| `select` | 选择了一个选项卡。 |
| `show` | 选项卡显示。 |

库中的每个组件都有回调选项（例如上表中的选项），它们被调整为查找任何访客交互中的关键时刻。我们在这些回调中使用的任何函数通常在更改发生之前执行。因此，您可以从回调中返回 false 并阻止操作发生。

在我们的下一个示例中，我们将看到使用标准非绑定技术如何轻松地对选择的特定选项卡作出反应。将`tabs8.html`中最后的`<script>`元素更改为以下内容：

```js
$(document).ready(function($){
 var handleSelect = function(e, tab) {
 $("<p></p>", {
 text: "Tab at index " + tab.newTab.index() + " selected", 
 "class": "status-message ui-corner-all"
 }).appendTo(".ui-tabs-nav", "#myTabs").fadeOut(5000, function() {
 $(this).remove();
 });
 },
 tabOpts = {
 beforeActivate: handleSelect
 }
 $("#myTabs").tabs(tabOpts);
});
```

将此文件保存为`tabs9.html`。我们还需要一些 CSS 来完成这个示例。在我们刚刚创建的页面的`<head>`中，添加以下`<link>`元素：

```js
<link rel="stylesheet" href="css/tabSelect.css">
```

然后，在文本编辑器的新页面中添加以下代码：

```js
.status-message { padding:11px 8px 10px; margin:0; border:1px solid #aaa; position: absolute; right: 10px; top: 9px; font-size: 11px; background-color: #fff; }
.ui-widget-header { color: #2e6e9e; font-weight: bold; }
```

将此文件保存为`tabSelect.css`，并放在`css`文件夹中。在本示例中，我们在生产环境中链接了多个 CSS 文件；您可能希望考虑将 CSS 合并为一个文件，以减少 CSS HTTP 请求。尽管这将有助于在较大的站点上提高性能，但它的代价是无法替换 jQuery UI CSS 文件，因为您将丢失添加的任何自定义。

在本示例中，我们利用了`beforeActivate`回调来创建一个使用`<p>`标签的新元素，尽管原理对于标签页触发的任何其他自定义事件都是相同的。我们的回调函数名称作为我们配置对象中`beforeActivate`属性的值提供。

当回调函数被执行时，小部件将自动传递两个参数，即原始事件对象和包含从所选标签页中提取的有用属性的自定义对象。

要找出点击了哪个标签页，我们可以查看第二个对象的`index()`属性（请记住这些是从零开始的索引）。这与一些解释性文本一起添加到我们动态创建的段落元素中，并附加到小部件标题中：

![使用标签页事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_05.jpg)

每当选择一个标签页时，它前面的段落就会消失。请注意，事件在更改发生之前被触发。

## 绑定事件

使用每个组件公开的事件回调是处理交互的标准方法。但是，除了前面表中列出的回调之外，我们还可以在每个组件在不同时间点触发的另一组事件中插入钩子。

我们可以使用标准的 jQuery `on()` 方法将事件处理程序绑定到由标签页小部件触发的自定义事件，这与我们可以绑定到标准 DOM 事件（例如点击）的方式相同。

下表列出了标签小部件的自定义绑定事件及其触发器：

| 事件 | 在什么时候触发... |
| --- | --- |
| `tabsselect` | 一个标签页被选中。 |
| `tabsload` | 远程标签页已加载。 |
| `tabsshow` | 显示一个标签页时。 |
| `tabsadd` | 一个标签页已添加到界面中。 |
| `tabsremove` | 一个标签页已从界面中移除。 |
| `tabsdisable` | 一个标签页已被禁用。 |
| `tabsenable` | 一个标签页已被启用。 |

前三个事件按顺序连续触发，即它们在表中出现的事件顺序。如果没有标签页是远程的，那么`tabsbeforeactivate`和`tabsactivate`将按照此顺序触发。这些事件可以在动作发生之前或之后触发，这取决于使用哪个事件。

让我们看看这种事件使用方式的实际效果；将`tabs8.html`中的最后一个`<script>`元素更改为以下内容：

```js
<script>
 $(document).ready(function($){
 $("#myTabs").tabs();
 $("#myTabs").on("tabsbeforeactivate", function(e, tab) {
 alert("The tab at index " + tab.newTab.index() + " was selected");
 });
 });
</script>
```

将此更改保存为`tabs10.html`。通过这种方式绑定到`tabsbeforeactivate`将产生与前一个示例相同的结果，使用`select`回调函数。与上次一样，警报应该在激活新标签页之前出现。

所有小部件公开的所有事件都可以使用`on()`方法，只需将小部件的名称前缀与事件的名称相结合即可。

### 注意

尽管每个回调名称都是使用驼峰格式拼写的，但每个事件名称必须以小写字母书写。

# 使用选项卡方法

选项卡小部件包含许多不同的方法，这意味着它具有丰富的行为集。它还支持实现高级功能，允许我们以编程方式使用它。让我们看一下列在下表中的方法：

| 方法 | 用于... |
| --- | --- |
| `destroy` | 完全移除选项卡小部件。 |
| `disable` | 禁用所有选项卡。 |
| `enable` | 启用所有选项卡。 |
| `load` | 重新加载 AJAX 选项卡的内容，指定选项卡的索引号。 |
| `option` | 在小部件初始化后获取或设置任何属性。 |
| `widget` | 返回调用`tabs()`小部件方法的元素。 |

# 启用和禁用选项卡

我们可以使用`enable`或`disable`方法在程序中启用或禁用特定的选项卡。这将有效地启用最初被禁用的任何选项卡，或者禁用当前处于活动状态的选项卡。

让我们使用`enable`方法来启用默认情况下在早期示例中禁用的选项卡。在`tabs5.html`中现有选项卡小部件的标记之后直接添加以下新的`<button>`元素：

```js
<button type="button" id="enable">Enable</button>
<button type="button" id="disable">Disable</button>
```

接下来，更改最后的`<script>`元素，使其显示如下：

```js
<script>
$(document).ready(function($){
 $("#myTabs").tabs({
 disabled: [1]
 });
 $("#enable").click(function() {
 $("#myTabs").tabs("enable", 1);
 });
 $("#disable").click(function() {
 $("#myTabs").tabs("disable", 1);
 });
});
</script>
```

将更改后的文件保存为`tabs11.html`。在页面上，我们添加了两个新的`<button>`元素——一个用于启用被禁用的选项卡，另一个用于再次禁用它。

在 JavaScript 中，我们使用**启用**按钮的`click`事件调用`tabs()`小部件方法。为此，我们将字符串`enable`作为第一个参数传递给`tabs()`方法。此外，我们将要启用的选项卡的索引号作为第二个参数传递。jQuery UI 中的所有方法都是这样调用的。我们将要调用的方法的名称指定为小部件方法的第一个参数。`disable`方法的使用方式相同。不要忘记，我们可以在不需要额外参数的情况下使用这两种方法，以启用或禁用整个小部件。

# 添加和移除选项卡

除了在程序中启用和禁用选项卡之外，我们还可以在运行时删除它们或添加全新的选项卡。在`tabs11.html`中，删除现有的`<button>`元素，并添加以下内容：

```js
<label>Enter a tab to remove:</label>
<input for="indexNum" id="indexNum">
<button type="button" id="remove">Remove!</button>
<button type="button" id="add">Add a new tab!</button>
```

然后按以下方式更改最后的`<script>`元素：

```js
<script>
  $(document).ready(function($){
 $("#myTabs").tabs();
 $("#remove").click(function() {
 var indexTab = parseInt($("#indexNum").val(), 10);
 var tab = $("#myTabs").find(".ui-tabs-nav li:eq(" + indexTab + ")").remove();
 $("#myTabs").tabs("refresh");
 });
 $("#add").click(function() {
 $("<li><a href='remoteTab.txt'>New Tab</a></li>") .appendTo("#myTabs .ui-tabs-nav");
 $("#myTabs").tabs("refresh");
 });
  });
</script>
```

我们还需要提供一些内容，这些内容将被远程加载到选项卡中——在一个新文件中，添加`远程选项卡内容！`，并将其保存为`remoteTab.txt`。

将此保存为`tabs12.html`——要预览此示例，您将需要使用诸如**WAMP**（用于 Windows）或**MAMP**（用于苹果 Mac）之类的本地 Web 服务器查看它。如果使用文件系统访问，演示将无法工作。

在页面上，我们添加了一个新的指令`<label>`，一个`<input>`和一个`<button>`，用于指定要移除的选项卡。我们还添加了第二个`<button>`，用于添加一个新选项卡。

在`<script>`中，我们的第一个新函数处理删除选项卡，使用`remove`方法。此方法使用 jQuery 的`:eq()`函数查找要删除的选项卡的索引。我们获取输入到文本框中的值，并使用索引标识要删除的选项卡，然后使用`refresh`方法更新 Tabs 的实例。

### 注意

jQuery 的`val()`方法返回的数据格式为字符串，因此我们将调用包装在 JavaScript 的`parseInt`函数中以进行转换。

`add`方法用于向小部件添加新选项卡，其工作原理类似。在这里，我们创建了一个列表项的实例，然后使用 jQuery 的`appendTo()`方法将其添加到现有的选项卡中并更新它们。在此示例中，我们指定应将`remoteTab.txt`文件中的内容添加为新选项卡的内容。可选地，我们还可以将新选项卡应插入的索引号指定为第四个参数。如果未提供索引，则新选项卡将添加为最后一个选项卡。

添加并可能移除一些选项卡后，页面应该如下所示：

![添加和删除选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_06.jpg)

# 模拟点击

有时您可能需要以编程方式选择特定的选项卡并显示其内容。这可能是由于访问者的某些其他交互而发生的。

我们可以使用`option`方法来执行此操作，该方法与单击选项卡的操作完全类似。将`tabs12.html`中的最后一个`<script>`块更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#myTabs").tabs();
    $("#remove").click(function() {
      var indexTab = parseInt($("#indexNum").val(), 10);
      var tab = $( "#myTabs" ).find(".ui-tabs-nav li:eq(" + indexTab + ")").remove();
      $("#myTabs").tabs("refresh");
    });
    $("#add").click(function() {
      $("<li><a href='remoteTab.txt'>New Tab</a></li>").appendTo("#myTabs .ui-tabs-nav");
      $("#myTabs").tabs("refresh");
 var tabCount = $("#myTabs ul li").length;
 $("#myTabs").tabs("option", "active", tabCount - 1);
    });
 });
</script>  
```

将此保存为`jqueryui`文件夹中的`tabs13.html`。现在当添加新选项卡时，它将自动选中。`option`方法需要两个额外的参数：第一个是要使用的选项的名称，第二个是要设置为活动状态的选项卡的 ID。

由于默认情况下（尽管可以更改），我们添加的任何选项卡都将是界面中的最后一个选项卡，并且由于选项卡索引是从零开始的，因此我们只需使用`length`方法返回选项卡的数量，然后从该数字中减去 1 以获取索引。结果传递给`option`方法。

有趣的是，立即选择新添加的选项卡会修复，或者至少隐藏，来自上一个示例的额外空间问题。

# 销毁选项卡

如前所示，我们可以轻松添加选项卡，但在某些情况下，您可能需要完全销毁一组选项卡。这可以使用`destroy`方法来实现，该方法对 jQuery UI 中找到的所有小部件都是通用的。让我们看看它是如何工作的。在`tabs13.html`中，立即删除现有的标记，然后添加一个新的`<button>`如下所示：

```js
<br>
<button type="button" id="destroy">Destroy the tabs</button>

```

接下来，将最后一个`<script>`元素更改为：

```js
<script>
 $(document).ready(function($){
 $("#myTabs").tabs();
 $("#destroy").click(function() {
 $("#myTabs").tabs("destroy");
 });
 });
</script> 

```

将此文件保存为`tabs14.html`。我们通过单击按钮调用的`destroy`方法完全删除了选项卡小部件，将底层 HTML 返回到其原始状态。单击按钮后，您应该会看到一个标准的 HTML 列表元素和来自每个选项卡的文本，类似于以下屏幕截图：

![销毁选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_07.jpg)

### 注意

如果销毁选项卡，则页面中硬编码的原始选项卡将保留，而不会保留使用`add`方法添加的选项卡。

# 获取和设置选项

像`destroy`方法一样，`option`方法由库中找到的所有不同组件公开。此方法用于在获取器模式和设置器模式下使用可配置选项和函数。让我们看一个基本示例；在`tabs9.html`中的选项卡小部件之后添加以下`<button>`：

```js
<button type="button" id="show">Show Selected!</button>
```

然后更改最后的`<script>`元素，使其如下所示：

```js
<script>
$(document).ready(function($){
 $("#myTabs").tabs();
 $("#show").click(function() {
 $("<p></p>", {
 text: "Tab at index " + $("#myTabs").tabs("option", "active") + " is active"
 }).appendTo(".ui-tabs-nav").fadeOut(5000);
 });
});
</script>
```

我们还需要调整所显示文本的位置，因此从现有代码中删除到`tabSelect.css`的链接，并在`<head>`部分中添加以下内容：

```js
  <style type="text/css">
    ul.ui-tabs-nav p { margin-top: 2px; margin-left: 210px;}
  </style>
```

将此文件保存为`tabs15.html`。页面上的`<button>`已更改，因此它显示当前活动的选项卡。我们所做的就是向状态栏消息中添加所选选项卡的索引，就像我们在早期示例中所做的那样。我们通过将字符串`active`作为第二个参数传递来获取`active`选项。可以以这种方式访问任何选项的任何值。

### 注意

**链接 UI 方法**

链接小部件方法（与其他 UI 方法或核心 jQuery 方法一起）是可能的，因为与底层 jQuery 库中的方法一样，它们几乎总是返回 jQuery（$）对象。请注意，当使用返回数据的获取器方法时，例如`length`方法时，这是不可能的。

要触发设置器模式，我们可以提供包含我们想要设置的选项的新值的第三个参数。因此，要更改`active`选项的值，以更改显示的选项卡，我们可以使用以下 HTML，而不是，为此，请按照以下所示更改 HTML，在`tabs15.html`底部：

```js
<br>
<label for="newIndex">Enter a tab index to activate</label>
<input id="newIndex" type="text">
<button type="button2" id="set">Change Selected</button>

```

接下来，按照所示添加点击处理程序：

```js
<script>
  $(document).ready(function($){
    $("#myTabs").tabs();
 $("#set").click(function() {
 $("#myTabs").tabs("option", "active", parseInt($("#newIndex").val()));
 });
  });
</script>
```

将此保存为`tabs16.html`。新页面包含一个`<label>`，一个`<input>`，以及一个用于获取应将`active`选项设置为的索引号的`<button>`。单击按钮时，我们的代码将检索`<input>`的值并使用它来更改所选索引。通过提供新值，我们将该方法置于设置器模式中。

当我们在浏览器中运行此页面时，我们应该看到，通过将其索引号输入为`1`并单击**更改所选**按钮，我们可以切换到第二个选项卡。

# 使用 AJAX 选项卡

我们看到了如何使用 `add` 方法将 AJAX 选项卡动态添加到小部件中，但我们也可以使用底层 HTML 添加远程内容到选项卡。在此示例中，我们希望始终可用于显示远程内容的选项卡，并不仅限于点击按钮后。这个示例也只能在已安装和配置了 PHP 的完整 Web 服务器上正确运行，例如 WAMP（PC）或 MAMP（Macs）。

在 `tabs16.html` 中的小部件的基础 HTML 中添加以下新的 `<a>` 元素：

```js
<li><a href="remoteTab.txt">AJAX Tab</a></li>
```

我们还应该从最后一个示例中移除 `<button>`。

最终的 `<script>` 元素可用于调用 `tabs` 方法；不需要额外的配置：

```js
$("#myTabs").tabs();
```

将其保存为 `tabs17.html`。我们所做的只是使用底层标记中 `<a>` 元素的 `href` 属性指定远程文件的路径（与我们在早期示例中使用的相同），从中创建选项卡。

与静态选项卡不同，我们不需要一个与链接的 `href` 匹配的 `<div>` 元素和 `id`。选项卡内容所需的附加元素将由小部件自动生成。

如果您使用 DOM 浏览器，您会发现我们添加的链接到远程选项卡的文件路径已被删除。相反，一个新的片段标识符已生成并设置为 `href`。新的片段也添加为新选项卡的 `id`（当然，不包括 `#` 符号），以便选项卡标题仍然显示选项卡。

除了从外部文件加载数据外，还可以从 URL 加载数据。当使用查询字符串或 Web 服务从数据库检索内容时，这非常有用。与 AJAX 选项卡相关的方法包括 `load` 和 `url` 方法。`load` 方法用于加载和重新加载 AJAX 选项卡的内容，这在需要频繁刷新内容的情况下非常有用。

### 注意

在选项卡小部件的 AJAX 功能中没有内在的跨域支持。因此，除非额外使用 PHP 或其他服务器脚本语言作为代理，否则您可能希望利用 **JavaScript Object** **Notation** (**JSON**) 结构化数据和 jQuery 的 JSONP 功能。文件和 URL 应位于运行小部件的页面的同一域下。

# 更改远程选项卡内容的 URL

`url` 方法用于更改 AJAX 选项卡检索其内容的 URL。让我们看看这两种方法在实际中的简要示例。还有一些与 AJAX 功能相关的属性。

在 `tabs17.html` 中的 Tabs 小部件后添加以下新的 `<select>` 元素：

```js
<select id="fileChooser">
  <option value="remoteTab1.txt">remoteTab1</option>
  <option value="remoteTab2.txt">remoteTab2</option>
</select>
```

然后将最终的 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#myTabs").tabs();
    $("#fileChooser").change(function() {
      $("#myTabs").tabs("option", "active", "2");
      $("#myTabs").find("ul>li a").attr("href", $(this).val());
      $("#myTabs").tabs("load", "active");
    });
  });
</script>
```

将新文件保存为 `tabs18.html`。我们在页面中添加了一个简单的 `<select>` 元素，让您可以选择在 AJAX 选项卡中显示的内容。在 JavaScript 中，我们为 `<select>` 设置了一个 change 处理程序，并指定了在每次检测到事件时要执行的匿名函数。

此函数首先设置活动选项卡；在本例中为 AJAX 选项卡，其 ID 为 2 - 然后使用 jQuery 的 `find()` 方法设置选项卡面板的 `href` 属性，然后使用 `load()` 方法将内容插入选项卡中。

我们还需要一个第二个本地内容文件。更改 `remoteTab1.txt` 文件中的文本，并将其另存为 `remoteTab2.txt`。

在浏览器中运行新文件，并使用 `<select>` 下拉列表选择第二个远程文件，然后切换到远程选项卡。第二个文本文件的内容应该会显示出来。

# 通过 JSONP 显示获取的数据

对于我们的最后一个示例，让我们为最后的选项卡示例拉取一些外部内容。如果我们使用选项卡小部件，结合标准的 jQuery 库的 `getJSON` 方法，我们可以绕过跨域排除策略，并从另一个域中拉取源，以在选项卡中显示。在 `tabs19.html` 中，将选项卡小部件更改为如下所示：

```js
<div id="myTabs">
 <ul>
 <li><a href="#a"><span>Nebula Information</span></a></li>
 <li><a href="#flickr"><span>Images</span></a></li>
 </ul>
 <div id="a">
 <p>A nebulae is an interstellar cloud of dust, hydrogen gas, and plasma. It is the first stage of a star's cycle. In these regions the formations of gas, dust, and other materials clump together to form larger masses, which attract further matter, and eventually will become big enough to form stars. The remaining materials are then believed to form planets and other planetary system objects. Many nebulae form from the gravitational collapse of diffused gas in the interstellar medium or ISM. As the material collapses under its own weight, massive stars may form in the center, and their ultraviolet radiation ionizes the surrounding gas, making it visible at optical wavelengths.</p>
 </div>
 <div id="flickr"></div>
</div>
```

接下来，将最后的 `<script>` 更改为以下内容：

```js
<script>
  $(document).ready(function($){
    var img = $("<img/>", {
      height: 100,
      width: 100
    }),
  tabOpts = {
  beforeActivate: function(event, ui) { 
    $('#myTabs a[href="#flickr"]').parent().index() != -1 ? getData() : null;
    function getData() {
      $("#flickr").empty();
      $.getJSON("http://api.flickr.com/services/feeds/photos_public.gne?tags=nebula&format=json&jsoncallback=?", function(data) {
          $.each(data.items, function(i,item){
            img.clone().attr("src", item.media.m) .appendTo("#flickr");
            if (i == 5) {
              return false;
            }
          });
        });
      }
    }
  };
  $("#myTabs").tabs(tabOpts);
});
</script>
```

将文件保存为 `tabs19.html` 到你的 `jqueryui` 文件夹中。我们首先创建一个新的 `<img>` 元素并将其存储在一个变量中。我们还创建一个配置对象并向其添加 `select` 事件选项。每当选中一个标签时，我们设置为该选项值的函数将检查是否选中了一个具有 `id` 为 `flickr` 的标签。如果是，则使用 jQuery 的 `getJSON` 方法从 [`www.flickr.com`](http://www.flickr.com) 检索图像源。

数据返回后，首先清空**Flickr**标签的内容，以防止图像堆积，然后使用 jQuery 的 `each()` 实用方法来迭代返回的 JSON 中的每个对象，并创建我们存储的图像的克隆。

每个图像的新副本都使用当前 feed 对象的信息设置其 `src` 属性，然后添加到空的**Flickr**标签中。一旦对 feed 中的六个对象进行了迭代，我们就退出了 jQuery 的 `each` 方法。就是这么简单。

当我们查看页面并选择**图像**选项卡后，经过短暂的延迟，我们应该会看到六张新图像，如下面的截图所示：

![通过 JSONP 显示获取的数据](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_03_08.jpg)

# 摘要

选项卡小部件是一种极好的节省页面空间的方法，通过将相关（甚至完全不相关）的内容部分组织起来，可以通过访问者的简单点击输入来显示或隐藏。它还为您的网站增添了一种交互性，可以帮助改善所使用的页面的整体功能和吸引力。

让我们回顾一下本章涵盖的内容。我们首先看了一下如何只需一点点的基本 HTML 和一行 jQuery 风格的 JavaScript，就可以实现默认的选项卡小部件。

然后，我们看到了添加自己的基本样式到标签页小部件是多么容易，这样可以改变它的外观，但不改变它的行为。我们已经知道，除此之外，我们可以使用预设计的主题或使用 ThemeRoller 创建全新的主题。

然后，我们继续研究了标签页 API 公开的一系列可配置选项。借助这些选项，我们可以启用或禁用小部件支持的不同选项，例如标签页是通过单击还是其他事件选择的，以及在小部件呈现时是否禁用某些标签页。

我们花了一些时间研究如何使用一系列预定义的回调选项，允许我们在检测到不同事件时执行任意代码。我们还看到，如果需要，jQuery 的`on()`方法可以监听相同的事件。

在可配置选项之后，我们介绍了一系列方法，可以通过编程方式使标签页执行不同的操作，例如模拟对标签页的点击，启用或禁用标签页，以及添加或删除标签页。

我们简要地了解了标签页小部件支持的一些更高级功能，如 AJAX 标签页，以及使用 JSONP 获取信息。这两种技术都很容易使用，并且可以为任何实现增加价值。

在下一章中，我们将继续研究**手风琴**小部件，类似于标签页小部件，用于将内容分组到相关部分，一次显示一个部分。
