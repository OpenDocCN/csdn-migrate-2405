# HTML5 和 CSS3 移动优先设计（一）

> 原文：[`zh.annas-archive.org/md5/8E3F0E6C99133E9B96FC8EF78A0D3F0F`](https://zh.annas-archive.org/md5/8E3F0E6C99133E9B96FC8EF78A0D3F0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

构建能够在从支持网络的智能手机到平板电脑、笔记本电脑和台式机上显示良好的网站是一个艰巨的挑战。屏幕尺寸和浏览器类型的多种组合可能足以成为不去尝试的理由。但是，如果您的业务依赖于将网络内容传递给这些设备上的人，并且您需要您的业务看起来技术先进，那么您必须尽力而为。在这本书中，您将看到，借助一些易于理解的原则和开源框架的帮助，您可以快速构建一个移动优先的响应式网站。

# 本书涵盖的内容

第一章，“移动优先-如何以及为什么？”，快速介绍了移动优先策略。

第二章，“构建主页”，直接构建您网站的面貌和其余网站的基础。

第三章，“构建画廊页面”，构建一个响应式页面来展示您的作品。

第四章，“构建联系表单”，让潜在客户可以从任何屏幕尺寸的设备上联系您。

第五章，“构建关于我页面”，创建一个引人注目的响应式页面，帮助人们了解你。

附录 A，“HTML5 Boilerplate 的解剖”，概述了 HTML5 Boilerplate，包括元标记和脚本。

附录 B，“使用 CSS 预处理器”，帮助您学习 CSS 预处理器的基础知识以及如何使用它们。

# 您需要为本书做好准备

您应该有 Windows 或 Linux。本书中的说明更偏向于 Mac OS X 和 Linux，但在大部分情况下，我们只会编写纯文本并使用极少的命令行工具。在我们使用命令行工具的地方，我已尽力提供如何在 Windows 计算机上获得类似结果的资源。您还应该有一个文本编辑器。如果您知道如何启动和使用命令行工具，将会非常有帮助。

# 这本书适合谁

如果您对响应式设计以及它如何帮助提供可用的网络界面（从手机到台式电脑）感到好奇或兴奋，那么本书适合您。

在技术技能方面，本书面向初学者到中级开发人员以及设计师。换句话说，您应该已经知道如何构建 HTML 页面，并使用某种文本编辑器对其进行样式设置。不过，您不必是这些方面的专家。您也不需要成为命令行专家，但希望您愿意使用命令行工具。它们非常有帮助。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“当浏览器对`screen`和`min-width 768px`都回答是，就满足了在该媒体查询中应用样式的条件。”

代码块设置如下：

```html
<!DOCTYPE html>
  <head>
    <link rel="stylesheet" href="css/main.css">
  </head>
  <body>
    <button class="big-button">Click Me!</button>
  </body>
</html>
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中出现，如：“我已经创建了指向尚不存在的页面的链接，所以如果您点击它们，您将收到**404 文件未找到**的消息。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：移动优先 - 如何以及为什么？

如果你从事为公司建立/维护网站或为代理机构建立网页属性的业务，你可以并且应该使用移动优先策略。为什么？因为这对你的最终产品有价值。你最终会得到一个被大多数人在所有可能的设备和浏览器上使用的网站。

这本书面向初学者和中级开发人员以及设计师。它还面向那些希望更深入了解现代工具和网页策略可能性（以及由此可能不切实际的内容）的商业和管理人员。本书中的代码示例，按步骤使用，应该帮助任何具有基本开发技能的人更深入地了解可能性以及如何实现可能性。当然，我喜欢每天都建造东西，但对于我们这些还必须制定策略并教育客户和同事的人来说，掌握如何制作移动优先网站的程序知识比仅掌握理论和概念知识更有价值。

# 什么是响应式网页设计？

**响应式网页设计**（**RWD**）是一组用于在不同尺寸屏幕上显示网页的策略。这些策略利用了现代浏览器中可用的功能，以及渐进增强策略（而不是优雅降级）。这些术语是什么意思？好吧，一旦我们深入了解程序和代码，它们就会变得更有意义。但这里有一个快速示例，用来说明 RWD 中使用的双向渐进增强。

假设你想要制作一个漂亮的按钮，它是一个大目标，可以可靠地被大而笨拙的拇指按下，在各种移动设备上都可以。事实上，你希望这个按钮几乎可以在人类所知的每一种移动设备上运行。这不是问题。以下代码是你（大大简化的）HTML 的样子：

```html
<!DOCTYPE html>
  <head>
    <link rel="stylesheet" href="css/main.css">
  </head>
  <body>
    <button class="big-button">Click Me!</button>
  </body>
</html>
```

以下代码是你的 CSS 的样子：

```html
.big-button {
  width: 100%;
  padding: 8px 0;
  background: hotPink;
  border: 3px dotted purple;
  font-size: 18px;
  color: #fff;
  border-radius: 20px;
  box-shadow: #111 3px 4px 0px;
}
```

### 提示

**下载示例代码**

你可以从你在[`www.PacktPub.com`](http://www.PacktPub.com)账户中购买的所有 Packt 图书中下载示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，将文件直接发送到你的邮箱。

因此，这会让你得到一个可以延伸到文档主体宽度的按钮。它还是热粉色的，带有点状紫色边框和厚重的黑色阴影（不要评判我的设计选择）。

这段代码的好处在于什么。让我们用一些想象中的设备/浏览器来解释一下第一段中的一些术语：

+   设备一（代号：Goldilocks）：这个设备有一个现代浏览器，屏幕尺寸为 320 x 480 像素。它经常更新，所以很可能拥有你在喜爱的博客中读到的所有酷炫的浏览器功能。

+   设备二（代号：小熊宝宝）：这个设备有一个部分支持 CSS2 并且文档不完善的浏览器，以至于你只能通过试错或论坛来确定支持哪些样式。屏幕尺寸为 320 x 240 像素。这描述了一个在移动设备上浏览网页的现代采用水平之前的设备，但你的使用情况可能需要你支持它。

+   设备三（代号：Papa Bear）：这是一台带有现代浏览器的笔记本电脑，但你永远不会知道屏幕尺寸，因为视口大小由用户控制。

因此，Goldilocks 得到以下显示：

![什么是响应式网页设计？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_01_01.jpg)

因为它装饰了完整的 CSS3 功能，它将呈现圆角和阴影。

![什么是响应式网页设计？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_01_02.jpg)

另一方面，小熊宝宝只会得到方形边角，没有阴影（如前面的屏幕截图中所示），因为它的浏览器无法理解这些样式声明，也不会对其进行任何操作。不过，这并不是什么大问题，因为你仍然可以得到按钮的重要功能；它可以延伸到屏幕的整个宽度，成为全世界所有拇指的大目标（而且它仍然是粉色的）。

大熊宝宝也得到了所有 CSS3 的好东西。

![什么是响应式网页设计？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_01_03.jpg)

也就是说，无论用户将浏览器调整到多宽，它都会延伸到整个浏览器的宽度。我们只需要它宽约 480 像素，这样用户就可以点击它，并且在我们想象的任何设计中看起来合理。因此，为了实现这一点，我们将利用一个称为`@media`查询的巧妙的 CSS3 功能。我们将在本书中广泛使用这些功能，并使您的样式表看起来像这样：

```html
.big-button {
  width: 100%;
  padding: 8px 0;
  background: hotPink;
  border: 3px dotted purple;
  font-size: 18px;
  color: #fff;
  border-radius: 20px;
  box-shadow: #111 3px 3px 0px;
}

@media only screen and (min-width: 768px){
  .big-button { 
    width: 480px;
  }
}
```

现在，如果您正在和我一起编码，并且有一个现代浏览器（意思是浏览器支持 HTML5 规范中的大多数，如果不是全部功能，稍后会详细介绍），您可以做一些有趣的事情。您可以调整浏览器的宽度，看看开始按钮如何响应`@media`查询。从浏览器非常窄的情况开始，按钮会变宽，直到屏幕宽度达到 768 像素；超过这个宽度，按钮将会变为只有 480 像素。如果您的浏览器宽度超过 768 像素，按钮将保持 480 像素宽，直到浏览器宽度小于 768 像素。一旦低于这个阈值，按钮就会变为全宽。

这是因为媒体查询的原因。这个查询基本上是在问浏览器几个问题。查询的第一部分是关于媒介类型是什么（打印还是屏幕）。查询的第二部分是询问屏幕的最小宽度是多少。当浏览器对`screen`和`min-width 768px`都回答是时，就满足了应用媒体查询内样式的条件。说这些样式被应用了有点误导。事实上，这种方法实际上利用了媒体查询中提供的样式可以覆盖样式表中先前设置的其他样式的事实。在我们的情况下，唯一应用的样式是一个显式宽度的按钮，它覆盖了先前设置的百分比宽度。

因此，这种方法的好处是，我们可以制作一个网站，可以适应很多屏幕尺寸。这种方法可以重复使用很多代码，只在需要时应用不同屏幕宽度的样式。其他让可用网站适应移动设备的方法需要维护多个代码库，并且必须识别设备，这只有在实际检测到请求网站的设备时才有效。这些其他方法可能很脆弱，也违反了编程中的“不要重复自己”（DRY）原则。

不过，本书将介绍一种特定的 RWD 方法。我们将使用**320 and Up**框架来实现移动优先策略。简而言之，这种策略假设请求网站的设备具有小屏幕，并且不一定具有很强的处理能力。320 and Up 还有很多很好的辅助功能，可以快速轻松地为客户的网站提供许多所需的功能。但是，当我们一起建立一个简单的网站时，我们将详细介绍这些细节。

### 注意

请注意，有很多框架可以帮助您构建响应式网站，甚至有一些可以帮助您构建响应式的移动优先网站。320 and Up 的一个特点是它比大多数框架更少地表达观点。我喜欢它，因为它简单，消除了为许多网站设置可能使用的繁琐工作。我还喜欢它是开源的，可以与静态网站以及任何服务器端语言一起使用。

# 先决条件

在我们开始构建之前，您需要下载与本书相关的代码。它将包含您所需的所有组件，并且已经为您正确地进行了结构化。如果您想要为自己的项目使用 320 and Up，您可以从*Andy Clarke*的网站（他是 320 and Up 的负责人）或他的 GitHub 账户上获取。我也在我的 GitHub 仓库中维护了一个分支。

## 安迪·克拉克的网站

[`stuffandnonsense.co.uk/projects/320andup/`](http://stuffandnonsense.co.uk/projects/320andup/)

## GitHub

[`github.com/malarkey/320andup`](https://github.com/malarkey/320andup)

## 我的 GitHub 分支

[`github.com/jasongonzales23/320andup`](https://github.com/jasongonzales23/320andup)

也就是说，跟随本书的最简单方法是从这里获取我为您打包好的代码：[`github.com/jasongonzales23/mobilefirst_book`](https://github.com/jasongonzales23/mobilefirst_book)

# 摘要

在本章中，我们看了一个简单的例子，展示了响应式网页设计策略如何为许多不同尺寸的屏幕提供相同的内容，并使布局根据显示屏进行调整。我们为一个粉色按钮写了一个简单的例子，并获得了一个指向 320 and Up 的链接，因此我们可以开始构建一个完整的移动优先响应式网站。


# 第二章：构建主页

在这一章中，我们将开始使用 320 and Up 框架，立即开始构建我们示例作品网站的主页。我们将从一些基础知识开始，了解特定代码放在哪里以及为什么。然后我们将快速转移到构建我们的页面，包括作品主页的许多典型元素：导航、主页/幻灯片和三个内容面板。如果你不知道这些术语的含义，不要担心，你很快就会知道的！

如果你已经成功下载并解压了第一章结尾处的链接中的所有代码，*移动优先-如何以及为什么？*，你已经准备好了。如果没有，请返回并使用链接下载示例代码。

# 准备和规划你的工作空间

每个人都有自己喜欢的代码存放方法和组织方式，网页开发中有很多关于组织的惯例，了解这些惯例是很好的。如果你有自己喜欢的工作流程，尤其是从教程中获取代码的工作流程，请继续使用。但是对于那些没有喜好的人，我建议你把下载的代码放在一个工作目录中，你可以在那里保存（或计划保存）所有的网页项目。我通常把所有的网页代码放在一个名为`work`的目录中。所以在 Unix 或 Mac OS X 机器上，它看起来是这样的：

```html
~/work/320-and-up

```

关于放置代码的一些建议。如果你使用这本书特别是为了构建你想要部署和使用的东西，你可能只想使用示例代码作为参考，并仅使用 320 and Up 框架提供的文件来构建你的项目。但是，请确保你把所有这些放在一个名为 320 and Up 之外的目录中。

无论你如何进行，我都会在每一章提供之前和之后的代码，这样你就可以有一个模板来开始，也可以看到我们在本章结束时将会得到的最终产品的示例。如果你刚开始并且对此感到困惑，只需复制代码并进行编辑。如果以后需要，你可以随时下载一个新的副本。

如果你查看`ch2`目录，你应该会看到两个文件夹`before`和`after`。从现在开始，我假设你会选择最简单的方式直接编辑`before`文件。但是请按照你喜欢的方式继续。

继续前往或查看`before`目录。你会看到我从 Andy Clarke 的 GitHub 仓库（`repo`）克隆下来的`320andup`文件夹。我所做的就是通过输入以下命令行来切换到`before`目录：

```html
$ cd before

```

然后我从仓库克隆了代码：

`git clone git@github.com:malarkey/320andup.git`

如果你不想去研究这些，就直接使用我提供的代码。我只是想让你知道我是如何把代码放在那里的。

一旦你查看了`320andup`文件夹的内容，你会看到很多文件。不要感到压力。我会在我们进行时解释我们正在使用的内容。而且我们有些文件根本不会用到。如果你要部署这些代码，我鼓励你进行某种生产过程，只部署你真正需要的代码。不过，这本书的范围超出了这一点，因为我们将专注于构建。

## 提前规划

我知道你可能很兴奋地开始编写一些代码，但首先我们需要对我们将要构建的内容进行一些规划。当我准备构建一个网站时，这是我首先要做的，这样我就有了一个构建代码的参考。这是一个好的实践；你不想随意尝试。但是当你构建一个响应式网站时，情况也会变得更加复杂。

也就是说，这是我们将遵循的每个页面的公式：

1.  描述我们想要的页面元素及其层次结构。

1.  为我们需要编码的所有不同屏幕尺寸的页面元素（称为**线框图**）绘制一些简单的图片。

1.  为 320 像素宽的屏幕编写一些代码（并提前考虑）。

1.  为我们需要编码的其他屏幕尺寸编写一些代码。

让我们从第一步开始。我们的作品集网站首页将包括以下元素：

+   导航菜单

+   主页/幻灯片

+   内容面板三合一

+   页脚

这是一个相当有效的作品集网站页面布局，但对于公司网站也同样有效。在设计页面之前，我们应该花一点时间以一种非常抽象的方式规划页面内容会是什么样子。通常，最好的表示方法是用线框图。线框图应该显示内容放置在页面上的位置以及相对大小。这是我们的网站作为台式机布局的样子：

![提前规划](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_02_03.jpg)

我很快就在 Photoshop 中制作了那张图片，但你可以在任何图片编辑器中轻松完成（事实上，我和许多同事都非常喜欢使用简单的协作图片编辑器，比如 Google Drive 中的编辑器）。如果你正在制作与这个示例不同的东西，你可能想现在花点时间制作你自己的图片。

在这个阶段，重要的是暂时不要考虑尺寸（但很快会考虑），而是考虑每种内容类型，并评估它对网站目的的重要性。这个作品集网站的目的是展示我们的作品，以便我们能够被雇佣。为了实现这一目标，我们决定有一个主页、一个画廊页面、一个联系表格和一个**关于我**页面。并不是开创性的，但相当有效。接下来，让我们看看主页如何支持网站的目的。

### 导航

在首页上，导航区将链接到我在上一节中列出的那些页面：

+   **标志**

+   **首页**

+   **画廊**

+   **联系**

+   **关于我**

### 主页/幻灯片

这个区域很大，很吸引人。让我们计划在这里放一些大胆的图片和/或文本，以吸引人们去浏览我们想要突出的画廊作品以及联系表格。

### 内容面板

这些区域应该突出网站的目的。我认为这些区域是为那些愿意往下滚动的人准备的。换句话说，愿意往下滚动的人是好奇的，我们应该为他们提供有关网站目的的更多细节。例如，我的内容可能突出三个技能领域：前端工程、用户体验和视觉设计。由于我主要是前端工程师，它是最优先的；其次是用户体验，最后是视觉设计。虽然在台式机或较大的平板电脑上可以同时看到这三个，但在较小的平板电脑和手机上，我们无法舒适地同时看到这三个。

对于你自己，仔细考虑一下你想要突出的三个领域。通常会将一个面板专门用于社交媒体整合。无论你决定了什么，确保它提供更多细节，而不仅仅是重复页面上相同的内容。

### 页脚

页脚将有一个简短的声明和一个顶部的链接，目的是返回主导航。特别是在手机上，有一个返回顶部的链接是非常重要的。在移动设备上，我们需要为用户提供一种方便的方式，让他们能够从页面顶部导航到底部，而不必手动滚动。

好的，现在我们已经对我们的内容进行了优先排序和分类，但你应该已经注意到线框图中的一个问题。我从台式机视图开始，但这本书主要是关于首先为手机设计，对吧？我之所以首先制作那个线框图，是因为我假设大多数读者在转向移动设计之前已经设计过台式机页面。事实上，只设计台式机视图是很常见的！从现在开始，我们将严格专注于首先设计手机。我保证！

因此，知道我们的内容是什么，现在我们需要制作一个适用于移动设备的布局。首先，我会向您展示我认为我们的布局应该是什么，然后解释原因。就是这样：

![页脚](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_02_04.jpg)

请注意，我们必须考虑地址栏和工具栏。请记住，我们不仅仅是为 iPhone 设计。我只是以它作为一个快速的例子，主要是因为它对很多人来说很熟悉。重点是，在移动设备上，您不仅要处理小屏幕，而且甚至不能指望获得所有小屏幕，因为大多数移动网络浏览器需要一些地址和工具栏的“chrome”。有一些事情我们可以做来尝试重新获得那个空间，但稍后再说。现在，我们需要做一个悲观的假设来规划我们的布局。如果我们以目前非常流行的 iPhone 4/4S 的移动 Safari 浏览器为例，我们只有 320 像素乘以 376 像素可用，因为我们使用 60 像素用于地址栏和 44 像素用于工具栏。iPhone 5 的高度要高大约 88 像素。再次重申，我们不仅仅是为 iPhone 设计。我们主要是看这个例子来说明一个观点——您不能保证在视口中放入大量内容。

实际上，看起来我们只能放一个导航栏和主要内容。最好确保英雄/幻灯片中的内容有意义！在本书中，我们不会过多关注内容策略，因为有很多其他更有经验的人在这方面；然而，让我们尽力在那里放一些精心选择的内容。

也就是说，我们仍然可以包括所有其他内容；它们现在只是看不见。如果用户向下滚动，他们仍然应该能够看到三个内容面板，而不是沿页面宽度展开。向下滚动的用户应该看到这个：

![页脚](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_02_05.jpg)

如果用户继续向下滚动，他们将看到第三个面板，最终是页脚。重申一下，当他们滚动到页脚时，从这里轻松访问站点导航可能会非常有帮助。

好的，我打赌您迫不及待地想要编写一些代码并构建！既然我们知道我们要构建什么，现在我们可以做到。由于 320 像素宽的屏幕需要所有内容填充屏幕的宽度，并且所有主要块都需要堆叠，HTML 和 CSS 代码将非常简单！

继续打开`320andup`目录中的`index.html`文件；或者按照代码示例打开此路径中的文件：

`ch2/before/320andup/index.html`

我们将快速浏览一下浏览器中的这个页面，然后我们将更改它以添加我们自己的内容。继续以您喜欢的方式在浏览器中查看此文件。我更喜欢使用 Python 简单的 HTTP 服务器（请参阅以下提示）。但由于我们只是在处理静态站点，您可以双击文件，甚至将其拖入浏览器窗口。

### 提示

**Python 简单 HTTP 服务器**

我不想太偏向 Mac OS X，但如果您使用 Mac，这将很容易。如果您使用其他*nix 操作系统，这仍然会很容易。如果您使用 Windows，这将需要更多的工作；然而，这可能是值得的。

在 Mac 上启动 Python 简单服务器，您只需通过命令行浏览到要提供给浏览器的目录，然后键入：

```html
python –m SimpleHTTPServer

```

如果使用其他*nix 操作系统，您可能需要使用软件包管理器安装 Python，然后运行上述命令。对于 Windows，您需要从[`www.python.org/getit/`](http://www.python.org/getit/)安装它。按照说明进行操作，然后使用命令行运行相同的命令。

对于熟悉 WAMP/MAMP 解决方案的人，您可能希望使用它们。您可以在以下位置找到它们：

+   [`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html)

+   [`www.mamp.info/en/index.html`](http://www.mamp.info/en/index.html)

我强烈建议你使用最先进的浏览器，比如 Chrome 或 Firefox，在本书中我们将要做的工作中，它们有非常有用的开发工具，可以帮助你了解你的代码发生了什么。开发工具使你更容易理解事物是如何工作的，以及如何解决问题。事实上，我们将要使用的许多功能只在现代浏览器中可用。所以如果你还没有，去下载一个；它们都是免费且易于安装的。就我个人而言，我的主要开发浏览器是 Chrome。

好的，一旦你在浏览器中打开这个页面，你应该能看到我在下面的图片中所展示的内容。花点时间仔细阅读一下。你可能会有很多问题，这是件好事。在我们构建东西的时候，你会知道更多。

![页脚](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_02_06.jpg)

所以，我们需要做的第一件事是编辑这个文件（路径为`ch2/before/320andup/index.html`）使其成为我们自己的。基本上，我们想要通过移除页眉、页脚和中间的所有内容来清空这个页面。在`before`目录中，我提供了一个名为`index_stripped.html`的示例。随意将你的努力与该示例文件进行比较（如果你是一名初学者开发者，不要被诱惑只是将`index_stripped.html`的名称改为`index.html`并使用它；努力编辑代码成功）。

我们一开始要做的另一件事是，使我们能够从谷歌的服务器中拉取 JavaScript 库 jQuery。谷歌非常友好，托管了大量的 JavaScript 和 AJAX 相关的库。因此，我们许多人可以将谷歌作为**内容交付网络**（**CDN**）。然而，你可能会注意到从谷歌服务中拉取它的 HTML 代码行缺少了一些东西：

```html
<script src="img/jquery.min.js"></script>

```

它缺少了 HTTP 协议，这是 URL 的第一部分，在斜杠之前的花哨说法。我敢打赌你在想为什么？原因是我们需要它在`http`或`https`域内工作，这取决于我们的网站是什么。将其省略会使其默认为此代码所在页面的 HTTP 协议。如果你在安全的`https`站点中错误地指定为`http`，它将向所有良好的浏览器发出安全警告，因为你不能在安全站点的上下文中提供不安全的内容。否则，`http`是完全可以的（你也可以完全省略这一点，使用你的网站所使用的任何协议）。

对于这个项目，我正在使用`http`；然而，如果你正在构建一个安全的网站，务必确保这也是安全的。现在你的代码应该是这样的：

```html
<script src="img/jquery.min.js"></script>
```

现在如果你刷新页面，你不应该注意到任何变化，除非你查看 jQuery 的来源。如果你不知道如何检查站点资源是否正在下载，现在不要太担心。但如果你看到错误，只需仔细检查你的代码是否与示例匹配。你可以在任何开发者控制台中检查是否有 JavaScript 错误，无论你使用的是哪种浏览器（甚至是 IE）。一旦这个工作正确了，你可以首先让页面请求 jQuery 库来自谷歌的服务。如果失败，它将来自你网站的服务器。再次强调，我不会过多介绍这个样板代码的细节，但知道以下这行 HTML 是一个备份，以防谷歌无法在你请求时提供 jQuery 文件：

```html
<script>window.jQuery || document.write('<script src="img/jquery-1.7.2.min.js"><\/script>')</script>
```

## 让我们开始构建！

好了！所有的基础都已经就位了。让我们首先为小屏幕构建页面的组件。让我们从页面顶部到底部开始。正如我之前提到的，通常所有的内容都应该跨越小屏幕的整个宽度。让我们从页眉和导航开始。

在 body 标签的下面，让我们放一些 HTML 来制作我们的导航。它应该是这个样子的：

```html
<body class="clearfix">
<!-- PUT YOUR CONTENT HERE -->
<header>
  <nav class="navbar open">
    <div class="navbar-inner">
      <div class="container">
          <a class="logo" href="./">Logo</a>
          <ul class="nav">
            <li><a href="./index.html">Home</a></li>
            <li><a href="./gallery.html">Gallery</a></li>
            <li><a href="./contact.html">Contact</a></li>
            <li><a href="./about.html">About Me</a></li>
          </ul>
        </div>
    </div>
  </nav>
</header>
```

### 页眉

我们创建了一个页眉块。我们出于语义和布局原因使用它。页眉主要包含标志和导航。

### 标志

标志将包含在`<a>`标签中。这遵循了非官方的网络惯例，即网站标志应链接回首页。我们仍然会有一个明确的链接到首页，但提供两个链接对用户而言是有帮助的，而不会令人困惑。我使用简写./以便页面链接回到当前深度级别的根目录；对于生产，您可能希望采取额外步骤，将其链接到您的完全合格的根域（例如，[www.yourdomain.com/index.html](http://www.yourdomain.com/index.html)）。

### 导航

我们创建了一个语义`<nav>`块，并在内部放置了一些嵌套容器，最后是一个`<ul>`（无序列表）。每个`<li>`（列表项）将链接到我们网站上的每个页面。对于这个项目，我们将手动编写每个链接，但如果您使用某种框架，这些链接将动态生成。我已经创建了指向尚不存在的页面的链接，因此如果您单击它们，将收到**404 文件未找到**的消息。

关于导航有一些关键事项需要注意。现在，没有应用任何 CSS，基本布局几乎是我们想要的。每个链接都垂直堆叠，并且有一些额外的填充，这将是全世界肥厚手指的明显目标。这一切都非常理想，因为知道您的网站在没有 CSS 的情况下仍然可以正常运行总是很好的。这有很多原因。其中一个是您的 CSS 由于某种原因未能提供服务。另一个包括使用纯文本浏览器的用户。您还会注意到这里有一些相对非语义的容器，它们作为实用容器发挥作用。我们很快会使用其中一些。

这种导航的一个问题是，一旦我们正确地对其进行样式设置，它将占用大量屏幕空间。在触摸界面上需要交互的元素的最小区域大约是 50 像素乘以 50 像素，以便足够宽以适应手指。不过这里有一些余地。例如，如果触摸目标真的很宽，您可以将其高度设置为大约 40 像素，但这可能有风险。一些可用性专家建议将触摸目标的宽度设置为 60 像素，以适应最粗的手指——拇指，因为许多用户在移动设备上使用它四处移动。不过，为了论证起见，让我们做出妥协，假设每个元素的高度为 40 像素，宽度为全宽，或者至少为 320 像素。这意味着我们的导航与标志将有 200 像素高。我们可能已经占用了超过一半的屏幕空间，只是导航，我们确实需要记住我们必须为潜在的浏览器界面做规划。只用导航而没有实际内容来迎接用户是非常糟糕的。

我们需要对此做些什么！

幸运的是，一个快速出现的惯例解决了这个问题。大多数移动友好的网站和移动应用程序使用一个由三条平行线组成的图标来表示隐藏的导航菜单。

![导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_02_07.jpg)

对于用户来说，这应该表明触摸或点击此元素将显示或隐藏导航。当然，这假设用户知道惯例。出于这个原因，可能有一些情况这不合适，特别是在导航很少的网站上。也就是说，我们将继续按照这个惯例构建我们的导航，以节省屏幕空间并学习如何进行此增强。

这是我们将使用的基本策略。我们将通过 CSS 隐藏和显示菜单，并使用 JavaScript 仅更改类。这样，如果用户没有 JS，他们仍然会得到菜单，但不幸的是它将完全展开。

首先要做的事情是添加一个按钮。在包含我们的标志的`<a>`标签下面添加你的按钮。我们将稍后对菜单进行样式设置，以更好地组织事物，但首先让我们让它工作起来。现在你的导航 HTML 应该是这样的：

```html
    <nav class="navbar">
    <div class="navbar-inner">
      <div class="container">
        <button class="menu-button">
        </button>
        <a class="logo" href="./">Logo</a>
```

如果刷新，你现在会看到一个小按钮的按钮，就在你的标志的左边。现在看起来不起眼，但请耐心等待。我们将编写 JS 代码来切换一些类来隐藏/显示导航菜单。继续打开路径`ch2/before/320andup/js/script.js`中的文件。此时，它应该是一个空文件。我们将编写一些简单的 JavaScript 来隐藏和显示菜单。同样，如果用户没有 JS，菜单就会保持打开状态。这只是渐进增强的一个小例子，还有更多要来的。

接下来，我们将编写这个 JS 来在用户触摸按钮时为菜单分配一个新的类。我们将使用一些简单而优雅的 jQuery：

```html
$(document).ready(function(){
    //all code that should run after the DOM loads goes here
    $('.navbar').removeClass('open');    
    $('.menu-button').on('click', function(){
        $('.navbar').toggleClass('open');
    });
});
```

这段代码的作用是什么呢。首先出现的 JS，`$(document).ready()`，是一些 jQuery，基本上等待 DOM 加载完成的时刻，然后执行放在`ready`函数中的所有代码。通常使用这个来确保 DOM 的所有元素都在那里，以便调用特定元素的代码实际上都在那里。

接下来的一行代码`$('.navbar').removeClass('open')`，将删除我们稍后将使用的`open`类，以便使用一些 CSS 来打开和关闭菜单。如果设备没有 JS，那么这个类就永远不会被移除，打开样式就是唯一应用于菜单的样式！

下一行代码以`$('.menu-button').on('click', function(){`开头，为具有`.menu-button`类的按钮附加了一个事件监听器。当用户点击按钮时，函数内的代码运行。此外，移动浏览器将触摸事件转换为点击，因此这段代码处理了两种事件。但回到函数——用户触摸或点击后，函数简单地在具有`.navbar`类的元素上添加或删除`open`类。从现在开始，我不会详细介绍我们编写的 JavaScript。如果你需要更多帮助理解它，那就超出了本书的范围。但如果你还不准备深入研究 JavaScript，只需跟着我，你应该会学到一些东西！

现在，如果你保存这段代码并重新加载页面，你可以试一下。如果你打开你最喜欢的开发者工具，点击按钮时查看`<nav>`标签，你应该会看到类`open`出现和消失在那个元素上。如果没有发生，或者你遇到错误，尝试重新追溯你的步骤，看看是否漏掉了一些代码。另外，尝试运行本章提供的完整代码，看看是否正常工作。如果我提供给你的代码不起作用，那么除了代码之外还有其他问题。

如果你没有看到任何错误，但同时在浏览器的检查器中也没有看到任何变化，那就耐心等待。可能由于某种原因它没有更新 DOM。但一旦我们添加一些样式，我们很快就会看到它的工作证明。

我将要写的大部分 CSS 可以用纯 CSS、SASS 或 LESS 来编写。出于几个原因，我更喜欢使用 SASS。这个主题也超出了本书的范围。但为了简洁起见，我将尽力向你展示如何在 SASS 和纯 CSS 中编写所有 CSS 代码示例。如果你需要了解更多，请阅读附录 B，*使用 CSS 预处理器*和其他预处理器。否则，请跟着我继续展示 CSS 和 SASS 的代码示例。完成的代码示例都是 CSS 和 SASS/SCSS。

首先，让我们安排导航菜单，以便以一种增强可用性和外观的方式布局事物。例如，让我们让所有这些堆叠的元素高 40 像素。

如果你正在使用 SCSS，请打开`scss`文件夹中的`_page.scss`，确保你将页面头部链接的`css`文件名更改为：

```html
<link rel="stylesheet" href="css/320andup-scss.css">
```

当然，你可以用其他方法来处理这个问题，但让我们保持简单。如果你正在编辑纯 CSS，只需打开路径中的文件：

`ch2/before/320andup/css/320andup.css`

当然，如果你愿意，你可以随时更改这个文件的名称以及头部链接的文件名称，但我建议我们现在保持简单，暂时不要更改。现在，让我们开始为这个页面添加样式。只是一个快速的提示——对于这些样式中的许多样式，我大量借鉴了强大的 Twitter Bootstrap 框架，这是一个包含样板 CSS 和 HTML 的前端框架。你可以在 320 and Up 中包含它，但出于简单起见，我决定不在本书中包含它。也就是说，如果你决定将两者结合起来（如果你喜欢快速而好地构建东西，我强烈建议你这样做），你会发现我使用的许多样式与它非常兼容。现在让我们开始吧！

首先，让我们把按钮移到它应该在的地方，并让它看起来不错：

```html
.menu-button {
  display: block;
  float: right;
  background: #444;
  border: 1px solid #000;
  padding: 7px 10px;
  margin: 5px;
}
```

按钮远离了所有的链接，这样用户在尝试打开链接时就不会意外触摸到它。它看起来也好一点，但仍然需要我们之前讨论过的那三行。不过我们不需要任何图片。

如果你正在使用任何 SASS 或 LESS，你可以利用 320 and Up 提供的许多方便的 mixin 之一。你应该打开`_mixins.scss`，快速查看所有的 mixin。同样，如果你对它们还不熟悉，我将很快给出一个例子，说明它们有多酷；不过，首先简要解释一下 SASS 中的 mixin 以及它们为什么如此出色。

在 SASS 中，你可以通过输入`@mixin`，然后是你想要生成的一些 CSS 来定义 mixin。如果你有一个复杂的任务，不想重复努力，这是非常好的。这回到了 DRY 的概念；例如，我们可以使用 CSS3 的圆角来制作菜单按钮的三个圆角矩形。问题是，目前至少有三种不同的方式来声明圆角，这要归功于供应商前缀。对于所有的圆角，我们必须这样定义：

```html
-moz-border-radius
-webkit-border-radius
border-radius
```

因此，我们可以在需要在网站样式中的任何地方使用圆角时每次都输入前面的代码。或者，我们可以节省精力并将这些放入 mixin 中。圆角 mixin 就是为你做这件事。现在就在`_mixins`文件中查看它。SASS 中的 mixin 可以做很多事情，但单单这种情况就很有说服力。它本质上就像一个可调用的函数，当代码编译成 CSS 时执行（详细信息请参阅附录 B，“使用 CSS 预处理器”）。你可以编写`@include rounded`，mixin 中的 CSS 将呈现在最终的 CSS 中。在这种情况下，你可以获得所有这些创建圆角的方式，而无需输入所有的内容。

如果你已经在使用 SASS，这就是你需要在你的网站上看到它的操作（如果你没有，阅读附录 B，“使用 CSS 预处理器”来了解如何开始）。首先，我们将为我们的按钮添加一些新的标记。

```html
<button class="menu-button">
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
</button>
```

将这个 SCSS 嵌套在你的`.menu-button` SCSS 中：

```html
  .icon-bar {
    display: block;
    width: 18px;
    height: 2px;
    margin-top: 3px;
    background-color: #fff;
    @include rounded(1px);
  }
```

圆角 mixin 将呈现以下 CSS（或者如果你愿意，你也可以手动编写）：

```html
  .menu-button .icon-bar {
    display: block;
    width: 18px;
    height: 2px;
    margin-top: 3px;
    background-color: #fff;
    -webkit-border-radius: 1px;
    -moz-border-radius: 1px;
    border-radius: 1px; }
```

当 SCSS 被处理时，最后三行是 mixin 生成的。这真的可以节省很多时间。现在你的按钮应该看起来整洁，漂浮在右边！

现在，让我们让所有这些链接看起来整洁。你的 SCSS 应该是这样的：

```html
.navbar {
  background: #1b1b1b;
  .navbar-inner {
     .logo{
      display: block;
      padding: 9px 15px;
      font-weight: bold;
      color: #999999;
      margin-bottom: 4px;
    }
    .nav {
      a {
        @extend .logo;
      }
    }
  }
}
```

以下是 CSS：

```html
.navbar {  
background: #1b1b1b; }
.navbar .navbar-inner {
    background: #1b1b1b; }
    .navbar .navbar-inner .logo, .navbar .navbar-inner .nav a {
      display: block;
      padding: 9px 15px;
      font-weight: bold;
      color: #999999;
      margin-bottom: 4px; }
```

这将产生一个清晰的对比，并使链接高 40 像素。但现在我们需要做一些事情来隐藏和显示菜单。我更倾向于不使用 JavaScript 动画来做。好吧，实际上这不仅仅是倾向。CSS3 动画在大多数情况下会更流畅，而且这确实符合渐进增强的思想。如果设备不支持 CSS3 动画，它很可能也不足以处理 JavaScript 动画，那么为什么要强制它运行 JS 循环来实现一个好看的功能呢？另一方面，大多数支持 CSS3 动画的设备通过利用 GPU 来优化这些动画。即使它们不这样做，它们也会播放 JS 动画。

我不会在我的论点上太聪明，但如果你是在一个不支持 CSS3 动画的慢设备上，或者你是在最流畅的移动设备上，这段代码基本上是有效的。

首先，我们需要在这里做一个尴尬的让步。当元素的高度自动计算时，CSS3 动画将无法工作（尚未！）。这对我们来说并不重要，因为我们可以很容易地知道我们的导航菜单的高度。但是，如果你想在未知大小的菜单上使用这种动画，你就不能使用这种方法。对于这种情况还有其他方法；然而，它们没有包含在这本书中。![导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/01.jpg)

所以，现在你的 SCSS 需要看起来像这样：

```html
.navbar {
  background: #1b1b1b;
  overflow: hidden;
  max-height:44px;
  @include transition(max-height .5s);
  &.open{
    max-height: 220px;
  }
  .navbar-inner {
    .logo{
      display: block;
      padding: 9px 15px;
      font-weight: bold;
      color: #999999;
      margin-bottom: 4px;
    }
    .nav {
      margin-bottom: 0;
      list-style:none;
      a {
        @extend .logo;
      }
    }
  }
}
```

和 CSS：

```html
.navbar {
  background: #1b1b1b;
  overflow: hidden;
  max-height: 44px;
  -webkit-transition: max-height 0.5s;
  -moz-transition: max-height 0.5s;
  -ms-transition: max-height 0.5s;
  -o-transition: max-height 0.5s;
  transition: max-height 0.5s; }
  .navbar.open {
    max-height: 220px; }
  .navbar .navbar-inner .logo, .navbar .navbar-inner .nav a {
    display: block;
    padding: 9px 15px;
    font-weight: bold;
    color: #999999;
    margin-bottom: 4px; }
  .navbar .navbar-inner .nav {
    margin-bottom: 0; }
```

我们设置打开菜单的最大高度为 5 x 44 = 220px。`nav`中有五个堆叠的元素，我们知道它们每个都有 44 像素高（我可以通过我的开发工具看到）。由此推断，关闭版本，即已删除`open`类的版本，应该有一个最大高度为 44 像素。我们需要隐藏溢出，这样当菜单折叠到较小的高度时，其他元素就不可见了。

你还应该注意到，创建 CSS3 过渡动画的五种不同方法是用一行 SCSS（另一个 mixin）编写的：

```html
  @include transition(max-height .5s);
```

现在看起来非常不错！随意尝试并享受。这是一个相当紧张的部分。其余部分会简单一些，我保证！

接下来，让我们继续我们的*英雄*部分。现在，我们将简单地有一个背景，一些占位文本和一个按钮。但我将在本节稍后提供一些制作幻灯片秀的提示和建议。

## 英雄

现在让我们暂时保持标记简单。稍后，我们将回来把它做成一个简单的幻灯片秀。

```html
<div class="hero">
  <div class="container">
    <h1>Big Headline</h1>
    <p>YOLO vero scenester, semiotics next level flannel Austin shoreditch portland 3 wolf moon chillwave gentrify consequat tousled retro. Umami tonx ennui cliche delectus pinterest, in excepteur hashtag before they sold out.</p>
      <a href="./contact.html" class="btn btn-primary btn-extlarge">Contact Me</a>
  </div>
</div>
```

英雄 div 充当一些样式和内容的容器，我们将添加一些内容。现在，我们将只添加一个标题，一些文本和一个按钮，最终会将用户带到我们的联系页面。

SCSS 应该是这样的：

```html
.hero {
  text-align: center;
  padding: 40px 20px;
  text-shadow: -1px 1px 0px #E0B78A;
  @include horizontal(#feb900, #cb790f);
  h1 {
    margin: 10px 0;
    font-size: 45px;
    font-weight: bold;
  }
  p {
    font-size: 18px;
    margin: 0 0 30px 0;
    font-weight: 200;
    line-height: 1.25;
  }
  .btn {
    text-shadow: 1px 1px 0px #000000;
  }
}
```

和 CSS：

```html
.hero {
  text-align: center;
  padding: 40px 20px;
  text-shadow: -1px 1px 0px #e0b78a;
  background-color: #cb790f;
  background-image: -webkit-gradient(linear, 0 0, 100% 0, from(#feb900), to(#cb790f));
  background-image: -webkit-linear-gradient(left, #feb900, #cb790f);
  background-image: -moz-linear-gradient(left, #feb900, #cb790f);
  background-image: -ms-linear-gradient(left, #feb900, #cb790f);
  background-image: -o-linear-gradient(left, #feb900, #cb790f);
  background-image: linear-gradient(left, #feb900, #cb790f);
  background-repeat: repeat-x; }
  .hero h1 {
    margin: 10px 0;
    font-size: 45px;
    font-weight: bold; }
  .hero p {
    font-size: 18px;
    margin: 0 0 30px 0;
    font-weight: 200;
    line-height: 1.25; }
  .hero .btn {
    text-shadow: 1px 1px 0px black; }
```

同样，你可以看到 mixin 的使用。我们使用了渐变 mixin，`@horizontal`，创建了八行普通的 CSS。你相信你应该使用 SASS 了吗？

其他的都相对简单。你可能会注意到，我不得不用黑色的阴影覆盖按钮的文本阴影，因为桃红色的阴影在黑色按钮上的白色文本后面看起来会很糟糕。所有其他选择都只是这个区域的一些基本样式，你可以根据自己的口味随意调整。

现在，让我们继续到底部的三个内容面板。

## 内容面板

现在，在英雄下面，放置这个示例代码：

```html
<!--panels -->
<div class="full clearfix">
  <div class="grids grids-three clearfix">
    <div class="header header-link clearfix">
      <h2 class="h2">Heading</h2>
    </div>
    <div class="grid grid-1 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
      <div class="grid grid-2 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
    <div class="grid grid-3 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
  </div><!-- / grids -->
</div>
```

现在，我必须在这里承认，我在这一部分所做的一切都只是复制了 Andy 在他的面板`upstart`中的示例。这些非常有用。你可以在任何预处理器文件夹中找到他的示例，但我从`ch2/before/320andup/scss/320andup-panels/index.html`中找到了我的。

这些不仅是自动布局的（这是愚蠢的开发人员用来表示自动发生但似乎神秘和神奇的事情），而且，正如你很快会看到的，它们已经是响应式的，而无需我们付出任何努力。这是一个巨大的回报！

我想要做的唯一更改是`full`类的`div`的背景颜色。蓝色与我的橙色主题不搭配。但是，如果你查看面板起始的 SCSS（在`upstarts/320andup-panels/_upstart.scss`中），你会注意到背景的颜色是从`$basecolor`变量计算出来的：

```html
background-color : lighten($basecolor, 75%);
```

这意味着你需要将`$basecolor`变量分配给某个值。让我们使用我们英雄渐变中的橙色之一！打开`_variables.scss`，将`$basecolor`更改为这样：

```html
$basecolor: rgb(203, 121, 15);
```

你会注意到我们英雄中的按钮颜色改变了！哇！这实际上是可以的，我已经计划好了。这是将样式与变量绑定在一起的强大功能，但如果你不注意的话，它可能会让你感到困扰。

好！现在看起来非常锐利！如果你调整浏览器大小，你会看到内容面板的大小和布局发生变化。我们只需要制作一个页脚，然后我们可以为 320 及以上的内容添加一些响应式样式。

## 页脚

让我们再次保持简单：

```html
<footer>
  <div class="container">
    <h4>Let's build something awesome together.</h4>
    <p>Connect with me in any of the following ways</p>
    <ul class="social">
      <li><a class="icon-facebook-sign" href="http://faceylink.html"></a></li>
      <li><a class="icon-twitter-sign" href="http://twitterlink.html"></a></li>
      <li><a class="icon-envelope" href="mailto:something@yourmail.com"></a></li>
    </ul>
    <div class="toplink">
      <a href="#">Top</a>
    </div>
  </div>
</footer>
```

我们将这样设计。首先是 SCSS：

```html
footer {
  padding: 15px 0;
  text-align: center;
  background: #1b1b1b;
  color: $white;
  overflow: auto;
  p {
    padding: 9px 15px;
  }
  .social {
    list-style: none;
    margin: 0 auto;
    width: 280px;
    li{
      float: left;
      height: 80px;
      width: 80px;
      list-style: none;
      border-radius: 50%;
      background: #000;
      margin-right: 20px;
      a {
        font-size: 42px;
        padding-top: 24px;
        color: $lightgrey;
        &:visited {
          color: $grey;
          text-decoration: none;
        }
        &:hover{
          text-decoration: none;
        }
      }
    }
    li:last-child {
      margin-right: 0;
    }
  }
  .toplink{
    clear:both;
    a {
      display:inline-block;
      padding:30px;
      color: #fff;
    }
  }
}
```

和 CSS：

```html
footer {
  padding: 15px 0;
  text-align: center;
  background: #1b1b1b;
  color: white;
  overflow: auto; }
  footer p {
    padding: 9px 15px; }
  footer .social {
    list-style: none;
    margin: 0 auto;
    width: 280px; }
    footer .social li {
      float: left;
      height: 80px;
      width: 80px;
      list-style: none;
      border-radius: 50%;
      background: #000;
      margin-right: 20px; }
    footer .social li a {
      font-size: 42px;
      padding-top: 24px;
      color: #bfbfbf; }
    footer .social li a:visited {
        color: gray;
        text-decoration: none; }
    footer .social li a:hover {
        text-decoration: none; }
    footer .social li:last-child {
      margin-right: 0; }
```

希望你现在已经掌握了这一点。但你可以再次看到在 SCSS 中使用一些变量以及`&`符号来帮助更快地编写代码。

接下来，我们处理在较大屏幕上的布局发生的变化。

## 使我们的页面响应式

查看何时需要添加新样式的最佳方法是将浏览器窗口从最窄逐渐拖宽。当设计开始看起来奇怪或破碎时，就是重新设计的时候了。

在我们的情况下，我们需要为较大的屏幕重新设计的主要内容是导航、英雄和页脚。内容面板已经为我们处理了。让我们从导航开始。

在导航的情况下，我们实现了隐藏/显示功能，以节省宝贵的屏幕空间，但在某些时候，我们不需要让用户点击来显示菜单。我们可以简单地将导航始终完全显示，就像我们习惯的桌面站点导航一样。为了找到布局中断的点，我们可以拖动浏览器宽度，这可能会很烦人。而且，实际上，响应式网站不是为了那些不断自发地调整浏览器大小的怪人，比如我自己，而是为了不同尺寸的设备。幸运的是，320 及以上在其工具箱中有一个有用的工具来帮助我们。

如果你在工作目录中打开名为`responsive.html`的 HTML 文件（提醒你，它是`ch2/before/320andup/responsive.html`），它应该会自动加载你的`index.html`文件。现在，通过左右滚动，你可以在五个良好的布局断点中看到你的布局（不要与调试代码中使用的断点混淆）。当然，会有例外，但这些断点是一个真正节省时间的起点，因为它们往往涵盖了当前可用的设备范围。我鼓励你批评和质疑，但现在，让我们利用它们，因为它们与 320 及以上配对，并且将加速几乎所有情况下支持良好设计的开发。如果你通过计算机文件系统打开此页面，它不会加载页面。请参阅本章前面的注释，找到打开此页面的好方法。但重申一下，对于这么简单的东西，我个人最喜欢的是 Python 简单的 HTTP 服务器。

好的，当您成功加载此页面时，您看到了什么？您应该注意到设计在移动和小平板布局上运行得非常好。基于我在这里放置的最少量的占位内容，它看起来既不太稀疏，也不显得太拥挤。而且作为一个奖励，这些整洁的内容面板会扩展以填充额外的空间。框架通过`@media`查询实现了这一点。稍后再详细介绍。

话虽如此，您对平板电脑的纵向布局有什么看法？通常情况下，它是有效的，但是现在我们在英雄区域有更多的空间。这并不意味着我们必须添加更多内容，但我们可能可以把文本放大一点来填充它。让我们大胆一点，让它变得非常粗体，吸引人们的注意。好处是，320 and Up 已经为轻松更改大小提供了所有的结构。首先让我们看看代码，然后我会解释底层发生了什么。

如果您正在使用 SASS，这非常容易。打开`_768.sass`或`_768.scss`文件并添加以下代码：

```html
.hero {
  h1 {
    font-size: 108px;
  }
  p{
    font-size: 40px;
  }
}
```

或者在 CSS 中，找到文件中的这一点：

```html
@media only screen and (min-width: 768px) 
```

在大括号内添加以下代码：

```html
  .hero h1 {
    font-size: 108px; }
  .hero p, .hero footer a, footer .hero a {
    font-size: 40px; }
```

因此，如果您对 SASS 或`@media`查询不熟悉，我将花一点时间帮助您理解这里发生了什么。首先，我将解释`@media`查询。在这种情况下，它的作用很简单，就是告诉浏览器一旦屏幕宽度达到最小宽度 768 像素，就应用其中的样式。您还可以设置其他尺寸和其他条件。

关于 SASS 中允许我们将这些样式组织在单独文件中的魔法，只有在`.sass`或`.scss`文件中（而不是`.css`文件）才有类似的语法，实质上是一条指令，让预处理器引入单独的文件。您可能已经注意到，您编辑的文件（以及其他一堆文件）的名称开头有一个下划线。这表示它是一个部分文件。如果您查看`320andup-sass.sass`文件或您选择的语言的相应文件，您会注意到在所有`@media`查询中，都有`@import`语句。对于我们刚刚编辑的文件，在相同的`@media`查询中有一个`@import 768`语句，就像您在普通 CSS 文件中看到的那样：

```html
// 768px
@media only screen and (min-width: 768px) {
@import "768";
}
```

当文件执行到这一点时，它告诉 SASS 预处理器去找到名称为`_768.sass`的文件，并将那里的任何代码呈现到这个位置。因此，这并不是什么高深的科学，但是设置所有这些的繁重工作已经为您处理了。

好的，现在回到让这个设计响应这个平板尺寸的问题。您还会注意到的另一件事是，我们可能不再需要隐藏导航元素了。如果我们可以保持导航方便，并显示大量内容，那么我们已经完成了一些非常重要的任务！所以让我们回到`_786.sass`文件，并在我们之前的代码块上面添加以下代码：

```html
.menu-button {
  display: none;
}
.navbar {
  position: fixed;
  width: 100%;
  .logo {
    float: right
  }

  .nav li {
    float: left;
  }
}
```

您会注意到这个结构与我们原始的`site.sass`文件的结构相似。这只是出于维护原因的一个良好实践，以确保样式实际上覆盖了其他样式。

如果需要，刷新您的屏幕，现在您会看到导航元素从左到右延伸。这可能是您在常规桌面网站上习惯看到的。大家都很高兴。这种样式也可能移动到`_480`文件布局中，但在我看来，这看起来有点拥挤。话虽如此，如果您的导航较少并且有一个小徽标（或没有徽标），您可能希望在 480 像素时应用该样式。

在这一点上，还有一个很棒的小调整。导航和英雄中的所有内容都比需要的边缘更靠近视口。我们肯定可以添加一些空间。在标记中，我们有一个很好的实用类，可以用于这个目的（这已经成为前端开发人员一直在使用的一种约定）。在您选择的`_768`文件中添加此代码，放在我们迄今为止编写的所有先前代码的上面：

```html
.container {
  width: 90%;
  margin: 0 auto;
}
```

这使我们能够将这些容器居中放置在我们希望在屏幕宽度上填充的其他元素中，这样我们的应用程序在不过分扩展内容的情况下产生了巨大的视觉影响。这种大小和边距是动态的，并且随着浏览器变得更宽而以流畅的方式变化。我们可以在各种视觉断点处设置明确的宽度；然而，如果我们这样做，我们就没有充分利用这个框架。我认为固定宽度是一种过时的范式。

让我解释一下我的意思。在网页设计的早期，设计师们让他们的页面看起来更像……嗯，页面。但是当前的网页设计有一个更灵活的理念。我认为这是一件好事，你不觉得吗？举个例子，使用大屏幕的用户不会在页面中间得到一个狭窄的内容带。

沿着这些线路，您是否注意到“320 and Up”的设计方式还有另一个便利之处？一旦我们应用了 768 的样式，这些样式也适用于更大的屏幕。很棒！更少的代码意味着更快更好的工作，更容易的维护。这也意味着浏览器需要下载更少的 CSS。这就是 UI 的三重要素：良好的用户体验，良好的性能和可维护性。

现在，你会注意到另一件事，我们的页脚没问题。我必须承认，我在这方面采取了简单的方法，但我在这里使用的方法对于这种类型的内容仍然很有用。当页面的某个区域（比如页脚）的内容很少时，只需将所有内容合理地居中对齐是很有益的。如果做得当，它很容易阅读，并且不会分散注意力，而这显然是页面上方更重要的内容。如果页脚有非常重要的内容，您应该考虑将其移到页面的主体部分！

接下来，让我们重新审视英雄区域，并讨论在其中添加图像并使用一些简单的代码来循环播放它们。

## 滑块

因此，在制作幻灯片之前，看一下 320 and Up 如何便于制作响应式图像将是有用的。如果您查看`index.html`文件中提供的代码，您将看到英雄标记下方的幻灯片标记。我已经在那里留下了注释，以便您可以轻松找到。

现在，因为我希望您看到已经为您放置在您自己的文件中的一些内容，所以只需添加以下标记：

```html
<div class="slider">
  <div class="container">
    <img src="img/placeholder.png"/>
  </div>
</div>
```

在这里使用这个标记代替英雄标记（要么删除英雄内容，要么将其注释掉；完全取决于你）。

接下来，在您正在工作的`site.css`文件中添加以下少量 CSS（所有文件类型中都是相同的）：

```html
.slider {
  text-align: center;
}
```

刷新页面并调整浏览器宽度。您应该看到图像在不被裁剪的情况下发生变化。这是一个优雅的解决方案，因为一个图像将适用于所有布局。这并不是所有情况的解决方案（目前有很多关于如何使图像更适应屏幕尺寸的讨论）。但是它适用于以下情况：我有少量不太大的图像，我不需要为不同的屏幕尺寸裁剪它们。这种情况实际上非常普遍，只要您的图像能够轻量化，它就能很好地工作。

现在，让我们增加一些复杂性，而不是重新发明轮子。现在，我们只会添加两张图片，并提供一些简单的 JavaScript 来循环播放并使图像淡入。

让我们更改标记，以便为更多的 JS 和 CSS 做好准备：

```html
<div class="slider">
  <div class="container">
    <div class="slide active"><img src="img/placeholder.png"/></div>
    <div class="slide"><img src="img/placeholder-2.png"/></div>
    <div class="slide"><img src="img/placeholder-3.png"/></div>
  </div>
</div>
```

代码不多，但让我们深入了解一下。现在我们需要将图像包装在`<div>`标签中（出于其他目的，您总是可以将它们放在其他块元素中；但是，现在这种简单的标记对于我们的目的来说是完全合适的）。这些`div`容器允许我们为幻灯片中的任何内容分配类并进行块级样式设置，而不仅仅是图像。目前，我们只在这些幻灯片中放置了一个图像，但是如果我们想要添加标题或按钮或其他东西，那将变得不切实际。为了使幻灯片放映灵活显示，我们只需要将这些包装器放在所有内容周围。

现在，让我们看一些 CSS，以便正确显示这个：

```html
.slider {
  text-align: center;
  position: relative;
  .container {
    position: relative;
    .slide{
      position: relative;
      display: none;
      &.active{
        display: block;
      }
    }
  }
}
```

和编译后的 CSS：

```html
.slider {
  text-align: center;
  position: relative; }
  .slider .container {
    position: relative; }
    .slider .container .slide {
      position: relative;
      display: none; }
      .slider .container .slide.active {
        display: block; }
```

这个标记使我们可以确保第一个图像是唯一可见的，甚至不需要运行任何 JavaScript。默认情况下，`slide`类是不可见的，只有在添加`active`类时才变得可见。这不仅在代码级别上起作用，而且读起来也很好。您读到代码，它说`class="active slide"`，您就会对这是什么意思有一个很好的想法。

接下来，让我们添加一些 JS，看看我们是否可以进行简单的动画。这不会是一个花哨的动画。提醒您一下；如果您想要一些带有酷炫控件和其他花里胡哨的东西，那就超出了本书的范围。如果您想要一个漂亮的响应式幻灯片放映，我建议使用 Twitter Bootstrap 中包含的轮播或其他任何响应式幻灯片放映。我下面分享的示例代码将简单地循环浏览一些图像。

在您的`document ready`函数中添加这个：

```html
  var changeSlide = function(){
    //query the DOM for an active slide
    var $active = $('.slider .active');
    //if there are no active slides set the last one as active
    if ( $active.length === 0 ) {
      $active = $('.slide').last();
    }
//get the next slide after the active one, if there is no next one, set next as the first slide
    var $next =  $active.next().length ? $active.next() : $('.slide').first();
    //set classes on active and next slides so we can apply styles appropriately
    $active.addClass('last-active');
    $next.addClass('active');
    $active.removeClass('active last-active');
  };
//this will kick off the slideshow code above
  $(function() {
    setInterval( changeSlide, 5000 );
  });
```

这段代码是从[`jonraasch.com/blog/a-simple-jquery-slideshow`](http://jonraasch.com/blog/a-simple-jquery-slideshow)改编的，以适应我们的 320 和 Up 布局。它将循环浏览您的图像，并将活动类附加到每个图像，同时从上一个图像中删除它。然后一旦到达最后一个，它就会分配给第一个。再次，这是一个非常简单的方法，因为本书的重点是 320 和 Up。如果您想使用幻灯片放映，我建议不要重复发明轮子，因为有很多很棒的组件可供选择。如果您想选择一个好的组件，请寻找一个设计为响应式的组件，或者至少不会干扰它。对我来说，另一个标准是它使用带有 JS polyfills 的 CSS3 动画。CSS3 动画在移动设备上可能（虽然不是在所有情况下）比 JS 动画更流畅。

我们使用的图像的一个限制是，对于非常大的屏幕，图像在幻灯片的左右负空间中有点被吞没。如果这让您感到困扰，并且使您的网站看起来不如您认为的那样好，那么您有两种策略可供选择：包含更大的图像或在该区域放置全宽度的背景。我更喜欢后者，因为比例更大的图像将占据我们布局的顶部，并且还意味着可能会损害性能的更大的文件。

请记住，这里的最终目标是将内容呈现给我们网站的访问者！后一种策略需要一些规划。要么您的图像需要在边缘周围具有一些透明度，要么所有图像的背景应与您在 CSS 或滑块区域中使用的背景相匹配。我将向您展示一个简单的匹配背景的示例。

我碰巧知道我创建的示例图像具有从`#383234`到`#231F20`的垂直渐变。所以现在我所需要做的就是制作一个与之匹配的背景。使用 320 和 Up 提供的 SCSS mixin 非常容易。我只需将这个添加到我的`.slider`样式中：

```html
  @include vertical(#383234, #231f20);
```

并且渲染为 CSS：

```html
  background-image: -webkit-gradient(linear, 0 0, 0 100%, from(#383234), to(#231f20));
  background-image: -webkit-linear-gradient(top, #383234, #231f20);
  background-color: #231f20;
  background-image: -moz-linear-gradient(top, #383234, #231f20);
  background-image: -ms-linear-gradient(top, #383234, #231f20);
  background-image: -o-linear-gradient(top, #383234, #231f20);
  background-image: linear-gradient(top, #383234, #231f20);
```

这种方法的局限性在于不支持渐变的设备将会得到纯色。如果这对你来说是不可接受的，那么现在是时候回到绘图板，想出一个在所有情况下都能工作的设计了！在大多数情况下，我与设计师合作，他们要么在这种情况下束手无策，要么找到方法使他们的设计在所有情况下都能工作。如果问我，这是一个不断变化的目标，最好把精力集中在一个你知道会完美呈现给 80%的受众，并且对你网站其他观众也还不错的设计上。

好！现在你已经掌握了一个主页的基本知识，它将在几乎任何设备上都能得到最佳显示！这是很多工作，但现在我们已经奠定了基础，其他页面将会很快。

# 总结

在这一章中，我们创建了根据屏幕大小变化的导航，这样小屏幕用户可以展开或折叠它，而大屏幕用户可以获得完整的导航菜单。我们甚至使用 CSS 创建了指示可折叠菜单的图标。我们制作了一个响应式的主区域，有一个大的行动号召，利用混合和变量快速将我们的设计与相互补充的颜色结合在一起。我们使用面板`Upstart`在页面底部获得了三个内容面板，并使用提供的图标和 CSS 框架在页脚包括社交媒体和联系信息图标。最重要的是，这一切发生得非常快。一旦你掌握了它，你可以在一个小时内完成这样的页面。现在让我们继续下一章吧！


# 第三章：构建画廊页面

在上一章中，我们做了很多工作，为我们的投资组合网站的其余部分建立了相当的基础。有了我们现在拥有的知识和我们在 320 和 Up 框架之上编写的少量代码，我们真的可以开始快速前进了。在本章中，我们将做到这一点。我们将构建一个面板画廊，用于窄屏堆叠，用于宽屏平铺。为此，我们将使用与上一章中用于页面底部内容面板三重内容相同的基本方法。

# 创建线框

在我们开始编码之前，让我们看一些线框图。以下屏幕截图显示了我们在小屏幕上的屏幕应该是什么样子：

![创建线框](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_08.jpg)

随着浏览器变得更宽，我们希望这些图像变得更大，并将布局从堆叠变为平铺，以更好地利用屏幕空间。以下屏幕截图是超过 992 像素宽的基本布局：

![创建线框](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_09.jpg)

我在上面创建的 320 和 Up 方便的两者之间有很多视觉断点。在使用 320 和 Up 时要记住的唯一一件事是如何使页面的其余部分与其保持一致。在这里，让我们分析布局正在做什么，并通过使用 320 和 Up 中已经存在的样式或创建我们自己的样式，使我们的页面的其余部分与其友好相处。

我为自己创建**画廊**页面的方式是在页面顶部使用某种英雄，但不是幻灯片。我觉得对于这种网站的大多数页面，重要的是用简单而醒目的陈述来引导用户。主要原因是您不能指望用户首先访问您的**主页**，因此您需要在每个页面上建立关于您的网站的相当多的背景信息。我想我会将这种策略与连续电视节目的编写者使用的策略进行比较：您必须假设观众可能需要在每一集或在这种情况下的每个页面中获得一些背景信息。

因此，让我们从一个不太高的英雄开始页面，但仍然具有非常粗体的文本-标题和简短的句子。

要开始，请从`ch3/before/320andup/gallery.html`获取`gallery.html`文件。该文件将包含我们可以从我们的**主页**中重复使用的所有项目，例如文件头中的代码，导航，页脚等。花点时间看一下它，并查看我们在前进过程中重复使用的内容。继续在浏览器中打开此页面，查看您要开始使用的内容。您应该看到导航部分紧挨着页脚。不用担心，我们很快就会填补它们之间的空间。

在我们继续之前，我只想快速概述我们从第一页中保留的代码以及原因。当然，我们保留了从文件顶部到结束的`</head>`标记的所有内容。我们还重复使用从页脚开始并延续到文件底部的代码。这是我们在每个页面上需要的整个代码，以便跨设备和浏览器进行基本工作，以及包括我们的样式，网站图标和 JavaScript 库。我们还有一些在每个页面上都相同的代码，例如导航和页脚的标记。换句话说，我们在构建的每个页面上都重复使用此代码。这是正确的，但是，例如，如果您使用的是 Django 或 Rails 等框架，或者在另一个框架中使用某种模板语言，您将把在每个页面上重复出现的代码分离到自己的文件中，以便可以在其他文件中重复使用和共享。这将是解决需要在每个页面上出现此代码的问题的一个很好的方法。

然而，为了使这本书不依赖于特定的平台，我只是简单地在我们进行的过程中将这段代码从一页复制到另一页。我真的不建议以这种方式制作网站。在不同的地方重复相同的代码只是在某个时候犯下可怕的错误的邀请（希望我没有犯下一个）。

让我解释一下仅仅手动从一页复制代码到另一页的一些风险。例如，如果你决定在一页上对导航部分进行更改，你必须记住在每一页上做同样的更改，并确保你精确执行。如果你已经编程一段时间，你会认识到这个原则叫做“不要重复你自己”（DRY）。这是编写代码的基本原则。你应该遵循它。这个原则是我之前推荐使用 Sass（或 LESS）的主要理由，也是你应该使用 320 and Up 这样的框架的主要理由！

好了，我说得够多的了。

页面的其他方面也适合在你选择的框架中重复使用。包含导航的页眉和页脚很可能在每一页上都是相同的，所以我也会使这些组件可重复使用。我要指出的最后一件事是，你还应该在底部重复使用 JavaScript。许多时候，开发人员使用策略使 CSS 和 JavaScript 的包含动态化，根据页面的需要，但对于我们简单的网站来说，这是不必要的。

现在我们已经处理好了这些事情，让我们继续处理这个页面上独特的内容。

# 纤细的英雄

现在，我们需要在这个页面顶部放一个英雄，但我们不想让它太过分散注意力，以至于影响到画廊瓷砖。所以，我们不想要一个大而引人注目的图片。相反，我们想要一些醒目的内容，快速总结一下页面上正在发生的事情，并满足以下要求（我之前也提到过）；假设访问者可能会在没有看到网站其他部分的情况下着陆在这个页面上，同时不侮辱那些已经在浏览网站的人的智慧。

当然，你实际说什么取决于你。真正的目标是理解内容的策略以及它如何与我们的布局相关。

这是我们在 320 像素宽设备上所追求的效果图：

![纤细的英雄](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_10.jpg)

在桌面浏览器上应该是这样的：

![纤细的英雄](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_11.jpg)

两个效果图之间的主要区别如下：

+   320 像素的布局将需要比更宽的布局更小的字体大小

+   320 像素的布局将文本居中对齐，而更宽的布局将文本左对齐

这并不是强制性的，只是我做出的一个设计决定，碰巧我们也可以通过响应式设计来支持它。

现在，让我们为此编写一些代码。将以下标记放在`</header>`标签的下面。标记需要如下所示：

```html
<div class="hero">
  <div class="container">
    <h1>Gallery of My Stuff</h1>
    <p>There is almost all excellent stuff here. The rest is just really good.</p>
  </div>
</div>
```

现在，很酷的是，如果你把所有东西放在正确的位置，你的页面看起来会接近我们想要的样子，因为我们正在重复使用**主页**页面的样式。准确地说，只有当我们在 320 像素宽的屏幕上查看时，它才看起来正确。花点时间看看**主页**和这个新的**画廊**页面，理解一下样式是如何被重复使用的。你可能会注意到一件事，现在我们的`<h1>`标签的文本跨越了两行，我们的`line-height`太高了。让我们稍微调整一下。通过添加以下代码行来编辑`.hero h1`样式：

```html
line-height: 1em;
```

现在，刷新页面，看看这样如何保持标题简洁。这是一个舒适的外观，你觉得呢？

好了，这真的很容易！这很有效。

这是为什么这样做有效的原因：您会注意到我将高度设置为`1em`。`em`是一种与像素不同的测量单位。像素设置了一个明确的测量，而`em`设置了一个相对的测量。为什么设置相对高度？为了使未来的更改更容易。一个`em`等于当前的字体大小。因此，在这种情况下，`line-height`最终等于字体大小。这是期望的结果，因为我们希望`line-height`与字体大小几乎没有额外的空白空间。

那么，为什么要如此抽象呢？您并不总是必须这样做，但我喜欢在这样的地方使用`em`，因为这样可以使更改字体大小变得不那么麻烦。如果我以后回来需要调整字体大小，我就不需要同时调整`line-height`以保持当前的样式效果。`em`将继续呈现与字体大小相同的`line-height`。

接下来，让我们看看所有这些对于桌面视图是如何工作的。使用您喜欢的方法（响应式`.html`页面或调整浏览器大小），继续查看我们正在为之设计的最宽宽度，1382 像素宽。

问题在于有一些细微的地方差了一点。您会注意到桌面布局上的字体大小稍微有点太大，以至于无法保持我们想要的紧凑布局。因此，我们需要覆盖一些从**主页**中重复使用的样式。

有两种方法可以实现这一点。一种方法是在我们想要以不同样式进行设计的页面元素之上分配一个类，然后从该类中派生一些新样式，这些新样式将覆盖现有的类。例如，当前，英雄中的`<h1>`元素获得了这种样式：

```html
.hero h1{
  font-size: 108px;
}
```

因此，我们可以向我们的英雄添加一个新类，如下所示：

```html
<div class="hero slimmer">
```

然后，在样式表的更下方，有一个具有以下属性的样式：

```html
.hero.slimmer  h1{
  font-size: 60px;
  text-align: left:
}
```

然后，这种样式将覆盖上面应用的`.hero`样式。然而，这并不理想；现在我们有了两种`hero`，非紧凑型的`hero`在语义上是模糊的。相反，我们可以给两种`hero`都添加一个类，以明确这些样式适用于`hero`的大版本。

首先，让我们返回并更改我们**主页**的 HTML 如下：

```html
<div class="hero jumbo">
  <div class="container">
  <h1>Big Headline</h1>
  <p>YOLO vero scenester, semiotics next level flannel Austin shoreditch portland 3 wolf moon chillwave gentrify consequat tousled retro.</p>
  <a href="./contact.html" class="btn btn-primary btn-extlarge">Contact Me</a>
  </div>
</div>
```

请注意添加了`jumbo`类。现在，假设您正在使用 SCSS，我们需要编辑我们的样式表，以匹配 768 像素及以上的屏幕。为了做到这一点，打开`ch3/before/320andup/scss/_76s.scss`文件。以后，我只会要求您按名称打开文件，而不是说明整个路径。因此，对于这个文件，我会要求您打开`768`文件。当我们需要编辑适用于 992 像素及更宽的布局样式时，我会要求您打开`992`文件，依此类推。有了这个基础，让我们继续向`768`文件添加一些代码。在这个文件中，我们的 SCSS 读取如下：

```html
.hero {
  h1 {
    font-size: 108px;
  }
  p{
    font-size: 40px;
  }
}
```

现在我们将`.hero`替换为`.jumbo`。

因此，现在，整个 SCSS 文件部分应该看起来像以下代码片段（接下来是 CSS）：

```html
.jumbo {
  h1 {
    font-size: 108px;
  }
  p{
    font-size: 40px;
  }
}
```

然后，在上一个代码片段中添加以下 CSS：

```html
@media only screen and (min-width: 768px) {

  .jumbo h1 {
    font-size: 108px; }
  .jumbo p {
    font-size: 40px; } }
```

因此，很酷的是`.jumbo h1`和`.jumbo p`现在更具可重用性，因为它们与`.hero`解耦，后者具有相当特定的应用。

现在我们需要为我们的**画廊**页面的样式进行处理。让我们将 HTML 代码修改如下：

```html
<div class="hero subhead">
  <div class="container">
    <h1>Gallery of My Stuff</h1>
    <p>There is almost all excellent stuff here. The rest is just really good.</p>
  </div>
</div>
```

我们不为 320 样式分配`subhead`样式，但让我们为需要更好地利用可用空间的样式添加它。第一站是 480 像素的视觉断点。查看这个 480 像素的布局；我们可以适当增加字体大小。这似乎是一个小改变，但让我们这样做不仅是因为我们可以，而且因为明年几乎肯定会有一个宽度为 520 像素的平板电脑，现在您花时间这样做，您的布局更有可能在这个分辨率下保持稳定！

如果你正在使用 SCSS（或其他预处理器），请在你的`480px`文件中添加以下代码：

```html
.subhead {
h1 {
    font-size: 48px;
  }
  p{
    font-size: 24px;
  }
}
```

这将再次渲染 CSS，嵌套在查询`@media only screen and (min. width: 480px)`内，并且看起来像这样：

```html
.subhead h1 {
  font-size: 60px; }
.subhead p {
  font-size: 24px; }
```

在这一点上，我们保持文本居中，因为布局的其余部分也将居中。在我们添加内容面板后再详细讨论这一点。

让我们继续到下一个视觉断点，即 600 像素。`48px`的标题看起来有点小。让我们把它全部增加到`60px`。将这段代码添加到你的`600px`文件中：

```html
.subhead {
  h1 {
    font-size: 60px;
  }
}
```

这段代码渲染了以下 CSS：

```html
.subhead h1 {
  font-size: 60px; }
```

现在，转到 768 像素的视觉断点——你觉得它看起来怎么样？我觉得这个字体大小在这里以及其他断点上都适用，但是如果你愿意的话，也可以对更大的尺寸进行更改。在某种程度上，这取决于你想要多大程度地定制字体大小以适应你的内容，或者你想要一些更安全、更通用的样式来很好地适应动态内容。我设计这些布局的目标是创建一个可能适用于各种内容的布局。

现在，我们的`subhead`标题在所有尺寸下看起来都很好！花点时间调整浏览器的大小，看看一切是如何变化并利用现有的屏幕空间。你可能会注意到的一件事是，文本与视图区域边缘之间的空间变得显著变窄，直到在 600 像素和 786 像素之间。你可能还记得，这发生的原因是因为我们直到达到 768 像素的断点之前，才对带有`container`类的`div`标签进行样式设置。我们稍后会解决这个问题，但在我们过多地干扰它之前，让我们看看它与内容面板的搭配效果如何。

在这一点上，我应该提到，我自己构建响应式布局的方法，无论是独自工作还是与团队合作，总是像这样递归的。我试图构建页面的一个组件，直到我觉得它要么完全符合我的要求，要么我对它如何与页面上其他内容搭配有疑问；对我来说，这是一个这样的关键时刻。在与团队合作时，我可能会开始编写这个页面的代码，并从设计师或其他开发人员那里得到反馈，然后进行调整，直到我们都满意到足以发布代码或向客户展示。因为我们正在为自己制作一个网站，我们只是独自迭代（你和我一起）。

因此，我们将添加我们的内容面板，但接着我们需要回过头来确保我们的`subhead`标题看起来不错。

# 内容面板

你可能还记得，与**主页**一样，每个内容面板都将有一个图像、一个标题和一个简短的简介。

![内容面板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_12.jpg)

如果我这样做是为了展示我在网站上的作品集，我会使用每个我想要突出显示的项目的屏幕截图，并编写相对简短的标题和简介。默认情况下，320 and Up 将每个标题作为指向相应页面的链接，但如果你担心人们不会点击它，你也可以将每个面板链接起来。稍后，我们将制作一个示例页面，演示用户如果点击标题会跳转到哪里。

对于这个示例页面，我们将继续使用占位图像和 Lorem Ipsum，但如果你已经准备好了一些实际的、有意义的内容，也可以随意使用。此外，如果你将这些布局连接到某种内容管理系统或博客，你应该考虑如何改变你的代码以适应这些方法。例如，你可能是通过模板中的循环来构建这个布局，这个模板依赖于你创建的`gallery`对象的数量。

对于面板本身，你只需要使用我们放在**主页**上的相同的面板；但是不仅仅是三个，你可以添加任意数量来展示你的出色工作。

以下是你需要制作第一组三个面板的 HTML 代码：

```html
<div class="full clearfix">
  <div class="grids grids-three clearfix">
    <div class="header header-link clearfix">
      <h2 class="h2">Heading</h2>
    </div>
    <div class="grid grid-1 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
    <div class="grid grid-2 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
    <div class="grid grid-3 clearfix">
      <p class="grid-a"><img src="img/410x230.png" alt=""></p>
      <h3 class="h2"><a href="#">Lorem ipsum dolor</a></h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
    </div>
  </div><!-- / grids -->
</div>
```

现在，您只需保存并刷新页面，就会看到一切都运行正常！效率非常高，不是吗？当然，对于您自己的内容，非常重要的是使用 410 x 230 像素的图像，您可以使用图像编辑软件或 CMS 或博客中的巧妙编辑工具进行裁剪。您会注意到，在这三个面板的上方有一个`<h2>`标题。如果有一些合理的分组可以受益于标题，我才会包括这个标题。即使没有这个特定的标题，布局也会很好地工作。我不建议删除`<h3>`标题，因为它们和图像一起，将帮助观看者快速浏览页面并快速找到信息。

因此，在这一点上，您可以使用代码示例中的占位图像来构建此页面，也可以开始包含您自己的内容。如果您是静态地进行操作，而不是在某种模板中使用循环构建页面，那么您只需要不断地复制和粘贴这些面板。

稍微尝试一下；不过，我想给您一些关于这些面板在页面上如何工作的快速想法。需要考虑的一件事是如何让面板在没有标题或额外空白的情况下布局。您真正需要做的就是根据需要不断重复`grid-1`、`grid-2`和`grid-3`块（当然，里面的整个标记也是如此）。我也在示例代码中分享了这一点。

另一个需要考虑的问题是，如果您没有完全是三的倍数的面板，该怎么办。没关系！它也可以正常工作。我在示例代码中也分享了这一点。我只停留在了五个块，它的布局正如您所希望的那样。

关于这个页面，只剩下两个问题需要解决。第一个问题是，您可能会注意到，在我的初始线框图中，我希望为较大的布局左对齐文本。我随意决定，我们将对所有大于 600 像素的布局进行左对齐。转到您的`600px`文件并添加以下代码：

```html
.subhead {
  text-align: left;
  h1 {
    font-size: 60px;
  }
}
```

或者，在您的 CSS 中的`600px` `@media`查询中添加以下代码：

```html
.subhead {
  text-align: left; }
.subhead h1 {
  font-size: 60px; }
```

现在，文本只在较小的设备上居中，而在平板电脑和较大的设备上左对齐。

第二个问题可能是当您在 600 像素和 768 像素之间调整浏览器大小时会注意到的。希望您已经注意到，英雄部分的文本最终与视图区域的边缘距离比布局的其余部分要近得多。您可能还记得，我们将所有内容放在`content`容器中，但是该类在`768px` `@media`查询触发之前不会被样式化。也许我们应该尝试将`768` `@media`查询中的样式应用于`600px`宽度的屏幕，看看这对大于`600px`的所有布局的所有断点有什么影响。因此，现在，立即从`768px`文件中剪切该样式，并粘贴到`600px`文件中。或者，如果您使用的是纯 CSS，您需要从`768px` `@media`查询中删除此代码，并将其粘贴到`600px`中。

现在，完成了这一步之后，回去调整**主页**和**画廊**页面，调整浏览器的大小。主页的标题现在与其下面的面板保持良好的对齐。这个更改似乎并不会对**主页**的标题或页脚产生不利影响，所以看起来我们可以继续了。

在某种程度上，这就是我为响应式网站开发的方式，我看看有什么问题，然后尝试修复它，以一种通用而优雅的方式，尽可能不对内容施加不必要的限制。

现在，我们在这一章中的最后一个重要任务是制作用户单击相应内容面板链接时将着陆的页面。我们将称这个任务为画廊详情。

# 画廊详情

现在，让我们看看我们想要在这个页面上的内容以及如何为不同的设备进行布局策略。

我认为，大多数人希望在任何类型的作品集中看到的主要内容是一些关键图像和一些更详细的文本，用于描述这些图像。

这是我们移动屏幕所需的布局：

![画廊详情](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_13.jpg)

在屏幕截图中显示的较小的正方形将是用户可以触摸或单击以显示页面上较小图像上方的较大图像的缩略图。第一个缩略图将是**画廊**页面加载时显示的默认图像。我们还将突出显示当前活动的缩略图，带有边框。为了做到这一点，我们需要制作所有图像的全尺寸和缩略图尺寸的图像。每个图像的描述将显示在缩略图下方（在我看来这完全合适）。如果您的图像足够引人注目，人们会向下滚动以阅读它。

现在，让我们看看相反的情况——桌面视图。现在我们有更多的屏幕空间，我们将希望以不同的方式布置事物：

![画廊详情](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_14.jpg)

有了额外的空间，我们可以将您辛苦撰写的文本放在大图像的旁边，下面是缩略图的位置。假设与其他响应式布局一样，只要我们以百分比调整页面的关键组件大小，这两种布局将覆盖所有断点。

与以前一样，让我们先从移动屏幕的布局开始。页面的 HTML 结构应该相当简单。我们需要将所有图像放在页面上，隐藏除第一个特色图像之外的所有图像，然后我们将添加我们的文本。同样，让我们不要过多考虑桌面页面的外观；让我们尽可能简单地获取移动布局所需的内容。

与以前一样，您需要确保重复使用我们页面的基本结构——页眉、导航和页脚。在关闭`</header>`标签之后，我们将在页眉下方插入新内容（确切地说）。请务必仔细调查示例代码`ch3/320andup/gallery-item.html`中以下代码的位置，以便您可以跟上。

以下是我们将在画廊项目页面上添加的 HTML 代码的样子：

```html
<header class="page-header">
  <h1>This is a Title</h1>
  <h2>Subtitle with more words</h2>
</header>
<div class="gallery-showcase">
  <div class="gallery-image-area">
    <ul class="featured-images">
      <li class="featured-image-item active"><img src="img/gallery_image-1.png" alt="image 1" /></li>
      <li class="featured-image-item"><img src="img/gallery_image-2.png" alt="image 2" /></li>
      <li class="featured-image-item"><img src="img/gallery_image-3.png" alt="image 3" /></li>
    </ul>
    <ul class="thumbnail-images">
      <li class="thumbnail actice"><img src="img/thumb-1.png" alt="thumb 1" /></li>
      <li class="thumbnail"><img src="img/thumb-2.png" alt="thumb 2" /></li>
      <li class="thumbnail"><img src="img/thumb-3.png" alt="thumb 3" /></li>
    </ul>
  </div>
</div>
<div class="gallery-description">
  <p>some text here…</p>
  <p>even more text if you want…</p>
</div>
```

您应该注意到代码的基本结构中有一个外部容器，其中包含所有我们的主要图像和所有我们的缩略图像。这个容器具有`gallery-showcase`类。在这个类内部，有用于大图像和较小缩略图像的容器——分别是`featured-images`和`thumbnail-images`，用户可以点击或触摸以查看相应的较大图像。内部的`gallery-image-area`容器主要用于布局。就像我们在幻灯片中所做的那样，我们将使用 CSS 将所有图像加载到页面上，同时隐藏不活动的图像。稍后，我们将连接一些简单而优雅的 JS 使其具有互动性。您将在以前的代码中注意到的最后一部分是`gallery-description`容器，它将包含您对作品集项目的描述。

我已经为您添加了占位图像，并在共享代码中提供了它们。大图像的尺寸为 550 x 550 像素，缩略图的尺寸为 80 x 80 像素。如果您想在不修改布局的情况下将这些布局用于自己的目的，您需要编辑一些图像到这些尺寸。

如果您感到不耐烦，就像我经常做的那样，您已经刷新了这个页面，并且可以看到它还没有准备好。我们还有一些工作要做。让我们首先隐藏在页面加载时不会看到的大画廊图像。就像我们为英雄幻灯片所做的那样，我们将为第一张图像分配一个类；这将使它成为页面上唯一可见的图像。回到我们刚刚制作的 HTML 文件，注意我们已经为第一张大图像和第一张缩略图分配了`active`类。

好的，让我们开始样式设计！

我们将为`page`文件添加一些样式；对我来说，那是`page.scss`文件。但是，如果你直接编辑 CSS，你只需要把这些样式添加到你的 CSS 文件中。由于 SCSS 预处理器的渲染方式，这些样式会在代码中的表格样式下面，文件中的位置相当靠后。我建议遵循这个顺序，这样这些样式会在样式表中比更通用的全站样式更低。我倾向于从*Andy*（无意冒犯）那里有点不同地看待`site`和`page`文件。我认为`site`样式是页面上会在每个（或几乎每个）页面上出现的元素。然后，我认为`page`样式是特定页面的样式，不太可能在其他页面上被重复使用。

首先，让我们把标题弄成我们想要的样子。你可能注意到我们在这个页面上有第二个`<header>`（是的，这是允许的）。我们想要为页面内的标题添加一些特定的样式。首先，我们需要让图片下面的文本居中对齐，所以我们只需要在 SCSS 或 CSS 中添加以下代码到适当的位置（如果你不确定，可以从 Packt Publishing 网站下载代码示例）：

```html
.page-header {
  text-align: center;
  margin: 12px 0;
}
```

然后，我们需要为字体应用样式：

```html
.page-header {
  text-align: center;
  margin: 12px 0;
  h1 {
    font-size: 30px;
    margin: 0;
  }
  h2{
    font-size: 18px;
  }
}
```

前面的代码渲染为以下 CSS：

```html
.page-header {
  text-align: center;
  margin: 12px 0; }
  .page-header h1 {
    font-size: 30px;
    margin: 0; }
  .page-header h2 {
    font-size: 18px; }
```

现在，让我们应用样式来隐藏所有未激活的大图库图片。为此，写入以下 SCSS 代码：

```html
.gallery-image-area {
  .featured-image-item {
    display: none;
    &.active {
      display: block;
    }
  }
}
```

前面的代码渲染为以下 CSS：

```html
.gallery-image-area .featured-image-item {
  display: none; }
  .gallery-image-area .featured-image-item.active {
    display: block; }
```

刷新页面，现在你应该只能看到第一个大图库图片。进展了！

你应该在 320 像素的布局上查看我们的布局（记住这是移动优先），会发现到目前为止，所有的东西都是堆叠的——绝对所有的东西。唯一我们肯定不想堆叠的就是缩略图。所以，让我们把它们正确地布局出来。基本上，我们只需要让`<li>`标签左浮动并添加一些间距，我们就会得到大部分我们需要的东西。

在你的样式表中添加以下代码：

```html
ul {
  list-style: none;
}
.thumbnail {
  float: left;
  margin: 0 20px 20px 0;
}
```

在这段代码中，我们首先移除了列表的默认项目符号（但仅限于`gallery-image-container`块内的列表），然后我们让缩略图左浮动。这样，你可以潜在地拥有尽可能多的缩略图，但我建议保持在三个左右，以便让你网站的访问者更容易理解。然而，问题在于，如果你像我在共享代码中一样放了三个缩略图，你会误以为这个布局完全没问题。如果你放了三个缩略图，暂时移除第三个的整个 HTML 代码，这样你就只剩下两个了。

![图库详情](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_03_15.jpg)

看到了吗？我们在缩略图下面的文本会因为缩略图的`<li>`浮动而上移。如果你不了解浮动的所有特性，我建议你去了解一下。这是一个关于浮动的很棒的文章链接：[`alistapart.com/article/css-floats-101`](http://alistapart.com/article/css-floats-101)

但是，现在，我只会告诉你一种修复这个问题的方法。我们只需要清除包含文本的容器。你可以通过添加以下 SCSS/CSS 来实现：

```html
.gallery-description {
  clear: left; 
}
```

在我们继续处理更大的布局之前，让我们再做一件事：让所有的内容远离屏幕边缘，并使其大小与导航栏类似。我们可以使用与之前处理英雄部分类似的方法来实现这一点。

在你的样式表中添加以下 SCSS/CSS 代码：

```html
.gallery-showcase, .gallery-description {
  width: 90%;
  margin: 0 auto;
}
```

现在看起来不错！我们只需要让布局适应更大的屏幕。一旦超过 768 像素，我们就可以把文本移到大图像的右侧。打开你的`_768`文件或者找到你的 CSS 中的`768` `@media`查询，我们将以最小的努力把文本移到右侧。以下是 SCSS/CSS 代码（再次；与本章前面显示的代码相同）：

```html
.gallery-showcase {
  width: 45%;
  float: left;
  margin: 0 2.5%;
}

.gallery-description {
  clear: none;
  width: 45%;
  float: left;
  margin: 0 2.5%
} 
```

现在，拖动浏览器的宽度并享受吧。还有一个问题要解决：您可能会注意到一旦导航的大小发生变化，标题会向上移动。您可能会记得这是由于导航部分是一个固定元素。我们需要做的就是在`page-header`上指定不同的边距，如下所示：

```html
.page-header {
  margin: 66px 0 12px 0;
}
```

然后，页面应该看起来正确。刷新页面并享受吧！

## 返回链接

让我们为页面添加一个简单的增强功能，以便轻松导航。由于这个画廊项目页面不在菜单中，而且为每个画廊项目添加一个菜单项可能并不实际，让我们只是在页面顶部添加一个返回链接。这样可以让任何设备上的用户轻松返回到**画廊**页面。

首先，让我们在`gallery-item.html`的标记中添加这个链接。将返回链接放在页眉内的最后一个位置：

```html
<a class="back btn" href="./gallery.html">&lt; Back</a>
```

以下是上下文中的代码：

```html
<header class="page-header">
  h1>This is a Title</h1>
  <h2>Subtitle with more words</h2>
  <a class="back btn" href="/gallery.html">&lt; Back</a>
</header>
```

刷新您的浏览器，您会注意到您免费获得了一些漂亮的按钮样式，这要感谢 320 and Up。我们需要再做一点点样式，但首先让我澄清一些重要的事情。我们刚刚构建的是一个示例画廊项目页面，链接自`gallery.html`页面。如果您正在手工构建这个静态网站（尽管我之前建议不要这样做），您需要为所有的画廊项目手动构建这个页面，并为每个页面指定一个不是`gallery-item.html`的独特名称。相反，您可能需要将其命名为`company-site.html`或者您要展示的项目的名称。此外，您会注意到我创建了返回链接返回到**画廊**页面，如下所示：

```html
…href="gallery.html"…
```

这不是形成链接的典型方式；在您自己的项目中，您更有可能将链接制作如下：

```html
…href="/gallery.html"…
```

在我们的示例代码中，我们需要使用`gallery.html`，因为更典型的`/gallery.html`会将我们带到整个项目的根目录。而且，猜猜看？在这个项目的根目录中并没有`gallery.html`页面，因为我已经将项目分成了章节。因此，在这个示例项目中，您将会收到**404**响应（**页面未找到**）。试一试吧。

总之，您很可能希望您的链接看起来像`href="/gallery.html"`而不是`href="gallery.html"`。

现在，让我们为按钮添加一些样式，这样它就不会只是坐在页面中间了。现在，最简单的做法就是将其浮动到左侧。要做到这一点，请将以下样式代码添加到您的`_page.scss`文件的相应位置：

```html
.back {
  float: left;
}
```

我将这个嵌套在了`.page-header`的代码内部。因此，在这个上下文中，代码如下所示：

```html
.page-header {
  text-align: center;
  margin: 12px 0;
  h1 {
    font-size: 30px;
    margin: 0;
  }
  h2{
    font-size: 18px;
  }
  .back {
    float: left;
  }
}
```

CSS 中的代码如下所示：

```html
.page-header .back {
  float: left; }
```

不过，这还不够。在添加这个样式后刷新页面，您会注意到页面看起来有问题。这是因为我们需要清除浮动。简单！在`.gallery-showcase`、`.gallery-description`样式的 SCSS 或 CSS 中添加以下代码：

```html
clear: both;
```

这个样式将应用于两个元素，对我们的目的没有任何不利影响。不过，如果您愿意，您可以将您的 CSS 代码分成两个独立的样式，如果这让您感到不舒服的话。现在，这个按钮还有最后一件事要做。它紧挨着视口和主图。让我们回去，添加一个边距将其推开。更新后的`.page-header` `.back`样式应该如下所示：

```html
float: left;
margin: 20px;
```

接下来，让我们开始使用画廊项目的 JavaScript！

## JavaScript 画廊项目

接下来，我们需要编写一些 JavaScript 来满足我们在这个画廊项目页面中的需求。我们的需求非常简单；如果用户点击缩略图，我们希望显示相应的较大图像。有很多策略可以做到这一点，但我将依赖两件事情来快速轻松地实现：我们的页面结构和 jQuery 轻松索引事物的能力。所以，让我先展示代码，然后再解释它是如何工作的。将以下代码粘贴或输入到您的`script.js`文件中，可以放在`ready`函数的任何位置（如果不确定，可以从 Packt Publishing 网站下载代码示例）：

```html
$('.thumbnail').on('click', function(){
  var idx = $(this).index();
  $('.featured-images').children('.active').removeClass('active');
  $('.featured-image-item').eq(idx).addClass('active');
  $('.thumbnail-images').children('.active').removeClass('active');
  $('.thumbnail').eq(idx).addClass('active');
});
```

以下是代码逐行的功能：

以下代码行将事件侦听器附加到缩略图上，这样当点击时，函数内的其余代码将被执行：

```html
$('.thumbnail').on('click', function(){
```

以下代码行获取您刚刚点击的缩略图的从零开始的索引。换句话说，它找出了与此缩略图并排的其他缩略图数量以及它在序列中的编号。从零开始是计算机的计数方式。因此，如果您点击列表中的第一个缩略图，它将获得索引`0`；第二个将获得索引`1`。如果这让您感到困惑，对不起，但这就是计算机计数许多事物的方式。无论如何，我们将使用该数字来定位稍后在`featured-images`列表中的相应图像。

```html
var idx = $(this).index();
```

以下代码行从当前具有`active`类的`featured-image-item`中删除`active`类：

```html
  $('.featured-images').children('.active').removeClass('active');
```

以下代码行将`active`类添加到与相应缩略图在列表中相同位置的`featured-image-item`容器中：

```html
  $('.featured-image-item').eq(idx).addClass('active');
```

以下两行代码的功能与我们刚刚看到的两行代码相同，并且也在缩略图上删除和添加`active`类：

```html
  $('.thumbnail-images').children('.active').removeClass('active');
  $('.thumbnail').eq(idx).addClass('active');
```

简单来说，前面的代码表示，当用户点击第*n*个缩略图时，`active`类使其活动，并使第*n*个特色图像活动。

现在您有了`active`类，另一个不错的增强是添加边框以突出显示活动缩略图。

更新您的`_page.scss`文件（或其等效文件）为以下代码：

```html
.thumbnail {
  float: left;
  margin: 0 20px 20px 0;
  &.active {
    border: 3px solid $basecolor;
    margin: 0 14px 14px 0;
  }
}
```

CSS 代码如下所示：

```html
.gallery-image-area .thumbnail.active {
  border: 3px solid #cb790f;
  margin: 0 14px 14px 0; }
```

我添加了 3 像素宽的边框，并选择了我们主题的基础颜色（尽管您可以选择最适合您的颜色）。由于边框会使每个缩略图占用更多空间，我相应地减少了边距。这会使缩略图稍微跳动，但我不介意，因为这会给用户一些反馈。如果您介意，我鼓励您找到一种不会发生这种情况的策略！

# 总结

我们又走了很多路！在本章中，我们制作了一个画廊概述和一个画廊详细信息，这对于从手机到台式机等各种设备都能很好地工作。我们重复使用了一些 320 和 Up 的起步，这样我们就不必从头开始构建响应式的三列布局。列在小屏幕上很好地堆叠，并在更宽的屏幕上水平排列以填充宽度。我们为**画廊**页面制作了一个略微修改的主视觉，而无需编写大量覆盖样式，甚至编写了一些优雅的 JavaScript 来使**画廊**详细页面交互。在下一章中，我们将制作一个页面，让网站访问者可以与我们联系。


# 第四章：构建联系表格

在第三章中，*构建画廊页面*，我们建立了展示我们作品的页面。希望你在这些页面上展示的作品质量是如此引人注目，以至于网站访客会想要联系你，雇佣你的出色工作。

让我们让这个能力变得简单和有吸引力！

# 制定表格计划

我知道表格并不是很令人兴奋，但我们必须以某种方式获取用户信息，所以我们不妨让它们看起来漂亮一些，而不是呆板和冷冰冰。一个干净友好的表格将会简单而且最少，只收集我们需要的信息。我们还需要确保填写表格的过程尽可能清晰和没有挫折感。320 和 Up 框架被设计用来促进这些工作，但我们仍然需要进行必要的规划，以确保一切都恰到好处。

幸运的是，对于我们相当简单的需求来说，这并不会太困难。让我们考虑一下我们需要收集的最基本信息，以便跟进潜在客户。我们需要以下信息：

+   潜在客户的姓名

+   公司

+   电子邮件地址

+   电话号码

+   一条消息

需要牢记的一些重要事项是，确保所有字段的标签都让用户知道应该在哪个字段中输入什么。我认为一个可用表格最具有说服力的论点是这样的：

人们从左到右，从上到下阅读。因此，标签应该出现在它所描述的输入框的上方，因为用户会先读标签，然后看到输入框。当然，这是一个假设，即我们的用户理解定义表单输入的视觉线索。如果我们的用户不知道表单字段是什么，我们可能就没什么希望了。也就是说，值得思考的是，我们的用户界面在很大程度上依赖于人们理解约定！

在这张表格上，我们可以使用其他约定。一个常见的约定是使用占位符来向用户展示每个输入中期望的内容类型的示例。同样，这个约定对于任何长时间使用互联网的人来说都是众所周知的。希望这也可以对一些不太熟悉这些约定的人有所帮助。

## 处理必填字段

我们需要让用户知道的最后一件事是我们希望他们输入的必填字段。关于这个问题有两种看法；我会介绍两种，主要是因为我认为两种方法都有其优点，而且这真的取决于你在做什么。

一个约定是在所有必填字段旁边放置必填的 `*`。这个约定对大多数访客来说确实有效，但这种方法的问题在于，如果我们基本上注释了一些我们认为是可选的字段，可能会阻止收集一些信息。这个论点基本上声称，如果我们不要求消息并且不将其标记为必填，用户跳过这一部分的可能性就会增加。我们的表格绝对应该要求用户提交姓名和电子邮件；否则，我们根本无法回复。通常不要求电话号码或消息。将**电话**字段留作可选是对大多数人的一种礼貌，因为有些人不希望通过电话联系。将**消息**字段留作可选是对用户的一种礼貌。我们不想强制要求，因为一旦我们有了姓名和电子邮件，我们就可以随时回复，尽管我们的回复可能会非常通用。对于我们的潜在客户来说，了解我们下次交谈的背景是有帮助的。这样可以节省每个人的时间和精力。

考虑到这一点，我想介绍一下不遵循将字段标记为必填的约定的论点。论点如下：

如果我们作为网站的创建者，只在表单上放上我们绝对需要跟进的输入字段，那么表单应该足够简单，不会让用户感到沮丧。在我们的情况下，我们有五个字段，这是相当节俭的。然后，通过不标记任何字段为必填，我们表明我们想要我们所要求的所有信息，但实际上并不需要。然后我们可以使用表单验证来确保我们得到最基本的信息，而在我们的情况下将是姓名和电子邮件。

最终，这些决定考虑了许多其他因素。由于我们的作品集网站很可能是用于数字媒体工作，我们的受众应该熟悉网络惯例，我们可以利用这一点，为每个人带来一个干净、简单的表单。在其他项目中，你肯定需要迎合不同的受众或收集更多的数据。希望通过我对这个表单规划的讲解，能对你未来的决策有所帮助。

## 表单布局

好了，现在让我们继续讨论我们希望在断点上看到这个表单的样子。这将很容易，因为我们在这个页面上的重点是从潜在客户那里获取一些信息。因此，我们几乎可以在移动端和桌面端几乎完全相同的布局上得逞。

这是移动端的布局：

![表单布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_04_16.jpg)

这是一个宽度大于 992 像素的布局示例：

![表单布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_04_17.jpg)

很难把它们区分开来！我知道，如果有人在全宽度的新 Thunderbolt 上打开这个表单，输入字段会变得不必要地宽。但实际上，我们不需要也不希望页面上的其他内容干扰，所以我们会小小努力，让页面看起来仍然令人愉悦。

好了，说了这么多！让我们写些代码。

首先，让我们在表单上方放一个小的主体区域。我总是喜欢在我在网上创建的东西中添加人情味，所以在标题下方，让我们放置这个标记：

```html
<!--hero markup -->
  <div class="hero subhead">
    <div class="container">
      <h1>Say Hello!</h1>
      <p>I just met you and this is crazy. Leave your number, I'd love to work with you.</p>
    </div>
  </div>  <!--end hero markup -->
```

你可能应该在里面放上你自己的消息，但你明白我的意思。

之后，让我们放置表单所需的标记。我们将在主体之后使用的标记如下：

```html
<!--form -->  <div class="full row clearfix">
    <h2 class="h2">Hello! Is it me you're looking for?</h2>    <p>Reach out to me for your new projects.</p>
    <form method="post" action="#" class="contact">      
<p>
<label for="name">Name</label>
<input id="name" name="name" placeholder="Firstname Lastname" type="text" required/>
</p>
<p>
<label for="company">Company</label>
<input id="company" name="company" placeholder="Widgets Inc." type="text"/>
</p>   
<p>
<label for="email">Email</label>>>      
<input id="email" name="email" placeholder="firstname@somename.com" type="email" required/>
</p>
<p>         
<label for="phone">Phone</label>        
<input id="phone" name="phone" placeholder="123-456-7890" type="tel"/>      
</p>      
<p>         
<label for="message">Message</label>        
<textarea id="message" name="message"></textarea>      
</p>      
<p>         
<input type="submit" class="btn btn-primary btn-extlarge" value="Send It!" />      
</p>    
</form>  
</div>  
<!--end form -->
```

这个标记大部分都很直接，但我使用了略微主观的标记和良好的实践。首先，你会注意到，我没有为表单的`action`参数提供值，用于将表单数据提交到服务器。我会留给你来做，因为我们不会制作一个处理这些数据的后端（或者，你可以使用许多巧妙的服务之一，它们会为你处理联系和电子邮件表单）。

在代码下方，你会注意到我用`<p>` `</p>`标签包裹了每个标签和输入配对。这并不罕见，但这是一种处理表单布局的主观方式。如果可以避免，我更倾向于不给输入和表单控件添加样式。对于成长的网站，这可能会导致大量不可重用的工作。你可以通过依赖一些包裹表单控件的元素来消除或减少这一点。始终保持这些元素在语义上适当。我会认为标签和输入表单是段落的一部分，因为它们共享相同的主题，并且是内容主题的一个断点。

## 输入标签魔法

另外，特别是对于手机，始终要充分利用标签中的`for`属性，只有在将该参数的值设置为要与其关联的输入的 ID 的值相匹配时，它才起作用。换句话说，如果您的标签是**电子邮件**输入，给该输入一个 ID 为`email`（`id=email`），并将标签也设置为`email`（`name=email`）。这种做法不仅仅是语义化的，否则我可能就不会费心了。一旦以这种方式配对了输入和标签，一些神奇的事情就会发生。标签现在具有了魔力——当用户点击或触摸标签时，与其配对的输入将获得焦点。这个标准早在触摸界面上网的实践变得普遍之前就已经存在了，但对于触摸来说，这是一个很棒的功能！现在，手指粗的用户、手抖的用户或者动作不精确的用户更有可能击中目标。如果你以前不知道这一点，可以试一试。如果你已经知道了，希望你跳过了这一段；时间宝贵。

我还有一些事情要指出。我在所有我想要强制的字段上放置了`required`属性。这个属性是 HTML 5 规范中的新内容，在幕后做了一些很好的魔术。我们需要为不支持这一特性的浏览器做一些回退，但是您可以暂时享受 HTML 5 会让您作为 web 开发人员的工作比以前更容易的幻想（不用担心，您仍然需要编写一些 JavaScript 来帮助验证这个表单）。不过，一旦您的潜在用户几乎都在使用现代浏览器时（问题是，那会是什么时候？），这个功能将节省您的时间。无论如何，试一试吧。启动一个简单的服务器，比如 Python Simple HTTP 服务器，然后访问您当前状态的联系表单。不要费心填写表单，然后点击**发送**。如果您使用的是 Chrome，您会得到一个很好的验证错误消息，**请填写此字段**，在一个工具提示中：

![输入标签魔法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_04_18.jpg)

其他浏览器的现代版本（Firefox、Safari 和 Internet Explorer）也会做类似的事情。在手机上也试一试吧，效果还不错！

好了，好玩的时间很快就会结束了，因为我们需要为不支持这一特性的浏览器做一些回退。但是，由于 HTML 5 规范，我们还有一些有趣的增强功能要添加。接下来，我想指出一些绝对轻松的增强功能，这些功能是通过一些 HTML 5 表单字段属性获得的。您会注意到，电子邮件输入的`type="email"`。这个属性给你带来了两种特殊的酱料。在桌面和手机上（当然是在支持的浏览器中），你会得到多年来我们在 JavaScript 中编写的电子邮件地址验证。它会寻找`@`等等。在手机上，它应该会打开一个软键盘，上面有一个醒目的`@`。

我们在 HTML 5 中使用的另一个带有新属性的字段是`type="tel"`属性。唯一的好处是，在手机上，它会弹出数字键盘而不是字母键盘。

![输入标签魔法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_04_19.jpg)

对于在小屏幕上填写表单的可怜人来说，这真是一件好事。您的用户会感谢您。

现在，让我们添加我们需要的最小样式，使其看起来与我们的其他应用程序一致。一切看起来都很不错；唯一的例外是输入框的边框是橙色的。如果你使用 SASS，而且你的编译器写出了样式的行号，这将非常容易调试。我一直鼓励你一直使用 SASS，但我真的很喜欢的一点是在开发过程中打印出所有样式选择器的行号。你确实需要为生产编译压缩的 CSS，但对于开发，总是切换到便于调试的代码。我用 CodeKit 做这个，还有其他一些原因。我应该补充说，我通常使用开源的命令行工具。例如，我使用`tmux`和`vim`来编写代码，而不是独立的文本编辑器。但是 Codekit 有很多有用的功能，而且配置起来非常轻松，我真的很喜欢。我只希望它有一个命令行版本。

当我在 CSS 中解决问题时，CodeKit 让我的整天变得更容易。

当我查看这些古怪的橙色边框时，这是我在 Chrome 开发工具中看到的：

![输入标签魔术](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mobi-1st-dsn-h5c3/img/6463_04_20.jpg)

我看到边框属性在`_forms.scss`的第 79 行定义。非常有帮助，对吧？

不幸的是，这还不是故事的结局。当我到达那行代码时，这是我看到的：

```html
input,
textarea,select {
display : inline-block;
width : 100%;
padding : 4px;
margin-bottom : $baselineheight / 4;
background-color : $inputbackground;
border : $inputborderwidth $inputborderstyle $inputborder;
color : $textcolor;

&:hover {
border-color : $inputhover; }
}
```

我立刻注意到两件事。边框颜色是用变量`$inputborder`定义的，悬停时的边框颜色是用`$inputhover`定义的。在我看来，这些变量命名不够准确，但公平地说，我过去做得更糟。无论如何，如果我能在这里做出改进，那就是将这些变量命名为某种指出它们实际上是颜色变量的名称，比如`$inputbordercolor`和`$inputborderhovercolor`。当然，这些名字很长，但它们很准确。

好的，继续。我们需要去`_variables.scss`部分看看发生了什么。这些边框为什么是橙色，天哪？不要惊慌，帮助就在眼前。进入`_variables.scss`文件，我快速搜索了`$inputborder`，这是我看到的：

```html
$inputborder    : lighten($basecolor, 40%);
```

让我们思考一下代码中发生了什么。对于许多设计来说，使用基本颜色作为输入边框可以创建和谐的设计。但是，在我的例子中，我选择了一种略带黄橙色的颜色，这使得边框的对比度相当低。老实说，它们让我感到很烦人；我无法想象对视觉有挑战的人来说会是什么样子。而且，我猜 90%的时间，我希望我的输入边框是灰色的。为什么呢？嗯，对于像创建表单这样关键的事情，我希望确保字段用高对比度的颜色清晰定义，而在白色背景下，最大的对比度是黑色。如果`#000`黑色看起来太刺眼，我们总是可以选择接近黑色的深灰色。在这一点上，我认为最好为这个设计（也许将来的其他设计）重新定义这个变量为某种灰色。

让我们试试这个：

```html
$inputborder    : $lightgrey;
```

我实际上尝试了这个变量文件中定义的所有灰色，我更喜欢浅灰色。它有助于使行看起来更有条理。到目前为止，你可能已经注意到的另一件事是，当你在输入上悬停时，边框仍然会变成橙色。让我们改成更深的灰色。与之前类似，你会注意到`input:hover`样式是在`_forms.scss`文件中定义的。它看起来是这样的：

```html
&:hover {
    border-color : $inputhover; }
```

现在我们去`_variables.scss`文件重新定义`$inputhover`！

让我们这样做：

```html
$inputhover     : $grey;
```

看起来不错！

我们只需要做一些微调，就可以让这个页面的样式更加完美。让我们让输入框看起来更漂亮，并且在移动浏览器中呈现输入框的方式更加一致。你会注意到在之前的屏幕截图中，iPhone 上的表单（或者如果你在自己的移动设备上检查你的工作）自动获得了圆角。让我们设置一个样式在我们的表单页面中做到这一点。

我想要改变整个网站上的所有输入框，所以我要去编辑`_forms.scss`文件。

更新这个样式：

```html
input,
 textarea,
 select {
 display : inline-block;
 width : 100%;
 padding : 4px;
 margin-bottom : $baselineheight / 4;
 background-color : $inputbackground;
 border : $inputborderwidth $inputborderstyle $inputborder;
 color : $textcolor;
 @include rounded(6px); //this is the new bit

 &:hover {
 border-color : $inputhover; }
}
```

在使用`rounded mixin`时，我喜欢 6 像素，但随意调整到你喜欢的样子。我想要改变这些输入框的另一件事是填充。拥有一个大目标很好，但它们也可以在单词和输入框边框之间留出一些空间。就在`rounded mixin`下面，让我们添加一些填充：

```html
padding: 10px;
```

看起来好多了！

我们在这个页面上的最后一个样式任务是限制表单的宽度。让我们保持表单不要超过 992 像素，并保持它居中。

实际上，我们可以在不使用任何`@`媒体查询的情况下做到这一点。让我们回到`site.scss`文件，并添加一个样式，如果我们想要重用它，它将起到相同的作用：

```html
.row {
  max-width: 992px;
  margin: 0 auto;
}
```

这正是我之前描述的。这实际上是一个很好的例子，说明了如何考虑响应式而不一定依赖于更新的标准。

好的，现在我们需要做的最后一件事是去连接验证，以便在尚未支持 HTML 5`required`属性的浏览器中起作用。

## JS 验证回退

嗯，我们可以写出所有的回退。知道如何写回退是非常有用的，但这超出了本书的范围。另外，有一种非常棒的方法可以使用已经制作好的回退。它叫做**webshims**，你可以在这里找到它：[`afarkas.github.io/webshim/demos/index.html`](http://afarkas.github.io/webshim/demos/index.html)。

这个库使得非常容易利用许多 HTML 5 功能，而无需为旧浏览器编写大量支持。在我们的情况下，我们将不需要做太多工作来支持表单中的 HTML 5 验证。

从我之前列出的网站上下载库。一旦你这样做了，将`js-webshim`文件夹复制到你的项目中。我已经在本章的`after`文件夹中完成了这个操作。

现在，我们还需要做两件事，然后就可以了。

在`contact.html`页面的底部包含`webshims`库中的`polyfiller`脚本：

```html
<script src="img/polyfiller.js"></script>
```

你必须把它放在 jQuery 之后，但在你写的脚本之前。

现在在`script.js`中，添加这一行来实例化`polyfiller`脚本：

```html
$.webshims.polyfill();
```

我已经把它放在`ready`函数中，以确保所有的表单元素在**文档对象模型**（**DOM**）中出现之前就已经触发了。

现在，我们已经完成了对表单验证的 polyfill，并且它应该在不支持 HTML 5 验证的浏览器中起作用。享受吧！

# 总结

因此，在本章中，我们计划了比我们其他页面更简单的布局，但有充分的理由。没有人喜欢填写表单，但如果我们可以在具有表单的页面上减少噪音，我们就可以鼓励用户提供信息，以更好地促进沟通。或者至少，我们不会阻止人们填写我们的表单。

可能，这里最大的挑战是客户端验证的跨浏览器支持。在大多数用户使用现代浏览器之前，我们仍然需要进行 shim 和 polyfill，但正如我们所看到的，写得很好的代码也使这变得相当容易，除非我们的要求很复杂。

接下来，让我们继续**关于我**页面。
