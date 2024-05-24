# Web 设计实战（一）

> 原文：[`zh.annas-archive.org/md5/7F8B3C6FCF9A035C2A6AD7E31BDFDEBB`](https://zh.annas-archive.org/md5/7F8B3C6FCF9A035C2A6AD7E31BDFDEBB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自从我开始在这个领域工作以来，我仍然对网络的发展感到惊讶。我一直喜欢互联网是一个快速发展的技术——技术、设计、流程以及一切都变化如此迅速。

《实用网页设计》是一本全面的网页设计师实践指南。每一章都经过彻底修订，提供易于理解和简单使用的信息、技巧和方法。

本书的第一部分是关于网页设计的基础知识。它关注其历史、发展，以及主要组成部分。我们将以逐步的设计工作流程和响应式设计与自适应设计的比较结束本书。

本书的第二部分将教你如何从头开始构建和实施你的网站，介绍 Bootstrap 框架、客户端渲染以及设计工作流程中最好的工具。

# 本书的受众

《实用网页设计》教读者网页设计的基础知识，以及如何从头开始构建具有交互和动态内容的响应式网站。这是任何想学习网页设计和前端开发的人的完美书籍。适合没有经验的人，也适合有一些经验并愿意提高的人。

# 充分利用本书

要充分利用本书，最好有一些设计经验，但并非必需。你可以在完全不了解的情况下完成这门课程。

此外，你需要一台运行 Windows 或 OS X 的计算机；你最喜欢的互联网浏览器的最新版本（Chrome、Firefox 或 Safari）；以及一个代码编辑器，在本书中，我们将使用 Atom。

# 下载示例代码文件

你可以从[www.packtpub.com](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果你在其他地方购买了本书，你可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到你的邮箱。

你可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用以下最新版本解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/Practical-Web-Design`](https://github.com/PacktPublishing/Practical-Web-Design)。如果代码有更新，将在现有的 GitHub 存储库上更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。你可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/PracticalWebDesign_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/PracticalWebDesign_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“让我们创建这个文件夹并将其命名为`Racing Club Website`。”

代码块设置如下：

```html
<html> <!--This is our HTML main tag-->
 <head> <!--This is our head tag where we put our title and script and all infos relative to our page.-->
  <title>My Page Title</title>
 </head>
 <body> <!--This is where all our content will go-->
  <h1>John Doe</h1>

 </body>
</html>
```

当我们希望引起你对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
.content {
  background-color: red;
  width: 75%;
}
.sidebar {
  background-color: green;
  width: 25%;
}
```

**粗体**：表示一个新术语，一个重要词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“然后点击右上角的三个点，然后点击“显示设备框架”。

警告或重要说明会显示为这样。

提示和技巧会显示为这样。


# 第一章：Web 设计的演变

我仍然记得小时候用 56k 调制解调器浏览互联网的情景。那时候感觉很棒！网站加载得很慢，但它们被设计成尽量减少我们使用的数据，因为每个 kbit 都被计算为使用量（没有无限上网，哈！）。为了理解 Web 设计的工作原理，我坚信我们需要了解它背后的历史，了解开发人员和设计师在 1991 年蒂姆·伯纳斯-李的第一个网站开始时是如何设计网站的。基于表格的网站、动画文本和 GIF 图像、免费页面构建工具的出现，以及 1996 年 Macromedia 引入 Flash 都是 Web 设计领域的重大进步。这将帮助您真正理解 Web 设计原则，了解它的发展方向和重要性。让我们通过这些关键方面来精确了解 Web 设计是如何演变的，并分析它在当代社会日常生活中的重要性。

在这一章中，我们将涵盖以下内容：

+   有史以来第一个网站：*万维网的开始*

+   基于表格的布局：*在 HTML 中引入表格标记*

+   Flash 的引入：*Web 设计的复兴*

+   CSS——救世主：*网站设计的新方式*

+   Web 2.0：*JavaScript——Web 的新智能*

+   移动设备的兴起：*移动 Web 设计的繁荣*

+   响应式 Web 设计：*为移动和桌面设计*

+   扁平设计：*新设计趋势的兴起*

# 有史以来第一个网站

有史以来第一个网站是由一位名叫蒂姆·伯纳斯-李的科学家于 1990 年创建的。他是欧洲核子研究组织（CERN）的一位英国计算机科学家。它基本上是一个基于文本的网站，带有一些链接。1992 年的原始页面副本仍然存在在线。它的存在只是为了向人们介绍和告诉他们什么是**万维网**（**WWW**）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f22f9da1-d3ba-4a31-810f-d2ab9901d62a.png)

随后的大多数网站基本上都是相同的。它们完全基于文本，使用简单的 HTML 标记：

+   `<h1>`用于标题

+   `<p>`用于段落

+   `<a>`用于链接（我们将在我们的 HTML 课程中学习所有这些标记）

HTML 的后续版本允许人们插入图像`<img>`和表格`<table>`，从而创造了更多的可能性。

1994 年，万维网联盟（W3C）成立，旨在制定和建立 Web 的标准（[`www.w3.org/`](https://www.w3.org/)）。主要是为了阻止私营公司建立自己的 Web 语言，因为这将在 Web 上造成混乱。W3C 至今仍在为开放 Web 提供标准，比如新的 HTML5 或 CSS3。

以下是 90 年代的一些网站示例。以下截图显示了 1994 年雅虎网页的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/7d9412b0-24ef-4b86-9f9a-b074f6b9b01f.png)

以下截图显示了 1996 年谷歌网页的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/17d58447-1cbc-432b-bcea-ca48d031f5a7.jpg)

# 基于表格的布局

随着 HTML 中表格标记的引入，Web 设计变得更加有趣。Web 设计师看到了使用原始表格标记（他们总是很狡猾）来构建他们的设计的机会。网站仍然以文本为主，但至少他们可以将内容分成不同的列、行和其他导航元素。1996 年，大卫·西格尔在他的书《Creating Killer Sites》中介绍了间隔 GIF 的使用，这使得 Web 设计师可以利用空白空间（基本上是在内容之间放置小的透明 GIF），并通过合并切片图像背景，用户会产生一个简单结构的错觉，而实际上背后是一个表格布局。设计师们最终可以玩弄一些图形设计元素，比如访问计数器、动画 GIF 等，随着它在流行中迅速增长。文字和图像在网站上随处可见。

我们可以在 1996 年 3drealms 的网站中看到这一点，它展示了设计师们用来添加到他们的网站中的所有花哨的元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/49e5743d-7f58-4023-aca8-87930792a842.png)

我们还可以看到 2002 年雅虎网页的演变：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0a4ebd3f-ea21-4aa2-ae46-990da7c92c9c.jpg)

# Flash 的介绍

Flash，之前是 Macromedia Flash，现在是 Adobe Flash，是在 1996 年创建的。它就像是网页设计的复兴。如果你今天用 Flash 建立你的网站，人们可能会取笑你，但在那个时候，它是创建交互和图形网站的杀手工具。设计师们能够添加动画、自定义字体和形状、3D 按钮、闪屏页面，而且所有这些都在一个工具-Flash 中。整个内容被封装到一个文件中，供用户的浏览器阅读。就像魔术一样。不幸的是，这种魔法很不方便。它对于**搜索引擎优化**（**SEO**）不友好，而且在计算机资源方面非常沉重。

Flash 开始衰落是在 2010 年，当时苹果决定停止在他们的 iOS 软件中支持 Flash（[`www.apple.com/hotnews/thoughts-on-flash/`](https://www.apple.com/hotnews/thoughts-on-flash/)）。随着 HTML5/CSS3 的新功能，你可以创建动画并添加多媒体内容，设计师和开发者很快就转向了 Flash，至少是在网页设计方面。

以下是一些 Flash 网站的例子。这个截图显示了一个非常基本的 Flash 网站，使用了滑块、动画和交互。你可以在[`www.richard-goodwin.com/flash/indexn.html`](http://www.richard-goodwin.com/flash/indexn.html)查看这个网站。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/96294a16-7593-435e-bd52-149fbcd7a754.jpg)

这是一个令人印象深刻的 Flash 网站，当我开始网页设计时它就存在了，*Immersive Garden*：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/3a4be243-d790-4149-bb79-388ccd0991e5.jpg)

# CSS - 救世主

**层叠样式表**（**CSS**）在 2000 年代变得更加流行，因为它们在网页浏览器中得到了越来越多的支持。CSS 定义了 HTML 的显示方式，这使得设计师能够将内容和设计分开，使网站更容易维护和加载更快。你可以在不触及内容的情况下改变基于 CSS 的网站的整体外观。

CSS 作为 Flash 的替代品真的起到了很大的作用。W3C 推荐它作为最佳实践，它提供了更清晰的语义，从而实现更好的 SEO。

然而，CSS 的一个缺点是各种浏览器的支持不足：一个浏览器会支持最新的功能，而另一个则不会。这对开发者来说是一场噩梦。

我们将在书的第六章中详细探讨这一点，*构建你自己的网站*。以下是雅虎网站（2009 年）的一些设计变化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e1f46d17-dc95-4cfd-a7e8-741c3d57bd6e.jpg)

# Web 2.0

21 世纪初期见证了 JavaScript 的崛起。这是事情真正开始朝着我们今天所知道的网络发展的时候。JavaScript 是向网络添加智能的第一种手段。设计师们能够向他们的设计中添加交互、复杂的导航和多媒体应用程序。

尽管网络的最初似乎主要关注设计和美学，但很快就变得以用户为中心，以可用性为主要关注点。设计师们也更加关注颜色分布、位置、对排版的关注，以及使用图标而不是文本链接。最后，Web 2.0 的发展也促进了 SEO 的增长，作为内容驱动。这些技术，如关键词优化、标记和入站和出站链接，现在仍在使用。网络行业真的意识到了 SEO 的重要性，这在这个时期成为了网页设计的主要关注点。

以下是一些网站的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/058caae0-a1c8-4fb9-a26e-08fb4b8be5a8.png)

我们可以看到设计上的差异。布局和内容更加结构化。随着*MySpace*网站，开发者开始为人们创建应用程序进行互动：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f1dae52e-571f-45c1-a7de-0758dec3e3a4.jpg)

# 移动的崛起

我仍然记得第一部 iPhone 发布时。 对我来说很明显我不会买。 那时我显然不了解自己。 iPhone 最终引发了移动浏览的繁荣。 网络行业的人们没有预料到这一点；用户怎么可能在如此小的屏幕上浏览网站？ 这显然一点也不用户友好。 网页设计师开始设计第二个只在移动上显示的网站。 我仍然记得那些链接以[m.domainname.com](http://m.domainname.com)开头。 维护两个网站绝对是一件麻烦事。 人们开始越来越多地从移动设备访问网站。

2016 年，全球首次移动和平板电脑上网使用超过了桌面使用：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/55c10b16-7b91-4e7f-a82f-85d6c96157f4.png)

StatCounter 统计 http://gs.statcounter.com/press/mobile-and-tablet-internet-usage-exceeds-desktop-for-first-time-worldwide

# 响应式网页设计

我们第一次听到“响应式网页设计”这个术语是在 2011 年由伊桑·马科特提出的。 在他关于响应式设计的书中，他描述了一种新的设计方式，既适用于桌面，也适用于移动界面，基本上建议在每个屏幕上使用相同的内容，但是不同的设计布局。 960 网格系统的引入也帮助了这个响应式问题（[`960.gs`](https://960.gs)）。 最流行的版本要么使用 12 列，要么使用 16 列。 对于设计师来说，设计他们的网站使用 12 列桌面，逐渐降级为移动查看已经成为标准。 随着 CSS3 的媒体查询的引入，设计师更容易为移动屏幕设计网站。

我们将在下一章节中更详细地探讨这个主题。

媒体查询是 CSS3 模块，允许内容呈现适应条件，如屏幕分辨率（例如，智能手机屏幕与计算机屏幕相比）。 从左到右，我们有 iPhone，iPad 和桌面版本。 这是网格系统和媒体查询的完美示例（[`www.wired.com/2011/09/the-boston-globe-embraces-responsive-design/`](https://www.wired.com/2011/09/the-boston-globe-embraces-responsive-design/)）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f3a71eaa-c6e6-4d2d-a732-fee341474eab.png)

# 扁平设计

你可能听说过这个术语。 如果没有，扁平设计是指设计风格，其中元素没有样式化的形状和字符，如渐变，投影阴影，纹理和任何使其看起来真实和立体的设计类型。 它通常被描述为与“丰富设计”的相反，后者用于使元素在用户导航时感觉更触觉，真实和可用。

人们经常说扁平设计起源于瑞士风格。 如果你没有听说过这个，瑞士风格（也称为国际排版风格）是 1940-50 年代的主导设计风格，起源于瑞士：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f9b1de8b-cd37-4fa3-b223-c72b5a1aa1fb.png)

它仍然对许多与设计相关的领域的现代主义运动的图形设计产生深远影响。 它成为了 20 世纪中叶世界各地图形设计的坚实基础。 这种设计风格的主要特征是使用不对称布局，网格，如 Akzidenz Grotesk 的无衬线字体和清晰的内容层次结构。 著名的字体 Helvetica 就是在这个时期创造的，并且在各种类型的设计中都被使用。

毫无疑问，瑞士风格对我们今天所知的扁平设计风格产生了很大影响。然而，这一趋势的主要原因主要是由于在这一时期响应式设计的发展，开发人员和设计师们努力实现了一个严重依赖纹理、投影和背景图像的设计。将这些模式缩小到各种屏幕尺寸，以及由于浏览器兼容性的限制，对设计师来说太过繁琐。他们不得不回归基础，简化他们的设计，使其更少的纹理化。这将导致网站加载更快，更高效，更容易设计。

作为一名设计师，我看到这一趋势正在上升。我仍然记得设计师们测试 CSS3 的最新功能，尝试尽可能少地使用设计资产，同时试图通过代码创建一切。在这个时候，开发人员和设计师的主要关注点是效率和更快的加载。

但我们可以一致同意的是，微软和苹果都对这一趋势产生了重大影响，并进一步推广了这一趋势。随着微软的 Metro 和苹果的 iOS 7 的推出，人们立即感到所谓的丰富设计已经完全过时，并迅速发现他们需要重新设计他们的网站或应用程序。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9471dfb5-8a1a-4f9c-bfde-234765fcd6c8.jpg)

iOS 6 和 iOS 7 之间的比较

# 接下来呢？

在审查了所有这些重要的网页设计特点之后，要记住并牢记的一件重要事情是，网页设计趋势并不是由任何特定的个人或公司导致的。网页设计是视觉设计（受印刷设计影响）和网络技术的结合。随着 HTML5 和 CSS3 的进步，我们可以开始看到设计变得比最初的扁平设计复杂得多。技术现在允许人们在设计和形式上拥有更多的灵活性。让我们看看网页设计趋势将如何发展，但要记住它发展得很快，非常快。

# 摘要

总结这一章，我们看到了互联网是如何由蒂姆·伯纳斯-李爵士创建的第一个网站开始的，以及互联网如何随着多年来表格布局、Flash、CSS 的发展，特别是智能手机的兴起而发生了变化，这改变了用户全球浏览互联网的方式。有了这段历史，我们现在可以跳到第二章，讨论网络组件并解释它们的用途。所以，让我们开始吧！


# 第二章：网页设计及其组件

在第一章中，*网页设计的演变*，我们看到自 1990 年蒂姆·伯纳斯-李爵士的第一个网页以来，网页设计是如何演变的。在这些年里，我们看到了新的元素和风格出现在网站设计中。一些元素将帮助用户浏览网站，一些将帮助讲述故事，但最重要的是，所有这些元素都有潜力改善访客的体验。在本章中，我将帮助你了解每个组件，它的用途，以及为什么它有用。让我们深入研究吧！

以下是我们将要涵盖的组件列表：

+   网格

+   行动号召

+   面包屑

+   搜索栏

+   图标

+   模态

+   排版

+   颜色

+   可用性

+   一致性

# 网格

如果你还记得，我们在第一章谈到了网格。网格在响应式设计中非常有用，但它们的用途并不止于此。设计师们自印刷设计以来就使用了网格，用于书籍、出版物，尤其是杂志。简单地定义，网格系统是一个帮助设计师结构他们的设计、内容和图像，并使其更易读和易管理的系统。

了解网格非常重要，因为它们将帮助你按比例设计，平衡设计中的元素，组织模块和部分。更重要的是，它将帮助用户以设计网格的一致性和熟悉性进行导航：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/cf4c7c41-d2c1-42d2-af16-9043cd0138b4.png)

网格系统网站([`thegridsystem.net/`](http://thegridsystem.net/))，对于每个网格系统来说都是一个非常有用的工具，必须要了解。

# 缺点

任何事物都有优点和缺点，网格也不例外。对于大多数人，特别是那些新手设计者来说，网格系统的第一个缺点是他们可能觉得网格系统在创意上有些限制和重复。这是完全可以理解的，不幸的是，有时你会觉得很难突破思维定式，感觉好像一遍又一遍地创造相同的东西。但请记住，网格不容易掌握，需要练习和经验才能充分利用它的优势。

网格在这里是为了帮助，但就像设计时的所有规则一样，规则是用来打破的。你不一定需要遵循网格，但在打破规则之前，你需要了解它是如何工作的。让我们来看一些使用网格布局的好例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/798a76e0-1a6a-42ac-ae6d-7fd8f09f2751.png)[`kinfold.com`](http://kinfold.com)

网格的出色使用，优雅而简单。你可以清楚地看到构图和布局。你可以在网站([`kinfold.com`](http://kinfold.com))上查看。你会发现顶部部分不是网格的一部分，但它仍然与设计完美地融合在一起：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e2b6adde-3b52-4b3d-8d04-0822683c3cde.png)

著名的 Bootstrap，基于网格的 CSS 框架

一个很好的练习是尝试在网站上找到网格。并看看它是如何设计的。

# 行动号召

**行动号召**（**CTA**）是一个营销术语，用来定义一个设计元素，它向用户征求并鼓励用户采取行动，最终目标是尝试销售。当你开始作为设计师设计网站时，特别是为营销目的时，你会经常听到这个术语。每个设计师的目标是最大化点击转化率，从而最终实现销售。在设计 CTA 时，以下是一些良好实践的指示。

# 显而易见

我要给出的建议是，在设计 CTA 时不要太有创意，因为它仍然是一个按钮，人们已经习惯了。随着用户习惯了在线体验，他们知道 CTA 以按钮的形式出现。他们看到一个按钮，就知道该怎么做。简单。让它变大，明显，并且与周围的一切脱颖而出，那就成功了。

这是一个糟糕的 CTA 示例：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c947c675-0c84-4c86-b8a3-ef203e0d46a3.png)

来自 Capgemini.com 网站 2017 年的图片。一切权利属于 Capgemini

箭头指向的区域是按钮，是的，我是认真的，你可以点击它。这就是为什么你应该将 CTA 作为按钮，而不是其他形式，尤其不要与内容或标题相似。

# 使用对比色

使用对比色可以使按钮突出，吸引用户的注意。颜色的选择也很重要，所以要小心你使用的颜色。我们将在本章后面讨论颜色心理学。

这是一个很好的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e3373df6-bcf1-4f9f-baa3-7d8358daf7cf.png)

来自[Freelancer.com](http://Freelancer.com)，一切权利属于 Freelancer International Limited

这个例子很有趣，因为这里的意图很明显是让用户专注于橙色按钮，眼睛会自然而然地转向它。通过使按钮成为对比色，你可以吸引用户的注意力。

# 引人注目的文案

你在 CTA 中写的内容也非常重要。措辞应该简短。超过十到十五个词的任何内容可能都太长了。简单的陈述是最好的。

这是一个很好的例子，措辞简洁高效：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/03e1d810-572b-44b8-be68-45df1d5cbb0e.png)

来自[Invision.com](http://Invision.com)的图片

# 位置

位置也非常重要，CTA 按钮需要放在用户接下来会看到的地方。作为设计师，你可以预测和预测这种行为。你不需要花哨，只需要合乎逻辑：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/fc6392c4-afee-4ba8-95dc-a3081b0b7e22.png)

来自[Dropbox.com](http://Dropbox.com)的图片

这里很直接，你必须点击的地方很明显。CTA 在表单之后放置得很合理。

另一方面，这是一个不太直接的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/465c2e1f-bb53-4b3d-88f2-27cb2db05894.png)

来自[Apple.com](http://Apple.com)的图片

在这个例子中，按钮的放置不直观，用户必须返回到上面才能点击 CTA，而不是在内容之后。

# 面包屑

**面包屑**（或面包屑导航）是指示用户在网站或 Web 应用程序上的位置的辅助导航系统。该术语来源于《韩赛尔与格莱特》童话故事，主要角色在故事中留下一串面包屑以便追踪回到他们的房子。就像童话故事一样，网页中的面包屑允许用户从开始的地方找回自己的路。对于复杂的网站或应用程序非常有用，但对于没有逻辑层次结构或分组的单页面网站来说并不是很有用。

以下是一些面包屑的例子。

这里有一个 Google Drive 的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/df9012c5-1a83-46c6-98d2-86920b142053.png)

这是一个电子商务网站的例子。([mac-addict.com.au](http://mac-addict.com.au)):

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/796ecbc8-7703-4956-be68-e793e42a1cba.png)

# 搜索栏

搜索栏对于内容丰富的网站（如 YouTube、Facebook 和 eBay）变得更加重要。用户现在习惯使用搜索栏，当他们搜索某物时，他们总是在寻找它。然而，并非每个网站都需要搜索栏。如果你有一个简单直观的网站，内容较少，搜索栏可能就太过了。

以下是设计搜索栏时的一些良好实践的快速提示。

# 提交按钮

设计师在设计时经常贬低提交按钮，但背后总是有原因的。即使用户可以按*Enter*按钮，不显示它也不够有价值。用户需要看到还有其他操作可以触发。为用户提供不同的可能性来实现他们的最终目标总是更好的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f0127dc8-fb1f-4567-9f79-27841b9fc7c6.png)

上面是一个糟糕的搜索栏和一个好的搜索栏的例子。

# 使其显眼

让用户寻找搜索框是一种不好的方法。搜索框应该很容易找到，特别是当你的网站上有很多内容时。通过对比或颜色使你的搜索栏突出是很重要的。显示一个完整的开放文本字段也很重要，因为隐藏在图标后面的搜索栏会使搜索功能不太显眼，并增加访问它的点击次数：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/07daf356-56a0-4084-8aab-4a5df9f7f2ba.png)

这是亚马逊移动网站的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1b1f50e3-36d8-4166-874c-02c13c6a40e5.png)

来自[Amazon.com](http://Amazon.com)的图片

你可以看到亚马逊在移动端专注于搜索栏，而不是隐藏它。

# 正确放置搜索栏

搜索栏需要突出，但也需要放置得当。由*A. Dawn Shaikh*和*Keisi Lenz*进行的一项研究（*搜索在哪里？重新审视用户对网络对象的期望*）涉及 142 名参与者，结果显示用户最方便的位置是在网站的每个页面的顶部中心或右上角。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/294b4f75-4022-467a-aa99-4fee284f5f0b.png)

来自([`blog.wikimedia.org/2010/06/15/usability-why-did-we-move-the-search-box/`](https://blog.wikimedia.org/2010/06/15/usability-why-did-we-move-the-search-box/))

# 图标

现在图标随处可见，你可以在路标、键盘、界面等地方找到它们。图标帮助我们更好地理解和解释信息。它在任何图形通信中都起着重要的视觉辅助作用。作为设计师，知道何时何地使用图标来服务你的设计是非常重要和关键的。以下是一些快速入门的提示。

# 简而言之

有趣的是，图标可以快速总结文本的内容。网络用户已经变得更擅长扫描页面，寻找对他们来说相关和有趣的内容。因此，他们只需看一眼图标，就能快速获取他们想要的信息。例如，在这个例子中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/43bdbf87-167e-4f8e-a673-75c52a3bb21d.png)

（[uber.com](http://uber.com)）

图标可以快速描述内容，并产生美观的效果。

# 吸引用户的注意力

一个没有图标的网站可能会很无聊。想象一下一本没有图片的杂志，会有多无聊？对于网站内的图标来说，也是同样的逻辑。此外，有了漂亮的图标，你为你的网站增添了更多的美感，而你的用户也会因为方便而感激你。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/304d4340-6670-4de6-95fa-724698c2246c.png)

来自[Paypal.com](http://Paypal.com)的图片

看看这张从 PayPal 网站上截取的带有图标的屏幕截图，与我们去掉图标的下一张对比：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/693b6835-cc04-4cde-9791-eeafca18c4a0.png)

来自[Paypal.com](http://Paypal.com)的图片

第一个肯定比第二个更有趣和吸引人。

# 方向性

我推荐使用图标的最后一个原因是向用户显示方向。与其显示“上一个”或“下一个”，显示箭头往往更有效，因为用户现在习惯了这种方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/3c604257-c457-4ca3-a429-c23947c64ce4.png)

箭头也可以设计得很好（[`cars3generations.com/`](http://cars3generations.com/)）。

# 模态

模态框通常是弹出窗口，而不是打开新的标签页/窗口。它们通常会使背景变暗，以吸引弹出窗口的注意。简而言之，模态框用于在同一页面上向用户显示信息，而不需要重新加载页面，从而提高了可用性。

模态框起源于 Windows、Mac OSX 和 Linux，但它们很快就传播到了 Web 应用程序和其他用途。

使用模态框的五种常见用法：

+   **错误：**警告用户出现错误

+   **警告：**警告用户可能有害的情况

+   **收集信息：**从用户那里收集信息

+   **确认或提示：**要求用户确认操作

+   **助手：** 在使用界面时帮助用户

模态框不应与侧边栏、手风琴菜单、工具栏等无模态组件混淆，因为它们允许用户与父窗口进行交互。

以下是一些模态框的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/fe5aef93-82e6-4765-9a36-f725605b7721.png)

在[Twitter.com](http://Twitter.com)上撰写推文时使用模态框：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/dae49917-38fe-4956-b591-3bd6b1ce4b65.png)

模态框也用于在登陆网站时获取人们的电子邮件或注意力，比如在[Getflywheel.com](http://getflywheel.com)上。

# 排版

我仍然记得设计我的第一个网站时，网页设计中的字体非常受限制。只有几种默认字体可用，我们大多数情况下不得不使用超级中性的 Arial 字体。随着 CSS3 的字体支持，现在可以添加自定义字体，这对设计师来说是一种解脱！排版在设计中非常重要，它可以改变访问者的感知。*纽约时报*（[`opinionator.blogs.nytimes.com/2012/08/08/hear-all-ye-people-hearken-o-earth/`](https://opinionator.blogs.nytimes.com/2012/08/08/hear-all-ye-people-hearken-o-earth/)）中有一项研究比较了字体的真实性。看一下这张图表：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0404d60b-298e-4578-8791-07a4ec633013.png)

权重一致

你可以看到人们倾向于相信 Baskerville 字体中写的信息胜过其他任何字体：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c55ad70e-5cba-454e-bab5-fcdf8e5081db.png)

权重不一致

排版在你的设计中真的可以起到作用。不幸的是，我在这里不是为了做一个完整的排版课程，但这里有一些快速选择最佳字体的小贴士。

# 选择一个与您的品牌相连接的字体

你所做的一切都应该与你的品牌相连接，包括你的排版。你选择的排版将给用户一个关于你的品牌是谁以及是关于什么的想法。基本上有三种不同的字体类别：有衬线、无衬线和手写体。

# 有衬线字体

有衬线字体很容易通过字母上延伸的小线或笔画来识别。这里有一张图解释了区别：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f2a9fe1b-cd15-4efa-923f-7a95fcd33a54.jpeg)

图表来自[`visualhierarchy.co/blog/serif-vs-sans-serif/`](https://visualhierarchy.co/blog/serif-vs-sans-serif/)

与有衬线字体相关的情绪通常是经典、浪漫、优雅、正式和成熟的。一些著名的有衬线字体包括 Times New Roman、Baskerville、Georgia 和 Garamond。

# 无衬线

无衬线字体通常被认为比有衬线字体更现代。与无衬线字体相关的情绪更清洁、友好、简约或现代。一些最著名的无衬线字体包括 Arial、Helvetica、Futura 或 Gotham。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a445b4c0-b65c-42c5-b061-e7c8d75d5024.png)

Gotham 字体来自[`www.typography.com/fonts/gotham/overview/`](https://www.typography.com/fonts/gotham/overview/)

Gotham 字体在 2000 年代末非常流行。

# 随意手写体

这些字体旨在表现得像是快速书写的非正式字体。很多时候它们看起来像是用毛笔画的。它们可以代表情感、速度和熟悉感。它们不适合作为正文内容，但可以作为一个非常好的标题来传达情感：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d8e6cf67-fff5-4349-b691-7110a3fd2d07.jpeg)

来自创意市场的 Bellisia 字体（[`creativemarket.com/sizimon/1719182-Bellisia-Script`](https://creativemarket.com/sizimon/1719182-Bellisia-Script)）

# 不要使用太多字体

这是我经常给年轻设计师的建议，因为他们倾向于在设计中使用太多的字体，我猜是因为太兴奋了。尽量保持设计的一致性，我建议使用一到三种不同的字体，但不要超过三种。使用有衬线字体作为标题，无衬线字体作为正文是一个很好的搭配。

以下是一些良好组合的示例：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4c6ebd7e-1745-4a8c-ab28-d2c3aa0bac0d.png)

Playfair 和 Futura 的组合([`www.dogstudio.co/`](https://www.dogstudio.co/))

另一个好的组合：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/42f79cfc-1a82-4ea6-a08d-7c019f0a82fb.png)

GTWalsheim 和 Adobe Garamond 的组合([`www.christianaslund.com/the-new-oil-frontier`](http://www.christianaslund.com/the-new-oil-frontier))

最后，GT-Sectra 和 Futura 的组合：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/10b5bb61-be4f-447a-a7d0-9c8cc0387a57.png)

GT-Sectra 和 Futura 的组合([`changegout.com/`](http://changegout.com/))

如果你想要一个网站来找到排版的好组合，我推荐[`fontpair.co/`](https://fontpair.co/)。

有不同的方法将字体添加到你的网站中：

+   你可以使用自己的字体，并使用字体生成器生成与你的浏览器兼容的字体。我推荐[`www.fontsquirrel.com/`](https://www.fontsquirrel.com/)。

+   你也可以使用免费的 Google 字体：[`fonts.google.com/`](https://fonts.google.com/)。

# 颜色

颜色在网页设计中具有巨大的重要性。根据 Kissmetrics 的说法，当你看到一种颜色时，你的眼睛会与大脑的下丘脑区域进行交流，然后，它会向垂体发送信号，最终到甲状腺。这会导致释放激素，引起情绪、情感的波动，从而产生行为。有趣，不是吗？

同样来自 Kissmetrics 的研究表明，一个网站访客形成判断或意见只需要 90 秒。而 62-90%的互动是由产品颜色决定的。

现在你应该明白为什么颜色非常重要，为什么选择它们的方式、时间、受众和目的至关重要。

# 颜色的含义

每种颜色在每个人身上都会引发特定的情感。尽管这可能会因文化、背景或偏好而有所不同。以下是颜色含义的快速参考：

+   黄色：

+   张扬的黄色应谨慎使用

+   男性觉得这不雅

+   孩子们喜欢

+   橙色：

+   新的红色，温暖而没有危险

+   与能量（饮料、运动、健身）相关

+   孩子们也喜欢

+   红色：

+   促使行动，增加呼吸和脉搏

+   象征激情，是时尚/化妆品品牌、约会和食品的理想选择

+   紫色：

+   奢华、优雅和女性化

+   涵盖了大量女性受众，没有负面联想

+   黑色：

+   高雅、传统、企业

+   卓越和正式

+   绿色：

+   成熟，绿色促进健康

+   适用于健康产品、道德运动

+   浅绿色表示创新和新思路

+   蓝色：

+   受欢迎的蓝色暗示着智慧和宁静

+   深蓝色与奢侈品相关

+   浅蓝色适用于清新的产品和创意

+   抑制食欲，所以不适合食品

+   粉色：

+   经典的粉色

+   经常被过度使用来吸引女性用户的注意

+   任何女性化和与婴儿有关的东西

+   它也被认为刺激甜食欲望

+   白色：

+   纯净、凉爽、平静和现代

+   棕色：

+   大多数人避开这种颜色

+   男性不喜欢

+   唤起自然

+   表示可靠性

例如，如果你想创建一个销售玩具的电子商务网站，你不会使用黑色，因为它暗示着更加高档和优雅。你会更多地在欧莱雅或魅可化妆品等奢侈品牌上使用它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/66926f13-ca35-49e7-aa9e-b164c35d15de.png)

图片来自[Loreal.com](http://Loreal.com)。

看看欧莱雅如何使用黑色看起来更奢华，尽管他们并不是奢侈品市场。

当然，记住这些只是指导方针（它们总是取决于上下文）。看看不同的网站如何使用颜色，这总是学习的最佳方式。

# 可用性

我们之前谈到设计如何演变为以用户为中心的设计。这正是我们现在要研究的，那么什么是可用性呢？可用性简单地定义了用户界面的易用性。通常用五个组成部分来衡量：

+   可学习性：用户在访问网站时，实现基本任务有多容易？

+   效率：学习之后，用户重新执行任务或完成其他任务有多有效率？

+   记忆性：用户在一段时间不使用网站后，再次返回并熟练使用网站有多容易？

+   容错性：用户从错误中恢复有多容易？

+   满意度：使用设计有多愉快和令人满意？

在过去几年里，用户已经习惯了网页设计的某些标准，不再容忍加载缓慢、难看或难以浏览的网站。如果你的网站不可用，那么还有很多其他选择。加载速度慢和糟糕的用户体验是增加网站跳出率的因素之一。但是，如果你研究用户的需求和行为，你就能够根据这些来调整你的内容和设计。以下是一些快速指南，让你对应该注意的事项有所了解：

# 简洁

简洁绝对是我在设计中始终追求的东西之一。有时，页面中简单的 CTA 就足够了，不是在开玩笑！首先尝试定义你的用户需要，然后尽可能简化用户体验。添加没有任何功能目的的不必要元素将不可避免地影响访问者。建筑师的著名语录：

“少即是多”

-路德维希·密斯·凡德罗

在某种程度上是相当准确的。

# 可导航性

在简洁的延续中，直观的导航对于良好的用户体验至关重要。不要让用户思考。尽量将自己放在最终用户的位置上，使导航尽可能无痛。与朋友或家人进行一些测试总是一个好主意。

以下是一些良好导航的快速提示：

+   保持主导航简单，放在页面顶部是不错的。

+   不要忘记在大型网站中加入页脚导航（人们经常使用页脚导航）。

+   包括一个搜索框（我们之前讨论过为什么要这样做）。

+   不要使你的导航过于复杂。对项目进行分类，但不要过于深入。

+   链接应该明显，下划线、加粗或者使用不同颜色，但它们应该总是与内容有所区别。

# 易访问性

如果你的网站加载时间超过三秒，你需要考虑优化你的网站。如今的用户懒惰且不耐烦。在一个一切都快速且易于访问的互联网世界中，你需要尽可能地让你的网站易于访问。

以下是可用性和易访问性的一些基础知识：

+   正常运行时间：确保你的网站没有宕机或在加载时出现任何错误。投资于一个良好的托管。

+   损坏的链接：确保没有死链接。用户不应该跳转到 404 页面。一个好的做法是如果链接无法访问，将用户重定向到一个新页面。

+   网站响应性：使你的网站适用于每种屏幕，并根据分辨率支持不同的布局。

良好的可访问性的一个很好的例子是亚马逊。他们的网站可以从任何地方访问，而且几乎没有宕机，主要是因为他们也是一个托管公司。但是如果你仔细观察，他们的网站在桌面和平板电脑上都是响应式的，在调整大小时会自适应。对于移动设备，他们有一个自适应网站，具有不同和更清晰的布局，更适应小分辨率。我们将在接下来的章节中看到响应式和自适应之间的区别。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/92d396e4-3439-4d43-b1b5-79caa89303c7.jpg)[Amazon.com](http://Amazon.com) 在台式电脑、iPad 和 iPhone 上

# 一致性

在审查了所有这些网页设计组件之后，我将以一致性及其重要性结束。一致性无疑是一个良好网站的关键组成部分。它将为你的出色网站或应用程序带来最后一块拼图。想象一个例子，当你想找到你的钥匙，但你知道它们总是在同一个地方，你就不必思考。但如果你找不到它，你会开始紧张地寻找它。对于用户来说，网站也是一样的。你不希望他们每次来到你的网站都要学习。

# 那么，我们如何保持一致呢？

这些是你应该保持一致的几个领域：

+   设计

+   内容

+   互动

# 设计

你的设计应该是一致的，这意味着你创建的每个元素，如链接、按钮、输入或标题，都应该遵循你自己的设计风格。用户会记住细节，无论是有意识地还是无意识地，所以他们会因为特定的颜色或形状而认出一个链接。

一个**用户界面**（**UI**）样式指南示例。这有助于保持 UI 的一致性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/83af72d2-7066-47ae-aa1e-207559b8b003.png)

# 内容

视觉方面不仅需要保持一致，内容也需要如此。网站上使用的情绪和语气必须反映品牌。如果你是一个面向企业销售的企业网站，你的网站内容既应该看起来，也应该感觉非常专业。

# 互动

最后，互动在整个网站上必须保持一致。网站如何响应用户的互动应始终保持一致并保持不变。例如，在 Dropbox 上打开文件时，返回按钮始终位于左上角位置，这样用户就不必再次寻找它并重新学习你的界面。

# 总结

在本章中，我们涵盖了很多主题，但总结起来，网页设计中的每个组件都很重要，对于你的设计来说很重要，但更重要的是对于最终用户来说很重要。有了所有给出的建议，你现在能够创建并使网站看起来很棒，用户友好。

在你开始着手创建自己的设计之前，我想向你介绍下一章，它将讨论响应式和自适应设计，这是你作为设计师或开发者需要了解的内容。让我们开始吧！


# 第三章：网站设计工作流程

在我们真正开始着手创建和实施我们的第一个网站之前，我希望你能从头到尾地经历一遍所有的过程。网页设计不仅仅是设计美观的网站和漂亮的布局；网页设计是一个整个过程，特别是当你想要在现实世界中实施你的设计时。

在这一章中，我们将涵盖以下内容：

+   目标确定：*如何确定我们的目标*

+   范围定义：*列出范围*

+   线框图创建：*如何创建线框图*

+   设计：*创建出色设计的框架*

+   实施、测试和发布

# 我们的情况

让我们想象自己作为设计师工作，接受客户工作。你的第一个项目是为一个赛车俱乐部设计网站；以下是项目的简要：

*Racing** Club*是一个赛车迷俱乐部，成立于 2016 年。它最初是由一群热爱汽车的朋友创建的，但迅速发展成一个热衷于分享他们的激情的社区。

那么现在，让我们来看整个过程。

# 目标确定

在这个阶段，你需要确定网站的最终目标。通过与客户沟通并询问他们关于他们的业务和目标的问题。

# 网站的目的是什么？

现在是确定要解决的问题或为网站设定目标的合适时机。销售门票或增加门票销售？看看你的客户想要什么，并为其找到最佳解决方案。你还需要进行自己的调查，深入了解他们的网站，并寻找需要修复的任何问题。通过之前学习的所有基础知识，你现在能够看到什么是好的，什么是不好的。

# 网站是为谁设计的？

简化设计过程和决策的最佳方法是了解你的目标受众。了解受众有很多方法。你可以问客户，使用不同的分析工具进行跟踪，或者查看以前关于同一市场的报告，这些都会在这个阶段帮助你。

# 这对我们的受众有用吗？

你的客户应该对他们的客户有一些信息，比如他们的年龄、收入等。利用这些信息来创建人物角色，并创建适合网站的用户流程。在我们的例子中，赛车俱乐部，我们会创建以下人物角色：

+   乔治：38 岁，父亲，车库工人，热衷于赛车

+   保罗：28 岁，单身，从事金融工作，热爱汽车和赛车

两种用户流程将有不同的工作方式，你可以排除任何与我们目标用户无关的流程。

# 他们期望在那里找到或做什么？

了解并定义网站的**信息架构**（**IA**）也很重要。知道要向用户展示什么将决定你屏幕的设计并规划用户体验。

你需要创建一个站点地图并定义你需要做的每个屏幕。首先这样做将极大地帮助你设计网站，因为你甚至不需要考虑它。

# 网站需要遵循品牌还是有自己的品牌身份？

当你需要遵循品牌风格指南时，设计网站可能会有所不同。由于风格指南将有助于保持品牌的一致性，客户希望你遵循它，即使这可能会在一定程度上限制你的创造力。

如果客户没有品牌身份，这是为他们创建一个品牌的好机会。

# 有竞争对手吗？如果有，网站与其他网站有何不同？

了解客户的竞争对手也是了解该做什么和不该做什么的好方法。在收集信息的过程中，你需要研究客户的竞争对手。这不仅仅是要做一些完全不同的事情，而是要为客户做好的事情。如果你的竞争对手的一些用户体验很好，可以从中汲取灵感，让你的客户网站变得更好。你通常不需要重新发明轮子，只需要改进它。

所以这就是我们的项目。

我们需要一个具有以下特点的网站：

+   首页

+   即将举行的活动页面

+   往期活动页面

+   活动页面详情（查看活动信息并购买门票）

+   博客页面

+   关于我们页面

+   联系页面

+   登录页面（查看购买门票的历史记录）

网站需要响应式设计，以便人们可以在手机上访问。客户没有品牌身份，并且愿意让我们创造一个。

网站的主要目标是首先向用户展示相关信息，然后，如果他们愿意，让他们能够在线购买门票，而不是去实际的地点购买。

网站地图如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2d1a35b7-2c92-4bf9-9316-9f7df187eaf3.png)

网站地图示例

# 定义范围

这通常是设计师的难点：了解和定义项目的范围。项目通常会比预期的时间长，但这不应该是问题，因为这会导致更多的工作。但有时，客户的期望和你的期望并不相同，所以最好设定边界，以防止意外的工作和范围蔓延。将所有内容都写入合同将有所帮助。这里有一些你可以使用的模板：[`www.smashingmagazine.com/2013/04/legal-guide-contract-samples-for-designers/`](https://www.smashingmagazine.com/2013/04/legal-guide-contract-samples-for-designers/)。

# 创建线框图

现在我们已经定义了项目的目标，我们可以开始设计一些线框图。

在这个项目示例中，我们只会做几个屏幕。这是我们将用于首页、活动页面和即将举行的活动页面的线框图。线框图不是为了精细和设计，它们只是为了得到布局和内容的想法。所以只需使用你喜欢的设计应用程序的简单矩形，或者甚至可以手绘。

这是我们想出的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1e6fc518-3101-4914-a9e8-9060e115542a.png)

对于活动页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/18c2a027-82d8-41ce-8f8b-e56658f78d34.png)

这是我们为活动页面想出的设计：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4d8881b8-d782-4429-92e6-8042f982e219.png)

# 设计

当我设计一个项目时，我总是使用相同的框架：

1.  获取灵感

1.  改进

1.  创新

让我解释一下我在每个步骤中做什么：

# 获取灵感

我真的认为灵感是设计创作的主要部分之一。寻找和收集灵感对我来说至关重要，因为我需要这些灵感来通过获取一些我认为酷或与这类项目相关的设计片段来制作自己的设计。

以下是我用来寻找灵感的一些网站：

+   Awwwards

+   CSSDesignawards

+   FWA

+   Dribbble

+   Behance

然后我会使用*BukketApp*来获取图片，并为这个特定项目创建一个情绪板。

# 改进

一旦你有了情绪板，你就可以开始调整和改进设计。就像拼图一样，尝试通过重新组合形状、颜色等来构成。这是最有趣和最有创意的部分，因为这取决于你的想象力和你创造独特高质量东西的灵活性。

# 创新

当你最终从上一步得到一些东西时，你现在可以将这个设计扩展到整个设计风格。

这个框架不仅可以应用在设计中，还可以应用在创意或研究过程的各个方面。看看生物学研究，比如仿生学，它模仿自然的元素和部分，解决复杂的人类问题。这个过程本质上是一样的，只是方式不同。

这是我们想出的最终设计：

首页设计：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9f1e84b6-611c-46f9-9586-a5e835fffd21.png)

# 实施、测试和发布

设计获得批准后，就是实施网页设计的时间了。这是一个非常有趣的阶段，因为你将让你的设计变得生动起来。看到并与之交互将会得到一些有趣的反馈，这些反馈在设计时可能没有看到。

一旦一切都完成了，你需要彻底测试每个页面，并确保每个链接都能正常工作。这也是一个很好的方法，可以将你的网站放在一个暂存网站上，让人们可以在不将其发布到生产服务器上的情况下进行测试。在这个过程中，你总会发现问题或错误。测试将确保你的网站在每个浏览器和每个设备上都能完美运行。这是一个漫长的过程，但必须完成！

最后，大家最喜欢的部分来了：发布是当你看到自己的作品最终上线时，你应该为此感到自豪。但是，仅仅因为你已经发布了网站，并不意味着工作结束了。你仍然可以进行一些 A/B 测试，使你的设计变得更好，永远不要忘记，一个伟大的网站不仅仅是关于美学，而是要找到形式和功能之间的正确平衡。

这最后三个步骤是下一章的一部分，所以我们将逐步进行这个过程。

# 总结

在本章中，我们经历了从设计网站到发布的整个过程。了解整个过程将有助于你与你的客户和项目。很多人在设计项目时匆忙行事，但在实际设计之前还有很多步骤。特别是如果你在做大量的用户体验设计，花一些时间进行一些研究实际上会为你节省大量的时间和金钱。

在下一章中，我们将深入了解响应式和自适应设计。这两者有着相似的最终目标，但它们是非常不同的。我们将看到其中的区别！


# 第四章：响应式设计与自适应设计

在设计我们的网站之前，让我们了解响应式和自适应设计之间的区别，以及为什么有必要了解它。了解响应式和自适应设计方法之间的区别对于网页和应用程序设计师来说非常重要。了解这些区别将使您在规划和执行设计时拥有更好的视野和结果。

随着我们现在拥有的设备数量，了解每个设备的需求和行为真的很重要。内容是关键，它需要在每个设备之间流动。正如 Josh Clark 所说的那样，把它看作是在每个设备上冷却的水：

“内容就像水一样。内容会呈现多种形式，流入许多不同的容器，其中许多我们甚至还没有想象过。”

-（也受到李小龙著名语录的启发）

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/45441c26-b926-4812-9ce0-5e4aabd2ce24.jpg)

作者/版权所有者：Stéphanie Walter

设计师们仍然混淆这些，并且并没有真正看到两者之间的界限，尤其是年轻的设计师。

在本章中，我们将学习：

+   响应式设计

+   自适应设计

+   哪一个是最好的？

+   并从中获得启发。

让我们开始吧！

# 响应式设计

我们在第一章中简要讨论了响应式设计，*Web 设计的演变；*如果你还记得的话，它描述了一种为桌面和移动界面设计的新方法。基本上是建议在每个屏幕上使用相同的内容，但是不同的布局设计。

更准确地说，响应式网站根据浏览器空间显示内容。如果你在桌面上打开一个响应式网站并改变浏览器窗口的大小，它将动态适应窗口大小并自行排列。

响应式设计的概念最初是由 Ethan Marcotte 创造的，当他写了一篇关于响应式建筑设计概念的介绍性文章时，即一个房间/空间会根据其中的人数自动调整。

“最近，一个名为“响应式建筑”的新兴学科开始探讨物理空间如何对通过它们的人的存在做出反应。通过嵌入式机器人技术和拉伸材料的结合，建筑师正在尝试艺术装置和墙体结构，当人群靠近时会弯曲、伸展和扩展。运动传感器可以与气候控制系统配对，根据房间内的人数调整温度和环境照明。一些公司已经生产出“智能玻璃技术”，当房间内的人数达到一定密度阈值时，玻璃会自动变得不透明，为他们提供额外的隐私层。”

这个想法是在网页设计中有类似的行为。与响应式建筑一样，网页设计应该自动调整给用户。最终目标是在每个设备上都有无缝的体验，主要是通过 CSS（媒体查询）在客户端上实现。

为了更容易理解，看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d8c73692-dc72-4636-b5f8-ed4f12add187.png)

在这个图中，你可以看到每个设备上的行为。桌面视图有三列，每列占总宽度的 33.3%。随着屏幕尺寸的减小，这个值增加到 50%，在移动视图上增加到 100%。结果，我们可以看到，内容会根据窗口大小拉伸，因此无论用户使用什么设备，内容仍然可读。

所有规则都在 CSS 文件中制定，因此 HTML 根本没有被修改。这就是为什么 CSS 媒体查询非常强大。

以下是一些良好响应式设计的例子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f462fa09-6ac1-41c5-a543-ea2c96e17058.png)

Stripe.com 上的响应式布局

来自*Stripe*网站的上述截图显示，布局完全是流动的，能够伸展和适应各种屏幕分辨率：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d6e5521a-acec-4e48-bb9d-9b5a19cb97f3.png)

Designmodo.com

来自*Designmodo*网站的上一张屏幕截图显示了非常清晰和清晰的设计，完全是响应式的。您可以看到右侧边栏在平板电脑和移动视图上都消失了。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9d86082b-27e1-4ab2-bce8-14589cd36372.png)

*Bloomberg*网站

上一张屏幕截图显示了*Bloomberg*网站。该网站以其良好的网格响应和让用户专注于内容而闻名。

# 自适应设计

而响应式设计旨在创建一个通用的外观和感觉，其中一个设计因设备而异，自适应设计则采用了不同的方法。自适应设计旨在检测用户设备并将用户重定向到专为该分辨率设计的网站。

由 Aaron Gustafson 在 2011 年的书*Adaptive Web Design: Crafting Rich Experience with Progressive Enhancement*中首次提出，自适应设计的主要区别在于在特定分辨率上有一个完全不同的网站。调整浏览器大小对设计没有影响。

自适应设计的最佳示例是[Amazon.com](http://Amazon.com)，它在平板电脑和手机上显示了一个全新的网站布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a4027ec6-af1d-471b-b07d-2ac778769929.jpg)

亚马逊网站在桌面、平板电脑和手机上。

如果您尝试调整浏览器大小，您会发现设计在 999 像素以下不会改变。

您可以使用 Google Chrome 的检查工具来测试网站的响应性或适应性。您只需右键单击并检查任何元素以打开开发者控制台，并单击小图标，如下面的屏幕截图所示。然后，您可以从左侧的下拉菜单中选择任何设备。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1bb4ffce-b9f1-4dda-aabd-2633b244e70e.png)

带有设备工具栏的 Chrome 检查器

因此，请记住，自适应网站在桌面上是看不到的，即使您调整大小，只能在相关设备上看到。

而响应式设计是在客户端使用 CSS 工作，自适应设计则是在服务器端工作。这确实是两个概念之间的主要区别。

以下是一些其他示例：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/cf3f2f5f-8631-4b64-8b80-ed2af8704392.png)

Opentable.com

上一张屏幕截图显示了*OpenTable*网站，该网站在 iPad 视图和 iPhone 视图上有一个自适应网站。看到他们如何完全改变了移动视图的布局是很有趣的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e9a45b3d-568c-4979-a996-2cf22ea42666.png)

Adidas.com

来自*Adidas*网站的上一张屏幕截图显示，*Adidas*在移动视图（[m.adidas.com](http://m.adidas.com)）上有一个完全不同的网站，外观更动态和用户友好：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/96434aca-1147-4ffc-a075-3f119b297a01.png)

最后一个例子将是 Google.com

上一张屏幕截图显示了*Google*网站。如果您还没有注意到，[Google.com](http://Google.com)在 iPad 和 iPhone 上是一个自适应网站，令人惊讶，不是吗？

# 那么哪一个是最好的呢？

响应式设计绝对更容易设计和实施。这就是为什么它是迄今为止最受欢迎的创建和设计网站的方法。

然而，它将对每个屏幕的设计控制权降低。在简单的网站上，它看起来相当简单，但在繁重和复杂的网站上，它往往会成为一个真正的头痛——在移动设备上不起作用的组件（广告）或视觉层次结构可能会变得不友好。有时，响应式网站会给人一种“未完成”的感觉，元素似乎是以适应屏幕的方式排列的，但并非为了最佳用户体验而设计。然而，还有另一种方法，即**移动优先**。这基本上是从移动设备开始设计，然后逐渐扩展到桌面。但它仍然无法解决问题。

移动优先的另一个优势是速度。研究显示，具有自适应网站的公司在加载速度测试中通常表现比响应式网站更好。这是因为响应式网站通常在桌面和移动设备上使用相同的元素/资产，而不是为移动网站具有特定的格式和大小。然而，如今，通过使用媒体查询，可以轻松地克服这个问题，如果响应式网站得到了正确的实施：

| **指标（默认）** | **自适应** | **响应式** |
| --- | --- | --- |
| 响应 | 568 毫秒 | 1,202 毫秒 |
| 文档完成 | 1,536 毫秒 | 4,086 毫秒 |
| 网页响应 | 2,889 毫秒 | 4,860 毫秒 |
| 下载的字节数 | 2,474,326 千字节 | 4,229,362 千字节 |
| 下载的对象 | 20 | 61 |

Catchpoint 进行的测试。UXPin ([`www.uxpin.com/studio/blog/Responsive-vs-Adaptive-design-whats-best-choice-designers/`](https://www.uxpin.com/studio/blog/responsive-vs-adaptive-design-whats-best-choice-designers/))。

自适应设计也有缺点。首先，设计和实施自适应设计通常比设计和实施响应式设计要多得多。管理和维护两个或更多不同的网站需要更多的基础设施和预算。

最后，虽然搜索引擎在识别`.com`和`m.com`网站方面变得更加出色，但仍然明智的是，大多数搜索引擎仍然不会平等地对待多个 URL 上的相同内容。

# 要点

响应式设计是设计跨设备网站的最流行方式。它更容易、更简单，但在设计方面可能会有限制。

| **优点** | **缺点** |
| --- | --- |
| 无缝和统一 | 较少的设计控制 |
| 对 SEO 友好 | 广告无法正常工作 |
| 更容易实施 | 加载时间稍长 |

自适应设计将被选择用于大型基础设施或复杂网站，以更好地控制设计并在各种设备上提供更好的用户体验。

| **优点** | **缺点** |
| --- | --- |
| 允许设计师构建更好的设计和用户体验 | 在设计和实施网站方面更多的工作 |
| 设计师可以优化设备上的广告 | 对于 SEO 目的来说具有挑战性 |
| 加载速度更快 |  |

没有好的或坏的做事方式。响应式设计和自适应设计只是值得理解的概念。您甚至可以在单个网站中同时使用它们，使用响应式设计用于个人电脑、笔记本电脑和平板电脑，使用自适应设计用于移动设备。只需记住这一点：在设计网站时，必须始终考虑用户的需求。

# 总结

在本章中，我们看到了响应式设计和自适应设计之间的区别。了解这些区别将有助于您在实施网站时。

现在我们已经学习了网页设计的基础知识，是时候转到另一边，建立自己的网站了。在下一章中，我们将学习 HTML 的基础知识，以及如何从头开始构建一个 HTML 页面。所以，让我们开始编写我们的第一个网站！


# 第五章：学习 HTML5

终于是时候开始构建我们的网站了。首先，您需要了解**超文本标记语言**（**HTML**）和 CSS 的基础知识。我们将从 HTML 开始，介绍 HTML 是什么。按照 HTML 文档的结构，我们将填充结构，并在途中添加一些图像和链接。

在本章中，我们将涵盖：

+   Atom，我们的文本编辑器

+   HTML 标签和属性

+   HTML 结构

+   图像和链接

所以，让我们开始吧。

# 我们的主要工具

在我们真正开始编码之前，我们需要下载一个文本编辑器。这是一个基本上用来编写我们所有代码的程序。在本课程中，我们将使用 Atom；您可以通过此 URL（[`atom.io/`](https://atom.io/)）下载该工具。该程序适用于 macOS、Windows 和 Linux，而且完全免费！

如果您熟悉其他文本编辑器，完全可以使用您自己的。还有一些其他非常好的免费编辑器，如 Sublime Text 3（[`www.sublimetext.com/`](https://www.sublimetext.com/)）、Bracket（[`brackets.io/`](http://brackets.io/)）和 Dreamweaver（[`www.adobe.com/products/dreamweaver.html`](https://www.adobe.com/products/dreamweaver.html)）。

一旦您有了文本编辑器，我们就可以开始课程了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/08310e57-09c8-4f8d-9086-851724993956.png)

ATOM 文本编辑器

首先，我们需要创建一个文件夹来放置所有我们的项目文件。让我们创建这个文件夹并将其命名为`Racing Club Website`。完成后，将此文件夹打开为我们的项目文件夹。单击文件|添加项目文件夹...：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/fbf980d9-7c88-412f-8f9a-3fbba4f97cfb.png)

既然我们已经安装了超级文本编辑器并设置了项目文件夹，让我们谈谈 HTML。

# 什么是 HTML？

HTML 是用于创建网页和 Web 应用程序的标准标记语言。结合 CSS 和 JavaScript，您可以创建简单和复杂的网站。

每个网页实际上都是一个 HTML 文件。每个 HTML 文件只是一个纯文本文件，但扩展名为`.html`而不是`.txt`。

# HTML 标签

HTML 标签是定义您如何对元素和内容进行排序和显示的隐藏关键字。大多数 HTML 标签都有两个部分，一个开放部分和一个关闭部分：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4c73cc9b-6edf-4afd-824d-79d822b5ac66.png)

请注意，关闭标签与开放标签具有相同的文本，但有一个额外的斜杠（`/`）字符。

也有一些例外，比如 HTML 标签`<img>`没有闭合标签：

```html
<tagname>Content</tagname>
```

要查看 HTML 文档，您需要一个网页浏览器，如 Google Chrome、Mozilla Firefox、Internet Explorer 或 Safari。

# HTML 属性

属性是用于自定义标签的内容，并且它们是在标签内定义的，例如：

```html
<img src="img/image.jpg">
```

大多数标签的属性是可选的，通常用于更改标签的默认状态。但是，某些标签，如`<img>`标签，需要`src`和`alt`等属性，这些属性对于浏览器正确显示图像是必需的。

# HTML 结构

每个 HTML 都遵循一种结构，以便浏览器能够读取页面。总结一下，它总是以`<html>`标签开头。此标签将包含`<head>`标签和`<body>`标签。让我们创建我们的第一个页面，这样您就可以理解了。

# 创建我们的第一个页面

要创建我们的第一个页面。单击文件|新建文件或*Command* + *N*（或*Ctrl* + *N*适用于 Windows）。

您现在有一个无标题文件。让我们快速保存并命名它，方法是单击文件|保存或*Command* + *S*（或*Ctrl* + *S*适用于 Windows），然后将其命名为`index.html`。

为什么要命名为`index.html`？因为`index.html`页面是在访客请求站点时默认显示的默认页面的常用名称。换句话说，`index.html`基本上是网站的主页名称。

现在我们有了我们的第一个 HTML 文件，我们必须放入必要的标签才能使其工作。必要的标签应按以下方式编写：

```html
<html>  <!--This is our HTML main tag-->
 <head>  <!--This is our head tag where we put our title and script and all infos relative to our page.-->
  <title>My Page Title</title>
 </head>
 <body> <!--This is where all our content will go-->

  This is where all my web page content goes!

 </body>
</html>

```

只需将代码复制粘贴到你的 HTML 文件中，并用你的互联网浏览器打开文件（我们将选择 Google Chrome）。不要忘记保存你的文档！

你的网页应该如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2b5ffab8-9591-4e92-81e1-b03e62689567.png)

在 Google Chrome 中打开的网页

恭喜！你刚刚创建了你的第一个网页！

现在让我们向我们的页面添加一些其他元素。

# HTML 元素

HTML 中有许多不同的元素，它们都是为不同的目的而设计的。不是必须要了解所有的元素，但是一些对于网站来说是必不可少的。以下是 HTML 中的一些基本元素。

# 标题和段落

要在 HTML 中插入标题，有一个名为`<h1>`的标签，一直到`<h6>`。数字由标题的重要性决定。

让我们把一个`<h1>`元素放到我们的`<body>`中：

```html
<html> <!--This is our HTML main tag-->
 <head> <!--This is our head tag where we put our title and script and all infos relative to our page.-->
  <title>My Page Title</title>
 </head>
 <body> <!--This is where all our content will go-->
  <h1>John Doe</h1>

 </body>
</html>
```

现在我们有了我们的第一个标题。让我们添加一个段落。要添加一个段落，我们可以使用 HTML 标签`<p>`：

```html
<h1>John Doe</h1>
  <p>I'm an amazing Designer</p>
```

你之前学到，对于每个 HTML 标签，我们有一个开放的`<tagname>`标签和一个关闭的`</tagname>`标签。这基本上是告诉你你的元素何时结束。你也可以在一个标签内添加另一个标签。例如，如果我们想要使一些文本**加粗**。

让我们使用我们的`<p>`标签，并在`amazing`单词中添加一个`<b>`标签使其加粗：

```html
<p>I'm an <b>amazing</b> Designer</p>
```

这是你在浏览器中应该看到的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d55513af-c3e3-4f79-af60-359b777c873a.png)

太棒了！你刚刚把文本加粗了！现在让我们添加一些表单。

使用表单，无论你想从用户那里获取什么类型的信息，你都需要使用`<input>`标签来获取它们。

有许多不同类型的输入，但是，现在我们将涵盖`email`和`submit`。

`input`标签是不需要闭合标签的例外之一；让我们把它添加到我们的段落中：

```html
<input type="email">
```

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ebf57f83-04d6-4698-9b73-9068aee54357.png)

HTML 属性

你可以把属性看作是每个标签的选项

但是`email`输入如果没有提交按钮就不会有任何作用！让我们添加另一个输入类型，`submit`：

```html
<input type="submit">
```

让我们看看我们现在有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d7941345-6943-42f8-82f6-726032dabbb7.png)

这是你在浏览器中应该看到的。用*Ctrl*（或*Cmd*）+ *S*保存你的 HTML 文档，然后刷新你的浏览器。

太棒了！但是我们可能会有一点问题。我们实际上没有说用户应该在`email`输入中输入什么。幸运的是，有一个名为`placeholder`的属性，让我们可以向我们的输入添加默认文本，这样用户就知道应该输入什么：

```html
<input type="email" placeholder="Your email">
```

太棒了！现在你可以在我们的电子邮件输入中看到我们的占位符。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/696a0ad2-9ca5-4f2c-b3dc-7dbbaaa6577a.png)

这是你在浏览器中应该看到的。用*Ctrl*（或*Cmd*）+ *S*保存你的 HTML 文档，然后刷新你的浏览器。

# 链接和图片

我们的最后一部分将是添加图片和链接。

网页如果没有图片会很无聊。要添加一张图片，你需要添加一个`<img>`标签：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/5d96c311-989e-4f6a-ae7f-8183b2635d5c.png)

img 标签结构

你需要添加`src`属性来放置你的图片位置。

但首先，让我们创建一个文件夹来放置我们所有的图片。回到你之前创建的主文件夹`Racing Club Website`。在里面，让我们创建一个名为`images`的文件夹。

在 GitHub 上的代码包中的`Images`文件夹中，你可以看到一个名为`designer.jpg`的图片；让我们把这张图片复制粘贴到我们的`images`文件夹中。

现在我们在`images`文件夹中有了图片，我们可以将它链接到我们的`img`标签。为此，添加以下内容：

```html
<img src="img/designer.jpg">
```

你可以在`src`属性中放置两种不同类型的 URL。相对 URL，比如我们放置的这个，只有在链接到与当前页面相同域的文件时才有效。因为我们是在本地进行操作，所以被视为相同域。绝对 URL，包括`http://`的 URL，会将你引导到图片目录，例如`http://philippehong.com/img/image-example.jpg`。

现在让我们添加一个链接。链接使用`<a>`标签和`href`属性添加。

您可以在`href`属性中放入两种不同类型的 URL，就像您可以为图像一样。这次让我们放入一个绝对 URL，添加我们的 Twitter 页面：

```html
<a href="http://twitter.com/philippehong">My Twitter</a>
```

但我们仍然需要在`<a>`标签内添加一些文本才能使其可见。

您的 HTML 文档应如下所示：

```html
<html> <!--This is our HTML main tag-->
  <head> <!--This is our head tag where we put our title and script and all infos relative to our page.-->
    <title>My Page Title</title>
  </head>
  <body> <!--This is where all our content will go-->

    <h1>John Doe</h1>
    <p>I'm an <b>amazing</b> Designer</p>
    <input type="email" placeholder="Your email">
    <input type="submit">
    <img src="img/designer.jpg">
```

```html
    <a href="http://twitter.com/philippehong">My Twitter</a>

  </body>
</html>
```

请注意，您可以看到代码已经准备就绪。让我们保存我们的 HTML 文档，看看它在我们的互联网浏览器中的效果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8e7fe83a-ed2a-4580-88a7-ef88046201a9.png)

这是您在浏览器中应该看到的内容。使用*Ctrl*（或*Cmd*）+ *S*保存您的 HTML 文档，然后刷新您的浏览器。

它看起来非常简单，但这是因为我们没有添加任何 CSS。

# 摘要

在本章中，我们学习了 HTML 的所有基础知识。我们了解了 HTML 标签、属性，以及 HTML 页面的整体结构。

在我们进入下一章之前，我们在本章学习的标签并不是 HTML 中唯一可用的标签。HTML 中有很多标签，您可以在本书末尾的术语表中查看它们。当我们创建自己的项目时，我们还将使用一些新的标签！现在让我们给我们的页面添加一些样式！


# 第六章：学习 CSS3

**层叠样式表**（**CSS**）允许您控制 HTML 内容的样式，更改颜色、字体、布局等。它相当容易理解，在本章中，我们将解决以下主题：

+   使用 CSS 的方法

+   CSS 格式

+   父元素和子元素

+   类和 ID

+   CSS 框模型

+   CSS 布局和分隔符

# 使用 CSS 的不同方法

有三种使用 CSS 的方法：

+   在具有`style`属性的 HTML 标签内（这种方法不推荐，但您仍然可以稍微使用）：

```html
<p style'"font-size:12px"></p>
```

+   在具有`<style>`标签的 HTML 文档的`<head>`部分内：

```html
<style>
  p {
    font-size:12px;
  } 
</style>
```

+   CSS 代码也可以放入外部文件中，并使用`<link>`标签链接到 HTML 文档。文件扩展名将保存为`.css`文件：

```html
<link rel="stylesheet" href="css/style.css">
```

对于此示例，我们将使用第二个选项，但是当我们开始构建自己的网站时，我们将学习第三个选项。

让我们从在`<head>`部分中添加`<style>`标签开始：

```html
<head> <!--This is our head tag where we put our title and script and all infos relative to our page.-->
  <title>My Page Title</title>
  <style>

  </style>
 </head>
```

# CSS 格式

我们现在准备好放入我们的 CSS，那么 CSS 的格式如何？

CSS 很简单理解：

+   **选择器**：这是您选择要添加样式的 HTML 元素的位置。在此示例中，我们选择所有`<h1>`元素。

+   **大括号**：这些括号内的所有样式将应用于选择器选择的 HTML 元素

+   **属性**：属性控制 HTML 元素样式的一个方面，例如 text-align、color、width、background 等。

+   **值**：值传递给属性。在这种情况下，text-align 的值可以是 left、right、center 或 justify。

+   **分号**：在属性的末尾应用它是强制性的。

您可以在同一个`<style>`标签中拥有多个样式。让我们居中所有`h1`和`p`标签。

您应该有以下内容：

```html
<style>
 h1 {
  text-align: center;
 }
 p {
  text-align: center;
 }
</style>
```

# 父元素和子元素

如果您想要居中所有文本而不仅仅是`<h1>`和`<p>`？有一种简单的方法可以实现。您必须了解父元素和子元素。基本上，如果您为父元素设置样式，则所有子元素将具有相同的样式，除非您为子元素指定特定样式。以下是我们的示例：

```html
<body> <!--This is our parent element -->
  <h1>John Doe</h1>
  <p>I'm an <b>amazing</b> Designer</p>
  <input type="email" placeholder="Your email">
  <input type="submit">
  <img src="img/designer.jpg">
  <a href="http://twitter.com/philippehong">My Twitter</a>
</body>
```

`<body>`标签是其中包含的每个元素的父元素，其中包括`<h1>`、`<p>`、`<input>`、`<img>`和`<a>`元素。

让我们删除以前的样式，并使用`text-align: center;`样式`<body>`元素：

```html
<style>
  body {
    text-align: center;
  }
</style>
```

让我们保存 HTML 文档并在 Chrome 中重新加载页面。请注意，每个元素都具有属性`text-align: center;`。

# 类和 ID

我们已经了解了如何使用 CSS 选择 HTML 标签，但是大多数情况下，您将拥有多个相同的 HTML 标签，例如`<p>`或`<a>`。我们如何区分它们，以便只选择和设置特定的样式？这就是类和 ID 的作用。它们用于选择您已经放置了`id`或`class`属性的特定 HTML 标签，例如：

```html
<div id="header"></div>
<p class="big"></p>
```

要在 CSS 中选择此 ID `header`，我们需要写一个井号（`#`）字符，后面跟着元素的 ID，在本例中是`header`：

```html
#header {
  margin-left: 10px;
}
```

要选择类，我们需要写一个句点（`.`）字符，后面跟着类的名称：

```html
.big {
  font-size:20px;
}
```

那么 ID 和类之间有什么区别？唯一的区别是 ID 在 HTML 文档中只能使用一次，而类可以多次使用。我们还需要知道以下内容：

**对于 ID：**

+   每个元素只能有一个 ID

+   每个页面只能有一个具有该 ID 的元素

**对于类：**

+   您可以在多个元素上使用相同的类

+   您可以在同一个元素上使用多个类

例如，我们可以有以下内容：

```html
<div id="header" class="big red blue"></div>
```

这意味着`<div>`元素具有 ID `header` 和类 `big`、`red` 和 `blue`。

现在让我们在文档中添加一些类和 ID：

```html
<body> <!--This is our parent element -->

  <h1 id="my-name">John Doe</h1>
   <p class="text">I'm an <b>amazing</b> Designer</p>
   <input class="form" type="email" placeholder="Your email">
   <input class="button" type="submit">
   <img class="image" src="img/designer.jpg">
   <a class="link" href="http://twitter.com/philippehong">My Twitter</a>

</body>

```

正如您所看到的，我添加了一些非常简单的 ID 和类，以便您了解它是如何工作的。当涉及到使用 ID 和类的最佳实践时，我们将详细介绍。

现在我们有了我们的 ID 和类，让我们为我们的 CSS 添加一些样式。 为此，让我们选择我们的第一个 ID`my-name`，并使其更大和带下划线。 为此，我们将使用 CSS 属性`font-size`和`text-decoration`：

```html
<style>
  body {
    text-align: center;
  }
  #my-name{
    font-size: 50px;
    text-decoration: underline;
  }
</style>
```

现在让我们来设置一些类。 例如，让我们在我们的 HTML 文档中添加另一个`<p>`标签，就在我们的链接之前，如下所示：

```html
<body> <!--This is where all our content will go-->

  <h1 id="my-name">John Doe</h1>
  <p class="text">I'm an <b>amazing</b> Designer</p>
  <input class="form" type="email" placeholder="Your email">
  <input class="button" type="submit">
  <img class="image" src="img/designer.jpg">
  <p class="text">Follow me on Twitter</p> <!--Added text-->
  <a class="link" href="http://twitter.com/philippehong">My Twitter</a>

</body>
```

现在我们有两个具有相同类的元素，让我们看看当我们想要通过添加`font-family`属性来样式化类`text`时会发生什么：

```html
<style>
  body {
    text-align: center;
  }
  #my-name{
    font-size: 50px;
    text-decoration: underline;
  }
  .text {
    font-family: Arial;
  }
</style>
```

保存您的 HTML 文档并刷新您的浏览器。 这是您应该看到的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/99bbee69-1a09-4146-ae89-4e65e2da8577.png)

这应该改变具有类`text`的元素的字体。 您可以看到两个元素都已更改。

# CSS 框模型

所有 HTML 元素都可以看作是框。 CSS 框模型允许我们定义元素之间的空间。 无论您想要添加边框、设置边距还是在元素之间添加填充，您都需要了解框模型。 在实施设计时，了解这一部分将对您有很大帮助。

# 盒子

框模型由四个属性组成：

+   **内容**：文本、图像等

+   **填充**：内容周围的透明区域，位于框内

+   **边距**：盒子之间的空间

+   **边框**：围绕填充和内容

请查看以下图表，以便更好地理解：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/aee4c299-0b14-4ac8-b2c8-f1e47aefeaff.png)

CSS 框模型可以如前图所示描述。

框模型还可以让我们设置元素的高度和宽度。 通过以下设置内容的宽度或高度：

```html
Width: 200px;
```

内容的宽度将为`200px`。

现在，标准框模型的讨厌之处在于，您只能设置内容的宽度和高度，而不能设置整个框本身的宽度和高度，这意味着填充、边距和边框将添加到我们指定的宽度和高度中。 这相当让人讨厌：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4823925c-1284-49ce-82bb-1637090149e6.png)

使用属性 content-box 的框模型

幸运的是，我们可以通过使用`box-sizing`属性来抵消这一点：

```html
box-sizing: border-box; 
```

通过将`box-sizing`设置为`border-box`，我们现在将设置整个框的宽度和高度：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0287cf02-8112-4755-a854-6fa32121f4ab.png)

使用属性 border-box 的框模型

# 块和内联

关于框模型还有最后一件事。 在 HTML 中，有我们所谓的块级元素和内联元素。

**块级元素**：它使用浏览器的整个宽度，并始终从新行开始。 您可以将它们视为需要一个接一个地堆叠的块。 标题和段落是块级元素的一些示例。

块级元素的示例：

+   `<div>`

+   `<h1> - <h6>`

+   `<p>`

+   `<form>`

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/7fe727ed-87c1-4b62-8889-194ea32e1d13.png)

块级元素用红色框表示

**内联元素**：内联元素不会从新行开始，只会占据必要的宽度。 看一下蓝色元素的示例：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/64816021-55cf-4e95-878c-8fc6d9aeb1d4.png)

内联元素用蓝色框表示

以下是内联元素的示例：

+   `<span>`

+   `<a>`

+   `<img>`

# CSS 布局和分隔符

现在我们了解了框模型的工作原理，我们可以尝试为我们的 HTML 页面构建一个简单的布局，如下图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/98e5d3ff-bc29-4e2d-8926-6e7252a5070c.png)

我们的布局将有一个带有右侧边栏的容器，并在底部有一个页脚。 这是许多网站的非常基本的布局。

此布局将位于一个容器内，该容器将居中于页面。 没有多余的话，让我们开始吧！

# 基本布局

为了创建我们的基本布局，我们将使用`<div>`元素。 `<div>`元素是最常用的 HTML 元素。 `<div>`代表分割，我们只是用它来通过创建放置内容的框来将我们的页面分成部分。

让我们在`<style>`部分清除我们的 CSS，从头开始。

我们将首先添加一个`<div>`元素来包装我们创建的所有内容，然后给它添加一个类`container`：

```html
   <div class="container">
     <h1 id="my-name">John Doe</h1>
     <p class="text">I'm an <b>amazing</b> Designer</p>
     <input class="form" type="email" placeholder="Your email">
     <input class="button" type="submit">
     <img class="image" src="img/designer.jpg">
     <p class="text">Follow me on Twitter</p> <!--Added text-->
     <a class="link" href="http://twitter.com/philippehong">My Twitter</a>
   </div> 
```

# 格式化和缩进您的 HTML

您可以在我的 HTML 文档中看到我的代码是缩进的。代码缩进适用于每种语言，使其更易于阅读和结构化。缩进的基本方法是使用*Tab*键将内容向右移动一步：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f4cc43ae-dd2e-4ce9-9ebb-639032fd7a72.png)

这是您应该具有的基本结构和缩进。

# 样式化我们的类

让我们首先对我们刚刚创建的`container`类进行样式化。为此，让我们转到我们的`<style>`部分并添加以下内容：

```html
<style>
  .container {
    width: 960px; 
  } 
</style>
```

这将把`width`属性设置为具有类`container`的`<div>`为`960px`。

我们希望我们的容器居中显示在页面上。为了做到这一点，我们需要添加`margin`属性，如下所示：

```html
<style>
  .container {
    width: 960px;
    margin-left: auto;
    margin-right: auto;
  }
</style>
```

添加`margin-left: auto;`和`margin-right: auto;`意味着左右边距会根据元素的上下文（在这种情况下是浏览器窗口）自动调整：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/21a73c75-1f74-4283-90c4-24965d6a6344.png)

有很多种方法可以使用 CSS 来使元素居中；这是第一种方法。我们将在接下来的章节中了解其他几种方法。

现在让我们按照我们想要的布局创建我们的`content`元素。

在我们的`<div class = "container">`内部，让我们添加我们的`<div class = "content">`。同样，让我们将我们的内容移动到这个`div`中，如下所示：

```html
<body> <!--This is where all our content will go-->
 <div class="container">
   <div class="content">
     <h1 id="my-name">John Doe</h1>
     <p class="text">I'm an <b>amazing</b> Designer</p>
     <input class="form" type="email" placeholder="Your email">
     <input class="button" type="submit">
     <img class="image" src="img/designer.jpg">
     <p class="text">Follow me on Twitter</p> <!--Added text-->
     <a class="link" href="http://twitter.com/philippehong">My Twitter</a>
   </div>
 </div>
</body>
```

接下来，让我们添加我们的`sidebar`。在我们的`<div class= "content">`之后，添加一个带有类`sidebar`的`div`。

在我们的`sidebar`内部，添加一个`<p>`元素来创建一些内容：

```html
<div class="sidebar">
   <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis turpis neque, volutpat ac consequat sed, ullamcorper at dolor. Donec placerat a mi quis ultricies. Etiam egestas semper tempor. Suspendisse nec eros porta, rhoncus tortor sed, consequat arcu. Suspendisse potenti. Nunc blandit nisl eu justo feugiat vestibulum. Vivamus consequat, quam vitae sagittis maximus, magna lacus fringilla justo, sit amet auctor mi nulla quis ante. Morbi malesuada gravida turpis, vel lobortis libero placerat sit amet. Vestibulum sollicitudin semper est eget ultricies. Donec posuere turpis urna.
  </p>
</div>
```

您可以通过访问网站[`www.lipsum.com/`](https://www.lipsum.com/)找到一些虚拟文本。

最后，让我们在`sidebar`元素之后添加我们的`footer`元素：

```html
<div class="footer">
  <p>This is my footer</p>
</div>
```

我们的 HTML 文档现在应该如下所示：

```html
<html> <!--This is our HTML main tag-->
 <head> <!--This is our head tag where we put our title and script and all infos relative to our page.-->
  <title>My Page Title</title>
  <style>
    .container {
      width: 960px;
      margin-left: auto;
      margin-right: auto;
    }
  </style>
 </head>
 <body> <!--This is where all our content will go-->
   <div class="container">
     <div class="content">
       <h1 id="my-name">John Doe</h1>
       <p class="text">I'm an <b>amazing</b> Designer</p>
       <input class="form" type="email" placeholder="Your email">
       <input class="button" type="submit">
       <img class="image" src="img/designer.jpg">
       <p class="text">Follow me on Twitter</p> <!--Added text-->
       <a class="link" href="http://twitter.com/philippehong">My Twitter</a>
     </div>
     <div class="sidebar">
       <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis turpis neque, volutpat ac consequat sed, ullamcorper at dolor. Donec placerat a mi quis ultricies. Etiam egestas semper tempor. Suspendisse nec eros porta, rhoncus tortor sed, consequat arcu. Suspendisse potenti. Nunc blandit nisl eu justo feugiat vestibulum. Vivamus consequat, quam vitae sagittis maximus, magna lacus fringilla justo, sit amet auctor mi nulla quis ante. Morbi malesuada gravida turpis, vel lobortis libero placerat sit amet. Vestibulum sollicitudin semper est eget ultricies. Donec posuere turpis urna.</p>
     </div>
     <div class="footer">
       <p>This is my footer</p>
     </div>
   </div>
 </body>
</html>

```

现在，出于本课程的目的，让我们为每个元素添加一些背景颜色，以查看布局的工作原理。为此，让我们转到我们的样式部分，并为每个类添加`background-color`属性，如下所示：

```html
<style>
  .container {
    width: 960px;
    margin-left: auto;
    margin-right: auto;
  }
  .content {
    background-color: red;
  }
  .sidebar {
    background-color: green;
  }
  .footer {
    background-color: blue;
  }
</style>

```

现在我们将保存我们的 HTML 文档并刷新我们的浏览器以查看它的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1b25bc05-d0e6-49a4-b93d-a72a6ebc74c3.png)

我们的网页看起来很丑，但它确实展示了布局是如何组合在一起的。让我们添加一些 CSS 属性，使其看起来符合我们的期望。

我们希望`.content`元素占总宽度（960px）的`75%`，而侧边栏占`25%`。我们可以进行一些数学计算，计算 960 的`75%`，但是在 CSS 中，您也可以按百分比设置`width`：

```html
.content {
  background-color: red;
  width: 75%;
}
.sidebar {
  background-color: green;
  width: 25%;
}

```

现在我们将保存我们的 HTML 文档并刷新我们的浏览器以查看它的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2f2c0dbb-2245-470c-ac25-1d64bccd7683.png)

如您所见，我们的元素的宽度属性为`75%`和`25%`。现在，为了将我们的`sidebar`移到内容旁边，我们需要使用名为`float`的 CSS 属性。使用`float`，元素可以被推到左侧或右侧，从而允许其他元素围绕它包裹。所以让我们这样做：

```html
.content {
  background-color: red;
  width: 75%;
  float: left;
}
.sidebar {
  background-color: green;
  width: 25%;
  float: right;
}

```

让我们保存我们的 HTML 文档并刷新我们的浏览器以查看它的外观：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6ca44f34-c5ac-4bd0-91f6-14139b76d741.png)

我们的内容和`sidebar`现在并排显示，但问题是我们的`footer`在右侧，因为它具有来自`sidebar`的`float`右侧的属性。为了避免这种情况，我们需要使用`clear`属性，它与`float`属性相对应。我们将属性设置为 both，这意味着右侧和左侧：

```html
.footer {
  background-color: blue;
  clear: both;
} 
```

保存并刷新文档。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ac60a70b-5f3c-40ca-bc0d-e55b5554e891.png)

我们现在已经完全使用 CSS 编写了我们的布局。

# 总结

我们现在终于有了我们的布局。再次强调，本课程不是为了做出漂亮的东西，而是为了帮助您了解如何正确使用 CSS 布局页面。在下一章中，我们将深入研究 HTML 和 CSS，通过创建和设计我们的网站来学习—多么令人兴奋！


# 第七章：创建您自己的网站

有趣的部分终于来了。我们将从头到尾开始实施我们的网站。我将逐步解释每个步骤。以下是本章将涵盖的内容列表：

+   安装 HTML 样板

+   使用图像、字体和 normalize.css 设置我们的项目

+   创建我们的页眉并美化它

+   创建我们的主要部分并学习 CSS 中的定位

+   创建我们的博客部分

+   添加关于部分

+   创建合作伙伴部分

+   创建页脚部分

首先，让我们看看我们将要实施的设计。如果您还记得，我们在第四章中看到了一个小预览，*响应式与自适应设计*。

# 我们的设计

我们的主页将包括以下内容：

1.  页眉：我们将学习如何创建和美化一个导航部分，带有标志和右侧菜单。

1.  主要图像：在网页设计中，它描述了一个前端横幅图像，通常是一个大图像。我们将学习如何创建一个带有大标题的全宽背景图像。

1.  带有六篇博客文章的`Blog`预览：我们将学习如何显示带有图像和内容的三个响应式列。

1.  关于我们部分：我们将学习如何向图像添加渐变。

1.  合作伙伴部分：我们将学习如何在页面上居中内容。

1.  页脚：基本上与页眉相同，但在底部。

您可以在我提供的资源文件中的`Resources` | `Screens`中查看主页的完整尺寸图像。项目还包括`Sketch`源文件。

我强烈建议您安装 Sketch 或 Figma，如果您还没有使用这些设计工具之一。Sketch 应用程序通常用于 Web 设计项目，可以在[`sketchapp.com`](http://sketchapp.com)下载。它有 14 天的免费试用期。Figma 类似于 Sketch，可以在没有试用期的情况下使用。

这就是我们的设计长什么样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/950045cf-145c-433e-8386-f5f70342876b.png)

我们的主页设计

话不多说，让我们开始吧！

# 安装 HTML 样板

我们将从头开始，因此让我们为这个项目创建一个新文件。当我开始一个项目时，我喜欢下载一个 HTML 样板。HTML5 样板是一个前端模板，旨在帮助您构建快速、强大和适应性强的 Web 应用程序或站点。您基本上只需下载一个包，它包含了开始项目所需的所有文件。

让我们去[`html5boilerplate.com/`](https://html5boilerplate.com/)下载模板的最新版本：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/bf458b1b-e3c9-418b-9b43-fb32cdfdaee0.png)

单击下载 v6.0.1 或更高版本。

让我们看看我们的包里有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c25985c3-e6d4-42c4-9592-77cd698dd7ab.png)

文件夹中有很多文件。我们可以看到，它包含了网站正常运行所需的所有基本文件：

+   `index.html`：我们的主页，用户访问网站时会首先看到的页面

+   `css`文件夹：存放所有 CSS 文件的文件夹

+   `img`文件夹：存放所有图像的文件夹

+   `js`文件夹：存放所有 JS 文件的文件夹

+   `favicon.ico`：显示在浏览器标签左上角的图标，向用户指示他们正在访问您的网站，通常是您的标志

+   `404.html`：一个用于错误 URL 的用户的 HTML 页面

其他文件对我们目前来说并不那么重要；我们将在即将到来的章节中进行审查。

让我们将文件夹重命名为我们自己的名字，例如`Web 项目`。

# 编辑 index.html

现在让我们在 Atom 中打开我们的文件夹；单击菜单|打开… |并选择我们的`Web 项目`文件夹。

从左侧面板选择`index.html`。您可以看到 HTML 文档及其内容：

```html
<!doctype html>
<html class="no-js" lang="">
  <head>
      <meta charset="utf-8">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <title></title>
      <meta name="description" content="">
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <link rel="manifest" href="site.webmanifest">
      <link rel="apple-touch-icon" href="icon.png">
      <!-- Place favicon.ico in the root directory -->

      <link rel="stylesheet" href="css/normalize.css">
      <link rel="stylesheet" href="css/main.css">
  </head>
  <body>
      <!--[if lte IE 9]>
          <p class="browserupgrade">You are using an <strong>outdated</strong> browser. Please <a href="https://browsehappy.com/">upgrade your browser</a> to improve your experience and security.</p>
      <![endif]-->

      <!-- Add your site or application content here -->
      <p>Hello world! This is HTML5 Boilerplate.</p>
      <script src="img/modernizr-3.5.0.min.js"></script>
      <script src="img/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
      <script>window.jQuery || document.write('<script src="img/jquery-3.2.1.min.js"><\/script>')</script>
      <script src="img/plugins.js"></script>
      <script src="img/main.js"></script>

      <!-- Google Analytics: change UA-XXXXX-Y to be your site's ID. -->
      <script>
          window.ga=function(){ga.q.push(arguments)};ga.q=[];ga.l=+new Date;
          ga('create','UA-XXXXX-Y','auto');ga('send','pageview')
      </script>
      <script src="img/analytics.js" async defer></script>
  </body>
</html>
```

现在我们将逐个审查此 HTML 文件的每个部分，以便您了解代码的每个部分：

```html
<title></title>
```

在这里，您将放置我们网站的标题；在这个练习中，让我们把标题设为“赛车俱乐部-活动和门票”。

```html
<meta name="description" content="">
```

这一部分是页面的描述，对于 SEO 很有用，并且会在标题之后出现在搜索结果中。

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

这将告诉浏览器如何在桌面和移动视图中行为。你可以保持原样。

```html
<link rel="stylesheet" href="css/normalize.css">
<link rel="stylesheet" href="css/main.css">
```

我们在上一章中学到，在我们的 HTML 页面中使用 CSS 有三种不同的方法。我们在练习中使用了第二种方法，但是使用 CSS 的最佳方式是将其放入一个外部文件中，就像这样。你可以保持原样。

```html
<!--[if lte IE 9]>
    <p class="browserupgrade">You are using an <strong>outdated</strong> browser. Please <a href="https://browsehappy.com/">upgrade your browser</a> to improve your experience and security.</p>
<![endif]-->
```

这基本上是为了建议使用 Internet Explorer 9 或更低版本的用户更新他们的互联网浏览器。你不需要改变这段代码。

```html
<!-- Add your site or application content here -->
 <p>Hello world! This is HTML5 Boilerplate.</p>
```

这是我们的内容。我们将编辑 HTML 的这部分来在我们的 HTML 页面中添加元素和内容。你可以删除`<p>`元素，因为我们不需要它。

以下代码包含了链接到我们页面的 JavaScript 插件的列表：

```html
<script src="img/modernizr-3.5.0.min.js"></script>
<script src="img/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
<script>window.jQuery || document.write('<script src="img/jquery-3.2.1.min.js"><\/script>')</script>
<script src="img/plugins.js"></script>
<script src="img/main.js"></script>

<!-- Google Analytics: change UA-XXXXX-Y to be your site's ID. -->
<script>
    window.ga=function(){ga.q.push(arguments)};ga.q=[];ga.l=+new Date;
    ga('create','UA-XXXXX-Y','auto');ga('send','pageview')
</script>
<script src="img/analytics.js" async defer></script>
```

插件如下：

+   `modernizr`：检测用户的浏览器并相应地改变网站的行为。

+   `Jquery`：我们将在下一章中使用这个框架来创建交互和动画。

+   `Plugin.js`：包含我们需要的所有其他插件。

+   `Main.js`：包含我们将创建的所有 JS 代码。

+   `Google Analytics`：用于分析用户并帮助了解你的网站表现的分析插件。我们将在第十章，*优化和发布我们的网站*中介绍这个。

让我们开始编辑我们的网页！

# 创建我们的网页

现在一切都准备好了，让我们开始整理我们的图片文件夹并安装我们的字体。

# 图片文件夹

我已经准备了一个包含所有你需要的图片的文件夹来进行这个练习。这些图片可以在`Resources` | `Image Web project`中找到。你可以简单地将所有图片和资源复制到我们新项目文件夹中的`img`文件夹中。

# 安装我们的字体

如果你再看一下网站，你会发现我们正在使用自定义字体，这意味着我们没有使用网页*安全*字体。网页安全字体是预装在每台设备上的字体。它们出现在所有操作系统上。这些字体集合被 Windows、Mac、Google、Linux、Unix 等使用。

可能还有一些，但这是常见的网页安全字体列表：

+   Arial

+   Helvetica

+   Times New Roman

+   Courier New

+   Courier

+   Verdana

+   Georgia

+   Comic Sans MS

+   Trebuchet MS

+   Arial Black

+   Impact

不是很吸引人；坦率地说。

但是，有了 CSS3，我们现在可以通过使用`@font-face`来添加自定义字体。让我们看看如何添加这个：

```html
@font-face
```

为了这个练习，我提供了一个名为`fonts.zip`的压缩文件，以便让你更容易。你可以解压这个文件，然后将`fonts`文件夹移动到我们的`Web Project`文件夹中。让我们看看这个文件夹里有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1b09f29a-51b1-449f-8c81-deb3334a918d.png)

它包含了网页所需的字体文件，并且可以直接使用。

要在网页上使用自定义字体，我们需要事先生成或转换这个字体为网页字体。你可以使用网站[fontsquirrel.com](http://fontsquirrel.com)从你自己的字体生成网页字体。

还有一个使用`@font-face`属性的 CSS 文件：

```html
@font-face {
  font-family: 'built_titling';
  src: url('built_titling_rg-webfont.woff2') format('woff2'),
       url('built_titling_rg-webfont.woff') format('woff');
  font-weight: 400;
  font-style: normal;
}

@font-face {
  font-family: 'built_titling';
  src: url('built_titling_el-webfont.woff2') format('woff2'),
       url('built_titling_el-webfont.woff') format('woff');
  font-weight: 200;
  font-style: normal;
}
```

因此，让我们将这个 CSS 文件链接到我们的 HTML 文件中。在我们的`index.html`中，让我们添加以下内容：

```html
<link rel="stylesheet" href="fonts/font.css"> <!-- Font face CSS link -->

<link rel="stylesheet" href="css/normalize.css">
<link rel="stylesheet" href="css/main.css">
```

很好，我们现在已经将我们的字体链接到我们的 HTML 页面。现在让我们添加我们的第二个字体，这是一个谷歌字体。

# 导入谷歌字体

自 2010 年以来，谷歌为用户提供了一个发现字体并免费使用的平台。谷歌字体的主网站上提供了 800 多种字体系列，我们将在这个练习中使用其中的一种。

谷歌让导入字体变得非常容易。以下是在我们的网站上引入字体的步骤：

1.  前往谷歌字体网站（[`fonts.google.com/`](https://fonts.google.com/)）。

1.  搜索我们的字体，Roboto，并点击相应的字体（[`fonts.google.com/specimen/Roboto`](https://fonts.google.com/specimen/Roboto)）。

1.  点击选择这个字体。

1.  点击底部的小弹出窗口，切换到自定义选项卡。

1.  我们希望有常规和粗体。

1.  切换回 EMBED 选项卡并复制显示的代码：

```html
<link href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet">
```

1.  在我们之前的 CSS 链接之前粘贴此代码：

```html
<link href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet">
<link rel="stylesheet" href="fonts/font.css"> <!-- Font face CSS link -->

```

您现在已安装了 Google 字体！

现在，要使用我们的 Google 字体，只需在我们要样式化的元素上粘贴 CSS 属性：

```html
font-family: 'Roboto', sans-serif;
```

让我们去我们的 CSS 文件，位于`css` | `main.css`。

找到以下注释的部分：

```html
/* ==========================================================================
   Author's custom styles
   ========================================================================== */
```

在这里，写：

```html
body {
  font-family: 'Roboto', sans-serif;
}
```

这将将 font-family 属性应用于`<body>`元素，这是我们 HTML 页面的主要元素，因此它将应用于`<body>`内的所有元素。

# 添加 normalize.css

当查找`main.css`时，您可能会注意到另一个`css`文件。`normalize.css`是什么，为什么我们应该将其与我们的 HTML 集成？

正如我们之前所看到的，每个浏览器的渲染方式都不相同。使用`normalize.css`，所有浏览器将更一致地渲染元素，并符合现代标准。我们只需要将其添加到我们的其他`css`文件中，它就会起作用。很酷，不是吗？

# 标题

让我们开始实施我们的标题。最佳做法是先做 HTML，然后再完成 CSS。让我们先看看我们的设计。

如您所见，我们的标题具有透明背景，左侧有标志和主菜单，右侧有次级菜单。

首先，在我们的 HTML 文档中创建一个`<header>`标签：

```html
<!-- Add your site or application content here --> <header></header>
```

# 创建菜单

要创建我们的菜单，我们需要创建一个列表。在 HTML 中，要创建列表，您必须使用标签`<ul>`。

`<ul>`代表无序列表；它需要在`<li>`内部有一个列表标签。您可以按以下方式使用它：

```html
<ul>
  <li>Coffee</li>
  <li>Tea</li>
  <li>Milk</li>
</ul>
```

我们的列表应该最终看起来像这样：

```html
<header>
  <ul>
    <li>Upcoming events</li>
    <li>Past events</li>
    <li>FAQ</li>
    <li>About us</li>
    <li>Blog</li>
    <li>Contact</li>
  </ul>
</header>
```

# 插入链接

为了使菜单工作，我们需要向我们的列表添加链接；否则，它将无法工作。要添加链接，您必须使用标签`<a>`。为了使每个`<li>`元素可点击为链接，我们需要在`<li>`标签内添加`<a>`标签，如下所示：

```html
<li><a>Upcoming events</a></li>
```

现在我们需要指定链接的位置。为此，我们需要添加属性`href`：

```html
<li><a href="upcoming.html">Upcoming events</a></li>
```

如果不存在`href`属性，则`<a>`标签将不起作用。`href`的值可以是指向另一个网站的绝对链接，也可以是指向同一域上的文件的相对链接。这基本上与我们之前看到的`src`属性的行为相同。

最后，我们的菜单应该看起来像这样：

```html
<ul>
  <li><a href="upcoming.html">Upcoming events</a></li>
  <li><a href="past.html">Past events</a></li>
  <li><a href="faq.html">FAQ</a></li>
  <li><a href="about.html">About us</a></li>
  <li><a href="blog.html">Blog</a></li>
  <li><a href="contact.html">Contact</a></li>
</ul>
```

最后，让我们给我们的`<ul>`标签添加一个类，这样我们以后可以用`css`指定样式，就像这样：

```html
<ul class="main-nav">
```

# 添加标志

除了我们的导航，我们还在左侧放置了一个标志。我在`资源`文件夹（`练习 2` | `资产`）中提供了一些您可以在此练习中使用的资产。

只需将`logo.png`和`logo@2x.png`文件复制并粘贴到您的`Web 项目`的`img`文件夹中。

`logo@2x.png`只是图像的视网膜版本，这意味着它的像素密度是普通图像的两倍。将视网膜图像命名为后缀`@2x`是一个很好的做法。

现在我们将简单地在我们的菜单之前添加一个图像，如下所示：

```html
<img src="img/logo.png" alt="">
```

也许您已经注意到我们只放置了`logo.png`，并没有使用`logo@2x.png`。为了能够仅在视网膜设备上使用我们的视网膜版本图像，我们将不得不使用属性`srcset`：

```html
<img src="img/logo.png" srcset="img/logo.png 1x, img/logo@2x.png 2x">
```

`srcset`属性非常简单易用。对于每个资产，添加密度以指定应该使用哪个屏幕密度。在这个例子中，我们将放置`img/logo@2x.png 2x`。您还可以指定它应该出现在哪个屏幕宽度，但让我们在这个例子中保持简单。

一个网页设计的良好实践是使标志链接到主页。为此，我们需要将`img`标签放在标签内：

```html
<a href="#"><img src="img/logo.png" srcset="img/logo.png 1x, img/logo@2x.png 2x"></a>
```

为了确保链接指向网站的主页，我们需要将`href`属性`"#"`更改为`"/"`，这样它将转到文件夹的根目录：

```html
<a href="/"><img src="img/logo.png" srcset="img/logo.png 1x, img/logo@2x.png 2x"></a>
```

最后，让我们放一个类`"logo"`，这样我们以后可以定位这个元素：

```html
<a class="logo" href="/"><img src="img/logo.png" srcset="img/logo.png 1x, img/logo@2x.png 2x"></a>
```

# 右侧菜单

菜单的最后一部分是右侧的菜单，有`登录`和`Facebook`喜欢按钮。有很多方法可以做到这一点，但我建议使用另一个列表，就像我们之前创建的那个：

```html
<ul class="right-nav">
  <li><a href="login.html">Login</a></li>
  <li><a href="#">Facebook</a></li>
</ul>
```

我们将添加类`"right-nav"`并添加 2 个`<li>`，就像前面的代码中所示。

# 添加 Facebook 喜欢按钮

要添加`Facebook`的喜欢按钮，我们首先需要创建按钮。为此，我们需要去 Facebook 开发者网站获取信息。我已经为你准备好了链接：[`developers.facebook.com/docs/plugins/like-button`](https://developers.facebook.com/docs/plugins/like-button%23)。在这个页面上，你会找到自定义按钮的方法，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/bf44dc43-7b50-49ae-8c75-14fcbda4b6ea.png)

完成后，点击获取代码，并选择 IFrame 选项卡：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9005f3a1-a6a7-420d-a54b-3a472259ee62.png)

我们可以将这段代码复制到我们网站的第二个`<li>`标签中。

我们将稍微定制一下按钮；将属性高度的默认值更改为`20px`。你应该最终得到这样的代码：

```html
<ul class="right-nav">
  <li><a href="login.html">Login</a></li>
  <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
</ul>

```

我们现在在 HTML 中有了我们的菜单；让我们用 CSS 添加一些样式，使它看起来更好。

# 为我们的页眉添加样式

此刻，我们的页眉看起来非常无聊。但是，别担心，我们将用 CSS 添加一些魔法，让它变得更漂亮。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/fe352669-a5d5-460c-b020-77d9cc704624.png)

我们之前看到 CSS 可以用三种不同的方式编写：

+   在带有`style`属性的 HTML 标签中

+   在 HTML 文档的`<head>`部分中，带有`style`属性的 HTML 标签

+   CSS 代码也可以放在外部文件中

对于我们自己的项目，我们将使用网页中普遍使用的第三种方式，因为 CSS 可以在不更改 HTML 文件的情况下进行更改。

让我们创建一个 CSS 文件，用于一般的样式。在 Atom 中，点击文件|新建文件，并将文件保存为文件|另存为。选择`css`文件夹，并将此文件命名为`styles.css`。我们必须像之前创建的`font.css`文件一样链接这个文件：

```html
<link href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet">
<link rel="stylesheet" href="fonts/fonts.css"> <!-- Font face CSS link -->
<link rel="stylesheet" href="css/normalize.css">
<link rel="stylesheet" href="css/main.css">
<link rel="stylesheet" href="css/styles.css">
```

现在我们有了`styles.css`，我们可以开始了。但我通常喜欢同时查看 HTML 和 CSS。这很容易做到；选择你的`styles.css`，然后转到查看|窗格|右侧拆分。现在你有两个不同窗格中打开的文件。你可以关闭左边的那个：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1d1d2304-cd7a-4047-915c-146f2ebf62fd.png)

Atom 中的两个视图拆分。

首先，我们需要定位`header`标签。`header`标签没有类，但我们可以只用这个标签来定位 HTML 标签。在 CSS 中，它将是：

```html
header {
}
```

这将基本上定位 HTML 中的每个`<header>`标签，所以你需要小心：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/39e89a00-64cf-4ca0-9a81-7ef5df63d514.png)

如果我们仔细看一下我们的设计，我们会发现页眉占据了整个网页的宽度，高度为*70px*，并且有一个从灰色到透明的渐变背景，让图像出现在其后。

为此，我们有 CSS 属性`width`：

```html
header {
  width: 100%;
  height: 70px;
}
```

现在我们可以添加背景渐变。为此，我们有 CSS 属性`background-image: linear-gradient`：

```html
background-image: linear-gradient(0deg, rgba(0,0,0,0.00) 0%, rgba(0,0,0,0.50) 50%);
```

为了使用 CSS 创建渐变，我经常使用一个生成器（[`www.colorzilla.com/gradient-editor/`](http://www.colorzilla.com/gradient-editor/)），它会为我创建最终的代码。

我有时也会使用 Sketch 或 Photoshop 提供的 CSS 工具，直接从设计中复制 CSS 属性。

在这个练习中，你可以直接复制我提供的代码：

```html
header {
  width: 100%;
  background-image: linear-gradient(0deg, rgba(0,0,0,0.00) 0%, rgba(0,0,0,0.50) 50%);
}
```

保存 CSS 和 HTML 文件，并在浏览器中打开`index.html`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/02519181-8ff7-4219-b23f-6b7046aff2c6.png)

现在我们有了容器，但我们仍然需要为我们的菜单添加样式。让我们首先通过它的类`main-nav`来定位我们的列表。如果你记得，要调用一个类，我们需要在类名前面加一个点，就像这样：

```html
header .main-nav {

}
```

现在我们想要具体地定位`<ul>`内的每个`<li>`。为了做到这一点，我们只需要在后面添加`li`，就像我们在之前的章节中看到的那样：

```html
header .main-nav li {

}
```

让我们首先移除列表的样式，它默认是一个圆圈。为了做到这一点，我们需要使用 CSS 属性`list-style-type`：

```html
header .main-nav li {
  list-style-type: none; 
}
```

让我们放置`none`，这样它将移除`li`标签中的所有样式。

我们还需要将列表水平显示而不是垂直显示。为了实现这一点，我们需要使用 CSS 属性 `display: inline-block`。

CSS 属性`display: inline-block` 将以内联方式显示列表，但具有设置宽度和高度的块元素的能力：

```html
header .main-nav li {
  list-style-type: none;
  display: inline-block;
}
```

让我们保存我们的工作并检查一下我们目前的进展：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1156431d-ae9c-4916-93d2-51a192fe0ed0.png)

我们现在的目标是将菜单放在标志旁边。为此，我们需要使标志浮动。正如我们之前在 CSS 章节中看到的，我们将在标志上使用 CSS 属性`float: left;`：

```html
header .logo {
  float: left;
}
```

我们现在需要正确显示菜单。我们首先给我们的`main-nav`添加一个高度：

```html
header .main-nav {
  height: 70px;
}
```

我们还需要使菜单浮动，以便右侧菜单可以显示在上方：

```html
header .main-nav {
  height: 70px;
}
```

由于所有`<ul>`标签默认具有一些填充和边距，我们需要覆盖它：

```html
Header .main-nav {
  height: 70px;
  float: left;
  margin: 0;
  padding: 0;
}
```

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f0a6ea9d-540d-4224-bcea-f678c3f80d5d.png)

问题是我们的菜单与标志并排，所以我们需要为菜单添加一些填充：

```html
header .main-nav {
  height: 70px;
  float: left;
  margin: 0;
  padding: 0;
  padding-left: 0;
}
```

但现在我们有两个重叠的属性，因为填充包括所有填充，如填充左侧。这仍然有效，但这是不好的 CSS。为了正确编写它，我们可以使用一个 CSS 属性来组合和修改填充：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8e3fbf8f-74db-4d02-be1f-90061813f75a.png)

这张图片解释了如何使用一个属性改变不同的填充。

对于我们的练习，我们将执行以下操作：

```html
header .main-nav {
  height: 70px;
  float: left;
  margin: 0;
  padding: 0px 15px;
}
```

我们的下一个目标是使我们的菜单与标志垂直对齐。为此，我们可以使用一点 CSS 技巧，通过使用行高，通常用于改变段落中行之间的间距。通过将`line-height`设置为菜单的高度，我们将使菜单垂直对齐：

```html
header .main-nav {
  height: 70px;
  float: left;
  margin: 0;
  padding: 0px 15px;
  line-height: 70px;
}
```

现在让我们自定义字体为我们之前安装的字体。让我展示最终的 CSS，这样我就可以逐行解释它的含义：

```html
header .main-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
  padding: 0px 15px;
}
```

首先，我们需要定位`.main-nav`类中的`<a>`标签。在括号内，我们将有以下内容：

1.  `color: white;` 将指定文本的颜色。您可以使用 HEX 代码或 140 种本地颜色 CSS 支持来设置这种颜色（[`www.w3schools.com/cssref/css_colors.asp`](https://www.w3schools.com/cssref/css_colors.asp)）。

1.  `text-decoration: none;` 将取消文本上的所有装饰。这里我们想要取消每个链接上的下划线。

1.  `font-family: 'built_titling', Helvetica, sans-serif;` 用于指定我们想要显示的字体。如果第一个字体无法加载，将使用以下字体名称。

1.  `font-weight: 200;` 是字体的粗细级别。

1.  `font-size: 20px;` 将是以像素为单位的字体大小。

1.  `letter-spacing:` 将指示每个字符之间的间距。

1.  `padding:` 这是我们之前学过的内部填充。

我们快要完成了。让我们保存并查看一下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/02519181-8ff7-4219-b23f-6b7046aff2c6.png)

我们只剩下右侧部分要完成，让我们完成它！

对于这部分，我们需要使它向右浮动。让我们首先定位这个类：

```html
Header .right-nav {

}
```

这个右侧导航将几乎与左侧导航具有相同的属性；我们只会将浮动更改为右侧：

```html
header .right-nav {
  height: 70px;
  float: right;
  margin: 0;
  padding: 0px 15px;
  line-height: 70px;
}
```

正如你将看到的，我们将在编码中使用大量的复制/粘贴，因为很多元素将使用相同的属性。

但是如果我们有很多选择器使用相同的 CSS 属性怎么办？我们需要复制/粘贴所有吗？在编码中的一个好习惯是始终简化我们的代码，以便加载时间更短。

在 CSS 中，我们可以调用多个选择器并放置相同的 CSS 属性。为此，我们需要用逗号`,`分隔它们。例如，对于我们的`left-nav`和`right-nav`，我们可以这样做：

```html
header .main-nav, header .right-nav{
  height: 70px;
  float: left;
  margin: 0;
  padding: 0px 15px;
  line-height: 70px;
}

header .right-nav {
  float: right;
}
```

这将产生与我们之前编写的代码相同的效果。因为我们调用了`.right-nav`并在之后添加了`float: right;`属性，它会覆盖之前的属性，即`float: left;`。这是在 CSS 中编码时的一个好习惯。

让我们在编写代码时遵循这个好习惯：

```html
header .main-nav li, header .right-nav li {
  list-style-type: none;
  display: inline-block;
}

header .main-nav li a, header .right-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
  padding: 0px 15px;
}
```

现在我们有了我们的标题。让我们保存它并最后看一下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1ac77da7-5344-4f43-ae36-20f144fc0bcd.png)

太棒了！最后，为了使我们的代码清晰易读，我建议在代码的每个部分的开头和结尾添加一些注释。

这将是我们`HEADER`部分的最终 CSS 代码：

```html
/* HEADER */

header {
  width: 100%;
  height: 70px;
  background-image: linear-gradient(0deg, rgba(0,0,0,0.00) 0%, rgba(0,0,0,0.50) 50%);
  position: absolute;
}

header .logo {
  float: left;
}

header .main-nav, header .right-nav{
  height: 70px;
  float: left;
  margin: 0;
  padding: 0px 15px;
  line-height: 70px;
}

header .right-nav {
  float: right;
}

header .main-nav li, header .right-nav li {
  list-style-type: none;
  display: inline-block;
}

header .main-nav li a, header .right-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
  padding: 0px 15px;
}

/* END OF HEADER */
```

# 添加英雄部分

在实现我们的标题后，我们现在可以进行下一步，即英雄部分。在网页设计中，英雄部分通常由一个大图像、一个标题、一个描述和一个**行动号召**（**CTA**）组成。它作为网站的概览，因为这是访问者将看到的第一件事情。

在我们的设计中，我们有以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e6c90e0c-69d4-40a2-9121-0600b314cb60.png)

这很简单。它由一个背景图像、一个渐变叠加和一些文本以及左侧的按钮组成。如果我们试图勾勒出每个块的轮廓，我们可能会得到这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/7f2a1d36-1804-40bc-9f62-55a221471807.png)

也许这可以帮助你想象我们在 HTML/CSS 中要做的事情。让我们从 HTML 开始：

我们可以首先创建一个将包含所有内容的部分（紫色）：

```html
<section id="hero">
</section>
```

我们将添加一个`id`，这样以后调用它会更容易。

现在我们需要创建一个包含所有元素但也水平居中的`container`（紫红色）。为此，我们将创建一个带有`container`类的`div`：

```html
<section id="hero">
  <div class="container">

  </div>
</section>
```

里面我们将有一个块，其中将包含标题、描述和按钮，这些将左对齐。我们可以称之为`"hero-text"`：

```html
<section id="hero">
  <div class="container">
    <div class="hero-text">

    </div>
  </div>
</section>
```

现在，让我们在里面添加内容：

```html
<section id="hero">
  <div class="container">
    <div class="hero-text">
      <p class="hero-date">10.05.18</p>
      <h1 class="hero-title">Wakefield Park</h1>
      <button type="button" name="button" class="btn-primary">Book now</button>
    </div>
  </div>
</section>
```

正如你可能已经注意到的，我们没有在 HTML 中添加图像，因为我们想用 CSS 添加它。使用 CSS 添加图像可以提供更多的灵活性和定制。在这种情况下，我们希望使其全屏并覆盖背景。首先，让我们调用我们的`#hero` div：

```html
#hero {

}
```

让我们添加以下样式：

```html
#hero {
  width: 100%;
  height: 700px;
  background-image:
    linear-gradient(to bottom, rgba(0,0,0,0.3) 0%,rgba(0,0,0,0.4) 100%),
    url("../img/hero-image.jpg");
  background-repeat: no-repeat;
  background-size: cover;
  background-position: center;
}
```

以下是一些解释：

1.  我们首先需要设置块的大小。因为我们希望它是全屏的，所以我们必须将宽度设为 100％，高度设为 700px，因为这是设计的尺寸。

1.  使用 CSS5，我们有能力添加多个背景。为此，我们需要用逗号分隔它们，就像之前展示的那样。

1.  我们使用`background-repeat`来使背景不像默认情况下那样无限重复。

1.  `background-size: cover;` 将使背景图像根据块的大小（这里是全屏）进行拉伸。

1.  `background-position: center;` 将始终将背景放在中心，即使在调整大小时也是如此。

1.  让我们保存我们的文件并看看我们得到了什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f5fc3b00-ff4e-4029-bab8-03450731a6e8.png)

我们有我们的图片和渐变；现在让我们进入我们的内容。

正如我们之前所说，我们需要我们的内容居中。正如你可能已经注意到的，我们的设计遵循一个网格：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8c7e7e11-1dc3-4940-a58a-06c2674cb445.png)

我们需要创建这个容器，它的宽度为 940px，并且在水平方向上居中。非常简单，我们需要做的就是：

```html
.container {
  max-width: 940px;
  margin: 0 auto;
}
```

以下是一些注释：

1.  `max-width: 940px:`：我们不希望容器超过`940px`，但它可以根据屏幕尺寸而小于这个值。

1.  `margin: 0 auto;` 是水平居中块级元素的简单方法。

下一步将是对内容进行样式化。但是，首先，我们需要在跳入代码之前分析设计。观察设计时，我们可以看到：

+   英雄内容需要从英雄部分垂直居中

+   英雄内容需要左对齐，并且宽度为 50％

# CSS flexbox

为了实现这一点，我们将使用新的 CSS 属性`display: flex`。CSS flexbox 非常实用，因为它可以让你非常容易地定位元素。使用 flexbox 可以非常轻松地实现居中、排序和对齐。如果你能掌握这个新属性，我保证你会成为 CSS 方面的高手。

在我们的情况下，我们希望我们的`.container`在垂直方向上居中。为了做到这一点，我们将针对这个类并添加这些属性：

```html
#hero .container {
  display: flex;
  align-items: center;
  height: 700px;
}
```

通过在`.container`之前添加`#hero`，我们只针对`#hero`内部的`.container`元素。我们不希望所有`.container`具有相同的属性：

1.  `display: flex;`必须设置在父元素上。

1.  `align-items: center;`将垂直对齐并居中此元素内的所有元素。神奇！

1.  需要设置`height`以便您可以将元素垂直对齐。

CSS flexbox 具有非常强大的属性。我们可以使用 flexbox 属性来完成整个网站，但为了让您了解所有可能性，我们必须经历所有步骤。

让我们继续进行文本样式设置：

```html
.hero-text {
  max-width: 470px;
}
```

我们设置这个宽度，因为我们不希望文本一直延伸到右边，所以我们将最大宽度设置为`.container`的`max-width`的一半。继续遵循我们的设计：

```html
.hero-text .hero-date {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-size: 30px;
  color: #FFFFFF;
  font-weight: normal;
}
```

接下来，我们有我们的标题：

```html
.hero-text .hero-title {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-size: 120px;
  margin: 20px 0px;
  font-weight: normal;
  color: #FFFFFF;
  line-height: 1;
}
```

最后，我们有我们的按钮：

```html
.btn-primary {
  display: inline-block;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 18px;
  letter-spacing: 4.5px;
  background: #BF0000;
  color: white;
  padding: 12px 22px;
  border: none;
  outline: none;
}
```

我们使用`display: inline-block;`，这样我们就可以将按钮用作内联元素，但具有块元素（宽度和高度）的特性。默认情况下，`border`和`outline`都设置为`none`。每个按钮都有一个`border`和`outline`。

让我们看看我们有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f1a91dad-7393-4be9-91a8-3edca345130b.png)

网站看起来很棒，但顶部有一些讨厌的边距。为了解决这个问题，我们需要使用 CSS 属性`"position"`。

# CSS 中的定位

在 CSS 中，有五种不同的定位值：

+   静态

+   相对的

+   固定的

+   绝对

+   粘性

# 静态位置

它们都有不同的用途。所有 HTML 元素默认都是静态定位的。

# 相对定位

具有相对位置的元素相对于其正常位置进行定位。您可以通过更改其左、上、右或下位置来调整定位。

例如：

```html
div.relative-element {
    position: relative;
    top: 50px;
    left: 50px;
}
```

查看以下图表以更好地理解：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/b852641e-891e-4059-9f3a-d24f9c0bdd94.png)

# 绝对位置

具有绝对位置的元素将被放置在其最近的定位父元素旁边，这意味着任何期望静态位置的位置元素。如果此元素没有父元素，则将定位到视口本身。

绝对定位的元素将放置在父元素之上。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/3f0a049e-1171-4be2-8eee-9ee152b22e6d.png)

# 固定位置

具有固定位置的元素将作为绝对位置，但仅在视口本身上。即使页面滚动，它也将保持在相同的位置：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8e21ca28-321e-4146-bffc-735c2f73e563.png)

# 粘性位置

具有粘性位置的元素是基于用户的滚动位置进行定位的。

在每个浏览器中并不完全支持，因此我们在这个练习中不会使用它。

现在我们了解了 CSS 中位置的用法，我们需要使标题叠加到英雄部分。为此，我们需要使标题位置绝对。由于标题没有父元素，它将定位在视口本身上。

让我们回到标题部分并添加`position: absolute`属性：

```html
header {
  width: 100%;
  height: 70px;
  background-image: linear-gradient(0deg, rgba(0,0,0,0.00) 0%, rgba(0,0,0,0.50) 50%);
  position: absolute;
}
```

让我们保存并看看我们有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/5887efb0-00d0-4303-9696-aba69f8e6807.png)

我们现在有了我们的第一部分和标题的良好实现。让我们继续到下一部分。

# 博客部分

首先，就像我们总是做的一样（你需要养成这个习惯），我们需要分析设计并看看它是如何组成的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d7b7385e-9f60-4fe8-88ff-66f9d87d9628.png)

正如我们所看到的，博客部分由标题和六篇博客文章组成。每行有三篇文章，宽度均为三分之一。

我们知道如何用`float`和`display: inline-block`属性来设计这个。让我们尝试用 CSS flexbox 来构建它。

让我们首先添加 HTML：

```html
<section id="blog">
  <div class="container">
    <h2><b>Blog</b> Everything about RACING CLUB</h2>

  </div>
</section>
```

这里有一些解释：

1.  我们需要创建另一个`section id "blog"`

1.  我们需要重用类`container`来拥有一个遵循相同宽度的容器

1.  我们添加了一个`<h2>`，因为它不像主标题那么重要

1.  我们添加了一个`<b>`标签来使单词 Blog 加粗

现在让我们添加我们的`blog`帖子部分：

```html
<section id="blog">
  <div class="container">
    <h2><b>Blog</b> Everything about RACING CLUB</h2>
    <div class="blog-posts">
      <div class="blog-post">
        <img src="img/blog1.jpg" srcset="img/blog-img/blog1.jpg 1x, img/blog-img/blog1@2x.jpg 2x">
        <p class="blog-post-date">09th January 2016</p>
        <h3>Racing Club Advan Neova Challenge Round 3 Update</h3>
        <p class="blog-post-desc">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi… <a href="#">Read More</a></p>
      </div>
    </div>
  </div>
</section>
```

这是我们做的事情：

1.  我们添加了一个带有类`"blog-posts"`的`div`，其中包含了所有的博客帖子。

1.  在内部，我们创建了一个带有类`"blog-post"`的`div`，它将是一个单独的博客帖子。

1.  在这个`div`里，我们添加了一个带有`img`标签和我们之前学到的`srcset`的图片。

1.  我们还为博客帖子日期添加了一个带有类`"blog-post-date"`的 p 标签。

1.  我们添加了一个没有类的`<h3>`，因为它是唯一的`h3`元素，所以我们可以很容易地用 CSS 来定位它。

1.  最后，我们添加了带有链接的`description`文本。

这代表一个单独的博客帖子，所以要创建六个，我们只需要复制`blog`帖子元素六次。

让我们也添加另一个`div`来制作我们的“显示更多”按钮：

```html
<div class="blog-show-more">
  <button type="button" name="button" class="btn-primary">More posts</button>
</div>
```

最后，你应该有这样的东西：

```html
<section id="blog">
  <div class="container">
    <h2><b>Blog</b> Everything about RACING CLUB</h2>
    <div class="blog-posts">

      <div class="blog-post">
        <img src="img/blog1.jpg" srcset="img/blog-img/blog1.jpg 1x, img/blog-img/blog1@2x.jpg 2x">
        <p class="blog-post-date">09th January 2016</p>
        <h3>Racing Club Advan Neova Challenge Round 3 Update</h3>
        <p class="blog-post-desc">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi… <a href="#">Read More</a></p>
      </div>

      <div class="blog-post">
        <img src="img/blog2.jpg" srcset="img/blog-img/blog2.jpg 1x, img/blog-img/blog2@2x.jpg 2x">
        <p class="blog-post-date">09th January 2016</p>
        <h3>Hidden Behind the Scenes</h3>
        <p class="blog-post-desc">Originally posted by Narada Kudinar, 23.08.11.
At our Trackdays, we get a variety - owners with their girlfriends, owners with their mates, owners and their mechanics - but there is one combination I am truly at envy with. It's the owners and their Dads. <a href="#">Read More</a></p>
      </div>

      <div class="blog-post">
        <img src="img/blog3.jpg" srcset="img/blog-img/blog3.jpg 1x, img/blog-img/blog3@2x.jpg 2x">
        <p class="blog-post-date">04th July 2015</p>
        <h3>Introducing Advan Trackdays!</h3>
        <p class="blog-post-desc">For the first time, Yokohama Advan Tyres are hosting their very own Trackdays, hosted by your's truly! The aim? To thank their loyal customers by providing a bargain event as well as introduce new Advan tyres to those who don't use them yet...<a href="#">Read More</a></p>
      </div>

      <div class="blog-post">
        <img src="img/blog4.jpg" srcset="img/blog-img/blog4.jpg 1x, img/blog-img/blog4@2x.jpg 2x">
        <p class="blog-post-date">09th Jun 2015</p>
        <h3>ANZAC Day Spots Running Out!</h3>
        <p class="blog-post-desc">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi… <a href="#">Read More</a></p>
      </div>

      <div class="blog-post">
        <img src="img/blog5.jpg" srcset="img/blog-img/blog5.jpg 1x, img/blog-img/blog5@2x.jpg 2x">
        <p class="blog-post-date">15th Mar 2015</p>
        <h3>10 Year Anniversary Details Now Available!</h3>
        <p class="blog-post-desc">Originally posted by Narada Kudinar, 23.08.11.
At our Trackdays, we get a variety - owners with their girlfriends, owners with their mates, owners and their mechanics - but there is one combination I am truly at envy with. It's the owners and their Dads. <a href="#">Read More</a></p>
      </div>

      <div class="blog-post">
        <img src="img/blog6.jpg" srcset="img/blog-img/blog6.jpg 1x, img/blog-img/blog6@2x.jpg 2x">
        <p class="blog-post-date">16th Jan 2015</p>
        <h3>Prepare for EPICNESS</h3>
        <p class="blog-post-desc">For the first time, Yokohama Advan Tyres are hosting their very own Trackdays, hosted by your's truly! The aim? To thank their loyal customers by providing a bargain event as well as introduce new Advan tyres to those who don't use them yet... <a href="#">Read More</a></p>
      </div>

    </div>
div class="blog-show-more">
      <button type="button" name="button" class="btn-primary">More posts</button>
    </div>

  </div>
</section>
```

现在让我们转到 CSS！我们将首先为标题添加样式：

```html
#blog h2 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 60px;
}
```

对于`blog-posts`容器，我们将按照以下方式进行：

```html
.blog-posts {
  display: flex;
  flex-direction: row;
  flex-wrap: wrap;
  margin-top: 50px;
}

.blog-post {
  width: 33.33%;
  padding: 0 5px;
  box-sizing: border-box;
  margin-bottom: 30px;
}
```

`.blog-posts`是父元素，`.blog-post`是子元素。

关于`.blog-posts`的一些信息：

1.  `display: flex;`总是需要添加到父元素。

1.  `flex-direction: row;`将把子元素定向为一行。如果你想的话，你也可以把它放在一列上。

1.  `flex-wrap: wrap;`将使子元素换行，从上到下。默认情况下，它会尝试将每个元素放在一行上。

1.  `margin-top: 50px;`在顶部添加了一点边距。

关于`.blog-post`的一些信息：

1.  `width: 33.33%;`将宽度设置为总宽度的三分之一

1.  `padding: 0 5px;`在右侧和左侧添加一些填充

1.  `box-sizing: border-box;`: 正如我们之前看到的，这使得填充和边距属性应用在盒子内部而不是外部

到目前为止，我们有了正确的布局：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/3db24515-d18f-4681-9653-3abe48a7f65c.png)

让我们为博客帖子内部的内容添加样式：

```html
.blog-post img {
  width: 100%;
}
```

我们使用`width: 100%;`因为我们希望我们的图片占据整个宽度。其余的都是相当基本的 CSS，只是为了遵循设计：

```html
.blog-post .blog-post-date {
  font-size: 14px;
  color: #9A9A9A;
  margin-top: 20px;
}

.blog-post h3 {
  font-size: 20px;
  color: #4A4A4A;
  letter-spacing: -0.4px;
  line-height: 1.4;
}

.blog-post .blog-post-desc {
  font-size: 14px;
  color: #4A4A4A;
  line-height: 1.6;
}

.blog-post .blog-post-desc a {
  color: #BF0000;
  text-decoration: underline;
  font-weight: bold;
}
```

这就是我们最终得到的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a1977518-badb-4ddc-bda9-d4834385a659.png)

现在看起来很相似了。最后一部分是“显示更多”按钮。一个简单的方法是在父元素中添加`text-align: center`，这样它就会使按钮在中间对齐：

```html
.blog-show-more {
  text-align: center;
}
```

最后一点，我会在底部添加一些边距，增加一些空白：

```html
#blog {
  margin-bottom: 50px; 
}
```

我们的博客部分的 CSS：

```html
/* BLOG SECTION */

#blog {
  margin-bottom: 50px;
}

#blog h2 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 60px;
}

.blog-posts {
  display: flex;
  flex-direction: row;
  flex-wrap: wrap;
  margin-top: 50px;
}

.blog-post {
  width: 33.33%;
  padding: 0 5px;
  box-sizing: border-box;
  margin-bottom: 30px;
}

.blog-post img {
  width: 100%;
}

.blog-post .blog-post-date {
  font-size: 14px;
  color: #9A9A9A;
  margin-top: 20px;
}

.blog-post h3 {
  font-size: 20px;
  color: #4A4A4A;
  letter-spacing: -0.4px;
  line-height: 1.4;
}

.blog-post .blog-post-desc {
  font-size: 14px;
  color: #4A4A4A;
  line-height: 1.6;
}

.blog-post .blog-post-desc a {
  color: #BF0000;
  text-decoration: underline;
  font-weight: bold;
}

.blog-show-more {
  text-align: center;
}

/* END OF BLOG SECTION */
```

# 创建关于我们部分

这个部分并不是很复杂。让我们来看看设计：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/590a2346-7a37-48e2-9527-1231bbdbe7d1.png)

如果我们使用我们的块分析器，我们可以得到这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c9cc4042-4633-4ec2-8229-6d62a1f3fe41.png)

我们需要做的事情：

+   使内容垂直居中

+   将文本对齐到左边

+   有一个覆盖整个部分的背景图片

如我们之前所见，垂直对齐元素的最佳方法是使用 CSS flexbox。

让我们创建我们的 HTML。在我们的`blog`部分之后，我们将添加我们的`about-us`部分：

```html
<section id="about-us">

</section>
```

在这个部分里，和往常一样，我们要添加我们的`container`：

```html
<section id="about-us">
          <div class="container">

          </div>
</section>
```

在我们的容器里，我们将创建两个块，用来包含我们的大标题和描述：

```html
<section id="about-us">
  <div class="container">
    <div class="about-us-title">
        <h3>The love of cars</h3>
    </div>
    <div class="about-us-desc">
      <h4>About us</h4>
      <p>Racing Club was founded in 2003 with one goal in mind, to make motorsport accessible through Trackdays. What started out simply as a bunch of mates with a love of cars and driving fast… </p>
      <button type="button" name="button" class="btn-primary">Learn more</button>
    </div>
  </div>
</section>
```

让我们保存并跳转到我们的 CSS 文件：

1.  首先，定位我们的关于部分 ID：

```html
#about-us {

}
```

1.  为我们的部分添加背景图片：

```html
#about-us {
  width: 100%;
  background-image: url(../img/about-us-bg.jpg);
  background-repeat: no-repeat;
  background-size: cover;
  padding: 120px 0;
  color: white;
}
```

我们使用了之前在我们的主标题部分使用的相同的 CSS 属性。添加了一些填充，以保持与设计的一致性。我们在父级设置了颜色，这样我们就不必在每个子元素中设置颜色。

1.  在`container`中设置 flexbox：

```html
#about-us .container {
  display: flex;
  align-items: top;
}
```

`align-items: top;`将使文本从顶部对齐，就像设计中的一样。

1.  我们现在必须设置容器内块的`width`；否则，flexbox 将无法工作：

```html
.about-us-title {
  width: 50%;
}

.about-us-desc {
  width: 50%;
}
```

让我们保存并检查设计：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4fbee7a3-9aa9-4eb7-905e-af77a48b2a09.png)

到目前为止，一切都很好；我们正在朝着正确的方向前进。让我们为我们的标题和描述添加一些样式。

1.  为我们的标题添加样式：

```html
.about-us-title h3 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 120px;
  line-height: 1;
  letter-spacing: -1px;
  margin: 0;
}
```

`margin: 0`必须默认添加，因为每个`h`标题都有一个跟随文本大小的边距。让我们再次检查：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/40546356-f808-41e7-9ec9-e100554383f0.png)

我们已经非常接近了，但我们仍然需要在实现上更加精确：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/89732d20-6250-465c-919e-bc09d4db7cf7.png)

我们可以看到在我们的设计中，标题底部有几个换行和一条红线。

为了做到这一点，我们需要在 HTML 中添加一些换行。要在 HTML 中添加换行，我们可以在任何文本块中使用标签`<br />`。所以在我们的标题中，我们会在`The`和`love`后面添加一个`<br />`标签：

```html
<h3>The<br /> love<br /> of cars</h3>
```

现在，要添加红线，我们可以创建一个`<div>`并自定义它为我们想要的形状和颜色。但这将在 HTML 中添加一些无用的东西。

更好的方法是在 CSS 中使用`::before/:: after`选择器。此选择器可以在 HTML 元素之前或之后添加一些文本。

它主要用于在段落后添加额外的文本，但我们将用它来添加这条红线。

为此，我们必须选择`h3`元素并添加`::after`：

```html
.about-us-title h3::after {

}
```

对于每个`::after`或`::before`选择，我们需要添加 CSS 属性`content`：

```html
.about-us-title h3::after {
  content: "";
}
```

我们将把值留空，因为我们不想要任何文本。继续：

```html
.about-us-title h3::after {
  content: "";
  display: block;
  background: #BF0000;
  width: 90px;
  height: 2px;
  margin-top: 30px;
}
```

我们做了什么：

+   我们将`display`设置为`block`，因为默认情况下它是内联的

+   我们添加了红色背景和尺寸

+   我们添加了一些边距，以便文本和红线之间有一些空间

我们几乎完成了。我们还需要为描述的标题添加最后的修饰：

```html
.about-us-desc h4 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 26px;
  line-height: 1;
  margin: 0;
}
```

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c33e957c-a5da-4558-bf22-394ca63ceaef.png)

关于我们部分的最终 CSS 代码如下：

```html
/* ABOUT US SECTION */

#about-us {
  width: 100%;
  background-image: url(../img/about-us-bg.jpg);
  background-repeat: no-repeat;
  background-size: cover;
  padding: 120px 0;
  color: white;
}

#about-us .container {
  display: flex;
  align-items: top;
}

.about-us-title {
  width: 50%;
}

.about-us-title h3 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 120px;
  line-height: 1;
  letter-spacing: -1px;
  margin: 0;
}

.about-us-title h3::after {
  content: "";
  display: block;
  background: #BF0000;
  width: 90px;
  height: 2px;
  margin-top: 30px;
}

.about-us-desc {
  width: 50%;
}

.about-us-desc h4 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 26px;
  line-height: 1;
  margin: 0;
}

/* END ABOUT US SECTION */
```

# 添加合作伙伴部分

让我们像上一个部分一样高效地进行这一部分。

看一下以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ddb03355-ba38-4afb-9fb4-328fa7f85701.png)

此部分仅包含一个标题、两个图像、文本和一个按钮。我们需要在我们通常的容器内创建一个块（如橙色所示）。

HTML：

```html
<section id="partners">

</section>
```

从我们的`section`标签和`id`开始，我们将其命名为`partners`：

```html
<section id="partners">
  <div class="container">
  </div>
</section>
```

像往常一样，我们需要我们的`div "container"`来维护我们的结构：

```html
<section id="partners">
  <div class="container">
    <div class="partners-container">
    </div>
  </div>
</section>
```

在内部，我们创建另一个容器，`"partners-container"`：

```html
<section id="partners">
  <div class="container">
    <div class="partners-container">

      <h2>Partners</h2>

      <div class="partners-inner">

        <div class="partner">
          <img src="img/partner1.png" srcset="img/partner1.png 1x, img/partner1@2x.png 2x">
          <p>Advan Neova Cup</p>
        </div>

        <div class="partner">
          <img src="img/partner2.png" srcset="img/partner2.png 1x, img/partner2@2x.png 2x">
          <p>JDM Style Tuning</p>
        </div>

      </div>

      <button type="button" name="button" class="btn-primary">Become a partner</button>
    </div>
  </div>
</section>
```

在我们的`"partners-container"` `div`内部，我们执行以下操作：

+   我们将我们的标题放入`h2`中

+   我们还创建了另一个`"partners-inner"` div 来容纳我们的两个合作伙伴图像

+   在这个`partner-inners div`内部，我们有我们的单个合作伙伴`div`，每个都有一个图像和一个文本

+   我们还添加了一个按钮，放在`partners-inner`之外，但在`"partners-container"`内

我们的 CSS 将如下所示：

```html
#partners {
  background-color: black;
  color: white;
  text-align: center;
  padding: 50px 0px;
}
```

以下是代码的一些解释：

1.  背景是`black;`，因为在设计中，我们有一个黑色背景

1.  我们可以在父元素中放置`color:white;`，这样所有内部元素都将具有相同的属性

1.  我们可以对`text-align:center;`做同样的事情

1.  我们还在顶部和底部添加了一些填充

```html
.partners-container {
  max-width: 400px;
  margin: 0 auto;
}
```

我们添加了`max-width`和`margin: 0 auto;`来使我们的`partners-container`居中。要使用`margin: auto`方法对齐任何内容，您总是需要为元素定义一个宽度：

```html
.partners-container h2 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 60px;
}
```

还要添加以下 CSS：

```html
.partners-inner {
  display: flex;
  margin: 30px 0px;
}

.partners-inner .partner {
  width: 50%;
}
```

为了能够使用`display:flex;`，我们需要为子元素设置`width`。

PARTNERS 部分完成了；让我们保存并查看一下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6c92deaa-26fe-4ed7-bad4-31f10c32850f.png)

我们 PARTNERS 部分的最终 CSS 代码如下：

```html
/* PARTNERS SECTION */

#partners {
  background-color: black;
  color: white;
  text-align: center;
  padding: 50px 0px;
}

.partners-container {
  max-width: 400px;
  margin: 0 auto;
}

.partners-container h2 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 60px;
  line-height: 1;
}

.partners-inner {
  display: flex;
  margin: 30px 0px;
}

.partners-inner .partner {
  width: 50%;
}

/* END PARTNERS SECTION */
```

全部完成了！让我们进入最后一步，页脚！

# 添加页脚部分

在这一部分，我们将致力于页脚部分。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2de61400-8d29-459c-875c-1dd4f8879cf3.png)

页脚基本上与页眉相同，因此为了简化编码，我们将简单地复制并粘贴来自我们页眉的代码，并更改一些内容：

```html
<header>
  <a id="logo" href="/"><img src="img/logo.png" srcset="img/logo.png 1x, img/logo@2x.png 2x"></a>
  <ul class="main-nav">
    <li><a href="upcoming.html">Upcoming events</a></li>
    <li><a href="past.html">Past events</a></li>
    <li><a href="faq.html">FAQ</a></li>
    <li><a href="about.html">About us</a></li>
    <li><a href="blog.html">Blog</a></li>
    <li><a href="contact.html">Contact</a></li>
  </ul>
  <ul class="right-nav">
    <li><a href="login.html">Login</a></li>
    <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
  </ul>
</header>
```

这里是我们需要更改的内容：

+   将`<header>`标签更改为`<footer>`标签

+   在我们的页脚内添加一个`.container` `div`，如下所示

+   将我们的标志图片更改为`"logo-footer.png"`。

这是最终的 HTML：

```html
<footer>
  <div class="container">
    <a id="logo" href="/"><img src="img/logo-footer.png" srcset="img/logo-footer.png 1x, img/logo-footer@2x.png 2x"></a>
    <ul class="main-nav">
      <li><a href="upcoming.html">Upcoming events</a></li>
      <li><a href="past.html">Past events</a></li>
      <li><a href="faq.html">FAQ</a></li>
      <li><a href="about.html">About us</a></li>
      <li><a href="blog.html">Blog</a></li>
      <li><a href="contact.html">Contact</a></li>
    </ul>
    <ul class="right-nav">
      <li><a href="login.html">Login</a></li>
      <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
    </ul>
  </div>
</footer>
```

让我们跳到 CSS。我们首先要定位我们的`footer`：

```html
footer {
  background: black;
  color: white;
}
```

我们调用`footer`而不带任何点或`#`，因为我们单独调用标签。这也意味着将选择每个其他`footer`标签。因此，我们需要确保只选择`footer`元素的标签。

我们添加了一个黑色的背景，就像设计中一样，但也在父级别添加了`color:white`。我们很懒，不想每次都添加。

```html
footer .container {
  display: flex;
  height: 120px;
}
```

这变得很有趣；我们现在已经针对`footer`内的`.container`进行了定位，并将其属性更改为`flex`，这样我们就可以将这些元素显示为内联。

我们不会为每个子元素指定宽度，因为我们希望它们占据自然的空间。

最后一步，我们将为标志添加一些填充以使其与菜单对齐：

```html
footer .logo {
  padding-top: 20px;
}

footer .main-nav li, footer .right-nav li {
  list-style-type: none;
  display: inline-block;
}

footer .main-nav li a, footer .right-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
  padding: 0px 15px;
}
```

我们还从`header`中获取了一些样式，并将其复制到这里：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d49c8bbc-ac34-49c2-8bb0-5092d4b47df9.png)

我们现在已经完成了我们的页脚！

以下是最终的 CSS 代码：

```html
/* FOOTER SECTION */

footer {
  background: black;
  color: white;
}

footer .container {
  display: flex;
  height: 120px;
}

footer .logo {
  padding-top: 20px;
}

footer .main-nav li, footer .right-nav li {
  list-style-type: none;
  display: inline-block;
}

footer .main-nav li a, footer .right-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
  padding: 0px 15px;
}

/* END FOOTER SECTION */
```

# 总结

迄今为止，我们所做的总结：我们从头开始创建了一个网页，还使用了 HTML Boilerplate 来启动我们的项目。我们学到了很多 CSS 技巧，特别是关于 CSS flexbox，这可能非常有用。

在下一章中，我们将解决 CSS 的响应式方面，并为我们的网站添加一些交互性。让我们开始吧！
