# VuePress 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/986b9a64ec5b7230ac6d991c3d740203`](https://zh.annas-archive.org/md5/986b9a64ec5b7230ac6d991c3d740203)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

VuePress 自称为“Vue 动力的静态站点生成器”。换句话说，VuePress 是一个简单的工具，可以让您在几分钟内创建静态站点和单页应用（SPA）。

在 VuePress 中构建的任何内容都是搜索引擎友好的，完全优化的，并且也是移动友好的，由于没有数据库驱动的操作或外部引擎的工作，因此速度非常快。您只需在 Markdown 中输入内容，VuePress 将解析 Markdown 文件为有效的 HTML。

但 VuePress 不仅仅是静态站点生成！您可以自定义其外观，调整默认的最小主题，并利用 Vue.js 专业知识来扩展站点的功能。考虑到 Vue.js 的受欢迎程度在稳步上升，VuePress 已经站在了一个巨人的肩膀上，并且有很大的增长潜力！

这本快速入门指南将帮助您在短时间内开始使用 VuePress！

# 本书适合的读者

本书适用于希望学习如何在 VuePress 中构建静态站点的任何人。所有内容都由 VuePress 呈现为 HTML，然后作为 SPA 执行。这意味着一切都可以快速运行并在瞬间加载。

如果您是 JavaScript 开发人员或希望专门研究 Vue.js，VuePress 对您来说可能是一个方便的工具。本书将帮助您了解 VuePress 的功能和方法，以帮助您适应 Vue.js 的操作方式。此外，如果您希望使用 Markdown 创建一个简单的站点，比如为现有或即将推出的项目创建一个文档站点，VuePress 可能是完美的解决方案。在这种情况下，这本快速入门指南就是您掌握 VuePress 所需的全部。

此外，如果您只是想学习一些关于静态站点和静态站点生成器的知识，那么这本书也适合您！

# 本书涵盖的内容

第一章《静态站点生成器和 VuePress 简介》向读者介绍了静态站点生成器，如 Jekyll、Hugo 和 Hexo。在特别讨论 VuePress 之前，本章还将讨论与静态站点生成器相关的各种优势和可能的缺点。

第二章《开始使用 VuePress》介绍了 VuePress 的大致情况。本章将涵盖诸如对 Vue.js 的基本理解、VuePress 是什么、它能做什么（以及不能做什么），以及如何在 VuePress 中开始的概念。此外，本章还介绍了 VuePress 的全局级别和依赖项安装。

第三章《VuePress 开发-初步步骤》包括了与 VuePres 配置数值相关的笔记，包括基本级别和构建流水线。除此之外，本章还包括了 VuePress 中的资源处理和 URL 结构。

第四章《在 VuePress 中创建网站》是我们开始实际网站开发的地方！本章包括了关于如何在 VuePress 中构建关于咖啡的静态网站的逐步教程。该网站的代码（Markdown 和渲染的 HTML）可以在本书的 GitHub 存储库中找到。

第五章《在 VuePress 中使用 Markdown》涵盖了 VuePress 中的 Markdown 使用。如果您对 Markdown 不熟悉，本章还包括了对其语法和格式的简要介绍，以及如何在 VuePress 中使用 Markdown。

第六章《在 VuePress 中进行主题开发》涉及 VuePress 中的主题开发。本章讨论了默认主题定制、导航栏和侧边栏设置、Git 集成以及自定义主题开发等主题。

第七章《在 VuePress 中做更多》以讨论 VuePress 中的国际化开始。它还教你如何在 VuePress 中本地化你的网站，然后讨论了 VuePress 的增长潜力、未来路线图以及与 VuePress 相关的其他因素。

第八章《将 VuePress 部署到网络上》涵盖了将 VuePress 部署到 Heroku、Netlify 和 Surge.sh 等托管提供商的远程服务器上。本章采用了详细的逐步方法，以帮助您轻松部署 VuePress 网站。

# 为了充分利用本书

以下技能、工具和实用程序可能会对您有所帮助，并帮助您充分利用本书：

+   **工作站**：显然，为了真正学习 VuePress 开发，您需要一台计算机，无论是笔记本还是台式机。如果您的计算机内存不多，也不用担心；VuePress 对资源使用并不是很大。

+   **基本编码技能**：您需要对 JavaScript 和 Vue 有基本的了解。如果没有，您可能仍然能够使用 VuePress，尽管需要额外的时间。然而，为了在 VuePress 中构建合法的网站，肯定需要对 Markdown 有一定的了解。

+   **代码编辑器**：建议使用一个好的代码编辑器来更好地格式化您的代码和文件。作者通常使用 Visual Studio Code，但您可以选择任何您喜欢的免费或付费编辑器。

+   **Node.js 和 npm**：运行 VuePress 需要 Node.js 8+。安装方法在本书的第二章中有介绍。

+   **互联网连接和网络浏览器**：这个显而易见！没有浏览器和互联网，您无法构建和部署网站。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)注册并直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码捆绑包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/VuePress-Quick-Start-Guide`](https://github.com/PacktPublishing/VuePress-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的图书和视频目录的其他代码捆绑包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789535754_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781789535754_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```js
module
    .exports = {
        head: [
            [ ... ]
        ]
    }
```

任何命令行输入或输出都是这样写的：

```js
**git add --all**
**git commit -m "initial commit"**
**git push -u origin master** 
```

**粗体**：表示一个新术语，一个重要单词，或者您在屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。这是一个例子：“从管理面板中选择系统信息。”

警告或重要提示会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：介绍静态网站生成器和 VuePress

在网页开发的早期，所有网页都是基于 HTML 和 CSS 的。一切都是静态的，内容管理系统等概念是闻所未闻的。动态数据库驱动的应用程序也是相当晚期才出现的。

然而，随着 WordPress 和 Drupal 等内容管理系统的出现，网站开发开始加快了步伐。静态网站和页面被动态查询驱动的页面所取代，这些页面从后端数据库获取数据，并将数据写入后端数据库。当然，这样做可以更好地控制和更好地组织内容。

与这种动态数据库驱动的内容管理系统相关的优势是很多的。首先，你可以按自己的喜好呈现和存储你的内容！你可以拥有多个用户帐户，每个帐户都有自己的设置，自定义后端和前端，等等。

此外，对于最终用户来说，基于数据库驱动的动态网站管理程序可以提供更容易访问和用户友好的界面。

说到这一点，静态网站生成器又是什么呢？最近，许多新的静态网站生成器正在崭露头角并获得动力。它们有特定的用途吗？更重要的是，当我们说“静态网站生成器”时，我们到底是什么意思？

在本书的过程中，我们将学习 VuePress，这是一个令人兴奋和有用的工具，可以帮助您在几分钟内生成快速易操作的网页。我们将探讨它的各种功能、能力、限制和依赖，以及我们如何充分利用它，比如通过自定义主题、扩展、配置等等！

VuePress 在静态网站生成器的世界中仍然可以说是相对较新的，尽管它已经存在了一段时间。对于任何熟悉 JavaScript（JS）的人来说，Vue.js 肯定不是一个陌生的名字。这是一个 JS 框架，每天都在吸引着忠实的追随者。以下是 Vue.js 的简要概述。

以下是本章我们将涵盖的一些主题：

+   什么是 Vue.js？

+   什么是静态网站生成器？

+   静态网站生成器的优缺点

+   一些主要的静态网站生成器及其与 VuePress 的比较

+   什么是 VuePress？

+   为什么要使用 VuePress？

# Vue.js 到底是什么？

Vue.js 是一个 JS 框架，可以让你构建用户界面。与许多其他庞大的 JS 框架不同，Vue 可以用来创建特定内容的单页面 Web 应用程序。它可以与其他库和项目集成，以满足你的需求。

详细讨论 Vue.js 显然超出了本书的范围。值得一提的是，Vue.js 是一个更专注于*视图*方面的 JS 框架——它是渐进式的，开源的，并且得到了忠实的社区支持。它可以被适应为以你希望的方式呈现你的网页和数据！

正如我们所看到的，Vue.js 在 JS 框架的世界中并不是一个小角色。因此，VuePress 有一个非常坚实的基础。但即使你不熟悉 VuePress，你也可以在阅读本书的过程中掌握它。

然而，对于那些仍然在想为什么像 VuePress 这样的东西值得麻烦，以及与 VuePress 等静态站点生成器相关的交易是什么，我们应该首先了解一些与这类站点生成器相关的基本信息。

# 什么是静态站点生成器？

因此，在继续之前，让我们首先简要了解静态站点生成器的概念。当我们说*VuePress 是一个静态站点生成器*时，我们是什么意思呢？

简而言之，静态站点生成器做的就是其名字所暗示的——它生成一组静态的网页。因此，一旦部署，静态站点生成器可以快速地动态生成网页。

大多数静态站点生成器通过一种非常简化的文件结构来工作。你会得到一组 HTML 文件，再加上一些 CSS 样式表来更好地呈现内容，就是这样。除此之外，我们只需要一组 JS 文件。没有复杂的插件、数据库或额外的内容管理选项。

为了更好地理解静态站点生成器（如 VuePress）的运作方式，我们可以将它们与基于数据库驱动的动态内容管理系统进行比较，比如 WordPress。

# 将静态站点生成器与动态站点生成器进行比较——方法论上的差异

WordPress，或者任何其他基于动态数据库的 CMS，究竟是如何工作的呢？

当用户访问特定的 WordPress 网站时，浏览器会向托管该站点的服务器发送请求。然后，WordPress 分析请求，并根据此准备数据。这可能意味着加载给定的帖子以及其媒体元素，显示评论，查询帖子的元数据等。为了获取此类信息，WordPress 需要查询并从其数据库服务器中提取数据。

因此，实际上，我们在这里采用了三步方法：

1.  用户或客户端向 WordPress 服务器发出请求

1.  WordPress 查询并从其数据库中提取所需数据以完成请求

1.  所请求的信息呈现给用户

现在，如果我们去除对数据库的依赖呢？如果我们绕过所有不需要的代码和方法，只是以静态形式生成页面呢？当然，我们可能无法展示复杂的操作，例如自定义插件功能，电子商务集成等。但我们将完全克服上一个示例中的第二步，如下所示：

1.  用户向服务器发出请求

1.  CMS 根据请求向用户呈现静态页面

通过这样做，我们在某种程度上加快了整个网站的性能。此外，由于没有对数据库的重复查询，我们还减轻了服务器负载。

这是动态内容管理系统和静态站点生成器之间的主要区别。虽然支持者可以就双方进行辩论，但基本区别在于工作方式。

# 静态站点生成器的优势

现在我们已经看到了像 VuePress 这样的工具与 WordPress 之类的工具有何不同，使用静态站点生成器工作流程有什么好处？简而言之，静态站点生成器（如 VuePress）有什么好处？

首先，这种静态站点生成器在运行时消耗的资源要少得多。您可以在具有比动态内容管理系统驱动的网站所需内存更少的服务器上运行使用生成器构建的博客或网站，例如 VuePress。此外，由于没有数据库或自定义数据查询需要处理，因此磁盘空间和带宽消耗也相对较少。

事实上，众所周知，您甚至可以在几兆字节的空间中部署和运行个人博客使用静态站点生成器！其他所有条件不变（视频、图片和博客文章），缺少数据库确实在这里创造了一个非常轻盈的氛围，操作速度更快。

静态站点生成器几乎总是比动态内容管理系统更快。事实上，像 VuePress 这样的静态站点生成器一旦调用，就可以作为单页面应用运行。这意味着不会有重复的查询或调用来加载页面。一切都可以立即加载！正如您可能已经意识到的那样，在互联网上，速度和页面加载时间非常重要，因为人们往往注意力不集中，耐心也不足。

此外，由于谷歌和其他搜索引擎通常将页面加载时间视为排名因素，静态站点生成器默认情况下对搜索引擎友好。当然，您仍然需要处理元数据、站点地图等，但基本的担忧“我的网站加载慢”将被解除。通常，像 VuePress 这样的单页面应用甚至不需要单独的缓存机制。

静态网站往往比动态网站更安全是一个常见的观念。原因在这里非常明显——静态网站没有数百行 PHP（或任何其他语言）代码、数据库和其他可能被黑客攻击的内容。您不必担心 WordPress 或 Drupal 版本过时。

同样，几乎没有糟糕编码或恶意插件或主题破坏您的辛勤工作的威胁。静态站点生成器大部分数据以 HTML、CSS 和偶尔的 JS 文件的形式存储。除了暴力破解密码，糟糕的代码几乎没有可能导致任何恶意软件或安全威胁。代码注入、隐藏在服务器端文件中的恶意代码、损坏的数据库条目等等，在这里都是过去的事情。

对于高级用户，静态站点生成器提供了更大的定制和个性化空间。不喜欢某个功能？希望调整一些东西以符合您的喜好？代码完全由您自定义，而且由于没有绝对要求拥有数据库或插件，您可以按照自己的意愿构建您的网站或博客！这是为什么许多高级用户倾向于静态站点生成器，特别是对于他们的个人项目和网站。

另一方面，这种高度定制化可能并不是每个人的菜。对于不太喜欢定制化的人来说，静态站点生成器可能会显得令人望而却步。但对于开发人员来说，这简直是天堂！

好吧，既然我们已经看到了这些优点，可以肯定的是，像 VuePress 这样的静态站点生成器是相当有能力的工具。加上速度和安全性的优势，你可以按照自己的喜好创建网站和页面，而不必担心动态数据库需求、安全插件、代码注入等等。

# 静态站点生成器的缺点

每件事都有好坏两面，静态站点生成器也不例外。

这种站点生成器最大的缺点是学习曲线陡峭。通常情况下，你需要调整工作环境才能安装站点生成器。正如我们将在接下来的章节中看到的，安装通常会很顺利，但你需要确保所有依赖和变量都得到充分满足。

对于初学者来说，这种方法通常太复杂了。如果你无法安装所有必需的框架和库，那么你很可能无法让静态站点生成器正常运行。

虽然静态站点生成器非常适合创建博客和基本网站，但并不是所有网站都适合使用它们。对于电子商务、复杂的数据库驱动内容网站和其他内容感知项目，静态站点生成器通常不是最佳选择。

值得一提的是，与 WordPress 或 Drupal 相比，大多数静态站点生成器相对较不为人知。这对于像 VuePress 这样的实体尤其如此。这意味着从另一个 CMS 迁移现有的博客或站点可能需要一些时间。

另一方面，将 VuePress 博客或站点迁移到另一个 CMS 可能会更加耗时。在成功迁移之前，你几乎肯定需要处理一些代码并调整一些设置。但是，从 WordPress 迁移到 Drupal，或者反之，通常非常容易，因为有各种免费和付费插件可供使用。

这表明静态站点生成器有其优缺点。但对于这些生成器的用途——博客和简单静态网站项目的创建，它们几乎可以说是完美的。此外，由于目标受众包括了知道自己在做什么的开发人员和爱好者，而不是需要拖放解决方案的最终用户，静态站点生成器不需要迎合所有人。这使得未来的开发路线图更加精简和集中。

但现在我们已经谈了很多关于静态站点生成器，我们有哪些选择呢？与其他任何事物一样，你可以选择很多生成器。在本书中，我们将完全专注于 VuePress。

然而，我们必须牢记 VuePress 是一个相对较新的平台，仍在积极开发中。因此，为了充分了解 VuePress 的重要性和用法，我们至少需要了解一些其他静态站点生成器。这将帮助我们更好地理解 VuePress 的重要性，并展示 VuePress 的特殊之处。我们不会详细介绍各种静态站点生成器，只会简单提及一些最流行的生成器。

此外，虽然本书的范围实际上超出了对多个静态站点生成器进行详细比较的范围，但我们仍将说明 VuePress 与某些其他静态站点生成器相比的情况，以便已经熟悉某个静态站点生成器（比如 Jekyll）的开发人员或读者更好地评估 VuePress 可以期待什么。

# 一些主要的静态站点生成器

现在是时候看一下一些主要的静态站点生成器了。

我们将主要关注那些没有外部数据库并且在性质或功能上类似于 VuePress 的生成器。

# Jekyll

我们名单上的第一个生成器已经存在了相当长的时间。事实上，Jekyll 在静态站点生成器的世界中已经成为一个常见的名字。它是一个简单易用的工具，可以直接使用，并实现一个简单的想法——将您的纯文本文件转换为作为静态站点运行的博客或网站。

Jekyll 不依赖于数据库，并消除了大多数不需要的动态内容管理系统的功能。您可以使用 Markdown、Liquid 或其他格式编写内容。由于所有内容都以静态页面的形式呈现，速度提升也是相当可观的。

与 VuePress 相比，Jekyll 有一个非常明显的优势：它具有博客意识，并允许您轻松地从其他平台迁移您的博客。通过博客意识，我们指的是 Jekyll 能够很好地识别类别、标签和其他博客特定的实体或元数据。正如我们将在本书的第四章中学到的，VuePress 默认情况下并不完全具有博客意识，因此您需要额外工作才能在 VuePress 中获得与 Jekyll 开箱即用相同的结果。

也就是说，Jekyll 不依赖于 Vue.js，实际上主要基于 Ruby。对于 JS 程序员来说，调整 Jekyll 有时是一个挑战。

Jekyll 的主页可以在[`jekyllrb.com`](https://jekyllrb.com)找到。

# Hugo

Hugo 是另一个非常受欢迎且完全开源的静态网站生成器。它使用 Apache 许可证，并基于 Go 语言。因此，对于使用或熟悉 Go 编程语言的程序员来说，Hugo 通常是静态网站生成器领域的事实选择。

但这并不是 Hugo 的最终卖点。与许多其他静态网站生成器不同，Hugo 还可以很好地与大多数动态 API（自定义内容、分类、菜单等）配合使用。在这方面，Hugo 更像是静态网站生成器和动态 CMS 之间的混合体。此外，Hugo 还配备了用于 SEO 和网站分析的模板。此外，Hugo 还有各种自定义短代码和大量的主题可供选择，以便充分利用您的网站或博客。

然而，对于一些寻求极简主义并且不想使用无数短代码或 API 的人来说，Hugo 可能会显得过于复杂。它更像是初学者友好的 CMS 和开发者友好的网站生成器之间的妥协。学习曲线也不是很困难。

Hugo 的主页可以在[`gohugo.io`](https://gohugo.io)找到。

# Gatsby

现在，最后，让我们来看一些基于 JS 的网站生成器！

Gatsby 是一个基于 JS 的静态网站生成器，使用 React 作为其模板引擎。显而易见的部分？由于 React 的流行，Gatsby 在其社区中自然拥有大量忠实用户。这里的工作方式很简单：Gatsby 可以从大量来源获取数据，然后处理数据以生成静态网页，这些网页可以托管在您选择的平台上。

因此，如果您的数据以无头 CMS、数据库、自定义动态 API、JSON 甚至动态内容管理系统（如 WordPress 或 Drupal）的形式存在，您可以使用 Gatsby 处理这些数据，然后将其导出为静态页面。换句话说，如果您希望创建设备感知型渐进式 Web 应用程序，并且正在使用 React，Gatsby 是理想的工具。Gatsby 就像一个 JS 框架，可以根据项目的需求进行扩展。但是，与 VuePress 相比，Gatsby 在某种程度上受限于依赖 GraphQL 和 React。

Gatsby 主页可在[`www.gatsbyjs.org`](https://www.gatsbyjs.org)找到。

# Hexo

Hexo 是一个静态网站生成器，主要以其创建博客、文档网站和其他需要频繁更新内容的项目的能力而自豪。它有自己的插件系统，甚至可以使用具有类似渊源的其他项目的插件。

Hexo 也基于 JS，在遗传学上与 VuePress 非常接近。但是，它并不完全依赖于 Vue.js。事实上，Hexo 与 VuePress 最大最明显的区别在于前者的主题架构是基于字符串的，而不是源自 Vue。

Hexo 主页可在[`hexo.io`](https://hexo.io)找到。

# Nuxt.js

我们列表中的最后一个条目 Nuxt.js 与 VuePress 有很多共同之处。与 VuePress 一样，Nuxt.js 也基于 JS，并使用 Vue.js 作为其模板引擎。事实上，Nuxt.js 本身就是一个非常强大的工具包，几乎可以完成 VuePress 所宣称的大部分功能。

因此，如果 Nuxt 是我们问题的答案，那么为什么还需要 VuePress 呢？原因很简单——Nuxt.js 主要用于基于 Vue.js 创建应用程序，但对于生成静态网站和博客，VuePress 是更好的选择！因此，VuePress 非常适合创建以内容为中心的网站和实体，如博客、文档网站等。Nuxt.js 通常处理基于 Vue.js 的应用程序，而不是以内容为中心的网站。

Nuxt.js 的主页可以在[`nuxtjs.org`](https://nuxtjs.org)找到。

好了，我们现在已经讨论了一些主要的静态站点生成器。那么，VuePress 有何特别之处呢？

# 为什么要使用 VuePress？

根据我们对其他静态站点生成器的简要讨论，很明显 VuePress 可以在其他静态站点生成器可能不够的情况下证明其有用。例如，请考虑以下情况。

如果您正在使用 JS，VuePress 是一个不错的选择。现在越来越多的开发人员转向 JS，因为它非常灵活、可扩展，并且可以轻松完成大型项目。此外，如果您不喜欢将 React 或 AngularJS 作为默认框架，Vue.js 在实力和功能方面是一个自然的选择。

如果您不需要创建仅应用程序项目，但需要用于构建内容为中心的网站的东西，VuePress 是一个值得选择的选项。

由于 VuePress 的主题引擎基于 Vue 本身，如果您刚开始使用 Vue.js 框架，它可能会成为一个很好的学习工具。

好了，现在我们已经了解了 VuePress 是什么，静态站点生成器可以做什么，以及为什么我们应该使用它。现在是为即将到来的事情做好准备的绝佳时机——VuePress 开发、定制、部署等等！

# 开始使用 VuePress 的入门

在接下来的章节中，我们将深入讨论与 VuePress 相关的概念。首先，我们将从安装开始，然后转向基本定制、调整、开始博客或网站、自定义主题等。

但是正如您所看到的，安装显然是第一步。VuePress 在磁盘空间、带宽或内存方面并没有巨大的需求。事实上，您甚至可以在共享托管环境中运行它，假设您的网络托管提供商支持所需的 JS 脚本（尽管在实际情况下，目前并没有多少共享主机可以这样做）。

如果您熟悉 JS 开发，您可能已经知道您需要什么以及如何获得它。很有可能您已经设置了这样的环境。为了帮助您为即将到来的事情做好准备，这里是运行 VuePress 所需的基本概述：

这里最大的先决条件是您需要 Node.js 版本 8 或更高版本。它将与 npm 捆绑在一起，所以请确保您的环境具有正确版本的 Node.js。

除此之外，要求很简单。对于生产网站，使用一些服务器端缓存总是一个好主意。正如前面所指出的，静态站点生成器如 VuePress 在其自身速度上相当快，因此不需要自定义编码的缓存系统。

服务器端缓存机制可以进一步提高网站的性能。

目前就是这些了。我们将把编码细节和其他输入留到接下来的章节。

# 摘要

在本章中，我们讨论了很多内容。我们了解了静态站点生成器，它们是什么，为什么我们应该使用它们，以及它们提供的优缺点。虽然我们不能在每种情况下都使用静态站点生成器，但在各种类型的网站、博客和其他项目中，这些生成器都可以证明是有用的。

现在，在静态站点生成器的世界中，我们有很多选择。然而，VuePress 对于希望创建内容依赖型网站并将其呈现为单页面应用以实现更快页面加载的人来说是一个不错的选择。VuePress 依赖于 Vue.js，因此，对 JS 及其框架方法论的一些了解对于帮助你充分利用 VuePress 是必不可少的。

随着我们在本书中的进展，我们将更详细地了解 VuePress。在接下来的章节中，我们将花一些时间熟悉 Vue.js 及其功能。这将帮助那些不是专家的读者来使用 Vue.js。

此后，我们将继续学习 VuePress，从安装、操作环境、设置、配置等方面开始。更重要的是，我们还将介绍安全步骤，以确保我们的生产网站安全无虞。在下一章中见到你，我们将开始学习 VuePress 开发的旅程！


# 第二章：开始使用 VuePress

在[第一章]（4e1526aa-d994-42d8-9a18-12374ba932a0.xhtml）中，*介绍静态站点生成器和 VuePress*，我们了解了静态站点生成器是什么，以及它们可能的优势，以及为什么我们应该使用它们。此外，我们还介绍了一些主要的静态站点生成器，以及 Vue.js。

在这一章中，是时候把我们所有的注意力转向 Vue.js 和 VuePress 了。当然，如果您对 VuePress 的工作方式不熟悉，您可能目前感到有些畏惧。但不用担心，VuePress 的设置相当容易，甚至更容易掌握。很快您就会看到，VuePress 的设置绝对不是什么难事。

然而，为了正确设置和安装 VuePress 并确保满足所有依赖关系，我们首先需要花一些时间熟悉 Vue.js。这将帮助我们更好地理解为什么 VuePress 需要特定的系统设置才能工作，以及如何才能充分利用这个简单而迅速的站点生成器。

因此，是时候把我们的注意力转向 Vue.js 了。

在本章中，我们将讨论以下主题：

+   开始使用 VuePress

+   基本的 Vue.js 术语

+   将 Vue.js 与其他 JavaScript（JS）框架（如 React 或 Angular）进行比较

+   理解 VuePress 的方法论

+   VuePress 的安装和基本配置

# 开始使用 Vue.js 和 VuePress

在我们转向 VuePress 及其与 Vue.js 的关联之前，让我们看看 Vue.js 是什么，以及它对我们有什么用处。

# 什么是 Vue.js？

简而言之，Vue.js 是一个主要用于构建用户界面的开源 JS 框架。它使用 MIT 许可证，这意味着您可以扩展其源代码并使用它构建新项目。

Vue.js 最大最明显的目标是成为固有可采用的。因此，如果您的项目使用其他 JS 库或框架，您不必放弃它们来使用 Vue.js——相反，您可以选择将其与您可能已经在使用的其他 JS 库或框架一起使用。

Vue.js 可以轻松驱动单页面应用程序，也可以作为 Web 应用程序框架。

那么，Vue.js 背后的重要之处是什么，使它与其他框架不同？Vue.js 的主要动机或灵感是简化 Web 开发。此外，它大多是非主观的，因此为开发提供了统一的一套方案。

因此，Vue.js 更多地面向用户界面（UI）开发。你可以将其核心组件嵌入到任何现有项目中，甚至可以利用构建工具和支持库来设置单页面应用程序。

所有 Vue 模板都是有效的 HTML，可以被任何现代 Web 浏览器读取和解析。这意味着你使用 Vue 构建的任何内容都可以轻松地在所有设备和浏览器上呈现。随着 VuePress 的进展，你会注意到 Vue 的这一特性是一个巨大的优势，可以帮助你避免许多兼容性问题。

现在，Vue 是如何工作的？实际上很简单。每当你更新 JS 对象时，Vue 都会更新视图。这种*反应性*的特性意味着输出会在进行更改时被渲染或重新渲染，而不是强制进行完全刷新。

# 一些基本的 Vue.js 术语

我们将在这里跳过有关 Vue.js 功能的详细学习，因为这超出了我们书籍的范围。要更好地了解 Vue.js 本身（而不是 VuePress），你可以查看有关该主题的任何出色的 Packt 图书。现在，我们只需要熟悉一些定义，这样当我们在 VuePress 中使用它们时，就会更容易记住。

我们已经了解到 Vue 模板遵循基于 HTML 的语法。现在，每个模板都可以附带*组件*。简单来说，组件是可重用代码块，用于扩展现有 HTML 元素的功能。

同样，Vue.js 有自己的应用过渡效果的方法。这可以以 CSS 过渡或 JS 挂钩的形式进行。在高级的 VuePress 项目中，你可能会发现自己集成自定义 JS 动画库以实现过渡效果。当然，这取决于你的项目性质，并不总是需要单页面应用程序或博客。

# 为什么不选择其他 JS 框架呢？

这一部分主要适用于那些已经具有 JS 背景并可能熟悉一两个 JS 框架的人。如果你是一个 JS 框架的初学者，而 Vue.js 是你第一个熟悉的框架，你可以跳过这部分。

然而，如果你已经了解了其他框架，你可能会想知道 Vue.js 能够提供什么其他框架不能提供的东西？

一些最流行的 JS 框架是 Angular 和 React，将在下一节中讨论。

# Angular/AngularJS

与 Angular 相比，Vue 似乎并不那么受欢迎。在实际应用中，Angular 是这两者中更大的名字——它得到了 Google 的支持，非常容易上手，并且非常受欢迎，这意味着与之相关的文献丰富。

然而，Vue 也有自己的一些好处。首先，Angular 对应用程序结构有很强的看法——这对于初学者和希望遵循特定应用程序开发模式的开发人员来说是理想的。然而，Vue 提供了更大的灵活性和对项目的完全控制。这意味着您有更多的实验空间，因为 Vue 非常适用于各种用例。

Angular 使用双向数据绑定，而 Vue 依赖其组件之间的单向数据流。在实际应用中，AngularJS（不是 Angular）在应用程序规模和重要性增长时往往变得较慢。这是因为事务之间存在多个观察者。但是 Vue 和 Angular 都没有这个缺点。

有趣的是，在 Vue 中，没有一种正确的应用程序结构方式。这意味着您有更大的灵活性和控制。但是，作为缺点，这也意味着从 Vue 到其他框架（或反之）的移植有时可能会受到严重阻碍。另一方面，Angular 具有一套良好的结构规则，可以强制执行标准，但对于一些用户来说也可能显得非常限制。

这就是为什么 AngularJS 的学习曲线非常陡峭。开发人员必须牢记各种 API 标准。对于 Vue 编码者来说，这些要求数量较少。

# React

React 和 Vue 有很多共同之处。很容易就可以为这些框架中的任何一个进行辩论——虽然 React 旨在扩展，并且从各个标准来看都是一个很好的框架，但对于许多用户来说，Vue 的学习曲线较为平缓。

话虽如此，Vue 目前在某些方面落后于 React。React 允许您为 iOS 和 Android 编写本机渲染的应用程序。这意味着您的应用程序可以在多个平台上无缝运行。Vue 目前正试图通过 Weex 来实现相同的功能，Weex 是 Apache 基金会目前正在孵化的项目。在[`weex.apache.org/`](https://weex.apache.org/)了解更多信息。

Weex 仍处于测试阶段，并没有像 React 那样被广泛采用。这使得 React 在 Vue 方面具有明显优势。

# 其他方面

Ember，另一个声誉良好的 JS 框架，与 Vue 的不同之处在于在 Ember 中，您需要为所有内容手动声明依赖项，并将其全部包装在对象中。在 Vue 中，您也可以利用普通的 JS 对象。与 Ember 相比，Vue 在性能方面显著更快更好，简单地因为 Vue 可以自动运行批量更新。

由 Google 支持的另一个 JS 框架 Polymer 与 Vue 的不同之处在于前者需要基本的 polyfills 才能工作，而 Vue 不需要任何依赖项或 polyfills（除非您的目标是较旧的 Web 浏览器）。

因此，我们可以看到与其他 JS 框架相比，Vue 有自己的几个优势和好处。如果您是 React 或 Angular 用户，您可能已经评估了 Vue 与其他框架的不同之处。它简单，允许组件的重复使用，并且消耗更少的资源。

# Vue.js 与 VuePress 有什么关系？

VuePress 自称为“Vue 动力”，这正是两者之间的关系。Vue.js 驱动 VuePress，换句话说，VuePress 基于 Vue.js。

这意味着您所读到的关于 Vue.js 的所有上述功能都可以被 VuePress 用户使用。因此，VuePress 可以用来快速生成单页面应用程序，这些应用程序在 Web 浏览器中渲染非常快，并且不会对服务器资源造成压力。Vue.js 是 VuePress 的支柱意味着以下几点：

+   VuePress 操作起来快速而敏捷。

+   它可以快速加载页面和单页面应用程序（SPA）。

+   它不需要大量的内存来运行。

# 了解 VuePress 的特殊之处

VuePress 在运行后会生成静态形式的预渲染 HTML，之后它可以作为 SPA 运行，因此对于每个简单的查询都不需要重复调用服务器。

这就是 VuePress 的特殊之处。与其他网站创建工具和平台不同，VuePress 不会占用大量资源。它是一个简单的站点生成器，设置最少。正如我们将在本章后面看到的那样，设置 VuePress 不需要复杂的火箭科学或服务器管理知识。您可以在几分钟内完成设置，即使是 JS 的基本学习者也可以开始使用。

此外，如果你是 Markdown 用户，VuePress 对你来说可能会有特殊用途，因为它的整个项目结构都是基于 Markdown 的。事实上，我们将在本书的后面章节中介绍 VuePress 中的 Markdown 扩展，以帮助你更好地了解它。

总的来说，如果你希望利用 Vue 所提供的优势，VuePress 就是你应该使用的。通过合理使用 Vue 组件，以及与 Markdown 扩展和自定义模板的结合，VuePress 可以作为完美的、高度可定制的、多功能的静态站点生成器，适用于各种用户。

# VuePress 是如何工作的？

在最基本的层面上，每个 VuePress 网站都有两个主要部分：

+   一个具有基于 Vue 的主题系统的静态站点生成器

+   一个默认的 VuePress 主题，理想情况下适用于文档站点，但也可以轻松定制为其他用途

现在，VuePress 生成的每个页面都是静态 HTML，并且完全优化了搜索引擎。然而，在页面加载时，静态内容会被转换成 SPA，以实现更快的性能。

现在，正如我们所看到的，每个 SPA 都由 Vue 驱动。Vue 使用 Vue 路由器，它与 Vue.js 核心无缝集成，有助于使 HTML5 友好的 SPA 成为一项简单的任务。有关 vue-router 的更多信息，请访问[`github.com/vuejs/vue-router`](https://github.com/vuejs/vue-router)。

最终，为了打包脚本并组合代码结构，VuePress 依赖于 webpack。这是一个流行的工具，可以用来将脚本、代码、图像和其他媒体捆绑成一个统一的单元，以在现代 Web 浏览器中显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/5ab1e2c8-a3b4-45bb-9ecc-77271f40b92c.png)

你可以在[`webpack.js.org`](https://webpack.js.org)了解更多关于 webpack 的信息。

由于 VuePress 使用 Markdown，它依赖于 Markdown——也就是说，它将 Markdown 文件编译成 HTML。你也可以在你的内容中嵌入动态内容，并使用 Markdown 作为代码——它可以处理两者。有关更多信息，请访问[`markdown-it.github.io`](https://markdown-it.github.io)。

因此，我们可以看到 VuePress 使用了所有免费可用的标准工具和服务。换句话说，你不必依赖复杂的专有软件来学习 VuePress 并使用它构建你的项目。

# VuePress 能做什么？

然而，一个重要的问题是，VuePress 能实现什么？

VuePress 带有内置的 Markdown 扩展和在 Markdown 中利用 Vue 的能力。这意味着它非常适合想要快速生成网站并将内容上线的人。此外，由于其主题系统是基于 Vue 的，它对于想要使用 Vue.js 开发网站的人来说是一个很好的起点。

VuePress 提供多种语言支持，并且还具有 Google Analytics 集成。默认的 VuePress 主题非常适合文档网站和项目。它完全响应式和移动友好，具有原生的基于标题的搜索，甚至还有导航菜单和侧边栏。这意味着 VuePress 非常适合基本的网站开发、Web 应用程序和文档项目。

然而，不足之处在于，VuePress 仍然没有完美的博客支持。您可以用它来写博客，但它没有开箱即用的博客功能。同样，虽然您可以调用和使用任何您喜欢的 Vue.js 扩展，但 VuePress 本身没有任何插件。

这意味着 VuePress 是一个轻量级的站点生成器，适用于普通的网页开发项目，而不一定适用于更庞大和高度专业的项目。

# 那么其他选择呢？

你可能会想：为什么我们要使用 VuePress，而不是其他东西呢？

首先，VuePress 是一个基于 Vue 的令人兴奋的新项目，可以提供很好的学习和开发体验。

与许多其他类似工具不同，VuePress 完全专注于静态网站和单页应用程序。例如，虽然 Nuxt 与 VuePress 非常相似，但前者完全专注于构建应用程序。另一方面，VuePress 具有使其成为在线文档项目和其他静态站点的完美工具的功能。

说到文档，像 Docsify 和 Docute 这样的解决方案也是不错的选择，因为它们都基于 Vue，并且具有帮助您轻松编写技术文档的功能。然而，Docsify 和 Docute 都是运行时驱动的。现在已经普遍知道，运行时驱动的应用在搜索引擎优化方面往往表现不佳。而 VuePress 在 SEO 方面也做得很好。

同样，VuePress 也比 Hexo 更具优势。许多人使用 Hexo（甚至许多 Vue.js 用户倾向于依赖 Hexo）。但是 Hexo 对 Markdown 的渲染不如 VuePress 灵活多变，这是 VuePress 胜过 Hexo 的明显优势。

正如我们所看到的，尽管 VuePress 相对较新且相对不太为人所知，但它具有一套很好的功能，可以成为许多用户的不错选择。

现在我们已经阅读并了解了 VuePress 的工作原理以及它所提供的功能，我们可以将注意力转向实际使用 VuePress 进行设置。

# 开始使用 VuePress

现在是时候开始了。我们现在已经了解了 Vue.js 是什么以及它所提供的主要功能。此外，我们还了解了 VuePress 的作用，它与 Vue.js 的关系以及它的主要用途和功能。在这一点上，我们已经准备好开始使用 VuePress，并朝着使用它创建令人惊叹的网络项目的方向前进。

自然而然的，第一步将是安装和设置 VuePress，使其可以运行，并准备好供使用。

# 安装

必须注意的是，VuePress 需要 Node.js 版本 8（或更高版本）才能运行，因此您必须在服务器上安装 Node.js 才能运行 VuePress。

VuePress 在服务器端需要 Node.js 8 或更高版本。

有两种流行的安装 VuePress 的方式。如果 VuePress 是您唯一或主要使用的工具，您可以选择全局安装它。或者，如果您在更大的工作流中使用 VuePress，您可以选择将其作为现有项目的依赖项进行安装。

考虑到这是一个快速入门指南，旨在帮助您快速了解 VuePress，将 VuePress 用于更大更复杂的现有项目技术上超出了本书的范围。尽管如此，我们将介绍两种安装类型的命令，以帮助您了解两者之间的主要区别。

# 全局安装 VuePress

有两种方式可以安装 VuePress：

+   使用 npm

+   使用 Yarn

npm 是 Node.js 默认的工具，大多数 Node.js 开发人员对其能力非常熟悉。Yarn 也是 JS 开发人员非常流行的依赖管理系统。它可以与各种 JS 框架和库一起使用，并且非常快速，因为它可以缓存您下载的每个软件包，这样就不需要重新下载任何内容。

如果您一直在关注 JS 开发，您可能已经了解 npm 和 Yarn。就全局安装 VuePress 而言，使用其中一个并没有明显的优势——在很大程度上，这是个人偏好的问题。然而，建议在现有项目中安装 VuePress 时避免使用 npm。

全局安装 VuePress 的方法如下：

```js
# installing vuepress globally
 yarn global add vuepress
 # creating our readme file
 echo '# My VuePress Site' > README.md
 # ready to develop
 vuepress dev
 # building it
 vuepress build
```

这个例子有四个简单的步骤，您可以用它们来安装 VuePress。没有别的。现在让我们更详细地分析每个步骤，从第一个命令开始：

```js
yarn global add vuepress
```

上述命令将全局安装 VuePress。请注意，它使用 Yarn。对于 npm 用户，语法看起来会像下面这样：

```js
npm install -g vuepress
```

第二个命令如下，将为我们创建一个 Markdown 文件：

```js
echo '# My VuePress Site' > README.md
```

第三个命令是最终启动 VuePress，如下所示：

```js
vuepress dev
```

最后，构建命令如下所示：

```js
vuepress build
```

就这样。您已成功在服务器或本地主机上全局安装了 VuePress，并可以开始使用它构建下一个 Web 项目。当然，可能需要一些基本配置来进一步完善您的网站，但我们可以稍后再谈。

# 在现有项目中安装 VuePress

在现有项目中将 VuePress 安装为依赖项是个好主意。请记住，VuePress 是一个相对较新的实体，需要对 JS 开发有相当的了解，您可能已经在运行各种自己的 JS 项目。在这种情况下，在现有项目中将 VuePress 作为本地依赖项意味着您可以利用其无数的功能和能力来为您的项目服务——比如，为您的项目渲染单页面应用，或者维护内容等。

VuePress 作为本地依赖项的安装非常简单。您只需要输入相关的 Yarn 命令，如下所示：

```js
yarn add -D vuepress
```

或者，对于 npm 用户，命令将如下所示：

```js
npm install -D vuepress
```

记得我之前提到过在现有项目中安装 VuePress 时要避免使用 npm 吗？这是因为如果您的项目已经将 Webpack 3.x 作为依赖项，npm 将无法生成 VuePress 的正确依赖树或结构。值得注意的是，Webpack 非常流行，被多个 JS 项目使用。因此，在实际应用中，当将 VuePress 作为本地依赖项添加时，您应该考虑使用 Yarn。

当将 VuePress 作为 webpack 3.x 所需的本地依赖项添加时，您应该考虑使用 Yarn。

在此之后，您需要创建一个 docs 目录，如下所示：

```js
mkdir docs
```

然后，就像以前一样，我们将为我们的项目创建 Markdown 文件：

```js
echo '# My VuePress Site' > README.md
```

就是这样！

在这个阶段，您可能希望向您的`package.json`文件中添加一些脚本。值得注意的是，脚本的要求显然取决于您的项目目的和工作流程。以下是一些示例：

```js
{
 "scripts": {
   "docs:dev": "vuepress dev docs",
   "docs:build": "vuepress build docs"
 }
}
```

现在，要编写脚本，请使用以下命令：

```js
yarn docs:dev
```

或者，对于 npm 用户，命令将如下所示：

```js
npm run docs:dev
```

要为您的项目生成静态资产，请输入此命令：

```js
yarn docs:build
```

对于 npm 用户，请使用以下命令：

```js
npm run docs:build
```

生成的资产和构建的静态文件可以部署到任何服务器。这个话题需要单独讨论，我们将在后面的章节中随着 VuePress 部署的进展而重新讨论它。

现在，您应该能够做到以下几点：

+   使用 Yarn 或 npm 安装 VuePress

+   全局安装 VuePress 或将其作为现有包的依赖项安装

# 理解 VuePress 配置

到目前为止，我们已经学会了如何安装 VuePress。然而，为了有效地使用 VuePress（或者任何 JS 项目），首先要理解配置结构是很重要的。

VuePress 配置非常简单和直观。安装后，您会注意到 VuePress 项目中有一个 docs 目录，该目录将包含您在安装过程中创建的`readme.md` Markdown 文件。除此之外，您可能还会注意到一个 package.json 文件。

现在，您应该在 docs 目录内创建一个`.vuepress`目录。这个`.vuepress`目录是您的`config.js`文件所在的地方——正如任何 JS 开发人员所能告诉您的那样，这个文件应该导出一个 JS 对象。

例如，要向您的 VuePress 站点添加标题和描述，您的`config.js`文件将导出以下内容：

```js
module.exports = {
    title: 'My Fancy Title',
    description: 'my fancy vuepress site'
    }
```

上述代码将为由您的 VuePress 安装呈现的最终页面导出一个标题和描述。

以下图表显示了默认 VuePress 目录结构的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/b66f21f5-14c5-4bfe-954e-09851a4d2cc6.png)

值得注意的是，您也可以使用其他配置格式，而不仅仅使用`config.js`。例如，您可以使用 YAML（然后会有一个`config.yml`文件）或 TOML（使用`config.tml`文件）。

然而，考虑到大多数 VuePress 用户对 Vue.js 都有相当熟悉的经验，并且更习惯使用`config.js`作为默认格式，我们将在本书的整个过程中坚持使用它。

# 其他配置

VuePress 还允许您编辑主题配置以个性化您的网站。VuePress 自带了默认主题，可以进行调整和定制以满足您的需求。然而，我们将只在第六章 *VuePress 中的主题开发* 中专门讨论自定义主题开发时，才会转向主题配置和调整。

正如我们在本章前面讨论的那样，VuePress 可以用来生成单页面 Web 应用程序。这意味着您可以使用自定义钩子将应用程序级配置添加到您的 VuePress 项目中。如果您之前有 Vue.js 的经验，并希望从现有项目中导入或利用现有的 Vue.js 插件和组件，这将非常有用。

在这种情况下，您需要在`.vuepress`目录中添加一个额外的`enhanceApp.js`文件。在该文件中，您可以指定用于添加插件和注册组件的自定义钩子。`.vuepress`/`enhanceApp.js`文件的一般语法如下：

```js
export default ({
Vue, 
options,
router,
siteData
}) => {
 // enhancements come here
}
```

请注意前面代码中每个元素所扮演的角色：

+   `Vue`提到了您的*VuePress*应用程序使用的 Vue 版本

+   `options`指定了 Vue 实例的选项

+   `router`指定了路由器实例的选项

+   `siteData`包含您的应用程序的元数据

请注意，如果您的应用程序不需要应用程序级增强，则不需要应用程序级增强。

您可以在官方文档中找到 VuePress 的所有配置引用的详细列表本身[`vuepress.vuejs.org/config/#basic-config`](https://vuepress.vuejs.org/config/#basic-config)。

# 总结

这就是本章的结束。到目前为止，我们已经涵盖了与 Vue.js 和 VuePress 相关的所有基本信息。我们还了解了 VuePress 是什么，它能做什么，它可以处理什么类型的项目、应用程序或网站，以及与同类产品相比如何表现。同样，我们还熟悉了一些关于 Vue.js 的基本知识，以及它的用途、能做什么等等。

除此之外，我们还介绍了如何安装和设置 VuePress。我们学习了如何在全局范围内安装 VuePress，以及在现有项目中安装为依赖项。我们涵盖了与基本 VuePress 配置文件相关的主题。

在下一章中，我们将把注意力转向 VuePress 开发。然而，与大规模的定制开发不同，我们首先将专注于资产处理和其他定制调用。这将使您能够了解和更好地理解 VuePress 的工作原理，以及您可以使用的一些编码技巧来充分利用它。之后，我们将开始使用 VuePress 创建一个实时网站，然后进行主题开发。


# 第三章：VuePress 开发 - 初步步骤

在第二章 *开始使用 VuePress* 中，我们介绍了 VuePress 的安装和设置。在这一点上，你已经学会了如何安装 VuePress，它的系统要求是什么，以及如何设置好 VuePress 以准备实际工作。

然而，安装 VuePress 只是第一步。为了构建一个功能完善的项目，并充分利用它，你需要学会如何更多地使用 VuePress。

这一章将帮助你实现这一点。

在这一章中，你将学习以下内容：

+   VuePress 开发基础

+   VuePress 的基本配置值

+   VuePress 的浏览器配置值

+   VuePress 的构建流程配置值

+   VuePress 中的资产处理

+   处理图片、公共文件和 URL

# VuePress 开发 - 入门

在这一章中，你将学习关于在 VuePress 中处理资产和处理文件和 URL 的概念。现在，由于 VuePress 是一个静态网站生成器，事情往往与你在 WordPress 等数据库驱动的内容管理系统中找到的有些不同。

考虑到在第四章 *在 VuePress 中创建网站* 中，我们将实际上使用 VuePress 设置一个演示网站，因此你需要对 VuePress 中如何处理文件和 URL 有一个很好的理解。第四章 *在 VuePress 中创建网站* 将帮助你规划网站或博客的完美结构。

# VuePress 配置值

在继续之前，我们需要花一些时间确保我们理解 VuePress 通常支持的配置的性质。

# VuePress 的基本配置值

首先，我们需要熟悉 VuePress 中使用的基本配置值。这个列表并不完整，你应该参考 VuePress 文档获取完整的列表，可能会跨越多个页面。

为了清晰起见，避免混淆，我们将在讨论自定义主题的章节中讨论与主题相关的配置。同样，我们将在有关 VuePress 中的 Markdown 的章节中讨论与 Markdown 相关的配置值。

# 标题

此值显示 VuePress 站点的标题。默认情况下，它被添加到站点上的所有页面，并显示在导航栏中，但您可以更改此功能：

```js
Type: string
Default: undefined
```

# 描述

这显示了站点的元描述。因此，在页面 HTML 中，它在`<meta>`标签内呈现：

```js
Type: string
Default: undefined
```

# 头部

这包括在 HTML 中呈现页面时在`<head>`标签内呈现的附加数据。通常，它采用在`[`和`]`方括号内封装的内容的合并形式。

基本语法如下：

```js
module
    .exports = {
        head: [
            [ ... ]
        ]
    }
```

自然，头部配置是数组类型，其一般默认形式为`[ ]`（空数组）。

# ga

此配置实体帮助您将 VuePress 站点与 Google Analytics 集成。如果您在 Web 开发领域活跃，您可能已经意识到 Google Analytics 可以为您的站点提供大量资源。因此，您只需将您的 Google Analytics ID 传递给此配置值，就可以了。

`ga`是数组类型，默认值为未定义，因为您需要将您的 Google Analytics ID 传递给它。

# 区域设置

此特定配置变量支持国际化和本地化；也就是说，与将站点翻译成其他语言的兼容性。由于我们已经有了一个专门讨论 VuePress 中国际化和本地化处理的章节，我们很快将详细讨论这个配置值。

默认值为未定义，接受的类型是此处所示格式的字符串对象：

```js
{ [path: string]: Object }
```

# shouldPrefetch

有时，一些文件倾向于附有预加载资源提示。`shouldPrefetch`函数处理这些限制和提示。

`shouldPrefetch`是函数类型，默认值为`( ) => true`格式。

对于我们所说的限制和提示感到困惑？嗯，Vue.js 有一种称为`<link rel="preload">`的资源提示。默认情况下，几乎所有要异步加载的资产都会被预取，以加快页面加载时间和性能。但是，如果您在带宽有限的较弱服务器上呢？预取所有内容肯定会消耗大量带宽。

在这种情况下，您可以使用`shouldPrefetch`函数来控制哪些文件具有预取提示，哪些文件没有。通过这种选择性选项，您可以避免在服务器上消耗大量带宽。

# serviceWorker

这个相当有趣。在继续之前，你需要确保满足一定的条件才能使用`serviceWorker`配置实体：

+   `serviceWorker`只能通过 HTTPS 注册，所以你需要确保你的网站使用 SSL 证书

+   `serviceWorker`仅在生产模式下工作；也就是说，在实际的网站上

现在，serviceWorker 是一个默认为 false 的布尔类型。但是当你将它设置为 true 时，VuePress 将自动生成并注册一个 service worker 脚本。这可以用来帮助缓存内容以供离线使用。

什么是 service worker？在**JavaScript**（**JS**）中，service worker 是一种特殊类型的脚本，它是在后台由 Web 浏览器动态生成并运行的。它的运行方式与实际的网页加载不同。这里的目标是执行一些非常重要的后台功能，但不需要实际的网页或用户配置。

现在使用 service worker 脚本的情况的例子包括浏览器中的推送通知，浏览器中的离线缓存，后台数据同步以便在连接失败时更容易恢复等。

当使用自定义主题时，正如你将在后面的章节中看到的，`serviceWorker`配置值有时也会发出以下事件：

+   `sw-ready`

+   ``sw-cached``

+   `sw-updated`

+   `sw-offline`

+   `sw-error`

这里的`serviceWorker`选项只会处理 JS `serviceWorker`脚本。这意味着它不会自行生成单页面 Web 应用程序；它取决于你是否利用`serviceWorker`脚本来满足项目的需求。

再次强调，确保只有在 SSL 激活时将`serviceWorker`设置为 true，因为`serviceWorker`脚本在非 HTTPS URL 上不起作用。

# dest

这个配置变量指定了 VuePress 最终构建过程的输出目录。默认路径是`.vuepress/dist`，但你可以通过指定任何其他字符串类型的路径来更改它。

# 端口

这是用来指定连接到开发服务器的端口值。除了 localhost，你的网络托管提供商应该能够更准确地告诉你可能希望在这里使用哪个端口。

默认值是`8080`，你只能使用整数类型的值，因为端口值只能指定为整数。

# 主机

此术语指定了您可以用来连接服务器的主机地址。再次强调，您的网络托管提供商或服务器管理员应该有关于此字段的准确细节。

它接受字符串类型的值，默认设置为`'0.0.0.0'`。

# 与浏览器兼容性相关的配置值

VuePress 目前只有一个与主要浏览器兼容性相关的配置值，您应该知道。

# 常青

此配置值是`boolean`类型，默认设置为 false。

但是，如果您希望您的 VuePress 网站仅针对常青网页浏览器，可以将其设置为 true。设置为 true 时，它将禁用对 ES5 转译和 polyfill 的支持。这意味着您的网站将无法与较旧版本的**Internet Explorer**（**IE**）很好地配合。

优势是什么？构建时间将大大缩短，事情将更快地运行。此外，您的网站的最终构建大小将更小。

什么是常青网页浏览器？常青网页浏览器是指自动更新到未来版本的浏览器。因此，用户无需下载新版本并从头安装。例如，如果您正在运行 IE 8 并希望安装 IE 9，则需要下载可安装文件然后运行它。另一方面，现代浏览器的版本，如 Chrome 或 Firefox，可以在发布新更新时自动更新，而无需再次运行安装程序。

这种滚动式的网页浏览器更新模式被称为“常青网页浏览器”。大多数较新的网页浏览器是常青的，而较旧的版本则不是。

# 与构建流水线相关的配置值

现在，让我们把注意力转向与构建流水线相关的配置值。在静态内容管理系统中，如 VuePress 和 Jekyll 中，构建流水线指的是生产线；也就是说，代码从开发到生产的流程。

在这一点上，您对 JS 和 CSS 的知识将会派上用场。这些与构建流水线相关的配置值大多围绕着 webpack。由于深入研究 JS 和 CSS 加载器超出了这个快速入门指南的范围，我们将只引用相关项目的 GitHub 页面，以便您可以根据需要学习更多。

# postcss

`postcss` 可以用来指定 webpack 中 PostCSS loader 的自定义选项。有关该加载程序的详细信息，请参阅：[`github.com/postcss/postcss-loader`](https://github.com/postcss/postcss-loader)。

一旦您指定了 `postcss` 值，您将覆盖其中的任何其他 autoprefix 值。它只接受对象类型的值，其默认语法如下：

```js
{ plugins: [require('autoprefixer')] }
```

# scss

`scss` 提供了用于将 SASS 转换为 CSS 的 SCSS loader 的选项。您可以在[`github.com/webpack-contrib/sass-loader`](https://github.com/webpack-contrib/sass-loader)了解更多关于此加载程序的信息。

此配置实体接受对象类型的值，其默认格式为 `{ }`。

# stylus

stylus 配置实体提供了调整 `webpack` 中 Stylus loader 的选项。默认情况下，它接受对象类型的值，语法如下：

```js
{ preferPathResolver: 'webpack' }
```

您可以在[`github.com/shama/stylus-loader`](https://github.com/shama/stylus-loader)了解更多关于 stylus loader 的信息。

# less

此术语指定了可以用于将 LESS 编译为 CSS 的 LESS loader 的选项。有关详细指南，请参阅[`github.com/webpack-contrib/less-loader`](https://github.com/webpack-contrib/less-loader)。

它接受对象类型的值，其默认格式为 `{ }`。

# sass

这提供了可以将 SASS 编译为 CSS 并加载 `*.sass` 文件的 SASS loader 的选项。有关此加载程序的其他详细信息，请参阅[`github.com/webpack-contrib/sass-loader`](https://github.com/webpack-contrib/sass-loader)。

它接受对象类型的值，其默认格式如下：

```js
{ indentedSyntax: true }
```

# chainWebpack

`chainWebpack` 是一个具有未定义默认值的函数。

它可以帮助您通过使用 Mozilla 的 Webpack Chain API 修改内部的 `webpack` 配置。这个特定的 API 可以生成并简化 webpack 的定制和配置过程。您可以在 GitHub 上了解更多信息：[`github.com/mozilla-neutrino/webpack-chain`](https://github.com/mozilla-neutrino/webpack-chain)。

以下是一些示例代码，显示了在 VuePress 中使用 `chainWebpack` 的语法：

```js
module.exports = {
    chainWebpack: (config, isServer) => {
    // provide instance and config details here
    }
}
```

# configureWebpack

正如其名称所示，这个特定的配置实体允许您修改 `webpack` 的内部配置。因此，它主要适用于已经熟悉 `webpack` 及其用法的人。

它使用了`webpack-merge`，详细信息可以在[`github.com/survivejs/webpack-merge`](https://github.com/survivejs/webpack-merge)找到。

通常，`webpack-merge`为你提供了一个合并函数，它简单地连接数组并合并对象。这将导致创建新的对象，你可以使用它们。

在 VuePress 中，`configureWebpack`的默认值为 undefined。但是，你应该注意它可以是对象类型或函数类型之一：

+   当值为对象类型时，该值通过使用`webpack-merge`合并到最终配置中，如前所述。

+   当值为函数类型时，它接收与第一个参数相同的配置细节（第二个参数通常是一个`isServer`标志）。然后，你可以选择直接修改作为参数传递的配置，或者将其详细信息作为一个可以合并的对象返回。

当使用`configureWebpack`作为函数类型时，语法如下：

```js
module.exports = {
    configureWebpack: (configArgs, isServer) => {
    if (!isServer) {
        // modify or work with the configArgs here
        }
    }
}
```

所以，你现在已经了解了 VuePress 中所有必需的配置实体的基本细节。再次强调，我们已经省略了与主题配置相关的配置术语，以及 Markdown，这些将在后续章节中讨论。

然而，现在你知道可以期待什么术语以及在哪里——例如，当处理要用作站点图标的图像资产时，你应该在头部配置中调用或引用它，依此类推。

现在是时候学习一些关于 VuePress 中 URL 和资产处理的理论了。然后，你将准备好开发你的第一个 VuePress 站点。

# 资产处理是什么？

当我们说*资产处理*时，我们指的是什么？

在开发领域，特别是在网络开发中，资产是指项目使用或处理的任何内容。这可能包括但不限于以下内容：

+   图片

+   视频

+   其他媒体文件

+   文件，比如 PDF

自然地，为了处理这些数据文件和资产，CMS 需要实施专门的措施和协议。换句话说，你不能把 JPG 文件当作代码文件来处理——它并不能被内容管理系统完全读取，但系统必须意识到它是图像类型的媒体资产，并应该相应地处理。

在 VuePress 中，方法论相当简单。首先，我们必须了解 VuePress 中 URL 的配置方式。然后，我们可以将注意力转向公开可见的文件，如图片和图形。

# VuePress 中的 URL

通常，您希望将实时的 VuePress 站点保留在以下两个位置之一：

+   在根 URL

+   在非根 URL

对于非根 URL，您需要在您的`config.js`中指定`base`选项-是的，就是我们在第二章中讨论的同一个`config.js`文件，它位于`.vuepress`目录中。

假设我们在[mysite.example.com](http://mysite.example.com)上有一个项目，并希望在名为`vuep`的目录中部署 VuePress。因此，我们的 VuePress 实例将在`mysite.example.com/vuep/`上运行。

在这种情况下，`base`值应设置为`/vuep/`。

请注意，`base`应以斜杠开头和结尾；即`/`。

现在，一旦您指定了`base`选项，它将自动添加到所有资产 URL 之前。这意味着您在`.vuepress/config.js`文件中指定的任何资产 URL 都将在其前面添加`base`值。

目前，理论部分就是您需要了解的全部内容。此方面的实际用法将在第四章中进行，即*使用 VuePress 创建站点*，在那里我们将使用 VuePress 设置站点。

# 在 VuePress 中处理公共文件

有多种方式可以访问 VuePress 中的文件。重申一下，我们指的是媒体元素和其他资产。

您可以通过以下方式来做：

+   在您的 Markdown 组件中引用文件

+   引用主题组件中的文件

+   将文件视为公共文件

我们将在随后的章节中介绍前两个步骤。

假设您有一个需要公开查看的图像文件。通过公开查看，我们指的是它应该对站点的所有访问者可见，而不仅仅是管理员，例如站点的 favicon。

您只需要将所述图像文件放在`.vuepress/public`目录中。此后，该文件将位于生成目录的根目录，并且可以公开访问。

然后，您可以参考或指定如下示例中的内容：

```js
mysite.example.com/vuep/favfile.png
```

在这里，`favfile.png`是您放置在`/public/`目录中的文件。

简单，不是吗？

那么，如果您希望重新定位 VuePress 站点怎么办？比如，更改`/vuep`位置？您可能需要更改以这种方式制作的所有 URL 的引用。

为了防止这种情况发生，VuePress 提供了一个相当简单的解决方案。

您可以使用内置的`$withBase`助手（在 VuePress 中原生构建，无需扩展），它将自动生成正确的路径，您无需担心指定的绝对路径可能会在以后更改。

以下是如何使用它的示例：

```js
<img :src="$withBase('/favfile.png')" alt="My Fancy Image File">
```

这段代码将确保引用保持在指定的文件上，而不管您在 VuePress 中使用的基本 URL 是什么。您可以使用它来处理您的公共文件，甚至在主题组件和 Markdown 文件中使用它。

# 相对 URL 呢？

在 VuePress 中，与现代网络上的任何其他内容管理系统一样，最好和建议通过相对 URL 引用所有资产元素。例如，`./sample.jpg`可以在任何文件模板中使用。在这种情况下，目标图像将首先使用 URL-loader 和 file-loader 进行处理，然后复制到最终静态构建所需的位置。

在使用`webpack`模块（以及在本章前面提到的构建管道配置部分中提到的配置实体）时，您可以使用`~`前缀。这在许多 JS 框架中都是标准的，如果您有任何这些 JS 框架的经验，您可能已经知道它。例如，`~some-directory/sample.jpg`是使用`webpack`别名引用文件的一种好方法。

在本章的前面，我们谈到了用于配置的`configureWebpack`选项。您可以在`.vuepress/config.js`文件中使用此选项轻松配置您的`webpack`别名。

这是一个这样的示例：

```js
module.exports = {
    configureWebpack: {
        resolve: {
          alias: {
            '@alias': 'custom/path/to/directory/relative-url'
          }
        }
      }
    }
```

在前面的例子中，您只是利用`configureWebpack`来确保所说的别名指向您为项目中要使用的所需资产或元素指定的自定义路径。与其他配置工具一起使用时，它可以帮助您轻松获取资产。

这就是 VuePress 中的资产处理。在这一点上，您已经准备好进行实际的站点开发了。

# 摘要

在本章中，您已经了解了 VuePress 中大多数基本和高级配置实体。您了解了基本术语，以及在哪里可能调用值，以及哪个函数可能返回哪个值。

显然，这将假定您熟悉基本的 JS 对象、函数和调用。

此外，您还了解了 VuePress 中的资产处理基础知识，URL 是如何相对处理的，媒体元素如何被引用等等。

然而，目前看起来可能会有信息过载，因为你已经学到了相当多的理论，但到目前为止还没有将其编译成生产或开发。但就像任何其他建立在现有语言之上并提供丰富可配置选项框架的软件或产品一样，VuePress 也需要被视为这样的产品。

在《第四章》*在 VuePress 中创建站点*中，我们将构建一个实时的 VuePress 网站。您可以使用任何您选择的代码编辑器或 IDE，以及任何平台。请注意，我们将在后面的章节中专注于部署，因此建议为下一章设置一个本地站点。您已经在上一章中学习了如何安装 VuePress。

因此，在阅读《第四章》*在 VuePress 中创建站点*时，有必要在需要时参考本章。这将帮助你了解哪些配置选项可以在哪里使用，以及如何避免一些常见的问题。因此，当我们在下一章中构建 VuePress 站点时遇到特定的配置时，我们将会实际学习它。

重点将放在处理媒体文件（如图像）上，因为没有图像，你实际上无法构建一个真正的实时站点！此外，我们还将涵盖一些真实世界的概念，比如与 Google Analytics 等服务的集成（请注意，我们已经在本章的*基本配置*部分中学习了配置引用的语法；请参见本章前面的`ga`）。这将帮助您构建一个真正可用而不仅仅是花哨示例的 VuePress 站点。

因此，确保您已经掌握并对本章涵盖的术语有了相当好的理解。在那之后，让我们继续前进，构建一个 VuePress 站点！


# 第四章：在 VuePress 中创建站点

在第三章中，*VuePress 开发-初步步骤*，我们学习了与 VuePress 配置相关的基础知识，以及如何使用变量和函数。我们了解了可以调整的各种值，以个性化和设置我们的 VuePress 站点。

除此之外，在第二章中，*使用 VuePress 入门*，我们已经在系统上安装了 VuePress。根据我们可能面临的要求，我们可以选择在全局安装 VuePress，或者将其作为现有包的依赖项进行安装。

无论安装方法如何，目前最重要的是我们应该有一个可用的 VuePress 安装。而且，现在我们已经掌握了 VuePress 等静态站点生成器的能力，以及如何配置它们，是时候开始看到实际效果了。

因此，在本章中，我们将把注意力转向 VuePress 的实际实现。换句话说，我们将使用 VuePress 构建一个实际的网站。这将帮助我们更好地理解 VuePress 的工作流程，也会让我们更全面地了解其基本概念。

因此，不要浪费任何时间，让我们开始吧！

在本章中，您将学习以下内容：

+   在 VuePress 中构建站点

+   如何创建 Markdown 文件并运行 VuePress 开发引擎

+   如何在 VuePress 中构建和呈现静态站点

+   介绍`.vuepress/config.js`文件

# 在 VuePress 中构建站点

值得注意的是，在这个阶段，您应该已经有一个正在运行的 VuePress 实例。如果您还没有安装 VuePress，请参考本书的第二章，*使用 VuePress 入门*。

此外，您需要使用基本的 Markdown 文件来输入内容。大多数 Web 开发人员都很熟悉 Markdown，并且大多数人都经常使用它。如果您不知道 Markdown 是什么，或者不习惯使用它，请参考本书的第五章，*在 VuePress 中使用 Markdown*。也就是说，在本章中，我们只会涉及 Markdown 元素的表面，比如段落、标题和链接。因此，对 Markdown 的基本了解现在已经足够了。

最后，虽然我们在本章实际上会建立一个网站，但我们不会将其部署到网络上的实时服务器。关于部署的细节，我们已经单独设置了一个章节。如果您希望在建立网站后立即部署项目文件，请参阅本书的第八章，*将 VuePress 部署到网络*。

既然我们已经介绍完了，现在是时候开始在 VuePress 中进行网站开发了！

# 我们将要建立什么？

大问题是：我们究竟要建立什么？

我们将使用 VuePress 创建一个简单的网站。举例来说，让我们假设这个给定的网站是关于咖啡的。

这是我们打算如何构建它的方式：

+   一个主页，详细介绍网站内容（并有一个呼吁行动的按钮）

+   一个关于页面

+   一个关于咖啡本身的示例页面

此外，我们的网站还将有一个导航菜单，链接到我们所有的页面，以及一个外部链接。实质上，我们希望在 VuePress 中构建一个多页面静态网站，具有自定义的主页视图。

以下是最终主页应该看起来的示例：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/c9a66607-bc1e-4917-b633-1a7a0535ad3d.png)

# 创建一个 VuePress 网站

既然我们已经明白了我们要做什么，让我们开始建立我们的网站吧。

# README.md 文件

在 VuePress 中，`README.md`文件充当我们的主页。自然而然，这就是 index.html 文件中的所有内容应该放置的地方。

我们可以在 Markdown 中编辑此文件，以包含我们需要的一切。除此之外，我们还可以使用 YAML Front Matter 语法来指定主页的自定义选项，比如区域设置、与 SEO 相关的元数据和自定义布局。

安装了 VuePress 之后，我们可以立即使用以下命令创建一个`README.md`文件：

```js
echo ‘Hello World!' > README.md
```

这个命令将创建一个包含“Hello World!”一行的简单的 Markdown 文件。输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/551ae3e7-d7b5-4c1e-b312-d3d0dc2e3121.png)

显然，这对我们的主页来说是不够的，对吧？我们很快将建立一个自定义的主页。

# 启动开发引擎

此时，打开终端（或命令行）并运行以下命令是一个好主意：

```js
vuepress dev
```

这将启动 VuePress 的开发引擎，看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/ee5f242c-6278-4a90-9bc5-cab24e6b09a3.png)

现在我们可以在网页浏览器中打开上面截图中显示的 URL，并且当我们对文件结构进行更改时，页面将自动刷新以展示实时更改，只要开发引擎正在运行（也就是说，终端是打开的），那么我们就可以在保存内容时查看实时更改。

确保在安装 VuePress 的确切目录中运行`vuepress dev`命令。所有文件都将放置和创建在其中，包括 Markdown 文件，任何媒体元素，以及任何 JS 配置文件。

# 构建首页

还记得我们刚刚创建的`README.md`文件吗？让我们打开它并稍作编辑。

任何编辑器都可以用来编辑 Markdown 文件。我个人只是在 Linux 中使用默认的 xed 或 gedit 文本编辑器。你也可以选择使用流行的代码编辑器来编辑 Markdown 文件。

我们将添加我们的前置内容，以生成一个自定义的首页。我们将使用 YAML 前置内容。如果你对此不熟悉，不用担心——我们将在下一章中更详细地讨论 Markdown 时进行介绍。

我们的首页应该有一个标题，后面跟着一个呼吁行动的按钮，鼓励我们的访客了解更多关于产品的信息。然后，我们还将添加三个单独的部分，向世界介绍更多关于我们的产品。最后，我们将添加页脚布局。

现在，让我们构建首页。

非常重要的是要知道，VuePress 默认主题附带了自己的首页布局。我们所要做的就是在前置内容中指定我们希望使用首页布局。为了做到这一点，我们只需要输入以下内容：

```js
---
home: true
---
```

然后，我们将添加额外的条目，比如我们的呼吁行动按钮文本和链接，如下所示：

```js
---
home: true
navbar: true
actionText: Learn More →
actionLink: /about
---
```

现在我们可以保存文件以预览更改。再次提醒，我们正在对刚刚创建的`README.md`文件进行更改。

如我们在下面的截图中所看到的，已经添加了一个呼吁行动的按钮，链接到一个*关于*页面（尚未创建，因此点击按钮将显示 404 错误）。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/4e0593f4-7cde-4304-b19e-c86543203743.png)

接下来，我们可以将剩余的内容添加到我们的前置内容中。以下是前置内容现在应该看起来的样子：

```js
---
home: true
navbar: true
actionText: Learn More →
actionLink: /about
features:
    - title: Caffeinated
    details: It is obvious that coffee is surely the greatest beverage known to humans.
    - title: Keeps You Awake
    details: Grab some strong coffee and stay awake forever... probably not a healthy idea though.
    - title: Good for Coding
    details: Nobody accepts this but programming is definitely impossible without coffee.
---
```

我们在首页添加了一个特性部分。我们添加了三个特性，每个都有自己的标题和正文内容。

因此，我们的首页应该变成以下样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/c5bad76e-fb41-41c2-998f-a9507214a166.png)

接下来，我们只需要添加页脚。我们只需要在我们的前置内容中指定一个页脚条款，如下所示：

```js
---
footer: MIT Licensed | A sample VuePress site built by Sufyan bin Uzayr
---
```

我们选择了 MIT 许可证，因为 VuePress 也使用这个许可证。当然，这完全取决于您如何希望对您的内容进行许可。

添加了页脚之后，我们的首页应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/fcf4fa9d-5480-40e9-a309-8a2754710737.png)

# 添加元数据

一旦我们建立了首页，我们也可以在前置内容中添加一些元数据，如下所示：

```js
---
meta:
    - name: description
    content: Just a simple VuePress site about coffee.
    - name: keywords
    content: vuepress coffee
lang: en-US
---
```

在上面的片段中，我们为我们的网站添加了一个元描述，并指定了一些关键词。此外，我们告诉引擎和爬虫我们的网站使用的是美式英语。

到这一点，我们的`README.md`文件应该看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/3af276f0-ad11-4568-938c-977704284048.png)

显而易见，整个文件仅由前置内容组成。我们将在第五章中详细学习有关 YAML 前置内容，*在 VuePress 中使用 Markdown*，以及在第六章中，VuePress 主题开发时，我们将讨论主题开发。

目前，我们的首页已经准备好了。我们可以选择在 Markdown 中向这个文件添加任何其他内容。这些内容需要在前置内容之后添加，尽管它将显示在页脚之上和首页英雄内容之下。

# 添加其他内容页面

现在我们的网站需要额外的页面来展示更多的内容。考虑到 VuePress 是一个静态网站生成器，我们只需要相应地添加内容，VuePress 会处理其余的工作。

是的，就是这么简单！：

1.  我们将我们的内容添加为 Markdown 文件

1.  VuePress 从这些 Markdown 文件中生成 HTML 文件，只要这些文件是有效的格式

就是这样。因为 VuePress 仍然不是一个博客或电子商务引擎，所以没有需要添加的自定义分类，或类似的东西。

对于我们的网站，我们将添加两个页面。第一个将是一个*关于*页面，第二个将是一个关于咖啡的页面。

对于我们的*关于*页面，我们在与`README.md`文件相同的目录中创建一个`about.md`文件。然后，我们可以用任何我们喜欢的内容填充我们的网站。这是我们在网站上使用的示例：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/c6b20e73-e679-46f0-a087-3132460aa337.png)

输出应该显示如下（确保在添加此文件后再次运行`vuepress dev`命令）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/35b9da51-5822-4988-b9d9-e0565c64c76f.png)

要查看输出，只需将 Web 浏览器导航到`/about.html`，根据开发引擎显示的本地主机地址。

值得注意的是，VuePress 自己处理了一些事情：

+   表情符号基于 GitHub 表情符号服务显示。

+   更重要的是，Markdown 中的每个 H1、H2、H3 和其他类似的标题标签在 HTML 中都被视为锚链接。您可以将光标悬停在任何标题上，注意到自动生成了一个锚链接。

同样，我们也可以添加`coffee.md`文件。实际上，我们可以添加任意数量的页面。我们只需要添加 Markdown 文件，并告诉 VuePress 正确的位置。

# 添加导航菜单

在这个阶段，我们已经向网站添加了所有页面和内容。我们还建立了一个主页，可以在 Web 浏览器中浏览和预览所有内容。

但显然，我们只是输入每个页面的 URL 以预览它们。现实世界的用户无法猜测文件名。因此，在没有导航菜单的情况下，我们的网站无法正常运行。

对于我们来说，考虑为我们的网站添加导航栏是合乎逻辑的。当我们在第六章中更详细地学习 VuePress 的主题开发时，*VuePress 中的主题开发*，我们将触及导航栏定制的每一个方面（包括永久禁用导航栏）。但是，现在，我们的首要任务是展示一个功能齐全且有用的导航栏，以便我们的用户可以轻松浏览网站。

好消息是，VuePress 默认支持导航栏功能。也就是说，除非我们明确向其中添加项目，否则它不会显示。

为了创建导航菜单，我们需要使用以下代码：

```js
module.exports = {
 themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'About', link: '/about' },
      { text: 'Coffee', link: '/coffee' },
      { text: 'GitHub', link: 'https://github.com/packtpublishing/vuepress-quick-start-guide' },
    ]
  }
 }
```

前面的代码为我们的主题配置导出了一个导航栏数组。在这里，我们为以下页面添加了四个链接：

+   主页，位于`/`

+   关于页面，位于`/about`

+   咖啡页面，位于`/coffee`

+   指向我们 GitHub 仓库的外部链接

值得注意的是，所有外部链接都需要完整输入，URL 开头需要带有 HTTP/HTTPS 协议，就像在这个截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/bbdc5f3e-65f2-4286-ad46-92622140d817.png)

我们需要将这段代码添加到我们的`config.js`文件中。这个特定的文件位于我们的 VuePress 站点的`.vuepress`目录中（如果偶然间这个文件不存在，可以随意创建一个名为`config.js`的空文件，然后在其中输入前面的代码）。如果我们将这个文件放在`.vuepress`目录之外，可能会导致事情不按预期工作。

`config.js`文件是什么？

在 VuePress 中，`config.js`文件包含了所有与配置相关的代码，正如其名称所示。这意味着任何调整 VuePress 配置的函数或代码都应该添加到这个文件中。如果没有这个文件，VuePress 将退回到默认配置值。

一旦保存了 config.js 的条目，我们可以刷新输出，导航栏将被添加，就像下面截图顶部所示的那样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/e6eb3268-ebed-4f05-a1d8-377a58814bfd.png)

您可能会注意到搜索栏也已经添加了。但是等等，我们实际上并没有在任何地方添加搜索栏，是吗？

是的，没错——VuePress 自带搜索栏功能，无需进行调整。它就位于导航菜单旁边。然而，我们可以通过外部搜索索引服务扩展或替换默认搜索方法。

搜索栏在我们输入时就会显示结果；无需刷新页面。这就是 JavaScript 的美妙之处；其他几种网页开发语言只有在强制进行完整页面重新加载后才会显示结果。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/677e12c9-5d3c-4a43-b9d0-fd7b034b5d26.png)

与 WordPress 和其他软件不同，VuePress 原生搜索不会在内容主体内进行搜索。相反，它只会搜索输入的标题。这就是为什么在前面的截图中，我们只看到了`Coffee is awesome`页面作为结果，而`coffee`这个词也出现在首页和*关于*页面中。

因此，为了获得更强大的搜索体验，通常建议使用外部服务。我们将在本书的第六章中学习如何集成这一点，*VuePress 主题开发*。

# 最终构建

现在我们已经成功构建了我们的完整站点。我们已经添加了内容，还创建了单独的页面，甚至创建了一个导航菜单。

到目前为止，我们使用`vuepress dev`命令来运行开发引擎并预览站点。一旦确定我们已经构建了站点，我们可以安全（字面上）地*构建*它。

为此，我们需要输入以下命令：

```js
vuepress build
```

此命令将提取我们站点的元数据并编译信息。然后，它将根据 Markdown 内容呈现静态 HTML 页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/8602d2ef-e97a-4255-972b-a14502d14517.png)

生成的内容默认放置在`.vuepress`目录中的 dist 目录中。因此，我们的 VuePress 站点的一般目录结构如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/2894978d-8b61-404a-bef2-4a937ae403b1.png)

值得指出的是，VuePress 根据我们创建的 Markdown 文件生成 HTML 文件。它进一步将所有媒体元素、JS 文件和 CSS 文件放置在`.vuepress/dist`路径下的 assets 子目录中。`/img`目录包含图像，而`/js`子目录包含 JS 文件。

除此之外，VuePress 还创建了一个`404`文件，以便在出现*页面未找到*错误时显示。我们可以根据需要自定义此文件，或者保持原样。

有趣的事实：这个示例站点的最终构建，全部压缩在一起，大约是 68 KB。而在动态数据库驱动的 CMS 中，比如 WordPress 或 Drupal，三个页面的类似站点很容易就会超过 50 MB。

就是这样！我们已经成功构建了一个 VuePress 站点！很简单，不是吗？

# 摘要

在本章中，我们学习了如何使用 VuePress 构建静态站点。我们学习了自定义主页布局，添加呼吁行动按钮以及其他内容，以及其他页面。

不仅如此，我们甚至为我们的站点添加了导航菜单。此外，我们还了解了`config.js`文件的作用。在接下来的章节中，我们将学习更多与定制相关的调整。这些调整中的大部分将放置在`config.js`文件中。

最后，我们学习了如何使用`vuepress build`命令*构建*VuePress 站点。到目前为止，我们已经使用我们自己的内容生成了一个静态站点。

您可以在该书的 GitHub 存储库中找到此站点的原始代码，包括所有 Markdown 文件，以压缩文件的形式。您还可以下载导出的`build`文件，包括静态内容，作为另一个压缩文件。GitHub 存储库位于[`github.com/packtpublishing/vuepress-quick-start-guide`](https://github.com/packtpublishing/vuepress-quick-start-guide)。

这个特定的网站现在可以轻松部署到我们选择的任何云托管服务上。然而，在本书的最后一章中，我们将转向部署，学习如何将我们的网站部署到各种托管服务，如 Heroku、Netlify 和 Google Firebase！

目前，我们将深入研究 Markdown，以便更好地掌握内容格式和演示。然后，我们将学习一些关于主题开发的知识，以便我们可以定制我们的网站，使其成为我们想要的样子。

在下一章中，我们将把注意力转向 Markdown 中的内容编辑，以及 VuePress 如何与 Markdown 配合工作。


# 第五章：在 VuePress 中使用 Markdown

在[第四章]中，我们学习了如何使用 VuePress 创建站点或博客。如果您迄今为止一直在跟进本书，您应该在本地服务器或计算机上安装了 VuePress，并且所有变量都已就位。此外，您还应该了解可以调整的各种配置值，以充分利用 VuePress。

除此之外，您还知道如何处理页面，如何设置站点结构和导航，应用默认样式等等。

换句话说，您知道如何启动和运行 VuePress 网站，以及如何填充内容。

但说到内容，如何在 VuePress 中管理和添加内容？在这种情况下，完成这些工作的最简单和首选方法是使用 Markdown。

Markdown 是一种简单且轻量级的标记语言，具有自己的格式和语法。由于其简单性和易用性，自诞生以来，Markdown 已经变得非常流行。

在本章中，我们将学习不仅 Markdown 是什么，还要学习如何在 VuePress 中使用它。我们将学习 Markdown 语法，以及 VuePress 的 Markdown 扩展和 Markdown 的各种配置变量。

通过本章的学习，您应该能够在 VuePress 中输入内容，也可以在任何其他内容管理系统中使用 Markdown。

在本章中，您将学习以下主题：

+   什么是 Markdown？

+   Markdown 如何使用？

+   VuePress 中的 Markdown 配置

+   VuePress 的 Markdown 扩展

+   在 VuePress 中格式化 Markdown 内容

# 学习在 VuePress 中使用 Markdown

强烈建议您获得一些 Markdown 格式化的基本技能，因为它很快将成为技术文档世界的事实标准，例如在 VuePress 项目的 README 文件中，甚至是 Vue.js 中。

# 什么是 Markdown？

如果您在 Web 开发领域活跃，您可能已经接触过 Markdown，并且很可能在项目中使用它。由于其流行，Markdown 不需要大量介绍。

话虽如此，值得一提的是，可能值得一提 Markdown 及其优点，以便即使是对这个主题新手的读者也可能会发现它有一些价值。

简而言之，Markdown 是一种注重易用性和可读性的内容格式化解决方案。它是由 John Gruber 于 2004 年与 Aaron Swartz 合作创建的。这里的目标是以更具表现力的格式提供纯文本内容，并在必要时可选择将其转换为有效的 HTML。

由于其高度简化和非常具有表现力的特性，Markdown 在技术上有能力的人群中获得了良好的追随者。

Markdown 带有 BSD 风格的许可证，目前可用于各种内容管理系统的专门插件形式。甚至 WordPress 也有几个 Markdown 插件可用。

此外，许多网站和项目都实现了它们自己定制的 Markdown 变体。这些用户包括 SourceForge、GitHub、reddit、Stack Exchange 等等。

# 一个例子

注意我们在前面的部分谈到了可读性吗？嗯，Markdown 非常注重可读性，即使在原始格式中也是如此。

考虑下面这段简单的 HTML 代码：

```js
<h1>VuePress Quick Start Guide</h1>
<h2>By: Sufyan bin Uzayr</h2>
<p>VuePress is a static site generator.</p>
<p>It is powered by Vue.js which is an amazing JS framework.</p>
<hr />
<p>Major features:</p>
<ul>
    <li>Easy to use</li>
    <li>Simple and powerful</li>
    <li>Supports Markdown</li>
</ul>
<p>Features again:</p>
<ol>
    <li>Easy to use</li>
    <li>Simple and powerful</li>
    <li>Supports Markdown</li>
</ol>
<p><a href="https://vuepress.vuejs.org/">VuePress Homepage</a></p>
<blockquote>
<p>This is a blockquote.</p>
</blockquote>
```

现在，将前面的示例与以下 Markdown 代码进行比较：

```js
# VuePress Quick Start Guide
## By: Sufyan bin Uzayr
VuePress is a static site generator.
It is powered by Vue.js which is an amazing JS framework.
* * *
Major features:
* Easy to use
* Simple and powerful
* Supports Markdown
Features again:
1\. Easy to use
2\. Simple and powerful
3\. Supports Markdown
[VuePress Homepage](https://vuepress.vuejs.org/)
> This is a blockquote.
```

前面两个代码示例将产生相同的输出。结果如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/3d103c42-83a4-47dd-9d16-1fd4f17f99d5.png)

但是，正如你所看到的，Markdown 代码比 HTML 更清晰易读。它没有被繁琐的标签和其他元素所淹没。简单的格式化辅助意味着即使在原始格式中（即没有输出的情况下），你也可以阅读文本。这就是 Markdown 的简单和美丽之处！它非常易读，易于理解，也很容易输入。

您可以在官方网站上阅读有关 Markdown 的功能和设置的更多信息，网址为[`daringfireball.net/projects/markdown`](https://daringfireball.net/projects/markdown)。

自然地，许多静态站点内容管理系统，如 VuePress，出于这些原因倾向于使用 Markdown。因此，尝试掌握 Markdown 中的一些基本格式化辅助是很有必要的，以便充分利用 VuePress。

# markdown-it 解析器

现在我们已经了解了 Markdown 是什么，以及它可以为我们提供什么优势，是时候开始学习 VuePress 中 Markdown 的用法和变化了。然而，在进入 VuePress 环境之前，我们必须先了解一个名为 markdown-it 的 Markdown 解析器。

Markdown 解析器是做什么的？

它最简单的任务是分析并将 Markdown 语句分解为易于处理的句法组件。

markdown-it 的工作相当出色，而且非常容易使用。它带有自己一套自定义扩展，多个插件，并且不会减慢你的环境。VuePress 中的大多数 Markdown 扩展和配置变量都与 markdown-it 很好地配合，有些甚至只能通过 markdown-it 来使用。

要使用 markdown-it，你首先需要安装它。可以通过 npm 来完成，就像 VuePress 一样（你已经在第一章 *介绍静态站点生成器和 VuePress*中学习了 npm 安装）：

```js
npm install markdown-it --save
```

接下来，你可以加载它的插件并根据需要使用它。要了解更多关于 markdown-it 解析器的信息，你可以查看其 GitHub 存储库[`github.com/markdown-it/markdown-it`](https://github.com/markdown-it/markdown-it)。

另外，还有一个可用的演示可以在[`markdown-it.github.io/`](https://markdown-it.github.io/)中查看，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/b4eeb097-6bb9-4457-b347-e5bb32d366ae.png)

VuePress 使用 markdown-it 作为默认的 Markdown 解析器或渲染器。当然，你不仅可以使用 markdown-it，还可以在 VuePress 中使用它的自定义扩展和插件。

为了在 VuePress 中进一步自定义 markdown-it，修改`.vuepress/config.js`文件以添加 Markdown 实例并在其中修改可能是个好主意。我们已经在之前的章节中介绍了`.vuepress/config.js`文件的内容和细节。请注意，你可以参考 markdown-it 文档以获取有关各种插件的更多详细信息，以及如何引用它们以供我们使用。

当添加到`config.js`文件时，你的示例代码应该如下所示：

```js
module.exports = {
    markdown: {
    // the markdown-it-anchor
        anchor: { permalink: false },
    // the markdown-it-toc extension
        toc: { includeLevel: [1, 2] },
    config: md => {
    // this is where you add more markdown-it extensions
        md.use(require('markdown-it-name-of-extension'))
        }
    }
}
```

在代码的最后部分，请确保添加你希望使用的 markdown-it 扩展的相关名称。请注意，我们将在本章中介绍 markdown-it-anchor 和 markdown-it-toc 扩展，以帮助你更好地理解如何引用它们以及预期的输出是什么。

现在你已经了解了 Markdown 是什么，markdown-it 解析器是什么，以及 VuePress 如何将其作为 Markdown 的默认渲染器，现在可以安全地转向 VuePress 中的 Markdown 配置变量和值。之后，我们将关注 VuePress 对 Markdown 的使用和处理。

# Markdown 配置参考

在这一点上，我们首先将关注 VuePress 中与 Markdown 相关的各种配置实体。请注意，这些是 VuePress 特定的，可能不适用于其他静态站点生成器。

我们已经在第三章中涵盖了基本的配置值，*VuePress 开发-初步步骤*。除此之外，我们将转向特定主题配置值及其在处理自定义主题的后续章节中的用途。

目前，我们只会关注 VuePress 配置中与 Markdown 相关的值和变量。随着在项目中使用 VuePress 的进展，你可以利用这些配置参考实体更好地管理 Markdown 中的内容，并确保它被格式化和呈现成你想要的样子。

# markdown.slugify

这是一个非常重要的功能，你应该尽一切可能了解它。在 VuePress 中，markdown.slugify 可以用来将标题文本转换为 slug。

因此，你可以在 Markdown 中输入标题文本，然后使用这个函数来生成一个 slug（即 URL 或永久链接）。当然，这意味着它主要用于锚链接、目录和其他相关材料。

由于`markdown.slugify`是函数类型，因此在数据类型方面没有值定义。相反，它有一个函数定义。让我们更仔细地看一下它的一般语法，以进一步理解它的功能：

```js
// string.js slugify drops non ascii chars so we have to 
// use a custom implementation here
const removeDiacritics = require('diacritics').remove
    // eslint-disable-next-line no-control-regex
    const rControl = /[\u0000-\u001f]/g
    const rSpecial = /[\s~`!@#$%^&*()\-_+=[\]{}|\\;:"'<>,.?/]+/g
module.exports = function slugify (str) {
    return removeDiacritics(str)
    // Remove control characters
    .replace(rControl, ' ')
    // Replace special characters
    .replace(rSpecial, '-')
    // Remove continous separators
    .replace(/\-{2,}/g, '-')
    // Remove prefixing and trailing separators
    .replace(/^\-+|\-+$/g, '')
    // ensure it doesn't start with a number (#121)
    .replace(/^(\d)/, '_$1')
    // lowercase
    .toLowerCase()
```

你也可以在[`github.com/vuejs/vuepress/blob/master/lib/markdown/slugify.js`](https://github.com/vuejs/vuepress/blob/master/lib/markdown/slugify.js)浏览相同的源代码。

现在，你注意到这个函数在做什么了吗？它获取标题文本，移除其中的空格字符，然后用连字符（`-`）替换，接着移除任何前缀和尾随字符，最后将标题文本转换为小写。

例如，如果我们的标题文本是`Header SamPLE`，它会将其转换为`header-sample`作为 slug。当然，因为 slug 是 URL 的一部分，它不能包含特定字符和空格。`markdown.slugify`确保了这一点。

# markdown.externalLinks

`markdown.externalLinks`用于向内容添加外部链接（从名称上就很明显）。默认情况下，它将其值配对在`<a>`标签中，并在新窗口中打开外部链接。

`markdown.externalLinks`是对象类型，其默认语法如下：

```js
{ target: '_blank', rel: 'noopener noreferrer' }
```

如果您希望不在新窗口中打开外部链接（出于 SEO 原因或类似原因），您可以删除`target:'_blank'`部分，就像您在任何其他 HTML 文档中所做的那样。

# markdown.config

markdown.config 是函数类型，其默认值因此为未定义。

它用于修改默认配置，并向我们在上一节中讨论的 markdown-it Markdown 解析器添加附加功能或外部插件。

以下是一个演示其用法的示例：

```js
module.exports = {
    markdown: {
        config: md => {
            md.set({ breaks: true })
            md.use(require('markdown-it-something'))
        }
    }
}
```

在上面的示例中，markdown.config 添加了对名为 markdown-it-something 的外部实体的要求，然后可以用于实现相同外部实体的附加功能。

# markdown.toc

`markdown.toc`提供了向我们的网站添加目录的选项。如果您计划创建一个需要这样的目录的网站，比如知识库网站或在线小说或书籍的章节布局，它尤其有用。

这是对象类型，其默认语法如下：

```js
{ includeLevel: [2, 3] }
```

值得注意的是，`markdown.toc`实际上与 markdown-it-table-of-contents 插件一起使用。这个特定的插件为 markdown-it 插件提供了一个目录布局。您可以在[`github.com/Oktavilla/markdown-it-table-of-contents`](https://github.com/Oktavilla/markdown-it-table-of-contents)上了解更多信息。

# markdown.anchor

`markdown.anchor`是对象类型，其一般语法如下：

```js
{ permalink: true, permalinkBefore: true, permalinkSymbol: '#' }
```

它提供了向您的内容添加标题锚的选项。

请注意，这不应与`markdown.slugify`添加的标题标识符或 ID 混淆，如前所讨论的那样。相反，markdown.anchor 允许您在内容中添加锚链接。

它与 markdown-it-anchor 插件协同工作，该插件为 markdown-it 添加了标题锚功能。您可以在其 GitHub 页面上了解有关此插件的更多信息[`github.com/valeriangalliat/markdown-it-anchor`](https://github.com/valeriangalliat/markdown-it-anchor)。

# markdown.lineNumbers

每当您向 VuePress 网站添加诸如代码块之类的内容时，您可以选择是否在代码块旁边显示行号。为此，您可以使用`markdown.lineNumbers`配置实体。

`markdown.lineNumbers`是`boolean`类型，它接受简单的`true`或`false`值来显示（或不显示）行号。

例如，当`markdown.lineNumbers`配置值设置为 true 时，代码输入将具有行号。

以下是如何做到的：

```js
module.exports = {
    markdown: {
    lineNumbers: true
    }
}
```

通过设置配置值，任何代码输入都将附加行号。例如，如果我们在页面中显示相同的代码作为预格式化内容，它将如何显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/6a450d13-1187-430e-861a-d8de7db545d6.png)

现在我们已经涵盖了几乎所有相关的 Markdown 配置术语，是时候把注意力转向 VuePress 中使用的 Markdown 扩展了。

# VuePress 中的 Markdown 扩展

当我们谈论 VuePress 中的 Markdown 扩展时，我们指的是那些可以立即在 VuePress 中使用的 Markdown 扩展。您已经看到了 Markdown 格式如何在 VuePress 的日常使用中使用，在第四章中，*在 VuePress 中创建站点*。

# 标题锚点

VuePress 中的所有标题都会自动应用锚链接，以便更轻松地浏览站点内容。这主要是为了方便浏览站点内容，因为 VuePress 主要是一个文档管理工具，而不是一个商业站点解决方案。在这种情况下，通过标题导航是管理内容的最简单方式。

如果您希望配置或修改锚点设置，可以使用`markdown.anchor`配置选项，如本章的前一节所讨论的那样。

# 链接

在 VuePress 中，链接可以是内部的或外部的。

顾名思义，内部链接指向本地内容，而外部链接指向其他网站和项目的内容。

让我们在下一节中分别讨论每一个。

# 外部链接

所有指向第三方网站的外部和出站链接都会自动附加`target="_blank" rel="noopener noreferrer"`标签。这意味着所有外部链接都会在新窗口（或浏览器标签）中打开。您可以使用`markdown.externalLinks`配置选项来修改此设置，如本章的前一节所讨论的那样。

# 内部链接

在这一点上，值得记住的是 VuePress 生成**单页面应用程序**（**SPA**）以便更轻松、更快速地浏览站点内容。现在，为了实现 SPA 导航，所有本地或入站链接都需要转换为路由链接。

VuePress 通过将所有以 Markdown 或 HTML 格式结尾的内部链接转换为`<router-link>`来实现这一点。

我们在上一章中学到，VuePress 中的每个子目录，除非不是公开访问的，必须有一个`README.md`文件，然后 VuePress 会将其转换为`index.html`文件，然后在浏览器中提供服务。

当在内容中添加内部链接时，您需要在文件路径中指定正确的文件扩展名，否则将会得到 404 错误。因此，在 VuePress 中添加内部或本地链接时，必须牢记以下考虑事项：

+   必须附加`.html`或`.md`——正确的文件扩展名。

+   在编写文件或资源的相对路径时，必须添加尾随斜杠`/`。如果没有尾随斜杠，VuePress 将无法遵循相对路径，并将给出 404 错误。因此，`/mypath`是不正确的，而`/mypath/`是正确的。

+   所有路径规范都是区分大小写的。

现在，为了更好地理解这些要求，让我们举个例子。考虑以下目录结构：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/b23b3e6e-45c2-4554-8132-c81992ac1209.png)

以下表格显示了此结构的链接语法应如何工作：

| **相对路径** | **Markdown** | **解释** |
| --- | --- | --- |
| `/` | `[首页]` | 位于`根`文件夹中的`README`文件 |
| `/testx/` | `[testx]` | 位于`testx`子目录中的`README`文件。 |
| `/testx/filea.md` | `[testx - filea]` | `testx`子目录中的`filea.md`文件；注意`.md`扩展名。 |
| `/testx/fileb.html` | `[testx - fileb]` |

&#124; `fileb.md`文件位于`testx`子目录中；注意`.html`扩展名，它仍然指向`.md`文件。 &#124;

&#124;  &#124;

|

在这个例子中，我们可以清楚地看到，当渲染页面时，VuePress 会自动将`.md`扩展名转换为解析的 HTML。

# 表情符号

考虑到表情符号已经变得相当流行，应该有一种方法来正确格式化并在您的内容中包含它们，如果您愿意的话。WordPress 甚至已经集成了自己的自定义 WordPress 表情符号，您可以在您的内容中使用，或者直接删除并依赖浏览器表情符号。

然而，与 WordPress 不同，VuePress 更注重轻量和迅速。因此，在 VuePress 的核心中配备自定义表情符号集是没有意义的。

但是，您可以轻松地使用 markdown-it-emoji 插件，该插件预装了超过 1,000 个表情符号供您选择。这是一个示例：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/9b5d102f-74c0-43e1-aa6b-b0b71c3ff4ce.png)

您可以选择使用提供所有 GitHub 支持表情符号的完整版本，或者只提供 Unicode 表情符号的轻量级版本。此特定插件还支持基于字符的表情符号，例如`:-)`等。它与 markdown-it 解析器一起工作，并可以通过 npm 安装，如下所示：

```js
npm install markdown-it-emoji --save
```

当然，我们这里的主要重点是如何在 VuePress 中使用 markdown-it-emoji。要了解有关插件本身的更多信息，您可以在其 GitHub 页面上找到：[`github.com/markdown-it/markdown-it-emoji`](https://github.com/markdown-it/markdown-it-emoji)。

在 VuePress 中，您只需在两个冒号内键入所需的表情符号名称即可。例如，要在每个连续行上添加一个头骨、一个外星人、一个尖叫的脸和一个太阳镜表情符号，请尝试以下代码：

```js
:skull:
:alien:
:scream:
:sunglasses:
```

在浏览器中的最终输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/8ab31bad-2450-42cc-9c9e-7781070cd70c.png)

当然，表情符号的最终实际外观也可能会因您的操作系统和浏览器版本而有所不同。有时，某些网络浏览器倾向于用自己的变体替换默认的网络表情符号。

# 添加表格

VuePress 在 Markdown 中原生支持两种主要类型的表格。

第一个显然是目录。这不是一个纯粹的表格，因为几乎没有行或列，但无论如何都被称为表格，所以让我们保持这样。语法很简单，如下所示：

```js
[[toc]]
```

这将根据内容中的标题自动生成目录。您可以进一步通过使用`markdown.toc`配置选项进行自定义，如本章前面所述。

VuePress 中的第二种表格类型类似于 GitHub 上的表格布局。实际上，它被称为 GitHub 风格表格。

假设我们正在创建一个简单的表格，概述每个国家的首都、旅游景点、流行运动和货币。您可以按照以下 Markdown 格式和详细信息输入：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/6af5c01f-1e35-4d4c-8b1a-cbe9973bfe07.png)

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/f51a2fbc-33c6-41f4-994d-0fba4d388939.png)

这就是 VuePress 中的表格。表格会自动格式化，并且交替行也会高亮显示，以使表格看起来更加整洁。

# 前置内容

通过 YAML 数据序列化的前置内容概念首先由 Jekyll 引入，Jekyll 是另一个非常流行和多功能的静态站点生成器，我们在第一章中简要讨论过，*介绍静态站点生成器和 VuePress*。

简而言之，前置内容被放置在文件的开头和三虚线之间。在该内容中，您可以指定自定义和预定义变量，以提供有关您的项目的更多信息。这些变量将随后可供您在所有页面和自定义组件中使用。

讨论与前置内容相关的所有变量远远超出了这个快速入门指南的范围。但是，您可以在 Jekyll 项目的网站上查看有关此主题的更多信息：[`jekyllrb.com/docs/frontmatter/`](https://jekyllrb.com/docs/frontmatter/)。

现在，让我们回到 VuePress。

在 VuePress 中，YAML 前置内容得到了原生支持，无需使用任何自定义导入或额外扩展。因此，您在三虚线之间指定的任何内容将在整个页面中都可用。

让我们通过一个例子来理解它。考虑以下前置内容代码：

```js
---
title: My Fancy VuePress Site
lang: en-US
meta:
    - name: site description
    content: hey, this is vuepress!
    - name: keywords
    content: vuepress blogging vuejs
---
```

现在，在上面的例子中，标题和语言变量已经为整个页面指定了。然后，您可以添加自定义的元标签，例如站点描述和与 SEO 相关的关键字，这些将适用于整个页面。

如果 YAML 不是您首选的脚本解决方案，您也可以选择其他选项。TOML 也得到了支持——要使用它，您只需指定您偏好 TOML，如下所示：

```js
---toml
title: My Fancy VuePress Site
lang: en-US
meta:
    - name: site description
    content: hey, this is vuepress!
    - name: keywords
content: vuepress blogging vuejs
---
```

然而，很多 JavaScript 程序员更喜欢 JSON。在这种情况下，您需要遵循标准的 JSON 格式来处理前置内容；也就是说，使用花括号和引号，就像下面的例子所示：

```js
---
{
“title”: “My Fancy VuePress Site”,
“lang”: “en-US”,
“meta”:
    - “name”: “site description”,
    “content”: “hey, this is vuepress!”,
    - “name”: “keywords”,
    “content”: “vuepress” “blogging” “vuejs”
}
---
```

前置内容规范在静态站点生成器的世界中非常常见，任何有过使用这类生成器经验的人几乎肯定已经了解了前置内容的作用。

# 自定义格式选项

在 Markdown 中，VuePress 原生支持一些其他不太常用的格式选项。这些将在下一节中讨论。

# 代码中的突出显示

您可以选择在代码中突出显示行，以使输出更具可读性。以下是一些示例代码：

```js
export default {
    data () {
        return {
        msg: 'Highlight me!'
        }
    }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/fadc0b9f-3bf7-446c-b3e6-f9f613984c08.png)

# 自定义容器

有时，您可能希望强调内容中的某些部分，比如警告、通知和提示。您可以在 VuePress 中轻松突出它们，以便用户的注意力直接被吸引到手头的内容上。

这意味着您首先需要将给定的内容指定为提示、警告或类似内容。之后，VuePress 将生成所需的通知或提示，并带有给定的彩色容器。

最终的实际外观可能会有所不同，取决于您自己的配置，但这个呈现方式与 GitHub 风格的 Markdown 相当类似，如果您在 GitHub 中有一些关于格式化`README`和其他 Markdown 文件的经验，您可能已经遇到过这样的自定义内容容器。

以下是您可以这样做的方法：

```js
::: tip
Hello World!
:::

::: warning
Hello World! You have been warned!
:::

::: danger
Hello World! This is a really serious warning.
:::
```

输出如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/d8f145d2-cfc5-4090-bd2a-b0a8e984f649.png)

您也可以选择调整每个容器的标题，就像这里所示：

```js
::: tip HOWDY
Hello World!
:::

::: warning STOP
Hello World! You have been warned!
:::

::: danger NOOO
Hello World! This is a really serious warning.
:::
```

再次，输出将显示如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/7baca20a-08f2-4360-ab20-26b87a22f518.png)

# 导入代码片段

如果您有包含代码的现有文件，您可以将代码片段从中导入到您的 VuePress 项目中。这样做的语法如下：

```js
<<< @/filepath
```

但是，您需要记住，您不能在 webpack 中使用路径别名，因为所有代码片段的导入通常必须在 webpack 编译之前执行。

请记住，代码片段的导入是一个实验性功能，仍处于测试阶段。它有时可能不按预期工作。

代码片段导入函数支持行高亮，正如本章前面讨论的那样。在这种情况下，语法将变成以下形式：

```js
<<< @/filepath{highlightLines}
```

`@`的默认值将是`process.cwd()`。

# 摘要

这就是本章的结束。

在本章中，我们了解了 Markdown 是什么，以及它为什么如此受欢迎，比如它的简单性和可读性，以及易用性。除此之外，我们还介绍了 markdown-it 解析器，这是在静态站点生成工具中渲染 Markdown 的非常常见和流行的实体，比如 VuePress。

我们还介绍了用于 Markdown 的 VuePress 配置值。此外，我们了解了在 VuePress 中可用的几种 Markdown 扩展。当然，这并不是一个详尽的列表。考虑到 VuePress 正在积极开发中，您可以预期最终会添加新的值和扩展。

话虽如此，在完成本章后，您现在应该对 VuePress 中的 Markdown 使用有足够的理解，并且应该能够添加`.md`文件，按照您希望呈现内容的方式对其进行格式化，并保存它们，以便 VuePress 可以将它们呈现为 HTML 并组合成单页应用程序。

说到单页应用程序（SPAs），我们现在需要涵盖网页开发中一个非常重要的方面——模板和主题！

在上一章中，我们了解了默认的 VuePress 主题以及它对我们的作用，它提供的布局以及我们如何使用它来呈现我们的内容。但是，自定义主题呢？在今天的世界中，通常更喜欢，有时甚至需要网站拥有自己独特的外观和感觉。自定义主题可以帮助您实现这一目标，并使您的网站脱颖而出！

因此，在下一章中，我们将把注意力转向 VuePress 中的自定义主题，并涵盖相关主题。


# 第六章：VuePress 中的主题开发

在上一章中，我们学习了如何使用 Markdown 格式化我们的内容。在那之前，我们已经建立了一个基本的 VuePress 网站。此外，我们还了解了 VuePress 提供的大部分配置设置。

然而，网站开发的一个关键方面仍然缺失。

是的，我们正在谈论主题开发。正如您可能知道的，一个好的主题或模板是任何网站或博客的无形部分。

VuePress 自带默认主题。在第四章 *在 VuePress 中创建网站*中，当您设置您的第一个 VuePress 网站时，您已经了解了默认主题以及如何使用它来展示您的内容。

然而，在本章中，我们将重新审视与 VuePress 主题开发和配置相关的一切。这意味着我们不仅将涵盖配置实体和变量，还将重新审视默认的 VuePress 主题以及它的工作原理，它的代码的具体部分可以用于什么等等。

但除此之外，我们还将把注意力转向 VuePress 主题的定制。我们将在本章的后半部分详细讨论自定义主题配置。

在这一章中，您将学习以下内容：

+   VuePress 的主题开发

+   主题开发的配置实体和值

+   在 VuePress 中使用默认主题配置进行工作

+   在 VuePress 中的自定义主题开发

+   在 VuePress 中使用 CSS 自定义

+   与 Git 存储库同步

# VuePress 中的主题开发

所以现在，不再浪费时间，让我们开始吧！

# 在 VuePress 中使用主题

VuePress 作为一个静态网站生成器，专注于简单和敏捷。这意味着，与 WordPress 不同，您不会找到大量的主题和插件可供使用。虽然这可能会对一些人构成障碍，因为在某些情况下，易于安装的主题是真正节省时间的，但这种功能性和开发者导向的方法对许多其他人非常有用。

它可以帮助您按照您想要的方式编写主题。此外，您还可以仅使用默认主题，并在几分钟内快速搭建一个现场网站。在第四章 *在 VuePress 中创建网站*中，我们看到在 VuePress 中设置默认主页就像编辑一个简单的 Markdown 文件一样容易！

# 是什么以及如何？

当前章节的布局非常简单，因为我们只涉及 VuePress 的一个特定概念——主题。话虽如此，值得记住的是，主题开发本身是一个相当广泛的主题。随着 VuePress 的规模和受欢迎程度的增长，以及随着时间的推移出现新版本，您可能需要复习和修订您的主题开发技能，以确保您遵守 VuePress 和 Vue.js 提出的最新编码标准。

在这一点上，我们将讨论或者说解剖 VuePress 的默认主题结构。这意味着我们将涵盖主页、导航、侧边栏和所有其他相关实体。你可能已经在第四章中学习了基础知识，但现在，我们更感兴趣的是理解这里的代码是如何工作的。你已经在第四章中看到了默认主题的实际应用。

在此之后，我们将把注意力转向定制。在 VuePress 中定制主题需要对默认结构进行一些更改，我们很快就会看到。

但在继续之前，让我们花一点时间来了解一些 VuePress 中基本主题配置值。与我们在之前章节中介绍的 Markdown 配置实体或基本配置实体不同，主题配置并不那么复杂。

# 主题的配置实体

在这一点上，让我们首先了解一些与 VuePress 主题开发相关的基本配置实体。我们已经在之前的章节中学习了其他配置实体。

# 主题

主题配置值用于指定自定义主题。这意味着如果您在项目中使用自定义主题，您需要调用主题配置来指定它。

它是字符串类型，默认情况下未定义，因为 VuePress 使用自己的默认主题，除非另有规定。

# themeConfig

顾名思义，`themeConfig`为当前主题提供配置选项。

它是对象类型，默认情况下写作`{}`。

请注意，`themeConfig`的内容和选项将根据您的主题结构方式而有所不同。随着您在主题定制中的进展，您将经常使用`themeConfig`实体。

这里有一个方便的例子。还记得我们在第三章中学到的 Service Worker，*VuePress 开发-初步步骤*吗？那是一个站点级别的 Service Worker。但是主题级别的呢？

当你使用`themeConfig.serviceWorker`时，你可以将其定制为仅适用于主题级别的内容。通过`themeConfig`，你可以定制 VuePress 开发的多个元素，以满足你的主题需求。

**这有什么用？**

想象一下。你的访问者在多个标签中打开了你的 VuePress 网站，并浏览你的内容。现在，如果你在那个时候更新了你的内容呢？在正常情况下，你的访问者直到关闭并重新打开所有标签，也就是说，硬性的浏览器端刷新或重新加载打开的页面，才能看到新的内容。

当你配置 Service Worker 与`themeConfig`一起工作时，你也可以用它做一些有趣的事情。其中之一就是弹出窗口的用户界面。

是的，每个人都知道弹出窗口是什么，以及它们有多烦人。但我们不是在谈论类似广告的垃圾弹出窗口。相反，`themeConfig.serviceWorker`元素将添加一个`updatePopup`选项，通知用户有新内容可用。

换句话说，当你更新你的网站并且用户打开了标签时，一个弹出窗口将出现，通知用户有新内容，并提供一个刷新按钮，这样新内容就可以立即显示，而不需要关闭客户端。

这个选项在你经常更新的网站上非常有用，比如技术项目的文档等等。

`themeConfig.serviceWorker.updatePopup`选项的基本语法如下（布尔值）：

```js
module.exports = {
  themeConfig: {
    serviceWorker: {
      updatePopup: true //now popup is set to true and will show up
      // default display for frontend is:  
      // updatePopup: { 
      // message: "New content is available.", 
      // buttonText: "Refresh" 
      // }
    }
  }
}
```

请注意，截至目前，VuePress 中的弹出功能仍处于测试阶段。

正如你所看到的，`themeConfig`可以用于各种目的，为你的 VuePress 安装增加更多的功能。

目前就这些了。这是我们需要记住的唯一两个配置值。因此，我们可以把注意力转向默认的 VuePress 主题，以便更好地理解它的功能。

# VuePress 中的默认主题配置

这个特定的部分完全只涉及默认的 VuePress 主题。如果你使用自定义主题，大部分或所有这些设置可能不适用。

在这个阶段，强烈建议您转到您在第四章中创建的虚拟站点，*在 VuePress 中创建站点*。我们涵盖了首页、导航、侧边栏、搜索功能等概念。我们现在将更好地理解这些内容，并了解默认 VuePress 主题提供的其他功能（例如与 GitHub 仓库的集成）。

# 首页

我们知道默认的 VuePress 主题自带自己的首页布局。为了使用这个布局，我们只需要在根目录的`README.md`文件中将`home:`的值设置为`true`。然后该文件将被 VuePress 解析为`index.html`，并显示默认的首页。

我们可以通过`README.md`文件直接向首页添加元数据。在上一章中，我们已经学会了如何以 YAML 格式编写前置内容。因此，现在是分析首页代码的时候了。从第四章中复制相同的首页前置内容，*在 VuePress 中创建站点*，我们得到以下内容：

```js
---
meta:
  - name: description
    content: Just a simple VuePress site about coffee.
  - name: keywords
    content: vuepress coffee
lang: en-US
home: true
navbar: true
actionText: Learn More →
actionLink: /about
features:
- title: Caffeinated
  details: It is obvious that coffee is surely the greatest beverage known to humans.
- title: Keeps You Awake
  details: Grab some strong coffee and stay awake forever... probably not a healthy idea though. 
- title: Good for Coding
  details: Nobody accepts this but programming is definitely impossible without coffee.
footer: MIT Licensed | A sample VuePress site built by Sufyan bin Uzayr
---
```

在上面的代码中，我们首先指定了关于我们站点的元数据。然后，我们添加了调用按钮的链接和锚文本详细信息。最后，我们输入要显示的附加信息。

正如我们在第四章中所看到的，*在 VuePress 中创建站点*，最终结果如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/7f6e8c14-1a4d-4972-a8c9-8d825689150e.png)

在前置内容之后放置的任何内容也会被解析为简化的 Markdown，并显示在首页的前置内容下方。

但是，如果您不想使用默认的首页呢？当然，您可以创建一个自定义主题，但为什么要为添加一个新页面而构建一个新主题呢？

在这种情况下，更好的选择是自定义首页布局。我们可以通过自定义布局来实现这一点。

# 页面的自定义布局

我们知道每个 Markdown `.md`文件都是由 VuePress 在 Web 浏览器中呈现为 HTML。一般来说，VuePress 会在 HTML 中的`<div class="page">`容器中解析 Markdown 文件的内容。

这意味着我们的默认布局——包括主要内容、导航栏和其他链接——都包含在容器内。

因此，这里的任务很简单。如果我们需要添加任何自定义布局或组件，我们只需要确保它包含在我们的默认容器内。

例如，假设我们已经指定了一个名为`MyLayout`的自定义`layout`。现在，在 YAML 前置内容中，我们只需要添加以下行：

```js
layout: MyLayout
```

有了这个，给定页面将呈现新的布局。

通过这种方式，您可以为尽可能多的页面指定自定义布局。

# 导航栏

VuePress 中的导航栏包括一组通用项目，例如导航菜单、搜索栏、指向您的 GitHub 存储库的链接（如果有的话）等等。

# 导航栏链接

还记得我们之前讨论过的`themeConfig`变量吗？您可以使用它向导航栏添加任意数量的链接。

让我们分析以下代码：

```js
// Goes to .vuepress/config.js
 module.exports = {
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'About', link: '/about' },
      { text: 'Coffee', link: '/coffee' },
      { text: 'External', link: 'http://sufyanism.com' },
 ]
 }
 }
```

在上面的例子中，我们创建了一个简单的导航链接菜单，提供了四个链接：

+   主页

+   关于页面

+   关于咖啡的页面

+   外部链接（GitHub）

相当简单，不是吗？您可以根据需要在这里不断添加链接。在浏览器中的效果如下：

！[](assets/ba00b3ac-cc02-4fe4-9c19-2097184e3126.png)

那么下拉菜单呢？您只需要将所述链接提供为数组，而不是独立的链接。例如，考虑以下代码：

```js
module.exports = {
  themeConfig: {
    nav: [
      {
        text: 'Linkz',
        items: [
          { text: 'Home', link: '/' },
          { text: 'About', link: '/about/' }
        ]
      }
    ]
  }
 }
```

有了这个，链接将显示为下拉菜单。

此外，您还可以拥有非常复杂的菜单，包括下拉条目下的子组和嵌套项目。对于 VuePress 网站，这种类型的菜单结构极不可能被使用，可能也不太有用。尽管如此，这里是这种菜单结构的默认语法，您可以根据自己的需求进行修改：

```js
module.exports = {
  themeConfig: {
    nav: [
      {
        text: 'Label',
        items: [
          { text: 'First', items: [/*  */] },
          { text: 'Second', items: [/*  */] }
        ]
      }
    ]
  }
 }
```

# 搜索栏

您可以选择在 VuePress 中使用原生搜索或 Algolia DocSearch。默认搜索栏位置就在导航菜单链接旁边，就像我们在第四章中看到的那样，*在 VuePress 中创建站点*：

！[](assets/82f865c1-dd3b-49ec-84a4-5e0ab99d5521.png)

# 原生搜索框

VuePress 自带其自己的原生搜索框，您无需进行调整。但是，如果您愿意，您可以使用`themeConfig`值完全禁用搜索框，或者限制显示搜索词的建议数量。

以下是如何禁用原生搜索框：

```js
module.exports = {
  themeConfig: {
    search: false,
  }
 }
```

或者，为了限制建议的数量，尝试以下代码：

```js
module.exports = {
  themeConfig: {
    searchMaxSuggestions: 5
  }
 }
```

VuePress 中原生搜索的一个很大的缺点是它只从`H1`、`H2`和`H3`标签构建其索引。这意味着它不会扫描实际的正文内容以搜索词。

当然，这样的搜索功能可能不适合每个人，因为通常正确的关键词在内容中而不是标题中。

为了克服这一点，我们可以将外部搜索机制集成到我们的主题中。

# 使用 Algolia 搜索

如果您对 Algolia DocSearch 不熟悉，可以访问他们的网站并在[`community.algolia.com/docsearch/`](https://community.algolia.com/docsearch/)上了解更多。

基本上，Algolia DocSearch 是文档搜索引擎的增强版本。它会爬取您的内容，对其进行索引，然后返回更好的搜索结果，涵盖并爬取整个内容，而不仅仅是标题。他们网站的截图如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/4fc86854-b6d5-4a6f-9f8b-6c371eb60711.png)

Algolia DocSearch 与各种环境完全兼容，包括 Bootstrap、React，当然还有 Vue.js。此外，它是一种上下文感知的搜索机制，可以随着您的输入而学习。因此，Algolia DocSearch 可以提供一系列功能，这些功能在本机搜索方法中可能缺失，例如：

+   自动完成建议

+   定制分析以查看详细的搜索统计信息

Algolia DocSearch 采用 MIT 许可证，是开源的。因此，为了在您的 VuePress 网站上使用它，您需要在 Algolia 注册一个账户。

Algolia DocSearch 与您的网站集成的详细文档可在[`github.com/algolia/docsearch#docsearch-options`](https://github.com/algolia/docsearch#docsearch-options)上找到。

一旦您在 Algolia 注册了一个账户，您就可以提交您的网站进行索引和爬取。之后，您只需要告知 VuePress 有关 Algolia DocSearch 引擎。为此，您将再次使用非常方便的`themeConfig`选项，如下所示：

```js
module.exports = {
 themeConfig: {
 algolia: {
 apiKey: '<API>',
 indexName: '<INDEX>'
 }
 }
 }
```

请注意，当网站索引完成时，您需要指定自己的 API 密钥和索引名称，这些信息由 Algolia DocSearch 提供。如果缺少 API 密钥或索引名称，或者其中任何一个值不正确，搜索功能将无法正常工作。

# 如何禁用导航栏？

有时，您可能需要禁用导航栏。在这种情况下，您可以通过`themeConfig`选项指定如下：

```js
// Goes to .vuepress/config.js
 module.exports = {
  themeConfig: {
    navbar: false
  }
 }
```

导航栏显示值现在设置为 false，因此它将不会显示在前端。

然而，前面的选项会全局禁用导航栏。要仅针对特定页面禁用它，最好编辑该页面的前置内容，如下所示：

```js
---
 navbar: false
 ---
```

# 上一页和下一页的链接

默认情况下，VuePress 会在站点上每个页面的末尾添加上一页和下一页的导航链接。这些链接是根据侧边栏中的标题自动推断的，并从当前页面计算得出。

然而，你也可以覆盖它们的外观和选择。在当前页面的前置内容中，你只需要指定你的选择。例如，对于自定义页面的选择，你可以添加以下内容：

```js
---
 prev: ./another-page
 next: ./yet-another-page
 ---
```

可选地，你也可以同时禁用两者：

```js
---
 prev: false
 next: false
 ---
```

或者，只需使用以下代码禁用其中一个：

```js
---
 prev: ./some-fancy-page
 next: false
 ---
```

或者：

```js
---
 prev: false
 next: ./my-awesome-page
 ---
```

等等。

这涵盖了关于导航本身的部分。现在，是时候把注意力转向侧边栏了。

# 侧边栏

VuePress 为你的站点提供了一个基于页面结构和其中的标题链接构建的原生侧边栏。

要为你的站点启用侧边栏，你需要使用`themeConfig.sidebar`选项通过链接数组进行配置。请注意，以下代码放入你的`config.js`文件中：

```js
// goes to .vuepress/config.js
 module.exports = {
  themeConfig: {
    sidebar: [
      '/',
      '/page-1',
      ['/page-2', 'optional link text']
    ]
  }
 }
```

在这个示例中，默认情况下链接会指向`README.md`文件。这意味着任何以`/`斜杠结尾的链接都会指向相关的`README.md`文件。

注意可选的链接文本？如果你在这里指定了某些内容，那么它将显示为侧边栏中的链接文本。或者，如果你在页面的前置内容中指定了标题，那么它将显示为侧边栏中的链接文本。最后，如果在任一位置未指定标题，则 VuePress 将自动从相关页面的第一个标题中选择链接文本。

# 修改侧边栏中的标题链接

你可以在 VuePress 的侧边栏中玩转标题链接。这里将讨论一些示例。

# 显示每个页面的标题链接

默认情况下，侧边栏只会显示当前页面的标题链接。你可以将其更改为立即显示所有页面的标题链接。你只需要将相关值设置为`true`即可，如下所示：

```js
module.exports = {
  themeConfig: {
    displayAllHeaders: true // Default is false
  }
 }
```

# 嵌套标题链接

侧边栏，正如你所知，将自动显示当前活动页面的标题链接。因此，当你浏览页面时，相关的标题链接将显示出来，以便更容易导航。

这样的标题是嵌套在活动页面下的，默认深度为`1`（这意味着所有`H2`标签都显示为标题，页面标题本身是`H1`）。

您可以使用`themeConfig.sidebarDepth`选项修改此行为，以显示更深层次的标题链接嵌套。例如，如果将嵌套深度更改为`0`，则所有标题链接都将被隐藏，只有`H1`值（页面标题）会显示。类似地，将深度更改为`2`将意味着所有嵌套在`H2`标题链接下的`H3`标题也会显示，依此类推。

您可以在 front matter 中指定相关深度。例如，要显示`H1`页面标题，`H2`标题链接以及`H3`和`H4`链接，您将指定深度为`3`，如下所示：

```js
 ---
 sidebarDepth: 3
 ---
```

# 活动标题链接

当用户向下滚动页面时，侧边栏的活动链接会自动更新。这是几乎所有静态站点生成器的默认行为，它们倾向于作为单页面应用程序工作。这样一来，根本不需要刷新或重新加载整个页面。

但是，如果需要的话，您可以通过`themeConfig.activeHeaderLinks`选项来禁用此行为，如下所示：

```js
module.exports = {
 themeConfig: {
 activeHeaderLinks: false, // Default is true
 }
 }
```

请注意，这意味着在浏览时不会突出显示活动标题链接，这可能会影响站点的整体用户体验。但是，这也可能会略微提高页面速度，因为相应的脚本将不再加载。

# 组织侧边栏

您可以选择将侧边栏组织或分成多个组。这是通过对象的帮助实现的。

VuePress 中的侧边栏组默认是可折叠的。但是，您也可以将可折叠选项指定为 false。创建侧边栏组的语法如下：

```js
// goes in .vuepress/config.js
 module.exports = {
  themeConfig: {
    sidebar: [
      {
        title: 'A Group',
        children: [
          '/'
        ]
      },
      {
        title: 'B Group',
        children: [ /* ... */ ]
      }
    ]
  }
 }
```

这个语法很简单。我们只是用给定的标题创建链接组，然后将页面和链接作为每个组的子项添加。

# 使用多个侧边栏

确实，您可以为内容的不同部分创建多个侧边栏。

但是，要使其正常工作，您首先需要相应地组织您的内容。一个好主意是将页面组织成目录和子目录。

例如，考虑以下目录结构，其中页面按目录组织：

现在，要创建多个侧边栏，我们需要将以下内容添加到我们的`config.js`文件中：

```js
// goes in .vuepress/config.js
 module.exports = {
  themeConfig: {
    sidebar: {
      '/testx/': [
        '', /* /testx/readme.md */
        'one', /* /testx/one.md */
        ],

      '/testxy/': [
        '', /* /testxy/readme.md */
       'two' /* /testxy/two.md */
      ],

      // fallback
      '/': [
        '',   /* readme.md at / */
        'about'   /* /about.md */
      ]
    }
  }
 }
```

上述配置将为每个部分声明侧边栏。请注意，强烈建议仅在最后声明 fallback 选项，因为 VuePress 按照从上到下的顺序读取侧边栏配置；也就是说，按照声明的时间顺序。

# 为单个页面添加侧边栏

您可以生成包含特定页面的标题链接的自定义迷你侧边栏-通常是当前活动页面。

要实现这一点，您首先需要在相关页面的 front matter 中指定如下：

```js
---
 sidebar: auto
 ---
```

您也可以在全局范围内重复这个过程。在这种情况下，您可以修改您的`config.js`文件如下：

```js
// goes in .vuepress/config.js
 module.exports = {
  themeConfig: {
    sidebar: 'auto'
  }
 }
```

# 如何禁用侧边栏？

如果您希望在特定页面上禁用侧边栏，可以在 front matter 中指定。这将使页面呈现全宽外观，并且可以按如下方式完成：

```js
---
 sidebar: false
 ---
```

# 对于 GitHub 用户

考虑到 VuePress 在其自己的 GitHub 存储库上得到积极维护，并且许多 Vue.js 用户倾向于偏爱 GitHub，VuePress 自然会加载一些对 GitHub 的本地支持。

# 同步到 GitHub 存储库

您可以通过简单指定存储库名称来轻松地向您的 GitHub 存储库添加编辑链接和更新。

然而，如果您不是 GitHub 用户，依赖于其他服务，如 BitBucket 或 GitLab，您仍然无需担心。在这种情况下，您可以在`config.js`文件中简单地提供存储库的完整 URL（正如我们将在即将介绍的语法中看到的），您会发现 VuePress 可以从中提取相关信息。

因此，总结一下：

+   GitHub 用户只需要告诉 VuePress 要使用哪个存储库

+   GitLab 和 BitBucket（或其他基于 Git 的平台用户）需要指定其存储库的完整 URL

要启用此特定功能，您只需要以下代码片段。请特别注意此代码中的注释，因为您需要根据需要更改它以使其正常工作。另外，根据您组织存储库的方式，您可能不需要大部分此代码（例如，如果您的文档不在不同的存储库中，您可以安全地从以下代码中省略该行）：

```js
// goes in .vuepress/config.js
 module.exports = {
  themeConfig: {
    // GitHub by default, provide full URLs for others.
    repo: 'repo-address-here',
    // Customize the header label that is shown in menu
    repoLabel: 'Contribute!',

    // Further options related to “Edit on Git” link

    // if docs are maintained in a separate repo:
    docsRepo: 'docs-repo-here-full-address',
    // if docs are in a sub-directory of main repo:
    docsDir: 'docs-directory-here',
    // if you do not want to use the Master branch on Git:
    docsBranch: 'master-or-branch-name',
    // do you want people to edit your docs? Boolean value
    editLinks: true,
    // modify the “edit this page” link that is shown
    editLinkText: 'Help me edit this page!'
  }
 }
```

在上面的代码片段中，您需要指定您的存储库地址，以及文档存储库（或您在 VuePress 上托管的任何文学作品）的地址，如果有的话。然后，您可以调整链接的外观，并选择是否希望其他人编辑或为您的存储库做出贡献。

# 如何在某些页面上隐藏编辑链接？

通常，您希望开源用户为项目或站点上的所有页面做出贡献，但可能有某些页面您希望免受编辑。这在涉及许可、法律条款、版权所有者等页面的情况下尤为重要。

在这种情况下，您只需要使用给定页面的前置内容，并关闭`editLink`属性，如下所示：

```js
 ---
 editLink: false
 ---
```

# 来自 GitHub 的时间戳

在使用 GitHub 存储库时，开发人员通常会展示或显示*上次更新时间*时间戳，以便跟踪进度，并通知用户所说的项目实际上正在积极开发中。

此时间戳来自 Git 提交，并在给定页面进行第一次提交时显示。之后，每当进行新的提交时，它都会更新。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vuep-qk-st-gd/img/9fe6c5a0-d25c-4394-bf3b-ff662faab38e.png)

在 VuePress 中，默认情况下是关闭的。但您可以选择打开它，并将其显示为上次更新的显示。

您可以使用`themeConfig.lastUpdated`选项，该选项将提取每个页面的最后一个 Git 提交的时间戳，并在页面底部显示它。

语法如下。请注意，时间戳是一个字符串值：

```js
module.exports = {
  themeConfig: {
    lastUpdated: 'Last Updated', // timestamp at bottom of page
  }
 }
```

这就是在为 VuePress 站点使用 GitHub 存储库时的全部内容。

现在，由于我们正在谈论主题开发，我们需要转向使网页显示其外观的内容。

是的，我们在谈论层叠样式表，或者 CSS。

# VuePress 主题开发中的 CSS

此时，我们将看看在 VuePress 中可以使用哪些自定义 CSS 覆盖和更改。

请注意，您需要对 CSS 有一定的了解，以执行本节中建议的任何调整。

# 页面的自定义类

往往，您可能需要为 VuePress 站点上的特定页面添加自定义 CSS。在这种情况下，您需要添加一个对于给定页面是唯一的自定义类。

到目前为止，您可能已经意识到需要使用 YAML 前置内容声明特定页面的内容。

因此，我们首先需要在 front matter 中的主题容器`div`中添加唯一的页面类：

```js
 ---
 pageClass: custom-page-class-name
 ---
```

之后，我们可以安全地为特定页面编写自定义 CSS，如下所示：

```js
/* this will NOT go to .vuepress/config.js */

 .theme-container.custom-page-class-name {
  /* page-specific custom CSS comes here */
 }
```

但是一个重要的问题是：我们在哪里添加主题容器并编写我们自定义的 CSS 呢？当然不是在 Markdown 文件中。

# CSS 覆盖文件结构

第一步是在您的`.vuepress/`目录中创建一个`override.styl`文件。这里的一般想法是在这里添加站点范围的常量覆盖，例如颜色，文本颜色等。

例如，要使整个文本颜色为黑色，您可以添加以下内容：

```js
$textColor = #000000
```

您可以使用普通的 CSS 语法进行编写。但如果您愿意，使用 Stylus 也是一个好主意。

Stylus 是一种 CSS 预处理器，以使在处理 CSS 时更容易阅读和编写而闻名。它支持多次迭代，嵌套运算符，并且不需要冒号，大括号和其他语法装饰。在[`stylus-lang.com/`](http://stylus-lang.com/)了解更多关于 Stylus 的信息。

然而，`override.styl`文件仅适用于 Stylus 常量。那么你自己的额外样式呢？

为此，您需要在`.vuepress/`目录中添加另一个`style.styl`文件。在这个文件中，您可以编写任何您希望的 CSS 样式。再次，您可以使用 Stylus 或普通 CSS 语法。

如果您不太喜欢 Stylus，请记住您也可以使用其他 CSS 预处理器，如 LESS 或 SASS。还记得您在第三章中学到的构建流水线配置值，《VuePress 开发-初步步骤》吗？您只需要根据您选择的 CSS 预处理器使用正确的值。

在任何时候，您都可以转到配置值列表（构建流水线）并参考这些内容；这就是为什么本书在第三章中提前很好地涵盖了这一点，《VuePress 开发-初步步骤》。

# 向后兼容性

这些信息对于较新版本的 VuePress 不再相关。但是，如果您使用的是较旧版本的 VuePress，您甚至可以只使用`override.styl`文件而不是第二个`style.styl`文件。考虑以下示例：

```js
// .vuepress/override.styl
 $textColor = black // stylus constants override.

 #my-style {} // extra CSS styles in the same file.
```

虽然这在实践中对于较旧版本的 VuePress 有效，但即使是这样，它也是双倍的处理。这是因为 Stylus 要求首先编译所有 Stylus 常量覆盖，然后再编译所有用户指定的额外 CSS。

如果你要在`override.styl`文件中编写你的样式，这意味着同一个文件在被导入一次后会被多次复制。为了避免这种情况，从版本 0.12.0 开始，VuePress 将 CSS 处理分成了`override.styl`和`style.styl`文件，如前所述。这是添加自定义 CSS 样式的正确方式。

学习更多关于老版本的 VuePress 是如何处理相同文件的，可以查看这个 GitHub 问题，链接在[`github.com/vuejs/vuepress/issues/637`](https://github.com/vuejs/vuepress/issues/637)。

# 弹出主题

有时，并不需要从头开始创建一个自定义主题。原因有很多：

+   这需要很长时间，特别是在像 VuePress 这样的平台上，它仍处于起步阶段。

+   编写自定义主题需要对 JavaScript 有广泛的了解，而且可能会破坏使用静态网站生成器的初衷，即节省时间和精力。

+   在错误修复、定期更新等方面，维护自定义主题并不总是容易的。

话虽如此，你可能也不喜欢使用默认主题，因为它不能使你的网站脱颖而出。在这种情况下，你可以选择使用自定义 CSS 样式和其他措施，如前所述，即使使用默认主题，也可以使你的网站具有独特的外观。

但如果你希望对默认主题进行重大更改呢？一旦你更新 VuePress，对默认主题源代码所做的任何更改都将丢失。

在这些情况下，你可以复制默认主题，然后编辑复制品，进行更改，就像它是一个自定义主题一样。这就是弹出主题。

要弹出你的主题，你需要输入以下命令：

```js
vuepress eject [target-directory-here]
```

这个命令将拉取默认主题的源代码，并将其复制到`.vuepress/theme`子目录中。这个特定的目录将作为你自定义主题的新家，你可以在其中进行更改。

请注意，一旦你弹出你的主题，你将负责它的维护和错误修复。你仍然可以根据需要更新 VuePress，但你将不再获得与默认主题相关的错误修复或功能更新。

确保只有当你知道自己在做什么，并且对 Vue.js 有很好的了解时，才弹出你的 VuePress 主题。当然，这已经超出了这个快速入门指南的范围。

但一旦你确实弹出了你的主题，就是时候转向自定义主题开发了！

# VuePress 中的自定义主题开发

为了创建自定义 VuePress 主题，需要使用 Vue 单文件组件。这意味着您需要对 Vue.js 有功能性的了解才能创建 VuePress 主题。如果您发现自己在时间或技能方面缺乏，建议您定制默认的 VuePress 主题，就像本章前面讨论的那样。

说到这里，创建自定义 VuePress 主题的第一步是在 VuePress 的`根`文件夹中创建一个`/theme/`目录。

然后，在`.vuepress/theme/`目录中创建一个`layout.vue`文件。

然后，您可以像为自定义 Vue.js 应用程序一样进行自定义主题创建。布局选项和设置完全取决于您。

您还可以选择从 npm 依赖项中使用自定义 VuePress 主题。在这种情况下，您需要在`config.js`文件中使用主题配置选项。只需将以下代码添加到您的`.vuepress/config.js`文件中：

```js
module.exports = {
  theme: 'your-theme-name'
}
```

请注意，您需要事先声明并发布主题到 npm，以便将其用作依赖项。

# 定制默认主题

我们之前讨论过的默认 VuePress 主题可以定制为自定义主题。然而，在这种情况下，您需要弹出默认主题，就像本章前面提到的那样。

在那之后，您可以开始自己调整自定义主题——请注意，一旦您弹出主题，将不会自动复制默认主题的任何未来更新或错误修复。但您可以像往常一样更新 VuePress。

# 处理元数据

每个 VuePress 主题都需要元数据来正确显示站点详细信息，正如我们已经学到的那样，最好使用布局组件来完成这一点。

在这个阶段，您应该熟悉两个 Vue.js 属性，即`$page`和`$site`。这两个属性都被注入到每个组件中。

因此，每次调用布局组件时，`$site`和`$page`属性也会被调用。因此，将您站点的元数据放置在`this.$site`和`this.$page`中是一个合乎逻辑的想法。

让我们先看看`$site`。这里是一个示例值：

```js
{
  "title": "Site-Title",
  "description": "Site description comes here",
  "base": "/",
  "pages": [
    {
      "path": "/",
      "title": "Title",
      "frontmatter": { }
    },
    ...
  ]
}
```

前面的语法非常清楚地显示了`$site`保存了与整个站点元数据相关的值。

对于`$page`，我们有以下语法：

```js
{
  "path": "/current/path/to/page",
  "title": "Page Title",
  "headers": [/* ... */],
  "frontmatter": { }
}
```

可以看到，`$page`保存了特定页面的元数据。

对于$site 的数值，大部分细节都是从`.vuepress/config.js`文件中复制而来。但是 pages 数值包含一个数组，其中包括每个页面的元数据对象。这些元数据对象通常是从相关页面的前置内容中提取的，或者是推断出来的，比如页面标题，可以在前置内容中指定，也可以从标题标签中获取。

$page 的数值经常可以用来构建主题的定制行为。您也可以根据需要对页面进行排序。这与定制 Vue.js 应用程序的顺序非常相似。

# 其他可能的增强

以下是一些其他潜在的指针，您可以在自定义 VuePress 主题时使用。

请注意，您需要对 Vue.js 工作流程有一定的了解，才能实现这些增强。

# 应用级别的增强

在您的主题根目录中，您可以创建一个`enhanceApp.js`文件来处理应用级别的增强。

这个特定的文件将导出一个钩子函数。在这个函数中，您应该接收一个包含特定应用程序细节或数据的对象数值。

然后，您可以非常容易地利用这个钩子来注册自定义插件，添加扩展，注册全局组件，定制其他功能等。

这个钩子函数的一般语法如下：

```js
export default ({
  Vue, // the current Vue.js version 
  options, // specify the options for Vue instance
  router, // the router for our app
  siteData // site metadata
}) => {
  // enter custom enhancements here 
}
```

听起来很混乱？只有当您是经验丰富的 Vue.js 开发人员，并且希望使用 VuePress 构建定制内容时，所有这些才有用。如果您只是想快速建立一个简单的站点，您可以安全地忽略这些细节。

这些都是您开始自定义 VuePress 主题开发所需的所有细节。再次强调，VuePress 中的主题需要对 Vue.js 有相当的了解，最好在进入生产级开发之前先进行一些实验。

# 总结

这标志着与 VuePress 主题相关的这一特定章节的结束。

在这一章中，我们已经涵盖了相当多的内容。现在我们对默认的 VuePress 主题有了很好的理解，知道如何调整它，如何改变标题链接、导航栏、侧边栏等外观。

此外，对于基于 GitHub 项目构建文档站点的情况，我们还学习了如何将站点与我们的 GitHub 存储库集成。除此之外，我们还学习了如何向我们的主题添加 CSS 样式来改变站点的外观。

不仅如此，我们现在知道如何弹出 VuePress 的默认主题并开始创建我们自己的自定义主题，当然，这也需要 Vue.js 应用程序的知识。

目前，您在本地主机上已经建立了一个活跃的网站，这是您在第四章中创建的*在 VuePress 中创建网站*。在该网站上尝试主题的更改和调整是一个好主意。本章中有所有的语法和代码示例，但为了清晰起见，我已经避免让它们特定于用例。因此，您可以修改这些通用的代码示例以适应您的生产和网站特定的需求。

结合我们迄今为止的进展，现在您应该能够安装 VuePress，调整`config.js`文件以修改主题和其他项目，以及在 Markdown 文件中创建内容并上传这些内容。

现在剩下的就是让网站上线，让全世界看到它！

但在此之前，我们需要掌握另一个学习步骤——本地化和国际化。在这方面，我们将讨论 VuePress 对多种语言的支持，以及我们何时以及如何利用这一点。下一章将涉及到这一点，之后我们将把注意力转向让我们的网站在互联网上发布。
