# 构建安卓 UI 自定义视图（一）

> 原文：[`zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14`](https://zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多年前，在安卓和 iPhone 推出之前，一个主要的担忧是有没有一个集中的地方来购买和下载移动应用程序。如今，我们通过广泛可用的集中应用商店如谷歌应用商店解决了这个问题，但代价是应用程序的可发现性降低。

谷歌应用商店（Google Play）和其他移动应用商店一样，市场竞争已经高度饱和。除非一个应用有独特之处或者有特别之处，否则在众多功能相近甚至不相关的应用中脱颖而出是非常困难的。

增加市场营销投入可能会暂时缓解这个问题，但从长远来看，应用程序仍然需要找到那项独特的功能或那个使其与众不同的细节。

一个让应用与众不同的方法是从安卓标准小部件和 UI 组件中稍微偏离，加入特定的自定义视图或自定义菜单，或者，在最后，任何让应用变得卓越的东西。我们应该知道，这并不意味着我们应该完全忽视安卓标准小部件，重写整个应用程序的 UI。与几乎所有事情一样，进行用户测试，发现对他们来说什么有效，什么无效。探索新选项，解决他们遇到的问题，但不要过度。有时，在应用程序顶部创建一个特定的菜单可能解决了导航问题，或者一个定义良好的动画可能向用户正确传达了过渡。

在这本书中，我们将学习如何开始为安卓构建自定义视图并将其集成到我们的应用程序中。我们会详细探讨如何与这些视图互动，添加动画，并给出 2D 和 3D 渲染能力的综合示例。最后，我们还将学习如何共享我们的自定义视图，以便在企业环境中复用，以及如何开源它们，让安卓开发社区也能使用。

# 本书内容涵盖

第一章，*入门*，解释了自定义视图是什么，我们何时需要它们，并展示如何构建你的第一个自定义视图。

第二章，*实现你的第一个自定义视图*，更详细地介绍了测量、实例化、参数化以及一些基本的渲染，从而开始感受自定义视图能做什么。

第三章，*处理事件*，向读者展示如何让自定义视图具有交互性，以及如何响应用户的交互。

第四章，*高级 2D 渲染*，添加了额外的渲染原语和操作，并展示如何将它们组合起来构建更复杂的自定义视图。

第五章，*引入 3D 自定义视图*，因为我们的渲染不仅限于 2D，本章介绍了如何使用 OpenGL ES 渲染 3D 的自定义视图。

第六章，*动画*，讲述了如何为自定义视图添加动画，既可以使用标准的 Android 组件，也可以自己实现。

第七章，*性能考虑*，提出了一些建议和最佳实践，在构建自定义视图时应当遵循，以及不遵循可能产生的影响。

第八章，*分享我们的自定义视图*，讲述了如何打包和分享我们的自定义视图，使其公开可用。

第九章，*实现自己的电子节目指南*，展示了如何通过结合我们在书中看到的内容，构建一个更复杂自定义视图的例子。

第十章，*构建图表组件*，详细介绍了如何逐步构建一个可定制的图表自定义视图。

第十一章，*创建 3D 旋转菜单*，介绍了如何构建一个更复杂的 3D 自定义视图，用作选择菜单。

# 阅读本书所需

为了跟随本书中的示例，你需要安装 Android Studio。我们将在第一章简要介绍如何安装和设置设备模拟器。强烈建议至少安装 Android Studio 3.0。在撰写本书时，Android Studio 3.0 仍然是测试版，但足够稳定，可以开发、运行和测试所有示例。此外，建议使用 Android 设备以更好地体验我们将创建的自定义视图中的用户交互，但它们也可以在 Android 模拟器中工作。

# 本书适合的读者

本书适用于希望提高 Android 应用开发技能并使用自定义视图构建 Android 应用的开发者。

# 约定

在本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理程序如下所示：

"我们可以使用`getWidth()`和`getHeight()`方法分别获取视图的宽度和高度。"

代码块设置如下：

```kt
<com.packt.rrafols.customview.OwnTextView 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:text="Hello World!" /> 
```

当我们希望引起你对代码块中某个特定部分的注意时，相关的行或项目会以粗体设置：

```kt
float maxLabelWidth = 0.f; 
if (regenerate) { 
    for (int i = 0; i<= 10; i++) { 
        float step; 
 if (!invertVerticalAxis) {
 step = ((float) i / 10.f);
 } else {
 step = ((float) (10 - i)) / 10.f;
}
```

新术语和重要词汇以粗体显示，例如，它们在文本中这样出现："布局通常被称为**ViewGroup**。"

警告或重要说明会以这样的方框显示。

技巧和诀窍会以这样的形式出现。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对这本书的看法——您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出您真正能从中获得最大收益的标题。

如果要给我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在邮件主题中提及本书的标题。

如果你对某个主题有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经拥有了 Packt 的一本书，我们有许多方法可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的账户下载本书的示例代码文件。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给您。

按照以下步骤，您可以下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标悬停在顶部的“支持”标签上。

1.  点击“代码下载与勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书。

1.  从下拉菜单中选择您购买本书的地方。

1.  点击“代码下载”。

文件下载后，请确保使用最新版本的以下软件解压或提取文件夹：

+   对于 Windows 系统，请使用 WinRAR / 7-Zip。

+   对于 Mac 系统，请使用 Zipeg / iZip / UnRarX。

+   对于 Linux 系统，请使用 7-Zip / PeaZip。

本书附带的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Building-Android-UIs-with-Custom-Views`](https://github.com/PacktPublishing/Building-Android-UIs-with-Custom-Views)。我们还有其他丰富的书籍和视频代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。请查看！

# 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能报告给我们，我们将不胜感激。这样做，您可以避免其他读者感到沮丧，并帮助我们在后续版本中改进这本书。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击“勘误提交表单”链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，勘误将被上传到我们的网站或添加到该标题下的现有勘误列表中。

要查看之前提交的勘误信息，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将显示在勘误部分下。

# 盗版问题

互联网上对版权材料进行盗版是一个所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果您发现疑似盗版材料，请通过 `copyright@packtpub.com` 联系我们，并提供相关链接。

我们感谢您帮助保护我们的作者以及我们为您提供有价值内容的能力。

# 问题咨询

如果您对本书的任何方面有问题，可以通过 `questions@packtpub.com` 联系我们，我们将尽力解决问题。


# 第一章：开始

你可能想知道自定义视图是什么；没问题，我们将在本书中介绍这个以及其他更多内容。如果你已经开发了一段时间的**Android**应用程序，你很可能已经多次使用过标准的 Android 视图或小部件。例如：**TextView**、**ImageView**、**Button**、**ListView**等等。自定义视图略有不同。简单来说，自定义视图是一个我们自行实现其行为的视图或**小部件**。在本章中，我们将介绍开始构建 Android 自定义视图所需的基本步骤，以及我们应该使用自定义视图的场景和应该依赖 Android 标准小部件的场景。更具体地说，我们将讨论以下主题：

+   自定义视图是什么，为什么我们需要它们？

+   如何设置和配置我们的开发环境以开发自定义视图

+   创建我们自己的第一个自定义视图

# 自定义视图是什么

正如我们刚刚提到的，自定义视图是我们自行实现其行为的视图。这有点过于简化了，但这是一个不错的起点。我们实际上并不需要自行实现其全部行为。有时，它可能只是一个简单的细节，或者是一个更复杂的功能，甚至是整个功能和行为，如交互、绘图、调整大小等等。例如，将按钮的背景颜色作为一个自定义视图的实现进行微调，这是一个简单的改变，但创建一个基于位图的 3D 旋转菜单在开发时间和复杂性上则完全不同。我们将在本书中展示如何构建这两种视图，但本章将仅关注一个非常简单的示例，在接下来的章节中，我们将添加更多功能。

在整本书中，我们将同时提到自定义视图和自定义布局。关于自定义视图的定义同样适用于布局，但主要区别在于，自定义布局可以帮助我们用我们创建的逻辑布置其包含的项目，并以我们希望的方式精确定位它们。稍后我们会学习如何做到这一点，敬请期待！

布局通常被称为**ViewGroup**。最典型的例子，也是你可能听说过的，在你的应用中很可能使用过的有：**LinearLayout**、**RelativeLayout**和**ConstraintLayout**。

如果想要了解更多关于 Android 视图和布局的信息，我们可以随时查阅官方的 Android 开发者文档：

[Android 开发者官网](https://developer.android.com/develop/index.html)。

# 为什么需要自定义视图

Google Play 和其他市场上有很多可爱的 Android 应用程序：仅使用标准**Android UI 组件**和布局的*亚马逊*。还有许多其他应用程序拥有让我们的互动更容易或仅仅更愉悦的小功能。虽然没有神奇的公式，但也许只是添加一些不同的东西，让用户觉得“这不仅仅是另一个用于...的应用程序”可能会提高我们的用户留存率。它可能不是决定性的因素，但有时确实可以产生差异。

一些自定义视图的影响力如此之大，以至于其他应用程序也希望效仿或构建类似的东西。这种效果为应用程序带来了病毒式营销，也吸引了开发者社区，因为可能会有许多类似的组件以教程或开源库的形式出现。显然，这种效果只会持续一段时间，但如果发生了，对你的应用程序来说绝对是值得的，因为它会在开发者中变得更加流行和知名，因为它不仅仅是另一个 Android 应用程序，而是有特色的东西。

我们为移动应用程序创建自定义视图的一个主要原因，正是为了拥有一些特别的东西。它可能是一个菜单、一个组件、一个屏幕，或者是我们应用程序真正需要的主要功能，或者只是一个附加功能。

此外，通过创建我们自己的自定义视图，我们实际上可以优化应用程序的性能。我们可以创建一种特定的布局方式，否则仅使用标准 Android 布局或自定义视图将需要许多层次结构，从而简化渲染或用户交互。

另一方面，我们很容易犯试图自定义构建一切的错误。Android 提供了一个出色的组件和布局列表，为我们处理了很多事情。如果我们忽略基本的 Android 框架，试图自己构建一切，那将是非常多的工作。我们可能会遇到许多 Android 操作系统开发者已经面对过的问题，至少也是非常相似的问题。一句话，我们就是在重新发明轮子。

# 市场上的例子

我们可能都使用过仅使用标准 Android UI 组件和布局构建的优秀应用程序，但也有许多其他应用程序有一些我们不知道或没有真正注意到的自定义视图。自定义视图或布局有时可能非常微妙，难以察觉。

我们不一定是第一个在应用程序中拥有自定义视图或布局的人。实际上，许多受欢迎的应用程序都有一些自定义元素。让我们来看一些例子：

第一个例子将是*Etsy*应用程序。*Etsy*应用程序有一个名为**StaggeredGridView**的自定义布局。它甚至在 GitHub 上作为开源发布。自 2015 年以来，它已被废弃，取而代之的是与**RecyclerView**一起使用的谷歌自己的`StaggeredGridLayoutManager`。

你可以通过从 Google Play 下载*Etsy*应用程序来亲自查看，但为了快速预览，以下截图实际上展示了*Etsy*应用程序中的 StaggeredGrid 布局：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/a66193d6-124e-4a87-aa25-828921766c4b.png)

还有许多其他潜在的例子，但第二个好的例子可能是荷兰最大的有线电视运营商之一*Ziggo*的电子编程指南。电子编程指南是一个自定义视图，为电视节目呈现不同的盒子，并改变当前时间前后内容的颜色。

该应用只能在荷兰的 Google Play 下载，不过，以下截图展示了应用程序如何呈现电子编程指南：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/79cf4f75-2f65-44a6-b133-677c310ba086.png)

最后，第三个例子，也是最近发布的应用程序是来自 Airbnb 的*Lottie*。*Lottie*是一个示例应用程序，它实时呈现**Adobe After Effects**动画。

*Lottie*可以直接从 Google Play 下载，但以下截图展示了应用程序的快速预览：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/ae3903a7-490c-4eaa-9459-5c17626d3d98.png)

渲染视图和自定义字体是自定义渲染的例子。有关*Lottie*的更多信息，请参考：

[`airbnb.design/introducing-lottie/`](http://airbnb.design/introducing-lottie/)。

我们刚刚看到了一些例子，但还有更多可用。一个发现它们或查看可用内容的好网站是 Android Arsenal：

[`android-arsenal.com/`](https://android-arsenal.com/)。

# 设置环境

既然我们已经对自定义视图、为什么需要它们以及市场上的一些例子有了简要介绍，那么让我们开始构建自己的视图吧。如果我们还没有这样做，那么我们的第一步自然就是安装 Android 开发工具。如果你已经安装了 Android Studio，可以跳过这一部分，直接进入正题。本书中的大多数例子都可以完美地与 Android Studio 2.3.3 配合使用，但后面的章节将需要 Android Studio 3.0。在撰写本文时，Android Studio 3.0 仍处于测试阶段，但强烈建议使用它来测试提供的所有示例。

# 安装开发工具

要开始创建自己的自定义视图，你只需要正常开发 Android 移动应用程序所需的工具。在本书中，我们将使用 Android Studio，因为这是谷歌推荐的工具。

我们可以从 Android Studio 的官方网站获取最新版本：

[`developer.android.com/studio/index.html`](https://developer.android.com/studio/index.html)。

一旦我们为电脑下载了软件包，就可以开始安装了：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/b6714aeb-1b24-41b8-906c-c396ce7c8c93.png)

现在，我们可以创建一个新项目，这个项目将用于我们自定义视图的初步尝试。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/dead148f-7aa0-47a8-8d91-613bdfc5ae95.png)

选择应用程序名称、公司域名（这将反转成应用程序包名）和项目位置后，Android Studio 会询问我们想要创建哪种类型的项目：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/38d73812-0b86-41f1-adf8-ea9c63be3429.png)

在这个例子中，我们不需要太花哨的东西，只要有手机和平板支持，API 21 的支持就足够了。完成这些设置后，我们可以添加一个空的活动（Empty Activity）：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/72eb2f0a-359a-4c21-8ca0-ea41dd8bc876.png)

如果你需要安装 Android Studio 的帮助，可以在《*Learning Android Application Development*, *Packt Publishing*》中找到一份分步指南，或者在 Android 开发者文档网站上总有很多信息。更多信息，请参考：

[学习 Android 应用开发](https://www.packtpub.com/application-development/learning-android-application-development)

现在，我们可以在设备模拟器或真实设备上运行这个应用程序了。

# 如何设置模拟器

要设置模拟器，我们需要运行**Android 虚拟设备管理器**（**AVD Manager**）。我们可以在顶部栏找到它的图标，就在播放/停止应用程序图标旁边。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/59188fcf-dd12-45b7-87bf-cc47d1a57707.png)

一旦我们执行了**Android 设备管理器**，就可以从那里添加或管理我们的虚拟设备，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/1a1a73ab-1b69-4a27-9a42-acb9e16cabc7.png)

点击“创建虚拟设备”将给我们一个使用 Android 设备定义之一的机会，甚至可以创建我们自己的硬件配置文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/96ceda49-fc4b-4787-b95a-ae6252f97738.png)

选择硬件后，我们需要选择在其上运行的软件，或者说是系统镜像。稍后，我们可以添加所有需要的测试组合：多种不同的设备，或者带有不同 Android 版本镜像的同一设备，甚至是两者的组合。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/5753dd3b-7ff9-4f7b-bcc6-d59ad186dfab.png)

最后一步是给我们的 AVD 命名，检查我们的硬件和软件选择，然后就可以开始了！

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/f322220a-56e9-42b8-b3cb-ce5c2c8c8a3b.png)

# 如何为开发设置真实设备

使用模拟器进行测试和调试是可以的，但有时我们确实想要在真实设备上测试或安装应用程序。为了在我们的设备上启用开发，我们需要执行几个步骤。首先，我们需要为开发启用我们的设备。我们可以轻松地通过在设置中点击七次“关于”菜单 -> “构建号”（自 Android 4.2 起）。完成这一步后，将出现一个新的菜单选项，称为“开发者选项”。那里有多种选项供我们探索，但现在我们需要的是启用 USB 调试。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/68517d92-821f-4c59-93e8-347122c6b254.png)

如果启用了 USB 调试，我们将在设备选择中看到我们的设备和正在运行的模拟器：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/a38c7e8c-afb3-41b3-bef0-6ebbc8521edb.png)

# 创建我们自己的第一个自定义视图

现在我们已经设置好了开发环境，可以在模拟器和真实设备上运行和调试 Android 应用程序，我们可以开始创建我们自己的第一个自定义视图了。为了简化，我们首先会轻松地修改一个现有的视图，稍后我们将从头开始创建我们自己的视图。

# 扩展一个视图

使用上一节的示例，或者如果你跳过了它，只需创建一个带有空活动的新项目，我们将用我们自己的实现来替换 `TextView`。

如果我们查看默认的布局 XML 文件，通常称为 `activity_main.xml`（除非在项目创建期间你更改了它），我们可以看到 `RelativeLayout` 中有一个 `TextView`：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  

    android:id="@+id/activity_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:paddingBottom="@dimen/activity_vertical_margin" 
    android:paddingLeft="@dimen/activity_horizontal_margin" 
    android:paddingRight="@dimen/activity_horizontal_margin" 
    android:paddingTop="@dimen/activity_vertical_margin" 
    tools:context="com.packt.rrafols.customview.MainActivity"> 

    <TextView 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:text="Hello World!" /> 
</RelativeLayout> 
```

让我们修改那个 `TextView`，将其变为我们接下来将实现的定制类。

```kt
<com.packt.rrafols.customview.OwnTextView 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:text="Hello World!" /> 
```

我们使用了 `com.packt.rrafols.customview` 包，但请根据你的应用程序的包名相应地更改它。

要实现这个类，我们首先会创建一个继承自 `TextView` 的类：

```kt
package com.packt.rrafols.customview; 

import android.content.Context; 
import android.util.AttributeSet; 
import android.widget.TextView; 

public class OwnTextView extends TextView { 

    public OwnTextView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 
    } 
} 
```

这个类或自定义视图将表现得像一个标准的 `TextView`。考虑到我们使用的构造函数。还有其他的构造函数，但现在我们只关注这一个。创建它是很重要的，因为它将接收上下文和我们定义在 XML 布局文件中的参数。

在这一点上，我们只是传递参数，并没有对它们进行任何花哨的操作，但让我们通过重写 `onDraw()` 方法来准备我们的自定义视图以处理新功能：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    super.onDraw(canvas); 
} 
```

通过重写 `onDraw()` 方法，我们现在可以控制自定义视图的绘制周期。如果我们运行应用程序，由于还没有添加任何新的行为或功能，我们不会注意到与原始示例有任何区别。为了解决这个问题，让我们做一个非常简单的更改，这将证明它实际上是在工作的。

在 `onDraw()` 方法中，我们将绘制一个红色矩形，覆盖视图的全部区域，如下所示：

```kt
@Override 
    protected void onDraw(Canvas canvas) { 
        canvas.drawRect(0, 0, getWidth(), getHeight(), backgroundPaint); 
        super.onDraw(canvas); 
    } 
```

我们可以使用`getWidth()`和`getHeight()`方法分别获取视图的宽度和高度。为了定义颜色和样式，我们将初始化一个新的`Paint`对象，但我们要在构造函数中执行这一操作，因为在`onDraw()`方法中执行是错误的做法。我们将在本书后面更多地讨论性能问题：

```kt
private Paint backgroundPaint; 

    public OwnTextView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 

        backgroundPaint= new Paint(); 
        backgroundPaint.setColor(0xffff0000); 
        backgroundPaint.setStyle(Paint.Style.FILL); 
    } 
```

在这里，我们使用整数十六进制编码将`Paint`对象初始化为红色，并将样式设置为`Style.FILL`，以便填充整个区域。默认情况下，`Paint`样式设置为`FILL`，但明确设置可以增加清晰度。

如果我们现在运行应用程序，我们将看到`TextView`，这是我们现在的类，背景为红色，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/81a9a33d-cc7b-4066-9646-fa28fefa7e70.png)

下面的代码片段是`OwnTextView`类的整个实现。更多详情，请查看 GitHub 仓库中`Example01`文件夹的完整项目：

```kt
package com.packt.rrafols.customview; 

import android.content.Context; 
import android.graphics.Canvas; 
import android.graphics.Paint; 
import android.util.AttributeSet; 
import android.widget.TextView; 

public class OwnTextView extends TextView { 

    private Paint backgroundPaint; 

    public OwnTextView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 

        backgroundPaint = new Paint(); 
        backgroundPaint.setColor(0xffff0000); 
        backgroundPaint.setStyle(Paint.Style.FILL); 
    } 

    @Override 
    protected void onDraw(Canvas canvas) { 
        canvas.drawRect(0, 0, getWidth(), getHeight(),
        backgroundPaint); 
        super.onDraw(canvas); 
    } 
} 
```

这个示例只是为了展示我们如何扩展标准视图并实现我们自己的行为；在 Android 中还有多种其他方法可以为小部件设置背景颜色或绘制背景颜色。

# 从零开始创建一个简单的视图

现在我们已经看到了如何修改已经存在的`View`，我们将看到一个更复杂的示例：如何从零开始创建我们自己的自定义视图！

让我们从创建一个继承自`View`的空类开始：

```kt
package com.packt.rrafols.customview; 

import android.content.Context; 
import android.util.AttributeSet; 
import android.view.View; 

public class OwnCustomView extends View { 

    public OwnCustomView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 
    } 

} 
```

我们现在将添加与上一个示例相同的代码以绘制红色背景：

```kt
package com.packt.rrafols.customview; 

import android.content.Context; 
import android.graphics.Canvas; 
import android.graphics.Paint; 
import android.util.AttributeSet; 
import android.view.View; 

public class OwnCustomView extends View { 

    private Paint backgroundPaint; 

    public OwnCustomView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 

        backgroundPaint= new Paint(); 
        backgroundPaint.setColor(0xffff0000); 
        backgroundPaint.setStyle(Paint.Style.FILL); 

    } 

    @Override 
    protected void onDraw(Canvas canvas) { 
        canvas.drawRect(0, 0, getWidth(), getHeight(),
        backgroundPaint); 
        super.onDraw(canvas); 
    } 
} 
```

如果我们运行应用程序，从下面的截图中可以看出，我们将得到与上一个示例略有不同的结果。这是因为在上一个示例中，`TextView`小部件调整大小以适应文本的大小。如果我们记得正确，我们在布局 XML 文件中有`android:layout_width="wrap_content"`和`android:layout_height="wrap_content"`。我们刚才创建的这个新的自定义视图不知道如何计算其大小。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/e962b44c-55c0-4b50-bffa-38096c7de345.png)

在 GitHub 仓库的`Example02`文件夹中查看这个简单例子的完整实现。

# 总结

在本章中，我们已经了解了为什么要构建自定义视图和布局的原因，同时也必须应用常识。Android 提供了一个用于创建 UI 的优秀基本框架，不使用它将是一个错误。并非每个组件、按钮或小部件都必须完全自定义开发，但通过在正确的位置执行此操作，我们可以添加一个可能会让我们的应用程序被记住的额外功能。此外，我们已经展示了一些已经在市场上使用自定义视图的应用程序示例，所以我们知道我们并不孤单！最后，我们已经看到了如何设置环境以开始工作，并且我们已经开始了自定义视图的初步尝试。

在下一章中，我们将继续添加功能；我们将了解如何计算自定义视图的正确大小并学习更多关于自定义渲染的内容。


# 第二章：实现你的第一个自定义视图

在前一章中，我们已经看到了如何创建自定义视图的基础，但除非我们添加更多功能和自定义，否则它将相当无用。在本章中，我们将在这些基础上继续构建，了解如何参数化我们的自定义视图，以便我们或其他开发人员可以自定义它们，并在最后，涵盖一些渲染内容，这将使我们能够构建更复杂的自定义视图。

此外，正如我们在前一章提到的，我们还可以创建自定义布局。在本章中，我们将了解如何创建一个简单的自定义布局。

更详细地说，我们将涵盖以下主题：

+   测量和参数化我们的自定义视图

+   实例化自定义视图

+   创建自定义布局

+   基本渲染

# 测量和参数化我们的自定义视图

为了有一个好的可重用的自定义视图，它需要能够适应不同的尺寸和设备分辨率，为了进一步提高其可重用性，它应该支持参数化。

# 测量我们的自定义视图

在前一章中我们快速构建的示例中，我们将所有尺寸和测量都委托给了父视图本身。坦白说，我们甚至没有委托它；我们只是没有特别做任何事情来处理这个问题。能够控制我们自定义视图的尺寸和维度是我们绝对需要关注的事情。首先，我们将从视图**重写**`onMeasure()`方法，如下所示：

```kt
@Override 
protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) { 
    super.onMeasure(widthMeasureSpec, heightMeasureSpec); 
} 
```

阅读关于`onMeasure()`方法的 Android 文档，我们应该看到我们必须**调用** `setMeasuredDimension(int, int)`或者父类的`onMeasure(int, int)`。如果我们忘记这样做，我们将得到一个`IllegalStateException`：

```kt
com.packt.rrafols.customview E/AndroidRuntime: FATAL EXCEPTION: main Process: com.packt.rrafols.customview, PID: 13601 java.lang.IllegalStateException: View with id -1: com.packt.rrafols.customview.OwnCustomView#onMeasure() did not set the measured dimension by calling setMeasuredDimension() at android.view.View.measure(View.java:18871)
```

有三种不同的**模式**，我们的视图的父视图可以通过这些模式指示我们的视图如何计算其大小。我们可以通过使用`MeasureSpec.getMode(int)`方法与每个尺寸规范`widthMeasureSpec`和`heightMeasureSpec`来获取模式。

这些模式如下：

+   `MeasureSpec.EXACTLY`

+   `MeasureSpec.AT_MOST`

+   `MeasureSpec.UNSPECIFIED`

当父视图计算或决定了尺寸时，我们将得到`MeasureSpec.EXACTLY`。即使我们的视图需要或返回不同的尺寸，它也将具有这个大小。如果我们得到`MeasureSpec.AT_MOST`，我们则有更大的灵活性：我们可以根据需要变得更大，但最大不超过给定的大小。最后，如果我们收到`MeasureSpec.UNSPECIFIED`，我们可以将视图的大小设置为任意我们想要的或视图需要的尺寸。

使用`MeasureSpec.getSize(int)`，我们还可以从尺寸规范中获取一个尺寸值。

既然有了这些，我们如何知道哪些值对应于我们 XML 布局文件中的宽度和高度参数？很容易看出，让我们检查一下。例如，如果我们像 GitHub 仓库中的`activity_main.xml`文件那样指定精确值，我们将得到以下代码：

```kt
<com.packt.rrafols.customview.OwnCustomView 
   android:layout_width="150dp" 
   android:layout_height="150dp"/> 
```

在我们的自定义视图中，使用`MeasureSpec.toString(int)`获取测量规范和尺寸的字符串描述的代码如下：

```kt
@Override 
protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) { 
    Log.d(TAG, "width spec: " +
    MeasureSpec.toString(widthMeasureSpec)); 
    Log.d(TAG, "height spec: " +
    MeasureSpec.toString(heightMeasureSpec)); 
    super.onMeasure(widthMeasureSpec, heightMeasureSpec); 
} 
```

在 Android 日志上的结果如下：

```kt
D/com.packt.rrafols.customview.OwnCustomView: width : MeasureSpec: EXACTLY 394 D/com.packt.rrafols.customview.OwnCustomView: height: MeasureSpec: EXACTLY 394
```

我们的视图将是精确的`394`乘`394`像素。这个`394`像素来自于将`150dp`转换为我用于测试的移动设备上的像素。

由于有许多具有不同分辨率和屏幕密度的 Android 设备，我们应始终使用**密度独立像素**（**dp**）或（**dip**）而不是像素。

要了解更多关于 dp 的信息，请参考谷歌在 YouTube 上发布的一个视频：DesignBytes：密度独立像素。

如果你想在特定设备上将 dp 转换为实际像素，你可以使用以下方法：

```kt
public final int dpToPixels(int dp) { 
    return (int) (dp * getResources().getDisplayMetrics().density +
    0.5); 
} 
```

我们可以看到转换是如何使用屏幕密度的，因此在不同的设备上转换可能会有所不同。前面代码中的`+ 0.5`只是为了在从浮点数转换为`int`时将值四舍五入。

要从像素转换到密度独立点，我们必须进行相反的操作，如下面的代码所示：

```kt
public final int pixelsToDp(int dp) { 
    return (int) (dp / getResources().getDisplayMetrics().density +
    0.5); 
} 
```

现在我们来看看，如果我们使用不同的测量参数，比如`match_parent`或`wrap_content`，如 GitHub 仓库中的`activity_main.xml`文件所示，我们会得到什么结果：

```kt
<com.packt.rrafols.customview.OwnCustomView 
   android:layout_width="match_parent" 
   android:layout_height="match_parent"/> 
```

运行与之前相同的代码，我们在 Android 日志中得到以下信息：

```kt
D/com.packt.rrafols.customview.OwnCustomView: width : MeasureSpec: EXACTLY 996 D/com.packt.rrafols.customview.OwnCustomView: height: MeasureSpec: EXACTLY 1500
```

因此，我们仍然得到了一个`MeasureSpec.EXACTLY`，但这次是父`RelativeLayout`的大小；让我们尝试在`activity_main.xml`中将一个`match_parents`改为`wrap_content`：

```kt
<com.packt.rrafols.customview.OwnCustomView 
    android:layout_width="match_parent" 
    android:layout_height="wrap_content"/> 
```

结果如下：

```kt
D/com.packt.rrafols.customview.OwnCustomView: width : MeasureSpec: EXACTLY 996 D/com.packt.rrafols.customview.OwnCustomView: height: MeasureSpec: AT_MOST 1500
```

我们可以轻松地识别出`MeasureSpec.EXACTLY`和`MeasureSpec.AT_MOST`的模式，但`MeasureSpec.UNSPECIFIED`呢？

如果我们的父视图没有边界，我们将得到一个`MeasureSpec.UNSPECIFIED`；例如，如果我们有一个垂直的`LinearLayout`在`ScrollView`内部，如 GitHub 仓库中的`scrollview_layout.xml`文件所示：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<ScrollView  
    android:orientation="vertical" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:orientation="vertical" 
        android:padding="@dimen/activity_vertical_margin"> 
        <com.packt.rrafols.customview.OwnCustomView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"/>
    </LinearLayout> 
</ScrollView> 
```

然后我们在 Android 日志中得到以下信息：

```kt
D/com.packt.rrafols.customview.OwnCustomView: width : MeasureSpec: EXACTLY 996 D/com.packt.rrafols.customview.OwnCustomView: height: MeasureSpec: UNSPECIFIED 1500
```

这看起来没问题，但如果我们现在运行这个代码会怎样呢？我们会得到一个空白屏幕；我们之前实现的红色背景不见了：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/a1bcec83-d3f8-4aab-8d2c-a4cbe743e041.png)

这是因为我们没有管理自定义视图的大小。让我们按照下面的代码所示进行修复：

```kt
private static int getMeasurementSize(int measureSpec, int defaultSize) { 
        int mode = MeasureSpec.getMode(measureSpec); 
        int size = MeasureSpec.getSize(measureSpec); 
        switch(mode) { 
            case MeasureSpec.EXACTLY: 
                return size; 

            case MeasureSpec.AT_MOST: 
                return Math.min(defaultSize, size); 

            case MeasureSpec.UNSPECIFIED: 
            default: 
                return defaultSize; 
        } 
    } 

    @Override 
    protected void onMeasure(int widthMeasureSpec, int
        heightMeasureSpec) { 
        int width = getMeasurementSize(widthMeasureSpec, DEFAULT_SIZE); 
        int height = getMeasurementSize(heightMeasureSpec,
        DEFAULT_SIZE); 
        setMeasuredDimension(width, height); 
    } 
```

现在，根据测量规格，我们将通过调用`setMeasuredDimension(int, int)`方法来设置视图的大小。

要查看完整示例，请检查 GitHub 仓库中`Example03-Measurement`文件夹中的源代码。

# 参数化我们的自定义视图

我们现在有一个能适应多种尺寸的自定义视图；这是好事，但如果我们需要另一个自定义视图，将背景色改为蓝色而不是红色呢？还有黄色？我们不应该为了每个定制而复制自定义视图类。幸运的是，我们可以在 XML 布局中设置参数，并从我们的自定义视图中读取它们：

1.  首先，我们需要定义我们将在自定义视图中使用的参数类型。我们必须在 `res` 文件夹中创建一个名为 `attrs.xml` 的文件：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
    <declare-styleable name="OwnCustomView"> 
        <attr name="fillColor" format="color"/> 
    </declare-styleable> 
</resources> 
```

1.  然后，在我们想要使用我们刚刚创建的这个新参数的布局文件中，我们添加了一个不同的命名空间：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<ScrollView  

    android:orientation="vertical" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:orientation="vertical" 
        android:padding="@dimen/activity_vertical_margin"> 

        <com.packt.rrafols.customview.OwnCustomView 
            android:layout_width="match_parent" 
            android:layout_height="wrap_content"
            app:fillColor="@android:color/holo_blue_dark"/>          
    </LinearLayout> 
</ScrollView> 
```

1.  现在我们已经定义了它，让我们看看如何从我们的自定义视图类中读取它：

```kt
int fillColor;
TypedArray ta =
    context.getTheme().obtainStyledAttributes(attributeSet,
        R.styleable.OwnCustomView, 0, 0);
try {
    fillColor =
        ta.getColor(R.styleable.OwnCustomView_ocv_fillColor,
            DEFAULT_FILL_COLOR);
} finally {
    ta.recycle();
}
```

通过使用我们在保存 `attrs.xml` 文件后，Android 工具为我们创建的样式属性 ID 来获取 `TypedArray`，我们将能够查询在 XML 布局文件上设置的这些参数的值。

在此示例中，我们创建了一个名为 `fillColor` 的属性，它将被格式化为颜色。这种格式，或者说基本上，属性的类别非常重要，因为它决定了我们可以设置哪种类型的值，以及之后如何从我们的自定义视图中检索这些值。

同时，对于我们定义的每个参数，我们将在 `TypedArray` 中获得一个 `R.styleable.<name>_<parameter_name>` 索引。在上述代码中，我们正在使用 `R.styleable.OwnCustomView_fillColor` 索引来查询 `fillColor`。

使用完 `TypedArray` 后，我们不应该忘记回收它，以便稍后可以重新使用，但一旦回收，我们就不能再使用它了。

让我们看看这个小小的自定义的结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/a9126c6f-80b6-489a-8525-aebfd9ecb311.png)

在这个特定情况下我们使用了颜色，但我们也可以使用许多其他类型的参数；例如：

+   布尔值

+   整数

+   浮点数

+   颜色

+   尺寸

+   图像

+   字符串

+   资源

每个都有自己的获取方法：`getBoolean(int index, boolean defValue)` 或 `getFloat(int index, float defValue)`。

此外，为了知道是否设置了参数，我们可以在查询之前使用 `hasValue(int)` 方法，或者我们可以简单地使用获取器的默认值。如果在那个索引处没有设置属性，获取器将返回默认值。

有关完整示例，请查看 GitHub 存储库中的 `Example04-Parameters` 文件夹。

# 实例化自定义视图

现在我们已经看到了如何在 XML 布局上设置参数并在我们的自定义视图类中解析它们，接下来我们将看到如何从代码中实例化自定义视图，并尽可能多地重用这两种实例化机制。

# 从代码中实例化自定义视图

在我们的自定义视图中，我们创建了一个带有两个参数的单个构造函数，一个 `Context` 和一个 `AttributeSet`。现在，如果我们是编程式地创建我们的 UI，或者由于任何其他原因我们需要通过代码实例化我们的自定义视图，我们需要创建一个额外的构造函数。

因为我们想要在 XML 布局中继续使用我们的自定义视图，所以我们必须保留这两个构造函数。为了避免代码重复，我们将创建一些辅助方法来初始化它，并从两个构造函数中使用它们：

```kt
   public OwnCustomView(Context context) { 
        super(context); 

        init(DEFAULT_FILL_COLOR); 
    } 

    public OwnCustomView(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 

        int fillColor; 

        TypedArray ta =
        context.getTheme().obtainStyledAttributes(attributeSet,
        R.styleable.OwnCustomView, 0, 0); 
        try { 
           fillColor = ta.getColor(R.styleable.OwnCustomView_fillColor,
           DEFAULT_FILL_COLOR); 
        } finally { 
            ta.recycle(); 
        } 

        init(fillColor); 
    } 

    private void init(int fillColor) { 
        backgroundPaint = new Paint(); 
        backgroundPaint.setStyle(Paint.Style.FILL); 

        setFillColor(fillColor); 
    } 

    public void setFillColor(int fillColor) { 
        backgroundPaint.setColor(fillColor); 
    } 
```

我们还创建了一个公共方法 `setFillColor(int)`，这样我们也可以通过代码设置填充颜色。例如，让我们修改我们的 `Activity`，以编程方式创建视图层次结构，而不是从 XML 布局文件中膨胀它：

```kt
public class MainActivity extends AppCompatActivity { 
    private static final int BRIGHT_GREEN = 0xff00ff00; 

    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 

        LinearLayout linearLayout = new LinearLayout(this); 
        linearLayout.setLayoutParams( 
                new LinearLayout.LayoutParams(ViewGroup.
                    LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT)); 

        OwnCustomView customView = new OwnCustomView(this); 
        customView.setFillColor(BRIGHT_GREEN); 
        linearLayout.addView(customView); 

        setContentView(linearLayout); 
    } 
} 
```

这里，我们只是创建了一个垂直方向的`LinearLayout`，并添加了一个自定义视图作为子视图。然后我们将`LinearLayout`设置为`Activity`的内容视图。此外，我们还直接使用了十六进制颜色。如果我们不习惯用十六进制格式指定颜色，可以使用`Color.argb()`或`Color.rgb()`将颜色组件转换为整数值。

完整的源代码可以在 GitHub 仓库中的`Example05-Code`文件夹中找到。

# 构建器模式

在上一个示例中，我们使用了`setFillColor()`方法来设置自定义视图的填充颜色，但是假设我们还有许多其他参数，代码可能会因为所有的设置器而变得有些混乱。

让我们创建一个简单的示例：不是使用单一背景色，我们将使用四种不同的颜色，并在我们的视图上绘制渐变：

让我们首先定义四种不同的颜色及其设置方法，如下所示：

```kt
private int topLeftColor = DEFAULT_FILL_COLOR; 
private int bottomLeftColor = DEFAULT_FILL_COLOR; 
private int topRightColor = DEFAULT_FILL_COLOR; 
private int bottomRightColor = DEFAULT_FILL_COLOR; 
private boolean needsUpdate = false;

public void setTopLeftColor(int topLeftColor) { 
    this.topLeftColor = topLeftColor; 
    needsUpdate = true; 
} 

public void setBottomLeftColor(int bottomLeftColor) { 
    this.bottomLeftColor = bottomLeftColor; 
    needsUpdate = true; 
} 

public void setTopRightColor(int topRightColor) { 
    this.topRightColor = topRightColor; 
    needsUpdate = true; 
} 

public void setBottomRightColor(int bottomRightColor) { 
    this.bottomRightColor = bottomRightColor; 
    needsUpdate = true; 
} 
```

我们还添加了一个布尔值以检查是否需要更新渐变。这里我们忽略线程同步，因为这不是此示例的主要目的。

然后，我们在`onDraw()`方法中为这个`boolean`添加了一个检查，如果需要的话，它会重新生成渐变：

```kt
@Override
protected void onDraw(Canvas canvas) {
    if (needsUpdate) {
        int[] colors = new int[] {topLeftColor, topRightColor,
        bottomRightColor, bottomLeftColor};

        LinearGradient lg = new LinearGradient(0, 0, getWidth(),
            getHeight(), colors, null, Shader.TileMode.CLAMP);

        backgroundPaint.setShader(lg);
        needsUpdate = false;
    }

    canvas.drawRect(0, 0, getWidth(), getHeight(), backgroundPaint);
    super.onDraw(canvas);
}
```

在`onDraw()`方法中创建新的对象实例是一个不好的实践。这里只做一次，或者每次更改颜色时都会执行。如果我们不断更改颜色，这将是一个不好的例子，因为它会不断创建新对象，污染内存，并触发**垃圾回收器**（**GC**）。关于性能和内存的内容将在第七章，*性能考量*中进行更详细的介绍。

我们必须更新我们的`Activity`的代码以设置这些新颜色：

```kt
public class MainActivity extends AppCompatActivity { 
    private static final int BRIGHT_GREEN = 0xff00ff00; 
    private static final int BRIGHT_RED = 0xffff0000; 
    private static final int BRIGHT_YELLOW = 0xffffff00; 
    private static final int BRIGHT_BLUE = 0xff0000ff; 

    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 

        LinearLayout linearLayout = new LinearLayout(this); 
        linearLayout.setLayoutParams( 
                new LinearLayout.LayoutParams(ViewGroup.
                LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT)); 

        OwnCustomView customView = new OwnCustomView(this); 
        customView.setTopLeftColor(BRIGHT_RED); 
        customView.setTopRightColor(BRIGHT_GREEN); 
        customView.setBottomLeftColor(BRIGHT_YELLOW); 
        customView.setBottomRightColor(BRIGHT_BLUE); 
        linearLayout.addView(customView); 
        setContentView(linearLayout); 
    } 
} 
```

如我们所见，我们使用了四个设置器来设置颜色。如果我们有更多参数，可以使用更多设置器，但这种方法的其中一个问题是，我们必须处理线程同步，并且对象可能在所有调用完成之前都处于不稳定状态。

另一个选择是将所有参数添加到构造函数中，但这也不是一个好的解决方案。它会使得我们的工作更加复杂，因为记住参数的顺序可能会很困难，或者在有可选参数的情况下，创建许多不同的构造函数或传递 null 引用，这会使我们的代码更难以阅读和维护。

在 GitHub 仓库的`Example06-BuilderPattern-NoBuilder`文件夹中查看此示例的完整源代码。

既然我们已经介绍了这个问题，让我们通过在自定义视图上实现`Builder`模式来解决它。我们从在自定义视图中创建一个`public static class`开始，它会按照以下方式构建视图：

```kt
public static class Builder { 
    private Context context; 
    private int topLeftColor = DEFAULT_FILL_COLOR; 
    private int topRightColor = DEFAULT_FILL_COLOR; 
    private int bottomLeftColor = DEFAULT_FILL_COLOR; 
    private int bottomRightColor = DEFAULT_FILL_COLOR; 

    public Builder(Context context) { 
        this.context = context; 
    } 

    public Builder topLeftColor(int topLeftColor) { 
        this.topLeftColor = topLeftColor; 
        return this; 
    } 

    public Builder topRightColor(int topRightColor) { 
        this.topRightColor = topRightColor; 
        return this; 
    } 

    public Builder bottomLeftColor(int bottomLeftColor) { 
        this.bottomLeftColor = bottomLeftColor; 
        return this; 
    } 

    public Builder bottomRightColor(int bottomRightColor) { 
        this.bottomRightColor = bottomRightColor; 
        return this; 
    } 

    public OwnCustomView build() { 
        return new OwnCustomView(this); 
    } 
} 
```

我们还创建了一个新的私有构造函数，它只接受一个`OwnCustomView.Builder`对象：

```kt
private OwnCustomView(Builder builder) { 
    super(builder.context); 

    backgroundPaint = new Paint(); 
    backgroundPaint.setStyle(Paint.Style.FILL); 

    colorArray = new int[] { 
            builder.topLeftColor, 
            builder.topRightColor, 
            builder.bottomRightColor, 
            builder.bottomLeftColor 
    }; 

    firstDraw = true; 
 } 
```

为了清晰起见，我们删除了其他构造函数。在这个阶段，我们还基于`builder`对象具有的颜色创建颜色数组，以及一个`boolean`来判断是否是第一次绘制。

这将有助于只实例化一次`LinearGradient`对象，避免创建许多实例：

```kt
@Override 
    protected void onDraw(Canvas canvas) { 
        if (firstDraw) { 
            LinearGradient lg = new LinearGradient(0, 0, getWidth(),
            getHeight(), 
                    colorArray, null, Shader.TileMode.CLAMP); 

            backgroundPaint.setShader(lg); 
            firstDraw = false; 
        } 

        canvas.drawRect(0, 0, getWidth(), getHeight(),
        backgroundPaint); 
        super.onDraw(canvas); 
    } 
```

现在，一旦创建了对象，我们就不能更改其颜色，但我们不需要担心线程同步和对象的状态。

为了使其工作，让我们也更新我们的`Activity`上的代码：

```kt
public class MainActivity extends AppCompatActivity { 
    private static final int BRIGHT_GREEN = 0xff00ff00; 
    private static final int BRIGHT_RED = 0xffff0000; 
    private static final int BRIGHT_YELLOW = 0xffffff00; 
    private static final int BRIGHT_BLUE = 0xff0000ff; 

    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 

        LinearLayout linearLayout = new LinearLayout(this); 
        linearLayout.setLayoutParams( 
                new LinearLayout.LayoutParams(ViewGroup.
                LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT)); 

        OwnCustomView customView = new OwnCustomView.Builder(this) 
                .topLeftColor(BRIGHT_RED) 
                .topRightColor(BRIGHT_GREEN) 
                .bottomLeftColor(BRIGHT_YELLOW) 
                .bottomRightColor(BRIGHT_BLUE) 
                .build(); 

        linearLayout.addView(customView); 

        setContentView(linearLayout); 
    } 
} 
```

使用`Builder`模式，我们的代码更清晰，当设置所有属性时构建或创建对象，如果自定义视图有更多参数，这将变得更加方便。

完整的示例源代码可以在 GitHub 仓库中的`Example07-BuilderPattern`文件夹中找到。

# 创建自定义布局

Android 提供了多种布局来以多种不同的方式定位我们的视图，但如果这些标准布局不适用于我们的特定用例，我们可以创建自己的布局。

# 扩展 ViewGroup

创建自定义布局的过程与创建自定义视图类似。我们需要创建一个从`ViewGroup`而不是视图继承的类，创建适当的构造函数，实现`onMeasure()`方法，并覆盖`onLayout()`方法，而不是`onDraw()`方法。

让我们创建一个非常简单的自定义布局；它会将元素添加到前一个元素的右侧，直到不适合屏幕，然后开始新的一行，使用较高的元素来计算新行的起始位置，并避免视图之间的任何重叠。

添加随机大小的视图，每个视图具有红色背景，将如下所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/62f2b38c-b67f-4150-b747-a33a9502534a.png)

首先，让我们创建一个从`ViewGroup`继承的类：

```kt
public class CustomLayout extends ViewGroup { 

    public CustomLayout(Context context, AttributeSet attrs) { 
        super(context, attrs); 
    } 

    @Override 
   protected void onLayout(boolean changed, int l, int t, int r, int b) { 

   } 
} 
```

我们创建了构造函数，并实现了`onLayout()`方法，因为这是一个抽象方法，我们必须实现它。让我们添加一些逻辑：

```kt
@Override 
   protected void onLayout(boolean changed, int l, int t, int r, int b){ 
        int count = getChildCount(); 
        int left = l + getPaddingLeft(); 
        int top = t + getPaddingTop(); 

        // keeps track of maximum row height 
        int rowHeight = 0; 

        for (int i = 0; i < count; i++) { 
            View child = getChildAt(i); 

            int childWidth = child.getMeasuredWidth(); 
            int childHeight = child.getMeasuredHeight(); 

            // if child fits in this row put it there 
            if (left + childWidth < r - getPaddingRight()) { 
                child.layout(left, top, left + childWidth, top +
                childHeight); 
                left += childWidth; 
        } else { 
            // otherwise put it on next row 
                left = l + getPaddingLeft(); 
                top += rowHeight; 
                rowHeight = 0; 
            } 

            // update maximum row height 
            if (childHeight > rowHeight) rowHeight = childHeight; 
        } 
    } 
```

这个逻辑实现了我们之前描述的内容；它试图将子项添加到前一个子项的右侧，如果不适合布局宽度，检查当前的`left`位置加上测量的子项宽度，它就会开始新的一行。`rowHeight`变量测量那一行上的较高视图。

让我们也实现`onMeasure()`方法：

```kt
@Override 
protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) { 

    int count = getChildCount(); 

    int rowHeight = 0; 
    int maxWidth = 0; 
    int maxHeight = 0; 
    int left = 0; 
    int top = 0; 

    for (int i = 0; i < count; i++) { 
        View child = getChildAt(i); 
        measureChild(child, widthMeasureSpec, heightMeasureSpec); 

        int childWidth = child.getMeasuredWidth(); 
        int childHeight = child.getMeasuredHeight(); 

        // if child fits in this row put it there 
        if (left + childWidth < getWidth()) { 
            left += childWidth; 
        } else { 
            // otherwise put it on next row 
            if(left > maxWidth) maxWidth = left; 
            left = 0; 
            top += rowHeight; 
            rowHeight = 0; 
        } 

        // update maximum row height 
        if (childHeight > rowHeight) rowHeight = childHeight; 
    } 

    if(left > maxWidth) maxWidth = left; 
    maxHeight = top + rowHeight; 

    setMeasuredDimension(getMeasure(widthMeasureSpec, maxWidth),
    getMeasure(heightMeasureSpec, maxHeight)); 

} 
```

逻辑与之前相同，但它没有布置其子项。它计算将需要的最大宽度和高度，然后在一个帮助方法的帮助下，根据宽度和高度测量规范设置此自定义布局的尺寸：

```kt
private int getMeasure(int spec, int desired) { 
        switch(MeasureSpec.getMode(spec)) { 
            case MeasureSpec.EXACTLY: 
                return MeasureSpec.getSize(spec); 

            case MeasureSpec.AT_MOST: 
                return Math.min(MeasureSpec.getSize(spec), desired); 

            case MeasureSpec.UNSPECIFIED: 
            default: 
                return desired; 
        } 
    } 
```

现在我们有了自定义布局，让我们将其添加到我们的`activity_main`布局中：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  

    android:id="@+id/activity_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:padding="@dimen/activity_vertical_margin" 
    tools:context="com.packt.rrafols.customview.MainActivity"> 

    <com.packt.rrafols.customview.CustomLayout 
        android:id="@+id/custom_layout" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent"> 

    </com.packt.rrafols.customview.CustomLayout> 
</RelativeLayout> 
```

在最后一步中，让我们添加一些随机大小的视图：

```kt
public class MainActivity extends AppCompatActivity { 
    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_main); 

        CustomLayout customLayout = (CustomLayout)
        findViewById(R.id.custom_layout); 

        Random rnd = new Random(); 
        for(int i = 0; i < 50; i++) { 
            OwnCustomView view = new OwnCustomView(this); 

            int width = rnd.nextInt(200) + 50; 
            int height = rnd.nextInt(100) + 100; 
            view.setLayoutParams(new ViewGroup.LayoutParams(width,
            height)); 
            view.setPadding(2, 2, 2, 2); 

            customLayout.addView(view); 
        } 
    } 
} 
```

在 GitHub 的`Example08-CustomLayout`文件夹中查看此示例的完整源代码。

在此页面上，我们还可以找到一个功能齐全的自定义布局的相当复杂的示例。

# 基本渲染

到目前为止，我们只绘制了纯色背景或线性渐变。这既不令人兴奋也没有实际用途。让我们看看如何绘制更有趣的形状和图元。我们将通过创建一个圆形活动指示器的示例来实现，在接下来的章节中，我们将在其中添加越来越多的功能。

# 创建基本的圆形活动指示器

`Canvas`类为我们提供了许多绘图函数；例如：

+   `drawArc()`

+   `drawBitmap()`

+   `drawOval()`

+   `drawPath()`

要绘制圆形活动指示器，我们可以使用`drawArc()`方法。让我们创建基本的类并绘制一个弧线：

```kt
public class CircularActivityIndicator extends View { 
    private static final int DEFAULT_FG_COLOR = 0xffff0000; 
    private static final int DEFAULT_BG_COLOR = 0xffa0a0a0; 
    private Paint foregroundPaint; 
    private int selectedAngle; 

    public CircularActivityIndicator(Context context, AttributeSet
    attributeSet) { 
        super(context, attributeSet); 

        foregroundPaint = new Paint(); 
        foregroundPaint.setColor(DEFAULT_FG_COLOR); 
        foregroundPaint.setStyle(Paint.Style.FILL); 

        selectedAngle = 280; 
    } 

    @Override 
    protected void onDraw(Canvas canvas) { 
        canvas.drawArc( 
                0, 
                0, 
                getWidth(), 
                getHeight(), 
                0, selectedAngle, true, foregroundPaint); 
    } 
} 
```

结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/2c9a946b-8846-4198-97c5-f5f935e32353.png)

让我们调整比例，使弧线的宽度与高度相同：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    int circleSize = getWidth(); 
    if (getHeight() < circleSize) circleSize = getHeight(); 

    int horMargin = (getWidth() - circleSize) / 2; 
    int verMargin = (getHeight() - circleSize) / 2; 

    canvas.drawArc( 
            horMargin, 
            verMargin, 
            horMargin + circleSize, 
            verMargin + circleSize, 
            0, selectedAngle, true, foregroundPaint); 
} 
```

我们将使用较小的尺寸，无论是宽度还是高度，并以正方形比例（宽度与高度相同）居中绘制弧线。

这看起来不像一个活动指示器；让我们改变它，只绘制弧线的一细带。我们可以通过使用`canvas`提供的剪裁功能来实现这一点。我们可以使用`canvas.clipRect`或`canvas.clipPath`，例如。使用剪裁方法时，我们还可以指定一个剪裁操作。如果我们不指定，默认情况下，它将与当前的剪裁相交。

为了只绘制一个细带，我们将在路径中创建一个较小的弧线，大小约为我们想要绘制的弧线的*75%*。然后，我们将它从整个视图的剪裁矩形中减去：

```kt
private Path clipPath; 

@Override 
protected void onDraw(Canvas canvas) { 
    int circleSize = getWidth(); 
    if (getHeight() < circleSize) circleSize = getHeight(); 

    int horMargin = (getWidth() - circleSize) / 2; 
    int verMargin = (getHeight() - circleSize) / 2; 

    // create a clipPath the first time 
    if(clipPath == null) { 
        int clipWidth = (int) (circleSize * 0.75); 

        int clipX = (getWidth() - clipWidth) / 2; 
        int clipY = (getHeight() - clipWidth) / 2; 
        clipPath = new Path(); 
        clipPath.addArc( 
                clipX, 
                clipY, 
                clipX + clipWidth, 
                clipY + clipWidth, 
                0, 360); 
    } 

    canvas.clipRect(0, 0, getWidth(), getHeight()); 
    canvas.clipPath(clipPath, Region.Op.DIFFERENCE); 

    canvas.drawArc( 
            horMargin, 
            verMargin, 
            horMargin + circleSize, 
            verMargin + circleSize, 
            0, selectedAngle, true, foregroundPaint); 
} 
```

在以下截图中，我们可以看到差异：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/6ac73a16-70b2-4c7a-87ea-d1feacd304a0.png)

作为最后的润色，让我们给弧线添加一个背景颜色，并将起始位置改为视图的顶部。

为了绘制背景，我们将在构造函数中添加以下代码来创建一个背景`Paint`：

```kt
backgroundPaint = new Paint(); 
backgroundPaint.setColor(DEFAULT_BG_COLOR); 
backgroundPaint.setStyle(Paint.Style.FILL); 
```

然后修改`onDraw()`方法，在实际绘制另一个弧线之前绘制它：

```kt
canvas.drawArc( 
        horMargin, 
        verMargin, 
        horMargin + circleSize, 
        verMargin + circleSize, 
        0, 360, true, backgroundPaint); 
```

作为一个小差异，我们绘制了整个`360`度，这样它将覆盖整个圆。

要改变弧线的起始位置，我们将旋转绘图操作。`Canvas`支持旋转、平移和矩阵变换。在这种情况下，我们只需逆时针旋转`90`度，就能使我们的起始点位于弧线的顶部：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    int circleSize = getWidth(); 
    if (getHeight() < circleSize) circleSize = getHeight(); 

    int horMargin = (getWidth() - circleSize) / 2; 
    int verMargin = (getHeight() - circleSize) / 2; 

    // create a clipPath the first time 
    if(clipPath == null) { 
        int clipWidth = (int) (circleSize * 0.75); 

        int clipX = (getWidth() - clipWidth) / 2; 
        int clipY = (getHeight() - clipWidth) / 2; 
        clipPath = new Path(); 
        clipPath.addArc( 
                clipX, 
                clipY, 
                clipX + clipWidth, 
                clipY + clipWidth, 
                0, 360); 
    } 

    canvas.clipRect(0, 0, getWidth(), getHeight()); 
    canvas.clipPath(clipPath, Region.Op.DIFFERENCE); 

    canvas.save(); 
    canvas.rotate(-90, getWidth() / 2, getHeight() / 2); 

    canvas.drawArc( 
            horMargin, 
            verMargin, 
            horMargin + circleSize, 
            verMargin + circleSize, 
            0, 360, true, backgroundPaint); 

    canvas.drawArc( 
            horMargin, 
            verMargin, 
            horMargin + circleSize, 
            verMargin + circleSize, 
            0, selectedAngle, true, foregroundPaint); 

    canvas.restore(); 
} 
```

我们还使用了`canvas.save()`和`canvas.restore()`来保存我们的`canvas`的状态；否则，每次绘制时它都会旋转`-90`度。当调用`canvas.rotate()`方法时，我们还指定了旋转的中心点，该中心点与屏幕的中心点以及弧线的中心点相匹配。

每当我们使用如`rotate`、`scale`或`translate`等`canvas`函数时，实际上我们是在对所有后续的`canvas`绘图操作应用变换。

最终结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/725dac60-6a60-4a79-8249-148e5a8cf8a4.png)

我们需要意识到的一件事是，并非所有的`canvas`操作在所有 Android 版本上都得到硬件支持。请检查您需要执行的操作是否受支持，或者为它们提供运行时解决方案。在以下链接中了解更多关于哪些操作是硬件加速的信息：

[`developer.android.com/guide/topics/graphics/hardware-accel.html`](https://developer.android.com/guide/topics/graphics/hardware-accel.html)。

这是类的最终实现代码：

```kt
public class CircularActivityIndicator extends View { 
    private static final int DEFAULT_FG_COLOR = 0xffff0000; 
    private static final int DEFAULT_BG_COLOR = 0xffa0a0a0; 
    private Paint backgroundPaint; 
    private Paint foregroundPaint; 
    private int selectedAngle; 
    private Path clipPath; 

    public CircularActivityIndicator(Context context, AttributeSet
        attributeSet) { 
        super(context, attributeSet); 

        backgroundPaint = new Paint(); 
        backgroundPaint.setColor(DEFAULT_BG_COLOR); 
        backgroundPaint.setStyle(Paint.Style.FILL); 

        foregroundPaint = new Paint(); 
        foregroundPaint.setColor(DEFAULT_FG_COLOR); 
        foregroundPaint.setStyle(Paint.Style.FILL); 

        selectedAngle = 280; 
    } 

    @Override 
    protected void onDraw(Canvas canvas) { 
        int circleSize = getWidth(); 
        if (getHeight() < circleSize) circleSize = getHeight(); 

        int horMargin = (getWidth() - circleSize) / 2; 
        int verMargin = (getHeight() - circleSize) / 2; 

        // create a clipPath the first time 
        if(clipPath == null) { 
            int clipWidth = (int) (circleSize * 0.75); 

            int clipX = (getWidth() - clipWidth) / 2; 
            int clipY = (getHeight() - clipWidth) / 2; 
            clipPath = new Path(); 
            clipPath.addArc( 
                    clipX, 
                    clipY, 
                    clipX + clipWidth, 
                    clipY + clipWidth, 
                    0, 360); 
        } 

        canvas.clipPath(clipPath, Region.Op.DIFFERENCE); 

        canvas.save(); 
        canvas.rotate(-90, getWidth() / 2, getHeight() / 2); 

        canvas.drawArc( 
                horMargin, 
                verMargin, 
                horMargin + circleSize, 
                verMargin + circleSize, 
                0, 360, true, backgroundPaint); 

        canvas.drawArc( 
                horMargin, 
                verMargin, 
                horMargin + circleSize, 
                verMargin + circleSize, 
                0, selectedAngle, true, foregroundPaint); 

        canvas.restore(); 
    } 
} 
```

整个示例源代码可以在 GitHub 仓库中的`Example09-BasicRendering`文件夹中找到。

此外，我在 2015 年 1 月在克拉科夫的 Android 开发者后台关于这个话题进行了演讲；以下是演讲的链接：

[`www.slideshare.net/RaimonRls/android-custom-views-72600098`](https://www.slideshare.net/RaimonRls/android-custom-views-72600098)。

# 总结

在本章中，我们学习了如何测量以及如何为自定义视图添加参数。我们还了解了如何从代码中实例化自定义视图，并使用`Builder`模式来简化所有参数，使代码保持整洁。此外，我们还快速通过一个自定义布局的示例，并开始构建圆形活动指示器。在下一章中，我们将学习如何处理事件并为刚刚开始构建的圆形活动指示器添加一些交互。


# 第三章：事件处理

现在我们已经了解了画布绘图的基础知识，并且我们的自定义视图已经适应了其大小，是时候与它进行交互了。许多自定义视图只需要以特定方式绘制某些内容；这就是我们创建它们为自定义视图的原因，但还有许多其他视图需要响应用户事件。例如，当用户在我们的自定义视图上点击或拖动时，它将如何表现？

为了回答这些问题，我们将在本章中详细介绍以下内容：

+   基本事件处理

+   高级事件处理

# 基本事件处理

让我们从为我们的自定义视图添加一些基本事件处理开始。我们将介绍基础知识，稍后我们将添加更复杂的事件。

# 响应触摸事件

为了使我们的自定义视图具有交互性，我们首先要实现的是处理并响应用户的触摸事件，或者基本上，当用户在我们的自定义视图上触摸或拖动时。

安卓提供了`onTouchEvent()`方法，我们可以在自定义视图中重写它。通过重写这个方法，我们将获取到发生在其上的任何触摸事件。为了了解它是如何工作的，让我们将它添加到上一章构建的自定义视图中：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    Log.d(TAG, "touch: " + event); 
    return super.onTouchEvent(event); 
} 
```

同时让我们添加一个日志调用，以查看我们接收的事件。如果我们运行此代码并在视图上触摸，我们将得到以下结果：

```kt
D/com.packt.rrafols.customview.CircularActivityIndicator: touch: MotionEvent { action=ACTION_DOWN, actionButton=0, id[0]=0, x[0]=644.3645, y[0]=596.55804, toolType[0]=TOOL_TYPE_FINGER, buttonState=0, metaState=0, flags=0x0, edgeFlags=0x0, pointerCount=1, historySize=0, eventTime=30656461, downTime=30656461, deviceId=9, source=0x1002 }
```

如我们所见，事件上有许多信息，如坐标、动作类型和时间，但即使我们对它执行更多操作，我们也只会收到`ACTION_DOWN`事件。这是因为视图的默认实现不是可点击的。默认情况下，如果我们不在视图上启用可点击标志，`onTouchEvent()`的默认实现将返回 false 并忽略进一步的事件。

`onTouchEvent()`方法必须返回`true`如果事件已经被处理，或者返回`false`如果还没有。如果我们在自定义视图中接收到一个事件，而我们不知道该如何处理或者对此类事件不感兴趣，我们应该返回`false`，这样它就可以由我们视图的父视图或其他组件或系统来处理。

为了接收更多类型的事件，我们可以做两件事：

+   使用`setClickable(true)`将视图设置为可点击

+   在我们自己的类中实现逻辑并处理事件

稍后，我们将实现更复杂的事件；我们将选择第二个选项。

让我们进行一个快速测试，将方法更改为只返回 true，而不是调用父方法：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    Log.d(TAG, "touch: " + event); 
    return true; 
} 
```

现在，我们应该能够接收许多其他类型的事件，如下所示：

```kt
...CircularActivityIndicator: touch: MotionEvent { action=ACTION_DOWN, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_UP, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_DOWN, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_MOVE, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_MOVE, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_MOVE, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_UP, ...CircularActivityIndicator: touch: MotionEvent { action=ACTION_DOWN,
```

如前一个示例所示，我们可以看到在之前的日志中，我们不仅拥有`ACTION_DOWN`和`ACTION_UP`，还有`ACTION_MOVE`来表示我们在视图上执行了拖动操作。

我们首先关注处理`ACTION_UP`和`ACTION_DOWN`事件。让我们添加一个名为`boolean`的变量，该变量将跟踪我们当前是否正在按或触摸我们的视图：

```kt
private boolean pressed; 

public CircularActivityIndicator(Context context, AttributeSet attributeSet) { 
    ... 
    ... 
    pressed = false; 
} 
```

我们添加了变量，并将其默认状态设置为`false`，因为视图在创建时不会被按压。现在，让我们在我们的`onTouchEvent()`实现中添加代码来处理这个问题：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    Log.d(TAG, "touch: " + event); 
    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            pressed = true; 
            return true; 

        case MotionEvent.ACTION_UP: 
            pressed = false; 
            return true; 

        default: 
            return false; 
    } 
} 
```

我们处理了`MotionEvent`。`ACTION_DOWN`和`MotionEvent.ACTION_UP`事件；我们在这里收到的任何其他动作，我们都会忽略并返回`false`，因为我们没有处理它。

好的，现在我们有一个变量来跟踪我们是否正在按压视图，但我们还应该做其他事情，否则这个变量不会很有用。让我们修改`onDraw()`方法，当视图被按压时，以不同的颜色绘制圆形：

```kt
private static final int DEFAULT_FG_COLOR = 0xffff0000; 
private static final int PRESSED_FG_COLOR = 0xff0000ff; 

@Override 
protected void onDraw(Canvas canvas) { 
    if (pressed) { 
        foregroundPaint.setColor(PRESSED_FG_COLOR); 
    } else { 
        foregroundPaint.setColor(DEFAULT_FG_COLOR); 
    } 
```

如果我们运行这个例子并触摸我们的视图，我们会发现什么都没有发生！问题是什么？我们没有触发任何重绘事件，视图也没有再次被绘制。如果我们设法持续按压视图，并将应用放到后台然后再返回前台，我们就能看到这段代码是有效的。然而，为了正确地处理，当我们更改需要重新绘制视图的内容时，我们应该触发一个重绘事件，如下所示：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    Log.d(TAG, "touch: " + event); 
    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            pressed = true; 
            invalidate(); 
            return true; 

        case MotionEvent.ACTION_UP: 
            pressed = false; 
            invalidate(); 
            return true; 

        default: 
            pressed = false; 
            invalidate(); 
            return false; 
    } 
} 
```

好的，这应该能解决问题！调用 invalidate 方法将在未来触发一个`onDraw()`方法的调用：

[`developer.android.com/reference/android/view/View.html#invalidate()`](https://developer.android.com/reference/android/view/View.html#invalidate())。

我们现在可以重构这段代码，并将其移动到一个方法中：

```kt
private void changePressedState(boolean pressed) { 
    this.pressed = pressed; 
    invalidate(); 
} 

@Override 
public boolean onTouchEvent(MotionEvent event) { 
    Log.d(TAG, "touch: " + event); 
    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            changePressedState(true); 
            return true; 

        case MotionEvent.ACTION_UP: 
            changePressedState(false); 
            return true; 

        default: 
            changePressedState(false); 
            return false; 
    } 
} 
```

我们需要知道 invalidate 必须在 UI 线程中调用，如果从其他线程调用将会抛出异常。如果我们需要从另一个线程调用它，例如，在从网络服务接收到一些数据后更新视图，我们应该调用`postInvalidate()`。

这是结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/2dc0bea6-a89d-419d-89a7-25935dad6ba3.png)

# 拖动事件

既然我们已经对`ACTION_DOWN`和`ACTION_UP`事件做出了反应，我们将通过也对`ACTION_MOVE`事件做出反应来增加一点复杂性。

让我们根据在两个方向上拖动的距离来更新角度。为此，我们需要存储用户最初按压的位置，因此我们将用`ACTION_DOWN`事件中的`X`和`Y`坐标来存储变量`lastX`和`lastY`。

当我们收到一个`ACTION_MOVE`事件时，我们计算`lastX`和`lastY`坐标与事件中收到的当前值之间的差。我们用`X`和`Y`差值的平均值来更新`selectedAngle`，并最终更新`lastX`和`lastY`坐标。我们必须记得调用 invalidate，否则我们的视图将不会被重绘：

```kt
private float lastX, lastY; 

@Override 
public boolean onTouchEvent(MotionEvent event) { 
    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            changePressedState(true); 

            lastX = event.getX(); 
            lastY = event.getY(); 
            return true; 

        case MotionEvent.ACTION_UP: 
            changePressedState(false); 
            return true; 

        case MotionEvent.ACTION_MOVE: 
            float dragX = event.getX(); 
            float dragY = event.getY(); 

            float dx = dragX - lastX; 
            float dy = dragY - lastY; 

            selectedAngle += (dx + dy) / 2; 

            lastX = dragX; 
            lastY = dragY; 

            invalidate(); 
            return true; 

        default: 
            return false; 
    } 
} 
```

这种移动可能感觉有点不自然，所以如果我们希望圆的角度跟随我们实际按压的位置，我们应该从笛卡尔坐标转换为极坐标：

[`en.wikipedia.org/wiki/List_of_common_coordinate_transformations`](https://en.wikipedia.org/wiki/List_of_common_coordinate_transformations)。

进行此更改后，无需跟踪先前坐标，因此我们可以用以下代码替换我们的代码：

```kt
private int computeAngle(float x, float y) { 
    x -= getWidth() / 2; 
    y -= getHeight() / 2; 

    int angle = (int) (180.0 * Math.atan2(y, x) / Math.PI) + 90; 
    return (angle > 0) ? angle : 360 + angle; 
} 

@Override 
public boolean onTouchEvent(MotionEvent event) { 
    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            selectedAngle = computeAngle(event.getX(), event.getY()); 
            changePressedState(true); 
            return true; 

        case MotionEvent.ACTION_UP: 
            changePressedState(false); 
            return true; 

        case MotionEvent.ACTION_MOVE: 
            selectedAngle = computeAngle(event.getX(), event.getY()); 
            invalidate(); 
            return true; 

        default: 
            return false; 
    } 
} 
```

# 复杂布局

到目前为止，我们已经了解了如何在自定义视图上管理`onTouchEvent()`事件，但这仅适用于占据整个屏幕大小的视图，因此这是一个相对简单的处理方式。如果我们想在也处理触摸事件的`ViewGroup`中包含我们的视图，例如`ScrollView`，我们需要做哪些更改？

让我们更改这个布局：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  

    android:id="@+id/activity_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:padding="@dimen/activity_vertical_margin" 
    tools:context="com.packt.rrafols.customview.MainActivity"> 

    <ScrollView 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:layout_alignParentTop="true" 
        android:layout_alignParentStart="true" 
        android:layout_marginTop="13dp"> 

        <LinearLayout 
            android:layout_width="match_parent" 
            android:layout_height="wrap_content" 
            android:orientation="vertical"> 

            <TextView 
                android:layout_width="match_parent" 
                android:layout_height="wrap_content" 
                android:paddingTop="100dp" 
                android:paddingBottom="100dp" 
                android:text="Top" 
                android:background="@color/colorPrimaryDark" 
                android:textColor="@android:color/white" 
                android:gravity="center"/> 

            <com.packt.rrafols.customview.CircularActivityIndicator 
                android:layout_width="match_parent" 
                android:layout_height="300dp"/> 

            <TextView 
                android:layout_width="match_parent" 
                android:layout_height="wrap_content" 
                android:paddingTop="100dp" 
                android:paddingBottom="100dp" 
                android:text="Bottom" 
                android:background="@color/colorPrimaryDark" 
                android:textColor="@android:color/white" 
                android:gravity="center"/> 
        </LinearLayout> 
    </ScrollView> 
</RelativeLayout> 
```

基本上，我们把自定义视图放在了`ScrollView`中，这样两者都可以处理事件。我们应该选择哪些事件由我们的视图处理，哪些事件由`ScrollView`处理。

为了实现这一点，视图为我们提供了`getParent()`方法，以获取其父视图：

[关于`ViewParent`的 Android 官方文档](https://developer.android.com/reference/android/view/ViewParent.html)。

一旦我们有了父视图，就可以调用`requestDisallowInterceptTouchEvent`来禁止父视图及其父视图拦截触摸事件。此外，为了只消耗我们感兴趣的事件，我们添加了一个检查，以查看用户触摸的位置是否在圆的半径内或外部。如果触摸在外部，我们将忽略该事件并不处理。

```kt
private boolean computeAndSetAngle(float x, float y) { 
    x -= getWidth() / 2; 
    y -= getHeight() / 2; 

    double radius = Math.sqrt(x * x + y * y); 
    if(radius > circleSize/2) return false; 

    int angle = (int) (180.0 * Math.atan2(y, x) / Math.PI) + 90; 
    selectedAngle = ((angle > 0) ? angle : 360 + angle); 
    return true; 
} 

@Override 
public boolean onTouchEvent(MotionEvent event) { 
    boolean processed; 

    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            processed = computeAndSetAngle(event.getX(), event.getY()); 
            if(processed) { 
                getParent().requestDisallowInterceptTouchEvent(true); 
                changePressedState(true); 
            } 
            return processed; 

        case MotionEvent.ACTION_UP: 
            getParent().requestDisallowInterceptTouchEvent(false); 
            changePressedState(false); 
            return true; 

        case MotionEvent.ACTION_MOVE: 
            processed = computeAndSetAngle(event.getX(), event.getY()); 
            invalidate(); 
            return processed; 

        default: 
            return false; 
    } 
} 
```

我们通过应用之前使用的相同笛卡尔极坐标变换来计算半径。我们还更改了代码，所以如果触摸点在圆的半径内，我们会在`ACTION_DOWN`事件上调用`getParent().requestDisallowInterceptTouchEvent(true)`，告诉`ViewParent`不要拦截触摸事件。我们需要在`ACTION_UP`事件上调用相反的`getParent().requestDisallowInterceptTouchEvent(false)`来撤销这个动作。

这是此更改的结果，我们可以看到自定义视图顶部和底部各有一个`TextView`：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/5031ea4d-f7c8-4a23-91e7-aed43739b00d.png)

现在如果我们触摸圆圈，我们的自定义视图将只处理事件并改变圆圈的角度。另一方面，如果触摸圆圈外部，我们将让`ScrollView`处理这些事件。

变化并不多，但是当我们构建一个可能会在多个地方重复使用的自定义视图时，我们绝对应该在多种布局配置中测试它，以了解其表现如何。

在 GitHub 仓库的`Example10-Events`文件夹中找到此示例的完整源代码。

# 高级事件处理

我们已经了解了如何处理`onTouchEvent()`，但我们还可以检测一些**手势**或更复杂的交互。Android 为我们提供了`GestureDetector`来帮助检测一些手势。支持库中甚至还有一个`GestureDetectorCompat`，用于为旧版本的 Android 提供支持。

有关`GestureDetector`的更多信息，请查看 Android 文档。

# 检测手势

让我们改变我们一直在构建的代码，以使用`GestureDetector`。我们还将使用`Scroller`实现来在值之间平滑滚动。我们可以修改构造函数以创建`Scroller`对象和实现了`GestureDetector.OnGestureListener`的`GestureDetector`：

```kt
private GestureDetector gestureListener; 
private Scroller angleScroller; 

public CircularActivityIndicator(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    ... 

    selectedAngle = 280; 
    pressed = false; 

    angleScroller = new Scroller(context, null, true); 
    angleScroller.setFinalX(selectedAngle); 

    gestureListener = new GestureDetector(context, new
    GestureDetector.OnGestureListener() { 
       boolean processed; 

       @Override 
       public boolean onDown(MotionEvent event) { 
           processed = computeAndSetAngle(event.getX(), event.getY()); 
           if (processed) { 
               getParent().requestDisallowInterceptTouchEvent(true); 
               changePressedState(true); 
               postInvalidate(); 
           } 
           return processed; 
       } 

       @Override 
       public void onShowPress(MotionEvent e) { 

       } 

       @Override 
       public boolean onSingleTapUp(MotionEvent e) { 
           endGesture(); 
           return false; 
       } 

       @Override 
       public boolean onScroll(MotionEvent e1, MotionEvent e2, float
       distanceX, float distanceY) { 
           computeAndSetAngle(e2.getX(), e2.getY()); 
           postInvalidate(); 
           return true; 
       } 

       @Override 
       public void onLongPress(MotionEvent e) { 
           endGesture(); 
       } 

       @Override 
       public boolean onFling(MotionEvent e1, MotionEvent e2, float
       velocityX, float velocityY) { 
           return false; 
       } 
   }); 
} 
```

这个接口中有许多回调方法，但首先，为了处理手势，我们需要在`onDown()`回调中返回 true；否则，我们表明不会进一步处理事件链。

现在我们简化了`onTouchEvent()`，因为它只需将事件简单地转发给`gestureListener`：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    return gestureListener.onTouchEvent(event); 
} 
```

因为我们可能有不同的手势，如长按、抛掷、滚动，所以我们创建了一个方法来结束手势并恢复状态：

```kt
private void endGesture() { 
    getParent().requestDisallowInterceptTouchEvent(false); 
    changePressedState(false); 
    postInvalidate(); 
} 
```

我们修改了`computeAndSetAngle()`方法以使用`Scroller`：

```kt
private boolean computeAndSetAngle(float x, float y) { 
    x -= getWidth() / 2; 
    y -= getHeight() / 2; 

    double radius = Math.sqrt(x * x + y * y); 
    if(radius > circleSize/2) return false; 

    int angle = (int) (180.0 * Math.atan2(y, x) / Math.PI) + 90; 
    angle = ((angle > 0) ? angle : 360 + angle); 

    if(angleScroller.computeScrollOffset()) { 
        angleScroller.forceFinished(true); 
    } 

    angleScroller.startScroll(angleScroller.getCurrX(), 0, angle -
    angleScroller.getCurrX(), 0); 
    return true; 
} 
```

`Scroller`实例将动画化这些值；我们需要不断检查更新的值以执行动画。一种实现方法是，在`onDraw()`方法中检查动画是否完成，并在动画未完成时触发失效以重新绘制视图：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    boolean notFinished = angleScroller.computeScrollOffset(); 
    selectedAngle = angleScroller.getCurrX(); 

    ... 

    if (notFinished) invalidate(); 
} 
```

`computeScrollOffset()`方法会在`Scroller`还未到达终点时返回 true；在调用它之后，我们可以使用`getCurrX()`方法查询滚动值。在这个例子中，我们正在动画化圆的角度值，但我们使用`Scroller`的`X`坐标来驱动这个动画。

使用这个`GestureDetector`，我们还可以检测长按和抛掷等手势。由于抛掷涉及更多动画，我们将在本书的下一章中进行介绍。

有关如何使视图具有交互性的更多信息，请参考：

[在 Android 开发者网站上了解如何使视图具有交互性](https://developer.android.com/training/custom-views/making-interactive.html)。

本例的源代码可以在 GitHub 仓库的`Example11-Events`文件夹中找到。

# 总结

在本章中，我们学习了如何与自定义视图进行交互。构建自定义视图的部分强大功能在于能够与它们互动并使它们具有交互性。我们也了解了如何简单地响应触摸和释放事件，如何拖动元素以及计算拖动事件之间的增量距离，最后学习了如何使用`GestureDetector`。

由于到目前为止渲染保持相当简单，我们将在下一章重点介绍使我们的渲染更加复杂并使用更多的绘图原语。
