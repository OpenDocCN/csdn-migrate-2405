# Sencha Touch2 JavaScript 移动框架（一）

> 原文：[`zh.annas-archive.org/md5/04504CE3000052C183ADF069B1AD3206`](https://zh.annas-archive.org/md5/04504CE3000052C183ADF069B1AD3206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

自首次发布以来，Sencha Touch 迅速成为开发基于 HTML5 的丰富移动网络应用的黄金标准。Sencha Touch 是第一个允许你在 iPhone、Android、BlackBerry 和 Windows Phone 触摸屏设备上开发看起来和感觉都像本地应用的 HTML5 移动 JavaScript 框架。Sencha Touch 是世界上第一个专门利用 HTML5、CSS3 和 JavaScript 构建最高水平的力量、灵活性和优化的应用程序框架。它专门使用 HTML5 来提供如音频和视频以及本地存储代理等组件，以便离线保存数据。Sencha Touch 在其组件和主题中广泛使用 CSS3，提供一个极其健壮的样式层，让你完全控制应用的外观。

Sencha Touch 让你能够为多个平台设计，而无需学习多种神秘的编程语言。相反，你可以利用你对 HTML 和 CSS 的现有知识，用 JavaScript 快速创建适用于移动设备的丰富网络应用。本书将向你展示如何使用 Sencha Touch 高效地制作吸引人、令人兴奋且易于使用的网络应用，从而让你的访客不断回访。

Sencha Touch 移动 JavaScript 框架教你所有开始使用 Sencha Touch 和构建绝妙的移动网络应用所需的知识。从对 Sencha Touch 的概述开始，本书将引导你创建一个完整的简单应用，然后是用户界面的样式设计，并通过综合示例解释 Sencha Touch 组件列表。接下来，你将学习关于触摸和组件事件的必要知识，这将帮助你创建丰富的动态动画。随后，本书提供有关核心数据包的信息以及处理数据的内容，并以构建另一个简单但强大的 Sencha Touch 应用作为结尾。

简而言之，本书采用逐步讲解和丰富内容，让初学者轻松快速地成为 Sencha Touch 高手。

利用 Sencha Touch，一个针对下一代触摸设备的多平台库。

# 本书涵盖内容

第一章，*用 Sencha Touch 开始*，概述了 Sencha Touch 并介绍了设置开发库的基础知识。我们还将讨论编程框架以及它们如何帮助你快速轻松地开发触摸友好的应用。

第二章，*创建一个简单应用*，首先通过创建一个简单应用来探索 Sencha Touch 的基本元素。我们还将探讨一些更常见的组件，如列表和面板，并指导你如何查找并修复常见错误。

（-   ）第三章，*用户界面样式*，探讨了在我们有了简单的应用程序之后，如何使用 CSS 样式来改变个别组件的外观和感觉。然后我们将深入探讨如何使用 Sencha Touch 主题，通过 SASS 和 Compass 来控制整个应用程序的外观。

（-   ）第四章，*组件和配置*，详细介绍了 Sencha Touch 的个别组件。我们还将讨论每个组件中的布局使用，以及它们如何用于安排应用程序的不同部分。

（-   ）第五章，*事件和控制器*，帮助我们查看 Sencha Touch 事件系统，该系统允许这些组件对用户的触摸做出反应并与彼此通信。我们将涵盖监听器和处理器的使用，并探讨如何监视和观察事件，以便我们可以看到我们应用程序的每个部分正在做什么。

（-   ）第六章，*获取数据*，解释了使用表单从用户那里获取信息、验证数据的方法，以及如何存储数据的细节，因为数据是任何应用程序的关键部分。我们还将讨论 Sencha Touch 使用的不同数据格式，以及如何使用 Sencha Touch 的模型和存储来操作这些数据。

（-   ）第七章，*获取数据出去*，将讨论使用面板和 XTemplates 来显示数据，因为在我们应用程序中有数据之后，我们需要能够将其取回以显示给用户。我们还将查看如何使用我们的数据创建多彩的图表和图形，使用 Sencha Touch 图表。

（-   ）第八章，*创建 Flickr 查找器应用程序*，创建了一个更复杂的应用程序，它基于我们当前的位置从 Flickr 获取照片，使用了我们所学的关于 Sencha Touch 的信息。我们还将借此机会讨论最佳实践，以结构化和组织您的应用程序及其文件。

（-   ）第九章，*高级主题*，探讨了如何通过创建自己的 API 来将您的数据与数据库服务器同步。此外，我们还将查看如何在大设备与数据库服务器之间同步数据，将您的应用程序与 Phone Gap 和 NimbleKit 编译。我们还将探讨如何开始成为 Apple iOS 或 Google Android 开发者。

# （-   ）本书所需材料

（-   ）为了完成本书中的任务，您需要一台计算机，配备以下物品：

+   Sencha Touch 2.1.x

+   （-   ）Sencha Cmd 3.1.x 或更高版本

+   （-   ）像 BBEdit、Text Wrangler、UltraEdit、TextMate、WebStorm、Aptana 或 Eclipse 这样的编程编辑器

+   例如内置的苹果 OSX 网络服务器、微软内置的 IIS 服务器，或者可下载的 WAMP 服务器和软件包等本地的网络服务器。

这些项目的链接在 *设置您的开发环境* 部分提供，位于 第一章，*让我们从 Sencha Touch 开始*。当需要时，其他可选但有助于帮助的软件将在特定章节中链接。

# 本书适合哪些人

如果您想掌握使用 Sencha Touch 移动网络应用程序框架的实践知识，制作适用于移动设备的吸引人的网络应用程序，这本书非常适合您。您应该对 HTML 和 CSS 有些熟悉。如果您是设计师，这本书将为您提供实现想法的技能；如果您是开发者，这本书将通过实际示例为您提供创意灵感。我们假定您知道如何使用触摸屏、触摸事件和移动设备，如苹果 iOS、谷歌 Android、黑莓和 Windows Phone。

# 约定

在这本书中，您会找到多种文本样式，用以区分不同类型的信息。以下是一些这些样式的示例及其含义解释。

文本中的代码词汇显示如下：“顶部标题还列出了组件紧邻的 `xtype` 值。”

代码块设置如下：

```js
var nestedList = Ext.create('Ext.NestedList', {
    fullscreen: true,
    title: 'Minions',
    displayField: 'text',
    store: store
});
```

当我们希望引起您对代码块中特定部分的关注时，相关的行或项目将被加粗：

```js
<img src="img/my-big-image.jpg">
```

任何命令行输入或输出都如下所示：

```js
C:\Ruby192>ruby -v
ruby 1.9.2p180 (2011-02-18) [i386-mingw32]

```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词汇，例如在菜单或对话框中出现的词汇，在文中会以这种方式显示：“还有一个 **选择代码** 选项，让您复制代码并将其粘贴到您自己的应用程序中。”

### 注意

警告或重要说明会以这种盒子形式出现。

### 提示

技巧和小窍门会以这种方式出现。

# 读者反馈

我们总是欢迎来自读者的反馈。告诉我们您对这本书的看法——您喜欢什么或者可能不喜欢什么。读者反馈对我们来说非常重要，以便我们开发出您能真正从中获益的标题。

如果您想发送一般性反馈，只需发送电子邮件至 `<feedback@packtpub.com>`，并在消息主题中提及书籍标题。

如果您在某个主题上有专业知识，并且对撰写或贡献书籍感兴趣，请查看我们在 [www.packtpub.com/authors](http://www.packtpub.com/authors) 上的作者指南。

# 客户支持

既然您已经成为 Packt 书籍的自豪拥有者，我们就有一系列的事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的账户上下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了此书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

## 错误

虽然我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——如果您能将这些错误报告给我们，我们将非常感激。这样做可以避免其他读者感到沮丧，并帮助我们改进此书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击**错误提交表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，并且错误将会上传到我们的网站，或者添加到该标题下的现有错误列表中。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看现有的错误。

## 盗版

互联网上版权材料的盗版是一个持续存在的问题，所有媒体都受到影响。在 Packt，我们对保护我们的版权和许可非常重视。如果您在互联网上发现我们作品的任何非法副本，无论以何种形式，请立即提供给我们地址或网站名称，以便我们可以寻求补救措施。

请通过`<copyright@packtpub.com>`联系我们，附上涉嫌侵权材料的链接。

我们感激您在保护我们的作者和我们的能力，带来有价值的内容方面所提供的帮助。

## 问题

如果您在阅读书籍过程中遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽最大努力解决问题。


# 第一章：让我们从 Sencha Touch 开始

随着移动设备、手机和平板电脑的日益普及，消费者迅速转向接受触摸屏操作系统和应用程序。这种普及为开发者提供了丰富的平台选择：苹果的 iOS（包括 iPhone、iPod Touch 和 iPad）、谷歌的 Android、Windows 7 移动版以及更多。不幸的是，这种丰富的平台选择带来了同样丰富的编程语言选择。选择任何单一的语言往往让你锁定使用特定的平台或设备。

Sencha Touch 通过提供基于 JavaScript、HTML5 和 CSS 的框架消除了这一障碍。这些标准得到了大多数现代浏览器和移动设备的支持。使用基于这些标准的框架，你可以将应用部署到多个平台，而无需完全重写你的代码。

本书将帮助你熟悉 Sencha Touch，从基本设置到构建复杂应用。我们还将涵盖一些框架和触摸屏应用的基础知识，并提供如何设置你的开发环境和以多种不同方式部署应用的技巧。

在本章中，我们将介绍以下主题：

+   框架

+   移动应用框架

+   为 Sencha Touch 设计应用

+   开始使用 Sencha Touch

+   设置你的开发环境

+   使用 Sencha Touch 开发应用程序的其他工具

# 框架

框架是一组可重用的代码，提供一组对象和函数，你可以使用它们来为构建应用程序提供一个起点。框架的主要目标是让你在每次构建应用程序时避免重新发明轮子。

编写良好的框架通过提供一定程度的一致性并轻轻地推动你遵循标准实践，也有助于提高可重用性。这种一致性还使框架更容易学习。可重用性和易于学习的两个关键编程概念是**对象**和**继承**。

大多数像 Sencha Touch 这样的框架都是围绕**面向对象编程**风格（也称为**OOP**）构建的。OOP 背后的想法是，代码是围绕简单的基对象设计的。基对象将有一些它可以执行的属性和函数。

例如，假设我们有一个名为`wheeledVehicle`的对象。我们的`wheeledVehicle`对象有几个如下列出的属性：

+   一个或多个轮子

+   一个或多个座位

+   转向装置

它还有一些如下列出的功能：

+   `moveForward`

+   `moveBackward`

+   `moveLeft`

+   `moveRight`

+   `stop`

这是我们基本的对象。一旦创建了基本对象，我们就可以扩展它以添加更多功能和属性。这允许我们创建更复杂的对象，如自行车、摩托车、汽车、卡车、公共汽车等。这些复杂对象比我们的基本车轮对象多得多，但它们也继承了原始对象的属性和能力。

我们甚至可以覆盖原始函数，例如如果需要，可以让我们的`moveForward`函数比自行车更快地运行。这意味着我们可以构建许多不同的`wheeledVehicles`实例，而无需重新创建我们的原始工作。我们甚至可以构建更复杂的对象。例如，一旦我们有了一个通用的汽车，我们只需添加特定模型的新的属性和函数，就可以从大众汽车到法拉利汽车构建出各种车型。

Sencha Touch 也是基于**面向对象编程（OOP）**的概念。让我们以 Sencha Touch 中的一个例子来说明。在 Sencha Touch 中，我们有一个简单的对象叫做`container`。

`container`对象是 Sencha Touch 的基本构建模块之一，如其名称所示，它用于包含应用程序视觉区域中的其他项目。其他视觉类，如面板、工具栏和表单面板，都扩展了`container`类。组件类有许多配置项，用于控制简单事物，例如以下内容：

+   `height`

+   `width`

+   `padding`

+   `margin`

+   `border`

配置选项还可以定义更复杂的行为，例如以下内容：

+   `layout`: 此选项用于确定容器中项目的位置。

+   `listeners`: 此选项用于确定容器应该关注哪些事件以及听到事件时应该做什么。

`component`对象拥有一些用于控制其行为和配置的方法。一些简单方法的示例如下：

+   `show`

+   `hide`

+   `enable`

+   `disable`

+   `setHeight`

+   `setWidth`

它还支持更复杂的方法，例如以下内容：

+   `query`: 此操作用于在容器内搜索特定项目。

+   `update`: 此操作用于更新容器中的 HTML 或数据内容。

容器有一些属性和事件可供使用和监听。例如，您可以监听以下事件：

+   `show`

+   `hide`

+   `initialize`

+   `resize`

基本的`container`对象是 Sencha Touch 中的一个构建块，用于创建其他视觉对象，如面板、标签页、工具栏、表单面板和表单字段。这些子对象或**子**对象继承了容器对象（**父**对象）的所有属性和能力。它们将包括相同的高度、宽度等配置选项，并且知道如何执行容器可以执行的所有操作：显示、隐藏等。

这些子对象也将有额外的、独特的配置和方法。例如，按钮有一个额外的`text`属性，用于设置它们的标题，当用户轻触按钮时，按钮会发出通知。通过扩展原始对象，创建按钮的人只需要为这些额外的配置和方法编写代码。

从编程角度来看，对象和继承使得我们可以复用大量的工作。这也意味着当我们遇到一个新的框架，如 Sencha Touch 时，我们可以利用我们对基本代码对象的学习来快速理解更复杂的对象。

## 构建基础

除了提供可复用性，框架还为您提供了一组核心对象和函数，通常用于构建应用程序。这使得您不需要每次开始一个新应用程序时都从头开始。

这些代码对象通常处理用户输入、操作或查看数据的大部分方式。它们还涵盖了应用程序后台发生的常见任务，如管理数据、处理会话、处理不同的文件格式以及格式化或转换不同类型的数据。

框架的目的是预见常见的任务，并为程序员提供预先构建的函数来处理这些任务。一旦您熟悉了 Sencha Touch 等框架提供的广泛对象和函数，您就可以快速、更有效地开发应用程序。

![构建基础](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_01.jpg)

## 有计划地构建

在选择任何框架时，关键之一是要查看其文档。没有文档的框架，或者是文档质量差的框架，使用起来简直就是一种折磨。良好的文档提供了关于框架中每个对象、属性、方法和事件的低层次信息。它还应该提供更一般性的信息，例如代码在各种不同情况下是如何使用的示例。

提供良好的文档和示例是 Sencha Touch 作为框架的两个亮点。在 Sencha 的主网站上，[`docs.sencha.com`](http://docs.sencha.com)，可以找到关于**Sencha 文档资源** | **Touch**的广泛信息。有自 Sencha Touch 1.1.0 版本以来的每个版本的文档。在这本书中，我们使用的是 Version 2.2.1，所以点击**Touch 2.2.1**链接会带您到相关的文档。您还可以下载文档作为 ZIP 文件。

一个设计良好的框架还维护一套规范和实践。这些可以是很简单的事情，比如使用驼峰命名法为变量命名（例如，`myVariable`），或者更复杂的注释和文档化代码的做法。这些标准和实践的关键是保持一致性。

一致性使你能够快速学习语言，并直观地知道在哪里找到你问题的答案。这有点像有一个建筑计划；你很快就能理解事物的布局和如何到达你需要去的地方。

框架也会通过提供结构和编码一致性的示例帮助你理解如何构建自己的应用。

在这方面，Sencha 竭尽全力鼓励一致性，遵守标准，并为 Sencha Touch 框架提供广泛的文档。这使得 Sencha-Touch 成为初学者非常有效的首选语言。

## 构建社区

框架很少是孤立的存在的。开发人员群体往往会聚集在特定的框架周围，形成社区。这些社区是询问问题和学习新语言的绝佳场所。

就像所有社区一样，有许多不成文的规定和习俗。在发帖提问之前，总是花时间浏览一下论坛，以防问题已经被提出并回答过了。

Sencha Touch 拥有一个活跃的开发社区，有一个可以从主要 Sencha 网站 [`www.sencha.com/forum`](http://www.sencha.com/forum) 访问的论坛（在网站上向下滚动以找到 Sencha Touch 特定的论坛）。

# 移动应用框架

移动应用框架需要解决与标准框架不同的功能问题。与传统的桌面应用不同，移动设备处理触摸和滑动而不是鼠标点击。键盘是屏幕的一部分，这可能使得传统的键盘导航命令变得困难，甚至不可能。此外，移动设备中有各种屏幕尺寸和分辨率可供选择。因此，框架必须根据屏幕和设备类型调整自身。移动设备的计算能力不如桌面设备，资源也不多，所以移动框架应该考虑这些限制。为了理解这些限制，我们可以先看看不同类型的移动框架以及它们是如何工作的。

## 原生应用与网页应用

移动应用框架主要有两种基本类型：一种用于构建**原生应用**，另一种用于构建**基于网页的应用**，如 Sencha Touch。

原生应用是指直接安装在设备上的应用。它通常能更多地访问设备的硬件（如摄像头、GPS、定位硬件等）和其他设备上的程序，比如通讯录和相册。原生应用的更新通常需要每个用户下载更新后的程序的新副本。

基于 Web 的应用程序，如名字暗示的那样，需要一个公共 Web 服务器，用户需要通过这个服务器来访问应用程序。用户会使用他们移动设备上的浏览器导航到你的应用程序的网站。由于应用程序在 Web 浏览器中运行，它对本地文件系统的访问权限更少，对硬件的访问权限也更少，但它也不需要用户经历复杂的下载和安装过程。基于 Web 的应用程序的更新可以通过对公共 Web 服务器进行一次更新来完成。然后，任何访问该网站的人都会自动更新程序。

基于 Web 的应用程序也可以修改，使其表现得更像原生应用程序，甚至可以通过单独的程序编译，成为一个完整的原生应用程序。

大多数移动浏览器允许用户将应用程序保存到移动设备的桌面。这将创建一个在移动设备主屏幕上的图标。从那里，应用程序可以被启动，并且表现得非常像一个原生应用程序。当从主屏幕图标启动应用程序时，浏览器的导航将不可见。Web 应用程序还可以使用移动设备的内置存储能力，例如使用**HTML5 本地存储**在设备上存储数据，使应用程序在没有网络连接的情况下离线工作。

![原生应用程序与 Web 应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_02.jpg)

如果你发现自己需要原生应用程序的全部功能，你可以使用 Sencha Cmd 命令行工具或外部编译器，如 PhoneGap([`www.phonegap.com/`](http://www.phonegap.com/))，将你的基于 Web 的应用程序编译成一个完整的原生应用程序，然后你可以在苹果的 App Store 或谷歌 Play 商店上传并销售。我们将在书的后面更详细地讨论这些选项。

## 基于 Web 的移动框架

基于 Web 的移动框架依赖于运行应用程序的 Web 浏览器。这是一个关键的信息，原因有几个。

基于 Web 的应用程序首先需要考虑的是，Web 浏览器在移动平台之间需要保持一致。如果你之前有任何网站开发经验，你就会知道浏览器兼容性问题非常痛苦。一个网站在不同的浏览器中可能看起来完全不同。在某个浏览器中可以工作的 JavaScript 在另一个浏览器中可能无法工作。人们也倾向于保留不更新老旧的浏览器。幸运的是，对于大多数移动设备来说，这些问题影响不大，对于 iOS 和 Android 来说更不是问题。

苹果的 iOS 和谷歌的 Android 的 Web 浏览器都是基于**WebKit**引擎。WebKit 是一个开源引擎，它基本上控制着浏览器如何显示页面、处理 JavaScript 以及实现 Web 标准。这意味着你的应用程序应该在这两个平台上的工作方式相同。

然而，不使用 WebKit 的手机设备（如 Windows 手机）将无法使用您的应用程序。好消息是，随着更多浏览器采用 HTML5 标准，这个问题也可能开始消失。

对于基于网页的应用程序的第二个考虑因素是它存放在哪里。原生应用程序被安装在用户的设备上。基于网页的应用程序需要被安装在公共服务器上。用户应该能够将 URL 输入到他们的网页浏览器中，并导航到您的应用程序。如果应用程序只存在于您的电脑上，只有您一个人可以使用它。这对于测试来说很好，但是如果您想让其他人使用您的应用程序，您需要将其托管在公共服务器上。

第三个考虑因素是连通性。如果用户无法连接到互联网，他们将无法使用您的应用程序。然而，Sencha Touch 可以配置为存储您的应用程序及其所有数据在本地。乍一看，这个能力似乎完全解决了连通性问题，但实际上，当用户用多个设备连接到您的应用程序时，它实际上会导致问题。

![基于网页的手机框架](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_03.jpg)

基于网页的应用程序存放在互联网上，因此它可以通过任何带有浏览器和网络连接的设备访问。同一个应用程序可以同时用于手机、个人电脑和移动设备。如果数据存储在中心服务器上，这是信息丰富应用的最大优势。这意味着在一个设备上输入的数据可以在另一个设备上访问。

但是，如果一个应用程序存储数据在本地，这将不可能实现，因为在一个移动设备上输入的数据无法在个人电脑上访问。如果用户使用个人电脑查看网站，应用程序将创建另一套本地数据。

幸运的是，Sencha Touch 可以设置为在服务器和其他各种设备之间同步数据。当您的应用程序连接到互联网时，它会同步任何现有的离线数据，并在在线时使用远程服务器存储任何数据。这确保了您的数据可以在所有设备上访问，同时允许您根据需要离线工作。

## 网页框架和触控技术

标准的网页应用程序框架已经被设计来与鼠标和键盘环境一起工作，但是，移动框架应该使用触控技术进行导航和数据输入。

![网页框架和触控技术](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_04.jpg)

以下是一些常见的触控手势：

+   **Tap**: 屏幕上的一次点击

+   **双击**: 在屏幕上快速点击两次

+   **Tap Hold**: 在设备上点击一次，然后保持手指按压

+   **Swipe**: 用一根手指从左到右或从上到下在屏幕上移动

+   **捏合或展开**: 用两根手指触摸屏幕，然后捏合在一起或分开以撤销动作

+   **旋转**：将两个手指放在屏幕上并顺时针或逆时针旋转它们，通常是为了在屏幕上旋转一个对象

最初，这些交互仅在原生应用中得到支持，但 Sencha Touch 使它们在网页应用中也可用。

# 为移动设备和触控技术设计应用

移动应用需要一些思维上的改变。最大的考虑因素是比例问题。

如果你习惯在 21 英寸显示器上设计应用，处理 3.5 英寸手机屏幕可能会是一种痛苦的经历。手机和移动设备使用各种屏幕分辨率；以下是一些例子：

+   **iPhone 5 Retina 显示屏**: 1136 x 640

+   **iPhone 5**: 960 x 640

+   **iPhone 4** 和 **iPod Touch 4**: 960 x 640

+   **iPhone 4** 和 **iPod Touch 3**: 480 x 320

+   **Android 4 手机**: 这些支持四种通用尺寸：

    +   大屏幕至少为 960 x 720

    +   小屏幕至少为 640 x 480

    +   普通屏幕至少为 470 x 320

    +   小屏幕至少为 426 x 320

+   **HTC 手机**: 800 x 480

+   **三星 Galaxy S3**: 1280 x 720

+   **iPad**: 1024 x 768

+   **iPad Retina**: 2048 x 1536

此外，Android 平板电脑具有各种分辨率和尺寸。为这些不同屏幕尺寸设计应用可能需要一些额外的努力。

设计移动应用时，通常的一个好主意是制作设计草图，以更好地了解比例和应用各种元素将要去的位置。有许多好的布局程序可以帮助你做这件事，如下列出：

+   Omni Graffle for the Mac ([`www.omnigroup.com/products/omnigraffle/`](http://www.omnigroup.com/products/omnigraffle/))

+   Balsamiq Mockups for Mac, Windows, and Linux ([`balsamiq.com/`](http://balsamiq.com/))

+   DroidDraw for Mac, Windows, and Linux ([`www.droiddraw.org/`](http://www.droiddraw.org/))

+   iMockups for the iPad ([`www.endloop.ca/imockups/`](http://www.endloop.ca/imockups/))

触控应用还有一些你需要留意的考虑因素。如果你来自典型的网络开发背景，你可能会习惯使用如悬停等事件。

悬停通常用于网络应用中，以提示用户可以执行某个操作，或者提供工具提示；例如，当用户将鼠标光标悬停在图像或文本上时，通过改变其颜色来显示该图像或文本可以被点击。由于触控应用要求用户与屏幕接触，所以实际上并不存在悬停的概念。用户可以激活或与之交互的对象应该是显而易见的，图标应该清晰标记。

与基于鼠标的应用程序不同，触控应用程序通常也被设计来模仿现实世界的交互。例如，在触控应用程序中翻页通常是通过水平地用手指在页面上滑动来完成的，这与现实世界中的操作非常相似。这鼓励了应用程序的探索，但这也意味着程序员在处理任何潜在的破坏性操作时（如删除一个条目）必须特别小心。

## 为什么是触控？

在触屏出现之前，应用程序通常限于从外部键盘和鼠标接收输入。这两种方式在移动平台上都不是很理想。即使在全内置键盘的非触控设备中使用，它们也可能占用设备上大量的空间，从而限制了可用的屏幕尺寸。相比之下，基于触控的键盘在不需要时会消失，从而留出更大的屏幕区域用于显示。

移动设备上的滑出式键盘并没有 adverse 影响屏幕尺寸，但它们可能会占用空间并且使用起来不舒服。此外，触控屏键盘允许有特定于应用程序的键盘和按键，比如在网页浏览器中使用的*.com*键。

键盘和鼠标设备也可能对一些用户造成心理上的 disconnect。在桌面上使用鼠标来控制分离屏幕上的小指针往往会让用户有一种没有完全控制活动的感觉，而直接在屏幕上触摸并移动一个对象则让你成为活动的主体。因为我们通过触摸和用手移动物体与物理世界互动，所以基于触控的应用程序通常提供更直观的用户界面（UI）。

触控技术随着 Windows 8 的问世也开始在桌面电脑领域取得重大突破。随着这项技术的价格降低并变得更加普及，对基于触控的应用程序的需求将继续增长。

# 开始使用 Sencha Touch

当你开始接触任何新的编程框架时，了解所有可用的资源是个好主意。购买这本书是一个很好的开始，但还有其他一些对你探索 Sencha Touch 框架来说非常有价值的资源。

幸运的是，Sencha 网站为我们提供了丰富的信息，帮助你在开发的每个阶段。

## 应用程序编程接口（API）

Sencha Touch 应用程序编程接口（API）文档提供了关于 Sencha Touch 中可用的每个对象类的详细信息。API 中的每个类都包括对该类每个配置选项、属性、方法和事件的详细文档。API 通常还包括每个类的简短示例，带有实时预览和代码编辑器。

应用程序编程接口（API）文档可在 Sencha 网站[`docs.sencha.com/touch/2.2.1/`](http://docs.sencha.com/touch/2.2.1/)上找到。

如以下屏幕截图所示的副本，也作为 Sencha Touch 框架的一部分包含在内，您将下载此框架来创建您的应用程序：

![The API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_05.jpg)

## 示例

Sencha 网站还包含了许多示例应用程序供您查看。其中最为有帮助的是厨房水槽（Kitchen Sink）应用程序。下面的屏幕截图展示了厨房水槽应用程序的外观：

![示例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_06.jpg)

### 厨房水槽应用程序

厨房水槽应用程序提供了以下示例：

+   用户界面元素，如按钮、表单、工具栏、列表等

+   动作的动画，如翻页或滑动表单

+   触摸事件，如轻触、滑动和捏合

+   处理 JSON、YQL 和 AJAX 的数据

+   音频和视频的媒体处理

+   更改应用程序外观的主题

每个示例在上右角都有一个**源代码**按钮，将显示厨房水槽示例的代码。

厨房水槽应用程序还提供了**事件记录器**和**事件模拟器**。这些功能将允许您录制、存储并回放设备屏幕上执行的任何触摸事件。

这些模拟器演示了如何在您的应用程序中记录操作以作为现场演示或教程回放，它们还可以用于轻松重复测试功能。

您可以在任何移动设备上或使用苹果的 Safari 网络浏览器在常规计算机上与厨房水槽应用程序互动。厨房水槽应用程序可在 Sencha 网站[`docs.sencha.com/touch/2.2.1/touch-build/examples/kitchensink/`](http://docs.sencha.com/touch/2.2.1/touch-build/examples/kitchensink/)上找到。

厨房水槽应用程序的副本也作为 Sencha Touch 框架的一部分包含在内，您将下载此框架来创建您的应用程序。

## 学习

Sencha 在网站上还有一个部分，致力于讨论 Sencha Touch 框架的特定方面。这个部分被适当地命名为**学习**。它包含了许多教程、屏幕录像和指南供您使用。每个子部分都被标记为**简单**、**中等**或**困难**，这样您就对您将要进入的内容有一个大致的了解。

**学习**部分可在 Sencha 网站[`www.sencha.com/learn/touch/`](http://www.sencha.com/learn/touch/)上找到。

## 论坛

Sencha 论坛值得再次提及。这些社区讨论提供了基础知识、错误报告、问答环节、示例、竞赛等内容。论坛是找到日常使用框架的人提供的解决方案的好地方。

# 设置您的开发环境

现在您已经熟悉了可用的 Sencha Touch 资源，下一步是设置您的开发环境并安装 Sencha Touch 库。

为了开始使用 Sencha Touch 开发应用程序，强烈建议您有一个可以托管应用程序的网络服务器。虽然通过使用网络浏览器查看本地文件夹来开发 Sencha Touch 应用程序是可能的，但没有网络服务器，您将无法在任何移动设备上测试您的应用程序。

## 在 Mac OS X 上设置网络共享。

如果您正在使用 Mac OS X，您已经安装了一个网络服务器。要启用它，请启动系统偏好设置，选择**共享**，并启用**网络共享**。如果您还没有这么做，点击**创建个人网站文件夹**来为您的主目录设置一个网络文件夹。默认情况下，这个文件夹名为`Sites`，这是我们构建应用程序的地方：

![在 Mac OS X 上设置网络共享](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_07.jpg)

**共享**面板将告诉您您的网络服务器 URL。记住这个，稍后用得着。

## 在 Microsoft Windows 上安装网络服务器。

如果您正在运行 Microsoft Windows，您可能正在运行 Microsoft 的**互联网信息服务器**（**IIS**）。您可以进入控制面板，选择以下任一选项来查看：

+   **程序特性** | **开启或关闭 Windows 功能**（在 Vista 或 Windows 7 中）。详细说明请参阅[`www.howtogeek.com/howto/windows-vista/how-to-install-iis-on-windows-vista/`](http://www.howtogeek.com/howto/windows-vista/how-to-install-iis-on-windows-vista/)。

+   **添加/删除程序** | **添加/删除 Windows 组件**（在 Windows XP 中）。详细说明请参阅[`www.webwiz.co.uk/kb/asp-tutorials/installing-iis-winXP-pro.htm`](http://www.webwiz.co.uk/kb/asp-tutorials/installing-iis-winXP-pro.htm)。

如果您没有安装 IIS，或者不熟悉其操作，建议您安装 Apache 服务器，与本书配合使用。这将使我们能够在示例中为 Mac 和 PC 提供一致的指导。

安装 Apache 的最简单方法之一是下载并安装 XAMPP 软件包([`www.apachefriends.org/en/xampp-windows.html`](http://www.apachefriends.org/en/xampp-windows.html))。这个软件包包括 Apache 以及 PHP 和 MySQL。这些额外的程序在您的技能增长时会有帮助，让您能够创建更复杂的程序和数据存储选项。

下载并运行 XAMPP 后，系统会提示您运行 XAMPP 控制面板。您还可以从 Windows**开始**菜单运行 XAMPP 控制面板。您应该点击控制面板中的**开始**按钮来启动您的网络服务器。如果您从防火墙软件收到通知，您应该选择允许 Apache 连接到互联网的选项。

![在 Microsoft Windows 上安装网络服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_08.jpg)

在您安装 XAMPP 的文件夹中，有一个名为`htdocs`的子目录。这是我们将要设置 Sencha Touch 的网页文件夹。完整路径通常是`C:\xampp\htdocs`。您的网页服务器 URL 将是`http://localhost/`；您想要记住这个步骤。

## 下载并安装 Sencha Touch 框架

在您的网页浏览器中，访问[`www.sencha.com/products/touch/`](http://www.sencha.com/products/touch/)，然后点击**下载**按钮。将 ZIP 文件保存到一个临时目录中。

### 注意

请注意，本书中的所有示例都是使用 Sencha Touch Version 2.1.1 编写的。

您下载的文件解压缩将创建一个名为`sencha-touch-version`的目录（在我们的案例中，它是`sencha-touch-2.1.1`）。将此目录复制到您的网页文件夹中并重命名它，删除版本号，只留下`sencha-touch`。

现在，打开您的网页浏览器并输入您的网页 URL，在末尾添加`sencha-touch/examples`。您应该看到以下 Sencha Touch 演示页面：

![下载并安装 Sencha Touch 框架](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_09.jpg)

恭喜您！您已成功安装了 Sencha Touch。

这个演示页面包含了应用程序的示例以及组件的简单示例。

# 用于使用 Sencha Touch 开发的额外工具

除了配置网页服务器和安装 Sencha Touch 库之外，还有一些开发工具您可能在深入您的第一个 Sencha Touch 应用程序之前想要了解一下。Sencha 还拥有几款其他可能对您的 Sencha Touch 应用有用的产品，还有不少第三方工具可以帮助您开发和部署您的应用。我们不会详细介绍如何设置和使用它们，但这些工具绝对值得一探。

## Safari 和 Chrome 开发者工具

编写代码时，能够看到幕后发生的情况通常非常有帮助。与 Sencha Touch 一起工作的最关键工具是 Safari 和 Chrome 开发者工具。这些工具将以多种方式帮助您调试代码，我们将在书中进一步详细介绍它们。现在，让我们快速了解一下以下四个基本工具，它们将在以下章节中解释。

### 提示

对于 Safari 用户，您可以通过前往**编辑** | **偏好设置** | **高级**来启用 Safari 开发者菜单。在菜单栏中勾选**显示开发**复选框。一旦启用此菜单，您可以看到所有可用的开发者工具。对于 Chrome 用户，这些工具可以通过**查看** | **开发者** | **开发者工具**菜单访问。

### JavaScript 控制台

JavaScript 控制台显示错误和控制台日志，这为您提供了出错时的指示。

![JavaScript 控制台](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_10.jpg)

注意我们在这里得到两方面的信息：错误和错误发生的文件。你可以点击文件名查看错误发生的确切行。你应该花些时间熟悉 Chrome 或 Safari 中的控制台。你可能会在这里花很多时间。

### 网络标签页

第二个有用的工具是**网络**标签页。这个标签页会显示在网页浏览器中加载的所有文件，包括浏览器尝试加载但无法找到的任何文件的错误。

![网络标签页](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_11.jpg)

丢失的文件显示为红色。点击一个文件会显示更多详细信息，包括传递给文件的任何数据和返回的数据。

### 网络检查器

网络检查器允许你检查页面中显示的任何元素的底层 HTML 和 CSS。下面的屏幕截图展示了网络检查器：

![网络检查器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_12.jpg)

网络检查器在寻找应用程序中的显示和定位错误时特别有用。你可以在 Chrome 中点击放大镜或 Safari 中的指针来选择页面上的任何元素并查看显示逻辑。

### 资源标签页

**资源**标签页显示浏览器为我们应用程序存储的信息。这包括我们存储在本地任何数据的信息，以及我们为这个应用程序创建的任何饼干的详细信息，如下面的屏幕截图所示：

![资源标签页](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_01_13.jpg)

从这一标签页中，你可以双击一个项目来编辑它，或者右键点击删除它。

随着书籍的进展，我们将更详细地查看这些工具，并展示一些额外的用途和技巧。

Safari 开发者工具的完整讨论可以在[`developer.apple.com/technologies/safari/developer-tools.html`](https://developer.apple.com/technologies/safari/developer-tools.html)找到。

Chrome 开发者工具的介绍可以在[`developers.google.com/chrome-developer-tools/`](https://developers.google.com/chrome-developer-tools/)找到。

## 其他 Sencha 产品

Sencha 提供了几款可以加速代码开发甚至扩展 Sencha Touch 功能的产品。

### Sencha Cmd

Sencha Cmd 是一个命令行工具，允许你从命令行提示符生成基本的 Sencha Touch 文件。它还可以让你编译应用程序供 Web 使用，或者编译成二进制文件，你可以在各种应用程序商店中销售。

在本书中，我们将多次使用 Sencha Cmd。你可以从以下网站下载它：

[`www.sencha.com/products/sencha-cmd/download`](http://www.sencha.com/products/sencha-cmd/download)

### Sencha Architect

Sencha Architect 是 Sencha Touch 和 ExtJS 应用的**集成开发环境**（**IDE**）。Sencha Architect 允许您在一个图形化环境中构建应用程序，通过拖放控件到屏幕上。您可以以多种方式排列和操作这些组件，而 Sencha Architect 会为您编写底层代码。您可以从以下网站下载：

[Sencha Architect](http://www.sencha.com/products/architect)

### Sencha Animator

Sencha Touch 带有一些内置动画；但是，对于更复杂的动画，需要一个更强大的应用程序。使用 Sencha Animator 桌面应用程序，您可以创建与 Flash 动画相媲美的专业动画。然而，与 Flash 动画不同，Sencha Animator 动画可以在大多数移动浏览器上运行，使其成为为您的 Sencha Touch 应用程序添加额外魅力完美的选择。您可以在以下网站下载 Sencha Animator：

[Sencha Animator](http://www.sencha.com/products/animator/)

## 第三方开发者工具

您还可以选择多种开发者工具，这些工具在开发您的 Sencha Touch 应用时可能会有所帮助。

### Notepad++

Notepad++是一个代码编辑器，非常适合编写 JavaScript 代码。它具有某些有用功能，如语法高亮、语法折叠、多视图和多语言环境以及多文档。这是一个免费且开源的工具，可在[Notepad++](http://notepad-plus-plus.org/features.html)上获得。这只适用于 Windows 和 Linux 操作系统。

### WebStorm

WebStorm 是一个 IDE（代码编辑器），用于开发使用 JavaScript 等语言的网页应用程序。WebStorm 适用于 Windows、OS X 和 Linux。Webstorm 提供 30 天免费试用，并可选商业、个人和教育用途的许可选项。您可以在以下网站找到它：

[WebStorm](http://www.jetbrains.com/webstorm/)

### Xcode 5

**Xcode 5** 是苹果完整的开发环境，旨在为任何苹果平台（OS X、iPhone 或 iPad）的开发者提供支持。因此，它包含很多对于编写 Sencha Touch 应用程序来说实际上并不必要的组件。然而，Xcode 5 中包含的一个对于 Sencha Touch 开发者可能非常有用的工具是 iOS 模拟器。使用 iOS 模拟器，您可以在不实际拥有它们的情况下在各种 iOS 设备上测试您的应用程序。

大多数使用 Xcode 5 的用户需要加入苹果开发者计划（比如在应用商店销售应用程序）。然而，iOS 模拟器任何人都可以使用。您可以从以下网站下载 Xcode 5：

[Xcode](http://developer.apple.com/xcode/)

### Android 模拟器

Android 模拟器是 Xcode 5 中 iOS 模拟器的 Android 对应程序。Android 模拟器是免费下载的 Android SDK 的一部分，地址为[`developer.android.com/guide/developing/devices/emulator.html`](http://developer.android.com/guide/developing/devices/emulator.html)。Android 模拟器可以配置为模仿许多具体的 Android 移动设备，使你能够跨广泛的设备测试你的应用程序。

### YUI 测试

编程的任何一部分都包括测试。YUI 测试是雅虎的 YUI JavaScript 库的一部分，它允许你创建和自动化单元测试，就像 JUnit 对 Java 做的那样。单元测试为特定代码段设置测试用例。然后，如果将来这段代码发生了变化，可以重新运行单元测试，以确定代码是否仍然成功。这非常有用，不仅用于查找代码中的错误，而且用于在发布之前确保代码质量。YUI 测试可以在以下网址找到：

[`yuilibrary.com/yui/docs/test/`](http://yuilibrary.com/yui/docs/test/)

### Jasmine

Jasmine 是一个类似于 YUI 测试的测试框架，只不过它是基于**行为驱动设计**（**BDD**）。在 BDD 测试中，你从规格开始——关于你的应用程序在某些场景下应该做什么的故事——然后编写符合这些规格的代码。YUI 测试和 Jasmine 都达到了测试你代码的相同目标，它们只是以不同的方式做到这一点。你可以在以下网址下载 Jasmine：

[`pivotal.github.com/jasmine/`](http://pivotal.github.com/jasmine/)

### JSLint

可能是这个列表中最有用的 JavaScript 工具，**JSLint**将检查你的代码中的语法错误和代码质量。由 JavaScript 的两位之父之一 Douglas Crockford 编写，JSLint 将详细检查你的代码，这对于在部署代码之前找到错误非常有帮助。你可以在以下网址找到更多信息：

[`www.jslint.com/lint.html`](http://www.jslint.com/lint.html)

# 总结

在本章中，我们介绍了 web 应用程序框架的基础知识以及为什么应该使用 Sencha Touch。我们带你了解如何设置开发环境和安装 Sencha Touch 库。我们还简要了解了移动设备的限制以及如何克服它们。我们还简要了解了在开发移动应用程序时应该注意的事情。我们还探讨了在移动应用程序开发中有用的其他工具：

+   Sencha Touch 学习中心（[`www.sencha.com/learn/touch/`](http://www.sencha.com/learn/touch/)

+   Apple 的 iOS 人机界面指南（[`developer.apple.com/library/ios/#documentation/UserExperience/Conceptual/MobileHIG/Introduction/Introduction.html`](http://developer.apple.com/library/ios/#documentation/UserExperience/Conceptual/MobileHIG/Introduction/Introduction.html)）——深入介绍为 iOS 设备开发用户界面的指南。

+   Android 界面指南([`developer.android.com/guide/practices/ui_guidelines/index.html`](http://developer.android.com/guide/practices/ui_guidelines/index.html))

在下一章中，我们将创建第一个 Sencha Touch 应用程序，在这个过程中，我们将学习如何使用 Sencha Touch 开发和 MVC 框架的基本知识。


# 第二章：创建一个简单的应用

在本章中，我们将带领大家了解如何在 Sencha Touch 中创建一个简单应用的基础知识。我们将涵盖大多数 Sencha Touch 应用中使用的的基本元素，并查看你可能会在自己的应用中使用的更常见的组件：容器、面板、列表、工具栏和按钮。

本章将涵盖以下主题：

+   使用 Sencha Cmd 创建基本应用

+   理解应用的文件和文件夹

+   修改应用

+   控制应用的布局

+   测试和调试应用

+   更新生产环境中的应用

让我们学习如何设置一个基本的 Sencha Touch 应用。

# 设置应用

在开始之前，你需要确保你已经根据前章的概要正确地设置了你的开发环境。

### 注意

**根目录**

如前章所述，为了允许网络服务器找到它们，你需要将你的应用文件和文件夹放在你本地机器上正确的文件夹中。

在 Mac 机器上，如果你使用网络共享，这将是你家目录下的`Sites`文件夹。如果你使用 MAMP，位置是`/Applications/MAMP/htdocs`。

在 Windows 上，这将是在前章中描述的安装 XAMPP 后的`C:\xampp\htdocs`。

在本书的其余部分，我们将把这个文件夹称为根目录。

在 Sencha Touch 的先前版本中，你必须手动设置你的目录结构。为了使这个过程变得稍微容易一些并且更加一致，Sencha 现在建议使用 Sencha Cmd 来创建初始应用结构。

## 使用 Sencha Cmd 入门

正如前章所提到的，Sencha Cmd 是一个命令行工具，它允许你从命令行生成许多基本的 Sencha Touch 文件。

首先，你需要从以下链接下载一个 Sencha Cmd 的副本：[`www.sencha.com/products/sencha-cmd/download`](http://www.sencha.com/products/sencha-cmd/download)

在 Windows 或 Mac 上，下载安装程序后可以运行它，然后按照安装 Sencha Cmd 的提示操作。

一旦你安装了 Sencha Cmd，你可以以以下方式在你的电脑上打开命令行提示：

+   在 Mac OS X 上，前往`Applications/Utilities`并启动**终端**

+   在 Windows 上，点击**开始** | **运行**，然后输入`cmd`

一旦命令行可用，输入`sencha`，你应该会看到类似以下内容：

![Sencha Cmd 入门](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_01.jpg)

这告诉你命令是否成功，并提供了一些 Sencha Cmd 的基本`帮助`选项。实际上，我们将使用这个帮助部分列出的第一个命令来生成我们的新应用：

```js
sencha -sdk /path/to/sdk generate app MyApp /path/to/myapp

```

这个命令有七个部分，所以我们逐一来看看：

+   `sencha`：这告诉命令行将处理命令的应用程序名称；在这个例子中，`Sencha Cmd`，或者简称`sencha`。

+   `-sdk`：这告诉 Sencha Cmd 我们将指定我们 Sencha Touch 库的路径。我们也可以直接将目录更改为我们下载这些库的文件夹，从而省略`-sdk`部分以及随后的路径信息。

+   `/path/to/sdk`：这将被替换为我们下载的 Sencha Touch 库文件的实际路径（不是 Sencha Cmd，而是实际的 Sencha Touch 库）。

+   `generate`：这表明了我们接下来要做什么。

+   `app`：由于我们将要生成一些东西，那么我们将要生成什么？这一部分的命令回答了这个问题。在这个例子中，我们将要生成一个应用。

+   `MyApp`：你的应用将被称为这个名字。它还将用于我们稍后介绍的 JavaScript 命名空间。这是任意的，但必须是一个没有空格的单个单词。

+   `/path/to/myapp`：这将是你的新应用的路径。这个路径应该在我们之前提到的根目录中的一个新文件夹里。

在本章节，我们将要创建一个名为`TouchStart`的应用。你的路径信息需要反映你个人的设置，但命令应该看起来类似于这样：

```js
sencha -sdk /Users/12ftguru/Downloads/touch-2.2.1 generate app TouchStart /Applications/MAMP/htdocs/TouchStart

```

根据你的 Sencha Touch 库和根目录的位置调整你的路径。命令一旦执行，你将在终端中看到如下方式出现的一系列信息：

![使用 Sencha Cmd 开始](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_02.jpg)

Sencha Cmd 复制它需要的文件并设置你的应用。一旦命令执行，你应该在根目录中有一个名为`TouchStart`的新文件夹。

打开那个文件夹，你会看到以下文件和目录：

![使用 Sencha Cmd 开始](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_03.jpg)

我们将几乎完全与`app`目录中的文件一起工作，但了解这些文件和目录的每个部分还是值得的：

+   `app`：本章节我们将详细介绍这个目录，这是我们的所有应用文件所在的地方。

+   `app.js`：这个 JavaScript 文件设置我们的应用并在应用启动时处理初始化。我们将在下一节更详细地查看这个文件。

+   `build.xml`：这是一个编译应用程序的配置文件。你可能不需要更改这个文件。

+   `index.html`：这个文件与任何网站的`index.html`文件类似。它是浏览器加载的第一个文件。然而，与传统的网站不同，我们应用的`index.html`文件只加载我们的初始 JavaScript，然后什么都不做。你不需要更改这个文件。

+   `packager.json`：这个配置文件告诉我们应用如何设置文件以及它们的所在位置。大部分情况下，你可能不需要更改这个文件。

+   `packages`：`packages`目录是一个占位符，你可以在这里为你的应用程序安装额外的包。在这个阶段，它基本上是未被使用的。

+   `resources`：`resources`目录包含我们的 CSS 文件和启动屏幕及图标。我们将在下一章关于样式的内容中了解更多关于这个目录的信息。

+   `touch`：这个目录包含 Sencha Touch 库文件的副本。它绝不应该被修改。

我们也可以通过访问我们的网页目录，在网络浏览器中查看我们新的应用程序。对于 Windows 和 MAMP 用户，这将是在`http://localhost/TouchStart`，而对于启用了网络共享的 Mac 用户，则是在`http://localhost/~username/TouchStart`。

![Sencha Cmd 入门](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_04(new).jpg)

### 提示

值得一提的是，Sencha Cmd 本身就有一个内置的网络服务器，你可以用它来查看你的 Sencha Touch 应用程序。你可以使用以下命令启动 Sencha Cmd 网络服务器：

```js
sencha fs web -port 8000 start –map /path/to/your/appfolder 

```

然后，你可以通过访问`http://localhost:8000`来打开你的网络浏览器。

有关使用 Sencha Cmd 网络服务器的更多信息，请访问[`docs.sencha.com/cmd/3.1.2/#!/guide/command.`](http://docs.sencha.com/cmd/3.1.2/#!/guide/command.)

从已经创建的基本应用程序中，我们可以看到的是位于`app/view`的`Main.js`文件的内容。我们可以修改这个文件，并在重新加载页面时看到结果。

在我们开始修改`Main.js`文件之前，我们需要先查看一下为我们加载所有内容的文件，即`app.js`。

## 创建 app.js 文件

`app.js`文件负责设置我们的应用程序，虽然我们不需要经常修改它，但了解它做什么以及为什么这样做是个好主意。

在你的代码编辑器中打开`app.js`文件；在顶部，你会看到一大段注释（你应该阅读并熟悉它）。在注释下方，代码以：

```js
Ext.Loader.setPath({
    'Ext': 'touch/src'
});
```

这告诉应用程序我们的 Sencha Touch 库文件位于哪里。

接下来，我们用以下代码定义我们的应用程序：

```js
Ext.application({
    name: 'TouchStart',

    requires: [
        'Ext.MessageBox'
    ],

    views: [
        'Main'
    ],

    icon: {
        '57': 'resources/icons/Icon.png',
        '72': 'resources/icons/Icon~ipad.png',
        '114': 'resources/icons/Icon@2x.png',
        '144': 'resources/icons/Icon~ipad@2x.png'
    },
    isIconPrecomposed: true,

    startupImage: {
        '320x460': 'resources/startup/320x460.jpg',
        '640x920': 'resources/startup/640x920.png',
        '768x1004': 'resources/startup/768x1004.png',
        '748x1024': 'resources/startup/748x1024.png',
        '1536x2008': 'resources/startup/1536x2008.png',
        '1496x2048': 'resources/startup/1496x2048.png'
    },
    launch: function() {
        // Destroy the #appLoadingIndicator element
        Ext.fly('appLoadingIndicator').destroy();

        // Initialize the main view
        Ext.Viewport.add(Ext.create('TouchStart.view.Main'));
    }
});
```

一口气吃下这么多代码确实有些多，所以让我们一步一步来理解。

第一部分，`Ext.Application({…});`，为 Sencha Touch 创建了一个新的应用程序。大括号之间的所有内容都是这个新应用程序的配置选项。虽然一个应用程序有很多配置选项，但大多数至少包括应用程序的名称和启动函数。

### 注意

**命名空间**

使用他人代码时的一个最大问题就是命名问题。例如，如果你正在使用的框架有一个名为`Application`的对象，而你又创建了一个名为`Application`的自定义对象，这两个对象的功能将会发生冲突。Sencha Touch 使用命名空间的概念来防止这些冲突的发生。

在此案例中，Sencha Touch 使用了命名空间`Ext`。你会在本书的代码中看到这个命名空间被广泛使用。这只是一个消除框架对象和代码以及您自己的对象和代码之间潜在冲突的方式。

Sencha 将自动为您自己的代码设置命名空间，作为新`Ext.Application`对象的一部分。在此案例中，它将是`TouchStart`，我们用它来生成我们的应用程序。

`Ext`也是 Sencha 的 Web 应用程序框架`ExtJS`的名称之一。Sencha Touch 使用相同的命名空间约定，让开发者熟悉一个库，并容易理解另一个库。

当我们创建一个新应用程序时，我们需要向其传递一些配置选项。这将告诉应用程序如何外观以及要做什么。这些配置选项包含在花括号`{}`内，并用逗号分隔。第一个选项是：

```js
name: 'TouchStart'
```

这将我们应用程序的名称设置为引号之间的任何内容。`name`值不应包含空格，因为 Sencha 也使用这个值为您自己的代码对象创建命名空间。在此案例中，我们称之为应用程序`TouchStart`。

在`name`选项之后，我们有一个`requires`选项：

```js
requires: [
        'Ext.MessageBox'
    ]
```

这是我们列出任何文件的地方，这些文件在应用程序启动时就需要。由于我们实际上在文件的底部使用了`Ext.Msg.confirm`函数，所以我们不得不在这里包含`Ext.MessageBox`类。

接下来，我们有`views`部分：

```js
views: [
        'Main'
    ]
```

本节作为`app/view`文件夹中`Main.js`文件的参考。我们也可以在这里为`controllers`、`stores`或`models`列出清单，但目前，这个骨架应用中唯一的一个是`Main.js`视图文件。我们将在后面的章节中了解更多关于控制器、模型、存储器和视图的内容。

`icon`和`startupImage`部分提供了用于应用程序图标和启动屏幕的图像文件的链接。列出的大小确保了应用程序的图像能够在多种设备上正确显示。

下一个选项是事情开始变得有趣的地方：

```js
launch: function() {
  // Destroy the #appLoadingIndicator element
  Ext.fly('appLoadingIndicator').destroy();

  // Initialize the main view
  Ext.Viewport.add(Ext.create('TouchStart.view.Main'));
}
```

`launch`函数在所需的 JavaScript 文件（以及任何列出的视图、模型、存储器和控制器）加载完成后执行。这个函数首先销毁我们的加载指示器（因为我们已经完成加载文件）。然后创建我们的主视图并将其添加到视口。视口是我们向用户显示内容的地方。

在此情况下，`TouchStart.view.Main`指的是`app/view`文件夹中的`Main.js`文件。这就是 Sencha Touch 如何查找文件的方式：

+   `TouchStart`是我们应用程序的一部分。

+   `view`是`views`文件夹

+   `Main`是我们的`Main.js`文件。

让我们 closer 看看这个`Main.js`文件，看看它是如何创建我们目前看到的骨架应用程序中的所有视觉元素的。

## 创建 Main.js 文件

`Main.js`文件位于`app/view`文件夹中。`view`文件是我们应用程序的视觉组件。让我们打开这个文件，看看如何创建一个简单的标签面板。

```js
Ext.define('TouchStart.view.Main', {
    extend: 'Ext.tab.Panel',
    xtype: 'main',
    requires: [
        'Ext.TitleBar',
        'Ext.Video'
    ],
    config: {
        tabBarPosition: 'bottom',

        items: [
            …
        ]
    }
});
```

我们从我们的代码示例中删除了`items`部分的内容，以使这更容易阅读。

前代码的的第一行和第二行在您在 Sencha Touch 中创建的几乎每个组件中都是通用的。

```js
Ext.define('TouchStart.view.Main', {
    extend: 'Ext.tab.Panel'
```

第一行定义了组件的全名，格式如下：

+   应用程序名称（命名空间）。

+   文件夹名称。

+   文件名（无扩展名）。

接下来，我们列出我们要扩展的组件；在这个例子中，是一个标签面板。您会在本书中看到这个定义/扩展模式。

您还会注意到，标签面板被称为`Ext.tab.Panel`。这使得 Sencha Touch 知道该组件是一个本地组件（`Ext`），位于名为`tab`的文件夹中的一个名为`Panel.js`的文件中。这种模式允许 Sencha Touch 加载正确的文件，并使用我们新的配置选项对其进行扩展：

```js
xtype: 'main',
requires: [
   'Ext.TitleBar',
   'Ext.Video'
],
config: {
   tabBarPosition: 'bottom'
```

我们做的第一件事是为我们的新组件设置一个`xtype`值。`xtype`部分是一个简短的名字，允许我们轻松地引用和创建我们组件的副本，而不必使用完整名称。您稍后在本书中会看到一些这样的例子。

我们的骨架应用程序使用了一个`TitleBar`和一个`Video`组件，因此我们需要这两个文件。

接下来，我们设置了一个`config`部分。这个部分用于为我们新组件设置任何自定义设置。在这个例子中，我们将我们的标签栏定位在底部。

现在，我们想看看我们从代码示例中删除的`items`部分，并研究这个部分对我们的标签面板有什么影响。

## 探索标签面板。

`Ext.tab.Panel`被设计为自动为我们做几件事情。最重要的是，对于我们在`items`部分添加的每一个面板，都会自动为我们在标签面板中创建一个对应的标签。默认情况下，只显示第一个面板。然而，标签面板也会在我们点击面板的标签时自动切换这些面板。

如果您回过头来看我们在浏览器中的应用程序，您还会看到每个标签页都有一个标题和一个图标。这两个`config`选项是作为当前看起来类似于这样的个别项目设置的：

```js
items: [
   {
      title: 'Welcome',
      iconCls: 'home',
      styleHtmlContent: true,
      scrollable: true,
         items: {
            docked: 'top',
            xtype: 'titlebar',
            title: 'Welcome to Sencha Touch 2'
         },
      html: [
         "You've just generated a new Sencha Touch 2 project. What you're looking at right now is the ",
         "contents of <a target='_blank' href=\"app/view/Main.js\">app/view/Main.js</a> - edit that file ",
         "and refresh to change what's rendered here."
      ].join("")
   },
   {
      title: 'Get Started',
      iconCls: 'action',
      items: [
         {
            docked: 'top',
            xtype: 'titlebar',
            title: 'Getting Started'
         },
         {
            xtype: 'video',
            url: 'http://av.vimeo.com/64284/137/87347327.mp4?token=1330978144_f9b698fea38cd408d52a2393240c896c',
            posterUrl: 'http://b.vimeocdn.com/ts/261/062/261062119_640.jpg'
         }
      ]
   }
]
```

请注意，我们的`items`列表用括号括起来，列表中的各个组件用花括号包含。这种嵌套组件结构是 Sencha Touch 的关键部分，您会在本书的各个章节中看到它的使用。

`title`和`iconCls`属性控制了每个条目中标签的外观。我们的标题目前设置为`Welcome`和`Getting Started`。我们的`iconCls`配置决定了标签中使用的图标。在这种情况下，我们使用了两个默认图标：`home`和`action`。

我们的面板是`Welcome`面板，它有配置选项，允许我们使用带样式的 HTML 内容并使其可滚动（如果内容大于屏幕大小）。`html`配置选项里面的文本是我们看作是第一个面板的内容的。

你会注意到我们的面板也有它自己的项目。在这种情况下，有一个`titlebar`将会被`docked`在我们的面板的`top`上，标题是“**欢迎使用 Sencha Touch 2**”。

我们的第二个`Get Started`面板里面有 two `items`：一个像我们第一个面板一样的`titlebar`和一个`video`组件，它列出视频的 URL 和另一个`posterUrl`，这是在用户播放视频前会显示的图片。

正如我们第一个面板中的文本所提到的，我们可以更改这个文件的内容，当我们重新加载页面时，就能看到结果。让我们试一试，看看它是如何工作的。

### 添加一个面板

我们想要做的第一件事是删除我们标签面板中`items`括号`[ ]`之间的所有内容。接下来，我们将添加一个类似的新面板：

```js
items: [
  {
    title: 'Hello',
    iconCls: 'home',
    xtype: 'panel',
    html: 'Hello World'
  }
]
```

如果我们现在重新加载浏览器，我们看到这个：

![添加一个面板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_05.jpg)

由于我们现在只有一个面板，所以我们只有一个标签。我们还移除了标题栏，所以我们页面顶部没有什么东西。

### 小贴士

细心的读者还会注意到，我们在这个例子中明确为`panel`设置了一个`xtype`值。标签面板会自动假设，如果你没有为它的一个项目指定`xtype`值，那么它就是个面板。然而，设定组件使用的`xtype`值是一个好习惯。我们将在第四章，*组件和配置*中更多地讨论 xtype。

现在，我们的面板非常简单，只包含一行文本。在现实世界中，应用程序很少有这么简单。我们需要一种在我们面板内安排不同元素的方法，这样我们就可以创建现代、复杂的布局。幸运的是，Sencha Touch 有一个内置的配置叫做`layout`，这将帮助我们实现这一点。

# 用布局控制外观

布局为您提供了一系列在容器内安排内容的选择。Sencha Touch 为容器提供了五种基本布局：

+   `fit`：这是一个单一项目的布局，它会自动扩展以占据整个容器。

+   `hbox`：这使得项目在容器内水平排列。

+   `vbox`：这使得项目在容器内垂直排列。

+   `card`：这像是一叠卡片一样排列项目，最初只显示活动卡片。

+   `docked`：这使得项目在显示区域的顶部或底部或左侧或右侧。

在我们之前的例子中，我们没有声明布局。通常，你总是想要为任何容器声明一个布局。如果你不这么做，容器内的组件在出现时可能不会适当地调整大小。

我们已经看到了最后两种布局。标签面板使用`card`布局在它的`items`列表中切换不同的面板。

我们原始的`Main.js`文件中的标题栏有一个`docked`属性作为它们配置的一部分。这个配置将它们停靠到屏幕的特定部分。你甚至可以将多个项目停靠到一个面板的四个边之一。

例如，如果我们向我们的当前面板的`items`部分添加如下内容：

```js
items: [
  {
    xtype: 'titlebar',
    docked: 'top',
    title: 'About TouchStart'
  },
  {
    xtype: 'toolbar',
    docked: 'top',
    items: [
      {
        xtype: 'button',
        text: 'My Button'
      }
    ]
  }
]
```

这两个栏将以下方式堆叠在一起：

![使用布局控制外观](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_06.jpg)

## 使用适合布局

让我们添加第二个面板来理解我们之前做了什么。在我们第一个面板的闭合花括号后，加上一个逗号，然后添加以下代码：

```js
{
  title: 'Fit',
  iconCls: 'expand',
  xtype: 'panel',
  layout: 'fit',
  items: [
    {
    xtype: 'button',
    text: 'Very Fit'
    }
  ]
}
```

对于这个面板，我们添加了一个`config`选项，`layout: 'fit'`，以及一个`items`部分，里面有一个按钮。

![使用适合布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_07.jpg)

正如前一个屏幕截图所示，这给了我们第二个标签页，其中包含我们新添加的按钮。由于布局被设置为适合，按钮会扩展以占据所有可用的空间。虽然当你想要一个组件占据所有可用空间时这很有用，但如果你想要嵌套多个组件，它就不会表现得很好。

## 使用 vbox 布局

`vbox`布局从上到下堆叠组件。在这个例子中，多个组件将填满可用的屏幕空间。让我们添加另一个面板来看看这是什么样子。像之前一样，在我们最后一个面板的闭合花括号后，加上一个逗号，然后添加以下代码：

```js
{
  title: 'VBox',
  iconCls: 'info',
  xtype: 'panel',
  layout: 'vbox',
  items: [
    {
      xtype: 'container',
      flex: 2,
      html: '<div id="hello">Hello World Top</div>',
      style: 'background:red',
      border: 1
    }, {
      xtype: 'container',
      flex: 1,
      html: '<div id="hello">Hello World Bottom</div>',
      style: 'background:yellow',
      border: 1
    }, {
      xtype: 'container',
      height: 50,
      html: '<div id="footer">Footer</div>',
      style: 'background:green',
    }

  ]
}
```

正如你所看到的，这个面板有一个`layout: 'vbox'`的配置和一个三个`items`的列表。这些项目是我们想要包含在我们`panel`内的`container`组件的集合。

`container`组件是`panel`的简化版，它没有工具栏或标题栏等元素的选项。

我们的前两个容器有一个叫做`flex`的配置。`flex`配置是`vbox`和`hbox`布局所特有的（我们会在后面马上讲到`hbox`）。`flex`配置控制组件在整体布局中占用的比例空间。你也许还注意到最后一个容器没有`flex`配置。相反，它有`height: 50`。`vbox`布局会解释这些值来按以下方式布局容器：

1.  由于我们有一个高度为`50`的组件，`vbox`布局将把这个组件的高度留为 50 像素。

1.  `vbox`布局然后将其他两个组件的`flex`值作为比例。在这个例子中，2:1。

1.  最终结果是在屏幕底部的一个 50 像素高的容器。其他两个容器将占据剩余的可用空间。顶部容器也将是中间容器两倍高。

为了使这些大小更清晰，我们还给每个容器添加了一个样式，以颜色背景并使其稍微突出。结果如下：

![使用 vbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_08.jpg)

这种布局在窗口大小调整时也会缩小和扩大，使其成为适应各种设备尺寸非常有效的布局。

## 使用 hbox 布局

`hbox`布局的运作方式几乎与`vbox`布局相同，不同之处在于`hbox`布局中的容器是从左到右排列的。

你可以通过复制我们之前的`vbox`示例并将其粘贴在我们`items`列表中的最后一个面板之后来添加一个具有`hbox`布局的面板（不要忘记在项目之间加上逗号）。

接下来，我们需要修改我们新面板中的几个配置：

+   将`title: 'VBox'`设置为`title: 'HBox'`

+   将`layout: 'vbox'`设置为`layout: 'hbox'`

+   在最后一个`container`中，将`height: 50`设置为`width: 50`

当你重新加载页面时，你应该能够点击**HBox**标签，并看到以下类似屏幕截图：

![使用 hbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_09.jpg)

你可以嵌套这些基本布局以以任何方式安排你的组件。我们还将介绍一些在第三章中样式化用户界面的方法*样式化用户界面*。

# 测试和调试应用程序

在测试应用程序时，首先要查找错误控制台的地方。在 Safari 中，从**开发**菜单中选择**显示错误控制台**。在 Chrome 中，从**查看**菜单中选择**开发者**，然后选择**JavaScript 控制台**。

![测试和调试应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_10.jpg)

## 解析错误

前一个屏幕截图中的错误控制台告诉我们两件非常重要的事情。首先，我们有一个**语法错误：解析错误**。这意味着代码中的某个地方，我们做了浏览器无法理解的事情。通常，这可能是因为：

+   忘记关闭一个括号、方括号或花括号，或者添加了一个多余的

+   在配置选项之间没有逗号，或者添加了多余的逗号

+   在变量声明的末尾遗漏了一个分号

+   没有关闭引号或双引号（也没有在必要的地方转义引号）

第二个重要信息是 **/app/TouchStart-4.js: 39**。它告诉我们：

+   **/app/TouchStart-4.js** 是发生错误的文件

+   **39** 是发生错误的行

使用这些信息，我们应该能够快速追踪到错误并修复它。

## 区分大小写

JavaScript 是一种区分大小写的语言。这意味着如果你输入`xtype: 'Panel'`，你将在错误控制台中得到以下内容：

**尝试创建一个具有未注册 xtype 的组件：Panel**

这是因为 Sencha Touch 期望`panel`而不是`Panel`。

## 丢失文件

另一个常见的问题是丢失文件。如果你没有正确地将你的`index.html`文件指向你的`sencha-touch-debug.js`文件，你会得到两个不同的错误：

+   **加载资源失败：服务器响应状态为 404（未找到）**

+   **引用错误：找不到变量：Ext**

第一个错误是关键信息；浏览器找不到您尝试包含的文件之一。第二个错误是由缺少的文件引起的，它简单地抱怨找不到`Ext`变量。在这种情况下，是因为缺少的文件是`sencha-touch-debug.js`，它首先设置了`Ext`变量。

## 网络检查器控制台

另一个对于调试应用程序非常有用的 Safari 网络检查器功能是控制台。在您的`app.js`文件中，添加以下命令：

```js
console.log('Creating Application');
```

在这行`Ext.Application`之前添加它：

```js
Ext.Application({
```

您应该在网页检查器的控制台标签中看到**创建应用**的文本。您还可以向控制台发送变量，以查看它们的 contents:

```js
console.log('My viewport: %o', Ext.Viewport);
```

如果您在`app.js`中的这行`Ext.Viewport.add(Ext.create('TouchStart.view.Main'));`之后放置这个控制台日志，控制台将显示完整的视图和所有嵌套的子组件。如果您有组件显示不正常的原因，这很有用。将对象发送到控制台允许您以 JavaScript 的方式查看对象。

### 注意

有关 Chrome 开发者工具的更多信息，请访问[`developers.google.com/chrome-developer-tools/`](https://developers.google.com/chrome-developer-tools/)。

如果您想了解更多关于使用 Safari 网络检查器调试您应用程序的信息，请访问苹果公司的*调试您的网站*页面：[`developer.apple.com/library/safari/#documentation/AppleApplications/Conceptual/Safari_Developer_Guide/DebuggingYourWebsite/DebuggingYourWebsite.html`](http://developer.apple.com/library/safari/#documentation/AppleApplications/Conceptual/Safari_Developer_Guide/DebuggingYourWebsite/DebuggingYourWebsite.html)。

# 为生产更新应用程序

当一个应用程序准备好投入生产时，通常需要进行许多步骤来准备和优化您的代码。这个过程包括压缩 JavaScript 以加快加载速度，优化图像，以及删除代码库中实际上您的应用程序不需要的部分。这可能是一个相当繁琐的过程，但 Sencha Cmd 将实际上用一个命令为您完成这个任务。

当您准备好更新您的应用程序以用于生产时，您可以打开您的命令行，并使用`cd`命令将您的代码根目录移动到：

```js
cd /path/to/my/application

```

一旦您进入该目录，您可以输入以下命令：

```js
sencha app build

```

此命令将在其中创建一个`build`目录，里面有您应用程序的优化版本。您可以测试这个优化版本是否有任何错误。如果您需要更改应用程序，您可以对未优化的代码进行更改，然后再次运行`build`命令。

一旦您对代码构建感到满意，就可以将应用程序投入生产。

# 将应用程序投入生产

既然你已经编写了并测试了你的应用程序并为其生产做好了准备，我们需要弄清楚我们的代码将存放在哪里。由于将应用程序投入生产的方法将根据您的设置而有所不同，我们将非常一般性地介绍这个任务。

首先要熟悉将应用程序投入生产的三个基本部分：

+   网页托管

+   文件传输

+   文件夹结构

虽然在本地的 Web 服务器上开发应用程序是可以的，但如果您想让其他人看到它，您需要一个可以持续连接到互联网的公共可访问的 Web 服务器。有许多网页托管提供商，例如 GoDaddy、HostGator、Blue Host、HostMonster 和 RackSpace。

由于我们的应用程序是纯 HTML/JavaScript/CSS，您不需要任何花哨的插件，例如数据库或服务器端编程语言（PHP 或 Java），在您的网页托管账户中。任何能够提供 HTML 页面的账户都足够了。这个决定的关键应该是客户支持。在选择提供商之前，确保检查评论。

托管提供商还将提供有关设置您的域名并将您的文件上传到 Web 服务器的信息。确保为将来参考保留好您的用户名和密码。

为了将您的应用程序复制到您的网页托管账户，你可能需要熟悉一个**FTP**（**文件传输协议**）程序，例如**FileZilla**。与托管提供商一样，FTP 程序的选择非常多。它们中的大多数遵循一些基本规范。

一开始，您需要使用 FTP 程序连接到 Web 服务器。为此，您需要以下内容：

+   Web 服务器的名称或 IP 地址

+   您的网页托管用户名和密码

+   Web 服务器的连接端口

您的网页托管提供商应该在您注册时提供这些信息。

![将应用程序投入生产](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_02_11.jpg)

一旦您连接到服务器，您将看到您本地机器上的文件列表以及您远程 Web 服务器上的文件。您需要将**TouchStart**文件拖到远程服务器上以进行上传。您的托管提供商还将为您提供这些文件需要去的特定文件夹的名称。该文件夹通常称为`httpd`、`htdocs`、`html`或`public_html`。

这让我们考虑上传文件的最后一件事情：文件夹路径。

文件夹路径会影响应用程序定位其文件和资源的方式。当您将应用程序上传到远程 Web 服务器时，它可能会影响应用程序内部如何查看您的文件夹。如果您有从绝对路径引用的任何文件，例如`http://127.0.0.1/~12ftguru/TouchStart/myfile.js`，那么在您将东西移到 Web 服务器上时，文件将无法工作。

即使相对路径在将文件传输到远程服务器时也可能出现问题。例如，如果你有一个使用路径`/TouchStart/myFile.js`的文件，而你上传了`TouchStart`文件夹的内容而不是上传整个文件夹，文件路径将会错误。

如果你发现自己遇到图片缺失错误或其他错误，这是一个需要记住的事情。

再次强调，你的网页托管服务商是你获取信息最好的资源。一定要寻找*入门指南*文档，并且不要害怕在任何用户论坛寻求帮助，这些论坛你的托管服务商可能会有。

# 摘要

在这一章，我们使用 Sencha Cmd 创建了第一个简单应用。我们了解了一些 Sencha Touch 组件的基本知识，包括配置和组件之间的嵌套。我们向你介绍了`TabPanel`、`Panel`和`Container`组件。此外，我们解释了一些基本的调试方法，并为我们应用的生产准备好了。

在下一章，我们将通过使用 SASS 和 Sencha Touch 库的样式工具为我们的应用创建一个自定义主题。


# 第三章：用户界面样式

现在我们已经了解了应用程序是如何组合在一起的，接下来我们将看看您可以使用的一些不同的视觉元素来定制您的应用程序。在本章中，我们将：

+   仔细观察工具栏和按钮，使用布局，以及其他样式和图标来提升用户界面的视觉吸引力

+   扩展我们之前关于图标的工作；这包括使用 Pictos 图标字体显示新图标

+   讨论与不同设备和屏幕尺寸一起工作时的一些考虑和捷径

+   使用 Sass 和 Compass 探索极其强大的 Sencha 主题引擎，以简单 CSS 样式命令创建复杂的视觉皮肤

# 样式组件与主题

在我们进入本章之前，了解样式化单个组件与创建主题之间的区别非常重要。

几乎 Sencha Touch 中的每一个显示组件都有设置自身样式的选项。例如，`panel`组件可以这样使用样式：

```js
{ 
 xtype: 'panel',
 style: 'border: none; font: 12px Arial black',
 html: 'Hello World'
}
```

样式也可以使用如下方式作为对象设置：

```js
{ 
 xtype: 'panel',
style : {
  'border' : 'none',
  'font' : '12px Arial black',
  'border-left': '1px solid black'
} 
html: 'Hello World'
}
```

### 提示

您会注意到在`style`块内部，我们对配置设置的两边都进行了引用。这仍然是 JavaScript 的正确语法，并且使用`style`块时这是一个非常好的习惯。这是因为许多标准 CSS 样式在其名称中使用连字符。如果我们不对`border-left`添加引号，JavaScript 会将此读作`border`减去`left`，并立即在错误堆中崩溃。

我们还可以为组件设置一个`style`类，并使用外部 CSS 文件如下定义该类：

```js
{ 
 xtype: 'panel',
 cls: 'myStyle',
 html: 'Hello World'
}
```

您的外部 CSS 文件可以以如下方式控制组件的样式：

```js
.myStyle {
 border: none;
 font: 12px Arial black;
}
```

这种基于类的显示控制被认为是最佳实践，因为它将样式逻辑与显示逻辑分开。这意味着当您需要更改边框颜色时，可以在一个文件中完成，而不是在多个文件中寻找单独的`style`设置。

这些样式选项对于控制个别组件的显示非常有用。还有一些样式元素，如边框、内边距和外边距，可以直接在组件的配置中设置：

```js
{ 
 xtype: 'panel',
 bodyMargin: '10 5 5 5',
 bodyBorder: '1px solid black',
 bodyPadding: 5,
 html: 'Hello World'
}
```

这些配置可以接受一个数字以应用于所有边，或者是一个 CSS 字符串值，如`1px solid black`或`10 5 5 5`。数字应不带引号输入，但 CSS 字符串值需要在引号内。

这些小的更改在样式化您的应用程序时可能会有所帮助，但如果您需要做一些更大的事情呢？如果您想要更改整个应用程序的颜色或外观呢？如果想要为按钮创建自己的默认样式呢？

这就是主题和 UI 样式发挥作用的地方。

# 工具栏和按钮的 UI 样式

让我们快速回顾一下在第二章，*创建一个简单应用程序*中创建的基本 MVC 应用程序，并使用它开始探索带有工具栏和按钮的样式。

首先，我们将向第一个面板添加一些内容，该面板包含我们的`titlebar`、`toolbar`和**你好世界**文本。

## 添加工具栏

在`app/views`中，你会发现`Main.js`。打开编辑器中的这个文件，看看我们项目列表中的第一个面板：

```js
items: [
  {
      title: 'Hello',
      iconCls: 'home',
      xtype: 'panel',
      html: 'Hello World',
      items: [
         {
            xtype: 'titlebar',
            docked: 'top',
            title: 'About TouchStart'
         }
     ]
  }...
```

我们将在现有工具栏的顶部添加第二个工具栏。定位`items`部分，在第一个工具栏的花括号后添加第二个工具栏，如下所示：

```js
{

 xtype: 'titlebar', 
 docked: 'top',
 title: 'About TouchStart'
}, {
 docked: 'top',
 xtype: 'toolbar',
 items: [
  {text: 'My Button'}
 ]}
```

不要忘记在两个工具栏之间加上逗号。

### 提示

**多余或缺少的逗号**

在 Sencha Touch 中工作时，导致解析错误的最常见原因之一是多余或缺少逗号。当你移动代码时，请确保你已经考虑到了任何散落或丢失的逗号。幸运的是，对于这些类型的解析错误，Safari 错误控制台通常会给我们一个关于查看哪一行的好主意。一个更详细的常见错误列表可以在以下网址找到：

[`javascript.about.com/od/reference/a/error.htm`](http://javascript.about.com/od/reference/a/error.htm)

现在当你查看第一个标签页时，你应该看到我们新的工具栏，以及左侧的新按钮。由于两个工具栏都有相同的背景，它们有点难以区分。所以，我们将使用`ui`配置选项更改底栏的外观：

```js
{
 docked: 'top',
 xtype: 'toolbar',
 ui: 'light',
 items: [
  {text: 'My Button'}
 ]
}
```

`ui`配置是 Sencha Touch 中特定样式集的简写。Sencha Touch 包含几个`ui`样式，我们将在本章后面向您展示如何创建自己的样式。

![添加工具栏](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_01.jpg)

## 样式按钮

按钮也可以使用`ui`配置设置，为此它们提供了几个不同的选项：

+   `normal`：这是默认按钮

+   `back`：这是一个左侧缩成一点的按钮

+   `round`：这是一个更急剧圆角的按钮

+   `small`：这是一个更小的按钮

+   `action`：这是一个默认按钮的更亮版本（颜色根据主题的活跃颜色而变化，我们稍后会看到）

+   `forward`：这是一个右侧缩成一点的按钮

按钮还内置了一些`ui`选项的颜色。这些颜色选项是`confirm`和`decline`。这些选项与前面的形状选项结合使用连字符；例如，`confirm-small`或`decline-round`。

让我们添加一些新按钮，看看这些按钮在我们的屏幕上看起来如何。在第二个工具栏中找到带有按钮的`items`列表：

```js
items: [
  {text: 'My Button'}
]
```

用以下新的`items`列表替换那个旧的`items`列表：

```js
items: [
 {
  text: 'Back',
  ui: 'back'
 }, {
  text: 'Round',
  ui: 'round'
 }, {
  text: 'Small',
  ui: 'small'
 }, {
  text: 'Normal',
  ui: 'normal'
 }, {
  text: 'Action',
  ui: 'action'
 }, {
  text: 'Forward',
  ui: 'forward'
 }
]
```

这将在工具栏顶部产生一系列按钮。正如您所注意到的，我们的所有按钮都靠左对齐。您可以通过在您想要推向右边的按钮前面添加一个`spacer` xtype 来将按钮移到右边。尝试通过在我们`Forward`和`Action`按钮之间添加以下内容来实现：

```js
{ xtype: 'spacer'},
```

这将使`Forward`按钮移动到工具栏的右侧：

![按钮样式](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_02.jpg)

由于按钮实际上可以任何地方使用，我们可以在我们的标题栏添加一些按钮，并使用`align`属性来控制它们出现的位置。修改我们第一个`panel`的`titlebar`，并添加一个`items`部分，如下面的代码所示：

```js
{
  xtype: 'titlebar',
  docked: 'top',
  title: 'About TouchStart',
  items: [
    {
      xtype: 'button',
      text: 'Left',
      align: 'left'
    },
    {
      xtype: 'button',
      text: 'Right',
      align: 'right'
    }
  ]
}
```

现在我们标题栏应该有两个按钮，一个在标题的每一边：

![按钮样式](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_03.jpg)

我们还在`panel`容器中添加一些按钮，以便我们可以看到`ui`选项`confirm`和`decline`的样子。

在我们`HelloPanel`容器的`items`部分末尾，位于第二个工具栏后面添加以下内容：

```js
{
 xtype: 'button',
 text: 'Confirm',
 ui: 'confirm',
 width: 100
}, {
 xtype: 'button',
 text: 'Decline',
 ui: 'decline',
 width: 100
}
```

您可能会注意到，我们的面板按钮和工具栏按钮之间有两个不同之处。第一个是我们在我们面板中声明了`xtype:'button'`，但在我们的工具栏中没有声明。这是因为工具栏假设它将包含按钮，而`xtype`只有在您使用除按钮之外的内容时才需要声明。面板没有设置默认的`xtype`属性，所以面板中的每个项目都必须声明一个。

第二个区别是我们为按钮声明了`width`。如果我们不在面板中使用按钮时声明`width`，它将扩展到面板的整个宽度。在工具栏上，按钮会自动调整大小以适应文本。

![按钮样式](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_04.jpg)

您还会注意到我们面板中的两个按钮粘在一起。您可以通过为每个按钮配置部分添加`margin: 5`来将它们分开。

这些简单的样式选项可以帮助使您的应用程序更易于导航，并为用户提供了关于重要或潜在破坏性操作的视觉提示。

## 标签栏

底部的标签栏也理解`ui`配置选项。在这种情况下，可用的选项是`light`和`dark`。标签栏还根据`ui`选项改变图标的外观；`light`工具栏将具有深色图标，而`dark`工具栏将具有浅色图标。

这些图标实际上是名为**Pictos**的特殊字体的一部分。Sencha Touch 从版本 2.2 开始使用 Pictos 字体，以解决某些移动设备上的兼容性问题，而不是使用图像图标。

### 注意

来自 Sencha Touch 先前版本的图标遮罩可用，但已在 2.2 版本中被弃用。

您可以在`Ext.Button`组件的文档中看到一些可用的图标：

[`docs.sencha.com/touch/2.2.0/#!/api/Ext.Button`](http://docs.sencha.com/touch/2.2.0/#!/api/Ext.Button)

如果你对 Pictos 字体感到好奇，你可以通过访问[`pictos.cc/`](http://pictos.cc/)了解更多相关信息。

# Sencha Touch 主题

有时候你希望不仅仅改变一个单个的面板或按钮的外观。Sencha Touch 主题是快速改变应用程序整体外观和感觉的强大方式。我们将在本章后面覆盖主题化过程，但在开始之前我们需要做一些基础工作。需要覆盖的概念信息很多，但你所获得的灵活性将是值得努力的。

我们需要覆盖的第一个工具是 Sencha Touch 中用于使应用程序主题化可能的工具：Sass 和 Compass。

### 注意

如果你已经熟悉 Sass 和 Compass，你将会更舒适地先安装然后再覆盖概念。你可以跳到*设置 Sass 和 Compass*部分。

## 介绍 Sass 和 Compass

**Syntactically Awesome Stylesheets** (**Sass**)用于扩展标准 CSS，允许变量、嵌套、混合函数、内置函数和选择器继承。这意味着你的所有常规 CSS 声明都会正常工作，但你也会得到一些额外的福利。

### 在 Sass 中的变量

变量允许你定义具体的值，然后在样式表中使用它们。变量名称是任意的，以`$`开始。例如，我们可以使用 Sass 定义以下内容：

```js
$blue: #4D74C1;
$red: #800000;
$baseMargin: 10px;
$basePadding: 5px;
```

我们可以在 Sass 文件中的标准 CSS 声明中使用以下变量：

```js
.box1 {
border: 1px solid $blue;
padding: $basePadding;
margin: $baseMargin;
}
```

我们还可以按照以下方式使用基本数学函数：

```js
.box2 {
border: 1px solid $blue;
padding: $basePadding * 2;
margin: $baseMargin / 2;
}
```

这将创建一个具有两倍内边距和原始盒子一半外边距的盒子。这对于创建灵活、可扩展的布局非常不错。通过更改你的基本值，你可以快速扩展你的应用程序以应对具有多种分辨率和屏幕尺寸的多台设备。

另外，当你决定要更改你使用的蓝色阴影时，你只需要在一个地方更改。Sass 还有许多内置函数用于调整颜色，例如：

+   `darken`: 这个函数通过百分比使颜色变暗

+   `lighten`: 这个函数通过百分比使颜色变亮

+   `complement`: 这个函数返回互补色

+   `invert`: 这个函数返回反色

+   `saturate`: 这个函数通过数值来饱和颜色

+   `desaturate`: 这个函数通过数值来去色

这些函数允许你执行操作，例如：

```js
.pullQuote {
border: 1px solid blue;
color: darken($blue, 15%);
}
```

还有针对数字、列表、字符串和基本 if-then 语句的函数。这些函数可以帮助你的样式表像你的编程代码一样灵活。

### 小贴士

**Sass 函数**

Sass 函数的完整列表可以在[`sass-lang.com/docs/yardoc/Sass/Script/Functions.html`](http://sass-lang.com/docs/yardoc/Sass/Script/Functions.html)找到。

### Sass 中的混合函数

**混合函数**是 Sass 变量标准的一种变体。避免简单地声明一个一对一的变量，例如以下内容：

```js
$margin: 10px;
```

相反，你可以使用混合（mixin）来声明一个整个 CSS 类作为变量：

```js
@mixin baseDiv {
 border: 1px solid #f00;
 color: #333;
 width: 200px;
} 
```

然后你可以把这个混合（mixin）用在 Sass 文件中：

```js
#specificDiv {
 padding: 10px;
 margin: 10px;
 float: right;
 @include baseDiv;
}
```

这给了你 `baseDiv` 混合（mixin）组件的所有属性和在 `#specificDiv` 类中声明的具体样式。

你还可以让你的混合（mixin）使用参数来使其更加灵活。让我们看看我们之前看到的内容的一个替代版本：

```js
@mixin baseDiv($width, $margin, $float) {
 border: 1px solid #f00;
 color: #333;
 width: $width;
 margin: $margin;
 float: $float;
}
```

这意味着我们可以在 Sass 代码中为 `width`、`margin` 和 `float` 设置值，如下所示：

```js
#divLeftSmall {
 @include baseDiv(100px, 10px, left);
}
#divLeftBig{
 @include baseDiv(300px, 10px, left);
}
#divRightBig {
 @include baseDiv(300px, 10px, right);
}
#divRightAlert {
 @include baseDiv(100px, 10px, right);
 color: #F00;
 font-weight: bold;
}
```

这给了我们四个带有稍有不同的属性的 `div` 标签。它们都共享与混合（mixin） `baseDiv` 类相同的基属性，但它们的 `width` 和 `float` 值是不同的。我们也可以通过在我们包含混合（mixin）时像在我们的 `#divRightAlert` 示例中添加它们来覆盖混合（mixin） `baseDiv` 的值。

### Sass 中的嵌套

Sass 也允许嵌套 CSS 声明。这不仅能让你写出的样式更紧密地反映你的 HTML 结构，而且还能写出更清晰、更容易维护的代码。

在 HTML 中，我们经常嵌套彼此之间的元素以给文档结构。这种的一个常见例子是一个无序列表包含几个列表项，如下所示：

```js
<ul>
 <li>Main List Item 1</li>
 <li>Main List Item 2</li>
</ul>
```

通常，通过 CSS 样式这个列表，你会分别写 `ul` 元素的规则和 `li` 元素的规则。这两个规则在你的 CSS 文件中可能相隔很远，使得调试或修改样式更加困难。

在 Sass 中，我们可以写如下内容：

```js
ul {
 width: 150px;
 border: 1px solid red;

 li {
  margin: 1px;
  border: 1px solid blue;
 }

}
```

看看我们是怎样在 `ul` 的样式声明内嵌套 `li` 元素的样式声明的？嵌套不仅匹配 HTML 文档的结构，而且还能让你知道当需要更新 `li` 元素时，它是在 `ul` 元素内的。

当你用 Sass 编译这个时，生成的 CSS 为 `ul` 和 `li` 元素有分开的规则：

```js
ul {
 width: 150px;
 border: 1px solid red;
}
ul li {
 margin: 1px;
 border: 1px solid blue;
}
```

如果你在浏览器中查看这个列表，你会看到一个有红色边框的列表，每个单独的列表项周围还有蓝色边框。

![Sass 中的嵌套](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_05.jpg)

使用和号（`&`）字符引用嵌套层级中的一级也是可能的。这在给嵌套元素添加悬停状态等事物时很有用，或者更一般地说，将你的规则的异常分组在一起。

假设我们想要在鼠标悬停在 `li` 元素上时改变背景色。我们可以在 `li` 样式声明内添加 `&:hover`：

```js
ul {
 width: 150px;
 border: 1px solid red;

 li {
  margin: 1px;
  border: 1px solid blue;

  &:hover {
   background-color: #B3C6FF;
  }

 }

}
```

Sass 编译器将 `&:hover` 转换为 `li:hover`：

```js
ul li:hover {
 background-color: #B3C6FF;
}
```

和号（`&`）特殊字符不必用在规则的开始处。比如说你的设计师有元素 `li`，当它们位于特殊的 `#sidebardiv` 组件内时，使用更大的边框。你可以在 `ul`/`li` 规则之后写一个单独的规则，或者使用特殊的 `&` 字符在 `li` 规则集中添加这个异常：

```js
ul {
 li {
  margin: 1px;
  border: 1px solid blue;

  &:hover {
   background-color: #B3C6FF;
  }
  div#sidebar& {
   border-width: 3px;
  }
 }
}
```

前面的代码将被翻译成以下规则：

```js
div#sidebar ul li { border-width: 3px; }
```

你也可以嵌套 CSS 命名空间。在 CSS 中，如果属性全部以相同的前缀开始，比如`font-`，那么你也可以嵌套它们：

```js
li {
 font: {
  family: Verdana;
  size: 18px;
  weight: bold;
 }
}
```

一定要记得在命名空间后面加上冒号。编译后，这将变为以下内容：

```js
li {
 font-family: Verdana;
 font-size: 18px;
 font-weight: bold;
}
```

这个方法适用于任何命名空间 CSS 属性，如`border-`或`background-`。

### Sass 中的选择器继承

Sass 中的选择器继承与 JavaScript 中的对象继承类似。同样，一个`panel`组件扩展了`container`对象，这意味着一个`panel`具有`container`的所有属性和功能，还有一些别的。Sass 让您拥有继承其他对象样式的对象。

假设我们想要为我们的应用程序创建一些消息框元素，一个用于信息性消息，一个用于错误。首先，我们需要定义一个通用框：

```js
.messageBox {
  margin: 10px;
  width: 150px;
  border: 1px solid;
  font: {
   size: 24px;
   weight: bold;
  }
}
```

现在，在任何我们想要包含`.messageBox`样式的类中，我们只需使用`@extend`指令`@extend .messageBox;`（单独一行）：

```js
.errorBox {
 @extend .messageBox;
 border-color: red;
 color: red;
}

.infoBox {
 @extend .messageBox;
 border-color: blue;
 color: blue;
}
```

然后，在 HTML 中，我们只需使用`.errorBox`和`.infoBox`类即可：

```js
<div class="infoBox">Here's some information you may like to have.</div>
<div class="errorBox">An unspecified error has occurred.</div>
```

把所有内容放在一起，你就会看到左边的盒子有一个蓝色的边框和蓝色的文本，右边的盒子有一个红色的边框和红色的文本：

![Sass 中的选择器继承](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_06.jpg)

### 指南针

正如 Sencha Touch 是建立在 JavaScript、CSS 和 HTML 这些低级语言之上的框架一样，Compass 也是建立在 Sass 和 CSS 之上的框架。Compass 为您应用程序的样式提供了一系列可重用的组件。这些包括：

+   **CSS 重置**：这能强制大多数 HTML 在所有主流网络浏览器中具有一致的外观。

+   **混合**：这些允许你为你的 CSS 声明复杂的程序化函数。

+   **布局和网格**：这些强制执行宽度和高度标准，以帮助保持跨所有页面的一致布局。

+   **图像雪碧**：这允许您自动从多个小图像生成单个图像（这对于浏览器下载来说更快）。CSS 将自动显示您需要的图像部分，隐藏其余部分。

+   **文本替换**：这允许您自动交换文档中特定文本片段。

+   **排版**：这为在您的网页中使用字体提供了高级选项。

Compass 还将其组件中融入最新的 CSS 最佳实践，这意味着你的样式表将会更简洁、更高效。

### Sass + Compass = 主题

Sencha Touch 主题通过提供变量和混合器，其功能性特定于 Sencha Touch，将 Sass 和 Compass 推进了一步。Sencha Touch 的 JavaScript 部分生成大量非常复杂的 HTML，以显示各种组件，如工具栏和面板。而不是学习所有 Sencha Touch 使用的复杂类和 HTML 技巧，你可以简单地使用适当的混合器来改变应用程序的外观。

# 设置 Sass 和 Compass

如果您决定要创建自己的 Sencha Touch 主题，则不需要安装 Sass 或 Compass，因为它们都包含在 Sencha Cmd 中。

然而，Windows 用户首先需要安装 Ruby。Ruby 用于将 Sass/Compass 文件编译成可用的主题。Linux 和 OS X 用户应该已经在他们的计算机上安装了 Ruby。

## 在 Windo

从[`rubyinstaller.org/`](http://rubyinstaller.org/)下载 Ruby 安装程序。

### 提示

我们建议下载版本 1.9.2，因为 Sencha Cmd 可能会与 Ruby 的新版本发生问题。

运行安装程序，并按照屏幕上的说明安装 Ruby。确保检查名为**将 Ruby 可执行文件添加到您的 PATH 中**的框。这将在以后命令行中为您节省很多输入。

安装完成后，打开 Windows 中的命令行，通过前往**开始** | **运行**，输入`cmd`，并按*Enter*键。这应该会打开命令行。

现在，尝试输入**ruby -v**。您应该会看到如下内容：

```js
C:\Ruby192>ruby -v
ruby 1.9.2p180 (2011-02-18) [i386-mingw32]

```

这意味着 Ruby 已经正确安装。

# 创建自定义主题

接下来我们需要做的是创建我们自己的主题 SCSS 文件。在`TouchStart/resources/sass`中找到`app.scss`文件，并复制该文件。将新复制的文件重命名为`myTheme.scss`。

更改文件名后，您需要将主题编译成应用程序可以读取的实际 CSS 文件。为此，我们需要回到命令行，移动到我们的`TouchStart/resources/sass`目录：

```js
cd /path/to/TouchStart/resources/sass

```

一旦进入目录，您可以输入以下命令：

```js
compass compile

```

这将编译我们新的主题，并在`resources/css`目录下创建一个名为`myTheme.css`的新文件。

### 提示

使用`compass compile`将目录中的任何`.scss`文件编译。每次更改`.scss`文件时，您都需要运行此命令。不过，您也可以使用命令`compass watch`来监视当前文件夹的任何更改，并自动编译它们。

既然我们已经有了新的 CSS 主题文件，接下来需要让应用程序加载它。在 Sencha Touch 的早期版本中，CSS 文件是从`index.html`文件中加载的。然而，由 Sencha Cmd 生成的应用程序实际上是从我们主`TouchStart`目录中的`app.json`文件中加载 CSS 文件的。

打开`app.json`，查找如下部分：

```js
"css": [
  {
     "path": "resources/css/app.css",
     "update": "delta"
  }
]
```

将此部分更改为：

```js
"css": [
  {
    "path": "resources/css/myTheme.css",
    "update": "delta"
  }
]
```

### 提示

**SCSS 和 CSS**

请注意，我们目前从`css`文件夹中包含了一个名为`sencha-touch.css`的样式表，并且在`scss`文件夹中有一个匹配的文件，名为`sencha-touch.scss`。当编译 SCSS 文件时，它们将在您的`css`文件夹中创建一个新文件。这个新文件将具有`.css`后缀，而不是`.scss`。

`.scss`是 Sass 文件的文件扩展名。

如果您在网页浏览器中重新加载应用程序，您将看不到任何变化，因为我们只是为我们的主题复制了文件。让我们看看我们如何改变这一点。打开您的`myTheme.scss`文件。您应该看到以下内容：

```js
@import 'sencha-touch/default';
@import 'sencha-touch/default/all';
```

这段代码抓取了所有默认的 Sencha Touch 主题信息。当我们运行`compass compile`或`compass watch`时，它会被编译并压缩成一个 CSS 文件，我们的应用程序可以阅读。

最好的部分是我们现在可以用一条代码就改变应用程序的整体颜色方案。

## 基本颜色

Sencha Touch 主题中的一个关键变量是`$base_color`。这个颜色及其变体在整个主题中都有使用。为了了解我们的意思，让我们将主题的颜色改为漂亮的森林绿，方法是在我们的`myTheme.scss`文件的顶部添加以下内容（在所有其他文本之上）：

```js
$base_color: #546346;
```

接下来，我们需要重新编译 Sass 文件以创建我们的`myTheme.css`文件。如果您正在运行`compass watch`，当您保存 Sass 文件时这将自动发生。如果没有，您需要像以前一样运行`compass compile`来更新 CSS（请记住，您需要从`resources/sass`目录中运行此命令）。

### 提示

**Compass 编译与 Compass 监控**

Compass 使用`compile`命令根据您的 SCSS 文件创建新的样式表。然而，您还可以设置 Compass 监控特定文件的更改，并在添加任何新内容时自动编译文件。这个命令在命令行中如下输入：

```js
compass watch filename

```

这个命令将一直保持活动状态，直到您的终端关闭。一旦您关闭终端窗口，您需要再次运行该命令，以便让 Compass 监控更改。

在 Safari 中重新加载页面，您应该看到我们应用程序的新森林绿色外观。

请注意，这一行代码为我们的深色和浅色工具栏创建了变体。更改基本颜色还改变了底部的标签栏图标。

这很酷，但如果我们要调整主题的个别部分呢？Sencha Touch 主题通过混合和`ui`配置选项为我们提供了 exactly 需要。

## 混合与 UI 配置

如我们之前提到的，Sencha 主题系统是一组预定义的混合和变量，它们被编译成 CSS 样式表。每个组件都有自己的混合和变量来控制样式。这意味着您可以覆盖这些变量或使用混合来定制您自己的主题。

您还可以使用混合（mixins）为`ui`配置选项创建额外选项（超出我们之前见过的简单的`light`和`dark`值）。例如，我们可以在`myTheme.sass`文件中添加一个新的混合来修改我们工具栏的颜色。

在我们的`myTheme.sass`文件中，找到如下行：

```js
@import 'sencha-touch/default/all';
```

在此行之后，添加以下行：

```js
@include sencha-toolbar-ui('subnav', #625546, 'matte');
```

这行代码告诉 Sass 为工具栏创建一个新的`ui`选项。我们新的选项将被称为`subnav`，它将具有`#625546`的基础颜色。最后一个选项设置了渐变的样式。可用的样式有：

+   `flat`：无渐变

+   `matte`：一个细微的渐变

+   `bevel`：一个中等渐变

+   `glossy`：一个玻璃样式渐变

+   `recessed`：一个反转的渐变

你可以在 Sencha Touch 文档的每个组件顶部找到有关这些变量（和任何可用的混合剂）的额外信息：[`docs.sencha.com/touch/2.2.0/`](http://docs.sencha.com/touch/2.2.0/)。

![混合剂和 UI 配置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_07.jpg)

保存文件后，你需要在命令行使用`compass compile`命令重新编译样式表。

我们还需要更改 JavaScript 文件中的`ui`配置选项。在`app/view`文件夹中找到我们的`Main.js`文件并打开它。找到我们应用程序中的第二个工具栏，就在我们添加按钮的上方。它应该如下所示：

```js
dock: 'top',
xtype: 'toolbar',
ui: 'light'
```

你需要将`ui:'light'`改为`ui:'subnav'`并保存文件。

然后你可以重新加载页面以查看你的更改。

![混合剂和 UI 配置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_08.jpg)

你还会注意到，工具栏内的按钮也调整了它们的颜色以匹配新工具栏的`ui`配置。

## 添加新图标

如我们在本章开头提到的，Sencha Touch 的早期版本使用图标遮罩来创建应用程序中的图标。这导致了一些与浏览器兼容性问题，所以新图标实际上是从 Pictos 图标字体生成的。默认情况下，包含这 26 个图标，但你可以使用`icon`混合剂添加更多。

### 注意

Sencha Touch 中可用的默认图标列表可以在[`docs.sencha.com/touch/2.2.0/#!/api/Ext.Button`](http://docs.sencha.com/touch/2.2.0/#!/api/Ext.Button)找到。

Pictos 图标的完整列表可以在[`pictos.cc/font/`](http://pictos.cc/font/)找到。

在你的`myTheme.sass`文件中，找到写着以下内容的行：

```js
@import 'sencha-touch/default/all';
```

此行之后，请添加以下内容：

```js
@include icon('camera', 'v'); 
```

`icon`混合剂有两个参数：你想要引用图标的名称（这是任意的）以及 Pictos 字体中图标的相应字母。第二个参数可以在前面提示中提到的 Pictos 网站上查找。

样式表重新编译后，我们可以在面板中更改`iconCls`值以使用新图像。

在`app/Main.js`文件中，找到我们的`HBox`面板的`iconCls`，目前显示为：

```js
iconCls: 'info',
```

用以下内容替换该行：

```js
iconCls: 'camera',
```

保存你的更改并重新加载页面以查看你的新图标。不要忘记在命令行使用`compass compile`重新编译 Sass 文件。

## 变量

变量也适用于大多数组件，并用于控制特定的颜色、大小和外观选项。与混合剂不同，变量针对组件的单一设置。例如，`button`组件包括以下变量的变量：

+   `$button-gradient`：所有按钮的默认渐变

+   `$button-height`：所有按钮的默认高度

+   `$button-radius`：所有按钮的默认边框半径

+   `$button-stroke-weight`：所有按钮的默认边框厚度

如前所述，您可以在每个组件的顶部找到这些变量（和任何可用的混合）的列表，在 Sencha Touch 文档中[`docs.sencha.com/touch/2.2.0/`](http://docs.sencha.com/touch/2.2.0/)。

例如，如果我们向我们的`myTheme.scss`文件添加`$button-height: 2em;`，然后我们可以重新编译并看到我们工具栏中的按钮现在比之前要大。

![变量](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_09.jpg)

您还会注意到我们的**小型**按钮大小没有改变。这是因为它的 UI 配置（`small`）已经单独定义，并包括了一个特定的高度。如果您想更改这个按钮的大小，您需要在`Main.js`文件中删除它的`ui`配置。

## 更多 Sass 资源

使用 Sencha Touch 主题中包含的混合和变量，您可以几乎改变界面的任何方面，使其完全按照您想要的方式显示。有许多在线资源可以帮助您深入了解 Sass 和 Compass 的所有可能性。

### 注意

**更多资源**

Sencha Touch 主题混合和变量的完整列表可在[`dev.sencha.com/deploy/touch/docs/theme/`](http://dev.sencha.com/deploy/touch/docs/theme/)找到。

详细了解 Sass，请访问[`sass-lang.com/`](http://sass-lang.com/)。

Compass 官网提供了使用 Compass 的网站示例、教程、帮助等内容；您可以访问[`compass-style.org/`](http://compass-style.org/)。

# 默认主题和主题切换

随着 Sencha Touch 2.2 的推出，现在支持 Blackberry 10 和 Windows Phone 平台。为了帮助您为这些平台样式化您的应用程序，Sencha Touch 2.2 包括两个平台的默认主题。让我们通过创建几个新的主题文件来了解这是如何工作的。

首先，将我们的原始`resources/sass/app.scss`文件复制两份，并将它们重命名为`windows.scss`和`blackberry.scss`。

在两个文件中，找到以下行：

```js
@import 'sencha-touch/default';
@import 'sencha-touch/default/all';
```

在`windows.scss`中，将行更改为：

```js
@import 'sencha-touch/windows';
@import 'sencha-touch/windows/all';
```

在`blackberry.scss`中，将行更改为：

```js
@import 'sencha-touch/bb10';
@import 'sencha-touch/bb10/all';
```

接下来，您需要运行`compass compile`以创建新的 CSS 文件。

现在我们可以使用我们的`app.json`文件根据应用程序运行的平台来切换这些主题。打开`app.json`文件，再次查找我们的`css`部分。它应该如下所示：

```js
"css": [
        {
            "path": "resources/css/myTheme.css",
            "update": "delta"
        }
    ]
```

让我们将其更改为如下所示：

```js
"css": [
 {
  "path": "resources/css/myTheme.css",
  "platform": ["chrome", "safari", "ios", "android", "firefox"],
  "theme": "Default",
  "update": "delta"
 },
 {
  "path": "resources/css/windows.css",
  "platform": ["ie10"],
  "theme": "Windows",
  "update": "delta"
 },
 {
  "path": "resources/css/blackberry.css",
  "platform": ["blackberry"],
  "theme": "Blackberry",
  "update": "delta"
 }
   ]
```

由于我们大多数人并不富有，我们可能没有每种类型的设备来测试。然而，我们可以在我们应用程序 URL 的末尾添加一个参数，以测试我们的每个主题。例如：

[`myapplication.com?platform=ie10`](http://myapplication.com?platform=ie10)

这将会在应用程序中自动处理，但我们可以通过向 URL 添加这个参数来测试我们的应用程序。我们应该现在有了基于平台的三种不同的主题。

![默认主题和主题切换](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_10.jpg)

我们可以根据这些三个选项之外的条件来制作这些条件主题。可用的平台有：

+   电话、平板电脑和桌面

+   iOS、Android 和 Blackberry

+   Safari、Chrome、IE 10 和 Firefox

这意味着我们可以根据前面列表中提到的任何平台来更改样式。只需生成新的 Sass/CSS 样式表，并在`app.json`中包含适当的配置行，就像之前的示例一样。

这类条件样式的微调将帮助您的应用程序在多种设备上保持可读性和易用性。

# 使用 Sencha.io Src 在不同设备上的图片

如果您的应用程序使用图片，那么您可能需要比前面部分使用的条件样式更健壮的东西。为每个设备创建单独的图片集将是一场噩梦。幸运的是，Sencha 的团队对这个问题的解决办法是一个名为`Sencha.io Src`的基于 Web 的服务。

`Sencha.io Src`是 Sencha 的一个独立服务，可以用于任何基于 Web 的应用程序。该服务通过获取原始图片并实时调整大小以适应当前设备和屏幕大小来工作。这些图片也被服务缓存并优化，以便快速、重复交付。要使用`Sencha.io Src`服务，您需要更改的只是图片的 URL。

例如，一个基本的 HTML 图片标签看起来像这样：

```js
<img src="img/my-big-image.jpg">
```

使用`Sencha.io Src`服务的同一个图片标签看起来像这样：

```js
<img src="img/my-big-image.jpg">
```

这个过程会将您图片的实际 URL 传递给系统进行处理。

### 注意

**Sencha.io Src 中的图片 URL**

正如您在示例中看到的，我们使用了一个完整的图片 URL（带有[`www.mydomain.com/`](http://www.mydomain.com/)），而不是一个更短的相对 URL（例如`/images/my-big-image.jpg`）。由于`Sencha.io Src`服务需要能够直接从主`Sencha.io`服务器获取文件，所以相对 URL 不起作用。图片文件需要放在一个可以向公众公开的 Web 服务器上，才能正确工作。

![Sencha.io Src 在不同设备上的图片](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_11.jpg)

使用这个服务，我们的大图片将根据我们使用的设备屏幕大小调整到全宽，无论设备的大小如何。`Sencha.io Src`还能保持图片的比例正确，不会出现压缩或拉伸的情况。

## 使用 Sencha.io Src 指定大小

我们并不总是在我们应用程序中使用全屏图片。我们经常用它们来作为应用程序中的图标和强调元素。`Sencha.io Src`还允许我们为图片指定特定的高度和/或宽度：

```js
<img src="img/my-big-image.jpg">
```

在这种情况下，我们已经将需要调整大小的图片宽度设置为`320`像素，高度设置为`200`像素。我们还可以只限制宽度；高度将自动设置为正确的比例：

```js
<img src="img/my-big-image.jpg">
```

### 提示

需要注意的是`Sencha.io Src`只会缩小图片；它不会放大它们。如果你输入的值大于实际图片的尺寸，它将 simply display at the full image size. 你的全尺寸图片应始终是你用于展示所需的最大尺寸。

### 通过公式确定大小

我们还可以使用公式根据设备屏幕大小进行更改。例如，我们可以使用以下代码使我们的照片比屏幕的全宽窄 20 像素：

```js
<img src="img/my-big-image.jpg">
```

如果你想要在图片周围留出一点边框，这个选项很有用。

### 通过百分比确定大小

我们还可以使用百分比宽度来设置图片大小：

```js
<img src="img/my-big-image.jpg">
```

我们 URL 中的`x50`部分将图片大小设置为屏幕宽度的 50%。

我们甚至可以将这两个元素结合起来创建一个可伸缩的图片库：

```js
<img src="img/my-big-image.jpg">
<img src="img/my-big-image.jpg">
```

使用公式`-20x50-5`，我们取原始图片，为边距去掉 20 像素，将其缩小到 50%，然后去掉额外的五像素，以允许两张图片之间有空间。

![通过百分比确定大小](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/sencha-tch2-mobi-js-fw/img/0748OS_03_12.jpg)

## 更改文件类型

`Sencha.io Src`提供了一些可能很有用的额外选项。首先，它让你可以实时更改图片的文件类型。例如，以下代码会将你的 JPG 文件转换为 PNG：

```js
<img src="img/my-big-image.jpg">
```

当向应用程序用户提供多个图片下载选项时，这个选项很有用。

此选项还可以与调整大小选项结合使用：

```js
<img src="img/my-big-image.jpg">
```

这将把文件转换为 PNG 格式并将其缩放到 50%。

使用`Sencha.io Src`中可用的功能，您可以自动调整应用程序中的图片大小，并在多种设备上提供一致的外观和感觉。

### 注意

Sencha.io 是一个免费服务。要获取使用`Sencha.io Src`的所有功能的完整列表，请访问：

[`www.sencha.com/learn/how-to-use-src-sencha-io/`](http://www.sencha.com/learn/how-to-use-src-sencha-io/)

# 总结

在这一章中，我们学习了如何使用`ui`配置选项来样式化工具栏。我们还讨论了 Sencha Touch 如何使用 Sass 和 Compass 创建一个健壮的主题系统。我们包括了 Sass 和 Compass 的安装说明，并解释了混合模式、变量、嵌套和选择器继承。最后，我们提到了为多种设备设计界面以及使用`Sencha.io Src`处理自动调整图片大小的方法。

在下一章中，我们将重新深入研究 Sencha Touch 框架。我们将回顾一下我们之前学过的关于组件层次结构的知识。然后，我们将介绍一些更专业的组件。最后，我们会给你一些在 Sencha Touch API 文档中找到所需信息的技巧。
