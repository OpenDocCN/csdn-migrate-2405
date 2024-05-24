# 创建 jQueryMobile 移动应用（一）

> 原文：[`zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA`](https://zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 我们能建造它吗？是的，我们能！

移动技术是存在的最快增长的技术领域。这是一股改变的浪潮，颠覆了所有分析师的预期。你可以选择驾驭这股浪潮，也可以选择被淹没。在 *使用 jQuery Mobile 创建移动应用* 中，我们将带领您完成一系列逐渐复杂的项目，涉及各种行业。与此同时，我们将解决一些移动可用性和体验问题，这些问题对所有移动实现都是共通的，不仅仅是 jQuery Mobile。

到最后，你将拥有使用 jQuery Mobile 和许多其他技术和技巧创建真正独特产品所需的所有技能。这将是有趣的。它将是具有挑战性的，到最后，你将引用《建筑工人鲍勃》中的话：“我们能建造它吗？是的，我们能！”

# 本书内容

第一章, *使用 jQuery Mobile 原型设计*，在开始编码之前利用快速原型设计的力量。与客户更快、更好、更共享地达成共识。

第二章, *一个小型移动网站*，实现了第一章中的原型。设计独特，开始建立基本的服务器端模板。

第三章, *分析、长表单和前端验证*，将 第二章 的随意实现与 Google Analytics、jQuery Validate 框架以及处理长表单的技术相结合。

第四章, *QR 码、地理定位、Google 地图 API 和 HTML5 视频*，将让您为一个电影院连锁店实现一个网站。

第五章, *客户端模板化、JSON API 和 HTML5 Web 存储*，创建了一个社交新闻中心，利用 Twitter、Flickr 和 Google Feeds API 的 API 功能。

第六章, *HTML5 音频*，利用 HTML5 音频和渐进增强，将一个非常基本的网页音频播放器页面转变为音乐艺术家的展示页面。

第七章, *完全响应式摄影*，探讨了使用 jQuery Mobile 作为移动优先的、**响应式网页设计** (**RWD**) 平台。我们还简要介绍了排版与 RWD 的关系。

第八章, *将 jQuery Mobile 集成到现有网站中*，探讨了为想要将其页面移动化但没有**内容管理系统** (**CMS**) 的客户构建 jQuery Mobile 网站的方法。我们还深入探讨了包括客户端、服务器端以及两者结合在内的移动检测方法。

第九章，*内容管理系统和 jQM*，教我们如何将 jQM 集成到 WordPress 和 Drupal 中。

第十章，将一切放在一起 - Flood.FM，借鉴了前几章的知识，并进行了一些增加，考虑使用 PhoneGap Build 进行编译。

# 你需要为这本书做好什么准备

你真的只需要一些东西来读这本书。

+   文本编辑器

    你的代码只需要一个基本的文本编辑器；在 Windows 上 Notepad++ 非常好用。我真的很喜欢 Sublime Text 2。Eclipse 也可以，虽然有点笨重。Dreamweaver 也不错，但价格昂贵。其实没太大关系；你可以选择任何让你开心的文本编辑器。

+   一个 Web 服务器

    你可以使用像 HostGator、Godaddy、1&1 等托管解决方案，或者在本地使用像 XAMPP、WAMP、MAMP 或 LAMP 这样的东西来进行所有的测试。

+   JavaScript 库

    在章节中，我们会介绍一些 JS 库。在每种情况下，我会告诉你它们是什么，以及在哪里找到它们。

+   开发者的幽默感

    我们都想到了，我们都说了。你会在这里找到一两个怒斥。根据它们的价值去看待它们，但不要太认真。

# 本书适合的读者群体

如果你已经相当擅长 web 开发（HTML、CSS、JavaScript 和 jQuery），那对我来说已经足够了。你可以在本书中学习并掌握 jQM，我想你会没问题的。

# 我们将覆盖的内容

+   构思和原型制作技术

+   集成自定义字体和图标集

+   使用 jQuery Validate 集成客户端表单验证

+   Google Analytics、Maps 和 Feeds API

+   地理位置

+   嵌入 HTML5 视频和音频

+   使用客户端模板和 JSON

+   消化 RSS 订阅

+   集成 PhotoSwipe

+   媒体查询

+   移动检测技术

+   与 Wordpress 和 Drupal 集成

+   与现有网站集成

# 为什么选择 jQuery Mobile

在移动领域，国王的崛起和衰落如此之快，几乎不可能预测谁会取胜。只需问问 RIM（黑莓设备制造商），他们从完全统治下降到了世界市场份额的 6%。在这种变化的程度和速度下，你怎么能知道你选择的平台是否适合你的项目？

+   **一个保险的选择**

    核心 jQuery 库被应用在超过 57% 的现存网站上，增长率没有显示出减缓的迹象 ([`trends.builtwith.com/javascript/jQuery`](http://trends.builtwith.com/javascript/jQuery))。它是目前为止，在开源 JavaScript 库中最值得信赖的名称。现在他们已经加入到移动领域，你可以打赌 jQuery Mobile 是一个相当安全的选择，可以用最小的努力达到最多的人。

    还值得注意的是，你可能会在一段时间后放弃大部分项目。使用 jQM 将增加后来者已经具备继续你工作的技能集的可能性。

+   **最广泛的设备支持**

    jQuery Mobile 具有最广泛的设备支持范围。通过对**渐进增强**（**PE**）的出色遵循，这一直是他们使命的一部分。当电梯坏了，它并不会变得完全无用。它只是变成了楼梯。同样，对于那些拥有智能手机的人，jQuery Mobile 为他们提供了一些非常棒的功能。但其他人呢？他们将看到一个没有所有花哨功能的标准网页。在一天结束时，一个精心制作的 jQM 页面可以适用于所有人。

+   **首先是移动端，但不仅限于移动端**

    jQM 从头开始就是为移动端设计的，但通过一些合理使用**响应式网页设计**（**RWD**），一个 jQM 项目可以服务于移动设备、平板甚至桌面电脑。

+   **声明式，而非程序式**

    在 jQM 中，大部分想要做的事情都可以在不写一行代码的情况下完成。这使得它成为即使是最新的新手也能够涉足移动领域并入门的理想工具。即使是没有真正编程经验的设计师也能轻松将他们的构想转化为具有外观的工作原型。对于我们这些会编程的人来说，这意味着我们需要做的编码要少得多，这总是件好事。jQM 完美地符合 jQuery 核心的座右铭：“写得少，做得多。”

+   **jQM 与其他框架比较**

    如果你想使用移动框架，有很多选择供你考虑。查看 [`www.markus-falk.com/mobile-frameworks-comparison-chart/`](http://www.markus-falk.com/mobile-frameworks-comparison-chart/) 来比较所有选项的工具。底线是：如果你想要支持所有人并且轻松实现，jQuery Mobile 是框架的正确选择。

+   **jQM 与响应式网页设计比较**

    最近关于 RWD 的讨论很多。我全力支持。一个统一的网站是每个开发者的梦想。然而，这通常要求网站从头开始就以 RWD 为基础构建。这也意味着网站的每一页都值得为移动受众提供服务。如果你有这样的增长机会，好好享受吧。

    令人沮丧的事实是，我们大多数人没有奢侈的条件从头开始建立一个全新的网站，也没有时间和三倍的预算来做好工作。而且，如果我们很诚实的话...很多网站有很多无用的页面，这些页面在移动网络中并没有存在的必要。你知道的。我知道的。一个完全符合用户需求和环境的定制解决方案通常是更好的选择。

+   **jQM 与自行开发比较**

    你当然可以选择从头开始创建自己的手机网站，但那就相当于用斧头砍树，然后用木板建造自己的房子。使用预制组件来制作你的杰作并不会使你不是一位手艺人。移动框架的存在是有原因的，它们所需的开发时间和跨设备测试将为你节省更多的时间和头痛。

    值得一提的是，Kasina 报告中突出的三大行业领导者中，*资产管理人和保险公司的移动领导力* （[`www.kasina.com/Page.asp?ID=1415`](http://www.kasina.com/Page.asp?ID=1415)）有两家都是使用了 jQuery Mobile。富兰克林坦普顿、美国世纪投资和万得理财被强调。前两者是使用 jQM 实现的。

    *全面披露：我曾是美国世纪投资公司的手机网站团队成员，所以我对这份报告感到相当自豪。*

## 渐进增强和优雅降级

抵抗是徒劳的。这种情况将发生在你身上。每年都会在 Black Hat 大会（[`www.blackhat.com/`](http://www.blackhat.com/)）上宣布新的漏洞利用。就像钟表一样，公司会关闭 JavaScript 直到提供补丁。你的移动受众中会有一个或多个受到影响。

虽然这种情况几乎和早期版的 Internet Explorer 一样恼人，但由于 jQuery Mobile 对渐进增强的精湛运用，它可以帮助。如果你按照框架的设计编码你的页面，那么你将不必害怕失去 JavaScript。网站仍然可以工作。可能没有那么漂亮，但对于从最智能的智能手机到最愚蠢的“傻手机”的所有人，它都能正常运行。

作为我们的责任（尽管可能让人不快），我们需要关闭 JavaScript 测试我们的产品，以确保人们始终可以访问。关掉手机的设置只需一会儿，看看会发生什么并不难。通常来说，很容易修复出问题的部分。

都说了这么多，但在本书中，我们将*无情地*打破这个规则，因为我们要超越框架的基础知识。在可能的情况下，我们将努力牢记这个原则并提供替代方案，但有些我们要尝试的东西如果没有 JavaScript 就做不到。欢迎来到 21 世纪！

## 辅助功能

智能手机是残障人士的优秀工具。jQuery Mobile 团队已尽一切努力支持 W3C 的 WAI-ARIA 辅助功能标准。至少你应该使用手机的语音助手技术测试你的成品。你会震惊于你的网站在多大程度上可以表现出色。你的需要帮助的客户将会感到高兴。

# 惯例

在本书中，您将找到几种不同信息类型的文本样式。以下是这些样式的一些例子，并解释它们的含义。

文本中的代码单词显示如下："要使用清单文件，您的网络服务器或`.htaccess`必须配置为返回`text/cache-manifest`类型。"

代码块设置如下：

```js
<link rel="apple-touch-icon-precomposed" sizes="144x144" href="images/album144.png">     
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="images/album114.png">     
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="images/album72.png">     
<link rel="apple-touch-icon-precomposed" href="images/album57.png"> 
```

**新术语**和**重要单词**以粗体显示。在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现："从那里，您可以下载最新的**WURFL API 包**并解压缩它。"

### 注意

警告或重要提示显示在这种框中。

### 提示

提示和技巧以这种方式出现。


# 第一章：jQuery Mobile 的原型设计

2011 年 11 月 22 日，我在[RoughlyBrilliant.com](http://RoughlyBrilliant.com)上开始了我的博客，以分享我对 jQuery Mobile 和移动用户体验（UX）的一切了解。我完全不知道它会变成什么样子，会引起怎样的共鸣。由于这是一个面向开发者的博客，我对我提到的首先远离键盘，先草绘设计的评论能够引起最积极的回应感到有些惊讶。我坚信，开始你的 jQuery Mobile 项目的最佳方式是在一叠便利贴上。

这一章可能会感觉是最费力的，也感觉最陌生的。但最终，我相信这可能是让你成长最多的章节。开发者坐下来开始编码是很正常的，但是现在是时候超越这一点了。是时候远离键盘了！

在本章中，我们涵盖：

+   移动领域的变化

+   移动设备的使用模式

+   纸上原型

+   小型企业移动网站的关键组件

+   绘制 jQuery Mobile UI

+   其他原型设计方法

# 游戏已经改变了

不久之前，开发者可以制作出产品，无论它有多糟糕，人们都会使用。它通常会因其存在而取得一定程度的成功。现在，我们生活在一个竞争更加激烈的时代。现在，借助像 jQuery Mobile 这样的工具，任何人都可以在几小时内迅速制作出看起来令人印象深刻的移动网站。

那么，我们如何与竞争对手区分开来呢？我们当然可以竞争价格。人们喜欢物有所值。但有一件事似乎一直超越价格，那就是用户的体验。**用户体验**（**UX**）是世界上大多数成功品牌的区别所在。

哪家电脑公司不仅保持盈利，而且绝对是成功的？苹果公司。这可能部分是因为他们的产品价格是应有之义的三倍。最终，我相信这是因为他们一直站在以用户为中心设计的前沿。

亚马逊通过帮助您快速找到所需的东西提供了很好的体验。他们为您的购买决策提供了很好的评价和建议。他们的一键购买功能非常方便，以至于他们实际上曾因此在法庭上进行了争斗，以保护它作为竞争的点（[`en.wikipedia.org/wiki/1-Click`](http://en.wikipedia.org/wiki/1-Click)）。

谷歌本可以走雅虎、AOL、MSN 等许多其他公司的路线。他们本可以在首页上推广任何他们想要的内容。相反，他们几乎保持了他们开始时的干净。他们的名字、一个搜索框和出色的结果。最多，有些可爱的徽标渲染。他们给用户他们想要的，并且基本上保持低调。

这很难！我们喜欢认为我们如何制作程序或网页至关重要。我们喜欢认为，通过减少 10%的代码，我们正在做出重大改变。但你有试过向朋友解释你当前项目的细节，只看着他们的眼睛开始发直吗？除了我们之外没有人关心。他们只听到更快、更小、更容易、更简单等等。他们只关心那些直接影响他们生活和用户体验的事情。

作为开发人员，我们可以写出最优雅的代码，创建最高效的系统，在不到 1K 的 JavaScript 中完成小奇迹，但如果我们在可用性方面失败……我们将彻底失败。

# 移动使用模式

jQuery Mobile 并非一种灵丹妙药。它不会立即创造对我们产品的吸引力。如果我们未能意识到用户的环境和使用模式，技术和库也无法拯救我们。

想一下：你上次在手机上花超过三分钟连续的时间在一个不是游戏的网站或应用上是什么时候？我们都知道《愤怒的小鸟》可以有多吸引人，但除此之外，我们往往匆匆忙忙就离开了。移动使用的特点是短暂的高效活动。这是因为我们的智能手机是完美的时间回收设备。我们随时随地都可以拿出来利用可以节省的任何时间，包括：

+   在家里（菜谱，发短信，无聊）

+   在排队或候诊时（无聊）

+   购物（女性：寻找优惠，男性：无聊）

+   工作期间（会议，厕所－我们都做过）

+   观看电视（每个广告间歇）

+   通勤（乘坐公共交通或困在交通拥堵中）

我们可以很容易地从自己的日常生活中看到这种微爆发活动。这就是我们希望成功的产品所必须适应的环境。最重要的是，这将要求我们专注。当用户在排队等候时，他们来找我们做什么？他们在一个广告间歇内能完成什么任务？在他们的第二优先事项中，他们会认为什么任务是最重要的？

# HTML 原型与绘制

不要从代码开始。作为一名开发人员，这真的很难说。jQuery Mobile 非常快速且易用。重构也很快速。然而，当你直接进行 HTML 原型设计时会发生一些事情。

不懂代码的人会认为我们距离完整的产品要比实际情况更接近。这在 jQuery Mobile 中尤其如此，因为即使是对项目最原始的尝试也会看起来经过精心打磨和完成。

人们会开始专注于像间距、边距、颜色、标志大小等细枝末节。

由于我们在当前设计中投入的时间成本，我们不太可能对最初编码的内容进行重大更改，因为重构比重做更容易。

相反，拿起笔和纸。*等等，什么？*这不是一本网页开发者的书吗？放松，你不必是一位艺术家。相信这个过程。后面会有很多机会来编码。现在，我们要画出我们的第一个 jQuery Mobile 站点。

用纸质的构思开始的伟大之处在于：

+   我们更愿意简单地放弃一个不到 30 秒就可以创建的图纸。

+   实际上，通过手工素描使用了大脑的不同部分，并且解锁了我们的创造中心。

+   我们可以在创建一个 HTML 页面的时间内提出三种完全不同的设计

+   即使不擅长平面设计或编码，每个人都可以贡献他们最好的想法

+   我们自然会从首要的事情开始画起

+   我们更多地关注能够使我们的网站正常运行的想法和流程，而不是无数的细节，很少有人会注意到

+   我们最终可能会得到一个更加以用户为中心的设计，因为我们正在绘制我们实际想要的东西

理想情况下，3x5 英寸的便笺是完美的，因为我们可以轻松地将它们摆放在墙上或桌子上，以模拟网站结构或流程。我们甚至可以用它们进行可用性测试。稍后，我们将布置我们的绘图供业主参考，看整个流程如何工作。

# 让我们的手弄脏一些小生意

根据凯瑟琳·科比在 [`archive.sba.gov/advo/research/rs299tot.pdf`](http://archive.sba.gov/advo/research/rs299tot.pdf) 上所述：

> “小企业继续在美国经济中发挥着重要作用。在 1998 年至 2004 年期间，小企业产生了一半的私人非农 GDP。”

[`www.msnbc.msn.com/id/16872553/`](http://www.msnbc.msn.com/id/16872553/)上的一篇文章称：

> “尽管大约有三分之二的小企业能够度过两年的时间，但根据劳工统计局的最新数据，只有 44%的企业能够度过四年的时间。”

即使在大企业的土地上，这对我们的手艺也是有利的；小企业的数量和变动如此之大。这意味着几乎无穷无尽的小商店在竞争。这就是我们介入的地方。

Nicky's Pizza 最近开业了。和许多其他企业一样，业主意识到他在开业之前应该有一个网站。他的朋友做了网站，而且实际上相当不错。只是还不是移动版。

披萨很棒，当我们坐在那里享受时，我们拿出笔，拿起一张餐巾纸。我们就要在这里，现在制作一个移动网站，赢得一些生意。让我们开始吧。

对于任何小型本地企业来说，都应该首先放在他们的移动网站上的是某些基本内容：

+   位置

+   联系信息

+   提供的服务/商品

由于这是一家餐厅，服务将是菜单。他们还足够聪明地创建了一个 Facebook 页面。因此，我们将链接到那里并带来一些推荐。

由于我们正在绘制而不是使用工具，您可以选择尽可能详细。以下两个图示是绘制相同页面的两个示例。任何一个都能传达核心思想。

当与我们自己的团队合作时，第一个可能已经足够了，因为我们都知道 jQuery Mobile 能做什么。我们知道框架会填充哪些细节，可以绘制足够的细节来告诉彼此我们在想什么。然而，当为客户（或者你知道更注重视觉和细节的人）绘制时，最好多花几秒钟添加更精细的细节，如阴影、渐变色彩和特别是标志。企业所有者对他们的“宝贝”非常自豪，而你为其添加的努力将立即赋予你的绘图一点额外的重量感。

![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_00.jpg)

第一张图肯定足够好，可以拿起来，放在手里，假装它是一个智能手机屏幕。在第二张图中，我们可以看到实际绘制标志会产生多大的不同，以及添加较硬的边缘和阴影会给人一种深度感。稍微擦亮一下，效果就大不同。

有几种方法可以为您的绘画添加投影阴影。最艺术的方式是使用铅笔，但使用铅笔绘图的问题在于会导致污渍，并且会过分关注细节。这些图纸应该是粗略的。如果你稍微搞砸了，没关系。毕竟，你可能每张图只花了不到一分钟，这就是重点。目标是快速实现共享的视觉理解。

这里有四种不同的方式来绘制相同的按钮：铅笔、钢笔、Sharpie 和标记笔。我个人偏爱使用细尖的 Sharpie。

![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/image1.jpg)

这里还有一些其他 jQuery Mobile 元素和绘制方法：

| **列表视图**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_05.jpg) | **对话框**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_06.jpg) |
| --- | --- |
| **导航栏**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_07.jpg) | **按钮**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_08.jpg) |
| **可折叠**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_10.jpg) | **分组按钮**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_09.jpg) |
| **输入**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_11.jpg) | **搜索**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_12.jpg) |
| **翻转开关**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_13.jpg) | **滑块**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_14.jpg) |
| **复选框集**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_15.jpg) | **单选按钮集**![亲手动手小型企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_16.jpg) |
| **选择菜单**![忙碌的小企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_17.jpg) | **多选**![忙碌的小企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_18.jpg) |
| **分割列表视图**![忙碌的小企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_19.jpg) | **气泡计数列表视图**![忙碌的小企业](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_20.jpg) |

## 网站的其余部分

`地图定位`按钮将引导用户到这个页面，在这里我们将列出地址并显示静态谷歌地图。点击地址或地图上的任何一个都将链接到完整的谷歌地图位置。

在 Android 和 iOS 5 系统上，链接到谷歌地图会导致本机系统在本机界面上打开指定位置，从而实现逐步导航。iOS 6 中发生了变化，但我们以后会讨论这个问题。

作为额外的奖励，以防用户不想去实际位置，让我们在标有`电话订餐`按钮上添加一个电话链接。

注意线条的不同粗细。还有一点颜色和我们典型的投影效果。添加这些小细节并不特别困难，但可以产生很大的影响。

![网站的其余部分](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_21.jpg)

整个网站上的所有`呼叫`按钮都将启动本机呼叫界面。下一张图是 iOS 版本的呼叫对话框。Android 版本基本相似。

注意背景按钮上闪亮的线条，表明它被点击了。还要注意，我们如何将背景（铅笔作品）遮蔽，以表明它的模态状态。

![网站的其余部分](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_22.jpg)

现在，让我们考虑菜单以及将作为全局标头的内容。您放入全局标头的前两个链接将转换为按钮。有一个设置可以在当前主页按钮位置自动插入返回按钮。只需将`data-add-back-btn="true"`添加到 jQuery Mobile 页面中即可。不过，我通常不会使用这个功能。我协助进行的可用性测试表明，大多数人只是按下他们设备的原生返回按钮。因此，让我们将第一个链接设为`主页`，第二个链接设为`呼叫`。

![网站的其余部分](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_24.jpg)

这里我们看到沙拉的详细视图。它基本上和以前一样，但我们在列表视图中进行了一些格式化。我们将在下一章中看到实际的代码。

![网站的其余部分](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_23.jpg)

当然，我们可以使用白板和标记笔来完成所有这些工作。我们可以协作地在白板上画出我们的想法，并使用我们打算针对的智能手机拍摄快照。我的建议是使用我们忠实的便利贴，简单地贴在白板上，使用标记笔来指示屏幕流程。下图显示了我在规划项目后的白板情况：

![网站的其余部分](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_01_26.jpg)

如果我们需要重新映射我们的应用流程，我们所要做的就是重新排列笔记并重新绘制我们的线条。这比在白板上再将一切都重新绘制一遍要少得多。

# 需求

考虑到我们到目前为止所做的事情。考虑到我们绘制的屏幕以及业主能够查看并签字确认这就是他想要的东西，还有多少问题需要问？我们真的需要一个列出需求或一个 30 页的**功能设计规格（FDS）**文档来准确告诉你一切应该是什么样子并且应该做什么吗？这样就够了吗？真的需要用 Photoshop 做吗，然后做成幻灯片展示吗？

还要考虑到到目前为止我们所做的事情总共花了五张便签纸、一个马克笔、一支铅笔和 20 分钟。我相信在大多数情况下，这就是你所需要的，你自己就可以做到。

## 替代纸上原型

如果纸上原型的速度和简洁还不足以说服你远离键盘，那么考虑另外两种快速原型设计的选项：

+   **Balsamiq Mockups** ([`www.balsamiq.com/`](http://www.balsamiq.com/))

+   **Axure RP** ([`www.axure.com/`](http://www.axure.com/))

我个人推荐 Balsamiq Mockups。它产生的原型具有统一但手绘的外观。这将达到与纸上原型相同的效果，但输出更一致，更容易在分布式团队之间进行协作。这两种工具都可以产生完全交互式的模型，用户实际上可以通过原型点击。最终，纸上原型仍然更快，任何人都可以贡献。

# 摘要

对于我们中的一些人来说，从未将纸上原型视为一门严肃的学科，这一开始可能会感到非常奇怪。有幸的是，这里学到的经验扩展了你的思维，并给了你对打造良好用户体验的新热情。如果你想深入探讨构思技术，我最推荐的一本书是 *Gamestorming*，作者是 Dave Gary ([`www.goodreads.com/book/show/9364936-gamestorming`](http://www.goodreads.com/book/show/9364936-gamestorming))。

现在，你应该能够有效地为你的同事和客户勾勒出一个 jQuery Mobile 接口。在下一章中，我们将把这里绘制的内容翻译成一个真正的 jQuery Mobile 实现，超越了普通的 jQuery Mobile 外观和感觉。只要记住，用户体验和可用性是首要的。追求快速、集中的直觉式生产力。


# 第二章：一家小型移动网站

前一章教会了我们一些有关纸质原型的宝贵经验，并为我们开始开发奠定了坚实的基础。现在，我们将把这些图纸变成一个真正的 jQuery Mobile (jQM) 网站，它具有响应式的功能并且看起来独特。

在本章中，我们涵盖：

+   一个新的 jQuery Mobile 样板

+   对完整网站链接的一种新思考

+   将样板分解为可配置的服务器端 PHP 模板

+   使用备用图标集

+   自定义字体

+   仅使用 CSS 实现页面翻页效果

+   性能优化技巧

+   移动设备检测和重定向技术

# 一个新的 jQuery Mobile 样板

jQuery Mobile 文档中有很多隐藏的宝藏。它们是一个很好的起点，但实际上有几种方法可以创建你的基础模板。有单页面模板、多页面模板、带有全局配置的模板以及动态生成的页面。

因此，让我们从基于原始单页面模板的新 jQM 单页面样板开始 ([`view.jquerymobile.com/1.3.0/docs/widgets/pages/`](http:// http://view.jquerymobile.com/1.3.0/docs/widgets/pages/))。随着我们进入其他章节，我们将逐步完善它，使其成为一个全面的模板。以下是我们将为本章创建的基本目录结构和我们将使用的文件：

![一个新的 jQuery Mobile 样板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_08.jpg)

现在，这是基础 HTML。让我们把它存储在 `template.html` 中：

### 提示

**下载示例代码**

你可以从你在[Packt](http://www.packtpub.com)帐户中下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到你的邮箱。

```js
<!DOCTYPE html> 
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.1.0/jquery.mobile-1.1.0.min.css" />
    <link rel="stylesheet" href="css/custom.css" />
    <script src="img/jquery-1.7.1.min.js"></script>
    <script src="img/custom-scripting.js"></script>
    <script src="img/jquery.mobile-1.1.0.min.js"></script>
    <title>Boilerplate</title> 
</head> 
<body>
    <div data-role="page">
        <div data-role="header">
            <h1>Boilerplate</h1>
        </div>
        <div data-role="content"> 
            <p>Page Body content</p>
        </div>
        <div data-role="footer">
            <h4>Footer content</h4>
        </div>
        <a href="{dynamic location}" class="fullSiteLink">View Full Site</a>
    </div>
</body>
</html>
```

## meta viewport 的不同之处

`meta viewport` 标签是真正使移动设备成为移动设备的关键！没有它，移动浏览器会假设它是一个桌面站点，一切都会变得很小，需要捏合缩放：

```js
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">
```

这个 `meta viewport` 标签与众不同，因为它实际上阻止了所有的捏合缩放操作。为什么？因为现在智能手机不仅仅掌握在了了解这些事情的技术精英手中。我个人见过人们在试图点击链接时不小心放大了页面。他们不知道他们做了什么或如何退出。无论如何，如果你使用 jQuery Mobile，你的用户不需要缩放：

```js
<linkrel="stylesheet" href="css/custom.css" />
```

我们将需要自定义样式。没有别的办法。即使我们使用了 jQuery Mobile ThemeRoller ([`jquerymobile.com/themeroller/`](http://jquerymobile.com/themeroller/))，总会有一些需要覆盖的内容。这就是你放置的地方：

```js
<script src="img/custom-scripting.js"></script>
```

最初在有关全局配置的部分提到（[`jquerymobile.com/demos/1.1.0/docs/api/globalconfig.html`](http://jquerymobile.com/demos/1.1.0/docs/api/globalconfig.html)），这是您放置全局覆盖的地方，以及您可能想要运行或普遍可用的任何脚本：

```js
<a href="{dynamic location}" class="fullSiteLinmk">View Full Site</a>
```

大多数移动网站遵循“最佳实践”，包括一个指向完整网站的链接。它通常位于页脚，并且通常链接到完整网站的主页。好的，很好。工作完成了对吗？错！最佳实践更应该被标记为“行业标准”，因为有更好的方法。

## 超越行业标准的完整网站链接

简单包括一个完整网站链接的行业标准未能支持用户的心理状态。当用户在移动网站上导航时，他们清楚地表明了他们想要查看的内容。支持用户从移动到完整网站的心理模型转换是更多工作，但打造良好的用户体验始终是如此。

想象一下。萨莉正在我们的移动网站上四处浏览，因为她想要从我们这里购买商品。她实际上花了时间向下浏览或搜索她想要查看的产品。然而，由于移动设备的限制，我们做出了一些有意识的选择，不在那里放置所有信息。我们只包括市场研究显示人们真正关心的重点。此时，她可能有点沮丧，因为她点按完整网站链接以获取更多信息。完整网站链接是以传统（懒惰）方式编码的，将她带到完整网站的根目录，现在她必须再次找到产品。现在她必须使用捏和缩放来做到这一点，这只会增加她的烦恼。除非萨莉非常感兴趣，否则她在经历了如此糟糕的体验后，继续在移动设备上查找的机会有多大，她会在桌面浏览器上回来的机会有多大？

现在，相反地，想象一下同样的移动产品页面经过深思熟虑地制作，将完整网站链接指向产品页面的桌面视图。这正是我们在我的工作地方所做的。每个可能的移动页面都明确映射到其桌面等效页面。这种无缝的过渡已经通过实际客户的用户测试，并获得了 50%的冷漠和 50%的喜悦的混合反应。用户方面肯定会有惊喜，因为它违反了他们的期望，但没有一个负面的反应。如果这不成功地论证了重新考虑传统方式处理完整网站链接的情况，我不知道还有什么。

当然，你可能会有用户体验专业人员，他们会使用像“一致性”、“最佳实践”、“行业标准”和“违背用户期望”这样的流行词汇。如果用户测试的证据无法说服他们，给他们一些以下哲学的剂量：

+   **一致性**：这种方法在自身内部是一致的。每个完整站点链接都映射到完整站点的那个页面。

+   **最佳实践**：实践只有在新的、更好的实践出现之前才是最佳的。如果他们宁愿坚持*旧*的最佳实践，那么也许他们应该卖掉他们的汽车，换一匹马和马车。

+   **行业标准**：行业标准是全世界试图跟随创新者的支撑物。好往往是伟大的敌人。不要满足于它。

+   **违背用户期望**：如果我们告诉用户我们将发送给他们一个免费的 MP3 播放器，然后我们发送给他们一台 128 GB 的 iPad 4，我们违背了他们的期望吗？是的！他们会介意吗？有些期望值是值得违背的。

让我们考虑另一面。如果用户确实想要转到完整站点的起始页面呢？嗯，他们只需一步之遥，因为现在他们只需点击主页按钮。因此，很有可能，我们已经为用户节省了几个导航步骤，而且最坏的情况下，只增加了一个步骤回到起点。

从好到伟大，细节决定成败。这确实是一个小细节，但我向你挑战，每页额外花 30 秒去做好这部分工作。

# 全局 JavaScript

由于 jQuery Mobile 中的 Ajax 导航和渐进增强，有很多不同和额外的事件。让我们考虑我发现最有用的三个独特的 jQuery Mobile 事件。我们不会立即使用它们，只是了解它们，并确保阅读注释。最终，我们将创建 `/js/global.js` 来存放我们需要的脚本。目前，只需阅读以下脚本：

```js
// JavaScript Document  

$('div[data-role="page"]').live( 'pageinit', 
function(event){          
    /* Triggered on the page being initialized, after
     initialization occurs. We recommend binding to this 
     event instead of DOM ready() because this will work
     regardless of whether the page is loaded directly or 
     if the content is pulled into another page as part of 
     the Ajax navigation system. */ 
});  

$('div[data-role="page"]').live('pagebeforeshow', function(event){   
    /* Triggered on the "toPage" we are transitioning to, 
     before the actual transition animation is kicked off. 
     Callbacks for this event will receive a data object as 
     their 2nd arg. This data object has the following  
     properties on it: */ 
});  

$('div[data-role="page"]').live( 'pageshow', 
function(event){    
    /* Triggered on the "toPage" after the transitionanimation has completed. Callbacks for this event will 
    receive a data object as their 2nd arg. This data 
    object has the following properties on it: */ 
});
```

## `.live` 与 `.on`

你可能已经注意到，我们在这里使用了 `.live` 方法来捕获事件。该方法自 jQuery 1.7 版本起已被弃用。截至撰写本文时，我们使用的是 jQuery 1.9 版本。然而，即使你查看文档中事件处理程序的示例，它们仍然在多个地方使用 `.live`。

`.live` 函数的作用是检查到达文档级别的每个事件，并查看它是否与选择器匹配。如果匹配，则执行该函数。`.live` 如此有用的原因在于，它非常适用于处理变动和动态注入的元素。毕竟，绑定尚不存在的东西很困难。但你总是可以依靠 `.live` 来捕获事件。由于它被过度使用且效率一般，它已被弃用，改用 `.on`。因此，下面是我们如何使用以下新方法完成相同任务的方式：

```js
$('div[data-role="page"]').live( 'pageinit', function(event){
  var $page = $(this);
});
```

将变为

```js
$(document).on('pageinit', function(event){
  var $page = $(event.target);
});
```

如果你想要针对每个页面进行处理，这样做非常合适。现在让我们考虑一个代码片段，可以单独针对单个页面的初始化：

```js
$('#someRandomPage').live( 'pageinit', function(event){
  var $page = $(this);
});
```

将变成

```js
$(document).on('pageinit', '#someRandomPage', function(event){
  var $page = $(event.target);
});
```

差异微妙，最终对于我们来说，从性能的角度来看并不会产生任何差异，因为我们处理的是一个围绕让页面事件冒泡到文档级别的框架。在 jQuery Mobile 实现中，使用`.on`与`.live`不会带来性能提升。但是，当你不得不更新时，可能会遇到升级头疼，因为它们最终摒弃了`.live`。

# 全局 CSS

如果这是你第一次接触响应式网页设计，大多数情况下，你的自定义样式将在默认部分。其他部分是用来覆盖默认样式，以适应其他设备的宽度和分辨率。`Horizontal Tweaks`部分是用来覆盖横向方向的样式。`iPad`部分适用于 768px 和 1024px 之间的平板分辨率。在`HD and Retina Tweaks`部分，你很可能只需要覆盖背景图样式以替换更高分辨率的图形。我们很快将看到这些实例，并将我们使用的内容放入`/css/custom.css`。与此同时，只需要看看这些结构。

```js
/* CSS Document */  
/* Default Styles   -------------*/  

/* Horizontal Tweaks   ----------*/ 
@media all and (min-width: 480px){   

}  

/* HD and Retina Tweaks ---------*/ 
@media only screen and (-webkit-min-device-pixel-ratio: 1.2),        
only screen and (min--moz-device-pixel-ratio: 1.2),       
only screen and (min-resolution: 240dpi) {   

}   

/* iPad ----------------*/ 
@media only screen and (min-device-width: 768px)
and (max-device-width: 1024px) {      

}

```

# 将 HTML 分解为服务器端模板

通常情况下，我是一个 Java 程序员，但由于 **LAMP** (**Linux, Apache, MySql, PHP**) 平台的普及，我选择了 PHP。其实我们在这里真正做的就是使用变量和服务器端包含来使我们的模板具有一致性和灵活性。

这并不是真正的生产代码。这只是将初始 HTML 拆分成漂亮的 PHP 样板。如果你现在想将其保存到文件中，我建议使用`/boilerplate.php`：

```js
<?php   
    /* the document title in the <head> */  
    $documentTitle = "jQuery Mobile PHP Boilerplate";       

    /* Left link of the header bar       
     *   
     * NOTE: If you set the $headerLeftLinkText = 'Back'     
     * then it will become a back button, in which case,     
     * no other field for $headerLeft need to be defined.    
     */     
    $headerLeftHref = "/";  
    $headerLeftLinkText = "Home";   
    $headerLeftIcon = "home";       

    /* The text to show up in the header bar */ 
    $headerTitle = "Boilerplate";   

    /* Right link of the heaer bar */   
    $headerRightHref = "tel:8165557438";    
    $headerRightLinkText = "Call";  
    $headerRightIcon = "grid";      

    /* The href to the full-site link */    
    $fullSiteLinkHref = "/";     
?>  
<!DOCTYPE html>  
<html> 
  <head>    
    <?php include "includes/meta.php" ?> 
  </head>  
  <body>
    <div data-role="page">

      <?php include "includes/header.php" ?>

      <div data-role="content">              
        <p>Page Body content</p>         
      </div>      

      <?php include "includes/footer.php" ?>                    
    </div> 
  </body> 
</html> 
```

现在我们将提取大部分的头部内容，并将其放入`/includes/meta.php`中：

```js
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">
<linkrel="stylesheet" href="http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.css" />
<linkrel="stylesheet" href="css/custom.css" />
<scriptsrc="img/jquery-1.8.2.min.js"></script>
<!-- from https://raw.github.com/carhartl/jquery-cookie/master/jquery.cookie.js-->
<scriptsrc="img/jquery.cookie.js"></script>
<scriptsrc="img/global.js"></script>
<scriptsrc="img/jquery.mobile-1.2.0.min.js"></script>src="img/jquery.mobile-1.1.0.min.js"></script>

<title><?=$documentTitle?></title>
```

### 注意

注意`js/jquery.cookie.js`中的 cookies 插件。你需要从[`github.com/carhartl/jquery-cookie`](https://github.com/carhartl/jquery-cookie)下载它。我们稍后将在移动设备检测中使用它。

现在，让我们将页面头部变为动态内容，并将其放入`/includes/header.php`中：

```js
<div data-role="header">	
<?PHP if(strtoupper ($headerLeftLinkText) == "BACK"){?>	<a data-icon="arrow-l" href="javascript://"                 
data-rel="back"><?=$headerLeftLinkText?></a>		
<?PHP } else if($headerLeftHref != ""){ ?>
<a<?PHP if($headerLeftIcon != ""){ ?>	
data-icon="<?=$headerLeftIcon ?>" 			
<?PHP } ?>href="<?=$headerLeftHref?>"><?=$headerLeftLinkText?></a>
<?PHP } ?>

<h1><?=$headerTitle ?></h1>

<?PHP if($headerRightHref != ""){ ?>
<a<?PHP if($headerRightIcon != ""){ ?>	
data-icon="<?=$headerRightIcon ?>" 
data-iconpos="right" 			
<? } ?>
href="<?=$headerRightHref?>"><?=$headerRightLinkText?></a>
<?PHP } ?>	
</div><!-- /header -->
```

接下来，让我们将页脚内容提取到`/includes/footer.php`中：

```js
<div data-role="footer">		
<insert 2 spaces>
<h4>Footer content</h4>	
</div><!-- /footer -->
<p class="fullSite">
<a class="fullSiteLink" href="<?=$fullSiteLinkHref?>">View Full Site</a>
</p>
<p class="copyright">&copy; 2012</p>
```

头部和底部的 PHP 文件是设置并忘记的文件。我们只需要在主页和`meta.php`、`header.php`和`footer.php`上填写一些变量，剩下的就交给它们来处理。`headers.php`被编码成当您的`$headerLeftLinkText`设置为单词`Back`（不区分大小写），它就会将头部的左侧按钮变成返回按钮。

# 我们需要创建我们的网站的内容

我们已经有了一个可行的样板文件。我们有了一个客户。让我们开始工作，并编写我们在第一章中绘制的内容，*jQuery Mobile 原型*。在本章中，我们将只专注于第一个屏幕，因为这是我们教授技能所需的全部内容。

![我们需要创建我们网站的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_00.jpg)

这是我们需要考虑的内容：

+   标志：我们将简单地包含桌面视图中的标志。

+   按钮：我们可以通过几种方式来完成这些按钮。乍一看，我们可能会考虑使用标准的`data-role="button"`链接。我们可以利用`ui-grid` ([`jquerymobile.com/demos/1.2.0/docs/content/content-grids.html`](http://jquerymobile.com/demos/1.2.0/docs/content/content-grids.html)) 来添加格式。如果我们只打算针对垂直持有的手机进行优化，那将是一个很好的方法。然而，我们要在这里跳出框架，创建一个在不同分辨率下反应良好的响应式菜单。

+   图标：这些不是标准的 jQuery Mobile 图标。在线有无数的图标集可供我们使用，但我们选择**Glyp****hish** ([`glyphish.com/`](http://glyphish.com/))。它们制作了包含多个尺寸、视网膜显示优化和原始 Adobe Illustrator 文件的高质量图标，以防您想要调整它们。这是一个非常优秀的选择。

+   客户见证：这看起来非常适合使用带有图像的列表视图。我们将从他们的 Facebook 页面上提取这些内容。

## 获取 Glyphish 并定义自定义图标

Glyphish 有一个许可证，允许在署名下免费使用。免费套装 ([`www.glyphish.com/download/`](http://www.glyphish.com/download/)) 只有一个尺寸和 200 个图标，"专业"套装有多个尺寸、400 个图标和无限许可证。仅需 25 美元，这是一个不费吹灰之力的选择。

创建一个带有图标的按钮非常简单。你所需要做的就是使用`data-icon`属性。像下面的代码一样，将产生一个按钮，如下图所示：

```js
<a href="index.html" data-role="button" 
data-icon="delete">Delete</a>
```

![获取 Glyphish 并定义自定义图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_04.jpg)

你可能还没有意识到 jQuery Mobile 实际上是这样做的。无论你将`data-icon`的值写成什么样，它都将成为按钮上的一个类名。如果你有一个`data-icon="directions"`的属性，那么 jQM 应用的类就是`ui-icon-directions`。当然，你需要像这样在你自己的自定义 CSS 文件中制作这个。我们将把这个以及其他类似的内容放入`css/custom.css`中。

```js
.ui-icon-directions{   
    background-image: 
    url(../icons/icons-gray/113-navigation.png);   
    height:28px;    
    width:28px;   
    background-size:28px 28px;   
    margin-left: -14px !important;  
}
```

另一件你需要做的事情是去掉典型图标周围的彩色圆盘。我们还需要删除边框半径，否则我们的图标将被裁剪以适应`ui-icon`样式中定义的圆形半径的形状。为此，我们将为每个要以这种方式自定义的链接添加`glyphishIcon`类。我们还需要将此定义添加到我们的`custom.css` **：**

```js
.glyphishIcon .ui-icon{   
    -moz-border-radius: 0px;   
    -webkit-border-radius: 0px;   
border-radius: 0px;    
background-color:transparent; 
}
```

最后，我们在首页上的四个按钮的代码将如下所示：

```js
<div class="homeMenu">
<a class="glyphishIcon" href=" https://maps.google.com/maps?q=9771+N+Cedar+Ave,+Kansas+City,+MO+64157&hl=en&sll=39.20525,-94.526954&sspn=0.014499,0.033002&hnear=9771+N+Cedar+Ave,+Kansas+City,+Missouri+64157&t=m&z=17&iwloc=A" data-role="button" data-icon="directions" data-inline="true" data-iconpos="top">Map it</a>
<a class="glyphishIcon" href="tel:+18167816500" data-role="button" data-inline="true" data-icon="iphone" data-iconpos="top">Call Us</a>
<a class="glyphishIcon" href="https://touch.facebook.com/nickyspizzanickyspizza" data-role="button" data-icon="facebook" data-iconpos="top" data-inline="true">Like Us</a>
<a class="glyphishIcon" href="menu.php" data-role="button" data-inline="true" rel="external" data-icon="utensils" data-iconpos="top">Menu</a>
</div>
```

它会在屏幕上呈现如下的截图所示：

![获取 Glyphish 并定义自定义图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_05.jpg)

# 链接到电话、电子邮件和地图

移动浏览器具有独特的可用性优势。如果我们想要链接到一个电子邮件地址，本机电子邮件客户端将立即弹出。以下代码是一个示例：

```js
<a href="mailto:shane@roughlybrilliant.com" >email me</a>
```

我们也可以对电话号码采取相同的方式，每个设备都会立即弹出一个选项，让用户拨打那个号码。这是桌面无法匹敌的功能，因为大多数桌面设备都没有电话功能。这是来自前述代码的`href`元素：

```js
href="tel:+18167816500"
```

地图是移动设备的另一个特色，因为几乎所有智能手机都内置了 GPS 软件。以下是地图链接的`href`元素。它只是一个到谷歌地图的标准链接：

```js
href="https://maps.google.com/maps?q=9771+N+Cedar+Ave,+Kansas+City,+MO+64157"
```

对于 iOS 5 和 Android，操作系统将拦截该点击，并在本机地图应用程序中显示位置。iOS 6 更改了这种模式，但我们仍然可以链接到谷歌地图链接，用户将会看到网页视图，并提示他们在 iOS 中打开谷歌地图，如下图所示：

![链接到电话、电子邮件和地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_07.jpg)

对于除了 iOS 和 Android 之外的平台，用户将直接转到谷歌地图网站。这很好，因为谷歌在使该网站可用于任何设备，包括非智能手机方面做得非常出色。

当然，我们可以就此结束，并且说它已经足够好了，但我们可以做更多的工作，通过发送用户到内置的苹果地图应用程序，为苹果用户提供更好的体验。这段代码将创建一个具有可配置属性的对象，用于配置和未来的适应。它通过版本嗅探来查看操作系统的主要版本是否大于 5。如果是，它将吸收谷歌地图链接。

这些链接可以通过两种方式进行转换。首先，它会查找超链接上的`data-appleMapsUrl`属性并使用它。如果链接上没有这个属性，它将检查`forceAppleMapsConversionIfNoAlt`配置选项，看看您是否已经配置了转换器对象来直接转换谷歌地图链接。

一旦系统意识到这部手机需要切换，它就会将这个事实存储到`localStorage`中，这样它就不必再次进行版本检查的工作。它只会检查`localStorage`中的值是否为`true`。

以下是位于`/js/global.js`的代码：

```js
var conditionalAppleMapsSwitcher = {
  appleMapsAltAttribute:"data-appleMapsUrl",
  forceAppleMapsConversionIfNoAlt:true,
  iPhoneAgent:"iPhone OS ",
  iPadAgent:"iPad; CPU OS ",
  process: function(){
    try{
      var agent = navigator.userAgent;
      if(window.localStorage && localStorage.getItem("replaceWithAppleMaps")){
        if(localStorage.getItem("replaceWithAppleMaps") == "true"){
          this.assimilateMapLinks();
        }
      }else{
        var iOSAgent = null;
        if(agent.indexOf(this.iPhoneAgent) > 0){
          iOSAgent = this.iPhoneAgent
        }
        else if(agent.indexOf(this.iPadAgent) > 0){  
          iOSAgent = this.iPadAgent
        }
        if(iOSAgent){
          var endOfAgentStringIndex = (agent.indexOf(iOSAgent)+iOSAgent.length);
          var version = agent.substr(endOfAgentStringIndex, agent.indexOf(" " , endOfAgentStringIndex));
          var majorVersion = Number(version.substr(0, version.indexOf("_")));
          if(majorVersion > 5){
            localStorage.setItem("replaceWithAppleMaps", "true");
            this.assimilateMapLinks();
          }
        }
      }
    }catch(e){}
  },
  assimilateMapLinks:function(){
    try{
      var switcher = this;
      $("a[href^='http://maps.google.com']").each(function(index, element) {
        var $link = $(element);
        if($link.attr(switcher.appleMapsAltAttribute)){
          $link.attr("href", $link.attr(switcher.appleMapsAltAttribute));
        }else if(switcher.forceAppleMapsConversionIfNoAlt){
          $link.attr("href", $link.attr("href").replace(/maps\.google\.com\/maps/,"maps.apple.com/"));
        }
      });
    }catch(e){}
  }
```

使用这段代码，现在很容易在我们的`/js/global.js`中的`pageinit`上调用它：

```js
$(document).on("pageinit", function(){        conditionalAppleMapsSwitcher.process();        
});
```

这种方法对用户来说是完全无缝的。无论他们使用的是什么系统，他们都会在尝试访问您客户的业务时获得最无摩擦的体验。

## 自定义字体

自定义字体出现在他们的完整网站上（因此也是他们品牌的一部分）。这些字体在移动端同样适用。像 iOS、Android 和最新的 BlackBerry 完全支持 `@font-face` CSS。旧版 BlackBerry 和 Windows Phone 可能会根据用户的型号支持或不支持 `@font-face`。对于任何不支持 `@font-face` 的人，他们将只看到您在 `font-family` 规则中指定的标准网络字体。有许多不同的网络字体提供商：

+   **Google Web** **Fonts** ([`www.google.com/webfonts/`](http://www.google.com/webfonts/))

+   **TypeKit** ([`typekit.com/`](https://typekit.com/))

+   **Font** **Squirrel** ([`www.fontsquirrel.com/`](http://www.fontsquirrel.com/))

+   **Fonts.com** **Web Fonts** ([`www.fonts.com/web-fonts`](http://www.fonts.com/web-fonts))

对于我们的项目，我们将使用 Google Web Fonts。我们需要在每个我们想要使用它们的页面的`<head>`中包含这些行。因为我们可能会在任何地方使用它们，所以让我们把这些行直接包含在我们的文件`/includes/meta.php`中。

```js
<link href='http://fonts.googleapis.com/css?family=Marvel' rel='stylesheet' type='text/css'>
```

一旦我们在`<head>`中链接了我们的字体，我们将需要在`/css/custom.css`文件中使用`font-family`规则来指定它们的使用方式，如下所示：

```js
h1,h2,h3,.cardo{font-family: Marvel, sans-serif;}
```

现在，对于任何（大多数情况下）支持它的浏览器，他们将看到如下内容：

![自定义字体](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_06.jpg)

### 注意

**注意**：网络字体并不轻量级。Marvel 的体积为 20 KB。不算大，但也不小。你不会想包含太多这样的字体的。

## 列表项的页面翻页阴影效果

我们将使用无序列表来布置客户的推荐。我们可以使用图像列表视图，但我们也想要在每个项目之间有一些间距以及一个页面翻页效果。所以，让我们只是给一个普通的无序列表加样式。尽可能避免覆盖标准的 jQuery Mobile 代码。那只是在找麻烦。每当你覆盖一个被设计成一个框架的东西（比如 jQuery Mobile）时，你都会面临下一个版本完全破坏你所做的覆盖和自定义适应的风险。

此定制的代码稍后将在本章显示并标记为最终的 CSS。重点是，我们将使用 CSS3 来完成这个。大多数移动浏览器完全支持 CSS3，包括转换、过渡、动画、阴影、渐变和圆角。古老的平台，如 Windows Phone 7 和 BlackBerry 5，是基于 Internet Explorer 7 或更早版本的，并且不完全支持 CSS3。在这些情况下，他们不会看到花哨的页面翻页效果，而只会看到一个包含图像和文本的白色框。虽然不是理想的情况，但这是一个完全合理的后备方案。

## 优化：为什么你应该首先考虑它

我相信优化是如此重要，以至于你需要在一开始就知道并且意识到它。你将做一些了不起的工作，我不希望你或你的利益相关者认为它不够了不起，或者慢，或者其他任何东西，因为你不知道如何挤压系统性能的技巧。从你的创作中获得最佳性能的窍门永远不嫌早。移动环境是一个非常苛刻的环境，本节中的一些技巧将产生比任何“最佳编码实践”更大的影响。

从性能的角度来看，绝对没有比 HTTP 请求更糟糕的事情了。这就是为什么 CSS 精灵是个好主意。我们发出的每一个请求都会减慢我们的速度，因为 TCP/IP 协议假定每个请求的可用带宽从几乎零开始。因此，我们不仅需要通信的延迟时间来开始从服务器拉取资产，而且还需要一段时间才能将该资产以最大可能的速度传输。4G 也无法拯救我们脱离这些事实。当然，它们一旦开始传输，传输速率是很快的，但是实际开始传输的延迟时间才是我们的致命问题。我们还必须考虑到用户在多久或没有接收到信号的情况下发现自己。这在建筑物中尤其如此。因此，以下是一些优化移动站点的技巧：

+   **通过尽可能合并尽可能多的资产来减少 HTTP 请求。** 当 **SPDY 协议** ([`www.chromium.org/spdy/spdy-whitepaper/`](http://www.chromium.org/spdy/spdy-whitepaper/)) 最终获得进展时，它将解决我们的问题，但是，目前和可预见的未来，这是最让我们变慢的原因。这也是为什么我不会建议用户使用像 **Require.js** ([`requirejs.org/`](http://requirejs.org/)) 这样的工具来动态加载页面中所需的内容。不要偷懒。了解你的页面需要什么，并尽可能合并。

+   **在服务器上启用 gzip 压缩。** 任何给定服务器都很有可能启用了 gzip 压缩，但是你应该检查一下。这将使你的基于文本的资产（HTML、CSS、JS）在传输时缩小多达 70%。这实际上比缩小代码更有影响。想要了解更多，请查看[`developers.google.com/speed/articles/gzip`](https://developers.google.com/speed/articles/gzip)。

+   **缩小文件。** 缩小是这样一个过程，一个完全可读的代码被剥夺了所有有用的空格、格式和注释。推送到浏览器的只是代码。有些人甚至会将变量和函数名称改为一个或两个字母的替换。这对于长期稳定的代码确实是一个好主意。具有倾向于在一开始就比较大的库，如 jQuery，肯定会受益。然而，对于你自己的代码，最好保持其可读性，这样如果必要的话，你就可以进行调试。就尽量让你的 HTML 页面保持在 25 KB（未压缩）以下，你的 JS 和 CSS 文件在 1 MB（同样未压缩）以下。雅虎进行的一项研究表明，在所有平台上，这似乎是设备在访问之间允许被缓存的最低公共分母（[`www.yuiblog.com/blog/2010/07/12/mobile-browser-cache-limits-revisited/`](http://www.yuiblog.com/blog/2010/07/12/mobile-browser-cache-limits-revisited/)）。

+   **缓存和微缓存**。如果你使用的是大多数其他网站上的 Apache（[`news.netcraft.com/archives/2012/01/03/january-2012-web-server-survey.html`](http://news.netcraft.com/archives/2012/01/03/january-2012-web-server-survey.html)），你可以很容易地使用`htaccess`文件设置缓存。如果你为某种类型的资源指定了一个月的缓存时间，那么浏览器将尝试在一个月内将这些资源保存在缓存中，甚至都不会检查服务器上是否有新的内容。在这里要小心。你不希望对任何可能需要迅速更改的东西设置长时间的缓存时间。然而，那些不会改变的 JavaScript 库和图像等内容肯定可以被缓存而不会产生任何不良影响。

    为了保护自己免受流量洪泛的影响，你可以使用`htaccess`缓存规则，使页面保持时间尽可能短，例如一分钟，使用以下代码：

    ```js
    # 1 MIN 
    <filesMatch "\.(html|htm|php)$">
      Header set Cache-Control "max-age=60, private, proxy-revalidate" 
    </filesMatch>
    ```

    你可以在[`www.askapache.com/htaccess/speed-up-sites-with-htaccess-caching.html`](http://www.askapache.com/htaccess/speed-up-sites-with-htaccess-caching.html)上了解更多关于 htaccess 缓存的内容。

+   **不要使用图片，如果可以用 CSS3 实现**。CSS3 标准始于 1999 年。W3C 在 2009 年开始起草 CSS4 推荐的第一稿。现在是让网络向前发展，让旧版本的浏览器归于历史的时候了。如果有人使用不支持 CSS 渐变的浏览器，让他们退回到他们丰富应得的纯色背景。如果他们的浏览器不支持 CSS 中的圆角，那么他们只能用方角了。

    如果潜在客户希望您超越网络标准来支持古老的技术，或者坚持像素完美的设计，那么辞退客户，或者收取足够多的额外费用以使其值得您的时间。像素完美的设计在桌面上已经很困难了。移动设备是一个无序之地，每个人都在实现自己的解决方案，只是稍有不同，以至于您永远不可能实现像素完美的解决方案。 ([`dowebsitesneedtolookexactlythesameineverybrowser.com/`](http://dowebsitesneedtolookexactlythesameineverybrowser.com/))

    在可能的情况下，使用 CSS3 代替图像以节省重量和 HTTP 请求。现在大多数现代智能手机都支持它（iOS、Android、BlackBerry 6+、Windows Phone 8+）。到 2013 年和 2014 年，几乎所有早期的智能手机都将被替换。

## 最终产品

现在我们已经具备了制作第一页所需的所有要求、知识和资产。我们将把这段代码作为第一页，并将其命名为 `index.php`。所有示例的图像都提供在源文件夹中。

以下是 `index.php` 的最终代码：

```js
<?php 
 $documentTitle = "Nicky's Pizza";

 $headerLeftHref = "/";
 $headerLeftLinkText = "Home";
 $headerLeftIcon = "home";

 $headerTitle = "Boilerplate";

 $headerRightHref = "tel:8165077438";
 $headerRightLinkText = "Call";
 $headerRightIcon = "grid";

 $fullSiteLinkHref = "/";

?>
<!DOCTYPE html>
<html>
<head>
 <?php include("includes/meta.php"); ?> 
</head>

<body>
<div data-role="page">
    <div data-role="content">

     <div class="logoContainer"><img src="img/LogoMobile.png" alt="Logo" width="290" style="margin:0" /></div>

        <div class="homeMenu">
            <a class="glyphishIcon" href="http://maps.google.com/maps?q=9771+N+Cedar+Ave,+Kansas+City,+MO+64157&hl=en&sll=39.20525,-94.526954&sspn=0.014499,0.033002&hnear=9771+N+Cedar+Ave,+Kansas+City,+Missouri+64157&t=m&z=17&iwloc=A" data-role="button" data-icon="directions" data-inline="true" data-iconpos="top">Map it</a>
            <a class="glyphishIcon" href="tel:+18167816500" data-role="button" data-inline="true" data-icon="iphone" data-iconpos="top">Call Us</a>
            <a class="glyphishIcon" href="https://touch.facebook.com/nickyspizzanickyspizza" data-role="button" data-icon="facebook" data-iconpos="top" data-inline="true">Like Us</a>
            <a class="glyphishIcon" href="menu.php" data-role="button" data-inline="true" rel="external" data-icon="utensils" data-iconpos="top">Menu</a>
        </div>

        <h3>What customers are saying:</h3>
        <div class="testimonials">
            <ul class="curl">
                <li><img class="facebook" src="img/fb2.jpg" alt="facebook photo" width="60" height="60" align="left" />I recommend the Italian Sausage Sandwich. Awesome!! Will be back soon!</li>
                <li><img class="facebook" src="img/fb0.jpg" alt="facebook photo" width="60" height="60" align="left" />LOVED your veggie pizza friday night and the kids devoured the cheese with jalapenos!!! salad was fresh and yummy with your house dressing!!</li>
                <li><img class="facebook" src="img/fb1.jpg" alt="facebook photo" width="60" height="60" align="left" />The Clarkes love Nicky's pizza! So happy you are here in liberty.</li>
            </ul>
        </div>

    </div>

    <?php include("includes/footer.php"); ?>
</div>

</body>
</html>
```

## 自定义 CSS

这段代码位于 `/css/custom.css` 中，包含了我们所做的所有自定义外观。其中包括自定义图标、页面翻页效果和自定义字体的定义。任何引用的图像都是客户提供的，并且在最终源文件中提供。

特别注意这里的评论，因为我已经详细说明了每个部分的目的以及它如何融入*响应式网页设计*：

```js
@charset "UTF-8";   

/*************************************************/
/* define the places we'll use custom fonts */
/*************************************************/

h1,h2,h3,.cardo{font-family: Marvel, sans-serif;} 
.logoContainer{
    font-family: Marvel, sans-serif; 
    text-align:center;margin:auto;
} 
.makersMark{
    margin:1.5em auto;
    font-family: Marvel, sans-serif; 
    text-align:center;
} 
.testimonials{margin:0 auto;} 

/*************************************************/
/*  define the background for the site */
/*************************************************/

.ui-content{ 
    background-image:url(../images/cropfade.jpg);
    background-repeat:no-repeat; 
    background-size: 100%;
}

/*************************************************/
/*  override the listview descriptions to allow them */
/*  to wrap instead of simply cutting off with an */
/*  ellipsis */
/*************************************************/

.ui-li-desc{white-space:normal;} 

/*************************************************/
/*  define our custom menu on the front page  */
/*************************************************/

.homeMenu{ text-align:center;} 
.homeMenu .ui-btn{ min-width:120px;  margin:.5em;}  
.glyphishIcon .ui-icon{
    -moz-border-radius: 0px;
    -webkit-border-radius: 0px;
    border-radius: 0px;
    background-color:transparent; 
}
/*************************************************/
/* define custom icons for our four menu buttons  */
/*************************************************/

.ui-icon-directions{
    background-image: url(../icons/icons-gray/113-navigation.png);  
    height:28px;
    width:28px;
    background-size:28px 28px;
    margin-left: -14px !important;
  }
.ui-icon-iphone{
    background-image: url(../icons/icons-gray/32-iphone.png);
    height:28px;
    width:16px;
    background-size:16px 28px;
    margin-left: -8px !important;
  }
.ui-icon-facebook{
    background-image: url(../icons/icons-gray/208-facebook.png);
    height:28px;
    width:22px;
    background-size:22px 22px;
    margin-left: -11px !important;
}
.ui-icon-utensils{
    background-image: url(../icons/icons-gray/48-fork-and-knife.png);
    height:28px;
    width:18px;
    background-size:18px 26px;
    margin-left: -9px !important;  
}  

/*************************************************/
/* define how to show people's Facebook images
/*************************************************/

li img.facebook{padding:0 10px 10px 0;} 

/*************************************************/
/* define the look of the footer content */
/*************************************************/
.fullSite{text-align:center;} 
.copyright{
    text-align:center;font-family: Marvel, sans-serif; 
    marign-top:2em;
} 		

/*************************************************/
/* define how the layout and images will change for */
/* phones in landscape mode.  RESPONSIVE WEB DESGIN */
/*************************************************/

/* Horizontal ----------*/ 
@media all and (min-width: 480px){

  /*************************************************/
  /* reflow the main menu buttons to display as */
  /* four in a row and give some appropriate margin */
  /*************************************************/
.homeMenu .ui-btn{ min-width:100px;  margin:.2em;} 
}  

/*************************************************/
/* define how we'll override the image URLs for */
/* devices with high resolutions. */
/* RESPONSIVE WEB DESIGN */
/*************************************************/
@media only screen and (-webkit-min-device-pixel-ratio: 1.5),    
only screen and (min--moz-device-pixel-ratio: 1.5),    
only screen and (min-resolution: 240dpi) { 	
.ui-icon-directions{ 
   background-image: url(../icons/icons-gray/113-navigation@2x.png);
  }
.ui-icon-iphone{
   background-image: url(../icons/icons-gray/32-iphone@2x.png);
  }
.ui-icon-facebook{
   background-image: url(../icons/icons-gray/208-facebook@2x.png);
  }
.ui-icon-utensils{
   background-image: url(../icons/icons-gray/48-fork-and-knife@2x.png);
  } 
}  

/*************************************************/
/* define the reflow, sizes, spacing for the menu */
/* buttons for iPad.  RESPONSIVE WEB DESIGN
/*************************************************/
/* iPad size -----------*/ 
@media only screen and (min-device-width: 768px) 
and (max-device-width: 1024px) {     
    .homeMenu .ui-btn{ min-width:120px;  margin:.7em; } 
}

/*************************************************/
/* begin page curl CSS */   
/*************************************************/
ul.curl {
    position: relative;
    z-index: 1;  
    list-style: none;   
    margin: 0;
    padding: 0;
  }
ul.curl li {   
    position: relative;
    float: left;
    padding: 10px;
    border: 1px solid #efefef;
    margin: 10px 0;
    background: #fff;   
    -webkit-box-shadow: 0 1px 4px rgba(0, 0, 0, 0.27), 0 0 40px rgba(0, 0, 0, 0.06) inset;   
    -moz-box-shadow: 0 1px 4px rgba(0, 0, 0, 0.27), 0 0 40px rgba(0, 0, 0, 0.06) inset;    
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.27), 0 0 40px rgba(0, 0, 0, 0.06) inset;    text-align:left;   
}
ul.curlli:before,
ul.curlli:after {   
    content: '';   
    z-index: -1;   
    position: absolute;   
    left: 10px; 	
    bottom: 10px;   
    width: 70%; 	
    max-width: 300px;  
    max-height: 100px;   
    height: 55%;   
    -webkit-box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);   
    -moz-box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);   
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);   
    -webkit-transform: skew(-15deg) rotate(-6deg); 	
    -moz-transform: skew(-15deg) rotate(-6deg); 	
    -ms-transform: skew(-15deg) rotate(-6deg);   
    -o-transform: skew(-15deg) rotate(-6deg);   
    transform: skew(-15deg) rotate(-6deg); 
}  
ul.curlli:after {   
    left: auto;
    right: 10px;
    -webkit-transform: skew(15deg) rotate(6deg);
    -moz-transform: skew(15deg) rotate(6deg);
    -ms-transform: skew(15deg) rotate(6deg);
    -o-transform: skew(15deg) rotate(6deg);   
    transform: skew(15deg) rotate(6deg); } 
/*************************************************/
/* end page curl CSS */ 
/*************************************************/
```

# 第一页的结果

让我们来看看我们工作的最终产品。在左侧，我们有纵向视图中的呈现页面，右侧是横向视图：

![第一页的结果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_01.jpg)

在两个方向上测试设计非常重要。当有人稍后过来，只是简单地转动手机就破坏了您的工作，这可能会让人感到相当尴尬。

![第一页的结果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_02_03.jpg)

这是在 iPad 上的效果。行业内存在一些关于 iPad 是否算作移动设备的辩论，因为它具有足够的分辨率和足够大的屏幕来查看正常的桌面站点，特别是在横向模式下查看。主张桌面视图的人忽略了一个非常重要的事实。iPad 和所有其他平板电脑，如 Kindle Fire、Nook Color 和 Google Nexus 设备，仍然是触摸界面。虽然全站点仍然可以完美阅读，但交互点可能仍然是小目标。如果是触摸界面，您的客户将更好地通过 jQuery Mobile 服务。

# 引导用户访问我们的移动站点

现在我们已经有了一个很好的移动站点，用户如何到达那里呢？`yourdomain.mobi`？`m.yourdomain.com`？事实上，用户不会直接访问移动站点。他们通常会执行以下两种操作之一：在 Google 中搜索该站点，或者在地址栏中输入主域名，这与他们在桌面站点上的行为相同。因此，我们有责任正确检测移动用户并为他们提供适当的界面。

行业内对此如何完成存在很多争议。大多数专家似乎都同意，你不希望涉足检测特定平台的业务，这被称为用户代理嗅探。起初，这似乎不是一个坏主意。毕竟，实际上只有四个主要平台：iOS、Android、Windows Phone 和 BlackBerry。即使如此，随着未来新平台的开发或主导地位的出现，这种方法很快就会变成一场噩梦。这里真正的问题是，我们为什么要关心他们使用的平台？我们真正关心的是设备的功能。

## 使用 JavaScript 进行检测和重定向

自然地，这不会涵盖移动市场的所有人。即使在美国，智能手机的普及率也仅为 50%。([`blog.nielsen.com/nielsenwire/online_mobile/smartphones-account-for-half-of-all-mobile-phones-dominate-new-phone-purchases-in-the-us/`](http://blog.nielsen.com/nielsenwire/online_mobile/smartphones-account-for-half-of-all-mobile-phones-dominate-new-phone-purchases-in-the-us/)) 但这有关系吗？ 。

如果这种方法最多只能覆盖市场的 50%，那么它真的是一个合适的解决方案吗？是的，但是怎么可能呢？以下两个原因最能解释这个问题：

+   没有智能手机的人通常没有数据计划。在网上冲浪变得经济上不可行。大多数没有智能手机和数据计划的人不会接触到你。

+   拥有旧款智能手机（如 BlackBerry 5 或更早版本）的人可能有数据计划。然而，这些设备的浏览器几乎不值得一提，他们的用户也知道这一点。他们*可能*会访问你的网站，但可能性不大，并且它们的存在正在迅速减少。

在大多数情况下，有可能会使用智能手机访问你的站点的人会有很好的响应。例外情况不值一提。

如果设备支持媒体查询并具有触摸界面，那么它非常适合我们的移动站点。当然，唯一的例外是 Windows Phone 7 上的 Internet Explorer。因此，我们将对他们稍作让步。首先，我们需要为 jQuery 下载 cookie 插件。如果你还没有，请从 [`github.com/carhartl/jquery-cookie`](https://github.com/carhartl/jquery-cookie) 获取，并将其放入 `/js/` 文件夹中。此代码将放置在你想要进行移动重定向的任何文件夹中。

```js
<script type="text/javascript">	
  //First, we check the cookies to see if the user has
  //clicked on the full site link.  If so, we don't want
//to send them to mobile again.  After that, we check for     
  //capabilities or if it's IE Mobile
if("true" != $.cookie("fullSiteClicked") &&
      ('querySelector' in document &&
       'localStorage' in window&&
'addEventListener' in window &&
('ontouchstart' in window || 
window.DocumentTouch && document instanceOf DocumentTouch
)
)     
|| navigator.userAgent.indexOf('IEMobile') > 0
)
{                
location.replace(YOUR MOBILE URL);   
}  
</script>
```

我们还可以根据每个页面的需求定制移动端目标页面。将这种技术与之前创建的动态完整站点链接配对，可以在用户想要切换时实现无缝的移动端和桌面端视图转换。我们现在只有一个问题。我们需要设置一个 Cookie，这样，如果他们点击完整站点链接，就不会被立即重定向回移动端。让我们把这个放到 `/js/global.js` 中：

```js
$("[data-role='page']").live('pageinit', function (event, ui) { 
    $("a.fullSiteLink").click(function(){     
    $.cookie("fullSiteClicked","true", {path: "/", expires: 3600});   
    }); 
}); 
```

对于为移动设备编写的任何 cookie，设置过期时间是个好主意。在台式电脑上，人们倾向于关闭他们的浏览器。在移动设备上，人们点击主页按钮，这可能实际上并未关闭该浏览器的会话。在 Android 上，除非用户明确关闭，否则浏览器永远不会被关闭。

## 在服务器端进行检测

如果你必须将所有移动用户都引导到你的移动站点，你需要在服务器端进行检测，使用类似 **WURFL**（[`wurfl.sourceforge.net/`](http://wurfl.sourceforge.net/)）这样的工具。这是一个由社区维护的无线设备描述符的终极数据库。本质上，这是用户代理嗅探，但是数据库由社区良好维护。该工具将能够告诉你访问你的每个设备的各种有用信息。链接 [`www.scientiamobile.com/wurflCapability/tree`](http://www.scientiamobile.com/wurflCapability/tree) 将为您提供 WURFL 的所有功能的完整列表。我们将在后面的章节中深入了解这个工具的具体原理。

# 总结

在本章中，我们涵盖了很多内容，现在我们具备了所有技能和工具，可以将原本看起来相当普通的移动站点变成独特的东西。我们知道如何使其看起来独特，如何托管它，如何引导用户到达那里，以及如何给他们一个更加功能强大的“降落伞”，以防他们不满意。已经，我们领先于那些刚刚入门的普通开发者数步，而这仅仅是第二章。在下一章中，我们将开始探讨更深入的话题，这些话题通常是大型企业关心的，比如验证、分析等等。


# 第三章：分析、长表单和前端验证

是时候发展了。业务正在增长，没有什么比大型表单、指标和定制体验更能体现出大企业的风范了。

在本章中，我们将涵盖：

+   谷歌静态地图

+   谷歌分析

+   长型和多页表单

+   集成 jQuery 验证

# 谷歌静态地图

在上一章中，我们完全沉浸在如何动态地直接链接到 iOS 和 Android 的本机 GPS 系统中。现在，让我们考虑另一种方法。客户希望有机会向用户显示街道地址、地图，并给他们另一次打电话的机会。在这种情况下，简单地链接到本机 GPS 系统是不够的。如果用户点击地址或地图，我们仍然可以触发它，但作为中间步骤，我们可以从谷歌注入一个静态地图（[`developers.google.com/maps/documentation/staticmaps/`](https://developers.google.com/maps/documentation/staticmaps/)）。

它是否像直接启动应用程序开始逐步转向方向一样惊艳？没有，但它要快得多，也许这就是用户所需要的。他们可能会立即识别出位置，并决定，是的，实际上，他们更愿意打电话。记住，始终从用户的角度来看待事物。并不总是要做我们能做到的最酷的事情。

让我们来看一下客户批准的绘图：

![谷歌静态地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_03_00.jpg)

让我们来看一下将放在`/map.php`中的此页面的代码：

```js
<?php 
  $documentTitle = "Map | Nicky's Pizza";

  $fullSiteLinkHref = "/";

  $mapsAddress = "https://maps.google.com/maps?q=9771+N+Cedar+Ave,+Kansas+City,+MO+64157&hl=en&sll=39.20525,-94.526954&sspn=0.014499,0.033002&hnear=9771+N+Cedar+Ave,+Kansas+City,+Missouri+64157&t=m&z=17&iwloc=A";
  $staticMapUrl = "https://maps.googleapis.com/maps/api/staticmap?center=39.269109,-94.45281&amp;zoom=15&amp;size=288x200&amp;markers=color:0xd64044%7Clabel:N%7C39.269109,-94.45281&amp;sensor=true;"
?>
<!DOCTYPE html>
<html>
<head>
  <?php include("includes/meta.php"); ?>
</head>

<body>
<div data-role="page">
  <div data-role="content">
    <div class="logoContainer"><img src="img/LogoMobile.png" alt="Logo" width="290" style="margin:0" /></div>
    <p>
      <a href="<?=$mapsAddress ?>">
        <address class="vcard">
          <div class="adr">
            <div class="street-address">9771 N Cedar Ave</div>
            <span class="locality">Kansas City</span>, 
            <span class="region">MO</span>, 
            <span class="postal-code">64157</span> 
            <div class="country-name">U.S.A.</div>
          </div>
        </address>
      </a>
    </p>
    <p><a href="<?= $mapsAddress ?>"><img src="img/<?=$staticMapUrl ?>" width="288" height="200" /></a></p>
    <p><a href="tel:+18167816500" data-role="button">Call for delivery</a></p>
  </div>
  <?php include("includes/footer.php"); ?>
</div>
</body>
</html>
```

注意使用微格式 ([`microformats.org/`](http://microformats.org/)) 来标记地址。虽然这不是必需的，但自 2007 年以来已经成为相当标准的做法，这是赋予您的信息更多语义价值的好方法。这意味着不仅人们可以读懂它，甚至计算机也可以读懂并理解它。如果您想了解更多关于微格式的信息，可以阅读 Smashing Magazine 的这篇文章：[`coding.smashingmagazine.com/2007/05/04/microformats-what-they-are-and-how-to-use-them/`](http://coding.smashingmagazine.com/2007/05/04/microformats-what-they-are-and-how-to-use-them/)

## 添加 Google Analytics

每个网站都应该有分析功能。如果没有，很难说有多少人访问了您的网站，我们是否通过转化漏斗吸引了人们，或者是哪些页面导致了人们离开我们的网站。

让我们增强全局 JavaScript (`/js/global.js`) 文件，以自动记录每个显示的页面。这是一个非常重要的区别。在桌面世界中，每个分析命中都基于文档就绪事件。这对于**jQuery Mobile**（**jQM**）不起作用，因为基于 Ajax 导航系统的第一个页面是唯一触发页面加载事件的页面。在 jQM 中，我们需要使用以下代码在`pageshow`事件上触发这个动作：

```js
/**********************************************/
/* Declare the analytics variables as global */
/**********************************************/
var _gaq = _gaq || [];

/**********************************************/
/* Initialize tracking when the page is loaded*/
/**********************************************/
$(document).ready(function(e) { 
(function() { 
var ga = document.createElement('script'); 
ga.type = 'text/javascript'; 

//Call in the Google Analytics scripts asynchronously.
ga.async = true;
ga.src = ('https:' == document.location.protocol ? 
'https://ssl' :
'http://www') 
+'.google-analytics.com/ga.js'; 
var s = document.getElementsByTagName('script')[0]; 
s.parentNode.insertBefore(ga, s); })(); 
});

/**********************************************/
/* On every pageshow, register each page view in GA */
/**********************************************/
$("[data-role='page']").live('pageshow', function (event, ui)
{

//wrap 3rd party code you don't control in try/catch
try {
_gaq.push(['_setAccount', 'YOUR ANALYTICS ID']);
if ($.mobile.activePage.attr("data-url")) { 
_gaq.push(['_trackPageview', 
//Pull the page to track from the data-url attribute 
//of the active page.
$.mobile.activePage.attr("data-url")]);
} else { 
_gaq.push(['_trackPageview']); 
} 
} 
 //if there is an error, let's dump it to the console
catch(err) {console.log(err);}
}); 

```

通过使用异步调用来拉取 Google Analytics，我们允许用户继续操作，即使跟踪功能不起作用或加载需要一些时间。通常，对 JavaScript 文件的调用会暂停所有进一步的资产加载和 JavaScript 执行，直到所请求的脚本完全加载和执行为止。我们真的不希望因为一些广告网络或分析跟踪需要一段时间才能响应而导致我们精心设计的、速度快且功能完善的页面受阻。

我们从当前页面的`data-url`属性中提取要跟踪的位置，因为你不能可靠地使用`document.location`函数来进行页面跟踪。jQM 的基于 Ajax 的导航会导致跟踪中出现一些非常奇怪的 URL。jQM 团队正在解决这个问题，但需要一段时间才能在所有设备上提供所需的技术。相反，只需从 jQM 页面的`data-url`属性中提取要跟踪的 URL。如果你动态创建页面，这也是你会为跟踪目的放置自定义页面名称的地方。如果你使用多页面模板，每个页面的 ID 将被跟踪为页面视图。

我们确实还没有做太多的分析工作，但让我们看一些我们已经开始收集的见解。这里只是一小部分技术细分的样本：

![添加 Google Analytics](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_03_01.jpg)

以下图片显示了同一视图的完整报告，稍微细分以显示哪些设备最受欢迎：

![添加 Google Analytics](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_03_02.jpg)

在前一张图片中，特别关注每个平台整体的**跳出率**列。如果其中一个显着高于另一个，这可能表明我们需要更仔细地查看该设备上的网站。

![添加 Google Analytics](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_03_03.jpg)

制作移动网站远不止于在移动浏览器上美化外观。一个量度良好的移动网站的最佳指标是人们能够快速进入并找到他们需要的内容。这使得“热门内容”报告成为我们的新朋友。

毫不奇怪，大多数访问网站的人都在点击菜单，如前一张报告中所示。然而，菜单只是一个起点而已。他们在菜单中最感兴趣的是什么？特色披萨。正是这种洞察力可以引导你成功地进行首次重新设计。也许，我们应该考虑在首页上展示特色产品，为用户节省时间。

底线是，没有良好的分析，你就不知道自己是否在构建正确的东西。当前设计的网站，让他们要点击两次才能看到最关心的内容，对吗？

到目前为止，我们只跟踪了页面浏览。但在移动世界中，这还不是全部的图片。那些拨打电话号码但不触发页面浏览的链接呢？那些转移到 Facebook 或到地图软件（如 Google 地图）的链接呢？这些当然也算是进一步的互动，但希望也能对所有这些点击行为进行统计。我们已经以不同的方式跟踪页面浏览，让我们继续下去。

自然地，我们希望跟踪自定义事件而不必为每个要跟踪的事件编写 JavaScript。让我们把我们的链接做成这样：

```js
<a href="tel:+18167816500" data-pageview="call">Call Us</a>
```

然后，让我们在 `pageinit` 处理程序中添加一些代码：

```js
$(document).on('pageinit', function (event, ui) { 
$page = $(event.target);

$page.find("[data-pageview]").click(function(){ 
var $eventTarget = $(this); 
if($eventTarget.attr("data-pageview") == "href"){ 
_gaq.push(['_trackPageview', 
$eventTarget.attr("href")]); 
}else{
_gaq.push(['_trackPageview', 
$eventTarget.attr("data-pageview")]); 
} 
});
```

还有很多可以进行的分析跟踪，比如自定义事件跟踪，电子商务活动跟踪，目标跟踪等等。既然你已经知道如何将 Google Analytics 与 jQuery Mobile 结合起来的基本知识，你可以继续探索更多的跟踪方式，可以查看这里：[`developers.google.com/analytics/devguides/collection/gajs/`](https://developers.google.com/analytics/devguides/collection/gajs/)。

# 长表单和多页面表单

在桌面上，长表单是很正常的。我们都见过注册页面和电子商务订单流程。表单越长，就越倾向于将它们分成更小、更合乎逻辑的片段。这通常是通过以下几种方式来实现的：

+   保持它作为一个完整的页面，但注入足够的空白和分组，使其看起来不那么令人生畏

+   要么物理上将表单分成多个页面，要么使用显示/隐藏技术来完成同样的事情

这两种方法在任务完成方面并没有太大的区别。无论哪种方式，都不是移动限制条件下特别不利的策略。增加成功的最佳方法是：

+   完全去除所有可选字段

+   尽量减少必填字段的数量（对此要尽快着手）

+   预先填写合理默认值的元素

+   立即验证字段，而不是等到最后

+   提前告知用户任务可能需要多长时间

即使这样做了，有时表单还是会很长。如果你遇到这种情况，下面是使用 jQuery Mobile 将一个长表单分成多个页面的一个有用方法。以下是来自 `ordercheckout.php` 的代码：

```js
<body>
 <form action="/m/processOrder.php" method="post">
  <div data-role="page" id="delivery">
    <?php $headerTitle = "Deliver To"; ?>
    <?php include("includes/header.php"); ?>
    <div data-role="content">
    <h2>Where will we be delivering?</h2>

      <!—-form elements go here -->   

      <p>
        <div class="ui-grid-a">
          <div class="ui-block-a"><a data-role="button" href="index.php">Cancel</a></div>
          <div class="ui-block-b"><a data-role="button" href="#payment">Continue</a></div>
        </div>
      </p>

    </div>
    <?php include("includes/footer.php"); ?>
  </div>

  <div data-role="page" id="payment">
    <?php $headerTitle = "Payment"; ?>
    <?php include("includes/header.php"); ?>
    <div data-role="content">
      <h2>Please enter payment information</h2>

        <!-—form elements go here -->              

      <p>
        <div class="ui-grid-a">
          <div class="ui-block-a"><a data-role="button" data-theme="d" href="index.php">Cancel</a></div>
          <div class="ui-block-b"><input type="submit"data-theme="b" value="Submit"/></div>
        </div>
      </p>

    </div>
      <?php include("includes/footer.php"); ?>
  </div>

 </form>
<body>
```

这里要注意的第一件事是 body 和 form 标签都在所有 jQuery Mobile 页面之外。记住，所有这些只是一个大的文档对象模型（DOM）。所有疯狂的渐进增强和 UI 中的页面切换都没有改变这一点。这个页面，在根本上，是一个我们将用来提交整个订单流程的巨大表单。

# 集成 jQuery 验证

在客户端尽可能多地验证始终对用户体验很重要。HTML5 通过提供更多的输入类型控制大大推动了这一目标。尽管 HTML5 输入类型很好，但我们需要更多。进入 Query Validate。 ([`bassistance.de/jquery-plugins/jquery-plugin-validation/`](http://bassistance.de/jquery-plugins/jquery-plugin-validation/))

Validate 插件是 jQuery 社区的一个基石，但有一些东西可以帮助我们的移动实现。让我们从自动将验证添加到任何具有 `validateMe` 类表单的页面开始。

```js
$("form.validateMe").each(function(index, element) { 
var $form = $(this); 
var v = $form.validate({
errorPlacement: function(error, element) {
vardataErrorAt = element.attr("data-error-at");
    if (dataErrorAt) 
        $(dataErrorAt).html(error); 
    else
      error.insertBefore(element); 
    } 
  }); 
});
```

由于页面可能包含多个表单，让我们现在就处理它，通过将其挂钩到每个请求验证的表单中，使用以下命令：

```js
$("form.validateMe").each
```

默认情况下，`ValidateMe` 在无效字段后放置错误信息。但在移动设备上，这样做不太好，因为错误信息会显示在表单元素的下方。在 BlackBerry 和某些 Android 系统上，表单元素不一定会垂直居中于键盘和字段本身之间的空间内。如果用户输入有误，反馈不会是即时和明显的。这就是为什么我们要对错误放置进行两个更改，使用以下代码行：

```js
errorPlacement:
```

在任何给定的元素上，我们都可以使用标准的 jQuery 选择器指定我们想要放置错误的位置，就像以下代码行所示的那样。也许我们永远不会使用它，但拥有它是方便的。

```js
element.attr("data-error-at");
```

如果在元素级别未指定错误放置位置，我们将在元素本身之前插入错误，就像以下代码行所示的那样。错误语言将显示在标签文本和表单元素之间。这样，键盘永远不会遮挡反馈。

```js
error.insertBefore(element);
```

在单表单、多页面的环境中，我们希望能够在继续到下一页之前逐个验证一个 jQM 页面。我们需要做的第一件事情是给出一个替代方式来处理 `required` 函数，因为我们显然不是一次性验证整个表单。

这可以在我们的全局脚本中在任何函数外部声明：

```js
$.validator.addMethod("pageRequired", function(value, element) {  	
var $element = $(element);
  if ($element.closest("."+$.mobile.subPageUrlKey).hasClass($.mobile.activePageClass)){  
    return !this.optional(element);
}
  return "dependency-mismatch";
}, $.validator.messages.required);
```

像这样添加额外的 `validator` 方法非常方便。我们可以为几乎任何事情声明自己的验证方法。

供您快速参考，以下是其他验证选项：

+   `required`

+   `remote`

+   `email`

+   `url`

+   `date`

+   `dateISO`

+   `number`

+   `digits`

+   `creditcard`

+   `equalTo`

+   `accept`

+   `maxlength`

+   `minlength`

+   `rangelength`

+   `range`

+   `max`

+   `min`

要查看更多启发人心的演示，请访问 [`bassistance.de/jquery-plugins/jquery-plugin-validation/`](http://bassistance.de/jquery-plugins/jquery-plugin-validation/) 并考虑向该项目捐赠。它让我们所有人的生活变得更美好。

![集成 jQuery Validate](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_03_04.jpg)

现在我们已经将 jQuery Validate 正确集成到我们的多页表单中，我们需要使我们的错误看起来像是真正的错误。我们可以选择一些非常简单的东西，比如文本上的红色，但我更喜欢保持与 jQuery Mobile 的样式一致。他们的默认主题集有一个 `data-theme="e"`，非常适合用于错误状态。将我们的错误类添加到他们的 `ui-bar-e` 的定义上似乎是个好主意，但不要这样做。在写这本书的过程中，jQuery Mobile 被修补了三次，如果我们采取这种方法，将会导致每次升级都有摩擦。相反，让我们将 `ui-bar-e` 的定义直接复制到我们的自定义样式表中，如下所示：

```js
label.error,input.error{
border:1px solid #f7c942;
background:#fadb4e;
color:#333;
text-shadow:0 1px 0 #fff;
background-image:-webkit-gradient(linear,lefttop,leftbottom,from(#fceda7),to(#fbef7e));
background-image:-webkit-linear-gradient(#fceda7,#fbef7e);
background-image:-moz-linear-gradient(#fceda7,#fbef7e);
background-image:-ms-linear-gradient(#fceda7,#fbef7e);
background-image:-o-linear-gradient(#fceda7,#fbef7e);
background-image:linear-gradient(#fceda7,#fbef7e)} 
```

我们几乎已经准备好使用我们的精美表单了。现在我们只需要能够在转移到下一页之前对其进行验证即可。我们不必担心提交链接，因为自然会触发验证，但让我们使用以下代码为继续链接添加一个类：

```js
<a data-role="button" data-theme="b" href="#payment"class="validateContinue">Continue</a>
```

然后，在我们的全局脚本中，让我们使用以下代码将这个函数添加到我们的 `pageinit` 处理程序中：

```js
$page.find(".validateContinue").click(function(){ 
  if($(this).closest("form").data("validator").form()){ 
    return true; 
  }else{
    event.stopPropagation();
    event.preventDefault();
    return false; 
  } 
}); 
```

如果用户在此过程中刷新会发生什么？字段将为空，但我们已经进入到下一页了。页面底部的一个小脚本，如下面的代码所示，应该可以处理这个问题：

```js
//page refresh mitigation 
$(document).on("pagebeforeshow", function(){ 
  if(document.location.hash != ""){
    var $firstRequiredInput = 
$("input.pageRequired").first(); 
    if($firstRequiredInput.val() == ""){
      var redirectPage = 
$firstRequiredInput.closest("[data-role='page']"); 
      $.mobile.changePage(redirectPage);
    }
  }
});
```

现在我们已经掌握了基本概念，并克服了一些小问题，让我们看看`ordercheckout.php` 文件的最终代码：

```js
<!DOCTYPE html>
<html>
<?php 
  $documentTitle = "Check Out | Nicky's Pizza";

  $headerLeftHref = "";
  $headerLeftLinkText = "Back";
  $headerLeftIcon = "";

  $headerRightHref = "tel:8165077438";
  $headerRightLinkText = "Call";
  $headerRightIcon = "grid";

  $fullSiteLinkHref = "/";

?>
<head>
  <?php include("includes/meta.php"); ?>
  <style type="text/css">
    #ordernameContainer{display:none;}
  </style>
</head>

<body>
  <form action="thankyou.php" method="post" class="validateMe">
```

这是我们多页表单的第一页。请记住，这些页面将一次性全部提交。在用户转移到下一页之前，我们将使用以下代码验证每一页：

```js
div data-role="page" id="delivery">
  <?php $headerTitle = "Deliver To"; ?>
  <?php include("includes/header.php"); ?>
  <div data-role="content">
    <h2>Where will we be delivering?</h2>

    <p>
      <label for="streetAddress">Street Address</label>
      <input type="text" name="streetAddress" id="streetAddress" class="pageRequired" />
    </p>

    <p>
      <label for="streetAddress2">Address Line 2 | Apt#</label>
      <input type="text" name="streetAddress2" id="streetAddress2" />
    </p>

    <p>
      <label for="zip">Zip Code</label>
      <input type="number" name="zip" id="zip" maxlength="5" class="pageRequired zip" />
    </p>

    <p>
      <label for="phone">Phone Number</label>
      <input type="tel" name="phone" id="phone" maxlength="10" class="number pageRequired" />
    </p>

    <p>
      <div class="ui-grid-a">
        <div class="ui-block-a"><a data-role="button" data-icon="delete" data-iconpos="left" data-theme="d" href="javascript://">Cancel</a></div>
        <div class="ui-block-b"><a data-role="button" data-icon="arrow-r" data-iconpos="right" data-theme="b" href="#payment" class="validateContinue">Continue</a></div>
      </div>
    </p>

  </div>
  <?php include("includes/footer.php"); ?>
</div>
```

这是用于收集付款信息的表单的第二页。请注意信用卡的验证。我们只需添加类 `"creditcard"` 即可使框架检查卡号是否符合 Luhn 算法（[`en.wikipedia.org/wiki/Luhn_algorithm`](http://en.wikipedia.org/wiki/Luhn_algorithm)）。

```js
<div data-role="page" id="payment">
  <?php $headerTitle = "Payment"; ?>
  <?php include("includes/header.php"); ?>
  <div data-role="content">
    <h2>Please enter payment information</h2>

    <p>
      <label for="nameOnCard">Name on card</label>
      <input type="text" name="nameOnCard" id="nameOnCard" class="pageRequired" />
    </p>

    <p>
      <label for="cardNumber">Card Number</label>
      <input type="tel" name="cardNumber" id="cardNumber" class="pageRequired creditcard" />
    </p>

    <p>
      <label for="expiration">Expiration</label>
      <input class="pageRequired number" type="tel" name="expiration" id="expiration" maxlength="4" size="4" placeholder="MMYY" />
    </p>

    <p>
      <label for="cvv">CVV2 (on the back of your card)</label>
      <input class="pageRequired number" type="number" name="cvv" id="cvv" minlength="3" maxlength="4" />
    </p>

    <p>
      <input type="checkbox" value="true" name="savePayment" id="savePayment" /><label for="savePayment">Save payment info for easier ordering?</label>
      <input type="checkbox" value="true" name="saveOrder" id="saveOrder" onchange="showHideOrderNameContainer()" /><label for="saveOrder">Save this order to your favorites?</label>
    </p>

    <p id="ordernameContainer">
      <label for="ordername">Give your order a name</label>
      <input type="text" name="ordername" id="ordername" placeholder="example: the usual" />
    </p>

    <p>
      <div class="ui-grid-a">
        <div class="ui-block-a"><a data-role="button" data-icon="delete" data-iconpos="left" data-theme="d" href="javascript://">Cancel</a></div>
        <div class="ui-block-b"><input type="submit" data-icon="arrow-r" data-iconpos="right" data-theme="b" value="Submit" /></div>
      </div>
    </p>

  </div>
  <?php include("includes/footer.php"); ?>
</div>

</form>
```

这些是我们在本章早些时候提到的脚本：

```js
 <script type="text/javascript">
  function showHideOrderNameContainer(){
   if($("#saveOrder").attr("checked")){
    $("#ordernameContainer").show();
   }else{
    $("#ordernameContainer").hide();
   }
  }

  //page refresh mitigation
  $("[data-role='page']").live("pagebeforeshow", function(){
   if(document.location.hash != ""){
    var $firstRequiredInput = $("input.pageRequired").first();
    if($firstRequiredInput.val() == ""){
     var redirectPage = $firstRequiredInput.closest("[data-role='page']");
     $.mobile.changePage(redirectPage);
    }
   }

  });
 </script>
</body>
</html>
```

这是自从集成 jQuery Validate 以来的 `meta.php` 文件：

```js
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">
<link href='http://fonts.googleapis.com/css?family=Marvel'rel='stylesheet' type='text/css'>
<linkrel="stylesheet" href="http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.css"/>
<link rel="stylesheet" href="css/custom.css" />
<script src="img/jquery-1.8.2.min.js"></script>
<script src="img/jquery.cookie.js"></script>
<script src="img/jquery.validate.min.js"></script>
<script src="img/global.js"></script>
<script src="img/jquery.mobile-1.2.0.min.js"></script>
<title><?=$documentTitle?></title>
```

经过三章，以下可能可以称为主 JavaScript 文件（`global.js`）。基本上是我在每个项目中使用的文件，只有轻微的变化：

```js
var _gaq = _gaq || []; 
var GAID = 'UA-XXXXXXXX-X'; 

/*******************************************************/
/* Load Google Analytics only once the page is fully loaded.
/*******************************************************/
$(document).ready(function(e) { 
(function() { 
var ga = document.createElement('script'); 
ga.type = 'text/javascript'; 
ga.async = true; 
ga.src = ('https:' == document.location.protocol ? 
'https://ssl' : 'http://www') +'.google-analytics.com/ga.js'; 
var s = document.getElementsByTagName('script')[0]; 
s.parentNode.insertBefore(ga, s); 
})();
});

/*******************************************************/
/* Upon jQM page initialization, place hooks on links with 
/* data-pageview attributes to track more with GA.
/* Also, hook onto the full-site links to make them cookie
/* the user upon click. 
/*******************************************************/
$(document).on('pageinit', function (event, ui) { 
$page = $(event.target); 

$page.find("[data-pageview]").click(function(){ 
var $eventTarget = $(this); 
if($eventTarget.attr("data-pageview") == "href"){ 
_gaq.push(['_trackPageview', 
$eventTarget.attr("href")]); 
}else{ 
_gaq.push(['_trackPageview', 
$eventTarget.attr("data-pageview")]); 
} 
}); 

$page.find("a.fullSiteLink").click(function(){ 
$.cookie("fullSiteClicked","true", {
path: "/", 
expires:3600
}); 
}); 

/*******************************************************/
/* Find any form with the class of validateMe and hook in
/* jQuery Validate.  Also, override the error placement.
/*******************************************************/
//Any form that might need validation 
$("form.validateMe").each(function(index, element) { 
var $form = $(this);
var v = $form.validate({
errorPlacement: function(error, element) { 
var dataErrorAt = element.attr("data-error-at"); if (dataErrorAt) 
$(dataErrorAt).html(error); 
else
error.insertBefore(element);
      }
});     
});  

/*******************************************************/
/* Hook in the validateContinue buttons.
/*******************************************************/
$page.find(".validateContinue").click(function(){ 
if($(this).closest("form").data("validator").form()){ return true;
}else{
event.stopPropagation(); 
event.preventDefault();
return false;
}
}); 
});   

/*******************************************************/
/* Every time a page shows, register it in GA.
/*******************************************************/

$(document).on('pageshow', function (event, ui) { 
try {
_gaq.push(['_setAccount', GAID]);
if ($.mobile.activePage.attr("data-url")) { 
_gaq.push(['_trackPageview', 
$.mobile.activePage.attr("data-url")]);
} else {
_gaq.push(['_trackPageview']);
    }
} catch(err) {}  
});  

/*******************************************************/
/*  Add the custom validator class to allow for validation 
/*  on multi-page forms.
/*******************************************************/
$.validator.addMethod("pageRequired", function(value, element) {
var $element = $(element);
if( $element.closest("."+$.mobile.subPageUrlKey)
.hasClass($.mobile.activePageClass)) 
{  
return !this.optional(element);  
} 
return "dependency-mismatch";  
}, $.validator.messages.required); 
```

# 使用 Google Analytics 进行电子商务跟踪

到目前为止，我们所跟踪的只是页面浏览量。确保非常有用，但大多数经理和业主都喜欢他们的报告。在感谢页面上，我们应该包含一些简单的电子商务跟踪。同样，由于 jQuery Mobile 的基于 Ajax 的导航系统，我们需要微调默认示例，以使其完全符合 jQM 的工作原理。

这是感谢页面（`thankyou.php`）的完整代码，其中的电子商务跟踪设置为只有在页面显示后才运行：

```js
<!DOCTYPE html>
<html>
<?php 
  $documentTitle = "Menu | Nicky's Pizza";

  $headerLeftHref = "index.php";
  $headerLeftLinkText = "Home";
  $headerLeftIcon = "home";

  $headerRightHref = "tel:8165077438";
  $headerRightLinkText = "Call";
  $headerRightIcon = "grid";

  $fullSiteLinkHref = "/index.php";
?>
<head>
  <?php include("includes/meta.php"); ?>
</head>

<body>
<div data-role="page" id="orderthankyou">
  <?php 
    $headerTitle = "Thank you"; 
    include("includes/header.php"); 
  ?>
  <div data-role="content" >
    <h2>Thank you for your order. </h2>
    <p>In a few minutes, you should receive an email confirming your order with an estimated delivery time.</p>

    <script type="text/javascript">
      $("#orderthankyou").live('pageshow', function(){
        _gaq.push(['_addTrans',
          '1234',                      // order ID - required
          'Mobile Checkout',  // affiliation or store name
          '21.99',                    // total - required
          '1.29',                     // tax
          ' ',                          // shipping
          'Kansas City',       // city
          'MO',              // state or province
          'USA'              // country
          ]);
        _gaq.push(['_trackTrans']); //submits transaction to the Analytics servers
      });
    </script>
  </div>
  <?php include("includes/footer.php"); ?>
</div>

</body>
</html>

```

# 摘要

表单并不是什么新鲜事物。自从互联网问世以来，我们就一直在使用它们。它们并不起眼，但可以是优雅、有效和响应灵敏的。jQuery Mobile 让您在基于触摸的界面中更有效地创建表单。现在，您可以通过多页面表单和客户端验证进一步完善它。不要低估这两种技术配合使用时的威力。当客户几乎可以在不必返回服务器的情况下完成所需的一切时，体验会自动得到提升。混合使用观察用户在您的网站上是如何浏览、他们喜爱的内容以及他们的流失点的能力，将帮助您打造更具吸引力的体验。只需记住，在思考分析数据时，重要的不是绝对数字，而是趋势；在完成这些基础工作之后，让我们着手研究一些更有趣的技术吧。在下一章中，我们将开始研究地理定位等内容。


# 第四章：QR 码、地理定位、Google 地图 API 和 HTML5 视频

我们已经讨论了许多小型和大型企业的核心关注点。现在让我们把目光转向其他可能会让媒体公司感兴趣的概念。在本章中，我们将看一下一个电影院连锁，但实际上，这些概念可以应用于任何具有多个实体位置的企业。

在本章中，我们将涵盖：

+   QR 码

+   基本地理定位

+   整合 Google 地图 API

+   链接和嵌入视频

# QR 码

我们热爱我们的智能手机。我们喜欢展示我们的智能手机可以做什么。所以，当那些充满神秘感的方块开始在各个地方出现并迷惑着大众时，智能手机用户迅速行动起来，并以同样过度热情的方式向人们展示这是怎么一回事，就像我们掏出它们来回答甚至是路过听到的最琐碎的问题一样。而且，由于看起来 NFC 不会很快普及，我们最好熟悉 QR 码以及如何利用它们。

![QR 码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_00.jpg)

数据显示，根据调查，QR 码的知识和使用率非常高：([`researchaccess.com/2012/01/new-data-on-qr-code-adoption/`](http://researchaccess.com/2012/01/new-data-on-qr- code-adoption/))

+   超过三分之二的智能手机用户扫描过码

+   超过 70%的用户表示他们会再次这样做（尤其是为了折扣）

等等，这和 jQuery Mobile 有什么关系？流量。大量成功的流量。如果只有百分之二的人点击横幅广告，那么这被认为是成功的 ([`en.wikipedia.org/wiki/Clickthrough_rate`](http://en.wikipedia.org/wiki/Clickthrough_rate))。QR 码的点击率超过 66%！我会说这是吸引人们注意我们创造物的一个相当好的方式，因此应该引起关注。但 QR 码不仅仅用于 URL。在下面的 QR 码中，我们有一个 URL、一个文本块、一个电话号码和一个短信：

![QR 码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_11.jpg)

### 提示

有许多生成 QR 码的方法 ([`www.the-qrcode-generator.com/`](http://www.the-qrcode-generator.com/)，[`www.qrstuff.com/`](http://www.qrstuff.com/))。实际上，只需在 Google 上搜索`QR Code Generator`，你就会有很多选择。

让我们考虑一个当地的电影院连锁。Dickinson Theatres ([dtmovies.com](http://dtmovies.com)) 自 1920 年代起就存在，并考虑加入移动领域。也许他们会投资于移动网站，并在公交车站和其他户外场所放置海报和广告。自然地，人们会开始扫描，这对我们很有价值，因为他们会告诉我们哪些位置是有效的。这真的是广告业的首创。我们有一个媒介似乎激励人们在扫描时与设备互动，这将告诉我们他们扫描时在哪里。地理位置很重要，这可以帮助我们找到合适的位置。

# 地理定位

当 GPS 首次出现在手机上时，除了紧急情况下的警察跟踪之外，它几乎没有什么用处。今天，它使我们手中的设备比我们的个人电脑更加个性化。目前，我们可以非常可靠地获得纬度、经度和时间戳。W3C 的地理位置 API 规范可以在[`dev.w3.org/geo/api/spec-source.html`](http://dev.w3.org/geo/api/spec-source.html)找到。目前，我们假装有一张海报，提示用户扫描 QR 码以找到最近的影院和放映时间。它会带用户到这样的页面：

![地理定位](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_05.jpg)

由于没有比共进晚餐和看电影更好的初次约会，看电影的人群倾向于偏年轻一些。不幸的是，这群人通常没有很多钱。他们可能比较倾向于使用功能手机而不是智能手机。有些人可能只有非常基本的浏览器。也许他们有 JavaScript，但我们不能指望它。如果有的话，他们可能会有地理位置信息。无论如何，考虑到受众，渐进增强将是关键。

我们要做的第一件事是创建一个基本级别的页面，其中包含一个简单的表单，该表单将向服务器提交一个邮政编码。由于我们使用了之前的模板，我们将为表单添加验证，供那些使用`validateMe`类的 JavaScript 的人使用。如果他们有 JavaScript 和地理位置，我们将用一条消息替换表单，说我们正在尝试找到他们的位置。目前，不要担心创建这个文件。此时源代码不完整。此页面将不断发展，最终版本将在文件`qrresponse.php`中的本章源包中，如以下代码所示：

```js
<?php  
  $documentTitle = "Dickinson Theatres";  
  $headerLeftHref = "/"; 
  $headerLeftLinkText = "Home"; 
  $headerLeftIcon = "home";  

  $headerTitle = "";  	
  $headerRightHref = "tel:8165555555"; 
  $headerRightLinkText = "Call"; 
  $headerRightIcon = "grid";  

  $fullSiteLinkHref = "/";  
?> 
<!DOCTYPE html>
<html>
<head> 
  <?php include("includes/meta.php"); ?>
</head>
<body>
<div id="qrfindclosest" data-role="page">
  <div class="logoContainer ui-shadow"></div>
  <div data-role="content">
    <div id="latLong>
      <form id="findTheaterForm" action="fullshowtimes.php"method="get" class="validateMe">             
        <p>
          <label for="zip">Enter Zip Code</label>
          <input type="tel" name="zip" id="zip"class="required number"/>
        </p>
        <p><input type="submit" value="Go"></p>             
      </form>
    </div>         
    <p>         
      <ul id="showing" data-role="listview" class="movieListings"data-dividertheme="g">              
      </ul>         
    </p>
  </div>
  <?php include("includes/footer.php"); ?>
</div>
<script type="text/javascript">
 //We'll put our page specific code here soon
</script>
</body>
</html>
```

对于没有 JavaScript 的任何人来说，这就是他们会看到的，没有什么特别的。我们可以用一点 CSS 来装饰它，但有什么意义呢？如果他们使用的是没有 JavaScript 的浏览器，那么他们的浏览器很可能也不擅长呈现 CSS。这其实没关系。毕竟，渐进增强并不一定意味着让它对每个人都很美好，它只意味着确保它对每个人都有效。大多数人永远不会看到这个，但如果他们看到了，它会正常工作。

![地理定位](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_06.jpg)

对于其他人，我们需要开始用 JavaScript 来以可以编程消化的格式获取我们的剧院数据。JSON 对于这个任务非常合适。如果你已经熟悉 JSON 的概念，现在就跳到下一段。如果你对它不熟悉，基本上，它是一种在互联网上传输数据的另一种方法。它就像 XML 但更有用。它不那么冗长，并且可以直接使用 JavaScript 进行交互和操作，因为它实际上是用 JavaScript 写的。JSON 是 JavaScript 对象表示法的首字母缩略词。特别感谢道格拉斯·克罗克福德（JSON 之父）。XML 在服务器上还有它的位置。如果你可以得到 JSON，它在浏览器中作为一种数据格式是没有理由存在的。这是一个如此普遍的观点，以至于在我参加的最后一次开发者大会上，有一个演讲者在问道时发出笑声，“还有谁在真正使用 XML 吗？”

本章的示例代码列有完整的剧院清单，但这应该足够让我们开始了。对于这个示例，我们将把 JSON 数据存储在`/js/theaters.js`中。

```js
{ 
  "theaters":[ 
    {
      "id":161,
      "name":"Chenal 9 IMAX Theatre", 
      "address":"17825 Chenal Parkway",
      "city":"Little Rock",
      "state":"AR",
      "zip":"72223",
      "distance":9999,
      "geo":{"lat":34.7684775,"long":-92.4599322}, 
      "phone":"501-821-2616"
    },
    {
      "id":158,
      "name":"Gateway 12 IMAX Theatre", 
      "address":"1935 S. Signal Butte", 
      "city":"Mesa",
      "state":"AZ",
      "zip":"85209",
      "distance":9999,
      "geo":{"lat":33.3788674,"long":-111.6016081}, 
      "phone":"480-354-8030"
    },
    {
      "id":135,
      "name":"Northglen 14 Theatre",
      "address":"4900 N.E. 80th Street",
      "city":"Kansas City",
      "state":"MO",
      "zip":"64119",
      "distance":9999,
      "geo":{"lat":39.240027,"long":-94.5226432}, 
      "phone":"816-468-1100"
    }   
  ]
}
```

现在我们有了要处理的数据，我们可以准备在页面中准备好脚本。让我们把以下的 JavaScript 代码片段放在 HTML 底部的脚本标签中，就在我们的注释处：`我们很快就会把我们的页面特定代码放在这里`。

```js
//declare our global variables
var theaterData = null; 
var timestamp = null; 	
var latitude = null; 
var longitude = null; 	
var closestTheater = null; 

//Once the page is initialized, hide the manual zip code form
//and place a message saying that we're attempting to find 
//their location.
$(document).on("pageinit", "#qrfindclosest", function(){
  if(navigator.geolocation){   
     $("#findTheaterForm").hide(); 
     $("#latLong").append("<p id='finding'>Finding your location...</p>"); 
  } 
});

//Once the page is showing, go grab the theater data and find out which one is closest.  
$(document).on("pageshow", "#qrfindclosest", function(){ 
 theaterData = $.getJSON("js/theaters.js", 
 function(data){ 
      theaterData = data;
      selectClosestTheater();
    });
}); 

function selectClosestTheater(){ 
 navigator.geolocation.getCurrentPosition(
   function(position) { //success 
  latitude = position.coords.latitude; 
  longitude = position.coords.longitude; 
  timestamp = position.timestamp; 
  for(var x = 0; x < theaterData.theaters.length; x++){  var theater = theaterData.theaters[x]; 
    var distance = getDistance(latitude, longitude,theater.geo.lat, theater.geo.long); 
    theaterData.theaters[x].distance = distance; 
  }} 
  theaterData.theaters.sort(compareDistances); 
  closestTheater = theaterData.theaters[0]; 	
 _gaq.push(['_trackEvent', "qr", "ad_scan",(""+latitude+","+longitude) ]); 
  var dt = new Date(); 
  dt.setTime(timestamp); 
  $("#latLong").html("<div class='theaterName'>"
    +closestTheater.name+"</div><strong>"
    +closestTheater.distance.toFixed(2)
    +"miles</strong><br/>"
    +closestTheater.address+"<br/>"
    +closestTheater.city+", "+closestTheater.state+" "
    +closestTheater.zip+"<br/><a href='tel:"
    +closestTheater.phone+"'>"
    +closestTheater.phone+"</a>"); 
  $("#showing").load("showtimes.php", function(){ 
    $("#showing").listview('refresh'); 
  });
}, 
function(error){ //error  
  switch(error.code)  	
  { 
    case error.TIMEOUT: 
      $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Timeout</div>"); 
      break; 
    case error.POSITION_UNAVAILABLE: 
      $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Position unavailable</div>"); 
      break; 
    case error.PERMISSION_DENIED: 
      $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Permission denied.You may want to check your settings.</div>"); 
      break; 
    case error.UNKNOWN_ERROR:  
      $("#latLong").prepend("<div class='ui-bar-e'>Unknown error while trying to access your position.</div>"); 
      break; 
   }
   $("#finding").hide();   
   $("#findTheaterForm").show(); 
},
{maximumAge:600000}); //nothing too stale
}
```

这里的关键是`geolocation.getCurrentPosition`函数，它将提示用户允许我们访问他们的位置数据，就像在 iPhone 上所示的那样。

![地理位置](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_07.jpg)

如果有人是隐私倡导者，他们可能已经关闭了所有的位置服务。在这种情况下，我们需要告知用户他们的选择已经影响了我们帮助他们的能力。这就是错误函数的作用。在这种情况下，我们将显示一个错误消息，并再次显示标准表单。

一旦我们有了用户的位置和剧院列表，就该按距离对剧院进行排序并显示最近的一个。以下是一个相当通用的代码，我们可能希望在多个页面上使用。因此，我们会把它放到我们的`global.js`文件中：

```js
function getDistance(lat1, lon1, lat2, lon2){ 
  //great-circle distances between the two points
  //because the earth isn't flat 
  var R = 6371; // km 	
  var dLat = (lat2-lat1).toRad(); 
  var dLon = (lon2-lon1).toRad(); 
  var lat1 = lat1.toRad(); 
  var lat2 = lat2.toRad();  
  var a = Math.sin(dLat/2) * Math.sin(dLat/2) +  
    Math.sin(dLon/2) * Math.cos(lat1) * 
    Math.cos(lat2);  
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));  
  var d = R * c; //distance in km 
  var m = d * 0.621371;  //distance in miles 
  return m; 
} 
if (typeof(Number.prototype.toRad) === "undefined") {   
  Number.prototype.toRad = function() { 
    return this * Math.PI / 180;   
  } 
}  

function compareDistances(a,b) {   
  if (a.distance<b.distance) return -1;   
  if (a.distance>b.distance) return 1;   
  return 0; 
} 
```

有了所有这些组件，现在就足够简单获取用户的位置并找到最近的剧院。它将成为数组中的第一个，并且直接存储在全局变量`closestTheater`中。如果他们关闭了 JavaScript，我们将不得不使用一些服务器端的算法或 API 来找出最近的剧院（这超出了本书的范围）。无论如何，我们都会将每个剧院的放映时间作为一个平面文件的列表项集合起来（`showtimes.php`）。在现实世界情况下，这将是由数据库驱动的，并且我们将调用带有正确剧院 ID 的 URL 的页面。现在，以下的代码就够了：

```js
<li data-role="list-divider">Opening This Week</li>     
<li>         
  <a href="movie.php?id=193818">             
    <img src="img/darkknightrises.jpeg">             
    <h3>Dark Knight Rises</h3>             
    <p>PG-13 - 2h 20m<br/>
      <strong>Showtimes:</strong> 
      12:00 - 12:30 - 1:00 - 1:30 - 3:30 - 4:00 - 4:30 – 
      7:00 - 7:15 - 7:30 - 7:45 - 8:00 - 10:30 - 10:45
    </p>         
  </a>     
</li>     
<li>         
  <a href="moviedetails.php?id=193812">
    <img src="img/iceagecontinentaldrift.jpeg">             
    <h3>Ice Age 4: Continental Drift</h3>
    <p>PG - 1h 56m<br/>
      <strong>Showtimes:</strong> 10:20 AM - 10:50 AM – 
      12:40 - 1:15 - 3:00 - 7:00 - 7:30 - 9:30
    </p>         
  </a>     
</li>     
<li data-role="list-divider">Also in Theaters</li>
<li>
  <a href="moviedetails.php?id=194103">
    <img src="img/savages.jpeg">             
    <h3>Savages</h3>
    <p>R - 7/6/2012<br/><strong>Showtimes:</strong> 
      10:05 AM - 1:05 - 4:05 - 7:05 - 10:15
    </p>         
  </a>     
</li>     
<li>
  <a href="moviedetails.php?id=194226">
    <img src="img/katyperrypartofme.jpeg">             
    <h3>Katy Perry: Part of Me</h3>
    <p>PG - 7/5/2012<br/>
      <strong>Showtimes:</strong> 10:05 AM - 1:05 – 
      4:05 - 7:05 - 10:15
    </p>         
  </a>     
</li>     
<li>         
  <a href="moviedetails.php?id=193807">
    <img src="img/amazingspiderman.jpeg">             
    <h3>Amazing Spider-Man</h3>
    <p>PG-13 - 7/5/2012<br/>
      <strong>Showtimes:</strong> 10:00 AM - 1:00 – 
      4:00 - 7:00 - 10:00
    </p>         
  </a>     
</li> 
```

我们使用以下的页面片段来引入这个页面片段的：

```js
$("#showing").load("showtimes.php", function(){ 
    $("#showing").listview('refresh'); 
});
```

在这种情况下，我们有包含仅列出视图项的 `showtimes.php` 文件，并且我们直接将它们注入到视图列表中，然后刷新。实现同样效果的另一种方法是拥有另一个文件，比如 `fullshowtimes.php`，它是一个完全渲染的页面，带有标题、页脚和其他一切。这在 JavaScript 或地理位置信息不可用且我们必须返回标准页面提交的情况下是完美的。

```js
<?php  
  $documentTitle = "Showtimes | Northglen 16 Theatre";  
  $headerLeftHref = "/"; 
  $headerLeftLinkText = "Home"; 
  $headerLeftIcon = "home";  
  $headerTitle = "";  	
  $headerRightHref = "tel:8165555555"; 
  $headerRightLinkText = "Call"; 
  $headerRightIcon = "grid";  
  $fullSiteLinkHref = "/";  
?> 
<!DOCTYPE html> 
<html> 
<head> 
  <?php include("includes/meta.php"); ?>  
</head>  
<body> 
  <div id="qrfindclosest" data-role="page">     
    <div class="logoContainer ui-shadow"></div>     
    <div data-role="content">
      <h3>Northglen 14 Theatre</h3>

      <p><a href="https://maps.google.com/maps?q=Northglen+14+Theatre,+Northeast+80th+Street,+Kansas+City,+MO&hl=en&sll=38.304661,-92.437099&sspn=7.971484,8.470459&oq=northglen+&t=h&hq=Northglen+14+Theatre,&hnear=NE+80th+St,+Kansas+City,+Clay,+Missouri&z=15">4900 N.E. 80th Street<br>         
        Kansas City, MO 64119</a>
      </p>

      <p><a href="tel:8164681100">816-468-1100</a></p>                  
      <p>
        <ul id="showing" data-role="listview"class="movieListings" data-dividertheme="g">             
          <?php include("includes/showtimes.php"); ?>             
        </ul>
      </p>
    </div>     
    <?php include("includes/footer.php");?> 
  </div> 
</body> 
</html>
```

然后，我们不再仅仅使用页面调用加载函数，而是加载整个页面，然后使用以下代码选择我们要注入的页面元素：

```js
$("#showing").load("fullshowtimes.php #showing li", function(){ 
  $("#showing").listview('refresh'); 
});
```

当然，这种做法效率较低，但值得注意的是，这样的事情是可以做到的。在未来，这几乎肯定会派上用场。

# 集成谷歌地图 API

到目前为止，我们已经很好地完成了自己的工作。我们可以告诉哪个影院最近，以及直线距离。不幸的是，尽管它有很多优点，但 21 世纪并没有让我们所有人都拥有私人喷气式背包。因此，最好不要显示那个距离。最有可能的是，他们会开车、乘坐公交车、骑自行车或步行。

让我们利用谷歌地图 API ([`developers.google.com/maps/documentation/javascript/`](https://developers.google.com/maps/documentation/javascript/))。如果您的网站要使用大量 API，请准备付费购买商业定价。对于我们来说，当我们处于开发阶段时，没有必要付费。

这是我们即将构建的样子：

![集成谷歌地图 API](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_08.jpg)

首先，我们需要另一页来显示地图和方向，以及将实际从谷歌地图 API 加载地图的脚本，使用以下代码：

```js
<div id="directions" data-role="page"> 
  <div data-role="header">         
    <h3>Directions</h3>     
  </div>     
  <div data-role="footer">         
    <div data-role="navbar" class="directionsBar">             
      <ul>                 
        <li>
          <a href="#" id="drivingButton"onClick="showDirections('DRIVING')">
            <div class="icon driving"></div>
          </a>
        </li>                 
        <li>
          <a href="#" id="transitButton"onClick="showDirections('TRANSIT')">
            <div class="icon transit"></div>
          </a>
        </li>
        <li>
          <a href="#" id="bicycleButton"onClick="showDirections('BICYCLING')">
            <div class="icon bicycle"></div>
          </a>
        </li>                 
        <li>
          <a href="#" id="walkingButton"onClick="showDirections('WALKING')">
            <div class="icon walking"></div>
          </a>
        </li>
      </ul>
    </div> 
  </div>     
  <div id="map_canvas"></div>     
  <div data-role="content" id="directions-panel">
  </div> 
</div> 
<scriptsrc="img/js?sensor=true"></script>
```

我们页面有几个重要部分。首先是 `footer` 属性中的 `navbar` 属性，用于指向剧院的方向。您可能没有意识到的是，页脚实际上不一定要位于页面底部。当您在 `footer` 属性中使用 `navbar` 属性时，您单击的链接将保持其活动状态。如果没有周围的页脚，链接将仅闪烁一次活动状态，然后恢复正常。`map_canvas` 和 `directions-panel` 属性将由谷歌地图 API 填充。

现在，我们需要更新额外图标和地图约束的 CSS 代码。和以前一样，我们将它们保存在 `/css/custom.css` 的位置。

```js
.directionsBar .icon{ 	  
  height:28px;   
  width:34px;   
  margin:auto;   
  background-repeat:no-repeat;   
  background-position:center center; 
} 

.directionsBar .driving{ 
  background-image:url(../icons/xtras-white/16-car.png); 
  background-size:34px 19px; 
} 
.directionsBar .transit{ 
  background-image:url(../icons/xtras-white/15-bus.png); 
  background-size:22px 28px; 
} 
.directionsBar .bicycle{ 	
  background-image:url(../icons/xtras-white/13-bicycle.png); 
  background-size:34px 21px; 
} 
.directionsBar .walking{ 
  background-image:url(../icons/icons-white/102-walk.png); 
  background-size:14px 27px; 
} 
.theaterAddress{ 
  padding-left:35px; 
  background-image:url(../icons/icons-gray/193-location-arrow.png); 
  background-size:24px 24px; 
  background-repeat:no-repeat;  
} 
.theaterPhone{ 
  padding-left:35px; 
  background-image:url(../icons/icons-gray/75-phone.png); 
  background-size:24px 24px; 
  background-repeat:no-repeat; 
  height: 24px;  
} 

#map_canvas { height: 150px; }  

@media only screen and (-webkit-min-device-pixel-ratio: 1.5),    
  only screen and (min--moz-device-pixel-ratio: 1.5),    
  only screen and (min-resolution: 240dpi) { 
    .directionsBar .driving{ 
      background-image:url(../icons/xtras-white/16-car@2x.png); 
    }
    .directionsBar .transit{ 
      background-image:url(../icons/xtras-white/15-bus@2x.png); 
    } 
    .directionsBar .bicycle{ 
      background-image:url(../icons/xtras-white/13bicycle@2x.png); 
    } 
    .directionsBar .walking{ 
      background-image:url(../icons/icons-white/102-walk@2x.png); 
    } 
    .theaterAddress{ 
      background-image:url(../icons/icons-gray/193-location-arrow@2x.png); 
    } 
    .theaterPhone{ 
      background-image:url(../icons/icons-gray/75-phone@2x.png); 
    } 
  }  
```

接下来，我们将在当前页面脚本中添加一些全局变量和函数。

```js
var directionData = null; 
var directionDisplay; 	
var directionsService = new google.maps.DirectionsService(); 
var map; 

function showDirections(travelMode){ 
  var request = { 
    origin:latitude+","+longitude, 
    destination:closestTheater.geo.lat+","
      +closestTheater.geo.long, 
    travelMode: travelMode 
}; 

  directionsService.route(request, 
    function(response, status){ 
      if (status == google.maps.DirectionsStatus.OK){
        directionsDisplay.setDirections(response); 
      } 
    }); 

  $("#directions").live("pageshow", 
    function(){ 
      directionsDisplay = new google.maps.DirectionsRenderer(); 
      var userLocation = new google.maps.LatLng(latitude, longitude); 
      var mapOptions = {
        zoom:14, 
        mapTypeId: google.maps.MapTypeId.ROADMAP, 
        center: userLocation 
      } 
      map = new google.maps.Map(   
        document.getElementById('map_canvas'), mapOptions);
        directionsDisplay.setMap(map);   
        directionsDisplay.setPanel(
        document.getElementById('directions-panel')
      ); 
      showDirections(
      google.maps.DirectionsTravelMode.DRIVING
  ); 
  $("#drivingButton").click(); 
});
```

在这里，我们看到了用于保存谷歌对象的全局变量。`showDirections` 方法被设计为接受一个表示四种不同出行方式的字符串：`'DRIVING'`、`'TRANSIT'`、`'BICYCLING'` 和 `'WALKING'`。

我们可以在弄清最近的影院的同时填充地图和方向。这实际上会为用户带来很好的体验。然而，没有分析数据显示大多数人确实需要方向，那么产生这些成本就没有意义了。最终，这是一个商业决策，但是任何规模的客户群体都可能受到 API 成本的打击。目前来看，最好在用户转到`directions`页面时触发地图和方向的加载。

# 极客时刻—GPS 监控

那么，让我们来极客一分钟。我们所做的对于大多数情况可能已经足够了。我们展示了一张地图和逐步转向指南。让我们再进一步。地理位置 API 不仅仅确定您当前的位置。它包括一个时间戳（没什么大不了的）并且可以允许您使用方法`navigator.geolocation.watchPosition`（[`dev.w3.org/geo/api/spec-source.html#watch-position`](http://dev.w3.org/geo/api/spec-source.html#watch-position)）连续监视用户的位置。这意味着，只需要一点点努力，我们就可以将我们之前的方向页面变成一个持续更新的方向页面。在示例代码中，所有这些都包含在文件`qrresponse2.php`中。

再次更新太频繁可能会变得很昂贵。因此，我们应该真正限制地图和方向的重新绘制频率。对于每种交通模式，更新之间需要的有意义时间量是不同的。趁热打铁，让我们重新设计按钮以包含这些选项。这是整个页面的代码：

```js
<?php  
  $documentTitle = "Dickinson Theatres";  

  $headerLeftHref = "/"; 
  $headerLeftLinkText = "Home"; 
  $headerLeftIcon = "home";  

  $headerTitle = "";  	

  $headerRightHref = "tel:8165555555"; 
  $headerRightLinkText = "Call"; 
  $headerRightIcon = "grid";  

  $fullSiteLinkHref = "/";  
?> 
<!DOCTYPE html> 
<html> 
<head> 
  <?php include("includes/meta.php"); ?> 
  <style type="text/css"> 
    .logoContainer{ 
      display:block; 
      height:84px; 
      background-image:url(images/header.png);  
      background-position:top center;   
      background-size:885px 84px;
      background-repeat:no-repeat;
    }  
  </style>     
  <script type="text/javascript"src="img/js?key=asdfafefaewfacaevaeaceebvaewaewbk&sensor=true"></script> 
</head>  
<body> 
  <div id="qrfindclosest" data-role="page">
    <div class="logoContainer ui-shadow"></div>
    <div data-role="content">
      <div id="latLong">
        <form id="findTheaterForm" action="fullshowtimes.php"method="get" class="validateMe">
          <p>
            <label for="zip">Enter Zip Code</label>
            <input type="tel" name="zip" id="zip"class="required number"/>
          </p>
          <p><input type="submit" value="Go"></p>              
        </form>
      </div>
      <p>         
        <ul id="showing" data-role="listview"class="movieListings" data-dividertheme="g">
        </ul>         
      </p>     
    </div>          
    <?php include("includes/footer.php"); ?> 
  </div>  

  <div id="directions" data-role="page">
    <div data-role="header">
      <h3>Directions</h3>
    </div>
    <div data-role="footer">
      <div data-role="navbar" class="directionsBar">             
        <ul>
          <li>
            <a href="#" id="drivingButton"data-transMode="DRIVING" data-interval="10000"
>
              <div class="icon driving"></div>
            </a>
          </li>
          <li>
            <a href="#" id="transitButton"data-transMode="TRANSIT" data-interval="10000">
              <div class="icon transit"></div>
            </a>
          </li>
          <li>
            <a href="#
" id="bicycleButton"data-transMode="BICYCLING" data-interval="30000">
              <div class="icon bicycle"></div>
            </a>
          </li>
          <li>
            <a href="#" id="walkingButton
"data-transMode="WALKING" data-interval="60000">
              <div class="icon walking"></div>
            </a>
          </li>
        </ul>
      </div>
    </div>
    <div id="map_canvas"></div>
    <div data-role="content" id="directions-panel"></div> 
  </div> 
```

那么，现在让我们看一下此 GPS 监控版本的页面脚本：

```js
  <script type="text/javascript"> 
    //declare our global variables 
    var theaterData = null; 
    var timestamp = null; 
    var latitude = null; 
    var longitude = null; 
    var closestTheater = null; 
    var directionData = null; 
    var directionDisplay; 
    var directionsService = new 
      google.maps.DirectionsService(); 
    var map; 
    var positionUpdateInterval = null; 
    var transporationMethod = null;   

    //Once the page is initialized, hide the manual zip form 
    //and place a message saying that we're attempting to find their location. 
    $(document).on("pageinit", "#qrfindclosest", function(){ 
      if(navigator.geolocation){ 
        $("#findTheaterForm").hide(); 
        $("#latLong").append("<p id='finding'>Finding your 
           location...</p>");
      } 
    }); 

    $(document).on("pageshow", "#qrfindclosest", function(){ 
      theaterData = $.getJSON("js/theaters.js", 
        function(data){ 
          theaterData = data; 
          selectClosestTheater(); 
    }); 

 $("div.directionsBar a").click(function(){
 if(positionUpdateInterval != null){ 
 clearInterval(positionUpdateInterval);
 } 
 var $link = $(this);
      transporationMethod = $link.attr("data-transMode"); 
 showDirections(); 
 setInterval(function(){
 showDirections(); 
        },Number($link.attr("data-interval"))); 
 }); 

    function showDirections(){
      var request = {
        origin:latitude+","+longitude,   
          destination:closestTheater.geo.lat+","
          +closestTheater.geo.long,
        travelMode: transportationMethod
      }

      directionsService.route(request, 
        function(response, status) { 
          if (status == google.maps.DirectionsStatus.OK){       directionsDisplay.setDirections(response);
          }
      }); 
    }  

    $(document).on("pageshow", "#directions", function(){  
      directionsDisplay = new google.maps.DirectionsRenderer();
      var userLocation = new google.maps.LatLng(latitude, longitude);
      var mapOptions = {
        zoom:14,
        mapTypeId: google.maps.MapTypeId.ROADMAP, 
        center: userLocation
      }
      map = new google.maps.Map(document.getElementById('map_canvas'), mapOptions); 
      directionsDisplay.setMap(map);   
      directionsDisplay.setPanel(
        document.getElementById('directions-panel')); 
 if(positionUpdateInterval == null) { 
        transportationMethod = "DRIVING"; 
 positionUpdateInterval = setInterval(function(){
 showDirections(); 
 },(10000)); 
      } 
      $("#drivingButton").click();
  });

  function selectClosestTheater(){ 
 var watchId=navigator.geolocation.watchPosition(
        function(position){ //success 
        latitude = position.coords.latitude;
        longitude = position.coords.longitude; 
        timestamp = position.timestamp;
        var dt = new Date();
        dt.setTime(timestamp);

        for(var x = 0; x < theaterData.theaters.length; x++){ 
          var theater = theaterData.theaters[x]; 
          var distance = getDistance(latitude, longitude, 
            theater.geo.lat, theater.geo.long); 
          theaterData.theaters[x].distance = distance;      } 

        theaterData.theaters.sort(compareDistances);  
        closestTheater = theaterData.theaters[0]; 

        $("#latLong").html("<div class='theaterName'>"
          +closestTheater.name
          +"</div><p class='theaterAddress'><a href='#directions'>"         
          +closestTheater.address+"<br/>"
          +closestTheater.city+", "
          +closestTheater.state
          +" "+closestTheater.zip
          +"</a></p><p class='theaterPhone'><a href='tel:"
          +closestTheater.phone+"'>"
          +closestTheater.phone+"</a></p>"
        );

        $("#showing").load("fullshowtimes.php #showing li", 
          function(){ 	
            $("#showing").listview('refresh'); 
        });
      }
    }, 
    function(error){ //error    
     $("#findTheaterForm").show();   
     $("#finding").hide();
     switch(error.code) { 
       case error.TIMEOUT: 
         $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Timeout</div>"); 
         break;
       case error.POSITION_UNAVAILABLE: 
         $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Position unavailable</div>");
         break;
     case error.PERMISSION_DENIED: 
       $("#latLong").prepend("<div class='ui-bar-e'>Unable to get your position: Permission denied.You may want to check your settings.</div>"); 
         break;
       case error.UNKNOWN_ERROR: 
         $("#latLong").prepend("<div class='ui-bar-e'>Unknown error while trying to access your position.</div>"); 
         break; 
     }
  }); 
}  
</script>   
</body> 
</html> 
```

# 链接和嵌入视频

预览是电影行业的一个主打。我们可以像许多人一样直接链接到 YouTube 上的预览。这里是一个简单的做法：

```js
<p><a data-role="button"href="http://www.youtube.com/watch?v=J9DlV9qwtF0">Watch Preview</a></p> 
```

![链接和嵌入视频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_04_10.jpg)

那样会起作用，但问题是它会把用户带离您的网站。尽管从用户的角度来看这可能并不是世界末日，但这是一个大忌。

为了改善用户体验并将用户留在我们自己的网站上，让我们直接嵌入 HTML5 视频，并像我们在这里描述的那样使用通用图像作为电影预览。

尽管看起来它将在页面的一个极小的部分中播放，但在智能手机上，视频将以全屏横向模式播放。在 iPad 上的情况有些不同，它将在内嵌侧边以内联方式播放。

最终，我们希望使用以下代码将适合用户设备的合适尺寸的视频返回给用户。没有高分辨率显示屏的智能手机不会真的受益于 720p 视频。

```js
<video id="preview" width="100%" controlsposter="images/preview.gif"> 

  <source src="img/batmanTrailer-2_720.mp4" type="video/mp4"  media="only screen and (-webkit-min-device-pixel-ratio: 1.5),only screen and (min--moz-device-pixel-ratio: 1.5),only screen and (min-resolution: 240dpi)"/>                 

  <source src="img/batmanTrailer-1_480.mov"type="video/mov" />                 

  <a data-role="button"href="http://www.youtube.com/watch?v=J9DlV9qwtF0">Watch Preview</a> 

</video>  
```

如果浏览器识别 HTML5 视频标签，播放器将从顶部开始查找每个源标签，直到找到一个它知道如何播放并符合正确的媒体查询（如果已指定媒体查询）。如果浏览器不支持 HTML5 视频，它将不知道如何处理视频和源标签，并且简单地将它们视为有效的 XML 元素。它们将被当作多余的 `div` 标签，并显示链接按钮。

正如你所见，我们在这里添加了媒体查询到不同的资源。如果是高分辨率屏幕，我们将加载更漂亮的视频。你可以真正地通过添加许多不同的来源来深入研究：为普通智能手机添加一个 480p 的视频，为 iPhone 和早期的 iPad 添加一个 720p 的视频，为第三代 iPad 添加一个 1080p 的视频。这里唯一需要注意的是，即使苹果视网膜显示屏能够显示更美丽的视频，但它仍然必须通过同样的管道传输。加载一个较小的视频可能仍然更好，因为它会更快播放，并为客户节省带宽成本。

让我们为这张图片添加一点 CSS。我们将图片宽度保留在容器的 100%。在智能手机上，随着宽度的增加，图片比例将正确缩放。iPad 则不太一样。因此，让我们使用媒体查询来检测其屏幕分辨率，并为其指定一个显式高度，以更好地利用屏幕空间。

```js
 /* iPad ----------------*/ @media only screen and (min-device-width: 768px) and (max-device-width: 1024px) { 
  #preview{ height:380px;} 
}
```

# 总结

我们已经在智能手机上探索了现代媒体的边界。现在你可以思考一下 QR 码的用途，并利用它，找出用户所在位置，监视用户的位置，从谷歌获取方向和地图，并向用户提供响应式视频。

想想你刚刚学到的所有内容。创建一个社交连接的网站，允许用户获取彼此位置的地图，并随着彼此的接近或远离而持续更新，这有多难？如果包装和营销得当，那是很有价值的。

在下一章中，我们将利用 GPS 来提取你地理区域内的 Twitter 动态。我们还将研究从其他几个来源提取动态的方法，比如 reddit、RSS 动态等等。这将非常有趣。这是我最喜欢写的章节之一。
