# React 渐进式 Web 应用（一）

> 原文：[`zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D`](https://zh.annas-archive.org/md5/7B97DB5D1B53E3A28B301BFF1811634D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

使用 React 创建渐进式 Web 应用旨在为您提供关于 Web 开发未来的一切所需。**渐进式 Web 应用**（**PWA**）对于希望利用 Web 所能提供的最佳功能的公司来说越来越普遍，它们由最前沿的技术驱动，弥合了 Web 应用和本地应用之间的差距。

在本书中，我们将利用流行的 JavaScript 库 React.js 的强大功能来创建快速和功能齐全的用户界面。然后，我们将使用革命性的新 Web 技术添加渐进式 Web 应用程序功能，如推送通知和即时加载。最后，我们将简化应用程序的性能，并探讨如何最好地衡量其速度。

通过本书，您将对 React 和 PWA 感到舒适，并为 Web 的未来做好准备。

# 本书涵盖内容

第一章，*创建我们的应用结构*，简要概述了您将学习构建的内容--一个具有推送通知和离线支持的实时聊天应用程序。您将了解这种应用程序所面临的挑战，并对将在本书中讨论的技术进行简要概述。在本章结束时，您将使用 HTML 和 CSS 设置聊天应用程序的应用程序结构。

第二章，*使用 Webpack 入门*，指出在编写任何 React 代码之前，您需要设置 webpack 构建过程。在本章中，您将介绍 webpack；您将学会安装该软件包并设置一些基本配置，以及启动开发服务器。本章将使您准备好开始学习 React。

第三章，*我们应用的登录页面*，向您介绍 React 时间！在本章中，您将学会编写前两个组件：一个应用程序包装器来包含应用程序和一个 LoginContainer。了解如何使用 ReactDOM 和 JSX 进行渲染，并编写一个基本表单，允许用户登录。在本章结束时，您将熟悉并熟悉 React 语法。

第四章《使用 Firebase 轻松设置后端》告诉您登录表单看起来不错，但缺乏实际功能。为了继续前进，您将需要一个后端数据库和身份验证解决方案来与之通信。本章将向您介绍 Google 的 Firebase。在 Firebase 控制台上设置应用程序，然后为表单编程登录和注册功能。

第五章《使用 React 进行路由》让您知道一旦用户登录，您希望将他们重定向到主要的聊天视图。因此，在本章中，您将学会构建主视图，然后设置 React 路由器，允许用户在页面之间移动。最后，学会添加第三个视图——个人用户视图，并探索 URL 中的参数匹配。

第六章《完成我们的应用程序》将带您完成构建基本应用程序的最后一步，为聊天和用户视图添加功能。您将学会如何从 Firebase 中写入和读取数据，并利用 React 生命周期方法来实现。一旦完成，您的 Web 应用程序将完成，但它还不够先进！

第七章《添加服务工作者》涵盖了服务工作者及其工作原理。在这里，您将了解如何注册自定义服务工作者，并了解其生命周期，然后连接到默认的 Firebase 消息服务工作者。

第八章《使用服务工作者发送推送通知》教你配置应用程序，因为我们的服务工作者已经准备好，可以发送推送通知。您将使用 Firebase Cloud Messaging 来管理发送这些通知，并添加自定义功能来控制在桌面和移动设备上何时以及如何发送它们。

第九章《使用清单使我们的应用可安装》教授清单是一个 JSON 文件，允许用户将您的应用保存到他们的主屏幕上。您将学会创建清单，并了解最佳实践以及 iOS 特定的考虑因素。您还将学会自定义闪屏和图标。

第十章，*应用外壳*，阐述了应用外壳模式作为 PWA 中的关键概念，但它带来了哪些优势？您将介绍渐进增强的外壳和 RAIL 系统，然后将一些应用布局移出 React 以实现最佳渲染。

第十一章，*使用 Webpack 对 JavaScript 进行分块以优化性能*，探讨了 PRPL 模式、其目标和方法，以及如何在应用中实现它的概述。然后，您将深入研究，根据路由将 JavaScript 分块，并延迟加载次要路由。

第十二章，*准备缓存*，介绍了如何利用服务工作线程实现离线功能，通过了解新的缓存 API 以及如何将其与服务工作线程一起使用来缓存 JavaScript 分块。

第十三章，*审计我们的应用*，现在是检查我们工作的时候了！在本章中，您将介绍 Lighthouse 并了解如何使用 Lighthouse 审计 PWA。

第十四章，*结论和下一步*，您的第一个 PWA 已经完成！在开发过程中，您手动构建了大部分 PWA 基础设施。在本章中，您将学习有关辅助库和快捷方式以节省时间，并探索 PWA 开发的未来。此外，您还将了解有关未来项目想法和改进的建议，作为额外的挑战。

# 本书所需内容

您所需的只是一台可以运行 Node.js 的计算机（[`nodejs.org/en/download/`](https://nodejs.org/en/download/)），一个用于编写代码的文本编辑器，以及最新版本的 Chrome 浏览器。如果您想在移动设备上测试应用程序，还需要一部 Android 或 iOS 手机。

# 本书适合对象

本书适用于想要开发高性能 Web 用户界面的 JavaScript 开发人员。本书需要对 HTML、CSS 和 JavaScript 有基本的了解。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：在`App.js`中，我们首先导入`LoginContainer`。

代码块设置如下：

```jsx
import React, { Component } from 'react';
import LoginContainer from './LoginContainer';
import './app.css';

class App extends Component {
  render() {
    return <LoginContainer />
  }
}

export default App;
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
if (module.hot) {
  module.hot.accept('./components/App', () => {
 const NextApp = require('./components/App').default;
    ReactDOM.render(
      <App/>,
      document.getElementById('root')
    );
  });
}
```

任何命令行输入或输出都以以下方式编写：

```jsx
 yarn add css-loader style-loader
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，以这种方式出现在文本中：返回到应用程序，您应该看到我们新组件的`Hello from LoginContainer`。

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：创建我们的应用结构

欢迎来到*使用 React 构建渐进式 Web 应用*！

本书将带您完成构建一个 React 应用程序，同时也作为渐进式 Web 应用程序的整个过程。我们将涵盖构建此类应用程序的“如何”，还将强调最佳实践以及如何衡量您的应用程序，以确保成功实施 PWA 功能。

渐进式 Web 应用程序有望成为 Web 应用程序的未来。它们承诺提供一系列额外功能，如推送通知和可安装性，将它们推向原生 iOS 或 Android 应用程序的领域。此外，对性能的强调（利用尖端的 Web 技术）意味着 PWAs 创建的应用程序对所有人都很快。

我们将深入讨论 PWAs 的每个方面，以及将常规 Web 应用程序转换为渐进式应用程序的过程。我们还将深入研究 React 最佳实践，使用诸如 React Router 之类的库。

要检查本章和未来章节的代码，您可以在[`github.com/scottdomes/chatastrophe/`](https://github.com/scottdomes/chatastrophe/)上查看已完成的项目。该存储库包括每个章节的分支。访问[`github.com/scottdomes/chatastrophe/tree/chapter1`](https://github.com/scottdomes/chatastrophe/tree/chapter1)查看本章的最终代码。

在这一章中，我们将开始应用的基本结构。以下是我们将涵盖的内容：

+   渐进式 Web 应用的用例

+   我们希望我们的应用程序实现的基本用户故事

+   项目结构和基本 HTML

+   安装依赖

+   开始使用 React

首先，让我们为我们应用的旅程设定场景。

# 设定场景

你的一个朋友打电话给你，兴奋地谈论他最新的创业想法（你知道的那个）。你耐心地听他的描述，但尊敬地拒绝成为其中的一部分。他很失望，但理解并承诺会随时向你更新项目的详情。你咕哝着表示同意。

几个月后，他在你的工作地点见到你，并宣布他找到了一群认真的投资者，他需要你帮助他建立他向他们承诺的软件。你再次拒绝，但在讨论报酬时，他提到了一个你无法拒绝的数字。一周后，你坐飞机去了旧金山。

在投资者面前（令你惊讶的是，他们是一个全神贯注的观众），你的朋友向你介绍了应用程序的基础知识。在充斥着流行语（“大规模互联”和“全球社区”）之间，你收集到了足够的信息，可以用一句话总结这个应用程序。

“所以，这是一个聊天室…为世界上的每个人…一次…”

你的朋友微笑着说：“是的。”

你被一百万陌生人同时在同一个应用程序中交谈的画面所困惑，但投资者们却掌声雷动。当你走向门口时，你的朋友再次宣布他们想要补偿你…提到了比之前更高的数字。你坐下来。

# 问题

“问题是，”你的朋友解释道，“这个聊天室必须是为每个人而设的。”

“全球社区，”你带着一个知情的点头说道。

“确切地说。每个人。即使他们在沙漠中的小屋里有糟糕的互联网。他们也应该被包括在内。”

“大规模互联”，你补充道。

“确切地说！所以它需要快速。轻巧。美观。动态。”

“所以每个人都会同时交谈？那不会是-”

“一个全球性的集体，是的。”

# 另一个问题

“另一个问题，”你的朋友宣布道，“是我们的用户大多会使用手机。在路上。”

“所以你想做一个 iOS 和 Android 应用？”

你的朋友挥了挥手。“不，不。没人再下载应用了。尤其是在发展中国家；那需要太多带宽。记住，全球性的集体。”

“所以是一个网页应用。”

“是的。一个网页集体。”

尽管你的直觉告诉你，这个项目很有趣。你如何设计一个网页应用程序尽可能快？如何使它在所有网络条件下工作？如何制作一个具有原生应用所有便利性的聊天应用，但是用于网页？

你叹了口气，握了握他的手。“让我们开始工作吧。”

# 开始工作

欢迎来到渐进式网页应用的世界。

在前面的情景中，你的朋友描述的问题正是**PWA**（渐进式网页应用）被设计解决的问题。

第一个问题是，许多用户将在较差的网络条件下访问你的网页。他们可能是硅谷的技术专家，在咖啡店里用 iPhone，WiFi 信号不好，或者他们可能是孟加拉国的村民在偏远地区。无论如何，如果你的网站对他们没有优化，他们就不会留下来。

您的应用程序加载速度有多快——它的性能——因此成为一个可访问性问题。PWA 通过第一次快速加载，以及之后每次更快地加载来解决这个问题。随着本书的进展，我们将更多地讨论它们是如何做到的。

其次，移动应用程序的安装过程对用户来说是一个障碍。这意味着您的用户需要更加致力于使用您的应用程序——足够多以放弃存储空间和时间，并使自己暴露于恶意和侵入性代码的可能性之中，甚至在他们有机会尝试应用程序之前！

如果我们可以在没有初始投资的情况下提供原生应用程序体验会怎样？PWA 试图弥合这一差距。同样，我们将在随后的章节中讨论它们是如何做到的，以及它们实际上有多成功。然而，这两者都是值得挑战的，并解决这两个问题将对我们的应用程序的用户体验产生巨大的影响。

# 为什么选择渐进式 Web 应用程序？

许多静态网页在性能方面做得非常出色。然而，当您只需要渲染一些 HTML、CSS 和少量 JavaScript 时，在各种网络条件下工作就不那么困难了。

当我们开始谈论 Web 应用程序——大型、复杂的、基于 JavaScript 的工作马——性能就成为一个重大挑战。我们的前端将有大量的代码。如果用户想要充分利用我们的应用程序，他们需要下载所有这些代码。我们如何确保他们不会在空白的加载屏幕前等待十秒，当 500KB 的 JavaScript 初始化时？

因此，我们大部分的性能增强将集中在解决 JavaScript 问题上。这在使用 React 时尤其如此。

# 为什么选择 React？

**React**正在迅速成为前端 Web 应用程序的首选解决方案。为什么？因为它快速、优雅，并且使管理大型应用程序变得容易。

换句话说，它使复杂性变得简单。当然，PWA 不一定要使用 React。PWA 可以是任何 Web 应用程序或网站。

React 确实有一个主要的好处——它的组件模式，其中 UI 被分割成不同的部分。正如我们将看到的，组件模式让我们将界面分解成小的代码块，以减轻之前的 JavaScript 下载问题。然而，除此之外，任何前端框架对于 PWA 来说都同样有效。

React 的优势在于它是构建前端应用程序的一种美丽而有趣的方式。这也是一种需求技能。如果你将对 React 的了解与 PWA 的经验相结合，你将成为快速发展的 Web 开发世界中未来准备的人。

# 换个名字也一样

你告诉你的朋友关于你在 PWA 和 React 上的学习，但在你结束之前，他挥了挥手打断了你。

“是的，是的。嘿，你觉得名字应该是什么？”

再一次，你被一种不安的感觉击中，觉得所有这一切都是一个错误，你永远不应该加入这个可疑的冒险，这个潜在的灾难。

“灾难性的对话”，你脱口而出。

你的朋友微笑着拍了拍你的背。“太棒了。好了，开始反应或者其他什么！”

# 用户故事

在我们开始构建应用程序之前，让我们更深入地了解我们到底想要实现什么。

我们可以从用户故事开始。用户故事是应用程序特定功能的描述，从我们用户的角度出发。

这是由*Jon Dobrowolski*建议的框架：

用户应该能够 _____。

作为用户，我希望做 ___，因为 ____。

假设我正在做 ___，我应该能够 ___ 以便 ___。

不是所有功能都需要整个框架。让我们从一些基本的例子开始：

+   用户应该能够登录和退出应用程序

相当简单。我认为我们不需要为此添加理由，因为这是一个非常基本的功能。

让我们转向更高级的东西：

+   用户应该能够在离线状态下查看他们的消息

+   作为用户，我希望能够在不需要互联网连接的情况下检查我的消息，因为我可能需要在外出时阅读它们

+   假设我在没有互联网访问的情况下启动应用程序，我应该能够查看所有过去的消息

让我们来看看应用程序的一些更基本的功能。用户应该能够实时发送和接收消息。

实时功能将是我们应用程序的关键。除非快速而流畅，否则聊天没有意义：

+   用户应该能够查看特定作者的所有消息

+   作为用户，我希望能够查看特定用户发送的所有消息列表，因为我可能需要查看他们在对话中的贡献，而不受其他消息的干扰

+   假设我点击用户的电子邮件，我应该被带到一个包含他们所有消息的个人资料视图

个人资料视图是您向客户建议管理主要聊天室不可避免的混乱的特殊功能。

让我们添加几个更多的 PWA 特定用户故事：

+   用户应该在其他用户发送消息时收到推送通知

+   作为用户，我希望能够不断更新对话的进展，因为我不想错过任何重要的内容

+   假设聊天室在我的屏幕上没有打开或可见，我应该收到另一个用户发送的每条消息的通知

并安装：

+   用户应该能够在他们的移动设备上安装应用程序

+   作为用户，我希望能够打开应用程序，而不必在浏览器中导航到 URL，因为我希望轻松访问聊天室

+   假设我是第一次注册聊天，我应该被提示在我的设备上安装应用程序

不要担心我们将如何实现这些目标；我们将及时解决这个问题。现在，让我们继续记录我们想要做的事情。

我们的客户非常重视性能，所以让我们指定一些性能特定的目标：

+   用户应该能够在不稳定的网络条件下在 5 秒内加载应用程序

+   作为用户，我希望能够尽快与应用程序交互，因为我不想被困在等待加载的过程中

+   假设我使用较差的互联网连接打开应用程序，我仍然应该在 5 秒内加载

在 5 秒内加载对于我们的应用程序来说仍然有点模糊。我们将在性能章节中更深入地重新讨论这个故事。

前面提到的用户故事涵盖了我们应用程序的基本功能。让我们谈谈这些要点所提出的具体挑战。

# 应用程序挑战

对于以下每一点，我鼓励您考虑如何在 Web 应用程序的背景下解决这些问题。希望这能让您更好地了解我们尝试通过 PWA 实现的目标以及我们面临的困难。

# 即时加载

通过渐进式 Web 应用程序，我们的目标是提供一种更接近原生应用程序（从 Apple 应用商店、Google Play 商店或其他应用商店下载的应用程序）的体验，而不是您典型的 Web 应用程序。当然，原生应用程序的一个优势是所有相关文件都是预先下载和安装的，而每次用户访问 Web 应用程序时，他们可能需要重新下载所有资产。

解决方案？当用户首次访问页面时，下载这些资产然后保存它们以备后用（也称为缓存）。然后，当用户重新打开应用程序时，我们不再通过互联网下载文件（慢），而是从用户设备中检索它们（快）。

然而，这仅适用于用户再次访问应用程序的情况。对于初始访问，我们仍然需要下载所有内容。这种情况特别危险，因为当用户首次访问 Chatastrophe 时，他们还没有意识到其价值，所以如果加载时间太长，他们很可能会离开（永远）。

我们需要确保我们的资产尽可能优化，并且在第一次访问时尽可能少地下载，以便用户留下来。

简而言之，第一次访问快速加载，随后每次访问几乎立即加载。

# 推送通知

没有通知的聊天应用是没有意义的！再次强调，我们正在尝试模拟传统上是原生应用功能的内容--直接向用户设备推送通知。

这个问题比看起来要棘手。推送通知只有在应用程序没有打开时才会收到（毕竟这就是整个目的）。因此，如果我们的网络应用程序没有打开和运行，我们怎么可能运行代码来显示通知呢？

答案是使用一个专门设计用于向注册设备发送通知的第三方服务。因此，设备不再接收通知提醒其用户，而是设备发送消息通知我们的通知服务，然后通知所有相关设备。

我们还需要一段代码，它始终处于“开启”状态，等待从第三方服务接收通知并显示它们。这个挑战最近才通过网络技术得以解决，也是 PWA 如此令人兴奋的原因之一。

现在，如果这种区别还没有“点亮”你，不要担心。我们稍后会更详细地讨论这个问题。现在，重点是推送通知将是我们的网络应用程序的一个有趣挑战。

# 离线访问

即使我们的用户没有连接到互联网，他们也应该能够查看过去的消息并在我们的应用程序中导航。

答案原来与之前关于即时加载的讨论密切相关。我们只需要缓存应用程序运行所需的所有内容，然后按需加载；当然，“简单”是关键词。

# 移动优先设计

多年来，Web 设计的一个大热词一直是响应式——从桌面缩放到移动尺寸时看起来一样好的网站。

PWA 本质上是对响应式设计的加强，将移动设计扩展到应用程序的各个方面，从外观到功能。

然而，归根结底，我们需要确保我们的应用在每种屏幕尺寸上都表现出色。它还需要在我们已经讨论过的限制条件下表现良好。我们不能过分依赖大背景图片或强烈的图形。我们需要一个简单而好看的 UI，既注重外观又注重性能。

# 渐进增强

任何 React 应用程序的性能瓶颈都在于下载和运行 JavaScript。我们整个应用程序的代码将包含在 JavaScript 文件中——直到这些文件被执行，我们的应用程序才能正常工作。这意味着我们的用户可能会被困在一个白屏上（没有任何功能），直到 JavaScript 准备就绪。

**渐进增强**是一种旨在解决这个问题的技术。本质上，它意味着用户的体验应该随着应用程序的下载而逐渐改善，取决于用户的浏览器。换句话说，随着时间的推移（和应用程序的下载量增加）以及用户软件的改进，应用程序体验会变得更好。

拥有最先进的浏览器、最快的互联网连接和完全下载的应用程序的用户将获得最佳体验，但使用过时的浏览器、不稳定的连接并刚刚登陆页面的用户也将获得优质的体验。

这意味着我们的`React.js`应用程序需要在没有任何 JavaScript 的情况下具有一些功能。这是一个有趣的挑战。

把我们的用户体验想象成一系列层次，从好到极好，随着时间的推移逐渐完善。

# 让我们开始吧

希望前面的概述让您对我们尝试实现这个应用程序的目标有了具体的想法，也让您了解了实现这些目标的障碍。虽然有很多挑战，但当我们逐步完成用户故事时，我们将逐个解决它们，直到我们拥有一个快速且功能齐全的渐进式 Web 应用程序。

通过上面提到的挑战，您可以看到一个普遍的趋势：在任何情况下都要有良好的性能和用户体验。这无疑是一个值得追求的目标，也正是为什么 PWA 技术适用于任何 Web 应用程序的原因；它们只是承诺为每个人提供更好的体验。

一旦我们开始构建我们的应用程序，我们还将看到解决这些问题仍然是一个挑战，但使用 React 是完全可以实现的。

下一步是为我们的应用程序设置一切，并使用 HTML 和 CSS 创建基本的文件夹结构。

# 我们的应用程序骨架

首先要做的事情。在我们开始构建 React 应用程序之前，让我们先使用基本的 HTML 和 CSS 进行设置-我们应用程序的骨架，我们将在其上堆叠 React 肌肉：

1.  打开您的终端并切换到您想要存储项目的任何目录。

1.  然后，我们将用`mkdir chatastrophe`创建我们的应用程序目录。让我们进入该文件夹，在其中创建另一个名为**`public`**的文件夹，在**`public`**中创建**`touch index.html`**。如果您使用 Windows，请使用**`type nul > index.html`**而不是**`touch`**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00005.jpeg)

1.  然后，在您选择的文本编辑器中打开整个`chatastrophe`文件夹。我将在本教程中使用**Sublime Text 3**。打开`index.html`文件，让我们写一些 HTML！

1.  让我们从基本的 HTML 元素开始。创建一个`<html>`标签，在其中是`<head>`和`<body>`。

1.  这不会是一个编程教程，如果没有一个 hello world，在 body 中，让我们在`<h1>`标签中放置`Hello world!`。

1.  然后，在浏览器中打开`index.html`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00006.jpeg)

本章结束时，我们的目标是显示与前面的插图完全相同的内容，但使用 React 来渲染我们的`<h1>`。

为什么我们把我们的`index.html`放在 public 文件夹里？嗯，当用户访问我们的页面时，我们的 HTML 是他们将下载的第一件事。他们将完全按照我们在这里看到的方式下载它。这与我们的 React JavaScript 形成了鲜明对比，在被提供给客户端之前，它将被转译（在下一章中会详细介绍）。我们编写的 React 代码将是私有的。我们编写的 HTML 将是公开的。

这是一个在我们进入 React 世界时会更有意义的区别，但现在，只需知道惯例是将 HTML 和静态资产放在 public 文件夹中即可。

# CSS 和资产

我们在初创公司的好朋友（现在被称为 Chatastrophe-你做了什么？）已经找了一位设计师为我们提供一些基本资产。这些包括用于我们聊天框的发送图标和应用程序的徽标。你不喜欢这种风格，但*这就是生活*。

让我们去[`github.com/scottdomes/chatastrophe-assets`](https://github.com/scottdomes/chatastrophe-assets)下载图像文件。您可以通过单击克隆或下载按钮，然后选择下载为 Zip 来下载它们。然后，将它们解压缩到`public`文件夹中，一个名为`assets`的新文件夹中（因此所有资产文件应该在`chatastrophe/public/assets`中）。

在继续之前，我们可以通过在`index.html`中测试它们来确保我们的资产看起来还不错。在`<h1>`上面，让我们放一个`img`标签，`src`设置为`/img/logo.png`，ID 设置为`test-image`：

```jsx
<img src=”assets/icon.png” id=”test-image”/>
```

它应该是这个样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00007.jpeg)

这更加美丽。

我们需要做的最后一件事是添加我们的 CSS。幸运的是，所有的 CSS 都已经神秘地为我们准备好了，省去了我们样式化应用的繁琐任务。我们所要做的就是引入`assets/app.css`。

我们可以通过链接标签将其包含在我们的`index.html`中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00008.jpeg)

我们应该立即看到页面的变化。背景应该是一个渐变，图片现在应该有一个轻微的脉动动画：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00009.jpeg)

成功了！这就是我们的主要资产。让我们继续进行一些对我们的 HTML 的改进。

# 元标签和网站图标

我们的应用将是以移动设备为先的，正如我们已经讨论过的。为了确保我们的 HTML 完全优化，让我们添加一些更多的标记。

首先，让我们在`index.html`的顶部添加一个`DOCTYPE`声明。这告诉浏览器可以期望什么样的文档。在 HTML 5（最新版本的 HTML）中，它总是这样的：

```jsx
<!DOCTYPE html>
```

接下来，我们需要为`viewport`宽度添加一个元标签。它看起来像这样：

```jsx
<meta name="viewport" content="width=device-width, initial-scale=1">
```

这是做什么的？基本上，它告诉浏览器以与其屏幕相同的宽度显示网页。因此，如果网页看起来是 960px，而我们的设备宽度是 320px，而不是缩小并显示整个页面，它会将所有内容压缩到 320px。

正如你所期望的那样，只有当你的网站是响应式的并且能够适应较小的尺寸时，这才是一个好主意。然而，由于响应性是我们的主要目标之一，让我们从一开始就这样做。在我们文档的`<head>`中添加这个标记。

还有几个标签要添加！我们网页上使用的字符集可以用几种不同的方式进行编码：**Unicode**和**ISO-8859-1**。您可以查阅这些编码以获取更多信息，但长话短说，我们使用 Unicode。让我们像这样添加它，就在前面的`<meta>`标签下面：

```jsx
<meta charset="utf-8">
```

趁热打铁，让我们添加 HTML 所在的语言。在我们现有的`<html>`标签上，添加`lang="en"`：

```jsx
<html lang="en">
```

好的，HTML 的清理工作就到此为止。我们需要的最后一件事是一个**favicon**，这是显示在浏览器标签中标题旁边的小图标。这包含在我们的资产包中，所以我们只需要将其链接起来（就在我们的`<meta>`标签下面）：

```jsx
<link rel="shortcut icon" href="assets/favicon.ico" type="image/x-icon">
```

您的浏览器标签现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00010.jpeg)

就这样，我们完成了！

接下来，我们将看看如何在我们的项目中包含 React，以及我们将需要的所有其他依赖项。

# npm 是什么？

React 应用程序主要是 JavaScript。如果您有使用 JavaScript 的经验，您就会知道浏览器完全能够解析和执行 JavaScript。

在大多数基本网站中，我们会在`<script>`标签中链接到页面所需的 JavaScript，然后浏览器会下载并运行它。

我们将在我们的 React 应用程序中做类似的事情（有相当复杂的情况；在第二章*，使用 Webpack 入门*中会详细介绍）。

然而，JavaScript 不再局限于浏览器。越来越多的应用程序也在后端使用 JavaScript，JavaScript 在自己的环境中运行。

长话短说，JavaScript 现在无处不在，这种普及的推动力是`Node.js`，一个 JavaScript 运行时库，它让您可以在浏览器环境之外运行 JavaScript。

好的，这很令人兴奋，但为什么这对我们的 React 项目很重要呢？

Node 还引入了将包的概念引入到 JavaScript 中。包本质上是您可以安装到应用程序中的第三方代码库，然后在需要的地方导入和使用它们。即使您的应用程序不是 Node 应用程序，也可以使用包。

React 就是这样一个包。之前提到的 Webpack 是另一个包。简而言之，为了构建复杂的 Web 应用程序，我们将不可避免地依赖于许多其他人的代码，因此我们需要包，我们需要**Node 的包管理器**（简称**`npm`**）来安装它们。

我们还将使用`npm`来启动我们的应用程序并执行一些基本任务，但它的主要目的是管理包。

# Node 设置

好了，说得够多了。让我们继续安装 Node，它已经捆绑了`npm`：

1.  前往[`nodejs.org`](https://nodejs.org)并下载 Node 的最新稳定版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00011.jpeg)

1.  在这里，我会选择 v6.10.3，这是大多数用户推荐的版本。

1.  安装完成后，打开终端并运行**`node -v`**以确认安装：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00012.jpeg)

1.  您还可以通过运行`npm -v`*.*来确认`npm`已经包含在内。

重申一下，Node 是一个 JavaScript 运行时，用于在浏览器之外执行 JavaScript，而`npm`是一种管理 JavaScript 代码模块的方法。在本书中，我们不会直接使用 Node，但我们会经常使用`npm`。

# npm 的黑暗面

在过去的一年里，`npm`因各种原因受到了批评。

+   它可能会很慢（尝试在较差的 Wi-Fi 连接上安装大型包）

+   它的安装过程可能会导致不同开发人员在同一项目上获得不同的结果

+   即使您之前已经下载了包，它也无法离线工作

作为对这些问题的回应，Facebook 推出了一个名为**Yarn**的包管理器。Yarn 本质上是`npm`的一个包装器，提供了相同的基本功能以及额外的好处。让我们安装它，以便可以使用它来管理我们的包！

访问[`yarnpkg.com/en/docs/install`](https://yarnpkg.com/en/docs/install)获取安装说明。对于 macOS，请注意您将需要**Homebrew**（这类似于 macOS 软件包的`npm`-软件包无处不在！），您可以在[`brew.sh/.`](https://brew.sh/)获取它。

# 项目初始化

我们需要做的下一件事是将我们的应用程序初始化为一个`npm`项目。让我们试一试，然后我们将讨论为什么需要这样做：

1.  在您的`project`文件夹中，在终端中输入`yarn init`并按回车键。

1.  它会问您一系列问题。第一个问题最重要--我们应用程序的名称。它应该只是当前文件夹的名称（`chatastrophe`）。如果不是，请输入`chatastrophe`。然后，只需按回车键跳过其余的问题，接受默认答案。如果我们打算发布自己的包，这些问题会更重要，但我们不打算，所以不用担心！

1.  如果你在完成了 yarn init 后查看项目文件夹，你会注意到它添加了一个带有我们项目名称和版本的`package.json`文件。我们的`package.json`很重要，因为它将作为我们依赖项的列表--我们将通过`yarn`安装的包。

不过，足够谈论依赖关系了，让我们安装我们的第一个！有什么比安装 React 更好的选择呢？

# 安装 React

让我们尝试通过在你的`project`文件夹中运行`yarn add react@15.6.1`来安装它。

我们正在安装 React 的特定版本（15.6.1）以确保与其他依赖项的兼容性，并确保在发布新版本时没有意外问题。

安装完成后，你应该看到 React 添加到我们的`package.json`的依赖项中。你还会看到`yarn`生成了一个`node_modules`文件夹和一个`yarn.lock`文件。

`node_modules`文件夹是我们所有包的所在地。如果你打开它，你会看到已经有几个文件夹了。我们不仅安装了 React，还安装了 React 所依赖的一切--依赖的依赖。

你可以想象，`node_modules`文件夹可能会变得相当庞大。因此，我们不会将其检入源代码控制。当新开发人员加入团队并下载项目文件时，他们可以根据`package.json`独立安装依赖项；这样可以节省时间和空间。

然而，我们需要确保他们获得与其他人相同的包和相同的版本；这就是`yarn.lock`文件的作用。

前面提到的设置确保我们已经准备好安全地使用第三方库。我们在项目中有`package.json`、`yarn.lock`和`node_modules`文件夹。在继续之前，让我们确保添加 React 成功了。

# 使用 React

让我们通过使用它来向我们的屏幕渲染一个简单的元素来确认 React 是否在我们的项目中。这将是我们第一次尝试 React，所以要慢慢来，确保你理解每一步。

首先，我们需要将我们刚刚用`yarn`安装的 React 包导入到我们的`index.html`中，以便我们可以在那里使用它。

为了做到这一点，我们在我们的`node-modules`文件夹中添加一个指向主 React 文件的`<script>`标签。这个标签看起来像这样：

```jsx
<script src="../node_modules/react/dist/react.js"></script>
```

将这个放在你的`index.html`中，放在`body`标签的底部（在闭合的`</body>`之前）。

好了，我们有了 React！让我们用它来制作一个简单的`<h1>`标签，就像我们在 HTML 中写的那样。

React 有一个名为`createElement`的函数来实现这一目的。它接受三个参数：元素类型，称为 props 的东西（稍后详细介绍），以及子元素（标记内部的内容）。

对我们来说，它看起来像这样：

```jsx
React.createElement('h1', null, 'Hello from React!')
```

这个函数调用创建了一个如下所示的元素：

```jsx
<h1>Hello from React!</h1>
```

为了确认它是否有效，让我们将其`console.log`出来：

```jsx
<script src="../node_modules/react/dist/react.js"></script>
<script>
  console.log(React.createElement('h1', null, 'Hello from react!'))
</script>
```

重新加载`index.html`，然后右键单击或按住 Control 键单击并选择 Inspect 以在 Chrome 中打开 DevTools 并切换到 Console 选项卡。在那里，我们看到我们的元素……或者没有。而不是 HTML 输出，我们得到了这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00013.jpeg)

这不是我们可能期望的 HTML 元素，但我们可以看到 React 以自己的方式工作。我们有一个 JavaScript 对象，其中有一个`h1`类型的字段。让我们看看是否可以将其转换为屏幕上的实际 HTML 标记。

# 欢迎来到 ReactDOM

关于 React 的一个秘密是，它是一个用于创建 UI 的库，但不是用于渲染 UI 的库。它本身没有渲染 UI 到浏览器的机制。

幸运的是，React 的创建者还有一个名为**ReactDOM**的包，专门用于这个目的。让我们安装它，然后看看它是如何工作的。

首先，我们使用**`yarn add react-dom@15.6.1`**来安装它。

然后，在`index.html`中以与 React 类似的方式引入它：

```jsx
<body>
  <img src="assets/icon.png" id="test-image"/>
  <h1>Hello world!</h1>
  <div id="root"></div>
  <script src="../node_modules/react/dist/react.js"></script>
 <script src="../node_modules/react-dom/dist/react-dom.js"></script>
  <script>
    console.log(React.createElement('h1', null, 'Hello from react!'));
  </script>
</body&gt;
```

ReactDOM 有一个名为`render`的函数，它接受两个参数：要渲染到屏幕上的 React 元素（嘿，我们已经有了！），以及它将被渲染在其中的 HTML 元素。

因此，我们有了第一个参数，但没有第二个。我们需要在我们现有的 HTML 中找到一些东西，可以抓取并连接到其中；ReactDOM 将在其中注入我们的 React 元素。

因此，在现有的`<h1>`标记下面，创建一个 ID 为`root`的空`div`。

然后，在我们的`ReactDOM.render`函数中，我们将传入 React 元素，然后使用`document.getElementById`来获取我们的新`div`。

我们的`index.html`应该如下所示：

```jsx
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta charset="utf-8">
    <link rel="stylesheet" href="assets/app.css">
    <link rel="shortcut icon" href="assets/favicon.ico" type="image/x-icon">
  </head>
  <body>
    <img src="assets/icon.png" id="test-image"/>
    <h1>Hello world!</h1>
    <div id="root"></div>
    <script src="../node_modules/react/dist/react.js"></script>
    <script src="../node_modules/react-dom/dist/react-dom.js"></script>
    <script>
      ReactDOM.render(React.createElement('h1', null, 'Hello from react!'), 
      document.getElementById('root'));
    </script>
  </body>
</html>
```

重新加载页面，你应该在屏幕中间看到`'Hello from React!'`的文本！

# 总结

成功！

在接下来的几章中，我们将深入（更深入）学习 ReactDOM 和 React。我们将学习如何以更直观的方式创建元素，以及 React 如何使构建 UI 成为一种梦想。

目前，我们已经准备好了项目的框架，这是我们未来应用的基础。干得好！

我们的下一步是完成准备的最后阶段，并深入研究我们最重要的依赖之一——一个名为 Webpack 的工具。


# 第二章：使用 Webpack 入门

本章主要讨论 Webpack：它是什么，如何使用它，以及为什么我们关心。然而，在我们深入研究 Webpack 之前，我有一个坦白要做。

在上一章中，我们在应用程序设置上有点作弊。我们需要添加一个文件夹结构的最后一部分--我们的 React 文件将存放的地方。

正如我们在上一章的*依赖*部分讨论的那样，React 的一个杀手功能是*用户界面的组件化*--将它们拆分成相关 HTML 和 JavaScript 的小块。例如，“保存”按钮可能是一个组件，位于表单组件内部，旁边是个人资料信息组件，依此类推。

组件结构的美妙之处在于与特定 UI 部分相关的所有内容都在一起（关注点分离），而且这些部分都在简洁易读的文件中。作为开发人员，你可以通过浏览文件夹结构轻松找到你要找的内容，而不是在一个庞大的 JavaScript 文件中滚动。

在本章中，我们将涵盖以下主题：

+   如何组织我们的 React 项目

+   设置 Webpack

+   添加一个开发服务器

+   使用 Babel 进行 JavaScript 转译入门

+   激活热重载

+   为生产环境构建

# 我们的项目结构

让我们看看实际操作中是什么样子。在我们的`chatastrophe`项目文件夹中，创建一个`src`文件夹（应该位于项目文件夹根目录中`public`和`node_modules`文件夹旁边）。

`src`文件夹是我们所有 React 文件的存放地。为了说明这将是什么样子，让我们创建一些模拟文件。

在`src`文件夹内，创建另一个名为`components`的文件夹。在该文件夹内，让我们创建三个 JavaScript 文件。你可以随意命名它们，但为了举例，我将称它们为`Component1.js`，`Component2.js`和`Component3.js`。

想象一下，每个组件文件都包含了我们用户界面的一部分。我们需要这三个文件来构建完整的用户界面。我们如何导入它们呢？

嗯，当我们需要使用 JavaScript 文件时，我们可以像迄今为止所做的那样。我们可以为我们`index.html`中的每个组件创建一个`script`标签。这是一种蛮力的方法。

然而，随着我们应用程序的增长，这种方法很快就会变得难以管理。例如，像 Facebook 这样的应用程序将拥有成千上万个组件。我们无法为成千上万个组件编写`script`标签！

理想情况下，我们只有一个`script`标签，所有的 JavaScript 都合并在一起。我们需要一个工具，将我们的各种文件压缩在一起，给我们最好的两个世界--为开发者组织、分离的代码，以及为用户压缩、优化的代码。

“但是，斯科特，”你可能会说，“如果我们把所有的代码放在一个文件中，那不是会让浏览器下载时间更长吗？有小的、分离的文件不是一件好事吗？”

你说得对。最终我们不想回到单一的单文件，但也不想有成千上万个单独的文件。我们需要一个合适的中间地带，有一些代码文件，我们会达到这个中间地带。然而，首先，让我们看看如何使用我们的新朋友--**Webpack**将多个 JavaScript 文件捆绑成一个文件。

# 欢迎来到 Webpack

我们这一节的目标是将我们在`index.html`中的脚本标签中的 JavaScript（负责渲染我们的“Hello from React!”）移到`src`文件夹中的 JavaScript 文件中，然后由 Webpack 捆绑并注入到 HTML 中。

听起来很复杂，但由于 Webpack 的魔力，它比听起来简单。让我们开始吧：

1.  首先，我们需要安装 Webpack：

```jsx
yarn add webpack@3.5.4
```

如果你检查`package.json`，你应该会看到 Webpack 列在我们的依赖项下。在本书中，我将使用**版本 3.5.4**；如果你遇到任何莫名其妙的问题，尝试使用`yarn add webpack@3.5.4`指定这个版本：

1.  现在，我们需要告诉 Webpack 该做什么。让我们先把我们的 React 代码移到`src`文件夹中。在`chatastrophe/src`中创建一个名为`index.js`的文件。

1.  然后，输入以下代码：

```jsx
console.log(‘hello from index.js!’);
```

我们的目标是让这个问候显示在我们的浏览器控制台中。

1.  好的，让我们试试 Webpack。在你的终端中，输入以下内容：

```jsx
node_modules/.bin/webpack src/index.js public/bundle.js
```

你的终端现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00014.jpeg)

这样做有什么作用？嗯，它告诉 Webpack 将第一个文件复制（以及它需要的一切，也就是说，它需要的每个文件）到第二个文件中（这是 Webpack 为我们创建的，因为它不存在）。

打开新创建的`public/bundle.js`，你会看到很多 Webpack 样板代码...在底部是我们的`console.log`。

好的，它可以工作；我们可以在我们的`index.html`中引入这个文件来看到我们的`console.log`，但这并没有充分利用 Webpack 的潜力。让我们试试其他的东西。

# 捆绑文件

让我们看看 Webpack 如何将我们的 JavaScript 文件合并在一起。按照以下步骤添加第二个 JavaScript 文件：

1.  在我们的`src`文件夹中，创建另一个文件。让我们称之为`index2.js`，因为缺乏创造力。

1.  在里面，添加第二个`console.log`：

```jsx
console.log(‘Hello from index2.js!’);
```

1.  然后，在`index.js`（第一个）中，我们将按如下方式需要另一个文件：

```jsx
require('./index2.js');
console.log('Hello from index.js!');
```

这基本上意味着`index.js`现在告诉 Webpack，“嘿，我需要另一个 index！”

1.  好的，让我们重新运行与之前相同的 Webpack 命令：

```jsx
node_modules/.bin/webpack src/index.js public/bundle.js
```

再次，我们只会指定`src/index.js`，但是如果你查看控制台输出，你会看到 Webpack 现在也获取了另一个文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00015.jpeg)

1.  打开`public/bundle.js`，滚动到底部，你会看到两个控制台日志。

这就是 Webpack 的美妙之处。我们现在可以扩展我们的应用程序以包含任意数量的 JavaScript 文件，并使用 Webpack 将它们合并为一个文件。

1.  好的，让我们确保那些控制台日志能够正常工作。在我们的`public/index.html`中，在其他三个标签下面添加另一个脚本标签：

```jsx
<script src="bundle.js"></script>
```

1.  重新加载页面，打开控制台，你会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00016.jpeg)

# 移动我们的 React

够了，现在让我们使用 Webpack 来处理一些有用的代码：

1.  删除我们的`index2.js`，并删除`index.js`中的所有代码。然后，将我们的 React 代码复制粘贴到`index.js`中，并删除`index.html`中的前三个脚本标签。

1.  这样做后，你的`index.html`中应该只有一个脚本标签（用于`bundle.js`），而你的`index.js`应该包含这一行：

```jsx
ReactDOM.render(React.createElement('h1', false, 'Hello from React!'), document.getElementById('root'))
```

1.  在运行 Webpack 之前，我们有一个问题。我们删除了需要 React 和 ReactDOM 的脚本标签，但我们仍然需要一种方法在我们的`index.js`中访问它们。

1.  我们可以以与需要`index2.js`相同的方式来做，也就是，输入`require(‘../node_modules/react/dist/react.js’)`，但那需要大量输入。此外，我们将在我们的代码中使用许多来自`node_modules`的依赖项。

1.  幸运的是，以这种方式需要模块是很常见的，所以`require`函数足够智能，可以根据名称单独获取依赖项，这意味着我们可以将其添加到我们的`index.js`的开头：

```jsx
var React = require('react');
var ReactDOM = require('react-dom');
```

然后，我们可以像以前一样在我们的代码中使用这些包！

1.  好的，让我们试一下。再次运行 Webpack：

```jsx
node_modules/.bin/webpack src/index.js public/bundle.js
```

它将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00017.jpeg)

现在，你可以在我们的`index.js`中看到 Webpack 捆绑在一起的所有文件：React，它的所有依赖项和 ReactDOM。

重新加载页面，您应该看到没有任何变化。但是，我们的应用程序现在更具可扩展性，我们可以更好地组织我们的文件。当我们添加一个依赖项时，我们不再需要添加另一个`<script>`标签；我们只需在我们使用它的代码中要求它。

# 快捷方式

打出那么长的 Webpack 命令很无聊，也可能导致错误（如果我们误输入了`bundle.js`，最终生成了错误的文件怎么办？）。让我们简化这个过程以保持我们的理智。

首先，让我们决定我们的`index.js`将是我们应用程序的入口点，这意味着它将需要应用程序中的所有其他文件（或者说，它将需要一些需要其他文件的文件，这些文件需要一些其他文件，依此类推）。

相反，我们的`bundle.js`将是我们的输出文件，其中包含我们所有捆绑的代码。

因此，这两个文件将始终是我们在终端中给 Webpack 命令的参数。由于它们不会改变，让我们配置 Webpack 始终使用它们。

在我们的项目文件夹中（不是在`src`中，而是顶层文件夹），创建一个名为`webpack.config.js`的文件。在其中，放入以下内容：

```jsx
module.exports = {
  entry:  __dirname + "/src/index.js",
  output: {
   path: __dirname + "/public",
   filename: "bundle.js",
   publicPath: "/",
  }
};
```

我们将我们的入口点定义为`index.js`的路径（`__dirname`是一个全局变量，它抓取当前目录，也就是说，无论我们在哪里运行`webpack`命令）。然后我们定义我们的输出文件。

现在，我们可以在终端中简单地运行`node_modules/.bin/webpack`，不带任何参数，得到相同的结果：

```jsx
node_modules/.bin/webpack
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00018.jpeg)

一个很好的改进，但我们是开发人员，所以我们懒惰，想要更多的快捷方式。让我们缩短`node_modules/.bin/webpack`命令。

`npm`的一个很酷的功能是能够编写脚本来执行常用任务。让我们试试。在我们的`package.json`中，创建一个脚本部分；在其中，创建一个名为`build`的脚本，值为`node_modules/.bin/webpack`命令：

```jsx
{
  "name": "chatastrophe",
  "version": "1.0.0",
  "main": "index.js",
  "license": "MIT",
 "scripts": {
 "build": "node_modules/.bin/webpack",
 },
  "dependencies": {
    "react": "15.6.1",
    "react-dom": "15.6.1",
    "webpack": "3.5.4",
  }
}
```

然后，在终端中，您可以运行`npm run build`或`yarn build`。它们做的事情是一样的：运行 Webpack 命令并捆绑我们的文件！

哇，我们的生活变得越来越容易。我们还能更懒吗？

简而言之，是的。

# 我们的开发服务器

如果我们想要更新我们的代码（比如，将我们的`h1`更改为`h2`），我们将不得不进行更改，重新运行`yarn build`，然后重新加载页面以查看我们想要看到的每一个更改。这将大大减慢我们的开发过程。

理想情况下，每当我们更改 JavaScript 时，Webpack 命令将自动重新运行，并重新加载页面。这将是多么奢侈的世界啊！

幸运的是，有一个叫做`webpack-dev-server`的包专门用于这个目的。要安装它，只需运行`yarn add webpack-dev-server`。

在我们深入之前，让我们简要介绍一下 Dev Server 是如何工作的。它在我们的机器后台运行一个小型的 Node 应用程序，提供我们公共文件夹中的文件，以便我们可以通过在浏览器中访问`localhost:3000`来查看它们。同时，它会监视`bundle.js`的源文件，当它们发生变化时重新打包，然后重新加载页面。

为了使其工作，我们需要指定要提供的文件夹（public），然后进行一些基本配置。

在我们的`webpack.config.js`中，在闭合的花括号之前添加以下内容（我们在这里有完整的代码）：

```jsx
devServer: {
  contentBase: "./public",
  historyApiFallback: true,
  inline: true,
}
```

`contentBase`会设置`public`作为要提供的文件夹，`historyApiFallback`让我们的单页应用看起来像多页应用，`inline`是自动刷新文件更改的部分：

```jsx
module.exports = {
  entry: __dirname + "/src/index.js",
  output: {
   path: __dirname + "/public",
   filename: "bundle.js",
   publicPath: "/"
  },
 devServer: {
 contentBase: "./public",
 historyApiFallback: true,
 inline: true,
 }
};
```

好的，让我们试试。首先，我们将在我们的`package.json`中添加一个名为`start`的新脚本：

```jsx
"scripts": {
  "build": "node_modules/.bin/webpack",
  "start": "node_modules/.bin/webpack-dev-server"
},
```

这将运行我们的 Dev Server（确保你首先运行了`yarn add webpack-dev-server`）。在你的终端中，输入**`yarn start`**。你会看到我们的 Webpack 编译，并且会收到一个通知，我们的应用正在端口`8080`上运行。让我们跳转到浏览器中的`http://localhost:8080`，我们应该能看到我们的应用程序。

最后的测试是将我们的`index.js`中的文本从`Hello from React`改为`Hello from Webpack!`。你的浏览器标签应该会自动重新加载并反映出更改，而无需重新运行 Webpack 命令。

# Webpack 加载器

我们即将迈入未来。

到目前为止，在这本书中，我们一直在使用旧形式的 JavaScript。这种语言最近（2015 年）进行了一次整容，增加了一些便利和新功能。这个新版本被称为**ECMAScript 2015**，简称**ES6**。它比旧版 JavaScript（ES5）更加令人愉快，但也存在问题。

所有的互联网浏览器都能够完美运行 JavaScript，但许多用户使用的是旧版本浏览器，还不能运行 ES6。因此，作为开发者，我们想要使用 ES6，但如何才能在旧版本浏览器上使我们的网站正常工作呢？

关键在于 ES6 并没有做太多 ES5 做不到的事情，它只是让编写变得更容易。

例如，以前循环遍历数组是这样做的：

```jsx
var arr = [1, 2, 3, 4];
for (var i = 0; i < arr.length; i++) {
  console.log(arr[i]);
}
```

现在，它是这样做的：

```jsx
[1, 2, 3, 4].forEach(num => console.log(num));
```

一个较旧的浏览器可以理解第一个，但不能理解第二个，但代码的功能是一样的。所以，我们只需要将第二个代码片段转换成第一个。这就是 Babel 的作用。**Babel**是 JavaScript 的转译工具；把它想象成一个翻译器。我们把我们美丽的 ES6 代码给它，它把它转换成更丑陋但更适合浏览器的 ES5 代码。

我们将把 Babel 插入到我们的 Webpack 构建过程中，这样当我们捆绑所有的 JavaScript 文件时，我们也会对它们进行转译。

要开始，我们将安装 Babel，以及一堆插件和附加组件，使其能够与 React 很好地配合。停止你的开发服务器，然后运行以下命令：

```jsx
yarn add babel-core babel-loader babel-preset-es2015 babel-preset-react babel-plugin-transform-class-properties
```

天啊，一次性安装了这么多的包！下一步中重要的是`babel-loader`。这是一个 Webpack 加载器，我们用它来获取（然后转译）我们的 JavaScript 文件，然后将它们传递给 Webpack 进行捆绑。让我们把它插入到 Webpack 中。

在我们的`webpack.config.js`中，创建一个带有加载器数组的模块对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00019.jpeg)

然后，我们可以在数组内定义我们的加载器。

我们将创建一个具有四个键的对象：test、exclude、loader 和 query：

+   **Test**是加载器用来确定它应该转译哪些文件的内容。对于 Babel，我们希望运行所有的 JavaScript 文件，所以我们的测试将是以`.js`结尾的文件：

```jsx
test: /\.js$/
```

+   **Exclude**是不需要运行的内容。我们可以跳过整个`node_modules`文件夹，因为这些包已经是 ES5 了：

```jsx
exclude: /node_modules/
```

+   **Loader**就是我们的加载器的名字：

```jsx
loader: ‘babel-loader’
```

+   最后，我们将使用**query**来定义我们的预设（Babel 将用它来转译 JavaScript）：

```jsx
query: {
  presets: ['es2015','react'],
  plugins: ['transform-class-properties']
}
```

完整的文件应该是这样的：

```jsx
module.exports = {
  entry: __dirname + "/src/index.js",
  output: {
   path: __dirname + "/public",
   filename: "bundle.js",
   publicPath: "/"
  },
  module: {
    loaders: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        loader: 'babel-loader',
        query: {
          presets: ['es2015','react'],
          plugins: ['transform-class-properties']
        }
      },
    ]
  },
  devServer: {
    contentBase: "./public",
    historyApiFallback: true,
    inline: true,
  }
};
```

运行**`yarn start`**并查找错误。如果没有错误，我们可以进行测试并编写一些 ES6 代码。

# 我们的第一个 ES6

让我们打开我们的`src/index.js`并看看我们如何让它更有趣。

首先，我们可以用新的`import`语法替换我们的`require`调用。它看起来像这样：

```jsx
import React from ‘react’;
import ReactDOM from 'react-dom';
```

这样做会更清晰一些，并且让我们可以做一些很酷的东西，我们稍后会看到。

对于 React 和 ReactDOM 都要这样做，然后我们可以最终替换我们的`React.createElement`调用。

你可能会猜到，通过调用`React.createElement`来构建复杂的 UI 会非常笨拙。我们希望拥有 JavaScript 的功能和功能，但又具有 HTML 的可读性。

输入 JSX；**JSX**是一种类似 HTML 的语法，但实际上是 JavaScript。换句话说，它编译成`React.createElement`，就像我们的 ES6 JavaScript 会编译成 ES5 一样。

它也有一些陷阱，因为它不是真正的 HTML，但我们会解决的。最后要注意的是，JSX 让一些开发人员感到非常不舒服；他们说在 JavaScript 内部放置 HTML 看起来很奇怪。我个人不同意，但这是一个观点问题。无论你的审美立场如何，JSX 提供了很多便利，所以让我们试一试。

我们可以简单地将我们的代码行转换为这样：

```jsx
ReactDOM.render(<h1>Hello from ES6!</h1>, document.getElementById('root'));
```

运行`yarn start`（或者，如果已经运行，它应该会自动刷新）。如果 Babel 工作正常，什么都不应该改变。我们的第一个 JSX 完成了！

当然，我们将更多地使用 JSX，看看它与 HTML 的区别，以及作为开发人员它为我们提供了什么优势。但是，现在让我们让我们的生活更加轻松。

# 拆分我们的应用程序

为了更好地组织我们的应用程序（并在下一节中进行一些魔术），让我们将我们的 JSX 从`ReactDOM.render`中移到一个单独的文件中。这将确保我们的文件结构具有良好的关注点分离。

在`src`文件夹的`index.js`旁边，创建一个名为`App.js`的文件。在里面，我们只需创建一个名为`App`的函数，它返回我们的 JSX：

```jsx
import React from 'react';

const App = () => {
  return <h1>Hello from React!!</h1>
};

export default App;
```

请注意底部的`export`语句；这意味着当我们导入我们的文件时，我们将自动获得此函数作为默认导入。我们将在后面看到非默认导入的示例，这将使这一点更清晰。

如果我们回到`index.js`，现在可以从`'./App'`导入`App`。然后，我们渲染它，如下所示：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import App from './App'

ReactDOM.render(<App />, document.getElementById('root'));
```

请注意，我们使用它就像 HTML（或者说 JSX）标签一样。我们将在接下来的章节中更多地讨论原因；现在，重要的是我们的应用程序更有组织性，我们的视图逻辑（JSX）与渲染逻辑（`ReactDOM.render`）分开。

# 热重载

我们已经为我们的开发过程取得了一些重大的胜利。在我们深入了解 Webpack 配置之前，我想再添加一个便利。

想象一个应用程序，它包括一个表单，当用户点击编辑按钮时，会弹出一个模态框。当你重新加载页面时，那个模态框会关闭。现在，想象一下你是开发人员，试图微调那个表单。你的开发服务器在每次微调后重新加载页面，迫使你重新打开模态框。在这种情况下，这可能有点烦人，但想象一下像浏览器游戏这样的东西，要回到之前的状态需要点击好几次。

简而言之，我们需要一种方法在保留应用程序当前状态的同时重新加载我们的 JavaScript，而不重新加载页面本身；这被称为**热重载**。我们使用 Webpack 来替换已更改的 UI 部分，而不重新加载所有内容。

为了这样做，我们将使用*Dan Abramov*的`react-hot-loader`包。让我们安装它并看看我们将如何配置 Webpack 以使其与之良好地配合。

要安装，输入`yarn add react-hot-loader@3.0.0`。在撰写本文时，版本 3 仍处于测试阶段；如果 yarn 提示您选择 3.0 的测试版本，请选择最新版本（对我来说，我选择了 beta.7）：

```jsx
yarn add react-hot-loader@3.0.0
```

为了使它工作，我们需要做四件事：

1.  启用 Webpack 自己的热模块替换插件。

1.  将 React Hot Loader 用作我们应用程序的入口点，以便 Webpack 查找源文件。

1.  将 React Hot Loader 连接到 Babel。

1.  在我们的开发服务器上启用热重载。

安装 Webpack 的`HMR`插件实际上非常容易。在我们的`webpack.config.js`中，首先在文件顶部要求 Webpack，以便我们可以访问该包：

```jsx
var webpack = require('webpack');
```

我们的 Webpack 文件不会被 Babel 处理，所以我们仍然会使用`require`而不是`import`。

然后，在我们的`devServer`键上面，添加一个名为`plugins`的新键，其值为一个数组，其中包括`new webpack.HotModuleReplacementPlugin()`作为唯一的项：

```jsx
module: {
  loaders: [
    {
      test: /\.js$/,
      exclude: /node_modules/,
      loader: 'babel-loader',
      query: {
        presets: ['es2015','react'],
        plugins: ['transform-class-properties']
      }
    },
  ]
},
plugins: [
 new webpack.HotModuleReplacementPlugin()
],
devServer: {
  contentBase: "./public",
  historyApiFallback: true,
  inline: true,
}
```

重新启动服务器以检查错误，然后继续进行第二步。

现在，我们的`index.js`是 Webpack 的入口点；它执行该文件中的代码，并从该执行中使用的文件的捆绑文件中派生。我们想要首先执行`react-hot-loader`包。让我们修改我们的入口键如下：

```jsx
entry: [
  'react-hot-loader/patch',
  __dirname + "/src/index.js"
 ],
```

为了使它与我们的开发服务器配合使用，我们需要添加一些代码：

```jsx
entry: [
   'react-hot-loader/patch',
   'webpack-dev-server/client?http://localhost:8080',
   'webpack/hot/only-dev-server',
   __dirname + "/src/index.js"
 ],
```

这个配置意味着 Webpack 会在移动到我们的代码之前执行这些路径中的代码。

再次尝试重新启动服务器。如果有错误，请检查拼写错误；否则，继续！

接下来，我们想要添加一个 Babel 插件，以便我们的热重新加载文件使用`babel-loader`进行编译。只需更新我们的 Babel 配置，如下所示，使用`react-hot-loader`中包含的 Babel 插件：

```jsx
loaders: [
  {
    test: /\.js$/,
    exclude: /node_modules/,
    loader: 'babel-loader',
    query: {
      presets: ['es2015','react'],
      plugins: ['react-hot-loader/babel', 'transform-class-properties']
    }
  },
]
```

我们还需要在我们的开发服务器中打开热重新加载；通过在我们的`devServer`配置中添加`hot: true`来实现：

```jsx
devServer: {
  contentBase: "./public",
  historyApiFallback: true,
  inline: true,
  hot: true
},
```

作为最后一步，我们需要在我们的`index.js`中添加一些代码。在文件底部添加以下内容：

```jsx
if (module.hot) {
  module.hot.accept('./App', () => {
    const NextApp = require('./App').default;
    ReactDOM.render(
     <App/>,
     document.getElementById('root')
    );
  });
}
```

上述代码基本上在文件更改时向`ReactDOM.render`发送我们应用程序的新版本。

好的，让我们试一试。重新启动服务器，然后打开`localhost:8080`。尝试编辑文本`Hello from React!`，看看 HTML 在不重新加载页面的情况下更新；很棒。

**热模块替换**将使我们的生活变得更加轻松，特别是当我们开始用不同的状态构建我们的应用程序时--重新加载页面将重置状态。

# 为生产构建

到目前为止，我们完全专注于在开发环境中使用 Webpack，但我们还需要考虑将我们的应用程序部署到生产环境中，以及可能涉及的内容。

当我们将我们的应用程序发送到全球网络时，我们不想发送任何不必要的东西（记住我们的目标是性能）；我们想要部署最少的内容。

这是我们需要的：

+   一个`index.html`页面（经过压缩）

+   一个 CSS 文件（经过压缩）

+   一个 JavaScript 文件（经过压缩）

+   所有图像资产

+   一个资产清单（上述静态文件的列表）

我们有一些这样的文件，但不是全部。让我们使用 Webpack 自动生成一个带有所有这些文件的`build`文件夹，以便稍后部署。

首先，一个经过压缩的`index.html`。我们希望 Webpack 获取我们的`public/index.html`文件，对其进行压缩，自动添加适当的脚本和 CSS 链接，然后将其添加到`build`文件夹中。

由于我们的生产环境中的 Webpack 流程将与开发环境不同，让我们制作一个`webpack.config.js`的副本，并将其命名为`webpack.config.prod.js`。在本章的大部分时间里，我们将使用`webpack.config.prod.js`，而不是`webpack.config.js`。

首先，从`webpack.config.prod.js`中删除`devServer`键。我们不会在生产中使用开发服务器，也不会使用热重新加载。我们需要删除`entry`下的两行`devServer`特定行，以及热重新加载行，使其看起来像这样：

```jsx
entry: __dirname + "/src/index.js",
```

此外，在我们的`webpack.config.prod.js`中，让我们指定我们的输出文件夹现在是`chatastrophe/build`，通过更改输出下面的这行：

```jsx
path: __dirname + "/public",
```

需要更改为这样：

```jsx
path: __dirname + "/build",
```

我们还需要添加一个`publicPath`，这样我们`build`文件夹中的`index.html`就知道在同一个文件夹中查找捆绑的 JavaScript：

```jsx
output: {
  path: __dirname + "/build",
  filename: "bundle.js",
  publicPath: './'
},
```

让我们将环境设置为生产环境，这样 React 就不会显示它的（在开发中很有帮助的）警告。我们还可以移除`HotModuleReplacementPlugin`：

```jsx
plugins: [
  new webpack.DefinePlugin({
    'process.env': {
      NODE_ENV: JSON.stringify('production')
    }
  }),
],
```

接下来，我们将使用一个新的 Webpack 插件，称为`HtmlWebpackPlugin`。它做起来就像它的名字一样--为我们打包 HTML！让我们使用`yarn add html-webpack-plugin`来安装它，然后使用以下选项添加它：

```jsx
plugins: [
  new webpack.DefinePlugin({
    'process.env': {
      NODE_ENV: JSON.stringify('production')
    }
  }),
  new HtmlWebpackPlugin({
    inject: true,
    template: __dirname + "/public/index.html",
    minify: {
      removeComments: true,
      collapseWhitespace: true,
      removeRedundantAttributes: true,
      useShortDoctype: true,
      removeEmptyAttributes: true,
      removeStyleLinkTypeAttributes: true,
      keepClosingSlash: true,
      minifyJS: true,
      minifyCSS: true,
      minifyURLs: true,
    },
  }),
],
```

不要忘记在`webpack.config.prod.js`的顶部要求它，就像我们要求 Webpack 一样：

```jsx
var HtmlWebpackPlugin = require('html-webpack-plugin');
```

是时候来测试一下了！在你的`package.json`中，更新我们的构建脚本以使用我们的新配置，如下所示：

```jsx
"build": "node_modules/.bin/webpack --config webpack.config.prod.js",
```

然后运行`yarn build`。

您应该在项目目录中看到一个`build`文件夹出现。如果您打开`build/index.html`，您会看到它被整合在一起。但是，有一个问题；在那个压缩的代码中，您应该看到两个脚本标签，都需要`bundle.js`。

这是我们之前指定的`HtmlWebpackPlugin`选项的结果。插件为我们添加了脚本标签！多么方便，除了我们已经在`public/index.html`中自己添加了它。

这里有一个简单的解决方案--让我们将我们的`HtmlWebpackPlugin`配置（和 require 语句）复制到`webpack.config.js`（我们的原始配置文件）中。但是，我们可以删除`minify`键及其所有选项，因为在开发中这是不必要的：

```jsx
// webpack.config.js
plugins: [
  new webpack.HotModuleReplacementPlugin(),
  new HtmlWebpackPlugin({
    inject: true,
    template: __dirname + '/public/index.html',
  })
],
```

然后，从`public/index.html`中删除脚本标签，然后再次尝试`yarn start`来测试我们的开发环境是否工作正常，以及`yarn build`来测试我们的生产构建。

好的，我们在我们的构建中有一个被压缩的 HTML 文件，并且我们也稍微改进了我们的开发启动过程。下一个任务是确保我们的 CSS 也被压缩并复制到我们的构建文件夹中。

在我们的 webpack 配置中（生产和开发环境都是），我们使用`babel-loader`来加载我们的 JavaScript 文件；我们将类似的方法用于 CSS。

为此，我们将结合两个加载器：`css-loader`和`style-loader`。

您可以在[`github.com/webpack-contrib/style-loader`](https://github.com/webpack-contrib/style-loader)的 style-loader GitHub 页面上阅读更多关于为什么建议同时使用两者的信息。

使用以下命令安装两者：

```jsx
 yarn add css-loader style-loader
```

让我们将它们添加到我们的`webpack.config.prod.js`和`webpack.config.js`中，通过在我们的`babel-loader`配置下添加以下代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00020.jpeg)

这些插件的作用是将我们的 React 代码所需的 CSS 文件转换为注入到我们的 HTML 中的`<style>`标签。现在，这对我们来说没有太大作用，因为我们的 CSS 目前位于我们的`public`/`assets`文件夹中。让我们将它移到`src`中，然后在`App.js`中引入它：

```jsx
import React from 'react';
import './app.css';

const App = () => {
  return <h1>Hello from React!!</h1>
};

export default App;
```

然后，我们可以从我们的`public/index.html`中删除我们的链接标签，并重新启动我们的服务器。

如果我们在浏览器中检查我们的 HTML 的头部，我们应该会看到一个包含所有 CSS 的`<style>`标签。很整洁！：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00021.jpeg)

现在，当我们刷新页面时，你可能会注意到有一些未经样式化的内容闪烁；这是因为我们的应用现在需要 React 在添加样式之前启动。我们将在接下来的章节中解决这个问题，放心。

运行`yarn build`，看一下`bundle.js`。如果你搜索"Start initial styles"，你会看到我们的 CSS 是如何捆绑在我们的 JavaScript 中的。另外，请注意我们的 JavaScript 相对于我们的 HTML 来说是相对可读的。下一步是对其进行缩小处理！

幸运的是，这样做非常容易。我们只需要在我们的`production`文件中添加另一个 Webpack 插件。在`HtmlWebpackPlugin`之后，添加以下内容：

```jsx
plugins: [
  new HtmlWebpackPlugin({
    inject: true,
    template: __dirname + '/public/index.html',
    minify: {
      removeComments: true,
      collapseWhitespace: true,
      removeRedundantAttributes: true,
      useShortDoctype: true,
      removeEmptyAttributes: true,
      removeStyleLinkTypeAttributes: true,
      keepClosingSlash: true,
      minifyJS: true,
      minifyCSS: true,
      minifyURLs: true
    }
  }),
  new webpack.optimize.UglifyJsPlugin({
    compress: {
      warnings: false,
      reduce_vars: false
    },
    output: {
      comments: false
    },
    sourceMap: true
  })
]
```

再次运行`yarn build`，你会看到我们的`bundle.js`已经变成了一行。这对人类来说不太好，但对浏览器来说更快。

好的，我们离结束越来越近了。接下来，我们要确保所有的资产文件都被复制到我们的`build`文件夹中。

我们可以通过向我们的 Webpack 配置添加另一个加载器来实现，称为`file-loader`。我们将使用`yarn add file-loader@0.11.2`来安装它。让我们看看代码是什么样子的（请注意，这仅适用于我们的`webpack.config.prod.js`文件）：

```jsx
module: {
  loaders: [
    {
      test: /\.js$/,
      exclude: /node_modules/,
      loader: 'babel-loader',
      query: {
        presets: ['es2015', 'react'],
        plugins: ['react-hot-loader/babel', 'transform-class-properties']
      }
    },
    {
      test: /\.css$/,
      use: [{ loader: 'style-loader' }, { loader: 'css-loader' }]
    },
 {
 exclude: [/\.html$/, /\.(js|jsx)$/, /\.css$/, /\.json$/],
 loader: 'file-loader',
 options: {
 name: 'static/media/[name].[ext]'
 }
 }</strong>
  ]
},
```

请注意，我们排除了 HTML、CSS、JSON 和 JS 文件。这些都已经被我们的其他加载器覆盖了，所以我们不想重复文件。

我们还将这些资产放在一个`static`文件夹中，就像我们的`public`文件夹中的`assets`文件夹一样。

然而，`file-loader`只会应用于我们的 JavaScript 代码所需的文件。我们有我们的 favicon 和图标，目前只在我们的`index.html`中使用，所以 Webpack 找不到它们。

为了做到这一点，我们将使用 JavaScript 而不是 Webpack（因为 Webpack 只关注我们的`src`文件夹）。

# 创建一个自定义脚本

在你的目录根目录下新建一个名为`scripts`的文件夹。在里面，创建一个名为`copy_assets.js`的文件。

在这里，我们将把`public`中的所有内容复制到`build`中，但不包括我们的`index.html`。

为了做到这一点（你猜对了），我们需要另一个包；运行 `yarn add fs-extra`。

然后，在 `copy_assets.js` 中引入它，如下所示：

```jsx
var fs = require('fs-extra');
```

`fs-extra` 是一个用于在 Node 环境中操作文件的包。它有一个叫做 `copySync` 的方法，我们将在这里使用它。

代码相当简单明了：

```jsx
fs.copySync('public', 'build', {
 dereference: true,
 filter: file => file !== 'public/index.html'
});
```

这意味着复制 `public` 文件夹中的所有内容到 `build` 文件夹，除了 `index.html` 文件。

如果你在之前的 Webpack 配置中的 `public` 文件夹中有一个 `bundle.js`，现在可以删除它了。

现在，要在构建时运行此命令，请将其添加到 `package.json` 中的构建脚本中：

```jsx
 "scripts": {
   "build": "node scripts/copy_assets.js && node_modules/.bin/webpack --config 
    webpack.config.prod.js",
   "start": "node_modules/.bin/webpack-dev-server"
 },
```

把 `copy_assets` 命令放在我们的 Webpack 命令之前是个好主意，这样可以确保我们不会在 `public` 中意外复制任何未经转译的 JavaScript 资源。

# 创建一个资产清单

作为最后一步，我们想要一个我们正在生成的所有静态资产的清单。一旦我们开始缓存它们以节省加载时间，这将会很有用。幸运的是，这是一个简单的步骤，另一个插件！

`yarn add webpack-manifest-plugin` 并将其添加到 `webpack.config.prod.js` 中的插件下，使用以下配置：

```jsx
var ManifestPlugin = require('webpack-manifest-plugin');
// Then, under plugins: new ManifestPlugin({
  fileName: 'asset-manifest.json',
}),
```

好的，让我们一起试试。运行 **`yarn build`**，然后在浏览器中打开 `index.html`。它应该看起来和运行 **`yarn start`** 一样。你还应该在我们的 `build` 文件夹中看到一个 `index.html`，一个 `bundle.js`，一个 `asset-manifest.json`，和一个 `assets` 文件夹。

# 总结

哇！那是很多的配置。好消息是现在我们已经完全准备好开始编写 React 并构建我们的应用程序了。这就是我们接下来要做的！

在本章中，我们涵盖了与 Webpack 相关的一切，添加了一堆方便的功能来加快我们的开发速度。在下一章中，我们将开始开发过程，并开始构建我们的 React 应用程序。这就是乐趣开始的地方！


# 第三章：我们的应用程序的登录页面

在过去的几章中，我们已经完全准备好了使用 React 进行开发。现在，让我们全力以赴地构建我们的应用程序。

在本章中，我们将在 React 中创建我们应用程序的登录页面。最后，你应该对基本的 React 语法感到舒适。

我们将涵盖以下关键的 React 概念：

+   将 UI 分成组件

+   编写 JSX

+   函数组件与类组件

+   组件状态

+   创建可重用的组件

# 什么是 React 组件？

**React 组件**，在最基本的层面上，是用户界面的一部分，更具体地说，是专门用于单一目的的 UI 部分。

在 React 中，你的 UI 被分成了各个部分，这些部分又包含在其他部分中，依此类推；你明白了吧。每个部分都是自己的组件，并且存在于单独的文件中。

这个系统的美妙之处现在可能并不明显，但一旦我们深入了解，你会发现它使我们的应用程序更易理解，也就是说，在开发过程中更容易理解和导航。我们只会构建一个包含几个组件的小应用程序。当你的应用程序增长到数百个组件时，效果会更加明显。

让我们来看一个将 UI 拆分成组件的快速示例。这是 Packt 的在线商店，也是这本书的出版商：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00022.jpeg)

如果我们要在 React 中重建这个 UI，我们将首先将 UI 分成有意义的部分。哪些部分涉及不同的目的？

请注意，这个问题并没有一个正确的答案；不同的开发人员会有不同的做法，但是以下的划分对我来说是有意义的：将其分成**FilterControl**、**SearchBar**和**ResultsGrid**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00023.jpeg)

我的想法是——**FilterControl**（在顶部）与排序和分页有关，**SearchSideBar** 是搜索特定结果的功能，**ResultsGrid** 则是显示匹配结果的功能。每个组件都有非常具体和明确的目的。

然后，在这三个组件中，我们可以进行更小的划分。**ResultsGrid** 中的每本书可以是一个**BookCard**组件，其中包含**BookInfo**和**BookImage**组件，依此类推。

我们想要将这些划分做得多细致，取决于我们自己。一般来说，更多数量的小组件更好，但是随着组件数量的增加，我们需要编写更多的样板代码。

React 组件化的另一个优势是可重用性。假设在我们的**ResultsGrid**中，我们为每个结果制作一个**BookCard**组件。然后，在 Packt 主页上，我们可以重用相同的组件！不再在两个地方重复编写相同的代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00024.jpeg)

代码的可重用性也是为什么较小的组件更好。如果您构建组件以最大化可重用性（以适应最多的上下文），您可以利用现有部分构建新功能。这增加了开发速度和便利性。我们将构建一个可重用的组件作为我们登录表单的一部分，并在应用程序扩展时在其他地方使用它。

让我们跳转到我们的`App.js`文件，看看我们构建的第一个组件：

```jsx
import React, { Component } from 'react';
import './app.css';

const App = () => {
  return <h1>Hello from React!!</h1>
};

export default App;
```

我们的`App`组件是一个返回一部分 JSX 的函数。就是这样。这是一种非常方便的思考 React 组件的方式，作为返回视图的一部分的函数。通过按照特定顺序调用某些函数，我们构建我们的 UI。

当然，情况会变得更加复杂。然而，如果你对 React 的语法和概念感到不知所措，请回到这个核心原则：React 组件只是返回 UI 的一部分的函数。

# 争议和关注点的分离

当 React 首次出现时，它非常具有争议性（对许多人来说，它仍然是）。许多开发人员关注的核心问题是 JSX，在 JavaScript 代码中间出现类似 HTML 的东西。

多年来，开发人员一直在不同的文件中编写他们的 HTML、CSS 和 JavaScript。React 违反了这一传统。一些开发人员指责该库违反了**关注点分离**（**SoC**）的编程原则-代码应该分离到各自用于一件事的文件中。从这个意义上讲，他们认为你应该有一个 HTML 文件，一个 CSS 文件和一个 JavaScript 文件-不应该混合 HTML 和 JavaScript。

React 开发人员指出的是，根据类型（HTML 与 JavaScript）分离文件是一种技术上的分离，而不是关注点的分离。HTML 和 JavaScript 都关注于呈现功能性 UI-它们是一体的。

React 提出，如果你有一个按钮，按钮的 HTML 结构和使其功能（点击时发生的事情）应该存在于同一个文件中，因为这都是同一个关注点。

因此，记住 React 的重要事情是关注点的分离——你可以根据组件的目的划定它们之间的界限。

所有这一切的缺失部分当然是 CSS。它不应该在同一个文件中吗？很多人都这么认为，但是尚未出现成熟的解决方案。你可以在[`medium.freecodecamp.org/css-in-javascript-the-future-of-component-based-styling-70b161a79a32`](https://medium.freecodecamp.org/css-in-javascript-the-future-of-component-based-styling-70b161a79a32)阅读更多关于 JS 中的 CSS。

# 类组件与函数组件

我们刚刚将 React 组件定义为返回 UI 片段的函数。这是一种有用的思考方式，对于我们的`App`组件来说当然是正确的。然而，还有另一种编写 React 组件的方式。

现在，我们的`App`组件是一个函数组件。这意味着它实际上是作为一个函数编写的，但你也可以将组件编写为 JavaScript 类。这些被称为**基于类**或**有状态**组件（我们稍后会讨论有状态部分）。

JavaScript 类是 ES6 的一个新特性。它们以一种类似（但不完全相同）的方式工作于其他语言中的类。我们不会在这里深入探讨它们，但是对于我们的目的，你可以做到以下几点：

+   让一个类扩展另一个类（并继承其属性）

+   用 new 关键字创建一个类的实例（即实例化它）

让我们通过将我们的`App`组件转换为基于类的组件来看一个例子。

每个类组件必须做两件事：它必须扩展 React 库中的`Component`类，并且它必须有一个`render`方法。

让我们从 React 中导入`Component`类开始：

```jsx
import React, { Component } from 'react';
```

对于那些对这种语法不熟悉的人来说，这是 ES6 中对象解构的一个例子。考虑以下内容：

```jsx
const property = object.property;
```

对象解构将前面的代码转换为这样，这样可以节省一些输入，但是做的事情是一样的：

```jsx
const { property } = object;
```

无论如何，既然我们已经导入了我们的`Component`类，让我们创建一个扩展它的类；删除我们的`App`函数，并编写以下内容：

```jsx
class App extends Component {

}
```

JavaScript 类的功能很像对象。它们可以有属性，这些属性可以是值或函数（称为方法）。正如我们之前所说，我们需要一个`render`方法。下面是它的样子：

```jsx
class App extends Component {
  render() {

  }
}
```

`render`方法做什么？实质上，当我们将我们的`App`作为一个函数组件编写时，它仅由一个`render`方法组成。整个东西只是一个大的`render()`。因此，`render`方法做了我们从 React 组件中期望的事情：它返回了一部分视图：

```jsx
class App extends Component {
  render() {
    return <h1>Hello from React!!</h1>;
  }
}
```

如果你启动了应用程序（或者它已经在运行），你会注意到什么都没有改变。

那么，类组件和函数组件之间有什么区别呢？

一个最佳实践是尽可能在应用程序中创建尽可能多的小型功能组件。从性能上讲，它们会快一点，而且 React 团队已经表达了对优化函数组件的兴趣。它们也更容易理解。

然而，类组件给了我们很多方便的功能。它们可以有属性，然后我们在`render`方法中使用这些属性：

```jsx
class App extends Component {
  greeting = 'Hello from React!!';

  render() {
    return <h1>{this.greeting}</h1>;
  }
}
```

我们可以从`render`方法中调用方法：

```jsx
class App extends Component {
  logGreeting = () => {
    console.log('Hello!');
  }

  render() {
    this.logGreeting()
    return <h1>Hello from React!!</h1>;
  }
}
```

正如我们之前讨论的那样，类可以被实例化（在诸如`const app = new App()`的语法中）。这就是 React 在我们的`ReactDOM.render`调用中所做的；它实例化我们的`App`，然后调用`render`方法来获取 JSX。

因此，将 React 组件视为返回视图片段的函数仍然是有用的。类组件只是在`render`函数周围添加了一些额外的功能。

# 我们的第二个组件

我们已经制作了一个 React 组件；让我们再制作一个！

正如我们之前讨论的，本章的目标是创建我们应用程序的登录页面。首先，让我们在我们的`src`文件夹中创建一个名为`components/`的文件夹，然后在里面创建一个名为`LoginContainer.js`的文件。

如果你仍然有我们第二章中的文件夹，*开始使用 Webpack*，其中包括`Component1.js`，`Component2.js`和`Component3.js`，现在可以随意删除这些文件。

我们的`LoginContainer`将是另一个类组件，原因我们将在后面看。就像我们的应用程序一样，让我们设置一个基本的类组件框架：

```jsx
import React, { Component } from 'react';

class LoginContainer extends Component {
  render() {

  }
}

export default LoginContainer;
```

让我们在深入研究之前测试一下渲染我们的组件。从我们的`render`方法中返回一个简单的`<h1>Hello from LoginContainer</h1>`；然后，让我们回到我们的`App.js`。

我对代码组织有点挑剔，所以在继续之前，让我们将我们的`App.js`移动到我们的`components`文件夹中。这也意味着我们将不得不更改`index.js`中的导入语句如下：

```jsx
import App from './components/App';
```

还有，将我们的`app.css`移到`components`文件夹中，然后在`index.js`中更改我们的热重载器配置：

```jsx
if (module.hot) {
  module.hot.accept('./components/App', () => {
 const NextApp = require('./components/App').default;
    ReactDOM.render(
      <App/>,
      document.getElementById('root')
    );
  });
}
```

现在我们所有的组件都住在同一个文件夹里，这样好多了。

在`App.js`中，我们首先导入`LoginContainer`：

```jsx
import LoginContainer from './LoginContainer';
```

然后，我们将其`render`而不是`<h1>`：

```jsx
import React, { Component } from 'react';
import LoginContainer from './LoginContainer';
import './app.css';

class App extends Component {
  render() {
    return <LoginContainer />
  }
}

export default App;
```

翻转回到应用程序，你应该看到我们新组件的 LoginContainer 的 Hello：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00025.jpeg)

正如我们在构建更多组件时将看到的那样，我们的`App`将是我们主要`Container`组件的包装器。它将是我们容器的容器。在`App.js`中，让我们为了 CSS 的目的将我们的`LoginContainer`包装在一个`div#container`中：

```jsx
class App extends Component {
  render() {
    return (
      <div id="container" className="inner-container">
        <LoginContainer />
      </div>
    );
  }
}
```

好了，回到`LoginContainer.js`，让我们写一些 JSX！

删除我们的`<h1>`标签，并用以下内容替换它：

```jsx
class LoginContainer extends Component {
  render() {
    return (
      <div id="LoginContainer" className="inner-container">

      </div>
    );
  }
}
```

这是我非常喜欢的一种模式 - 大多数 React 组件都包裹在一个带有类名的`div`中；尽管这只是一种偏好（一种你必须遵循的偏好，因为我写了 CSS！）。

注意 JSX 周围的括号！这种格式使多行 JSX 更易读。

当然，我们登录表单的本质就是一个表单。这个表单将处理登录和注册。以下是基本的 JSX：

```jsx
class LoginContainer extends Component {
   render() {
     return (
       <div id="LoginContainer" className="inner-container">
         <form>
           <p>Sign in or sign up by entering your email and password.</p>
           <input 
             type="text" 
             placeholder="Your email" />
           <input 
             type="password" 
             placeholder="Your password" />
           <button className="red light" type="submit">Login</button>
         </form>
       </div>
     )
  }
}
```

在前面的 JSX 中，你可能注意到我写了`<button>`的`className`而不是 class。记住我说过 JSX 有一些注意事项吗？这就是其中之一：因为 class 是 JavaScript 中的一个受保护的关键字，我们不能使用它，所以我们使用`className`代替。你很快就会习惯的。

注意前面 JSX 中的`ID`和`className`，否则你的 CSS 看起来就不会那么漂亮。

在我们的表单上面，我们将写一个带有我们的标志的基本标题：

```jsx
<div id="LoginContainer" className="inner-container">
  <div id="Header">
    <img src="/assets/icon.png" alt="logo" />
    <h1>Chatastrophe</h1>
  </div>
  <form>
```

现在你的应用程序应该看起来像这样（如果你还没有这样做，请从`index.html`中删除`<h1>`和`<img>`标签）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/pgs-webapp-react/img/00026.jpeg)

看起来漂亮，但它能做什么呢？

# React 中的状态

每个 React 组件都有一个叫做**state**的东西。你可以把它看作是组件在某个特定时间点的配置。

举个例子，当你点击它时变红的心形图标，就像 Twitter 的情况一样。按钮有两种状态：**未点击**和**已点击**。点击按钮会导致它的状态，从而导致它的外观发生变化。

这就是 React 的流程；用户的操作或事件会导致组件状态的改变，从而导致组件的外观改变。

前面的陈述带有大量的“嗯，并不总是……”，但这是理解状态的一个有用的起点：

```jsx
User event -> State change -> Appearance change
```

让我们给我们的`LoginContainer`添加一些`state`，然后从那里开始。

状态很容易定义；它是类的属性的对象。我们可以像这样定义它：

```jsx
class LoginContainer extends Component {
  state = { text: ‘Hello from state!’ }

   render() {
```

我们总是在组件的顶部定义`state`。

然后我们可以在`render`方法中访问我们的`state`：

```jsx
class LoginContainer extends Component {
  state = { text: ‘Hello from state!’ };

  render() {
    return (
      <div id="LoginContainer" className="inner-container">
        <div id="Header">
          <img src="/assets/icon.png" alt="logo" />
          <h1>{this.state.text}</h1>
        </div>
```

在前面的代码中，JSX 中的花括号表示我们正在插入一些 Javascript 代码。

这是我们初始化`state`的方式，但这个状态并不是很有用，因为没有改变它的机制。

我们需要做的是提供一种响应用户事件并根据它们修改状态的方法。

如果用户点击 Hello from state!时文本发生了变化会怎么样？

让我们给我们的`h1`标签添加一个`onClick`属性，如下所示：

```jsx
<h1 onClick={this.handleClick}>{this.state.text}</h1>
```

它引用了我们类上的一个叫做`handleClick`的方法，我们可以定义如下：

```jsx
class LoginContainer extends Component {
  state = { text: 'Hello from state!' };

  handleClick = () => {
    this.setState({ text: 'State changed!' });
  };

  render() {
```

在`handleClick`中，我们想要改变我们的状态。我们可以通过 React 中的一个叫做`this.setState`的函数来实现这一点，我们将新的状态对象传递给它。

试一试！当你点击 Hello from state!时，它应该立即改变为新的文本。

那么，这是如何工作的呢？`setState`的作用是将传入的对象合并到当前状态中（如果状态中有多个属性，但只传入一个属性的对象给`setState`，它将只改变该属性，而不是覆盖其他属性）。然后，它再次调用`render()`方法，我们的组件在 DOM 中更新以反映新的状态。

如果这看起来令人困惑，不用担心，我们还有几个例子要讲解，所以你会对组件状态有更多的练习。

我们的`LoginContainer`将有两个状态，一个与每个`<input>`标签配对。我们将在状态中存储用户在电子邮件和密码字段中输入的内容，以便在他们提交表单时我们可以访问它们。

“等一下，斯科特，”你可能会说，“为什么我们不直接进入 DOM，当用户提交表单时抓取每个输入的值，用 jQuery 的方式呢？”

我们当然可以这样做，但这将打破 React 的流程，具体如下：

```jsx
User edits input -> Update state -> Re-render input to reflect new value.
```

这样，我们的输入值就存储在状态中，视图与之保持同步，而不是将输入值存储为 DOM 元素的属性，并在需要时访问它。

这种方法的优势在这一点上可能并不明显，但它使我们的代码更加明确和可理解。

因此，在上述流程中，每当用户更改输入时，我们需要更新我们的状态。首先，让我们改变我们的状态初始化方式：

```jsx
state = { email: '', password: '' };
```

然后，让我们删除`handleClick`并将`handleEmailChange`和`handlePasswordChange`方法添加到我们的组件中：

```jsx
 handleEmailChange = (event) => {
   this.setState({ email: event.target.value });
 };

 handlePasswordChange = (event) => {
   this.setState({ password: event.target.value });
 };
```

上述方法接收一个事件（用户在字段中输入），从事件中获取值，然后将状态设置为该值。

再次注意，我们不必每次调用`setState`时都定义电子邮件和密码；它将合并到现有状态对象的更改，而不会覆盖其他值。

好的，现在是最后一步。让我们为我们的输入添加`onChange`属性，调用我们的 change 处理程序。另一个关键步骤是，我们的输入的`value`必须来源于状态。我们可以这样做：

```jsx
<input
  type="text"
  onChange={this.handleEmailChange}
  value={this.state.email}
  placeholder="Your email"
/>
<input
  type="password"
  onChange={this.handlePasswordChange}
  value={this.state.password}
  placeholder="Your password"
/>
```

您可以将您的`h1`重置为`<h1>Chatastrophe</h1>`。

如果一切顺利，您应该注意到您的输入功能没有任何变化（如果您的代码中有拼写错误，您将无法在其中一个字段中输入）。让我们通过为表单提交添加一个处理程序来确保它实际上是有效的：

```jsx
<form onSubmit={this.handleSubmit}>
```

和我们的方法：

```jsx
handleSubmit = (event) => {
  event.preventDefault();
  console.log(this.state);
};
```

当用户提交表单（点击按钮）时，上述方法将只为我们记录状态，并阻止表单实际提交。

尝试在两个字段中输入，然后单击提交。您应该看到一个带有`state`对象的控制台日志：

```jsx
Object { email: "email@email.com", password: "asdfas" }
```

我们做到了！我们的第一个具有状态的 React 组件。

希望你已经对 React 数据流有了一定的了解。我们的应用程序具有状态（存储在不同的组件中），它会在事件（通常是用户发起的）的响应中更新，这会导致我们应用程序的部分根据新状态重新渲染：

```jsx
Events -> State changes -> Re-render.
```

一旦你理解了这种简单的模式，就很容易追踪你的应用程序在任何时间点看起来的原因。

# 重用组件

在我们完成`LoginContainer`骨架之前，我想再做一个改变。

我们之前谈到过如何使 React 组件可重用，这样你就可以在应用程序的多个地方实现相同的代码。我们应该尽量将我们的 UI 拆分成尽可能多的小而可重用的部分，以节省时间，我在我们的`LoginContainer`中看到了一个很好的候选者。

`LoginContainer`不会是我们唯一的容器。在接下来的几章中，我们将创建具有不同内容的新页面，但我们希望它们具有相同的外观，并且我们希望 Chatastrophe 的标志和标题仍然在顶部的相同位置。

我建议我们制作一个新的`Header`组件，以备将来使用。

现在，我们将`LoginContainer`设置为类组件，因为我们需要使用状态和方法。另一方面，我们的页眉不会有任何状态或功能；它只是一个 UI 元素。最好的选择是将其设置为函数组件，因为我们可以。

类组件与函数组件的规则基本上是，尽可能将组件设置为函数组件，除非你需要状态或方法。

在我们的`src/`组件文件夹中，创建一个名为`Header.js`的新文件。然后，我们可以创建一个函数组件的框架。复制并粘贴`LoginContainer`中相关的`div#Header`，并将其添加为`return`语句：

```jsx
import React from 'react';

const Header = () => {
  return (
    <div id="Header">
      <img src="/assets/icon.png" alt="logo" />
      <h1>Chatastrophe</h1>
    </div>
  );
};

export default Header;
```

现在，回到我们的`LoginContainer`，我们想要导入我们的页眉，如下所示：

```jsx
import Header from './Header';
```

然后，我们可以用简单的`<Header />`标签替换`div#Header`：

```jsx
render() {
 return (
   <div id="LoginContainer" className="inner-container">
     <Header />
     <form onSubmit={this.handleSubmit}>
```

另一个 JSX 的陷阱是，所有的 JSX 标签都必须关闭。你不能只是使用`<Header>`。

就是这样！制作一个小型、可重用的组件就是这么简单。我们的`LoginContainer`现在看起来更整洁了，而且我们节省了一些将来的打字时间。

我们的登录表单看起来很棒，但有一个问题。当你在 Chatastrophe 总部向团队进行演示时（尽管你是唯一的开发人员，但团队不知何故膨胀到了二十人），一名实习生举手发问：“它实际上是怎么工作的？”

# 总结

我们创建了我们的第一个有状态的 React 组件，一个登录表单。我们学习了关于 React 组件的所有知识，以及创建它们的最佳实践。然后我们构建了我们的登录表单，并介绍了如何处理表单的更改，更新我们的状态。

不幸的是，只记录电子邮件和密码的登录表单并不那么有用（或安全！）。我们的下一步将是设置应用程序的后端，以便用户实际上可以创建账户并登录。
