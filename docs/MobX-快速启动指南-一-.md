# MobX 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7`](https://zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多年来，响应式编程一直吸引着程序员的想象力。自从四人组标准化了观察者设计模式以来，这个术语已经成为每个程序员标准词汇的一部分：

观察者：定义对象之间的一对多依赖关系，以便当一个对象改变状态时，所有依赖者都会被通知并自动更新。-《设计模式》，Erich Gamma，Richard Helm，Ralph Johnson，John Vlissides，1995

尽管如此，有各种各样的技术、库和框架实现了观察者模式。然而，MobX 在应用这种模式到状态管理方面是独一无二的。它有一个非常友好的语法，一个小的核心 API，使初学者很容易学习，并且可以应用在任何 JavaScript 项目中。此外，该库已被证明是可扩展的，不仅在 Mendix 首次应用该项目时，而且在著名项目中，如 Microsoft Outlook，DICE 的战地 1，Jenkins，Coinbase 等等。

这本书不仅会指导您了解基础知识；它还会让您沉浸在 MobX 的哲学中：*任何可以从应用程序状态中派生出来的东西，都应该自动派生出来。*

MobX 并不是第一个这样的库，但它站在巨人的肩膀上，推动了透明响应式编程范例的可能性边界。例如，据作者所知，它是第一个将反应性与同步事务结合起来的主要库，也是第一个明确区分派生值和自动副作用（反应）概念的库。

与许多学习材料不同，本书将指导您了解 MobX 及其许多扩展点的内部工作原理。这本书希望留下一个持久的印象，即一个基本简单（而且非常可读！）的范例可以用来完成非常具有挑战性的任务，不仅在领域复杂性方面，而且在性能方面也是如此。

# 这本书适合谁

状态管理在任何状态在代码库的不同位置相关的应用程序中起着至关重要的作用。这要么是因为有多个数据的使用者或多个数据的生产者。在实践中，这意味着 MobX 在任何具有大量数据输入或数据可视化的应用程序中都是有用的。

MobX 官方支持 React.js、Preact 和 Angular。然而，许多人将该库与 jQuery、konva.js、Next.js、Vue.js 甚至 Backbone 等库和框架结合使用。在阅读本书时，您将发现使用类似 MobX 这样的工具所需的概念在任何环境中都是通用的。

# 本书涵盖内容

第一章，“状态管理简介”，从概念上介绍了*状态管理*及其许多细微之处。它介绍了副作用模型，并为您准备了理解 MobX 所需的哲学。最后，它快速介绍了 MobX 及其一些核心构建模块。

第二章，“可观察对象、操作和反应”，深入探讨了 MobX 的核心构建模块。它向您展示了创建可观察对象的各种方法，使用操作对可观察对象进行变化，并最终使用反应来对可观察对象上发生的任何变化做出反应。这三者构成了 MobX 的核心三部曲。

第三章，“使用 MobX 构建 React 应用”，结合到目前为止所获得的知识，为 React 应用提供动力。它解决了在线商店搜索图书的使用案例。该应用首先通过识别核心可观察状态来构建，使用操作来改变状态，并使用 mobx-react 中的`observer()`实用程序来通过反应。React 组件是观察者，它们对可观察状态的变化做出反应，并自动呈现新状态。本章将让您提前体验 MobX 在 React 应用中进行状态管理的简单性。

第四章，“设计可观察状态树”，着重设计可观察状态，并介绍了 MobX 中的各种选项。我们将解决如何限制 MobX 中的可观察性，并学习如何创建一个仅观察必要内容的紧密可观察状态。除了限制可观察性，我们还将看到如何使用`extendObservable()`扩展可观察性。最后，我们将研究计算属性，并研究使用 ES2015 类来建模可观察状态。

第五章《派生、操作和反应》进一步探讨了 MobX 的核心构建块，并更详细地探索了 API。它还涉及了统治这些构建块的哲学。通过本章结束时，您将巩固对 MobX 的理解和核心直觉。

第六章《处理真实世界的用例》是我们将 MobX 应用于两个重要的真实世界用例的地方：表单处理和页面路由。这两者在本质上都是非常直观的，但我们会认为，当以可观察的状态、操作和反应的形式表示时，它们可以更容易地处理。这种表示使得 React 组件（*观察者*）成为状态的自然视觉扩展。我们还将发展我们对使用 MobX 进行状态建模的核心直觉。

第七章《特殊情况的特殊 API》是对低级别且功能强大但隐藏在顶级 API 阴影中的 API 的调查，例如`observable()`、`action()`、`computed()`和`reaction()`。我们将探索这些低级别的 API，然后简要介绍 MobX 开发人员可用的调试工具。令人欣慰的是，即使在那些罕见的奇怪情况下，MobX 也会全方位地支持您。

第八章《探索 mobx-utils 和 mobx-state-tree》为您提供了一些有用的包的味道，这些包可以简化 MobX 驱动开发中遇到的日常用例。顾名思义，mobx-utils 是一个实用工具包，其中包含各种函数。另一方面是强大的 mobx-state-tree，通常简称为 MST，它规定了一种可扩展的 MobX 应用程序方法，内置了一些模式，一旦您采用了 MST 思维方式，这些模式就会免费提供给您。这是对 MobX 的一个值得的升级，对于严肃的用户来说是必不可少的。

第九章，*MobX 内部*，在这里我们通过剥离层并窥探 MobX 的内部工作方式来达到高潮。核心抽象非常简单和明确定义，它们清晰地分离了责任。如果术语*透明函数式响应式编程*听起来像是一门黑魔法，这一章将揭开魔法，揭示 MobX 如何拥抱它。这一章也是对 MobX 代码库的入门，对于希望成为 MobX 项目核心贡献者的任何人来说都是值得一读的。

# 充分利用本书

MobX 通常用于长期存储在内存中起重要作用的编程环境，尤其是 Web、移动和桌面应用程序。本书需要对 JavaScript 编程语言有基本的了解，并且在示例中将使用现代的`ES2015`语法。前端示例基于 ReactJS 框架，因此对它的一些了解将会有所帮助，但并非必需。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载完成后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/MobX-Quick-Start-Guide`](https://github.com/PacktPublishing/MobX-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。 您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/MobXQuickStartGuide_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/MobXQuickStartGuide_ColorImages.pdf)。

# 代码演示

访问以下链接查看代码运行的视频：

[`bit.ly/2NEww85`](http://bit.ly/2NEww85)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。 例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```jsx
connect(mapStateToProps, mapDispatchToProps, mergeProps, options)(Component)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
import { observable, autorun, action } from 'mobx';

let cart = observable({
    itemCount: 0,
    modified: new Date(),
});
```

任何命令行输入或输出都以以下形式编写：

```jsx
$ mkdir css
$ cd css
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。 例如，菜单中的单词或对话框中的单词会以这种形式出现在文本中。 例如："从管理面板中选择系统信息。"

警告或重要说明会出现在这样的形式中。提示和技巧会出现在这样的形式中。


# 第一章：状态管理介绍

您的 React 应用的核心位于客户端状态（数据）中，并通过 React 组件呈现。随着您处理**用户交互**（**UI**）、执行异步操作和处理领域逻辑，管理这种状态可能变得棘手。在本章中，我们将从 UI 中的状态管理的概念模型、副作用的作用和数据流开始。

然后，我们将快速了解 MobX 并介绍其核心概念。这些概念将有助于与 Redux 进行一些比较。您会发现 MobX 实际上是 Redux 的更*声明性*形式！

本章涵盖的主题如下：

+   什么是客户端状态？

+   副作用模型

+   MobX 的快速介绍

# 客户端状态

您在屏幕上看到并可以操作的 UI 是将数据的视觉表示呈现出来的结果。数据的形状暗示了您提供用于可视化和操作这些数据的控件的类型。例如，如果您有一个项目列表，您可能会显示一个具有`ListItems`数组的`List`控件。操作可能包括*搜索、分页、过滤*、*排序*或*分组*列表中的项目。这些操作的状态也被捕获为数据，并通知了视觉表示。

以下图表显示了*数组*与*List*控件之间的直接关系：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00005.jpeg)

简而言之，描述 UI 的关键角色是*数据*。处理结构和管理可能发生在这些数据上的变化通常被称为**状态管理**。状态只是在 UI 上呈现的客户端数据的同义词。

状态管理是定义数据形状和用于操作数据的操作的行为。在 UI 的上下文中，它被称为*客户端*状态管理。

随着 UI 的复杂性增加，客户端上积累了更多的状态。它达到了一个点，状态成为我们在屏幕上看到的一切的最终真相。在 UI 开发中，我们提升了客户端状态的重要性，这是前端世界中最大的转变之一。有一个有趣的方程式捕捉了 UI 和状态之间的关系：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00006.jpeg)

`fn` 是一个应用在状态（数据）上的转换函数，它产生相应的 UI。事实上，这里隐藏的微妙含义是，给定相同的状态，`fn` 总是产生相同的 UI。

在 React 的上下文中，前述等式可以写成如下形式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00007.jpeg)

唯一的区别在于 `fn` 接受两个输入，`props` 和 `state`，这是 React 组件的约定契约。

# 处理状态变化

然而，前述等式只是 UI 故事的一半。的确，视觉表示是从状态（通过转换函数 `fn`）派生出来的，但它并没有考虑到在 UI 上发生的 *用户操作*。就好像我们在等式中完全忽略了 *用户*。毕竟，界面不仅用于视觉表示数据（状态），还允许对数据进行操作。

这就是我们需要介绍代表这些用户操作的 **actions** 的概念，这些操作会导致状态的改变。Actions 是您根据触发的各种输入事件而调用的命令。这些 actions 导致状态的改变，然后反映在 UI 上。

我们可以在下图中可视化 **State**、**UI** 和 **Actions** 的三元组：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00008.jpeg)

值得注意的是，UI 不会直接改变状态，而是通过 *消息传递* 系统来触发 *actions* 来实现状态的改变。*Action* 封装了触发适当状态改变所需的参数。UI 负责捕获各种用户事件（点击、键盘按键、触摸、语音等），并将其 *转换* 为一个或多个 actions，然后触发这些 actions 来改变状态。

当 **State** 改变时，它会通知所有观察者（订阅者）状态的改变。UI 也是其中一个最重要的订阅者，会收到通知。当发生这种情况时，UI 会重新渲染并更新到新的状态。从 **State** 流向 **UI** 的数据流始终是单向的，已成为现代 UI 开发中状态管理的基石。

这种方法的最大好处之一是很容易理解 UI 如何与变化的数据保持同步。它还清晰地分离了*渲染*和*数据变化*之间的责任。React 框架确实拥抱了这种单向数据流，并且你也会看到这种方法在**MobX**中得到了采纳和扩展。

# 副作用模型

现在我们了解了 UI、状态和操作的角色，我们可以将其扩展到构建 UI 操作的思维模型。回顾`操作` --> `状态` --> `UI`的三元组，我们可以做一些有趣的观察，这些观察并不明确。让我们思考一下如何处理以下操作：

+   从服务器下载数据

+   将数据持久化到服务器

+   运行定时器并定期执行某些操作

+   当某个状态发生变化时执行一些验证逻辑

这些事情并不完全适合我们的数据流三元组。显然，我们在这里缺少了一些东西，对吧？你可能会争辩说，你可以将这些操作放在 UI 本身内部，并在特定时间触发操作。然而，这将给 UI 增加额外的责任，使其操作复杂化，并且也使其难以测试。从更学术的角度来看，这也会违反**单一责任原则**（**SRP**）。SRP 规定一个类或模块应该只有一个变化的原因。如果我们开始在 UI 中处理额外的操作，它将有多个变化的原因。

因此，看起来我们在这里有一些相互对立的力量。我们希望保持数据流三元组的纯度，处理诸如前面列表中提到的辅助操作，并且不向 UI 添加额外的责任。为了平衡所有这些力量，我们需要将辅助操作视为数据流三元组之外的东西。我们称这些为**副作用**。

副作用是某种状态变化的结果，并且是通过响应来自状态的通知来调用的。就像 UI 一样，有一个处理程序，我们可以称之为*副作用处理程序*，它观察（订阅）状态变化通知。当发生匹配的状态变化时，相应的副作用被调用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00009.jpeg)

系统中可能有许多副作用处理程序，每个处理程序都是状态的观察者。当它们观察的状态的一部分发生变化时，它们将调用相应的副作用。现在，这些副作用也可以通过触发额外的动作来导致状态的改变。

举例来说，你可以从 UI 触发一个动作来下载一些数据。这会导致某个标志的状态改变，从而通知所有观察者。观察标志的副作用处理程序会看到这种改变，并触发网络调用来下载数据。当下载完成时，它会触发一个动作来使用新数据更新状态。

*副作用*也可以触发动作来更新状态，这是一个重要的细节，有助于完成管理状态的循环。因此，不仅 UI 可以引起状态改变，而且外部操作（通过副作用）也可以影响状态改变。这就是*副作用*的心智模型，它可以用来开发 UI 并管理其呈现的状态。这个模型非常强大，随着时间的推移，它的扩展性也非常好。在本章以及整本书中，您将看到 MobX 如何使这个*副作用*模型成为现实并且使用起来很有趣。

有了这些概念，我们现在准备进入 MobX 的世界。

# MobX 的快速介绍

MobX 是一个反应式状态管理库，它使得采用副作用模型变得容易。MobX 中的许多概念直接反映了我们之前遇到的术语。让我们快速浏览一下这些构建块。

# 一个 observable 状态

状态是 UI 中发生的所有事情的中心。MobX 提供了一个核心构建块，称为**observable**，它代表了应用程序的反应式状态。任何 JavaScript 对象都可以用来创建一个 observable。我们可以使用名副其实的`observable()` API，如下所示：

```jsx
import {observable} from 'mobx';

let cart = observable({
    itemCount: 0,
    modified: new Date()
});
```

在前面的例子中，我们创建了一个简单的`cart`对象，它也是一个`observable`。`observable()` API 来自于***mobx*** NPM 包。通过这个简单的`observable`声明，我们现在有了一个反应灵敏的`cart`，它可以跟踪其任何属性的变化：`itemCount`和`modified`。

# 观察状态变化

仅仅使用可观察对象并不能构建一个有趣的系统。我们还需要它们的对应物，**观察者**。MobX 为您提供了三种不同类型的观察者，每一种都专为您在应用程序中遇到的用例量身定制。核心观察者是`autorun`，`reaction`和`when`。我们将在下一章更详细地介绍它们，但现在让我们先介绍`autorun`。

`autorun` API 接受一个函数作为输入并立即执行它。它还跟踪传入函数中使用的可观察对象。当这些被跟踪的可观察对象发生变化时，函数会被重新执行。这个简单的设置真正美丽和优雅的地方在于，不需要额外的工作来跟踪可观察对象并订阅任何变化。这一切都是自动发生的。这并不是魔术，但绝对是一个智能的系统在运作，我们将在后面的章节中介绍。

```jsx
import {observable, autorun} from 'mobx';

let cart = observable({
    itemCount: 0,
    modified: new Date()
});

autorun(() => {
    console.log(`The Cart contains ${cart.itemCount} item(s).`);
});

cart.itemCount++;

// Console output:
The Cart contains 0 item(s).
The Cart contains 1 item(s).
```

在前面的例子中，传递给`autorun`的`arrow-function`在第一次执行时，也在`itemCount`增加时执行。这导致打印了两个控制台日志。`autorun`使传入的函数（*tracking-function*）成为其引用的*observables*的*observer*。在我们的例子中，`cart.itemCount`被观察到，当它增加时，*tracking*函数会自动收到通知，导致打印控制台日志。

# 是时候采取行动了

尽管我们直接改变了`cart.itemCount`，但这绝对不是推荐的方法。记住，状态不应该直接改变，而应该通过*actions*来完成。使用*action*还为可观察状态的操作增加了词汇。

在我们的例子中，我们可以将我们正在进行的状态变化称为`incrementCount`操作。让我们使用 MobX 的`action` API 来封装这个变化：

```jsx
import { observable, autorun, action } from 'mobx';

let cart = observable({
    itemCount: 0,
    modified: new Date(),
});

autorun(() => {
    console.log(`The Cart contains ${cart.itemCount} item(s).`);
});

const incrementCount = action(() => {
 cart.itemCount++;
});

incrementCount();

```

`action` API 接受一个函数作为参数，每当调用该操作时都会调用该函数。当我们可以将变异包装在普通函数中并调用普通函数而不是将函数传递给*action*时，可能会显得多余。这是一个敏锐的想法。好吧，这样做是有充分理由的。在内部，`action`做的远不止是简单的包装。它确保所有状态变化的通知都被触发，但只在`action`函数完成后才触发。

当您在动作中修改大量的可观察对象时，您不希望立即收到每一个小改变的通知。相反，您希望能够等待所有改变完成，然后触发通知。这使系统更加高效，也减少了过多通知的噪音。

回到我们的例子，我们可以看到将其包装在一个动作中也提高了代码的可读性。通过给动作（`incrementCount`）一个具体的名称，我们为我们的领域增加了词汇。这样做，我们可以抽象出实际*增加计数*所需的细节。

可观察对象、观察者和动作是 MobX 的核心。有了这些基本概念，我们可以构建一些最强大和复杂的 React 应用程序。

在 MobX 的文献中，*副作用*也被称为*反应*。与*导致*状态改变的*动作*不同，*反应*是对状态改变做出响应的。

请注意与之前看到的单向数据流的惊人相似之处。**可观察对象**捕获应用程序的状态。**观察者**（也称为*反应*）包括*副作用*处理程序以及 UI。**动作**是，嗯，导致可观察状态改变的动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00010.jpeg)

# 与 Redux 的比较

如果我们谈论 React 中的状态管理，却没有提到 Redux，那就是完全的疏忽。Redux 是一个非常流行的状态管理库，它之所以流行，是因为它简化了 Facebook 提出的原始 Flux 架构。它摒弃了 Flux 中的某些角色，比如*调度器*，这导致将所有存储器合并为一个，通常称为**单一状态树**。

在这一部分，我们将与另一个称为**Redux**的状态管理库进行正面比较。如果您以前没有使用过 Redux，可以跳过这一部分，继续阅读本章的总结。

就数据流而言，MobX 在概念上与 Redux 有一些相似之处，但这也是相似之处的尽头。MobX 采用的机制与 Redux 采用的机制截然不同。在我们深入比较之前，让我们简要了解一下 Redux。

# 在简言之中的 Redux

我们之前看到的数据流三角也适用于整个 Redux。Redux 在*状态更新*机制中添加了自己的特色。可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00011.jpeg)

当 UI 触发动作时，它会在存储上分派。在存储内部，动作首先经过一个或多个**中间件**，在那里可以对其进行操作并在不进一步传播的情况下被吞噬。如果动作通过中间件，它将被发送到一个或多个**reducers**，在那里可以被处理以产生存储的新状态。

存储的新状态通知给所有订阅者，其中**UI**是其中之一。如果状态与 UI 之前的值不同，UI 将被重新渲染，并与新状态同步。

这里有几件值得强调的事情：

+   从动作进入存储的那一刻起，直到计算出新状态，整个过程都是同步的。

+   Reducers 是纯函数，接受动作和先前状态，并产生新状态。由于它们是纯函数，您不能在 reducer 中放置*副作用*，例如网络调用。

+   中间件是唯一可以执行副作用的地方，最终导致动作在存储上分派。

如果您正在使用 Redux 与 React，这是最有可能的组合，有一个名为`react-redux`的实用库，它可以将存储与 React 组件粘合在一起。它通过一个名为`connect()`的函数来实现这一点，该函数将存储与传入的 React 组件绑定。在`connect()`内部，React 组件订阅存储以接收状态更改通知。通过`connect()`绑定到存储意味着每个状态更改都会通知到每个组件。这需要添加额外的抽象，例如*state-selector*（使用`mapStateToProps`）或实现`shouldComponentUpdate()`来仅接收相关的状态更新：

```jsx
connect(mapStateToProps, mapDispatchToProps, mergeProps, options)(Component)
```

我们故意跳过了一些其他细节，这些细节对于完整的 React-Redux 设置是必需的，但基本要素已经就位，可以更深入地比较 Redux 和 MobX。

# MobX 与 Redux

原则上，MobX 和 Redux 实现了提供单向数据流的相同目标。*store*是管理所有状态更改并通知 UI 和其他观察者状态更改的中心角色。MobX 和 Redux 之间实现这一目标的机制是完全不同的。

Redux 依赖于*immutable*状态快照和两个状态快照之间的引用比较来检查更改。相比之下，MobX 依赖于*mutable*状态，并使用细粒度的通知系统来跟踪状态更改。这种方法上的根本差异对使用每个框架的**开发者体验**（**DX**）有影响。我们将使用构建单个功能的 DX 来执行 MobX 与 Redux 的比较。

让我们先从 Redux 开始。在使用 Redux 时，您需要做的事情如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00012.jpeg)

+   定义将封装在存储中的状态树的形状。这通常被称为`initialState`。

+   识别可以执行以更改此状态树的所有操作。每个操作以`{ type: string, payload: any }`的形式定义。`type`属性用于标识操作，`payload`是随操作一起携带的附加数据。操作类型通常作为`string`常量创建并从模块导出。

+   每次需要分派它们时定义原始操作变得非常冗长。相反，惯例是有一个包装操作类型细节并将有效负载作为参数传入的`action-creator`函数。

+   使用`connect`方法将 React 组件与存储连接起来。由于每个状态更改都会通知到每个组件，因此您必须小心，不要不必要地重新渲染组件。只有当组件实际呈现的状态部分发生变化时（通过`mapStateToProps`），渲染才应该发生。由于每个状态更改都会通知到所有*连接的组件*，因此每次计算`mapStateToProps`可能会很昂贵。为了最小化这些计算，建议使用诸如*reselect*之类的状态选择器库。这增加了正确设置高性能 React 组件所需的工作量。如果您不使用这些库，您必须承担编写高效的`shouldComponentUpdate`钩子的责任。

+   在每个 reducer 中，您必须确保在发生更改时始终返回状态的新实例。请注意，通常将 reducers 与`initialState`定义分开，并且需要来回确保在每个 reducer 操作中正确更改状态。

+   您想执行的任何副作用都必须包装在中间件中。对于涉及异步操作的更复杂的副作用，最好依赖于专用中间件库，如`redux-thunk`，`redux-saga`或`redux-observables`。请注意，这也使副作用的构建和执行变得更加复杂。先前提到的每个中间件都有自己的约定和术语。此外，分派动作的位置与处理实际副作用的位置不是共同位置。这导致需要在文件之间跳转，以构建功能如何组合的思维模型。

+   随着功能的复杂性增加，`actions`，`action-creators`，`middlewares`，`reducers`和`initialState`之间的碎片化也越来越多。不共同位置也增加了开发清晰的功能组合思维模型所需的工作量。

在 MobX 世界中，开发者体验是完全不同的。随着我们在本书中探索 MobX，您将看到更多，但这是顶层信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00013.jpeg)

+   在存储类中为功能定义可观察状态。可以更改并应该被观察的各种属性都标有`observable` API。

+   定义需要改变可观察状态的`actions`。

+   在同一功能类中定义所有的副作用（`autorun`，`reaction`和`when`）。动作、反应和可观察状态的共同位置使思维模型清晰。MobX 还原生支持异步状态更新，因此不需要额外的中间件库来管理它。

+   使用包含`observer` API 的`mobx-react`包，允许 React 组件连接到可观察存储。您可以在 React 组件树中随处添加*observer*组件，这实际上是调整组件更新的推荐方法。

+   使用*observer*的优势在于不需要额外的工作来使组件高效。在内部，*observer* API 确保组件仅在呈现的可观察状态发生变化时才会更新。

MobX 将您的思维转向可观察状态和相应的 React 组件。您不必过多关注实现这一点所需的连接。它被简单而优雅的 API 所抽象，如`observable`，`action`，`autorun`和`observer`。

我们甚至可以说，MobX 实现了一种更具声明性的 Redux 形式。没有动作创建者、减速器或中间件来处理动作并产生新状态。动作、副作用（反应）和可观察状态都位于类或模块内。没有复杂的`connect()`方法将 React 组件粘合到存储中。一个简单的`observer()`就能完成工作，不需要额外的连接。

MobX 是声明性的 Redux。它接管了与 Redux 相关的工作流程，并大大简化了它。不再需要一些显式的设置，比如在容器组件中使用`connect()`，为记忆化状态选择使用 reselect，动作、减速器，当然还有中间件。

# 摘要

UI 是数据（状态）的视觉等价物，以及交互控件来改变该状态。UI 触发动作，导致状态的改变。*副作用*是由于某种状态改变而触发的外部操作。系统中有*观察者*，它们寻找特定的状态改变并执行相应的副作用。

*动作* --> *状态* --> *UI*的数据流三元组，加上副作用，构成了 UI 的简单心智模型。MobX 强烈遵循这个心智模型，你可以在它的 API 中看到这一点，包括*可观察对象*、*动作*、*反应*和*观察者*。这个 API 的简单性使得它很容易处理 UI 中的一些复杂交互。

如果你以前使用过 Redux，你会发现 MobX 减少了引起状态改变和处理副作用所需的仪式。MobX 努力提供一种声明性和反应性的状态管理 API，而不会牺牲简单性。在本书中，将探讨 MobX 的这种哲学，深入了解其 API 和实际用例。

在下一章中，我们将深入了解 MobX 的核心构建模块。


# 第二章：Observables、Actions 和 Reactions

描述客户端状态的结构是 UI 开发的第一步。使用 MobX，您可以通过创建**observables**树来实现这一点。当用户与应用程序交互时，在 observable 状态上调用操作，这将引起反应（也称为副作用）。继续阅读第一章，*状态管理简介*，我们现在将更深入地了解 MobX 的核心概念。

本章涵盖的主题包括：

+   创建各种类型的 observables

+   设置改变 observable 的操作

+   使用反应来处理外部变化

# 技术要求

您将需要使用 JavaScript 编程语言。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter02`](https://github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter02)

查看以下视频以查看代码的运行情况：

[`bit.ly/2NEww85`](http://bit.ly/2NEww85)

# Observables

数据是 UI 的命脉。回到定义数据和 UI 之间关系的方程式，我们知道以下是真的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00014.jpeg)

因此，专注于*定义将驱动 UI 的数据结构*是有意义的。在 MobX 中，我们使用 observable 来做到这一点。看一下这个图表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00015.jpeg)

*Observables*，顾名思义，是可以被观察的实体。它们跟踪其值发生的变化并通知所有*观察者*。当您开始设计客户端状态的结构时，这种看似简单的行为具有强大的影响。在前面的图表中，每个圆代表一个**Observable**，每个菱形代表一个**Observer**。观察者可以观察一个或多个 observable，并在它们中任何一个值发生变化时得到通知。

# 创建 observables

创建 observable 的最简单方法是使用`observable()`函数。看一下以下内容：

```jsx
const item = observable({
    name: 'Party Balloons',
    itemId: '1234',
    quantity: 2,
    price: 10,
    coupon: {
        code: 'BIGPARTY',
        discountPercent: 50
  }
});
```

`item`现在是一个`observable`对象，并将开始跟踪其属性的变化。您可以将此对象用作常规 JavaScript 对象，而无需任何特殊的 API 来*获取*或*设置*其值。在前面的片段中，您还可以使用`observable.object()`创建一个 observable `item`。

在下面的片段中，我们可以看到对可观察对象进行的简单变化，就像任何常规的 JavaScript 代码一样：

```jsx
// Set values
item.quantity += 3;
item.name = 'Small Balloons';

// Get values
console.log(`Buying ${item.quantity} of ${item.name}`);
```

可观察对象只会跟踪在`observable()`或`observable.object()`中提供的初始值中提供的属性。这意味着如果以后添加新属性，它们不会自动变为可观察的。这是关于可观察对象需要记住的一个重要特性。它们就像具有固定属性集的记录或类。如果你确实需要动态跟踪属性，你应该考虑使用*可观察映射*；这将在本章后面进一步介绍。

在内部，MobX 会透明地跟踪属性的变化并通知相应的观察者。我们将在后面的章节中探讨这种内部行为。

`observable()`函数会自动将*对象*、*数组*或*映射*转换为可观察实体。这种自动转换*不适用*于其他类型的数据，比如 JavaScript 原始类型（数字、字符串、布尔值、null、undefined）、函数，或者类实例（带有原型的对象）。因此，如果你调用`observable(20)`，它将会失败并显示错误，如下所示：

```jsx
Error: [mobx] The provided value could not be converted into an observable. If you want just create an observable reference to the object use 'observable.box(value)'
```

如错误中所建议的，我们必须使用更专门的`observable.box()`将原始值转换为可观察值。包装*原始值*、*函数*或*类实例*的可观察值被称为**包装的可观察值**。看一下这个：

```jsx
const count = observable.box(20);

// Get the count console.log(`Count is ${count.get()}`);

// Change count count.set(22);
```

我们必须使用包装的可观察对象的`get()`和`set()`方法，而不是直接读取或分配给它。这些方法给了我们 MobX 固有的可观察性。

除了对象和单一值，你还可以将数组和映射转换为可观察对象。它们有相应的 API，可以在这个表格中看到：

| 对象 | `observable.object({ })` |
| --- | --- |
| 数组 | `observable.array([ ])` |
| 映射 | `observable.map(value)` |
| 原始值、函数、类实例 | `observable.box(value)` |

正如我们之前提到的，`observable()`会自动将对象、数组或映射转换为可观察对象。它是`observable.object()`、`observable.array()`或`observable.map()`的简写。对于原始值、函数和类实例，你应该使用`observable.box()`API。尽管在实践中，使用`observable.box()`相当罕见。更常见的是使用`observable.object()`、`observable.array()`或`observable.map()`。

MobX 在创建 observable 时应用*深度可观察性*。这意味着 MobX 将自动观察对象树、数组或映射中的每个级别的每个属性。它还会跟踪数组和映射的添加或删除。这种行为对大多数情况都很有效，但在某些情况下可能过于严格。有一些特殊的装饰器可以应用于控制这种可观察性。我们将在第四章中进行探讨，*构建可观察树*。

# Observable arrays

使用`observable.array()`与使用`observable()`非常相似。您可以将数组作为初始值传递，或者从空数组开始。在以下代码示例中，我们从一个空数组开始：

```jsx
const items = observable.array(); // Start with empty array

console.log(items.length); // Prints: 0
 items.push({
    name: 'hats', quantity: 40,
});

// Add one in the front items.unshift({ name: 'Ribbons', quantity: 2 });

// Add at the back items.push({ name: 'balloons', quantity: 1 });

console.log(items.length); // Prints: 3
```

请注意，observable 数组*不是*真正的 JavaScript 数组，尽管它具有与 JS 数组相同的 API。当您将此数组传递给其他库或 API 时，可以通过调用`toJS()`将其转换为 JS 数组，如下所示：

```jsx
import { observable, **toJS** } from 'mobx';

const items = observable.array();

/* Add/remove items*/  const plainArray = toJS(items);
console.log(plainArray);
```

MobX 将对 observable 数组应用*深度可观察性*，这意味着它将跟踪数组中项目的添加和删除，还将跟踪数组中每个项目发生的属性更改。

# Observable maps

您可以使用`observable.map()` API 创建一个 observable map。原则上，它的工作方式与`observable.array()`和`observable.object()`相同，但它适用于 ES6 Maps。observable map 实例与常规的 ES6 Map 共享相同的 API。Observable maps 非常适合跟踪键和值的动态变化。这与 observable objects 形成鲜明对比，后者不会跟踪在创建后添加的属性。

在以下代码示例中，我们正在创建一个动态的 Twitter 句柄到名称的字典。这非常适合使用 observable map，因为我们在创建后*添加*键。看一下这段代码：

```jsx
import { observable } from 'mobx';

// Create an Observable Map const twitterUserMap = observable.map();

console.log(twitterUserMap.size); // Prints: 0   // Add keys twitterUserMap.set('pavanpodila', 'Pavan Podila');
twitterUserMap.set('mweststrate', 'Michel Weststrate');

console.log(twitterUserMap.get('pavanpodila')); // Prints: Pavan Podila console.log(twitterUserMap.has('mweststrate')); // Prints: Michel Weststrate   twitterUserMap.forEach((value, key) => console.log(`${key}: ${value}`));

// Prints: // pavanpodila: Pavan Podila // mweststrate: Michel Weststrate 
```

# 关于可观察性的说明

当您使用`observable()` API 时，MobX 将对 observable 实例应用*深度可观察性*。这意味着它将跟踪发生在 observable 对象、数组或映射上的更改，并且会对每个级别的每个属性进行跟踪。在数组和映射的情况下，它还将跟踪条目的添加和删除。数组或映射中的任何新条目也将成为深度可观察的。这绝对是一个很好的合理默认值，并且适用于大多数情况。但是，在某些情况下，您可能不希望使用这个默认值。

你可以在创建可观察性时改变这种行为。你可以使用兄弟 API（`observable.object()`，`observable.array()`，`observable.map()`）来创建可观察性，而不是使用`observable()`。每个 API 都接受一个额外的参数来设置可观察实例的选项。看一下这个：

```jsx
observable.object(value, decorators, { deep: false });
observable.map(values, { deep: false });
observable.array(values, { deep: false });
```

通过将`{ deep: false }`作为选项传递进去，你可以有效地*修剪*可观察性，只到第一级。这意味着以下内容：

对于可观察对象，MobX 只观察初始属性集。如果属性的值是对象、数组或映射，它不会进行进一步的观察。

请注意，`{ deep: false }`选项是`observable.object()`的第三个参数。第二个参数称为**装饰器**，可以更精细地控制可观察性。我们将在后面的章节中进行介绍。现在，你可以将一个空对象作为第二个参数传递。

对于可观察数组，MobX 只观察数组中项目的添加和移除。如果一个项目是对象、数组或映射，它不会进行进一步的观察。

对于可观察映射，MobX 只观察映射中项目的添加和移除。如果键的值是对象、数组或映射，它不会进行进一步的观察。

现在值得一提的是，`observable()`在内部调用前面的 API 之一，并将选项设置为`{ deep: true }`。这就是`observable()`具有深层可观察性的原因。

# 计算可观察性

到目前为止，我们所见过的可观察性与客户端状态的形状直接对应。如果你要表示一个项目列表，你会在客户端状态中使用一个可观察数组。同样，列表中的每个项目可以是一个可观察对象或可观察映射。故事并不止于此。MobX 还给你另一种可观察性，称为**计算属性**或**计算可观察性**。

计算属性不是客户端状态固有的可观察性。相反，它是一个*从其他可观察性派生其值*的可观察性。现在，*为什么会有用*？你可能会问。让我们举个例子来看看好处。

考虑跟踪项目列表的`cart`可观察性。看一下这个：

```jsx
import { observable } from 'mobx';

const cart = observable.object({
    items: [],
    modified: new Date(),
});
```

假设你想要一个描述`cart`的`description`属性，格式如下：购物车中有{no, one, n}个项目。

对于零个项目，描述如下：购物车中没有项目。

当只有一个项目时，描述变为：*购物车中有一个项目*。

对于两个或更多个项目*(n)*，描述应该是：*购物车中有* *n* *个项目*。

让我们思考一下如何对这个属性进行建模。考虑以下内容：

+   显然，`description`不是购物车的固有属性。它的值取决于`items.length`。

+   我们可以添加一个名为`description`的可观察属性，但是我们必须在`items`或`items.length`发生变化时更新它。这是额外的工作，容易忘记。而且，我们有可能会有人从外部修改描述。

+   描述应该只是一个没有 setter 的 getter。如果有人观察描述，他们应该在任何时候都会收到通知。

从前面的分析可以看出，我们似乎无法将这种行为归类为先前讨论过的任何可观察类型。我们需要的是计算属性。我们可以通过简单地向`cart`可观察对象添加`get-property`来定义一个*computed*描述属性。它将从`items.length`派生其值。看一下这段代码：

```jsx
const cart = observable.object({
    items: [],
    modified: new Date(),

    get description() {
        switch (this.items.length) {
            case 0:
                return 'There are no items in the cart';
            case 1:
                return 'There is one item in the cart';
            default:
                return `There are ${this.items.length} items in the 
                 cart`;
        }
    },
});
```

现在，您只需读取`cart.description`，就可以始终获得最新的描述。任何观察此属性的人在`cart.description`发生变化时都会自动收到通知，如果您向购物车中添加或删除商品，这种情况就会发生。以下是如何使用这个计算属性的示例：

```jsx
cart.items.push({ name: 'Shoes', quantity: 1 });
console.log(cart.description);
```

请注意，它还满足了先前对`description`属性的所有标准的所有标准。我会让您，读者，确认这是否属实。

*Computed properties*，也称为**derivations**，是 MobX 工具箱中最强大的工具之一。通过将客户端状态视为一组最小的可观察对象，并用派生（计算属性）来增强它，您可以轻松地对各种情况进行建模。计算属性的值取决于其他可观察对象。如果其中任何一个依赖的可观察对象发生变化，计算属性也会发生变化。

您还可以使用其他计算属性构建计算属性。MobX 在内部构建依赖树以跟踪可观察对象。它还缓存计算属性的值，以避免不必要的计算。这是一个重要的特性，极大地提高了 MobX 反应性系统的性能。与 JavaScript 的 get 属性不同，后者总是急切地评估，计算属性会记忆（又名缓存）值，并且只在相关的可观察对象发生变化时进行评估。

随着使用 MobX 的经验的积累，您会意识到*计算属性*可能是您最好的可观察对象朋友。

# 更好的装饰器语法

到目前为止，我们所有的示例都使用了 MobX 的*ES5 API*。然而，API 的特殊形式给了我们一种非常方便的表达可观察对象的方式。这是通过`@decorator`语法实现的。

装饰器语法仍然是 JavaScript 语言标准的一个待定提案（截至目前为止）。但这并不妨碍我们使用它，因为我们有**Babel**来帮助我们。通过使用 Babel 插件`transform-decorators-legacy`，我们可以将装饰器语法转译为常规的 ES5 代码。如果您使用 TypeScript，还可以通过在`tsconfig.json`中设置`{ experimentalDecorators: true}`编译器选项来启用装饰器支持。

装饰器语法*仅适用于类*，可用于类声明、属性和方法。以下是使用装饰器表达的等效`Cart`可观察对象：

```jsx
class Cart {
    @observable.shallow items = [];
    @observable modified = new Date();

    @computed get description() {
        switch (this.items.length) {
            case 0:
                return 'There are no items in the cart';
            case 1:
                return 'There is one item in the cart';
            default:
                return `There are ${this.items.length} items in the 
                cart`;
        }
    }
}
```

请注意使用装饰器来*装饰*可观察属性。默认的`@observable`装饰器对值的所有属性进行深度观察。实际上，它是使用`@observable.deep`的简写。

同样，我们有`@observable.shallow`装饰器，它是在可观察对象上设置`{ deep: false }`选项的*粗略*等效。它适用于对象、数组和映射。我们将在第四章中介绍`observable.shallow`的更技术上正确的 ES5 等效。

下面的片段显示了`items`和`metadata`属性，标记为*浅观察对象*：

```jsx
class Cart {
    // Using decorators
    @observable.shallow items = [];
    @observable.shallow metadata = {};
}
```

我们将在后面的章节中介绍更多的装饰器，但我们不想等到那时才讨论装饰器语法。我们认为你应该首选装饰器来声明可观察对象。请注意，它们只在类内部可用。然而，绝大多数情况下，您将使用类来建模您的可观察树，所以装饰器在使其更可读方面非常有帮助。

# 行动

虽然您可以直接更改可观察对象，但强烈建议您使用*actions*来执行。如果您还记得，在上一章中，我们看到动作是导致状态变化的原因。UI 只是触发动作，并期望一些可观察对象被改变。动作隐藏了变异应该如何发生或哪些可观察对象应该受到影响的细节。

下面的图表提醒我们，**UI**只能通过**Action**来修改**State**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00016.jpeg)

行动在 UI 中引入了*词汇*，并为改变状态的操作提供了声明性的名称。MobX 完全接受了这个想法，并将行动作为*一流*的概念。要创建一个动作，我们只需在`action()`API 中包装变异函数。这会给我们一个可以像原始传入的函数一样调用的函数。看一下这段代码：

```jsx
import { observable, action } from 'mobx';

const cart = observable({
    items: [],
    modified: new Date(),
});

// Create the actions const addItem = action((name, quantity) => {
    const item = cart.items.find(x => x.name === name);
    if (item) {
        item.quantity += 1;
    } else {
        cart.items.push({ name, quantity });
    }

    cart.modified = new Date();
});

const removeItem = action(name => {
    const item = cart.items.find(x => x.name === name);
    if (item) {
        item.quantity -= 1;

        if (item.quantity <= 0) {
            cart.items.remove(item);
        }

        cart.modified = new Date();
    }
});

// Invoke actions addItem('balloons', 2);
addItem('paint', 2);
removeItem('paint');
```

在前面的片段中，我们介绍了两个动作：`addItem()`和`removeItem()`，它们向`cart`可观察对象添加和移除项目。由于`action()`返回一个将参数转发给传入函数的函数，我们可以使用所需的参数调用`addItem()`和`removeItem()`。

除了改善代码的可读性外，动作还提高了 MobX 的性能。默认情况下，当您修改一个可观察对象时，MobX 会*立即*发出更改的通知。如果您一起修改一堆可观察对象，您可能希望在所有这些对象都被修改后再发出更改通知。这将减少太多通知的噪音，并将一组更改视为一个*原子事务*。这实质上是一个`action()`的核心责任。

# 强制使用动作

毫不奇怪，MobX 强烈建议使用*actions*来修改可观察对象。事实上，通过配置 MobX 始终强制执行此策略，也称为**strict mode**，可以使此操作成为强制性的。`configure()`函数可用于将`enforceActions`选项设置为 true。如果尝试在动作之外修改可观察对象，MobX 现在将抛出错误。

回到我们之前关于`cart`的例子，如果我们尝试在*动作*之外*修改*它，MobX 将会出现错误，如下例所示：

```jsx
import { observable, configure } from 'mobx';

configure({
 enforceActions: true,
});

// Modifying outside of an action
cart.items.push({ name: 'test', quantity: 1 });
cart.modified = new Date();

Error: [mobx] Since strict-mode is enabled, changing observed observable values outside actions is not allowed. Please wrap the code in an `action` if this change is intended. Tried to modify: ObservableObject@1.items
```

关于使用`configure({ enforceActions: true })`有一件小事需要记住：它只会在有观察者观察您尝试改变的可观察对象时才会抛出错误。如果没有观察者观察这些可观察对象，MobX 将安全地忽略它。这是因为没有触发反应过早的风险。但是，如果您确实想严格执行此操作，还可以设置`{ enforceActions: 'strict' }`。即使没有观察者附加到变异的可观察对象，这也会抛出错误。

# 装饰动作

装饰器在 MobX 中是无处不在的。动作也通过`@action`装饰器获得特殊处理，以将类方法标记为动作。使用装饰器，`Cart`类可以编写如下所示：

```jsx
class Cart {
    @observable modified = new Date();
    @observable.shallow items = [];

 @action  addItem(name, quantity) {
        this.items.push({ name, quantity });
        this.modified = new Date();
    }

    **@action.bound**
  removeItem(name) {
        const item = this.items.find(x => x.name === name);
        if (item) {
            item.quantity -= 1;

            if (item.quantity <= 0) {
                this.items.remove(item);
            }
        }
    }
}
```

在前面的片段中，我们为`removeItem()`动作使用了`@action.bound`。这是一种特殊形式，可以预先绑定类的实例到该方法。这意味着您可以传递对`removeItem()`的引用，并确保`this`值始终指向 Cart 的实例。

使用类属性和箭头函数预先绑定`this`声明`removeItem`动作的另一种方式是。以下代码中可以看到这一点：

```jsx
class Cart {
    /* ... */
    **@action** removeItem = (name) => {
        const item = this.items.find(x => x.name === name);
        if (item) {
            item.quantity -= 1;

            if (item.quantity <= 0) {
                this.items.remove(item);
            }
        }
    }
}
```

在这里，`removeItem`是一个*类属性*，其值是一个*箭头函数*。由于*箭头函数*，它绑定到*词法*`this`，即`Cart`的实例。

# 反应

**Reactions**确实可以改变您的应用程序世界。它们是对可观察对象变化做出反应的副作用行为。反应完成了 MobX 的核心三部曲，并充当可观察对象的观察者。看一下这个图表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00017.jpeg)

MobX 为您提供了三种不同的方式来表达您的反应或副作用。这些是`autorun()`，`reaction()`和`when()`。让我们依次看看每一个。

# autorun()

`autorun()` 是一个长时间运行的副作用，它接受一个函数（`effect-function`）作为参数。`effect-function` 函数是你应用所有副作用的地方。现在，这些副作用可能依赖于一个或多个 observables。MobX 将自动跟踪这些 *dependent* observables 的任何变化，并重新执行此函数以应用副作用。在代码中更容易看到这一点，如下所示：

```jsx
import { observable, action, autorun } from 'mobx';

class Cart {
    @observable modified = new Date();
    @observable.shallow items = [];

    constructor() {
        autorun(() => {
            console.log(`Items in Cart: ${this.items.length}`);
        });
    }

    @action
  addItem(name, quantity) {
        this.items.push({ name, quantity });
        this.modified = new Date();
    }
}

const cart = new Cart();
cart.addItem('Power Cable', 1);
cart.addItem('Shoes', 1);

// Prints:
// Items in Cart: 0 // Items in Cart: 1 // Items in Cart: 2
```

在上面的例子中，我们将一个 *observable*（`this.items.length`）记录到控制台。记录会*立即*发生，也会在 observable 变化时发生。这是 `autorun()` 的定义特征；它立即运行，并且在 dependent observables 变化时也会运行。

我们之前提到 `autorun()` 是一个长时间运行的副作用，只要你不明确停止它，它就会继续。但是，你如何实际停止它呢？嗯，`autorun()` 的返回值实际上是一个函数，它实际上是一个 `disposer-function`。通过调用它，你可以取消 `autorun()` 的副作用。看一下这个：

```jsx
import { observable, action, autorun } from 'mobx';

class Cart {
    /* ... */

    cancelAutorun = null;

    constructor() {
        this.cancelAutorun = autorun(() => {
            console.log(`Items in Cart: ${this.items.length}`);
        });
    }

    /* ... */
}

const cart = new Cart();
// 1\. Cancel the autorun side-effect
cart.cancelAutorun();

// 2\. The following will not cause any logging to happen
cart.addItem('Power Cable', 1);
cart.addItem('Shoes', 1);

// Prints:
// Items in Cart: 0
```

在上面的片段中，我们将 `autorun()` 的返回值（一个 `disposer-function`）存储在一个类属性中：`cancelAutorun`。在实例化 `Cart` 后立即调用它，我们取消了副作用。现在 `autorun()` 只打印一次，再也不会打印了。

快速阅读者问题：为什么它只打印一次？因为我们立即取消了，`autorun()` 不应该完全跳过打印吗？对此的答案是刷新 `autorun` 的核心特征。

# reaction()

`reaction()` 是 MobX 中另一种反应的方式。是的，API 名称的选择是有意的。`reaction()` 类似于 `autorun()`，但在执行 `effect-function` 之前等待 observables 的变化。`reaction()` 实际上接受两个参数，如下所示：

```jsx
reaction(tracker-function, effect-function): disposer-function

tracker-function: () => data, effect-function: (data) => {}
```

`tracker-function` 是跟踪所有 observables 的地方。任何时候跟踪的 observables 发生变化，它都会重新执行。它应该返回一个值，用于与上一次运行的 `tracker-function` 进行比较。如果这些返回值不同，就会执行 `effect-function`。

通过将反应的活动分解为一个检测变化的函数（`tracker`函数）和`effect`函数，`reaction()`使我们对何时引起副作用有了更精细的控制。它不再仅仅依赖于`tracker`函数内部跟踪的可观察对象。相反，它现在取决于`tracker`函数返回的数据。`effect`函数接收这些数据作为输入。在效果函数中使用的任何可观察对象都不会被跟踪。

就像`autorun()`一样，你还会得到一个`disposer`函数作为`reaction()`的返回值。这可以用来随时取消副作用。

我们可以通过一个例子来实践这一点。假设你想在你的`购物车`中的任何物品价格变化时得到通知。毕竟，你不想购买突然涨价的东西。与此同时，你也不想错过一个好的交易。因此，当价格变化时得到通知是一个有用的功能。我们可以通过使用`reaction()`来实现这一点，如下所示：

```jsx
import { observable, action, reaction } from 'mobx';

class Cart {
    @observable modified = new Date();
    @observable items = [];

    cancelPriceTracker = null;

    trackPriceChangeForItem(name) {
        if (this.cancelPriceTracker) {
            this.cancelPriceTracker();
        }

 // 1\. Reaction to track price changes
        this.cancelPriceTracker = reaction(
            () => {
                const item = this.items.find(x => x.name === name);
                return item ? item.price : null;
            },
            price => {
                console.log(`Price changed for ${name}: ${price !== 
                null ? price : 0}`);
            },
        );
    }

    @action
  addItem(name, price) {
        this.items.push({ name, price });
        this.modified = new Date();
    }

    @action
  changePrice(name, price) {
        const item = this.items.find(x => x.name === name);
        if (item) {
            item.price = price;
        }
    }
}

const cart = new Cart();

cart.addItem('Shoes', 20);

// 2\. Now track price for "Shoes"
cart.trackPriceChangeForItem('Shoes');

// 3\. Change the price
cart.changePrice('Shoes', 100);
cart.changePrice('Shoes', 50);

// Prints:
// Price changed for Shoes: 100
// Price changed for Shoes: 50
```

在上面的片段中，我们在*注释 1*中设置了一个价格跟踪器，作为*跟踪价格变化的反应*。请注意，它接受两个函数作为输入。第一个函数（`tracker-function`）找到具有给定`name`的物品，并将其价格作为`tracker`函数的输出返回。每当它变化时，相应的`effect`函数就会被执行。

控制台日志也只在价格变化时打印。这正是我们想要的行为，并通过`reaction()`实现了。现在你已经被通知价格变化，你可以做出更好的购买决策。

# 响应式 UI

在谈到反应时，值得一提的是 UI 是应用程序中最辉煌的反应（或副作用）之一。正如我们在前一章中看到的那样，*UI*依赖于数据，并应用转换函数来生成视觉表示。在 MobX 世界中，这个 UI 也是响应式的，它对数据的变化做出反应，并自动重新渲染自己。

MobX 提供了一个名为***mobx-react***的伴侣库，它与 React 绑定。通过使用来自`mobx-react`的装饰器函数（`observer()`***），您可以将 React 组件转换为观察`render()`函数中使用的可观察对象。当它们发生变化时，会触发 React 组件的重新渲染。在内部，`observer()`创建一个包装组件，该组件使用普通的`reaction()`来监视可观察对象并重新渲染为副作用。这就是为什么我们将 UI 视为另一个副作用，尽管是一个非常显而易见的副作用。

下面展示了使用`observer()`的简短示例。我们使用了一个**无状态函数组件**，将其传递给 observer。由于我们正在读取`item`可观察对象，因此组件现在将对`item`的更改做出反应。两秒后，当我们更新`item`时，`ItemComponent`将自动重新渲染。看一下这个：

```jsx
import { observer } from 'mobx-react';
import { observable } from 'mobx';
import ReactDOM from 'react-dom';
import React from 'react';

const item = observable.box(30);

// 1\. Create the component with observer
const ItemComponent = observer(() => {
    // 2\. Read an observable: item
    return <h1>Current Item Value = {item.get()}</h1>;
});

ReactDOM.render(<ItemComponent />, document.getElementById('root'));

// 3\. Update item
setTimeout(() => item.set(50), 2000);
```

我们将在第三章中涵盖`mobx-react`，*使用 MobX 的 React 应用程序*，并且在整本书中都会涉及。

# when()

正如其名称所示，`when()`仅在满足条件时执行`effect-function`，并在此之后自动处置副作用。因此，与`autorun()`和`reaction()`相比，`when()`是一次性副作用。`predicate`函数通常依赖于一些可观察对象来进行条件检查。如果可观察对象发生变化，`predicate`函数将被重新评估。

`when()`接受两个参数，如下所示：

```jsx
when(predicate-function, effect-function): disposer-function

predicate-function: () => boolean, effect-function: ()=>{}
```

`predicate`函数预计返回一个布尔值。当它变为`true`时，执行`effect`函数，并且`when()`会自动处置。请注意，`when()`还会返回一个`disposer`函数，您可以调用它来提前取消副作用。

在下面的代码块中，我们正在监视物品的可用性，并在其重新上架时通知用户。这是一次性效果，您不必持续监视。只有当库存中的物品数量超过零时，您才会执行通知用户的副作用。看一下这个：

```jsx
import { observable, action, when } from 'mobx';

class Inventory {
    @observable items = [];

    cancelTracker = null;

    trackAvailability(name) {

 // 1\. Establish the tracker with when
        this.cancelTracker = when(
            () => {
                const item = this.items.find(x => x.name === name);
                return item ? item.quantity > 0 : false;
            },
            () => {
                console.log(`${name} is now available`);
            },
        );
    }

    @action
  addItem(name, quantity) {
        const item = this.items.find(x => x.name === name);
        if (item) {
            item.quantity += quantity;
        } else {
            this.items.push({ name, quantity });
        }
    }
}

const inventory = new Inventory();

inventory.addItem('Shoes', 0);
inventory.trackAvailability('Shoes');

// 2\. Add two pairs
inventory.addItem('Shoes', 2);

// 3\. Add one more pair
inventory.addItem('Shoes', 1);

// Prints:
// Shoes is now available
```

这里的`when()`接受两个参数。`predicate`函数在`item.quantity`大于零时返回 true。`effect`函数只是通过`console.log`通知物品在商店中可用。当 predicate 变为 true 时，`when()`执行副作用并自动处理自身。因此，当我们将两双鞋子添加到库存时，`when()`执行并记录可用性。

注意，当我们将一双鞋子添加到库存中时，不会打印任何日志。这是因为此时`when()`已被处理并且不再监视*Shoes*的可用性。这是`when()`的一次性效果。

# 带有 promise 的 when()

`when()`还有一个特殊版本，只接受一个参数（`predicate`函数），并返回一个 promise 而不是`disposer`函数。这是一个很好的技巧，您可以跳过使用`effect`函数，而是等待`when()`解析后再执行效果。在代码中更容易看到，如下所示：

```jsx
class Inventory {
    /* ... */    async trackAvailability(name) {
 // 1\. Wait for availability
        await when(() => {
            const item = this.items.find(x => x.name === name);
            return item ? item.quantity > 0 : false;
        });

 // 2\. Execute side-effect
        console.log(`${name} is now available`);
    }

    /* ... */ }
```

在*注释 1*中，我们正在使用只接受`predicate`函数的`when()`来等待物品的可用性。通过使用`async-await`操作符等待 promise，我们可以得到清晰、可读的代码。在`await`语句后面的任何代码都会在 promise 解析后自动安排执行。如果您*不*想传递一个效果回调，这是使用`when()`的更好方式。

`when()`也非常高效，不会轮询`predicate`函数以检查更改。相反，它依赖于 MobX 反应性系统在基础可观察对象发生变化时重新评估`predicate`函数。

# 关于反应的快速回顾

MobX 提供了几种执行副作用的方式，但您必须确定哪种适合您的需求。以下是一个快速总结，可以帮助您做出正确的选择。

我们有三种运行副作用的方式：

1.  `autorun( effect-function: () => {} )`：对于长时间运行的副作用很有用。`effect`函数立即执行，也会在其中使用的依赖可观察对象（在其内部使用）发生变化时执行。它返回一个`disposer`函数，可以随时用于取消。

1.  `reaction( tracker-function: () => data, effect-function: (data) => {} )`: 也用于长时间运行的副作用。只有当`tracker`函数返回的数据不同时，才执行`effect`函数。换句话说，`reaction()`在可观察对象发生变化之前等待。它还返回一个`disposer`函数，以提前取消效果。

1.  `when( predicate-function: () => boolean, effect-function: () => {} )`: 用于一次性效果。`predicate`函数在其依赖的可观察对象发生变化时进行评估。只有当`predicate`函数返回`true`时，才执行`effect`函数。`when()`在运行`effect`函数后会自动处理自身。还有一种特殊形式的`when()`，只接受`predicate`函数并返回一个 promise。可以与`async-await`一起使用以简化`when()`。

# 总结

MobX 的故事围绕着可观察对象展开。操作改变这些可观察对象。派生和反应观察并对这些可观察对象的变化做出反应。可观察对象、操作和反应构成了核心三元组。

我们已经看到了几种用对象、数组、映射和包装可观察对象来塑造你的可观察对象的方法。操作是修改可观察对象的推荐方式。它们增加了操作的词汇量，并通过最小化变更通知来提高性能。反应是观察者，它们对可观察对象的变化做出反应。它们是导致应用程序产生副作用的原因。

反应有三种形式，`autorun()`、`reaction()`和`when()`，它们以长时间运行或一次性运行的方式区分自己。`when()`是唯一的一次性效果器，它有一个更简单的形式，可以在给定`predicate`函数的情况下返回一个 promise。


# 第三章：一个带有 MobX 的 React 应用

使用 React 很有趣。现在，再加上 MobX 来满足所有你的状态管理需求，你就有了一个超级组合。基本的 MobX 已经完成，我们现在可以进入使用之前讨论过的想法来构建一个简单的 React 应用。我们将处理定义可观察状态的过程，可以在该状态上调用的操作，以及观察和呈现变化状态的 React UI。

本章涵盖的主题包括以下内容：

+   书籍搜索用例

+   创建可观察状态和操作

+   构建响应式 UI

# 技术要求

你需要有 JavaScript 编程语言。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter03`](https://github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter03)

查看以下视频，看看代码是如何运行的：

[`bit.ly/2v0HnkW`](http://bit.ly/2v0HnkW)

# 书籍搜索

我们简单的 React 应用的用例是传统电子商务应用程序之一，即在巨大的库存中搜索产品。在我们的案例中，搜索的是书籍。我们将使用*Goodreads* API 来按标题或作者搜索书籍。Goodreads 要求我们注册一个帐户来使用他们的 API。

通过访问此 URL 创建一个 Goodreads 帐户：[`www.goodreads.com/api/keys`](https://www.goodreads.com/api/keys)。你可以使用你的亚马逊或 Facebook 帐户登录。一旦你有了帐户，你需要生成一个 API 密钥来进行 API 调用。

Goodreads 公开了一组端点，以 XML 格式返回结果。同意，这并不理想，但他们有大量的书籍，将 XML 转换为 JSON 对象是一个小小的代价。事实上，我们将使用一个`npm`包进行此转换。我们将使用的端点是 search-books ([`www.goodreads.com/search/index.xml?key=API_KEY&q=SEARCH_TERM`](https://www.goodreads.com/search/index.xml?key=API_KEY&q=SEARCH_TERM))。

我们应用的 UI 将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00018.jpeg)

即使在这个看起来相当简单的界面中，也有一些非常规的用例。由于我们正在进行网络调用来获取结果，所以在显示“结果列表”之前，我们有一个*等待结果*的中间状态。此外，现实世界是严酷的，你的网络调用可能会失败或返回零结果。所有这些状态将在我们的 React UI 中通过 MobX 来处理。

# 可观察状态和操作

UI 只是数据的宏伟转换。它也是这些数据的观察者，并触发操作来改变它。由于数据（又名状态）对 UI 非常重要，因此我们首先从对这种状态进行建模开始是有意义的。使用 MobX，可观察对象表示该状态。回顾之前的 UI 设计，我们可以识别可观察状态的各个部分：

+   用户输入的搜索文本。这是一个字符串类型的可观察字段。

+   有一个可观察的结果数组。

+   有关结果的元信息，例如当前子集和总结果计数。

+   有一些状态来捕获我们将要调用的“async search（）”操作。操作的初始“状态”是“空”。一旦用户调用搜索，我们就处于“挂起”状态。当搜索完成时，我们可能处于“完成”或“失败”状态。这更像是`<empty>`，`pending`，`completed`或`failed`的枚举，并且可以用可观察字段来捕获。

由于所有这些状态属性都相关，我们可以将它们放在一个可观察对象下：

```jsx
const searchState = observable({
    term: '',
    state: '',
    results: [],
    totalCount: 0,
});
```

这肯定是一个很好的开始，似乎捕捉到了我们需要在 UI 上显示的大部分内容。除了状态，我们还需要确定可以在 UI 上执行的操作。对于我们简单的 UI，这包括调用搜索和在用户在文本框中输入字符时更新术语。在 MobX 中，操作被建模为动作，它们在内部改变可观察状态。我们可以将这些作为`searchState`可观察对象上的*操作*添加：

```jsx
const searchState = observable({
    term: '',
    status: '',
    results: [],
    totalCount: 0,

    search: action(function() {
        // invoke search API
  }),

    setTerm: action(function(value) {
        this.term = value;
    }),
});
```

`searchState`可观察对象正在慢慢增长，并且在定义可观察状态时也积累了一些语法噪音。随着我们添加更多的可观察字段、计算属性和操作，这肯定会变得更加难以控制。更好的建模方式是使用类和装饰器。

关于我们为`searchState`可观察定义操作的方式有一个小注意事项。请注意，我们故意避免使用箭头函数来定义操作。这是因为箭头函数在定义操作时捕获**词法 this**。然而，`observable()` API 返回一个新对象，这当然与在`action()`调用中捕获的**词法 this**不同。这意味着您正在改变的`this`不会是从`observable()`返回的对象。您可以尝试通过将箭头函数传递给`action()`调用来验证这一点。

通过将一个普通函数传递给`action()`，我们可以确保`this`指向可观察的正确实例。

让我们看看使用类和装饰器是什么样子的：

```jsx
class BookSearchStore {
    @observable term = '';
    @observable status = '';
    @observable.shallow results = [];

    @observable totalCount = 0;

    @action.bound
  setTerm(value) {
        this.term = value;
    }

    @action.bound
  async search() {
        // invoke search API
    }
}

export const store = new BookSearchStore();
```

使用装饰器使得很容易看到类的可观察字段。事实上，我们有灵活性来混合和匹配可观察字段和常规字段。装饰器还使得调整可观察性的级别变得容易（例如：为结果使用`shallow`可观察）。`BookSearchStore`类利用装饰器捕获可观察字段和操作。由于我们只需要这个类的一个实例，我们将单例实例导出为`store`。

# 管理异步操作

使用`async search()`操作更有趣。我们的 UI 需要在任何时间点知道操作的确切状态。为此，我们有可观察字段：`status`，用于跟踪操作状态。它最初处于`empty`状态，并在操作开始时变为`pending`。一旦操作完成，它可以处于`completed`或`failed`状态。您可以在代码中看到这一点，如下所示：

```jsx
class BookSearchStore {
    @observable term = '';
    @observable status = '';
    @observable.shallow results = [];

    @observable totalCount = 0;

    /* ... */

    @action.bound
  async search() {
        try {
            this.status = 'pending';
            const result = await searchBooks(this.term);

            runInAction(() => {
                this.totalCount = result.total;
                this.results = result.items;
                this.status = 'completed';
            });
        } catch (e) {
            runInAction(() => (this.status = 'failed'));
            console.log(e);
        }
    }
}
```

在前面的代码中有一些值得注意的地方：

+   `async`操作与`sync`操作并没有太大不同。事实上，*async-action 只是在不同时间点上的 sync-actions*。

+   设置可观察状态只是一个赋值的问题。我们在`await`之后的代码中使用`runInAction()`来确保所有可观察值都在一个操作内被改变。当我们为 MobX 打开`enforceActions`配置时，这变得至关重要。

+   因为我们使用了`async-await`，我们在一个地方处理了两种未来的可能性。

+   `searchBooks()`函数只是一个调用 Goodreads API 并获取结果的服务方法。它返回一个 promise，我们在`async`操作中`await`它。

此时，我们已经准备好应用程序的可观察状态，以及可以对这些可观察对象执行的一组操作。我们将创建的 UI 只是简单地绘制这个可观察状态，并公开控件来调用这些操作。让我们直接进入 UI 的观察者领域。

刚刚看到的`async search()`方法中的一个观察是将状态变化包装在`runInAction()`中。如果您在这些调用之间有多个`await`调用并且有状态变化，这可能会变得很繁琐。认真地包装这些状态变化中的每一个可能会很麻烦，甚至可能会忘记包装！

为了避免这种繁琐的仪式，您可以使用一个名为`flow()`的实用函数，它接受一个`generator`函数，而不是`await`，使用`yield`操作符。`flow()`实用程序正确地在`yield`后包装了状态变化，而无需您自己去做。我们将在后面的章节中使用这种方法。

# 响应式 UI

在 MobX 的核心三部曲中，反应起着影响外部世界的作用。在第二章中，*可观察对象、动作和反应*，我们已经看到了一些这些反应的形式，如`autorun()`、`reaction()`和`when()`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00019.jpeg)

`observer()`是另一种类型的反应，有助于将 React 世界与 MobX 绑定在一起。`observer()`是`mobx-react` NPM 包的一部分，这是一个用于 MobX 和 React 的绑定库。它创建了一个**高阶组件**（**HOC**），用于自动更新可观察状态的变化。在内部，`observer()`跟踪在组件的`render`方法中取消引用的可观察对象。当它们中的任何一个发生变化时，会触发组件的重新渲染。

在 UI 组件树中随处可以添加`observer()`组件是非常常见的。无论何时需要一个可观察对象来渲染组件，都可以使用`observer()`。

我们要构建的 UI 将把`BookSearchStore`的可观察状态映射到各种组件。让我们将 UI 分解为其结构组件，如下图所示。这里的观察者组件包括**SearchTextField**和**ResultsList**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00020.jpeg)当您开始将可观察状态映射到 React 组件时，您应该从一个单片组件开始，该组件读取所有必要的状态并将其呈现出来。然后，您可以开始拆分观察者组件，并逐渐创建组件层次结构。建议您尽可能细化观察者组件。这可以确保当只有一小部分组件发生变化时，React 不会不必要地渲染整个组件。

在最高级别上，我们有`App`组件，它组合了`SearchTextField`和`ResultsList`。在代码中，这看起来如下：

```jsx
import {**inject**, observer} from '**mobx-react**'; @inject('store')
@observer class App extends React.Component {
    render() {
        const { store } = this.props;

        return (
            <Fragment>
                <Header />

                <Grid container>
                    <Grid item xs={12}>
                      <Paper elevation={2}  style={{ padding: '1rem' }}>
                            <**SearchTextField**
  onChange={this.updateSearchText}   onEnter={store.search}  />
                        </Paper>
                    </Grid>

                    <ResultsList style={{ marginTop: '2rem' }} />
                </Grid>
            </Fragment>
        );
    }

    updateSearchText = event => {
        this.props.store.setTerm(event.target.value);
    };
}
```

如果您已经注意到了，`App`类上有一个我们以前没有见过的新装饰器：`inject('store')`，也是`mobx-react`包的一部分。这创建了一个将`store`可观察对象绑定到 React 组件的 HOC。这意味着，在`App`组件的`render()`中，我们可以期望在`props`上有一个`store`属性可用。

我们正在使用`material-ui` NPM 包来使用各种 UI 组件。这个组件库为我们的 UI 提供了 Material Design 外观，并提供了许多实用组件，如`TextField`、`LinearProgress`、`Grid`等。

# 到达 store

使用`inject()`，您可以将可观察的`BookSearchStore`连接到您的任何 React 组件。然而，神秘的问题是：*`inject()`*如何知道我们的*`BookSearchStore`*？这就是您需要查看`App`组件上一级发生的事情的地方，我们在那里渲染整个 React 应用程序：

```jsx
import { store } from './BookStore';
import React, { Fragment } from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'mobx-react';

ReactDOM.render(
    <Provider store={store}>
        <App />
    </Provider>,
    document.getElementById('root'),
);
```

来自`mobx-react`的`Provider`组件与`BookSearchStore`可观察对象建立了真正的连接粘合剂。导出的`BookSearchStore`（名为`store`）的单例实例作为名为`store`的 prop 传递到`Provider`中。在内部，它使用 React Context 将`store`传播到由`inject()`装饰器包装的任何组件。因此，`Provider`提供了`store`可观察对象，而`inject()`连接到*React Context*（由`Provider`公开），并将`store`注入到包装的组件中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00021.jpeg)

值得注意的是，命名 prop`store`并没有什么特别之处。您可以选择任何您喜欢的名称，甚至可以将多个可观察实例传递给`Provider`。如果我们的简单应用程序需要一个单独的*用户偏好*存储，我们可以这样传递它：

```jsx
import { store } from './BookStore';
import { preferences } from 'PreferencesStore;

<Provider store={store} userPreferences={preferences}>
    <App />
</Provider>
```

当然，这意味着`inject()`也将将其引用为`userPreferences`：

```jsx
@inject('userPreferences')
@observer class PreferencesViewer extends React.Component {
    render() {
        const { userPreferences } = this.props;

        /* ... */
  }
}
```

# `SearchTextField`组件

回到我们最初的例子，我们可以利用`Provider`和`inject()`的功能，在组件树的任何级别访问`store`（`BookSearchStore`的一个实例）。`SearchTextField`组件利用它来成为`store`的观察者：

```jsx
@inject('store')
@observer export class SearchTextField extends React.Component {
    render() {
 const { store, onChange } = this.props;
 const { term } = store;

        return (
            <Fragment>
                <TextField
  placeholder={'Search Books...'}   InputProps={{
                        startAdornment: (
                            <InputAdornment position="start">
                                <Search />
                            </InputAdornment>
                        ),
                    }}   fullWidth={true}  value={term}   onChange={onChange}   onKeyUp={this.onKeyUp}  />

                <SearchStatus />
            </Fragment>
        );
    }

    onKeyUp = event => {
        if (event.keyCode !== 13) {
            return;
        }

        this.props.onEnter();
    };
}
```

`SearchTextField`观察`store`的`term`属性，并在其更改时更新自身。对`term`的更改作为`TextField`的`onChange`处理程序的一部分进行处理。实际的`onChange`处理程序作为一个 prop 传递到`SearchTextField`中，由`App`组件传递。在`App`组件中，我们触发`setTerm()`动作来更新`store.term`属性。

```jsx
@inject('store')
@observer class App extends React.Component {
    render() {
        const { store } = this.props;

        return (
            <Fragment>
                <Header />

                <Grid container>
                    <Grid item xs={12}>
                      <Paper elevation={2}  style={{ padding: '1rem' }}>
                            <SearchTextField
 onChange={this.updateSearchText}  onEnter={store.search}  />
                        </Paper>
                    </Grid>

                    <ResultsList style={{ marginTop: '2rem' }} />
                </Grid>
            </Fragment>
        );
    }

 updateSearchText = event => {
 this.props.store.setTerm(event.target.value);
 };
}
```

现在，`SearchTextField`不仅处理对`store.term`可观察对象的更新，还显示了`SearchStatus`组件的搜索操作状态。我们将这个组件直接包含在`SearchTextField`中，但没有传递任何 props。起初这可能有点不安。`SearchStatus`如何知道当前的`store.status`？嗯，一旦你看到`SearchStatus`的定义，这就显而易见了：

```jsx
import React, { Fragment } from 'react';
import { inject, observer } from 'mobx-react';

export const SearchStatus = inject('store')(
    observer(({ store }) => {
        const { status, term } = store;

        return (
            <Fragment>
                {status === 'pending' ? (
                    <LinearProgress variant={'query'} />
                ) : null}

                {status === 'failed' ? (
                    <Typography
  variant={'subheading'}   style={{ color: 'red', marginTop: '1rem' }}  >
                        {`Failed to fetch results for "${term}"`}
                    </Typography>
                ) : null}
            </Fragment>
        );
    }),
);
```

使用`inject()`，我们可以访问`store`可观察对象，并通过使用`observer()`包装组件，我们可以对可观察状态（`term`，`status`）的变化做出反应。注意嵌套调用`inject('store')(observer( () => {} ))`的使用。这里的顺序很重要。首先调用`inject()`请求要注入的 Provider-prop。这将返回一个以组件为输入的函数。在这里，我们使用`observer()`创建一个高阶组件，并将其传递给`inject()`。

由于`SearchStatus`组件基本上是独立的，`SearchTextField`可以简单地包含它并期望它能正常工作。

当`store.status`改变时，只有`SearchStatus`的虚拟 DOM 发生变化，重新渲染了该组件。`SearchTextField`的其余部分保持不变。这种渲染效率内置在`observer()`中，你不需要额外的工作。在内部，`observer()`会仔细跟踪在`render()`中使用的可观察对象，并设置一个`reaction()`来在任何被跟踪的可观察对象发生变化时更新组件。

# ResultsList 组件

使用`SearchTextField`，当您输入一些文本并按下*Enter*时，搜索操作将被调用。这会改变可观察状态，部分由`SearchTextField`渲染。然而，当结果到达时，与*搜索词*匹配的书籍列表将由`ResultsList`组件显示。正如预期的那样，它是一个*观察者*组件，通过`inject()`连接到`store`可观察对象。但这一次，它使用了稍微不同的方法连接到`store`：

```jsx
import { inject, observer } from 'mobx-react';

@inject(({ store }) => ({ searchStore: store }))
@observer
export class ResultsList extends React.Component {
    render() {
        const { searchStore, style } = this.props;
        const { isEmpty, results, totalCount, status } = searchStore;

        return (
            <Grid spacing={16} container style={style}>
                {isEmpty && status === 'completed' ? (
                    <Grid item xs={12}>
 <EmptyResults />
                    </Grid>
                ) : null}

                {!isEmpty && status === 'completed' ? (
                    <Grid item xs={12}>
                        <Typography>
                            Showing <strong>{results.length}</strong> 
                             of{' '}
                            {totalCount} results.
                        </Typography>
                        <Divider />
                    </Grid>
                ) : null}

                {results.map(x => (
                    <Grid item xs={12} key={x.id}>
 <BookItem book={x} />
                        <Divider />
                    </Grid>
                ))}
            </Grid>
        );
    }
}
```

请注意使用`@inject`装饰器，该装饰器接受一个函数来提取`store`可观察对象。这为您提供了一种更加类型安全的方法，而不是使用字符串属性。您还会看到我们在*提取函数*中将`store`重命名为`searchStore`。因此，`store`可观察对象将以`searchStore`的名称注入。

在`ResultsList`的渲染方法中，我们还在做一些值得注意的其他事情：

+   使用`isEmpty`属性检查搜索结果是否为空。这之前没有声明，但实际上是一个`computed`属性，检查结果数组的长度，如果为零则返回`true`：

```jsx
class BookSearchStore {
    @observable term = 'javascript';
    @observable status = '';
    @observable.shallow results = [];

    @observable totalCount = 0;

 @computed
  get isEmpty() {
 return this.results.length === 0;
 }

    /* ... */
}
```

如果搜索操作已完成并且没有返回结果（`isEmpty = true`），我们将显示`EmptyResults`组件。

+   如果搜索完成并且我们得到了一些结果，我们将显示计数以及结果列表，每个结果都使用`BookItem`组件渲染。

因此，我们应用程序的组件树如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00022.jpeg)

**Provider**实际上是可观察状态的提供者。它依赖于 React Context 来在组件子树中传播`store`可观察对象。通过使用`inject()`和`observer()`装饰组件，您可以连接到可观察状态并对更改做出反应。**SearchTextField**、**SearchStatus**和**ResultsList**组件依赖于`observer()`和`inject()`为您提供响应式 UI。

随着在 React 16.3+中引入`React.createContext()`，您可以自己创建`Provider`组件。这可能有点冗长，但它实现了相同的目的——在组件子树中传播存储。如果您感到有点冒险，可以尝试一下。

# 总结

`mobx`和`mobx-react`是两个广泛用于构建响应式 UI 的 NPM 包。`mobx`包提供了构建可观察状态、动作和反应的 API。另一方面，`mobx-react`提供了将 React 组件与可观察状态连接并对任何更改做出反应的绑定粘合剂。在我们的示例中，我们利用这些 API 构建了一个图书搜索应用程序。在创建基于*observer*的组件树时，确保使用观察者进行细粒度操作。这样你就可以对你需要渲染 UI 的可观察对象做出反应。

`SearchTextField`、`SearchStatus`和`ResultsList`组件旨在细粒度并对焦点可观察表面做出反应。这是在 React 中使用 MobX 的推荐方式。

在下一章中，我们将深入探讨 MobX，探索可观察对象。


# 第四章：创建可观察树

定义应用程序的响应模型通常是使用 MobX 和 React 时的第一步。我们非常清楚，这都属于以下领域：

+   Observables, which represent the application state

+   操作，改变它

+   Reactions, which produce side effects by observing the changing observables

在定义可观察状态时，MobX 为您提供了各种工具来精确控制可观察性。在本章中，我们将探讨 MobX 的这一方面，并深入研究*创建可观察树*。

本章将涵盖以下主题：

+   数据的形状

+   使用各种装饰器控制可观察性

+   创建计算属性

+   使用类建模 MobX 存储

# 技术要求

您需要掌握 JavaScript 编程语言。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter04`](https://github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter04)

查看以下视频以查看代码的实际操作：

[`bit.ly/2uYmln9`](http://bit.ly/2uYmln9)

# 数据的形状

我们在应用程序中处理的数据以各种形状和大小出现。然而，这些不同的形状相当有限，可以列举如下：

+   **Singular values**: These include primitives like numbers, booleans, strings, null, undefined, dates, and so on.

+   **列表**: 您典型的项目列表，其中每个项目都是独一无二的。通常最好避免将不同数据类型的项目放在同一个列表中。这样可以创建易于理解的同质列表。

+   **层次结构**: 我们在 UI 中看到的许多结构都是分层的，比如文件和文件夹的层次结构，父子关系，组和项目等等。

+   **组合**: 一些或所有前述形状的组合。大多数现实世界的数据都是这种形式。

MobX 给了我们 API 来模拟每个形状，我们已经在之前的章节中看到了一些例子。然而，MobX 在单一值和其他类型（如数组和映射）之间做了一个区分。这也反映在 API 中，`observable()`只能用来创建对象、数组和映射。将单一值创建为 observable 需要我们使用`observable.box()`API 来包装它。

# 控制可观察性

默认情况下，MobX 对您的对象、数组和映射应用深度可观察性。这使您可以看到可观察树中任何级别的变化。虽然这是一个很好的默认值，但在某些时候，您将不得不更加关注限制可观察性。减少可观察性也可以提高性能，因为 MobX 需要跟踪的内容更少。

有两种不同的方式可以控制可观察性：

+   通过在类内部使用各种`@decorators`

+   通过使用`decorate()` API

# 使用@decorators

装饰器是一种语法特性，允许您将行为附加到类及其字段上。我们已经在第三章中看到了这一点，*使用 MobX 创建 React 应用*，因此以下代码应该非常熟悉：

```jsx
class BookSearchStore {
    @observable term = 'javascript';
    @observable status = '';
    @observable.shallow results = [];

    @observable totalCount = 0;
}
```

使用`@observable`装饰器，您可以将类的属性变成可观察的。这是开始建模可观察对象的推荐方法。默认情况下，`@observable`应用深度可观察性，但还有一些专门的装饰器可以让您更好地控制。

`@observable`是`@observable.deep`的缩写形式或别名，这是默认的装饰器。它在对象、数组和映射的所有级别上应用*深度可观察性*。然而，深度观察在对象具有*构造函数或原型*的地方停止。这样的对象通常是类的实例，并且预计具有自己的*可观察属性*。MobX 选择在深度观察期间跳过这样的对象。

# 使用@observable.shallow 创建浅观察对象

这个装饰器将可观察性修剪到数据的第一层，也称为**一级深度**观察，对于可观察数组和映射特别有用。对于数组，它将监视数组本身的引用更改（例如，分配一个新数组），以及数组中项目的添加和删除。如果数组中有具有属性的项目，则这些属性不会被视为浅观察。同样，对于映射，只考虑键的添加和删除，以及映射本身的引用更改。可观察映射中键的值保持不变，不被视为观察对象。

以下代码片段展示了`@observable.shallow`装饰器的应用。

```jsx
class BookSearchStore {
    @observable term = 'javascript';
    @observable status = '';
 @observable.shallow results = [];

    @observable totalCount = 0;
}
```

我们选择将这个装饰器应用到`BookSearchStore`的`results`属性上。很明显，我们并不特别观察每个单独结果的属性。事实上，它们是只读对象，永远不会改变值，因此我们只需要将可观察性修剪到项目的添加和移除以及`results`数组中的引用更改。因此，`observable.shallow`在这里是正确的选择。

这里需要记住的一个微妙的点是数组的`length`属性（在地图的情况下是`size`）也是可观察的。你能想出它为什么是可观察的吗？

# 使用@observable.ref 创建仅引用的可观察对象

如果您*不*对数据结构（对象、数组、地图）内发生的任何更改感兴趣，而只对*值的更改*感兴趣，那么`@observable.ref`就是您要找的东西。它只会监视可观察对象的引用更改。

```jsx
import { observable, action } from 'mobx';

class FormData {
 @observable.ref validations = null;

    @observable username = '';
    @observable password = '';

    @action
  validate() {
        const { username, password } = this;
 this.validations = applyValidations({ username, password });
    }
}
```

在前面的例子中，`validations`可观察性总是被分配一个新值。由于我们从未修改此对象的属性，最好将其标记为`@observable.ref`。这样，我们只跟踪`validations`的引用更改，而不跟踪其他任何东西。

# 使用@observable.struct 创建结构可观察对象

MobX 具有内置行为来跟踪值的更改，并且对于诸如字符串、数字、布尔值等基元类型非常有效。但是，在处理*对象*时，它变得不太理想。每当将新对象分配给可观察对象时，它都将被视为更改，并且反应将触发。您真正需要的是*结构检查*，其中比较对象的*属性*而不是*对象引用*，然后决定是否有更改。这就是`@observable.struct`的目的。

它基于*属性值*进行深度比较，而不是依赖顶层引用。您可以将其视为对`observable.ref`装饰器的改进。

让我们看一下以下代码，我们为`location`属性创建一个`@observable.struct`：

```jsx
class Sphere {
 @observable.struct location = { x: 0, y: 0 };

    constructor() {
 autorun(() => {
 console.log(
 `Current location: (${this.location.x}, ${this.location.y})`,
 );
 });
    }

    @action
  moveTo(x, y) {
        this.location = { x, y };
    }
}

let x = new Sphere();

x.moveTo(0, 0);
x.moveTo(20, 30); // Prints
Current location: (0, 0)
Current location: (20, 30)
```

请注意，`autorun()`立即触发一次，然后不会对下一个位置（`{ x: 0, y: 0}`）做出反应。由于结构值相同（0, 0），它不被视为更改，因此不会触发通知。只有当我们将位置设置为不同的（x, y）值时，`autorun()`才会被触发。

现在我们可以表示装饰器的可观察性级别，如下图所示。`@observable`（在这种情况下，`@observable.deep`）是最强大的，其次是`@observable.shallow`，`@observable.ref`，最后是`@observable.struct`。随着可观察装饰器的细化，您可以修剪可观察树中的表面积。这用橙色形状表示。可观察的越多，MobX 的跟踪区域就越大：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00023.jpeg)

# 使用 decorate() API

使用`@decorators`绝对非常方便和可读，但它确实需要一些 Babel 设置（使用*babel-plugin-transform-decorators-legacy*）或在 TypeScript 的编译器选项中打开`experimentalDecorators`标志。MobX 在版本 4 中引入了用于装饰对象或类的可观察属性的*ES5* API。

使用`decorate()` API，您可以有选择地针对属性并指定可观察性。以下代码片段应该可以说明这一点：

```jsx
import { action, computed, decorate, observable } from 'mobx';
 class BookSearchStore {
 term = 'javascript';
 status = '';
 results = [];

 totalCount = 0;

 get isEmpty() {
 return this.results.length === 0;
 }

 setTerm(value) {
 this.term = value;
 }

 async search() {}
}

decorate(BookSearchStore, {
 term: observable,
 status: observable,
 results: observable.shallow,
 totalCount: observable,

 isEmpty: computed,
 setTerm: action.bound,
 search: action.bound,
});
```

```jsx
decorate(target, decorator-object)
```

`target`可以是对象原型或类类型。第二个参数是一个包含要装饰的目标属性的对象。

在前面的示例中，请注意我们将装饰器应用于类类型的方式。从开发人员的角度来看，在没有`@decorators`语法支持时使用它们感觉很自然。事实上，`decorate()` API 也可以用于其他类型的装饰器，如`action`，`action.bound`和`computed`。

# 使用 observable()进行装饰

使用`decorate()` API 时，声明可观察性也适用于`observable()` API。

`observable(properties, decorators, options)`:它的参数如下：

+   `properties`*:* 声明可观察对象的属性

+   `decorators`: 定义属性装饰器的对象

+   `options`: 用于设置默认可观察性和调试友好名称的选项 (`{ deep: false|true, name: string }`)

`observable()`的第二个参数是您在对象中为各种属性指定装饰器的地方。这与`decorate()`调用的工作方式完全相同，如下面的代码片段所示：

```jsx
import { action, computed, observable } from 'mobx';

const cart = observable(
    {
        items: [],
        modified: new Date(),
        get hasItems() {
            return this.items.length > 0;
        },
        addItem(name, quantity) {
            /* ... */
  },
        removeItem(name) {
            /* ... */
  },
    },
 {
 items: observable.shallow,
 modified: observable,

 hasItems: computed,
 addItem: action.bound,
 removeItem: action.bound,
 },
);
```

在第二个参数中，我们已经应用了各种装饰器来控制*可观察性*，应用*操作*，并标记*计算属性*。

在使用`observable()`API 时，不需要显式标记计算属性。MobX 将把传入对象的任何`getter`属性转换为计算属性。

同样，对于`modified`属性，实际上没有必要进行装饰，因为`observable()`默认会使所有内容深度可观察。我们只需要指定需要不同处理的属性。换句话说，只为特殊属性指定装饰器。

# 扩展可观察性

在建模客户端状态时，最好预先定义我们在响应式系统中需要的可观察性。这样可以将领域中的可观察数据的所有约束和范围都固定下来。然而，现实世界总是不可饶恕的，有时您需要在运行时扩展可观察性。这就是`extendObservable()`API 的用武之地。它允许您在运行时混入额外的属性，并使它们也可观察。

在下面的例子中，我们正在扩展`cart`的可观察性以适应节日优惠：

```jsx
import { observable, action, extendObservable } from 'mobx';

const cart = observable({
    /* ... */ });

function applyFestiveOffer(cart) {
    extendObservable(
        cart,
        {
            coupons: ['OFF50FORU'],
            get hasCoupons() {
                return this.coupons && this.coupons.length > 0;
            },
            addCoupon(coupon) {
                this.coupons.push(coupon);
            },
        },
        {
            coupons: observable.shallow,
            addCoupon: action,
        },
    );
}
```

```jsx
extendObservable(target, object, decorators)
```

`extendObservable()`的*第一个*参数是我们要扩展的目标对象。第二个参数是将混入目标对象的可观察属性和操作的列表。第三个参数是将应用于属性的装饰器的列表。

在前面的例子中，我们想要为**购物车**添加更多可观察的内容，以跟踪节日优惠。这只能在运行时根据活动的节日季节来完成。当满足条件时，将调用`applyFestiveOffers()`函数。

`extendObservable()`实际上是`observable()`和`observable.object()`的超集。`observable()`实际上是`extendObservable({}, object)`。这看起来与`decorate()`相似并非巧合。MobX 努力保持 API 一致和直观。虽然`extendObservable()`的第一个参数是实际对象，但`decorate()`要求它是类和对象原型。

*[趣闻]*在引入`decorate()`之前，`extendObservable()`被用来在*类构造函数*内部扩展`this`：`extendObservable(this, { })`。当然，现在推荐的方法是使用`decorate()`，它可以直接应用于类或对象原型。

值得思考的一点是，*observable Map*也可以用于动态添加可观察属性。但是，它们只能是*状态承载*属性，而不是*操作*或*计算属性*。当您想要动态添加*操作*和*计算属性*时，可以使用`extendObservable()`。

# 使用@computed 派生状态

MobX 的一个核心理念是可观察状态应尽可能简化。其他一切都应该通过计算属性***派生***出来。当我们谈论 UI 中的状态管理时，这种观点是有道理的。UI 始终对相同的可观察状态进行微妙的处理，并根据上下文和任务的不同需要状态的不同视图。这意味着在同一个 UI 中有许多可能性来派生基于视图的状态（或表示）。

这种基于视图的状态的一个例子是相同可观察对象列表的表视图和图表视图。两者都在相同的状态上操作，但需要不同的表示来满足 UI（视图）的需求。这样的表示是状态派生的主要候选对象。MobX 认识到了这一核心需求，并提供了***计算属性***，这些计算属性是从其他依赖的可观察对象派生其值的专门的可观察对象。

*计算属性*非常高效并且缓存计算结果。虽然计算属性在依赖的可观察对象发生变化时会重新评估，但如果新值与先前缓存的值匹配，则不会触发通知。此外，如果没有计算属性的观察者，计算属性也会被垃圾回收。这种自动清理也增加了效率。*缓存*和*自动清理*是 MobX 建议大量使用计算属性的主要原因。

使用计算属性，我们可以根据 UI 的需要创建单独的可观察对象。随着应用程序规模的增长，您可能需要更多依赖于核心状态的派生。这些派生（计算属性）可以在需要时使用`extendObservable()`混合进来。

MobX 提供了三种不同的方式来创建计算属性：使用`@computed`装饰器，`decorate()` API，或者使用`computed()`函数。这些可以在以下代码片段中看到：

```jsx
import { observable, computed, decorate } from 'mobx';

// 1\. Using @computed class Cart {
    @observable.shallow items = [];

 @computed
  get hasItems() {
 return this.items.length > 0;
 }
}

// 2\. Using decorate() class Cart2 {
    items = [];

    get hasItems() {
        return this.items.length > 0;
    }
}
decorate(Cart2, {
    items: observable.shallow,
 hasItems: computed,
});

// 3\. Using computed() const cart = new Cart();

const isCartEmpty = computed(() => {
 return cart.items.length === 0;
});

console.log(isCartEmpty.get());

const disposer = isCartEmpty.observe(change => console.log(change.newValue));
```

直接使用`computed()`函数的感觉就像是在使用包装的可观察对象。您必须使用返回的计算函数上的`get()`方法来检索值。

您还可以使用`computed()`函数的`observe()`方法。通过附加观察者，您可以获得更改后的值。这种技术也可以用于处理副作用或反应。

这两个 API 都可以在前面的代码片段中看到。这种用法并不是很常见，但在直接处理装箱可观察对象时可以利用。

# 结构相等

如果计算属性的返回值是一个原始值，那么很容易知道是否有新值。MobX 会将计算属性的先前值与新计算的值进行比较，然后在它们不同时触发通知。因此，值比较变得重要，以确保通知只在*真正的改变*时触发。

对于对象来说，这并不是一件简单的事情。默认比较是基于引用检查进行的（使用`===`运算符）。这会导致对象被视为不同，即使它们内部的值完全相同。

在下面的示例中，`metrics`计算属性每次`start`或`end`属性更改时都会生成一个新对象。由于`autorun`（在构造函数中定义）依赖于`metrics`，它会在每次`metrics`更改时运行副作用：

```jsx
import { observable, computed, action, autorun } from 'mobx';

class DailyPrice {
    @observable start = 0;
    @observable end = 0;

 @computed
  get metrics() {
 const { start, end } = this;
 return {
 delta: end - start,
 };
 }

    @action
  update(start, end) {
        this.start = start;
        this.end = end;
    }

    constructor() {
        autorun(() => {
            const { delta } = this.metrics;
            console.log(`Price Delta = ${delta}`);
        });
    }
}

const price = new DailyPrice();

// Changing start and end, but metrics don't change
price.update(0, 10);
price.update(10, 20);
price.update(20, 30);
```

但是，请注意，即使`start`和`end`属性在更改，`metrics`实际上并没有改变。这可以通过*autorun*副作用来看出，它一直打印相同的增量值。这是因为`metrics`计算属性在每次评估时都返回一个新对象：

```jsx
Price Delta = 0;
Price Delta = 10;
Price Delta = 10;
Price Delta = 10;
```

修复这个问题的方法是使用`@computed.struct`装饰器，它会对对象结构进行深度比较。这确保在重新评估`metrics`属性时返回相同结构时不会触发任何通知。

这是一种保护依赖于这样一个计算可观察对象的昂贵反应的方法。使用`computed.struct`装饰它，以确保只有对象结构的真正改变被视为通知。在概念上，这与我们在本章前一节中看到的`observable.struct`装饰器非常相似：

```jsx
class DailyPrice {
    @observable start = 0;
    @observable end = 0;

 @computed.struct  get metrics() {
        const { start, end } = this;
        return {
            delta: end - start,
        };
    }
    // ... 
}
```

在实践中，很少使用`computed.struct`可观察对象。计算值只有在依赖的可观察对象发生变化时才会改变。当任何依赖的可观察对象发生变化时，必须创建一个新的计算值，在大多数真实世界的应用程序中，它在大多数情况下是不同的。因此，你不需要真的使用`computed.struct`修饰，因为大多数计算值在连续评估中都会非常不同。

# 建模存储

当你开始使用 MobX 为你的 React 应用程序建模客户端状态时，这似乎是一项艰巨的任务。一个可以帮助你在这个过程中的想法是简单地意识到*你的应用程序只是一组特性*，组合在一起形成一个连贯的单元。通过从最简单的特性开始，你可以逐个特性地串联整个应用程序。

这种思维方式指导你首先对特性级别的存储进行建模。应用级别的存储（也称为根存储）只是这些特性存储的组合，具有共享的通信渠道。在 MobX 世界中，你首先使用一个*类*来描述特性存储。根据复杂程度，你可以将特性存储分解为许多子存储。特性存储充当所有子存储的协调者。这是对软件建模的经典*分而治之*方法：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00024.jpeg)

让我们举个例子来说明这种建模响应式客户端状态的方法。在我们之前构建的*图书搜索*应用中，我们想要添加创建愿望清单的功能。愿望清单可以包含你将来想要购买的物品。你应该能够创建任意多个愿望清单。让我们使用 MobX 来建模愿望清单功能。我们不会担心 React 方面的事情，而是专注于使用 MobX 来建模客户端状态。

**愿望清单功能**

这增加了创建愿望清单的能力。愿望清单有一个名称，并包含一个将来要购买的物品列表。可以根据需要创建任意多个愿望清单。愿望清单项具有物品的标题和一个标志来跟踪是否已购买。

使用 MobX 进行建模的第一步是确定*可观察状态*和可以改变它的*操作*。我们现在不会担心*反应*（或*观察者*）。

# 可观察状态

我们将从一个*类*`WishListStore`开始，来跟踪愿望清单功能的所有细节。这是我们的*特性级存储*，其中包含整个特性的可观察状态。根据我们之前看到的描述，让我们提炼核心可观察状态：

+   一个愿望清单数组，其中每个项目都是`WishList`类的一个实例

+   `WishList`有一个*名称*，并包含`WishListItem`实例的数组

+   每个`WishListItem`都有一个*标题*和一个布尔值*purchased*属性

这里值得注意的一件事是，我们从之前的描述中提取了一些词汇。这包括`WishListStore`，`WishList`和`WishListItem`，它们构成了我们特性的支柱。识别这些词汇是困难的部分，可能需要几次迭代才能找到正确的术语。难怪“命名事物”被归类为计算机科学中的两个难题之一！

在代码中，我们现在可以这样捕获这个可观察状态：

```jsx
import { observable } from 'mobx';

class WishListStore {
    @observable.shallow lists = [];
}

class WishList {
    @observable name = '';
    @observable.shallow items = [];
}

class WishListItem {
    @observable title = '';
    @observable purchased = false;
}

const store = new WishListStore();
```

注意数组的`observable.shallow`装饰器的使用。我们不需要对它们进行深层观察。单独的项目（`WishListItem`）有它们自己的可观察属性。愿望清单功能由`WishListStore`（`store`）的单例实例表示。由于我们将创建`WishList`和`WishListItem`的实例，我们可以添加构造函数来使这更容易：

```jsx
class WishList {
    @observable name = '';
    @observable.shallow items = [];

 constructor(name) {
 this.name = name;
 }
}

class WishListItem {
    @observable title = '';
    @observable purchased = false;

 constructor(title) {
 this.title = title;
 }
}
```

# 派生状态

现在核心可观察状态已经建立，我们可以考虑一下派生状态。派生状态（推导）是依赖于其他可观察属性的计算属性。在消费核心可观察状态的上下文中考虑派生状态是有帮助的。

当你有数组时，一个常见的用例是考虑空状态。通常有一些视觉指示列表是空的。与其测试`array.length`，这是相当低级的，不如暴露一个名为`isEmpty`的计算属性。这样的计算属性关注我们存储的*语义*，而不是直接处理核心可观察状态：

```jsx
class WishListStore {
    @observable.shallow lists = [];

 @computed
  get isEmpty() {
 return this.lists.length === 0;
 }
}

class WishList {
    @observable name = '';
    @observable.shallow items = [];

 @computed
  get isEmpty() {
 return this.items.length === 0;
 }

    /* ... */
}
```

同样，如果我们想知道从`WishList`中购买的物品，就不需要定义任何新的可观察状态。它可以从`items`通过过滤`purchased`属性来派生。这就是`purchasedItems`的定义*计算属性*。我将把定义这个计算属性留给读者作为练习。

您应该始终将*observable state*视为最小*core state*和*derived state*的组合。请考虑以下方程式，以确保您没有将太多内容放入核心状态中。可以派生的内容应始终位于*derived state*中：

在现实世界的应用程序中，很可能由于重构而将在一个存储中跟踪的属性移动到另一个存储中。例如，`WishListItem`的`purchased`属性可以由一个单独的存储（例如`ShoppingCartStore`）跟踪。在这种情况下，`WishListItem`可以将其设置为*computed property*并依赖外部存储来跟踪它。这样做不会改变 UI 上的任何内容，因为您读取`purchased`的方式仍然保持不变。此外，由于计算属性隐式创建的依赖关系，MobX 使得保持`purchased`属性始终保持最新变得简单。

# 操作

一旦确定了 observable state，就自然而然地包括可以改变它的*actions*。这些是用户将调用的操作，并由 React 接口公开。在愿望清单功能的情况下，这包括：

+   创建新的`WishList`

+   删除愿望清单

+   重命名愿望清单

+   将项目（`WishListItem`）添加到愿望清单

+   从愿望清单中删除项目

将添加或删除愿望清单的操作放入顶层的`WishListStore`中，而涉及愿望清单中项目的操作将放在`WishList`类中。愿望清单的重命名也可以放在`WishList`类中：

```jsx
import { observable, action } from 'mobx';

class WishListStore {
    @observable.shallow lists = [];

    /* ... */

    @action
  addWishList(name) {
        this.lists.push(new WishList(name));
    }

    @action
  removeWishList(list) {
        this.lists.remove(list);
    }
}

class WishList {
    @observable name = '';
    @observable.shallow items = [];

    /* ... */ 
    @action
  renameWishList(newName) {
        this.name = newName;
    }

    @action
  addItem(title) {
        this.items.push(new WishListItem(title));
    }

    @action
  removeItem(item) {
        this.items.remove(item);
    }
}
```

MobX 为*observable arrays*提供了方便的 API 来移除项目。使用`remove()`方法，您可以删除与值或引用匹配的项目。如果找到并删除了该项目，则该方法将返回*true*。

# 摘要

一旦对 observable state 进行了广泛的切割，就可以使用 observable decorators 进一步定制它。这样可以更好地控制可观察性，并改善 MobX 响应性系统的性能。我们已经看到了两种不同的方法：一种是使用`@decorator`语法，另一种是使用`decorate()`API。

还可以使用`extendObservable()`动态添加新的*observable properties*。实际上，您甚至可以使用`extendObservable()`添加新的*actions*和*computed properties*。

*Observable State = Core State + Derived State*

*核心状态*和*派生状态*是 MobX 中*可观察状态*的两个方面。这很容易用类和装饰器来建模，就像前面的章节中所示的那样。一旦你确定了你的功能的词汇，它们就成为封装*可观察状态*的类名。为了处理功能的复杂性，你可以将其分解为较小的类，并将它们组合在*功能存储*中。然后这些*功能存储*再组合在顶层的*根存储*中。

现在我们对定义和构建*可观察对象*有了更深入的理解，是时候我们来看看 MobX 的其他支柱：*actions*和*reactions*。这就是我们下一章要讨论的内容。
