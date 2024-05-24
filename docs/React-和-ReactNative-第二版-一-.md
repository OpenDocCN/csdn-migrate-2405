# React 和 ReactNative 第二版（一）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我从来没有对开发移动应用程序感兴趣。我曾坚信这是网络，或者什么都不是，已经有太多应用程序安装在设备上了，没有必要再安装更多的应用程序。然后 React Native 出现了。我已经在为 Web 应用程序编写 React 代码并且喜欢它。事实证明，我并不是唯一一个对使用不同的工具、环境和编程语言来维护同一个应用程序的想法感到犹豫的开发人员。React Native 的诞生是出于自然的愿望，即将 Web 开发体验中表现良好的东西（React），应用到原生应用程序开发中。原生移动应用程序提供比 Web 浏览器更好的用户体验。事实证明我错了，我们现在确实需要移动应用程序。但这没关系，因为 React Native 是一个很棒的工具。这本书基本上是我作为 Web 上的 React 开发人员和作为一个经验较少的移动应用程序开发人员的经验。React Native 旨在让已经了解 Web 上的 React 的开发人员轻松过渡。通过这本书，你将学习在两种环境中进行 React 开发的微妙之处。你还将学习 React 的概念主题，一个可以针对任何东西的简单渲染抽象。今天，它是 Web 浏览器和移动设备。明天，它可能是任何东西。

这本书的第二版是为了应对不断发展的 React 项目而写的 - 包括实施 React 组件的最新最佳实践以及围绕 React 的生态系统。我认为，React 开发人员重要的是要了解 React 的工作原理，以及 React 的实现如何改变以更好地支持依赖它的人。在这一版的 React 和 React Native 中，我尽力捕捉了 React 今天的本质和它的发展方向。

# 这本书适合谁

这本书是为任何想要开始学习如何使用 Facebook 的两个 UI 库的 JavaScript 开发人员 - 无论是初学者还是专家编写的。不需要了解 React，但对 ES2017 的工作知识会帮助你更好地跟上。

# 第一部分：React

第一章，*为什么选择 React？*，介绍了 React 的基本知识以及为什么你想要使用它。

第二章，“使用 JSX 进行渲染”，解释了 JSX 是 React 用于渲染内容的语法。HTML 是最常见的输出，但 JSX 也可以用于渲染许多其他内容，例如原生 UI 组件。

第三章，“组件属性，状态和上下文”，展示了属性如何传递给组件，状态在更改时如何重新渲染组件，以及上下文在组件中的作用。

第四章，“事件处理-React 方式”，解释了 React 中的事件是在 JSX 中指定的。React 处理事件的方式有微妙之处，以及您的代码应该如何响应它们。

第五章，“打造可重用组件”，显示组件通常是使用较小的组件组合而成的。这意味着您必须正确地将数据和行为传递给子组件。

第六章，“React 组件生命周期”，解释了 React 组件是如何不断创建和销毁的。在此期间还有其他几个生命周期事件，您可以在其中执行诸如从网络获取数据之类的操作。

第七章，“验证组件属性”，展示了 React 具有一种机制，允许您验证传递给组件的属性类型。这确保了没有意外的值传递给您的组件。

第八章，“扩展组件”，介绍了用于扩展 React 组件的机制。这包括继承和高阶组件。

第九章，“使用路由处理导航”，解释了导航是任何 Web 应用程序的重要部分。React 使用`react-router`包以声明方式处理路由。

第十章，“服务器端 React 组件”，讨论了当在浏览器中渲染时，React 如何将组件呈现到 DOM 中。它还可以将组件呈现为字符串，这对于在服务器上呈现页面并将静态内容发送到浏览器非常有用。

第十一章，*移动优先 React 组件*，解释了移动 Web 应用程序与为桌面屏幕分辨率设计的 Web 应用程序在根本上是不同的。`react-bootstrap`包可用于以移动优先的方式构建 UI。

# 第二部分：React Native

第十二章，*为什么选择 React Native？*，显示 React Native 是用于移动应用程序的 React。如果您已经投资于 Web 应用程序的 React，为什么不利用相同的技术提供更好的移动体验呢？

第十三章，*启动 React Native 项目*，讨论了没有人喜欢编写样板代码或设置项目目录。React Native 有工具来自动化这些单调的任务。

第十四章，*使用 Flexbox 构建响应式布局*，解释了为什么 Flexbox 布局模型在使用 CSS 的 Web UI 布局中很受欢迎。React Native 使用相同的机制来布局屏幕。

第十五章，*在屏幕之间导航*，讨论了导航是 Web 应用程序的重要部分，移动应用程序也需要工具来处理用户如何从一个屏幕移动到另一个屏幕。

第十六章，*渲染项目列表*，显示 React Native 有一个列表视图组件，非常适合渲染项目列表。您只需提供数据源，它就会处理剩下的事情。

第十七章，*显示进度*，解释了进度条非常适合显示确定数量的进度。当您不知道某事会花费多长时间时，您可以使用进度指示器。React Native 具有这两个组件。

第十八章，*地理位置和地图*，显示了`react-native-maps`包为 React Native 提供了地图功能。在 Web 应用程序中使用的地理位置 API 直接由 React Native 提供。

第十九章，*收集用户输入*，显示大多数应用程序需要从用户那里收集输入。移动应用程序也不例外，React Native 提供了各种控件，与 HTML 表单元素类似。

第二十章，*警报、通知和确认*，解释了警报用于打断用户，让他们知道发生了重要的事情，通知是不显眼的更新，确认用于立即获得答案。

第二十一章，*响应用户手势*，讨论了移动设备上的手势在浏览器中很难做到正确。另一方面，原生应用程序为滑动、触摸等提供了更好的体验。React Native 为你处理了很多细节。

第二十二章，*控制图像显示*，展示了图像在大多数应用程序中扮演着重要角色，无论是作为图标、标志还是物品的照片。React Native 具有加载图像、缩放图像和适当放置图像的工具。

第二十三章，*离线操作*，解释了移动设备往往具有不稳定的网络连接。因此，移动应用程序需要能够处理临时的离线条件。为此，React Native 具有本地存储 API。

# 第三部分：React 架构

第二十四章，*处理应用程序状态*，讨论了应用程序状态对于任何 React 应用程序，无论是 Web 还是移动应用程序都很重要。这就是为什么理解 Redux 和 Immutable.js 等库很重要。

第二十五章，*为什么使用 Relay 和 GraphQL*？解释了 Relay 和 GraphQL 结合使用是一种处理规模化状态的新方法。它是一个查询和变异语言，以及一个用于包装 React 组件的库。

第二十六章，*构建 Relay React 应用程序*，显示了 Relay 和 GraphQL 的真正优势在于你的状态模式在应用程序的 Web 和原生版本之间是共享的。

# 为了充分利用本书

1.  告知读者在开始之前需要了解的事情，并明确你所假设的知识。

1.  任何额外的安装说明和他们设置所需的信息。

+   一个代码编辑器

+   一个现代的网络浏览器

+   NodeJS

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的软件解压缩文件夹：

+   Windows 系统使用 WinRAR/7-Zip

+   Mac 系统使用 Zipeg/iZip/UnRarX

+   Linux 系统使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/React-and-React-Native-Second-Edition`](https://github.com/PacktPublishing/React-and-React-Native-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，可以从我们丰富的图书和视频目录中获得，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```jsx
import React, { Component } from 'react';
// Renders a "<button>" element, using
// "this.props.children" as the text.
export default class MyButton extends Component {
  render() {
    return <button>{this.props.children}</button>;
  }
}
```

任何命令行输入或输出都以以下方式编写：

```jsx
$ npm install -g create-react-native-app $ create-react-native-app my-project 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：为什么要使用 React？

如果你正在阅读这本书，你可能已经对 React 有一些想法。你可能也听过一两个 React 的成功故事。如果没有，不用担心。我会尽力在本章节中避免让你接触到额外的营销文学。然而，这是一本内容丰富的书，所以我觉得设定基调是一个合适的第一步。是的，目标是学习 React 和 React Native。但同时也是为了构建一个持久的架构，可以处理我们今天和未来想要用 React 构建的一切。

本章以 React 存在的简要解释开始。然后，我们将讨论使 React 成为一种吸引人的技术的简单性，以及 React 如何能够处理 Web 开发人员面临的许多典型性能问题。接下来，我们将介绍 React 的声明性哲学以及 React 程序员可以期望使用的抽象级别。最后，我们将介绍 React 16 的一些主要新功能。

让我们开始吧！

# 什么是 React？

我认为 React 在其主页上的一行描述([`facebook.github.io/react`](https://facebook.github.io/react)))非常出色：

*“用于构建用户界面的 JavaScript 库。”*

这是一个用于构建用户界面的库。这很完美，因为事实证明，这正是我们大多数时候想要的。我认为这个描述最好的部分是它所省略的一切。它不是一个大型框架。它不是一个从数据库到实时更新的 Web 套接字连接处理一切的全栈解决方案。实际上，我们并不想要大多数这些预打包的解决方案，因为最终它们通常会带来更多问题而不是解决问题。

# React 只是视图

React 通常被认为是应用程序中的*视图*层。你可能以前使用过类似 Handlebars 或 jQuery 的库。就像 jQuery 操作 UI 元素，或者 Handlebars 模板被插入到页面上一样，React 组件改变了用户所看到的内容。下面的图表说明了 React 在我们前端代码中的位置：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1df1b7e1-3681-4845-8f34-9e75d6569c10.png)

这就是 React 的全部核心概念。当然，在我们阅读本书的过程中，这个主题可能会有一些微妙的变化，但流程基本上是一样的。我们有一些应用逻辑生成一些数据。我们想要将这些数据渲染到 UI 上，所以我们将其传递给一个 React 组件，它负责将 HTML 放入页面中。

也许你会想知道这有什么大不了的，特别是因为在表面上，React 似乎只是另一种渲染技术。在本章的其余部分，我们将涉及 React 可以简化应用程序开发的一些关键领域。

# 简单就是好

React 并没有太多需要学习和理解的部分。在内部，有很多事情正在发生，我们将在本书中逐渐涉及这些事情。与大型框架相比，拥有一个小的 API 可以让你花更多的时间熟悉它，进行实验等等。大型框架则相反，你需要花费大量时间来弄清楚所有东西是如何工作的。下图大致展示了我们在使用 React 编程时需要考虑的 API：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/eae05f1a-d2bc-4099-a59e-06c9d921eb2d.png)

React 分为两个主要的 API。首先是 React DOM。这是用于在网页上执行实际渲染的 API。其次是 React 组件 API。这些是实际由 React DOM 渲染的页面的部分。在 React 组件中，我们需要考虑以下几个方面：

+   **数据**：这是来自某处的数据（组件不关心来自哪里），并由组件渲染。

+   **生命周期**：这些是我们实现的方法，用于响应组件生命周期的变化。例如，组件即将被渲染。

+   **事件**：这是我们编写的用于响应用户交互的代码。

+   **JSX**：这是 React 组件的语法，用于描述 UI 结构。

暂时不要过于专注于 React API 的这些不同领域代表什么。这里要记住的是，React 本质上是简单的。看看需要弄清楚的东西是多么少！这意味着我们不必在这里花费大量时间去了解 API 的细节。相反，一旦掌握了基础知识，我们可以花更多时间来研究 React 的微妙用法模式。

# 声明式 UI 结构

React 新手很难接受组件将标记与 JavaScript 混合在一起的想法。如果您看过 React 示例并有相同的不良反应，不要担心。最初，我们都对这种方法持怀疑态度，我认为原因是我们几十年来一直被**关注分离**原则所影响。现在，每当我们看到事物混合在一起，我们自动假设这是不好的，不应该发生。

React 组件使用的语法称为**JSX**（**JavaScript XML**）。组件通过返回一些 JSX 来呈现内容。JSX 本身通常是 HTML 标记，混合了用于 React 组件的自定义标记。在这一点上具体细节并不重要；我们将在接下来的章节中详细讨论。这里绝对突破性的是，我们不必执行微操作来改变组件的内容。

虽然我在本书中不会遵循惯例，但一些 React 开发人员更喜欢使用`.jsx`扩展名而不是`.js`来命名他们的组件。

例如，想想使用类似 jQuery 来构建应用程序。您有一个页面上有一些内容，当单击按钮时，您想向段落添加一个类。执行这些步骤足够简单。这被称为**命令式编程**，对 UI 开发来说是有问题的。虽然在响应事件时更改元素的类的这个例子很简单，但实际应用程序往往涉及超过三四个步骤才能实现某些事情。

React 组件不需要以命令式的方式执行步骤来呈现内容。这就是为什么 JSX 对于 React 组件如此重要的原因。XML 风格的语法使得描述 UI 应该是什么样子变得容易。也就是说，这个组件将呈现哪些 HTML 元素？这被称为**声明式编程**，非常适合 UI 开发。

# 时间和数据

React 新手难以理解的另一个领域是 JSX 就像一个静态字符串，代表了一块渲染输出。这就是时间和数据发挥作用的地方。React 组件依赖于传递给它们的数据。这些数据代表了 UI 的动态方面。例如，基于布尔值呈现的 UI 元素可能会在下次组件渲染时发生变化。这里是这个想法的一个例证：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/81ae1649-8ce0-4024-a22e-aad9c53a364b.png)

每次渲染 React 组件时，就像在那个确切的时间点拍摄 JSX 的快照。随着应用程序随时间向前推进，您将拥有一个有序的渲染用户界面组件的集合。除了声明性地描述 UI 应该是什么之外，重新渲染相同的 JSX 内容对开发人员来说更加容易。挑战在于确保 React 能够处理这种方法的性能要求。

# 性能很重要

使用 React 构建用户界面意味着我们可以使用 JSX 声明 UI 的结构。这比逐个组装 UI 的命令式方法更不容易出错。然而，声明性方法确实给我们带来了一个挑战：性能。

例如，具有声明性 UI 结构对于初始渲染是可以的，因为页面上还没有任何内容。因此，React 渲染器可以查看 JSX 中声明的结构，并将其呈现到 DOM 浏览器中。

**DOM**代表**文档对象模型**，表示在浏览器中呈现后的 HTML。DOM API 是 JavaScript 能够更改页面上内容的方式。

这个概念在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/acea7504-94d5-4687-b33b-48c3e27a766c.png)

在初始渲染时，React 组件及其 JSX 与其他模板库没有区别。例如，Handlebars 将模板呈现为 HTML 标记作为字符串，然后插入到浏览器 DOM 中。React 与诸如 Handlebars 之类的库不同之处在于数据发生变化时，我们需要重新渲染组件。Handlebars 将重新构建整个 HTML 字符串，就像在初始渲染时所做的那样。由于这对性能有问题，我们经常需要实现命令式的解决方法，手动更新 DOM 的一小部分。我们最终会得到一堆混乱的声明性模板和命令式代码来处理 UI 的动态方面。

在 React 中我们不这样做。这就是 React 与其他视图库不同的地方。组件在初始渲染时是声明性的，并且即使在重新渲染时也保持这种状态。React 在幕后所做的工作使得重新渲染声明性 UI 结构成为可能。

React 有一个叫做**虚拟 DOM**的东西，用于在内存中保持对真实 DOM 元素的表示。它这样做是为了每次重新渲染组件时，它可以比较新内容和已经显示在页面上的内容。根据差异，虚拟 DOM 可以执行必要的命令步骤来进行更改。因此，当我们需要更新 UI 时，我们不仅可以保留我们的声明式代码，React 还会确保以高效的方式完成。这个过程看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cbf9b28a-c045-438e-b0f5-0e77bb63f85d.png)当你阅读关于 React 的内容时，你经常会看到诸如**diffing**和**patching**之类的词语。Diffing 意味着比较旧内容和新内容，以找出发生了什么变化。Patching 意味着执行必要的 DOM 操作来渲染新内容。

和任何其他 JavaScript 库一样，React 受到主线程运行完成性质的限制。例如，如果 React 内部正在忙于 diffing 内容和 patching DOM，浏览器就无法响应用户输入。正如你将在本章的最后一节中看到的，React 16 对内部渲染算法进行了更改，以减轻这些性能缺陷。

# 适当的抽象水平

在我们深入研究 React 代码之前，我想以高层次来讨论另一个主题，即**抽象**。React 并没有太多抽象，但 React 实现的抽象对其成功至关重要。

在前面的部分中，你看到了 JSX 语法如何转换为我们不感兴趣的低级操作。观察 React 如何转换我们的声明式 UI 组件的更重要的方式是，我们并不一定关心渲染目标是什么。渲染目标恰好是浏览器 DOM，但它并不局限于浏览器 DOM。

React 有潜力用于我们想要创建的任何用户界面，可以在任何可想象的设备上使用。我们只是刚刚开始在 React Native 中看到这一点，但可能性是无限的。当 React Toast 成为一种事物时，我个人不会感到惊讶，它可以将 JSX 的渲染输出烤到面包上。React 的抽象水平正好，而且位置合适。

以下图表让你了解 React 可以针对的不仅仅是浏览器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/25d52f31-da33-4d24-bb90-4c61f319fcc8.png)

从左到右，我们有 React Web（纯粹的 React）、React Native、React Desktop 和 React Toast。正如你所看到的，为了针对新的目标，同样的模式适用：

+   实现特定于目标的组件

+   实现一个可以在底层执行特定于平台的操作的 React 渲染器

+   利润

这显然是对任何给定的 React 环境实际实现的过度简化。但这些细节对我们来说并不那么重要。重要的是，我们可以利用我们的 React 知识来专注于描述任何平台上用户界面的结构。

不幸的是，React Toast 可能永远不会成为一种东西。

# React 16 的新功能

在这一部分，我想强调 React 16 的主要变化和新功能。随着我们在整本书中遇到这些变化，我将更详细地介绍这些变化。

# 核心架构改进

React 16 中最大的变化可能是内部协调代码。这些变化不会影响您与 React API 交互的方式。相反，这些变化是为了解决一些痛点，这些痛点阻碍了 React 在某些情况下的扩展。例如，这个新架构的主要概念之一是 fiber。React 不再以运行到编译的方式渲染页面上的每个组件，而是渲染 fiber - 页面的较小块，可以优先级和异步渲染。

要更深入地了解这种新架构，这些资源应该会有所帮助：

+   [`github.com/acdlite/react-fiber-architecture`](https://github.com/acdlite/react-fiber-architecture)

+   [`reactjs.org/blog/2017/09/26/react-v16.0.html`](https://reactjs.org/blog/2017/09/26/react-v16.0.html)

# 生命周期方法

React 16 必须重新设计一些可用于类组件的生命周期方法。一些生命周期方法已被弃用，并最终将被移除。有新的生命周期方法来替换它们。主要问题是，弃用的生命周期方法鼓励以一种与新的异步 React 核心不兼容的方式编码。

有关这些生命周期方法的更多信息，请访问此页面：[`reactjs.org/blog/2018/03/27/update-on-async-rendering.html`](https://reactjs.org/blog/2018/03/27/update-on-async-rendering.html)。

# 上下文 API

React 一直为开发人员提供上下文 API，但它一直被视为实验性的。上下文是将数据从一个组件传递到下一个组件的替代方法。例如，使用属性，您可以通过多层组件树传递数据。这个树中间的组件实际上并不使用任何这些属性，它们只是充当中间人。随着应用程序的增长，这变得有问题，因为您的源代码中有很多属性，增加了复杂性。

React 16.3 中的新上下文 API 更加官方，并提供了一种方法，让您在任何树级别为组件提供数据。您可以在这里阅读有关新上下文 API 的更多信息：[`reactjs.org/docs/context.html`](https://reactjs.org/docs/context.html)。

# 渲染片段

如果您的 React 组件呈现了几个兄弟元素，例如三个`<p>`元素，您将不得不将它们包装在`<div>`中，因为 React 只允许组件返回单个元素。这种方法的唯一问题是它会导致大量不必要的 DOM 结构。使用`<Fragment>`包装您的元素与使用`<div>`包装它们的想法是一样的，只是不会有多余的 DOM 元素。

您可以在这里阅读更多关于片段的信息：[`reactjs.org/docs/fragments.html`](https://reactjs.org/docs/fragments.html)。

# 门户

当 React 组件返回内容时，它会被渲染到其父组件中。然后，父级的内容被渲染到其父组件中，依此类推，一直到树根。有时，您希望渲染的内容专门针对 DOM 元素。例如，应该将其呈现为对话框的组件可能不需要挂载到父级。使用门户，您可以控制组件内容的具体渲染位置。

您可以在这里阅读更多关于门户的信息：[`reactjs.org/docs/portals.html`](https://reactjs.org/docs/portals.html)。

# 渲染列表和字符串

在 React 16 之前，组件必须返回 HTML 元素或另一个 React 组件作为其内容。这可能会限制您如何组合应用程序。例如，您可能有一个负责生成错误消息的组件。以前，您必须将这些字符串包装在 HTML 标记中，以被视为有效的 React 组件输出。现在您可以直接返回字符串。同样，您可以直接返回字符串列表或元素列表。

介绍 React 16 的博客文章中有关于这个新功能的更多细节：[`reactjs.org/blog/2017/09/26/react-v16.0.html`](https://reactjs.org/blog/2017/09/26/react-v16.0.html)。

# 处理错误

在 React 中处理错误可能很困难。到底在哪里处理错误？如果一个组件处理 JavaScript 异常并将组件的错误状态设置为 true，那么如何重置这个状态？在 React 16 中，有错误边界。错误边界是通过在组件中实现`componentDidCatch()`生命周期方法来创建的。然后，这个组件可以作为错误边界来包装其他组件。如果任何被包装的组件抛出异常，错误边界组件可以渲染替代内容。

像这样设置错误边界可以让您以最适合您的应用程序的方式构建组件。您可以在这里阅读更多关于错误边界的信息：[`reactjs.org/docs/error-boundaries.html`](https://reactjs.org/docs/error-boundaries.html)。

# 服务器端渲染

在 React 中的**服务器端渲染**（**SSR**）可能很难理解。你在服务器上渲染，然后在客户端上也渲染？由于 SSR 模式变得更加普遍，React 团队在 React 16 中使其更易于使用。此外，通过启用将渲染内容流式传输到客户端，还可以获得一些内部性能和效率方面的收益。

如果您想阅读更多关于 React 16 中的 SSR 的内容，我推荐以下资源：

+   [`hackernoon.com/whats-new-with-server-side-rendering-in-react-16-9b0d78585d67`](https://hackernoon.com/whats-new-with-server-side-rendering-in-react-16-9b0d78585d67)

+   [`reactjs.org/docs/react-dom-server.html`](https://reactjs.org/docs/react-dom-server.html)

# 摘要

在本章中，您以高层次介绍了 React。React 是一个库，具有一个小的 API，用于构建用户界面。接下来，您将介绍 React 的一些关键概念。首先，我们讨论了 React 之所以简单，因为它没有太多的移动部分。接下来，我们看了 React 组件和 JSX 的声明性质。然后，您了解到 React 认真对待性能，这就是我们能够编写可以一遍又一遍重新渲染的声明性代码的原因。接下来，您了解了渲染目标的概念，以及 React 如何轻松成为所有这些目标的首选 UI 工具。最后，我大致概述了 React 16 的新功能。

现在关于介绍和概念的内容就够了。当我们逐渐接近书的结尾时，我们将重新讨论这些想法。现在，让我们退一步，从 JSX 开始，打好基础。

# 测试您的知识

1.  什么是声明式 UI 结构，React 如何支持这个想法？

1.  声明式 UI 是由在使用之前声明的所有组件构建的。如果所有组件没有预先声明，React 将无法渲染。

1.  声明式 UI 结构定义了 UI 组件是什么，而不用担心它是如何定义的。React 通过允许使用 JSX 语法声明组件来支持这个想法。

1.  在 React 中，声明式 UI 结构是完全可选的。您也可以轻松地采用命令式方法。

1.  React 如何提高渲染性能？

1.  React 有一个虚拟 DOM，它在内存中比较组件数据的更改，尽量避免使用浏览器 DOM。React 16 有一个新的内部架构，允许将渲染分成更小的工作块并设置优先级。

1.  React 设置了 Web Workers，以便尽可能地并行处理工作。

1.  React 不专注于性能，而是依赖于增量浏览器性能改进。

1.  何时会渲染一个片段？

1.  当您需要在渲染的内容中使用占位符时，可以使用片段。

1.  片段用于提高其子元素的性能。

1.  片段用于避免渲染不必要的 DOM 元素。

# 进一步阅读

点击以下链接获取更多信息：

+   [`facebook.github.io/react`](https://facebook.github.io/react)

+   [`github.com/acdlite/react-fiber-architecture`](https://github.com/acdlite/react-fiber-architecture)

+   [`reactjs.org/blog/2017/09/26/react-v16.0.html`](https://reactjs.org/blog/2017/09/26/react-v16.0.html)

+   [`reactjs.org/blog/2018/03/27/update-on-async-rendering.html`](https://reactjs.org/blog/2018/03/27/update-on-async-rendering.html)

+   [`reactjs.org/docs/context.html`](https://reactjs.org/docs/context.html)

+   [`reactjs.org/docs/fragments.html`](https://reactjs.org/docs/fragments.html)

+   [`reactjs.org/docs/portals.html`](https://reactjs.org/docs/portals.html)

+   [`reactjs.org/blog/2017/09/26/react-v16.0.html`](https://reactjs.org/blog/2017/09/26/react-v16.0.html)

+   [`reactjs.org/docs/error-boundaries.html`](https://reactjs.org/docs/error-boundaries.html)

+   [`hackernoon.com/whats-new-with-server-side-rendering-in-react-16-9b0d78585d67`](https://hackernoon.com/whats-new-with-server-side-rendering-in-react-16-9b0d78585d67)

+   [`reactjs.org/docs/react-dom-server.html`](https://reactjs.org/docs/react-dom-server.html)

+   [`github.com/facebook/react/wiki/Sites-Using-React`](https://github.com/facebook/react/wiki/Sites-Using-React)


# 第二章：使用 JSX 渲染

本章将向您介绍 JSX。我们将从基础知识开始：什么是 JSX？然后，您会发现 JSX 内置支持 HTML 标记，正如您所期望的那样，所以我们将在这里运行一些示例。在查看了一些 JSX 代码之后，我们将讨论它如何使我们轻松描述 UI 的结构。然后，我们将开始构建我们自己的 JSX 元素，并使用 JavaScript 表达式进行动态内容。最后，您将学习如何使用片段来产生更少的 HTML——这是 React 16 的一个新功能。

准备好了吗？

# 什么是 JSX？

在这一部分，我们将实现义不容辞的*你好世界*JSX 应用程序。在这一点上，我们只是在试水；更深入的例子将会接下来。我们还将讨论什么使这种语法适合声明式 UI 结构。

# 你好 JSX

话不多说，这是你的第一个 JSX 应用程序：

```jsx
// The "render()" function will render JSX markup and
// place the resulting content into a DOM node. The "React"
// object isn't explicitly used here, but it's used
// by the transpiled JSX source.
import React from 'react';
import { render } from 'react-dom';

// Renders the JSX markup. Notice the XML syntax
// mixed with JavaScript? This is replaced by the
// transpiler before it reaches the browser.
render(
 <p>
    Hello, <strong>JSX</strong>
  </p>,
  document.getElementById('root')
);
```

让我们来看看这里发生了什么。首先，我们需要导入相关的部分。`render()`函数是这个例子中真正重要的部分，因为它将 JSX 作为第一个参数并将其呈现到作为第二个参数传递的 DOM 节点上。

在这个例子中，实际的 JSX 内容呈现了一个段落，里面有一些加粗的文本。这里没有什么花哨的东西，所以我们可以直接将这个标记插入到 DOM 中作为普通字符串。然而，JSX 比这里展示的更复杂。这个例子的目的是展示将 JSX 呈现到页面上所涉及的基本步骤。现在，让我们稍微谈一下声明式 UI 结构。

JSX 被转译成 JavaScript 语句；浏览器不知道 JSX 是什么。我强烈建议您从[`github.com/PacktPublishing/React-and-React-Native-Second-Edition`](https://github.com/PacktPublishing/React-and-React-Native-Second-Edition)下载本书的配套代码，并在阅读时运行它。一切都会自动转译给您；您只需要遵循简单的安装步骤。

# 声明式 UI 结构

在我们继续进行代码示例之前，让我们花一点时间来反思我们的*hello world*示例。 JSX 内容简短而简单。它也是**声明性**的，因为它描述了要渲染的内容，而不是如何渲染它。具体来说，通过查看 JSX，您可以看到此组件将呈现一个段落，并在其中呈现一些粗体文本。如果这是以命令式方式完成的，可能会涉及一些更多的步骤，并且它们可能需要按特定顺序执行。

我们刚刚实施的示例应该让您了解声明性 React 的全部内容。随着我们在本章和整本书中的继续前进，JSX 标记将变得更加复杂。但是，它始终将描述用户界面中的内容。让我们继续。

# 就像 HTML 一样

归根结底，React 组件的工作是将 HTML 渲染到 DOM 浏览器中。这就是为什么 JSX 默认支持 HTML 标记。在本节中，我们将查看一些代码，用于渲染一些可用的 HTML 标记。然后，我们将介绍在 React 项目中使用 HTML 标记时通常遵循的一些约定。

# 内置 HTML 标记

当我们渲染 JSX 时，元素标记引用的是 React 组件。由于为 HTML 元素创建组件将是繁琐的，React 带有 HTML 组件。我们可以在我们的 JSX 中渲染任何 HTML 标记，输出将如我们所期望的那样。现在，让我们尝试渲染一些这些标记：

```jsx
import React from 'react';
import { render } from 'react-dom';

// The render() function will only complain if the browser doesn't
// recognize the tag
render(
  <div>
    <button />
    <code />
    <input />
    <label />
    <p />
    <pre />
    <select />
    <table />
    <ul />
  </div>,
  document.getElementById('root')
);
```

不要担心此示例的渲染输出；这没有意义。我们在这里所做的一切只是确保我们可以渲染任意 HTML 标记，并且它们会按预期渲染。

你可能已经注意到周围的`<div>`标签，将所有其他标签分组为其子标签。这是因为 React 需要一个根组件来渲染。在本章的后面，你将学习如何渲染相邻的元素，而不需要将它们包装在父元素中。

# HTML 标记约定

当您在 JSX 标记中渲染 HTML 标记时，期望是您将使用小写来表示标记名称。事实上，大写 HTML 标记的名称将失败。标记名称是区分大小写的，而非 HTML 元素是大写的。这样，很容易扫描标记并找到内置的 HTML 元素与其他所有内容。

您还可以传递 HTML 元素的任何标准属性。当您传递意外的内容时，将记录有关未知属性的警告。以下是一个说明这些想法的示例：

```jsx
import React from 'react';
import { render } from 'react-dom';

// This renders as expected, except for the "foo"
// property, since this is not a recognized button
// property.
render(
  <button title="My Button" foo="bar">
    My Button
  </button>,
  document.getElementById('root')
);

// This fails with a "ReferenceError", because
// tag names are case-sensitive. This goes against
// the convention of using lower-case for HTML tag names.
render(<Button />, document.getElementById('root'));

```

在书的后面，我将介绍你制作的组件的属性验证。这可以避免类似于这个例子中`foo`属性的静默错误行为。

# 描述 UI 结构

JSX 是描述复杂 UI 结构的最佳方式。让我们看一些声明比单个段落更复杂结构的 JSX 标记：

```jsx
import React from 'react';
import { render } from 'react-dom';

// This JSX markup describes some fairly-sophisticated
// markup. Yet, it's easy to read, because it's XML and
// XML is good for concisely-expressing hierarchical
// structure. This is how we want to think of our UI,
// when it needs to change, not as an individual element
// or property.
render(
  <section>
    <header>
      <h1>A Header</h1>
    </header>
    <nav>
      <a href="item">Nav Item</a>
    </nav>
    <main>
      <p>The main content...</p>
    </main>
    <footer>
      <small>&copy; 2018</small>
    </footer>
  </section>,
  document.getElementById('root')
);
```

正如你所看到的，在这个标记中有很多语义元素，描述了 UI 的结构。关键在于这种复杂结构很容易理解，我们不需要考虑渲染它的特定部分。但在我们开始实现动态 JSX 标记之前，让我们创建一些自己的 JSX 组件。

这是渲染的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7c723ef2-ec1d-43ba-987f-d6703b8193f6.png)

# 创建你自己的 JSX 元素

组件是 React 的基本构建块。事实上，组件是 JSX 标记的词汇。在本节中，我们将看到如何在组件中封装 HTML 标记。我们将构建示例，向你展示如何嵌套自定义 JSX 元素以及如何为你的组件命名空间。

# 封装 HTML

你想创建新的 JSX 元素的原因是为了封装更大的结构。这意味着你可以使用自定义标签，而不是输入复杂的标记。React 组件返回替换元素的 JSX。现在让我们看一个例子：

```jsx
// We also need "Component" so that we can
// extend it and make a new JSX tag.
import React, { Component } from 'react';
import { render } from 'react-dom';

// "MyComponent" extends "Compoennt", which means that
// we can now use it in JSX markup.
class MyComponent extends Component {
  render() {
    // All components have a "render()" method, which
    // retunrns some JSX markup. In this case, "MyComponent"
    // encapsulates a larger HTML structure.
    return (
      <section>
        <h1>My Component</h1>
        <p>Content in my component...</p>
      </section>
    );
  }
}

// Now when we render "<MyComponent>" tags, the encapsulated
// HTML structure is actually rendered. These are the
// building blocks of our UI.
render(<MyComponent />, document.getElementById('root'));

```

这是渲染的输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/70ef79a1-882c-478e-a6d4-cc8fd5fb9e8d.png)

这是你实现的第一个 React 组件，所以让我们花点时间来分析一下这里发生了什么。你创建了一个名为`MyComponent`的类，它继承自 React 的`Component`类。这是你创建一个新的 JSX 元素的方式。正如你在`render()`中看到的，你正在渲染一个`<MyComponent>`元素。

这个组件封装的 HTML 是由`render()`方法返回的。在这种情况下，当 JSX `<MyComponent>`被`react-dom`渲染时，它被一个`<section>`元素替换，并且其中的所有内容。 

当 React 渲染 JSX 时，你使用的任何自定义元素必须在同一个作用域内具有相应的 React 组件。在前面的例子中，`MyComponent`类在`render()`调用的同一个作用域中声明，所以一切都按预期工作。通常，你会导入组件，将它们添加到适当的作用域中。随着你在书中的进展，你会看到更多这样的情况。

# 嵌套元素

使用 JSX 标记有助于描述具有父子关系的 UI 结构。例如，`<li>`标记只有作为`<ul>`或`<ol>`标记的子标记才有用-您可能会使用自己的 React 组件创建类似的嵌套结构。为此，您需要使用`children`属性。让我们看看这是如何工作的。以下是 JSX 标记：

```jsx
import React from 'react';
import { render } from 'react-dom';

// Imports our two components that render children...
import MySection from './MySection';
import MyButton from './MyButton';

// Renders the "MySection" element, which has a child
// component of "MyButton", which in turn has child text.
render(
  <MySection>
    <MyButton>My Button Text</MyButton>
  </MySection>,
  document.getElementById('root')
);
```

您正在导入两个自己的 React 组件：`MySection`和`MyButton`。现在，如果您查看 JSX 标记，您会注意到`<MyButton>`是`<MySection>`的子代。您还会注意到`MyButton`组件接受文本作为其子代，而不是更多的 JSX 元素。让我们看看这些组件是如何工作的，从`MySection`开始：

```jsx
import React, { Component } from 'react';

// Renders a "<section>" element. The section has
// a heading element and this is followed by
// "this.props.children".
export default class MySection extends Component {
  render() {
    return (
      <section>
        <h2>My Section</h2>
        {this.props.children}
      </section>
    );
  }
}
```

这个组件呈现了一个标准的`<section>`HTML 元素，一个标题，然后是`{this.props.children}`。正是这个构造允许组件访问嵌套元素或文本，并将其呈现出来。

在前面的例子中使用的两个大括号用于 JavaScript 表达式。我将在下一节中详细介绍在 JSX 标记中找到的 JavaScript 表达式语法的更多细节。

现在，让我们看一下`MyButton`组件：

```jsx
import React, { Component } from 'react';

// Renders a "<button>" element, using
// "this.props.children" as the text.
export default class MyButton extends Component {
  render() {
    return <button>{this.props.children}</button>;
  }
}
```

这个组件使用与`MySection`完全相同的模式；获取`{this.props.children}`的值，并用有意义的标记包围它。React 会为您处理混乱的细节。在这个例子中，按钮文本是`MyButton`的子代，而`MyButton`又是`MySection`的子代。但是，按钮文本是透明地通过`MySection`传递的。换句话说，我们不需要在`MySection`中编写任何代码来确保`MyButton`获得其文本。很酷，对吧？渲染输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/8ac4edd8-81cc-432a-b3ed-55d7e862e629.png)

# 命名空间组件

到目前为止，您创建的自定义元素都使用了简单的名称。有时，您可能希望给组件一个命名空间。在您的 JSX 标记中，您将写入`<MyNamespace.MyComponent>`而不是`<MyComponent>`。这样可以清楚地告诉任何人`MyComponent`是`MyNamespace`的一部分。

通常，`MyNamespace`也将是一个组件。**命名空间**的想法是使用命名空间语法呈现其子组件。让我们来看一个例子：

```jsx
import React from 'react';
import { render } from 'react-dom';

// We only need to import "MyComponent" since
// the "First" and "Second" components are part
// of this "namespace".
import MyComponent from './MyComponent';

// Now we can render "MyComponent" elements,
// and it's "namespaced" elements as children.
// We don't actually have to use the namespaced
// syntax here, we could import the "First" and
// "Second" components and render them without the
// "namespace" syntax. It's a matter of readability
// and personal taste.
render(
  <MyComponent>
    <MyComponent.First />
    <MyComponent.Second />
  </MyComponent>,
  document.getElementById('root')
);

```

这个标记呈现了一个带有两个子元素的`<MyComponent>`元素。关键在于，我们不是写`<First>`，而是写`<MyComponent.First>`，`<MyComponent.Second>`也是一样。这个想法是我们想要明确地显示`First`和`Second`属于`MyComponent`，在标记内部。

我个人不依赖于这样的命名空间组件，因为我宁愿通过查看模块顶部的`import`语句来看哪些组件正在使用。其他人可能更愿意导入一个组件，并在标记中明确标记关系。没有正确的做法；这是个人品味的问题。

现在，让我们来看一下`MyComponent`模块：

```jsx
import React, { Component } from 'react';

// The "First" component, renders some basic JSX...
class First extends Component {
  render() {
    return <p>First...</p>;
  }
}

// The "Second" component, renders some basic JSX...
class Second extends Component {
  render() {
    return <p>Second...</p>;
  }
}

// The "MyComponent" component renders it's children
// in a "<section>" element.
class MyComponent extends Component {
  render() {
    return <section>{this.props.children}</section>;
  }
}

// Here is where we "namespace" the "First" and
// "Second" components, by assigning them to
// "MyComponent" as class properties. This is how
// other modules can render them as "<MyComponent.First>"
// elements.
MyComponent.First = First;
MyComponent.Second = Second;

export default MyComponent;

// This isn't actually necessary. If we want to be able
// to use the "First" and "Second" components independent
// of "MyComponent", we would leave this in. Otherwise,
// we would only export "MyComponent".
export { First, Second };

```

这个模块声明了`MyComponent`以及属于这个命名空间的其他组件（`First`和`Second`）。这个想法是将组件分配给命名空间组件（`MyComponent`）作为类属性。在这个模块中有很多可以改变的东西。例如，你不必直接导出`First`和`Second`，因为它们可以通过`MyComponent`访问。你也不需要在同一个模块中定义所有东西；你可以导入`First`和`Second`并将它们分配为类属性。使用命名空间是完全可选的，如果你使用它们，应该一致地使用它们。

# 使用 JavaScript 表达式

正如你在前面的部分中看到的，JSX 有特殊的语法，允许你嵌入 JavaScript 表达式。每当 React 渲染 JSX 内容时，标记中的表达式都会被评估。这是 JSX 的动态方面，在本节中，你将学习如何使用表达式来设置属性值和元素文本内容。你还将学习如何将数据集合映射到 JSX 元素。

# 动态属性值和文本

一些 HTML 属性或文本值是静态的，意味着它们在 JSX 重新渲染时不会改变。其他值，即属性或文本的值，是基于应用程序中其他地方找到的数据。记住，React 只是视图层。让我们看一个例子，这样你就可以感受一下在 JSX 标记中 JavaScript 表达式语法是什么样子的：

```jsx
import React from 'react';
import { render } from 'react-dom';

// These constants are passed into the JSX
// markup using the JavaScript expression syntax.
const enabled = false;
const text = 'A Button';
const placeholder = 'input value...';
const size = 50;

// We're rendering a "<button>" and an "<input>"
// element, both of which use the "{}" JavaScript
// expression syntax to fill in property, and text
// values.
render(
  <section>
    <button disabled={!enabled}>{text}</button>
    <input placeholder={placeholder} size={size} />
  </section>,
  document.getElementById('root')
);

```

任何有效的 JavaScript 表达式，包括嵌套的 JSX，都可以放在大括号`{}`之间。对于属性和文本，这通常是一个变量名或对象属性。请注意，在这个例子中，`!enabled`表达式计算出一个布尔值。渲染输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/219285aa-1d17-4bcd-8f4a-d210c2c8466a.png)如果你正在使用可下载的配套代码进行跟进，我强烈建议你这样做，尝试玩玩这些值，看看渲染的 HTML 如何改变。

# 将集合映射到元素

有时，你需要编写 JavaScript 表达式来改变你的标记结构。在前面的部分中，你学会了如何使用 JavaScript 表达式语法来动态改变 JSX 元素的属性值。那么当你需要根据 JavaScript 集合添加或删除元素时呢？

在整本书中，当我提到 JavaScript**集合**时，我指的是普通对象和数组。或者更一般地说，任何可迭代的东西。

动态控制 JSX 元素的最佳方式是从集合中映射它们。让我们看一个如何做到这一点的例子：

```jsx
import React from 'react';
import { render } from 'react-dom';

// An array that we want to render as s list...
const array = ['First', 'Second', 'Third'];

// An object that we want to render as a list...
const object = {
  first: 1,
  second: 2,
  third: 3
};

render(
  <section>
    <h1>Array</h1>

    {/* Maps "array" to an array of "<li>"s.
         Note the "key" property on "<li>".
         This is necessary for performance reasons,
         and React will warn us if it's missing. */}
    <ul>{array.map(i => <li key={i}>{i}</li>)}</ul>
    <h1>Object</h1>

    {/* Maps "object" to an array of "<li>"s.
         Note that we have to use "Object.keys()"
         before calling "map()" and that we have
         to lookup the value using the key "i". */}
    <ul>
      {Object.keys(object).map(i => (
        <li key={i}>
          <strong>{i}: </strong>
          {object[i]}
        </li>
      ))}
    </ul>
  </section>,
  document.getElementById('root')
);

```

第一个集合是一个名为`array`的数组，其中包含字符串值。在 JSX 标记中，你可以看到对`array.map()`的调用，它将返回一个新数组。映射函数实际上返回了一个 JSX 元素（`<li>`），这意味着数组中的每个项目现在在标记中表示。

评估这个表达式的结果是一个数组。别担心；JSX 知道如何渲染元素数组。

对象集合使用相同的技术，只是你需要调用`Object.keys()`，然后映射这个数组。将集合映射到页面上的 JSX 元素的好处是，你可以根据集合数据驱动 React 组件的结构。这意味着你不必依赖命令式逻辑来控制 UI。

渲染输出如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/56381615-16d4-4762-b848-03fee269794e.png)

# JSX 片段的片段

React 16 引入了**JSX 片段**的概念。片段是一种将标记块组合在一起的方式，而无需向页面添加不必要的结构。例如，一种常见的方法是让 React 组件返回包裹在`<div>`元素中的内容。这个元素没有实际目的，只会给 DOM 添加混乱。

让我们看一个例子。这里有一个组件的两个版本。一个使用包装元素，另一个使用新的片段功能：

```jsx
import React from 'react';
import { render } from 'react-dom';

import WithoutFragments from './WithoutFragments';
import WithFragments from './WithFragments';

render(
  <div>
    <WithoutFragments />
    <WithFragments />
  </div>,
  document.getElementById('root')
);
```

渲染的两个元素分别是`<WithoutFragments>`和`<WithFragments>`。渲染时的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c8442577-0a54-49a6-a35c-121afc44bc51.png)

现在让我们比较这两种方法。

# 包装元素

第一种方法是将兄弟元素包装在`<div>`中。以下是源代码的样子：

```jsx
import React, { Component } from 'react';

class WithoutFragments extends Component {
  render() {
    return (
      <div>
        <h1>Without Fragments</h1>
        <p>
          Adds an extra <code>div</code> element.
        </p>
      </div>
    );
  }
}

export default WithoutFragments;
```

这个组件的本质是`<h1>`和`<p>`标签。然而，为了从`render()`中返回它们，你必须用`<div>`包装它们。实际上，使用浏览器开发工具检查 DOM 会发现这个`<div>`除了增加了另一层结构外并没有做任何事情。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c91d419c-89ef-4e2f-af12-b4c7bb13bbbc.png)

现在，想象一个有很多这些组件的应用程序，那就是很多无意义的元素！

# 避免使用片段的不必要标签

现在让我们来看一下`WithFragments`组件：

```jsx
import React, { Component, Fragment } from 'react';

class WithFragments extends Component {
  render() {
    return (
      <Fragment>
        <h1>With Fragments</h1>
        <p>Doesn't have any unused DOM elements.</p>
      </Fragment>
    );
  }
}

export default WithFragments;
```

而不是将组件内容包装在`<div>`中，使用了`<Fragment>`元素。这是一种特殊类型的元素，表示只需要渲染它的子元素。如果你检查 DOM，你可以看到与`WithoutFragments`组件相比的区别：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/4aa026e6-9dc9-42bb-a7bb-80bc05082936.png)注意在前面的例子中你不得不从 React 中导入`Fragment`吗？这是因为并非所有的转译器（如 Babel）都能理解 Fragment 元素。在未来的版本中，实际上会有一种简写的方式来在 JSX 中表示片段：`<>My Content</>`。但是目前，`React.Fragment`应该可以在所有的 React 工具中使用。

# 摘要

在本章中，你学习了 JSX 的基础知识，包括其声明性结构以及为什么这是一件好事。然后，你编写了一些代码来渲染一些基本的 HTML，并学习了如何使用 JSX 描述复杂的结构。

接下来，你花了一些时间学习了通过实现自己的 React 组件来扩展 JSX 标记的词汇量，这是 UI 的基本构建块。然后，你学习了如何将动态内容带入到 JSX 元素属性中，以及如何将 JavaScript 集合映射到 JSX 元素，消除了控制 UI 显示的命令式逻辑的需要。最后，你学习了如何使用新的 React 16 功能来渲染 JSX 内容的片段。

现在你已经感受到了在 JavaScript 模块中嵌入声明性 XML 来渲染 UI 的感觉，是时候进入下一章了，在那里我们将更深入地了解组件属性和状态。

# 测试你的知识

1.  你可以将所有标准的 HTML 标签作为 JSX 元素使用吗？

1.  是的，但你必须从 react-dom 中导入你想要使用的任何 HTML 标签

1.  不，你必须实现自己的 React 组件来渲染 HTML 内容

1.  是的，React 支持这个功能

1.  如何访问组件的子元素？

1.  子 JSX 元素始终可以通过 `children` 属性访问

1.  子 JSX 元素作为参数传递给 `render()` 方法

1.  无法从组件内部访问子元素

1.  `Fragment` 组件从 React 做什么？

1.  它更有效地呈现其子元素

1.  它创建一个可重复使用的标记片段，然后可以在整个应用程序中重复使用

1.  它通过消除渲染无意义的元素（如容器 div）来充当容器组件

# 进一步阅读

查看以下链接以获取更多信息：

+   [`reactjs.org/docs/introducing-jsx.html`](https://reactjs.org/docs/introducing-jsx.html)

+   [`reactjs.org/docs/fragments.html`](https://reactjs.org/docs/fragments.html)


# 第三章：组件属性，状态和上下文

React 组件依赖于 JSX 语法，用于描述 UI 的结构。JSX 只能带你走这么远 - 你需要数据来填充 React 组件的结构。本章的重点是组件数据，它有两种主要的变体：*属性*和*状态*。向组件传递数据的另一种选择是通过上下文。

我将首先定义属性和状态的含义。然后，我将通过一些示例来演示设置组件状态和传递组件属性的机制。在本章的末尾，我们将建立在您对 props 和 state 的新知识的基础上，并介绍功能组件和容器模式。最后，您将了解上下文以及何时选择它比属性更好地向组件传递数据。

# 组件状态是什么？

React 组件使用 JSX 声明 UI 元素的结构。但是，如果组件要有用，它们需要数据。例如，您的组件 JSX 可能声明一个`<ul>`，将 JavaScript 集合映射到`<li>`元素。这个集合是从哪里来的？

**状态**是 React 组件的动态部分。您可以声明组件的初始状态，随着时间的推移而改变。

想象一下，您正在渲染一个组件，其中其状态的一部分被初始化为空数组。稍后，该数组将被填充数据。这被称为**状态变化**，每当您告诉 React 组件更改其状态时，组件将自动重新渲染自身。该过程在这里可视化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/710f0e3c-dd8c-4453-b746-81925f964f61.png)

组件的状态是组件本身可以设置的东西，或者是组件外的其他代码片段。现在我们将看看组件属性以及它们与组件状态的区别。

# 组件属性是什么？

**属性**用于将数据传递给您的 React 组件。与使用新状态作为参数调用方法不同，属性仅在组件呈现时传递。也就是说，您将属性值传递给 JSX 元素。

在 JSX 的上下文中，属性被称为**属性**，可能是因为在 XML 术语中是这样称呼它们的。在本书中，属性和属性是同义词。

属性与状态不同，因为它们在组件初始渲染后不会改变。如果属性值已更改，并且你想重新渲染组件，那么我们必须重新渲染用于首次渲染的 JSX。React 内部会确保这样做的效率。下面是使用属性渲染和重新渲染组件的图示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b6424cc1-3cd8-4039-b8df-3ff501aa0ce9.png)

这看起来与有状态的组件有很大不同。真正的区别在于，对于属性来说，往往是父组件决定何时渲染 JSX。组件实际上不知道如何重新渲染自己。正如你将在本书中看到的那样，这种自上而下的流程比在各个地方更改状态更容易预测。

让我们通过编写一些代码来理解这两个概念。

# 设置组件状态

在这一部分，你将编写一些设置组件状态的 React 代码。首先，你将了解初始状态——这是组件的默认状态。接下来，你将学习如何改变组件的状态，导致它重新渲染自己。最后，你将看到新状态如何与现有状态合并。

# 初始组件状态

组件的初始状态实际上并不是必需的，但如果你的组件使用状态，应该设置初始状态。这是因为如果组件期望某些状态属性存在，而它们不存在，那么组件要么会失败，要么会渲染出意外的东西。幸运的是，设置初始组件状态很容易。

组件的初始状态应该始终是一个具有一个或多个属性的对象。例如，你可能有一个使用单个数组作为状态的组件。这没问题，但确保将初始数组设置为状态对象的属性。不要将数组用作状态。原因很简单：一致性。每个 React 组件都使用普通对象作为其状态。

现在让我们把注意力转向一些代码。这是一个设置初始状态对象的组件：

```jsx
import React, { Component } from 'react';

export default class MyComponent extends Component {
 // The initial state is set as a simple property
  // of the component instance.
  state = {
    first: false,
    second: true
  };

  render() {
    // Gets the "first" and "second" state properties
    // into constants, making our JSX less verbose.
    const { first, second } = this.state;

    // The returned JSX uses the "first" and "second"
    // state properties as the "disabled" property
    // value for their respective buttons.
    return (
      <main>
        <section>
          <button disabled={first}>First</button>
        </section>
        <section>
          <button disabled={second}>Second</button>
        </section>
      </main>
    );
  }
}
```

当你查看`render()`返回的 JSX 时，你实际上可以看到这个组件依赖的状态值——`first`和`second`。由于你在初始状态中设置了这些属性，所以可以安全地渲染组件，不会有任何意外。例如，你可以只渲染这个组件一次，它会按预期渲染，多亏了初始状态：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

// "MyComponent" has an initial state, nothing is passed
// as a property when it's rendered.
render(<MyComponent />, document.getElementById('root'));
```

渲染输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f6cbbd99-c074-4366-b7da-d285cdc4722c.png)

设置初始状态并不是很令人兴奋，但它仍然很重要。让组件在状态改变时重新渲染自己。

# 设置组件状态

让我们创建一个具有一些初始状态的组件。然后渲染这个组件，并更新它的状态。这意味着组件将被渲染两次。让我们来看看这个组件：

```jsx
import React, { Component } from 'react';

export default class MyComponent extends Component {
  // The initial state is used, until something
  // calls "setState()", at which point the state is
  // merged with this state.
  state = {
    heading: 'React Awesomesauce (Busy)',
    content: 'Loading...'
  };

  render() {
    const { heading, content } = this.state;

    return (
      <main>
        <h1>{heading}</h1>
        <p>{content}</p>
      </main>
    );
  }
}
```

这个组件的 JSX 取决于两个状态值——`heading`和`content`。该组件还设置了这两个状态值的初始值，这意味着它可以在没有任何意外情况的情况下被渲染。现在，让我们看一些代码，渲染组件，然后通过改变状态重新渲染它：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

// The "render()" function returns a reference to the
// rendered component. In this case, it's an instance
// of "MyComponent". Now that we have the reference,
// we can call "setState()" on it whenever we want.
const myComponent = render(
  <MyComponent />,
  document.getElementById('root')
);

// After 3 seconds, set the state of "myComponent",
// which causes it to re-render itself.
setTimeout(() => {
  myComponent.setState({
    heading: 'React Awesomesauce',
    content: 'Done!'
  });
}, 3000);
```

首先使用默认状态渲染组件。然而，这段代码中有趣的地方是`setTimeout()`的调用。3 秒后，它使用`setState()`来改变两个状态属性的值。果然，这个改变在 UI 中得到了体现。在渲染时，初始状态如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/42c4bd4e-78b1-424d-a47e-09eb21bcefcd.png)

在状态改变后，渲染输出如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/acde8faf-2d3e-44d7-b06f-66c69d96140b.png)这个例子突出了具有声明性 JSX 语法来描述 UI 组件结构的强大功能。你只需声明一次，然后随着应用程序中的变化随时间更新组件的状态以反映这些变化。所有 DOM 交互都经过优化并隐藏在视图之外。

在这个例子中，你替换了整个组件状态。也就是说，调用`setState()`传入了与初始状态中找到的相同对象属性。但是，如果你只想更新组件状态的一部分呢？

# 合并组件状态

当你设置 React 组件的状态时，实际上是将组件的状态与传递给`setState()`的对象进行合并。这很有用，因为这意味着你可以设置组件状态的一部分，同时保持其余状态不变。现在让我们来看一个例子。首先，一个带有一些状态的组件：

```jsx
import React, { Component } from 'react';

export default class MyComponent extends Component {
  // The initial state...
  state = {
    first: 'loading...',
    second: 'loading...',
    third: 'loading...',
    fourth: 'loading...',
    doneMessage: 'finished!'
  };

  render() {
    const { state } = this;

    // Renders a list of items from the
    // component state.
    return (
      <ul>
        {Object.keys(state)
          .filter(key => key !== 'doneMessage')
          .map(key => (
            <li key={key}>
              <strong>{key}: </strong>
              {state[key]}
            </li>
          ))}
      </ul>
    );
  }
}
```

该组件呈现其状态的键和值——除了`doneMessage`。每个值默认为`loading...`。让我们编写一些代码，分别设置每个状态属性的状态：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

// Stores a reference to the rendered component...
const myComponent = render(
  <MyComponent />,
  document.getElementById('root')
);

// Change part of the state after 1 second...
setTimeout(() => {
  myComponent.setState({ first: 'done!' });
}, 1000);

// Change another part of the state after 2 seconds...
setTimeout(() => {
  myComponent.setState({ second: 'done!' });
}, 2000);

// Change another part of the state after 3 seconds...
setTimeout(() => {
  myComponent.setState({ third: 'done!' });
}, 3000);

// Change another part of the state after 4 seconds...
setTimeout(() => {
  myComponent.setState(state => ({
    ...state,
    fourth: state.doneMessage
  }));
}, 4000);

```

从此示例中可以得出的结论是，您可以在组件上设置单个状态属性。它将有效地重新呈现自身。以下是初始组件状态的呈现输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c2f5e541-d867-419e-8a75-ab4f73b099ee.png)

以下是两个`setTimeout()`回调运行后输出的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b0582be3-d3d4-4649-8254-69312bbd8f98.png)

对`setState()`的第四次调用与前三次不同。您可以传递一个函数，而不是传递一个新对象以合并到现有状态中。此函数接受一个状态参数-组件的当前状态。当您需要基于当前状态值进行状态更改时，这将非常有用。在此示例中，`doneMessage`值用于设置`fourth`的值。然后函数返回组件的新状态。您需要将现有状态值合并到新状态中。您可以使用扩展运算符来执行此操作（`...state`）。

# 传递属性值

属性就像传递到组件中的状态数据。但是，属性与状态不同之处在于它们只在组件呈现时设置一次。在本节中，您将了解*默认属性值*。然后，我们将看看*设置属性值*。在本节之后，您应该能够理解组件状态和属性之间的区别。

# 默认属性值

默认属性值的工作方式与默认状态值略有不同。它们被设置为一个名为`defaultProps`的类属性。让我们看一个声明默认属性值的组件：

```jsx
import React, { Component } from 'react';

export default class MyButton extends Component {
  // The "defaultProps" values are used when the
  // same property isn't passed to the JSX element.
  static defaultProps = {
    disabled: false,
    text: 'My Button'
  };

  render() {
    // Get the property values we want to render.
    // In this case, it's the "defaultProps", since
    // nothing is passed in the JSX.
    const { disabled, text } = this.props; 

    return <button disabled={disabled}>{text}</button>;
  }
}

```

为什么不像默认状态一样将默认属性值设置为实例属性？原因是*属性是不可变的*，它们不需要保留为实例属性值。另一方面，状态不断变化，因此组件需要对其进行实例级引用。

您可以看到，此组件为`disabled`和`text`设置了默认属性值。只有在通过用于呈现组件的 JSX 标记未传递这些值时，才会使用这些值。让我们继续呈现此组件，而不使用任何属性，以确保使用`defaultProps`值：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyButton from './MyButton';

// Renders the "MyButton" component, without
// passing any property values.
render(<MyButton />, document.getElementById('root'));

```

始终具有默认状态的相同原则也适用于属性。您希望能够呈现组件，而无需预先知道组件的动态值是什么。

# 设置属性值

首先，让我们创建一些期望不同类型的属性值的组件：

在第七章*验证组件属性*中，我将更详细地讨论验证传递给组件的属性值。

```jsx
import React, { Component } from 'react';

export default class MyButton extends Component {
  // Renders a "<button>" element using values
  // from "this.props".
  render() {
    const { disabled, text } = this.props;

    return <button disabled={disabled}>{text}</button>;
  }
}
```

这个简单的按钮组件期望一个布尔类型的`disabled`属性和一个字符串类型的`text`属性。让我们再创建一个期望一个数组属性值的组件：

```jsx
import React, { Component } from 'react';

export default class MyList extends Component {
  render() {
    // The "items" property is an array.
    const { items } = this.props;

    // Maps each item in the array to a list item.
    return <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>;
  }
}
```

你可以通过 JSX 传递几乎任何你想要的东西作为属性值，只要它是一个有效的 JavaScript 表达式。现在让我们编写一些代码来设置这些属性值：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

// The two components we're to pass props to
// when they're rendered.
import MyButton from './MyButton';
import MyList from './MyList';

// This is the "application state". This data changes
// over time, and we can pass the application data to
// components as properties.
const appState = {
  text: 'My Button',
  disabled: true,
  items: ['First', 'Second', 'Third']
};

// Defines our own "render()" function. The "renderJSX()"
// function is from "react-dom" and does the actual
// rendering. The reason we're creating our own "render()"
// function is that it contains the JSX that we want to
// render, and so we can call it whenever there's new
// application data.
function render(props) {
  renderJSX(
    <main>
      {/* The "MyButton" component relies on the "text"
           and the "disabed" property. The "text" property
           is a string while the "disabled" property is a
           boolean. */}
      <MyButton text={props.text} disabled={props.disabled} />

      {/* The "MyList" component relies on the "items"
           property, which is an array. Any valid
           JavaScript data can be passed as a property. */}
      <MyList items={props.items} />
    </main>,
    document.getElementById('root')
  );
}

// Performs the initial rendering...
render(appState);

// After 1 second, changes some application data, then
// calls "render()" to re-render the entire structure.
setTimeout(() => {
  appState.disabled = false;
  appState.items.push('Fourth');

  render(appState);
}, 1000);

```

`render()`函数看起来像是每次调用时都在创建新的 React 组件实例。React 足够聪明，能够弄清楚这些组件已经存在，并且只需要弄清楚使用新的属性值时输出的差异是什么。

从这个例子中得出的另一个要点是，你有一个`appState`对象，它保存了应用程序的状态。然后将这个状态的部分作为属性传递给组件，当组件被渲染时。状态必须存在于某个地方，在这种情况下，它在组件之外。我将在下一节中继续讨论这个话题，届时你将学习如何实现无状态的功能组件。

# 无状态组件

到目前为止，在本书中你所见过的组件都是扩展了基础的`Component`类的类。现在是时候学习 React 中的**功能性组件**了。在本节中，你将通过实现一个功能性组件来学习什么是功能性组件。然后，你将学习如何为无状态的功能性组件设置默认属性值。

# 纯函数组件

一个功能性的 React 组件就像它听起来的那样——一个函数。想象一下你见过的任何 React 组件的`render()`方法。这个方法本质上就是组件。一个功能性的 React 组件的工作是返回 JSX，就像基于类的 React 组件一样。不同之处在于，这是一个功能性组件可以做的全部。它没有状态和生命周期方法。

为什么要使用函数组件？这更多是简单性的问题。如果你的组件只渲染一些 JSX 而不做其他事情，那么为什么要使用类，而不是一个函数更简单呢？

**纯函数**是没有副作用的函数。也就是说，给定一组参数调用函数时，函数总是产生相同的输出。这对于 React 组件是相关的，因为给定一组属性，更容易预测渲染的内容会是什么。总是返回相同值的函数在测试时也更容易。

现在让我们看一个函数组件：

```jsx
import React from 'react'; 

// Exports an arrow function that returns a 
// "<button>" element. This function is pure 
// because it has no state, and will always 
// produce the same output, given the same 
// input. 
export default ({ disabled, text }) => ( 
  <button disabled={disabled}>{text}</button> 
); 
```

简洁明了，不是吗？这个函数返回一个`<button>`元素，使用传入的属性作为参数（而不是通过`this.props`访问它们）。这个函数是纯的，因为如果传入相同的`disabled`和`text`属性值，就会渲染相同的内容。现在，让我们看看如何渲染这个组件：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

// "MyButton" is a function, instead of a
// "Component" subclass.
import MyButton from './MyButton';

// Renders two "MyButton" components. We only need
// the "first" and "second" properties from the
// props argument by destructuring it.
function render({ first, second }) {
  renderJSX(
    <main>
      <MyButton text={first.text} disabled={first.disabled} />
      <MyButton text={second.text} disabled={second.disabled} />
    </main>,
    document.getElementById('root')
  );
}

// Reders the components, passing in property data.
render({
  first: {
    text: 'First Button',
    disabled: false
  },
  second: {
    text: 'Second Button',
    disabled: true
  }
});
```

从 JSX 的角度来看，基于类和基于函数的 React 组件没有任何区别。无论是使用类还是函数语法声明的组件，JSX 看起来都是一样的。

惯例是使用箭头函数语法来声明功能性的 React 组件。然而，如果传统的 JavaScript 函数语法更适合你的风格，也是完全有效的。

渲染后的 HTML 如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/ce97845e-5e19-4a46-953d-82a3e96c2e96.png)

# 函数组件中的默认值

函数组件很轻量；它们没有任何状态或生命周期。然而，它们支持一些**元数据**选项。例如，你可以像类组件一样指定函数组件的默认属性值。下面是一个示例：

```jsx
import React from 'react';

// The functional component doesn't care if the property
// values are the defaults, or if they're passed in from
// JSX. The result is the same.
const MyButton = ({ disabled, text }) => (
  <button disabled={disabled}>{text}</button>
);

// The "MyButton" constant was created so that we could
// attach the "defaultProps" metadata here, before
// exporting it.
MyButton.defaultProps = {
  text: 'My Button',
  disabled: false
};

export default MyButton;

```

`defaultProps`属性是在函数上定义的，而不是在类上。当 React 遇到具有此属性的函数组件时，它知道如果没有通过 JSX 提供默认值，就会传递默认值。

# 容器组件

在这一部分，你将学习**容器组件**的概念。这是一个常见的 React 模式，它汇集了你所学到的关于状态和属性的许多概念。

容器组件的基本原则很简单：不要将数据获取与渲染数据的组件耦合在一起。容器负责获取数据并将其传递给其子组件。它包含负责渲染数据的组件。

这个模式的目的是让你能够在一定程度上实现**可替换性**。例如，一个容器可以替换它的子组件。或者，一个子组件可以在不同的容器中使用。让我们看看容器模式的实际应用，从容器本身开始：

```jsx
import React, { Component } from 'react';

import MyList from './MyList';

// Utility function that's intended to mock
// a service that this component uses to
// fetch it's data. It returns a promise, just
// like a real async API call would. In this case,
// the data is resolved after a 2 second delay.
function fetchData() {
  return new Promise(resolve => {
    setTimeout(() => {
      resolve(['First', 'Second', 'Third']);
    }, 2000);
  });
}

// Container components usually have state, so they
// can't be declared as functions.
export default class MyContainer extends Component {
  // The container should always have an initial state,
  // since this will be passed down to child components
  // as properties.
  state = { items: [] };

  // After the component has been rendered, make the
  // call to fetch the component data, and change the
  // state when the data arrives.
  componentDidMount() {
    fetchData().then(items => this.setState({ items }));
  }

  // Renders the container, passing the container
  // state as properties, using the spread operator: "...".
  render() {
    return <MyList {...this.state} />;
  }
}
```

这个组件的工作是获取数据并设置它的状态。每当状态被设置时，`render()`就会被调用。这就是*子组件*的作用。容器的状态被传递给子组件作为属性。接下来让我们来看一下`MyList`组件：

```jsx
import React from 'react';

// A stateless component that expects
// an "items" property so that it can render
// a "<ul>" element.
export default ({ items }) => (
  <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>
);

```

`MyList`是一个期望有一个`items`属性的函数组件。让我们看看容器组件实际上是如何使用的：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyContainer from './MyContainer';

// All we have to do is render the "MyContainer"
// component, since it looks after providing props
// for it's children.
render(<MyContainer />, document.getElementById('root'));
```

容器组件设计将在第五章中更深入地介绍，*Crafting Reusable Components*。这个例子的目的是让你感受一下在 React 组件中状态和属性之间的相互作用。

当你加载页面时，你会在模拟 HTTP 请求需要 3 秒后看到以下内容被渲染出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/26ac6029-21c3-4f11-9b88-6725adf88629.png)

# 提供和消费上下文

随着你的 React 应用程序的增长，它将使用更多的组件。它不仅会有更多的组件，而且你的应用程序的结构将发生变化，使得组件嵌套更深。嵌套在最深层级的组件仍然需要传递数据给它们。从父组件向子组件传递数据并不是什么大问题。挑战在于当你不得不开始使用组件作为传递数据的间接方式时。

对于需要传递到应用程序中任何组件的数据，你可以创建并使用一个上下文。在使用 React 中上下文时，有两个关键概念要记住——提供者和消费者。**上下文提供者**创建数据并确保它对任何 React 组件都可用。**上下文消费者**是一个在上下文中使用这些数据的组件。

你可能会想知道上下文是否只是在 React 应用程序中说全局数据的另一种方式。基本上，这正是上下文的用途。使用 React 的方法将组件与上下文包装在一起比创建全局数据更好，因为你可以更好地控制数据如何流经你的组件。例如，你可以有嵌套的上下文和许多其他高级用例。但现在，让我们只关注简单的用法。

假设您有一些应用程序数据，用于确定给定应用程序功能的权限。这些数据可以从 API 中获取，也可以是硬编码的。无论哪种情况，要求是您不希望通过组件树传递所有这些权限数据。如果权限数据只需存在，供任何需要它的组件使用，那就太好了。

从组件树的顶部开始，让我们看一下`index.js`：

```jsx
import React from 'react';
import { render } from 'react-dom';

import { PermissionProvider } from './PermissionContext';
import App from './App';

render(
  <PermissionProvider>
    <App />
  </PermissionProvider>,
  document.getElementById('root')
);
```

`<App>`组件是`<PermissionProvider>`组件的子组件。这意味着权限上下文已经提供给了`<App>`组件及其所有子组件，一直到树的最底部。让我们看一下定义权限上下文的`PermissionContext.js`模块。

```jsx
import React, { Component, createContext } from 'react';

const { Provider, Consumer } = createContext('permissions');

export class PermissionProvider extends Component {
  state = {
    first: true,
    second: false,
    third: true
  };

  render() {
    return (
      <Provider value={this.state}>{this.props.children}</Provider>
    );
  }
}

const PermissionConsumer = ({ name, children }) => (
  <Consumer>{value => value[name] && children}</Consumer>
);

export { PermissionConsumer };
```

`createContext()`函数用于创建实际的上下文。返回值是一个包含两个组件——`Provider`和`Consumer`的对象。接下来，有一个用于整个应用程序的权限提供者的简单抽象。状态包含组件可能想要使用的实际数据。在这个例子中，如果值为 true，则应该正常显示该功能。如果为 false，则该功能没有权限进行渲染。在这里，状态只设置一次，但由于这是一个常规的 React 组件，您可以像在任何其他组件上设置状态一样设置状态。渲染的值是`<Provider>`组件。这通过`value`属性为任何子组件提供上下文数据。

接下来，有一个用于权限消费者的小抽象。不是让每个需要测试权限的组件一遍又一遍地实现相同的逻辑，`PermissionConsumer`组件可以做到。`<Consumer>`组件的子组件始终是一个以上下文数据作为参数的函数。在这个例子中，`PermissionConsumer`组件有一个`name`属性，用于功能的名称。这与上下文中的值进行比较，如果为 false，则不会渲染任何内容。

现在让我们看一下`App`组件：

```jsx
import React, { Fragment } from 'react';

import First from './First';
import Second from './Second';
import Third from './Third';

export default () => (
  <Fragment>
    <First />
    <Second />
    <Third />
  </Fragment>
);
```

这个组件渲染了三个需要检查权限的功能组件。如果没有 React 的上下文功能，您将不得不通过这个组件将这些数据作为属性传递给每个组件。如果`<First>`有需要检查权限的子组件或孙子组件，相同的属性传递机制可能会变得非常混乱。

现在让我们来看一下`<First>`组件（`<Second>`和`<Third>`几乎完全相同）：

```jsx
import React from 'react';
import { PermissionConsumer } from './PermissionContext';

export default () => (
  <PermissionConsumer name="first">
    <div>
      <button>First</button>
    </div>
  </PermissionConsumer>
);
```

这就是`PermissionConsumer`组件的用法。您只需要为其提供一个`name`属性，如果权限检查通过，则子组件将被渲染。`<PermissionConsumer>`组件可以在任何地方使用，无需传递数据即可使用。以下是这三个组件的渲染输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e83d35dc-0f8a-4cd7-af4f-8b26ba753c59.png)

第二个组件没有被渲染，因为它在`PermissionProvider`组件中的权限被设置为 false。

# 摘要

在本章中，您了解了 React 组件中的状态和属性。您首先定义并比较了这两个概念。然后，您实现了几个 React 组件并操纵了它们的状态。接下来，您通过实现了从 JSX 传递属性值到组件的代码来了解了属性。然后，您了解了容器组件的概念，用于将数据获取与呈现内容解耦。最后，您了解了 React 16 中的新上下文 API 以及如何使用它来避免在组件中引入间接性。

在下一章中，您将学习如何处理 React 组件中的用户事件。

# 测试您的知识

1.  为什么始终初始化组件的状态是个好主意？

1.  因为如果不这样做，当您尝试渲染时，React 将抛出错误。

1.  因为 React 不知道您在组件状态中有什么类型，并且无法优化渲染。

1.  因为如果`render()`方法期望状态值，您需要确保它们始终存在，以避免意外的渲染行为。

1.  什么时候应该使用属性而不是状态？

1.  状态应该只用于可以更改的值。对于其他所有情况，应该使用属性。

1.  尽量避免使用状态。

1.  您应该只使用属性来更新现有状态。

1.  什么是 React 中的上下文？

1.  上下文是您如何将事件处理程序函数传递给应用程序中的不同组件的方法。

1.  上下文用于避免瞬态属性。上下文用于与少数组件共享公共数据。

1.  上下文就像在组件之间共享的状态。

# 进一步阅读

访问以下链接获取更多信息：

+   [`reactjs.org/docs/react-component.html#instance-properties-1`](https://reactjs.org/docs/react-component.html#instance-properties-1)

+   [`reactjs.org/docs/react-without-es6.html#setting-the-initial-state`](https://reactjs.org/docs/react-without-es6.html#setting-the-initial-state)

+   [`reactjs.org/docs/context.html`](https://reactjs.org/docs/context.html)

+   [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_syntax`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_syntax)


# 第四章：事件处理，React 方式

本章的重点是事件处理。React 在处理事件方面有独特的方法：在 JSX 中声明事件处理程序。我将首先看一下在 JSX 中声明特定元素的事件处理程序。然后，您将了解如何绑定处理程序上下文和参数值。接下来，我们将实现内联和高阶事件处理程序函数。

然后您将了解 React 实际上是如何将事件处理程序映射到 DOM 元素的。最后，您将了解 React 传递给事件处理程序函数的合成事件，以及它们如何为性能目的进行池化。

# 声明事件处理程序

在 React 组件中处理事件的不同因素是它是**声明式**的。与 jQuery 相比，你必须编写命令式代码来选择相关的 DOM 元素并将事件处理程序函数附加到它们上。

在 JSX 标记中声明事件处理程序的声明性方法的优势在于它们是 UI 结构的一部分。不必追踪分配事件处理程序的代码是一种心理上的解放。

在本节中，您将编写一个基本的事件处理程序，以便了解在 React 应用程序中找到的声明性事件处理语法。然后，您将学习如何使用通用事件处理程序函数。

# 声明处理程序函数

让我们看一个声明了元素点击事件的基本组件：

```jsx
import React, { Component } from 'react';

export default class MyButton extends Component {
  // The click event handler, there's nothing much
  // happening here other than a log of the event.
  onClick() {
    console.log('clicked');
  }

  // Renders a "<button>" element with the "onClick"
  // event handler set to the "onClick()" method of
  // this component.
  render() {
    return (
      <button onClick={this.onClick}>{this.props.children}</button>
    );
  }
}
```

事件处理程序函数`this.onClick()`被传递给`<button>`元素的`onClick`属性。通过查看这个标记，清楚地知道按钮被点击时将运行什么代码。

请参阅官方的 React 文档，了解支持的事件属性名称的完整列表：[`facebook.github.io/react/docs/`](https://facebook.github.io/react/docs/)。

# 多个事件处理程序

我真的很喜欢声明式事件处理程序语法的一点是，当一个元素分配了多个处理程序时，它很容易阅读。有时，例如，一个元素有两个或三个处理程序。命令式代码很难处理单个事件处理程序，更不用说多个事件处理程序了。当一个元素需要更多处理程序时，它只是另一个 JSX 属性。从代码可维护性的角度来看，这在很大程度上是可扩展的。

```jsx
import React, { Component } from 'react';

export default class MyInput extends Component {
  // Triggered when the value of the text input changes...
  onChange() {
    console.log('changed');
  }

  // Triggered when the text input loses focus...
  onBlur() {
    console.log('blured');
  }

  // JSX elements can have as many event handler
  // properties as necessary.
  render() {
    return <input onChange={this.onChange} onBlur={this.onBlur} />;
  }
}
```

这个`<input>`元素可能有几个更多的事件处理程序，代码仍然可以读得很清楚。

当您不断向组件添加更多事件处理程序时，您会注意到很多事件处理程序都在做相同的事情。接下来，您将学习如何在组件之间共享通用处理程序函数。

# 导入通用处理程序

任何 React 应用程序都可能会为不同组件共享相同的事件处理逻辑。例如，响应按钮点击时，组件应该对项目列表进行排序。这些类型的通用行为应该属于它们自己的模块，以便多个组件可以共享它们。让我们实现一个使用通用事件处理程序函数的组件：

```jsx
import React, { Component } from 'react';

// Import the generic event handler that
// manipulates the state of a component.
import reverse from './reverse';

export default class MyList extends Component {
  state = {
    items: ['Angular', 'Ember', 'React']
  };

  // Makes the generic function specific
  // to this component by calling "bind(this)".
  onReverseClick = reverse.bind(this);

  render() {
    const { state: { items }, onReverseClick } = this;

    return (
      <section>
        {/* Now we can attach the "onReverseClick" handler
            to the button, and the generic function will
            work with this component's state. */}
        <button onClick={onReverseClick}>Reverse</button>
        <ul>{items.map((v, i) => <li key={i}>{v}</li>)}</ul>
      </section>
    );
  }
}
```

让我们从这里开始，逐步了解正在发生的事情，从导入开始。您正在导入一个名为`reverse()`的函数。这是您在`<button>`元素中使用的通用事件处理程序函数。当它被点击时，列表应该反转其顺序。

`onReverseClick`方法实际上调用了通用的`reverse()`函数。它是使用`bind()`来将通用函数的上下文绑定到此组件实例而创建的。

最后，看一下 JSX 标记，您可以看到`onReverseClick()`函数被用作按钮点击的处理程序。

那么，这到底是如何工作的呢？您有一个通用函数，它以某种方式改变了此组件的状态，因为您将上下文绑定到它？嗯，基本上是的，就是这样。现在让我们来看一下通用函数的实现：

```jsx
// Exports a generic function that changes the 
// state of a component, causing it to re-render 
// itself.
export default function reverse() { 
  this.setState(this.state.items.reverse()); 
} 
```

此函数依赖于`this.state`属性和状态中的`items`数组。关键在于状态是通用的；一个应用程序可能有许多具有其状态中的`items`数组的组件。

我们渲染的列表如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3f3ca9fb-eafe-488e-97a6-b4aac6401ce6.png)

如预期的那样，点击按钮会导致列表排序，使用您的通用`reverse()`事件处理程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/79b751c3-0cb7-40ee-8d7f-3d4cc5138f7b.png)

接下来，您将学习如何绑定事件处理程序函数的上下文和参数值。

# 事件处理程序上下文和参数

在这一部分，您将了解绑定其事件处理程序上下文的 React 组件以及如何将数据传递给事件处理程序。对于 React 事件处理程序函数来说，拥有正确的上下文是很重要的，因为它们通常需要访问组件属性或状态。能够对事件处理程序进行参数化也很重要，因为它们不会从 DOM 元素中提取数据。

# 获取组件数据

在本节中，您将了解处理程序需要访问组件属性以及参数值的情况。您将渲染一个自定义列表组件，该组件在列表中的每个项目上都有一个点击事件处理程序。组件将按以下方式传递一个值数组：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyList from './MyList';

// The items to pass to "<MyList>" as a property.
const items = [
  { id: 0, name: 'First' },
  { id: 1, name: 'Second' },
  { id: 2, name: 'Third' }
];

// Renders "<MyList>" with an "items" property.
render(<MyList items={items} />, document.getElementById('root'));

```

列表中的每个项目都有一个`id`属性，用于标识该项目。当用户在 UI 中点击项目时，您需要能够访问此 ID，以便事件处理程序可以处理该项目。以下是`MyList`组件的实现方式：

```jsx
import React, { Component } from 'react';

export default class MyList extends Component {
  constructor() {
    super();

    // We want to make sure that the "onClick()"
    // handler is explicitly bound to this component
    // as it's context.
    this.onClick = this.onClick.bind(this);
  }

  // When a list item is clicked, look up the name
  // of the item based on the "id" argument. This is
  // why we need access to the component through "this",
  // for the properties.
  onClick(id) {
    const { name } = this.props.items.find(i => i.id === id);
    console.log('clicked', `"${name}"`);
  }

  render() {
    return (
      <ul>
        {/* Creates a new handler function with
            the bound "id" argument. Notice that
            the context is left as null, since that
            has already been bound in the
            constructor. */}
        {this.props.items.map(({ id, name }) => (
          <li key={id} onClick={this.onClick.bind(null, id)}>
            {name}
          </li>
        ))}
      </ul>
    );
  }
}
```

渲染列表如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/fd1f7b83-a034-431c-a345-6ccda04e2066.png)

您必须绑定事件处理程序的上下文，这是在构造函数中完成的。如果您查看`onClick()`事件处理程序，您会发现它需要访问组件，以便它可以在`this.props.items`中查找被点击的项目。此外，`onClick()`处理程序需要一个`id`参数。如果您查看此组件的 JSX 内容，您会发现调用`bind()`为列表中的每个项目提供了参数值。这意味着当处理程序响应点击事件时，项目的`id`已经提供了。

这种参数化事件处理的方法与以往的方法有很大不同。例如，我过去常常依赖于从 DOM 元素本身获取参数数据。当你只需要一个事件处理程序时，这种方法效果很好，它可以从事件参数中提取所需的数据。这种方法也不需要通过迭代集合并调用`bind()`来设置几个新函数。

这就是其中的权衡。React 应用程序避免触及 DOM，因为 DOM 实际上只是 React 组件的渲染目标。如果您可以编写不引入对 DOM 元素的显式依赖的代码，那么您的代码将是可移植的。这就是您在此示例中事件处理程序所实现的内容。

如果你担心为集合中的每个项目创建一个新函数会对性能产生影响，那就不用担心。你不会一次在页面上渲染成千上万个项目。对你的代码进行基准测试，如果结果表明`bind()`调用是 React 事件处理程序中最慢的部分，那么你可能有一个非常快速的应用程序。

# 高阶事件处理程序

**高阶函数**是返回新函数的函数。有时，高阶函数也将函数作为参数。在前面的例子中，您使用`bind()`来绑定事件处理程序函数的上下文和参数值。返回事件处理程序函数的高阶函数是另一种技术。这种技术的主要优点是您不需要多次调用`bind()`。相反，您只需在要将参数绑定到函数的位置调用该函数。让我们看一个示例组件：

```jsx
import React, { Fragment, Component } from 'react';

export default class App extends Component {
  state = {
    first: 0,
    second: 0,
    third: 0
  };

  // This function is defined as an arrow function, so "this" is
  // lexically-bound to this component. The name argument is used
  // by the function that's returned as the event handler in the
  // computed property name.
  onClick = name => () => {
    this.setState(state => ({
      ...state,
      [name]: state[name] + 1
    }));
  };

  render() {
    const { first, second, third } = this.state;

    return (
      <Fragment>
        {/* By calling this.onClick() and supplying an argument value,
            you're creating a new event handler function on the fly. 
       */}
        <button onClick={this.onClick('first')}>First {first}</button>
        <button onClick={this.onClick('second')}>
          Second {second}
        </button>
        <button onClick={this.onClick('third')}>Third {third}</button>
      </Fragment>
    );
  }
}
```

该组件呈现三个按钮，并具有三个状态片段-每个按钮的计数器。`onClick()`函数会自动绑定到组件上下文，因为它被定义为箭头函数。它接受一个`name`参数并返回一个新函数。返回的函数在调用时使用这个`name`值。它使用计算属性语法（`[]`内的变量）来增加给定名称的状态值。在每个按钮被点击几次后，该组件内容如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/41bea184-c17d-446a-b4e5-17fbdf0c91cc.png)

# 内联事件处理程序

将处理程序函数分配给 JSX 属性的典型方法是使用**命名**函数。但是，有时您可能想要使用**内联**函数。这是通过直接将**箭头**函数分配给 JSX 标记中的事件属性来完成的：

```jsx
import React, { Component } from 'react';

export default class MyButton extends Component {
  // Renders a button element with an "onClick()" handler.
  // This function is declared inline with the JSX, and is
  // useful in scenarios where you need to call another
  // function.
  render() {
    return (
      <button onClick={e => console.log('clicked', e)}>
        {this.props.children}
      </button>
    );
  }
}

```

像这样内联事件处理程序的主要用途是当您有一个静态参数值要传递给另一个函数时。在这个例子中，您正在使用字符串`clicked`调用`console.log()`。您可以通过在 JSX 标记之外创建一个使用`bind()`创建新函数，或者使用高阶函数来为此目的设置一个特殊函数。但是，您将不得不再想一个新的函数名称。有时内联更容易。

# 将处理程序绑定到元素

当您将事件处理程序函数分配给 JSX 中的元素时，React 实际上并没有将事件侦听器附加到底层 DOM 元素上。相反，它将函数添加到内部函数映射中。页面上的文档有一个单一的事件侦听器。当事件通过 DOM 树冒泡到文档时，React 处理程序会检查是否有匹配的处理程序。该过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/dd1ebd5b-d2b9-49e7-ba39-38152fd442b0.png)

你可能会问，为什么 React 要费这么大的劲？这与我在过去几章中一直在讲的原则相同；尽可能将声明式 UI 结构与 DOM 分开。

例如，当渲染新组件时，其事件处理程序函数只是添加到 React 维护的内部映射中。当触发事件并且它命中`document`对象时，React 将事件映射到处理程序。如果找到匹配项，它会调用处理程序。最后，当 React 组件被移除时，处理程序只是从处理程序列表中移除。

这些 DOM 操作实际上都没有触及 DOM。它都是由单个事件侦听器抽象出来的。这对性能和整体架构都是有利的（保持渲染目标与应用程序代码分开）。

# 合成事件对象

当您使用原生的`addEventListener()`函数将事件处理程序函数附加到 DOM 元素时，回调函数将会传递一个事件参数。React 中的事件处理程序函数也会传递一个事件参数，但它不是标准的`Event`实例。它被称为`SyntheticEvent`，它是原生事件实例的简单包装。

在 React 中，合成事件有两个目的：

+   提供一致的事件接口，规范浏览器的不一致性

+   合成事件包含传播所需的信息

以下是在 React 组件上下文中合成事件的示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/78ee36b3-8721-44a7-8be9-3bb2a2240db4.png)

在下一节中，您将看到这些合成事件是如何为了性能原因而进行池化的，以及这对异步代码的影响。

# 事件池化

用原生事件实例包装的一个挑战是可能会导致性能问题。每个创建的合成事件包装器最终都需要被垃圾回收，这在 CPU 时间方面可能是昂贵的。

当垃圾收集器运行时，您的 JavaScript 代码将无法运行。这就是为什么要节约内存；频繁的垃圾收集意味着对响应用户交互的代码的 CPU 时间较少。

例如，如果您的应用程序只处理少量事件，这可能并不重要。但即使按照适度的标准，应用程序也会响应许多事件，即使处理程序实际上并不对其执行任何操作。如果 React 不断地必须分配新的合成事件实例，这就成了一个问题。

React 通过分配**合成实例池**来解决这个问题。每当触发事件时，它都会从池中取出一个实例并填充其属性。当事件处理程序运行结束时，合成事件实例将被释放回池中，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d3773e6e-17f6-44b0-a5f8-37103058ff30.png)

这可以防止在触发大量事件时垃圾收集器频繁运行。池保留对合成事件实例的引用，因此它们永远不会被垃圾收集。React 也不需要分配新实例。

然而，有一个需要注意的地方。它涉及在事件处理程序的异步代码中访问合成事件实例。这是一个问题，因为一旦处理程序运行结束，实例就会返回到池中。当它返回到池中时，它的所有属性都被清除。下面是一个示例，展示了这种情况可能出错的情况：

```jsx
import React, { Component } from 'react'; 

// Mock function, meant to simulate fetching 
// data asynchronously from an API. 
function fetchData() { 
  return new Promise((resolve) => { 
    setTimeout(() => { 
      resolve(); 
    }, 1000); 
  }); 
} 

export default class MyButton extends Component { 
  onClick(e) { 
    // This works fine, we can access the DOM element 
    // through the "currentTarget" property. 
    console.log('clicked', e.currentTarget.style); 

    fetchData().then(() => { 
      // However, trying to access "currentTarget" 
      // asynchronously fails, because it's properties 
      // have all been nullified so that the instance 
      // can be reused. 
      console.log('callback', e.currentTarget.style); 
    }); 
  } 

  render() { 
    return ( 
      <button onClick={this.onClick}> 
        {this.props.children} 
      </button> 
    ); 
  } 
} 
```

第二次调用`console.log()`试图从异步回调中访问合成事件属性，直到事件处理程序完成才运行，这导致事件清空其属性。这会导致警告和`undefined`值。

这个例子的目的是说明当您编写与事件交互的异步代码时，事情可能会出错。千万不要这样做！

# 摘要

本章向您介绍了 React 中的事件处理。React 和其他事件处理方法的关键区别在于处理程序是在 JSX 标记中声明的。这使得追踪哪些元素处理哪些事件变得更加简单。

您学到了在单个元素上有多个事件处理程序是添加新的 JSX 属性的问题。接下来，您学到了共享处理通用行为的事件处理函数是一个好主意。如果事件处理程序函数需要访问组件属性或状态，则上下文可能很重要。您了解了绑定事件处理程序函数上下文和参数值的各种方法。这些包括调用`bind()`和使用高阶事件处理程序函数。

然后，您了解了内联事件处理程序函数及其潜在用途，以及 React 实际上是如何将单个 DOM 事件处理程序绑定到文档对象的。合成事件是包装本机事件的抽象，您了解了它们为什么是必要的以及它们如何被池化以实现高效的内存消耗。

在下一章中，您将学习如何创建可重用于各种目的的组件。

# 测试你的知识

1.  什么使 React 中的事件处理程序是声明式的？

1.  任何事件处理程序函数都是声明式的

1.  React 事件处理程序被声明为组件 JSX 的一部分

1.  React 事件处理程序不是声明式的

1.  高阶事件处理程序函数的常见用途是什么？

1.  当你有几个处理相同事件的组件时，你可以使用高阶函数将被点击的项目的 ID 绑定到处理程序函数

1.  应该尽可能使用高阶函数作为 React 事件处理程序函数

1.  当你不确定事件处理程序需要什么数据时，高阶函数允许你传递任何你需要的东西

1.  你能把内联函数传递给事件属性吗？

1.  是的。当事件处理程序是简单的一行代码时，这是首选。

1.  不。你应该总是将事件处理程序函数声明为方法或绑定函数。

1.  为什么 React 使用事件实例池而不是在每个事件中创建新实例？

1.  React 不使用事件池

1.  如果不这样做，最终会耗尽内存，因为这些对象永远不会被删除

1.  为了避免在短时间内触发大量事件时调用垃圾收集器来删除未使用的事件实例

# 进一步阅读

访问以下链接以获取更多信息：

+   [`reactjs.org/docs/handling-events.html`](https://reactjs.org/docs/handling-events.html)
