# React17 设计模式最佳实践（一）

> 原文：[`zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F`](https://zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

React 是一个开源的、适应性强的 JavaScript 库，用于从称为组件的小型、独立的部分构建复杂的用户界面。本书将帮助您有效地使用 React，使您的应用程序更加灵活、易于维护，并提高其性能，同时通过提高速度而不影响质量来提高工作流程的效率。

您将首先了解 React 的内部工作原理，然后逐渐转向编写可维护和清晰的代码。接下来的章节将向您展示如何构建可在整个应用程序中重复使用的组件，如何组织应用程序以及如何创建真正有效的表单。之后，您将通过探索如何为 React 组件添加样式并优化它们，使应用程序更快、更具响应性。最后，您将学习如何有效地编写测试，并学习如何为 React 及其生态系统做出贡献。

阅读本书结束时，您将能够避免试错和开发头疼的过程，而是拥有有效构建和部署真实 React web 应用程序所需的技能。

# 本书适合对象

本书适用于希望增进对 React 的理解并将其应用于实际应用程序开发的 Web 开发人员。假定具有中级水平的 React 和 JavaScript 经验。

# 本书内容包括

*第一章*，*开始使用 React*，涵盖了一些对于后续内容至关重要且对于日常使用 React 至关重要的基本概念。我们将学习如何编写声明性代码，并清楚地了解我们创建的组件与 React 用于在屏幕上显示实例的元素之间的区别。然后，我们将了解将逻辑和模板放在一起的选择背后的原因，以及为什么这个不受欢迎的决定对 React 来说是一个巨大的胜利。我们将了解在 JavaScript 生态系统中感到疲劳是常见的原因，但我们也将看到如何通过迭代方法来避免这些问题。最后，我们将了解新的`create-react-app` CLI 是什么，有了它，我们就准备好开始编写一些真正的代码了。

第二章《清理您的代码》教会您大量关于 JSX 的工作原理以及如何在我们的组件中正确使用它。我们从语法的基础开始，建立坚实的知识基础，使我们能够掌握 JSX 及其特性。我们将看看 ESLint 及其插件如何帮助我们更快地发现问题，并强制执行代码库中的一致风格指南。最后，我们将学习函数式编程的基础知识，以理解在编写 React 应用程序时使用的重要概念。现在我们的代码已经整洁，我们准备深入研究 React，并学习如何编写真正可重用的组件。

第三章《React Hooks》教会您如何使用新的 React Hooks 以及如何构建自己的 Hooks。

第四章《探索流行的组合模式》解释了如何组合我们的可重用组件并使它们有效地进行通信。然后，我们将介绍 React 中一些最有趣的组合模式。我们还将看到 React 如何尝试通过混合解决组件之间共享功能的问题。然后，我们将学习如何处理上下文，而无需将我们的组件与其耦合在一起，这要归功于 HOCs。最后，我们将看到如何通过遵循“FunctionAsChild”模式来动态组合组件。

第五章《使用真实项目理解 GraphQL》解释了如何在一个真实项目中使用 GraphQL 查询和变异，您将学习如何使用 GraphQL、JWT 令牌和 Node.js 构建身份验证系统。

第六章《数据管理》介绍了一些常见的模式，以使子组件和父组件使用回调进行通信。然后，我们将学习如何使用一个共同的父组件来在不直接连接的组件之间共享数据。我们将从一个简单的组件开始，它将能够从 GitHub 加载数据，然后我们将使用 HOCs 使其可重用，然后继续学习如何使用`react-refetch`将数据获取模式应用到我们的组件中，避免重复造轮子。最后，我们将学习如何使用新的 Context API。

第七章，“为浏览器编写代码”，探讨了当我们使用 React 针对浏览器时可以做的不同事情，从表单创建到事件；从动画到 SVG。React 为我们提供了一种声明性的方式来管理我们在创建 Web 应用程序时需要处理的所有方面。React 以一种我们可以执行命令式操作的方式让我们访问实际的 DOM 节点，这在我们需要将 React 与现有的命令式库集成时非常有用。

第八章，“让您的组件看起来漂亮”，研究了为什么常规 CSS 可能不是样式化组件的最佳方法，以及各种替代解决方案。在本章中，我们将学习在 React 中使用内联样式，以及这种方法的缺点，可以通过使用 Radium 库来解决。最后，将介绍一个新的库`styled-components`，以及它提供的现代方法的概要。

第九章，“为了乐趣和利润进行服务器端渲染”，邀请您按照一定的步骤设置服务器端渲染的应用程序。到本章末，我们将能够构建一个通用应用程序，并了解其利弊。

第十章，“改善您的应用程序的性能”，快速查看了 React 性能的基本组件，以及我们如何使用一些 API 来帮助库找到更新 DOM 的最佳路径，而不会降低用户体验。我们还将学习如何使用一些工具来监视性能并找到瓶颈，这些工具可以导入到我们的代码库中。最后，我们将看到不可变性和*PureComponent*是构建快速 React 应用程序的完美工具。

第十一章，“测试和调试”，解释了为什么测试我们的应用程序很重要，以及我们可以使用哪些最流行的工具来使用 React 创建测试的概要。我们还将学习建立一个 Jest 环境，使用 Enzyme 测试组件，以及讨论 Enzyme 是什么以及为什么它对于测试 React 应用程序是必不可少的。通过涵盖所有这些主题，到本章末，我们将能够从头开始创建一个测试环境，并为我们应用程序的组件编写测试。

*第十二章*，*React Router*，讨论了一些步骤，将帮助我们在应用程序中实现 React Router。随着我们完成每个部分，我们将添加动态路由，并了解 React Router 的工作原理。我们将学习如何安装和配置 React Router，以及向路由添加组件、exact 属性和参数。

*第十三章*，*应避免的反模式*，讨论了在使用 React 时应避免的常见反模式。我们将研究为什么改变状态对性能有害。选择正确的键和帮助调和器也将在本章中讨论，以及为什么在 DOM 元素上扩展 props 是不好的，以及我们如何避免这样做。

*第十四章*，*部署到生产环境*，涵盖了如何在 Google Cloud 上的 Ubuntu 服务器上使用 Node.js 和 nginx 部署我们的 React 应用程序，以及配置 nginx、PM2 和域。还将介绍如何实施 CircleCI 进行持续集成。

*第十五章*，*下一步*，演示了我们如何通过提出问题和拉取请求来为 React 库做出贡献，并解释了为什么重要的是回馈社区并分享我们的代码。最后，我们将介绍在推送开源代码时需要牢记的最重要的方面，以及如何发布一个`npm`包以及如何使用语义版本控制。

# 为了充分利用本书

要精通 React，您需要对 JavaScript 和 Node.js 有基本的了解。本书主要针对 Web 开发人员，在撰写时，对读者做出了以下假设：

+   读者知道如何安装最新版本的 Node.js。

+   读者是一名中级开发人员，能够理解 JavaScript ES6 语法。

+   读者对 CLI 工具和 Node.js 语法有一定的经验。

## 下载示例代码文件

您可以从 GitHub 上的[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition)下载本书的示例代码文件。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码捆绑包可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

## 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781800560444_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781800560444_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。以下是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```jsx
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
const name = `Carlos`
const multilineHtml = `<p>
  This is a multiline string
 </p>`
console.log(`Hi, my name is ${name}`)
```

任何命令行输入或输出都以以下方式编写：

```jsx
npm install -g @babel/preset-env @babel/preset-react 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。以下是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：你好，React！

本节的目标是向您解释声明式编程的基本概念，React 元素以及如何使用 TypeScript。

在本节中，我们将涵盖以下章节：

+   *第一章，用 React 迈出第一步*

+   *第二章，整理你的代码*


# 第一章：用 React 迈出第一步

你好，读者们！

本书假定您已经知道 React 是什么以及它可以为您解决什么问题。您可能已经用 React 编写了一个小/中型应用程序，并且希望提高自己的技能并回答所有未解决的问题。您应该知道 React 由 Facebook 的开发人员和 JavaScript 社区内的数百名贡献者维护。React 是创建 UI 的最受欢迎的库之一，由于其与**文档对象模型**（**DOM**）的智能工作方式而闻名。它带有 JSX，这是一种在 JavaScript 中编写标记的新语法，这需要您改变有关关注点分离的思维。它具有许多很酷的功能，例如服务器端渲染，这使您有能力编写通用应用程序。

在本章中，我们将介绍一些基本概念，这些概念对于有效使用 React 至关重要，但对于初学者来说也足够简单易懂：

+   命令式编程和声明式编程之间的区别

+   React 组件及其实例，以及 React 如何使用元素来控制 UI 流程

+   React 如何改变了我们构建 Web 应用程序的方式，强制执行了一种不同的关注点分离的新概念，以及其不受欢迎设计选择背后的原因

+   为什么人们感到 JavaScript 疲劳，以及在接近 React 生态系统时开发人员常犯的最常见错误，您可以做些什么来避免这些错误

+   TypeScript 如何改变了游戏

# 技术要求

为了遵循本书，您需要具有一些使用终端运行几个 Unix 命令的最小经验。此外，您需要安装 Node.js。您有两个选项。第一个是直接从官方网站[`nodejs.org`](https://nodejs.org)下载 Node.js，第二个选项（推荐）是从[`github.com/nvm-sh/nvm`](https://github.com/nvm-sh/nvm)安装**Node Version Manager**（**NVM**）。

如果您决定使用 NVM，您可以安装任何您想要的 Node.js 版本，并使用`nvm install`命令切换版本：

```jsx
# "node" is an alias for the latest version:
nvm install node

# You can also install a global version of node (will install the latest from that version):
nvm install 10
nvm install 9
nvm install 8
nvm install 7
nvm install 6

# Or you can install a very specific version:
nvm install 6.14.3
```

安装了不同版本后，您可以使用`nvm use`命令切换它们：

```jsx
nvm use node # for latest version
nvm use 10
nvm use 6.14.3
```

最后，您可以通过运行以下命令指定默认的`node`版本：

```jsx
nvm alias default node
nvm alias default 10
nvm alias default 6.14.3
```

简而言之，以下是完成本章所需的要求列表：

+   **Node.js (12+)**: [`nodejs.org`](https://nodejs.org)

+   **NVM**：[`github.com/nvm-sh/nvm`](https://github.com/nvm-sh/nvm)

+   **VS Code**：[`code.visualstudio.com`](https://code.visualstudio.com)

+   **TypeScript**：[`www.npmjs.com/package/typescript`](https://www.npmjs.com/package/typescript)

您可以在本书的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition)。

# 区分声明性和命令式编程

当阅读 React 文档或关于 React 的博文时，你肯定会遇到“**声明性**”这个术语。React 之所以如此强大的原因之一是它强制执行声明性编程范式。

因此，要精通 React，了解声明性编程的含义以及命令式和声明式编程之间的主要区别是至关重要的。最简单的方法是将命令式编程视为描述事物如何工作的方式，将声明式编程视为描述你想要实现的方式。

进入酒吧喝啤酒是命令式世界中的一个现实例子，通常你会给酒吧员以下指示：

1.  找一个玻璃杯并从架子上拿下来。

1.  把玻璃杯放在龙头下面。

1.  拉下把手直到玻璃杯满了。

1.  递给我玻璃杯。

在声明性世界中，你只需要说“我可以要一杯啤酒吗？”

声明性方法假设酒吧员已经知道如何倒啤酒，这是声明性编程工作方式的一个重要方面。

让我们来看一个 JavaScript 的例子。在这里，我们将编写一个简单的函数，给定一个小写字符串数组，返回一个相同字符串的大写数组：

```jsx
toUpperCase(['foo', 'bar']) // ['FOO', 'BAR']
```

解决问题的命令式函数将实现如下：

```jsx
const toUpperCase = input => { 
  const output = []

  for (let i = 0; i < input.length; i++) { 
    output.push(input[i].toUpperCase())
  } 

  return output
}
```

首先，创建一个空数组来包含结果。然后，函数循环遍历输入数组的所有元素，并将大写值推入空数组中。最后，返回输出数组。

声明性解决方案如下：

```jsx
const toUpperCase = input => input.map(value => value.toUpperCase())
```

输入数组的项目被传递给一个`map`函数，该函数返回一个包含大写值的新数组。有一些重要的区别需要注意：前面的例子不够优雅，需要更多的努力才能理解。后者更简洁，更易读，在大型代码库中会产生巨大的差异，可维护性至关重要。

另一个值得一提的方面是，在声明式的例子中，无需使用变量，也无需在执行过程中更新它们的值。声明式编程倾向于避免创建和改变状态。

最后一个例子，让我们看看 React 作为声明式的含义。我们将尝试解决的问题是 Web 开发中的常见任务：创建一个切换按钮。

想象一个简单的 UI 组件，比如一个切换按钮。当您点击它时，如果之前是灰色（关闭），它会变成绿色（打开），如果之前是绿色（打开），它会变成灰色（关闭）。

这样做的命令式方式如下：

```jsx
const toggleButton = document.querySelector('#toggle')

toogleButton.addEventListener('click', () => {
  if (toggleButton.classList.contains('on')) {
    toggleButton.classList.remove('on')
    toggleButton.classList.add('off')
  } else {
    toggleButton.classList.remove('off')
    toggleButton.classList.add('on')
  }
})
```

由于需要改变类的所有指令，这是命令式的。相比之下，使用 React 的声明式方法如下：

```jsx
// To turn on the Toggle
<Toggle on />

// To turn off the toggle
<Toggle />
```

在声明式编程中，开发人员只描述他们想要实现的内容，无需列出所有步骤来使其工作。React 提供声明式方法使其易于使用，因此生成的代码简单，通常会导致更少的错误和更易维护性。

在下一节中，您将了解 React 元素的工作原理，并且将更多地了解`props`如何在 React 组件中传递。

# React 元素的工作原理

本书假设您熟悉组件及其实例，但如果您想有效地使用 React，还有另一个对象您应该了解——元素。

每当您调用`createClass`，扩展`Component`或声明一个无状态函数时，您都在创建一个组件。React 在运行时管理所有组件的实例，并且在给定时间点内可以存在同一组件的多个实例。

如前所述，React 遵循声明式范式，无需告诉它如何与 DOM 交互；您声明要在屏幕上看到什么，React 会为您完成这项工作。

正如你可能已经经历过的那样，大多数其他 UI 库的工作方式正好相反：它们将保持界面更新的责任留给开发人员，开发人员必须手动管理 DOM 元素的创建和销毁。

为了控制 UI 流程，React 使用一种特殊类型的对象，称为**元素**，它描述了在屏幕上显示什么。这些不可变的对象与组件及其实例相比要简单得多，并且只包含严格需要表示界面的信息。

以下是一个元素的示例：

```jsx
  { 
    type: Title, 
    props: { 
      color: 'red', 
      children: 'Hello, Title!' 
    } 
  }
```

元素有`type`，这是最重要的属性，还有一些属性。还有一个特殊的属性，称为`children`，它是可选的，代表元素的直接后代。

`type`很重要，因为它告诉 React 如何处理元素本身。如果`type`是一个字符串，那么该元素代表一个 DOM 节点，而如果`type`是一个函数，那么该元素是一个组件。

DOM 元素和组件可以相互嵌套，以表示渲染树：

```jsx
  { 
    type: Title, 
    props: { 
      color: 'red', 
      children: { 
        type: 'h1', 
        props: { 
          children: 'Hello, H1!' 
        } 
      } 
    } 
  }
```

当元素的类型是一个函数时，React 调用该函数，传递`props`以获取底层元素。它继续对结果进行相同的递归操作，直到获得一个 DOM 节点树，React 可以在屏幕上渲染。这个过程称为**协调**，它被 React DOM 和 React Native 用来创建各自平台的 UI。

React 是一个改变游戏规则的技术，所以一开始，React 的语法可能对你来说很奇怪，但一旦你理解了它的工作原理，你会喜欢它，为此，你需要忘掉你到目前为止所知道的一切。

# 忘掉一切

第一次使用 React 通常需要开放的思维，因为这是一种设计 Web 和移动应用程序的新方式。React 试图创新我们构建 UI 的方式，打破了大多数众所周知的最佳实践。

在过去的二十年里，我们学到了关注点的分离是重要的，并且我们曾经认为这是将逻辑与模板分离。我们的目标一直是将 JavaScript 和 HTML 写在不同的文件中。已经创建了各种模板解决方案来帮助开发人员实现这一目标。

问题是，大多数时候，这种分离只是一种幻觉，事实上 JavaScript 和 HTML 是紧密耦合的，无论它们在哪里。

让我们看一个模板的例子：

```jsx
{{#items}} 
  {{#first}} 
    <li><strong>{{name}}</strong></li> 
  {{/first}} 
 {{#link}} 
    <li><a href="{{url}}">{{name}}</a></li> 
  {{/link}} 
{{/items}}
```

前面的片段摘自 Mustache 网站，这是最流行的模板系统之一。

第一行告诉 Mustache 循环遍历一组项目。在循环内部，有一些条件逻辑来检查`＃first`和`＃link`属性是否存在，并根据它们的值呈现不同的 HTML 片段。变量用花括号括起来。

如果您的应用程序只需要显示一些变量，模板库可能是一个很好的解决方案，但当涉及开始处理复杂的数据结构时，情况就会改变。模板系统及其**特定领域语言**（**DSL**）提供了一组功能，并试图提供一个真正编程语言的功能，但没有达到相同的完整性水平。正如示例所示，模板高度依赖于它们从逻辑层接收的模型来显示信息。

另一方面，JavaScript 与模板呈现的 DOM 元素进行交互，以更新 UI，即使它们是从不同的文件加载的。同样的问题也适用于样式 - 它们在不同的文件中定义，但在模板中引用，并且 CSS 选择器遵循标记的结构，因此几乎不可能更改一个而不破坏另一个，这就是**耦合**的定义。这就是为什么经典的关注点分离最终更多地成为技术分离，这当然不是一件坏事，但它并没有解决任何真正的问题。

React 试图向前迈进一步，将模板放在它们应该在的地方 - 靠近逻辑。它这样做的原因是，React 建议您通过组合称为组件的小模块来组织应用程序。框架不应告诉您如何分离关注点，因为每个应用程序都有自己的关注点，只有开发人员应该决定如何限制其应用程序的边界。

基于组件的方法彻底改变了我们编写 Web 应用程序的方式，这就是为什么传统的关注点分离概念逐渐被更现代的结构所取代的原因。React 强制执行的范式并不新鲜，也不是由其创作者发明的，但 React 已经促使这个概念变得更加流行，并且最重要的是，使其更容易被不同水平的开发人员理解。

渲染 React 组件看起来像这样：

```jsx
return ( 
  <button style={{ color: 'red' }} onClick={this.handleClick}> 
    Click me! 
  </button> 
)
```

我们都同意，开始时似乎有点奇怪，但那只是因为我们不习惯那种语法。一旦我们学会了它，意识到它有多么强大，我们就能理解它的潜力。在逻辑和模板中使用 JavaScript 不仅有助于更好地分离我们的关注点，而且还赋予我们更多的权力和更多的表现力，这正是我们构建复杂 UI 所需要的。

这就是为什么即使在开始时混合 JavaScript 和 HTML 的想法听起来很奇怪，但至关重要的是给 React 5 分钟。开始使用新技术的最佳方法是在一个小的副项目上尝试并看看效果如何。总的来说，正确的方法始终是准备好忘掉一切，如果长期利益值得的话，改变你的思维方式。

还有一个概念是相当有争议的，也很难接受，那就是 React 背后的工程师们试图向社区推动的：也将样式逻辑移至组件内部。最终目标是封装用于创建我们组件的每个单一技术，并根据其领域和功能分离关注点。

这是一个从 React 文档中提取的样式对象的示例：

```jsx
const divStyle = { 
  color: 'white', 
  backgroundImage: `url(${imgUrl})`, 
  WebkitTransition: 'all', // note the capital 'W' here 
  msTransition: 'all' // 'ms' is the only lowercase vendor prefix 
}

ReactDOM.render(<div style={divStyle}>Hello World!</div>, mountNode)
```

这套解决方案中，开发人员使用 JavaScript 来编写他们的样式，被称为`#CSSinJS`，我们将在*第八章《让您的组件看起来美丽》*中对此进行广泛讨论。

在接下来的部分中，我们将看到如何避免 JavaScript 疲劳，这是由运行 React 应用程序所需的大量配置（主要是 webpack）引起的。

# 理解 JavaScript 疲劳

有一种普遍的观点认为，React 由大量的技术和工具组成，如果你想使用它，就不得不处理包管理器、转译器、模块捆绑器和无限的不同库列表。这个想法是如此普遍并且在人们中间共享，以至于它已经被明确定义，并被命名为**JavaScript 疲劳**。

理解这背后的原因并不难。React 生态系统中的所有存储库和库都是使用全新的技术、最新版本的 JavaScript 和最先进的技术和范例制作的。

此外，在 GitHub 上有大量的 React 样板，每个样板都有数十个依赖项，以解决任何问题。很容易认为启动使用 React 需要所有这些工具，但事实远非如此。尽管有这种常见的思维方式，React 是一个非常小的库，可以像以前使用 jQuery 或 Backbone 一样在任何页面（甚至在 JSFiddle 中）使用，只需在页面中包含脚本即可。

有两个脚本是因为 React 被分成了两个包：

+   `react`：实现了库的核心功能

+   `react-dom`：包含所有与浏览器相关的功能

这背后的原因是核心包用于支持不同的目标，比如浏览器中的 React DOM 和移动设备上的 React Native。在单个 HTML 页面中运行 React 应用程序不需要任何包管理器或复杂的操作。您只需下载分发包并自行托管（或使用[`unpkg.com/`](https://unpkg.com/)），就可以在几分钟内开始使用 React 及其功能。

以下是在 HTML 中包含的 URL，以开始使用 React：

+   [`unpkg.com/react@17.0.1/umd/react.production.min.js`](https://unpkg.com/react@17.0.1/umd/react.production.min.js)

+   [`unpkg.com/react-dom@17.0.1/umd/react-dom.production.min.js`](https://unpkg.com/react-dom@17.0.1/umd/react-dom.production.min.js)

如果我们只添加核心 React 库，我们无法使用 JSX，因为它不是浏览器支持的标准语言；但整个重点是从最少的功能集开始，并在需要时添加更多功能。对于简单的 UI，我们可以只使用`createElement`（在 React 17 中为`_jsx`），只有当我们开始构建更复杂的东西时，才能包含转译器以启用 JSX 并将其转换为 JavaScript。一旦应用程序稍微增长，我们可能需要一个路由器来处理不同的页面和视图，我们也可以包含它。

在某些时候，我们可能想要从一些 API 端点加载数据，如果应用程序不断增长，我们将达到需要一些外部依赖来抽象复杂操作的地步。只有在那个时刻，我们才应该引入一个包管理器。然后，到了分离我们的应用程序为单独模块并以正确方式组织我们的文件的时候。在那时，我们应该开始考虑使用模块捆绑器。

遵循这种简单的方法，就不会感到疲劳。从具有 100 个依赖项和数十个我们一无所知的`npm`包的样板开始是迷失的最佳方式。重要的是要注意，每个与编程相关的工作（特别是前端工程）都需要不断学习。网络以惊人的速度发展并根据用户和开发人员的需求进行变化，这是我们的环境自始至终的工作方式，也是使其非常令人兴奋的原因。

随着我们在网络上工作的经验增加，我们学会了不能掌握一切，我们应该找到保持自己更新的正确方法以避免疲劳。我们能够跟上所有新趋势，而不是为了新库而跳进去，除非我们有时间做一个副业项目。

令人惊讶的是，在 JavaScript 世界中，一旦规范被宣布或起草，社区中就会有人将其实现为转译器插件或填充物，让其他人可以在浏览器供应商同意并开始支持之前使用它。

这是使 JavaScript 和浏览器与任何其他语言或平台完全不同的东西。它的缺点是事物变化很快，但只是要找到押注新技术与保持安全之间的正确平衡。

无论如何，Facebook 的开发人员非常关心**开发者体验**（**DX**），他们仔细倾听社区的意见。因此，即使使用 React 并不需要学习数百种不同的工具，他们意识到人们感到疲劳，于是发布了一个 CLI 工具，使创建和运行真正的 React 应用程序变得非常容易。

唯一的要求是使用`node.js/npm`环境，并全局安装 CLI 工具，如下所示：

```jsx
npm install -g create-react-app
```

当可执行文件安装后，我们可以使用它来创建我们的应用程序，传递一个文件夹名称：

```jsx
create-react-app hello-world --template typescript
```

最后，我们进入我们应用程序的文件夹`cd hello-world`，然后运行以下命令：

```jsx
npm start
```

神奇的是，我们的应用程序只依赖一个依赖项，但具有构建完整 React 应用程序所需的所有功能。以下截图显示了使用`create-react-app`创建的应用程序的默认页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/946a0deb-dac3-4f19-ae7e-62b6fb2e7e00.png)

这基本上就是您的第一个 React 应用程序。

# 介绍 TypeScript

**TypeScript**是 JavaScript 的一个有类型的超集，它被编译成 JavaScript，这意味着**TypeScript**是带有一些额外功能的**JavaScript**。TypeScript 是由微软的 Anders Hejlsberg（C#的设计者）设计的，并且是开源的。

让我们看看 TypeScript 的特性以及如何将 JavaScript 转换为 TypeScript。

## TypeScript 特性

本节将尝试总结您应该利用的最重要的特性：

+   **TypeScript 就是 JavaScript**：您编写的任何 JavaScript 代码都将与 TypeScript 一起工作，这意味着如果您已经知道如何基本使用 JavaScript，您基本上已经具备了使用 TypeScript 所需的一切；您只需要学习如何向代码添加类型。最终，所有 TypeScript 代码都会转换为 JavaScript。

+   **JavaScript 就是 TypeScript**：这意味着您可以将任何有效的`.js`文件重命名为`.ts`扩展名，它将可以工作。

+   **错误检查**：TypeScript 编译代码并检查错误，这有助于在运行代码之前突出显示错误。

+   **强类型**：默认情况下，JavaScript 不是强类型的。使用 TypeScript，您可以为所有变量和函数添加类型，甚至可以指定返回值类型。

+   **支持面向对象编程**：它支持诸如类、接口、继承等概念。

## 将 JavaScript 代码转换为 TypeScript

在这一部分，我们将看到如何将一些 JavaScript 代码转换为 TypeScript。

假设我们需要检查一个单词是否是回文。这个算法的 JavaScript 代码如下：

```jsx
function isPalindrome(word) {
  const lowerCaseWord = word.toLowerCase()
  const reversedWord = lowerCaseWord.split('').reverse().join('')

  return lowerCaseWord === reversedWord
}
```

您可以将此文件命名为`palindrome.ts`。

正如您所看到的，我们接收一个`string`变量（`word`），并返回一个`boolean`值，那么这将如何转换为 TypeScript 呢？

```jsx
function isPalindrome(word: string): boolean {
  const lowerCaseWord = word.toLowerCase()
  const reversedWord = lowerCaseWord.split('').reverse().join('')

  return lowerCaseWord === reversedWord
}
```

您可能会想到，我刚刚指定了`string`类型作为`word`，并且将`boolean`类型指定为函数返回值，但现在呢？

如果您尝试使用与字符串不同的某个值运行函数，您将收到 TypeScript 错误：

```jsx
console.log(isPalindrome('Level')) // true
console.log(isPalindrome('Anna')) // true console.log(isPalindrome('Carlos')) // false
console.log(isPalindrome(101)) // TS Error
console.log(isPalindrome(true)) // TS Error
console.log(isPalindrome(false)) // TS Error
```

因此，如果您尝试将数字传递给函数，您将收到以下错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/131bd7c8-9e32-44ab-9c50-650ed2758157.png)

这就是为什么 TypeScript 非常有用，因为它将强制您对代码更加严格和明确。

## 类型

在最后一个示例中，我们看到了如何为函数参数和返回值指定一些原始类型，但您可能想知道如何以更详细的方式描述对象或数组。**类型**可以帮助我们以更好的方式描述我们的对象或数组。例如，假设您想描述一个`User`类型以将信息保存到数据库中：

```jsx
type User = {
  username: string
  email: string
  name: string
  age: number
  website: string
  active: boolean
}

const user: User = {
  username: 'czantany',
  email: 'carlos@milkzoft.com',
  name: 'Carlos Santana',
  age: 33,
  website: 'http://www.js.education',
  active: true
}

// Let's suppose you will insert this data using Sequelize...
models.User.create({ ...user }}
```

如果您忘记添加其中一个节点或在其中一个节点中放入无效值，您将收到以下错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/11bdeec1-e67c-4181-9d37-004b0c1a8057.png)

如果您需要可选节点，您可以在节点名称旁边始终放置`?`，如以下代码块所示：

```jsx
type User = {
  username: string
  email: string
  name: string
  age?: number
  website: string
  active: boolean
}
```

您可以根据需要命名`type`，但遵循的一个良好实践是添加`T`的前缀，因此，例如，`User`类型将变为`TUser`。这样，您可以快速识别它是`type`，并且不会混淆认为它是类或 React 组件。

## 接口

**接口**与类型非常相似，有时开发人员不知道它们之间的区别。接口可用于描述对象或函数签名的形状，就像类型一样，但语法不同：

```jsx
interface User {
  username: string
  email: string
  name: string
  age?: number
  website: string
  active: boolean
}
```

您可以根据需要命名接口，但遵循的一个良好实践是添加`I`的前缀，因此，例如，`User`接口将变为`IUser`。这样，您可以快速识别它是接口，而不会混淆认为它是类或 React 组件。

接口也可以扩展、实现和合并。

### 扩展

接口或类型也可以扩展，但语法将有所不同，如以下代码块所示：

```jsx
// Extending an interface
interface IWork {
  company: string
  position: string
}

interface IPerson extends IWork {
  name: string
  age: number
}

// Extending a type
type TWork = {
  company: string
  position: string
}

type TPerson = TWork & {
  name: string
  age: number
}

// Extending an interface into a type
interface IWork {
  company: string
  position: string
}

type TPerson = IWork & {
  name: string
  age: number
}
```

如您所见，通过使用`&`字符，您可以扩展类型，而使用`extends`关键字扩展接口。

### 实现

类可以以完全相同的方式实现接口或类型别名。但它不能实现（或扩展）命名为联合类型的类型别名，例如：

```jsx
// Implementing an interface
interface IWork {
  company: string
  position: string
}

class Person implements IWork {
  name: 'Carlos'
  age: 33
}

// Implementing a type
type TWork = {
  company: string
  position: string
}

class Person2 implements TWork {
  name: 'Cristina'
  age: 32
}

// You can't implement a union type
type TWork2 = { company: string; position: string } | { name: string; age: number } class Person3 implements TWork2 {
  company: 'Google'
  position: 'Senior Software Engineer'
}
```

如果您编写该代码，您将在编辑器中收到以下错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/00a5e85f-aca1-4b88-a3a2-d4ea0190bc33.png)

如您所见，您无法实现联合类型。

### 声明合并

与类型不同，接口可以被多次定义，并且将被视为单个接口（所有声明将被合并），如下面的代码块所示：

```jsx
interface IUser {
  username: string
  email: string
  name: string
  age?: number
  website: string
  active: boolean
}

interface IUser {
  country: string
}

const user: IUser = {
  username: 'czantany',
  email: 'carlos@milkzoft.com',
  name: 'Carlos Santana',
  country: 'Mexico',
  age: 33,
  website: 'http://www.js.education',
  active: true
}
```

当您需要通过重新定义相同的接口在不同场景下扩展接口时，这非常有用。

# 总结

在本章中，我们学习了一些对于接下来的书非常重要的基本概念，这些概念对于每天使用 React 非常关键。我们现在知道如何编写声明式代码，并且清楚地理解了我们创建的组件与 React 用来在屏幕上显示它们的实例之间的区别。

我们了解了将逻辑和模板放在一起的选择背后的原因，以及为什么这个不受欢迎的决定对 React 来说是一个巨大的胜利。我们通过了解在 JavaScript 生态系统中感到疲劳是很常见的原因，但我们也看到了如何通过迭代方法来避免这些问题。

我们学会了如何使用 TypeScript 来创建一些基本类型和接口。最后，我们看到了新的 `create-react-app` CLI 是什么，现在我们准备开始编写一些真正的代码。

在下一章中，您将学习如何使用 JSX/TSX 代码，并应用非常有用的配置来改进您的代码风格。


# 第二章：清理您的代码

本章假设您已经有了 JSX 的经验，并且希望提高使用它的技能。要想毫无问题地使用 JSX/TSX，理解其内部工作原理以及构建 UI 的有用工具的原因是至关重要的。

我们的目标是编写干净的 JSX/TSX 代码，维护它，并了解它的来源，它是如何被转换为 JavaScript 的，以及它提供了哪些特性。

在本章中，我们将涵盖以下主题：

+   什么是 JSX，为什么我们应该使用它？

+   Babel 是什么，我们如何使用它来编写现代 JavaScript 代码？

+   JSX 的主要特性以及 HTML 和 JSX 之间的区别

+   以优雅和可维护的方式编写 JSX 的最佳实践

+   linting 以及特别是 ESLint 如何使我们的 JavaScript 代码在应用程序和团队之间保持一致。

+   函数式编程的基础以及为什么遵循函数式范式会让我们编写更好的 React 组件

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

# 使用 JSX

在上一章中，我们看到了 React 如何改变关注点分离的概念，将边界移到组件内部。我们还学习了 React 如何使用组件返回的元素来在屏幕上显示 UI。

现在让我们看看如何在组件内部声明我们的元素。

React 提供了两种定义元素的方式。第一种是使用 JavaScript 函数，第二种是使用 JSX，一种可选的类似 XML 的语法。以下是官方 React.js 网站示例部分的截图（[`reactjs.org/#examples`](https://reactjs.org/#examples)）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/c47b0f53-2804-4466-b2e2-74e4f74880ff.png)

首先，JSX 是人们失败接触 React 的主要原因之一，因为第一次看到主页上的示例并且看到 JavaScript 与 HTML 混合在一起可能对我们大多数人来说都会感到奇怪。

一旦我们习惯了它，我们就会意识到它非常方便，因为它类似于 HTML，并且对于已经在 Web 上创建过 UI 的人来说非常熟悉。开放和闭合标签使得表示嵌套的元素树变得更容易，使用纯 JavaScript 将会变得难以阅读和难以维护。

让我们在以下子章节中更详细地了解 JSX。

## Babel 7

要在我们的代码中使用 JSX（和一些 ES6 的特性），我们必须安装新的 Babel 7。Babel 是一个流行的 JavaScript 编译器，在 React 社区广泛使用。

首先，重要的是清楚地了解它可以为我们解决的问题，以及为什么我们需要在我们的流程中添加一步。原因是我们想要使用语言的特性，这些特性尚未添加到浏览器，我们的目标环境。这些高级特性使我们的代码对开发人员更清晰，但浏览器无法理解和执行它。

解决方案是在 JSX 和 ES6 中编写我们的脚本，当我们准备好发布时，我们将源代码编译成 ES5，这是今天主要浏览器中实现的标准规范。

Babel 可以将 ES6 代码编译成 ES5 JavaScript，还可以将 JSX 编译成 JavaScript 函数。这个过程被称为**转译**，因为它将源代码编译成新的源代码，而不是可执行文件。

在较旧的 Babel 6.x 版本中，您安装了`babel-cli`包，并获得了`babel-node`和`babel-core`，现在一切都分开了：`@babel/core`，`@babel/cli`，`@babel/node`等等。

要安装 Babel，我们需要安装`@babel/core`和`@babel/node`如下：

```jsx
npm install -g @babel/core @babel/node
```

如果您不想全局安装它（开发人员通常倾向于避免这样做），您可以将 Babel 安装到项目中并通过`npm`脚本运行它，但在本章中，全局实例就可以了。

安装完成后，我们可以运行以下命令来编译任何 JavaScript 文件：

```jsx
babel source.js -o output.js
```

Babel 之所以如此强大的原因之一是因为它是高度可配置的。Babel 只是一个将源文件转译为输出文件的工具，但要应用一些转换，我们需要对其进行配置。

幸运的是，有一些非常有用的预设配置，我们可以轻松安装和使用：

```jsx
npm install -g @babel/preset-env @babel/preset-react
```

安装完成后，我们在`root`文件夹中创建一个名为`.babelrc`的配置文件，并将以下行放入其中，告诉 Babel 使用这些预设：

```jsx
{
  "presets": [
    "@babel/preset-env",
    "@babel/preset-react"
  ]
}
```

从这一点开始，我们可以在我们的源文件中编写 ES6 和 JSX，并在浏览器中执行输出文件。

## 创建我们的第一个元素

现在我们的环境已经设置好支持 JSX，我们可以深入最基本的例子：生成一个`div`元素。这是您使用`_jsx`函数创建`div`元素的方式：

```jsx
_jsx('div', {})
```

这是用于创建`div`元素的 JSX：

```jsx
<div />
```

它看起来类似于常规 HTML。

最大的区别在于我们在`.js`文件中编写标记，但重要的是要注意 JSX 只是语法糖，在在浏览器中执行之前会被转译成 JavaScript。

实际上，当我们运行 Babel 时，我们的`<div />`元素被翻译成`_jsx('div', {})`，这是我们在编写模板时应该牢记的事情。

在 React 17 中，`React.createElement('div')`已被弃用，现在内部使用`react/jsx-runtime`来渲染 JSX，这意味着我们将得到类似`_jsx('div', {})`的东西。基本上，这意味着您不再需要导入 React 对象来编写 JSX 代码。

## DOM 元素和 React 组件

使用 JSX，我们可以创建 HTML 元素和 React 组件；唯一的区别是它们是否以大写字母开头。

例如，要渲染一个 HTML 按钮，我们使用`<button />`，而要渲染`Button`组件，我们使用`<Button />`。第一个按钮被转译成如下：

```jsx
_jsx('button', {})
```

第二个被转译成如下：

```jsx
_jsx(Button, {})
```

这里的区别在于，在第一个调用中，我们将 DOM 元素的类型作为字符串传递，而在第二个调用中，我们传递的是组件本身，这意味着它应该存在于作用域中才能工作。

正如您可能已经注意到的，JSX 支持自闭合标签，这对保持代码简洁非常有用，并且不需要我们重复不必要的标签。

## 属性

当您的 DOM 元素或 React 组件具有 props 时，JSX 非常方便。使用 XML 很容易在元素上设置属性：

```jsx
<img src="https://www.js.education/images/logo.png" alt="JS Education" />
```

在 JavaScript 中的等价物如下：

```jsx
_jsx("img", { 
  src: "https://www.js.education/images/logo.png", 
  alt: "JS Education" 
})
```

这样的代码可读性差得多，即使只有几个属性，没有一点推理就很难阅读。

## 子元素

JSX 允许您定义子元素以描述元素树并组合复杂的 UI。一个基本的例子是带有文本的链接，如下所示：

```jsx
<a href="https://js.education">Click me!</a>
```

这将被转译成如下：

```jsx
_jsx( 
  "a", 
  { href: "https://www.js.education" }, 
  "Click me!" 
)
```

我们的链接可以被包含在`div`元素中以满足一些布局要求，实现这一目的的 JSX 片段如下：

```jsx
<div> 
  <a href="https://www.js.education">Click me!</a> 
</div>
```

JavaScript 等价物如下：

```jsx
_jsx( 
  "div", 
  null, 
  _jsx( 
    "a", 
    { href: "https://www.js.education" }, 
    "Click me!" 
  ) 
)
```

现在应该清楚了 JSX 的*类似 XML*的语法如何使一切更易读和易维护，但重要的是要知道我们的 JSX 的 JavaScript 并行对元素的创建有控制。好处是我们不仅限于将元素作为元素的子元素，而是可以使用 JavaScript 表达式，比如函数或变量。

为了做到这一点，我们必须用花括号括起表达式：

```jsx
<div> 
  Hello, {variable}. 
  I'm a {() => console.log('Function')}. 
</div> 
```

同样适用于非字符串属性，如下所示：

```jsx
<a href={this.createLink()}>Click me!</a>
```

如你所见，任何变量或函数都应该用花括号括起来。

## 与 HTML 的不同

到目前为止，我们已经看到了 JSX 和 HTML 之间的相似之处。现在让我们看看它们之间的小差异以及存在的原因。

### 属性

我们必须始终记住 JSX 不是一种标准语言，它被转译成 JavaScript。因此，某些属性无法使用。

例如，我们必须使用`className`代替`class`，并且必须使用`htmlFor`代替`for`，如下所示：

```jsx
<label className="awesome-label" htmlFor="name" />
```

这是因为`class`和`for`在 JavaScript 中是保留字。

### 样式

一个相当重要的区别是`style`属性的工作方式。我们将在*第八章，使您的组件看起来漂亮*中更详细地讨论如何使用它，但现在我们将专注于它的工作方式。

`style`属性不接受 CSS 字符串，而是期望一个 JavaScript 对象，其中样式名称是*驼峰式*的：

```jsx
<div style={{ backgroundColor: 'red' }} />
```

正如你所看到的，你可以将一个对象传递给`style`属性，这意味着你甚至可以将你的样式放在一个单独的变量中。

```jsx
const styles = {
  backgroundColor: 'red'
} 

<div style={styles} /> 
```

这是控制内联样式的最佳方式。

### 根

与 HTML 的一个重要区别是，由于 JSX 元素被转换为 JavaScript 函数，并且在 JavaScript 中不能返回两个函数，所以每当您在同一级别有多个元素时，您被迫将它们包装在一个父元素中。

让我们看一个简单的例子：

```jsx
<div />
<div />
```

这给了我们以下错误：

```jsx
Adjacent JSX elements must be wrapped in an enclosing tag.
```

另一方面，以下内容有效：

```jsx
<div> 
  <div /> 
  <div /> 
</div>
```

以前，React 强制你返回一个包裹在`<div>`元素或任何其他标签中的元素；自 React 16.2.0 以来，可以直接返回一个数组，如下所示：

```jsx
return [
  <li key="1">First item</li>, 
  <li key="2">Second item</li>, 
  <li key="3">Third item</li>
]
```

或者你甚至可以直接返回一个字符串，就像下面的代码块所示：

```jsx
return 'Hello World!'
```

此外，React 现在有一个名为`Fragment`的新功能，它也可以作为元素的特殊包装器。它可以用`React.Fragment`来指定：

```jsx
import { Fragment } from 'react'

return ( 
  <Fragment>
    <h1>An h1 heading</h1> 
    Some text here. 
    <h2>An h2 heading</h2> 
    More text here.
    Even more text here.
  </Fragment>
)
```

或者您可以使用空标签（`<></>`）：

```jsx
return ( 
  <>
    <ComponentA />
    <ComponentB />
    <ComponentC />
  </>
)
```

`Fragment`不会在 DOM 上呈现任何可见的内容；它只是一个辅助标签，用于包装您的 React 元素或组件。

### 空格

有一件事情可能在开始时会有点棘手，再次强调的是，我们应该始终记住 JSX 不是 HTML，即使它具有类似 XML 的语法。JSX 处理文本和元素之间的空格与 HTML 不同，这种方式是违反直觉的。

考虑以下片段：

```jsx
<div> 
  <span>My</span> 
  name is 
  <span>Carlos</span> 
</div>
```

在解释 HTML 的浏览器中，这段代码会给你`My name is Carlos`，这正是我们所期望的。

在 JSX 中，相同的代码将被呈现为`MynameisCarlos`，这是因为三个嵌套的行被转译为`div`元素的单独子元素，而不考虑空格。获得相同输出的常见解决方案是在元素之间明确放置一个空格，如下所示：

```jsx
<div> 
  <span>My</span> 
  {' '}
  name is
  {' '} 
  <span>Carlos</span> 
</div>
```

正如您可能已经注意到的，我们正在使用一个空字符串包裹在 JavaScript 表达式中，以强制编译器在元素之间应用空格。

### 布尔属性

在真正开始之前，还有一些事情值得一提，关于在 JSX 中定义布尔属性的方式。如果您设置一个没有值的属性，JSX 会假定它的值是`true`，遵循与 HTML `disabled`属性相同的行为，例如。

这意味着如果我们想将属性设置为`false`，我们必须明确声明它为 false：

```jsx
<button disabled /> 
React.createElement("button", { disabled: true })
```

以下是另一个布尔属性的例子：

```jsx
<button disabled={false} /> 
React.createElement("button", { disabled: false })
```

这可能在开始时会让人困惑，因为我们可能会认为省略属性意味着`false`，但事实并非如此。在 React 中，我们应该始终明确以避免混淆。

## 扩展属性

一个重要的特性是**扩展属性**运算符（`...`），它来自于 ECMAScript 提案的 rest/spread 属性，非常方便，每当我们想要将 JavaScript 对象的所有属性传递给一个元素时。

减少错误的一种常见做法是不通过引用将整个 JavaScript 对象传递给子级，而是使用它们的原始值，这样可以轻松验证，使组件更健壮和防错。

让我们看看它是如何工作的：

```jsx
const attrs = { 
  id: 'myId',
  className: 'myClass'
}

return <div {...attrs} />
```

前面的代码被转译成了以下内容：

```jsx
var attrs = { 
  id: 'myId',
  className: 'myClass'
} 

return _jsx('div', attrs)
```

## 模板文字

**模板文字**是允许嵌入表达式的字符串文字。您可以使用多行字符串和字符串插值功能。

模板文字由反引号（`` ``）字符而不是双引号或单引号括起来。此外，模板文字可以包含占位符。您可以使用美元符号和大括号（`${expression}`）添加它们：

```jsx
const name = `Carlos`
const multilineHtml = `<p>
 This is a multiline string
 </p>`
console.log(`Hi, my name is ${name}`)
```

## 常见模式

现在我们知道了 JSX 的工作原理并且可以掌握它，我们准备好看看如何按照一些有用的约定和技巧正确使用它。

### 多行

让我们从一个非常简单的开始。如前所述，我们应该更喜欢 JSX 而不是 React 的 `_jsx` 函数的一个主要原因是它的类似 XML 的语法，以及平衡的开放和闭合标签非常适合表示节点树。

因此，我们应该尝试以正确的方式使用它并充分利用它。一个例子如下；每当我们有嵌套元素时，我们应该总是多行： 

```jsx
<div> 
 <Header /> 
 <div> 
 <Main content={...} /> 
  </div> 
</div>
```

这比以下方式更可取：

```jsx
<div><Header /><div><Main content={...} /></div></div>
```

例外情况是如果子元素不是文本或变量等元素。在这种情况下，保持在同一行并避免向标记添加噪音是有意义的，如下所示：

```jsx
<div> 
 <Alert>{message}</Alert> 
  <Button>Close</Button> 
</div>
```

当您在多行上编写元素时，请记住始终将它们包装在括号中。JSX 总是被函数替换，而在新行上编写的函数可能会因为自动分号插入而给您带来意外的结果。例如，假设您从 render 方法中返回 JSX，这就是您在 React 中创建 UI 的方式。

以下示例工作正常，因为 `div` 元素与 `return` 在同一行上：

```jsx
return <div />
```

然而，以下是不正确的：

```jsx
return 
  <div />
```

原因是您将会得到以下结果：

```jsx
return
_jsx("div", null)
```

这就是为什么您必须将语句包装在括号中，如下所示：

```jsx
return ( 
  <div /> 
)
```

### 多属性

在编写 JSX 时常见的问题是元素具有多个属性。一种解决方法是将所有属性写在同一行上，但这会导致我们的代码中出现非常长的行（请参阅下一节了解如何强制执行编码样式指南）。

一种常见的解决方案是将每个属性写在新行上，缩进一级，然后将闭合括号与开放标签对齐：

```jsx
<button 
  foo="bar" 
  veryLongPropertyName="baz" 
  onSomething={this.handleSomething} 
/>
```

### 条件语句

当我们开始使用**条件语句**时，事情变得更有趣，例如，如果我们只想在某些条件匹配时渲染一些组件。我们可以在条件中使用 JavaScript 是一个很大的优势，但在 JSX 中表达条件的方式有很多不同，了解每一种方式的好处和问题对于编写既可读又易于维护的代码是很重要的。

假设我们只想在用户当前登录到我们的应用程序时显示一个注销按钮。

一个简单的起步代码如下：

```jsx
let button

if (isLoggedIn) { 
  button = <LogoutButton />
} 

return <div>{button}</div>
```

这样做是可以的，但不够易读，特别是如果有多个组件和多个条件。

在 JSX 中，我们可以使用内联条件：

```jsx
<div> 
  {isLoggedIn && <LoginButton />} 
</div>
```

这是因为如果条件是`false`，则不会渲染任何内容，但如果条件是`true`，则会调用`LoginButton`的`createElement`函数，并将元素返回以组成最终的树。

如果条件有一个备选项（经典的`if...else`语句），并且我们想要，例如，如果用户已登录则显示一个注销按钮，否则显示一个登录按钮，我们可以使用 JavaScript 的`if...else`语句如下：

```jsx
let button

if (isLoggedIn) { 
  button = <LogoutButton />
} else { 
  button = <LoginButton />
} 

return <div>{button}</div>
```

或者，更好的方法是使用一个使代码更加紧凑的三元条件：

```jsx
<div> 
  {isLoggedIn ? <LogoutButton /> : <LoginButton />} 
</div>
```

你可以在一些流行的代码库中找到三元条件的使用，比如 Redux 的真实世界示例（[`github.com/reactjs/redux/blob/master/examples/real-world/src/components/List.js#L28`](https://github.com/reactjs/redux/blob/master/examples/real-world/src/components/List.js#L28)），在这里，三元条件用于在组件获取数据时显示一个“加载中”标签，或者根据`isFetching`变量的值在按钮内显示“加载更多”：

```jsx
<button [...]> 
  {isFetching ? 'Loading...' : 'Load More'} 
</button>
```

现在让我们看看当事情变得更加复杂时的最佳解决方案，例如，当我们需要检查多个变量以确定是否渲染一个组件时：

```jsx
<div>
  {dataIsReady && (isAdmin || userHasPermissions) && 
    <SecretData />
  }
</div>
```

在这种情况下，使用内联条件是一个好的解决方案，但可读性受到了严重影响。相反，我们可以在组件内创建一个辅助函数，并在 JSX 中使用它来验证条件：

```jsx
const canShowSecretData = () => { 
  const { dataIsReady, isAdmin, userHasPermissions } = props
  return dataIsReady && (isAdmin || userHasPermissions)
} 

return (
  <div> 
    {this.canShowSecretData() && <SecretData />} 
  </div> )
```

正如你所看到的，这种改变使得代码更易读，条件更加明确。如果你在 6 个月后看这段代码，仅仅通过函数名就能清楚地理解。

计算属性也是一样。假设你有两个单一属性用于货币和价值。你可以创建一个函数来创建价格字符串，而不是在 `render` 中创建它：

```jsx
const getPrice = () => { 
  return `${props.currency}${props.value}`
}

return <div>{getPrice()}</div>
```

这样做更好，因为它是隔离的，如果包含逻辑，你可以很容易地测试它。

回到条件语句，其他解决方案需要使用外部依赖。一个很好的做法是尽可能避免外部依赖，以使我们的捆绑包更小，但在这种特殊情况下可能是值得的，因为提高我们模板的可读性是一个很大的胜利。

第一个解决方案是 `render-if`，我们可以通过以下方式安装它：

```jsx
npm install --save render-if
```

然后我们可以在我们的项目中轻松使用它，如下所示：

```jsx
const { dataIsReady, isAdmin, userHasPermissions } = props

const canShowSecretData = renderIf( 
  dataIsReady && (isAdmin || userHasPermissions) 
);

return (
  <div> 
    {canShowSecretData(<SecretData />)} 
  </div> 
);
```

在这里，我们将我们的条件包装在 `renderIf` 函数中。

返回的实用函数可以作为一个接收 JSX 标记的函数来使用，当条件为 `true` 时显示。

一个目标是永远不要在我们的组件中添加太多逻辑。其中一些组件将需要一点逻辑，但我们应该尽量保持它们尽可能简单，这样我们就可以很容易地发现和修复错误。

我们至少应该尽量保持 `renderIf` 方法尽可能干净，为了做到这一点，我们可以使用另一个实用程序库，称为 `react-only-if`，它让我们编写我们的组件，就好像条件总是为 `true` 一样，通过使用**高阶组件**（**HOC**）设置条件函数。

我们将在 *第四章* *探索流行的组合模式* 中广泛讨论 HOCs，但现在，你只需要知道它们是接收一个组件并通过添加一些属性或修改其行为来返回一个增强的组件的函数。

要使用该库，我们需要按照以下方式安装它：

```jsx
npm install --save react-only-if
```

安装完成后，我们可以在我们的应用程序中以以下方式使用它：

```jsx
import onlyIf from 'react-only-if'

const SecretDataOnlyIf = onlyIf(
  ({ dataIsReady, isAdmin, userHasPermissions }) => dataIsReady && 
  (isAdmin || userHasPermissions)
)(SecretData)

const MyComponent = () => (
  <div>
    <SecretDataOnlyIf 
      dataIsReady={...}
      isAdmin={...}
      userHasPermissions={...}
    />
 </div>
)

export default MyComponent
```

正如你在这里看到的，组件本身没有任何逻辑。

我们将条件作为 `onlyIf` 函数的第一个参数传递，当条件匹配时，组件被渲染。

用于验证条件的函数接收组件的 props、state 和 context。

这样，我们就避免了用条件语句污染我们的组件，这样更容易理解和推理。

### 循环

UI 开发中一个非常常见的操作是显示项目列表。在显示列表时，使用 JavaScript 作为模板语言是一个非常好的主意。

如果我们在 JSX 模板中编写一个返回数组的函数，数组的每个元素都会被编译成一个元素。

正如我们之前所看到的，我们可以在花括号中使用任何 JavaScript 表达式，给定一个对象数组，生成一个元素数组的最常见方法是使用`map`。

让我们深入一个真实的例子。假设你有一个用户列表，每个用户都有一个附加的名字属性。

要创建一个无序列表来显示用户，你可以这样做：

```jsx
<ul> 
  {users.map(user => <li>{user.name}</li>)} 
</ul>
```

这段代码非常简单，同时也非常强大，HTML 和 JavaScript 的力量在这里汇聚。

### 控制语句

条件和循环在 UI 模板中是非常常见的操作，你可能觉得使用 JavaScript 的三元运算符或`map`函数来执行它们是错误的。JSX 被构建成只抽象了元素的创建，将逻辑部分留给了真正的 JavaScript，这很好，除了有时候，代码变得不够清晰。

总的来说，我们的目标是从组件中移除所有的逻辑，特别是从渲染方法中移除，但有时我们必须根据应用程序的状态显示和隐藏元素，而且我们经常必须循环遍历集合和数组。

如果你觉得使用 JSX 进行这种操作会使你的代码更易读，那么有一个可用的 Babel 插件可以做到：`jsx-control-statements`。

它遵循与 JSX 相同的哲学，不会向语言添加任何真正的功能；它只是一种被编译成 JavaScript 的语法糖。

让我们看看它是如何工作的。

首先，我们必须安装它：

```jsx
npm install --save jsx-control-statements
```

安装完成后，我们必须将它添加到我们的`.babelrc`文件中的 Babel 插件列表中：

```jsx
"plugins": ["jsx-control-statements"]
```

从现在开始，我们可以使用插件提供的语法，Babel 将把它与常见的 JSX 语法一起转译。

使用该插件编写的条件语句如下所示：

```jsx
<If condition={this.canShowSecretData}> 
  <SecretData /> 
</If>
```

这被转译成了一个三元表达式，如下所示：

```jsx
{canShowSecretData ? <SecretData /> : null}
```

`If`组件很棒，但是如果由于某种原因，你在渲染方法中有嵌套的条件，它很容易变得混乱和难以理解。这就是`Choose`组件派上用场的地方：

```jsx
<Choose> 
  <When condition={...}> 
    <span>if</span> 
  </When> 
 <When condition={...}> 
    <span>else if</span> 
  </When> 
 <Otherwise> 
 <span>else</span> 
 </Otherwise> 
</Choose>
```

请注意，前面的代码被转译成了多个三元运算符。

最后，还有一个组件（永远记住我们不是在谈论真正的组件，而只是语法糖）来管理循环，也非常方便：

```jsx
<ul> 
 <For each="user" of={this.props.users}> 
    <li>{user.name}</li> 
  </For> 
</ul>
```

前面的代码被转译成了一个`map`函数 - 没有什么魔术。

如果你习惯使用**linters**，你可能会想知道为什么 linter 没有对那段代码进行投诉。在转译之前，`user`变量并不存在，也没有被包裹在一个函数中。为了避免这些 linting 错误，还有另一个要安装的插件：`eslint-plugin-jsx-control-statements`。

如果您不理解上一句话，不用担心；我们将在接下来的部分讨论 linting。

### 子渲染

值得强调的是，我们始终希望保持我们的组件非常小，我们的渲染方法非常干净和简单。

然而，这并不是一个容易的目标，特别是当您迭代地创建一个应用程序时，在第一次迭代中，您并不确定如何将组件拆分成更小的组件。那么，当`render`方法变得太大而无法维护时，我们应该做些什么呢？一个解决方案是将其拆分成更小的函数，以便让我们将所有逻辑保留在同一个组件中。

让我们看一个例子：

```jsx
const renderUserMenu = () => { 
  // JSX for user menu 
} 

const renderAdminMenu = () => { 
  // JSX for admin menu 
} 

return ( 
  <div> 
 <h1>Welcome back!</h1> 
    {userExists && renderUserMenu()} 
    {userIsAdmin && renderAdminMenu()} 
  </div> 
)
```

这并不总是被认为是最佳实践，因为将组件拆分成更小的组件似乎更明显。然而，有时候这有助于保持渲染方法的清晰。例如，在 Redux 的真实示例中，使用子渲染方法来渲染*load more*按钮。

既然我们是 JSX 的高级用户，现在是时候继续前进，看看如何在我们的代码中遵循样式指南，使其保持一致。

# 代码样式

在本节中，您将学习如何实现 EditorConfig 和 ESLint，通过验证您的代码风格来提高代码质量。在团队中拥有标准的代码风格并避免使用不同的代码风格是很重要的。

## EditorConfig

**EditorConfig**帮助开发人员在不同的 IDE 之间保持一致的编码风格。

EditorConfig 受许多编辑器支持。您可以在官方网站[`www.editorconfig.org`](https://www.editorconfig.org)上检查您的编辑器是否受支持。

您需要在您的`root`目录中创建一个名为`.editorconfig`的文件 - 我使用的配置是这样的：

```jsx
root = true

[*]
indent_style = space 
indent_size = 2
end_of_line = lf
charset = utf-8 
trim_trailing_whitespace = true 
insert_final_newline = true

[*.html] 
indent_size = 4

[*.css] 
indent_size = 4

[*.md]
trim_trailing_whitespace = false
```

您可以影响所有文件`[*]`，以及特定文件`[.extension]`。

## Prettier

**Prettier**是一种主观的代码格式化工具，支持许多语言，并可以集成到大多数编辑器中。这个插件非常有用，因为您可以在保存代码时格式化代码，而无需在代码审查中讨论代码风格，这将节省您大量的时间和精力。

如果您使用 Visual Studio Code，首先必须安装 Prettier 扩展：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/7a10a5dd-0c4b-43fc-837d-f95b014dd3c4.png)

然后，如果您想配置选项以在保存文件时进行格式化，您需要转到设置，搜索`Format on Save`，并检查该选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/f1a9fade-d007-40df-a295-54f736f126d2.png)

这将影响您所有的项目，因为这是一个全局设置。如果您只想在特定项目中应用此选项，您需要在项目内创建一个`.vscode`文件夹和一个带有以下代码的`settings.json`文件：

```jsx
{
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.formatOnSave": true
}
```

然后，您可以在`.prettierrc`文件中配置您想要的选项-这是我通常使用的配置：

```jsx
{
 "**arrowParens**": "avoid",
 "**bracketSpacing**": true,
 "**jsxSingleQuote**": false,
 "**printWidth**": 100,
 "**quoteProps**": "as-needed",
 "**semi**": false,
 "**singleQuote**": true,
 "**tabWidth**": 2,
 "**trailingComma**": "none",
 "**useTabs**": false
}
```

这将帮助您或您的团队标准化代码风格。

## ESLint

我们总是尽量写出最好的代码，但有时会出现错误，花几个小时捕捉由于拼写错误而导致的错误非常令人沮丧。幸运的是，一些工具可以帮助我们在输入代码时检查代码的正确性。这些工具无法告诉我们我们的代码是否会按预期运行，但它们可以帮助我们避免语法错误。

如果您来自静态语言，比如 C#，您习惯于在 IDE 中获得这种警告。几年前，Douglas Crockford 在 JavaScript 中使用 JSLint（最初于 2002 年发布）使 linting 变得流行；然后我们有了 JSHint，最后，现在在 React 世界中的事实标准是 ESLint。

**ESLint**是一个于 2013 年发布的开源项目，因为它高度可配置和可扩展而变得流行。

在 JavaScript 生态系统中，库和技术变化非常快，拥有一个可以轻松通过插件进行扩展的工具以及可以在需要时启用和禁用规则是至关重要的。最重要的是，现在我们使用转译器，比如 Babel，以及不属于 JavaScript 标准版本的实验性功能，因此我们需要能够告诉我们的代码检查工具我们在源文件中遵循哪些规则。代码检查工具不仅帮助我们减少错误，或者至少更早地发现这些错误，而且强制执行一些常见的编码风格指南，这在拥有许多开发人员的大团队中尤为重要，每个开发人员都有自己喜欢的编码风格。

在使用不一致的风格编写不同文件甚至不同函数的代码库中，很难阅读代码。因此，让我们更详细地了解一下 ESLint。

### 安装

首先，我们必须安装 ESLint 和一些插件，如下所示：

```jsx
npm install -g eslint eslint-config-airbnb eslint-config-prettier eslint-plugin-import eslint-plugin-jsx-a11y eslint-plugin-prettier eslint-plugin-react
```

一旦可执行文件安装完成，我们可以使用以下命令运行它：

```jsx
eslint source.ts
```

输出会告诉我们文件中是否有错误。

当我们第一次安装和运行它时，我们不会看到任何错误，因为它是完全可配置的，不带有任何默认规则。

### 配置

让我们开始配置 ESLint。可以使用项目根目录中的`.eslintrc`文件进行配置。要添加一些规则，让我们创建一个为 TypeScript 配置的`.eslintrc`文件并添加一个基本规则：

```jsx
{
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint", "prettier"],
  "extends": [
    "airbnb",
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:prettier/recommended"
  ],
  "settings": {
    "import/extensions": [".js", ".jsx", ".ts", ".tsx"],
    "import/parsers": {
      "@typescript-eslint/parser": [".ts", ".tsx"]
    },
    "import/resolver": {
      "node": {
        "extensions": [".js", ".jsx", ".ts", ".tsx"]
      }
    }
  },
  "rules": {
    "semi": [2, "never"]
  }
}
```

这个配置文件需要一点解释：`"semi"`是规则的名称，“[2，“never”]”是值。第一次看到它时并不是很直观。

ESLint 规则有三个级别，确定问题的严重程度：

+   关闭（或 0）：规则被禁用。

+   警告（或 1）：规则是一个警告。

+   错误（或 2）：规则会抛出错误。

我们使用值为 2 是因为我们希望 ESLint 在我们的代码不遵循规则时抛出错误。第二个参数告诉 ESLint 我们不希望使用分号（相反的是*always*）。ESLint 及其插件都有非常好的文档，对于任何单个规则，您都可以找到规则的描述以及一些示例，说明何时通过何时失败。

现在创建一个名为`index.ts`的文件，内容如下：

```jsx
const foo = 'bar';
```

如果我们运行`eslint index.js`，我们会得到以下结果：

```jsx
Extra semicolon (semi) 
```

这很棒；我们设置了代码检查工具，它帮助我们遵循第一个规则。

以下是我喜欢关闭或更改的其他规则：

```jsx
"rules": {
    "semi": [2, "never"],
    "@typescript-eslint/class-name-casing": "off",
    "@typescript-eslint/interface-name-prefix": "off",
    "@typescript-eslint/member-delimiter-style": "off",
    "@typescript-eslint/no-var-requires": "off",
    "@typescript-eslint/ban-ts-ignore": "off",
    "@typescript-eslint/no-use-before-define": "off",
    "@typescript-eslint/ban-ts-comment": "off",
    "@typescript-eslint/explicit-module-boundary-types": "off",
    "no-restricted-syntax": "off",
    "no-use-before-define": "off",
    "import/extensions": "off",
    "import/prefer-default-export": "off",
    "max-len": [
      "error",
      {
        "code": 100,
        "tabWidth": 2
      }
    ],
    "no-param-reassign": "off",
    "no-underscore-dangle": "off",
    "react/jsx-filename-extension": [
      1,
      {
        "extensions": [".tsx"]
      }
    ],
    "import/no-unresolved": "off",
    "consistent-return": "off",
    "jsx-a11y/anchor-is-valid": "off",
    "sx-a11y/click-events-have-key-events": "off",
    "jsx-a11y/no-noninteractive-element-interactions": "off",
    "jsx-a11y/click-events-have-key-events": "off",
    "jsx-a11y/no-static-element-interactions": "off",
    "react/jsx-props-no-spreading": "off",
    "jsx-a11y/label-has-associated-control": "off",
    "react/jsx-one-expression-per-line": "off",
    "no-prototype-builtins": "off",
    "no-nested-ternary": "off",
    "prettier/prettier": [
      "error",
      {
        "endOfLine": "auto"
      }
    ]
  }
```

### Git 钩子

为了避免在我们的存储库中有未经过 lint 处理的代码，我们可以在我们的过程的某个时候使用 Git 钩子添加 ESLint。例如，我们可以使用`husky`在名为`pre-commit`的 Git 钩子中运行我们的 linter，还可以在名为`pre-push`的钩子上运行我们的单元测试。

要安装`husky`，您需要运行以下命令：

```jsx
npm install --save-dev husky
```

然后，在我们的`package.json`文件中，我们可以添加这个节点来配置我们想要在 Git 钩子中运行的任务：

```jsx
{
  "scripts": {
    "lint": "eslint --ext .tsx,.ts src",
    "lint:fix": "eslint --ext .tsx,.ts --fix src",
    "test": "jest src"
  },
  "husky": {
    "hooks": {
      "pre-commit": "npm lint",
      "pre-push": "npm test"
    }
  }
}
```

ESlint 命令有一个特殊的选项（标志）叫做`--fix` - 使用这个选项，ESlint 将尝试自动修复所有我们的 linter 错误（不是所有）。请注意这个选项，因为有时它可能会影响我们的代码风格。另一个有用的标志是`--ext`，用于指定我们想要验证的文件的扩展名，在这种情况下只有`.tsx`和`.ts`文件。

在下一节中，您将了解**函数式编程**（**FP**）的工作原理以及一级对象、纯度、不可变性、柯里化和组合等主题。

# 函数式编程

除了在编写 JSX 时遵循最佳实践并使用 linter 来强制一致性并更早地发现错误之外，我们还可以做一件事来清理我们的代码：遵循 FP 风格。

如*第一章*中所讨论的，React 采用了一种声明式的编程方法，使我们的代码更易读。FP 是一种声明式的范式，其中避免副作用，并且数据被视为不可变，以使代码更易于维护和理解。

不要将以下子部分视为 FP 的详尽指南；这只是一个介绍，让您了解 React 中常用的一些概念。

## **一级函数**

JavaScript 具有一级函数，因为它们被视为任何其他变量，这意味着您可以将函数作为参数传递给其他函数，或者它可以被另一个函数返回并分配为变量的值。

这使我们能够介绍**高阶函数**（**HoFs**）的概念。 HoFs 是接受函数作为参数的函数，并且可能还有一些其他参数，并返回一个函数。返回的函数通常具有一些特殊的行为。

让我们看一个例子：

```jsx
const add = (x, y) => x + y

const log = fn => (...args) => { 
 return fn(...args)
}

const logAdd = log(add)
```

在这里，一个函数正在添加两个数字，增强一个记录所有参数然后执行原始函数的函数。

理解这个概念非常重要，因为在 React 世界中，一个常见的模式是使用 HOCs 将我们的组件视为函数，并用常见的行为增强它们。我们将在*第四章*，*探索流行的组合模式*中看到 HOCs 和其他模式。

## 纯度

FP 的一个重要方面是编写纯函数。在 React 生态系统中，您会经常遇到这个概念，特别是如果您研究 Redux 等库。

一个函数纯是什么意思？

当函数没有副作用时，函数就是纯的，这意味着函数不会改变任何不属于函数本身的东西。

例如，一个改变应用程序状态的函数，或者修改在上层作用域中定义的变量的函数，或者触及外部实体，比如**文档对象模型**（**DOM**）的函数被认为是不纯的。不纯的函数更难调试，大多数情况下不可能多次应用它们并期望得到相同的结果。

例如，以下函数是纯的：

```jsx
const add = (x, y) => x + y
```

它可以多次运行，始终得到相同的结果，因为没有任何东西被存储，也没有任何东西被修改。

以下函数不是纯的：

```jsx
let x = 0
const add = y => (x = x + y)
```

运行`add(1)`两次，我们得到两个不同的结果。第一次得到`1`，但第二次得到`2`，即使我们用相同的参数调用相同的函数。我们得到这种行为的原因是全局状态在每次执行后都被修改。

## 不可变性

我们已经看到如何编写不改变状态的纯函数，但是如果我们需要改变变量的值怎么办？在 FP 中，一个函数不是改变变量的值，而是创建一个新的带有新值的变量并返回它。这种处理数据的方式被称为**不可变性**。

不可变值是一个不能被改变的值。

让我们看一个例子：

```jsx
const add3 = arr => arr.push(3)
const myArr = [1, 2]

add3(myArr); // [1, 2, 3]
add3(myArr); // [1, 2, 3, 3]
```

前面的函数不遵循不可变性，因为它改变了给定数组的值。同样，如果我们两次调用相同的函数，我们会得到不同的结果。

我们可以改变前面的函数，使用`concat`使其不可变，返回一个新的数组而不修改给定的数组：

```jsx
const add3 = arr => arr.concat(3)
const myArr = [1, 2]
const result1 = add3(myArr) // [1, 2, 3]
const result2 = add3(myArr) // [1, 2, 3]
```

当我们运行函数两次后，`myArr`仍然保持其原始值。

## 柯里化

FP 中的一个常见技术是柯里化。**柯里化**是将接受多个参数的函数转换为一次接受一个参数并返回另一个函数的过程。让我们看一个例子来澄清这个概念。

让我们从之前看到的 `add` 函数开始，并将其转换为柯里化函数。

假设我们有以下代码：

```jsx
const add = (x, y) => x + y
```

我们可以改为以下方式定义函数：

```jsx
const add = x => y => x + y
```

我们以以下方式使用它：

```jsx
const add1 = add(1)
add1(2); // 3
add1(3); // 4
```

这是编写函数的一种非常方便的方式，因为在应用第一个参数后，第一个值被存储，我们可以多次重复使用第二个函数。

## 组合

最后，FP 中一个重要的概念可以应用到 React 中，那就是**组合**。函数（和组件）可以组合在一起，产生具有更高级功能和属性的新函数。

考虑以下函数：

```jsx
const add = (x, y) => x + y
const square = x => x * x
```

这些函数可以组合在一起创建一个新的函数，该函数将两个数字相加，然后将结果加倍：

```jsx
const addAndSquare = (x, y) => square(add(x, y))
```

遵循这个范式，我们最终得到了小型、简单、可测试的纯函数，可以组合在一起。

## FP 和 UI

最后一步是学习如何使用 FP 来构建 UI，这正是我们使用 React 的目的。

我们可以将 UI 视为一个函数，将应用程序的状态应用如下：

```jsx
UI = f(state)
```

我们期望这个函数是幂等的，这样它在应用程序的相同状态下返回相同的 UI。

使用 React，我们使用组件来创建我们的 UI，我们可以将其视为函数，正如我们将在接下来的章节中看到的。

组件可以组合在一起形成最终的 UI，这是 FP 的一个特性。

在使用 React 构建 UI 的方式和 FP 的原则中有很多相似之处，我们越了解，我们的代码就会越好。

# 总结

在本章中，我们学到了关于 JSX 的工作原理以及如何在组件中正确使用它的很多知识。我们从语法的基础开始，创建了一个坚实的知识基础，使我们能够掌握 JSX 及其特性。

在第二部分，我们看了如何配置 Prettier 以及 ESLint 及其插件如何帮助我们更快地发现问题，并强制执行一致的代码风格指南。

最后，我们通过 FP 的基础知识来理解在编写 React 应用程序时使用的重要概念。

现在我们的代码已经整洁，我们准备在下一章深入学习 React，并学习如何编写真正可重用的组件。


# 第二部分：React 工作原理

本节将解释如何使用新的 React Hooks，它们的规则，以及如何创建自己的 Hooks。还将涵盖如何将当前的 React 类组件应用迁移到新的 React Hooks。

我们将在本节中涵盖以下章节：

+   第三章，React Hooks

+   第四章，探索流行的组合模式

+   第五章，通过真实项目了解 GraphQL

+   第六章，数据管理

+   第七章，为浏览器编写代码


# 第三章：React Hooks

React 发展非常迅速，自 React 16.8 以来，引入了新的 React Hooks，这是 React 开发的一个改变者，因为它们将提高编码速度并改善应用程序的性能。React 使我们能够仅使用功能组件编写 React 应用程序，这意味着不再需要使用类组件。

在这一章中，我们将涵盖以下主题：

+   新的 React Hooks 以及如何使用它们

+   Hooks 的规则

+   如何将类组件迁移到 React Hooks

+   使用 Hooks 和效果理解组件生命周期

+   如何使用 Hooks 获取数据

+   如何使用`memo`、`useMemo`和`useCallback`来记忆组件、值和函数

+   如何实现`useReducer`

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter03`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter03)。

# 介绍 React Hooks

React Hooks 是 React 16.8 中的新添加。它们让您在不编写 React 类组件的情况下使用状态和其他 React 功能。React Hooks 也是向后兼容的，这意味着它不包含任何破坏性更改，也不会取代您对 React 概念的了解。在本章的过程中，我们将看到有关经验丰富的 React 用户的 Hooks 概述，并且我们还将学习一些最常见的 React Hooks，如`useState`、`useEffect`、`useMemo`、`useCallback`和`memo`。

## 没有破坏性更改

许多人认为，使用新的 React Hooks，类组件在 React 中已经过时，但这种说法是不正确的。没有计划从 React 中删除类。Hooks 不会取代您对 React 概念的了解。相反，Hooks 为 React 概念提供了更直接的 API，如 props、state、context、refs 和生命周期，这些您已经了解。

## 使用 State Hook

您可能知道如何在类中使用`this.setState`来使用组件状态。现在您可以使用新的 React `useState` Hook 来使用组件状态。

首先，您需要从 React 中提取`useState` Hook：

```jsx
import { useState } from 'react'
```

自 React 17 以来，不再需要 React 对象来渲染 JSX 代码。

然后，您需要通过定义状态和特定状态的 setter 来声明要使用的状态：

```jsx
const Counter = () => {
  const [counter, setCounter] = useState<number>(0)
}
```

正如您所看到的，我们使用`setCounter` setter 声明了计数器状态，并且我们指定只接受数字，最后，我们将初始值设置为零。

为了测试我们的状态，我们需要创建一个将由`onClick`事件触发的方法：

```jsx
const Counter = () => {
  const [counter, setCounter] = useState<number>(0)

  const handleCounter = (operation) => {
    if (operation === 'add') {
      return setCounter(counter + 1)
    }

    return setCounter(counter - 1)
  }
}
```

最后，我们可以渲染`counter`状态和一些按钮来增加或减少`counter`状态：

```jsx
return (
  <p>
    Counter: {counter} <br />
    <button onClick={() => handleCounter('add')}>+ Add</button>
    <button onClick={() => handleCounter('subtract')}>- Subtract</button>
  </p>
)
```

如果您点击+添加按钮一次，您应该在计数器中看到 1：

！[](assets/266d444a-ec32-44c6-bff3-29f4d5ab4d4b.png)

如果您连续点击减号按钮两次，那么您应该在计数器中看到-1：

！[](assets/56a2e476-d287-46d0-80b9-7956e95c8c4c.png)

正如您所看到的，`useState` Hook 在 React 中是一个改变游戏规则的东西，并且使得在功能组件中处理状态变得非常容易。

## Hooks 的规则

React Hooks 基本上是 JavaScript 函数，但是您需要遵循两条规则才能使用它们。React 提供了一个 lint 插件来强制执行这些规则，您可以通过运行以下命令来安装它：

```jsx
npm install --save-dev eslint-plugin-react-hooks 
```

让我们看看这两条规则。

### 规则 1：只在顶层调用 Hooks

来自官方 React 文档（[`reactjs.org/docs/hooks-rules.html`](https://reactjs.org/docs/hooks-rules.html)）：

“**不要在循环、条件或嵌套函数中调用 Hooks**。相反，始终在 React 函数的顶层使用 Hooks。遵循此规则，您确保每次组件渲染时以相同的顺序调用 Hooks。这就是允许 React 在多次 useState 和 useEffect 调用之间正确保存 Hooks 状态的原因。”

### 规则 2：只从 React 函数调用 Hooks

来自官方 React 文档（[`reactjs.org/docs/hooks-rules.html`](https://reactjs.org/docs/hooks-rules.html)）：

“不要从常规 JavaScript 函数调用 Hooks。相反，您可以：

+   从 React 函数组件调用 Hooks。

+   从自定义 Hooks 调用 Hooks（我们将在下一页学习它们）。

遵循此规则，您确保组件中的所有有状态逻辑在其源代码中清晰可见。”

在下一节中，我们将学习如何将类组件迁移到使用新的 React Hooks。

# 将类组件迁移到 React Hooks

让我们转换一个当前正在使用类组件和一些生命周期方法的代码。在这个例子中，我们正在从 GitHub 仓库中获取问题并列出它们。

对于这个例子，您需要安装`axios`来执行获取操作：

```jsx
npm install axios
```

这是类组件版本：

```jsx
// Dependencies
import { Component } from 'react'
import axios from 'axios'

// Types
type Issue = {
  number: number
  title: string
  state: string
}
type Props = {}
type State = { issues: Issue[] };

class Issues extends Component<Props, State> {
  constructor(props: Props) {
    super(props)

    this.state = {
      issues: []
    }
  }

  componentDidMount() {
    axios
    .get('https://api.github.com/repos/ContentPI/ContentPI/issues')
     .then((response: any) => {
        this.setState({
          issues: response.data
        })
      })
  }

  render() {
    const { issues = [] } = this.state

    return (
      <>
        <h1>ContentPI Issues</h1>

        {issues.map((issue: Issue) => (
          <p key={issue.title}>
            <strong>#{issue.number}</strong> {' '}
            <a href=    {`https://github.com/ContentPI/ContentPI/issues/${issue.number}`}
                target="_blank">{issue.title}</a> {' '}
            {issue.state}
          </p>
        ))}
      </>
    )
  }
}

export default Issues
```

如果您渲染此组件，应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b0280137-c6aa-43cb-aae0-b6f5fd070592.png)

现在，让我们将我们的代码转换为使用 React Hooks 的函数组件。我们需要做的第一件事是导入一些 React 函数和类型：

```jsx
// Dependencies
import { FC, useState, useEffect } from 'react'
import axios from 'axios'
```

现在我们可以删除之前创建的`Props`和`State`类型，只留下`Issue`类型：

```jsx
// Types
type Issue = {
  number: number
  title: string
  state: string
}
```

之后，您可以更改类定义以使用函数组件：

```jsx
const Issues: FC = () => {...}
```

`FC`类型用于在 React 中定义**函数组件**。如果您需要将一些 props 传递给组件，可以这样传递：

```jsx
type Props = { propX: string propY: number propZ: boolean  
}

const Issues: FC<Props> = () => {...}
```

接下来，我们需要做的是使用`useState` Hook 来替换我们的构造函数和状态定义：

```jsx
// The useState hook replace the this.setState method
const [issues, setIssues] = useState<Issue[]>([])
```

我们以前使用了名为`componentDidMount`的生命周期方法，它在组件挂载时执行，并且只会运行一次。新的 React Hook，称为`useEffect`，现在将使用不同的语法处理所有生命周期方法，但现在，让我们看看如何在我们的新函数组件中获得与`componentDidMount`相同的*效果*：

```jsx
// When we use the useEffect hook with an empty array [] on the 
// dependencies (second parameter) 
// this represents the componentDidMount method (will be executed when the 
// component is mounted).
useEffect(() => {
  axios
    .get('https://api.github.com/repos/ContentPI/ContentPI/issues')
    .then((response: any) => {
      // Here we update directly our issue state
      setIssues(response.data)
    })
}, [])
```

最后，我们只需渲染我们的 JSX 代码：

```jsx
return (
  <>
    <h1>ContentPI Issues</h1>

    {issues.map((issue: Issue) => (
      <p key={issue.title}>
        <strong>#{issue.number}</strong> {' '}
        <a href=
          {`https://github.com/ContentPI/ContentPI/issues/${issue.number}`} 
            target="_blank">{issue.title}</a> {' '}
        {issue.state}
      </p>
    ))}
  </>
)
```

正如您所看到的，新的 Hooks 帮助我们大大简化了我们的代码，并且更有意义。此外，我们通过 10 行减少了我们的代码（类组件代码有 53 行，函数组件有 43 行）。

# 理解 React 效果

在本节中，我们将学习在类组件上使用的组件生命周期方法和新的 React 效果之间的区别。即使您在其他地方读到它们是相同的，只是语法不同，这是不正确的。

## 理解 useEffect

当您使用`useEffect`时，您需要*思考效果*。如果您想使用`useEffect`执行`componentDidMount`的等效方法，可以这样做：

```jsx
useEffect(() => {
  // Here you perform your side effect
}, [])
```

第一个参数是您想要执行的效果的回调函数，第二个参数是依赖项数组。如果在依赖项中传递一个空数组(`[]`)，状态和 props 将具有它们的原始初始值。

然而，重要的是要提到，即使这是`componentDidMount`的最接近等价物，它并不具有相同的行为。与`componentDidMount`和`componentDidUpdate`不同，我们传递给`useEffect`的函数在布局和绘制之后，在延迟事件期间触发。这通常适用于许多常见的副作用，比如设置订阅和事件处理程序，因为大多数类型的工作不应该阻止浏览器更新屏幕。

然而，并非所有的效果都可以延迟。例如，如果你需要改变**文档对象模型**（**DOM**），你会看到一个闪烁。这就是为什么你必须在下一次绘制之前同步触发事件的原因。React 提供了一个叫做`useLayoutEffect`的 Hook，它的工作方式与`useEffect`完全相同。

## 有条件地触发效果

如果你需要有条件地触发一个效果，那么你应该向依赖数组中添加一个依赖项，否则，你将多次执行效果，这可能会导致无限循环。如果你传递一个依赖项数组，`useEffect` Hook 将只在其中一个依赖项发生变化时运行：

```jsx
useEffect(() => {
  // When you pass an array of dependencies the useEffect hook will only 
  // run 
  // if one of the dependencies changes.
}, [dependencyA, dependencyB])
```

如果你了解 React 类生命周期方法的工作原理，基本上，`useEffect`的行为与`componentDidMount`，`componentDidUpdate`和`componentWillUnmount`的行为相同。

效果非常重要，但让我们也探索一些其他重要的新 Hook，包括`useCallback`，`useMemo`和`memo`。

# 理解 useCallback，useMemo 和 memo

为了理解`useCallback`，`useMemo`和`memo`之间的区别，我们将做一个待办事项清单的例子。你可以使用`create-react-app`和 typescript 作为模板创建一个基本的应用程序：

```jsx
create-react-app todo --template typescript
```

在那之后，你可以移除所有额外的文件（`App.css`，`App.test.ts`，`index.css`，`logo.svg`，`reportWebVitals.ts`和`setupTests.ts`）。你只需要保留`App.tsx`文件，其中包含以下代码：

```jsx
// Dependencies
import { useState, useEffect, useMemo, useCallback } from 'react'

// Components
import List, { Todo } from './List'

const initialTodos = [
  { id: 1, task: 'Go shopping' },
  { id: 2, task: 'Pay the electricity bill'}
]

function App() {
  const [todoList, setTodoList] = useState(initialTodos)
  const [task, setTask] = useState('')

  useEffect(() => {
    console.log('Rendering <App />')
  })

  const handleCreate = () => {
    const newTodo = {
      id: Date.now(), 
      task
    }

    // Pushing the new todo to the list
    setTodoList([...todoList, newTodo])

    // Resetting input value
    setTask('')
  }

  return (
    <>
      <input 
        type="text" 
        value={task} 
        onChange={(e) => setTask(e.target.value)} 
      />

      <button onClick={handleCreate}>Create</button>

      <List todoList={todoList} />
    </>
  )
}

export default App
```

基本上，我们正在定义一些初始任务并创建`todoList`状态，我们将把它传递给列表组件。然后你需要创建`List.tsx`文件，其中包含以下代码：

```jsx
// Dependencies
import { FC, useEffect } from 'react'

// Components
import Task from './Task'

// Types
export type Todo = {
  id: number
  task: string
}

interface Props {
  todoList: Todo[]
}

const List: FC<Props> = ({ todoList }) => {
  useEffect(() => {
    // This effect is executed every new render
    console.log('Rendering <List />')
  })

  return (
    <ul>
      {todoList.map((todo: Todo) => (
        <Task key={todo.id} id={todo.id} task={todo.task} />
      ))}
    </ul>
  )
}

export default List
```

正如你所看到的，我们通过使用`Task`组件渲染`todoList`数组的每个任务，并将`task`作为 prop 传递。我还添加了一个`useEffect` Hook 来查看我们执行了多少次渲染。

最后，我们创建我们的`Task.tsx`文件，其中包含以下代码：

```jsx
import { FC, useEffect } from 'react'

interface Props {
  id: number
  task: string
}

const Task: FC<Props> = ({ task }) => {
  useEffect(() => {
    console.log('Rendering <Task />', task)
  })

  return (
    <li>{task}</li>
  )
}

export default Task
```

这就是我们应该看待待办事项清单的方式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/aebfa2b0-1b3f-4145-b7f3-366ce9252c7f.png)

正如你所看到的，当我们渲染我们的待办事项列表时，默认情况下，我们会对`Task`组件执行两次渲染，对`List`执行一次渲染，对`App`组件执行一次渲染。

现在，如果我们尝试在输入框中写一个新的任务，我们会发现，每写一个字母，我们都会再次看到所有这些渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/32dd8a44-a55b-4886-b827-2ab09b1a1a41.png)

正如你所看到的，只需写`Go`，我们就有了两批新的渲染，所以我们可以确定这个组件的性能不好，这就是`memo`可以帮助我们提高性能的地方。在接下来的部分，我们将学习如何实现`memo`，`useMemo`和`useCallback`来对组件，值和函数进行记忆化。

## 使用 memo 对组件进行记忆化

`memo` **高阶组件（HOC）**类似于 React 类的`PureComponent`，因为它对 props 进行浅比较（意思是表面检查），所以如果我们一直尝试使用相同的 props 渲染组件，组件将只渲染一次并进行记忆。唯一重新渲染组件的方法是当一个 prop 改变其值时。

为了修复我们的组件，避免在输入时多次渲染，我们需要将我们的组件包装在`memo` HOC 中。

我们将要修复的第一个组件是我们的`List`组件，你只需要引入`memo`并将组件包装在`export default`中：

```jsx
import { FC, useEffect, memo } from 'react'

...

export default memo(List)
```

然后你需要对`Task`组件做同样的操作：

```jsx
import { FC, useEffect, memo } from 'react'

...

export default memo(Task)
```

现在，当我们再次尝试在输入框中写`Go`时，让我们看看这一次我们得到了多少次渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/a758059b-3561-4a90-9927-55f4b2ad7a61.png)

现在，我们只在第一次得到第一批渲染，然后，当我们写`Go`时，我们只得到`App`组件的另外两个渲染，这是完全可以接受的，因为我们正在改变的任务状态（输入值）实际上是`App`组件的一部分。

此外，我们可以看到当我们点击“创建”按钮创建一个新任务时，我们执行了多少次渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/128157ac-ed62-472c-b399-63287304f2f3.png)

如果你看到，前 16 次渲染是对“去看医生”字符串的字数统计，然后，当你点击“创建”按钮时，你应该看到`Task`组件的一次渲染，`List`的一次渲染，以及`App`组件的一次渲染。正如你所看到的，我们大大提高了性能，并且我们只执行了确实需要渲染的内容。

此时，你可能在想正确的方法是始终向我们的组件添加备忘录，或者你在想为什么 React 不会默认为我们这样做呢？

原因是**性能**，这意味着**除非完全必要，否则不要向所有组件添加`memo`**，否则，浅比较和记忆的过程将比不使用它的性能差。

当涉及确定是否使用`memo`时，我有一个规则，这个规则很简单：**就是不要使用它。**通常，当我们有小组件或基本逻辑时，除非你正在处理**来自某个 API 的大量数据或者你的组件需要执行大量渲染（通常是巨大的列表），或者当你注意到你的应用程序运行缓慢**，我们不需要这个。只有在这种情况下，我才建议使用`memo`。

## 使用`useMemo`进行值的备忘录

假设我们现在想在待办事项列表中实现搜索功能。我们需要做的第一件事是向`App`组件添加一个名为`term`的新状态：

```jsx
const [term, setTerm] = useState('')
```

然后我们需要创建一个名为`handleSearch`的函数：

```jsx
const handleSearch = () => {
 setTerm(task)
}
```

在返回之前，我们将创建`filterTodoList`，它将根据任务筛选待办事项，并在那里添加一个控制台，以查看它被渲染了多少次：

```jsx
const filteredTodoList = todoList.filter((todo: Todo) => {
  console.log('Filtering...')
 return todo.task.toLowerCase().includes(term.toLocaleLowerCase())
})
```

最后，我们需要在已经存在的创建按钮旁边添加一个新按钮：

```jsx
<button onClick={handleSearch}>Search</button>
```

此时，我建议你删除或注释`List`和`Task`组件中的`console.log`，这样我们可以专注于过滤的性能：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/61331e13-ded8-4eab-add0-1704e4d178be.png)

当你再次运行应用程序时，你会看到过滤被执行了两次，然后`App`组件也是，一切看起来都很好，但是这有什么问题吗？尝试在输入框中再次输入“去看医生”，让我们看看你会得到多少次渲染和过滤：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/130012da-d053-4f2b-b2b5-1b83bdadc05e.png)

如你所见，每输入一个字母，你会得到两次过滤调用和一次`App`渲染，你不需要是天才就能看出这是糟糕的性能；更不用说如果你正在处理一个大数据数组，情况会更糟，那么我们该如何解决这个问题呢？

`useMemo` Hook 在这种情况下是我们的英雄，基本上，我们需要将我们的过滤器放在`useMemo`中，但首先让我们看一下语法：

```jsx
const filteredTodoList = useMemo(() => SomeProcessHere, [])
```

`useMemo` Hook 将记忆函数的结果（值），并且将有一些依赖项来监听。让我们看看如何实现它：

```jsx
const filteredTodoList = useMemo(() => todoList.filter((todo: Todo) => {
  console.log('Filtering...')
 return todo.task.toLowerCase().includes(term.toLowerCase())
}), [])
```

现在，如果您再次在输入框中输入内容，您会发现过滤不会一直执行，就像以前的情况一样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/1f273372-2b54-4147-b084-8818284276e8.png)

这很好，但仍然有一个小问题。如果您尝试单击搜索按钮，它不会进行过滤，这是因为我们错过了依赖项。实际上，如果您查看控制台警告，您将看到此警告：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/67075e04-e4cf-4722-8849-9b64fedcf868.png)

需要将`term`和`todoList`依赖项添加到数组中：

```jsx
const filteredTodoList = useMemo(() => todoList.filter((todo: Todo) => {
  console.log('Filtering...')
 return todo.task.toLowerCase().includes(term.toLocaleLowerCase())
}), [term, todoList])
```

如果您现在写`Go`并单击搜索按钮，它应该可以工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/34c00dec-2193-44f3-bbb0-05ed84679c9c.png)在这里，我们必须使用与记忆相同的规则；**直到绝对必要时才使用它。**

## 使用`useCallback`来记忆函数定义

现在我们将添加一个删除任务的功能，以了解`useCallback`的工作原理。我们需要做的第一件事是在我们的`App`组件中创建一个名为`handleDelete`的新函数：

```jsx
const handleDelete = (taskId: number) => {
  const newTodoList = todoList.filter((todo: Todo) => todo.id !== taskId)
  setTodoList(newTodoList)
}
```

然后，您需要将此函数作为属性传递给`List`组件：

```jsx
<List todoList={filteredTodoList} handleDelete={handleDelete} />
```

然后，在我们的`List`组件中，您需要将该属性添加到`Props`接口中：

```jsx
interface Props {
  todoList: Todo[]
  handleDelete: any
}
```

接下来，您需要从属性中提取它并将其传递给`Task`组件：

```jsx
const List: FC<Props> = ({ todoList, handleDelete }) => {
  useEffect(() => {
    // This effect is executed every new render
    console.log('Rendering <List />')
  })

  return (
    <ul>
      {todoList.map((todo: Todo) => (
        <Task 
          key={todo.id} 
          id={todo.id}
          task={todo.task} 
          handleDelete={handleDelete}
        />
      ))}
    </ul>
  )
}
```

在`Task`组件中，您需要创建一个按钮，该按钮将执行`handleDelete onClick`：

```jsx
interface Props {
  id: number
  task: string
  handleDelete: any
}

const Task: FC<Props> = ({ id, task, handleDelete }) => {
  useEffect(() => {
    console.log('Rendering <Task />', task)
  })

  return (
    <li>{task} <button onClick={() => handleDelete(id)}>X</button></li>
  )
}
```

在这一点上，我建议您删除或注释`List`和`Task`组件中的`console.log`，这样我们就可以专注于过滤的性能。现在您应该看到任务旁边的 X 按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/0cb5eb97-875e-49f4-9a91-7c0c381cb587.png)

如果您单击`去购物`的 X，应该可以将其删除：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/aabf1a76-e3c6-410d-bf21-a58a7b1a10fd.png)

到目前为止，还好，对吧？但是我们在这个实现中又遇到了一个小问题。如果您现在尝试在输入框中写一些内容，比如`去看医生`，让我们看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/7acf5bb0-bb7c-4f70-88a4-dc0398c62fe3.png)

如果您看到，我们再次执行了所有组件的**71**次渲染。此时，您可能会想，*如果我们已经实现了 memo HOC 来记住组件，那么现在发生了什么*？但现在的问题是，我们的`handleDelete`函数被传递给了两个组件，从`App`到`List`，再到`Task`，问题在于每次重新渲染时，这个函数都会被重新生成，也就是说，每次我们写东西时都会重新生成。那么我们如何解决这个问题呢？

`useCallback` Hook 在这种情况下是英雄，并且在语法上与`useMemo`非常相似，但主要区别在于，它不是像`useMemo`那样记住函数的结果值，而是记住**函数定义**：

```jsx
const handleDelete = useCallback(() => SomeFunctionDefinition, [])
```

我们的`handleDelete`函数应该像这样：

```jsx
const handleDelete = useCallback((taskId: number) => {
  const newTodoList = todoList.filter((todo: Todo) => todo.id !== taskId)
  setTodoList(newTodoList)
}, [todoList])
```

现在，如果我们再次写`去看医生`，它应该可以正常工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/04e9608a-b0b5-425a-9826-ddfd424785e3.png)

现在，我们只有 23 个渲染，而不是 71 个，这是正常的，我们也能够删除任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/3910a623-ff9b-4198-947c-24f7574e0a9e.png)

正如您所看到的，`useCallback` Hook 帮助我们显着提高了性能。在下一节中，您将学习如何在`useEffect` Hook 中记忆作为参数传递的函数。

## 作为参数传递给 effect 的记忆函数

有一种特殊情况，我们需要使用`useCallback` Hook，这是当我们将一个函数作为参数传递给`useEffect` Hook 时，例如，在我们的`App`组件中。让我们创建一个新的`useEffect`块：

```jsx
const printTodoList = () => {
  console.log('Changing todoList')
}

useEffect(() => {
  printTodoList()
}, [todoList])
```

在这种情况下，我们正在监听`todoList`状态的变化。如果您运行此代码并创建或删除任务，它将正常工作（请记得首先删除所有其他控制台）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/88a3b7ff-a819-4871-86c5-f2e7c2989aba.png)

一切都运行正常，但让我们将`todoList`添加到控制台中：

```jsx
const printTodoList = () => {
  console.log('Changing todoList', todoList)
}
```

如果您使用的是 Visual Studio Code，您将收到以下警告：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/47c343cd-00bc-4851-b52c-547a6ceeec9a.png)

基本上，它要求我们将`printTodoList`函数添加到依赖项中：

```jsx
useEffect(() => {
  printTodoList()
}, [todoList, printTodoList])
```

但现在，在我们这样做之后，我们收到了另一个警告：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/7a3abf84-d180-43d3-acd6-c4bfe17fd267.png)

我们收到此警告的原因是我们现在正在操作一个状态（控制状态），这就是为什么我们需要在这个函数中添加`useCallback` Hook 来解决这个问题：

```jsx
const printTodoList = useCallback(() => {
  console.log('Changing todoList', todoList)
}, [todoList])
```

现在，当我们删除一个任务时，我们可以看到`todoList`已经正确更新了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/333a4b5d-6f08-4e91-83ad-7fe0a24a8679.png)

在这一点上，这可能对您来说是信息过载，所以让我们快速回顾一下：

`memo`：

+   记忆**组件**

+   当道具改变时重新记忆

+   避免重新渲染

`useMemo`：

+   记忆**计算值**

+   对于计算属性

+   对于繁重的过程

`useCallback`：

+   记忆**函数定义**以避免在每次渲染时重新定义它。

+   每当将函数作为效果参数传递时使用它。

+   每当将函数作为道具传递给记忆组件时使用它。

最后，不要忘记黄金法则：**除非绝对必要，否则不要使用它们。**

在下一节中，我们将学习如何使用新的`useReducer` Hook。

# 理解 useReducer Hook

您可能有一些使用 Redux（`react-redux`）与类组件的经验，如果是这样，那么您将了解`useReducer`的工作原理。基本概念基本相同：动作、减速器、分发、存储和状态。即使在一般情况下，它似乎与`react-redux`非常相似，它们也有一些不同之处。主要区别在于`react-redux`提供了中间件和包装器，如 thunk、sagas 等等，而`useReducer`只是提供了一个您可以使用来分发纯对象作为动作的`dispatch`方法。此外，`useReducer`默认没有存储；相反，您可以使用`useContext`创建一个，但这只是重复造轮子。

让我们创建一个基本的应用程序来理解`useReducer`的工作原理。您可以通过创建一个新的 React 应用程序开始：

```jsx
create-react-app reducer --template typescript
```

然后，像往常一样，您可以删除`src`文件夹中的所有文件，除了`App.tsx`和`index.tsx`，以启动全新的应用程序。

我们将创建一个基本的`Notes`应用程序，我们可以使用`useReducer`列出、删除、创建或更新我们的笔记。您需要做的第一件事是将我们稍后将创建的`Notes`组件导入到您的`App`组件中：

```jsx
import Notes from './Notes'

function App() {
  return (
    <Notes />
  )
}

export default App
```

现在，在我们的`Notes`组件中，您首先需要导入`useReducer`和`useState`：

```jsx
import { useReducer, useState, ChangeEvent } from 'react'
```

然后，我们需要定义一些我们需要用于`Note`对象、Redux 动作和动作类型的 TypeScript 类型：

```jsx
type Note = {
  id: number
  note: string
}

type Action = {
  type: string
  payload?: any
}

type ActionTypes = {
  ADD: 'ADD'
  UPDATE: 'UPDATE'
  DELETE: 'DELETE'
}

const actionType: ActionTypes = {
  ADD: 'ADD',
  DELETE: 'DELETE',
  UPDATE: 'UPDATE'
}
```

之后，我们需要创建`initialNotes`（也称为`initialState`）并添加一些虚拟笔记：

```jsx
const initialNotes: Note[] = [
  {
    id: 1,
    note: 'Note 1'
  },
  {
    id: 2,
    note: 'Note 2'
  }
]
```

如果您记得减速器的工作原理，那么这将与我们使用`switch`语句处理减速器的方式非常相似，以执行`ADD`、`DELETE`和`UPDATE`等基本操作：

```jsx
const reducer = (state: Note[], action: Action) => {
  switch (action.type) {
    case actionType.ADD:
      return [...state, action.payload]

    case actionType.DELETE: 
      return state.filter(note => note.id !== action.payload)

    case actionType.UPDATE:
      const updatedNote = action.payload
      return state.map((n: Note) => n.id === updatedNote.id ? 
        updatedNote : n)

    default:
      return state
  }
}
```

最后，这个组件非常简单。基本上，你从`useReducer` Hook 中获取笔记和`dispatch`方法（类似于`useState`），你需要传递`reducer`函数和`initialNotes`（`initialState`）：

```jsx
const Notes = () => {
  const [notes, dispatch] = useReducer(reducer, initialNotes)
  const [note, setNote] = useState('')
  ...
}
```

然后，我们有一个`handleSubmit`函数，当我们在输入框中写东西时，可以创建一个新的笔记。然后，我们按下*Enter*键：

```jsx
const handleSubmit = (e: ChangeEvent<HTMLInputElement>) => {
  e.preventDefault()

  const newNote = {
    id: Date.now(),
    note
  }

  dispatch({ type: actionType.ADD, payload: newNote })
}
```

最后，我们使用`map`渲染我们的`Notes`列表，并创建两个按钮，一个用于删除，一个用于更新，然后输入框应该包装在`<form>`标签中：

```jsx
return (
  <div>
    <h2>Notes</h2>

    <ul>
      {notes.map((n: Note) => (
        <li key={n.id}>
          {n.note} {' '}
          <button 
            onClick={() => dispatch({ 
              type: actionType.DELETE,
              payload: n.id
            })}
          >
            X
          </button>

          <button 
            onClick={() => dispatch({ 
              type: actionType.UPDATE,
              payload: {...n, note}
            })}
          >
            Update
          </button>
        </li>
      ))}
    </ul>

    <form onSubmit={handleSubmit}>
      <input 
        placeholder="New note" 
        value={note} 
        onChange={e => setNote(e.target.value)} 
      />
    </form>
  </div>
)

export default Notes
```

如果你运行应用程序，你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/bf608854-dd2c-45c9-b79f-62980c4fa16e.png)

正如你在 React DevTools 中所看到的，`Reducer`对象包含了我们定义的两个笔记作为初始状态。现在，如果你在输入框中写点东西，然后按下*Enter*，你应该能够创建一个新的笔记：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/12c45050-34b0-48da-9360-078d81bac8ac.png)

然后，如果你想删除一个笔记，你只需要点击 X 按钮。让我们删除笔记 2：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b59b6e27-19c5-4086-be3d-8b298b5ae25d.png)

最后，你可以在输入框中写任何你想要的东西，如果你点击更新按钮，你将改变笔记的值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/dd7d6d51-28c4-43ab-8223-35ee015dde78.png)

不错，对吧？正如你所看到的，`useReducer` Hook 在`dispatch`方法、动作和 reducers 方面与 redux 基本相同，但主要区别在于这仅限于你的组件及其子组件的上下文，因此，如果你需要一个全局存储来自你整个应用程序，那么你应该使用`react-redux`。

# 总结

希望你喜欢阅读这一章，其中包含了有关新的 React Hooks 的非常好的信息。到目前为止，你已经学会了新的 React Hooks 是如何工作的，如何使用 Hooks 获取数据，如何将类组件迁移到 React Hooks，效果是如何工作的，`memo`、`useMemo`和`useCallback`之间的区别，最后，你学会了`useReducer` Hook 的工作原理，以及与`react-redux`相比的主要区别。这将帮助你提高 React 组件的性能。

在下一章中，我们将介绍一些最流行的组合模式和工具。
