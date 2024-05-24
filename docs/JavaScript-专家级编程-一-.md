# JavaScript 专家级编程（一）

> 原文：[`zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD`](https://zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第一章：*前言*

## 关于

本节简要介绍了作者、本书的内容、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于本书

深入了解 JavaScript，更容易学习其他框架，包括 React、Angular 和相关工具和库。本书旨在帮助您掌握构建现代应用程序所需的核心 JavaScript 概念。

您将首先学习如何在文档对象模型（DOM）中表示 HTML 文档。然后，您将结合对 DOM 和 Node.js 的知识，为实际情况创建一个网络爬虫。随着您阅读更多章节，您将使用 Express 库为 Node.js 创建基于 Node.js 的 RESTful API。您还将了解如何使用模块化设计来实现更好的可重用性，并与多个开发人员在单个项目上进行协作。后面的章节将指导您构建单元测试，以确保程序的核心功能不会随时间而受到影响。本书还将演示构造函数、async/await 和事件如何快速高效地加载您的应用程序。最后，您将获得有关不可变性、纯函数和高阶函数等函数式编程概念的有用见解。

通过本书，您将掌握使用现代 JavaScript 方法解决客户端和服务器端的任何真实世界 JavaScript 开发问题所需的技能。

### 关于作者

**雨果·迪弗朗西斯科（Hugo Di Francesco）**是一名软件工程师，他在 JavaScript 方面有丰富的经验。他拥有伦敦大学学院（UCL）的数学计算工程学士学位。他曾在佳能和 Elsevier 等公司使用 JavaScript 创建可扩展和高性能的平台。他目前正在使用 Node.js、React 和 Kubernetes 解决零售运营领域的问题，同时运营着同名的 Code with Hugo 网站。工作之外，他是一名国际击剑运动员，他在全球范围内进行训练和比赛。

**高思远（Siyuan Gao）**是艺电公司的软件工程师。他拥有普渡大学的计算机科学学士学位。他已经使用 JavaScript 和 Node.js 超过 4 年，主要为高可用性系统构建高效的后端解决方案。他还是 Node.js 核心项目的贡献者，并且已经发布了许多 npm 模块。在业余时间，他喜欢学习视频游戏设计和机器学习。

**Vinicius Isola**于 1999 年开始使用 Macromedia Flash 和 ActionScript 进行编程。2005 年，他获得了 Java 认证，并专门从事构建 Web 和企业应用程序。JavaScript 和 Web 技术一直在他的许多工作角色和所在公司中发挥作用。在业余时间，他喜欢参与开源项目并指导新开发人员。

菲利普·柯克布赖德（Philip Kirkbride）在蒙特利尔拥有超过 5 年的 JavaScript 经验。他于 2011 年从技术学院毕业，自那时起一直在不同的角色中使用 Web 技术。他曾与 2Klic 合作，这是一家由主要电暖公司 Convectair 承包的物联网公司，用 Z-Wave 技术创建智能加热器。他的角色包括在 Node.js 和 Bash 中编写微服务。他还有机会为开源项目 SteemIt（基于区块链的博客平台）和 DuckDuckGo（基于隐私的搜索引擎）做出一些贡献。

### 学习目标

通过本书，您将能够：

+   应用函数式编程的核心概念

+   构建一个使用 Express.js 库托管 API 的 Node.js 项目

+   为 Node.js 项目创建单元测试以验证其有效性

+   使用 Cheerio 库与 Node.js 创建基本网络爬虫

+   开发一个 React 界面来构建处理流程

+   使用回调作为将控制权带回的基本方法

### 受众

如果您想从前端开发人员转变为全栈开发人员，并学习 Node.js 如何用于托管全栈应用程序，那么这本书非常适合您。阅读本书后，您将能够编写更好的 JavaScript 代码，并了解语言中的最新趋势。为了轻松掌握这里解释的概念，您应该了解 JavaScript 的基本语法，并且应该使用过流行的前端库，如 jQuery。您还应该使用过 JavaScript 与 HTML 和 CSS，但不一定是 Node.js。

### 方法

本书的每一部分都经过明确设计，旨在吸引和激发您，以便您可以在实际环境中保留和应用所学知识，产生最大的影响。您将学习如何应对具有智力挑战的编程问题，这将通过函数式编程和测试驱动开发实践为您准备真实世界的主题。每一章都经过明确设计，以 JavaScript 作为核心语言进行构建。

### 硬件要求

为了获得最佳体验，我们建议以下硬件配置：

+   处理器：Intel Core i5 或同等级处理器

+   内存：4GB RAM

+   存储：5GB 可用空间

### 软件要求

我们还建议您提前安装以下软件：

+   Git 最新版本

+   Node.js 10.16.3 LTS ([`nodejs.org/en/`](https://nodejs.org/en/))

### 约定

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

"ES6 的`import`函数还允许您导入模块的子部分，而不是整个模块。这是 ES6 的`import`比 Node.js 的`require`函数更强大的功能。SUSE"

代码块设置如下：

```js
let myString = "hello";
console.log(myString.toUpperCase()); // returns HELLO
console.log(myString.length); // returns 5
```

### 安装和设置

在我们可以使用数据做出了不起的事情之前，我们需要准备好最高效的环境。在这个简短的部分中，我们将看到如何做到这一点。

### 安装 Node.js 和 npm

Node.js 的安装包中包含 npm（Node.js 的默认包管理器）。

**在 Windows 上安装 Node.js**：

1.  在[`nodejs.org/en/download/current/`](https://nodejs.org/en/download/current/)官方安装页面上找到您想要的 Node.js 版本。

1.  确保选择 Node.js 12（当前版本）。

1.  确保您为计算机系统安装了正确的架构；即 32 位或 64 位。您可以在操作系统的**系统属性**窗口中找到这些信息。

1.  下载安装程序后，只需双击文件，然后按照屏幕上的用户友好提示操作即可。

**在 Linux 上安装 Node.js 和 npm**：

在 Linux 上安装 Node.js，您有几个不错的选择：

+   要在未详细介绍的系统上通过 Linux 软件包管理器安装 Node.js，请参阅[`nodejs.org/en/download/package-manager/`](https://nodejs.org/en/download/package-manager)。

+   要在 Ubuntu 上安装 Node.js，请运行此命令（更多信息和手动安装说明可在[`github.com/nodesource/distributions/blob/master/README.md#installation-instructions`](https://github.com/nodesource/distributions/blob/master/README.md#installation-instructions)找到）：

```js
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt-get install -y nodejs
```

+   要在基于 Debian 的发行版上安装 Node.js（更多信息和手动安装说明可在[`github.com/nodesource/distributions/blob/master/README.md#installation-instructions`](https://github.com/nodesource/distributions/blob/master/README.md#installation-instructions)找到）：

```js
# As root
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-get install -y nodejs
```

+   官方 Node.js 安装页面还提供了一些 Linux 系统的其他安装选项：[`nodejs.org/en/download/current/`](https://nodejs.org/en/download/current)。

**在 macOS 上安装 Node.js 和 npm**：

与 Linux 类似，Mac 上安装 Node.js 和 npm 有几种方法。要在 macOS X 上安装 Node.js 和 npm，请执行以下操作：

1.  按下*cmd + Spacebar*打开 Mac 的终端，输入`terminal`并按下*Enter*。

1.  通过运行`xcode-select --install`命令行来安装 Xcode。

1.  安装 Node.js 和 npm 的最简单方法是使用 Homebrew，通过运行`ruby -e "$(curl -fsSL` ([`raw.githubusercontent.com/Homebrew/install/master/install`](https://raw.githubusercontent.com/Homebrew/install/master/install))来安装 Homebrew。

1.  最后一步是安装 Node.js 和 npm。在命令行上运行`brew install node`。

1.  同样，您也可以通过[`nodejs.org/en/download/current/`](https://nodejs.org/en/download/current/)提供的安装程序安装 Node.js 和 npm。

**安装 Git**

安装 git，请前往[`git-scm.com/downloads`](https://git-scm.com/downloads)，并按照针对您平台的说明进行操作。

### 其他资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/Professional-JavaScript`](https://github.com/TrainingByPackt/Professional-JavaScript)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing)找到。快去看看吧！


# 第二章：JavaScript，HTML 和 DOM

## 学习目标

在本章结束时，您将能够：

+   描述 HTML 文档对象模型（DOM）

+   使用 Chrome DevTools 源选项卡来探索网页的 DOM

+   实现 JavaScript 来查询和操作 DOM

+   使用 Shadow DOM 构建自定义组件

在本章中，我们将学习 DOM 以及如何使用 JavaScript 与其交互和操作。我们还将学习如何使用可重用的自定义组件构建动态应用程序。

## 介绍

HTML 最初是用于静态文档的标记语言，易于使用，并且可以使用任何文本编辑器编写。在 JavaScript 成为互联网世界的主要角色之后，有必要将 HTML 文档暴露给 JavaScript 运行时。这就是创建 DOM 的时候。DOM 是将 HTML 映射到可以使用 JavaScript 查询和操作的对象树。

在本章中，您将学习 DOM 是什么以及如何使用 JavaScript 与其交互。您将学习如何在文档中查找元素和数据，如何操作元素状态以及如何修改其内容。您还将学习如何创建 DOM 元素并将其附加到页面上。

了解 DOM 及其如何操作后，您将使用一些示例数据构建动态应用程序。最后，您将学习如何创建自定义 HTML 元素以构建可重用组件，使用 Shadow DOM。

## HTML 和 DOM

当浏览器加载 HTML 页面时，它会创建代表该页面的树。这棵树基于 DOM 规范。它使用标记来确定每个节点的起始和结束位置。

考虑以下 HTML 代码片段：

```js
<html>
  <head>
    <title>Sample Page</title>
  </head>
  <body>
    <p>This is a paragraph.</p>
    <div>
      <p>This is a paragraph inside a div.</p>
    </div>
    <button>Click me!</button>
  </body>
</html>
```

浏览器将创建以下节点层次结构：

![图 1.1：段落节点包含文本节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_01.jpg)

###### 图 1.1：段落节点包含文本节点

一切都变成了节点。文本，元素和注释，一直到树的根部。这棵树用于匹配 CSS 样式并渲染页面。它还被转换为对象，并提供给 JavaScript 运行时使用。

但为什么它被称为 DOM 呢？因为 HTML 最初是设计用来共享文档，而不是设计我们今天拥有的丰富动态应用程序。这意味着每个 HTML DOM 都以一个文档元素开始，所有元素都附加到该元素上。考虑到这一点，前面的 DOM 树示意图实际上变成了以下内容：

![图 1.2：所有 DOM 树都有一个文档元素作为根](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_02.jpg)

###### 图 1.2：所有 DOM 树都有一个文档元素作为根

当我说浏览器使 DOM 可用于 JavaScript 运行时时，这意味着如果您在 HTML 页面中编写一些 JavaScript 代码，您可以访问该树并对其进行一些非常有趣的操作。例如，您可以轻松访问文档根元素并访问页面上的所有节点，这就是您将在下一个练习中要做的事情。

### 练习 1：在文档中迭代节点

在这个练习中，我们将编写 JavaScript 代码来查询 DOM 以查找按钮，并向其添加事件侦听器，以便在用户单击按钮时执行一些代码。事件发生时，我们将查询所有段落元素，计数并存储它们的内容，然后在最后显示一个警报。

此练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson01/Exercise01`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson01/Exercise01)找到。

执行以下步骤完成练习：

1.  打开您喜欢的文本编辑器，并创建一个名为`alert_paragraphs.html`的新文件，其中包含上一节中的示例 HTML（可以在 GitHub 上找到：[`bit.ly/2maW0Sx`](https://bit.ly/2maW0Sx)）：

```js
<html>
  <head>
    <title>Sample Page</title>
  </head>
  <body>
    <p>This is a paragraph.</p>
    <div>
      <p>This is a paragraph inside a div.</p>
    </div>
    <button>Click me!</button>
  </body>
</html>
```

1.  在`body`元素的末尾，添加一个`script`标签，使最后几行看起来像下面这样：

```js
    </div>
    <button>Click me!</button>
    <script>
    </script>
  </body>
</html>
```

1.  在`script`标签内，为按钮的点击事件添加一个事件监听器。为此，你需要查询文档对象以找到所有带有`button`标签的元素，获取第一个（页面上只有一个按钮），然后调用`addEventListener`：

```js
document.getElementsByTagName('button')[0].addEventListener('click', () => {});
```

1.  在事件监听器内部，再次查询文档以查找所有段落元素：

```js
const allParagraphs = document.getElementsByTagName('p');
```

1.  之后，在事件监听器内创建两个变量，用于存储你找到的段落元素的数量和存储它们的内容：

```js
let allContent = "";
let count = 0;
```

1.  迭代所有段落元素，计数它们，并存储它们的内容：

```js
for (let i = 0; i < allParagraphs.length; i++) {  const node = allParagraphs[i];
  count++;
  allContent += `${count} - ${node.textContent}\n`;
}
```

1.  循环结束后，显示一个警报，其中包含找到的段落数和它们所有内容的列表：

```js
alert(`Found ${count} paragraphs. Their content:\n${allContent}`);
```

你可以在这里看到最终的代码应该是什么样子的：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise01/alert_paragraphs.html`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise01/alert_paragraphs.html)。

在浏览器中打开 HTML 文档并点击按钮，你应该会看到以下警报：

![图 1.3：显示页面上段落信息的警报框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_03.jpg)

###### 图 1.3：显示页面上段落信息的警报框

在这个练习中，我们编写了一些 JavaScript 代码，查询了特定元素的 DOM。我们收集了元素的内容，以在警报框中显示它们。

我们将在本章的后续部分探索其他查询 DOM 和迭代节点的方法。但是从这个练习中，你已经可以看到这是多么强大，并开始想象这开启了哪些可能性。例如，我经常使用它来计数或从互联网上的网页中提取我需要的数据。

## 开发者工具

现在我们了解了 HTML 源代码和 DOM 之间的关系，我们可以使用一个非常强大的工具来更详细地探索它：浏览器开发者工具。在本书中，我们将探索谷歌 Chrome 的**DevTools**，但你也可以在所有其他浏览器中轻松找到等效的工具。

我们要做的第一件事是探索我们在上一节中创建的页面。当你在谷歌 Chrome 中打开它时，你可以通过打开**Chrome**菜单来找到开发者工具。然后选择**更多工具**和**开发者工具**来打开开发者工具：

![图 1.4：在谷歌 Chrome 中访问开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_04.jpg)

###### 图 1.4：在谷歌 Chrome 中访问开发者工具

**开发者工具**将在页面底部打开一个面板：

![图 1.5：谷歌 Chrome DevTools 打开时的面板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_05.jpg)

###### 图 1.5：谷歌 Chrome DevTools 打开时的面板

你可以在顶部看到提供加载页面上发生的不同视角的各种选项卡。在本章中，我们将主要关注三个选项卡：

+   **元素** – 显示浏览器看到的 DOM 树。你可以检查浏览器如何查看你的 HTML，CSS 如何被应用，以及哪些选择器激活了每个样式。你还可以改变节点的状态，模拟特定状态，比如`hover`或`visited`：

![图 1.6：元素选项卡的视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_05.jpg)

###### 图 1.6：元素选项卡的视图

+   **控制台** – 在页面的上下文中提供对 JavaScript 运行时的访问。在加载页面后，可以使用控制台来测试简短的代码片段。它还可以用于打印重要的调试信息：

![图 1.7：控制台选项卡的视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_07.jpg)

###### 图 1.7：控制台选项卡的视图

+   **源** – 显示当前页面加载的所有源代码。这个视图可以用来设置断点和开始调试会话：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_08.jpg)

###### 图 1.8：源选项卡的视图

选择**元素**选项卡，你会看到当前文档的 DOM 树：

![图 1.9：在 Chrome DevTools 中查看的元素选项卡中的 DOM 树](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_09.jpg)

###### 图 1.9：在 Chrome DevTools 中查看的元素选项卡中的 DOM 树

### 练习 2：从元素选项卡操作 DOM

为了感受到这个工具有多强大，我们将对*练习 1：遍历文档中的节点*中的页面进行一些更改。我们将在其中添加一个新段落并删除一个现有的段落。然后，我们将使用**样式**侧边栏来更改元素的一些样式。

执行以下步骤完成练习：

1.  首先，*右键单击*`body`元素，然后选择**编辑为 HTML**：![图 1.10：编辑 HTML 主体元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_10.jpg)

###### 图 1.10：编辑 HTML 主体元素

1.  这将把节点更改为一个可以输入的文本框。在第一个段落下面，添加另一个文本为**另一个段落**的段落。它应该看起来像下面这样：![图 1.11：在 HTML 主体中添加一个新段落](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_11.jpg)

###### 图 1.11：在 HTML 主体中添加一个新段落

1.  按下*Ctrl + Enter*（或 Mac 上的*Cmd + Enter*）保存您的更改。

1.  再次单击**点击我！**按钮，您会看到新段落及其内容现在显示在列表中：![图 1.12：显示所有段落内容的警报，包括添加到页面中的段落](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_12.jpg)

###### 图 1.12：显示所有段落内容的警报，包括添加到页面中的段落

1.  您还可以玩弄元素的样式，并在页面上实时看到变化。让我们将第一个段落的背景更改为黑色，颜色更改为白色。首先，通过单击 DOM 树上的它来选择它；它会变成蓝色以表示已选择：![图 1.13：在元素选项卡上选择 DOM 元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_13.jpg)

###### 图 1.13：在元素选项卡上选择 DOM 元素

1.  现在，在右侧，您会看到**样式**选项卡。它包含已应用于元素的样式和一个用于元素样式的空占位符。单击它，您将获得一个输入框。输入**background: black**，按下*Enter*，然后输入**color: white**，再次按下*Enter*。您会看到随着您的输入，元素会发生变化。最终，它将看起来像下面这样：![图 1.14：左侧的样式化段落和右侧的应用样式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_14.jpg)

###### 图 1.14：左侧的样式化段落和右侧的应用样式

1.  您还可以通过单击**样式**选项卡右上角的**新规则按钮**来创建一个应用于页面的新 CSS 规则：![图 1.15：当您单击添加新规则时，它将基于所选元素（在本例中为段落）添加一个新规则](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_15.jpg)

###### 图 1.15：当您单击添加新规则时，它将基于所选元素（在本例中为段落）添加一个新规则

1.  让我们添加类似的规则来影响所有段落，输入**background: green**，按下*Enter*，输入**color: yellow**，然后按下*Enter*。现在除了第一个段落外，所有段落都将具有绿色背景和黄色文本。页面现在应该是这样的：

![图 1.16：向段落添加规则](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_16.jpg)

###### 图 1.16：向段落添加规则

在这个练习中，您改变了页面的 DOM，并实时看到了变化。您向页面添加了元素，更改了一个元素的样式，然后添加了一个新的 CSS 规则来影响更广泛的元素组。

像这样实时操作 DOM 对于您试图弄清布局并测试一些迭代或操作 DOM 元素的代码的情况非常有用。在我们的情况下，我们可以轻松测试如果我们向页面添加一个新段落元素会发生什么。

### 练习 3：从源选项卡调试代码

我们之前提到过，您可以从**源**选项卡调试代码。要做到这一点，您只需要设置一个断点，并确保代码通过该点。在这个练习中，我们将在调试我们的代码时探索**源**选项卡。

执行以下步骤完成练习：

1.  您需要做的第一件事是在“开发者工具”面板中选择“源”选项卡。然后，打开我们目前拥有的一个源文件。您可以通过在左侧面板中点击它来实现这一点：![图 1.17：源选项卡显示了如何找到您的源文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_17.jpg)

###### 图 1.17：源选项卡显示了如何找到您的源文件

1.  要在源代码中设置断点，您需要点击行号所在的边栏，在您想要设置断点的行处点击。在这个练习中，我们将在事件处理程序内的第一行设置一个断点。一个蓝色的箭头符号将出现在那一行上：![图 1.18：断点显示为源文件边栏上的箭头标记](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_18.jpg)

###### 图 1.18：断点显示为源文件边栏上的箭头标记

1.  点击页面上的“点击我！”按钮来触发代码执行。您会注意到发生了两件事情 - 浏览器窗口冻结了，并且有一条消息表明代码已经暂停了：![图 1.19：当浏览器遇到断点时，执行会暂停](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_19.jpg)

###### 图 1.19：当浏览器遇到断点时，执行会暂停

1.  此外，正在执行的代码行在“源”选项卡中得到了突出显示：![图 1.20：源代码中的执行暂停，突出显示将要执行的下一行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_20.jpg)

###### 图 1.20：源代码中的执行暂停，突出显示将要执行的下一行

1.  在侧边栏中，注意当前执行的堆栈和当前作用域中的所有内容，无论是全局还是局部。这是右侧面板的视图，显示了有关运行代码的所有重要信息：![图 1.21：源选项卡右侧显示了当前暂停执行的执行上下文和堆栈跟踪](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_21.jpg)

###### 图 1.21：源选项卡右侧显示了当前暂停执行的执行上下文和堆栈跟踪

1.  顶部的工具栏可以用来控制代码执行。每个按钮的功能如下：

“播放”按钮结束暂停并正常继续执行。

“步过”按钮会执行当前行直到完成，并在下一行再次暂停。

点击“步入”按钮将执行当前行并步入任何函数调用，这意味着它将在被调用的函数内的第一行暂停。

“步出”按钮将执行所有必要的步骤以退出当前函数。

“步”按钮将执行下一个操作。如果是函数调用，它将步入。如果不是，它将继续执行下一行。

1.  按下“步过”按钮，直到执行到第 20 行：![图 1.22：突出显示的行显示了执行暂停以进行调试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_22.jpg)

###### 图 1.22：突出显示的行显示了执行暂停以进行调试

1.  在右侧的“作用域”面板上，您会看到四个作用域：两个“块”作用域，然后一个“局部”作用域和一个“全局”作用域。作用域将根据您在代码中的位置而变化。在这种情况下，第一个“块”作用域仅包括`for`循环内的内容。第二个“块”作用域是整个循环的作用域，包括在`for`语句中定义的变量。“局部”是函数作用域，“全局”是浏览器作用域。这是您应该看到的：![图 1.23：作用域面板显示了当前执行上下文中不同作用域中的所有变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_23.jpg)

###### 图 1.23：作用域面板显示了当前执行上下文中不同作用域中的所有变量

1.  此时要注意的另一件有趣的事情是，如果你将鼠标悬停在当前页面中的 HTML 元素上，Chrome 会为你突出显示该元素：

![图 1.24：Chrome 在不同位置悬停时突出显示 DOM 元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_24.jpg)

###### 图 1.24：Chrome 在不同位置悬停时突出显示 DOM 元素

使用**源**选项卡调试代码是作为 Web 开发人员最重要的事情之一。了解浏览器如何看待你的代码，以及每行中变量的值是解决复杂应用程序中问题的最简单方法。

#### 注意

内联值：当你在**源**选项卡中调试时逐步执行代码时，你会注意到 Chrome 在每行的侧边添加了一些浅橙色的突出显示，显示了在该行中受影响的变量的当前值。

### 控制台选项卡

现在你知道如何在**元素**选项卡中遍历和操作 DOM 树，以及如何在**源**选项卡中探索和调试代码，让我们来探索一下**控制台**选项卡。

**控制台**选项卡可以帮助你调试问题，也可以探索和测试代码。为了了解它能做什么，我们将使用本书代码库中`Lesson01/sample_002`文件夹中的示例商店。

打开商店页面，你会看到这是一个食品产品的商店。它看起来是这样的：

![图 1.25：商店示例页面的屏幕截图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_25.jpg)

###### 图 1.25：商店示例页面的屏幕截图

在底层，你可以看到 DOM 非常简单。它有一个`section`元素，其中包含所有的页面内容。里面有一个带有类项的`div`标签，代表产品列表，以及每个产品的一个带有类项的`div`。在**元素**选项卡中，你会看到这样的内容：

![图 1.26：商店页面的 DOM 树非常简单](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_26.jpg)

###### 图 1.26：商店页面的 DOM 树非常简单

回到**控制台**选项卡：你可以在这个 DOM 中运行一些查询来了解更多关于元素和内容的信息。让我们写一些代码来列出所有产品的价格。首先，我们需要找到 DOM 树中的价格在哪里。我们可以查看**元素**选项卡，但现在，我们将只使用**控制台**选项卡来学习更多。在**控制台**选项卡中运行以下代码将打印一个包含 21 个项目的`HTMLCollection`对象：

```js
document.getElementsByClassName('item')
```

让我们打开第一个，看看里面有什么：

```js
document.getElementsByClassName('item')[0]
```

现在你看到 Chrome 打印了一个 DOM 元素，如果你在上面悬停，你会看到它在屏幕上被突出显示。你也可以打开在**控制台**选项卡中显示的迷你 DOM 树，看看元素是什么样子的，就像在**元素**选项卡中一样：

![图 1.27：控制台选项印刷 DOM 中的元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_27.jpg)

###### 图 1.27：控制台选项印刷 DOM 中的元素

你可以看到价格在一个`span`标签内。要获取价格，你可以像查询根文档一样查询元素。

#### 注意：自动完成和之前的命令

在**控制台**选项卡中，你可以通过按下*Tab*来使用基于当前上下文的自动完成，并通过按上/下箭头键快速访问之前的命令。

运行以下代码来获取列表中第一个产品的价格：

```js
document.getElementsByClassName('item')[0]
  .getElementsByTagName('span')[0].textContent
```

产品的价格将显示在控制台中作为一个字符串：

![图 1.28：查询包含价格的 DOM 元素并获取其内容](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_28.jpg)

###### 图 1.28：查询包含价格的 DOM 元素并获取其内容

### 活动 1：从页面中提取数据

假设您正在编写一个需要来自 Fresh Products Store 的产品和价格的应用程序。商店没有提供 API，其产品和价格大约每周变化一次-不够频繁以证明自动化整个过程是合理的，但也不够慢以至于您可以手动执行一次。如果他们改变了网站的外观方式，您也不想麻烦太多。

您希望以一种简单生成和解析的方式为应用程序提供数据。最终，您得出结论，最简单的方法是生成一个 CSV，然后将其提供给您的应用程序。

在这个活动中，您将编写一些 JavaScript 代码，可以将其粘贴到商店页面的**控制台**选项卡中，并使用它从 DOM 中提取数据，将其打印为 CSV，以便您的应用程序消费。

#### 注意：在控制台选项卡中的长代码

在 Chrome 控制台中编写长代码时，我建议在文本编辑器中进行，然后在想要测试时粘贴它。控制台在编辑代码时并不糟糕，但在尝试修改长代码时很容易搞砸事情。

执行以下步骤：

1.  初始化一个变量来存储 CSV 的整个内容。

1.  查询 DOM 以找到表示每个产品的所有元素。

1.  遍历找到的每个元素。

1.  从`product`元素中，查询带有单位的价格。使用斜杠拆分字符串。

1.  再次，从`product`元素中查询名称。

1.  将所有信息附加到步骤 1 中初始化的变量中，用逗号分隔值。不要忘记为附加的每一行添加换行字符。

1.  使用`console.log`函数打印包含累积数据的变量。

1.  在打开商店页面的**控制台**选项卡中运行代码。

您应该在**控制台**选项卡中看到以下内容：

```js
name,price,unit
Apples,$3.99,lb
Avocados,$4.99,lb
Blueberry Muffin,$2.50,each
Butter,$1.39,lb
...
```

#### 注意

此活动的解决方案可在第 582 页找到。

在这个活动中，您可以使用**控制台**选项卡查询现有页面并从中提取数据。有时，从页面中提取数据非常复杂，而且爬取可能会变得非常脆弱。根据您需要从页面获取数据的频率，可能更容易在**控制台**选项卡中运行脚本，而不是编写一个完整的应用程序。

### 节点和元素

在之前的章节中，我们学习了 DOM 以及如何与其交互。我们看到浏览器中有一个全局文档对象，表示树的根。然后，我们观察了如何查询它以获取节点并访问其内容。

但在前几节探索 DOM 时，有一些对象名称、属性和函数是在没有介绍的情况下访问和调用的。在本节中，我们将深入研究这些内容，并学习如何找到每个对象中可用的属性和方法。

关于本节将讨论的内容，最好的文档位置是 Mozilla 开发者网络网页文档。您可以在[developer.mozilla.org](http://developer.mozilla.org)找到。他们对所有 JavaScript 和 DOM API 都有详细的文档。

节点是一切的起点。节点是表示 DOM 树中的接口。如前所述，树中的一切都是节点。所有节点都有一个`nodeType`属性，用于描述节点的类型。它是一个只读属性，其值是一个数字。节点接口对于每个可能的值都有一个常量。最常见的节点类型如下：

+   `Node.ELEMENT_NODE` - HTML 和 SVG 元素属于这种类型。在商店代码中，如果您从产品中获取`description`元素，您将看到它的`nodeType`属性是`1`，这意味着它是一个元素：

![图 1.29：描述元素节点类型为 Node.ELEMENT_NODE](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_29.jpg)

###### 图 1.29：描述元素节点类型为 Node.ELEMENT_NODE

这是我们从**元素**选项卡中获取的元素：

![图 1.30：在元素选项卡中查看的描述节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_30.jpg)

###### 图 1.30：在元素选项卡中查看的描述节点

+   `Node.TEXT_NODE` - 标签内的文本变成文本节点。如果您从`description`节点获取第一个子节点，您会发现它的类型是`TEXT_NODE`：

![图 1.31：标签内的文本变成文本节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_31.jpg)

###### 图 1.31：标签内的文本变成文本节点

这是在**元素**选项卡中查看的节点：

![图 1.32：在元素选项卡中选择的文本节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_32.jpg)

###### 图 1.32：在元素选项卡中选择的文本节点

+   `Node.DOCUMENT_NODE` - 每个 DOM 树的根是一个`document`节点：

![图 1.33：树的根始终是文档节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_33.jpg)

###### 图 1.33：树的根始终是文档节点

一个重要的事情要注意的是`html`节点不是根节点。当创建 DOM 时，`document`节点是根节点，它包含`html`节点。您可以通过获取`document`节点的第一个子节点来确认：

![图 1.34：html 节点是文档节点的第一个子节点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_34.jpg)

###### 图 1.34：html 节点是文档节点的第一个子节点

`nodeName`是节点具有的另一个重要属性。在`element`节点中，`nodeName`将为您提供它们的 HTML 标签。其他节点类型将返回不同的内容。`document`节点将始终返回`#document`（如前图所示），而`Text`节点将始终返回`#text`。

对于`TEXT_NODE`、`CDATA_SECTION_NODE`和`COMMENT_NODE`等类似文本的节点，您可以使用`nodeValue`来获取它们所包含的文本。

但节点最有趣的地方在于你可以像遍历树一样遍历它们。它们有子节点和兄弟节点。让我们在下面的练习中稍微练习一下这些属性。

### 练习 4：遍历 DOM 树

在这个练习中，我们将遍历*图 1.1*中示例页面中的所有节点。我们将使用递归策略来迭代所有节点并打印整个树。

执行以下步骤以完成练习：

1.  第一步是打开文本编辑器并设置它以编写一些 JavaScript 代码。

1.  要使用递归策略，我们需要一个函数，该函数将被调用以处理树中的每个节点。该函数将接收两个参数：要打印的节点和节点在 DOM 树中的深度。以下是函数声明的样子：

```js
function printNodes(node, level) {
}
```

1.  函数内部的第一件事是开始标识将要打开此节点的消息。为此，我们将使用`nodeName`，对于`HTMLElements`，它将给出标签，对于其他类型的节点，它将给出一个合理的标识符：

```js
let message = `${"-".repeat(4 * level)}Node: ${node.nodeName}`;
```

1.  如果节点也有与之关联的`nodeValue`，比如`Text`和其他文本行节点，我们还将将其附加到消息中，然后将其打印到控制台：

```js
if (node.nodeValue) {
  message += `, content: '${node.nodeValue.trim()}'`;
}
console.log(message);
```

1.  之后，我们将获取当前节点的所有子节点。对于某些节点类型，`childNodes`属性将返回 null，因此我们将添加一个空数组的默认值，以使代码更简单：

```js
var children = node.childNodes || [];
```

1.  现在我们可以使用`for`循环来遍历数组。对于我们找到的每个子节点，我们将再次调用该函数，启动算法的递归性质：

```js
for (var i = 0; i < children.length; i++) {
  printNodes(children[i], level + 1);
}
```

1.  函数内部的最后一件事是打印具有子节点的节点的关闭消息：

```js
if (children.length > 0) {
  console.log(`${"-".repeat(4 * level)}End of:${node.nodeName}`);}
```

1.  现在我们可以通过调用该函数并将文档作为根节点传递，并在函数声明结束后立即将级别设置为零来启动递归：

```js
printNodes(document, 0);
```

最终的代码应该如下所示：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise04/open_close_tree_print.js`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise04/open_close_tree_print.js)。

1.  在 Chrome 中打开示例 HTML。文件位于：[`bit.ly/2maW0Sx`](https://bit.ly/2mMje1K)。

1.  打开**开发者工具**面板，在**控制台**选项卡中粘贴 JavaScript 代码，然后运行。以下是您应该看到的输出：

图 1.35：遍历 DOM 并递归打印所有节点及其子节点

###### 图 1.35：遍历 DOM 并递归打印所有节点及其子节点

在这个练习中，您学会了如何使用递归来逐个节点地遍历整个 DOM 树。您还学会了如何检查节点的属性，因为在遍历整个树时，您会看到不是 HTML 的节点，比如文本和注释。

非常有趣的一点是浏览器还保留了您添加到 HTML 中的空格。以下截图将源代码与练习中打印的树进行了比较：

图 1.36：演示空格也成为 DOM 树中的节点

###### 图 1.36：演示空格也成为 DOM 树中的节点

您可以使用颜色代码查看映射：

+   红色标记了包含标题文本的文本节点。

+   绿色标记了整个`title`元素。

+   蓝色框和箭头标记了`title`元素之前和之后的空格。

#### 注意：注意间隔

在处理 DOM 节点时，非常重要的一点是要记住并非所有节点都是 HTML 元素。有些甚至可能是您没有故意放入文档中的东西，比如换行符。

我们谈论了很多关于节点的内容。您可以查看 Mozilla 开发者网络文档以了解其他节点属性和方法。但您会注意到节点接口主要关注 DOM 树中节点之间的关系，比如兄弟节点和子节点。它们非常抽象。因此，让我们更具体一些，探索`Element`类型的节点。

所有 HTML 元素都被转换为`HTMLElement`节点，它们继承自`Element`，后者又继承自一个节点。它们继承了父类型的所有属性和方法。这意味着元素是一个节点，而`HTMLElement`实例是一个元素。

因为`element`代表一个元素（带有其所有属性和内部标签的标签），所以您可以访问其属性。例如，在`image`元素中，您可以读取`src`属性。以下是获取商店页面第一个`img`元素的`src`属性的示例：

图 1.37：获取页面第一个图像的 src 属性

###### 图 1.37：获取页面第一个图像的 src 属性

HTML 元素还具有的另一个有用属性是`innerHTML`属性。使用它，您可以获取（和设置）元素的 HTML。以下是获取具有`image`类的第一个`div`并打印其`innerHTML`的示例：

图 1.38：innerHTML 可用于访问元素内部的 HTML

###### 图 1.38：innerHTML 可用于访问元素内部的 HTML

还有`outerHTML`属性，它将给出元素本身的 HTML，包括其中的所有内容：

图 1.39：outerHTML 给出了元素及其内部的 HTML

###### 图 1.39：outerHTML 给出了元素及其内部的 HTML

最后但同样重要的是`className`属性，它可以让您访问应用于元素的类：

图 1.40：className 可以访问元素的类

###### 图 1.40：className 可以访问元素的类

关于这些属性更重要的是它们是可读/可写的，这意味着您可以使用它们来修改 DOM，添加类并更改元素的内容。在接下来的部分中，我们将使用这里所学到的内容来创建根据用户交互而变化的动态页面。

### 特殊对象

到目前为止，我们在许多示例和练习中都访问了`document`对象。但它到底是什么，还能做什么？文档是一个代表浏览器中加载的页面的全局对象。正如我们所见，它作为 DOM 树中元素的入口点。

它还有一个我们到目前为止还没有讨论的重要作用，那就是在页面中创建新节点和元素的能力。这些元素可以附加到树的不同位置，以在页面加载后修改它。我们将在接下来的章节中探讨这种能力。

除了`document`，还有另一个对象是 DOM 规范的一部分，那就是`window`对象。`window`对象是一个全局对象，也是所有在浏览器中运行的 JavaScript 代码的绑定目标。这意味着该变量是指向`window`对象的指针：

![图 1.41：浏览器中的全局范围和默认绑定目标是窗口对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_41.jpg)

###### 图 1.41：浏览器中的全局范围和默认绑定目标是窗口对象

`window`对象包含您需要从浏览器访问的所有内容：位置、导航历史、其他窗口（弹出窗口）、本地存储等等。`document`和`console`对象也归属于`window`对象。当您访问`document`对象时，实际上是在使用`window.document`对象，但绑定是隐式的，因此您不需要一直写`window`。而且因为`window`是一个全局对象，这意味着它必须包含对自身的引用：

![图 1.42：窗口对象包含对自身的引用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_42.jpg)

###### 图 1.42：窗口对象包含对自身的引用

### 使用 JavaScript 查询 DOM

我们一直在讨论通过`document`对象查询 DOM。但是我们用来查询 DOM 的所有方法也可以从 DOM 中的元素中调用。本节介绍的方法也可以从 DOM 中的元素中调用。我们还将看到一些只能从元素中而不是`document`对象中使用的方法。

从元素中查询非常方便，因为查询的范围仅限于执行查询的位置。正如我们在*Activity 1, Extracting Data from the DOM*中看到的，我们可以从一个查询开始，找到所有基本元素 - 在这种特定情况下是产品元素，然后我们可以从执行查询的元素中执行一个新的查询，该查询将仅搜索在执行查询的元素内部的元素。

我们在上一节中用来查询 DOM 的方法包括直接从 DOM 中使用`childNodes`列表访问元素，或者使用`getElementsByTagName`和`getElementsByClassName`方法。除了这些方法，DOM 还提供了一些其他非常强大的查询元素的方法。

首先，有`getElement*`方法系列：

+   `getElementsByTagName` - 我们之前见过并使用过这个方法。它获取指定标签的所有元素。

+   `getElementsByClassName` - 这是`getElement`的一个变体，它返回具有指定类的所有元素。请记住，一个元素可以通过用空格分隔它们来包含一个类的列表。以下是在商店页面中运行的代码的屏幕截图，您可以看到选择`ui`类名将获取还具有`items`、`teal`（颜色）和`label`类的元素：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_43.jpg)

###### 图 1.43：按类名获取元素通常返回包含其他类的元素

+   `getElementById` - 注意该方法名称中的单数形式。该方法将获取具有指定 ID 的唯一元素。这是因为在页面上预期 ID 是唯一的。

`getElement*`方法族非常有用。但有时，指定类或标记名称是不够的。这意味着您必须使用一系列操作来使您的代码非常复杂：获取所有具有此类的元素，然后获取具有此其他标记的元素，然后获取具有此类的元素，然后选择第三个，依此类推。

多年来，jQuery 是唯一的解决方案，直到引入了`querySelector`和`querySelectorAll`方法。这两种方法可以用来在 DOM 树上执行复杂的查询。它们的工作方式完全相同。两者之间唯一的区别是`querySelector`只会返回与查询匹配的第一个元素，而`querySelectorAll`会返回一个可以迭代的列表。

`querySelector*`方法使用 CSS 选择器。您可以使用任何 CSS 选择器来查询元素。让我们在下一个练习中更深入地探索一下。

### 练习 5：使用 querySelector 查询 DOM

在这个练习中，我们将探索在之前章节学到的各种查询和节点导航技术。为此，我们将使用商店代码作为基本 HTML 来探索，并编写 JavaScript 代码来查找商店页面上所有有机水果的名称。为了增加难度，有一个标记为有机的蓝莓松饼。

在开始之前，让我们看一下`product`元素及其子元素。以下是从`Elements`选项卡查看的`product`元素的 DOM 树：

![图 1.44：产品元素及其子元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_44.jpg)

###### 图 1.44：产品元素及其子元素

您可以看到每个产品的根元素是一个带有`class`项的`div`标记。名称和标记位于一个带有类 content 的子 div 中。产品的名称位于一个带有类 header 的锚点中。标记是一组带有三个类`ui`、`label`和`teal`的`div`标记。

在处理这样的问题时，您想要查询和过滤一组在一个共同父级下相关的元素时，有两种常见的方法：

+   首先查询根元素，然后进行过滤和查找所需的元素。以下是这种方法的图形表示：

![图 1.45：第一种方法涉及从根元素开始](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_45.jpg)

###### 图 1.45：第一种方法涉及从根元素开始

+   从匹配过滤条件的子元素开始，如果需要，应用额外的过滤，然后导航到您要查找的元素。以下是这种方法的图形表示：

![图 1.46：第二种方法涉及从过滤条件开始](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_46.jpg)

###### 图 1.46：第二种方法涉及从过滤条件开始

执行以下步骤完成练习：

1.  为了使用第一种方法解决练习，我们需要一个函数来检查产品是否包含指定的标签列表。这个函数的名称将是`the`，它接收两个参数-产品根元素和要检查的标签列表：

```js
function containLabels(element, ...labelsToCheck) {
}
```

1.  在这个函数中，我们将使用一些数组映射和过滤来找到参数中指定的标签和被检查产品的标签之间的交集：

```js
const intersection = Array.from(element.querySelectorAll('.label'))
  .map(e => e.innerHTML)
  .filter(l => labelsToCheck.includes(l));
```

1.  函数中的最后一件事是返回一个检查，告诉我们产品是否包含所有标签。检查告诉我们交集的大小是否与要检查的所有标签的大小相同，如果是，我们就有一个匹配：

```js
return intersection.length == labelsToCheck.length;
```

1.  现在我们可以使用查询方法来查找元素，将它们添加到数组中，进行过滤和映射到我们想要的内容，然后打印到控制台：

```js
//Start from the product root element
Array.from(document.querySelectorAll('.item'))
//Filter the list to only include the ones with both labels
.filter(e => containLabels(e, 'organic', 'fruit'))
//Find the product name
.map(p => p.querySelector('.content a.header'))
.map(a => a.innerHTML)
//Print to the console
.forEach(console.log);
```

1.  要使用第二种方法解决问题，我们需要一个函数来查找指定元素的所有兄弟元素。打开您的文本编辑器，让我们从声明带有数组的函数开始存储我们找到的所有兄弟元素。然后，我们将返回数组：

```js
function getAllSiblings(element) {
  const siblings = [];
  // rest of the code goes here
  return siblings;
}
```

1.  然后，我们将使用`while`循环和`previousElementSibling`属性迭代所有先前的兄弟元素。在迭代兄弟元素时，我们将它们推入数组中：

```js
let previous = element.previousElementSibling;
while (previous) {
  siblings.push(previous);
  previous = previous.previousElementSibling;
}
```

#### 注意：再次注意间隙

我们使用`previousElementSibling`而不是`previousNode`，因为这将排除所有文本节点和其他节点，以避免不得不为每个节点检查`nodeType`。

1.  对于指定元素之后的所有兄弟元素，我们做同样的操作：

```js
let next = element.nextElementSibling;
while (next) {
  siblings.push(next);
  next = next.nextElementSibling;
}
```

1.  现在我们有了`getAllSiblings`函数，我们可以开始查找产品。我们可以使用`querySelectorAll`函数，以及一些数组映射和过滤来找到并打印我们想要的数据：

```js
//Start by finding all the labels with content 'organic'
Array.from(document.querySelectorAll('.label'))
.filter(e => e.innerHTML === 'organic')
//Filter the ones that don't have a sibling label 'fruit'
.filter(e => getAllSiblings(e).filter(s => s.innerHTML === 'fruit').length > 0)
//Find root product element
.map(e => e.closest('.item'))
//Find product name
.map(p => p.querySelector('.content a.header').innerHTML)
//Print to the console
.forEach(console.log);
```

1.  在**开发者工具**的**控制台**选项卡中执行代码，您将看到以下输出：

![图 1.47：练习中代码的输出。打印所有有机水果的名称。](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_47.jpg)

###### 图 1.47：练习中代码的输出。打印所有有机水果的名称。

#### 注意

此练习的代码可以在 GitHub 上找到。包含第一种方法代码的文件路径是：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise05/first_approach.js`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise05/first_approach.js)。

包含第二种方法代码的文件路径是：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise05/second_approach.js`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise05/second_approach.js)。

在这个练习中，我们使用了两种不同的技术从页面中获取数据。我们使用了许多查询和节点导航方法和属性来查找元素并在 DOM 树中移动。

当构建现代 Web 应用程序时，了解这些技术是至关重要的。在这种类型的应用程序中，导航 DOM 和获取数据是最常见的任务。

### 操作 DOM

现在我们知道了 DOM 是什么，以及如何查询元素和在其周围导航，是时候学习如何使用 JavaScript 来更改它了。在本节中，我们将重写商店前端，通过使用 JavaScript 加载产品列表并创建页面元素，使其更具交互性。

本节的示例代码可以在 GitHub 上找到：[`bit.ly/2mMje1K`](https://bit.ly/2mMje1K)。

在使用 JavaScript 创建动态应用程序时，我们需要知道的第一件事是如何创建新的 DOM 元素并将它们附加到树中。由于 DOM 规范完全基于接口，没有具体的类可实例化。当您想要创建 DOM 元素时，需要使用`document`对象。`document`对象有一个名为`createElement`的方法，它接收一个标签名称作为字符串。以下是创建`div`元素的示例代码：

```js
const root = document.createElement('div');
```

`product`项元素具有`item`类。要将该类添加到它，我们只需设置`className`属性，如下所示：

```js
root.className = 'item';
```

现在我们可以将元素附加到需要去的地方。但首先，我们需要找到它需要去的地方。此示例代码的 HTML 可以在 GitHub 上找到[`bit.ly/2nKucVo`](https://bit.ly/2nKucVo)。您可以看到它有一个空的`div`元素，产品项将被添加到其中：

```js
<div class="ui items"></div>
```

我们可以使用`querySelector`来找到该元素，然后在其上调用`appendChild`方法，这是每个节点都有的方法，并将刚刚创建的元素节点传递给它，以便将其添加到 DOM 树中：

```js
const itemsEl = document.querySelector('.items');
products.forEach((product) => {
  itemsEl.appendChild(createProductItem(product));
});
```

在这里，`createProductItem`是一个函数，它接收一个产品并使用先前提到的`createElement`函数为其创建 DOM 元素。

创建一个 DOM 元素并没有太大的用处。对于动态商店示例，我们有一个包含我们构建页面所需的所有数据的对象数组。对于每一个对象，我们需要创建所有的 DOM 元素，并将它们粘合在正确的位置和顺序上。但首先，让我们来看看数据是什么样子的。以下显示了每个`product`对象的外观：

```js
{
  "price": 3.99,
  "unit": "lb",
  "name": "Apples",
  "description": "Lorem ipsum dolor sit amet, ...",
  "image": "../images/products/apples.jpg",
  "tags": [ "fruit", "organic" ]
}
```

以下是我们在之前章节中使用的静态商店代码中相同产品的 DOM 看起来的方式：

![图 1.48：产品的 DOM 树部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_48.jpg)

###### 图 1.48：产品的 DOM 树部分

您可以看到有许多嵌套的元素需要创建才能得到所需的最终 DOM 树。因此，让我们看看在使用 JavaScript 构建复杂应用程序时非常有用的一些技术。

让我们开始看一下示例代码中的`createProductItem`：

```js
function createProductItem(product) {
  const root = document.createElement('div');
  root.className = 'item';
  root.appendChild(createProductImage(product.image));
  root.appendChild(createContent(product));
  return root;
}
```

我们通过创建产品树的根元素开始这个方法，这是一个`div`元素。从前面的截图中，您可以看到这个`div`需要一个`item`类，这就是在元素创建后的下一行发生的事情，就像本节开头描述的那样。

元素准备好后，就可以开始向其添加子元素了。我们不是在同一个方法中完成所有操作，而是创建其他负责创建每个子元素的函数，并直接调用它们，将每个函数的结果附加到根元素：

```js
root.appendChild(createProductImage(product.image));
root.appendChild(createContent(product));
```

这种技术很有用，因为它将每个子元素的逻辑隔离在自己的位置上。

现在让我们来看一下`createProductImage`函数。从之前的示例代码中，您可以看到该函数接收`product`图像的路径。这是该函数的代码：

```js
function createProductImage(imageSrc) {
  const imageContainer = document.createElement('div');
  imageContainer.className = 'image';
  const image = document.createElement('img');
  image.setAttribute('src', imageSrc);
  imageContainer.appendChild(image);
  return imageContainer;
}
```

该函数分为两个主要部分：

1.  它创建图像的容器元素。从 DOM 截图中，您可以看到`img`元素位于一个带有`image`类的`div`内。

1.  它创建`img`元素，设置`src`属性，然后将其附加到`container`元素。

这种代码风格简单、可读且易于理解。但这是因为需要生成的 HTML 相当简短。它只是一个`div`标签中的一个`img`标签。

不过，有时树变得非常复杂，使用这种策略使得代码几乎无法阅读。因此，让我们看看另一种策略。附加到产品根元素的另一个子元素是`content`元素。这是一个具有许多子元素的`div`标签，包括一些嵌套的子元素。

我们可以像`createProductImage`函数一样处理它。但是该方法需要执行以下操作：

1.  创建`container`元素并为其添加一个类。

1.  创建包含产品名称的锚元素并将其附加到容器。

1.  创建价格的容器并将其附加到根容器。

1.  创建带有价格的`span`元素并将其附加到上一步中创建的元素。

1.  创建包含描述的元素并将其附加到容器。

1.  为`tag`元素创建`container`元素并将其附加到根容器。

1.  对于每个标签，创建`tag`元素并将其附加到上一步中的容器。

听起来像是一长串步骤，不是吗？我们可以使用模板字符串来生成 HTML，然后为容器元素设置`innerHTML`，而不是试图编写所有那些代码。因此，步骤看起来会像下面这样：

1.  创建`container`元素并为其添加一个类。

1.  使用字符串模板创建内部内容的 HTML。

1.  在`container`元素上设置`innerHTML`。

这听起来比以前的方法简单得多。而且，正如我们将看到的那样，它也会更加可读。让我们来看看代码。

如前所述，第一步是创建根容器并为其添加类：

```js
function createContent(product) {
  const content = document.createElement('div');
  content.className = 'content';
```

然后，我们开始生成`tag`元素的 HTML。为此，我们有一个函数，它接收标签作为字符串并返回其 HTML 元素。我们使用它将所有标签映射到使用`tags`数组上的`map`函数的元素。然后，我们通过使用其`outerHTML`属性将元素映射到 HTML：

```js
 const tagsHTML = product.tags.map(createTagElement)
    .map(el => el.outerHTML)
    .join('');
```

有了`container`元素创建和标签的 HTML 准备好后，我们可以使用模板字符串设置`content`元素的`innerHTML`属性并返回它：

```js
  content.innerHTML = `
    <a class="header">${product.name}</a>
    <div class="meta"><span>$${product.price} / ${product.unit}</span></div>
    <div class="description">${product.description}</div>
    <div class="extra">${tagsHTML}</div>
  `;
  return content;
}
```

与生成 HTML 元素并附加它们所需的许多步骤相比，这段代码要简短得多，更容易理解。在编写动态应用程序时，您可以决定在每种情况下哪种方式最好。在这种情况下，权衡基本上是可读性和简洁性。但对于其他情况，权衡也可以是根据某些过滤器要求缓存元素以添加事件侦听器或隐藏/显示它们。

### 练习 6：过滤和搜索产品

在这个练习中，我们将为我们的商店应用程序添加两个功能，以帮助我们的客户更快地找到产品。首先，我们将使标签可点击，这将通过所选标签过滤产品列表。然后，我们将在顶部添加一个搜索框，供用户按名称或描述查询。页面将如下所示：

![图 1.49：顶部带有搜索栏的新商店前端](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_49.jpg)

###### 图 1.49：顶部带有搜索栏的新商店前端

在这个新的商店前端，用户可以点击标签来过滤具有相同标签的产品。当他们这样做时，用于过滤列表的标签将显示在顶部，呈橙色。用户可以点击搜索栏中的标签以删除过滤器。页面如下所示：

![图 1.50：顶部标签过滤的工作原理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_50.jpg)

###### 图 1.50：顶部标签过滤的工作原理

用户还可以使用右侧的搜索框按名称或描述搜索产品。随着他们的输入，列表将被过滤。

此练习的代码可以在 GitHub 上找到：[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson01/Exercise06`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson01/Exercise06)。

执行以下步骤以完成练习：

1.  我们将首先编写基本的 HTML 代码，稍后将使用 JavaScript 添加所有其他元素。此 HTML 现在包含一个基本的`div`容器，其中将包含所有内容。其中的内容分为两部分：一个包含标题的部分，其中包含标题和搜索栏，以及一个`div`，其中将包含所有产品项目。创建一个名为`dynamic_storefront.html`的文件，并在其中添加以下代码：

```js
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="../css/semantic.min.css" />
    <link rel="stylesheet" type="text/css" href="../css/store_with_header.css" />
  </head>
  <body>
    <div id="content">
      <section class="header">
        <h1 class="title">Welcome to Fresh Products Store!</h1>
        <div class="ui menu">
          <div class="right item">
            <div class="ui icon input">
              <input type="text" placeholder="Search..." />
              <i class="search icon"></i>
            </div>
          </div>
        </div>
      </section>
      <div class="ui items"></div>
    </div>
    <script src="../data/products.js"></script>
    <script src="../sample_003/create_elements.js"></script>
    <script src="filter_and_search.js"></script>
  </body>
</html>
```

此 HTML 使用了`products.js`和`create_elements.js`脚本，这与本节中使用的示例代码相同。它还使用了`Lesson01`文件夹中的 CSS 文件。如果您在同一个文件夹中，可以直接参考它们，或者将它们复制粘贴到您的项目中。

1.  创建一个名为`filter_and_search.js`的文件，这是在 HTML 代码中加载的最后一个 JavaScript 代码。这是我们将为此练习添加所有代码的地方。我们需要做的第一件事是存储过滤器状态。用户可以应用到页面的两种可能过滤器：选择标签和/或输入一些文本。为了存储它们，我们将使用一个数组和一个字符串变量：

```js
const tagsToFilterBy = [];
let textToSearch = '';
```

1.  现在我们将创建一个函数，该函数将为页面中的所有标签添加事件侦听器。此函数将查找所有`tag`元素，将它们包装在一个数组中，并使用`Element`中的`addEventListener`方法添加事件侦听器以响应`click`事件：

```js
function addTagFilter() {
  Array.from(document.querySelectorAll('.extra .label')).forEach(tagEl => {
    tagEl.addEventListener('click', () => {
      // code for next step goes here
    });
  });
}
```

1.  在事件侦听器中，我们将检查标签是否已经在要按其进行过滤的标签数组中。如果没有，我们将添加它并调用另一个名为`applyTagFilters`的函数：

```js
if (!tagsToFilterBy.includes(tagEl.innerHTML)) {
  tagsToFilterBy.push(tagEl.innerHTML);
  applyFilters();
}
```

1.  `applyFilters`只是一个包含与更新页面相关的所有逻辑的捕捉函数。您将只调用我们将在接下来的步骤中编写的函数：

```js
function applyFilters() {
  createListForProducts(filterByText(filterByTags(products)));
  addTagFilter();
  updateTagFilterList();
}
```

1.  在继续`applyFilters`函数之前，我们将添加另一个函数来处理文本搜索输入框上的事件。这个处理程序将监听`keyup`事件，当用户完成输入每个字母时触发。处理程序将获取输入框中的当前文本，将值设置为`textToSearch`变量，并调用`applyFilters`函数：

```js
function addTextSearchFilter() {
  document.querySelector('.menu .right input'
.addEventListener('keyup', (e) => {
      textToSearch = e.target.value;
      applyFilters();
    });
}
```

1.  现在，回到`applyFilters`函数。在其中调用的第一个函数几乎是隐藏的。这就是`filterByTags`函数，它使用`tagsToFilterBy`数组对产品列表进行过滤。它使用递归的方式对传入的产品列表使用选择的标签进行过滤：

```js
function filterByTags() {
  let filtered = products;
  tagsToFilterBy
    .forEach((t) => filtered = filtered.filter(p => p.tags.includes(t)));
  return filtered;
}
```

1.  无论过滤函数的输出是什么，都会传递给另一个过滤函数，即基于文本搜索过滤产品的函数。`filterByText`函数在比较之前将所有文本转换为小写。这样，搜索将始终不区分大小写：

```js
function filterByText(products) {
  const txt = (textToSearch || '').toLowerCase();
  return products.filter((p) => {
    return p.name.toLowerCase().includes(txt)
      || p.description.toLowerCase().includes(txt);
  });
}
```

在通过选择的标签进行过滤和通过输入的文本进行过滤之后，我们将过滤后的数值传递给`createListForProducts`，这是`create_elements.js`中的一个函数，在本节练习之前已经描述过。

1.  现在我们已经在页面上显示了新产品列表，我们需要重新注册标签过滤器事件监听器，因为 DOM 树元素已经被重新创建。所以我们再次调用`addTagFilter`。如前所示，这就是`applyFilters`函数的样子：

```js
function applyFilters() {
  createListForProducts(filterByText(filterByTags(products)));
  addTagFilter();
  updateTagFilterList();
}
```

1.  `applyTagFilter`函数中调用的最后一个函数是`updateTagFilterList`。此函数将找到将保存过滤器指示器的元素，检查是否有选定的标签进行过滤，并相应地进行更新，要么将文本设置为`无过滤器`，要么为每个应用的标签添加指示器：

```js
function updateTagFilterList() {
  const tagHolder = document.querySelector('.item span.tags');
  if (tagsToFilterBy.length == 0) {
    tagHolder.innerHTML = 'No filters';
  } else {
    tagHolder.innerHTML = '';
    tagsToFilterBy.sort();
    tagsToFilterBy.map(createTagFilterLabel)
      .forEach((tEl) => tagHolder.appendChild(tEl));
  }
}
```

1.  我们需要将所有这些联系在一起的最后一个函数是`createTagFilterLabel`函数，它用于在搜索栏中创建标签被选中的指示器。此函数将创建 DOM 元素并添加一个事件侦听器，当单击时，将从数组中删除标签并再次调用`applyTagFilter`函数：

```js
function createTagFilterLabel(tag) {
  const el = document.createElement('span');
  el.className = 'ui label orange';
  el.innerText = tag;
  el.addEventListener('click', () => {
    const index = tagsToFilterBy.indexOf(tag);
    tagsToFilterBy.splice(index, 1);
    applyTagFilter();
  });

  return el;
}
```

1.  使页面工作的最后一步是调用`applyTagFilter`函数，以便将页面更新到初始状态，即未选择任何标签。此外，它将调用`addTextSearchFilter`以添加文本框的事件处理程序：

```js
addTextSearchFilter();
applyFilters();
```

在 Chrome 中打开页面，您会看到顶部的过滤器为空，并且所有产品都显示在列表中。它看起来像本练习开头的截图。单击一个标签或在文本框中输入内容，您会看到页面更改以反映新状态。例如，选择两个**饼干**和**面包店**标签，并在文本框中输入**巧克力**，页面将只显示具有这两个标签和名称或描述中包含**巧克力**的产品：

![图 1.51：商店前端通过两个面包店和饼干标签以及单词巧克力进行过滤](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_51.jpg)

###### 图 1.51：商店前端通过两个面包店和饼干标签以及单词巧克力进行过滤

在本练习中，您已经学会了如何响应用户事件并相应地更改页面，以反映用户希望页面处于的状态。您还学会了当元素被移除并重新添加到页面时，事件处理程序会丢失并需要重新注册。

### 影子 DOM 和 Web 组件

在之前的部分中，我们已经看到一个简单的 Web 应用可能需要复杂的编码。当应用程序变得越来越大时，它们变得越来越难以维护。代码开始变得混乱，一个地方的变化会影响其他意想不到的地方。这是因为 HTML、CSS 和 JavaScript 的全局性质。

已经创建了许多解决方案来尝试规避这个问题，**万维网联盟**（**W3C**）开始着手提出标准的方式来创建自定义的、隔离的组件，这些组件可以拥有自己的样式和 DOM 根。Shadow DOM 和自定义组件是从这一倡议中诞生的两个标准。

Shadow DOM 是一种创建隔离的 DOM 子树的方式，可以拥有自己的样式，并且不受添加到父树的样式的影响。它还隔离了 HTML，这意味着在文档树上使用的 ID 可以在每个影子树中多次重用。

以下图示了处理 Shadow DOM 时涉及的概念：

![图 1.52：Shadow DOM 概念](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_52.jpg)

###### 图 1.52：Shadow DOM 概念

让我们描述一下这些概念的含义：

+   **文档树**是页面的主要 DOM 树。

+   **影子宿主**是附加影子树的节点。

+   **影子树**是附加到文档树的隔离 DOM 树。

+   **影子根**是影子树中的根元素。

影子宿主是文档树中附加影子树的元素。影子根元素是一个不显示在页面上的节点，就像主文档树中的文档对象一样。

要理解这是如何工作的，让我们从一些具有奇怪样式的 HTML 开始：

```js
<style>
  p {
    background: #ccc;
    color: #003366;
  }
</style>
```

这将使页面上的每个段落都具有灰色背景，并带有一些蓝色文字。这是页面上段落的样子：

![图 1.53：应用了样式的段落](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_53.jpg)

###### 图 1.53：应用了样式的段落

让我们添加一个影子树，并在其中添加一个段落，看看它的行为。我们将使用`div`元素将段落元素包装起来，并添加一些文本：

```js
<div><p>I'm in a Shadow DOM tree.</p></div>
```

然后我们可以在元素中使用`attachShadow`方法创建一个影子根元素：

```js
const shadowHost = document.querySelector('div');
const shadowRoot = shadowHost.attachShadow({ mode: 'open' });
```

上面的代码选择了页面上的`div`元素，然后调用`attachShadow`方法，将配置对象传递给它。配置表示这个影子树是打开的，这意味着可以通过元素的`shadowRoot`属性访问它的影子根元素 - 在这种情况下是`div`：

![图 1.54：可以通过附加树的元素访问打开的影子树](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_54.jpg)

###### 图 1.54：可以通过附加树的元素访问打开的影子树

影子树可以关闭，但不建议采用这种方法，因为这会产生一种虚假的安全感，并且会让用户的生活变得更加困难。

在我们将影子树附加到文档树后，我们可以开始操纵它。让我们将影子宿主中的 HTML 复制到影子根中，看看会发生什么：

```js
shadowRoot.innerHTML = shadowHost.innerHTML;
```

现在，如果您在 Chrome 中加载页面，您会看到以下内容：

![图 1.55：加载了影子 DOM 的页面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_55.jpg)

###### 图 1.55：加载了影子 DOM 的页面

您可以看到，即使向页面添加了样式来选择所有段落，但向影子树添加的段落不受其影响。Shadow DOM 中的元素与文档树完全隔离。

现在，如果您查看 DOM，您会发现有些地方看起来很奇怪。影子树替换并包装了原来在`div`元素内部的段落，这就是影子宿主：

![图 1.56：影子树与影子宿主中的其他节点处于同一级别](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_56.jpg)

###### 图 1.56：影子树与影子宿主中的其他节点处于同一级别

但是影子宿主内部的原始段落不会在页面上呈现。这是因为当浏览器渲染页面时，如果元素包含具有新内容的影子树，它将替换宿主下的当前树。这个过程称为平铺，下面的图表描述了它的工作原理：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_57.jpg)

###### 图 1.57：平铺时，浏览器会忽略影子宿主下的节点

现在我们了解了 Shadow DOM 是什么，我们可以开始使用它来构建或者自己的 HTML 元素。没错！通过自定义组件 API，你可以创建自己的 HTML 元素，然后像任何其他元素一样使用它。

在本节的其余部分，我们将构建一个名为**counter**的自定义组件，它有两个按钮和中间的文本。你可以点击按钮来增加或减少存储的值。你还可以配置它具有初始值和不同的增量值。下面的屏幕截图显示了组件完成后的外观。这个代码存放在 GitHub 上，网址是[`bit.ly/2mVy1XP`](https://bit.ly/2mVy1XP)：

![图 1.58：计数器组件及其在 HTML 中的使用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_58.jpg)

###### 图 1.58：计数器组件及其在 HTML 中的使用

要定义你的自定义组件，你需要在自定义组件注册表中调用`define`方法。有一个名为`customElements`的全局注册表实例。要注册你的组件，你调用`define`，传递你的组件将被引用的字符串。它至少需要有一个破折号。你还需要传递实例化你的组件的构造函数。下面是代码：

```js
customElements.define('counter-component', Counter);
```

你的构造函数可以是一个普通函数，或者，就像这个例子中一样，你可以使用新的 JavaScript `class`定义。它需要扩展`HTMLElement`：

```js
class Counter extends HTMLElement {
}
```

为了使自定义组件与页面的其余部分隔离，你可以使用一个阴影树，其中阴影主机是你的组件元素。你不需要使用 Shadow DOM 来构建自定义组件，但建议对于更复杂的组件也包装一些样式。

在你的元素的构造函数中，通过调用`attachShadow`来创建自己的实例的阴影根：

```js
constructor() {
  super(); // always call super first
  // Creates the shadow DOM to attach the parts of this component
  this.attachShadow({mode: 'open'});
  // ... more code here
}
```

记住，当你使用`open`模式将阴影 DOM 附加到元素时，元素将把该阴影根存储在`shadowRoot`属性中。所以，从现在开始我们可以使用`this.shadowRoot`来引用它。

在前面的图中，你看到`counter`组件有两个属性，它用来配置自身：`value`和`increment`。这些属性在构造函数的开始使用`Element`的`getAttribute`方法设置，并在没有可用时设置合理的默认值：

```js
this.value = parseInt(this.getAttribute('value') || 0);
this.increment = parseInt(this.getAttribute('increment') || 1);
```

之后，我们为这个组件创建了所有的 DOM 元素，并将它们附加到阴影根。我们不会深入细节，因为你现在已经看到了足够的 DOM 操作。在构造函数中，我们只是调用创建这些元素的函数，并使用`this.shadowRoot.appendChild`将它们附加：

```js
// Create and attach the parts of this component
this.addStyles();
this.createButton('-', () => this.decrementValue());
this.createValueSpan();
this.createButton('+', () => this.incrementValue());
```

第一个方法创建一个`link`元素，导入`counter`组件的 CSS 文件。第二和第四个方法创建`decrement`和`increment`按钮，并附加事件处理程序。第三个方法创建一个`span`元素，并在`property`下保留对它的引用。

`incrementValue`和`decrementValue`方法通过指定的数量增加当前值，然后调用`updateState`方法，将值的状态与 DOM（在这种情况下是 Shadow DOM）同步。`incrementValue`和`updateState`方法的代码如下：

```js
incrementValue() {
  this.value += this.increment;
  this.triggerValueChangedEvent();
  this.updateState();
}
updateState() {
  this.span.innerText = `Value is: ${this.value}`;
}
```

在`incrementValue`函数中，我们还调用函数来触发事件，通知用户值已经改变。这个函数将在后面讨论。

现在你已经定义并注册了你的新的`HTMLElement`，你可以像任何其他现有的 HTML 元素一样使用它。你可以通过 HTML 代码中的标签添加它，如下所示：

```js
<counter-component></counter-component>
<counter-component value="7" increment="3"></counter-component>
```

或者，通过 JavaScript，通过创建一个元素并将其附加到 DOM 中：

```js
const newCounter = document.createElement('counter-component');
newCounter.setAttribute('increment', '2');
newCounter.setAttribute('value', '3');
document.querySelector('div').appendChild(newCounter);
```

要完全理解 Web 组件的强大之处，还有两件事情你需要知道：回调和事件。

自定义组件有生命周期回调，你可以在你的类中设置它们，以便在它们周围的事情发生变化时得到通知。最重要的两个是`connectedCallback`和`attributeChangedCallback`。

第一个对于当你想要在组件附加到 DOM 后操纵 DOM 时很有用。对于**counter**组件，我们只是在控制台上打印一些东西，以显示组件现在连接到了 DOM：

```js
connectedCallback() {
  console.log("I'm connected to the DOM!");
}
```

当页面加载时，你可以看到为每个**counter**组件添加到 DOM 中打印的语句：

![图 1.59：当计数器组件附加到 DOM 时在控制台中打印的语句](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_59.jpg)

###### 图 1.59：当计数器组件附加到 DOM 时在控制台中打印的语句

`attributeChangedCallback`在组件中的某个属性被更改时被调用。但是为了让它工作，你需要一个静态的 getter，它会告诉你想要被通知属性的更改。以下是静态 getter 的代码：

```js
static get observedAttributes() {
  return ['value', 'increment'];
}
```

它只是返回一个包含我们想要被通知的所有属性的数组。`attributeChangedCallback`接收几个参数：更改的属性名称，旧值（如果没有设置，则为 null），和新值。以下是**counter**组件的回调代码：

```js
attributeChangedCallback(attribute, _, newValue) {
  switch(attribute) {
    case 'increment':
      this.increment = parseInt(newValue);
      break;
    case 'value':
      this.value = parseInt(newValue);
      break;
  }
  this.updateState();
}
```

我们的回调检查属性名称，忽略旧值，因为我们不需要它，将其转换为整数，解析为整数，并根据属性的名称相应地设置新值。最后，它调用`updateState`函数，该函数将根据其属性更新组件的状态。

关于网络组件的最后一件事是你需要知道如何分发事件。事件是标准组件的重要部分；它们构成了与用户的所有交互的基础。因此，将逻辑封装到组件中的一个重要部分是理解你的组件的用户将对哪些事件感兴趣。

对于我们的**counter**组件，每当值更改时分发事件是非常有意义的。在事件中传递值也是有用的。这样，用户就不需要查询你的组件来获取当前值。

要分发自定义事件，我们可以使用`Element`的`dispatchEvent`方法，并使用`CustomEvent`构造函数来使用自定义数据构建我们的事件。我们的事件名称将是`value-changed`。用户可以添加事件处理程序来监听此事件，并在值更改时收到通知。

以下代码是`triggerValueChangedEvent`函数，之前提到过；这个函数从`incrementValue`和`decrementValue`函数内部调用： 

```js
triggerValueChangedEvent() {
  const event = new CustomEvent('value-changed', { 
    bubbles: true,
    detail: { value: this.value },
  });
  this.dispatchEvent(event);
}
```

这个函数创建了一个`CustomEvent`的实例，它在 DOM 中冒泡，并在`detail`属性中包含当前值。我们本可以创建一个普通的事件实例，并直接在对象上设置属性，但是对于自定义事件，建议使用`CustomEvent`构造函数，它可以正确处理自定义数据。创建事件后，调用`dispatchEvent`方法，传递事件。

现在我们已经发布了事件，我们可以注册并在页面上显示信息。以下是查询所有`counter-components`并为`value-changed`事件添加事件侦听器的代码。处理程序在每次单击组件时向现有的`div`添加一个段落：

```js
const output = document.getElementById('output');
Array.from(document.querySelectorAll('counter-component'))
  .forEach((el, index) => {
    el.addEventListener('value-changed', (e) => {
    output.innerHTML += '<p>Counter ${index} value is now ${e.detail.value}</p>';
  });
});
```

这是在不同计数器上点击几次后页面的外观：

![图 1.60：页面上添加的段落，显示计数器被点击](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_60.jpg)

###### 图 1.60：页面上添加的段落，显示计数器被点击

### 练习 7：用网络组件替换搜索框

要完全理解网络组件的概念，你需要看看一个应用程序如何被分解为封装的、可重用的组件。我们在上一个练习中构建的商店页面是我们开始的好地方。

在这个练习中，我们将编写一个网络组件，以替换页面右上角的搜索框。这就是我们谈论的组件：

![图 1.61：将转换为 Web 组件的搜索框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_01_61.jpg)

###### 图 1.61：将转换为 Web 组件的搜索框

这个组件将处理它的外观、渲染和状态，并在状态改变时发出事件。在这种情况下，搜索框只有一个状态：**搜索**文本。

执行以下步骤以完成练习：

1.  将代码从`Exercise 6`复制到一个新文件夹中，这样我们就可以在不影响现有 storefront 的情况下进行更改。

1.  让我们开始创建一个 Web 组件。创建一个名为`search_box.js`的文件，添加一个名为`SearchBox`的新类，并使用这个类定义一个新组件：

```js
class SearchBox extends HTMLElement {
}
customElements.define('search-box', SearchBox);
```

1.  在类中，添加一个构造函数，调用`super`，并将组件附加到一个影子根。构造函数还将通过设置一个名为`_searchText`的变量来初始化状态：

```js
constructor() {
  super();
  this.attachShadow({ mode: 'open' });
  this._searchText = '';
}
```

1.  为了公开当前状态，我们将为`_searchText`字段添加一个 getter：

```js
get searchText() {
  return this._searchText;
```

1.  仍然在类中，创建一个名为`render`的方法，它将把`shadowRoot.innerHTML`设置为我们想要的模板组件。在这种情况下，它将是搜索框的现有 HTML 加上一个指向 semantic UI 样式的链接，以便我们可以重用它们：

```js
render() {
  this.shadowRoot.innerHTML = '
    <link rel="stylesheet" type="text/css" href="../css/semantic.min.css" />
    <div class="ui icon input">
      <input type="text" placeholder="Search..." />
      <i class="search icon"></i>
    </div>
  ';
}
```

1.  创建另一个名为`triggerTextChanged`的方法，它将触发一个事件来通知监听器搜索文本已更改。它接收新的文本值并将其传递给监听器：

```js
triggerTextChanged(text) {
  const event = new CustomEvent('changed', {
    bubbles: true,
    detail: { text },
  });
  this.dispatchEvent(event);
}
```

1.  在构造函数中，在附加影子根后，调用`render`方法并注册一个监听器到输入框，以便我们可以为我们的组件触发 changed 事件。构造函数现在应该是这样的：

```js
constructor() {
  super();
  this.attachShadow({ mode: 'open' });
  this._searchText = '';
  this.render();
  this.shadowRoot.querySelector('input').addEventListener('keyup', (e) => {
    this._searchText = e.target.value;
    this.triggerTextChanged(this._searchText);
  });
}
```

1.  准备好我们的 Web 组件后，我们可以用它替换旧的搜索框。在`dynamic_storefront.html` HTML 中，用我们创建的新组件`search-box`替换`div`标签和它们的所有内容。还要将新的 JavaScript 文件添加到 HTML 中，放在所有其他脚本之前。您可以在 GitHub 上查看最终的 HTML，网址为[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise07/dynamic_storefront.html`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Exercise07/dynamic_storefront.html)。

1.  通过使用文档的`querySelector`方法保存对`search-box`组件的引用：

```js
const searchBoxElement = document.querySelector('search-box');
```

1.  注册一个 changed 事件的事件监听器，这样我们就知道何时有新值可用，并调用`applyFilters`：

```js
searchBoxElement.addEventListener('changed', (e) => applyFilters());
```

1.  现在我们可以清理`filter_and_search.js` JavaScript，因为部分逻辑已经移动到新组件中。我们将进行以下清理：

删除`textToSearch`变量（第 2 行），并将其替换为`searchBoxElement.searchText`（第 40 行）。

删除`addTextSearchFilter`函数（第 16-22 行）和脚本末尾对它的调用（第 70 行）。

如果一切顺利，在 Chrome 中打开文件将得到完全相同的 storefront，这正是我们想要的。

现在，处理搜索框和搜索文本的逻辑已经封装起来，这意味着如果我们需要更改它，我们不需要四处寻找分散在各处的代码片段。当我们需要知道搜索文本的值时，我们可以查询保存它的组件。

### 活动 2：用 Web 组件替换标签过滤器

现在我们已经用 web 组件替换了搜索框，让我们使用相同的技术替换标签过滤器。这个想法是我们将有一个组件来存储选定的标签列表。

这个组件将封装一个可以通过使用`mutator`方法（`addTag`和`removeTag`）来修改的选定标签列表。当内部状态发生变化时，会触发一个 changed 事件。此外，当列表中的标签被点击时，将触发一个`tag-clicked`事件。

步骤：

1.  首先将代码从练习 7 复制到一个新文件夹中。

1.  创建一个名为`tags_holder.js`的新文件，在其中添加一个名为`TagsHolder`的类，它扩展了`HTMLElement`，然后定义一个名为`tags-holder`的新自定义组件。

1.  创建两个`render`方法：一个用于渲染基本状态，另一个用于渲染标签或指示未选择任何标签进行过滤的文本。

1.  在构造函数中，调用`super`，将组件附加到影子根，初始化所选标签列表，并调用两个`render`方法。

1.  创建一个 getter 来公开所选标签的列表。

1.  创建两个触发器方法：一个用于触发`changed`事件，另一个用于触发`tag-clicked`事件。

1.  创建两个`mutator`方法：`addTag`和`removeTag`。这些方法接收标签名称，如果不存在则添加标签，如果存在则删除标签。如果列表被修改，触发`changed`事件并调用重新渲染标签列表的方法。

1.  在 HTML 中，用新组件替换现有代码，并将新的脚本文件添加到其中。

1.  在`filter_and_search.js`中，删除`tagsToFilterBy`变量，并用新创建的组件中的新`mutator`方法和事件替换它。

#### 注意。

此活动的解决方案可在第 584 页找到。

## 总结

在本章中，我们通过学习基本接口、属性和方法来探索 DOM 规范。我们了解了你编写的 HTML 与浏览器从中生成的树之间的关系。我们查询了 DOM 并导航 DOM 树。我们学会了如何创建新元素，将它们添加到树中，并操作现有元素。最后，我们学会了如何使用 Shadow DOM 来创建隔离的 DOM 树和可以在 HTML 页面中轻松重用的自定义组件。

在下一章中，我们将转向后端世界。我们将开始学习有关 Node.js 及其基本概念。我们将学习如何使用**nvm**安装和管理多个 Node.js 版本，最后但同样重要的是，我们还将学习有关**npm**以及如何查找和使用外部模块。


# 第三章：Node.js 和 npm

## 学习目标

在本章结束时，您将能够：

+   安装和使用 Node.js 构建应用程序

+   使用 Node.js 执行环境运行 JavaScript 代码

+   使用 nvm 安装和管理多个 Node.js 版本

+   识别并使用其他开发人员开发的模块，使用 npm

+   创建和配置自己的 npm 包

在本章中，我们将转向后端世界，学习有关 Node.js 及其基本概念。我们将学习如何使用 nvm 安装和管理多个 Node.js 版本，然后我们将学习 npm 以及如何查找和使用外部模块。

## 介绍

在上一章中，我们了解了 HTML 如何成为 DOM 以及如何使用 JavaScript 来查询和操作页面内容。

在 JavaScript 出现之前，所有页面都是静态的。在 Netscape 将脚本环境引入其浏览器后，开发人员开始使用它来创建动态和响应式应用程序。应用程序变得越来越复杂，但 JavaScript 运行的唯一地方是在浏览器内部。然后，在 2009 年，Node.js 的原始开发人员 Ryan Dahl 决定创建一种在服务器端运行 JavaScript 的方式，通过允许他们构建应用程序而无需依赖其他语言，简化了 Web 开发人员的生活。

在本章中，您将学习 Node.js 的工作原理以及如何使用它来使用 JavaScript 创建脚本。您将了解 Node.js 核心 API 的基础知识，以及如何找到它们的文档，并如何使用它们的**read-eval-print loop** (**REPL**)命令行。

掌握构建 JavaScript 代码的技能后，您将学习如何管理多个 Node.js 版本，并了解 Node.js 的重要性。您还将学习 npm 是什么，以及如何导入和使用其他开发人员的软件包并构建 Node.js 应用程序。

## 什么是 Node.js？

Node.js 是在 V8 JavaScript 引擎之上运行的执行环境。它的基本前提是它是异步和事件驱动的。这意味着所有阻塞操作，例如从文件中读取数据，可以在后台处理，而应用程序的其他部分可以继续工作。当数据加载完成时，将发出事件，等待数据的人现在可以执行并进行工作。

从诞生之初，Node.js 就被设计为 Web 应用程序的高效后端。因此，它被各种规模和行业类型的公司广泛采用。Trello、LinkedIn、PayPal 和 NASA 是一些在其技术堆栈的多个部分中使用 Node.js 的公司。

但是什么是执行环境？执行环境为程序员编写应用程序提供基本功能，例如 API。例如，想象一下浏览器-它具有 DOM，诸如文档和窗口的对象，诸如`setTimeout`和`fetch`的函数，以及前端世界中可以做的许多其他事情。所有这些都是浏览器执行环境的一部分。由于该执行环境专注于浏览器，它提供了与 DOM 交互和与服务器通信的方式，这是它存在的全部。

Node.js 专注于为开发人员提供一种有效构建 Web 应用程序后端的环境。它提供 API 来创建 HTTP(S)服务器，读写文件，操作进程等。

正如我们之前提到的，Node.js 在底层使用 V8 JavaScript 引擎。这意味着为了将 JavaScript 文本转换为计算机处理的可执行代码，它使用了 V8，这是由 Google 构建的开源 JavaScript 引擎，用于驱动 Chromium 和 Chrome 浏览器。以下是这个过程的示例：

![图 2.1：Node.js 使用 V8 引擎将 JavaScript 源代码转换为可在处理器中运行的可执行代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_01.jpg)

###### 图 2.1：Node.js 使用 V8 引擎将 JavaScript 源代码转换为在处理器中运行的可执行代码

Node.js 提供的执行环境是单线程的。这意味着每次只有一段 JavaScript 代码可以执行。但是 Node.js 有一个叫做事件循环的东西，它可以将等待某些东西的代码（比如从文件中读取数据）放入队列，而另一段代码可以执行。

从文件中读取或写入数据以及通过网络发送或接收数据都是由系统内核处理的任务，在大多数现代系统中都是多线程的。因此，一些工作最终会分布在多个线程中。但对于在 Node.js 执行环境中工作的开发人员来说，这一切都隐藏在一个叫做异步编程的编程范式中。

异步编程意味着你将要求执行一些任务，当结果可用时，你的代码将被执行。让我们回到从文件中读取数据的例子。在大多数编程语言和范式中，你只需编写一些伪代码，如下所示：

```js
var file = // open file here
var data = file.read(); // do something with data here
```

采用异步编程模型，工作方式有所不同。你打开文件并告诉 Node.js 你想要读取它。你还给它一个回调函数，当数据对你可用时将被调用。伪代码如下：

```js
var file = // open file here
file.read((data) => {
  // do something with data here
});
```

在这个例子中，脚本将被加载，并开始执行。脚本将逐行执行并打开文件。当它到达读取操作时，它开始读取文件并安排稍后执行回调。之后，它到达脚本的末尾。

当 Node.js 到达脚本的末尾时，它开始处理事件循环。事件循环分为阶段。每个阶段都有一个队列，存储着计划在其中运行的代码。例如，I/O 操作被安排在轮询阶段。有六个阶段，它们按以下顺序执行：

1.  **计时器**：使用`setTimeout`或`setInterval`计划的代码

1.  **挂起** **回调**：上一个周期的 I/O 的延迟回调

1.  **空闲**，**准备**：仅内部

1.  **轮询**：计划进行 I/O 处理的代码

1.  **检查**：`setImmediate`回调在这里执行

1.  **关闭回调**：计划在关闭套接字等上执行的代码

每个阶段都会执行代码，直到发生两种情况之一：阶段队列耗尽，或者执行了最大数量的回调：

![图 2.2：事件循环阶段](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_02.jpg)

###### 图 2.2：事件循环阶段

要理解这是如何工作的，让我们看一些代码，将阶段映射到事件循环，并了解底层到底发生了什么：

```js
console.log('First');
setTimeout(() => {
  console.log('Last');
}, 100);
console.log('Second');
```

在这段简短的代码中，我们向控制台打印一些内容（在 Node.js 中，默认情况下会输出到标准输出），然后我们设置一个函数在`100`毫秒后调用，并向控制台打印一些其他文本。

当 Node.js 启动你的应用程序时，它会解析 JavaScript 并执行脚本直到结束。当结束时，它开始事件循环。这意味着，直接打印到控制台时，它会立即执行。计划的函数被推送到计时器队列，并等待脚本完成（以及**100**毫秒过去）才会执行。当事件循环没有任务可执行时，应用程序结束。以下图表说明了这个过程：

![图 2.3：Node.js 应用程序的执行流程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_03.jpg)

###### 图 2.3：Node.js 应用程序的执行流程

由于执行顺序，应用程序的输出如下：

```js
First
Second
Last
```

这里发生了两件重要的事情。首先，传递给`setTimeout`函数的代码在脚本执行完成后执行。其次，应用程序在脚本执行到最后不会立即退出；相反，它会等待事件循环耗尽要执行的任务。

Node.js 有两种执行方法。最常用的是当您传递文件的路径时，JavaScript 代码将从那里加载和执行。第二种方法是在 REPL 中。如果您执行 Node.js 命令而不给出任何参数，它将以 REPL 模式启动，这类似于我们在上一章中看到的 Dev Tools 中的控制台。让我们在下一个练习中详细探讨这一点。

### 练习 8：运行您的第一个 Node.js 命令

在这个练习中，您将在计算机上下载和安装 Node.js，创建您的第一个脚本并运行它。然后，我们将使用 Node.js 附带的 REPL 工具，并在其中运行一些命令。

#### 注意

要能够运行 Node.js 应用程序，您需要在计算机上安装它。为此，您可以转到`nodejs.org`并下载 Node.js 软件包。建议下载最新的**长期支持**（**LTS**）版本，这将为您提供最稳定和最长的安全和错误修补支持时间。在撰写本文时，该版本为`10.16.0`。

执行以下步骤以完成此练习：

1.  下载并安装 Node.js 后，转到命令行并检查您已安装的版本：

```js
$ node –version
v10.16.0
```

1.  现在，创建一个名为`event_loop.js`的新文本文件，并添加代码的扩展版本（事件循环示例），如前所示。它看起来像这样：

```js
console.log('First');
const start = Date.now();
setTimeout(() => {
  console.log(`Last, after: ${Date.now() - start}ms`);
}, 100);
console.log('Second');
```

1.  要使用 Node.js 运行 JavaScript，调用`node`并传递要执行的文件的路径。要运行刚刚创建的文件，请在命令行中执行以下代码，从您创建文件的目录中执行：

```js
$ node event_loop.js
```

您将看到以下输出：

```js
$ node event_loop.js
First
Second
Last, after: 106ms
```

最后看到的时间将在每次运行时都有所不同。这是因为`setTimeout`只能确保代码将在指定的时间之后运行，但不能保证它会准确地在您要求的时间执行。

1.  运行`node`命令而不带任何参数；您将进入 REPL 模式：

```js
$ node
>
```

`>`表示您现在在 Node.js 执行环境中。

1.  在 REPL 命令行中，键入命令并按*Enter*执行。让我们尝试第一个：

```js
> console.log('First');
First
Undefined
```

你可以看到它打印出你传递给`console.log`调用的字符串。它还打印出`Undefined`。这是最后执行语句的返回值。由于`console.log`没有返回任何东西，它打印了 undefined。

1.  创建存储当前时间的常量：

```js
> const start = Date.now()
undefined
```

1.  声明变量也不会返回任何东西，所以它再次打印`undefined`：

```js
> start
1564326469948
```

如果要知道变量的值是多少，只需键入变量名称并按*Enter*。变量名称的返回语句是变量值，因此它会打印出该值。

1.  现在，键入`setTimeout`调用，就像在您的文件中一样。如果您按*Enter*并且您的语句不完整，因为您正在启动一个函数或打开括号，Node.js 将打印省略号，表示它正在等待命令的其余部分：

```js
> setTimeout(() => {
... 
```

1.  您可以继续键入，直到所有命令都被键入。`setTimeout`函数返回一个`Timeout`对象，您可以在控制台中看到它。您还可以看到在执行回调时打印的文本：

```js
> setTimeout(() => {
...   console.log('Last, after: ${Date.now() - start}ms');
... }, 100);
```

以下是前述代码的输出：

```js
Timeout {
  _called: false,
  _idleTimeout: 100,
  _idlePrev: [TimersList],
  _idleNext: [TimersList],
  _idleStart: 490704,
  _onTimeout: [Function],
  _timerArgs: undefined,
  _repeat: null,
  _destroyed: false,
  domain: [Domain],
  [Symbol(unrefed)]: false,
  [Symbol(asyncId)]: 492,
  [Symbol(triggerId)]: 5 }
> Last, after: 13252ms
```

您可以看到打印出的时间远远超过了`100`毫秒。这是因为`start`变量是一段时间前声明的，它正在从初始值中减去当前时间。因此，该时间表示`100`毫秒，再加上您键入和执行命令所花费的时间。

1.  尝试更改`start`的值。您会观察到 Node.js 不会让您这样做，因为我们将其声明为常量：

```js
> start = Date.now();
Thrown:
TypeError: Assignment to constant variable.
```

我们可以尝试将其重新声明为一个变量，但是 Node.js 不会让我们这样做，因为它已经在当前环境中声明过了：

```js
> let start = Date.now()
Thrown:
SyntaxError: Identifier 'start' has already been declared
```

1.  在另一个函数中声明超时的整个调度，以便每次执行函数时都获得一个新的作用域：

```js
> const scheduleTimeout = () => {
... const start = Date.now();
... setTimeout(() => {
..... console.log('Later, after: ${Date.now() - start}');
..... }, 100);
... };
```

每次调用该函数，它都会安排并在`100`毫秒后执行，就像在您的脚本中一样。这将输出以下内容：

```js
Undefined
> scheduleTimeout
[Function: scheduleTimeout]
> scheduleTimeout()
Undefined
> Later, after: 104
```

1.  要退出 REPL 工具，您可以按两次*Ctrl + C*，或者输入`.exit`然后按*Enter*：

```js
>
(To exit, press ^C again or type .exit)
>
```

安装 Node.js 并开始使用它非常容易。其 REPL 工具允许您快速原型设计和测试。了解如何使用这两者可以提高您的生产力，并在日常 JavaScript 应用程序开发中帮助您很多。

在这个练习中，您安装了 Node.js，编写了一个简单的程序，并学会了如何使用 Node.js 运行它。您还使用了 REPL 工具来探索 Node.js 执行环境并运行一些代码。

## Node 版本管理器（nvm）

Node.js 和 JavaScript 拥有一个庞大的社区和非常快速的开发周期。由于这种快速的发展和发布周期，很容易过时（查看 Node.js 的先前版本页面以获取更多信息：[`nodejs.org/en/download/releases/`](https://nodejs.org/en/download/releases/)）。

你能想象在一个使用 Node.js 且已经存在几年的项目上工作吗？当您回来修复一个错误时，您会注意到您安装的版本无法再运行代码，因为存在一些兼容性问题。或者，您会发现您无法使用当前版本更改代码，因为生产环境中运行的版本已经有几年了，没有 async/await 或其他您在最新版本中经常使用的功能。

这个问题发生在所有编程语言和开发环境中，但在 Node.js 中，由于其极快的发布周期，这一点尤为突出。

为了解决这个问题，通常会使用版本管理工具，这样您就可以快速在 Node.js 的不同版本之间切换。**Node 版本管理器**（**nvm**）是一个广泛使用的工具，用于管理安装的 Node.js 版本。您可以在[`github.com/nvm-sh/nvm`](https://github.com/nvm-sh/nvm)上找到有关如何下载和安装它的说明。

#### 注意

如果您使用 Windows，可以尝试 nvm-windows（[`github.com/coreybutler/nvm-windows`](https://github.com/coreybutler/nvm-windows)），它为 Linux 和 Mac 中的 nvm 提供了类似的功能。此外，在本章中，许多命令都是针对 Mac 和 Linux 的。对于 Windows，请参阅`nvm-windows`的帮助部分。

安装程序在您的系统中执行两件事：

1.  在您的主目录中创建一个`.nvm`目录，其中放置了所有与管理 Node.js 的所有托管版本相关的脚本

1.  添加一些配置以使 nvm 在所有终端会话中可用

nvm 非常简单易用，并且有很好的文档。其背后的想法是您的机器上将运行多个版本的 Node.js，您可以快速安装新版本并在它们之间切换。

在我的电脑上，我最初只安装了一段时间前下载的 Node.js 版本（10.16.0）。安装 nvm 后，我运行了列出所有版本的命令。以下是输出：

```js
$ nvm ls

->system
iojs -> N/A (default)
node -> stable (-> N/A) (default)
unstable -> N/A (default)
```

您可以看到我没有其他版本可用。我还有一个系统版本，这是您在系统中安装的任何版本。我可以通过运行 `node --version` 来检查当前的 Node.js 版本：

```js
$ node --version
v10.16.0
```

作为使用 nvm 的示例，假设您想要在最新版本上测试一些实验性功能。您需要做的第一件事是找出那个版本。因此，您运行`nvm ls-remote`命令（或者对于 Windows 系统，运行`nvm list`命令），这是列出远程版本的命令：

```js
$ nvm ls-remote
        v0.1.14
        v0.1.15
        v0.1.16
       ...
       v10.15.3   (LTS: Dubnium)
       v10.16.0   (Latest LTS: Dubnium)
       ...
        v12.6.0
        v12.7.0
```

这将打印出所有可用版本的长列表。在写作时，最新的版本是 12.7.0，所以让我们安装这个版本。要安装任何版本，请运行`nvm install` <`version`>命令。这将下载指定版本的 Node.js 二进制文件，验证包是否损坏，并将其设置为终端中的当前版本：

```js
$ nvm install 12.7.0
Downloading and installing node v12.7.0...
Downloading https://nodejs.org/dist/v12.7.0/node-v12.7.0-darwin-x64.tar.xz...
######################################################################## 100.0%
Computing checksum with shasum -a 256
Checksums matched!
Now using node v12.7.0 (npm v6.10.0)
```

现在，您可以验证您已经安装了最新版本，并准备在终端中使用：

```js
$ node --version
v12.7.0
```

或者，您可以直接使用别名`node`，这是最新版本的别名。但是对于 Windows，您需要提到需要安装的特定版本：

```js
$ nvm install node
v12.7.0 is already installed.
Now using node v12.7.0 (npm v6.10.0)
```

广泛使用的框架和语言（如 Node.js）通常会为特定版本提供 LTS。这些 LTS 版本被认为更稳定，并保证对错误和安全修复提供更长时间的支持，这对于无法像正常发布周期那样快速迁移到新版本的公司或团队来说非常重要。如果您想使用最新的 LTS 版本，可以使用`--lts`选项：

```js
$ nvm install --lts
Installing the latest LTS version.
Downloading and installing node v10.16.0...
Downloading https://nodejs.org/dist/v10.16.0/node-v10.16.0-darwin-x64.tar.xz...
######################################################################## 100.0%
Computing checksum with shasum -a 256
Checksums matched!
Now using node v10.16.0 (npm v6.9.0)
```

使用 nvm 安装多个版本的 Node.js 后，您可以使用`use`命令在它们之间切换：

```js
$ nvm use system --version
Now using system version of node: v10.16.0 (npm v6.9.0)
$ nvm use node
Now using node v12.7.0 (npm v6.10.0)
$ nvm use 7
Now using node v7.10.1 (npm v4.2.0)
```

当您有多个项目并经常在它们之间切换时，很难记住您为每个项目使用的 Node.js 版本。为了让我们的生活更轻松，nvm 支持项目目录中的配置文件。您只需在项目的根目录中添加一个`.nvmrc`文件，它将使用文件中的版本。您还可以在项目的任何父目录中添加一个`.nvmrc`文件。因此，如果您想在父目录中按 Node.js 版本对项目进行分组，可以在该父目录中添加配置文件。

例如，如果您在一个文件夹中有一个`.nvmrc`文件，版本为`12.7.0`，当您切换到该文件夹并运行`nvm use`时，它将自动选择该版本：

```js
$ cat .nvmrc 
12.7.0
$ nvm use
Found '.../Lesson02/Exercise09/.nvmrc' with version <12.7.0>
Now using node v12.7.0 (npm v6.10.0)
```

### 练习 9：使用 nvm 管理版本

正如我们之前提到的，Node.js 的发布周期非常短。例如，如果您寻找 URL 类（[`nodejs.org/dist/latest-v12.x/docs/api/url.html#url_class_url`](https://nodejs.org/dist/latest-v12.x/docs/api/url.html#url_class_url)），您会发现它最近才在全局范围内可用。这发生在 10.0.0 版本中，这个版本在写作时只有大约一年的历史。

在这个练习中，我们将编写一个`.nvmrc`文件，使用 nvm 安装多个版本的 Node.js，并尝试不同的版本，看看当您使用错误的 Node.js 版本时会得到什么类型的错误。

执行以下步骤完成这个练习：

1.  在您的项目中添加一个`.nvmrc`文件。在一个空文件夹中，创建一个名为`.nvmrc`的文件，并在其中添加数字 12.7.0。您可以使用`echo`命令一次完成这个操作，并将输出重定向到文件中：

```js
$ echo '12.7.0' > .nvmrc
```

1.  您可以使用`cat`命令检查文件是否包含您想要的内容：

```js
$ cat .nvmrc
12.7.0
```

1.  让我们使用`nvm use`命令，它将尝试使用`.nvmrc`文件中的版本：

```js
$ nvm use
Found '.../Lesson02/Exercise09/.nvmrc' with version <12.7.0>
N/A: version "12.7.0 -> N/A" is not yet installed.
```

在使用之前，您需要运行`nvm install 12.7.0`来安装它。如果您没有安装指定的版本，nvm 将给出清晰的消息。

1.  调用`nvm install`来安装项目需要的版本：

```js
$ nvm install
Found '.../Lesson02/Exercise09/.nvmrc' with version <12.7.0>
Downloading and installing node v12.7.0...
Downloading https://nodejs.org/dist/v12.7.0/node-v12.7.0-darwin-x64.tar.xz...
#################################################################### 100.0%
Computing checksum with shasum -a 256
Checksums matched!
Now using node v12.7.0 (npm v6.10.0)
```

请注意，您不必传递您想要的版本，因为 nvm 将从`.nvmrc`文件中获取这个版本。

1.  现在，创建一个名为`url_explorer.js`的文件。在其中，通过传递完整的 URL 来创建一个 URL 的实例。让我们还添加一些调用来探索 URL 的各个部分：

```js
const url = new URL('https://www.someserver.com/not/a/path?param1=value1&param2=value2`);
console.log(`URL is: ${url.href}`);
console.log(`Hostname: ${url.hostname}`);
console.log(`Path: ${url.pathname}`);
console.log(`Query string is: ${url.search}`);
console.log(`Query parameters:`)
Array.from(url.searchParams.entries())
  .forEach((entry) => console.log(`\t- ${entry[0]} = ${entry[1]}`));
```

1.  运行脚本。您会看到 URL 被正确解析，并且所有关于它的细节都正确地打印到控制台上：

```js
$ node url_explorer.js
URL is: https://www.someserver.com/not/a/path?param1=value1&param2=value2
Hostname: www.someserver.com
Path: /not/a/path
Query string is: ?param1=value1&param2=value2
Query parameters:
    - param1 = value1
    - param2 = value2
```

1.  现在，让我们尝试错误的 Node.js 版本。使用`nvm`安装版本`9.11.2`：

```js
$ nvm install 9.11.2
Downloading and installing node v9.11.2...
Downloading https://nodejs.org/dist/v9.11.2/node-v9.11.2-darwin-x64.tar.xz...
################################################################## 100.0%
Computing checksum with shasum -a 256
Checksums matched!
Now using node v9.11.2 (npm v5.6.0)
```

1.  现在，您可以再次运行`url_explorer.js`，看看会发生什么：

```js
$ node url_explorer.js
.../Exercise09/url_explorer.js:1 ... { const url = new URL('...);^
ReferenceError: URL is not defined
    at Object.<anonymous> (.../Exercise09/url_explorer.js:1:75)
    at Module._compile (internal/modules/cjs/loader.js:654:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:665:10)
    at Module.load (internal/modules/cjs/loader.js:566:32)
    at tryModuleLoad (internal/modules/cjs/loader.js:506:12)
    at Function.Module._load (internal/modules/cjs/loader.js:498:3)
    at Function.Module.runMain (internal/modules/cjs/loader.js:695:10)
    at startup (internal/bootstrap/node.js:201:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:516:3)
```

您应该看到与前面代码中相似的错误。它告诉您 URL 未定义。这是因为，正如我们之前提到的，URL 类只在 10.0.0 版本中变为全局可用。

1.  修复 Node.js 的版本并再次运行脚本以查看正确的输出：

```js
$ nvm use
Found '.../Lesson02/Exercise09/.nvmrc' with version <12.7.0>
Now using node v12.7.0 (npm v6.10.0)
$ node url_explorer.js 
URL is: https://www.someserver.com/not/a/path?param1=value1&param2=value2
Hostname: www.someserver.com
Path: /not/a/path
Query string is: ?param1=value1&param2=value2
Query parameters:
    - param1 = value1
    - param2 = value2
```

第 7 步中的错误消息没有提及 Node.js 版本。它只是一些关于缺少类的神秘错误。这类错误很难识别，并需要大量的历史追踪。这就是为什么在项目的根目录中有`.nvmrc`是重要的原因。它使其他开发人员能够快速识别和使用正确的版本。

在这个练习中，您学会了如何安装和使用多个版本的 Node.js，还学会了为项目创建`.nvmrc`文件。最后，您还了解了在使用错误版本时会看到的错误类型，以及`.nvmrc`文件的重要性。

## Node 包管理器（npm）

当有人谈论**Node 包管理器**或简称 npm 时，他们可能指的是以下三种情况之一：

+   一个管理 Node.js 应用程序包的命令行应用程序

+   开发人员和公司发布他们的包供他人使用的存储库

+   管理个人资料和搜索包的网站

大多数编程语言至少提供一种开发人员之间共享包的方式：Java 有 Maven，C#有 NuGet，Python 有 PIP 等。Node.js 在初始发布几个月后开始使用自己的包管理器。

包可以包括开发人员认为对他人有用的任何类型的代码。有时，它们还包括帮助开发人员进行本地开发的工具。

由于打包的代码需要共享，因此需要一个存储所有包的存储库。为了发布他们的包，作者需要注册并注册自己和他们的包。这解释了存储库和网站部分。

第三部分，即命令行工具，是您应用程序的实际包管理器。它随 Node.js 一起提供，并可用于设置新项目、管理依赖项以及管理应用程序的脚本，如构建和测试脚本。

#### 注意

Node.js 项目或应用程序也被视为一个包，因为它包含一个`package.json`文件，代表了包中的内容。因此，通常可以互换使用以下术语：应用程序、包和项目。

每个 Node.js 包都有一个描述项目及其依赖关系的`package.json`文件。要为您的项目创建一个`package.json`文件，您可以使用`npm init`命令。只需在您想要项目存在的文件夹中运行它：

```js
$ cd sample_npm
$ npm init
This utility will walk you through creating a package.json file.
It only covers the most common items and tries to guess sensible defaults.
See 'npm help json' for definitive documentation on these fields and exactly what they do.
Use 'npm install <pkg>' afterwards to install a package and save it as a dependency in the package.json file.
Press ^C at any time to quit.
package name: (sample_npm) 
version: (1.0.0) 
description: Sample project for the Professional JavaScript.
entry point: (index.js) 
test command: 
git repository: https://github.com/TrainingByPackt/Professional-JavaScript/
keywords: 
author: 
license: (ISC) MIT
About to write to .../Lesson02/sample_npm/package.json:
{
  "name": "sample_npm",
  "version": "1.0.0",
  "description": "Sample project for the Professional JavaScript.",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/TrainingByPackt/Professional-JavaScript.git"
  },
  "author": "",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/TrainingByPackt/Professional-JavaScript/issues"
  },
  "homepage": "https://github.com/TrainingByPackt/Professional-JavaScript#readme"
}
Is this OK? (yes) yes
```

该命令将询问您一些问题，指导您创建`package.json`文件。最后，它将打印生成的文件并要求您确认。它包含关于项目的所有信息，包括代码的位置、使用的许可证以及作者是谁。

现在我们有了一个 npm 包，我们可以开始寻找可以使用的外部模块。让我们去[`npmjs.com`](https://npmjs.com)寻找一个帮助我们解析命令行参数的包。在搜索框中输入**command line**并按*Enter*键，我们会得到一个包选择列表：

![图 2.4：搜索一个包来帮助我们构建一个命令行应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_04.jpg)

###### 图 2.4：搜索一个包来帮助我们构建一个命令行应用程序

由于我们正在寻找一个工具来帮助我们解析命令行参数，**commander**听起来像是一个不错的解决方案。它的简短描述是**node.js 命令行程序的完整解决方案**。让我们在一个应用程序中安装它，并使用它来理解这个流程是如何工作的。

要将包添加为您的包的依赖项，您可以从命令行请求 npm 按名称安装它：

```js
$ npm install commander
npm notice created a lockfile as package-lock.json. You should commit this file.
+ commander@2.20.0
added 1 package from 1 contributor and audited 1 package in 1.964s
found 0 vulnerabilities
```

您可以看到 npm 找到了该包并下载了最新版本，截至本文撰写时为`2.20.0`。它还提到了关于`package-lock.json`文件的一些内容。我们将稍后更多地讨论这个问题，所以现在不用担心它。

最近添加到 npm 的另一个很酷的功能是漏洞检查。在`install`命令输出的末尾，您可以看到有关发现的漏洞的注释，或者更好的是，没有发现漏洞。npm 团队正在努力增加对其存储库中所有包的漏洞检查和安全扫描。

#### 注意

从 npm 使用包是如此简单，以至于很多人都在向那里推送恶意代码，以捕捉最不注意的开发人员。强烈建议您在从 npm 安装包时要非常注意。检查拼写、下载次数和漏洞报告，并确保您要安装的包确实是您想要的。您还需要确保它来自可信任的方。 

运行`npm install`后，您会注意到`package.json`文件中添加了一个新的部分。它是`dependencies`部分，包含您刚刚请求的包：

```js
"dependencies": {
  "commander": "².20.0"
}
```

这就是`install`命令输出中`commander`前面的+号的含义：该包已作为项目的依赖项添加。

`dependencies`部分用于自动检测和安装项目所需的所有包。当您在一个具有`package.json`文件的 Node.js 应用程序上工作时，您不必手动安装每个依赖项。您只需运行`npm install`，它将根据`package.json`文件的`dependencies`部分自动解决所有问题。这里是一个例子：

```js
$ npm install
added 1 package from 1 contributor and audited 1 package in 0.707s
found 0 vulnerabilities
```

尽管没有指定任何包，npm 假定您想要安装当前包的所有依赖项，这些依赖项来自`package.json`。

除了向`package.json`文件添加`dependencies`部分之外，它还创建了一个`node_modules`文件夹。那是它下载并保留项目所有包的地方。您可以使用列表命令（`ls`）检查`node_modules`中的内容：

```js
$ ls node_modules/
commander
$ ls node_modules/commander/
CHANGELOG.md  LICENSE   Readme.md   index.js    package.json  typings
```

如果您再次运行`npm install`来安装 commander，您会注意到 npm 不会再次安装该包。它只显示该包已更新和已审核：

```js
$ npm install commander
+ commander@2.20.0
updated 1 package and audited 1 package in 0.485s
found 0 vulnerabilities
```

在下一个练习中，我们将构建一个使用 commander 作为依赖项的 npm 包，然后创建一个命令行 HTML 生成器。

### 练习 10：创建一个命令行 HTML 生成器

现在您已经学会了使用 npm 创建包以及如何安装一些依赖项的基础知识，让我们把这些知识整合起来，构建一个可以为您的下一个网站项目生成 HTML 模板的命令行工具。

在这个练习中，您将创建一个 npm 包，该包使用 commander 作为处理命令行参数的依赖项。然后，您将探索您创建的工具，并生成一些 HTML 文件。

此练习的代码可以在 GitHub 上找到，网址为[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson02/Exercise10`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson02/Exercise10)。

执行以下步骤以完成此练习：

1.  创建一个新的文件夹，您将在其中放置此练习的所有文件。

1.  在命令行中，切换到新文件夹并运行`npm init`来初始化一个`package.json`文件。选择所有默认选项应该就足够了：

```js
$ npm init
This utility will walk you through creating a package.json file.
...
Press ^C at any time to quit.
package name: (Exercise10) 
version: (1.0.0) 
...
About to write to .../Lesson02/Exercise10/package.json:
{
  "name": "Exercise10",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
Is this OK? (yes)
```

1.  安装`commander`包作为依赖项：

```js
$ npm install commander
npm notice created a lockfile as package-lock.json. You should commit this file.
+ commander@2.20.0
added 1 package from 1 contributor and audited 1 package in 0.842s
found 0 vulnerabilities
```

在您的`package.json`中，添加以下内容：

```js
"main": "index.js"
```

这意味着我们应用程序的入口点是`index.js`文件。

1.  运行一个具有入口点的 npm 包，并使用`node`命令，传递包含`package.json`文件的目录。以下是一个在`Lesson02/sample_npm`中运行该包的示例，该示例可在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson02/sample_npm`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson02/sample_npm)上找到：

```js
$ node sample_npm/
I'm an npm package running from sample_npm
```

1.  创建一个名为`index.js`的文件，在其中使用`require`函数加载`commander`包：

```js
const program = require('commander');
```

这就是您开始使用外部包所需要的全部内容。

Commander 解析传入 Node.js 应用程序的参数。您可以配置它告诉它您期望的参数类型。对于这个应用程序，我们将有三个选项：`-b`或`--add-bootstrap`，它将在生成的输出中添加 bootstrap 4；`-c`或`--add-container`，它将在 body 中添加一个带有 ID container 的`<div>`标签；以及`-t`或`--title`，它将在页面上添加一个接受标题文本的`<title>`。

1.  配置 commander，我们调用 version 方法，然后多次调用 option 方法来添加应用程序将支持的每个选项。最后，我们调用`parse`，它将验证传入的参数（`process.argv`将在下一章详细讨论）是否与预期的选项匹配：

```js
program.version('0.1.0')
  .option('-b, --add-bootstrap', 'Add Bootstrap 4 to the page.')
  .option('-c, --add-container', 'Adds a div with container id in the body.')
  .option('-t, --title [title]', 'Add a title to the page.')
  .parse(process.argv);
```

1.  现在，您可以运行您的应用程序并查看到目前为止的结果：

```js
$ node . –help
```

我们将收到以下输出：

```js
Usage: Exercise10 [options]
Options:
  -V, --version        output the version number
  -b, --add-bootstrap  Add Bootstrap 4 to the page.
  -c, --add-container  Adds a div with container id in the body.
  -t, --title [title]  Add a title to the page.
  -h, --help           output usage information
```

您可以看到 commander 为您提供了一个很好的帮助消息，解释了您的工具应该如何使用。

1.  现在，让我们使用这些选项来生成 HTML。我们需要做的第一件事是声明一个变量，用于保存所有的 HTML：

```js
let html = '<html><head>';
```

我们可以使用`<html>`和`<head>`开放标签来初始化它。

1.  然后，检查程序是否接收到`title`选项。如果是，就添加一个带有传入标签内容的`<title>`标签：

```js
if (program.title) {
  html += `<title>${program.title}</title>`;
}
```

1.  对于`Bootstrap`选项也是同样的操作。在这种情况下，选项只是一个布尔值，因此您只需检查并添加一个指向`Bootstrap.css`文件的`<link>`标签：

```js
if (program.addBootstrap) {
  html += '<link';
  html += ' rel="stylesheet"';
  html += ' href="https://stackpath.bootstrapcdn.com';
  html += '/bootstrap/4.3.1/css/bootstrap.min.css"';
  html += '/>';
}
```

1.  关闭`<head>`标签并打开`<body>`标签：

```js
html += '</head><body>';
```

1.  检查容器`<div>`选项，并在启用时添加它：

```js
if (program.addContainer) {
  html += '<div id="container"></div>';
}
```

1.  最后，关闭`<body>`和`<html>`标签，并将 HTML 打印到控制台：

```js
html += '</body></html>';
console.log(html);
```

1.  不带任何选项运行应用程序将给我们一个非常简单的 HTML：

```js
$ node .
<html><head></head><body></body></html>
```

1.  运行应用程序，启用所有选项：

```js
$ node . -b -t Title -c
This will return a more elaborate HTML:
<html><head><title>Title</title><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"/></head><body><div id="container"></div></body></html>
```

npm 使得在您的应用程序中使用包变得非常容易。像 commander 和 npm 存储库中的其他数以千计的包使得 Node.js 成为构建功能强大且复杂的应用程序的绝佳选择，而代码量却很少。探索和学习如何使用包可以为您节省大量时间和精力，这将决定一个项目是否能够成功应用于数百万用户。

在这个练习中，您创建了一个 npm 包，使用外部包来解析命令行参数，这通常是一项费力的任务。您已经配置了 commander 来将参数解析为一个很好的可用格式，并学会了如何使用解析后的参数来构建一个根据用户输入做出决策的应用程序。

### 依赖项

在上一节中，我们看到 npm 如何使用`package.json`文件的`dependencies`部分来跟踪您的包的依赖关系。依赖关系是一个复杂的话题，但您必须记住的是，npm 支持语义版本或 semver 格式的版本号，并且它可以使用区间和其他复杂的运算符来确定您的包可以接受其他包的哪些版本。

默认情况下，正如我们在上一个练习中看到的，npm 使用插入符号标记所有包版本，例如 2.20.0。该插入符号表示您的包可以使用与 2.20.0 兼容的任何版本。在语义版本的意义上，兼容性意味着新的次要或补丁版本被认为是有效的，因为它们是向后兼容的：

![图 2.5：将次要和补丁版本视为有效的语义格式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_05.jpg)

###### 图 2.5：将次要和补丁版本视为有效的语义格式

与 2.20.0 兼容的版本是 2.21.0 或 2.21.5，甚至是 2.150.47！

偶尔，您可能希望更新您的软件包版本，以提高安全性或转移到具有解决某些依赖项中出现的问题的版本。这就是为什么 npm 为您安装的软件包版本添加了插入符号的原因。使用一个命令，您可以将所有依赖项更新为更新的兼容版本。

例如，很久以前启动的命令行应用程序使用的是 commander 的 2.0.0 版本。当开发人员运行`install`命令时，他们在`package.json`文件中得到了 2.0.0 版本。几年后，他们回过头来注意到 commander 中存在一些安全漏洞。他们只需运行`npm update`命令来解决这个问题：

```js
$ npm update
+ commander@2.20.0
added 1 package from 1 contributor and audited 1 package in 0.32s
found 0 vulnerabilities
```

大多数情况下，开发人员遵循语义版本控制规范，并不会在次要或补丁版本更改时进行破坏性更改。但是，随着项目的增长，依赖项的数量很快就会达到成千上万，破坏性更改或兼容性问题的概率呈指数级增长。

为了帮助您在出现复杂的依赖树时，npm 还会生成一个`package-lock.json`文件。该文件包含了您的`node_modules`目录中的软件包的表示，就像您上次更改依赖包时一样。当您使用`install`命令安装新依赖项或使用`update`命令更新版本时，就会发生这种情况。

`package-lock.json`文件应该与您的其他代码一起检查，因为它跟踪您的依赖树，并且对于调试复杂的兼容性问题非常有用。另一方面，`node_modules`应该始终添加到您的`.gitignore`文件中，因为 npm 可以使用来自您的`package.json`和`package-lock.json`文件的信息随时重新创建该文件夹，并从 npm 存储库下载包。

除了`dependencies`部分，您的`package.json`文件还可以包含一个`devDependencies`部分。这个部分是开发人员在构建或测试包时使用的依赖项，但其他人不需要。这可以包括诸如`babel`之类的工具来`转译`代码，或者诸如`jest`之类的测试框架。

`devDependencies`中的依赖项在其他包使用时不会被拉取。一些框架，如 Webpack 或`Parcel.js`，也有一个生产模型，将在创建最终捆绑包时忽略这些依赖项。

### npm 脚本

当您运行`npm init`命令时，创建的`package.json`文件中将包含一个`scripts`部分。默认情况下，会添加一个测试脚本。它看起来像这样：

```js
"scripts": {
  "test": "echo \"Error: no test specified\" && exit 1"
},
```

脚本可用于运行开发人员在处理软件包时可能需要的任何类型的命令。脚本的常见示例包括测试、linting 和其他代码分析工具。还可以有脚本来启动应用程序或从命令行执行其他任何操作。

要定义一个脚本，您需要在`scripts`部分添加一个属性，其中值是将要执行的脚本，如下所示：

```js
"scripts": {
  "myscript": "echo 'Hello world!'"
},
```

上述代码创建了一个名为`myscript`的脚本。当调用时，它将打印文本“Hello World!”。

要调用一个脚本，您可以使用`npm run`或 run-script 命令，传入脚本的名称：

```js
$ npm run myscript
> sample_scripts@1.0.0 myscript .../Lesson02/sample_scripts
> echo 'Hello World!'
Hello World!
```

npm 将输出正在执行的所有细节，以让您知道它在做什么。您可以使用`--silent`（或`-s`）选项要求它保持安静：

```js
$ npm run myscript --silent
Hello World!
$ npm run myscript -s
Hello World!
$ npm run-script myscript -s
Hello World!
```

关于脚本的一个有趣的事情是，您可以使用前缀“pre”和“post”在设置和/或清理任务之前和之后调用其他脚本。以下是这种用法的一个例子：

```js
"scripts": {
  "preexec": "echo 'John Doe' > name.txt",
  "exec": "node index.js",
  "postexec": "rm -v name.txt"
}
```

`index.js`是一个 Node.js 脚本，它从`name.txt`文件中读取名称并打印一个 hello 消息。`exec`脚本将执行`index.js`文件。在执行之前和之后，将自动调用预和后`exec`脚本，创建和删除`name.txt`文件（在 Windows 中，您可以使用`del`命令而不是`rm`）。运行 exec 脚本将产生以下输出：

```js
$ ls
index.js package.json
$ npm run exec
> sample_scripts@1.0.0 preexec ../Lesson02/sample_scripts
> echo 'John Doe' > name.txt
> sample_scripts@1.0.0 exec ../Lesson02/sample_scripts
> node index.js
Hello John Doe!
> sample_scripts@1.0.0 postexec ../Lesson02/sample_scripts
> rm -v name.txt
name.txt
$ ls
index.js        package.json
```

您可以看到，在调用 exec 脚本之前，`name.txt`文件不存在。调用`preexec`脚本，它将创建带有名称的文件。然后调用 JavaScript 并打印 hello 消息。最后，调用`postexec`脚本，它将删除文件。您可以看到，在 npm 执行完成后，`name.txt`文件不存在。

npm 还带有一些预定义的脚本名称。其中一些是 published，install，pack，test，stop 和 start。这些预定义名称的优势在于您不需要使用`run`或`run-script`命令；您可以直接按名称调用脚本。例如，要调用由`npm init`创建的默认测试脚本，只需调用`npm test`：

```js
$ npm test
> sample_scripts@1.0.0 test .../Lesson02/sample_scripts
> echo "Error: no test specified" && exit 1
Error: no test specified
npm ERR! Test failed.  See above for more details.
```

在这里，您可以看到它失败了，因为它有一个`exit 1`命令，这使得 npm 脚本的执行失败，因为任何以非零状态退出的命令都会立即使调用停止。

`start`是一个广泛使用的脚本，用于启动本地前端开发的 Web 服务器。前面代码中的 exec 示例可以重写为以下形式：

```js
"scripts": {
  "prestart": "echo 'John Doe' > name.txt",
  "start": "node index.js",
  "poststart": "rm -v name.txt"
}
```

然后，只需调用`npm start`即可运行：

```js
$ npm start
> sample_scripts@1.0.0 prestart .../Lesson02/sample_scripts
> echo 'John Doe' > name.txt
> sample_scripts@1.0.0 start .../Lesson02/sample_scripts
> node index.js
Hello John Doe!
> sample_scripts@1.0.0 poststart .../Lesson02/sample_scripts
> rm -v name.txt
name.txt
```

#### 注意

编写 npm 脚本时要牢记的一件重要事情是是否有必要使它们独立于平台。例如，如果您正在与一大群开发人员一起工作，其中一些人使用 Windows 机器，另一些人使用 Mac 和/或 Linux，那么在 Windows 中编写的脚本可能会在 Unix 世界中失败，反之亦然。JavaScript 是这种情况的完美用例，因为 Node.js 为您抽象了平台依赖性。

正如我们在上一章中看到的，有时我们想从网页中提取数据。在那一章中，我们使用了一些 JavaScript，它是从开发者工具控制台选项卡中注入到页面中的，这样就不需要为此编写应用程序。现在，您将编写一个 Node.js 应用程序来做类似的事情。

### 活动 3：创建一个用于解析 HTML 的 npm 包

在这个活动中，您将使用 npm 创建一个新的包。然后，您将编写一些 Node.js 代码来使用名为`cheerio`的库加载和解析 HTML 代码。有了加载的 HTML，您将查询和操作它。最后，您将打印操作后的 HTML 以查看结果。

执行的步骤如下：

1.  使用 npm 在新文件夹中创建一个新包。

1.  使用`npm install`（[`www.npmjs.com/package/cheerio`](https://www.npmjs.com/package/cheerio)）安装一个名为`cheerio`的库。

1.  创建一个名为`index.js`的新条目文件，并在其中加载`cheerio`库。

1.  创建一个变量，用于存储*第一章，JavaScript，HTML 和 DOM*中第一个示例的 HTML（文件可以在 GitHub 上找到：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Example/sample_001/sample-page.html`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson01/Example/sample_001/sample-page.html)）。

1.  使用 cheerio 加载和解析 HTML。

1.  在加载的 HTML 中的`div`中添加一个带有一些文本的段落元素。

1.  使用 cheerio，迭代当前页面中的所有段落，并将它们的内容打印到控制台。

1.  打印控制台的操作版本。

1.  运行您的应用程序。

输出应该看起来像下面这样：

![图 2.6：从 node.js 调用应用程序后的预期输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_02_06.jpg)

###### 图 2.6：从 Node.js 调用应用程序后的预期输出

#### 注意

此活动的解决方案可在第 588 页找到。

在本活动中，你使用 npm init 命令创建了一个 Node.js 应用程序。然后，你导入了一个 HTML 解析库，用它来操作和查询解析后的 HTML。在下一章中，我们将继续探索技术，帮助我们更快地抓取网页，并且我们将实际应用于一个网站。

## 总结

在本章中，我们了解了 Node.js 是什么，以及它的单线程、异步、事件驱动的编程模型如何用于构建简单高效的应用程序。我们还学习了 nvm 以及如何管理多个 Node.js 版本。然后，我们学习了 npm，并在我们的 Node.js 应用程序中使用了外部库。最后，我们学习了 npm 脚本以及与其相关的一些基本概念。

为了帮助你理解本章学到的内容，你可以去 npm 仓库，找一些项目，探索它们的代码库。了解 npm、Node.js 以及存在的包和库的最佳方法是探索其他人的代码，看看他们是如何构建的，以及他们使用了哪些库。

在下一章中，我们将探索 Node.js 的 API，并学习如何使用它们来构建一个真正的网页抓取应用程序。在未来的章节中，你将学习如何使用 npm 脚本和包来通过 linting 和自动化测试来提高代码质量。
