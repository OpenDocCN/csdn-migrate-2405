# React 挂钩学习手册（一）

> 原文：[`zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667`](https://zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

React 是一个用于构建高效和可扩展的 Web 应用程序的 JavaScript 库。React 由 Facebook 开发，被用于许多大型 Web 应用程序，如 Facebook、Instagram、Netflix 和 WhatsApp Web。

React Hooks 是在 React 16.8 版本中引入的，解决了许多 React 项目中的常见问题。Hooks 使组件变得不那么复杂，更简洁，更易于阅读和重构。此外，它们使许多 React 功能更容易使用和理解，避免了使用包装组件。

本书是学习 React Hooks 的权威指南。您将学习如何使用 React Hooks 管理 React 组件中的状态和效果，以及如何使用其他 React 功能，如上下文，通过 Hooks。通过实际示例，您将学习如何使用易于扩展和理解的代码开发大型高效的应用程序。

本书还涉及高级概念，如将 Hooks 与 Redux 和 MobX 等库结合使用。此外，您将学习如何有效地将现有项目迁移到 React Hooks。

# 本书适合对象

本书适用于任何级别的 JavaScript 和 React 框架的 Web 开发人员。本书还将满足那些因其先进的功能集和能力而迁移到 React 的开发人员的需求。

# 本书涵盖内容

第一章 *介绍 React 和 React Hooks*，介绍了 React 和 React Hooks 的基本原理，它们是什么以及为什么要使用它们。然后，我们通过介绍 State Hook 作为替代类组件中的 React 状态来了解 Hooks 的功能。最后，我们介绍了 React 提供的各种 Hooks，并介绍了本书中将要学习的一些 Hooks。

第二章 *使用 State Hook*，通过重新实现`useState` Hook 来深入讲解 Hook 的工作原理。通过这样做，我们发现了 Hooks 的某些限制。然后，我们将重新实现的 Hook 与真正的 Hooks 进行比较。此外，我们介绍了替代的 Hook API，并讨论了它们所面临的问题。最后，我们学习如何使用 Hooks 解决常见问题，如条件 Hooks 和循环中的 Hooks。

第三章，“使用 React Hooks 编写你的第一个应用程序”，将前两章学到的知识付诸实践，通过使用 React Hooks，特别是 State Hook，开发博客应用程序。在本章中，我们还学习了如何以可扩展的方式构建 React 项目结构。

第四章，“使用 Reducer 和 Effect Hooks”，从学习简单的 State Hook 并将其应用到实践中开始。我们将学习 React 库预定义的另外两个主要 Hooks：Reducer 和 Effect Hooks。首先我们学习何时应该使用 Reducer Hook 而不是 State Hook。然后我们学习如何将现有的 State Hook 转换为 Reducer Hook 以了解概念。最后，我们学习如何使用 Effect Hooks 实现更高级的功能。

第五章，“实现 React Context”，解释了 React 上下文以及如何在我们的应用程序中使用它。然后我们在博客应用程序中实现 React 上下文，以提供主题功能和使用 Context Hooks 的全局状态。

第六章，“实现请求和 React Suspense”，涵盖了使用 Effect Hook 和 State 或 Reducer Hook 从服务器请求资源的内容。然后我们学习如何使用`React.memo`来防止不必要的组件重新渲染。最后，我们了解了 React Suspense，它可以用于推迟渲染直到满足条件，也称为延迟加载。

第七章，“使用 Hooks 进行路由”，解释了如何在我们的博客应用程序中使用 Hooks 来实现路由。我们了解了 Navi，这是一个用于 React 的路由库，它利用了 Hooks 和 Suspense。我们首先在应用程序中实现页面，然后定义路由，最后开始实现路由 Hooks。

第八章《使用社区钩子》解释了 React 社区已经开发了各种利用钩子的库。在本章中，我们将学习如何实现来自社区的各种钩子，以及在哪里找到更多的钩子。我们首先学习了输入处理钩子。接下来，我们学习如何用钩子替换 React 生命周期方法。然后，我们学习了各种有用的钩子和使用钩子进行响应式设计。此外，我们学习了如何使用钩子实现撤销/重做功能。最后，我们学习了在社区提供的其他钩子的位置。

第九章《Hooks 的规则》涵盖了 Hooks 的规则。掌握 Hooks 的规则对于构建我们自己的 Hooks 非常重要，而这将在下一章中进行。我们还深入了解了 Hooks 的限制，并发现了需要注意的事项。最后，我们学习了如何使用代码检查器强制执行 Hooks 的规则。

第十章《构建自己的 Hooks》从 Hooks 的基本概念开始。我们现在将构建自己的 Hooks。我们首先从我们的博客应用程序的现有函数中提取一个自定义的 Hook，然后学习如何使用我们的自定义 Hook。接下来，我们学习了如何在 Hooks 之间传递信息。最后，我们学习了 React Hooks API 以及我们可以使用的其他 Hooks 来构建我们自己的 Hooks。在本章结束时，我们的应用程序将完全由 Hooks 驱动！

第十一章《从 React 类组件迁移》涵盖了使用 React 类组件处理状态。我们首先使用类组件实现了一个简单的 ToDo 应用程序。然后，我们学习如何将使用类组件的现有项目迁移到基于 Hooks 的实现。最后，我们学习了使用类组件与 Hooks 的权衡以及有效迁移现有项目的策略。

第十二章《Redux 和 Hooks》解释了使用 Redux 处理状态。我们首先将现有的 ToDo 应用程序迁移到 Redux，然后学习如何使用 Redux 与 Hooks。此外，我们学习了如何将现有的 Redux 应用程序迁移到 Hooks。最后，我们学习了使用 Redux 的权衡。

第十三章，*MobX 和 Hooks*，涵盖了使用 MobX 进行状态处理。我们首先将现有的 ToDo 应用程序迁移到 MobX。然后我们学习如何使用 Hooks 与 MobX。此外，我们还学习了如何将现有的 MobX 应用程序迁移到 Hooks。最后，我们了解了使用 MobX 的权衡之处。

# 充分利用本书

我们假设您已经以某种方式使用过 React，尽管本书也适合 React 的完全初学者。

请注意，强烈建议您自己编写代码。不要简单地运行提供的代码示例。重要的是要自己编写代码，以便正确学习和理解。但是，如果遇到任何问题，您可以随时参考代码示例。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择支持选项卡。

1.  单击“代码下载”。

1.  在搜索框中输入书名，并按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的以下软件解压缩文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/Learn-React-Hooks`](https://github.com/PacktPublishing/Learn-React-Hooks)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781838641443_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781838641443_ColorImages.pdf)。

# 实际操作中的代码

访问以下链接查看代码运行的视频：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL 和用户输入。以下是一个例子：“JavaScript 类提供了一个`render`方法，该方法返回用户界面（通常通过 JSX）。”

代码块设置如下：

```jsx
class Example extends React.Component {
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
    constructor (props) {
        super(props)
        this.state = { name: '' }
        this.handleChange = this.handleChange.bind(this)
    }
```

任何命令行输入或输出都以以下形式书写：

```jsx
> npm run-script build
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。以下是一个例子：“在本章中，我们还将学习有关**JSX**以及**ES6**引入的新 JavaScript 功能，直到**ES2018**。”

在代码块中，我们使用粗体格式来突出代码中的更改。通常，我们使用粗体来突出新代码。如果指定，我们可能还会使用粗体格式来指示应删除的代码部分。

警告或重要提示会出现在这样的形式中。提示和技巧会以这种形式出现。


# 第一部分：Hooks 简介

在本书的第一部分，我们将介绍并涵盖 React 和 React Hooks 的基础知识，包括为什么以及如何使用它们。随后，我们将在实际环境中运用所学知识，使用 React Hooks 创建一个博客应用程序。

在本节中，我们将涵盖以下章节：

+   第一章，*介绍 React 和 React Hooks*

+   第二章，*使用 State Hook*

+   第三章，*使用 React Hooks 编写你的第一个应用程序*


# 第一章：介绍 React 和 React Hooks

React 是一个可以用于构建高效和可扩展 Web 应用程序的 JavaScript 库。React 由 Facebook 开发，并在许多大型 Web 应用程序中使用，如 Facebook、Instagram、Netflix 和 WhatsApp Web。

在本书中，我们将学习如何使用 React 构建复杂和高效的用户界面，同时保持代码简单和可扩展。使用 React Hooks 的新范式，我们可以极大地简化在 Web 应用程序中处理状态管理和副作用，确保以后应用程序的增长和扩展潜力。我们还将学习有关**React 上下文**和**React 悬挂**，以及它们如何与 Hooks 一起使用。之后，我们将学习如何将**Redux**和**MobX**与 React Hooks 集成。最后，我们将学习如何从现有的 React 类组件、Redux 和 MobX Web 应用程序迁移到 React Hooks。

在本书的第一章中，我们将学习 React 和 React Hooks 的基本原则。我们首先学习 React 和 React Hooks 是什么，以及为什么我们应该使用它们。然后，我们继续学习 Hooks 的功能。最后，我们介绍了 React 提供的各种 Hooks 的类型，以及本书中将要学习的一些 Hooks。通过学习 React 和 React Hooks 的基础知识，我们将更好地理解本书中将介绍的概念。

本章将涵盖以下主题：

+   了解 React 的基本原则

+   激发对 React Hooks 的需求

+   开始使用 React Hooks

+   概述各种 Hooks

# 技术要求

应该已经安装了相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter01`](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter01)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行之前提供的代码示例。重要的是要自己编写代码，以便正确学习和理解它。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始这一章。

# React 的原则

在我们开始学习 React Hooks 之前，我们将学习 React 的三个基本原则。这些原则使我们能够轻松编写可扩展的 Web 应用程序。了解这些基本原则很重要，因为它们将帮助我们理解 Hooks 如何以及为什么适用于 React 生态系统。

React 基于三个基本原则：

+   **声明式**：我们告诉 React 我们想要它做什么，而不是告诉它如何做事情。因此，我们可以轻松设计我们的应用程序，当数据发生变化时，React 将高效地更新和渲染正确的组件。例如，下面的代码是命令式的，它是声明式的相反：

```jsx
const input = ['a', 'b', 'c']
let result = []
for (let i = 0; i < input.length; i++) {
    result.push(input[i] + input[i])
}
console.log(result) // prints: [ 'aa', 'bb', 'cc' ]
```

正如我们所看到的，命令式代码中，我们需要一步一步地告诉计算机要做什么。然而，使用声明式代码，我们只需告诉计算机我们想要什么，如下所示：

```jsx
const input = ['a', 'b', 'c']
let result = input.map(str => str + str)
console.log(result) // prints: [ 'aa', 'bb', 'cc' ]
```

在前面的声明式代码中，我们告诉计算机我们想要将`input`数组的每个元素从`str`映射到`str + str`。如我们所见，声明式代码要简洁得多。

+   **基于组件**：React 封装了管理自己状态和视图的组件，然后允许我们组合它们以创建复杂的用户界面。

+   **学一次，随处编写**：React 不对您的技术栈做出假设，并尽量确保您可以开发应用程序而尽量不重写现有代码。

我们刚提到 React 是基于组件的。在 React 中，有两种类型的组件：

+   **函数组件**：以 props 作为参数的 JavaScript 函数，并返回用户界面（通常通过 JSX）

+   **类组件**：提供`render`方法的 JavaScript 类，该方法返回用户界面（通常通过 JSX）

虽然函数组件更容易定义和理解，但是类组件需要处理状态、上下文和 React 的许多高级功能。然而，使用 React Hooks，我们可以处理 React 的高级功能而不需要类组件！

# 使用 React Hooks 的动机

React 的三个基本原则使得编写代码、封装组件和在多个平台上共享代码变得容易。React 总是尽量利用现有的 JavaScript 特性，而不是重复造轮子。因此，我们将学习软件设计模式，这些模式将适用于许多情况，而不仅仅是设计用户界面。

React 始终努力使开发者体验尽可能顺畅，同时确保保持足够的性能，而开发者不必过多担心如何优化性能。然而，在使用 React 的多年中，已经确定了一些问题。

让我们在接下来的章节中详细看看这些问题。

# 混乱的类

过去，我们必须使用带有特殊函数的类组件，称为生命周期方法，例如`componentDidUpdate`，以及特殊的状态处理方法，例如`this.setState`，以处理状态变化。React 类，尤其是 JavaScript 对象的`this`上下文，对人类和机器来说都很难阅读和理解。

`this`是 JavaScript 中的一个特殊关键字，它总是指向它所属的对象：

+   在方法中，`this`指的是类对象（类的实例）。

+   在事件处理程序中，`this`指的是接收到事件的元素。

+   在函数或独立状态下，`this`指的是全局对象。例如，在浏览器中，全局对象是`Window`对象。

+   在严格模式下，`this`在函数中是`undefined`。

+   此外，`call()`和`apply()`等方法可以改变`this`所指的对象，因此它可以指向任何对象。

对于人类来说，类很难，因为`this`总是指向不同的东西，所以有时（例如在事件处理程序中）我们需要手动重新绑定它到类对象。对于机器来说，类很难，因为机器不知道类中的哪些方法将被调用，以及`this`将如何被修改，这使得优化性能和删除未使用的代码变得困难。

此外，类有时要求我们同时在多个地方编写代码。例如，如果我们想在组件渲染时获取数据，或者数据更新时获取数据，我们需要使用两种方法来做到这一点：一次在`componentDidMount`中，一次在`componentDidUpdate`中。

举个例子，让我们定义一个从**应用程序编程接口**（**API**）获取数据的类组件：

1.  首先，我们通过扩展`React.Component`类来定义我们的类组件：

```jsx
class Example extends React.Component {
```

1.  然后，我们定义`componentDidMount`生命周期方法，在这里我们从 API 中获取数据：

```jsx
        componentDidMount () {
            fetch(`http://my.api/${this.props.name}`)
                .then(...)
        }
```

1.  然而，我们还需要定义`componentDidUpdate`生命周期方法，以防`name`属性发生变化。此外，我们需要在这里添加一个手动检查，以确保只有在`name`属性发生变化时才重新获取数据，而不是在其他属性发生变化时：

```jsx
    componentDidUpdate (prevProps) {
        if (this.props.name !== prevProps.name) {
            fetch(`http://my.api/${this.props.name}`)
                .then(...)
        }
    }
}
```

1.  为了使我们的代码更少重复，我们可以定义一个名为`fetchData`的单独方法，以便获取我们的数据，如下所示：

```jsx
        fetchData () {
            fetch(`http://my.api/${this.props.name}`)
                .then(...)
        }
```

1.  然后，我们可以在`componentDidMount`和`componentDidUpdate`中调用该方法：

```jsx
        componentDidMount () {
            this.fetchData()
        }

        componentDidUpdate (prevProps) {
            if (this.props.name !== prevProps.name) {
                this.fetchData()
```

```jsx
            }
        }
```

然而，即使这样，我们仍然需要在两个地方调用`fetchData`。每当我们更新传递给方法的参数时，我们需要在两个地方更新它们，这使得这种模式非常容易出现错误和未来的 bug。

# 包装地狱

在 Hooks 之前，如果我们想要封装状态管理逻辑，我们必须使用高阶组件和渲染属性。例如，我们创建一个使用上下文来处理用户认证的 React 组件如下：

1.  我们首先通过导入`authenticateUser`函数来包装我们的组件与上下文，以及`AuthenticationContext`组件来访问上下文：

```jsx
import authenticateUser, { AuthenticationContext } from './auth'
```

1.  然后，我们定义了我们的`App`组件，在这里我们使用了`AuthenticationContext.Consumer`组件和`user`渲染属性：

```jsx
const App = () => (
    <AuthenticationContext.Consumer>
        {user =>
```

1.  现在，我们根据用户是否已登录来显示不同的文本：

```jsx
                user ? `${user} logged in` : 'not logged in'
```

在这里，我们使用了两个 JavaScript 概念：

+   +   一个三元运算符，它是`if`条件的内联版本。它看起来如下：`ifThisIsTrue ? returnThis : otherwiseReturnThis`。

+   一个模板字符串，它可以用来将变量插入到字符串中。它用反引号（`` ` ``) 而不是普通的单引号（`'`）。 变量可以通过`${ variableName}`语法插入。我们还可以在`${}`括号内使用任何JavaScript表达式，例如`${someValue + 1}`。

1.  最后，我们在用`authenticateUser`上下文包装后导出我们的组件：

```jsx
        }
    </AuthenticationContext.Consumer>
)

export default authenticateUser(App)
```

在前面的示例中，我们使用了高阶的`authenticateUser`组件来为现有组件添加身份验证逻辑。然后，我们使用`AuthenticationContext.Consumer`通过其渲染属性将`user`对象注入到我们的组件中。

正如您可以想象的那样，使用许多上下文将导致一个庞大的树，其中有许多子树，也称为**包装器地狱**。例如，当我们想使用三个上下文时，包装器地狱看起来如下：

```jsx
<AuthenticationContext.Consumer>
    {user => (
        <LanguageContext.Consumer>
            {language => (
                <StatusContext.Consumer>
                    {status => (
                        ...
                    )}
                </StatusContext.Consumer>
            )}
        </LanguageContext.Consumer>
    )}
</AuthenticationContext.Consumer>
```

这并不容易阅读或编写，如果我们以后需要更改某些内容，它也容易出错。此外，包装器地狱使得调试变得困难，因为我们必须查看一个庞大的组件树，其中许多组件仅作为包装器。

# 钩子来救援！

React 钩子基于与 React 相同的基本原则。它们试图通过使用现有的 JavaScript 功能来封装状态管理。因此，我们不再需要学习和理解专门的 React 功能；我们可以简单地利用我们现有的 JavaScript 知识来使用钩子。

使用钩子，我们可以解决所有前面提到的问题。我们不再需要使用类组件，因为钩子只是可以在函数组件中调用的函数。我们也不再需要为上下文使用高阶组件和渲染属性，因为我们可以简单地使用上下文钩子来获取我们需要的数据。此外，钩子允许我们在组件之间重用有状态的逻辑，而不需要创建高阶组件。

例如，上述生命周期方法的问题可以通过使用钩子来解决，如下所示：

```jsx
function Example ({ name }) {
    useEffect(() => {
        fetch(`http://my.api/${this.props.name}`)
            .then(...)
    }, [ name ])
    // ...
}
```

这里实现的 Effect Hook 将在组件挂载时自动触发，并且每当`name`属性发生变化时。

此外，前面提到的包装器地狱也可以通过使用钩子来解决，如下所示：

```jsx
    const user = useContext(AuthenticationContext)
    const language = useContext(LanguageContext)
    const status = useContext(StatusContext)
```

既然我们知道钩子可以解决哪些问题，让我们开始在实践中使用钩子吧！

# 开始使用 React 钩子

正如我们所见，React 钩子解决了许多问题，尤其是大型 Web 应用程序的问题。钩子是在 React 16.8 中添加的，它们允许我们使用状态以及各种其他 React 功能，而不必编写类。在本节中，我们将首先使用`create-react-app`初始化一个项目，然后我们将定义一个类组件，最后我们将使用钩子将同一组件编写为函数组件。在本节结束时，我们将讨论钩子的优势，以及我们如何着手迁移到基于钩子的解决方案。

# `create-react-app`初始化项目

要初始化 React 项目，我们可以使用`create-react-app`工具，该工具为 React 开发设置了环境，包括以下内容：

+   Babel，以便我们可以使用 JSX 和 ES6 语法

+   它甚至包括超出 ES6 的语言扩展，例如对象展开运算符，我们将在后面使用

+   此外，我们甚至可以使用 TypeScript 和 Flow 语法

此外，`create-react-app`设置了以下内容：

+   自动添加前缀的**层叠样式表**（**CSS**），这样我们就不需要特定浏览器的`-webkit`等前缀

+   一个快速的交互式单元测试运行器，带有代码覆盖报告

+   一个实时开发服务器，它会警告我们常见的错误

+   一个构建脚本，它为生产捆绑 JavaScript、CSS 和图像，包括哈希值和源映射

+   一个离线优先的服务工作者和一个 Web 应用清单，以满足**渐进式 Web 应用**（**PWA**）的所有标准

+   对前面列出的所有工具的无忧更新

正如我们所见，`create-react-app`工具使 React 开发对我们来说变得更加容易。它是我们学习 React 以及部署 React 应用程序到生产环境的完美工具。

# 创建新项目

为了设置一个新项目，我们运行以下命令，该命令创建一个名为`<app-name>`的新目录：

```jsx
> npx create-react-app <app-name>
```

如果你更喜欢使用`yarn`包管理器，你可以运行`yarn create react-app <app-name>`来代替。

我们现在将使用`create-react-app`创建一个新项目。运行以下命令以创建第一个章节中的第一个示例的新 React 项目：

```jsx
> npx create-react-app chapter1_1
```

既然我们已经初始化了项目，让我们继续启动项目。

# 启动项目

为了在开发模式下启动项目，我们必须运行`npm start`命令。运行以下命令：

```jsx
> npm start
```

现在，我们可以通过在浏览器中打开`http://localhost:3000`来访问我们的项目：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/0a60f3e7-17d3-415e-bb06-6f135db4f8ec.png)

我们的第一个 React 应用！

正如我们所见，使用`create-react-app`，设置一个新的 React 项目相当容易！

# 部署项目

为了构建用于生产部署的项目，我们只需运行`build`脚本：

1.  运行以下命令以构建用于生产部署的项目：

```jsx
> npm run-script build
```

使用`yarn`，我们可以简单地运行`yarn build`。实际上，我们可以以这种方式运行任何不与内部`yarn`命令名称冲突的包脚本：`yarn <script-name>`，而不是`npm run-script <script-name>`。

1.  然后，我们可以使用 Web 服务器或使用`serve`工具来提供我们的静态构建文件夹。首先，我们必须安装它：

```jsx
> npm install -g serve
```

1.  然后，我们可以运行以下`serve`命令：

```jsx
> serve -s build
```

`serve`命令的`-s`标志将所有未找到的请求重写为`index.html`，允许客户端路由。

现在，我们可以通过在浏览器中打开`http://localhost:5000`来访问同一个应用。请注意，`serve`工具不会自动在您的浏览器中打开页面。

在了解了`create-react-app`之后，我们现在将用 React 编写我们的第一个组件。

# 从类组件开始

首先，我们从传统的 React 类组件开始，它允许我们输入一个名字，然后我们在我们的应用中显示这个名字。

# 设置项目

如前所述，我们将使用`create-react-app`来初始化我们的项目。如果你还没有这样做，现在运行以下命令：

```jsx
> npx create-react-app chapter1_1
```

接下来，我们将把我们的应用定义为类组件。

# 定义类组件

我们首先将我们的应用编写为传统的类组件，如下所示：

1.  首先，我们从`src/App.js`文件中删除所有代码。

1.  接下来，在`src/App.js`中，我们导入`React`：

```jsx
import React from 'react'     
```

1.  然后，我们开始定义我们自己的类组件——`MyName`：

```jsx
class MyName extends React.Component {
```

1.  接下来，我们必须定义一个`constructor`方法，在其中设置初始的`state`对象，这将是一个空字符串。在这里，我们还需要确保调用`super(props)`，以便让`React.Component`构造函数知道`props`对象：

```jsx
    constructor (props) {
        super(props)
        this.state = { name: '' }
    }
```

1.  现在，我们定义一个方法来设置`name`变量，使用`this.setState`。由于我们将使用这个方法来处理来自文本字段的输入，我们需要使用`evt.target.value`来从输入字段获取值：

```jsx
   handleChange (evt) {
       this.setState({ name: evt.target.value })
   }
```

1.  然后，我们定义`render`方法，在其中我们将显示一个输入字段和名字：

```jsx
   render () {
```

1.  为了从`this.state`对象中获取`name`变量，我们将使用解构：

```jsx
       const { name } = this.state
```

前面的语句等同于做以下操作：

```jsx
       const name = this.state.name
```

1.  然后，我们显示当前输入的`name`状态变量：

```jsx
    return (
        <div>
            <h1>My name is: {name}</h1>
```

1.  我们显示一个`input`字段，将处理方法传递给它：

```jsx
                <input type="text" value={name} onChange={this.handleChange} />
            </div>
        )
    }
}
```

1.  最后，我们导出我们的类组件：

```jsx
export default MyName
```

如果我们现在运行这段代码，当我们输入文本时，我们会得到以下错误，因为将处理方法传递给`onChange`改变了`this`上下文：

未捕获的 TypeError：无法读取未定义的属性'setState'

1.  所以，现在我们需要调整`constructor`方法并重新绑定我们处理方法的`this`上下文到类：

```jsx
    constructor (props) {
        super(props)
        this.state = { name: '' }
        this.handleChange = this.handleChange.bind(this)
    }
```

有可能使用箭头函数作为类方法，以避免重新绑定`this`上下文。然而，为了使用这个特性，我们需要安装 Babel 编译器插件，`@babel/plugin-proposal-class-properties`，因为它还不是已发布的 JavaScript 特性。

最后，我们的组件工作了！如你所见，为了使状态处理在类组件中正常工作，需要编写大量的代码。我们还需要重新绑定`this`上下文，否则我们的处理方法将无法工作。这并不直观，而且在开发过程中很容易忽略，导致令人讨厌的开发体验。

# 示例代码

示例代码可以在`Chapter01/chapter1_1`文件夹中找到。

只需运行`npm install`来安装所有依赖项，并运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果它没有自动打开）。

# 使用 Hooks 替代

使用传统的类组件编写我们的应用之后，我们将使用 Hooks 来编写相同的应用。和之前一样，我们的应用将允许我们输入一个名字，然后在我们应用中显示这个名字。

请注意，只有在 React 函数组件中才能使用 Hooks。你不能在 React 类组件中使用 Hooks！

现在，我们开始设置项目。

# 设置项目

再次，我们使用`create-react-app`来设置我们的项目：

```jsx
> npx create-react-app chapter1_2
```

现在让我们开始使用 Hooks 定义函数组件。

# 定义函数组件

现在，我们将同一个组件定义为函数组件：

1.  首先，我们从`src/App.js`文件中删除所有代码。

1.  接下来，在`src/App.js`中，我们导入 React 和**`useState`** Hook：

```jsx
    import React, { useState } from 'react'
```

1.  我们从函数定义开始。在我们的例子中，我们没有传递任何参数，因为我们的组件没有任何 props：

```jsx
    function MyName () {
```

下一步将是从组件状态中获取`name`变量。但是，我们不能在函数组件中使用`this.state`。我们已经了解到 Hooks 只是 JavaScript 函数，但这究竟意味着什么？这意味着我们可以像使用任何其他 JavaScript 函数一样，直接从函数组件中使用 Hooks！

通过 Hooks 使用状态，我们调用`useState()`函数，并将初始状态作为参数传递。该函数返回一个包含两个元素的数组：

+   +   当前状态

    +   设置状态的 setter 函数

1.  我们可以使用解构来将这两个元素分别存储在单独的变量中，如下所示：

```jsx
            const [ name, setName ] = useState('')
```

前面的代码等同于以下代码：

```jsx
            const nameHook = useState('')
            const name = nameHook[0]
            const setName = nameHook[1]
```

1.  现在，我们定义输入处理函数，在其中我们使用`setName` setter 函数：

```jsx
            function handleChange (evt) {
                setName(evt.target.value)
            }
```

由于我们现在不处理类，因此不再需要重新绑定`this`了！

1.  最后，我们通过从函数返回它来渲染我们的用户界面。然后，我们导出函数组件：

```jsx
    return (
        <div>
            <h1>My name is: {name}</h1>
            <input type="text" value={name} onChange={handleChange} />
        </div>
    )
}

export default MyName
```

就这样——我们第一次成功地使用了 Hooks！如您所见，`useState` Hook 是`this.state`和`this.setState`的直接替代品。

让我们通过执行`npm start`来运行我们的应用，并在浏览器中打开`http://localhost:3000`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/df481a51-52a2-4436-901c-f8ceeb300fa6.png)

我们的第一个使用 Hooks 的 React 应用

在实现同一个应用的类组件和函数组件之后，让我们比较解决方案。

# 示例代码

示例代码可以在`Chapter01/chapter1_2`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果它没有自动打开）。

# 比较解决方案

让我们比较我们的两个解决方案，以便看到类组件和使用 Hooks 的函数组件之间的差异。

# 类组件

类组件使用`constructor`方法来定义状态，并且需要重新绑定`this`以便将处理程序方法传递给`input`字段。完整的类组件代码如下所示：

```jsx
import React from 'react'

class MyName extends React.Component {
    constructor (props) {
        super(props)
        this.state = { name: '' }

        this.handleChange = this.handleChange.bind(this)
    }

    handleChange (evt) {
        this.setState({ name: evt.target.value })
    }

    render () {
        const { name } = this.state
        return (
            <div>
                <h1>My name is: {name}</h1>
                <input type="text" value={name} onChange={this.handleChange} />
            </div>
        )
    }
}

export default MyName
```

正如我们所见，类组件需要大量的样板代码来初始化`state`对象和处理函数。

现在，让我们来看一下函数组件。

# 使用 Hook 的函数组件

函数组件使用`useState` Hook，因此我们不需要处理`this`或`constructor`方法。完整的函数组件代码如下所示：

```jsx
import React, { useState } from 'react'

function MyName () {
    const [ name, setName ] = useState('')

    function handleChange (evt) {
        setName(evt.target.value)
    }

    return (
        <div>
            <h1>My name is: {name}</h1>
            <input type="text" value={name} onChange={handleChange} />
        </div>
    )
}

export default MyName
```

正如我们所见，钩子使我们的代码更加简洁，更容易推理。我们不再需要担心内部工作原理；我们可以简单地通过访问`useState`函数来使用状态！

# 钩子的优势

让我们回顾一下 React 的第一原则：

声明性：我们不是告诉 React 如何做事情，而是告诉它我们想要它做什么。因此，我们可以轻松设计我们的应用程序，而 React 将有效地更新和渲染数据变化时恰好需要的组件。

正如我们在本章中学到的，钩子允许我们编写告诉 React 我们想要什么的代码。然而，使用类组件时，我们需要告诉 React 如何做事情。因此，钩子比类组件更具声明性，使它们更适合 React 生态系统。

钩子因其声明性，使得 React 能够对我们的代码进行各种优化，因为分析函数和函数调用比分析类及其复杂的`this`行为更容易。此外，钩子使得抽象和在组件之间共享常见的有状态逻辑变得更加容易。通过使用钩子，我们可以避免使用渲染属性和高阶组件。

我们可以看到，钩子不仅使我们的代码更加简洁，而且对开发者来说更容易推理，它们还使代码更容易为 React 优化。

# 迁移到钩子

现在，您可能会想：这是否意味着类组件已经过时，我们现在需要将所有内容迁移到钩子？当然不是——钩子是完全可选的。您可以在一些组件中尝试钩子，而不需要重写任何其他代码。React 团队目前也没有计划删除类组件。

现在不必急于将所有内容迁移到钩子。建议您在某些组件中逐步采用钩子，这些组件将最有用。例如，如果您有许多处理类似逻辑的组件，您可以将逻辑提取到钩子中。您还可以在类组件旁边使用带有钩子的函数组件。

此外，钩子是 100%向后兼容的，并提供了一个直接的 API，用于您已经了解的所有 React 概念：**props**、**state**、**context**、**refs**和**生命周期**。此外，钩子提供了新的方式来组合这些概念，并以一种不会导致包装器地狱或类似问题的方式更好地封装它们的逻辑。我们将在本书后面了解更多关于这方面的内容。

# 钩子的思维方式

钩子的主要目标是解耦有状态逻辑和渲染逻辑。它们允许我们在单独的函数中定义逻辑并在多个组件中重用它们。使用钩子，我们不需要为了实现有状态逻辑而改变我们的组件层次结构。不再需要定义一个单独的组件来为多个组件提供状态逻辑，我们可以简单地使用一个钩子！

然而，Hooks 需要与经典 React 开发完全不同的思维方式。我们不应该再考虑组件的生命周期。相反，我们应该考虑数据流。例如，我们可以告诉 Hooks 在某些 props 或其他 Hooks 的值发生变化时触发。我们将在第四章《使用 Reducer 和 Effect Hooks》中学习更多关于这个概念的内容。我们也不应该再根据生命周期来拆分组件。相反，我们可以使用 Hooks 来处理常见的功能，如获取数据或设置订阅。

# Hooks 的规则

Hooks 非常灵活。然而，使用 Hooks 存在一定的限制，我们应该始终牢记：

+   Hooks 只能用于函数组件，不能用于类组件

+   Hook 定义的顺序很重要，需要保持不变；因此，我们不能将 Hooks 放在 `if` 条件语句、循环或嵌套函数中

我们将在本书中更详细地讨论这些限制，以及如何绕过它们。

# 各种 Hooks 的概述

正如我们在上一节中学到的，Hooks 提供了直接访问所有 React 概念的 API。此外，我们可以定义自己的 Hooks，以便在不编写高阶组件的情况下封装逻辑，从而避免包装器地狱。在本节中，我们将概述将在本书中学习的各种 Hooks。

# React 提供的 Hooks

React 已经为不同的功能提供了各种 Hooks。有三个基本 Hooks 和一些额外的 Hooks。

# 基本 Hooks

基本 Hooks 提供了有状态 React 应用中最常用的功能。它们如下：

+   `useState`

+   `useEffect`

+   `useContext`

让我们在接下来的章节中逐一了解这些内容。

# useState

我们已经使用过这个 Hook。它返回一个有状态的值（`state`）和一个设置函数（`setState`）以便更新值。

`useState` Hook 用于处理 React 中的 `state`。我们可以这样使用它：

```jsx
import { useState } from 'react'

const [ state, setState ] = useState(initialState)
```

`useState` Hook 取代了 `this.state` 和 `this.setState()`。

# useEffect

这个 Hook 的工作方式类似于在 `componentDidMount` 和 `componentDidUpdate` 上添加一个函数。此外，Effect Hook 允许从中返回一个清理函数，其工作方式类似于在 `componentWillUnmount` 上添加一个函数。

`useEffect` Hook 用于处理有副作用的代码，如定时器、订阅、请求等。我们可以这样使用它：

```jsx
import { useEffect } from 'react'

useEffect(didUpdate)
```

`useEffect` Hook 取代了 `componentDidMount`、`componentDidUpdate` 和 `componentWillUnmount` 方法。

# useContext

这个 Hook 接受一个上下文对象并返回当前的上下文值。

`useContext` Hook 用于处理 React 中的上下文。我们可以这样使用它：

```jsx
import { useContext } from 'react'

const value = useContext(MyContext)
```

`useContext` Hook 取代了上下文消费者。

# 额外的 Hooks

额外的 Hooks 要么是基本 Hooks 的更通用变体，要么是为某些边缘情况所需的。我们将要查看的额外 Hooks 如下：

+   `useRef`

+   `useReducer`

+   `useMemo`

+   `useCallback`

+   `useLayoutEffect`

+   `useDebugValue`

让我们在以下部分中深入研究这些额外的钩子。

# useRef

此钩子返回一个可变的 `ref` 对象，其中 `.current` 属性被初始化为传入的参数（`initialValue`）。我们可以这样使用它：

```jsx
import { useRef } from 'react'

const refContainer = useRef(initialValue)
```

`useRef` 钩子用于处理 React 中元素和组件的引用。我们可以通过将 `ref` 属性传递给元素或组件来设置引用，如下所示：`<ComponentName ref={refContainer} />`

# useReducer

此钩子是 `useState` 的替代品，与 Redux 库的工作方式类似。我们可以这样使用它：

```jsx
import { useReducer } from 'react'

const [ state, dispatch ] = useReducer(reducer, initialArg, init)
```

`useReducer` 钩子用于处理复杂的状态逻辑。

# useMemo

记忆化是一种优化技术，其中函数调用的结果被缓存，然后在再次出现相同输入时返回。`useMemo` 钩子允许我们计算一个值并将其记忆化。我们可以这样使用它：

```jsx
import { useMemo } from 'react'

const memoizedValue = useMemo(() => computeExpensiveValue(a, b), [a, b])
```

`useMemo` 钩子在避免重新执行昂贵操作时非常有用，有助于优化。

# useCallback

此钩子允许我们传递内联回调函数和依赖项数组，并返回回调函数的记忆化版本。我们可以这样使用它：

```jsx
import { useCallback } from 'react'

const memoizedCallback = useCallback(
    () => {
        doSomething(a, b)
    },
    [a, b]
)
```

`useCallback` 钩子在将回调传递给优化的子组件时非常有用。它与 `useMemo` 钩子类似，但对于回调函数。

# useLayoutEffect

这个钩子与 `useEffect` 相同，但它只在所有 **文档对象模型**（**DOM**）突变后触发。我们可以这样使用它：

```jsx
import { useLayoutEffect } from 'react'

useLayoutEffect(didUpdate)
```

`useLayoutEffect` 钩子可用于读取 DOM 信息。

尽可能使用 `useEffect` 钩子，因为 `useLayoutEffect` 会阻止视觉更新并减慢应用程序速度。

最后，我们将研究在撰写本文时由 React 提供的最后一个钩子。

# useDebugValue

此钩子可用于在创建自定义钩子时在 React DevTools 中显示标签。我们可以这样使用它：

```jsx
import { useDebugValue } from 'react'

useDebugValue(value)
```

确保在自定义钩子中使用此钩子以显示钩子的当前状态，因为它将使调试它们变得更加容易。

# Community Hooks

除了 React 提供的所有钩子之外，社区已经发布了许多库。这些库也提供钩子。我们将要研究的钩子如下：

+   `useInput`

+   `useResource`

+   `useDimensions`

+   Navigation Hooks

+   生命周期钩子

+   Timer Hooks

让我们在以下部分中概述这些钩子是什么。

# useInput

此钩子用于轻松实现输入处理，并将 `input` 字段的状态与变量同步。它可以这样使用：

```jsx
import { useInput } from 'react-hookedup'

function App () {
    const { value, onChange } = useInput('')

    return <input value={value} onChange={onChange} />
}
```

如我们所见，钩子极大地简化了在 React 中处理输入字段的过程。

# useResource

此钩子可用于通过请求在我们的应用程序中实现异步数据加载。我们可以这样使用它：

```jsx
import { useRequest } from 'react-request-hook'

const [profile, getProfile] = useResource(id => ({
    url: `/user/${id}`,
    method: 'GET'
})
```

如我们所见，使用专门处理获取数据的钩子非常简单。

# Navigation Hooks

这些钩子是 Navi 库的一部分，用于在 React 中通过钩子实现路由。Navi 库提供了许多与路由相关的钩子。我们将在本书后面深入学习通过钩子进行路由。我们可以这样使用它们：

```jsx
import { useCurrentRoute, useNavigation } from 'react-navi'

const { views, url, data, status } = useCurrentRoute()
const { navigate } = useNavigation()
```

正如我们所见，钩子使得路由处理变得更加容易。

# 生命周期钩子

`react-hookedup`库提供了各种钩子，包括 React 的所有生命周期监听器。

请注意，在使用钩子开发时不建议从组件生命周期的角度思考。这些钩子只是提供了一种快速重构现有组件到钩子的方法。然而，在开发新组件时，建议你考虑数据流和依赖关系，而不是生命周期。

这里我们列出了两个，但实际上库中提供了更多的钩子，我们将在后面学习。我们可以这样使用`react-hookedup`提供的钩子：

```jsx
import { useOnMount, useOnUnmount } from 'react-hookedup'

useOnMount(() => { ... })
useOnUnmount(() => { ... })
```

正如我们所见，钩子可以直接替换类组件中的生命周期方法。

# 计时器钩子

`react-hookedup`库还提供了用于`setInterval`和`setTimeout`的钩子。这些钩子的工作方式类似于直接调用`setTimeout`或`setInterval`，但作为 React 钩子，它将在重新渲染之间保持持久性。如果我们直接在函数组件中定义计时器而没有使用钩子，我们将在每次组件重新渲染时重置计时器。

我们可以将毫秒数作为第二个参数传递。我们可以这样使用它们：

```jsx
import { useInterval, useTimeout } from 'react-hookedup'

useInterval(() => { ... }, 1000)
useTimeout(() => { ... }, 1000)
```

正如我们所看到的，Hooks 极大地简化了我们在 React 中处理间隔和超时的方式。

# 其他社区 Hooks

正如你可以想象的那样，社区提供了许多其他的 Hooks。我们将深入学习之前提到的社区 Hooks，以及第八章中的其他社区 Hooks：*使用社区 Hooks*。

# 总结

在本书的第一章中，我们首先学习了 React 的基本原则以及它提供的组件类型。然后，我们继续学习了类组件的常见问题，以及如何使用 React 的现有功能，以及它们如何违反基本原则。接下来，我们使用类组件和带有 Hooks 的函数组件实现了一个简单的应用程序，以便能够比较这两种解决方案之间的差异。正如我们所发现的，带有 Hooks 的函数组件更适合 React 的基本原则，因为它们不会遇到类组件的相同问题，并且使我们的代码更加

简洁易懂！最后，我们初次见识了本书中将要学习的各种 Hooks。在本章之后，React 和 React Hooks 的基础知识已经清晰。现在我们可以继续学习更高级的 Hooks 概念。

在下一章中，我们将深入了解 State Hook 的工作原理，通过从头开始重新实现它。通过这样做，我们将了解 Hooks 的内部工作原理以及它们的局限性。之后，我们将使用 State Hook 创建一个小型的博客应用程序！

# 问题

回顾一下我们在本章学到的内容，尝试回答以下问题：

1.  React 的三个基本原则是什么？

1.  React 中有哪两种类型的组件？

1.  React 中类组件存在哪些问题？

1.  在 React 中使用高阶组件的问题是什么？

1.  我们可以使用哪个工具来设置一个 React 项目，我们需要运行什么命令来使用它？

1.  如果我们在类组件中遇到以下错误，我们需要做什么：*TypeError: undefined is not an object (evaluating 'this.setState')*？

1.  我们如何使用 Hooks 访问和设置 React 状态？

1.  使用 Hooks 的函数组件与类组件相比有什么优势？

1.  在更新 React 时，我们是否需要使用 Hooks 替换所有类组件为函数组件？

1.  React 提供的三个基本 Hooks 是什么？

# 进一步阅读

如果您对本章学习的概念感兴趣，可以查看以下阅读材料：

+   在 GitHub 上创建 React 应用程序：[`github.com/facebook/create-react-app#create-react-app--`](https://github.com/facebook/create-react-app#create-react-app--)

+   React Hooks 的 RFC：[`github.com/reactjs/rfcs/blob/master/text/0068-react-hooks.md`](https://github.com/reactjs/rfcs/blob/master/text/0068-react-hooks.md)

+   使用 React 处理输入：[`reactjs.org/docs/forms.html`](https://reactjs.org/docs/forms.html)

+   React 中类组件的状态和生命周期：[`reactjs.org/docs/state-and-lifecycle.html`](https://reactjs.org/docs/state-and-lifecycle.html)

+   解构：[`exploringjs.com/es6/ch_destructuring.html`](http://exploringjs.com/es6/ch_destructuring.html)

+   模板字符串：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals)

+   三元运算符：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Conditional_Operator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Conditional_Operator)


# 第二章：使用 State Hook

现在你已经了解了 React 的原则，并且对 Hooks 有了介绍，我们将深入学习 State Hook。我们将首先通过重新实现来学习 State Hook 的内部工作原理。接下来，我们将了解 Hooks 的一些限制以及它们存在的原因。然后，我们将学习可能的替代 Hook API 及其相关问题。最后，我们将学习如何解决由 Hooks 限制导致的常见问题。通过本章的学习，我们将知道如何使用 State Hook 来实现 React 中的有状态函数组件。

本章将涵盖以下主题：

+   将`useState` Hook 重新实现为一个简单的函数，用于访问全局状态

+   将我们的重新实现与真实的 React Hooks 进行比较，并了解它们之间的区别

+   学习可能的替代 Hook API 及其权衡

+   解决由 Hooks 限制导致的常见问题

+   解决条件 Hooks 的问题

# 技术要求

应该已经安装了一个相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 仓库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter02`](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter02)。

查看以下视频以查看代码的实际运行情况：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行之前提供的代码示例。重要的是您自己编写代码，以便正确地学习和理解它。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始本章的学习。

# 重新实现 useState 函数

为了更好地理解 Hooks 的内部工作原理，我们将从头开始重新实现`useState` Hook。但是，我们不会将其实现为实际的 React Hook，而是作为一个简单的 JavaScript 函数——只是为了了解 Hooks 实际在做什么。

请注意，这个重新实现并不完全是 React Hooks 内部的工作原理。实际的实现是类似的，因此具有类似的约束。然而，真实的实现要比我们在这里实现的要复杂得多。

我们现在将开始重新实现 State Hook：

1.  首先，我们从`chapter1_2`中复制代码，我们将用我们自己的实现替换当前的`useState` Hook。

1.  打开`src/App.js`并通过删除以下行来移除 Hook 的导入：

```jsx
import  React,  {  useState  }  from  'react' 
```

用以下代码替换它：

```jsx
import  React  from  'react'
import ReactDOM from 'react-dom'
```

我们将需要`ReactDOM`来强制重新渲染我们的`useState` Hook 的组件。如果我们使用实际的 React Hooks，这将在内部处理。

1.  现在，我们定义我们自己的`useState`函数。正如我们已经知道的，`useState`函数将`initialState`作为参数：

```jsx
function useState (initialState) {
```

1.  然后，我们定义一个值，我们将在其中存储我们的状态。起初，这个值将被设置为传递给函数的`initialState`：

```jsx
    let value = initialState
```

1.  接下来，我们定义`setState`函数，我们将在其中将值设置为不同的东西，并强制重新渲染我们的`MyName`组件：

```jsx
    function setState (nextValue) {
        value = nextValue
        ReactDOM.render(<MyName />, document.getElementById('root'))
    }
```

1.  最后，我们将`value`和`setState`函数作为数组返回：

```jsx
    return [ value, setState ]
}
```

我们使用数组而不是对象的原因是，我们通常想要重命名`value`和`setState`变量。使用数组使得通过解构很容易重命名变量：

```jsx
const [ name, setName ] = useState('')
```

正如我们所看到的，Hooks 是处理副作用的简单的 JavaScript 函数，比如设置有状态的值。

我们的 Hook 函数使用闭包来存储当前值。闭包是一个环境，变量存在并被存储在其中。在我们的例子中，函数提供了闭包，`value`变量被存储在闭包中。`setState`函数也在同一个闭包中定义，这就是为什么我们可以在该函数中访问`value`变量。在`useState`函数之外，我们不能直接访问`value`变量，除非我们从函数中返回它。

# 我们简单的 Hook 实现存在的问题

如果我们现在运行我们的 Hook 实现，我们会注意到当我们的组件重新渲染时，状态被重置，所以我们无法在字段中输入任何文本。这是因为每次我们的组件重新渲染时`value`变量的重新初始化，这是因为我们每次渲染组件时都调用`useState`。

在接下来的部分，我们将通过使用全局变量来解决这个问题，然后将简单值转换为数组，从而允许我们定义多个 Hooks。

# 使用全局变量

正如我们所学的，值存储在由 `useState` 函数定义的闭包中。每次组件重新渲染时，闭包都会被重新初始化，这意味着我们的值将被重置。为了解决这个问题，我们需要将值存储在函数之外的全局变量中。这样，`value` 变量将在函数之外的闭包中，这意味着当函数再次被调用时，闭包不会被重新初始化。

我们可以定义一个全局变量如下：

1.  首先，在 `useState` 函数定义之前，我们添加以下行（加粗）。

```jsx
let value

function useState (initialState) {
```

1.  然后，我们用以下代码替换我们函数中的第一行：

```jsx
       if (typeof value === 'undefined') value = initialState
```

现在，我们的 `useState` 函数使用全局 `value` 变量，而不是在其闭包中定义 `value` 变量，因此当函数再次被调用时，它不会被重新初始化。

# 定义多个 Hook

我们的 Hook 函数起作用了！但是，如果我们想要添加另一个 Hook，我们会遇到另一个问题：所有的 Hook 都写入同一个全局 `value` 变量！

让我们通过向我们的组件添加第二个 Hook 来更仔细地研究这个问题。

# 向我们的组件添加多个 Hook

假设我们想要为用户的姓氏创建第二个字段，如下所示：

1.  我们首先在函数开头创建一个新的 Hook，放在当前 Hook 之后：

```jsx
    const [ name, setName ] = useState('')
 const [ lastName, setLastName ] = useState('')
```

1.  然后，我们定义另一个 `handleChange` 函数：

```jsx
    function handleLastNameChange (evt) {
        setLastName(evt.target.value)
    }
```

1.  接下来，我们将 `lastName` 变量放在名字后面：

```jsx
 <h1>My name is: {name} **{lastName}**</h1>
```

1.  最后，我们添加另一个 `input` 字段：

```jsx
            <input type="text" value={lastName} onChange={handleLastNameChange}
   />
```

当我们尝试这样做时，我们会注意到我们重新实现的 Hook 函数同时使用相同的值，所以我们总是同时更改两个字段。

# 实现多个 Hook

为了实现多个 Hook，我们应该有一个 Hook 值的数组，而不是一个单一的全局变量。

现在，我们将 `value` 变量重构为 `values` 数组，以便我们可以定义多个 Hook：

1.  删除以下代码行：

```jsx
let value
```

用以下代码片段替换它：

```jsx
let values = []
let currentHook = 0
```

1.  然后，编辑 `useState` 函数的第一行，我们现在在 `values` 数组的 `currentHook` 索引处初始化值：

```jsx
    if (typeof values[currentHook] === 'undefined') values[currentHook] = initialState
```

1.  我们还需要更新 setter 函数，以便只更新相应的状态值。在这里，我们需要将`currentHook`的值存储在单独的`hookIndex`变量中，因为`currentHook`的值稍后会更改。这确保在`useState`函数的闭包中创建了`currentHook`变量的副本。否则，`useState`函数将访问外部闭包中的`currentHook`变量，该变量在每次调用`useState`时都会被修改。

```jsx
    let hookIndex = currentHook
    function setState (nextValue) {
        values[hookIndex] = nextValue
        ReactDOM.render(<MyName />, document.getElementById('root'))
    }
```

1.  编辑`useState`函数的最后一行，如下所示：

```jsx
        return [ values[currentHook++], setState ]
```

使用`values[currentHook++]`，我们将`currentHook`的当前值作为索引传递给`values`数组，然后将`currentHook`增加一。这意味着在从函数返回后`currentHook`将增加。

如果我们想先增加一个值，然后再使用它，我们可以使用`arr[++indexToBeIncremented]`语法，它首先增加，然后将结果传递给数组。

1.  当我们开始渲染组件时，我们仍然需要重置`currentHook`计数器。在组件定义之后添加以下行（用粗体标出）：

```jsx
function Name () {
    currentHook = 0
```

最后，我们对`useState` Hook 的简单重新实现有效！以下截图突出显示了这一点：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/de58db6c-14f4-478c-8f14-074080e7ee47.png)

我们的自定义 Hook 重新实现有效

正如我们所看到的，使用全局数组来存储我们的 Hook 值解决了在定义多个 Hook 时遇到的问题。

# 示例代码

简单 Hook 重新实现的示例代码可以在`Chapter02/chapter2_1`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 我们可以定义条件 Hook 吗？

如果我们想要添加一个复选框来切换使用名字字段，该怎么办？

让我们通过实现这样一个复选框来找出：

1.  首先，我们添加一个新的 Hook 来存储复选框的状态：

```jsx
    const [ enableFirstName, setEnableFirstName ] = useState(false)
```

1.  然后，我们定义一个处理函数：

```jsx
 function  handleEnableChange  (evt)  { setEnableFirstName(!enableFirstName) }
```

1.  接下来，我们渲染一个复选框：

```jsx
            <input type="checkbox" value={enableFirstName} onChange={handleEnableChange} />
```

1.  如果我们不想显示名字，可以编辑以下现有行以添加对`enableFirstName`变量的检查：

```jsx
            <h1>My name is: {enableFirstName ? name : ''} {lastName}</h1>
```

1.  我们是否可以将 Hook 定义放入`if`条件或三元表达式中，就像我们在以下代码片段中所做的那样？

```jsx
    const [ name, setName ] = enableFirstName
        ? useState('')
        : [ '', () => {} ]
```

1.  实际上，最新版本的`react-scripts`在定义条件钩子时会抛出错误，因此我们需要通过运行以下命令来降级库以进行示例：

```jsx
> npm install --save react-scripts@².1.8
```

在这里，我们要么使用钩子，要么如果名字被禁用，我们返回初始状态和一个空的 setter 函数，这样编辑输入字段就不起作用。

如果我们现在尝试运行这段代码，我们会注意到编辑姓氏仍然有效，但编辑名字不起作用，这正是我们想要的。正如我们在以下截图中所看到的，现在只有编辑姓氏有效：

！[](assets/3d7b5e61-a873-4b2d-b8b3-2d7ef07896e6.png)

勾选复选框之前的应用状态

当我们点击复选框时，会发生一些奇怪的事情：

+   复选框已被选中

+   名字输入字段已启用

+   现在姓氏字段的值是名字字段的值

我们可以在以下截图中看到单击复选框的结果：

！[](assets/1796851e-7490-424a-8e4f-8892e2f9babd.png)

勾选复选框后的应用状态

我们可以看到姓氏状态现在在名字字段中。值已经交换，因为钩子的顺序很重要。正如我们从我们的实现中所知，我们使用`currentHook`索引来知道每个钩子的状态存储在哪里。然而，当我们在两个现有钩子之间插入一个额外的钩子时，顺序就会混乱。

在勾选复选框之前，`values`数组如下：

+   `[false, '']`

+   钩子顺序：`enableFirstName`，`lastName`

然后，我们在`lastName`字段中输入了一些文本：

+   `[false, 'Hook']`

+   钩子顺序：`enableFirstName`，`lastName`

接下来，我们切换复选框，激活了我们的新钩子：

+   `[true, 'Hook', '']`

+   钩子顺序：`enableFirstName`，`name`，`lastName`

正如我们所看到的，在两个现有钩子之间插入一个新的钩子会使`name`钩子窃取下一个钩子（`lastName`）的状态，因为它现在具有与`lastName`钩子先前相同的索引。现在，`lastName`钩子没有值，这导致它设置初始值（空字符串）。因此，切换复选框会将`lastName`字段的值放入`name`字段中。

# 示例代码

我们简单的钩子重新实现的条件钩子问题的示例代码可以在`Chapter02/chapter2_2`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 将我们的重新实现与真实的 Hooks 进行比较

我们简单的 Hook 实现已经让我们对 Hooks 内部工作原理有了一些了解。然而，在现实中，Hooks 并不使用全局变量。相反，它们在 React 组件内部存储状态。它们还在内部处理 Hook 计数器，因此我们不需要在函数组件中手动重置计数。此外，当状态改变时，真正的 Hooks 会自动触发我们组件的重新渲染。然而，为了能够做到这一点，Hooks 需要从 React 函数组件中调用。React Hooks 不能在 React 之外或在 React 类组件内部调用。

通过重新实现`useState` Hook，我们学到了一些东西：

+   Hooks 只是访问 React 功能的函数

+   Hooks 处理持续存在于重新渲染中的副作用

+   Hook 定义的顺序很重要

最后一点尤其重要，因为这意味着我们不能有条件地定义 Hooks。我们应该始终在函数组件的开头定义所有的 Hook，并且永远不要在`if`或其他结构中嵌套它们。

在这里，我们还学到了以下内容：

+   React Hooks 需要在 React 函数组件内部调用

+   React Hooks 不能有条件地定义，也不能在循环中定义

我们现在将看一下允许有条件 Hooks 的替代 Hook API。

# 替代 Hook API

有时，有条件地或在循环中定义 Hooks 可能会很好，但为什么 React 团队决定这样实现 Hooks 呢？有什么替代方案吗？让我们来看看其中的一些。

# 命名的 Hooks

我们可以给每个 Hook 一个名称，然后将 Hooks 存储在对象中，而不是数组中。然而，这不会产生一个好的 API，并且我们还必须考虑想出唯一的 Hook 名称：

```jsx
// NOTE: Not the actual React Hook API
const [ name, setName ] = useState('nameHook', '')
```

此外，当条件设置为`false`时，或者从循环中移除一个项目时会发生什么？我们会清除 Hook 状态吗？如果我们不清除 Hook 状态，可能会导致内存泄漏。

即使我们解决了所有这些问题，仍然会存在名称冲突的问题。例如，如果我们创建一个自定义钩子，利用了`useState`钩子，并将其命名为`nameHook`，那么我们在组件中就不能再调用任何其他钩子`nameHook`，否则就会造成名称冲突。这甚至适用于来自库的钩子名称，因此我们需要确保避免与库定义的钩子发生名称冲突！

# 钩子工厂

或者，我们也可以创建一个钩子工厂函数，它在内部使用`Symbol`，以便为每个钩子提供一个唯一的键名：

```jsx
function createUseState () {
    const keyName = Symbol()

    return function useState () {
        // ... use unique key name to handle hook state ...
    }
}
```

然后，我们可以按照以下方式使用工厂函数：

```jsx
// NOTE: Not the actual React Hook API
const useNameState = createUseState()

function MyName () {
    const [ name, setName ] = useNameState('')
    // ...
}
```

然而，这意味着我们需要实例化每个钩子两次：一次在组件外部，一次在函数组件内部。这会增加出错的可能性。例如，如果我们创建两个钩子并复制粘贴样板代码，那么我们可能会在使用工厂函数生成的钩子名称时出错，或者在组件内部使用钩子时出错。

这种方法还使得创建自定义钩子变得更加困难，迫使我们编写包装函数。此外，调试这些包装函数比调试简单函数更加困难。

# 其他替代方案

对于 React Hooks，有许多提出的替代 API，但它们每个都遇到了类似的问题：要么使 API 更难使用，更难调试，要么引入了名称冲突的可能性。

最终，React 团队决定，最简单的 API 是通过计算调用它们的顺序来跟踪 Hooks。这种方法也有其缺点，比如不能在条件语句中或循环中调用 Hooks。然而，这种方法使我们非常容易创建自定义 Hooks，并且简单易用易调试。我们也不需要担心命名钩子、名称冲突或编写包装函数。最终的 Hooks 方法让我们可以像使用任何其他函数一样使用 Hooks！

# 解决钩子的常见问题

正如我们发现的那样，使用官方 API 实现 Hooks 也有其自身的权衡和限制。我们现在将学习如何克服这些常见问题，这些问题源于 React Hooks 的限制。

我们将看看可以用来克服这两个问题的解决方案：

+   解决条件钩子

+   在循环中解决钩子

# 解决条件钩子

那么，如何实现条件 Hooks 呢？与其使 Hook 有条件，不如始终定义 Hook 并在需要时使用它。如果这不是一个选择，我们需要拆分我们的组件，这通常也更好！

# 始终定义 Hook

对于简单的情况，比如我们之前提到的名字示例，我们可以始终保持 Hook 的定义，如下：

```jsx
const [ name, setName ] = useState('')
```

始终定义 Hook 通常是一个简单的解决方案。

# 拆分组件

解决条件 Hooks 的另一种方法是将一个组件拆分为多个组件，然后有条件地渲染这些组件。例如，假设我们想在用户登录后从数据库中获取用户信息。

我们不能这样做，因为使用`if`条件可能会改变 Hook 的顺序：

```jsx
function UserInfo ({ username }) {
    if (username) {
        const info = useFetchUserInfo(username)
        return <div>{info}</div>
    }
    return <div>Not logged in</div>
}
```

相反，我们必须为用户登录时创建一个单独的组件，如下所示：

```jsx
function LoggedInUserInfo ({ username }) {
    const info = useFetchUserInfo(username)
    return <div>{info}</div>
}

function UserInfo ({ username }) {
    if (username) {
        return <LoggedInUserInfo username={username} />
    }
    return <div>Not logged in</div>
}
```

为非登录和登录状态使用两个单独的组件总是有意义的，因为我们希望坚持一个组件一个功能的原则。因此，通常情况下，如果我们坚持最佳实践，不能使用条件 Hooks 并不是什么限制。

# 解决循环中的 Hooks

至于循环中的 Hooks，我们可以使用包含数组的单个 State Hook，或者我们可以拆分我们的组件。例如，假设我们想显示所有在线用户。

# 使用数组

我们可以简单地使用包含所有`users`的数组，如下所示：

```jsx
function OnlineUsers ({ users }) {
    const [ userInfos, setUserInfos ] = useState([])
    // ... fetch & keep userInfos up to date ...
    return (
        <div>
            {users.map(username => {
                const user = userInfos.find(u => u.username === username)
                return <UserInfo {...user} />
            })}
        </div>
    )
}
```

然而，这可能并不总是有意义。例如，我们可能不希望通过`OnlineUsers`组件来更新`user`状态，因为我们需要从数组中选择正确的`user`状态，然后修改数组。这可能有效，但相当繁琐。

# 拆分组件

更好的解决方案是在`UserInfo`组件中使用 Hook。这样，我们可以保持每个用户的状态更新，而不必处理数组逻辑：

```jsx
function OnlineUsers ({ users }) {
    return (
        <div>
            {users.map(username => <UserInfo username={username} />)}
        </div>
    )
}

function UserInfo ({ username }) {
    const info = useFetchUserInfo(username)
    // ... keep user info up to date ...
    return <div>{info}</div>
}
```

正如我们所看到的，为每个功能使用一个组件可以使我们的代码简单而简洁，并且避免了 React Hooks 的限制。

# 解决条件 Hooks 的问题

现在我们已经了解了条件 Hooks 的不同替代方案，我们将解决之前在我们的小示例项目中遇到的问题。这个问题的最简单解决方案是总是定义 Hook，而不是有条件地定义它。在这样一个简单的项目中，总是定义 Hook 是最合理的。

编辑`src/App.js`并删除以下条件 Hook：

```jsx
 const  [  name,  setName  ]  =  enableFirstName ?  useState('') : [ '',  ()  =>  {} ]
```

用一个普通的 Hook 替换它，比如以下内容：

```jsx
    const [ name, setName ] = useState('')
```

现在，我们的示例运行良好！在更复杂的情况下，总是定义 Hook 可能不可行。在这种情况下，我们需要创建一个新组件，在那里定义 Hook，然后有条件地渲染组件。

# 示例代码

简单解决条件 Hooks 问题的示例代码可以在`Chapter02/chapter2_3`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 总结

在本章中，我们首先通过使用全局状态和闭包重新实现了`useState`函数。然后我们了解到，为了实现多个 Hooks，我们需要使用状态数组。然而，通过使用状态数组，我们被迫保持 Hooks 在函数调用中的顺序一致。这种限制使得条件 Hooks 和循环中的 Hooks 变得不可能。然后我们了解了 Hook API 的可能替代方案，它们的权衡以及为什么选择了最终的 API。最后，我们学会了如何解决由 Hooks 限制引起的常见问题。我们现在对 Hooks 的内部工作原理和限制有了扎实的理解。此外，我们深入了解了 State Hook。

在下一章中，我们将使用 State Hook 创建一个博客应用程序，并学习如何结合多个 Hooks。

# 问题

总结一下我们在本章学到的内容，尝试回答以下问题：

1.  在开发我们自己的`useState` Hook 的重新实现时，我们遇到了什么问题？我们是如何解决这些问题的？

1.  为什么在 React 的 Hooks 实现中条件 Hooks 不可能？

1.  Hooks 是什么，它们处理什么？

1.  在使用 Hooks 时，我们需要注意什么？

1.  替代 API 想法的常见问题是什么？

1.  我们如何实现条件 Hooks？

1.  我们如何在循环中实现 Hooks？

# 进一步阅读

如果您对本章学习的概念想了解更多，请参考以下阅读材料：

+   有关替代 Hook API 缺陷的更多信息：[`overreacted.io/why-do-hooks-rely-on-call-order/`](https://overreacted.io/why-do-hooks-rely-on-call-order/)

+   官方对替代 Hook API 的评论：[`github.com/reactjs/rfcs/pull/68#issuecomment-439314884`](https://github.com/reactjs/rfcs/pull/68#issuecomment-439314884)

+   有关条件 Hooks 不起作用的官方文档：[`reactjs.org/docs/hooks-rules.html#explanation`](https://reactjs.org/docs/hooks-rules.html#explanation)


# 第三章：使用 React Hooks 编写您的第一个应用程序

深入了解 State Hook 后，我们现在将利用它从头开始创建一个博客应用程序。在本章中，我们将学习如何以可扩展的方式构建 React 应用程序，如何使用多个 Hooks，如何存储状态以及如何使用 Hooks 解决常见用例。在本章结束时，我们将拥有一个基本的博客应用程序，可以在其中登录、注册和创建帖子。

本章将涵盖以下主题：

+   以可扩展的方式构建 React 项目

+   从模拟中实现静态的 React 组件

+   使用 Hooks 实现有状态的组件

# 技术要求

应该已经安装了相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter03`](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter03)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行先前提供的代码示例。重要的是您自己编写代码，以便能够正确学习和理解。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始本章。

# 构建 React 项目

在学习了 React 的原则、如何使用`useState` Hook 以及 Hooks 的内部工作原理后，我们现在将利用真正的`useState` Hook 来开发一个博客应用程序。首先，我们将创建一个新项目，并以一种可以在以后扩展项目的方式来构建文件夹结构。然后，我们将定义我们需要的组件，以涵盖博客应用程序的基本功能。最后，我们将使用 Hooks 为我们的应用程序引入状态！在本章中，我们还将学习**JSX**，以及在**ES6**到**ES2018**中引入的新 JavaScript 功能。

# 文件夹结构

项目可以有许多不同的结构方式，不同的结构方式适用于不同的项目。通常，我们创建一个`src/`文件夹，并按功能将文件分组在那里。另一种流行的项目结构方式是按路由进行分组。对于一些项目，此外还可能根据代码的类型进行分离，比如`src/api/`和`src/components/`。然而，对于我们的项目，我们主要关注**用户界面**（**UI**）。因此，我们将按功能在`src/`文件夹中将文件分组。

最好一开始从一个简单的结构开始，只有在实际需要时才进行更深的嵌套。在开始项目时不要花太多时间考虑文件结构，因为通常情况下，你不知道文件应该如何分组。

# 选择功能

我们首先必须考虑在我们的博客应用程序中要实现哪些功能。至少，我们希望实现以下功能：

+   注册用户

+   登录/登出

+   查看单个帖子

+   创建新帖子

+   列出帖子

既然我们已经选择了功能，让我们提出一个初始的文件夹结构。

# 提出一个初始结构

从我们之前的功能中，我们可以抽象出一些功能组：

+   用户（注册，登录/登出）

+   帖子（创建，查看，列出）

现在我们可以保持非常简单，将所有组件创建在`src/`文件夹中，不进行任何嵌套。然而，由于我们已经对博客应用程序需要的功能有了相当清晰的了解，我们现在可以提出一个简单的文件夹结构：

+   `src/`

+   `src/user/`

+   `src/post/`

在定义文件夹结构之后，我们可以继续进行组件结构。

# 组件结构

在 React 中，组件的理念是让每个组件处理单个任务或 UI 元素。我们应该尽量将组件做得细粒度，以便能够重用代码。如果我们发现自己在从一个组件复制和粘贴代码到另一个组件，那么创建一个新组件并在多个其他组件中重用它可能是个好主意。

通常，在开发软件时，我们会从 UI 模拟开始。对于我们的博客应用程序，模拟将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/3ead741d-7e4f-402b-9dca-710eb2d8ced0.png)

我们博客应用程序的初始模拟

在拆分组件时，我们使用单一职责原则，该原则规定每个模块应对功能的一个封装部分负责。

在这个模拟中，我们可以在每个组件和子组件周围画框，并给它们命名。请记住，每个组件应该只负责一个功能。我们从构成这个应用程序的基本组件开始：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/76bb8249-2b7f-4058-86dc-166e76f0844b.png)

从我们的模拟中定义基本组件

我们为注销功能定义了一个`Logout`组件，一个包含创建新帖子表单的`CreatePost`组件，以及一个用于显示实际帖子的`Post`组件。

现在我们已经定义了我们的基本组件，我们将看看哪些组件在逻辑上属于一起，从而形成一个组。为此，我们现在定义容器组件，这样我们就可以将组件组合在一起：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/dea42556-65fd-4997-b85f-f2a6ba394f71.png)

从我们的模拟中定义容器组件

我们定义了一个`PostList`组件来将帖子分组，然后定义了一个`UserBar`组件来处理登录/注销和注册。最后，我们定义了一个`App`组件来将所有内容组合在一起，并定义我们应用程序的结构。

现在我们已经完成了对我们的 React 项目进行结构化，我们可以继续实现静态组件。

# 实现静态组件

在我们开始通过 Hooks 向我们的博客应用程序添加状态之前，我们将模拟应用程序的基本功能作为静态 React 组件。这样做意味着我们必须处理应用程序的静态视图结构。

首先处理静态结构是有意义的，这样可以避免以后将动态代码移动到不同的组件中。此外，首先只处理**超文本标记语言（HTML）**和 CSS 更容易——这有助于我们快速启动项目。然后，我们可以继续实现动态代码和处理状态。

逐步进行这一步，而不是一次实现所有内容，有助于我们快速启动新项目，而不必一次考虑太多，并且让我们避免以后重新构建项目！

# 设置项目

我们已经学会了如何设置一个新的 React 项目。正如我们所学到的，我们可以使用`create-react-app`工具轻松初始化一个新项目。我们现在要这样做：

1.  首先，我们使用`create-react-app`来初始化我们的项目：

```jsx
>npx create-react-app chapter3_1
```

1.  然后，我们为我们的功能创建文件夹：

+   +   **创建文件夹**：`src/user/`

+   **创建文件夹**：`src/post/`

现在我们的项目结构已经设置好，我们可以开始实施组件。

# 实施用户

我们将从静态组件方面最简单的功能开始：实施与用户相关的功能。正如我们从模拟中看到的，我们在这里需要四个组件：

+   一个`Login`组件，当用户尚未登录时我们将展示它

+   一个`Register`组件，当用户尚未登录时我们也会展示它

+   一个`Logout`组件，当用户登录后将显示

+   一个`UserBar`组件，它将有条件地显示其他组件

我们将首先定义前三个组件，它们都是独立的组件。最后，我们将定义`UserBar`组件，因为它依赖于其他组件的定义。

# 登录组件

首先，我们定义`Login`组件，其中我们展示两个字段：用户名字段和密码字段。此外，我们展示一个登录按钮：

1.  我们首先为我们的组件创建一个新文件：`src/user/Login.js`

1.  在新创建的`src/user/Login.js`文件中，我们导入`React`：

```jsx
import  React  from  'react'
```

1.  然后，我们定义我们的函数组件。目前，`Login`组件不会接受任何 props：

```jsx
export  default  function  Login  ()  { 
```

1.  最后，我们通过 JSX 返回两个字段和登录按钮。我们还定义了一个`form`容器元素来包裹它们。为了在提交表单时避免页面刷新，我们必须定义一个`onSubmit`处理程序并在事件对象上调用`e.preventDefault()`：

```jsx
    return (
        <form onSubmit={e => e.preventDefault()}>
            <label htmlFor="login-username">Username:</label>
            <input type="text" name="login-username" id="login-username" />
            <label htmlFor="login-password">Password:</label>
            <input type="password" name="login-password" id="login-password" />
            <input type="submit" value="Login" />
        </form>
    )
}
```

在这里，我们使用匿名函数来定义`onSubmit`处理程序。匿名函数的定义如下，如果它们没有任何参数：`() => { ... }`，而不是`function () { ... }`。有了参数，我们可以写成`(arg1, arg2) => { ... }`，而不是`function (arg1, arg2) { ... }`。如果我们只有一个参数，我们可以省略`()`括号。此外，如果我们的函数中只有一个语句，我们可以省略`{}`括号，就像这样：`e => e.preventDefault()`。

使用语义化的 HTML 元素，如`<form>`和`<label>`，可以使您的应用程序更易于使用辅助功能软件的人导航，例如屏幕阅读器。此外，当使用语义化的 HTML 时，键盘快捷键，例如按回车键提交表单，会自动生效。

我们的`Login`组件已经实现，现在可以进行测试了。

# 测试我们的组件

既然我们已经定义了我们的第一个组件，让我们渲染它并看看它的样子：

1.  首先，我们编辑`src/App.js`，并删除所有内容。

1.  然后，我们首先导入`React`和`Login`组件：

```jsx
import React from 'react'

import Login from './user/Login'
```

将导入分组成属于一起的代码块是一个好主意。在这种情况下，我们通过在外部导入（如 React）和本地导入（如我们的`Login`组件）之间添加空行来分隔它们。这样做可以保持我们的代码可读性，特别是当我们以后添加更多导入语句时。

1.  最后，我们定义`App`组件，并返回`Login`组件：

```jsx
export default function App () {
    return <Login />
}
```

如果我们只返回一个组件，可以在`return`语句中省略括号。而不是写`return (<Login />)`，我们可以简单地写`return <Login />`。

1.  在浏览器中打开`http://localhost:3000`，您应该看到`Login`组件被渲染。如果您已经在浏览器中打开了页面，当您更改代码时，它应该会自动刷新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/98b35abf-b0b4-4890-823f-2fbb0affbb34.png)

我们博客应用的第一个组件：通过用户名和密码登录

正如我们所看到的，静态的`Login`组件在 React 中渲染得很好。现在我们可以继续进行`Logout`组件。

# 登出组件

接下来，我们定义`Logout`组件，它将显示当前登录的用户和一个登出按钮：

1.  创建一个新文件：`src/user/Logout.js`

1.  导入`React`，如下所示：

```jsx
import React from 'react'
```

1.  这次，我们的函数将接受一个`user`属性，我们将使用它来显示当前登录的用户：

```jsx
export default function Logout ({ user }) {
```

在这里，我们使用解构来从`props`对象中提取`user`键。React 将所有组件 props 作为单个对象作为函数的第一个参数传递。在第一个参数上使用解构类似于在类组件中执行`const { user } = this.props`。

1.  最后，我们返回一个文本，显示当前登录的`user`和登出按钮：

```jsx
    return (
        <form onSubmit={e => e.preventDefault()}>
            Logged in as: <b>{user}</b>
            <input type="submit" value="Logout" />
        </form>
    )
}
```

1.  现在，我们可以在`src/App.js`中用`Logout`组件替换`Login`组件，以便看到我们新定义的组件（不要忘记将`user`属性传递给它！）：

```jsx
import React from 'react'

import Logout from './user/Logout'

export default function App () {
    return <Logout user="Daniel Bugl" />
}
```

现在`Logout`组件已经定义，我们可以继续定义`Register`组件。

# 注册组件

静态的`Register`组件将与`Login`组件非常相似，只是多了一个重复密码的字段。如果它们如此相似，您可能会想将它们合并为一个组件，并添加一个 prop 来切换重复密码字段。然而，最好遵循单一职责原则，让每个组件只处理一个功能。稍后，我们将使用动态代码扩展静态组件，然后`Register`和`Login`的代码将大不相同。因此，我们稍后需要再次拆分它们。

尽管如此，让我们开始编写`Register`组件的代码：

1.  首先，我们创建一个新的`src/user/Register.js`文件，并从`Login`组件中复制代码，因为静态组件毕竟非常相似。确保将组件的名称更改为`Register`：

```jsx
import React from 'react'

export default function Register () {
    return (
        <form onSubmit={e => e.preventDefault()}>
            <label htmlFor="register-username">Username:</label>
            <input type="text" name="register-username" id="register-username" />
            <label htmlFor="register-password">Password:</label>
            <input type="password" name="register-password" id="register-password" />
```

1.  接下来，我们在 Password 字段代码下方添加重复密码字段：

```jsx
            <label htmlFor="register-password-repeat">Repeat password:</label>
            <input type="password" name="register-password-repeat" id="register-password-repeat" />
```

1.  最后，我们还将提交按钮的值更改为 Register：

```jsx
            <input type="submit" value="Register" />
        </form>
    )
}
```

1.  同样，我们可以编辑`src/App.js`以类似的方式显示我们的组件，就像我们在`Login`组件中所做的那样：

```jsx
import React from 'react'

import Register from './user/Register'

export default function App () {
    return <Register />
}
```

正如我们所看到的，我们的`Register`组件看起来与`Login`组件非常相似。

# UserBar 组件

现在是时候将我们与用户相关的组件放在一个`UserBar`组件中了。在这里，我们将有条件地显示`Login`和`Register`组件，或者`Logout`组件，这取决于用户是否已经登录。

让我们开始实现`UserBar`组件：

1.  首先，我们创建一个新的`src/user/UserBar.js`文件，并导入`React`以及我们定义的三个组件：

```jsx
import React from 'react'

import Login from './Login'
import Logout from './Logout'
import Register from './Register'
```

1.  接下来，我们定义我们的函数组件，并为`user`定义一个值。现在，我们只是将它保存在一个静态变量中：

```jsx
export default function UserBar () {
    const user = ''
```

1.  然后，我们检查用户是否已登录。如果用户已登录，我们显示`Logout`组件，并将`user`值传递给它：

```jsx
    if (user) {
        return <Logout user={user} />
```

1.  否则，我们展示`Login`和`Register`组件。在这里，我们可以使用`React.Fragment`而不是`<div>`容器元素。这样可以保持我们的 UI 树干净，因为组件将简单地并排渲染，而不是包裹在另一个元素中：

```jsx
    } else {
        return (
            <React.Fragment>
                <Login />
                <Register />
            </React.Fragment>
        )
    }
}
```

1.  再次编辑`src/App.js`，现在我们展示我们的`UserBar`组件：

```jsx
import React from 'react'

import UserBar from './user/UserBar'

export default function App () {
    return <UserBar />
}
```

1.  我们可以看到，它起作用了！我们现在展示`Login`和`Register`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/8de0c0af-3059-426e-9428-5be16c081648.png)

我们的 UserBar 组件，展示了 Login 和 Register 组件

1.  接下来，我们可以编辑`src/user/UserBar.js`文件，并将`user`值设置为一个字符串：

```jsx
        const user = 'Daniel Bugl' 
```

1.  这样做之后，我们的应用程序现在显示`Logout`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/810249b7-c3e0-428f-a41e-72ef8e97006f.png)

我们的应用程序在定义`user`值后显示了 Logout 组件

在本章的后面，我们将向我们的应用程序添加 Hooks，这样我们就可以登录并使状态动态更改，而无需编辑代码！

# 示例代码

与用户相关的组件的示例代码可以在`Chapter03/chapter3_1`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 实现帖子

在实现了所有与用户相关的组件之后，我们继续在博客应用中实现帖子。我们将定义以下组件：

+   一个`Post`组件用于显示单个帖子

+   一个`CreatePost`组件用于创建新的帖子

+   一个`PostList`组件用于显示多个帖子

现在让我们开始实现与帖子相关的组件。

# Post 组件

在创建模型时，我们已经考虑了帖子具有哪些元素。帖子应该有一个标题，内容和作者（撰写帖子的用户）。

现在让我们实现`Post`组件：

1.  首先，我们创建一个新文件：`src/post/Post.js`

1.  然后，我们导入`React`，并定义我们的函数组件，接受三个属性：`title`，`content`和`author`：

```jsx
import React from 'react'

export default function Post ({ title, content, author }) {
```

1.  接下来，我们以类似模型的方式呈现所有属性：

```jsx
    return (
        <div>
            <h3>{title}</h3>
            <div>{content}</div>
            <br />
            <i>Written by <b>{author}</b></i>
        </div>
    )
}
```

1.  像往常一样，我们可以通过编辑`src/App.js`文件来测试我们的组件：

```jsx
import React from 'react'

import Post from './post/Post'

export default function App () {
    return <Post title="React Hooks" content="The greatest thing since sliced bread!" author="Daniel Bugl" />
}
```

现在，静态的`Post`组件已经实现，我们可以继续进行`CreatePost`组件。

# CreatePost 组件

接下来，我们实现一个表单来允许创建新的帖子。在这里，我们将`user`值作为属性传递给组件，因为作者应该始终是当前登录的用户。然后，我们显示作者，并为博客帖子的`title`提供一个输入字段，以及一个`<textarea>`元素用于内容。

现在让我们实现`CreatePost`组件：

1.  创建一个新文件：`src/post/CreatePost.js`

1.  定义以下组件：

```jsx
import React from 'react'

export default function CreatePost ({ user }) {
    return (
        <form onSubmit={e => e.preventDefault()}>
            <div>Author: <b>{user}</b></div>
            <div>
                <label htmlFor="create-title">Title:</label>
                <input type="text" name="create-title" id="create-title" />
            </div>
            <textarea />
            <input type="submit" value="Create" />
        </form>
    )
}
```

1.  像往常一样，我们可以通过编辑`src/App.js`文件来测试我们的组件：

```jsx
import React from 'react'

import CreatePost from './post/CreatePost'

export default function App () {
    return <CreatePost />
}
```

正如我们所看到的，`CreatePost`组件渲染正常。我们现在可以继续进行`PostList`组件。

# PostList 组件

在实现其他与文章相关的组件之后，我们现在可以实现博客应用程序最重要的部分：博客文章的动态更新。目前，动态更新只是简单地显示博客文章列表。

让我们现在开始实现`PostList`组件：

1.  我们首先导入`React`和`Post`组件：

```jsx
import React from 'react'

import Post from './Post'
```

1.  然后，我们定义我们的`PostList`函数组件，接受一个`posts`数组作为 prop。如果`posts`未定义，我们将其默认设置为空数组：

```jsx
export default function PostList ({ posts = [] }) {
```

1.  接下来，我们使用`.map`函数和扩展语法来渲染所有`posts`：

```jsx
    return (
        <div>
            {posts.map((p, i) => <Post {...p} key={'post-' + i} />)}
        </div>
    )
}
```

如果我们要渲染一个元素列表，我们必须给每个元素一个唯一的`key` prop。当数据发生变化时，React 使用这个`key` prop 来高效地计算两个列表的差异。

在这里，我们使用`map`函数，它将一个函数应用于数组的所有元素。这类似于使用`for`循环并存储所有结果，但它更加简洁、声明性，并且更容易阅读！或者，我们可以使用`map`函数的替代方法：

```jsx
let renderedPosts = []
let i = 0
for (let p of posts) {
    renderedPosts.push(<Post {...p} key={'post-' + i} />)
    i++
}

return (
    <div>
        {renderedPosts}
    </div>
)
```

然后我们为每篇文章返回`<Post>`组件，并将文章对象`p`的所有键作为 props 传递给组件。我们使用扩展语法来实现这一点，它的效果与手动列出对象中所有键作为 props 相同，如下所示：`<Post title={p.title} content={p.content} author={p.author} />`

1.  在模型中，每篇博客文章之后都有一条水平线。我们可以通过使用`React.Fragment`来实现这一点，而无需额外的`<div>`容器元素：

```jsx
{posts.map((p, i) => (
     <React.Fragment key={'post-' + i} >
          <Post {...p} />
          <hr />
     </React.Fragment>
))}
```

`key` prop 始终必须添加到在`map`函数中渲染的最上层父元素。在这种情况下，我们不得不将`key` prop 从`Post`组件移动到`React.Fragment`组件中。

1.  我们通过编辑`src/App.js`文件来测试我们的组件：

```jsx
import React from 'react'

import PostList from './post/PostList'

const posts = [
 { title: 'React Hooks', content: 'The greatest thing since sliced bread!', author: 'Daniel Bugl' },
 { title: 'Using React Fragments', content: 'Keeping the DOM tree clean!', author: 'Daniel Bugl' }
]

export default function App () {
    return <PostList posts={posts} />
}
```

现在，我们可以看到我们的应用程序列出了我们在`posts`数组中定义的所有文章：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/e96b9030-8422-4caa-9f22-df847b8557e7.png)

使用 PostList 组件显示多篇文章

正如我们所看到的，通过`PostList`组件列出多篇文章是可以的。现在我们可以继续组合应用程序。

# 组合应用程序

在实现所有组件之后，为了复制模型，我们现在只需要将所有内容放在`App`组件中。然后，我们将成功复制模型！

让我们开始修改`App`组件，并组合我们的应用程序：

1.  编辑`src/App.js`，并删除所有当前代码。

1.  首先，我们导入`React`、`PostList`、`CreatePost`和`UserBar`组件：

```jsx
import React from 'react'

import PostList from './post/PostList'
import CreatePost from './post/CreatePost'
import UserBar from './user/UserBar'
```

1.  然后，我们为我们的应用程序定义一些模拟数据：

```jsx
const user = 'Daniel Bugl'
const posts = [
    { title: 'React Hooks', content: 'The greatest thing since sliced bread!', author: 'Daniel Bugl' },
    { title: 'Using React Fragments', content: 'Keeping the DOM tree clean!', author: 'Daniel Bugl' }
]
```

1.  接下来，我们定义`App`组件，并返回一个`<div>`容器元素，在这里我们设置一些填充：

```jsx
export default function App () {
    return (
        <div style={{ padding: 8 }}>
```

1.  现在，我们插入`UserBar`和`CreatePost`组件，将`user`属性传递给`CreatePost`组件：

```jsx
            <UserBar />
            <br />
            <CreatePost user={user} />
            <br />
            <hr />
```

请注意，您应该始终优先使用 CSS 进行间距设置，而不是使用`<br />`HTML 标记。但是，目前我们专注于 UI，而不是其样式，因此我们尽可能使用 HTML。

1.  最后，我们显示`PostList`组件，列出所有的`posts`：

```jsx
            <PostList posts={posts} />
        </div>
    )
}
```

1.  保存文件后，`http://localhost:3000`应该会自动刷新，现在我们可以看到完整的 UI 了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/84ac3159-6797-4900-8367-b09b754b990f.png)

根据模拟的静态博客应用程序的完整实现

正如我们所看到的，我们之前定义的所有静态组件都在一个`App`组件中一起呈现。我们的应用程序现在看起来就像模拟一样。接下来，我们可以继续使所有组件都变得动态。

# 示例代码

我们博客应用程序静态实现的示例代码可以在`Chapter03/chapter3_2`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 Hooks 实现有状态的组件

现在我们已经实现了应用程序的静态结构，我们将为它添加`useState` Hooks，以便能够处理状态和动态交互！

# 为用户功能添加 Hooks

为了为用户功能添加 Hooks，我们需要用一个 State Hook 替换静态的`user`值。然后，我们需要在登录、注册和注销时调整这个值。

# 调整 UserBar

回想一下，当我们创建`UserBar`组件时，我们静态定义了`user`值。现在我们将用一个 State Hook 替换这个值！

让我们开始修改`UserBar`组件，使其变得动态：

1.  编辑`src/user/UserBar.js`，通过调整`React`导入语句导入`useState` Hook，如下所示：

```jsx
import React, { useState } from 'react'
```

1.  删除以下代码行：

```jsx
    const user = 'Daniel Bugl'
```

用一个空的用户`''`作为默认值替换它：

```jsx
    const [ user, setUser ] = useState('')
```

1.  然后，我们将`setUser`函数传递给`Login`、`Register`和`Logout`组件：

```jsx
    if (user) {
        return <Logout user={user} setUser={setUser} />
    } else {
        return (
            <React.Fragment>
                <Login setUser={setUser} />
                <Register setUser={setUser} />
            </React.Fragment>
        )
    }
```

现在，`UserBar`组件提供了一个`setUser`函数，可以在`Login`、`Register`和`Logout`组件中使用，以设置或取消`user`的值。

# 调整登录和注册组件

在`Login`和`Register`组件中，我们需要使用`setUser`函数来相应地设置`user`的值，当我们登录或注册时。

# 登录

在`Login`组件中，我们现在暂时忽略密码字段，只处理用户名字段。

让我们首先修改`Login`组件以使其动态化：

1.  编辑`src/user/Login.js`，并导入`useState` Hook：

```jsx
import React, { useState } from 'react'
```

1.  然后，调整函数定义以接受`setUser`属性：

```jsx
export default function Login ({ setUser }) {
```

1.  现在，我们为用户名字段的值定义一个新的 State Hook：

```jsx
    const [ username, setUsername ] = useState('')
```

1.  接下来，我们定义一个处理程序函数：

```jsx
    function handleUsername (evt) {
        setUsername(evt.target.value)
    }
```

1.  然后，我们调整`input`字段，以使用`username`的值，并在输入更改时调用`handleUsername`函数：

```jsx
            <input type="text" value={username} onChange={handleUsername} name="login-username" id="login-username" />
```

1.  最后，当按下登录按钮并且表单被提交时，我们需要调用`setUser`函数：

```jsx
            <form onSubmit={e => { e.preventDefault(); setUser(username) }} />
```

1.  此外，当`username`值为空时，我们可以禁用登录按钮：

```jsx
            <input type="submit" value="Login" disabled={username.length === 0} />
```

它起作用了——我们现在可以输入用户名，按下登录按钮，然后我们的`UserBar`组件将改变其状态，并显示`Logout`组件！

# 注册

对于注册，我们还将检查输入的密码是否相同，只有在这种情况下我们才会设置`user`的值。

让我们首先修改`Register`组件以使其动态化：

1.  首先，我们执行与“登录”相同的步骤，以处理“用户名”字段：

```jsx
import React, { useState } from 'react'

export default function Register ({ setUser }) {
 const [ username, setUsername ] = useState('')

 function handleUsername (evt) {
 setUsername(evt.target.value)
 }

    return (
        <form onSubmit={e => { e.preventDefault(); setUser(username) }}>
            <label htmlFor="register-username">Username:</label>
            <input type="text" value={username} onChange={handleUsername} name="register-username" id="register-username" />
            <label htmlFor="register-password">Password:</label>
            <input type="password" name="register-password" id="register-password" />
            <label htmlFor="register-password-repeat">Repeat password:</label>
            <input type="password" name="register-password-repeat" id="register-password-repeat" />
            <input type="submit" value="Register" disabled={username.length === 0} />
        </form>
    )
}
```

1.  现在，我们为`密码`和`重复密码`字段定义了两个新的 State Hooks：

```jsx
    const [ password, setPassword ] = useState('')
    const [ passwordRepeat, setPasswordRepeat ] = useState('')
```

1.  然后，我们为它们定义两个处理程序函数：

```jsx
    function handlePassword (evt) {
        setPassword(evt.target.value)
    }

    function handlePasswordRepeat (evt) {
        setPasswordRepeat(evt.target.value)
    }
```

您可能已经注意到，我们总是为`input`字段编写类似的处理程序函数。实际上，这是创建自定义 Hook 的完美用例！我们将在未来的章节中学习如何做到这一点。

1.  接下来，我们将`value`和`onChange`处理程序函数分配给`input`字段：

```jsx
             <label htmlFor="register-password">Password:</label>
             <input type="password" value={password} onChange={handlePassword} name="register-password" id="register-password" />
             <label htmlFor="register-password-repeat">Repeat password:</label>
             <input type="password" value={passwordRepeat} onChange={handlePasswordRepeat} name="register-password-repeat" id="register-password-repeat" />
```

1.  最后，我们检查密码是否匹配，如果不匹配，我们保持按钮处于禁用状态：

```jsx
             <input type="submit" value="Register" disabled={username.length === 0 || password.length === 0 || password !== passwordRepeat} />
```

现在我们成功地实现了检查密码是否相等，并且我们实现了注册！

# 调整登出

对于用户功能，还有一件事情还缺少——我们还不能注销。

现在让我们使`Logout`组件动态化：

1.  编辑`src/user/Logout.js`，并添加`setUser`属性：

```jsx
export default function Logout ({ user, setUser }) {
```

1.  然后，调整`form`的`onSubmit`处理程序并将用户设置为`''`：

```jsx
            <form onSubmit={e => { e.preventDefault(); setUser('') }} />
```

由于我们在这里不创建新的 Hook，所以不需要从 React 中导入`useState` Hook。我们可以简单地使用传递给`Logout`组件的`setUser`函数作为 prop。

现在，当我们点击注销按钮时，`Logout`组件将`user`值设置为`''`。

# 将用户传递给 CreatePost

你可能已经注意到，`CreatePost`组件仍然使用硬编码的用户名。为了能够在那里访问`user`值，我们需要将 Hook 从`UserBar`组件移动到`App`组件。

现在让我们重构`user` State Hook 的定义：

1.  编辑`src/user/UserBar.js`，并删除那里的 Hook 定义：

```jsx
    const [ user, setUser ] = useState('')
```

1.  然后，我们编辑函数定义，并接受这两个值作为 props：

```jsx
export default function UserBar ({ user, setUser }) {
```

1.  现在，我们编辑`src/App.js`，并在那里导入`useState` Hook：

```jsx
import React, { useState } from 'react'
```

1.  接下来，我们删除静态的`user`值定义：

```jsx
    const user = 'Daniel Bugl'
```

1.  然后，我们将之前剪切的`user` State Hook 插入`App`组件函数中：

```jsx
    const [ user, setUser ] = useState('')
```

1.  现在，我们可以将`user`和`setUser`作为 props 传递给`UserBar`组件：

```jsx
            <UserBar user={user} setUser={setUser} />
```

`user`状态是全局状态，因此我们需要在应用程序中的许多组件中使用它。目前，这意味着我们需要将`user`值和`setUser`函数传递给每个需要它的组件。在未来的章节中，我们将学习关于 React Context Hooks，它解决了必须以这种方式传递 props 的问题。

1.  最后，只有在用户登录时才显示`CreatePost`组件。为了做到这一点，我们使用一种模式，它允许我们根据条件显示组件：

```jsx
 {user && <CreatePost user={user} />}
```

现在，用户功能已经完全实现了——我们可以使用`Login`和`Register`组件，并且`user`值也传递给了`CreatePost`组件！

# 为帖子功能添加 Hooks

实现用户功能后，我们现在要实现动态创建帖子。我们首先调整`App`组件，然后修改`CreatePost`组件，以便能够插入新帖子。

让我们开始调整 App 组件。

# 调整 App 组件

正如我们从用户功能中所知道的，帖子也将是全局状态，因此我们应该在`App`组件中定义它。

现在让我们将`posts`值作为全局状态实现：

1.  编辑`src/App.js`，并将当前的`posts`数组重命名为`defaultPosts`：

```jsx
const defaultPosts = [
    { title: 'React Hooks', content: 'The greatest thing since sliced bread!', author: 'Daniel Bugl' },
    { title: 'Using React Fragments', content: 'Keeping the DOM tree clean!', author: 'Daniel Bugl' }
]
```

1.  然后，为`posts`状态定义一个新的 State Hook：

```jsx
    const [ posts, setPosts ] = useState(defaultPosts)
```

1.  现在，我们将`posts`值和`setPosts`函数作为 props 传递给`CreatePost`组件：

```jsx
            {user && <CreatePost user={user} posts={posts} setPosts={setPosts} />}
```

现在，我们的`App`组件为`CreatePost`组件提供了`posts`数组和`setPosts`函数。让我们继续调整 CreatePost 组件。

# 调整 CreatePost 组件

接下来，我们需要使用`setPosts`函数来在按下 Create 按钮时插入一个新的帖子。

让我们开始修改`CreatePost`组件，以使其动态化：

1.  编辑`src/posts/CreatePost.js`，并导入`useState` Hook：

```jsx
import React, { useState } from 'react'
```

1.  然后，调整函数定义以接受`posts`和`setPosts`属性：

```jsx
export default function CreatePost ({ user, posts, setPosts }) {
```

1.  接下来，我们定义两个新的 State Hooks——一个用于`title`值，一个用于`content`值：

```jsx
    const [ title, setTitle ] = useState('')
    const [ content, setContent ] = useState('')
```

1.  现在，我们定义了两个处理函数——一个用于`input`字段，一个用于`textarea`：

```jsx
    function handleTitle (evt) {
        setTitle(evt.target.value)
    }

    function handleContent (evt) {
        setContent(evt.target.value)
    }
```

1.  我们还为 Create 按钮定义了一个处理函数：

```jsx
    function handleCreate () {
```

1.  在这个函数中，我们首先从`input`字段的值创建一个`newPost`对象：

```jsx
        const newPost = { title, content, author: user }
```

在较新的 JavaScript 版本中，我们可以将以下对象赋值缩短为`{ title: title }`，变为`{ title }`，并且会产生相同的效果。因此，我们可以简单地使用`{ title, contents }`来代替`{ title: title, contents: contents }`。

1.  然后，我们通过首先将`newPost`添加到数组中，然后使用扩展语法列出所有现有的`posts`来设置新的`posts`数组：

```jsx
        setPosts([ newPost, ...posts ])
    }
```

1.  接下来，我们将`value`和处理函数添加到`input`字段和`textarea`元素中：

```jsx
             <div>
                 <label htmlFor="create-title">Title:</label>
                 <input type="text" value={title} onChange={handleTitle} name="create-title" 
                        id="create-title" />
             </div>
             <textarea value={content} onChange={handleContent} />
```

通常在 HTML 中，我们将`textarea`的值放在其子元素中。然而，在 React 中，`textarea`可以像任何其他`input`字段一样处理，通过使用`value`和`onChange`属性。

1.  最后，我们将`handleCreate`函数传递给`form`元素的`onSubmit`处理程序：

```jsx
         <form onSubmit={e => { e.preventDefault(); handleCreate() }}>
```

1.  现在，我们可以登录并创建一个新的帖子，它将被插入到动态源的开头：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/e09c94b6-d289-4cb9-98c5-38f8dec399c6.png)

使用 Hooks 插入新博客帖子后的博客应用程序的第一个版本

正如我们所看到的，现在我们的应用程序是完全动态的，我们可以使用它的所有功能！

# 示例代码

使用 Hooks 实现我们的博客应用程序的动态示例代码可以在`Chapter03/chapter3_3`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 总结

在本章中，我们从头开始开发了自己的博客应用程序！我们从一个模型开始，然后创建了静态组件来模拟它。之后，我们实现了 Hooks，以实现动态行为。在整个章节中，我们学会了如何使用 Hooks 处理本地和全局状态。此外，我们学会了如何使用多个 Hooks，以及在哪些组件中定义 Hooks 和存储状态。我们还学会了如何解决常见用例，比如使用 Hooks 处理输入字段。

在下一章中，我们将学习`useReducer` Hook，它使我们能够更轻松地处理特定状态变化。此外，我们将学习`useEffect` Hook，它使我们能够运行具有副作用的代码。

# 问题

为了总结我们在本章学到的内容，试着回答以下问题：

1.  在 React 中，文件夹结构的最佳实践是什么？

1.  在拆分 React 组件时应该使用哪个原则？

1.  `map`函数是做什么的？

1.  解构是如何工作的，我们什么时候使用它？

1.  展开运算符是如何工作的，我们什么时候使用它？

1.  我们如何使用 React Hooks 处理输入字段？

1.  本地状态 Hook 应该在哪里定义？

1.  什么是全局状态？

1.  全局状态 Hook 应该在哪里定义？

# 进一步阅读

如果您对本章学到的概念更感兴趣，可以查看以下阅读材料：

+   *React 思维*的官方文档：[`reactjs.org/docs/thinking-in-react.html`](https://reactjs.org/docs/thinking-in-react.html)

+   使用 React 处理输入字段：[`reactjs.org/docs/forms.html`](https://reactjs.org/docs/forms.html)
