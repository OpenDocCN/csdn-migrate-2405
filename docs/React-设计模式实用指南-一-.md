# React 设计模式实用指南（一）

> 原文：[`zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940`](https://zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

框架和库来来去去。设计模式通常会持续更长时间。在这本书中，我们将学习 React Native 和与该生态系统相关的设计模式。当涉及到 React 时，关于设计模式的基本知识散布在各个地方。有时它被埋在专有的代码库中。这本书将把它带给你。我称它们为**思想模式：**通过真实的工作示例来解释的实用设计模式。在这本书中，我们使用 React Native，但你也可以成功地在 React 的 Web 开发中使用大多数这些模式，甚至是其他框架，比如 Angular 或 Vue。希望你能利用这些知识来构建深思熟虑且易于维护的代码库。祝你好运！

# 这本书适合谁

业余程序员和热情的人非常欢迎阅读这本书，但请注意，这可能比初级编程书籍更具挑战性。

我假设你有一些 JavaScript 编程经验，并且对终端窗口并不陌生。理想情况下，你应该是一名开发人员（初级/中级/高级），这样你就会有广阔的视野，并且可以立即将知识应用到你的工作中。不需要有开发移动应用程序的经验。

# 为了充分利用这本书，

花点时间，不要着急。你不需要在一周内读完这本书。

随着你的开发者职业的进步，回到这本书。你将专注于完全不同的事情，这样你将能够充分利用这本书。

玩一下我准备的例子。每个都是一个独立的应用程序，所以你可以在我们进行的过程中玩耍和改进代码。这旨在作为一个游乐场，这样你不仅可以从例子中学习，还可以创建它们的扩展。当你构建时，你将理解在每个部分引入的变化。如果你只是读这本书，你肯定会错过这个视角。

# 下载示例代码文件

你可以从[www.packt.com](http://www.packt.com)的账户中下载这本书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接发送到你的邮箱。

你可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/Ajdija/hands-on-design-patterns-with-react-native`](https://github.com/Ajdija/hands-on-design-patterns-with-react-native)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781788994460_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```jsx
export default function() {
    return React.createElement(
        Text,
  {style: {marginTop: 30}},
  'Example Text!'
  ); }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
export default **function** App() {
  return (
      <View style={styles.container}>
  ...
      </View>
  ); }
```

任何命令行输入或输出都将按以下方式编写：

```jsx
yarn test -- --coverage
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："您现在可以点击 详细 按钮导航到 任务详情 屏幕。"

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：React 组件模式

开发 Android 和 iOS 从未像现在这样简单。React Native 改变了我们开发新应用并向最终用户提供价值的速度。了解这项技术将使你在市场上拥有巨大优势。我是 Matt，很高兴向你展示我在 React Native 生态系统中学到的最佳实践。通过本书，我们将通过示例探索设计模式。仅在本章中，我们将创建超过 10 个小应用程序。在本书的后面，我们将使用我逐渐向你介绍的模式创建更复杂的应用程序。

在本章中，我们将探讨同样适用于 React Native 世界的 React 模式。你需要理解的最关键的模式是无状态和有状态组件。了解如何使用这些模式将使你成为一个更好的 React Native 开发者，并赋予你在每个 React Native 应用程序中使用的标准模式。

在组件方面，使它们尽可能可重用并遵循众所周知的程序员原则——**不要重复自己**（**DRY**）是至关重要的。展示性组件和容器组件就是为了做到这一点。我们将通过几个示例来深入了解它们，学习如何将功能分割成可重用的部分。

更准确地说，在本章中，我们将研究以下主题：

+   无状态和有状态组件，使用简短然后更复杂的示例

+   如何创建可重用且易于配置的展示性组件

+   容器组件及其在功能封装中的作用

+   何时组合组件以及如何创建**高阶组件**（**HOCs**）

是时候采取行动了。**如果你想跟着学习并尝试示例，请立即为 React Native 开发准备好你的环境**。本书中的大部分代码示例都可以在模拟器或真实移动设备上运行和显示。现在，确保你可以在手机或模拟器上启动`Hello World`示例。

代码示例已经提交到 GitHub 上的 Git 存储库中，可以在[`github.com/Ajdija/hands-on-design-patterns-with-react-native`](https://github.com/Ajdija/hands-on-design-patterns-with-react-native)找到。

请按照`readme.md`中的说明设置您的计算机并启动我们的第一个示例。`Hello World`示例可以在以下目录中找到`src/Chapter_1_React_component_patterns/Example_1_Hello_World`。

# 无状态和有状态组件

首先，让我们看看为我们创建的第一个无状态组件。它是由**Create React Native App**（**CRNA**）自动生成的，用于我们的`Hello World`应用程序。这个组件是使用 ECMAScript 2015（ES6）中引入的类语法自动生成的。这样的组件通常被称为**类组件**：

```jsx
// src/ Chapter 1/ Example 1_Hello World/ App.js

**export default class** App extends React.Component {
 render() {
 return (
        <View style={styles.container}>
 <Text>Hands-On Design Patterns with React Native</Text>
 <Text>Chapter 1: React Component Patterns</Text>
 <Text style={styles.text}>You are ready to start the journey. 
          Fun fact is, this text is rendered by class component called 
          App. Check App.js if you want to look it up.</Text>
 </View>  );
  }
}
```

类组件可用于创建有状态组件。

本书提供的代码示例使用具有 Stage 3 功能*类字段声明*的 ECMAScript 2018 语法。 Babel 是支持这样的代码的转换器，相关插件由 CRNA 工具箱预先配置。如果您决定不使用 CRNA，则可能需要自行配置 Babel。

然而，在这种情况下，类组件是不必要的。我们可以安全地使用无状态组件，因为它更简单。让我们看看如何声明**无状态组件**。最常见的方法是使用 ES6 箭头语法。这样的组件称为**功能组件**。查看以下代码，看看我们重写的组件是什么样子的：

```jsx
const App = () => (
    <View style={styles.container}>  <Text>Hands-On Design Patterns with React Native</Text>  <Text>Chapter 1: React Component Patterns</Text>  <Text style={styles.text}>You are ready to start the journey. Fun 
      fact is, this text is rendered by Functional Component called 
      App. Check App.js if you want to look it up.</Text>  </View>  );
export default App;
```

如果您不喜欢箭头语法，您也可以使用常规的`function`语法：

```jsx
// src/ Chapter 1/ Example_2_Functional_Components/ App.js

export default **function** App() {
  return (
      <View style={styles.container}>
  ...
      </View>
  ); }
```

首先弹出的第一个问题是：为什么它是无状态的？答案很简单：它不包含任何内部状态。这意味着我们没有在其中存储任何私有数据。组件需要渲染自身的一切都来自外部世界，而组件并不关心。

在这个小例子中，我们实际上从未将任何外部数据传递给组件。现在让我们来做这件事。为此，我们将创建另一个名为`HelloText`的组件，它消耗一个属性：要显示的文本。将文本传递给这样一个组件的通常约定是将文本放在开放和关闭标签之间，例如`<HelloText>传递的示例文本</HelloText>`。因此，在我们的功能组件中检索这样的属性，我们将需要使用一个名为`children`的特殊键：

```jsx
// src/ Chapter 1/ Example_3_Functional_Components_with_props/ App.js

const HelloText = ({children, ...otherProps}) => (
    <Text {...otherProps}>{children}**</Text>** ); const App = () => (
    <View style={styles.container}>
 <HelloText>  Hands-On Design Patterns with React Native
        </HelloText>
 <HelloText>Chapter 1: React Component Patterns</HelloText>
 <HelloText style={styles.text}>
  You are ready to start the journey. Fun fact is, this text
            is rendered by Functional Component called HelloText.
            Check App.js if you want to look it up.
        </HelloText>
 </View> ); export default App;
```

使用`children`属性使我们的`HelloText`组件更加强大。属性是一种非常灵活的机制。使用属性，您可以发送任何有效的 JavaScript 类型。在这种情况下，我们只发送了文本，但您也可以发送其他组件。

现在是时候为我们的组件添加一些活力了。我们将使其展开第三个文本块，但只有在按下章节或标题文本后才会展开。为了实现这个功能，我们需要存储一个状态，记住组件是展开还是折叠的。

您需要做的是：

1.  将组件更改为类语法。

1.  利用 React 库的状态对象。我们必须在类构造函数中初始化状态，并默认使文本折叠。

1.  在组件的`render`函数中添加条件渲染。

1.  添加按下处理程序，当我们点击标题或章节文本时将改变状态。

解决方案如下所示：

```jsx
// src/ Chapter 1/ Example_4_Stateful_expandable_component/ App.js export default class App extends React.Component {
    constructor() {
        super();
  this.state = {
            // default state on first render
  expanded: **false**
  }
    }

    expandOrCollapse() {
        // toggle expanded: true becomes false, false becomes true
  this.setState({expanded: !this.state.expanded})**;**
  }

    render = () => (
        <View style={styles.container}>
 <HelloText onPress={() => this.expandOrCollapse()}>
  Hands-On Design Patterns with React Native
            </HelloText>
 <HelloText onPress={() => this.expandOrCollapse()}>
  Chapter 1: React Component Patterns
            </HelloText>
  {
                this.state.expanded &&
                <HelloText style={styles.text}>
  You can expand and collapse this text by clicking
                    the Title or Chapter text. Bonus: Check Chapter 4
                    to learn how to animate expanding andcollapsing.
                </HelloText>
  }
        </View>
  );
}
```

恭喜——我们已经创建了我们的第一个无状态和有状态组件！

注意显示组件的`&&`运算符。如果运算符左侧的布尔值为`true`，那么右侧的组件将被显示。整个表达式需要用大括号括起来。我们将在第三章中探索更多功能，样式模式。

现在是时候创建一些更具挑战性的东西：`任务列表`。请重新开始并准备好您的代码。清理`App.js`，使其只包括`App`类组件：

1.  构造函数应该在其状态中初始化任务列表。在我的示例中，任务列表将是一个字符串数组。

1.  迭代任务以为每个任务创建`Text`组件。这应该发生在`App`组件的`render`函数中。请注意，您可以使用`map`函数简化迭代，而不是使用常规的`for`循环。这应该成为第二天性，因为它已经成为几乎每个 JS 项目的标准。

我的解决方案如下所示：

```jsx
// src/ Chapter 1/ Example 5_Task_list/ App.js export default class App extends React.Component {
  constructor() {
    super();
    // Set the initial state, tasks is an array of strings
  this.state = {
 tasks: ['123', '456']
 }
  }

  render = () => (
      <View style={styles.container}>
  {
          this.state.tasks
  .map((task, index) => (
 <Text key={index} style={styles.text}>{task}</Text>
  ))
        }
      </View>
  );
}
```

使用`map`进行迭代是一个很好的功能，但整个组件看起来还不像一个任务列表。别担心，您将学会如何在第三章中为组件添加样式，*样式模式*。

# 无状态组件的优势是什么？

也许只使用有状态的类组件并开发整个应用程序似乎很诱人。为什么我们要费心使用无状态的函数组件呢？答案是性能。无状态的函数组件可以更快地渲染。这样做的原因之一是因为无状态的函数组件不需要一些生命周期钩子。

什么是生命周期钩子？React 组件有生命周期。这意味着它们有不同的阶段，如挂载、卸载和更新。您可以挂钩每个阶段甚至子阶段。请查看官方 React 文档以查看可用生命周期方法的完整列表：[`reactjs.org/docs/state-and-lifecycle.html`](https://reactjs.org/docs/state-and-lifecycle.html)。这些对于触发从 API 获取数据或更新视图非常有用。

请注意，如果您使用的是 React v16 或更高版本，功能组件不会在 React 库内部被包装成类组件。

React 16 中的功能组件与类组件不走相同的代码路径，不像在之前的版本中它们被转换为类并且会有相同的代码路径。类组件有额外的检查和创建实例的开销，而简单函数没有。尽管这些是微优化，不应该在真实应用中产生巨大差异，除非你的类组件过于复杂。- Dominic Gannaway，Facebook React 核心团队的工程师

功能组件更快，但在大多数情况下被扩展`React.PureComponent`的类组件性能更好：

“但要明确的是，当 props 浅相等时，它们不会像 PureComponent 那样退出渲染。”- Dan Abramov，Redux 和 Create React App 的共同作者，Facebook React 核心团队的工程师

功能组件不仅更简洁，而且通常也是纯函数。我们将在《第九章》中进一步探讨这个概念，*函数式编程模式的元素*。纯函数提供了许多好处，如可预测的 UI 和轻松跟踪用户行为。应用程序可以以某种方式实现来记录用户操作。这些数据有助于调试和在测试中重现错误。我们将在本书的后面深入探讨这个话题。

# 组件组合

如果您学习过任何**面向对象**（**OO**）语言，您可能已经广泛使用了继承。在 JavaScript 中，这个概念有点不同。JavaScript 继承是基于原型的，因此我们称之为**原型继承**。功能不是复制到对象本身，而是从对象的原型继承，甚至可能通过原型树中的其他原型继承。我们称之为**原型链**。

然而，在 React 中，使用继承并不是很常见。由于组件，我们可以采用另一种称为**组件组合**的模式。我们将创建一个新的父组件，该组件将使用其子组件使自己更具体或更强大，而不是创建一个新类并从基类继承。让我们看一个例子：

```jsx
// src/ Chapter 1/ Example_6_Component_composition_red_text/ App.js

const WarningText = ({style, ...otherProps}) => (
    <**Text** style={[style, {color: 'orange'}]} {...otherProps} /> );   export default class App extends React.Component {
    render = () => (
        <**View** style={styles.container}>
 <**Text** style={styles.text}>Normal text</**Text**>
 <**WarningText** style={styles.text}>Warning</**WarningText**>
 </**View**>  ); }
```

`App`组件由三个组件构建：`View`，`Text`和`WarningText`。这是一个完美的例子，说明一个组件如何通过组合来重用其他组件的功能。

`WarningText`组件使用组合来强制`Text`组件中的橙色文本颜色。它使通用的`Text`组件更具体。现在，我们可以在应用程序的任何地方重用`WarningText`。如果我们的应用程序设计师决定更改警告文本，我们可以快速适应一个地方的新设计。

注意隐式传递了一个名为 children 的特殊 prop。它代表组件的子元素。在`Example 6_ Component composition *-* red text`中，我们首先将警告文本作为子元素传递给`WarningText`组件，然后使用扩展运算符将其传递给`Text`组件，`WarningText`封装了它。

# 组合应用程序布局

假设我们必须为我们的应用程序创建一个欢迎屏幕。它应该分为三个部分 - 头部，主要内容和页脚。我们希望对已登录和匿名用户都有一致的边距和样式。但是，头部和页脚内容将不同。我们的下一个任务是创建一个支持这些要求的组件。

让我们创建一个欢迎屏幕，它将使用一个通用组件来封装应用程序布局。

按照以下逐步指南操作：

1.  创建`AppLayout`组件，强制一些样式。它应该接受三个 props：`header`，`MainContent`和`Footer`：

```jsx
const AppLayout = ({Header, MainContent, Footer}) => (
    // **These three props can be any component that we pass.**
    // You can think of it as a function that
    // can accept any kind of parameter passed to it.
    <View style={styles.container}>
        <View style={styles.layoutHeader}>{Header}</View>
        <View style={styles.layoutContent}>{MainContent}</View>
        <View style={styles.layoutFooter}>{Footer}</View>
    </View>
);
```

1.  现在是时候为标题、页脚和内容创建占位符了。我们创建了三个组件：`WelcomeHeader`，`WelcomeContent`和`WelcomeFooter`。如果你愿意，你可以将它们扩展为比一个微不足道的文本更复杂的组件：

```jsx
const WelcomeHeader = () => <View><Text>Header</Text></View>;
const WelcomeContent = () => <View><Text>Content</Text></View>;
const WelcomeFooter = () => <View><Text>Footer</Text></View>;
```

1.  我们应该将`AppLayout`与我们的占位符组件连接起来。创建`WelcomeScreen`组件，它将占位符组件（来自*步骤 2*）作为 props 传递给`AppLayout`：

```jsx
const WelcomeScreen = () => (
    <AppLayout
        Header={<WelcomeHeader />}
 MainContent={<WelcomeContent />}
 Footer={<WelcomeFooter />}
    />
);
```

1.  最后一步将是为我们的应用程序创建根组件并添加一些样式：

```jsx
// src/ Chapter 1/ Example_7_App_layout_and_Welcome_screen/ App.js

// root component
export default class App extends React.Component {
 render = () => <WelcomeScreen />; }

// styles
const styles = StyleSheet.create({
 container: {
         flex: 1,
  marginTop: 20
    },
 layoutHeader: {
 width: '100%',
 height: 100,
 backgroundColor: 'powderblue'
    },
 layoutContent: {
 flex: 1,
 width: '100%',
 backgroundColor: 'skyblue'
    },
 layoutFooter: {
 width: '100%',
 height: 100,
 backgroundColor: 'steelblue'
    }
});
```

请注意使用`StyleSheet.create({...})`。这将创建一个表示我们应用程序样式的样式对象。在这种情况下，我们创建了四种不同的样式（`container`，`layoutHeader`，`layoutContent`和`layoutFooter`），可以在我们定义的标记中使用。我们以前使用诸如`width`，`height`和`backgroundColor`之类的键来自定义样式，这些都是微不足道的。然而，在这个例子中，我们还使用了来自术语**flexbox 模式**的`flex`。我们将在第三章中详细解释这种方法，*样式模式*，我们主要关注`StyleSheet`模式。

这很不错。我们为我们的应用程序制作了一个微不足道的布局，然后创建了欢迎屏幕。

# 组件继承怎么样？

“在 Facebook，我们在成千上万的组件中使用 React，并且我们没有发现任何我们建议创建组件继承层次结构的用例。”- React 官方文档（[`reactjs.org/docs/composition-vs-inheritance.html`](https://reactjs.org/docs/composition-vs-inheritance.html)）

我还没有遇到过必须放弃组件组合而选择继承的情况。Facebook 的开发人员也没有（根据前面的引用）。因此，我强烈建议你习惯于组合。

# 在高级模式上测试组件

在创建可靠和稳定的应用程序时，测试是非常重要的。首先，让我们看看你需要编写的最常见的三种测试类型：

+   **琐碎的单元测试：**我不明白，但它是否工作或根本不工作？通常，检查组件是否渲染或函数是否无错误运行的测试被称为琐碎的单元测试。如果你手动进行这些测试，你会称这些测试为冒烟测试。这些测试非常重要。不管你喜不喜欢，你都应该编写琐碎的测试，至少要知道每个功能*某种程度*上是否工作。

+   **单元测试：**代码是否按照我的预期工作？它是否在所有的代码分支中工作？分支指的是代码中的分支位置，例如，if 语句将代码分支到不同的代码路径，这类似于 switch-case 语句。单元测试是指测试单个代码单元。在应用程序的关键特性中，单元测试应该覆盖整个函数代码（原则上：对于关键特性，代码覆盖率达到 100%）。

+   **快照测试：**测试之前和实际版本是否产生相同的结果被称为快照测试。快照测试只是创建文本输出，但一旦输出被证明是正确的（通过开发人员评估和代码审查），它可能会作为比较工具。尽量多使用快照测试。这些测试应该提交到你的代码库并经过审查过程。Jest 中的这个新功能为开发人员节省了大量时间：

+   **图像快照测试：**在 Jest 中，快照测试比较文本（JSON 到 JSON），但是你可能会在移动设备上遇到快照测试的引用，这意味着比较图像和图像。这是一个更高级的话题，但是大型网站通常会使用。拍摄这样的屏幕截图很可能需要构建整个应用程序，而不仅仅是一个单独的组件。构建整个应用程序是耗时的，因此一些公司只在计划发布时运行这种类型的测试，例如在发布候选版本构建上。这种策略可以自动化遵循*持续集成*和*持续交付*原则。

由于我们在本书中使用 CRNA 工具箱，你想要检查的测试解决方案是 Jest（[`facebook.github.io/jest/`](https://facebook.github.io/jest/)）。

如果你来自 React web 开发背景，请注意。React Native，顾名思义，是在本地环境中运行的，因此有许多组件，比如 react-native-video 包，可能需要特殊的测试解决方案。在许多情况下，你需要模拟（创建占位符/模仿行为）这些包。

点击[`facebook.github.io/jest/docs/en/tutorial-react-native.html#mock-native-modules-using-jestmock`](https://facebook.github.io/jest/docs/en/tutorial-react-native.html#mock-native-modules-using-jestmock)了解更多信息。

我们将在第十章中解决其中一些问题，*管理依赖*。

通常有一些测试指标，比如代码覆盖率（测试覆盖的行数）、报告的错误数量和注册的错误数量。

尽管非常有价值，但这些指标可能会产生一个错误的信念，即应用程序经过了充分测试。

在涉及测试模式时，有一些完全错误的做法需要提及：

+   **仅依赖单元测试**：单元测试意味着仅测试单独的代码片段，例如，通过向函数传递参数并检查输出来测试。这很好，可以避免很多错误，但无论你有多高的代码覆盖率，你可能会在集成经过充分测试的组件时遇到问题。我喜欢用的一个现实例子是两扇门放得太靠近，导致它们不断开合。

+   **过分依赖代码覆盖率**：不要过分强调自己或其他开发人员达到 100%或 90%的代码覆盖率。如果你有能力做到，那很好，但通常这会导致开发人员编写价值较低的测试。有时，向函数发送不同的整数值是至关重要的；例如，在测试除法时，仅发送两个正整数是不够的。你还需要检查当除以零时会发生什么。覆盖率无法告诉你这一点。

+   **不追踪测试指标如何影响错误数量**：如果你只依赖于一些指标，无论是代码覆盖率还是其他任何指标，请重新评估这些指标是否反映了真相，例如，指标的增加是否导致了更少的错误。举个例子，我听过许多不同公司的开发人员说，代码覆盖率超过 80%并没有对他们有太大帮助。

如果你是产品所有者，并且已经查看了上面的*不追踪测试指标如何影响错误数量*，请与项目的技术负责人或资深开发人员进行咨询。可能会有一些特定因素影响这个过程，例如，开发进度转向更可重复的代码。请不要过快下结论。

# 快照测试可扩展组件

这一次，我们将展示快照测试的一个棘手部分。

让我们从创建我们的第一个快照测试开始。转到`Chapter_1/Example 4_Stateful_expandable_component`并在命令行中运行`yarn test`。您应该会看到一个测试通过。这是什么样的测试？这是一个位于`App.test.js`文件中的微不足道的单元测试。

是时候创建我们的第一个快照测试了。将`expect(rendered).toBeTruthy();`替换为`expect(rendered).toMatchSnapshot();`。它应该是这样的：

```jsx
it('renders', () => {
  const rendered = renderer.create(<App />).toJSON();
  expect(rendered).toMatchSnapshot(); });
```

完成后，重新运行`yarn test`。将创建一个名为`__snapshots__`的新目录，其中包含`App.test.js.snap`文件。查看其内容。这是您的第一个快照。

是时候测试应用的覆盖率了。您可以使用以下命令来完成：

```jsx
yarn test -- --coverage
```

它产生了一些令人担忧的东西：

```jsx
File |  % Stmts | % Branch |  % Funcs |  % Lines | Uncovered Line #s
All files|    66.67 |       50 |       50 |    66.67
App.js   |    66.67 |       50 |       50 |    66.67 | 18,23,26
```

我们有一个组件有一个分支（`if`），进行快照测试后，覆盖率甚至没有接近 100%。出了什么问题？

显然，依赖状态的分支存在问题，但是否会占据超过 30%的代码行数？让我们看看完整的报告。打开`./coverage/lcov-report/App.js.html`文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/a30aada2-a239-4b49-be3f-6d5d3530d170.png)

覆盖率报告文件。您可以看到代码未被覆盖，测试标记为红色。

现在，你看到了问题所在。答案很简单——快照测试不测试属性函数。为什么？首先，这没有太多意义。我们为什么要将一个函数转换为 JSON，这有什么帮助呢？其次，告诉我如何序列化这个函数。我应该将函数代码作为文本返回，还是以其他方式计算输出？

以此例为教训，**快照测试并不足够**。

# 测试驱动开发方法

您经常会听到**测试驱动开发**（**TDD**）方法，基本上意味着先编写测试。为了简化这个过程，让我们总结为以下三个步骤：

1.  编写测试并观察它们失败。

1.  实现功能直到看到测试通过。

1.  重构为最佳实践（可选）。

我必须承认，我真的很喜欢这种方法。然而，事实是大多数开发人员会赞美这种方法，但几乎没有人会使用它。这通常是因为它很耗时，而且很难预测即将测试的东西是什么样子。

更进一步，你会发现测试类型之一是针对 TDD 的。快照测试只能在组件实现后创建，因为它们依赖于其结构。这也是为什么快照测试更多是对你的测试的一种补充，而不是替代品的另一个原因。

这种方法在长期运行的大型应用程序中效果最好，其中一组技术架构师规划要使用的接口和模式。这最有可能出现在后端项目中，你会对所有类和模式如何相互连接有一个大致的了解。然后，你只需拿出接口并编写测试。接下来，你跟进实现。如果你想在 React Native 中创建接口，你需要支持 TypeScript。

有人认为 TDD 在小型项目中很棒，你可能很快就会在 Stack Overflow 上找到这样的讨论。不要误会我的意思；我很高兴有些人很开心。然而，小型项目往往非常不稳定，很可能经常变化。如果你正在构建一个**最小可行产品（MVP）**，它与 TDD 并不很搭配。你最好依赖于你使用的库经过了充分测试，并及时使用快照测试来交付项目。

总结一下：放弃 TDD 不应该意味着写更少的测试。

# 表现组件

现在是时候学习如何使组件可重用了。为了实现这个目标，我们将利用我们手中最好的工具：**表现组件**模式。它将组件与逻辑解耦，并使它们更加灵活。

表现组件是一个模式名称，如果以后你决定使用 Redux 库，你会经常听到。例如，在 Dan Abramov 的 Redux 课程中，表现组件被大量使用。

我喜欢解释，表现组件模式是网站的世界。很长一段时间以来，每个网站都有三个主要的组成部分：CSS、HTML 和 JavaScript。然而，React 引入了一种有点不同的方法，即基于 JavaScript 自动生成 HTML。HTML 变成了虚拟的。因此，你可能听说过**虚拟文档对象模型**（**虚拟 DOM**）。这种关注点的分离——HTML（视图）、CSS（样式）和 JavaScript（逻辑，有时称为控制器）——应该在我们的 JavaScript 世界中保持不变。因此，在我们的 JavaScript 世界中，使用表现组件来模仿 HTML，使用容器组件来处理逻辑。

以与 React Native 应用程序相同的方式解决这个问题。你编写的标记应该与它所消耗的逻辑分离。

让我们看看这个问题。你还记得`Example 4_Stateful expandable component`吗？它已经有一个呈现层组件了：

```jsx
const HelloText = ({children, ...otherProps}) => (
    <Text {...otherProps}>{children}</Text> ); 
```

这个组件不引入任何逻辑，只包含标记，在这种情况下非常简短。任何有用的逻辑都隐藏在 props 中并传递，因为这个组件不需要使用它。在更复杂的例子中，你可能需要解构 props 并将它们传递给正确的组件；例如，当使用上面的展开运算符时，所有未解构的 props 都被传递了。

但是，与其专注于这个简单的例子，不如开始重构`App`组件。首先，我们将把标记移到单独的呈现层组件中：

```jsx
// src/ Chapter_1_React_component_patterns/
// Example_9_Refactoring_to_presentational_component/ App.js
// Text has been replaced with "..." to save space.

**export const** HelloBox = ({ isExpanded, expandOrCollapse }) => (
    <View style={styles.container}>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
  {
            isExpanded &&
            <HelloText style={styles.text}>...</HelloText>
  }
    </View> );
```

现在，我们需要用以下内容替换`App`组件中的`render`函数：

```jsx
render = () => (
    **<HelloBox**
  isExpanded={this.state.expanded}
        expandOrCollapse={this.expandOrCollapse}
    **/>** );
```

然而，如果你现在运行代码，你会在`HelloText`的按键事件上遇到一个错误。这是由于 JavaScript 处理`this`关键字的方式。在这次重构中，我们将`expandOrCollapse`函数传递给另一个对象，在那里，`this`指的是一个完全不同的对象。因此，它无法访问状态。

有几种解决这个问题的方法，其中一种是使用箭头函数。我将坚持性能最佳的方法。关键是在你的构造函数中添加以下行：

```jsx
this.expandOrCollapse = this.expandOrCollapse.bind(this); 
```

搞定了；应用程序已经完全可用，就像以前一样。我们已经将一个组件重构为两个——一个是呈现层的，一个负责逻辑的。很好。

假设我们只对两个组件进行了浅层单元测试。

我们能否识别出`this`关键字的问题？

也许不记得了。这个简单的陷阱可能会在大型项目中让你陷入困境，到时候你会太忙碌而无法重新思考每一个组件。小心并记住**集成测试**。

# 解耦样式

在前面的例子中，你可能已经注意到样式与呈现层组件紧密耦合。为什么紧密？因为我们通过`style={styles.container}`明确地包含它们，但`styles`对象是不可配置的。我们无法用 props 替换任何样式部分，这使我们与现有的实现紧密耦合。在某些情况下，这是期望的行为，但在其他情况下则不是。

如果您对样式工作感兴趣，我们将深入研究涉及它们的模式，在第三章中，*样式模式*。您还将了解来自 CSS 的 flexbox 模式和许多其他约定。

如果您尝试将代码拆分为单独的文件，您将遇到这个问题。我们该如何解决这个问题？

让样式成为可选属性。如果未提供样式，则我们可以回退到默认值：

```jsx
// src/ Chapter_1/ Example_10_Decoupling_styles/ App.js

export const HelloBox = ({
    isExpanded,
  expandOrCollapse,
  containerStyles,
  expandedTextStyles
}) => (
    <View style={containerStyles || styles.container}>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
  {
            isExpanded &&
            <HelloText style={expandedTextStyles || styles.text}>
                ...
            </HelloText>
  }
    </View> );
```

注意使用`||`运算符。在上面的例子（`expandedTextStyles || styles.text`）中，它首先检查`expandedTextStyles`是否已定义，如果是，则返回该值。如果`expandedTextStyles`未定义，则返回我们硬编码的默认样式对象`styles.text`。

现在，如果我们希望，在某些地方，我们可以通过传递相应的 props 来覆盖我们的样式：

```jsx
render = () => (
    <HelloBox   isExpanded={this.state.expanded}
        expandOrCollapse={this.expandOrCollapse}
        expandedTextStyles={{ color: 'red' }}
    /> );
```

这就是我们如何分割标记、样式和逻辑。请记住尽可能经常使用表现性组件，以使您的功能在许多屏幕/视图上真正可重用。

如果您来自后端背景，您可能会迅速假设它就像**MVC 模式**：**Model**，**View**和**Controller**。它不一定是 1:1 的关系，但一般来说，您可以简化为以下内容：

+   **View**：这是一个表现性组件。

+   **Model**：这是数据表示，对我们来说，它是在有状态组件中构建的状态，或者使用所谓的存储和 reducers（查看第五章，*存储模式*，了解有关 Redux 是什么以及如何使用它的更多细节）。

+   **Controller**：这是一个负责应用程序逻辑的容器组件，包括事件处理程序和服务。它应该是精简的，并从相应的文件中导入逻辑。

# 容器组件

容器组件模式是很久以前引入的，并在 React 社区中由 Dan Abramov 推广。到目前为止，当我们将 App 组件的内容重构为*表现性组件*时，我们已经创建了一个容器组件。事实证明，`App`组件成为了一个容器组件——它包含了`HelloBox`组件并实现了必要的逻辑。我们从这种方法中获得了什么？我们获得了以下内容：

+   我们可以以不同的方式实现展开和折叠，并重用`HelloBox`组件的标记

+   `HelloBox`不包含逻辑

+   容器组件封装了逻辑，并将其隐藏在其他组件中

我强烈建议阅读 Dan Abramov 在 medium 上的文章。查看[`medium.com/@dan_abramov/smart-and-dumb-components-7ca2f9a7c7d0`](https://medium.com/@dan_abramov/smart-and-dumb-components-7ca2f9a7c7d0)获取更多信息。当涉及到依赖注入模式时，容器组件是非常有用的工具。查看第十章，*管理依赖项*，以了解更多信息。

# HOC

**HOC**是一种模式，用于增强组件的附加属性或功能，例如，如果您想使组件可扩展。我们可以使用 HOC 模式，而不是像之前那样只创建一个有状态的容器。让我们将我们的有状态容器组件重构为 HOC，并将其命名为`makeExpandable`：

```jsx
// src/ Chapter_1/ Example_12_Higher_order_component_makeExpandable/ App.js
 const makeExpandable = (ComponentToEnrich) => (
    class HelloBoxContainer extends React.Component {
        constructor() {
            super();
  this.state = {
                // default state on first render
  expanded: false
  };
  this.expandOrCollapse = this.expandOrCollapse.bind(this);
  }

        expandOrCollapse() {
            // toggle expanded: true becomes false, false becomes true
  this.setState({expanded: !this.state.expanded});
  }

        render = () => (
            <**ComponentToEnrich**
  isExpanded={this.state.expanded}
                expandOrCollapse={this.expandOrCollapse}
            />
  );
  }
);
```

`makeExpandable`组件接受`ComponentToEnrich`。因此，我们可以创建一个根组件（`App`）如下：

```jsx
export default makeExpandable(HelloBox);
```

酷，不是吗？现在，让我们创建一些其他组件，并用我们的 HOC 来丰富它。这将是一个显示文本隐藏或显示的小按钮。如果用户按下按钮，它应该显示或隐藏一个小的彩色框。对于这个任务，你可以使用以下样式：

```jsx
box: {
    width: 100,
  height: 100,
  backgroundColor: 'powderblue', }
```

将它们放在`StyleSheet.create({ ... })`中。我的解决方案非常简单：

```jsx
// src/ Chapter_1/
// Example_13_Higher_order_component_show_hide_button/ App.js

export const SomeSection = ({
    isExpanded,
  expandOrCollapse,
  containerStyles,
  boxStyle
}) => (
    <View style={containerStyles || styles.container}>
 <Button
            onPress={expandOrCollapse}
 title={isExpanded ? "Hide" : "Show"}
 color="#841584"
        />
        {isExpanded && <View style={boxStyle || styles.box} />}
    </View> );

export default makeExpandable(SomeSection);
```

在前面的示例中，`SomeSection`组件被`makeExpandable` HOC 包装，并接收`isExpanded`和`expandOrCollapse`属性。

太棒了！我们刚刚制作了一个可重用的 HOC，它运行得非常完美。

现在，我将向您展示一个相当不为人知但有时很有用的技术，可以使您的 HOC 更加灵活。想象一下，您将增强一个对属性命名要求严格的组件，就像以下示例中一样：

```jsx
export const SomeSection = ({
    showHideBox,
  isVisible,
  containerStyles,
  boxStyle
}) => {...};
```

不幸的是，我们的 HOC，`makeExpandable`，传递了错误的属性名称。让我们来修复一下：

```jsx
// src/ Chapter_1/ Example_14_Flexible_prop_names_in_HOC/ App.js
render = () => {
  const props = {
    [propNames && propNames.isExpanded || 'isExpanded']: this.state.expanded,
  [propNames && propNames.expandOrCollapse || 'expandOrCollapse']: this.expandOrCollapse
  };
  return <ComponentToEnrich {...props} /> }; 
```

这是一个棘手的例子。它提供了重命名由 HOC 传递的属性的能力。要重命名它，我们需要将一个名为`propNames`的配置对象传递给 HOC。如果传递了这样的对象，并且它包含某个键，那么我们将覆盖该名称。如果该键不存在，则我们将回退到默认的属性名称，例如`isExpanded`。

注意对象内部的`[]`的使用。它允许您在对象中动态命名键。在这个例子中，键是根据`propNames`的存在动态选择的。

为了使一切正常工作，我们还需要在`makeExpandable` HOC 中接受可选参数`propNames`：

```jsx
const makeExpandable = (ComponentToEnrich, propNames) => (
    ...
)
```

太棒了！现在我们的 HOC 在处理 prop 名称时更加灵活了！我们可以将其与前面提到的严格的`SomeSection`组件一起使用：

```jsx
export default makeExpandable(SomeSection, {
    isExpanded: 'isVisible',
  expandOrCollapse: **'showHideBox'** }); 
```

在`render`函数内创建变量时要注意性能影响。它会减慢你的应用程序。有时，模式可能会牺牲一点性能，有时则不会。明智地使用它们。你也可以将内联的`propNames`变量作为两个 props。

确保查看下一节以获得更清晰和解耦的方法。

# HOC 组合

创建 HOC 的主要原因是能够组合它们提供的功能。

再次从上一节的问题来看。如果我们可以将工作委托给另一个 HOC 呢？例如，有一个名为`mapPropNames`的 mapper HOC，你可以像这样与我们之前的 HOC 组合：

```jsx
makeExpandable(mapPropNames(SomeSection)); 
```

这是`mapPropNames`的实现：

```jsx
// src/ Chapter_1/ Example_15_HOC_Composition/ App.js

const mapPropNames = (Component) => (props) => (
    <Component
        {...props}
  isVisible={props.isExpanded}
 showHideBox={props.expandOrCollapse}
    />  );
```

很好，很快，不是吗？这是一个常见的模式，也在处理作为 JSON 发送的后端数据时使用。它可以将数据格式适应到前端层的表示。正如你所看到的，我们在处理 HOC 时也可以采用这个好主意！

如果你来自面向对象的背景，请注意 HOC 模式与装饰器模式非常相似。然而，装饰器还依赖继承，并且需要实现它装饰的接口。

请查看[`en.wikipedia.org/wiki/Decorator_pattern`](https://en.wikipedia.org/wiki/Decorator_pattern)以获取示例。

你也可以组合装饰器。它的工作方式类似。

# 有用的 HOC 示例

你需要一个快速的记录器来显示应用程序的行为吗？或者你正在准备一个实时演示，想在屏幕上显示一些动态信息？来吧：

```jsx
// src/ Chapter_1/ Example_16_Useful_HOCs/ App.js

const logPropChanges = Component => props => {
    console.log('[Actual props]:', props)**;**
  return <Component {...props} />; };
// Use: makeExpandable(logPropChanges(mapPropNames(SomeSection))); 
```

好的。现在，假设你正在等待一些数据加载。这里就是加载动画：

```jsx
// src/ Chapter_1/ Example_16_Useful_HOCs/ App.js

import {ActivityIndicator} from 'react-native';
const withSpinner = Component => props => (
    props.shouldSpin
        ? <View style={styles.container}>
 <Text>Your fav spinner f.in. on data load.</Text>
 <**ActivityIndicator** size="large" color="#0000ff" />
 </View>  : <Component {...props} /> );
// Needs a HOC that provides prop shouldSpin (true/false)
```

你可能想要求用户为你的应用打五星。你需要一个模态框来做这个：

```jsx
const withModalOpener = Component => props => (
    // Replace with your favourite Modal box implementation
  <Component {...props} openModal={() => console.log('opening...')} /> );
```

有时，模态框也应该足够智能，以维持它们的可见性。

```jsx
// src/ Chapter_1/ Example_16_Useful_HOCs/ App.js

const withModalOpener = OriginalComponent => (
    class ModalExample extends React.Component {
        // Check this shorter way to init state
        state = {
 modalVisible: true,
        }**;**    setModalVisible(visible) {
            this.setState({modalVisible: visible})**;**
  }

        render() {
            return (
                // Replace with your favourite Modal box implementation
  <View style={styles.container}>
 <OriginalComponent  {...this.props}
                        openModal={() => this.setModalVisible(true)}
                        closeModal={() =>
                     this.setModalVisible(false)}
                    />
 <**Modal**  animationType="slide"
  visible={this.state.modalVisible}
                        onRequestClose={() => {
                            alert('Modal has been closed.');
  }}>
 <View style={styles.container}>
 <Text>Example modal!</Text>   <TouchableHighlight  onPress={() => {
                                    this.setModalVisible(false);
  }}>
 <Text style={{fontSize: 30}}>
  Hide Modal
                                </Text>
 </TouchableHighlight> </View> </**Modal**> </View>  );
  }
    }
); 
```

在这个例子中，我们用`Modal`来丰富组件。`Modal`可以使用名为`openModal`和`closeModal`的 props 打开或关闭。关于模态框是打开还是关闭的信息存储在 HOC 的私有状态中，在这个例子中不会暴露给原始组件。很好的分离，对吧？这个 HOC 也是可重用的。

现在是你的作业时间：我们如何使`Modal`在盒子显示的同时打开？你不能改变`SomeComponent`。

# 总结

在这一章中，你已经学会了如何在 React Native 环境中使用 React 创建基本组件。现在，你应该对无状态和有状态组件感到相当舒适。此外，你还学会了关于展示性和容器性组件。你知道这些模式用于解耦标记和逻辑。你还学会了如何通过使用高阶组件来增强组件功能。希望你也已经在 Git 存储库中玩过我为你收集的可运行示例。

在第二章 *视图模式* 中，我们将更多关注标记。你还将学习一些可以使用的标签。


# 第二章：查看模式

一个非常苛刻的技能是第一次写好视图代码。这需要经验，并且在某个时候几乎变得自动化。因此，从一开始就做对是至关重要的。在本章中，我们将探讨最佳实践，并深入研究您在上一章中已经使用的 React JSX 模式。我们还将专注于更广泛的内置组件范围，其中包括输入和表单。最后，我将向您展示一个名为 linter 的好工具，它对于任何新的前端项目都是必不可少的。

在本章中，您将学习以下内容：

+   编写简洁的 JSX

+   使用常见的 React Native 内置组件

+   使用`TextInput`创建简单的表单

+   区分受控和不受控输入

+   创建错误边界

+   从代码库中消除混合物

+   设置一个代码风格指南的 linter

# 技术要求

在本章中，您将了解各种模式，以及它们的代码片段。但是，要运行它们，您将需要 Create React Native App 包。我已经将每个示例分成一个独立的应用程序，您可以在手机或模拟器上启动。

要跟着本章的示例，您将需要以下内容：

+   一个 Android/iOS 手机或模拟器

+   Git，获取示例：[`github.com/Ajdija/hands-on-design-patterns-with-react-native`](https://github.com/Ajdija/hands-on-design-patterns-with-react-native)

按照 GitHub 页面上的安装和运行说明开始。

# JSX 简介

到目前为止，我们一直在使用 JSX，但是它是什么意思呢？JSX 代表 JavaScript 扩展。它怎么能是一个扩展呢？

您可能知道，ECMAScript 也是 JavaScript 的一个扩展（有点）。ECMAScript 被转译成 JavaScript。这意味着什么？这意味着它只是将 ECMAScript 代码转换为有效的 JavaScript 代码。JavaScript 缺少我们从 ECMAScript 中喜欢的许多功能，例如箭头函数、类和解构运算符。

JSX 的工作方式也是一样的。JSX 被转译成 JavaScript，它的主要特点是根据您编写的标记创建 React 元素。

我们能只使用 JavaScript 吗？是的。值得吗？很可能不值得。

让我们看看这个实例。这是 JSX *和* ECMAScript：

```jsx
export default () => <Text style={{marginTop: 30}}>Example Text!</Text>
```

现在，将这与纯 JavaScript 进行比较：

```jsx
export default function() {
    return React.createElement(
        Text,
  {style: {marginTop: 30}},
  'Example Text!'
  ); }
```

毫无疑问，第一个代码片段更容易阅读和理解。

Babel 将 JSX 转译为 JavaScript。查看这个交互式工具，以便您可以玩耍并查看更复杂示例中的输出：[`goo.gl/RjMXKC`](https://goo.gl/RjMXKC)。

# JSX 标准技巧

在我们继续之前，我想向您展示在编写 JSX 标记时的最佳实践。这将使您在接下来的示例中更容易理解。

让我们从简单的规则开始：

+   如果您的组件内没有子元素，请使用自闭合标签：

```jsx
// good
<Button onPress={handlePress} />

// bad
<Button onPress={handlePress}></Button> 
```

+   如果需要根据某些条件显示组件，则使用`&&`运算符：

```jsx
// bad
function HelloComponent(props) {   if (isSomeCondition) {
return <p>Hello!</p>;   }
return null;  }

// bad
const HelloComponent = () => {
  return isSomeCondition ? <p>Hello!</p> : null
};

// ok (probably it will require some logic before return)
const HelloComponent = () => { return isSomeCondition && <p>Hello!</p> };

// almost good (isSomeCondition can be passed using props)
const HelloComponent = () => isSomeCondition && <p>Hello!</p>;

// best: use above solution but within encapsulating component
// this way HelloComponent is not tightly tied to isSomeCondition

const HelloComponent = () => <p>Hello!</p>;
const SomeComponent = () => (
    // <== here some component JSX ...
   isSomeCondition && <HelloComponent />
    // <== the rest of encapsulating component markup here
);
```

前述做法仅适用于其他选项为`null`的情况。如果 false 情况也是一个组件，您可以使用`*b ? x : y*`运算符，甚至是简单的`if-else`方法，但是它应符合您项目的最佳实践。

+   如果使用`*b ? x : y*`运算符，则可能会发现大括号（`{}`）很有用：

```jsx
const SomeComponent = (props) => (
<View>
 <Text>{props.isLoggedIn ? 'Log In' : 'Log Out'}</Text>
 </View> );
```

+   您还可以使用大括号（`{}`）来解构 props 对象：

```jsx
const SomeComponent = ({ isLoggedIn, ...otherProps }) => (
<View>
 <Text>{isLoggedIn ? 'Log In' : 'Log Out'}</Text>
 </View> );
```

+   如果要将`isLoggedIn`传递为`true`，只需写入 prop 名称即可：

```jsx
// recommended const OtherComponent = () => (
    <SomeComponent isLoggedIn />
);

// not recommended
const OtherComponent = () => (
    <SomeComponent isLoggedIn={true} />
);
```

+   在某些情况下，您可能希望传递所有其他 props。在这种情况下，您可以使用展开运算符：

```jsx
const SomeButton = ({ type , ...other }) => {
const className = type === "blue" ? "BlueButton" : "GrayButton";
  return <button className={className} {...other} />; }; 
```

# 初学者命名指南

命名可能听起来微不足道，但在 React 中有一些标准做法，您应该遵守。这些做法可能因项目而异，但请记住，您至少应该尊重这里提到的做法。在其他情况下，请检查您项目的样式指南，可能还有您的 linter 配置。

伟大的 React 样式指南之一来自 Airbnb，可以在[`github.com/airbnb/javascript/tree/master/react#naming`](https://github.com/airbnb/javascript/tree/master/react#naming)上查看。

组件名称应以大写字母开头，除非它是 HOC。使用组件名称作为文件名。文件名应为 UpperCamelCase（有关 CamelCase 的更多信息，请参见[`en.wikipedia.org/wiki/Camel_case`](https://en.wikipedia.org/wiki/Camel_case)）：

```jsx
// bad
someSection.js
// good
SomeSection.js or SomeSection.jsx
// Current Airbnb style guide recommends .jsx extension though.
```

以下是有关导入组件的规则：

```jsx
// bad
import App from './App/App';

// bad
import App from './App/index';

// good
import App from './App';
```

如果是 HOC，请使用小写字母的小驼峰命名法开始其名称，例如`makeExpandable`。

Airbnb 还建议您注意内部组件的名称。我们需要指定`displayName`属性，如下所示：

```jsx
// Excerpt from
// https://github.com/airbnb/javascript/tree/master/react#naming
// bad
export default function withFoo(WrappedComponent) {
 return function WithFoo(props) {
 return <WrappedComponent {...props} foo />;
  }
}

// good
export default function withFoo(WrappedComponent) {
  function WithFoo(props) {
 return <WrappedComponent {...props} foo />;
  }

  const wrappedComponentName = WrappedComponent.displayName
 || WrappedComponent.name
 || 'Component';

  WithFoo.displayName = `withFoo(${wrappedComponentName})`;
 return WithFoo;
}
```

这是一个有效的观点，因为在某些工具中，您可能会从看到正确的组件名称中受益。遵循此模式是可选的，并由团队决定。

可以创建一个 HOC 来处理`displayName` prop。这样的 HOC 可以在我们在第一章中创建的 HOC 之上重复使用，*React 组件模式*。

在定义新的 props 时，请避免使用曾经表示其他含义的常见 props。一个例子可能是我们用来将样式传递给组件的 style prop。

请查看以下链接，了解应避免使用哪些 props：

+   与您的应用程序布局对应的 Props：

+   [`facebook.github.io/react-native/docs/layout-props.html`](https://facebook.github.io/react-native/docs/layout-props.html)

+   为组件样式保留的 Props，因为它可能会造成混淆：

+   [`facebook.github.io/react-native/docs/image-style-props.html`](https://facebook.github.io/react-native/docs/image-style-props.html)

+   [`facebook.github.io/react-native/docs/text-style-props.html`](https://facebook.github.io/react-native/docs/text-style-props.html)

+   [`facebook.github.io/react-native/docs/view-style-props.html`](https://facebook.github.io/react-native/docs/view-style-props.html)

不要太害怕。迟早会感觉更自然。

# 使用 PropTypes 进行类型检查

React 带有对基本类型检查的支持。它不需要您升级到 TypeScript 或其他更高级的解决方案。要立即实现类型检查，您可以使用`prop-types`库。

让我们为`Chapter 1/Example 12`中的`HelloBox`组件提供类型定义：

```jsx
import PropTypes from 'prop-types';

// ...  HelloBox.propTypes = {
 isExpanded: PropTypes.bool.isRequired,
  expandOrCollapse: PropTypes.func.isRequired,
  containerStyles: PropTypes.object,
  expandedTextStyles: PropTypes.object }; 
```

这样，我们强制`isExpanded`为布尔类型（`true`或`false`），并且`expandOrCollapse`为函数。我们还让 React 知道两个可选的样式 props（`containerStyles`和`expandedTextStyles`）。如果未提供样式，我们将简单地返回默认样式。

在标记中还有一个很好的功能可以避免显式的`if`——默认 props。看一下：

```jsx
HelloBox.defaultProps = {
    containerStyles: styles.container,
  expandedTextStyles: styles.text }; 
```

太棒了！现在，如果`containerStyles`或`expandedTextStyles`为 null，那么它们将获得相应的默认值。但是，如果您现在运行应用程序，您会注意到一个小警告：

```jsx
Warning: Failed prop type: Invalid prop `containerStyles` of type `number` supplied to `HelloBox`, expected `object`.
```

你现在可能感到恐慌，但这是正确的。这是 React Native 团队做出的一个很好的优化，你可能不知道。它缓存样式表，只是发送缓存的 ID。以下行返回了表示传递的`styles`对象的样式表的数字和 ID：

```jsx
styles.container
```

因此，我们需要调整我们的类型定义：

```jsx
HelloBox.propTypes = {
    isExpanded: PropTypes.bool.isRequired,
  expandOrCollapse: PropTypes.func.isRequired,
  containerStyles: PropTypes.oneOfType([
 PropTypes.object,
        PropTypes.number
 ])**,**
  expandedTextStyles: PropTypes.oneOfType([
 PropTypes.object,
        PropTypes.number
 ])
};
```

现在，您可以在组件标记中删除显式的`if`语句。它应该看起来更或多如下所示：

```jsx
export const HelloBox = ({
    isExpanded,
  expandOrCollapse,
  containerStyles,
  expandedTextStyles
}) => (
    <View style={containerStyles}>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
 <HelloText onPress={() => expandOrCollapse()}>...</HelloText>
  {
            isExpanded &&
            <HelloText style={expandedTextStyles}>
                ...
            </HelloText>
  }
    </View> );
```

干得好！我们已经为我们的组件定义了默认属性和类型检查。请查看`src/chapter 2`目录中的完整工作`Example 2`以获取更多详细信息。

请注意，从现在开始，所有的代码示例都将被拆分成几个模块化的源文件。所有文件将放在各自示例的`./src`目录下。

例如，`Example 2`的组织方式如下：

+   `src`

+   `HelloBox.js`

+   `HelloText.js`

+   `makeExpandable.js`

+   `App.js`

这个结构将随着应用程序的发展而发展。在第十章中，*管理依赖关系*，您将学习如何在拥有一百万行代码的大型项目中组织文件。

# 您需要了解的内置组件

React Native 正在快速发展并经常变化。我已经选择了一系列组件的精选列表，这些组件可能会在 API 中长期存在。我们将花一些时间学习它们，这样我们以后在这本书中就能更快地进行下去。任何进一步的示例都将依赖于这些组件，并假设您知道这些组件的用途。

# ScrollView 组件

到目前为止，我们知道了三个组件：`View`，`Text`和`StyleSheet`。现在，想象一种情况，我们在应用程序中有很多行要显示——比如我脑海中浮现出的信息表。显然，这将是一个很长的表，但屏幕很小，所以我们将使其可滚动——上下滚动，就像在浏览器中一样。这在概念上可能看起来微不足道，但实现起来并不容易，这就是为什么 React Native 提供了`ScrollView`组件。

让我们看看这个问题是如何发生的。从`Chapter 2`文件夹中查看`Example 3_ No ScrollView problem`来开始。

在这里，我们有一个典型的`TaskList`组件，它将每个任务转换为一个`Task`组件。`Task`以`Text`的形式显示其名称和描述。这是一个非常简单的机制，但是一旦任务数量庞大，比如 20 个或更多个任务，它就会填满整个屏幕，突然间你意识到你无法像在浏览器窗口中那样滚动：

```jsx
// Chapter 2 / Example 3 / src / TaskList.js
export const TaskList = ({tasks, containerStyles}) => (
    <View style={containerStyles}>
  {tasks.map(task => // problems if task list is huge
            <ExpandableTask
  key={task.name + task.description}
                name={task.name}
                description={task.description}
            />
  )}
    </View> );
```

为了解决这个问题并使内容可滚动，将`View`替换为`ScrollView`。您还需要将`style`属性重命名为`contentContainerStyle`。请参见完整示例，如下所示：

```jsx
// Chapter 2 / Example 4 / src / TaskList.js import React from 'react'; import Task from './Task'; import PropTypes from 'prop-types'; import {StyleSheet, Text, ScrollView, View} from 'react-native'; import makeExpandable from './makeExpandable';   const ExpandableTask = makeExpandable(Task);   export const TaskList = ({tasks, containerStyles}) => (
     <**ScrollView** contentContainerStyle={containerStyles}>
  {tasks.map(task =>
             <ExpandableTask key={task.name + task.description}
                name={task.name}
                description={task.description}
             />
  )}
 </**ScrollView**> );   const styles = StyleSheet.create({
 container: {
 backgroundColor: '#fff'     }
});   TaskList.propTypes = {
 tasks: PropTypes.arrayOf(PropTypes.shape({
 name: PropTypes.string.isRequired,
 description: PropTypes.string.isRequired
  })),
  containerStyles: PropTypes.oneOfType([
         PropTypes.object,
  PropTypes.number
     ])
};   TaskList.defaultProps = {
 tasks: [],
 containerStyles: styles.container };   export default TaskList;  
```

我还包括了`PropTypes`定义，这样您就可以练习我们在上一节中学到的内容。

注意在`Task`组件上使用`key`属性（`key={task.name + task.description}`）。这在渲染集合时是必需的，以便 React 可以区分元素的属性更改，并在可能的情况下避免不必要的重绘组件。

# 图像组件

你经常会使用的下一个组件是`Image`组件。让我们用 React 标志扩展我们的任务列表。在每个任务之后，我们将展示 React 标志的.png 图片：

```jsx
// Chapter 2_View patterns/ Example 5/src /Task.js // ...
**<Image** // styles just to make it smaller in the example  style={{width: 100, height: 100}}
 source={require("./**react.png**")}
**/>**
// ... 
```

请注意，目前并非所有图像类型都受支持。例如，SVG 图像将需要一个单独的库来工作。

您可以在官方文档中查看`Image`组件消耗的 props：[`facebook.github.io/react-native/docs/image`](https://facebook.github.io/react-native/docs/image)。您会在这里找到有用的 props，比如`loadingIndicatorSource`——这是在加载大源图像时显示的图像。

# 文本输入组件

我们将在下一节经常使用这个组件。总体思路是能够从智能手机键盘传递数据。`TextInput`用于登录和注册表单以及用户需要向应用程序发送文本数据的许多其他地方。

让我们扩展第一章中的`HelloWorld`示例，“React 组件模式”，以接受一个名字：

```jsx
// Chapter 2 / Example 6 / src / TextInputExample.js
export default class TextInputExample extends React.Component {
    state = {
        name: null
  };    render = () => (
        <View style={styles.container}>
  {this.state.name && (
                <Text style={styles.text}>
  Hello {this.state.name}
                </Text>
  )}
            <Text>Hands-On Design Patterns with React Native</Text>
 <Text>Chapter 2: View Patterns</Text>
 <Text style={styles.text}>
  Enter your name below and see what happens.
            </Text>
 <TextInput  style={styles.input}
 onChangeText={name => this.setState({name})}
            **/>**
 </View>  ); }
// ... styles skipped for clarity in a book, check source files.
```

如果用户在`TextInput`组件中输入文本，那么我们会在简短的问候语中显示输入的文本。条件渲染使用`state`来检查名字是否已经定义。当用户输入时，`onChangeText`事件处理程序被调用，并且我们传递的函数会用新的名字更新状态。

有时，本地键盘可能会与您的`View`组件重叠，并隐藏重要信息。如果您的应用程序出现这种情况，请熟悉`KeyboardAvoidingView`组件。

查看[`facebook.github.io/react-native/docs/keyboardavoidingview.html`](https://facebook.github.io/react-native/docs/keyboardavoidingview.html)获取更多信息。

# 按钮组件

`Button`是一个常见的组件，你会发现自己在任何类型的应用程序中使用它。让我们用上下按钮构建一个小的`like`计数器：

```jsx
// Chapter 2 / Example 7 / src / LikeCounter.js
class LikeCounter extends React.Component {
    state = {
        likeCount: 0
  }
    // like/unlike function to increase/decrease like count in state
    like = () => this.setState({likeCount: this.state.likeCount + 1})
    unlike = () => this.setState({likeCount: this.state.likeCount - 1})

    render = () => (
        <View style={styles.container}>
 <Button  onPress={this.unlike}
                title="Unlike"
  />
 <Text style={styles.text}>{this.state.likeCount}</Text>
 <Button  onPress={this.like}
                title="Like"
  />
 </View>  ); }
// Styles omitted for clarity
```

对这个概念的进一步修改可以实现对评论的点赞/踩或者对评论的星级评价系统。

`Button`组件非常有限，习惯于 Web 开发的人可能会感到惊讶。例如，您不能以 Web 方式设置文本，例如`<Button>Like</Button>`，也不能传递样式属性。如果您需要为按钮设置样式，请使用`TouchableXXXX`。查看下一节以获取`TouchableOpacity`的示例。

# 不透明的触摸

当按钮需要自定义外观时，很快似乎需要更好的替代方案。这就是`TouchableOpacity`发挥作用的地方。当内部内容需要变得可触摸时，它可以满足任何目的。因此，我们将制作自己的按钮并根据需要进行样式设置：

```jsx
class LikeCounter extends React.Component {
    state = {
        likeCount: 0
  }
    like = () => this.setState({likeCount: this.state.likeCount + 1})
    unlike = () => this.setState({likeCount: this.state.likeCount - 1})

    render = () => (
        <View style={styles.container}>
 <TouchableOpacity  style={styles.button}
 onPress={this.unlike}
            **>**
 <Text>Unlike</Text>
 **</TouchableOpacity>** <Text style={styles.text}>{this.state.likeCount}</Text>
 <TouchableOpacity  style={styles.button}
 onPress={this.like}
            **>**
 <Text>Like</Text>
 **</TouchableOpacity>** </View>  ); }
```

以下是一些示例样式。我们将在第三章中深入探讨样式模式：

```jsx
const styles = StyleSheet.create({
    container: {
        flexDirection: 'row',
  paddingTop: 20,
  paddingLeft: 20
  },   button: {
 alignItems: 'center', // horizontally centered
  justifyContent: 'center', // vertically centered
  backgroundColor: '#DDDDDD',
  padding: 20
  }**,**
  text: {
        fontSize: 45
  }
}); 
```

按钮的内容在垂直和水平方向上都居中。我们有一个自定义的灰色背景颜色和按钮内的填充。填充是从子元素到组件边框的空间。

现在我们知道了这些简单的组件，我们准备进一步探索如何构建表单以及如何处理更复杂的用例。

# 构建表单

在本节中，我们将探讨如何处理用户的文本输入。从所谓的表单中收集输入的传统方式分为两种主要方式：受控和不受控。在本机环境中，这意味着要么在 React Native 端处理任何按键（*受控输入*），要么让其在本机系统级别上处理并根据需要在 React 中收集数据（*不受控输入*）。

如果您来自 Web 开发背景，请注意，写作本书时，没有表单组件，我也看不到它的出现。对于引用和您可以使用它们的方式也有限制。例如，您不能要求`TextInput`的引用获取其当前值。请查看以下两个小节以获取更多详细信息。您也可以使用自定义库，但我不会在这里讨论这样的解决方案，因为这些解决方案往往经常变化。

# 受控输入

受控输入是在 JavaScript 端处理所有用户输入的输入，很可能是在 React 状态或其他状态替代品中（有关更多信息，请参见第五章 *Store Patterns*）。这意味着，当用户输入时，按键在本地系统级别和 JavaScript 级别都被记住。当然，这可能是低效的，不应该在复杂的 UI 中使用，这在移动世界中似乎是罕见的。

还记得本章前面的*带有你的名字的 hello world*示例吗？这是受控输入的一个完美例子。让我们再看一遍：

```jsx
// Chapter 2_ View patterns/Example 6/src/TextInputExample.js

export default class TextInputExample extends React.Component {
    state = {
 name: null
  }**;**    render = () => (
        <View style={styles.container}>
  {this.state.name && (
                <Text style={styles.text}>
  Hello {this.state.name}
                </Text>
  )}  ...  <TextInput  style={styles.input}
                onChangeText={name => this.setState({name})}
            />
 </View>  ); }
```

我们监听文本的每一次改变（`onChangeText`），然后立即更新组件状态（`this.setState({name})`）。状态成为唯一的真相来源。我们不需要请求本地组件的值。我们只关心状态中的内容。因此，我们使用状态来显示新的`Hello`消息，以及输入的文本。

让我们看看在一个更复杂的例子中它是如何工作的。我们的任务是创建一个登录表单，其中包括登录`TextInput`、密码`TextInput`和一个显示文本为“登录”的`Button`组件。当用户按下按钮时，它应该将信息记录到我们的调试控制台。在一个真实的应用程序中，你会将登录详情传递给服务器进行验证，然后登录用户。你将在第五章 *Store Patterns*中学习如何做到这一点，当我们讨论副作用时：

```jsx
// Chapter 2 / Example 9 / src / LoginForm.js

export default class LoginForm extends React.Component {
    // Initial state for our components
  state = {
        login: this.props.initLogin || '', // remembered login or ''
  password: ''
  };
  // Submit handler when the Login button is pressed
  submit = () => {
        console.log(this.state.login);
  console.log(this.state.password);
  };    render() {
        return (
            <View style={styles.container}>
 <View> <TextInput  style={styles.input}
                        placeholder={'Login'}
                        onChangeText={login => this.setState({login})}
                    />
 </View> <View> <TextInput  style={styles.input}
                        placeholder={'Password'}
                        onChangeText={
                            password => this.setState({password})
                        }
                        secureTextEntry={true} // hide password
  />
 </View> <View> <Button  onPress={this.submit}
                        title="Login"
  />
 </View> </View>  );
  }
}
```

请注意这里的三个重要事项：

+   它提供了传递记住的登录文本的能力。完整的功能需要在物理设备内存中记住登录信息，因此我为了清晰起见省略了这一点。

+   `TextInput`的`secureTextEntry`属性可以将密码隐藏在点后面。

+   在按钮组件上设置`onPress`处理程序，以便它可以对收集到的数据进行操作。在这个简单的例子中，我们只是将日志记录到调试控制台。

# 不受控输入

React Native 中的不受控输入并不是在 Web 开发中的真实情况。事实上，`TextInput`不能完全不受控制。你需要以某种方式监听数值的变化：

+   `onChangeText`在文本输入改变时触发

+   `onSubmitEditing`在按下文本输入的提交按钮时触发

另外，`TextInput`本身就是一个受控组件。进一步查看解释。很久以前，它曾经有一个叫做`controlled`的属性，允许您指定一个布尔值，但是这已经改变了。当时的文档指定了以下内容：

"如果您真的希望它表现得像一个受控组件，您可以将其设置为 true，但是您可能会看到闪烁、丢失的按键和/或输入延迟，这取决于您如何处理 onChange 事件。"

- [`facebook.github.io/react-native/docs/0.7/textinput.html`](https://facebook.github.io/react-native/docs/0.7/textinput.html)。

我意识到 React Native 团队在解决这些问题上付出了很多努力，并且他们修复了`TextInput`。然而，`TextInput`在某种程度上变成了受控输入。例如，`TextInput`上的选择由 React Native 在`componentDidUpdate`函数中进行管理。

"选择也是一个受控属性。如果本地值与 JS 值不匹配，则更新为 JS 值。"

- TextInput 的 React Native 源代码：[`github.com/facebook/react-native/blob/c595509048cc5f6cab360cd2ccbe7c86405baf92/Libraries/Components/TextInput/TextInput.js`](https://github.com/facebook/react-native/blob/c595509048cc5f6cab360cd2ccbe7c86405baf92/Libraries/Components/TextInput/TextInput.js)。

除非您指定`onChangeText`或`value`属性，否则您的组件似乎不会有任何额外的开销。

事实上，您仍然可以使用引用。查看以下示例，了解如何使用 React 的最新 API：

```jsx
// Chapter 2 / Example 10 / App.js

export default class App extends React.Component {
    constructor(props) {
        super(props);    this.inputRef = React.createRef()**;**
  }

    render = () => (
        <TextInput style={{height:50}} ref={ref => this.inputRef = ref} **/>**
  );    componentDidMount() {
        this.inputRef.focus()**;**
  }
}
```

然而，有一些限制。您不能要求输入值的引用。可悲的是，我觉得这种情况不太可能改变。如果你从另一个角度来看，这种情况更自然。你可能只需要受控组件。目前，非受控组件的好处在于性能，并没有太大的不同。因此，我怀疑你在 React Native 中是否需要非受控组件。我甚至无法想出一个需要大量非受控组件的用例，因为性能问题。

我能做的最接近让组件独立的是使用`onSubmitEditing`或`onEndEditing`。这样的回调可以像`onChangeText`属性一样使用。它们直到用户按下本机键盘上的提交/返回按钮才会触发。不幸的是，您可能可以想象到当用户按下预期的按钮而不是按下登录按钮时的情况。在这种情况下，状态不会更新为最新数据，因为本机键盘仍然打开。这样的细微差别可能导致不正确的数据提交和关键错误。要小心。

如果您正在使用 React 开发网站，请不要因为这一部分而感到沮丧。refs 对于棕地网站非常有用，对于那些无法将现有部分重写为 React 的人也很有用。如果这是您的情况，请还要查看 React v16 的门户 API[https://reactjs.org/docs/portals.html]（https://reactjs.org/docs/portals.html）。

# 错误边界介绍

这是 React 版本 16 中带来的一个被忽视的功能。正如您应该已经知道的，JavaScript 可能会抛出错误。这样的错误不应该破坏您的应用程序，特别是如果它来自金融部门。JavaScript 的常规命令式解决方案是`try-catch`块：

```jsx
try {
    // helloWorld function can potentially throw error
    helloWorld(); } catch (error) {
    // If helloWorld throws error
    // we catch it and handle gracefully
    // ... }
```

这种方法在 JSX 中很难使用。因此，React 团队为 React 视图开发了一种替代解决方案。它被称为“错误边界”。任何类组件都可以成为`ErrorBoundary`组件，只要它实现了`componentDidCatch`函数：

```jsx
class AppErrorBoundary extends React.Component {
    state = { hasError: false };    componentDidCatch() {
        this.setState({ hasError: true });
  }

    render = () => (
        this.state.hasError
  ? <Text>Something went wrong.</Text>
  : this.props.children
  )
}

export default () => (
    <AppErrorBoundary>  <LoginForm /> </AppErrorBoundary**>** )
```

如果您跟随这些示例，您可能会看到一个带有错误的红色屏幕。这是开发模式下的默认行为。您将不得不关闭屏幕才能看到应用程序的外观：错误边界将按预期工作。如果切换到发布模式，错误屏幕将不会出现。

`LoginForm`现在被包装在`ErrorBoundary`中。它捕获渲染`LoginForm`时发生的任何错误。如果捕获到`Error`，我们会显示一个简短的消息，说明“出了点问题”。我们可以从错误对象中获取真正的错误消息。但是，与最终用户分享它并不是一个好的做法。相反，将其发送到您的分析服务器：

```jsx
// Chapter 2_View patterns/Example 11/ App.js
...
**componentDidCatch**(error) {
    this.setState({
        hasError: true,
  errorMsg: error
    }); }

render = () => (
    this.state.hasError
  ? (
            <View>
 <Text>Something went wrong.</Text>
 <Text>{this.state.errorMsg.toString()}**</Text>**
 </View>  )
        : this.props.children )
...
```

# 错误边界如何捕获错误

错误边界似乎是用来捕获阻止渲染成功完成的运行时错误的。因此，它们非常特定于 React，并且是使用类组件的特殊生命周期钩子来实现的。

错误边界不会捕获以下错误：

+   事件处理程序

+   异步代码（例如，`setTimeout`或`requestAnimationFrame`回调）

+   服务器端渲染

+   错误边界本身抛出的错误（而不是其子组件）

- React 官方文档网址：[`reactjs.org/docs/error-boundaries.html`](https://reactjs.org/docs/error-boundaries.html)。

让我们进一步讨论之前提到的错误边界的限制：

+   **事件处理程序**：这个限制是由于事件处理程序的异步性质。回调是由外部函数调用的，并且事件对象作为参数传递给回调。我们对此没有任何控制，也不知道何时会发生。代码被执行，永远不会进入 catch 子句。提示：这也以同样的方式影响`try-catch`。

+   **异步代码**：大多数异步代码不会与错误边界一起工作。这个规则的例外是异步渲染函数，这将在未来的 React 版本中推出。

+   **服务器端渲染**：这通常涉及服务器端渲染的网站。这些网站是在服务器上计算并发送到浏览器的。由于这个原因，用户可以立即看到网站的内容。大多数情况下，这样的服务器响应会被缓存和重复使用。

+   **错误边界本身抛出的错误**：您无法捕获发生在同一类组件内部的错误。因此，错误边界应该包含尽可能少的逻辑。我总是建议为它们使用单独的组件。

# 理解错误边界

错误边界可以以许多不同的方式放置，每种方法都有其自己的好处。选择适合您用例的方法。有关想法，请跳转到下一节。在这里，我们将演示应用程序根据错误边界的放置方式而表现出的行为。

这个第一个例子在`LikeCounter`组件周围使用了两个错误边界。如果其中一个`LikeCounter`组件崩溃，另一个仍然会显示出来：

```jsx
...
    <AppErrorBoundary>  <LikeCounter /> </AppErrorBoundary**>** <AppErrorBoundary>  <LikeCounter /> </AppErrorBoundary**>** **...** 
```

这第二个例子在两个`LikeCounter`组件周围使用了一个`ErrorBoundary`。如果一个崩溃，另一个也将被`ErrorBoundary`替换：

```jsx
...
    <AppErrorBoundary>  <LikeCounter /> <LikeCounter /> </AppErrorBoundary**>** **...**
```

# 何时使用错误边界

`ErrorBoundary`绝对是一个很好的模式。它将`try-catch`的概念转化为声明性的 JSX。我第一次看到它时，立刻想到将整个应用程序包装在一个边界中。这没问题，但这不是唯一的用例。

考虑错误边界的以下用例：

+   **小部件**：如果给定一些不正确的数据，您的小部件可能会遇到问题。在最坏的情况下，如果它无法处理数据，它可能会抛出错误。鉴于这个小部件对于应用程序的其余部分并不是至关重要的，您希望其余的应用程序仍然可用。您的分析代码应该收集错误并保存至少一个堆栈跟踪，以便开发人员可以修复它。

+   **模态框**：保护应用程序的其余部分免受错误模态框的影响。这些通常用于显示一些数据和简短的消息。您不希望模态框炸毁您的应用程序。这样的错误应该被认为是非常罕见的，但“宁愿安全也不要后悔”。

+   **功能容器的边界**：假设您的应用程序被划分为由容器组件表示的主要功能。例如，让我们以 Facebook Messenger 这样的消息应用为例。您可以向侧边栏、我的故事栏、页脚、开始新消息按钮和消息历史记录列表视图添加错误边界。这将确保，如果一个功能出现故障，其他功能仍有机会正常工作。

现在我们知道了所有的优点，让我们讨论一下缺点：混合。

# 为什么混合是反模式

使用混合模式，您可以将某种行为与您的 React 组件混合在一起。您可以免费注入一种行为，并且可以在不同的组件中重用相同的混合。这一切听起来都很棒，但实际上并不是这样——您很容易找到关于为什么的文章。在这里，我想通过示例向您展示这种反模式。

# 混合示例

与其大声喊叫*混合是有害的*，不如创建一个正在使用它们的组件，并查看问题所在。混合已经被弃用，因此第一步是找到一种使用它们的方法。事实证明，它们仍然以一种传统的方式创建 React 类组件。以前，除了 ES6 类之外，还有一个特殊的函数叫做`createReactClass`。在一个重大版本发布中，该函数从 React 库中删除，并且现在可以在一个名为`'create-react-class'`的单独库中使用：

```jsx
// Chapter 2_View patterns/Example 12/App.js
...
import createReactClass from **'create-react-class'**;

const LoggerMixin = {
    componentDidMount: function() { // uses lifecycle method to log
        console.log('Component has been rendered successfully!');
  }
};   export default createReactClass({
    mixins: [LoggerMixin]**,**   render: function() {
        return (
            <View>
 <Text>Some text in a component with mixin.</Text>
 </View>  );
  }
});
```

在这里，我们创建了`LoggerMixin`，它负责记录必要的信息。在这个简单的例子中，它只是关于已呈现的组件的信息，但它可以很容易地进一步扩展。

在这个例子中，我们使用了`componentDidMount`，这是组件生命周期钩子之一。这些也可以在 ES6 类中使用。请查看官方文档以了解其他方法的见解：[`reactjs.org/docs/react-component.html#the-component-lifecycle`](https://reactjs.org/docs/react-component.html#the-component-lifecycle)。

如果您需要更多的记录器，可以使用逗号将它们混合到单个组件中：

```jsx
...
mixins: [LoggerMixin, LoggerMixin2],
...
```

这是一本关于模式的书，因此在这里停下来看一下`createReactClass`函数。

为什么它已经被弃用？答案实际上非常简单。React 团队更喜欢显式 API 而不是隐式 API。`CreateReactClass`函数是另一个隐式抽象，它会隐藏实现细节。与其添加一个新函数，不如使用标准方式：ES6 类。ES6 类也有自己的缺点，但这是另一个完全不同的话题。此外，您可以在其他基于 ECMAScript 构建的语言中使用类，例如 TypeScript。这是一个巨大的优势，特别是在现今 TypeScript 变得流行的时代。

要了解更多关于这种思维过程的信息，我建议您观看 Sebastian Markbåge 的一次精彩演讲，名为**Minimal API Surface Area**。它最初是在 2014 年的 JSConf EU 上发布的，可以在[`www.youtube.com/watch?v=4anAwXYqLG8`](https://www.youtube.com/watch?v=4anAwXYqLG8)找到。

# 使用 HOC 代替

我相信您可以轻松地将前面的用例转换为 HOC。让我们一起做这个，然后我们将讨论为什么 HOC 更好：

```jsx
// Chapter 2_View patterns/ Example 13/ App.js
const withLogger = (ComponentToEnrich, logText) =>
    class WithLogger extends React.Component {
        componentDidMount = () => console.log(
            logText || 'Component has been rendered successfully!'
  );    render = () => <ComponentToEnrich {...this.props} />;
  };   const App = () => (
    <View style={styles.container}>
 <Text>Some text in a component with mixin.</Text>
 </View> );   export default withLogger(withLogger(App), 'Some other log msg');
```

您立即注意到的第一件事是 HOC 可以堆叠在一起。HOC 实际上是相互组合的。这样更加灵活，并且可以保护您免受在使用 Mixins 时可能发生的名称冲突。React 开发人员提到`handleChange`函数是一个问题示例：

*"不能保证两个特定的 mixin 可以一起使用。例如，如果`FluxListenerMixin`定义了`handleChange()`，而`WindowSizeMixin`也定义了`handleChange()`，那么您不能将它们一起使用。您也不能在自己的组件上定义一个具有这个名称的方法。*

*如果您控制 mixin 代码，这并不是什么大问题。当出现冲突时，您可以在其中一个 mixin 上重命名该方法。但是，这很棘手，因为一些组件或其他 mixin 可能已经直接调用了这个方法，您需要找到并修复这些调用。"*

*- Dan Abramov 的官方 React 博客文章（[`reactjs.org/blog/2016/07/13/mixins-considered-harmful.html`](https://reactjs.org/blog/2016/07/13/mixins-considered-harmful.html)).*

此外，混入可能会导致添加更多状态。从前面的例子来看，HOCs 可能会做同样的事情，但实际上不应该。这是我在 React 生态系统中遇到的问题。它给您很大的权力，您可能没有意识到您开始使用的模式是如此一般。对我来说，有状态的组件应该很少，有状态的 HOCs 也应该很少。在本书中，我将教您如何避免使用状态对象，而是更倾向于一种更好的解决方案，尽可能地将状态与组件解耦。我们将在第五章中进一步了解这一点，*存储模式*。

# 代码检查工具和代码样式指南

在本节中，我们将看一下完全不同的一组模式，即如何构建代码的模式。多年来，已经有数十种样式的方法，一般规则是：人越多，越多种偏好的方式。

因此，设置项目的**关键点**是**选择您的样式指南**，以及您定义的一套明确的规则。这将为您节省大量时间，因为它消除了任何潜在的讨论。

在高级集成开发环境的时代，可以在几秒钟内快速重新格式化整个代码库。如果您需要允许对代码样式进行小的未来更改，这将非常方便。

# 添加代码检查工具以创建 React Native 应用

按照以下步骤配置您自己的代码检查工具：

1.  打开终端并导航到项目目录。`cd`命令用于更改目录将非常方便。

1.  列出目录中的文件，并确保您位于根目录，并且可以看到`package.json`文件。

1.  使用`yarn add`命令添加以下软件包。新添加的软件包将自动添加到`package.json`中。`--dev`将其安装在`package.json`的开发依赖项中：

```jsx
yarn add --dev eslint eslint-config-airbnb eslint-plugin-import eslint-plugin-react eslint-plugin-jsx-a11y babel-eslint
```

ESLint 是我们将使用的代码检查工具，通过运行上述命令，您将已经将其安装在项目的`node_modules`目录中。

1.  现在，我们准备为您的项目定义一个新的脚本。请编辑`package.json`，并在`scripts`部分下添加以下行：

```jsx
"scripts": {
...
 "lint": "./node_modules/eslint/bin/eslint.js src"
...
}
```

前面的命令运行 ESLint 并向其传递一个参数。这个参数是将包含要进行代码检查的文件的目录的名称。如果你不打算跟着这本书一起学习，我们使用`src`目录来存储源 JavaScript 文件。

1.  下一步是指定代码风格，更准确地说，是实现您的代码风格的代码检查器配置。在本例中，我们将使用一个众所周知的 Airbnb 样式指南。但是，我们还将对其进行调整，以符合我的首选风格。

首先，通过运行以下命令创建您的代码检查器配置：

```jsx
./node_modules/eslint/bin/eslint.js --init
```

1.  接下来将出现一个特殊提示。选择以下选项：

```jsx
How would you like to configure ESLint? Use a popular style guide
Which style guide do you want to follow? Airbnb
Do you use React? Yes
What format do you want your config file to be in? JSON
```

1.  将为您创建一个名为`.eslintrc.json`的配置文件。打开文件并添加以下规则。在下一节中，我将解释这些选择。现在，请使用给定的一组规则：

```jsx
{
  "rules": {
    "react/jsx-filename-extension": [1, { "extensions": [".js"] }],
  "comma-dangle": ["error", "never"],
    "no-use-before-define": ["error", { "variables": false }],
  "indent": ["error", 4],
  "react/jsx-indent": ["error", 4],
    "react/jsx-indent-props": ["error", 4]
  },
  "parser": "babel-eslint", // usage with babel transpiler
  "extends": "airbnb" }
```

1.  现在，您可以通过使用以下命令运行代码检查器：

```jsx
yarn run lint 
```

完整的设置在`第二章 _ 视图模式`文件夹下的`示例 14`中提供。

# Airbnb React 样式指南规则

Airbnb React 样式指南定义了数十个经过深思熟虑的规则。这是一个很好的资源，也是您下一个 React 项目的基础。我强烈建议您深入研究。您可以在[`github.com/airbnb/javascript/tree/master/react`](https://github.com/airbnb/javascript/tree/master/react)找到 Airbnb React 样式指南。

但是，每个人都应该找到自己的风格。我的风格只是从 Airbnb 中调整了一些东西。

+   `comma-dangle`：Airbnb 建议您在数组多行元素、列表或对象多行键值列表的末尾留下一个逗号。这不是我习惯的。我更喜欢 JSON 样式，它不会留下尾随逗号：

```jsx
// My preference
const hero = {
  firstName: 'Dana',
  lastName: 'Scully'
};

const heroes = [
  'Batman',
  'Superman'
];

// Airbnb style guide
const hero = {
  firstName: 'Dana',
  lastName: 'Scully',
};

const heroes = [
  'Batman',
  'Superman',
];
```

+   `react/jsx-filename-extension`：在我看来，这个规则应该在样式指南中进行更改。它试图说服您在使用 JSX 的文件中使用`.jsx`扩展名。我不同意这一点。我想引用 Dan Abramov 在这个问题上的评论：

“.js 和.jsx 文件之间的区别在 Babel 之前是有用的，但现在已经不那么有用了。

还有其他语法扩展（例如 Flow）。如果使用 Flow 的 JS 文件应该如何命名？.flow.js？那使用 Flow 的 JSX 文件呢？.flow.jsx？还有其他一些实验性语法呢？.flow.stage-1.jsx？

大多数编辑器都是可配置的，因此您可以告诉它们在.js 文件中使用 JSX 语法方案。由于 JSX（或 Flow）是 JS 的严格超集，我认为这不是问题。

- Dan Abramov：[`github.com/facebook/create-react-app/issues/87#issuecomment-234627904`](https://github.com/facebook/create-react-app/issues/87#issuecomment-234627904)。

+   `no-use-before-define`：这是一个聪明的规则。它防止您使用稍后定义的变量和函数，尽管 JavaScript 的提升机制允许您这样做。但是，我喜欢将我的 StyleSheets 放在每个组件文件的底部。因此，我放宽了这个规则，允许在定义之前使用变量。

当我将片段复制到这本书中时，我也更喜欢使用四个空格的缩进来提高清晰度。

# 修复错误

由于我们已经设置了 linter，我们可以在以前的项目中尝试它。

如果您想跟着这个例子，只需从第二章中复制`Example 9_Controlled TextInput`，*View Patterns*，并在复制的项目中设置一个 linter。之后，执行以下命令，该命令在源目录上执行您的 linter 脚本。

我在`Example 9_ Controlled TextInput`的`LoginForm.js`上尝试了它。不幸的是，它列出了一些错误：

```jsx
$ yarn run lint
yarn run v1.5.1 $ ./node_modules/eslint/bin/eslint.js src

/Users/mateuszgrzesiukiewicz/Work/reactnativebook/src/Chapter 2: View patterns/Example 14: Linter/src/LoginForm.js
2:8 error    A space is required after '{' object-curly-spacing
2:44 error    A space is required before '}' object-curly-spacing
7:27 error    'initLogin' is missing in props validation    react/prop-types
12:9 warning  Unexpected console statement                  no-console
13:9 warning  Unexpected console statement                  no-console
22:37 error    Curly braces are unnecessary here             react/jsx-curly-brace-presence
23:62 error    A space is required after '{' object-curly-spacing
23:68 error    A space is required before '}' object-curly-spacing
29:37 error    Curly braces are unnecessary here             react/jsx-curly-brace-presence
31:55 error    A space is required after '{' object-curly-spacing
31:64 error    A space is required before '}' object-curly-spacing
33:25 error    Value must be omitted for boolean attributes  react/jsx-boolean-value
49:20 error    Unexpected trailing comma                     comma-dangle

 13 problems (11 errors, 2 warnings)
10 errors, 0 warnings potentially fixable with the `--fix` option.
```

13 个问题！幸运的是，ESLint 可以尝试自动修复它们。让我们试试。执行以下操作：

```jsx
$ yarn run lint -- --fix
```

很好 - 我们将问题减少到了只有三个：

```jsx
7:27 error 'initLogin' is missing in props validation react/prop-types
12:9 warning Unexpected console statement no-console
13:9 warning Unexpected console statement no-console
```

我们可以跳过最后两个。这些警告是相关的，但控制台对于这本书来说很方便：它提供了一个打印信息的简单方法。在生产中不要使用`console.log`。然而，`'initLogin'在 props 验证 react/prop-types 中丢失`是一个有效的错误，我们需要修复它：

```jsx
LoginForm.propTypes = {
    initLogin: PropTypes.string
};
```

`LoginForm`现在已经验证了它的 props。这将修复 linter 错误。要检查这一点，请重新运行 linter。看起来我们又遇到了另一个问题！正确的链接是：

```jsx
error: propType "initLogin" is not required, but has no corresponding defaultProp declaration react/require-default-props
```

这是真的 - 如果未提供`initLogin`，我们应该定义默认的 props：

```jsx
LoginForm.defaultProps = {
    initLogin: '' };
```

从现在开始，如果我们没有明确提供`initLogin`，它将被分配一个默认值，即一个空字符串。重新运行 linter。它现在会显示一个新的错误：

```jsx
error 'prop-types' should be listed in the project's dependencies. Run 'npm i -S prop-types' to add it import/no-extraneous-dependencies
```

至少这是一个简单的问题。它正确地建议您明确维护`prop-types`依赖关系。

通过在控制台中运行以下命令添加`prop-types`依赖项：

```jsx
yarn add prop-types
```

重新运行 linter。太好了！最终，没有错误了。干得好。

# 总结

在本章中，我们学习了以后在本书中会非常有用的视图模式。现在我们知道如何编写简洁的 JSX 和类型检查组件。我们还可以组合来自 React Native 库的常见内置组件。当需要时，我们可以编写简单表单的标记并知道如何处理输入。我们比较了受控和不受控输入，并深入了解了`TextInput`的工作原理。如果出现错误，我们的错误边界将处理这个问题。

最后，我们确保了我们有一个严格的风格指南，告诉我们如何编写 React Native 代码，并且我们通过使用 ESLint 来强制执行这些规则。

在下一章中，我们将致力于为我们学到的组件进行样式设置。由此，我们的应用程序将看起来漂亮而专业。


# 第三章：样式模式

现在是为我们的应用程序添加一些外观的时候了。在本章中，我们将探索独特的样式解决方案和机制。React Native StyleSheet 可能类似于 Web 层叠样式表（CSS）；然而，原生应用程序的样式是不同的。语法上的相似之处很快就结束了，您应该花一些时间来学习样式的基础知识。在本书的后面，我们将使用一个提供现成样式的外部库。对于您来说，了解如何自己制作这样的组件至关重要，特别是如果您计划在 React Native 团队中专业工作，他们提供定制设计。

在本章中，我们将涵盖以下主题：

+   在 React Native 环境中为组件设置样式

+   处理有限的样式继承

+   使用密度无关像素

+   使用 Flexbox 定位元素

+   处理长文本问题

+   使用 Animated 库制作动画

+   使用每秒帧数（FPS）指标来测量应用程序的速度

# 技术要求

与前几章一样，我已经将每个示例分成一个独立的应用程序，您可以在手机或模拟器上启动。要做这些示例，您将需要以下内容：

+   模拟器或 Android/iOS 智能手机

+   使用 Git 拉取示例：[`github.com/Ajdija/hands-on-design-patterns-with-react-native`](https://github.com/Ajdija/hands-on-design-patterns-with-react-native)。请按照 GitHub 页面上的安装说明进行操作。

# React Native 样式的工作原理”

“React 的核心前提是 UI 只是数据投影到不同形式的数据中。相同的输入产生相同的输出。一个简单的纯函数。”

- React 库自述文件（[`github.com/reactjs/react-basic/blob/master/README.md`](https://github.com/reactjs/react-basic/blob/master/README.md)）。

您将在本书的后面学习纯函数。查看以下示例以了解基础知识：

```jsx
// Code example from React readme. Comments added for clarity.

// JavaScript pure function
// for a given input always returns the same output
function NameBox(name) {
    return { fontWeight: 'bold', labelContent: name };  }

// Example with input
'Sebastian Markbåge' ->
{ fontWeight: 'bold', labelContent: 'Sebastian Markbåge' };
```

回到更实际的例子，让我们看看在 React Native 中如何实现前提。

“使用 React Native，您不需要使用特殊的语言或语法来定义样式。您只需使用 JavaScript 为应用程序设置样式。所有核心组件都接受一个名为`style`的属性。样式名称和值通常与 Web 上的 CSS 工作方式相匹配，只是名称使用驼峰式命名，例如 backgroundColor 而不是 background-color。

样式属性可以是一个普通的 JavaScript 对象。(...) 您还可以传递一个样式数组 - 数组中的最后一个样式具有优先权，因此您可以使用它来继承样式。

随着组件复杂性的增加，通常更清晰的做法是使用 StyleSheet.create 在一个地方定义多个样式。

- React Native 官方文档([`facebook.github.io/react-native/docs/style.html`](https://facebook.github.io/react-native/docs/style.html)).

总之，我们有三种定义组件样式的方式：

+   使用样式属性并传递一个包含键值对的对象，表示样式。

+   使用样式属性并传递一个对象数组。每个对象应包含表示样式的键值对。数组中的最后一个样式具有优先权。可以使用这种机制来继承样式或像阴影函数和变量一样阴影它们。

+   使用 StyleSheet 组件及其 create 函数来创建样式。

在下面的示例中，您可以找到定义样式的三种方式：

```jsx
// src/ Chapter_3/ Example_1_three_ways_to_define_styles/ App.js

export default () => (
    <View>
 <Text style={{ color: 'green' }}>inline object green</Text>
 <Text style={styles.green}>styles.green green</Text>
 <Text style={[styles.green, styles.bigred]}>
  [styles.green, styles.bigred] // big red
        </Text>
 <Text style={[styles.bigred, styles.green]}>
  [styles.bigred, styles.green] // big green
        </Text>
 </View> );   const styles = StyleSheet.create({
    green: {
        color: 'green'
  },
  bigred: {
        color: 'red',
  fontSize: 35
  }
});
```

注意使用对象数组的用例。您可以结合先前学到的技巧来实现条件样式：

```jsx
<View>
 <Text  style={[
            styles.linkStyle,
  this.props.isActive && styles.activeLink
        ]}
    >
  Some link
    </Text> </View> 
```

另外，让我们讨论一下为什么我们使用`StyleSheet`组件而不是内联样式：

+   代码质量：

+   通过将样式从渲染函数中移出，可以使代码更容易理解。

+   给样式命名是向渲染函数中的低级组件添加含义的好方法。

+   性能：

+   将样式对象转换为样式表，可以通过 ID 引用它，而不是每次都创建一个新的样式对象。

+   它还允许您通过桥只发送样式一次。所有后续使用都将引用一个 ID（尚未实现）。

- React Native 官方文档

[`facebook.github.io/react-native/docs/stylesheet.html`](https://facebook.github.io/react-native/docs/stylesheet.html).

在质量和可重用性方面，StyleSheet 将样式和组件标记分离。甚至可以将这些样式提取到一个单独的文件中。此外，正如文档中所述，它可以使您的标记更容易理解。您可以看到一个有意义的名称，比如**`styles.activeLink`**，而不是一个庞大的样式对象。

如果您低估了应用程序中的解耦性，那么请尝试将代码基础扩展到超过 5,000 行。您可能会发现一些紧密耦合的代码需要一些技巧才能重用。不良实践会滚雪球，使代码基础非常难以维护。在后端系统中，它通常与单片结构相辅相成。拯救的惊人主意是微服务。在[`en.wikipedia.org/wiki/Microservices`](https://en.wikipedia.org/wiki/Microservices)了解更多。

# 令人惊讶的样式继承

当我们开始使用样式时，理解 React Native 样式不像网站的 CSS 是至关重要的。特别是在继承方面。

父组件的样式不会被继承，除非它是一个`Text`组件。如果是`Text`组件，它只会从父组件继承，只有父组件是另一个`Text`组件时才会继承：

```jsx
// src/ Chapter_3/ Example_2_Inheritance_of_Text_component/ App.js

export default () => (
    <View style={styles.container}>
 <Text style={styles.green}>
  some green text
            <Text style={styles.big}>
  some big green text
            </Text>
 </Text> </View> );   const styles = StyleSheet.create({
    container: {
        marginTop: 40
    },
    green: {
        color: **'green'**
  },
  big: {
        fontSize: **35**
  }
});
```

如果您运行此代码，您会看到显示的文本是绿色的，后面的部分也很大。具有大样式的`Text`从父`Text`组件继承了绿色。还请注意，整个文本都呈现在具有 40 dp 的顶部边距的`View`组件内，这是密度无关像素。跳转到*学习无单位尺寸*部分以了解更多。

# 有限继承的解决方法

想象一种情况，您希望在整个应用程序中重用相同的字体。鉴于前面提到的继承限制，您将如何做到这一点？

解决方案是我们已经学到的一个机制：组件组合。让我们创建一个满足我们要求的组件：

```jsx
// src/ Chapter_3/ Example_3/ src/ AppText.js

const AppText = ({ children, ...props }) => (
    <Text style={styles.appText} {...props}>
  {children}
    </Text> );  // ... propTypes and defaultProps omitted for clarity   const styles = StyleSheet.create({
    appText: {
        fontFamily: **'Verdana'**
  }
});   export default AppText;
```

`AppText`组件只是包装了`Text`组件并指定了它的样式。在这个简单的例子中，它只是`fontFamily`。

请注意，`style`对象中的`fontFamily`键接受字符串值，并且在平台之间可能不同（在 Android 上接受一些，在 iOS 上接受一些）。为了保持一致性，您可能需要使用自定义字体。设置相当简单，但需要一些时间，因此超出了本书的设计模式主题。要了解更多，请访问[`docs.expo.io/versions/latest/guides/using-custom-fonts`](https://docs.expo.io/versions/latest/guides/using-custom-fonts)。

考虑如何编辑`AppText`以支持自定义样式，以便可以覆盖指定的键。

在这种情况下，样式对象覆盖是最好的解决方案吗？也许不是；您创建此组件是为了统一样式，而不是允许覆盖。但是，您可能会说需要创建另一个组件，比如`HeaderText`或类似的东西。您需要一种重用现有样式并仍然放大文本的方法。幸运的是，您仍然可以在这里使用`Text`继承：

```jsx
// src / Chapter 3 / Example 3 / App.js
export default () => (
    <View style={styles.container}>
 **<AppText>**  some text, Verdana font
            <Text style={styles.big}**>**
  some big text, Verdana font
            </Text>  **</AppText>** <Text style={styles.big}>
  some normal big text
        </Text>
 </View> );
```

因此，`HeaderText`将非常容易实现。请查看以下代码：

```jsx
// src / Chapter 3 / Example 3 / src / HeaderText.js
const HeaderText = ({ children, ...props }) => (
    <**AppText**>
 <Text style={styles.headerText} {...props}>
  {children}
        </Text>
 </**AppText**> );
// ...
const styles = StyleSheet.create({
    headerText: {
        fontSize: 30
  }
});
```

# 学习无单位的尺寸。

在这一部分，我们将学习 React Native 应用程序在屏幕上的尺寸。

"设置组件尺寸的最简单方法是在样式中添加固定的宽度和高度。在 React Native 中，所有尺寸都是无单位的，表示密度无关的像素。"

- React Native 官方文档

[`facebook.github.io/react-native/docs/height-and-width.html`](https://facebook.github.io/react-native/docs/height-and-width.html)。

与 CSS 不同，对于样式属性如`margin`、`bottom`、`top`、`left`、`right`、`height`和`width`，您必须以 dp 或百分比提供值。

文档到此结束。但是在处理屏幕时，您还需要了解以下关键字：

+   **像素**：这些是屏幕上可以控制的最小单元。每个像素通常由三个子像素组成：红色、绿色和蓝色。这些颜色通常被称为 RGB。

+   **尺寸**：这是屏幕或窗口的宽度和高度。

+   **分辨率**：这是每个维度上可以显示的像素数。

+   **DPI**/**PPI**：这是每英寸可以放置的点/像素数。

+   **点数**：这是 iOS 上的一个抽象度量。

+   **密度无关的像素**：这是 Android 上的一个抽象度量。

如果您想检查这些概念在 Java 中是如何实现的，请查看：

[`github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/uimanager/LayoutShadowNode.java`](https://github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/uimanager/LayoutShadowNode.java)。

为了计算这些值，我们将需要`width`、`height`和`scale`。您可以从`Dimensions`对象中获取这些信息：

```jsx
// src/ Chapter 3/ Example 4/ App.js

export default () => {
    const { height, width } = Dimensions.get('window');
  return (
        <View style={{ marginTop: 40 }}>
 <Text>Width: {width}, Height: {height}</Text>
 <View  style={{
                    width: width / 4,
  height: height / 3**,**
  backgroundColor: 'steelblue'
  }}
            />
 <View style={styles.powderblue} />
 </View>  ); };   const styles = StyleSheet.create({
    powderBlueBox: {
        width: Dimensions.get('window').width / 2,
  height: Dimensions.get('window').height / 5,
  backgroundColor: 'powderblue'
  }
});
```

然而，这段代码有问题。你能看出来为什么吗？如果你旋转设备，它就不会更新。

如果尺寸发生变化，我们需要强制重新渲染。我们可以通过注册自己的监听器使用`Dimensions.addEventListener`来检测尺寸变化。然后我们需要在这个监听器中强制重新渲染。通常人们使用`state`来这样做。React 检查`state`的变化并在发生变化时重新渲染：

```jsx
// src/ Chapter_3/ Example_5_Listening_on_dimensions_change/ App.js

export default class LogDimensionChanges extends React.Component {
    state = { window: Dimensions.get('window') };
  componentWillMount() {
        // This lifecycle hook runs before component
        // is render for the first time
        Dimensions.addEventListener('change', this.handler)**;**
  }
    componentWillUnmount() {
        // This lifecycle hook runs after unmount
        // that is when component is removed
        // It is important to remove listener to prevent memory leaks
  Dimensions.removeEventListener('change', this.handler)**;**
  }
    handler = dims => this.setState(dims);    render() {
        const { width, height } = this.state.window**;**
  return (
            ...  <View  style={{
                        width: width / 4,
  height: height / 3,
  backgroundColor: 'steelblue'
  }}
                />
 <View style={styles.powderBlueBox} />
 ...  );
  }
}

const styles = StyleSheet.create({
    powderBlueBox: {
        width: Dimensions.get('window').width / 2,
  height: Dimensions.get('window').height / 5,
  backgroundColor: 'powderblue'
  }
});
```

在结果中，我们有一个适应尺寸变化的工作`View`。这是通过使用我们使用 React 生命周期方法(`componentWillMount`和`componentWillUnmount`)注册的自定义事件监听器完成的。然而，另一个使用`StyleSheet`的`View`没有适应。它无法访问`this.state`。StyleSheet 通常是静态的，以提供优化，例如只通过桥一次发送样式到本机。

如果我们仍然希望我们的`StyleSheet`样式适应？我们可以做以下之一：

+   放弃 StyleSheet 并创建一个返回表示样式的对象的自定义函数，并将它们作为内联样式传递。如果这是目标，它将提供类似的解耦：

```jsx
dynamicStyles(newWidth, newHeight) {
    return {
        // calculate styles using passed newWidth, newHeight
    }
}
...
render = () => (
<View
    style={
        this.dynamicStyles(this.state.window.width, this.state.window.height)
    }
>
...
</View>
)
```

+   使用`styles`来覆盖标记中的语法：

```jsx
<View
  style={[
        styles.powderBlueBox,
  {
            width: this.state.window.width / 2,
  height: this.state.window.height / 5 }
    ]}
/>
```

+   使用`StyleSheet.flatten`来覆盖标记外的`styles`：

```jsx
const powderBlueBox = StyleSheet.flatten([
    styles.powderBlueBox, {
        width: this.state.window.width / 4,
  height: this.state.window.height / 5
  }
]);   return (
    ...  <View style={powderBlueBox} />
 ... );
```

与内联样式一样，要注意性能影响。当涉及到样式缓存时，你将失去优化。很可能，在每次重新渲染时，`styles`将被重新计算并再次通过桥发送。

# 绝对和相对定位

这一部分是关于定位事物的基础知识。在 React Native 中，默认情况下一切都是`relative`的。这意味着如果我把`View`嵌套到另一个具有`marginTop: 40`的`View`中，这个定位也会影响我的嵌套`View`。

在 React Native 中，我们也可以将定位改为`absolute`。然后位置将根据父级的固定像素数计算。在 StyleSheet 中使用`top`/`bottom` *+* `left`/`right`键。记住，其他视图不会考虑这个位置。如果你想让视图重叠，这很方便：

三个框重叠在一起，因为它们是绝对定位的。

查看以下代码，以查看前面三个重叠框的示例：

```jsx
// src/ Chapter 3/ Example_6/ App.js

export default () => (
    <View>
 <View style={[styles.box]}>
 <Text style={styles.text}>B1</Text>
 </View> <View style={[styles.box, {
            left: 80,
  top: 80**,**
  backgroundColor: 'steelblue'
  }]}
        >
 <Text style={styles.text}>B2</Text>
 </View> <View style={[styles.box, {
            left: 120,
  top: 120**,**
  backgroundColor: 'powderblue'
  }]}
        >
 <Text style={styles.text}>B3</Text>
 </View> </View> );   const styles = StyleSheet.create({
    box: {
        position: 'absolute'**,**
  top: 40,
  left: 40**,**
  width: 100,
  height: 100,
  backgroundColor: 'red'
  },
  text: {
        color: '#ffffff',
  fontSize: 80
  }
});
```

组件根据它们在标记中的顺序进行渲染，所以`B3`覆盖`B2`，`B2`覆盖`B1`。

如果需要将一些组件放在顶部，请使用`zIndex`属性。

查看文档以获取更详细的解释：[`facebook.github.io/react-native/docs/layout-props.html#zindex`](https://facebook.github.io/react-native/docs/layout-props.html#zindex)。

由于我们有三个`absolute`盒子，让我们看看如果将`B2`更改为`relative`会发生什么：

```jsx
<View style={[styles.box, {
    position: 'relative'**,**
  backgroundColor: 'steelblue' }]}
>
 <Text style={styles.text}>B2</Text> </View>
```

突然**B1**消失了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d073afbb-0f85-40f7-990d-b2394d3c2f8f.png)

**B2**盒子现在相对于其父`View`。因此，其位置从父位置的左上角开始（因为我们没有填充或边距）。**B1**和**B2**盒子大小相同；**B2**覆盖了**B1**的所有内容。如果我们使用`{ width: 50, height: 50 }`稍微缩小**B2**，我们将看到**B1**在下面。我还将**B2**的文本字体大小更改为`40`以便清晰。查看`src/Chapter 3/Example 7`目录中的`App.js`。结果如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/7729cda8-eecf-455d-884f-8711d1fc1f63.png)

现在我们已经了解了绝对定位和相对定位，是时候学习一个称为 Flexbox 的伟大模式了。

# 使用弹性盒模型

这是我在样式方面学到的最伟大的模式之一。**弹性盒模型**（**Flexbox**）可以使您的盒子变得灵活。

让我们看一个小例子。目标是将您的盒子拉伸以填满屏幕的整个宽度：

```jsx
// src/ Chapter_3/ Example_8/ App.js
export default () => (
    <View style={{ flex: 1 }}>
 <View  style={{ backgroundColor: 'powderblue', height: 50 }}
        />
 </View> );
```

以下是前述代码的结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/3c8780b5-14c9-448a-911a-647f47b0b498.png)由于我们使用了 flex: 1 样式，框延伸到整个屏幕宽度

这并不太花哨，但您不需要使用`Dimensions`。显然这只是一个开始。

您已经知道默认情况下视图是相对于彼此的，因此如果要制作一些条纹，只需将三个`div`堆叠在一起即可：

```jsx
// src/ Chapter_3/ Example_8/ App.js

export default () => (
    <View style={{ flex: 1 }}>
 <**View**  style={{ backgroundColor: 'powderblue', height: 50 }}
        />
 <**View**  style={{ backgroundColor: 'skyblue', height: 50 }}
        />
 <**View**  style={{ backgroundColor: 'steelblue', height: 50 }}
        />
 </View> );  
```

查看以下屏幕截图，看到三个盒子横跨整个屏幕的宽度：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/a80a3717-b9cf-425a-b20f-46789faa7d71.png)三个盒子依次排列，每个盒子都使用从父 View 组件继承的 flex: 1 进行拉伸

现在，让我们使用这个相当简单的概念来创建头部、主要内容和页脚组件。为了实现这一点，让我们拉伸中间的`View`：

```jsx
<View
  style={{ backgroundColor: 'skyblue', flex: 1 }}
/>
```

现在中间的`View`延伸以填充所有可用空间，为头部`View`留下 50 dp，为页脚`View`留下另外 50 dp。

现在是时候向我们分割的屏幕添加一些有用的内容了。

在接下来的章节中，我将尝试使用示例来解释 Flexbox。但请也查看 Flexbox Froggy 游戏，以了解不同情景下的 flexbox。它提供了一个交互式编辑器，你的目标是将青蛙移动到相应的叶子上[`github.com/thomaspark/flexboxfroggy/`](https://github.com/thomaspark/flexboxfroggy/)。

# 使用 Flexbox 定位项目

第一个重要的关键是`flexDirection`。我们可以将其设置为`row`，`row-reverse`，`column`或`column-reverse`。Flex 方向使内容沿着该方向流动。在 React Native 中，默认情况下，flex 方向设置为`column`。这就是为什么在前面的示例中，框以列的形式显示的原因。

让我们使用`flexDirection`在页脚中显示三个小部分：`主页`，`搜索`和`关于`：

```jsx
// src / Chapter 3 / Example 9 / App.js
...
<View
  style={{
        backgroundColor: 'steelblue',
  height: 70,
  flexDirection: **'row'**
  }}
>
 <View><Text style={{ fontSize: 40 }}>Home</Text></View>
 <View><Text style={{ fontSize: 40 }}>Search</Text></View>
 <View><Text style={{ fontSize: 40 }}>About</Text></View> </View>
...
```

好的，现在我们的页脚中有三个单独的文本。我们将学习如何在第七章中切换屏幕的方法，*导航模式*。

我们的页脚看起来几乎没问题：

三个单独的页脚文本

现在是学习如何在 x 轴上均匀分布视图的时候了。如果`flexDirection`设置为`row`或`row-reverse`，我们可以使用`justifyContent`。`justifyContent`接受`flex-start`，`flex-end`，`center`，`space-between`，`space-around`和`space-evenly`值。我们稍后会使用它们。现在，让我们使用`space-between`。它将拉伸`主页`视图，`搜索`视图和`关于`视图，以在它们之间留下均匀的空间：

```jsx
...
    style={{
        backgroundColor: 'steelblue',
  height: 70,
  justifyContent: 'space-between'**,**
  flexDirection: **'row'**
  }}
...
```

结果如下：

页脚中的三个文本现在用均匀的空格分隔开来

虽然与 flexbox 无关，但我们可以添加一些填充使其更美观：

```jsx
paddingLeft: 10, paddingRight: 10
```

这样文本更容易阅读：

右边和左边的填充从屏幕边缘添加空间

如果我们还想垂直定位怎么办？有一个叫做`alignItems`的关键。它接受`flex-start`，`flex-end`，`center`，`stretch`和`baseline`值。

现在让我们把页脚的高度提高：100 个密度无关像素。此外，我们希望文本在垂直方向上居中：

```jsx
// src / Chapter 3 / Example 10 / App.js
...
    style={{
        backgroundColor: 'steelblue',
  height: 100,
  alignItems: 'center'**,**
  justifyContent: 'space-between',
  flexDirection: 'row',
  paddingLeft: 10,
  paddingRight: 10
  }}
...
```

查看结果：

页脚中的文本现在垂直居中

# 样式化 flex 项

当我们构建应用程序时，您可能很快意识到样式有点丑陋。调色板是一个完全的灾难。除非您是设计师，我建议您搜索调色板生成器。我已经将颜色更改为更可接受的：白色，黑色和蓝色。

此外，我已经添加了边距和填充。标题和内容之间通过边框很好地分隔开来。让我们看看在 iPhone 8 和 iPhone X 上的效果如何：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/1261aefe-5759-4bea-859d-13c5edeef2da.png)

在颜色更改后，iPhone 8 和 iPhone X 模拟器上的完整应用程序外观

有些人可能不了解样式的基础知识，所以让我们快速解释一下边距和填充是什么。**边距**用于在元素周围创建空间。这个空间是从元素的边框创建的。如果您只想在某个地方应用空间，您可以选择顶部、底部、左侧或右侧。**填充**非常类似，但它不是在外部创建空间，而是在内部创建空间。空间是从边框内部创建的。查看元素检查器以直观地理解这一点。我已经检查了我们应用程序的标题，以了解样式是如何工作的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/93cf522c-04ba-4849-a804-9a41a4a5aed1.png)

Header box 的边距和填充

在上一张截图中，填充用绿色标记，边距用橙色标记。组件空间是浅蓝色的。有关样式中指定的确切值，请查看图像的右侧部分。

要打开元素检查器，请摇动您的设备，当菜单打开时，选择切换元素检查器。如果您正在使用模拟器，您可以通过从模拟器菜单中选择硬件/摇动手势来模拟摇动。

以下是我用来创建`header`的样式：

```jsx
header: {
    height: 45,
  borderBottomColor: '#000000',
  borderBottomWidth: 1,
  paddingLeft: 10,
  paddingRight: 10,
  marginBottom: 10 },
// All the other styles are available in
// src/ Chapter_3/ Example_11/ App.js
```

接下来，让我们使页脚更具重复使用性。如果在某个时候，我们不需要“关于”链接，而是需要“通知”链接呢？这个词真的很长。它不适合我们的设计。虽然现在是一个问题，但如果我们计划添加翻译，我们也会在那里遇到这个问题。

大多数应用程序使用图标来解决这些问题。让我们试试：

1.  安装图标包：

```jsx
yarn add @expo/vector-icons
```

1.  更改页脚标记：

```jsx
// src/ Chapter_3/ Example_11/ App.js
<View style={styles.footer}>
 <Ionicons name="md-home" size={32} color="white" />
 <Ionicons name="md-search" size={32} color="white" />
 <Ionicons name="md-notifications" size={32} color="white" /> </View> 
```

新增的图标可以在以下截图中观察到：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/10ec45dc-f0a2-4521-b2ac-7d8d8c4fd203.png)应用程序的页脚现在由图标组成

页脚现在是可重复使用的，并支持任何语言。如果您支持他们的语言，请检查其他国家的图标含义。

# 样式内容

我们已经使用方向行定位了页脚。现在是定位主要内容和列的时候了。在之前的章节中，我们创建了一个任务列表。现在是将其与我们的设计整合的时候了。

将`TaskList`组件添加到内容框中。我还添加了`ScrollView`组件，以便在任务占用太多空间无法全部显示时使内容可滚动：

```jsx
import data from './tasks.json';

// ... header
<**ScrollView** style={styles.content}>
 <**TaskList** tasks={data.tasks} /> </**ScrollView**>
// ... footer
```

我的任务模拟在 JSON 文件中呈现如下。在本书的后面，我们将学习如何从后端服务器获取任务以及如何将这样的逻辑与标记分离：

```jsx
{
  "tasks": [
    {
      "name": "Task 1",
  "description": "Task 1 description...",
  "likes": 239
  },
 //... more comma separated tasks here
  ]
}
```

有了模拟，我们可以实现`TaskList`视图：

```jsx
const TaskList = ({ tasks }) => (
    <View>
  {tasks.map(task => (
            <View key={task.name}>
 <Text>{task.name}</Text>
 <Text>{task.description}</Text>
 <LikeCounter likes={task.likes} />
 </View>  ))}
    </View> );
// separate component for each task is not created for book clarity 
```

`LikeCounter`是从`Chapter 2 / Example 8 / src`复制并调整以接受点赞作为 props（替换默认的零）。请注意，它也使用了 Flexbox，并且`flexDirection`设置为行。

现在，我们准备样式内容。这是我们的起点：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/ecb8b650-3477-4530-9dd7-5a4ed34dbc87.png)

iPhone 8 和 iPhone X 模拟器的当前外观

我们想重新组织每个任务的内容。**点赞**和**取消点赞**小部件应该显示在任务的右侧，并且应该使用图标。任务名称应该比描述稍大，并且应该适合任务宽度的 70%。右侧的点赞/取消点赞小部件应该用细灰色边框分隔。边框也应该分隔任务。在必要的地方添加漂亮的填充和边距：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/48d8384f-5440-4237-90ff-5a8ecb6ff8cb.png)

iPhone 8 和 iPhone X 模拟器的期望外观

好的，我们如何开始？我们需要将事情分解成可以分别实现的小块。创建以下内容：

+   具有任务容器样式和顶部边框样式的任务`View`。

+   两个内部`Views` - 一个用于名称和描述，另一个用于点赞计数器。这些应该以行的形式显示。

+   名称和描述`View`内应该有两个`Views`：一个用于名称，一个用于描述。添加样式使名称的`fontSize`更大。

+   点赞计数器`View`容器应该在左边定义边框。容器内应该有两个`Views`：一个用于点赞数量，另一个用于点赞/取消点赞图标。这些`Views`应该使用列作为默认方向。

+   具有点赞/取消点赞图标的`View`应该具有行方向的 flexbox 样式。

有了这个，使用`alignItems`和`justifyContent`来垂直或水平定位元素。请从检查器中查看辅助图像：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d696a937-dffb-4a83-9bea-c81bc6f1374f.png)

已实现组件的检查器视图。作为实现的提示。

橙色高亮表示`View`边距，绿色高亮表示`View`填充。

尝试自己实现这个。完整的解决方案可以在`src/ Chapter_3/ Example_12/ src/`文件夹中的`App.js`、`TaskList.js`和`LikeCounter.js`文件中找到。

# 解决文本溢出问题

最常见的问题之一是文本溢出。解决这个问题最简单的方法是换行，但有时不可能。例如：

+   按钮文本

+   需要显示的大数字（例如，点赞数）

+   不应该被分解的长单词

问题是：我们如何解决这个问题？有很多解决方案。让我们看看其中一些。

# 缩小字体

这在 iOS 上是可能的。

```jsx
<Text
  style={styles.text}
    numberOfLines={1}
    **adjustsFontSizeToFit** >
  {this.state.likeCount}
</Text>
```

但是，在我们的情况下，结果是完全灾难性的。即使我们在这个缩放解决方案上付出了一些工作，布局仍然感觉非常不一致：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d8571279-3fa0-4228-9325-f04d21172d7b.png)使用 iOS 的 adjustsFontSizeToFit 属性进行自动字体调整正如本书前面所示，您可以使用`Dimensions`而不是依赖`adjustsFontSizeToFit`。基于`Dimensions`，您可以创建一个缩放函数来计算`fontSize`。

# 截断文本

另一种方法被称为**截断**。根据文本长度，您可以在某个位置截断它，并用三个点`...`代替。然而，这种方法对我们的用例不好。我们处理的是点赞数，我们想知道数字是多少：

```jsx
<Text style={styles.text}>
  {
        this.state.likeCount.toString().length > 4
  ? `${this.state.likeCount.toString().substring(0, 4)}**...`**
  : this.state.likeCount
  }
</Text>
```

观察以下截断的点赞数：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/3e3f886e-8f39-412c-b1df-7164ab0c92da.png)

截断的数字是没有意义的，这个解决方案只适用于文本

# 使用千位分隔符社交媒体表示法

您知道 kilo 表示 1,000。社交媒体设计师将这个想法推广到了网络和移动设备。每当一个数字大于 1,000 时，他们用 K 替换最后的 3 位数字。例如 20K 表示 20,000。

微不足道的实现：

```jsx
const likes = this.state.likeCount.toString();
...
<Text style={styles.text}>
  {
        likes.length > 3
  ? `${likes.substring(0, likes.length - 3)}**K`**
  : likes   }
</Text>
```

然而，一个数字如*9,876,543,210*将再次溢出。但 9,876,543K 仍然太长。让我们用一个简单的递归函数来解决这个问题：

```jsx
// src / Chapter 3 / Example 12 / src / LikeCounter.js

kiloText = (nr, nrK = 0) => (nr.length > 3
  ? this.kiloText(nr.substring(0, nr.length - 3), nrK + 1)
    : nr + Array(nrK).fill('K').join(''))
```

该算法的工作原理如下：

该函数接受一个字符串格式的数字和一个可选参数，指示原始数字已经剥离了多少千。

它检查是否可以再减去一千，如果可以，就返回自身的结果，其中数字减去三个数字，千位数增加一。

如果数字长度小于四，计算文本：取数字并附加相应数量的 K 作为后缀。我们使用一个巧妙的技巧来计算 K：创建一个大小等于 K 数量的数组，用 K 字符串填充每个元素，并将所有元素连接成一个长字符串。现在 JSX 简单多了：

```jsx
<Text style={styles.text}>
  {this.kiloText(likes)}
</Text> 
```

检查结果如下。长数字现在使用千位符号显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/548a9826-d600-4b6b-87c7-67037f2b3ef0.png)

现在使用千（K）符号显示大的点赞数

可以肯定地说，点赞数不会超过 9,000,000,000。如果需要支持更大的数字，请尝试使用**M**或**B**字母。

# React Native 动画

当我们构建应用程序时，我们需要关注**用户体验**（**UX**）。其中一部分是使我们的屏幕更加生动并提供对操作的即时反馈的动画。如果你自己玩过我们的应用程序，你会发现当你点击喜欢/不喜欢图标时，它会有一个小闪烁效果。这种效果是由`TouchableOpacity`自带的。现在是时候学习如何在我们自己的应用程序中实现这样的功能了。

# 什么是动画？

当我第一次阅读 Animated 库的文档时，我吓了一跳。有很多新词汇需要你适应。与其直接深入其中，不如先了解动画到底是什么。

动画是组件样式随时间的变化。

记住：你需要一个样式属性，它的起始值和结束值。动画是当这个值随着时间从起始值到结束值时所看到的。你可以组合许多属性，可能同时对许多组件进行动画处理。

存储随时间变化的变量的常见和推荐方法是组件状态。React Native Animated 提供了一个特殊的类，以非常高效的方式实现了这个功能：`Animated.Value`。例如：

```jsx
state = {
    fadeIn: new Animated.Value(0)
}
```

# 随时间改变属性

在 React Native 中，有三种主要的创建动画的方式：

+   `Animated.timing()`: 以毫秒为单位的时间和期望的结束值，并将它们映射到你的`Animated.Value`。

+   `Animated.decay()`: 从初始速度开始，然后慢慢衰减。

+   `Animated.spring()`: 提供了一个简单的弹簧物理模型。

让我们看看它是如何运作的。我们的目标是在应用程序启动时淡入应用程序。为了实现淡入效果，我们将从 0 到 1 操纵不透明度。动画应该持续两秒：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/84ff6dee-ace8-495a-becb-45211ddbcf78.png)

显示随时间推移不透明度动画进度的图像序列

`Animated.timing`需要两个参数：要操作的变量和配置对象。在配置对象中，您需要指定`toValue`键，以告诉函数在毫秒的持续时间后您的变量应该是什么结束值 - 在我们的情况下是 2,000。我选择了两秒只是为了让动画更容易看到。随意尝试：

```jsx
// src/ Chapter_3/ Example_13/ src/ App.js
class App extends React.Component {
    state = {
        fadeIn: new Animated.Value(0)
    }

    componentDidMount() {
        this.fadeInApp();
  }

    fadeInApp() {
        Animated.timing(
 this.state.fadeIn,
  {
 toValue: 1,
  duration: 2000,
  easing: Easing.linear
  }
 ).start()**;**
  }

    render = () => (
        <**Animated.View**
  style={[
                styles.appContainer,
  { opacity: this.state.fadeIn }
            ]}
        >
 ... // rest of render removed for clarity  </**Animated.View**>  )
}
```

我们还引入了一个新组件：`Animated.View`。它使我们通常的`View`组件支持动画。

React Native Animated 提供了可动画化的组件：`Animated.Image`、`Animated.ScrollView`、`Animated.Text`和`Animated.View`，但您也可以使用`createAnimatedComponent()`函数定义自己的组件。

此外，在配置对象中，我们指定了**easing**。缓动是动画应该如何进行的方式。如果它应该随时间线性改变值，那么使用`Easing.linear`。然而线性并不自然。查看下一节以了解更多关于缓动函数的信息。

学习动画需要时间。您可以创建无数不同的场景，应该自己尝试 API。特别是当涉及到`Animated.decay`和`Animated.spring`时。我在书中没有涵盖它们，因为它不是一个非常大的模式，它只是您需要学习的另一个 API。在接下来的章节中，我们将专注于如何链接动画，然后如何使它们性能良好。

想想如何使用`Animated.decay`创建一个可拖动的框。您还需要一个`PanResponder`组件。在触摸事件释放时，它应该保持在相同方向上的速度，并在飞行一段距离后慢慢停止。

第二个练习可能是实现一个带有按钮的红色正方形框。在按下按钮时，正方形框应该通过另外 15 个独立像素来扩展其宽度和高度。所有这些都应该通过弹簧动画完成，因此宽度应该略微超过 15，然后再回到 15。就像弹簧一样。

如果这两个练习听起来很困难，请继续下一节。一旦您了解了缓动函数，它们应该会变得更容易。

# 缓动函数

动画是随时间的变化。这种变化可以以多种方式应用。确定随时间变化的新值的函数称为缓动函数。

为什么我们使用缓动函数而不是线性缓动？我喜欢的常见例子是抽屉的打开。当您在现实世界中打开抽屉时，这是一个线性过程吗？也许不是。

现在让我们看看常见的缓动函数。有几种。选择适合您应用程序的那个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/9a122705-48ef-44c2-ae7e-58b8c1162eb6.png)许多不同的缓动函数，以及每个函数随时间变化的可视化。

在图表上，灰色线表示起始值和结束值。黑线表示值随时间的变化。最终，黑线达到了上方的灰色线。正如您所见，一些缓动函数会低于起始值或超过结束值。这些可能对突出重要操作很有用。

想看更多缓动函数？查看[`easings.net/`](http://easings.net/)。

大多数这些函数可以使用 RN Easing 模块实现。

回到 React Native 缓动。我为您准备了一个应用程序，让您玩转缓动函数。您可以在`src/ Chapter_3/ Example_14/ App.js`找到源代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/327c9d13-9568-4c15-8e64-778eb6f807af.png)缓动函数游乐场应用

当您点击按钮时，您将看到一个框从左到右移动，使用相应的缓动函数。

至于动画，我是通过操纵框的`marginLeft`来实现的。动画从`marginLeft`设置为 20 开始，并应用缓动函数在 2 秒内达到 300：

```jsx
// src/ Chapter_3/ Example_14/ App.js
// ...
animate(easing) {
    this.easeValue.setValue(20);
  Animated.timing(
        this.easeValue,
  {
            toValue: 300,
  duration: 2000,
  easing
        }
    ).start(); }

onPress = easingName => this.animate(Easing[easingName.toLowerCase()]);
// ... 
```

# 调度事件

现在我们知道如何创建动画，现在让我们谈谈如何安排它们。

最简单的方法是延迟动画调度：

+   `Animated.delay()`: 在给定的延迟后开始动画。如果您需要延迟对用户操作的响应，这很有用。但通常情况下并不需要。

让我们谈谈我们想要安排的事件数组。应该分派多个事件。如果我们需要所有事件同时发生，这也很简单：

+   `Animated.parallel()`: 同时开始多个动画。但如果我们需要按顺序进行呢？这就是序列的用处。

+   `Animated.sequence()`: 按顺序开始动画，等待每个动画完成后再开始下一个。还有一个并行的变体，称为 stagger。

+   `Animated.stagger()`: 按顺序和并行启动动画，但具有连续的延迟。

练习时间：用彩色框填满屏幕。行应该以交错的方式一个接一个地出现在屏幕上：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/91d74030-2f9b-485b-8548-65dd4c1049a9.png)

显示随时间变化的交错动画的图像

完整的实现可在`src/ Chapter_3/ Example_15/ App.js`中找到。让我们看一下关键片段：

```jsx
// ...
getFadeInAnimation = animatedVal =>
    Animated.timing(animatedVal, { toValue: 1, duration: 5000 });   componentDidMount() {
    const animations = Boxes.map(box =>
        this.getFadeInAnimation(this.state[box]));
  Animated.stagger(10, animations).start(); }
// ...
```

第一个函数只是一个辅助函数。它生成一个定时动画。我们使用这个辅助函数来生成所有的动画，并将它们收集在`animations`变量中。辅助函数期望`animatedVal`，它将被缓慢到 1。在我的实现中，我为每个框创建了一个单独的`Animated.Value`。最后，我将生成的动画数组传递给`stagger`并立即开始。

很不错的动画，对吧？现在，让我们谈谈性能。

# 测量 FPS

网站和移动应用程序很少使用动画。大多数情况下，这是对用户行为的响应，往往是缓慢的。如果您曾经玩过动态电脑游戏，您可能还记得这是一个不同的世界。是的，当我们深入研究动画时，有一件事来自电脑游戏，您应该记住：**FPS**。

每秒帧数 - 屏幕上的所有内容都以光学幻觉的形式出现在运动中，这是由于以一致的速度快速更改帧而创建的。60 FPS 意味着每秒 60 帧，这意味着您每 16.67 毫秒看到一个新帧。JavaScript 需要在这么短的时间内传递该帧，否则帧将被丢弃。如果是这样，您的 FPS 指标将低于 60。

React Native 以其在大多数应用程序中的惊人性能而闻名：**60 FPS**。但是，当我们开始使用大量动画时，我们很快就会降低性能。在本节中，我想向您展示如何测量应用程序的 FPS。

让我们检查一下我们之前的动画表现如何：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/66b4e2d1-ae1f-4a0e-8d09-a64d1542b067.png)

显示随时间变化的交错动画的图像

我们将测量这个动画。在模拟器上，我得到**48** FPS，动画已经进行了一半。接近完成时，FPS 降至**18**。当所有动画完成时，FPS 恢复到正常的 60。我还在我的真实手机（iPhone 7 plus）上进行了检查，结果类似。

这只是开发环境中 FPS 下降的一个例子。然而，您应该在真实的生产版本中测试您的应用程序。在[`facebook.github.io/react-native/docs/performance.html`](https://facebook.github.io/react-native/docs/performance.html)了解更多。

# 如何测量 FPS

现在是时候学习如何检查 FPS 了。有两种主要方法：

+   使用工具，比如 Perf Monitor。它提供了这个功能。它还允许您测量本机环境。

+   编写自定义 JavaScript 代码来测量 FPS。这只会测量 JS 线程的性能。

使用*Create React Native* App 的性能监视器就像摇动您的设备并选择“显示 Perf Monitor”选项一样简单：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/e7dc8e56-7e84-4300-bd30-6c66f82cdb95.png)显示性能监视器。数字 60 和 45 代表 FPS 测量的最新值

在 JavaScript 中实现自己的解决方案应该依赖于所需的 60FPS 意味着每 16.67ms（1000ms/60）有一帧。我为您创建了一个简单的示例：

```jsx
// src / Chapter 3 / Example 16 / App.js
constructor() {
    // ...   let FPScounter = 0;
 setInterval(() => FPScounter++, 16)**;**
  setInterval(() => {
        this.setState({ fps: FPScounter });
  FPScounter = 0;
  }, 1000); }  // ... render = () => (
    // ...  <Text>FPS: {this.state.fps}</Text>
 // ...  );
// makes sure these measures are only done in dev environment
// and never leak to the production app!
// Beware: This example is not really very accurate and performant
// I have made it to illustrate the idea
```

由于本书致力于教授设计模式，我希望您也能检查您的解决方案是否具有高性能。

# 总结

在本章中，您学会了如何为 React Native 应用程序设置样式。我们介绍了许多不同的元素定位方式，您还学会了我们的设计如何在真实设备上呈现。最后，我们制作了一些动画，并根据 FPS 进行了测量。

到目前为止，我们知道如何使用 React 组件创建可重用的代码，以及如何对它们进行样式设置。我们使用本地 JSON 文件中存储的有限数据进行了工作。现在是时候让我们的应用程序变得更加复杂，并讨论影响大型应用程序的不同场景。在下一章中，您将学习 Flux，这是一种架构模式。
