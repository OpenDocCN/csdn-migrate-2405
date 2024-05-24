# React 挂钩学习手册（六）

> 原文：[`zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667`](https://zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：评估

# 问题的答案

在这里，我们回答每章末尾提出的所有问题。您可以使用这些问题来回顾您在整本书中学到的知识。

# 第一章：介绍 React 和 React Hooks

1.  React 的三个基本原则是什么？

+   **声明性的：** 我们告诉 React 我们想要什么，而不是告诉 React 如何做事。因此，我们可以轻松设计我们的应用程序，当数据发生变化时，React 将高效地更新和渲染恰当的组件。

+   **基于组件的：** React 封装了管理自己状态和视图的组件，然后允许我们组合它们以创建复杂的用户界面。

+   **学一次，随处编写：** React 不对您的技术堆栈做出假设，并努力确保您可以尽可能少地重写现有代码来开发。

1.  React 中有哪两种类型的组件？

+   **函数组件：** 接受 props 作为参数并返回用户界面的 JavaScript 函数（通常通过 JSX）

+   **类组件：** 提供`render`方法的 JavaScript 类，该方法返回用户界面（通常通过 JSX）

1.  在 React 中类组件有哪些问题？

+   JavaScript 类对开发人员来说也很难理解：`this`上下文可能令人困惑，有时我们不得不同时在多个地方编写代码。

+   它们对机器也很难理解：很难说哪些方法会被调用，因此性能优化实际上并不可行。

+   +   它们不是声明性的，因此违反了 React 的基本原则：要使用 React 功能，我们必须编写代码告诉 React 要做什么，而不是如何做。

1.  在 React 中使用高阶组件的问题是什么？

+   使用高阶组件会向我们的视图树引入实际上在视图结构方面并不重要的组件。拥有许多高阶组件会导致所谓的**包装器地狱**。

1.  我们可以使用哪个工具来设置 React 项目，我们需要运行什么命令来使用它？

+   我们可以使用`create-react-app`。要创建一个新项目，我们必须运行`npx create-react-app <app-name>`或`yarn create react-app <app-name>`。

1.  如果我们在类组件中遇到以下错误，我们需要做什么：*TypeError: undefined is not an object (evaluating 'this.setState')*？

+   我们忘记在类的`constructor`中重新绑定方法的`this`上下文。结果，`this`指向的不是类，而是输入字段的上下文。

1.  我们如何使用 Hooks 访问和设置 React 状态？

+   我们使用`useState()` Hook 如下：`const [ name, setName ] = useState('')`

1.  与类组件相比，使用带有 Hooks 的函数组件的优势是什么？

+   具有 Hooks 的函数组件不会遇到与类相同的问题。它们是声明性的，因此更适合 React 的基本原则。Hooks 还使我们的代码更简洁，更易于理解。

1.  在更新 React 时，我们是否需要用 Hooks 替换所有类组件？

+   不，我们不需要替换所有类组件。带有 Hooks 的函数组件可以与现有的类组件并存，并且是 100%向后兼容的。我们可以简单地使用 Hooks 编写新组件，或者以自己的步调升级现有组件。

1.  React 提供的三个基本 Hooks 是什么？

+   `useState`，`useEffect`和`useContext` Hooks 是 React 提供的基本 Hooks，并在项目中经常使用。但是，React 还提供了一些更高级的 Hooks。

# 第二章：使用 State Hook

1.  在开发自己的`useState` hook 的重新实现时，我们遇到了什么问题？我们是如何解决这些问题的？

+   一个问题是每次组件被渲染时值的初始化。我们通过使用全局变量来存储值来解决了这个问题。

+   然后，我们遇到了多个 Hooks 写入同一个全局变量的问题。为了解决这个问题，我们将值存储在数组中，并通过为每个 Hook 分配索引来跟踪当前 Hook。

1.  为什么在 React 的 Hooks 实现中不可能有条件 Hooks？

+   条件 Hooks 是不可能的，因为 React 使用 Hook 定义的顺序来跟踪值。如果我们稍后更改 Hooks 的顺序，值将分配给不同的 Hooks。

1.  Hooks 是什么，它们处理什么？

+   Hooks 是处理 React 应用程序中状态和效果的函数

1.  在使用 Hooks 时，我们需要注意什么？

+   我们需要确保 Hooks 的顺序始终保持不变，因此我们不能在循环或条件语句中使用 Hooks

1.  Hooks 的替代 API 想法的常见问题是什么？

+   命名钩子存在名称冲突的问题。即使在库中使用钩子时，每个钩子也必须具有唯一的名称。

+   钩子工厂需要更多的样板代码，主要是实例化每个钩子两次，一次在组件外部，一次在组件内部。此外，它们使得创建自定义钩子变得更加困难。

1.  我们如何实现条件钩子？

+   在简单情况下，我们总是可以定义钩子。否则，我们必须拆分组件，并有条件地渲染一个单独的组件，而不是有条件地渲染钩子。

1.  我们如何在循环中实现钩子？

+   在简单情况下，我们可以将数组存储在状态钩子中。否则，我们必须拆分组件并在循环中渲染一个单独的组件。

# 第三章：使用 React Hooks 编写您的第一个应用程序

1.  在 React 中，文件结构的最佳实践是什么？

+   首先从一个简单的结构开始，需要时再进行更深层次的嵌套。在启动项目时，不要花太多时间考虑文件结构。

1.  在拆分 React 组件时应该使用哪个原则？

+   单一职责原则，即每个组件应对功能的单个封装部分负责

1.  `map`函数是做什么的？

+   `map`函数将给定的函数应用于数组的所有元素，并返回具有结果的新数组

1.  解构是如何工作的，我们什么时候使用它？

+   通过解构，我们可以通过在赋值的左侧指定结构和变量名称来从对象中获取属性或从数组中获取元素。我们可以使用解构来获取 React 组件中的某些 props。

1.  扩展运算符是如何工作的，我们什么时候使用它？

+   扩展运算符在另一个对象/数组的特定点插入对象的所有属性或数组的所有元素。它可以用于创建新的数组或对象，或者将对象的所有属性作为 props 传递给 React 组件。

1.  我们如何使用 React Hooks 处理输入字段？

+   我们为输入字段值创建一个状态钩子，并定义一个设置值的处理函数

1.  本地状态钩子应该在哪里定义？

+   本地状态钩子应始终在使用它们的组件中定义

1.  什么是全局状态？

+   全局状态是在整个应用程序中跨多个组件使用的状态

1.  全局状态钩子应该在哪里定义？

+   全局状态 Hook 应该尽可能高地定义在组件树中。在我们的例子中，我们在 `App` 组件中定义了它们。

# 第四章：使用 Reducer 和 Effect Hooks

1.  State Hook 的常见问题是什么？

+   使用 State Hook 很难进行复杂的状态改变

1.  什么是动作？

+   动作是描述状态改变的对象，例如，`{ type: 'CHANGE_FILTER', byAuthor: 'Daniel Bugl' }`

1.  什么是 reducer？

+   Reducer 是处理状态改变的函数。它们接受当前状态和一个动作对象，并返回一个新状态。

1.  何时应该使用 Reducer Hook 而不是 State Hook？

+   当需要复杂的状态改变时，应该使用 Reducer Hook。通常，这适用于全局状态。

+   当多个 State Hook 的 setter 函数一起被调用时，这是使用 Reducer Hook 的一个很好的指标。

1.  为了将 State Hook 转换为 Reducer Hook，需要哪些步骤？

+   我们首先需要定义动作，然后是 reducer 函数，最后是 Reducer Hook

1.  我们如何更容易地创建动作？

+   我们可以定义返回动作对象的函数，称为**动作创建者**

1.  何时应该合并 Reducer Hook？

+   当我们想要避免有两个单独的 dispatch 函数或者同一个动作修改多个 reducer 中的状态时

1.  在合并 Reducer Hook 时需要注意什么？

+   我们需要确保每个 reducer 对于未处理的动作返回当前状态

1.  在类组件中，Effect Hook 的等价物是什么？

+   在 React 类组件中，我们将使用 `componentDidMount` 和 `componentDidUpdate` 来处理效果

1.  使用 Effect Hook 相对于类组件有什么优势？

+   使用 Effect Hook 时，我们不需要同时定义 `componentDidMount` 和 `componentDidUpdate`。此外，Effect Hook 更容易理解，我们不需要知道 React 内部的工作原理就能使用它们。

# 第五章：实现 React 上下文

1.  上下文避免了哪些问题？

+   上下文避免了必须通过多个组件层级传递 props 的问题

1.  上下文由哪两部分组成？

+   React 上下文由提供者和消费者组成

1.  使用上下文是否需要两部分都定义？

+   提供者不是必需的，因为当没有定义提供者时，上下文将使用传递给 `React.createContext` 的默认值

1.  使用 Hooks 而不是传统上下文消费者的优势是什么？

+   Hooks 不需要使用组件和渲染 props 来进行消费。使用多个上下文和消费者组件会使我们的组件树变得非常深，使我们的应用程序更难调试和维护。Hooks 通过允许我们通过简单调用 Hook 函数来消费上下文来避免这个问题。

1.  上下文的替代方案是什么，什么时候应该使用它？

+   上下文使得重用组件变得更加困难。只有在我们需要在不同嵌套级别的多个组件中访问数据时，才应该使用上下文。否则，我们可以通过传递 props 或传递渲染的组件来使用控制反转技术。

1.  我们如何实现动态更改上下文？

+   我们需要使用 State Hook 来为上下文提供值

1.  什么时候使用上下文来管理状态是有意义的？

+   通常情况下，使用上下文来管理全局状态是有意义的，这些状态在不同嵌套级别的多个组件中使用。

# 第六章：实现请求和 React Suspense

1.  如何从一个简单的 JSON 文件中轻松创建一个完整的 REST API？

+   我们可以使用`json-server`工具从 JSON 文件创建一个完整的 REST API，用于开发和测试

1.  在开发过程中使用代理访问后端服务器的优势是什么？

+   在使用代理时，在开发过程中我们不需要处理跨站点限制

1.  我们可以使用哪些组合的 Hooks 来实现请求？

+   我们可以使用 Effect 和 State 或 Reducer Hook 来实现请求

1.  我们可以使用哪些库来实现请求？

+   我们还可以使用`axios`和`react-request-hook`库来实现请求

1.  我们如何使用`react-request-hook`处理加载状态？

+   我们可以使用从`useResource` Hook 返回的`result.isLoading`标志，并有条件地显示加载消息

1.  我们如何使用`react-request-hook`处理错误？

+   我们可以使用从`useResource` Hook 返回的`result.error`对象并分派错误操作

1.  如何防止组件不必要的重新渲染？

+   使用`React.memo`，我们可以防止不必要的重新渲染，类似于`shouldComponentUpdate`

1.  我们如何减少应用程序的捆绑大小？

+   我们可以使用`React.Suspense`来延迟加载某些组件，这意味着只有在需要时才会从服务器请求它们。

# 第七章：使用 Hooks 进行路由

1.  为什么我们需要定义单独的页面？

+   大多数大型应用程序由多个页面组成。例如，每篇博客文章都有一个单独的页面

1.  我们如何使用 Navi 库定义路由？

+   我们使用`mount`函数并传递一个将路径映射到`route`函数的对象

1.  我们如何使用 URL 参数定义路由？

+   我们可以使用`:parameter`语法在路径中指定 URL 参数

1.  如何使用 Navi 定义静态链接？

+   可以使用`react-navi`中的`Link`组件来定义静态链接

1.  我们如何实现动态导航？

+   可以使用`useNavigation` Hook 并调用`navigation.navigate()`来实现动态导航

1.  用于访问当前路由信息的 Hook 是什么？

+   `useCurrentRoute` Hook 为我们提供了关于当前路由的所有信息

1.  用于访问当前加载路由的 Hook 是什么？

+   `useLoadingRoute` Hook 为我们提供了关于当前正在加载的路由的所有信息

# 第八章：使用社区 Hooks

1.  我们可以使用哪个 Hook 来简化输入字段处理？

+   我们可以使用`react-hookedup`库中的`useInput` Hook

1.  如何使用 Effect Hooks 实现`componentDidMount`和`componentWillUnmount`生命周期？

+   `componentDidMount`可以通过使用 Effect Hook 并将空数组作为第二个参数传递来实现。例如，`useEffect(() => console.log('did mount'), [])`。

+   `componentWillUnmount`可以通过从 Effect Hook 返回一个函数来实现，其中空数组作为第二个参数传递，例如，`useEffect(() => { return () => console.log('will unmount') }, [])`。

1.  我们如何使用 Hooks 来获得`this.setState()`的行为？

+   `this.setState()`将现有状态对象与给定状态对象合并。我们可以使用`useMergeState` Hook 来获得相同的行为，而不是简单的 State Hook。

1.  为什么我们应该使用定时器 Hooks 而不是直接调用`setTimeout`和`setInterval`？

+   在定义简单的超时或间隔时，当组件重新渲染时它们将被重置。为了防止这种重置发生，我们必须使用`react-hookedup`中的`useTimeout`和`useInterval` Hook。

1.  我们可以使用哪些 Hooks 来简化处理常见数据结构？

+   我们可以使用`react-hookedup`中的`useBoolean`、`useArray`和`useCounter` Hooks

1.  何时应该使用 Hooks 进行响应式设计，而不是简单地使用 CSS 媒体查询？

+   当在画布或 WebGL 中渲染元素时，或者当我们动态地想要根据窗口大小决定是否加载组件时，我们应该使用 Hooks 进行响应式设计

1.  我们可以使用哪个 Hook 来实现撤销/重做功能？

+   我们可以使用`use-undo`库中的`useUndo` Hook 来在我们的应用程序中实现简单的撤销/重做功能

1.  什么是防抖动？为什么我们需要这样做？

+   防抖动意味着函数只会在一定时间后被调用，而不是每次事件触发时都被调用。使用防抖动，我们可以在文本字段中输入的值仅在每秒后存储在撤销历史中，而不是在每次输入字符后。

1.  我们可以使用哪个 Hook 来进行防抖动？

+   我们可以使用`use-debounce`库中的`useDebounce`或`useDebouncedCallback` Hook

# 第九章：Hook 的规则

1.  Hook 可以在哪里调用？

+   Hook 只能在 React 函数组件或自定义 Hook 的开头调用

1.  我们可以在 React 类组件中使用 Hook 吗？

+   不，不可能在 React 类组件中使用 Hook

1.  关于 Hook 的顺序，我们需要注意什么？

+   Hook 的顺序不应该改变，因为它用于跟踪各种 Hook 的值

1.  Hook 可以在条件语句、循环或嵌套函数中调用吗？

+   不，Hook 不能在条件语句、循环或嵌套函数中调用，因为那样会改变 Hook 的顺序

1.  Hook 的命名约定是什么？

+   Hook 函数名称应始终以`use`前缀开头，然后是`CamelCase`中的名称。例如：`useSomeHookName`。

1.  我们如何自动强制执行 Hook 的规则？

+   我们可以使用`eslint`和`eslint-plugin-react-hooks`来强制执行 Hook 的规则

1.  详尽的依赖规则是什么？

+   详尽的依赖规则确保在 Effect Hook 中使用的所有变量都通过第二个参数列为依赖项

1.  我们如何自动修复 linter 警告？

+   我们可以运行`npm run lint -- --fix`命令来自动修复 linter 警告。例如，运行此命令将自动将 Effect Hook 中使用的所有变量输入为依赖项。

# 第十章：构建自己的 Hooks

1.  我们如何从现有代码中提取自定义 Hook？

+   我们可以简单地将我们的代码放入一个单独的函数中。在自定义 Hook 函数中可以使用其他 Hook 函数，但我们需要确保不违反 Hook 的规则。

1.  创建 API Hooks 的优势是什么？

+   当为各种 API 调用定义单独的函数时，如果 API 以后发生更改，我们可以很容易地调整它们，因为我们把所有与 API 相关的代码放在一个地方

1.  我们何时应该将功能提取到自定义 Hook 中？

+   当某个功能在多个地方使用或以后可能被重复使用时，我们应该创建一个自定义 Hook

1.  我们如何使用自定义 Hooks？

+   我们可以像调用官方 React Hooks 或来自库的 Hooks 一样简单地调用自定义 Hooks

1.  何时应该创建本地 Hooks？

+   当我们想要将某个功能封装在单独的函数中，但它只会在单个组件中使用时，可以使用本地 Hooks

1.  Hooks 之间有哪些交互？

+   我们可以在 Hook 函数中使用其他 Hooks，并且可以从其他 Hooks 传递值到 Hooks

1.  我们可以使用哪个库来测试 Hooks？

+   我们可以使用`jest`测试运行器与 React Hooks 测试库（`@testing-library/react-hooks`）和`react-test-renderer`来测试 Hooks

1.  我们如何测试 Hook 动作？

+   可以使用`act`函数来测试 Hook 动作。例如，`act(() => result.current.increment())`。

1.  我们如何测试上下文？

+   通过编写一个上下文包装函数来测试上下文，该函数返回提供者。然后可以将包装函数传递给`renderHook`函数。例如，`const { result } = renderHook(() => useTheme(), { wrapper: ThemeContextWrapper })`。

1.  我们如何测试异步代码？

+   我们可以使用与从`renderHook`返回的`waitForNextUpdate`函数结合使用 async/await 构造来等待异步代码完成运行

# 第十一章：从 React 类组件迁移

1.  React 类组件是如何定义的？

+   React 类组件是通过使用`class ComponentName extends React.Component {`来定义的

1.  在使用类组件的`constructor`时，我们需要调用什么？为什么？

+   我们首先需要调用`super(props)`来确保 props 被传递给`React.Component`类

1.  我们如何在类组件中设置初始状态？

+   我们可以通过在`constructor`中定义`this.state`对象来在类组件中设置初始状态

1.  我们如何改变类组件的状态？

+   在类组件中，我们使用`this.setState()`来改变状态

1.  为什么我们需要重新绑定类组件方法的`this`上下文？

+   当将方法传递给元素作为事件处理程序时，`this`上下文会更改为触发事件的元素。我们需要重新绑定`this`上下文到类以防止这种情况发生。

1.  我们如何重新绑定`this`上下文？

+   我们需要在构造函数中对方法使用`.bind(this)`。例如，`this.handleInput = this.handleInput.bind(this)`。

1.  如何在类组件中使用 React 上下文？

+   我们可以设置`contextType`，然后访问`this.context`。例如，`static contextType = StateContext`。

+   如果我们想使用多个上下文，我们可以使用上下文消费者。例如，`<StateContext.Consumer>{value => <div>State is: {value}</div>}</StateContext.Consumer>`。

1.  在迁移到 Hooks 时，我们可以用什么替换状态管理？

+   我们可以用 State Hook 替换`this.state`和`this.setState`。

1.  使用 Hooks 与类组件相比有哪些权衡？

+   使用 Hooks 的函数组件更简单（不需要处理构造函数、`this`或多次解构相同的值，处理上下文、props 和状态时没有魔法，不需要同时定义`componentDidMount`和`componentDidUpdate`）。函数组件还鼓励创建小而简单的组件，更容易重构和测试，需要更少的代码，对初学者更容易理解，更具有声明性。

+   然而，当遵循特定约定并使用最新的 JavaScript 特性来避免`this`重新绑定时，类组件可能是可以的。此外，由于具有现有知识，类组件可能更容易为团队理解。

1.  何时以及如何将现有项目迁移到 Hooks？

+   在适当的时候逐步用基于 Hook 的函数组件替换旧的类组件。例如，当您已经在重构一个组件时。

# 第十二章：Redux 和 Hooks

1.  Redux 应该用于哪种状态？

+   Redux 应该用于全局状态，即在我们的应用程序中多个组件中使用的状态。

1.  Redux 由哪些元素组成？

+   Redux 由**store**（描述应用程序完整状态的对象）、**actions**（描述状态修改的对象）、**action creators**（创建操作对象的函数）、**reducers**（接受当前状态和操作对象并返回新状态的函数）和**connectors**（将现有组件连接到 Redux 的高阶组件）组成

1.  Redux 的三个原则是什么？

+   单一数据源（数据应始终具有单一来源）

+   只读状态（不可能直接修改状态，只能通过分派操作来修改）

+   状态更改通过纯函数处理（给定相同的状态和操作，reducer 将始终返回相同的新状态）

1.  为什么要定义操作类型？

+   动作类型避免在定义或比较动作的`type`属性时出现拼写错误。

1.  我们如何将组件连接到 Redux？

+   我们可以使用`connect`高阶组件，也可以使用 Dispatch 和 Selector Hooks。

1.  我们可以使用哪些 Hooks 与 Redux 一起使用？

+   使用`useDispatch`来获取分发函数，使用`useSelector`来获取状态的某个部分，使用`useStore`来获取 Redux 存储（用于特殊用例，比如替换 reducers）。

1.  为什么我们应该创建可重用的选择器？

+   可重用的选择器可以在多个组件中使用。此外，它们会记忆结果，并且只在状态改变时重新计算。

1.  我们如何迁移 Redux 应用程序？

+   我们应该首先用 State Hooks 替换简单的本地状态，比如输入字段的值。然后用 Reducer Hooks 替换复杂的本地状态。我们将全局状态（在多个组件中使用）保留在 Redux 存储中。最后，我们使用 Selector 和 Dispatch Hooks 来代替`connect`高阶组件。

1.  Redux 的权衡是什么？

+   使用 Redux 的优点是：它提供了一定的项目结构，使我们可以轻松地扩展和修改代码，代码中的错误可能性较少，它的性能比仅使用 React 上下文来管理状态要好，并且通过将状态管理和动作创建者转移到 Redux，使我们的`App`组件变得更简单。

+   使用 Redux 的缺点是：它需要大量样板代码，项目结构变得更加复杂，并且需要一个包装组件（`Provider`）来连接应用程序到存储。

1.  我们何时应该使用 Redux？

+   我们应该只在需要复杂状态更改的应用程序中使用 Redux。对于简单项目，Reducer Hooks 甚至只使用 State Hooks 可能就足够了。

# 第十三章：MobX 和 Hooks

1.  哪些元素构成 MobX 的生命周期？

+   事件调用**动作**，从而修改状态。**状态**是可观察的，不应包含冗余或可推导的数据。**计算值**是通过纯函数从状态派生出来的。**反应**类似于计算值，但它们也可以产生副作用，比如在 React 中更新用户界面。

1.  MobX 提供哪些装饰器？

+   MobX 为各种元素提供装饰器：`observer`、`observable`、`computed`和`action`。

1.  我们如何将组件连接到 MobX？

+   我们可以通过使用`Provider`组件将我们的应用连接到 MobX 存储，然后通过`inject`高阶组件连接组件。如果我们希望组件在状态更改时自动重新渲染，还需要使用`observer`修饰函数来包装它。

1.  MobX 提供了哪些 Hooks？

+   我们可以使用`useObserver` Hook 来定义组件的部分，在状态更改时应该重新计算。

1.  如何使用 Hooks 访问 MobX 存储？

+   MobX 提供了一个上下文，可以用来创建访问 MobX 存储的自定义 Hooks。我们可以使用普通的上下文 Hook 来访问`mobx-react`中的`MobXProviderContext`。

1.  我们可以使用 MobX 存储本地状态吗？

+   是的，使用 MobX，我们可以创建任意数量的存储。MobX 甚至提供了一个`useLocalStore` Hook 来创建本地存储。

1.  我们应该如何将现有的 MobX 应用迁移到 Hooks？

+   我们可以逐步升级 MobX 应用的某些部分。我们可以使用自定义 Hook 来访问上下文的一部分，而不是`inject`高阶组件。我们可以使用`useObserver` Hook 来替代`observer`高阶组件。

+   我们应该首先使用 State Hook 来处理简单的本地状态，然后使用`useLocalState` Hook 来处理复杂的本地状态，最后将全局状态保留在单独的 MobX 存储中。

1.  使用 MobX 的优势是什么？

+   它提供了处理状态更改的简单方式，需要更少的样板代码，在应用代码结构方面提供了更多的灵活性，允许使用多个全局和本地存储，并通过将状态管理和操作交给 MobX 使`App`组件变得更简单。

1.  使用 MobX 的缺点是什么？

+   它允许状态更改发生在任何地方，而不仅仅是在单个存储中，这可能会使我们的应用更加不可预测。更多的灵活性也意味着可能以不好的方式构建项目并导致错误或缺陷。此外，如果我们想要获得所有功能，MobX 需要一个包装组件将应用连接到存储（我们可以直接导入和使用 MobX 存储，但这将破坏诸如服务器端渲染之类的功能）。

1.  什么时候不应该使用 MobX？

+   如果状态更改简单且仅使用组件内的本地状态，则不应使用 MobX。在这种情况下，状态和 Reducer Hooks 可能足够了。
