# React 挂钩学习手册（二）

> 原文：[`zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667`](https://zh.annas-archive.org/md5/0d61b163bb6c28fa00edc962fdaa2667)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：深入理解 Hooks

在本书的这一部分，我们将学习各种 React Hooks 以及如何使用它们。此外，我们还将学习 Hooks 的规则以及如何编写我们自己的 Hooks。

在本节中，我们将涵盖以下章节：

+   第四章，*使用 Reducer 和 Effect Hooks*

+   第五章，*实现 React Context*

+   第六章，*实现请求和 React Suspense*

+   第七章，*使用 Hooks 进行路由*

+   第八章，*使用社区提供的 Hooks*

+   第九章，*Hooks 的规则*

+   第十章，*构建自己的 Hooks*


# 第四章：在我们的博客应用中使用 Reducer 和 Effect Hooks

在使用 State Hook 开发我们自己的博客应用之后，我们现在要学习 React 提供的另外两个非常重要的 Hooks：**Reducer**和**Effect** Hooks。我们首先要学习何时应该使用 Reducer Hook 而不是 State Hook。然后，我们学习如何将现有的 State Hook 转换为 Reducer Hook，以便在实践中掌握这个概念。接下来，我们将学习 Effect Hooks 以及它们的用途。最后，我们将在我们的博客应用中实现它们。

本章将涵盖以下主题：

+   学习有关 Reducer Hooks 和 State Hooks 之间的区别

+   在我们的博客应用中实现 Reducer Hooks

+   在我们的博客应用中使用 Effect Hooks

# 技术要求

应该已经安装了相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter04`](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter04)[.](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter04)

查看以下视频以查看代码的实际运行情况：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行提供的代码示例。重要的是您自己编写代码，以便能够正确学习和理解。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始本章。

# Reducer Hooks 与 State Hooks

在上一章中，我们学习了如何处理本地和全局状态。我们对两种情况都使用了 State Hooks，这对于简单的状态更改是可以的。然而，当我们的状态逻辑变得更加复杂时，我们需要确保保持状态一致。为了做到这一点，我们应该使用 Reducer Hook 而不是多个 State Hooks，因为很难在彼此依赖的多个 State Hooks 之间保持同步。作为替代方案，我们可以将所有状态保存在一个 State Hook 中，但然后我们必须确保不会意外地覆盖我们状态的部分。

# State Hook 的问题

State Hook 已经支持向其传递复杂对象和数组，并且可以很好地处理它们的状态变化。然而，我们总是需要直接改变状态，这意味着我们需要使用大量的扩展语法，以确保我们不会覆盖状态的其他部分。例如，想象一下，我们有一个这样的状态对象：

```jsx
const [ config, setConfig ] = useState({ filter: 'all', expandPosts: true })
```

现在，我们想要改变过滤器：

```jsx
setConfig({ filter: { byAuthor: 'Daniel Bugl', fromDate: '2019-04-29' } })
```

如果我们简单地运行前面的代码，我们将删除状态的`expandPosts`部分！所以，我们需要做以下操作：

```jsx
setConfig({ ...config, filter: { byAuthor: 'Daniel Bugl', fromDate: '2019-04-29' } })
```

现在，如果我们想要将`fromDate`过滤器更改为不同的日期，我们需要两次使用扩展语法，以避免删除`byAuthor`过滤器：

```jsx
setConfig({ ...config, filter: { ...config.filter, fromDate: '2019-04-30' } })
```

但是，如果我们在`filter`状态仍然是字符串时这样做会发生什么？我们将得到以下结果：

```jsx
{ filter: { '0': 'a', '1': 'l', '2': 'l', fromDate: '2019-04-30' },
  expandPosts: true }
```

什么？为什么突然出现了三个新键—`0`、`1`和`2`？这是因为扩展语法也适用于字符串，它们以这样的方式扩展，即每个字母根据其在字符串中的索引获得一个键。

正如你所想象的那样，对于较大的状态对象，使用扩展语法和直接改变状态对象会变得非常繁琐。此外，我们总是需要确保我们不会引入任何错误，并且需要在应用程序的各个地方检查错误。

# 操作

而不是直接改变状态，我们可以创建一个处理状态变化的函数。这样的函数只允许通过特定操作来改变状态，比如`CHANGE_FILTER`或`TOGGLE_EXPAND`操作。

操作只是具有`type`键的对象，告诉我们我们正在处理哪个操作，并且更详细地描述操作的其他键。

`TOGGLE_EXPAND`操作非常简单。它只是一个定义了`type`的对象：

```jsx
{ type: 'TOGGLE_EXPAND' }
```

`CHANGE_FILTER`操作可以处理我们之前遇到的复杂状态变化问题，如下所示：

```jsx
{ type: 'CHANGE_FILTER', all: true }
{ type: 'CHANGE_FILTER', fromDate: '2019-04-29' }
{ type: 'CHANGE_FILTER', byAuthor: 'Daniel Bugl' }
{ type: 'CHANGE_FILTER', fromDate: '2019-04-30' }
```

第二、第三和第四个操作将把`filter`状态从字符串更改为对象，然后设置相应的键。如果对象已经存在，我们只需调整在操作中定义的键。每个操作后，状态将如下更改：

+   `{ expandPosts: true, filter: 'all' }`

+   `{ expandPosts: true, filter: **{** fromDate: '2019-04-29' **}** }`

+   `{ expandPosts: true, filter: { fromDate: '2019-04-29', byAuthor: 'Daniel Bugl' } }`

+   { expandPosts: true, filter: { fromDate: '2019-04-30', byAuthor: 'Daniel Bugl' } }

现在，看一下以下代码：

```jsx
{ type: 'CHANGE_FILTER', all: true }
```

如果我们分派了另一个 action，就像前面的代码一样，那么状态将回到初始状态中的`all`字符串。

# Reducers

现在，我们仍然需要定义处理这些状态变化的函数。这样的函数被称为 reducer 函数。它以当前的`state`和`action`作为参数，并返回一个新的 state。

如果您熟悉 Redux 库，您可能已经非常熟悉状态、actions 和 reducers 的概念。

现在，我们要定义我们的`reducer`函数：

1.  我们从我们的`reducer`的函数定义开始：

```jsx
function reducer (state, action) {
```

1.  然后，我们使用`switch`语句检查`action.type`：

```jsx
    switch (action.type) {
```

1.  现在，我们要处理`TOGGLE_EXPAND`动作，我们只是切换当前的`expandPosts`状态：

```jsx
        case 'TOGGLE_EXPAND':
            return { ...state, expandPosts: !state.expandPosts }
```

1.  接下来，我们要处理`CHANGE_FILTER`动作。在这里，我们首先需要检查`all`是否设置为`true`，在这种情况下，只需将我们的`filter`设置为`'all'`字符串：

```jsx
        case 'CHANGE_FILTER':
            if (action.all) {
                return { ...state, filter: 'all' }
            }
```

1.  现在，我们必须处理其他`filter`选项。首先，我们检查`filter`变量是否已经是一个`object`。如果不是，我们创建一个新的。否则，我们使用现有的对象：

```jsx
            let filter = typeof state.filter === 'object' ? state.filter : {}
```

1.  然后，我们定义各种过滤器的处理程序，允许同时设置多个过滤器，而不是立即返回新的`state`：

```jsx
            if (action.fromDate) {
                filter = { ...filter, fromDate: action.fromDate }
            }
            if (action.byAuthor) {
                filter = { ...filter, byAuthor: action.byAuthor }
            }
```

1.  最后，我们返回新的`state`：

```jsx
            return { ...state, filter }
```

1.  对于`default`情况，我们抛出错误，因为这是一个未知的动作：

```jsx
        default:
            throw new Error()
    }
}
```

在默认情况下抛出错误与 Redux reducers 的最佳实践不同，在那里我们只会在默认情况下返回当前状态。因为 React Reducer Hooks 不会将所有状态存储在一个对象中，我们只会处理特定状态对象的某些动作，所以我们可以对未知的动作抛出错误。

现在，我们的`reducer`函数已经定义，我们可以继续定义 Reducer Hook。

# Reducer Hook

现在我们已经定义了 actions 和`reducer`函数，我们可以从`reducer`创建一个 Reducer Hook。`useReducer` Hook 的签名如下：

```jsx
const [ state, dispatch ] = useReducer(reducer, initialState)
```

我们唯一还需要定义的是`initialState`；然后我们可以定义一个 Reducer Hook：

```jsx
const initialState = { all: true }
```

现在，我们可以通过使用从 Reducer Hook 返回的`state`对象来访问状态，并通过`dispatch`函数分派 actions，如下所示：

```jsx
dispatch({ type: 'TOGGLE_EXPAND' })
```

如果我们想要向 action 添加其他选项，我们只需将它们添加到 action 对象中：

```jsx
dispatch({ type: 'CHANGE_FILTER', fromDate: '2019-04-30' })
```

正如我们所看到的，使用操作和减速器处理状态变化比直接调整状态对象要容易得多。

# 实现 Reducer Hooks

在了解了操作、减速器和 Reducer Hook 之后，我们将在我们的博客应用程序中实现它们。当状态对象或状态变化变得太复杂时，任何现有的 State Hook 都可以转换为 Reducer Hook。

如果有多个`setState`函数总是同时调用，这是它们应该在一个单独的 Reducer Hook 中分组的一个很好的提示。

全局状态通常是使用 Reducer Hook 的一个很好的候选，而不是 State Hook，因为全局状态的变化可以发生在应用程序的任何地方。然后，在一个地方处理操作并仅更新状态变化逻辑会更容易。将所有状态变化逻辑放在一个地方使得更容易维护和修复错误，而不会因忘记在所有地方更新逻辑而引入新错误。

现在，我们将一些现有的 State Hooks 在我们的博客应用程序中转换为 Reducer Hooks。

# 将 State Hook 转换为 Reducer Hook

在我们的博客应用程序中，我们有两个全局 State Hooks，我们将用 Reducer Hooks 替换它们：

+   `user`状态

+   `posts`状态

我们首先替换`user` State Hook。

# 替换用户 State Hook

我们将从`user` State Hook 开始，因为它比`posts` State Hook 更简单。以后，`user`状态将包含复杂的状态变化，因此在这里使用 Reducer Hook 是有意义的。

首先，我们将定义我们的操作，然后我们将定义减速器函数。最后，我们将用 Reducer Hook 替换 State Hook。

# 定义操作

我们首先定义我们的操作，因为在定义减速器函数时，这些操作将很重要。

现在让我们定义操作：

1.  首先，我们需要一个操作来允许用户通过提供`username`值和`password`值来登录：

```jsx
{ type: 'LOGIN', username: 'Daniel Bugl', password: 'notsosecure' }
```

1.  然后，我们还需要一个`REGISTER`操作，在我们的情况下，它将类似于`LOGIN`操作，因为我们还没有实现任何注册逻辑：

```jsx
{ type: 'REGISTER', username: 'Daniel Bugl', password: 'notsosecure', passwordRepeat: 'notsosecure' }
```

1.  最后，我们将需要一个`LOGOUT`操作，它只是简单地注销当前登录的用户：

```jsx
{ type: 'LOGOUT' }
```

现在，我们已经定义了所有必需的与用户相关的操作，我们可以继续定义减速器函数了。

# 定义减速器

接下来，我们为`user`状态定义一个减速器函数。现在，我们将把我们的减速器放在`src/App.js`文件中。

以后，创建一个单独的`src/reducers.js`文件，甚至是一个单独的`src/reducers/`目录，为每个 reducer 函数创建单独的文件可能是有意义的。

让我们开始定义`userReducer`函数：

1.  在`src/App.js`文件中，在`App`函数定义之前，为`user`状态创建一个`userReducer`函数：

```jsx
function userReducer (state, action) {
```

1.  再次，我们对动作类型使用`switch`语句：

```jsx
    switch (action.type) {
```

1.  然后，我们处理`LOGIN`和`REGISTER`动作，将`user`状态设置为给定的`username`值。在我们的情况下，我们暂时只是从`action`对象中返回`username`值：

```jsx
        case 'LOGIN':
        case 'REGISTER':
            return action.username
```

1.  接下来，我们处理`LOGOUT`动作，将状态设置为空字符串：

```jsx
        case 'LOGOUT':
            return ''
```

1.  最后，当遇到未处理的动作时，我们会抛出一个错误：

```jsx
        default:
            throw new Error()
    }
}
```

现在，`userReducer`函数已经定义，我们可以继续定义 Reducer Hook。

# 定义 Reducer Hook

定义完动作和 reducer 函数后，我们将定义 Reducer Hook，并将其状态和 dispatch 函数传递给需要它的组件。

让我们开始实现 Reducer Hook：

1.  首先，我们需要通过调整`src/App.js`中的以下`import`语句来导入`useReducer` Hook：

```jsx
import React, { useState, useReducer } from 'react'
```

1.  编辑`src/App.js`，移除以下 State Hook：

```jsx
    const [ user, setUser ] = useState('')
```

用 Reducer Hook 替换前面的 State Hook——初始状态是一个空字符串，就像以前一样：

```jsx
    const [ user, dispatchUser ] = useReducer(userReducer, '')
```

1.  现在，将`user`状态和`dispatchUser`函数作为`dispatch`属性传递给`UserBar`组件：

```jsx
            <UserBar user={user} dispatch={dispatchUser} />
```

1.  我们不需要修改`CreatePost`组件，因为我们只是将`user`状态传递给它，而这部分没有改变。

1.  接下来，我们编辑`src/user/UserBar.js`中的`UserBar`组件，并用`dispatch`函数替换`setUser`属性：

```jsx
export default function UserBar ({ user, dispatch }) {
    if (user) {
        return <Logout user={user} dispatch={dispatch} />
    } else {
        return (
            <React.Fragment>
                <Login dispatch={dispatch} />
                <Register dispatch={dispatch} />
            </React.Fragment>
        )
    }
}
```

1.  现在，我们可以编辑`src/user/Login.js`中的`Login`组件，并用`dispatch`函数替换`setUser`函数：

```jsx
export default function Login ({ dispatch }) {
```

1.  然后，我们用`dispatch`函数替换了对`setUser`的调用，派发一个`LOGIN`动作：

```jsx
            <form onSubmit={e => { e.preventDefault(); dispatch({ type: 'LOGIN', username }) }}>
```

我们还可以创建返回动作的函数，即所谓的动作创建者。我们可以简单地调用`loginAction('username')`，而不是每次手动创建动作对象，它会返回相应的`LOGIN`动作对象。

1.  我们在`src/user/Register.js`中的`Register`组件中重复相同的过程：

```jsx
export default function Register ({ dispatch }) {
    // ...
            <form onSubmit={e => { e.preventDefault(); dispatch({ type: 'REGISTER', username }) }}>
```

1.  最后，我们也在`src/user/Logout.js`中的`Logout`组件中重复相同的过程：

```jsx
export default function Logout ({ user, dispatch }) {
    // ...
            <form onSubmit={e => { e.preventDefault(); dispatch({ type: 'LOGOUT' }) }}>
```

现在，我们的应用应该和以前一样工作，但是它使用了 Reducer Hook 而不是简单的 State Hook！

# 替换 posts State Hook

使用 Reducer Hook 来处理`posts`状态也是有道理的，因为以后我们会有一些功能可以用来删除和编辑帖子，所以将这些复杂的状态变化封装起来是很有意义的。现在让我们开始用 Reducer Hook 替换 posts State Hook。

# 定义操作

同样，我们首先定义操作。目前，我们只考虑`CREATE_POST`操作：

```jsx
{ type: 'CREATE_POST', title: 'React Hooks', content: 'The greatest thing since sliced bread!', author: 'Daniel Bugl' }
```

这是我们目前需要的唯一操作。

# 定义 reducer

接下来，我们将以与`user`状态相似的方式定义 reducer 函数：

1.  我们首先编辑`src/App.js`，在那里定义 reducer 函数。以下代码定义了`postsReducer`函数：

```jsx
function postsReducer (state, action) {
    switch (action.type) {
```

1.  在这个函数中，我们将处理`CREATE_POST`操作。我们首先创建一个`newPost`对象，然后使用扩展语法将其插入到当前`posts`状态的开头，类似于我们之前在`src/post/CreatePost.js`组件中所做的方式：

```jsx
        case 'CREATE_POST':
            const newPost = { title: action.title, content: action.content, author: action.author }
            return [ newPost, ...state ]
```

1.  目前，这将是我们在这个 reducer 中处理的唯一操作，所以我们现在可以定义`default`语句：

```jsx
        default:
            throw new Error()
    }
}
```

现在，`postsReducer`函数已经定义，我们可以继续创建 Reducer Hook。

# 定义 Reducer Hook

最后，我们将定义并使用`posts`状态的 Reducer Hook：

1.  我们首先在`src/App.js`中删除以下 State Hook：

```jsx
       const [ posts, setPosts ] = useState(defaultPosts)
```

我们用以下 Reducer Hook 替换它：

```jsx
       const [ posts, dispatchPosts ] = useReducer(postsReducer, defaultPosts)
```

1.  然后，我们将`dispatchPosts`函数作为`dispatch`属性传递给`CreatePost`组件：

```jsx
            {user && <CreatePost user={user} posts={posts} dispatch={dispatchPosts} />}
```

1.  接下来，我们编辑`src/post/CreatePost.js`中的`CreatePost`组件，并用`dispatch`函数替换`setPosts`函数：

```jsx
export default function CreatePost ({ user, posts, dispatch }) {
```

1.  最后，在`handleCreate`函数中使用`dispatch`函数：

```jsx
    function handleCreate () {
        dispatch({ type: 'CREATE_POST', title, content, author: user })
    }
```

现在，`posts`状态也使用 Reducer Hook 而不是 State Hook，并且与以前的方式一样工作！然而，如果以后我们想要添加更多逻辑来管理帖子，比如搜索、过滤、删除和编辑，那么这将更容易做到。

# 示例代码

在我们的博客应用程序中使用 Reducer Hook 的示例代码可以在`Chapter04/chapter4_1`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 合并 Reducer Hook

目前，我们有两个不同的 dispatch 函数：一个用于`user`状态，一个用于`posts`状态。在我们的情况下，将这两个 reducers 合并成一个是有意义的，然后调用进一步的 reducers 来处理子状态。

这种模式类似于 Redux 中 reducer 的工作方式，其中我们只有一个包含整个应用程序状态树的对象，在全局状态的情况下是有意义的。然而，对于复杂的局部状态更改，将 reducers 保持分开可能更有意义。

让我们开始将我们的 reducer 函数合并成一个 reducer 函数。在此过程中，让我们将所有 reducers 重构到`src/reducers.js`文件中，以使`src/App.js`文件更易读：

1.  创建一个新的`src/reducers.js`文件。

1.  从`src/App.js`文件中剪切以下代码，并粘贴到`src/reducers.js`文件中：

```jsx
function userReducer (state, action) {
    switch (action.type) {
        case 'LOGIN':
        case 'REGISTER':
            return action.username

        case 'LOGOUT':
            return ''

        default:
            throw new Error()
    }
}

function postsReducer (state, action) {
    switch (action.type) {
        case 'CREATE_POST':
            const newPost = { title: action.title, content: action.content, author: action.author }
            return [ newPost, ...state ]

        default:
            throw new Error()
    }
}
```

1.  编辑`src/reducers.js`，并在现有的 reducer 函数下面定义一个新的 reducer 函数，名为`appReducer`：

```jsx
export default function appReducer (state, action) {
```

1.  在这个`appReducer`函数中，我们将调用另外两个 reducer 函数，并返回完整的状态树：

```jsx
    return {
        user: userReducer(state.user, action),
        posts: postsReducer(state.posts, action)
    }
}
```

1.  编辑`src/App.js`，并在那里导入`appReducer`：

```jsx
import  appReducer  from  './reducers'
```

1.  然后，我们移除以下两个 Reducer Hook 定义：

```jsx
            const [ user, dispatchUser ] = useReducer(userReducer,
             '')
            const [ posts, dispatchPosts = useReducer(postsReducer, 
         defaultPosts)
```

用`appReducer`的单一 Reducer Hook 定义替换前面的 Reducer Hook 定义：

```jsx
    const [ state, dispatch ] = useReducer(appReducer, { user: '', posts: defaultPosts })
```

1.  接下来，我们使用解构从我们的`state`对象中提取`user`和`posts`的值：

```jsx
    const { user, posts } = state
```

1.  现在，我们仍然需要用`dispatch`函数替换我们传递给其他组件的`dispatchUser`和`dispatchPosts`函数：

```jsx
            <UserBar user={user} dispatch={dispatch} />
            <br />
            {user && <CreatePost user={user} posts={posts} dispatch={dispatch} />}
```

我们可以看到，现在只有一个`dispatch`函数和一个单一的状态对象。

# 忽略未处理的 actions

然而，如果我们现在尝试登录，我们将会看到来自`postsReducer`的错误。这是因为我们仍然在未处理的 actions 上抛出错误。为了避免这种情况，我们必须忽略未处理的 actions，简单地返回当前状态：

编辑`src/reducers.js`中的`userReducer`和`postsReducer`函数，并移除以下代码：

```jsx
        default:
            throw new Error()
```

用一个`return`语句替换前面的代码，该语句返回当前的`state`：

```jsx
            default:
                return state
```

我们可以看到，现在我们的应用程序仍然以与以前完全相同的方式工作，但我们正在使用一个单一的 reducer 来处理整个应用程序状态！

# 示例代码

我们博客应用程序中使用单一 Reducer Hook 的示例代码可以在`Chapter04/chapter4_2`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 Effect Hooks

我们将经常使用的最后一个重要 Hook 是 Effect Hook。 使用 Effect Hook，我们可以从我们的组件执行副作用，例如在组件挂载或更新时获取数据。

在我们的博客案例中，我们将实现一个功能，当我们登录时更新我们网页的标题，以便包含当前登录用户的用户名。

# 记得 componentDidMount 和 componentDidUpdate 吗？

如果您以前使用过 React，您可能已经使用了`componentDidMount`和`componentDidUpdate`生命周期方法。 例如，我们可以使用 React 类组件将文档`title`设置为给定的 prop，如下所示。 在下面的代码部分中，生命周期方法用粗体标出：

```jsx
import React from 'react'

class App extends React.Component {
 componentDidMount () {
 const { title } = this.props document.title = title
 }

    render () {
        return (
            <div>Test App</div>
        )
    }
}
```

这很好。 但是，当`title`prop 更新时，更改不会反映在我们网页的标题中。 为了解决这个问题，我们需要定义`componentDidUpdate`生命周期方法（新代码用粗体标出），如下所示：

```jsx
import React from 'react'

class App extends React.Component {
    componentDidMount () {
        const { title } = this.props
        document.title = title
    }

 componentDidUpdate (prevProps) {
 const { title } = this.props
        if (title !== prevProps.title) {
 document.title = title
        }
 }

    render () {
        return (
            <div>Test App</div>
        )
    }
}
```

您可能已经注意到我们几乎写了相同的代码两次；因此，我们可以创建一个新方法来处理`title`的更新，然后从两个生命周期方法中调用它。 在下面的代码部分中，更新的代码用粗体标出：

```jsx
import React from 'react'

class App extends React.Component {
 updateTitle () {
 const { title } = this.props
 document.title = title
 }

    componentDidMount () {
        this.updateTitle()
    }

    componentDidUpdate (prevProps) {
        if (this.props.title !== prevProps.title) {
 this.updateTitle()
        }
    }

    render () {
        return (
            <div>Test App</div>
        )
    }
}
```

但是，我们仍然需要两次调用`this.updateTitle()`。 当我们稍后更新代码时，例如，向`this.updateTitle()`传递参数时，我们始终需要记住在两次调用方法时传递它。 如果我们忘记更新其中一个生命周期方法，可能会引入错误。 此外，我们需要在`componentDidUpdate`中添加一个`if`条件，以避免在`title`prop 未更改时调用`this.updateTitle()`。

# 使用 Effect Hook

在 Hooks 的世界中，`componentDidMount`和`componentDidUpdate`生命周期方法在`useEffect`Hook 中合并在一起，当不指定依赖数组时，会在组件中的任何 prop 更改时触发。

因此，我们现在可以使用 Effect Hook 定义一个带有 Effect Hook 的函数组件，它与以前的功能相同。 传递给 Effect Hook 的函数称为“effect 函数”：

```jsx
import React, { useEffect } from 'react'

function App ({ title }) {
    useEffect(() => {
        document.title = title
    })

    return (
        <div>Test App</div>
    )
}
```

这就是我们需要做的一切！ 我们定义的 Hook 将在任何 prop 更改时调用我们的 effect 函数。

# 仅在某些 props 更改时触发效果

如果我们想要确保我们的效果函数只在`title` prop 发生变化时才被调用，例如出于性能原因，我们可以指定应该触发更改的值，作为`useEffect` Hook 的第二个参数：

```jsx
    useEffect(() => {
        document.title = title
    }, [title])
```

而且这不仅限于 props，我们可以在这里使用任何值，甚至来自其他 Hooks 的值，比如 State Hook 或 Reducer Hook：

```jsx
    const [ title, setTitle ] = useState('')
    useEffect(() => {
        document.title = title
    }, [title])
```

正如我们所看到的，使用 Effect Hook 比使用生命周期方法处理变化的值要简单得多。

# 仅在挂载时触发效果

如果我们想要复制仅添加`componentDidMount`生命周期方法的行为，而不在 props 更改时触发，我们可以通过将空数组作为`useEffect` Hook 的第二个参数来实现这一点：

```jsx
    useEffect(() => {
        document.title = title
    }, [])
```

传递一个空数组意味着我们的效果函数只会在组件挂载时触发一次，并且不会在 props 更改时触发。然而，与其考虑组件的挂载，使用 Hooks，我们应该考虑效果的依赖关系。在这种情况下，效果没有任何依赖关系，这意味着它只会触发一次。如果一个效果有指定的依赖关系，当任何依赖关系发生变化时，它将再次触发。

# 清理效果

有时效果在组件卸载时需要清理。为此，我们可以从 Effect Hook 的效果函数中返回一个函数。这个返回的函数类似于`componentWillUnmount`生命周期方法：

```jsx
    useEffect(() => {
        const updateInterval = setInterval(() => console.log('fetching update'), updateTime)

        return () => clearInterval(updateInterval)
    }, [updateTime])
```

上面加粗的代码被称为清理函数。清理函数将在组件卸载时调用，并在再次运行效果之前调用。这可以避免 bug，例如`updateTime` prop 发生变化。在这种情况下，先前的效果将被清理，并且将使用更新的`updateTime`值定义一个新的间隔。

# 在我们的博客应用程序中实现一个 Effect Hook

现在我们已经学会了 Effect Hook 的工作原理，我们将在我们的博客应用程序中使用它，以在登录/注销时实现标题更改（当`user`状态发生变化时）。

让我们开始在我们的博客应用程序中实现一个 Effect Hook：

1.  编辑`src/App.js`，并导入`useEffect` Hook：

```jsx
import React, { useReducer, useEffect } from 'react'
```

1.  在定义了我们的`useReducer` Hook 和状态解构之后，定义一个`useEffect` Hook，根据`username`值调整`document.title`变量：

```jsx
    useEffect(() => {
```

1.  如果用户已登录，我们将`document.title`设置为`<username> - React Hooks Blog`。我们使用模板字符串，允许我们通过`${ }`语法在字符串中包含变量或 JavaScript 表达式。模板字符串使用`` ` ``定义：

```jsx
        if (user) {
            document.title = `${user} - React Hooks Blog`
```

4.  否则，如果用户没有登录，我们只需将`document.title`设置为`React Hooks Blog`即可：

```jsx
        } else {
        document.title = 'React Hooks Blog'
        }
```

5.  最后，我们将`user`值作为第二个参数传递给效果挂钩，以确保每当`user`值更新时，我们的效果函数都会再次触发:

```jsx
    }, [user])
```

如果我们现在启动我们的应用程序，我们可以看到`document.title`被设置为`React Hooks Blog`，因为 Effect Hook 在`App`组件挂载时触发，而`user`值尚未定义：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/7e34bb73-64d7-4c65-8d7e-6d6f6628f317.png)

我们的 Effect Hook 的效果：改变网页标题

在使用`Test User`登录后，我们可以看到`document.title`更改为`Test User - React Hooks Blog`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/7cb775dc-c5c3-4469-a41f-acb25f83e14f.png)

我们的 Effect Hook 重新触发的效果，用户值更改后

正如我们所看到的，我们的 Effect Hook 在`user`值更改后成功重新触发！

# 示例代码

在我们的博客应用程序中实现 Effect Hooks 的示例代码可以在`Chapter04/chapter4_3`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序，然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。 

# 总结

在本章中，我们首先学习了 actions、reducers 和 Reducer Hooks。我们还学习了何时应该使用 Reducer Hooks 而不是 State Hooks。然后，我们用两个 Reducer Hooks 替换了现有的全局 State Hooks，用于`user`和`posts`状态。接下来，我们将两个 Reducer Hooks 合并为一个单一的 app Reducer Hook。最后，我们学习了 Effect Hooks，以及它们如何可以代替`componentDidMount`和`componentDidUpdate`。

在下一章中，我们将学习关于 React context，以及如何在 Hooks 中使用它。然后，我们将向我们的应用程序添加 Context Hooks，以避免在多个组件层中传递 props。

# 问题

为了回顾本章学到的内容，请尝试回答以下问题：

1.  State Hooks 有哪些常见问题？

1.  什么是 actions？

1.  什么是 reducer？

1.  何时应该使用 Reducer Hook 而不是 State Hook？

1.  将 State Hook 转换为 Reducer Hook 需要哪些步骤？

1.  我们如何更轻松地创建 actions？

1.  何时应该合并 Reducer Hooks？

1.  在合并 Reducer Hooks 时需要注意什么？

1.  在类组件中，等效于 Effect Hook 的是什么？

1.  使用 Effect Hook 与类组件相比有哪些优势？

# 进一步阅读

如果您对本章探讨的概念更感兴趣，可以查阅以下阅读材料：

+   有关 Reducer Hook 的官方文档：[`reactjs.org/docs/hooks-reference.html#usereducer`](https://reactjs.org/docs/hooks-reference.html#usereducer)

+   官方文档和使用 Effect Hooks 的技巧：[`reactjs.org/docs/hooks-effect.html`](https://reactjs.org/docs/hooks-effect.html)

+   *Learning Redux* 由 *Pa**ckt* 出版，提供有关操作、减速器和管理应用状态的更深入信息：[`www.packtpub.com/web-development/learning-redux`](https://www.packtpub.com/web-development/learning-redux)


# 第五章：实现 React 上下文

在之前的章节中，我们学习了最基本的 Hooks，比如 State Hook、Reducer Hook 和 Effect Hook。我们使用这些 Hooks 开发了一个小型的博客应用程序。在开发博客应用程序的过程中，我们注意到我们不得不从`App`组件传递`user`状态到`UserBar`组件，然后从`UserBar`组件传递到`Login`、`Register`和`Logout`组件。为了避免这样传递状态，我们现在要学习关于 React 上下文和上下文 Hooks。

我们将首先学习什么是 React 上下文，提供者和消费者是什么。然后，我们将使用上下文 Hooks 作为上下文消费者，并讨论何时应该使用上下文。最后，我们将通过上下文实现主题和全局状态。

本章将涵盖以下主题：

+   引入 React 上下文作为传递 props 的替代方法

+   通过上下文实现主题

+   利用上下文来管理全局状态

# 技术要求

应该已经安装了相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Web-Development-with-Hooks/tree/master/Chapter05)

查看以下视频以查看代码的实际操作：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行提供的代码示例。重要的是您自己编写代码，以便能够正确学习和理解。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始本章。

# 介绍 React 上下文

在之前的章节中，我们从`App`组件传递了`user`状态和`dispatch`函数到`UserBar`组件；然后从`UserBar`组件传递到`Logout`、`Login`和`Register`组件。React 上下文提供了解决这种繁琐的跨多个组件级别传递 props 的方法，它允许我们在组件之间共享值，而无需通过 props 显式传递它们。正如我们将看到的，React 上下文非常适合在整个应用程序中共享值。

首先，我们将更仔细地看一下传递 props 的问题。然后，我们将介绍 React 上下文作为解决方案。

# 传递 props

在深入学习 React 上下文之前，让我们回顾一下我们在之前章节中实现的内容，以便对上下文解决的问题有所了解：

1.  在`src/App.js`中，我们定义了`user`状态和`dispatch`函数：

```jsx
 const  [  state,  dispatch  ]  =  useReducer(appReducer,  { user:  '', posts:  defaultPosts  })
 const  {  user,  posts  }  =  state
```

1.  然后，我们将`user`状态和`dispatch`函数传递给`UserBar`组件（以及`CreatePost`组件）：

```jsx
    return ( <div  style={{ padding: 8 }}> <UserBar  user={user} dispatch={dispatch**}** /> <br /> {user  && <CreatePost  user={user} posts={posts} dispatch={dispatch**}** />} <br /> <hr /> <PostList  posts={posts} /> </div> )
```

1.  在`src/user/UserBar.js`组件中，我们将`user`状态作为 prop，并将其传递给`Logout`组件。我们还将`dispatch`函数作为 prop，并将其传递给`Logout`、`Login`和`Register`组件：

```jsx
export  default  function  UserBar  ({  user,  dispatch  })  { if (user) { return  <Logout  user={user} dispatch={dispatch**}** /> }  else  { return ( <React.Fragment> <Login  dispatch={dispatch**}** /> <Register  dispatch={dispatch**}** /> </React.Fragment>
        ) } }
```

1.  最后，我们在`Logout`、`Login`和`Register`组件中使用了`dispatch`和`user`props。

React 上下文允许我们跳过步骤 2 和 3，直接从步骤 1 跳到步骤 4。可以想象，对于更大的应用程序，上下文变得更加有用，因为我们可能需要在许多级别上传递 props。

# 介绍 React 上下文

React 上下文用于在 React 组件树中共享值。通常，我们希望共享全局值，例如`user`状态和`dispatch`函数，应用程序的主题或所选择的语言。

React 上下文由两部分组成：

+   提供者，提供（设置）值

+   消费者，消耗（使用）值

首先，我们将看一下上下文是如何工作的，使用一个简单的例子，然后在下一节中，我们将在我们的博客应用中实现它们。我们使用`create-react-app`工具创建一个新项目。在我们的简单示例中，我们将定义一个主题上下文，其中包含应用程序的主要颜色。

# 定义上下文

首先，我们必须定义上下文。自从引入 Hooks 以来，这种工作方式并没有改变。

我们只需使用`React.createContext(defaultValue)`函数创建一个新的上下文对象。我们将默认值设置为`{ primaryColor: 'deepskyblue' }`，因此当没有提供者定义时，我们的默认主要颜色将是`'deepskyblue'`。

在`src/App.js`中，在`App`函数之前添加以下定义：

```jsx
export const ThemeContext = React.createContext({ primaryColor: 'deepskyblue' })
```

请注意，我们在这里导出`ThemeContext`，因为我们将需要导入它作为消费者。

这就是我们使用 React 定义上下文所需做的一切。现在我们只需要定义消费者。

# 定义消费者

现在，我们必须在我们的`Header`组件中定义消费者。现在我们将以传统方式做这个，然后在下一步中使用 Hooks 来定义消费者：

1.  创建一个新的`src/Header.js`文件

1.  首先，我们必须从`App.js`文件中导入`ThemeContext`：

```jsx
import React from 'react'
import { ThemeContext } from './App'
```

1.  现在，我们可以定义我们的组件，在这里我们使用`ThemeContext.Consumer`组件和一个`render`函数作为`children`属性，以便利用上下文值：

```jsx
const Header = ({ text }) => (
    <ThemeContext.Consumer>
        {theme => (
```

1.  在`render`函数中，我们现在可以利用上下文值来设置我们的`Header`组件的`color`样式：

```jsx

            <h1 style={{ color: theme.primaryColor }}>{text}</h1>
        )}
    </ThemeContext.Consumer>
)

export default Header
```

1.  现在，我们仍然需要在`src/App.js`中导入`Header`组件，通过添加以下`import`语句：

```jsx
import Header from './Header'
```

1.  然后，我们用以下代码替换当前的`App`函数：

```jsx
const App = () => (
    <Header text="Hello World" />
)

export default App
```

像这样使用上下文是有效的，但是，正如我们在第一章中学到的那样，以这种方式使用带有`render`函数 props 的组件会使我们的 UI 树混乱，并使我们的应用程序更难以调试和维护。

# 使用 Hooks

使用上下文的更好方法是使用`useContext` Hook！这样，我们可以像使用`useState` Hook 一样使用上下文值：

1.  编辑`src/Header.js`。首先，我们从 React 中导入`useContext` Hook，以及从`src/App.js`中导入`ThemeContext`对象：

```jsx
import React, { useContext } from 'react'
import { ThemeContext } from './App'
```

1.  然后，我们创建我们的`Header`组件，现在我们定义`useContext` Hook：

```jsx
const Header = ({ text }) => {
 const theme = useContext(ThemeContext)
```

1.  我们组件的其余部分将与以前相同，只是现在，我们可以简单地返回我们的`Header`组件，而不需要使用额外的组件来作为消费者：

```jsx
    return <h1 style={{ color: theme.primaryColor }}>{text}</h1>
}

export default Header
```

正如我们所看到的，使用 Hooks 使我们的上下文消费者代码更加简洁。此外，它将更容易阅读，维护和调试。

我们可以看到标题现在的颜色是`deepskyblue`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/f75e52bf-5b27-4664-87f2-e2c67672250d.png)

一个使用上下文 Hook 的简单应用程序！

正如我们所看到的，我们的主题上下文成功为标题提供了主题。

# 定义提供程序

当没有定义提供程序时，上下文使用传递给`React.createContext`的默认值。当组件没有嵌入在应用程序中时，这对于调试组件非常有用。例如，我们可以调试单个组件作为独立组件。在应用程序中，我们通常希望使用提供程序来提供上下文的值，我们现在将定义它。

编辑`src/App.js`，在我们的`App`函数中，我们简单地用`<ThemeContext.Provider>`组件包装`Header`组件，其中我们将`coral`作为`primaryColor`传递：

```jsx
const App = () => (
    <ThemeContext.Provider value={{ primaryColor: 'coral' }}>
        <Header text="Hello World" />
    </ThemeContext.Provider>
)

export default App
```

我们现在可以看到我们的标题颜色从 `deepskyblue` 变为 `coral`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/63746442-6a7f-4f42-a9a6-834f8c09f619.png)

我们的提供者改变了标题的颜色

如果我们想要更改上下文的值，我们可以简单地调整传递给`Provider`组件的`value`属性。

请注意，当我们在没有将`value`属性传递给它的情况下定义提供者时，上下文的默认值不会被使用！如果我们定义一个没有`value`属性的提供者，那么上下文的值将是`undefined`。

现在我们已经为我们的上下文定义了单个提供者，让我们继续定义多个嵌套提供者。

# 嵌套提供者

使用 React 上下文，还可以为同一上下文定义多个提供者。使用这种技术，我们可以在应用程序的某些部分覆盖上下文值。让我们考虑之前的例子，并向其添加第二个标题：

1.  编辑 `src/App.js`，并添加第二个 `Header` 组件：

```jsx
const App = () => (
    <ThemeContext.Provider value={{ primaryColor: 'coral' }}>
        <Header text="Hello World" />
 <Header text="This is a test" />
    </ThemeContext.Provider>
)

export default App
```

1.  现在，使用不同的`primaryColor`定义第二个`Provider`组件：

```jsx
const App = () => (
    <ThemeContext.Provider value={{ primaryColor: 'coral' }}>
        <Header text="Hello World" />
 <ThemeContext.Provider value={{ primaryColor: 'deepskyblue' }}> <Header text="This is a test" />
        </ThemeContext.Provider>
    </ThemeContext.Provider>
)

export default App
```

如果我们在浏览器中打开应用程序，第二个标题现在与第一个标题的颜色不同：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/02a3debe-ceb4-486c-8073-c72a50c12595.png)

使用嵌套提供者覆盖上下文值

正如我们所看到的，我们可以通过定义提供者来覆盖 React 上下文的值。提供者也可以嵌套，因此可以覆盖组件树中较高提供者的值。

# 示例代码

小主题上下文示例的示例代码可以在`Chapter05/chapter5_1`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 上下文的替代方案

但是，我们应该小心，不要经常使用 React 上下文，因为这会使组件的重用变得更加困难。我们只应在需要在许多不同嵌套级别的组件中访问数据时使用上下文。此外，我们需要确保只使用上下文来存储不经常更改的数据。上下文频繁更改的值可能导致整个组件树重新渲染，从而导致性能问题。因此，对于频繁更改的值，我们应该使用 Redux 或 MobX 等状态管理解决方案。

如果我们只想避免传递 props，我们可以传递渲染的组件而不是数据。例如，假设我们有一个`Page`组件，它渲染一个`Header`组件，后者又渲染一个`Profile`组件，然后渲染一个`Avatar`组件。我们在`Page`组件中得到一个`headerSize`属性，我们需要在`Header`组件中使用它，但也需要在`Avatar`组件中使用它。我们可以这样做，而不是通过多个级别传递 props：

```jsx
function Page ({ headerSize }) {
    const profile = (
        <Profile>
            <Avatar size={headerSize} />
        </Profile>
    )
    return <Header size={headerSize} profile={profile} />
}
```

现在，只有`Page`组件需要知道`headerSize`属性，而且不需要在树中进一步传递。在这种情况下，上下文是不必要的。

这种模式被称为**控制反转**，它可以使您的代码比传递 props 或使用上下文更清晰。然而，我们也不应该总是使用这种模式，因为它会使高级组件变得更加复杂。

# 实现主题

在学习了如何在一个小例子中实现主题之后，我们现在要在我们的博客应用程序中使用 React 上下文和钩子来实现主题。

# 定义上下文

首先，我们必须定义上下文。在我们的博客应用程序中，我们将创建一个单独的文件来定义上下文，而不是在`src/App.js`文件中定义它。将上下文放在单独的文件中可以更容易地在以后进行维护。此外，我们总是知道从哪里导入上下文，因为文件名清晰明了。

让我们开始定义一个主题上下文：

1.  创建一个新的`src/contexts.js`文件。

1.  然后，我们导入`React`：

```jsx
import React from 'react'
```

1.  接下来，我们定义`ThemeContext`。与我们在小例子中一样，我们将默认的`primaryColor`设置为`deepskyblue`。此外，我们将`secondaryColor`设置为`coral`：

```jsx
export const ThemeContext = React.createContext({
    primaryColor: 'deepskyblue',
    secondaryColor: 'coral'
})
```

现在我们已经定义了上下文，我们可以继续定义上下文钩子。

# 定义上下文钩子

在定义上下文之后，我们将使用上下文钩子来定义我们的消费者。我们首先创建一个新的头部组件，然后为现有的`Post`组件定义一个上下文钩子。

# 创建头部组件

首先，我们创建一个新的`Header`组件，它将在我们应用程序的`primaryColor`中显示`React Hooks Blog`。

现在让我们创建`Header`组件：

1.  创建一个新的`src/Header.js`文件。

1.  在这个文件中，我们导入`React`和`useContext`钩子：

```jsx
import React, { useContext } from 'react'
```

1.  接下来，我们从先前创建的`src/contexts.js`文件中导入`ThemeContext`：

```jsx
import { ThemeContext } from `'./contexts'
```

1.  然后，我们定义我们的`Header`组件和上下文钩子。我们不再将上下文值存储在`theme`变量中，而是使用解构直接提取`primaryColor`值：

```jsx
const Header = ({ text }) => {
    const { primaryColor } = useContext(ThemeContext)
```

1.  最后，我们返回`h1`元素，就像我们在我们的小例子中做的那样，并`export` `Header`组件：

```jsx
    return <h1 style={{ color: primaryColor }}>{text}</h1>
}

export default Header
```

现在我们已经定义了`Header`组件，我们可以使用它了。

# 使用`Header`组件

创建`Header`组件后，我们将在`App`组件中使用它，如下所示：

1.  编辑`src/App.js`，并导入`Header`组件：

```jsx
import Header from './Header'
```

1.  然后，在`UserBar`组件之前呈现`Header`组件：

```jsx
    return (
        <div style={{ padding: 8 }}>
            <Header text="React Hooks Blog" />
            <UserBar user={user} dispatch={dispatch} />
```

您可能希望将`React Hooks Blog`值重构为传递给`App`组件的 prop（应用程序配置），因为我们在这个组件中已经使用了三次。

现在，我们的`Header`组件将在应用程序中呈现，我们可以继续在`Post`组件中实现上下文钩子。

# 实现`Post`组件的上下文钩子

接下来，我们希望用辅助颜色显示`Post`标题。为此，我们需要为`Post`组件定义一个上下文钩子，如下所示：

1.  编辑`src/post/Post.js`，并调整`import`语句以导入`useContext`钩子：

```jsx
import React, { useContext } from 'react'
```

1.  接下来，我们导入`ThemeContext`：

```jsx
import { ThemeContext } from '../contexts'
```

1.  然后，在`Post`组件中定义一个上下文钩子，并通过解构从主题中获取`secondaryColor`值：

```jsx
export  default  function  Post  ({  title,  content,  author  })  {
    **const { secondaryColor } = useContext(ThemeContext)** 
```

1.  最后，我们使用`secondaryColor`值来设置我们的`h3`元素的样式：

```jsx
    return (
        <div>
            <h3 style={{ color: secondaryColor }}>{title}</h3>
```

如果我们现在查看我们的应用程序，我们可以看到`ThemeContext`中两种颜色都被正确使用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/95ba1a24-ae40-4a7f-b635-768d53db8fd0.png)

我们的 ThemeContext 在行动

正如我们所看到的，我们的应用程序现在使用主标题的主要颜色，以及帖子标题的辅助颜色。

# 定义提供程序

现在，我们的上下文钩子使用上下文指定的默认值，当没有定义提供程序时。为了能够更改值，我们需要定义一个提供程序。

让我们开始定义提供程序：

1.  编辑`src/App.js`，并导入`ThemeContext`：

```jsx
import { ThemeContext } from './contexts'
```

1.  用`ThemeContext.Provider`组件包装整个应用程序，提供与我们之前设置为默认值的相同主题：

```jsx
    return (
 <ThemeContext.Provider value={{ primaryColor: 'deepskyblue', secondaryColor: 'coral' }}> <div style={{ padding: 8 }}>
                <Header text="React Hooks Blog" />
                ...
                <PostList posts={posts} />
            </div>
 </ThemeContext.Provider>
    )
```

我们的应用程序应该看起来和以前完全一样，但现在我们正在使用提供程序中的值！

# 动态更改主题

现在我们已经定义了一个提供程序，我们可以使用它来动态改变主题。我们将不再向提供程序传递静态值，而是使用一个 State Hook 来定义当前主题。然后，我们将实现一个改变主题的组件。

# 使用上下文提供程序的 State Hook

首先，我们将定义一个新的 State Hook，我们将使用它来设置上下文提供程序的值。

让我们定义一个 State Hook，并在上下文提供程序中使用它：

1.  编辑`src/App.js`，并导入`useState` Hook：

```jsx
import React, { useReducer, useEffect, useState } from 'react'
```

1.  在`App`组件的开头定义一个新的 State Hook；在这里，我们将默认值设置为我们的默认主题：

```jsx
export default function App () {
 const [ theme, setTheme ] = useState({
 primaryColor: 'deepskyblue',
 secondaryColor: 'coral'
 })
```

1.  然后，我们将`theme`值传递给`ThemeContext.Provider`组件：

```jsx
    return (
        <ThemeContext.Provider value={theme}>
```

我们的应用程序看起来仍然与以前一样，但现在我们已经准备好动态改变我们的主题了！

# 实现 ChangeTheme 组件

我们主题功能的最后部分是一个组件，可以通过利用我们之前定义的 State Hook 来动态改变主题。State Hook 将重新渲染`App`组件，这将改变传递给`ThemeContext.Provider`的值，进而重新渲染所有使用`ThemeContext` Context Hook 的组件。

让我们开始实现`ChangeTheme`组件：

1.  创建一个新的`src/ChangeTheme.js`文件。

1.  和往常一样，我们必须先导入`React`，然后才能定义一个组件：

```jsx
import React from 'react'
```

1.  为了能够轻松地以后添加新的主题，我们将创建一个常量`THEMES`数组，而不是手动复制和粘贴不同主题的代码。这将使我们的代码更加简洁，更易于阅读：

```jsx
const THEMES = [
    { primaryColor: 'deepskyblue', secondaryColor: 'coral' },
    { primaryColor: 'orchid', secondaryColor: 'mediumseagreen' }
]
```

给硬编码的常量值一个特殊的名称是个好主意，比如用大写字母写整个变量名。以后，将所有这些可配置的硬编码值放在一个单独的`src/config.js`文件中可能是有意义的。

1.  接下来，我们定义一个组件来渲染单个`theme`：

```jsx
function ThemeItem ({ theme, active, onClick }) {
```

1.  在这里，我们渲染一个链接，并显示主题的小预览，显示主要颜色和次要颜色：

```jsx
    return (
        <span onClick={onClick} style={{ cursor: 'pointer', paddingLeft: 8, fontWeight: active ? 'bold' : 'normal' }}>
            <span style={{ color: theme.primaryColor }}>Primary</span> / <span style={{ color: theme.secondaryColor }}>Secondary</span>
        </span>
    )
}
```

在这里，我们将光标设置为`pointer`，以使元素看起来可点击。我们也可以使用`<a>`元素；但是，如果我们没有有效的链接目标，比如一个单独的页面，这是不推荐的。

1.  然后，我们定义`ChangeTheme`组件，它接受`theme`和`setTheme` props：

```jsx
export default function ChangeTheme ({ theme, setTheme }) {
```

1.  接下来，我们定义一个函数来检查一个主题对象是否是当前活动的主题：

```jsx
    function isActive (t) {
        return t.primaryColor === theme.primaryColor && t.secondaryColor === theme.secondaryColor
    }
```

1.  现在，我们使用`.map`函数来渲染所有可用的主题，并在点击它们时调用`setTheme`函数：

```jsx
    return (
        <div>
            Change theme:
            {THEMES.map((t, i) =>
                <ThemeItem key={'theme-' + i} theme={t} active={isActive(t)} onClick={() => setTheme(t)} />
            )}
        </div>
    )
}
```

1.  最后，在`src/App.js`中的`Header`组件之后导入并渲染`ChangeTheme`组件：

```jsx
import ChangeTheme from './ChangeTheme'
// ...
    return (
        <ThemeContext.Provider value={theme}>
            <div style={{ padding: 8 }}>
                <Header text="React Hooks Blog" />
                <ChangeTheme theme={theme} setTheme={setTheme} />
                <br /> 
```

我们可以看到，我们现在有一种方法可以在我们的应用程序中更改主题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/fc47c205-d957-4bc8-a052-0e4e8808abf4.png)

我们在更改主题后，使用上下文钩子与状态钩子相结合

现在，我们有一个通过 Hooks 消耗的上下文，也可以通过 Hooks 进行更改！

# 示例代码

我们的博客应用程序中主题功能的示例代码可以在`Chapter05/chapter5_2`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用上下文进行全局状态

在学习了如何使用 React 上下文在我们的博客应用程序中实现主题之后，我们现在将使用上下文来避免手动传递`state`和`dispatch` props 以用于全局应用程序状态。

# 定义 StateContext

我们首先在我们的`src/contexts.js`文件中定义上下文。

在`src/contexts.js`中，我们定义了`StateContext`，它将存储`state`值和`dispatch`函数：

```jsx
export const StateContext = React.createContext({
    state: {},
    dispatch: () => {}
})
```

我们将`state`值初始化为空对象，并将`dispatch`函数初始化为空函数，当没有提供程序时将使用它。

# 定义上下文提供程序

现在，我们将在我们的`src/App.js`文件中定义上下文提供程序，该提供程序将从现有的 Reducer Hook 中获取值。

现在让我们为全局状态定义上下文提供程序：

1.  在`src/App.js`中，通过调整现有的`import`语句导入`StateContext`：

```jsx
import  {  ThemeContext**, StateContext**  }  from  './contexts'
```

1.  然后，我们通过从我们的`App`函数中返回它来定义一个新的上下文提供程序：

```jsx
    return (
 <StateContext.Provider value={{ state, dispatch }}>
            <ThemeContext.Provider value={theme}>
                ...
            </ThemeContext.Provider>
 </StateContext.Provider>
    )
```

现在，我们的上下文提供程序为我们的整个应用程序提供了`state`对象和`dispatch`函数，我们可以继续使用上下文值。

# 使用 StateContext

现在，我们已经定义了我们的上下文和提供程序，我们可以在各种组件中使用`state`对象和`dispatch`函数。

我们首先删除在`src/App.js`中手动传递给组件的 props。删除以下用粗体标记的代码段：

```jsx
        <div style={{ padding: 8 }}>
            <Header text="React Hooks Blog" />
            <ChangeTheme theme={theme} setTheme={setTheme} />
            <br />
            <UserBar user={user} dispatch={dispatch} />
            <br />
            {user && <CreatePost user={user} posts={posts} dispatch={dispatch} />}
            <br />
            <hr />
            <PostList posts={posts} />
        </div>
```

由于我们正在使用上下文，因此不再需要手动传递 props。我们现在可以继续重构组件。

# 重构用户组件

首先，我们重构用户组件，然后再转向帖子组件。

现在让我们重构与用户相关的组件：

1.  编辑`src/user/UserBar.js`，并且移除那里的 props（加粗标记的代码应该被移除），因为我们不再需要手动传递它们了：

```jsx
export  default  function  UserBar  (**{** user,  dispatch **}**)  {
 if (user) { return  <Logout  user={user} dispatch={dispatch**}** /> }  else  { return ( <React.Fragment> <Login  dispatch={dispatch**}** /> <Register  dispatch={dispatch**}** /> </React.Fragment> ) } } 
```

1.  然后，我们在`src/user/UserBar.js`中导入`useContext` Hook 和`StateContext`，以便能够判断用户是否已登录：

```jsx
import React, { useContext } from 'react'
import { StateContext } from '../contexts'
```

1.  现在，我们可以使用 Context Hook 从我们的`state`对象中获取`user`状态：

```jsx
export default function UserBar () {
 const { state } = useContext(StateContext)
 const { user } = state
```

1.  同样地，我们在`src/user/Login.js`中导入`useContext`和`StateContext`：

```jsx
import React, { useState, useContext } from 'react'
import { StateContext } from '../contexts'
```

1.  然后，我们移除`dispatch` prop，并使用 Context Hook 代替：

```jsx
export default function Login () {
 const { dispatch } = useContext(StateContext)
```

1.  我们在`src/user/Register.js`组件中重复相同的过程：

```jsx
import React, { useState, useContext } from 'react'
import { StateContext } from '../contexts' export default function Register () { const { dispatch } = useContext(StateContext) 
```

1.  在`src/user/Logout.js`组件中，我们做同样的事情，但也从`state`对象中获取`user`状态：

```jsx
import React, { useContext } from 'react'
import { StateContext } from '../contexts' export default function Logout () { const { state, dispatch } = useContext(StateContext)
    const { user } = state 
```

我们的与用户相关的组件现在使用上下文而不是 props。让我们继续重构与帖子相关的组件。

# 重构帖子组件

现在，唯一剩下的就是重构帖子组件；然后我们整个应用程序都将使用 React 上下文来管理全局状态：

1.  我们从`src/post/PostList.js`组件开始，导入`useContext`和`StateContext`，移除 props，并使用 Context Hook 代替：

```jsx
import React, { useContext } from 'react'
import { StateContext } from '../contexts'

import Post from './Post'

export default function PostList () {
 const { state } = useContext(StateContext)
 const { posts } = state
```

1.  我们对`CreatePost`组件做同样的事情，这是我们需要重构的最后一个组件：

```jsx
import React, { useState, useContext } from 'react'
import { StateContext } from '../contexts'

export default function CreatePost () {
 const { state, dispatch } = useContext(StateContext)
 const { user } = state
```

我们的应用程序的工作方式与以前相同，但现在我们使用上下文来管理全局状态，这使我们的代码更清晰，并避免了必须传递 props！

# 示例代码

我们博客应用程序中全局状态上下文的示例代码可以在`Chapter05/chapter5_3`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 总结

在本章中，我们首先学习了 React 上下文作为在多个级别的 React 组件之间传递 props 的替代方法。然后，我们学习了上下文提供者和消费者，以及通过 Hooks 定义消费者的新方法。接下来，我们学习了何时不应该使用上下文，以及何时应该使用控制反转。然后，我们通过在博客应用程序中实现主题来实践所学的知识。最后，我们在博客应用程序中使用 React 上下文进行全局状态管理。

在下一章中，我们将学习如何使用 React 和 Hooks 从服务器请求数据。然后，我们将学习`React.memo`来防止组件不必要地重新渲染，以及 React Suspense 来在需要时延迟加载组件。

# 问题

为了总结本章学到的知识，请尝试回答以下问题：

1.  上下文避免了哪些问题？

1.  上下文由哪两部分组成？

1.  使用上下文时，两部分都必须定义吗？

1.  使用 Hooks 而不是传统上下文消费者的优势是什么？

1.  上下文的替代方案是什么，何时应该使用它？

1.  我们如何实现动态更改上下文？

1.  何时使用上下文来管理状态是有意义的？

# 进一步阅读

如果您对本章中探讨的概念感兴趣，可以查看以下阅读材料：

+   React 上官方文档关于上下文：[`reactjs.org/docs/context.html`](https://reactjs.org/docs/context.html)

+   有关组合与继承的更多信息：[`reactjs.org/docs/composition-vs-inheritance.html`](https://reactjs.org/docs/composition-vs-inheritance.html)

+   HTML 颜色代码列表（如果您想定义新主题）：[`www.rapidtables.com/web/color/html-color-codes.html.`](https://www.rapidtables.com/web/color/html-color-codes.html)


# 第六章：实现请求和 React Suspense

在之前的章节中，我们学习了如何使用 React 上下文作为手动传递 props 的替代方法。我们了解了上下文提供者、消费者以及如何使用 Hooks 作为上下文消费者。接下来，我们学习了作为上下文替代方法的控制反转。最后，我们在博客应用程序中使用上下文实现了主题和全局状态。

在本章中，我们将设置一个简单的后端服务器，该服务器将从**JavaScript 对象表示**（**JSON**）文件中生成，使用`json-server`工具。然后，我们将通过使用 Effect Hook 结合 State Hook 来实现请求资源。接下来，我们将使用`axios`和`react-request-hook`库做同样的事情。最后，我们将通过使用`React.memo`来防止不必要的重新渲染，并通过 React Suspense 来懒加载组件。

本章将涵盖以下主题：

+   使用 Hooks 请求资源

+   使用`React.memo`防止不必要的重新渲染

+   使用 React Suspense 实现延迟加载

# 技术要求

应该已经安装了相当新的 Node.js 版本（v11.12.0 或更高）。还需要安装 Node.js 的`npm`包管理器。

本章的代码可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter06`](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter06)[.](https://github.com/PacktPublishing/Learn-React-Hooks/tree/master/Chapter06)

查看以下视频，了解代码的运行情况：

[`bit.ly/2Mm9yoC`](http://bit.ly/2Mm9yoC)

请注意，强烈建议您自己编写代码。不要简单地运行提供的代码示例。重要的是您自己编写代码，以便您能够正确学习和理解。但是，如果遇到任何问题，您可以随时参考代码示例。

现在，让我们开始本章。

# 使用 Hooks 请求资源

在本节中，我们将学习如何使用 Hooks 从服务器请求资源。首先，我们将只使用 JavaScript 的`fetch`函数和`useEffect`/`useState` Hooks 来实现请求。然后，我们将学习如何使用`axios`库结合`react-request-hook`来请求资源。

# 设置虚拟服务器

在我们实现请求之前，我们需要创建一个后端服务器。由于我们目前专注于用户界面，我们将设置一个虚拟服务器，这将允许我们测试请求。我们将使用`json-server`工具从 JSON 文件创建一个完整的**表述状态转移**（**REST**）API。

# 创建 db.json 文件

为了能够使用`json-server`工具，首先我们需要创建一个`db.json`文件，其中将包含服务器的完整数据库。`json-server`工具将允许您执行以下操作：

+   `GET`请求，用于从文件中获取数据

+   `POST`请求，用于将新数据插入文件中

+   `PUT`和`PATCH`请求，用于调整现有数据

+   删除请求，用于删除数据

对于所有修改操作（`POST`，`PUT`，`PATCH`和`DELETE`），更新后的文件将由工具自动保存。

我们可以使用我们为帖子定义的默认状态作为帖子减速器的现有结构。但是，我们需要确保提供一个`id`值，以便稍后可以查询数据库：

```jsx
[ { **"id": "react-hooks",** "title": "React Hooks", "content":  "The greatest thing since sliced bread!", "author":  "Daniel Bugl"  }, { **"id": "react-fragments",** "title":  "Using React Fragments", "content":  "Keeping the DOM tree clean!", "author":  "Daniel Bugl"  } ]
```

至于用户，我们需要想出一种存储用户名和密码的方法。为简单起见，我们只是以明文形式存储密码（在生产环境中不要这样做！）。在这里，我们还需要提供一个`id`值：

```jsx
[
    { "id": 1, "username": "Daniel Bugl", "password": "supersecure42" }
]
```

此外，我们将在我们的数据库中存储主题。为了调查是否正确地从我们的数据库中提取主题，我们现在将定义第三个主题。和往常一样，每个主题都需要一个`id`值：

```jsx
[
    { "id": 1, "primaryColor": "deepskyblue", "secondaryColor": "coral" },
    { "id": 2, "primaryColor": "orchid", "secondaryColor": "mediumseagreen" },
    { "id": 3, "primaryColor": "darkslategray", "secondaryColor": "slategray" }
]
```

现在，我们只需要将这三个数组合并成一个单独的 JSON 对象，将帖子数组存储在`posts`键下，将用户数组存储在`users`键下，将主题数组存储在`themes`键下。

让我们开始创建用作后端服务器数据库的 JSON 文件：

1.  在我们应用程序文件夹的根目录中创建一个新的`server/`目录。

1.  创建一个`server/db.json`文件，其中包含以下内容。我们可以使用 Reducer Hook 中的现有状态。但是，由于这是一个数据库，我们需要为每个元素提供一个`id`值（用粗体标记）：

```jsx
{
    "posts": [ { **"id": "react-hooks",** "title": "React Hooks", "content":  "The greatest thing since sliced bread!", "author":  "Daniel Bugl"  }, { **"id": "react-fragments",** "title":  "Using React Fragments", "content":  "Keeping the DOM tree clean!", "author":  "Daniel Bugl"  }
 ],
    "users": [
        { "id": 1, "username": "Daniel Bugl", "password": "supersecure42" }
    ],
    "themes": [
        { "id": 1, "primaryColor": "deepskyblue", "secondaryColor": "coral" },
        { "id": 2, "primaryColor": "orchid", "secondaryColor": "mediumseagreen" },
        { "id": 3, "primaryColor": "darkslategray", "secondaryColor": "slategray" }
    ]
}
```

对于`json-server`工具，我们只需要一个 JSON 文件作为数据库，该工具将为我们创建一个完整的 REST API。

# 安装 json-server 工具

现在，我们将通过使用`json-server`工具安装并启动我们的后端服务器：

1.  首先，我们将通过`npm`安装`json-server`工具：

```jsx
> npm install --save json-server
```

1.  现在，我们可以通过调用以下命令启动我们的后端服务器：

```jsx
>npx json-server --watch server/db.json
```

`npx`命令执行在项目中本地安装的命令。我们需要在这里使用`npx`，因为我们没有全局安装`json-server`工具（通过`npm install -g json-server`）。

我们执行了`json-server`工具，并让它监视我们之前创建的`server/db.json`文件。`--watch`标志意味着它将监听文件的更改，并自动刷新。

现在，我们可以转到`http://localhost:3000/posts/react-hooks`来查看我们的帖子对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/0c6cd543-2149-4d60-b028-38817018abf5.png)

我们简单的 JSON 服务器正在工作并提供帖子！

正如我们所看到的，这个工具为我们从数据库 JSON 文件创建了一个完整的 REST API！

# 配置 package.json

接下来，我们需要调整我们的`package.json`文件，以便启动服务器，以及我们的客户端（通过`webpack-dev-server`运行）。

让我们开始调整`package.json`文件：

1.  首先，我们通过将其插入到`package.json`文件的`scripts`部分中来创建一个名为`start:server`的新包脚本。我们还确保更改端口，以便它不在与我们的客户端相同的端口上运行：

```jsx
    "scripts": {
        "start:server": "npx json-server --watch server/db.json --port 4000",
        "start": "react-scripts start",
```

1.  然后，我们将`start`脚本重命名为`start:client`：

```jsx
    "scripts": {
        "start:server": "npx json-server --watch server/db.json",
        "start:client": "react-scripts start",
```

1.  接下来，我们安装一个名为`concurrently`的工具，它可以让我们同时启动服务器和客户端：

```jsx
> npm install --save concurrently
```

1.  现在，我们可以使用`concurrently`命令定义一个新的`start`脚本，然后将服务器和客户端命令作为参数传递给它：

```jsx
    "scripts": {
 "start": "npx concurrently \"npm run start:server\" \"npm run start:client\"",
```

现在，运行`npm start`将运行客户端，以及后端服务器。

# 配置代理

最后，我们必须定义一个代理，以确保我们可以从与客户端相同的**统一资源定位符（URL）**请求我们的 API。这是必需的，否则，我们将不得不处理跨站点请求，这更加复杂。我们将定义一个代理，将从`http://localhost:3000/api/`转发请求到`http://localhost:4000/`。

现在，让我们配置代理：

1.  首先，我们必须安装`http-proxy-middleware`包：

```jsx
> npm install --save http-proxy-middleware
```

1.  然后，我们创建一个新的`src/setupProxy.js`文件，内容如下：

```jsx
const proxy = require('http-proxy-middleware')

module.exports = function (app) {
    app.use(proxy('/api', {
```

1.  接下来，我们必须定义代理的目标，即后端服务器，运行在`http://localhost:4000`上：

```jsx
        target: 'http://localhost:4000',
```

1.  最后，我们必须定义一个路径重写规则，它在转发请求到我们的服务器之前移除了`/api`前缀：

```jsx
        pathRewrite: { '^/api': '' }
    }))
}
```

前面的代理配置将`/api`链接到我们的后端服务器；因此，我们现在可以通过以下命令同时启动服务器和客户端：

```jsx
> npm start
```

然后，我们可以通过打开`http://localhost:3000/api/posts/react-hooks`来访问 API！

# 定义路由

默认情况下，`json-server`工具定义了以下路由：[`github.com/typicode/json-server#routes`](https://github.com/typicode/json-server#routes)。

我们还可以通过创建一个`routes.json`文件来定义自己的路由，我们可以将现有路由重写为其他路由：[`github.com/typicode/json-server#add-custom-routes`](https://github.com/typicode/json-server#add-custom-routes)。

对于我们的博客应用程序，我们将定义一个单独的自定义路由：`/login/:username/:password`。我们将把这个路由链接到一个`/users?username=:username&password=:password`查询，以便找到具有给定用户名和密码组合的用户。

现在我们将为我们的应用程序定义自定义登录路由：

1.  创建一个新的`server/routes.json`文件，内容如下：

```jsx
{
    "/login/:username/:password": "/users?username=:username&password=:password"
}
```

1.  然后，调整`package.json`文件中的`start:server`脚本，并添加`--routes`选项，如下所示：

```jsx
        "start:server": "npx json-server --watch server/db.json --port 4000 --routes server/routes.json",
```

现在，我们的服务器将为我们提供自定义登录路由，我们将在本章后面使用它！我们可以尝试通过在浏览器中打开以下 URL 来登录：`http://localhost:3000/api/login/Daniel%20Bugl/supersecure42`。这将返回一个用户对象；因此，登录成功了！

我们可以在浏览器中看到用户对象以文本形式返回：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/c041ed70-364f-4077-8550-429c49d306f2.png)

直接在浏览器中访问我们的自定义路由

正如我们所看到的，访问我们的自定义路由是有效的！我们现在可以使用它来登录用户。

# 示例代码

示例代码可以在`Chapter06/chapter6_1`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 Effect 和 State/Reducer Hooks 实现请求

在我们使用库来使用 Hooks 实现请求之前，我们将手动实现它们，使用 Effect Hook 来触发请求，使用 State/Reducer Hooks 来存储结果。

# 使用 Effect 和 State Hooks 进行请求

首先，我们将从服务器请求主题，而不是硬编码主题列表。

让我们使用 Effect Hook 和 State Hook 来实现请求主题：

1.  在`src/ChangeTheme.js`文件中，调整 React 的`import`语句，以便导入`useEffect`和`useState` Hooks：

```jsx
import React, { useEffect, useState } from 'react'
```

1.  删除`THEMES`常量，即以下所有代码：

```jsx
const  THEMES  = [ { primaryColor:  'deepskyblue', secondaryColor:  'coral'  }, { primaryColor:  'orchid', secondaryColor:  'mediumseagreen'  } ] 
```

1.  在`ChangeTheme`组件中，定义一个新的`useState` Hook 来存储主题：

```jsx
export default function ChangeTheme ({ theme, setTheme }) {
 const [ themes, setThemes ] = useState([])
```

1.  然后定义一个`useEffect` Hook，我们将在其中进行请求：

```jsx
    useEffect(() => {
```

1.  在这个 Hook 中，我们使用`fetch`来请求一个资源；在这种情况下，我们请求`/api/themes`：

```jsx
        fetch('/api/themes')
```

1.  Fetch 利用了 Promise API；因此，我们可以使用`.then()`来处理结果。首先，我们必须将结果解析为 JSON：

```jsx
            .then(result => result.json())
```

1.  最后，我们使用来自我们请求的主题数组调用`setThemes`：

```jsx
            .then(themes => setThemes(themes))
```

我们还可以将前面的函数缩短为`.then(setThemes)`，因为我们只传递了从`.then()`中获取的`themes`参数。

1.  目前，这个 Effect Hook 应该只在组件挂载时触发，所以我们将空数组作为第二个参数传递给`useEffect`。这确保了 Effect Hook 没有依赖项，因此只会在组件挂载时触发：

```jsx
    }, [])
```

1.  现在，唯一剩下的事情就是用我们从 Hook 中获取的`themes`值替换`THEMES`常量：

```jsx
            {themes.map(t =>
```

正如我们所看到的，现在有三个主题可用，都是通过我们的服务器从数据库加载的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/5aa425f0-21e5-4624-9b93-3c1531df8414.png)

使用 Hooks 从我们的服务器加载了三个主题！

我们的主题现在是从后端服务器加载的，我们可以继续通过 Hooks 请求帖子。

# 使用 Effect 和 Reducer Hooks 进行请求

现在，我们将使用后端服务器来请求帖子数组，而不是将其硬编码为`postsReducer`的默认值。

让我们使用 Effect Hook 和 Reducer Hook 来请求帖子：

1.  **删除**`src/App.js`中的`defaultPosts`常量定义，即以下所有代码：

```jsx
const  defaultPosts  = [ { title:  'React Hooks', content:  'The greatest thing since sliced bread!', author:  'Daniel Bugl'  }, { title:  'Using React Fragments', content:  'Keeping the DOM tree clean!', author:  'Daniel Bugl'  } ]
```

1.  用一个空数组替换`useReducer`函数中的`defaultPosts`常量：

```jsx
 const  [  state,  dispatch  ]  =  useReducer(appReducer,  { user:  '', posts:  []  })
```

1.  在`src/reducers.js`中，在`postsReducer`函数中定义一个新的动作类型，称为`FETCH_POSTS`。这个动作类型将用新的帖子数组替换当前状态：

```jsx
function postsReducer (state, action) {
    switch (action.type) {
 case 'FETCH_POSTS':
 return action.posts
```

1.  在`src/App.js`中，定义一个新的`useEffect` Hook，位于当前的 Hook 之前：

```jsx
    useEffect(() => {
```

1.  在这个 Hook 中，我们再次使用`fetch`来请求一个资源；在这种情况下，我们请求`/api/posts`：

```jsx
        fetch('/api/posts')
            .then(result => result.json())
```

1.  最后，我们使用来自我们请求的`posts`数组分派了一个`FETCH_POSTS`动作：

```jsx
            .then(posts => dispatch({ type: 'FETCH_POSTS', posts }))
```

1.  目前，这个 Effect Hook 应该只在组件挂载时触发，所以我们将空数组作为第二个参数传递给`useEffect`：

```jsx
    }, [])
```

正如我们所看到的，现在帖子是从服务器请求的！我们可以查看 DevTools Network 标签以查看请求：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/317e2749-c1ab-4d39-9043-303e61250ac4.png)

从我们的服务器请求帖子！

现在从后端服务器请求帖子。在下一节中，我们将使用`axios`和`react-request-hook`从服务器请求资源。

# 示例代码

示例代码可以在`Chapter06/chapter6_2`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 axios 和 react-request-hook

在上一节中，我们使用 Effect Hook 触发请求，并使用 Reducer/State Hook 从请求的结果更新状态。与手动实现请求不同，我们可以使用`axios`和`react-request-hook`库轻松地使用 Hooks 来实现请求。

# 设置这些库

在我们开始使用`axios`和`react-request-hook`之前，我们必须设置一个`axios`实例和一个`RequestProvider`组件。

让我们开始设置这些库：

1.  首先，我们安装这些库：

```jsx
>npm install --save react-request-hook axios
```

1.  然后，在`src/index.js`中导入它们：

```jsx
import { RequestProvider } from 'react-request-hook'
import axios from 'axios'
```

1.  现在，我们定义一个`axios`实例，其中我们将`baseURL`设置为`http://localhost:3000/api/`—我们的后端服务器：

```jsx
const axiosInstance = axios.create({
    baseURL: 'http://localhost:3000/api/'
})
```

在我们的`axios`实例配置中，我们还可以定义其他选项，例如请求的默认超时时间或自定义标头。有关更多信息，请查看`axios`文档：[`github.com/axios/axios#axioscreateconfig`](https://github.com/axios/axios#axioscreateconfig)。

1.  最后，我们用`<RequestProvider>`组件包装我们的`<App />`组件。删除以下代码行：

```jsx
ReactDOM.render(<App />, document.getElementById('root'));
```

用以下代码替换它：

```jsx
ReactDOM.render(
    <RequestProvider value={axiosInstance}>
        <App />
    </RequestProvider>,
    document.getElementById('root')
)
```

现在，我们的应用程序已准备好使用 Resource Hooks！

# 使用 useResource Hook

处理请求的更强大的方法是使用`axios`和`react-request-hook`库。使用这些库，我们可以访问可以取消单个请求甚至清除所有待处理请求的功能。此外，使用这些库可以更容易地处理错误和加载状态。

现在我们将实现`useResource` Hook 以从服务器请求主题：

1.  在`src/ChangeTheme.js`中，从`react-request-hook`库中导入`useResource` Hook：

```jsx
import { useResource } from 'react-request-hook'
```

1.  删除先前定义的 State 和 Effect Hooks。

1.  然后，在`ChangeTheme`组件中定义一个`useResource` Hook。该 Hook 返回一个值和一个 getter 函数。调用 getter 函数将请求资源：

```jsx
export default function ChangeTheme ({ theme, setTheme }) {
 const [ themes, getThemes ] = useResource(() => ({
```

在这里，我们使用了`() => { return { } }`的简写语法，即`() => ({ })`。使用这种简写语法可以简洁地编写只返回对象的函数。

1.  在这个 Hook 中，我们传递一个函数，该函数返回有关请求的信息的对象：

```jsx
        url: '/themes',
        method: 'get'
    }))
```

使用`axios`，我们只需要将`/themes`作为`url`传递，因为我们已经定义了包含`/api/`的`baseURL`。

1.  Resource Hook 返回一个带有`data`值、`isLoading`布尔值、`error`对象和`cancel`函数的对象，用于取消挂起的请求。现在，我们从`themes`对象中提取出`data`值和`isLoading`布尔值：

```jsx
    const { data, isLoading } = themes
```

1.  然后，我们定义一个`useEffect` Hook 来触发`getThemes`函数。我们只希望它在组件挂载时触发一次，因此我们将空数组作为第二个参数传递：

```jsx
    useEffect(getThemes, [])
```

1.  此外，我们使用`isLoading`标志在等待服务器响应时显示加载消息：

```jsx
            {isLoading && ' Loading themes...'}
```

1.  最后，我们将`themes`值重命名为从`useResource` Hook 返回的`data`值，并添加条件检查以确保`data`值已经可用：

```jsx
            {data && data.map(t =>
```

如果我们现在看一下我们的应用程序，我们会发现“加载主题…”的消息会在很短的时间内显示，然后从我们的数据库中显示主题！现在我们可以继续使用 Resource Hook 请求帖子。

# 使用 Reducer Hook 与 useResource

`useResource` Hook 已经处理了我们请求结果的状态，所以我们不需要额外的`useState` Hook 来存储状态。然而，如果我们已经有一个现有的 Reducer Hook，我们可以将其与`useResource` Hook 结合使用。

现在我们将在我们的应用程序中实现`useResource` Hook 与 Reducer Hook 的组合使用：

1.  在`src/App.js`中，从`react-request-hook`库中导入`useResource` Hook：

```jsx
import { useResource } from 'react-request-hook'
```

1.  删除先前使用`fetch`请求`/api/posts`的`useEffect` Hook。

1.  定义一个新的`useResource` Hook，在其中请求`/posts`：

```jsx
    const [ posts, getPosts ] = useResource(() => ({
        url: '/posts',
        method: 'get'
    }))
```

1.  定义一个新的`useEffect` Hook，简单地调用`getPosts`：

```jsx
    useEffect(getPosts, [])
```

1.  最后，定义一个`useEffect` Hook，在检查数据是否已经存在后，触发`FETCH_POSTS`动作：

```jsx
    useEffect(() => {
        if (posts && posts.data) {
            dispatch({ type: 'FETCH_POSTS', posts: posts.data })
        }
```

1.  我们确保这个 Effect Hook 在`posts`对象更新时触发：

```jsx
    }, [posts])
```

现在，当我们获取新的帖子时，将会触发`FETCH_POSTS`动作。接下来，我们将处理请求期间的错误。

# 处理错误状态

我们已经在`ChangeTheme`组件中处理了加载状态。现在，我们将实现帖子的错误状态。

让我们开始处理帖子的错误状态：

1.  在`src/reducers.js`中，使用新的动作类型`POSTS_ERROR`定义一个新的`errorReducer`函数：

```jsx
function errorReducer (state, action) {
    switch (action.type) {
        case 'POSTS_ERROR':
            return 'Failed to fetch posts'

        default:
            return state
    }
}
```

1.  将`errorReducer`函数添加到我们的`appReducer`函数中：

```jsx
export default function appReducer (state, action) {
    return {
        user: userReducer(state.user, action),
        posts: postsReducer(state.posts, action),
 error: errorReducer(state.error, action)
    }
}
```

1.  在`src/App.js`中，调整我们的 Reducer Hook 的默认状态：

```jsx
    const [ state, dispatch ] = useReducer(appReducer, { user: '', posts: [], error: '' })
```

1.  从`state`对象中取出`error`值：

```jsx
    const { user, error } = state
```

1.  现在，我们可以调整处理来自`posts`资源的新数据的现有 Effect Hook，在出现错误的情况下分派`POSTS_ERROR`动作：

```jsx
    useEffect(() => {
 if (posts && posts.error) {
 dispatch({ type: 'POSTS_ERROR' })
 }
        if (posts && posts.data) {
            dispatch({ type: 'FETCH_POSTS', posts: posts.data })
        }
    }, [posts])
```

1.  最后，在`PostList`组件之前显示错误消息：

```jsx
 {error && <b>{error}</b>}
                 <PostList />
```

如果现在只启动客户端（通过`npm run start:client`），将显示错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/0638f515-47f9-46f4-a865-5e64b4ee4f9e.png)

在请求失败时显示错误！

如我们所见，由于服务器未运行，我们的应用程序中显示了无法获取帖子的错误。现在我们可以继续通过请求实现帖子创建。

# 实现帖子创建

现在我们已经很好地掌握了如何从 API 请求数据，我们将使用`useResource` Hook 来创建新数据。

让我们开始使用 Resource Hook 实现帖子创建：

1.  编辑`src/post/CreatePost.js`，并导入`useResource` Hook：

```jsx
import { useResource } from 'react-request-hook'
```

1.  然后，在其他 Hooks 之后但在处理程序函数定义之前，定义一个新的 Resource Hook。在这里，我们将方法设置为`post`（创建新数据），并将数据从`createPost`函数传递给请求配置：

```jsx
    const [ , createPost ] = useResource(({ title, content, author }) => ({
        url: '/posts',
        method: 'post',
        data: { title, content, author }
    }))
```

在这里，我们使用了数组解构的简写语法：我们通过不指定值名称来忽略数组的第一个元素。我们不写`const [ post, createPost ]`，然后不使用`post`，而是直接写一个逗号，如下所示：`const [  , createPost ]`。

1.  现在，我们可以在`handleCreate`处理程序函数中使用`createPost`函数。我们确保保留对`dispatch`函数的调用，以便在等待服务器响应的同时立即在客户端插入新帖子。添加的代码已用粗体标出：

```jsx
    function handleCreate () {
 createPost({ title, content, author: user })
        dispatch({ type: 'CREATE_POST', title, content, author: user })
    }
```

请注意，在这个简单的例子中，我们不期望或处理帖子创建的失败。在这种情况下，我们甚至在请求完成之前就分派了动作。然而，在实施登录时，我们将处理来自请求的错误状态，以检查用户是否成功登录。在真实世界的应用程序中，始终处理错误状态是最佳实践。

1.  请注意，现在插入帖子时，帖子将首先出现在列表的开头；然而，刷新后，它将出现在列表的末尾。不幸的是，我们的服务器将新帖子插入到列表的末尾。因此，在从服务器获取帖子后，我们将颠倒顺序。编辑`src/App.js`，并调整以下代码：

```jsx
        if (posts && posts.data) {
            dispatch({ type: 'FETCH_POSTS', posts: posts.data.reverse() })
        }
```

现在，通过服务器插入新帖子运行良好，我们可以继续实施注册！

# 实施注册

接下来，我们将实施注册，这将与创建帖子的方式非常相似。

让我们开始实施注册：

1.  首先，在`src/user/Register.js`中导入`useEffect`和`useResource`钩子：

```jsx
import React, { useState, useContext, useEffect } from 'react'
import { useResource } from 'react-request-hook'
```

1.  然后，在其他钩子下面和处理程序函数之前定义一个新的`useResource`钩子。与我们在创建帖子时所做的不同，我们现在还希望存储生成的`user`对象：

```jsx
    const [ user, register ] = useResource((username, password) => ({
        url: '/users',
        method: 'post',
        data: { username, password }
    }))
```

1.  接下来，在`useResource`钩子下面定义一个新的`useEffect`钩子，当请求完成时将分派一个`REGISTER`动作：

```jsx
    useEffect(() => {
        if (user && user.data) {
            dispatch({ type: 'REGISTER', username: user.data.username })
        }
    }, [user])
```

请注意，在这个简单的例子中，我们不期望或处理注册的失败。在这种情况下，我们只在用户成功创建后分派动作。然而，在实施登录时，我们将处理来自请求的错误状态，以检查用户是否成功登录。在真实世界的应用程序中，始终处理错误状态是最佳实践。

1.  最后，我们调整表单提交处理程序，以调用`register`函数，而不是直接分派动作：

```jsx
        <form onSubmit={e => { e.preventDefault(); register(username, password) }}>
```

现在，如果我们输入用户名和密码，然后点击注册，一个新用户将被插入到我们的`db.json`文件中，就像以前一样，我们将登录。我们现在继续通过资源钩子实施登录。

# 实施登录

最后，我们将通过使用我们的自定义路由来实施登录。这样做后，我们的博客应用程序将完全连接到服务器。

让我们开始实施登录：

1.  首先，编辑`src/user/Login.js`并导入`useEffect`和`useResource`钩子：

```jsx
import React, { useState, useContext, useEffect } from 'react'
import { useResource } from 'react-request-hook'
```

1.  我们定义了一个新的 State Hook，它将存储一个布尔值，用于检查登录是否失败：

```jsx
    const [ loginFailed, setLoginFailed ] = useState(false)
```

1.  然后，我们为密码字段定义一个新的 State Hook，因为之前我们没有处理它：

```jsx
    const [ password, setPassword ] = useState('')
```

1.  现在，我们为密码字段定义一个处理函数，放在`handleUsername`函数下面：

```jsx
    function handlePassword (evt) {
        setPassword(evt.target.value)
    }
```

1.  接下来，我们处理`input`字段中的值更改：

```jsx
            <input type="password" value={password} onChange={handlePassword} name="login-username" id="login-username" />
```

1.  现在，我们可以在 State Hooks 下面定义我们的 Resource Hook，在这里我们将`username`和`password`传递给`/login`路由。由于我们将它们作为 URL 的一部分传递，我们需要确保首先正确地对它们进行编码：

```jsx
    const [ user, login ] = useResource((username, password) => ({
        url: `/login/${encodeURI(username)}/${encodeURI(password)}`,
        method: 'get'
    }))
```

请注意，通过 GET 请求以明文发送密码是不安全的。我们之所以这样做，只是为了简化配置我们的虚拟服务器。在真实世界的应用程序中，应该使用 POST 请求进行登录，并将密码作为 POST 数据的一部分发送。还要确保使用**超文本传输安全协议（HTTPS）**，以便对 POST 数据进行加密。

1.  接下来，我们定义一个 Effect Hook，如果请求成功完成，它将分派`LOGIN`动作：

```jsx
    useEffect(() => {
        if (user && user.data) {
```

1.  因为登录路由返回的要么是一个空数组（登录失败），要么是一个包含单个用户的数组，所以我们需要检查数组是否至少包含一个元素：

```jsx
            if (user.data.length > 0) {
                setLoginFailed(false)
                dispatch({ type: 'LOGIN', username: user.data[0].username })
            } else {
```

1.  如果数组为空，我们将`loginFailed`设置为`true`：

```jsx
                setLoginFailed(true)
            }
        }
```

1.  如果我们从服务器获得错误响应，我们还将登录状态设置为失败：

```jsx
        if (user && user.error) {
            setLoginFailed(true)
        }
```

1.  我们确保 Effect Hook 在 Resource Hook 更新`user`对象时触发：

```jsx
    }, [user])
```

1.  然后，我们调整`form`的`onSubmit`函数，以调用`login`函数：

```jsx
 <form onSubmit={e => { e.preventDefault(); login(username, password**)** }}>
```

1.  最后，在提交按钮下面，我们显示“用户名或密码无效”的消息，以防`loginFailed`被设置为`true`：

```jsx
            {loginFailed && <span style={{ color: 'red' }}>Invalid username or password</span>}
```

正如我们所看到的，输入错误的用户名或密码（或没有密码）将导致错误，而输入正确的用户名/密码组合将使我们登录：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/a5f6d839-c39e-459a-a083-674827a8ce51.png)

在登录失败时显示错误消息

现在，我们的应用程序已完全连接到后端服务器！

# 示例代码

示例代码可以在`Chapter06/chapter6_3`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 React.memo 防止不必要的重新渲染

在类组件中，我们有`shouldComponentUpdate`，它可以防止组件在 props 没有改变时重新渲染。

使用函数组件，我们可以使用`React.memo`来做同样的事情，这是一个高阶组件。`React.memo`会记住上次渲染的结果，如果 props 没有改变，它将跳过重新渲染组件：

```jsx
const SomeComponent = () => ...

export default React.memo(SomeComponent)
```

默认情况下，`React.memo`将像`shouldComponentUpdate`的默认定义一样，它只会浅层比较 props 对象。如果我们想要进行特殊比较，可以将函数作为第二个参数传递给`React.memo`：

```jsx
export default React.memo(SomeComponent, (prevProps, nextProps) => {
    // compare props and return true if the props are equal and we should not update
})
```

与`shouldComponentUpdate`不同，传递给`React.memo`的函数在 props 相等时返回`true`，因此它不应该更新，这与`shouldComponentUpdate`的工作方式相反！学习了`React.memo`之后，让我们尝试在实践中实现`React.memo`来为 Post 组件。

# 在 Post 组件中实现 React.memo

首先，让我们找出`Post`组件何时重新渲染。为此，我们将向`Post`组件添加一个`console.log`语句，如下所示：

1.  编辑`src/post/Post.js`，并在组件渲染时添加以下调试输出：

```jsx
export default function Post ({ title, content, author }) {
 console.log('rendering Post')
```

1.  现在，打开`http://localhost:3000`的应用程序，并打开 DevTools（在大多数浏览器上：右键单击|在页面上检查）。转到控制台选项卡，您应该看到输出两次，因为我们正在渲染两篇文章：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/cdef8b29-ea94-4c5a-8d74-673d1d9e6131.png)

渲染两篇文章时的调试输出

1.  到目前为止，一切顺利。现在，让我们尝试登录，并看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/117dcf52-9fda-4279-b272-caa9eba73376.png)

登录后重新渲染文章

正如我们所看到的，登录后，文章组件不必要地重新渲染，尽管它们的 props 没有改变。我们可以使用`React.memo`来防止这种情况，如下所示：

1.  编辑`src/post/Post.js`，并删除函数定义的 export default 部分（用粗体标记）：

```jsx
export default function Post ({ title, content, author }) {
```

1.  然后，在文件底部，将 Post 组件包装在`React.memo()`中后导出：

```jsx
export default React.memo(Post)
```

1.  现在，刷新页面并重新登录。我们可以看到两篇文章被渲染，这产生了初始的调试输出。然而，现在登录不再导致文章组件重新渲染了！

如果我们想要对文章是否相等进行自定义检查，我们可以比较`title`，`content`和`author`，如下所示：

```jsx
export  default  React.memo(Post, (prev,  next)  =>  prev.title ===  next.title && prev.content === next.content && prev.author === next.author ) 
```

在我们的情况下，这样做将产生相同的效果，因为 React 默认已经对所有 props 进行了浅比较。当我们有深层对象需要比较，或者当我们想要忽略某些 props 的更改时，这个函数才会变得有用。请注意，我们不应该过早地优化我们的代码。重新渲染可能没问题，因为 React 是智能的，如果没有变化，它就不会在浏览器中绘制。因此，除非已经确定某种情况是性能瓶颈，否则优化所有重新渲染可能有些过度。

# 示例代码

示例代码可以在`Chapter06/chapter6_4`文件夹中找到。

只需运行`npm install`来安装所有依赖项，然后运行`npm start`来启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 使用 React Suspense 实现懒加载

React Suspense 允许我们在渲染之前让组件等待。目前，React Suspense 只允许我们使用`React.lazy`动态加载组件。将来，Suspense 将支持其他用例，比如数据获取。

`React.lazy`是另一种性能优化的形式。它让我们动态加载组件以减少捆绑包大小。有时我们希望在初始渲染时避免加载所有组件，只在需要时请求特定组件。

例如，如果我们的博客有一个会员区域，我们只需要在用户登录后加载它。这样做将减少那些只访问我们博客阅读博文的访客的捆绑包大小。为了了解 React Suspense，我们将在我们的博客应用程序中懒加载`Logout`组件。

# 实现 React.Suspense

首先，我们必须指定一个加载指示器，在我们的懒加载组件加载时显示。在我们的示例中，我们将使用 React Suspense 包装`UserBar`组件。

编辑`src/App.js`，并用以下代码替换`<UserBar />`组件：

```jsx
                    <React.Suspense fallback={"Loading..."}>
                        <UserBar />
                    </React.Suspense>
```

现在，我们的应用程序已准备好实现懒加载。

# 实现 React.lazy

接下来，我们将通过使用`React.lazy()`来实现`Logout`组件的懒加载：

1.  编辑 `src/user/UserBar.js`，并删除`Logout`组件的导入语句：

```jsx
import Logout from './Logout'
```

1.  然后，通过懒加载定义`Logout`组件：

```jsx
const Logout = React.lazy(() => import('./Logout'))
```

`import()`函数动态加载`Logout`组件从`Logout.js`文件中。与静态的`import`语句相反，这个函数只有在`React.lazy`触发时才会被调用，这意味着只有在需要组件时才会被导入。

如果我们想看到延迟加载的效果，可以在 Google Chrome 中将网络节流设置为 Slow 3G：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/a62969d1-50ad-4b34-98ac-b763d644f451.png)

在 Google Chrome 中将网络节流设置为 Slow 3G，在 Firefox 中，我们可以通过将网络节流设置为 GPRS 来实现相同的效果。

不幸的是，Safari 目前还没有这样的功能，但我们可以使用苹果的“硬件 IO 工具”中的 Network Link Conditioner 工具：[`developer.apple.com/download/more/`](https://developer.apple.com/download/more/)

如果我们现在刷新页面，然后登录，我们首先可以看到“加载中…”的消息，然后会显示`Logout`组件。如果我们查看网络日志，我们可以看到`Logout`组件是通过网络请求的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-hk/img/5d3e7ef1-f8cb-4a8a-86dd-9bfe1c8f3a0e.png)

通过网络加载的注销组件

正如我们所看到的，`Logout`组件现在是懒加载的，这意味着只有在需要时才会被请求。

# 示例代码

示例代码可以在`Chapter06/chapter6_5`文件夹中找到。

只需运行`npm install`以安装所有依赖项，然后运行`npm start`启动应用程序；然后在浏览器中访问`http://localhost:3000`（如果没有自动打开）。

# 总结

在本章中，我们首先学习了如何从 JSON 文件设置 API 服务器。然后，我们学习了如何使用 Effect 和 State/Reducer Hooks 请求资源。接下来，我们学习了如何使用`axios`和`react-request-hook`库请求资源。最后，我们学习了如何使用`React.memo`来防止不必要的重新渲染，以及如何使用 React Suspense 来懒加载组件。

在下一章中，我们将为我们的应用程序添加路由，并学习如何使用 Hooks 进行路由。

# 问题

为了总结本章学到的知识，请尝试回答以下问题：

1.  我们如何可以轻松地从简单的 JSON 文件创建一个完整的 REST API？

1.  使用代理访问后端服务器在开发过程中有哪些优势？

1.  我们可以使用哪些 Hooks 组合来实现请求？

1.  我们可以使用哪些库来实现请求？

1.  我们如何使用`react-request-hook`处理加载状态？

1.  我们如何使用`react-request-hook`处理错误？

1.  我们如何防止组件不必要的重新渲染？

1.  我们如何减少应用程序的捆绑大小？

# 进一步阅读

如果您对我们在本章中探讨的概念更感兴趣，可以查阅以下阅读材料：

+   `json-server`的官方文档：[`github.com/typicode/json-server`](https://github.com/typicode/json-server).

+   `concurrently`的官方文档：[`github.com/kimmobrunfeldt/concurrently`](https://github.com/kimmobrunfeldt/concurrently).

+   `axios`的官方文档：[`github.com/axios/axios`](https://github.com/axios/axios).

+   `react-request-hook`的官方文档：[`github.com/schettino/react-request-hook`](https://github.com/schettino/react-request-hook).

+   Create React App 关于配置代理的文档：[`facebook.github.io/create-react-app/docs/proxying-api-requests-in-development#configuring-the-proxy-manually`](https://facebook.github.io/create-react-app/docs/proxying-api-requests-in-development#configuring-the-proxy-manually).

+   使用 React Hooks 获取数据：[`www.robinwieruch.de/react-hooks-fetch-data`](https://www.robinwieruch.de/react-hooks-fetch-data)

+   何时使用`useMemo`：[`kentcdodds.com/blog/usememo-and-usecallback`](https://kentcdodds.com/blog/usememo-and-usecallback)
