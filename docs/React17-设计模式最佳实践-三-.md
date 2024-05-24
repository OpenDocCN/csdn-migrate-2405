# React17 设计模式最佳实践（三）

> 原文：[`zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F`](https://zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：管理数据

**适当的数据获取**经历了一些最常见的模式，以使子代和父代使用回调进行通信。我们将学习如何使用一个共同的父代来在不直接连接的组件之间共享数据。然后我们将开始学习新的 React 上下文 API 和 React Suspense。

在本章中，我们将涵盖以下主题：

+   React 上下文 API

+   如何使用 useContext 消耗上下文

+   如何使用 React Suspense 与 SWR

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter06`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter06)。

# 介绍 React 上下文 API

自版本 16.3.0 以来，React 上下文 API 已正式添加；在此之前，它只是实验性的。新的上下文 API 是一个改变游戏规则的东西。许多人正在摆脱 Redux，以使用新的上下文 API。上下文提供了一种在组件之间共享数据的方法，而无需将 prop 传递给所有子组件。

让我们看一个基本示例，我们可以在其中使用新的上下文 API。我们将在*第三章 React Hooks*中做相同的示例，我们在那里获取了一些 GitHub 问题，但现在使用上下文 API。

## 创建我们的第一个上下文

您需要做的第一件事是创建问题上下文。为此，您可以在`src`文件夹内创建一个名为`contexts`的文件夹，然后在其中添加`Issue.tsx`文件。

然后，您需要从 React 和`axios`导入一些函数：

```jsx
import { FC, createContext, useState, useEffect, ReactElement, useCallback } from 'react'
import axios from 'axios'
```

在这一点上，很明显您应该安装`axios`。如果您还没有，请执行以下操作：

```jsx
npm install axios 
npm install --save-dev @types/axios
```

然后我们需要声明我们的接口：

```jsx
export type Issue = {
  number: number
  title: string
  url: string
  state: string
}

interface Issue_Context {
  issues: Issue[]
  url: string
}

interface Props {  url: string
}
```

在此之后，我们需要做的第一件事是使用`createContext`函数创建我们的上下文，并定义我们要导出的值：

```jsx
export const IssueContext = createContext<Issue_Context>({
  issues: [],
  url: ''
})
```

一旦我们有了`IssueContext`，我们需要创建一个组件，我们可以在其中接收 props，设置一些状态，并使用`useEffect`执行获取，然后我们渲染`IssueContext.Provider`，在那里我们指定上下文（值）我们将导出：

```jsx
const IssueProvider: FC<Props> = ({ children, url })  => {
  // State
  const [issues, setIssues] = useState<Issue[]>([])

  const fetchIssues = useCallback(async () => {
    const response = await axios(url)

    if (response) {
      setIssues(response.data)
    }
  }, [url])

  // Effects
  useEffect(() => {
    fetchIssues()
  }, [fetchIssues])

  const context = {
    issues,
    url
  }

  return <IssueContext.Provider value={context}>{children}</IssueContext.Provider>
}

export default IssueProvider
```

正如您所知，每当您想在`useEffect` Hook 中使用函数时，您需要使用`useCallback` Hook 包装您的函数。如果您想使用`async/await`，一个好的做法是将其放在一个单独的函数中，而不是直接放在`useEffect`中。

一旦我们执行获取并将数据放入我们的`issues`状态中，然后我们将所有要导出为上下文的值添加到`IssueContext.Provider`中，然后当我们渲染`IssueContext.Provider`时，我们将上下文传递给`value`属性，最后，我们渲染组件的子组件。

## 用提供者包装我们的组件

您消费上下文的方式分为两部分。第一部分是您用上下文提供者包装您的应用程序，因此这段代码可以添加到`App.tsx`（通常所有提供者都在父组件中定义）。

请注意，这里我们正在导入`IssueProvider`组件：

```jsx
// Providers
import IssueProvider from '../contexts/Issue'

// Components
import Issues from './Issues'

const App = () => {
  return (
    <IssueProvider url=
      "https://api.github.com/repos/ContentPI/ContentPI/issues">
      <Issues />
    </IssueProvider>
  )
}

export default App;
```

正如您所看到的，我们正在用`IssueProvider`包装`Issues`组件，这意味着在`Issues`组件内部，我们可以使用我们的上下文并获取问题的值。

有时候很多人会感到困惑。如果您忘记用提供者包装您的组件，那么您就无法在组件内部使用您的上下文，而困难的部分是您可能不会得到任何错误；您只会得到一些未定义的数据，这使得很难识别。

## 使用 useContext 消费上下文

如果您已经在`App.tsx`中放置了`IssueProvider`，现在您可以通过使用`useContext` Hook 在`Issues`组件中消费您的上下文。

请注意，这里我们正在导入`IssueContext`上下文（在`{}`之间）：

```jsx
// Dependencies
import { FC, useContext } from 'react'

// Contexts
import { IssueContext, Issue } from '../contexts/Issue'

const Issues: FC = () => {
  // Here you consume your Context, and you can grab the issues value.
  const { issues, url } = useContext(IssueContext)

  return (
    <>
      <h1>ContentPI Issues from Context</h1>

      {issues.map((issue: Issue) => (
        <p key={`issue-${issue.number}`}>
          <strong>#{issue.number}</strong> {' '}
          <a href={`${url}/${issue.number}`}>{issue.title}</a> {' '}
          {issue.state}
        </p>
      ))}
    </>
  )
}

export default Issues
```

如果你做得正确，你应该能够看到问题列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/6edba673-ea96-4588-a2b8-d86791557dd5.png)

当您想要将应用程序与数据分离并在其中执行所有获取操作时，上下文 API 非常有用。当然，上下文 API 有多种用途，也可以用于主题设置或传递函数；这完全取决于您的应用程序。

在下一节中，我们将学习如何使用 SWR 库实现 React Suspense。

# 介绍 React Suspense 与 SWR

React Suspense 是在 React 16.6 中引入的。现在（2021 年 4 月）这个功能仍然是实验性的，你不应该在生产应用程序中使用它。Suspense 允许您暂停组件渲染直到满足条件。您可以渲染一个加载组件或任何您想要的作为 Suspense 的回退。目前只有两种用例：

+   代码拆分：当您拆分应用程序并等待在用户要访问时下载应用程序的一部分时

+   **数据获取**：当您获取数据时

在这两种情况下，您可以呈现一个回退，通常可以是加载旋转器、一些加载文本，甚至更好的是占位符骨架。

**警告**：新的 React Suspense 功能仍处于实验阶段，因此我建议您不要在生产环境中使用它，因为它尚未在稳定版本中可用。

## 介绍 SWR

**过时-同时重新验证**（**SWR**）是用于数据获取的 React Hook；它是一种 HTTP 缓存失效策略。SWR 是一种策略，首先从缓存中返回数据（过时），然后发送获取请求（重新验证），最后返回最新的数据，并由创建 Next.js 的公司 Vercel 开发。

## 构建宝可梦图鉴！

我找不到一个更好的例子来解释 React Suspense 和 SWR，比构建宝可梦图鉴更好的例子。我们将使用一个公共的宝可梦 API（[`pokeapi.co`](https://pokeapi.co)）；* gotta catch 'em all *！

您需要做的第一件事是安装一些软件包：

```jsx
npm install swr react-loading-skeleton styled-components
```

对于这个例子，您需要在`src/components/Pokemon`目录下创建 Pokemon 目录。我们需要做的第一件事是创建一个 fetcher 文件，我们将在其中执行我们的请求，以便使用 SWR。

此文件应创建在`src/components/Pokemon/fetcher.ts`：

```jsx
const fetcher = (url: string) => {
  return fetch(url).then((response) => {
    if (response.ok) {
      return response.json()
    }

    return {
      error: true
    }
  })
}

export default fetcher
```

如果您注意到，如果响应不成功，我们将返回一个带有错误的对象。这是因为有时我们可以从 API 获取 404 错误，这可能导致应用程序崩溃。

创建了 fetcher 文件后，让我们修改`App.tsx`以配置`SWRConfig`并启用 Suspense：

```jsx
// Dependencies
import { SWRConfig } from 'swr'

// Components
import PokeContainer from './Pokemon/PokeContainer'
import fetcher from './Pokemon/fetcher'

// Styles
import { StyledPokedex, StyledTitle } from './Pokemon/Pokemon.styled'

const App = () => {
  return (
    <> 
      <StyledTitle>Pokedex</StyledTitle> 

      <SWRConfig
        value={{
          fetcher,
          suspense: true,
        }}
      >
        <StyledPokedex>
          <PokeContainer />
        </StyledPokedex>
 </SWRConfig>
    </>
  )
}

export default App
```

正如您所看到的，我们需要将我们的`PokeContainer`组件包装在`SWRConfig`内，以便能够获取数据。`PokeContainer`组件将是我们的父组件，在那里我们将添加我们的第一个 Suspense。此文件位于`src/components/Pokemon/PokeContainer.tsx`：

```jsx
import { FC, Suspense } from 'react'

import Pokedex from './Pokedex'

const PokeContainer: FC = () => {
  return (
    <Suspense fallback={<h2>Loading Pokedex...</h2>}>
      <Pokedex />
    </Suspense>
  )
}

export default PokeContainer
```

正如您所看到的，我们为我们的第一个 Suspense 定义了一个回退，即`加载宝可梦图鉴...`文本。您可以在其中呈现任何您想要的东西，React 组件或纯文本。然后，我们在 Suspense 中有我们的`Pokedex`组件。

现在让我们看看我们的`Pokedex`组件，我们将首次使用`useSWR` Hook 来获取数据：

```jsx
// Dependencies
import { FC, Suspense } from 'react'
import useSWR from 'swr'

// Components
import LoadingSkeleton from './LoadingSkeleton'
import Pokemon from './Pokemon'

import { StyledGrid } from './Pokemon.styled'

const Pokedex: FC = () => {
  const { data: { results } } = 
 useSWR('https://pokeapi.co/api/v2/pokemon?limit=150')

  return (
    <>
      {results.map((pokemon: { name: string }) => (
        <Suspense fallback={<StyledGrid><LoadingSkeleton /></StyledGrid>}>
          <Pokemon key={pokemon.name} pokemonName={pokemon.name} />
        </Suspense>
      ))}
    </>
  )
}

export default Pokedex
```

正如你所看到的，我们正在获取前 150 只宝可梦，因为我是老派的，那些是第一代。现在我不知道有多少只宝可梦存在。另外，如果你注意到，我们正在获取来自数据的`results`变量（这是 API 的实际响应）。然后我们将我们的结果映射到每个宝可梦上，但我们为每个宝可梦添加了一个悬念组件，带有`<LoadingSkeleton />`回退（`<StyledGrid />`有一些 CSS 样式，使其看起来更漂亮），最后，我们将`pokemonName`传递给我们的`<Pokemon>`组件，这是因为第一次获取只带来了宝可梦的名字，但我们需要再次获取实际的宝可梦数据（名字、类型、力量等）。

然后，最后，我们的宝可梦组件将通过宝可梦的名字执行特定的获取并渲染数据：

```jsx
// Dependencies
import { FC } from 'react'
import useSWR from 'swr'

// Styles
import { StyledCard, StyledTypes, StyledType, StyledHeader } from './Pokemon.styled'

type Props = {
  pokemonName: string
}

const Pokemon: FC<Props> = ({ pokemonName }) => {
  const { data, error } = 
 useSWR(`https://pokeapi.co/api/v2/pokemon/${pokemonName}`)

  // Do you remember the error we set on the fetcher?
  if (error || data.error) {
    return <div />
  }

  if (!data) {
    return <div>Loading...</div>
  }

  const { id, name, sprites, types } = data
  const pokemonTypes = types.map((pokemonType: any) => 
    pokemonType.type.name)

  return (
    <StyledCard pokemonType={pokemonTypes[0]}>
      <StyledHeader>
        <h2>{name}</h2>
        <div>#{id}</div>
      </StyledHeader>

      <img alt={name} src={sprites.front_default} />

      <StyledTypes>
        {pokemonTypes.map((pokemonType: string) => (
 <StyledType key={pokemonType}>{pokemonType}</StyledType>
        ))}
      </StyledTypes>
    </StyledCard>
  )
} 

export default Pokemon
```

基本上，在这个组件中，我们汇总了所有的宝可梦数据（`id`、`name`、`sprites`和`types`），然后渲染信息。正如你所看到的，我正在使用`styled`组件，这太棒了，所以如果你想知道我为`Pokedex`使用的样式，这里是`Pokemon.styled.ts`文件：

```jsx
import styled from 'styled-components'

// Type colors
const type: any = {
  bug: '#2ADAB1',
  dark: '#636363',
  dragon: '#E9B057',
  electric: '#ffeb5b',
  fairy: '#ffdbdb',
  fighting: '#90a4b5',
  fire: '#F7786B',
  flying: '#E8DCB3',
  ghost: '#755097',
  grass: '#2ADAB1',
  ground: '#dbd3a2',
  ice: '#C8DDEA',
  normal: '#ccc',
  poison: '#cc89ff',
  psychic: '#705548',
  rock: '#b7b7b7',
  steel: '#999',
  water: '#58ABF6'
}

export const StyledPokedex = styled.div`
  display: flex;
  flex-wrap: wrap;
  flex-flow: row wrap;
  margin: 0 auto;
  width: 90%;

  &::after {
    content: '';
    flex: auto;
  }
`

type Props = {
  pokemonType: string
} 

export const StyledCard = styled.div<Props>`
  position: relative;
  ${({ pokemonType }) => `
    background: ${type[pokemonType]} url(./pokeball.png) no-repeat;
    background-size: 65%;
    background-position: center;
  `}
  color: #000;
  font-size: 13px;
  border-radius: 20px;
  margin: 5px;
  width: 200px;

  img {
    margin-left: auto;
    margin-right: auto;
    display: block;
  }
`

export const StyledTypes = styled.div`
  display: flex;
  margin-left: 6px;
  margin-bottom: 8px;
`

export const StyledType = styled.span`
  display: inline-block;
  background-color: black;
  border-radius: 20px;
  font-weight: bold;
  padding: 6px;
  color: white;
  margin-right: 3px;
  opacity: 0.4;
  text-transform: capitalize;
`

export const StyledHeader = styled.div`
  display: flex;
  justify-content: space-between;
  width: 90%;

  h2 {
    margin-left: 10px;
    margin-top: 5px;
    color: white;
    text-transform: capitalize;
  }

  div {
    color: white;
    font-size: 20px;
    font-weight: bold;
    margin-top: 5px;
  }
`

export const StyledTitle = styled.h1`
  text-align: center;
`

export const StyledGrid = styled.div`
  display: flex;
  flex-wrap: wrap;
  flex-flow: row wrap;
  div {
    margin-right: 5px;
    margin-bottom: 5px;
  }
`
```

最后，我们的`LoadingSkeleton`组件应该是这样的：

```jsx
import { FC } from 'react'
import Skeleton from 'react-loading-skeleton'

const LoadingSkeleton: FC = () => (
  <div>
    <Skeleton height={200} width={200} />
  </div>
)

export default LoadingSkeleton
```

这个库太棒了。它让你创建骨架占位符来等待数据。当然，你可以建立任意多的形式。你可能在 LinkedIn 或 YouTube 等网站上看到过这种效果。

## 测试我们的 React 悬念

一旦你的代码所有部分都运行正常，有一个技巧可以让你看到所有的悬念回退。通常，如果你有高速连接，很难看到它，但你可以减慢你的连接速度，看看所有东西是如何被渲染的。你可以在 Chrome 检查器的网络选项卡中选择慢速 3G 连接来做到这一点。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b8f1b87e-300c-4b20-a642-990ebc8d1fe0.png)

一旦你设置了慢速 3G 预设，并运行你的项目，你将看到的第一个回退是 Loading Pokedex...：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/9060d4d4-09ec-4844-a3d7-421fcc9bb8ca.png)

然后，你将看到正在渲染的宝可梦回退，为每个正在加载的宝可梦渲染`SkeletonLoading`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/6d0a18fd-d91a-4c09-89c4-4d6bffd52bde.png)

通常这些加载器有动画，但在这本书中你当然看不到！然后你将开始看到数据是如何渲染的，一些图片开始出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/46590725-c067-4d2d-a269-8c48965e8361.png)

如果你等到所有数据都正确下载了，你现在应该可以看到有所有宝可梦的宝可梦图鉴了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/fb2507aa-63c4-4bbe-a64a-095ad5f08c09.png)

挺不错的，对吧？但还有一件事要提一下；就像我之前提到的，SWR 会首先从缓存中获取数据，然后会一直重新验证数据，看看是否有新的更新。这意味着每当数据发生变化时，SWR 都会执行另一个获取操作，以重新验证旧数据是否仍然有效，或者需要被新数据替换。即使你从宝可梦图鉴标签移出去然后再回来，你也会看到效果。你会发现你的网络终端第一次应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/c9f97cee-179c-447a-8df8-9cf959726b63.png)

正如你所看到的，我们执行了 151 个初始请求（1 个用于宝可梦列表，另外 150 个，每个宝可梦一个），但如果你切换标签然后再回来，你会看到 SWR 再次获取数据：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/f8cd8287-2369-430e-aaa3-906e1f4d0384.png)

现在你可以看到它正在执行 302 个请求（另外 151 个）。当你有实时数据想要每秒或每分钟获取时，这非常有用。

目前，React Suspense 还没有一个明确定义的使用模式，这意味着你可以找到不同的使用方式，目前还没有一些良好的实践方法。我发现 SWR 是使用 React Suspense 最简单和最容易理解的方式，我认为它是一个非常强大的库，甚至可以在没有 Suspense 的情况下使用。

# 总结

我真的希望你喜欢阅读这一章，其中包含了关于 React Context API 以及如何使用 SWR 实现 React Suspense 的大量信息。

在下一章中，我们将学习如何处理表单和动画。


# 第七章：为浏览器编写代码

在使用 React 和浏览器时，我们可以进行一些特定的操作。例如，我们可以要求用户使用表单输入一些信息，在本章中，我们将看看如何应用不同的技术来处理表单。我们可以实现**不受控制的组件**，让字段保持其内部状态，或者我们可以使用**受控组件**，在这种情况下，我们完全控制字段的状态。

在本章中，我们还将看看 React 中的事件是如何工作的，以及该库如何实现一些高级技术，为我们提供一个在不同浏览器中具有一致接口的解决方案。我们将看看 React 团队实现的一些有趣的解决方案，使事件系统非常高效。

在事件之后，我们将跳转到 refs，看看我们如何在 React 组件中访问底层 DOM 节点。这代表了一个强大的功能，但应该谨慎使用，因为它会破坏一些使 React 易于使用的约定。

在 refs 之后，我们将看看如何使用 React 附加组件和第三方库（如`react-motion`）轻松实现动画。最后，我们将学习在 React 中使用**可伸缩矢量图形**（**SVG**）有多么容易，以及如何为我们的应用程序创建动态可配置的图标。

在本章中，我们将介绍以下主题：

+   使用不同的技术在 React 中创建表单

+   监听 DOM 事件并实现自定义处理程序

+   使用 refs 在 DOM 节点上执行命令式操作的一种方式

+   创建在不同浏览器中都有效的简单动画

+   生成 SVG 的 React 方式

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter07`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter07)。

# 理解并实现表单

在本章中，我们将学习如何使用 React 实现表单。一旦我们开始用 React 构建一个真正的应用程序，我们就需要与用户进行交互。如果我们想在浏览器中向用户询问信息，表单是最常见的解决方案。由于库的工作方式和其声明性的特性，使用 React 处理输入字段和其他表单元素是非常复杂的，但一旦我们理解了它的逻辑，就会变得清晰。在接下来的章节中，我们将学习如何使用不受控制和受控组件。

## 不受控制的组件

不受控制的组件就像常规的 HTML 表单输入，你将无法自己管理值，而是 DOM 会处理值，并且你可以使用 React ref 来获取这个值。让我们从一个基本的例子开始——显示一个带有输入字段和提交按钮的表单。

代码非常简单：

```jsx
import { useState, ChangeEvent, MouseEvent } from 'react' const Uncontrolled = () => {
  const [value, setValue] = useState('')

  return (
    <form> 
<input type="text" /> 
      <button>Submit</button> 
 </form>  ) 
}

export default Uncontrolled
```

如果我们在浏览器中运行前面的片段，我们将看到完全符合预期的结果——一个输入字段，我们可以在其中输入一些内容，以及一个可点击的按钮。这是一个不受控制的组件的例子，我们不设置输入字段的值，而是让组件管理自己的内部状态。

很可能，我们希望在单击提交按钮时对元素的值做一些操作。例如，我们可能希望将数据发送到 API 端点。

我们可以通过添加一个`onChange`监听器来轻松实现这一点（我们将在本章后面更多地讨论事件监听器）。让我们看看添加监听器意味着什么。

我们需要创建`handleChange`函数：

```jsx
const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
  console.log(e.target.value)
}
```

事件监听器接收到一个事件对象，其中`target`表示生成事件的字段，我们对其值感兴趣。我们首先只是记录它，因为逐步进行很重要，但很快我们将把值存储到状态中。

最后，我们渲染表单：

```jsx
return (
  <form> 
 <input type="text" onChange={handleChange} /> 
    <button>Submit</button> 
 </form> 
)
```

如果我们在浏览器中渲染组件并在表单字段中输入`React`这个词，我们将在控制台中看到类似以下的内容：

```jsx
R
Re
Rea
Reac
React
```

`handleChange`监听器在输入值改变时被触发。因此，我们的函数每输入一个字符就会被调用一次。下一步是存储用户输入的值，并在用户单击提交按钮时使其可用。

我们只需要改变处理程序的实现方式，将其存储在状态中而不是记录下来，如下所示：

```jsx
const handleChange = (e: ChangeEvent<HTMLInputElement>) => { 
  setValue(e.target.value)
}
```

得知表单何时提交与监听输入字段的更改事件非常相似；它们都是在发生某些事件时由浏览器调用的。

让我们定义`handleSubmit`函数，我们只是记录这个值。在现实世界的场景中，你可以将数据发送到 API 端点或将其传递给另一个组件：

```jsx
const handleSubmit = (e: MouseEvent<HTMLButtonElement>) => { 
  e.preventDefault()

  console.log(value)
}
```

这个处理程序非常简单；我们只是记录当前存储在状态中的值。我们还希望克服浏览器在提交表单时的默认行为，以执行自定义操作。这似乎是合理的，并且对于单个字段来说效果很好。现在的问题是，如果我们有多个字段怎么办？假设我们有数十个不同的字段？

让我们从一个基本的例子开始，手动创建每个字段和处理程序，并看看如何通过应用不同级别的优化来改进它。

让我们创建一个新的表单，包括名字和姓氏字段。我们可以重用`Uncontrolled`组件并添加一些新的状态：

```jsx
const [firstName, setFirstName] = useState('')
const [lastName, setLastName] = useState('')
```

我们在状态中初始化了两个字段，并为每个字段定义了一个事件处理程序。正如你可能已经注意到的，当有很多字段时，这种方法并不很好扩展，但在转向更灵活的解决方案之前，清楚地理解问题是很重要的。

现在，我们实现新的处理程序：

```jsx
const handleChangeFirstName = ({ target: { value } }) => {
  setFirstName(value) 
} 

const handleChangeLastName = ({ target: { value } }) => {
  setLastName(value) 
}
```

我们还必须稍微改变提交处理程序，以便在点击时显示名字和姓氏：

```jsx
const handleSubmit = (e: MouseEvent<HTMLButtonElement>) => { 
  e.preventDefault()

  console.log(`${firstName} ${lastName}`)
}
```

最后，我们渲染表单：

```jsx
return ( 
  <form onSubmit={handleSubmit}> 
    <input type="text" onChange={handleChangeFirstName} /> 
    <input type="text" onChange={handleChangeLastName} /> 
    <button>Submit</button> 
  </form> 
)
```

我们已经准备好了：如果我们在浏览器中运行前面的组件，我们将看到两个字段，如果我们在第一个字段中输入`Carlos`，在第二个字段中输入`Santana`，当表单提交时，我们将在浏览器控制台中看到全名显示出来。

同样，这样做是可以的，我们可以以这种方式做一些有趣的事情，但它不能处理复杂的场景，而不需要我们编写大量的样板代码。

让我们看看如何优化一下。我们的目标是使用一个单一的 change 处理程序，这样我们就可以添加任意数量的字段而不需要创建新的监听器。

让我们回到组件，让我们改变我们的状态：

```jsx
const [values, setValues] = useState({ firstName: '', lastName: '' })
```

我们可能仍然希望初始化这些值，在本节的后面，我们将看看如何为表单提供预填充的值。

现在，有趣的部分是我们如何修改`onChange`处理程序的实现方式，使其在不同字段中工作：

```jsx
const handleChange = ({ target: { name, value } }) => {    
  setValues({ 
    ...values,
    [name]: value
  })
}
```

正如我们之前所见，我们接收到的事件的`target`属性代表了触发事件的输入字段，因此我们可以使用字段的名称和其值作为变量。

然后我们必须为每个字段设置名称：

```jsx
return ( 
  <form onSubmit={handleSubmit}> 
    <input 
 type="text" 
      name="firstName" 
      onChange={handleChange} 
    /> 
    <input 
 type="text" 
      name="lastName" 
      onChange={handleChange} 
    /> 
 <button>Submit</button> 
 </form> 
)
```

就是这样！现在我们可以添加任意多个字段而不需要创建额外的处理程序。

## 受控组件

受控组件是一个通过使用组件状态来控制表单中输入元素的值的 React 组件。

在这里，我们将看看如何使用一些值预填充表单字段，这些值可以来自服务器或作为父级传递的 props。为了充分理解这个概念，我们将从一个非常简单的无状态函数组件开始，然后逐步改进它。

第一个例子显示了输入字段中的预定义值：

```jsx
const Controlled = () => ( 
  <form> 
 <input type="text" value="Hello React" /> 
 <button>Submit</button> 
 </form> 
)
```

如果我们在浏览器中运行此组件，我们会意识到它按预期显示默认值，但不允许我们更改值或在其中输入其他任何内容。

它这样做的原因是，在 React 中，我们声明了我们想要在屏幕上看到的内容，并且设置一个固定值属性总是导致渲染该值，无论采取了什么其他操作。这不太可能是我们在现实世界应用程序中想要的行为。

如果我们打开控制台，会得到以下错误消息。React 本身告诉我们我们在做一些错误的事情：

```jsx
You provided a `value` prop to a form field without an `onChange` handler. This will render a read-only field.
```

现在，如果我们只想让输入字段具有默认值，并且希望能够通过输入更改它，我们可以使用`defaultValue`属性：

```jsx
import { useState } from 'react'

const Controlled = () => {
  return (
    <form> 
 <input type="text" defaultValue="Hello React" /> 
      <button>Submit</button> 
 </form> 
  )
}

export default Controlled
```

这样，当渲染时，该字段将显示`Hello React`，但用户可以在其中输入任何内容并更改其值。现在让我们添加一些状态：

```jsx
const [values, setValues] = useState({ firstName: 'Carlos', lastName: 'Santana' })
```

处理程序与之前的相同：

```jsx
const handleChange = ({ target: { name, value } }) => { 
  setValues({ 
    [name]: value 
  })
} 

const handleSubmit = (e) => { 
  e.preventDefault()

  console.log(`${values.firstName} ${values.lastName}`)
}
```

实际上，我们将使用输入字段的`value`属性来设置它们的初始值，以及更新后的值：

```jsx
return ( 
  <form onSubmit={handleSubmit}> 
    <input 
 type="text" 
      name="firstName" 
      value={values.firstName} 
      onChange={handleChange} 
    /> 
 <input 
 type="text" 
      name="lastName" 
      value={values.lastName} 
      onChange={handleChange} 
    /> 
 <button>Submit</button> 
 </form> 
)
```

第一次渲染表单时，React 使用状态中的初始值作为输入字段的值。当用户在字段中输入内容时，将调用`handleChange`函数，并将字段的新值存储在状态中。

当状态改变时，React 会重新渲染组件并再次使用它来反映输入字段的当前值。现在我们完全控制字段的值，并且我们称这种模式为**受控组件**。

在下一节中，我们将处理事件，这是 React 处理来自表单的数据的基本部分。

# 处理事件

**事件**在不同的浏览器中有稍微不同的工作方式。React 试图抽象事件的工作方式，并为开发人员提供一致的接口来处理。这是 React 的一个很棒的特性，因为我们可以忘记我们要针对的浏览器，编写与供应商无关的事件处理程序和函数。

为了提供这个功能，React 引入了**合成事件**的概念。合成事件是一个包装了浏览器提供的原始事件对象的对象，它具有相同的属性，无论在何处创建。

要将事件监听器附加到节点并在事件触发时获取事件对象，我们可以使用一个简单的约定，回忆起事件附加到 DOM 节点的方式。事实上，我们可以使用单词 `on` 加上驼峰命名的事件名称（例如 `onKeyDown`）来定义在事件发生时要触发的回调。一个常用的约定是将事件处理程序函数命名为事件名称，并使用 `handle` 作为前缀（例如 `handleKeyDown`）。

我们已经在之前的例子中看到了这种模式的运作，我们在那里监听了表单字段的 `onChange` 事件。让我们重申一个基本的事件监听器示例，看看我们如何以更好的方式在同一个组件中组织多个事件。我们将实现一个简单的按钮，并且像往常一样，首先创建一个组件：

```jsx
const Button = () => {

}

export default Button
```

然后我们定义事件处理程序：

```jsx
const handleClick = (syntheticEvent) => { 
  console.log(syntheticEvent instanceof MouseEvent)
  console.log(syntheticEvent.nativeEvent instanceof MouseEvent)
}
```

正如你在这里看到的，我们只是做了一件非常简单的事情：我们只是检查我们从 React 接收到的事件对象的类型和附加到它的原生事件的类型。我们期望第一个返回 `false`，第二个返回 `true`。

你永远不应该需要访问原始的原生事件，但知道如果需要的话你可以这样做是很好的。最后，我们使用 `onClick` 属性定义按钮，并附加我们的事件监听器：

```jsx
return ( 
  <button onClick={handleClick}>Click me!</button> 
)
```

现在，假设我们想要将第二个处理程序附加到按钮，监听双击事件。一个解决方案是创建一个新的独立处理程序，并使用 `onDoubleClick` 属性将其附加到按钮，如下所示：

```jsx
<button 
 onClick={handleClick} 
  onDoubleClick={handleDoubleClick} 
> 
  Click me! 
</button>
```

记住，我们总是希望写更少的样板代码并避免重复代码。因此，一个常见的做法是为每个组件编写一个**单个事件处理程序**，根据事件类型触发不同的操作。

这种技术在 Michael Chan 的一本模式集合中有所描述：

[`reactpatterns.com/#event-switch`](http://reactpatterns.com/#event-switch)。

让我们实现通用事件处理程序：

```jsx
const handleEvent = (event) => { 
  switch (event.type) { 
    case 'click': 
      console.log('clicked')
      break

    case 'dblclick': 
      console.log('double clicked')
      break

    default: 
      console.log('unhandled', event.type)
  } 
}
```

通用事件处理程序接收事件对象并根据事件类型触发正确的操作。如果我们想在每个事件上调用一个函数（例如，分析），或者如果一些事件共享相同的逻辑，这将特别有用。

最后，我们将新的事件监听器附加到`onClick`和`onDoubleClick`属性上：

```jsx
return ( 
  <button 
    onClick={handleEvent} 
    onDoubleClick={handleEvent} 
  > 
    Click me! 
  </button> 
) 
```

从这一点开始，每当我们需要为同一组件创建一个新的事件处理程序时，我们可以只需添加一个新的情况到 switch，而不是创建一个新的方法并绑定它。

关于 React 中事件的另外一些有趣的事情是，合成事件是可重用的，并且存在**单个全局处理程序**。第一个概念意味着我们不能存储合成事件并在以后重用它，因为它在操作后立即变为 null。这种技术在性能方面非常好，但如果我们想出于某种原因将事件存储在组件状态中，可能会有问题。为了解决这个问题，React 在合成事件上给了我们一个`persist`方法，我们可以调用它使事件持久化，这样我们就可以存储并在以后检索它。

第二个非常有趣的实现细节再次涉及性能，它与 React 将事件处理程序附加到 DOM 的方式有关。

每当我们使用`on`属性时，我们正在描述我们想要实现的行为，但是库并没有将实际的事件处理程序附加到底层 DOM 节点上。

它所做的是将单个事件处理程序附加到根元素，通过**事件冒泡**监听所有事件。当我们感兴趣的事件被浏览器触发时，React 代表其调用特定组件上的处理程序。这种技术称为**事件委托**，用于内存和速度优化。

在我们的下一节中，我们将探索 React 引用并看看我们如何利用它们。

# 探索引用

人们喜欢 React 的一个原因是它是声明式的。声明式意味着你只需描述你想在屏幕上显示的内容，React 就会处理与浏览器的通信。这个特性使得 React 非常容易理解，同时也非常强大。

然而，可能会有一些情况需要访问底层的 DOM 节点来执行一些命令式操作。这应该被避免，因为在大多数情况下，有更符合 React 的解决方案来实现相同的结果，但重要的是要知道我们有这个选项，并知道它是如何工作的，以便我们能做出正确的决定。

假设我们想创建一个简单的表单，其中包含一个输入元素和一个按钮，当点击按钮时，输入字段获得焦点。我们想要做的是在浏览器窗口内调用输入节点的 `focus` 方法，即输入的实际 DOM 实例。

让我们创建一个名为 `Focus` 的组件；你需要导入 `useRef` 并创建一个 `inputRef` 常量：

```jsx
import { useRef } from 'react'
 const Focus = () => {
  const inputRef = useRef(null)
}

export default Focus
```

然后，我们实现 `handleClick` 方法：

```jsx
const handleClick = () => { 
  inputRef.current.focus()
} 
```

正如你所看到的，我们正在引用 `inputRef` 的 `current` 属性，并调用它的 `focus` 方法。

要理解它来自哪里，你只需检查 `render` 的实现。

```jsx
return ( 
  <> 
    <input 
      type="text" 
      ref={inputRef} 
    /> 
    <button onClick={handleClick}>Set Focus</button> 
  </> 
)
```

这里是逻辑的核心。我们创建了一个带有输入元素的表单，并在其 `ref` 属性上定义了一个函数。

我们定义的回调函数在组件挂载时被调用，元素参数表示输入的 DOM 实例。重要的是要知道，当组件被卸载时，相同的回调会以 `null` 参数被调用以释放内存。

在回调中我们所做的是存储元素的引用，以便将来使用（例如，当触发 `handleClick` 方法时）。然后，我们有一个带有事件处理程序的按钮。在浏览器中运行上述代码将显示带有字段和按钮的表单，并且点击按钮将聚焦输入字段，如预期的那样。

正如我们之前提到的，一般来说，我们应该尽量避免使用 refs，因为它们会使代码更加命令式，变得更难阅读和维护。

# 实现动画

当我们考虑 UI 和浏览器时，我们一定也要考虑动画。动画化的 UI 对用户更加愉悦，它们是向用户展示发生了或即将发生的事情的非常重要的工具。

本节不旨在成为创建动画和美观 UI 的详尽指南；这里的目标是为您提供一些关于我们可以采用的常见解决方案的基本信息，以便为我们的 React 组件添加动画。

对于 React 这样的 UI 库，提供一种简单的方式让开发人员创建和管理动画是至关重要的。React 自带一个名为 `react-addons-css-transition-group` 的附加组件，它是一个帮助我们以声明方式构建动画的组件。再次，能够以声明方式执行操作是非常强大的，它使代码更容易理解并与团队共享。

让我们看看如何使用 React 附加组件对文本应用简单的淡入效果，然后我们将使用 `react-motion` 执行相同的操作，这是一个使创建复杂动画更容易的第三方库。

要开始构建一个动画组件，我们需要做的第一件事是安装这个附加组件：

```jsx
npm install --save react-addons-css-transition-group @types/react-addons-css-transition-group
```

一旦我们完成了这个操作，我们就可以导入该组件：

```jsx
import CSSTransitionGroup from 'react-addons-css-transition-group'
```

然后，我们只需包装我们想要应用动画的组件：

```jsx
const Transition = () => ( 
  <CSSTransitionGroup 
    transitionName="fade" 
    transitionAppear 
    transitionAppearTimeout={500} 
  > 
    <h1>Hello React</h1> 
  </CSSTransitionGroup> 
)
```

正如你所看到的，有一些需要解释的属性。

首先，我们声明了 `transitionName` 属性。`ReactCSSTransitionGroup` 将该属性的名称应用到子元素的类中，以便我们可以使用 CSS 过渡来创建我们的动画。

使用单个类，我们无法轻松创建适当的动画，这就是为什么过渡组件根据动画状态应用多个类。在这种情况下，使用 `transitionAppear` 属性，我们告诉组件我们希望在屏幕上出现时对子元素进行动画处理。

因此，图书馆所做的是在组件被渲染时立即应用 `fade-appear` 类（其中 `fade` 是 `transitionName` 属性的值）。在下一个时刻，`fade-appear-active` 类被应用，以便我们可以从初始状态到新状态触发我们的动画，使用 CSS。

我们还必须设置 `transitionAppearTimeout` 属性，告诉 React 动画的长度，以便在动画完成之前不要从 DOM 中移除元素。

使元素淡入的 CSS 如下。

首先，我们定义元素在初始状态下的不透明度：

```jsx
.fade-appear { 
  opacity: 0.01; 
}
```

然后，我们使用第二个类来定义我们的过渡，一旦它被应用到元素上就会开始：

```jsx
.fade-appear.fade-appear-active { 
  opacity: 1; 
  transition: opacity .5s ease-in; 
}
```

我们正在使用`ease-in`函数在`500ms`内将不透明度从`0.01`过渡到`1`。这很容易，但我们可以创建更复杂的动画，我们也可以动画化组件的不同状态。例如，当新元素作为过渡组的子元素添加时，`*-enter`和`*-enter-active`类会被应用。类似的情况也适用于删除元素。

在我们的下一节中，我们将查看在 React 中创建动画最流行的库：`react-motion`，这个库由 Cheng Lou 维护。它提供了一个非常干净和易于使用的 API，为我们提供了一个非常强大的工具来创建任何动画。

## React Motion

**React Motion**是一个用于 React 应用程序的动画库，它使得创建和实现逼真动画变得容易。一旦动画的复杂性增加，或者当我们需要依赖其他动画的动画，或者当我们需要将一些基于物理的行为应用到我们的组件上（这是一个更高级的技术），我们会意识到过渡组并不能帮助我们足够，所以我们可能会考虑使用第三方库。

要使用它，我们首先必须安装它：

```jsx
npm install --save react-motion @types/react-motion
```

安装成功后，我们需要导入`Motion`组件和`spring`函数。`Motion`是我们将用来包装我们想要动画的元素的组件，而函数是一个实用工具，可以将一个值从其初始状态插值到最终状态：

```jsx
import { Motion, spring } from 'react-motion'
```

让我们看看代码：

```jsx
const Transition = () => ( 
  <Motion 
    defaultStyle={{ opacity: 0.01 }} 
    style={{ opacity: spring(1) }} 
  > 
    {interpolatingStyle => ( 
      <h1 style={interpolatingStyle}>Hello React</h1> 
    )} 
  </Motion> 
)
```

这里有很多有趣的东西。首先，您可能已经注意到这个组件使用了函数作为子模式（参见*第四章，探索流行的组合模式*），这是一种非常强大的技术，用于定义在运行时接收值的子元素。

然后，我们可以看到`Motion`组件有两个属性：第一个是`defaultStyle`，它表示初始的`style`属性。同样，我们将不透明度设置为`0.01`来隐藏元素并开始淡入。

`style`属性代表最终的样式，但我们不直接设置值；相反，我们使用`spring`函数，使得值从初始状态插值到最终状态。

在`spring`函数的每次迭代中，子函数接收给定时间点的插值样式，只需将接收到的对象应用到组件的`style`属性，我们就可以看到不透明度的过渡。

这个库可以做一些更酷的事情，但首先要了解的是基本概念，这个例子应该能澄清它们。

比较过渡组和`react-motion`的两种不同方法也很有趣，以便能够选择适合你正在工作的项目的正确方法。

最后，在下一节中，我们将看到如何在 React 中使用 SVG。

# 探索 SVG

最后但同样重要的是，我们可以在浏览器中应用一种最有趣的技术来绘制图标和图形，那就是**可缩放矢量图形**（**SVG**）。

SVG 很棒，因为它是一种描述矢量的声明性方式，它与 React 的目的完全契合。我们过去常常使用图标字体来创建图标，但它们有众所周知的问题，首先是它们不可访问。用 CSS 定位图标字体也相当困难，它们在所有浏览器中并不总是看起来美观。这就是我们应该为我们的 Web 应用程序更喜欢 SVG 的原因。

从 React 的角度来看，无论我们从`render`方法中输出`div`还是 SVG 元素，都没有任何区别，这就是它如此强大的原因。我们也倾向于选择 SVG，因为我们可以很容易地使用 CSS 和 JavaScript 在运行时修改它们，这使它们成为 React 功能方法的绝佳选择。

因此，如果我们将组件视为其 props 的函数，我们可以很容易地想象如何创建可以通过传递不同 props 来操作的自包含 SVG 图标。在 React 中创建 SVG 的常见方法是将我们的矢量图包装到一个 React 组件中，并使用 props 来定义它们的动态值。

让我们看一个简单的例子，我们画一个蓝色的圆，从而创建一个包装 SVG 元素的 React 组件：

```jsx
const Circle = ({ x, y, radius, fill }) => ( 
  <svg> 
 <circle cx={x} cy={y} r={radius} fill={fill} /> 
  </svg> 
)
```

正如你所看到的，我们可以很容易地使用一个无状态的函数组件来包装 SVG 标记，它接受与 SVG 相同的 props。

一个示例用法如下：

```jsx
<Circle x={20} y={20} radius={20} fill="blue" /> 
```

显然，我们可以充分利用 React 的功能，并设置一些默认参数，以便如果圆形图标在没有 props 的情况下呈现，我们仍然可以显示一些东西。

例如，我们可以定义默认颜色：

```jsx
const Circle = ({ x, y, radius, fill = 'red' }) => (...)
```

当我们构建 UI 时，这非常强大，特别是在一个团队中，我们共享我们的图标集，并且希望在其中有一些默认值，但我们也希望让其他团队决定他们的设置，而不必重新创建相同的 SVG 形状。

然而，在某些情况下，我们更倾向于更严格地固定一些值以保持一致性。使用 React，这是一个非常简单的任务。

例如，我们可以将基本圆形组件包装成`RedCircle`，如下所示：

```jsx
const RedCircle = ({ x, y, radius }) => ( 
  <Circle x={x} y={y} radius={radius} fill="red" /> 
)
```

在这里，颜色是默认设置的，不能更改，而其他 props 会透明地传递给原始圆。

以下截图显示了由 React 使用 SVG 生成的两个圆，蓝色和红色：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/024940fd-bb15-47bd-8457-f738b7cd573a.png)

我们可以应用这种技术，并创建圆的不同变体，比如`SmallCircle`和`RightCircle`，以及构建 UI 所需的其他一切。

# 总结

在本章中，我们看了一下当我们用 React 来针对浏览器时可以做的不同事情，从表单创建到事件，从动画到 SVG。此外，我们学会了如何使用新的`useRef` Hook。React 为我们提供了一种声明性的方式来管理我们在创建 Web 应用程序时需要处理的所有方面。

如果需要，React 会以一种方式为我们提供对实际 DOM 节点的访问，这意味着我们可以对它们执行命令式操作，这在我们需要将 React 与现有的命令式库集成时非常有用。

下一章将讨论 CSS 和内联样式，它将阐明在 JavaScript 中编写 CSS 意味着什么。


# 第三部分：性能，改进和生产！

本节将解释如何提高 React 应用程序的性能，如何使用 CSS 模块和`styled-components`处理样式，最后如何将应用程序部署到生产环境。

我们将在本节中涵盖以下章节：

+   第八章，让你的组件看起来漂亮

+   第九章，为了乐趣和利润进行服务器端渲染

+   第十章，提高应用程序的性能

+   第十一章，测试和调试

+   第十二章，React 路由

+   第十三章，要避免的反模式

+   第十四章，部署到生产环境

+   第十五章，下一步


# 第八章：使您的组件看起来漂亮

我们的 React 最佳实践和设计模式之旅现在已经达到了我们想要让组件看起来漂亮的地步。为了做到这一点，我们将详细介绍为什么常规 CSS 可能不是样式化组件的最佳方法的所有原因，并且我们将了解各种替代解决方案。

从内联样式开始，然后是 Radium、CSS 模块和`styled-components`，本章将指导您进入 JavaScript 中 CSS 的神奇世界。

在本章中，我们将涵盖以下主题：

+   规模上常见的常规 CSS 问题

+   在 React 中使用内联样式及其缺点

+   Radium 库如何帮助解决内联样式的问题

+   如何使用 Webpack 和 CSS 模块从头开始设置项目

+   CSS 模块的特性以及它们为什么是避免全局 CSS 的绝佳解决方案

+   `styled-components`，一种为 React 组件提供现代样式的新库

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

您可以在书籍的 GitHub 存储库中找到本章的代码：[`github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter08`](https://github.com/PacktPublishing/React-17-Design-Patterns-and-Best-Practices-Third-Edition/tree/main/Chapter08)。

# JavaScript 中的 CSS

在社区中，每个人都同意在 2014 年 11 月，React 组件的样式发生了革命，当时 Christopher Chedea 在 NationJS 会议上发表了演讲。

在互联网上也被称为**vjeux**，Christopher 在 Facebook 工作并为 React 做出贡献。在他的演讲中，他详细介绍了他们在 Facebook 面临的所有与 CSS 相关的问题。值得理解所有这些问题，因为其中一些问题非常普遍，它们将帮助我们引入内联样式和本地作用域类名等概念。

以下是 CSS 存在的问题清单，基本上是在规模上出现的问题：

+   全局命名空间

+   依赖关系

+   死代码消除

+   最小化

+   共享常量

+   非确定性解决方案

+   隔离

CSS 的第一个众所周知的问题是所有选择器都是全局的。无论我们如何组织我们的样式，使用命名空间或诸如**块**，**元素**，**修饰符**（**BEM**）方法之类的过程，最终我们总是在污染全局命名空间，我们都知道这是错误的。这不仅在原则上是错误的，而且在大型代码库中会导致许多错误，并且在长期内使可维护性非常困难。与大团队合作，要知道特定类或元素是否已经被样式化是非平凡的，大多数情况下，我们倾向于添加更多类而不是重用现有类。

CSS 的第二个问题涉及依赖关系的定义。事实上，很难清楚地说明特定组件依赖于特定的 CSS，并且必须加载 CSS 才能应用样式。由于样式是全局的，任何文件中的任何样式都可以应用于任何元素，失去控制非常容易。

第三个问题是前端开发人员倾向于使用预处理器来将他们的 CSS 拆分成子模块，但最终，会为浏览器生成一个大的全局 CSS 捆绑包。由于 CSS 代码库很快变得庞大，我们失去了对它们的控制，第三个问题与死代码消除有关。很难迅速确定哪些样式属于哪个组件，这使得删除代码非常困难。事实上，由于 CSS 的级联特性，删除选择器或规则可能会导致浏览器中出现意外结果。

与 CSS 工作的另一个痛点涉及选择器和类名在 CSS 和 JavaScript 应用程序中的缩小。这似乎是一项简单的任务，但实际上并非如此，特别是当类在客户端上应用或连接时；这是第四个问题。

无法缩小和优化类名对性能来说非常糟糕，并且它可能会对 CSS 的大小产生巨大影响。另一个常见的非平凡操作是在样式和客户端应用程序之间共享常量。我们经常需要知道标题的高度，例如，以便重新计算依赖于它的其他元素的位置。

通常，我们使用 JavaScript API 在客户端读取值，但最佳解决方案是共享常量并避免在运行时进行昂贵的计算。这代表了 vjeux 和 Facebook 的其他开发人员试图解决的第五个问题。

第六个问题涉及 CSS 的非确定性解析。实际上，在 CSS 中，顺序很重要，如果 CSS 按需加载，顺序就无法保证，这会导致错误的样式应用于元素。

例如，假设我们想优化请求 CSS 的方式，只有在用户导航到特定页面时才加载与该页面相关的 CSS。如果与最后一个页面相关的 CSS 具有一些规则，这些规则也适用于不同页面的元素，那么最后加载它可能会影响应用程序其余部分的样式。例如，如果用户返回到上一个页面，他们可能会看到一个 UI 略有不同于他们第一次访问时的页面。

控制各种样式、规则和导航路径的各种组合非常困难，但是，能够在需要时加载 CSS 可能会对 Web 应用程序的性能产生关键影响。

最后但同样重要的是，根据 Christopher Chedeau 的说法，CSS 的第七个问题与隔离有关。在 CSS 中，几乎不可能在文件或组件之间实现适当的隔离。选择器是全局的，很容易被覆盖。仅仅通过知道应用于元素的类名就很难预测元素的最终样式，因为样式不是隔离的，应用程序其他部分的其他规则可能会影响不相关的元素。这可以通过使用内联样式来解决。

在接下来的部分中，我们将看看在 React 中使用内联样式意味着什么，以及其优缺点。

# 理解并实现内联样式

官方的 React 文档建议开发人员使用内联样式来为他们的 React 组件设置样式。这似乎有点奇怪，因为多年来我们都学到了分离关注点很重要，我们不应该混合标记和 CSS。

React 试图通过将关注点的概念从技术的分离转移到组件的分离来改变。当标记、样式和逻辑紧密耦合且一个不能没有另一个而无法工作时，将它们分离到不同的文件中只是一种幻觉。即使它有助于保持项目结构更清洁，但它并没有提供任何真正的好处。

在 React 中，我们组合组件来创建应用程序，其中组件是我们结构的基本单位。我们应该能够在应用程序中移动组件，并且无论它们被渲染在哪里，它们都应该提供相同的逻辑和 UI 结果。

这是为什么在 React 中将样式与组件放在一起，并使用内联样式在元素上应用它们可能是有意义的原因之一。

首先，让我们看一个例子，看看在 React 中使用节点的样式属性来为我们的组件应用样式意味着什么。我们将创建一个带有文本 `Click me!` 的按钮，并为其应用颜色和背景颜色：

```jsx
const style = { 
  color: 'palevioletred', 
  backgroundColor: 'papayawhip'
};

const Button = () => <button style={style}>Click me!</button>;
```

正如你所看到的，使用内联样式在 React 中很容易为元素设置样式。我们只需要创建一个对象，其中属性是 CSS 规则，值是我们在常规 CSS 文件中使用的值。

唯一的区别是，连字符的 CSS 规则必须转换为驼峰命名以符合 JavaScript 的规范，并且值是字符串，因此它们必须用引号括起来。

关于供应商前缀有一些例外情况。例如，如果我们想在 `webkit` 上定义一个过渡，我们应该使用 `WebkitTransition` 属性，其中 `webkit` 前缀以大写字母开头。这条规则适用于所有供应商前缀，除了 `ms`，它是小写的。

其他用例是数字 - 它们可以不用引号或单位来编写，并且默认情况下被视为像素。

以下规则适用于 `100` 像素的高度：

```jsx
const style = { 
  height: 100
}
```

通过使用内联样式，我们还可以做一些难以用常规 CSS 实现的事情。例如，我们可以在客户端动态重新计算一些 CSS 值，这是一个非常强大的概念，正如你将在下面的例子中看到的。

假设你想创建一个表单字段，其字体大小根据其值改变。因此，如果字段的值为`24`，字体大小将为 24 像素。使用普通的 CSS，这种行为几乎不可能在不付出巨大努力和重复代码的情况下复制。

让我们看看使用内联样式有多容易，首先创建一个`FontSize`组件，然后声明一个值状态：

```jsx
import { useState, ChangeEvent } from 'react'

const FontSize = () => {
  const [value, setValue] = useState<number>(16)
}

export default FontSize
```

我们实现了一个简单的变更处理程序，其中我们使用事件的目标属性来检索字段的当前值：

```jsx
const handleChange = (e: ChangeEvent<HTMLInputElement>) => { 
  setValue(Number(e.target.value))
}
```

最后，我们渲染`number`类型的输入文件，这是一个受控组件，因为我们通过使用状态来保持其值更新。它还有一个事件处理程序，每当字段的值改变时就会触发。

最后但并非最不重要的是，我们使用字段的样式属性来设置其`font-size`值。正如你所看到的，我们使用了 CSS 规则的驼峰命名版本，以遵循 React 的约定：

```jsx
return ( 
  <input 
    type="number" 
    value={value} 
    onChange={handleChange} 
    style={{ fontSize: value }} 
  /> 
)
```

渲染前面的组件，我们可以看到一个输入字段，它根据其值更改其字体大小。它的工作方式是，当值改变时，我们将字段的新值存储在状态中。修改状态会强制组件重新渲染，我们使用新的状态值来设置字段的显示值和字体大小；这很简单又很强大。

计算机科学中的每个解决方案都有其缺点，并且总是代表一种权衡。在内联样式的情况下，不幸的是，问题很多。

例如，使用内联样式时，不可能使用伪选择器（例如`:hover`）和伪元素，如果你正在创建具有交互和动画的 UI，这是一个相当重要的限制。

有一些变通方法，例如，你总是可以创建真实的元素而不是伪元素，但对于伪类，需要使用 JavaScript 来模拟 CSS 行为，这并不理想。

同样适用于**媒体查询**，无法使用内联样式来定义，这使得创建响应式 Web 应用程序变得更加困难。由于样式是使用 JavaScript 对象声明的，也不可能使用样式回退：

```jsx
display: -webkit-flex; 
display: flex;
```

JavaScript 对象不能具有相同名称的两个属性。应该避免使用样式回退，但如果需要，总是可以使用它们。

CSS 的另一个特性是**动画**，这是无法使用内联样式来模拟的。在这里的解决方法是全局定义动画，并在元素的 style 属性中使用它们。使用内联样式时，每当我们需要用常规 CSS 覆盖样式时，我们总是被迫使用`!important`关键字，这是一种不好的做法，因为它会阻止任何其他样式被应用到元素上。

使用内联样式最困难的事情是调试。我们倾向于使用类名在浏览器的开发工具中查找元素进行调试，并检查应用了哪些样式。使用内联样式时，所有项目的样式都列在它们的`style`属性中，这使得检查和调试结果非常困难。

例如，我们在本节早些时候创建的按钮以以下方式呈现：

```jsx
<button style="color:palevioletred;background-color:papayawhip;">Click me!</button>
```

单独看起来并不难阅读，但是如果想象一下您有数百个元素和数百种样式，您会意识到问题变得非常复杂。

此外，如果您正在调试一个列表，其中每个项目都具有相同的`style`属性，并且如果您在浏览器中实时修改其中一个以检查结果，您会发现您只将样式应用于该项目，而不是所有其他兄弟项目，即使它们共享相同的样式。

最后但并非最不重要的是，如果我们在服务器端渲染我们的应用程序（我们将在*第九章* *为了乐趣和利润而进行服务器端渲染*中涵盖此主题），那么使用内联样式时页面的大小会更大。

使用内联样式，我们将所有 CSS 内容放入标记中，这会向发送给客户端的文件添加额外的字节数，并使 Web 应用程序显得更慢。压缩算法可以帮助解决这个问题，因为它们可以轻松压缩相似的模式，并且在某些情况下，加载关键路径 CSS 是一个很好的解决方案；但总的来说，我们应该尽量避免使用内联样式。

事实证明，内联样式带来的问题比它们试图解决的问题更多。因此，社区创建了不同的工具来解决内联样式的问题，但同时保持样式在组件内部或局部，以获得两全其美。

在 Christopher Chedeau 的讲话之后，许多开发人员开始谈论内联样式，并进行了许多解决方案和实验，以找到在 JavaScript 中编写 CSS 的新方法。起初，有两三种解决方案，而今天已经有 40 多种。

在接下来的章节中，我们将介绍最受欢迎的解决方案。

# 探索 Radium 库

为了解决我们在前一节中遇到的内联样式问题而创建的最早的库之一是**Radium**。它由 Formidable Labs 的优秀开发人员维护，仍然是最受欢迎的解决方案之一。

在本节中，我们将看看 Radium 是如何工作的，它解决了哪些问题，以及为什么它是与 React 一起用于样式化组件的绝佳库。我们将创建一个非常简单的按钮，类似于本章前面示例中构建的按钮。

我们将从一个没有样式的基本按钮开始，然后添加一些基本样式，以及伪类和媒体查询，以便我们可以了解该库的主要特性。

我们将从以下方式创建按钮开始：

```jsx
const Button = () => <button>Click me!</button>
```

首先，我们必须使用`npm`安装 Radium：

```jsx
npm install --save radium @types/radium
```

安装完成后，我们可以导入库并将按钮包装在其中：

```jsx
import Radium from 'radium'

const Button = () => <button>Click me!</button>

export default Radium(Button)
```

`Radium`函数是一个**高阶组件**（**HOC**）（见*第四章*，*探索所有组合模式*），它扩展了`Button`的功能，返回一个新的增强组件。如果我们在浏览器中渲染按钮，目前不会看到任何特别之处，因为我们没有对其应用任何样式。

让我们从一个简单的样式对象开始，我们在其中设置背景颜色、填充、大小和一些其他 CSS 属性。正如我们在前一节中看到的，React 中的内联样式是使用驼峰式 CSS 属性定义的 JavaScript 对象：

```jsx
const styles = { 
  backgroundColor: '#ff0000', 
  width: 320, 
  padding: 20, 
  borderRadius: 5, 
  border: 'none', 
  outline: 'none'
}
```

前面的片段与 React 中的普通内联样式没有区别，如果我们将其传递给我们的按钮，我们可以在浏览器中看到应用于按钮的所有样式：

```jsx
const Button = () => <button style={styles}>Click me!</button>
```

结果如下标记：

```jsx
<button data-radium="true" style="background-color: rgb(255, 0, 0); width: 320px; padding: 20px; border-radius: 5px; border: none; outline: none;">Click me!</button>
```

您可以在这里看到的唯一区别是元素附加了`data-radium`属性设置为`true`。

现在，我们已经看到内联样式不允许我们定义任何伪类；让我们看看如何使用 Radium 解决这个问题。

使用伪类，比如`：hover`，与 Radium 一起非常简单。我们必须在样式对象内创建一个`:hover`属性，Radium 会完成其余工作：

```jsx
const styles = { 
  backgroundColor: '#ff0000', 
  width: 320, 
  padding: 20, 
  borderRadius: 5, 
  border: 'none', 
  outline: 'none', 
  ':hover': { 
    color: '#fff' 
  } 
}
```

如果您将这个样式对象应用于您的按钮并在屏幕上呈现它，您会看到将鼠标悬停在按钮上会导致按钮变成白色文本，而不是默认的黑色。这太棒了！我们可以同时使用伪类和内联样式。

然而，如果您打开 DevTools 并尝试在`Styles`面板中强制`：hover`状态，您会发现什么也没有发生。您可以看到悬停效果，但无法用 CSS 模拟它的原因是 Radium 使用 JavaScript 来应用和移除`style`对象中定义的悬停状态。

如果您在打开 DevTools 的情况下悬停在元素上，您会看到`style`字符串发生变化，并且颜色会动态添加到其中：

```jsx
<button data-radium="true" style="background-color: rgb(255, 0, 0); width: 320px; padding: 20px; border-radius: 5px; border: none; outline: none; color: rgb(255, 255, 255);">Click me!</button> 
```

Radium 的工作方式是为可以触发伪类行为的每个事件添加事件处理程序并监听它们。

一旦其中一个事件被触发，Radium 会改变组件的状态，这将重新呈现具有正确状态样式的组件。这一开始可能看起来很奇怪，但这种方法没有真正的缺点，而且在性能方面的差异是不可感知的。

我们可以添加新的伪类，例如`:active`，它们也会起作用：

```jsx
const styles = { 
  backgroundColor: '#ff0000', 
  width: 320, 
  padding: 20, 
  borderRadius: 5, 
  border: 'none', 
  outline: 'none', 
  ':hover': { 
    color: '#fff'
  }, 
  ':active': { 
    position: 'relative', 
    top: 2
  } 
}
```

Radium 启用的另一个关键功能是媒体查询。媒体查询对于创建响应式应用程序至关重要，Radium 再次使用 JavaScript 在我们的应用程序中启用了这个 CSS 特性。

让我们看看它是如何工作的 - API 非常相似；我们必须在我们的样式对象上创建一个新属性，并在其中嵌套必须在媒体查询匹配时应用的样式：

```jsx
const styles = { 
  backgroundColor: '#ff0000', 
  width: 320, 
  padding: 20, 
  borderRadius: 5, 
  border: 'none', 
  outline: 'none', 
  ':hover': { 
    color: '#fff' 
  }, 
  ':active': { 
    position: 'relative', 
    top: 2
  }, 
  '@media (max-width: 480px)': { 
    width: 160 
  } 
}
```

我们必须做一件事才能使媒体查询正常工作，那就是将我们的应用程序包装在 Radium 提供的`StyleRoot`组件中。

为了使媒体查询正常工作，特别是在服务器端渲染中，Radium 将在**文档对象模型**（**DOM**）中注入与媒体查询相关的规则，所有属性都设置为`!important`。

这是为了避免在库弄清匹配查询之前应用于文档的不同样式之间闪烁。通过在`style`元素内实现样式，可以通过让浏览器执行其常规工作来防止这种情况。

因此，想法是导入`Radium.StyleRoot`组件：

```jsx
import Radium from 'radium'
```

然后，我们可以将整个应用程序包装在其中：

```jsx
const App = () => { 
  return ( 
    <Radium.StyleRoot> 
      ... 
    </Radium.StyleRoot> 
  ) 
}
```

因此，如果您打开 DevTools，您会看到 Radium 将以下样式注入到 DOM 中：

```jsx
<style>@media (max-width: 480px) { .rmq-1d8d7428{width: 160px !important;}}</style>
```

`rmq-1d8d7428`类也已自动应用于按钮：

```jsx
<button class="rmq-1d8d7428" data-radium="true" style="background-color: rgb(255, 0, 0); width: 320px; padding: 20px; border-radius: 5px; border: none; outline: none;">Click me!</button>
```

如果您现在调整浏览器窗口大小，您会发现按钮在小屏幕上变小，这是预期的。

在下一节中，我们将学习如何使用 CSS 模块。

# 使用 CSS 模块

如果您觉得内联样式不适合您的项目和团队，但仍希望将样式尽可能靠近组件，那么有一个适合您的解决方案，称为**CSS 模块**。CSS 模块是 CSS 文件，默认情况下所有类名和动画名称都是本地作用域的。让我们看看如何在我们的项目中使用它们；但首先，我们需要配置 Webpack。

## Webpack 5

在深入研究 CSS 模块并了解它们的工作原理之前，重要的是要了解它们是如何创建的以及支持它们的工具。

在*第二章* *清理您的代码*中，我们看到了如何编写 ES6 代码并使用 Babel 及其预设进行转译。随着应用程序的增长，您可能还希望将代码库拆分为模块。

你可以使用 Webpack 或 Browserify 将应用程序分成小模块，需要时可以导入它们，同时为浏览器创建一个大捆绑。这些工具被称为**模块捆绑器**，它们的作用是将应用程序的所有依赖项加载到一个可以在浏览器中执行的单个捆绑中，浏览器本身没有任何模块的概念（尚未）。

在 React 世界中，Webpack 特别受欢迎，因为它提供了许多有趣和有用的功能，第一个功能是加载器的概念。使用 Webpack，您可以潜在地加载除 JavaScript 以外的任何依赖项，只要有相应的加载器。例如，您可以在捆绑包中加载 JSON 文件，以及图像和其他资产。

2015 年 5 月，CSS 模块的创作者之一 Mark Dalgleish 发现您也可以在 Webpack 捆绑包中导入 CSS，并推动了这一概念。他认为，由于 CSS 可以在组件中本地导入，所有导入的类名也可以本地作用域，这很棒，因为这将隔离样式。

## 设置项目

在本节中，我们将看看如何设置一个非常简单的 Webpack 应用程序，使用 Babel 来转译 JavaScript 和 CSS 模块以将我们的本地作用域 CSS 加载到捆绑包中。我们还将介绍 CSS 模块的所有特性并看看它们可以解决的问题。首先要做的是移动到一个空文件夹并运行以下命令：

```jsx
npm init
```

这将创建一个`package.json`文件并设置一些默认值。

现在，是时候安装依赖项了，第一个是`webpack`，第二个是`webpack-dev-server`，我们将使用它来在本地运行应用程序并即时创建捆绑包：

```jsx
npm install --save-dev webpack webpack-dev-server webpack-cli
```

一旦安装了 Webpack，就是安装 Babel 及其加载器的时候了。由于我们使用 Webpack 来创建捆绑包，我们将使用 Babel 加载器在 Webpack 内部转译我们的 ES6 代码：

```jsx
npm install --save-dev @babel/core @babel/preset-env @babel/preset-react ts-loader
```

最后，我们安装`style-loader`和 CSS 加载器，这是我们需要启用 CSS 模块的两个加载器：

```jsx
npm install --save-dev style-loader css-loader
```

还有一件事要做，让事情变得更容易，那就是安装`html-webpack-plugin`，这是一个插件，可以通过查看 Webpack 配置来即时创建一个 HTML 页面来托管我们的 JavaScript 应用程序，而无需我们创建一个常规文件。此外，我们需要安装`fork-ts-checker-webpack-plugin`包来使 TypeScript 与 Webpack 一起工作：

```jsx
npm install --save-dev html-webpack-plugin fork-ts-checker-webpack-plugin typescript
```

最后但同样重要的是，我们安装`react`和`react-dom`来在我们的简单示例中使用它们：

```jsx
npm install react react-dom
```

现在所有的依赖都安装好了，是时候配置一切使其工作了。

首先，您需要在根路径下创建一个`.babelrc`文件：

```jsx
{
 "presets": ["@babel/preset-env", "@babel/preset-react"]
}
```

首先要做的是在`package.json`中添加一个`npm`脚本来运行`webpack-dev-server`，它将在开发中为应用程序提供服务：

```jsx
"scripts": { 
  "dev": "webpack serve --mode development --port 3000" 
}
```

在 Webpack 5 中，您需要使用这种方式调用`webpack`而不是`webpack-dev-server`，但您仍然需要安装这个包。

Webpack 需要一个配置文件来知道如何处理我们应用程序中使用的不同类型的依赖关系，为此，我们必须创建一个名为`webpack.config.js`的文件，它导出一个对象：

```jsx
module.exports = {}
```

我们导出的对象代表 Webpack 用来创建捆绑包的配置对象，它可以根据项目的大小和特性有不同的属性。

我们希望保持我们的示例非常简单，所以我们将添加三个属性。第一个是`entry`，它告诉 Webpack 我们应用程序的主文件在哪里：

```jsx
entry: './src/index.tsx'
```

第二个是`module`，在那里我们告诉 Webpack 如何加载外部依赖项。它有一个名为`rules`的属性，我们为每种文件类型设置了特定的加载器：

```jsx
module: { 
  rules: [
    {
      test: /\.(tsx|ts)$/,
      exclude: /node_modules/,
      use: {
        loader: 'ts-loader',
        options: {
          transpileOnly: true
        }
      }
    }, 
    { 
      test: /\.css/,
      use: [
        'style-loader',
        'css-loader?modules=true'
      ]
    } 
  ]
}
```

我们说匹配`.ts`或`.tsx`正则表达式的文件将使用`ts-loader`加载，以便它们被转译并加载到捆绑包中。

您可能还注意到我们在`.babelrc`文件中添加了我们的预设。正如我们在*第二章*中看到的*清理您的代码*，预设是一组配置选项，指示 Babel 如何处理不同类型的语法（例如 TSX）。

`rules`数组中的第二个条目告诉 Webpack 在导入 CSS 文件时该怎么做，并且它使用`css-loader`和启用`modules`标志来激活 CSS 模块。转换的结果然后传递给`style-loader`，它将样式注入到页面的头部。

最后，我们启用 HTML 插件来为我们生成页面，自动使用我们之前指定的入口路径添加`script`标签：

```jsx
const HtmlWebpackPlugin = require('html-webpack-plugin')
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin')

plugins: [
  new ForkTsCheckerWebpackPlugin(),
 new HtmlWebpackPlugin({
    title: 'Your project name',
    template: './src/index.html',
    filename: './index.html'
  })
]
```

完整的`webpack.config.js`应该如下代码块所示：

```jsx
const HtmlWebpackPlugin = require('html-webpack-plugin')
const path = require('path')
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin')

const isProduction = process.env.NODE_ENV === 'production'

module.exports = {
  devtool: !isProduction ? 'source-map' : false, // We generate source maps 
  // only for development
  entry: './src/index.tsx',
  output: { // The path where we want to output our bundles
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].[hash:8].js',
    sourceMapFilename: '[name].[hash:8].map',
    chunkFilename: '[id].[hash:8].js',
    publicPath: '/'
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.json', '.css'] // Here we add the 
    // extensions we want to support
  },
  target: 'web',
  mode: isProduction ? 'production' : 'development', // production mode 
  // minifies the code
  module: { 
    rules: [
      {
        test: /\.(tsx|ts)$/,
        exclude: /node_modules/,
        use: {
          loader: 'ts-loader',
          options: {
            transpileOnly: true
          }
        }
      }, 
      { 
        test: /\.css/,
        use: [
          'style-loader',
          'css-loader?modules=true'
        ]
      } 
    ]
  }, 
  plugins: [
    new ForkTsCheckerWebpackPlugin(),
 new HtmlWebpackPlugin({
      title: 'Your project name',
      template: './src/index.html',
      filename: './index.html'
    })
  ],
  optimization: { // This is to split our bundles into vendor and main
    splitChunks: {
      cacheGroups: {
        default: false,
        commons: {
          test: /node_modules/,
          name: 'vendor',
          chunks: 'all'    
        }
      }
    }
  }
}
```

然后，要配置 TypeScript，您需要这个`tsconfig.json`文件：

```jsx
{
  "compilerOptions": {
    "allowJs": true,
    "allowSyntheticDefaultImports": true,
    "baseUrl": "src",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "jsx": "react-jsx",
    "lib": ["dom", "dom.iterable", "esnext"],
    "module": "esnext",
    "moduleResolution": "node",
    "noEmit": true,
    "noFallthroughCasesInSwitch": true,
    "noImplicitAny": false,
    "resolveJsonModule": true,
    "skipLibCheck": true,
    "sourceMap": true,
    "strict": true,
    "target": "es6"
  },
  "include": ["src/**/*.ts", "src/**/*.tsx"],
  "exclude": ["node_modules"]
}
```

为了使用 TypeScript 导入`css`文件，您需要在`src/declarations.d.ts`中创建一个声明文件：

```jsx
declare module '*.css' {
  const content: Record<string, string>
  export default content
}
```

然后，您需要在`src/index.tsx`中创建主文件：

```jsx
import { render } from 'react-dom'

const App = () => {
  return <div>Hello World</div>
}

render(<App />, document.querySelector('#root'))
```

最后，您需要在`src/index.html`中创建初始 HTML 文件：

```jsx
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" 
      />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title><%= htmlWebpackPlugin.options.title %></title>
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
```

我们完成了，如果我们在终端中运行`npm run dev`命令并将浏览器指向`http://localhost:8080`，我们应该能够看到提供的以下标记：

```jsx
<!DOCTYPE html> 
<html> 
  <head> 
    <meta charset="UTF-8"> 
    <title>Your project name</title>
    <script defer src="/vendor.12472959.js"></script>
    <script defer src="/main.12472959.js"></script> 
  </head> 
 <body>    <div id="root"></div>
  </body> 
</html>
```

完美-我们的 React 应用程序正在运行！现在让我们看看如何向我们的项目添加一些 CSS。

## 本地作用域的 CSS

现在，是时候创建我们的应用程序了，它将由一个简单的按钮组成，与我们在以前的示例中使用的相同类型。我们将用它来展示 CSS 模块的所有功能。

让我们更新`src/index.tsx`文件，这是我们在 Webpack 配置中指定的入口：

```jsx
import { render } from 'react-dom'
```

然后，我们可以创建一个简单的按钮。像往常一样，我们将从一个非样式化的按钮开始，然后逐步添加样式：

```jsx
 const Button = () => <button>Click me!</button>
```

最后，我们可以将按钮呈现到 DOM 中：

```jsx
render(<Button />, document.querySelector('#root'))
```

现在，假设我们想要为按钮应用一些样式-背景颜色，大小等。我们创建一个名为`index.css`的常规 CSS 文件，并将以下类放入其中：

```jsx
.button { 
  background-color: #ff0000; 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
}
```

现在，我们说过使用 CSS 模块可以将 CSS 文件导入到 JavaScript 中；让我们看看它是如何工作的。

在我们定义按钮组件的 `index.js` 文件中，我们可以添加以下行：

```jsx
import styles from './index.css'
```

这个 `import` 语句的结果是一个 `styles` 对象，其中所有属性都是在 `index.css` 中定义的类。

如果我们运行 `console.log(styles)`，我们可以在 DevTools 中看到以下对象：

```jsx
{ 
  button: "_2wpxM3yizfwbWee6k0UlD4" 
}
```

因此，我们有一个对象，其中属性是类名，值是（表面上）随机字符串。我们稍后会看到它们并非随机，但让我们先检查一下该对象可以做什么。

我们可以使用对象来设置按钮的类名属性，如下所示：

```jsx
const Button = () => ( 
  <button className={styles.button}>Click me!</button> 
);
```

如果我们回到浏览器，现在可以看到我们在 `index.css` 中定义的样式已经应用到按钮上。这并不是魔术，因为如果我们在 DevTools 中检查，应用到元素的类与我们在代码中导入的 `style` 对象附加的相同字符串。

```jsx
<button class="_2wpxM3yizfwbWee6k0UlD4">Click me!</button>
```

如果我们查看页面的头部部分，现在可以看到相同的类名也已经被注入到页面中：

```jsx
<style type="text/css"> 
  ._2wpxM3yizfwbWee6k0UlD4 { 
    background-color: #ff0000; 
    width: 320px; 
    padding: 20px; 
    border-radius: 5px; 
    border: none; 
    outline: none; 
  } 
</style>
```

这就是 CSS 和样式加载器的工作原理。

CSS 加载器允许您将 CSS 文件导入到您的 JavaScript 模块中，并且当模块标志被激活时，所有类名都会被局部作用于导入的模块。正如我们之前提到的，我们导入的字符串并非随机，而是使用文件的哈希和一些其他参数生成的，以在代码库中是唯一的。

最后，`style-loader` 接受 CSS 模块转换的结果，并将样式注入到页面的头部部分。这非常强大，因为我们拥有 CSS 的全部功能和表现力，同时又具有局部作用域类名和明确依赖项的优势。

正如本章开头提到的，CSS 是全局的，这使得在大型应用程序中很难维护。使用 CSS 模块，类名是局部作用域的，它们不会与应用程序不同部分的其他类名冲突，从而强制产生确定性结果。

此外，明确地在组件内部导入 CSS 依赖项有助于清晰地看到哪些组件需要哪些 CSS。它还非常有用，可以消除死代码，因为当我们出于任何原因删除一个组件时，我们可以准确地知道它使用的是哪些 CSS。

CSS 模块是常规的 CSS，因此我们可以使用伪类、媒体查询和动画。

例如，我们可以添加以下 CSS 规则：

```jsx
.button:hover { 
  color: #fff; 
} 

.button:active { 
  position: relative; 
  top: 2px; 
} 

@media (max-width: 480px) { 
  .button { 
    width: 160px 
  } 
}
```

这将被转换为以下代码并注入到文档中：

```jsx
._2wpxM3yizfwbWee6k0UlD4:hover { 
  color: #fff; 
} 

._2wpxM3yizfwbWee6k0UlD4:active { 
  position: relative; 
  top: 2px; 
} 

@media (max-width: 480px) { 
  ._2wpxM3yizfwbWee6k0UlD4 { 
    width: 160px 
  } 
}
```

类名被创建并在按钮使用的所有地方被替换，使其可靠且本地化，正如预期的那样。

您可能已经注意到，这些类名很棒，但它们使调试变得非常困难，因为我们无法轻松地知道哪些类生成了哈希。在开发模式下，我们可以添加一个特殊的配置参数，通过它我们可以选择用于生成作用域类名的模式。

例如，我们可以将加载程序的值更改如下：

```jsx
{
  test: /\.css/,
  use: [
    { 
      loader: 'style-loader'
    },
    {
      loader: "css-loader",
      options: {
        modules: {
          localIdentName: "[local]--[hash:base64:5]"
        }
      }
    }
  ]
}
```

在这里，`localIdentName`是参数，`[local]`和`[hash:base64:5]`是原始类名值和五个字符哈希的占位符。其他可用的占位符是`[path]`，代表 CSS 文件的路径，以及`[name]`，代表源 CSS 文件的名称。

激活之前的配置选项，我们在浏览器中得到的结果如下：

```jsx
<button class="button--2wpxM">Click me!</button>
```

这样更易读，更容易调试。

在生产环境中，我们不需要这样的类名，我们更关心性能，因此我们可能希望更短的类名和哈希。

使用 Webpack 非常简单，因为我们可以有多个配置文件，可以在应用程序生命周期的不同阶段使用。此外，在生产环境中，我们可能希望提取 CSS 文件，而不是将其从捆绑包中注入到浏览器中，以便我们可以获得更轻的捆绑包，并将 CSS 缓存到内容交付网络以获得更好的性能。

要做到这一点，您需要安装另一个 Webpack 插件，称为`mini-css-extract-plugin`，它可以编写一个实际的 CSS 文件，其中包含从 CSS 模块生成的所有作用域类。

有几个值得一提的 CSS 模块特性。

第一个是`global`关键字。实际上，用`:global`作为任何类的前缀意味着要求 CSS 模块不要在本地范围内对当前选择器进行范围限定。

例如，假设我们将 CSS 更改如下：

```jsx
:global .button { 
  ... 
}
```

输出将如下所示：

```jsx
.button { 
  ... 
}
```

如果您想应用无法在本地范围内进行范围限定的样式，例如第三方小部件，这是很好的。

CSS 模块的我最喜欢的特性是**组合**。通过组合，我们可以从同一文件或外部依赖中提取类，并将所有样式应用于元素。

例如，将将按钮的背景设置为红色的规则从按钮的规则中提取到一个单独的块中，如下所示：

```jsx
.background-red { 
  background-color: #ff0000; 
}
```

然后，我们可以按照以下方式在我们的按钮中进行组合：

```jsx
.button { 
  composes: background-red; 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
}
```

结果是按钮的所有规则和`composes`声明的所有规则都应用于元素。

这是一个非常强大的功能，它以一种迷人的方式工作。你可能期望所有组合的类在被引用为 SASS `@extend`时会在类内部重复，但事实并非如此。简而言之，所有组合的类名都会依次应用于 DOM 中的组件。

在我们的特定情况下，我们会有以下情况：

```jsx
<button class="_2wpxM3yizfwbWee6k0UlD4 Sf8w9cFdQXdRV_i9dgcOq">Click me!</button>
```

在这里，注入到页面中的 CSS 如下：

```jsx
.Sf8w9cFdQXdRV_i9dgcOq { 
  background-color: #ff0000; 
} 

._2wpxM3yizfwbWee6k0UlD4 { 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
}
```

正如你所看到的，我们的 CSS 类名具有唯一的名称，这有利于隔离我们的样式。现在，让我们来看看原子 CSS 模块。

## 原子 CSS 模块

应该清楚组合是如何工作的，以及为什么它是 CSS 模块的一个非常强大的特性。在我开始写这本书的时候工作的公司 YPlan 中，我们试图将其推向更高一步，结合`composes`的强大功能和**原子 CSS**（也称为**功能性 CSS**）的灵活性。

原子 CSS 是一种使用 CSS 的方式，其中每个类都有一个单一的规则。

例如，我们可以创建一个类来将`margin-bottom`设置为`0`：

```jsx
.mb0 { 
  margin-bottom: 0; 
}
```

我们可以使用另一个类将`font-weight`设置为`600`：

```jsx
.fw6 { 
  font-weight: 600; 
} 
```

然后，我们可以将所有这些原子类应用于元素：

```jsx
<h2 class="mb0 fw6">Hello React</h2>
```

这种技术既有争议，又非常高效。开始使用它很困难，因为最终会在标记中有太多的类，这使得难以预测最终结果。如果你仔细想想，它与内联样式非常相似，因为你每条规则应用一个类，除了你使用更短的类名作为代理。

反对原子 CSS 的最大论点通常是你将样式逻辑从 CSS 移动到标记中，这是错误的。类是在 CSS 文件中定义的，但它们在视图中组合，每当你必须修改元素的样式时，你最终会编辑标记。

另一方面，我们尝试使用原子 CSS 一段时间，发现它使原型设计变得非常快速。

事实上，当所有基本规则都已生成时，将这些类应用到元素并创建新样式是一个非常快速的过程，这是很好的。其次，使用原子 CSS，我们可以控制 CSS 文件的大小，因为一旦我们创建了具有其样式的新组件，我们就使用现有的类，而不需要创建新的类，这对性能来说非常好。

因此，我们尝试使用 CSS 模块解决原子 CSS 的问题，并将这种技术称为**原子 CSS 模块**。

实质上，您开始创建您的基本 CSS 类（例如，`mb0`），然后，而不是在标记中逐个应用类名，您可以使用 CSS 模块将它们组合成占位符类。

让我们看一个例子：

```jsx
.title { 
  composes: mb0 fw6; 
}
```

这里有另一个例子：

```jsx
<h2 className={styles.title}>Hello React</h2>
```

这很棒，因为您仍然将样式逻辑保留在 CSS 中，而 CSS 模块的`composes`会通过在标记中应用所有单个类来为您完成工作。

上述代码的结果如下：

```jsx
<h2 class="title--3JCJR mb0--21SyP fw6--1JRhZ">Hello React</h2>
```

在这里，`title`，`mb0`和`fw6`都会自动应用到元素上。它们也是局部作用域的，因此我们拥有 CSS 模块的所有优势。

## React CSS 模块

最后但同样重要的是，有一个很棒的库可以帮助我们使用 CSS 模块。您可能已经注意到，我们使用`style`对象来加载 CSS 的所有类，因为 JavaScript 不支持连字符属性，我们被迫使用驼峰命名的类名。

此外，如果我们引用了 CSS 文件中不存在的类名，就无法知道它，`undefined`会被添加到类名列表中。出于这些和其他有用的功能，我们可能想尝试一个使使用 CSS 模块更加顺畅的包。

让我们通过回到我们在本节中之前使用普通 CSS 模块的`index.tsx`文件，将其更改为使用 React CSS 模块来看看这意味着什么。

该包名为`react-css-modules`，我们首先必须安装它：

```jsx
npm install react-css-modules
```

安装完包后，我们在`index.tsx`文件中导入它：

```jsx
import cssModules from 'react-css-modules'
```

我们将其作为 HOC 使用，将要增强的`Button`组件和我们从 CSS 中导入的`styles`对象传递给它：

```jsx
const EnhancedButton = cssModules(Button, styles)
```

现在，我们必须改变按钮的实现，避免使用`styles`对象。使用 React CSS 模块，我们使用`styleName`属性，它会转换为常规类。

这样做的好处是，我们可以将类名作为字符串使用（例如，`"button"`）：

```jsx
const Button = () => <button styleName="button">Click me!</button>;
```

如果我们现在将 `EnhancedButton` 渲染到 DOM 中，我们会发现与之前相比，实际上没有什么变化，这意味着库是有效的。

假设我们尝试将 `styleName` 属性更改为引用一个不存在的类名，如下所示：

```jsx
import { render } from 'react-dom'
import styles from './index.css'
import cssModules from 'react-css-modules'

const Button = () => <button styleName="button1">Click me!</button>

const EnhancedButton = cssModules(Button, styles)

render(<EnhancedButton />, document.querySelector('#root'))
```

通过这样做，我们将在浏览器的控制台中看到以下错误：

```jsx
Uncaught Error: "button1" CSS module is undefined.
```

当代码库不断增长，我们有多个开发人员在不同的组件和样式上工作时，这将特别有帮助。

# 实现 styled-components

有一个非常有前途的库，因为它考虑了其他库在样式化组件方面遇到的所有问题。已经有了不同的路径来编写 JavaScript 中的 CSS，并且尝试了许多解决方案，因此现在是时候使用所有这些经验教训来构建一个库了。

该库由 JavaScript 社区中两位知名的开发人员 *Glenn Maddern* 和 *Max Stoiberg* 构思和维护。它代表了解决问题的一种非常现代的方法，并且使用了 ES2015 的边缘功能和一些已应用于 React 的高级技术，为样式提供了一个完整的解决方案。

让我们看看如何创建与前几节中看到的相同的按钮，并检查我们感兴趣的所有 CSS 特性（例如伪类和媒体查询）是否与 `styled-components` 一起工作。

首先，我们必须通过运行以下命令来安装该库：

```jsx
npm install styled-components
```

安装库后，我们必须在组件文件中导入它：

```jsx
import styled from 'styled-components'
```

在那时，我们可以使用 `styled` 函数通过 `styled.elementName` 来创建任何元素，其中 `elementName` 可以是 `div`、按钮或任何其他有效的 DOM 元素。

第二件事是定义我们正在创建的元素的样式，为此，我们使用了一个名为 **tagged template literals** 的 ES6 特性，这是一种在不被插值的情况下将模板字符串传递给函数的方法。

这意味着函数接收到了包含所有 JavaScript 表达式的实际模板，这使得库能够充分利用 JavaScript 的全部功能来应用样式到元素上。

让我们从创建一个带有基本样式的简单按钮开始：

```jsx
const Button = styled.button`
  backgroundColor: #ff0000; 
  width: 320px; 
  padding: 20px; 
  borderRadius: 5px; 
  border: none; 
  outline: none; 
`;
```

这种*有点奇怪*的语法返回一个名为`Button`的合适的 React 组件，它渲染一个按钮元素，并将模板中定义的所有样式应用于它。样式的应用方式是创建一个唯一的类名，将其添加到元素中，然后将相应的样式注入到文档的头部。

以下是被渲染的组件：

```jsx
<button class="kYvFOg">Click me!</button>
```

添加到页面的样式如下：

```jsx
.kYvFOg { 
  background-color: #ff0000; 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
}
```

`styled-components`的好处是它支持几乎所有 CSS 的功能，这使它成为在实际应用中使用的一个很好的选择。

例如，它使用类似 SASS 的语法支持伪类：

```jsx
const Button = styled.button` 
  background-color: #ff0000; 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
  &:hover { 
    color: #fff; 
  } 
  &:active { 
    position: relative; 
    top: 2px; 
  }
`
```

它还支持媒体查询：

```jsx
const Button = styled.button` 
  background-color: #ff0000; 
  width: 320px; 
  padding: 20px; 
  border-radius: 5px; 
  border: none; 
  outline: none; 
  &:hover { 
    color: #fff; 
  } 
  &:active { 
    position: relative; 
    top: 2px; 
  } 
  @media (max-width: 480px) { 
    width: 160px; 
  } 
`;
```

这个库还有许多其他功能可以为您的项目带来。

例如，一旦您创建了按钮，就可以轻松地覆盖其样式，并多次使用具有不同属性的按钮。在模板内，还可以使用组件接收到的 props，并相应地更改样式。

另一个很棒的功能是**主题**。将您的组件包装在`ThemeProvider`组件中，您可以向三个组件的子组件注入一个主题属性，这样就可以轻松地创建 UI，其中一部分样式在组件之间共享，而另一些属性取决于当前选择的主题。

毫无疑问，`styled-components`库在将样式提升到下一个级别时是一个改变游戏规则的工具，在开始时可能会感觉有点奇怪，因为它是通过组件实现样式，但一旦您习惯了，我保证它会成为您最喜欢的样式包。

# 总结

在本章中，我们涉及了许多有趣的话题。我们首先讨论了在规模上使用 CSS 时遇到的问题，具体来说，Facebook 在处理 CSS 时遇到的问题。我们了解了在 React 中如何使用内联样式，以及为什么将样式与组件共同定位是有益的。我们还看了内联样式的局限性。然后，我们转向了 Radium，它解决了内联样式的主要问题，为我们提供了一个清晰的接口来在 JavaScript 中编写 CSS。对于那些认为内联样式是一个不好的解决方案的人，我们进入了 CSS 模块的世界，从零开始设置了一个简单的项目。

将 CSS 文件导入到我们的组件中可以清晰地表明依赖关系，而在本地范围内命名类名可以避免冲突。我们看到了 CSS 模块的`composes`是一个很棒的功能，以及我们如何可以将其与原子 CSS 结合使用，创建一个快速原型的框架。

最后，我们简要地看了一下`styled-components`，这是一个非常有前途的库，旨在彻底改变我们处理组件样式的方式。

到目前为止，您已经学习了许多在 React 中使用 CSS 样式的方法，从内联样式到 CSS 模块，或者使用诸如`styled-components`之类的库。在下一章中，我们将学习如何实现并从服务器端渲染中获益。
