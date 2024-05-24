# React 项目（二）

> 原文：[`zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0`](https://zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 React 和 Suspense 构建动态项目管理面板

在这本书的前两章中，你已经自己创建了两个 React 项目，现在你应该对 React 的核心概念有了扎实的理解。到目前为止，你已经使用的概念也将在本章中用于创建你的第三个 React 项目，其中包括一些新的和更高级的概念，这将展示出使用 React 的强大之处。如果你觉得自己可能缺乏完成本章内容所需的一些知识，你可以随时重复你到目前为止所建立的内容。

本章将再次使用 Create React App，这是你在上一章中使用过的。在开发本章的项目管理面板应用程序时，你将使用使用`styled-components`创建的可重用组件。之后，你将使用更高级的 React 技术来控制组件中的数据流。此外，将使用 HTML5 Web API 来动态拖放作为**高阶组件**（**HOC**）的组件。

本章将涵盖以下主题：

+   React Suspense 和代码拆分

+   使用 HOC

+   动态数据流

# 项目概述

在本章中，我们将使用 Create React App 和`styled-components`创建一个可重用的 React 组件和样式的**渐进式 Web 应用程序**（**PWA**）。该应用程序将具有使用 HTML5 拖放 API 的动态拖放界面。

构建时间为 1.5-2 小时。

# 入门

在本章中，我们将创建一个基于 GitHub 上初始版本的项目：[`github.com/PacktPublishing/React-Projects/tree/ch3-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch3-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch3`](https://github.com/PacktPublishing/React-Projects/tree/ch3)。

从 GitHub 下载初始应用程序后，我们可以进入其根目录并运行`npm install`命令。这将安装来自 Create React App 的核心包（`react`、`react-dom`和`react-scripts`），以及我们在上一章中使用的`styled-components`包。安装完成后，我们可以通过执行`npm start`命令启动应用程序，并通过访问`http://localhost:3000`在浏览器中访问项目。

我们还可以通过执行`npm run build`，然后`serve -s build`来构建应用程序。现在可以访问应用程序的缩小版本`http://localhost:5000`。由于它被设置为 PWA，即使没有任何互联网连接，它也可以工作。

如果您之前构建并提供了 Create React App PWA，可能会看到与在本地运行项目时不同的应用程序。这是由于 PWA 的 service worker 在浏览器中存储了该应用程序的缓存版本。您可以通过打开`devTools`并打开`Application`选项卡，在`Clear storage`部分中单击`Clear site data`按钮来从浏览器缓存中删除任何先前的应用程序。

如下截图所示，该应用程序具有一个基本的标题和分为四列。这些列是**项目管理看板**的车道，一旦我们将项目连接到数据文件，它们将包含各个票证：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/85a074c4-8949-4341-a38f-6bd913bc28a5.png)

正如我们在第二章中提到的，*使用可重用的 React 组件创建渐进式 Web 应用程序*，我们可以通过访问`Application`选项卡的`Service Workers`部分来检查当没有互联网连接时我们的应用程序是否正在运行。在此页面上，我们可以选中`Offline`复选框，然后尝试刷新浏览器。

如果我们查看项目的结构，我们会发现它的结构与前几章的项目相同。应用程序的入口点是`src/index.js`文件，它渲染了一个名为`App`的组件，该组件包含两个其他组件，分别是`Header`和`Board`。第一个是应用程序的实际标题，而`Board`组件包含我们在应用程序中看到的四个列。这些列由`Lane`组件表示。

此外，在`assets`目录中，我们会看到一个名为`data.json`的文件，其中包含我们可以在项目管理看板上显示的数据：

```jsx
project-management-board
|-- assets
    |-- data.json
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
    |-- components
        |-- Header
            |-- Header.js
        |-- Lane
            |-- Lane.js
    |-- containers
        |-- App.js
        |-- Board.js
    |-- index.js
    |-- serviceWorker.js
.gitignore
package.json
```

# 创建项目管理看板应用

在本节中，我们将创建一个使用 React API（如 Suspense 和 HTML5 拖放 API）的项目管理看板 PWA。我们将使用 Create React App，可以在本章的 GitHub 存储库中找到。

# 处理数据流

在放置初始版本的应用程序之后，下一步是从数据文件中获取数据并通过组件处理其流程。为此，我们将使用 React Suspense 和 memo。使用 Suspense，我们可以访问 React 懒加载 API 来动态加载组件，并且使用 memo，我们可以控制哪些组件在其 props 更改时应该重新渲染。

本节的第一部分将向我们展示如何使用 React 生命周期方法从数据源加载数据并在 React 组件中显示。

# 加载和显示数据

加载和显示从数据源检索的数据是我们在上一章中做过的事情。本节将进一步探讨这一点。按照以下步骤开始：

1.  我们将从数据文件中获取项目数据开始。为此，我们需要向`Board`组件添加必要的函数。我们需要这些函数来访问 React 生命周期。这些是`constructor`，在其中设置初始状态，以及`componentDidMount`，在其中将获取数据：

```jsx
...
class Board extends Component {
+ constructor() {
+   super();
+   this.state = {
+     data: [],
+     loading: true,
+     error: '',
+   }
+ }

+ async componentDidMount() {
+   try {
+     const tickets = await fetch('../../assets/data.json');
+     const ticketsJSON = await tickets.json();

+     if (ticketsJSON) {
+       this.setState({
+         data: ticketsJSON,
+         loading: false,
+       });
+     }
+   } catch(error) {
+     this.setState({
+      loading: false,
+      error: error.message,
+    });
+   }
+ }

  render() {
    ...
  }
}

export default Board;
```

在`componentDidMount`生命周期函数中，在`try..catch`语句内获取数据。此语句捕获从数据获取过程返回的任何错误，并用此消息替换错误状态。

1.  现在，我们可以将票务分发到相应的车道上：

```jsx
...
class Board extends Component {
  ...
  render() {
+   const { data, loading, error } = this.state;

    const lanes = [
      { id: 1, title: 'To Do' },
      { id: 2, title: 'In Progress' },
      { id: 3, title: 'Review' },
      { id: 4, title: 'Done' },
    ];

    return (
      <BoardWrapper>
        {lanes.map(lane =>
          <Lane
            key={lane.id}
            title={lane.title}
+           loading={loading}
+           error={error}
+           tickets={data.filter(ticket => ticket.lane === 
            lane.id)}
          />
        )}
      </BoardWrapper>
    );
  }
}

export default Board;
```

在上述代码中，我们可以看到，在`render`内部，`data`，`loading`和`error`常量已经从状态对象中解构出来。在迭代`lanes`常量的函数内部，这些值应该作为 props 传递给`Lane`组件。对于数据状态，有一些特殊的情况，因为`filter`函数被用来仅返回与车道 ID 匹配的`data`状态的票。

3. 接下来，我们需要对`Lane`组件进行一些更改：

```jsx
import React from 'react';
import styled from 'styled-components';
+ import Ticket from '../Ticket/Ticket';

...

+ const TicketsWrapper = styled.div`
+  padding: 5%;
+ `;

+ const Alert = styled.div`
+  text-align: center;
+ `;

- const Lane = ({ title }) => (
+ const Lane = ({ tickets, loading, error, title }) => (
    <LaneWrapper>
      <Title>{title}</Title>
+     {(loading || error) && <Alert>{loading ? 'Loading...' : 
       error}</Alert>}
+     <TicketsWrapper>
+       {tickets.map(ticket => <Ticket key={ticket.id} 
         ticket={ticket} />)}
+     </TicketsWrapper>
    </LaneWrapper>
);

export default Lane;
```

1.  `Lane`组件现在需要三个其他 props，即`tickets`，`loading`和`error`，其中`tickets`包含来自`data`状态的票数组，`loading`表示是否应显示加载消息，`error`包含错误消息（如果有的话）。我们可以看到已经创建了一个包装器，并且在`map`函数内部，将呈现显示票务信息的`Ticket`组件。这个`Ticket`组件也是我们需要在`src/components`目录中创建的：

```jsx
import React from 'react';
import styled from 'styled-components';

const TicketWrapper = styled.div`
  background: darkGray;
  padding: 20px;
  border-radius: 20px;

  &:not(:last-child) {
    margin-bottom: 5%;
  }
`;

const Title = styled.h3`
  width: 100%;
  margin: 0px;
`;

const Body = styled.p`
  width: 100%;
`;

const Ticket = ({ ticket }) => (
  <TicketWrapper>
    <Title>{ticket.title}</Title>
    <Body>{ticket.body}</Body>
  </TicketWrapper>
);

export default Ticket;
```

如果我们在网页浏览器中访问`http://localhost:3000`，我们会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/36586f9d-bcd0-4458-829f-6d7eaf57f8c3.png)

由于此应用程序已设置为 PWA，我们可以重新构建项目并重新启动服务工作程序。在离线模式下，项目应该仍然显示标题和四列，并在这些列内显示一个消息，显示“无法获取*”。

要构建和提供 PWA，我们需要在构建过程完成后运行`npm run`和`serve -s build`。现在，我们可以访问项目`http://localhost:5000`。我们可能需要重新启动服务工作程序，在`devTools`中的“应用程序”选项卡上可以执行此操作，并选择“服务工作程序”部分。在此部分的右侧，紧挨服务工作程序，按“更新”。要在离线模式下查看应用程序，我们需要选中“离线”复选框。

从数据源获取数据是可以在整个应用程序中重复使用的逻辑。在下一节中，我们将探讨如何使用 HOC 在多个组件之间重用此逻辑。

# 开始使用 HOC

HOC 是 React 中的高级功能，专注于组件的可重用性。它们不是官方的 React API 的一部分，但引入了一种在核心团队和许多库中流行的模式。

在本节的第一部分中，我们将创建我们的第一个 HOC，该 HOC 使用逻辑从我们在上一节中创建的数据源中检索数据。

# 创建 HOC

正如我们之前提到的，HOC 专注于重用组件。因此，它可以最好地描述如下：

“HOC 是一个接受组件并返回一个新组件的函数。”

为了解释这在实践中意味着什么，让我们创建一个示例。我们的项目有一个`Board`组件，它获取并呈现所有的车道。在这个组件中有逻辑，以`constructor`、`componentDidMount`的形式，以及关于如何呈现每个`Lane`组件的信息。我们如何处理只想显示一个没有车道，只有票的情况？我们只是向`Board`组件发送不同的 props 吗？当然，这是可能的，但在 React 中，这就是 HOC 的用途。

一个没有`lanes`的`Board`组件将不会映射所有的`lanes`并将相应的`lane`作为 props 渲染。相反，它将映射所有的`tickets`并直接渲染它们。尽管渲染的组件不同，但设置初始状态、获取数据和渲染组件的逻辑可以被重用。HOC 应该能够通过将这个组件发送给它以及一些额外的 props，为`Board`组件添加生命周期。

要创建 HOC，将一个名为`withDataFetching.js`的新文件放在`src`目录中。现在，按照以下步骤进行操作：

1.  首先，我们需要导入 React 并创建一个新的 HOC 函数，它成为默认导出。由于这个 HOC 将为数据获取添加生命周期，让我们称这个 HOC 为`withDataFetching`，并让它以组件作为参数。这个函数应该返回另一个组件。

```jsx
+ import React from 'react';

+ export default function withDataFetching(WrappedComponent) {
+   return class extends React.Component {

+ }
```

1.  在返回的组件内部，添加`constructor`组件，它的结构几乎与`Board`组件相同。

```jsx
...

export default function withDataFetching(WrappedComponent) {
  return class extends React.Component {
+   constructor(props) {
+     super(props);
+     this.state = {
+       data: [],
+       loading: true,
+       error: '',
+     };
+   }
...
```

1.  接下来，我们需要创建`componentDidMount`函数，这是数据获取的地方。`dataSource`属性被用作获取数据的位置。另外，请注意，常量名称现在更加通用，不再指定单一用途。

```jsx
export default function withDataFetching(WrappedComponent) {
  return class extends React.Component {

  ...

+ async componentDidMount() {
+   try {
+     const data = await fetch(this.props.dataSource);
+     const dataJSON = await data.json();

+     if (dataJSON) {
+       this.setState({
+         data: dataJSON,
+         loading: false,
+       });
+     }
+   } catch(error) {
+     this.setState({
+       loading: false,
+       error: error.message,
+     });
+   }
+ }

 ...
```

1.  在`render`函数中，我们可以返回插入到函数中的`WrappedComponent`，并将`data`、`loading`和`error`状态作为 props 传递。重要的是要理解，它还接受任何通过`{...this.props}`扩展的额外 props。

```jsx
export default function withDataFetching(WrappedComponent) {
  return class extends React.Component {

    ...

+   render() {
+     const { data, loading, error } = this.state;

+     return (
+       <WrappedComponent 
+         data={data} 
+         loading={loading} 
+         error={error}
+         {...this.props} 
+       />
+     );
+   }
  };
}
```

恭喜！你已经创建了你的第一个 HOC！但是，它需要一个组件来返回一个支持数据获取的组件。因此，我们需要将我们的`Board`组件重构为一个函数组件。让我们开始吧：

1.  从`src/withDataFetching.js`文件中导入 HOC：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
+ import withDataFetching from '../withDataFetching';
import Lane from '../components/Lane/Lane';

const BoardWrapper = styled.div`
  display: flex;
  justify-content: space-between;
  flex-direction: row;
  margin: 5%;

  @media (max-width: 768px) {
    flex-direction: column;
  }
`;

...
```

1.  随后，我们可以从这个文件中删除整个类组件`Board`，并创建一个新的函数组件，返回我们在重构后的类组件的`return`函数中声明的 JSX。这个函数组件将以`lanes`、`loading`、`error`和`data`作为 props。

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
import withDataFetching from '../withDataFetching';
import Lane from '../components/Lane/Lane';

const BoardWrapper = ...;

+ const Board = ({ lanes, loading, error, data }) => (
+  <BoardWrapper>
+    {lanes.map(lane =>
+      <Lane
+        key={lane.id}
+        title={lane.title}
+        loading={loading}
+        error={error}
+        tickets={data.filter(ticket => ticket.lane === lane.id)}
+      />
+    )}
+  </BoardWrapper>
+ ); export default Board;
```

3. 最后，导出函数组件以及 HOC 函数：

```jsx
...
const Board = ({ lanes, loading, error, data }) => (
  <BoardWrapper>
    {boards.map(lane =>
      <Lane
        key={lane.id}
        title={lane.title}
        loading={loading}
        error={error}
        tickets={data.filter(ticket => ticket.lane === lane.id)}
      />
    )}
  </BoardWrapper>
);

- export default Board;
+ export default withDataFetching(Board);
```

但这些 props 是从哪里来的呢？如果我们打开应用程序并打开浏览器，我们会看到以下错误：

```jsx
TypeError: Cannot read property 'map' of undefined
```

这是因为我们的`Board`组件尝试对`lanes`prop 进行映射，但是在 HOC 中，`WrappedComponent`接收到`data`、`loading`和`error` prop。幸运的是，我们还添加了通过组件发送的任何其他 props 的扩展选项。如果我们打开`App`组件，在那里`Board`组件被打开，我们可以使用之前在`Board`组件中声明的`lane`常量传递`lanes`prop：

```jsx
...

class App extends Component {
  render() {
+   const lanes = [
+     { id: 1, title: 'To Do' },
+     { id: 2, title: 'In Progress' },
+     { id: 3, title: 'Review' },
+     { id: 4, title: 'Done' },
+   ]

    return (
        <>
          <GlobalStyle />
            <AppWrapper>
            <Header />
-           <Board />
+           <Board lanes={lanes} />
          </AppWrapper>
        </>
    );
  }
}

export default App;
```

现在，如果我们在浏览器中查看我们的项目，我们会看到应用程序再次被渲染。然而，它显示了 HOC 中`try...catch`语句的错误消息。这个 HOC 需要`dataSource0` prop，我们也需要将其传递给`Board`组件：

```jsx
...
class App extends Component {
  render() {

    ...

    return (
        <>
          <GlobalStyle />
            <AppWrapper>
            <Header />
-           <Board lanes={lanes} />
+           <Board lanes={lanes} dataSource={'../../assets/data.json'} />
          </AppWrapper>
        </>
    );
  }
}

export default App;
```

最后，我们可以看到`Board`组件在浏览器中由 HOC 渲染。然而，正如我们之前提到的，HOC 应该重用逻辑。在下一节中，我们将学习如何通过将 HOC 添加到不同的组件来实现这一点。

# 使用 HOC

在第一个 HOC 就位的情况下，现在是时候考虑使用这个 HOC 创建其他组件，比如只显示票的组件。创建这个组件的过程包括两个步骤：创建实际的组件并导入组件并向其传递所需的 props。让我们开始吧：

1.  在 containers 目录中，我们需要创建一个名为`Tickets.js`的新文件，并将以下代码放入其中。在我们导入 HOC 的地方，使用`styled-components`设置一些基本样式，并创建一个可以导出的函数组件：

```jsx
import React from 'react';
import styled from 'styled-components';
import withDataFetching from '../withDataFetching';
import Ticket from '../components/Ticket/Ticket';

const TicketsWrapper = styled.div`
  display: flex;
  justify-content: space-between;
  flex-direction: row;
  margin: 5%;

  @media (max-width: 768px) {
    flex-direction: column;
  }
`;

const Alert = styled.div`
    text-align: center;
`;

const Tickets = ({ loading, data, error }) => (
  <TicketsWrapper>
    {(loading || error) && <Alert>{loading ? 'Loading... : 
     error}</Alert>}
    {data.map(ticket => <Ticket key={ticket.id} ticket={ticket} />)}
  </TicketsWrapper>
);

export default withDataFetching(Tickets);
```

1.  在`App`组件中，我们可以导入这个组件并向其传递一个`dataSource` prop：

```jsx
import React, { Component } from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import Board from './Board';
+ import Tickets from './Tickets';
import Header from '../components/Header/Header';

...

class App extends Component {
  render() {
    ...
    return (
        <>
          <GlobalStyle />
            <AppWrapper>
            <Header />
            <Board boards={boards} 
             dataSource={'../../assets/data.json'} />
+           <Tickets dataSource={'../../assets/data.json'} />                    
            </AppWrapper>
       </>
    );
  }
}

export default App;
```

有点不对劲的是，票据显示在一起而没有任何边距。我们可以在实际的`Ticket`组件中更改这一点，但这也会改变在车道中显示的票据的边距。为了解决这个问题，我们可以传递一个被`styled-components`用于这个组件的 prop。为了做到这一点，我们需要对渲染票据的`Tickets`组件和定义样式的`Ticket`组件进行更改。让我们开始吧：

1.  在`map`函数内部向`Ticket`组件传递一个名为`marginRight`的新 prop。这个 prop 只是一个布尔值，不需要值：

```jsx
...

const Tickets = ({ loading, data, error }) => (
  <TicketsWrapper>
    {(loading || error) && <Alert>{loading ? 'Loading...' : 
      error}</Alert>}
-   {data.map(ticket => <Ticket key={ticket.id} ticket={ticket} />)}
+   {data.map(ticket => <Ticket key={ticket.id} marginRight ticket={ticket} />)}
  </TicketsWrapper>
);

export default withDataFetching(Tickets);
```

1.  在`Ticket`组件中，我们需要解构这个 prop 并将它传递给我们用`styled-components`创建的`TicketWrapper`：

```jsx
import React from 'react';
import styled from 'styled-components';

const TicketWrapper = styled.div`
  background: darkGray;
  padding: 20px;
  border-radius: 20px;

  &:not(:last-child) {
    margin-bottom: 5%;
+   margin-right: ${props => !!props.marginRight ? '1%' : '0'};
  }
`;

...

- const Ticket = ({ ticket }) => (
+ const Ticket = ({ marginRight, ticket }) => (
-   <TicketWrapper>
+   <TicketWrapper marginRight={marginRight}>
      <Title>{ticket.title}</Title>
      <Body>{ticket.body}</Body>
    </TicketWrapper>
);

export default Ticket;
```

现在，我们可以通过向`Ticket`组件发送 props 来控制`TicketWrapper`的`margin-right`属性。如果我们在浏览器中查看我们的应用程序，我们会看到，在具有四个车道的`Board`组件正下方，另一个组件正在呈现一个`Ticket`组件。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/996d76ec-4437-4aaa-bfef-3fe46f0753f4.png)

我们可以自定义的另一件事是，HOC 返回的组件在 React 开发者工具中的命名方式。在浏览器中打开应用程序并查看组件树。在这里，我们可以看到我们创建的没有 HOC 的组件具有可读的命名约定，如`App`或`Header`。由 HOC 创建的组件被命名为`<_class />`。为了使这个组件树更清晰，我们可以让我们的 HOC 轻松地将这种命名约定添加到它创建的组件中。通常，我们会使用 HOC 创建的组件的名称。然而，在我们的情况下，HOC 被称为`withDataFetching`，当我们插入一个名为`Board`的组件时，在 React 开发者工具中显示的名称将是`withDataFetching(Board)`。为了设置这一点，我们需要对`withDataFetching.js`文件进行一些更改。让我们开始吧：

1.  在声明类组件之前删除`return`，并给类组件命名。为此，使用 HOC 的名称，并将第一个字符改为大写字母。这将得到`WithDataFetching`：

```jsx
import React from 'react';

export default function withDataFetching(WrappedComponent) {
- return class extends React.Component {
+ class WithDataFetching extends React.Component {
  ...
```

1.  在文件的最后几行，我们可以获取已插入 HOC 的`WrappedComponent`的名称，并将其用于通过设置返回组件的`displayName`来命名 HOC。不要忘记在文件末尾返回`WithDataFetching`类组件：

```jsx
import React from 'react';

export default function withDataFetching(WrappedComponent) {
  class WithDataFetching extends React.Component {

    ...

    render() {
      const { data, loading, error } = this.state;

      return (
        <WrappedComponent 
          data={data} 
          loading={loading} 
          error={error} 
          {...this.props} 
        />
      );
    }
  };

+ WithDataFetching.displayName = `WithDataFetching(${WrappedComponent.name})`;

+ return WithDataFetching;
}
```

再次查看 React 开发者工具，我们可以看到这些更改导致了 HOC 创建的组件具有更可读的命名约定。

在我们的应用程序中，显示在车道中的所有票据只在一个部分，因为我们希望能够将这些票据拖放到不同的车道中。我们将在下一节中学习如何做到这一点，我们将为板块添加动态功能。

# 让板块变得动态起来

通常给项目管理板提供良好用户交互的一件事是能够将票务从一个车道拖放到另一个车道。这是可以很容易地通过 HTML5 拖放 API 来实现的，该 API 在包括 IE11 在内的每个现代浏览器中都可用。

HTML5 拖放 API 使我们能够在项目管理板中拖放元素。为了实现这一点，它使用拖动事件。`onDragStart`、`onDragOver`和`onDrop`将用于此应用程序。这些事件应放置在`Lane`和`Ticket`组件上。让我们开始吧：

1.  首先，我们需要将`Board`组件从函数组件更改为类组件。我们这样做是因为票务数据需要添加到状态中，而`Board`组件是最合适的地方，因为我们可能希望`Lane`组件在其他地方被重用。我们可以通过更改`Board`常量的定义来实现这一点，如下所示：

```jsx
...
 - const Board = ({ lanes, loading, data, error }) => (
+ class Board extends React.Component {
+   render() {
+     const { lanes, loading, data, error } = this.props;

+     return (
        <BoardWrapper>
          {lanes.map(lane =>
            <Lane
              key={lane.id}
              title={lane.title}
              loading={loading}
              error={error}
              tickets={data.filter(ticket => ticket.lane ===  
              lane.id)}
            />
          )}
        </BoardWrapper>
      );
+   }
+ }

export default withDataFetching(Board);
```

1.  现在，我们可以将票务的初始值添加到状态中。我们这样做是因为我们希望更改应该放置在的车道的键。通过将这些数据添加到状态中，我们可以使用`setState`函数动态地改变它。

```jsx
...
class Board extends React.Component {
+ constructor() {
+   super();
+   this.state = {
+     tickets: [],
+   };
+ } 
  render() {
  ...
```

1.  由于数据需要从源加载，并且在应用程序首次挂载时不可用，我们需要检查这些组件的 props 是否已更改。如果是，我们需要将票务数据添加到状态中。为此，使用`componentDidUpdate`生命周期方法，该方法可以将先前的 props 作为参数：

```jsx
...

class Board extends React.Component {
  constructor() {
    super()
    this.state = {
      tickets: [],
    };
  }

+ componentDidUpdate(prevProps) {
+   if (prevProps.data !== this.props.data) {
+     this.setState({ tickets: this.props.data });
+   }
+ } 
  render() {
  ...
```

1.  最后，显示来自状态的票务：

```jsx
...  
render() {
-   const { lanes, data, loading, error } = this.props; 
+   const { lanes, loading, error } = this.props;

    return (
      <BoardWrapper>
        {lanes.map(lane =>
          <Lane
            key={lane.id}
            title={lane.title}
            loading={loading}
            error={error}
-           tickets={data.filter(ticket => ticket.lane === 
            lane.id)}
+           tickets={this.state.tickets.filter(ticket => 
            ticket.lane === lane.id)}
          />
        )}
      </BoardWrapper>
    );
  }
}

export default withDataFetching(Board);
```

如果我们现在在浏览器中查看项目，应该没有可见的变化。唯一的区别是票务的数据现在是从状态中加载，而不是从 props 中加载。

在同一个文件中，让我们添加响应拖放事件的函数，这些函数需要发送到`Lane`和`Ticket`组件：

1.  首先，添加`onDragStart`事件的事件处理程序函数，该函数在开始拖动操作时触发，添加到`Board`组件。这个函数需要传递给`Lane`组件，然后可以传递给`Ticket`组件。这个函数为被拖动的票务设置一个 ID，该 ID 被用于浏览器识别拖动元素的`dataTransfer`对象：

```jsx
...
class Board extends React.Component {
  constructor() {
    super();
    this.state = {
      tickets: [],
    };
  }

  componentDidUpdate(prevProps) {
    if (prevProps.data !== this.props.data) {
        this.setState({ tickets: this.props.data });
    }
  }

+ onDragStart = (e, id) => {
+   e.dataTransfer.setData('id', id);
+ }; 
  render() {
    const { lanes, loading, error } = this.props;

    return (
      <BoardWrapper>
        {lanes.map(lane =>
          <Lane
            key={lane.id}
            title={lane.title}
            loading={loading}
            error={error}
+           onDragStart={this.onDragStart}
            tickets={this.state.tickets.filter(ticket => 
            ticket.lane === lane.id)}
          />
        )}
      </BoardWrapper>
    );
  }
}

export default withDataFetching(Board);
```

1.  在`Lane`组件中，我们需要将此事件处理程序函数传递给`Ticket`组件：

```jsx
...
- const Lane = ({ tickets, loading, error, title }) => (
+ const Lane = ({ tickets, loading, error, onDragStart, title }) => (
  <LaneWrapper>
    <Title>{title}</Title>
    {(loading || error) && <Alert>{loading ? 'Loading...' : 
     error}</Alert>}
    <TicketsWrapper>
-     {tickets.map(ticket => <Ticket key={ticket.id} 
       ticket={ticket} />)}
+     {tickets.map(ticket => <Ticket key={ticket.id} 
       onDragStart={onDragStart} ticket={ticket} />)}
    </TicketsWrapper>
  </LaneWrapper>
);

export default Lane;
```

1.  现在，我们可以在`Ticket`组件中调用这个函数，我们还需要在`TicketWrapper`中添加`draggable`属性。在这里，我们将元素和票据 ID 作为参数发送到事件处理程序：

```jsx
...
- const Ticket = ({ marginRight, ticket }) => (
+ const Ticket = ({ marginRight, onDragStart, ticket }) => (
  <TicketWrapper
+   draggable
+   onDragStart={e => onDragStart(e, ticket.id)}
    marginRight={marginRight}
  >
    <Title>{ticket.title}</Title>
    <Body>{ticket.body}</Body>
  </TicketWrapper>
);

export default Ticket;
```

做出这些更改后，我们应该能够看到每个票据都可以被拖动。但是现在不要把它们放在任何地方——其他放置事件和更新状态的事件处理程序也应该被添加。可以通过点击票据而不释放鼠标并将其拖动到另一个车道来将票据从一个车道拖动到另一个车道，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/8294248f-db92-4260-9317-934a712d18a1.png)

实现了`onDragStart`事件后，`onDragOver`和`onDrop`事件也可以实现。让我们开始吧：

1.  默认情况下，不可能将元素放入另一个元素中；例如，将`Ticket`组件放入`Lane`组件中。这可以通过在`onDragOver`事件中调用`preventDefault`方法来防止：

```jsx
...
 +  onDragOver = e => {
+   e.preventDefault();
+ };

 render() {
    const { lanes, loading, error } = this.props;

    return (
      <BoardWrapper>
        {lanes.map(lane =>
          <Lane
            key={lane.id}
            title={lane.title}
            loading={loading}
            error={error}
            onDragStart={this.onDragStart}
+           onDragOver={this.onDragOver}
            tickets={this.state.tickets.filter(ticket => 
            ticket.lane === lane.id)}
          />
        )}
      </BoardWrapper>
    );
  }
}
```

2. 这个事件处理程序需要放在`Lane`组件上：

```jsx
...
- const Lane = ({ tickets, loading, error, title }) => (
+ const Lane = ({ tickets, loading, error, onDragOver, title }) => (
-   <LaneWrapper>
+   <LaneWrapper
+     onDragOver={onDragOver}
+   >
      <Title>{title}</Title>
      {(loading || error) && <Alert>{loading ? 'Loading...' : 
       error}</Alert>}
      <TicketsWrapper>
        {tickets.map(ticket => <Ticket onDragStart={onDragStart}   
         ticket={ticket} />)}
      </TicketsWrapper>
    </LaneWrapper>
);

export default Lane;
```

`onDrop`事件是让事情变得有趣的地方，因为这个事件使我们能够在完成拖动操作后改变状态。

这个事件处理程序的函数应该放在`Ticket`组件上，但在`Board`组件中定义，因为`setState`函数只能在与状态的初始值相同的文件中调用。

```jsx
...  
+  onDrop = (e, laneId) => {
+   const id = e.dataTransfer.getData('id');
+
+   const tickets = this.state.tickets.filter(ticket => {
+     if (ticket.id === id) {
+       ticket.board = boardId;
+     }
+     return ticket;
+   });
+
+   this.setState({
+     ...this.state,
+     tickets,
+   });
+ }; 
  render() {
    const { lanes, loading, error } = this.props;

    return (
      <BoardWrapper>
        {lanes.map(lane =>
          <Lane
            key={lane.id}
+           laneId={lane.id}
            title={lane.title}
            loading={loading}
            error={error}
            onDragStart={this.onDragStart}
            onDragOver={this.onDragOver}
+           onDrop={this.onDrop}
            tickets={this.state.tickets.filter(ticket => ticket.lane === 
            lane.id)}
          />
        )}
      </BoardWrapper>
    );
  }
}

export default withDataFetching(Board);
```

这个`onDrop`事件处理函数接受一个元素和车道的 ID 作为参数，因为它需要被拖动元素的 ID 和它应该放置在的新车道的 ID。有了这些信息，函数使用`filter`函数来找到需要移动的票，并改变车道的 ID。这些新信息将用`setState`函数替换状态中票的当前对象。由于`onDrop`事件是从`Lane`组件触发的，它作为一个 prop 传递给这个组件。此外，车道的 ID 也作为一个 prop 添加，因为这需要从`Lane`组件传递给`onDrop`事件处理函数：

```jsx
...
- const Lane = ({ tickets, loading, error, onDragStart, onDragOver, title }) => (
+ const Lane = ({ laneId, tickets, loading, error, onDragStart, onDragOver, onDrop, title }) => (
  <LaneWrapper
    onDragOver={onDragOver}
+   onDrop={e => onDrop(e, laneId)}
  >
    <Title>{title}</Title>
    {(loading || error) && <Alert>{loading ? 'Loading...' : error}</Alert>}
    <TicketsWrapper>
      { tickets.map(ticket => <Ticket onDragStart={onDragStart} 
        ticket={ticket} />)}
    </TicketsWrapper>
  </LaneWrapper>
);

export default Lane;
```

有了这个，我们就能在我们的看板上将票据拖放到其他车道上了。

# 总结

在本章中，您创建了一个项目管理面板，可以使用 React Suspense 和 HTML5 拖放 API 将票据从一个车道移动到另一个车道。该应用程序的数据流使用本地状态和生命周期来处理，并确定在不同车道中显示哪些票据。本章还介绍了**高阶组件**（HOCs）的高级 React 模式。使用 HOCs，您可以在应用程序中跨类组件重用状态逻辑。

这种高级模式还将在下一章中使用，该章将处理 React 应用程序中的路由和**服务器端渲染**（SSR）。您有没有尝试过使用 Stack Overflow 来找到您曾经遇到的编程问题的解决方案？我有！

在下一章中，我们将构建一个使用 Stack Overflow 作为数据源并使用 React 来渲染应用程序的社区动态。

# 进一步阅读

+   拖放 API：[`developer.mozilla.org/en-US/docs/Web/API/HTML_Drag_and_Drop_API`](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Drag_and_Drop_API)。

+   HOC：[`medium.com/@dan_abramov/mixins-are-dead-long-live-higher-order-components-94a0d2f9e750`](https://medium.com/@dan_abramov/mixins-are-dead-long-live-higher-order-components-94a0d2f9e750)。

+   DataTransfer：[`developer.mozilla.org/en-US/docs/Web/API/DataTransfer`](https://developer.mozilla.org/en-US/docs/Web/API/DataTransfer)。

+   React DnD：[`github.com/react-dnd/react-dnd`](https://github.com/react-dnd/react-dnd)。


# 第四章：使用 React Router 构建基于 SSR 的社区动态

到目前为止，您已经了解到 React 应用程序通常是**单页应用程序**（**SPA**），可以用作**渐进式 Web 应用程序**（**PWA**）。这意味着应用程序是在客户端渲染的，当用户访问您的应用程序时，它会在浏览器中加载。但您是否知道 React 还支持**服务器端渲染**（**SSR**），就像您可能还记得从以前代码只能从服务器渲染的时代一样？

在这一章中，您将使用`react-router`为 Create React App 添加声明式路由，并使组件动态加载到服务器而不是浏览器。为了启用 SSR，将使用 React 特性 Suspense 与`ReactDOMServer`。如果您对**搜索引擎优化**（**SEO**）感兴趣，本章将使用 React Helmet 为页面添加元数据，以便您的应用程序可以更好地被搜索引擎索引。

本章将涵盖以下主题：

+   声明式路由

+   服务器端渲染

+   React 中的 SEO

# 项目概述

在本章中，我们将使用`react-router`创建一个支持 SSR 的 PWA，因此从服务器而不是浏览器加载。此外，该应用程序使用 React Helmet 进行搜索引擎优化。

构建时间为 2 小时。

# 入门

在本章中，我们将创建的项目是在初始版本的基础上构建的，您可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch4-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch4-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch4`](https://github.com/PacktPublishing/React-Projects/tree/ch4)。此外，该项目使用公开可用的 Stack Overflow API 来填充应用程序的数据。这是通过获取发布到 Stack Overflow 的问题来完成的。有关此 API 的更多信息，请访问：[`api.stackexchange.com/docs/questions#order=desc&sort=hot&tagged=reactjs&filter=default&site=stackoverflow&run=true`](https://api.stackexchange.com/docs/questions#order=desc&sort=hot&tagged=reactjs&filter=default&site=stackoverflow&run=true)。

从 GitHub 下载初始项目后，您需要进入该项目的根目录并运行`npm install`。由于该项目是基于 Create React App 构建的，运行此命令将安装`react`、`react-dom`和`react-scripts`。此外，`styled-components`用于处理应用程序中所有组件的样式。安装过程完成后，您可以执行`npm`命令`start`，以便在浏览器中访问项目，网址为`http://localhost:3000`。

由于该项目设置为 PWA，服务工作者已注册，使得即使没有互联网连接也可以访问该应用。您可以通过首先运行`npm run build`，然后在构建过程完成后运行`serve -s build`来检查这一点。现在可以访问该应用的构建版本，网址为`http://localhost:5000`。如前一章所述，您可以通过访问浏览器的开发者工具中的“应用程序”选项卡来检查在没有互联网连接时应用程序是否仍然可用。在该选项卡中，您可以在左侧菜单中找到“服务工作者”；点击此链接后，您可以在出现的页面上选择“离线”复选框。

如果您之前构建并提供过 Create React App PWA，则可能看到与在本地运行项目时不同的应用程序。您可以通过打开浏览器的开发者工具并打开“应用程序”选项卡，在其中可以点击“清除站点数据”按钮来删除浏览器缓存中的任何先前应用程序。

初始应用程序位于`http://localhost:3000`，包括一个简单的标题和一系列卡片，如下面的屏幕截图所示。这些卡片有标题和元信息，如查看次数、回答次数以及提出此问题的用户的信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/ea99accb-4a72-4c9c-852e-7cce404f51c8.png)

如果您查看项目的结构，它使用与之前创建的项目相同的结构。该应用程序的入口点是一个名为`src/index.js`的文件，它渲染一个名为`App`的容器组件，其中包含`Header`和`Feed`组件。`Header`组件仅显示项目的标题，而`Feed`是一个具有生命周期方法的类组件，调用 Stack Overflow API，并渲染包含 Stack Overflow 问题的`Card`组件：

```jsx
community-feed
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
    |-- components
        |-- Header
            |-- Header.js
        |-- Card
            |-- Card.js
        |-- Owner
            |-- Owner.js
    |-- containers
        |-- App.js
        |-- Feed.js
    |-- index.js
    |-- serviceWorker.js
.gitignore
package.json
```

# 社区动态应用

在本节中，您将使用启用了 SSR 的声明式路由构建一个社区动态应用程序。为了 SEO，将使用一个名为 React Helmet 的软件包。在这个社区动态中，您可以看到 Stack Overflow 上具有`reactjs`标签的最新问题的概述，并单击它们以查看更多信息和答案。起点将是使用 Create React App 创建的项目。

# 声明式路由

使用`react-router`软件包，您可以通过添加组件来为 React 应用程序添加声明式路由。这些组件可以分为三种类型：路由器组件、路由匹配组件和导航组件。

使用`react-router`设置路由包括多个步骤：

1.  要使用这些组件，您需要通过执行以下命令来安装`react-router`的 web 软件包，称为`react-router-dom`：

```jsx
npm install react-router-dom
```

1.  安装完`react-router-dom`后，下一步是在您的应用程序入口点组件中从该软件包中导入路由和路由匹配组件。在这种情况下，这是`App`组件，它位于`src/containers`目录中：

```jsx
import React, { Component } from 'react';
import styled, { createGlobalStyle } from 'styled-components';
+ import { BrowserRouter as Router, Route } from 'react-router-dom';
import Header from '../components/Header/Header';
import Feed from './Feed';

const GlobalStyle = createGlobalStyle`...`;

const AppWrapper = styled.div`...`;

class App extends Component {
    ...
```

1.  实际的路由必须添加到该组件的`return`函数中，在那里所有的路由匹配组件(`Route`)必须包裹在一个路由组件`Router`中。当您的 URL 与`Route`的任何迭代中定义的路由匹配时，该组件将呈现添加为`component`属性的 JSX 组件：

```jsx
...
class App extends Component {
  render() {
    return (
        <>
          <GlobalStyle />
          <AppWrapper>
            <Header />
+           <Router>
+             <Route path='/' component={Feed} />
+           </Router>
          </AppWrapper>
        </>
    );
  }
}

export default App;
```

1.  如果您现在在浏览器中再次访问项目，地址为`http://localhost:3000`，将呈现显示所有问题的`Feed`组件。此外，如果您在浏览器中输入`http://localhost:3000/feed`，`Feed`组件仍将被呈现。这是因为`/`路由匹配每个可能的 URL，因为您没有定义应该进行精确匹配。因此，添加`exact`属性到`Route`：

```jsx
...
class App extends Component {
  render() {
    return (
        <>
          <GlobalStyle />
          <AppWrapper>
            <Header />
            <Router>
-             <Route path='/' component={Feed} />
+             <Route exact path='/' component={Feed} />
            </Router>
          </AppWrapper>
        </>
    );
  }
}

export default App;
```

现在，如果您访问除`/`之外的任何路由，不应该看到`Feed`组件被呈现。

如果您希望显示这些路由，例如，显示特定的问题，您需要向路由发送参数。如何做到这一点将在本节的下一部分中展示。

# 带参数的路由

有了第一个路由之后，其他路由可以添加到路由器组件中。一个合理的路由是为单独的问题添加一个路由，该路由具有指定要显示的问题的额外参数。因此，必须创建一个名为`Question`的新容器组件，其中包含从 Stack Overflow API 获取问题的逻辑。当路径匹配`/question/:id`时，将呈现此组件，其中`id`代表从 feed 中点击的问题的 ID：

1.  在`src/containers`目录中创建一个名为`Question`的新类组件，并向该文件添加一个`constructor`和一个`render`方法：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';

const QuestionWrapper = styled.div`
  display: flex;
  justify-content: space-between;
  flex-direction: column;
  margin: 5%;
`;

const Alert = styled.div`
  text-align: center;
`;

class Question extends Component {
  constructor() {
    super();
    this.state = {
      data: [],
      loading: true,
      error: '',
    };
  }

  render() {
    const { data, loading, error } = this.state;

    if (loading || error) {
      return <Alert>{loading ? 'Loading...' : error}</Alert>;
    }

    return (
      <QuestionWrapper></QuestionWrapper>
    );
  }
}

export default Question;
```

1.  要使此路由可用，您需要在`App`组件内导入此组件并为其定义一个路由：

```jsx
import React, { Component } from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { BrowserRouter as Router, Route } from 'react-router-dom';
import Header from '../components/Header/Header';
import Feed from './Feed';
+ import Question from './Question';
...
class App extends Component {
  render() {
    return (
        <>
          <GlobalStyle />
          <AppWrapper>
            <Header />
            <Router>
              <Route exact path='/' component={Feed} />
+             <Route path='/questions/:id' component={Question} />
            </Router>
          </AppWrapper>
        </>
    );
  }
}

export default App;
```

如果您现在访问`http://localhost:3000/questions/55366474`，由于尚未实现数据获取，将显示`Loading...`消息。`Route`组件将 props 传递给它渲染的组件，在本例中是`Question`；这些 props 是`match`，`location`和`history`。您可以通过打开 React 开发者工具并搜索`Question`组件来查看这一点，将返回以下结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/f5161ba8-f886-4949-87e7-0d3e8b2a9492.png)

`match`属性是最有趣的，因为它包含了`id`参数的值。`location`和`history`属性包含了有关应用程序当前位置和过去位置的信息。

您还可以通过使用`withRouter`**Higher-Order Component** (**HOC**)访问`react-router` props，该组件在每次渲染时将`match`，`location`和`history` props 传递给包装组件。这样，您可以在应用程序的任何位置使用`history.goBack`或`history.push`等方法。在第三章中，*使用 React 和 Suspense 构建动态项目管理面板*，您已经看到了使用 HOC 的示例；`withRouter` HOC 以相同的方式实现。

在`Question`组件上实现数据获取，您需要检查`id`参数并从 Stack Overflow API 中获取相应的问题：

1.  因此，应向`Question`添加一个`componentDidMount`方法，该方法使用此参数获取 API：

```jsx
...

+ const ROOT_API = 'https://api.stackexchange.com/2.2/';

class Question extends Component {
  constructor(props) { ... }

+ async componentDidMount() {
+   const { match } = this.props;
+   try {
+     const data = await fetch(
+       `${ROOT_API}questions/${match.params.id}?site=stackoverflow`,
+     );
+     const dataJSON = await data.json();

+     if (dataJSON) {
+       this.setState({
+         data: dataJSON,
+         loading: false,
+       });
+     }
+   } catch(error) {
+     this.setState({
+       loading: true,
+       error: error.message,
+     });
+   }
+ }

  render() {
    ...
```

1.  然后，获取的数据可以显示在`Card`组件内。请记住，当进行此请求时，Stack Overflow API 返回的是一个数组而不是单个对象：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
+ import Card from '../components/Card/Card';

...

class Question extends Component {
  ...
  render() {
    const { data, loading, error } = this.state;

    if (loading || error) {
      return <Alert>{loading ? 'Loading...' : error}</Alert>;
    }

    return (
      <QuestionWrapper>
+       <Card key={data.items[0].question_id} data={data.items[0]} />
      </QuestionWrapper>
    );
  }
}

export default Question;
```

1.  如果你现在刷新`http://localhost:3000/questions/55366474`，将显示一个显示有关这个特定问题信息的`Card`组件。为了能够从`Feed`组件导航到这个页面，应该添加一个`Link`导航来包裹`Card`：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
+ import { Link } from 'react-router-dom';
import Card from '../components/Card/Card';

...

class Feed extends Component {
  ...
  render() {
    const { data, loading, error } = this.state;

    if (loading || error) {
      return <Alert>{loading ? 'Loading...' : error}</Alert>;
    }

    return (
      <FeedWrapper>   
        {data.items.map(item =>
+         <Link key={item.question_id} to={`/questions/${item.question_id}`}>
-            <Card key={item.question_id} data={item} />
+            <Card data={item} />
+          </Link>
+ )}
       </FeedWrapper>
     );
   }
}

export default Feed;
```

1.  当你访问`http://localhost:3000/`时，你可能会注意到`Card`组件现在是可点击的，并链接到一个新页面，显示你刚刚点击的问题。`Card`组件的样式也发生了变化，因为`Link`导航组件是一个`a`元素；它会添加下划线并改变填充。你需要做以下更改来修复这些样式变化：

```jsx
...
+ const CardLink = styled(Link)`
+  text-decoration: none;
+  color: inherit;
+ `; 
const  ROOT_API  =  'https://api.stackexchange.com/2.2/'; 
class Feed extends Component {
  ...
  render() {
    const { data, loading, error } = this.state;

    if (loading || error) {
      return <Alert>{loading ? 'Loading...' : error}</Alert>;
    }

    return (
      <FeedWrapper>
        {data.items.map(item => (
-         <Link key={item.question_id} to={`/questions/${item.question_id}`}>
+         <CardLink key={item.question_id} to={`/questions/${item.question_id}`}>
            <Card data={item} />
-         </Link>
+         </CardLink>
        ))}
      </FeedWrapper>
    );
  }
}

export default Feed;
```

现在，样式应该恢复了，你可以导航到问题路由以查看单个问题。但除了参数之外，还有其他方法可以使用路由进行过滤或向其传递数据，即查询字符串。这些将在本章的下一部分中进行探讨。

# 处理查询字符串

当你想要为项目添加路由时，能够导航到单个问题只是其中的一部分，分页可能是另一个部分。为此，将所有问题的概述移动到另一个名为`/questions`的路由可能是一个好主意。为此，你需要在`App`组件中的`Router`中添加另一个引用`Feed`组件的`Route`：

```jsx
...
class App extends Component {
  render() {
    return (
       <>
         <GlobalStyle />
         <AppWrapper>
           <Header />
           <Router>
             <Route exact path='/' component={Feed} />
+            <Route path='/questions' component={Feed} />
             <Route path='/questions/:id' component={Question} />
           </Router>
          </AppWrapper>
        </>
     );
   }
 }

 export default App;
```

然而，如果你现在访问该项目并尝试点击任何一个问题，你会发现渲染的组件和 URL 都没有改变。由于`react-router`的设置方式，它会导航到与当前 URL 匹配的任何路由。为了解决这个问题，你需要添加一个`Switch`路由匹配组件，它的工作原理类似于 switch 语句，并且会渲染与当前位置匹配的第一个`Route`。

1.  你可以在`scr/containers/App.js`文件中从`react-router-dom`包中导入`Switch`：

```jsx
import React, { Component } from 'react';
import styled, { createGlobalStyle } from 'styled-components';
- import { BrowserRouter as Router, Route } from 'react-router-dom';
+ import { BrowserRouter as Router, Route, Switch } from 'react-router-dom'; 
...
```

1.  并将这个`Switch`放在`Router`中，路由的顺序必须改变，以确保每当有一个`id`参数时，这个路由将首先被渲染。

```jsx
...
class App extends Component {
  render() {
    return (
      <>
        <GlobalStyle />
        <AppWrapper>
          <Header />
          <Router>
+         <Switch>
            <Route exact path='/' component={Feed} />
-           <Route path='/questions' component={Feed} />
            <Route path='/questions/:id' component={Question} />
+           <Route path='/questions' component={Feed} />
+         </Switch>
          </Router>
        </AppWrapper>
       </>
     );
   }
 }

 export default App;
```

现在`/questions`和`/questions/:id`路由将返回正确的组件，即`Feed`或`Question`组件。有了这个设置，下一步是添加分页。如果你查看 API 响应，返回的对象有一个叫做`has_more`的字段。如果这个字段的值是`true`，就意味着你可以通过在 API 请求中添加`page`查询字符串来请求更多问题。

你可以尝试将这个查询字符串添加到浏览器中的 URL 中，访问`http://localhost:3000/questions?page=2`。这个查询字符串现在作为`Feed`组件的一个 prop 出现在`location`对象的`search`字段下，你可以在 React Developer Tools 的输出中看到它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/aa4a5765-277c-4b01-85ff-1d6cfe2a8d1d.png)

不幸的是，`react-router`没有一个标准的解决方案来轻松地获取`location.search`的值。因此，你需要使用`npm`安装`query-string`包：

```jsx
npm install query-string
```

这个包被创建用来解析查询字符串，比如`location.search`，将其转换为你可以在应用程序中使用的对象：

1.  你可以通过在`Feed`组件中导入包来实现这一点：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
+ import queryString from 'query-string';

...
```

1.  现在，你可以在`constructor`方法中解析`page`查询字符串的值，并将这个解析后的值添加到`state`中。确保使用 JavaScript 的`parseInt`函数，这样页面将成为一个整数而不是一个字符串。如果没有可用的页面查询字符串，就假定你正在访问第一页：

```jsx
...
class Feed extends Component {
- constructor() {
-   super();
+ constructor(props) {
+   super(props);
+   const query = queryString.parse(props.location.search);
    this.state = {
      data: [],
+     page: (query.page) ? parseInt(query.page) : 1,
      loading: true,
      error: '',
    };
}
...
```

1.  如果`state`中有`page`查询字符串的值，你可以将其发送到 API，以获取你指定的页面号的问题：

```jsx
...
async componentDidMount() {
+ const { page } = this.state;
  try {
-   const data = await fetch(
-     `${ROOT_API}questions/${match.params.id}?site=stackoverflow`,
-   );
+   const data = await fetch(
+     `${ROOT_API}questions?order=desc&sort=activity&tagged=reactjs&site=stackoverflow${(page) ? `&page=${page}` : ''}`,
+   );
    const dataJSON = await data.json();

    if (dataJSON) {
      this.setState({
        data: dataJSON,
        loading: false,
      });
    }
  } catch(error) {
    this.setState({
      loading: false,
      error: error.message,
    });
  }
}
...
```

你可以通过更改`page`的查询字符串来测试它是否有效，比如`http://localhost:3000/questions?page=1`或`http://localhost:3000/questions?page=3`。为了使应用程序更加用户友好，让我们在页面底部添加分页按钮。

1.  创建`PaginationBar`组件，其中包含两个`Button`组件，它们是来自`react-router`的样式化的`Link`组件：

```jsx
...
 + const PaginationBar = styled.div`
+  width: 100%;
+  display: flex;
+  justify-content: space-between;
+ `;

+ const PaginationLink = styled(Link)`
+  padding: 1%;
+  background: lightBlue;
+  color: white;
+  text-decoration: none
+  border-radius: 5px;
+ `;

const  ROOT_API  =  'https://api.stackexchange.com/2.2/'; class Feed extends Component {
  ...
```

1.  现在你可以将这些添加到`FeedWrapper`的底部。

```jsx
...
render() {
  const { data, loading, error } = this.state;

    if (loading || error) {
      return <Alert>{loading ? 'Loading...' : error}</Alert>;
    }

    return (
      <FeedWrapper>
        {data.items.map(item => (
          <CardLink key={item.question_id} to={`/questions/${item.question_id}`}>
            <Card data={item} />
          </CardLink>
        ))} +       <PaginationBar>
+         <PaginationLink>Previous</PaginationLink>
+         <PaginationLink>Next</PaginationLink>
+       </PaginationBar>
      </FeedWrapper>
    );
  }
}

export default Feed;
```

1.  这些`PaginationLink`组件应该链接到某个地方，以便用户能够导航到不同的页面。为此，可以从`match`属性中获取当前 URL，并且当前页码在`state`中可用。请注意，只有当页码大于 1 时，才应显示上一页按钮，而只有当 API 响应表明返回的结果比返回的结果更多时，才应显示下一页按钮：

```jsx
...

render() {
- const { data, loading } = this.state; 
+ const { data, page, loading } = this.state;
+ const { match } = this.props;

  if (loading || error) {
    return <Alert>{loading ? 'Loading...' : error}</Alert>;
  }

  return (
    <FeedWrapper>
      {data.items.map(item => (
        <CardLink key={item.question_id} to={`/questions/${item.question_id}`}>
          <Card data={item} />
        </CardLink>
      ))}
      <PaginationBar>
-       <PaginationLink>Previous</PaginationLink>
-       <PaginationLink>Next</PaginationLink>
+       {page > 1 && <PaginationLink to={`${match.url}?page=${page - 1}`}>Previous</PaginationLink>}
+       {data.has_more && <PaginationLink to={`${match.url}?page=${page + 1}`}>Next</PaginationLink>}
      </PaginationBar>
     </FeedWrapper>
    );
  }
}

export default Feed;
```

然而，如果您现在尝试单击下一个（或上一个）按钮，URL 将更改，显示的问题不会更改。通过使用`componentDidMount`方法，API 将仅在应用程序首次挂载后调用。要在应用程序已经挂载时监视`props`或`state`的任何更改，您需要使用另一个称为`componentDidUpdate`的生命周期方法。该方法可以监视`props`或`state`的更改，因为它可以访问更新之前的`props`和`state`的值。它们在`componendDidUpdate`方法中作用域内，作为`prevProps`和`prevState`参数，您可以比较它们以检查在任何`props`或`state`更改时是否需要再次获取 API。

1.  实现这一点的第一步是创建一个获取 API 的函数，该函数还可以在`componentDidMount`方法之外使用。此函数应将`page`号作为参数，以便可以获取正确的页面：

```jsx
...
+ async fetchAPI(page) {
+   try {
+     const data = await fetch(`${ROOT_API}questions?order=desc&sort=activity&tagged=reactjs&site=stackoverflow${(page) ? `&page=${page}` : ''}`);
+     const dataJSON = await data.json();
+
+     if (dataJSON) {
+       this.setState({
+         data: dataJSON,
+         loading: false,
+       });
+     }
+   } catch(error) {
+     this.setState({
+      loading: false,
+      error: error.message,
+    });
+  }
+ }

async componentDidMount() {
  ...
```

1.  创建此函数后，可以在`componentDidMount`方法中调用它，因为这不再需要是一个异步函数，因为这已经由新的`fetchAPI`函数处理。因此，该方法可以被删除并替换为以下内容：

```jsx
...
 - async componentDidMount() { ... }

+ componentDidMount() {
+  const { page } = this.state;
+  this.fetchAPI(page);
+ } render() {
  ...
```

1.  在`componentDidMount`方法之后，您需要添加新的`componentDidUpdate`生命周期方法。如前所述，这可以将`prevProps`和`prevState`作为参数，但是由于导航到新 URL 只会更改`props`，因此只使用前者。在这里，您需要检查查询字符串是否已更改。如果它们已更改，则需要使用`page`查询字符串的新解析值更新`state`，并调用`fetchAPI`函数以获取此页面的结果：

```jsx
...  
componentDidMount() {
  const { page } = this.state;
  this.fetchAPI(page);
}

+ componentDidUpdate(prevProps) {
+  if (prevProps.location.search !== this.props.location.search) {
+    const query = queryString.parse(this.props.location.search);
+    this.setState({ page: parseInt(query.page) }, () => 
+      this.fetchAPI(this.state.page),
+    );
+  }
+ }

render() {
...
```

在使用`componentDidUpdate`生命周期方法时，您应始终确保将`prevProps`或`prevState`与当前的`props`或`state`进行比较。`componentDidUpdate`方法会不断调用，当您不比较任何值时，可能会导致应用程序崩溃的无限循环。

您现在已经实现了解析查询字符串以动态更改应用程序路由的功能。在下一节中，您将探索 React 的另一项功能，即 SRR，它使您能够从服务器上提供应用程序，而不是在运行时进行渲染。

# 启用 SSR

使用 SSR 可以帮助您构建需要快速渲染的应用程序，或者当您希望在网页可见之前加载某些信息时。尽管大多数搜索引擎现在能够渲染 SPA，但如果您希望用户在社交媒体上分享您的页面，这仍然可以是一个改进。

# 使用 react-router 创建 express 服务器

没有标准模式可以为您的 React 应用程序启用 SSR，但起点是创建一个 Node.js 服务器，该服务器为应用程序的构建版本提供服务。为此，您将使用一个名为`express`的 Node.js 的最小 API 框架。此外，您已经使用的包，如`react-router`和`styled-components`，也可以与 SSR 一起使用：

1.  您可以通过运行以下命令来安装`express`：

```jsx
npm install express
```

1.  现在，您必须在项目的根目录中创建一个名为`server`的新目录，并在其中放置一个名为`server.js`的新文件。在此文件中，您可以放置以下代码块来导入您需要运行 Node.js 服务器、`react`和`react-dom/server`的软件包，后者用于从服务器渲染您的应用程序：

```jsx
import path from 'path';
import fs from 'fs';
import express from 'express';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
```

1.  在这些导入的正下方，您需要导入应用程序的入口点，该入口点应该由服务器进行渲染：

```jsx
import path from 'path';
import fs from 'fs';
import express from 'express';
import React from 'react';
import ReactDOMServer from 'react-dom/server';

+ import App from '../src/containers/App';
```

1.  在定义了入口点之后，可以添加用`express`设置 Node.js 服务器并使其监听服务器上的所有端点的代码。首先，您需要设置`express`将运行的端口，之后，您定义所有与`/*`通配符匹配的路由应返回由`ReactDOMServer`呈现为字符串的应用程序的静态版本。这是通过获取`index.html`构建文件的内容并用包含`App`组件的服务器渲染版本的新标记替换`<div id="root"></div>`标记来完成的：

```jsx
...
const PORT = 8080;
const app = express();

app.get('/*', (req, res) => {
  const context = {};
  const app = ReactDOMServer.renderToString(<App />);

  const indexFile = path.resolve('./build/index.html');
  fs.readFile(indexFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Something went wrong:', err);
      return res.status(500).send('Oops, better luck next time!');
    }

    data = data.replace('<div id="root"></div>', `<div id="root">${app}</div>`);

    return res.send(data);
  });
});
```

1.  并且通过将以下代码块添加到此文件的底部，使此`express`服务器监听您定义的`8080`端口：

```jsx
...
app.listen(PORT, () => {
  console.log(`Server-Side Rendered application running on port ${PORT}`);
});
```

1.  最后，您需要更改`src/index.js`中应用程序的入口点的方式。在这个文件中，`ReactDOM.render`需要被`ReactDOM.hydrate`替换，因为 Node.js 服务器试图通过注入服务器渲染版本来更改`index.html`构建文件的标记：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import App from './containers/App';
import * as serviceWorker from './serviceWorker';

+ ReactDOM.hydrate(<App />, document.getElementById('root'));

...
```

然而，这个 Node.js 服务器无法使用 React 应用程序使用的任何 webpack 配置，因为其代码不在`src`目录中。为了能够运行这个 Node.js 服务器，您需要为`server`目录配置 Babel 并安装一些 Babel 包。这是您在第一章中做过的事情：

1.  应该安装的 Babel 包是`@babel/polyfill`，它编译诸如`async`/`await`之类的函数；`@babel/register`告诉 Babel 它应该转换扩展名为`.js`的文件；`@babel/preset-env`和`@babel/preset-react`用于配置 Babel 以与 React 一起工作：

```jsx
npm install @babel/polyfill @babel/register @babel/preset-env @babel/preset-react
```

1.  在`server`目录内的一个名为`index.js`的新文件中，您现在可以要求这些包，并使此文件作为`server.js`文件的入口点：

```jsx
require('@babel/polyfill');

require('@babel/register')({
 presets: ['@babel/preset-env', '@babel/preset-react'],
});

require('./server');
```

1.  您应该能够通过执行`node server/index.js`命令来运行`server/index.js`文件。因此，在`package.json`中的 scripts 字段中为此命令创建一个快捷方式：

```jsx
...  
"scripts": {
  "start": "react-scripts start",
  "build": "react-scripts build",
  "test": "react-scripts test",
  "eject": "react-scripts eject",
+  "ssr": "node server/index.js"
},
```

在运行`npm run ssr`命令之前，您应该始终在 Node.js 服务器使用构建版本之前执行`npm run build`。如果您现在运行`npm run ssr`命令，您将收到一个错误，提示“BrowserRouter 需要 DOM 来渲染”。由于`react-router`的设置方式，您需要在使用 SSR 时使用`StaticRouter`组件，而不是`BrowserRouter`：

1.  当应用程序在客户端运行时（使用`npm start`），它仍然需要使用`BrowserRouter`，因此`Route`组件的包装应该从`App`移到`src/index.js`文件中：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
+ import { BrowserRouter as Router } from 'react-router-dom';
import App from './containers/App';
import * as serviceWorker from './serviceWorker';

ReactDOM.hydrate(
+  <Router>
     <App />
+  </Router>,
  document.getElementById('root'),
);
```

1.  当然，它从`App`组件中删除：

```jsx
import React, { Component } from 'react';
import styled, { createGlobalStyle } from 'styled-components';
- import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
+ import { Route, Switch } from 'react-router-dom';
import Header from '../components/Header/Header';
import Feed from './Feed';
import Question from './Question';

...

class App extends Component {
  render() {
    return (
       <>
        <GlobalStyle />
        <AppWrapper>
          <Header />
-         <Router>
          <Switch>
            <Route exact path='/' component={Feed} />
            <Route path='/questions/:id' component={Question} />
            <Route path='/questions' component={Feed} />
          </Switch>
-         </Router>
        </AppWrapper>
      </>
    );
  }
}

export default App;
```

1.  要使 Node.js 服务器现在使用`react-router`中的`StaticRouter`组件，您需要在`server/index.js`中添加此内容，并使用`StaticRouter`包装由`ReactDOMServer`呈现的`App`组件。对于`react-router`来知道加载哪个路由，您必须将当前 URL 作为`location`属性传递，并且（在本例中）将空的`context`属性作为`StaticRouter`应该始终具有此属性以处理重定向：

```jsx
import path from 'path';
import fs from 'fs';
import express from 'express';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
+ import { StaticRouter } from 'react-router-dom';

import App from '../src/containers/App';

const PORT = 8080;
const app = express();

app.get('/*', (req, res) => {
  const context = {};
  const app = ReactDOMServer.renderToString(
-   <Router>
+   <Router location={req.url} context={context}>
      <App />
    </Router>,
  );

  ...
```

完成了最后一步，您可以再次执行`npm run build`。构建完成后，您可以通过运行`npm run ssr`启动 Node.js 服务器，以在`http://localhost:8080`上查看您的服务器渲染的 React 应用程序。这个应用程序看起来一样，因为 SSR 不会改变应用程序的外观。

SSR 的另一个优点是，您的应用程序可以更有效地被搜索引擎发现。在本节的下一部分，您将添加标记，使您的应用程序可以被这些引擎发现。

# 使用 React Helmet 添加头标签

假设您希望您的应用程序被搜索引擎索引，您需要为爬虫设置头标签，以识别页面上的内容。对于每个路由，您都希望动态执行此操作，因为每个路由都将具有不同的内容。在 React 应用程序中设置这些头标签的流行包是 React Helmet，它支持 SSR。您可以使用`npm`安装 React Helmet：

```jsx
npm install react-helmet
```

React Helmet 可以在应用程序中呈现的任何组件中定义头标签，并且如果嵌套，则组件树中`Helmet`组件的最低定义将被使用。这就是为什么您可以在`Header`组件中为所有路由创建一个`Helmet`组件，并且在每个在路由上呈现的组件中，您可以覆盖这些标签：

1.  在`src/components/App/Header.js`文件中导入`react-helmet`包，并创建一个`Helmet`组件，设置`title`和 meta`description`：

```jsx
import React from 'react';
import styled from 'styled-components';
+ import Helmet from 'react-helmet';

...

const Header = () => (
+  <>
+    <Helmet>
+      <title>Q&A Feed</title>
+      <meta name='description' content='This is a Community Feed project build with React' />
+    </Helmet>
    <HeaderWrapper>
      <Title>Q&A Feed</Title>
    </HeaderWrapper>
+  </>
);

export default Header;
```

1.  此外，在 `src/containers/Feed.js` 中创建一个 `Helmet` 组件，该组件仅为此路由设置标题，因此它将使用 `Header` 的 `description` 元标签。此组件放置在 `Alert` 组件之前的 Fragment 中，因为这在应用程序首次渲染时可用。

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
import queryString from 'query-string'
import { Link } from 'react-router-dom';
+ import Helmet from 'react-helmet';
import Card from '../components/Card/Card';

  ...

  render() {
    const { data, page, loading, error } = this.state;
    const { match } = this.props;

    if (loading || error) {
      return 
+       <>
+         <Helmet>
+           <title>Q&A Feed - Questions</title>
+         </Helmet>
          <Alert>{loading ? 'Loading...' : error}</Alert>
+       </>
    }
    ...
```

1.  对于 `src/containers/Question.js` 文件也要做同样的操作，您还可以从 `match` props 中获取问题的 ID，使页面标题更加动态：

```jsx
import React, { Component } from 'react';
import styled from 'styled-components';
+ import Helmet from 'react-helmet';
import Card from '../components/Card/Card';

  ...

  render() {
+   const { match } = this.props;
    const { data, loading, error } = this.state;

    if (loading || error) {
      return 
+       <>
+         <Helmet>
+           <title>{`Q&A Feed - Question #${match.params.id}`}</title>
+         </Helmet>
          <Alert>{loading ? 'Loading...' : error}</Alert>
+       </>
    }

    ...
```

1.  当您执行 `npm start` 命令在客户端运行应用程序时，这些头标签将被使用。但是为了支持 SSR，React Helmet 也应该在 Node.js 服务器上进行配置。为此，您可以使用 `Helmet.renderStatic` 方法，该方法会将您代码中的 `Helmet` 组件转换为其他组件的 `ReactDOMserver.renderToString` 所做的方式一样。打开 `server/server.js` 文件并添加以下代码：

```jsx
import path from 'path';
import fs from 'fs';
import express from 'express';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { StaticRouter as Router } from 'react-router-dom';
+ import Helmet from 'react-helmet';

...

app.get('/*', (req, res) => {
  const context = {};
  const app = ReactDOMServer.renderToString(
    <Router location={req.url} context={context}>
      <App />
    </Router>,
  );
+  const helmet = Helmet.renderStatic();

  const indexFile = path.resolve('./build/index.html');
  fs.readFile(indexFile, 'utf8', (err, data) => {
    if (err) {
      console.error('Something went wrong:', err);
      return res.status(500).send('Oops, better luck next time!');
    }

    data = data.replace('<div id="root"></div>', `<div id="root">${app}</div>`);
+   data = data.replace('<meta name="helmet"/>', `${helmet.title.toString()}${helmet.meta.toString()}`);

    return res.send(data);
  });
});

...
```

1.  在此文件的最后一行中，您现在已经定义了 `<meta name="helmet" />` 元素应该被 React Helmet 创建的 `title` 和 `meta` 标签替换。为了能够用这些标签替换这个元素，将此元素添加到 `public` 目录中的 `index.html` 中。此外，您还必须删除 React Helmet 现在已经创建的 `title` 元素：

```jsx
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <link rel="shortcut icon" href="%PUBLIC_URL%/favicon.ico" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1, shrink-to-fit=no"
    />
    <meta name="theme-color" content="#000000" />
    <link rel="manifest" href="%PUBLIC_URL%/manifest.json" />
+   <meta name="helmet" />
-   <title>React App</title>
  </head>
...
```

完成了这些最后的更改后，您现在可以再次运行 `npm run build` 来创建应用程序的新构建版本。完成此过程后，执行 `npm run ssr` 命令来启动 Node.js 服务器，并在浏览器上访问您的 React SSR 应用程序，网址为 `http://localhost:8080`。

# 摘要

在本章中，您使用 `react-router` 为 Create React App 添加了动态路由，使用户可以在特定页面上打开您的应用程序。通过使用 React 的 Suspense 特性，组件在客户端动态加载。这样，您可以减少用户首次接触应用程序之前的时间。在本章中创建的项目还支持 SSR，并且使用 React Helmet 为应用程序添加动态头标签以用于 SEO 目的。

完成本章后，您应该已经感觉像是 React 的专家了！下一章肯定会将您的技能提升到更高的水平，因为您将学习如何使用上下文 API 处理状态管理。使用上下文 API，您可以在应用程序中的多个组件之间共享状态和数据，无论它们是父组件的直接子组件还是其他组件。

# 进一步阅读

+   React Helmet: [`github.com/nfl/react-helmet`](https://github.com/nfl/react-helmet)

+   ReactDOMServer: [`reactjs.org/docs/react-dom-server.html`](https://reactjs.org/docs/react-dom-server.html)
