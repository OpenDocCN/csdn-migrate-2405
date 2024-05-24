# React 项目（三）

> 原文：[`zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0`](https://zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用上下文 API 和 Hooks 构建个人购物清单应用程序

状态管理是现代 Web 和移动应用程序的一个非常重要的部分，也是 React 擅长的领域。在 React 应用程序中处理状态管理可能会相当令人困惑，因为有多种方式可以处理应用程序的当前状态。本书前四章创建的项目并没有过多关注状态管理，这一点将在本章中更加深入地探讨。

本章将展示如何在 React 中处理状态管理，通过为应用程序创建一个全局状态，可以从每个组件中访问。在 React v16.3 之前，您需要第三方包来处理 React 中的全局状态，但是随着上下文 API 的更新版本，这不再是必需的。此外，随着 React Hooks 的发布，引入了更多改变此上下文的方法。使用一个示例应用程序，演示了处理应用程序全局状态管理的方法。

本章将涵盖以下主题：

+   使用上下文 API 进行状态管理

+   **高阶组件**（**HOC**）和上下文

+   使用 Hooks 改变上下文

# 项目概述

在本章中，我们将使用`react-router`创建一个**渐进式 Web 应用程序**（**PWA**），它使用上下文和 React Hooks 进行全局状态管理。此外，HOC 用于在整个应用程序中访问数据。

构建时间为 2.5 小时。

# 入门

本章将创建的项目是在 GitHub 上找到的初始版本的基础上构建的：[`github.com/PacktPublishing/React-Projects/tree/ch5-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch5-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch5`](https://github.com/PacktPublishing/React-Projects/tree/ch5)。

下载初始应用程序后，请确保从项目的根目录运行`npm install`。该项目是使用 Create React App 创建的，并安装了`react`、`react-dom`、`react-scripts`、`styled-components`和`react-router`等包，这些包在前几章中已经见过。安装完成后，您可以在终端的同一个标签页中运行`npm start`，并在浏览器中查看项目（`http://localhost:3000`）。

由于项目是使用 Create React App 创建的，因此已注册服务工作者以使应用程序作为 PWA 运行。您可以通过首先运行`npm run build`，然后在构建过程完成后运行`serve -s build`来检查此功能。现在可以访问应用程序的构建版本`http://localhost:5000`。如果您访问此 URL 上的应用程序并看到不同的 URL，可能是您在任何先前章节中创建的应用程序的构建版本仍在提供。这可能是由服务工作者创建的浏览器缓存造成的。您可以通过在浏览器上打开开发者工具并打开“应用程序”选项卡，在那里您可以单击“清除站点数据”部分上的“清除存储”按钮来清除浏览器缓存中的任何先前的应用程序。

检查应用程序在没有互联网连接时是否仍然可用，您可以让浏览器模拟离线情况。启用此选项可以在浏览器的开发者工具中的“应用程序”选项卡中找到。在此选项卡中，您可以在左侧菜单中找到“服务工作者”，单击此链接后，可以在出现的页面上选择“离线”复选框。

本节的初始应用程序位于`http://localhost:3000`，比以往任何一章都要先进一些。打开应用程序时，将呈现显示标题、副标题和两个列表的屏幕。例如，如果您单击此处显示的第一个列表，将打开一个新页面，显示此列表的项目。在此页面上，您可以单击右上角的“添加列表”按钮打开一个新页面，该页面具有添加新列表的表单，并且看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/b98a5a77-3dfa-4140-b1a3-10a6c27951ad.png)

此表单由`Form`组件呈现，但尚无功能，因为稍后将添加此功能。当您单击左侧按钮时，它将使用`react-router`中的`history.goBack`方法将您重定向到先前访问的页面。

当您尝试提交表单以添加新列表或向列表中添加新项目时，什么也不会发生。这些表单的功能将稍后在本节中添加，您将使用上下文 API 和 React Hooks。

该项目的结构与您之前创建的应用程序的结构相同。在`components`目录中区分了可重用的函数组件和`containers`目录中的类组件。类组件被包装在一个名为`withDataFetching`的 HOC 中，该 HOC 为这些组件添加了数据获取和生命周期（`componentDidMount`）。

`withDataFetching` HOC 是在第二章中创建的 HOC 的略微修改版本，即*使用可重用的 React 组件创建渐进式 Web 应用程序*，该版本也被称为`withDataFetching.js`。这个修改后的版本是一个柯里化组件，意味着它一次接受多个参数。在 HOC 的情况下，这意味着您不仅可以将组件用作参数，还需要将此组件的 props 用作参数。

以下是项目的完整结构概述：

```jsx
shopping-list
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
    |-- components
        |-- Button
            |-- Button.js
        |-- FormItem
            |-- FormItem.js
        |-- Header
            |-- Header.js
            |-- Subheader.js
         |-- ListItem
             |-- ListItem.js
 |-- containers
    |-- App.js
    |-- Form.js
    |-- List.js
    |-- Lists.js
 |-- index.js
 |-- serviceWorker.js
.gitignore
db.json
package.json
```

这个应用程序的入口点是`src/index.js`文件，它在`react-router`的`Router`组件中渲染`App`类组件。`App`组件包含一个`Header`组件和一个`Switch`路由组件，定义了四个路由。这些路由如下：

+   `/`：渲染`Lists`，显示所有列表的概述

+   `/list/:id`：渲染`List`，显示特定列表中所有项目的概述

+   `/list/:id/new`：渲染`Form`，显示向特定列表添加新项目的表单

数据是从一个使用免费服务创建的模拟服务器中获取的，该服务是 My JSON Server，它从 GitHub 项目的根目录中的`db.json`文件创建服务器。该文件包含一个具有两个字段`items`和`lists`的 JSON 对象，它在模拟服务器上创建了多个端点。在本章中，您将使用的端点如下：

+   `https://my-json-server.typicode.com/<your-username>/<your-repo>/items`

+   `https://my-json-server.typicode.com/<your-username>/<your-repo>/lists`

`db.json`文件必须存在于您的 GitHub 存储库的主分支（或默认分支）中，以使 My JSON Server 正常工作。否则，在尝试请求 API 端点时，您将收到 404 Not Found 的消息。

# 个人购物清单

在本节中，您将构建一个个人购物清单应用程序，该应用程序使用 Context 和 React Hooks 进行全局状态管理。通过这个应用程序，您可以创建购物清单，并添加商品、数量和价格。本节的起点是一个已启用路由和本地状态管理的初始应用程序。

# 使用上下文 API 进行状态管理

状态管理非常重要，因为应用程序的当前状态包含对用户有价值的数据。在之前的章节中，您已经通过在`constructor`中设置初始状态并使用`this.setState`方法进行更新来使用本地状态管理。当状态中的数据只对设置状态的组件重要时，这种模式非常有用。由于通过多个组件传递状态作为 props 可能会变得混乱，您需要一种方法来在整个应用程序中访问 props，即使您没有专门将它们作为 props 传递。为此，您可以使用 React 的上下文 API，这也是您在之前章节中已经使用的包（如`styled-components`和`react-router`）所使用的。

在多个组件之间共享状态，将探讨一个名为 Context 的 React 功能，从本节的第一部分开始。

# 创建 Context

当您想要将 Context 添加到 React 应用程序中时，可以通过使用 React 的`createContext`方法创建一个新的 Context 来实现。这将创建一个由两个 React 组件组成的 Context 对象，称为**Provider**和**Consumer**。Provider 是 Context 的初始（以及随后的当前）值所在的地方，可以被存在于 Consumer 中的组件访问。

这是在`src/containers/App.js`中的`App`组件中完成的，因为您希望列表的上下文在由`Route`渲染的每个组件中都可用。

1.  让我们首先为列表创建一个 Context，并将其导出，以便列表数据可以在任何地方使用。为此，您可以在一个新目录`src/Context`中创建一个名为`ListsContextProvider.js`的新文件。在这个文件中，您可以添加以下代码：

```jsx
import React from 'react';
import withDataFetching from '../withDataFetching';

export const ListsContext = React.createContext();
const ListsContextProvider = ({ children, data }) => (
  <ListsContext.Provider value={{ lists: data }}>
    {children}
  </ListsContext.Provider>
);

export default withDataFetching({
  dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists',
})(ListsContextProvider);
```

先前的代码基于传递为 prop 的 Context 组件创建了一个 Provider，并根据从获取所有列表的`withDataFetching` HOC 的返回设置了一个值。使用`children` prop，所有将包装在`ListsContextProvider`组件内的组件都可以从 Consumer 中检索值的数据。

1.  这个`ListsContextProvider`组件和上下文可以在`src/containers/App.js`中的`App`组件中导入，随后应该放在`Switch`组件周围。`ListsContext`对象也被导入，因为之后无法创建 Consumer：

```jsx
import React from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { Route, Switch } from 'react-router-dom';
+ import ListsContextProvider, { ListsContext } from '../Context/ListsContextProvider';

...

const App = () => (
 <>
   <GlobalStyle />
   <AppWrapper>
     <Header />
+    <ListsContextProvider>
       <Switch>
         <Route exact path='/' component={Lists} />
         <Route path='/list/:id/new' component={Form} />
         <Route path='/list/:id' component={List} />
       </Switch>
+    </ListsContextProvider>
 </AppWrapper>
 </>
);

export default App;
```

1.  这样，您现在可以为`ListsContext`添加一个 Consumer，它嵌套在包含`ListsContext`的 Provider 的`ListsContextProvider`组件中。这个 Consumer 返回 Provider 中包含的值，其中包含之前获取的列表数据：

```jsx
...

const App = () => (
  <>
    <GlobalStyle />
      <AppWrapper>
      <Header />
        <ListsContextProvider>
+         <ListsContext.Consumer>
+           {({ lists }) => (
              <Switch>
                <Route exact path='/' component={Lists} />
                <Route path='/list/:id/new' component={Form} />
                <Route path='/list/:id' component={List} />
              </Switch>
+           )}
+         </ListsContext.Consumer>
        </ListsContextProvider>
    </AppWrapper>
  </>
);

export default App;
```

1.  要将此列表数据实际传递给`Route`渲染的任何组件，您应该更改将组件传递给`Route`组件的方式。您可以使用 React 的`RenderProps`模式，而不是告诉`Route`要渲染哪个组件。这种模式是指一种在 React 组件之间共享代码的技术，使用一个值为返回组件的函数的 prop。在这种情况下，您希望`Route`组件渲染一个组件，不仅将`react-router`的 props 添加到其中，还要添加来自`ListsContext`的列表数据：

```jsx
...
<ListsContextProvider>                       
  <ListsContext.Consumer>
    {({ lists }) => (
      <Switch>
-       <Route exact path='/' component={Lists} />
+       <Route exact path='/' render={props => lists && <Lists lists={lists} {...props} /> } />
        <Route path='/list/:id/new' component={Form} />
        <Route path='/list/:id' component={List} />
      </Switch>
    )}
  </ListsContext.Consumer>
</ListsContextProvider>
...
```

1.  如果您现在查看浏览器的开发者工具中的网络选项卡，您会看到 API 被获取了两次。由于现在`ListsContextProvider`也在获取列表，因此`Lists`组件本身不再需要获取 API，因为它现在作为 prop 发送。因此，您可以对`src/containers/Lists.js`进行以下更改：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
- import withDataFetching from '../withDataFetching';
import SubHeader from '../components/SubHeader/SubHeader';

...

- const Lists = ({ data, loading, error, match, history }) => (
+ const Lists = ({ lists, loading = false, error = false, match, history }) => (
  <>
    {history && <SubHeader title='Your Lists' openForm={() => history.push('/new')} /> }
    <ListWrapper>
      {(loading || error) && <Alert>{loading ? 'Loading...' : error}</Alert>}
-     {data.lists && data.lists.map(list => (
+     {lists && lists.map(list => (
        <ListLink key={list.id} to={`list/${list.id}`}>
          <Title>{ list.title }</Title>
        </ListLink>
      ))}
    </ListWrapper>
  </>
);

- export default withDataFetching({
-   dataSource: 'https://github.com/PacktPublishing/React-Projects/lists',
})(Lists); + export default Lists;
```

现在您已经从`Lists`中删除了`withDataFetching` HOC，不再发送重复的 API 请求。列表的数据是从`ListsContextProvider`中获取的，并由`ListsContext.Consumer`传递给`Lists`。如果通过转到`http://localhost:3000/`在浏览器中打开应用程序，您会看到列表像以前一样被渲染。

您还可以将列表数据发送到`List`组件中，这样，例如，当您从主页点击列表时，可以显示所选列表的名称：

1.  为此，您再次使用`RenderProps`模式，这次是为`Route`渲染`List`。这确保了`lists`是可用的，并在之后渲染`List`组件，该组件还接受所有的`react-router` props：

```jsx
...
<ListsContextProvider>                       
  <ListsContext.Consumer>
    {({ lists }) => (
      <Switch>
        <Route exact path='/' render={props => lists && <Lists lists={lists} {...props} /> } />
        <Route path='/list/:id/new' component={Form} />
-       <Route path='/list/:id' component={List} />
+       <Route path='/list/:id' render={props => lists && <List lists={lists} {...props} />} />
      </Switch>
    )}
  </ListsContext.Consumer>
</ListsContextProvider>
...
```

1.  在`src/containers/List.js`文件中的`List`组件中，您可以从 props 中检索列表。这个数组需要被过滤以获取正确的`list`，找到的对象包含`title`，可以添加到`SubHeader`组件中，这样它就会显示在页面上：

```jsx
- const List = ({ data, loading, error, match, history }) => {
+ const List = ({ data, loading, error, lists, match, history }) => {
    const items = data && data.filter(item => item.listId === parseInt(match.params.id))
+   const list = lists && lists.find(list => list.id === parseInt(match.params.id));

  return (
    <>
-     {history && <SubHeader goBack={() => history.goBack()} openForm={() => history.push(`${match.url}/new`)} />}
+     {history && list && <SubHeader goBack={() => history.goBack()} title={list.title} openForm={() => history.push(`${match.url}/new`)} />}
      <ListItemWrapper>
        {items && items.map(item => <ListItem key={item.id} data={item} />)}
      </ListItemWrapper>
    </>
  )
};

export default withDataFetching({
  dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items',
})(List);
```

通过这些添加，如果您访问`http://localhost:3000/list/1`，当前列表的`title`现在将显示。在`SubHeader`组件中，标题"Daily groceries"现在可见，看起来类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/c48fd6c0-648d-4305-8e55-61d57a15c80b.png)

在下一节中，您还将为项目添加一个 Context 对象，这样项目也可以在`react-router`的`Switch`组件内的所有组件中使用。

# 嵌套上下文

就像对于列表数据一样，项目数据也可以存储在 Context 中，并传递给需要这些数据的组件。这样，数据不再从任何渲染的组件中获取，而是从`src/Providers`目录中的`ContextProvider`组件中获取：

1.  再次，首先创建一个新的组件，其中创建了一个 Context 和 Provider。这次，它被称为`ItemsContextProvider`，也可以添加到`src/Context`目录中，文件名为`ItemsContextProvider.js`：

```jsx
import React from 'react';
import withDataFetching from '../withDataFetching';

export const ItemsContext = React.createContext();

const ItemsContextProvider = ({ children, data }) => (
  <ItemsContext.Provider value={{ items: data }}>
    { children }
  </ItemsContext.Provider>
);

export default withDataFetching({
  dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items', 
})(ItemsContextProvider);
```

1.  接下来，在`src/containers/App.js`中导入这个新的 Context 和`ContextProvider`，您可以将其嵌套在`ListsContextProvider`组件内：

```jsx
import React from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { Route, Switch } from 'react-router-dom';
import ListsContextProvider, { ListsContext } from '../Context/ListsContextProvider';
+ import ItemsContextProvider, { ItemsContext } from '../Context/ItemsContextProvider';

...

const App = () => (
  <>
    <GlobalStyle />
    <AppWrapper>
     <Header />
     <ListsContextProvider>
+    <ItemsContextProvider>
     <ListsContext.Consumer>
        ...
```

1.  `ItemsContextProvider`现在嵌套在`ListsContextProvider`下面，这意味着`ItemsContext`的`Consumer`也可以嵌套在`ListsContext`的`Consumer`下面。这使得来自`ItemsContextProvider`的值可以被使用`RenderProps`模式的`List`组件使用：

```jsx
<ListsContextProvider>
  <ItemsContextProvider>
    <ListsContext.Consumer>
      {({ lists }) => (
+       <ItemsContext.Consumer>
+         {({ items }) => (
            <Switch>
              <Route exact path='/' render={props => lists && <Lists lists={lists} {...props} />} />
              <Route path='/new' component={Form} />
              <Route path='/list/:id/new' component={Form} />
-             <Route path='/list/:id' render={props => lists && <List lists={lists} {...props} />
+             <Route path='/list/:id' render={props => lists && items && <List lists={lists} listItems={items} {...props} />}/>
             </Switch>
+          )}
+        </ItemsContext.Consumer>
       )}
     </ListsContext.Consumer>
   </ItemsContextProvider>
 </ListsContextProvider>
```

1.  在将项目数据作为 prop 传递给`List`之后，现在可以使用`withDataFetching` HOC 替换已经存在的数据获取。为了实现这一点，您需要对`src/containers/List.js`进行以下更改：

```jsx
import React from 'react';
import styled from 'styled-components';
- import withDataFetching from '../withDataFetching';
import SubHeader from '../components/SubHeader/SubHeader';
import ListItem from '../components/ListItem/ListItem';

...

- const List = ({ data, lists, loading, error, match, history }) => {
+ const List = ({ lists, listItems, loading = false, error = false, match, history }) => {
-   const items = data && data.filter(item => item.listId === parseInt(match.params.id))
+   const items = listItems && listItems.filter(item => item.listId === parseInt(match.params.id))

    const list = lists && lists.find(list => list.id === parseInt(match.params.id));
    return (
      <>
        {history && <SubHeader goBack={() => history.goBack()} title={list.title} openForm={() => history.push(`${match.url}/new`)} />}
        <ListItemWrapper>
          {items && items.map(item => <ListItem key={item.id} data={ item } />) }
        </ListItemWrapper>
      </>
    )
};

- export default withDataFetching({
    dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items',
  })(List);
+ export default List;
```

现在所有的数据获取都不再由`List`和`Lists`组件进行。通过嵌套这些 Context Providers，返回值可以被多个组件消耗。但这仍然不是理想的，因为现在在启动应用程序时加载了所有的列表和所有的项目。

在下一节中，您将看到如何通过将上下文与 Hooks 结合来获取所需的数据。

# 使用 Hooks 改变上下文

有多种方式可以有条件地从上下文中获取数据；其中一种是将上下文中的数据放入本地状态。这可能是一个较小应用的解决方案，但对于较大的应用来说效率不高，因为您仍然需要将这个状态传递到组件树中。另一个解决方案是使用 React Hooks 创建一个函数，将其添加到上下文的值中，并可以从嵌套在此上下文中的任何组件中调用。此外，这种获取数据的方法可以防止您有效地加载只需要的数据。

如何将其与 React 生命周期和使用 Hooks 进行状态管理结合使用的示例在本节的第一部分中进行了演示。

# 在函数组件中使用生命周期

Hooks 带来的许多伟大的增强之一是在函数组件中使用生命周期。在 Hooks 之前，只有类组件支持生命周期，使用容器组件模式和到目前为止您使用的`withDataFetching` HOC。按照以下步骤：

1.  实现这一点的第一步是将数据获取功能从`withDataFetching` HOC 移动到列表的 Provider 中，在`src/Context/ListsContextProvider.js`文件中。这个函数将接受`dataSource`（可以是文件或 API）并使用`fetch`从这个源中检索数据：

```jsx
import React from 'react';

export const ListsContext = React.createContext();

async function fetchData(dataSource) {
 try {
 const data = await fetch(dataSource);
 const dataJSON = await data.json();

 if (dataJSON) {
 return await ({ data: dataJSON, error: false });
 }
 } catch(error) {
 return ({ data: false, error: error.message });
 }
};

....
```

1.  有了这个函数，下一步将是使用`dataSource`调用它并将数据添加到 Provider 中。但是，您应该将`dataSource`返回的数据存储在哪里？以前，您使用`componentDidMount`生命周期方法来实现这一点，并将来自源的结果添加到本地状态中。使用 Hooks，您可以在函数组件中使用`useState` Hook 进行本地状态管理。您可以将状态的初始值作为参数传递给这个 Hook，这个初始值是您之前在`constructor`中设置的。返回的值将是一个数组，包含此状态的当前值和一个更新此状态的函数。此外，Hooks 应该始终在使用它的组件内部创建——在这种情况下，应该在`ListsContextProvider`内部创建。

```jsx
...
async function fetchData(dataSource) {
  try {
    const data = await fetch(dataSource);
    const dataJSON = await data.json();

    if (dataJSON) {
      return await ({ data: dataJSON, error: false });
    }
  } catch(error) {
      return ({ data: false, error: error.message });
  }
};

- const ListsContextProvider = ({ children, data }) => ( + const ListsContextProvider = ({ children }) => {
+    const [lists, setLists] = React.useState([]);
+    return (
-       <ListsContext.Provider value={{ lists: data }}>
+       <ListsContext.Provider value={{ lists }}>
          {children}
        </ListsContext.Provider>
      ) + };

- export default withDataFetching({
    dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items', 
  })(ListsContextProvider);
+ export default ListsContextProvider; 
```

1.  在前面的代码块中，您可以看到状态的初始值是一个空数组，它被传递给`ListsContext`的 Provider。要用来自`dataSource`的数据填充此状态，您需要实际调用`fetchData`函数。通常情况下，这将在`componentDidMount`或`componentDidUpdate`生命周期方法内完成，但由于组件是一个函数组件，您将使用一个 Hook。这个 Hook 被称为`useEffect`，用于处理副作用，无论是应用程序挂载时还是状态或 prop 更新时。这个 Hook 接受两个参数，第一个是回调函数，第二个是包含此 Hook 依赖的所有变量的数组。当其中任何一个发生变化时，将调用此 Hook 的回调函数。当此数组中没有值时，Hook 将仅在第一次挂载时调用。从源中获取数据后，状态将被更新为结果：

```jsx
...
const ListsContextProvider = ({ children }) => {
const [lists, setLists] = React.useState([]); React.useEffect(() => {
    const asyncFetchData = async dataSource => {
      const result = await fetchData(dataSource);

      setLists([...result.data]);
    };

    asyncFetchData('https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists');

  }, [fetchData, setLists]);  return (    <ListsContext.Provider value={{ lists }}>
      {children}
    </ListsContext.Provider>
  )
};

export default ListsContextProvider;
```

您可以看到`fetchData`函数并不是直接调用的，而是包裹在一个名为`asyncFetchData`的函数中。由于`fetchData`函数中的`async/await`将返回`Promise`，您需要另一个`async/await`来检索值并解决`Promise`。但是，您不能直接在`useEffect` Hook 中使用`async/await`。在`useEffect` Hook 的回调之后的数组块被称为依赖数组，在这里定义了在 Hook 中使用的值。`fetchData`和`setLists`函数是在此组件的第一次挂载时创建的，这意味着`useEffect` Hook 模拟了一个类似于`componentDidMount`的生命周期。如果要将此 Hook 用作`componentDidUpdate`生命周期方法，数组将包含应该被监视更新的所有状态变量和 props。

通过使用其他 Hooks，您还可以直接将数据传递给 Provider，而无需使用本地状态管理。这将在本节的下一部分中进行演示。

# 使用 Flux 模式更新 Provider

另一种使用动作将数据添加到 Provider 的方法是使用类似 Flux 的模式，这是由 Facebook 引入的。Flux 模式描述了一个数据流，其中派发动作从存储中检索数据并将其返回给视图。这意味着动作需要在某个地方描述；应该有一个全局的地方存储数据，视图可以读取这些数据。为了使用上下文 API 实现这种模式，可以使用另一个名为`useReducer`的 Hook。这个 Hook 可以用来从任何数据变量中返回数据，而不是从本地状态中返回数据。

1.  与`useState` Hook 一样，使用`useReducer` Hook 的组件也需要添加到其中。`useReducer`将接受一个初始值和一个确定应返回哪些数据的函数。这个初始值需要在`src/Context/ListsContextProvider.js`文件中添加，然后再添加 Hook。

```jsx
import React from 'react';

export const ListsContext = React.createContext();

const initialValue = {
 lists: [],
 loading: true,
  error: '',
},

... 
```

1.  `initialValue`旁边，`useReducer` Hook 还接受一个名为`reducer`的函数。这个`reducer`函数也应该被创建，它是一个更新`initialValue`的函数，根据发送给它的动作返回当前值。如果派发的动作不匹配`reducer`中定义的任何动作，`reducer`将只是返回当前值而没有任何改变。

```jsx
import React from 'react';

export const ListsContext = React.createContext();

const initialValue = {
  lists: [],
  loading: true,
  error: '',
};

const reducer = (value, action) => {
 switch (action.type) {
 case 'GET_LISTS_SUCCESS':
 return {
 ...value,
 lists: action.payload,
 loading: false,
 };
 case 'GET_LISTS_ERROR':
 return {
        ...value,
 lists: [],
        loading: false,
 error: action.payload,
 };
 default:
 return value;
 }
};

...
```

1.  现在将`useReducer` Hook 的两个参数添加到文件中，因此需要添加实际的 Hook 并将`initialValue`和`reducer`传递给它。

```jsx
...

const ListsContextProvider = ({ children }) => { 
-    const [lists, setLists] = React.useState([]);
+    const [value, dispatch] = React.useReducer(reducer, initialValue);

...
```

1.  正如你所看到的，当`GET_LISTS_SUCCESS`或`GET_LISTS_ERROR`动作发送到`reducer`时，`reducer`会改变它返回的值。在之前提到过，可以使用`useReducer` Hook 返回的`dispatch`函数来调用这个`reducer`。然而，由于你还需要处理数据的异步获取，所以不能直接调用这个函数。相反，你需要创建一个`async/await`函数，调用`fetchData`函数，然后派发正确的动作。

```jsx
...
const ListsContextProvider = ({ children }) => {
  const [value, dispatch] = React.useReducer(reducer, initialValue);

 const getListsRequest = async () => {
    const result = await fetchData('https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists');

    if (result.data && result.data.length) {
      dispatch({ type: 'GET_LISTS_SUCCESS', payload: result.data });
    } else {
      dispatch({ type: 'GET_LISTS_ERROR', payload: result.error });
    }
  } ...
```

使用前面的`getListsRequest`函数时，当调用这个函数时，会对`fetchData`函数进行`async/await`调用。如果`dataSource`返回的数据不是空数组，将使用`useReducer` Hook 中的`dispatch`函数向 reducer 派发`GET_LISTS_SUCCESS`动作。如果不是，将派发`GET_LISTS_ERROR`动作，返回错误消息。

1.  当您的应用程序挂载时，现在可以从`useEffect` Hook 中调用`getListsRequest`函数，以便应用程序将填充列表数据。这应该是从视图中完成的，因此您需要创建一个操作，可以将其添加到`Provider`中，以便从`Consumer`中获取此值的任何组件都可以使用它：

```jsx
...  

-  React.useEffect(() => {
-    const asyncFetchData = async (dataSource) => {
-      const result = await fetchData(dataSource);
-
-      setLists([...result.data]);
-    }
-
-    asyncFetchData('https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists');
-  }, [setLists]);

  return (
-   <ListsContext.Provider value={{ lists: state }}>               
+   <ListsContext.Provider value={{ ...value, getListsRequest }}>
      {children}
    </ListsContext.Provider>
  );
};

export default ListsContextProvider;
```

1.  在显示列表的组件`Lists`中，您可以使用`getListsRequest`函数检索列表的数据。因此，您需要从`src/containers/App.js`文件中的`RenderProps`中将其传递给此组件。此外，当尚未检索到列表数据或发生错误时，您可以添加一个加载指示器或错误消息：

```jsx
...
const App = () => (
  <>
    <GlobalStyle />
      <AppWrapper>
      <Header />
        <ListsContextProvider>
          <ItemsContextProvider>
            <ListsContext.Consumer>
-             {({ lists }) => (
+             {({ lists, loading: listsLoading, error: listsError, getListsRequest }) => (
                <ItemsContext.Consumer>
                  {({ items }) => (
                    <Switch>
-                     <Route exact path='/' render={props => lists && <Lists lists={lists} {...props} />} />
+                     <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
...
```

1.  最后，在`Lists`组件中挂载时，从`Lists`组件调用`getListsRequest`函数，并添加加载指示器或错误消息。只有在尚无可用列表时才应检索列表：

```jsx
- const Lists = ({lists, loading = false, error = '', match, history}) => !loading && !error ? (
+ const Lists = ({lists, loading, error, getListsRequest, match, history}) => {
+  React.useEffect(() => {
+    if (!lists.length) {
+      getListsRequest();
+    }
+  }, [lists, getListsRequest]);

+ return !loading && !error ? (
  <>
    {history && <SubHeader title='Your Lists' openForm={() => history.push('/new')} /> }
    <ListWrapper>
      {lists && lists.map(list => (
        <ListLink key={list.id} to={`list/${list.id}`}>
          <Title>{list.title}</Title>
        </ListLink>
      ))}
    </ListWrapper>
  </>
- );
+  ) : <Alert>{loading ? 'Loading...' : error}</Alert>;
+ } export default Lists;
```

如果您现在再次在浏览器中访问项目，您会发现列表中的数据与以前一样加载。最大的区别是数据是使用 Flux 模式获取的，这意味着这可以扩展到在其他情况下获取数据。同样，也可以在`src/Context/ItemsContextProvider.js`文件中对`ItemsContextProvider`执行相同操作：

1.  首先添加项目的初始值，这将与`useReducer` Hook 一起使用：

```jsx
import React from 'react';
- import withDataFetching from '../withDataFetching';

+ const initialValue = {
+  items: [],
+  loading: true,
+  error: '',
+ }

export const ItemsContext = React.createContext();

- const ItemsContextProvider = ({ children, data }) => (
+ const ItemsContextProvider = ({ children }) => {
    + const [value, dispatch] = React.useReducer(reducer, initialValue);

+ return (
  <ItemsContext.Provider value={{ items: data }}>
    {children}
  </ItemsContext.Provider>
);
+ };

...
```

1.  之后，您可以添加 reducer，它有两个操作，与列表 reducer 的操作非常相似。唯一的区别是它们将向 Provider 添加有关项目的信息。还要添加与您添加到`ListsContextProvider`的`fetchData`函数相同的函数：

```jsx
import React from 'react';
import withDataFetching from '../withDataFetching';

export const ItemsContext = React.createContext();

const initialValue = {
  items: [],
  loading: true,
  error: '',
}

+ const reducer = (value, action) => {
+  switch (action.type) {
+    case 'GET_ITEMS_SUCCESS':
+      return {
+        ...value,
+        items: action.payload,
+        loading: false,
+      };
+    case 'GET_ITEMS_ERROR':
+      return {
+        ...value,
+        items: [],
+        loading: false,
+        error: action.payload,
+      };
+    default:
+      return value;
+  }
+ };

+ async function fetchData(dataSource) {
+  try {
+    const data = await fetch(dataSource);
+    const dataJSON = await data.json();
+
+    if (dataJSON) {
+      return await ({ data: dataJSON, error: false })
+    }
+  } catch(error) {
+      return ({ data: false, error: error.message })
+  }
+ };

const ItemsContextProvider = ({ children }) => {
    ...
```

1.  现在，您可以创建`async/await`函数，用于获取项目的`dataSource`。此函数还将获取所选列表的`id`变量，以避免数据的过度获取。`withDataFetching` HOC 可以被移除，因为不再需要检索数据：

```jsx
...
const ItemsContextProvider = ({ children }) => {
  const [value, dispatch] = React.useReducer(reducer, initialValue);

+  const getItemsRequest = async (id) => {
+    const result = await fetchData(`
+      https://my-json-server.typicode.com/PacktPublishing/React-Projects/items/${id}/items
+    `);

+    if (result.data && result.data.length) {
+      dispatch({ type: 'GET_ITEMS_SUCCESS', payload: result.data });
+    } else {
+      dispatch({ type: 'GET_ITEMS_ERROR', payload: result.error });
+    }
+  }

  return (
-    <ItemsContext.Provider value={{ items: data }}>            
+    <ItemsContext.Provider value={{ ...value, getItemsRequest }}>
      {children}
    </ItemsContext.Provider>
  );
}

- export default withDataFetching({
    dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items', 
  })(ItemsContextProvider);
+ export default ItemsContextProvider;
```

1.  由于现在已将检索项目的函数添加到项目的 Provider 中，因此 Consumer 是`src/containers/App.js`，可以将此函数传递给显示项目的`List`组件：

```jsx
...
const App = () => (
  <>
    <GlobalStyle />
      <AppWrapper>
      <Header />
        <ListsContextProvider>
          <ItemsContextProvider>
            <ListsContext.Consumer>
              {({ lists, loading: listsLoading, error: listsError, getListsRequest }) => (
                <ItemsContext.Consumer>
-                 {({ items }) => (
+                 ({ items, loading: itemsLoading, error: itemsError, getItemsRequest }) => (
                    <Switch>
                      <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
                      <Route path='/list/:id/new' component={Form} />
-                     <Route path='list/:id' render={props => lists && items && <List lists={lists} listItems={items} {...props} /> 
+                     <Route path='/list/:id' render={props => lists && items && <List lists={lists} items={items} loading={itemsLoading} error={itemsError} getItemsRequest={getItemsRequest} {...props} /> } />
                    </Switch>
                  )}
                </ItemsContext.Consumer>
              )}
           </ListsContext.Consumer>
         </ItemsContextProvider>
       </ListsContextProvider>
    </AppWrapper>
  </>
);

export default App;
```

1.  最后，在`src/containers/List.js`中的`List`组件中调用`getItemsRequest`函数。此函数将使用`match`属性从当前路由中获取您正在显示的列表的`id`变量。重要的是要提到，只有在`items`的值为空时才应调用此函数，以防止不必要的数据获取。

```jsx
...
- const List = ({ listItems, loading = false, error = '', lists, match, history }) => {
+ const List = ({ items, loading, error, lists, getItemsRequest, match, history }) => {
-  const items = listItems && listItems.filter(item => item.listId === parseInt(match.params.id));
  const list = lists && lists.find(list => list.id === parseInt(match.params.id));

+  React.useEffect(() => {
+   if (!items.length > 0) {
+     getItemsRequest(match.params.id);
+   };
+ }, [items, match.params.id, getItemsRequest]);

  return !loading && !error ? (
    <>
      {(history && list) && <SubHeader goBack={() => history.goBack()} title={list.title} openForm={() => history.push(`${match.url}/new`)} />}
      <ListItemWrapper>
        {items && items.map(item => <ListItem key={item.id} data={ item } />)}
      </ListItemWrapper>
    </>
) : <Alert>{loading ? 'Loading... : error}</Alert>
};

export default List;
```

您可能会注意到，当您刷新页面时，列表的标题将不再显示。只有在`Lists`组件挂载时才会获取列表的信息，因此您需要创建一个新函数，始终获取`List`组件中当前显示的列表的信息：

1.  在`src/Context/ListsContextProvider.js`文件中，您需要扩展`initialValue`，还要添加一个名为`list`的字段：

```jsx
import React from 'react';

export const ListsContext = React.createContext();

const initialValue = {
  lists: [],
+ list: {},
  loading: true,
  erorr: '',
}

const reducer = (value, action) => {
...
```

1.  在`reducer`中，现在还必须检查两个新操作，其中一个是将列表数据添加到上下文中，另一个是添加错误消息：

```jsx
...

const reducer = (value, action) => {
  switch (action.type) {
    case 'GET_LISTS_SUCCESS':
      return {
        ...value,
        lists: action.payload,
        loading: false,
      };
    case 'GET_LISTS_ERROR':
      return {
        ...value,
        lists: [],
        loading: false,
        error: action.payload,
      };
+   case 'GET_LIST_SUCCESS':
+     return {
+       ...value,
+       list: action.payload,
+       loading: false,
+     };
+   case 'GET_LIST_ERROR':
+     return {
+       ...value,
+       list: {},
+       loading: false,
+       error: action.payload,
+     };
    default:
      return value;
  }
};

async function fetchData(dataSource) {
...
```

1.  这些操作将从一个使用特定`id`调用`dataSource`的`async/await`函数中分派。如果成功，将分派`GET_LIST_SUCCESS`操作；否则，将分派`GET_LIST_ERROR`操作。还要将该函数传递给 Provider，以便可以从`List`组件中使用：

```jsx
...
const ListsContextProvider = ({ children }) => {
  const [value, dispatch] = React.useReducer(reducer, initialValue);

  const getListsRequest = async () => {
    const result = await fetchData('https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists');

    if (result.data && result.data.length) {
      dispatch({ type: 'GET_LISTS_SUCCESS', payload: result.data });
    } else {
      dispatch({ type: 'GET_LISTS_ERROR', payload: result.error });
    }
  }

+  const getListRequest = async id => {
+    const result = await fetchData(`https://my-json-server.typicode.com/PacktPublishing/React-Projects/lists/${id}`);

+    if (result.data && result.data.hasOwnProperty('id')) {
+      dispatch({ type: 'GET_LIST_SUCCESS', payload: result.data });
+    } else {
+      dispatch({ type: 'GET_LIST_ERROR', payload: result.error });
+    }
+  }

  return (
-   <ListsContext.Provider value={{ ...value, getListsRequest }}>
+   <ListsContext.Provider value={{ ...value, getListsRequest, getListRequest }}>
        ...
```

1.  并将其传递给`List`组件，通过从`ListsContext` Consumer 中解构它。还要从此 Consumer 中获取列表数据，并将其传递给`List`组件。`lists`属性现在可以从此组件中删除，因为现在列表数据的过滤是由`ListsContextProvider`完成的：

```jsx
<ListsContext.Consumer>
-  {({ lists, loading: listsLoading, error: listsError, getListsRequest }) => (
+  {({ list, lists, loading: listsLoading, error: listsError, getListsRequest, getListRequest }) => (
     <ItemsContext.Consumer>
       {({ items, loading: itemsLoading, error: itemsError, getItemsRequest }) => (
         <Switch>
           <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
           <Route path='/list/:id/new' component={Form} />
-          <Route path='/list/:id' render={props => lists && items && <List lists={lists} items={items} loading={itemsLoading} error={itemsError} getItemsRequest={getItemsRequest} {...props} /> } />
+          <Route path='/list/:id' render={props => list && items && <List list={list} items={items} loading={itemsLoading} error={itemsError} getListRequest={getListRequest} getItemsRequest={getItemsRequest} {...props} /> } />
         </Switch>
       )}
     </ItemsContext.Consumer>
   )}
</ListsContext.Consumer>

...
```

1.  最后，您可以调用`getListRequest`函数，从`List`组件中获取列表数据。只有在此数据尚不可用时，您才希望检索列表信息；因此不再需要对`lists`属性进行过滤：

```jsx
...
- const List = ({ items, loading, error, lists, getItemsRequest, match, history }) => {
+ const List = ({ items, loading, error, list, getListRequest, getItemsRequest, match, history }) => {
-   const list = lists && lists.find(list => list.id === parseInt(match.params.id));

  React.useEffect(() => {
+   if (!list.id) {
+     getListRequest(match.params.id);
+   }

    if (!items.length > 0) {
      getItemsRequest(match.params.id);
    }
- }, [items, match.params.id, getItemsRequest]);
+ }, [items, list, match.params.id, getItemsRequest, getListRequest]);

  return !loading && !error ? (
    ...
```

现在，您的应用程序中的所有数据都是使用 Providers 加载的，这意味着它现在与视图分离。此外，`withDataFetching` HOC 已完全删除，使您的应用程序结构更易读。

不仅可以使用此模式的上下文 API 使数据可用于许多组件，还可以改变数据。如何改变这些数据将在下一节中展示。

# 在 Provider 中改变数据

不仅可以使用这种 Flux 模式来检索数据，还可以用它来更新数据。模式仍然是一样的：您派发一个动作，触发对服务器的请求，根据结果，reducer 将使用这个结果改变数据。根据是否成功，您可以显示成功消息或错误消息。

该代码已经有一个用于向列表添加新项目的表单，但目前还没有工作。让我们通过更新`items`的 Provider 来创建添加项目的机制：

1.  第一步是创建一个新的函数，可以处理`POST`请求，因为这个函数在处理`fetch`请求时还应该设置方法和主体。您可以在`src/Context/ItemsContextProvider.js`文件中创建这个函数：

```jsx
...
async function fetchData(dataSource) {
  try {
    const data = await fetch(dataSource);
    const dataJSON = await data.json();

    if (dataJSON) {
      return await ({ data: dataJSON, error: false });
    }
  } catch(error) {
      return ({ data: false, error: error.message });
  }
};

async function postData(dataSource, content) {
 try {
 const data = await fetch(dataSource, {
 method: 'POST',
 body: JSON.stringify(content),
 });
 const dataJSON = await data.json();

 if (dataJSON) {
 return await ({ data: dataJSON, error: false });
 }
 } catch(error) {
 return ({ data: false, error: error.message });
 }
};

const ItemsContextProvider = ({ children }) => {
    ...
```

1.  这个函数不仅需要`dataSource`，还需要将要发布到这个源的信息。就像检索项目一样，在`reducer`的`switch`语句中可以添加一个情况。这一次，它将寻找一个名为`ADD_ITEM_REQUEST`的动作，它的载荷由`dataSource`和应该添加到值中的`content`组成。这些动作会改变`loading`和/或`error`的值，并在返回时也会传播实际的当前值。如果不这样做，所有关于列表的已有信息都将被清除：

```jsx
...
const reducer = (value, action) => {
  switch (action.type) {
    case 'GET_ITEMS_SUCCESS':
      return {
        ...value,
        items: action.payload,
        loading: false,
      };
    case 'GET_ITEMS_ERROR':
      return {
        ...value,
        items: [],
        loading: action.payload,
      };
+   case 'ADD_ITEM_SUCCESS':
+     return {
+       ...value,
+       items: [
+         ...value.items,
+         action.payload,
+       ],
+       loading: false,
+     };
+   case 'ADD_ITEM_ERROR':
+     return {
+       ...value,
+       loading: false,
+       error: 'Something went wrong...',
+     };
    default:
      return value;
  }
};

async function fetchData(dataSource) {
...

```

来自 My JSON Server 的模拟 API 一旦添加、更新或删除请求，数据就不会持久保存。但是，您可以通过在浏览器的开发者工具的 Network 选项卡中检查请求来查看请求是否成功。这就是为什么输入内容分布在`items`的值上，所以这些数据可以从 Consumer 中获取。

1.  还要创建一个处理`POST`请求的`async/await`函数。如果这个请求成功，返回的数据将有一个名为`id`的字段。因此，在这种情况下，可以派发`ADD_ITEM_SUCCESS`动作。否则，会派发一个`ADD_ITEM_ERROR`动作。这些动作将从`reducer`改变这个 Provider 的值：

```jsx
...
const ItemsContextProvider = ({ children }) => {
  const [value, dispatch] = React.useReducer(reducer, initialValue);

  const getItemsRequest = async (id) => {
    const result = await fetchData(`
      https://my-json-server.typicode.com/PacktPublishing/React-Projects/items/${id}/items
    `);

    if (result.data && result.data.length) {
      dispatch({ type: 'GET_ITEMS_SUCCESS', payload: result.data });
    } else {
      dispatch({ type: 'GET_ITEMS_ERROR', payload: result.error });
    }
  }

+  const addItemRequest = async (content) => {
+    const result = await postData('https://my-json-server.typicode.com/PacktPublishing/React-Projects/items', content);

+    if (result.data && result.data.hasOwnProperty('id')) {
+      dispatch({ type: 'ADD_ITEM_SUCCESS', payload: content });
+    } else {
+      dispatch({ type: 'ADD_ITEM_ERROR' });
+    }
+  }

  return (
-   <ItemsContext.Provider value={{ ...value, getItemsRequest }}>
+   <ItemsContext.Provider value={{ ...value, getItemsRequest, addItemRequest }}>
    ...
```

1.  就像检索列表一样，用于添加列表的`actionDispatch`函数可以包装在一个辅助函数中。这个函数将在稍后从表单返回的内容。还要将这个函数传递给 Provider，以便它可以在任何使用这个 Provider 的组件中使用：

```jsx
...
  const getListsRequest = () => {
    actionDispatch({ 
      type: 'GET_LISTS_REQUEST', 
      payload: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items',
    });
  };

+  const addListRequest = (content) => {
+    actionDispatch({
+      type: 'ADD_LIST_REQUEST',
+      payload: { 
+        dataSource: 'https://my-json-server.typicode.com/PacktPublishing/React-Projects/items', 
+        content, 
+       } 
+     });
+  };

  return (
-    <ListsContext.Provider value={{ ...value, getListsRequest }}>
+    <ListsContext.Provider value={{ ...value, getListsRequest, addListRequest }}>
      {children}
    </ListsContext.Provider>
  )
};

export default ListsContextProvider;
```

1.  由于现在可以从提供者中使用添加列表的函数，你可以通过使用`Route`的`RenderProps`将其传递给`Form`组件。这可以在`src/containers/App.js`文件中完成。确保不要忘记发送`match`和`history`属性，因为这些被`Form`组件使用：

```jsx
...
<ListsContext.Consumer>
  {({ list, lists, loading: listsLoading, error: listsError, getListsRequest, getListRequest }) => (
    <ItemsContext.Consumer>
-     {({ items, loading: itemsLoading, error: itemsError, getItemsRequest }) => (
+     {({ items, loading: itemsLoading, error: itemsError, getItemsRequest, addItemRequest }) => (
        <Switch>
          <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
-         <Route path='/list/:id/new' component={Form} />
+         <Route path='/list/:id/new' render={props => <Form addItemRequest={addItemRequest} {...props} />} />
          <Route path='/list/:id' render={props => list && items && <List list={list} items={items} loading={itemsLoading} error={itemsError} getListRequest={getListRequest} getItemsRequest={getItemsRequest} {...props} /> } />
        </Switch>
      )}
    </ItemsContext.Consumer>
  )}
</ListsContext.Consumer>

...
```

`Form`组件现在可以使用`addListRequest`函数，该函数将触发`POST`请求的动作，将项目添加到`dataSource`中。当用户提交表单时，需要触发这个函数。

然而，表单中输入字段的值需要首先确定。因此，输入字段需要成为受控组件，这意味着它们的值由封装值的本地状态控制：

1.  为此，你可以使用`useState` Hook，并为你想要创建的每个`state`值调用它。这个 Hook 将返回这个`state`值的当前值和一个更新这个值的函数，必须添加在`src/containers/Form.js`中：

```jsx
...
- const Form = ({ match, history }) => (
+ const Form = ({ addItemRequest, match, history }) => {  
+  const [title, setTitle] = React.useState('');
+  const [quantity, setQuantity] = React.useState('');
+  const [price, setPrice] = React.useState('');

+  return (
  <>
    {history && <SubHeader goBack={() => history.goBack()} title='Add Item' />}
    <FormWrapper>
      <form>
        <FormItem id='title' label='Title' placeholder='Insert title' />
        <FormItem id='quantity' label='Quantity' type='number' placeholder='0' />
        <FormItem id='price' label='Price' type='number' placeholder='0.00' />
        <SubmitButton>Add Item</SubmitButton>
      </form>
    </FormWrapper>
  </>
);
+ }

export default Form;
```

1.  本地状态值和触发本地`state`值更新的函数必须作为`FormItem`组件的属性进行设置：

```jsx
...

  return (
    <>
      {history && <SubHeader goBack={() => history.goBack()} title='Add item' /> }
      <FormWrapper>
        <form>
-         <FormItem id='title' label='Title' placeholder='Insert title' />
+         <FormItem id='title' label='Title' placeholder='Insert title' value={title} handleOnChange={setTitle} />
-         <FormItem id='quantity' label='Quantity' type='number' placeholder='0' />
+         <FormItem id='quantity' label='Quantity' type='number' placeholder='0' value={quantity} handleOnChange={setQuantity} />
-         <FormItem id='price' label='Price' type='number' placeholder='0.00' />
+         <FormItem id='price' label='Price' type='number' placeholder='0.00' value={price} handleOnChange={setPrice} />
          <SubmitButton>Add Item</SubmitButton>
        </form>
      </FormWrapper>
    </>
  )
};

export default Form;

```

1.  `FormItem`组件在`src/components/FormItem.js`文件中可以接受这些属性，并使输入字段调用`handleOnChange`函数。元素的当前`target`值必须作为此函数的参数使用：

```jsx
...
- const FormItem = ({ id, label, type = 'text', placeholder = '' }) => (
+ const FormItem = ({ id, label, type = 'text', placeholder = '', value, handleOnChange }) => (
  <FormItemWrapper>
    <Label htmlFor={id}>{label}</Label>
-    <Input type={type} name={id} id={id} placeholder={placeholder} />
+    <Input type={type} name={id} id={id} placeholder={placeholder} value={value} onChange={e => handleOnChange(e.target.value)} />
  </FormItemWrapper>
);

export default FormItem;
```

1.  现在你需要做的最后一件事是添加一个函数，当点击提交按钮时将被调度。这个函数接受本地状态的`value`，添加关于列表的信息和一个随机生成的`id`，然后使用这些来调用`addItemRequest`函数。在调用了这个函数之后，将调用`history`属性中的`goBack`函数：

```jsx
...
const Form = ({ addItemRequest, match, history }) => {
  ...

+ const handleOnSubmit = e => {
+    e.preventDefault();
+    addItemRequest({
+      title, 
+      quantity,
+      price,
+      id: Math.floor(Math.random() * 100), 
+      listId: parseInt(match.params.id) 
+    });
+    history.goBack();
+  };

  return (
    <>
      {history && <SubHeader goBack={() => history.goBack()} title={title} />}
      <FormWrapper>
-        <form>
+        <form onSubmit={handleOnSubmit}>

...
```

现在当你提交表单时，将发送一个`POST`请求到模拟服务器。你将被发送回到之前的页面，你可以在那里看到结果。如果成功，将会触发`GET_LIST_SUCCESS`动作，并且你插入的项目将被添加到列表中。

到目前为止，上下文中的信息仅通过使用提供者分开使用，但这也可以合并为一个全局上下文，如下一节所示。

# 创建全局上下文

如果你看一下你的`App`组件中路由的当前结构，你可以想象如果你在应用程序中添加更多的 Providers 和 Consumers，这将变得混乱。状态管理包如 Redux 倾向于有一个全局状态，其中存储了应用程序的所有数据。当使用 Context 时，可以创建一个全局 Context，可以使用`useContext` Hook 访问。这个 Hook 充当 Consumer，可以从传递给它的 Context 的 Provider 中检索值。让我们重构当前的应用程序以拥有一个全局 Context：

1.  首先，在`src/Context`目录中创建一个名为`GlobalContext.js`的文件。这个文件将导入`ListsContextProvider`和`ItemsContextProvider`，将它们嵌套，并让它们包装任何作为`children`属性传递给它的组件：

```jsx
import React from 'react';
import ListsContextProvider from './ListsContextProvider';
import ItemsContextProvider from './ItemsContextProvider';

const GlobalContext = ({ children }) => {
  return (
    <ListsContextProvider>
      <ItemsContextProvider>
        {children}
      </ItemsContextProvider>
    </ListsContextProvider>
  );
};

export default GlobalContext;
```

1.  在`src/containers/App.js`文件中，你现在可以导入`GlobalContext`文件，而不是导入列表和项目的 Providers：

```jsx
import React from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { Route, Switch } from 'react-router-dom';
- import ListsContextProvider, { ListsContext } from '../Context/ListsContextProvider';
- import ItemsContextProvider, { ItemsContext } from '../Context/ItemsContextProvider';
+ import GlobalContext from '../Context/GlobalContext';
...
```

1.  你可以用`GlobalContext`替换`ListsContextProvider`和`ItemsContextProvider`。如果你仍然导入它们，Consumer 仍然可以从`ListsContext`和`ItemsContext`中检索数据：

```jsx
const App = () => (
  <>
    <GlobalStyle />
      <AppWrapper>
      <Header />
+      <GlobalContext>
-      <ListsContextProvider>
-        <ItemsContextProvider>
          <ListsContext.Consumer>
            {({ list, lists, loading: listsLoading, error: listsErorr, getListsRequest, getListRequest }) => (
              <ItemsContext.Consumer>
                {({ items, loading: itemsLoading, error: itemsError, getItemsRequest, addItemRequest }) => (
                  <Switch>
                    <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
                    <Route path='/list/:id/new' render={props => <Form addItemRequest={addItemRequest} {...props} />} />
                    <Route path='/list/:id' render={props => list && items && <List list={list} items={items} loading={itemsLoading} error={itemsError} getListRequest={getListRequest} getItemsRequest={getItemsRequest} {...props} /> } />
                  </Switch>
                )}
              </ItemsContext.Consumer>
            )}
          </ListsContext.Consumer>
-       </ItemsContextProvider>
-     </ListsContextProvider>
+     </GlobalContext>
    </AppWrapper>
  </>
);

export default App;
```

1.  接下来，你可以删除路由中的 Consumers 和`RenderProps`模式。上下文中的值将不再从两个 Consumers 中传递，而是将使用`useContext` Hook 在每个路由中检索：

```jsx
...
        <GlobalContext>
-         <ListsContext.Consumer>
-           {({ list, lists, loading: listsLoading, error: listsError, getListsRequest, getListRequest }) => (
-             <ItemsContext.Consumer>
-               {({ items, loading: itemsLoading, error: itemsError, getItemsRequest, addItemRequest }) => (
                  <Switch>
-                   <Route exact path='/' render={props => lists && <Lists lists={lists} loading={listsLoading} error={listsError} getListsRequest={getListsRequest} {...props} />} />
+                   <Route exact path='/' component={Lists} />
-                   <Route path='/list/:id/new' render={props => <Form addItemRequest={addItemRequest} {...props} />} />
+                   <Route path='/list/:id/new' component={Form} />
-                   <Route path='/list/:id' render={props => list && items && <List list={list} items={items} loading={itemsLoading} error={itemsError} getListRequest={getListRequest} getItemsRequest={getItemsRequest} {...props} /> } />
+                   <Route path='/list/:id' component={List} />
                  </Switch>
-               )}
-             </ItemsContext.Consumer>
-           )}
-        </ListsContext.Consumer>
       </GlobalContext>
...
```

1.  在每个由`Route`渲染的组件中，你想要使用的上下文都应该被导入。然后，`useContext` Hook 可以从这个上下文中检索值。你可以从`src/containers/Lists.js`组件开始添加这个 Hook：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
+ import { ListsContext } from '../Context/ListsContextProvider';
import SubHeader from '../components/Header/SubHeader';

...

- const Lists = ({lists, loading, error, getListsRequest, match, history}) => {
+ const Lists = ({ match, history }) => {
+  const { lists, loading, error, getListsRequest } =    React.useContext(ListsContext);
  React.useEffect(() => {
    if (!lists.length) {
      getListsRequest();
    }
  }, [lists, getListsRequest]);

  return !loading && !error ? (
    <>
      {history && <SubHeader title='Your Lists' />}
      <ListWrapper>
        {lists && lists.map((list) => (
          <ListLink key={list.id} to={`list/${list.id}`}>
            <Title>{list.title}</Title>
          </ListLink>
        ))}
      </ListWrapper>
    </>
  ) : <Alert>{loading ? 'Loading...' : error}</Alert>;
}
export default Lists;
```

1.  正如你所看到的，`useContext`只需要将要使用的上下文作为参数。要在`List`组件中实现这一点，你需要在`src/containers/List.js`文件中导入`ListsContext`和`ItemsContext`：

```jsx
import React from 'react';
import styled from 'styled-components';
import { ListsContext } from '../Context/ListsContextProvider';
import { ItemsContext } from '../Context/ItemsContextProvider';
import SubHeader from '../components/Header/SubHeader';
import ListItem from '../components/ListItem/ListItem';

...

- const List = ({ items, loading, error, list, getListRequest, getItemsRequest, match, history }) => {
+ const List = ({ match, history }) => {
+  const { list, getListRequest } = React.useContext(ListsContext);
+  const { loading, error, items, getItemsRequest } = React.useContext(ItemsContext);

  React.useEffect(() => {    ...
```

1.  对于`Form`组件在`src/containers/Form.js`文件中也是一样，你只使用`ItemsContext`：

```jsx
import React from 'react';
import styled from 'styled-components';
+ import { ItemsContext } from '../Context/ItemsContextProvider';
import SubHeader from '../components/Header/SubHeader';
import FormItem from '../components/FormItem/FormItem';
import Button from '../components/Button/Button';

...

- const Form = ({ addItemRequest, match, history }) => {
+ const Form = ({ match, history }) => {
+  const { addItemRequest } = React.useContext(ItemsContext);

...
```

现在你可以看到你的应用程序有一个更清晰的结构，同时数据仍然是通过 Providers 检索的。

# 总结

在这一章中，您已经创建了一个购物清单应用程序，该应用程序使用上下文 API 和 Hooks 来传递和检索数据，而不是使用 HOC。上下文用于存储数据，Hooks 用于检索和改变数据。使用上下文 API，您可以使用`useReducer` Hook 创建更高级的状态管理场景。此外，您已经重新创建了一个情况，其中所有数据都存储在全局，并且可以通过创建共享上下文从任何组件访问。

在下一章中，上下文 API 也将被使用，该章节将向您展示如何使用诸如 Jest 和 Enzyme 等库构建具有自动化测试的酒店评论应用程序。它将向您介绍使用 React 创建 UI 组件的多种测试方法，并向您展示如何使用上下文 API 测试应用程序中的状态管理。

# 进一步阅读

消耗多个上下文对象：[`reactjs.org/docs/Context.html#consuming-multiple-Contexts`](https://reactjs.org/docs/Context.html#consuming-multiple-Contexts)


# 第六章：使用 Jest 和 Enzyme 构建探索 TDD 的应用程序

为了保持应用的可维护性，最好为项目设置测试。一些开发人员讨厌编写测试，因此试图避免编写测试，而其他开发人员则喜欢将测试作为其开发过程的核心，实施**测试驱动开发**（**TDD**）策略。关于测试应用程序以及如何进行测试有很多不同的观点。幸运的是，在使用 React 构建应用程序时，许多出色的库可以帮助您进行测试。

在本章中，您将使用两个库来对 React 应用程序进行单元测试。第一个是 Jest，由 Facebook 自己维护，并随 Create React App 一起发布。另一个工具叫做 Enzyme，它比 Jest 具有更多的功能，并且可以用来测试组件内的整个生命周期。它们一起非常适合测试大多数 React 应用程序，如果您想要测试函数或组件在给定特定输入时是否表现如预期。

本章将涵盖以下主题：

+   使用 Jest 进行单元测试

+   为测试渲染 React 组件

+   使用 Enzyme 进行测试

# 项目概述

在本章中，我们将创建一个酒店评论应用程序，并使用 Jest 和 Enzyme 进行单元和集成测试。该应用程序已经预先构建，并使用了我们在前几章中看到的相同模式。

构建时间为 2 小时。

# 入门

本章的应用程序是基于初始版本构建的，可以在[`github.com/PacktPublishing/React-Projects/tree/ch6-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch6-initial)找到。本章的完整代码可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch6`](https://github.com/PacktPublishing/React-Projects/tree/ch6)。

从 GitHub 下载初始项目，并进入该项目的根目录，然后运行`npm install`命令。由于该项目是基于 Create React App 构建的，运行此命令将安装`react`、`react-dom`和`react-scripts`。此外，还将安装`styled-components`和`react-router-dom`，以便它们可以处理应用程序的样式和路由。安装过程完成后，可以执行`npm start`命令来运行应用程序，然后在浏览器中访问`http://localhost:3000`来查看项目。就像你在之前章节中构建的应用程序一样，这个应用程序也是一个 PWA。

初始应用程序包括一个简单的标题和酒店列表。这些酒店有标题和缩略图等元信息。该页面将如下所示。如果你点击列表中的任何酒店，将会打开一个新页面，显示该酒店的评论列表。通过点击页面左上角的按钮，你可以返回到上一个页面；通过点击右上角的按钮，将打开一个包含表单的页面，你可以在其中添加评论。如果你添加了新的评论，这些数据将被存储在全局上下文中，并发送到一个模拟 API 服务器。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/c25bf83e-16c2-42a4-a572-8dffff5127ea.png)

如果你查看项目的结构，你会发现它使用了与我们之前创建的项目相同的结构。这个应用程序的入口点是一个名为`src/index.js`的文件，它渲染了一个名为`App`的组件。在这个`App`组件中，所有的路由都被声明并包装在一个路由组件中。此外，这里还声明了持有全局上下文和提供者的组件。与之前创建的应用程序相比，这个应用程序中没有使用容器组件模式。相反，所有的数据获取都是通过上下文组件完成的。生命周期是使用 Hooks 来访问的：

```jsx
hotel-review
|-- node_modules
|-- public
    |-- assets
        |-- beachfront-hotel.jpg
        |-- forest-apartments.jpg
        |-- favicon.ico
        |-- index.html
        |-- manifest.json
|-- src
    |-- components
        |-- Button
            |-- Button.js
        |-- Detail
            |-- Detail.js
            |-- ReviewItem.js
        |-- Form
            |-- Form.js
            |-- FormItem.js
        |-- Header
            |-- Header.js
            |-- SubHeader.js
        |-- Hotels
            |-- Hotels.js
            |-- HotelItem.js
        |-- App.js
    |-- Context
        |-- GlobalContext.js
        |-- HotelsContextProvider.js
        |-- ReviewsContextProvider.js
    |-- api.js
    |-- index.js
    |-- serviceWorker.js
.gitignore
package.json
```

在上述项目结构中，你可以看到`public/assets`目录中还有两个文件，这些文件是酒店的缩略图。为了在渲染的应用程序中使用它们，你可以将它们放在`public`目录中。此外，在`src`中还有一个名为`api.js`的文件，它导出了函数，以便可以向 API 发送`GET`和`POST`请求。

# 酒店评论应用程序

在本节中，我们将为在 Create React App 中创建的酒店评论应用程序添加单元测试和集成测试。这个应用程序允许你向酒店列表中添加评论，并从全局上下文中控制这些数据。Jest 和 Enzyme 将用于在没有 DOM 的情况下渲染 React 组件，并对这些组件进行测试断言。

# 使用 Jest 进行单元测试

单元测试是应用程序的重要部分，因为你希望知道你的函数和组件在进行代码更改时是否按预期行为。为此，你将使用 Jest，这是一个由 Facebook 创建的用于 JavaScript 应用程序的开源测试包。使用 Jest，你可以测试断言，例如，如果函数的输出与你预期的值匹配。

要开始使用 Jest，你无需安装任何东西；它是 Create React App 的一部分。如果你查看`package.json`文件，你会看到已经有一个用于运行测试的脚本。

让我们看看如果你从终端执行以下命令会发生什么：

```jsx
npm run test 
```

这将返回一条消息，说`No tests found related to files changed since last commit.`，这意味着 Jest 正在观察模式下运行，并且只对已更改的文件运行测试。通过按下`a`键，你可以运行所有测试，即使你没有修改任何文件。如果按下这个键，将显示以下消息：

```jsx
No tests found
 26 files checked.
 testMatch: /hotel-review/src/**/__tests__/**/*.{js,jsx,ts,tsx},/hotel-review/src/**/?(*.)(spec|test).{js,jsx,ts,tsx} - 0 matches
 testPathIgnorePatterns: /node_modules/ - 26 matches
Pattern: - 0 matches
```

这条消息说明已经调查了`26`个文件，但没有找到测试。它还说明正在寻找项目中名为`__tests__`的目录中的 JavaScript 或 JSX 文件，以及具有`spec`或`test`后缀的文件。`node_modules`目录，即所有`npm`包安装的地方，将被忽略。从这条消息中，你可能已经注意到 Jest 会自动检测包含测试的文件。

可以使用 Jest 来创建这些测试，这将在本节的第一部分进行演示。

# 创建一个单元测试

由于 Jest 可以以多种方式检测哪个文件包含测试，让我们选择每个组件都有一个单独的测试文件的结构。这个测试文件将与包含组件的文件同名，后缀为`.test`。如果我们选择`SubHeader`组件，我们可以在`src/components/Header`目录中创建一个名为`SubHeader.test.js`的新文件。将以下代码添加到这个文件中：

```jsx
describe('the <SubHeader /> component', () => {
  it('should render', () => {

  });
});
```

这里使用了 Jest 的两个全局函数：

+   `describe`：用于定义一组相关的测试

+   `it`：用于定义测试

在测试的定义中，您可以添加假设，比如`toEqual`或`toBe`，分别检查值是否完全等于某些内容，或者只是类型匹配。假设可以在`it`函数的回调中添加：

```jsx
describe('the <SubHeader /> component', () => {
  it('should render', () => {
+   expect(1+2).toBe(3);
  });
});
```

如果您的终端仍在运行测试脚本，您将看到 Jest 已检测到您的测试。测试成功，因为`1+2`确实是`3`。让我们继续并将假设更改为以下内容：

```jsx
describe('the <SubHeader /> component', () => {
  it('should render', () => {
-    expect(1+2).toBe(3);
+    expect(1+2).toBe('3');
  });
});
```

现在，测试将失败，因为第二个假设不匹配。虽然`1+2`仍然等于`3`，但假设返回了一个值为`3`的字符串类型，而实际上返回的是一个数字类型。这在编写代码时可以帮助您，因为您可以确保应用程序不会更改其值的类型。

然而，这个假设实际上没有用，因为它并没有测试您的组件。要测试您的组件，您需要渲染它。在本节的下一部分将处理渲染组件以便测试它们。

# 渲染 React 组件进行测试

Jest 基于 Node.js，这意味着它无法使用 DOM 来渲染您的组件并测试其功能。因此，您需要向项目添加一个 React 核心软件包，它可以帮助您在没有 DOM 的情况下渲染组件。让我们在这里看一下：

1.  从您的终端执行以下命令，它将在您的项目中安装`react-test-renderer`。它可以作为 devDependency 安装，因为您不需要在应用程序的构建版本上运行测试：

```jsx
npm install react-test-renderer --save-dev
```

1.  安装了`react-test-renderer`后，您现在可以将此软件包导入到`src/components/Header/SubHeader.test.js`文件中。此软件包返回一个名为`ShallowRenderer`的方法，让您可以渲染组件。使用浅渲染，您只在其第一级渲染组件，从而排除任何可能的子组件。您还需要导入 React 和您想要测试的实际组件，因为这些是`react-test-renderer`使用的：

```jsx
+ import React from 'react';
+ import ShallowRenderer from 'react-test-renderer/shallow';
+ import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
 ....
```

1.  在您的测试中，您现在可以使用`ShallowRenderer`来渲染组件，并获得此组件的输出。使用 Jest 的`toMatchSnapshot`假设，您可以测试组件的结构。`ShallowRenderer`将渲染组件，`toMatchSnapshot`将从此渲染创建快照，并在每次运行此测试时将其与实际组件进行比较：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
  it('should render', () => {
-   expect(1+2).toBe('3');
+    const renderer = new ShallowRenderer();
+    renderer.render(<SubHeader />);
+    const component = renderer.getRenderOutput();

+    expect(component).toMatchSnapshot();
  });
});
```

1.  在`src/components/Header`目录中，Jest 现在创建了一个名为`__snapshots__`的新目录。在这个目录中有一个名为`SubHeader.test.js.snap`的文件，其中包含了快照。如果您打开这个文件，您会看到`SubHeader`组件的渲染版本存储在这里：

```jsx
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`the <SubHeader /> component should render 1`] = `
<ForwardRef>
  <ForwardRef />
</ForwardRef>
`;
```

使用`styled-components`创建的组件无法被`react-test-renderer`渲染，因为它们是由`styled-components`导出的方式。如果您查看`SubHeader`组件的代码，您会看到`ForwardRef`组件代表`SubHeaderWrapper`和`Title`。在本章的后面，我们将使用 Enzyme 进行测试，它可以更好地处理这种测试场景。

1.  由于未向`SubHeader`组件传递任何 props，因此`react-test-renderer`不会呈现任何实际值。您可以通过向`SubHeader`组件传递`title` prop 来检查快照的工作方式。为此，创建一个新的测试场景，应该呈现带有标题的`SubHeader`。此外，将`renderer`常量的创建移动到`describe`函数中，以便它可以被所有的测试场景使用：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
+  const renderer = new ShallowRenderer();

  it('should render', () => {
-   const renderer = new ShallowRenderer(); 
    renderer.render(<SubHeader />);
    const component = renderer.getRenderOutput();

    expect(component).toMatchSnapshot();
  });

+  it('should render with a dynamic title', () => {
+    renderer.render(<SubHeader title='Test Application' />);
+    const component = renderer.getRenderOutput();

+    expect(component).toMatchSnapshot();
+  }); });
```

1.  下次运行测试时，将会在`src/components/Header/__snapshots__/SubHeader.test.js.snap`文件中添加一个新的快照。这个快照为`title` prop 呈现了一个值。如果您在测试文件中更改了`SubHeader`组件显示的`title` prop 的值，渲染的组件将不再与快照匹配。您可以通过更改测试场景中`title` prop 的值来尝试这一点：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
  const renderer = new ShallowRenderer();

  ...

  it('should render with a dynamic title', () => {
-   renderer.render(<SubHeader title='Test Application' />);
+   renderer.render(<SubHeader title='Test Application Test' />);
    const component = renderer.getRenderOutput();

    expect(component).toMatchSnapshot();
  });
});
```

Jest 将在终端中返回以下消息，其中指定了与快照相比发生了哪些变化的行。在这种情况下，显示的标题不再是`Test Application`，而是`Test Application Test`，这与快照中的标题不匹配：

```jsx
 • the <SubHeader /> component › should render

 expect(value).toMatchSnapshot()

 Received value does not match stored snapshot "the <SubHeader /> component should render 1".

 - Snapshot
 + Received

 <ForwardRef>
 <ForwardRef>
 - Test Application
 + Test Application Title
 </ForwardRef>
 </ForwardRef>
...
```

通过按下`u`键，您可以更新快照以处理这个新的测试场景。这是测试组件结构的一种简单方法，可以看到标题是否已经被渲染。通过前面的测试，最初创建的快照仍然与第一个测试的渲染组件匹配。此外，还为第二个测试创建了另一个快照，其中向`SubHeader`组件添加了`title` prop。

1.  你可以对传递给`SubHeader`组件的其他属性做同样的操作，如果你传递或不传递某些属性，它会以不同的方式呈现。除了`title`之外，这个组件还接受`goBack`和`openForm`作为属性，其中`openForm`属性的默认值为 false。

就像我们为`title`属性所做的那样，我们也可以为另外两个属性创建测试场景。当`goBack`有值时，会创建一个按钮，让我们返回到上一页，而当`openForm`有值时，会创建一个按钮，让我们可以继续到下一页，这样我们就可以添加新的评论。你需要将这两个新的测试场景添加到`src/components/Header/SubHeader.test.js`文件中：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
  const renderer = new ShallowRenderer();

  ...

+  it('should render with a goback button', () => {
+   renderer.render(<SubHeader goBack={() => {}} />);
+    const component = renderer.getRenderOutput();
+
+    expect(component).toMatchSnapshot();
+  });

+  it('should render with a form button', () => {
+   renderer.render(<SubHeader openForm={() => {}} />);
+    const result = renderer.getRenderOutput();
+
+    expect(component).toMatchSnapshot();
+  });
});
```

你现在为`SubHeader`组件创建了另外两个快照，总共有四个快照。Jest 还会显示你的测试覆盖了多少行代码。你的测试覆盖率越高，就越有理由认为你的代码是稳定的。你可以通过执行带有`--coverage`标志的`test`脚本命令来检查你的代码的测试覆盖率，或者在终端中使用以下命令：

```jsx
npm run test --coverage
```

这个命令将运行你的测试并生成一个报告，其中包含有关每个文件的代码测试覆盖信息。在为`SubHeader`添加测试之后，这个报告将如下所示：

```jsx
 PASS src/components/Header/SubHeader.test.js
----------------------------|----------|----------|----------|----------|-------------------|
File | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s |
----------------------------|----------|----------|----------|----------|-------------------|
All files | 5 | 6.74 | 4.26 | 5.21 | |
 src | 0 | 0 | 0 | 0 | |
 api.js | 0 | 0 | 0 | 0 |... 20,22,23,26,30 |
 index.js | 0 | 100 | 100 | 0 | 1,2,3,4,5,17 |
 serviceWorker.js | 0 | 0 | 0 | 0 |... 23,130,131,132 |
 src/components | 0 | 100 | 0 | 0 | |
 App.js | 0 | 100 | 0 | 0 |... ,8,10,22,26,27 |
 src/components/Button | 0 | 100 | 0 | 0 | |
 Button.js | 0 | 100 | 0 | 0 | 20 |
 src/components/Detail | 0 | 0 | 0 | 0 | |
 Detail.js | 0 | 0 | 0 | 0 |... 26,27,31,33,35 |
 ReviewItem.js | 0 | 100 | 0 | 0 |... 15,21,26,30,31 |
 src/components/Form | 0 | 0 | 0 | 0 | |
 Form.js | 0 | 0 | 0 | 0 |... 29,30,31,34,36 |
 FormInput.js | 0 | 0 | 0 | 0 |... 17,26,35,40,41 |
 src/components/Header | 100 | 100 | 100 | 100 | |
 Header.js | 100 | 100 | 100 | 100 | |
 SubHeader.js | 100 | 100 | 100 | 100 | |
...
```

测试覆盖只告诉我们关于已经测试过的代码行和函数的信息，而不是它们的实际实现。拥有 100%的测试覆盖并不意味着你的代码中没有任何错误，因为总会有边缘情况。此外，达到 100%的测试覆盖意味着你可能会花更多的时间编写测试而不是实际的代码。通常，80%以上的测试覆盖被认为是良好的实践。

正如你所看到的，组件的测试覆盖率为 100%，这意味着你的测试覆盖了所有的代码行。然而，使用快照测试的这种方法会创建大量新文件和代码行。我们将在本节的下一部分中看看我们可以用其他方法来测试我们的组件。

# 使用断言测试组件

理论上，快照测试并不一定是坏的实践；然而，随着时间的推移，你的文件可能会变得非常庞大。此外，由于你没有明确告诉 Jest 你想测试组件的哪一部分，你可能需要定期更新你的代码。

幸运的是，使用快照并不是我们测试组件是否渲染正确属性的唯一方法。相反，您还可以直接比较组件渲染的属性的值并进行断言。使用断言进行测试的重要优势是，您可以进行大量测试，而无需深入了解正在测试的组件的逻辑。

例如，您可以查看正在渲染的子元素的样子。让我们看看如何做到这一点：

1.  首先，让我们为 `Button` 组件创建一个快照测试，以比较测试覆盖率的影响。创建一个名为 `src/components/Button/Button.test.js` 的新文件。在这个文件中，您需要插入一个创建快照的测试：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import Button from './Button';

describe('the <Button /> component', () => {
  const renderer = new ShallowRenderer();

  it('should render', () => {
    const children = 'This is a button';
    renderer.render(<Button>{children</Button>);
    const result = renderer.getRenderOutput();

    expect(result).toMatchSnapshot();
  });
});
```

1.  如果您使用 `--coverage` 标志运行测试，将创建一个新的测试覆盖报告：

```jsx
npm run test --coverage
```

此报告生成以下报告，显示了 `Button` 组件的覆盖率，为 100％：

```jsx
 PASS src/components/Header/SubHeader.test.js
 PASS src/components/Button/Button.test.js
 › 1 snapshot written.
 PASS src/components/Header/Header.test.js
----------------------------|----------|----------|----------|----------|-------------------|
File | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s |
----------------------------|----------|----------|----------|----------|-------------------|
All files | 5.45 | 6.74 | 6.38 | 5.69 | |
 src | 0 | 0 | 0 | 0 | |
 api.js | 0 | 0 | 0 | 0 |... 20,22,23,26,30 |
 index.js | 0 | 100 | 100 | 0 | 1,2,3,4,5,17 |
 serviceWorker.js | 0 | 0 | 0 | 0 |... 23,130,131,132 |
 src/components | 0 | 100 | 0 | 0 | |
 App.js | 0 | 100 | 0 | 0 |... ,8,10,22,26,27 |
 src/components/Button | 100 | 100 | 100 | 100 | |
 Button.js | 100 | 100 | 100 | 100 | |
```

如果您打开 `src/components/Button/__snapshots__/Button.test.js.snap` 文件中 `Button` 组件的快照，您将看到按钮内部渲染的唯一内容（由 `ForwardRef` 表示）是 `children` 属性：

```jsx
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`the <Button /> component should render 1`] = `
<ForwardRef>
  This is a button
</ForwardRef>
`;
```

1.  尽管测试覆盖率达到了 100％，但还有其他方法可以测试正确的子元素是否已被渲染。为此，我们可以创建一个新的测试，也使用 `ShallowRenderer` 并尝试使用子元素渲染 `Button` 组件。这个测试断言渲染的 `children` 属性是否等于 `Button` 渲染的实际 `children` 属性。您可以删除快照测试，因为您只想通过断言测试子元素：

```jsx
import React from 'react';
import ShallowRenderer from 'react-test-renderer/shallow';
import Button from './Button';

describe('the <Button /> component', () => {
  const renderer = new ShallowRenderer();

-  it('should render', () => {
-    const children = 'This is a button';
-    renderer.render(<Button>{children}</Button>);
-    const result = renderer.getRenderOutput();

-    expect(result).toMatchSnapshot();
-  })

+  it('should render the correct children', () => {
+    const children = 'This is a button';
+    renderer.render(<Button>{children}</Button>);
+    const component = renderer.getRenderOutput();

+    expect(component.props.children).toEqual(children);
+  });
});
```

1.  从您的终端运行 `npm run test --coverage` 再次检查这种测试方法对测试覆盖率的影响：

```jsx
 PASS src/components/Header/Header.test.js
 PASS src/components/Header/SubHeader.test.js
 PASS src/components/Button/Button.test.js
 › 1 snapshot obsolete.
 • the <Button /> component should render 1
----------------------------|----------|----------|----------|----------|-------------------|
File | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s |
----------------------------|----------|----------|----------|----------|-------------------|
All files | 5.45 | 6.74 | 6.38 | 5.69 | |
 src | 0 | 0 | 0 | 0 | |
 api.js | 0 | 0 | 0 | 0 |... 20,22,23,26,30 |
 index.js | 0 | 100 | 100 | 0 | 1,2,3,4,5,17 |
 serviceWorker.js | 0 | 0 | 0 | 0 |... 23,130,131,132 |
 src/components | 0 | 100 | 0 | 0 | |
 App.js | 0 | 100 | 0 | 0 |... ,8,10,22,26,27 |
 src/components/Button | 100 | 100 | 100 | 100 | |
 Button.js | 100 | 100 | 100 | 100 | |
...
```

在上述报告中，您可以看到测试覆盖率仍然为 100％，这意味着这种测试方法具有相同的结果。但这次，您特别测试子元素是否等于该值。好处是，您无需在每次进行代码更改时更新快照。

1.  还显示了一个消息，指出 `1 个快照已过时`。通过使用 `-u` 标志运行 `npm run test`，`Button` 组件的快照将被 Jest 删除：

```jsx
npm run test -u
```

这为我们提供了以下输出，显示快照已被移除：

```jsx
 PASS src/components/Button/Button.test.js
 › snapshot file removed.

Snapshot Summary
 › 1 snapshot file removed from 1 test suite.
```

然而，`Button`组件不仅接受`children`属性，还接受`onClick`属性。如果您想测试当单击按钮时是否触发了此`onClick`属性，您需要以不同的方式渲染组件。这可以通过使用`react-test-renderer`来完成，但 React 文档还指出您也可以使用 Enzyme 来实现这一点。

在下一节中，我们将使用 Enzyme 的浅渲染函数，该函数比`ShallowRenderer`有更多选项。

# 使用 Enzyme 进行 React 测试

`react-test-renderer`的`ShallowRenderer`允许我们渲染组件的结构，但不会显示组件在某些场景下的交互方式，例如当触发`onClick`事件时。为了模拟这一点，我们将使用一个更复杂的工具，称为 Enzyme。

# 使用 Enzyme 进行浅渲染

Enzyme 是由 Airbnb 创建的开源 JavaScript 测试库，可以与几乎所有 JavaScript 库或框架一起使用。使用 Enzyme，您还可以浅渲染组件以测试组件的第一级，以及渲染嵌套组件，并模拟集成测试的生命周期。Enzyme 库可以使用`npm`安装，并且还需要一个适配器来模拟 React 功能。让我们开始吧：

1.  安装 Enzyme，您需要从终端运行以下命令，该命令安装 Enzyme 和您正在使用的 React 版本的特定适配器：

```jsx
npm install enzyme enzyme-adapter-react-16 --save-dev
```

1.  安装 Enzyme 后，您需要创建一个设置文件，告诉 Enzyme 应该使用哪个适配器来运行测试。通常，您需要在`package.json`文件中指定保存此配置的文件，但是，当您使用 Create React App 时，这已经为您完成。自动用作测试库配置文件的文件名为`setupTests.js`，应该创建在`src`目录中。创建文件后，将以下代码粘贴到其中：

```jsx
import { configure } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';

configure({ adapter: new Adapter() });
```

安装 Enzyme 后，您将无法再使用使用`react-test-renderer`的测试场景。因此，您需要更改`SubHeader`和`Button`组件的测试。正如我们之前提到的，Enzyme 有一个方法允许我们浅渲染组件。让我们先尝试对`SubHeader`组件进行这样的操作：

1.  您需要从 Enzyme 导入`shallow`，而不是导入`react-test-renderer`。`ShallowRender`方法不应再添加到`renderer`常量中，因此您可以删除此行：

```jsx
import React from 'react';
- import ShallowRenderer from 'react-test-renderer/shallow';
+ import { shallow } from 'enzyme';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
-  const renderer = new ShallowRenderer();
  it('should render', () => {
    ...
```

1.  每个测试方案都应更改为使用 Enzyme 的浅渲染函数。我们可以通过用`shallow`替换`renderer.render`来实现这一点。我们用于获取此渲染输出的函数也可以删除。Enzyme 的`shallow`渲染将立即创建一个可以由 Jest 测试的结果：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
  it('should render', () => {
-    renderer.render(<SubHeader />);
-    const component = renderer.getRenderOutput();
+    const component = shallow(<SubHeader />);

    expect(component).toMatchSnapshot();
  });

  ...
```

1.  就像我们在第一个测试方案中所做的那样，我们必须替换其他测试方案；否则，测试将无法运行。这是因为我们已经删除了`react-test-renderer`的设置：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader from './SubHeader';

describe('the <SubHeader /> component', () => {
  ...

  it('should render with a dynamic title', () => {
-    renderer.render(<SubHeader title='Test Application' />);
-    const component = renderer.getRenderOutput();
+    const component = shallow(<SubHeader title='Test Application' />);

    expect(component).toMatchSnapshot();
  });

  it('should render with a goback button', () => {
-    renderer.render(<SubHeader goBack={() => {}} />);
-    const component = renderer.getRenderOutput();
+    const component = shallow(<SubHeader goBack={() => {}} />);

    expect(component).toMatchSnapshot();
  });

  it('should render with a form button', () => {
-    renderer.render(<SubHeader openForm={() => {}} />);
-    const component = renderer.getRenderOutput();
+    const component = shallow(<SubHeader openForm={() => {}} />);

    expect(component).toMatchSnapshot();
  });
});
```

1.  在终端中，您现在可以通过运行`npm run test`再次运行测试。由于测试正在观察模式下运行，`Button`组件的测试可能也会开始运行。您可以通过按下`p`键然后在终端中输入`SubHeader`来指定应该运行哪些测试。现在，Jest 将仅运行`SubHeader`组件的测试。

由于您的快照不再是由`react-test-renderer`创建的快照，测试将失败。Enzyme 的浅渲染对来自`styled-components`的导出有更好的理解，不再将这些组件呈现为`ForwardRef`组件。相反，它返回，例如，名为`styled.div`或`styled.h2`的组件：

```jsx
 FAIL src/components/Header/SubHeader.test.js
 the <SubHeader /> component
 Χ should render (27ms)
 Χ should render with a dynamic title (4ms)
 Χ should render with a goback button (4ms)
 Χ should render with a form button (4ms)

 • the <SubHeader /> component › should render

 expect(value).toMatchSnapshot()

 Received value does not match stored snapshot "the <SubHeader /> component should render 1".

 - Snapshot
 + Received

 - <ForwardRef>
 - <ForwardRef />
 - </ForwardRef>
 + <styled.div>
 + <styled.h2 />
 + </styled.div>
```

通过按下`u`键，所有由`react-test-renderer`创建的快照将被 Enzyme 的新快照替换。

对于`Button`组件，也可以进行相同的操作，不使用快照进行测试。而是使用断言。在您的测试方案中，在`src/components/Button/Button.test.js`文件中，用 Enzyme 的浅渲染替换`ShallowRenderer`。此外，由于 Enzyme 呈现组件的方式，`component.props.children`的值不再存在。相反，您需要使用`props`方法，该方法可用于浅渲染的组件上，以获取`children`属性：

```jsx
import React from 'react';
- import ShallowRenderer from 'react-test-renderer/shallow';
+ import { shallow } from 'enzyme';
import Button from './Button';

describe('the <Button /> component', () => {
-  const renderer = new ShallowRenderer();

  it('should render the correct children', () => {
    const children = 'This is a button';
-   renderer.render(<Button>{children}</Button>);
-   const component = renderer.getRenderOutput();
+   const component = shallow(<Button>{children}</Button>)

-   expect(component.props.children).toEqual(children)
+   expect(component.props().children).toEqual(children)
  })
})
```

现在当您运行测试时，所有测试都应该成功，并且测试覆盖率不应受影响，因为您仍在测试组件上的属性是否被渲染。然而，使用 Enzyme 的快照，您可以获得有关正在呈现的组件结构的更多信息。现在，您甚至可以测试更多内容，并找出例如`onClick`事件是如何处理的。

然而，快照并不是测试 React 组件的唯一方式，正如我们将在本节的下一部分中看到的那样。

# 使用浅渲染进行断言测试

除了`react-test-renderer`之外，Enzyme 可以处理浅渲染组件上的`onClick`事件。为了测试这一点，您必须创建一个模拟版本的函数，该函数应在组件被点击时触发。之后，Jest 可以检查该函数是否被执行。

您之前测试过的`Button`组件不仅接受`children`作为属性 - 它还接受`onClick`函数。让我们尝试看看是否可以使用 Jest 和 Enzyme 来测试这一点，通过在`Button`组件的文件中创建一个新的测试场景：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import Button from './Button';

describe('the <Button /> component', () => {
  ...

+  it('should handle the onClick event', () => {
+    const mockOnClick = jest.fn();
+    const component = shallow(<Button onClick={mockOnClick} />);

+    component.simulate('click');

+    expect(mockOnClick).toHaveBeenCalled();
+  });
});
```

在前面的测试场景中，使用 Jest 创建了一个模拟的`onClick`函数，该函数作为属性传递给了浅渲染的`Button`组件。然后，在该组件上调用了一个带有点击事件处理程序的`simulate`方法。模拟点击`Button`组件应该执行模拟的`onClick`函数，您可以通过检查该测试场景的测试结果来确认这一点。

`SubHeader`组件的测试也可以更新，因为它渲染了两个带有`onClick`事件的按钮。让我们开始吧：

1.  首先，您需要对`src/components/Header/SubHeader.js`中的`SubHeader`组件的文件进行一些更改，因为您需要导出使用`styled-components`创建的组件。通过这样做，它们可以在`SubHeader`的测试场景中用于测试：

```jsx
import React from 'react';
import styled from 'styled-components';
import Button from '../Button/Button';

const SubHeaderWrapper = styled.div`
  width: 100%;
  display: flex;
  justify-content: space-between;
  background: cornflowerBlue;
`;

- const Title = styled.h2`
+ export const Title = styled.h2`
  text-align: center;
  flex-basis: 60%;

  &:first-child {
    margin-left: 20%;
  }

  &:last-child {
    margin-right: 20%;
  }
`;

- const SubHeaderButton = styled(Button)`
+ export const SubHeaderButton = styled(Button)`
  margin: 10px 5%;
`;

...
```

1.  一旦它们被导出，我们就可以将这些组件导入到我们的`SubHeader`测试文件中：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
- import SubHeader from './SubHeader';
+ import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
    ...
```

1.  这样可以在任何测试中找到这些组件。在这种情况下，使用快照测试了`title`属性的渲染，但您也可以直接测试`SubHeader`中的`Title`组件是否正在渲染`title`属性。要测试这一点，请更改以下代码行：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
  it('should render with a dynamic title', () => {
+    const title = 'Test Application';
-    const component = shallow(<SubHeader title='Test Application' />);
+    const component = shallow(<SubHeader title={title} />);

-    expect(component).toMatchSnapshot();

+    expect(component.find(Title).text()).toEqual(title);
  });

  ...
```

在这里创建了一个新的常量用于`title`属性，并将其传递给`SubHeader`组件。不再使用快照作为断言，而是创建一个新的快照，尝试找到`Title`组件，并检查该组件内的文本是否等于`title`属性。

1.  除了`title` prop 之外，您还可以测试`goBack`（或`openForm`）prop。如果存在这个 prop，将渲染一个具有`goBack` prop 作为`onClick`事件的按钮。这个按钮被渲染为`SubHeaderButton`组件。在这里，我们需要改变第二个测试场景，使其具有`goBack` prop 的模拟函数，然后创建一个断言来检查渲染组件中`SubHeaderButton`的存在：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
  ...

  it('should render with a goback button and handle the onClick event', () => {
+    const mockGoBack = jest.fn();
-    const component = shallow(<SubHeader goBack={() => {}} />);
+    const component = shallow(<SubHeader goBack={mockGoBack} />);

-    expect(component).toMatchSnapshot();

+    const goBackButton = component.find(SubHeaderButton);
+    expect(goBackButton.exists()).toBe(true);
  });
  ...
```

1.  我们不仅要测试带有`goBack` prop 的按钮是否被渲染，还要测试一旦我们点击按钮，这个函数是否被调用。就像我们为`Button`组件测试所做的那样，我们可以模拟点击事件并检查模拟的`goBack`函数是否被调用：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
  ...

  it('should render with a goback button and handle the onClick event', () => {
    const mockGoBack = jest.fn();
    const component = shallow(<SubHeader goBack={mockGoBack} />);

    const goBackButton = component.find(SubHeaderButton);
    expect(goBackButton.exists()).toBe(true);

+    goBackButton.simulate('click');
+    expect(mockGoBack).toHaveBeenCalled();
  })
  ...
```

1.  如果我们用两个断言替换测试快照的断言，测试按钮的存在以及它是否触发了模拟的`openForm`函数，那么对于`openForm` prop 也可以做同样的事情。我们可以将这个添加到现有的测试场景中，也可以扩展`goBack`按钮的测试场景：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
  ...

-   it('should render with a goback button and handle the onClick event', () => {
+   it('should render with a buttons and handle the onClick events', () => {
    const mockGoBack = jest.fn();
+    const mockOpenForm = jest.fn();
-    //const component = shallow(<SubHeader goBack={mockGoBack} />);
+    const component = shallow(<SubHeader goBack={mockGoBack} openForm={mockOpenForm} />);

    ...
  });

-  it('should render with a form button', () => {
-    const component = shallow(<SubHeader openForm={() => {}} />);

-    expect(component).toMatchSnapshot();
-  });
});
```

1.  现在为`SubHeader`渲染的组件应该同时具有一个按钮返回到上一页和一个按钮打开表单。然而，它们都使用`SubHeaderButton`组件进行渲染。返回按钮首先在组件树中进行渲染，因为它位于`SubHeader`的左侧。因此，我们需要指定哪个渲染的`SubHeaderButton`是哪个按钮：

```jsx
import React from 'react';
import { shallow } from 'enzyme';
import SubHeader, { Title, SubHeaderButton } from './SubHeader';

describe('the <SubHeader /> component', () => {
  ...

  it('should render with buttons and handle the onClick events', () => {
    const mockGoBack = jest.fn();
    const mockOpenForm = jest.fn();
    const component = shallow(<SubHeader goBack={mockGoBack} openForm={mockOpenForm} />);

-   const goBackButton = component.find(SubHeaderButton);
+   const goBackButton = component.find(SubHeaderButton).at(0);
    expect(goBackButton.exists()).toBe(true);

+   const openFormButton = component.find(SubHeaderButton).at(1);
+   expect(openFormButton.exists()).toBe(true)

    goBackButton.simulate('click');
    expect(mockGoBack).toHaveBeenCalled();

+    openFormButton.simulate('click');
+    expect(mockOpenForm).toHaveBeenCalled();
  });
  ...
```

在这些更改之后，所有使用快照的测试场景都被移除，并替换为更具体的测试，一旦我们改变了任何代码，它们就会变得不太脆弱。除了快照，这些测试将在我们改变任何使重构更容易的 props 时继续工作。

在这一部分，我们已经创建了单元测试，用于测试我们代码的特定部分。然而，测试不同部分的代码如何一起工作可能会很有趣。为此，我们将向我们的项目添加集成测试。

# 使用 Enzyme 进行集成测试

我们创建的所有测试都使用浅渲染来渲染组件，但是在 Enzyme 中，我们也有选项来挂载组件。使用这个选项时，我们可以启用生命周期并测试比第一级更深的更大的组件。当我们想一次测试多个组件时，这被称为集成测试。在我们的应用程序中，由路由直接渲染的组件也会渲染其他组件。`Hotels`组件就是一个很好的例子，它渲染了上下文返回的酒店列表。让我们开始吧：

1.  和往常一样，起点是在与要测试的组件位于同一目录中创建一个带有`.test`后缀的新文件。在这里，我们需要在`src/components/Hotels`目录中创建`Hotels.test.js`文件。在这个文件中，我们需要从 Enzyme 中导入`mount`，导入我们要测试的组件，并创建一个新的测试场景：

```jsx
import React from 'react';
import { mount } from 'enzyme';
import Hotels from './Hotels';

describe('the <Hotels /> component', () => {

});
```

2. `Hotels`组件使用`useContext` Hook 来获取显示酒店所需的数据。然而，由于这是针对特定组件的测试，该数据需要被模拟。在我们可以模拟这些数据之前，我们需要为`useContext` Hook 创建一个模拟函数。如果我们有多个使用此模拟的测试场景，我们还需要使用`beforeEach`和`afterEach`方法为每个场景创建和重置这个模拟函数。

```jsx
import React from 'react';
import { mount } from 'enzyme';
import Hotels from './Hotels';

+ let useContextMock;

+ beforeEach(() => {
+  useContextMock = React.useContext = jest.fn();
+ });

+ afterEach(() => {
+  useContextMock.mockReset();
+ });

describe('the <Hotels /> component', () => {
    ...
```

1.  现在我们可以使用模拟的`useContextMock`函数来生成将用作上下文的模拟数据，该数据将由`Hotels`组件使用。将返回的数据也应该是模拟的，可以通过调用可用于模拟函数的`mockReturnValue`函数来实现。如果我们看一下`Hotels`组件的实际代码，我们会发现它从上下文中获取了四个值：`loading`，`error`，`hotels`和`getHotelsRequest`。这些值应该在我们将创建的第一个测试场景中被模拟和返回，以检查上下文在加载酒店数据时的行为：

```jsx
import React from 'react';
import { mount } from 'enzyme';
import Hotels from './Hotels';

...

describe('the <Hotels /> component', () => {
  it('should handle the first mount', () => {
+    const mockContext = { 
+      loading: true,
+      error: '', 
+      hotels: [], 
+      getHotelsRequest: jest.fn(),
+    }
+    useContextMock.mockReturnValue(mockContext);
+    const wrapper = mount(<Hotels />);
+
+    expect(mockContext.getHotelsRequest).toHaveBeenCalled();
  });
});
```

这个第一个测试场景检查了`Hotels`组件在首次挂载时是否会调用上下文中的`getHotelsRequest`函数。这意味着在`Hotels`中使用的`useEffect` Hook 已经经过了测试。

1.  由于数据仍在加载中，我们还可以测试`Alert`组件是否从上下文中渲染了`loading`值并显示了加载消息。在这里，我们需要从`src/components/Hotels/Hotels.js`中导出这个组件：

```jsx
...

- const Alert = styled.span`
+ export const Alert = styled.span`
  width: 100%;
  text-align: center;
`;

const Hotels = ({ match, history }) => {
    ...
```

现在，我们可以在测试文件中导入这个组件，并编写断言来检查它是否显示了来自上下文的值：

```jsx
import React from 'react';
import { mount } from 'enzyme';
- import Hotels from './Hotels';
+ import Hotels, { Alert } from './Hotels';

...

describe('the <Hotels /> component', () => {
  it('should handle the first mount', () => {
    const mockContext = { 
      loading: true,
      error: '',
      hotels: [], 
      getHotelsRequest: jest.fn(), 
    }
    useContextMock.mockReturnValue(mockContext);
    const wrapper = mount(<Hotels />);

    expect(mockContext.getHotelsRequest).toHaveBeenCalled();
+   expect(wrapper.find(Alert).text()).toBe('Loading...');
  });
```

1.  在`Hotels`组件挂载并且数据被获取后，上下文中的`loading`、`error`和`hotels`的值将被更新。当`loading`和`error`的值为`false`时，`HotelItemsWrapper`组件将被`Hotels`渲染。为了测试这一点，我们需要从`Hotels`中导出`HotelItemsWrapper`：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
import { HotelsContext } from '../../Context/HotelsContextProvider';
import SubHeader from '../Header/SubHeader';
import HotelItem from './HotelItem';

- const HotelItemsWrapper = styled.div`
+ export const HotelItemsWrapper = styled.div`
  display: flex;
  justify-content: space-between;
  flex-direction: column;
  margin: 2% 5%;
`;

...
```

在测试文件中，现在可以导入这个组件，这意味着我们可以添加新的测试场景，检查这个组件是否被渲染：

```jsx
import React from 'react';
import { mount } from 'enzyme';
- import Hotels, { Alert } from './Hotels';
+ import Hotels, { Alert, HotelItemsWrapper } from './Hotels';

describe('the <Hotels /> component', () => {
  ...

+  it('should render the list of hotels', () => {
+    const mockContext = {
+      loading: false,
+      error: '',
+      hotels: [{
+        id: 123,
+        title: 'Test Hotel',
+        thumbnail: 'test.jpg',
+      }],
+      getHotelsRequest: jest.fn(),
+    }
+    useContextMock.mockReturnValue(mockContext);
+    const wrapper = mount(<Hotels />);

+    expect(wrapper.find(HotelItemsWrapper).exists()).toBe(true);
+  });
});
```

现在，当我们运行测试时，会出现错误，显示“不变式失败：您不应该在<Router>之外使用<Link>”，因为 Enzyme 无法渲染`Link`组件，这是我们点击酒店时用来导航的。因此，我们需要将`Hotels`组件包装在`react-router`的路由器组件中：

```jsx
import React from 'react';
import { mount } from 'enzyme';
+ import { BrowserRouter as Router } from 'react-router-dom';
import Hotels, { Alert, HotelItemsWrapper } from './Hotels';

...

describe('the <Hotels /> component', () => {
  ...

  it('should render the list of hotels', () => {
    const mockContext = {
      loading: false,
      alert: '',
      hotels: [{
        id: 123,
        title: 'Test Hotel',
        thumbnail: 'test.jpg',
      }],
      getHotelsRequest: jest.fn(),
    }
    useContextMock.mockReturnValue(mockContext);
-    const wrapper = mount(<Hotels />);
+    const wrapper = mount(<Router><Hotels /></Router>);

    expect(wrapper.find(HotelItemsWrapper).exists()).toBe(true);
  });
});
```

这个测试现在会通过，因为 Enzyme 可以渲染组件，包括`Link`来导航到酒店。

1.  在`HotelItemsWrapper`组件内部是一个`map`函数，它遍历来自上下文的酒店数据。对于每次迭代，都会渲染一个`HotelItem`组件。在这些`HotelItem`组件中，数据将以某种方式显示，例如一个`Title`组件。我们可以测试这些组件中将显示的数据是否等于模拟的上下文数据。显示酒店标题的组件应该从`src/components/Hotels/HotelItem.js`中导出。

```jsx
- const Title = styled.h3`
+ export const Title = styled.h3`
  margin-left: 2%;
`
```

除了`HotelItem`组件，这应该被导入到`Hotels`的测试中。在测试场景中，我们现在可以检查`<HotelItem`组件是否存在，并检查这个组件是否有`Title`组件。这个组件显示的值应该等于数组`hotels`中第一行的标题的模拟上下文值：

```jsx
import React from 'react';
import { mount } from 'enzyme';
import { BrowserRouter as Router } from 'react-router-dom';
import Hotels, { Alert, HotelItemsWrapper } from './Hotels';
+ import HotelItem, { Title } from './HotelItem';

...

describe('the <Hotels /> component', () => {
  ...

  it('should render the list of hotels', () => {
    const mockContext = {
      loading: false,
      alert: '',
      hotels: [{
        id: 123,
        title: 'Test Hotel',
        thumbnail: 'test.jpg',
      }],
      getHotelsRequest: jest.fn(),
    }
    useContextMock.mockReturnValue(mockContext);
    const wrapper = mount(<Router><Hotels /></Router>);

    expect(wrapper.find(HotelItemsWrapper).exists()).toBe(true);

+   expect(wrapper.find(HotelItem).exists()).toBe(true);
+ expect(wrapper.find(HotelItem).at(0).find(Title).text()).toBe(mockContext.hotels[0].title);
  });
});
```

在使用`--coverage`标志再次运行测试之后，我们将能够看到编写此集成测试对我们的覆盖率产生了什么影响。由于集成测试不仅测试一个特定的组件，而是一次测试多个组件，因此`Hotels`的测试覆盖率将得到更新。此测试还涵盖了`HotelItem`组件，我们将能够在运行`npm run test --coverage`后的覆盖率报告中看到这一点：

```jsx
 PASS src/components/Button/Button.test.js
 PASS src/components/Header/SubHeader.test.js
 PASS src/components/Hotels/Hotels.test.js
----------------------------|----------|----------|----------|----------|-------------------|
File | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s |
----------------------------|----------|----------|----------|----------|-------------------|
All files | 13.27 | 11.24 | 12.77 | 13.73 | |
 ...
 src/components/Hotels | 100 | 83.33 | 100 | 100 | |
 HotelItem.js | 100 | 100 | 100 | 100 | |
 Hotels.js | 100 | 83.33 | 100 | 100 | 33 |
```

`Hotels`的覆盖率接近 100%。`HotelItems`的测试覆盖率也达到了 100%。这意味着我们可以跳过为`HotelItem`编写单元测试，假设我们只在`Hotels`组件中使用此组件。

相对于单元测试，集成测试的唯一缺点是它们更难编写，因为它们通常包含更复杂的逻辑。此外，由于集成测试具有更多的逻辑并将多个组件组合在一起，因此这些集成测试将运行得更慢。

# 摘要

在本章中，我们介绍了使用 Jest 结合`react-test-renderer`或 Enzyme 进行 React 应用程序测试。这两个软件包对于希望为其应用程序添加测试脚本的每个开发人员都是很好的资源，它们也与 React 很好地配合。本章讨论了为应用程序编写测试的优势，希望现在您知道如何为任何项目添加测试脚本。还展示了单元测试和集成测试之间的区别。

由于本章中测试的应用程序与前几章的应用程序具有相同的结构，因此可以将相同的测试原则应用于本书中构建的任何应用程序。

下一章将结合本书中已经使用过的许多模式和库，因为我们将使用 React、GraphQL 和 Apollo 创建一个全栈电子商务商店。

# 进一步阅读

+   Enzyme 浅渲染：[`airbnb.io/enzyme/docs/api/shallow.html`](https://airbnb.io/enzyme/docs/api/shallow.html)

+   Enzyme 挂载：[`airbnb.io/enzyme/docs/api/mount.html`](https://airbnb.io/enzyme/docs/api/mount.html)
