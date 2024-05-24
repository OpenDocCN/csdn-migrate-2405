# React 和 ReactNative 第二版（七）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十五章：为什么选择 Relay 和 GraphQL？

在前一章中，你了解了 Flux 的架构原则。特别是，你使用 Redux 库在 React 应用程序中实现了具体的 Flux 概念。有了像 Flux 这样的模式框架，可以帮助你思考状态如何改变并在应用程序中流动，这是一件好事。在本章的结尾，你了解了在扩展方面的潜在限制。

在本章中，我们将带你走进另一种处理 React 应用程序状态的方法。与 Redux 一样，Relay 用于 Web 和移动 React 应用程序。Relay 依赖一种叫做 GraphQL 的语言，用于获取资源和改变这些资源。

Relay 的前提是它可以以 Redux 和其他处理状态的方法所限制的方式进行扩展。它通过消除它们，将焦点放在组件的数据需求上来实现这一点。

在本书的最后一章，你将会在 React Native 中实现备受欢迎的 Todo MVC 应用程序。

# 又一种方法？

当我了解 Relay 和 GraphQL 时，我就有了这个确切的问题。然后我提醒自己，React 的美妙之处在于它只是 UI 的视图抽象；当然会有许多处理数据的方法。因此，真正的问题是，Relay 比 Redux 之类的东西更好还是更差？

在高层次上，你可以将 Relay 看作是 Flux 架构模式的一种实现，你可以将 GraphQL 看作是描述 Relay 内部 Flux 存储工作方式的接口。在更实际的层面上，Relay 的价值在于实现的便利性。例如，使用 Redux，你需要做很多实现工作，只是为了用数据填充存储。随着时间的推移，这变得冗长。正是这种冗长使得 Redux 难以在一定程度之上进行扩展。

难以扩展的不是单个数据点。而是有大量获取请求最终构建非常复杂的存储的总体效果。Relay 通过允许你声明给定组件需要的数据，并让 Relay 找出获取这些数据并将其与本地存储同步的最佳方法来改变这一点。

Relay 的方法是否比 Redux 和其他处理 React 应用程序中数据的方法更好？在某些方面，是的。它完美吗？远非如此。这涉及到一个学习曲线，并非每个人都能理解它。它是不可变的，其中的一些部分很难使用。然而，了解 Relay 的方法的前提并看到它的实际效果是值得的，即使你最终决定不采用它。

现在，让我们分解一些词汇。

# 冗长的俗语

在我开始更深入地讨论数据依赖和突变之前，我认为我应该先介绍一些一般的 Relay 和 GraphQL 术语定义：

+   Relay：一个管理应用程序数据获取和数据突变的库，并提供高阶组件，将数据传递给我们的应用程序组件

+   GraphQL：用于指定数据需求和数据突变的查询语言

+   数据依赖：一个抽象概念，表示给定的 React 组件依赖于特定的数据

+   查询：查询是数据依赖的一部分，用 GraphQL 语法表示，并由封装的 Relay 机制执行

+   片段：较大的 GraphQL 查询的一部分

+   容器：一个 Relay React 组件，将获取的数据传递给应用程序 React 组件

+   突变：一种特殊类型的 GraphQL 查询，它改变了一些远程资源的状态，一旦完成，Relay 必须找出如何在前端反映这种变化

让我们快速谈谈数据依赖和突变，这样我们就可以看一些应用程序代码。

# 声明性数据依赖

Relay 使用 collocation 这个术语来描述声明性数据依赖，这些数据依赖与使用数据的组件并存。这意味着你不必四处寻找实际获取组件数据的动作创建函数，这些函数分散在几个模块中。通过 collocation，你可以清楚地看到组件需要什么。

让我们先尝试一下这是什么样子。如果你想显示用户的名字和姓氏，你需要告诉 Relay 你的组件需要这些数据。然后，你可以放心，数据将始终存在于你的组件中。这是一个例子：

```jsx
const User = ({ first, last }) => ( 
  <section> 
    <p>{first}</p> 
    <p>{last}</p> 
  </section> 
); 

const UserContainer = Relay.createFragmentContainer(User, { 
   user: () => graphql` 
    fragment on User { 
      first, 
      last, 
   } 
  `
}); 
```

你有两个组件在这里。首先，有`User`组件。这是应用程序组件，实际上呈现了`first`和`last`名称数据的 UI 元素。请注意，这只是一个普通的旧 React 组件，呈现传递给它的 props。使用您创建的`UserContainer`组件，Relay 遵循了您在本书中学到的容器模式。在`createFragmentContainer()`函数中，您通过传递 GraphQL 语法的片段来指定此组件需要的数据依赖关系。

再次强调，暂时不要过多关注 Relay/GraphQL 的具体细节。这里的想法只是简单说明这是您需要编写的所有代码，以获取组件所需的数据。其余的只是引导 Relay 查询机制，您将在下一章中看到。

# 改变应用程序状态

Relay mutations 是导致系统产生副作用的操作，因为它们改变了 UI 关心的某些资源的状态。关于 Relay mutations 有趣的是，它们关心的是由于某些状态变化而导致的数据的副作用。例如，如果您更改用户的名称，这肯定会影响显示用户详细信息的屏幕。但是，它也可能影响显示多个用户的列表屏幕。

让我们看看 mutation 是什么样子的：

```jsx
const mutation = graphql`
  mutation ChangeAgeMutation($input: ChangeAgeInput!) {
    changeTodoStatus(input: $input) {
      viewer {
        users
      }
      user {
        age
      }
    }
  }
`; 
```

这就是 Relay 能够确定在执行此 mutation 的副作用可能受到影响的内容。例如，用户可能会改变，但`viewer.users`集合也可能会改变。您将在接下来的章节中看到更多 mutation 的操作。

# GraphQL 后端和微服务

到目前为止，我所涵盖的关于 Relay 的一切都是在浏览器中的。Relay 需要将其 GraphQL 查询发送到某个地方。为此，您需要一个 GraphQL 后端。您可以使用 Node.js 和一些 GraphQL 库来实现这一点。您创建所谓的模式，描述将使用的所有数据类型、查询和 mutation。

在浏览器中，Relay 通过减少数据流复杂性来帮助您扩展应用程序。您有一种声明所需数据的方法，而不必担心如何获取它。实际上需要解析这些数据的是后端的模式。

这是 GraphQL 帮助解决的另一个扩展问题。现代 Web 应用程序由微服务组成。这些是较小的、自包含的 API 端点，提供一些比整个应用程序更小的特定目的（因此称为微服务）。我们的应用程序的工作是将这些微服务组合在一起，并为前端提供有意义的数据。

再次，你面临着一个可扩展性问题——如何在不引入不可逾越的复杂性的情况下维护由许多微服务组成的后端？这是 GraphQL 类型擅长的事情。在接下来的章节中，您将开始使用后端 GraphQL 服务实现您的 Todo 应用程序。

# 摘要

本章的目标是在本书的最后一章之前，快速向您介绍 Relay 和 GraphQL 的概念，您将在最后一章中实现一些 Relay/GraphQL 代码。

Relay 是 React 应用程序中状态管理问题的另一种方法。它不同之处在于，它减少了与数据获取代码相关的复杂性，我们必须使用其他 Flux 方法（如 Redux）编写。

Relay 的两个关键方面是声明式数据依赖和显式的突变副作用处理。所有这些都通过 GraphQL 语法表达。为了拥有一个 Relay 应用程序，你需要一个数据模式存在的 GraphQL 后端。现在，进入最后一章，你将更详细地研究 Relay/GraphQL 的概念。

# 测试你的知识

1.  Relay 和其他受 Flux 启发的库（如 Redux）之间有什么区别？

1.  没有区别，Relay 只是另一个 Flux 选项。

1.  Relay 是为 React Native 应用程序设计的，你应该在 Web 应用程序中使用 Redux。

1.  Relay 通过允许数据依赖声明和隐藏所有服务器通信复杂性来帮助扩展您的 Flux 架构。

1.  Relay 如何简化 React 组件的数据需求？

1.  通过合并数据依赖查询，您可以准确地看到您的组件使用的数据，而无需查看执行获取操作的代码。

1.  通过预先获取所有应用程序数据，Relay 可以查询每个组件需要的数据。

1.  通过抽象网络调用。GraphQL 是可选的，如果你愿意，你可以使用直接的 HTTP。

1.  在基于 Relay 的应用程序中，您的 React 组件如何与服务器通信？

1.  您必须实现自己的网络通信逻辑。Relay 只处理将数据传递给组件。

1.  Relay 编译在您的组件中找到的 GraphQL 查询，并为您处理所有的 GraphQL 服务器通信，包括缓存优化。

# 更多阅读

访问以下链接获取更多信息：

+   [`facebook.github.io/relay/`](https://facebook.github.io/relay/)


# 第二十六章：构建 Relay React 应用

在上一章中，你对 Relay/GraphQL 有了一个概览，并了解了为什么应该在 React 应用程序中使用这种方法。现在你可以使用 Relay 构建你的 Todo React Native 应用程序。在本章结束时，你应该对 GraphQL 中心架构中的数据传输感到自如。

# TodoMVC 和 Relay

我最初计划扩展我们在本章前面工作过的 Neckbeard News 应用程序。但我决定使用 Relay 的 TodoMVC 示例（[`github.com/taion/relay-todomvc`](https://github.com/taion/relay-todomvc)），这是一个强大而简洁的示例，我很难超越它。

我将带你走过一个示例 React Native 实现的 Todo 应用程序。关键是，它将使用与 Web UI 相同的 GraphQL 后端。我认为这对于想要构建其应用程序的 Web 和原生版本的 React 开发人员来说是一个胜利；他们可以共享相同的模式！

我已经在随本书一起提供的代码中包含了 TodoMVC 应用程序的 Web 版本，但我不会详细介绍它的工作原理。如果你在过去 5 年里从事过 Web 开发，你可能已经接触过一个样本 Todo 应用程序。这是 Web 版本的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/750d45e8-c429-4262-a5e9-b1b9559a072b.png)

即使你以前没有使用过任何 TodoMVC 应用程序，我建议在尝试实现本章剩余部分的原生版本之前，先尝试玩一下这个。

你即将实现的原生版本的目标不是功能平等。事实上，你的目标是实现一个非常简化的 todo 功能子集。目标是向你展示，Relay 在原生平台上的工作方式与在 Web 平台上基本相同，并且 GraphQL 后端可以在 Web 和原生应用程序之间共享。

# GraphQL 模式

模式是 GraphQL 后端服务器和前端 Relay 组件使用的词汇。GraphQL 类型系统使模式能够描述可用的数据，以及在查询请求到来时如何将所有数据组合在一起。这就是整个方法如此可扩展的原因，因为 GraphQL 运行时会找出如何组合数据。你只需要提供告诉 GraphQL 数据在哪里的函数；例如，在数据库中或在某个远程服务端点中。

让我们来看看在 TodoMVC 应用程序的 GraphQL 模式中使用的类型，如下所示：

```jsx
import {
  GraphQLBoolean,
  GraphQLID,
  GraphQLInt,
  GraphQLList,
  GraphQLNonNull,
  GraphQLObjectType,
  GraphQLSchema,
  GraphQLString
} from 'graphql';
import {
  connectionArgs,
  connectionDefinitions,
  connectionFromArray,
  cursorForObjectInConnection,
  fromGlobalId,
  globalIdField,
  mutationWithClientMutationId,
  nodeDefinitions,
  toGlobalId
} from 'graphql-relay';

import {
  Todo,
  User,
  addTodo,
  changeTodoStatus,
  getTodo,
  getTodos,
  getUser,
  getViewer,
  markAllTodos,
  removeCompletedTodos,
  removeTodo,
  renameTodo
} from './database';

const { nodeInterface, nodeField } = nodeDefinitions(
  globalId => {
    const { type, id } = fromGlobalId(globalId);
    if (type === 'Todo') {
      return getTodo(id);
    }
    if (type === 'User') {
      return getUser(id);
    }
    return null;
  },
  obj => {
    if (obj instanceof Todo) {
      return GraphQLTodo;
    }
    if (obj instanceof User) {
      return GraphQLUser;
    }
    return null;
  }
);

const GraphQLTodo = new GraphQLObjectType({
  name: 'Todo',
  fields: {
    id: globalIdField(),
    complete: { type: GraphQLBoolean },
    text: { type: GraphQLString }
  },
  interfaces: [nodeInterface]
});

const {
  connectionType: TodosConnection,
  edgeType: GraphQLTodoEdge
} = connectionDefinitions({ nodeType: GraphQLTodo });

const GraphQLUser = new GraphQLObjectType({
  name: 'User',
  fields: {
    id: globalIdField(),
    todos: {
      type: TodosConnection,
      args: {
        status: {
          type: GraphQLString,
          defaultValue: 'any'
        },
        ...connectionArgs
      },
      resolve: (obj, { status, ...args }) =>
        connectionFromArray(getTodos(status), args)
    },
    numTodos: {
      type: GraphQLInt,
      resolve: () => getTodos().length
    },
    numCompletedTodos: {
      type: GraphQLInt,
      resolve: () => getTodos('completed').length
    }
  },
  interfaces: [nodeInterface]
});

const GraphQLRoot = new GraphQLObjectType({
  name: 'Root',
  fields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    node: nodeField
  }
});

const GraphQLAddTodoMutation = mutationWithClientMutationId({
  name: 'AddTodo',
  inputFields: {
    text: { type: new GraphQLNonNull(GraphQLString) }
  },
  outputFields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    todoEdge: {
      type: GraphQLTodoEdge,
      resolve: ({ todoId }) => {
        const todo = getTodo(todoId);
        return {
          cursor: cursorForObjectInConnection(getTodos(), todo),
          node: todo
        };
      }
    }
  },
  mutateAndGetPayload: ({ text }) => {
    const todoId = addTodo(text);
    return { todoId };
  }
});

const GraphQLChangeTodoStatusMutation = mutationWithClientMutationId({
  name: 'ChangeTodoStatus',
  inputFields: {
    id: { type: new GraphQLNonNull(GraphQLID) },
    complete: { type: new GraphQLNonNull(GraphQLBoolean) }
  },
  outputFields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    todo: {
      type: GraphQLTodo,
      resolve: ({ todoId }) => getTodo(todoId)
    }
  },
  mutateAndGetPayload: ({ id, complete }) => {
    const { id: todoId } = fromGlobalId(id);
    changeTodoStatus(todoId, complete);
    return { todoId };
  }
});

const GraphQLMarkAllTodosMutation = mutationWithClientMutationId({
  name: 'MarkAllTodos',
  inputFields: {
    complete: { type: new GraphQLNonNull(GraphQLBoolean) }
  },
  outputFields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    changedTodos: {
      type: new GraphQLList(GraphQLTodo),
      resolve: ({ changedTodoIds }) => changedTodoIds.map(getTodo)
    }
  },
  mutateAndGetPayload: ({ complete }) => {
    const changedTodoIds = markAllTodos(complete);
    return { changedTodoIds };
  }
});

const GraphQLRemoveCompletedTodosMutation = mutationWithClientMutationId(
  {
    name: 'RemoveCompletedTodos',
    outputFields: {
      viewer: {
        type: GraphQLUser,
        resolve: getViewer
      },
      deletedIds: {
        type: new GraphQLList(GraphQLString),
        resolve: ({ deletedIds }) => deletedIds
      }
    },
    mutateAndGetPayload: () => {
      const deletedTodoIds = removeCompletedTodos();
      const deletedIds = deletedTodoIds.map(
        toGlobalId.bind(null, 'Todo')
      );
      return { deletedIds };
    }
  }
);

const GraphQLRemoveTodoMutation = mutationWithClientMutationId({
  name: 'RemoveTodo',
  inputFields: {
    id: { type: new GraphQLNonNull(GraphQLID) }
  },
  outputFields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    deletedId: {
      type: GraphQLID,
      resolve: ({ id }) => id
    }
  },
  mutateAndGetPayload: ({ id }) => {
    const { id: todoId } = fromGlobalId(id);
    removeTodo(todoId);
    return { id };
  }
});

const GraphQLRenameTodoMutation = mutationWithClientMutationId({
  name: 'RenameTodo',
  inputFields: {
    id: { type: new GraphQLNonNull(GraphQLID) },
    text: { type: new GraphQLNonNull(GraphQLString) }
  },
  outputFields: {
    todo: {
      type: GraphQLTodo,
      resolve: ({ todoId }) => getTodo(todoId)
    }
  },
  mutateAndGetPayload: ({ id, text }) => {
    const { id: todoId } = fromGlobalId(id);
    renameTodo(todoId, text);
    return { todoId };
  }
});

const GraphQLMutation = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    addTodo: GraphQLAddTodoMutation,
    changeTodoStatus: GraphQLChangeTodoStatusMutation,
    markAllTodos: GraphQLMarkAllTodosMutation,
    removeCompletedTodos: GraphQLRemoveCompletedTodosMutation,
    removeTodo: GraphQLRemoveTodoMutation,
    renameTodo: GraphQLRenameTodoMutation
  }
});

export default new GraphQLSchema({
  query: GraphQLRoot,
  mutation: GraphQLMutation
});

```

这里导入了很多东西，所以我将从导入开始。我想包括所有这些导入，因为我认为它们在这次讨论中是相关的。首先，有来自`graphql`库的基本 GraphQL 类型。接下来，您有来自`graphql-relay`库的辅助程序，简化了定义 GraphQL 模式。最后，有来自您自己的`database`模块的导入。这不一定是一个数据库，实际上，在这种情况下，它只是模拟数据。例如，如果您需要与远程 API 端点通信，您可以将`database`替换为`api`，或者我们可以将两者结合起来；就您的 React 组件而言，这都是 GraphQL。

然后，您定义了一些自己的 GraphQL 类型。例如，`GraphQLTodo`类型有两个字段——`text`和`complete`。一个是布尔值，一个是字符串。关于 GraphQL 字段的重要事情是`resolve()`函数。这是告诉 GraphQL 运行时如何在需要时填充这些字段的方法。这两个字段只是返回属性值。

然后，有`GraphQLUser`类型。这个字段代表了用户在 UI 中的整个宇宙，因此得名。例如，`todos`字段是您如何从 Relay 组件查询待办事项的方式。它使用`connectionFromArray()`函数进行解析，这是一种快捷方式，可以省去更冗长的字段定义。然后，有`GraphQLRoot`类型。这有一个单一的`viewer`字段，用作所有查询的根。

现在让我们更仔细地看一下添加待办事项的突变，如下所示。出于篇幅考虑，我不会介绍此应用程序的 Web 版本中使用的每个突变：

```jsx
const GraphQLAddTodoMutation = mutationWithClientMutationId({
  name: 'AddTodo',
  inputFields: {
    text: { type: new GraphQLNonNull(GraphQLString) }
  },
  outputFields: {
    viewer: {
      type: GraphQLUser,
      resolve: getViewer
    },
    todoEdge: {
      type: GraphQLTodoEdge,
      resolve: ({ todoId }) => {
        const todo = getTodo(todoId);
        return {
          cursor: cursorForObjectInConnection(getTodos(), todo),
          node: todo
        };
      }
    }
  },
  mutateAndGetPayload: ({ text }) => {
    const todoId = addTodo(text);
    return { todoId };
  }
}); 
```

所有的突变都有一个`mutateAndGetPayload()`方法，这是突变实际上调用某个外部服务来改变数据的方法。返回的有效负载可以是已更改的实体，但也可以包括作为副作用而更改的数据。这就是`outputFields`发挥作用的地方。这是传递给 Relay 在浏览器中的信息，以便它有足够的信息来根据突变的副作用正确更新组件。别担心，您很快就会从 Relay 的角度看到这是什么样子。

您在这里创建的突变类型用于保存所有应用程序突变。最后，这是整个模式如何组合并从模块中导出的方式：

```jsx
export default new GraphQLSchema({
  query: GraphQLRoot,
  mutation: GraphQLMutation
}); 
```

现在不要担心将此模式馈送到 GraphQL 服务器中。

# 引导 Relay

此时，您的 GraphQL 后端已经启动运行。现在，您可以专注于前端的 React 组件。特别是，您将在 React Native 环境中查看 Relay，这实际上只有一些细微的差异。例如，在 Web 应用程序中，通常是`react-router`引导 Relay。在 React Native 中，情况有些不同。让我们看看作为本机应用程序入口点的`App.js`文件：

```jsx
import React from 'react';
import { View, Text } from 'react-native';
import { Network } from 'relay-local-schema';
import { Environment, RecordSource, Store } from 'relay-runtime';
import { QueryRenderer, graphql } from 'react-relay';

import schema from './data/schema';
import styles from './styles';
import TodoInput from './TodoInput';
import TodoList from './TodoList';

if (typeof Buffer === 'undefined')
  global.Buffer = require('buffer').Buffer;

const environment = new Environment({
  network: Network.create({ schema }),
  store: new Store(new RecordSource())
});

export default () => (
  <QueryRenderer
    environment={environment}
    query={graphql`
      query App_Query($status: String!) {
        viewer {
          ...TodoList_viewer
        }
      }
    `}
    variables={{ status: 'any' }}
    render={({ error, props }) => {
      if (error) {
        return <Text>Error!</Text>;
      }
      if (!props) {
        return <Text>Loading...</Text>;
      }
      return (
        <View style={styles.container}>
          <TodoInput environment={environment} {...props} />
          <TodoList {...props} />
        </View>
      );
    }}
  />
); 
```

让我们从这里开始分解发生的事情，从环境常量开始：

```jsx
const environment = new Environment({
  network: Network.create({ schema }),
  store: new Store(new RecordSource())
});
```

这是您与 GraphQL 后端通信的方式，通过配置网络。在这个例子中，您从`relay-local-schema`中导入`Network`，这意味着没有进行网络请求。这对于刚开始使用特别方便，尤其是构建 React Native 应用程序。

接下来是`QueryRenderer`组件。这个 Relay 组件用于渲染依赖于 GraphQL 查询的其他组件。它期望一个查询属性：

```jsx
query={graphql`
  query App_Query($status: String!) {
    viewer {
      ...TodoList_viewer
    }
  }
`}
```

请注意，查询是由它们所在的模块前缀的。在这种情况下，是`App`。这个查询使用了另一个模块`TodoList`中的 GraphQL 片段，并命名为`TodoList_viewer`。您可以向查询传递变量：

```jsx
variables={{ status: 'any' }}
```

然后，`render`属性是一个在 GraphQL 数据准备就绪时渲染组件的函数：

```jsx
render={({ error, props }) => {
  if (error) {
    return <Text>Error!</Text>;
  }
  if (!props) {
    return <Text>Loading...</Text>;
  }
  return (
    <View style={styles.container}>
      <TodoInput environment={environment} {...props} />
      <TodoList {...props} />
    </View>
  );
}}
```

如果出现问题，错误将包含有关错误的信息。如果没有错误和没有属性，那么可以安全地假定 GraphQL 数据仍在加载中。

# 添加待办事项

在`TodoInput`组件中，有一个文本输入框，允许用户输入新的待办事项。当他们输入完待办事项后，Relay 将需要向后端 GraphQL 服务器发送一个 mutation。以下是组件代码的样子：

```jsx
import React, { Component } from 'react';
import { TextInput } from 'react-native';

import styles from './styles';
import AddTodoMutation from './mutations/AddTodoMutation';

export default class App extends Component {
  onSubmitEditing = ({ nativeEvent: { text } }) => {
    const { environment, viewer } = this.props;
    AddTodoMutation.commit(environment, viewer, text);
  };

  render() {
    return (
      <TextInput
        style={styles.textInput}
        placeholder="What needs to be done?"
        onSubmitEditing={this.onSubmitEditing}
      />
    );
  }
} 
```

它看起来并不比您典型的 React Native 组件有多大的不同。突出的部分是 mutation——`AddTodoMutation`。这是告诉 GraphQL 后端您想要创建一个新的`todo`节点的方式。

让我们看看目前为止应用程序的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e3ff8741-63d2-4e06-804a-1bc807755549.png)

用于添加新待办事项的文本框就在待办事项列表的上方。现在，让我们看看`TodoList`组件，它负责渲染待办事项列表。

# 渲染待办事项

`TodoList`组件的工作是渲染待办事项列表项。当`AddTodoMutation`发生时，`TodoList`组件需要能够渲染这个新项目。Relay 负责更新内部数据存储，其中包含我们所有的 GraphQL 数据。再次查看项目列表，添加了几个更多的待办事项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/39f4da0a-c9ea-457a-8eaa-efea4c539730.png)

这是`TodoList`组件本身：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { View } from 'react-native';
import { createFragmentContainer, graphql } from 'react-relay';

import Todo from './Todo';

class TodoList extends Component {
  static propTypes = {
    viewer: PropTypes.object.isRequired,
    relay: PropTypes.object.isRequired
  };

  static contextTypes = {
    relay: PropTypes.shape({
      variables: PropTypes.shape({
        status: PropTypes.string.isRequired
      }).isRequired
    }).isRequired
  };

  render() {
    const { viewer } = this.props;
    return (
      <View>
        {viewer.todos.edges.map(edge => (
          <Todo key={edge.node.id} viewer={viewer} todo={edge.node} />
        ))}
      </View>
    );
  }
}

export default createFragmentContainer(
  TodoList,
  graphql`
    fragment TodoList_viewer on User {
      todos(status: $status, first: 2147483647)
        @connection(key: "TodoList_todos") {
        edges {
          node {
            id
            complete
            ...Todo_todo
          }
        }
      }
      id
      numTodos
      numCompletedTodos
      ...Todo_viewer
    }
  `
); 
```

获取所需数据的相关 GraphQL 作为第二个参数传递给`createFragmentContainer()`。这是组件的声明性数据依赖关系。当您渲染`<Todo>`组件时，您会将`edge.todo`数据传递给它。现在，让我们看看`Todo`组件本身是什么样子。

# 完成待办事项

这个应用程序的最后一部分是渲染每个待办事项并提供更改待办事项状态的能力。让我们看看这段代码：

```jsx
import React, { Component } from 'react';
import classNames from 'classnames';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Text, View, Switch } from 'react-native';

import ChangeTodoStatusMutation from './mutations/ChangeTodoStatusMutation';
import styles from './styles';

const completeStyleMap = new Map([
  [true, { textDecorationLine: 'line-through' }],
  [false, {}]
]);

class Todo extends Component {
  static propTypes = {
    viewer: PropTypes.object.isRequired,
    todo: PropTypes.object.isRequired,
    relay: PropTypes.object.isRequired
  };

  onValueChange = value => {
    const { relay, viewer, todo } = this.props;

    ChangeTodoStatusMutation.commit(
      relay.environment,
      viewer,
      todo,
      value
    );
  };

  render() {
    const {
      todo: { text, complete }
    } = this.props;

    return (
      <View style={styles.todoItem}>
        <Switch value={complete} onValueChange={this.onValueChange} />
        <Text style={completeStyleMap.get(complete)}>{text}</Text>
      </View>
    );
  }
}

export default createFragmentContainer(Todo, {
  viewer: graphql`
    fragment Todo_viewer on User {
      id
    }
  `,
  todo: graphql`
    fragment Todo_todo on Todo {
      id
      complete
      text
    }
  `
}); 
```

实际渲染的组件是一个开关控件和项目文本。当用户标记待办事项为完成时，项目文本会被划掉。用户也可以取消选中项目。`ChangeTodoStatusMutation`变异发送请求到 GraphQL 后端以更改`todo`状态。GraphQL 后端然后与任何需要使此操作发生的微服务进行通信。然后，它会响应此组件所依赖的字段。

我想指出的这段代码的重要部分是 Relay 容器中使用的片段。这个容器实际上并不直接使用它们。相反，它们被`TodoList`组件中的`todos`查询使用（`Todo.getFrament()`）。这很有用，因为这意味着您可以在另一个上下文中使用`Todo`组件，使用另一个查询，并且它的数据依赖关系总是会被满足。

# 摘要

在本章中，您实现了一些特定的 Relay 和 GraphQL 想法。从 GraphQL 模式开始，您学习了如何声明应用程序使用的数据以及这些数据类型如何解析为特定的数据源，例如微服务端点。然后，您学习了如何在 React Native 应用程序中从 Relay 引导 GraphQL 查询。接下来，您将详细了解如何添加、更改和列出待办事项。应用程序本身使用与 Todo 应用程序的 Web 版本相同的模式，这在开发 Web 和原生 React 应用程序时会更加容易。

好了，这本书就到这里了。我们一起学习了很多材料，我希望你从阅读中学到的东西和我从写作中学到的一样多。如果有一个主题是你应该记住的，那就是 React 只是一个渲染抽象。随着新的渲染目标出现，新的 React 库也会出现。随着开发人员想出处理大规模状态的新方法，你会看到新的技术和库发布。我希望你现在已经准备好在这个快速发展的 React 生态系统中工作了。


# 第二十七章：测试你的知识答案

# 第一章

1.  声明式 UI 结构是什么，React 如何支持这个想法？

1.  **声明式 UI 结构定义了 UI 组件是什么，而不是担心它是如何定义的。React 通过允许使用 JSX 语法声明组件来支持这个想法。**

1.  React 如何提高渲染性能？

1.  **React 具有虚拟 DOM，它比较内存中组件数据的更改，尽量避免浏览器 DOM。React 16 具有新的内部架构，允许将渲染分成更小的工作块并优先处理。**

1.  何时会渲染片段？

1.  **片段用于避免渲染不必要的 DOM 元素**

# 第二章

1.  您可以将所有标准 HTML 标签用作 JSX 元素吗？

1.  **是的，React 默认支持这一点**

1.  如何从组件中访问子元素？

1.  **通过 `children` 属性始终可以访问子 JSX 元素**

1.  React 中的 `Fragment` 组件是做什么的？

1.  **它作为一个容器组件，通过 否定 渲染无意义的元素， 如 容器 divs**

# 第三章

1.  为什么总是初始化组件的状态是一个好主意？

1.  **因为如果 `render()` 方法期望状态值，您需要确保它们始终存在，以避免意外的渲染行为。**

1.  何时应该使用属性而不是状态？

1.  **状态应该只用于可以改变的值。对于其他所有情况，应该使用属性。**

1.  在 React 中什么是上下文？

1.  **上下文用于避免瞬态属性。上下文用于与少数组件共享常见数据。**

# 第四章

1.  在 React 中，事件处理程序是什么使得它声明式的？

1.  **React 事件处理程序被声明为组件 JSX 的一部分**

1.  高阶事件处理程序函数的常见用途是什么？

1.  **当您有多个处理相同事件的组件时，可以使用高阶函数将被点击的项目的 ID 绑定到处理程序函数**

1.  您可以将内联函数传递给事件属性吗？

1.  **是的。当事件处理程序很简单时，这是更可取的。**

1.  为什么 React 使用事件实例池而不是在每个事件中创建新实例？

1.  **为了避免在 短时间内 触发大量事件时调用垃圾收集器来删除未使用的事件实例**

# 第五章

1.  为什么应该避免庞大的 React 组件？

1.  **因为它们难以理解，并且难以重构为以后可重用的较小组件。**

1.  为什么应该使组件功能化？

1.  **功能组件只依赖于传递给它的属性值。它们不依赖于状态或生命周期方法，这两者都是潜在的问题来源。**

1.  渲染道具如何简化 React 应用程序？

1.  **它们减少了组件的直接依赖数量，使您能够组合新的行为。**

# 第六章

1.  `render()`是一个生命周期方法吗？

1.  **是的，`render()`与任何其他生命周期方法没有区别。**

1.  以下哪项是`componentWillUnmount()`方法的有效用途？

1.  **取消异步操作，如果组件未挂载则会失败。**

1.  错误边界组件使用哪个生命周期方法？

1.  `**componentDidCatch()**`

# 第七章

1.  以下哪项最能描述`prop-types`包？

1.  **用于在开发过程中验证传递给组件的属性值。**

1.  如何验证属性值是否可以被渲染？

1.  **使用`PropTypes.node`验证器。**

1.  `PropTypes.shape`验证器的目的是什么？

1.  **确保对象具有特定类型的特定属性，忽略任何额外的属性。**

# 第八章

1.  何时应该继承组件状态？

1.  **只有当你有许多不同的组件都共享相同的状态结构，但渲染不同的输出时**

1.  什么是高阶组件？

1.  **返回另一个组件的组件**

1.  如果你从一个组件继承 JSX，你应该覆盖什么？

1.  **你可以在`componentDidMount()`中向继承的组件传递新的状态值。**

# 第九章

1.  `react-router`包是 React 应用程序中路由的官方包，因此是唯一的选择。

1.  **不，`react-router`是 React 的事实上的路由解决方案，除非你有充分的理由不使用它。**

1.  `Route`和`Router`组件之间有什么区别？

1.  **`Route`用于根据 URL 匹配渲染组件，`Router`用于声明路由-组件映射。**

1.  如何在路由更改时仅更改 UI 的某些部分？

1.  **您可以使用`Route`组件根据提供的`path`属性渲染特定于任何给定部分的内容。您可以有多个具有相同`path`值的`Route`。**

1.  何时应该使用`NavLink`组件？

1.  **当您想要使用`activeStyle`或`activeClassName`属性来为活动链接设置样式时**

1.  如何从 URL 路径中获取值？

1.  **您可以使用`: `语法来指定这是一个变量，`react-router`将将此值作为属性传递给您的组件**

# 第十章

1.  `react-dom`中的`render()`函数和`react-dom/server`中的`renderToString()`函数之间有什么区别？

1.  **`render()`函数仅用于在浏览器中将 React 组件内容与 DOM 同步。`renderToString()`函数不需要 DOM，因为它将标记呈现为字符串。**

1.  服务器端的路由是必要的，因为：

1.  **服务器上的路由将根据请求的 URL 确定渲染的内容。然后将此内容发送到浏览器，以便用户感知更快的加载时间。**

1.  在协调服务器端渲染的 React 标记与浏览器中的 React 组件时应该使用哪个函数？

1.  **当服务器发送渲染的 React 组件时，始终使用`hydrate()`。与`render()`不同，`hydrate()`期望渲染的组件标记并且可以有效地处理它。**

# 第十一章

1.  为什么 React 开发人员应该考虑移动优先的方法来设计他们的应用程序？

1.  **因为将移动设备作为应用程序的主要显示目标可以确保您可以处理移动设备，并且向更大的设备进行扩展比反之容易。**

1.  `react-router`与`react-bootstrap`集成良好吗？

1.  **是的。尽管您可能希望使用`react-router-bootstrap`包，以确保您可以将链接添加到`NavItem`和`MenuItem`组件中。**

1.  如何使用`react-bootstrap`渲染项目列表？

1.  使用`react-bootstrap`中的`ListGroup`和`ListGroupItem`组件。

1.  为什么应该为`react-bootstrap`表单组件创建一个抽象？

1.  **因为有许多相关的组件需要用于基本输入，创建这种抽象会让生活更容易。**

# 第十二章

1.  React Native 的主要目标是什么？

1.  **让 React 开发人员能够将他们已经了解的构建 UI 组件的知识应用到构建原生移动应用程序中。**

1.  React Native 在 iOS 和 Android 上提供完全相同的体验吗？

1.  **不，iOS 和 Android 有根本不同的用户体验。**

1.  React Native 是否消除了移动 Web 应用的需求？

1.  **不，移动 Web 应用程序始终需要。当您需要原生移动应用程序时，React Native 就在那里为您。**

# 第十三章

1.  **`create-react-native-app`**工具是由 Facebook 创建的

1.  **不，这是一个社区支持的工具，跟随** `create-react-app` **的脚步**

1.  为什么应该全局安装**`create-react-native-app`**？

1.  **因为这是一个用于生成项目样板的工具，实际上并不是项目的一部分**

1.  Expo 应用在移动设备上的作用是什么？

1.  **这是一个帮助开发人员在开发过程中在移动设备上运行其应用程序的工具，开销非常小**

1.  React Native 打包程序能够模拟 iOS 和 Android 设备

1.  **它不会这样做，但它会与 iOS 和 Android 模拟器通信以运行应用程序**

# 第十四章

1.  CSS 样式和 React Native 组件使用的样式有什么区别？

1.  **React Native 与 CSS 共享许多样式属性。样式属性在 React Native 中表示为普通对象属性**

1.  为什么在设计布局时需要考虑状态栏？

1.  **因为状态栏可能会干扰 iOS 上的组件**

1.  什么是 flexbox 模型？

1.  **flexbox 布局模型用于以一种抽象许多细节并自动对布局更改做出灵活响应的方式来布局组件**

1.  在考虑布局选项时，屏幕方向是否是一个因素？

1.  **是的，在开发过程中，始终需要确保在纵向或横向方向上没有意外情况**

# 第十五章

1.  在 React web 应用和 React Native 应用中导航的主要区别是什么？

1.  **Web 应用程序依赖于 URL 作为移动的中心概念。原生应用程序没有这样的概念，因此由开发人员和他们使用的导航库来管理他们的屏幕。**

1.  应该使用什么函数来导航到新屏幕？

1.  **屏幕组件会传递一个导航属性。您应该** **使用** `navigation.navigate()` **来移动到另一个屏幕。**

1.  react-navigation 是否为您处理返回按钮功能？

1.  **是的。包括 Android 系统上的内置返回按钮。**

1.  如何将数据传递给屏幕？

1.  **您可以将普通对象作为第二个参数传递给** `navigation.navigate()`。 **然后，通过** `navigation.getParam()` **可以访问这些属性。**

# 第十六章

1.  **`FlatList`**组件可以呈现什么类型的数据？

1.  **`FlatList`期望一个对象数组。`renderItem`属性接受一个负责渲染每个项目的函数。**

1.  为什么`key`属性是传递给`FlatList`的每个数据项的要求？

1.  **这样列表可以进行有效的相等性检查，有助于在列表数据更新期间提高渲染性能。**

1.  如何渲染在滚动期间保持固定位置的列表控件？

1.  **您可以使用`FlatList`的`ListHeaderComponent`属性。**

1.  当用户滚动列表时，如何懒加载更多数据？

1.  **您可以为`FlatList`的`onEndReached`属性提供一个函数。当用户接近列表的末尾时，将调用此函数，并且该函数可以使用更多数据填充列表数据。**

# 第十七章

1.  进度条和活动指示器有什么区别？

1.  **进度条是确定的，而进度指示器用于指示不确定的时间量。**

1.  React Native 的`ActivityIndicator`组件在 iOS 和 Android 上是否工作相同？

1.  **是的，这个组件是平台无关的。**

1.  如何以平台无关的方式使用`ProgressViewIOS`和`ProgressBarAndroid`组件？

1.  **您可以定义自己的`ProgressBar`组件，导入具有特定于平台的文件扩展名的其他组件。**

# 第十八章

1.  在 React Native 中找到的地理位置 API 的工作方式与 Web 浏览器中找到的地理位置 API 相同。

1.  **是的，它是相同的 API。**

1.  React Native 应用程序中地理位置 API 的主要目的是什么？

1.  **查找设备的纬度和经度坐标，并将这些值与其他 API 一起使用，以查找有用信息，比如地址。**

1.  `MapView`组件能够显示用户附近的兴趣点吗？

1.  **是的，默认情况下已启用。**

1.  如何在地图上标记点？

1.  **通过将纬度/经度数组数据作为属性传递给`MapView`组件。**

# 第十九章

1.  为什么要更改文本输入的虚拟键盘上的返回键？

1.  **因为在某些情况下，有一个搜索按钮或其他更符合输入上下文的东西是有意义的**

1.  应该使用哪个`TextInput`属性将输入标记为密码字段？

1.  `**secureTextEntry**`

1.  为什么要为选择元素创建抽象？

1.  **由于两个平台之间的样式挑战**

1.  为什么要为日期和时间选择器创建抽象？

1.  **因为 iOS 和 Android 的组件完全不同**

# 第二十章

1.  警报和模态之间有什么区别？

1.  警报在继承移动环境的外观和感觉方面做得很好，而模态是常规的 React Native 视图，您可以完全控制其样式。

1.  哪个 React Native 组件可用于创建覆盖屏幕上其他组件的模态视图？

1.  `Modal`组件。

1.  在 Android 系统上显示被动通知的最佳方法是什么？

1.  您可以使用`ToastAndroid` React Native API。在 iOS 上没有不涉及自己编写代码的好的替代方法。

1.  React Native Alert API 仅在 iOS 上可用。

1.  错误

# 第二十一章

1.  Web 应用程序和本机移动应用程序之间用户交互的主要区别是什么？

1.  没有鼠标。相反，用户使用手指与您的 UI 进行交互。这是一种根本不同于使用鼠标的体验，需要进行调整。

1.  如何在 React Native 中为用户提供触摸反馈？

1.  通过使用`TouchableOpacity`或`TouchableHighlight`组件包装可触摸组件。

1.  移动应用程序中的滚动比 Web 应用程序中的滚动复杂得多的原因是什么？

1.  在移动 Web 应用程序中滚动需要考虑诸如速度之类的因素，因为用户是用手指进行交互的。否则，交互会感觉不自然。

1.  为什么要使用`ScrollView`组件来实现可滑动行为？

1.  因为这是用户在移动 Web 应用程序中习惯的，以及他们学习 UI 控件的方式。

# 第二十二章

1.  `Image`组件的`source`属性接受哪些类型的值？

1.  图像组件接受本地文件和远程图像 URL 的路径。

1.  在图像加载时应该使用什么作为占位符？

1.  您应该使用在图像使用的上下文中有意义的占位图像。

1.  如何使用`Image`组件缩放图像？

1.  通过设置`width`和`height`属性，`Image`组件将自动处理图像的缩放。

1.  安装`react-native-vector-icons`包值得吗？

1.  是的，这个包为您的应用程序提供了数千个图标，并且图标是向用户传达意图的重要工具。

# 第二十三章

1.  为什么`AsyncStorage` API 中的操作是异步的？

1.  为了避免干扰 UI 的响应性。

1.  您会使用哪个`AsyncStorage` API 来一次查找多个项目？

1.  `AsyncStorage.getAllKeys()`和`AsyncStorage.multiGet()`的组合。

1.  在 React Native 应用程序中，如何获取设备的连接状态？

1.  您调用`NetInfo.getConnectionInfo()`并读取生成的连接类型。

1.  在 React Native 应用程序中如何响应连接状态的变化？

1.  您可以通过调用`NetInfo.addEventListener('connectionChange', ...)`来监听`connectionChange`事件。

# 第二十四章

1.  以下哪项最能描述 Flux？

1.  Flux 是一种用于控制应用程序中数据单向流动的架构模式，使变化更加可预测。

1.  Flux 和 Redux 之间有什么区别？

1.  Redux 是 Flux 概念的一种有偏见的实现，您可以使用它来帮助管理应用程序中的数据流。

1.  如何将 Redux 存储中的数据传递到您的组件中？

1.  您使用`connect()`高阶函数将您的组件连接到存储，使用一个将存储数据转换为组件属性的函数。

1.  Redux 在 Web 应用程序和原生移动应用程序中有什么区别？

1.  没有区别。

# 第二十五章

1.  Relay 和其他受 Flux 启发的库（如 Redux）之间有什么区别？

1.  Relay 通过允许数据依赖声明并隐藏所有服务器通信复杂性来帮助扩展您的 Flux 架构。

1.  Relay 如何简化 React 组件的数据需求？

1.  通过合并数据依赖查询，您可以准确地看到您的组件使用的所有数据，而无需查看执行获取操作的代码。

1.  在基于 Relay 的应用程序中，您的 React 组件如何与服务器通信？

1.  Relay 编译在您的组件中找到的 GraphQL 查询，并为您处理所有的 GraphQL 服务器通信，包括缓存优化。
