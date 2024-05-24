# Vue 与 GraphQL 应用构建指南（三）

> 原文：[`zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD`](https://zh.annas-archive.org/md5/60CC414A1AE322EC97E6A0F8A5BBE3AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：创建 Chat 和 Message Vuex、页面和路由

在本章中，我们将完成应用程序并创建最终部分。本章将完成应用程序的开发，使其准备好为部署创建最终产品。

在这里，您将学习如何创建 GraphQL 查询和片段，创建 Chat Vuex 模块和业务规则，创建联系人页面和页面中使用的组件，最后创建消息页面和创建页面所需的组件。

在本章中，我们将涵盖以下食谱：

+   创建 GraphQL 查询和片段

+   在您的应用程序上创建 Chat Vuex 模块

+   创建应用程序的联系人页面

+   创建应用程序的消息页面

# 技术要求

在本章中，我们将使用 Node.js，AWS Amplify 和 Quasar Framework。

注意，Windows 用户！您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装所需的包。要执行此操作，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装**Quasar Framework**，您需要打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @quasar/cli
```

要安装**AWS Amplify**，您需要打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @aws-amplify/cli
```

# 创建 GraphQL 查询和片段

在 GraphQL 中，可以创建一个简单的查询来获取您想要的数据。通过这样做，您的代码可以减少用户网络和处理能力的使用。这种技术也被称为**片段**。

在这个食谱中，我们将学习如何创建 GraphQL 片段并在我们的应用程序中使用它们。

## 准备工作

这个食谱的先决条件如下：

+   在第五章的食谱*为您的应用程序创建用户页面和路由*中的项目，创建用户 Vuex 模块、页面和路由

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要启动我们将在应用程序中使用的 GraphQL 片段，我们将继续使用我们在第五章中创建的项目，创建用户 Vuex 模块、页面和路由。

## 如何做...

在这个配方中，我们将创建应用程序中所需的片段，并用这里创建的片段替换我们在上一个配方中编写的一些代码。

### 创建 GraphQL 片段

在这里，我们将创建我们在应用程序中将使用的所有片段：

1.  在`src/graphql`文件夹中创建一个名为`fragments.js`的文件并打开它。

1.  然后，我们需要导入`graphql`语言解释器：

```js
import graphql from 'graphql-tag';
```

1.  让我们创建`getUser`片段来获取用户信息。这个片段将获取用户的基本信息。首先，我们需要启动`graphql`解释器，然后传递带有我们查询的模板文字字符串。使用`getUser`查询作为基本查询，我们将创建一个只包含我们想要从服务器获取的数据的查询模式：

```js
const getUser = graphql`
 query getUser($id: ID!) {
 getUser(id: $id) {
 id username avatar { bucket key region } email name } } `;
```

ES2015 规范中的模板文字提供了一个称为标记模板或标记函数的新功能。这些用于在使用附加到它的字符串之前预处理模板文字上的字符串。

1.  然后我们将创建`listUsers`片段来获取应用程序中的所有用户。这个片段将使用从 AWS Amplify 创建的基本查询中的`listUsers`查询。然后它将返回我们应用程序中所有当前用户的基本信息：

```js
const listUsers = graphql`
 query listUsers { listUsers { items { id username name createdAt avatar { bucket region key } } } } `;
```

1.  为了完成用户片段，我们将创建`getUserAndConversations`片段来获取用户的基本信息和他们最近的 10 次对话。这个片段基于`GetUser`查询：

```js
const getUserAndConversations = graphql`
 query getUserAndConversations($id:ID!) {
 getUser(id:$id) {
 id username conversations(limit: 10) {
 items { id conversation { id name associated { items { user { id name email avatar { bucket key region } } } } } } } } } `;
```

1.  为了获取用户对话，我们将创建一个名为`getConversation`的片段，基于`GetConversation`查询，从当前对话 ID 的用户那里获取最后 1,000 条消息和对话成员：

```js
const getConversation = graphql`
 query GetConversation($id: ID!) {  getConversation(id:$id) {  id name members messages(limit: 1000) {  items {  id content author {  name avatar {  bucket key region  }
 }  authorId messageConversationId createdAt  }
 }  createdAt updatedAt  }
 } `;
```

1.  要在我们的 API 中创建新的消息，我们需要创建一个名为`createMessage`的片段。这个片段基于`CreateMessage`变异。片段将接收`id`、`authorId`、`content`、`messageConversationId`和`createdAt`：

```js
const createMessage = graphql`mutation CreateMessage(
  $id: ID,
  $authorId: String,
  $content: String!,
  $messageConversationId: ID!
  $createdAt: String, ) {  createMessage(input: {
  id: $id,
  authorId: $authorId
 content: $content,
  messageConversationId: $messageConversationId,
  createdAt: $createdAt,
  }) {  id authorId content messageConversationId createdAt  } } `;
```

1.  要在两个用户之间开始新的对话，我们需要创建一个名为`createConversation`的新片段。这个片段基于`CreateConversation`变异；它将接收对话的`name`和正在创建的对话的`members`列表：

```js
const createConversation = graphql`mutation CreateConversation($name: String!, $members: [String!]!) {  createConversation(input: {
  name: $name, members: $members
  }) {  id name members  } } `;
```

1.  然后，我们将使用基于 CreateConversationLink 变异的 createConversationLink 片段完成我们的片段。此片段将链接在我们的应用程序中创建的对话并生成唯一 ID。为使其工作，此片段需要接收 conversationLinkConversationId 和 conversationLinkUserId：

```js
const createConversationLink = graphql`mutation CreateConversationLink(
  $conversationLinkConversationId: ID!,
  $conversationLinkUserId: ID ) {  createConversationLink(input: {
  conversationLinkConversationId: $conversationLinkConversationId,
  conversationLinkUserId: $conversationLinkUserId
  }) {  id conversationLinkUserId conversationLinkConversationId conversation {  id name  }
 } } `;
```

1.  最后，我们将导出我们创建的所有片段到 JavaScript 对象中：

```js
export {
  getUser,
  listUsers,
  getUserAndConversations,
  getConversation,
  createMessage,
  createConversation,
  createConversationLink, };  
```

### 将片段应用于 User Vuex 操作

现在我们可以更新 User Vuex 操作以使用我们创建的片段：

1.  在 store/user 文件夹中打开 actions.js 文件。

1.  在`import`部分，我们将从 src/graphql/queries 替换 getUser 和 listUsers 为新创建的 src/graphql/fragments。

```js
import { listUsers, getUser } from 'src/graphql/fragments';
```

## 它是如何工作的...

使用 GraphQL 查询语言，我们能够创建小查询和变异，称为片段，可以执行原始查询或变异的部分，并返回相同的响应，但包含我们请求的数据。

通过这样做，我们的应用程序数据使用量减少了，遍历数据的处理能力也减少了。

GraphQL 片段与作为基础的查询或变异相同。这是因为 GraphQL 使用相同的模式、查询和变异作为基础。通过这样做，您可以在搜索和变异中使用在查询或变异中声明的相同变量。

因为我们在替换 User Vuex 操作中导入的代码时使用了相同的名称作为基础查询，所以我们不需要更改任何内容，因为请求的结果将与旧的结果相同。

## 另请参阅

+   在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals)找到有关模板文字标签函数的更多信息。

+   在[`graphql.org/learn/queries/`](https://graphql.org/learn/queries/)找到有关 GraphQL 查询、变异和片段的更多信息。

# 在您的应用程序上创建 Chat Vuex 模块

要创建聊天应用程序，我们需要为应用程序的聊天部分创建自定义业务规则。这部分将包含获取新消息、发送消息和在用户之间开始新对话的所有逻辑。

在这个教程中，我们将在应用程序的 Vuex 中创建 Chat 模块，其中我们将存储已登录用户和其他用户之间的所有消息，获取新消息，发送新消息，并开始新对话。

## 准备工作

此教程的先决条件如下：

+   来自上一个教程的项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

为了开始我们的 Chat Vuex 模块，我们将继续使用在 *创建 GraphQL 查询和片段* 教程中创建的项目。

## 如何做...

为了创建 Chat Vuex 模块，我们将把任务分成五个部分：创建 **state**、**mutations**、**getters** 和 **actions**，然后将模块添加到 Vuex。

### 创建 Chat Vuex 状态

为了在 Vuex 模块上存储数据，我们需要一个具有存储数据的状态。在这里，我们将创建 Chat 状态：

1.  在 store 文件夹中创建一个名为 `chat` 的新文件夹，然后创建一个名为 `state.js` 的新文件，并打开它。

1.  创建一个名为 `createState` 的新函数，它返回一个具有 `conversations`、`messages`、`loading` 和 `error` 属性的 JavaScript 对象。`conversations` 和 `messages` 属性将被定义为空数组，`loading` 属性将被定义为 `false`，`error` 为 `undefined`：

```js
export function createState() {
  return {
  conversations: [],
  messages: [],
  loading: false,
  error: undefined,
  }; }
```

1.  最后，为了将状态导出为单例，并将其作为 JavaScript 对象可用，我们需要将 `createState` 函数的执行导出为默认值：

```js
export default createState();
```

### 创建 Chat Vuex mutations

现在要在状态上保存任何数据，Vuex 需要一个 mutation。为此，我们将创建 Chat mutation，用于管理此模块的 mutations：

1.  在 store/chat 文件夹中创建一个名为 `types.js` 的新文件，并打开它。

1.  在文件中，导出一个默认的 JavaScript 对象，其属性与字符串的值相同。属性将是 `SET_CONVERSATIONS`、`SET_MESSAGES`、`LOADING` 和 `ERROR`：

```js
export default {
  SET_CONVERSATIONS: 'SET_CONVERSATIONS',
  SET_MESSAGES: 'SET_MESSAGES',
  LOADING: 'LOADING',
  ERROR: 'ERROR', };
```

1.  在 store/chat 文件夹中创建一个名为 `mutations.js` 的新文件，并打开它。

1.  导入新创建的 `types.js` 文件：

```js
import MT from './types';
```

1.  创建一个名为 `setLoading` 的新函数，以 `state` 作为第一个参数。在其中，我们将定义 `state.loading` 为 `true`：

```js
function setLoading(state) {
 state.loading = true; }
```

1.  创建一个名为 `setError` 的新函数，以 `state` 作为第一个参数，`error` 作为第二个参数，其默认值为 `new Error()`。在其中，我们将定义 `state.error` 为 `error`，并将 `state.loading` 定义为 `false`：

```js
function setError(state, error = new Error()) {
 state.error = error;
  state.loading = false; }
```

1.  创建一个名为`setConversations`的新函数，第一个参数是`state`，第二个参数是 JavaScript 对象，具有`items`属性。通过这样做，我们将使用接收到的数组定义状态对话：

```js
function setConversations(state, payload) {
 state.conversations = payload.items;
  state.loading = false; }
```

1.  创建一个名为`setMessages`的新函数，第一个参数是`state`，第二个参数是 JavaScript 对象。在这个函数中，我们将尝试查找是否有与`payload`中接收到的`id`相等的消息，并将消息添加到状态中：

```js
function setMessages(state, payload) {
  const messageIndex = state.messages.findIndex(m => m.id === 
   payload.id);    if (messageIndex === -1) {
 state.messages.push(payload);
  } else {
 state.messages[messageIndex].messages.items = payload.messages.items;
  }
 state.loading = false; }
```

1.  最后，导出一个默认的 JavaScript 对象，其中键是导入的 mutation 类型，值是对应于每种类型的函数：

+   将`MT.LOADING`定义为`setLoading`。

+   将`MT.ERROR`定义为`setError`。

+   将`MT.SET_CONVERSATION`定义为`setConversations`。

+   将`MT.SET_MESSAGES`定义为`setMessages`：

```js
export default {
  [MT.LOADING]: setLoading,
  [MT.ERROR]: setError,
  [MT.SET_CONVERSATIONS]: setConversations,
  [MT.SET_MESSAGES]: setMessages, };
```

### 创建 Chat Vuex getters

访问存储在状态中的数据，我们需要创建`getters`。在这里，我们将为 Chat 模块创建`getters`：

在`getter`函数中，该函数将接收的第一个参数始终是 Vuex `store`的当前`state`。

1.  在`store/chat`文件夹中创建一个名为`getters.js`的新文件。

1.  创建一个名为`getConversations`的新函数。该函数首先接收`state`，`_getters`，`_rootState`和`rootGetters`作为柯里化函数的第一部分。最后，它将返回用户和应用程序中另一个用户之间的对话的筛选列表：

```js
const getConversations = (state, _getters, _rootState, rootGetters) => {
  const { conversations } = state;
  return conversations
  .reduce((acc, curr) => {
  const { conversation } = curr;    const user = rootGetters['user/getUser'].id;    const users = conversation
  .associated
        .items
        .reduce((a, c) => [...a, { ...c.user, conversation: 
           conversation.id }], [])
  .filter(u => u.id !== user);    return [...acc, users];
  }, [])
  .flat(Infinity); };
```

`_variable`（下划线变量）是 JavaScript 中用于指示创建的函数可以具有这些参数，但目前不会使用它们的技术。在我们的情况下，Vuex getters API 始终执行每个 getter 调用，传递`state`，`getters`，`rootState`和`rootGetters`，因为根据 linter 规则，我们为未使用的参数添加了下划线。

1.  创建一个名为`getChatMessages`的新函数，这是一个使用方法调用的 getter。首先，我们传递`state`，然后返回一个接收`convId`的函数。最后，它将返回该对话 ID 的消息列表：

```js
const getChatMessages = (state) => (convId)  => (state.messages.length ? state.messages
  .find(m => m.id === convId).messages.items : []);
```

1.  创建一个名为`isLoading`的新函数，返回`state.loading`：

```js
const isLoading = (state) => state.loading;
```

1.  创建一个名为`hasError`的新函数，返回`state.error`：

```js
const hasError = (state) => state.error;
```

1.  最后，导出一个默认的 JavaScript 对象，其中包含创建的函数作为属性：`getConversations`，`getChatMessages`，`isLoading`和`hasError`：

```js
export default {
  getConversations,
  getChatMessages,
  isLoading,
  hasError, };  
```

### 创建 Chat Vuex actions

在这里，我们将创建 Chat 模块的 Vuex actions：

1.  在`store/chat`文件夹中创建一个名为`actions.js`的文件，并打开它。

1.  首先，我们需要导入在这部分中要使用的函数、枚举和类：

+   从`aws-amplify`包中导入`graphqlOperation`。

+   从`src/graphql/fragments.js`导入`getUserAndConversations`，`createConversation`，`createConversationLink`，`createMessage`和`getConversation`。

+   从`driver/auth.js`导入`getCurrentAuthUser`函数。

+   从`driver/appsync`导入`AuthAPI`。

+   从`./types.js`导入 Vuex 变异类型：

```js
import { graphqlOperation } from 'aws-amplify';
import {
  getUserAndConversations,
  createConversation,
  createConversationLink,
  createMessage,
  getConversation,
} from 'src/graphql/fragments';
import {
  getCurrentAuthUser,
} from 'src/driver/auth';
import { uid } from 'quasar';
import { AuthAPI } from 'src/driver/appsync';
import MT from './types';
```

1.  创建一个名为`newConversation`的异步函数。在第一个参数中，我们将添加`_vuex`，并使用一个 JavaScript 对象作为第二个参数，接收`authorId`和`otherUserId`作为属性。在这个函数中，我们将根据接收到的载荷创建一个新的对话。然后我们需要创建对话和对话中用户之间的关系。最后，我们返回对话的 ID 和名称：

```js
async function newConversation(_vuex, { authorId, otherUserId }) {
  try {
  const members = [authorId, otherUserId];    const conversationName = members.join(' and ');    const {
    data: {
      createConversation: {
        id: conversationLinkConversationId,
      },
    },
  } = await AuthAPI.graphql(
    graphqlOperation(createConversation,
      {
        name: conversationName,
        members,
      }),
  );    const relation = { conversationLinkConversationId };    await Promise.all([
    AuthAPI.graphql(
      graphqlOperation(createConversationLink, {
        ...relation,
        conversationLinkUserId: authorId,
      }),
    ),
    AuthAPI.graphql(
      graphqlOperation(createConversationLink, {
        ...relation,
        conversationLinkUserId: otherUserId,
      }),
    )]);    return Promise.resolve({
    id: conversationLinkConversationId,
    name: conversationName,
  });
  } catch (e) {
  return Promise.reject(e);
  } }
```

1.  为了向用户发送新消息，我们需要创建一个名为`newMessage`的异步函数。这个函数将在第一个参数中接收一个解构的 JavaScript 对象，其中包含`commit`变量，并作为第二个参数，另一个解构的 JavaScript 对象，其中包含`message`和`conversationId`属性。然后，在函数中，我们需要获取用户的`username`并返回 GraphQL 的`createMessage`变异，传递变量，其中`id`定义为`uid()`，`authorID`定义为`username`，`content`定义为`message`，`messageConversationId`定义为`conversationId`，`createdAt`定义为`Date.now()`：

```js
async function newMessage({ commit }, { message, conversationId }) {
  try {
  commit(MT.LOADING);    const { username } = await getCurrentAuthUser();    return AuthAPI.graphql(graphqlOperation(
    createMessage,
    {
      id: uid(),
      authorId: username,
      content: message,
      messageConversationId: conversationId,
      createdAt: Date.now(),
    },
  ));
  } catch (e) {
  return Promise.reject(e);
  } finally {
  commit(MT.LOADING);
  } }
```

1.  为了获取初始用户消息，我们需要创建一个名为`getMessages`的异步函数。这个函数将在第一个参数中接收一个解构的 JavaScript 对象，其中包含`commit`变量。在这个函数内部，我们需要获取经过身份验证的用户的`id`，然后执行 GraphQL 的`getUserAndConversations`变异来获取所有当前用户的`conversations`，将它们传递给变异，并返回它们：

```js
async function getMessages({ commit }) {
  try {
  commit(MT.LOADING);    const { id } = await getCurrentAuthUser();    const {
    data: {
      getUser: {
        conversations,
      },
    },
  } = await AuthAPI.graphql(graphqlOperation(
    getUserAndConversations,
    {
      id,
    },
  ));    commit(MT.SET_CONVERSATIONS, conversations);    return Promise.resolve(conversations);
  } catch (err) {
  commit(MT.ERROR, err);
  return Promise.reject(err);
  } }
```

1.  然后我们需要完成聊天操作，创建`fetchNewMessages`函数。这个异步函数将在第一个参数中接收一个解构的 JavaScript 对象，其中包含`commit`变量，第二个参数包含`conversationId`属性。在这个函数中，我们将使用 GraphQL 的`getConversation`查询通过传递对话 ID 来获取对话中的消息。最后，接收到的消息数组将通过 Vuex 的`SET_MESSAGES`mutation 添加到状态中，并返回`true`：

```js
async function fetchNewMessages({ commit }, { conversationId }) {
  try {
  commit(MT.LOADING);    const { data } = await AuthAPI.graphql(graphqlOperation(
    getConversation,
    {
      id: conversationId,
    },
  ));    commit(MT.SET_MESSAGES, data.getConversation);    return Promise.resolve(true);
  } catch (e) {
  return Promise.reject(e);
  } }
```

1.  最后，我们将导出所有创建的函数：

```js
export default {
  newConversation,
  newMessage,
  getMessages,
  fetchNewMessages, }; 
```

### 将 Chat 模块添加到 Vuex

现在我们将 Chat 模块导入到 Vuex 状态管理中：

1.  在`store/chat`文件夹中创建一个名为`index.js`的新文件。

1.  导入我们刚刚创建的`state.js`、`actions.js`、`mutation.js`和`getters.js`文件：

```js
import state from './state'; import actions from './actions'; import mutations from './mutations'; import getters from './getters';
```

1.  创建一个带有 JavaScript 对象的`export default`，其中属性为`state`、`actions`、`mutations`、`getters`和`namespaced`（定义为`true`）：

```js
export default {
  namespaced: true,
  state,
  actions,
  mutations,
  getters, };  
```

1.  打开`store`文件夹中的`index.js`文件。

1.  将新创建的`index.js`文件导入到`store/chat`文件夹中：

```js
import Vue from 'vue'; import Vuex from 'vuex'; import user from './user';
import chat form './chat';
```

1.  在创建 Vuex 存储时，添加一个名为`modules`的新属性，并将导入的用户文件添加到此属性中：

```js
export default function (/* { ssrContext } */) {
  const Store = new Vuex.Store({
  modules: {
  user,
      chat,
  },
  strict: process.env.DEV,
  });    return Store; }  
```

## 它是如何工作的...

在这个示例中，我们创建了 Chat Vuex 模块。该模块包括了管理应用程序内对话和消息所需的所有业务逻辑。

在 Vuex 操作中，我们使用了**AppSync API Driver**和 GraphQL 片段来创建新的对话和消息，并在 API 上获取它们。在获取后，所有消息和对话都通过 Vuex mutations 存储在 Vuex 状态中。

最后，所有数据都可以通过 Vuex getter 访问到。getter 被开发为柯里化函数，因此在执行时可以访问状态并在其中进行搜索，以获取对话消息，并使用完整的 API 获取用户对话。

## 另请参阅

+   在[`vuex.vuejs.org/api/#getters`](https://vuex.vuejs.org/api/#getters)找到有关 Vuex getters API 的更多信息。

+   在[`vuex.vuejs.org/guide/getters.html#method-style-access`](https://vuex.vuejs.org/guide/getters.html#method-style-access)找到有关 Vuex getters 方法数据访问的更多信息。

# 创建应用程序的联系人页面

在聊天应用程序中，通常会有一个起始页面，用户可以从旧对话中选择继续发送消息，或者开始新的对话。这种做法可以作为应用程序的主页面。在我们的应用程序中，也不会有所不同。

在这个示例中，我们将创建一个联系人页面，用户可以使用它来开始对话或继续旧对话。

## 准备工作

这个示例的先决条件如下：

+   来自上一个示例的项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的用户联系人页面，我们将继续使用在*在应用程序中创建 Chat Vuex 模块*示例中创建的项目。

## 操作步骤...

在这个示例中，我们需要将我们的工作分为两部分：首先是一个新的组件来开始新的对话，最后是联系人页面本身。

### 创建 NewConversation 组件

首先，我们需要创建一个组件，在应用程序中的用户和另一个用户之间开始新的对话。

#### 单文件组件<script>部分

在这里，我们将创建组件的`<script>`部分：

1.  在`src/components`文件夹中创建一个名为`NewConversation.vue`的新文件并打开它。

1.  从`vuex`中导入`mapActions`和`mapGetters`：

```js
import { mapActions, mapGetters } from 'vuex';
```

1.  导出一个带有七个属性的`default`JavaScript 对象：`name`，`props`，`data`，`watch`，`computed`和`methods`：

```js
export default {
  name: 'NewConversation',
  components: {},
  props: {},
  data: () => ({}),
  watch: {},
  computed: {},
  methods: {},
};
```

1.  在`components`属性中，将`AvatarDisplay`组件导入为 lazyload 组件：

```js
components: {
  AvatarDisplay: () => import('components/AvatarDisplay'), },
```

1.  在`props`属性中，我们将添加一个名为`value`的新属性，类型为`Boolean`，默认值为`false`：

```js
props: {
  value: {
  type: Boolean,
  default: false,
  }, },
```

1.  在`data`属性上，我们需要定义两个属性：`userList`作为一个数组，`pending`作为一个布尔值，定义为`false`：

```js
data: () => ({
  userList: [],
  pending: false, }),
```

1.  在`methods`属性中，首先，我们将从用户模块中解构`mapActions`调用`listAllUsers`函数。然后我们将对聊天模块做同样的操作，调用`newConversation`函数。现在我们将创建一个名为`fetchUser`的异步函数，设置组件为`pending`，获取所有用户，并将`userList`设置为过滤掉当前用户的响应。最后，我们需要创建一个名为`createConversation`的异步函数，它接收一个`otherUserId`参数，创建一个新的对话，并将用户重定向到消息页面：

```js
methods: {
  ...mapActions('user', ['listAllUsers']),
  ...mapActions('chat', ['newConversation']),
  async fetchUsers() {
  this.pending = true;
  try {
  const users = await this.listAllUsers();
  this.userList = users.filter((u) => u.id !== this.getUser.id);
  } catch (e) {
  this.$q.dialog({
  message: e.message,
  });
  } finally {
  this.pending = false;
  }
 },
  async createConversation(otherUserId) {
  try {
  const conversation = await this.newConversation({
  authorId: this.getUser.id,
 otherUserId,
  });
 await this.$router.push({
  name: 'Messages',
  params: conversation,
  });
  } catch (e) {
  this.$q.dialog({
  message: e.message,
  });
  }
 }, },
```

1.  在`computed`属性上，首先，我们将从用户模块调用`getUser`解构`mapGetters`。然后我们将对聊天模块的`getConversations`做同样的操作。现在我们将创建一个名为`contactList`的函数，它返回当前`userList`，并通过当前用户已经开始对话的用户进行筛选：

```js
computed: {
  ...mapGetters('user', ['getUser']),
  ...mapGetters('chat', ['getConversations']),
  contactList() {
  return this.userList
      .filter((user) => this.getConversations
        .findIndex((u) => u.id === user.id) === -1);
  }, },
```

1.  最后，在`watch`属性上，我们将添加一个名为`value`的异步函数，它接收一个名为`newVal`的参数。这个函数检查`newVal`的值是否为`true`；如果是，它将在 API 中获取用户列表：

```js
watch: {
  async value(newVal) {
  if (newVal) {
  await this.fetchUsers();
  }
 }, },
```

#### 单文件组件的<template>部分

现在让我们为`NewConversation`组件创建`<template>`部分：

1.  创建一个带有`value`属性定义为`value`的`QDialog`组件。还创建一个事件监听器`input`，定义为`$emit`函数，发送带有`$event`作为数据的`'input'`事件：

```js
<q-dialog
  :value="value"
  @input="$emit('input', $event)" ></q-dialog>
```

1.  在`QDialog`组件内部，创建一个带有`style`属性定义为`min-width: 400px; min-height: 100px;`的`QCard`组件。在`QCard`组件内部，创建两个`QCardSection`子组件。在第一个组件中，添加一个`class`属性定义为`row items-center q-pb-none`：

```js
<q-card
  style="min-width: 400px; min-height: 100px" >
 <q-card-section class="row items-center q-pb-none">
 </q-card-section>  <q-card-section></q-card-section>
</q-card>
```

1.  在第一个`QCardSection`组件上，添加一个带有`class`属性定义为`text-h6`的`div`，并将内部 HTML 定义为`New Conversation`。然后添加一个`QSpace`组件。最后，添加一个带有`icon`属性定义为`close`的`QBtn`，并将`flat`、`round`和`dense`属性定义为`true`，并添加`v-close-popup`指令：

```js
<q-card-section class="row items-center q-pb-none">
 <div class="text-h6">New Conversation</div>
 <q-space/>
 <q-btn icon="close" flat round dense v-close-popup/> </q-card-section>
```

1.  在第二个`QCardSection`组件中，创建一个带有`QItem`子组件的`QList`组件。在`QItem`子组件中，添加一个`v-for`指令来迭代`contactList`。然后将`key`变量属性定义为`contact.id`，`class`属性定义为`q-my-sm`，并将`clickable`定义为`true`**。**添加`v-ripple`指令。最后，在`click`事件上添加一个事件监听器，调度`createConversation`方法并发送`contact.id`作为参数：

```js
<q-list>
 <q-item
  v-for="contact in contactList"
  :key="contact.id"
  class="q-my-sm"
  clickable
 v-ripple @click="createConversation(contact.id)"
  ></q-item>
</q-list>
```

1.  在`QItem`组件内部，创建一个带有`avatar`属性定义为`true`的`QItemSection`组件。然后创建一个`QAvatar`组件作为子组件，以及一个`AvatarDisplay`组件作为`QAvatar`的子组件。在`AvatarDisplay`组件上，添加一个`avatar-object`动态属性作为`contact.avatar`，以及一个`name`动态属性作为`contact.name`：

```js
<q-item-section avatar>
  <q-avatar>
  <avatar-display
    :avatar-object="contact.avatar"
    :name="contact.name"
  />
  </q-avatar> </q-item-section>
```

1.  在第一个`QItemSection`组件之后，创建另一个作为同级元素的`QItemSection`。在这个`QItemSection`内，添加两个`QItemLabel`组件。对于第一个，将`contact.name`添加为内部 HTML，对于第二个，将`caption`属性设置为`true`，`lines`设置为`1`，内部 HTML 设置为`contact.email`：

```js
<q-item-section>
 <q-item-label>{{ contact.name }}</q-item-label>
 <q-item-label caption lines="1">{{ contact.email }}</q-item-label> </q-item-section>
```

1.  然后创建另一个作为第三个同级元素的`QItemSection`组件，其中`side`属性设置为`true`。在其中添加一个`name`属性设置为`add_comment`，`color`设置为`green`的`QIcon`组件：

```js
<q-item-section side>
 <q-icon name="add_comment" color="green"/> </q-item-section>
```

1.  最后，作为`QList`组件的同级元素，创建一个带有`showing`属性定义为`pending`的`QInnerLoading`组件。在其中添加一个`size`属性设置为`50px`，`color`属性定义为`primary`的`QSpinner`组件：

```js
<q-inner-loading
  :showing="pending">
 <q-spinner
  size="50px"
  color="primary"/> </q-inner-loading>
```

这是您组件的渲染版本：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/6d55d973-123f-4f66-9d1d-f3448259fb78.png)

### 创建联系人页面

现在是创建联系人页面的时候了。这个页面将是已认证用户应用程序的初始页面。在这里，用户可以转到用户更新页面，进入并恢复旧对话，或创建新对话。

#### 单文件组件 <script> 部分

在这里，我们将创建单文件组件的`<script>`部分，它将成为联系人页面：

1.  在`src/pages`文件夹中打开`Contacts.vue`文件。在文件的`<script>`部分中，从`vuex`中导入`mapActions`和`mapGetters`：

```js
import { mapActions, mapGetters } from 'vuex';
```

1.  导出一个带有这些属性的`default` JavaScript 对象：`name`，`mixins`，`components`，`data`，`mounted`和`methods`。将`name`属性定义为`ChatContacts`，在`mixins`属性中，添加导入的`getAvatar`混合的数组。在`components`属性中，添加两个新属性，`NewConversation`和`AvatarDisplay`，它们将接收一个返回导入组件的匿名函数。最后，在`data`属性上，创建一个具有`dialogNewConversation`属性和值为`false`的对象：

```js
export default {
  name: 'ChatContacts',
  components: {
  AvatarDisplay: () => import('components/AvatarDisplay'),
  NewConversation: () => import('components/NewConversation'),
  },
  data: () => ({
  dialogNewConversation: false,
  }),
  async mounted() {},
  computed: {},
  methods: {}, };
```

1.  在`computed`属性中，首先，我们将通过调用`getUser`从用户模块中解构`mapGetters`。然后我们将对聊天模块的`getConversations`做同样的操作：

```js
computed: {
  ...mapGetters('user', ['getUser']),
  ...mapGetters('chat', ['getConversations']), },
```

1.  在`methods`属性中，我们将通过调用`getMessages`函数从聊天模块中解构`mapActions`：

```js
methods: {
  ...mapActions('chat', [
  'getMessages',
  ]), },
```

1.  最后，在`mounted`生命周期钩子上，我们需要将其设置为异步，并调用`getMessage`函数：

```js
async mounted() {
  await this.getMessages(); },
```

#### 单文件组件 <template> 部分

现在，让我们为页面创建`<template>`部分：

1.  创建一个`QPage`组件，然后将一个带有`bordered`属性定义为`true`的`QList`组件作为子元素添加：

```js
<q-page>
 <q-list bordered>
 </q-list> </q-page> 
```

1.  在`QList`组件内部，创建一个带有`v-for`指令的`QItem`组件，迭代`getConversations`。将组件属性定义如下：`key`为`contact.id`，`to`为包含路由目标信息的 JavaScript 对象，`class`为`q-my-sm`，`clickable`为`true`，然后添加`v-ripple`指令：

```js
<q-item
  v-for="contact in getConversations"
  :key="contact.id"
  :to="{
  name: 'Messages',
  params: {
  id: contact.conversation,
  name: contact.name,
  },
  }"
  class="q-my-sm"
  clickable
 v-ripple ></q-item>
```

1.  在`QItem`组件内部，创建一个`QItemSection`组件，其中`avatar`属性定义为`true`。然后创建一个`QAvatar`组件作为子组件，以及一个`AvatarDisplay`组件作为`QAvatar`的子组件。在`AvatarDisplay`组件上，添加一个`avatar-object`动态属性作为`contact.avatar`，以及一个`name`动态属性作为`contact.name`：

```js
<q-item-section avatar>
  <q-avatar>
  <avatar-display
    :avatar-object="contact.avatar"
    :name="contact.name"
  />
  </q-avatar> </q-item-section>
```

1.  在第一个`QItemSection`之后，创建另一个`QItemSection`作为兄弟元素。在这个`QItemSection`内部，添加两个`QItemLabel`组件。在第一个组件上，将`contact.name`作为内部 HTML，而在第二个组件上，将`caption`属性定义为`true`，`lines`定义为`1`，内部 HTML 为`contact.email`。

```js
<q-item-section>
 <q-item-label>{{ contact.name }}</q-item-label>
 <q-item-label caption lines="1">{{ contact.email }}</q-item-label> </q-item-section>
```

1.  然后创建另一个`QItemSection`组件作为第三个兄弟元素，其中`side`属性定义为`true`。在其中添加一个`QIcon`组件，其中`name`属性为`chat_bubble`，`color`为`green`：

```js
<q-item-section side>
  <q-icon name="chat_bubble" color="green"/> </q-item-section>
```

1.  最后，作为`QList`组件的兄弟元素，创建一个`QPageSticky`组件，其中`position`属性定义为`bottom-right`，`offset`为`[18, 18]`。在组件内部，创建一个新的子`QBtn`组件，其中`fab`属性定义为`true`，`icon`为`chat`，`color`为`accent`，并且`click`事件监听器将`dialogNewConversation`更改为当前`dialogNewConversation`的否定。然后，将`NewConversation`组件作为`QBtn`的兄弟元素，其中`v-model`指令定义为`dialogNewConversation`：

```js
<q-page-sticky position="bottom-right" :offset="[18, 18]">
 <q-btn
  fab
 icon="chat"
  color="accent"
  @click="dialogNewConversation = !dialogNewConversation"
  />
 <new-conversation
  v-model="dialogNewConversation"
  /> </q-page-sticky>
```

这是页面预览的样子：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/123f4c54-4631-4265-ad02-afdca75ceaa9.png)

## 它是如何工作的...

联系人页面作为所有创建的 Vuex 模块的聚合，使用户可以更好地体验应用程序。该页面包含用户最初导航和开始使用应用程序所需的所有信息。

`NewConversation`组件的`<template>`部分与联系人页面的`<template>`部分之间的相似之处是有意为之，这样用户在创建新对话和查看当前联系人列表时有相同的体验。

混合使用对于使代码更清晰，减少代码重复并使代码更简单重用至关重要。

## 另请参阅

+   在[`quasar.dev/vue-components/button`](https://quasar.dev/vue-components/button)找到有关 Quasar `QBtn`组件的更多信息。

+   在[`quasar.dev/vue-components/dialog`](https://quasar.dev/vue-components/dialog)找到有关 Quasar `QDialog`组件的更多信息。

+   在[`quasar.dev/vue-components/inner-loading`](https://quasar.dev/vue-components/inner-loading)找到有关 Quasar `QInnerLoading`组件的更多信息。

+   在[`quasar.dev/vue-components/spinners`](https://quasar.dev/vue-components/spinners)找到有关 Quasar `QSpinners`的更多信息。

+   在[`quasar.dev/layout/page-sticky`](https://quasar.dev/layout/page-sticky)找到有关 Quasar `QPageSticky`组件的更多信息。

+   在[`quasar.dev/vue-directives/close-popup`](https://quasar.dev/vue-directives/close-popup)找到有关 Quasar `ClosePopup`指令的更多信息。

+   在[`vuejs.org/v2/guide/mixins.html`](https://vuejs.org/v2/guide/mixins.html)找到有关 Vue mixins 的更多信息。

# 创建应用程序的消息页面

没有消息的聊天应用程序只是一个简单的联系人列表。在这个最终的配方中，我们将完成应用程序的整个周期，为用户创建与其他用户直接交流的可能性。

在这个配方中，我们将创建聊天页面，`ChatInput`组件和消息布局。

## 准备工作

此处的先决条件如下：

+   来自上一个配方的项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始我们的用户消息页面，我们将继续使用在*创建应用程序的联系人页面*中创建的项目。

## 如何做...

在这个配方中，我们需要将其分为三个部分：创建`ChatInput`组件，创建消息布局，最后创建聊天页面。

### 创建 ChatInput 组件

在这里，我们将创建`ChatInput`组件。该组件的责任是接收用户的新消息输入并将其发送到服务器。

#### 单文件组件<script>部分

在这部分，我们将为页面创建`<script>`部分：

1.  在`src/components`文件夹中创建一个名为`ChatInput.vue`的新文件，并打开它。

1.  从`vuex`包中导入`mapActions`：

```js
import { mapActions } from 'vuex';
```

1.  导出一个具有`name`、`data`和`methods`属性的`default` JavaScript 对象。将`name`属性定义为`ChatInput`：

```js
export default {
  name: 'ChatInput',
  data: () => ({}),
  methods: {}, };
```

1.  在`data`属性上，添加一个名为`text`的新属性，其默认值为空字符串：

```js
data: () => ({
  text: '', }),
```

1.  在`methods`属性中，我们将从聊天模块中解构`mapActions`，调用`newMessage`和`fetchNewMessages`函数。然后我们需要创建一个名为`sendMessage`的新函数，该函数将在服务器上创建新消息并从服务器获取新消息。

```js
methods: {
  ...mapActions('chat', ['newMessage', 'fetchNewMessages']),
  async sendMessage() {
  await this.newMessage({
  message: this.text,
  conversationId: this.$route.params.id,
  });    await this.fetchNewMessages({
  conversationId: this.$route.params.id,
  });    this.text = '';
  }, },
```

#### 单文件组件<template>部分

现在是时候创建单文件组件的`<template>`组件部分了：

1.  创建一个`QInput`组件，其`v-model`指令绑定到`text`。然后将`bottom-slots`属性定义为`true`，`label`属性定义为`"Message"`。最后，在`enter`按钮上定义`keypress`事件监听器，执行`sendMessage`函数。

```js
<q-input
  v-model="text"
  bottom-slots
 label="Message"
  @keypress.enter="sendMessage" ></q-input>
```

1.  在`QInput`组件内部，创建一个带有`v-slot`指令的`Template`组件，名称为`after`。然后创建一个子`QBtn`组件，属性为`round`和`flat`定义为`true`，然后`icon`定义为`"send"`。最后，在`@click`事件上添加事件监听器，执行`sendMessage`函数：

```js
<template v-slot:after>
 <q-btn
  round
 flat icon="send"
  @click="sendMessage"
  /> </template>
```

这是您组件的渲染：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/e5c54eab-bf8c-4b50-8655-8310886bef1f.png)

### 创建消息布局

在聊天页面中，我们需要一个页脚组件，让用户输入他们的消息，并且这将需要对我们在之前的示例中创建的聊天布局进行大量修改。为了简化和更容易维护，我们将创建一个专门用于聊天页面的新布局，并将其称为消息布局。

#### 单文件组件<script>部分

现在让我们创建消息布局的`<script>`部分：

1.  在`layouts`文件夹中创建一个名为`Messages.vue`的新文件。

1.  从`src/driver/auth.js`文件中导入`signOut`函数和`components/ChatInput`中的`ChatInput`组件：

```js
import {signOut,} from 'src/driver/auth';
import ChatInput from '../components/ChatInput';
```

1.  导出一个`name`属性定义为`"ChatLayout"`的`default` JavaScript 对象，具有`components`属性和另一个名为`methods`的属性：

```js
export default {
  name: 'MessagesLayout',
  components: {},
  methods: {   }, };
```

1.  在`components`属性中，添加导入的`ChatInput`组件：

```js
components: { ChatInput },
```

1.  在`methods`属性中，添加一个名为`logOff`的新的异步函数。在这个函数中，我们将执行`signOut`函数，并在其后重新加载浏览器：

```js
methods: {
 async logOff() {
  await signOut();
  window.location.reload();
 },
}
```

#### 单文件组件`<template>`部分

在这里，我们将创建 Chat 布局的`<template>`部分：

1.  创建一个带有`view`属性定义为`"hHh lpR fFf"`的`QLayout`组件：

```js
<q-layout view="hHh lpR fFf"> </q-layout>
```

1.  在`QLayout`组件内部，我们需要添加一个带有`elevated`属性的`QHeader`组件：

```js
<q-header elevated> </q-header>
```

1.  在`QHeader`组件上，我们将添加一个`QToolbar`组件，其中包含一个`QToolbarTitle`组件作为子元素，具有文本作为插槽占位符：

```js
<q-toolbar>
 <q-toolbar-title>
  Chat App - {{ $route.params.name }}
 </q-toolbar-title> </q-toolbar>
```

1.  在`QToolbar`组件上，在`QToolbarTitle`组件之前，我们将添加一个`dense`，`flat`和`round`属性被定义为`true`的`QBtn`组件。`icon`属性将显示一个`back`图标，并且`v-go-back`指令被定义为`$route.meta.goBack`，因此目的地在路由文件中被定义：

```js
<q-btn
  v-go-back="$route.meta.goBack"
  dense
 flat round icon="keyboard_arrow_left" />
```

1.  在`QToolbarTitle`组件之后，我们将添加一个`QBtn`组件，其中`dense`，`flat`和`round`属性被定义为`true`。我们将`icon`属性定义为`exit_to_app`，并在`@click`指令上传递`logOff`方法：

```js
<q-btn
  dense
 flat round icon="exit_to_app"
  @click="logOff" />
```

1.  作为`QHeader`组件的同级，创建一个带有`RouterView`组件作为直接子元素的`QPageContainer`组件：

```js
<q-page-container>
 <router-view /> </q-page-container>
```

1.  最后，创建一个`class`属性定义为`bg-white`的`QFooter`组件。添加一个子`QToolbar`组件，其中包含一个子`QToolbarTitle`组件。在`QToolbarTitle`组件内部，添加`ChatInput`组件：

```js
<q-footer class="bg-white">
 <q-toolbar>
 <q-toolbar-title>
 <chat-input />
 </q-toolbar-title>
 </q-toolbar> </q-footer>
```

### 更改应用程序路由

在创建 Messages 布局之后，我们需要更改聊天页面路由的挂载方式，以便可以使用新创建的 Messages 布局：

1.  打开`router`文件夹中的`routes.js`文件。

1.  找到`/chat`路由并提取`Messages`路由对象。在`/chat`路由之后，创建一个新的 JavaScript 对象，具有`path`，`component`和`children`属性。将`path`属性定义为`/chat/messages`，然后在`component`属性上，我们需要延迟加载新创建的`Messages`布局。最后，将提取的路由对象放在`children`属性上，并将`children`数组中新添加的对象的`path`属性更改为`:id/name`：

```js
{
  path: '/chat/messages',
  component: () => import('layouts/Messages.vue'),
  children: [
 {  path: ':id/:name',
  name: 'Messages',
  meta: {
        autenticated: true,
  goBack: {
  name: 'Contacts',
  },
  },
  component: () => import('pages/Messages.vue'),
  },
  ], },
```

### 创建消息页面

在这个食谱的最后部分，我们将创建消息页面。在这里，用户将向他们的联系人发送消息并接收消息。

#### 单文件组件<script>部分

让我们创建单文件组件的<script>部分：

1.  在`src/pages`文件夹中打开`Messages.vue`文件。在文件的`<script>`部分，从`vuex`中导入`mapActions`和`mapGetters`，以及从`quasar`中导入`date`：

```js
import { mapActions, mapGetters } from 'vuex'; import { date } from 'quasar';
```

1.  导出一个默认的 JavaScript 对象，其中包含`name`、`components`、`data`、`beforeMount`、`beforeDestroy`、`watch`、`computed`和`methods`属性。将`name`属性定义为`MessagesPage`。在`components`属性中，添加一个新的属性，`AvatarDisplay`，它将接收一个返回导入组件的匿名函数。最后，在`data`属性上，创建一个带有值为`null`的`interval`属性的对象：

```js
export default {
  name: 'MessagesPage',
  components: {
  AvatarDisplay: () => import('components/AvatarDisplay'),
  },
  data: () => ({
  interval: null,
  }),
  async beforeMount() {},
  beforeDestroy() {},
  watch: {},
  computed: {},
  methods: {}, };
```

1.  在`computed`属性上，首先，我们将解构`mapGetters`函数，将`user`模块作为第一个参数传递，`getUser`作为第二个参数。然后我们将对 chat 模块做同样的操作，获取`getChatMessages`。最后，创建一个`currentMessages`函数，用于获取当前对话的消息，并返回带有`createdAt`日期格式的消息：

```js
computed: {
  ...mapGetters('chat', ['getChatMessages']),
  ...mapGetters('user', ['getUser']),
  currentMessages() {
  const messages = this.getChatMessages(this.$route.params.id);
  if (!messages.length) return [];
  return messages.map((m) =>  ({
  ...m,
  createdAt: date.formatDate(new Date(parseInt(m.createdAt, 
        10)), 'YYYY/MM/DD HH:mm:ss'),
  }));
  }, },
```

1.  在`methods`属性中，通过调用`fetchNewMessages`从`chat`模块中解构`mapActions`：

```js
methods: {
  ...mapActions('chat', ['fetchNewMessages']), },
```

1.  在`watch`属性中，创建一个名为`currentMessages`的属性，它是一个 JavaScript 对象，有三个属性，`handler`、`deep`和`immediate`。将`handler`属性定义为一个带有`newValue`和`oldValue`参数的函数。这个函数将检查`newValue`是否大于`oldValue`。然后创建一个超时，将屏幕滚动到最后可见的元素。将`deep`属性定义为`true`，将`immediate`属性定义为`false`：

```js
watch: {
  currentMessages: {
  handler(newValue, oldValue) {
  if (newValue.length > oldValue.length) {
  setTimeout(() => {
  const lastMessage = [...newValue].pop();
  const [{ $el: el }] = this.$refs[`${lastMessage.id}`];
  el.scrollIntoView();
  }, 250);
  }
 },
  deep: true,
  immediate: false,
  }, },
```

1.  我们需要将`beforeMount`生命周期钩子设置为异步。然后我们需要将`interval`分配给一个新的`setInterval`，它将每 1 秒获取新消息：

```js
async beforeMount() {
  this.interval = setInterval(async () => {
  await this.fetchNewMessages({
  conversationId: this.$route.params.id,
  });
  }, 1000); },
```

1.  最后，在`beforeDestroy`生命周期钩子上，我们将清除`interval`循环，并将`interval`定义为`null`：

```js
beforeDestroy() {
  clearInterval(this.timeout);
  this.timeout = null; },
```

#### 单文件组件<template>部分

现在让我们创建单文件组件的<template>部分

1.  创建一个带有`class`属性定义为`q-pa-md row justify-center`的`QPage`组件，并将`QChatMessage`组件作为子组件添加。

1.  在`QChatMessage`子组件中，首先在`v-for`指令上对`currentMessages`进行迭代。

1.  将`ref`和`key`组件属性定义为`message.id`，`stamp`定义为`message.createdAt`，`text`定义为`[message.content]`。

1.  然后将`sent`属性定义为评估`message.authorId`是否与`getUser.id`相同，`name`定义为`message.author.name`，`avatar`定义为传入`message.author.avatar`和`message.author.name`作为参数的`getAvatar`方法。

1.  然后，将`class`属性定义为`col-12`。

1.  最后，在`QChatMessage`组件内，在`avatar`插槽上创建一个`template`组件，并添加`AvatarDisplay`组件。将`avatar-object`动态属性定义为`message.author.avatar`，将`name`动态属性定义为`message.author.name`，将`tag`属性定义为`'img'`，将`class`属性定义为`'q-message-avatar'`，将类动态属性定义为三元运算符，检查`getUser.id`是否与`message.authorId`不同，如果是，则返回`'q-message-avatar--received'`，如果消息来自发送者，则返回`'q-message-avatar--sent'`。

```js
<template>
  <q-page class="q-pa-md row justify-center">
  <q-chat-message
    v-for="message in currentMessages"
    :ref="`${message.id}`"
    :key="message.id"
    :stamp="message.createdAt"
    :text="[message.content]"
    :sent="getUser.id === message.authorId"
    :name="message.author.name"
    class="col-12"
  >
    <template v-slot:avatar>
      <avatar-display
        :avatar-object="message.author.avatar"
        :name="message.author.name"
        tag="img"
        class="q-message-avatar"
        :class="getUser.id !== message.authorId
        ? 'q-message-avatar--received'
        : 'q-message-avatar--sent'"
      />
    </template>
  </q-chat-message>
  </q-page> </template>
```

这是页面的预览：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/311932f4-95f8-4f1a-98fc-801cbbc2b0d4.png)

## 它是如何工作的...

消息页面由三个部分组成：布局、`ChatInput`组件和页面。使用这种组合，我们能够将代码分割为不同的责任，以增加代码的可维护性。

在`ChatInput`组件中，我们使用 Chat Vuex 模块直接发送消息，无需通过页面或布局等容器，使组件具有状态。

我们需要添加新的布局和路由修改，因为应用程序的布局需要一个固定在应用程序底部的组件。这个底部是消息输入，需要始终对用户可见。

最后，消息页面是一个自动刷新页面，每秒获取新内容，并始终为用户显示新消息。

## 另请参阅

+   在[`quasar.dev/vue-components/chat`](https://quasar.dev/vue-components/chat)找到有关 Quasar Framework 的`QChatMessage`组件的更多信息。

+   在[`quasar.dev/quasar-utils/date-utils`](https://quasar.dev/quasar-utils/date-utils)找到有关 Quasar Framework 的`date`工具的更多信息。


# 第七章：将您的应用程序转换为 PWA 并部署到 Web

当我们编码完成时，是时候完成我们的应用程序并准备发布了。现在，我们的自定义聊天应用程序已经与后端的 Amplify 服务以及前端的 Quasar 和 Vue 一起运行，我们已经准备好在网络上运行。

在本章中，您将学习如何将您的应用程序转换为**渐进式 Web 应用程序**（**PWA**），在服务工作者上添加一些事件以通知用户您的应用程序的新版本，为 iOS 设备创建自定义横幅以进行安装，并最终部署应用程序。

因此，在本章中，我们将涵盖以下配方：

+   将应用程序转换为 PWA

+   创建应用程序更新通知

+   在 iOS 上添加自定义 PWA 安装通知

+   创建生产环境和部署

# 技术要求

在本章中，我们将使用**Node.js**，**AWS Amplify**和**Quasar Framework**。

注意，Windows 用户！您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装所需的软件包。要执行此操作，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装**Quasar Framework**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @quasar/cli
```

要安装**AWS Amplify**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @aws-amplify/cli
```

# 将应用程序转换为 PWA

为了在当前网络上获得应用程序的最佳体验，您需要有一个**PWA**，在其中可以使您的应用程序缓存代码的某些部分，离线工作，接收推送通知等等。

在这个配方中，您将学习如何将您的**单页应用程序**（**SPA**）转换为 PWA，并重新配置 Amplify CLI 以适应新的配置。

## 做好准备

此配方的先决条件是 Node.js 12+。

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始将我们的项目转换为 PWA，我们将继续使用在*第六章，创建聊天和消息 Vuex，页面和路由*中创建的项目。

## 如何做...

在将应用程序发布到生产环境之前，是时候将我们的应用程序转换为 PWA 了。按照以下步骤将 PWA 模式添加到 Quasar 中：

1.  首先，我们需要将 PWA 模式添加到 Quasar 应用程序中。要做到这一点，在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> quasar m add pwa
```

1.  在项目根文件夹中打开`quasar.conf.js`文件，并找到`pwa`属性。从 JavaScript 对象中删除`workboxPluginMode`和`workboxOptions`属性，并添加`cleanupOutdatedCaches`，`skipWaiting`和`clientsClaim`属性，定义为`true`。最后，在`manifest`属性上，更改`name`，`short_name`和`description`以匹配您的应用程序，如下面的代码所示：

```js
pwa: {
 cleanupOutdatedCaches: true,
 skipWaiting: true,
 clientsClaim: true,
   manifest: {
     name: 'Chat Application',
     short_name: 'Chat App',
     description: 'Quasar & AWS Amplify Chat Application',
     ...
   },
 ...
}
```

1.  现在是时候将 Amplify CLI 的配置更改为新的配置。为此，在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> amplify configure project
```

1.  CLI 将要求您是否要更改项目名称。无需更改，因此按*Enter*继续：

```js
? Enter a name for the project (chatapp) 
```

1.  CLI 将要求您是否要更改项目默认编辑器。选择`Visual Studio Code`（或者您将在项目中使用的默认编辑器），然后按*Enter*继续：

```js
? Choose your default editor: (Use arrow keys)
❯ Visual Studio Code 
  Atom Editor 
  Sublime Text 
  IntelliJ IDEA 
  Vim (via Terminal, Mac OS only) 
  Emacs (via Terminal, Mac OS only) 
  None 
```

1.  CLI 将要求您是否要更改项目应用程序类型。选择`javascript`选项，然后按*Enter*继续：

```js
? Choose the type of app that you're building (Use arrow keys)
  android 
  ios 
❯ javascript 
```

1.  CLI 将要求您是否要更改项目的 JavaScript 框架。选择`none`，然后按*Enter*继续：

```js
Please tell us about your project
? What javascript framework are you using (Use arrow keys)
  angular 
  ember 
  ionic 
  react 
  react-native 
  vue 
❯ none 
```

1.  CLI 将要求您是否要更改项目应用程序源目录。无需更改，因此按*Enter*继续：

```js
? Source Directory Path:  (src)
```

1.  CLI 将要求您是否要更改项目应用程序分发目录；更改路径为`dist/pwa`，然后按*Enter*继续：

```js
? Distribution Directory Path: dist/pwa
```

1.  CLI 将要求您输入`Build Command`选项；更改命令为`quasar build -m pwa`，然后按*Enter*继续：

```js
? Build Command: quasar build -m pwa
```

1.  CLI 将要求您输入`Start Command`选项；更改为`quasar dev -m pwa`，然后按*Enter*继续：

```js
? Start Command: quasar dev -m pwa
```

1.  CLI 将要求您是否要更新或删除项目配置。选择`update`，然后按*Enter*继续：

```js
Using default provider awscloudformation

For more information on AWS Profiles, see:
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html

For the awscloudformation provider.
? Do you want to update or remove the project level configuration (Use arrow keys)
❯ update 
  remove 
  cancel 
```

1.  CLI 将要求您在此更新中是否要使用 AWS 配置文件。输入*Y*，然后按*Enter*继续：

```js
? Do you want to use an AWS profile? Y
```

1.  最后，选择您想要使用的配置文件，然后按*Enter*继续：

```js
? Please choose the profile you want to use (Use arrow keys)
❯ default 
```

## 工作原理...

在本教程中，我们使用 Quasar CLI 将 PWA 开发环境添加到我们的项目中，使用内置的`quasar -m add`命令来添加新的开发环境。

然后，我们配置了`quasar.conf.js`文件，以在`pwa`属性上添加新属性，以便我们可以在部署的应用程序中添加更好的用户体验。

最后，我们更改了 Amplify CLI 配置，以便它将使用新的`pwa`环境作为构建命令和分发文件夹。

## 另请参阅

+   在[`quasar.dev/quasar-cli/developing-pwa/introduction`](https://quasar.dev/quasar-cli/developing-pwa/introduction)找到有关使用 Quasar 开发 PWA 的更多信息。

+   在[`docs.amplify.aws/cli`](https://docs.amplify.aws/cli)找到有关 Amplify CLI 的更多信息。

# 创建应用程序更新通知

让用户始终了解应用程序的更新是一个好习惯，因为他们将始终知道应用程序正在维护和改进。

使用 PWA，您可以访问诸如创建原生移动应用程序、允许在移动设备上安装应用程序等功能。

发布更新时，我们需要通知用户并更新当前安装的代码。

在本教程中，我们将学习如何使用服务工作程序生命周期来注册应用程序安装，并将其用于在有新更新时通知用户并应用新的更新版本。

## 准备好了吗？

本教程的先决条件是 Node.js 12+。

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始添加自定义更新通知，我们将继续使用在*将应用程序转换为 PWA*教程中创建的项目。

## 如何做...

按照以下步骤在我们的 PWA 中添加更新通知：

1.  打开项目根文件夹中的`quasar.conf.js`文件，找到`framework`属性。然后对于`plugins`属性，将`'Notify'`字符串添加到数组中，以便 Quasar 在应用程序启动时加载`Notify`插件：

```js
framework: {
 ...
  plugins: [
   'Dialog',
  'Notify',
 ],
 ...
},
```

1.  打开`src-pwa`文件夹中的`register-service-worker.js`文件，并从 Quasar 导入`Notify`插件：

```js
import { Notify } from 'quasar';
```

1.  创建一个名为`clearLocalCache`的异步函数。然后创建一个名为`cachedFiles`的常量，并将其定义为`await caches.keys()`；在`cachedFiles`常量上，使用参数`file`执行一个数组`map`函数；在函数内部执行`await caches.delete(file)`。最后，重新加载应用程序：

```js
async function clearLocalCache() {
  const cachedFiles = await caches.keys();    await cachedFiles.map(async (file) => {
  await caches.delete(file);
  });    window.location.reload(); }
```

1.  找到`updatefound`函数，并创建一个名为`installKey`的常量，并将其定义为`'chatAppInstalled'`。然后验证浏览器的`localStorage`项中是否有与您创建的常量名称相同的项。如果存在该项，则执行`Notify.create`函数，并将 JavaScript 对象作为参数传递，其中`color`属性定义为`'dark'`，`message`定义为更新消息。如果`localStorage`项不存在，则向`localStorage`添加一个名为`installKey`常量的项，其值为`'1'`：

```js
updatefound(/* registration */) {
  const installKey = 'chatAppInstalled';
  if (localStorage.getItem(installKey)) {
    Notify.create({
      color: 'dark',
      message: 'An update is being downloaded from the server.',
    });
  } else {
    localStorage.setItem(installKey, '1');
  }
},
```

1.  最后，找到`updated`函数，并添加一个`Notify.create`函数，将 JavaScript 对象作为参数传递。在此对象中，添加一个`type`属性，定义为`'positive'`，一个`message`属性，定义为成功更新的消息，一个带有刷新应用程序指示的`caption`属性，以及一个定义为数组的`actions`属性。在`actions`数组中，添加一个 JavaScript 对象，其中`label`属性定义为`'Refresh'`，`color`属性定义为`'white'`，`handler`属性定义为`clearLocalCache`函数：

```js
updated(/* registration */) {
  Notify.create({
  type: 'positive',
  message: 'The application was updated successfully!',
  caption: 'Please refresh the page to apply the new update.',
  actions: [
 {  label: 'Refresh',
  color: 'white',
  handler: clearLocalCache,
  },
  ],
  }); },
```

以下是通知的预览：

+   发现新更新：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/8b444e5c-d289-4f6a-9d61-743880d74740.png)

+   更新已应用：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/665cbf77-cab3-4f35-b56d-c0a409ef6789.png)

## 它是如何工作的...

首先，我们将`Notify`插件添加到`quasar.conf.js`文件的插件属性中，这样 Quasar CLI 就可以在执行运行时为我们提供它。

然后，在`register-service-worker.js`文件中，我们添加了 Notify 插件并创建了一个自定义的缓存清除函数。

在`updatefound`生命周期中，我们添加了安装验证，以便新的更新通知只会显示给已在其浏览器上安装了应用程序的用户。

最后，我们在更新的生命周期中添加了更新完成过程的通知，并为用户添加了一个清除缓存并重新启动应用程序的操作按钮。

## 另请参阅

+   在[`quasar.dev/quasar-plugins/notify`](https://quasar.dev/quasar-plugins/notify)找到有关 Quasar Notify 插件的更多信息。

+   在[`developer.mozilla.org/en-US/docs/Web/API/Cache`](https://developer.mozilla.org/en-US/docs/Web/API/Cache)找到有关 JavaScript 缓存接口的更多信息。

# 在 iOS 上添加自定义 PWA 安装通知

不幸的是，在 iOS 上，Safari 浏览器引擎没有默认的 PWA 安装横幅。在这种情况下，我们必须实现自己的版本。使用名为`a2hs.js`（用于*添加到主屏幕*）的社区插件，我们可以为 iOS 用户启用自定义安装消息的显示。

在这个教程中，我们将学习如何在项目中添加`a2hs.js`插件，并如何使用 Quasar 引导文件将其添加到项目引导序列中。

## 准备工作

这个教程的先决条件是 Node.js 12+。

需要的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

+   `a2h2.js`

要开始开发自定义 iOS PWA 安装横幅，我们将继续使用在“创建应用程序更新通知”教程中创建的项目。

## 如何做...

在 Safari 上的 iOS 平台上，浏览器中没有 PWA 应用的安装横幅。在这些步骤中，我们将添加`a2hs.js`插件以添加此缺失的功能：

1.  首先，我们需要在项目中安装`a2js.js`插件。要做到这一点，在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm install --save a2hs.js
```

1.  在`boot`文件夹中，然后在`src`文件夹内，创建一个`a2hs.js`文件并打开它。接下来，导入`a2hs.js`插件：

```js
import AddToHomeScreen from 'a2hs.js';
```

1.  要使 Quasar 引导文件起作用，我们需要创建一个默认导出的函数。在这个函数中，创建一个名为`options`的常量，并将其定义为一个 JavaScript 对象，其中`brandName`属性作为应用程序的名称：

```js
export default() => {
 const options = {
  brandName: 'Chat App',  };
  AddToHomeScreen(options); };
```

1.  最后，在项目根文件夹中，打开`quasar.conf.js`文件并找到`boot`属性。在数组中，添加`'a2hs'`字符串，以使其对 Quasar CLI 可用，并加载新创建的引导文件：

```js
boot: [
  'amplify',
  'axios',
  'a2hs', ],
```

这是在 iOS 设备上弹出的警报的预览：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/bd-vue-app-gql/img/e8ff8fe2-d307-4148-9223-38c1d933674c.png)

## 它是如何工作的...

首先，我们使用`npm`安装了`a2hs.js`插件到项目中。然后，我们在 Quasar 上创建了一个`a2hs.js`文件，用作引导文件。

然后，在新创建的文件中，我们导入了`a2hs.js`插件和应用程序 logo，然后实例化了具有自定义选项的`a2hs.js`插件。

最后，我们将`a2hs`引导文件添加到`quasar.conf.js`文件的`boot`属性中。

## 另请参阅

+   您可以在[`quasar.dev/quasar-cli/boot-files`](https://quasar.dev/quasar-cli/boot-files)找到有关 Quasar 引导文件结构的更多信息。

+   您可以在[`github.com/koddr/a2hs.js/`](https://github.com/koddr/a2hs.js/)找到有关`a2hs.js`的更多信息。

# 创建生产环境和部署

在所有工作都已经完成，准备好我们的应用程序后，现在是时候将其构建为一个生产就绪的分发，通过创建一个生产环境并将其部署到该环境。这个新环境将不会有来自测试的数据，并且我们将确保这个环境将专门用于生产状态。

生产环境可以被描述为一个最终用户放置您的应用程序的环境，具有准备好接收最终用户数据的代码和数据库。

在这个教程中，我们将学习如何使用 Amplify CLI 创建一个生产环境，以及如何在 Amplify 控制台上将其定义为默认的生产环境。

## 准备工作

这个教程的先决条件是 Node.js 12+。

所需的 Node.js 全局对象如下：

+   `@aws-amplify/cli`

+   `@quasar/cli`

要开始创建生产环境，我们将继续使用在*在 iOS 上添加自定义 PWA 安装通知*教程中创建的项目。

## 如何做...

我们需要准备好我们的应用程序，以在生产环境中发布给我们的用户。按照以下步骤在 Amplify 控制台中创建生产环境并将其定义为我们应用程序的默认生产环境：

1.  在项目根目录中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> amplify env add
```

1.  Amplify CLI 会询问您是否要使用现有环境作为基础；按下*N*和*Enter*继续：

```js
? Do you want to use an existing environment? (Y/n) n
```

1.  现在 Amplify CLI 会询问您新环境的名称；将`production`作为名称输入并按*Enter*继续：

```js
? Enter a name for the environment production production
```

1.  CLI 会询问您是否要在此更新中使用 AWS 配置文件；输入*Y*并按*Enter*继续：

```js
? Do you want to use an AWS profile? (Y/n) y
```

1.  选择要使用的配置文件并按*Enter*继续：

```js
? Please choose the profile you want to use (Use arrow keys)
❯ default 
```

1.  现在，我们需要将所做的更改推送到服务器；为此，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify push
```

1.  Amplify CLI 将询问您是否要更新自动生成的 GraphQl 代码；输入*Y*并按*Enter*继续：

```js
? Do you want to update code for your updated GraphQL API (Y/n) y
```

1.  Amplify CLI 将询问您是否要覆盖当前现有的代码；输入*Y*并按*Enter*继续：

```js
? Do you want to generate GraphQL statements (queries, mutations and 
  subscription) based on your schema types?
This will overwrite your current graphql queries, mutations and subscriptions (Y/n) y
```

1.  然后将您的网站发布到生产环境。要做到这一点，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify publish
```

1.  对于最后一部分，我们需要配置应用程序设置以使用我们创建的新`production`环境。为此，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），进入项目文件夹，并执行以下命令：

```js
> amplify console
```

1.  打开侧边菜单，点击“常规”链接：

！[](assets/b7081945-0d9a-4a5b-a68a-cc92f0dd841c.png)

1.  现在，在应用程序详细信息卡中，点击右上角的“编辑”按钮：

！[](assets/47f656dd-14e9-44e7-941f-753000177c57.png)

1.  然后在设置中，打开生产环境选择框，并选择生产环境：

！[](assets/b1fba80a-b5bd-4cbf-a2e5-f12549521816.png)

1.  最后，要检查更改是否已正确保存，请刷新页面并检查应用程序详细信息卡的“设置”部分：

！[](assets/5cf19669-f198-4def-b807-dce6e093918b.png)

## 它是如何工作的...

在这个教程中，我们首先使用 Amplify CLI 向本地 Amplify 实例添加了一个新环境，并选择使用全新的环境。然后，我们将这个新环境发送到云端，更新我们的本地代码库，并最终使用这个新环境发布项目。

最后，我们去 Amplify 控制台配置应用程序的生产环境，作为我们创建的新环境。

## 另请参阅

+   在[`docs.amplify.aws/cli`](https://docs.amplify.aws/cli)上查找有关 Amplify CLI 的更多信息。

+   在[`aws.amazon.com/amplify/console/?nc1=h_ls`](https://aws.amazon.com/amplify/console/?nc1=h_ls)上查找有关 Amplify 控制台的更多信息。
