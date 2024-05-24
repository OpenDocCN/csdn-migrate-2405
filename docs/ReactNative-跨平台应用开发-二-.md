# ReactNative 跨平台应用开发（二）

> 原文：[`zh.annas-archive.org/md5/6A2675D80E0FE70F7D8BA886F2160D60`](https://zh.annas-archive.org/md5/6A2675D80E0FE70F7D8BA886F2160D60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：项目 3 - 消息应用

一对一通信是手机的主要用途，尽管短信已经很快被直接消息应用所取代。在本课程中，我们将使用 React Native 构建一个消息应用，并得到 Firebase 的支持，这是一个移动后端服务，将使我们摆脱为我们的应用构建整个后端的负担。相反，我们将专注于完全从前端处理我们应用的状态。当然，这可能会有安全方面的影响，需要最终解决，但为了保持本书对 React Native 能力的关注，我们将坚持将所有逻辑保留在我们的应用内部的方法。

Firebase 是一个建立在自我同步数据集合上的实时数据库，它与 MobX 配合非常好，所以我们将再次使用它来控制我们应用的状态。但在本课程中，我们将更深入地挖掘，因为我们将构建更大的数据存储，这些数据将通过 mobx-react 连接器注入到我们的组件树中。

我们将构建该应用，使其可以在 iOS 和 Android 上使用，为导航编写一些特定于平台的代码（我们将在 iOS 上使用选项卡导航，在 Android 上使用抽屉导航）。

为了减少代码的大小，在本课程中，我们将把重点放在功能上，而不是设计上。大部分用户界面将是简单明了的，但我们会尽量考虑可用性。此外，我们将在我们的聊天屏幕上使用 `react-native-gifted` 聊天--一个预先构建的 React Native 组件，用于根据消息列表渲染聊天室。

# 概览

消息应用需要比我们在之前课程中审查过的应用更多的工作，因为它需要一个用户管理系统，包括登录、注册和退出登录。我们将使用 Firebase 作为后端来减少构建这个系统的复杂性。除了用户管理系统，我们还将使用他们的推送通知系统，在新消息发送给用户时通知他们。Firebase 还提供了分析平台、lambda 函数服务和免费的存储系统，但我们将从中获得最大利润的功能是他们的实时数据库。我们将把用户的个人资料、消息和聊天数据存储在那里。

让我们来看一下我们的应用将会是什么样子，以便对我们将要构建的屏幕有一个心理形象：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_01.jpg)

第一个屏幕将是登录/注册屏幕，因为我们需要用户提供姓名和一些凭据，以将他们的设备连接到特定帐户，这样他们就可以接收每条消息的推送通知。这两种身份验证方法都是使用 Firebase 的 API 进行验证的，如果成功，将会显示聊天屏幕：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_02.jpg)

当在联系人列表中按下一个联系人时，应用程序将在聊天屏幕中显示与所选联系人的对话：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_03.jpg)

聊天屏幕将显示所有为登录用户启动的对话。最初，这个屏幕将是空的，因为用户还没有开始任何对话。要开始对话，用户应该去搜索屏幕以找到一些联系人：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_04.jpg)

这是一个简单的屏幕，用户可以在数据库中输入联系人姓名进行搜索。如果联系人姓名匹配成功，用户将能够点击它开始对话。从那时起，对话将显示在聊天屏幕中。

最后一个屏幕是个人资料屏幕：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_05.jpg)

这个屏幕只是用来注销当前用户的。在扩展应用程序时，我们可以添加更多功能，比如更改头像或用户名。

虽然在 Android 上应用程序看起来非常相似，但导航将被抽屉替换，从中可以访问所有屏幕。让我们看看 Android 版本：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_06.jpg)

登录/注册屏幕在 Android 上具有标准的文本输入和按钮组件：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_07.jpg)

用户登录后，可以通过滑动手指打开抽屉来浏览所有屏幕。默认登录后打开的屏幕是聊天屏幕，我们将列出用户拥有的所有对话列表：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_08.jpg)

从这个屏幕，用户可以按下特定对话以列出其中的消息：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_09.jpg)

接下来的屏幕是搜索屏幕，用于搜索其他用户并与他们开始对话：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_10.jpg)

最后一个屏幕是个人资料屏幕，可以找到**注销**按钮：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_11.jpg)

该应用程序将在横屏和竖屏模式下都能正常工作：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/03_12.jpg)

正如我们可以想象的那样，这个应用程序将需要一个强大的后端环境来存储我们的用户、消息和状态。此外，当用户收到任何消息时，我们将需要一个推送通知平台来通知用户。由于我们在本书中专注于 React Native，我们将把所有这些后端工作委托给移动世界中最流行的**移动后端作为服务**（**MBaaS**）之一：Firebase。

在开始编码之前，我们将花一些时间设置我们的 Firebase 推送通知服务和实时数据库，以更好地了解我们的应用程序将要处理的数据类型。

总之，在本课程中，我们将讨论以下主题：

+   React Native 中的复杂 Redux

+   Firebase 实时数据库

+   Firebase 推送通知

+   Firebase 用户管理

+   表单

让我们首先回顾一下我们将使用的数据模型以及我们的应用程序将如何与 Firebase 连接以同步其数据。

# Firebase

Firebase 是一种**移动后端作为服务**（**MBaaS**），这意味着它为移动开发人员提供了所有后端必需品，如用户管理、无 SQL 数据库和推送通知服务器。它通过官方的 node 包轻松集成到 React Native 中，这为数据库连接提供了免费的服务。不幸的是，Firebase 并没有为他们的推送通知服务提供 JavaScript SDK，但有几个 React Native 库通过将 Firebase 的 iOS 和 Java SDK 与 JavaScript 接口进行桥接来填补这一空白。我们将使用`react-native-fcm`，因为它在这个领域是最成熟的。

在 Firebase MBaaS 上构建应用程序之前，您需要为其创建一个项目。这是一个免费的过程，可以在 Firebase 的网站[`firebase.google.com/`](https://firebase.google.com/)上找到解释。虽然这个过程与 React Native 没有直接关系，但这是一个很好的起点，可以了解如何为我们的应用程序设置和使用 MBaaS。通过遵循 Firebase 文档网站上提供的教程，大部分配置可以在几分钟内完成。设置这个 MBaaS 的好处使得这几分钟的时间和最初的麻烦都是值得的。

要设置 Firebase 并将我们的应用程序连接到正确的项目，我们需要使用在我们的 Firebase 项目仪表板内的**设置**屏幕中找到的`web 配置`片段。我们将这个初始化片段添加到`src/firebase.js`中：

```jsx
import firebase from 'firebase';

var firebaseConfig = {
  apiKey: “<Your Firebase API key>",
  authDomain: “<Your Firebase Auth domain>",
  databaseURL: “<Your Firebase database URL>",
  projectId: “<Your Firebase projectId>",
  storageBucket: “<Your Firebase storageBucket>",
  messagingSenderId: “<Your messaging SenderId>"
};

export const firebaseApp = firebase.initializeApp(firebaseConfig);
```

一旦项目设置完成，我们可以开始看一下我们的数据库将如何被构建。

## 实时数据库

Firebase 允许移动开发人员使用云托管的 NoSQL 数据库在用户和设备之间实时存储和同步数据。更新后的数据在毫秒内同步到连接的设备上，如果应用离线，数据仍然可用，无论网络连接如何，都能提供出色的用户体验。

在考虑一对一通信应用程序应该处理的基本数据时，有三个数据模型涉及其中：

+   `users`：这里将存储头像、姓名和推送通知令牌。这里不需要存储认证数据，因为它是通过不同的 Firebase API（认证 API）处理的。

+   `messages`：我们将在每个聊天室单独保存每条消息，以便使用聊天室 ID 作为键轻松检索。

+   聊天：所有关于已打开聊天的信息都将存储在这里。

为了理解我们将如何请求和使用应用中的数据，让我们看一下我们实际可以用于测试的示例数据的要点：

```jsx
{
  “chats" : {
    “--userId1--" : {
      “--userId2----userId1--" : {
        “contactId" : “--userId2--",
        “image" : “https://images.com/person2.jpg",
        “name" : “Jason"
      }
    },
    “--userId2--" : {
      “--userId2----userId1--" : {
        “contactId" : “--userId1--",
        “image" : “https://images.com/person1.jpg",
        “name" : “John"
      }
    }
  },
  “messages" : {
    “--userId2----userId1--" : {
      “-KpEwU8sr01vHSy3qvRY" : {
        “_id" : “2367ad00-301d-46b5-a7b5-97cb88781489",
        “createdAt" : 1500284842672,
        “text" : “Hey man!",
        “user" : {
          “_id" : “--userId2--",
          “name" : “Jason"
        }
      }
    }
  },
  “users" : {
    “--userId1--" : {
      “name" : “John",
      “notificationsToken" : “"
    },
    “--userId2--" : {
      “name" : “Jason",
      “notificationsToken" : “--notificationsId1--"
    }
  }
}
```

我们以一种易于消息应用检索和同步的方式组织了我们的数据。我们引入了一些数据重复，以增加数据检索速度，并将前端代码简化到最大程度，而不是对数据结构进行规范化。

`users`集合使用用户 ID 作为键（`--user1--`和`--user2--`）来保存用户数据。这些用户 ID 在注册/登录期间由 Firebase 自动检索。每个用户都有一个通知令牌，这是用户使用推送通知服务登录的设备的标识符。当用户注销时，通知令牌将被移除，因此发送给该用户的消息将被存储，但不会通知到任何设备。

`chats`集合通过用户 ID 存储每个用户的聊天列表。每个聊天都有自己的 ID（由两个用户 ID 连接而成），并且会被复制，因为每个参与聊天的用户都应该有一份聊天数据的副本。在每个副本中，都有足够的信息供另一个用户构建他们的聊天界面。

`messages`集合存储在一个单独的集合中，可以通过该 ID 引用。每个聊天 ID 指向一条消息列表（在本例中只有一条），其中存储了聊天界面所需的所有数据。在这个集合中也有一些重复，因为一些用户数据与每条消息一起存储，以减少构建聊天界面时所需的请求次数。

在他们的网站上可以找到有关如何在 Firebase 的实时数据库中读写数据的完整教程（[`firebase.google.com/docs/database/`](https://firebase.google.com/docs/database/)），但是我们将快速浏览一下我们在本课程中将使用的方法。

### 从 Firebase 的数据库中读取数据

从 Firebase 的数据库中检索数据有两种方法。第一种方法设置一个监听器，每当数据更改时都会调用它，因此我们只需要为我们的应用程序的整个生命周期设置一次即可：

```jsx
firebaseApp.database().ref('/users/' + userId).on('value', (snapshot) => {
  const userObj = snapshot.val();
  this.name = userObj.name;
  this.avatar = userObj.avatar;
});
```

正如我们所看到的，为了检索数据的快照，我们需要在我们的`firebaseApp`对象中调用`database()`方法（我们在`src/firebase.js`文件中创建的对象）。然后，我们将有一个`database`对象，我们可以在其上调用`ref('<uri>')`，传递数据存储的 URI。这将返回一个由该 URI 指向的数据片段的引用。我们可以使用`on('value', callback)`方法，它将附加一个回调，传递数据的快照。Firebase 总是将对象作为快照返回，因此我们需要自己将它们转换为普通数据。在这个例子中，我们想要检索一个具有两个键（`name`和`avatar`）的对象，所以我们只需要在快照上调用`val()`方法来检索包含数据的普通对象。

如果我们不需要在更新时自动同步检索到的数据，我们可以使用`once()`方法而不是`on()`：

```jsx
import firebase from 'firebase';
import { firebaseApp } from '../firebase';

firebaseApp.database().ref('/users/' + userId).once('value')
.then((snapshot) => {
  const userObj = snapshot.val();
  this.name = userObj.name;
  this.avatar = userObj.avatar;
});
```

接收快照的回调只会被调用一次。

### 在 Firebase 的数据库中更新数据

在 Firebase 数据库中写入数据也可以通过两种不同的方式完成：

```jsx
firebaseApp.database().ref('/users/' + userId).update({
  name: userName
});
```

`update()`方法根据传递的键和值更改由提供的 URI 引用的对象。对象的其余部分保持不变。

另一方面，`set()`将用我们提供的对象替换数据库中的对象：

```jsx
firebaseApp.database().ref('/users/' + userId).set({
  name: userName,
  avatar: avatarURL
});
```

最后，如果我们想要添加一个新的数据快照，但是我们希望 Firebase 为其生成一个 ID，我们可以使用`push`方法：

```jsx
firebaseApp.database().ref('/messages/' + chatId).push().set(message);
```

## 认证

我们将使用 Firebase 认证服务，因此我们不需要担心在我们这边存储登录凭据、处理忘记的密码或验证电子邮件。这些和其他相关任务都可以通过 Firebase 认证服务免费完成。

为了通过电子邮件和密码激活登录和注册，我们需要在 Firebase 仪表板中将此方法作为会话登录方法启用。有关如何执行此操作的更多信息，请访问 Firebase 网站[`firebase.google.com/docs/auth/web/password-auth`](https://firebase.google.com/docs/auth/web/password-auth)。

在我们的应用程序中，我们只需要使用提供的 Firebase SDK 进行登录：

```jsx
firebase.auth().signInWithEmailAndPassword(username, password)
  .then(() => {
        //user is logged in
  })
  .catch(() => {
        //error logging in
  })
})
```

对于注册，我们可以使用以下代码：

```jsx
firebase.auth().createUserWithEmailAndPassword(email, password)
.then((user) => {
   //user is registered
})
.catch((error) => {
   //error registering
})
```

所有令牌处理将由 Firebase 处理，我们只需要添加一个监听器来确保我们的应用程序在身份验证状态更改时得到更新：

```jsx
firebase.auth().onAuthStateChanged((user) => {
  //user has logged in or out
}
```

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将命名为`messagingApp`，并将可用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.45.1" messagingApp
```

我们将使用 MobX 来管理应用程序中的状态，因此我们需要一个存储文件夹。其余的文件夹结构对大多数 React 应用程序都是标准的。

我们需要五个屏幕（`Chats`、`Chat`、`Login`、`Profile`和`Search`）、一个组件（`ListItem`）和两个存储（`chats`和`users`），这些将通过`stores/index.js`文件可用。我们还将使用两个辅助程序来支持我们的应用程序：

+   `notifications.js`：所有与推送通知相关的逻辑将存储在此文件中

+   `firebase.js`：这包括 Firebase SDK 的配置和初始化

由于我们将使用 MobX 和其他几个依赖项，让我们查看一下我们的`package.json`文件，以了解我们将使用哪些包：

```jsx
/*** package.json ***/

{
        “name": “messagingApp",
        “version": “0.0.1",
        “private": true,
        “scripts": {
                “start": “node node_modules/react-native/local-cli
                         /cli.js start",
                “test": “jest"
        },
        “dependencies": {
                “firebase": “⁴.1.3",
                “mobx": “³.2.0",
                “mobx-react": “⁴.2.2",
                “react": “16.0.0-alpha.12",
                “react-native": “0.45.1",
                “react-native-fcm": “⁷.1.0",
                “react-native-gifted-chat": “⁰.2.0",
                “react-native-keyboard-aware-scroll-view": “⁰.2.9",
                “react-native-vector-icons": “⁴.2.0",
                “react-navigation": “¹.0.0-beta.11"
        },
        “devDependencies": {
                “babel-jest": “20.0.3",
                “babel-plugin-transform-decorators-legacy": “¹.3.4",
                “babel-preset-react-native": “2.1.0",
                “jest": “20.0.4",
                “react-test-renderer": “16.0.0-alpha.12"
        },
        “jest": {
                “preset": “react-native"
        }
}
```

我们将使用一些`npm`包：

+   `firebase`：Firebase 的身份验证和数据库连接的 SDK

+   `mobx`：MobX 将处理我们的应用程序状态

+   `react-native-fcm`：Firebase 的推送消息 SDK

+   `react-native-gifted-chat`：用于渲染聊天室的库，包括日期分隔、头像和许多其他功能

+   `react-native-keyboard-aware-scroll-view`：一个库，确保在处理表单时屏幕键盘不会隐藏任何焦点文本输入

+   `react-native-vector-icons`：我们将在此应用程序中使用 Font Awesome 图标

+   `react-navigation`：我们将使用抽屉式、选项卡式和堆栈式导航器来处理我们应用程序中的屏幕

+   `babel-plugin-transform-decorators-legacy`：此库允许我们使用装饰器（使用传统的`@`语法），在使用 MobX 时非常有用

在运行`npm install`之后，我们的应用程序将准备好开始编码。与以前的应用程序一样，我们的消息应用程序的入口点将是`index.ios.js`（iOS）和`index.android.js`（Android）中相同的代码：

```jsx
/*** index.ios.js and index.android.js ***/ 

import React from 'react'
import { AppRegistry } from 'react-native';
import App from './src/main';

import { Provider } from 'mobx-react/native';
import { chats, users } from './src/stores';

class MessagingApp extends React.Component {
  render() {
    return (
      <Provider users={users} chats={chats}>
        <App/>
      </Provider>
    )
  }
}

AppRegistry.registerComponent('messagingApp', () => MessagingApp);
```

这是使用 MobX 启动 React Native 应用程序的标准方式--`<Provider />`作为根元素提供，以将两个商店（`users`和`chats`）注入到我们应用程序中的屏幕中。所有初始化和导航逻辑都已推迟到`src/main.js`文件中：

```jsx
/*** src/main.js ***/

import React from 'react'
import { DrawerNavigator,TabNavigator } from 'react-navigation'
import { Platform, View } from 'react-native'
import { observer, inject } from 'mobx-react/native'

import Login from './screens/Login'
import Chats from './screens/Chats'
import Profile from './screens/Profile'
import Search from './screens/Search'
import { users, chats } from './stores'

let Navigator;
if(Platform.OS === 'ios'){
  Navigator = TabNavigator({
    Chats: { screen: Chats },
    Search: { screen: Search },
    Profile: { screen: Profile }
  }, {
    tabBarOptions: {
      inactiveTintColor: '#aaa',
      activeTintColor: '#000',
      showLabel: true
    }
  });
} else {
  Navigator = DrawerNavigator({
    Chats: { screen: Chats },
    Search: { screen: Search },
    Profile: { screen: Profile }
  });
}

@inject('users') @observer
export default class App extends React.Component {
  constructor() {
    super();
  }

  render() {
    if(this.props.users.isLoggedIn){
      return <Navigator/>
    } else {
      return <Login/>
    }
  }
}
```

我们在`src/main.js`文件中看到的第一件事是，我们将使用不同的导航器，这取决于我们运行应用程序的平台：iOS 将打开一个选项卡导航器，而 Android 将打开一个基于抽屉的导航器。

然后，我们会在我们应用程序的许多组件中重复看到一行：

```jsx
@inject('users') @observer
```

这是告诉 MobX 这个组件需要接收`users`商店的方式。然后 MobX 将其作为属性传递给这个组件，因此我们可以使用它所持有的所有方法和属性。在这种情况下，我们对`isLoggedIn`属性感兴趣，以便在用户尚未登录时向用户呈现`<Login />`屏幕。由于 MobX 将这个属性注入为我们组件的属性，访问它的正确方式将是`this.props.users.isLoggedIn`。

在继续构建组件之前，让我们看一下我们将在本课程中使用的商店，以更好地了解可用的数据和操作。

# 用户商店

该商店负责保存所有与用户相关的数据和逻辑，但也在用户登录时帮助聊天商店初始化：

```jsx
/*** src/stores/users.js ***/

import {observable, computed, map, toJS, action} from 'mobx';
import chats from './chats'
import firebase from 'firebase';
import { firebaseApp } from '../firebase';
import notifications from '../notifications'

class Users {
        @observable id = null;
        @observable isLoggedIn = false;
        @observable name = null;
        @observable avatar = null;
        @observable notificationsToken = null;
        @observable loggingIn = false;
        @observable registering = false;
        @observable loggingError = null;
        @observable registeringError = null;

        @action login = function(username, password) {
                //login with Firebase email/password method
        }

        @action logout = function() {
                //logout from Firebase authentication service
        }

        @action register = function(email, password, name) {
                //register through firebase authentication service
        }

        @action setNotificationsToken(token) {
                //store the notifications token for this device
        }

        searchUsers(name) {
                //helper for searching users by name in the database
        }

        constructor() {
                this.bindToFirebase();
        }

        bindToFirebase() {
                //Initialise connection to Firebase user 
                //authentication status and data
        }
}

const users = new Users();

export default users;
```

这些是我们为此商店需要的所有属性和方法。有几个标志（包含动词-ing 形式的属性）来注意网络活动。现在让我们实现每个方法：

```jsx
@action login = function(username, password) {
        this.loggingIn = true;
        this.loggingError = null;
        firebase.auth().signInWithEmailAndPassword(username, password)
        .then(() => {
                this.loggingIn = false;
                notifications.init((notificationsToken) => {
                        this.setNotificationsToken(notificationsToken);
                });
        })
        .catch((error) => {
                this.loggingIn = false;
                this.loggingError = error.message;
        });
}
```

使用 Firebase 登录就像在他们的身份验证 SDK 上调用`signInWithEmailAndPassword`一样简单。如果登录成功，我们将初始化通知模块以启用设备接收推送通知。我们将在注销时遵循相反的路径：

```jsx
@action logout = function() {
        notifications.unbind();
        this.setNotificationsToken('');
        firebase.auth().signOut();
}
```

在注册操作中，除了设置适当的网络活动标志之外，我们还需要验证用户输入了名称，初始化通知，并将名称存储在数据库中：

```jsx
@action register = function(email, password, name) {
        if(!name || name == '') {
                this.registering = false;
                this.registeringError = 'Name was not entered';
                return;
        }
        this.registering = true;
        this.registeringError = null;
        firebase.auth().createUserWithEmailAndPassword(email, password)
        .then((user) => {
                this.registering = false;
                notifications.init((notificationsToken) => {
                        this.setNotificationsToken(notificationsToken);
                });
                firebaseApp.database().ref('/users/' + user.uid).set({
                        name: name
                });
        })
        .catch((error) => {
                this.registering = false;
                this.registeringError = error.message;
        })
}
```

设置通知令牌只是在数据库中进行简单的更新：

```jsx
@action setNotificationsToken(token) {
        if(!this.id) return;
        this.notificationsToken = token;
        firebaseApp.database().ref('/users/' + this.id).update({
                notificationsToken: token
        });
}
```

`searchUsers()`方法没有标记为`@action`，因为它不会修改我们应用程序的状态，而只是在数据库中搜索并返回具有提供的名称的用户列表：

```jsx
searchUsers(name) {
        return new Promise(function(resolve) {
                firebaseApp.database().ref('/users/').once('value')
                .then(function(snapshot) {
                        let foundUsers = [];
                        const users = snapshot.val();
                        for(var id in users) {
                                if(users[id].name === name) {
                                        foundUsers.push({
                                                name: users[id].name,
                                                avatar: 
                                                users[id].avatar,
                                                notificationsToken:  
                                                users[id].
                                                notificationsToken,
                                                id
                                        });
                                }
                        }
                        resolve(foundUsers);
                });
        });
}
```

由于我们正在进行的请求是异步的，我们将以 promise 的形式返回结果。

最后，`bindToFirebase()`将把这个存储中的属性附加到 Firebase 数据库中的数据快照。这个方法由构造函数调用，因此它作为用户数据的初始化。重要的是要注意，当认证状态改变时，这些数据将被更新，以始终反映用户的最新数据：

```jsx
bindToFirebase() {
  return firebase.auth().onAuthStateChanged((user) => {
    if(this.chatsBind && typeof this.chatsBind.off === 'function')  
      this.chatsBind.off();
    if(this.userBind && typeof this.userBind.off === 'function') 
      this.userBind.off();

    if (user) {
      this.id = user.uid;
      this.isLoggedIn = true;
      this.chatsBind = chats.bindToFirebase(user.uid);
      this.userBind = firebaseApp.database().ref('/users/' + this.id).
                                             on('value', (snapshot) =>  
    {
        const userObj = snapshot.val();
        if(!userObj) return;
        this.name = userObj.name;
        this.avatar = userObj.avatar;
      });
    } else {
      this.id = null;
      this.isLoggedIn = false;
      this.userBind = null;
      this.name = null;
      this.avatar = null;
    }
  });
}
```

我们将存储聊天数据的监听器（作为`this.chatsBind`）和用户数据的监听器（作为`this.userBind`），这样我们可以在每次`auth`状态改变时移除它们（通过调用`off()`方法），然后附加新的监听器。

# 聊天存储

这个存储负责保存所有与聊天和消息相关的数据和逻辑，但它还有助于在用户登录时初始化`chats`存储：

```jsx
/*** src/stores/chats.js ***/

import { observable, computed, map, toJS, action } from 'mobx';
import { AsyncStorage } from 'react-native'

import { firebaseApp } from '../firebase'
import notifications from '../notifications'

class Chats {
  @observable list;
  @observable selectedChatMessages;
  @observable downloadingChats = false;
  @observable downloadingChat = false;

  @action addMessages = function(chatId, contactId, messages) {
    //add a list of messages to a chat
  }

  @action selectChat = function(id) {
    //set a chat as selected and retrieve all the messages for it
  }

  @action add(user1, user2) {
    //add a new chat to the list of chats for the users in it
  }

  bindToFirebase(userId) {
    //listen for the list of chats in Firebase to update the 
    @observable list
  }
}

const chats = new Chats()
export default chats;
```

我们将在`@observable list`中存储用户拥有的开放聊天列表。当用户选择一个聊天时，我们将下载并同步该聊天上的消息列表到`@observable selectedChatMessages`。然后，我们将设置一些标志，让用户知道我们正在从 Firebase 数据库下载数据。

让我们逐个查看每个方法。我们将从`addMessages`开始：

```jsx
@action addMessages = function(chatId, contactId, messages) {
  if(!messages || messages.length < 1) return;

  messages.forEach((message) => {
    let formattedMessage = {
      _id: message._id,
      user: {
        _id: message.user._id,
      }
    };
    if(message.text) formattedMessage.text = message.text;
    if(message.createdAt) formattedMessage.createdAt = 
      message.createdAt/1;
    if(message.user.name) formattedMessage.user.name = 
      message.user.name;
    if(message.user.avatar) formattedMessage.user.avatar = 
      message.user.avatar;
    if(message.image) formattedMessage.image = message.image;

    //add the message to the chat
    firebaseApp.database().ref('/messages/' + 
      chatId).push().set(formattedMessage);

    //notify person on the chat room
    firebaseApp.database().ref('/users/' + contactId).once('value')
    .then(function(snapshot) {
      var notificationsToken = snapshot.val().notificationsToken;
      notifications.sendNotification(notificationsToken, {
        sender: message.user.name,
        text: message.text,
        image: message.user.image,
        chatId
      });
    });
  });
}
```

这个方法接收三个参数：

+   `chatId`：消息将被添加到的聊天的 ID。

+   `contactId`：我们要发送消息的用户的 ID。这将用于向用户的联系人发送通知。

+   `messages`：这是我们想要添加到聊天中的所有消息的数组。

我们将循环遍历消息列表，格式化消息的方式，然后调用数据库引用上的`set()`方法，将新消息保存在 Firebase 数据库中。最后，我们需要向我们的联系人发送通知，因此我们通过查询`users`集合来检索他们的通知令牌，以获取他们的通知令牌。

通常，发送通知是由后端处理的，但由于我们正在在应用程序本身上设置所有逻辑，我们需要构建一个发送通知的函数。我们在我们的通知`module: notifications.sendNotification(notificationsToken, data);`中完成了这个。

让我们看看当我们选择一个聊天来显示其消息时会发生什么：

```jsx
@action selectChat = function(id) {
  this.downloadingChat = true;
  if(this.chatBind && typeof this.chatBind.off === 'function') 
  this.chatBind.off();
  this.chatBind = firebaseApp.database().ref('/messages/' + id)
  .on('value', (snapshot) => {
    this.selectedChatMessages = [];
    this.downloadingChat = false;
    const messagesObj = snapshot.val();
    for(var id in messagesObj) {
      this.selectedChatMessages.push({
        _id: id,
        text: messagesObj[id].text,
        createdAt: messagesObj[id].createdAt,
        user: {
          _id: messagesObj[id].user._id,
          name: messagesObj[id].user.name,
          avatar: messagesObj[id].user.avatar
        },
        image: messagesObj[id].image
      });
    }
  });
}
```

这里的主要功能是将监听器附加到消息/聊天 ID 集合，这将使`this.selectedChatMessages`可观察对象与数据库中所选聊天的消息列表同步。这意味着每当在 Firebase 中存储新消息时，`this.selectedChatMessages`将同步以反映它。这就是 Firebase SDK 中`on()`方法的工作原理：我们传递一个回调，我们可以使用它来将实时数据库与我们应用的状态同步。

添加新聊天将使用`add()`方法完成：

```jsx
@action add(user1, user2) {
  return new Promise(function(resolve, reject) {
    firebaseApp.database().ref('/chats/' + user1.id + '/' + user1.id + 
    user2.id).set({
      name: user2.name,
      image: user2.avatar,
      contactId: user2.id
    }).then(() => {
      firebaseApp.database().ref('/chats/' + user2.id + '/'
                                 + user1.id + 
      user2.id).set({
        name: user1.name,
        image: user1.avatar,
        contactId: user1.id
      }).then(() => {
        resolve();
      })
    })
  });
}
```

在这里，我们正在构建并返回一个承诺，当两个聊天（每个用户参与的一个）更新时将解决。这两个数据库更新可以被视为数据的复制，但它也将减少数据结构的复杂性，从而提高我们代码库的可读性。

这个存储中的最后一个方法是`bindToFirebase()`：

```jsx
bindToFirebase(userId) {
  this.downloadingChats = true;
  return firebaseApp.database().ref('/chats/' + userId).
                                on('value', (snapshot) => {
    this.downloadingChats = false;
    const chatsObj = snapshot.val();
    this.list = [];
    for(var id in chatsObj) {
      this.list.push({
        id,
        name: chatsObj[id].name,
        image: chatsObj[id].image,
        contactId: chatsObj[id].contactId
      });
    }
  });
}
```

正如我们在`users`存储中看到的，当用户登录时将调用此方法，并将监听器附加到`chats/<userId>`数据快照，以使所有聊天数据与数据库上的`this.list`属性同步。

为了方便起见，我们将两个存储都放在`src/stores/index.js`中，这样我们就可以在一行代码中导入它们：

```jsx
/*** src/stores/index.js ***/

import users from './users';
import chats from './chats';

export {
  users,
  chats
};
```

这就是我们将要使用的存储。正如我们所看到的，大部分业务逻辑都在这里处理，因此可以进行彻底的测试。现在让我们转移到我们将用于通知的辅助程序。

# 使用 Firebase 进行推送通知

Firebase 集成了 iOS 和 Android 的推送通知服务，但不幸的是，它没有提供任何 JavaScript 来使用它的 SDK。因此，一个开源库被创建，将 Objective-C 和 Java SDK 桥接到 React Native 模块中：`react-native-fcm`。

我们不会在本书中涵盖此模块的安装，因为这是一个不断变化的过程，最好在其存储库中进行跟踪[`github.com/evollu/react-native-fcm`](https://github.com/evollu/react-native-fcm)。

我们决定将这个模块的逻辑抽象到我们的`src/notifications.js`文件中，以便在保持可维护性的同时为每个组件提供该逻辑。让我们来看看这个文件：

```jsx
/*** src/notifications.js ***/

import {Platform} from 'react-native';
import FCM, {FCMEvent, RemoteNotificationResult, WillPresentNotificationResult, NotificationType} from 'react-native-fcm';

let notificationListener = null;
let refreshTokenListener = null;
const API_URL = 'https://fcm.googleapis.com/fcm/send';
const FirebaseServerKey = '<Your Firebase Server Key>';

const init = (cb) => {
  FCM.requestPermissions();
  FCM.getFCMToken().then(token => {
    cb(token)
  });
  refreshTokenListener = FCM.on(FCMEvent.RefreshToken, (token) => {
    cb(token);
  });
}

const onNotification = (cb) => {
  notificationListener = FCM.on(FCMEvent.Notification, (notif) => {
      cb(notif);

      if(Platform.OS ==='ios'){
        switch(notif._notificationType){
          case NotificationType.Remote:
            notif.finish(RemoteNotificationResult.NewData)
            break;
          case NotificationType.NotificationResponse:
            notif.finish();
            break;
          case NotificationType.WillPresent:
            notif.finish(WillPresentNotificationResult.All)
            break;
        }
      }
  })
}

const unbind = () => {
  if(notificationListener) notificationListener.remove();
  if(refreshTokenListener) refreshTokenListener.remove();
}

const sendNotification = (token, data) => {
  let body = JSON.stringify({
    “to": token,
    “notification": {
                “title": data.sender || '',
                “body": data. text || '',
                “sound": “default"
        },
    “data": {
      “name": data.sender,
      “chatId": data.chatId,
      “image": data.image
    },
        “priority": 10
  });

  let headers = new Headers({
                “Content-Type": “application/json",
                “Content-Length": parseInt(body.length),
                “Authorization": “key=" + FirebaseServerKey
  });

  fetch(API_URL, { method: “POST", headers, body })
        .then(response => console.log(“Send response", response))
        .catch(error => console.log(“Error sending “, error));
}

export default { init, onNotification, sendNotification, unbind }
```

这个模块中暴露了四个函数：

+   `init`：这请求权限接收推送通知（如果尚未授予），并请求设备令牌或在更改时刷新它。

+   `onNotification`：当收到通知时，调用提供的回调函数。在 iOS 中，它还调用通知上的适当方法来关闭循环。

+   `unbind`：这将停止监听推送通知。

+   `sendNotification`：这会格式化并发送推送通知到特定设备，使用提供的通知令牌。

在 Firebase 中发送通知可以使用它们的 HTTP API，因此我们将使用`fetch`来发送带有适当标头和主体数据的`POST`请求。

现在，我们已经拥有了构建屏幕和组件所需的所有逻辑。

# 登录

`<Login />`组件在逻辑上严重依赖于`users`存储，因为它主要专注于呈现登录和注册两个表单。所有表单的验证都由 Firebase 完成，因此我们只需要专注于呈现 UI 元素和调用适当的存储方法。

在这个屏幕中，我们将使用`react-native-keyboard-aware-scroll`视图，这是一个提供自动滚动的`<Scrollview />`模块，它会对任何聚焦的`<TextInput />`做出反应，以便它们在键盘弹出时不会被隐藏。

让我们来看一下代码：

```jsx
/*** src/screens/Login.js ***/

import React, { PropTypes } from 'react'
import {
  ScrollView,
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';
import { observer, inject } from 'mobx-react/native'
import Icon from 'react-native-vector-icons/FontAwesome'
import { KeyboardAwareScrollView } from 'react-native-keyboard-aware-scroll-view'

import LoginForm from '../components/LoginForm'
import RegistrationForm from '../components/RegistrationForm'

@inject('users') @observer
class Login extends React.Component {
  onLogin(email, password) {
    this.props.users.login(email, password);
  }

  onPressRegister(email, password, name) {
    this.props.users.register(email, password, name);
  }

  render() {
    return (
      <KeyboardAwareScrollView style={{padding: 20, marginTop: 20, 
        backgroundColor: '#eee'}}>
        <Icon name="comments" size={60} color='#ccc' 
          style={{alignSelf: 'center', paddingBottom: 20}}/>
        <View style={{alignItems: 'center', marginBottom: 20}}>
          <Text>- please, login to continue -</Text>
        </View>
        <LoginForm
          onPress={this.onLogin.bind(this)}
          busy={this.props.users.loggingIn}
          loggingError={this.props.users.loggingError}
        />
        <View style={{alignItems: 'center', marginTop: 20, 
                      marginBottom: 20}}>
          <Text>- or register -</Text>
        </View>
        <RegistrationForm
          onPress={this.onPressRegister.bind(this)}
          busy={this.props.users.registering}
          registeringError={this.props.users.registeringError}
        />
      </KeyboardAwareScrollView>
    )
  }
}

export default Login;
```

我们将登录屏幕分为两个表单：`<LoginForm />`和`<RegistrationForm />`。这两个组件都需要传递三个 props：

+   `onPress`：当按下**发送**按钮时，组件需要执行的操作。

+   `busy`：我们是否在等待远程数据？

+   `loginError/registrationError`：登录/注册时发生的错误的描述（如果发生了）。

我们将整个屏幕包裹在`<KeyboardAwareScrollView />`中，以确保当焦点集中时，没有任何`<TextInput />`会被键盘遮挡。现在让我们来看一下`LoginForm`：

```jsx
/*** src/components/LoginForm.js ***/

import React, { PropTypes } from 'react'
import {
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';

class LoginForm extends React.Component {
  state= {
    loginEmail: '',
    loginPassword: ''
  }

  onPressLogin() {
    this.props.onPress(this.state.loginEmail, 
    this.state.loginPassword);
  }

  render() {
    return (
        <View style={{backgroundColor: 'white', padding: 15, 
                      borderRadius: 10}}>
          {
            this.props.loggingError &&
            <View style={{backgroundColor: '#fcc', borderRadius: 5, 
              alignItems: 'center', marginBottom: 10}}>
              <Text>{this.props.loggingError}</Text>
            </View>
          }
          <TextInput
            autoCapitalize='none'
            autoCorrect={false}
            keyboardType='email-address'returnKeyType='next'
            style={{height: 40}}
            onChangeText={(loginEmail) => this.setState({loginEmail})}
            value={this.state.loginEmail}
            placeholder='email'
            onSubmitEditing={(event) => {
              this.refs.loginPassword.focus();
            }}
          />
          <TextInput
            ref='loginPassword'
            style={{height: 40}}
            onChangeText={(loginPassword) => 
            this.setState({loginPassword})}
            value={this.state.loginPassword}
            secureTextEntry={true}
            placeholder='password'
          />
          {
            this.props.busy ?
            <ActivityIndicator/>
            :
            <Button
              onPress={this.onPressLogin.bind(this)}
              title='Login'
            />
          }
        </View>
      )
  }
}

export default LoginForm;
```

对于包含电子邮件的`<TextInput />`元素，我们将属性`keyboardType='email-address'`设置为使`@`符号在软键盘上易于访问。还有其他选项，比如数字键盘，但我们只会在这个应用程序中使用`'email-address'`。

`<TextInput />`上的另一个有用的 prop 是`returnKeyType`。我们将`returnKeyType='next'`设置为那些不是最后一个的表单输入，以在键盘中显示`下一个`按钮，以便用户知道他们可以通过点击该按钮转到下一个输入。这个 prop 与以下 prop 一起使用：

```jsx
onSubmitEditing={(event) => {
  this.refs.loginPassword.focus();
}}
```

`onSubmitEditing` 是一个 `<TextInput />` 属性，当用户按下键盘上的 `Return` 或 `Next` 按钮时将被调用。我们使用它来聚焦到下一个 `<TextInput />`，在处理表单时这是非常用户友好的。为了获取下一个 `<TextInput />` 的引用，我们使用 `ref`，这并不是最安全的方式，但对于简单的表单来说已经足够了。为了使其工作，我们需要将相应的 `ref` 分配给下一个 `<TextInput />`：`ref='loginPassword'`。

`RegistrationForm` 是一个非常相似的表单：

```jsx
/*** src/components/RegistrationForm ***/

import React, { PropTypes } from 'react'
import {
  ScrollView,
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';

class RegisterForm extends React.Component {
  state= {
    registerEmail: '',
    registerPassword: '',
    registerName: ''
  }

  onPressRegister() {
    this.props.onPress(this.state.registerEmail, 
    this.state.registerPassword, this.state.registerName);
  }

  render() {
    return (
      <View style={{backgroundColor: 'white', padding: 15, 
                    borderRadius: 10}}>
        {
          this.props.registeringError &&
          <View style={{backgroundColor: '#fcc', borderRadius: 5, 
            alignItems: 'center', marginBottom: 10}}>
            <Text>{this.props.registeringError}</Text>
          </View>
        }
        <TextInput
          autoCapitalize='none'
          autoCorrect={false}
          keyboardType='email-address'
          returnKeyType='next'
          style={{height: 40}}
          onChangeText={(registerEmail) => 
          this.setState({registerEmail})}
          value={this.state.registerEmail}
          placeholder='email'
          onSubmitEditing={(event) => {
            this.refs.registerName.focus();
          }}
        />
        <TextInput
          ref='registerName'
          style={{height: 40}}
          onChangeText={(registerName) => 
          this.setState({registerName})}
          returnKeyType='next'
          value={this.state.registerName}
          placeholder='name'
          onSubmitEditing={(event) => {
            this.refs.registerPassword.focus();
          }}
        />
        <TextInput
          ref='registerPassword'
          style={{height: 40}}
          onChangeText={(registerPassword) => 
          this.setState({registerPassword})}
          value={this.state.registerPassword}
          secureTextEntry={true}
          placeholder='password'
        />
        {
          this.props.busy ?
          <ActivityIndicator/>
          :
          <Button
            onPress={this.onPressRegister.bind(this)}
            title='Register'
          />
        }
      </View>
    )
  }
}

export default RegisterForm;
```

# 聊天

这是显示打开聊天列表的屏幕。这里需要注意的特殊之处是，我们使用了第二个导航器来在聊天列表的顶部显示选定的聊天。这意味着我们的 `Chats` 组件中需要一个 `StackNavigator`，其中包含两个屏幕：`ChatList` 和 `Chat`。当用户从 `ChatList` 中点击一个聊天时，`StackNavigator` 将在 `ChatList` 顶部显示选定的聊天，通过标题栏中的标准 `< back` 按钮使聊天列表可用。

为了列出聊天，我们将使用 `<FlatList />`，这是一个用于渲染简单、平面列表的高性能界面，支持大部分 `<ListView />` 的功能：

```jsx
/*** src/screens/Chats.js ***/

import React, { PropTypes } from 'react'
import { View, Text, FlatList, ActivityIndicator } from 'react-native'
import { observer, inject } from 'mobx-react/native'
import { StackNavigator } from 'react-navigation'
import Icon from 'react-native-vector-icons/FontAwesome'
import notifications from '../notifications'

import ListItem from '../components/ListItem'
import Chat from './Chat'

@inject('chats') @observer
class ChatList extends React.Component {
  imgPlaceholder = 
  'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                    2160923_960_720.png'

  componentWillMount() {
    notifications.onNotification((notif)=>{
      this.props.navigation.goBack();
      this.props.navigation.navigate('Chat', {
        id: notif.chatId,
        name: notif.name || '',
        image: notif.image || this.imgPlaceholder
      })
    });
  }

  render () {
    return (
      <View>
        {
          this.props.chats.list &&
          <FlatList
            data={this.props.chats.list.toJS()}
            keyExtractor={(item, index) => item.id}
            renderItem={({item}) => {
              return (
                <ListItem
                  text={item.name}
                  image={item.image || this.imgPlaceholder}
                  onPress={() => this.props.navigation.navigate('Chat', 
                  {
                    id: item.id,
                    name: item.name,
                    image: item.image || this.imgPlaceholder,
                    contactId: item.contactId
                  })}
                />
              )
            }}
          />
        }
        {
          this.props.chats.downloadingChats &&
          <ActivityIndicator style={{marginTop: 20}}/>
        }
      </View>
    )
  }
}

const Navigator = StackNavigator({
  Chats: {
    screen: ChatList,
    navigationOptions: ({navigation}) => ({
      title: 'Chats',
    }),
  },
  Chat: {
    screen: Chat
  }
});

export default class Chats extends React.Component {
  static navigationOptions = {
    tabBarLabel: 'Chats',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="comment-o" size={30} color={tintColor}/>
    )
  };

  render() {
      return <Navigator />
  }
}
```

我们注意到的第一件事是我们注入了 `chats` 存储，其中保存了聊天列表：`@inject('chats') @observer`。我们需要这样做来构建我们的 `<FlatList />`，基于 `this.props.chats.list`，但是由于聊天列表是一个可观察的 MobX 对象，我们需要使用它的 `toJS()` 方法来转换它，使其成为一个 JavaScript 数组。

在 `componentWillMount()` 函数中，我们将调用通知模块上的 `onNotification` 来在用户每次按下设备上的推送通知时打开相应的聊天。因此，我们将在导航器上使用 `navigate()` 方法来打开正确的聊天界面，包括联系人的姓名和头像。

# 列表项

聊天列表依赖于 `<ListItem />` 来渲染列表中的每个特定聊天。这个组件是我们创建的一个自定义 UI 类，用来减少 `ChatList` 组件的复杂性：

```jsx
/*** src/components/ListItem.js ***/

import React, { PropTypes } from 'react'
import { View, Image, Text, TouchableOpacity } from 'react-native'
import Icon from 'react-native-vector-icons/FontAwesome'

const ListItem = (props) => {
  return (
    <TouchableOpacity onPress={props.onPress}>
      <View style={{height: 60, borderColor: '#ccc', 
                    borderBottomWidth: 1, 
        marginLeft: 10, flexDirection: 'row'}}>
        <View style={{padding: 15, paddingTop: 10}}>
          <Image source={{uri: props.image}} style={{width: 40, 
                                                     height: 40, 
            borderRadius: 20, resizeMode: 'cover'}}/>
        </View>
        <View style={{padding: 15, paddingTop: 20}}>
          <Text style={{fontSize: 15}}>{ props.text }</Text>
        </View>
        <Icon name="angle-right" size={20} color="#aaa" 
          style={{position: 'absolute', right: 20, top: 20}}/>
      </View>
    </TouchableOpacity>
  )
}

export default ListItem
```

这个组件上有很少的逻辑，因为它只接收一个名为 `onPress()` 的 prop，当 `<ListItem />` 被按下时将被调用，正如我们在这个组件的父组件中看到的那样，它将打开聊天界面以显示特定聊天中的消息列表。让我们来看看渲染特定聊天的 `chat` 屏幕。

# 聊天

为了保持我们的代码简洁和可维护，我们将使用`GiftedChat`来渲染聊天中的所有消息，但是我们仍然需要做一些工作来正确渲染这个屏幕：

```jsx
/*** src/screens/Chat.js ***/

import React, { PropTypes } from 'react'
import { View, Image, ActivityIndicator } from 'react-native';
import { observer, inject } from 'mobx-react/native'
import { GiftedChat } from 'react-native-gifted-chat'

@inject('chats', 'users') @observer
class Chat extends React.Component {
  static navigationOptions = ({ navigation, screenProps }) => ({
    title: navigation.state.params.name,
    headerRight: <Image source={{uri: navigation.state.params.image}} 
    style={{
      width: 30,
      height: 30,
      borderRadius: 15,
      marginRight: 10,
      resizeMode: 'cover'
    }}/>
  })

  onSend(messages) {
    this.props.chats.addMessages(this.chatId, this.contactId, 
    messages);
  }

  componentWillMount() {
    this.contactId = this.props.navigation.state.params.contactId;
    this.chatId = this.props.navigation.state.params.id;this.props.chats.selectChat(this.chatId);
  }

  render () {
    var messages = this.props.chats.selectedChatMessages;
    if(this.props.chats.downloadingChat) {
      return <View><ActivityIndicator style={{marginTop: 20}}/></View>
    }

    return (
      <GiftedChat
        onSend={(messages) => this.onSend(messages)}
        messages={messages ? messages.toJS().reverse() : []}
        user={{
          _id: this.props.users.id,
          name: this.props.users.name,
          avatar: this.props.users.avatar
        }}
      />
    )
  }
}

export default Chat;
```

我们还需要为我们的`<Chat />`组件注入一些存储。这次，我们需要`users`和`chats`存储，它们将作为组件内的 props 可用。该组件还期望从导航器接收两个参数：`chatId`（聊天的 ID）和`contactId`（用户正在聊天的人的 ID）。

当组件准备好被挂载（`onComponentWillMount()`）时，我们在组件内部保存`chatId`和`contactId`到更方便的变量中，并在`chats`存储上调用`selectChat()`方法。这将触发一个请求到 Firebase 数据库，以获取所选聊天的消息，这些消息将通过`chats`存储进行同步，并通过`this.props.chats.selectedChatMessages`在组件中访问。MobX 还将更新一个`downloadingChat`属性，以确保我们让用户知道数据正在从 Firebase 中检索。

最后，我们需要为`GiftedChat`添加一个`onSend()`函数，每次按下`Send`按钮时，它将在`chats`存储上调用`addMessages()`方法，以将消息发布到 Firebase。

`GiftedChat`在很大程度上帮助我们减少了渲染聊天消息列表所需的工作量。另一方面，我们需要按照`GiftedChat`的要求格式化消息，并提供一个`onSend()`函数，以便在需要将消息发布到我们的后端时执行。

# 搜索

搜索屏幕分为两部分：一个`<TextInput />`用于用户搜索姓名，一个`<FlatList />`用于显示输入姓名找到的联系人列表：

```jsx
import React, { PropTypes } from 'react'
import { View, TextInput, Button, FlatList } from 'react-native'
import Icon from 'react-native-vector-icons/FontAwesome'
import { observer, inject } from 'mobx-react/native'

import ListItem from '../components/ListItem'

@inject('users', 'chats') @observer
class Search extends React.Component {
  imgPlaceholder = 'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                   2160923_960_720.png'

  state = {
    name: '',
    foundUsers: null
  }

  static navigationOptions = {
    tabBarLabel: 'Search',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="search" size={30} color={tintColor}/>
    )
  };

  onPressSearch() {
    this.props.users.searchUsers(this.state.name)
    .then((foundUsers) => {
      this.setState({ foundUsers });
    });
  }

  onPressUser(user) {
    //open a chat with the selected user
  }

  render () {
    return (
      <View>
        <View style={{padding: 20, marginTop: 20, 
                      backgroundColor: '#eee'}}>
          <View style={{backgroundColor: 'white', padding: 15, 
                        borderRadius: 10}}>
            <TextInput
              style={{borderColor: 'gray', borderBottomWidth: 1, 
                      height: 40}}
              onChangeText={(name) => this.setState({name})}
              value={this.state.name}
              placeholder='Name of user'
            />
            <Button
              onPress={this.onPressSearch.bind(this)}
              title='Search'
            />
          </View>
        </View>
        {
          this.state.foundUsers &&
          <FlatList
            data={this.state.foundUsers}
            keyExtractor={(item, index) => index}
            renderItem={({item}) => {
              return (
                <ListItem
                  text={item.name}
                  image={item.avatar || this.imgPlaceholder}
                  onPress={this.onPressUser.bind(this, item)}
                />
              )
            }}
          />
        }
      </View>
    )
  }
}

export default Search;
```

该组件需要注入两个存储（`users`和`chats`）。当用户点击`搜索`按钮时，`users`存储用于调用`searchUsers()`方法。这个方法不会修改状态，因此我们需要提供一个回调来接收找到的用户列表，最终将该列表设置在组件的状态上。

第二个存储`chats`将用于通过从`onPressUser()`函数调用`add()`在 Firebase 中存储打开的聊天：

```jsx
onPressUser(user) {
  this.props.chats.add({
    id: this.props.users.id,
    name: this.props.users.name,
    avatar: this.props.users.avatar || this.imgPlaceholder,
    notificationsToken: this.props.users.notificationsToken || ''
  }, {
    id: user.id,
    name: user.name,
    avatar: user.avatar || this.imgPlaceholder,
    notificationsToken: user.notificationsToken || ''
  });

  this.props.navigation.navigate('Chats', {});
}
```

`chats`存储中的`add()`方法需要传递两个参数：每个用户在新打开的聊天中一个参数。这些数据将被正确存储在 Firebase 中，因此两个用户将在应用程序的聊天列表中看到聊天。添加新聊天后，我们将导航到聊天屏幕，以便用户可以查看添加是否成功。

# 个人资料

个人资料屏幕显示用户的头像，姓名和“注销”按钮以退出登录：

```jsx
import React, { PropTypes } from 'react'
import { View, Image, Button, Text } from 'react-native'
import { observer, inject } from 'mobx-react/native'
import Icon from 'react-native-vector-icons/FontAwesome'

import notifications from '../notifications'

@inject('users') @observer
class Profile extends React.Component {
  static navigationOptions = {
    tabBarLabel: 'Profile',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="user" size={30} color={tintColor}/>
    ),
  };

  imgPlaceholder = 
  'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                    2160923_960_720.png'

  onPressLogout() {
    this.props.users.logout();
  }

  render () {
    return (
        <View style={{ padding: 20 }}>
          {
              this.props.users.name &&
              <View style={{ flexDirection: 'row', alignItems: 'center' 
          }}>
                <Image
                  source={{uri: this.props.users.avatar || 
                  this.imgPlaceholder}}
                  style={{width: 100, height: 100, borderRadius: 50, 
                          margin: 20, resizeMode: 'cover'}}
                />
                <Text style={{fontSize: 25}}>{this.props.users.name}
               </Text>
              </View>
          }
          <Button
            onPress={this.onPressLogout.bind(this)}
            title="Logout"
          />
        </View>
    )
  }
}

export default Profile;
```

注销过程是通过在`users`存储上调用`logout()`方法来触发的。由于我们在`src/main.js`文件中控制了身份验证状态，因此在注销成功时，应用程序将自动返回到**登录**或**注册**屏幕。

# 总结

我们涵盖了大多数现代企业应用程序的几个重要主题：用户管理，数据同步，复杂的应用程序状态和处理表单。这是一个完整的应用程序，我们设法用一个小的代码库和 MobX 和 Firebase 的帮助来修复它。

Firebase 非常有能力在生产中处理具有大量用户的应用程序，但构建我们自己的后端系统不应该是一个复杂的任务，特别是如果我们有使用 socket.io 和实时数据库的经验。

在本课程中还有一些方面缺失，比如处理安全性（完全可以在 Firebase 内完成）或为两个以上用户创建聊天室。无论如何，这些方面都超出了 React Native 的环境，因此故意被排除在外。

完成本课程后，我们应该能够在 Firebase 和 MobX 上构建任何应用程序，因为我们涵盖了这两种技术上最常用的用例。当然，还有一些更复杂的情况被排除在外，但通过对本课程中解释的基础知识有很好的理解，它们可以很容易地学会。

在下一课中，我们将构建一种非常不同类型的应用程序：用 React Native 编写的游戏。

# 评估

1.  这个 ____ 存储负责保存所有与聊天和消息相关的数据和逻辑，并在用户登录时帮助聊天存储初始化。

1.  推送通知

1.  列表

1.  聊天

1.  搜索

1.  以下哪个是用于计算存储在精灵中的每个精灵的新位置的主要功能。

1.  `getRockProps()`

1.  `reducer()`

1.  `action()`

1.  移动精灵()

1.  判断以下陈述是真还是假：Firebase 允许移动开发人员使用云托管的 NoSQL 数据库实时存储和同步用户和设备之间的数据。

1.  背景图像不包含在任何自定义组件中，而是在 ______ 中。这是因为作为静态元素，它不需要任何特殊的逻辑。

1.  `<GamseContainer />`

1.  `<Image />`

1.  `<TouchableWithoutFeedback />`

1.  `<TouchableOpacity />`

1.  可用的 Redux 动作有哪些？


# 第四章：项目 4 - 游戏

应用商店上大多数成功的应用都是游戏。它们被证明非常受欢迎，因为移动用户倾向于在通勤、候诊室、旅行或者在家休息时玩各种类型的游戏。事实上，移动用户更倾向于为游戏付费，而不是市场上的其他类型的应用，因为大多数时候它们的感知价值更高。

现代游戏通常是使用强大的游戏引擎构建的，比如 Unity 或 Unreal，因为它们提供了一系列工具和框架来处理精灵、动画或物理效果。但事实是，由于其原生能力，React Native 也可以构建出优秀的游戏。此外，React Native 已经将许多网页和移动应用程序员引入游戏开发，因为它为他们提供了熟悉和直观的界面。当构建游戏时，非游戏开发人员可能需要理解一些游戏开发的概念，以充分利用库的优势。像精灵、滴答声或碰撞这样的概念是非游戏开发人员在构建游戏之前可能需要克服的小障碍。

游戏将为 iOS 和 Android 构建，并将使用有限数量的外部库。选择了 Redux 作为状态管理库，以帮助计算每一帧上每个精灵的位置。

我们将使用一些自定义精灵，并添加声音效果以提醒每次得分增加。构建游戏时的主要挑战之一是确保精灵能够响应式地渲染，以便不同设备以相同的比例显示游戏，从而在不同的屏幕尺寸上提供相同的游戏体验。

这款游戏将设计为仅支持竖屏模式。

# 概述

我们在这节课中要构建的游戏具有简单的机制：

+   目标是帮助一只鹦鹉在洞穴中飞过岩石

+   点击屏幕会使鹦鹉飞得更高

+   重力会把鹦鹉拉向地面

+   鹦鹉与岩石或地面之间的任何碰撞都将导致游戏结束

+   每次鹦鹉飞过一组岩石时，得分将增加

这种类型的游戏非常适合使用 React Native 构建，因为它实际上不需要复杂的动画或物理能力。我们只需要确保在正确的时间移动屏幕上的每个精灵（图形组件），以创建连续动画的感觉。

让我们来看一下我们游戏的初始屏幕：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_01.jpg)

这个屏幕展示了游戏的标志和关于如何启动游戏的说明。在这种情况下，简单的轻触将启动游戏机制，导致鹦鹉在每次轻触时向前飞行。

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_02.jpg)

玩家必须帮助我们的鹦鹉飞过岩石。每次通过一组岩石，玩家将获得一分。

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_03.jpg)

为了增加难度，岩石的高度将会变化，迫使鹦鹉飞得更高或更低以通过岩石。如果鹦鹉与岩石或地面发生碰撞，游戏将停止，并向用户呈现最终得分：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_04.jpg)

在这一点上，用户可以通过再次在屏幕上轻触来重新开始游戏。

为了使游戏更加美观和易玩，可以在屏幕的任何位置进行轻触，这将导致不同的效果，具体取决于用户所在的屏幕：

+   在初始屏幕上轻触将启动游戏

+   游戏中的轻触将导致鹦鹉飞得更高

+   在**游戏结束**屏幕上轻触将重新开始游戏并重置得分

正如可以观察到的那样，这将是一个非常简单的游戏，但正因为如此，它很容易扩展并且很有趣。在构建这种类型的应用程序时，一个重要的方面是拥有一套精美的图形。为此，我们将从多个游戏资产市场之一下载我们的资产，这些市场可以在线找到（大多数游戏资产需要支付一小笔费用，尽管偶尔也可以找到免费资产）。

这个游戏的技术挑战更多地在于精灵如何随时间移动，而不是在于复杂的状态维护。尽管如此，我们将使用 Redux 来保持和更新应用程序的状态，因为它是一个高性能且广为人知的解决方案。除了重新审视 Redux，我们还将在本课程中复习以下主题：

+   处理动画精灵

+   播放音效

+   检测碰撞的精灵

+   不同屏幕分辨率下的绝对定位

# 精灵

精灵是游戏中使用的图形，通常分组成一个或多个图像。许多游戏引擎包括工具来方便地拆分和管理这些图形，但在 React Native 中并非如此。由于它是设计用来处理不同类型的应用程序的，有几个库支持 React Native 处理精灵，但我们的游戏将足够简单，不需要使用这些库，所以我们将把一个图形存储在每个图像中，并将它们分别加载到应用程序中。

在开始构建游戏之前，让我们熟悉一下我们将加载的图形，因为它们将是整个应用程序的构建模块。

## 数字

我们将使用精灵来显示游戏中的得分，而不是使用`<Text/>`组件，以获得更吸引人的外观。这些是我们将用来表示用户得分的图像：

![数字](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_05.jpg)

如前所述，所有这些图形将存储在单独的图像中（命名为`0.png`到`9.png`），因为 React Native 缺乏精灵拆分功能。

## 背景

我们需要一个大背景来确保它适合所有屏幕尺寸。在本课程中，我们将使用这个精灵作为静态图形，尽管它可以很容易地进行动画处理，以创建一个漂亮的视差效果：

![背景](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_06.jpg)

从这个背景中，我们将取一块地面来进行动画。

## 地面

地面将循环动画，以创建恒定的速度感。这个图像的大小需要大于我们想要支持的最大屏幕分辨率，因为它应该从屏幕的一侧移动到另一侧。在任何时候，将显示两个地面图像，一个接一个地确保在动画期间至少显示一个图像在屏幕上。

![地面](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_07.jpg)

## 岩石

移动的岩石是我们的鹦鹉需要通过的障碍物。顶部和底部各有一个，并且两者将以与地面相同的速度进行动画处理。它们的高度将因每对岩石而异，但始终保持它们之间的间隙大小相同：

![岩石](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_08.jpg)

在我们的`images`文件夹中，我们将有`rock-up.png`和`rock-down.png`代表每个精灵。

## 鹦鹉

我们将使用两张不同的图像来表示我们的主角，这样我们就可以创建一个动画，显示用户何时点击了屏幕：

![鹦鹉](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_09.jpg)

第一张图将在鹦鹉向下移动时显示：

![鹦鹉](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_10.jpg)

第二张图片将在用户按下屏幕使鹦鹉上升时显示。这些图片将被命名为`parrot1.png`和`parrot2.png`。

## 主屏幕

对于主屏幕，我们将显示两张图片：一个标志和一些关于如何开始游戏的说明。让我们来看看它们：

![主屏幕](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_11.jpg)

开始游戏的说明只是指出轻触将开始游戏：

![主屏幕](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_12.jpg)

## 游戏结束画面

当鹦鹉撞到岩石或地面时，游戏将结束。然后，是时候显示游戏结束标志和重置按钮，以重新开始游戏：

![游戏结束画面](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_13.jpg)

虽然整个屏幕都可以触摸以重新开始游戏，但我们将包括一个按钮，让用户知道轻触将导致游戏重新开始：

![游戏结束画面](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_14.jpg)

这张图片将被存储为`reset.png`。

这是我们游戏中将拥有的全部图片列表：

![游戏结束画面](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_15.jpg)

现在，我们知道了我们游戏中将使用的图片列表。让我们来看看整个文件夹结构。

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将命名为`birdGame`，并可用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.46.4" birdGame
```

由于这是一个简单的游戏，我们只需要一个屏幕，我们将在其中定位所有我们的精灵，根据游戏状态移动、显示或隐藏它们，这将由 Redux 管理。因此，我们的文件夹结构将符合标准的 Redux 应用程序：

![设置文件夹结构](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_16.jpg)

`actions`文件夹将只包含一个文件，因为在这个游戏中只会发生三个动作（`start`，`tick`和`bounce`）。还有一个`sounds`文件夹，用于存储每次鹦鹉通过一对岩石时播放的音效：

![设置文件夹结构](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_17.jpg)

对于每个精灵，我们将创建一个组件，以便可以轻松地移动、显示或隐藏它：

![设置文件夹结构](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_18.jpg)

再次，只需要一个 reducer 来处理我们所有的动作。我们还将创建两个辅助文件：

+   `constants.js`：这是我们将存储用于分割播放游戏设备屏幕高度和宽度的辅助变量的地方。

+   `sprites.js`：这里存储了所有将计算精灵在每一帧中应该定位的函数，以创建所需的动画。

`main.js`将作为 iOS 和 Android 的入口点，并负责初始化 Redux：

![设置文件夹结构](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/04_19.jpg)

其余文件由 React Native 的 CLI 生成。

现在让我们来审查一下`package.json`文件，我们需要在项目中设置依赖项：

```jsx
/*** package.json ***/

{
  “name": “birdGame",
  “version": “0.0.1",
  “private": true,
  “scripts": {
    “start": “node node_modules/react-native/local-cli/cli.js start",
    “test": “jest"
  },
  “dependencies": {
    “react": “16.0.0-alpha.12",
    “react-native": “0.46.4",
    “react-native-sound": “⁰.10.3",
    “react-redux": “⁴.4.5",
    “redux": “³.5.2"
  },
  “devDependencies": {
    “babel-jest": “20.0.3",
    “babel-preset-react-native": “2.1.0",
    “jest": “20.0.4",
    “react-test-renderer": “16.0.0-alpha.12"
  },
  “jest": {
    “preset": “react-native"
  }
}
```

除了 Redux 库，我们还将导入`react-native-sound`，它将负责在我们的游戏中播放任何声音。

运行`npm install`后，我们的应用程序将准备好开始编码。与以前的应用程序一样，我们的消息应用的入口点将在`index.ios.js`和`index.android.js`中是相同的代码，但两者都将将初始化逻辑委托给`src/main.js`：

```jsx
/*** index.ios.js and index.android.js ***/ 

import { AppRegistry } from 'react-native';
import App from './src/main';

AppRegistry.registerComponent('birdGame', () => App);
```

`src/main.js`负责初始化 Redux，并将`GameContainer`设置为我们应用程序的根组件：

```jsx
/*** src/main.js ***/

import React from “react";
import { createStore, combineReducers } from “redux";
import { Provider } from “react-redux";

import gameReducer from “./reducers/game";
import GameContainer from “./components/GameContainer";

let store = createStore(combineReducers({ gameReducer }));

export default class App extends React.Component {
  render() {
    return (
      <Provider store={store}>
        <GameContainer />
      </Provider>
    );
  }
}
```

我们将`GameContainer`用作应用程序中组件树的根。作为常规的 Redux 应用程序，`<Provider />`组件负责向所有需要读取或修改应用程序状态的组件提供存储。

# GameContainer

`GameContainer`负责在用户点击屏幕后启动游戏。它将使用`requestAnimationFrame()`来实现这一点——这是 React Native 中实现的自定义定时器之一。

`requestAnimationFrame()`类似于`setTimeout()`，但前者会在所有帧刷新后触发，而后者会尽快触发（在 iPhone 5S 上每秒超过 1000 次）；因此，`requestAnimationFrame()`更适合处理动画游戏，因为它只处理帧。

与大多数动画游戏一样，我们需要创建一个循环来通过计算每个元素在每一帧上的下一个位置来为屏幕中的精灵创建动画。这个循环将由`GameContainer`内部的名为`nextFrame()`的函数创建：

```jsx
nextFrame() {
if (this.props.gameOver) return;
    var elapsedTime = new Date() - this.time;
    this.time = new Date();
    this.props.tick(elapsedTime);
this.animationFrameId = 
      requestAnimationFrame(this.nextFrame.bind(this));
}
```

如果属性`gameOver`设置为`true`，则此函数将被中止。否则，它将触发`tick()`动作（根据经过的时间计算精灵在下一帧上应该如何移动），最后通过`requestAnimationFrame()`调用自身。这将保持游戏中的循环以动画移动精灵。

当然，这个`nextFrame()`应该在第一次开始时被调用，所以我们还将在`GameContainer`内创建一个`start()`函数来启动游戏：

```jsx
start() {
cancelAnimationFrame(this.animationFrameId);
    this.props.start();
    this.props.bounce();
    this.time = new Date();
    this.setState({ gameOver: false });
this.animationFrameId = 
      requestAnimationFrame(this.nextFrame.bind(this));
}
```

`start`函数通过调用`cancelAnimationFrame()`确保没有启动任何动画。这将防止用户重置游戏时执行任何双重动画。

然后，这些函数触发`start()`动作，它只是在存储中设置一个标志，以通知游戏已经开始。

我们希望通过将鹦鹉向上移动来开始游戏，这样用户就有时间做出反应。为此，我们还调用`bounce()`动作。

最后，我们通过将已知的`nextFrame()`函数作为`requestAnimationFrame()`的回调来启动动画循环。

让我们也来审查一下我们将用于这个容器的`render()`方法：

```jsx
render() {
    const {
      rockUp,
      rockDown,
      ground,
      ground2,
      parrot,
      isStarted,
      gameOver,
      bounce,
      score
    } = this.props;

    return (
      <TouchableOpacity
onPress={
          !isStarted || gameOver ? this.start.bind(this) : 
            bounce.bind(this)
        }
        style={styles.screen}
activeOpacity={1}
      >
        <Image
          source={require(“../../images/bg.png")}
          style={[styles.screen, styles.image]}
        />
        <RockUp
          x={rockUp.position.x * W} //W is a responsiveness factor 
                                    //explained in the 'constants' section
          y={rockUp.position.y}
          height={rockUp.size.height}
          width={rockUp.size.width}
        />
        <Ground
          x={ground.position.x * W}
          y={ground.position.y}
          height={ground.size.height}
          width={ground.size.width}
        />
        <Ground
          x={ground2.position.x * W}
          y={ground2.position.y}
          height={ground2.size.height}
          width={ground2.size.width}
        />
        <RockDown
          x={rockDown.position.x * W}
          y={rockDown.position.y * H} //H is a responsiveness factor  
                                      //explained in the 'constants' 
                                      //section
          height={rockDown.size.height}
          width={rockDown.size.width}
        />
        <Parrot
          x={parrot.position.x * W}
          y={parrot.position.y * H}
          height={parrot.size.height}
          width={parrot.size.width}
        />
        <Score score={score} />
        {!isStarted && <Start />}
        {gameOver && <GameOver />}
        {gameOver && isStarted && <StartAgain />}
      </TouchableOpacity>
    );
  }
```

可能会很长，但实际上，它只是简单地将屏幕上所有可见元素进行定位，同时将它们包裹在`<TouchableOpacity />`组件中，以便捕捉用户在屏幕的任何部分点击。这个`<TouchableOpacity />`组件实际上在用户点击屏幕时不会向用户发送任何反馈（我们通过传递`activeOpacity={1}`作为属性来禁用它），因为这个反馈已经由鹦鹉在每次点击时反弹来提供。

### 注意

我们本可以使用 React Native 的`<TouchableWithoutFeedback />`来处理这个问题，但它有一些限制，这可能会影响我们的性能。

提供的`onPress`属性只是定义了用户在屏幕上点击时应用程序应该执行的操作：

+   如果游戏处于活动状态，它将使鹦鹉精灵反弹

+   如果用户在游戏结束画面上，它将通过调用`start()`动作重新启动游戏

`render()`方法中的所有其他子元素都是我们游戏中的图形元素，为每个元素指定它们的位置和大小。还有几点需要注意：

+   有两个`<Ground />`组件，因为我们需要在*x*轴上连续地对其进行动画处理。它们将水平排列在一起，以便一起进行动画处理，因此当第一个`<Ground />`组件的末端显示在屏幕上时，第二个的开头将跟随其后，从而创建连续感。

+   背景不包含在任何自定义组件中，而是包含在`<Image />`中。这是因为作为静态元素，它不需要任何特殊的逻辑。

+   一些位置被因子变量（`W`和`H`）相乘。我们将在常量部分更深入地研究这些变量。在这一点上，我们只需要知道它们是帮助绝对定位元素的变量，考虑到所有屏幕尺寸。

+   现在让我们将所有这些函数放在一起来构建我们的`<GameContainer />`：

```jsx
/*** src/components/GameContainer.js ***/

import React, { Component } from “react";
import { connect } from “react-redux";
import { bindActionCreators } from “redux";
import { TouchableOpacity, Image, StyleSheet } from “react-native";

import * as Actions from “../actions";
import { W, H } from “../constants";
import Parrot from “./Parrot";
import Ground from “./Ground";
import RockUp from “./RockUp";
import RockDown from “./RockDown";
import Score from “./Score";
import Start from “./Start";
import StartAgain from “./StartAgain";
import GameOver from “./GameOver";

class Game extends Component {
constructor() {
    super();
    this.animationFrameId = null;
    this.time = new Date();
  }

  nextFrame() {
     ...
  }

  start() {
     ...
  }

componentWillUpdate(nextProps, nextState) {
    if (nextProps.gameOver) {
      this.setState({ gameOver: true });
      cancelAnimationFrame(this.animationFrameId);
    }
  }

shouldComponentUpdate(nextProps, nextState) {
    return !nextState.gameOver;
  }

  render() {

     ...

  }
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    alignSelf: “stretch",
    width: null
  },
  image: {
    resizeMode: “cover"
  }
});

function mapStateToProps(state) {
  const sprites = state.gameReducer.sprites;
  return {
parrot: sprites[0],
    rockUp: sprites[1],
    rockDown: sprites[2],
    gap: sprites[3],
    ground: sprites[4],
    ground2: sprites[5],
    score: state.gameReducer.score,
    gameOver: state.gameReducer.gameOver,
    isStarted: state.gameReducer.isStarted
  };
}
function mapStateActionsToProps(dispatch) {
  return bindActionCreators(Actions, dispatch);
}

export default connect(mapStateToProps, mapStateActionsToProps)(Game);
```

我们在这个组件中添加了另外三个 ES6 和 React 生命周期方法：

+   `super()`: 构造函数将保存一个名为`animationFrameId`的属性，以捕获`nextFrame`函数将运行的动画帧的 ID，还将保存另一个名为`time`的属性，该属性将存储游戏初始化的确切时间。`time`属性将被`tick()`函数用于计算精灵应该移动多少。

+   `componentWillUpdate()`: 每当传递新的 props（游戏中精灵的位置和大小）时，将调用此函数。它将检测游戏是否因碰撞而必须停止，因此游戏结束屏幕将被显示。

+   `shouldComponentUpdate()`: 这执行另一个检查，以避免在游戏结束时重新渲染游戏容器。

其余的函数与 Redux 相关。它们负责通过注入操作和属性将组件连接到存储中：

+   `mapStateToProps()`: 这会获取存储中所有精灵的数据，并将它们注入组件作为 props。精灵将被存储在一个数组中，因此它们将通过索引访问。除此之外，`Score`，一个标志表示当前游戏是否结束，以及一个标志表示游戏是否正在进行也将从状态中检索并注入到组件中。

+   `mapStateActionsToProps()`: 这将把三个可用操作（`tick`，`bounce`和`start`）注入到组件中，以便它们可以被使用。

### 注意

通过索引访问精灵数据并不是一种推荐的做法，因为如果精灵的数量增加，索引可能会发生变化，但出于简单起见，我们将在此应用中使用它。

# 操作

正如我们之前提到的，只有三个 Redux 操作将可用：

+   `tick()`: 计算屏幕上精灵的下一个位置

+   `bounce()`: 让鹦鹉向上飞

+   `start()`: 初始化游戏变量

这意味着我们的`src/actions/index.js`文件应该非常简单：

```jsx
/*** src/actions/index.js ***/

export function start() {
  return { type: “START" };
}

export function tick(elapsedTime) {
  return { type: “TICK", elapsedTime };
}

export function bounce() {
  return { type: “BOUNCE" };
}
```

只有`tick()`操作需要传递一个有效负载：自上一帧以来经过的时间。

# Reducer

由于我们有非常有限的行动，我们的减速器也会相当简单，并且会将大部分功能委托给`src/sprites.js`文件中的精灵助手函数：

```jsx
/*** src/reducers/index.js ***/

import {
  sprites,
  moveSprites,
  checkForCollision,
  getUpdatedScore,
  bounceParrot
} from “../sprites";

const initialState = {
  score: 0,
  gameOver: false,
  isStarted: false,
  sprites
};

export default (state = initialState, action) => {
  switch (action.type) {
    case “TICK":
      return {
        ...state,
        sprites: moveSprites(state.sprites, action.elapsedTime),
        gameOver: checkForCollision(state.sprites[0], 
        state.sprites.slice(1)),
        score: getUpdatedScore(state.sprites, state.score)
      };
    case “BOUNCE":
      return {
        ...state,
        sprites: bounceParrot(state.sprites)
      };
    case “START":
      return {
        ...initialState,
        isStarted: true
      };
    default:
      return state;
  }
};
```

`start()`函数只需要将`isStarted`标志设置为`true`，因为初始状态默认情况下将其设置为`false`。我们将在每次游戏结束时重用此初始状态。

`bounce()`将使用精灵模块中的`bounceParrot()`函数来为主角设置新的方向。

最重要的变化将发生在触发`tick()`函数时，因为它需要计算所有移动元素的位置（通过`moveSprites()`函数），检测鹦鹉是否与任何静态元素发生碰撞（通过`checkForCollision()`函数），并在存储中更新得分（通过`getUpdatedScore()`函数）。

正如我们所看到的，大部分游戏功能都委托给了精灵模块内的辅助函数，因此让我们更深入地看一下`src/sprites.js`文件。

# 精灵模块

精灵模块的结构由精灵数组和几个导出函数组成：

```jsx
/*** src/sprites.js ***/

import sound from “react-native-sound";

const coinSound = new sound(“coin.wav", sound.MAIN_BUNDLE);
let heightOfRockUp = 25;
let heightOfRockDown = 25;
let heightOfGap = 30;
let heightOfGround = 20;

export const sprites = [
   ...
];

function prepareNewRockSizes() {
  ...
}

function getRockProps(type) {
  ...
}

export function moveSprites(sprites, elapsedTime = 1000 / 60) {
  ...
}

export function bounceParrot(sprites) {
  ...
}

function hasCollided(mainSprite, sprite) {
  ...
}

export function checkForCollision(mainSprite, sprites) {
  ...
}

export function getUpdatedScore(sprites, score) {
  ...
}
```

该模块首先通过加载我们将在鹦鹉通过一组岩石时播放的音效来开始，以向用户反馈其得分增加。

然后，我们为几个精灵定义了一些高度：

+   `heightOfRockUp`：这是将出现在屏幕上部的岩石的高度。

+   `heightOfRockDown`：这是岩石的高度，将显示在屏幕的下部。

+   `heightOfGap`：我们将在上部和下部岩石之间创建一个不可见的视图，以侦测鹦鹉何时通过每组岩石，以便更新得分。这是间隙的高度。

+   `heightOfGround`：这是地面高度的静态值。

此模块中的每个其他项目都在移动或定位屏幕上的精灵。

## 精灵数组

这是负责在给定时间存储所有精灵位置和大小的数组。为什么我们使用数组来存储我们的精灵，而不是哈希映射（对象）？主要是为了可扩展性；虽然哈希映射会使我们的代码更易读，但如果我们想要添加新的现有类型的精灵（就像在这个应用程序中的`ground`精灵一样），我们需要为它们每个使用人工键，尽管它们是相同类型的。使用精灵数组是游戏开发中的一种常见模式，它允许将实现与精灵列表解耦。

每当我们想要移动一个精灵，我们将更新它在这个数组中的位置：

```jsx
export const sprites = [
  {

    type: “parrot",
    position: { x: 50, y: 55 },
    velocity: { x: 0, y: 0 },
    size: { width: 10, height: 8 }
  },
  {
    type: “rockUp",
    position: { x: 110, y: 0 },
    velocity: { x: -1, y: 0 },
    size: { width: 15, height: heightOfRockUp }
  },
  {
    type: “rockDown",
    position: { x: 110, y: heightOfRockUp + 30 },
    velocity: { x: -1, y: 0 },
    size: { width: 15, height: heightOfRockDown }
  },
  {
    type: “gap",
    position: { x: 110, y: heightOfRockUp },
    velocity: { x: -1, y: 0 },
    size: { width: 15, height: 30 }
  },
  {
    type: “ground",
    position: { x: 0, y: 80 },
    velocity: { x: -1, y: 0 },
    size: { width: 100, height: heightOfGround }
  },
  {
    type: “ground",
    position: { x: 100, y: 80 },
    velocity: { x: -1, y: 0 },
    size: { width: 100, height: heightOfGround }
  }
];
```

数组将存储游戏中所有移动精灵的定位和大小的初始值。

## prepareNewRockSizes()

这个函数随机计算下一个上部和下部岩石的大小以及它们之间间隙的高度：

```jsx
function prepareNewRockSizes() {
  heightOfRockUp = 10 + Math.floor(Math.random() * 40);
  heightOfRockDown = 50 - heightOfRockUp;
  heightOfGap = 30;
}
```

重要的是要注意，这个函数只计算新一组岩石的高度，但不创建它们。这只是一个准备步骤。

## getRockProps()

格式化岩石（或`gap`）的`position`和`size`属性的辅助函数：

```jsx
function getRockProps(type) {
  switch (type) {
    case “rockUp":
      return { y: 0, height: heightOfRockUp };
    case “rockDown":
      return { y: heightOfRockUp + heightOfGap, 
               height: heightOfRockDown };
    case “gap":
      return { y: heightOfRockUp, height: heightOfGap };
  }
}
```

## 移动精灵()

这是主要函数，因为它计算了存储在精灵数组中的每个精灵的新位置。游戏开发依赖于物理学来计算每帧中每个精灵的位置。

例如，如果我们想要将一个对象移动到屏幕的右侧，我们将需要更新它的`x`位置一定数量的像素。我们为对象的`x`属性添加的像素越多，下一帧它就移动得越快（`sprite.x = sprite.x + 5;`比`sprite.x = sprite.x + 1;`移动得快五倍）。

正如我们在下面的例子中所看到的，我们计算每个精灵的新位置的方式基于三个因素：精灵的当前位置，自上一帧以来经过的时间（`elapsedTime`），以及精灵的重力/速度（`即 sprite.velocity.y + elapsedTime * gravity`）。

此外，我们将使用辅助函数`getRockProps`来获取岩石的新大小和位置。让我们看看`moveSprites`函数是什么样子的：

```jsx
export function moveSprites(sprites, elapsedTime = 1000 / 60) {
  const gravity = 0.0001;
  let newSprites = [];

  sprites.forEach(sprite => {
    if (sprite.type === “parrot") {
      var newParrot = {
        ...sprite,
        position: {
          x: sprite.position.x,
          y:
            sprite.position.y +
            sprite.velocity.y * elapsedTime +
            0.5 * gravity * elapsedTime * elapsedTime
        },
        velocity: {
          x: sprite.velocity.x,
          y: sprite.velocity.y + elapsedTime * gravity
        }
      };
      newSprites.push(newParrot);
    } else if (
      sprite.type === “rockUp" ||
      sprite.type === “rockDown" ||
      sprite.type === “gap"
    ) {
      let rockPosition,
        rockSize = sprite.size;
      if (sprite.position.x > 0 - sprite.size.width) {
        rockPosition = {
          x: sprite.position.x + sprite.velocity.x,
          y: sprite.position.y
        };
      } else {
        rockPosition = { x: 100, y: getRockProps(sprite.type).y };
        rockSize = { width: 15, 
                     height: getRockProps(sprite.type).height };
      }
      var newRock = {
        ...sprite,
        position: rockPosition,
        size: rockSize
      };
      newSprites.push(newRock);
    } else if (sprite.type === “ground") {
      let groundPosition;
      if (sprite.position.x > -97) {
        groundPosition = { x: sprite.position.x + sprite.velocity.x,
                           y: 80 };
      } else {
        groundPosition = { x: 100, y: 80 };
      }
      var newGround = { ...sprite, position: groundPosition };
      newSprites.push(newGround);
    }
  });
  return newSprites;
}
```

计算精灵的下一个位置，大多数情况下是基本的加法（或减法）。例如，让我们看看鹦鹉应该如何移动：

```jsx
var newParrot = {
        ...sprite,
        position: {
          x: sprite.position.x,
          y:
            sprite.position.y +
            sprite.velocity.y * elapsedTime +
            0.5 * gravity * elapsedTime * elapsedTime
        },
        velocity: {
          x: sprite.velocity.x,
          y: sprite.velocity.y + elapsedTime * gravity
        }
     }
```

鹦鹉只会在垂直方向移动，其速度基于重力，因此`x`属性对它来说始终保持不变，而`y`属性将根据函数`sprite.position.y +` `sprite.velocity.y * elapsedTime +` `0.5 * gravity * elapsedTime * elapsedTime`进行改变，这个函数总结起来就是将经过的时间和重力分别加到不同的因素中。

岩石应该如何移动的计算要复杂一些，因为我们需要考虑每次岩石从屏幕上消失的情况（`if (sprite.position.x > 0 - sprite.size.width)`）。当它们被超过时，我们需要用不同的高度重新创建它们（`rockPosition = { x: 100, y: getRockProps(sprite.type).y }`）。

我们对地面也有相同的行为，需要在它完全离开屏幕时重新创建它（`if (sprite.position.x > -97)`）。

## 弹跳鹦鹉()

这个函数的唯一任务是改变主角的速度，这样它就会向上飞，逆转重力的影响。这个函数将在用户在游戏开始时点击屏幕时调用：

```jsx
export function bounceParrot(sprites) {
  var newSprites = [];
  var sprite = sprites[0];
  var newParrot = { ...sprite, velocity: { x: sprite.velocity.x,
                    y: -0.05 } };
  newSprites.push(newParrot);
  return newSprites.concat(sprites.slice(1));
}
```

这是一个简单的操作，我们从`sprites`数组中获取鹦鹉的精灵数据；我们将其在**y**轴上的速度更改为负值，以使鹦鹉向上移动。

## checkForCollision()

`checkForCollision()`负责识别任何刚性精灵是否与鹦鹉精灵发生了碰撞，以便游戏可以停止。它将使用`hasCollided()`作为一个支持函数，对每个特定的精灵执行所需的计算。

```jsx
function hasCollided(mainSprite, sprite) {
  /*** 
   *** we will check if 'mainSprite' has entered in the
   *** space occupied by 'sprite' by comparing their
   *** position, width and height 
   ***/

  var mainX = mainSprite.position.x;
  var mainY = mainSprite.position.y;
  var mainWidth = mainSprite.size.width;
  var mainHeight = mainSprite.size.height;

  var spriteX = sprite.position.x;
  var spriteY = sprite.position.y;
  var spriteWidth = sprite.size.width;
  var spriteHeight = sprite.size.height;

  /*** 
   *** this if statement checks if any border of mainSprite
   *** sits within the area covered by sprite 
   ***/

  if (
    mainX < spriteX + spriteWidth &&
    mainX + mainWidth > spriteX &&
    mainY < spriteY + spriteHeight &&
    mainHeight + mainY > spriteY
  ) {
    return true;
  }
}

export function checkForCollision(mainSprite, sprites) {
  /*** 
   *** loop through all sprites in the sprites array
   *** checking, for each of them, if there is a
   *** collision with the mainSprite (parrot)
   ***/

  return sprites.filter(sprite => sprite.type !== “gap").find(sprite => {
    return hasCollided(mainSprite, sprite);
  });
}
```

为了简单起见，我们假设所有精灵都是矩形的形状（尽管岩石朝末端变得更薄），因为如果考虑不同的形状，计算会更加复杂。

总之，`checkForCollision()`只是循环遍历`sprites`数组，以找到任何发生碰撞的精灵，`hasCollided()`根据精灵的大小和位置检查碰撞。在一个`if`语句中，我们比较了精灵和鹦鹉精灵的边界，以查看它们是否占据了屏幕相同的区域。

## getUpdatedScore()

精灵模块中的最后一个函数将检查分数是否需要根据鹦鹉位置相对于间隙位置（上下岩石之间的间隙也被视为一个精灵）进行更新：

```jsx
export function getUpdatedScore(sprites, score) {
  var parrot = sprites[0];
  var gap = sprites[3];

  var parrotXPostion = parrot.position.x;
  var gapXPosition = gap.position.x;
  var gapWidth = gap.size.width;

  if (parrotXPostion === gapXPosition + gapWidth) {
    coinSound.play();
    score++;
    prepareNewRockSizes();
  }

  return score;
}
```

一个`if`语句检查了鹦鹉在**x**轴上的位置是否超过了间隙（`gapXPosition + gapWidth`）。当这种情况发生时，我们通过调用其`play()`方法来播放我们在模块头部创建的声音（`const coinSound = new sound(“coin.wav", sound.MAIN_BUNDLE);`）。此外，我们将增加`score`变量，并准备一个新的岩石组在当前的岩石离开屏幕时渲染。

# 常量

我们已经看到了变量`W`和`H`。它们代表了屏幕的一部分，如果我们把它分成 100 部分。让我们看一下`constants.js`文件，以更好地理解这一点：

```jsx
/*** src/constants.js ***/

import { Dimensions } from “react-native";

var { width, height } = Dimensions.get(“window");

export const W = width / 100;
export const H = height / 100;
```

`W`可以通过将设备屏幕的总宽度除以`100`单位来计算（因为百分比在定位我们的精灵时更容易推理）。`H`也是如此；它可以通过将总高度除以`100`来计算。使用这两个常量，我们可以相对于屏幕的大小来定位和调整我们的精灵的大小，因此所有屏幕尺寸将显示相同的位置和大小比例。

这些常量将用于所有需要响应能力的视觉组件，因此它们将根据屏幕大小的不同显示和移动。这种技术将确保即使在小屏幕上，游戏也是可玩的，因为精灵将相应地调整大小。

现在让我们继续移动到将显示在`<GameContainer />`内的组件。

# 鹦鹉

主角将由这个组件表示，它将由`<GameContainer />`传递的`Y`位置属性驱动的两个不同的图像组成（翅膀上扬和下垂的相同鹦鹉）：

```jsx
/*** src/components/parrot.js ***/

import React from “react";
import { Image } from “react-native";
import { W, H } from “../constants";

export default class Parrot extends React.Component {
  constructor() {
    super();
    this.state = { wings: “down" };
  }

  componentWillUpdate(nextProps, nextState) {
    if (this.props.y < nextProps.y) {
      this.setState({ wings: “up" });
    } else if (this.props.y > nextProps.y) {
      this.setState({ wings: “down" });
    }
  }

  render() {
    let parrotImage;
    if (this.state.wings === “up") {
      parrotImage = require(“../../images/parrot1.png");
    } else {
      parrotImage = require(“../../images/parrot2.png");
    }
    return (
      <Image
        source={parrotImage}
        style={{
          position: “absolute",
          resizeMode: “contain",
          left: this.props.x,
          top: this.props.y,
          width: 12 * W,
          height: 12 * W
        }}
      />
    );
  }
}
```

我们使用一个名为`wings`的状态变量来选择鹦鹉将会是哪个形象--当它向上飞时，会显示翅膀下垂的形象，而向下飞时会显示翅膀上扬的形象。这将根据鸟在**y**轴上的位置来计算，该位置作为属性从容器传递过来：

+   如果`Y`位置低于先前的`Y`位置，意味着鸟正在下降，因此翅膀应该上扬

+   如果`Y`位置高于先前的`Y`位置，意味着鸟正在上升，因此翅膀应该下垂

鹦鹉的大小固定为`12 * W`，对于`height`和`width`都是如此，因为精灵是一个正方形，我们希望它相对于每个屏幕设备的宽度进行调整。

# RockUp 和 RockDown

岩石的精灵上没有逻辑，基本上是由父组件定位和调整大小的 `<Image />` 组件。这是 `<RockUp />` 的代码：

```jsx
/*** src/components/RockUp.js ***/

import React, { Component } from “react";
import { Image } from “react-native";

import { W, H } from “../constants";

export default class RockUp extends Component {
  render() {
    return (
      <Image
        resizeMode="stretch"
        source={require(“../../images/rock-down.png")}
        style={{
          position: “absolute",
          left: this.props.x,
          top: this.props.y,
          width: this.props.width * W,
          height: this.props.height * H
        }}
      />
    );
  }
}
```

高度和宽度将通过以下公式计算：`this.props.width * W` 和 `this.props.height * H`。这将使岩石相对于设备屏幕和提供的高度和宽度进行调整。

`<RockDown />` 的代码非常相似：

```jsx
/*** src/components/RockDown.js ***/

import React, { Component } from “react";
import { Image } from “react-native";

import { W, H } from “../constants";

export default class RockDown extends Component {
  render() {
    return (
      <Image
        resizeMode="stretch"
        source={require(“../../images/rock-up.png")}
        style={{
          position: “absolute",
          left: this.props.x,
          top: this.props.y,
          width: this.props.width * W,
          height: this.props.height * H
        }}
      />
    );
  }
}
```

# 地面

构建地面组件与岩石精灵类似。在正确的位置和大小渲染图像将足以满足此组件的需求：

```jsx
/*** src/components/Ground.js ***/

import React, { Component } from “react";
import { Image } from “react-native";

import { W, H } from “../constants";

export default class Ground extends Component {
  render() {
    return (
      <Image
        resizeMode="stretch"
        source={require(“../../images/ground.png")}
        style={{
          position: “absolute",
          left: this.props.x,
          top: this.props.y * H,
          width: this.props.width * W,
          height: this.props.height * H
        }}
      />
    );
  }
}
```

在这种情况下，我们将使用 `H` 来相对定位地面图像。

# 得分

我们决定使用数字图像来渲染分数，因此我们需要加载它们并根据用户的分数选择适当的数字：

```jsx
/*** src/components/Score.js ***/

import React, { Component } from “react";
import { View, Image } from “react-native";

import { W, H } from “../constants";

export default class Score extends Component {
getSource(num) {
    switch (num) {
      case “0":
        return require(“../../images/0.png");
      case “1":
        return require(“../../images/1.png");
      case “2":
        return require(“../../images/2.png");
      case “3":
        return require(“../../images/3.png");
      case “4":
        return require(“../../images/4.png");
      case “5":
        return require(“../../images/5.png");
      case “6":
        return require(“../../images/6.png");
      case “7":
        return require(“../../images/7.png");
      case “8":
        return require(“../../images/8.png");
      case “9":
        return require(“../../images/9.png");
      default:
        return require(“../../images/0.png");
    }
  }

  render() {
    var scoreString = this.props.score.toString();
    var scoreArray = [];
    for (var index = 0; index < scoreString.length; index++) {
      scoreArray.push(scoreString[index]);
    }

    return (
      <View
        style={{
          position: “absolute",
          left: 47 * W,
          top: 10 * H,
          flexDirection: “row"
        }}
      >
        {scoreArray.map(
          function(item, i) {
            return (
              <Image
                style={{ width: 10 * W }}
                key={i}
                resizeMode="contain"
                source={this.getSource(item)}
              />
            );
          }.bind(this)
        )}
      </View>
    );
  }
}
```

我们在 `render` 方法中进行以下操作：

+   将分数转换为字符串

+   将字符串转换为数字列表

+   使用支持的 `getSource()` 函数将数字列表转换为图像列表

React Native `<Image />` 的一个限制是其源不能作为变量被引入。因此，我们使用 `getSource()` 方法来检索源的小技巧，该方法实际上获取所有可能的图像，并通过 `switch`/`case` 子句返回正确的图像。

# 开始

开始屏幕包括两个图像：

+   一个标志

+   一个解释如何启动游戏的开始按钮（在屏幕上的任何位置轻触）

```jsx
/*** src/components/Start.js ***/

import React, { Component } from “react";
import { Text, View, StyleSheet, Image } from “react-native";

import { W, H } from “../constants";

export default class Start extends Component {
  render() {
    return (
      <View style={{ position: “absolute", left: 20 * W, top: 3 * H }}>
        <Image
          resizeMode="contain"
          source={require(“../../images/logo.png")}
          style={{ width: 60 * W }}
        />
        <Image
          resizeMode="contain"
          style={{ marginTop: 15, width: 60 * W }}
          source={require(“../../images/tap.png")}
        />
      </View>
    );
  }
}
```

我们再次使用我们的 `H` 和 `W` 常量，以确保元素在每个设备屏幕上都定位正确。

# 游戏结束

当鹦鹉与岩石或地面发生碰撞时，我们应该显示游戏结束画面。这个画面只包含两个图像：

+   游戏结束标志

+   重新开始游戏的按钮

让我们首先看一下游戏结束标志：

```jsx
/*** src/components/GameOver.js ***/

import React, { Component } from “react";
import { Image } from “react-native";

import { W, H } from “../constants";

export default class GameOver extends Component {
  render() {
    return (
      <Image
        style={{
          position: “absolute",
          left: 15 * W,
          top: 30 * H
        }}
        resizeMode="stretch"
        source={require(“../../images/game-over.png")}
      />
    );
  }
}
```

现在，让我们继续重置游戏按钮。

# 重新开始

实际上，重置按钮只是一个标志，因为用户不仅可以在按钮上轻触，还可以在屏幕的任何位置开始游戏。无论如何，我们将使用 *H* 和 *W* 常量在每个屏幕上正确定位此按钮：

```jsx
/*** src/components/StartAgain.js ***/

import React, { Component } from “react";
import { Text, View, StyleSheet, TouchableOpacity, Image } 
from “react-native";

import { W, H } from “../constants";

export default class StartAgain extends Component {
  render() {
    return (
      <Image
        style={{ position: “absolute", left: 35 * W, top: 40 * H }}
        resizeMode="contain"
        source={require(“../../images/reset.png")}
      />
    );
  }
}
```

# 总结

游戏是一种非常特殊的应用程序。它们基于根据时间和用户交互在屏幕上显示和移动精灵。这就是为什么我们在大部分课程中解释了如何以最高效的方式轻松显示所有图像以及如何定位和调整它们的大小。

我们还审查了一种常见的技巧，相对于设备屏幕的高度和宽度来定位和调整精灵的大小。

尽管 Redux 并非专门为游戏设计，但我们在应用程序中使用它来存储和分发精灵的数据。

总的来说，我们证明了 React Native 可以用于构建高性能的游戏，尽管它缺乏游戏特定的工具，但我们可以生成非常可读的代码，这意味着它应该很容易扩展和维护。事实上，在这个阶段可以创建一些非常简单的扩展来使游戏更有趣和可玩性：在通过特定数量的障碍物后增加速度，减少或增加间隙大小，在屏幕上显示多组岩石等等。

通过这个，我们已经完成了这次学习之旅。我希望你有一个顺利的旅程，并在 React 上获得了很多知识。

祝愿你在未来的项目中一切顺利。继续学习和探索！

# 评估

1.  命名游戏中使用的图形，通常分组为一个或多个图像。

1.  数字

1.  背景

1.  地面

1.  精灵

1.  请说明以下陈述是真还是假：精灵是游戏中使用的图形，通常分组为一个或多个图像。许多游戏引擎包括工具来方便地拆分和管理这些图形，但在 React Native 中并非如此。

1.  请说明以下陈述是真还是假：精灵数组是负责在特定时间存储所有精灵位置和大小的数组。

1.  哪些功能负责通过注入操作和属性将组件连接到存储中？

1.  ________ 负责在用户点击屏幕后启动游戏。它将使用`requestAnimationFrame()`来实现这一点——这是 React Native 中实现的自定义定时器之一。

1.  `nextFrame()`

1.  `cancelAnimationFrame()`

1.  `GameContainer`

1.  `mapStateToProps(state)`
