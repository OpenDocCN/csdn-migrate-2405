# Vue2 Bootstrap4 Web 开发（三）

> 原文：[`zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8`](https://zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：请进行身份验证！

在上一章中，我们将 ProFitOro 应用程序连接到了实时数据库。每当用户更新番茄钟计时器设置时，这些设置都会存储在数据库中，并立即在使用它们的组件之间传播。由于我们没有身份验证机制，我们不得不使用一个虚假用户来测试我们的更改。在本章中，我们将拥有真正的用户！

在这方面，我们将使用 Firebase 身份验证 API。因此，在本章中，我们将做以下事情：

+   讨论 AAA 的含义以及身份验证和授权之间的区别

+   探索 Firebase 身份验证 API

+   创建一个登录页面，并将其与 Firebase 身份验证 API 连接

+   将用户的设置与用户的身份验证连接起来

# 解释 AAA

**AAA**代表**身份验证、授权和计费**。最初，这个术语是用来描述安全网络协议的，然而，它可以很容易地应用于任何系统、网络资源或站点。

那么，AAA 是什么意思，为什么我们要关心呢？

**身份验证**是唯一识别系统用户的过程。经过身份验证的用户是被授予对系统访问权限的用户。通常，身份验证是通过一些用户名和密码来完成的。当您必须提供用户名和密码来打开您的 Facebook 页面时，您正在进行身份验证。

您的护照是在机场验证自己身份的一种方式。护照控制人员会看着你的脸，然后检查你的护照。因此，任何允许您“通过”的东西都是您身份验证的一部分。它可以是一个只有您和系统知道的特殊词（密码），也可以是您随身携带的可以帮助系统唯一识别您的东西（护照）。

**授权**是一种控制每个用户有权（权限）访问哪些资源的方式。如果您正在开发 Facebook 应用程序，您可以访问开发者页面，而普通用户无法访问此页面。

**计费**衡量为每个用户分配的资源。如果您拥有 Dropbox 商业标准帐户，您可以使用高达 2TB 的存储空间，而拥有普通免费 Dropbox 帐户只能获得 2GB 的空间。

对于我们的应用程序，我们应该关注 Triple-A 的前两个部分——*身份验证*和*授权*。在计算机科学中，我们经常使用术语**auth**，指的是身份验证或授权，甚至同时指两者。因此，我们将实现 auth，其中 auth 同时指身份验证和授权。在我们的 ProFitOro 应用程序的上下文中，这两个术语有什么区别呢？嗯，身份验证将允许用户登录到系统中，所以这很容易。授权呢？

您还记得我们决定只有经过身份验证的用户才能访问番茄工作法设置和统计数据吗？这就是授权。以后，我们可能会进一步实现一个特殊的角色——健身教练。拥有这个角色的用户将能够访问锻炼区域并能够添加新的锻炼。

在本章中，我们将使用 Firebase 身份验证机制，以添加登录和登陆到我们的应用程序的可能性，并控制用户可以访问的内容。

# Firebase 如何进行身份验证？

在上一章中，您学习了如何使用 Firebase API 创建 Firebase 应用程序实例，并通过应用程序使用它。我们能够访问数据库，读取它，并在其中存储数据。

您使用 Firebase 身份验证 API 的方式非常相似。您创建一个 Firebase 实例，向其提供一个`config`对象，并使用`firebase.auth()`方法来访问与身份验证相关的不同方法。检查您的 Firebase 控制台的**身份验证**选项卡：

![Firebase 如何进行身份验证？](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00095.jpeg)

现在还没有用户，但我们将在一分钟内解决这个问题！

Firebase SDK 提供了几种用户身份验证的方式：

+   基于电子邮件和密码的身份验证：对用户进行身份验证的经典方式。Firebase 提供了一种使用电子邮件/密码登录用户并将其登录的方法。它还提供了重置用户密码的方法。

+   联合实体提供者身份验证：与外部实体提供者（如 Google、Facebook、Twitter 或 GitHub）对用户进行身份验证的方式。

+   电话号码身份验证：通过向用户发送包含验证码的短信来对用户进行身份验证，用户需要输入验证码以确认其身份。

+   自定义身份验证系统集成：将已经存在的身份验证解决方案与 Firebase 身份验证 API 集成的方式。

+   **匿名用户身份验证**：提供 Firebase 功能（例如访问 Firebase 数据库）而无需进行身份验证的方式。例如，我们可以使用此匿名帐户来提供对数据库中存储的默认配置的访问权限。

对于我们的应用程序，我们将使用第一个和最后一个方法，因此我们将允许用户使用其电子邮件和密码组合进行登录和登录，并且我们将允许匿名用户使用应用程序的基本功能。

您应该在 Firebase 控制台中明确激活这两种方法。只需打开 Firebase 项目的**身份验证**选项卡，单击登录方法链接，然后启用这两种方法：

![Firebase 如何与身份验证工作？](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00096.jpeg)

明确启用电子邮件/密码和匿名登录方法

使用 Firebase 身份验证 API 的工作流程如下：

1.  创建所有必要的方法进行登录和登录。

1.  为您的身份验证实现所有必要的 UI。

1.  将 UI 的更改连接到身份验证方法。

在第 3 步中发现了什么有趣的东西吗？*将 UI 的更改连接到身份验证方法*。您还记得我们正在处理一种响应式数据绑定框架，对吧？所以这将会很有趣！

# 如何将 Firebase 身份验证 API 连接到 Web 应用程序

为了将您的应用程序连接到 Firebase 身份验证 API，您应该首先创建一个 Firebase 应用程序实例：

```js
let config = {
  apiKey: 'YourAPIKey',
  databaseURL: 'YourDBURL',
  authDomain: 'YourAuthDomain'
}
let app = firebase.initializeApp(config)
```

您可以在弹出窗口中找到必要的密钥和 URL，如果单击**Web 设置**按钮将打开该窗口：

![如何将 Firebase 身份验证 API 连接到 Web 应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00097.jpeg)

在 Web 应用程序中使用 Firebase 的设置配置

现在您可以使用应用程序实例来访问`auth()`对象及其方法。查看有关身份验证 API 的官方 Firebase 文档：[`firebase.google.com/docs/auth/users`](https://firebase.google.com/docs/auth/users)。

对我们来说 API 最重要的部分是创建和登录用户的方法，以及监听身份验证状态变化的方法：

```js
app.auth().**createUserWithEmailAndPassword**(email, password)
```

或者：

```js
app.auth().**signInWithEmailAndPassword**(email, password)
```

监听应用程序身份验证状态变化的方法称为`onAuthStateChanged`。您可以在此方法中设置重要属性，考虑应用程序根据用户是否已登录需要具有的状态：

```js
app.auth().**onAuthStateChanged**((user) => {
  if (user) {
    // user is logged in
  } else {
    // user is logged out
  }
})
```

就是这样！在我们的应用程序中，我们只需要提供一种可视方式将用户名和密码传递给 API。

# 认证到 ProFitOro 应用程序

现在让我们让 ProFitOro 应用程序的登录和注销成为可能！首先，我们必须设置 Firebase 实例，并找出应该将所有与身份验证相关的方法放在哪里。Firebase 应用程序初始化已经在 store/index.js 文件中完成。如果您仍然没有在 config 中包含它们，请添加 apiKey 和 authDomain 配置条目：

```js
// store/index.js
let config = {
  apiKey: 'YourAPIKey',
  databaseURL: 'https://profitoro-ad0f0.firebaseio.com',
  authDomain: 'profitoro-ad0f0.firebaseapp.com'
}
let firebaseApp = firebase.initializeApp(config)
```

我还将使用扩展运算符在 store 的 state 属性中导出 firebaseApp：

```js
//store/index.js
export default new Vuex.Store({
  state: {
    ...state,
    firebaseApp
  },
  <...>
})
```

我还将向我们的状态添加一个用户属性，以便我们可以在 onAuthStateChanged 监听器的处理程序上重置它：

```js
// store/state.js
export default {
  config,
  statistics,
  **user,**
 **isAnonymous: false**
}
```

让我们还创建一个小的变异，将用户对象的值重置为给定值：

```js
// store/mutations.js
export default {
  <...>
  **setUser (state, value) {**
 **state.user = value**
 **}**
}
```

现在我们已经完全准备好创建所需的操作。我将创建四个对我们的应用程序至关重要的操作：

+   createUser：此操作将调用 Firebase auth 的 createUserWithEmailAndPassword 方法，使用给定的电子邮件和密码

+   authenticate：此操作将调用 Firebase auth 的 signInWithEmailAndPassword 方法以使用给定的电子邮件和密码登录用户

+   注销：此操作将调用 Firebase auth 的 signOut 方法

+   bindAuth：此操作将设置 onAuthStateChanged 回调并提交 setUser 变异

首先，让我们以一种非常简单的方式实现这些操作，而不附加任何回调。因此，它们将如下所示：

```js
// store/actions.js
**createUser** ({state}, {email, password}) {
  state.firebaseApp.auth().**createUserWithEmailAndPassword**(email, password).catch(error => {
    console.log(error.code, error.message)
  })
},
**authenticate** ({state}, {email, password}) {
  state.firebaseApp.auth().**signInWithEmailAndPassword**(email, password)
},
**logout** ({state}) {
  state.firebaseApp.auth().**signOut**()
},
**bindAuth** ({commit, state}) {
  state.firebaseApp.auth().**onAuthStateChanged**((user) => {
    commit('setUser', user)
  })
},
```

太棒了！现在让我们将 bindAuth 操作附加到主 App.vue 组件的 created 方法上：

```js
// App.vue
methods: {
  ...mapActions(['bindStatistics', 'bindConfig', **'bindAuth'**])
},
created () {
  **this.bindAuth()**
  this.bindConfig()
  this.bindStatistics()
}
```

现在，一旦应用程序被创建，身份验证状态的监听器将立即绑定。我们可以做什么？现在，App.vue 组件立即显示的唯一组件是主内容组件。但是，如果用户没有登录，我们实际上应该显示着陆页组件，以提供给用户登录或注册的可能性。我们可以很容易地使用绑定到用户属性的 v-if 指令来实现。如果用户已定义，让我们显示主内容组件；否则，让我们显示着陆页组件。多么简单？我们的 App.vue 组件的模板将如下所示：

```js
// App.vue
<template>
  <div id="app">
    <landing-page **v-if="!user"**></landing-page>
    <main-content **v-if="user"**></main-content>
  </div>
</template>
```

如果您现在打开页面，您将看到显示着陆页：

![Authenticating to the ProFitOro application](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00098.jpeg)

当应用程序启动时，会显示登陆页面，因为用户没有登录

所有相关的代码到这部分都在`chapter6/1/profitoro`文件夹中。特别注意商店的文件（`index.js, actions.js, mutations.js, state.js`）和`App.vue`组件。

现在我们卡在了显示一些占位文本的登陆页面上，没有办法进入应用程序，因为我们无法登录！

好吧，这很容易解决：让我们在`Authentication.vue`组件中创建一个简单的注册和登录表单，并将其与我们的操作连接起来。

所以我将添加组件数据，用于保存注册的电子邮件、登录的电子邮件和相应的密码：

```js
// Authentication.vue
export default {
  **data** () {
    return {
 **registerEmail: '',**
 **registerPassword: '',**
 **loginEmail: '',**
 **loginPassword: ''**
    }
  }
}
```

我还将添加一个非常简单的标记，用于显示相应数据的输入：

```js
<template>
  <div>
    <h1>Register</h1>
    <input **v-model="registerEmail"** type="text" placeholder="email">
    <input **v-model="registerPassword"** type="password" placeholder="password">
    <button>Register!</button>
    <h1>Login</h1>
    <input **v-model="loginEmail"** type="text" placeholder="email">
    <input **v-model="loginPassword"** type="password" placeholder="password">
    <button>Log in!</button>
  </div>
</template>
```

现在让我们导入必要的操作（`authenticate`和`createUser`）并创建将调用这些操作的方法：

```js
// Authentication.vue
<script>
  **import {mapActions} from 'vuex'**

  export default {
    <...>
    methods: {
      **...mapActions(['createUser', 'authenticate'])**,
      **onRegisterClick** () {
        this.**createUser**({email: **this.registerEmail**, password: **this.registerPassword**})
      },
      **onLoginClick** () {
        this.**authenticate**({email: **this.loginEmail**, password: **this.loginPassword**})
      }
    }
  }
</script>
```

现在我们只需要将事件绑定到相应的按钮上，使用`v-on:click`指令：

```js
// Authentication.vue
<template>
  <div>
    <h1>Register</h1>
    <input v-model="registerEmail" type="text" placeholder="email">
    <input v-model="registerPassword" type="password" placeholder="password">
    <button **@click="onRegisterClick"**>Register!</button>
    <h1>Login</h1>
    <input v-model="loginEmail" type="text" placeholder="email">
    <input v-model="loginPassword" type="password" placeholder="password">
    <button **@click="onLoginClick"**>Log in!</button>
  </div>
</template>
```

让我们还在`HeaderComponent.vue`组件中添加一个按钮。这个按钮应该允许用户注销。这很容易；我们甚至不需要创建任何方法，我们只需要将事件绑定到实际的操作。因此整个标记和所需的脚本看起来就像这样简单：

```js
// HeaderComponent.vue
<template>
  <div>
    <button **@click="logout"**>Logout</button>
  </div>
</template>
<script>
  **import {mapActions} from 'vuex'**

  export default {
    methods: {
      **...mapActions(['logout'])**
    }
  }
</script>
```

就是这样！打开页面并尝试在你的应用程序中注册！它起作用了！一旦你登录，你不仅会看到番茄钟，还可以看到注销按钮。点击它，检查你是否真的被踢出应用程序到登陆页面。尝试重新登录。一切都像魅力一样运行。

不要忘记打开你的 Firebase 控制台并检查**认证**选项卡。你应该在那里看到所有注册的用户：

![Authenticating to the ProFitOro application](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00099.jpeg)

通过 Firebase 控制台的认证选项卡监视你的注册用户

恭喜！你刚刚使用 Firebase 认证 API 为你的应用程序实现了完整的认证机制。你可以在`chapter6/2/profitoro`文件夹中找到相应的代码。特别注意`Authentication.vue`和`HeaderComponent.vue`组件。

# 使认证界面再次变得伟大

我们刚刚为我们的 ProFitOro 应用程序实现了认证机制。这很棒，但是我们的认证页面的 UI 看起来好像我们使用了时光机，回到了互联网的早期。让我们使用我们强大的朋友-Bootstrap 来解决这个问题。

首先，我想将我的登陆页面布局为两列网格布局，因此整个登录属于左列，而将用户引导到应用程序而不注册的按钮位于右侧。但是，我希望这两列在移动设备上堆叠。

这对您来说并不新鲜；我想您应该还记得如何使用 Bootstrap 的网格布局来实现这种行为：[`v4-alpha.getbootstrap.com/layout/grid/`](https://v4-alpha.getbootstrap.com/layout/grid/)。因此，在我们的`LandingPage`组件中，我将把认证和`go-to-app-link`组件包装到带有`row`类的`div`中，并为这些组件添加相应的`col-*`类：

```js
// LandingPage.vue
<template>
  <div>
    <...>
    <div class="**container row justify-content-center**">
      <div class="**col-sm-12 col-md-6 col-lg-6**">
        <authentication></authentication>
      </div>
      <div class="**col-sm-12 col-md-6 col-lg-6**">
        <go-to-app-link></go-to-app-link>
      </div>
    </div>
  </div>
</template>
```

就是这样！现在您有一个漂亮的两列布局，在小型设备上会转换为单列布局：

![使认证 UI 再次变得伟大](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00100.jpeg)

这是我们在桌面设备上的布局

如您所见，在桌面设备上，我们有一个漂亮的两列布局。如果将浏览器调整到移动设备的大小，右列将跳到左列后面：

![使认证 UI 再次变得伟大](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00101.jpeg)

这是我们在移动设备上的布局

现在让我们来看看我们的`Authentication.vue`组件。为了使其比 20 年前的网页更美观，让我们对其应用 Bootstrap 的魔法。为此，我们将使用 Bootstrap 表单的类：[`v4-alpha.getbootstrap.com/components/forms/`](https://v4-alpha.getbootstrap.com/components/forms/)。

我们将整个表单包装到`<form>`标签中，将每个输入都包装到带有`form-group`类的`div`中。我们还将为每个输入添加`form-control`类。因此，例如，电子邮件输入将如下所示：

```js
<div class="**form-group**">
  <input class="**form-control**" v-model="email" type="email" placeholder="email">
</div>
```

作为一个小练习，做以下事情：

+   只需创建一个表单，其中有一个按钮可以在登录和注册表单之间切换

+   只需创建一个方法，根据表单当前的状态调用其中一个动作

+   探索 Bootstrap 的实用程序类，以除去所有边框，除了底部边框，并从中删除圆角：[`v4-alpha.getbootstrap.com/utilities/borders/`](https://v4-alpha.getbootstrap.com/utilities/borders/)

最后，您的表单应该如下所示：

![使身份验证 UI 再次变得伟大](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00102.jpeg)

这就是最终两种形式应该看起来的样子。它们应该通过底部按钮进行切换

尝试自己实现。要检查您的工作，请查看`chapter6/3/profitoro`文件夹。特别是，检查`Authentication.vue`组件的代码。它非常不同！

# 管理匿名用户

ProFitOro 允许未注册用户使用该应用程序。唯一的区别是，这些未注册用户也不被允许配置他们的设置，因为他们无法访问他们的统计数据。他们也无法管理锻炼。这就是我们遇到三 A 定义的第二个 A - *授权*。我们如何管理这些用户？如果我们只允许我们的用户注册和登录，他们如何进入应用程序？好吧，出于某种原因，我们已经准备好了“转到应用程序”的部分。让我提醒您在模型中的外观：

![管理匿名用户](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00103.jpeg)

在初始模型中的无需注册！按钮

幸运的是，Firebase 身份验证 API 提供了一种方法来登录匿名用户。返回的用户对象包含`isAnonymous`属性，这将允许我们管理可以或不可以访问此匿名用户的资源。因此，让我们添加名为`authenticateAnonymous`的操作，并在其中调用相应的 Firebase `auth`方法：

```js
// store/actions.js
**authenticateAnonymous** ({state}) {
  state.firebaseApp.auth().**signInAnonymously**().catch(error => {
    console.log(error.code, error.message)
  })
},
```

这就是我们！现在让我们稍微修改一个设置用户和**isAnonymous**状态属性的变化，使其与用户对象中的相应属性相对应：

```js
// store/mutations.js
setUser (state, value) {
  state.user = value
  **state.isAnonymous = value.isAnonymous**
}
```

让我们还修改绑定配置和统计操作，并仅在用户设置且用户不是匿名用户时执行实际绑定：

```js
// state/actions.js
bindConfig: firebaseAction(({bindFirebaseRef, state}) => {
  if (state.user **&& !state.isAnonymous**) {
    bindFirebaseRef('config', state.configRef)
  }
}),
bindStatistics: firebaseAction(({bindFirebaseRef, state}) => {
  if (state.user **&& !state.isAnonymous**) {
    bindFirebaseRef('statistics', state.statisticsRef)
  }
})
```

我们已经完成了后端！现在让我们实现这个按钮！只需三个步骤即可实现。打开`GoToAppLink.vue`组件，导入`mapActions`助手，添加按钮，并使用`v-on:click`指令将事件侦听器绑定到它，该事件侦听器将调用相应的操作：

```js
// GoToAppLink.vue
<template>
  <div>
    **<button @click="authenticateAnonymous">**
 **START WITHOUT REGISTRATION**
 **</button>**
  </div>
</template>
<script>
  **import {mapActions} from 'vuex'**

  export default {
    methods: {
      **...mapActions(['authenticateAnonymous'])**
    }
  }
</script>
```

这有多简单？现在，作为一个小练习，借助 Bootstrap，尝试使事物看起来像下面这样：

![管理匿名用户](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00104.jpeg)

使用相应的 Bootstrap 类使我们的按钮看起来像这样，并垂直对齐列。

检查 Bootstrap 的对齐类：[`v4-alpha.getbootstrap.com/layout/grid/#alignment`](https://v4-alpha.getbootstrap.com/layout/grid/#alignment)。还要检查辅助类以去除圆角。通过查看`chapter6/4/profitoro`文件夹中的代码来检查自己。特别注意`GoToAppLink.vue`组件和存储组件，如`action.js`和`mutations.js`。

# 个性化番茄钟

现在，我们已经可以注册新用户并登录现有用户，可能我们应该考虑利用我们的身份验证机制，因为现在我们实际上没有利用它。我们只是注册和登录。是的，我们还可以根据用户的身份验证隐藏或显示一些内容，但这还不够。所有这一切努力的重点是能够存储和检索用户的自定义番茄钟配置和用户的统计数据。

到目前为止，我们一直在使用硬编码的数据库对象，其中包含键`test`，以便访问用户的数据，但现在，由于我们已经有了真正的用户，是时候用真正的用户数据填充数据库并在我们的应用程序中使用它了。实际上，我们唯一需要做的就是用实际用户的 ID 替换这个硬编码的值。因此，例如，我们绑定`config`引用的代码看起来像这样：

```js
// store/actions.js
bindConfig: firebaseAction(({bindFirebaseRef, state}) => {
  if (state.user && !state.isAnonymous) {
    bindFirebaseRef('config', **state.configRef**)
  }
}),
```

在这里，引用`state.configRef`已经在存储的入口点`index.js`中定义：

```js
// store/actions.js
let firebaseApp = firebase.initializeApp(config)
let db = firebaseApp.database()
**let configRef = db.ref('/configuration/test')**

```

现在，我们实际上不能在存储的入口点实例化我们的数据库引用，因为在这一点上（无意冒犯），我们仍然不知道我们的用户是否已经通过身份验证。因此，最好的做法是将此代码传递给实际的`bindConfig`函数，并用真实用户的*uid*替换这个`test`：

```js
// store/action.js
bindConfig: firebaseAction(({bindFirebaseRef, state}) => {
  if (state.user && !state.isAnonymous) {
    let db = firebaseApp.database()
    bindFirebaseRef('config', **db.ref(`/configuration/${state.user.uid}`)**)
  }
}),
```

现在，我亲爱的细心用户，我知道你在惊叹“但是用户的*uid*配置是如何存储的？”非常注意到：它没有。我们仍然需要在用户首次注册时将其存储。实际上，我们需要存储配置和统计数据。

Firebase 数据库提供了一种写入新数据到数据库的方法，称为`set`。因此，您基本上获取引用（就像读取数据的情况一样）并设置您需要写入的数据：

```js
firebaseApp.database().ref(**`/configuration/${state.user.uid}`**).set(
  state.config
);
```

这将在我们的配置表中为给定的用户 ID 创建一个新条目，并设置默认状态的`config`数据。因此，我们将不得不在新用户创建时调用此方法。我们仍然需要将数据库引用绑定到我们的状态对象。为了减少代码量，我创建了一个方法`bindFirebaseReference`，它接收引用和表示应将其绑定到的状态键的字符串。该方法将分析数据库中是否已存在给定引用的条目，并在需要时创建它。为此，Firebase 提供了一个几乎可以应用于任何东西的好方法 - 这个方法称为`once`，它接收一个回调和一个快照。因此，在此回调中，我们可以分析此快照是否具有给定名称的子项，甚至是否具有值或为`null`。如果值已设置，我们将将我们的状态绑定到它。如果没有，我们将创建一个新条目。在这方面查看官方 Firebase 文档：[`firebase.google.com/docs/database/web/read-and-write`](https://firebase.google.com/docs/database/web/read-and-write)。这就是`once`方法及其回调的外观：

![个性化番茄钟](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00105.jpeg)

如何使用`once`方法检查数据库中是否存在数据

不考虑数据的存在与否，我们的绑定引用方法应调用 Firebase 绑定。因此，它将如下所示：

```js
// store/actions.js
bindFirebaseReference: firebaseAction(({bindFirebaseRef, state}, {reference, toBind}) => {
  return reference.once('value').then(snapshot => {
    if (!snapshot.val()) {
      **reference.set(state[toBind])**
    }
    **bindFirebaseRef(toBind, reference)**
  })
}),
```

我还用一个方法替换了绑定`config`和`statistics`的两种方法：

```js
// store/actions.js
bindFirebaseReferences: firebaseAction(({bindFirebaseRef, state, commit, dispatch}, user) => {
  let db = state.firebaseApp.database()
  let **configRef** = db.ref(**`/configuration/${user.uid}`**)
  let **statisticsRef** = db.ref(**`/statistics/${user.uid}`**)
  dispatch('bindFirebaseReference', {reference: configRef, toBind: 'config'}).then(() => {
    **commit('setConfigRef', configRef)**
  })
  dispatch('bindFirebaseReference', {reference: statisticsRef, toBind: 'statistics'}).then(() => {
    **commit('setStatisticsRef', statisticsRef)**
  })
}),
```

这个方法是从`bindAuth`方法中调用的。因此，现在我们可以从`App.vue`的`created`方法中删除绑定`config`和`statistics`的调用。我们还不需要在`store/index.js`中实例化引用，因为这两个引用都是在这个新方法中实例化的。我们还必须添加两个将引用设置为状态的 mutations，这样我们就不需要更改我们的 Pomodoro 配置设置 actions，因为它们正在使用这两个引用来更新数据。

检查`chapter6/5/profitoro`文件夹中代码的外观。查看`App.vue`组件中的轻微更改，并查看存储文件现在的外观（`index.js`，`mutations.js`，`state.js`，特别是`actions.js`）。

玩一下你的应用程序。注册、登录、更改番茄钟定时器配置、退出登录，然后检查它是否有效。检查你的 Firebase 控制台 - **实时数据库**选项卡和**身份验证**选项卡。检查无论你改变什么，你的数据都是一致的 - 在你的数据库中，在你的**身份验证**选项卡中，最重要的是在你的应用程序中（因为应用程序是你的用户将要看到的，对吧？）：

![个性化番茄钟定时器](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00106.jpeg)

检查数据在各处是否一致

现在我们可以注册新用户，以现有用户身份登录，以匿名用户身份登录。我们为经过身份验证的用户提供了一个不错的价值 - 能够配置他们的番茄钟定时器并检查他们的统计数据。当然，我们的应用程序还远远不完美 - 我们没有验证输入，接受番茄钟配置区域中的任何值，这是不对的，而且我们也没有在启动页面上显示更改密码的可能性。但是我们有一个坚实的框架，它使我们能够在其基础上构建一个坚实而不错的应用程序。所以让我们继续前进！

# 更新用户的个人资料

如果我们能够通过显示欢迎消息来欢迎我们的用户，比如**欢迎 Olga**，那不是很有趣吗？但是我们的用户没有名字；他们只有电子邮件和密码 - 这两个在注册过程中传递的基本认证组件。那么，我们该怎么做呢？如果你仔细阅读了 Firebase 关于身份验证的文档（[`firebase.google.com/docs/auth/web/manage-users`](https://firebase.google.com/docs/auth/web/manage-users)），你可能会发现这些不错的方法：

![更新用户个人资料](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00107.jpeg)

用于更新用户个人资料和电子邮件地址的 Firebase 方法

让我们使用这些方法来更新我们用户的个人资料和用户的个人资料图片！

我们将定义三个新的操作 - 一个将通过调用 Firebase 的`updateProfile`方法来更新用户的显示名称，另一个将通过调用相同的方法来更新用户的个人资料图片 URL，还有一个将调用`updateEmail`方法。然后我们将在`Settings.vue`组件中创建必要的标记，将这些操作绑定到相应输入的更新上。听起来很容易，对吧？相信我，实际实现起来就像听起来的那么容易。

因此，让我们定义我们的操作。它们将如下所示：

```js
// store/actions.js
**updateUserName** ({state, commit}, displayName) {
  state.user.**updateProfile**({
    displayName
  })
},
**updatePhotoURL** ({state}, photoURL) {
  state.user.**updateProfile**({
    photoURL
  })
},
**updateUserEmail** ({state}, email) {
  state.user.**updateEmail**(email).then(() => {
    // Update successful.
  }, error => {
    console.log(error)
  })
},
```

太棒了！现在让我们切换到我们的`Settings.vue`组件，它将负责渲染所需的数据以更改帐户设置，并在需要时调用所需的操作来更新这些数据。所以首先，我将向数据函数添加三个条目，这些条目将在组件被`created`时设置为当前用户对象的相应属性：

```js
// Settings.vue
data () {
  return {
    **displayName**: '',
    **email**: '',
    **photoURL**: 'static/tomato.png'
  }
},
computed: {
  ...mapGetters({**user**: 'getUser'})
},
created () {
  **this.displayName** = this.user.displayName
  **this.email** = this.user.email
  **this.photoURL** = this.user.photoURL ? this.user.photoURL : this.photoURL
}
```

现在这些数据可以在相应的操作中使用。所以，让我们导入所需的操作并创建相应的方法：

```js
// Settings.vue
methods: {
  **...mapActions(['updateUserName', 'updateUserEmail', 'updatePhotoURL'])**,
  onChangeUserName () {
    this.**updateUserName**(this.**displayName**)
  },
  onChangeUserEmail () {
    this.**updateUserEmail**(this.**email**)
  },
  **onProfilePicChanged** () {
    this.**updatePhotoURL**(this.**photoURL**)
  }
}
```

现在我们可以添加所需的标记，其中包含了我们将使用`v-model`数据绑定指令绑定数据的输入框！我们还将在每个输入框的更新上调用相应的方法：

```js
// Settings.vue
<form>
  <div class="form-group">
    <figure class="figure">
      <img **:src="photoURL"** alt="Avatar">
      <input type="text" **v-model="photoURL"** **@change="onProfilePicChanged"**>
    </figure>
  </div>
  <div class="form-group">
    <input **@change="onChangeUserName"** **v-model="displayName"** type="text" placeholder="Change your username">
  </div>
  <div class="form-group">
    <input **@change="onChangeUserEmail"** **v-model="email"** type="text" placeholder="Change your username">
  </div>
</form>
```

然后...我们完成了！

作为一个小练习，做以下操作：在我们的图像后面添加一个标题，说**更改个人资料图片**。新图片 URL 的输入框应该只在用户点击这个标题时可见。一旦 URL 更新完成，输入框应该再次变得不可见。

结果应该如下所示：

![更新用户资料](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00108.jpeg)

用户点击更改个人资料图片标题之前的外观如下

最初，它包含默认用户图片。

用户点击标题后，更改图片 URL 的输入框出现：

![更新用户资料](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00109.jpeg)

用户点击标题后，输入框出现

用户更改个人资料图片 URL 后，输入框再次隐藏：

![更新用户资料](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00110.jpeg)

用户更改个人资料图片的 URL 后，输入框消失了

我的建议：向`Settings.vue`组件的数据添加一个额外的属性，当用户点击标题时将其设置为`true`，并在输入框内的值改变时将其重置为`false`。

还有，不要忘记我们这一部分的初始目标 - 在`Header.vue`组件内添加一个欢迎消息。这个欢迎消息应该包含用户的显示名称。它应该看起来像这样：

![更新用户资料](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00111.jpeg)

欢迎消息提到用户的名字

请注意，如果您决定更改您的电子邮件，您将不得不注销并再次登录；否则，您将在控制台中收到一些 Firebase 安全错误。

本章的最终代码可以在`chapter6/6/profitoro`文件夹中找到。请注意，我将帐户设置和番茄钟设置分成了两个单独的组件（`AccountSettings.vue`和`PomodoroTimerSettings.vue`）。这样做可以更容易地进行维护。也要注意存储组件。查看`Header.vue`组件以及它如何显示欢迎消息。

# 总结

在本章中，我们学习了如何结合 Firebase 实时数据库和认证 API 来更新用户的设置。我们已经构建了一个用户界面，允许用户更新其个人资料设置。在短短几分钟内，我们就完成了应用程序的完整认证和授权部分。我不知道你们，但我对此感到非常惊讶。

在下一章中，我们将最终摆脱包含应用程序所有部分的庞大页面 - 番茄钟计时器本身、统计数据和设置配置视图。我们将探索 Vue 的一个非常好的重要功能 - `vue-router`。我们将把它与 Bootstrap 的导航系统结合起来，以实现流畅的导航。我们还将探讨代码拆分这样一个热门话题，以实现应用程序的延迟加载。所以，让我们开始吧！


# 第七章：使用 vue-router 和 Nuxt.js 添加菜单和路由功能

在上一章中，我们为我们的应用程序添加了一个非常重要的功能 - *身份验证*。现在，我们的用户可以注册、登录应用程序，并在登录后管理他们的资源。因此，他们现在可以管理番茄钟计时器的配置和他们账户的设置。一旦登录，他们还可以访问他们的统计数据。我们已经学会了如何使用 Firebase 的身份验证 API 并将 Vue 应用程序连接到它。我必须说，上一章在学习上非常广泛，而且非常偏向后端。我非常喜欢它，希望你也喜欢。

尽管我们的应用程序具有身份验证和授权的复杂功能，但仍然缺乏导航。出于简单起见，我们目前在主页上显示应用程序的所有部分。这很丑陋：

![使用 vue-router 和 Nuxt.js 添加菜单和路由功能](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00112.jpeg)

承认吧，这很丑陋

在本章中，我们不打算让事情变得美丽。我们要做的是使事情可导航，以便通过导航访问应用程序的所有部分。我们将应用`vue-router`机制，以实现自然的浏览器导航，并且我们将使用 Bootstrap 的`navbar`来轻松导航到每个部分。因此，在本章中，我们将：

+   再次探索`vue-router`以实现 ProFitOro 应用程序的导航

+   使用 Bootstrap 的`navbar`来渲染导航栏

+   探索代码拆分技术，仅在需要时加载应用程序的每个部分

+   最后，我们将探索 Nuxt.js 模板，使用它重建我们的应用程序，并以不显眼和愉快的方式实现路由

# 使用 vue-router 添加导航

希望你还记得第二章中`vue-router`是什么，它是做什么的，以及它是如何工作的。只是提醒一下：

> Vue-router 是 Vue.js 的官方路由器。它与 Vue.js 核心深度集成，使使用 Vue.js 构建单页面应用程序变得轻而易举。

-(来自 vue-router 的官方文档)

`vue-router`非常容易使用，我们不需要安装任何东西 - 它已经与 Vue 应用程序的默认脚手架和 webpack 模板一起提供。简而言之，如果我们有应该表示路由的 Vue 组件，这就是我们要做的事情：

+   告诉 Vue 使用`vue-router`

+   创建一个路由实例并将每个组件映射到其路径

+   将此实例传递给 Vue 实例或组件的选项

+   使用`router-view`组件进行渲染

### 注意

查看官方`vue-router`文档：[`router.vuejs.org`](https://router.vuejs.org)

创建路由时，应将路由数组传递给它。每个数组项表示给定组件与某个路径的映射：

```js
{
  name: 'home',
  component: HomeComponent,
  path: '/'
}
```

ProFitOro 只有四个可能的路由 - 番茄钟计时器本身，我们可以将其视为主页，带有设置和统计信息的视图，以及协作锻炼的视图。因此，我们的路由看起来非常简单易懂：

```js
// router/index.js
import Vue from 'vue'
import Router from 'vue-router'
import {PomodoroTimer, Settings, Statistics, Workouts} from '@/components/main/sections'

Vue.use(Router)

export default new Router({
  mode: 'history',
  routes: [
    {
      name: **'home'**,
      component: **PomodoroTimer**,
      path: '**/**'
    },
    {
      name: **'settings'**,
      component: **Settings**,
      path: '**/settings'**
    },
    {
      name: **'statistics'**,
      component: **Statistics**,
      path: '**/statistics**'
    },
    {
      name: **'workouts'**,
      component: **Workouts**,
      path: '**/workouts**'
    }
  ]
})
```

现在，如果您在`ContentComponent`视图中导入创建的路由，将其传递给组件的选项并渲染`router-view`组件，您将能够看到 Vue 路由的实际效果！您还可以删除所有组件导入，因为`ContentComponent`现在实际上应该导入的唯一事物是负责其他一切的路由。因此，`ContentComponent`将如下所示：

```js
// ContentComponent.vue
<template>
  <div class="container">
    **<router-view></router-view>**
  </div>
</template>
<script>
  **import router from '@/router'**

  export default {
    **router**
  }
</script>
```

打开页面，在浏览器地址栏中输入`localhost:8080/settings`，`localhost:8080/statistics`，`localhost:8080/workouts`，您将看到视图根据您实际尝试访问的内容而出现。您必须承认，这真的很容易。

现在让我们添加链接，因为我们希望通过单击某些按钮进行导航，而不是在浏览器地址栏中输入导航 URL，对吧？

使用`vue-router`添加导航链接非常容易。使用提供的`router-link`组件，带有指向所需路径的`to`属性的链接：

```js
<router-link to="/">Home</router-link>
```

让我们在我们的`Header`组件中添加这些链接。这个组件应该负责导航表示。因此，在我们的`HeaderComponent.vue`的`template`部分中，添加以下内容：

```js
// HeaderComponent.vue
<template>
  <router-link to="/">Home </router-link>
  <router-link to="statistics">Statistics </router-link>
  <router-link to="workouts">Workouts </router-link>
  <router-link to="settings">Settings </router-link>
</template>
```

不要忘记在组件选项中导入路由并导出它：

```js
// HeaderComponent.vue
<script>
  //...
  **import router from '@/router'**

  export default {
    //

    **router**
  }
</script>
```

通过一点 Bootstrap 类的调整，我们可以得到如下结果：

![使用 vue-router 添加导航](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00113.jpeg)

使用 vue-router 导航 ProFitOro

这就是用`vue-router`及其组件进行路由和导航的基础知识。您可以在`chapter7/1/profitoro`文件夹中找到此部分的最终代码。特别注意路由器本身（`router/index.js`）、`ContentComponent.vue`和`HeaderComponent.vue`文件。

## 练习 - 根据身份验证限制导航

不要忘记，我们必须根据用户的身份验证状态限制导航链接。如果用户是匿名身份验证的，我们不应该显示导航链接。然而，应该有一个按钮，让用户返回到主页。因此，这个按钮应该调用注销功能，并显示不同的文本，比如**返回到起始页**。您已经知道如何有条件地渲染 Vue 组件。我们的路由链接不过是普通组件，所以根据用户的值和其属性`isAnonymous`应用条件渲染机制。

在`chapter7/2/profitoro`文件夹中检查此练习的解决方案。注意`HeaderComponent`组件。

# 使用 Bootstrap 导航栏进行导航链接

我们当前的导航栏很棒 - 它很实用，但不是响应式的。幸运的是，Bootstrap 有一个`navbar`组件，为我们实现了响应性和适应性。我们只需用一些 Bootstrap 类包装我们的导航元素，然后坐下来检查我们美丽的导航栏，在移动设备上折叠，在桌面设备上展开。查看 Bootstrap 关于`navbar`组件的文档：[`v4-alpha.getbootstrap.com/components/navbar/`](https://v4-alpha.getbootstrap.com/components/navbar/)。

### 注意

请记住，此 URL 是用于 alpha 版本。下一个稳定版本 4 将在官方网站上提供。

这些是我们将使用的类，将我们简单的导航栏转换为由 Bootstrap 管理的响应式导航栏：

+   导航栏：这个包裹整个导航栏元素

+   `navbar-toggleable-*`：这也应该包裹整个导航栏元素，并告诉它何时在展开/折叠状态之间切换（例如，`navbar-toggleable-md`会使导航栏在中等大小设备上折叠）

+   `navbar-toggler`：这是一个用于在小型设备上打开折叠菜单的按钮类

+   `navbar-toggler-*`：这告诉`toggler`元素应该被放置在哪里，例如，`navbar-toggler-right`

+   `navbar-brand`：这是代表品牌的导航栏元素的类（可以是标志和/或文本）

+   `collapse navbar-collapse`：这些类将包裹应该在小设备上折叠的导航栏元素

+   `nav-item`：这是每个导航栏项的类

+   `nav-link`：这是`nav-item`项的嵌套元素的类；最终这将是一个将您带到给定链接的锚点

还有许多其他类来定义导航栏的颜色方案，以及其定位、对齐等。查看文档并尝试它们。我将只改变`Header`组件的标记。因此，它将看起来像下面这样：

```js
// HeaderComponent.vue
<template>
  <div>
    <nav class="**navbar navbar-toggleable-md navbar-light**">
      <button class="**navbar-toggler navbar-toggler-right**" type="button" data-toggle="collapse" data-target="#navbarHeader" aria-controls="navbarHeader" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="**navbar-brand**">
        <logo></logo>
      </div>
      <div class="collapse navbar-collapse" id="navbarHeader">
        <ul class="navbar-nav ml-auto">
          <li class="**nav-item**">
            <router-link class="**nav-link**" to="/">Home </router-link>
          </li>
          <li class="nav-item">
            <router-link class="**nav-link**" to="settings">Settings </router-link>
          </li>
          <li class="**nav-item**">
            <router-link class="**nav-link**" to="statistics">Statistics </router-link>
          </li>
          <li class="**nav-item**">
            <router-link class="**nav-link**" to="workouts">Workouts </router-link>
          </li>
        </ul>
        <form class="form-inline my-2 my-lg-0">
          <button class="btn btn-secondary" @click="onLogout">Logout</button>
        </form>
      </div>
    </nav>
  </div>
</template>
```

您可能已经注意到，我在导航项中使用了我们的`router-link`元素和`nav-link`类。事实证明它们非常好地配合在一起。因此，我们将 Vue 路由机制与 Bootstrap 的导航栏混合在一起，在我们的 Vue 应用程序中实现了一个优雅的响应式路由解决方案。现在，我们的页眉看起来就像这样：

![使用 Bootstrap 导航栏进行导航链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00114.jpeg)

ProFitOro 在桌面设备上的导航栏

如果我们在移动设备上打开 ProFitOro，我们将看到一个漂亮的切换按钮而不是菜单：

![使用 Bootstrap 导航栏进行导航链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00115.jpeg)

这是 ProFitOro 在移动设备上的菜单样子

如果我们在移动设备上点击切换按钮，菜单将垂直展开：

![使用 Bootstrap 导航栏进行导航链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00116.jpeg)

这是在移动设备上扩展的 ProFitOro 菜单的样子

### 提示

这在 Bootstrap 4 的 alpha 版本中运行良好，但是如果您使用 Bootstrap 4 Beta，您将看到一些不一致之处。一些类被删除，一些类被添加。为了使它看起来完全相同，做如下操作：

+   用`navbar-expand-lg`替换`navbar-tooglable-md`类

+   将`btn-secondary`按钮的类替换为`button-outline-secondary`，交换切换按钮和品牌元素

基于身份验证的条件渲染功能已被删除。我将重新添加它，但是不再在用户匿名时隐藏元素，而是将它们禁用。这将为应用程序带来额外的价值-未注册用户将不断被提醒，如果他注册，就可以使用一些不错的功能。因此，我将把`disabled` Bootstrap 类绑定到`router-link`元素上。如果用户是匿名的，这个类将被激活。因此，我们的每个路由链接将如下所示：

```js
// HeaderComponent.vue
<router-link class="nav-link" **:class="{disabled:user.isAnonymous}"** to="settings">Settings </router-link>
```

如果你现在打开页面并以匿名用户的身份进入应用程序，你会发现链接显示为禁用状态：

![使用 Bootstrap 导航栏进行导航链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00117.jpeg)

对于未经授权的用户，链接将显示为禁用状态

但是，我们的用户很聪明，我们都知道，对吧？我们的用户将做与你现在考虑做的事情完全相同（如果你还没有做过的话）-打开开发者工具控制台，转到元素选项卡，编辑标记并删除`disabled`类。*Ba-dum-tsss*，现在你可以点击导航链接了！

因此，我们还需要在路由器端保护它。幸运的是，`vue-router`实例提供了一个名为`beforeEach`的钩子方法。这个方法接收下一个和上一个路由，并且在其中你可以评估它们并调用`next()`方法，这将根据条件继续到下一个路由或替换被调用的路径。

此外，每个路由项都可以包括元属性，我们可以在其中传递一个条件，该条件决定是否可以调用该路由。在这方面，请查看`vue-router`文档：[`router.vuejs.org/en/advanced/meta.html`](https://router.vuejs.org/en/advanced/meta.html)。

因此，让我们为每个三个路由项添加一个`requiresAuth`的元属性，并像这样使用`beforeEach`方法：

```js
// router/index.js
router.beforeEach((**to, from, next**) => {
  if (to.matched.some(record => **record.meta.requiresAuth**)) {
    if **(!store.state.user || store.state.user.isAnonymous)** {
      next({
        **path: '/'**
      })
    } else {
      **next()**
    }
  } else {
    **next()**
  }
})
```

*Et voilá*，从现在开始，即使你在未经授权的情况下在浏览器地址栏中明确输入了其中一个有条件的路由 URL，你也会被重定向到主页！

查看`chapter7/3/profitoro`文件夹中此部分的最终代码。特别注意路由器本身（`router/index.js`）和`Header`组件。

# 代码拆分或延迟加载

当我们构建应用程序以部署到生产环境时，所有 JavaScript 都被捆绑到一个唯一的 JavaScript 文件中。这非常方便，因为一旦浏览器加载了这个文件，整个应用程序已经在客户端上了，没有人担心加载更多的东西。当然，这仅适用于单页应用程序。

我们的 ProFitOro 应用程序（至少在这个阶段）受益于这种捆绑行为-它很小，只有一个请求，一切就位，我们不需要为任何 JavaScript 文件从服务器请求任何内容。

然而，这种捆绑可能会有一些缺点。我非常确定您已经构建过或已经看到过庞大的 JavaScript 应用程序。总会有一些时候，加载庞大的捆绑包将变得难以忍受地慢，特别是当我们希望这些应用程序在桌面和移动环境下运行时。

这个问题的一个明显解决方案是以一种方式拆分代码，只有在需要时才加载不同的代码块。这对于单页应用程序来说是一个相当大的挑战，这就是为什么我们现在有一个庞大的社区致力于网页开发。

目前，在网页开发领域已经存在一些简单的技术，可以用来拆分 webpack 应用程序中的代码。查看官方 webpack 文档以了解更多信息：[`webpack.js.org/guides/code-splitting/`](https://webpack.js.org/guides/code-splitting/)。

为了在 Vue.js 应用程序中使用代码拆分，您不需要做任何复杂的事情。无需重新配置您的 webpack 配置文件，也无需重写您的组件。查看有关延迟加载路由的文档条目：[`router.vuejs.org/en/advanced/lazy-loading.html`](https://router.vuejs.org/en/advanced/lazy-loading.html)。

### 提示

**TL;DR**：为了延迟加载您的路由，您只需要改变导入它们的方式。因此，请考虑以下代码：`import PomodoroTimer from '@/components/main/sections/PomodoroTimer'` 要惰性加载您的路由，您应该写成以下形式：`const PomodoroTimer = () => import('@/components/main/sections/PomodoroTimer')`

其余的代码保持完全不变！

因此，我们只需改变在路由器中导入组件的方式：

```js
// router/index.js
const PomodoroTimer = () => import('@/components/main/sections/PomodoroTimer')
const Settings = () => import('@/components/main/sections/Settings')
const Statistics = () => import('@/components/main/sections/Statistics')
const Workouts = () => import('@/components/main/sections/Workouts')
```

就是这样！检查页面，确保一切仍然按预期工作。检查网络面板。您会看到现在将为不同的路由视图请求不同的 JavaScript 包！

如果您将网络请求与以前的版本进行比较，您将看到现在实际上有四个请求-`0.js`，`1.js`，`2.js`和`3.js`-与以前的单个`app.js`请求相比：

![代码分割或延迟加载](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00118.jpeg)

代码分割或延迟加载之前的 app.js 包的单个请求

在代码分割之后，如果我们通过应用程序的导航链接导航，我们将看到以下内容：

![代码分割或延迟加载](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00119.jpeg)

每个路由都会请求相当小的 JavaScript 块

注意一下块的大小。您不认为对于大型项目，代码分割技术实际上可能会增加应用程序的性能吗？检查`chapter7/3.1/profitoro`文件夹中的路由器代码。

# 服务器端渲染

**服务器端渲染**（**SSR**）最近成为了 Web 开发世界中又一个流行的缩写词。它与代码分割技术一起使用，有助于提高 Web 应用的性能。它还对 SEO 产生积极影响，因为所有内容一次性加载，爬虫能够立即看到，而不是在初始请求后在浏览器中构建内容的情况。

我找到了一篇关于 SSR 的好文章，比较了服务器端和客户端渲染（尽管它是 2012 年的）。看看这个链接：[`openmymind.net/2012/5/30/Client-Side-vs-Server-Side-Rendering/`](http://openmymind.net/2012/5/30/Client-Side-vs-Server-Side-Rendering/)。

将服务器端渲染引入 Vue 应用程序非常容易-在这方面查看官方文档：[`ssr.vuejs.org`](https://ssr.vuejs.org)。

我们的应用程序性能很重要；SEO 的工作也很重要。然而，重要的是不滥用工具，不引入实现开销和过度。我们的 ProFitOro 应用程序需要 SSR 吗？要回答这个问题，让我们考虑一下我们的内容。如果有大量的内容被带到页面上，并被用作初始渲染的基础，那么答案可能是肯定的。好吧，这不适用于我们的应用程序。我们有一个简单的登录页面，我们的 ProFitOro 计时器，以及一些配置设置。目前可能有意义的唯一视图是包含锻炼的视图。但现在，让我们不要把事情搞得太复杂。您可以尝试使用我们的 ProFitOro 进行 Vue 应用程序的服务器端渲染技术，但请记住，这不是应该始终使用的东西。还要了解服务器端渲染和预渲染之间的区别（[`github.com/chrisvfritz/prerender-spa-plugin`](https://github.com/chrisvfritz/prerender-spa-plugin)），并检查我们的应用程序实际上如何从这两种技术中受益。

# Nuxt.js

在我们忙于定义路由器对象、路由器链接、代码拆分和学习有关服务器端渲染的知识时，有人实现了一种开发 Vue.js 应用程序的方式，而不必担心所有这些事情。只需编写您的代码。所有诸如路由、代码拆分甚至服务器端渲染的事情都将在幕后为您处理！如果你想知道这到底是什么，让我向你介绍 Nuxt.js：[`nuxtjs.org`](https://nuxtjs.org)。

那么，Nuxt.js 是什么？

Nuxt.js 是用于创建通用 Vue.js 应用程序的框架。

它的主要范围是 UI 渲染，同时抽象出客户端/服务器分发。

它有什么了不起的地方？Nuxt.js 引入了页面的概念 - 基本上，页面也是 Vue 组件，但每个页面代表一个*路由*。一旦您在`pages`文件夹中定义了您的组件，它们就会成为路由，无需任何额外的配置。

在本章中，我们将完全将我们的 ProFitOro 迁移到 Nuxt 架构。所以，做好准备；我们将进行大量的更改！在本章结束时，我们的努力将得到一段漂亮、优雅的代码。

Nuxt 应用有一个单独的`config`文件，你可以在其中定义必要的 webpack 配置，以及`meta`、`links`和额外的`scripts`用于你的`index.html`文件。这是因为 Nuxt 会在构建过程中自动生成你的`index.html`，所以你不必在应用的根目录中拥有它。在这个配置文件中，你还可以定义每个路由变化时应该发生的过渡效果。

创建 Nuxt 应用的方式与创建任何 Vue 应用非常相似 - 所有 Nuxt.js 功能都内置在`nuxt-starter`模板中：[`github.com/nuxt-community/starter-template`](https://github.com/nuxt-community/starter-template)。因此，使用 Nuxt 模板创建 Vue.js 应用只是：

```js
**vue init nuxt/starter <project-name>**

```

让我们创建一个`profitoro-nuxt`项目并看看它是如何工作的。运行以下命令：

```js
**vue init nuxt/starter profitoro-nuxt**

```

点击 Enter 回答问题。

进入生成的文件夹，安装依赖，并运行应用：

```js
**cd profitoro-nuxt**
**npm install**
**npm run dev**

```

在`localhost:3000`上打开页面，并确保你看到这个：

![Nuxt.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00120.jpeg)

Nuxt 应用的初始默认页面

让我们来探索文件夹的结构和代码。有一个名为`pages`的文件夹，你可以在里面找到`index.vue`页面。还有一个名为`components`的文件夹 - 在这里我们将存储我们的组件。有一个`nuxt.config.js`文件，其中存储了所有基本配置。简而言之，就是这样。

让我们来处理`pages`文件夹。我们的 ProFitOro 应用的哪些组件可以定义为`pages`？很容易识别它们，因为我们已经定义了路由。所以，我会说我们可以识别以下页面：

+   `index.vue`：这将检查用户是否已登录，并渲染登录页面或番茄钟计时器页面

+   `login.vue`：这个页面与我们当前的`LandingComponent.vue`完全相同

+   `pomodoro.vue`：这将是包含番茄钟计时器组件的页面

+   `settings.vue`：这个页面将代表我们的`Settings.vue`组件

+   `statistics.vue`：这个页面将负责渲染`Statistics.vue`组件

+   `workouts.vue`：这个页面将负责管理锻炼

让我们为所有这些页面创建占位符。这是我在`pages`文件夹内部的目录结构：

```js
**├── pages**
**│   ├── index.vue**
**│   ├── login.vue**
**│   ├── pomodoro.vue**
**│   ├── settings.vue**
**│   ├── statistics.vue**
**│   └── workouts.vue**

```

这是`login.vue`页面的初始内容：

```js
//login.vue
<template>
  <div>
    login
  </div>
</template>
<script>

</script>
<style scoped>

</style>
```

其他页面都和这个页面非常相似，除了`index.vue`页面：

```js
//index.vue
<template>
  <div>
    <pomodoro></pomodoro>
    <login></login>
  </div>
</template>
<script>
  **import login from './login'**
 **import pomodoro from './pomodoro'**

  export default {
    components: {login, pomodoro}
  }
</script>
<style>
</style>
```

如果你在浏览器中打开此应用程序，并尝试在浏览器的地址栏中键入不同的路径（`localhost:3000/pomodoro`，`localhost:3000/settings`等），你将看到它实际上呈现了相应的页面。多么美妙啊！我们不需要定义任何路由或任何额外的配置就能实现这种行为！在`chapter7/4/profitoro-nuxt`文件夹中检查此部分的代码。

## 使用 nuxt-link 添加链接

就像`vue-router`提供了一个名为`router-link`的组件一样，Nuxt 提供了一个非常相似的组件，名为`nuxt-link`。让我们使用 nuxt-links 而不是 router-links 来更改我们的`HeaderComponent`，并将此组件包含在我们的页面中。

在这之前，让我们安装`sass-loader`，因为，如果你记得的话，我们正在使用 sass 预处理器来处理我们的 CSS，而我们的`HeaderComponent`实际上在很大程度上依赖于它。因此，请继续运行以下命令：

```js
**npm install --save-dev node-sass sass-loader**

```

我还重新包含了 Bootstrap 样式，使用它的*sass*样式而不是纯 CSS。查看`chapter7/5/profitoro-nuxt`文件夹中的`assets/styles`文件夹。在此文件夹中运行`npm install`，并将其用作本部分的工作目录。

现在让我们将`HeaderComponent.vue`和`Logo.vue`复制到`components/common`文件夹中。我们的 logo 标记将发生变化。之前它被包裹在`router-link`组件内，并指向主页。我们将使用`nuxt-link`组件，而不是使用`router-link`：

```js
//components/common/Logo.vue
<template>
  **<nuxt-link to="/">**
    <img class="logo" :src="src" alt="ProFitOro">
  **</nuxt-link>**
</template>
```

请注意，我们将`src`属性绑定到`src`值。我们将从`assets`文件夹获取我们的源。在 Nuxt 应用程序中，我们可以使用`~`符号来指示应用程序的根目录。使用此符号实际上有助于使用相对路径。因此，logo 的源数据属性将如下所示：

```js
// components/common/Logo.vue
<script>
  export default {
    data () {
      return {
        **src: require('~/assets/profitoro_logo.svg')**
      }
    }
  }
</script>
```

我们的 logo 已经准备好了；现在是时候检查`HeaderComponent`组件，并用`nuxt-links`替换所有的路由链接。

打开刚刚复制的`HeaderComponent.vue`组件，暂时删除从 Vuex 存储中使用的所有数据，只保留`Logo`组件的`import`：

```js
//components/common/HeaderComponent.vue
<script>
  import Logo from '~/components/common/Logo'

  export default {
    components: {
      Logo
    }
  }
</script>
```

另外，删除标记内部所有数据的引用，只保留链接并用`nuxt-link`组件替换它们。因此，我们的链接部分将如下所示：

```js
//components/common/HeaderComponent.vue
<ul class="navbar-nav ml-auto">
  <li class="nav-item">
    <**nuxt-link** class="nav-link" **to="/"**>Home **</nuxt-link>**
  </li>
  <li class="nav-item">
    <**nuxt-link** class="nav-link" **to="settings"**>Settings **</nuxt-link>**
  </li>
  <li class="nav-item">
    <**nuxt-link** class="nav-link" **to="statistics"**>Statistics **</nuxt-link>**
  </li>
  <li class="nav-item">
    <**nuxt-link** class="nav-link" **to="workouts"**>Workouts **</nuxt-link>**
  </li>
</ul>
<form class="form-inline my-2 my-lg-0">
  <button class="btn btn-secondary" >Logout</button>
</form>
```

将`HeaderComponent`导入到我们的页面（`settings`，`statistics`，`pomodoro`和`workouts`）中：

```js
//pages/pomodoro.vue
<template>
  <div class="container">
    **<header-component></header-component>**
    pomodoro
  </div>
</template>
<script>
  **import HeaderComponent from '~/components/common/HeaderComponent'**
  export default {
    components: {
      **HeaderComponent**
    }
  }
</script>
<style scoped lang="scss">
  @import "../assets/styles/main";
</style>
```

打开页面。检查我们的链接是否完全没有改变：

![使用 nuxt-link 添加链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00121.jpeg)

我们的链接看起来完全一样！

检查一下，即使我们的响应性仍然存在。如果调整页面大小，你会看到 Bootstrap 的菜单按钮：

![使用 nuxt-link 添加链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00122.jpeg)

菜单按钮仍然存在

当然，最重要的部分是路由工作！点击链接并检查页面是否变化。

你也注意到了当你从一个页面切换到另一个页面时发生了一个很好的过渡吗？

![使用 nuxt-link 添加链接](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00123.jpeg)

过渡是自动发生的，我们没有额外编写任何代码让它发生！

你可以在 `chapter7/6/profitoro-nuxt` 文件夹中找到到目前为止的最终代码。

## 练习 - 使菜单按钮工作

正如我们已经检查过的，我们的响应式菜单按钮仍然存在。但是，如果你点击它，什么也不会发生！这是因为这个按钮的行为是在 `bootstrap.js` 依赖中定义的，而我们还没有包含它。使用 `nuxt.config.js` 来包含必要的 JavaScript 文件，使菜单按钮再次变得伟大。

完成后，检查我在 `chapter7/7/profitoro-nuxt` 文件夹中的解决方案。特别要检查 `nuxt.config.js` 文件的 `head` 部分。

## Nuxt.js 和 Vuex store

在这一部分不会有任何新东西 - Vuex store 可以以与以前相同的方式使用。啊，等等。在 Nuxt 应用程序内，我们必须导出返回 Vuex store 而不是实例本身的函数。在这方面查看官方文档：[`nuxtjs.org/guide/vuex-store`](https://nuxtjs.org/guide/vuex-store)。所以，基本上我们不会使用以下代码：

```js
export default new Vuex.Store({
  state,
  getters,
  mutations: {
    ...
  },
  actions
})
```

相反，我们必须这样做：

```js
**export default () => Vuex.Store**({
  state,
  getters,
  mutations: {
    ...
  },
  actions
})
```

让我们也利用这个机会在一个单独的文件中初始化 Firebase 应用程序，并将其用作我们应用程序的单例。因此，将 `firebaseApp` 的初始化移动到其单独的 `firebase/index.js` 文件中，并用导入的 `firebaseApp` 实例替换所有 `state.firebaseApp` 的出现。

最后，但同样重要的是，不要忘记安装所需的 `vuexfire` 和 `firebase` 依赖项：

```js
**npm install --save vuexfire firebase**

```

在 `chapter7/8/profitoro-nuxt` 文件夹中检查此部分的代码。特别要注意 `store` 和 `firebase` 文件夹。

## Nuxt.js 中间件

你还记得我们如何不得不在 vue 路由实例中引入`beforeEach`方法，以防止一些路由在用户未经身份验证时被渲染吗？Nuxt.js 有一个非常类似的机制。你只需要定义一个所谓的`middleware`，在其中可以根据一些条件（例如，基于 Vuex 存储中的`isAuthenticated`属性的值）重定向请求，然后告诉页面它们必须依赖于身份验证中间件。然后，每当尝试路由到给定页面时，中间件的函数将运行并执行其要求执行的任何操作。

让我们将这种类型的中间件添加到我们的 ProFitOro Nuxt 应用程序中。在`middleware`文件夹内创建一个名为`authentication.js`的文件，并添加以下内容：

```js
//middleware/authenticated.js
export default function ({ store, redirect }) {
  if (!store.getters.isAuthenticated) {
    return redirect('/')
  }
}
```

这段代码负责检查`isAuthenticated`属性并在其为 false 或未定义时将用户重定向到主页。

现在，在设置、统计和锻炼页面中添加 middleware 属性：

```js
<template>
  <...>
</template>
<script>
  //...
  export default {
    **middleware: 'authenticated'**,
    //...
  }
</script>
```

打开页面并尝试单击我们刚刚添加了 middleware 的页面的相应链接。它不会起作用！尝试删除一些页面的 middleware 代码，并检查路由是否正常工作。这不是很棒吗？

检查`chapter7/9/profitoro-nuxt`文件夹中的此部分代码。检查`middleware/index.js`文件和`pages`文件夹中的 Vue 页面。

## 练习-完成所有！

嗯，为了使我们的 ProFitOro 成为 Nuxt.js 应用程序，我们已经做了很多工作，但我们的功能还不完全。我们仍然需要复制很多组件。所以，请做吧。现在，这只是一个很好的复制粘贴的问题。所以，请做，并确保我们的 ProFitOro 正常工作。

如果有疑问，请查看`chapter7/10/profitoro-nuxt`文件夹。您可能会遇到尝试使用*Enter*键登录并发现自己成为匿名用户的问题。这是一个将在接下来的章节中修复的小问题。现在，请每次尝试使用有效凭据登录时，只需不要忘记点击**登录**按钮！

# 摘要

在本章中，我们使用不同的工具为我们的应用程序添加了基本路由。首先，我们学习了如何使用 vue-router 来实现路由功能，然后我们使用 Nuxt.js 模板来使用旧组件和样式构建全新的应用程序。我们使用了 Nuxt vue 提供的页面概念，以便以与`vue-router`相同的路由功能，并以轻松和不显眼的方式将我们的 ProFitOro 应用程序转变为 Nuxt 应用程序。我们显著减少了代码量并学到了新东西。完全是赢家！

在本章中，我们还使用了 Bootstrap 的`navbar`以一种漂亮和响应的方式显示我们的导航路由，并且学会了即使进行了最彻底的重构，当我们使用 Bootstrap 方法时，功能和响应性仍然与我们同在。再次取得了巨大成功！

我们的应用程序几乎完全功能，但是它仍然缺少主要功能 - 锻炼。目前，在番茄工作法间隔期间，我们正在展示一个硬编码的俯卧撑锻炼。

在阅读本书时，您是否正在使用 ProFitOro 应用程序？如果是的话，我想我会在街上认出你 - 你会因为做了这么多俯卧撑而有巨大的肌肉。

是时候在我们的应用程序中添加更多的锻炼了，不是吗？如果你还记得需求，锻炼是协作工作的主题。因此，我们将在下一章中添加这个功能。我们将使用 Firebase 的数据存储机制来存储锻炼的图像，实时数据库来存储锻炼的对象，Bootstrap 的卡片布局来显示不同的锻炼，以及基于 Bootstrap 的表单来向我们的应用程序添加新的锻炼。


# 第八章：让我们合作 - 使用 Firebase 数据存储和 Vue.js 添加新的锻炼

在上一章中，我们学习了如何使用`vue-router`和`Nuxt.js`为 Vue 应用程序添加一些基本导航。我们已经重新设计了我们的 ProFitOro 应用程序，将其转变为基于 Nuxt 的应用程序。现在我们的应用程序是功能性的，它具有身份验证机制，并且可以导航。但是，它仍然缺少最重要的功能之一 - 锻炼。在本章中，我们将实现锻炼管理页面。你还记得它在第二章 *底层 - 教程解释*中的要求吗？

这个页面应该允许用户查看数据库中现有的锻炼，选择或取消选择它们在番茄钟休息期间显示，对它们进行评分，甚至添加新的锻炼。我们不打算实现所有这些功能。但是，我们将实现足够的功能让你能够继续这个应用程序，并且以巨大的成功完成它的实现！因此，在本章中，我们将做以下工作：

+   为锻炼管理页面定义一个响应式布局，它将包括两个基本部分 - 所有锻炼的可搜索列表以及向列表中添加新锻炼的可能性

+   使用 Firebase 数据库和数据存储机制存储新的锻炼以及锻炼图片

+   使用 Bootstrap 模态框显示每个单独的锻炼

+   使用响应式布局和 fixed-bottom 类使我们的页脚更好看

# 使用 Bootstrap 类创建布局

在我们开始为锻炼页面实现布局之前，让我提醒你模拟看起来是什么样子的：

![使用 Bootstrap 类创建布局](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00124.jpeg)

这是我们最初在模拟中定义的东西

我们将做一些略有不同的事情 - 类似于我们在设置页面所做的事情。让我们创建一个在移动设备上堆叠的两列布局。因此，这个模拟将适用于移动屏幕，但在桌面设备上会显示两列。

让我们在`components/workouts`文件夹内添加两个组件 - `WorkoutsComponent.vue`和`NewWorkoutComponent.vue`。在这些新组件的模板中添加一些虚拟文本，并在`workouts.vue`页面中定义我们的两列布局。你肯定记得，为了在小设备上堆叠列，并在其他设备上使用不同大小的列，我们必须使用`col-*-<number>`表示法，其中`*`表示设备的大小（`sm`表示小，`md`表示中，`lg`表示大，等等），数字表示列的大小，范围从`1`到`12`。由于我们希望我们的布局在小设备上堆叠（这意味着列的大小应为`12`），并且在中大型设备上是两个大小相等的列，我想出了以下布局定义：

```js
// pages/workouts.vue
<template>
  <div class="container">
    <header-component></header-component>
    <div class="row justify-content-center">
      <div class="**col-sm-12 col-md-6 col-lg-6**">
        **<workouts-component></workouts-component>**
      </div>
      <div class="**col-sm-12 col-md-6 col-lg-6**">
        **<new-workout-component></new-workout-component>**
      </div>
    </div>
    <footer-component></footer-component>
  </div>
</template>
```

不要忘记将`WorkoutsComponent.vue`和`NewWorkoutComponent.vue`组件都导入`workouts.vue`页面：

```js
// pages/workouts.vue
<script>
  //...
  **import { NewWorkoutComponent, WorkoutComponent, WorkoutsComponent } from '~/components/workouts'**
  export default {
    components: {
    /...
      **NewWorkoutComponent**,
      **WorkoutsComponent**
    }
  }
</script>
```

现在我们有了一个两列响应式布局：

![使用 Bootstrap 类创建布局](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00125.jpeg)

用于训练管理页面的两列响应式布局

检查`chapter8/1/profitoro`文件夹中的此实现的代码。特别注意`components/workouts`文件夹的内容和`workouts.vue`页面的内容。

# 使页脚漂亮

你不厌倦这个硬编码词“**页脚**”总是在我们的内容下面吗？

![使页脚漂亮](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00126.jpeg)

丑陋的飞行硬编码页脚总是粘在我们的内容上

让我们对此做些什么！如果你查看我们的模型，那里有三列：

+   版权信息的一列

+   另一个是当天的事实

+   最后是作者信息

你已经知道该怎么做了，对吧？再次强调，我们希望这些列在中大型设备上均匀分布，并在移动设备上堆叠。因此，我们的代码将如下所示：

```js
// components/common/FooterComponent.vue
<template>
  <div class="footer">
    <div class="container row">
      <div class="copyright **col-lg-4 col-md-4 col-sm-12**">Copyright</div>
      <div class="fact **col-lg-4 col-md-4 col-sm-12**">Working out sharpens your memory</div>
      <div class="author **col-lg-4 col-md-4 col-sm-12**"><span class="bold">Workout Lovers</span></div>
    </div>
  </div>
</template>
```

让我们暂时将“当天事实”部分硬编码。好吧，现在我们的页脚看起来好一些了。至少它不再只是“页脚”这个词在那里：

![使页脚漂亮](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00127.jpeg)

我们的页脚不再只是“页脚”这个词，但它仍然粘在主内容上

然而，它仍然固定在主要内容上，这并不是很好。如果我们的页脚固定在视口底部会很棒。这是一个常见的问题，在互联网上会找到很多关于这个问题的文章和解决方案：[`stackoverflow.com/questions/18915550/fix-footer-to-bottom-of-page`](https://stackoverflow.com/questions/18915550/fix-footer-to-bottom-of-page)。幸运的是，我们正在使用 Bootstrap，它带有一系列用于粘性顶部、固定底部等的实用类。

### 提示

为了使您的页脚在 Bootstrap 中固定，只需向其添加这个类：`fixed-bottom`

一旦将这个类添加到您的页脚中，您将看到它如何固定在视口底部。尝试调整视口大小，将页面底部上下移动，您会发现我们的页脚会跟随在底部。

在`chapter8/2/profitoro`文件夹中检查本节的代码。唯一的变化是`HeaderComponent.vue`组件，它位于`components/common`文件夹中。

# 使用 Firebase 实时数据库存储新的锻炼

在开始本节之前，请检查`chapter8/3/profitoro`文件夹中的代码。`Workouts`和`NewWorkout`组件都填充有标记。

### 提示

不要忘记运行`npm install`和`npm run dev`！

它还没有起作用，但显示了一些东西：

![使用 Firebase 实时数据库存储新的锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00128.jpeg)

带有一些内容的锻炼管理页面

在本节中，我们将向 Firebase 数据库中的锻炼资源添加锻炼对象。之后，我们最终可以学习如何使用 Firebase 数据存储机制存储图像。

首先，让我们像为统计和配置对象一样添加 Firebase 绑定。打开`action.js`文件，找到`bindFirebaseReferences`方法。在这里，我们应该为`workouts`资源添加绑定。因此，这个方法现在包含三个绑定：

```js
// state/actions.js
**bindFirebaseReferences**: firebaseAction(({state, commit, dispatch}, user) => {
  let db = firebaseApp.database()
  let configRef = db.ref(`/configuration/${user.uid}`)
  let statisticsRef = db.ref(`/statistics/${user.uid}`)
  **let workoutsRef = db.ref('/workouts')**

  dispatch('bindFirebaseReference', {reference: configRef, toBind: 'config'}).then(() => {
    commit('setConfigRef', configRef)
  })
  dispatch('bindFirebaseReference', {reference: statisticsRef, toBind: 'statistics'}).then(() => {
    commit('setStatisticsRef', statisticsRef)
  })
  **dispatch('bindFirebaseReference', {reference: workoutsRef, toBind: 'workouts'}).then(() => {**
 **commit('setWorkoutsRef', workoutsRef)**
 **})**
})
```

一旦应用程序卸载，我们还应该解除它们的绑定：

```js
//state/actions.js
unbindFirebaseReferences: firebaseAction(({unbindFirebaseRef, commit}) => {
    commit('setConfigRef', null)
    commit('setStatisticsRef', null)
    **commit('setWorkoutsRef', null)**
    try {
      unbindFirebaseRef('config')
      unbindFirebaseRef('statistics')
      **unbindFirebaseRef('workouts')**
    } catch (error) {
      return
    }
  })
```

让我们还向我们的状态添加`workoutsRef`和`workouts`属性。最后但并非最不重要的是，不要忘记实现名为`setWorkoutsRef`的 mutation：

```js
// state/mutations.js
setWorkoutsRef (state, value) {
  state.workoutsRef = value
}
```

现在，有了存储在我们状态中的`workoutsRef`，我们可以实现将其更新为新创建的锻炼的操作。之后，我们将能够在`NewWorkout`组件中使用此操作并填充我们的锻炼数据库。

查看 Firebase 关于读取和写入实时数据库的文档：[`firebase.google.com/docs/database/web/read-and-write`](https://firebase.google.com/docs/database/web/read-and-write)。向下滚动，直到找到“*新帖子创建*”示例：

![使用 Firebase 实时数据库存储新锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00129.jpeg)

Firebase 数据库文档中的新帖子创建示例

你不觉得这个案例和我们的非常相似吗？用户添加的每个锻炼都有其名称、描述和图片（或者甚至多张图片）。锻炼也属于创建它们的用户。所以，也许我们可以做一些非常类似的事情。如果我们决定实现每个用户删除他们的锻炼的可能性，为`user-workouts`创建一个资源可能会很有用。在复制此代码之前，让我们就锻炼对象数据结构达成一致意见。它应该包含什么？由于它来自`NewWorkout`组件，它将已经带有锻炼的名称、描述和图片 URL。我们应该在`action`内丰富它吗？可能，我们应该添加添加它的用户的名称和 UID，创建日期和评分属性。这应该足够了。所以，我们的锻炼数据结构将如下所示：

```js
{
  **name**: 'string',
  **description**: 'string',
  **pictures**: ['string'],
  **username**: 'string',
  **uid**: 'string',
  **rate**: 'number',
  **date**: 'timestamp'
}
```

`name`、`description`、`username`和`uid`属性都是字符串。`pictures`属性应该是 URL 字符串的数组，`rating`应该是一个数字，让我们以时间戳的形式存储我们的`date`属性。

### 注意

很好，我们正在实现前端和后端部分，所以我们在我们之间达成了数据架构的一致。如果你曾经在一个有前端和后端开发人员的团队中工作过，请不要忘记在任何实施之前达成数据架构的一致！

因此，我们知道描述、名称和图片 URL 应该在`NewWorkout`组件内填充。因此，让我们在我们的`action`方法内填充其他所有内容。最后，它看起来会非常类似于 Firebase 示例：

```js
// store/actions.js
**createNewWorkout** ({commit, state}, workout) {
  if (!workout) {
    return
  }

  **workout.username = state.user.displayName**
 **workout.uid = state.user.uid**
 **workout.date = Date.now()**
 **workout.rate = 0**
  // Get a key for a new Workout.
  let newWorkoutKey = state.workoutsRef.push().key

  // Write the new post's data simultaneously in the posts list and the user's post list.
  let updates = {}
  updates['/**workouts**/' + newWorkoutKey] = workout
  updates['/**user-workouts**/' + state.user.uid + '/' + newWorkoutKey] = workout

  return firebaseApp.database().ref().update(updates)
},
```

再次注意，我们正在引入一个名为`user-workouts`的新资源。我们可以以与统计和配置用户数据相同的方式将此资源绑定到我们的状态。如果我们决定实现删除用户资源，这可能会很方便。

现在，让我们转到我们的`NewWorkout`组件。在这里，我们只需要将一些 Vue 模型绑定到相应的输入和单击事件绑定到**提交**按钮。**应用**按钮上的单击事件应绑定到`createNewWorkout`动作，同时调用相应的数据。暂时不要担心`pictures`，我们将在下一节中处理它们。

此时，我们可以用状态训练对象替换`Workouts`组件中的硬编码训练数组：

```js
//Components/Workouts.vue
// ...
<script>
  import {mapState} from 'vuex'
  export default {
    **computed: {**
 **...mapState(['workouts'])**
 **}**
  }
</script>
//...
```

检查您新创建的训练立即出现在训练部分的方式！

检查`chapter8/4/profitoro`文件夹中此部分的最终代码。注意存储文件（`actions.js`，`mutations.js`）以及`components/workouts`文件夹中的`NewWorkoutComponent`和`WorkoutsComponent`组件。

# 使用 Firebase 数据存储存储图像

Firebase 云存储允许您上传和检索不同的内容（文件、视频、图像等）。同样，Firebase 提供了一种访问和管理数据库的方式，您可以访问和管理存储桶。您可以上传 Blob、Base64 字符串、文件对象等。

首先，您应告诉您的 Firebase 应用程序，您将使用 Google 云存储。因此，您需要向应用程序配置对象添加`storageBucket`属性。在 Google Firebase 控制台上检查应用程序的设置，并将`storageBucket`引用复制到`firebase/index.js`文件中：

```js
// Initialize Firebase
import firebase from 'firebase'
//...
let config = {
  apiKey: 'YOUR_API_KEY',
  databaseURL: 'https://profitoro-ad0f0.firebaseio.com',
  authDomain: 'profitoro-ad0f0.firebaseapp.com',
  **storageBucket: 'gs://profitoro-ad0f0.appspot.com'**
}
//...
```

现在您的 Firebase 应用程序知道要使用哪个存储桶。让我们还打开 Firebase 控制台的数据存储选项卡，并为我们的训练图像添加一个文件夹。让我们称之为…训练：

![使用 Firebase 数据存储存储图像](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00130.jpeg)

在 Firebase 数据存储选项卡中创建一个名为“workouts”的文件夹

现在一切准备就绪，可以开始使用我们的云存储桶。

首先，我们必须获取对我们的训练文件夹的引用，以便我们可以修改它。查看有关存储桶引用创建的 Firebase API 文档：[`firebase.google.com/docs/storage/web/create-reference`](https://firebase.google.com/docs/storage/web/create-reference)。在我们的情况下，引用将如下所示：

```js
firebaseApp.storage().ref().child('workouts')
```

我们应该在哪里使用它？在存储训练之前，我们应该存储图片文件，获取它们的云 URL，并将这些 URL 分配给训练的`pictures`属性。因此，这是我们的计划：

+   创建一个上传文件并返回这些文件的下载 URL 的方法

+   在调用`createNewWorkout`动作之前使用这个方法来为 workout 对象的 pictures 属性分配 URL

让我们创建一个上传文件并返回其`downloadURL`的方法。查看 Firebase 文档，了解如何使用其 API 上传文件：[`firebase.google.com/docs/storage/web/upload-files`](https://firebase.google.com/docs/storage/web/upload-files)。看一下**从 Blob 或文件上传**部分。你会看到我们应该在云存储引用上使用"`put`"方法，提供一个文件对象。这将是一个返回快照对象的 promise：

```js
var file = ... // use the Blob or File API
ref.put(file).then(function(snapshot) {
  console.log('Uploaded a blob or file!');
});
```

这个`snapshot`对象是什么？这是存储在云上的文件的表示。它包含了很多信息，但对我们来说最重要的是它的`downloadURL`属性。因此，我们的 promise 看起来会和示例 promise 非常相似，但它将返回`snapshot.downloadURL`。因此，打开`actions.js`文件，创建一个名为`uploadImage`的新方法。这个方法将接收一个文件对象，在我们的`workout`云文件夹引用上创建一个子引用，然后`put`一个文件并返回`downloadURL`。因此，它看起来会像这样：

```js
function _uploadImage (file) {
  let ref = firebaseApp.storage().ref().child('workouts')
  return **ref.child(file.name)**.put(file).then(snapshot => {
    **return snapshot.downloadURL**
  })
}
```

你难道没有看到一个小问题吗？如果两个不同的用户提交了不同的图片，但使用了相同的名称，那么这些图片将会互相覆盖。作为一个小练习，想想避免这个问题的方法。

### 提示

提示：看一下这个 npm 包：

[`www.npmjs.com/package/uuid`](https://www.npmjs.com/package/uuid)

因此，我们有一个上传文件并返回其`downloadURL`的 promise。然而，这还不是我们最终的动作。我们最终的`action`方法应该上传一个*数组*的文件，因为这是我们从多文件输入中得到的 - 一组文件对象。因此，我们最终的 promise 将只返回所有 promise 的结果，它看起来会像下面这样简单：

```js
uploadImages ({state}, files) {
  return **Promise.all**(files.map(**_uploadImage**))
}
```

现在可以在`NewWorkout`组件中调用这个动作，然后再调用`createNewWorkout`动作。

首先，我们需要将`pictures`属性绑定到文件输入元素。显而易见的选择是使用`v-model`指令将属性`pictures`绑定到输入上：

```js
<input **v-model="pictures"** type="file" multiple class="form-control-file" id="imageFile">
```

尽管如此显而易见吗？`v-model`指令确定了*双向数据绑定*，但我们如何设置数据呢？文件输入的数据要么是`FileObject`，要么是`FileList`。我们该如何设置它呢？似乎对这个元素应用双向数据绑定是没有意义的。

### 注意

实际上，你不能将响应式数据绑定到文件输入，但是你可以在 change 事件中设置你的数据：

[`forum.vuejs.org/t/vuejs2-file-input/633/2`](https://forum.vuejs.org/t/vuejs2-file-input/633/2)

因此，我们必须监听`change`事件，并在每次更改时设置我们的数据。让我们将这个事件绑定到`filesChange`方法：

```js
// NewWorkoutComponent.vue
<input @change="**filesChange($event.target.files)**" type="file" multiple class="form-control-file" id="imageFile">
```

现在让我们创建这个方法，只需将`this.pictures`分配给我们接收到的参数。好吧，不是*只是分配*，因为我们接收到的是一个`FileList`对象，它并不完全是一个可以迭代的数组。因此，我们需要将它转换成一个简单的`File`对象数组。

### 提示

我们可以使用 ES6 扩展运算符来做到这一点：

`filesArray = [...fileListObject]`

因此，我们的`filesChange`方法将如下所示：

```js
  // NewWorkoutComponent.vue
  export default {
    methods: {
      //...
      **filesChange (files) {**
 **this.pictures = [...files]**
 **}**
    //...
    }
  }
```

现在我们终于可以更新我们的`onCreateNew`方法了。首先，它应该分发`uploadImages`动作，并在承诺解决后分发`createNewWorkout`动作，将承诺的结果分配给`pictures`数组。现在这个方法将如下所示：

```js
// NewWorkoutComponent.vue
onCreateNew (ev) {
  ev.preventDefault()
  ev.stopPropagation()
  **this.uploadImages(this.pictures).then(picUrls => {**
    this.createNewWorkout({
      name: this.name,
      description: this.description,
      pictures: **picUrls**
    })
    this.reset()
  })
}
```

不要忘记导入`uploadImages`动作。另外，创建一个`reset`方法，将所有数据重置为初始状态。

创建一些带有图片的锻炼，并享受结果！

## 让我们搜索！

所以现在我们可以创建锻炼，并看到它们显示在锻炼列表中。然而，我们有这个不错的搜索输入，但它什么也没做：(. 尽管如此，我们正在使用 Vue.js，所以实现这个搜索真的很容易。我们只需要创建一个`searchTerm`数据属性，并将其绑定到搜索输入，然后通过这个`searchTerm`过滤锻炼数组。因此，我将添加计算属性，让我们称之为`workoutsToDisplay`，这个属性将表示一个通过名称、描述和用户名属性过滤的锻炼属性（我们从 Vuex 存储的状态中导入的属性）。因此，它将给我们提供通过所有这些术语进行搜索的可能性：

```js
// WorkoutsComponent.vue
<script>
  //...
  export default {
    //...
    computed: {
      ...mapState(['workouts']),
      **workoutsToDisplay () {**
 **return this.workouts.filter(workout => {**
 **let name = workout.name.toLowerCase()**
 **let description = workout.description.toLowerCase()**
 **let username = workout.username.toLowerCase()**
 **let term = this.searchTerm.toLowerCase()**
 **return name.indexOf(term) >= 0 || description.indexOf(term) >= 0 || username.indexOf(term) >= 0**
 **})**
 **}**
    }
  //...
  }
</script>
```

不要忘记将`searchTerm`属性添加到组件的数据中，并将其绑定到搜索输入元素：

```js
<template>
  <div>
    <div class="form-group">
      <input **v-model="searchTerm"** class="input" type="search" placeholder="Search for workouts">
    </div>
  </div>
</template>
<script>
  //...
  export default {
    data () {
      return {
        name: '',
        username: '',
        datecreated: '',
        description: '',
        pictures: [],
        rate: 0,
        **searchTerm**: ''
      }
    }
  }
</script>
```

当然，我们现在应该遍历`workoutsToDisplay`数组来显示锻炼卡片，而不是遍历锻炼数组。因此，只需稍微编辑卡片`div`的`v-for`指令：

```js
v-for="workout in **workoutsToDisplay**"
```

打开页面并尝试搜索！如果我按用户名搜索，只会显示由该用户创建的锻炼：

![让我们搜索！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00131.jpeg)

有道理，因为我创建了所有现有的锻炼直到现在

如果我按锻炼的名称搜索，比如俯卧撑，只会出现这个锻炼：

![让我们搜索！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00132.jpeg)

按锻炼名称搜索

我们快要完成了！现在我们唯一要做的就是在番茄钟的休息时段显示从锻炼列表中随机选择的锻炼，而不是硬编码的数据。尝试在`pomodoro.vue`页面中自己做到这一点。

现在您可以创建新的锻炼，并且它们将立即出现在锻炼部分。它们还会在我们的番茄钟休息期间出现在主页上。

干得好！检查`chapter8/5/profitoro`文件夹中此部分的代码。特别注意`store/actions.js`文件中的新操作以及`components/workouts`文件夹中的`Workouts`和`NewWorkout`组件。查看随机锻炼是如何被选择并显示在`pomodoro.vue`页面中的。

# 使用 Bootstrap 模态框显示每个锻炼

现在我们可以在页面上看到所有现有的锻炼，这很棒。然而，我们的用户真的很想详细了解每个锻炼-查看锻炼的描述，对其进行评分，查看谁创建了它们以及何时创建的等等。在小的“卡片”元素中放置所有这些信息是不可想象的，因此我们需要一种放大每个元素以便能够查看其详细信息的方法。Bootstrap 模态框是提供此功能的绝佳工具。查看 Bootstrap 文档有关模态 API 的信息：[`v4-alpha.getbootstrap.com/components/modal/`](https://v4-alpha.getbootstrap.com/components/modal/)。

### 注意

请注意，Bootstrap 4 在撰写本文时处于 alpha 阶段，这就是为什么在某个时候这个链接可能不再有效，所以只需在官方 Bootstrap 网站上搜索相关信息即可。

基本上，我们需要一个触发模态的元素和模态标记本身。在我们的情况下，每个小锻炼卡都应该被用作模态触发器；`WorkoutComponent`将是我们的模态组件。因此，只需在 Workouts 组件内的`card`元素中添加`data-toggle`和`data-target`属性：

```js
// WorkoutsComponent.vue
<div class="card-columns">
  <div data-toggle="modal" data-target="#workoutModal" v-for="workout in workouts" class="card">
    <img class="card-img-top img-fluid" :src="workout.pictures && workout.pictures.length && workout.pictures[0]" :alt="workout.name">
    <div class="card-block">
      <p class="card-text">{{ workout.name }}</p>
    </div>
  </div>
</div>
```

现在让我们来处理`WorkoutComponent`组件。假设它将接收以下属性：

+   名称

+   描述

+   用户名

+   创建日期

+   费率

+   图片

因此，我们可以为我们的模态构建一个非常简单的标记，类似于这样：

```js
<template>
  <div class="modal fade" id="**workoutModal**" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">**{{ name }}**</h5>
          <button type="button" class="close" data-dismiss="modal" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="modal-body">
          <div class="text-center">
            <img **:src="pictures && pictures.length && pictures[0]"** class="img-fluid" :alt="name">
          </div>
          <p>**{{ description }}**</p>
        </div>
        <div class="modal-footer">
          <p>Created on **{{ datecreated }}** by **{{ username }}**</p>
        </div>
      </div>
    </div>
  </div>
</template>
```

请记住，这个模态需要具有与其从切换元素进行定位的完全相同的 ID 属性。

不要忘记在`props`属性下指定所需的属性：

```js
// WorkoutComponent.vue
<script>
  export default {
    **props: ['name', 'description', 'username', 'datecreated', 'rate', 'pictures']**
  }
</script>
```

现在这个组件可以被导入到 Workouts 组件中并在那里使用：

```js
// WorkoutsComponent.vue
<template>
  <div>
    <...>
    <div class="card-columns">
      <...>
    </div>
    **<workout-component**
 **:name="name"**
 **:description="description"**
 **:username="username"**
 **:datecreated="datecreated"**
 **:pictures="pictures"**
 **:rate="rate">**
 **</workout-component>**
  </div>
</template>
```

如果你现在点击一些小卡片，空的模态将会打开：

![使用 Bootstrap 模态框显示每个锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00133.jpeg)

模态有效！但是它是空的

我们肯定还应该做一些事情，以便所选元素的数据传播到组件的数据中。让我们添加一个方法来执行这项工作，并将其绑定到`card`元素的`click`事件上：

```js
// WorkoutsComponent.vue
<div data-toggle="modal" data-target="#workoutModal" v-for="workout in workouts" class="card" **@click="onChosenWorkout(workout)"**>
```

该方法将只是将锻炼的数据复制到相应组件的数据中：

```js
// WorkoutsComponent.vue – **methods** section
**onChosenWorkout** (workout) {
  this.name = workout.name
  this.description = workout.description
  this.username = workout.username
  this.datecreated = workout.date
  this.rate = workout.rate
  this.pictures = workout.pictures
}
```

现在看起来好多了！

![使用 Bootstrap 模态框显示每个锻炼](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00134.jpeg)

数据绑定确实有效！

看起来不错，所有数据都在这里，但还不完美。想想我们如何能改进它。

## 练习

使模态底部显示的日期可读。以这样的方式做，使底部看起来像这样：

![Exercise](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00135.jpeg)

锻炼模态的底部，带有可读的数据

尝试使用现有工具，而不是重新发明轮子。

### 提示

想想 moment.js 库：

[`momentjs.com/`](https://momentjs.com/)

自己检查一下，直到这一刻的最终代码在`chapter8/6/profitoro`文件夹中。注意`components/workout`文件夹中的`Workouts`和`Workout`组件。

# 是时候应用一些样式了

我们的应用程序现在已经完全功能，可以立即使用。当然，它还不完美。它缺乏验证和一些功能，一些要求尚未实现，最重要的是...它缺乏美感！它全是灰色，没有风格...我们是人类，我们喜欢美丽的东西，不是吗？每个人都以自己的方式实现风格。我强烈建议，如果你想使用这个应用程序，请找到自己的风格和主题，并实现它并与我分享。我会很乐意看到它。

至于我，因为我不是设计师，我请我的好朋友 Vanessa（[`www.behance.net/MeegsyWeegsy`](https://www.behance.net/MeegsyWeegsy)）为 ProFitOro 应用程序设计一个漂亮的设计。她做得很好！因为我忙着写这本书，所以我没有时间实现 Vanessa 的设计，因此我请我的好朋友 Filipe（[`github.com/fil090302`](https://github.com/fil090302)）帮助我。Filipe 也做得很好！一切看起来都和 Vanessa 实现的一样。我们使用了`scss`，所以你一定很熟悉，因为我们在这个应用程序中已经在使用它作为预处理器。

您可以重用现有的样式来覆盖一些变量，以创建自己的主题。请在`chapter8/7/profitoro`文件夹中检查最终代码。所有样式都位于`assets/styles`目录中。它具有以下结构：

![是时候应用一些风格](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00136.jpeg)

目录结构

至于最终的外观，就是这样的。

这是带有 Pomodoro 计时器的主页面：

![是时候应用一些风格](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00137.jpeg)

包含 Pomodoro 计时器的主页面

这是设置页面的样子：

![是时候应用一些风格](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00138.jpeg)

设置页面的外观和感觉

最后，这就是 Workouts 页面的样子：

![是时候应用一些风格](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00139.jpeg)

Workouts 页面的外观和感觉

你仍然需要实现统计页面-现在，它只显示完成的 Pomodoro 的总数：

![是时候应用一些风格](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00140.jpeg)

统计页面尚未完全完成，只显示完成的 Pomodoros 的总数

还有一些工作要做，但你不觉得我们迄今为止做得很好吗？我们不仅拥有一个完全可配置的番茄钟计时器，还可以在工作日进行小型锻炼。这是多么棒啊！

# 总结

在本章中，我们终于实现了锻炼管理页面。现在我们可以看到数据库中存储的所有锻炼，并创建我们自己的锻炼。我们学会了如何使用 Google Firebase 数据存储系统和 API 来存储静态文件，并且能够将新创建的锻炼存储在 Firebase 实时数据库中。我们还学会了如何使用 Bootstrap 模态框，并将其用于在漂亮的模态弹出窗口中显示每个锻炼。

在下一章中，我们将进行每个软件实施过程中最重要的工作 - 我们将测试迄今为止所做的工作。我们将使用 Jest ([`facebook.github.io/jest/`](https://facebook.github.io/jest/)) 来测试我们的应用程序。之后，我们将最终部署我们的应用程序并定义未来的工作。你准备好测试你的工作了吗？那就翻开下一页吧！
