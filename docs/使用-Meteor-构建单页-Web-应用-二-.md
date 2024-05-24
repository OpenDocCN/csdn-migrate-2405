# 使用 Meteor 构建单页 Web 应用（二）

> 原文：[`zh.annas-archive.org/md5/54FF21F0AC5E9648A2B99A8900626FC1`](https://zh.annas-archive.org/md5/54FF21F0AC5E9648A2B99A8900626FC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用会话保持状态

我们在之前的章节中实现懒加载技术时已经使用了 Meteor 的 session 对象。在本章中，我们想要更深入地了解它，并学习如何使用它来创建特定模板的反应式函数。

本章将涵盖以下主题：

+   会话是什么

+   热代码推送如何影响 session

+   使用 session 重新运行模板助手

+   重新运行函数

+   创建特定模板的反应式函数

    ### 注意

    如果你直接跳到这一章节并想要跟随示例，可以从书籍的网页上[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或从 GitHub 仓库[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter5`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter5)下载上一章节的代码示例。

    这些代码示例还将包含所有的样式文件，因此我们不必担心在过程中添加 CSS 代码。

# Meteor 的 session 对象

Meteor 提供的`Session`对象是一个反应式数据源，主要用于在热代码重载过程中维护全局状态，尽管它不会在页面手动重载时保存其数据，这使得它与 PHP 会话不同。

### 注意

当我们上传新代码时，服务器会将这些更新推送给所有客户端，这时就会发生热代码重载。

`Session`对象是一个反应式数据源。这意味着无论这个 session 变量在反应式函数中如何使用，当它的值发生变化时，它都会重新运行那个函数。

session 变量的一个用途可以是维护我们应用的全局状态，例如，检查用户是否显示侧边栏。

session 对象对于模板和其他应用部分之间的简单数据通信并不有用，因为维护这会很快变得令人痛苦，并且可能发生命名冲突。

## 实现简单反应性的更好方法

如果我们想要用于应用内通信，最好使用 Meteor 的`reactive-var`包，它带有一个类似于`ReactiveVar`对象的`Session`。

使用它时，我们可以简单地通过`$ meteor add reactive-var`来添加它。

然后需要实例化这个对象，并带有反应式的`get()`和`set()`函数，类似于`session`对象：

```js
Var myReactiveVar = new ReactiveVar('my initial value');

// now we can get it in any reactive function
myReactiveVar.get();

// and set it, to rerun depending functions
myReactiveVar.set('my new value');
```

为了实现更自定义的反应性，我们可以使用 Meteor 的`Tracker`包构建我们自己的自定义反应式对象。有关更多信息，请参阅第九章，*高级反应性*。

### 提示

对于与特定模板实例绑定的反应式变量，请查看我的`frozeman:template-var`包在[`atmospherejs.com/frozeman/template-var`](https://atmospherejs.com/frozeman/template-var)。

# 在模板助手使用 session

由于所有模板助手函数都是反应式函数，因此在这样的助手内部使用 session 对象是一个好地方。

反应式意味着当我们在这个函数内部使用反应式对象时，该函数会在反应式对象发生变化时重新运行，同时重新渲染模板的这部分。

### 注意

模板助手不是唯一的反应式函数；我们还可以使用`Tracker.autorun(function(){…})`创建自己的，正如我们早先章节中看到的那样。

为了展示在模板助手中美使用会话的方法，请执行以下步骤：

1.  打开我们的`my-meteor-blog/client/templates/home.js`文件，并在文件中的任何位置添加以下助手代码：

    ```js
    Template.home.helpers({
      //...
      sessionExample: function(){
        return Session.get('mySessionExample');
      }
    });
    ```

    这创建了`sessionExample`助手，它返回`mySessionExample`会话变量的值。

1.  接下来，我们需要把我们这个助手添加到我们的`home`模板本身，通过打开`my-metepr-blog/client/templates/home.html`文件，在我们`{{#each postsList}}`块助手上面加上助手：

    ```js
    <h2>This comes from our Session: <strong>{{sessionExample}}</strong></h2>
    ```

1.  现在，打开浏览器窗口，输入`http://localhost:3000`。我们会看到我们添加的静态文本出现在博客的主页上。然而，为了看到 Meteor 的反应式会话在起作用，我们需要打开浏览器的控制台并输入以下代码行：

    ```js
    Session.set('mySessionExample', 'I just set this.');
    ```

    以下屏幕截图说明了这一点：

    ![在模板助手中美使用会话](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00017.jpeg)

在我们按下*Enter*键的那一刻，我们就看到了文字被添加到了我们的模板中。这是因为当我们调用`Session.set('mySessionExample', ...)`时，Meteor 会在我们之前调用`Session.get('mySessionExample')`的每个反应式函数中重新运行。对于模板助手，这只会重新运行这个特定的模板助手，只重新渲染模板的这部分。

我们可以通过为`mySessionExample`会话变量设置不同的值来尝试，这样我们就可以看到文字如何随时变化。

## 会话和热代码推送

热代码推送是指当我们更改文件时，Meteor 服务器将这些更改推送到客户端。Meteor 足够智能，可以重新加载页面，而不会丢失 HTML 表单或会话的值。因此，会话可以用来在热代码推送过程中保持用户状态的一致性。

为了看到这一点，我们将`mySessionExample`的值设置为我们想要的任何东西，并看到网站更新为此值。

现在，我们打开我们的`home.html`文件，进行一点小修改，例如移除`{{sessionExample}}`助手周围的`<strong>`标签并保存文件，我们会发现尽管页面随着新更改的模板重新加载，我们的会话状态仍然保持。这在以下屏幕截图中得到证明：

![会话和热代码推送](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00018.jpeg)

### 注意

如果我们手动使用浏览器的刷新按钮重新加载页面，会话将无法保持更改，文字将消失。

为了克服这个限制，Meteor 的包仓库中有许多包，它们反应式地将数据存储在浏览器的本地存储中，以在页面重新加载时保持数据。其中一个包叫做`persistent-session`，可以在[`atmospherejs.com/package/persistent-session`](http://atmospherejs.com/package/persistent-session)找到。

# 反应性地重新运行函数

为了根据会话更改重新运行函数，Meteor 提供了`Tracker.autorun()`函数，我们之前用它来改变懒加载订阅。

`Tracker.autorun()`函数将使传递给它的每个函数都具有反应性。为了看到一个简单的例子，我们将创建一个函数，每次函数重新运行时都会警告一个文本。

### 注意

`Tracker`包是会话在幕后使用的东西，以使反应性工作。在第九章，*高级反应性*，我们将深入研究这个包。

执行以下步骤以反应性地重新运行函数：

1.  让我们创建一个名为`main.js`的新文件，但这次在`my-meteor-blog`目录的根目录中，内容如下：

    ```js
    if(Meteor.isClient) {

        Tracker.autorun(function(){
            var example = Session.get('mySessionExample'); 
            alert(example);
        });
    }
    ```

    ### 注意

    在后面的章节中我们将会需要`main.js`文件。因此，我们在根目录中创建了它，使其可以在客户端和服务器上访问。

    然而，由于 Meteor 的 session 对象只存在于客户端，我们将使用`if(Meteor.isClient)`条件，以便只在客户端执行代码。

    现在当我们查看浏览器时，我们会看到一个显示`undefined`的警告。这是因为传递给`Tracker.autorun()`的函数在代码执行时也会运行，在这个时候我们还没有设置我们的会话。

1.  要设置会话变量的默认值，我们可以使用`Session.setDefault('mySessionExample', 'My Text')`。这将在不运行任何反应性函数的情况下设置会话，当会话值未定义时。如果会话变量的值已经设置，`setDefault`将根本不会更改变量。

1.  在我们的示例中，当页面加载时我们可能不希望出现一个警告窗口。为了防止这种情况，我们可以使用`Tracker.Computation`对象，它作为我们函数的第一个参数传递给我们，并为我们提供了一个名为`firstRun`的属性。这个属性将在函数的第一次运行时设置为`true`。当我们使用这个属性时，我们可以在开始时防止显示警告：

    ```js
    Tracker.autorun(function(c){
        var example = Session.get('mySessionExample'); 

        if(!c.firstRun) {
            alert(example);
        }
    });
    ```

1.  现在让我们打开浏览器的控制台，将会话设置为任何值以查看警告窗口出现：

    ```js
    Session.set('mySessionExample','Hi there!');
    ```

此代码的输出在下方的屏幕截图中展示：

![反应性地重新运行函数](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00019.jpeg)

### 注意

当我们再次运行相同的命令时，我们不会看到警告窗口出现，因为 Meteor 足够智能，可以防止在会话值不变时重新运行。如果我们将其设置为另一个值，警告将再次出现。

## 停止反应式函数

作为第一个参数传递的`Tracker.Computation`对象还为我们提供了一种完全停止函数反应性的方法。为了尝试这个，我们将更改函数，使其在我们传递`stop`字符串给会话时停止其反应性：

```js
Tracker.autorun(function(c){
    var example = Session.get('mySessionExample'); 

    if(!c.firstRun) {
        if(Session.equals('mySessionExample', 'stop')) {
            alert('We stopped our reactive Function');
            c.stop();
        } else {
            alert(example);
        }
    }
});
```

现在，当我们进入浏览器的控制台并运行`Session.set('mySessionExample', 'stop')`时，响应式函数将停止变得响应式。为了测试这一点，我们可以尝试运行`Session.set('mySessionExample', 'Another text')`，我们会发现警告窗口不会出现。

### 注意

如果我们对代码进行更改并且发生了热代码重载，响应式函数将再次变为响应式，因为代码被执行了 again。

前面的示例还使用了一个名为`Session.equals()`的函数。这个函数可以比较两个标量值，同时防止不必要的重新计算，与使用`Session.get('mySessionExample) === 'stop'`相比。使用`Session.equals()`只有在会话变量改变*到*或*从*那个值时才会重新运行这个函数。

### 注意

在我们的示例中，然而，这个函数并没有什么区别，因为我们之前也调用了`Session.get()`。

# 在模板中使用 autorun

虽然在某些情况下在我们的应用程序中全局使用`Tracker.autorun()`可能很有用，但随着我们应用程序的增长，这些全局响应式函数很快变得难以维护。

因此，将响应式函数绑定到它们执行操作的模板是一个好的实践。

幸运的是，Meteor 提供了一个特殊的`Tracker.autorun()`版本，它与模板实例相关联，并在模板被销毁时自动停止。

为了利用这一点，我们可以在`created()`或渲染回调中启动响应式函数。首先，让我们注释掉`main.js`文件中的上一个示例，这样我们就不会得到两个警告窗口。

打开我们的`home.js`文件，添加以下代码行：

```js
Template.home.created = function(){

    this.autorun(function(){
        alert(Session.get('mySessionExample'));
    });
};
```

这将在主页模板创建时创建响应式函数。当我们进入浏览器的控制台并设置`mySessionExample`会话为新值时，我们会看到警告窗口出现，如下面的屏幕截图所示：

![在模板中使用 autorun](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00020.jpeg)

现在，当我们通过点击菜单中的**关于**链接切换模板，并将`mySessionExample`会话变量再次设置为另一个值时，我们不会看到警告窗口出现，因为当模板被销毁时，响应式的`this.autorun()`已经停止。

### 注意

注意所有的`Tracker.autorun()`函数都返回一个`Tracker.Computation`对象，可以使用`Tracker.Computation.stop()`随时停止 autorun 的响应性：

```js
Var myReactiveFunction = Tracker.autorun(function(){...});
// Do something which needs to stop the autorun
myReactiveFunction.stop();
```

# 响应式的会话对象

我们看到了会话对象可以在其值改变时重新运行函数。这和集合的`find()`和`findOne()`函数的行为一样，这些函数在集合的底层数据改变时会重新运行函数。

我们可以使用会话来在热代码推送之间保持用户状态，比如下拉菜单或弹出的状态。但是，请注意，如果没有明确的命名约定，这些会话变量很快就会变得难以维护。

为了实现更具体的反应式行为，最好使用 Meteor 的`Tracker`核心包构建一个自定义的反应式对象，这将在第九章，*高级反应性*中介绍。

# 总结

在本章中，我们了解了 Meteor 的反应式会话对象能做什么。我们用它来重新运行模板助手和我们自己的自定义函数，并且我们通过`created()`和`destroyed()`回调创建了一个特定的反应式函数模板。

要深入了解，请查看 Meteor 关于会话和反应性的文档，具体资源如下：

+   [Meteor 的反应性](https://docs.meteor.com/#/full/reactivity)

+   [Meteor 的反应式会话对象](https://docs.meteor.com/#/full/session)

+   [Meteor 的反应式变量包](https://docs.meteor.com/#/full/reactivevar_pkg)

+   [Meteor 的 Tracker](https://www.meteor.com/tracker)

你可以在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)找到本章的代码示例，或者在 GitHub 上查看[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter6`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter6)。

在下一章中，我们将为我们的博客创建管理员用户和后端，为创建和编辑帖子打下基础。


# 第七章：用户和权限

通过对前一章的内容进行操作，我们应该现在有一个运行中的博客了。我们可以点击所有的链接和帖子，甚至可以延迟加载更多的帖子。

在本章中，我们将添加我们的后端登录并创建管理员用户。我们还将创建一个编辑帖子的模板，并使管理员用户能够看到编辑按钮，以便他们可以编辑和添加新内容。

在本章中，我们将学习以下概念：

+   Meteor 的 `accounts` 包

+   创建用户和登录

+   如何限制某些路由仅供已登录用户使用

    ### 注意

    你可以删除前一章中的所有会话示例，因为我们在推进应用时不需要它们。从 `my-meteor-blog/main.js`、`my-meteor-blog/client/templates/home.js` 和 `my-meteor-blog/client/templates/home.html` 中删除会话的代码，或者下载前一章代码的新副本。

    如果你直接跳到这一章并且想跟随示例，可以从以下网址下载前一章的代码示例：[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或从 GitHub 仓库 [`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter6`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter6) 下载。

    这些代码示例还将包含所有的样式文件，所以我们不需要在过程中添加 CSS 代码。

# Meteor 的 accounts 包

Meteor 使得通过其 `accounts` 包向我们的网络应用添加身份验证变得非常容易。`accounts` 包是一个与 Meteor 的核心紧密相连的完整的登录解决方案。创建的用户可以在许多 Meteor 的服务器端函数中通过 ID 进行识别，例如，在一个出版物中：

```js
Meteor.publish("examplePublication", function () {
  // the current loggedin user id can be accessed via
  this.userId;
}
```

此外，我们还可以通过简单地添加一个或多个 `accounts-*` 核心包来添加通过 Facebook、GitHub、Google、Twitter、Meetup 和 Weibo 登录的支持。

Meteor 还提供了一个简单的登录界面，一个可以通过使用 `{{> loginButtons}}` 助手添加的额外模板。

所有注册的用户资料都将存储在一个名为 `Users` 的集合中，Meteor 为我们创建了这个集合。所有的认证过程和通信过程都使用 **Secure Remote Password** (**SRP**) 协议，大多数外部服务都使用 OAuth。

对于我们的博客，我们只需创建一个管理员用户，当登录后，他们可以创建和编辑帖子。

### 注意

如果我们想要使用第三方服务之一进行登录，我们可以先完成本章的内容，然后添加前面提到的其中一个包。

添加额外包后，我们可以打开 **登录** 表单。我们将看到一个按钮，我们可以配置第三方服务以供我们的应用使用。

# 添加 accounts 包

要开始使用登录系统，我们需要将 `accounts-ui` 和 `accounts-password` 包添加到我们的应用中，如下所示：

1.  为了做到这一点，我们打开终端，导航到我们的`my-meteor-blog`文件夹，并输入以下命令：

    ```js
    $ meteor add accounts-ui accounts-password

    ```

1.  在我们成功添加包之后，我们可以使用`meteor`命令再次运行我们的应用程序。

1.  因为我们想要阻止我们的访客创建额外的用户账户，所以我们需要在我们的`accounts`包中禁止这个功能。首先，我们需要打开我们在前一章节中创建的`my-meteor-blog/main.js`文件，并删除所有代码，因为我们不再需要会话示例。

1.  然后在这个文件中添加以下代码行，但一定要确保不要使用`if(Meteor.isClient)`，因为这次我们希望在客户端和服务器上都执行代码：

    ```js
    Accounts.config({
        forbidClientAccountCreation: true
    });
    ```

    这将禁止在客户端调用`Accounts.createUser()`，并且`accounts-ui`包将不会向我们的访客显示**注册**按钮。

    ### 注意

    这个选项似乎对第三方服务不起作用。所以，当使用第三方服务时，每个人都可以注册并编辑文章。为了防止这种情况，我们将在服务器端创建“拒绝”规则以禁止用户创建，这超出了本章节的范围。

# 为我们的模板添加管理功能

允许编辑我们文章的最佳方式是在我们文章的页面上添加一个**编辑文章**链接，这个链接只有在登录后才能看到。这样，我们节省了为另一个后端重建类似基础设施的工作，并且使用起来很方便，因为前端和后端之间没有严格的分离。

首先，我们将向我们的`home`模板添加一个**创建新文章**链接，然后将**编辑文章**链接添加到文章的`pages`模板中，最后在主菜单中添加登录按钮和表单。

## 添加新文章的链接

让我们先添加一个**创建新文章**链接。打开`my-meteor-blog/clients/templates/home.html`中的`home`模板，并在`{{#each postsList}}`块助手之上添加以下代码行：

```js
{{#if currentUser}}
    <a href="/create-post" class="createNewPost">Create new post</a>
{{/if}}
```

`{{currentUser}}`助手随`accounts-base`包一起提供，当我们安装我们的`accounts`包时安装了它。它会返回当前登录的用户，如果没有用户登录，则返回 null。将其用于`{{#if}}`块助手内部允许我们只向登录用户显示内容。

## 添加编辑文章的链接

要编辑文章，我们只需在我们的`post`模板中添加一个**编辑文章**链接。打开同一文件夹中的`post.html`，并在`{{author}}`之后添加`{{#if currentUser}}..{{/if}}`，如下所示：

```js
<small>
    Posted {{formatTime timeCreated "fromNow"}} by {{author}}

    {{#if currentUser}}
        | <a href="/edit-post/{{slug}}">Edit post</a>
    {{/if}}
</small>
```

## 添加登录表单

现在我们已经有了添加和编辑文章的链接，让我们添加登录表单。我们可以创建自己的表单，但 Meteor 已经包含了一个简单的登录表单，我们可以将其样式修改以符合我们的设计。

由于我们之前添加了`accounts-ui`包，Meteor 为我们提供了`{{> loginButtons}}`模板助手，它作为一个即插即用的模板工作。为了添加这个功能，我们将打开我们的`layout.html`模板，并在菜单的`<ul></ul>`标签内添加以下助手，如下所示：

```js
<h1>My Meteor Single Page App</h1>
<ul>
    <li>
        <a href="/">Home</a>
    </li>
    <li>
        <a href="/about">About</a>
    </li>

</ul>

{{> loginButtons}}

```

# 创建编辑文章的模板

现在我们只缺少编辑帖子的模板。为了添加这个模板，我们将在`my-meteor-blog/client/templates`文件夹中创建一个名为`editPost.html`的文件，并填入以下代码行：

```js
<template name="editPost">
  <div class="editPost">
     <form>
        <label>
          Title
          <input type="text" name="title" placeholder="Awesome title" value="{{title}}">
        </label>

        <label>
          Description
          <textarea name="description" placeholder="Short description displayed in posts list" rows="3">{{description}}</textarea>
        </label>

        <label>
          Content
          <textarea name="text" rows="10" placeholder="Brilliant content">{{text}}</textarea>
        </label>

        <button type="submit" class="save">Save Post</button>
    </form>
  </div>
</template>
```

正如我们所看到的，我们添加了`{{title}}`、`{{description}}`和`{{text}}`帮助器，这些将从帖子数据中稍后获取。这个简单的模板，带有它的三个文本字段，将允许我们以后编辑和创建新帖子。

如果我们现在查看浏览器，我们会注意到我们看不到到目前为止所做的任何更改，除了网站角落里的**登录**链接。为了能够登录，我们首先需要添加我们的管理员用户。

# 创建管理员用户

由于我们已禁用客户端创建用户，作为一种安全措施，我们将在服务器上以创建示例帖子的方式创建管理员用户。

打开`my-meteor-blog/server/main.js`文件，在`Meteor.startup(function(){...})`内的某个位置添加以下代码行：

```js
if(Meteor.users.find().count() === 0) {

    console.log('Created Admin user');

    Accounts.createUser({
        username: 'johndoe',
        email: 'johndoe@example.com',
        password: '1234',
        profile: {
            name: 'John Doe'
        }
    });
}
```

如果我们现在打开浏览器，我们应该能够使用我们刚才创建的用户登录，我们会立即看到所有编辑链接出现。

然而，当我们点击任何编辑链接时，我们会看到`notFound`模板出现，因为我们还没有创建任何管理员路由。

## 添加权限

Meteor 的`account`包默认并不带有对用户可配置权限的支持。

为了添加权限控制，我们可以添加第三方包，比如`deepwell:authorization`包，可以在 Atmosphere 上找到，网址为[`atmospherejs.com/deepwell/authorization`](http://atmospherejs.com/deepwell/authorization)，它带有复杂的角色模型。

如果我们想手动完成，我们可以在创建用户时向用户文档添加简单的`roles`属性，然后在创建或更新帖子时在允许/拒绝角色中检查这些角色。我们将在下一章学习允许/拒绝规则。

如果我们使用`Accounts.createUser()`函数创建用户，我们就不能添加自定义属性，因此我们需要在创建用户后更新用户文档，如下所示：

```js
var userId = Accounts.createUser({
  username: 'johndoe',
  email: 'johndoe@example.com',
  password: '1234',
  profile: {
    name: 'John Doe'
  }
});
// add the roles to our user
Meteor.users.update(userId, {$set: {
  roles: {admin: true},
}})
```

默认情况下，Meteor 会发布当前登录用户`username`、`emails`和`profile`属性。要添加其他属性，比如我们的自定义`roles`属性，我们需要添加一个发布功能，以便在客户端访问`roles`属性，如下所示：

1.  打开`my-meteor/blog/server/publications.js`文件，添加以下发布功能：

    ```js
    Meteor.publish("userRoles", function () {
     if (this.userId) {
      return Meteor.users.find({_id: this.userId}, {fields: {roles: 1}});
     } else {
      this.ready();
     }
    });
    ```

1.  在`my-meteor-blog/main.js`文件中，我们像下面这样添加订阅：

    ```js
    if(Meteor.isClient){
      Meteor.subscribe("userRoles");
    }
    ```

1.  现在既然我们在客户端已经有了`roles`属性，我们可以把`home`和`post`模板中的`{{#if currentUser}}..{{/if}}`改为`{{#if currentUser.roles.admin}}..{{/if}}`，这样只有管理员才能看到按钮。

## 有关安全性的说明

用户只能使用以下命令更新自己的`profile`属性：

```js
Meteor.users.update(ownUserId, {$set: {profiles:{myProperty: 'xyz'}}})

```

如果我们想要更新`roles`属性，我们将失败。为了看到这一点，我们可以打开浏览器的控制台并输入以下命令：

```js
Meteor.users.update(Meteor.user()._id, {$set:{ roles: {admin: false}}});

```

这将给我们一个错误，指出：**更新失败：拒绝访问**，如下面的屏幕截图所示：

![关于安全性的说明](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00021.jpeg)

### 注意

如果我们想要允许用户编辑其他属性，例如他们的`roles`属性，我们需要为此添加一个`Meteor.users.allow()`规则。

# 为管理员创建路由

现在我们已经有了一个管理员用户，我们可以添加那些指向`editPost`模板的路由。尽管从理论上讲`editPost`模板对每个客户端都是可用的，但它不会造成任何风险，因为允许和拒绝规则才是真正的安全层，我们将在下一章中查看这些规则。

要添加创建文章的路由，让我们打开我们的`my-meteor-blog/routes.js`文件，并向`Router.map()`函数添加以下路由：

```js
this.route('Create Post', {
    path: '/create-post',
    template: 'editPost'
});
```

这将在我们点击主页上的**创建新文章**链接后立即显示`editPost`模板，如下面的屏幕截图所示：

![为管理员创建路由](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00022.jpeg)

我们发现表单是空的，因为我们没有为模板设置任何数据上下文，因此模板中显示的`{{title}}`、`{{description}}`和`{{text}}`占位符都是空的。

为了使编辑文章的路由工作，我们需要添加类似于为`Post`路由本身所做的订阅。为了保持事物的**DRY**（这意味着**不要重复自己**），我们可以创建一个自定义控制器，这个控制器将被两个路由使用，如下所示：

1.  在`Router.configure(...);`调用之后添加以下代码行：

    ```js
    PostController = RouteController.extend({
        waitOn: function() {
            return Meteor.subscribe('single-post', this.params.slug);
        },

        data: function() {
            return Posts.findOne({slug: this.params.slug});
        }
    });
    ```

1.  现在我们可以简单地编辑`Post`路由，删除`waitOn()`和`data()`函数，并添加`PostController`：

    ```js
    this.route('Post', {
        path: '/posts/:slug',
        template: 'post',
        controller: 'PostController'
    });
    ```

1.  现在我们还可以通过简单地更改`path`和`template`属性来添加`编辑文章`路由：

    ```js
    this.route('Edit Post', {
        path: '/edit-post/:slug',
        template: 'editPost',
        controller: 'PostController'
    });
    ```

1.  这就完成了！现在当我们打开浏览器时，我们将能够访问任何文章并点击**编辑**按钮，然后我们将被引导到`editPost`模板。

如果您想知道为什么表单会填充文章数据，请查看我们刚刚创建的`PostController`。在这里，我们在`data()`函数中返回文章文档，将模板的数据上下文设置为文章的数据。

现在我们已经设置了这些路由，我们应该完成了。难道不是吗？

还不是，因为任何知道`/create-post`和`/edit-post/my-title`路由的人都可以简单地看到`editPost`模板，即使他或她不是管理员。

## 防止访客看到管理路由

```js
routes.js file:
```

```js
var requiresLogin = function(){
    if (!Meteor.user() ||
        !Meteor.user().roles ||
        !Meteor.user().roles.admin) {
        this.render('notFound');

    } else {
        this.next();
    }
}; 

Router.onBeforeAction(requiresLogin, {only: ['Create Post','Edit Post']});
```

在这里，首先我们创建了`requiresLogin()`函数，它将在`创建文章`和`编辑文章`路由之前执行，因为我们将其作为第二个参数传递给`Router.onBeforeAction()`函数。

在`requiresLogin()`内部，我们检查用户是否已登录，当调用`Meteor.user()`时，这将返回用户文档，并且检查他们是否有`admin`角色。如果没有，我们简单地渲染`notFound`模板，并不再继续路由。否则，我们运行`this.next()`，这将继续渲染当前路由。

就这样！如果我们现在登出并导航到`/create-post`路由，我们将看到`notfound`模板。

如果我们登录，模板将切换并立即显示`editPost`模板。

这是因为一旦我们将`requiresLogin()`函数传递给`Router.onBeforeAction()`，它就会变得具有反应性，而`Meteor.user()`是一个反应式对象，所以用户状态的任何变化都会重新运行这个函数。

现在我们已经创建了管理员用户和所需的模板，我们可以继续实际创建和编辑帖子。

# 总结

在本章中，我们学习了如何创建和登录用户，如何仅向已登录用户显示内容和模板，以及如何根据登录状态更改路由。

要了解更多，请查看以下链接：

+   在[`www.meteor.com/accounts`](https://www.meteor.com/accounts)

+   在[`docs.meteor.com/#/full/accounts_api`](https://docs.meteor.com/#/full/accounts_api)

+   在[`docs.meteor.com/#/full/meteor_users`](https://docs.meteor.com/#/full/meteor_users)

+   [`en.wikipedia.org/wiki/Secure_Remote_Password_protocol`](http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)

+   [`github.com/EventedMind/iron-router/blob/devel/Guide.md#using-hooks`](https://github.com/EventedMind/iron-router/blob/devel/Guide.md#using-hooks)

您可以在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或 GitHub 上的[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter7`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter7)找到本章的代码示例。

在下一章中，我们将学习如何创建和更新帖子以及如何从客户端控制数据库的更新。


# 第八章：使用允许和拒绝规则进行安全设置

在前一章中，我们创建了我们的管理员用户并准备了`editPost`模板。在本章中，我们将使这个模板工作，以便我们可以使用它创建和编辑帖子。

为了使插入和更新数据库中的文档成为可能，我们需要设置约束，使不是每个人都可以更改我们的数据库。在 Meteor 中，这是使用允许和拒绝规则完成的。这些函数将在文档被插入数据库前检查它们。

在本章中，您将涵盖以下主题：

+   添加和更新帖子

+   使用允许和拒绝规则来控制数据库的更新

+   在服务器上使用方法以获得更多灵活性

+   使用方法桩来增强用户体验

    ### 注意

    如果您直接跳到这一章节并希望跟随示例，请从书籍的网页[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或 GitHub 仓库[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter7`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter7)下载前一章节的代码示例。

    这些代码示例还将包含所有的样式文件，所以我们不需要担心在过程中添加 CSS 代码。

# 添加一个生成 slug 的函数

为了从我们的帖子标题生成 slugs，我们将使用带有简单`slugify()`函数的`underscore-string`库。幸运的是，这个库的一个包装包已经在 Meteor 包服务器上存在。要添加它，我们请在终端中运行以下命令，位于我们的`my-meteor-blog`文件夹中：

```js
$ meteor add wizonesolutions:underscore-string

```

这将使用默认在 Meteor 中使用的`underscore`扩展一些额外的字符串函数，如`_.slugify()`，从字符串生成一个 slug。

# 创建新帖子

现在我们已经可以为每个创建的页面生成 slugs，我们可以继续将保存过程添加到`editPost`模板中。

为此，我们需要为我们的`editPost`模板创建一个 JavaScript 文件，通过将一个名为`editPost.js`的文件保存到`my-meteor-blog/client/templates`文件夹中来实现。在这个文件中，我们将为模板的**保存**按钮添加一个事件：

```js
Template.editPost.events({
  'submit form': function(e, template){
    e.preventDefault();
    console.log('Post saved');
  }
});
```

现在，如果我们前往`/create-post`路由并点击**保存帖子**按钮，**帖子已保存**日志应该在浏览器控制台中出现。

## 保存帖子

为了保存帖子，我们只需取表单的内容并将其存储在数据库中。稍后，我们将重定向到新创建的帖子页面。为此，我们将我们的点击事件扩展为以下几行代码：

```js
Template.editPost.events({
  'submit form': function(e, tmpl){
    e.preventDefault();
    var form = e.target,
        user = Meteor.user();
```

我们获取当前用户，以便稍后将其作为帖子的作者添加。然后使用我们的`slugify()`函数从帖子标题生成一个 slug：

```js
        var slug = _.slugify(form.title.value);
```

接着，我们使用所有其他表单字段将帖子文档插入到`Posts`集合中。对于`timeCreated`属性，我们使用在第一章，*Meteor 入门*中添加的`moment`包获取当前的 Unix 时间戳。

`owner`字段将帮助我们确定是由哪个用户创建了此帖子：

```js
Posts.insert({
            title:          form.title.value,
            slug:           slug,
            description:    form.description.value,
            text:           form.text.value,
            timeCreated:    moment().unix(),
            author:         user.profile.name,
            owner:          user._id

        }, function(error) {
            if(error) {
                // display the error to the user
                alert(error.reason);
            } else {
                // Redirect to the post
                Router.go('Post', {slug: slug});
            }
        });
    }
});
```

我们传递给`insert()`函数的第二个参数是一个由 Meteor 提供的回调函数，如果出错，它将接收到一个错误参数。如果发生错误，我们警告它，如果一切顺利，我们使用生成的 slug 将用户重定向到新插入的帖子。

由于我们的路由控制器将会订阅这个 slug 的帖子，它将能够加载我们新创建的帖子并在帖子模板中显示它。

现在，如果我们打开浏览器，填写表单，并点击**保存**按钮，我们应该已经创建了我们的第一个帖子！

# 编辑帖子

所以保存是可行的。编辑呢？

当我们点击帖子中的**编辑**按钮时，我们将再次显示`editPost`模板。这次，表单字段填充了帖子的数据。到目前为止还不错，但如果我们现在点击**保存**按钮，我们将创建另一个帖子，而不是更新当前帖子。

## 更新当前帖子

由于我们设置了`editPost`模板的数据上下文，我们可以简单地使用帖子`_id`字段的存在作为更新的指示器，而不是插入帖子数据：

```js
Template.editPost.events({
    'submit form': function(e, tmpl){
        e.preventDefault();
        var form = e.target,
            user = Meteor.user(),
            _this = this; // we need this to reference the slug in the callback

        // Edit the post
        if(this._id) {

            Posts.update(this._id, {$set: {
                title:          form.title.value,
                description:    form.description.value,
                text:           form.text.value

            }}, function(error) {
                if(error) {
                    // display the error to the user
                    alert(error.reason);
                } else {
                    // Redirect to the post
                    Router.go('Post', {slug: _this.slug});
                }
            });

        // SAVE
        } else {

            // The insertion process ...

        }
    }
});
```

知道了`_id`，我们可以简单地使用`$set`属性来更新当前文档。使用`$set`只会覆盖`title`、`description`和`text`字段。其他字段将保持原样。

请注意，我们现在还需要在函数顶部创建`_this`变量，以便在回调 later 中访问当前数据上下文的`slug`属性。这样，我们稍后可以将用户重定向到我们编辑的帖子页面。

现在，如果我们保存文件并回到浏览器，我们可以编辑帖子并点击**保存**，所有更改都将如预期般保存到我们的数据库中。

现在，我们可以创建和编辑帖子。在下一节中，我们将学习如何通过添加允许和拒绝规则来限制对数据库的更新。

# 限制数据库更新

到目前为止，我们只是将插入和更新功能添加到了我们的`editPost`模板中。然而，如果有人在他们浏览器的控制台输入一个`insert`语句，任何人都可以插入和更新数据。

为了防止这种情况，我们需要在服务器端正确检查插入和更新权限，然后再更新数据库。

Meteor 的集合带有允许和拒绝函数，这些函数在每次插入或更新之前运行，以确定该操作是否被允许。

允许规则让我们允许某些文档或字段被更新，而拒绝规则覆盖任何允许规则，并肯定地拒绝对其集合的任何操作。

为了使这更加明显，让我们想象一个例子，我们定义了两个允许规则；其中一个将允许某些文档的`title`字段被更改，另一个只允许编辑`description`字段，但还有一个额外的拒绝规则可以防止某个特定文档在任何情况下被编辑。

## 删除不安全的包

为了开始使用允许和拒绝规则，我们需要从我们的应用程序中删除`insecure`包，这样客户端就不能简单地不通过我们的允许和拒绝规则就对我们的数据库进行更改。

使用终端中的*Ctrl* + *C* 停止运行中的`meteor`实例，并运行以下命令：

```js
$ meteor remove insecure

```

成功删除包后，我们可以使用`meteor`命令再次运行 Meteor。

当我们现在打开浏览器尝试编辑任何帖子时，我们将看到一个提示窗口，显示**访问被拒绝**。记得我们之前在更新或插入操作失败时添加了这个`alert()`调用吗？

## 添加我们的第一个允许规则

为了使我们的帖子再次可编辑，我们需要添加允许规则以重新启用数据库更新。

为此，我们将在我们的`my-meteor-blog/collections.js`文件中添加以下允许规则，但在这个例子中，我们通过检查 Meteor 的`isServer`变量，使它们只在服务器端执行：

```js
if(Meteor.isServer) {

    Posts.allow({
        insert: function (userId, doc) {
            // The user must be logged in, and the document must be owned by the user
            return userId && doc.owner === userId && Meteor.user().roles.admin;
        },
```

在插入*允许*规则中，我们只会在帖子所有者与当前用户匹配时插入文档，如果用户是管理员，我们可以在上一章中添加的`roles.admin`属性来确定。

如果允许规则返回`false`，将拒绝文档的插入。否则，我们将成功添加一个新帖子。更新也是一样，只是我们只检查当前用户是否是管理员：

```js
        update: function (userId, doc, fields, modifier) {
            // User must be an admin
            return Meteor.user().roles.admin;
        },
        // make sure we only get this field from the documents
        fetch: ['owner']
    });
}
```

传递给`update`函数的参数如下表所示：

| ```Field``` | 描述 |
| --- | --- |
| ```---``` | ```---``` |
| ```userId``` | 执行`update`操作的当前登录用户的用户 ID |
| ```doc``` | 数据库中的文档，不包括拟议的更改 |
| ```fields``` | 包含将要更新的字段参数的数组 |
| ```modifier``` | 用户传递给`update`函数的修改器，例如`{$set: {'name.first': "Alice"}, $inc: {score: 1}}` |

我们最后在允许规则的对象中指定的`fetch`属性，决定了当前文档的哪些字段应该传递给更新规则。在我们这个例子中，我们只需要`owner`属性用于我们的更新规则。`fetch`属性存在是为了性能原因，以防止不必要的巨大文档被传递到规则函数中。

### 注意

此外，我们可以指定`remove()`规则和`transform()`函数。`remove()`规则将获得与`insert()`规则相同的参数，并允许或阻止文档的删除。

`transform()`函数可以用来在传递给允许或拒绝规则之前转换文档，例如，使其规范化。然而，要注意的是，这不会改变插入数据库的文档。

现在如果我们尝试在我们的网站上编辑一个帖子，我们应该能够编辑所有帖子以及创建新的帖子。

# 添加拒绝规则

为了提高安全性，我们可以修复帖子的所有者和创建时间。我们可以通过向我们的`Posts`集合中添加一个额外的拒绝规则来防止对所有者以及`timeCreated`和`slug`字段的更改，如下所示：

```js
if(Meteor.isServer) {

  // Allow rules

  Posts.deny({
    update: function (userId, docs, fields, modifier) {
      // Can't change owners, timeCreated and slug
      return _.contains(fields, 'owner') || _.contains(fields, 'timeCreated') || _.contains(fields, 'slug');
    }
  });
}
```

这个规则将简单地检查`fields`参数是否包含受限制的字段之一。如果包含，我们就拒绝更新这篇帖子。所以，即使我们之前的允许规则已经通过，我们的拒绝规则也确保了文档不会发生变化。

我们可以在浏览器的控制台中尝试拒绝规则，当我们处于一个帖子页面时，输入以下命令：

```js
Posts.update(Posts.findOne()._id, {$set: {'slug':'test'}}); 

```

这应该会给你一个错误，提示**更新失败：访问被拒绝**，如下面的截图所示：

![添加拒绝规则](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00023.jpeg)

虽然我们现在可以添加和更新帖子，但还有一种比简单地将它们从客户端插入到我们的`Posts`集合中更好的添加新帖子的方法。

# 使用方法调用来添加帖子

方法是可以在客户端调用并在服务器上执行的函数。

## 方法存根和延迟补偿

方法的优势在于它们可以在服务器上执行代码，同时拥有完整的数据库和客户端上的存根方法。

例如，我们可以有一个方法在服务器上执行某些操作，并在客户端的存根方法中模拟预期的结果。这样，用户不必等待服务器的响应。存根还可以调用界面更改，例如添加一个加载指示器。

一个原生方法调用的例子是 Meteor 的`Collection.insert()`函数，它将执行客户端侧的函数，立即将文档插入到本地`minimongo`数据库中，同时发送一个请求在服务器上执行真正的`insert`方法。如果插入成功，客户端已经有了插入的文档。如果出现错误，服务器将响应并从客户端再次移除插入的文档。

在 Meteor 中，这个概念被称为**延迟补偿**，因为界面会立即对用户的响应做出反应，从而补偿延迟，而服务器的往返将在后台发生。

使用方法调用来插入帖子，使我们能够简单地检查我们想要为帖子使用的 slug 是否已经在另一篇帖子中存在。此外，我们还可以使用服务器的时间来为`timeCreated`属性确保我们没有使用错误的用户时间戳。

## 更改按钮

在我们的示例中，我们将简单地使用方法存根功能，在服务器上运行方法时将**保存**按钮的文本更改为`Saving…`。为此，执行以下步骤：

1.  首先，让我们通过模板助手更改**保存**按钮的静态文本，以便我们可以动态地更改它。打开`my-meteor-blog/client/templates/editPost.html`，用以下代码替换**保存**按钮的代码：

    ```js
    <button type="submit" class="save">{{saveButtonText}}</button>
    ```

1.  现在打开`my-meteor-blog/client/templates/editPost.js`，在文件开头添加以下模板助手函数：

    ```js
    Session.setDefault('saveButton', 'Save Post');
    Template.editPost.helpers({
      saveButtonText: function(){
        return Session.get('saveButton');
      }
    });
    ```

    在这里，我们返回名为`saveButton`的会话变量，我们之前将其设置为默认值`Save Post`。

更改会话将允许我们在保存文档的同时稍后更改**保存**按钮的文本。

## 添加方法

现在我们有了一个动态的**保存**按钮，让我们在我们的应用中添加实际的方法。为此，我们将创建一个名为`methods.js`的新文件，直接位于我们的`my-meteor-blog`文件夹中。这样，它的代码将在服务器和客户端加载，这是在客户端作为存根执行方法所必需的。

添加以下代码以添加方法：

```js
Meteor.methods({
    insertPost: function(postDocument) {

        if(this.isSimulation) {
            Session.set('saveButton', 'Saving...');
        }
    }
});
```

这将添加一个名为`insertPost`的方法。在这个方法内部，存根功能已经通过使用`isSimulation`属性添加，该属性是通过 Meteor 在函数的`this`对象中提供的。

`this`对象还具有以下属性：

+   `unblock()`：当调用此函数时，将防止该方法阻塞其他方法调用

+   `userId`：这包含当前用户的 ID

+   `setUserId()`：这个函数用于将当前客户端连接到某个用户

+   `connection`：这是通过该方法在服务器上调用的连接

如果`isSimulation`设置为`true`，该方法不会在服务器端运行，而是作为存根在客户端运行。在这个条件下，我们简单地将`saveButton`会话变量设置为`Saving…`，以便按钮文本会更改：

```js
Meteor.methods({
  insertPost: function(postDocument) {

    if(this.isSimulation) {

      Session.set('saveButton', 'Saving...');

    } else {
```

为了完成方法，我们将添加帖子插入的服务器端代码：

```js
       var user = Meteor.user();

       // ensure the user is logged in
       if (!user)
       throw new Meteor.Error(401, "You need to login to write a post");
```

在这里，我们获取当前用户以添加作者名称和所有者 ID。

如果用户没有登录，我们就抛出异常，用`new Meteor.Error`。这将阻止方法的执行并返回我们定义的错误信息。

我们还查找具有给定 slug 的帖子。如果我们找到一个，我们在 slug 前添加一个随机字符串，以防止重复。这确保了每个 slug 都是唯一的，我们可以成功路由到我们新创建的帖子：

```js
      if(Posts.findOne({slug: postDocument.slug}))
      postDocument.slug = postDocument.slug +'-'+ Math.random().toString(36).substring(3);
```

在我们插入新创建的帖子之前，我们使用`moment`库和`author`和`owner`属性添加`timeCreated`：

```js
      // add properties on the serverside
      postDocument.timeCreated = moment().unix();
      postDocument.author      = user.profile.name;
      postDocument.owner       = user._id;

      Posts.insert(postDocument);
```

在我们插入文档之后，我们返回修正后的 slug，然后在该方法调用的回调中作为第二个参数接收：

```js
       // this will be received as the second argument of the method callback
       return postDocument.slug;
    }
  }
});
```

# 调用方法

现在我们已经创建了`insertPost`方法，我们可以改变在`editPost.js`文件中之前插入帖子时的提交事件代码，用我们的方法进行调用：

```js
var slug = _.slugify(form.title.value);

Meteor.call('insertPost', {
  title:          form.title.value
  slug:           slug,
  description:    form.description.value
  text:           form.text.value,

}, function(error, slug) {
  Session.set('saveButton', 'Save Post');

  if(error) {
    return alert(error.reason);
  }

  // Here we use the (probably changed) slug from the server side method
  Router.go('Post', {slug: slug});
});
```

正如我们在方法调用的回调中看到的那样，我们使用在回调中作为第二个参数接收到的`slug`变量路由到新创建的帖子。这确保了如果`slug`变量在服务器端被修改，我们使用修改后的版本来路由到帖子。此外，我们将`saveButton`会话变量重置为将文本更改为`Save Post`。

就这样！现在，我们可以使用我们新创建的`insertPost`方法创建并保存新的帖子。然而，编辑仍然会在客户端使用`Posts.update()`进行，因为我们现在有了允许和拒绝规则，以确保只有允许的数据被修改。

# 总结

在本章中，我们学习了如何允许和拒绝数据库的更新。我们设置了自己的允许和拒绝规则，并了解了方法如何通过将敏感过程移动到服务器端来提高安全性。我们还通过检查 slug 是否已存在并在其中添加了一个简单的进度指示器来改进发帖过程。

如果您想更深入地了解允许和拒绝规则或方法，请查看以下 Meteor 文档：

+   [`docs.meteor.com/#/full/allow`](http://docs.meteor.com/#/full/allow)

+   [`docs.meteor.com/#/full/deny`](http://docs.meteor.com/#/full/deny)

+   [`docs.meteor.com/#/full/methods_header`](https://docs.meteor.com/#/full/methods_header)

您可以在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)找到本章的代码示例，或者在 GitHub 上找到[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter8`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter8)。

在下一章中，我们将通过不断更新帖子的时间戳来使我们的界面实现实时更新。


# 第九章：高级响应式

现在我们的博客基本上已经完成了，因为我们能够创建和编辑文章。在本章中，我们将利用 Meteor 的响应式模板来使我们的界面时间戳自动更新。我们将构建一个响应式对象，该对象将重新运行模板助手，显示博客文章创建的时间。这样，它们总是显示正确的相对时间。

在本章中，我们将介绍以下内容：

+   响应式编程

+   手动重新运行函数

+   使用`Tracker`包构建响应式对象

+   停止响应式函数

    ### 注意

    如果你直接跳到这一章并想跟随示例，请从以下网址下载上一章的代码示例：[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或从 GitHub 仓库：[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter8`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter8)。

    这些代码示例还将包含所有的样式文件，所以我们不需要担心在过程中添加 CSS 代码。

# 响应式编程

如我们已经在全书中看到的，Meteor 使用某种称为**响应性**的东西。

开发者在构建软件应用程序时必须解决的一个问题是指界面中表示数据的的一致性。大多数现代应用程序使用某种称为**模型-视图-控制器**（**MVC**）的东西，其中视图的控制器确保它始终表示模型的当前状态。模型通常是服务器 API 或浏览器内存中的 JSON 对象。

保持界面一致的最常见方法如下（来源：[`manual.meteor.com`](http://manual.meteor.com)）：

+   **轮询和差异**：定期（例如，每秒一次）获取事物的当前值，看看它是否发生变化，如果是，执行更新。

+   **事件**：可以变化的事物在变化时发出事件。程序的另一部分（通常称为控制器）安排监听这个事件，获取当前值，并在事件触发时执行更新。

+   **绑定**：值由实现某些接口的对象表示，例如`BindableValue`。然后，使用“绑定”方法将两个`BindableValues`连接在一起，这样当一个值发生变化时，另一个值会自动更新。有时，作为设置绑定的一部分，可以指定一个转换函数。例如，可以将`Foo`与`Bar`绑定，并使用`toUpperCase`转换函数。

这些模式很好，但它们仍然需要大量的代码来维护所表示数据的的一致性。

另一种模式，尽管还不是那么常用，那就是**响应式编程**。这种模式是一种声明式的数据绑定方式。这意味着当我们使用一个响应式数据源，如一个`Session`变量或`Mongo.Collection`时，我们可以确信，一旦其值发生变化，使用这些值的响应式函数或模板助手将重新运行，总是保持基于这些值的用户界面或计算更新。

米托尔手册为我们提供了一个响应式编程用法的实例：

> 响应式编程非常适合构建用户界面，因为它不是试图用一段统一的代码来模拟所有的交互，而是让程序员表达在特定变化发生时应该发生的事情。响应变化的范式比显式地建模哪些变化会影响程序状态更容易理解。
> 
> 例如，假设我们正在编写一个 HTML5 应用程序，有一个项目表，用户可以点击一个项目来选择它，或者按 Ctrl 点击来选择多个项目。我们可能有一个`<h1>`标签，并希望该标签的内容等于当前选定项目的大写名称，如果有多个项目被选中，则为“Multiple selection”。而且，我们可能有一组`<tr>`标签，并希望每个`<tr>`标签的 CSS 类为“selected”，如果该项目对应的行在选定项目的集合中，否则为空字符串。

为了使这个例子在上述模式中实现，我们可以很快地看到，与响应式编程相比，它变得多么复杂（来源：[`manual.meteor.com`](http://manual.meteor.com)）：

+   如果我们使用轮询和差分，UI 将会变得不可接受地卡顿。用户点击后，屏幕实际上直到下一次轮询周期才会更新。此外，我们必须存储旧的选定集合，并与新的选定集合进行差分，这有点麻烦。

+   如果我们使用事件，我们就必须编写一些相当复杂的控制器代码，手动将选择的变化或选定项目的名称映射到 UI 的更新。例如，当选择发生变化时，我们必须记住更新`<h1>`标签和（通常）两个受影响的`<tr>`标签。更重要的是，当选择发生变化时，我们必须自动在新生成的选定项目上注册一个事件处理程序，以便我们记住要更新`<h1>`。尤其是当 UI 被扩展和重新设计时，很难构建干净的代码并维护它。

+   如果我们使用绑定，我们就必须使用一个复杂的**领域特定语言**（**DSL**）来表达变量之间复杂的 relationships。这个 DSL 必须包括间接性（将`<h1>`的内容绑定到当前选择的任何固定项目的名称，而是绑定到由当前选择指示的项目）、转换（将名称首字母大写）和条件（如果有多个项目被选择，显示一个占位符字符串）。

使用米托尔的反应式模板引擎 Blaze，我们可以简单地使用`{{#each}}`块助手来遍历一个元素列表，并根据用户交互或根据项目的属性添加一些条件以添加一个选中类。

如果用户现在更改数据或从服务器接收的数据发生变化，界面将自动更新以表示相应的数据，节省我们大量时间并避免不必要的复杂代码。

## 无效化周期

理解反应式依赖的关键部分是无效化周期。

当我们在一个反应式函数中使用反应式数据源，例如`Tracker.autorun(function(){…})`，反应式数据源本身看到它在一个反应式函数中，并将当前函数作为依赖项添加到其依赖存储中。

然后，当数据源的值发生变化时，它会无效化（重新运行）所有依赖的函数，并将它们从其依赖存储中移除。

在反应式函数的重新运行中，它会将反应式函数重新添加到其依赖存储中，这样在下次无效化（值变化）时它们会再次运行。

这是理解反应性的关键，正如我们在以下示例中所看到的。

想象我们有三个`Session`变量设置为`false`：

```js
Session.set('first', false);
Session.set('second', false);
```

此外，我们还有`Tracker.autorun()`函数，它使用了这两个变量：

```js
Tracker.autorun(function(){
    console.log('Reactive function re-run');
    if(Session.get('first')){
        Session.get('second');
    }
});
```

现在我们可以调用`Session.set('second', true)`，但是反应式函数不会重新运行，因为在第一次运行中它从未被调用，因为`first`会话变量被设置为`false`。

如果我们现在调用`Session.set(first, true)`，该函数将重新运行。

此外，如果我们现在设置`Session.set('second', false)`，它也会重新运行，因为在第二次重新运行中，`Session.get('second')`可以添加这个反应式函数作为依赖项。

由于反应式数据源在每次无效化时都会从其存储中移除所有依赖项，并在反应式函数的重新运行中重新添加它们，因此我们可以设置`Session.set(first, false)`并尝试将其更改为`Session.set('second', true)`。函数将不再重新运行，因为在这个运行中从未调用过`Session.get('second')`！

一旦我们理解了这一点，我们就可以实现更细粒度的反应性，将反应式更新保持在最小。解释的控制台输出与以下屏幕截图类似：

![无效化周期](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00024.jpeg)

# 构建一个简单的反应式对象

正如我们所看到的，**反应式对象**是一个在反应式函数中使用的对象，当它的值发生变化时，它会重新运行函数。米托尔的`Session`对象是反应式对象的一个例子。

在本章中，我们将构建一个简单的反应式对象，它将在时间间隔内重新运行我们的`{{formatTime}}`模板助手，以便所有相对时间都能正确更新。

米托尔的反应性是通过`Tracker`包实现的。这个包是所有反应性的核心，允许我们跟踪依赖项并在需要时重新运行它们。

执行以下步骤以构建简单的反应式对象：

1.  让我们开始吧，让我们将以下代码添加到`my-meteor-blog/main.js`文件中：

    ```js
    if(Meteor.isClient) {
        ReactiveTimer = new Tracker.Dependency;
    }
    ```

    这将在客户端创建一个名为`ReactiveTimer`的变量，带有`Tracker.Dependency`的新实例。

1.  在`ReactiveTimer`变量下方，但仍在`if(Meteor.isClient)`条件下，我们将添加以下代码，每 10 秒重新运行一次我们`ReactiveTimer`对象的的所有依赖项：

    ```js
    Meteor.setInterval(function(){
        // re-run dependencies every 10s
        ReactiveTimer.changed();
    }, 10000);
    ```

    `Meteor.setInterval`将每 10 秒运行一次函数。

    ### 注意

    Meteor 自带了`setInterval`和`setTimeout`的实现。尽管它们与原生 JavaScript 等效，但 Meteor 需要这些来引用服务器端特定用户的确切超时/间隔。

Meteor 自带了`setInterval`和`setTimeout`的实现。尽管它们与原生 JavaScript 等效，但 Meteor 需要这些来引用服务器端特定用户的确切超时/间隔。

在这个区间内，我们调用`ReactiveTimer.changed()`。这将使每个依赖函数失效，并重新运行。

## 重新运行函数

到目前为止，我们还没有创建依赖项，所以让我们这样做。在`Meteor.setInterval`下方添加以下代码：

```js
Tracker.autorun(function(){
    ReactiveTimer.depend();
    console.log('Function re-run');
});
```

如果我们现在回到浏览器控制台，我们应该会看到每 10 秒**函数重新运行**一次，因为我们的反应式对象重新运行了函数。

我们甚至可以在浏览器控制台中调用`ReactiveTimer.changed()`，函数也会重新运行。

这些例子很好，但不会自动更新我们的时间戳。

为此，我们需要打开`my-meteor-blog/client/template-helpers.js`并在我们的`formatTime`助手函数顶部添加以下行：

```js
ReactiveTimer.depend();
```

这样，我们应用中的每个`{{formatTime}}`助手每 10 秒就会重新运行一次，更新流逝时的相对时间。要看到这一点，请打开浏览器，创建一篇新博客文章。现在保存博客文章，并观察创建时间文本，你会发现过了一会儿它会发生变化：

![重新运行函数](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00025.jpeg)

# 创建高级计时器对象

之前的示例是一个自定义反应式对象的简单演示。为了使其更有用，最好创建一个单独的对象，隐藏`Tracker.Dependency`函数并添加其他功能。

Meteor 的反应性和依赖跟踪允许我们从另一个函数内部调用`depend()`函数时创建依赖项。这种依赖链允许更复杂的反应式对象。

在下一个示例中，我们将取我们的`timer`对象并为其添加`start`和`stop`函数。此外，我们还将使其能够选择一个时间间隔，在该时间间隔内计时器将重新运行：

1.  首先，让我们从`main.js`和`template-helpers.js`文件中删除之前添加的代码示例，并在`my-meteor-blog/client`内创建一个名为`ReactiveTimer.js`的新文件，内容如下：

    ```js
    ReactiveTimer = (function () {

        // Constructor
        function ReactiveTimer() {
            this._dependency = new Tracker.Dependency;
            this._intervalId = null;
        };

        return ReactiveTimer;
    })();
    ```

    这创建了一个经典的 JavaScript 原型类，我们可以使用`new ReactiveTimer()`来实例化它。在其构造函数中，我们实例化了一个`new Tracker.Dependency`并将其附加到该函数。

1.  现在，我们将创建一个`start()`函数，它将启动一个自选的间隔：

    ```js
    ReactiveTimer = (function () {

        // Constructor
        function ReactiveTimer() {
            this._dependency = new Tracker.Dependency;
            this._intervalId = null;
        };
        ReactiveTimer.prototype.start = function(interval){
            var _this = this;
            this._intervalId = Meteor.setInterval(function(){
                // rerun every "interval"
                _this._dependency.changed();
            }, 1000 * interval);
        };

        return ReactiveTimer;
    })();
    ```

    这是我们之前使用的相同代码，不同之处在于我们将间隔 ID 存储在`this._intervalId`中，这样我们可以在`stop()`函数中稍后停止它。传递给`start()`函数的间隔必须是秒；

1.  接下来，我们在类中添加了`stop()`函数，它将简单地清除间隔：

    ```js
    ReactiveTimer.prototype.stop = function(){
        Meteor.clearInterval(this._intervalId);
    };
    ```

1.  现在我们只需要一个函数来创建依赖关系：

    ```js
    ReactiveTimer.prototype.tick = function(){
        this._dependency.depend();
    };
    ```

    我们的反应式定时器准备好了！

1.  现在，要实例化`timer`并使用我们喜欢的间隔启动它，请在文件末尾的`ReactiveTimer`类后添加以下代码：

    ```js
    timer = new ReactiveTimer();
    timer.start(10);
    ```

1.  最后，我们需要回到`template-helper.js`文件中的`{{formatTime}}`助手，并`添加``time.tick()`函数，界面上所有的相对时间都会随着时间流逝而更新。

1.  要看到反应式定时器的动作，可以在浏览器的控制台中运行以下代码片段：

    ```js
    Tracker.autorun(function(){
        timer.tick();
        console.log('Timer ticked!');
    });
    ```

1.  我们应该现在每 10 秒看到一次**Timer ticked!**的日志。如果我们现在运行`time.stop()`，定时器将停止运行其依赖函数。如果我们再次调用`time.start(2)`，我们将看到`Timer ticked!`现在每两秒出现一次，因为我们设置了间隔为`2`：![创建一个高级定时器对象](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00026.jpeg)

正如我们所看到的，我们的`timer`对象现在相当灵活，我们可以在整个应用程序中创建任意数量的时间间隔。

# 反应式计算

Meteor 的反应性和`Tracker`包是一个非常强大的特性，因为它允许将事件行为附加到每个函数和每个模板助手。这种反应性正是保持我们界面一致性的原因。

虽然到目前为止我们只接触了`Tracker`包，但它还有几个我们应该查看的属性。

我们已经学习了如何实例化一个反应式对象。我们可以调用`new Tracker.Dependency`，它可以通过`depend()`和`changed()`创建和重新运行依赖关系。

## 停止反应式函数

当我们在一个反应式函数内部时，我们也能够访问到当前的计算对象，我们可以用它来停止进一步的反应式行为。

为了看到这个效果，我们可以在浏览器的控制台中使用我们已经在运行的`timer`，并使用`Tracker.autorun()`创建以下反应式函数：

```js
var count = 0;
var someInnerFunction = function(count){
    console.log('Running for the '+ count +' time');

    if(count === 10)
        Tracker.currentComputation.stop();
};
Tracker.autorun(function(c){
    timer.tick();

    someInnerFunction(count);

    count++;
});

timer.stop();
timer.start(2);
```

在这里，我们创建了`someInnerFunction()`来展示我们如何从嵌套函数中访问当前计算。在这个内部函数中，我们使用`Tracker.currentComputation`获取计算，它给了我们当前的`Tracker.Computation`对象。

我们使用之前在`Tracker.autorun()`函数中创建的`count`变量进行计数。当我们达到 10 时，我们调用`Tracker.currentComputation.stop()`，这将停止内部依赖和`Tracker.autorun()`函数的依赖，使它们失去反应性。

为了更快地看到结果，我们在示例的末尾以两秒的间隔停止和开始`timer`对象。

如果我们把前面的代码片段复制并粘贴到浏览器的控制台并运行它，我们应该看到**Running for the xx time**出现 10 次：

![停止响应式函数](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00027.jpeg)

当前计算对象对于从依赖函数内部控制响应式依赖项很有用。

## 防止在启动时运行

`Tracker``.Computation`对象还带有`firstRun`属性，我们在前一章中使用过。

例如，当使用`Tracker.autorun()`创建响应式函数时，它们在首次被 JavaScript 解析时也会运行。如果我们想要防止这种情况，我们可以在检查`firstRun`是否为`true`时简单地停止函数，在执行任何代码之前：

```js
Tracker.autorun(function(c){
    timer.tick();

    if(c.firstRun)
        return;

    // Do some other stuff
});
```

### 注意

我们在这里不需要使用`Tracker.currentComputation`来获取当前计算，因为`Tracker.autorun()`已经将其作为第一个参数。

同样，当我们停止`Tracker.autorun()`函数时，如以下代码所述，它将永远不会为会话变量创建依赖关系，因为第一次运行时从未调用`Session.get()`：

```js
Tracker.autorun(function(c){
  if(c.firstRun)
    return;

  Session.get('myValue');
}):
```

为了确保我们使函数依赖于`myValue`会话变量，我们需要将它放在`return`语句之前。

## 高级响应式对象

`Tracker`包还有一些更高级的属性和函数，允许您控制何时无效化依赖项（`Tracker.flush()`和`Tracker.Computation.invalidate()`）以及允许您在它上面注册额外的回调（`Tracker.onInvalidate()`）。

这些属性允许您构建复杂的响应式对象，这超出了本书的范围。如果您想要更深入地了解`Tracker`包，我建议您查看 Meteor 手册中的[`manual.meteor.com/#tracker`](http://manual.meteor.com/#tracker)。

# 总结

在本章中，我们学习了如何构建我们自己的自定义响应式对象。我们了解了`Tracker.Dependency.depend()`和`Tracker.Dependency.changed()`，并看到了响应式依赖项具有自己的计算对象，可以用来停止其响应式行为并防止在启动时运行。

为了更深入地了解，请查看`Tracker`包的文档，并查看以下资源的`Tracker.Computation`对象的详细属性描述：

+   [`www.meteor.com/tracker`](https://www.meteor.com/tracker)

+   [`docs.meteor.com/#/full/tracker`](https://docs.meteor.com/#/full/tracker)

+   [`docs.meteor.com/#/full/tracker_computation`](https://docs.meteor.com/#/full/tracker_computation)

+   [`docs.meteor.com/#/full/tracker_dependency`](https://docs.meteor.com/#/full/tracker_dependency)

你可以在本章的代码示例在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或者在 GitHub 上找到[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter9`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter9)。

现在我们已经完成了我们的博客，我们将在下一章看看如何将我们的应用程序部署到服务器上。


# 第十章：部署我们的应用程序

我们的应用程序现在已准备好部署。在本章中，我们将了解如何将我们的应用程序部署到不同的服务器上，使其公开并向世界展示我们所构建的内容。

Meteor 使得在自身的服务器基础设施上部署应用程序变得非常容易。操作免费且迅速，但可能不适合生产环境。因此，我们将探讨手动部署以及一些为在任何 Node.js 服务器上部署而构建的优秀工具。

在本章中，我们将涵盖以下主题：

+   注册 Meteor 开发者账户

+   在 Meteor 的自有服务器基础设施上部署

+   手动打包和部署 Meteor

+   使用 Demeteorizer 部署

+   使用 Meteor Up 部署

    ### 注意

    如果你想要部署本书中构建的完整应用程序，可以从以下网址下载代码：[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或从 GitHub 仓库：[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10)。

    这段代码将不包括创建虚拟帖子的部分，因此你可以在自己的服务器上启动一个干净的博客。

# 在 meteor.com 上部署

Meteor 提供了自己的托管环境，其中每个人都可以用一个命令免费部署应用程序。为了部署应用程序，Meteor 会为我们创建一个开发者账户，以便我们稍后管理和部署应用程序。首先，让我们执行以下步骤，在 [meteor.com](http://meteor.com) 上部署我们的应用程序：

1.  在 meteor.com 的子域上部署就像在我们的应用程序文件夹中的终端运行以下命令那么简单：

    ```js
    $ meteor deploy myCoolNewBlog

    ```

    我们可以自由选择要部署的子域。如果 `myCoolNewBlog.meteor.com` 已经被占用，Meteor 会要求我们登录所有者的账户以覆盖当前部署的应用程序，或者我们必须选择另一个名字。

1.  如果域名可用，Meteor 会要求我们提供一个电子邮件地址，以便它为我们创建一个开发者账户。输入电子邮件地址后，我们将收到一封电子邮件，其中有一个链接设置我们的 Meteor 开发者账户，如下面的屏幕截图所示：![在 meteor.com 上部署](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00028.jpeg)

1.  为了创建我们的账户，我们需要遵循 Meteor 给出的链接，以便我们通过添加用户名和密码完全设置我们的账户，如下面的屏幕截图所示：![在 meteor.com 上部署](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00029.jpeg)

1.  完成这些操作后，我们将访问我们的开发者账户页面，在那里我们可以添加电子邮件地址，检查我们的最后登录，以及授权其他 Meteor 开发者登录到我们的应用程序（尽管我们首先必须添加 `accounts-meteor-developer` 包）。

1.  最后，要在终端中使用 `$ meteor login` 登录我们的 Meteor 开发者账户，输入我们的凭据，并再次运行 `deploy` 命令来最终部署我们的应用程序：

    ```js
    $ meteor deploy myCoolNewBlog

    ```

1.  使用`$ meteor authorized –add <username>`命令，我们可以允许其他 Meteor 开发者将应用程序部署到我们应用程序的子域，如下所示屏幕截图：![在 meteor.com 上部署](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00030.jpeg)

1.  如果我们想更新我们部署的应用程序，我们只需在我们应用程序的文件夹内运行`$ meteor deploy`。 Meteor 将要求我们提供凭据，然后我们可以部署我们的应用程序。

如果我们正在朋友的计算机上，并且想使用我们的 Meteor 账户，可以使用`$ meteor login`。 Meteor 将保持我们登录状态，并且每个人都可以重新部署我们的任何应用程序。 我们需要确保在完成时使用`$ meteor logout`。

## 使用域名在 meteor.com 上部署

我们还可以将应用程序托管在[meteor.com](http://meteor.com)，但可以定义我们自己的域名。

要这样做，我们只需使用我们的域名进行部署，如下所示：

```js
$ meteor deploy mydomain.com

```

这将使应用程序托管在 meteor.com 上，但没有类似于[myapp.meteor.com](http://myapp.meteor.com)的直接 URL。

要将我们的域名指向 Meteor 服务器上的应用程序，我们需要将域名的**A 记录**更改为`origin.meteor.com`的 IP 地址（在撰写本书时为`107.22.210.133`），或**CNAME 记录**更改为`origin.meteor.com`。 您可以在注册域名的 DNS 配置中提供商处进行此操作。

Meteor 然后从我们的域名获取请求并在内部将其重定向到托管我们应用程序的服务器。

## 备份并恢复托管在 meteor.com 上的数据库

如果您需要备份数据库或将它移动到另一个服务器，您可以使用以下命令获取部署数据库的临时 Mongo 数据库凭据：

```js
$ meteor mongo myapp.meteor.com –url

```

这将获取类似于以下凭据：

```js
mongodb://client-ID:xyz@production-db-b1.meteor.io:27017/yourapp_meteor_com

```

然后，您可以使用前面输出的凭据使用`mongodump`备份您的数据库：

```js
$ mongodump -h production-db-b1.meteor.io --port 27017 --username client-ID --password xyz --db yourapp_meteor_com

```

这将在您所在位置创建一个名为`dump/yourapp_meteor_com`的文件夹，并将数据库的转储文件放在里面。

要恢复到另一个服务器，请使用`mongorestore`，最后一个参数是你放置数据库转储的文件夹：

```js
$ mongorestore -h mymongoserver.com --port 27017 --username myuser --password xyz --db my_new_database dump/yourapp_meteor_com

```

如果你只想将数据放入您本地的 Meteor 应用程序数据库中，请使用`$ meteor`启动 Meteor 服务器并运行以下命令：

```js
$ mongorestore --port 3001

```

# 在其他服务器上部署

Meteor 的免费托管很棒，但当涉及到在生产中使用应用程序时，我们希望能够控制我们正在使用的服务器。

Meteor 允许我们将应用程序捆绑在一起，这样我们就可以在任何 Node.js 服务器上部署它。唯一的缺点是我们需要自己安装某些依赖项。此外，还有两个使部署应用程序几乎像 Meteor 本身一样简单的包，尽管它们的配置仍然需要。

## 捆绑我们的应用程序

为了在我们的服务器上部署应用，我们需要一个安装了最新版本的 Node.js 和 NPM 的 Linux 服务器。服务器应该和我们将要创建捆绑包的本地机器是同一平台。如果你想在另一个平台上部署你的应用，查看下一节。现在让我们通过以下步骤构建应用：

1.  如果我们的服务器符合上述要求，我们可以在本地机器上的应用文件夹中运行以下命令：

    ```js
    $ meteor build myAppBuildFolder

    ```

1.  这将创建一个名为`myAppBuildFolder`的文件夹，里面有一个`*.tar.gz`文件。然后我们可以将这个文件上传到我们的服务器，并在例如`~/Sites/myApp`下提取它。然后我们进入提取的文件夹并运行以下命令：

    ```js
    $ cd programs/server
    $ npm install

    ```

1.  这将安装所有的 NPM 依赖。安装完成后，我们设置必要的环境变量：

    ```js
    $ export MONGO_URL='mongodb://user:password@host:port/databasename'
    $ export ROOT_URL='http://example.com'
    $ export MAIL_URL='smtp://user:password@mailhost:port/'
    $ export PORT=8080

    ```

    `export`命令将设置`MONGO_URL`、`ROOT_URL`和`MAIL_URL`环境变量。

1.  由于这种手动部署没有预装 MongoDB，我们需要在我们的机器上安装它，或者使用像 Compose 这样的托管服务（[`mongohq.com`](http://mongohq.com)）。如果我们更愿意自己在服务器上安装 MongoDB，我们可以遵循在[`docs.mongodb.org/manual/installation`](http://docs.mongodb.org/manual/installation)的指南。

1.  `ROOT_URL`变量应该是指向我们服务器的域的 URL。如果我们的应用发送电子邮件，我们还可以设置自己的 SMTP 服务器，或使用像 Mailgun 这样的服务（[`mailgun.com`](http://mailgun.com)）并更改`MAIL_URL`变量中的 SMTP 主机。

    我们也可以指定我们希望应用运行的端口，使用`PORT`环境变量。如果我们没有设置`PORT`变量，它将默认使用端口`80`。

1.  设置这些变量后，我们转到应用的根目录，并使用以下命令启动服务器：

    ```js
    $ node main.js

    ```

    ### 提示

    如果你想确保你的应用在崩溃或服务器重启时能够重新启动，可以查看`forever` NPM 包，具体解释请参阅[`github.com/nodejitsu/forever`](https://github.com/nodejitsu/forever)。

如果一切顺利，我们的应用应该可以通过`<your server's ip>:8080`访问。

如果我们手动部署应用时遇到麻烦，我们可以使用接下来的方法。

## 使用 Demeteorizer 部署

使用`$ meteor build`的缺点是，大多数 node 模块已经被编译，因此在服务器环境中可能会造成问题。因此出现了 Demeteorizer，它与`$ meteor build`非常相似，但还会额外解压捆绑包，并创建一个包含所有 node 依赖项和项目正确 node 版本的`package.json`文件。以下是使用 Demeteorizer 部署的方法：

1.  Demeteorizer 作为一个 NPM 包提供，我们可以使用以下命令安装：

    ```js
    $ npm install -g demeteorizer

    ```

    ### 注意

    如果`npm`文件夹没有正确的权限，请在命令前使用`sudo`。

1.  现在我们可以去应用文件夹并输入以下命令：

    ```js
    $ demeteorizer -o ~/my-meteor-blog-converted

    ```

1.  这将把准备分发的应用程序输出到`my-meteor-blog-converted`文件夹。我们只需将这个文件夹复制到我们的服务器上，设置与之前描述相同的环境变量，并运行以下命令：

    ```js
    $ cd /my/server/my-meteor-blog-converted
    $ npm install
    $ node main.js

    ```

这应该会在我们指定的端口上启动我们的应用程序。

## 使用 Meteor Up 部署

前面的步骤可以帮助我们在自己的服务器上部署应用程序，但这种方法仍然需要我们构建、上传和设置环境变量。

**Meteor Up**（**mup**）旨在使部署像运行`$ meteor deploy`一样简单。然而，如果我们想要使用 Meteor Up，我们需要在服务器上拥有完全的管理权限。

此外，这允许我们在应用程序崩溃时自动重新启动它，使用`forever` NPM 包，以及在服务器重新启动时启动应用程序，使用`upstart` NPM 包。我们还可以恢复先前的部署版本，这为我们提供了在生产环境部署的良好基础。

### 注意

接下来的步骤是针对更高级的开发人员，因为它们需要在服务器机器上设置`sudo`权限。因此，如果您在部署方面没有经验，可以考虑使用像 Modulus 这样的服务（[`modulus.io`](http://modulus.io)），它提供在线 Meteor 部署，使用自己的命令行工具，可在[`modulus.io/codex/meteor_apps`](https://modulus.io/codex/meteor_apps)找到。

Meteor Up 将按照以下方式设置服务器并部署我们的应用程序：

1.  要在我们的本地机器上安装`mup`，我们输入以下命令：

    ```js
    $ npm install -g mup

    ```

1.  现在我们需要创建一个用于部署配置的文件夹，这个文件夹可以位于我们的应用程序所在的同一个文件夹中：

    ```js
    $ mkdir ~/my-meteor-blog-deployment
    $ cd ~/my-meteor-blog-deployment
    $ mup init

    ```

1.  Meteor Up 为我们创建了一个配置文件，它看起来像以下这样：

    ```js
    {
      "servers": [
        {
          "host": "hostname",
          "username": "root",
          "password": "password"
          // or pem file (ssh based authentication)
          //"pem": "~/.ssh/id_rsa"
        }
      ],
      "setupMongo": true,
      "setupNode": true,
      "nodeVersion": "0.10.26",
      "setupPhantom": true,
      "appName": "meteor",
      "app": "/Users/arunoda/Meteor/my-app",
      "env": {
        "PORT": 80,
        "ROOT_URL": "http://myapp.com",
        "MONGO_URL": "mongodb://arunoda:fd8dsjsfh7@hanso.mongohq.com:10023/MyApp",
        "MAIL_URL": "smtp://postmaster%40myapp.mailgun.org:adj87sjhd7s@smtp.mailgun.org:587/"
      },
      "deployCheckWaitTime": 15
    }
    ```

1.  现在我们可以编辑这个文件以适应我们的服务器环境。

1.  首先，我们将添加 SSH 服务器认证。我们可以提供我们的 RSA 密钥文件，或者提供一个用户名和密码。如果我们想要使用后者，我们需要安装`sshpass`，一个用于在不使用命令行的前提下提供 SSH 密码的工具：

    ```js
    "servers": [
        {
          "host": "myServer.com",
          "username": "johndoe",
          "password": "xyz"
          // or pem file (ssh based authentication)
          //"pem": "~/.ssh/id_rsa"
        }
    ],
    ```

    ### 注意

    要为我们的环境安装`sshpass`，我们可以按照[`gist.github.com/arunoda/7790979`](https://gist.github.com/arunoda/7790979)的步骤进行，或者如果您在 Mac OS X 上，可以查看[`www.hashbangcode.com/blog/installing-sshpass-osx-mavericks`](http://www.hashbangcode.com/blog/installing-sshpass-osx-mavericks)。

1.  接下来，我们可以设置一些选项，例如选择在服务器上安装 MongoDB。如果我们使用像 Compose 这样的服务，我们将将其设置为`false`：

    ```js
    "setupMongo": false,
    ```

    如果我们已经在我们的服务器上安装了 Node.js，我们还将将下一个选项设置为`false`：

    ```js
    "setupNode": false,
    ```

    如果我们想要指定一个特定的 Node.js 版本，我们可以如下设置：

    ```js
    "nodeVersion": "0.10.25",
    ```

    Meteor Up 还可以为我们安装 PhantomJS，这对于我们使用 Meteor 的 spiderable 包是必要的，这个包可以使我们的应用程序被搜索引擎爬取：

    ```js
    "setupPhantom": true,
    ```

    在下一个选项中，我们将设置我们应用程序的名称，它可以与我们的应用程序文件夹名称相同：

    ```js
    "appName": "my-meteor-blog",
    ```

    最后，我们需要指向我们的本地应用程序文件夹，以便 Meteor Up 知道要部署什么：

    ```js
    "app": "~/my-meteor-blog",
    ```

1.  Meteor Up 还允许我们预设所有必要的环境变量，例如正确的`MONGO_URL`变量：

    ```js
    "env": {
        "ROOT_URL": "http://myServer.com",
        "MONGO_URL": "mongodb://user:password@host:port/databasename",
        "PORT": 8080
    },
    ```

1.  最后一个选项设置了 Meteor Up 在检查应用是否成功启动前会等待的时间：

    ```js
    "deployCheckWaitTime": 15
    ```

### 设置服务器

为了使用 Meteor Up 设置服务器，我们需要对`sudo`进行无密码访问。按照以下步骤设置服务器：

1.  为了启用无密码访问，我们需要将当前用户添加到服务器的`sudo`组中：

    ```js
    $ sudo adduser <username> sudo

    ```

1.  然后在`sudoers`文件中添加`NOPASSWD`：

    ```js
    $ sudo visudo

    ```

1.  现在用以下这行替换`%sudo ALL=(ALL) ALL`行：

    ```js
    %sudo ALL=(ALL) NOPASSWD:ALL

    ```

### 使用 mup 部署

如果一切顺利，我们可以设置我们的服务器。以下步骤解释了如何使用`mup`进行部署：

1.  从本地`my-meteor-blog-deployment`目录中运行以下命令：

    ```js
    $ mup setup

    ```

    这将配置我们的服务器并安装配置文件中选择的全部要求。

    一旦这个过程完成，我们随时可以通过在同一目录下运行以下命令来部署我们的应用：

    ```js
    $ mup deploy

    ```

通过创建两个具有不同应用名称的 Meteor Up 配置，我们还可以创建生产和演示环境，并将它们部署到同一服务器上。

# 前景

目前，Meteor 将原生部署限制在其自己的服务器上，对环境控制有限。计划推出一款企业级服务器基础设施，名为**Galaxy**，它将使部署和扩展 Meteor 应用像 Meteor 本身一样简单。

尽管如此，凭借 Meteor 的简洁性和强大的社区，我们已经拥有部署到任何基于 Node.js 的托管和 PaaS 环境的丰富工具集。

### 注意

例如，如果我们想在 Heroku 上部署，我们可以查看 Jordan Sissel 在[`github.com/jordansissel/heroku-buildpack-meteor`](https://github.com/jordansissel/heroku-buildpack-meteor)上的构建包。

# 总结

在本章中，我们学习了如何部署 Meteor，以及在 Meteor 自己的服务器架构上部署可以有多么简单。我们还使用了 Demegorizer 和 Meteor Up 这样的工具来部署我们自己的服务器架构。

要了解更多具体的部署方法，请查看以下资源：

+   [`www.meteor.com/services/developer-accounts`](https://www.meteor.com/services/developer-accounts)

+   [`docs.meteor.com/#/full/deploying`](https://docs.meteor.com/#/full/deploying)

+   [`www.meteor.com/services/build`](https://www.meteor.com/services/build)

+   [`github.com/onmodulus/demeteorizer`](https://github.com/onmodulus/demeteorizer)

+   [`github.com/arunoda/meteor-up`](https://github.com/arunoda/meteor-up)

您可以在这个应用的[完整示例代码](https://www.packtpub.com/books/content/support/17713)中找到准备部署的版本，或者在 GitHub 上查看[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10)。

在下一章中，我们将创建一个包含我们之前创建的`ReactiveTimer`对象的包，并将其发布到 Meteor 的官方包仓库。


# 第十一章：构建我们自己的包

在本章中，我们将学习如何构建自己的包。编写包允许我们创建可以共享在许多应用中的闭合功能组件。在本章的后半部分，我们将把我们的应用发布到 Atmosphere，Meteor 的第三方包仓库，地址为[`atmospherejs.com`](https://atmospherejs.com)。

在本章中，我们将涵盖以下主题：

+   结构化一个包

+   创建一个包

+   发布自己的包

    ### 注意

    在本章中，我们将包装在第九章，*高级反应性*中构建的`ReactiveTimer`对象。要遵循本章中的示例，请从以下任一位置下载上一章的代码示例：[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)（书籍网页）或[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter10）（GitHub 仓库）。

# 包的结构

包是一个包含特定变量暴露给 Meteor 应用的 JavaScript 文件集合。除了在 Meteor 应用中，包文件将按我们指定的加载顺序加载。

每个包都需要一个`package.js`文件，该文件包含该包的配置。在这样的文件中，我们可以添加一个名称、描述和版本，设置加载顺序，并确定哪些变量应该暴露给应用。此外，我们还可以为我们的包指定单元测试来测试它们。

`package.js`文件的一个例子可能看起来像这样：

```js
Package.describe({
  name: "mrt:moment",
  summary: "Moment.js, a JavaScript date library.",
  version: "0.0.1",
  git: "https://..."
});

Package.onUse(function (api, where) {
  api.export('moment');

  api.addFiles('lib/moment-with-langs.min.js', 'client');
});

Package.onTest(function(api){
  api.use(["mrt:moment", "tinytest"], ["client", "server"]);
  api.addFiles("test/tests.js", ["client", "server"]);
});
```

我们可以按照自己的意愿结构包中的文件和文件夹，但以下安排是一个好的基础：

![包的结构](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00031.jpeg)

+   `tests`：包含包的单元测试和`tests.js`文件

+   `lib`：包含包使用的第三方库

+   `README.md`：包含使用包的简单说明

+   `package.js`: 此文件包含包的元数据

+   `myPackage.js`：这些是包含包代码的一个或多个文件

要测试一个包，我们可以使用 Meteor 的`tinytest`包，它是一个简单的单元测试包。如果我们有测试，我们可以使用以下命令运行它们：

```js
$ meteor test-packages <my package name>

```

这将启动一个 Meteor 应用，地址为`http://localhost:3000`，它运行我们的包测试。要了解如何编写一个包，请查看下一章。

# 创建自己的包

要创建自己的包，我们将使用我们在第九章，*高级反应性*中构建的`ReactiveTimer`对象：

1.  我们来到终端，在我们的应用文件夹中运行以下命令：

    ```js
    $ meteor create --package reactive-timer

    ```

1.  这将创建一个名为`packages`的文件夹，其中有一个`reactive-timer`文件夹。在`reactive-timer`文件夹内，Meteor 已经创建了一个`package.js`文件和一些示例包文件。

1.  现在我们可以删除`reactive-timer`文件夹内的所有文件，除了`package.js`文件。

1.  然后我们将我们在第九章 *高级反应性*中创建的`my-meteor-blog/client/ReactiveTimer.js`文件移动到我们新创建的`reactive-timer`包文件夹中。

1.  最后，我们打开复制的`ReactiveTimer.js`文件，并删除以下行：

    ```js
    timer = new ReactiveTimer();
    timer.start(10);
    ```

    稍后，我们在应用本身内部实例化`timer`对象，而不是在包文件中。

现在我们应该有一个简单的文件夹，带有默认的`package.js`文件和我们的`ReactiveTimer.js`文件。这几乎就是全部了！我们只需要配置我们的包，就可以在应用中使用它了。

## 添加包元数据

要添加包的元数据，我们打开名为`package.js`的文件，并添加以下代码行：

```js
Package.describe({
  name: "meteor-book:reactive-timer",
  summary: "A simple timer object, which can re-run reactive functions based on an interval",
  version: "0.0.1",
  // optional
  git: "https://github.com/frozeman/meteor-reactive-timer"
});
```

这为包添加了一个名称、一个描述和一个版本。

请注意，包名称与作者的名称命名空间。这样做的目的是，通过它们的作者名称，可以使具有相同名称的包区分开来。在我们这个案例中，我们选择`meteor-book`，这并不是一个真实的用户名。要发布包，我们需要使用我们真实的 Meteor 开发者用户名。

在`Package.describe()`函数之后是实际的包依赖关系：

```js
Package.onUse(function (api) {
  // requires Meteor core packages 1.0
  api.versionsFrom('METEOR@1.0');

  // we require the Meteor core tracker package
  api.use('tracker', 'client');

  // and export the ReactiveTimer variable
  api.export('ReactiveTimer');

  // which we find in this file
  api.addFiles('ReactiveTimer.js', 'client');
});
```

在这里，我们定义了这个包应该使用的 Meteor 核心包的版本：

+   使用`api.use()`，我们定义了这个包依赖的额外包（或包）。请注意，这些依赖不会被使用这个包的应用本身访问到。

    ### 注意

    另外，还存在`api.imply()`，它不仅使另一个包在包的文件中可用，而且还将它添加到 Meteor 应用本身，使其可以被应用的代码访问。

+   如果我们使用第三方包，我们必须指定最低的包版本，如下所示：

    ```js
    api.use('author:somePackage@1.0.0', 'server');

    ```

    ### 注意

    我们还可以传入第三个参数，`{weak: true}`，以指定只有在开发者已经将依赖包添加到应用中时，才会使用该依赖包。这可以用来在有其他包存在时增强一个包。

+   在`api.use()`函数的第二个参数中，我们可以指定是否在客户端、服务器或两者上都加载它，使用数组：

    ```js
    api.use('tracker', ['client', 'server']);

    ```

    ### 提示

    我们实际上不需要导入`Tracker`包，因为它已经是 Meteor 核心`meteor-platform`包的一部分（默认添加到任何 Meteor 应用中）；我们在这里这样做是为了示例。

+   然后我们使用`api.export('ReactiveTimer')`来定义包中应该向使用此包的 Meteor 应用公开哪个变量。记住，我们在`ReactiveTimer.js`文件中使用以下代码行创建了`ReactiveTimer`对象：

    ```js
    ReactiveTimer = (function () {
      ...
    })();
    ```

    ### 注意

    请注意，我们没有使用`var`来创建变量。这样，它在包的所有其他文件中都可以访问，也可以暴露给应用本身。

+   最后，我们使用`api.addFiles()`告诉包系统哪些文件属于这个包。我们可以有`api.addFiles()`的多个调用，一个接一个。这个顺序将指定文件的加载顺序。

    在这里，我们再次告诉 Meteor 将文件加载到哪个地方——客户端、服务器还是两者都加载——使用`['client', 'server']`。

    在这个例子中，我们只在客户端提供了`ReactiveTimer`对象，因为 Meteor 的反应式函数只存在于客户端。

    ### 注意

    如果你想要查看`api`对象的所有方法，请查看 Meteor 的文档[`docs.meteor.com/#packagejs`](http://docs.meteor.com/#packagejs)。

## 添加包

将包文件夹复制到`my-meteor-blog/packages`文件夹中并不足以让 Meteor 使用这个包。我们需要遵循额外的步骤：

1.  为了添加包，我们需要从终端前往我们的应用文件夹，停止任何正在运行的`meteor`实例，并运行以下命令：

    ```js
    $ meteor add meteor-book:reactive-timer

    ```

1.  然后，我们需要在我们的应用中实例化`ReactiveTimer`对象。为此，我们需将以下代码行添加到我们的`my-meteor-blog/main.js`文件中：

    ```js
    if(Meteor.isClient) {
        timer = new ReactiveTimer();
        timer.start(10);
    }
    ```

1.  现在我们可以再次使用`$ meteor`启动 Meteor 应用，并在`http://localhost:3000`打开我们的浏览器。

我们应该看不到任何区别，因为我们只是用我们`meteor-book:reactive-timer`包中的`ReactiveTimer`对象替换了应用中原本的`ReactiveTimer`对象。

为了看到计时器运行，我们可以打开浏览器的控制台并运行以下的代码片段：

```js
Tracker.autorun(function(){
    timer.tick();
    console.log('timer run');
});
```

这应该会每 10 秒记录一次`timer run`，显示我们的包实际上是在工作的。

# 发布我们的包给公众

向世界发布一个包是非常容易的，但为了让人们使用我们的包，我们应该添加一个 readme 文件，这样他们就可以知道如何使用我们的包。

在我们之前创建的包文件夹中创建一个名为`README.md`的文件，并添加以下的代码片段：

```js
# ReactiveTimer

This package can run reactive functions in a given interval.
## Installation

    $ meteor add meteor-book:reactive-timer

## Usage

To use the timer, instantiate a new interval:

    var myTimer = new ReactiveTimer();

Then you can start an interval of 10 seconds using:

    myTimer.start(10);

To use the timer just call the following in any reactive function:

    myTimer.tick();

To stop the timer use:

    myTimer.stop();
```

正如我们所见，这个文件使用了 Markdown 语法。这样，它将在 GitHub 和[`atmospherejs.com`](http://atmospherejs.com)上看起来很不错，这是一个你可以浏览所有可用 Meteor 包的网站。

通过这个 readme 文件，我们将使其他人更容易使用我们的包并欣赏我们的工作。

## 在线发布我们的包

在我们保存了`readme`文件之后，我们可以将这个包推送到 GitHub 或其他的在线 Git 仓库，并将仓库的 URL 添加到`package.js`文件的`Package.describe({git: …})`变量中。将代码托管在 GitHub 上可以保证它的安全性，并允许他人进行分叉和改进。下面让我们来进行将我们的包推送到线上的步骤：

1.  发布我们的包，我们可以在终端的`pages`文件夹内简单地运行以下命令：

    ```js
    $ meteor publish --create

    ```

    这会构建并捆绑包，然后上传到 Meteor 的包服务器上。

1.  如果一切顺利，我们应该能够通过输入以下命令找到我们的包：

    ```js
    $ meteor search reactive-timer

    ```

    这在下面的截图中有所说明：

    ![在线发布我们的包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00032.jpeg)

1.  然后，我们可以使用以下命令显示找到的包的所有信息：

    ```js
    $ meteor show meteor-book:reactive-timer

    ```

    这在上面的截图中说明：

    ![在线发布我们的包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00033.jpeg)

1.  要使用来自 Meteor 服务器的包版本，我们只需将`packages/reactive-timer`文件夹移到别处，删除`package`文件夹，然后运行`$ meteor`来启动应用程序。

    现在 Meteor 在`packages`文件夹中找不到具有该名称的包，并将在线查找该包。既然我们发布了它，它将被下载并用于我们的应用程序。

1.  如果我们想在我们的应用程序中使用我们包的特定版本，我们可以在终端中从我们应用程序的文件夹内运行以下命令：

    ```js
    $ meteor add meteor-book:reactive-timer@=0.0.1

    ```

现在我们的包已经发布，我们可以在`http://atmospherejs.com/meteor-book/reactive-timer`看到它，如下所示：

![在线发布我们的包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00034.jpeg)

### 注意

请注意，这只是一个包的示例，并且从未实际发布过。然而，在[`atmospherejs.com/frozeman/reactive-timer`](http://atmospherejs.com/frozeman/reactive-timer)以我的名义发布的这个包的版本可以找到。

## 更新我们的包

如果我们想发布我们包的新版本，我们只需在`package.js`文件中增加版本号，然后从`packages`文件夹内使用以下命令发布新版本：

```js
$ meteor publish

```

要使我们的应用程序使用我们包的最新版本（只要我们没有指定固定版本），我们只需在终端内从我们的应用程序文件夹中运行以下命令：

```js
$ meteor update meteor-book:reactive-timer

```

如果我们想更新所有包，我们可以运行以下命令：

```js
$ meteor update –-packages-only

```

# 总结

在本章中，我们从我们的`ReactiveTimer`对象创建了自己的包。我们还了解到，在 Meteor 的官方打包系统中发布包是多么简单。

要深入了解，请阅读以下资源中的文档：

+   [`docs.meteor.com/#/full/writingpackages`](https://docs.meteor.com/#/full/writingpackages)

+   [`docs.meteor.com/#packagejs`](https://docs.meteor.com/#packagejs)

+   [Meteor 包服务器](https://www.meteor.com/services/package-server)

+   [`www.meteor.com/isobuild`](https://www.meteor.com/isobuild)

您可以在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或 GitHub 上[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter11`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter11)找到本章的代码示例。

这个代码示例只包含包，所以为了将其添加到应用程序中，请使用前一章的代码示例。

在下一章中，我们将查看测试我们的应用程序和包。
