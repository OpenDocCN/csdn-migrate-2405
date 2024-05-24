# Vue CLI3 快速启动指南（三）

> 原文：[`zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf`](https://zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：在 GitHub Pages 上部署 Vue CLI 3 应用

在本章中，我们将在一个新的 GitHub 账户上设置一个新的仓库，并快速原型化一个 Vue 项目。然后，我们将使用 GitHub Pages 进行部署。在本章中，我们将熟悉以下内容：

+   GitHub 桌面应用

+   Git 的基础知识（它是什么以及它是如何工作的）

+   一些基本的 Git 命令

+   理解 Git 中的分支

+   如何正确设置 Vue 应用以在 GitHub Pages 上工作

在本章结束时，你将拥有一个在 GitHub Pages 上运行的完全可用的 Vue 应用。让我们从理解如何使用 GitHub 桌面应用开始。

# 安装 GitHub 桌面应用

首先，转到以下 URL：`https://desktop.github.com`。接下来，只需通过屏幕中央醒目的下载按钮下载应用，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/a488acad-2b93-495a-b0ef-3715fa7f7c30.png)

一旦你下载了 GitHub 桌面应用的安装文件（`GithubDesktopSetup.exe`），你需要运行安装。

安装完成后，你会看到一个简洁的界面。如果你第一次使用 Git 和 GitHub，这个简洁的界面可能看起来几乎是*太简洁*了。这个应用到底是怎么回事？

为了理解这个应用是如何工作的，你需要了解一些 Git 的基本概念。

# 理解 Git 的工作原理

在你工作在一个项目上时，如果你没有使用像 Git 这样的源代码版本控制，你可能会认为你的项目只有一个文件夹。例如，使用 Vue CLI 3 安装的任何 Vue 应用都会以一个单独的文件夹的形式存在，里面包含了一些子文件夹。

我们可以简化这样一个 Vue 应用的树形结构，并描述它如下：

```js
aVueApp
   |- aSubfolder
   |- anotherSubfolder
   |- yetAnotherSubfolder
```

请注意，我们想象中的 Vue 应用有一个名为`aVueApp`的根文件夹。在这个根文件夹里有三个子文件夹，包含了我们 Vue 应用的完整功能。

只要我们只处理一些文件和文件夹，也就是说，只要我们的 Vue 应用非常小，我们就不必担心对文件和文件夹进行版本控制，因为几乎没有什么需要进行版本控制的。如果我们在一个文件或文件夹中犯了错误，我们只需撤消更改，就可以回到文件的早期版本。这是一个合理的方法。

然而，如果我们的项目增长到，比如说，30 个文件分布在七个文件夹中，会发生什么呢？让我们再想象一下，在开发 Vue 项目期间，我们只更新了这 30 个文件中的几行代码。让我们进一步想象，我们对这些文件做了很多更改，并且在开发过程中犯了一些重大错误，以至于我们根本无法继续在我们的项目上工作。通常，在一个较小的项目上，我们可以简单地撤消我们对几个文件所做的更改，以回到我们应用程序的*上一个工作版本*。

然而，由于许多更改分布在许多不同的文件中，我们不仅不太可能记得撤消每个更改以回到我们应用程序的上一个工作版本，而且撤消所有这些更改也会耗费时间，因此最终是不切实际的。

开发者该怎么办呢？

幸运的是，我们有版本控制。Git 被称为**分布式版本控制系统**。不用太技术化地说，你可以把 Git 想象成一个大的撤销/重做按钮，只是有一个小小的附带条件。Git 不是在单个文件上撤消更改，而是通过时间跟踪开发者应用程序的版本，有点像在某个时间点对整个应用程序进行快照。

开发者负责决定何时进行这个过程。例如，当你在应用程序中编写了一个新功能，并且准备保存应用程序的当前状态以便以后回到它时，你只需通过*提交更改*来保存它。

与其在理论上描述这个过程，不如开始一个新的 Vue 应用程序，并借助 Git 跟踪对其所做的更改。

# 开始一个新的 Vue 应用程序，并使用 Git 跟踪更改

让我们打开 Git Bash，并按照以下步骤在我们选择的文件夹中创建一个新的 Vue 项目：

```js
vue create chapter8
```

让我们保持简单，每当 Vue CLI 3 提示我们回答时，按下*Enter*键。正如我们已经学到的，这是在使用 Vue CLI 3 安装新的 Vue 应用程序时接受默认设置的快速简便方法。

要开始使用 Git 跟踪项目，我们运行以下命令：

```js
git init
```

这个命令初始化了一个新的本地 Git 仓库。我们在这里使用“本地”这个词，因为目前，这个仓库只存在于我们的计算机上。如果明天我们抹掉了计算机的磁盘，我们刚刚创建的本地 Git 仓库也会丢失。

然而，有些情况下 Git 仓库已经被初始化。以下是一个简单的命令，我们可以运行来查看我们的项目中是否有 Git 仓库：

```js
git status
```

上面的命令为我们提供了有关我们仓库当前状态的信息。如果我们运行此命令的文件夹不为空，它将报告当前文件夹不是一个 Git 仓库。

现在让我们在`chapter8`文件夹的根目录运行`git status`命令。这是我们得到的内容：

```js
On branch master
nothing to commit, working tree clean
```

这些信息告诉我们，我们目前正在项目的主分支上，并且没有要提交的内容。工作树是干净的。这个*工作树*是什么？

**工作树**代表了在我们项目中保存并已提交更改的所有文件和文件夹。

要检查对我们项目文件所做更改的历史记录，我们可以运行这个命令：

```js
git log
```

这个命令将列出到目前为止我们添加到项目中的所有提交。以下是上一个命令的输出：

```js
commit ee07b4828fb217902f2f7c1047f00f936c3a461f (HEAD -> master)
Author: UserWithEmail <user@email.com>
Date: Mon Apr 22 22:18:48 2019 +0200

 init
```

在这里，我们可以看到几条信息：

+   用一个包含 40 个字符的 SHA 唯一标识符进行提交

+   提交作者（包括作者的用户名和电子邮件地址）

+   提交时的日期和时间

现在让我们对`App.vue`文件进行一个小的更改。我们将把`msg`属性从 Welcome to Your Vue.js App 更新为只是 Welcome。一旦我们保存了更改，我们可以再次运行`git status`命令。这是我们将在控制台中得到的内容：

```js
On branch master
Changes not staged for commit:
 (use ''git add <file>...'' to update what will be committed)
 (use ''git checkout -- <file>...'' to discard changes in working directory)

 modified: src/App.vue
no changes added to commit (use ''git add'' and/or ''git commit -a'')
```

现在，我们可以创建应用程序在这个时间点的另一个*快照*。为此，我们需要做以下两件事：

+   首先，我们需要将所有更改添加到*暂存区*（这是第二个 Git 树）。

+   其次，我们需要提交这些更改，以便它们获得自己的提交 SHA（由 40 个伪随机字符组成的唯一标识符）。

# 提交更改到我们的应用程序

让我们用这个命令添加所有的更改：

```js
git add --all
```

接下来，我们将通过给出提交消息来提交更改，如下所示：

```js
git commit -m "Update App.vue's template"
```

现在，让我们再次运行`git log`命令来查看输出。这一次，我们还将传递一个标志，`--oneline`，如下所示：

```js
git log --oneline
```

这是我们在控制台中得到的结果：

```js
e469374 (HEAD -> master) Update App.vue's template
ee07b48 init
```

请注意，这一次，我们得到的信息要简洁得多。40 个字符的 SHA 字符串现在被缩写为前八个字母和数字，并且作者的详细信息被省略了。`--oneline`标志在我们需要查看许多提交时非常有用。您甚至可以通过传递另一个标志来缩小结果的数量，以减少要查看的提交数量。无论您指定的数字是多少，您都将得到最近提交的这么多个。

例如，我们目前有两个提交，所以我们可以运行这个命令来查看最后两个提交：

```js
git log --oneline -2
```

我们也可以运行这个命令来只查看最后一次提交：

```js
git log --oneline -1
```

接下来，我们将看看三棵树的概念。

# 三棵树的概念

Git 中有三棵树的概念。重要的是要注意，这个概念与树数据结构无关。在这里，树只是一个我们用来指代文件某种状态的比喻。这三棵树包括以下内容：

+   工作目录

+   暂存区（也称为暂存索引）

+   存储库

三棵树的概念可能一开始听起来很混乱，但实际上非常简单。以下是一个基本的 Git 工作流程：

1.  我们使用`vue create <appname>`来安装一个应用程序。

1.  作为安装的一部分，我们的应用程序被初始化为一个 Git 存储库。

1.  安装完成后，我们拥有了所有的文件（工作目录）和一个单独的提交（带有消息“init”，表示已初始化存储库）。

1.  然后，我们对工作目录进行了一些更改。

1.  在提交这些更改之前，我们需要将它们添加到我们的*暂存索引*中。暂存索引只是一棵准备提交的更新文件的树。如果我们没有使用`git add <filename>`命令添加任何文件，我们的暂存索引就是空的。

1.  当您将所有文件暂存到暂存区后，然后提交它们（使用`git commit -m`语法，后面跟着引号内的特定提交消息）。

1.  当您提交了更改后，您只需重复这个过程。

除了工作目录和暂存区，第三棵树就是存储库。您可以使用`checkout`命令来*加载*存储库中的任何部分到您的工作目录中。然后，如果需要，您可以简单地重复这个过程。

# Git 中的分支

Git 中的另一个重要概念是分支。对于科幻小说迷来说，分支可以被描述为一种多元宇宙：一个项目可以在其中有一个底部导航栏，或者根本没有导航栏。

当我们想要向项目中添加一个新功能时，我们使用分支。这样，每个分支代表项目的一个单独功能。

每个 Git 项目都从一个单一分支开始：master。

一旦我们决定需要另一个分支来处理特殊功能，我们只需运行以下命令：

```js
git checkout -b "branch name here"
```

上面的命令意味着：创建一个新分支，称之为`分支名称`，并切换到这个新添加的分支。

要查看我们项目中所有分支的列表，我们只需运行以下命令：

```js
git branch
```

这个命令将打印出我们项目中所有的分支，并在当前分支前面放一个星号。以下是一个示例输出：

```js
branch one
branch two
* master
```

上面的输出意味着我们的项目中总共有三个分支，我们当前位于`master`分支上。

# 合并分支

在我们在 GitHub 中设置项目之前，还有一件事要提到，那就是合并分支的概念。

工作流程如下：我们使用一个合理的名称（例如`add-navbar`）检出一个新分支。接下来，我们将所有想要的功能添加到这个分支，并提交我们的更改。完成后，我们切换回另一个分支，例如*master*。然后我们只需运行以下命令：

```js
git merge add-navbar
```

这样做将导致`add-navbar`分支中的所有代码被合并到`master`分支中。我们的`master`分支和`add-navbar`分支现在共享相同的代码。

请注意，如果你的工作目录中有未提交的更改，你不能切换分支！如果你不想提交你的更改，但仍然需要切换到另一个分支，一个解决方法是使用`git stash`命令。

这就结束了我们对 Git 一些基本概念的快速介绍。然而，这远远不是一个完整的介绍。我们只是提到了一些我们将在项目中使用的基本功能。还有很多东西要学习。

# 注册一个新的 GitHub 账户

我们已经安装了 GitHub 桌面版。我们对 Git 也有足够的了解，能够理解本章节的其余内容。现在我们将注册一个 GitHub 账户。

导航到[`github.com`](https://github.com)并注册一个新账户。确保检查你的电子邮件并确认注册。

一旦您注册并登录，您将看到这样的界面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/cb732c39-e541-4bf8-803f-e2ae7562db96.png)

这是我们的*远程*GitHub 存储库将位于的位置。要添加到我们的远程存储库，我们需要将更改推送到那里。远程存储库被称为*origin/master*。

幸运的是，我们已经安装了 GitHub 桌面，并且使用它是与 GitHub 交互的最简单的方式。您可以轻松创建新存储库，更新现有存储库，添加分支，并从 GitHub 桌面推送到远程存储库。

我们已经有了`chapter8 Vue`项目，并向其添加了一个提交。现在让我们使用 GitHub 桌面将其添加到远程。

# 使用 GitHub 桌面添加 origin/master

让我们打开 GitHub 桌面应用程序。我们将通过添加我们的`chapter8`项目开始使用它。要做到这一点，请单击主应用程序菜单顶部的文件下拉菜单。接下来，单击“添加本地存储库”命令。

将会出现一个弹出窗口。此弹出窗口的标题是“添加本地存储库”。在弹出窗口的正文中，我们可以看到一个带有占位符“存储库路径”的单个输入字段。旁边是选择本地存储库的按钮。让我们单击“选择...”按钮。

单击“选择...”按钮将打开 Windows 资源管理器，我们可以导航到`chapter8`文件夹的位置。一旦选择了`chapter8`文件夹，只需单击 Windows 资源管理器窗口底部的“选择文件夹”按钮。

接下来，只需按照以下弹出窗口中的“添加存储库”按钮：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/b6185478-abbb-4c2c-9a88-01f6f58d336b.png)

就是这样！您刚刚添加了您的本地存储库。现在，您已经准备好发布它了。

# 发布您的本地存储库

要发布我们的本地存储库，我们只需单击“发布存储库”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/385e46d6-e6fe-4709-9d2c-5b8411182fd6.png)

单击“发布存储库”按钮后，将会出现一个新的弹出窗口。在“发布存储库”弹出窗口中已经添加了以下默认设置：

+   存储库名称（在 GitHub 中显示的名称）

+   描述（默认为空）

+   保持此代码私有复选框（已选中）

让我们接受默认设置并单击“发布存储库”按钮。我们现在在 GitHub 帐户中将有一个新的私有存储库。

回到 GitHub，这是我们的远程存储库：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/41ffa129-8509-4c53-8223-d6b865a99bb6.png)

如果我们单击左侧边栏中的`chapter8`链接，我们将被带到我们的存储库，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/cf965295-56f6-481e-91f0-be2b69386b18.png)

在这里，我们可以看到整个项目。

我们还可以看到我们的存储库中目前有 2 次提交。单击“2 次提交”链接将带我们进入一种提交的可视 Git 日志，您还可以单击每个单独的提交以检查在项目历史的特定时间所做的更改。

接下来，我们将发布我们的项目，以便在 GitHub Pages 上看到。

# 在 GitHub Pages 上发布我们的项目

GitHub Pages 是一个托管服务。您可以在那里托管静态文件。这意味着您不能托管带有后端数据库的项目，因此使用后端技术编写的项目，如 PHP、Node、.NET 等，无法添加。

不过，一个由静态文件组成的简单项目可以走得很远，这是很有趣的。您甚至可以使用 Jekyll 来托管博客，这是 GitHub 的无服务器博客平台。

然而，本节的重点是发布我们的简单 Vue 应用程序，所以让我们准备好做到这一点。

# 准备好发布我们的项目

我们将从 GitHub 上的存储库仪表板开始。让我们按照以下步骤导航到“设置”选项卡：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/d4756100-23ef-4af2-90cd-c122bdc145f8.png)

接下来，我们需要向下滚动到 GitHub Pages 部分，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/7b314042-65c6-4ab7-a6c2-6a6e4ff1f5cb.png)

从前面的屏幕截图中，我们可以看到我们需要在将存储库公开之前才能在 GitHub Pages 上发布。为此，我们只需点击“使公开”按钮（在“危险区域”标题下的第一个按钮）如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/04375b60-1f5c-4f7d-b544-1afa465d584a.png)

在弹出窗口中，我们将输入我们的存储库名称以确认我们的选择，然后点击“我明白，使此存储库公开”按钮。GitHub 可能会要求您在此阶段重新输入密码。

现在，您需要再次向下滚动到 GitHub Pages 部分，并单击下拉按钮。在下拉列表中选择主分支，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/35449adc-68e9-46e8-bc7c-18392c94474e.png)

一旦您选择了主分支，在主菜单下会出现一个警报，上面会显示“GitHub Pages 源已保存”，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/0520a350-e6e5-472f-a9e7-51dfe0de8429.png)

最后，再次向下滚动到 GitHub Pages 部分，您将看到此消息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/ff3dffd1-1d26-4d64-8afd-47a950404a69.png)

一切都已准备就绪，可以在 GitHub Pages 上发布，但我们仍然需要配置我们的 Vue 应用程序。

# 更新 Vue 配置文件

在本书中看到的所有配置文件中，Vue 本身也有一个！这个文件的名称是`vue.config.js`，它位于我们项目的根目录中。这个文件是可选的，所以`vue.config.js`不是我们项目预安装的。让我们将其添加到我们项目的根目录，并向其中添加以下代码：

```js
// vue.config.js
module.exports = {
  // options...
}
```

我们将给我们的 Vue 配置文件的第一个选项是`publicPath`，如下所示：

```js
module.exports = {
  publicPath: process.env.NODE_ENV === 'production'
    ? '/chapter8/'
    : '/'
}
```

您可以在以下网址阅读更多关于此设置的信息：[`cli.vuejs.org/guide/deployment.html#github-pages`](https://cli.vuejs.org/guide/deployment.html#github-pages)。

让我们保存我们的更改，并使用 GitHub Desktop 将它们提交并推送到远程存储库。

# 保存更改并使用 GitHub Desktop 将它们推送到远程存储库

打开 GitHub Desktop，您将看到列出您的更改。只需在应用程序的左下角键入提交消息，然后单击提交到主按钮（GitHub Desktop 应用程序的左下角的蓝色按钮，如下面的屏幕截图所示）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/f6e8911f-480c-4137-80b2-14683fe4ff86.png)

一旦您点击提交到主按钮，您需要将更改推送到 origin（远程存储库的另一个名称），如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/67a208d2-6163-42a5-870d-02c08eede6a4.png)

不幸的是，我们的存储库仍然不会被发布。要发布它，我们需要打开我们根目录中的`.gitignore`文件，并注释掉`/dist`文件夹，以便它不再被忽略，如下所示：

```js
.DS_Store
node_modules
#/dist
```

接下来，我们将使用以下命令构建我们的项目：

```js
npm run build
```

我们将看到以下消息：

```js
Build deployed. The dist directory is ready to be deployed.
```

在 GitHub Desktop 中提交更改并附上消息，例如：`准备 dist 目录`。之后，像以前一样，点击 Push origin 按钮。

# 调试您的 GitHub 页面部署

有时，事情就是不像它们应该的那样工作。在这种情况下，您可以简单地定位项目中隐藏的`.git`文件夹，然后将其删除。这将删除本地存储库。接下来，更新`vue.config.js`文件，就像这样：

```js
module.exports = {
    publicPath: process.env.NODE_ENV === 'production'
      ? '/chp8/'
      : '/'
  }
```

回到 GitHub Desktop，应用程序将注意到您的更改并提供您发布存储库的选项。提供的存储库名称是`chapter8`，但您需要将其重命名为`chp8`。回到 GitHub，在您的新`chp8`存储库中，将其设置为公共。请注意，您可以在 GitHub Desktop 的弹出窗口中完成此操作。无论您如何做到这一点，使存储库公开是很重要的。接下来，在 GitHub 存储库仪表板的设置选项卡中向下滚动到 GitHub Pages 部分，并在主分支上发布一个新的 GitHub Pages 项目，就像我们之前所做的那样。

目前，在 Vue 文档中并不十分清楚如何轻松地在 GitHub Pages 上部署网站。目前有效的方法是将您的`dist`文件夹发布为子树存储库。以下是用于实现此目的的命令：

```js
git init  # with /dist un-ignored in .gitignore
npm run build
git add dist
git commit -m "Init dist"
git status
git subtree push --prefix dist origin master
git add --all
git commit -m "Publish all"
 create mode 100644 README.md
 create mode 100644 babel.config.js
 create mode 100644 package-lock.json
 create mode 100644 package.json
 create mode 100644 public/favicon.ico
 create mode 100644 public/index.html
 create mode 100644 src/App.vue
 create mode 100644 src/assets/logo.png
 create mode 100644 src/components/HelloWorld.vue
 create mode 100644 src/main.js
# make some additional changes, follow it up with ''npm run build''
git add dist
git commit -m "Publish chp8 title"
git subtree push --prefex origin master
```

本章的存储库可以在`https://github.com/ImsirovicAjdin/chp8`找到。如果您查看文件结构，您会注意到您的存储库看起来像这样：

```js
css/
  └── app.11c93175.css
img/
 └── logo.82b9c7a5.png
js/
 ├── app.8c7f6fb3.js
 ├── app.8c7f6fb3.map
 ├── chunk-vendors.ecd76ec1.js
 └── chunk-vendors.ecd76ec1.js.map
favicon.ico
index.html
```

显然，`git subtree push --prefix dist origin master`命令只推送了`dist`目录的内容到 GitHub。要更好地理解本章的存储库是如何工作的，请参考本书代码中的`chapter8`文件夹，并在打开后，在命令行程序中运行`git log`命令。

# 总结

在本章中，我们学习了 Git 和 GitHub 的基础知识。我们已经了解了如何设置和使用 GitHub Desktop，以及如何使用它快速轻松地将本地存储库推送到 GitHub 上的远程存储库。

此外，我们已经学习了如何向我们的应用程序添加分支，以及如何拉取这些分支并将它们与主分支合并。最后，我们讨论了我们需要对项目进行的调整，以便在 GitHub Pages 上发布它。
