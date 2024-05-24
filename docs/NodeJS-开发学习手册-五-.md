# NodeJS 开发学习手册（五）

> 原文：[`zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF`](https://zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：将应用程序部署到 Web

在本章中，我们将担心添加版本控制和部署我们的应用程序，因为当涉及到创建真实的 Node 应用程序时，将应用程序部署到 Web 上显然是其中非常重要的一部分。现实世界中，每家公司都使用某种形式的版本控制。这对软件开发过程至关重要，而且大多数公司都没有使用 Git。Git 已经变得非常流行，占据了版本控制的市场份额。Git 也是免费和开源的，并且有大量优质的教育材料。他们有一本关于如何学习 Git 的书。它是免费的，Stack Overflow 上充满了 Git 特定的问题和答案。

我们将使用 Git 保存我们的项目。我们还将使用它将我们的工作备份到一个名为 GitHub 的服务中，最后我们将使用 Git 将我们的项目实时部署到 Web 上。因此，我们将能够将我们的 Web 服务器部署给任何人访问。它不仅仅可以在本地主机上使用。

具体来说，我们将研究以下主题：

+   设置和使用 Git

+   设置 GitHub 和 SSH 密钥

+   将 Node 应用程序部署到 Web

+   整个开发生命周期的工作流程

# 添加版本控制

在本节中，我们将学习如何设置和使用 Git，这是一个版本控制系统。Git 将允许我们随着时间的推移跟踪我们项目的变化。当出现问题并且我们需要恢复到项目中以前工作正常的状态时，这非常有用。它还非常有用于备份我们的工作。

# 安装 Git

要开始，我们需要在计算机上安装 Git，但幸运的是，这是一个非常简单的安装过程。这是一个我们只需通过几个步骤单击“下一步”按钮的安装程序。所以让我们继续做到这一点。

1.  我们可以通过浏览器转到[git-scm.com](http://git-scm.com)来获取安装程序。

在我们继续安装之前，我想向您展示一本名为 Pro Git 的书的链接([`git-scm.com/book/en/v2`](https://git-scm.com/book/en/v2))。这是一本免费的书，也可以在线阅读。它涵盖了 Git 所提供的一切。在本章中，我们将研究一些更基本的功能，但我们可以很容易地创建一个关于 Git 的整个课程。实际上，Udemy 上有专门关于 Git 和 GitHub 的课程，所以如果您想学习更多内容，我建议阅读这本书或参加课程，无论您的首选学习方法是什么。

1.  单击主页右侧的下载按钮，适用于所有操作系统，无论是 Windows、Linux 还是 macOS。这应该会带我们到安装程序页面，我们应该能够自动下载安装程序。如果您在[SourceForge.net](http://SourceForge.net)上遇到任何问题，那么我们可能需要实际点击它以手动下载以开始下载。

1.  安装程序下载完成后，我们可以简单地运行它。

1.  接下来，通过安装程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f28f15a4-51a0-4b2c-833e-2db4f5206597.png)

1.  点击“继续”并安装软件包：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c69a0917-3956-4c99-8cd1-213499b6467d.png)

1.  完成后，我们可以继续测试安装是否成功：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7ee9bd39-d428-431b-b851-b425179cb950.png)

# macOS 上的 Git

如果您使用的是 macOS，您需要启动软件包安装程序，可能会收到以下消息框，表示它来自未知开发者：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b642c42a-6ab9-40cf-974d-20ce383b5c53.png)

这是因为它是通过第三方分发的，而不是在 macOS 应用商店中。我们可以右键单击软件包，然后单击“打开”按钮，并确认我们确实要打开它。

一旦您到达安装程序，整个过程将非常简单。您可以在每个步骤中单击“继续”和“下一步”。

# Windows 上的 Git

但是，如果您使用的是 Windows，有一个重要的区别。在安装程序中，您将看到一个与此类似的屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/4550bcdb-51c6-4bb5-a53c-0948d0946423.png)

同样重要的是，您还要安装 Git Bash，如截图所示。Git Bash 是一个模拟 Linux 类型终端的程序，在我们创建下一节中的 SSH 密钥时，它将非常重要，以便唯一标识我们的机器。

# 测试安装

现在，让我们进入终端测试安装。从终端中，我们可以继续运行`git --version`。这将打印出我们安装的新版本的 Git：

```js
git --version
```

如下截图所示，我们可以看到我们有 git 版本 2.14.3：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1e395129-2b63-495b-89ff-d32c34d8d6a3.png)

现在，如果您的终端仍然打开，并且出现类似 git 命令未找到的错误，我建议尝试重新启动终端。有时在安装新命令（如刚刚安装的`git`命令）时，这是必需的。

# 将 node-web-server 目录转换为 Git 仓库

安装 Git 成功后，我们现在可以将我们的`node-web-server`目录转换为 Git 存储库。为了做到这一点，我们将运行以下命令：

```js
git init
```

`git init`命令需要在我们项目的根目录中执行，即包含我们要跟踪的所有内容的文件夹。在我们的情况下，`node-web-server`就是那个文件夹。它包含我们的`server.js`文件，我们的`package.json`文件和所有的目录。因此，从服务器文件夹中，我们将运行`git init`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cf1cdef2-0067-47d4-a89d-b857ffd358e7.png)

这将在该文件夹内创建一个`.git`目录。我们可以通过运行`ls -a`命令来证明：

```js
ls -a
```

如下截图所示，我们获得了所有目录，包括隐藏的目录，而我确实有.git：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/025bc4ba-5321-442b-809f-a2f09d977e8e.png)

对于 Windows，可以从 Git Bash 中运行这些命令。

现在这个目录不是我们应该手动更新的东西。我们将使用终端中的命令来对 Git 文件夹进行更改。

您不希望手动进入那里搞乱事情，因为您很可能会破坏 Git 存储库，而您的辛苦工作将变得毫无意义。现在显然，如果有备份，这不是什么大问题，但实际上没有理由进入那个 Git 文件夹。

让我们使用`clear`命令清除终端输出，现在我们可以开始看 Git 的工作原理。

# 使用 Git

如前所述，Git 负责跟踪项目的更改，但默认情况下它实际上不会跟踪任何文件。我们必须告诉 Git 确切地要跟踪哪些文件，这是有很好的理由的。每个项目中都有一些文件，我们很可能不想将其添加到 Git 仓库中，我们将在稍后讨论哪些文件以及为什么。现在让我们继续运行以下命令：

```js
git status
```

现在，所有这些命令都需要在项目的根目录中执行。如果您尝试在存储库之外运行此命令，您将收到类似 git repository not found 的错误。这意味着 Git 找不到`.git`目录，无法实际获取存储库的状态。

当我们运行此命令时，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/bf2f92bd-950c-4cce-8b8c-49efff90be6c.png)

现在重要的部分是未跟踪文件标题和其下的所有文件。这些都是 Git 捕获的所有文件和文件夹，但它目前没有跟踪。Git 不知道您是否要跟踪这些文件的更改，或者您是否要将它们从存储库中忽略。

现在，例如，`views`文件夹是我们确实想要跟踪的。这对项目至关重要，我们希望确保每当有人下载存储库时，他们都会得到`views`文件夹。另一方面，日志文件实际上不需要包含在 Git 中。通常我们的日志文件不会被提交，因为它们通常包含特定时间点服务器运行时的信息。

如上面的代码输出所示，我们有`server.js`，我们的 public 文件夹和`package.json`。这些都是执行应用程序过程中必不可少的。这些肯定会被添加到我们的 Git 仓库中，而我们上面有的第一个是`node_modules`文件夹。`node_modules`文件夹是所谓的生成文件夹。

生成的文件夹可以通过运行命令轻松生成。在我们的情况下，我们可以使用`npm install`重新生成整个目录。我们不想将 Node 模块添加到我们的 Git 仓库，因为它的内容取决于您安装的 npm 版本和您使用的操作系统。最好不要添加 Node 模块，让每个使用您的存储库的人手动在他们实际运行应用程序的计算机上安装模块。

# 将未跟踪的文件添加到提交

现在我们列出了这六个文件夹和文件，所以让我们继续添加我们想要保留的四个文件夹和文件。首先，我们将使用任何`git add`命令。`git add`命令让我们告诉 Git 我们要跟踪某个文件。让我们输入以下命令：

```js
git add package.json
```

在这之后，我们可以再次运行`git status`，这次我们得到了一个非常不同的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6768c7e0-bc2a-4124-98be-a0504a0df1d4.png)

现在我们有一个初始提交标题。这是新的，我们有我们旧的未跟踪文件标题。请注意，在未跟踪的文件下，我们不再有`package.json`。它移到了初始提交标题下。这些都是在我们进行第一次提交时要保存的文件，也就是提交的文件。现在我们可以继续添加其他 3 个。我们将再次使用`git add`命令告诉 Git 我们要跟踪 public 目录。我们可以运行`git status`命令来确认它是否按预期添加了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/12564fb0-5e07-4cd3-9e23-983de41d424d.png)

在上面的截图中，我们可以看到 public/help.html 文件现在将在我们运行提交后提交到 Git。

接下来，我们可以使用`git add server.js`添加`server.js`，并使用`git add views`添加`views`目录，就像这样：

```js
git add server.js

git add views/
```

我们将运行`git status`命令进行确认：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b5000133-53cd-4855-80f3-755e0b800deb.png)

一切看起来都很好。现在未跟踪的文件将一直保留在这里，直到我们执行以下两种操作之一——要么将它们添加到 Git 存储库中，要么使用我们将在 Atom 中创建的自定义文件来忽略它们。

在 Atom 中，我们想要在我们项目的根目录中创建一个名为`.gitignore`的新文件。`gitignore`文件将成为我们的 Git 存储库的一部分，并告诉 Git 要忽略哪些文件和文件夹。在这种情况下，我们可以继续忽略`node_modules`，就像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/28a9f78a-7f62-42f9-b13e-6a8501af7dcf.png)

当我们保存`gitignore`文件并从终端重新运行`git status`时，我们现在会得到一个完全不同的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ba523296-dcee-4f98-9716-1671a425921f.png)

如图所示，我们有一个新的未跟踪文件—`.gitignore`—但`node_modules`目录不见了，这正是我们想要的。我们想要完全删除它，确保它永远不会被添加到 Git 仓库中。接下来，我们可以继续忽略`server.log`文件，通过输入它的名称，`server.log`：

```js
node modules/
server.log
```

我们将保存`gitignore`，再次从终端运行`git status`，确保一切看起来都很好：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fa3d0f70-2563-406d-8cce-3b760f5b5c4a.png)

如图所示，我们有一个`gitignore`文件作为我们唯一的未跟踪文件。`server.log`文件和`node_modules`都不见了。

现在我们有了`gitignore`，我们将使用`git add .gitignore`将其添加到 Git 中，当我们运行`git status`时，我们应该能够看到所有显示的文件都在初始提交之下：

```js
git add .gitignore

git status
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/58456adc-9681-47bd-8016-f76be91ff32f.png)

现在是时候进行提交了。提交实际上只需要两件事。它需要存储库中的一些更改。在这种情况下，我们正在教 Git 如何跟踪大量新文件，所以我们确实在改变一些东西，还需要一个消息。我们已经处理了文件部分。我们告诉 Git 我们想要保存什么，只是还没有真正保存它。

# 进行提交

为了进行我们的第一个提交并将我们的第一件事保存到 Git 存储库中，我们将运行`git commit`并提供一个标志，即`m`标志，这是短消息。在引号内，我们可以指定我们想要用于此提交的消息。使用这些消息非常重要，因此当有人查看提交历史时，可以看到对项目的所有更改的列表，这实际上是有用的。在这种情况下，`Initial commit`总是一个很好的消息，用于你的第一个提交：

```js
git commit -m 'Initial commit'
```

我将继续点击*enter*，如下面的截图所示，我们可以看到对存储库所做的所有更改：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8bee6774-3f98-4d2d-b49b-ffaa394bf715.png)

我们在 Git 存储库中创建了一堆新文件。这些都是我们告诉 Git 我们想要跟踪的文件，这太棒了。

我们现在有了我们的第一个提交，这基本上意味着我们已经保存了项目的当前状态。如果我们对`server.js`进行了重大更改，搞砸了，不知道如何恢复到原来的状态，我们总是可以恢复，因为我们做了一个 Git 提交。现在我们将在后面的部分探讨一些更高级的 Git 功能。我们将讨论如何使用 Git 做大部分你想做的事情，包括部署到 Heroku 和推送到 GitHub。

# 设置 GitHub 和 SSH 密钥

现在你有了一个本地的 Git 存储库，我们将看看如何将代码推送到一个名为 GitHub 的第三方服务。GitHub 将让我们远程托管我们的 Git 存储库，所以如果我们的机器崩溃了，我们可以找回我们的代码，它还有很棒的协作工具，所以我们可以开源一个项目，让其他人使用我们的代码，或者我们可以保持私有，只有我们选择合作的人可以看到源代码。

现在，为了在我们的机器和 GitHub 之间进行实际通信，我们将不得不创建一个称为 SSH 密钥的东西。SSH 密钥旨在在两台计算机之间进行安全通信。在这种情况下，它将是我们的机器和 GitHub 服务器。这将让我们确认 GitHub 是他们所说的那样，它将让 GitHub 确认我们确实可以访问我们试图修改的代码。这将全部通过 SSH 密钥完成，我们将首先创建它们，然后配置它们，最后将我们的代码推送到 GitHub。

# 设置 SSH 密钥

设置 SSH 密钥的过程可能是一个真正的负担。这是一个那种话题，错误的余地真的很小。如果你输入任何错误的命令，事情就不会按预期工作。

现在，如果你使用的是 Windows，你需要在 Git Bash 中执行本节中的所有操作，而不是常规命令提示符，因为我们将使用一些在 Windows 上不可用的命令。但是，在 Linux 和 macOS 上是可用的。因此，如果你使用这两种操作系统中的任何一种，你可以继续使用本书中一直在使用的终端。

# SSH 密钥文档

在我们深入命令之前，我想向您展示一个快速指南，以防您遇到困难或有任何问题。您可以搜索 GitHub SSH 密钥，这将链接您到一篇名为生成 SSH 密钥的文章：[`help.github.com/articles/connecting-to-github-with-ssh/`](https://help.github.com/articles/connecting-to-github-with-ssh/)。一旦您到达这里，您就可以单击 SSH 面包屑，这将带您回到他们关于 SSH 密钥的所有文章：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/435bd81e-9ce8-4538-96fe-64cbca643e25.png)

在这些文章中，我们将专注于检查是否有密钥，生成新密钥，将密钥添加到 GitHub，最后测试一切是否按预期工作。如果您在这些步骤中遇到任何问题，您可以随时单击该步骤的指南，并且您可以选择您正在使用的操作系统，以便查看该操作系统的适当命令。既然您知道这一点，让我们一起来做吧。

# 工作中的命令

我们将从终端运行的第一个命令是检查是否有现有的 SSH 密钥。如果没有，那没关系。我们将继续创建一个。如果您不确定是否有密钥，您可以运行以下命令来确认您是否有密钥：`ls`与`al`标志。这将打印出给定目录中的所有文件，默认情况下，SSH 密钥存储在您的计算机上的用户目录中，您可以使用（`~`）作为`/.ssh`的快捷方式：

```js
ls -al ~/.ssh
```

当您运行该命令时，您将看到 SSH 目录中的所有内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6b6e13c4-95a4-44bb-88bc-cb7c5aef7415.png)

在这种情况下，我已经删除了所有我的 SSH 密钥，所以我的目录中没有任何内容。我只有当前目录和上一个目录的路径。既然我们已经做好了准备，并且确认我们没有密钥，我们可以继续生成一个。如果您已经有一个密钥，例如`id_rsa`文件，您可以跳过生成密钥的过程。

# 生成密钥

要生成一个密钥，我们将使用`ssh-keygen`命令。现在`ssh-keygen`需要三个参数。我们将传入`t`，将其设置为`rsa`。我们将传入`b`，用于字节，将其设置为`4096`。确保精确匹配这些参数，我们将设置一个大写的`C`标志，该标志将设置为您的电子邮件：

```js
ssh-keygen -t rsa -b 4096 -C 'garyngreig@gmail.com'
```

现在，实际发生在幕后的范围不在本书的讨论范围之内。SSH 密钥和设置安全性，这可能是一个完整的课程。我们将使用此命令来简化整个过程。

现在我们可以继续按*enter*键，这将在我们的`.ssh`文件夹中生成两个新文件。当您运行此命令时，您将受到几个步骤的欢迎。我希望您对所有步骤都使用默认设置：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/88530059-be3b-483f-b0b5-8940e302fdfe.png)

他们想要问您是否要自定义文件名。我不建议这样做。您可以直接按*enter*键：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e2ee020a-0ca3-49e8-8542-95d2a061ae15.png)

接下来，他们会要求您输入密码，我们将不使用密码。我将按下*enter*键，不设置密码，然后需要确认密码，所以我将再次按下*enter*键：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2d7558f9-87a6-4555-9c1c-b5f36368cb54.png)

如图所示，我们收到了一条消息，说明我们的 SSH 密钥已经正确创建，并且确实保存在我们的文件夹中。

有了这个，我现在可以通过之前的命令循环运行`ls`命令，我会得到什么？

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6c4674f8-fa15-4d8d-b4e8-de584d2f7536.png)

我们得到了`id_rsa`和`id_rsa.pub`文件。`id_rsa`文件包含私钥。这是您绝对不应该给任何人的密钥。它只存在于您的计算机上。`.pub`文件是公共文件。这是您将提供给 GitHub 或 Heroku 等第三方服务的文件，我们将在接下来的几节中进行操作。

# 启动 SSH 代理

现在我们的密钥已生成，我们需要做的最后一件事是启动 SSH 代理并添加此密钥，以便它知道它的存在。我们将通过运行两个命令来实现这一点。这些是：

+   `eval`

+   `ssh-add`

首先，我们将运行`eval`，然后我们将打开一些引号，在引号内，我们将使用美元符号并打开和关闭一些括号，就像这样：

```js
eval "$()"
```

在括号内，我们将键入带有`s`标志的`ssh-agent`：

```js
eval "$(ssh-agent -s)"
```

这将启动 SSH 代理程序，并且还会打印进程 ID 以确认它确实正在运行，如所示，我们得到 Agent pid 1116：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ceb07845-3dee-4a7c-afad-5a8c6633857f.png)

进程 ID 显然对每个人都是不同的。只要你得到这样的回复，你就可以继续了。

接下来，我们必须告诉 SSH 代理此文件的位置。我们将使用`ssh-add`来实现这一点。这需要我们的私钥文件的路径，我们在用户目录`/.ssh/id_rsa`中有：

```js
ssh-add ~/.ssh/id_rsa
```

当我运行这个时，我应该收到一个像身份添加的消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/aafd390a-9a20-42b4-8bf4-fea82ce82d75.png)

这意味着本地计算机现在知道了这对公钥/私钥，并且在与 GitHub 等第三方服务通信时会尝试使用这些凭据。既然我们已经准备就绪，我们就可以配置 GitHub 了。我们将创建一个帐户，设置它，然后我们将回来测试一切是否按预期工作。

# 配置 GitHub

要配置 GitHub，请按照以下步骤操作：

1.  首先进入浏览器，转到[github.com](https://github.com/)。

1.  在这里，登录到您现有的帐户或创建一个新帐户。如果您需要一个新帐户，请注册 GitHub。如果您已经有一个现有的帐户，请继续登录。

1.  一旦登录，您应该看到以下屏幕。这是您的 GitHub 仪表板：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8febedc9-307f-45a4-9a4f-7568c1be71a7.png)

1.  从这里，导航到设置，位于左上角，通过个人资料图片。转到设置| SSH 和 GPG 密钥| SSH 密钥：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/4009ef30-e031-423f-a85b-b1e064d34d49.png)

1.  从这里，我们可以添加公钥，让 GitHub 知道我们要使用 SSH 进行通信。

1.  添加新的 SSH 密钥：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2d79ceaf-0649-4806-9ca6-e09327a7516a.png)

在这里，您需要做两件事：给它一个名称，并添加密钥。

首先添加名称。名称可以是任何你喜欢的东西。例如，我通常使用一个唯一标识我的计算机的名称，因为我有几台电脑。我会像这样使用`MacBook Pro`。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3bf11c47-360e-4ed1-a677-62e46f6361f9.png)

接下来，添加密钥。

要添加密钥，我们需要获取在上一小节中生成的`id_rsa.pub`文件的内容。该文件包含 GitHub 需要的信息，以便在我们的计算机和他们的计算机之间进行安全通信。有不同的方法来获取密钥。在浏览器中，我们有添加新的 SSH 密钥到您的 GitHub 帐户文章供我们参考。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d0581d38-6875-4aa3-9164-0021295dcf7b.png)

1.  这包含一个命令，您可以使用它从终端中直接复制该文件的内容到剪贴板。现在显然对于操作系统，macOS，Windows 和 Linux 是不同的，所以运行适用于您的操作系统的命令。

1.  使用 macOS 可用的`pbcopy`命令。

然后，进入终端并运行它。

```js
 pbcopy < ~/.ssh/id_rsa.pub
```

这将文件的内容复制到剪贴板。您还可以使用常规文本编辑器打开命令并复制文件的内容。我们可以使用任何方法来复制文件。重要的是你要做。

1.  现在回到 GitHub，点击文本区域并粘贴进去。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/47824d09-e80c-418d-a5db-e8674a55dc52.png)

`id_rsa.pub`的内容应该以`ssh-rsa`开头，并以您使用的电子邮件结尾。

1.  完成后，继续点击“添加 SSH 密钥”。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c6dc5fb0-fbee-49b3-b111-947fd8ce6da7.png)

现在我们可以继续测试一下事情是否正常运行，通过在终端中运行一个命令。再次强调，这个命令可以在您的机器的任何地方执行。你不需要在你的项目文件夹中执行这个命令。

# 测试配置

为了测试我们的 GitHub 配置的工作情况，我们将使用`ssh`，它尝试建立连接。我们将使用`T`标志，后面跟着我们要连接到的 URL，获取`git@github.com`：

```js
ssh -T git@github.com
```

这将测试我们的连接。它将确保 SSH 密钥已正确设置，并且我们可以安全地与 GitHub 通信。当我运行命令时，我收到一条消息，说主机'github.com (192.30.253.113)'的真实性无法得到证实。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/812f487e-a33e-405b-adc1-fd223a4fa200.png)

我们知道我们想要与[github.com](http://www.github.com)进行通信。我们期望通信会发生，所以我们可以继续输入`yes`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/76f3a5f0-7184-4e53-9afa-214333fb2514.png)

从这里，我们会收到 GitHub 服务器的消息，如前面的屏幕截图所示。如果你看到这条消息和你的用户名，那么你已经完成了。你已经准备好创建你的第一个存储库并推送你的代码。

现在，如果你没有看到这条消息，那么在这个过程中出了问题。也许 SSH 密钥没有正确生成，或者 GitHub 没有识别它。

接下来，我们将进入 GitHub，返回到主页，并创建一个新的存储库。

# 创建一个新的存储库

要创建一个新的存储库，请按照以下步骤进行：

1.  在 GitHub 主页的右上角，导航到新存储库按钮，它应该是这样的（如果是新的存储库，点击开始新项目）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/90b7620e-c249-4e79-a8d9-c938466f49d6.png)

这将带我们到新的存储库页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a0488724-e8fe-4236-a050-8e537fcf4b92.png)

1.  在这里，我们只需要给它一个名字。我要把这个叫做`node-course-2-web-server`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/4714c8c1-9b5c-4f49-aafa-094d37a0655f.png)

一旦你有了一个名字，你可以给它一个可选的描述，你可以选择是公共存储库还是私有存储库。

现在私有存储库会让你选择$7 的计划。如果你正在与其他公司创建项目，我建议你选择私有存储库。

1.  不过，在这种情况下，我们正在创建非常简单的项目，如果其他人发现了代码也不会有太大关系，所以继续使用公共存储库的选项。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c74b276d-3e8f-4cfd-805b-00fb8ebd3879.png)

1.  一旦你填写好这两个内容，点击创建存储库按钮：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/becc7ab1-c7f4-4ea0-b896-3bd5e139ece7.png)

这将带你到你的存储库页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d6dead70-af67-4194-a4f1-c2fbe4b76e79.png)

它会给你一些设置，因为目前没有代码可以查看，所以它会根据你所处的情况给你一些指示。

# 设置存储库

现在，在前面的三个设置说明中，我们不需要创建新存储库的说明。我们也不会使用从其他 URL 导入我们的代码的说明。我们已经有一个现有的存储库，我们想要从命令行推送它。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f8204b97-d77b-4c95-b35e-91ecf2a17931.png)

我们将从项目内运行这两个命令：

+   第一个命令将向我们的 Git 存储库添加一个新的远程

+   第二个命令将把它推送到 GitHub

远程让 Git 知道你想要同步的第三方 URL。也许我想把我的代码推送到 GitHub 与我的同事进行交流。也许我还想能够推送到 Heroku 来部署我的应用程序。这意味着你会想要两个远程。在我们的情况下，我们只会添加一个，所以我会复制这个 URL，进入终端，粘贴它，然后点击*enter*：

```js
git remote add origin https://github.com/garygreig/node-course-2-web-server.git
```

现在我们已经添加了`git remote`，我们可以继续运行第二个命令。我们将在整本书中广泛使用第二个命令。在终端中，我们可以复制并粘贴第二个命令的代码，然后运行它：

```js
git push -u origin master
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c83f9342-1742-464d-ab08-8fa0a5612345.png)

如前面的屏幕截图所示，我们可以看到一切都进行得很顺利。我们成功地将所有数据写入 GitHub，如果我们回到浏览器并刷新页面，我们将不再看到那些设置说明。相反，我们将看到我们的存储库，有点像树形视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fccc9e1b-31ab-493b-9752-9a30649564e1.png)

在这里我们可以看到我们有`server.js`文件，这很好。我们看不到日志文件或`node_module`文件，这很好，因为我们忽略了它。我有我的公共目录。一切都运行得非常非常好。我们还有问题跟踪，拉取请求。您可以创建一个 Wiki 页面，用于为存储库设置说明。GitHub 有很多非常棒的功能。我们将只使用最基本的功能。

在我们的存储库中，我们可以看到我们有一个提交，如果我们点击那个提交按钮，实际上可以进入提交页面，在这里我们可以看到我们输入的初始提交消息。我们在上一节中进行了提交：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ebb35b17-82b5-4d6e-aef1-1d0cce8dc53d.png)

这将让我们跟踪所有我们的代码，如果我们进行了不需要的更改，可以回滚，并管理我们的存储库。现在我们的代码已经推送上去，我们完成了。

# 将 node 应用程序部署到 Web

在本节中，您将使用 Heroku 将您的 Node 应用程序实时部署到 Web。在本节结束时，您将获得一个 URL，您可以将其提供给任何人，他们将能够在其浏览器中访问该 URL 以查看应用程序。我们将通过 Heroku 完成这一点。

Heroku 是一个网站。它是一个用于管理托管在云中的 Web 应用程序的 Web 应用程序。这是一个非常棒的服务。他们几乎可以毫不费力地创建新应用程序，部署您的应用程序，更新应用程序，并添加一些很酷的附加功能，如日志记录和错误跟踪，所有这些都是内置的。现在 Heroku，就像 GitHub 一样，不需要信用卡即可注册，并且有免费的套餐，我们将使用。他们为几乎所有功能提供付费计划，但我们可以使用免费套餐来完成本节中的所有操作。

# 安装 Heroku 命令行工具

首先，我们将打开浏览器并转到[heroku.com](https://www.heroku.com/)。在这里，我们可以继续注册一个新帐户。花点时间要么登录您现有的帐户，要么注册一个新帐户。一旦登录，它会显示您的仪表板。现在您的仪表板将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/87c811c3-1195-476c-abc7-5007a55e5608.png)

尽管可能会有一个问候语告诉您创建一个新应用程序，但您可以忽略。我有很多应用程序。您可能没有这些，这完全没问题。

接下来我们要做的是安装 Heroku 命令行工具。这将让我们能够在终端中创建应用程序，部署应用程序，打开应用程序，并且可以在终端中进行各种非常酷的操作，而不必进入 Web 应用程序。这将节省我们的时间并使开发变得更加容易。我们可以通过访问[toolbelt.heroku.com](https://devcenter.heroku.com/articles/heroku-cli)来获取下载。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d50fe3e5-ab59-4355-aa29-c8d5a32fa200.png)

在这里，我们可以获取适用于您正在运行的任何操作系统的安装程序。让我们开始下载。这是一个非常小的下载，所以应该很快。

完成后，我们可以继续进行以下步骤：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ff34b500-7688-4a9c-bd58-394173e8f79e.png)

这是一个简单的安装程序，您只需点击“安装”。无需自定义任何内容。您不必输入关于您的 Heroku 帐户的任何特定信息。让我们继续完成安装程序。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e96706f0-735c-483d-b391-77c533ded72b.png)

这将为我们提供一个新的终端命令，我们可以执行。在我们执行之前，我们必须在终端中本地登录，这正是我们接下来要做的事情。

# 在本地登录 Heroku 帐户

现在我们将启动终端。如果您已经运行它，您可能需要重新启动它，以便您的操作系统识别新的命令。您可以通过运行以下命令来测试它是否已正确安装：

```js
heroku --help
```

当您运行此命令时，您将看到它正在首次安装 CLI，然后我们将获得所有的帮助信息。这将告诉我们我们可以访问哪些命令以及它们的确切工作方式：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/df251077-46ab-48ec-848f-9c501116a932.png)

现在我们需要在本地登录 Heroku 账户。这个过程非常简单。在前面的代码输出中，我们有所有可用的命令，其中之一恰好是登录。我们可以像这样运行`heroku login`来开始这个过程：

```js
heroku login
```

我将运行`login`命令，现在我们只需使用之前设置的电子邮件和密码：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7d1db6e9-234f-4622-b73e-ff0a59a8d0ea.png)

我将输入我的电子邮件和密码。密码输入是隐藏的，因为它是安全的。当我这样做时，您会看到已登录为 garyngreig@gmail.com 显示出来，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/98bda0a2-43c2-455e-a716-b413419aafc0.png)

现在我们已经登录，并且能够成功地在我们的机器命令行和 Heroku 服务器之间进行通信。这意味着我们可以开始创建和部署应用程序。

# 获取 SSH 密钥到 Heroku

在继续之前，我们将使用`clear`命令清除终端输出，并将我们的 SSH 密钥放在 Heroku 上，有点像我们在 GitHub 上所做的，只是这次我们可以通过命令行来完成。所以这将更容易。为了将我们的本地密钥添加到 Heroku，我们将运行`heroku keys:add`命令。这将扫描我们的 SSH 目录并添加密钥：

```js
heroku keys:add
```

在这里，您可以看到它找到了`id_rsa.pub`文件的密钥：您想将其上传到 Heroku 吗？。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/dc07ba5a-58fb-4d94-8add-6f48a20f0abe.png)

输入`Yes`并按*enter*：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8557ad60-5ff6-47f9-b610-2af46bc03f0f.png)

现在我们已经上传了我们的密钥。就是这么简单。比配置 GitHub 要容易得多。从这里开始，我们可以使用`heroku keys`命令来打印当前在我们账户上的所有密钥：

```js
heroku keys
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5f26c53d-81eb-455c-8a04-6c36a39ac379.png)

我们总是可以使用`heroku keys:remove`命令删除它们，后面跟着与该密钥相关的电子邮件。在这种情况下，我们将保留我们拥有的 Heroku 密钥。接下来，我们可以使用`v`标志和`git@heroku.com`测试我们的连接使用 SSH：

```js
ssh -v git@heroku.com
```

这将与 Heroku 服务器通信：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8663a61d-95a4-452e-9a8e-5c7ebd46d3f2.png)

如图所示，我们可以看到它正在询问同样的问题：主机'heroku.com'的真实性无法确定，您确定要继续连接吗？输入`Yes`。

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f1b7981c-4ee5-4b44-bb73-694e952531d4.png)

现在当您运行该命令时，您将得到大量的加密输出。您要寻找的是认证成功，然后在括号中的公钥。如果事情没有进行顺利，您将看到权限被拒绝的消息，括号中有公钥。在这种情况下，认证是成功的，这意味着我们可以继续。我将再次运行 clear，清除终端输出。

# 在 Heroku 的应用程序代码中设置

现在我们可以把注意力转向应用程序代码，因为在我们可以部署到 Heroku 之前，我们需要对代码进行两处更改。这些是 Heroku 希望您的应用程序具备的东西，以便正常运行，因为 Heroku 会自动执行很多操作，这意味着您必须为 Heroku 设置一些基本的东西。这并不复杂——一些非常简单的更改，一些一行代码。

# 在`server.js`文件中的更改

首先，在`server.js`文件的最底部，我们有端口和我们的`app.listen`静态编码在`server.js`中：

```js
app.listen(3000, () => {
  console.log('Server is up on port 3000');
});
```

我们需要使这个端口动态化，这意味着我们想要使用一个变量。我们将使用 Heroku 将设置的环境变量。Heroku 将告诉您的应用程序使用哪个端口，因为随着部署应用程序，该端口将发生变化，这意味着我们将使用该环境变量，这样我们就不必每次部署时都要更换我们的代码。

使用环境变量，Heroku 可以在操作系统上设置一个变量。您的 Node 应用程序可以读取该变量，并将其用作端口。现在所有的机器都有环境变量。您实际上可以通过在 Linux 或 macOS 上运行`env`命令或在 Windows 上运行`set`命令来查看您的机器上的环境变量。

当您这样做时，您将得到一个非常长的键值对列表，这就是所有环境变量的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3a25bfd6-231b-4e72-a147-c99bec678e14.png)

在这里，我有一个 LOGNAME 环境变量设置为 Andrew。我有一个 HOME 环境变量设置为我的主目录，还有各种各样的环境变量在我的操作系统中。

Heroku 将设置其中一个叫做`PORT`的变量，这意味着我们需要去获取那个`port`变量，并在`server.js`中使用它，而不是 3000。在`server.js`文件的顶部，我们需要创建一个叫做`port`的常量，这将存储我们将用于应用程序的端口：

```js
const express = require('express');.
const hbs = require('hbs');
const fs = require('fs');

const port
```

现在我们要做的第一件事是从`process.env`中获取一个端口。`process.env`是一个存储所有环境变量的键值对的对象。我们正在寻找一个 Heroku 将设置的叫做`PORT`的变量：

```js
const port = process.env.PORT;
```

这对 Heroku 来说将会很好，但是当我们在本地运行应用程序时，`PORT`环境变量将不存在，因此我们将使用这个语句中的 OR (`||`)运算符来设置默认值。如果`process.env.port`不存在，我们将把端口设置为`3000`：

```js
const port = process.env.PORT || 3000;
```

现在我们有一个配置为与 Heroku 一起工作并在本地运行的应用程序，就像以前一样。我们所要做的就是取`PORT`变量，并在`app.listen`中使用它，而不是`3000`。如所示，我将引用`port`，并在我们的消息中，我将用模板字符串替换它，现在我可以用注入的端口变量替换`3000`，这将随时间变化：

```js
app.listen(port, () => {
  console.log(`Server is up on port ${port}`);
});
```

有了这个设置，我们现在已经解决了应用程序的第一个问题。我现在将从终端中运行`node server.js`，就像我们在上一章中做的那样：

```js
node server.js
```

我们仍然会得到完全相同的消息：服务器在端口 3000 上运行，所以您的应用程序在本地仍然可以正常工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/74024ce3-1f81-4925-8a6a-b45c66f20a81.png)

# 在 package.json 文件中的更改

接下来，我们必须在`package.json`中指定一个脚本。在`package.json`中，您可能已经注意到我们有一个`scripts`对象，在其中我们有一个`test`脚本。

这是 npm 默认设置的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a1ceea77-ec80-431a-b609-5934b8e619c4.png)

我们可以在`scripts`对象内创建各种脚本，做任何我们喜欢的事情。脚本只不过是我们从终端运行的命令，所以我们可以把这个命令`node server.js`转换成一个脚本，这正是我们要做的。

在`scripts`对象内，我们将添加一个新的脚本。脚本需要被命名为`start`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b838a47f-aff9-48e1-a2a9-2ea8270104de.png)

这是一个非常特定的内置脚本，我们将把它设置为启动我们应用程序的命令。在这种情况下，它将是`node server.js`：

```js
"start": "node server.js"
```

这是必要的，因为当 Heroku 尝试启动我们的应用程序时，它不会使用您的文件名运行 Node，因为它不知道您的文件名叫什么。相反，它将运行启动脚本，启动脚本将负责执行正确的操作；在这种情况下，启动服务器文件。

现在我们可以使用终端中的`start`脚本来运行我们的应用程序，使用以下命令：

```js
npm start
```

当我这样做时，我们会得到与 npm 相关的一些输出，然后我们会得到服务器在端口 3000 上运行的消息，如果我们在浏览器中访问应用程序，一切都与上一章中完全相同：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/20eb655f-3457-44f5-a41b-7ec954e7ce69.png)![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/12aa3060-6ae5-4fd9-92ca-da30a03042bd.png)

最大的区别是我们现在已经准备好使用 Heroku 了。我们也可以使用终端运行`npm test`来运行测试脚本：

```js
npm test
```

现在，我们没有指定任何测试，这是预期的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/504c1768-8ee0-44d9-aba9-cbf61852fef3.png)

# 在 Heroku 中进行提交

该过程的下一步将是进行提交，然后我们最终可以开始将其上载到 Web 上。从终端，我们将使用本章前面探讨过的一些 Git 命令。首先是`git status`。当我们运行`git status`时，我们会看到一些新的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/63fd7620-9bac-46ac-bf81-1809739a6d38.png)

这里显示的代码输出中，我们不是有新文件，而是有修改过的文件。我们有一个修改过的`package.json`文件和一个修改过的`server.js`文件。如果我们现在运行`git commit`，这些将不会被提交；我们仍然需要使用`git add`。我们将运行`git add`并使用点作为下一个参数。点将添加所有显示的每一样东西，并将状态添加到下一个提交。

现在我只建议使用`Changes not staged for commit`标题中列出的所有内容的语法。这些是您实际想要提交的内容，在我们的情况下，这确实是我们想要的。如果我运行`git add`，然后重新运行`git status`，我们现在可以看到下一个将要提交的内容，在`Changes to be committed`标题下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/40663077-fbf3-49af-b2a6-b10557614460.png)

这里有我们的`package.json`文件和`server.js`文件。现在我们可以继续进行提交。

我将运行`git commit`命令，并使用`m`标志来指定我们的消息，对于这个提交，一个好的消息可能是`设置启动脚本和 heroku 端口`：

```js
git commit -m 'Setup start script and heroku port'
```

现在我们可以继续运行该命令，这将进行提交。

现在我们可以使用`git push`命令将其推送到 GitHub，我们可以省略`origin`远程，因为 origin 是默认远程。我将继续运行以下命令：

```js
git push
```

这将把它推送到 GitHub，现在我们准备实际创建应用程序，将我们的代码推送上去，并在浏览器中查看它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/11cc1707-de4f-48ff-9f19-e019aa29aceb.png)

# 运行 Heroku 创建命令

该过程的下一步是从终端运行一个名为`heroku create`的命令。`heroku create`需要在应用程序内部执行：

```js
heroku create
```

就像我们运行 Git 命令一样，当我运行`heroku create`时，会发生一些事情：

+   首先，它将在 Heroku Web 应用程序中创建一个真正的新应用程序

+   它还将向您的 Git 存储库添加一个新的远程

现在记住我们有一个指向我们 GitHub 存储库的 origin 远程。我们将有一个指向我们 Heroku Git 存储库的 Heroku 远程。当我们部署到 Heroku Git 存储库时，Heroku 将会看到。它将接受更改并将其部署到 Web 上。当我们运行 Heroku create 时，所有这些都会发生：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/0ad124db-be01-4728-bdc8-0c3db0ef11b5.png)

现在我们仍然需要将其推送到这个 URL，以实际执行部署过程，我们可以使用`git push`后跟`heroku`来完成：

```js
git push heroku
```

刚刚添加的全新远程是因为我们运行了`heroku create`。现在这次推送将按照正常流程进行。然后您将开始看到一些日志。

这些是来自 Heroku 的日志，让您知道您的应用程序是如何部署的。它正在进行整个过程，向您展示沿途发生了什么。这将花费大约 10 秒，在最后我们有一个成功的消息—验证部署...完成：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a1e756eb-5400-47c9-b211-2796c92b01b1.png)

它还验证了应用程序成功部署，并且确实通过了。从这里，我们实际上有一个可以访问的 URL（[`sleepy-retreat-32096.herokuapp.com/`](https://sleepy-retreat-32096.herokuapp.com/)）。我们可以复制它，粘贴到浏览器中。我将使用以下命令：

```js
heroku open
```

`heroku open`将在默认浏览器中打开 Heroku 应用程序。当我运行这个命令时，它会切换到 Chrome，我们的应用程序会如预期般显示出来：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/16c3c634-0e1b-4641-9328-a913db1d08a0.png)

我们可以在页面之间切换，一切都像在本地一样工作。现在我们有一个 URL，这个 URL 是由 Heroku 给我们的。这是 Heroku 生成应用程序 URL 的默认方式。如果您有自己的域名注册公司，您可以继续配置其 DNS 以指向此应用程序。这将让您为 Heroku 应用程序使用自定义 URL。您将不得不参考您的域名注册商的具体说明来做到这一点，但这确实是可以做到的。

现在我们已经完成了这一步，成功地将我们的 Node 应用程序部署到 Heroku 上，并且这真是太棒了。为了做到这一点，我们所要做的就是提交更改我们的代码并将其推送到一个新的 Git 远程。部署我们的代码再也不会更容易了。

您还可以通过转到 Heroku 仪表板来管理您的应用程序。如果您刷新一下，您应该会在仪表板的某个地方看到全新的 URL。记住我的是 sleepy retreat。你的会是其他的。如果我点击 sleepy retreat，我就可以查看应用程序页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/db13379f-d9eb-44f0-9b39-6dd4bc8c2f3b.png)

在这里，我们可以进行很多配置。我们可以管理活动和访问权限，这样我们就可以与他人合作。我们有指标，我们有资源，各种真正酷的东西。有了这个，我们现在已经完成了基本的部署部分。

在下一节中，您的挑战将是再次经历这个过程。您将对 Node 应用程序进行一些更改。您将提交它们，部署它们，并在 Web 上实时查看它们。我们将首先创建本地更改。这意味着我将在这里使用`app.get`注册一个新的 URL。

我们将创建一个新的页面/projects，这就是为什么我将其作为我的 HTTP get 处理程序的路由。在第二个参数中，我们可以指定我们的`callback`函数，它将被调用并传入请求和响应，就像我们对上面的其他路由，根路由和 about 路由一样，我们将调用`response.render`来渲染我们的模板。在渲染参数列表中，我们将提供两个。

第一个将是文件名。文件不存在，但我们仍然可以继续调用`render`。我会称它为`projects.hbs`，然后我们可以指定要传递给模板的选项。在这种情况下，我们将设置页面标题，将其设置为`Projects`，P 要大写。太棒了！现在，服务器文件已经全部完成了。那里不会再有更多的更改了。

我将继续前往`views`目录，创建一个名为`projects.hbs`的新文件。在这里，我们将能够配置我们的模板。首先，我将从 about 页面复制模板。因为它非常相似，我会复制它。关闭 about，粘贴到 projects，然后我只会更改这个文本为项目页面文本将在这里。然后我们可以保存文件并进行最后的更改。

我们想要做的最后一件事是更新页眉。我们现在有一个位于`/projects`的全新项目页面。所以我们要继续并将其添加到页眉链接列表中。在这里，我会创建一个新的段落标签，然后我会创建一个锚标签。链接的文本将是`Projects`，P 要大写，`href`是链接被点击时要访问的 URL。我们将把它设置为`/projects`，就像我们为 about 设置为`/about`一样。

现在我们已经完成了这一切，所有的更改都已经完成，我们准备在本地测试。我将使用`server.js`文件在本地启动应用程序。首先，我们在 localhost 3000 上启动。因此，在浏览器中，我可以切换到 localhost 标签页，而不是 Heroku 应用标签页，然后单击刷新。在这里，我们有主页，指向主页，我们有关于，指向关于，我们有项目，确实指向`/projects`，呈现项目页面。项目页面的文本将在这里。有了这个，我们现在在本地完成了。

我们已经做出了更改，已经测试过了，现在是时候进行提交了。这将在终端内进行。我将关闭服务器并运行 Git 状态。这将显示我仓库中自上次提交以来的所有更改。我有两个修改过的文件：服务器文件和标题文件，还有我的全新项目文件。所有这些看起来都很好。我想将所有这些添加到下一个提交中，所以我可以使用`Git add .`来做到这一点。

现在在我实际进行提交之前，我确实想通过运行 Git 状态来测试是否添加了正确的内容。在这里，我可以看到要提交的更改显示为绿色。一切看起来都很好。接下来，我们将运行 Git 提交来实际进行提交。这将把所有更改保存到 Git 仓库中。这次提交的消息可能是添加一个项目页面。

提交完成后，下一步需要做的是将其推送到 GitHub。这将备份我们的代码并让其他人进行协作。我将使用 Git push 来做到这一点。记住，我们可以省略 origin 远程，因为 origin 是默认远程，所以如果你省略远程，它仍然会使用默认的远程。

更新了我们的 GitHub 仓库，最后要做的事情就是部署到 Heroku，我们可以通过 Git push 将 Git 仓库推送到 Heroku 远程。当我们这样做时，我们会得到一长串日志，因为 Heroku 服务器正在安装我们的 npm 模块，构建应用程序，并实际部署它。一旦完成，我们将回到终端，然后可以在浏览器中打开 URL。现在我可以从这里复制它，或者运行 Heroku open。由于我已经在浏览器中打开了 URL，我只需刷新一下。现在你可能会在刷新应用程序时遇到一些延迟。有时，在部署新应用程序后立即启动应用程序可能需要大约 10 到 15 秒。这只会在第一次访问时发生。其他时候，当你点击刷新按钮时，它应该立即重新加载。

现在我们有了项目页面，如果我访问它，一切看起来都很棒。导航栏运行良好，项目页面确实在`/projects`处呈现。有了这个，我们现在完成了。我们已经完成了添加新功能、在本地测试、进行 Git 提交、推送到 GitHub 并部署到 Heroku 的过程。现在我们有了一个使用 Node.js 构建真实网络应用的工作流程。这也标志着本节的结束。

# 总结

你也学到了 Git、GitHub 和 Heroku。这些是我在创建应用程序时喜欢使用的工具。我喜欢使用 Git，因为它非常流行。这基本上是当今唯一的选择。我喜欢使用 GitHub，因为它有一个很棒的用户界面。它拥有大量令人惊叹的功能，几乎每个人都在使用它。有一个很棒的社区。我喜欢使用 Heroku，因为它非常简单，可以轻松部署应用程序的新版本。你可以用其他工具替换这些工具。你可以使用亚马逊网络服务等服务进行托管。你可以使用 Bitbucket 作为 GitHub 的替代品。这些都是完全可以接受的解决方案。真正重要的是你有一些适合你的工具，你有一个 Git 仓库在某个地方备份，无论是 GitHub 还是 Bitbucket，你有一个简单的部署方式，这样你就可以快速进行更改并将其快速推送给用户。

在不同的章节中，我们学习了如何将文件添加到 Git 以及如何进行第一次提交。接下来，我们设置了 GitHub 和 Heroku，然后学习了如何推送我们的代码并部署它。然后，我们学习了如何与 Heroku 通信以部署我们的代码。之后，我们学习了一些实际的工作流程，用于创建新的提交，推送到 GitHub，并部署到 Heroku。

在下一章中，我们将学习如何测试我们的应用程序。


# 第十章：测试 Node 应用程序-第一部分

在本章中，我们将看一下如何测试我们的代码，以确保它按预期工作。现在，如果您曾经为其他语言设置过测试用例，那么您就知道开始可能有多么困难。您必须设置实际的测试基础设施。然后您必须编写您的各个测试用例。每次我没有测试一个应用程序，都是因为设置过程和可用工具对我来说是如此繁重。然后您在网上搜索信息，您会得到一些非常简单的例子，但不是用于测试异步代码等真实世界事物的例子。我们将在本章中做所有这些。我将为您提供一个非常简单的测试设置和编写测试用例。

我们将会看一下最好的可用工具，这样你就会真正兴奋地编写这些测试用例，并看到所有那些绿色的勾号。从现在开始我们也会进行测试，所以让我们深入研究一下如何测试一些代码。

# 基本测试

在这一部分，您将创建您的第一个测试用例，以便测试您的代码是否按预期工作。通过将自动测试添加到我们的项目中，我们将能够验证函数是否按其所说的那样工作。如果我们创建一个应该将两个数字相加的函数，我们可以自动验证它是否正在执行这个操作。如果我们有一个应该从数据库中获取用户的函数，我们也可以确保它正在执行这个操作。

现在在本节中开始，我们将看一下在 Node.js 项目中设置测试套件的基础知识。我们将测试一个真实世界的函数。

# 安装测试模块

为了开始，我们将创建一个目录来存储本章的代码。我们将在桌面上使用`mkdir`创建一个目录，并将其命名为`node-tests`：

```js
mkdir node-tests
```

然后我们将使用`cd`更改其中的目录，这样我们就可以运行`npm init`。我们将安装模块，这将需要一个`package.json`文件：

```js
cd node-tests

npm init
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/584340e3-28e2-4603-a985-6fa4ec7f1654.png)

我们将使用默认值运行`npm init`，在每一步中只需简单地按下*enter*：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2276dd53-3b2e-41ad-ab4b-b70728616f3c.png)

现在一旦生成了`package.json`文件，我们就可以在 Atom 中打开该目录。它在桌面上，名为`node-tests`。

从这里开始，我们准备实际定义我们想要测试的函数。本节的目标是学习如何为 Node 项目设置测试，因此我们将要测试的实际函数将会相当琐碎，但这将帮助说明如何设置我们的测试。

# 测试一个 Node 项目

让我们开始制作一个虚假模块。这个模块将有一些函数，我们将测试这些函数。在项目的根目录中，我们将创建一个全新的目录，我将把这个目录命名为`utils`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/91f6a6aa-0422-4de1-b593-62b42deb4787.png)

我们可以假设这将存储一些实用函数，比如将一个数字加到另一个数字上，或者从字符串中去除空格，任何不属于任何特定位置的混杂物。我们将在`utils`文件夹中创建一个名为`utils.js`的新文件，这与我们在上一章中创建`weather`和`location`目录时所做的类似模式：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/503f66d8-7558-4525-9aec-8c92b0a1bb99.png)

您可能想知道为什么我们有一个同名的文件夹和文件。当我们开始测试时，这将变得清晰。

现在在我们可以编写我们的第一个测试用例来确保某些东西工作之前，我们需要有东西来测试。我将创建一个非常基本的函数，它接受两个数字并将它们相加。我们将创建一个如下所示的加法器函数：

```js
module.exports.add = () => {

}
```

这个箭头函数(`=>`)将接受两个参数`a`和`b`，在函数内部，我们将返回值`a + b`。这里没有太复杂的东西：

```js
module.exports.add = () => {
  return a + b;
};
```

现在，由于我们在箭头函数(`=>`)内只有一个表达式，并且我们想要返回它，我们实际上可以使用箭头函数(`=>`)表达式语法，这使我们可以添加我们的表达式，如下面的代码所示，`a + b`，它将被隐式返回：

```js
module.exports.add = (a, b) => a + b;
```

在函数上不需要显式添加`return`关键字。现在我们已经准备好`utils.js`，让我们来探索测试。

我们将使用一个名为 Mocha 的框架来设置我们的测试套件。这将让我们配置我们的单个测试用例，并运行所有的测试文件。这对于创建和运行测试非常重要。我们的目标是使测试变得简单，我们将使用 Mocha 来实现这一点。现在我们有了一个文件和一个我们真正想要测试的函数，让我们来探索如何创建和运行测试套件。

# Mocha - 测试框架

我们将使用超级流行的测试框架 Mocha 进行测试，您可以在[mochajs.org](https://mochajs.org/)找到它。这是一个创建和运行测试套件的绝佳框架。它非常受欢迎，他们的页面上包含了有关设置、配置以及所有酷炫功能的所有信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8ef865ef-3a75-4f15-bce3-cc3dd95785f5.png)

如果您在此页面上滚动，您将能够看到目录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fa505fff-2c7e-46bb-ad6e-43d622059cd7.png)

在这里，您可以探索 Mocha 提供的所有功能。我们将在本章中涵盖大部分内容，但对于我们未涵盖的任何内容，我希望您知道您可以在此页面上了解到。

现在我们已经探索了 Mocha 文档页面，让我们安装它并开始使用它。在终端中，我们将安装 Mocha。首先，让我们清除终端输出。然后我们将使用`npm install`命令进行安装。当您使用`npm install`时，您也可以使用快捷方式`npm i`。这具有完全相同的效果。我将使用`npm i`与`mocha`，指定版本`@3.0.0`。这是拍摄时的最新版本：

```js
npm i mocha@3.0.0
```

现在我们确实希望将其保存到`package.json`文件中。以前，我们使用了`save`标志，但我们将讨论一个新标志，称为`save-dev`。`save-dev`标志将仅为开发目的保存此软件包 - 这正是 Mocha 的用途。我们实际上不需要 Mocha 在像 Heroku 这样的服务上运行我们的应用程序。我们只需要在本地机器上使用 Mocha 来测试我们的代码。 

当您使用`save-dev`标志时，它会以相同的方式安装模块：

```js
npm i mocha@5.0.0 --save-dev
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d3d4bba5-1689-45b2-a839-d163e8cd6131.png)

但是，如果您查看`package.json`，您会发现情况有所不同。在我们的`package.json`文件中，我们有一个`devDependencies`属性，而不是一个 dependencies 属性：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/732a982a-a748-4705-9bad-ce655510abc2.png)

在这里，我们有 Mocha，版本号作为值。`devDependencies`非常棒，因为它们不会安装在 Heroku 上，但它们将在本地安装。这将使 Heroku 的启动时间非常快。它不需要安装实际上不需要的模块。从现在开始，我们将在大多数项目中同时安装`devDependencies`和`dependencies`。

# 为 add 函数创建一个测试文件

现在我们已经安装了 Mocha，我们可以继续创建一个测试文件。在`utils`文件夹中，我们将创建一个名为`utils.test.js`的新文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a48c09b3-f218-4fb9-925f-47c9b04e15bb.png)

这个文件将存储我们的测试用例。我们不会将测试用例存储在`utils.js`中。这将是我们的应用程序代码。相反，我们将创建一个名为`utils.test.js`的文件。当我们使用这个`test.js`扩展名时，我们基本上告诉我们的应用程序，这将存储我们的测试用例。当 Mocha 在我们的应用程序中寻找要运行的测试时，它应该运行任何具有此扩展名的文件。

现在我们有一个测试文件，唯一剩下的事情就是创建一个测试用例。测试用例是运行一些代码的函数，如果一切顺利，测试被认为是通过的。如果事情不顺利，测试被认为是失败的。我们可以使用`it`创建一个新的测试用例。这是 Mocha 提供的一个函数。我们将通过 Mocha 运行我们的项目测试文件，所以没有理由导入它或做任何类似的事情。我们只需要像这样调用它：

```js
it();
```

现在它让我们定义一个新的测试用例，并且它需要两个参数。这些是：

+   第一个参数是一个字符串

+   第二个参数是一个函数

首先，我们将有一个关于测试具体做什么的字符串描述。如果我们正在测试加法函数是否有效，我们可能会有类似以下的内容：

```js
it('should add two numbers');
```

请注意这里与句子相符。它应该读起来像这样，`it should add two numbers`；准确描述了测试将验证的内容。这被称为**行为驱动开发**，或**BDD**，这是 Mocha 构建的原则。

现在我们已经设置了测试字符串，下一步是将一个函数添加为第二个参数：

```js
it('should add two numbers', () => {

});
```

在这个函数内部，我们将添加测试 add 函数是否按预期工作的代码。这意味着它可能会调用`add`并检查返回的值是否是给定的两个数字的适当值。这意味着我们确实需要在顶部导入`util.js`文件。我们将创建一个常量，称为`utils`，将其设置为从`utils`中获取的返回结果。我们使用`./`，因为我们将要求一个本地文件。它在同一个目录中，所以我可以简单地输入`utils`而不需要`js`扩展名，如下所示：

```js
const utils = require('./utils');

it('should add two numbers', () => {

});
```

现在我们已经加载了 utils 库，在回调函数内部我们可以调用它。让我们创建一个变量来存储返回的结果。我们将称之为 results。然后我们将它设置为`utils.add`，传入两个数字。让我们使用类似`33`和`11`的数字：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);
});
```

我们期望得到`44`。现在在这一点上，我们的测试套件内确实有一些代码，所以我们运行它。我们将通过在`package.json`中配置我们在上一章中看到的测试脚本来实现这一点。

目前，测试脚本只是简单地在屏幕上打印一条消息，说没有测试存在。我们要做的是调用 Mocha。如下面的代码所示，我们将调用 Mocha，将我们想要测试的实际文件作为唯一的参数传递进去。我们可以使用通配符模式来指定多个文件。在这种情况下，我们将使用`**`来查找每个目录中的文件。我们正在寻找一个名为`utils.test.js`的文件：

```js
"scripts": {
  "test": "mocha **/utils.test.js"
},
```

现在这是一个非常具体的模式。这不会特别有用。相反，我们也可以用星号替换文件名。现在我们正在寻找项目中以`.test.js`结尾的任何文件：

```js
"scripts": {
  "test": "mocha **/*.test.js"
},
```

这正是我们想要的。从这里，我们可以通过保存`package.json`并转到终端来运行我们的测试套件。我们将使用`clear`命令来清除终端输出，然后我们可以运行我们的`test`脚本，使用如下所示的命令：

```js
npm test
```

当我们运行这个时，我们将执行那个 Mocha 命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a3119576-d86c-4ad2-834f-c55d42ee1617.png)

它会触发。它将获取我们所有的测试文件。它将运行所有这些文件，并在终端内打印结果，就像前面的截图中显示的那样。在这里，我们可以看到我们的测试旁边有一个绿色的勾号，`should add two numbers`。接下来，我们有一个小结，一个通过的测试，在 8 毫秒内完成。

现在在我们的情况下，我们实际上并没有断言关于返回的数字的任何内容。它可以是 700，我们也不在乎。测试将始终通过。要使测试失败，我们需要抛出一个错误。这意味着我们可以抛出一个新的错误，并将我们想要用作错误的消息传递给构造函数，如下面的代码块所示。在这种情况下，我可以说类似`值不正确`的内容：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);
  throw new Error('Value not correct')
});
```

现在有了这个，我可以保存测试文件，并从终端重新运行测试，通过重新运行`npm test`，现在我们有 0 个通过的测试和 1 个失败的测试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/6e79b1dd-204b-4b42-8ef9-cd2f4eedebf7.png)

接下来，我们可以看到一个测试是应该添加两个数字，我们得到了我们的错误消息，值不正确。当我们抛出一个新的错误时，测试失败了，这正是我们想要为`add`做的。

# 为测试创建 if 条件

现在，我们将为测试创建一个`if`语句。如果响应值不等于`44`，那意味着我们有麻烦了，我们将抛出一个错误：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  if (res != 44){

  }
});
```

在`if`条件内部，我们可以抛出一个新的错误，我们将使用模板字符串作为我们的消息字符串，因为我确实想要在错误消息中使用返回的值。我会说`Expected 44, but got`，然后我会注入实际的值，无论发生什么：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  if (res != 44){
    throw new Error(`Expected 44, but got ${res}.`);
  }
});
```

现在在我们的情况下，一切都会很顺利。但是如果`add`方法没有正确工作会怎么样呢？让我们通过简单地添加另一个加法来模拟这种情况，在`utils.js`中添加上类似`22`的东西：

```js
module.exports.add = (a, b) => a + b + 22;
```

我会保存文件，重新运行测试套件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fc218425-26d3-4080-b0c2-449f70e511e4.png)

现在我们得到了一个错误消息：期望得到 44，但得到了 66。这个错误消息很棒。它让我们知道测试出了问题，甚至告诉我们确切得到了什么，以及我们期望得到了什么。这将让我们进入`add`函数，寻找错误，并希望修复它们。

创建测试用例不需要非常复杂。在这种情况下，我们有一个简单的测试用例，测试一个简单的函数。

# 测试平方函数

现在，我们将创建一个新的函数，它对一个数字进行平方并返回结果。我们将在`utils.js`文件中定义，使用`module.exports.square`。我们将把它设置为一个箭头函数(`=>`)，它接受一个数字`x`，然后我们返回`x`乘以`x`，`x * x`，就像这样：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;
```

现在我们有了这个全新的`square`函数，我们将创建一个新的测试用例，确保`square`按预期工作。在`utils.test.js`中，在`add`函数的`if`条件旁边，我们将再次调用`it`函数：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  if (res != 44){
    throw new Error(`Expected 44, but got ${res}.`);
  }
});

it();
```

在`it`函数内部，我们将添加我们的两个参数，字符串和回调函数。在字符串内部，我们将创建我们的消息，`should square a number`：

```js
it('should square a number', () => {

});
```

在回调函数内部，我们实际上可以继续调用`square`。现在我们确实想要创建一个变量来存储结果，以便我们可以检查结果是否符合预期。然后我们可以调用`utils.square`传入一个数字。在这种情况下，我会选择`3`，这意味着我应该期望返回`9`：

```js
it('should square a number', () => {
  var res = utils.square(3);
});
```

在下一行，我们可以有一个`if`语句，如果结果不等于`9`，那么我们会抛出一个消息，因为事情出错了：

```js
it('should square a number', () => {
  var res = utils.square(3);

  if (res !== 9) {

  }
});
```

我们可以使用`throw new Error`抛出错误，传入任何我们喜欢的消息。我们可以使用普通字符串，但我总是更喜欢使用模板字符串，这样我们可以轻松地注入值。我会说类似于`Expected 9, but got`，后面跟着不正确的值；在这种情况下，这个值存储在响应变量中：

```js
it('should square a number', () => {
  var res = utils.square(3);

  if (res !== 9) {
    throw new Error(`Expected 9, but got ${res}`);
  }
});
```

现在我可以保存这个测试用例，并从终端运行测试套件。使用上箭头键和*enter*键，我们可以重新运行上一个命令：

```js
npm test
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/f9f81971-f62f-4d66-b24b-28de4fbf9eef.png)

我们得到了两个通过的测试，应该添加两个数字和应该对一个数字进行平方都有对号。而且我们只用了 14 毫秒运行了两个测试，这太棒了。

现在，下一件事，我们想要做的是搞砸`square`函数，以确保当数字不正确时我们的测试失败。我会在`utils.js`中的结果上加`1`，这将导致测试失败：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x + 1;
```

然后我们可以从终端重新运行测试，我们应该会看到错误消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d97536cd-561d-4137-87b2-e23a7c65b50a.png)

我们得到了预期的 9，但得到了 10。这太棒了。我们现在有一个能够测试`add`函数和`square`函数的测试套件。我将删除那个`+ 1`，然后我们就完成了。

我们现在有一个非常非常基本的测试套件，我们可以使用 Mocha 执行。目前，我们有两个测试，并且为了创建这些测试，我们使用了 Mocha 提供的`it`方法。在接下来的部分中，我们将探索 Mocha 给我们的更多方法，并且我们还将寻找更好的方法来进行断言。我们将使用一个断言库来帮助完成繁重的工作，而不是手动创建它们。

# 自动重新启动测试

在编写更多测试用例之前，让我们看一种自动重新运行测试套件的方法，当我们更改测试代码或应用程序代码时。我们将使用`nodemon`来实现这一点。现在，我们之前是这样使用`nodemon`的：

```js
nodemon app.js
```

我们将输入`nodemon`，然后传入一个文件，如`app.js`。每当我们应用程序中的任何代码更改时，它将重新运行`app.js`文件作为 Node 应用程序。实际上，我们可以指定我们想要在文件更改时运行的世界上的任何命令。这意味着我们可以在文件更改时重新运行`npm test`。

为此，我们将使用`exec`标志。此标志告诉`nodemon`我们将指定要运行的命令，它可能不一定是一个 Node 文件。如下命令所示，我们可以指定该命令。它将是`'npm test'`：

```js
nodemon --exec 'npm test'
```

如果您使用 Windows，请记住使用双引号代替单引号。

现在，我们可以运行`nodemon`命令。它将首次运行我们的测试套件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/52e75c77-16e7-4be1-bc90-2ce1e09df52b.png)

在这里，我们看到有两个测试通过。让我们继续进入应用程序`utils.js`，并对其中一个函数进行更改，以便它失败。我们将为`add`的结果添加`3`或`4`：

```js
module.exports.add = (a, b) => a + b + 4;

module.exports.square = (x) => x * x;
```

它会自动重新启动：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/81443c9b-d50d-4ae9-a1ed-25ef54e1b1df.png)

现在我们看到我们有一个测试套件，其中一个测试通过，一个测试失败。我可以随时撤消我们添加的错误，保存文件，测试套件将自动重新运行。

这将使测试应用程序变得更加容易。每当我们对应用程序进行更改时，我们就不必切换到终端并重新运行`npm test`命令。现在我们有一个可以运行的命令，我们将关闭`nodemon`并使用上箭头键再次显示它。

我们实际上可以将其移入`package.json`中的一个脚本。

在`package.json`中，我们将在测试脚本之后创建一个新的脚本。现在我们已经使用了`start`脚本和`test`脚本-这些是内置的-我们将创建一个名为`test-watch`的自定义脚本，并且我们可以运行`test-watch`脚本来启动。在`test-watch`中，我们将使用与终端中运行的完全相同的命令。这意味着我们将会使用`nodemon`。我们将使用`exec`标志，并在引号内运行`npm test`：

```js
"scripts": {
  "test": "mocha **/*.test.js",
  "test-watch": "nodemon --exec 'npm test'"
},
```

现在我们已经有了这个，我们可以从终端运行脚本，而不是每次启动自动测试套件时都要输入这个命令。

我们目前在`package.json`中拥有的脚本将在 macOS 和 Linux 上运行。它也将在使用 Linux 的 Heroku 上运行。但它在 Windows 上不起作用。以下脚本将起作用：

`"test-watch": "nodemon --exec \"npm test\""`.

如您所见，我们正在转义围绕`npm test`的引号，并且我们正在使用双引号，正如我们所知，这是 Windows 支持的唯一引号。此脚本将消除您看到的任何错误，例如找不到 npm，如果您将`npm tests`用单引号括起来并在 Windows 上运行脚本时会出现。因此，请使用上述脚本以实现跨操作系统的兼容性。

要在终端中运行具有自定义名称的脚本，例如`test-watch`，我们只需要运行`npm run`，然后是脚本名称`test-watch`，如下命令所示：

```js
npm run test-watch
```

如果我这样做，它会启动。我们将得到我们的测试套件，它仍在等待变化，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9abb5b25-aa06-48bc-b910-8b07bcfd103c.png)

现在，每次你启动测试套件，你可以简单地使用`npm run test-watch`。这将启动`test-watch`脚本，它会启动`nodemon`。每当你的项目发生变化，它都会重新运行`npm test`，并将测试套件的结果显示在屏幕上。

现在我们有了一种自动重新启动测试套件的方法，让我们继续深入了解在 Node 中进行测试的具体内容。

# 在测试 Node 模块中使用断言库

在前面的部分，我们制作了两个测试用例来验证`utils.add`和我们的`utils.square`方法是否按预期工作。我们使用了一个`if`条件来做到这一点，也就是说，如果值不是`44`，那就意味着出了问题，我们就会抛出一个错误。在本节中，我们将学习如何使用一个断言库，它将为我们处理`utils.test.js`代码中的所有`if`条件：

```js
if (res !== 44)
  throw new Error(`Expected 44, but got ${res}.`)
}
```

因为当我们添加越来越多的测试时，代码最终会变得非常相似，没有理由一直重写它。断言库让我们可以对值进行断言，无论是关于它们的类型，值本身，还是数组是否包含元素，诸如此类的各种事情。它们真的很棒。

我们将使用的是 expect。你可以通过谷歌搜索`mjackson expect`来找到它。这就是我们要找的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/db8fec07-660e-4fe8-aaed-8f51c493f29c.png)

这是 mjackson 的存储库，expect。这是一个很棒而且非常受欢迎的断言库。这个库让我们可以传递一个值并对其进行一些断言。在这个页面上，我们可以在介绍和安装之后滚动到一个例子：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/728344df-44fe-4c2e-b48f-77d20eaf4672.png)

如前面的截图所示，我们有我们的断言标题和我们的第一个断言，`toExist`。这将验证一个值是否存在。在下一行，我们有一个例子，我们将一个字符串传递给`expect`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5fb080fa-90b3-4c74-856d-41b77619b2cd.png)

这是我们想要对其进行一些断言的值。在我们的应用程序上下文中，这将是`utils.test.js`中的响应变量，如下所示：

```js
const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);
  if (res !== 44) {
    throw new Error(`Expected 44, but got ${res}.`)
  }
});
```

我们想要断言它是否等于`44`。在我们调用`expect`之后，我们可以开始链接一些断言调用。在下一个断言示例中，我们检查它是否存在：

```js
expect('something truthy').toExist()
```

这不会抛出错误，因为在 JavaScript 中，字符串确实是真值。如果我们传入一些不是`真值`的东西，比如`undefined`，`toExist`会失败。它会抛出一个错误，测试用例不会通过。使用这些断言，我们可以非常轻松地检查测试中的值，而不必自己编写所有的代码。

# 探索断言库

让我们继续开始探索断言库。首先，让我们在终端中运行`npm install`来安装模块。模块名本身叫做 expect，我们将获取最新版本`@1.20.2`。我们将再次使用`save-dev`标志，就像我们在 Mocha 中所做的那样。因为我们确实希望将这个依赖保存在`package.json`中，但它是一个`dev`依赖，不管是在 Heroku 还是其他服务上运行，都不是必需的：

```js
npm install expect@1.20.2 --save-dev
```

`expect`库已经捐赠给了另一个组织。最新版本是 v21.1.0，与我们在这里使用的旧版本 1.20.2 不兼容。我希望你安装 1.20.2 版本，以确保在接下来的几节中使用。

让我们继续安装这个依赖。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b511a1be-49e1-48ed-a0f9-3a2124c7d558.png)

然后我们可以转到应用程序，查看`package.json`文件，如下截图所示，看起来很棒：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d77c03b2-9944-4f4e-a3cd-313fb6fcf88c.png)

我们既有 expect，又有 Mocha。现在，在我们的`utils.test`文件中，我们可以通过加载库并使用 expect 进行第一次断言来启动。在文件的顶部，我们将加载库，创建一个名为`expect`的常量，并`require('expect')`，就像这样：

```js
const expect = require('expect');
```

现在，我们可以通过调用`expect`来替换`utils.test.js`代码中的`if`条件：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  // if(res !== 44) {
  //   throw new Error(`Expected 44, but got ${res}.`)
  //}
});
```

正如你在断言/expect 页面上的示例中看到的，我们将通过调用`expect`作为一个函数来开始所有的断言，传入我们想要进行断言的值。在这种情况下，那就是`res`变量：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  expect(res)
  // if(res !== 44) {
  //   throw new Error(`Expected 44, but got ${res}.`)
  //}
});
```

现在，我们可以断言各种事情。在这种情况下，我们想要断言该值等于`44`。我们将使用我们的断言`toBe`。在文档页面上，它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/07986522-41a9-488c-a795-be6e3f87be25.png)

这断言一个值等于另一个值，这正是我们想要的。我们断言传入 expect 的值等于另一个值，使用`toBe`，将该值作为第一个参数传入。回到 Atom 中，我们可以使用这个断言`.toBe`，我们期望结果变量是数字`44`，就像这样：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  expect(res).toBe(44);
  // if(res !== 44) {
  //   throw new Error(`Expected 44, but got ${res}.`)
  //}
});
```

现在我们有了我们的测试用例，它应该与`if`条件一样正常工作。

为了证明它确实有效，让我们进入终端并使用`clear`命令来清除终端输出。现在我们可以运行`test-watch`脚本，如下命令所示：

```js
npm run test-watch
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e72bdf9c-5f95-4901-8a10-3a4233c84b58.png)

如前面的代码输出所示，我们的两个测试都通过了，就像以前一样。现在，如果我们将`44`更改为像`40`这样的其他值，那么会抛出错误：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  expect(res).toBe(40);
  // if(res !== 44) {
  //   throw new Error(`Expected 44, but got ${res}.`)
  //}
});
```

我们保存文件，然后会得到一个错误，`expect`库将为我们生成有用的错误消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/06d5d04c-a118-49b5-9667-36c1cba16ae3.png)

它说我们预期 44 是 40。显然这不是这样，所以会抛出一个错误。我将把它改回`44`，保存文件，所有的测试都会通过。

# 链接多个断言

现在我们也可以链接多个断言。例如，我们可以断言从`add`返回的值是一个数字。这可以使用另一个断言来完成。所以让我们进入文档看一看。在 Chrome 中，我们将浏览断言文档列表。有很多方法。我们将探索其中一些。在这种情况下，我们正在寻找`toBeA`，这个方法接受一个字符串：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/72f449b0-2275-49a4-b133-aeb0a0b2aa54.png)

这将使用字符串类型，并使用`typeof`运算符来断言该值是某种类型。在这里，我们期望`2`是一个数字。我们可以在我们的代码中做完全相同的事情。在 Atom 中，在`toBe`之后，我们可以链接另一个调用`toBeA`，然后是类型。这可能是字符串，也可能是对象，或者在我们的情况下，可能是一个数字，就像这样：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  expect(res).toBe(44).toBeA('number');
  // if(res !== 44) {
  //   throw new Error(`Expected 44, but got ${res}.`)
  //}
});
```

我们将打开终端，这样我们就可以看到结果。它目前是隐藏的。保存文件。我们的测试将重新运行，我们可以看到它们都通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9c4f3131-3392-4529-b3f5-08f8ae8a8513.png)

让我们使用一个不同的类型，例如会导致测试失败的字符串：

```js
 expect(res).toBe(44).toBeA('string');
```

然后我们会得到一个错误消息，预期 44 是一个字符串：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/148b632f-b576-400e-86d7-7674d0c50863.png)

这真的很有用。它将帮助我们快速清理错误。让我们把代码改回数字，然后就可以开始了。

# 对于 square 函数的多个断言

现在我们想为我们的平方数函数的测试做同样的事情。我们将使用`expect`来断言响应确实是数字`9`，并且类型是一个数字。我们将使用与`add`函数相同的这两个断言。首先，我们需要删除当前的平方`if`条件代码，因为我们将不再使用它。如下所示，我们将对`res`变量做一些期望。我们期望它是数字`9`，就像这样：

```js
it('should square a number', () => {
  var res = utils.square(3);

  expect(res).toBe(9);
});
```

我们将保存文件并确保测试通过，它确实通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7b487bf1-d06d-434b-a50b-8f9c765b1ac0.png)

现在，我们将使用`toBeA`来断言类型。在这里，我们正在检查`square`方法的返回值类型是否为数字：

```js
it('should square a number', () => {
  var res = utils.square(3);

  expect(res).toBe(9).toBeA('number');
});
```

当我们保存文件时，我们仍然通过了我们的两个测试，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7b72f471-5ee4-4ee0-bf06-c9a76ac72b6c.png)

现在这只是一个关于`expect`能做什么的小测试。让我们创建一个虚假测试用例，探索一些我们可以使用`expect`的更多方式。我们将不会测试一个实际的函数。我们只是在`it`回调内部玩一些断言。

# 探索使用 expect 进行虚假测试

要创建虚假测试，我们将使用`it`回调函数创建一个新的测试：

```js
it('should expect some values');
```

我们可以在这里放任何我们想要的东西，这并不太重要。我们将传入一个箭头函数(`=>`)作为我们的回调函数：

```js
it('should expect some values', () => {

});
```

现在正如我们已经看到的，你将做的最基本的断言之一就是检查是否相等。我们想要检查类似响应变量是否等于其他东西，比如数字`44`。在`expect`内部，我们也可以做相反的事情。我们可以期望一个值像`12`不等于，使用`toNotBe`。然后我们可以断言它不等于其他值，比如`11`：

```js
it('should expect some values', () => {
  expect(12).toNotBe(11);
});
```

两者不相等，所以当我们在终端中保存文件时，所有三个测试都应该通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/870d8673-50d1-4c10-8a66-f07723443dc4.png)

如果我将其设置为相同的值，它将无法按预期工作：

```js
it('should expect some values', () => {
  expect(12).toNotBe(12);
});
```

我们会得到一个错误，预期 12 不等于 12：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9cc4d4d4-50a6-40ce-9c22-8e3c5e3abf73.png)

现在`toBe`和`toNotBe`对于数字、字符串和布尔值效果很好，但是如果你试图比较数组或对象，它们将无法按预期工作，我们可以证明这一点。

# 使用 toBe 和 toNotBe 比较数组/对象

我们将从注释掉当前代码开始。我们将保留它，以便稍后使用：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
});
```

我们将`expect`一个具有`name`属性设置为`Andrew`的对象，`toBe`，并且我们将断言它是另一个具有 name 属性等于`Andrew`的对象，就像这样：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  expect({name: 'Andrew'})
});
```

我们将使用`toBe`，就像我们用`number`一样，检查它是否与另一个 name 等于`Andrew`的对象相同：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  expect({name: 'Andrew'}).toBe({name: 'Andrew'});
});
```

现在当我们保存这个文件时，你可能会认为测试会通过，但它并没有：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/57f7879d-4325-48a3-8fb6-66d5fce52a11.png)

如前面的输出所示，我们看到我们期望这两个名称相等。当使用三重等号进行对象比较时，也就是`toBe`使用的方式，它们不会相同，因为它试图看它们是否是完全相同的对象，而它们不是。我们创建了两个具有相同属性的单独对象。

# 使用 toEqual 和 toNotEqual 断言

要检查这两个名称是否相等，我们将不得不使用不同的东西。它被称为`toEqual`，如下所示：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  expect({name: 'Andrew'}).toEqual({name: 'Andrew'});
});
```

如果我们现在保存文件，这将起作用。它将深入对象属性，确保它们具有相同的属性：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d0b3cc75-0879-4062-9987-aef09129e358.png)

`toNotEqual`也是一样的。这检查两个对象是否不相等。为了检查这一点，我们将继续并将第一个对象更改为`andrew`中的小写 a：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
});
```

现在，测试通过了。它们不相等：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/51524f8b-6f39-41df-a287-bae020478cf9.png)

这是我们如何对我们的对象和数组进行相等性比较的方式。现在我们还有一个非常有用的东西，那就是`toInclude`。

# 使用 toInclude 和 toExclude

`toInclude`断言检查数组或对象是否包含一些东西。如果是数组，我们可以检查数组中是否包含某个项目。如果是对象，我们可以检查对象是否包含某些属性。让我们通过一个例子来运行一下。

我们期望在`it`回调中有一个包含数字`2`、`3`和`4`的数组包含数字`5`，我们可以使用`toInclude`来做到这一点：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  expect([2,3,4]).toInclude(5);
});
```

`toInclude`断言接受项目。在这种情况下，我们将检查数组中是否包含`5`。现在显然它没有，所以这个测试将失败：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/be047123-f90a-43e9-9bfd-353d07cf9a68.png)

我们得到消息，期望[ 2, 3, 4]包括 5。那不存在。现在我们把这个改成一个存在的数字，比如`2`：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  expect([2,3,4]).toInclude(2);
});
```

我们将重新运行测试套件，一切都将按预期工作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7a4a5f75-7093-4d79-ae04-57d0e31a12fb.png)

现在，除了`toInclude`，我们还有`toExclude`，就像这样：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  expect([2,3,4]).toExclude(1);
});
```

这将检查某些东西是否不存在，例如数字`1`，它不在数组中。如果我们运行这个断言，测试通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/76187806-132d-4519-9569-5e31fe3216ed.png)

同样的两种方法，`toInclude`和`toExclude`，也适用于对象。我们可以在下一行直接使用。我期望以下对象有一些东西：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  // expect([2,3,4]).toExclude(1);
  expect({

  })
});
```

让我们继续创建一个具有一些属性的对象。这些是：

+   `name`：我们将把它设置为任何名字，比如`Andrew`。

+   `age`：我们将把它设置为年龄，比如`25`。

+   `location`：我们将把它设置为任何位置，例如`Philadelphia`。

这将看起来像以下的代码块：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  // expect([2,3,4]).toExclude(1);
  expect({
    name: 'Andrew',
 age: 25,
 location: 'Philadelphia'
  })
});
```

现在假设我们想对特定属性做一些断言，而不一定是整个对象。我们可以使用`toInclude`来断言对象是否具有某些属性，并且这些属性的值等于我们传入的值：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  // expect([2,3,4]).toExclude(1);
  expect({
    name: 'Andrew',
    age: 25,
    location: 'Philadelphia'
  }).toInclude({

 })
});
```

例如，`age`属性。假设我们只关心年龄。我们可以断言对象具有一个等于`25`的`age`属性，方法是输入以下代码：

```js
it('should expect some values', () => {
  // expect(12).toNotBe(12);
  // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
  // expect([2,3,4]).toExclude(1);
  expect({
    name: 'Andrew',
    age: 25,
    location: 'Philadelphia'
  }).toInclude({
    age: 25
  })
});
```

`name`属性无关紧要。`name`属性可以是任何值。这在这个断言中是无关紧要的。现在让我们使用值`23`：

```js
.toInclude({
    age: 23
  })
```

由于值不正确，这个测试将失败：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/eb2f5516-e01c-49e7-9ffd-db74c5328603.png)

我们期望`age`属性是`23`，但实际上是`25`，所以测试失败。`toExclude`断言也是一样的。

在这里我们可以保存我们的测试文件。这检查对象是否没有一个等于`23`的属性 age。它确实没有，所以测试通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/917b02e0-062b-4e65-bb6b-338229c4ec58.png)

这只是对 expect 能做什么的一个快速了解。关于功能的完整列表，我建议浏览文档。还有很多其他断言可以使用，比如检查一个数字是否大于另一个数字，一个数字是否小于或等于另一个数字，还包括各种与数学相关的操作。

# 测试 setName 方法

现在让我们用一些更多的测试来结束这一节。在`utils.js`中，我们可以创建一个新的函数，一个我们将要测试的函数，`module.exports.setName`。`setName`函数将接受两个参数。它将接受一个`user`对象，一个具有一些通用属性的虚构用户对象，它将接受一个字符串`fullName`：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;

module.exports.setName (user, fullName)
```

`setName`的工作将是将`fullName`分成两部分——名字和姓氏——通过在空格上分割它。我们将设置两个属性，名字和姓氏，并返回`user`对象。我们将填写函数，然后编写测试用例。

我们将首先将名字分割成一个`names`数组，`var names`将是那个数组：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;

module.exports.setName (user, fullName) => {
  var names
};
```

它将有两个值，假设名称中只有一个空格。我们假设有人输入他们的名字，敲击空格，然后输入他们的姓氏。我们将把这个设置为`fullName.split`，然后我们将在空格上分割。所以我将传入一个包含空格的空字符串作为分割的值：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;

module.exports.setName (user, fullName) => {
  var names = fullName.split(' ');
};
```

现在我们有一个`names`数组，其中第一项是`firstName`，最后一项是`lastName`。所以我们可以开始更新`user`对象。`user.firstName`将等于`names`数组中的第一项，我们将获取索引`0`，这是第一项。我们将对`lastName`做类似的操作，`user.lastName`等于`names`数组的第二项：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;

module.exports.setName (user, fullName) => {
  var names = fullName.split(' ');
  user.firstName = names[0];
  user.lastName = names[1];
};
```

现在我们已经完成了，我们已经设置了名称，并且我们可以返回`user`对象，就像这样使用`return` user：

```js
module.exports.add = (a, b) => a + b;

module.exports.square = (x) => x * x;

module.exports.setName (user, fullName) => {
  var names = fullName.split(' ');
  user.firstName = names[0];
  user.lastName = names[1];
  return user;
};
```

在`utils.test`文件中，我们现在可以开始。首先，我们将注释掉我们的`it('should expect some values')`处理程序：

```js
const expect = require('expect');

const utils = require('./utils');

it('should add two numbers', () => {
  var res = utils.add(33, 11);

  expect(res).toBe(44).toBeA('number');
});

it('should square a number', () => {
  var res = utils.square(3);

  expect(res).toBe(9).toBeA('number');
});

// it('should expect some values', () => {
//   // expect(12).toNotBe(12);
//   // expect({name: 'andrew'}).toNotEqual({name: 'Andrew'});
//   // expect([2,3,4]).toExclude(1);
//   expect({
//      name: 'Andrew',
//      age: 25,
//      location: 'Philadelphia'
//    }).toExclude({
//      age: 23
//    })
//  });
```

这对于文档来说非常棒。如果您忘记了事情是如何工作的，您随时可以稍后探索它。我们将创建一个新的测试，应该验证名字和姓氏是否已设置。

我们将创建一个`user`对象。在该`user`对象上，我们想设置一些属性，如`age`和`location`。然后我们将变量`user`传递给`setName`方法。这将是`utils.js`文件中定义的第一个参数。我们将传入一个字符串。这个字符串是`firstName`后面跟着一个空格，然后是`lastName`。然后我们将得到结果，并对其进行一些断言。我们想要断言返回的对象是否包含使用`toInclude`断言。

如下所示的代码，我们将调用它来创建新的测试用例。我们将测试：

```js
it('should set firstName and lastName')
```

在`it`中，我们现在可以提供我们的第二个参数，这将是我们的回调函数。让我们将其设置为箭头函数(`=>`)，现在我们可以创建`user`对象：

```js
it('should set firstName and lastName', () => {

});
```

`user`对象将有一些属性。让我们添加一些像`location`的东西，将其设置为`Philadelphia`，然后设置一个`age`属性，将其设置为`25`：

```js
it('should set firstName and lastName', () => {
  var user = {location: 'Philadelphia', age: 25};
});
```

现在我们将调用我们在`utils.js`中定义的方法，即`setName`方法。我们将在下一行执行这个操作，创建一个名为`res`的变量来存储响应。然后我们将把它设置为`utils.setName`，传入两个参数，即`user`对象和`fullName`，`Andrew Mead`：

```js
it('should set firstName and lastName', () => {
  var user = {location: 'Philadelphia', age: 25};
  var res = utils.setName(user, 'Andrew Mead');
});
```

现在在这一点上，结果应该是我们期望的。我们应该有`firstName`和`lastName`属性。我们应该有`location`属性和`age`属性。

现在，如果您对 JavaScript 了解很多，您可能知道对象是按引用传递的，因此`user`变量实际上也已经更新了。这是预期的。`user`和`res`将具有完全相同的值。我们实际上可以继续使用断言来证明这一点。我们将`expect` `user`等于`res`使用`toEqual`：

```js
it('should set firstName and lastName', () => {
  var user = {location: 'Philadelphia', age: 25};
  var res = utils.setName(user, 'Andrew Mead');

  expect(user).toEqual(res);
});
```

在终端中，我们可以看到测试确实通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/40134642-c54b-48fa-b144-c17a57ca1977.png)

让我们删除`expect(user).toEqual(res);`。现在，我们想要检查`user`对象或`res`对象是否包含某些属性。我们将使用`expect`来检查`res`变量是否具有某些属性，使用`toInclude`：

```js
it('should set firstName and lastName', () => {
  var user = {location: 'Philadelphia', age: 25};
  var res = utils.setName(user, 'Andrew Mead');

  expect(res).toInclude({

 })
});
```

我们要查找的属性是`firstName`等于我们期望的值，即`Andrew`，以及`lastName`等于`Mead`：

```js
it('should set firstName and lastName', () => {
  var user = {location: 'Philadelphia', age: 25};
  var res = utils.setName(user, 'Andrew Mead');

  expect(res).toInclude({
    firstName: 'Andrew',
 lastName: 'Mead'
  })
});
```

这些是应该进行的断言，以验证`setName`是否按预期工作。如果我保存文件，`test`套件将重新运行，我们确实得到了通过的测试，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/da39513e-fd35-4ed0-a94a-7bc08925cbb0.png)

我们有三个，只用了 10 毫秒来运行。

有了这个，我们现在为我们的`test`套件创建了一个断言库。这太棒了，因为编写测试用例变得更加容易，整个章节的目标是使测试变得易于接近和简单。

在下一节中，我们将开始看如何测试更复杂的异步函数。

# 异步测试

在这一部分，您将学习如何测试异步函数。测试异步函数的过程与测试同步函数并没有太大不同，就像我们已经做过的那样，但是有一点不同，所以它有自己的部分。

# 使用 setTimeout 对象创建 asyncAdd 函数

首先，我们将使用`setTimeout`创建一个虚拟的`async`函数，以模拟`utils.js`中的延迟。就在我们创建`add`函数的下面，让我们创建一个叫做`asyncAdd`的函数。它基本上具有相同的特性，但它将使用`setTimeout`，并且它将有一个回调来模拟延迟。现在在现实世界中，这种延迟可能是数据库请求或 HTTP 请求。我们将在接下来的章节中处理这个问题。不过，现在让我们添加`module.exports.asyncAdd`：

```js
module.exports.add = (a, b) => a + b;

module.exports.asyncAdd = ()
```

这将需要三个参数，而不是`add`函数所需的两个参数，`a`，`b`和`callback`：

```js
module.exports.add = (a, b) => a + b;

module.exports.asyncAdd = (a, b, callback)
```

这就是使函数异步的原因。最终，一旦`setTimeout`结束，我们将调用回调函数并传递总和，无论是 1 加 3 得到 4，还是 5 加 9 得到 14。接下来，我们可以在箭头函数（`=>`）中放置箭头并打开和关闭大括号：

```js
module.exports.asyncAdd = (a, b, callback) => {

};
```

如上所述，在箭头函数（`=>`）中，我们将使用`setTimeout`来创建延迟。我们将传递一个回调和我们的`setTimeout`。在这种情况下，我们将使用 1 秒：

```js
module.exports.asyncAdd = (a, b, callback) => {
  setTimeout(() => {

  }, 1000);
};
```

默认情况下，如果我们的测试时间超过 2 秒，Mocha 将认为这不是我们想要的，它将失败。这就是为什么我们在这种情况下使用 1 秒的原因。在我们的回调中，我们可以调用实际的`callback`参数，使用和`b`的和`a`，就像这样：

```js
module.exports.asyncAdd = (a, b, callback) => {
  setTimeout(() => {
    callback(a + b);
  }, 1000);
};
```

现在我们有了一个`asyncAdd`函数，我们可以开始为它编写测试了。

# 为 asyncAdd 函数编写测试

在`utils.test`文件中，就在我们之前对`utils.add`的测试下面，我们将为`asyncAdd`添加一个新的测试。测试设置看起来非常相似。我们将调用`it`并传递一个字符串作为第一个参数，传递一个回调作为第二个参数。然后我们将添加我们的回调，就像这样：

```js
it('should async add two numbers', () => {

});
```

在回调中，我们可以开始调用`utils.asyncAdd`。我们将使用`utils.asyncAdd`调用它，并传入这三个参数。我们将使用`4`和`3`，这应该得到`7`。我们将提供回调函数，它应该被调用并传递该值，该值为`7`：

```js
it('should async add two numbers', () => {
  utils.asyncAdd(4, 3, () => {

  });
});
```

在回调参数中，我们期望像`sum`这样的东西返回：

```js
it('should async add two numbers', () => {
  utils.asyncAdd(4, 3, (sum) => {

  });
});
```

# 对 asyncAdd 函数进行断言

现在我们可以开始对`sum`变量进行一些断言，使用`expect`对象。我们可以将它传递给`expect`来进行我们的断言，这些断言并不是新的。这是我们已经做过的事情。我们将`expect` `sum`变量等于数字`7`，使用`toBe`，然后我们将检查它是否是一个数字，使用`toBeA`，在引号内，`number`：

```js
it('should async add two numbers', () => {
  utils.asyncAdd(4, 3, (sum) => {
    expect(sum).toBe(7).toBeA('number');
  });
});
```

显然，如果它等于`7`，那就意味着它是一个数字，但我们两者都使用只是为了模拟我们的期望调用内部链式调用的工作原理。

现在我们的断言已经就位，让我们保存文件并运行测试，看看会发生什么。我们将从终端运行它，`npm run test-watch`来启动我们的`nodemon`监视脚本：

```js
npm run test-watch
```

现在我们的测试将运行，测试确实通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7a5061b7-3cbd-41cd-9253-c2c8d0a81782.png)

唯一的问题是它通过了错误的原因。如果我们将`7`更改为`10`并保存文件：

```js
it('should async add two numbers', () => {
  utils.asyncAdd(4, 3, (sum) => {
    expect(sum).toBe(10).toBeA('number');
  });
});
```

在这种情况下，测试仍然会通过。在这里，您可以看到我们有四个测试通过：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5ef4f4cd-2e72-43a1-aaa9-b21931ccd1d3.png)

# 添加 done 参数

现在，这个测试通过的原因不是因为`utils.test.js`中的断言是有效的。它通过是因为我们有一个需要 1 秒的异步操作。这个函数将在`async`回调被触发之前返回。当我说函数返回时，我指的是`callback`函数，即`it`的第二个参数。

这是 Mocha 认为你的测试已经完成的时候。这意味着这些断言永远不会运行。Mocha 输出已经说我们的测试通过了，然后才会触发这个回调。我们需要做的是告诉 Mocha 这将是一个需要时间的异步测试。为了做到这一点，我们只需在传递给它的回调函数内提供一个参数。我们将称之为`done`：

```js
it('should async add two numbers', (done) => {
```

当我们指定了`done`参数时，Mocha 知道这意味着我们有一个异步测试，并且它不会完成处理此测试，直到调用`done`。这意味着我们可以在断言之后调用`done`：

```js
it('should async add two numbers', (done) => {
  utils.asyncAdd(4, 3, (sum) => {
    expect(sum).toBe(10).toBeA('number');
    done();
  });
});
```

有了这个，我们的测试现在将运行。函数在调用`async.Add`后将立即返回，但这没关系，因为我们已经指定了`done`。大约一秒钟后，我们的回调函数将触发。在`asyncAdd`回调函数内部，我们将进行断言。这次断言将很重要，因为我们有`done`，而且我们还没有调用它。在断言之后，我们调用 done，这告诉 Mocha 我们已经完成了测试。它可以继续处理结果，让我们知道它是通过还是失败。这将修复那个错误。

如果我保存文件在这个状态下，它将重新运行测试，我们将看到我们的测试应该`async.Add`两个数字确实失败。在终端中，让我们打开错误消息，我们预期的是 7 是 10：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/858b39b4-9141-4f4f-85d0-db38d9be3d0d.png)

这正是我们第一次没有使用`done`时认为会发生的情况，但正如我们所看到的，当我们在测试中进行异步操作时，我们确实需要使用`done`。

现在我们可以将这个期望改回`7`，保存文件：

```js
it('should async add two numbers', (done) => {
  utils.asyncAdd(4, 3, (sum) => {
    expect(sum).toBe(7).toBeA('number');
    done();
  });
});
```

这一次事情应该按预期工作，1 秒延迟后运行此测试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/752973ad-70d3-4cf5-a5ea-d9694f49feeb.png)

它不能立即报告，因为它必须等待 done 被调用。请注意，我们的总测试时间现在大约是一秒。我们可以看到我们有四个测试通过。Mocha 还在测试花费很长时间时警告我们，因为它认为这是不正常的。即使是 Node 中的任何东西，甚至是数据库或 HTTP 请求，也不应该花费接近一秒的时间，所以它基本上是在告诉我们，你的函数中可能有错误——它花费了非常非常长的时间来处理。但在我们的情况下，一秒的延迟显然是在`utils`中清楚地设置的，所以不需要担心那个警告。

有了这个，我们现在有了我们的第一个异步方法的测试。我们所要做的就是添加一个`done`作为参数，并在完成断言后调用它。

# `square`函数的异步测试

现在让我们创建`square`方法的异步版本，就像我们用同步方法一样。为了开始，我们将首先定义函数，然后我们将担心编写测试。

# 创建异步平方函数

在`utils`文件中，我们可以在`square`方法旁边开始创建一个名为`asyncSquare`的新方法：

```js
module.exports.square = (x) => x * x;

module.exports.asyncSquare
```

它将需要两个参数：我们称之为`x`的原始参数，以及在 1 秒延迟后将被调用的`callback`函数：

```js
module.exports.square = (x) => x * x;

module.exports.asyncSquare = (x, callback) => {

};
```

然后我们可以完成箭头函数(`=>`)，然后开始编写`asyncSquare`的主体。它看起来与`asyncAdd`很相似。我们将调用`setTimeout`传递一个回调和一个延迟。在这种情况下，延迟将是相同的；我们将使用 1 秒：

```js
module.exports.square = (x) => x * x;

module.exports.asyncSquare = (x, callback) => {
  setTimeout(() => {

  }, 1000);
};
```

现在我们可以实际调用回调。这将触发传入的`callback`函数，并且我们将传入值`x`乘以`x`，这将正确地平方替代`x`的数字：

```js
module.exports.square = (x) => x * x;

module.exports.asyncSquare = (x, callback) => {
  setTimeout(() => {
    callback(x * x);
  }, 1000);
};
```

# 编写`asyncSquare`的测试

现在在`test`文件中，事情确实通过了，但我们还没有为`asyncSquare`函数添加测试，所以让我们这样做。在`utils.test`文件中，您需要做的下一件事是调用`it`。在测试`asyncAdd`函数旁边，让我们调用`it`来为这个`asyncSquare`函数创建一个新的测试：

```js
it('should square a number', () => {
  var res = utils.square(3);

  expect(res).toBe(9).toBeA('number');
});

it('should async square a number')
```

接下来，我们将提供回调函数，当测试实际执行时将调用该函数。由于我们正在测试一个`async`函数，我们将在回调函数中放置`done`，如下所示：

```js
it('should async square a number', (done) => {

});
```

这将告诉 Mocha 等到调用`done`后才决定测试是否通过。接下来，我们现在可以调用`utils.asyncSquare`，传入我们选择的一个数字。我们将使用`5`。接下来，我们可以传入一个回调函数：

```js
it('should async square a number', (done) => {
  utils.asyncSquare(5, () => {

  })
});
```

这将得到最终结果。在箭头函数（`=>`）中，我们将创建一个变量来存储该结果：

```js
 utils.asyncSquare(5, (res) => {

  });
```

现在我们有了这个，我们可以开始进行断言。

# 为`asyncSquare`函数进行断言

断言将使用`expect`库完成。我们将对`res`变量进行一些断言。我们将使用`toBe`断言它等于数字`25`，即`5`乘以`5`。我们还将使用`toBeA`来断言关于值类型的一些内容：

```js
it('should async square a number', (done) => {
  utils.asyncSquare(5, (res) => {
    expect(res).toBe(25).toBeA('number');
  });
});
```

在这种情况下，我们希望确保`square`确实是一个数字，而不是布尔值、字符串或对象。有了这个，我们确实需要调用`done`，然后保存文件：

```js
it('should async square a number', (done) => {
  utils.asyncSquare(5, (res) => {
    expect(res).toBe(25).toBeA('number');
    done();
  });
});
```

请记住，如果您不调用`done`，您的测试将永远不会完成。您可能会发现偶尔会在终端内出现这样的错误：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b050421f-a3c1-451c-bf59-a522f76a0edd.png)

您收到了一个错误超时，超过了 2,000 毫秒。这是 Mocha 中断您的测试。如果您看到这个，通常意味着两件事：

+   您有一个`async`函数，实际上从未调用回调函数，因此您对`done`的调用从未被触发。

+   你从未调用过`done`。

如果您看到此消息，通常意味着`async`函数中某处有小错误。要克服这一点，要么通过确保调用回调来修复方法（`utils.js`）中的问题，要么通过调用`done`来修复测试（`utils.test.js`）中的问题，然后保存文件，您现在应该看到所有测试都通过了。

在我们的案例中，有 5 个测试通过，用了 2 秒钟。这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/80634d18-e725-4f62-9bbc-0c7b819f8df0.png)

现在我们有了测试同步函数和异步函数的方法。这将使测试更加灵活。它将让我们测试应用程序中的几乎所有内容。

# 总结

在本章中，我们研究了同步和异步函数的测试。我们研究了基本测试。我们探索了测试框架 Mocha。然后，我们研究了在测试 Node 模块中使用断言库。

在下一章中，我们将看看如何测试我们的 Express 应用程序。
