# jQuery 热点（三）

> 原文：[`zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F`](https://zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：制作自己的 jQuery

在 jQuery 1.8 发布中，引入了一项全体设计希望已久的新功能-能够构建只包含特定任务所需功能的自定义版本的 jQuery。

# 任务简报

在这个项目中，我们将设置我们需要使用 jQuery 构建工具的环境。我们将看到我们需要使用的其他软件，如何运行构建工具本身，以及我们可以期望构建工具的输出。

## 为什么它很棒？

尽管有人通常会说他们在构建的每个网站中都使用 jQuery（对我来说通常是这样），但我期望很少有人会说他们在每个项目中都使用完全相同的 jQuery 方法，或者他们使用了大量可用方法和功能。

减少文件大小以满足移动空间的需求，以及诸如 **Zepto** 等微框架的兴起，它以更小的尺寸提供了大量 jQuery 功能，这促使 jQuery 提供了一种精简大小的方法。

从 jQuery 1.8 开始，我们现在可以使用官方 jQuery 构建工具来构建我们自己的定制版本的库，从而只选择我们所需的功能来最小化库的大小。

### 注意

有关 Zepto 的更多信息，请查看 [`zeptojs.com/`](http://zeptojs.com).

## 你的顶尖目标

要成功完成这个项目，我们需要完成以下任务：

+   安装 Git 和 Make

+   安装 Node.js

+   安装 Grunt.js

+   配置环境

+   构建自定义 jQuery

+   运行 QUnit 单元测试

## 任务清单

我们将使用 Node.js 来运行构建工具，所以你现在应该下载一个副本。Node 网站（[`nodejs.org/download/`](http://nodejs.org/download/)）提供了 64 位和 32 位 Windows 的安装程序，以及 Mac OS X 的安装程序。它还为 Mac OS X、Linux 和 SunOS 提供了二进制文件。下载并安装适合你的操作系统的版本。

jQuery 的官方构建工具（尽管它除了构建 jQuery 之外还可以做很多其他事情）是 **Grunt.js**，由 *Ben Alman* 编写。我们不需要下载它，因为它是通过 **Node Package Manager** （**NPM**）安装的。我们将在项目后面详细看这个过程。

### 注意

要了解更多关于 Grunt.js 的信息，请访问官方网站 [`gruntjs.com`](http://gruntjs.com).

首先，我们需要设置一个本地工作区。我们可以在根项目文件夹中创建一个名为 `jquery-source` 的文件夹。当我们克隆 jQuery Github 仓库时，我们会将 jQuery 源代码存储在这里，并且 Grunt 也会在这里构建最终版本的 jQuery。

# 安装 Git 和 Make

我们需要安装的第一件事是 Git，我们需要它来从 Github 存储库克隆 jQuery 源代码到我们自己的计算机，这样我们就可以处理源文件。我们还需要一个叫做 Make 的东西，但我们只需要在 Mac 平台上真正安装它，因为在 Windows 上安装 Git 时它会自动安装。

### 提示

因为我们将创建的文件仅供我们自己使用，并且我们不想通过将代码推送回存储库来为 jQuery 做出贡献，所以我们不需要担心在 Github 上创建账户。

## 准备起飞

首先，我们需要下载 Git 和 Make 的相关安装程序。根据你是在 Mac 还是 Windows 平台上开发，需要不同的应用程序。

### Mac 开发者

Mac 用户可以访问[`git-scm.com/download/mac`](http://git-scm.com/download/mac)获取 Git。

接下来我们可以安装 Make。Mac 开发者可以通过安装 XCode 来获取。可以从[`developer.apple.com/xcode/`](https://developer.apple.com/xcode/)下载。

### Windows 开发者

Windows 用户可以安装**msysgit**，可以通过访问[`code.google.com/p/msysgit/downloads/detail?name=msysGit-fullinstall-1.8.0-preview20121022.exe`](https://code.google.com/p/msysgit/downloads/detail?name=msysGit-fullinstall-1.8.0-preview20121022.exe)获取。

## 启动推进器

下载完成安装程序后，运行它们来安装应用程序。安装程序默认选择的设置对这个任务来说应该是合适的。首先我们应该安装 Git（或者在 Windows 上安装 msysgit）。

### Mac 开发者

Mac 开发者只需要运行 Git 的安装程序将其安装到系统中。安装完成后，我们可以安装 XCode。我们只需要运行安装程序，Make 以及一些其他工具将被安装并准备好。

### Windows 开发者

msysgit 的完整安装程序完成后，你应该可以看到一个命令行界面（标题为 MINGW32），表明一切准备就绪，你可以开始进行编码。但是，在我们开始编码之前，我们需要编译 Git。

为了做到这一点，我们需要运行一个叫做`initialize.sh`的文件。在 MINGW32 窗口中，`cd`到`msysgit`目录。如果你允许它安装到默认位置，你可以使用以下命令：

```js
cd C:\\msysgit\\msysgit\\share\\msysGit

```

一旦我们在正确的目录中，就可以在 CLI 中运行`initialize.sh`。和安装一样，这个过程可能需要一些时间，所以请耐心等待 CLI 返回`$`字符的闪烁光标。

### 注意

以这种方式编译 Git 需要互联网连接。

Windows 开发者需要确保`Git.exe`和 MINGW 资源可以通过系统的`PATH`变量访问。这可以通过转到**控制面板** | **系统** | **高级系统设置** | **环境变量**来更新。

在对话框的底部部分，双击**路径**，并将以下两个路径添加到位于您选择安装位置内的`msysgit`文件夹中的`bin`文件夹中的`git.exe`文件中：

+   `;C:\msysgit\msysgit\bin;`

+   `C:\msysgit\msysgit\mingw\bin;`

### 提示

**谨慎更新路径！**

您必须确保`Git.exe`的路径与其余路径变量之间用分号分隔。如果在添加`Git.exe`路径之前路径不以分号结尾，请确保添加一个。错误地更新路径变量可能导致系统不稳定和/或数据丢失。我在上一个代码示例的开头显示了一个分号，以说明这一点。

路径更新后，我们应该能够使用常规命令提示符来运行 Git 命令。

### 安装后的任务

在终端或 Windows 命令提示符（我将两者简称为 CLI 以便简洁起见）窗口中，我们应该首先`cd`进入我们在项目开始时创建的`jquery-source`文件夹。根据您本地开发文件夹的位置不同，此命令看起来会像下面这样：

```js
cd c:\jquery-hotshots\jquery-source

```

要克隆 jQuery 仓库，请在 CLI 中输入以下命令：

```js
git clone git://github.com/jquery/jquery.git

```

同样，在 CLI 返回到闪烁的光标以指示进程完成之前，我们应该看到一些活动。

根据您所开发的平台不同，您应该会看到类似以下截图的内容：

![安装后的任务](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_03.jpg)

## 完成目标 - 迷你总结

我们安装了 Git，然后使用它克隆了 jQuery 的 Github 仓库到这个目录，以获取 jQuery 源代码的最新版本。如果您习惯于 SVN，克隆仓库的概念上与检出仓库是相同的。

再次说明，这些命令的语法在 Mac 和 Windows 系统上非常相似，但请注意，在 Windows 中使用路径时需要转义反斜杠。完成此操作后，我们应该会在`jquery-source`目录内看到一个名为`jquery`的新目录。

如果我们进入此目录，会看到一些更多的目录，包括：

+   `build`：此目录由构建工具用于构建 jQuery

+   `speed`：此目录包含基准测试

+   `src`：此目录包含编译为 jQuery 的所有单个源文件

+   `测试`：此目录包含 jQuery 的所有单元测试

它还包含一系列各种文件，包括：

+   授权和文档，包括 jQuery 的作者和项目贡献指南

+   Git 特定文件，如`.gitignore`和`.gitmodules`

+   Grunt 特定文件，如 `Gruntfile.js`

+   JSHint 用于测试和代码质量目的

我们不需要直接使用 Make，但是当我们构建 jQuery 源代码时，Grunt 会使用它，因此它需要存在于我们的系统中。

# 安装 Node.js

Node.js 是一个用 JavaScript 构建的运行服务器端应用程序的平台。例如，可以轻松创建一个接收和响应 HTTP 请求的网络服务器实例，使用回调函数。

服务器端 JS 与更熟悉的客户端对应物并不完全相同，但在您所熟悉和喜爱的舒适语法中，您会发现许多相似之处。在这个项目中，我们实际上不会编写任何服务器端 JavaScript — 我们只需要 Node 来运行 Grunt.js 构建工具。

## 为起飞做准备

要获取适用于您平台的适当安装程序，请访问 Node.js 网站 [`nodejs.org`](http://nodejs.org) 并点击下载按钮。如果支持的话，应该会自动检测到适合您平台的正确安装程序。

## 启动推进器

在 Windows 或 Mac 平台上，安装 Node 非常简单，因为两者都有安装程序。此任务将包括运行安装程序，这显然是简单的，并使用 CLI 测试安装。

在 Windows 或 Mac 平台上，运行安装程序，它将指导您完成安装过程。我发现在大多数情况下默认选项都很好。与之前一样，我们还需要更新`Path`变量以包括 Node 和 Node 的包管理器 NPM。这些目录的路径在不同平台上会有所不同。

### Mac

Mac 开发者应检查 `$PATH` 变量是否包含对 `usr/local/bin` 的引用。我发现这已经在我的 `$PATH` 中了，但是如果您发现它不存在，您应该添加它。

### 注意

有关更新 `$PATH` 变量的更多信息，请参阅 [`www.tech-recipes.com/rx/2621/os_x_change_path_environment_variable/`](http://www.tech-recipes.com/rx/2621/os_x_change_path_environment_variable/)。

### Windows

Windows 开发者需要像以前一样更新`Path`变量，其中包括以下路径：

+   `C:\Program Files\nodejs\;`

+   `C:\Users\Desktop\AppData\Roaming\npm;`

### 注意

Windows 开发者可能会发现 `Path` 变量已经包含了一个 Node 条目，因此可能只需要添加 NPM 的路径。

## 目标完成 - 迷你总结

一旦安装了 Node，我们就需要使用 CLI 与其进行交互。要验证 Node 是否已正确安装，请在 CLI 中键入以下命令：

```js
node -v

```

CLI 应该报告使用的版本，如下所示：

![目标完成 - 迷你总结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_04.jpg)

我们可以通过运行以下命令来测试 NPM：

```js
npm -v

```

# 安装 Grunt.js

在这个任务中，我们需要安装 Grunt.js，这个过程非常快速且简单，就像安装 Node 一样。我们甚至不需要手动下载任何东西，就像以前一样，相同的命令应该在 Mac 或 Windows 系统上都能工作，只需要非常小的调整。

## 启动推进器

我们需要使用**Node 包管理器 NPM**来安装它，可以通过运行以下命令来执行（注意，不能运行 Node 本身）：

```js
npm install -g grunt-cli

```

### 注意

Mac 用户可能需要在命令开头使用 `superuser do`：

```js
sudo –s npm install –g grunt

```

准备等待几分钟。同样，当 Grunt 需要的资源被下载和安装时，我们应该会看到大量活动。一旦安装完成，提示符将返回到闪烁的光标。CLI 应该会像以下截图一样显示，具体取决于您正在开发的平台：

![启动推进器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_06.jpg)

## 完成目标 - 迷你总结

如果一切顺利（通常情况下应该如此，除非您的系统出现问题），那么在 Grunt 及其依赖项通过 NPM 全局下载和安装完成时，CLI 中将会看到大量活动，一旦完成，Grunt 将被安装并准备就绪。

### 提示

需要互联网连接才能使用 NPM 自动下载和安装软件包。

为了验证 Grunt 是否已正确安装，我们可以在 CLI 中输入以下命令：

```js
grunt -version

```

这将输出当前 Grunt 的版本，并且应该可以从任何目录中运行，因为 Grunt 已经全局安装了。

## 机密情报

除了构建自定义版本的 jQuery 外，Grunt 还可以用于创建几种不同的常见项目。我们首先选择以下项目类型之一：

+   `gruntfile`

+   `commonjs`

+   `jquery`

+   `node`

我们可以运行内置的 `init` 任务，并指定其中一个项目，Grunt 将继续设置包含该项目常用资源的骨架项目。

例如，运行 `jquery init` 任务将设置一个工作目录，用于创建一个 jQuery 插件。在该目录中，Grunt 将创建源脚本文件和单元测试的文件夹，以及创建一系列文件，包括一个 `package.json` 文件。

很可能在某个时候，所有新的 jQuery 插件都需要按照 Grunt 创建此项目类型时的方式来构建结构，因此，对于任何 jQuery 插件开发者来说，Grunt 将成为一款不可或缺的、节省时间的工具。

# 配置环境

在我们准备构建自己的 jQuery 版本之前，还有一些事情需要做。我们还可以通过构建 jQuery 的完整版本来测试我们的安装和配置，以确保一切都按预期工作。

## 准备起飞

我们需要安装一些额外的 Grunt 依赖项，以便我们可以使用从 Github 克隆的源文件来创建 jQuery 脚本文件。项目还使用了一系列 NPM 模块，这些模块也需要安装。幸运的是，NPM 可以自动为我们安装所有内容。

## 启动推进器

在构建 jQuery 源码之前，我们需要在 `jquery` 源码文件夹中安装一些额外的 Grunt 依赖项。我们可以使用 NPM 来做到这一点，因此可以在 CLI 中输入以下命令：

```js
npm install 

```

### 注意

在运行 `install` 命令之前，请确保您已经使用 `cd` 命令导航到 `jquery` 目录。

在运行 `install` 命令后，CLI 应该会有很多活动，而在进程结束时，CLI 应该会显示类似以下截图的内容：

![启动推进器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_05.jpg)

为了测试一切是否按预期进行，我们可以构建 jQuery 的完整版本。只需在 CLI 中运行 `grunt` 命令：

```js
grunt

```

### 注意

如果此时出现任何错误或警告，说明某些内容未安装或配置正确。失败的原因可能有很多，所以最好的做法是卸载我们安装的所有内容，然后重新开始整个过程，确保所有步骤都严格按照要求进行。

同样，我们应该会在 CLI 上看到很多活动，以表明事情正在发生：

![启动推进器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_01.jpg)

## 目标完成 - 迷你总结

安装过程完成后，我们应该会发现 Node 依赖项已经安装到 `jquery` 目录中的一个名为 `node_modules` 的目录中。在这个文件夹中是 Grunt 针对这个特定项目所需要的任何其他文件。

为了测试一切，我们然后使用 `grunt` 命令运行 jQuery 的默认构建任务。此任务将执行以下操作：

+   阅读所有 jQuery 源文件

+   为任务的输出创建一个 `/dist` 目录

+   构建 `jquery.js` 分发文件

+   使用 `jshint` 对分发文件进行代码检查

+   运行单元测试

+   构建分发文件的源映射

+   构建 `jquery.min.js` 分发文件

脚本文件应该是完整文件 230 KB，`.min` 文件为 81 KB，尽管随着 jQuery 版本号的增加，这些数字可能会有所不同。

# 构建自定义 jQuery

在这个任务中，我们将构建一个自定义版本的 jQuery，它不会包含构成 "完整" jQuery 的所有不同模块，这些模块会合并成一个文件，通常我们从 jQuery 站点下载，就像上一个任务结束时我们构建的文件一样，而是仅包含核心模块。

## 启动推进器

现在我们可以构建一个自定义版本的 jQuery。要构建一个精简版的 jQuery，省略所有非核心组件，我们可以在 CLI 中输入以下命令： 

```js
grunt custom:-ajax,-css,-deprecated,-dimensions,-effects,-offset

```

## 目标完成 - 迷你总结

一旦我们拥有源代码并配置好本地环境，我们就能够构建一个自定义版本的 jQuery，只包含核心组件，而省略了所有可选组件。

在这种情况下，我们排除了所有可选组件，但我们可以排除其中任何一个，或任意组合它们，以生成一个仅仅尽可能大的脚本文件。

如果此时检查 `/dist` 目录，我们应该会发现完整的脚本文件现在是 159 KB，而 `.min` 版本只有 57 KB，大约节省了文件大小的 30%；对于几分钟的工作来说，这还不错！

### 注意

项目功能或范围的变化可能需要重新构建源文件并包括以前排除的模块。一旦排除，就无法将可选模块添加到构建的文件中而不重新构建。

## 机密情报

随着 jQuery 的发展，特别是在 2.0 里程碑之后，越来越多的 jQuery 组件将被公开到构建工具作为可选组件，因此将有可能排除更广泛的库部分。

虽然在撰写时我们节省的文件大小可能会被我们的大多数访问者不会在其缓存中拥有我们的自定义版本的 jQuery 而需要下载的事实所抵消，但可能会有一天我们能够将文件大小缩小到这样的程度，以至于下载我们的超轻量级脚本文件仍然比从缓存中加载完整源文件更有效率。

# 使用 QUnit 运行单元测试

QUnit 是 jQuery 的官方测试套件，并包含在我们在项目早期从 Git 克隆的源代码中。如果我们在`jquery`文件夹内的测试文件夹中查找，我们应该会发现有很多单元测试，用于测试构成 jQuery 的不同组件。

我们可以针对 jQuery 的各个组件运行这些测试，以查看 QUnit 需要的环境，并查看使用它测试 JavaScript 文件有多容易。为此任务，我们需要安装一个 web 服务器和 PHP。

### 注意

有关 QUnit 的更多信息，请参阅[`qunitjs.com`](http://qunitjs.com)上的文档。

## 为起飞做好准备

Mac 开发者应该已经拥有运行 QUnit 所需的一切，因为 Mac 计算机已经预装了 Apache 和 PHP。然而，Windows 开发者可能需要做一些设置。

在这种情况下，web 服务器有两个选择，Apache 或者 IIS。两者都支持 PHP。那些希望使用 Apache 的开发者可以安装像**WAMP**（**Windows Apache Mysql PHP**）这样的东西，以便安装和配置 Apache，并将 MySQL 和 PHP 安装为模块。

要下载并安装 WAMP，请访问 Wamp Server 网站的**下载**部分（[`www.wampserver.com/en/`](http://www.wampserver.com/en/)）。

选择适合您平台的安装程序并运行它。这应该会安装和配置一切必要的内容。

希望使用 IIS 的人可以通过控制面板中的**程序和功能**页面的**添加/删除 Windows 组件**区域安装它（在这种情况下需要 Windows 安装光盘），或者使用**Web 平台安装程序**（**WPI**），可以从[`www.microsoft.com/web/downloads/platform.aspx`](http://www.microsoft.com/web/downloads/platform.aspx)下载。

下载并运行安装程序。一旦启动，搜索 IIS 并让应用程序安装它。安装完成后，也通过 WPI 搜索 PHP 并进行安装。

要使用 web 服务器和 PHP 运行 QUnit，你需要将项目文件夹内的`jquery`目录中的源文件复制到 web 服务器用于提供文件的目录中，或者配置 web 服务器以提供`jquery`目录中的文件。

在 Apache 上，我们可以通过编辑`httpd.conf`文件（在开始菜单中应该有一个条目）来配置默认目录（当浏览器请求时用于提供页面的目录）。向下阅读配置文件，直到找到默认目录的行，并更改它，使其指向项目文件夹中的`jquery`目录。

在 IIS 上，我们可以使用 IIS 管理器添加一个新网站。在左侧的**连接**窗格中右键单击**站点**，然后选择**添加网站…**。填写打开的对话框中的详细信息，我们就可以开始了。

## 启动推进器

要运行测试，我们只需要在浏览器中使用`localhost:8080`（或配置的任何主机名/端口号）访问`/test`目录：

```js
localhost:8080/test
```

测试应该显示如下屏幕截图所示：

![启动推进器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_07_02.jpg)

## 完成目标 - 小结

当在浏览器中访问测试套件的 URL 时，QUnit 将运行为 jQuery 编写的所有单元测试。目前对完整版本的 jQuery 有超过 6000 个测试，对所有可选模块都排除的自定义版本有约 4000 个测试。

你可能会发现一些测试失败。别担心，这是正常的，原因是我们从 Git 获取的默认 jQuery 版本将是最新的开发版本。就我写作时而言，当前版本的 jQuery 是 1.8.3，但从 Git 克隆的版本是 2.0.0pre。

要解决这个问题，我们可以切换到当前稳定分支，然后从那里进行构建。所以如果我想获取版本 1.8.3，我可以在 CLI 中使用以下命令：

```js
git checkout 1.8.3

```

然后我们可以再次构建源码，运行 QUnit，所有测试应该都会通过。

### 注意

在检出 jQuery 源码的另一个版本后，我们需要在`jquery`目录中运行`npm install`来重新安装节点依赖项。

## 机密情报

单元测试并不总是被前端开发者严格遵循，但是一旦你的应用程序跨越了一定的规模和复杂度阈值，或者在团队环境中工作时，单元测试就变得对于维护至关重要，所以至少学习基础知识是最好的。

QUnit 使得编写 JavaScript 单元测试变得容易。它采用了围绕着用简单函数证明的断言概念的简单 API。QUnit 的 API 包括我们可以使用的方法来进行这些断言，包括：

+   `equal()`

+   `notEqual()`

+   `ok()`

这样可以轻松检查变量是否等于特定值，或者函数的返回值是否不等于特定值，等等。

在 QUnit 中，使用全局的 `test()` 方法构建测试，该方法接受两个参数：描述测试的字符串和执行测试的函数：

```js
test("Test the return value of myCustomMethod()", function() {
    //test code here
});
```

在函数内部，我们可以使用一个或多个断言来检查我们正在测试的方法或函数执行的操作的结果：

```js
var value = myCustomMethod();
equal(value, true, "This method should return true");
```

`equal()` 方法检查第一个和第二个参数是否相等，最后一个参数是描述我们期望发生的情况的字符串。

### 提示

如果打开 `jquery/test/unit` 目录中的一些脚本文件，可以很容易地看出如何构造测试。

QUnit 网站上的文档非常出色。它不仅清晰简洁地描述了 API，还提供了大量关于单元测试概念的信息，因此对于初学者来说是一个很好的起点。

在该网站上，您还可以找到在 Grunt 之外运行 QUnit 所需的源文件以及一个 HTML 模板页面，您可以在浏览器中运行测试套件。

# 任务完成

在这个任务中，我们不仅学会了如何通过排除不需要的组件来构建自定义版本的 jQuery，以及如何运行 jQuery 的单元测试套件，而且，也许更重要的是，我们学会了如何设置一个体面的构建环境，用于编写干净、无错的应用级 JavaScript。

# 你准备好了吗？挑战来了！

我们已经学会了如何构建我们自己的 jQuery，并排除了最大数量的组件，所以在撰写本文时，我们已经没有太多可以做的了。

如果您在 jQuery 1.9 版本发布后阅读本文，则可能会有更多的组件可以排除，或者其他构建 jQuery 的技术，因此，为了真正巩固您对构建过程的理解，请构建一个新的自定义构建，也排除任何新的可选组件。

如果没有任何新的可选组件，我建议您花些时间为您编写的任何自定义脚本编写 QUnit 测试。其思想是编写一个复制错误的测试。然后您可以修复错误并观察测试通过。


# 第八章：使用 jQuery 进行无限滚动

无限滚动是许多热门网站采用的一种技术，它最小化了页面最初加载的数据量，然后在用户滚动到页面底部时逐步加载更多数据。你可以在 Facebook 或 Twitter 的时间线上看到这种效果，等等。

# 任务简报

在本项目中，我们将使用 jQuery 构建一个无限滚动系统，模仿前述网站上看到的效果。我们将请求一些数据并在页面上显示它。一旦用户滚动到页面底部，我们将请求下一页的数据，依此类推，直到用户继续滚动。

一旦我们建立了无限滚动系统，我们应该得到类似以下截图的结果：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_08_01.jpg)

## 为什么很棒？

如果您有大量数据要显示，并且它可以轻松按照时间顺序排列，那么使用无限滚动技术是最大程度地提高页面用户体验的简单方法，通过渐进式披露向用户逐渐展示更多内容。

首先可以显示一小部分数据，这样可以加快页面加载速度，同时防止您的访问者被大量数据所压倒，随着用户交互逐渐增加。

本项目将要消费的数据是 YouTube 上 TEDTalks 频道上传的视频列表，以 JSON 格式提供。

### 注意

请记住，JSON 是一种轻量级的基于文本的数据格式，非常适合在网络上进行传输。有关 JSON 的更多信息，请参阅 [`www.json.org/`](http://www.json.org/)。

在该频道上可以找到数千个视频，因此它是我们项目的一个很好的测试基础。按时间顺序排序的数据是一个无限滚动的绝佳基础。

### 注意

TEDTalks 频道可以直接在 YouTube 网站上查看，网址是 [`www.youtube.com/user/tedtalksdirector`](http://www.youtube.com/user/tedtalksdirector)。

## 您的热门目标

该项目将分解为以下任务：

+   准备基础页面

+   获取初始供稿

+   显示初始结果集

+   处理滚动到页面底部

## 任务清单

我们可以像在之前的一些示例中那样链接到 JsRender 的托管版本，但在这个项目中，我们将使用一个称为 imagesLoaded 的便捷小型 jQuery 插件，它允许我们在所选容器中的所有图像加载完成时触发回调函数。

imagesLoaded 插件可以从 [`github.com/desandro/imagesloaded`](https://github.com/desandro/imagesloaded) 下载，并应保存在我们项目的 `js` 目录中。

# 准备基础页面

在此任务中，我们将设置我们在整个项目中要使用的文件，并准备我们的无限滚动页面的基础。

## 准备起飞

和往常一样，我们将为此项目使用自定义样式表和自定义脚本文件，所以让我们首先添加它们。创建一个名为`infinite-scroller.js`的新 JavaScript 文件，并将其保存在`js`目录中。然后创建一个名为`infinite-scoller.css`的新样式表，并将其保存在`css`目录中。最后，将`template.html`文件的副本保存在根项目文件夹中，并将其命名为`infinite-scroller.html`。

## 启动推进器

示例页面使用的底层标记将是最小的 - 我们将使用的许多元素将由我们的模板动态生成，我们也可以在此任务中添加它们。

首先，我们应该将对新文件的引用添加到 HTML 页面中。首先，在`infinite-scroller.html`的`<head>`中，直接在对`common.css`的链接之后添加一个`<link>`元素：

```js
<link rel="stylesheet" href="css/infinite-scroller.css" />
```

接下来，我们可以链接到两个新的 JavaScript 文件。在 jQuery 之后直接添加以下`<script>`元素：

```js
<script src="img/jsrender.js">
</script>
<scriptsrc="img/jquery.imagesloaded.min.js"></script>
<scriptsrc="img/infinite-scroller.js"></script>
```

我们还需要添加一个简单的容器来渲染我们的数据。将以下代码添加到页面的`<body>`中：

```js
<div id="videoList"></div>
```

现在我们可以添加我们将要使用的模板了。在这个项目中，我们将使用两个模板 - 一个用于呈现外部容器和用户数据，它将被呈现一次，另一个用于呈现视频列表，我们可以根据需要重复使用。

与以前一样，它们将位于页面`<body>`中的`<script>`元素内。在现有的`<script>`元素之前，添加以下新模板：

```js
<script id="containerTemplate" type="text/x-jsrender">
    <section>
        <header class="clearfix">
            <imgsrc="img/{{>avatar}}" alt="{{>name}}" />
            <hgroup>
                <h1>{{>name}}</h1>
                <h2>{{>summary.substring(19, 220)}}</h2>
            </hgroup>
        </header>
        <ul id="videos"></ul>
    </section>
</script>
```

现在轮到视频模板了：

```js
<script id="videoTemplate" type="text/x-jsrender">
    <li>
        <article class="clearfix">
            <header>
                <a href="{{>content[5]}}" title="Watch video">
                    <imgsrc="img/{{>thumbnail.hqDefault}}" alt="{{>title}}" />
                </a>
                <cite>
                    <a href="{{>content[5]}}" 
                    title="Watch video">{{>title}}</a>
                </cite>
            </header>
            <p>
                {{>~Truncate(12, description)}}
                    <a class="button" href="{{>content[5]}}" 
                    title="Watch video">Watch video</a>
            </p>
            <div class="meta">
                <dl>
                    <dt>Duration:</dt>
                    <dd>{{>~FormatTime(duration)}}</dd>
                    <dt>Category:</dt>
                    <dd>{{>category}}</dd>
                    <dt>Comments:</dt>
                    <dd>{{>commentCount}}</dd>
                    <dt>Views:</dt>
                    <dd>{{>viewCount}}</dd>
                    <dt>Likes:</dt>
                    <dd>{{>likeCount}}</dd>
                </dl>
            </div>
        </article>
    </li>
</script>
```

现在我们也可以为这些元素添加样式了。在`infinite-scroller.css`中，添加以下选择器和规则：

```js
section { width:960px; padding-top:20px; margin:auto; }
section { 
    width:960px; padding:2em 2.5em 0; 
    border-left:1px solid #ccc; border-right:1px solid #ccc; 
    margin:auto; background-color:#eee; 
}
section> header { 
    padding-bottom:2em; border-bottom:1px solid #ccc; 
}
img, hgroup, hgroup h1, hgroup h2 { float:left; }
hgroup { width:80%; }
headerimg { margin-right:2em; }
hgroup h1 { font-size:1.5em; }
hgroup h1, hgroup h2 { width:80%; }
hgroup h2 { 
    font-weight:normal; margin-bottom:0; font-size:1.25em;
    line-height:1.5em; 
}
ul { padding:0; }
li { 
    padding:2em 0; border-top:1px solid #fff; 
    border-bottom:1px solid #ccc; margin-bottom:0; 
    list-style-type:none; 
}
article header a { 
    display:block; width:27.5%; margin-right:2.5%; float:left; }
aimg { max-width:100%; }
article cite { 
    width:70%; margin-bottom:10px; float:left; 
    font-size:1.75em; 
}
article cite a { width:auto; margin-bottom:.5em; }
article p { 
    width:45%; padding-right:2.5%; 
    border-right:1px solid #ccc; margin:0 2.5% 2em 0;
    float:left; line-height:1.75em; 
}
article .button { display:block; width:90px; margin-top:1em; }
article dl { width:19%; float:left; }
article dt, article dd { 
    width:50%; float:left; font-size:1.15em; text-align:right; 
} 
article dt { margin:0 0 .5em; clear:both; font-weight:bold; }

li.loading{ height:100px; position:relative; }
li.loading span { 
    display:block; padding-top:3em; margin:-3em 0 0 -1em; 
    position:absolute; top:50%; left:50%; text-align:center;
    background:url(../img/ajax-loader.gif) no-repeat 50% 0; 
}
```

### 注意

此项目中使用的`ajax-loader.gif`图像可以在本书的附带代码下载中找到。

## 目标完成 - 小结

因此，实际上整个页面都是由我们添加到页面`<body>`中的模板构建的，除了一个空的`<div>`，它将为我们提供一个容器来渲染数据。该模板包含了用于视频列表的标记，以及用于显示视频作者信息的标记。

在第一个模板中，数据的外部容器是一个`<section>`元素。在其中是一个`<header>`，显示有关用户的信息，包括他/她的个人资料图片、姓名和简介。

YouTube 返回的实际简介可能相当长，因此我们将使用 JavaScript 的`substring()`函数返回此摘要的缩短版本。该函数传递两个参数；第一个是从哪个字符开始复制，第二个是结束字符。

在第二个模板中，实际的视频列表将显示在第一个模板中添加的`<ul>`元素中，每个视频占据一个`<li>`。在每个`<li>`内，我们有一个`<article>`元素，这是一个适当的独立内容单元的容器。

在`<article>`中，我们有一个包含视频的一些关键信息的`<header>`，如标题和缩略图。在`<header>`之后，我们显示视频的简短摘要在`<p>`元素中。我们还使用我们的缩短帮助函数`Truncate()`，从第 12 个字符开始。

最后，我们使用`<dl>`显示关于视频的一些元信息，例如播放次数、点赞次数和视频的持续时间。

我们使用另一个辅助函数来显示视频中的持续时间，`FormatTime()`。YouTube 返回视频的长度（以秒为单位），所以我们可以将其转换为一个格式良好的时间字符串。

我们使用`>`字符来 HTML 编码我们插入到页面中的任何数据。这样做是为了安全考虑，始终是最佳选择。

添加的 CSS 纯粹是用于表现的；仅用于以列表格式布局页面，并使其看起来略有趣味和可呈现。请随意更改布局样式的任何方面，或者元素的主题。

## 机密情报

你们中注重 SEO 的人会意识到，一个几乎完全由 AJAX 传递的内容构建的页面不太可能在搜索结果中得到很好的位置。传统上，这几乎肯定是正确的，但现在我们可以使用 HTML History API 中令人惊叹的`pushState()`方法来提供一个完全可由搜索引擎索引的动态网站。

`pushState()`的完整描述超出了本书的范围，但有很多很好的示例和教程。被许多人认为是 History API 的权威指南的是 Mozilla 开发者网络上关于`pushState()`的文档，其中包括关于`pushState()`的部分。你可以在 [`developer.mozilla.org/en-US/docs/DOM/Manipulating_the_browser_history`](https://developer.mozilla.org/en-US/docs/DOM/Manipulating_the_browser_history) 上查看文档。

# 获取初始饲料

在这个任务中，我们将专注于获取初始数据集，以便在页面首次加载时创建页面。我们需要编写我们的代码，使得获取第一页数据的函数对于任何数据页都是可重用的，以便我们稍后在项目中可以使用它。

## 准备起飞

我们可以使用 jQuery 提供的标准`document ready`快捷方式，就像我们在许多之前的项目中所做的那样。我们可以通过将以下代码添加到我们之前创建的`infinite-scroller.js`文件中来做好准备：

```js
$(function () {

    //rest of our code will go here...  

});
```

## 启动推进器

首先，我们可以添加从 YouTube 检索数据的代码。用以下内容替换前面代码段中的注释：

```js
var data = {},
    startIndex = 1;

var getUser = function () {
    return $.getJSON("http://gdata.youtube.com/feeds/api/users/tedtalksdirector?callback=?", {
        v: 2,
        alt: "json"
    }, function (user) {
        data.userdata = user.entry;
    });
};

var getData = function () {
    return $.getJSON("https://gdata.youtube.com/feeds/api/videos?callback=?", {
        author: "tedtalksdirector",
        v: 2,
        alt: "jsonc",
        "start-index": startIndex
    }, function (videos) {
        data.videodata = videos.data.items;
    });
};
```

接下来，我们需要稍微处理一下响应。我们可以使用以下代码，在我们之前添加的代码之后直接添加，以执行回调函数，一旦两个 AJAX 请求都完成，就会执行该回调函数：

```js
$.when(getUser(), getData()).done(function () {
    startIndex+=25;

    var ud = data.userdata,
        clean = {};

    clean.name = ud.yt$username.display;
    clean.avatar = ud.media$thumbnail.url;
    clean.summary = ud.summary.$t;
    data.userdata = clean;
});
```

## 目标完成 - 迷你总结

我们首先定义了几个变量。第一个是一个空对象，我们将用我们的 AJAX 请求的结果填充它。第二个是一个整数，表示我们希望获取的第一个视频的索引号。YouTube 视频不像常规的 JavaScript 数组那样从零开始，所以我们最初将变量定义为`1`。

接下来，我们添加了我们将用于获取数据的两个函数。第一个是请求获取我们将要显示其 Feed 的用户的个人资料数据。我们只会在页面最初加载时使用此函数一次，但您将会看到为什么重要的是我们以这种方式将函数定义为变量。

第二个函数将被重用，因此将其存储在一个变量中是一个很好的方法，可以随时调用它以获取新的视频数据页面。重要的是这两个函数都返回`getJSON()`方法返回的`jqXHR`对象。

这两个请求都使用 jQuery 的`getJSON()`方法进行请求。在用户请求中，我们只需要设置`v`和`alt`查询参数，这些参数设置在传递给`getJSON()`的第二个参数中的对象中。我们想要获取其个人资料数据的用户实际上是我们正在进行请求的 URL 的一部分。

此请求的回调函数简单地将从请求接收到的`user.entry`对象的内容添加到我们的`data`对象的`userdata`属性中。

第二个请求需要稍微更多的配置。我们仍然使用`v`参数设置我们要使用的 API 版本，但这次我们将响应格式设置为`jsonc`而不是`json`。在此请求的回调函数中，我们将视频数组存储在我们的`data`对象的`videodata`属性中。

**JSON-C** 代表 json-in-script，是 Google 可以针对某些请求进行响应的格式。以 JSON-C 格式返回的数据通常比以 JSON 格式返回的相同响应更轻量级，更高效，这是由于 Google 的 API 已经进行了工程化。

当使用这种格式时，我们需要使用的属性只有在返回时才会返回。我们在请求用户数据时不使用它的唯一原因是因为该特定查询没有 JSON-C 响应。

### 注

有关从 Google 的 API 返回的 JSON-C 响应的更多信息，请参阅 [`developers.google.com/youtube/2.0/developers_guide_jsonc`](https://developers.google.com/youtube/2.0/developers_guide_jsonc) 上的文档。

接下来我们使用 jQuery 的`when()`方法来启动我们的两个请求，然后使用`done()`方法在两个`jqXHR`对象都已解析后执行回调函数。这就是为什么单独使用的`getUser()`函数以与可重用的`getData()`函数相同的方式结构化很重要的原因。

在`done()`的回调函数内部，我们首先将`startIndex`变量增加 25，这样当我们发出另一个请求时，我们就会获得下一个包含 25 个视频的“页面”。现在我们已经有了第一页的数据，当我们稍后使用`getData()`函数时，我们将自动获得“下一页”的结果。

### 注意

`when()`和`done()`方法是自 jQuery 1.5 以来处理异步操作的首选方法。

此时，我们只需要对我们的`userdata`对象进行一点处理。有一大堆我们不需要使用的数据，而我们需要使用的一些数据被埋在嵌套对象中，所以我们简单地创建一个名为`clean`的新对象，并直接在这个对象上设置我们需要的数据。

一旦完成了这个操作，我们就可以将我们的干净对象保存回我们的`data`对象，覆盖原始的`userdata`对象。这样做可以使对象在我们的模板中更容易处理。

# 显示初始结果集

现在我们已经从 YouTube 的 API 返回数据，我们可以渲染我们的模板了。然而，为了渲染我们的模板，我们需要添加用于格式化部分数据的辅助函数。在此任务中，我们可以添加这些辅助函数，然后渲染模板。

## 启动推进器

模板辅助函数不需要驻留在`$.done()`回调函数内部。我们可以直接在`infinite-scroller.js`中的此代码之前添加它们：

```js
var truncate = function (start, summary) {
        return summary.substring(start,200) + "...";
    },
    formatTime = function (time) {
        var timeArr = [],
            hours = Math.floor(time / 3600),
            mins = Math.floor((time % 3600) / 60),
            secs= Math.floor(time % 60);

        if (hours> 0) {
            timeArr.push(hours);
        }

        if (mins< 10) {
            timeArr.push("0" + mins);
        } else {
            timeArr.push(mins);
        }

        if (secs< 10) {
            timeArr.push("0" + secs);
        } else {
            timeArr.push(secs);
        } 

        return timeArr.join(":");
    };
```

接下来，我们只需要注册这些辅助函数。在上一段代码后面直接添加以下内容：

```js
$.views.helpers({
    Truncate: truncate, 
    FormatTime: formatTime
});
```

最后，我们可以渲染我们的模板。我们希望一个可以从代码的任何位置调用的函数，以备将来进行进一步的请求。在注册辅助函数后添加以下代码：

```js
var renderer = function (renderOuter) {

    var vidList = $("#videoList");

    if (renderOuter) {
        vidList.append(
$("#containerTemplate").render(data.userdata));
    }
    vidList.find("#videos")
           .append($("#videoTemplate").render(data.videodata));
}
```

现在我们只需要在我们的`$.done()`回调函数的末尾调用这个函数：

```js
renderer(true);
```

## 目标完成 - 小结

我们的第一个辅助函数，`truncate()`非常简单。我们只是返回该函数作为参数接收的字符串的缩短版本。`substring()`函数接受两个参数；第一个是在字符串中开始复制的位置，第二个参数是要复制的字符数，我们固定在`200`。  

为了显示字符串已经被缩短，我们还在返回的字符串末尾附加了一个省略号，这就是我们在这里使用辅助函数的原因，而不是像之前直接在模板中使用子字符串一样。

`formatTime()`辅助函数稍微复杂一些，但仍然相对简单。这个函数将接收以秒为单位的时间，我们希望将其格式化为稍微漂亮一些的字符串，显示小时（如果有的话）、分钟和秒。

我们首先创建一个空数组来存储字符串的不同组成部分。然后，我们创建一些变量来保存我们将要创建的时间字符串的小时、分钟和秒部分。

小时数通过将总秒数除以 3600（一小时的秒数）来计算。我们对其使用`Math.floor()`，以便只得到一个整数结果。我们需要稍微不同地计算分钟，因为我们需要考虑小时数。

在这里我们使用模数运算符（`%`）首先去除任何小时，然后将余数除以`60`，这将告诉我们总分钟数或在考虑小时后剩余的分钟数。要计算秒数，我们只需要再次使用模数运算符和值`60`。

然后，我们使用一系列条件语句来确定要添加到数组中的变量。如果有任何小时数（这在视频的性质上是不太可能的），我们将它们推入数组中。

如果分钟数少于`10`，我们在分钟数前添加`0`，然后将其推入数组中。如果分钟数超过`10`，我们只需将`mins`变量推入数组中。在将其推入数组之前，对`secs`变量应用相同的逻辑。

这个函数通过将数组中的项目连接起来并使用冒号作为分隔符来返回一个格式良好的时间。字符串将以`H:MM:SS`或`MM:SS`的格式呈现，具体取决于视频的长度。然后，我们使用 JsRender 的`helpers`对象向模板注册辅助函数，该对象本身嵌套在由模板库添加到 jQuery 的`views`对象中。我们希望添加的辅助函数被设置为对象文字中的值，其中键与模板中的函数调用匹配。

接下来，我们添加了一个函数，我们可以调用该函数来呈现我们的模板。`renderer()`函数接受一个布尔值参数，指定是否同时呈现容器模板和视频模板，或只呈现视频模板。在函数内部，我们首先缓存对视频列表的外部容器的引用。

如果`renderOuter`参数具有真值（也就是说，如果它具体保留了值`true`），我们就呈现`containerTemplate`并将其附加到页面的空`<div>`中。然后，我们呈现`videoTemplate`，将呈现的 HTML 附加到由`containerTemplate`添加的`<ul>`中。

最后，我们第一次调用我们的`renderer()`函数，将`true`作为参数传递，以同时呈现容器和初始视频列表。

# 处理滚动到页面底部

现在我们已经得到了第一页的视频，我们想添加一个处理程序，监视窗口的滚动事件，并检测页面是否已经滚动到底部。

## 启动推进器

首先，我们需要添加一些新的变量。修改文件顶部附近的第一组变量，使其显示如下：

```js
var data = {},
    startIndex = 1,
    listHeight = 0,
    win = $(window),
    winHeight = win.height();
```

现在我们需要更新我们的`renderer()`函数，以便在模板被渲染后更新新的`listHeight`变量。在我们渲染`videoTemplate`后添加以下代码：

```js
vidList.imagesLoaded(function () {
    listHeight = $("#videoList").height();
});
```

接下来，我们可以为滚动事件添加一个处理程序。在`infinite-scroller.js`中的`when()`方法后面，添加以下代码：

```js
win.on("scroll", function () {

    if (win.scrollTop() + winHeight >= listHeight) {
        $("<li/>", {
            "class": "loading",
            html: "<span>Loading older videos...</span>"
        }).appendTo("#videos");

        $.when(getData()).done(function () {
            startIndex += 25;

            renderer();

            $("li.loading").remove();

        });
    }
}).on("resize", function() {
    winHeight = win.height();
});
```

我们正在使用一个旋转器来向用户显示正在检索更多数据的信息。我们需要一些额外的样式来处理旋转器的位置，所以我们也可以将以下代码添加到我们的`infinite-scroller.css`样式表的底部：

```js
li.loading{ height:100px; position:relative; }
li.loading span { 
    display:block; padding-top:38px; margin:-25px 0 0 -16px; 
    position:absolute; top:50%; left:50%; text-align:center; 
    background:url(../img/ajax-loader.gif) no-repeat 50% 0;
}
```

## 目标完成 - 迷你总结

我们使用我们缓存的`win`对象和`on()`方法将处理程序附加到窗口。事件类型被指定为`scroll`。在回调函数内部，我们首先检查当前窗口的`scrollTop`属性加上视口的`height`是否大于或等于我们的`videolist`容器的`height`。我们需要这样做来知道页面何时滚动到底部。

如果两个高度相等，我们创建一个临时加载器，向用户提供视觉反馈，表明正在发生某些事情。我们将一个新的`<li>`元素附加到包含视频的`<ul>`中，并给它一个类名为`loading`，以便我们可以轻松地用一些 CSS 来定位它。我们将一个`<span>`元素设置为新列表项的内容。

我们可以使用 jQuery 的`scrollTop()`方法获取`scrollTop`属性的当前值。我们正在使用窗口`height`的缓存值。我们的滚动处理程序将相当密集，因为它将在用户滚动时被调用，因此使用窗口`height`的缓存值会使这个过程稍微更有效率一些。

但这意味着如果窗口被调整大小，这个值将不再准确。我们通过为窗口添加一个调整大小处理程序来解决这个问题，每当窗口调整大小时重新计算这个值。这是通过在滚动处理程序之后链接另一个对`on()`方法的调用来完成的，该方法查找`window`对象的调整大小事件，并相应地更新`winHeight`变量。

然后我们再次使用 jQuery 的`when()`方法，调用我们的`getData()`函数来检索下一个 25 个视频。我们还再次使用`done()`方法来在请求完成后执行回调函数。

在这个回调函数中，我们再次将我们的`startIndex`变量增加`25`，准备请求下一组视频。`getData()`函数将填充我们的`data`对象，新的视频数据，所以我们只需调用我们的`renderer()`函数来显示新的视频，然后移除临时加载器。

在这一点上，我们应该有一个完全功能的无限加载器，当用户滚动到页面底部时加载更多视频。当我们滚动到底部时，我们应该能够运行页面并看到类似以下的内容：

![目标完成 - 迷你总结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_08_02.jpg)

# 任务完成

在这个项目中，我们编写的大部分代码都是关于获取我们想要显示的数据。实际上，添加无限滚动功能本身只需要一小部分代码 - 一个监视滚动事件并在文档滚动到底部时触发新数据请求的单个处理程序。

如你所见，这是一个非常容易作为附加层来修改现有功能的功能。这种技术最适合能够轻松按时间顺序排列的数据，新项目出现在顶部，旧项目出现在底部。

这并不一定是分页数据的完全替代，但在处理诸如新闻故事、博客文章、推文或状态更新等内容时，肯定是有意义的。它与社交数据配合得非常好。

# 你准备好大干一场了吗？一个高手挑战。

在这个项目中，我们只是为每个 YouTube 视频提供了回到全屏视频播放器的链接。所以，当访问者点击视频缩略图或标题时，他们将被送到 YouTube 实际观看视频。

虽然这样做并没有什么本质上的错，但更酷的做法是打开一个包含在`<iframe>`中嵌入的视频播放器的灯箱。这样访问者就可以在不离开您的网站的情况下观看视频。来自 YouTube 视频的响应包含一个可以用作`<iframe>`的`src`属性的链接，那为什么不试试自己连接一下呢？

你会注意到，如果你滚动到页面底部，然后立即继续向下滚动，同一组视频将被多次请求。作为另一个任务，看看你是否可以通过仅在当前没有请求正在进行时才请求更多数据来防止这种情况发生。

这应该非常容易设置，只需在请求开始时设置一个标志，结束时删除标志。然后，只有在标志未被设置时才能发出请求。


# 第九章：一个 jQuery 热图

热图可以告诉您有关您的网站如何使用的很多信息。在分析领域，这是一种有价值的工具，可以告诉您网站的哪些功能被最多使用，以及哪些区域可能需要一些改进以真正吸引访问者。

# 任务简报

在这个项目中，我们将建立自己的热图，记录任何页面的哪些区域被点击最多。我们需要建立一种实际记录每次点击发生的位置以及将该信息传输到某个地方以便存储的方法。

我们实际上将构建整个热图的两个不同部分 - 客户端部分在访问者的浏览器中执行以捕获点击，并且一个管理控制台，向网站的所有者显示热图。

我们需要考虑不同的分辨率和设备，以便捕获尽可能多的信息，并确保我们的脚本足够高效地在后台运行而不被注意到。

当然，在客户端不会发生任何可见的事情（所有这部分将做的就是记录和存储点击），但是在项目结束时，我们将能够在管理控制台中显示有关页面上所有点击的数量和位置的详细信息，如以下屏幕截图所示：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_09_01.jpg)

## 它为什么很棒？

所有的分析对网站的所有者都是有用的，并且可以提供有关访问网站的人的详细信息，包括他们的计算环境，他们进入网站的页面，他们离开的页面以及他们访问的页面数量。

从开发者的角度来看，热图同样具有信息量。您页面的哪些部分被点击最频繁？热图可以告诉您。

我们将构建的热图将适用于能够根据设备屏幕宽度改变其布局以适应的响应式网站。单个项目远远不足以涵盖响应式设计的所有方面，因为我们主要关注脚本本身，所以我们不会详细介绍它。

如果您已经使用过响应式技术，那么您将不需要额外的信息。如果您之前没有使用过响应式原理，那么这应该是一个关于该主题的温和介绍，应该作为该主题的入门手册。

## 您的热门目标

在这个项目中，我们将涵盖以下任务：

+   确定并保存环境

+   捕获访问者的点击

+   保存点击数据

+   添加管理控制台

+   请求点击数据

+   显示热图

+   允许选择不同的布局

+   显示每个布局的热图

## 任务清单

这是唯一一个我们不打算自己构建所需的 HTML 和 CSS 的项目。我们希望我们的热图能够与各种布局配合使用，测试这一点的最佳方法是使用响应式布局。如果我们自己编写代码，我们会在此项目的大部分时间里仅编写和讨论布局，甚至在开始制作热图之前。

我们将在这个项目中使用一个预先构建的响应式模板，这样我们就可以直接进入有趣的部分，而不会分心。我们将使用的模板称为 Simplex，但不幸的是，它已经不再在线上提供了。您需要使用本书附带下载的模板文件。只需将下载存档中的`simplex`文件夹复制到主`jquery-hotshots`项目目录中即可。我们需要做的就是在模板的每个 HTML 页面中添加几个脚本引用。应该更新的文件是：

+   `contact.html`

+   `gallery.html`

+   `index.html`

+   `who-we-are.html`

新的`<script>`元素可以放在每个页面的`<body>`底部。首先，我们需要 jQuery：

```js
<script src="img/jquery-1.9.0.min.js"></script>
```

我们还将使用我们在上一个项目中使用的 imagesLoaded 插件：

```js
<script src="img/jquery.imagesloaded.min.js"></script>
```

在这个项目中，我们将创建两个脚本，一个用于客户端，一个用于管理控制台。最初，我们将使用客户端脚本，因此我们应该在每个页面中添加以下内容：

```js
<script src="img/heat-map-client.js"></script>
```

当然，这个文件还不存在，所以在我们进行设置时，我们可以先创建这个文件。它应该保存在`js`目录中，与我们的其他脚本一起。

# 确定并保存环境

在我们的第一个任务中，我们将存储一些关于当前浏览环境的信息，例如当前页面的 URL。我们还将解析任何附加的样式表，查找媒体查询。

## 准备升空

我们将像我们在大多数其他项目中所做的那样，从我们的`document ready`快捷方式开始。在`heat-map-client.js`文件中，添加以下代码：

```js
$(function () {

});
```

我们添加到这个文件的所有附加代码都将放在此回调函数中。

## 启动推进器

我们首先设置一系列在整个脚本中将使用的变量。我们还需要解析任何附加的样式表，并查找**媒体查询**，以便我们可以确定为不同布局定义了哪些断点。

### 注意

媒体查询是一种在 CSS 中指定一组样式的方法，只有在满足某些条件时才会应用，例如屏幕的宽度。有关更多信息，请参阅[`en.wikipedia.org/wiki/Media_queries`](http://en.wikipedia.org/wiki/Media_queries)。

将以下代码添加到我们刚刚添加的回调函数中：

```js
var doc = $(document),
    clickStats = {
        url: document.location.href,
        clicks: []
    },
    layouts = [];

$.ajaxSetup({
    type: "POST",
    contentType: "application/json",
    dataType: "json"
});

$.each(doc[0].styleSheets, function (x, ss) {

  $.each(ss.rules, function (y, rule) {

    if (rule.media&&rule.media.length) {

      var jq = $,
          current = rule.media[0],
          mq = {
            min: (current.indexOf("min") !== -1) ? 
            jq.trim(current.split("min-width:")[1]
            .split("px")[0]) : 0,

            max: (current.indexOf("max") !== -1) ? 
            jq.trim(current.split("max-width:")[1]
            .split("px")[0]) : "none"
          };

      layouts.push(mq);
    }
  });
});

layouts.sort(function (a, b) {
    return a.min - b.min;
});

$.ajax({
    url: "/heat-map.asmx/saveLayouts",
    data: JSON.stringify({ url: url, layouts: layouts })
});
```

## 完成目标 - 迷你总结

我们首先定义了一系列变量。我们缓存了对`document`对象的引用，并使用 jQuery 功能对其进行了包装。然后我们创建了一个名为`clickStats`的对象，我们将用作会话的通用存储容器。

在对象内部，我们存储页面的 URL，并定义一个名为`clicks`的空数组，用于存储每次点击事件。最后，我们创建另一个数组，这次在我们的`clickStats`对象之外，我们将使用它来存储代表文档每个布局的对象。

我们还使用 jQuery 的`ajaxSetup()`方法为任何 AJAX 请求设置一些默认值，该方法接受包含要设置的选项的对象。我们将进行几个请求，因此设置在两个请求中都设置的任何选项的默认值是有意义的。在本例中，我们需要将`type`设置为`POST`，将`contentType`设置为`application/json`，并将`dataType`设置为`json`。

我们的下一个代码块涉及解析通过`<link>`元素附加到文档的任何样式表，并提取其中定义的任何媒体查询。

我们首先使用 jQuery 的`each()`方法来迭代存储在`document`对象的`StyleSheets`集合中的样式表对象。对于每个样式表，集合中都会有一个对象，其中包含其所有选择器和规则，包括任何媒体查询。

我们正在迭代的集合由对象组成，因此我们传递给`each()`方法的回调函数将接收当前对象的索引（我们将其设置为`x`）和当前对象本身（我们将其设置为`ss`）作为参数。

在我们的回调函数内部，我们再次使用 jQuery 的`each()`方法。这次，我们正在迭代传递给回调函数的`ss`对象的`rules`集合。此集合将包含一系列对象。我们传递给该方法的回调函数将再次接收索引（这次设置为`y`）和当前对象（这次设置为`rule`）作为参数。

对象的类型将取决于其是什么。它可能是一个`CSSImportRule`，用于`@import`语句，一个`CSSFontFaceRule`，用于`@font-face`规则，一个`CSSStyleRule`，用于样式表定义的任何选择器，或者一个`CSSMediaRule`，用于任何媒体查询。

我们只对`CSSMediaRule`对象感兴趣，因此在嵌套的`each()`回调中，我们首先检查规则对象是否具有`media`属性，以及媒体属性是否具有`length`。

只有`CSSMediaRule`对象会有一个`media`属性，但是此属性可能为空，因此我们可以在嵌套的回调中使用`if`条件检查此属性的存在并检查其是否具有`length`。

如果这两个条件都为`true`（或者是真值），我们就知道我们找到了一个媒体查询。我们首先设置一些新变量。第一个变量是`media`集合的第一项，它将包含定义媒体查询的文本字符串，第二个是一个称为`mq`的对象，我们将使用它来存储媒体查询的断点。

我们设置了该对象的两个属性 - 媒体查询的`min`和`max`值。我们通过检查文本字符串是否包含单词`min`来设置`min`属性。如果是，我们首先在术语`min-width:`上拆分字符串，然后获取`split()`函数将返回的数组中的第二项，然后在结果字符串上拆分术语`px`并获取第一项。我们可以像这样链式调用`split()`，因为该函数返回一个数组，这也是它被调用的方式。

如果字符串不包含单词`min`，我们将值设置为`0`。如果存在`max-width`，我们也执行同样的操作来提取它。如果没有`max-width`，我们将其设置为字符串`none`。创建`layout`对象后，我们将其推送到`layouts`数组中。

最后，我们对我们的断点数组进行排序，以便按升序排列。我们可以通过向 JavaScript 的`sort()`方法传递一个排序函数来做到这一点，该方法在数组上调用。我们传递的函数将从我们正在排序的数组中接收两个项目。

如果第一个对象的`min`属性小于第二个对象`b`的`min`属性，则函数将返回一个负数，这会将较小的数字放在数组中较大的数字之前 - 这正是我们想要的。

因此，我们将得到一个数组，其中每个项目都是一个特定的断点，它在数组中逐渐增加，从而使稍后检查哪个断点正在应用变得更加容易。

最后，我们需要将这些数据发送到服务器，可能是为了保存。对于这个请求，我们需要设置的唯一选项是要发送请求的 URL，以及我们用来将页面的 URL 和媒体查询数组发送到服务器的`data`选项。当然，我们之前设置的 AJAX 默认值也会被使用。

## 分类情报

如果您已经熟悉媒体查询，请随意跳到下一个任务的开始；如果没有，我们在这里简要地看一下它们，以便我们都知道我们的脚本试图做什么。

媒体查询类似于 CSS 中的`if`条件语句。CSS 文件中的媒体查询将类似于以下代码片段：

```js
@media screen and (max-width:320px) {
    css-selector { property: style; }
}
```

该语句以`@media`开头表示媒体查询。查询指定了一个媒介，例如`screen`，以及可选的附加条件，例如`max-width`或`min-width`。只有在满足查询条件时，查询中包含的样式才会被应用。

媒体查询是响应式网页设计的主要组成部分之一，另一个是相对尺寸。通常，一个响应式构建的网页将有一个或多个媒体查询，允许我们为一系列屏幕尺寸指定不同的布局。

我们包含的每个媒体查询都将设置布局之间的断点。当断点超过时，例如在前一个媒体查询中设备的最大宽度小于`320px`时，布局会按照媒体查询指示进行更改。

# 捕获访客点击

在这个任务中，我们需要构建捕获页面上发生的任何点击的部分。在页面打开时，我们希望记录有关布局和点击本身的信息。

## 启动推进器

我们可以使用以下代码捕获点击并记录我们想要存储的其他信息，该代码应直接添加到上一个任务中我们添加到`heat-map-client.js`中的`ajax()`方法之后：

```js
$.imagesLoaded(function() {

    doc.on("click.jqHeat", function (e) {

        var x = e.pageX,
              y = e.pageY,
             docWidth = doc.outerWidth(),
             docHeight = doc.outerHeight(),
             layout,
             click = {
                 url: url,
                 x: Math.ceil((x / docWidth) * 100),
                 y: Math.ceil((y / docHeight) * 100)
            };

        $.each(layouts, function (i, item) {

            var min = item.min || 0,
                  max = item.max || docWidth,
                  bp = i + 1;

            if (docWidth>= min &&docWidth<= max) {
                click.layout = bp;
            } else if (docWidth> max) {
                click.layout = bp + 1;
            }
        });

        clickStats.clicks.push(click);
    });
});
```

## 目标完成 - 小型总结

我们可以通过使用 jQuery 的`on()`方法添加处理程序来监听页面上的点击，我们还希望确保页面中的任何图像在我们开始捕获点击之前已完全加载，因为图像将影响文档的高度，进而影响我们的计算。因此，我们需要将我们的事件处理程序附加到`imagesLoaded()`方法的回调函数内。

我们将`click`指定为要监听的事件，但同时使用`jqHeat`对事件进行命名空间化。我们可能希望在一系列页面上使用此代码，每个页面可能具有自己的事件处理代码，我们不希望干扰此代码。

在事件处理程序中，我们首先需要设置一些变量。该函数将事件对象作为参数接收，我们使用它来设置我们的前两个变量，这些变量存储点击的`x`和`y`位置。此数字将表示页面上的像素点。

我们然后存储文档的宽度和高度。我们每次点击都存储这个的原因是因为页面的宽度，以及因此文档的高度，在页面打开期间可能会发生变化。

有人说只有开发人员在测试响应式构建时调整浏览器大小，但这并不总是事实。根据正在使用的媒体查询定义的断点，设备方向的变化可能会影响文档的宽度和高度，这可能会在页面加载后的任何时间发生。

接下来我们定义`layout`变量，但我们暂时不为其分配值。我们还创建一个新对象来表示点击。在此对象中，我们最初将点击坐标存储为百分比。

将像素坐标转换为百分比坐标是一个微不足道的操作，只需将像素坐标除以文档的宽度（或高度），然后将该数字乘以`100`即可。我们使用 JavaScript 的`Math.ceil()`函数使数字向上舍入到下一个整数。

接下来，我们需要确定我们处于哪种布局中。我们可以再次使用 jQuery 的`each()`方法迭代我们的`layouts`数组。回调函数的第一个参数接收`layouts`数组中当前项目的索引，第二个参数是实际对象。

在回调函数内部，我们首先设置我们的变量。这次我们需要的变量是布局的最小宽度，我们将其设置为对象的`min`属性，如果没有定义`min`，则设置为零。我们还将`max`变量设置为当前项目的`max`属性，或者如果没有`max`属性，则设置为文档的宽度。

我们最后的变量只是将当前索引加`1`。索引是从零开始的，但是对于我们的布局来说，将其标记为`1`到布局数目比标记为`0`到布局数目更有意义。

然后，我们使用一个`if`条件来确定当前应用的是哪个布局。我们首先检查当前文档宽度是否大于或等于媒体查询的最小值，并且小于或等于最大值。如果是，我们就知道我们在当前布局内，因此将转换后的布局索引保存到我们的`click`对象中。

如果我们没有匹配到任何布局，那么浏览器的大小必须大于媒体查询定义的最大`max-width`值，所以我们将布局设置为转换后的布局再加一。最后，我们将创建的`click`对象添加到我们的`clickStats`对象的`clicks`数组中。

# 保存点击数据

有人访问了一个我们的热图客户端脚本正在运行的页面，他们点击了一些内容，到目前为止我们的脚本已记录了每次点击。现在呢？现在我们需要一种将这些信息传输到服务器以进行永久存储并在管理控制台中显示的方法。这就是我们将在本任务中看到的内容。

## 启动推进器

我们可以确保将捕获的任何点击都发送到服务器以进行永久存储，使用以下代码，应在`imagesLoaded()`回调函数之后添加：

```js
window.onbeforeunload = function () {

    $.ajax({
        async: false,
        type: "POST",
        contentType: "application/json",
        url: "/heat-map.asmx/saveClicks",
        dataType: "json",
        data: JSON.stringify({ clicks: clicks })
    });
}
```

## 目标完成 - 迷你简报

我们为`window`对象附加了一个`beforeunload`事件处理程序，以便在离开页面之前将数据发送到服务器。不幸的是，这个事件并不总是被完全处理 - 有时它可能不会触发。

为了尽量将此功能减少到最小，我们直接将事件处理程序附加到原生的`window`对象上，而不是 jQuery 包装的对象，我们可以通过数组中的第一个项目访问该对象，该项目是 jQuery 对象。

使用任何 jQuery 方法，包括`on()`，都会增加额外开销，因为会调用 jQuery 方法以及底层的 JavaScript 函数。为了尽量减少这种开销，我们在这里避免使用 jQuery，并恢复到使用旧式方法来附加事件处理程序，即以`on`作为事件名的前缀，并将函数分配为它们的值。

在这个函数内部，我们需要做的就是将数据发送到服务器，以便将其插入到数据库中。我们使用 jQuery 的`ajax()`方法发起请求，并将`async`选项设置为`false`以使请求同步进行。

这很重要，并且将确保请求在 Chrome 中发出。无论如何，我们对服务器的响应不感兴趣 - 我们只需确保在页面卸载之前发出请求即可。

我们还将 `type` 设置为 `POST`，因为我们正在向服务器发送数据，并将 `contentType` 设置为 `application/json`，这将为请求设置适当的头，以确保服务器正确处理数据。

`url` 明显是我们要发送数据到的 Web 服务的 URL，并且我们将 `dataType` 设置为 `json`，这样可以更容易地在服务器上消耗数据。

最后，我们将 `clicks` 数组转换为字符串并使用浏览器的原生 JSON 引擎将其包装在对象中。我们使用 `data` 选项将字符串化的数据发送到服务器。

此时，当打开连接到该脚本的页面时，脚本将在后台静静运行，记录页面上点击的任何点的坐标。当用户离开页面时，他们生成的点击数据将被发送到服务器进行存储。

## 机密情报

不具有 JSON 引擎的浏览器，比如 Internet Explorer 的第 7 版及更低版本，将无法运行我们在此任务中添加的代码，尽管存在可在这些情况下使用的 polyfill 脚本。

更多信息请参阅 Github 上的 JSON 仓库（[`github.com/douglascrockford/JSON-js`](https://github.com/douglascrockford/JSON-js)）。

# 添加管理控制台

我在项目开始时说过我们不需要编写任何 HTML 或 CSS。那是一个小小的夸张；我们将不得不自己构建管理控制台页面，但不用担心，我们不需要写太多代码 - 我们在页面上显示的大部分内容都将是动态创建的。

## 准备起飞

根据我们的标准模板文件创建一个名为 `console.html` 的新 HTML 页面，并将其保存在我们为此项目工作的 `simplex` 目录中。接下来创建一个名为 `console.js` 的新脚本文件，并将其保存在相同的文件夹中。最后，创建一个名为 `console.css` 的新样式表，并将其保存在 `simplex` 目录内的 `css` 文件夹中。

我们应该从新的 HTML 页面的 `<head>` 中链接到新样式表：

```js
<link rel="stylesheet" href="css/console.css" />
```

我们还应该在 `<body>` 的底部链接到 jQuery 和我们的新脚本文件：

```js
<script src="img/jquery-1.9.0.min.js"></script>
<script src="img/console.js"></script>
```

最后，我们应该将类名 `jqheat` 添加到 `<body>` 元素中：

```js
<body class="jqheat">
```

## 启动推进器

页面将需要显示一个界面，用于选择要查看点击统计信息的页面。将以下代码添加到 `console.html` 的 `<body>` 中：

```js
<header>
    <h1>jqHeat Management Console</h1>
    <fieldset>
        <legend>jqHeat page loader</legend>
        <input placeholder="Enter URL" id="url" />
        <button id="load" type="button">Load page</button>
    </fieldset>
</header>
<section role="main">
    <iframe scrolling="no" id="page" />
</section>
```

我们还可以为这些元素添加一些非常基本的 CSS。将以下代码添加到 `console.css` 中：

```js
.jqheat{ overflow-y:scroll; }
.jqheat header { 
    border-bottom:1px solid #707070; text-align:center; 
}
.jqheat h1 { display:inline-block; width:100%; margin:1em 0; }
.jqheat fieldset { 
    display:inline-block; width:100%; margin-bottom:3em; 
}
.jqheat legend { display:none; }
.jqheat input { 
    width:50%; height:34px; padding:0 5px; 
    border:1px solid #707070; border-radius:3px; 
}
.jqheat input.empty{ border-color:#ff0000; }
.jqheat button { padding:9px5px; }
.jqheat section {
    width:100%;margin:auto;
    position:relative;
}
.jqheat iframe, .jqheat canvas {
    Width:100%; height:100%; position:absolute; left:0; top:0;
}
.jqheat canvas { z-index:999; }
```

在此任务中，我们不会添加任何实际功能，但我们可以准备好我们的脚本文件，以便在下一个任务中使用通常的 `document ready` 处理程序。在 `console.js` 中，添加以下代码：

```js
$(function () {

});
```

## 目标已完成 - 迷你总结

我们的页面首先包含一个包含`<h1>`和`<fieldset>`中页面标题的`<header>`元素。在`<fieldset>`内是必须的`<legend>`和一个非常简单的页面 UI，它包含一个`<input>`和一个`<button>`元素。`<input>`和`<button>`元素都有`id`属性，以便我们可以在脚本中轻松选择它们。

页面的主要内容区域由一个`<section>`元素组成，该元素具有`role`属性为`main`。使用此属性标记页面的主要内容区域是标准做法，有助于澄清该区域对辅助技术的意图。

`<section>`内部是一个`<iframe>`。我们将使用`<iframe>`来显示用户想要查看点击统计信息的页面。目前，它只有一个`id`属性，这样我们就可以轻松选择它，并且非标准的`scrolling`属性设置为`no`。我不太喜欢使用非标准属性，但在这种情况下，这是防止在加载内容文档时`<iframe>`出现无意义滚动条的最简单方法。

页面很可能会导致滚动条出现，而我们可以设置页面的`<body>`永久具有垂直滚动条，而不是在滚动条出现时发生的移动。除此之外，CSS 主要是一些定位相关的东西，我们不会深入研究。

## 机密情报

我们在`<input>`元素上使用了 HTML5 的`placeholder`属性，在支持的浏览器中，该属性的值会显示在`<input>`内部，作为内联标签。

这很有用，因为这意味着我们不必添加一个全新的元素来显示一个`<label>`，但是在撰写时，支持并不是 100%。幸运的是，有一些出色的`polyfills`可以在不支持的浏览器中提供合理的回退。

### 注意

Modernizr 团队推荐了一整套`placeholder` polyfills（还有许多其他推荐）。您可以通过访问[`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills`](https://github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills)来查看完整列表。

# 请求点击数据

控制台页面几乎为空，主要包含一个用于加载我们想要查看点击数据的页面的表单。在这个任务中，我们将看看如何加载该页面并从服务器请求其数据。

## 启动推进器

在`console.js`中的空函数中添加以下代码：

```js
var doc = $(document),
    input = doc.find("#url"),
    button = doc.find("#load"),
    iframe = doc.find("#page"),
    canvas = document.createElement("canvas");

$.ajaxSetup({
    type: "POST",
    contentType: "application/json",
    dataType: "json",
    converters: {
        "textjson": function (data) {
            var parsed = JSON.parse(data);

            return parsed.d || parsed;
        }
    }
});
```

然后，我们可以为`<button>`元素添加一个点击处理程序：

```js
doc.on("click", "#load", function (e) {
    e.preventDefault();

    var url = input.val(),
        len;

    if (url) {
        input.removeClass("empty").data("url", url);
        button.prop("disabled", true);
        iframe.attr("src", url).load(function() {
          $(this).trigger("iframeloaded");
        });
    } else {
        input.addClass("empty");
        button.prop("disabled", false);
  }
});
```

最后，我们可以为自定义的`iframeloaded`事件添加事件处理程序：

```js
doc.on("iframeloaded", function () {

    var url = input.data("url");

    $.ajax({
        type: "POST",
        contentType: "application/json",
        url: "/heat-map.asmx/getClicks",
        dataType: "json",
        data: JSON.stringify({ url:url, layout: 4 }),
        converters: {
          "textjson": function (data) {
              var parsed = JSON.parse(data);

              returnparsed.d || parsed;
          }
        }
    });
});
```

## 目标完成 - 小型总结

我们像往常一样开始，设置了一些变量。我们存储了一个包装在 jQuery 中的`document`对象的引用，我们可以使用这个引用作为起点在页面上选择任何元素，而无需每次选择元素或绑定事件处理程序时都创建一个新的 jQuery 对象。

我们还存储了一个包含页面 URL 的`<input>`元素的引用，一个紧挨着`<input>`的`<button>`的引用，以及我们将加载请求页面的`<iframe>`的引用。最后，我们设置了一个未定义的变量叫做`canvas`，我们将使用`createElement()`函数使用 JavaScript 创建一个`<canvas>`元素的引用。

当然，我们可以使用 jQuery 来创建这个元素，但我们只是创建一个单独的元素，而不是复杂的 DOM 结构，所以我们可以使用纯 JavaScript 同时获得性能提升。

与以前一样，我们可以使用`ajaxSetup()`方法来设置将发送到服务器的请求的`type`、`contentType`和`dataType`选项。我们还使用了一个转换器来转换服务器将返回的数据。

`converters` 选项接受一个对象，其中指定要用于数据类型的转换器的键，指定要用作转换器的函数的值。

一些服务器将返回包裹在属性`d`中的对象中的 JSON 数据，以增加安全性，而其他服务器不会这样做。通常，`text json`数据类型将使用 jQuery 的`parseJSON()`方法进行解析，但在这种情况下，我们的代码仍然需要从对象中提取实际数据，然后才能使用它。

相反，我们的转换器使用浏览器的原生 JSON 解析器解析 JSON，然后返回`d`的内容（如果存在）或解析的数据。这意味着处理数据的代码在数据是否包裹在对象中都是相同的。

虽然在这个特定的例子中并不是必需的，但转换器在代码分发和将在其上运行的平台事先未知的情况下，可以非常有用。

接下来，我们使用 jQuery 的`on()`方法在事件代理模式下向`document`添加了一个点击处理程序。为了添加一个代理处理程序，我们将处理程序附加到一个父元素，即`document`，并使用`on()`的第二个参数来提供事件应该被过滤的选择器。

事件从触发元素一直冒泡到外部的`window`对象。只有当触发元素与传递为第二个参数的选择器匹配时，处理程序才会被执行。第一个参数当然是事件类型，第三个参数是处理程序函数本身。

在函数内部，我们首先阻止事件的默认浏览器操作，然后将`<input>`元素的值存储在名为`url`的变量中。我们还设置了一个未定义的变量叫做`len`。我们现在不需要使用它，但以后会用到。

接下来，我们检查我们设置的 `url` 变量是否具有真值，比如长度不为零的字符串。如果是，则如果 `<input>` 元素具有 `empty` 类名，则删除它，然后使用 jQuery 的 `data()` 方法将 `<input>` 的内容设置为元素的数据。

以这种方式将 URL 关联到元素是一种很好的持久化数据的方法，这样可以从代码中的其他函数中获取数据，而这些函数无法访问事件处理程序的作用域。我们还禁用了 `<button>` 以防止重复请求。在热图绘制到屏幕上后，我们可以随后启用它。

然后，我们将从 `<input>` 元素获得的 URL 添加为 `<inframe>` 的 `src` 属性，这会导致 `<iframe>` 加载该 URL 所指向的页面。我们为 `<iframe>` 添加了一个 `load` 事件的处理程序，一旦页面加载完成，该处理程序将被触发。在这个处理程序内部，我们使用 jQuery 的 `trigger()` 方法触发了一个自定义的 `iframeloaded` 事件。

如果 `url` 变量不包含真值，则将 `empty` 类添加到 `<input>` 中，并再次启用 `<button>`。

最后，我们为自定义的 `iframeloaded` 事件添加了一个事件处理程序。自定义事件会像常规事件一样冒泡到 `document`，因此我们可以将处理程序附加到我们缓存的 `<body>` 元素，它仍然会在适当的时间被触发。

在这个处理程序中，我们通过回顾与 `<input>` 元素相关联的数据来获取已加载页面的 URL。然后，我们使用 jQuery 的 `ajax()` 方法向服务器发出请求。

我们已经再次使用 `ajaxSetup()` 设置了一些必需的 AJAX 选项为默认值，因此对于此请求，我们只设置了 `url` 和 `data` 选项。这次发送的数据是一个包含页面 URL 和获取点击数据的布局的字符串化对象。作为响应，我们期望收到一个 JSON 对象，其中包含一系列点击对象，每个对象包含指向页面上特定点的 `x` 和 `y` 坐标。

请注意，此时我们正在硬编码要加载的布局，我们将其设置为 `4`。我们将在下一部分回来，并允许用户选择要查看的布局。

# 显示热图

我们已经准备好显示热图了。在这个任务中，我们将处理点击数据以生成热图，然后使用 `<canvas>` 元素显示在 `<iframe>` 上方。

## 启动推进器

首先，我们可以为上一个任务末尾所做的 AJAX 请求添加一个成功处理程序。我们可以通过将 `done()` 方法链接到 `ajax()` 方法来实现这一点：

```js
}).done(function (clicks) {

    var loadedHeight = $("html", iframe[0].contentDocument)
.outerHeight();

    doc.find("section").height(loadedHeight);

    canvas.width = doc.width();
    canvas.height = loadedHeight;
    $(canvas).appendTo(doc.find("section"))
             .trigger("canvasready", { clicks: clicks });

});
```

接下来，我们可以为自定义的 `canvasready` 事件添加一个处理程序。这应该直接添加在 `iframeloaded` 事件处理程序之后：

```js
doc.on("canvasready", function (e, clickdata) {

    var docWidth = canvas.width,
        docHeight = canvas.height,
        ctx = canvas.getContext("2d") || null;

    if (ctx) {

        ctx.fillStyle = "rgba(0,0,255,0.5)";

        $.each(clickdata.clicks, function (i, click) {

            var x = Math.ceil(click.x * docWidth / 100),
                y = Math.ceil(click.y * docHeight / 100);

            ctx.beginPath();
            ctx.arc(x, y, 10, 0, (Math.PI/180)*360, true);
            ctx.closePath();
            ctx.fill();

        });
    }

    button.prop("disabled", false);

});
```

## 目标完成 - 迷你总结

一旦 AJAX 请求完成，我们首先存储已在 `<iframe>` 中加载的文档的高度。jQuery 方法可以在选择器之后传递第二个参数，该参数设置应该被搜索以匹配选择器的上下文。我们可以将上下文设置为页面上第一个 `<iframe>` 的 `contentDocument` 对象，我们可以使用 `frame[0]` 访问它。

设置 `<section>` 元素的 `height` 将自动使之前创建的 `<iframe>` 和 `<canvas>` 元素的 `width` 和 `height` 等于 `<section>` 的宽度和高度，以便可以全屏查看页面。

接下来，我们设置了上一个任务中创建的 `<canvas>` 元素的 `width` 和 `height` 属性。我们尚未设置 `<canvas>` 元素的 `width` 或 `height` 属性，因此默认情况下，无论 CSS 设置的可见大小如何，它都只有 300 x 300 像素的大小。因此，我们将属性设置为正确的大小。

然后，我们可以将新的 `<canvas>` 添加到页面上的 `<section>` 元素中，然后触发自定义的 `canvasready` 事件。我们将要在此事件的事件处理程序中使用服务器传递的数据，因此我们使用 `trigger()` 方法的第二个参数将其传递给处理程序函数。

我们接着为 `canvasready` 事件添加了一个处理程序。该函数接收事件对象和点击数据作为参数。在函数内部，我们首先获取 `<canvas>` 元素的 `width` 和 `height`。我们将点击数据存储为百分比，需要将其转换为像素值。

为了在 `<canvas>` 上绘制，我们需要获取一个上下文。我们可以使用 canvas 对象的 `getContext()` 函数获取 `<canvas>` 的 2D 上下文并将其存储在一个变量中。如果不支持 `<canvas>` 元素，则 `ctx` 变量将被设置为 `null`。因此，只有在上下文不为 `null` 时，我们才能继续与画布交互。

如果 `ctx` 不为 `null`，我们首先使用 canvas API 的 `clearRect()` 函数清除 `<canvas>`，然后设置我们将要在画布上绘制的颜色。我们可以将其设置为 RGBA（红、绿、蓝、透明度）字符串 `0,0,255,.05`，这是一种半透明的蓝色。这只需要设置一次。

然后，我们使用 jQuery 的 `each()` 方法迭代服务器返回的点击数据。迭代器函数将执行数组中项目的数量，传递当前项目在数组中的索引和 `click` 对象。

我们首先存储每个点击的像素的 `x` 和 `y` 位置。这些数字目前是百分比，因此我们需要将它们转换回像素值。这只是在热力图的客户端部分执行的相反计算。我们只需将百分比乘以 `<canvas>` 的 `width` 或 `height`，然后将该数字除以 `100`。

然后，我们可以在点击发生的地方在`<canvas>`上绘制一个点。我们通过使用 canvas 对象的`beginPath()`方法开始一个新路径来实现这一点。点是使用`arc()`方法绘制的，该方法传递了一些参数。前两个是圆弧中心的坐标，我们将其设置为刚计算的`x`和`y`值。

第三个参数是圆的半径。如果我们将点设置为单个像素，数据将非常难以解释，因此使用大点而不是单个像素将大大提高热图的外观。

第三个和第四个参数是弧开始和结束的角度，以弧度而不是度表示。我们可以通过从零弧度开始，到约 6.5 弧度结束来绘制完整的圆。

定义了弧之后，我们可以使用`closePath()`方法关闭路径，并使用`fill()`方法填充弧形颜色。此时，我们应该能够在浏览器中运行控制台，输入模板页面之一的 URL，并看到对应于点击的点的页面。

# 允许选择不同的布局

在项目的这个任务中，我们需要允许用户选择页面支持的每个布局。我们可以通过使用`<select>`框来实现这一点，在页面加载时用不同的布局填充它。

## 启动推进器

首先，我们可以将`<select>`元素添加到页面中。这可以放在`console.html`顶部的搜索字段和按钮之间：

```js
<select id="layouts"></select>
```

接下来，我们需要在页面加载时进行请求，为`<select>`元素填充每个不同布局的`<option>`。我们可以在之前在`console.js`中添加的`<button>`的点击处理程序中执行此操作。

它需要放在条件语句的第一个分支中，该条件语句检查是否已将 URL 输入到`<input>`中，直接在我们设置`<iframe>`的`src`之前。

```js
$.ajax({
    url: "/heat-map.asmx/getLayouts",
    data: JSON.stringify({ url: url })
}).done(function (layouts) {

    var option = $("<option/>"),
        max;

    len = layouts.length;

    function optText(type, i, min, max) {

        var s,
            t1 = "layout ";

        switch (type) {
            case "normal":
                s = [t1, i + 1, " (", min, "px - ", max, "px)"];
                break;
            case "lastNoMax":
                s = [t1, len + 1, " (", min, "px)"];
                break;
            case "lastWithMax":
                s = [t1, len + 1, " (", max, "px+)"];
                break;
        }

        return s.join("");
    }

    $.each(layouts, function (i, layout) {

        var lMin = layout.min,
            lMax = layout.max,
            text = optText("normal", i, lMin, lMax);

        if (i === len - 1) {
            if (lMax === "none") {
                text = optText("lastNoMax", null, lMin, null);
            } else {
                max = lMax;
            }
        }

        option.clone()
              .text(text)
              .val(i + 1)
              .appendTo("#layouts");
        });

        if (max) {

            var fText = optText("lastWithMax", null, null, max);

            option.clone()
                  .text(fText)
                  .val(len + 1)
                  .prop("selected",true)
                  .appendTo("#layouts");
  }
});
```

我们还可以为我们的新`<select>`元素添加一点 CSS。我们可以将这些内容放在`console.css`的底部：

```js
.jqheat select { 
    width:175px; height:36px; padding:5px;
    margin:0 .25em 0 .5em; border:1px solid #707070;
    border-radius:3px;
}
```

## 目标完成 - 小型总结

首先，我们向服务器发出请求以获取布局信息。`url`设置为返回布局的 Web 服务，`data`是我们想要布局的页面的 URL。

我们使用`done()`方法设置了一个成功处理程序，这是向承诺对象添加成功处理程序的推荐技术，以便在它们解决时调用。在处理程序中，我们首先设置了一些变量。

我们创建一个`<option>`元素，因为我们每个布局都需要一个，所以可以使用`clone()`方法克隆它，需要多少次就可以克隆多少次。我们还更新了之前创建但未定义的`len`变量，将其更新为布局的数量，即函数将接收的数组的`length`，以及一个未定义的变量`max`。

接下来，我们定义了一个名为`optText()`的函数，我们可以使用它来为我们创建的每个`<option>`元素生成文本。该函数将接受要创建的字符串类型、索引和`min`和`max`值。

在此函数中，我们设置了几个变量。第一个变量称为`s`，在这一点上是未定义的。第二个变量`t1`用于存储在字符串的每个变体中使用的一些简单文本。

然后，我们使用`switch`条件来确定要构建的字符串，该字符串基于类型确定，该类型将作为第一个参数传递到函数中，并将设置为`normal`、`lastNoMax`或`lastWithMax`，并应该考虑可能找到的不同类型的媒体查询。

在正常情况下，我们指定了`min`和`max`值。当没有`max`值时，我们使用`min`值构建字符串，当有`max`值时，我们使用`max`值构建字符串。

每个字符串都使用数组构造，然后在函数末尾，我们通过连接所创建的任一数组来返回一个字符串。

然后我们使用 jQuery 的`each()`方法来迭代服务器返回的`layouts`对象。与往常一样，迭代器函数会传入当前项的索引和当前项本身作为参数。

在迭代器函数内部，我们设置了变量，这些变量在这种情况下是当前布局对象的`min`和`max`属性值，以及文本字符串的普通变体，我们肯定会至少使用一次。我们调用我们的`optText()`函数并将结果存储供以后使用。

然后我们检查是否处于最后一次迭代，我们会在索引等于之前存储的`layouts`数组长度减去`1`时知道。如果我们处于最后一次迭代，我们会检查`max`值是否等于字符串`none`。如果是，我们再次调用我们的`optText()`函数，并将文本设置为`lastNoMax`类型，该类型为我们生成所需的文本字符串。如果不是，则将`max`变量设置为当前对象的`max`值，该变量最初被声明为未定义。最后，我们为`layouts`数组中的每个对象创建所需的`<option>`元素。给定我们设置的文本，以及索引加`1`的值。创建完成后，将`<option>`追加到`<select>`元素中。

最后，我们检查`max`变量是否有一个真值。如果是，我们再次调用我们的`optText()`函数，这次使用`lastWithMax`类型，并创建另一个`<option>`元素，将其设置为选定项。这是必需的，因为我们的布局比`layouts`数组中的对象多一个。

当我们在浏览器中运行页面时，我们应该发现，当我们在`<input>`中输入 URL 并点击加载页面时，`<select>`元素会填充一个`<option>`，每个布局对应一个选项。

## 机密情报

在我们的`optText()`函数中，`switch`语句中的中间`case`（`lastNoMax`）实际上在这个示例中不会被使用，因为我们使用的模板中的媒体查询的结构如何。在这个示例中，最后一个断点的媒体查询是`769px`到`1024px`。有时，媒体查询可能结构化，使得最后一个断点只包含`min-width`。

我已经包含了`switch`的这个`case`，以使代码支持这种其他类型的媒体查询格式，因为这是相当常见的，当您自己使用媒体查询时，您可能会遇到它。

# 显示每个布局的热图

现在，我们在`<select>`元素中有每个布局后，我们可以将其连接起来，以便当所选布局更改时，页面更新为显示该布局的热图。

## 启动推进器

在这个任务中，我们需要修改先前任务中编写的一些代码。我们需要更改`<button>`的点击处理程序，以便布局不会硬编码到请求中。

首先，我们需要将`len`变量传递给`iframeloaded`事件的处理程序。我们可以通过向`trigger()`方法添加第二个参数来实现这一点：

```js
$(this).trigger("iframeloaded", { len: len });
```

现在，我们需要更新回调函数，以便该对象由该函数接收：

```js
doc.on("iframeloaded", function (e, maxLayouts) {
```

现在，我们可以修改硬编码的布局`4`的位，在向服务器请求点击数据时传递给服务器的数据中：

```js
data: JSON.stringify({ url: url, layout: maxLayouts.len + 1 }),
```

现在我们准备好在`<select>`更改时更新热图了。在`console.js`的`canvasready`处理程序之后直接添加以下代码：

```js
doc.on("change", "#layouts", function () {

    var url = input.data("url"),
          el = $(this),
          layout = el.val();

    $.ajax({
        url: "/heat-map.asmx/getClicks",
        data: JSON.stringify({ url: url, layout: layout })
    }).done(function (clicks) {

        doc.find("canvas").remove();

        var width,
              loadedHeight,
              opt = el.find("option").eq(layout - 1),
              text = opt.text(),
              min = text.split("(")[1].split("px")[0],
              section = doc.find("section"),
              newCanvas = document.createElement("canvas");

        if (parseInt(layout, 10) === el.children().length) {
            width = doc.width();
        } else if (parseInt(min, 10) > 0) {
            width = min; 
        } else {
            width = text.split("- ")[1].split("px")[0];
      }

        section.width(width);
        newCanvas.width = width;

        loadedHeight = $("html", 
        iframe[0].contentDocument).outerHeight();

        section.height(loadedHeight);
        newCanvas.height = loadedHeight;

        canvas = newCanvas;

        $(newCanvas).appendTo(section).trigger("canvasready", { 
            clicks: clicks });
        });
    });
```

## 完成目标 - 小结

我们首先委派我们的处理程序给文档，就像我们大多数其他事件处理程序一样。这次，我们正在监听由具有`id`为`layouts`的元素触发的`change`事件，这是我们在上一个任务中添加的`<select>`元素。

然后，我们继续遵循以前的形式，设置一些变量。我们获取保存为`<input>`元素的`data`的 URL。我们还缓存了`<select>`元素和所选`<option>`的值。

接下来，我们需要发起一个 AJAX 请求来获取所选布局的热图。我们将`url`设置为将返回此信息的 Web 服务，并将我们想要的热图的`url`和布局作为请求的一部分发送。不要忘记，此请求也将使用我们使用`ajaxSetup()`设置的默认值。

我们再次使用`done()`方法添加一个请求的成功处理程序。当收到响应时，我们首先从页面中删除现有的`<canvas>`元素，然后设置一些更多的变量。

前两个变量一开始是未定义的；我们马上会填充这些。我们存储了所选的`<option>`，以便我们可以获取其文本，该文本存储在下一个变量中。我们通过分割我们刚刚存储的文本来获取断点的最小宽度，然后缓存页面上的`<section>`的引用。最后，我们创建一个新的`<canvas>`元素来显示新的热图。

后续的条件 if 语句处理设置我们的第一个未定义变量 - `width`。第一个分支测试所请求的布局是否是最后一个布局，如果是，则将新的`<canvas>`设置为屏幕的宽度。

如果未请求最后一个布局，则条件的下一个分支检查布局的最小宽度是否大于`0`。如果是，则将`width`变量设置为最小断点。

当断点的最小宽度为`0`时，使用最终分隔`<option>`文本获得的最大断点`width`。

然后，我们使用刚刚计算出的宽度来设置`<section>`元素和新的`<canvas>`元素的宽度。

接下来，我们可以定义我们的第二个未定义变量 - `loadedHeight`。这个变量的计算方式与之前相同，通过访问加载到`<iframe>`中的文档，并使用 jQuery 的`outerHeight()`方法获取其`document`对象的高度来获取，其中包括元素可能具有的任何填充。一旦我们有了这个值，我们就可以设置`<section>`元素和新的`<canvas>`元素的高度。

当我们消耗点击数据并生成热图时，我们将再次触发我们的`canvasready`事件。不过，在此之前，我们只需将新创建的`<canvas>`元素保存回我们在`console.js`顶部设置的`canvas`变量即可。

此时，我们应该能够加载 URL 的默认热图，然后使用`<select>`元素查看另一个布局的热图：

![目标完成 - 小结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_09_02.jpg)

## 机密情报

我使用了**MS SQL**数据库来存储数据，并使用包含此项目所需的各种 Web 方法的**C#** Web 服务。在本书附带的代码下载中包含了数据库的备份和 Web 服务文件的副本，供您使用。

MS SQL express 是 SQL 服务器的免费版本，可以将数据库恢复到该版本，而免费的 Visual Studio 2012 for web 将愉快地通过其内置的开发服务器运行 Web 服务。

如果您没有安装这些产品，并且您可以访问 Windows 机器，我强烈建议您安装它们，这样您就可以看到此项目中使用的代码运行情况。也可以轻松地使用开源替代产品 PHP 和 MySQL，尽管您将需要自己编写此代码。

# 任务完成

在这个项目中，我们构建了一个简单的热图生成器，用于捕获使用响应式技术构建的网页上的点击数据。我们将热图生成器分为两部分——一些在网站访问者的浏览器中运行的代码，用于捕获屏幕上的每次点击，以及一个与之配合使用的简单管理控制台，可以在其中选择要为其生成热图的页面的 URL 和要显示的布局。

虽然我们必须允许一定的误差范围，以考虑像素到百分比的转换及其逆过程，不同的屏幕分辨率，以及不同断点之间的范围，但这个易于实现的热图仍然可以为我们提供有价值的信息，了解我们的网站如何使用，哪些功能受欢迎，哪些功能浪费了屏幕空间。

# 你准备好全力以赴了吗？挑战热血青年

我们还没有处理的一个问题是颜色。我们的热图由均匀蓝色的点构成。由于它们是半透明的，在密集区域出现更多点时会变暗，但是随着足够多的数据，我们应该尽量改变颜色，从红色、黄色一直到白色为最多点击的区域。看看你是否能自己添加这个功能，真正为项目锦上添花。


# 第十章：带有 Knockout.js 的可排序、分页表格

Knockout.js 是一个很棒的 JavaScript **模型-视图-视图模型**（**MVVM**）框架，可以帮助你在编写复杂的交互式用户界面时节省时间。它与 jQuery 配合得非常好，甚至还具有用于构建显示不同数据的重复元素的内置基本模板支持。

# 任务简报

在本项目中，我们将使用 jQuery 和 Knockout.js 从数据构建分页表格。客户端分页本身是一个很好的功能，但我们还将允许通过提供可点击的表头对表格进行排序，并添加一些附加功能，如根据特定属性过滤数据。

到此任务结束时，我们将建立如下屏幕截图所示的东西：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_10_01.jpg)

## 为什么这很棒？

构建快速响应用户交互的复杂 UI 是困难的。这需要时间，而且应用程序越复杂或交互性越强，花费的时间就越长，需要的代码也越多。而应用程序需要的代码越多，就越难以保持组织和可维护性。

虽然 jQuery 擅长帮助我们编写简洁的代码，但它从未旨在构建大规模、动态和交互式应用程序。它功能强大，擅长自己的工作以及它被设计用来做的事情；只是它并没有被设计用来构建整个应用程序。

在构建大规模应用程序时需要其他东西，需要提供一个框架，可以在其中组织和维护代码。Knockout.js 就是这样一个旨在实现此目标的框架之一。

Knockout.js 被称为一个 MVVM 框架，它基于三个核心组件 - **模型**、**视图** 和 **视图模型**。这类似于更为人熟知的 MVC 模式。这些和其他类似的模式的目的是提供清晰的应用程序可视部分和管理数据所需代码之间的分离。

**模型** 可以被认为是应用程序的数据。实际上，实际数据是模型的结果，但在客户端工作时，我们可以忽略数据是如何被服务器端代码访问的，因为通常我们只是发出 AJAX 请求，数据就会被传递给我们。

**视图** 是数据的可视化表示，实际的 HTML 和 CSS 用于向用户呈现模型。在使用 Knockout.js 时，应用程序的这一部分也可以包括绑定，将页面上的元素映射到特定的数据部分。

**视图模型** 位于模型和视图之间，实际上是视图的模型 - 视图状态的简化表示。它管理用户交互，生成并处理对数据的请求，然后将数据反馈到用户界面。

## 你的炫酷目标

完成此任务所需的任务如下：

+   渲染初始表格

+   对表格进行排序

+   设置页面大小

+   添加上一页和下一页链接

+   添加数字页面链接

+   管理类名

+   重置页面

+   过滤表格

## 任务清单

在这个项目中我们将使用 Knockout.js，所以现在你需要获取它的副本。这本书印刷时的最新版本为 2.2.1，可以从以下网址下载：[`knockoutjs.com/downloads/index.html`](http://  http://knockoutjs.com/downloads/index.html)。应将其保存在主`jquery-hotshots`项目文件夹内的`js`目录中，命名为`knockout-2.2.1.js`。

我们还需要一些数据来完成这个项目。我们将需要使用一个相当大的数据集，其中包含可以按多种方式排序的数据。我们将使用元素周期表的 JSON 格式作为我们的数据源。

我已经提供了一个文件作为这个示例的一部分，名为`table-data.js`，其中包含一个名为`elements`的属性的对象。该属性的值是一个对象数组，其中每个对象表示一个元素。对象的格式如下：

```js
{ 
    name: "Hydrogen", 
    number: 1, 
    symbol: "H", 
    weight: 1.00794, 
    discovered: 1766,
    state: "Gas"
}
```

# 渲染初始表格

在项目的第一个任务中，我们将构建一个超级简单的 ViewModel，添加一个基本的 View，并将 Model 渲染到一个裸的`<table>`中，没有任何增强或附加功能。这将使我们能够熟悉 Knockout 的一些基本原理，而不是直接投入到深水区。

## 准备起飞

此时我们创建项目中将要使用的文件。将模板文件另存为`sortable-table.html`，保存在根项目目录中。

我们还需要一个名为`sortable-table.css`的样式表，应将其保存在`css`文件夹中，并且一个名为`sortable-table.js`的 JavaScript 文件，当然应将其保存在`js`目录中。

HTML 文件应链接到每个资源，以及`knockout-2.2.1.js`文件。样式表应在`common.css`之后直接链接，我们迄今为止在本书中大部分项目中都使用了它，而`knockout.js`、`table-data.js`和这个项目的自定义脚本文件（`sortable-table.js`）应在链接到 jQuery 之后添加，按照这个顺序。

## 启动推进器

首先我们可以构建 ViewModel。在`sortable-table.js`中，添加以下代码：

```js
$(function () {

    var vm = {
        elements: ko.observableArray(data.elements)
    }

    ko.applyBindings(vm);

});
```

接下来，我们可以添加 View，它由一些简单的 HTML 构建而成。将以下标记添加到`sortable-table.html`的`<body>`中，位于`<script>`元素之前：

```js
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Atomic Number</th>
            <th>Symbol</th>
            <th>Atomic Weight</th>
            <th>Discovered</th>
        </tr>
    </thead>
    <tbody data-bind="foreach: elements">
        <tr>
            <td data-bind="text: name"></td>
            <td data-bind="text: number"></td>
            <td data-bind="text: symbol"></td>
            <td data-bind="text: weight"></td>
            <td data-bind="text: discovered"></td>
        </tr>
    </tbody>
</table>
```

最后，我们可以通过将以下代码添加到`sortable-table.css`来为我们的`<table>`及其内容添加一些基本样式：

```js
table { 
    width:650px; margin:auto; border-collapse:collapse;
}
tbody { border-bottom:2px solid #000; }
tbodytr:nth-child(odd) td { background-color:#e6e6e6; }
th, td { 
    padding:10px 50px 10px 0; border:none; cursor:default;
}
th { 
    border-bottom:2px solid #000;cursor:pointer;
    position:relative;
}
td:first-child, th:first-child { padding-left:10px; }
td:last-child { padding-right:10px; }
```

## 目标完成 - 迷你简报

在我们的脚本中，首先添加了通常的回调函数，在文档加载时执行。在此之中，我们使用存储在变量`vm`中的对象字面量创建了 ViewModel。

此对象唯一的属性是`elements`，其值是使用 Knockout 方法设置的。Knockout 添加了一个全局的`ko`对象，我们可以使用它来调用方法。其中之一是`observableArray()`方法。该方法接受一个数组作为参数，并且传递给该方法的数组将变为可观察的。这就是我们应用程序的数据。

在 Knockout 中，诸如字符串或数字之类的基本类型可以是可观察的，这使它们能够在其值更改时通知订阅者。可观察数组类似，只是它们与数组一起使用。每当向可观察数组添加或删除值时，它都会通知任何订阅者。

定义了我们的 ViewModel 之后，我们需要应用可能存在于 View 中的任何绑定。我们马上就会看到这些绑定；暂时只需知道，在调用 Knockout 的 `applyBindings()` 方法之前，我们添加到 View 的任何绑定都不会生效。

我们添加的 HTML 几乎毫无特色，只是一个简单的`<table>`，每个元素的属性都有一个列。如果你查看`table-data.js`文件，你会看到数组中每个元素的属性与`<th>`元素匹配。

第一件有趣的事情是我们添加到`<tbody>`元素的`data-bind`属性。这是 Knockout 用于实现声明式绑定的机制。这是我们将 View 中的元素与 ViewModel 属性连接起来的方式。

`data-bind`属性的值由两部分组成 - 绑定和要连接到的 ViewModel 属性。第一部分是绑定，我们将其设置为`foreach`。这是 Knockout 的流程控制绑定之一，其行为方式类似于常规 JavaScript 中的标准`for`循环。

绑定的第二部分是要绑定到的 ViewModel 属性。我们目前的 ViewModel 只有一个属性，即`elements`，其中包含一个可观察数组。`foreach`绑定将映射到一个数组，然后为数组中的每个项渲染任何子元素。

此元素的子元素是一个`<tr>`和一系列`<td>`元素，因此我们将在`elements`数组中的每个项中获得一个表格行。为了将`<td>`元素填充内容，我们将使用另一个 Knockout 绑定 - `text`绑定。

`text`绑定绑定到单个可观察属性，因此我们有一个`<td>`绑定到`elements`数组中每个对象的每个属性。每个`<td>`的文本将设置为当前数组项中每个属性的值。

我们在任务结束时添加的 CSS 纯粹是为了表现目的，与 Knockout 或 jQuery 无关。此时，我们应该能够在浏览器中运行页面，并在一个整洁的`<table>`中看到来自`table-data.js`的数据显示出来。

## 机密情报

View 元素和 ViewModel 属性之间的绑定是 Knockout 的核心。ViewModel 是 UI 状态的简化版本。由于绑定，每当底层 ViewModel 发生更改时，视图将更新以反映这些更改。

因此，如果我们以编程方式向可观察数组添加一个新的元素对象，则`<table>`将立即更新以显示新元素。类似地，如果我们从 ViewModel 中的数组中删除一个项目，则相应的`<tr>`将立即被删除。

# 对表格进行排序

在这个任务中，我们可以更改`<th>`元素，使其可点击。当其中一个被点击时，我们可以按照被点击的列对表格行进行排序。

## 启动推进器

首先，我们可以更新`sortable-table.html`中包含的`<tr>`和`<th>`元素：

```js
<tr data-bind="click: sort">
    <th data-bind="css: nameOrder">Name</th>
    <th data-bind="css: numberOrder">Atomic Number</th>
    <th data-bind="css: symbolOrder">Symbol</th>
    <th data-bind="css: weightOrder">Atomic Weight</th>
    <th data-bind="css: discoveredOrder">Discovered</th>
</tr>
```

接下来，我们可以在`sortable-table.js`中的 ViewModel 中添加一些新的可观察属性：

```js
nameOrder: ko.observable("ascending"),
numberOrder: ko.observable("ascending"),
symbolOrder: ko.observable("ascending"),
weightOrder: ko.observable("ascending"),
discoveredOrder: ko.observable("ascending"),
```

我们还添加了一个名为`sort`的新方法：

```js
sort: function (viewmodel, e) {

    var orderProp = $(e.target).attr("data-bind")
                               .split(" ")[1],

        orderVal = viewmodel[orderProp](),
        comparatorProp = orderProp.split("O")[0];

    viewmodel.elements.sort(function (a, b) {

        var propA = a[comparatorProp],
            propB = b[comparatorProp];

        if (typeof (propA) !== typeof (propB)) {

            propA = (typeof (propA) === "string") ? 0 :propA;
            propB = (typeof (propB) === "string") ? 0 :propB;
        }

        if (orderVal === "ascending") {
            return (propA === propB) ? 0 : (propA<propB) ? -1 : 1;

        } else {
            return (propA === propB) ? 0 : (propA<propB) ? 1 : -1;

        }

    });

    orderVal = (orderVal === "ascending") ? "descending" : "ascending";

    viewmodelorderProp;

    for (prop in viewmodel) {
        if (prop.indexOf("Order") !== -1 && prop !== orderProp) {
            viewmodelprop;
        }
    }
}
```

最后，我们可以添加一些额外的 CSS 来样式化我们可点击的`<th>`元素：

```js
.ascending:hover:after { 
    content:""; display:block; border-width:7px; 
    border-style:solid; border-left-color:transparent; 
    border-right-color:transparent; border-top-color:#000;
    border-bottom:none; position:absolute; margin-top:-3px; 
    right:15px; top:50%; 
}
.descending:hover:after {
    content:""; display:block; border-width:7px; 
    border-style:solid; border-left-color:transparent; 
    border-right-color:transparent; border-bottom-color:#000; 
    border-top:none; position:absolute; margin-top:-3px; 
    right:15px; top:50%; 
}
```

## 目标完成 - 小结

首先，我们使用更多的绑定更新了我们的 HTML。首先，我们使用`data-bind`属性在父级`<tr>`上添加了`click`绑定。`click`绑定用于向任何 HTML 元素添加事件处理程序。

处理程序函数可以是 ViewModel 方法或任何常规 JavaScript 函数。在这个示例中，我们将处理程序绑定到一个名为`sort`的函数，它将是我们 ViewModel 的一个方法。

请注意，我们将绑定添加到父级`<tr>`而不是各个`<th>`元素。我们可以利用事件向上冒泡的特性来实现一种非常简单且计算成本低廉的事件委派形式。

我们还为每个`<th>`元素添加了`css`绑定。`css`绑定用于向元素添加类名。因此，元素获取的类名取决于它绑定到的 ViewModel 属性。我们的每个`<th>`元素都绑定到不同的 ViewModel 属性，并将用作我们排序的一部分。

接下来，我们对我们的脚本文件进行了一些更改。首先，我们添加了一系列新的可观察属性。我们添加了以下属性：

+   `nameOrder`

+   `numberOrder`

+   `symbolOrder`

+   `weightOrder`

+   `discoveredOrder`

这些属性中的每一个都是可观察的，这是必需的，以便当任何一个属性发生更改时，`<th>`元素的类名会自动更新。每个属性最初都设置为字符串`ascending`，因此每个`<th>`元素都将被赋予这个类名。

### 对数据进行排序

接下来，我们将我们的`sort`方法添加到 ViewModel 中。因为此方法是事件处理绑定的一部分（我们添加到`<tr>`的`click`绑定），所以该方法将自动传递两个参数 - 第一个是 ViewModel，第二个是事件对象。我们可以在函数中使用这两个参数。

首先我们定义一些变量。我们使用 jQuery 选择被点击的任何`<th>`元素。我们可以使用事件对象的`target`属性来确定这一点，然后我们用 jQuery 包装它，以便我们可以在所选元素上调用 jQuery 方法。

我们可以使用 jQuery 的`attr()`方法获取元素的`data-bind`属性，然后根据绑定名称和绑定到的属性之间的空格拆分它。所以例如，如果我们在浏览器中点击包含**Name**的`<th>`，我们的第一个变量`orderProp`将被设置为`nameOrder`。

下一个变量`orderVal`被设置为 ViewModel 属性的当前值，`orderProp`变量指向的属性。Knockout 提供了一种简单的方法来以编程方式获取或设置任何 ViewModel 属性。

如果我们想获取属性的值，我们将其调用为函数，如下所示：

```js
property();
```

如果我们想设置属性，我们仍然像调用函数一样调用它，但是我们将要设置的值作为参数传递：

```js
property(value);
```

因此，继续上述点击包含**Name**的`<th>`的例子，`orderVal`变量将具有值`ascending`，因为这是每个`…Order`属性的默认值。请注意我们如何使用`orderProp`变量和方括号表示法获取正确的值。

我们的最后一个变量`comparatorProp`很方便地存储我们将要根据其对`elements`数组中的对象进行排序的属性。我们的 ViewModel 属性在末尾有字符串`Order`，但是`elements`数组中的对象内部的属性没有。因此，为了获取正确的属性，我们只需要在大写`O`上拆分字符串，并从`split()`返回的数组中取第一个项目。

### observableArray

接下来我们使用`sort()`方法进行排序。看起来我们在使用 JavaScript 的普通`sort()`函数，但实际上我们并不是。不要忘记，`elements`数组不只是一个普通数组；它是一个**observableArray**，因此虽然我们可以从元素的`viewModel`属性中获取基础数组，然后在其上调用普通的 JavaScript`sort()`函数，但 Knockout 提供了更好的方法。

Knockout 提供了一系列可以在 observable 数组上调用的标准 JavaScript 数组函数。在很大程度上，这些函数的工作方式与它们的原始 JavaScript 对应函数非常相似，但是尽可能使用 Knockout 变体通常更好，因为它们在浏览器中得到了更好的支持，特别是传统浏览器，比原始 JavaScript 版本。一些 Knockout 方法还为我们提供了一些额外的功能或便利。

其中一个例子是使用 Knockout 的`sort()`方法。这并不是我们在这里使用该方法的原因，但这是 Knockout 如何改进原始 JavaScript 函数的一个例子。

JavaScript 内置的默认`sort()`函数对数字的排序效果不是很好，因为它会自动将数字转换为字符串，然后根据字符串而不是数字进行排序，导致我们得到意料之外的结果。

Knockout 的`sort()`方法不会自动对字符串或数字数组进行排序。在这一点上，我们不知道我们将排序字符串，数字，还是两者兼有，因为`elements`数组中的对象既包含字符串又包含数字，有时在同一个属性中。

就像 JavaScript 的`sort()`函数一样，传递给 Knockout 的`sort()`方法的函数将自动传递两个值，这两个值是当前要排序的项。与 JavaScript 的`sort()`函数一样，Knockout 的`sort()`方法应返回`0`，如果要比较的值相等，返回负数，如果第一个值较小，或者返回正数，如果第一个值较大。

在传递给`sort()`的函数中，我们首先从对象中获取我们将要比较的值。传递给函数的两个值都将是对象，但我们只想比较每个对象内部的一个属性，所以我们为了方便起见将要比较的属性存储在`propA`和`propB`变量中。

### 比较不同类型的值

我之前提到有时我们可能会比较不同类型的值。这可能发生在我们按日期列排序时，其中可能包含形式为年份的数字，或者可能是字符串`Antiquity`，而这些对象中有一些包含这样的值。

所以我们使用 JavaScript 的`typeof`运算符和普通的`if`语句来检查要比较的两个值是否属于相同的类型。如果它们不是相同的类型，我们检查每个属性是否是字符串，如果是，就将其值转换为数字`0`。在`if`语句内部，我们使用 JavaScript 的三元运算符来简洁地表达。

### 检查顺序

然后，我们检查我们在一会儿设置的`orderProp`变量是否设置为 ascending。如果是，我们执行标准排序。我们检查两个值是否相等，如果是，返回`0`。如果两个值不相等，我们可以检查第一个值是否小于第二个值，如果是，返回`-1`，如果不是，返回`1`。为了将整个语句保持在一行上，我们可以使用复合的三元运算符。

如果顺序不是`ascending`，那么必须是`descending`，所以我们可以执行降序排序。这段代码几乎与之前的代码相同，只是如果第一个值小于第二个值，我们返回`1`，如果不是，我们返回`-1`，这与条件语句的第一个分支相反。

然后，我们需要更新我们刚刚排序过的列的`…Order`属性的值。这段代码的作用类似于一个简单的开关 - 如果值当前设置为`ascending`，我们将其设置为`descending`。如果它设置为`descending`，我们只需将其设置为`ascending`。这种行为允许的是，当单击`<th>`元素第一次时，它将执行默认的升序排序。如果再次单击它，它将执行降序排序。

最后，如果我们的 ViewModel 的其他`…Order`属性已更改，我们希望重置它们。我们使用一个简单的 JavaScript `for in`循环来迭代我们的 ViewModel 的属性。对于每个属性，我们检查它是否包含字符串`Order`，以及它是否不是我们刚刚更新的属性。

如果这两个条件都满足，我们将当前属性的值重置为默认值`ascending`。

### 添加图标

我们添加的 CSS 用于在悬停时向每个`<th>`元素添加一个小的排序图标。我们可以利用 CSS 形状技术来创建一个向下指向的箭头，表示升序，和一个向上指向的箭头，表示降序。我们还使用`:after` CSS 伪选择器来避免硬编码非语义元素，比如`<span>`或类似的元素，来显示形状。显示哪个箭头取决于我们绑定到 ViewModel 的`…Order`属性的类名。

### 注意

如果您以前从未使用过 CSS 形状，我强烈建议您研究一下，因为它们是创建图标的绝佳方法，而无需非语义占位符元素或 HTTP 重的图像。有关更多信息，请查看 [`css-tricks.com/examples/ShapesOfCSS/`](http://css-tricks.com/examples/ShapesOfCSS/) 上的 CSS 形状指南。

此时，我们应该能够在浏览器中运行页面，并单击任何一个标题，一次执行升序排序，或者点击两次执行降序排序：

![添加图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_10_02.jpg)

# 设置页面大小

所以我们添加的排序功能非常棒。但是`<table>`仍然相当大且笨重 - 实际上太大了，无法完整地在页面上显示。所以分页正好适用。

我们需要做的一件事是确定每页应包含多少项数据。我们可以在脚本中硬编码一个值，表示每页显示的项目数，但更好的方法是添加一个 UI 功能，让用户可以自己设置每页显示的项目数。这就是我们将在此任务中做的事情。

## 启动推进器

我们可以从添加一些额外的标记开始。直接在`<tbody>`元素之后添加以下元素：

```js
<tfoot>
    <tr>
        <tdcolspan="5">
            <div id="paging" class="clearfix">
                <label for="perPage">Items per page:</label>
                <select id="perPage" data-bind="value: pageSize">
                    <option value="10">10</option>
                    <option value="30">30</option>
                    <option value="all">All</option>
                </select>
            </div>
        </td>
    </tr>
</tfoot>
```

我们还需要对`<tbody>`元素进行一些小改动。它目前具有对观察到的元素数组的`foreach`绑定。我们将在稍后为我们的 ViewModel 添加一个新属性，然后需要更新`sortable-table.html`中的绑定，以便它链接到这个新属性：

```js
<tbody data-bind="foreach: elementsPaged">
```

接下来，我们可以在 `sortable-table.js` 中添加一些新的 ViewModel 属性：

```js
pageSize: ko.observable(10),
currentPage: ko.observable(0),
elementsPaged: ko.observableArray(),
```

最后，我们可以添加一个特殊的新变量，称为 **computed observable**。这应该在 `vm` 变量之后出现：

```js
vm.createPage = ko.computed(function () {

    if (this.pageSize() === "all") {
        this.elementsPaged(this.elements.slice(0));
    } else {
        var pagesize = parseInt(this.pageSize(), 10),
            startIndex = pagesize * this.currentPage(),
            endIndex = startIndex + pagesize;

        this.elementsPaged(this.elements.slice(startIndex,endIndex));
    }

}, vm);
```

## 完成目标 - 小结

我们从添加一个包含一个行和一个单元格的 `<tfoot>` 元素开始这项任务。单元格内是用于我们分页元素的容器。然后我们有一个 `<label>` 和一个 `<select>` 元素。

`<select>` 元素包含一些选项，用于显示不同数量的项目，包括一个查看所有数据的选项。它还使用 Knockout 的 `value data-bind` 属性将 `<select>` 元素的值链接到 ViewModel 上的一个名为 `pageSize` 的属性。这种绑定意味着每当 `<select>` 元素的值更改时，例如用户进行选择时，ViewModel 属性将自动更新。

此绑定是双向的，因此如果我们在脚本中以编程方式更新 `pageSize` 属性，则页面上的元素将自动更新。

然后，我们将 `<tbody>foreach` 绑定到我们的 ViewModel 上的一个新属性，称为 `elementsPaged`。我们将使用这个新属性来存储 `elements` 数组中项目的一个子集。该属性中的实际项目将构成数据的单个页面。

接下来，我们在存储在 `vm` 变量中的对象字面量中添加了一些新属性，也称为我们的 ViewModel。这些属性包括我们刚刚讨论的 `currentPage`、`pageSize` 和 `elementsPaged` 属性。

我们最后要做的是添加一个名为 **computed observable** 的 Knockout 功能。这是一个非常有用的功能，它让我们监视一个或多个变量，并在任何可观察变量更改值时执行代码。

我们使用 `ko.computed()` 方法将计算的 observable 设置为 ViewModel 的一个方法，将函数作为第一个参数传入。ViewModel 作为第二个参数传入。现在我们不在一个附加到我们的 ViewModel 的方法中，所以我们需要将 ViewModel 传递给 `computed()` 方法，以便将其设置为 ViewModel。

在作为第一个参数传递的函数中，我们引用了刚刚添加的三个新 ViewModel 属性。在此函数中引用的任何 ViewModel 属性都将被监视变化，并在此发生时调用该函数。

此函数的全部功能是检查 `pageSize()` 属性是否等于字符串 `all`。如果是，则将元素数组中的所有对象简单地添加到 `elementsPaged` 数组中。它通过取 `elements` 数组的一个切片来实现这一点，该切片从第一个项目开始。当 `slice()` 与一个参数一起使用时，它将切片到数组的末尾，这正是我们需要获得整个数组的方式。

如果`pageSize`不等于字符串`all`，我们首先需要确保它是一个整数。因为这个 ViewModel 属性与页面上的`<select>`元素相关联，有时值可能是一个数字的字符串而不是实际的数字。我们可以通过在属性上使用`parseInt()` JavaScript 函数并将其存储在变量`pagesize`中，在函数的其余部分中使用它来确保它始终是一个数字。

接下来，我们需要确定传递给`slice()`作为第一个参数的起始索引应该是什么。要解决此问题，我们只需将`pageSize`属性的值乘以最初设置为`0`的`currentPage`属性的值。

然后，我们可以使用`elements`数组的一个片段来填充`elementsPaged`数组，该片段从我们刚刚确定的`startIndex`值开始，到`endIndex`值结束，该值将是`startIndex`加上每页项目数。

当我们在浏览器中运行页面时，`<select>`框将最初设置为值 10，这将触发我们的计算可观察到的行为，选择`elements`数组中的前 10 个项目，并在`<table>`中显示它们。

我们应该发现，我们可以使用`<select>`来动态更改显示的条目数量。

## 机密情报

在此任务中，我们使用了`slice()` Knockout 方法。您可能认为我们使用的是 JavaScript 的原生`Array.slice()`方法，但实际上我们使用的是 Knockout 版本，而且有一种简单的方法来识别它。

通常，当我们想要获取可观察属性内部的值时，我们会像调用函数一样调用属性。因此，当我们想要获取 ViewModel 的`pageSize`属性时，我们使用了`this.pageSize()`。

然而，当我们调用`slice()`方法时，我们没有像调用函数那样调用元素属性，因此实际数组在属性内部并未返回。`slice()`方法直接在可观察对象上调用。

Knockout 重新实现了一系列可以在数组上调用的原生方法，包括`push()`、`pop()`、`unshift()`、`shift()`、`reverse()`和`sort()`，我们在上一个任务中使用了它们。

建议使用这些方法的 Knockout 版本而不是原生 JavaScript 版本，因为它们在 Knockout 支持的所有浏览器中都受到支持，从而保持了依赖跟踪并保持了应用程序的 UI 同步。

# 添加上一页和下一页链接

此时，我们的页面现在只显示前 10 个项目。我们需要添加一个界面，允许用户导航到其他数据页面。在此任务中，我们可以添加**上一页**和**下一页**链接，以便以线性顺序查看页面。

## 启动推进器

我们将再次从添加此功能的 HTML 组件开始。在`<tfoot>`元素中的`<select>`元素之后直接添加以下新标记：

```js
<nav>
    <a href="#" title="Previous page" 
    data-bind="click: goToPrevPage">&laquo;</a>

    <a href="#" title="Next page" 
    data-bind="click: goToNextPage">&raquo;</a>
</nav>
```

接下来，我们可以向我们的 ViewModel 添加一些新方法。这些可以直接添加到我们之前在`sortable-table.js`中添加的`sort`方法后面：

```js
totalPages: function () {
    var totalPages = this.elements().length / this.pageSize() || 1;
        return Math.ceil(totalPages);
},
goToNextPage: function () {
    if (this.currentPage() < this.totalPages() - 1) {
        this.currentPage(this.currentPage() + 1);
    }
},
goToPrevPage: function () {
    if (this.currentPage() > 0) {
        this.currentPage(this.currentPage() - 1);
    }
}
```

最后，我们可以通过将以下代码添加到 `sortable-table.css` 来为此部分添加的新元素以及上一部分添加的元素添加一些 CSS 以进行整理：

```js
tfoot label, tfoot select, tfootnav {
    margin-right:4px; float: left; line-height:24px; 
}
tfoot select { margin-right:20px; }
tfootnav a { 
    display:inline-block; font-size:30px; line-height:20px; 
    text-decoration:none; color:#000; 
}
```

## 目标完成 - 小结

我们首先通过向页面添加包含两个 `<a>` 元素的 `<nav>` 元素来开始，这些元素制作了**上一页**和**下一页**链接。我们为链接添加了数据绑定，将**上一页**链接连接到 `goToPrevPage()` 方法，将**下一页**链接连接到 `goToNextPage()` 方法。

然后，我们添加了一个小的实用方法，以及这两个新方法到我们的 ViewModel。我们的方法不必像 `sort()` 方法那样接受参数，我们可以在方法中使用 `this` 访问我们的 ViewModel。

第一个方法 `totalPages()` 简单地通过将 `elements` 数组中的总项目数除以 `pageSize` 属性中保存的值来返回总页数。

有时 `currentPage` 属性将等于字符串 `all`，当在数学运算中使用时将返回 `NaN`，因此我们可以添加双竖线 OR (`||`) 来在这种情况下返回 `1`。我们还使用 `Math.ceil()` 来确保我们获得一个整数，因此当有 11.8 页的数据时（基于每页 10 个项目的默认值），该方法将返回 12。`Ceil()` 函数将总是向上舍入，因为我们不能有部分页面。

我们在上一个任务中添加的 `createPage` 计算的可观察对象实际上为我们做了大部分工作。接下来的两个方法只是更新了 `currentPage` 属性，这将自动触发 `createPage()` 计算的可观察对象。

在 `goToNextPage()` 方法中，我们首先检查我们是否已经在最后一页，只要我们不是，我们就将 `currentPage` 属性增加一。在我们检查是否在最后一页时，我们使用 `totalPages()` 方法。

`goToPrevPage()` 方法同样简单。这次我们检查我们是否已经在数据的第一页（如果 `currentPage` 等于 `0`），如果不是，我们将 `currentPage` 的值减去 `1`。

我们添加的少量 CSS 只是整理了 `<tfoot>` 元素中的元素，使它们能够与彼此并排浮动，并使新链接比默认情况下稍大一些。

# 添加数字页面链接

现在，我们可以添加任意数量的链接，以便允许用户直接访问任何页面。这些是直接链接到每个单独页面的数字页面链接。

## 启动推进器

首先，我们需要在我们的 ViewModel 中的现有可观察属性之后直接添加一个新的可观察属性，在 `sortable-table.js` 中：

```js
pages: ko.observableArray(),
```

在此之后，我们可以向我们的 ViewModel 中添加一个新方法。这可以添加在 `goToPrevPage()` 方法之后，位于 `vm` 对象字面量内部：

```js
changePage: function (obj, e) {
    var el = $(e.target),
        newPage = parseInt(el.text(), 10) - 1;

    vm.currentPage(newPage);
}
```

不要忘记在`goToPrevPage()`方法后面加上逗号！然后我们可以添加一个新的计算可观察属性，方式与我们之前添加的一样。这可以直接放在我们在上一个任务中添加的`createPage`计算可观察属性之后：

```js
vm.createPages = ko.computed(function () {

    var tmp = [];

    for (var x = 0; x < this.totalPages(); x++) {
        tmp.push({ num: x + 1 });
    }

    this.pages(tmp);

}, vm);
```

接下来，我们需要在 HTML 页面中添加一些新的标记。这应该在我们在上一个任务中添加的**Previous**和**Next**链接之间添加：

```js
<ul id="pages" data-bind="foreach: pages">
    <li>
        <a href="#" data-bind="text: num, 
        click: $parent.changePage"></a>
    </li>
</ul>
```

最后，我们可以添加一点 CSS 来定位`sortable-table.css`中的新元素：

```js
tfoot nav ul { margin:3px 0 0 10px; }
tfoot nav ul, tfootnav li { float:left; }
tfoot nav li { margin-right:10px; }
tfoot nav li a { font-size:20px; }
```

## 目标完成 - 小结。

首先，我们在 ViewModel 中添加了一个新的`pages`可观察数组。一开始我们没有给它一个数组；我们会在合适的时候动态添加。

我们添加的计算可观察属性`createPages`用于构建一个数组，其中数组中的每个项目表示数据的一个页面。我们可以像之前一样使用我们的`totalPages()`方法获取总页数。

一旦确定了这一点，也就是每当`pageSize()`可观察属性发生变化时，我们就可以填充刚刚添加的可观察数组。

添加到数组中的对象是使用简单的`for`循环创建的，以创建一个对象并将其推入数组中。一旦我们为每个页面构建了一个对象，我们就可以将数组设置为`pages`属性的值。

我们创建的每个对象都只有一个属性，称为`num`，其值是循环中使用的`x`计数器变量的当前值。

在 HTML 页面中，我们使用`foreach`数据绑定来迭代我们添加到`pages`数组中的数组。对于数组中的每个对象，我们创建一个`<li>`元素和一个`<a>`元素。`<a>`使用`data-bind`属性指定了两个绑定。

第一个是`text`绑定，它设置元素的文本。在这种情况下，我们将文本设置为每个对象具有的`num`属性的值。

第二个绑定是一个点击绑定，它调用一个名为`changePage`的方法。然而，在`foreach`绑定中，上下文被设置为`pages`数组中的当前对象，所以我们需要使用特殊的`$parent`上下文属性来访问 ViewModel 上的方法。

最后，我们添加了`changePage`方法，它被`<a>`元素使用。在这个简单的方法中，我们需要做的就是获取被点击元素的文本，从其值中减去`1`，因为实际的页码是从零开始的，并更新我们 ViewModel 的`curentPage`可观察属性。在这个方法中，由于某种原因，`this`的值并没有设置为被点击的元素，正如我们之前遇到的`sort()`方法所期望的那样。

因为触发`changePage`方法的`<a>`元素是在`foreach`绑定内创建的，所以传递给`changePage`的第一个参数将是`pages`数组中与`<a>`元素关联的对象。幸运的是，我们仍然可以使用变量`vm`访问 ViewModel。

我们添加的 CSS 简单地将列表项浮动在一起，稍微间隔开它们，并设置文本的颜色和大小。

## 机密情报

除了 `$parent` 上下文属性允许我们访问在 `foreach` 绑定中迭代的 ViewModel 属性的父对象之外，我们还可以利用 `$data`，它指向正在迭代的数组。

除此之外，还有一个 `$index` 属性，允许我们访问当前迭代的索引，我们可以在这个示例中使用它，而不是在每个对象上设置 `num` 属性。

# 管理类名

在这个任务中，我们可以向用户显示反馈，描述当前正在查看的页面。如果我们在数据的第一页或最后一页，我们也可以禁用 **Previous** 或 **Next** 链接。我们可以使用更多的脚本和一些简单的 CSS 来完成所有这些。

## 启动推进器

首先，我们需要在 `sortable-table.js` 中的现有方法后直接添加另一个方法到我们的 ViewModel 中：

```js
manageClasses: function () {
    var nav = $("#paging").find("nav"),
        currentpage = this.currentPage();

    nav.find("a.active")
       .removeClass("active")
       .end()
       .find("a.disabled")
       .removeClass("disabled"); 

    if (currentpage === 0) {
       nav.children(":first-child").addClass("disabled");
    } else if (currentpage === this.totalPages() - 1) {
        nav.children(":last-child").addClass("disabled");
    }

    $("#pages").find("a")
               .eq(currentpage)
               .addClass("active");
}
```

然后，我们需要从我们现有的代码中的几个位置调用这个方法。首先，我们需要在 `createPage()` 和 `createPages()` 计算观察函数的末尾调用它，通过在每个函数的最后一行（以 `this` 开头的行）添加以下代码：

```js
.manageClasses();
```

然后，为了在与表格交互之前添加初始类名，我们需要在 ViewModel 之后的 `applyBindings()` 方法之后调用它：

```js
vm.manageClasses();
```

最后，我们可以添加任务介绍中提到的额外 CSS：

```js
tfoot nav a.disabled, tfoot nav a.disabled:hover { 
    opacity: .25; cursor: default; color:#aaa;
}
tfoot nav li a.active, tfoot a:hover { color:#aaa; }
```

## 目标完成 - 小结

在这个任务中，我们首先向我们的 ViewModel 添加了一个新方法 - `manageClasses()` 方法。该方法负责向 **Previous** 和 **Next** 链接添加或移除 `disabled` 类，并向当前页对应的数字链接添加活动类。

在方法内部，我们首先缓存包含 `<nav>` 元素的选择器，以便我们能够尽可能高效地访问需要更新的元素。我们还获取 `curentPage` ViewModel 属性，因为我们将多次比较其值。

然后，我们找到具有 `disabled` 和 `active` 类的元素，并将它们移除。注意我们在移除 `active` 类后如何使用 jQuery 的 `end()` 方法返回到原始的 `<nav>` 选择。

现在我们只需要将类重新放回适当的元素上。如果 `currentPage` 是 `0`，我们使用 jQuery 的 `:first-child` 选择器与 `children()` 方法一起将 `disabled` 类添加到 `<nav>` 中的第一个链接。

或者，如果我们在最后一页，我们将 `disabled` 类添加到 `<nav>` 的最后一个子元素，这次使用 `:last-child` 选择器。

使用 jQuery 的 `eq()` 方法轻松地选择要应用 `active` 类的元素，该方法将元素的选择减少到作为指定索引的单个元素。我们使用 `currentpage` 作为要在选择中保留的元素的索引。

CSS 仅用于为具有不同样式的类名的元素添加样式，因此可以轻松地看到类何时添加和删除。

现在在浏览器中运行页面时，我们应该发现**上一页**链接一开始是禁用的，并且数字`1`是活动的。如果我们访问任何页面，该数字将获得 `active` 类。

# 重置页面

现在我们已经连接了我们的数字分页链接，一个问题变得明显起来。有时，在更改每页项目数时，将显示空表格。

我们可以通过向 `<select>` 元素添加另一个绑定来修复此问题，该绑定在 `<select>` 元素的 `value` 更改时重置当前页面。

## 启动推进器

首先，我们可以将新的绑定添加到 HTML 中。将 `<select>` 元素更改为以下内容：

```js
<select id="perPage" data-bind="value: pageSize, event: { 
 change: goToFirstPage
}">
```

现在我们可以将 `goToFirstPage()` 方法添加到 ViewModel 中：

```js
goToFirstPage: function () {
    this.currentPage(0);
}
```

## 目标完成 - 迷你总结

首先，我们将 `event` 绑定添加为 `<select>` 元素的第二个绑定，负责设置每页项的数量。此绑定的格式与我们在此项目中使用的其他绑定略有不同。

在绑定的名称之后，`event` 在本例中，我们在大括号内指定事件的名称和事件发生时要调用的处理程序。之所以使用此格式是因为如果需要，我们可以在括号内指定多个事件和处理程序。

然后，我们将新的事件处理程序 `goToFirstPage()` 添加为 ViewModel 的方法。在处理程序中，我们只需要将 `currentPage` 可观察值设置为 `0`，这将自动将我们移回到结果的第一页。每当 `<select>` 元素的值发生变化时，都会发生这种情况。

# 对表进行过滤

为了完成项目，我们可以添加过滤器，以便可以显示不同类型的元素。表的数据包含我们尚未使用的列——元素的 `state`（实际物理元素，而不是 HTML 元素！）

在此任务中，我们可以添加一个 `<select>` 元素，以允许我们根据其状态对元素进行过滤。

## 启动推进器

首先，我们需要向 ViewModel 添加一个新的可观察数组，该数组将用于存储表示元素可能的不同状态的对象：

```js
states: ko.observableArray(),
```

我们还可以向 ViewModel 添加一个简单的非可观察属性：

```js
originalElements: null,
```

接下来，我们需要填充新数组。我们可以在调用 `vm.manageClasses()` 之后直接执行此操作：

```js
var tmpArr = [],
      refObj = {};

tmpArr.push({ state: "Filter by..." });

$.each(vm.elements(), function(i, item) {

    var state = item.state;

    if (!refObj.hasOwnProperty(state)) {

        var tmpObj = {state: state};
        refObj[state] = state;
        tmpArr.push(tmpObj);
    }
});

vm.states(tmpArr);
```

然后，我们可以添加新的 HTML，该 HTML 将创建用于过滤 `<table>` 数据的 `<select>` 元素：

```js
<div class="filter clearfix">
    <label for="states">Filter by:</label>
    <select id="states" data-bind="foreach: states, event: { 
        change: filterStates
    }">
        <option data-bind="value: state, text: state">
        </option>
    </select>
</div>
```

现在我们需要向 ViewModel 添加一个最终方法，该方法在进行选择时实际过滤数据：

```js
filterStates: function (obj, e) {

    if (e.originalEvent.target.selectedIndex !== 0) {

        var vm = this,
            tmpArr = [],
            state = e.originalEvent.target.value;

        vm.originalElements = vm.elements();

        $.each(vm.elements(), function (i, item) {
            if (item.state === state) {
                tmpArr.push(item);
            }
        });

        vm.elements(tmpArr).currentPage(0);

        var label = $("<span/>", {
            "class": "filter-label",
            text: state
        });
        $("<a/>", {
            text: "x",
            href: "#",
            title: "Remove this filter"
        }).appendTo(label).on("click", function () {

            $(this).parent().remove();
            $("#states").show().prop("selectedIndex", 0);
            vm.elements(vm.originalElements).currentPage(0);

        });

        label.insertBefore("#states").next().hide();
    }
}
```

最后，我们可以向`sortable-table.css`添加一点 CSS，只是为了整理新元素：

```js
tfoot .filter { float:right; }
tfoot .filter label { 
    display:inline-block; height:0; line-height:0; 
    text-indent:-9999em; overflow:hidden; 
}
tfoot .filter select { margin-right:0; float:right; }
tfoot .filter span { 
    display:block; padding:0 7px; border:1px solid #abadb3;
    border-radius:3px; float:right; line-height:24px;
}
tfoot .filter span a { 
    display:inline-block; margin-left:4px; color:#ff0000;
    text-decoration:none; font-weight:bold;
}
```

## 完成目标 - 小结

首先，我们添加了一个名为`states`的新的可观察数组，该数组将用于包含构成我们数据的元素的不同状态。这些状态是固体、液体、气体或未知状态。

我们还向 ViewModel 添加了一个简单的属性，称为`originalElements`，它将用于存储完整的元素集合。该属性只是一个常规对象属性，因为我们不需要观察其值。

### 填充状态数组

接下来，我们将状态数组填充为数据中找到的所有唯一状态。我们只需要填充一次这个数组，所以它可以出现在 ViewModel 之外。我们首先创建一个空数组和一个空对象。

然后，我们向数组添加一个单个项目，该项目将用于`<select>`元素中的第一个`<option>`元素，并在与`<select>`框交互之前作为标签起作用。

然后，我们可以使用 jQuery 的`each()`方法迭代`elements`数组。对于数组中的每个项目（如果您记得的话，它将是表示单个元素的对象），我们获取其`state`并检查这是否存储在引用对象中。我们可以使用`hasOwnProperty()`JavaScript 函数来检查这一点。

如果状态在对象中不存在，我们将其添加。如果已经存在，则我们不需要做任何事情。如果对象不包含该状态，我们还将状态推入空数组。

一旦`each()`循环结束，我们应该有一个数组，其中包含数据中找到的每个`state`的单个实例，因此我们可以将此数组添加为`states`可观察数组的值。

### 构建`<select>`框

过滤功能的底层标记非常简单。我们添加了一个带有几个类名的容器`<div>`，一个`<label>`和一个`<select>`。`<label>`类名只是为了可访问性而添加的，我们不会显示它，因为`<select>`元素的第一个`<option>`将作为标签。

`<select>`元素有几个 Knockout 绑定。我们使用了`foreach`绑定，它连接到状态数组，因此一旦这个数组被填充，`<select>`的`<option>`元素就会自动添加。

我们还一次使用了`event`绑定，为`change`事件添加了一个处理程序，每当与`<select>`框交互时就会触发。

在`<select>`元素内部，我们为`<option>`元素添加了一个模板。每个选项将被赋予`states`数组中当前对象的`state`属性的`text`和`value`。

### 过滤数据

然后，我们添加了负责过滤`<table>`中显示的数据的 ViewModel 的方法。在方法中，我们首先检查第一个`<option>`是否未被选中，因为这只是一个标签，不对应任何状态。

我们可以通过查看`target`元素(`<select>`)的`selectedIndex`属性来确定这一点，该属性在`originalEvent`对象中可用。这本身是自动传递给我们的事件处理程序的事件对象的一部分。

因为我们将要更改`elements`可观察数组（以触发对过滤元素的分页），所以我们希望稍后存储原始元素。我们可以将它们存储在 ViewModel 的`originalElements`属性中。

接下来，我们需要构建一个新数组，其中仅包含具有在`<select>`元素中选择的`state`的元素。为此，我们可以创建一个空数组，然后迭代`elements`数组并检查每个元素的`state`。如果匹配，则将其推入新数组。

我们可以再次使用传递给我们的事件处理程序的事件对象来获取从`<select>`元素中选择的`state`。这次我们在`originalEvent`对象中使用`target`元素的`value`属性。

一旦新数组被填充，我们就更新`elements`数组，使其仅包含我们刚刚创建的新数组，然后将`currentPage`设置为`0`。

我们添加的过滤器是互斥的，因此一次只能应用一个过滤器。选择过滤器后，我们希望隐藏`<select>`框，以便无法选择另一个过滤器。

我们还可以创建一个标签，显示当前正在应用的过滤器。此标签由一个`<span>`元素制成，显示过滤器的文本，并且还包含一个`<a>`元素，可用于删除过滤器并将`<table>`返回到其最初显示所有元素的状态。

我们可以使用 jQuery 的`on()`方法在创建并附加到页面后立即附加`<a>`元素的处理程序。在处理程序中，我们只需将 ViewModel 的`elements`属性设置回保存在`originalEvents`属性中的数组，并将`<table>`重新设置为第一页，方法是将`currentPage`属性设置为`0`。

现在我们应该发现，我们可以在`<select>`框中选择其中一个选项，仅查看过滤后的数据和过滤标签，然后单击过滤标签中的红色叉号以返回初始的`<table>`。以下是数据的筛选选择和筛选标签的截图：

![数据过滤](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_10_03.jpg)

# 任务完成

我们的应用程序主要依赖 Knockout 功能运行，它允许我们轻松地将动态元素填充到内容中，添加事件处理程序，并通常管理应用程序的状态。我们也使用 jQuery，主要是在 DOM 选择容量方面，还偶尔使用它来使用实用程序，例如我们多次利用的`$.each()`方法。

完全可以纯粹使用 jQuery 构建此应用程序，而不使用 Knockout；但是，jQuery 本身从未被设计或打算成为构建复杂动态应用程序的完整解决方案。

当我们尝试仅使用 jQuery 构建复杂动态应用程序时，通常会发现我们的脚本很快变成一堆事件处理程序的混乱代码，既不容易阅读，也不易于维护或在将来更新。

使用 Knockout 来处理应用程序状态的维护，并使用 jQuery 来实现它的预期角色，为我们提供了使用非常少的代码构建高度动态、数据驱动的复杂应用程序的理想工具集。

在整个示例中，我尽量使各个方法尽可能简单，并且让它们只做一件事情。以这种方式将功能单元保持隔离有助于保持代码的可维护性，因为很容易看到每个现有函数的功能，也很容易添加新功能而不会破坏已有的内容。

# 你准备好全力以赴了吗？挑战热门的高手？

Knockout 可以轻松地从数据数组中构建一个`<table>`，由于数据是动态的，因此很容易编辑它或向其添加新项目，并使应用程序中的数据得以更新。尽管在此示例中数据是存储在本地文件中的，但将数据存储在服务器上并在页面加载时使用简单的 AJAX 函数填充我们的元素数组是很简单的。

如果你想进一步学习这个示例，这将是首要任务。完成这个任务后，为什么不试试使表格单元格可编辑，以便可以更改它们的值，或添加一个允许你插入新行到`<table>`的功能。完成这些后，你会想把新数据发送回服务器，以便永久存储。
