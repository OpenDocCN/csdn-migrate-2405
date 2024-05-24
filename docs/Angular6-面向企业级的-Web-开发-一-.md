# Angular6 面向企业级的 Web 开发（一）

> 原文：[`zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992`](https://zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎！如果你想学习并精通 Angular 开发，你来对地方了。这本书旨在向你灌输敏捷和 DevOps 的思维，让你能够自信地创建可靠和灵活的解决方案。无论你是自由职业者为小型企业开发软件，全栈开发人员，企业开发人员还是网页开发人员，你需要了解如何设计、架构、开发、维护、交付和部署 Web 应用程序，以及需要应用的最佳实践和模式并没有太大的差异。如果你要向用户群交付应用程序，从某种意义上说，你是一个全栈开发人员，因为你必须了解许多服务器技术。事实上，如果你掌握了如何使用 TypeScript 交付 Angular 应用程序，那么使用 Node.js、Express.js 和 TypeScript 编写自己的 RESTful API 对你来说并不困难，但这超出了本书的范围。

根据某些定义，全栈开发人员需要了解从满足国际版权法到成功在当今的网络上创建和运营应用程序的一切。从某种意义上说，如果你是一名企业家，这是正确的。然而，在这本书中，你的烹饪技能和法律学位并不适用。这本书假设你已经知道如何使用你选择的技术栈编写 RESTful API，如果不知道，不要担心！你仍然可以受益并了解如何使用 RESTful API 工作。

# 本书适合对象

这本书既适合初学者又适合有经验的开发人员，他们想学习 Angular 或者网页开发。如果你是 Angular 开发人员，你将接触到设计和部署 Angular 应用程序到生产环境的整个过程。你将学习易于理解并能够教给他人的 Angular 模式。如果你是自由职业者，你将掌握交付 Angular 应用程序的有效工具和技术，以安全、自信和可靠的方式。如果你是企业开发人员，你将学习编写具有可扩展架构的 Angular 应用程序的模式和实践。

# 充分利用本书

1.  你应该已经熟悉全栈 Web 开发

1.  按照出版顺序跟随本书，在每一章的内容旁边编写你的解决方案。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹。

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包托管在 GitHub 上，网址为**[`github.com/PacktPublishing/Angular-6-for-Enterprise-Ready-Web-Applications`](https://github.com/PacktPublishing/Angular-6-for-Enterprise-Ready-Web-Applications)**。

该书的代码包也托管在作者的 GitHub 存储库中，网址为[`github.com/duluca/local-weather-app`](https://github.com/duluca/local-weather-app)和[`github.com/duluca/lemon-mart`](https://github.com/duluca/lemon-mart)。

我们还提供来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```ts
{
  "name": "local-weather-app",
  "version": "0.0.0",
  "license": "MIT",
  **...**
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```ts
 "scripts": {
    "ng": "ng",
    "start": "ng serve",
 **"build": "ng build",**
 **"test": "ng test",**
    "lint": "ng lint",
    "e2e": "ng e2e"
  },
```

任何跨平台或 macOS 特定的命令行输入或输出如下所示：

```ts
$ brew tap caskroom/cask
```

Windows 特定的命令行输入或输出如下所示：

```ts
PS> Set-ExecutionPolicy AllSigned; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

**粗体**：表示新术语、重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“启动开始菜单。”

警告或重要说明会出现在这样的样式中。提示和技巧会出现在这样的样式中。


# 第一章：搭建开发环境

让我们从质疑整本书的前提开始，即 Angular 本身。为什么学习 Angular，而不是 React、Vue 或其他框架？首先，我不会反对学习任何新工具的论点。我相信每个工具都有其存在的场所和目的。熟练掌握 React 或 Vue 只会进一步加深您对 Angular 的理解。自 2012 年以来，像 Backbone 或 Angular 这样的**单页面应用**（**SPA**）框架就吸引了我的全部注意力，当时我意识到服务器端渲染的模板是不可能维护的，并且会导致软件系统的非常昂贵的重写。如果您打算创建可维护的软件，必须遵守的首要指令是将 API 和业务逻辑与**用户界面**（**UI**）解耦。

问题是，为什么要精通 Angular？我发现 Angular 完美地符合帕累托原则。它已经成为一个成熟且不断发展的平台，使您能够用 20%的努力完成 80%的任务。此外，从版本 4 开始，在**长期支持**（**LTS**）直到 2018 年 10 月，每个主要版本都受到 18 个月的支持，创造了一个持续学习、保持最新和淘汰旧功能的过程。从全栈开发人员的角度来看，这种连续性是非常宝贵的，因为您的技能和培训将在未来多年内保持有用和新鲜。

这第一章将帮助您和您的团队成员创建一致的开发环境。对于初学者来说，创建正确的开发环境可能很困难，这对于无挫折的开发体验至关重要。对于经验丰富的开发人员和团队来说，实现一致和最小的开发环境仍然是一个挑战。一旦实现，这样的开发环境有助于避免许多与 IT 相关的问题，包括持续维护、许可和升级成本。

安装 GitHub 桌面版、Node.js、Angular CLI 和 Docker 的说明将成为从初学者到经验丰富的团队的良好参考，以及自动化和确保开发环境的正确和一致配置的策略。

如果您已经设置了强大的开发环境，可以跳过本章；但是，请注意，本章中声明的一些环境假设可能会导致后续章节中的一些指令对您不起作用。如果遇到问题或需要帮助同事、学生或朋友设置他们的开发环境，请返回本章作为参考。

在本章中，您将学到以下内容：

+   使用 CLI 包管理器安装和更新软件：

+   Windows 10 上的 Chocolatey

+   macOS X 上的 Homebrew

+   使用脚本来自动化安装：

+   Windows 10 上的 Powershell

+   macOS X 上的 Bash

+   实现一致且跨平台的开发环境

您应该熟悉这些内容：

+   JavaScript ES2015+

+   前端开发基础知识

+   RESTful API

支持的操作系统如下：

+   Windows 10 Pro v1703+与 PowerShell v5.1+

+   macOS Sierra v10.12.6+与终端（Bash 或 Oh My Zsh）

+   大多数建议的软件也适用于 Linux 系统，但您的体验可能会有所不同。

建议的跨平台软件如下：

+   Node 8.10+（除非非 LTS 版本）

+   npm 5.7.1+

+   GitHub Desktop 1.0.0+

+   Visual Studio Code v1.16.0+

+   Google Chrome 64+

# CLI 包管理器

通过**图形用户界面**（**GUI**）安装软件是缓慢且难以自动化的。作为全栈开发人员，无论您是 Windows 用户还是 Mac 用户，您都必须依赖**命令行界面**（**CLI**）包管理器来高效地安装和配置您将依赖的软件。请记住，任何可以表示为 CLI 命令的东西也可以被自动化。

# 为 Windows 安装 Chocolatey

Chocolatey 是 Windows 的基于 CLI 的包管理器，可用于自动化软件安装。要在 Windows 上安装 Chocolatey，您需要运行一个提升的命令行：

1.  启动开始菜单

1.  开始在`PowerShell`中输入

1.  您应该看到 Windows PowerShell 桌面应用程序作为搜索结果

1.  右键单击 Windows PowerShell 并选择以管理员身份运行

1.  这将触发用户账户控制（UAC）警告；选择“是”继续

1.  在 PowerShell 中执行以下命令来安装 Chocolatey 包管理器：

```ts
PS> Set-ExecutionPolicy AllSigned; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

1.  通过执行`choco`来验证您的 Chocolatey 安装

1.  您应该看到类似的输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/4ce21c0f-3f85-4441-bf36-adfef32776ab.png)成功安装 Chocolatey 所有后续的 Chocolatey 命令也必须从提升的命令行中执行。或者，也可以在不需要提升的命令行中安装 Chocolatey。但是，这将导致非标准和不太安全的开发环境，并且通过该工具安装的某些应用程序可能仍然需要提升。

有关更多信息，请参阅：[`chocolatey.org/install`](https://chocolatey.org/install)。

# 为 macOS 安装 Homebrew

Homebrew 是 macOS 的基于命令行的软件包管理器，可用于自动化软件安装。要在 macOS 上安装 Homebrew，您需要运行一个命令行。

1.  使用⌘ + Space 启动 Spotlight 搜索

1.  在“终端”中输入

1.  在终端中执行以下命令以安装 Homebrew 软件包管理器：

```ts
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  通过执行`brew`来验证您的 Homebrew 安装

1.  您应该看到类似的输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/3e8bd1f9-2ac6-4f22-9df8-4407185798e9.png)成功安装 Homebrew

1.  要启用对其他软件的访问，请执行以下命令：

```ts
$ brew tap caskroom/cask
```

有关更多信息，请访问：[`brew.sh/`](https://brew.sh/)。

# Git 和 GitHub 桌面

本节旨在建立一个最佳实践的 Git 配置，适用于尽可能广泛的受众。为了充分利用本节和本书后续章节，假定读者已满足以下先决条件：

+   对源代码管理和 Git 的理解

+   在[GitHub.com](https://github.com/)上创建一个免费帐户

# 为什么使用 GitHub？

如果您是 Git 用户，很可能您也使用在线存储库，如 GitHub、Bitbucket 或 GitLab。每个存储库都有一个免费的开源项目层，配有功能各异的强大网站，包括您可以付费使用的本地企业选项。GitHub 在 2016 年托管了 3800 多万个存储库，是目前最受欢迎的在线存储库。GitHub 被广泛认为是一个基本的实用工具，永远不会被社区下线。

随着时间的推移，GitHub 添加了许多丰富的功能，使其从一个简单的存储库变成了一个在线平台。在本书中，我将引用 GitHub 的功能和功能，以便您可以利用其能力来改变您开发、维护和发布软件的方式。

# 为什么使用 GitHub 桌面？

Git CLI 工具确实很强大，如果你坚持使用它，你会没问题的。然而，作为全栈开发人员，我们担心各种问题。在你匆忙完成手头的任务时，你很容易因为遵循错误或不完整的建议而毁掉你自己，有时甚至毁掉你的团队的一天。

请参见来自 StackOverflow 的以下建议的截图([`stackoverflow.com/questions/1125968/force-git-to-overwrite-local-files-on-pull`](http://stackoverflow.com/questions/1125968/force-git-to-overwrite-local-files-on-pull))：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ecd0f401-456e-472a-9729-fe20f4479c30.png)

如果你执行上述命令，请准备好失去未提交的本地更改。不幸的是，新手用户倾向于遵循最简单和最直接的指令，可能导致丢失工作。如果你认为你过去的提交是安全的，再想想！当涉及到 Git 时，如果你能想象到，通过 CLI 都可以做到。

幸运的是，通过 GitHub，你可以保护分支并实施 GitHub 工作流程，其中包括分支、提交、合并、更新和提交拉取请求。这些保护和工作流程有助于防止有害的 Git 命令造成不可逆转的更改，并实现一定程度的质量控制，使你的团队保持高效。通过 CLI 执行所有这些操作，特别是在存在合并冲突时，可能会变得复杂和繁琐。

要更深入地了解 Git 和 GitHub 的优势和缺陷，你可以阅读我 2016 年关于这个主题的文章：[Bit.ly/InDepthGitHub](http://bit.ly/InDepthGitHub)。

# 安装 Git 和 GitHub 桌面

GitHub 桌面提供了一个易于使用的 GUI 来执行 GitHub 工作流程，这种方式在 Windows 和 macOS 上是一致的。当新人或初级团队成员加入时，或者如果你不经常贡献代码，一致性是非常有价值的。

1.  执行安装命令：

对于 Windows：

```ts
**PS> choco install git github-desktop -y** 
```

对于 macOS：

```ts
$ brew install git && brew cask install github-desktop
```

1.  通过执行 `git --version` 来验证你的 Git 安装，并观察返回的版本号

在安装新的 CLI 工具后，你需要重新启动你的终端。然而，你可以通过刷新或源化你的环境变量来避免重新启动终端并节省一些时间。在 Windows 上，执行 `refreshenv`；在 macOS 上，执行 `source ~/.bashrc` 或 `source ~/.zshrc`。

1.  通过启动应用程序来验证你的 GitHub 桌面安装

1.  在 GitHub 桌面上登录[`github.com/`](https://github.com/)

1.  创建了存储库后，您可以通过在终端中执行以下命令来启动应用程序：

```ts
$ github path/to/repo
```

1.  如果您已经在正确的文件夹中，可以输入以下命令：

```ts
$ github .
```

对于 Windows，在 GitHub Desktop 启动时，如果卡在登录屏幕上，请关闭应用程序，以管理员身份重新启动，完成设置，然后您将能够正常使用它，而无需再次以管理员身份启动。有关更多信息，请参阅：[`desktop.github.com/`](https://desktop.github.com/)。

# Node.js

本节旨在建立最佳实践的 JavaScript 开发环境。为了充分利用本书，假定您已满足以下先决条件：

+   对现代 JavaScript 生态系统和工具的认识

+   NodeJS 的网站：[`nodejs.org`](https://nodejs.org)

+   Npm 的网站：[`www.npmjs.com`](https://www.npmjs.com)

+   Angular 的网站：[`angular.io`](https://angular.io)

+   Legacy AngularJS 的网站：[`angularjs.org/`](https://angularjs.org/)

+   Yarn 的网站：[`yarnpkg.com`](https://yarnpkg.com)

+   React 的网站：[`facebook.github.io/react`](https://facebook.github.io/react)

Node.js 是可以在任何地方运行的 JavaScript。它是一个开源项目，旨在在服务器上运行 JavaScript，构建在谷歌 Chrome 的 V8 JavaScript 引擎上。2015 年底，Node.js 稳定下来，并宣布了企业友好的 18 个月 LTS 周期，为平台带来了可预测性和稳定性，配合更频繁更新但更实验性的 Latest 分支。Node 还附带了 npm，Node 包管理器，截至 2018 年，npm 是世界上最大的 JavaScript 包存储库。

要更详细地了解 Node 的历史，请阅读我在 Node 上的两部分文章：[Bit.ly/NodeJSHistory](http://bit.ly/NodeJSHistory)。

您可能听说过 yarn 以及它比 npm 更快或更好。截至 npm 5，它与 Node 8 捆绑在一起，npm 更加功能丰富，更易于使用，并且在性能方面与 yarn 不相上下。Yarn 由 Facebook 发布，该公司还创建了 React JavaScript UI 库。必须指出的是 yarn 依赖于 npm 存储库，因此无论您使用哪种工具，都可以访问相同的包库。

# 现有的 Node.js 安装

如果您之前安装过 Node.js，在使用 choco 或 brew 安装新版本 Node 时，请确保仔细阅读命令输出。您的软件包管理器可能会返回警告或额外的指令，因此您可以成功完成安装。

您的系统或文件夹权限很可能在过去被手动编辑过，这可能会影响 Node 的无障碍操作。如果以下命令无法解决您的问题，请作为最后的手段使用 Node 网站上的 GUI 安装程序。

无论如何，您必须小心卸载之前使用`npm -g`安装的所有全局工具。随着每个主要的 Node 版本，您的工具与 Node 之间的本地绑定可能会失效。此外，全局工具很快就会过时，项目特定的工具也很快就会不同步。因此，全局安装工具现在是一种反模式，已被更好的技术所取代，这些技术在下一节和第二章的 Angular CLI 部分中有介绍，*创建一个本地天气 Web 应用*。

要查看全局安装的软件包列表，请执行`npm list -g --depth 0`。要卸载全局软件包，请执行`npm uninstall -g package-name`。我建议您卸载所有全局安装的软件包，并根据下一节提供的建议重新开始。

# 安装 Node.js

本书假定您正在使用 Node 8.4 或更高版本。Node 的奇数版本不适合长期使用。6.x.x、8.x.x、10.x.x 等是可以的，但是要尽量避免 7.x.x、9.x.x 等。

1.  执行安装命令：

对于 Windows：

```ts
PS> choco install nodejs-lts -y
```

对于 macOS：

```ts
$ brew install node@8
```

1.  验证 Node 的安装是否成功，执行`node -v`

1.  验证 npm 的安装是否成功，执行`npm -v`

请注意，不要在 Windows 上使用`npm install -g npm`来升级 npm 版本，如第四章中所述，*与 Angular 更新保持最新*。强烈建议您使用`npm-windows-upgrade` npm 包。

npm 存储库包含许多有用且成熟的 CLI 命令，通常是跨平台的。以下是我经常依赖并选择全局安装以提高性能的命令：

+   `npx`：通过按需下载最新版本或项目特定的本地`node_modules`文件夹来执行 CLI 工具。它随 npm 5 一起提供，并允许您运行频繁更新的代码生成器，而无需全局安装。

+   `rimraf`：Unix 命令`rm -rf`，但在 Windows 上也可以使用。在删除`node_modules`文件夹时非常有用，特别是当 Windows 由于嵌套文件夹结构而无法执行此操作时。

+   `npm-update`：分析您的项目文件夹，并报告哪些包有更新版本，哪些没有，如果您愿意，可以更新所有这些包。

+   `n`：非常容易快速切换 Node 版本的工具，无需记住特定版本号。不幸的是，它只在 macOS/Linux 上运行。

+   `http-server`：简单的、零配置的命令行 HTTP 服务器，是本地测试静态 HTML/CSS 页面或 Angular 或 React 项目的`dist`文件夹的绝佳方式。

+   `npm-windows-upgrade`：在 Windows 上升级 npm 所必需的。

# Visual Studio Code

**Visual Studio Code**（**VS Code**）是最好的代码编辑器/集成开发环境之一。它是免费的，而且跨平台。值得注意的是，VS Code 具有代码编辑器的极快性能，类似于 NotePad++或 Sublime Text，但具有昂贵的集成开发环境的功能集和便利性，例如 Visual Studio 或 WebStorm。对于 JavaScript 开发，这种速度是必不可少的，并且对于经常在不同项目之间频繁切换的开发人员来说，这是一项巨大的生活质量改善。VS Code 集成了终端、易于使用的扩展系统、透明的设置、出色的搜索和替换功能，以及在我看来存在的最好的 Node.js 调试器。

# 安装 Visual Studio Code

对于 Angular 开发，这本书将利用 VS Code。强烈建议您也使用 VS Code。

1.  执行安装命令：

对于 Windows：

```ts
PS> choco install VisualStudioCode -y
```

对于 macOS：

```ts
$ brew cask install visual-studio-code
```

Visual Studio Code 的最佳功能之一是您还可以从 CLI 启动它。如果您想要编辑的文件夹中，只需执行`code .`或通过执行`code ~/.bashrc`或`code readme.md`来执行特定文件。

1.  通过启动 Visual Studio Code 来验证安装

1.  转到一个文件夹并执行`code .`

1.  这将打开一个新的 VS Code 窗口，其中资源管理器显示当前文件夹的内容

有关更多信息，请参阅[`code.visualstudio.com`](https://code.visualstudio.com)。

# Windows 和 macOS 的自动化

在本章的开头，我宣称*任何可以表示为 CLI 命令的东西也可以被自动化*。在设置过程中，我们确保每个使用的工具都已设置并且通过 CLI 命令可验证其功能。这意味着我们可以轻松地创建一个 PowerShell 或 bash 脚本来串联这些命令，并简化设置和验证新环境的任务。事实上，我已经创建了这些脚本的一个基本实现，您可以从本书的 GitHub 存储库的`第一章`文件夹中下载：

1.  导航至[`github.com/duluca/web-dev-environment-setup`](https://github.com/duluca/web-dev-environment-setup)查找脚本

1.  在 PowerShell 中执行`install-windows-deps.ps1`以安装和验证 Windows 上的依赖关系

1.  在终端中执行`install-mac-deps.sh`以安装和验证 macOS 上的依赖关系

残酷的现实是，这些脚本并不代表一个非常有能力或弹性的解决方案。脚本无法远程执行或管理，并且它们无法轻松地从错误中恢复或在机器启动周期中生存。此外，您的 IT 需求可能超出了这里所涵盖的范围。

如果您处理大型团队和频繁的人员流动，自动化工具将大大地产生回报，而如果您是独自一人或是一个较小、稳定的团队的一部分，它将是极度过剩的。我鼓励您探索诸如 Puppet、Chef、Ansible 和 Vagrant 等工具，以帮助您决定哪一个最适合您的需求，或者一个简单的脚本是否足够好。

# 总结

在这一章中，您掌握了基于 CLI 的软件包管理器在 Windows 和 macOS 上的使用，以加快和自动化开发环境的设置，为您和您的同事。通过减少开发人员环境之间的差异，您的团队可以更容易地克服任何个人配置问题，并更多地专注于手头的任务执行。通过对共同环境的集体理解，团队中没有一个人需要承担帮助排除其他人问题的负担。因此，您的团队将更加高效。通过利用更复杂和弹性的工具，中大型组织将能够在其 IT 预算中实现巨大的节省。

在下一章中，您将熟悉新的 Angular 平台，优化您的 Web 开发环境，利用 Waffle 和 GitHub 问题来使用看板，学习 Angular 基础知识以构建一个考虑全栈架构的简单 Web 应用，并介绍使用 RxJS 进行响应式编程。

# 进一步阅读

Vishwas Parameshwarappa 的《自动化本地开发者机器设置》一文是使用 Vagrant 的绝佳起点。您可以在[Red-gate.com/simple-talk/sysadmin/general/automating-setup-local-developer-machine](https://www.red-gate.com/simple-talk/sysadmin/general/automating-setup-local-developer-machine)找到这篇文章。


# 第二章：创建本地天气 Web 应用程序

在本章中，我们将使用迭代开发方法设计和构建一个简单的本地天气应用程序，使用 Angular 和第三方 Web API。您将专注于首先提供价值，同时学习使用 Angular、TypeScript、Visual Studio Code、响应式编程和 RxJS 的微妙之处和最佳方式。在我们开始编码之前，我们将介绍 Angular 背后的哲学，并确保您的开发环境经过优化，可以实现协作和轻松的信息辐射。

本章的每个部分都将向您介绍新概念、最佳实践和利用这些技术的最佳方式，并涵盖关闭您可能对 Web 和现代 JavaScript 开发基础知识的任何知识空白的基础知识。

在本章中，您将学习 Angular 的基础知识，以构建一个简单的 Web 应用程序，并熟悉新的 Angular 平台和全栈架构。

在本章中，您将学到以下内容：

+   介绍 Angular 及其背后的哲学

+   为全栈开发配置具有最佳文件夹结构的存储库

+   使用 Angular CLI 生成您的 Angular Web 应用程序

+   优化 Visual Code 以进行 Angular 和 TypeScript 开发

+   使用 Waffle 作为与 GitHub 连接的看板板来规划您的路线图

+   打造一个新的 UI 元素来显示当前天气信息，使用组件和接口

+   使用 Angular 服务和 HttpClient 从 OpenWeatherMap API 检索数据

+   利用可观察流使用 RxJS 转换数据

本书提供的代码示例需要使用 Angular 5 和 6 版本。Angular 5 的代码与 Angular 6 兼容。Angular 6 将在 LTS 中得到支持，直到 2019 年 10 月。代码存储库的最新版本可以在以下位置找到：

+   对于第 2 到 6 章，LocalCast Weather，请访问：[Github.com/duluca/local-weather-app](https://github.com/duluca/local-weather-app)

+   对于第 7 到 12 章，LemonMart，请访问：[Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)

# 介绍 Angular

Angular 是由谷歌和一群开发者社区维护的开源项目。新的 Angular 平台与您过去可能使用过的遗留框架大不相同。与微软的合作使得 TypeScript 成为默认的开发语言，它是 JavaScript 的超集，使开发者能够针对旧版浏览器（如 Internet Explorer 11）编写现代 JavaScript 代码，同时在 Chrome、Firefox 和 Edge 等最新浏览器中得到支持。Angular 的遗留版本，即 1.x.x 范围内的版本，现在被称为 AngularJS。2.0.0 及更高版本简称为 Angular。AngularJS 是一个单页应用程序（SPA）框架，而 Angular 是一个能够针对浏览器、混合移动框架、桌面应用程序和服务器端渲染视图的平台。

在 AngularJS 中，每个次要版本增量都意味着风险更新，伴随着昂贵的废弃和不确定间隔的主要新功能。这导致了一个不可预测的、不断发展的框架，似乎没有指导手来推动代码库向前发展。如果你使用过 AngularJS，你可能会卡在一个特定的版本上，因为你的代码库的特定架构使得很难迁移到新版本。在 2018 年春/夏季，AngularJS 的最后一个主要更新将发布版本 1.7。这个发布将标志着这个遗留框架的终结，计划在 2021 年 7 月终止支持。

Angular 在各个方面都比 AngularJS 有所改进。该平台遵循语义版本控制，如[`semver.org/`](https://semver.org/)所定义，其中次要版本增量表示新功能添加和可能废弃通知的第二个下一个主要版本，但不会有破坏性的变化。此外，谷歌的 Angular 团队已经承诺了一个确定的发布计划，每 6 个月发布一次主要版本增量。从 Angular 4 开始，在这 6 个月的开发窗口之后，所有主要版本都将获得长期支持（LTS），为期 12 个月的错误修复和安全补丁。从发布到终止支持，每个主要版本都将获得 18 个月的支持。请参考以下图表，了解 AngularJS 和 Angular 的暂定发布和支持计划：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/bbf1891b-b82c-4980-81fb-98864e5e4312.png)暂定的 Angular 发布和支持计划

那么，这对你意味着什么呢？你可以放心，你在 Angular 中编写的代码将在大约 24 个月的时间范围内得到支持，并且向后兼容，即使你对其不做任何更改。因此，如果你在 2017 年 4 月编写了一个 Angular 4 版本的应用程序，你的代码现在可以在 Angular 5 中运行，而 Angular 5 本身将在 2019 年 4 月之前得到支持。要将你的 Angular 4 代码升级到 Angular 6，你需要确保你没有使用在 Angular 5 中宣布为废弃的任何 API。实际上，这些废弃的内容很少，除非你正在使用低级别的 API 来实现高度专业化的用户体验，否则更新代码库所需的时间和精力应该是最小的。然而，这是谷歌所做出的承诺，而不是一份合同。Angular 团队有很大的动力来确保向后兼容，因为谷歌在整个组织中运行着 600 多个 Angular 应用程序，每次只有一个版本的 Angular 处于活动状态。这意味着，当你阅读这篇文章时，所有这 600 多个应用程序都将在 Angular 6 中运行。你可能认为谷歌有无限的资源来实现这一点，但像任何其他组织一样，他们也有有限的资源，并非每个应用程序都有专门的团队进行积极维护。这意味着 Angular 团队必须通过自动化测试来确保兼容性，并尽可能地减少未来的主要版本更新所需的工作量。在 Angular 6 中，通过引入 `ng update`，更新过程变得更加简单。未来，团队将发布自动化的 CLI 工具，以使废弃功能的升级成为一个合理的努力。

这对开发人员和组织来说都是个好消息。现在，你不必永远停留在 Angular 的旧版本上，而是可以计划并分配必要的资源，将你的应用程序移向未来，而无需进行昂贵的重写。正如我在 2017 年的一篇博客文章中所写的那样，《Angular 4 的最佳新功能》，链接在 [bit.ly/NgBestFeature](http://bit.ly/NgBestFeature)，信息很明确：

**对于开发人员和经理：**Angular 会一直存在，所以你应该投入时间、注意力和金钱来学习它-即使你目前热爱其他框架。**对于决策者（CIO，CTO 等）：**计划在接下来的 6 个月内开始过渡到 Angular。这将是一个可以向商业人士解释的投资，并且您的投资将在最初的 LTS 窗口到期后的多年内产生回报，具有优雅的升级路径到 Angular vNext 及更高版本。

那么，为什么谷歌（Angular）和微软（TypeScript，Visual Studio Code）免费提供这样的技术？有多种原因，其中一些包括展示技术证明以留住和吸引人才，通过与数百万开发人员一起验证和调试新的想法和工具，并最终使开发人员更容易地创建出色的网络体验，从而为谷歌和微软带来更多业务。我个人认为这里没有任何恶意意图，并且欢迎开放、成熟和高质量的工具，我可以随意摆弄并根据自己的意愿进行调整，如果必要的话，而不必为专有技术的支持合同付费。

注意，在网上寻找 Angular 帮助可能会有些棘手。您会注意到大多数时候，Angular 被称为 Angular 2 或 Angular 4。有时，Angular 和 AngularJS 都简称为 AngularJS。当然，这是不正确的。Angular 的文档在[angular.io](https://angular.io)。如果您登陆[angularjs.org](https://angularjs.org/)，您将看到有关传统 AngularJS 框架的信息。有关即将发布的 Angular 版本的最新更新，请查看官方发布计划：[Github.com/angular/angular/blob/master/docs/RELEASE_SCHEDULE.md](https://github.com/angular/angular/blob/master/docs/RELEASE_SCHEDULE.md)。

# Angular 的哲学

Angular 的哲学是在配置和约定之间犯错误。基于约定的框架，虽然从外部看起来可能很优雅，但对新手来说很难掌握框架。然而，基于配置的框架旨在通过显式配置元素和钩子公开其内部工作原理，您可以将自定义行为附加到框架上。实质上，Angular 试图不那么神奇，而 AngularJS 则有很多魔力。

这导致了大量冗长的编码。这是件好事。简洁的代码是可维护性的敌人，只有原始作者受益。然而，正如 Andy Hunt 和 David Thomas 在《实用程序员》中所说的，

请记住，你（以及之后的人）将会读取代码很多次，但只会写入几次。

冗长、解耦、内聚和封装的代码是未来保护你的代码的关键。Angular 通过其各种机制，实现了这些概念的正确执行。它摒弃了在 AngularJS 中发明的许多自定义约定，比如`ng-click`，并引入了一个更直观的语言，建立在现有的 HTML 元素和属性之上。因此，`ng-click`变成了`(click)`，扩展了 HTML 而不是替换它。

# Angular 6 有什么新功能？

本书中的大部分内容、模式和实践都与 Angular 4 及以上版本兼容。Angular 6 是最新版本的 Angular，为平台带来了许多底层改进，提高了整体稳定性和生态系统的内聚性。通过额外的 CLI 工具，开发体验得到了极大的改善，这些工具使得更新软件包版本和加快构建时间更加容易，从而改善了代码-构建-视图的反馈循环。有了 Angular 6，所有平台工具都与 6.0 版本同步，这样更容易理清生态系统。在下表中，你可以看到这样做如何使得工具兼容性更容易沟通：

|  | **之前** | **v6 时** |
| --- | --- | --- |
| **CLI** | 1.7 | 6.0 |
| **Angular** | 5.2.10 | 6.0 |
| **Material** | 5.2.4 | 6.0 |

Angular CLI 6.0 带来了重大的新功能，比如`ng update`和`ng add`命令；`ng update`使得更新 Angular 版本、npm 依赖、RxJS 和 Angular Material 变得更加容易，包括一些确定性的代码重写能力，以应用对 API 或函数的名称更改。关于更新 Angular 版本的主题在第四章中有详细介绍，*与 Angular 更新保持最新*。`ng add`为 Angular CLI 带来了原理图支持。通过原理图，您可以编写自定义代码，为 Angular 应用添加新的功能，添加任何依赖项、样板配置代码或脚手架。一个很好的例子是通过执行`ng add @angular/material`来将 Angular Material 添加到您的项目中。关于将 Angular Material 添加到您的项目中的主题在第五章中有详细介绍，*使用 Angular Material 增强 Angular 应用*。一个独立的 Material 更新工具旨在使 Angular Material 的更新变得不那么痛苦，可以在[Github.com/angular/material-update-tool](https://github.com/angular/material-update-tool)找到，但预计这个功能将合并到`ng update`中。进一步的原理图可以为 CLI 带来自己的`generate`命令，使您的生活更加轻松，代码库随着时间的推移更加一致。此外，Webpack 的第 4 版被配置为将您的 Angular 应用构建为更小的模块，并具有范围托管，缩短了应用的首次绘制时间。

Angular 6 的主要主题是在幕后进行性能改进和自定义元素支持。版本 6 在基本捆绑包大小方面比 v5 提高了 12%，达到 65 KB，这将从快速 3G 到光纤连接的加载时间提高了 21-40%。随着您的应用程序增长，Angular 利用更好的摇树技术来进一步修剪最终可交付的未使用代码。速度是 Angular 6 的 UX 功能。这是通过更好地支持 Angular **Component Development Kit** (**CDK**), Angular Material, Animations, and i18n 来实现的。Angular Universal 允许服务器端辅助快速启动时间，并且 Angular **Progressive Web App** (**PWA**)支持利用本机平台功能，如缓存和离线，因此在随后的访问中，您的应用程序保持快速。RxJS 6 支持可摇树的`pipe`命令，更频繁地减少捆绑包大小，并修复了`throttle`的行为，我在第六章中警告您，*Reactive Forms and Component Interaction,*以及众多的错误修复和性能改进。TypeScript 2.7 带来了更好的支持，可以导入不同类型的 JavaScript 包，并在构建时捕获编码错误的更高级功能。

自定义元素支持是 Web 组件规范的一部分，非常重要。使用 Angular Elements，您可以编写一个 Angular 组件，并在*任何*其他使用*任何*Web 技术的 Web 应用程序中重用该组件，从本质上来说，声明您自己的自定义 HTML 元素。这些自定义元素将与任何基于 HTML 的工具链兼容，包括其他 Web 应用程序库或框架。为了使其工作，整个 Angular 框架需要与您的新自定义元素一起打包。这在 Angular 6 中是不可行的，因为这意味着每次创建新用户控件都至少需要增加 65 KB。此外，在 2018 年初，只有 Chrome 支持自定义元素，而无需添加 polyfills 以使这些自定义元素工作。由于其实验性质，我在本书中不涉及自定义元素。Angular 的未来更新，可能在 2018 年底或 2019 年初，应该会引入 Ivy 渲染引擎，使基本捆绑包大小最小为 2.7 KB，从而实现闪电般快速的加载时间，并使得可以发布基于 Angular 的自定义元素。在这个时间范围内，构建这样的组件的工具和自定义元素的本地浏览器支持也将得到改进，包括 Firefox 和 Safari 的支持，使得 Microsoft Edge 成为最后一个实现该标准的浏览器。

在对新的 Web 技术感到兴奋之前，始终在[`caniuse.com`](https://caniuse.com)上检查，以确保您确实能够在必须支持的浏览器中使用该功能。

尽管[Angular.io](https://Angular.io)已更新以演示自定义元素的可行性，但该文档网站每月吸引了 100 多万独立访问者，因此应该有助于解决一些难题，使其更加成熟。自定义元素是托管交互式代码示例的绝佳用例，可以与静态内容一起使用。在 2018 年初，[Angular.io](https://Angular.io)开始使用[StackBlitz.io](https://StackBlitz.io)进行交互式代码示例。这是一个令人惊叹的网站，本质上是一个云中的 Visual Studio Code IDE，您可以在其中尝试不同的想法或运行 GitHub 存储库，而无需本地拉取或执行任何代码。

Angular 生态系统也欢迎 NgRx 库，它基于 RxJS 为 Angular 带来了类似 Redux 的状态管理。这种状态管理对于在 PWA 和移动环境中构建离线优先应用是必要的。然而，在 iOS 的 Safari 浏览器中，PWA 的支持并不好，并且在新的 IE6 浏览器决定加入之前，PWA 不会得到广泛的应用。此外，NgRx 是对已经令人困惑和复杂的工具如 RxJS 的抽象。鉴于我对最小化工具的积极态度，以及对 RxJS 在利基受众之外缺乏明确必要性，我不会涉及这个工具。RxJS 足够强大和有能力解锁复杂和可扩展的模式，帮助您构建出色的 Angular 应用，正如在第十章中所展示的，*Angular 应用设计和配方*。

Angular Material 6 添加了新的用户控件，如树和徽章，同时通过一系列错误修复、功能完整性和现有组件的主题化，使库更加稳定。Angular Flex Layout 6 引入了 polyfills，使 Internet Explorer 11 支持 CSS Flexbox。这使得使用 Material 和 Flex Layout 的 Angular 应用程序完全兼容于仍然存在于企业和政府中的最后一个主要遗留浏览器技术，尽管在 2018 年 1 月与 Windows 8.1 一起离开了主流支持，并被 Microsoft Edge 取代了 16 次。Angular 6 本身可以通过 polyfills 配置为与 IE9 兼容。这对于必须支持这些遗留浏览器并且仍然能够使用现代技术构建解决方案的开发人员来说是个好消息。

还发布了一些令人兴奋的新的辅助工具，可以实现高频率、高性能或大型企业用例。由前 Angular 团队成员开发的 Nx CLI 工具为 Angular 带来了一个有见地的开发环境设置，适用于顾问和必须确保一致环境的大型组织。这本书遵循类似的模式，旨在教育您建立一致的架构和设计模式，以应用于您的应用程序。Google 的 Bazel 构建工具实现了增量构建，因此未更改的应用程序部分无需重新构建，大大提高了大型项目的构建时间，并允许在 Angular 应用程序之间共享库的打包。

我希望您和我一样对 Angular 6 和它所解锁的未来可能性感到兴奋。现在，让我们把这一切放在一边，深入研究通过构建一个简单的 Angular 应用程序来完成事情。

# 全栈架构中的 Angular

在本章中，我们将为您的 Angular 项目设计、架构、创建一个待办事项，并建立文件夹结构，以便与 REST API 进行通信。这个应用程序将被设计来演示以下用途：

+   角 CLI 工具（ng）

+   角组件的 UI 重用

+   角 HTTP 客户端

+   角路由器

+   角反应形式

+   材料自动完成

+   材料工具栏

+   材料 Sidenav

无论您使用的是什么后端技术，我建议您的前端始终驻留在自己的存储库中，并且使用自己的 Web 服务器进行提供，而不依赖于您的 API 服务器。

首先，您需要一个愿景和一个路线图来行动。

# 线框设计

有一些很棒的工具可以制作粗略的模型，以展示您的想法，并具有令人惊讶的丰富功能。如果您有专门的 UX 设计师，这些工具非常适合创建准原型。然而，作为全栈开发人员，我发现最好的工具是纸和笔。这样，您就不必学习另一个工具（YAL），而且没有设计要比有设计好得多。把东西写在纸上会让您避免在后续过程中进行昂贵的编码绕路，如果您能提前验证用户的线框设计，那就更好了。我将我的应用称为 LocalCast Weather，但请发挥创意，选择您自己的名称。以下是您天气应用的线框设计：

LocalCast 的线框。故意手绘。

线框不应该是什么花哨的东西。我建议从手绘设计开始，这样做非常快速，并且可以有效地传递粗略的轮廓。有很多很棒的线框工具，我将在本书中建议并使用其中的一些，但是在项目的最初几天，每个小时都很重要。可以肯定，这种粗糙的设计可能永远不会离开您团队的范围，但请知道，没有什么比将您的想法写在纸上或白板上更能获得即时的反馈和协作。

# 高级架构

无论您的项目大小如何，坦率地说，大多数时候您都无法提前准确预测，从一个健壮的架构开始至关重要，如果需要，它可以扩展，但不会增加执行一个简单应用想法的工作量。关键是确保从一开始就进行适当的解耦。在我看来，有两种解耦方式，一种是软解耦，基本上是达成“绅士协议”，不混合关注点，尽量不搞乱代码库。这可以适用于您编写的代码，一直到基础设施级别的交互。如果您将前端代码保持在与后端代码相同的代码结构下，并且让您的 REST 服务器提供前端应用程序，那么您只是在练习软解耦。

相反，你应该练习硬解耦，这意味着前端代码存放在一个单独的存储库中，从不直接调用数据库，并且完全托管在自己的网络服务器上。这样，你可以确保在任何时候，你的 REST API 或前端代码是完全可以独立替换的。练习硬解耦也有经济和安全方面的好处。前端应用的服务和扩展需求肯定与后端不同，因此您将能够适当优化您的主机环境并节省金钱。如果您将对 REST API 的访问白名单限制为仅允许来自前端服务器的调用，您将大大提高安全性。请考虑下面我们 LocalCast Weather 应用的高级架构图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/41e34a04-4d6b-4647-8d54-6d1679ade8db.jpg)LocalCast 高级架构

高级架构显示，我们的 Angular web 应用程序完全与任何后端解耦。它托管在自己的网络服务器上，可以与 Web API（如**OpenWeatherMap**）通信，或者选择与后端基础设施配对，以解锁丰富和定制的功能，这是仅仅使用 Web API 无法提供的，比如存储每个用户的偏好或者用我们自己的数据集补充 OpenWeatherMap 的数据集。

# 文件夹结构

我建议不要将前端和后端代码放在同一个代码存储库中。在同一个存储库中使用会导致奇怪的依赖关系，当你需要启用持续集成或将代码部署到生产环境时。为了获得集成的开发体验，并能够快速在存储库之间切换，您可以使用 IDE 功能，比如 VS Code Workspace，一次打开多个存储库在同一树状结构下。

如果必须使用单个存储库，为后端代码和前端代码创建单独的文件夹，分别命名为`server`和`web-app`。这样做的好处至少是很大的，因为团队成员可以在不互相干扰的情况下开始在前端或后端上工作。

按照接下来的两个部分的说明正确设置您的应用程序。如果您已经有一个强大的开发目录设置，并且您是一个 Git 专家，那么跳过到*生成您的 Angular 应用程序*部分。

# 设置您的开发目录

设置一个专门的`dev`目录是一个救命稻草。因为这个目录下的所有数据都将使用 GitHub 进行备份，您可以安全地配置您的防病毒软件、云同步或备份软件来忽略它。这将大大减少 CPU、磁盘和网络的利用率。作为一个全栈开发人员，您很可能会经常进行多任务处理，因此避免不必要的活动将对性能、功耗和数据消耗产生净正面影响，尤其是如果您的开发环境是一台资源匮乏的笔记本电脑，或者当您在移动时希望尽可能延长电池续航时间。

直接在`c:\`驱动器下创建一个`dev`文件夹非常重要，因为 Windows，或者说 NTFS，无法处理超过 260 个字符的文件路径。这一开始可能看起来足够，但当您在已经深层次的文件夹结构中安装 npm 包时，`node_modules`文件夹结构很容易达到这个限制。使用 npm 3+，引入了一种新的、更扁平的包安装策略，这有助于解决 npm 相关的问题，但尽可能靠近`root`文件夹将对任何工具都有很大帮助。在 2016 年末，有报道称微软可能会引入一个“启用 NTFS 长路径”的组策略来解决这个问题，但截至 2017 年底，这在 Windows 10 上还没有实现。

1.  使用以下命令创建您的`dev`文件夹：

对于 Windows：

```ts
PS> mkdir c:\dev
PS> cd c:\dev
```

在基于 Unix 的操作系统中，`~`（读作波浪线）是当前用户`home`目录的快捷方式，位于`/Users/your-user-name`下。

对于 macOS：

```ts
$ mkdir ~/dev
$ cd ~/dev
```

现在您的开发目录已准备就绪，让我们开始生成您的 Angular 应用程序。

# 生成您的 Angular 应用程序

Angular CLI（Angular 命令行界面）是一个官方的 Angular 项目，以确保新创建的 Angular 应用程序具有统一的架构，遵循社区多年来完善的最佳实践。这意味着您今后遇到的任何 Angular 应用程序都应该具有相同的一般形状。Angular CLI 不仅限于初始代码生成。您将经常使用它来创建新的组件、指令、管道、服务、模块等。Angular CLI 还将在开发过程中帮助您进行实时重新加载，以便您可以快速查看更改的结果。Angular CLI 还可以测试、检查代码，并构建优化版本的代码以进行生产发布。此外，随着新版本的 Angular 发布，Angular CLI 将帮助您升级您的代码，自动重写部分代码，以使其与潜在的破坏性更改保持兼容。

# 安装 Angular CLI

[`angular.io/guide/quickstart`](https://angular.io/guide/quickstart)上的文档将指导您安装`@angular/cli`作为全局 npm 软件包。不要这样做。随着 Angular CLI 的升级，不断地保持全局和项目内版本同步是一个不断的烦恼。如果不这样做，工具会不断地抱怨。此外，如果您正在处理多个项目，随着时间的推移，您将拥有不同版本的 Angular CLI。因此，您的命令可能不会返回您期望的结果，或者您的团队成员会受到影响。

下一节详细介绍的策略将使您的 Angular 项目的初始配置比必要的复杂一些；然而，如果您在几个月或一年后返回项目，您将能够使用您在该项目上最后使用的工具版本，而不是可能需要进行升级的未来版本。在下一节中，您将应用这一最佳实践来初始化您的 Angular 应用程序。

# 初始化 Angular 应用程序

现在，我们将使用`npx`初始化应用程序进行开发，当您安装最新版本的 Node LTS 时，它已经安装在您的系统上：

1.  在您的`dev`文件夹下，执行`npx @angular/cli new local-weather-app`

1.  在您的终端上，您应该看到类似于以下的成功消息：

```ts
...  
  create local-weather-app/src/tsconfig.app.json (211 bytes)
  create local-weather-app/src/tsconfig.spec.json (283 bytes)
  create local-weather-app/src/typings.d.ts (104 bytes)
  create local-weather-app/src/app/app.module.ts (316 bytes)
  create local-weather-app/src/app/app.component.html (1141 bytes)
  create local-weather-app/src/app/app.component.spec.ts (986 bytes)
  create local-weather-app/src/app/app.component.ts (207 bytes)
  create local-weather-app/src/app/app.component.css (0 bytes)
added 1273 packages from 1238 contributors in 60.594s
Project 'local-weather-app' successfully created.
```

您的项目文件夹`local-weather-app`已经初始化为 Git 存储库，并使用了初始的文件和文件夹结构，应该看起来像这样：

```ts
local-weather-app
├── angular.json
├── .editorconfig
├── .gitignore
├── .gitkeep
├── e2e
├── karma.conf.js
├── node_modules
├── package-lock.json
├── package.json
├── protractor.conf.js
├── README.md
├── src
├── tsconfig.json
└── tslint.json
```

`@angular/cli`的别名是`ng`。如果您要全局安装 Angular CLI，您只需执行`ng new local-weather-app`，但我们没有这样做。因此，重要的是要记住，今后您将执行`ng`命令，但这次是在`local-weather-app`目录下。最新版本的 Angular CLI 已经安装在`node_modules/.bin`目录下，因此您可以运行`ng`命令，比如`npx ng generate component my-new-component`，并继续以有效的方式工作。

如果您使用的是 macOS，您可以通过实现 shell 自动回退来进一步改善开发体验，这样就不需要使用`npx`命令了。如果找到未知命令，npx 将接管请求。如果包已经在`node_modules/.bin`下本地存在，npx 将把您的请求传递给正确的二进制文件。因此，您只需像全局安装一样运行命令，比如`ng g c my-new-component`。请参考 npx 的自述文件，了解如何在[npmjs.com/package/npx#shell-auto-fallback](https://www.npmjs.com/package/npx#shell-auto-fallback)上设置这一点。

# 使用 GitHub 桌面发布 Git 存储库

GitHub 桌面允许您直接在应用程序中创建新存储库：

1.  打开 GitHub 桌面

1.  文件 | 添加本地存储库...

1.  通过单击 Choose...来定位`local-weather-app`文件夹

1.  单击添加存储库

1.  请注意，Angular CLI 已经在历史选项卡中为您创建了第一个提交

1.  最后，点击发布存储库，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c4aebec3-835d-4533-88ea-8063784d4b99.png)GitHub 桌面

# 检查和更新 package.json

`Package.json`是您应该随时密切关注的最重要的配置文件。您的项目脚本、运行时和开发依赖项都存储在这个文件中。

1.  打开`package.json`并找到`name`和`version`属性：

```ts
package.json
{
  "name": "local-weather-app",
  "version": "0.0.0",
  "license": "MIT",
  **...**
```

1.  将您的应用程序重命名为您希望的任何名称；我将使用`localcast-weather`

1.  将您的版本号设置为`1.0.0`

`npm`使用语义化版本（semver），其中版本号数字表示主要.次要.补丁增量。Semver 从`1.0.0`开始为任何发布的 API 设置版本号，尽管它不会阻止 0.x.x 版本。作为 Web 应用程序的作者，您的应用程序的版本对您没有真正影响，除了内部工具、团队或公司沟通目的。但是，您的依赖项的版本对您的应用程序的可靠性非常关键。总之，补丁版本应该只是错误修复。次要版本增加功能而不会破坏现有功能，主要版本增量可以进行不兼容的 API 更改。然而，在现实中，任何更新都会对应用程序的测试行为构成风险。这就是为什么`package-lock.json`文件存储了应用程序的整个依赖树，以便其他开发人员或持续集成服务器可以复制应用程序的确切状态。欲了解更多信息，请访问：[`semver.org/`](https://semver.org/)。

在下面的代码块中，可以看到`scripts`属性包含一组有用的启动脚本，您可以进行扩展。`start`和`test`命令是 npm 的默认命令，因此可以通过`npm start`或`npm test`来执行。但是，其他命令是自定义命令，必须在前面加上`run`关键字。例如，要构建您的应用程序，您必须使用`npm run build`：

```ts
package.json
  ...
 "scripts": {
    "ng": "ng",
    "start": "ng serve",
    "build": "ng build",
    "test": "ng test",
    "lint": "ng lint",
    "e2e": "ng e2e"
  },
  ...
```

在 npx 引入之前，如果您想要在没有全局安装的情况下使用 Angular CLI，您必须使用`npm run ng -- g c my-new-component`来运行它。双破折号是必需的，以便让 npm 知道命令行工具名称在哪里结束并开始选项。例如，要在除默认端口`4200`之外的端口上启动您的 Angular 应用程序，您需要运行`npm start -- --port 5000`。

1.  更新您的`package.json`文件，以便从一个不常用的端口（如`5000`）运行您的应用的开发版本作为新的默认行为：

```ts
package.json
  ... "start": "ng serve --port 5000",
  ...
```

在`dependencies`属性下，您可以观察到您的运行时依赖项。这些库将与您的代码一起打包并发送到客户端浏览器。保持此列表最小化非常重要：

```ts
package.json
  ... "dependencies": {
    "@angular/animations": "⁶.0.0",
    "@angular/common": "⁶.0.0",
    "@angular/compiler": "⁶.0.0",
    "@angular/core": "⁶.0.0",
    "@angular/forms": "⁶.0.0",
    "@angular/http": "⁶.0.0",
    "@angular/platform-browser": "⁶.0.0",
    "@angular/platform-browser-dynamic": "⁶.0.0",
    "@angular/router": "⁶.0.0",
    "core-js": "².5.4",
    "rxjs": "⁶.0.0",
    "zone.js": "⁰.8.26"
  },
  ...
```

在前面的示例中，所有 Angular 组件都是相同版本。当您安装额外的 Angular 组件或升级单个组件时，建议将所有 Angular 包保持在相同的版本。这特别容易做到，因为 npm 5 不再需要`--save`选项来永久更新软件包版本。例如，只需执行`npm install @angular/router`就足以更新`package.json`中的版本。总的来说，这是一个积极的变化，因为您在`package.json`中看到的将与实际安装的内容匹配。但是，您必须小心，因为 npm 5 还将自动更新`package-lock.json`，这将传播您可能无意的更改给您的团队成员。

您的开发依赖项存储在`devDependencies`属性下。在向项目安装新工具时，您必须小心地在命令后面添加`--save-dev`，以便正确分类您的依赖关系。开发依赖项仅在开发过程中使用，不会发送到客户端浏览器。您应该熟悉每一个这些软件包及其具体目的。如果您对我们继续显示的软件包不熟悉，了解更多关于它们的最佳资源是[`www.npmjs.com/`](https://www.npmjs.com/)：

```ts
package.json
  ... "devDependencies": {
    "@angular/compiler-cli": "⁶.0.0",
    "@angular-devkit/build-angular": "~0.6.1",
    "typescript": "~2.7.2",
    "@angular/cli": "~6.0.1",
    "@angular/language-service": "⁶.0.0",
    "@types/jasmine": "~2.8.6",
    "@types/jasminewd2": "~2.0.3",
    "@types/node": "~8.9.4",
    "codelyzer": "~4.2.1",
    "jasmine-core": "~2.99.1",
    "jasmine-spec-reporter": "~4.2.1",
    "karma": "~1.7.1",
    "karma-chrome-launcher": "~2.2.0",
    "karma-coverage-istanbul-reporter": "~1.4.2", 
```

```ts
 "karma-jasmine": "~1.1.1",
    "karma-jasmine-html-reporter": "⁰.2.2",
    "protractor": "~5.3.0", "ts-node": "~5.0.1",
    "tslint": "~5.9.1"
  }
  ...
```

版本号前面的字符在 semver 中具有特定含义。

+   波浪号`~`在定义版本号的所有三个数字时启用波浪范围，允许自动应用补丁版本升级。

+   上插字符`^`使插入范围生效，允许自动应用次要版本升级

+   缺少任何字符会提示 npm 在您的计算机上安装该库的确切版本

您可能会注意到，不允许自动进行主要版本升级。一般来说，更新软件包可能存在风险。为了确保没有软件包在您明确知识的情况下进行更新，您可以使用 npm 的`--save-exact`选项安装确切版本的软件包。让我们通过安装我发布的一个名为`dev-norms`的 npm 软件包来尝试这种行为，这是一个生成团队围绕的合理默认规范的 markdown 文件的 CLI 工具，如下所示：

1.  在`local-weather-app`目录下，执行`npm install dev-norms --save-dev --save-exact`。请注意，`"dev-norms": "1.3.6"`或类似的内容已添加到`package.json`中，并且`package-lock.json`已自动更新以相应地反映这些更改。

1.  工具安装完成后，执行`npx dev-norms create`。创建了一个名为`dev-norms.md`的文件，其中包含上述的开发者规范。

1.  保存对`package.json`的更改。

使用过时的软件包会带来自己的风险。在 npm 6 中，引入了`npm audit`命令，以让您了解您正在使用的软件包中发现的任何漏洞。在`npm install`期间，如果收到任何漏洞通知，您可以执行`npm audit`以了解任何潜在风险的详细信息。

在下一节中，您将提交您对 Git 所做的更改。

# 使用 VS Code 提交代码

为了提交您的更改到 Git，然后将您的提交同步到 GitHub，您可以使用 VS Code。

1.  切换到源代码控制窗格，在此处标记为 1：

！[](Images/e771b503-a971-4ce4-ae81-957de6a252b1.png)Visual Studio Code 源代码控制窗格

1.  在 2 中输入提交消息

1.  单击 3 中的复选标记图标提交您的更改

1.  最后，通过单击 4 中的刷新图标将您的更改与 GitHub 存储库同步。

从现在开始，您可以在 VS Code 中执行大多数 Git 操作。

# 运行您的 Angular 应用程序

运行您的 Angular 应用程序以检查它是否正常工作。在开发过程中，您可以通过`ng serve`命令执行`npm start`；此操作将在 localhost 上转译、打包和提供启用了实时重新加载的代码：

1.  执行`npm start`

1.  导航到`http://localhost:5000`

1.  您应该看到一个类似于此的呈现页面：

！[](Images/10bd04de-9c6d-4a91-b4b0-a20e77386d26.png)默认的 Angular CLI 登陆页面

1.  通过在集成终端中按下*Ctrl* + *C*来停止应用程序。

# 优化用于 Angular 的 VS Code

一直保存文件可能会变得乏味。您可以通过以下方式启用自动保存：

1.  打开 VS Code

1.  切换到“文件”|“自动保存”下的设置。

您可以通过启动“首选项”来进一步自定义 VS Code 行为的许多方面。在 Windows 上启动首选项的键盘快捷键是*Ctrl* + *，*，在 macOS 上是⌘ + *，*。

# IDE 设置

您可以通过在项目目录的根目录中创建一个`.vscode`文件夹并在其中放置一个`settings.json`文件来与同事共享这些设置。如果您将此文件提交到存储库，每个人都将共享相同的 IDE 体验。不幸的是，个人无法使用自己的本地偏好覆盖这些设置，因此请确保共享设置是最小化的，并且作为团队规范达成一致。

以下是我用于实现最佳、节省电池寿命的 Angular 开发体验的自定义设置：

```ts
.vscode/settings.json
{
  "editor.tabSize": 2,
  "editor.rulers": [90, 140],
  "files.trimTrailingWhitespace": true,
  "files.autoSave": "onFocusChange",
  "editor.cursorBlinking": "solid",
  "workbench.iconTheme": "material-icon-theme", // Following setting 
                                               requires Material Icon 
                                                   Theme Extension
  "git.enableSmartCommit": true,
  "editor.autoIndent": true,
  "debug.openExplorerOnEnd": true,
  "auto-close-tag.SublimeText3Mode": true,      // Following setting 
                                               requires Auto Close Tag 
                                                      Extension
  "explorer.openEditors.visible": 0,
  "editor.minimap.enabled": false,
  "html.autoClosingTags": false,
  "git.confirmSync": false,
  "editor.formatOnType": true,
  "editor.formatOnPaste": true,
  "editor.formatOnSave": true,
  "prettier.printWidth": 90,                 // Following setting requires
                                                    Prettier Extension
  "prettier.semi": false,
  "prettier.singleQuote": true,
  "prettier.trailingComma": "es5",
  "typescriptHero.imports.insertSemicolons": false, // Following setting 
                                                   requires TypeScriptHero 
                                                          Extension
  "typescriptHero.imports.multiLineWrapThreshold": 90,
}
```

此外，您还可以在 VS Code 中启用以下设置，以获得更丰富的开发体验：

```ts
"editor.codeActionsOnSave": {
  "source.organizeImports": true
},    
"npm.enableScriptExplorer": true
```

# IDE 扩展

对于使用 VS Code 和 Angular 进行*神奇*开发体验，您应该安装由 John Papa 创建和策划的 Angular Essentials 扩展包。John Papa 是 Angular 社区中的领军者和思想领袖之一。他不断不懈地寻求最佳的开发体验，以便您作为开发人员更加高效和快乐。他是一个值得信赖并且非常认真对待的资源。我强烈建议您在 Twitter 上关注他`@john_papa`。

与设置类似，您还可以通过 JSON 文件共享推荐的扩展。以下是我用于 Angular 开发的扩展：

```ts
.vscode/extensions.json
{
  "recommendations": [
    "johnpapa.angular-essentials",
 "PKief.material-icon-theme",
    "formulahendry.auto-close-tag",
    "PeterJausovec.vscode-docker",
    "eamodio.gitlens",
    "WallabyJs.quokka-vscode",
    "rbbit.typescript-hero",
```

```ts
    "DSKWRK.vscode-generate-getter-setter",
    "esbenp.prettier-vscode"
  ]
}
```

VS Code 还会建议您安装一些扩展。我建议不要安装太多扩展，因为这些扩展会明显地减慢 VS Code 的启动性能和最佳运行。

# 编码风格

您可以在 VS Code 和 Angular CLI 中自定义编码风格执行和代码生成行为。在 JavaScript 方面，我更喜欢 StandardJS 设置，它规范了一种编写代码的最简化方法，同时保持了良好的可读性。这意味着使用 2 个空格作为制表符，而不使用分号。除了减少按键次数外，StandardJS 在水平方面也占用更少的空间，这在您的 IDE 只能利用屏幕的一半，另一半被浏览器占用时尤其有价值。您可以在以下网址了解更多关于 StandardJS 的信息：[`standardjs.com/`](https://standardjs.com/)。

使用默认设置，您的代码将如下所示：

```ts
import { AppComponent } from "./app.component";
```

使用 StandardJS 设置，您的代码将如下所示：

```ts
import { AppComponent } from './app.component'
```

最终，这对您来说是一个可选的步骤。但是，我的代码示例将遵循 StandardJS 风格。您可以通过以下步骤开始进行配置更改：

1.  安装 Prettier - Code formatter 扩展

1.  使用新的扩展更新`.vscode/extensions.json`文件

1.  执行`npm i -D prettier`

可以使用`i`代替更冗长的`--save-dev`选项进行`install`，并使用`-D`代替。但是，如果你将`-D`误输入为`-d`，你最终会将该包保存为生产依赖项。

1.  编辑`package.json`添加一个新的脚本，更新现有的脚本，并创建新的格式规则：

```ts
**package.json**
  ... 
  "scripts": {
    ...
    "standardize": "prettier **/*.ts --write",
    "start": "npm run standardize && ng serve --port 5000",
    "build": "npm run standardize && ng build",
    ...
  },
  ...
 "prettier": {
    "printWidth": 90,
    "semi": false,
    "singleQuote": true,
    "trailingComma": "es5",
    "parser": "typescript"
  } ... 
```

macOS 和 Linux 用户必须修改`standardize`脚本，为了正确遍历目录，必须在`**/*.ts`周围添加单引号。在 macOS 和 Linux 中，正确的脚本看起来像这样`"standardize": "prettier '**/*.ts' --write"`。

1.  类似地，使用新的格式规则更新`tslint.json`：

```ts
tslint.json
  ...  
  "quotemark": [
    true,
    "single"
  ],
  ...
  "semicolon": [
    true,
    "never"
  ],
  ...  "max-line-length": [
    true,
    120
  ],...
```

1.  执行`npm run standardize`来更新所有文件到新的样式

1.  观察 GitHub Desktop 中的所有文件更改

1.  今后，每当你执行`npm start`或`npm run build`时，新的`standardize`脚本将自动运行并保持文件的格式。

1.  提交并推送你的更改到你的存储库

当你输入新代码或使用 Angular CLI 生成新组件时，你会遇到双引号或分号被下划线标记为问题。在大多数情况下，问题旁边会出现一个黄色的灯泡图标。如果你点击灯泡，你会看到一个修复动作：不必要的分号或类似的消息。你可以利用这些自动修复程序，或者按下*Shift* + *Alt* + *F*来运行整个文件的 Prettier 格式文档命令。在下面的截图中，你可以看到自动修复程序的运行情况，有黄色的灯泡和相应的上下文菜单：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/28378c58-35a6-4666-ba48-4e85e1364fec.png)VS Code 自动修复程序

# 使用 Waffle 规划功能路线图

在开始编码之前制定一个大致的行动计划非常重要，这样你和你的同事或客户就会意识到你计划执行的路线图。无论是为自己还是为他人构建应用程序，功能的活动积压总是会在你休息后回到项目时作为一个很好的提醒，或者作为一个信息辐射器，防止不断的状态更新请求。

在敏捷开发中，您可能已经使用了各种票务系统或工具，比如表面或看板。我的最爱工具是 Waffle.io，因为它直接与您的 GitHub 存储库的问题集成，并通过标签跟踪问题的状态。这样，您可以继续使用您选择的工具与存储库进行交互，并轻松地传递信息。在下一节中，您将设置一个 Waffle 项目来实现这个目标。

# 设置 Waffle 项目

现在我们将设置我们的 Waffle 项目：

1.  转到 Waffle.io [`waffle.io/`](https://waffle.io/)。

1.  点击登录或免费开始。

1.  选择公共和私有存储库以允许访问所有存储库。

1.  点击创建项目。

1.  搜索本地天气应用存储库并选择它。

1.  点击继续。

您将获得两个起始布局模板，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/9cb448bb-d7e6-48ae-bde1-ce3cbb174c7a.png)Waffle.io 默认看板布局

对于这个简单的项目，您将选择基本。但是，高级布局演示了如何修改 Waffle 的默认设置，例如添加额外的列，比如 Review，以考虑参与过程的测试人员或产品所有者。您可以进一步自定义任何看板以适应您现有的流程。

1.  选择基本布局，然后点击创建项目。

1.  您将看到为您创建的新看板。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/59ab5b31-7f09-446d-9f1e-69d1bb6afed0.png)空的 Waffle 看板

默认情况下，Waffle 将作为看板。允许您将任务从一个状态移动到另一个状态。但是，默认视图将显示存储库中存在的所有问题。要将 Waffle 用作 Scrum 板，您需要将问题分配给 GitHub 里程碑，这将代表冲刺。然后，您可以使用过滤功能仅显示来自该里程碑的问题，或者换句话说，来自当前冲刺的问题。

在 Waffle 上，您可以通过点击![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/743fa9fd-b4cb-44e6-952c-a53cedda025f.jpg)比例图标将故事点附加到问题上。列将自动显示总数和卡片顺序，代表优先级，并且将从会话到会话保留。此外，您可以切换到指标视图以获取里程碑燃尽和吞吐量图表和统计信息。

# 为您的本地天气应用创建问题

我们现在将创建一个问题的积压，您将使用它来跟踪您实施应用程序设计的进展。在创建问题时，您应该专注于提供对用户有价值的功能迭代。您必须克服的技术障碍对您的用户或客户没有兴趣。

以下是我们计划在第一个发布版本中构建的功能：

+   显示当前位置当天的天气信息

+   显示当前位置的天气预报信息

+   添加城市搜索功能，以便用户可以查看其他城市的天气信息

+   添加首选项窗格以存储用户的默认城市

+   使用 Angular Material 改进应用程序的用户体验

继续在 Waffle 或 GitHub 上创建您的问题；无论您喜欢哪个都可以。在创建 Sprint 1 的范围时，我对功能有一些其他想法，所以我只是添加了这些问题，但我没有分配给任何人或者里程碑。我还继续为我打算处理的问题添加了故事点。以下是看板的样子，因为我要开始处理第一个故事：

！[](Images/afcc6387-02dc-4e09-9f46-0c45a106a8e2.png)看板的初始状态快照在[`waffle.io/duluca/local-weather-app`](https://waffle.io/duluca/local-weather-app)。最终，Waffle 提供了一个易于使用的 GUI，以便非技术人员可以轻松地与 GitHub 问题进行交互。通过允许非技术人员参与 GitHub 上的开发过程，您可以解锁 GitHub 成为整个项目的唯一信息来源的好处。关于功能和问题的问题，答案和讨论都作为 GitHub 问题的一部分进行跟踪，而不是在电子邮件中丢失。您还可以在 GitHub 上存储维基类型的文档，因此通过在 GitHub 上集中所有与项目相关的信息，数据，对话和工件，您大大简化了可能需要持续维护的多个系统的复杂交互，成本高昂。对于私有存储库和本地企业安装，GitHub 的成本非常合理。如果您坚持使用开源，就像我们在本章中一样，所有这些工具都是免费的。作为奖励，我在我的存储库[`github.com/duluca/local-weather-app/wiki`](https://github.com/duluca/local-weather-app/wiki)上创建了一个基本的维基页面。请注意，您无法将图像上传到`README.md`或维基页面。为了解决这个限制，您可以创建一个新问题，在评论中上传图像，并复制并粘贴其 URL 以将图像嵌入`README.md`或维基页面。在示例维基中，我遵循了这种技术将线框设计嵌入页面中。

有了具体的路线图，现在你可以开始实施你的应用程序了。

# 使用组件和接口来制作 UI 元素

您将利用 Angular 组件，接口和服务以一种解耦的，内聚的和封装的方式构建当前天气功能。

Angular 应用程序的默认登陆页面位于`app.component.html`中。因此，首先通过编辑`AppComponent`的模板，使用基本的 HTML 来布置应用程序的初始登陆体验。

我们现在开始开发 Feature 1：显示当前位置的当天天气信息，所以你可以将卡片移动到 Waffle 的 In Progress 列。

我们将添加一个`h1`标签作为标题，然后是我们应用的标语作为`div`，以及用于显示当前天气的占位符，如下面的代码块所示：

```ts
src/app/app.component.html
<div style="text-align:center">
  <h1>
  LocalCast Weather
  </h1>
  <div>Your city, your forecast, right now!</div>
  <h2>Current Weather</h2>
  <div>current weather</div>
</div>
```

此时，您应该运行`npm start`并在浏览器中导航到`http://localhost:5000`，以便您可以实时观察您所做的更改。

# 发现 OpenWeatherMap API

由于`httpClient`是强类型的，我们需要创建一个符合我们将调用的 API 形状的新接口。为了能够做到这一点，您需要熟悉当前天气数据 API。

1.  通过导航到[`openweathermap.org/current`](http://openweathermap.org/current)阅读文档：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c2cf5e84-5346-44a8-b651-b8f3403adff4.png)OpenWeatherMap 当前天气数据 API 文档

您将使用名为“按城市名称”的 API，该 API 允许您通过提供城市名称作为参数来获取当前天气数据。因此，您的网络请求将如下所示：

```ts
api.openweathermap.org/data/2.5/weather?q={city name},{country code}
```

1.  在文档页面上，点击“API 调用示例”下的链接，您将看到类似以下的示例响应：

```ts
http://samples.openweathermap.org/data/2.5/weather?q=London,uk&appid=b1b15e88fa797225412429c1c50c122a1
{
  "coord": {
    "lon": -0.13,
    "lat": 51.51
  },
  "weather": [
    {
      "id": 300,
      "main": "Drizzle",
      "description": "light intensity drizzle",
      "icon": "09d"
    }
  ],
  "base": "stations",
  "main": {
    "temp": 280.32,
    "pressure": 1012,
    "humidity": 81,
    "temp_min": 279.15,
    "temp_max": 281.15
  },
  "visibility": 10000,
  "wind": {
    "speed": 4.1,
    "deg": 80
  },
  "clouds": {
    "all": 90
  },
  "dt": 1485789600,
  "sys": {
    "type": 1,
    "id": 5091,
    "message": 0.0103,
    "country": "GB",
    "sunrise": 1485762037,
    "sunset": 1485794875
  },
  "id": 2643743,
  "name": "London",
  "cod": 200
}
```

考虑到您已经创建的现有`ICurrentWeather`接口，此响应包含的信息比您需要的要多。因此，您将编写一个新接口，符合此响应的形状，但只指定您将使用的数据部分。此接口将仅存在于`WeatherService`中，我们不会导出它，因为应用程序的其他部分不需要了解此类型。

1.  在`weather.service.ts`中的`import`和`@Injectable`语句之间创建一个名为`ICurrentWeatherData`的新接口

1.  新接口应该像这样：

```ts
src/app/weather/weather.service.ts
interface ICurrentWeatherData {
  weather: [{
    description: string,
    icon: string
  }],
  main: {
    temp: number
  },
  sys: {
    country: string
  },
  dt: number,
  name: string
}
```

通过`ICurrentWeatherData`接口，我们通过向接口添加具有不同结构的子对象来定义新的匿名类型。这些对象中的每一个都可以单独提取出来，并定义为自己的命名接口。特别要注意的是，`weather`将是具有`description`和`icon`属性的匿名类型的数组。

# 添加一个 Angular 组件

我们需要显示当前天气信息，位置在`<div>current weather</div>`处。为了实现这一点，您需要构建一个负责显示天气数据的组件。

创建单独组件的原因是架构最佳实践，这在**Model-View-ViewModel**（**MVVM**）设计模式中得到了体现。你可能之前听说过**Model-View-Controller**（**MVC**）模式。大多数在 2005 年至 2015 年左右编写的基于 Web 的代码都是按照 MVC 模式编写的。MVVM 与 MVC 模式在重要方面有所不同。正如我在 2013 年的 DevPro 文章中所解释的：

[有效实现 MVVM]本质上强制执行关注点的正确分离。业务逻辑与展示逻辑清晰分离。因此，当一个视图被开发时，它就会保持开发状态，因为修复一个视图功能中的错误不会影响其他视图。另一方面，如果[你使用]视觉继承有效并[创建]可重用的用户控件，修复一个地方的错误可以解决整个应用程序中的问题。

Angular 提供了 MVVM 的有效实现。

ViewModels 清晰地封装任何展示逻辑，并通过作为模型的专业版本来简化 View 代码。View 和 ViewModel 之间的关系很直接，可以更自然地将 UI 行为包装在可重用的用户控件中。

你可以在[`bit.ly/MVVMvsMVC`](http://bit.ly/MVVMvsMVC)阅读更多关于架构细微差别的内容和插图。

接下来，你将创建你的第一个 Angular 组件，其中将包括 View 和 ViewModel，使用 Angular CLI 的`ng generate`命令：

1.  在终端中，执行`npx ng generate component current-weather`

确保你在`local-weather-app`文件夹下执行`ng`命令，而不是在`root`项目文件夹下执行。此外，请注意`npx ng generate component current-weather`可以重写为`ng g c current-weather`。今后，本书将使用简写格式，并期望你在必要时加上`npx`。

1.  观察在你的`app`文件夹中创建的新文件：

```ts
src/app
├── app.component.css
├── app.component.html
├── app.component.spec.ts
├── app.component.ts
├── app.module.ts
├── current-weather
  ├── current-weather.component.css
  ├── current-weather.component.html
  ├── current-weather.component.spec.ts
  └── current-weather.component.ts
```

生成的组件有四个部分：

+   `current-weather.component.css`包含特定于组件的任何 CSS，并且是一个可选文件。

+   `current-weather.component.html`包含定义组件外观和绑定渲染的 HTML 模板，并且可以被视为 View，结合使用的任何 CSS 样式。

+   `current-weather.component.spec.ts`包含基于 Jasmine 的单元测试，你可以扩展以测试你的组件功能。

+   `current-weather.component.ts`包含了类定义上方的`@Component`装饰器，它是将 CSS、HTML 和 JavaScript 代码粘合在一起的粘合剂。类本身可以被视为 ViewModel，从服务中提取数据并执行任何必要的转换，以公开视图的合理绑定，如下所示：

```ts
src/app/current-weather/current-weather.component.ts
import { Component, OnInit } from '@angular/core'
@Component({
  selector: 'app-current-weather',
  templateUrl: './current-weather.component.html',
  styleUrls: ['./current-weather.component.css'],
})
export class CurrentWeatherComponent implements OnInit {
  constructor() {}

  ngOnInit() {}
}
```

如果您计划编写的组件很简单，可以使用内联样式和内联模板重写它，以简化代码结构。

1.  使用内联模板和样式更新`CurrentWeatherComponent`：

```ts
src/app/current-weather/current-weather.component.ts import { Component, OnInit } from '@angular/core'

@Component({
  selector: 'app-current-weather',
  template: `
  <p>
    current-weather works!
  </p>
  `,
  styles: ['']
})
export class CurrentWeatherComponent implements OnInit {
constructor() {}

ngOnInit() {}
}
```

当您执行生成命令时，除了创建组件，该命令还将您创建的新模块添加到`app.module.ts`中，避免了将组件连接在一起的繁琐任务。

```ts
src/app/app.module.ts ...
import { CurrentWeatherComponent } from './current-weather/current-weather.component'
...
@NgModule({
declarations: [AppComponent, CurrentWeatherComponent],
...
```

Angular 的引导过程，诚然有点复杂。这也是 Angular CLI 存在的主要原因。`index.html`包含一个名为`<app-root>`的元素。当 Angular 开始执行时，它首先加载`main.ts`，该文件配置了用于浏览器的框架并加载了应用模块。应用模块然后加载所有依赖项，并在前述的`<app-root>`元素内呈现。在第七章中，*创建一个以路由为首的业务应用程序*，当我们构建一个业务应用程序时，我们将创建自己的功能模块，以利用 Angular 的可扩展性特性。

现在，我们需要在初始的`AppComponent`模板上显示我们的新组件，以便最终用户可以看到：

1.  通过用`<app-current-weather></app-current-weather>`替换`<div>current weather</div>`，将`CurrentWeatherComponent`添加到`AppComponent`中：

```ts
src/app/app.component.html
<div  style="text-align:center"> <h1> LocalCast Weather </h1> <div>Your city, your forecast, right now!</div>
 <h2>Current Weather</h2>
 <app-current-weather></app-current-weather> </div>
```

1.  如果一切正常，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0ae2d6b8-f075-4af4-a501-c31dd137408d.png)您的本地天气应用程序的初始渲染请注意浏览器窗口标签中的图标和名称。作为 Web 开发的规范，在`index.html`文件中，使用应用程序的名称和图标更新`<title>`标签和`favicon.ico`文件，以自定义浏览器标签信息。如果您的 favicon 没有更新，请在`href`属性后附加一个唯一的版本号，例如`href="favicon.ico?v=2"`。结果，您的应用程序将开始看起来像一个真正的 Web 应用程序，而不是一个由 CLI 生成的起始项目。

# 使用接口定义您的模型

现在你的`View`和`ViewModel`已经就位，你需要定义你的`Model`。如果你回顾设计，你会发现组件需要显示：

+   城市

+   国家

+   当前日期

+   当前图片

+   当前温度

+   当前天气描述

你将首先创建一个代表这个数据结构的接口：

1.  在终端中，执行`npx ng generate interface ICurrentWeather`

1.  观察一个新生成的名为`icurrent-weather.ts`的文件，其中包含一个空的接口定义，看起来像这样：

```ts
src/app/icurrent-weather.ts
export  interface ICurrentWeather { }
```

这不是一个理想的设置，因为我们可能会向我们的应用程序添加许多接口，追踪各种接口可能会变得乏味。随着时间的推移，当你将这些接口的具体实现作为类添加时，将把类和它们的接口放在自己的文件中是有意义的。

为什么不直接将接口命名为`CurrentWeather`？这是因为以后我们可能会创建一个类来实现`CurrentWeather`的一些有趣的行为。接口建立了一个契约，确定了任何实现或扩展接口的类或接口上可用属性的列表。始终要意识到何时使用类与接口是非常重要的。如果你遵循最佳实践，始终以大写`I`开头命名你的接口，你将始终意识到你正在传递的对象的类型。因此，接口被命名为`ICurrentWeather`。

1.  将`icurrent-weather.ts`重命名为`interfaces.ts`

1.  将接口名称的大写改正为`ICurrentWeather`

1.  同时，按照以下方式实现接口：

```ts
src/app/interfaces.ts
export interface ICurrentWeather {
  city: string
  country: string
  date: Date
  image: string
  temperature: number
  description: string
}
```

这个接口及其最终的具体表示作为一个类是 MVVM 中的模型。到目前为止，我已经强调了 Angular 的各个部分如何符合 MVVM 模式；未来，我将用它们的实际名称来引用这些部分。

现在，我们可以将接口导入到组件中，并开始在`CurrentWeatherComponent`的模板中连接绑定。

1.  导入`ICurrentWeather`

1.  切换回`templateUrl`和`styleUrls`

1.  定义一个名为`current`的局部变量，类型为`ICurrentWeather`

```ts
src/app/current-weather/current-weather.component.ts import { Component, OnInit } from '@angular/core'
import { ICurrentWeather } from '../interfaces'

@Component({
  selector: 'app-current-weather',
  templateUrl: './current-weather.component.html',
  styleUrls: ['./current-weather.component.css'],
})
export class CurrentWeatherComponent implements OnInit {
  current: ICurrentWeather

  constructor() {}

  ngOnInit() {}
}
```

如果你只是输入`current: ICurrentWeather`，你可以使用自动修复程序自动插入导入语句。

在构造函数中，你将临时用虚拟数据填充当前属性以测试你的绑定。

1.  将虚拟数据实现为一个 JSON 对象，并使用 as 运算符声明其遵守`ICurrentWeather`：

```ts
src/app/current-weather/current-weather.component.ts
...
constructor() {
 this.current = {
 city: 'Bethesda',
 country: 'US',
 date: new Date(),
 image: 'assets/img/sunny.svg',
 temperature: 72,
 description: 'sunny',
 } as ICurrentWeather
} ...
```

在`src/assets`文件夹中，创建一个名为`img`的子文件夹，并放置一张你选择的图片以在虚拟数据中引用。

你可能会忘记你创建的接口中的确切属性。你可以通过按住*Ctrl*并将鼠标悬停在接口名称上来快速查看它们，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/9875716b-28c2-4286-8436-3365b3357d40.png)*Ctrl* + 悬停在接口上

现在你可以更新模板，将你的绑定与基本的基于 HTML 的布局连接起来。

1.  实现模板：

```ts
src/app/current-weather/current-weather.component.html <div>
  <div>
    <span>{{current.city}}, {{current.country}}</span>
    <span>{{current.date | date:'fullDate'}}</span>
  </div>
  <div>
    <img [src]='current.image'>
    <span>{{current.temperature | number:'1.0-0'}}℉</span>
  </div>
  <div>
    {{current.description}}
  </div>
</div>
```

要更改`current.date`的显示格式，我们使用了上面的`DatePipe`，传入`'fullDate'`作为格式选项。在 Angular 中，各种内置和自定义管道`|`操作符可用于改变数据的外观，而不实际改变基础数据。这是一个非常强大、方便和灵活的系统，可以在不编写重复的样板代码的情况下共享用户界面逻辑。在上面的例子中，如果我们想以更紧凑的形式表示当前日期，我们可以传入`'shortDate'`。有关各种`DatePipe`选项的更多信息，请参阅[`angular.io/api/common/DatePipe`](https://angular.io/api/common/DatePipe)上的文档。要格式化`current.temperature`，以便不显示小数值，可以使用`DecimalPipe`。文档在[`angular.io/api/common/DecimalPipe`](https://angular.io/api/common/DecimalPipe)。

请注意，你可以使用它们各自的 HTML 代码来渲染℃和℉： ![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/3aead4cb-5060-4f39-99ff-77e8378a22e7.png) 代表℃， ![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e8c94057-be77-44bd-9f19-f7c814114fa2.png) 代表℉。

1.  如果一切正常，你的应用程序应该看起来类似于这个截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/39d31e79-3c3f-482d-993a-01450525f3d9.png)绑定虚拟数据后的应用程序

恭喜，你已成功连接了你的第一个组件。

# 使用 Angular 服务和 HttpClient 来检索数据

现在你需要将你的`CurrentWeather`组件连接到`OpenWeatherMap`的 API。在接下来的章节中，我们将介绍以下步骤来实现这个目标：

1.  创建一个新的 Angular 服务

1.  导入`HttpClientModule`并将其注入到服务中

1.  发现`OpenWeatherMap` API

1.  创建一个符合 API 形状的新接口

1.  编写一个`get`请求

1.  将新服务注入到`CurrentWeather`组件中

1.  从`CurrentWeather`组件的`init`函数中调用服务

1.  最后，使用 RxJS 函数将 API 数据映射到本地的`ICurrentWeather`类型，以便组件可以使用它

# 创建一个新的 Angular 服务

任何触及组件边界之外的代码都应该存在于一个服务中；这包括组件间的通信，除非存在父子关系，以及任何缓存或从 cookie 或浏览器的 localStorage 中检索数据的代码。这是一个关键的架构模式，可以使您的应用在长期内易于维护。我在我的 DevPro MVVM 文章中对这个想法进行了扩展，网址为 [`bit.ly/MVVMvsMVC`](http://bit.ly/MVVMvsMVC)。

要创建一个 Angular 服务，执行以下操作：

1.  在终端中执行 `npx ng g s weather --flat false`

1.  观察新创建的`weather`文件夹：

```ts
src/app
...
└── weather
   ├── weather.service.spec.ts
   └── weather.service.ts
```

生成的服务有两部分：

+   `weather.service.spec.ts` 包含了基于 Jasmine 的单元测试，您可以扩展以测试您的服务功能。

+   `weather.service.ts` 包含了类定义之上的`@Injectable`装饰器，这使得可以将此服务注入到其他组件中，利用 Angular 的提供者系统。这将确保我们的服务是单例的，意味着无论它被注入到其他地方多少次，它只会被实例化一次。

服务已经生成，但没有自动提供。要做到这一点，请按照以下步骤操作：

1.  打开`app.module.ts`

1.  在 providers 数组中输入`WeatherService`

1.  使用自动修复程序为您导入类：

```ts
src/app/app.module.ts
...
import { WeatherService } from './weather/weather.service'
...
@NgModule({
  ...
  providers: [WeatherService],
  ...
```

如果您安装了推荐的扩展程序 TypeScript Hero，导入语句将会自动添加。您不必使用自动修复程序来完成。今后，我将不再提到导入模块的需要。

# 注入依赖项

为了进行 API 调用，您将在 Angular 中利用`HttpClient`模块。官方文档 ([`angular.io/guide/http`](https://angular.io/guide/http)) 简洁地解释了这个模块的好处：

“使用 HttpClient，@angular/common/http 为 Angular 应用程序提供了一个简化的 HTTP 功能 API，构建在浏览器暴露的 XMLHttpRequest 接口之上。HttpClient 的额外好处包括可测试性支持，请求和响应对象的强类型化，请求和响应拦截器支持，以及基于 Observables 的更好的错误处理。”

让我们从将`HttpClientModule`导入到我们的应用程序开始，这样我们就可以在模块中将`HttpClient`注入到`WeatherService`中：

1.  将`HttpClientModule`添加到`app.module.ts`中，如下所示：

```ts
src/app/app.module.ts
...
import { HttpClientModule } from  '@angular/common/http'
...
@NgModule({
  ...
  imports: [
    ...
    HttpClientModule,
    ...
```

1.  在`WeatherService`中注入`HttpClient`，由`HttpClientModule`提供，如下所示：

```ts
src/app/weather/weather.service.ts
import { HttpClient } from '@angular/common/http'
import { Injectable } from '@angular/core'

@Injectable()
export class WeatherService {
  constructor(private httpClient: HttpClient) {}
}
```

现在，`httpClient`已经准备好在您的服务中使用。

# 存储环境变量

很容易忽略，但是前几节中的示例 URL 包含一个必需的`appid`参数。您必须将此密钥存储在您的 Angular 应用程序中。您可以将其存储在天气服务中，但实际上，应用程序需要能够在从开发到测试、暂存和生产环境的不同资源集之间切换。Angular 提供了两个环境：一个是`prod`，另一个是默认的。

在继续之前，您需要注册一个免费的`OpenWeatherMap`帐户并检索您自己的`appid`。您可以阅读[`openweathermap.org/appid`](http://openweathermap.org/appid)上的`appid`文档以获取更详细的信息。

1.  复制您的`appid`，它将包含一长串字符和数字

1.  将您的`appid`存储在`environment.ts`中

1.  为以后使用配置`baseUrl`：

```ts
src/environments/environment.ts
export const environment = {
  production: false,
  appId: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  baseUrl: 'http://',
}
```

在代码中，我们使用驼峰命名法`appId`来保持我们的编码风格一致。由于 URL 参数不区分大小写，`appId`和`appid`都可以使用。

# 实现 HTTP GET 操作

现在，我们可以在天气服务中实现 GET 调用：

1.  在`WeatherService`类中添加一个名为`getCurrentWeather`的新函数

1.  导入`environment`对象

1.  实现`httpClient.get`函数

1.  返回 HTTP 调用的结果：

```ts
src/app/weather/weather.service.ts
import { environment } from '../../environments/environment'
...
export class WeatherService {
  constructor(private httpClient: HttpClient) { }

  getCurrentWeather(city: string, country: string) {
    return this.httpClient.get<ICurrentWeatherData>(
        `${environment.baseUrl}api.openweathermap.org/data/2.5/weather?` +
          `q=${city},${country}&appid=${environment.appId}`
    )
  }
}
```

请注意 ES2015 的字符串插值特性的使用。您可以使用反引号语法包裹``您的字符串``，而不是通过将变量追加到一起来构建字符串，例如`environment.baseUrl + 'api.openweathermap.org/data/2.5/weather?q=' + city + ',' + country + '&appid=' + environment.appId`。在反引号内，您可以有换行，并且还可以直接嵌入变量到字符串流中，方法是用`${dollarbracket}`语法将它们包裹起来。但是，当您在代码中引入换行时，它将被解释为字面换行—`\n`。为了在代码中断开字符串，您可以添加反斜杠`\`，但是接下来的代码行不能有缩进。更容易的方法是连接多个模板，就像前面的代码示例中所示的那样。请注意，在`get`函数中使用了 TypeScript 泛型，使用了尖括号语法，如`<TypeName>`。使用泛型是开发时的生活质量特性。通过向函数提供类型信息，该函数的输入和/或返回变量类型将在编写代码时显示并在开发和编译时进行验证。

# 从组件中检索服务数据

为了能够在`CurrentWeather`组件中使用`getCurrentWeather`函数，您需要将服务注入到组件中：

1.  将`WeatherService`注入到`CurrentWeatherComponent`类的构造函数中

1.  删除在构造函数中创建虚拟数据的现有代码：

```ts
src/app/current-weather/current-weather.component.ts
constructor(private weatherService: WeatherService) { }
```

1.  在`ngOnInit`函数中调用`getCurrentWeather`函数：

```ts
src/app/current-weather/current-weather.component.ts
ngOnInit() {
  this.weatherService.getCurrentWeather('Bethesda', 'US')
    .subscribe((data) => this.current = data)
}
```

公平警告，不要指望这段代码立即能够工作。您应该会看到一个错误，所以让我们在下一部分中了解发生了什么。

Angular 组件具有丰富的生命周期钩子集合，允许您在组件被渲染、刷新或销毁时注入自定义行为。`ngOnInit()`是您将要使用的最常见的生命周期钩子。它只会在组件首次实例化或访问时被调用。这是您希望执行服务调用的地方。要深入了解组件生命周期钩子，请查看文档[`angular.io/guide/lifecycle-hooks`](https://angular.io/guide/lifecycle-hooks)。请注意，您传递给`subscribe`的匿名函数是 ES2015 的箭头函数。如果您不熟悉箭头函数，一开始可能会感到困惑。箭头函数实际上非常简洁和简单。

考虑以下箭头函数：

`(data) => { this.current = data }`

你可以简单地重写它为：

`function(data) { this.current = data }`

有一个特殊条件——当您编写一个简单转换数据的箭头函数时，比如这样：

`(data) => { data.main.temp }`

该功能有效地将`ICurrentWeatherData`作为输入，并返回 temp 属性。返回语句是隐式的。如果将其重写为常规函数，它将如下所示：

`function(data) { return data.main.temp }`

当`CurrentWeather`组件加载时，`ngOnInit`将触发一次，这将调用`getCurrentWeather`函数，该函数返回一个类型为`Observable<ICurrentWeatherData>`的对象。如官方文档所述，Observable 是 RxJS 的最基本构建块，表示事件发射器，它将以`ICurrentWeatherData`类型随时间发出接收到的任何数据。`Observable`对象本身是无害的，除非被监听，否则不会引发网络事件。您可以在[reactivex.io/rxjs/class/es6/Observable.js~Observable.html](http://reactivex.io/rxjs/class/es6/Observable.js~Observable.html)上阅读更多关于 Observables 的信息。

通过在 Observable 上调用`.subscribe`，实质上是将侦听器附加到发射器上。您在`subscribe`方法中实现了一个匿名函数，每当接收到新数据并发出事件时，该函数将被执行。匿名函数以数据对象作为参数，并且在这种情况下的具体实现中，将数据分配给名为 current 的局部变量。每当 current 更新时，您之前实现的模板绑定将拉取新数据并在视图上呈现它。即使`ngOnInit`只执行一次，对 Observable 的订阅仍然存在。因此，每当有新数据时，current 变量将被更新，并且视图将重新呈现以显示最新数据。

手头错误的根本原因是正在发出的数据是`ICurrentWeatherData`类型；但是，我们的组件只能理解按照`ICurrentWeather`接口描述的形状的数据。在下一节中，您需要深入了解 RxJS，以了解如何最好地完成该任务。

注意，VS Code 和 CLI 有时会停止工作。如前所述，当您编写代码时，`npm start` 命令正在 VS Code 的集成终端中运行。Angular CLI 与 Angular Language Service 插件结合，不断监视代码更改并将您的 TypeScript 代码转译为 JavaScript，因此您可以在浏览器中实时查看您的更改。很棒的是，当您出现编码错误时，除了在 VS Code 中的红色下划线外，您还会在终端或甚至浏览器中看到一些红色文本，因为转译失败了。在大多数情况下，纠正错误后，红色下划线将消失，Angular CLI 将自动重新转译您的代码，一切都会正常工作。然而，在某些情况下，您会注意到 VS Code 无法在 IDE 中捕捉到输入更改，因此您将无法获得自动补全帮助，或者 CLI 工具会卡在显示“webpack: Failed to compile”的消息上。您有两种主要策略来从这种情况中恢复：

1.  点击终端并按 *Ctrl* + *C* 停止运行 CLI 任务，然后通过执行 `npm start` 重新启动

1.  如果 **#1** 不起作用，请使用 *Alt* + *F4*（Windows）或 ⌘ + *Q*（macOS）退出 VS Code 并重新启动它

考虑到 Angular 和 VS Code 的每月发布周期，我相信随着时间的推移，工具只会变得更好。

# 使用 RxJS 转换数据

RxJS 代表响应式扩展，这是一个模块化库，可以实现响应式编程，这本身是一种异步编程范式，并允许通过转换、过滤和控制函数来操作数据流。您可以将响应式编程视为事件驱动编程的演变。

# 了解响应式编程

在事件驱动编程中，您会定义一个事件处理程序并将其附加到事件源。更具体地说，如果您有一个保存按钮，它公开了一个 `onClick` 事件，您将实现一个 `confirmSave` 函数，当触发时，会显示一个弹出窗口询问用户“您确定吗？”。请看下图以可视化此过程。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/087093d4-6cc4-4942-b53f-61a0cbce08f8.png)事件驱动实现

简而言之，您将有一个事件在每次用户操作时触发。如果用户多次点击保存按钮，这种模式将愉快地渲染出与点击次数相同的弹出窗口，这并没有太多意义。

发布-订阅（pub/sub）模式是一种不同类型的事件驱动编程。在这种情况下，我们可以编写多个处理程序来同时处理给定事件的结果。假设您的应用程序刚刚收到了一些更新的数据。发布者将遍历其订阅者列表，并将更新的数据传递给它们每一个。参考以下图表，更新的数据事件如何触发一个`updateCache`函数，该函数可以使用新数据更新本地缓存，一个`fetchDetails`函数，该函数可以从服务器检索有关数据的更多详细信息，以及一个`showToastMessage`函数，该函数可以通知用户应用程序刚刚收到了新数据。所有这些事件都可以异步发生；但是，`fetchDetails`和`showToastMessage`函数将接收比它们实际需要的更多数据，并且尝试以不同方式组合这些事件以修改应用程序行为可能会变得非常复杂。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/cfdf8261-a38b-401f-97b8-3f23210b81bf.png)发布-订阅模式实现

在响应式编程中，一切都被视为流。流将包含随时间发生的事件，这些事件可以包含一些数据或没有数据。以下图表可视化了一个场景，您的应用程序正在监听用户的鼠标点击。无序的用户点击流是没有意义的。通过对其应用`throttle`函数，您可以对此流施加一些控制，以便每 250 毫秒只获取更新。如果订阅此新事件，每 250 毫秒，您将收到一个点击事件列表。您可以尝试从每个点击事件中提取一些数据，但在这种情况下，您只对发生的点击事件数量感兴趣。我们可以使用`map`函数将原始事件数据转换为点击次数。

在流的下游，我们可能只对包含两个或更多点击的事件感兴趣，因此我们可以使用`filter`函数仅对本质上是双击事件的事件进行操作。每当我们的过滤事件触发时，这意味着用户打算双击，您可以通过弹出警报来对此信息进行操作。流的真正力量来自于您可以选择在任何时候对事件进行操作，因为它通过各种控制、转换和过滤函数。您可以选择使用`*ngFor`和 Angular 的`async`管道在 HTML 列表上显示点击数据，以便用户可以每 250 毫秒监视被捕获的点击数据类型。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e47a3a03-78c2-45ee-ae01-35bae1e77478.png)一个响应式数据流实现

# 实施响应式转换

为了避免将意外类型的数据从您的服务中返回，您需要更新`getCurrentWeather`函数以定义返回类型为`Observable<ICurrentWeather>`，并导入`Observable`类型，如下所示：

```ts
**src/app/weather/weather.service.ts**
import { Observable } from 'rxjs'
import { ICurrentWeather } from '../interfaces'
... 
```

```ts
export class WeatherService {
  ...
  getCurrentWeather(city:  string, country:  string): Observable<ICurrentWeather> {
  }
  ...
}
```

现在，VS Code 会提醒您，`Observable<ICurrentWeatherData>`类型无法赋值给`Observable<ICurrentWeather>`类型：

1.  编写一个名为`transformToICurrentWeather`的转换函数，可以将`ICurrentWeatherData`转换为`ICurrentWeather`

1.  另外，编写一个名为`convertKelvinToFahrenheit`的辅助函数，将 API 提供的开尔文温度转换为华氏度：

```ts
src/app/weather/weather.service.ts export class WeatherService {...
  private transformToICurrentWeather(data: ICurrentWeatherData): ICurrentWeather {
    return {
      city: data.name,
      country: data.sys.country,
      date: data.dt * 1000,
      image: `http://openweathermap.org/img/w/${data.weather[0].icon}.png`,
      temperature: this.convertKelvinToFahrenheit(data.main.temp),
      description: data.weather[0].description
    }
  }

  private convertKelvinToFahrenheit(kelvin: number): number {
    return kelvin * 9 / 5 - 459.67
  }
}
```

请注意，您需要在此阶段将图标属性转换为图像 URL。在服务中执行此操作有助于保持封装性，将图标值绑定到视图模板中的 URL 将违反**关注点分离**（**SoC**）原则。如果您希望创建真正模块化、可重用和可维护的组件，您必须在执行 SoC 方面保持警惕和严格。有关天气图标的文档以及 URL 应如何形成的详细信息，包括所有可用的图标，可以在[`openweathermap.org/weather-conditions`](http://openweathermap.org/weather-conditions)找到。另外，可以提出这样的论点，即从开尔文到华氏的转换实际上是一个视图关注点，但我们已经在服务中实现了它。这个论点是站得住脚的，特别是考虑到我们计划的功能可以在摄氏度和华氏度之间切换。另一个论点是，此时，我们只需要以华氏度显示，并且天气服务的工作部分是能够转换单位。这个论点也是有道理的。最终的实现将是编写一个自定义的 Angular 管道，并在模板中应用它。管道也可以轻松地与计划中的切换按钮绑定。然而，此时，我们只需要以华氏度显示，我会倾向于*不*过度设计解决方案。

1.  将`ICurrentWeather.date`更新为`number`类型

在编写转换函数时，您会注意到 API 将日期返回为数字。这个数字代表自 UNIX 纪元（时间戳）以来的秒数，即 1970 年 1 月 1 日 00:00:00 UTC。然而，`ICurrentWeather`期望一个`Date`对象。通过将时间戳传递给`Date`对象的构造函数进行转换是很容易的，就像`new Date(data.dt)`。这样做没问题，但也是不必要的，因为 Angular 的`DatePipe`可以直接处理时间戳。为了追求简单和充分利用我们使用的框架的功能，我们将更新`ICurrentWeather`以使用`number`。如果您正在转换大量数据，这种方法还有性能和内存上的好处，但这个问题在这里并不适用。有一个例外——JavaScript 的时间戳是以毫秒为单位的，但服务器的值是以秒为单位的，所以在转换过程中仍然需要进行简单的乘法运算。

1.  在其他导入语句下方导入 RxJS 的`map`操作符：

```ts
src/app/weather/weather.service.ts
import { map } from 'rxjs/operators'
```

手动导入`map`操作符可能看起来有点奇怪。RxJS 是一个非常强大的框架，具有广泛的 API 表面。仅 Observable 本身就有 200 多个附加方法。默认情况下包括所有这些方法会在开发时创建太多的函数选择问题，并且还会对最终交付的大小、应用程序性能和内存使用产生负面影响。因此，您必须单独添加您打算使用的每个操作符。

1.  通过`pipe`将`map`函数应用于`httpClient.get`方法返回的数据流。

1.  将`data`对象传递给`transformToICurrentWeather`函数：

```ts
src/app/weather/weather.service.ts
...
return this.httpClient
  .get<ICurrentWeatherData>(
    `http://api.openweathermap.org/data/2.5/weather?q=${city},${country}&appid=${environment.appId}`
  ).pipe(
    map(data => 
      this.transformToICurrentWeather(data)
    )
  )
...
```

现在，传入的数据可以在流经过程中进行转换，确保`OpenWeatherMap`当前天气 API 数据的格式正确，以便`CurrentWeather`组件可以使用。

1.  确保您的应用成功编译

1.  在浏览器中检查结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/acb5fa9f-0a66-4115-ac92-88f29e710067.png)从 OpenWeatherMap 显示实时数据

最后，您应该看到您的应用能够从`OpenWeatherMap`获取实时数据，并正确地将服务器数据转换为您期望的格式。

您已经完成了 Feature 1 的开发：显示当前位置的当天天气信息。提交您的代码并将卡片移动到 Waffle 的 Done 列。

1.  最后，我们可以将此任务移动到 Done 列：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ae1e16d3-ee5c-4476-b31a-59a191e05af7.png)Waffle.io 看板状态

# 摘要

恭喜，在本章中，您创建了您的第一个具有灵活架构的 Angular 应用，同时避免了过度工程化。这是可能的，因为我们首先制定了一个路线图，并将其编码在一个可见于您的同行和同事的看板中。我们专注于实施我们正在进行中的第一个功能，并且没有偏离计划。

您现在可以使用 Angular CLI 和优化的 VS Code 开发环境来帮助您减少需要编写的代码量。您可以利用 TypeScript 匿名类型和可观察流来准确地将复杂的 API 数据重塑为简单的格式，而无需创建一次性接口。

您学会了通过主动声明函数的输入和返回类型以及使用通用函数来避免编码错误。您使用日期和小数管道来确保数据按预期格式化，同时将与格式相关的问题大部分放在模板中，这种逻辑属于模板。

最后，您使用接口在组件和服务之间进行通信，而不会将外部数据结构泄漏到内部组件。通过结合应用所有这些技术，Angular、RxJS 和 TypeScript 允许我们做到这一点，您已经确保了关注点的正确分离和封装。因此，`CurrentWeather`组件现在是一个真正可重用和可组合的组件；这并不是一件容易的事情。

如果您没有发布它，那就从未发生过。在下一章中，我们将通过解决应用程序错误、确保自动化单元测试和端到端测试通过，并使用 Docker 将 Angular 应用程序容器化，以便可以在网络上发布。


# 第三章：为生产发布准备 Angular 应用程序

如果你不发布它，它就没有发生过。在上一章中，您创建了一个可以检索当前天气数据的本地天气应用程序。您已经创造了一定价值；但是，如果您不将应用程序放在网络上，最终您将创造零价值。交付某物是困难的，将某物交付到生产中更加困难。您希望遵循一种能够产生可靠、高质量和灵活发布的策略。

我们在第二章中创建的应用程序，*创建一个本地天气 Web 应用程序*，是脆弱的，有失败的单元和端到端（e2e）测试，并且会发出控制台错误。我们需要修复单元测试并通过有意引入错误来加固应用程序，以便您可以使用调试工具看到真实条件的副作用。我们还需要能够单独交付前端应用程序和后端应用程序，这是保持能够推送单独的应用程序和服务器更新的灵活性非常重要的解耦。此外，解耦将确保随着应用程序堆栈中的各种工具和技术不可避免地不再受支持或受青睐，您将能够替换前端或后端，而无需完全重写系统。

在本章中，您将学会以下内容：

+   运行 Angular 单元和 e2e

+   使用 Chrome 开发者工具排除常见的 Angular 错误

+   防止空数据

+   使用 Docker 将应用程序容器化

+   使用 Zeit Now 将应用程序部署到网络上

所需软件如下所示：

+   Docker 社区版 17.12 版本

+   Zeit Now 账户

# Angular 单元测试

仅仅因为您的 Angular 应用程序使用`npm start`启动并且似乎工作正常，并不意味着它没有错误或准备好投入生产。如前面在第二章中所述，Angular CLI 在创建新组件和服务时会创建一个单元测试文件，例如`current-weather.component.spec.ts`和`weather.service.spec.ts`。

在最基本的层面上，这些默认单元测试确保您的新组件和服务可以在测试中正确实例化。看一下以下规范文件，并观察`should create`测试。该框架断言`CurrentWeatherComponent`类型的组件不是 null 或 undefined，而是真实的。

```ts
src/app/current-weather/current-weather.component.spec.ts
describe('CurrentWeatherComponent', () => {
  let component: CurrentWeatherComponent
  let fixture: ComponentFixture<CurrentWeatherComponent>

  beforeEach(
    async(() => {
      TestBed.configureTestingModule({
        declarations: [CurrentWeatherComponent],
      }).compileComponents()
    })
  )

  beforeEach(() => {
    fixture = TestBed.createComponent(CurrentWeatherComponent)
    component = fixture.componentInstance
    fixture.detectChanges()
  })

  it('should create', () => {
    expect(component).toBeTruthy()
  })
})
```

`WeatherService`规范包含了类似的测试。但是，您会注意到这两种类型的测试设置略有不同：

```ts
src/app/weather/weather.service.spec.ts
describe('WeatherService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [WeatherService],
    })
  })

  it('should be created', inject([WeatherService], (service: WeatherService) => {
      expect(service).toBeTruthy()
    })
  )
})
```

在`WeatherService`规范的`beforeEach`函数中，正在将要测试的类配置为提供者，然后注入到测试中。另一方面，`CurrentWeatherComponent`规范有两个`beforeEach`函数。第一个`beforeEach`函数异步声明和编译了组件的依赖模块，而第二个`beforeEach`函数创建了一个测试装置，并开始监听组件的变化，一旦编译完成就准备运行测试。

# 单元测试执行

Angular CLI 使用 Jasmine 单元测试库来定义单元测试，并使用 Karma 测试运行器来执行它们。最好的是，这些测试工具已经配置好可以直接运行。您可以使用以下命令执行单元测试：

```ts
$ npm test
```

测试将由 Karma 测试运行器在新的 Chrome 浏览器窗口中运行。Karma 的主要优点是它带来了类似于 Angular CLI 在开发应用程序时使用 WebPack 实现的实时重新加载功能。您应该观察终端上的最后一条消息为 Executed 5 of 5 (5 FAILED) ERROR。这是正常的，因为我们根本没有注意测试，所以让我们修复它们。

保持 Karma Runner 窗口与 VS Code 并排打开，这样您可以立即看到您的更改结果。

# 声明

AppComponent 应该创建应用程序测试失败。如果您观察错误详情，您会发现`AppComponent`无法创建，因为'app-current-weather'不是一个已知的元素。此外，如果指出错误，错误会出现一个[ERROR ->]标签，最后一行为我们解释了事情，类似于 AppComponent.html 中的第 6 行出现的错误。

在`app.component.spec.ts`的声明中包括`CurrentWeatherComponent`：

```ts
src/app/app.component.spec.ts
...
TestBed.configureTestingModule({
  declarations: [AppComponent, CurrentWeatherComponent],
}).compileComponents()
...
```

# 提供者

您会注意到错误数量并没有减少。相反，`AppComponent`和`CurrentWeatherComponent`由于缺少`WeatherService`的提供者而无法创建。因此，让我们在这两个组件的规范文件中为`WeatherService`添加提供者。

1.  在`app.component.spec.ts`的声明中提供`WeatherService`。

1.  在`current-weather.component.spec.ts`中应用相同的代码更改，如下所示：

```ts
src/app/app.component.spec.ts
src/app/current-weather/current-weather.component.spec.ts ...  beforeEach(    async(() => { TestBed.configureTestingModule({
        declarations: [...],
        providers: [WeatherService],
        ...
```

你可能会想知道为什么`AppComponent`需要一个提供程序，因为组件构造函数没有注入`WeatherService`。这是因为`CurrentWeatherComponent`是`AppComponent`的硬编码依赖项。可以通过两种方式进一步解耦这两个组件：一种方式是使用`ng-container`动态注入组件，另一种方式是利用 Angular Router 和`router-outlet`。后一种选项是你将会在大多数应用程序中使用的结构方式，并且将在后面的章节中进行介绍，而实现前一种选项以正确解耦组件则留给读者作为练习。

# 导入

你仍然有剩余的错误。让我们首先修复`WeatherService`的错误，因为它是其他组件的依赖项。测试报告了一个缺少`HttpClient`提供程序的错误。然而，我们不希望我们的单元测试进行 HTTP 调用，所以我们不应该提供`HttpClient`，就像我们在上一节中所做的那样。Angular 为`HttpClient`提供了一个名为`HttpClientTestingModule`的测试替身。为了利用它，你必须导入它，然后它将自动为你提供给服务。

在提供程序下方导入`HttpClientTestingModule`。

```ts
**src/app/weather/weather.service.spec.ts** import { HttpClientTestingModule } from '@angular/common/http/testing' 
...
describe('WeatherService', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
        imports: [HttpClientTestingModule],
        ... 
```

类似于`HttpClientTestingModule`，还有一个`RouterTestingModule`和一个`NoopAnimationsModule`，它们是真实服务的模拟版本，因此单元测试可以专注于测试你编写的组件或服务代码。在后面的章节中，我们还将介绍如何编写自己的模拟。

现在你应该只看到与`AppComponent`和`CurrentWeatherComponent`相关的错误。即使你已经提供了它们的依赖项，这些组件也失败了。要理解为什么会发生这种情况以及如何解决它，你还必须了解如何使用测试替身。

# 测试替身

只有在受测试的类中的代码应该被执行。在`CurrentWeatherComponent`的情况下，我们需要确保服务代码不被执行。因此，你*永远*不应该提供服务的实际实现。这也是我们在上一节中使用`HttpClientTestingModule`的原因。由于这是我们的自定义服务，我们必须提供我们自己的测试替身的实现。

在这种情况下，我们将实现一个服务的虚假。由于`WeatherService`的虚假将用于多个组件的测试，您的实现应该在一个单独的文件中。为了保持代码库的可维护性和可发现性，一个文件一个类是一个很好的遵循的原则。将类放在单独的文件中将使您免受某些编码罪的困扰，比如错误地在两个类之间创建或共享全局状态或独立函数，从而在此过程中保持代码适当地解耦：

1.  创建一个新文件`weather/weather.service.fake.ts`

我们需要确保实际实现和测试替身的 API 不会随着时间而不同步。我们可以通过为服务创建一个接口来实现这一点。

1.  如下所示，将`IWeatherService`添加到`weather.service.ts`中：

```ts
src/app/weather/weather.service.ts
export interface IWeatherService {
  getCurrentWeather(city: string, country: string): Observable<ICurrentWeather>
}
```

1.  更新`WeatherService`以实现新接口：

```ts
src/app/weather/weather.service.ts
export class WeatherService implements IWeatherService
```

1.  在`weather.service.fake.ts`中实现一个基本的虚假。

```ts
src/app/weather/weather.service.fake.ts
import { Observable, of } from 'rxjs'

import { IWeatherService } from './weather.service'
import { ICurrentWeather } from '../interfaces'

export class WeatherServiceFake implements IWeatherService {
  private fakeWeather: ICurrentWeather = {
    city: 'Bursa',
    country: 'TR',
    date: 1485789600,
    image: '',
    temperature: 280.32,
    description: 'light intensity drizzle',
  }

```

```ts
  public getCurrentWeather(city: string, country: string): Observable<ICurrentWeather> {
    return of(this.fakeWeather)
  }
}
```

我们正在利用现有的`ICurrentWeather`接口，以确保我们的虚假数据正确地构建，但我们还必须将其转换为`Observable`。这很容易通过使用`of`来实现，它会根据提供的参数创建一个可观察序列。

现在您已经准备好为`AppComponent`和`CurrentWeatherComponent`提供虚假。

1.  更新两个组件的提供者以使用`WeatherServiceFake`

以便虚假将被用于实际服务的替代品：

```ts
src/app/app.component.spec.ts
src/app/current-weather/current-weather.component.spec.ts
  ...
  beforeEach(
    async(() => {
      TestBed.configureTestingModule({
        ...
        providers: [{ provide: WeatherService, useClass: WeatherServiceFake}],
        ...
```

随着您的服务和组件变得更加复杂，很容易提供一个不完整或不足的测试替身。您可能会看到诸如 NetworkError: Failed to execute 'send' on 'XMLHttpRequest'，Can't resolve all parameters，或[object ErrorEvent] thrown 等错误。在后一种错误的情况下，点击 Karma 中的调试按钮以发现视图错误详情，可能会显示为 Timeout - Async callback was not invoked within timeout specified by jasmine。单元测试设计为在毫秒内运行，因此实际上应该不可能达到默认的 5 秒超时。问题几乎总是出现在测试设置或配置中。

我们已成功解决了所有与单元测试相关的配置和设置问题。现在，我们需要修复使用初始代码生成的单元测试。

# 茉莉花规范

有两个单元测试失败。在 Jasmine 术语中，单元测试称为规范，由`it`函数实现；`it`函数组织在包含可以在每个测试之前或之后执行的辅助方法的`describe`函数下，并处理规范的整体配置需求。您的应用程序为您生成了五个规范，其中两个现在失败了。

第一个是`AppComponent 应该有标题'app'`；但是，我们从`AppComponent`中删除了这个属性，因为我们没有在使用它。在这种罕见情况下，我们需要这样做：

1.  删除`应该有标题'app'`单元测试。

错误消息足够描述性，可以让您快速了解哪个测试失败了。这是因为提供给`describe`函数的描述是'AppComponent'，而提供给`it`函数的描述是'应该有标题'app''。Jasmine 然后将任何父对象的描述附加到规范的描述中。当您编写新的测试时，您需要维护规范的可读描述。

接下来的错误，`AppComponent 应该在 h1 标签中呈现标题`，是我们必须修复的一个错误。我们现在在`h1`标签中呈现`LocalCast Weather`这几个词。

1.  更新`应该在 h1 标签中呈现标题`测试如下所示：

```ts
src/app/app.component.spec.ts ...it(  'should render title in a h1 tag',
    ...
    expect(compiled.querySelector('h1').textContent).toContain('LocalCast Weather')
    ... 
```

所有单元测试现在都成功通过了。我们应该执行原子提交，所以让我们提交代码更改。

1.  提交您的代码更改。

为了实现有效的单元测试覆盖率，您应该专注于测试包含业务逻辑的函数的正确性。这意味着您应该特别注意遵守单一职责和开闭原则，即 SOLID 原则中的 S 和 O。

# Angular e2e 测试

除了单元测试外，Angular CLI 还为您的应用程序生成和配置 e2e 测试。虽然单元测试侧重于隔离被测试的类，e2e 测试则是关于集成测试。Angular CLI 利用 Protractor 和 WebDriver，因此您可以从用户在浏览器上与您的应用程序交互的角度编写**自动接受测试**（**AAT**）。根据经验，您应该始终编写比 AAT 多一个数量级的单元测试，因为您的应用程序经常发生变化，因此与单元测试相比，AAT 更加脆弱且昂贵。

如果术语 Web 驱动程序听起来很熟悉，那是因为它是经典的 Selenium WebDriver 的演变。截至 2017 年 3 月 30 日，WebDriver 已被提议为 W3C 的官方 Web 标准。您可以在[`www.w3.org/TR/webdriver`](https://www.w3.org/TR/webdriver)上阅读更多关于它的信息。如果您之前熟悉 Selenium，您会感到宾至如归，因为许多模式和实践几乎是相同的。

CLI 为初始的`AppComponent`提供了 e2e 测试，根据应用程序的复杂性和功能集，您可以遵循提供的模式来更好地组织您的测试。在`e2e`文件夹下为每个组件生成两个文件：

```ts
e2e/app.e2e-spec.ts
import { AppPage } from './app.po'

describe('web-app App', () => {
  let page: AppPage

  beforeEach(() => {
    page = new AppPage()
  })

  it('should display welcome message', () => {
    page.navigateTo()
    expect(page.getParagraphText()).toEqual('Welcome to app!')
  })
})
```

`app.e2e-spec.ts`是用 Jasmine 编写的，实现了验收测试。该规范依赖于页面对象（`po`）文件，该文件定义在`spec`文件旁边：

```ts
e2e/app.po.ts
import { browser, by, element } from 'protractor'

export class AppPage {
  navigateTo() {
    return browser.get('/')
  }

  getParagraphText() {
    return element(by.css('app-root h1')).getText()
  }
}
```

页面对象文件封装了来自`spec`文件的 Web 驱动程序实现细节。 AATs 是最。这导致了易于维护、人类可读的规范文件。通过在这个级别分离关注点，您可以将 AAT 的脆弱性隔离到一个位置。通过利用类继承，您可以构建一个强大的页面对象集合，随着时间的推移更容易维护。

# e2e 测试执行

您可以在终端中使用以下命令执行 e2e 测试；确保`npm test`进程没有在运行：

```ts
$ npm run e2e
```

您会注意到测试执行与单元测试不同。虽然您可以配置一个观察者来不断执行 Karma 的单元测试，但由于 e2e 测试的用户驱动和有状态的特性，尝试使用类似的配置来执行 e2e 测试并不是一个好的做法。运行测试一次并停止测试工具确保每次运行都有一个干净的状态。

# e2e 规范

执行 e2e 测试后，您应该会看到类似于这里的错误消息：

```ts
**************************************************
* Failures *
**************************************************

1) web-app App should display welcome message
 - Expected 'LocalCast Weather' to equal 'Welcome to app!'.

Executed 1 of 1 spec (1 FAILED) in 1 sec.
```

这个错误类似于您之前修复的单元测试：

1.  更新`spec`以期望正确的标题如下：

```ts
e2e/app.e2e-spec.ts expect(page.getParagraphText()).toEqual('LocalCast Weather')
```

1.  重新运行测试，现在应该通过了：

```ts
Jasmine started

 web-app App
 √ should display welcome message

Executed 1 of 1 spec SUCCESS in 1 sec.
```

1.  提交您的代码更改。

# 排除常见的 Angular 错误

我们的单元测试和 e2e 测试现在正在运行。在这一部分，您有意引入一个容易犯的错误，以便您可以熟悉在开发应用程序时可能发生的真实错误，并对使您成为一名有效的开发人员的工具有扎实的理解。

在 macOS 上按*option* + ⌘ + *I*，或在 Windows 上按*F12*或*Ctrl* + *Shift* + *I*打开 Chrome 开发者工具（dev tools）。

```ts
src/app/weather/weather.service.ts
...
return this.httpClient
  .get<ICurrentWeatherData>(
    `api.openweathermap.org/data/2.5/weather?q=${city},${country}&appid=${environment.appId}`
  ).pipe(map(data => this.transformToICurrentWeather(data)))
...
```

你的应用将成功编译，但当你在浏览器中检查结果时，你不会看到任何天气数据。事实上，就像你在下面的图片中看到的那样，`CurrentWeather`组件似乎根本没有渲染：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/8abe7631-fffb-459f-a67a-48885508448b.png)带有实时重新加载的并排开发

要找出原因，你需要调试你的 Angular 应用。

# 使用 Chrome 开发者工具进行调试

作为开发人员，我使用谷歌 Chrome 浏览器，因为它具有跨平台和一致的开发者工具，还有有用的扩展。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/702cc572-cc9a-42c5-9635-facae5ecfac5.png)CurrentWeather 未渲染

作为最佳实践，我会在 VS Code 和浏览器并排编码，同时在浏览器中也打开开发工具。有几个很好的理由来练习并排开发：

+   **快速反馈循环**：通过实时重新加载，你可以很快看到你的更改的最终结果

+   **笔记本电脑**：现在很多开发人员大部分时间都在笔记本电脑上进行开发，而第二个显示器是一种奢侈。

+   注意响应式设计：由于我有限的空间可用，我不断关注移动优先开发，在事后修复桌面布局问题。观察一下并排开发是什么样子的：

+   **网络活动意识**：为了让我能够快速看到任何 API 调用错误，并确保请求的数据量保持在我的预期范围内

+   **控制台错误意识**：为了让我能够在引入新错误时快速做出反应和解决问题

假设我们在从`OpenWeatherMap.org`的 API 文档页面复制和粘贴 URL 时犯了一个无心的错误，并忘记在其前面添加`http://`。这是一个容易犯的错误：

最终，你应该做最适合你的事情。通过并排设置，我经常发现自己在打开和关闭 VS Code 的资源管理器，并根据手头的具体任务调整开发工具窗格的大小。要切换 VS Code 的资源管理器，请点击前面截图中圈出的资源管理器图标。

就像你可以使用`npm start`进行带有实时重新加载的并排开发一样，你也可以使用`npm test`进行单元测试，获得同样类型的快速反馈循环。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a7785cea-8818-426c-b393-7979d7c13f67.png)并排开发与单元测试

通过并排的单元测试设置，你可以在开发单元测试方面变得非常有效。

# 优化 Chrome 开发工具

为了使并排开发和实时重新加载正常工作，你需要优化默认的开发工具体验。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/75d088f6-c4a3-481d-ad5d-ceb75fc7c11b.png)优化的 Chrome 开发者工具

从前面的图中可以看出，有很多设置和信息显示器被突出显示：

1.  默认打开网络选项卡，这样你就可以看到网络流量的流动。

1.  点击![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0934097c-46b9-40a7-a157-d5685f22e518.png)按钮打开开发工具设置。

1.  点击右侧图标，使开发工具停靠在 Chrome 的右侧。这种布局可以提供更多的垂直空间，这样你就可以一次看到更多的网络流量和控制台事件。作为一个附带的好处，左侧的布局接近移动设备的大小和形状。

1.  切换到大请求行，并关闭概览，以便查看每个请求的 URL 和参数，并获得更多的垂直空间。

1.  勾选禁用缓存选项，这样当你在打开开发工具的情况下刷新页面时，将强制重新加载每个资源。这可以防止奇怪的缓存错误影响你的工作。

1.  你主要会对各种 API 的 XHR 调用感兴趣，所以点击 XHR 来过滤结果。

1.  请注意，你可以在右上角看到控制台错误的数量为 12。理想情况下，控制台错误的数量应该始终为 0。

1.  请注意，请求行中的顶部项目表明状态码为 404 未找到的错误。

1.  由于我们正在调试一个 Angular 应用程序，Augury 扩展已经加载。我将在第七章中更详细地介绍这个工具，*创建一个更复杂的应用程序时，你将会构建一个更复杂的应用程序。

有了优化的开发工具环境，你现在可以有效地排除之前的应用程序错误。

# 故障排除网络问题

在这个状态下，应用程序有三个可见的问题：

+   组件详情没有显示

+   有很多控制台错误。

+   API 调用返回 404 未找到错误

首先检查任何网络错误，因为网络错误通常会引起连锁反应：

1.  在网络选项卡中点击失败的 URL

1.  在 URL 右侧打开的详细信息窗格中，点击预览选项卡

1.  您应该看到这个：

```ts
Cannot GET /api.openweathermap.org/data/2.5/weather
```

仅仅观察这个错误消息，您很可能会忽略这样一个事实，即您忘记向 URL 添加`http://`前缀。这个错误很微妙，当然不是非常明显的。

1.  将鼠标悬停在 URL 上，并观察完整的 URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/b91c6120-fedf-41eb-af35-06e479b1bd40.png)检查网络错误

正如您所看到的，现在这个错误非常明显。在这个视图中，我们可以看到完整的 URL，并且清楚地看到`weather.service.ts`中定义的 URL 没有完全合格，因此 Angular 尝试从其父服务器`localhost:5000`上加载资源，而不是通过网络到正确的服务器上。

# 调查控制台错误

在您修复此问题之前，值得了解 API 调用失败的连锁效应：

1.  观察控制台错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/08e5a182-5e45-4fc3-8867-87745b5daf94.png)开发工具控制台错误上下文

这里需要注意的第一个元素是`ERROR CONTEXT`对象，它有一个名为`DebugContext_`的属性。`DebugContext_`包含了发生错误时您的 Angular 应用程序的当前状态的详细快照。`DebugContext_`中包含的信息远远超过了 AngularJS 生成的大部分不太有用的错误消息。

值为(...)的属性是属性获取器，您必须点击它们以加载其详细信息。例如，如果您点击 componentRenderElement 的省略号，它将被填充为 app-current-weather 元素。您可以展开该元素以检查组件的运行时条件。

1.  现在滚动到控制台的顶部

1.  观察第一个错误：

```ts
ERROR TypeError: Cannot read property 'city' of undefined
```

您可能之前遇到过`TypeError`。这个错误是由于尝试访问未定义对象的属性而引起的。在这种情况下，`CurrentWeatherComponent.current`没有分配给一个对象，因为 http 调用失败了。由于`current`没有初始化，模板盲目地尝试绑定其属性，比如`{{current.city}}`，我们会得到一个消息，说无法读取未定义的属性'city'。这是一种连锁反应，可能会在您的应用程序中产生许多不可预测的副作用。您必须积极编码以防止这种情况发生。

# Karma、Jasmine 和单元测试错误

当使用`ng test`命令运行测试时，你可能会遇到一些高级错误，这些错误可能掩盖了实际潜在错误的根本原因。

解决错误的一般方法应该是从内而外，首先解决子组件的问题，最后解决父组件和根组件的问题。

# 网络错误

网络错误可能是由多种潜在问题引起的：

```ts
NetworkError: Failed to execute 'send' on 'XMLHttpRequest': Failed to load 'ng:///DynamicTestModule/AppComponent.ngfactory.js'.
```

从内而外地工作，你应该实现服务的测试替身，并将伪造的东西提供给适当的组件，就像前一节所介绍的那样。然而，在父组件中，即使你正确地提供了伪造的东西，你可能仍然会遇到错误。请参考处理通用错误事件的部分，以揭示潜在的问题。

# 通用错误事件

错误事件是隐藏潜在原因的通用错误：

```ts
[object ErrorEvent] thrown
```

为了暴露通用错误的根本原因，实现一个新的`test:debug`脚本：

1.  在`package.json`中实现如下所示的`test:debug`：

```ts
package.json
...
"scripts": {
  ...
  "test:debug": "ng test --sourcemaps=false",
  ...
}
```

1.  执行`npm run test:debug`

1.  现在 Karma 运行器可能会揭示潜在的问题

1.  如果有必要，跟踪堆栈以找到可能导致问题的子组件

如果这种策略不起作用，你可以通过断点调试单元测试来获取更多关于出错原因的信息。

# 使用 Visual Studio Code 进行调试

你还可以直接在 Visual Studio Code 中调试你的 Angular 应用程序、Karma 和 Protractor 测试。首先，你需要配置调试器以与 Chrome 调试环境配合工作，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7da64ae5-7684-4230-a1e8-55bb8cb009c0.png)VS Code 调试设置

1.  点击调试窗格

1.  展开“无配置”下拉菜单，然后点击“添加配置...”

1.  在“选择环境”选择框中，选择 Chrome

这将在`.vscode/launch.json`文件中创建一个默认配置。我们将修改这个文件以添加三个单独的配置。

1.  用以下配置替换`launch.json`的内容：

```ts
.vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "npm start",
      "type": "chrome",
      "request": "launch",
      "url": "http://localhost:5000/#",
      "webRoot": "${workspaceRoot}",
      "runtimeArgs": [
        "--remote-debugging-port=9222"
        ],
      "sourceMaps": true
    },
    {
      "name": "npm test",
      "type": "chrome",
      "request": "launch",
      "url": "http://localhost:9876/debug.html",
      "webRoot": "${workspaceRoot}",
      "runtimeArgs": [
        "--remote-debugging-port=9222"
        ],
      "sourceMaps": true
    },
    {
      "name": "npm run e2e",
      "type": "node",
      "request": "launch",
      "program": "${workspaceRoot}/node_modules/protractor/bin/protractor",
      "protocol": "inspector",
      "args": ["${workspaceRoot}/protractor.conf.js"]
    }
  ]
}
```

1.  在开始调试之前，执行相关的 CLI 命令，如`npm start`、`npm test`或`npm run e2e`

1.  在调试页面上，在调试下拉菜单中，选择 npm start，然后点击绿色播放图标

1.  观察 Chrome 实例是否已启动

1.  在`.ts`文件上设置断点

1.  执行应用程序中的操作以触发断点

1.  如果一切顺利，Chrome 将报告代码已在 Visual Studio Code 中暂停

在发布时，这种调试方法并不总是可靠的。我不得不在 Chrome Dev Tools | Sources 标签中手动设置断点，在`webpack://.`文件夹下找到相同的`.ts`文件，这样才能正确地触发 VS Code 中的断点。然而，这使得使用 VS Code 调试代码的整个好处变得毫无意义。有关更多信息，请在 GitHub 上查看 Angular CLI 部分关于 VS Code Recipes 的内容：[`github.com/Microsoft/vscode-recipes`](https://github.com/Microsoft/vscode-recipes)。

# 在 Angular 中进行 null 防范

在 JavaScript 中，`undefined`和`null`值是一个持久性问题，必须在每一步积极地处理。在 Angular 中，有多种方法可以防范`null`值：

1.  属性初始化

1.  安全导航操作符`?.`

1.  使用`*ngIf`进行 null 防范

# 属性初始化

在诸如 Java 这样的静态类型语言中，你被灌输了正确的变量初始化/实例化是无错误操作的关键。所以让我们在`CurrentWeatherComponent`中尝试通过使用默认值来初始化当前值：

```ts
src/app/current-weather/current-weather.component.ts
constructor(private weatherService: WeatherService) {
  this.current = {
    city: '',
    country: '',
    date: 0,
    image: '',
    temperature: 0,
    description: '',
  }
}
```

这些更改的结果将把控制台错误从 12 个减少到 3 个，此时您只会看到与 API 调用相关的错误。然而，应用本身仍然不是一个可以展示的状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0b7f8993-abf1-455f-aeaf-9af5a22498e2.png)

属性初始化的结果

为了使这个视图对用户可见，我们必须在模板的每个属性上编写默认值的代码。因此，通过初始化来修复 null 防范问题，我们创建了一个默认值处理问题。对于开发人员来说，初始化和默认值处理都是*O(n)*规模的任务。在最好的情况下，这种策略将是烦人的实施，在最坏的情况下，高度无效且容易出错，每个属性至少需要*O(2n)*的工作量。

# 安全导航操作符

Angular 实现了安全导航操作`?.`来防止对未定义对象的意外遍历。因此，我们只需更新模板，而不是编写初始化代码并处理模板值：

```ts
src/app/current-weather/current-weather.component.html
<div>
  <div>
    <span>{{current?.city}}, {{current?.country}}</span>
    <span>{{current?.date | date:'fullDate'}}</span>
  </div>
  <div>
    <img [src]='current?.image'>
    <span>{{current?.temperature}}℉</span>
  </div>
  <div>
    {{current?.description}}
  </div>
</div>
```

这一次，我们不必自己设置默认值，让 Angular 处理显示未定义的绑定。您会注意到，就像初始化修复一样，错误数量已经从 12 个减少到 3 个。应用本身的状态有所改善。不再显示混乱的数据；然而，它仍然不是一个可以展示的状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/47b9f913-c1ae-4553-bdc4-87ace908cfa1.png)安全导航操作符的结果

你可能可以想象在更复杂的场景中安全导航操作符可以派上用场的方式。然而，当大规模部署时，这种类型的编码仍然需要至少*O(n)*级别的工作量来实现。

# 使用*ngIf 进行空值保护

理想的策略是使用`*ngIf`，这是一个结构指令，意味着 Angular 将在假语句之后停止遍历 DOM 树元素。

在`CurrentWeather`组件中，我们可以在尝试渲染模板之前轻松检查`current`变量是否为 null 或未定义：

1.  更新顶层的`div`元素，使用`*ngIf`来检查`current`是否是一个对象，如下所示：

```ts
src/app/current-weather/current-weather.component.html <div *ngIf="current">
  ...
</div>
```

现在观察控制台日志，没有报告任何错误。你始终要确保你的 Angular 应用程序报告零控制台错误。如果你仍然在控制台日志中看到错误，请确保你已经正确恢复了`OpenWeather`的 URL 到正确的状态，或者终止并重新启动你的`npm start`进程。我强烈建议在继续之前解决任何控制台错误。一旦你修复了所有错误，确保你再次提交你的代码。

1.  提交你的代码。

# 使用 Docker 对应用进行容器化

Docker [docker.io](http://docker.io) 是一个用于开发、发布和运行应用程序的开放平台。Docker 结合了一个轻量级的容器虚拟化平台和工作流程以及工具，帮助管理和部署应用程序。虚拟机（VMs）和 Docker 容器之间最明显的区别是，VMs 通常有数十 GB 的大小，需要数 GB 的内存，而容器在磁盘和内存大小方面只有几 MB 的要求。此外，Docker 平台抽象了主机操作系统级别的配置设置，因此成功运行应用程序所需的每一部分配置都编码在人类可读的 Dockerfile 格式中，如下所示：

```ts
**Dockerfile**
FROM duluca/minimal-node-web-server:8.11.1 WORKDIR /usr/src/app COPY dist public
```

前面的文件描述了一个新的容器，该容器继承自一个名为`duluca/minimal-node-web-server`的容器，将工作目录更改为`/usr/src/app`，然后将开发环境中`dist`文件夹的内容复制到容器的`public`文件夹中。在这种情况下，父镜像配置了一个 Express.js 服务器，充当 web 服务器，以提供`public`文件夹中的内容。请参考以下图表，以了解正在发生的情况的可视化表示：

Docker 镜像的上下文

在基础层是我们的主机操作系统，比如 Windows 或 macOS，它运行 Docker 运行时，将在下一节中安装。Docker 运行时能够运行自包含的 Docker 镜像，这是由上述的`Dockerfile`定义的。`duluca/minimal-node-web-server`基于轻量级的 Linux 操作系统 Alpine。Alpine 是 Linux 的一个完全精简版本，不带有任何图形界面，驱动程序，甚至大多数你可能期望从 Linux 系统中得到的 CLI 工具。因此，这个操作系统的大小只有大约 5MB。基础软件包然后安装了 Node.js，Node.js 本身的大小约为 10MB，以及我定制的基于 Node.js 的 Express.js web 服务器，结果是一个微小的约 15MB 的镜像。Express 服务器被配置为提供`/usr/src/app`文件夹的内容。在前面的`Dockerfile`中，我们只是将开发环境中`/dist`文件夹的内容复制到`/usr/src/app`文件夹中。我们稍后将构建并执行这个镜像，这将运行我们的 Express web 服务器，其中包含我们`dist`文件夹的输出。

Docker 的美妙之处在于你可以导航到[`hub.docker.com`](https://hub.docker.com)，搜索`duluca/minimal-node-web-server`，阅读它的`Dockerfile`，并追溯其源头直到作为 web 服务器基础的原始基础镜像。我鼓励你以这种方式审查你使用的每个 Docker 镜像，以了解它对你的需求到底带来了什么。你可能会发现它要么过度复杂，要么有你以前不知道的功能，可以让你的生活变得更加轻松。请注意，父镜像需要特定版本的`duluca/minimal-node-web-server`，为`8.11.1`。这是非常有意义的，作为读者，你应该选择你找到的 Docker 镜像的最新可用版本。然而，如果你不指定版本号，你将始终获得镜像的最新版本。随着镜像的发布更多版本，你可能会拉取一个未来版本，可能会破坏你的应用程序。因此，对于你依赖的镜像，总是指定一个版本号。

一个这样的案例是`duluca/minimal-node-web-server`中内置的 HTTPS 重定向支持。当你只需要在你的 Dockerfile 中添加以下行时，你可以花费无数小时尝试设置一个 nginx 代理来做同样的事情：

```ts
ENV ENFORCE_HTTPS=xProto
```

就像 npm 包一样，Docker 可以带来巨大的便利和价值，但你必须小心地理解你正在使用的工具。

在第十一章中，*AWS 上高可用云基础设施*，我提到了基于 Nginx 的低占用的 docker 镜像的使用。如果你熟悉配置`nginx`，你可以使用`duluca/minimal-nginx-web-server`作为你的基础镜像。

# 安装 Docker

为了能够构建和运行容器，你必须首先在你的计算机上安装 Docker 执行环境。

Windows 对 Docker 的支持可能具有挑战性。你必须拥有一个支持虚拟化扩展的 CPU 的 PC，这在笔记本电脑上并不是一定的。你还必须拥有启用了 Hyper-V 的 Windows 专业版。另一方面，Windows Server 2016 原生支持 Docker，这是微软向行业采用 Docker 和容器化倡议所表现出的前所未有的支持量。

1.  通过执行以下命令安装 Docker：

对于 Windows：

```ts
**PS> choco install docker docker-for-windows -y** 
```

对于 macOS：

```ts
$ brew install docker
```

1.  执行`docker -v`来验证安装。

# 设置 Docker 脚本

现在，让我们配置一些 Docker 脚本，您可以使用这些脚本来自动构建，测试和发布您的容器。我开发了一组名为**npm Scripts for Docker**的脚本，适用于 Windows 10 和 macOS。您可以在[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)获取这些脚本的最新版本：

1.  在[`hub.docker.com/`](https://hub.docker.com/)上注册 Docker Hub 帐户

1.  为您的应用程序创建一个公共（免费）存储库

不幸的是，在发布时，Zeit 不支持私有 Docker Hub 存储库，因此您的唯一选择是公开发布您的容器。如果您的图像必须保持私有，我建议您按照第十一章中描述的在 AWS ECS 环境中设置的方法进行操作，*在 AWS 上构建高可用云基础设施*。您可以通过访问 Zeit Now 的文档[zeit.co/docs/deployment-types/docker](https://zeit.co/docs/deployment-types/docker)来了解问题的最新情况。

1.  更新`package.json`以添加一个新的配置属性，具有以下配置属性：

```ts
package.json
  ...
  "config": {
    "imageRepo": "[namespace]/[repository]",
    "imageName": "custom_app_name",
    "imagePort": "0000"
  },
 ...
```

命名空间将是您的 DockerHub 用户名。您将在创建过程中定义您的存储库的名称。示例图像存储库变量应如`duluca/localcast-weather`。图像名称用于轻松识别您的容器，同时使用 Docker 命令，如`docker ps`。我将只称之为`localcast-weather`。端口将定义应从容器内部使用哪个端口来公开您的应用程序。由于我们在开发中使用`5000`，请选择另一个端口，如`8080`。

1.  通过从[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)复制粘贴脚本将 Docker 脚本添加到`package.json`。以下是脚本的注释版本，解释了每个功能。

请注意，使用 npm 脚本时，`pre`和`post`关键字分别用于在给定脚本的执行之前或之后执行辅助脚本，并且脚本故意分成较小的部分，以便更容易阅读和维护它们：

```ts
package.json
...
  "scripts": {
    ...
    "predocker:build": "npm run build",
    "docker:build": "cross-conf-env docker image build . -t $npm_package_config_imageRepo:$npm_package_version",
    "postdocker:build": "npm run docker:tag",
    ...
```

`npm run docker:build`将在`pre`中构建您的 Angular 应用程序，然后使用`docker image build`命令构建 Docker 镜像，并在`post`中为图像打上版本号：

```ts
package.json
    ...
    "docker:tag": " cross-conf-env docker image tag $npm_package_config_imageRepo:$npm_package_version $npm_package_config_imageRepo:latest",
    ...
```

`npm run docker:tag`将使用`package.json`中的`version`属性的版本号和`latest`标签标记已构建的 Docker 镜像：

```ts
package.json
    ...
    "docker:run": "run-s -c docker:clean docker:runHelper",
    "docker:runHelper": "cross-conf-env docker run -e NODE_ENV=local --name $npm_package_config_imageName -d -p $npm_package_config_imagePort:3000 $npm_package_config_imageRepo",
    ...
```

`npm run docker:run`将删除任何现有的先前版本的镜像，并使用`docker run`命令运行已构建的镜像。请注意，`imagePort`属性用作 Docker 镜像的外部端口，该端口映射到 Node.js 服务器监听的图像的内部端口`3000`：

```ts
package.json
    ...
    "predocker:publish": "echo Attention! Ensure `docker login` is correct.",
    "docker:publish": "cross-conf-env docker image push $npm_package_config_imageRepo:$npm_package_version",
    "postdocker:publish": "cross-conf-env docker image push $npm_package_config_imageRepo:latest",
    ...
```

`npm run docker:publish`将使用`docker image push`命令将构建的镜像发布到配置的存储库，本例中为 Docker Hub。首先发布带版本标签的镜像，然后发布带`latest`标签的镜像。

```ts
package.json
    ...
    "docker:clean": "cross-conf-env docker rm -f $npm_package_config_imageName",
    ...
```

`npm run docker:clean`将使用`docker rm -f`命令从系统中删除先前构建的镜像：

```ts
package.json
    ...
    "docker:taillogs": "cross-conf-env docker logs -f $npm_package_config_imageName",
    ...
```

运行`npm run docker:taillogs`将使用`docker log -f`命令显示正在运行的 Docker 实例的内部控制台日志，这是在调试 Docker 实例时非常有用的工具：

```ts
package.json
    ...
    "docker:open:win": "echo Trying to launch on Windows && timeout 2 && start http://localhost:%npm_package_config_imagePort%",
    "docker:open:mac": "echo Trying to launch on MacOS && sleep 2 && URL=http://localhost:$npm_package_config_imagePort && open $URL",
    ...
```

`npm run docker:open:win`或`npm run docker:open:mac`将等待 2 秒，然后使用`imagePort`属性以正确的 URL 启动浏览器到您的应用程序：

```ts
package.json
    ...
    "predocker:debug": "run-s docker:build docker:run",
    "docker:debug": "run-s -cs docker:open:win docker:open:mac docker:taillogs"
  },
...
```

`npm run docker:debug`将构建您的镜像并在`pre`中运行一个实例，打开浏览器，然后开始显示容器的内部日志。

1.  安装两个开发依赖项，以确保脚本的跨平台功能：

```ts
$ npm i -D cross-conf-env npm-run-all
```

1.  自定义预构建脚本以在构建图像之前执行单元测试和 e2e 测试：

```ts
package.json
"predocker:build": "npm run build -- --prod --output-path dist && npm test -- --watch=false && npm run e2e",
```

请注意，`npm run build`提供了`--prod`参数，可以实现两个目标：

1. 将约 2.5 MB 的开发时间负载优化为约 73kb 或更少

2. 在`src/environments/environment.prod.ts`中定义的配置项在运行时使用

1.  更新`src/environments/environment.prod.ts`，使用您自己的`OpenWeather`的`appId`：

```ts
export const environment = {
  production: true,
  appId: '01ffxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  baseUrl: 'https://',
}
```

我们正在修改`npm test`的执行方式，以便测试只运行一次，工具停止执行。提供`--watch=false`选项以实现此行为，而不是默认的持续执行行为。此外，`npm run build`提供了`--output-path dist`，以确保`index.html`发布在文件夹的根目录。

1.  创建一个名为`Dockerfile`的新文件，没有文件扩展名

1.  实现`Dockerfile`，如下所示：

```ts
Dockerfile
FROM duluca/minimal-node-web-server:8.11.1
WORKDIR /usr/src/app
COPY dist public
```

确保检查`dist`文件夹的内容。确保`index.html`位于`dist`的根目录。否则，请确保您的`Dockerfile`复制具有`index.html`的文件夹。

1.  执行`npm run predocker:build`以确保您的应用程序更改已成功

1.  执行`npm run docker:build`以确保您的镜像成功构建

虽然您可以单独运行提供的任何脚本，但您实际上只需要记住其中两个：

+   **npm run docker:debug**将在新的浏览器窗口中测试、构建、标记、运行、追踪和启动您的容器化应用程序

+   **npm run docker:publish**将发布您刚刚构建和测试的图像到在线 Docker 存储库

1.  在终端中执行`docker:debug`：

```ts
$ npm run docker:debug
```

您会注意到脚本在终端窗口中显示错误。这些并不一定是失败的指标。脚本并不完善，因此它们会同时尝试 Windows 和 macOS 兼容的脚本，并且在第一次构建时，清理命令会失败，因为没有东西需要清理。在您阅读此文时，我可能已经发布了更好的脚本；如果没有，您可以随时提交拉取请求。

成功的`docker:debug`运行应该会在焦点中打开一个新的浏览器窗口，显示您的应用程序和服务器日志在终端中被追踪，如下所示：

```ts
Current Environment: local.
Server listening on port 3000 inside the container
Attenion: To access server, use http://localhost:EXTERNAL_PORT
EXTERNAL_PORT is specified with 'docker run -p EXTERNAL_PORT:3000'. See 'package.json->imagePort' for th
e default port.
GET / 304 12.402 ms - -
GET /styles.d41d8cd98f00b204e980.bundle.css 304 1.280 ms - -
GET /inline.202587da3544bd761c81.bundle.js 304 11.117 ms - -
GET /polyfills.67d068662b88f84493d2.bundle.js 304 9.269 ms - -
GET /vendor.c0dc0caeb147ad273979.bundle.js 304 2.588 ms - -
GET /main.9e7f6c5fdb72bb69bb94.bundle.js 304 3.712 ms - -
```

您应该始终运行`docker ps`来检查您的镜像是否正在运行，上次更新时间，或者它是否与声称相同端口的现有镜像发生冲突。

1.  在终端中执行`docker:publish`：

```ts
$ npm run docker:publish
```

您应该在终端窗口中观察到成功运行，如下所示：

```ts
The push refers to a repository [docker.io/duluca/localcast-weather]
60f66aaaaa50: Pushed
...
latest: digest: sha256:b680970d76769cf12cc48f37391d8a542fe226b66d9a6f8a7ac81ad77be4f58b size: 2827
```

随着时间的推移，您的本地 Docker 缓存可能会增长到相当大的规模，在我的笔记本电脑上大约是两年 40GB。您可以使用`docker image prune`和`docker container prune`命令来减小缓存的大小。有关更详细的信息，请参阅[`docs.docker.com/config/pruning`](https://docs.docker.com/config/pruning)上的文档。

让我们来看一下与 Docker 互动的更简单的方法。

# VS Code 中的 Docker 扩展

与 Docker 镜像和容器互动的另一种方式是通过 VS Code。如果您已经安装了`PeterJausovec.vscode-docker` Docker 扩展，如第二章*创建本地天气 Web 应用程序*中建议的那样，您将在 VS Code 的资源管理器窗格中看到一个名为 DOCKER 的可展开标题，如下截图中的箭头所指出的那样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/b002db3c-9f9a-4476-b5bb-90c2085ac184.png)VS Code 中的 Docker 扩展

让我们来看一下扩展提供的一些功能：

1.  **镜像**包含系统上存在的所有容器快照的列表

1.  右键单击 Docker 镜像会弹出上下文菜单，可以在其中运行各种操作，如运行、推送和标记

1.  **容器**列出系统上存在的所有可执行 Docker 容器，您可以启动、停止或附加到它们

1.  **注册表**显示您配置连接的注册表，如 DockerHub 或 AWS 弹性容器注册表

虽然该扩展使与 Docker 的交互变得更容易，**npm 脚本用于 Docker**可以自动化与构建、标记和测试镜像相关的许多琐事。它们是跨平台的，并且在持续集成环境中同样有效。

通过 CLI 与 npm 脚本进行交互可能会让您感到困惑。让我们接下来看一下 VS Code 的 npm 脚本支持。

# VS Code 中的 NPM 脚本

VS Code 默认支持 npm 脚本。为了启用 npm 脚本资源管理器，打开 VS Code 设置，并确保存在`"npm.enableScriptExplorer": true`属性。一旦您这样做了，您将在资源管理器窗格中看到一个可展开的标题，名为 NPM SCRIPTS，如下箭头所指：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ce308d57-171d-4d8b-a50f-1d11a1dcb2e9.png)VS Code 中的 NPM 脚本

您可以单击任何脚本来启动包含该脚本的行`package.json`，或者右键单击并选择运行来执行该脚本。

# 部署容器化应用

如果从编码的角度来看，将某些东西交付到生产环境是困难的，那么从基础架构的角度来看，要做到正确更是极其困难。在后面的章节中，我将介绍如何为您的应用程序配置世界一流的 AWS **弹性容器服务**（**ECS**）基础架构，但如果您需要快速展示一个想法，这是无济于事的。现在，Zeit Now 登场了。

# Zeit Now

Zeit Now，[`zeit.co/now`](https://zeit.co/now)，是一个多云服务，可以实现应用程序的实时全球部署，直接从 CLI 进行。Now 可以与正确实现`package.json`或`Dockerfile`的应用程序一起工作。尽管我们两者都做了，但我们更喜欢部署我们的 Docker 镜像，因为在幕后会应用更多的魔法来使`package.json`部署工作，而您的 Docker 镜像可以部署到任何地方，包括 AWS ECS。

# 配置 Now CLI 工具

现在，让我们配置 Zeit Now 来在您的存储库上工作：

1.  通过执行`npm i -g now`来安装 Zeit Now

1.  通过执行`now -v`来确保正确安装

1.  在`local-weather-app`下创建一个名为`now`的新文件夹

1.  在新的`now`文件夹下创建一个新的`Dockerfile`

1.  实现从您刚刚发布的图像中提取文件：

```ts
now/Dockerfile
FROM duluca/localcast-weather:6.0.1
```

1.  最后，在您的终端中执行`now`命令，并按照说明完成配置：

```ts
$ now
> No existing credentials found. Please log in:
> We sent an email to xxxxxxxx@gmail.com. Please follow the steps provided
 inside it and make sure the security code matches XXX XXXXX.
√ Email confirmed
√ Fetched your personal details
> Ready! Authentication token and personal details saved in "~\.now"
```

# 部署

在 Zeit Now 上部署非常容易：

1.  将您的工作目录更改为`now`并执行命令：

```ts
$ now --docker --public
```

1.  在终端窗口中，该工具将报告其进度和您可以访问您的已发布应用程序的 URL：

```ts
> Deploying C:\dev\local-weather-app\web-app\now under duluca
> Ready! https://xxxxxxxxxxxxx.now.sh [3s]
> Initializing...
> Building
> ▲ docker build
Sending build context to Docker daemon 2.048 kBkB
> Step 1 : FROM duluca/localcast-weather
> latest: Pulling from duluca/localcast-weather
...
> Deployment complete!
```

1.  导航到第二行列出的 URL，并验证您的应用程序的发布。

请注意，如果您在途中出现配置错误，您的浏览器可能会显示一个错误，指出此页面正在尝试加载不安全的脚本，请允许并重新加载以查看您的应用程序。

您可以探索 Zeit Now 的付费功能，这些功能允许为您的应用程序提供高级功能，例如自动扩展。

恭喜，您的应用程序已在互联网上发布！

# 总结

在本章中，您掌握了单元测试和端到端测试的配置和设置。您优化了故障排除工具，并了解了在开发应用程序时可能遇到的常见 Angular 错误。您学会了如何通过防范空数据来最好地避免 Angular 控制台错误。您配置了系统以与 Docker 一起工作，并成功地为您的 Web 应用程序容器化了自己专用的 Web 服务器。您为 Docker 配置了项目的 npm 脚本，可以被任何团队成员利用。最后，您成功地在云中交付了一个 Web 应用程序。

现在您知道如何构建一个可靠、弹性和容器化的生产就绪的 Angular 应用程序，以实现灵活的部署策略。在下一章中，我们将改进应用程序的功能集，并使用 Angular Material 使其看起来更加出色。
