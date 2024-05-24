# Angular6 面向企业级的 Web 开发（二）

> 原文：[`zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992`](https://zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：与 Angular 更新保持同步

在不同版本的几十种不同浏览器的数十种组合上提供安全、快速和一致的 Web 体验并不是一件容易的事。Angular 的存在就是为了实现这一点；然而，互联网是一个不断发展的竞争技术和供应商的领域。Angular 团队已经承诺定期更新平台，但是要靠您来跟上 Angular 的补丁、次要版本和主要版本的发布。

Angular 是一个旨在最大程度减少从一个版本升级到另一个版本的工作量的平台，提供了有用的工具和指南，最重要的是确定性的发布节奏和关于废弃功能的充分沟通，这允许进行适当的规划以保持最新。

您必须以一种深思熟虑和计划的方式保持与 Angular 的最新版本同步。这样的策略将最大程度地提高您使用 Angular 这样的平台所获得的好处，将错误和浏览器之间的不一致体验降至最低。在极端情况下，您有选择：要么保留数百名测试人员来测试您的 Web 应用程序在所有主要浏览器及其最新版本上的兼容性问题，要么保持您的 Angular 版本（或您选择的框架）保持最新。请记住，最终，确保您交付的产品质量是由您来决定的。

现在可以随意跳过本章，当 Angular 的一个次要或主要版本发布时再回来阅读，或者继续阅读以了解潜在的升级过程可能是什么样子。

在本章中，我们将讨论以下主题：

+   更新节点

+   更新 `npm` 和全局包

+   更新 Angular

+   解决安全漏洞

+   更新您的 Web 服务器

# Web 框架的简要历史

首先，重要的是考虑为什么我们首先要使用 Angular 或 React 等框架？在 Angular 之前，有 AngularJS 和 Backbone，它们都严重依赖于普遍存在的 jQuery 之前的框架。在 jQuery 存在的早期，即 2006 年，它对 Web 开发人员的目的是非常明显的——创建一个一致的 API 表面来实现 DOM 操作。浏览器供应商应该实现各种 Web 技术，如 HTML、JavaScript/EcmaScript 和 CSS，这是由万维网联盟（W3C）标准化的。当时，绝大多数互联网用户依赖的唯一浏览器是 Internet Explorer，它作为推动专有技术和 API 以保持其作为首选浏览器的优势的工具。首先是 Mozilla 的 Firefox，然后是 Google 的 Chrome 浏览器成功地获得了重要市场份额。然而，新浏览器版本开始以惊人的速度发布，竞争利益和不同的实现草案和已批准标准的版本和名称的质量差异造成了开发人员无法在 Web 上提供一致的体验。因此，您可以使用 jQuery 而不是反复编写代码来检查浏览器版本，这样您就可以轻松地隐藏供应商特定实现的所有复杂性，通过优雅地填补空白来弥补缺失的功能。

在 jQuery 中创建丰富的用户体验仍然很繁琐，Backbone 和 AngularJS 等框架使构建具有本地感和速度的 Web 应用程序更具成本效益。然而，浏览器不断变化，jQuery 和早期设计决策的意想不到的影响随之而来，随着标准的不断发展，导致了在 Angular 和 React 中构建 Web 应用程序的两种新的不同方法。从 AngularJS 过渡到 Angular 对整个社区来说都是一个令人不适的经历，包括 Angular 开发团队，但这必须是一个重大发布，以创建一个可以不断发展的平台。现在，新的 Angular 平台致力于保持最新状态，定期发布增量版本，以避免过去的错误。

# 更新 Node

即使您不将 Node.js 用作 Web 服务器，您也已经在使用它通过 npm 安装您的依赖项，并通过基于 Node.js 的软件包（如 WebPack，Gulp 或 Grunt）执行构建和测试任务。Node.js 是一个轻量级的跨平台执行环境，可以使大多数现代开发工具无缝工作。由于其性质，Node 位于您的主机操作系统之外的技术堆栈的最底层。保持 Node 的版本最新以获得安全性、速度和功能更新的好处非常重要。

Node.js 有两个分支：**长期支持**（**LTS**）版本和当前版本。奇数版本是一次性的、风险的发布，不计划进行 LTS 阶段。偶数版本首先作为当前版本发布，然后进入 LTS 阶段。

为了最大的稳定性和避免意外问题，我强烈建议坚持使用 Node 的 LTS 版本：

1.  通过运行此命令检查您当前的版本：

```ts
node -v
v8.9.0
```

您可以在[`nodejs.org`](https://nodejs.org)上查看有关最新发布的更多信息。除了计划发布，这个网站通常会包含有关各种 Node.js 发布的临时关键安全补丁的信息。

1.  如果您使用奇数或非 LTS 发布频道，请删除您现有的 Node 安装：

在 Windows 上，请确保您以管理员权限运行 PowerShell：

```ts
PS> choco uninstall node

```

在 macOS 上，如果您的环境设置正确，您不需要在命令中添加`sudo`：

```ts
$ brew uninstall --ignore-dependencies node
```

1.  在 Windows 上，要升级到最新的 LTS 版本，请执行以下命令：

```ts
PS> choco upgrade nodejs-lts
```

1.  在 macOS 上，如果您还没有安装 Node 8，您首先需要执行以下操作：

```ts
$ brew install node@8
```

1.  如果您已经在版本 8 上，则执行以下操作：

```ts
$ brew upgrade node@8
```

请注意，计划在 2018 年 10 月发布版本 10 作为下一个 LTS 版本，因此在运行 brew install 命令之前，您需要牢记这一点。

如果您在 macOS 上，请参考下一节，了解使用`n`工具更轻松地管理您的 Node 版本的方法。否则，请跳转到*更新 Npm*部分。

# n - 用于 macOS 的 Node 版本管理器

在 macOS 上，HomeBrew 没有 Node 的 LTS 特定频道，如果最新版本是奇数版本，您将发现自己处于一个不理想的位置。如果您错误地执行了`brew upgrade node`并升级到奇数版本，要从这个错误中恢复最好是很烦人的。这个过程包括通过运行类似于这样的命令来潜在地破坏其他 CLI 工具：

```ts
$ brew uninstall --ignore-dependencies node
```

在通过 brew 进行初始 Node 安装后，我强烈建议利用功能丰富、交互式的 Node 版本管理工具`n`，由前 Node 维护者 TJ Holowaychuk 创建：

1.  安装`n`：

```ts
$ npm install -g n
```

1.  执行`n`，它将显示您计算机上先前下载的所有 Node 版本的列表，并标记当前版本：

```ts
$ n
 ...
 node/8.2.1
 node/8.3.0
 node/8.4.0
 ο node/8.9.0
```

1.  执行`n lts`以安装最新的 LTS 版本：

```ts
$ n lts
 install : node-v8.9.3
 mkdir : /usr/local/n/versions/node/8.9.3
 fetch : https://nodejs.org/dist/v8.9.3/node-v8.9.3-darwin-x64.tar.gz
######################################################################## 100.0%
 installed : v8.9.3
```

使用`n`，您可以快速在不同的 Node 版本之间切换。

在本节中，我们将介绍如何保持 npm 的最新状态。

# 更新 npm 和全局 npm 包

如果 Node 是您技术栈中最低级别的工具，那么 npm 和全局 npm 包将被视为坐落在 Angular 和 Node 之间的下一层。

每次更新 Node 版本时，您还会获得一个新版本的 npm，它与 Node 捆绑在一起。但是，npm 的发布计划与 Node 的不一致。有时，会有显著的性能和功能增益，需要特定升级您的 npm 版本，例如 npm v5.0.0 引入的数量级速度改进，或者 npm v5.2.0 引入的减少全局包需求的 npx 工具：

+   在 Windows 上，您需要使用`npm-windows-upgrade`工具来升级您的 npm 版本：

1.  安装`npm-windows-upgrade`：

```ts
PS> npm install --global --production npm-windows-upgrade
```

如果在安装工具时遇到错误，请参考*Npm fails to install a global tool on Windows*部分，解决系统设置的任何问题。

1.  在提升的 shell 中执行`npm-windows-upgrade`，您将获得一系列选项，如下所示：

```ts
PS> npm-windows-upgrade
npm-windows-upgrade v4.1.0
? Which version do you want to install?
 6.0.1-next.0
> 6.0.0
 6.0.0-next.2
 6.0.0-next.1
 6.0.0-next.0
 5.10.0-next.0
 5.9.0-next.0
(Move up and down to reveal more choices)
```

1.  选择一个稳定的版本，例如`6.0.0`：

```ts
PS>
? Which version do you want to install? 6.0.0
Checked system for npm installation:
According to PowerShell: C:\Program Files\nodejs
According to npm: C:\Users\duluc\AppData\Roaming\npm
Decided that npm is installed in C:\Program Files\nodejs
Upgrading npm... \

Upgrade finished. Your new npm version is 6.0.0\. Have a nice day!
```

1.  验证您的安装：

```ts
PS> npm -v
6.0.0
```

+   在 macOS 上，升级您的 npm 版本很简单：

1.  执行`npm install -g npm`：

```ts
$ npm install -g npm
/usr/local/bin/npm -> /usr/local/lib/node_modules/npm/bin/npm-cli.js
/usr/local/bin/npx -> /usr/local/lib/node_modules/npm/bin/npx-cli.js
+ npm@6.0.0
updated 1 package in 18.342s
```

请注意，安装全局包，如前面所示，不应需要使用`sudo`。

1.  如果需要`sudo`，执行以下操作：

```ts
$ which npm
/usr/local/bin/npm
```

1.  找到此文件夹的所有者和权限：

```ts
$ ls -ld /usr/local/bin/npm
lrwxr-xr-x 1 youruser group 38 May 5 11:19 /usr/local/bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js
```

如您所见，正确的配置看起来像您自己的用户，以粗体显示为`youruser`，对该文件夹具有读/写/执行权限，也以粗体显示为`rwx`，其中`npm`位于其中。如果不是这种情况，请使用`sudo chown -R $USER /usr/local/bin/npm`来拥有该文件夹，然后使用`chmod -R o+rwx /usr/local/bin/npm`来确保您的用户具有完全权限。

1.  验证您的安装：

```ts
$ npm -v
6.0.0
```

保持任何全局安装的软件包最新也很重要；请参考下一节，了解如何将全局安装保持在最低限度，并解决 Windows 上的安装问题。

# 全局 Npm 包

如本节和第二章中所述，在设置 Angular 项目时，您应该避免将任何项目特定工具安装为全局包。这包括诸如`typescript`、`webpack`、`gulp`或`grunt`等工具。`npx`工具使您能够方便地运行 CLI 命令，例如使用特定版本的`tsc`，而对性能的影响很小。如第二章中所讨论的，全局安装项目特定工具会对您的开发环境产生不利影响。

我确实提到了一些我仍然继续全局安装的工具，比如来自*升级 Node*部分的`n`工具，或者`rimraf`，这是一个跨平台递归删除工具，在 Windows 10 不配合删除您的`node_modules`文件夹时非常方便。这些工具是非项目特定的，而且基本稳定，不需要频繁更新。

事实是，除非工具提醒您升级自己，否则您很可能永远不会主动这样做。我们在第三章中使用的 now CLI 工具，*为生产发布准备 Angular 应用*，以在云中发布我们的 Docker 容器，是一个很好的例子，它始终保持警惕，以确保自己与以下消息保持最新：

```ts
 ^(─────────────────────────────────────────
   │ Update available! 8.4.0 → 11.1.7                                  │
   │ Changelog: https://github.com/zeit/now-cli/releases/tag/11.1.7    │
   │ Please download binaries from https://zeit.co/download            │
    ─────────────────────────────────────────)
```

您可以通过执行以下操作升级全局工具：

```ts
$ npm install -g now@latest
```

请注意，`@latest`请求将升级到下一个主要版本，如果可用的话，而不会引起太多轰动。虽然主要版本包含令人兴奋和有用的新功能，但它们也有破坏旧功能的风险，而您可能正在依赖这些功能。

这应该完成您的升级。然而，特别是在 Windows 上，很容易使您的 Node 和 npm 安装处于破损状态。以下部分涵盖了常见的故障排除步骤和您可以采取的操作，以恢复您的 Windows 设置。

# Npm 在 Windows 上无法安装全局工具

Npm 可能无法安装全局工具；请考虑以下讨论的症状、原因和解决方案：

**症状**：当您尝试安装全局工具时，您可能会收到一个包含拒绝删除消息的错误消息，类似于下面显示的消息：

```ts
PS C:\WINDOWS\system32> npm i -g now
npm ERR! path C:\Users\duluc\AppData\Roaming\npm\now.cmd
npm ERR! code EEXIST
npm ERR! Refusing to delete C:\Users\duluc\AppData\Roaming\npm\now.cmd: node_modules\now\download\dist\now symlink target is not controlled by npm C:\Users\duluc\AppData\Roaming\npm\node_modules\now
npm ERR! File exists: C:\Users\duluc\AppData\Roaming\npm\now.cmd
npm ERR! Move it away, and try again.
npm ERR! A complete log of this run can be found in:
npm ERR! C:\Users\duluc\AppData\Roaming\npm-cache\_logs\2017-11-11T21_30_28_382Z-debug.log
```

**原因**：在 Windows 上，如果您曾经执行过`npm install -g npm`或使用 choco 升级过您的 Node 版本，您的 npm 安装很可能已经损坏。

**解决方案 1**：使用`npm-windows-upgrade`工具恢复您的环境：

1.  执行 npm 升级例程：

```ts
PS> npm install --global --production npm-windows-upgrade
PS> npm-windows-upgrade
```

1.  使用`rimraf`删除有问题的文件和目录：

```ts
PS> npm i -g rimraf
rimraf C:\Users\duluc\AppData\Roaming\npm\now.cmd
rimraf C:\Users\duluc\AppData\Roaming\npm\now
```

1.  尝试重新安装：

```ts
PS> npm i -g now@latest
```

如果这不能解决您的问题，请尝试解决方案 2。

**解决方案 2**：如果您安装了非 LTS nodejs 或者没有正确配置 npm，请尝试以下步骤：

1.  卸载非 LTS nodejs 并重新安装它：

```ts
PS> choco uninstall nodejs
PS> choco install nodejs-lts --force -y
```

1.  按照[`github.com/npm/npm/wiki/Troubleshooting#upgrading-on-windows`](https://github.com/npm/npm/wiki/Troubleshooting#upgrading-on-windows)中的指南安装`npm-windows-upgrade`。

1.  在具有管理员权限的 Powershell 中执行此操作：

```ts
PS> Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
PS> npm install --global --production npm-windows-upgrade
PS> npm-windows-upgrade
```

1.  执行`npm-windows-upgrade`：

```ts
PS> npm-windows-upgrade
npm-windows-upgrade v4.1.0
? Which version do you want to install? 5.5.1
Checked system for npm installation:
According to PowerShell: C:\Program Files\nodejs
According to npm: C:\Users\duluc\AppData\Roaming\npm
Decided that npm is installed in C:\Program Files\nodejs
Upgrading npm... -
Upgrade finished. Your new npm version is 5.5.1\. Have a nice day!
```

1.  注意根据 npm 文件夹。

1.  转到此文件夹，并确保此文件夹中不存在`npm`或`npm.cmd`。

1.  如果有，删除。

1.  确保此文件夹在`PATH`中。

单击“开始”，搜索“环境变量”。单击“编辑系统环境变量”。在“系统属性”窗口中，单击“环境变量”。选择带有路径的行。单击“编辑”。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/649fc16c-7b98-4fae-9171-a066cd8db525.png)编辑环境变量对话框

1.  尝试重新安装您的全局工具。

1.  如果问题仍然存在，您可能需要使用 PowerShell 命令删除全局的`npm`文件夹，如下所示：

```ts
PS> cmd /C "rmdir /S /Q C:\Users\duluc\AppData\Roaming\npm"
```

1.  转到该文件夹：

```ts
PS> dir C:\Users\duluc\AppData\Roaming\npm
```

1.  执行 npm：

```ts
PS> npm@5.5.1 C:\Program Files\nodejs\node_modules\npm
```

1.  重新执行`npm-windows-upgrade`例程：

```ts
PS> npm install --global --production npm-windows-upgrade
PS> npm-windows-upgrade
```

1.  重新安装工具：

```ts
PS> npm i -g now
C:\Users\duluc\AppData\Roaming\npm\now -> C:\Users\duluc\AppData\Roaming\npm\node_modules\now\download\dist\now
> now@8.4.0 postinstall C:\Users\duluc\AppData\Roaming\npm\node_modules\now
> node download/install.js
> For the source code, check out: https://github.com/zeit/now-cli
> Downloading Now CLI 8.4.0 [====================] 100%
+ now@8.4.0
```

将来不要运行`npm i -g npm`。

# 更新 Angular

使用 Node 和 npm 最新版本，您现在可以准备升级您的 Angular 版本了。Angular 生态系统经过精心设计，使您的版本更新尽可能轻松。次要版本更新应该是直接和快速的，从版本`6.0.0`开始；主要版本升级应该更容易，因为 Angular CLI 附带了新的`ng update`命令。配合[update.angular.io](https://update.angular.io)上发布的更新指南和特定于您升级路径的各种辅助工具，更新 Angular 是直接的。在本节中，我们将介绍如何更新您的 Angular 应用程序，假设从版本 5.2 升级到 6.0 的情景。指南应该基本保持不变，任何变化或将来的更改都记录在[`update.angular.io/`](https://update.angular.io/)中。

请记住，Angular 不建议在升级时跳过主要版本号，因此如果您使用的是版本 4，则首先需要升级到 5，然后再升级到 6。不要延迟更新您的框架版本，认为可以通过跳跃到最新版本来获得一些效率。

# Angular 更新指南

按照这一步骤指南准备、执行和测试您的 Angular 版本升级过程。

# 了解您当前的版本

让我们首先检查`package.json`，以便您了解您正在使用的各种依赖项的版本。所有`@angular`包应该是相同的次要版本，例如`5.2`，如图所示：

```ts
package.json
 "@angular/animations": "5.2.5",
    "@angular/cdk": "⁵.2.2",
    "@angular/common": "5.2.5",
    "@angular/compiler": "5.2.5",
    "@angular/core": "5.2.5",
    "@angular/flex-layout": "².0.0-beta.12",
    "@angular/forms": "5.2.5",
    "@angular/http": "5.2.5",
    "@angular/material": "⁵.2.2",
    "@angular/platform-browser": "5.2.5",
    "@angular/platform-browser-dynamic": "5.2.5",
    "@angular/router": "5.2.5",
    "core-js": "².4.1",
    ...
    "rxjs": "⁵.5.6",
    "ts-enum-util": "².0.0",
    "zone.js": "⁰.8.20"
  },
  "devDependencies": {
    "@angular/cli": "1.7.0",
    "@angular/compiler-cli": "5.2.5",
    "@angular/language-service": "5.2.5",
...
```

# 使用 Angular 更新指南

现在您已经了解了您当前的版本，可以使用更新指南了：

1.  导航至[update.angular.io](https://update.angular.io/)

1.  选择您的应用程序的复杂性：

+   基本：没有动画，没有 HTTP 调用

+   中级：如果您正在使用 Angular Material 或进行 HTTP 调用或使用 RxJS，通常作为 1-2 人开发团队并交付小型应用程序

+   高级：多人团队，交付中大型应用程序

大多数应用程序将属于中等复杂性；我强烈建议选择此选项。如果您已经在文档中深入实现了 Angular 功能，通过利用文档中提到的功能来实现任何自定义行为，确保在 HTTP、渲染、路由等方面实现任何自定义行为——一定要先浏览高级列表，以确保您没有使用已弃用的功能。

1.  在更新指南上，选择从哪个版本升级到哪个版本。在这种情况下，选择从 5.2 升级到 6.0，如图所示：

！[](Images/9561a4ef-1e63-4b22-84d1-df6ee3e7ff8a.png)Angular 更新指南

1.  点击“显示我如何更新！”

1.  请注意屏幕上显示的指示，分为更新前、更新中和更新后三个不同的部分

现在是困难的部分，我们需要遵循说明并应用它们。

# 更新您的 Angular 应用程序

更新软件是有风险的。有几种策略可以减少您在更新应用程序时的风险。这是您在应用程序中构建大量自动化测试的主要原因；然而，随着时间的推移，您的实施，包括 CI 和 CD 系统，可能会恶化。版本更新是重新评估您的自动化系统的健壮性并进行必要投资的好时机。在开始更新过程之前，请考虑以下升级前清单。

# 升级前清单

以下是在开始升级之前要运行的一些方便的检查项目清单：

1.  确保`@angular`版本一直匹配到最后一个补丁。

1.  确保您的 CI 和 CD 管道正常运行，没有失败或禁用的测试。

1.  在升级之前对应用程序进行烟雾测试。确保所有主要功能正常运行，没有控制台错误或警告。

1.  在升级之前解决任何发现的质量问题。

1.  按顺序和有条不紊地遵循更新指南。

1.  准备好回滚更新。

让我们从更新前的活动开始更新过程。

# 在更新之前

Angular 更新指南建议在“更新前”部分采取特定步骤，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c227ddff-eb76-499b-8760-25fd55409643.png)Angular 更新指南 - 更新前

在尝试更新之前，您可能需要对代码进行几种不同的更新。

**命名空间更改**：上述列表中的第一项通知我们某些动画服务和工具的命名空间可能已经更改。这些更改应该是低风险的，并且可以通过在 VS Code 中使用全局搜索工具快速完成。让我们看看如何快速观察你的应用程序中所有`'@angular/core'`的用法。看下一张截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/2a9f3550-dd3b-45f4-bbfe-816035588bd1.png)'@angular/core'的搜索结果

在这种情况下，没有与动画相关的用法，所以我们可以继续。

**重命名和替换更新**：在版本 4 中，有一个要求，即将`OpaqueTokens`类型替换为`InjectionTokens`。对于这些类型的更改，再次使用全局搜索工具查找和替换必要的代码。

在使用全局搜索工具查找和替换代码时，确保您启用了匹配大小写（由 Aa 表示）和匹配整个单词（由 Ab|表示），以防止意外的替换。看一下以下截图，看看这两个选项处于启用状态时的情况：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/df0f981e-2df2-445d-bc8d-f83e477deb8b.png)匹配大小写和匹配整个单词已启用

**功能性更改**：弃用的功能提前一个主要版本发出信号，需要重写应用程序代码中受影响部分。如果您一直在大量使用`HttpModule`和`Http`，那么您的代码将需要进行严重的改造：

1.  首先，使用全局搜索发现实际用法的实例。

1.  在[angular.io](https://angular.io)上搜索新引入的服务，例如`HttpClient`或`HttpClientModule`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/4d712046-bafb-4a2c-a43d-41c085705f58.png)Angular.io 文档页面

1.  单击标题下的相关链接，其中包含有关新服务的丰富和上下文的信息。

新的服务通常伴随着新的好处，比如改进的编码体验，更好的可测试性或性能。

1.  重新实现必要的代码。

1.  执行下一节中提到的后续更新检查表。

这些功能性变化可以同时成为巨大的生产力助推器，但也会极大地增加及时升级到新版本 Angular 的摩擦。然而，您可以通过提前准备来降低变更成本，并最大程度地获得这些变化的好处。

在这种情况下，LocalCast Weather 应用程序没有使用已弃用的模块，因为恰好是在发布`HttpClient`服务后不久开始开发该应用程序。然而，如果我没有关注 Angular 社区，我就不会知道这个变化。出于这个原因，我强烈建议关注[`blog.angular.io`](https://blog.angular.io)。

此外，您可以定期检查 Angular 更新工具。该工具可能不会被迅速更新；然而，它是所有即将到来的变化的一个很好的摘要资源。

在更新工具中，如果您选择未来版本的 Angular，您将收到警告消息：

**警告**：当前主要版本之后的发布计划尚未最终确定，可能会更改。这些建议是基于计划的弃用。

这是保持领先并提前规划资源围绕 Angular 更新的一个很好的方法。

完成“更新前”阶段后，考虑在进入下一阶段之前查看后续更新检查表。

# 更新期间

以下是指南中关于`ng update`工具的更新期间部分：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/024c4569-8053-44f2-b095-deb8d3eae5ba.jpg)Angular 更新指南-更新期间

相比之下，Angular 6 之前的升级看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/058c1b0c-c834-4d6c-a00d-9b1047f4786d.jpg)Angular 更新指南-在 Angular 6 之前

如果你对手动更新更感兴趣，请参考手动更新部分。在这一部分，我详细介绍了你应该执行的步骤，以更全面地进行自动升级。在第二章中，*创建一个本地天气 Web 应用程序*，我们避免安装 Angular CLI，这就是这种策略的好处所在。你可以继续在现有的 Angular 4 或 Angular 5 项目上工作，而不必担心 CLI 向后兼容性问题：

1.  确保你已经更新到了最新的 Node LTS 版本，就像本章前面展示的那样

1.  确保你使用的是 npm 的最新版本，就像本章前面展示的那样

1.  在你的终端中，`cd`进入项目文件夹

1.  清理你的`node_modules`文件夹：

```ts
$ rimraf node_modules
```

重要的是要注意，Node 或 npm 的版本更改可能会影响你的`node_modules`依赖项在计算机上的安装或存储方式。在升级到更低级别的工具，比如 Node 或 npm 之后，最好清除`node_modules`并在你的项目中重新安装你的包。在你的持续集成（CI）服务器上，这意味着使现有的包缓存无效。

1.  重新安装依赖项：

```ts
$ npm install
```

1.  卸载全局安装的`@angular/cli`、`webpack`、`jasmine`或`typescript`的版本：

```ts
$ npm uninstall -g @angular/cli webpack jasmine typescript
```

1.  在你的项目中更新到最新的 CLI 版本：

```ts
$ npm i -D @angular/cli@latest
> @angular/cli@6.0.0 postinstall /Users/du/dev/local-weather-app/node_modules/@angular/cli
> node ./bin/ng-update-message.js

===================================================================
The Angular CLI configuration format has been changed, and your 
existing configuration can be updated automatically by running 
the following command:
ng update @angular/cli
===================================================================
```

1.  根据前面的消息建议更新项目配置：

```ts
$ npx ng update @angular/cli 
 master!
 Updating karma configuration
 Updating configuration
 Removing old config file (.angular-cli.json)
 Writing config file (angular.json)
 Some configuration options have been changed, please make sure to update any npm scripts which you may have modified.
DELETE .angular-cli.json
CREATE angular.json (3644 bytes)
UPDATE karma.conf.js (1007 bytes)
UPDATE src/tsconfig.spec.json (324 bytes)
UPDATE package.json (3874 bytes)
UPDATE tslint.json (3024 bytes)
...
added 620 packages from 669 contributors in 24.956s
```

1.  尝试执行`ng update`：

```ts
$ npx ng update
We analyzed your package.json, there are some packages to update:

Name Version Command to update
-------------------------------------------------------------------
@angular/core 5.1.0 -> 6.0.0 ng update @angular/core
@angular/material 5.0.0 -> 6.0.0 ng update @angular/material
rxjs 5.5.2 -> 6.1.0 ng update rxjs

There might be additional packages that are outdated.
Or run ng update --all to try to update all at the same time.
```

1.  尝试执行`ng update --all`：

```ts
$ npx ng update --all
```

你可能会收到一个错误消息，说找到了不兼容的 peer 依赖。列出了一个或多个具体的问题。在解决所有问题之前，你将无法使用`ng update`。

在下一节中，我将介绍解决 peer 依赖错误的策略。如果你没有这种错误，可以跳过这一节。

# 不兼容的 peer 依赖

我将介绍一些在升级过程中遇到的不兼容的 peer 依赖错误，以及解决这些错误的不同策略。请注意，我将从简单的情况开始，并演示可能需要的研究量，因为你需要的依赖项可能不仅仅是你的包的最新发布版本。

+   包`karma-jasmine-html-reporter`缺少 peer 依赖`"jasmine" @ "³.0.0"`。

这是一个简单的错误，只需简单地更新到最新版本的`jasmine`即可解决：

```ts
$ npm i -D jasmine
```

+   包`@angular/flex-layout`与`"rxjs"`有不兼容的对等依赖关系（需要`"⁵.5.0"`，将安装`"6.1.0"`）。

这个错误需要一些对生态系统的研究和理解。截至 Angular 6，我们知道所有库都是版本同步的，因此我们需要这个库的 6.x 版本。让我们使用`npm info`来发现当前可用的版本：

```ts
$ npm info @angular/flex-layout
 ...
 dist-tags:
 latest: 5.0.0-beta.14 next: 6.0.0-beta.15

published a month ago by angular <devops+npm@angular.io>
```

截至目前，该库仍处于 beta 版本，最新版本为 5.0.0，因此简单地更新到最新版本的`@angular/flex-layout`是行不通的。在这种情况下，我们需要安装包的`@next`版本，如下所示：

```ts
$ npm i @angular/flex-layout@next
```

您将收到一堆依赖警告，显示需要 Angular 6 包。一旦更新完成，这些错误将消失。

+   包"@angular/compiler-cli"与"typescript"有不兼容的对等依赖关系（需要">=2.7.2 <2.8"，将安装"2.8.3"）。

Angular CLI 依赖于特定版本的 Typescript。如果执行`npm info typescript`，则最新版本的 Typescript 可能比所需版本更新。在这种情况下，正如前面的错误消息所报告的那样，它是`2.8.3`。错误消息确实向我们指出了具体需要的版本，如果你看一下 requires 语句。下限`2.7.2`似乎是正确的安装版本，所以让我们安装它，如下所示：

```ts
$ npm install -D typescript@2.7.2
```

理论上，我们所有的操作都应该解决所有对等依赖问题。实际上，我注意到这些错误有时会在使用`npx ng update --all`时仍然存在，因此我们将继续通过运行单独的更新命令来进行更新。

在非 macOS 操作系统上，您可能会持续遇到与 fsevents 相关的警告，例如`npm WARN optional SKIPPING OPTIONAL DEPENDENCY: fsevents@1.1.3`。这是一个可选的包，仅在 macOS 上使用。避免看到这个错误的简单方法是运行`npm install --no-optional`命令。

# 继续更新。

我们将逐步更新 Angular：

1.  让我们从 Angular Core 开始更新：

```ts
$ npx ng update @angular/core
Updating package.json with dependency rxjs @ "6.1.0" (was "5.5.6")...
 Updating package.json with dependency @angular/language-service @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/compiler-cli @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/router @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/forms @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/platform-browser @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/animations @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency zone.js @ "0.8.26" (was "0.8.20")...
 Updating package.json with dependency @angular/platform-browser-dynamic @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/common @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/core @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/compiler @ "6.0.0" (was "5.2.5")...
 Updating package.json with dependency @angular/http @ "6.0.0" (was "5.2.5")...
 UPDATE package.json (5530 bytes)
 ...
 added 12 packages from 37 contributors and updated 14 packages in 54.204s
```

请注意，此命令还会更新`rxjs`。

1.  更新 Angular Material：

```ts
$ npx ng update @angular/material
Updating package.json with dependency @angular/cdk @ "6.0.0" (was "5.2.2")...
 Updating package.json with dependency @angular/material @ "6.0.0" (was "5.2.2")...
 UPDATE package.json (5563 bytes)
 ...
```

确保您查看第五章中的 Material Update Tool 和手动更新 Angular Material 的策略，*使用 Angular Material 增强 Angular 应用*。

1.  更新其他依赖项，包括使用`npm update`更新类型：

```ts
$ npm update
+ codelyzer@4.3.0
+ karma-jasmine@1.1.2
+ jsonwebtoken@8.2.1
+ core-js@2.5.5
+ prettier@1.12.1
+ karma-coverage-istanbul-reporter@1.4.2
+ typescript@2.8.3
+ @types/jsonwebtoken@7.2.7
+ ts-enum-util@2.0.2
+ @types/node@6.0.108
```

请注意，`typescript`已更新到其最新版本`2.8.3`，这对于 Angular 6 来说是不可接受的，正如前一节所述。通过执行`npm install -D typescript@2.7.2`回滚到版本`2.7.2`。

1.  解决任何 npm 错误和警告。

你已经完成了主要的 Angular 依赖项更新。考虑在继续*升级后*部分之前执行“升级后检查清单”。

# 升级后

“升级后”阶段通知需要在主要 Angular 依赖项更新后进行的更改，并有时告诉我们在升级我们的 Angular 版本后可以获得的进一步好处。观察下一步：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ef42ec2d-eb0b-48d9-a0a0-c07311f76961.jpg)Angular 升级指南-升级后

在这种情况下，我们必须解决与我们升级到 RxJS 相关的弃用。幸运的是，Angular 团队知道这可能是一个痛苦的过程，因此他们建议使用一个自动化工具来帮助我们入门：

1.  不要全局安装该工具

1.  执行迁移工具，如下所示：

```ts
$ npx rxjs-tslint -p .\src\tsconfig.app.json

Running the automatic migrations. Please, be patient and wait until the execution completes.
Found and fixed the following deprecations:

Fixed 2 error(s) in C:/dev/lemon-mart/src/app/common/common.ts
Fixed 6 error(s) in C:/dev/lemon-mart/src/app/auth/auth.service.ts
Fixed 1 error(s) in C:/dev/lemon-mart/src/app/common/ui.service.ts
...

WARNING: C:/dev/lemon-mart/src/app/auth/auth-http-interceptor.ts[2, 1]: duplicate RxJS import
WARNING: C:/dev/lemon-mart/src/app/auth/auth-http-interceptor.ts[4, 27]: outdated import path
```

```ts
WARNING: C:/dev/lemon-mart/src/app/auth/auth.service.fake.ts[2, 1]: duplicate RxJS import
...
```

1.  手动解决任何警告；考虑以下示例：

```ts
example
import { BehaviorSubject, Observable, of } from 'rxjs'
import { ErrorObservable } from 'rxjs/observable/ErrorObservable'
import { IfObservable } from 'rxjs/observable/IfObservable'
import { catchError } from 'rxjs/operators'
```

在前面的示例中，我们只需要根据 RxJS 6 文档从`'rxjs'`和`'rxjs/operators'`导入，因此删除另外两个导入。此外，`ErrorObservable`和`IfObservable`导入被任何一行代码引用，因此很容易识别并删除。

一些警告可能掩盖了与新的 RxJS 函数的错误或不兼容性，因此逐一检查它们非常重要。

1.  移除`rxjs-compat`：

```ts
$ npm uninstall rxjs-compat
```

1.  构建和测试您的代码，以确保通过执行`npm run predocker:build`进行构建。

`predocker:build`以生产模式构建您的 Angular 应用程序，并通过执行以下命令运行您的单元测试和端到端测试：

```ts
$ npm run build -- --prod && npm test -- --watch=false && npm run e2e
```

解决任何错误。如果您遇到与您的代码无关的神秘错误，请尝试删除`node_modules`并重新安装软件包。

如果一切正常工作，恭喜你，你已经完成了升级！在你打开起泡酒之前，执行“升级后检查清单”。

# 升级后检查清单

更新后的清单在确保在进行大规模代码更改后没有引入任何退化的情况下非常有用。建议在更新过程的每个阶段之后执行此清单。可能并不总是可能或可行执行整个清单，但在对代码基进行重大更改后，如果有必要，更新你的单元测试，并逐步执行以下清单：

1.  构建和烟雾测试你的 Angular 应用

1.  提交你的更改

1.  每次提交时，确保 CI 流水线保持正常

1.  如果进行功能性更改，可能需要遵循你的组织的发布周期程序，其中可能包括由 QA 团队进行手动测试

1.  建议逐个实施和部署这些更改，并将它们部署到生产环境

1.  收集性能数据，如下一节所述

在一类更改后提交你的代码，这样可以在出现问题时回滚或挑选进一步的升级提交。

出于各种原因，你可能需要手动升级 Angular，这在下一节中有所涉及。

# 手动更新

最好对手动升级的工作原理有一个大致的了解，因为你可能无法使用具有自动更新功能的 Angular CLI 版本；你可能需要完全退出你的项目或者工具可能包含错误。这里讨论的版本号是从更新指南中复制的示例。

为了举例，我将演示从 Angular 4 到 Angular 5 的潜在升级：

1.  遵循指南和本章的更新说明

1.  确保 Node 和 npm 是最新的

1.  为了升级到版本 `5.0.0`，执行以下命令：

```ts
$ npm install @angular/animations@'⁵.0.0' @angular/common@'⁵.0.0' @angular/compiler@'⁵.0.0' @angular/compiler-cli@'⁵.0.0' @angular/core@'⁵.0.0' @angular/forms@'⁵.0.0' @angular/http@'⁵.0.0' @angular/platform-browser@'⁵.0.0' @angular/platform-browser-dynamic@'⁵.0.0' @angular/platform-server@'⁵.0.0' @angular/router@'⁵.0.0' typescript@2.4.2 rxjs@'⁵.5.2'
```

1.  接着执行`--save-exact`命令，以防 TypeScript 被意外升级：

```ts
$ npm install typescript@2.4.2 --save-exact
```

1.  确保你的 `package.json` 文件已经更新到正确的版本：

```ts
"dependencies": {
    "@angular/animations": "⁵.0.0",
    "@angular/common": "⁵.0.0",
    "@angular/compiler": "⁵.0.0",
    "@angular/core": "⁵.0.0",
    "@angular/forms": "⁵.0.0",
    "@angular/http": "⁵.0.0",
    "@angular/platform-browser": "⁵.0.0",
    "@angular/platform-browser-dynamic": "⁵.0.0",
    "@angular/platform-server": "⁵.0.0",
    "@angular/router": "⁵.0.0",
    "core-js": "².5.1",
    "rxjs": "⁵.5.2",
    "zone.js": "⁰.8.17"
  },
  "devDependencies": {
    "@angular/cli": "¹.5.0",
    "@angular/compiler-cli": "⁵.0.0",
    "@angular/language-service": "⁴.4.3",
   ...
    "typescript": "2.4.2"
  },
```

注意，TypeScript 版本中的插入符号和波浪号已被移除，以防止任何意外的升级，因为 Angular 工具对任何给定 TypeScript 发布的特定功能非常敏感。

注意，`@angular/cli` 和 `@angular/compiler-cli` 已经更新到它们的最新版本；然而，工具没有更新 `@angular/language-service`。这突显了手动检查的重要性，因为你的工具链中的每个工具都容易受到小错误的影响。

1.  通过执行以下命令更新`@angular/language-service`：

```ts
$ npm install @angular/language-service@⁵.0.0
```

1.  验证`package.json`中是否有正确的文件版本：

```ts
"@angular/language-service": "⁵.0.0",
```

您已完成更新您的软件包。

1.  按照指南和本章的更新说明进行操作。

在升级您的 Angular 应用程序后，测试您的更改对性能的影响是一个好主意。

# 性能测试

在更新之前和之后测试您的 Angular 应用程序的性能，以确保您的性能数字保持预期。在下面的情况中，由于平台级别的改进，我们自动获得了性能优势。首先，让我们比较一下 Angular v4 和 v5：

| **类别** | **   Angular 4** | **   Angular 5** | **        % 差异** |
| --- | --- | --- | --- |
| JavaScript Assets Delivered (gzipped) |             83.6 KB |             72.6 KB |            13% smaller |
| 首页渲染时间（Fiber） |                 0.57 秒 |                 0.54 秒 |                 5% 更快 |
| 首页渲染时间（快速 3G） |                 1.27 秒 |                 1.18 秒 |                 7% 更快 |

Angular 4.4.3 vs 5.0.0

Angular 6 的改进趋势持续下去：

| **类别** | **   Angular 5** | **   Angular 6** | **      % 差异** |
| --- | --- | --- | --- |
| JavaScript Assets Delivered (gzipped) |             72.6 KB |             64.1 KB |        12% 更小 |
| 首页渲染时间（Fiber） |                 0.54 秒 |                 0.32 秒 |           40% 更快 |
| 首页渲染时间（快速 3G） |                 1.18 秒 |                 0.93 秒 |           21% 更快 |

Angular 5.0.0 vs 6.0.0

这种趋势应该在未来的更新中继续，使用 Ivy 渲染引擎的目标大小为 3KB。我们将在第五章中介绍这些性能数字的重要性，*使用 Angular Material 增强 Angular 应用程序*。

# 解决安全漏洞

有时您会收到关于某些软件包的安全漏洞的通知，通过博客或者如果您使用 GitHub，您可能会在您的存储库上看到这样的警告：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/d4b0300f-e7fe-4956-9ce7-7a6febaef2b0.png)GitHub.com 漏洞扫描

这是一个特定的问题，当我的 Angular 应用程序版本为 5.0.0，我的 CLI 版本为 1.5.0 时出现的。如果您查看这个依赖项，您可以看到依赖的软件包，并获得更多关于这个问题的细节。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/483d2dc6-7e5d-4eee-8a63-5f5e0adf509d.png)GitHub.com 安全公告

在这种情况下，handlebars 的易受攻击版本 1.3.0 是由 Angular 5.0 包之一引起的。

进一步研究 Angular 的 GitHub 问题表明，问题实际上是由`@angular/cli 版本 1.5.0`引起的。参考是[`github.com/angular/angular/issues/20654`](https://github.com/angular/angular/issues/20654)。

这是尝试更新到 Angular、Material 或 CLI 的最新次要版本更新的好方法，在这种情况下是版本 5.1.0 和 1.6.0：

```ts
$ npm install @angular/animations@⁵.1.0 @angular/common@⁵.1.0 @angular/compiler@⁵.1.0 @angular/compiler-cli@⁵.1.0 @angular/core@⁵.1.0 @angular/forms@⁵.1.0 @angular/http@⁵.1.0 @angular/platform-browser@⁵.1.0 @angular/platform-browser-dynamic@⁵.1.0 @angular/platform-server@⁵.1.0 @angular/router@⁵.1.0 @angular/language-service@⁵.1.0 @angular/cli@¹.6.0
```

这次更新解决了 GitHub 显示的安全警告。如果你无法通过升级解决你的问题，请在 GitHub 上创建一个新问题，并密切关注 Angular 的即将发布的补丁或次要版本，直到问题得到解决。

# 更新你的 Web 服务器

你的堆栈顶部是你托管 Web 应用程序的 Web 服务器。这是一个实时的生产系统，很可能暴露在互联网上，因此风险最大。应该谨慎地保持最新状态。

理想情况下，你的发布流水线类似于第三章*，为生产发布准备 Angular 应用程序*中描述的流水线，其中你的前端应用程序由一个容器化的低配置实例提供。这可以是我发布和维护的`minimal-node-web-server`，也可以是基于 Nginx 的实例。在任何情况下，通过更改基础镜像旁边列出的版本号来升级是很简单的：

```ts
Dockerfile
FROM duluca/minimal-node-web-server:8.6.0
WORKDIR /usr/src/app
COPY dist public
```

指定你正在使用的基础 Docker 镜像的版本号总是一个好主意。否则，它将默认为最新行为，这在这种情况下可能意味着一个不适合生产的奇数版本。也就是说，`minimal-node-web-server`遵循了最佳安全实践的层层叠加，减少了攻击面，使成功攻击你的 Web 应用程序变得非常困难。与这一安全最佳实践主题一致，`minimal-node-web-server`永远不会将奇数节点版本作为默认行为。

如果你的内容是通过 IIS、Apache 或 Tomcat 等 Web 服务器安装提供的，你必须遵循和跟踪这些技术的安全公告。然而，很可能另一个人或另一个部门将负责升级这台服务器，这可能会导致从几天到几个月的延迟，这在互联网时间中是永远的。

你处于最高风险，如果你通过同一应用服务器提供静态网页内容，比如你的 SPA，同时也实现了后端 API。即使你的架构可能是解耦的，如果在你的依赖树中升级任何工具或应用程序对你的应用的任何其他部分产生副作用，这意味着你在保护或改进前端应用性能方面存在重大摩擦。

一个真正解耦的架构还将允许前端以不同的速度扩展，而不同于你的后端基础设施，这可以带来巨大的成本效益。例如，假设你的前端提供大量静态信息，并且很少需要轮询后端。在高负载时，你可能需要三个前端服务器实例来处理所有请求，但只需要一个后端服务器实例，因为调用很少。

# 更新 Docker 镜像

在升级应用程序及其依赖项或简单添加新功能后，您需要更新并发布新的 Docker 镜像。

1.  在`package.json`中，将版本属性更新为`1.1.0`或将您的版本与当前的 Angular 版本匹配

1.  执行`npm run docker:debug`来构建并验证您的更新是否正确工作

1.  最后，执行`npm run docker:publish`将您的新镜像推送到存储库

在发布图像后，采取必要步骤将图像部署到服务器或云提供商，如第三章中所述，*准备 Angular 应用程序进行生产发布*，以及第十一章中所述，*AWS 上高可用云基础设施*。

# 摘要

在本章中，我们讨论了保持整个依赖栈的最新状态的重要性，从 Node 和 npm 等开发工具到 Angular。我们看了看如何使用 ng update 和 Angular Update Guide 来尽可能地减少 Angular 更新的痛苦。我们还涵盖了手动更新、性能测试、处理超出安全漏洞和补丁的问题，包括保持 Web 服务器最新的必要性。保持相对最新的系统具有直接的成本效益。差距越小，维护的工作量就越小。然而，随着时间的推移，升级系统的成本呈指数级增长。作为非直接的好处，我们可以列举出由更好的性能带来的客户满意度，这是影响亚马逊等公司数百万美元的指标。工具中的新功能也对开发人员的生产力和幸福感产生深远影响，这有助于留住人才，减少新功能的成本，从而可能提高客户满意度。保持最新状态无疑是一个积极的反馈循环。

在下一章中，我们将讨论如何通过将 Angular Material 添加到项目中，使您的本地天气应用程序看起来更加出色。在这个过程中，您将了解用户控制或 UI 组件库可能对应用程序产生的负面性能影响，包括基本的 Material 组件、Angular Flex 布局、可访问性、排版、主题设置以及如何更新 Angular Material。


# 第五章：使用 Angular Material 增强 Angular 应用

在第三章*，为生产发布准备 Angular 应用*中，我们提到了提供高质量应用程序的需求。目前，该应用程序的外观和感觉非常糟糕，只适用于上世纪 90 年代创建的网站。用户或客户对您的产品或工作的第一印象非常重要，因此我们必须能够创建一个外观出色且在移动和桌面浏览器上提供出色用户体验的应用程序。

作为全栈开发人员，很难专注于应用程序的完善。随着应用程序功能集的迅速增长，情况会变得更糟。编写支持视图的优秀且模块化的代码很有趣，但在匆忙中退回到 CSS hack 和内联样式来改进应用程序是没有乐趣的。

Angular Material 是一个与 Angular 密切协调开发的令人惊叹的库。如果您学会如何有效地利用 Angular Material，您创建的功能将从一开始就看起来和运行得很好，无论您是在小型还是大型应用程序上工作。Angular Material 将使您成为一个更有效的 Web 开发人员，因为它附带了各种您可以利用的用户控件，并且您不必担心浏览器兼容性。作为额外的奖励，编写自定义 CSS 将变得罕见。

在本章中，您将学习以下内容：

+   如何配置 Angular Material

+   使用 Angular Material 升级 UX

# Angular Material

Angular Material 项目的目标是提供一系列有用且标准的高质量用户界面（UI）组件。该库实现了谷歌的 Material Design 规范，在谷歌的移动应用程序、网络属性和 Android 操作系统中普遍存在。Material Design 确实具有特定的数字和盒状外观和感觉，但它不仅仅是另一个 CSS 库，就像 Bootstrap 一样。考虑在此处使用 Bootstrap 编码的登录体验：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/56b5efb4-a4c0-433e-ab0d-604e0831e7cf.png)Bootstrap 登录体验

请注意，输入字段及其标签位于不同的行上，复选框是一个小目标，错误消息显示为短暂的弹出通知，提交按钮只是坐落在角落里。现在考虑给定的 Angular Material 示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f4d79a7f-aaed-4d65-9f60-dd05562e57cb.png)Angular Material 登录体验

输入字段及其标签最初是组合在一起的，以紧凑的形式吸引用户的注意力。复选框对触摸友好，提交按钮会拉伸以占用可用空间，以获得更好的默认响应式用户体验。一旦用户点击字段，标签就会收起到输入字段的左上角，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7ef987fd-ae5d-4b4e-8f48-13fdfd8062ac.png)Angular Material 动画和错误

此外，验证错误消息会内联显示，并与标签颜色变化结合，使用户注意力集中在输入字段上。

Material Design 帮助您设计具有自己品牌和样式的模块化 UI，同时定义动画，使用户在使用您的应用程序时拥有更好的用户体验（UX）。人类大脑下意识地跟踪对象及其位置。任何帮助过渡或由人类输入引起的反应的动画都会减少用户的认知负担，因此允许用户专注于处理内容，而不是试图弄清您特定应用程序的怪癖。

模块化 UI 设计和流畅的动作的结合创造了出色的用户体验。看看 Angular Material 如何实现一个简单的按钮。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7e0b60a1-4d7b-4fcb-be2d-53029100d40e.png)Angular Material 按钮动画

在上面的截图中，请注意按钮上的点击动画是从用户实际点击的位置开始的。然而微妙，这创造了一种连续的动作，导致了对给定动作的适当反应。当按钮在移动设备上使用时，这种特效变得更加明显，从而导致更加自然的人机交互。大多数用户无法表达什么使直观的用户体验实际上直观，设计和体验中的这些微妙但至关重要的线索在允许您为用户设计这样的体验方面取得了巨大进步。

Angular Material 还旨在成为 Angular 高质量 UI 组件的参考实现。如果您打算开发自定义控件，Angular Material 的源代码应该是您首要的资源。术语“高质量”经常被使用，量化其含义非常重要。Angular Material 团队在他们的网站上恰当地表达了这一点。

**我们所说的“高质量”是什么意思？**

国际化和可访问性，以便所有用户都可以使用它们。简单直观的 API，不会让开发人员困惑，并且在各种用例中表现如预期，没有错误。行为经过充分的单元测试和集成测试。在 Material Design 规范的范围内可定制。性能成本最小化。代码清晰，有文档，可以作为 Angular 开发人员的示例。浏览器和屏幕阅读器支持。

Angular Material 支持所有主要浏览器的最近两个版本：Chrome（包括 Android）、Firefox、Safari（包括 iOS）和 IE11 / Edge。

构建 Web 应用程序，特别是那些也兼容移动设备的应用程序，确实很困难。有很多细微之处需要注意。Angular Material 将这些细微之处抽象出来，包括支持所有主要浏览器，这样您就可以专注于创建您的应用程序。Angular Material 不是一时的潮流，也不应轻视。如果使用正确，您可以大大提高生产率和工作质量的感知。

在您的项目中，不一定总是能够使用 Angular Material。我建议使用 PrimeNG（[`www.primefaces.org/primeng`](https://www.primefaces.org/primeng)）或 Clarity（[`vmware.github.io/clarity`](https://vmware.github.io/clarity)）作为组件工具包，可以满足您大部分，如果不是全部，用户控制需求。要避免的一件事是从不同来源获取大量用户控件，最终得到一个杂乱的库，其中有数百个怪癖和错误需要学习、维护或解决。

# Angular Material 的设置和性能

Angular Material 默认配置为优化最终交付的包大小。在 Angular.JS 和 Angular Material 1.x 中，将加载整个依赖库。然而，在 Angular Material 6 中，我们能够指定我们打算使用的组件，从而实现显著的性能改进。

在下表中，您可以看到典型的 Angular 1.x + Angular Material 1.x 与 Angular 6 + Material 6 应用程序在高速低延迟的光纤连接下性能特征的改进：

| **光纤网络** | **Angular 6 + Material 6** | **Angular 1.5 + Material 1.1.5** | **% 差异** |
| --- | --- | --- | --- |
| 首页渲染时间* | 0.61 秒 | 1.69 秒** | ~2.8 倍更快 |
| 基本级别资产交付* | 113 KB | 1,425 KB | 缩小 12.6 倍 |

**图像或其他媒体内容未包含在结果中，以进行公平比较*

**平均值：较低质量的基础设施导致初始渲染时间为 0.9 到 2.5 秒*

在高速低延迟连接的理想条件下，Angular 6 + Material 6 应用程序在一秒内加载。然而，当我们切换到更常见的中等速度和高延迟的快速 3G 移动网络时，差异变得更加明显，如下表所示：

| **快速 3G 移动网络** | **Angular 6 + Material 6** | **Angular 1.5 + Material 1.1.5** | **    % 差异** |
| --- | --- | --- | --- |
| 首页渲染时间* | 1.94 秒 | 11.02 秒 | 5.7 倍更快 |
| 基本级别资产交付* | 113 KB | 1,425 KB | 缩小 12.6 倍 |

**图像或其他媒体内容未包含在结果中，以进行公平比较*

尽管应用程序的大小差异保持一致，但您可以看到移动网络引入的额外延迟导致传统的 Angular 应用程序速度显着下降到不可接受的水平。

将所有组件添加到 Material 6 将导致约 1.3 MB 的额外负载需要传递给用户。正如您可以从之前的比较中看到的，这必须以任何代价避免。为了提供可能最小的应用程序，尤其是在移动和与销售相关的场景中，每 100 毫秒的加载时间对用户保留都有影响，您可以逐个加载和包含模块。Webpack 的摇树过程将模块分成不同的文件，从而减少初始下载大小。在未来的构建中，预计 Angular 的大小将进一步缩小，可能会减少上表中提到的大小一半。

# 安装 Angular Material

让我们开始任务，并使用 Angular Material 改进天气应用程序的用户体验。让我们将改进应用程序用户体验的任务移动到我们的 Waffle.io 看板上的进行中。在这里，您可以看到我的看板的状态：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/da9a69e9-5ce9-4e8a-bcb1-1efedc94f194.png)Waffle.io 看板

# 自动

在 Angular 6 中，您可以自动将 Angular Material 添加到您的项目中，从而在过程中节省大量时间：

1.  执行`add`命令，如下所示：

```ts
$ npx ng add @angular/material
Installing packages for tooling via npm.

+ @angular/material@6.0.1
added 1 package in 15.644s
Installed packages for tooling via npm.
UPDATE package.json (1381 bytes)
UPDATE angular.json (3694 bytes)
UPDATE src/app/app.module.ts (502 bytes)
UPDATE src/index.html (474 bytes)
UPDATE node_modules/@angular/material/prebuilt-themes/indigo-pink.css (56678 bytes)
added 1 package in 13.031s
```

请注意，`index.html`文件已经被修改以添加图标库和默认字体，如下所示：

```ts
src/index.html
<head>
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500" rel="stylesheet">
  ...
</head>
```

还要注意`app.module.ts`已更新以导入`BrowserAnimationsModule`，如下所示：

```ts
src/app/app.module.ts

import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    ...
    BrowserAnimationsModule
  ],
```

1.  启动您的应用程序并确保它能正常工作：

```ts
$ npm start
```

有了这个，你就完成了。您的应用程序应该已配置为使用 Angular Material。重要的是要了解组成 Angular Material 的各种组件；在接下来的章节中，我们将介绍手动安装和配置步骤。您可以跳到*Angular Flex Layout*部分，但我强烈建议浏览一下手动步骤，因为我介绍了创建一个 Angular 模块来组织您的 Material 模块的概念。

# 手动

我们将从安装所有必需的库开始。从 Angular 5 开始，Angular Material 的主要版本应该与您的 Angular 安装版本匹配，而在 Angular 6 中，版本应该同步：

1.  在终端中，执行`npm install @angular/material @angular/cdk @angular/animations hammerjs`

1.  观察`package.json`版本：

```ts
package.json
 "dependencies": {
    "@angular/animations": "6.0.0",
    "@angular/cdk": "6.0.0",
    "@angular/material": "6.0.0",
    "hammerjs": "².0.8",
    ...
```

在这种情况下，所有库的主要和次要版本都是 5.0。如果您的主要和次要版本不匹配，您可以重新运行`npm install`命令以安装特定版本，或者选择通过将包的 semver 版本附加到安装命令来升级您的 Angular 版本：

```ts
$ npm install @angular/material@6.0.0 @angular/cdk@6.0.0 @angular/animations@6.0.0
```

如果您使用类似 Bash 的 shell，可以使用括号语法来节省一些输入，以避免重复命令的部分，比如`npm install @angular/{material,cdk,animations}@6.0.0`。

如果您需要更新 Angular 的版本，请参考第四章中的*更新 Angular*部分，*保持与 Angular 更新同步*。

# 理解 Material 的组件

让我们看看我们究竟安装了什么：

+   `@angular/material`是官方的 Material 2 库。

+   `@angular/cdk`是一个对等依赖项，除非您打算构建自己的组件，否则不会直接使用它。

+   `@angular/animations` 启用了一些 Material 2 模块的动画。可以省略它以保持应用程序的大小最小。您可以使用`NoopAnimationsModule`来禁用需要此依赖项的模块中的动画。结果，您将失去一些 Angular Material 的 UX 优势。

+   `hammerjs`启用了手势支持；如果您的目标是任何触摸设备，不仅仅是手机和平板电脑，还包括混合式笔记本电脑，这一点非常重要。

# 手动配置 Angular Material

现在依赖项已安装，让我们在 Angular 应用中配置 Angular Material。请注意，如果您使用`ng add @angular/material`来安装 Angular Material，则其中一些工作将由系统自动完成。

# 导入模块

我们将首先创建一个单独的模块文件，用于存放所有我们的 Material 模块导入：

1.  在终端中执行以下命令以生成`material.module.ts`：

```ts
$ npx ng g m material --flat -m app
```

请注意`--flat`标志的使用，它表示不应为`material.module.ts`创建额外的目录。另外，请注意，指定了`-m`，它是`--module`的别名，以便我们的新模块自动导入到`app.module.ts`中。

1.  观察新创建的文件`material.module.ts`：

```ts
src/app/material.module.ts
import { NgModule } from '@angular/core'
import { CommonModule } from '@angular/common'

@NgModule({
  imports: [CommonModule],
  declarations: [],
})
export class MaterialModule {}
```

1.  确保该模块已被导入到`app.module.ts`中：

```ts
src/app/app.module.ts
import { MaterialModule } from './material.module'
...  
@NgModule({
  ...
    imports: [..., MaterialModule],
}
```

1.  添加动画和手势支持（可选，但对移动设备支持必要）：

```ts
src/app/app.module.ts
import 'hammerjs'
import { BrowserAnimationsModule } from '@angular/platform-browser/animations'

@NgModule({
  ...
  imports: [..., MaterialModule, BrowserAnimationsModule],
}
```

1.  修改`material.module.ts`以导入按钮、工具栏和图标的基本组件

1.  移除`CommonModule`：

```ts
src/app/material.module.ts
import { MatButtonModule, MatToolbarModule, MatIconModule } from '@angular/material'
import { NgModule } from '@angular/core'

@NgModule({
  imports: [MatButtonModule, MatToolbarModule, MatIconModule],
  exports: [MatButtonModule, MatToolbarModule, MatIconModule],
})
export class MaterialModule {}
```

Material 现在已导入到应用程序中，现在让我们配置一个主题并将必要的 CSS 添加到我们的应用程序中。

# 导入主题

为了使用 Material 组件，需要一个基本主题。我们可以在`angular.json`中定义或更改默认主题：

```ts
angular.json
... 
"styles": [
  {
    "input": "node_modules/@angular/material/prebuilt-themes/indigo-pink.css"
  },
  "src/styles.css"
],
...
```

1.  从这里选择一个新选项：

+   `deeppurple-amber.css`

+   `indigo-pink.css`

+   `pink-bluegrey.css`

+   `purple-green.css`

1.  更新`angular.json`以使用新的 Material 主题

您也可以创建自己的主题，这在本章的自定义主题部分有介绍。有关更多信息，请访问[`material.angular.io/guide/theming`](https://material.angular.io/guide/theming)。

请注意，`styles.css`中实现的任何 CSS 将在整个应用程序中全局可用。也就是说，不要在此文件中包含特定于视图的 CSS。每个组件都有自己的 CSS 文件用于此目的。

# 添加 Material 图标字体

通过将 Material 图标 Web 字体添加到应用程序中，您可以访问一个很好的默认图标集。这个库大小为 48 kb，非常轻量级。

+   对于图标支持，请在`index.html`中导入字体：

```ts
src/index.html
<head>
  ...
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
```

在[`www.google.com/design/icons/`](https://www.google.com/design/icons/)上发现并搜索图标。

要获得更丰富的图标集，请访问[MaterialDesignIcons.com](https://materialdesignicons.com/)。这个图标集包含了 Material 图标的基本集，以及丰富的第三方图标，包括来自社交媒体网站的有用图像，以及涵盖了很多领域的丰富的操作。这个字体大小为 118 kb。

# Angular Flex Layout

在您可以有效使用 Material 之前，您必须了解其布局引擎。如果您已经做了一段时间的 Web 开发，您可能遇到过 Bootstrap 的 12 列布局系统。这对我大脑以 100%的方式分配事物的数学障碍。Bootstrap 还要求严格遵守 div 列、div 行的层次结构，必须从顶层 HTML 精确管理到底部。这可能会导致非常沮丧的开发体验。在下面的截图中，您可以看到 Bootstrap 的 12 列方案是什么样子的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/8256e1d7-bda6-48d1-a3d7-5367a0865298.png)Bootstrap 的 12 列布局方案

Bootstrap 的自定义网格布局系统在当时是革命性的，但随后 CSS3 Flexbox 出现了。结合媒体查询，这两种技术允许创建响应式用户界面。然而，有效地利用这些技术是非常费力的。从 Angular v4.1 开始，Angular 团队推出了其 Flex 布局系统，它可以正常工作。

GitHub 上的 Angular Flex Layout 文档恰如其分地解释了如下内容：

Angular Flex Layout 提供了一个复杂的布局 API，使用 FlexBox CSS + mediaQuery。这个模块为 Angular（v4.1 及更高版本）开发人员提供了使用自定义布局 API、mediaQuery observables 和注入的 DOM flexbox-2016 CSS 样式的组件布局功能。

Angular 的出色实现使得使用 FlexBox 非常容易。正如文档进一步解释的那样：

布局引擎智能地自动应用适当的 FlexBox CSS 到浏览器视图层次结构。这种自动化还解决了许多传统的、手动的、仅使用 Flexbox CSS 的应用程序所遇到的复杂性和解决方法。

该库非常强大，可以容纳您能想象到的任何类型的网格布局，包括与您可能期望的所有 CSS 功能的集成，比如`calc()`函数。在下图中，您可以看到如何使用 CSS Flexbox 描述列：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/63d95278-15b4-4cc3-af6b-2abf80f6ef36.png)Angular Flex Layout 方案

令人振奋的消息是，Angular Flex 布局与 Angular Material 没有任何耦合，并且可以独立使用。这是非常重要的解耦，解决了使用 AngularJS 与 Material v1 时的一个主要痛点，其中 Material 的版本更新经常会导致布局中的错误。

更多详情，请查看：[`github.com/angular/flex-layout/wiki`](https://github.com/angular/flex-layout/wiki)。

在发布时，`@angular/flex-layout`还没有发布稳定版本。该项目的 GitHub 活动表明，稳定版本将与 Angular 6 的发布同步。此外，CSS Grid 有望取代 CSS Flexbox，因此，该库使用的基础技术可能会发生变化。我希望这个库作为布局引擎的抽象层。

# 响应式布局

您设计和构建的所有 UI 都应该是面向移动设备的 UI。这不仅仅是为了服务于手机浏览器，还包括笔记本电脑用户可能会将您的应用与其他应用并排使用的情况。要正确实现移动设备优先设计有许多微妙之处。

以下是*Mozilla 圣杯布局*，它演示了“根据不同屏幕分辨率动态更改布局的能力”，同时优化移动设备的显示内容。

您可以在[`mzl.la/2vvxj25`](https://mzl.la/2vvxj25)了解有关 Flexbox 基本概念的更多信息。

这是大屏幕上 UI 外观的表示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/65decbe5-c598-4b0c-86df-2583ed0dfcd1.png)Mozilla 大屏幕上的圣杯布局

同样的布局在小屏幕上表示如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0ec3a455-4250-41c3-a5b0-caf6a25c787c.png)Mozilla 小屏幕上的圣杯布局

Mozilla 的参考实现需要 85 行代码来完成这种响应式 UI。Angular Flex 布局只需一半的代码就能完成同样的任务。

# 安装 Angular Flex 布局

让我们安装并将 Angular Flex 布局添加到我们的项目中：

1.  在终端中，执行`npm i @angular/flex-layout`

在发布时，`@angular/flex-layout`的当前版本是`5.0.0-beta.14`，这会导致许多对等依赖错误。为了避免这些错误，请执行`npm i @angular/flex-layout@next`来安装版本`6.0.0-beta.15`，如第四章中所述，*与 Angular 更新保持最新*。

1.  更新`app.module.ts`，如下所示：

```ts
src/app.module.ts
import { FlexLayoutModule } from '@angular/flex-layout'

imports: [
...
  FlexLayoutModule,
],
```

# 布局基础

Bootstrap 和 CSS FlexBox 与 Angular Flex 布局是不同的东西。如果你学会了 Angular Flex 布局，你将编写更少的布局代码，因为 Angular Material 大多数时候会自动做正确的事情，但是一旦你意识到一旦你离开 Angular Flex 布局的保护茧，你将不得不写更多的代码来让事情运转起来，你会感到失望。然而，你的技能仍然会转化，因为概念基本上是相同的。

让我们在接下来的部分中回顾一下 Flex 布局 API。

# DOM 容器的 Flex 布局 API

这些指令可以用在诸如`<div>`或`<span>`之类的 DOM 容器上，比如`<div fxLayout="row" fxLayoutAlign="start center" fxLayoutGap="15px">...</div>`：

| HTML API     | 允许的值 |
| --- | --- |
| `fxLayout` | <direction> &#124; <direction> <wrap>  Use: row &#124; column &#124; row-reverse &#124; column-reverse |

| `fxLayoutAlign` | <main-axis> <cross-axis>  main-axis: start &#124;center &#124; end &#124; space-around &#124; space-between

cross-axis: start &#124; center &#124; end &#124; stretch |

| `fxLayoutGap` | % &#124; px &#124; vw &#124; vh |
| --- | --- |

# DOM 元素的 Flex 布局 API

这些指令影响 DOM 元素在其容器中的行为，比如`<div fxLayout="column"><input fxFlex /></div>`：

| HTML API | 允许的值 |
| --- | --- |
| `fxFlex` | "" &#124; px &#124; % &#124; vw &#124; vh &#124; <grow> <shrink> <basis> |
| `fxFlexOrder` | int |
| `fxFlexOffset` | % &#124; px &#124; vw &#124; vh |
| `fxFlexAlign` | start &#124; baseline &#124; center &#124; end |
| `fxFlexFill` | *none* |

# 任何元素的 Flex 布局 API

以下指令可以应用于任何 HTML 元素，以显示、隐藏或更改所述元素的外观和感觉，比如`<div fxShow fxHide.lt-sm></div>`，它会显示一个元素，除非屏幕尺寸小于小屏幕：

| HTML API | 允许的值 |
| --- | --- |
| `fxHide` | TRUE &#124; FALSE &#124; 0 &#124; "" |
| `fxShow` | TRUE &#124; FALSE &#124; 0 &#124; "" |
| `ngClass` | @extends ngClass core |
| `ngStyle` | @extends ngStyle core |

本节介绍了静态布局的基础知识。您可以在[`github.com/angular/flex-layout/wiki/Declarative-API-Overview`](https://github.com/angular/flex-layout/wiki/Declarative-API-Overview)上阅读更多关于静态 API 的信息。我们将在*第十章，Angular 应用程序设计和技巧*中介绍响应式 API。您可以在[`github.com/angular/flex-layout/wiki/Responsive-API`](https://github.com/angular/flex-layout/wiki/Responsive-API)上阅读更多关于响应式 API 的信息。

# 向您的应用程序添加 Material 组件

现在我们已经安装了各种依赖项，我们可以开始修改我们的 Angular 应用程序以添加 Material 组件。我们将添加一个工具栏，Material 设计卡片元素，并涵盖基本布局技术以及辅助功能和排版方面的问题。

# Angular Material 原理图

使用 Angular 6 和引入原理图，像 Material 这样的库可以提供自己的代码生成器。在出版时，Angular Material 附带了三个基本的生成器，用于创建具有侧边导航、仪表板布局或数据表的 Angular 组件。您可以在[`material.angular.io/guide/schematics`](https://material.angular.io/guide/schematics)上阅读更多关于生成器原理图的信息。

例如，您可以通过执行以下操作创建一个侧边导航布局：

```ts
$ ng generate @angular/material:material-nav --name=side-nav 

CREATE src/app/side-nav/side-nav.component.css (110 bytes)
CREATE src/app/side-nav/side-nav.component.html (945 bytes)
CREATE src/app/side-nav/side-nav.component.spec.ts (619 bytes)
CREATE src/app/side-nav/side-nav.component.ts (489 bytes)
UPDATE src/app/app.module.ts (882 bytes)
```

此命令更新了`app.module.ts`，直接将 Material 模块导入到该文件中，打破了我之前建议的`material.module.ts`模式。此外，一个新的`SideNavComponent`被添加到应用程序作为一个单独的组件，但正如在第九章中的*侧边导航*部分所提到的，*设计认证和授权*，这样的导航体验需要在应用程序的根部实现。

简而言之，Angular Material 原理图承诺使向您的 Angular 应用程序添加各种 Material 模块和组件变得不那么繁琐；然而，如提供的那样，这些原理图并不适用于创建灵活、可扩展和良好架构的代码库，正如本书所追求的那样。

目前，我建议将这些原理图用于快速原型设计或实验目的。

现在，让我们开始手动向 LocalCast Weather 添加一些组件。

# 使用 Material 工具栏修改着陆页面

在我们开始对 `app.component.ts` 进行进一步更改之前，让我们将组件切换为使用内联模板和内联样式，这样我们就不必在相对简单的组件中来回切换文件。

1.  更新 `app.component.ts` 以使用内联模板

1.  移除 `app.component.html` 和 `app.component.css`

```ts
src/app/app.component.ts import { Component } from '@angular/core'

@Component({
  selector: 'app-root',
  template: `
    <div style="text-align:center">
      <h1>
      LocalCast Weather
      </h1>
      <div>Your city, your forecast, right now!</div>
      <h2>Current Weather</h2>
      <app-current-weather></app-current-weather>
    </div>
  `
})
export class AppComponent {}
```

让我们通过实现一个全局工具栏来改进我们的应用：

1.  观察 `app.component.ts` 中的 `h1` 标签：

```ts
**src/app/app.component.ts**
<h1>
 LocalCast Weather </h1>
```

1.  使用 `mat-toolbar` 更新 `h1` 标签：

```ts
src/app/app.component.ts    
<mat-toolbar>
  <span>LocalCast Weather</span>
</mat-toolbar>
```

1.  观察结果；您应该看到一个工具栏，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/42f5f573-2884-440c-9540-770ed02f0388.png) 本地天气工具栏

1.  使用更引人注目的颜色更新 `mat-toolbar`：

```ts
src/app/app.component.ts    
<mat-toolbar color="primary">
```

为了更加原生的感觉，工具栏与浏览器的边缘接触是很重要的。这在大屏和小屏格式上都很有效。此外，当您将可点击的元素（如汉堡菜单或帮助按钮）放在工具栏的最左侧或最右侧时，您将避免用户点击空白空间的可能性。这就是为什么 Material 按钮实际上具有比视觉表示更大的点击区域。这在打造无挫折的用户体验方面有很大的不同：

```ts
src/styles.css
body {
  margin: 0;
}
```

这对于这个应用来说并不适用，但是，如果您正在构建一个密集的应用程序，您会注意到您的内容将一直延伸到应用程序的边缘，这并不是一个理想的结果。考虑将您的内容区域包裹在一个 div 中，并使用 css 应用适当的边距，如下所示：

```ts
src/styles.css
.content-margin {
  margin-left: 8px;
  margin-right: 8px;
}
```

在下一个截图中，您可以看到应用了主色的边到边工具栏：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7e54cf2f-2240-4a22-866f-b7654818ba92.png) 带有改进工具栏的本地天气

# 在 Material Card 中表示天气

Material 卡片是一个很好的容器，用来表示当前的天气信息。卡片元素被一个投影阴影所包围，将内容与周围区域分隔开来：

1.  在 `material.module` 中导入 `MatCardModule`：

```ts
src/app/material.module.ts
import { ..., MatCardModule} from '@angular/material'
...
@NgModule({
  imports: [..., MatCardModule],
  exports: [..., MatCardModule],
})
```

1.  在 `app.component` 中用 `<mat-card>` 包围 `<app-current-weather>`：

```ts
src/app/app.component.ts
  <div style="text-align:center">
    <mat-toolbar color="primary">
      <span>LocalCast Weather</span>
    </mat-toolbar>
    <div>Your city, your forecast, right now!</div>
    <mat-card>
      <h2>Current Weather</h2>
      <app-current-weather></app-current-weather>
    </mat-card>
  </div>
```

1.  观察如图所示的几乎无法区分的卡片元素：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ad16e3d4-58ff-43d4-8988-a1676f40c863.png) 带有不可区分卡片的本地天气

为了更好地布局屏幕，我们需要切换到 Flex 布局引擎。首先从组件模板中移除训练轮：

1.  从周围的 `<div>` 中移除 `style="text-align:center"`：

要在页面中心放置一个元素，我们需要创建一行，为中心元素分配一个宽度，并在两侧创建两个额外的列，这些列可以灵活地占据空白空间，如下所示：

```ts
src/app/app.component.ts
<div fxLayout="row">
  <div fxFlex></div>
  <div fxFlex="300px">  
    ...
  </div>
  <div fxFlex></div>
</div>
```

1.  用前面的 HTML 包围`<mat-card>`

1.  注意卡片元素已正确居中，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/7bf7efe3-f04f-4bea-a665-6e685e8f8c65.png)带居中卡片的 LocalCast 天气

阅读卡片文档，并查看 Material 文档站点上的示例，您会注意到`mat-card`提供了容纳标题和内容的元素。我们将在接下来的部分中实现这一点。

在[material.angular.io](https://material.angular.io)上，您可以通过单击括号图标查看任何示例的源代码，或者通过单击箭头图标在 Plunker 中启动一个可工作的示例。

# 可访问性

利用这样的 Material 特性可能会感觉不必要；然而，在设计应用程序时，您必须考虑响应性、样式、间距和可访问性问题。Material 团队已经付出了很多努力，以便您的代码在大多数情况下能够正确运行，并为尽可能多的用户群提供高质量的用户体验。这可能包括视力受损或键盘主导用户，他们必须依赖专门的软件或键盘功能（如标签）来浏览您的应用程序。利用 Material 元素为这些用户提供了关键的元数据，使他们能够浏览您的应用程序。

Material 声称支持以下屏幕阅读器软件：

+   Windows 上的 IE / FF / Chrome 上的 NVDA 和 JAWS

+   iOS 上的 Safari 和 Safari / Chrome 上的 VoiceOver

+   Android 上的 Chrome TalkBack

# 卡头和内容

现在，让我们实现`mat-card`的标题和内容元素，如下所示：

```ts
src/app/app.component.ts    
<mat-toolbar color="primary">
  <span>LocalCast Weather</span>
</mat-toolbar>
<div>Your city, your forecast, right now!</div>
<div fxLayout="row">
  <div fxFlex></div>
  <mat-card fxFlex="300px">
    <mat-card-header>
      <mat-card-title>Current Weather</mat-card-title>
    </mat-card-header>
    <mat-card-content>
      <app-current-weather></app-current-weather>
    </mat-card-content>
  </mat-card>
  <div fxFlex></div>
</div>
```

在 Material 中，少即是多。您会注意到我们能够删除中心的`div`，并直接在中心卡上应用`fxFlex`。所有 Material 元素都原生支持 Flex 布局引擎，这在复杂的 UI 中具有巨大的积极维护影响。

应用`mat-card-header`后，您可以看到这个结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/28ccc742-6469-4e94-b138-269bd94daefd.png)带标题和内容的 LocalCast 天气卡

请注意，卡片内的字体现在与 Material 的 Roboto 字体匹配。然而，Current Weather 不再像以前那样引人注目。如果你在 `mat-card-title` 内部添加回 `h2` 标签，Current Weather 在视觉上会显得更大；然而，字体将不再与你的应用程序的其余部分匹配。要解决这个问题，你必须了解 Material 的排版特性。

# Material 排版

Material 的文档恰如其分地将其表述如下：

排版是一种排列字体的方式，使文本在显示时易于辨认、可读和吸引人。

Material 提供了不同级别的排版，具有不同的字体大小、行高和字重特性，你可以应用到任何 HTML 元素上，而不仅仅是提供的组件。

在下表中是你可以使用的 CSS 类，用于应用 Material 的排版，比如 `<div class="mat-display-4">Hello, Material world!</div>`：

| **类名** | **用法** |
| --- | --- |
| `display-4`, `display-3`, `display-2` 和 `display-1` | 大的、一次性的标题，通常位于页面顶部（例如，主标题） |
| `headline ` | 对应 `<h1>` 标签的章节标题 |
| `title ` | 对应 `<h2>` 标签的章节标题 |
| `subheading-2` | 对应 `<h3>` 标签的章节标题 |
| `subheading-1` | 对应 `<h4>` 标签的章节标题 |
| `body-1` | 基本正文文本 |
| `body-2` | 更粗的正文文本 |
| `caption ` | 较小的正文和提示文本 |
| `button` | 按钮和锚点 |

你可以在 [`material.angular.io/guide/typography`](https://material.angular.io/guide/typography) 阅读更多关于 Material 排版的信息。

# 应用排版

有多种方式可以应用排版。一种方式是利用 `mat-typography` 类，并使用相应的 HTML 标签如 `<h2>`：

```ts
src/app/app.component.ts 
<mat-card-header class="mat-typography">
  <mat-card-title><h2>Current Weather</h2></mat-card-title>
</mat-card-header>
```

另一种方式是直接在元素上应用特定的排版，比如 `class="mat-title"`：

```ts
src/app/app.component.ts 
<mat-card-title><div class="mat-title">Current Weather</div></mat-card-title>
```

请注意，`class="mat-title"` 可以应用到 `div`、`span` 或带有相同结果的 `h2` 上。

作为一个一般的经验法则，通常更好的做法是实现更具体和局部化的选项，即第二种实现方式。

# 更新标语为居中对齐的标题

我们可以使用 `fxLayoutAlign` 居中应用程序的标语，并给它一个柔和的 `mat-caption` 排版，如下所示：

1.  实现布局更改和标题排版：

```ts
**src/app/app.component.ts** 
<div fxLayoutAlign="center">
  <div class="mat-caption">Your city, your forecast, right now!</div>
</div>
```

1.  观察结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/6d9d2f32-1481-4e39-a7ae-4438c97290ce.png)LocalCast 天气中心标语居中

# 更新当前天气卡片布局

仍然有更多工作要做，以使 UI 看起来像设计，特别是当前天气卡片的内容，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c7872ffe-c0e2-4cba-8afc-206e4eaaec03.png)

为了设计布局，我们将利用 Angular Flex。

您将编辑`current-weather.component.html`，该文件使用`<div>`和`<span>`标签来建立分别位于不同行或同一行上的元素。随着切换到 Angular Flex，我们需要将所有元素切换为`<div>`，并使用`fxLayout`指定行和列。

# 实施布局脚手架

我们需要首先实现粗糙的脚手架。

考虑模板的当前状态：

```ts
 src/app/current-weather/current-weather.component.html
 1 <div *ngIf="current">
 2  <div>
 3    <span>{{current.city}}, {{current.country}}</span>
 4    <span>{{current.date | date:'fullDate'}}</span>
 5  </div>
 6  <div>
 7    <img [src]='current.image'>
 8    <span>{{current.temperature | number:'1.0-0'}}℉</span>
 9  </div>
10  <div>
11    {{current.description}}
12  </div>
13 </div>
```

让我们逐步通过文件并更新它：

1.  将第 3、4 和 8 行的`<span>`元素更新为`<div>`

1.  用`<div>`包装`<img>`元素

1.  在第 2 行和第 6 行有多个子元素的`<div>`元素上添加`fxLayout="row"`属性

1.  城市和国家列大约占据了屏幕的 2/3，因此在第 3 行的`<div>`元素上添加`fxFlex="66%"`

1.  在第 4 行的下一个`<div>`元素上添加`fxFlex`，以确保它占据其余的水平空间

1.  在新的`<div>`元素周围添加`fxFlex="66%"`，以包围`<img>`元素

1.  在第 4 行的下一个`<div>`元素上添加`fxFlex`

模板的最终状态应该如下所示：

```ts
 src/app/current-weather/current-weather.component.html
 1 <div *ngIf="current">
 2   <div fxLayout="row">
 3     <div fxFlex="66%">{{current.city}}, {{current.country}}</div>
 4     <div fxFlex>{{current.date | date:'fullDate'}}</div>
 5   </div>
 6   <div fxLayout="row">
 7     <div fxFlex="66%">
 8       <img [src]='current.image'>
 9     </div>
10     <div fxFlex>{{current.temperature | number:'1.0-0'}}℉</div>
11   </div>
12   <div>
13    {{current.description}}
14  </div>
15 </div>
```

您可以在添加 Angular Flex 属性时更详细; 但是，您写的代码越多，将来需要维护的内容就越多，这会使未来的更改变得更加困难。例如，第 12 行的`<div>`元素不需要`fxLayout="row"`，因为`<div>`隐式地换行。同样，在第 4 行和第 7 行，右侧列不需要显式的`fxFlex`属性，因为它将自动被左侧元素挤压。

从网格放置的角度来看，所有元素现在都在正确的*单元格*中，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/55cad2dd-c7cf-40c2-a1c3-b6fb224128f5.png)带有布局脚手架的 LocalCast 天气

# 对齐元素

现在，我们需要对齐和样式化每个单独的单元格以匹配设计。日期和温度需要右对齐，描述需要居中：

1.  要右对齐日期和温度，请在`current-weather.component.css`中创建一个名为`.right`的新 css 类：

```ts
src/app/current-weather/current-weather.component.css
.right {
  text-align: right
}
```

1.  在第 4 行和第 10 行的`<div>`元素中添加`class="right"`

1.  以与之前章节中应用标语居中的方式居中`<div>`元素的描述

1.  观察元素是否正确对齐，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/4d1dc5c5-d03b-42cc-a401-a78812906c9e.png)具有正确对齐的 LocalCast 天气

# 样式元素

最终确定元素的样式通常是前端开发中最耗时的部分。我建议进行多次尝试，首先以最小的努力实现设计的足够接近版本，然后让您的客户或团队决定是否值得额外投入更多时间来完善设计：

1.  添加一个新的 css 属性：

```ts
src/app/current-weather/current-weather.component.css
.no-margin {
  margin-bottom: 0
}
```

1.  对于城市名称，在第 3 行，添加'class="mat-title no-margin"'

1.  对于日期，在第 4 行，添加"mat-subheading-2 no-margin"到'class="right"'

1.  将日期格式从'fullDate'更改为'EEEE MMM d'以匹配设计

1.  修改`<img>,`在第 8 行添加`style="zoom: 175%"`

1.  对于温度，在第 10 行，追加"mat-display-3 no-margin"

1.  对于描述，在第 12 行，添加'class="mat-caption"'

这是模板的最终状态：

```ts
src/app/current-weather/current-weather.component.html
<div *ngIf="current">
  <div fxLayout="row">
    <div fxFlex="66%" class="mat-title no-margin">{{current.city}}, {{current.country}}</div>
    <div fxFlex class="right mat-subheading-2 no-margin">{{current.date | date:'EEEE MMM d'}}</div>
  </div>
  <div fxLayout="row">
    <div fxFlex="66%">
      <img style="zoom: 175%" [src]='current.image'>
    </div>
    <div fxFlex class="right mat-display-3 no-margin">{{current.temperature | number:'1.0-0'}}℉</div>
  </div>
  <div fxLayoutAlign="center" class="mat-caption">
    {{current.description}}
  </div>
</div>
```

1.  观察您的代码的样式化输出如何改变，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a48e4e8a-d448-438b-b6a4-b0da85fc268e.png)带有样式的 LocalCast 天气

# 微调样式

标语可以从顶部和底部边距中受益。这是我们可能会在整个应用程序中使用的常见 CSS，所以让我们把它放在'styles.css'中：

1.  实现'vertical-margin'：

```ts
src/styles.css
.vertical-margin {
  margin-top: 16px;
  margin-bottom: 16px;
}
```

1.  应用'vertical-margin'：

```ts
src/app/app.component.ts
<div class="mat-caption vertical-margin">Your city, your forecast, right now!</div>
```

当前天气与城市名称具有相同的样式；我们需要区分这两者。

1.  在'app.component.ts'中，使用'mat-headline'排版更新当前天气：

```ts
src/app/app.component.ts
<mat-card-title><div class="mat-headline">Current Weather</div></mat-card-title>
```

1.  图像和温度没有居中，因此在第 6 行的围绕这些元素的行中添加'fxLayoutAlign="center center"':

```ts
src/app/current-weather/current-weather.component.html
<div fxLayout="row" fxLayoutAlign="center center">
```

1.  观察您的应用程序的最终设计，应该是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/bf49f665-4779-4c99-93f5-5f5a2a176a0c.png)LocalCast 天气最终设计

# 微调以匹配设计

这是一个你可能会花费大量时间的领域。如果我们遵循 80-20 原则，像素完美的微调通常最终成为需要花费 80%的时间来完成的最后 20%。让我们来看看我们的实现与设计之间的差异以及弥合差距需要付出的努力：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/77565e77-0a6a-4088-8dab-f487cc8133d3.png)

日期需要进一步定制。缺少数字序数*th*; 为了实现这一点，我们需要引入第三方库，如 moment，或者实现我们自己的解决方案，并将其绑定到模板上的日期旁边：

1.  更新'current.date'以附加序数：

```ts
src/app/current-weather/current-weather.component.html
{{current.date | date:'EEEE MMM d'}}{{getOrdinal(current.date)}}
```

1.  实现一个`getOrdinal`函数：

```ts
src/app/current-weather/current-weather.component.ts export class CurrentWeatherComponent implements OnInit {
...
  getOrdinal(date: number) {
    const n = new Date(date).getDate()
    return n > 0
      ? ['th', 'st', 'nd', 'rd'][(n > 3 &amp;&amp; n < 21) || n % 10 > 3 ? 0 : n % 10]
      : ''
  }
  ...
}
```

请注意，`getOrdinal`的实现归结为一个复杂的一行代码，不太可读，很难维护。如果这样的函数对您的业务逻辑至关重要，应该进行大量的单元测试。

在撰写本文时，Angular 6 不支持日期模板中的新行换行；理想情况下，我们应该能够将日期格式指定为`'EEEE\nMMM d'`，以确保换行始终保持一致。

温度的实现需要使用`<span>`元素将数字与单位分开，用`<p>`包围，以便可以将上标样式应用到单位，例如`<span class="unit">℉</span>`，其中 unit 是一个 CSS 类，使其看起来像一个上标元素。

1.  实现一个`unit` CSS 类：

```ts
src/app/current-weather/current-weather.component.css
.unit {
  vertical-align: super;
}
```

1.  应用`unit`：

```ts
src/app/current-weather/current-weather.component.html
...   
 7 <div fxFlex="55%">
...
10 <div fxFlex class="right no-margin">
11   <p class="mat-display-3">{{current.temperature | number:'1.0-0'}}
12     <span class="mat-display-1 unit">℉</span>
13   </p>
```

我们需要通过调整第 7 行的`fxFlex`值来实验预报图像应该有多少空间。否则，温度会溢出到下一行，并且您的设置还会受到浏览器窗口大小的影响。例如，`60%`在小浏览器窗口下效果很好，但当最大化时会导致溢出。然而，`55%`似乎满足了两个条件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/4e0df4b3-6917-409e-8d70-2ce2fd05e3c3.png)调整后的 LocalCast 天气

与往常一样，可以进一步调整边距和填充以进一步定制设计。然而，每一次偏离库都会在以后产生可维护性后果。除非您真的要围绕显示天气数据构建业务，否则应该在项目结束时推迟任何进一步的优化，如果时间允许，如果经验是任何指导，您将不会进行这种优化。

通过两个负的 margin-bottom hack，你可以获得一个与原始设计非常接近的设计，但我不会在这里包含这些 hack，而是留给读者在 GitHub 存储库中发现。这些 hack 有时是必要的恶，但总的来说，它们指向设计和实现现实之间的脱节。在调整部分之前的解决方案是甜蜜点，Angular Material 在这里蓬勃发展：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/414f1e2e-7bb5-48c9-a6f6-3c1326a1c882.png)调整和 hack 后的 LocalCast 天气

# 更新单元测试

为了保持您的单元测试运行，您需要将`MaterialModule`导入到任何使用 Angular Material 的组件的`spec`文件中：

```ts
*.component.spec.ts
...
  beforeEach(
    async(() => {
      TestBed.configureTestingModule({
        ...
        imports: [..., MaterialModule, NoopAnimationsModule],
      }).compileComponents()
    })
  )
```

你还需要更新任何测试，包括 e2e 测试，以搜索特定的 HTML 元素。

例如，由于应用程序的标题 LocalCast Weather 不再在`h1`标签中，你必须更新`spec`文件，以在`span`元素中查找它：

```ts
src/app/app.component.spec.ts
expect(compiled.querySelector('span').textContent).toContain('LocalCast Weather')
```

同样，在 e2e 测试中，你需要更新你的页面对象函数，以从正确的位置检索文本：

```ts
e2e/app.po.ts
getParagraphText() {
  return element(by.css('app-root mat-toolbar span')).getText()
}
```

# 自定义主题

正如我们之前讨论的，Material 默认提供了一些默认主题，如深紫色-琥珀色、蓝紫色-粉色、粉色-蓝灰色和紫色-绿色。然而，你的公司或产品可能有自己的配色方案。为此，你可以创建一个自定义主题，改变你的应用程序的外观。

为了创建一个新的主题，你必须实现一个新的 scss 文件：

1.  在`src`下创建一个名为`localcast-theme.scss`的新文件

1.  Material 主题指南，位于[`material.angular.io/guide/theming`](https://material.angular.io/guide/theming)，包括一个最新的起始文件。我将进一步解释文件的内容

1.  首先包含基础主题库：

```ts
src/localcast-theme.scss
@import '~@angular/material/theming';
```

1.  导入`mat-core()` mixin，其中包括各种 Material 组件使用的所有通用样式：

```ts
src/localcast-theme.scss
@include mat-core();
```

`mat-core()`应该只在你的应用程序中包含一次；否则，你将在应用程序中引入不必要和重复的 css 负载。

`mat-core()`包含必要的 scss 函数，可以将自定义颜色注入到 Material 中，例如 mat-palette、mat-light-theme 和 mat-dark-theme。

至少，我们必须定义一个新的主色和一个强调色。然而，定义新的颜色并不是一个简单的过程。Material 需要定义一个调色板，mat-palette，它需要由一个复杂的颜色对象种子化，不能简单地被一个简单的十六进制值如`#BFB900`所覆盖。

要选择你的颜色，可以使用位于[`material.io/color`](https://material.io/color)的 Material Design Color Tool。这是工具的截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/8f3bf1d1-8b8c-4e8c-9c48-b4d4f2a2c6ff.png)Material.io 颜色工具

1.  使用 Material Palette，选择一个主色和一个次要颜色：

+   我的主要选择是红色，色调值为`500`

+   我的次要选择是蓝紫色，色调值为`A400`

1.  通过浏览左侧的 6 个预构建屏幕，观察你的选择如何应用到 Material 设计应用程序

1.  评估你的选择对可访问性的影响，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/12c7fbf2-e1ea-4800-ae75-87bc62b30a05.png)Material.io 颜色工具可访问性选项卡该工具警告我们，我们的选择导致不合格的文本，当白色文本用于主要颜色时。您应该注意避免在主要颜色上显示白色文本，或更改您的选择。

`mat-palette`的接口如下所示：

```ts
mat-palette($base-palette, $default: 500, $lighter: 100, $darker: 700)
```

1.  使用工具的默认色调定义主要和次要的`mat-palette`对象：

```ts
src/localcast-theme.scss
$localcast-primary: mat-palette($mat-red, 500);
$localcast-accent: mat-palette($mat-indigo, A400);
```

1.  创建一个新主题并应用它：

```ts
src/localcast-theme.scss
$localcast-app-theme: mat-light-theme($localcast-primary, $localcast-accent);

@include angular-material-theme($localcast-app-theme);
```

1.  在`angular.json`中，找到`apps.styles`属性

1.  在删除`styles.input`属性的同时，在列表前加上`localcast-theme.scss`

```ts
angular.json
...      
"styles": [
  "src/localcast-theme.scss",
  "src/styles.css"
],
...
```

即使您的主题是 scss，您仍然可以在应用程序的其余部分使用 css。Angular CLI 支持编译 scss 和 css。如果您想更改默认行为，可以通过将`angular.json`文件中的`defaults.styleExt`属性从 css 更改为 scss 来完全切换到 scss。

您还可以选择消除`styles.css`并将其内容与`localcast-theme.scss`合并，或者通过简单将其重命名为`styles.scss`将`styles.css`转换为 sass 文件。如果这样做，不要忘记更新`angular.json`。

您的应用程序现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/43caf8be-eb2d-49ea-ba98-27770c9852e5.png)带有自定义主题的 LocalCast 天气

我们现在可以将 UX 任务移动到已完成的列中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a334c98f-f445-4c4a-81cb-97ecf78285ac.png)Waffle.io 看板状态

# 高级主题

为了创建更多定制的主题，您应该考虑使用 Material Design 主题调色板生成器[`mcg.mbitson.com`](http://mcg.mbitson.com)。这将生成定义自定义颜色调色板以创建真正独特主题所需的代码。

您还可以在[`meyerweb.com/eric/tools/color-blend`](https://meyerweb.com/eric/tools/color-blend)找到颜色混合器，以找到两种颜色之间的中间点。

# 更新 Angular Material

在第四章中，*与 Angular 更新保持最新*，我们利用了`ng update`进行自动升级体验，并介绍了手动和系统化的更新包方法。我们将在更新 Angular Material 时采用类似的策略。

您可以使用`ng update`来快速且无痛的升级体验，应该如下所示：

```ts
$ npx ng update @angular/material
 Updating package.json with dependency @angular/cdk @ "6.0.0" (was "5.2.2")...
 Updating package.json with dependency @angular/material @ "6.0.0" (was "5.2.2")...
UPDATE package.json (5563 bytes)
```

此外，我发现了 Angular 团队在 [`github.com/angular/material-update-tool`](https://github.com/angular/material-update-tool) 发布的 `material-update-tool`。目前这个工具被宣传为一个特定的 Angular Material 5.x 到 6.0 的更新工具，因此它可能在未来成为 `ng update` 的一部分，就像 `rxjs-tslint` 工具一样。您可以按照下面的示例运行该工具：

```ts
$ npx angular-material-updater -p .\src\tsconfig.app.json

√ Successfully migrated the project source files. Please check above output for issues that couldn't be automatically fixed.
```

如果您幸运并且一切顺利，可以随意跳过本节的其余部分。在本节的其余部分中，我将介绍我在开发此示例时遇到的涉及发布候选版本和 Beta 版本的特定情况，这突显了手动更新的必要性。首先，我们将了解当前版本，然后发现最新可用版本，最后，更新和测试升级，就像我们手动更新 Angular 时所做的那样。

# 对您当前的版本进行盘点

观察 `package.json` 中的 Angular Material 包版本：

```ts
package.json
"dependencies": {
  "@angular/core": "⁵.0.0",
  ...
  "@angular/animations": "⁵.0.0",
  "@angular/cdk": "⁵.0.0-rc0",
  "@angular/flex-layout": "².0.0-beta.10-4905443", 
  "@angular/material": "⁵.0.0-rc0",
  "hammerjs": "².0.8",
},
```

在这种特殊情况下，我在 RC 阶段安装了 Material 5.0.0。建议不要发布 Beta 或 RC 库。由于我们的 `@angular/core` 包指示我们使用的是 Angular 版本 5.0.0，我们将目标升级到最新的 Angular Material 5.x.x 版本。

# 检查最新可用版本

我们将利用 npm CLI 工具来发现 Angular Material 的最新可用版本：

1.  执行 `npm info @angular/material` 并观察输出：

```ts
{ 
  name: '@angular/material',
  description: 'Angular Material',
  'dist-tags': { latest: '5.0.0' },
  versions:
   [ ...
     '5.0.0-rc.0',
     '5.0.0-rc.1',
     '5.0.0-rc.2',
     '5.0.0-rc.3',
     '5.0.0-rc0',
     '5.0.0' ],
...
time: {
  created: ...
     '5.0.0-rc0': '2017-11-06T20:15:29.863Z',
     '5.0.0-rc.1': '2017-11-21T00:38:56.394Z',
     '5.0.0-rc.0': '2017-11-27T19:21:19.781Z',
     '5.0.0-rc.2': '2017-11-28T00:13:13.487Z',
     '5.0.0-rc.3': '2017-12-05T21:20:42.674Z',
     '5.0.0': '2017-12-06T20:19:25.466Z' 
}

```

您可以观察到，结合输出中更深层的时间信息，自 `5.0.0-rc0` 发布以来已经推出了 5 个新版本，最终版本是库的主要版本 5.0.0 发布。

如果 Material 库有其他主要版本可用，比如 6.0.0，您仍应坚持使用 5.x.x 版本，因为我们的 `@angular/core` 版本是 5.x.x。一般来说，您应该保持 Angular 和 Material 的主要版本相同。

1.  研究 `@angular/core`、`@angular/animations`、`@angular/cdk`、`@angular/flex-layout`、`@angular/material` 和 `hammerjs` 的最新可用版本。

1.  为了减少您需要筛选的信息量，对每个包执行 `npm info <package-name>` versions

1.  将您的发现记录在类似以下的表中；我们将讨论如何确定您的目标版本：

| **包** | **当前** | **最新** | **目标** |
| --- | --- | --- | --- |
| @angular/core | 5.0.0 | 5.1.0 | 5.0.0 |
| @angular/animations | 5.0.0 | 5.1.0 | 5.0.0 |
| @angular/cdk | 5.0.0-rc0 | 5.0.0 | 5.0.0 |
| @angular/flex-layout | 2.0.0-beta.10-4905443 | 2.0.0-rc.1 | 2.x.x |
| @angular/material | 5.0.0-rc0 | 5.0.0 | 5.0.0 |
| hammerjs | 2.0.8 | 2.0.8 | 2.x.x |

研究结果表明，发布了新的 Angular 小版本，这是有用的信息。在确定目标版本时，要保守。遵循以下指导：

+   在更新 Material 时不要更新 Angular 组件

+   如果您打算同时更新 Angular 组件，请分阶段进行，并确保在每个单独阶段之后执行测试

+   将任何 Beta 或 RC 软件包更新到其最新可用版本

+   当软件包的新版本可用时，保持在软件包的相同主要版本中

+   除非文档另有建议，否则遵循这些指南

# 更新 Angular Material

现在我们知道要升级到哪个版本，让我们继续进行：

1.  执行以下命令以将 Material 及其相关组件更新到其目标版本：

```ts
$ npm install @angular/material@⁵.0.0 @angular/cdk@⁵.0.0 @angular/animations@⁵.0.0 @angular/flex-layout@².0.0-rc.1
```

1.  验证您的`package.json`以确保版本与预期版本匹配

1.  解决任何 NPM 警告（详见第四章，*与 Angular 更新保持最新*，*更新 Angular*部分）

在这种特定情况下，我收到了无法满足的`@angular/flex-layout`包的对等依赖警告。在 GitHub 上进一步调查（[`github.com/angular/flex-layout/issues/508`](https://github.com/angular/flex-layout/issues/508)）显示这是一个已知问题，通常可以从 Beta 或 RC 包中预期到。这意味着可以安全地忽略这些警告。

升级完成后，请确保执行“后续更新清单”，详见第四章，*与 Angular 更新保持最新*。

# 摘要

在本章中，您了解了什么是 Angular Material，如何使用 Angular Flex 布局引擎，UI 库对性能的影响，以及如何将特定的 Angular Material 组件应用于您的应用程序。您意识到了过度优化 UI 设计的陷阱，以及如何向应用程序添加自定义主题。我们还讨论了如何保持 Angular Material 的最新状态。

在下一章中，我们将更新天气应用程序，以响应用户输入使用响应式表单，并保持我们的组件解耦，同时还使用`BehaviorSubject`在它们之间实现数据交换。在下一章之后，我们将完成天气应用程序，并将重点转移到构建更大的业务应用程序。
