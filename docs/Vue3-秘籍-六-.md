# Vue3 秘籍（六）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：将应用程序部署到云平台

现在是时候将您的应用程序部署到全球范围内，使其对全球所有人都可用。

在这一章中，我们将学习如何在三个不同的托管平台上进行操作 - Netlify，Now 和 Firebase。在这里，我们将学习在每个平台上创建帐户的过程，设置环境，配置应用程序以进行部署，最后将其部署到网络上。

在本章中，我们将涵盖以下配方：

+   创建 Netlify 帐户

+   为在 Netlify 上部署应用程序做准备

+   为在 GitHub 上的 Netlify 进行自动部署做准备

+   创建一个 Vercel 帐户

+   配置 Vercel-CLI 并部署您的项目

+   为在 GitHub 上的 Vercel 进行自动部署做准备

+   创建一个 Firebase 项目

+   配置 Firebase-CLI 并部署您的项目

# 技术要求

在本章中，我们将使用**Node.js**和**Vue-CLI**。

注意 Windows 用户！您需要安装一个名为 windows-build-tools 的 NPM 包，以便能够安装以下必需的软件包。要做到这一点，以管理员身份打开 PowerShell 并执行以下命令：`> npm install -g windows-build-tools`

要安装 Vue-CLI，您需要打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

## 创建一个 Vue 项目

要创建一个 Vue-CLI 项目，请按照以下步骤进行：

1.  打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> vue create vue-project
```

1.  Vue-CLI 将要求您选择一个预设；使用*空格键*选择`Manually select features`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features 
```

1.  现在，Vue-CLI 将要求选择功能，您需要选择`Router`，`Vuex`和`Linter / Formatter`作为默认功能之外的附加功能：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support ❯ Router ❯ Vuex
  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  现在，Vue-CLI 将询问您是否要使用历史模式进行路由管理。我们将选择`y`（是）：

```js
?  Use history mode for router? (Requires proper server setup for 
  index fallback in production)  (Y**/n) y** 
```

1.  通过选择 linter 和 formatter 来继续该过程。我们将选择`ESLint + Airbnb config`：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  选择 linter 的附加功能（这里是`Lint and fix on commit`）：

```js
?  Pick additional lint features: (Use arrow keys) Lint on save ❯ Lint and fix on commit
```

1.  选择您想要放置 linter 和 formatter 配置文件的位置（这里是`In dedicated config files`）：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  最后，CLI 将询问您是否要保存未来项目的设置；您将选择`N`。之后，Vue-CLI 将为您创建文件夹并安装依赖项：

```js
?  Save this as a preset for future projects?  (y/N) n
```

# 创建 Netlify 帐户

现在是时候开始将部署过程到 Netlify 平台。在这个教程中，我们将学习如何创建我们的 Netlify 账户，以便我们可以将我们的应用程序部署到网络上。

## 准备就绪

本教程的先决条件如下：

+   一个电子邮件地址

+   GitHub 账户

+   一个 GitLab 账户

+   一个 BitBucket 账户

在创建 Netlify 账户的过程中，您可以使用**电子邮件**地址、**GitHub**账户、**GitLab**账户或**BitBucket**账户来实现这一点。

## 如何做...

在这里，我们将学习如何使用电子邮件地址创建 Netlify 账户：

1.  转到 Netlify 网站[`www.netlify.com/`](https://www.netlify.com/)，并在页眉菜单中单击**注册→**。您将被重定向到初始**注册**页面。

1.  在这个页面上，您可以选择您想要使用的注册 Netlify 的方法。在这个过程中，我们将继续使用电子邮件地址。点击**电子邮件**按钮，将被重定向到电子邮件注册表单。

1.  填写表单，使用您选择的电子邮件地址和密码。密码规则为最少 8 个字符。填写完表单后，点击**注册**按钮。然后，您将被重定向到成功页面。

1.  现在，您将在收件箱中收到一封验证电子邮件，您需要这封邮件才能继续使用 Netlify 平台。要继续，请打开您的电子邮件收件箱并检查 Netlify 的电子邮件。

1.  在您的电子邮件收件箱中，打开 Netlify 的电子邮件，然后点击**验证电子邮件**按钮。此时，将打开一个新窗口，您将能够使用最近注册的电子邮件和密码登录。

1.  在这里，您可以使用您在第 3 步选择的电子邮件地址和密码填写登录表单。之后，点击登录按钮，将被重定向到 Netlify 平台的主窗口。

1.  最后，您将发现自己在 Netlify 平台的主屏幕上，有一个空白页面可以开始在平台上部署。

## 它是如何工作的...

在这个教程中，我们学习了如何在 Netlify 上创建我们的账户。我们看到可以使用各种 OAuth 方法和我们在教程中使用的基本电子邮件来实现这一点。

电子邮件地址创建过程涉及定义将要使用的电子邮件地址和账户密码，验证账户电子邮件。然后，您可以登录到平台。

## 另请参阅

在[`docs.netlify.com/`](https://docs.netlify.com/)找到更多关于 Netlify 的信息。

# 为在 Netlify 中部署应用程序做准备

要开始部署过程，我们需要配置我们的项目以具有有效的 Netlify 部署模式。在这个食谱中，您将学习如何在任何基于 Vue 的应用程序上设置 Netlify 部署模式。

## 做好准备

这个食谱的先决条件如下：

+   Node.js 12+

+   一个 Vue 项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做…

在这个食谱中，我们将学习如何准备我们的应用程序以部署到 Netlify：

1.  打开您的 Vue 项目并打开`package.json`文件。检查是否已定义`build`脚本，如下例所示：

```js
"scripts": {
  "serve": "Vue-CLI-service serve",
  "build": "Vue-CLI-service build",
  "lint": "Vue-CLI-service lint" },
```

1.  打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）并执行以下命令：

```js
> npm run build
```

1.  确保您的应用程序的`build`脚本在主文件夹中创建一个`dist`文件夹。

1.  如果您的`vue-router`被定义为与历史模式一起工作，您必须在`public`文件夹中创建一个`_redirects`文件。在这个文件中，您需要添加指示给 Netlify 路由器的指令：

```js
# Netlify settings for single-page application
/*    /index.html   200
```

1.  将您的应用程序发布到 GitHub 存储库。不用担心构建文件夹，因为它已经在`.gitignore`文件中声明，并且不会发送到您的存储库。

## 它是如何工作的…

在这个食谱中，我们学习了如何检查和准备我们的应用程序进行 Netlify 部署。

为了使部署工作，我们需要确保在`package.json`的脚本部分中有`build`命令，并验证构建目标是`dist`文件夹。

最后，我们在 public 文件夹中创建了一个`_redirects`文件，以指示 Netlify 路由器理解 vue-router 的历史模式。

## 另请参阅

在[`cli.vuejs.org/guide/deployment.html#netlify`](https://cli.vuejs.org/guide/deployment.html#netlify)上查找有关 Netlify 部署的官方 Vue-CLI 文档的更多信息。

在[`docs.netlify.com/routing/redirects/rewrites-proxies/#history-pushstate-and-single-page-apps`](https://docs.netlify.com/routing/redirects/rewrites-proxies/#history-pushstate-and-single-page-apps)上查找有关 Netlify 路由器重写的更多信息。

# 为在 GitHub 上自动部署到 Netlify 做准备

是时候为部署做准备了。在这个食谱中，您将学习如何设置 Netlify 部署过程，以便在 GitHub 上自动获取并部署您的应用程序。

## 做好准备

这个食谱的先决条件如下：

+   一个 Netlify 账户

+   一个 Vue 项目

+   一个 GitHub 账户

## 如何做…

最后，在创建 Netlify 帐户，将项目发布到 GitHub 存储库并配置所有内容之后，现在是时候准备 Netlify 平台以在每次 GitHub 推送时执行自动部署了：

1.  转到 Netlify（[`www.netlify.com/`](https://www.netlify.com/)），登录并打开您的初始仪表板。在那里，您会找到一个来自 Git 的新站点按钮。您将被重定向到创建新站点页面。

1.  现在，您可以单击 GitHub 按钮打开一个新窗口，以在 GitHub 上进行 Netlify 授权并在那里继续该过程。

1.  使用您的 GitHub 帐户登录，然后您将被重定向到应用程序安装页面。

1.  在此页面上，您可以选择向 Netlify 提供对所有存储库的访问权限，或仅选择的存储库，但请确保使您的应用程序的存储库可用。

1.  在 GitHub 上完成 Netlify 的安装后，您在上一步中授予访问权限的存储库将可以在 Netlify 平台上选择。选择包含您的应用程序的存储库。

1.  完成创建过程，您需要选择用于自动部署的分支。然后，您需要填写应用程序中使用的构建命令，在我们的情况下是`npm run build`。打开包含构建文件的文件夹，在我们的情况下是`dist`文件夹，并单击“部署站点”按钮。

1.  最后，Netlify-CLI 将启动构建过程，并在构建完成且没有任何错误时发布您的应用程序。

## 工作原理...

Netlify 平台连接到您的 GitHub 帐户并安装为应用程序，从而可以访问选定的存储库。然后，在平台上，您可以选择要用于部署的存储库。选择存储库后，我们需要使用构建说明和构建目标文件夹配置 Netlify-CLI。最后，CLI 运行，我们的应用程序就可以在网络上运行了。

## 另请参阅

在[`docs.netlify.com/configure-builds/file-based-configuration/`](https://docs.netlify.com/configure-builds/file-based-configuration/)上查找有关高级 Netlify 部署的更多信息。

# 创建 Vercel 帐户

Vercel 是一个著名的平台，用于在网络上部署您的应用程序。使用 Vercel，您可以自动化与 GitHub、GitLab 和 BitBucket 的部署过程。在本教程中，我们将学习如何在 Vercel 平台上创建我们的帐户。

## 准备就绪

这个教程的先决条件只是以下选项之一：

+   一个 GitHub 账户

+   一个 GitLab 账户

+   一个 BitBucket 账户

## 如何做...

让我们开始在 Vercel 平台上的旅程。在这里，我们将学习如何在平台上创建我们的账户以开始我们的项目部署：

1.  打开 Vercel 网站（[`vercel.com/`](https://vercel.com/)），并点击顶部栏的注册按钮。您将被重定向到注册页面。

1.  在这里，您可以选择这些存储库管理器中的一个 - GitHub、GitLab 或 BitBucket。我们将继续点击**GitHub**按钮。选择注册方法后，您将被重定向到授权页面。

1.  在此页面上，您正在授权 Vercel 平台访问您账户上的信息。点击**授权**按钮后，您将被重定向回 Vercel 仪表板。

1.  最后，您已经创建了 Vercel 账户，并准备好使用。

## 它是如何工作的...

在这个教程中，我们进入了 Vercel 平台，并使用存储库管理器注册了它。我们能够创建我们的账户，并且现在可以通过存储库集成或 CLI 工具在平台上开始部署过程。

## 另请参阅

您可以在[`vercel.com/`](https://vercel.com/)找到有关 Vercel 的更多信息。

# 配置 Vercel-CLI 并部署您的项目

您已经创建了一个 Vercel 账户。现在是时候在您的项目上配置 Vercel-CLI，以便它可以在 Vercel 平台和 Web 上使用。

## 准备工作

这个教程的先决条件如下：

+   一个 Vercel 账户

+   一个 Vue 项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

+   `vercel`

要安装`vercel`，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> npm i -g vercel
```

## 如何做...

在这个教程中，我们将学习如何通过 Vercel-CLI 将我们的项目链接到 Vercel 平台，然后使用它部署平台：

1.  打开您的 Vue 项目，然后打开`package.json`文件。检查您是否定义了`build`脚本，如下例所示：

```js
"scripts": {
  "serve": "Vue-CLI-service serve",
  "build": "Vue-CLI-service build",
  "lint": "Vue-CLI-service lint" },
```

1.  确保您的应用构建脚本在主文件夹中创建一个`dist`文件夹。

1.  在您的`project`文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vercel
```

这将提示您登录 Vercel 平台：

```js
> No existing credentials found. Please log in:
 Enter your email:
```

1.  输入与您用于登录 Vercel 的仓库管理器相关联的电子邮件地址。您将收到一封带有“验证”按钮的电子邮件；点击它以验证您的电子邮件地址：

1.  一旦您的电子邮件地址得到验证，您就可以使用`> vercel`命令在您的终端中部署应用程序。

1.  要将应用程序部署到网络上，我们需要在`project`文件夹中执行`> vercel`命令，并且在部署之前它会询问一些关于项目设置的问题。第一个问题将涉及项目路径：

```js
? Set up and deploy "~/Versionamento/Vue.js-3.0-Cookbook/chapter-
   14/14.5"? [Y/n] y
```

1.  现在它将要求您定义将部署项目的范围。当您在同一用户名下定义了多个帐户访问选项时使用。在大多数情况下，它只会有一个，您可以按*Enter*：

```js
? Set up and deploy "~/Versionamento/Vue.js-3.0-Cookbook/chapter-
   14/14.5"? y
? Which scope do you want to deploy to? ❯ **Heitor Ramon Ribeiro**  
```

1.  然后，它将要求链接到 Vercel 上的现有项目。在我们的情况下，这是一个全新的项目，所以我们将选择`n`：

```js
? Link to existing project? [Y/n] n
```

1.  您将被要求定义项目的名称（只允许小写字母数字字符和连字符）：

```js
? What's your project's name? vuejscookbook-12-5
```

1.  您现在需要定义项目源代码的位置。此位置是`package.json`文件所在的位置；在我们的情况下，这将是`./`文件夹，或者主项目文件夹：

```js
? In which directory is your code located? ./
```

1.  Vercel-CLI 将检测到项目是一个 Vue-CLI 项目，并将自动定义所有用于部署应用程序的命令和目录设置。在我们的情况下，我们将选择`n`。

```js
Auto-detected Project Settings (Vue.js): - Build Command: `npm run build` or `Vue-CLI-service build` - Output Directory: dist - Development Command: Vue-CLI-service serve --port $PORT ? Want to override the settings? [y/N] n
```

1.  一切设置完成后，CLI 将部署应用程序的第一个预览，并将发送一个链接以访问应用程序的预览。要将应用程序部署为生产就绪状态，您需要在 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）中执行以下命令：

```js
> vercel --prod
```

## 它是如何工作的...

在这个教程中，我们学习了如何将 Vercel-CLI 连接到与仓库管理器相关联的电子邮件地址的在线平台，并设置项目部署。

在这个过程中，我们学习了如何通过定义构建命令、分发文件夹和开发命令来配置 CLI 的高级选项。

最后，我们能够在将项目部署到生产环境之前获得项目的预览 URL。

## 另请参阅

您可以在[`vercel.com/docs/cli?query=CLI#getting-started`](https://vercel.com/docs/cli?query=CLI#getting-started)找到有关 Vercel-CLI 的更多信息。

您可以在[`vercel.com/docs/configuration?query=now.json#introduction/configuration-reference`](https://vercel.com/docs/configuration?query=now.json#introduction/configuration-reference)找到有关 Vercel 高级配置的更多信息。

# 准备在 GitHub 上使用 Vercel 进行自动部署

在上一个教程中，我们学习了如何使用 Vercel-CLI 将我们的应用程序部署到网络上，使用您的本地终端，但是可以将存储库管理器与 Vercel 平台集成，并通过任何推送或打开拉取请求自动部署。这就是我们将在这个教程中做的事情。

## 准备工作

本教程的先决条件如下：

+   Vercel 帐户

+   存储库管理器上的 Vue 项目

## 如何做...

在这个教程中，我们将学习如何将 Vercel 平台与存储库管理器集成，并进行自动部署：

1.  打开您的 Vercel 仪表板（[`vercel.com/dashboard`](https://vercel.com/dashboard)）并点击导入项目按钮。

1.  在导入项目页面上，点击**继续**按钮，位于来自 Git 存储库卡内。

1.  现在，Vercel 网站将询问持有您要导入的项目的存储库的用户是否是您的个人帐户。如果是，请点击**是**。如果不是，Vercel 将在开始该过程之前将该项目分叉到您的个人帐户。

1.  然后，Vercel 将询问您要将项目绑定到哪个帐户。在我们的情况下，这将是我们的个人帐户。选择它，然后点击**继续**按钮。

1.  您将被重定向到 GitHub 网页，以授予 Vercel 对您的存储库的访问权限。您可以授予对所有存储库的访问权限，或者只是您想要部署的存储库。在我们的情况下，我们将授予对我们帐户上所有存储库的访问权限。

1.  在您的 GitHub 帐户上安装 Vercel 应用程序后，您将被发送回 Vercel 网页。在这里，您可以定义您正在创建的项目的设置，包括项目名称、您正在使用的预设、构建说明和环境变量。Vercel 将自动检测到我们的项目是一个 Vue-CLI 项目，并为我们配置构建和部署设置。然后，点击**部署**按钮继续。

1.  Vercel 将启动第一个部署过程。完成后，Vercel 将为您提供应用程序的链接，以及一个打开仪表板的链接。

## 它是如何工作的...

Vercel 平台连接到您的 GitHub 帐户并安装为应用程序，从而可以访问选定的存储库。然后，在平台上，您可以选择要用于部署的存储库。

选择存储库后，您需要使用构建说明和构建目标文件夹配置 Vercel-CLI。

最后，CLI 运行，我们的应用程序在 Web 上运行起来了。

## 参见

在[`zeit.co/docs/v2/git-integrations`](https://zeit.co/docs/v2/git-integrations)找到有关 Vercel 与 Git 存储库集成的更多信息。

# 创建 Firebase 项目

Firebase 是由 Google 创建的一体化解决方案，旨在为开发人员提供专用的分析、通知、机器学习和云解决方案工具。他们提供的云解决方案之一是托管平台。

有了托管平台，我们可以在 Google 云服务器上托管我们的单页应用程序，并通过全球内容传送网络使其对所有人可用。

## 准备工作

此处的先决条件如下：

+   一个 Google 帐户

+   一个 Vue 项目

## 如何做...

在这个教程中，我们将学习如何创建我们的 Firebase 项目，以便我们可以将我们的应用程序部署到 Firebase 托管：

1.  打开 Firebase 主页（[`firebase.google.com/`](https://firebase.google.com)）并单击页眉菜单中的“登录”链接。如果您已经登录到您的 Google 帐户，请单击“转到控制台”链接。

1.  在控制台页面上，单击“创建项目”按钮以创建新的 Firebase 项目。

1.  Firebase 将要求输入项目名称（您只能使用字母数字字符和空格）。

1.  然后，Firebase 会询问您是否要在此项目中启用 Google Analytics。在我们的情况下，我们将禁用此选项。

1.  最后，您将被重定向到项目概览仪表板。

## 它是如何工作的...

在这个教程中，我们创建了我们的第一个 Firebase 项目。为此，我们首先登录到我们的 Google 帐户并转到 Firebase 控制台。在 Firebase 控制台上，我们创建了一个新项目，并在设置向导步骤中禁用了 Google Analytics 选项，因为我们在这个教程中不会使用附加的分析。最后，当我们完成设置向导时，我们的项目已经准备就绪。

## 参见

在[`firebase.google.com`](https://firebase.google.com)找到有关 Google Firebase 的更多信息。

# 配置 Firebase-CLI 并部署您的项目

要将我们的应用程序部署到 Firebase Hosting，我们需要使用 Firebase-CLI。CLI 将帮助打包文件并将它们发送到 Google Cloud 服务器的过程。

在本配方中，我们将学习如何配置 Firebase-CLI 以使用本地终端将应用程序部署到网络。

## 准备工作

本配方的先决条件如下：

+   一个 Google 帐户

+   一个 Vue 项目

+   一个 Firebase 项目

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

+   `firebase-tools`

安装`firebase-tools`，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g firebase-tools
```

## 如何做...

在本配方中，我们将学习如何在我们的项目中设置 Firebase-CLI，并如何使用上一个配方中创建的项目对其进行初始化：

1.  在项目的根文件夹中打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> firebase login
```

1.  Firebase-CLI 将打开一个浏览器窗口，以便您登录到您的 Google 帐户，并允许 Firebase-CLI 访问您的 Google 帐户的部分。（如果浏览器没有自动打开，Firebase-CLI 上会出现一个链接，复制链接，然后粘贴到浏览器中继续。）

1.  在项目的根文件夹中打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> firebase init
```

1.  现在我们正在使用我们的项目初始化 CLI 的配置过程。对于 CLI 的第一个问题，我们将只使用**Hosting**功能，因此我们需要只选择`Hosting`：

```js
**? Which Firebase CLI features do you want to set up 
    for this folder?** 
 **Press space to select feature, then Enter to confirm 
    your choices.** 
  Database: Deploy Firebase Realtime Database Rules
  Firestore: Deploy rules and create indexes for Firestore
 Functions: Configure and deploy Cloud Functions ❯ Hosting: Configure and deploy Firebase Hosting sites
 Storage: Deploy Cloud Storage security rules Emulators: Set up local emulators for Firebase features
```

1.  然后，CLI 将询问我们要使用哪个 Firebase 项目。在我们的情况下，我们在上一个配方中早些时候创建了项目，因此我们将选择`使用现有项目`：

```js
? Use an existing project ❯ Use an existing project
  Create a new project
  Add Firebase to an existing Google Cloud Platform project
  Don't set up a default project
```

1.  现在将显示您帐户上可用项目的列表。选择要与此应用程序一起部署的项目：

```js
? **Select a default Firebase project for this directory: (Use arrow** 
   **keys)** ❯ vue-3-cookbook-firebase-18921 (Vue 3 Cookbook Firebase)
```

1.  CLI 将询问应用程序的公共目录，或者在我们的情况下，因为它是单页面应用程序，我们需要使用构建目标文件夹。键入目标文件夹的名称，在我们的情况下是`dist`：

```js
? **What do you want to use as your project public directory?** **dist**
```

1.  最后，过程中的最后一步是选择是否要将配置用作单页面应用程序。键入`y`以启用所有 URL 的重写为`index.html`，以便我们可以使用`vue-router`的历史模式：

```js
? Configure as a single-page app (rewrite all urls to /index.html)? 
  (y/N) y
```

1.  打开项目根目录下的`package.json`文件，并添加一个新的脚本来自动化构建和部署过程：

```js
"scripts": {
  "serve": "Vue-CLI-service serve",
  "build": "Vue-CLI-service build",
  "deploy": "npm run build && firebase deploy",
  "lint": "Vue-CLI-service lint" },
```

1.  打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并在项目的根目录下执行以下命令：

```js
> npm run deploy
```

现在您的项目已经部署并可以在网络上访问，CLI 将为您提供访问链接：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/ae1dd54b-f854-42d2-a206-7d58799dc231.png)

## 工作原理...

在这个教程中，我们学习了如何配置 Firebase CLI 并部署我们的应用程序。

首先，我们安装了 Firebase-CLI 并登录到 Google 身份验证平台。然后，我们能够在项目文件夹中初始化 CLI。

在这个过程中，我们选择了在上一个教程中创建的项目，并将构建文件夹指向 Vue-CLI 项目中的正确文件夹。

然后，我们配置了要使用单页面应用程序路由结构，并向`package.json`添加了部署脚本。最后，我们能够部署我们的应用程序并使其对所有人可用。

## 另请参阅

在[`firebase.google.com/docs/hosting`](https://firebase.google.com/docs/hosting)上找到有关 Firebase Hosting 的更多信息。


# 第十一章：指令，插件，SSR 等

现在您已经进入专业联赛！您是一个高级的 Vue 开发者。让我们来玩一些有趣的东西，并查看一些为您量身定制的优秀配方！以下是一些精选的优化解决方案，可以提高您的 Vue 应用程序的质量，并使您的生活更轻松。

在本章中，我们将涵盖以下配方：

+   自动加载`vue-router`路由

+   自动加载`vuex`模块

+   创建自定义指令

+   创建 Vue 插件

+   使用 Quasar 在 Vue 中创建 SSR，SPA，PWA，Cordova 和 Electron 应用程序

+   创建更智能的 Vue 观察者和计算属性

+   使用 Python `Flask`创建`Nuxt.js` SSR

+   Vue 应用程序的注意事项和禁忌

# 技术要求

在本章中，我们将使用 Node.js，`Vue-CLI`，`Cordova`，`Electron`，`Quasar`，`Nuxt.js`和 Python。

注意 Windows 用户：您需要安装一个名为`windows-build-tools`的`npm`包，以便能够安装以下所需的包。为此，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装`Vue-CLI`，您需要在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)中执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

要安装**`Cordova`**，您需要在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)中执行以下命令：

```js
> npm install -g cordova
```

如果您在 macOS 上运行，并且想要运行 iOS 模拟器，您需要在终端(macOS)中执行以下命令：

```js
> npm install -g ios-sim ios-deploy
```

要安装`Electron`**，您需要在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)中执行以下命令：

```js
> npm install -g electron
```

要安装**`Quasar`**，您需要在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)中执行以下命令：

```js
> npm install -g @quasar/cli
```

要安装**`Nuxt.js`**，您需要在终端(macOS 或 Linux)或命令提示符/PowerShell(Windows)中执行以下命令：

```js
> npm install -g create-nuxt-app
```

# 自动加载 Vue 路由

为了创建可维护的代码，我们可以使用自动导入具有相同结构的文件的策略。就像在`vue-router`中的路由一样，当应用程序变得更大时，我们会发现大量的文件被手动导入和处理。在这个配方中，我们将学习一个技巧，使用 webpack 的`require.context`函数来自动为我们注入文件。

此函数将读取文件内容，并将路由添加到一个数组中，默认情况下将其导出到我们的文件中。您可以通过添加更多受控的路由导入甚至基于环境的路由规则来改进此配方。

## 准备就绪

此配方的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们需要使用`Vue-CLI`创建一个新的 Vue 项目，或者使用之前创建的项目：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create router-import
```

1.  CLI 会询问一些问题，这些问题将有助于创建项目。您可以使用箭头键进行导航，使用*Enter*键继续，使用*空格键*选择选项。

1.  有两种启动新项目的方法。默认方法是一个基本的`babel`和`eslint`项目，没有任何插件或配置，还有一个是`手动`模式，您可以在其中选择更多模式、插件、代码检查工具和选项。我们将选择`手动`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features  ‌
```

1.  现在我们被问及我们想要在项目中使用的功能。这些功能包括一些 Vue 插件，如`Vuex`或`Router`（`vue-router`），测试工具，代码检查工具等。选择`Babel`、`Router`和`Linter / Formatter`：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support ❯ Router   Vuex
  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing   E2E Testing
```

1.  通过选择一个代码检查工具和格式化工具来继续这个过程。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  设置了代码检查规则后，我们需要定义它们何时应用于您的代码。它们可以在保存时应用，也可以在提交时修复：

```js
?  Pick additional lint features: (Use arrow keys)   Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、代码检查工具和处理器之后，我们需要选择设置和配置的存储位置。最佳存储位置是专用文件，但也可以将它们存储在`package.json`中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use 
  arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  现在您可以选择是否要将此选择设置为将来项目的预设，这样您就不需要重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

`Vue-CLI`将创建项目，并自动为我们安装包。

如果您想在安装完成后在`vue-ui`上检查项目，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue ui
```

或者您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令来运行内置的`npm`命令：

+   `npm run serve` - 本地运行开发服务器

+   `npm run build` - 用于构建和压缩应用程序以进行部署

+   `npm run lint` - 对代码执行 lint

## 如何做...

按照这些说明，在项目中创建路由文件的自动导入，它将处理特定文件夹内的路由文件：

1.  创建并放置在`routes`文件夹内的路由文件后，我们需要确保每个路由文件中都有一个默认的`export`对象。在`src/router`文件夹内的`index.js`文件中，删除文件中存在的默认`routes`数组：

```js
import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);

export default new VueRouter({});
```

1.  现在创建一个空的`routes`数组，它将由从文件夹中导入的路由填充，并开始导入。这样，`requireRoutes`将成为一个对象，其键是文件名，值是文件的 ID：

```js
import Vue from 'vue'; import VueRouter from 'vue-router';   Vue.use(VueRouter);   const routes = []; const requireRoutes = require.context(
  './routes',
  true,
  /^(?!.*test).*\.js$/is, );   const router = new VueRouter({
  routes, });   export default router; 
```

1.  为了将这些文件推送到`routes`数组中，我们需要添加以下代码，并在`router`文件夹内创建一个名为`routes`的文件夹：

```js
import Vue from 'vue'; import VueRouter from 'vue-router';   Vue.use(VueRouter);   const routes = []; const requireRoutes = require.context(
  './routes',
  true,
  /^(?!.*test).*\.js$/is, );   requireRoutes.keys().forEach((fileName) => {
  routes.push({
  ...requireRoutes(fileName).default,
  }); });   const router = new VueRouter({
  routes, });   export default router;
```

现在，只要在`routes`文件夹内创建一个新的`.js`文件，你的路由就会自动加载到应用程序中。

## 工作原理...

`require.context`是 webpack 内置的函数，允许您传入要搜索的目录、一个指示是否应该检查子目录的标志，以及一个匹配文件的正则表达式。

当构建过程开始时，webpack 将搜索所有`require.context`函数，并对其进行预执行，因此导入所需的文件将在最终构建中存在。

我们向函数传递了三个参数：第一个是它将开始搜索的文件夹，第二个询问搜索是否会进入下降的文件夹，最后，第三个是用于文件名匹配的正则表达式。

在这个配方中，我们将`./routes`定义为文件夹，作为函数的第一个参数自动加载路由。作为函数的第二个参数，我们定义`false`，不搜索子目录。最后，作为第三个参数，我们定义`/^(?!.*test).*\.js$/is`作为正则表达式，用于搜索`.js`文件并忽略文件名中包含`.test`的文件。

## 还有更多...

通过这个配方，可以通过使用子目录进行路由模块和环境进行路由控制，将应用程序提升到下一个级别。

通过这些增量，函数可以被提取到另一个文件中，但在`router.js`中，它仍然需要被导入到`main.js`文件中。或者，您可以获取`import`函数，并将`routes`数组传递给`router.js`。

## 另请参阅

在 webpack 文档中阅读有关 webpack 依赖管理和`require.context`的更多信息：[`webpack.js.org/guides/dependency-management/.`](https://webpack.js.org/guides/dependency-management/)

# 自动加载 Vuex 模块

有时，当我们在一个大项目上工作时，我们需要管理许多导入的`Vuex`模块和存储。为了处理这些模块，我们总是需要通过创建一个包含所有导入文件的文件来导入它们，然后将其导出到 Vuex 存储创建中。

在这个食谱中，我们将学习一个使用 webpack 的`require.context`函数的函数，以自动加载并将这些文件注入到 Vuex 存储创建中。

## 准备就绪

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们需要使用`Vue-CLI`创建一个新的 Vue 项目，或者使用之前创建的项目：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create vuex-import
```

1.  CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*空格键*选择选项。

1.  有两种启动新项目的方法。默认方法是一个基本的`babel`和`eslint`项目，没有任何插件或配置，还有一个`手动`模式，您可以在其中选择更多模式、插件、检查器和选项。我们将选择`手动`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features  ‌
```

1.  现在我们被问及我们将在项目中需要哪些功能。这些功能包括一些 Vue 插件，如`Vuex`或`Router`（`vue-router`），测试器，检查器等。选择`Babel`，`Vuex`和`Linter / Formatter`：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router ❯Vuex
  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  通过选择一个检查器和格式化程序来继续此过程。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  设置好检查规则后，我们需要定义它们何时应用于您的代码。它们可以在保存时应用，也可以在提交时修复：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、检查器和处理器之后，我们需要选择设置和配置的存储位置。将它们存储在专用文件中是最好的地方，但也可以将它们存储在`package.json`中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use 
  arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  现在您可以选择是否要将此选择作为将来项目的预设，这样您就不需要重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

`Vue-CLI`将创建项目，并为我们自动安装包。

如果你想在安装完成后在`vue-ui`上检查项目，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue ui
```

或者你可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令来运行内置的`npm`命令：

+   `npm run serve` – 本地运行开发服务器

+   `npm run build` – 为部署构建和压缩应用程序

+   `npm run lint` – 执行代码的 lint

## 如何做...

按照以下说明，在项目中创建`vuex`模块的自动导入，以处理特定文件夹内的路由文件：

1.  在`store`文件夹中创建并放置路由文件后，我们需要确保每个`store`文件都有一个默认的`export`对象。在`src/store`文件夹中的`index.js`文件中，我们需要提取`stores`或`modules`的数组：

```js
import Vue from 'vue';
import Vuex from 'vuex';

Vue.use(Vuex);

export default new Vuex.Store({});
```

1.  在`src/store`文件夹中创建另一个名为`loader.js`的文件（它将是我们的`module`加载器）。重要的是要记住，当使用这个方法时，你将使用`vuex`的命名空间，因为所有的`stores`都需要作为一个模块使用，并且需要导出为一个单一的 JavaScript 对象。每个文件名将被用作命名空间的引用，并且将被解析为驼峰式文本风格：

```js
const toCamel = (s) => s.replace(/([-_][a-z])/ig, (c) => c.toUpperCase()
  .replace(/[-_]/g, '')); const requireModule = require.context('./modules/', false, 
   /^(?!.*test).*\.js$/is); const modules = {};   requireModule.keys().forEach((fileName) => {
  const moduleName = toCamel(fileName.replace(/(\.\/|\.js)/g, ''));    modules[moduleName] = {
  namespaced: true,
  ...requireModule(fileName).default,
  }; });   export default modules; 
```

1.  由于我们将默认导入`modules`文件夹中的每个文件，一个好的做法是为每个模块创建一个文件。例如，当你创建一个名为`user`的模块时，你需要创建一个名为`user.js`的文件，它导入所有的`stores`操作、mutations、getters 和 state。这些可以放在一个与模块同名的文件夹中。`modules`文件夹的结构将类似于这样：

```js
modules
├── user.js
├── user
│ └── types.js
│   └── state.js
│   └── actions.js
│   └── mutations.js
│   └── getters.js
└───────
```

`src/store/modules`文件夹中的`user.js`文件将如下所示：

```js
import state from './user/state'; import actions from './user/actions'; import mutations from './user/mutations'; import getters from './user/getters';   export default {
  state,
  actions,
  mutations,
  getters, }; 
```

1.  在`src/store`文件夹中的`index.js`文件中，我们需要添加自动加载的导入模块：

```js
import Vue from 'vue'; import Vuex from 'vuex'; import modules from './loader';   Vue.use(Vuex);   export default new Vuex.Store({
  modules, }); 
```

现在，只要在`src/store/modules`文件夹中创建一个新的`.js`文件，你的`vuex`模块就会自动加载到你的应用程序中。

## 它是如何工作的...

`require.context`是 webpack 的内置函数，它接收一个目录来执行搜索，一个布尔标志，指示是否在此搜索中包括子目录，以及用于文件名模式匹配的正则表达式（作为参数）。

当构建过程开始时，webpack 将搜索所有`require.context`函数，并预先执行它们，以便导入所需的文件在最终构建中存在。

在我们的情况下，我们传递了`./modules`作为文件夹，`false`表示不搜索子目录，`/^(?!.*test).*\.js$/is`作为正则表达式来搜索`.js`文件并忽略文件名中包含`.test`的文件。

然后，该函数将搜索文件，并通过`for`循环将结果添加到`vuex`模块的数组中。

## 另请参阅

在 webpack 文档中阅读有关 webpack 依赖管理和`require.context`的更多信息[`webpack.js.org/guides/dependency-management/.`](https://webpack.js.org/guides/dependency-management/)

# 创建自定义指令

谈到 Vue 等视觉框架，我们总是想到组件、渲染和视觉元素，而忘记了除了组件本身之外还有很多东西。

这些指令使组件与模板引擎一起工作，它们是数据和视觉结果之间的绑定代理。还有 Vue 核心中的内置指令，如`v-if`，`v-else`和`v-for`。

在这个食谱中，我们将学习如何制作我们的指令。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们需要使用`Vue-CLI`创建一个新的 Vue 项目，或者使用之前食谱中创建的项目：

1.  我们需要在 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows）中执行以下命令：

```js
> vue create vue-directive
```

1.  CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，*空格键*选择选项。

1.  有两种方法可以启动一个新项目。默认方法是一个基本的`babel`和`eslint`项目，没有任何插件或配置，还有一个`手动`模式，您可以在其中选择更多模式、插件、代码检查工具和选项。我们将选择`手动`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features  ‌
```

1.  现在我们被问及项目中想要的功能。这些功能包括一些 Vue 插件，如`Vuex`或`Router`（`vue-router`），测试工具，代码检查工具等。选择`Babel`和`Linter / Formatter`：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel TypeScript Progressive Web App (PWA) SupportRouter
  Vuex
  CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  通过选择一个代码检查工具和格式化工具来继续这个过程。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  设置了 linting 规则之后，我们需要定义它们何时应用于您的代码。它们可以在“保存时”应用，也可以在“提交时”修复：

```js
?  Pick additional lint features: (Use arrow keys) Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、linters 和处理器之后，我们需要选择设置和配置存储的位置。存储它们的最佳位置是专用文件，但也可以将它们存储在`package.json`中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  现在您可以选择是否要将此选择作为将来项目的预设，这样您就不需要重新选择所有内容。

```js
?  Save this as a preset for future projects?  (y/N) n
```

`Vue-CLI`将创建项目，并自动为我们安装软件包。

如果您想在安装完成后在`vue-ui`上检查项目，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue ui
```

或者，您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行内置的 npm 命令：

+   `npm run serve` - 本地运行开发服务器

+   `npm run build` - 为部署构建和缩小应用程序

+   `npm run lint` - 对代码执行 lint

## 操作步骤如下...

按照以下说明创建一个用于掩码输入字段的指令：

1.  在`src/directives`文件夹中创建名为`formMaskInputDirective.js`的文件，并在同一文件夹中创建名为`tokens.js`的文件。

1.  在`tokens.js`文件中，我们将添加我们的掩码基本令牌。这些令牌将用于识别我们的输入将接受的值类型：

```js
export default {
  "#": { pattern: /[\x2A\d]/ },
  0: { pattern: /\d/ },
  9: { pattern: /\d/ },
  X: { pattern: /[0-9a-zA-Z]/ },
  S: { pattern: /[a-zA-Z]/ },
  A: { pattern: /[a-zA-Z]/, transform: v => v.toLocaleUpperCase() },
  a: { pattern: /[a-zA-Z]/, transform: v => v.toLocaleLowerCase() },
  "!": { escape: true }
};
```

1.  我们从`token.js`导入令牌并创建我们的函数：

```js
import tokens from './tokens';

function maskerValue() {
  // Code will be developed in this recipe
}

function eventDispatcher() {
  // Code will be developed in this recipe
}

function maskDirective() {
 // Code will be developed in this recipe
}

export default maskDirective;
```

1.  在`maskDirective`函数中，我们需要检查调用者传递的指令上的绑定值，并检查它是否是有效的绑定。为此，我们首先检查`binding`参数上是否存在`value`属性，然后将其添加到`tokens`中导入的`config`变量中：

```js
function maskDirective(el, binding) {
  let config;

  if (!binding.value) return false;

  if (typeof config === 'string') {
    config = {
      mask: binding.value,
      tokens,
    };
  } else {
    throw new Error('Invalid input entered');
  }
```

1.  现在我们需要检查元素并验证它是否是`input` HTML 元素。为此，我们将检查指令传递的元素是否具有`input`的`tagName`，如果没有，我们将尝试在传递的元素中找到`input` HTML 元素：

```js
let element = el;

  if (element.tagName.toLocaleUpperCase() !== 'INPUT') {
    const els = element.getElementsByTagName('input');

    if (els.length !== 1) {
      throw new Error(`v-input-mask directive requires 1 input, 
         found ${els.length}`);
    } else {
      [element] = els;
    }
  }
```

1.  现在我们需要为元素添加事件侦听器。侦听器将调用两个外部函数，一个用于分派事件，另一个用于将掩码值返回到输入中：

```js
element.oninput = (evt) => {
    if (!evt.isTrusted) return;
    let position = element.selectionEnd;

    const digit = element.value[position - 1];
    element.value = maskerValue(element.value, config.mask, 
       config.tokens);
    while (
      position < element.value.length
      && element.value.charAt(position - 1) !== digit
    ) {
      position += 1;
    }
    if (element === document.activeElement) {
      element.setSelectionRange(position, position);
      setTimeout(() => {
        element.setSelectionRange(position, position);
      }, 0);
    }
    element.dispatchEvent(eventDispatcher('input'));
  };

  const newDisplay = maskerValue(element.value, config.mask, 
     config.tokens);
  if (newDisplay !== element.value) {
    element.value = newDisplay;
    element.dispatchEvent(eventDispatcher('input'));
  }

  return true;
}
// end of maskDirective function
```

1.  让我们创建`eventDispatcher`函数；这个函数将发出事件，将被`v-on`指令监听到：

```js
function eventDispatcher(name) {
  const evt = document.createEvent('Event');

  evt.initEvent(name, true, true);

  return evt;
}
```

1.  现在复杂的部分：将掩码输入值返回到输入框。为此，我们需要创建`maskerValue`函数。该函数接收值、掩码和令牌作为参数。该函数检查当前值与掩码是否匹配，以查看掩码是否完整或值是否是有效令牌。如果一切正常，它将把值传递给输入框：

```js
function maskerValue(v, m, tkn) {
  const value = v || '';

  const mask = m || '';

  let maskIndex = 0;

  let valueIndex = 0;

  let output = '';

  while (maskIndex < mask.length && valueIndex < value.length) {
    let maskCharacter = mask[maskIndex];
    const masker = tkn[maskCharacter];
    const valueCharacter = value[valueIndex];

    if (masker && !masker.escape) {
      if (masker.pattern.test(valueCharacter)) {
        output += masker.transform ? 
           masker.transform(valueCharacter) : valueCharacter;
        maskIndex += 1;
      }

      valueIndex += 1;
    } else {
      if (masker && masker.escape) {
        maskIndex += 1;
        maskCharacter = mask[maskIndex];
      }

      output += maskCharacter;

      if (valueCharacter === maskCharacter) valueIndex += 1;

      maskIndex += 1;
    }
  }

  let outputRest = '';
  while (maskIndex < mask.length) {
    const maskCharacter = mask[maskIndex];

    if (tkn[maskCharacter]) {
      outputRest = '';
      break;
    }

    outputRest += maskCharacter;

    maskIndex += 1;
  }

  return output + outputRest;
}
//end of maskerValue function
```

1.  准备好后，我们需要在`main.js`文件中导入掩码指令，并将指令添加到 Vue 中，给指令命名为`'input-mask'`：

```js
import Vue from 'vue';
import App from './App.vue';
import InputMaskDirective from './directives/formMaskInputDirective';

Vue.config.productionTip = false;

Vue.directive('input-mask', InputMaskDirective);

new Vue({
  render: (h) => h(App),
}).$mount('#app');
```

1.  要在我们的应用程序中使用该指令，我们需要在单文件组件`<template>`部分的`input` HTML 元素上调用指令，将`token`模板`'###-###-###'`作为参数传递给`v-input-mask`指令，如下所示：

```js
<template>
  <div id="app">
    <input
      type="text"
      v-input-mask="'###-###-###'"
      v-model="inputMask"
    />
  </div>
</template>

<script>
export default {
  name: 'app',
  data: () => ({
    inputMask: '',
  }),
};
</script>
```

## 工作原理...

Vue 指令有五个可能的钩子。我们只使用了一个`bind`。它直接绑定到元素和组件。它有三个参数：`element`，`binding`和`vnode`。

当我们在`main.js`文件中将指令添加到 Vue 中时，它将在整个应用程序中可用，因此该指令已经在`App.vue`中，可以被输入框使用。

在调用`v-input-mask`的同时，我们将第一个参数`element`传递给指令，第二个参数`binding`是属性的值。

我们的指令通过检查输入框上的每个新字符值来工作。执行正则表达式测试并验证字符，以查看它是否是指令实例化时给定的令牌列表中的有效字符。然后，如果通过测试，它将返回字符，如果是无效字符，则不返回任何内容。

# 创建一个 Vue 插件

有时需要对应用程序进行新的添加，并且需要共享这个添加。最好的共享方式是使用插件。在 Vue 中，插件是通过扩展初始化应用程序的 Vue 全局原型来添加新功能，如指令、混合、过滤器、原型注入或全新功能。

现在我们将学习如何制作我们的插件，以及如何使用它与整个 Vue 进行交互（而不会干扰原型并破坏它）。

## 准备工作

此食谱的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

我们需要使用`Vue-CLI`创建一个新的 Vue 项目，或者使用以前的配方创建的项目：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create vue-plugin
```

1.  CLI 将询问一些问题，这些问题将有助于创建项目。您可以使用箭头键导航，*Enter*键继续，s*pacebar*选择选项。

1.  有两种启动新项目的方法。默认方法是一个基本的`babel`和`eslint`项目，没有任何插件或配置，以及`手动`模式，您可以在其中选择更多模式、插件、linter 和选项。我们将选择`手动`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features  ‌
```

1.  现在我们被问及我们想要在项目中的功能。这些功能是一些 Vue 插件，如`Vuex`或`Router`（`vue-router`），测试器，linter 等。选择`Babel`和`Linter / Formatter`：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router
  Vuex
  CSS Pre-processors ❯   Linter / Formatter
 Unit Testing E2E Testing
```

1.  通过选择一个 linter 和 formatter 来继续此过程。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  设置 linting 规则后，我们需要定义它们何时应用于您的代码。它们可以在保存时应用，也可以在提交时修复：

```js
?  Pick additional lint features: (Use arrow keys) Lint on save ❯ Lint and fix on commit
```

1.  在定义了所有这些插件、linter 和处理器之后，我们需要选择设置和配置的存储位置。存储它们的最佳位置是专用文件，但也可以将它们存储在`package.json`中：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use
  arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  现在，您可以选择是否要将此选择设置为将来项目的预设，这样您就不需要重新选择所有内容：

```js
?  Save this as a preset for future projects?  (y/N) n
```

Vue-CLI 将创建项目，并自动为我们安装包。

如果您想在安装完成后在`vue-ui`上检查项目，请打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue ui
```

或者，您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行内置的 npm 命令：

+   `npm run serve` - 本地运行开发服务器

+   `npm run build` - 为部署构建和缩小应用程序

+   `npm run lint` - 执行代码上的 lint

## 如何做...

编写 Vue 插件很简单，无需更多了解 Vue 本身。插件的基本概念是一个需要具有`install`函数的对象，当通过`Vue.use()`方法调用时将执行该函数。`install`函数将接收两个参数：Vue 和将用于实例化插件的选项。

按照以下说明编写一个插件，向 Vue 全局原型添加两个新函数`$localStorage`和`$sessionStorage`：

1.  在我们的项目中，我们需要在`src/plugin`文件夹中创建一个名为`storageManipulator.js`的文件。

1.  在这个文件中，我们将创建插件安装对象-我们将添加默认的插件选项和函数的基本原型：

```js
/* eslint no-param-reassign: 0 */

const defaultOption = {
  useSaveFunction: true,
  useRetrieveFunction: true,
  onSave: value => JSON.stringify(value),
  onRetrieve: value => JSON.parse(value),
};

export default {
  install(Vue, option) {
    const baseOptions = {
      ...defaultOption,
      ...option,
    };

    Vue.prototype.$localStorage = generateStorageObject(
       window.localStorage,
        baseOptions,
      ); // We will add later this code

    Vue.prototype.$sessionStorage = generateStorageObject(
        window.localStorage,
        baseOptions,
      ); // We will add later this code
  },
};
```

1.  现在我们需要创建`generateStorageObject`函数。这个函数将接收两个参数：第一个是窗口存储对象，第二个是插件选项。通过这样，将可以生成将用于注入到 Vue 中的原型的对象：

```js
const generateStorageObject = (windowStorage, options) => ({
  set(key, value) {
    windowStorage.setItem(
      key,
      options.useSaveFunction
        ? options.onSave(value)
        : value,
    );
  },

  get(key) {
    const item = windowStorage.getItem(key);
    return options.useRetrieveFunction ? options.onRetrieve(item) : 
      item;
  },

  remove(key) {
    windowStorage.removeItem(key);
  },

  clear() {
    windowStorage.clear();
  },
});
```

1.  需要将插件导入到`main.js`中，然后使用`Vue.use`函数在我们的 Vue 应用程序中安装插件：

```js
import Vue from 'vue';
import App from './App.vue';
import StorageManipulatorPlugin from './plugin/storageManipulator';

Vue.config.productionTip = false;

Vue.use(StorageManipulatorPlugin);

new Vue({
  render: h => h(App),
}).$mount('#app');
```

现在你可以在 Vue 应用程序的任何地方使用插件，调用`this.$localStorage`方法或`this.$sessionStorage`。

## 工作原理...

Vue 插件通过将所有指令要使用的代码添加到 Vue 应用程序层（如 mixin）来工作。

当我们使用`Vue.use()`导入我们的插件时，我们告诉 Vue 在导入文件的对象上调用`install()`函数并执行它。Vue 将自动将当前 Vue 作为第一个参数传递，并将选项（如果声明了）作为第二个参数传递。

在我们的插件中，当调用`install()`函数时，我们首先创建`baseOptions`，将默认选项与传递的参数合并，然后将两个新属性注入到 Vue 原型中。这些属性现在因为传递的`Vue`参数是应用程序中使用的`Vue 全局`，所以在任何地方都可用。

我们的`generateStorageObject`是浏览器的 Storage API 的纯抽象。我们将其用作插件内原型的生成器。

## 另见

您可以在[`vuejs.org/v2/guide/plugins.html`](https://vuejs.org/v2/guide/plugins.html)找到有关 Vue 插件的更多信息。

您可以在[`github.com/vuejs/awesome-vue`](https://github.com/vuejs/awesome-vue)找到精选的 Vue 插件列表。

# 使用 Quasar 在 Vue 中创建 SSR、SPA、PWA、Cordova 和 Electron 应用程序

Quasar 是一个基于 Vue 和 Material Design 的框架，利用“一次编写，随处使用”的优势。

CLI 可以将相同的代码库部署到不同的版本，如**单页应用程序**（**SPA**）、**服务器端渲染**（**SSR**）、**渐进式 Web 应用程序**（**PWA**）、**移动应用程序**（Cordova）和**桌面应用程序**（Electron）。

这减轻了开发人员的一些问题，比如为开发配置 webpack、Cordova 和 Electron 与**HMR**（**热模块重新加载**），或者在 SPA 项目中添加 SSR 配置。该框架帮助开发人员尽快开始生产。

在这个教程中，我们将学习如何使用 Quasar 和 CLI 来创建一个基本项目，以及如何使用 CLI 为 SPA、PWA、SSR、移动应用和桌面应用添加开发目标。

## 准备工作

这个教程的先决条件如下：

+   Node.js 12+

所需的 Node.js 全局对象如下：

+   `@quasar/cli`

我们需要使用 Quasar CLI 创建一个新的 Quasar 项目，或者使用之前创建的项目。

要做到这一点，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar create quasar-project
```

现在，当被询问时，我们需要选择手动选择功能：

1.  `Quasar-CLI`将要求您输入项目名称。定义您的项目名称。在我们的情况下，我们选择了`quasar_project`：

```js
> Project name: quasar_project
```

1.  然后`Quasar-CLI`将要求输入项目产品名称。这将被移动应用程序用来定义它们的标题名称。在我们的情况下，我们使用了提供的默认名称：

```js
> Project product name (must start with letter if building mobile 
    apps) (Quasar App)
```

1.  现在`Quasar-CLI`将要求输入项目描述。这在页面被分享时用于搜索引擎的元标记。在我们的情况下，我们使用了提供的默认描述：

```js
> Project description: (A Quasar Framework app)
```

1.  然后`Quasar-CLI`将要求输入项目作者。用`package.json`的有效名称填写（例如，`Heitor Ribeiro<heitor@example.com>`）：

```js
> Author: <You>
```

1.  现在是选择 CSS 预处理器的时候了。在我们的情况下，我们将选择`Sass with indented syntax`：

```js
Pick your favorite CSS preprocessor: (can be changed later) (Use arrow keys) ❯ Sass with indented syntax (recommended)
 Sass with SCSS syntax (recommended)
 Stylus
 None (the others will still be available)
```

1.  然后`Quasar-CLI`将询问组件和指令的导入策略。我们将使用默认的`auto-import`策略：

```js
Pick a Quasar components & directives import strategy: (can be   
  changed later) (Use arrow keys ) ❯ * Auto-import in-use Quasar components & directives - also 
 treeshakes Quasar; minimum bundle size
 * Import everything from Quasar - not treeshaking Quasar;         
    biggest bundle size
```

1.  现在我们需要为项目选择额外的功能。我们将选择`EsLint`：

```js
Check the features needed for your project: EsLint
```

1.  之后，`Quasar-CLI`将要求选择 ESLint 的预设。选择`Airbnb`预设：

```js
Pick an ESLint preset: Airbnb
```

1.  最后，`Quasar-CLI`将要求选择要用于安装项目依赖项的应用程序。在我们的情况下，我们使用了`yarn`，因为我们已经安装了它（但您可以选择您喜欢的）：

```js
Continue to install project dependencies after the project has been 
  created? (recommended) (Use arrow keys) ❯ Yes, use Yarn (recommended)
 Yes, use npm
 No, I will handle that myself
```

现在在您的 IDE 或代码编辑器中打开创建的文件夹。

## 如何做...

在使用 Quasar 创建应用程序时，您总是需要选择一个口味来开始，但主要代码将是 SPA。因此，其他口味将根据其需求具有其特殊的功能和特色，但您可以根据构建环境个性化并使您的构建执行一些代码。

### 开发 SPA（单页应用程序）

开始开发 SPA 是一个开箱即用的解决方案；不需要添加任何新的配置。

所以让我们开始向我们的应用程序添加一个新页面。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> quasar new page About
```

`Quasar-CLI`将自动为我们创建 Vue 页面。我们需要在路由文件中添加对页面的引用，然后该页面将在应用程序中可用：

1.  为了做到这一点，我们需要打开`src/router`文件夹中的`routes.js`文件，并添加`About`页面：

```js
const routes = [
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: '', name: 'home', component: () => 
         import('pages/Index.vue') },
      { path: 'about', name: 'about', component: () => 
         import('pages/About.vue') },
    ],
  },
  {
    path: '*',
    component: () => import('pages/Error404.vue'),
  }
];

export default routes;
```

1.  然后在`src/pages`文件夹中打开`About.vue`文件。您会发现该文件是一个单文件组件，其中有一个空的`QPage`组件，因此我们需要在`<template>`部分中添加基本标题和页面指示：

```js
<template>
<q-page
    padding
    class="flex flex-start"
  >
    <h1 class="full-width">About</h1>
    <h2>This is an About Us Page</h2>
  </q-page>
</template>

<script>
export default {
  name: 'PageAbout',
};
</script>
```

1.  现在，在`src/layouts`文件夹中的`MainLayout.vue`文件中，对于`q-drawer`组件，我们需要添加到`Home`和`About`页面的链接：

```js
<template>
  <q-layout view="lHh Lpr lFf">
    <q-header elevated>
      <q-toolbar>
        <q-btn flat dense round 
        @click="leftDrawerOpen = !leftDrawerOpen" 
        aria-label="Menu">
          <q-icon name="menu" />
        </q-btn>

        <q-toolbar-title>
          Quasar App
          </q-toolbar-title>

        <div>Quasar v{{ $q.version }}</div>
      </q-toolbar>
    </q-header>

    <q-drawer v-model="leftDrawerOpen" 
    bordered content-class="bg-grey-2">
      <q-list>
        <q-item-label header>Menu</q-item-label>
        <q-item clickable tag="a" :to="{name: 'home'}">
          <q-item-section avatar>
            <q-icon name="home" />
          </q-item-section>
          <q-item-section>
            <q-item-label>Home</q-item-label>
          </q-item-section>
        </q-item>
        <q-item clickable tag="a" :to="{name: 'about'}">
          <q-item-section avatar>
            <q-icon name="school" />
          </q-item-section>
          <q-item-section>
            <q-item-label>About</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
    </q-drawer>

    <q-page-container>
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script>
export default {
  name: "MyLayout",
  data() {
    return {
      leftDrawerOpen: this.$q.platform.is.desktop
    };
  }
};
</script>

```

我们已经完成了一个简单的 SPA 在 Quasar 框架内运行的示例。

#### 命令

您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行`Quasar-CLI`命令：

+   `quasar dev` - 启动开发模式

+   `quasar build` - 构建 SPA

### 开发 PWA（渐进式 Web 应用程序）

开发 PWA，我们首先需要告诉 Quasar 我们想要添加一个新的开发模式。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> quasar mode add pwa
```

`Quasar-CLI`将创建一个名为`src-pwa`的文件夹，其中将包含我们的`service-workers`文件，与我们的主要代码分开。

为了清理新添加的文件，并将其格式化为 Airbnb 格式，我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> eslint --fix --ext .js ./src-pwa
```

我们添加到 SPA 的代码仍将被用作我们的基础，以便我们可以添加新页面、组件和其他功能，这些功能也将用于 PWA。

那么，您是否想知道为什么`service-worker`不在主`src`文件夹中？这是因为这些文件专门用于 PWA，并且在除此之外的任何其他情况下都不需要。在不同的构建类型中也会发生相同的情况，例如 Electron，Cordova 和 SSR。

#### 在 PWA 上配置 quasar.conf

对于 PWA 开发，您可以在`root`文件夹中的`quasar.conf.js`文件上设置一些特殊标志：

```js
pwa: {
  // workboxPluginMode: 'InjectManifest',
  // workboxOptions: {},
  manifest: {
    // ...
  },

  // variables used to inject specific PWA
  // meta tags (below are default values)
  metaVariables: {
    appleMobileWebAppCapable: 'yes',
    appleMobileWebAppStatusBarStyle: 'default',
    appleTouchIcon120: 'statics/icons/apple-icon-120x120.png',
    appleTouchIcon180: 'statics/icons/apple-icon-180x180.png',
    appleTouchIcon152: 'statics/icons/apple-icon-152x152.png',
    appleTouchIcon167: 'statics/icons/apple-icon-167x167.png',
    appleSafariPinnedTab: 'statics/icons/safari-pinned-tab.svg',
    msapplicationTileImage: 'statics/icons/ms-icon-144x144.png',
    msapplicationTileColor: '#000000'
  }
}
```

#### 命令

您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行`Quasar-CLI`命令：

+   `quasar dev -m pwa` - 以 PWA 模式启动开发模式

+   `quasar build -m pwa` - 将代码构建为 PWA

### 开发 SSR（服务器端渲染）

要开发 SSR，我们首先需要告诉 Quasar 我们想要添加一个新的开发模式。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar mode add ssr
```

`Quasar-CLI`将创建一个名为`src-ssr`的文件夹，其中包含我们的`extension`和`server`启动文件，与我们的主要代码分开。

`extension`文件不会被`babel`转译，并在 Node.js 上下文中运行，因此与 Express 或`Nuxt.js`应用程序相同。您可以使用服务器插件，如`database`，`fileread`和`filewrites`。

`server`启动文件将是我们`src-ssr`文件夹中的`index.js`文件。与扩展名一样，它不会被`babel`转译，并在 Node.js 上下文中运行。对于 HTTP 服务器，它使用 Express，并且如果您配置`quasar.conf.js`以向客户端传递 PWA，则可以同时拥有 SSR 和 PWA。

#### 在 SSR 上配置 quasar.conf

对于 SSR 开发，您可以在`root`文件夹中的`quasar.conf.js`文件上配置一些特殊标志：

```js
ssr: {
  pwa: true/false, // should a PWA take over (default: false), or just 
                                                            // a SPA?
},
```

#### 命令

您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行`Quasar-CLI`命令：

+   `quasar dev -m ssr` - 以 SSR 模式启动开发模式

+   `quasar build -m ssr` - 将代码构建为 SSR

+   `quasar serve` - 运行 HTTP 服务器（可用于生产）

### 开发移动应用程序（Cordova）

要开发 SSR，我们首先需要告诉 Quasar 我们想要添加一个新的开发模式。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar mode add cordova
```

现在`Quasar-CLI`将询问您一些配置问题：

1.  **Cordova 应用程序 ID 是什么？** `(org.cordova.quasar.app)`

1.  **Cordova 是否可以匿名报告使用统计数据以随时间改进工具？** **（Y/N）** `N`

`Quasar-CLI`将创建一个名为`src-cordova`的文件夹，其中将包含一个 Cordova 项目。

Cordova 项目的文件夹结构如下：

```js
src-cordova/
├── config.xml
├── packages.json
├── cordova-flag.d.ts
├── hooks/
├── www/
├── platforms/
├── plugins/
```

作为 Quasar 内部的一个独立项目，要添加 Cordova 插件，您需要在`src-cordova`文件夹内调用`plugman`或`cordova plugin add`命令。

#### 在 Cordova 上配置 quasar.conf

对于 Cordova 开发，您可以在`root`文件夹中的`quasar.conf.js`文件上设置一些特殊标志：

```js
cordova:  { iosStatusBarPadding:  true/false,  // add the dynamic top padding on 
     // iOS mobile devices backButtonExit:  true/false  // Quasar handles app exit on mobile phone 
      // back button  },
```

#### 命令

您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令来运行`Quasar-CLI`命令：

如果您的桌面上尚未配置 Cordova 环境，您可以在此处找到有关如何设置的更多信息：[`quasar.dev/quasar-cli/developing-cordova-apps/preparation#Android-setup`](https://quasar.dev/quasar-cli/developing-cordova-apps/preparation#Android-setup)。

+   `quasar dev -m cordova -T android` – 以 Android 设备模拟器的形式启动开发模式

+   `quasar build -m cordova -T android` – 作为 Android 构建代码

+   `quasar dev -m cordova -T ios` – 以 iOS 设备模拟器的形式启动开发模式（仅限 macOS）

+   `quasar build -m cordova -T ios` – 以 iOS 设备模拟器的形式启动构建模式（仅限 macOS）

### 开发桌面应用程序（Electron）

要开发 SSR，我们首先需要告诉 Quasar 我们想要添加一个新的开发模式。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> quasar mode add electron
```

`Quasar-CLI`将创建一个名为`src-electron`的文件夹，其中将包含一个 Electron 项目。

Electron 项目的文件夹结构如下：

```js
src-electron/
├── icons/
├── main-process/
├── electron-flag.d.ts
```

在`icons`文件夹中，您将找到`electron-packager`在构建项目时将使用的图标。在`main-process`文件夹中将是您的主要 Electron 文件，分成两个文件：一个仅在开发时调用，另一个在开发和生产时调用。

#### 在 Electron 上配置 quasar.conf

对于 Electron 开发，您可以在根文件夹的`quasar.conf.js`文件上设置一些特殊标志：

```js
electron: {
  // optional; webpack config Object for
  // the Main Process ONLY (/src-electron/main-process/)
  extendWebpack (cfg) {
    // directly change props of cfg;
    // no need to return anything
  },

  // optional; EQUIVALENT to extendWebpack() but uses webpack-chain;
  // for the Main Process ONLY (/src-electron/main-process/)
  chainWebpack (chain) {
    // chain is a webpack-chain instance
    // of the Webpack configuration
  },

  bundler: 'packager', // or 'builder'

  // electron-packager options
  packager: {
    //...
  },

  // electron-builder options
  builder: {
    //...
  }
},
```

`packager`键使用`electron-packager`模块的 API 选项，`builder`键使用`electron-builder`模块的 API 选项。

#### 命令

您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行`Quasar-CLI`命令：

+   `quasar dev -m electron` – 以 Electron 模式启动开发模式

+   `quasar build -m electron` – 以 Electron 模式构建代码

## 它是如何工作的...

这一切都是可能的，因为 Quasar 框架在 CLI 上封装了构建、解析和捆绑。您不需要担心使用 Electron、Cordova 甚至 Babel 的 webpack 和配置。

一个简单的 CLI 命令可以为您生成全新的页面、布局、组件、存储、路由，甚至是一个新的构建。由于 CLI 只是 Vue、webpack、Babel 和其他工具的包装器，您不必只使用 Quasar 的可视组件。如果您不想使用它们，可以选择不导入它们，并利用 CLI 构建应用程序的功能。

## 另请参阅

您可以在[`quasar.dev/introduction-to-quasar`](https://quasar.dev/introduction-to-quasar)的文档中了解更多关于 Quasar 框架的信息

在[`quasar.dev/quasar-cli/developing-spa/introduction`](https://quasar.dev/quasar-cli/developing-spa/introduction)上阅读有关 Quasar 的 SPA 开发的更多信息

在[`quasar.dev/quasar-cli/developing-pwa/introduction`](https://quasar.dev/quasar-cli/developing-pwa/introduction)上阅读有关 Quasar 的 PWA 开发的更多信息

在[`quasar.dev/quasar-cli/developing-ssr/introduction`](https://quasar.dev/quasar-cli/developing-ssr/introduction)上阅读有关 Quasar 的 SSR 开发的更多信息

在[`quasar.dev/quasar-cli/developing-cordova-apps/introduction`](https://quasar.dev/quasar-cli/developing-cordova-apps/introduction)上阅读有关 Quasar 的移动应用开发的更多信息

在[`cordova.apache.org`](https://cordova.apache.org)上阅读有关 Cordova 项目的更多信息

在[`quasar.dev/quasar-cli/developing-electron-apps/introduction`](https://quasar.dev/quasar-cli/developing-electron-apps/introduction)上阅读有关 Quasar 的桌面应用程序开发的更多信息

在[`electronjs.org/`](https://electronjs.org/)上阅读有关 Electron 项目的更多信息

在[`github.com/electron/electron-packager`](https://github.com/electron/electron-packager)上阅读有关`electron-packager`的更多信息

在[`electron.github.io/electron-packager/master/interfaces/electronpackager.options.html`](https://electron.github.io/electron-packager/master/interfaces/electronpackager.options.html)找到`electron-packager`选项 API。

在[`www.electron.build/`](https://www.electron.build/)了解更多关于`electron-build`的信息。

在[`www.electron.build/configuration/configuration`](https://www.electron.build/configuration/configuration)找到`electron-build`选项 API。

# 创建更智能的 Vue 观察者和计算属性

在 Vue 中，使用观察者和计算属性总是一个很好的解决方案，可以检查和缓存您的数据，但有时这些数据需要一些特殊处理，或者需要与预期不同的方式进行操作。有一些方法可以赋予这些 Vue API 新的生命，帮助您的开发和生产力。

## 如何做...

我们将把这个配方分为两类：一个是观察者，另一个是计算属性。有些方法通常一起使用，比如`non-cached`计算和`deep-watched`值。

### 观察者

选择这三个观察者配方是为了提高生产力和最终代码质量。使用这些方法可以减少代码重复，提高代码重用。

#### 使用方法名

所有观察者都可以接收方法名而不是函数，从而避免编写重复的代码。这将帮助您避免重写相同的代码，或者检查值并将其传递给函数：

```js
<script>
export default {
  watch: {
    myField: 'myFunction',
  },
  data: () => ({
    myField: '',
  }),
  methods: {
    myFunction() {
      console.log('Watcher using method name.');
    },
 },
};
</script>
```

#### 立即调用和深度监听

通过传递一个属性立即执行您的观察者，并通过调用`deep`属性使其无论值的变化深度如何都执行：

```js
<script>
export default {
  watch: {
    myDeepField: {
      handler(newVal, oldVal) {
        console.log('Using Immediate Call, and Deep Watch');
        console.log('New Value', newVal);
        console.log('Old Value', oldVal);
      },
      deep: true,
      immediate: true,
    },
  },
  data: () => ({
    myDeepField: '',
  }),
};
</script>
```

#### 多个处理程序

您可以使您的观察者同时执行多个处理程序，而无需将观察处理程序设置为绑定到唯一的函数：

```js
<script>
export default {
  watch: {
    myMultiField: [
      'myFunction',
      {
        handler(newVal, oldVal) {
          console.log('Using Immediate Call, and Deep Watch');
          console.log('New Value', newVal);
          console.log('Old Value', oldVal);
        },
        immediate: true,
      },
    ],
  },
  data: () => ({
    myMultiField: '',
  }),
  methods: {
    myFunction() {
      console.log('Watcher Using Method Name');
    },
  },
};
</script>
```

### 计算属性

有时计算属性只是作为简单的基于缓存的值使用，但它们有更大的潜力。以下是两种显示如何提取此功能的方法。

#### 无缓存值

通过将`cache`属性设置为`false`，您可以使计算属性始终更新值，而不是缓存值：

```js
<script>
export default {
  computed: {
    field: {
      get() {
       return Date.now();
      },
      cache: false,
   },
  },
};
</script>
```

#### 获取器和设置器

您可以向计算属性添加一个 setter 函数，并使其成为一个完全完整的数据属性，但不绑定到数据。

不建议这样做，但是可能，在某些情况下，你可能需要这样做。一个例子是当你需要以毫秒保存日期，但需要以 ISO 格式显示它。使用这种方法，你可以让`dateIso`属性`get`和`set`值：

```js
<script>
export default {
  data: () => ({
    dateMs: '',
  }),
  computed: {
    dateIso: {
      get() {
        return new Date(this.dateMs).toISOString();
      },
      set(v) {
        this.dateMs = new Date(v).getTime();
      },
   },
  },
};
</script>
```

## 另请参阅

您可以在[`vuejs.org/v2/api/#watch`](https://vuejs.org/v2/api/#watch)找到有关 Vue `watch` API 的更多信息。

您可以在[`vuejs.org/v2/api/#computed`](https://vuejs.org/v2/api/#computed)找到有关 Vue `computed` API 的更多信息。

# 使用 Python Flask 作为 API 创建 Nuxt.js SSR

`Nuxt.js`是一个服务器端渲染框架，可以在服务器端渲染所有内容并将其加载。通过这个过程，页面获得了 SEO 的力量和在渲染之前快速的 API 获取。

正确使用它，您可以实现一个功能强大的 SPA 或 PWA，以前是不可能的。

在后端，Python 是一种解释性动态语言，速度快，稳定。具有活跃的用户群和快速的学习曲线，非常适合服务器 API。

将两者结合起来，可以尽快部署一个强大的应用程序。

## 准备工作

这个配方的先决条件如下：

+   Node.js 12+

+   Python

所需的 Node.js 全局对象如下：

+   `create-nuxt-app`

要安装`create-nuxt-app`，您需要在终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）中执行以下命令：

```js
> npm  install -g create-nuxt-app
```

对于这个配方的后端，我们将使用**Python**。这个配方所需的 Python 全局对象如下：

+   `flask`

+   `flask-restful`

+   `flask-cors`

要安装`flask`，`flask-restful`和`flask-cors`，您需要在终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）中执行以下命令：

```js
> **pip** install **flask**
> **pip install flask-restful**
> **pip install flask-cors**
```

## 如何做...

我们需要将我们的配方分成两部分。第一部分是后端部分（或者如果你喜欢的话是 API），将使用 Python 和 Flask 完成。第二部分将是前端部分，它将在 SSR 模式下运行`Nuxt.js`。

### 创建您的 Flask API

我们的 API 服务器将基于 Python Flask 框架。我们需要创建一个服务器文件夹来存储我们的服务器文件并开始服务器的开发。

您将需要安装以下 Python 软件包。要这样做，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

+   要安装 Flask 框架，请使用以下命令：

```js
> **pip** install flask
```

+   要安装 Flask RESTful 扩展，使用以下命令：

```js
> **pip install flask-restful**
```

+   要安装 Flask CORS 扩展，使用以下命令：

```js
> **pip install flask-cors**
```

#### 初始化应用程序

为了创建我们的简单 RESTful API，我们将创建一个单一的文件，并使用 SQLite3 作为数据库：

1.  创建一个名为`server`的文件夹，并在其中创建一个名为`app.py`的文件：

```js
import sqlite3 as sql
from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_cors import CORS

app = Flask(__name__)
api = Api(app)
CORS(app)

parser = reqparse.RequestParser()

conn = sql.connect('tasks.db')
conn.execute('CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY 
   KEY AUTOINCREMENT, task TEXT)')
conn.close()
```

1.  然后，我们将创建我们的`ToDo`类，并在类的构造函数中连接到数据库并选择所有的`tasks`：

```js
class ToDo(Resource):
    def get(self):
        con = sql.connect('tasks.db')
        cur = con.cursor()
        cur.execute('SELECT * from tasks')
        tasks = cur.fetchall()
        con.close()

        return {
            'tasks': tasks
        }
```

1.  要实现 RESTful POST 方法，创建一个函数来接收`task`作为参数，并将带有添加的`task`、添加的`status`的对象添加到任务列表中，然后将列表返回给用户：

```js
 def post(self):
        parser.add_argument('task', type=str)
        args = parser.parse_args()

        con = sql.connect('tasks.db')
        cur = con.cursor()
        cur.execute('INSERT INTO tasks(task) values ("
                       {}")'.format(args['task']))
        con.commit()
        con.close()

        return {
            'status': True,
            'task': '{} added.'.format(args['task'])
        }
```

1.  接下来，我们将创建 RESTful PUT 方法，通过创建一个函数来接收`task`和`id`作为函数的参数。然后，这个函数将使用当前的`id`更新`task`，并将更新后的`task`和更新的`status`返回给用户：

```js
def put(self, id):
        parser.add_argument('task', type=str)
        args = parser.parse_args()

        con = sql.connect('tasks.db')
        cur = con.cursor()
        cur.execute('UPDATE tasks set task = "{}" WHERE id = 
           {}'.format(args['task'], id))
        con.commit()
        con.close()

        return {
            'id': id,
            'status': True,
            'task': 'The task {} was updated.'.format(id)
        }
```

1.  然后，创建一个 RESTful DELETE 方法，通过创建一个函数来接收将被移除的`task`的`ID`，然后将返回被移除的`ID`、`status`和`task`给用户：

```js
 def delete(self, id):
        con = sql.connect('tasks.db')
        cur = con.cursor()
        cur.execute('DELETE FROM tasks WHERE id = {}'.format(id))
        con.commit()
        con.close()

        return {
            'id': id,
            'status': True,
            'task': 'The task {} was deleted.'.format(id)
        }
```

1.  最后，我们将在`'/'`路由上将`ToDo`类作为 API 的资源，并初始化应用程序：

```js
api.add_resource(ToDo, '/', '/<int:id>')

if __name__ == '__main__':
    app.run(debug=True)
```

#### 启动服务器

要启动服务器，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> python server/app.py
```

您的服务器将在`http://localhost:5000`上运行并监听。

### 创建您的 Nuxt.js 服务器

要渲染您的应用程序，您需要创建您的`Nuxt.js`应用程序。使用`Nuxt.js`的`create-nuxt-app` CLI，我们将创建它并为其选择一些选项。打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> create-nuxt-app client
```

然后，您将被问及安装过程的一些问题。我们将使用以下内容：

1.  当您使用`Nuxt-CLI`开始创建项目时，它将首先要求项目名称。在我们的情况下，我们将选择`client`作为名称：

```js
**Project Name:** **client**
```

1.  然后，您需要选择将在项目中使用的编程语言。我们将选择`JavaScript`：

```js
> Programming language: (Use arrow keys)
   ❯ JavaScript
 TypeScript
```

1.  接下来，`Nuxt-CLI`将要求选择将用于安装依赖项的软件包管理器。在我们的情况下，我们选择`Yarn`，但您可以选择您喜欢的软件包管理器：

```js
> Package manager: (Use arrow keys) 
   ❯ Yarn
 npm
```

1.  现在，`Nuxt-CLI`将要求选择在项目中使用的 UI 框架。从可用列表中选择`Bulma`：

```js
**> UI Framework:** **Bulma**
```

1.  然后，`Nuxt-CLI` 将询问您是否要为项目选择额外的模块。我们将从当前模块列表中选择 `Axios`：

```js
**> Nuxt.JS modules:**  **Axios**
```

1.  `Nuxt-CLI` 将询问我们想要在项目上使用的 linting 工具；我们将选择 `None`：

```js
**> Choose Linting tools:**  **None**
```

1.  然后，`Nuxt-CLI` 将询问我们想要在项目上实现的测试框架；我们将选择 `None`：

```js
**> Choose Test Framework:  None**
```

1.  接下来，`Nuxt-CLI` 将询问项目将使用的渲染模式；我们将选择 `Universal (SSR)`：

```js
**> Choose  Rendering Mode:  Universal (SSR)**
```

1.  `Nuxt-CLI` 将询问将在构建结构上使用的部署目标；我们将选择 `Server (Node.js hosting)`：

```js
> Deployment target: Server (Node.js hosting)
```

1.  最后，`Nuxt-CLI` 将询问我们想要使用的开发工具配置；我们将选择 `jsconfig.json`：

```js
> Development tools: jsconfig.json
```

在 CLI 完成安装过程后，我们可以在编辑器或 IDE 中打开 `client` 文件夹。

#### 将 Bulma 添加到全局 CSS

要将 Bulma 添加到应用程序中，我们需要在 `nuxt` 配置文件中声明它，方法如下：

1.  在 `client` 文件夹中打开 `nuxt.config.js`。

1.  然后，更新 CSS 属性并添加 Bulma 导入，以使其在应用程序的全局范围内可用：

```js
export default {
  /* We need to change only the css property for now, */
  /* the rest we will maitain the same */
  /*
   ** Global CSS
   */
  css: ['bulma/css/bulma.css'],
}

```

#### 配置 axios 插件

要开始创建我们的 API 调用，我们需要在应用程序中添加 `axios` 插件：

1.  为此，我们需要打开根文件夹中的 `nuxt.config.js` 文件，并添加 `axios` 属性：

```js
export default {
  /* We need to change only the axios property for now, */
  /* the rest we will maitain the same */
  axios: {},
}
```

1.  在 `axios` 属性上，添加以下配置属性：

+   `HOST` 并将其定义为 `'127.0.0.1'`

+   `PORT` 并将其定义为 `'5000'`

+   `https` 并将其定义为 `false`

+   `debug` 并将其定义为 `true`：

```js
axios: {
  HOST: '127.0.0.1',
  PORT: '5000',
  https: false,
  debug: true, // Only on development
},
```

### 运行 Nuxt.js 服务器

现在您已经设置好了一切，想要运行服务器并开始查看发生了什么。`Nuxt.js` 自带一些预先编程的 `npm` 脚本。您可以通过打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令之一来运行其中之一：

+   `npm run dev` - 以开发模式运行服务器

+   `npm run build` - 使用 webpack 构建文件并对生产环境进行 CSS 和 JS 的最小化

+   `npm run generate` - 为每个路由生成静态 HTML 页面

+   `npm start` - 在运行构建命令后，启动生产服务器

### 创建 TodoList 组件

对于 TodoList 应用程序，我们将需要一个组件来获取任务并删除任务。

#### 单文件组件的 `<script>` 部分

在这里，我们将创建单文件组件的 `<script>` 部分：

1.  在`client/components`文件夹中，创建一个名为`TodoList.vue`的文件并打开它。

1.  然后，我们将导出一个`default`的 JavaScript 对象，其中`name`属性定义为`TodoList`，然后将`beforeMount`生命周期钩子定义为一个异步函数。将`computed`和`methods`属性定义为一个空的 JavaScript 对象。然后，创建一个`data`属性，定义为返回一个 JavaScript 对象的单例函数。在`data`属性中，创建一个`taskList`属性，定义为一个空数组：

```js
export default {
  name: 'TodoList',
  data: () => ({
    taskList: [],
  }),
  computed: {},
  async beforeMount() {},
  methods: {},
};
```

1.  在`computed`属性中，创建一个名为`taskObject`的新属性。这个`computed`属性将返回`Object.fromEntries(new Map(this.taskList))`的结果：

```js
taskObject() {
      return Object.fromEntries(new Map(this.taskList));
    },
```

1.  在`methods`属性中，创建一个名为`getTask`的新方法 - 它将是一个异步函数。这个方法将从服务器获取任务，然后将使用响应来定义`taskList`属性：

```js
async getTasks() {
      try {
        const { tasks } = await 
           this.$axios.$get('http://localhost:5000');
        this.taskList = tasks;
      } catch (err) {
        console.error(err);
      }
    },
```

1.  然后，创建一个`deleteTask`方法。这个方法将是一个异步函数，并将接收一个`id`作为参数。使用这个参数，它将执行一个 API 执行来删除任务，然后执行`getTask`方法：

```js
async deleteTask(i) {
      try {
        const { status } = await 
           this.$axios.$delete(`http://localhost:5000/${i}`);
        if (status) {
          await this.getTasks();
        }
      } catch (err) {
        console.error(err);
      }
    },
```

1.  最后，在`beforeMount`生命周期钩子中，我们将执行`getTask`方法：

```js
async beforeMount() {
    await this.getTasks();
  },
```

#### 单文件组件<template>部分

现在是创建单文件组件的`<template>`部分的时候了：

1.  在`client/components`文件夹中，打开`TodoList.vue`文件。

1.  在`<template>`部分，创建一个`div`HTML 元素，并添加值为`box`的`class`属性：

```js
<div class="box"></div>
```

1.  作为`div.box`HTML 元素的子元素，创建一个`div`HTML 元素，`class`属性定义为`content`，具有一个子元素定义为`ol`HTML 元素，属性`type`定义为`1`：

```js
<div class="content">
  <ol type="1"></ol>
</div>
```

1.  作为`ol`HTML 元素的子元素，创建一个`li`HTML 元素，其中`v-for`指令定义为`(task, i) in taskObject`，`key`属性定义为一个变量`i`：

```js
<li
  v-for="(task, i) in taskObject"
  :key="i">
</li>
```

1.  最后，作为`ol`HTML 元素的子元素，将`{{ task }}`添加为内部文本，并作为文本的兄弟元素，创建一个`button`HTML 元素，`class`属性定义为`delete is-small`，`@click`事件监听器定义为`deleteTask`方法，传递`i`变量作为参数：

```js
{{ task }}
<button
  class="delete is-small"
  @click="deleteTask(i)"
/>
```

### 创建 Todo 表单组件

将任务发送到服务器，我们需要一个表单。这意味着我们需要创建一个表单组件来处理这个任务。

#### 单文件组件<script>部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`client/components`文件夹中，创建一个名为`TodoForm.vue`的文件并打开它。

1.  然后，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`TodoForm`，然后将`methods`属性定义为空的 JavaScript 对象。然后，创建一个`data`属性，定义为返回 JavaScript 对象的单例函数。在`data`属性中，创建一个`task`属性作为空数组：

```js
export default {
  name: 'TodoForm',
  data: () => ({
    task: '',
  }),
  methods: {},
};
```

1.  在`methods`属性中，创建一个名为`save`的方法，这将是一个异步函数。这个方法将`task`发送到 API，如果 API 接收到`Ok 状态`，它将发出一个带有`task`的`'new-task'`事件，并清除`task`属性：

```js
async save() {
      try {
        const { status } = await 
          this.$axios.$post('http://localhost:5000/', {
          task: this.task,
        });
        if (status) {
          this.$emit('new-task', this.task);
          this.task = '';
        }
      } catch (err) {
        console.error(err);
      }
    },
```

#### 单文件组件<template>部分

现在是时候创建单文件组件的`<template>`部分了：

1.  在`client/components`文件夹中，打开名为`TodoForm.vue`的文件。

1.  在`<template>`部分中，创建一个`div` HTML 元素，并添加`class`属性，值为`box`：

```js
<div class="box"></div>
```

1.  在`div.box` HTML 元素内部，创建一个`div` HTML 元素，`class`属性定义为`field has-addons`：

```js
<div class="field has-addons"></div>
```

1.  然后，在`div.field.has-addons` HTML 元素内部，创建一个子`div` HTML 元素，`class`属性定义为`control is-expanded`，并添加一个子输入 HTML 元素，`v-model`指令定义为`task`属性。然后，将`class`属性定义为`input`，`type`属性定义为`text`，`placeholder`定义为`ToDo Task`。最后，在`@keypress.enter`事件监听器中，定义`save`方法：

```js
<div class="control is-expanded">
  <input
    v-model="task"
    class="input"
    type="text"
    placeholder="ToDo Task"
    @keypress.enter="save"
  >
</div>
```

1.  最后，在`div.control.is-expanded` HTML 元素的同级位置，创建一个`div` HTML 元素，`class`属性定义为`control`，并添加一个子`a` HTML 元素，`class`属性定义为`button is-info`，在`@click`事件监听器中，将其定义为`save`方法。在`a` HTML 元素的内部文本中，添加`Save Task`文本：

```js
<div class="control">
  <a
    class="button is-info"
    @click="save"
  >
    Save Task
  </a>
</div>
```

### 创建布局

现在我们需要创建一个新的布局来包装应用程序作为一个简单的高阶组件。在`client/layouts`文件夹中，打开名为`default.vue`的文件，删除文件的`<style>`部分，并将`<template>`部分更改为以下内容：

```js
<template>   
    <nuxt />
</template>
```

### 创建页面

现在我们将创建我们应用程序的主页面，用户将能够查看他们的`TodoList`并添加一个新的`TodoItem`。

#### 单文件组件<script>部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`client/pages`文件夹中打开`index.vue`文件。

1.  导入我们创建的`todo-form`和`todo-list`组件，然后我们将导出一个带有`components`属性的`default` JavaScript 对象，其中包含导入的组件。

```js
<script>
import TodoForm from '../components/TodoForm.vue';
import TodoList from '../components/TodoList.vue';

export default {
  components: { TodoForm, TodoList },
};
</script>
```

#### 单文件组件<template>部分

现在是创建单文件组件的`<template>`部分的时候了：

1.  在`client/pages`文件夹中，打开`index.vue`文件。

1.  在`<template>`部分，创建一个`div` HTML 元素，作为子元素添加一个`class`属性定义为`hero is-primary`的`section` HTML 元素。然后，作为`section` HTML 元素的子元素，创建一个`class`属性定义为`hero-body`的`div` HTML 元素。作为`div.hero-body` HTML 元素的子元素，创建一个`class`属性定义为`container`的`div` HTML 元素，并作为子元素添加一个`class`定义为`title`的`h1` HTML 元素，其中内部文本为`Todo App`。

```js
<section class="hero is-primary">
 <div class="hero-body">
 <div class="container">
 <h1 class="title">
  Todo App
      </h1>
 </div>
 </div> </section>
```

1.  作为`section.hero.is-primary` HTML 元素的兄弟元素，创建一个`section` HTML 元素，其中`class`属性定义为`section`，`style`属性定义为`padding: 1rem`。作为子元素添加一个`class`属性定义为`container`的`div` HTML 元素，其中包含一个`ref`属性定义为`list`的`todo-list`组件。

```js
<section
  class="section"
  style="padding: 1rem" >
 <div class="container">
 <todo-list
  ref="list"
  />
 </div> </section>
```

1.  最后，作为`section.section` HTML 元素的兄弟元素，创建一个`section` HTML 元素，其中`class`属性定义为`section`，`style`属性定义为`padding: 1rem`。作为子元素添加一个`class`属性定义为`container`的`div` HTML 元素，其中包含一个`todo-form`组件，其中`@new-task`事件监听器定义为`$refs.list.getTasks()`。

```js
<section
  class="section"
  style="padding: 1rem" >
 <div class="container">
 <todo-form
  @new-task="$refs.list.getTasks()"   />
 </div> </section>
```

## 工作原理...

此示例显示了通过 Python 的本地 API 服务器与通过`Nuxt.js`提供的 SSR 平台之间的集成。

当您首先启动 Python 服务器时，您正在打开端口以接收来自客户端的数据作为被动客户端，只是等待某些事件发生以启动您的代码。通过相同的过程，`Nuxt.js` SSR 可以在幕后执行很多操作，但完成后会变得空闲，等待用户操作。

当用户与前端交互时，应用程序可以向服务器发送一些请求，服务器将把数据返回给用户，以在屏幕上显示。

## 另请参阅

您可以在[`palletsprojects.com/p/flask/.`](https://palletsprojects.com/p/flask/)了解有关 Flask 和 Python 内部的 HTTP 项目的更多信息。

如果您想了解更多关于`Nuxt.js`的信息，可以在[`nuxtjs.org/guide/.`](https://nuxtjs.org/guide/)阅读文档。

如果您想了解`Nuxt.js`对 Axios 的实现以及如何配置它和使用插件，可以在[`axios.nuxtjs.org/options.`](https://axios.nuxtjs.org/options)阅读文档。

如果您想了解在本教程中使用的 CSS 框架 Bulma，可以在[`bulma.io.`](https://bulma.io)找到更多信息。

# Vue 应用程序的 Dos 和 Don'ts

安全性始终是每个人都担心的事情，对于技术也是如此。您需要时刻保持警惕。在本节中，我们将看看如何使用一些技术和简单的解决方案来防止攻击。

## 检查器

在使用 ESLint 时，请确保已启用 Vue 插件，并且遵循强烈推荐的规则。这些规则将帮助您进行开发，检查一些常见的错误，这些错误可能会打开攻击的大门，比如`v-html`指令。

在`Vue-CLI`项目中，选择了检查器选项后，将会创建一个名为`.eslintrc.js`的文件，以及项目文件。在这个文件中，一组基本规则将被预先确定。以下是一个`ESLint + AirBnb`项目的一组良好实践规则的示例：

```js
module.exports = {
  root: true,
  env: {
    node: true,
  },
  extends: [
    'plugin:vue/essential',
    'plugin:vue/recommended',
    'plugin:vue/strongly-recommended',
    '@vue/airbnb',
  ],
parserOptions: {
    parser: 'babel-eslint',
  },
rules: {
 'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'off',
 'no-debugger': process.env.NODE_ENV === 'production' ? 'error' : 'off',
 }, 
};
```

现在，如果您有任何违反检查规则的代码，它将不会在开发或构建中被解析。

## JavaScript

JavaScript 具有一些漏洞，可以通过遵循一些简单的清单和简单的实现来预防。这些实现可以是客户端-服务器通信或 DOM 操作，但您始终需要小心不要忘记它们。

以下是一些使用 JavaScript 的技巧：

+   尽可能使用经过身份验证和加密的 API。请记住，JWT 本身并不是加密的；您需要添加加密层（JWE）才能拥有完整的 JSON。

+   如果您想存储 API 令牌，请始终使用`SessionStorage`。

+   在将用户输入的 HTML 发送到服务器之前，始终对其进行消毒。

+   在将 HTML 呈现到 DOM 之前，始终对其进行消毒。

+   永远要对用户输入的`RegeExp`进行转义；它将被执行，以防止任何 CPU 线程攻击。

+   始终捕获错误，并且不要向用户显示任何堆栈跟踪，以防止任何代码操纵。

以下是在使用 JavaScript 时不要做的一些提示：

+   永远不要使用`eval()`；它会使您的代码运行缓慢，并为恶意代码在您的代码内执行打开一扇门。

+   永远不要呈现来自用户的任何输入而没有经过消毒或转义的数据。

+   永远不要在 DOM 上呈现任何未经过消毒的 HTML。

+   永远不要将 API 令牌存储在`LocalStorage`中。

+   永远不要在 JWT 对象中存储敏感数据。

## Vue

在开发 Vue 应用程序时，您需要检查一些基本规则，这些规则可以帮助开发，并且不会为外部操纵您的应用程序打开任何大门。

以下是一些使用 Vue 的提示：

+   始终为您的 props 添加类型验证，并在可能的情况下进行验证检查。

+   避免全局注册组件；使用本地组件。

+   尽可能使用延迟加载的组件。

+   使用`$refs`而不是直接 DOM 操作。

以下是在使用 Vue 时不要做的一些提示：

+   永远不要在窗口或任何全局范围上存储`Vue`，`$vm`，`$store`或任何应用程序变量。

+   永远不要修改 Vue 原型；如果需要向原型添加新变量，请创建一个新的 Vue 插件。

+   不建议直接在组件之间建立连接，因为这将使组件绑定到父级或子级。

## 另请参阅

您可以在 OWASP CheatCheat 的[`github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md`](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)和[`html5sec.org/`](https://html5sec.org/)找到有关 XSS（跨站点脚本）的更多信息。

在[`eslint.vuejs.org/`](https://eslint.vuejs.org/)找到有关`eslint-vue-plugin`的更多信息。

您可以在[`github.com/i0natan/nodebestpractices#6-security-best-practices`](https://github.com/i0natan/nodebestpractices#6-security-best-practices)了解有关 Node.js 安全最佳实践的更多信息。

在[`quasar.dev/security/dos-and-donts`](https://quasar.dev/security/dos-and-donts)找到有关 Vue 应用程序的 dos 和 don'ts 的更多信息。
