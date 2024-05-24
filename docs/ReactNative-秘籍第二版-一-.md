# ReactNative 秘籍第二版（一）

> 原文：[`zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce`](https://zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的部分内容需要 macOS 才能使用的软件。虽然 React Native 开发可以在 Windows 机器上完成，但是某些方面，比如在 iOS 设备和 iOS 模拟器上运行应用程序，或者使用 Xcode 编辑本地代码，只能在 Mac 上完成。

开发人员有许多种方式来构建 iOS 或 Android 应用程序。React Native 是构建混合移动应用程序的最稳定、性能最佳和开发人员友好的选择之一。使用 React Native 开发移动应用程序允许开发人员在单个代码库中构建 iOS 和 Android 应用程序，并且可以在两个平台之间共享代码。

更好的是，有经验在 React 中构建 Web 应用程序的开发人员将会处于领先地位，因为许多相同的模式和约定都被延续到 React Native 中。如果您有使用 React 或其他基于**模型**、**视图**、**组件**（MVC）的框架构建 Web 应用程序的经验，那么在 React Native 中构建移动应用程序会让您感到宾至如归。

目前有两种广泛使用的方法来创建和开发 React Native 应用程序：使用 React Native CLI 进行纯 React Native 开发，或者使用 Expo（[www.expo.io](http://www.expo.io)），这是一套全面的工具、库和服务，用于开发 React Native 应用程序。除非您需要访问 React Native 的某些通常更高级的功能，Expo 是我推荐的 React Native 开发工具。Expo 具有许多功能，可以改善开发体验，例如通过 Expo SDK 访问更多本地功能，更灵活和友好的 CLI，以及用于常见开发任务的基于浏览器的 GUI。这就是为什么本书中不需要纯 React Native 的所有食谱都使用 Expo 实现。有关 React Native 和 Expo 之间的区别，请查看第十章“应用程序工作流程和第三方插件”中的*React Native 开发工具*部分。

本书旨在成为构建各种应用程序时常见问题解决方案的参考手册。每一章都以一系列逐步说明的食谱呈现，每个食谱都解释了如何构建整个应用程序的单个功能。

React Native 是一种不断发展的语言。在撰写本文时，它仍处于开发生命周期的 0.5x 阶段，因此未来几个月甚至几年可能会发生一些变化。最佳实践可能会变成陈旧的想法，或者在这里突出显示的开源软件包可能会不受青睐。本书中的每个示例都经过了更新和修订，以反映开发过程的更新并提高清晰度。我已尽力使本文尽可能保持最新，但技术发展迅速，因此一本书无法单独跟上。本书中涵盖的所有代码存储在 GitHub 上。如果您发现这里的代码有任何问题，请提交问题。或者，如果您有更好的方法来做某事，请考虑提交拉取请求！

无论这本书中的任何内容有何更新，您都可以在 GitHub 存储库中找到详细信息和更改。

希望您在 React Native 的学习过程中找到这本书有所帮助。祝您开发愉快！

# 这本书适合谁

本书旨在面向初学者到中级水平的 React Native 开发人员。即使您没有太多的 Web 开发经验，本书中的 JavaScript 也希望不会超出您的理解范围。我尽量避免复杂性，以便将重点放在每个示例中所教授的课程上。

本书还假设开发人员使用运行 macOS 的计算机。虽然在 Windows 或 Linux 上开发 React Native 应用程序在技术上是可能的，但有许多限制使 macOS 机器在 React Native 开发中更可取，包括通过 Xcode 与本机 iOS 代码一起工作，在 iOS 模拟器上运行 iOS 代码，并使用最强大的 React Native 应用程序开发工具。

# 这本书涵盖了什么

第一章，*设置您的环境*，介绍了我们将安装的不同软件，以便开始开发 React Native 应用程序。

第二章，*创建一个简单的 React Native 应用*，介绍了构建布局和导航的基础知识。本章中的示例作为 React Native 开发的入门，并涵盖了大多数移动应用程序中的基本功能。

第三章《实现复杂用户界面-第一部分》涵盖了包括自定义字体和自定义可重用主题在内的功能。

第四章《实现复杂用户界面-第二部分》继续基于 UI 功能的更多技巧。它涵盖了处理屏幕方向变化和构建用户表单等功能。

第五章《实现复杂用户界面-第三部分》涵盖了构建复杂 UI 时可能需要的其他常见功能。本章涵盖了添加地图支持、实现基于浏览器的身份验证和创建音频播放器。

第六章《为您的应用添加基本动画》涵盖了创建动画的基础知识。

第七章《为您的应用添加高级动画》继续在上一章的基础上构建，增加了更高级的功能。

第八章《处理应用逻辑和数据》向我们介绍了处理数据的应用程序的构建。我们将涵盖一些主题，包括本地存储数据和优雅地处理网络丢失。

第九章《实现 Redux》涵盖了使用 Redux 库实现 Flux 数据模式。Redux 是处理 React 应用程序中的数据流的经过实战检验的方法，在 React Native 中同样有效。

第十章《应用程序工作流程和第三方插件》涵盖了开发人员可以使用的构建应用程序的不同方法，以及如何使用开源代码构建应用程序。这也将涵盖使用纯 React Native（使用 React Native CLI）构建应用程序和使用 Expo（一个全面的开发工具）构建应用程序之间的区别。

第十一章《添加原生功能-第一部分》涵盖了在 React Native 应用程序中使用原生 iOS 和 Android 代码的基础知识。

第十二章《添加原生功能-第二部分》涵盖了在 React Native 和原生层之间进行通信的更复杂的技术。

第十三章《与原生应用集成》涵盖了将 React Native 与现有原生应用集成的内容。并非每个应用都可以从头开始构建。这些技巧对于需要将他们的工作与已经在应用商店中的应用集成的开发人员应该是有帮助的。

第十四章*部署您的应用程序*介绍了部署 React Native 应用程序的基本流程，以及使用 HockeyApp 跟踪应用程序指标的详细信息。

第十五章，*优化您的应用程序的性能*，介绍了编写高性能 React Native 代码的一些技巧和最佳实践。

# 为了充分利用本书

假设您具有以下理解水平：

+   您具有一些基本的编程知识。

+   您熟悉 Web 开发基础知识。

如果您还具有以下内容，将会很有帮助：

+   具有 React、Vue 或 Angular 经验

+   至少具有中级水平的 JavaScript 经验

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 上使用 WinRAR/7-Zip

+   Mac 上使用 Zipeg/iZip/UnRarX

+   Linux 上使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/warlyware/react-native-cookbook`](https://github.com/warlyware/react-native-cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781788991926_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788991926_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 用户名。这是一个例子：“我们将使用一个带有一个`liked`布尔属性的`state`对象来实现这个目的。”

代码块设置如下：

```jsx
export default class App extends React.Component {
  state = {
    liked: false,
  };

  handleButtonPress = () => {
    // We'll define the content on step 6
  }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```jsx
onst styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  topSection: {
    flexGrow: 3,
    backgroundColor: '#5BC2C1',
 alignItems: 'center',
  },
```

任何命令行输入或输出都以以下方式编写：

```jsx
expo init project-name
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“单击 Components 选项卡，并从提供的模拟器列表中安装一个模拟器。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。

# 部分

在本书中，您会发现一些经常出现的标题（*Getting ready*，*How to do it...*，*How it works...*，*There's more...*，和 *See also*）。

为了清晰地说明如何完成一个食谱，使用以下部分：

# 准备工作

这一部分告诉您在食谱中可以期待什么，并描述如何设置食谱所需的任何软件或任何初步设置。

# 如何做…

这一部分包含了遵循食谱所需的步骤。

# 它是如何工作的…

这一部分通常包括对前一部分发生的事情的详细解释。

# 还有更多…

这一部分包含了有关食谱的额外信息，以使您对食谱更加了解。

# 另请参阅

这一部分为食谱提供了有用的链接到其他有关食谱的信息。


# 第一章：设置您的环境

自第一版以来，React Native 生态系统已经发生了相当大的变化。特别是，开源工具 Expo.io 已经简化了项目初始化和开发阶段，使得在 React Native 中的工作比 0.36 版本中更加愉快。

使用 Expo 工作流程，您将能够仅使用 JavaScript 构建本机 iOS 和 Android 应用程序，在 iOS 模拟器和 Android 模拟器中进行实时重新加载，并通过 Expo 应用程序轻松测试您的应用程序在任何真实设备上。除非您需要访问原生代码（比如，与来自单独代码库的遗留原生代码集成），否则您可以完全在 JavaScript 中开发应用程序，而无需使用 Xcode 或 Android Studio。如果您的项目最终发展成必须支持原生代码的应用程序，Expo 提供了将您的项目弹出的功能，这将使您的应用程序变成原生代码，以便在 Xcode 和 Android Studio 中使用。有关弹出您的 Expo 项目的更多信息，请参阅第十章，*应用程序工作流程和第三方插件*。

Expo 是一种很棒的方式，可以在 Android 和 iOS 设备上构建功能齐全的应用程序，而无需处理原生代码。让我们开始吧！

在本章中，我们将涵盖以下主题：

+   安装依赖项

+   初始化您的第一个应用程序

+   在模拟器/仿真器中运行您的应用程序

+   在真实设备上运行您的应用程序

# 技术要求

本章将涵盖您在本书中将要使用的工具的安装。它们包括：

+   Expo

+   Xcode（仅适用于 iOS 模拟器，仅限 macOS）

+   Android Studio

+   Node.js

+   看门人

# 安装依赖项

构建我们的第一个 React Native 应用程序的第一步是安装依赖项以开始。

# 安装 Xcode

如本章介绍的，Expo 为我们提供了一种工作流程，可以避免完全在 Xcode 和 Android Studio 中工作，因此我们可以完全使用 JavaScript 进行开发。但是，为了在 iOS 模拟器中运行您的应用程序，您需要安装 Xcode。

Xcode 需要 macOS，因此只有在 macOS 上才能在 iOS 模拟器中运行您的 React Native 应用程序。

Xcode 应该从 App Store 下载。您可以在 App Store 中搜索 Xcode，或使用以下链接：

[`itunes.apple.com/app/xcode/id497799835`](https://itunes.apple.com/app/xcode/id497799835).

Xcode 是一个庞大的下载，所以这部分需要一些时间。安装 Xcode 后，您可以通过 Finder 中的`应用程序`文件夹运行它：

1.  这是您启动 Xcode 时将看到的第一个屏幕。请注意，如果这是您第一次安装 Xcode，您将看不到最近的项目列在右侧：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/fccac559-1b6f-4fbd-a9e1-df9cf7777be4.png)

1.  从菜单栏中选择`Xcode | 偏好设置...`如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/a59eb8ca-7c3e-4103-b906-a6603f12f75f.png)

1.  单击组件选项卡，并从提供的模拟器列表中安装一个模拟器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/cc9d1bb1-78ee-46a4-b705-067611cfe959.png)

1.  安装完成后，您可以从菜单栏中打开模拟器：`Xcode | 打开开发人员工具`|`模拟器`：

**![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/786b9447-3a97-44b9-bfa3-b73e1aeb1b03.png)**

# 安装 Android Studio

Android Studio 附带官方的 Android 模拟器，这是 Expo 在开发过程中推荐使用的模拟器。

# 操作步骤如下...

1.  从[`developer.android.com/studio/`](https://developer.android.com/studio/)下载 Android Studio。

1.  打开下载的文件，并将`Android Studio.app`图标拖动到`应用程序`文件夹图标中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d969b12d-6b0c-42e6-b833-ec29541b3248.png)

1.  安装完成后，我们需要更改 Android Studio 的偏好设置。打开 Android Studio，然后从系统栏中的 Android Studio 菜单中打开`偏好设置`。在`偏好设置`子菜单中，选择`外观和行为`|`系统设置`|`Android SDK`。在`SDK 工具`选项卡下，确保您已安装某个版本的 Android SDK 构建工具，并且如果尚未安装，则安装它。

1.  我们还需要通过编辑`~/.bash_profile`或`~/.bashrc`将 Android SDK 位置添加到系统的`PATH`中。您可以通过添加以下行来实现：

```jsx
export PATH=$PATH:/Users/MY_USER_NAME/Library/Android/sdk
```

请务必将`MY_USER_NAME`替换为您的系统用户名。

1.  在 macOS 上，您还需要在`~/.bash_profile`或`~/.bashrc`中的`PATH`中添加`platform-tools`。您可以通过添加以下行来实现：

```jsx
  PATH=$PATH:/Users/MY_USER_NAME/Library/Android/platform-tools 
```

请务必将`MY_USER_NAME`替换为您的系统用户名。

如果您以前从未编辑过`.bash_profile`或`.bashrc`文件，或者对`PATH`不熟悉，您可以从以下资源获取有关它们的作用以及如何使用它们的更多信息：

+   [`www.rc.fas.harvard.edu/resources/documentation/editing-your-bashrc/`](https://www.rc.fas.harvard.edu/resources/documentation/editing-your-bashrc/)

+   [`www.cyberciti.biz/faq/appleosx-bash-unix-change-set-path-environment-variable/`](https://www.cyberciti.biz/faq/appleosx-bash-unix-change-set-path-environment-variable/)

1.  如果`PATH`已正确更新，则`adb`命令应在终端中起作用。更改生效可能需要重新启动终端。

1.  在安装 Android Studio 的新环境中，您将看到一个欢迎屏幕。开始一个新的应用程序以完全打开软件。然后，从窗口右上角的按钮中选择 AVD 管理器，如下面的步骤所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/6ca12bc5-4d5a-49db-ab25-2c21e2602074.png)

1.  在打开的模态中按“创建虚拟设备”。

1.  在“选择硬件”屏幕中选择一个设备，然后按“下一步”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/ee381f01-110e-4ccf-af75-b169a486ea64.png)

1.  在“系统映像”屏幕的“推荐”选项卡下下载一个系统映像：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/cc9b9206-b23c-450b-9784-fcd823387812.png)

1.  在最后一个屏幕上按“完成”，Android Studio 将创建您的新虚拟设备。可以通过按右上角按钮行中的播放按钮随时运行该设备：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/9ec76ee1-bcef-4a91-a28d-5b3a261d8be0.png)

在开发过程中在 Android 模拟器上运行您的应用程序，Expo 以前建议使用出色的第三方模拟器 Genymotion。然而，从 Expo 版本 29 开始，他们现在建议使用随 Android Studio 一起提供的官方模拟器。

您可以按照官方 Expo 文档中提供的逐步指南，确保 Android Studio 设置正确，以便与 Expo 开发工作流程正常工作。该指南可以在[`docs.expo.io/versions/latest/workflow/android-studio-emulator`](https://docs.expo.io/versions/latest/workflow/android-studio-emulator)找到。

这就是您开始使用 Expo 开发第一个 React Native 应用程序所需的所有设置！但是，对于纯 React Native 应用程序（非 Expo 应用程序），您需要执行一些额外的步骤。纯 React Native 应用程序开发将在第十章*应用程序工作流和第三方插件*中深入介绍。由于此设置过程涉及的内容较多且可能会更改，我建议参考官方指南。您可以在 React Native: 入门指南中找到这些说明，网址为[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html)，位于使用本地代码构建项目部分。

一旦模拟器打开，通过菜单栏选择您想要的 iOS 设备：硬件|设备| [IOS 版本] | [iOS 设备]。将来在模拟器中运行 Expo 应用程序时，应该会自动使用相同的设备。

如果您在终端中使用 Expo CLI 运行以下命令，即可启动应用程序：

```jsx
 expo start
```

该命令将构建您的应用程序并在 Web 浏览器中打开 Expo 开发者工具。在 Expo 开发者工具中，选择在 iOS 模拟器上运行。

# 还有更多...

一旦您在模拟器中启动了应用程序，您就可以在不从 Xcode 中打开模拟器的情况下按下*在 iOS 模拟器上运行*按钮。它还应该记住您的设备选择。从 Xcode 中打开模拟器提供了一种简单的方式来选择您首选的 iOS 设备进行模拟。

如果您按照 Expo 指南中的步骤进行操作，可以在*安装 Android Studio*部分找到，您还会发现它涵盖了安装虚拟设备，我们可以将其作为模拟器运行。要在模拟器上启动您的应用程序，只需在 Android Studio 中打开您安装的 Android 虚拟设备，在终端中运行`expo start`命令，并选择在 Android 设备/模拟器上运行。

# 安装 Node.js

Node.js 是构建在 Chrome 的 V8 JavaScript 引擎上的 JavaScript 运行时，旨在构建可扩展的网络应用程序。Node 允许在终端中执行 JavaScript，并且是任何 Web 开发人员的必不可少的工具。有关 Node.js 的更多信息，您可以阅读项目的*关于 Node.js*页面，网址为[`nodejs.org/en/about/`](https://nodejs.org/en/about/)。

根据博览会安装文档，Node.js 在技术上并不是必需的，但一旦你开始实际构建东西，你会想要它。Node.js 本身不在本书的范围之内，但你可以在本章末尾的*进一步阅读*部分查看更多关于使用 Node.js 的资源。

有许多安装 Node.js 的方法，因此很难推荐特定的安装方法。在 macOS 上，你可以通过以下方式之一安装 Node.js：

+   从项目网站[`nodejs.org/en/download/`](https://nodejs.org/en/download)下载并安装 Node.js。

+   通过 Homebrew 进行安装。如果你熟悉 Homebrew，这个过程在[`medium.com/@katopz/how-to-install-specific-nodejs-version-c6e1cec8aa11`](https://medium.com/@katopz/how-to-install-specific-nodejs-version-c6e1cec8aa11)中有简洁的说明。

+   通过 Node Version Manager（NVM; [`github.com/creationix/nvm`](https://github.com/creationix/nvm)）进行安装。NVM 允许你安装多个版本的 Node.js，并轻松在它们之间切换。使用存储库的 README 中提供的说明来安装 NVM。这是推荐的方法，因为它灵活，只要你习惯在终端中工作。

# 安装 Expo

Expo 项目曾经有一个基于 GUI 的开发环境叫做 Expo XDE，现在已经被一个名为 Expo Developer Tools 的基于浏览器的 GUI 取代。由于 Expo XDE 已经被弃用，现在创建新的 Expo 应用程序总是使用 Expo CLI。这可以通过终端使用 npm（Node.js 的一部分）安装，使用以下命令：

```jsx
 npm install expo-cli -g
```

在本书中，我们将会大量使用 Expo 来创建和构建 React Native 应用程序，特别是那些不需要访问原生 iOS 或 Android 代码的应用程序。使用 Expo 构建的应用程序在开发中有一些非常好的优势，帮助混淆原生代码，简化应用程序发布和推送通知，并提供许多有用的功能内置到 Expo SDK 中。有关 Expo 如何工作以及它如何适应 React Native 开发的更多信息，请参见第十章*应用程序工作流程和第三方插件*。

# 安装 Watchman

Watchman 是 React Native 内部使用的工具。它的目的是监视文件更新，并在发生更改时触发响应（如实时重新加载）。Expo 文档建议安装 Watchman，因为有报道称一些 macOS 用户在没有它的情况下遇到了问题。安装 Watchman 的推荐方法是通过 Homebrew。作为 macOS 的缺失软件包管理器，Homebrew 允许您直接从终端安装各种有用的程序。这是一个不可或缺的工具，应该在每个开发者的工具包中。

1.  如果您还没有安装 Homebrew，请在终端中运行以下命令进行安装（您可以在[`brew.sh/`](https://brew.sh/)了解更多信息并查看官方文档）：

```jsx
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  安装 Homebrew 后，在终端中运行以下两个命令来安装`watchman`：

```jsx
brew update
brew install watchman
```

# 初始化您的第一个应用程序

这是你开始使用 Expo 开发第一个 React Native 应用所需的所有设置！但是，对于使用纯 React Native 应用（非 Expo 应用）需要执行一些额外的步骤。纯 React Native 应用的开发将在第十章 *应用工作流程和第三方插件*中进行深入讨论。由于这个设置过程有点复杂并且可能会发生变化，我建议参考官方指南。您可以在 React Native | 入门指南中找到这些说明

[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html) 在使用本机代码构建项目选项卡下。从现在开始，我们可以使用 Expo 提供的魔法轻松创建新的开发应用。

我们将使用 Expo 通过 Expo CLI 创建我们的第一个应用程序。创建一个新应用程序就像运行以下命令一样简单：

```jsx
expo init project-name
```

运行此命令将首先提示您要创建哪种类型的应用程序：`blank`应用程序，没有添加功能，或者`tabs`应用程序，将创建一个具有最小标签导航的新应用程序。在本书的示例中，我们将使用`blank`应用程序选项。

选择了首选的应用程序类型后，在新的`project-name`目录中创建了一个新的、空的 Expo-powered React Native 应用，以及开始开发所需的所有依赖项。你只需要开始编辑新项目目录中的`App.js`文件就可以开始工作了。

要运行我们的新应用程序，我们可以`cd`进入目录，然后使用`expo start`命令。这将自动构建和提供应用程序，并在新的浏览器窗口中打开 Expo 开发者工具，用于开发中的 React Native 应用程序。

有关 Expo CLI 的所有可用命令列表，请查看[`docs.expo.io/versions/latest/guides/expo-cli.html`](https://docs.expo.io/versions/latest/guides/expo-cli.html)上的文档。

创建了我们的第一个应用程序后，让我们继续在 iOS 模拟器和/或 Android 模拟器中运行该应用程序。

# 在模拟器/模拟器中运行您的应用程序

您已经创建了一个新项目，并在上一步中使用 Expo 开始运行该项目。一旦我们开始对 React Native 代码进行更改，能够看到这些更改的结果将是件好事，对吧？由于 Expo，运行已安装的 iOS 模拟器或 Android 模拟器中的项目也变得更加简单。

# 在 iOS 模拟器上运行您的应用程序

在 Xcode 模拟器中运行您的应用程序只需点击几下。

1.  打开 Xcode。

1.  从菜单栏中打开模拟器：Xcode | 打开开发者工具 | 模拟器：

**![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/f777110d-c8e4-438f-833d-330d03c6e695.png)**

1.  如果您运行以下命令，应用程序可以在终端中使用 Expo CLI 启动：

```jsx
expo start
```

该命令将构建您的应用程序并在您的 Web 浏览器中打开 Expo 开发者工具。在 Expo 开发者工具中，选择在 iOS 模拟器上运行。

1.  第一次通过“在 iOS 模拟器上运行”在 iOS 模拟器上运行 React Native 应用程序时，Expo 应用程序将安装在模拟器上，并且您的应用程序将自动在 Expo 应用程序中打开。模拟的 iOS 将询问您是否要“在“Expo”中打开”？选择“打开”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/beedc679-8089-4313-89bd-183d734aa54d.png)

1.  加载后，您将看到 Expo 开发者菜单。您可以通过在键盘上按下*command*键 + D 来在此菜单和您的 React Native 应用程序之间切换：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/a8edd55d-7cc2-4483-bb52-63930f7c5c1e.png)

# 还有更多...

一旦您在模拟器中启动了应用程序，您将能够按下“在 iOS 模拟器上运行”按钮，而无需从 Xcode 中打开模拟器。它还应该记住您的设备选择。从 Xcode 中打开模拟器提供了一种简单的方式来选择您首选的 iOS 设备进行模拟。

您可以通过在键盘上按下*command*键 + *M*来在您的 React Native 应用程序和 Expo 开发者菜单之间切换，后者是一个列出了开发中有用功能的列表。Expo 开发者菜单应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7cdc2973-e449-46da-b0f8-db3fa04351e0.png)

# 在真实设备上运行您的应用程序

在真实设备上运行您的开发应用程序就像在模拟器上运行应用程序一样简单。通过原生 Expo 应用程序和 QR 码的巧妙组合，只需点击几下，就可以在真实设备上运行应用程序！

# 在 iPhone 或 Android 上运行您的应用程序

你可以通过三个简单的步骤在手机上运行正在开发中的应用程序：

1.  在 iPhone 上打开 App Store，或者在 Android 设备上打开 Google Play 商店。

1.  搜索并下载 Expo Client 应用程序。

1.  当您的应用程序在开发机器上运行时，您还应该在浏览器中打开 Expo 开发者工具。您应该在 Expo 开发者工具左侧菜单底部看到一个 QR 码。使用 iPhone 的原生相机应用程序，或 Android 上 Expo 客户端应用程序中的扫描 QR 码按钮，扫描 QR 码。这将在 Expo 客户端应用程序内打开您正在开发的应用程序。

您的 React Native 应用现在应该在您的真实设备上运行，并配备了实时重新加载！您还可以摇动设备，在 React Native 应用和 Expo 开发者菜单之间切换。

# 摘要

在本章中，我们已经介绍了开发 React Native 应用程序所需的所有步骤，包括初始化新项目，在计算机上模拟运行新项目以及在真实设备上运行开发应用程序。由于 Expo 的强大功能，现在比以往任何时候都更容易开始工作了。

现在您已经设置好了一切，是时候开始构建了！

# 进一步阅读

以下是涵盖类似主题的其他资源列表：

+   Expo 安装文档在[`docs.expo.io/versions/latest/introduction/installation.html`](https://docs.expo.io/versions/latest/introduction/installation.html)。

+   *Node.js Web Development* 在[`www.packtpub.com/mapt/book/web_development/9781785881503`](https://www.packtpub.com/mapt/book/web_development/9781785881503)

+   *介绍热重载 - React Native* 在[`facebook.github.io/react-native/blog/2016/03/24/introducing-hot-reloading.html`](https://facebook.github.io/react-native/blog/2016/03/24/introducing-hot-reloading.html)。这篇来自 React Native 团队的博客文章深入介绍了热重载的工作原理。

+   *使用 Expo 发布*在[`docs.expo.io/versions/latest/guides/publishing.html`](https://docs.expo.io/versions/latest/guides/publishing.html)。Expo 具有发布功能，允许您通过创建持久 URL 与其他开发人员共享正在开发中的 React Native 应用程序。

+   在[`snack.expo.io`](https://snack.expo.io)上体验 Expo Snack。类似于[codepen.io](http://codepen.io)或[jsfiddle.net](https://jsfiddle.net)，Snack 允许您在浏览器中实时编辑 React Native 应用程序！


# 第二章：创建一个简单的 React Native 应用程序

在本章中，我们将涵盖以下内容：

+   向元素添加样式

+   使用图像模拟视频播放器

+   创建一个切换按钮

+   显示项目列表

+   使用 flexbox 创建布局

+   设置和使用导航

React Native 是一个快速增长的库。在过去的几年里，它在开源社区中变得非常受欢迎。几乎每隔一周就会有一个新版本发布，改进性能，添加新组件，或者提供对设备上新 API 的访问。

在本章中，我们将学习库中最常见的组件。为了逐步完成本章中的所有配方，我们将不得不创建一个新的应用程序，所以确保您的环境已经准备就绪。

# 向元素添加样式

我们有几个组件可供使用，但容器和文本是创建布局或其他组件最常见和有用的组件。在这个配方中，我们将看到如何使用容器和文本，但更重要的是我们将看到样式在 React Native 中是如何工作的。

# 准备工作

按照上一章的说明创建一个新应用程序。我们将把这个应用程序命名为`fake-music-player`。

在使用 Expo 创建新应用程序时，`App.js`文件中的`root`文件夹将添加少量样板代码。这将是您构建的任何 React Native 应用程序的起点。随时在每个配方的开头删除所有样板代码，因为所有代码（包括在`App.js`样板中使用的代码）都将被讨论。

# 如何做...

1.  在`App.js`文件中，我们将创建一个无状态组件。这个组件将模拟一个小型音乐播放器。它只会显示歌曲的名称和一个用来显示进度的条。第一步是导入我们的依赖项：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
```

1.  一旦我们导入了依赖项，我们就可以构建组件：

```jsx
export default class App extends React.Component {
  render() {
    const name = '01 - Blue Behind Green Bloches';

    return (
      <View style={styles.container}>
        <View style={styles.innerContainer} />
        <Text style={styles.title}>
          <Text style={styles.subtitle}>Playing:</Text> {name}
        </Text>
      </View>
    );
  }
}
```

1.  我们的组件已经准备好了，现在我们需要添加一些样式，以添加颜色和字体：

```jsx
const styles = StyleSheet.create({
  container: {
    margin: 10,
    marginTop: 100,
    backgroundColor: '#e67e22',
    borderRadius: 5,
  },
  innerContainer: {
    backgroundColor: '#d35400',
    height: 50,
    width: 150,
    borderTopLeftRadius: 5,
    borderBottomLeftRadius: 5,
  },
  title: {
    fontSize: 18,
    fontWeight: '200',
    color: '#fff',
    position: 'absolute',
    backgroundColor: 'transparent',
    top: 12,
    left: 10,
  },
  subtitle: {
    fontWeight: 'bold',
  },
});
```

1.  只要我们的模拟器和模拟器正在运行我们的应用程序，我们应该看到变化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/b811e149-433a-4eb0-89bf-57e9676bc390.png)

# 它是如何工作的...

在*步骤 1*中，我们包含了我们组件的依赖项。在这种情况下，我们使用了`View`，它是一个容器。如果您熟悉 Web 开发，`View`类似于`div`。我们可以在其他`View`内添加更多的`View`，`Text`，`List`，以及我们创建或从第三方库导入的任何其他自定义组件。

如果您熟悉 React，您会注意到，这是一个无状态组件，这意味着它没有任何状态；它是一个纯函数，不支持任何生命周期方法。

我们在组件中定义了一个`name`常量，但在实际应用中，这些数据应该来自 props。在返回中，我们定义了我们需要渲染组件的**JavaScript XML **（**JSX**），以及对样式的引用。

每个组件都有一个名为`style`的属性。该属性接收一个包含我们想要应用于给定组件的所有样式的对象。样式不会被子组件继承（除了`Text`组件），这意味着我们需要为每个组件设置单独的样式。

在*步骤 3*中，我们为我们的组件定义了样式。我们正在使用`StyleSheet` API 来创建所有样式。我们本可以使用包含样式的普通对象，但是通过使用`StyleSheet` API 而不是对象，我们可以获得一些性能优化，因为样式将被重用于每个渲染器，而不是在每次执行渲染方法时创建一个对象。

# 还有更多...

我想要引起您对*步骤 3*中`title`样式定义的注意。在这里，我们定义了一个名为`backgroundColor`的属性，并将`transparent`设置为其值。作为一个很好的练习，让我们注释掉这行代码并查看结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/92ede04a-de11-4f51-865a-d278c011698c.png)

在 iOS 上，文本将具有橙色背景颜色，这可能不是我们真正想要在我们的 UI 中发生的事情。为了解决这个问题，我们需要将文本的背景颜色设置为透明。但问题是，为什么会发生这种情况？原因是 React Native 通过将颜色从父元素的背景颜色设置为文本添加了一些优化。这将提高渲染性能，因为渲染引擎不必计算文本每个字母周围的像素，渲染将更快地执行。

在将背景颜色设置为`transparent`时要仔细考虑。如果组件将频繁更新内容，特别是如果文本太长，可能会出现一些性能问题。

# 使用图像模仿视频播放器

图像是任何 UI 的重要组成部分，无论我们是用它们来显示图标、头像还是图片。在这个食谱中，我们将使用图像来创建一个模拟视频播放器。我们还将显示来自本地设备的图标和来自远程服务器（由 Flickr 托管）的大图像。

# 准备工作

为了按照这个食谱中的步骤，让我们创建一个新的应用程序。我们将把它命名为`fake-video-player`。

我们将在我们的应用程序中显示一些图像，以模仿视频播放器，所以您需要为您的应用程序准备相应的图像。我建议使用我在 GitHub 上的食谱存储库中下载的图标，网址为[`github.com/warlyware/react-native-cookbook/tree/master/chapter-2/fake-video-player/images`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-2/fake-video-player/images)。

# 如何做...

1.  我们要做的第一件事是在项目的根目录下创建一个名为`Images`的新文件夹。将您下载的图像添加到新文件夹中。

1.  在`App.js`文件中，我们包括了这个组件所需的所有依赖项：

```jsx
import React from 'react'; 
import { StyleSheet, View, Image } from 'react-native';
```

1.  我们需要`require`在我们的组件中显示的图像。通过在常量中定义它们，我们可以在不同的地方使用相同的图像：

```jsx
const playIcon = require('./images/play.png');
const volumeIcon = require('./images/sound.png');
const hdIcon = require('./images/hd-sign.png');
const fullScreenIcon = require('./images/full-screen.png');
const flower = require('./images/flower.jpg');
const remoteImage = { uri: `https://farm5.staticflickr.com/4702/24825836327_bb2e0fc39b_b.jpg` };
```

1.  我们将使用一个无状态组件来渲染 JSX。我们将使用在上一步中声明的所有图像。

```jsx
export default class App extends React.Component {
  render() {
    return (
      <View style={styles.appContainer}>
        <ImageBackground source={remoteImage} style=
         {styles.videoContainer} resizeMode="contain">
          <View style={styles.controlsContainer}>
            <Image source={volumeIcon} style={styles.icon} />
            <View style={styles.progress}>
              <View style={styles.progressBar} />
            </View>
            <Image source={hdIcon} style={styles.icon} />
            <Image source={fullScreenIcon} style={styles.icon} />
          </View>
        </ImageBackground>
      </View>
    );
  }
};
```

1.  一旦我们有了要渲染的元素，我们需要为每个元素定义样式：

```jsx
const styles = StyleSheet.create({
  flower: {
    flex: 1,
  },
  appContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  videoContainer: {
    backgroundColor: '#000',
    flexDirection: 'row',
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  controlsContainer: {
    padding: 10,
    backgroundColor: '#202020',
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 175,
  },
  icon: {
    tintColor: '#fff',
    height: 16,
    width: 16,
    marginLeft: 5,
    marginRight: 5,
  },
  progress: {
    backgroundColor: '#000',
    borderRadius: 7,
    flex: 1,
    height: 14,
    margin: 4,
  },
  progressBar: {
    backgroundColor: '#bf161c',
    borderRadius: 5,
    height: 10,
    margin: 2,
    paddingTop: 3,
    width: 80,
    alignItems: 'center',
    flexDirection: 'row',
  },
});
```

1.  我们完成了！现在，当您查看应用程序时，您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/2570e533-9f2c-4a85-ae1d-6a02846bfa88.png)

# 它是如何工作的...

在*步骤 2*中，我们需要`Image`组件。这是负责从设备的本地文件系统或远程服务器上渲染图像的组件。

在*步骤 3*中，我们需要所有的图像。最好的做法是在组件外部需要图像，以便只需要一次。在每个渲染器上，React Native 将使用相同的图像。如果我们处理来自远程服务器的动态图像，那么我们需要在每个渲染器上需要它们。

`require`函数接受图像路径作为参数。路径是相对于我们类所在的文件夹的。对于远程图像，我们需要使用一个定义`uri`的对象来指定我们的文件在哪里。

在 *步骤 4* 中，声明了一个无状态组件。我们使用 `remoteImage` 作为我们应用程序的背景，通过一个 `ImageBackground` 元素，因为 `Image` 元素不能有子元素。这个元素类似于 CSS 中的 `background-url` 属性。

`Image` 的 `source` 属性接受一个对象来加载远程图像或所需文件的引用。非常重要的是要明确地要求我们想要使用的每个图像，因为当我们准备我们的应用程序进行分发时，图像将自动添加到捆绑包中。这就是我们应该避免做任何动态操作的原因，比如以下操作：

```jsx
const iconName = playing ? 'pause' : 'play'; 
const icon = require(iconName); 
```

上述代码不会将图像包含在最终的捆绑包中。因此，当尝试访问这些图像时，会出现错误。相反，我们应该将我们的代码重构为类似于这样的东西：

```jsx
const pause = require('pause'); 
const play = require('playing'); 
const icon = playing ? pause : play; 
```

这样，当准备我们的应用程序进行分发时，捆绑包将包括两个图像，并且我们可以在运行时动态决定显示哪个图像。

在 *步骤 5* 中，我们定义了样式。大多数属性都是不言自明的。尽管我们用于图标的图像是白色的，但我添加了 `tintColor` 属性来展示它如何用于着色图像。试一试！将 `tintColor` 改为 `#f00`，看看图标变成红色。

Flexbox 被用来对齐布局的不同部分。在 React Native 中，Flexbox 的行为基本上与 web 开发中的行为相同。我们将在本章后面的 *使用 flexbox 创建布局* 部分更多地讨论 flexbox，但是 flexbox 本身的复杂性超出了本书的范围。

# 创建一个切换按钮

按钮是每个应用程序中必不可少的 UI 组件。在这个部分中，我们将创建一个切换按钮，默认情况下将不被选中。当用户点击它时，我们将改变应用于按钮的样式，使其看起来被选中。

我们将学习如何检测点击事件，使用图像作为 UI，保持按钮的状态，并根据组件状态添加样式。

# 准备工作

让我们创建一个新的应用程序。我们将把它命名为 `toggle-button`。在这个部分中，我们将使用一张图片。您可以从 GitHub 上托管的相应存储库中下载这个部分的资产，网址为 [`github.com/warlyware/react-native-cookbook/tree/master/chapter-2/toggle-button/images`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-2/toggle-button/images)。

# 如何做...

1.  我们将在项目的根目录中创建一个名为`images`的新文件夹，并将心形图片添加到新文件夹中。

1.  让我们导入这个类的依赖项。

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  View,
  Image,
  Text,
  TouchableHighlight,
} from 'react-native';

const heartIcon = require('./images/heart.png');
```

1.  对于这个示例，我们需要跟踪按钮是否被按下。我们将使用一个带有`liked`布尔属性的`state`对象来实现这个目的。初始类应该是这样的：

```jsx
export default class App extends React.Component {
  state = {
    liked: false,
  };

  handleButtonPress = () => {
    // Defined in a later step
  }

  render() {
    // Defined in a later step
  }
}
```

1.  我们需要在`render`方法中定义我们新组件的内容。在这里，我们将定义`Image`按钮和其下方的`Text`元素：

```jsx
export default class App extends React.Component {
  state = {
    liked: false,
  };

  handleButtonPress = () => {
    // Defined in a later step
  }

  render() {
    return (
      <View style={styles.container}>
        <TouchableHighlight
          style={styles.button}
          underlayColor="#fefefe"
        >
          <Image
            source={heartIcon}
            style={styles.icon}
          />
        </TouchableHighlight>
        <Text style={styles.text}>Do you like this app?</Text>
      </View>
    );
  }
}
```

1.  让我们定义一些样式来设置尺寸、位置、边距、颜色等等：

```jsx
const styles = StyleSheet.create({
  container: {
    marginTop: 50,
    alignItems: 'center',
  },
  button: {
    borderRadius: 5,
    padding: 10,
  },
  icon: {
    width: 180,
    height: 180,
    tintColor: '#f1f1f1',
  },
  liked: {
    tintColor: '#e74c3c',
  },
  text: {
    marginTop: 20,
  },
});
```

1.  当我们在模拟器上运行项目时，我们应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/48d16278-db2d-4bd2-8c50-b6b59c3153f2.png)

1.  为了响应触摸事件，我们需要定义`handleButtonPress`函数的内容，并将其分配为`onPress`属性的回调函数：

```jsx
  handleButtonPress = () => {
    this.setState({
      liked: !this.state.liked,
    });
  }

  render() {
    return (
      <View style={styles.container}>
        <TouchableHighlight
          onPress={this.handleButtonPress}
          style={styles.button}
          underlayColor="#fefefe"
        >
          <Image
            source={heartIcon}
            style={styles.icon}
          />
        </TouchableHighlight>
        <Text style={styles.text}>Do you like this app?</Text>
      </View>
    );
  }
```

1.  如果我们测试我们的代码，我们不会看到 UI 上的任何变化，即使当我们按下按钮时组件上的状态发生变化。让我们在状态改变时为图片添加不同的颜色。这样，我们就能看到 UI 的响应：

```jsx
  render() {
 const likedStyles = this.state.liked ? styles.liked : undefined; 
    return (
      <View style={styles.container}>
        <TouchableHighlight
          onPress={this.handleButtonPress}
          style={styles.button}
          underlayColor="#fefefe"
        >
          <Image
            source={heartIcon}
 style={[styles.icon, likedStyles]}          />
        </TouchableHighlight>
        <Text style={styles.text}>Do you like this app?</Text>
      </View>
    );
  }
```

# 它是如何工作的...

在*步骤 2*中，我们导入了`TouchableHighlight`组件。这是负责处理触摸事件的组件。当用户触摸活动区域时，内容将根据我们设置的`underlayColor`值进行高亮显示。

在*步骤 3*中，我们定义了`Component`的状态。在这种情况下，状态只有一个属性，但我们可以根据需要添加多个属性。在第三章中，*实现复杂用户界面-第一部分*，我们将看到更多关于在更复杂场景中处理状态的示例。

在*步骤 6*中，我们使用`setState`方法来改变`liked`属性的值。这个方法是从我们正在扩展的`Component`类继承而来的。

在*步骤 7*中，基于`liked`属性的当前状态，我们使用样式将图片的颜色设置为红色，或者返回`undefined`以避免应用任何样式。当将样式分配给`Image`组件时，我们使用数组来分配多个对象。这非常方便，因为组件将所有样式合并为一个单一对象。具有最高索引的对象将覆盖数组中具有最低对象索引的属性：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7af91424-5d64-4f7d-aa3e-72a9c2e7b3e1.png)

# 还有更多...

在实际应用中，我们将使用多个按钮，有时带有左对齐的图标，标签，不同的大小，颜色等。强烈建议创建一个可重用的组件，以避免在整个应用程序中重复编写代码。在第三章，*实现复杂用户界面-第一部分*中，我们将创建一个按钮组件来处理其中一些情况。

# 显示项目列表

列表随处可见：用户历史记录中的订单列表，商店中可用商品的列表，要播放的歌曲列表。几乎任何应用程序都需要在列表中显示某种信息。

对于这个示例，我们将在`list`组件中显示多个项目。我们将定义一个带有一些数据的 JSON 文件，然后使用简单的`require`加载此文件，最后使用漂亮但简单的布局渲染每个项目。

# 准备工作

让我们从创建一个空应用程序开始。我们将把这个应用程序命名为`list-items`。我们需要一个图标来显示在每个项目上。获取图像的最简单方法是从托管在 GitHub 上的此示例的存储库中下载它们：[`github.com/warlyware/react-native-cookbook/tree/master/chapter-2/list-items/images`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-2/list-items/images)。

# 如何做...

1.  我们将首先创建一个`images`文件夹，并将`basket.png`添加到其中。还要在项目的根目录中创建一个名为`sales.json`的空文件。

1.  在`sales.json`文件中，我们将定义要在列表中显示的数据。以下是一些示例数据：

```jsx
[
  {
    "items": 5,
    "address": "140 Broadway, New York, NY 11101",
    "total": 38,
    "date": "May 15, 2016"
  }
]
```

1.  为了避免使本书的页面混乱，我只定义了一个记录，但请继续向数组中添加更多内容。多次复制和粘贴相同的对象将起作用。此外，您可以更改数据中的一些值，以便每个项目在 UI 中显示唯一的数据。

1.  在我们的`App.js`文件中，让我们导入我们需要的依赖项：

```jsx
import React, { Component } from 'react'; import {
  StyleSheet,
  View, 
  ListView, 
  Image, 
  Text,
} from 'react-native'; 
import data from './sales.json'; 

const basketIcon = require('./images/basket.png');
```

1.  现在，我们需要创建用于渲染项目列表的类。我们将在状态中保留销售数据；这样，我们可以轻松地插入或删除元素：

```jsx
export default class App extends React.Component {
  constructor(props) {
    super(props);
    const dataSource = new ListView.DataSource({
      rowHasChanged: (r1, r2) => r1 !== r2
    });

    this.state = {
      dataSource: dataSource.cloneWithRows(data),
    };
  }

  renderRow(record) {
    // Defined in a later step
  }

  render() {
    // Defined in a later step
  }
}
```

1.  在`render`方法中，我们需要定义`ListView`组件，并使用`renderRow`方法来渲染每个项目。`dataSource`属性定义了我们将在列表上渲染的元素数组：

```jsx
render() {
  return (
    <View style={styles.mainContainer}>
      <Text style={styles.title}>Sales</Text>
      <ListView dataSource={this.state.dataSource} renderRow={this.renderRow} />
    </View>
  );
}
```

1.  现在，我们可以定义`renderRow`的内容。这个方法接收包含我们需要的所有信息的每个对象。我们将在三列中显示数据。在第一列中，我们将显示一个图标；在第二列中，我们将显示每个销售的物品数量和订单将发货的地址；第三列将显示日期和总计：

```jsx
    return ( 
      <View style={styles.row}> 
        <View style={styles.iconContainer}> 
          <Image source={basketIcon} style={styles.icon} /> 
        </View> 
        <View style={styles.info}> 
          <Text style={styles.items}>{record.items} Items</Text> 
          <Text style={styles.address}>{record.address}</Text> 
        </View> 
        <View style={styles.total}> 
          <Text style={styles.date}>{record.date}</Text> 
          <Text style={styles.price}>${record.total}</Text> 
        </View> 
      </View> 
    ); 
```

1.  一旦我们定义了 JSX，就该添加样式了。首先，我们将为主容器、标题和行容器定义颜色、边距、填充等样式。为了为每一行创建三列，我们需要使用`flexDirection: 'row'`属性。我们将在本章后面的*使用 flexbox 创建布局*中更多了解这个属性：

```jsx
const styles = StyleSheet.create({
  mainContainer: {
    flex: 1,
    backgroundColor: '#fff',
  },
  title: {
    backgroundColor: '#0f1b29',
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
    padding: 10,
    paddingTop: 40,
    textAlign: 'center',
  },
  row: {
    borderColor: '#f1f1f1',
    borderBottomWidth: 1,
    flexDirection: 'row',
    marginLeft: 10,
    marginRight: 10,
    paddingTop: 20,
    paddingBottom: 20,
  },
});
```

1.  如果我们刷新模拟器，应该看到类似于以下截图的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/0eb4c14f-0cae-4506-b78e-c90f26015e80.png)

1.  现在，在`StyleSheet`定义内部，让我们为图标添加样式。我们将添加一个黄色的圆作为背景，并将图标的颜色改为白色：

```jsx
  iconContainer: {
    alignItems: 'center',
    backgroundColor: '#feb401',
    borderColor: '#feaf12',
    borderRadius: 25,
    borderWidth: 1,
    justifyContent: 'center',
    height: 50,
    width: 50,
  },
  icon: {
    tintColor: '#fff',
    height: 22,
    width: 22,
  },
```

1.  在这个改变之后，我们将在每一行的左侧看到一个漂亮的图标，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/24055416-5280-4b11-b86c-16713a744c15.png)

1.  最后，我们将为文本添加样式。我们需要设置`color`、`size`、`fontWeight`、`padding`和其他一些属性：

```jsx
  info: { 
    flex: 1, 
    paddingLeft: 25, 
    paddingRight: 25, 
  }, 
  items: { 
    fontWeight: 'bold', 
    fontSize: 16, 
    marginBottom: 5, 
  }, 
  address: { 
    color: '#ccc', 
    fontSize: 14, 
  }, 
  total: { 
    width: 80, 
  }, 
  date: { 
    fontSize: 12, 
    marginBottom: 5, 
  }, 
  price: { 
    color: '#1cad61', 
    fontSize: 25, 
    fontWeight: 'bold', 
  }  
```

1.  最终结果应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/3d839666-d353-4e9e-ba3a-320e4fd5f698.png)

# 它是如何工作的...

在*步骤 5*中，我们创建了数据源并向状态添加了数据。`ListView.DataSource`类实现了`ListView`组件的性能数据处理。`rowHasChanged`属性是必需的，它应该是一个比较下一个元素的函数。在我们的情况下，如果变化与当前数据不同，表示为`(r1, r2) => r1 !== r2`，那么 React Native 将知道如何响应并重新渲染 UI。

在用数据填充数据源时，我们需要调用`cloneWithRows`方法并发送一个记录数组。

如果我们想添加更多数据，我们应该再次使用包含先前和新数据的数组调用`cloneWithRows`方法。数据源将确保计算差异并根据需要重新渲染列表。

在*步骤 7*中，我们定义了渲染列表的 JSX。列表只需要两个属性：我们已经从*步骤 6*中得到的数据源和`renderRow`。

`renderRow`属性接受一个函数作为值。这个函数需要返回每一行的 JSX。

# 还有更多...

我们使用 flexbox 创建了一个简单的布局；但是，在本章中还有另一个教程，我们将更详细地介绍如何使用 flexbox。

一旦我们有了我们的列表，很有可能我们需要查看每个订单的详细信息。您可以使用`TouchableHighlight`组件作为每行的主容器，所以继续尝试一下。如果您不确定如何使用`TouchableHighlight`组件，请参阅本章早期的*创建切换按钮*教程。

# 使用 flexbox 创建布局

在这个教程中，我们将学习有关 flexbox 的知识。在本章的先前教程中，我们一直在使用 flexbox 来创建布局，但在这个教程中，我们将专注于我们可以使用的属性，通过重新创建 App Store 上名为*Nominazer*的随机名称生成应用程序的布局（[`itunes.apple.com/us/app/nominazer/id765422087?mt=8`](https://itunes.apple.com/us/app/nominazer/id765422087?mt=8)）。

在 React Native 中使用 flexbox 基本上与在 CSS 中使用 flexbox 相同。这意味着如果您习惯于使用 flexbox 布局开发网站，那么您已经知道如何在 React Native 中创建布局！这个练习将涵盖在 React Native 中使用 flexbox 的基础知识，但是要查看您可以使用的所有布局属性的列表，请参考布局属性的文档（[`facebook.github.io/react-native/docs/layout-props.html`](https://facebook.github.io/react-native/docs/layout-props.html)）。

# 准备工作

让我们从创建一个新的空白应用程序开始。我们将其命名为`flexbox-layout`。

# 如何做...

1.  在`App.js`中，让我们导入我们应用程序所需的依赖项：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
```

1.  我们的应用程序只需要一个`render`方法，因为我们正在构建一个静态布局。渲染的布局包括一个容器`View`元素和应用程序每个彩色部分的三个子`View`元素。

```jsx
export default class App extends React.Component { 
 render() { 
  return ( 
    <View style={styles.container}> 
      <View style={styles.topSection}> </View> 
       <View style={styles.middleSection}></View> 
       <View style={styles.bottomSection}></View> 
    </View> ); 
  } 
 }
```

1.  接下来，我们可以开始添加我们的样式。我们将添加的第一个样式将应用于包裹整个应用程序的`View`元素。将`flex`属性设置为`1`将导致所有子元素填充所有空白空间：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
  }
});
```

1.  现在，我们可以为三个子`View`元素添加样式。每个部分都应用了`flexGrow`属性，这决定了每个元素应该占用多少可用空间。`topSection`和`bottomSection`都设置为`3`，所以它们将占用相同的空间。由于`middleSection`的`flexGrow`属性设置为`1`，这个元素将占用`topSection`和`bottomSection`占用空间的三分之一：

```jsx
  topSection: {
    flexGrow: 3,
    backgroundColor: '#5BC2C1',
  },
  middleSection: {
    flexGrow: 1,
    backgroundColor: '#FFF',
  },
  bottomSection: {
    flexGrow: 3,
    backgroundColor: '#FD909E',
  },
```

1.  如果我们在模拟器中打开我们的应用程序，我们应该已经能够看到基本布局正在形成：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/f05a61bb-3f96-4511-b497-9d169b08efe0.png)

1.  在这里，我们可以在*步骤 2*中创建的三个子`View`元素中的每一个添加一个`Text`元素。请注意，新增的代码已经被突出显示：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <View style={styles.topSection}>
 <Text style={styles.topSectionText}>
            4  N A M E S
          </Text>
        </View>
        <View style={styles.middleSection}>
 <Text style={styles.middleSectionText}>
 I P S U M
 </Text>
        </View>
        <View style={styles.bottomSection}>
 <Text style={styles.bottomSectionText}>
            C O M
          </Text>
        </View>
      </View>
    );
  }
```

1.  每个部分的文本默认显示在该部分的左上角。我们可以使用 flexbox 来使每个元素按照期望的位置进行对齐和排列。所有三个子`View`元素的`alignItems` flex 属性都设置为`'center'`，这将导致每个元素的子元素沿着*x*轴居中。`justifyContent`在中间和底部部分上使用，定义了子元素沿着*y*轴应该如何对齐：

```jsx
onst styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  topSection: {
    flexGrow: 3,
    backgroundColor: '#5BC2C1',
 alignItems: 'center',
  },
  middleSection: {
    flexGrow: 1,
    backgroundColor: '#FFF',
 justifyContent: 'center',
    alignItems: 'center',
  },
  bottomSection: {
    flexGrow: 3,
    backgroundColor: '#FD909E',
 alignItems: 'center',
    justifyContent: 'flex-end'
  }
});
```

1.  唯一剩下的就是为`Text`元素添加基本样式，增加`fontSize`、`fontWeight`和所需的`margin`：

```jsx
  topSectionText: {
    fontWeight: 'bold',
    marginTop: 50
  },
  middleSectionText: {
    fontSize: 30,
    fontWeight: 'bold'
  },
  bottomSectionText: {
    fontWeight: 'bold',
    marginBottom: 30
  }
```

1.  如果我们在模拟器中打开我们的应用程序，我们应该能够看到我们完成的布局：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/9ce98ba3-6356-4317-bd43-74a4596c41c6.png)

# 工作原理...

我们的应用程序看起来非常不错，而且通过使用 flexbox 很容易实现。我们通过将`flexGrow`属性分别设置为`3`、`1`和`3`来创建了三个不同的部分，这使得顶部和底部部分的垂直大小相等，而中间部分是顶部和底部部分的三分之一。

在使用 flexbox 时，我们有两个方向来布置子内容，`row`和`column`：

+   `row`：这允许我们水平排列容器的子元素。

+   `column`：这允许我们垂直排列容器的子元素。这是 React Native 中的默认方向。

当我们像对容器`View`元素所做的那样设置`flex: 1`时，我们告诉该元素占用所有可用空间。如果我们移除`flex: 1`或将`flex`设置为`0`，我们会看到布局在自身内部收缩，因为容器不再在所有空白空间中伸展：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c28d05ad-a247-4f43-9a90-77d41db556a0.png)

Flexbox 也非常适合支持不同的屏幕分辨率。即使不同设备可能有不同的分辨率，我们可以确保一致的布局，使其在任何设备上都看起来很好。

# 还有更多...

React Native 中的 flexbox 工作方式与 CSS 中的工作方式有一些不同。首先，在 CSS 中，默认的`flexDirection`属性是`row`，而在 React Native 中，默认的`flexDirection`属性是`column`。

`flex`属性在 React Native 中的行为也有些不同。与将`flex`设置为字符串值不同，它可以设置为正整数、`0`或`-1`。正如官方的 React Native 文档所述：

当 flex 为正数时，它使组件具有灵活性，并且其大小将与其 flex 值成比例。因此，将 flex 设置为 2 的组件将占据比将 flex 设置为 1 的组件多一倍的空间。当 flex 为 0 时，组件的大小根据宽度和高度确定，是不灵活的。当 flex 为-1 时，组件通常根据宽度和高度确定大小。但是，如果空间不足，组件将收缩到其最小宽度和最小高度。

关于 flexbox 还有很多要讨论的，但目前我们已经有所了解。在第三章 *实现复杂用户界面-第一部分*中，我们将学习更多关于布局的知识。我们将学习更多关于布局，并创建一个使用更多可用布局属性的复杂布局。

# 另请参阅

+   React Native 布局属性文档([`facebook.github.io/react-native/docs/layout-props.html`](https://facebook.github.io/react-native/docs/layout-props.html))

+   React Native 文本样式属性文档([`facebook.github.io/react-native/docs/text-style-props.html`](https://facebook.github.io/react-native/docs/text-style-props.html))

+   Yoga ([`github.com/facebook/yoga`](https://github.com/facebook/yoga))——React Native 使用的 Facebook 的 Flexbox 实现。

+   一篇优秀的 Stack Overflow 帖子介绍了 React Native 弹性属性的工作原理和示例-[`stackoverflow.com/questions/43143258/flex-vs-flexgrow-vs-flexshrink-vs-flexbasis-in-react-native`](https://stackoverflow.com/questions/43143258/flex-vs-flexgrow-vs-flexshrink-vs-flexbasis-in-react-native)

# 设置和使用导航

对于任何具有多个视图的应用程序，导航系统至关重要。导航在应用程序开发中是如此普遍，以至于 Expo 在创建新应用程序时提供了两个模板：**空白**或**标签导航**。这个教程是基于 Expo 提供的非常简化的标签导航应用程序模板。我们仍将从一个空白应用程序开始，并从头开始构建我们的基本标签导航应用程序，以更好地理解所有必需的部分。完成此教程后，我鼓励您使用标签导航模板开始一个新应用程序，以查看我们将在后面章节中涵盖的一些更高级的功能，包括推送通知和堆栈导航。

# 准备工作

让我们继续创建一个名为`simple-navigation`的新空白应用程序。我们还需要一个第三方包来处理我们的导航。我们将使用`react-navigation`包的 1.5.9 版本。使用此包的更新版本将无法正确使用此代码，因为该包的 API 最近经历了重大变化。在终端中，转到新项目的根目录，并使用以下命令安装此包：

```jsx
yarn add react-navigation@1.5.9
```

这就是我们需要的所有设置。让我们开始构建吧！

# 如何做到...

1.  在`App.js`文件中，让我们导入我们的依赖项：

```jsx
import  React  from  'react'; import { StyleSheet, View } from  'react-native';
```

1.  这个应用程序的`App`组件将非常简单。我们只需要一个带有渲染我们应用程序容器的`App`类和一个`render`函数。我们还将添加填充窗口和添加白色背景的样式：

```jsx
export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
      </View>
   );
 }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  }
});
```

1.  `App.js`的下一步是导入并使用`MainTabNavigator`组件，这是我们将在*步骤 4*中创建的新组件：

```jsx
React.Component {
  render() {
    return (
      <View style={styles.container}>
        <MainTabNavigator />
      </View>
    );
  }
}
```

1.  我们需要为我们的`MainTabNavigator`组件创建一个新文件。让我们在项目的根目录中创建一个名为`navigation`的新文件夹。在这个新文件夹中，我们将为我们的导航组件创建`MainTabNavigator.js`。

1.  在`MainTabNavigator.js`中，我们可以导入我们需要的所有导航依赖项。这些依赖项包括三个屏幕（`HomeScreen`、`LinksScreen`和`SettingsScreen`）。我们将在后面的步骤中添加这些屏幕：

```jsx
import React from 'react';
import { Ionicons } from '@expo/vector-icons';
import { TabNavigator, TabBarBottom } from 'react-navigation';

import HomeScreen from '../screens/HomeScreen';
import LinksScreen from '../screens/LinksScreen';
import SettingsScreen from '../screens/SettingsScreen';
```

1.  我们的导航组件将使用`react-navigation`提供的`TabNavigator`方法来定义应用程序的路由和导航。`TabNavigator`接受两个参数：一个`RouteConfig`对象来定义每个路由，以及一个`TabNavigatorConfig`对象来定义我们的`TabNavigator`组件的选项：

```jsx
export default TabNavigator({
    // RouteConfig, defined in step 7.
}, {
    // TabNavigatorConfig, defined in steps 8 and 9.
});
```

1.  首先，我们将定义`RouteConfig`对象，它将为我们的应用程序创建一个路由映射。`RouteConfig`对象中的每个键都作为路由的名称。我们为每个路由的屏幕属性设置为我们希望在该路由上显示的相应屏幕组件：

```jsx
export default TabNavigator({
 Home: {
    screen: HomeScreen,
  },
  Links: {
    screen: LinksScreen,
  },
  Settings: {
    screen: SettingsScreen,
  },
}, {
  // TabNavigatorConfig, defined in steps 8 and 9\. 
});
```

1.  `TabNavigatorConfig`还有一些内容。我们将通过将`react-navigation`提供的`TabBarBottom`组件传递给`tabBarComponent`属性来声明我们想要使用什么样的选项卡栏（在本例中，是设计用于屏幕底部的选项卡栏）。`tabBarPosition`定义了栏是在屏幕顶部还是底部。`animationEnabled`指定了过渡是否是动画的，`swipeEnabled`声明了视图是否可以通过滑动来改变：

```jsx
export default TabNavigator({
    // Route Config, defined in step 7\. 
}, {
  navigationOptions: ({ navigation }) => ({
    // navigationOptions, defined in step 9.
  }),
  tabBarComponent: TabBarBottom,
  tabBarPosition: 'bottom',
  animationEnabled: false,
  swipeEnabled: false,
});
```

1.  在`TabNavigatorConfig`对象的`navigationOptions`属性中，我们将通过声明一个函数来为每个路由定义动态的`navigationOptions`，该函数接受当前路由/屏幕的导航 prop。我们可以使用此函数来决定选项卡栏如何针对每个路由/屏幕进行操作，因为它被设计为返回一个为适当屏幕设置`navigationOptions`的对象。我们将使用此模式来定义每个路由的`tabBarIcon`属性的外观：

```jsx
  navigationOptions: ({ navigation }) => ({
    tabBarIcon: ({ focused }) => {
      // Defined in step 10
    },
  }),
```

1.  `tabBarIcon`属性设置为一个函数，其参数是当前路由的 props。我们将使用`focused`属性来决定是渲染有颜色的图标还是轮廓图标，这取决于当前路由。我们通过`navigation.state`从导航 prop 中获取`routeName`，为我们的三条路线定义图标，并返回适当路线的渲染图标。我们将使用 Expo 提供的`Ionicons`组件来创建每个图标，并根据图标的路线是否`focused`来定义图标的颜色：

```jsx
  navigationOptions: ({ navigation }) => ({
    tabBarIcon: ({ focused }) => {
 const { routeName } = navigation.state;

      let iconName;
      switch (routeName) {
        case 'Home':
          iconName = `ios-information-circle`;
          break;
        case 'Links':
          iconName = `ios-link`;
          break;
        case 'Settings':
          iconName = `ios-options`;
      }
      return (
        <Ionicons name={iconName}
          size={28} style={{marginBottom: -3}}
          color={focused ? Colors.tabIconSelected :
          Colors.tabIconDefault}
        />
      );
    },
  }),
```

1.  设置`MainTabNavigator`的最后一步是创建用于给每个图标上色的`Colors`常量：

```jsx
const Colors = {
  tabIconDefault: '#ccc',
  tabIconSelected: '#2f95dc',
}
```

1.  我们的路由现在已经完成！现在剩下的就是为我们导入和定义在`MainTabNavigator.js`中的三个路由创建三个屏幕组件。为简单起见，这三个屏幕将具有相同的代码，除了背景颜色和标识文本不同。

1.  在项目的根目录中，我们需要创建一个`screens`文件夹来存放我们的三个屏幕。在新文件夹中，我们需要创建`HomeScreen.js`、`LinksScreen.js`和`SettingsScreen.js`。

1.  让我们从打开新创建的`HomeScreen.js`并添加必要的依赖项开始：

```jsx
import React from 'react';
import {
  StyleSheet,
  Text,
  View,
} from 'react-native';
```

1.  `HomeScreen`组件本身非常简单，只是一个全彩色页面，屏幕中间有一个`Home`字样，显示我们当前所在的屏幕：

```jsx
export default class HomeScreen extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.headline}>
          Home
        </Text>
      </View>
    );
  }
}
```

1.  我们还需要为我们的`Home`屏幕布局添加样式：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#608FA0',
  },
  headline: {
    fontWeight: 'bold',
    fontSize: 30,
    color: 'white',
  }
});
```

1.  现在剩下的就是重复*步骤 14*、*步骤 15*和*步骤 16*，为剩下的两个屏幕做一些微小的更改。`LinksScreen.js`应该看起来像`HomeScreen.js`，并更新以下突出显示的部分：

```jsx
import React from 'react';
import {
  StyleSheet,
  Text,
  View,
} from 'react-native';

export default class LinksScreen extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.headline}>
 Links
        </Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
 backgroundColor: '#F8759D',  },
  headline: {
    fontWeight: 'bold',
    fontSize: 30,
    color: 'white',
  }
});
```

1.  同样，在`SettingsScreen.js`内部，我们可以使用与前两个屏幕相同的结构创建第三个屏幕组件：

```jsx
import React from 'react';
import {
  StyleSheet,
  Text,
  View,
} from 'react-native';

export default class SettingsScreen extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.headline}>
          Settings
        </Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
 backgroundColor: '#F0642E',
  },
  headline: {
    fontWeight: 'bold',
    fontSize: 30,
    color: 'white',
  }
});
```

1.  我们的应用程序已经完成！当我们在模拟器中查看我们的应用程序时，屏幕底部应该有一个选项卡栏，可以在三个路由之间切换：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/10300526-2ca1-44b3-a4d7-8c8e94c3bf5a.png)

# 它是如何工作的...

在这个教程中，我们介绍了原生应用中最常见和基本的导航模式之一，即选项卡栏。React Navigation 库是一个非常强大、功能丰富的导航解决方案，很可能能够为您的应用程序提供任何所需的导航。我们将在第三章中介绍更多关于 React Navigation 的用法，*实现复杂的用户

接口 - 第一部分。*

# 另请参阅

+   React Navigation 官方文档（[`reactnavigation.org/`](https://reactnavigation.org/)）

+   Expo 的路由和导航指南（[`docs.expo.io/versions/latest/guides/routing-and-navigation.html`](https://docs.expo.io/versions/latest/guides/routing-and-navigation.html)）


# 第三章：实现复杂的用户界面-第一部分

在本章中，我们将实现复杂的用户界面。我们将学习如何使用 flexbox 创建适用于不同屏幕尺寸的组件，如何检测方向变化等。

本章将涵盖以下教程：

+   创建具有主题支持的可重用按钮

+   使用 flexbox 为平板电脑构建复杂的布局

+   包括自定义字体

+   使用字体图标

# 创建具有主题支持的可重用按钮

在开发软件时，可重用性非常重要。我们应该避免一遍又一遍地重复相同的事情，而是应该创建可以尽可能多次重用的小组件。

在本教程中，我们将创建一个`Button`组件，并且我们还将定义几个属性来改变其外观和感觉。在学习本教程的过程中，我们将学习如何动态地将不同的样式应用到组件上。

# 准备工作

我们需要创建一个空的应用程序。让我们将其命名为`reusable-button`。

# 如何做...

1.  在我们新应用程序的根目录中，我们需要为可重用的按钮相关代码创建一个新的`Button`文件夹。让我们还在新的`Button`文件夹中创建`index.js`和`styles.js`。

1.  我们将从导入新组件的依赖项开始。在`Button/index.js`文件中，我们将创建一个`Button`组件。这意味着我们需要导入`Text`和`TouchableOpacity`组件。您会注意到我们还在导入尚不存在的样式。我们将在本教程的后续部分中定义这些样式。在`Button/index.js`文件中，我们应该有以下导入：

```jsx
import React, { Component } from 'react';

import {
  Text,
  TouchableOpacity,
} from 'react-native';

import {
  Base,
  Default,
  Danger,
  Info,
  Success
} from './styles';
```

1.  现在我们已经导入了依赖项，让我们为这个组件定义类。我们将需要一些属性和两种方法。还需要导出此组件，以便我们可以在其他地方使用它：

```jsx
export default class Button extends Component {
  getTheme() {
    // Defined in a later step
  }

  render() {
    // Defined in a later step
  }
}
```

1.  我们需要根据给定的`属性`选择要应用于我们组件的样式。为此，我们将定义`getTheme`方法。该方法将检查任何`属性`是否为`true`，并返回相应的样式。如果没有一个是`true`，它将返回`Default`样式：

```jsx
  getTheme() {
    const { danger, info, success } = this.properties;

    if (info) {
      return Info;
    }

    if (success) {
      return Success;
    }

    if (danger) {
      return Danger;
    }

    return Default;
  }
```

1.  所有组件都需要一个`render`方法。在这里，我们需要返回此组件的 JSX 元素。在这种情况下，我们将获取给定`属性`的样式，并将其应用于`TouchableOpacity`组件。

我们还为按钮定义了一个标签。在这个标签内，我们将渲染`children`属性。如果接收到回调函数，那么当用户按下这个组件时它将被执行：

```jsx
  render() {
    const theme = this.getTheme();
    const {
      children,
      onPress,
      style,
      rounded,
    } = this.properties;

    return (
      <TouchableOpacity
        activeOpacity={0.8}
        style={[
          Base.main,
          theme.main,
          rounded ? Base.rounded : null ,
          style,
        ]}
        onPress={onPress}
      >
        <Text style={[Base.label, theme.label]}>{children}</Text>
      </TouchableOpacity>
    );
  }
```

1.  我们的`Button`组件几乎完成了。我们仍然需要定义我们的样式，但首先让我们转到项目根目录下的`App.js`文件。我们需要导入依赖项，包括我们创建的`Button`组件。

当用户点击按钮时，我们将显示警报消息，因此我们还需要导入`Alert`组件：

```jsx
import React from 'react';
import {
  Alert,
  StyleSheet,
  View
} from 'react-native';
import Button from './Button';
```

1.  一旦我们有了所有的依赖项，让我们定义一个无状态组件，渲染几个按钮。第一个按钮将使用默认样式，第二个按钮将使用成功样式，这将为按钮的背景添加一个漂亮的绿色。最后一个按钮将在按下时显示一个警报。为此，我们需要定义使用`Alert`组件的回调函数，只需设置标题和消息：

```jsx
export default class App extends React.Component {
  handleButtonPress() {
    Alert.alert('Alert', 'You clicked this button!');
  }

  render() {
    return(
      <View style={styles.container}>
        <Button style={styles.button}>
          My first button
        </Button>
        <Button success style={styles.button}>
          Success button
        </Button>
        <Button info style={styles.button}>
          Info button
        </Button>
        <Button danger rounded style={styles.button}
        onPress={this.handleButtonPress}>
          Rounded button
        </Button>
      </View>
    );
  }
}
```

1.  我们将为主要布局的对齐和每个按钮的对齐方式添加一些样式，以及一些边距：

```jsx
const styles = StyleSheet.create({
  container: {
      flex: 1,
      alignItems: 'center',
      justifyContent: 'center',
    },
  button: {
    margin: 10,
  },
});
```

1.  如果我们现在尝试运行应用程序，将会出现一些错误。这是因为我们还没有为按钮声明样式。让我们现在来解决这个问题。在`Button/styles.js`文件中，我们需要定义基本样式。这些样式将应用于按钮的每个实例。在这里，我们将定义半径、填充、字体颜色和我们需要的所有常见样式：

```jsx
import { StyleSheet } from 'react-native';

const Base = StyleSheet.create({
  main: {
    padding: 10,
    borderRadius: 3,
  },
  label: {
    color: '#fff',
  },
  rounded: {
    borderRadius: 20,
  },
});
```

1.  一旦我们有了按钮的常见样式，我们需要为`Danger`、`Info`、`Success`和`Default`主题定义样式。为此，我们将为每个主题定义不同的对象。在每个主题内，我们将使用相同的对象，但具有该主题的特定样式。

为了保持简单，我们只会改变`backgroundColor`，但我们可以使用尽可能多的样式属性：

```jsx
const Danger = StyleSheet.create({
  main: {
    backgroundColor: '#e74c3c',
  },
});

const Info = StyleSheet.create({
  main: {
    backgroundColor: '#3498db',
  },
});

const Success = StyleSheet.create({
  main: {
    backgroundColor: '#1abc9c',
  },
});

const Default = StyleSheet.create({
  main: {
    backgroundColor: 'rgba(0 ,0 ,0, 0)',
  },
  label: {
    color: '#333',
  },
});
```

1.  最后，让我们导出样式。这一步是必要的，这样`Button`组件就可以导入每个主题的所有样式：

```jsx
export {
  Base,
  Danger,
  Info,
  Success,
  Default,
};
```

1.  如果我们打开应用程序，我们应该能够看到我们完成的布局：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/fb784d29-16db-4a64-a1c9-bba06dcfaf0a.png)

# 工作原理...

在这个例子中，我们使用了`TouchableOpacity`组件。这个组件允许我们定义一个漂亮的动画，当用户按下按钮时改变不透明度。

我们可以使用`activeOpacity`属性来设置按钮被按下时的不透明度值。该值可以是`0`到`1`之间的任何数字，其中`0`是完全透明的。

如果我们按下圆形按钮，我们将看到一个原生的警报消息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/4b6b4ca1-7313-4570-9e82-17758d2b4711.png)

# 使用 flexbox 为平板电脑构建复杂布局

当涉及到创建响应式布局时，flexbox 真的非常方便。React Native 使用 flexbox 作为布局系统，如果你已经熟悉这些概念，那么对于你来说开始创建任何类型的布局将会非常容易。

如前一章所述，在 React Native 中，flexbox 的工作方式与 CSS 中的工作方式有一些不同。有关 React Native 和 CSS flexbox 之间的区别的更多信息，请参阅第二章中*如何工作...*部分的*使用 flexbox 创建布局*教程。

在这个教程中，我们将创建一个布局来显示博客文章列表。每篇文章都将是一个带有图片、摘录和阅读更多按钮的小卡片。我们将使用 flexbox 根据屏幕大小在主容器上排列这些文章。这将允许我们通过正确对齐横向和纵向的卡片来处理屏幕旋转。

# 准备工作

我们需要一个新的应用程序来完成这个教程。让我们把它命名为`tablet-flexbox`。

当我们使用 Expo 创建一个新应用程序时，项目的基础部分会创建一个`app.json`，其中提供了一些基本配置。在这个教程中，我们正在构建一个应用程序，我们希望它在平板电脑上看起来很好，特别是在横向模式下。当我们打开`app.json`时，我们应该看到一个`orientation`属性设置为`'portrait'`。该属性确定应用程序内允许哪些方向。`orientation`属性接受`'portrait'`（锁定应用程序为纵向模式）、`'landscape'`（锁定应用程序为横向模式）和`'default'`（允许应用程序根据设备的方向调整屏幕方向）。对于我们的应用程序，我们将把`orientation`设置为`'landscape'`，这样我们就可以支持横向和纵向布局。

我们还将使用一些图片，这些图片需要远程托管，以便为该示例正确模拟加载远程数据并使用`Image`组件显示图片。我已经将这些图片上传到[www.imgur.com](http://www.imgur.com)图像托管服务，并在`data.json`文件中引用了这些远程图片，该文件是该示例用于其可消耗数据的。如果由于任何原因这些远程图片对您来说加载不正常，它们也包含在该示例的存储库中的`/assets`文件夹中。请随意将它们上传到任何服务器或托管服务，并相应地更新`data.json`中的图片 URL。该存储库可以在 GitHub 上找到，网址为[`github.com/warlyware/react-native-cookbook/tree/master/chapter-3/tablet-flexbox`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-3/tablet-flexbox)。

# 如何做...

1.  首先，我们需要在项目的根目录中创建一个`Post`文件夹。我们还需要在新的`Post`文件夹中创建一个`index.js`和一个`styles.js`文件。我们将使用这个`Post`组件来为我们的应用程序显示每个帖子。最后，我们需要在项目的根目录中添加一个`data.json`文件，我们将使用它来定义一个帖子列表。

1.  现在我们可以继续构建`App.js`组件。首先，我们需要导入这个类的依赖项。我们将使用`ListView`组件来渲染帖子列表。我们还需要`Text`和`View`组件作为内容容器。我们将创建一个自定义的`Post`组件来渲染列表中的每个帖子，并且我们还需要导入`data.json`文件：

```jsx
import React, { Component } from 'react';
import { ListView, StyleSheet, Text, View } from 'react-native';

import Post from './Post';
import data from './data.json';
```

1.  让我们为`App`组件创建类。在这里，我们将使用`.json`文件中的数据来创建列表的`dataSource`。我们将在下一步向我们的`data.json`文件中添加一些实际数据。在`render`方法中，我们将定义一个简单的顶部工具栏和`List`组件。我们将使用`Post`组件来处理每条记录，并从`state`中获取`dataSource`。

如果您对`ListView`组件有任何疑问，您应该查看第二章中的示例，*创建一个简单的 React Native 应用程序*，在那里我们创建了一个订单列表：

```jsx
const dataSource = new ListView.DataSource({
  rowHasChanged: (r1, r2) => r1 !== r2,
});

export default class App extends Component {
  state = {
    dataSource: dataSouce.cloneWithRows(data.posts),
  };

  render() {
    return (
      <View style={styles.container}>
        <View style={styles.toolbar}>
          <Text style={styles.title}>Latest posts</Text>
        </View>
        <ListView
          dataSource={this.state.dataSource}
          renderRow={post => <Post {...post} />}
          style={styles.list}
          contentContainerStyle={styles.content}
        />
      </View>
    );
  }
}
```

1.  还缺少两个文件：包含数据的`.json`文件和`Post`组件。在这一步中，我们将创建我们将用于每个帖子的数据。为了简化事情，在以下代码片段中只有一条数据记录，但我在这个示例中使用的其余`POST`对象可以在本示例的代码存储库中的`data.json`文件中找到，位于[`github.com/warlyware/react-native-cookbook/blob/master/chapter-3/tablet-flexbox/data.json`](https://github.com/warlyware/react-native-cookbook/blob/master/chapter-3/tablet-flexbox/data.json)：

```jsx
{
  "posts": [
    {
      "title": "The Best Article Ever Written",
      "img": "https://i.imgur.com/mf9daCT.jpg",
      "content": "Lorem ipsum dolor sit amet...",
      "author": "Bob Labla"
    },
    // Add more records here.
  ]
}
```

1.  现在我们有了一些数据，我们准备开始处理`Post`组件。在这个组件中，我们需要显示图片、标题和按钮。由于这个组件不需要知道状态，我们将使用一个无状态组件。以下代码使用了我们在第二章中学到的所有组件，*创建一个简单的 React Native 应用*。如果有什么不清楚的地方，请再次查看那一章。这个组件将接收数据作为参数，然后我们将用它来显示组件中的内容。`Image`组件将使用`data.json`文件中每个对象上定义的`img`属性来显示远程图片。

```jsx
import React from 'react';
import {
  Image,
  Text,
  TouchableOpacity,
  View
} from 'react-native';

import styles from './styles';

const Post = ({ content, img, title }) => (
  <View style={styles.main}>
    <Image
      source={{ uri: img }}
      style={styles.image}
    />
    <View style={styles.content}>
      <Text style={styles.title}>{title}</Text>
      <Text>{content}</Text>
    </View>
    <TouchableOpacity style={styles.button} activeOpacity={0.8}>
      <Text style={styles.buttonText}>Read more</Text>
    </TouchableOpacity>
  </View>
);

export default Post;
```

1.  一旦我们定义了组件，我们还需要为每个帖子定义样式。让我们创建一个空的`StyleSheet`导出，以便依赖于`styles.js`的`Post`组件能够正常运行。

```jsx
import { StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  // Defined in later steps
});

export default styles;
```

1.  如果我们尝试运行应用程序，我们应该能够在屏幕上看到来自`.json`文件的数据。不过，它不会很漂亮，因为我们还没有应用任何样式。

1.  我们在屏幕上已经有了所需的一切。现在我们准备开始布局工作。首先，让我们为我们的`Post`容器添加样式。我们将设置`width`、`height`、`borderRadius`和其他一些样式。让我们把它们添加到`/Post/styles.js`文件中。

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#fff',
    borderRadius: 3,
    height: 340,
    margin: 5,
    width: 240,
  }
});
```

1.  到目前为止，我们应该看到垂直对齐的小框。这是一些进展，但我们需要为图片添加更多样式，这样我们才能在屏幕上看到它。让我们在上一步的相同`styles`常量中添加一个`image`属性。`resizeMode`属性将允许我们设置我们想要如何调整图片的大小。在这种情况下，通过选择`cover`，图片将保持原始的宽高比。

```jsx
  image: {
    backgroundColor: '#ccc',
    height: 120,
    resizeMode: 'cover',
  }
```

1.  对于帖子的`content`，我们希望占据卡片上所有可用的高度，因此我们需要使其灵活并添加一些填充。我们还将向内容添加`overflow: hidden`以避免溢出`View`元素。对于`title`，我们只需要更改`fontSize`并在底部添加`margin`：

```jsx
  content: {
    padding: 10,
    overflow: 'hidden',
    flex: 1,
  },
  title: {
    fontSize: 18,
    marginBottom: 5,
  },
```

1.  最后，对于按钮，我们将`backgroundColor`设置为绿色，文本设置为白色。我们还需要添加一些`padding`和`margin`来进行间距：

```jsx
  button: {
    backgroundColor: '#1abc9c',
    borderRadius: 3,
    padding: 10,
    margin: 10,
  },
  buttonText: {
    color: '#fff',
    textAlign: 'center',
  }
```

1.  如果我们刷新模拟器，我们应该能够看到我们的帖子以小卡片的形式显示。目前，卡片是垂直排列的，但我们希望将它们全部水平渲染。我们将在以下步骤中解决这个问题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/9b2adc12-a3f8-4fe4-9a57-1a67d26382d0.png)已为所有帖子元素添加了主要样式

1.  目前，我们只能在列表中以列的形式看到前三个项目，而不是横向排列在屏幕上。让我们返回`App.js`文件并开始添加我们的样式。我们在`container`中添加`flex: 1`，以便我们的布局始终填满屏幕。我们还希望在顶部显示一个工具栏。为此，我们只需要定义一些`padding`和`color`如下：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#34495e',
    padding: 10,
    paddingTop: 20,
  },
  title: {
    color: '#fff',
    fontSize: 20,
    textAlign: 'center',
  }
});
```

1.  让我们也为`list`添加一些基本样式。一个漂亮的背景颜色和一些填充。我们还将添加`flex`属性，这将确保列表占据屏幕上所有可用的高度。我们这里只有两个组件：工具栏和列表。工具栏占用大约 50 像素。如果我们使列表灵活，它将占据所有剩余的可用空间，这正是我们在旋转设备或在不同屏幕分辨率下运行应用程序时想要的效果：

```jsx
  list: {
    backgroundColor: '#f0f3f4',
    flex: 1,
    paddingTop: 5,
    paddingBottom: 5,
  }
```

1.  如果我们再次在模拟器中检查应用程序，我们应该能够看到工具栏和列表按预期布局：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7136ddc4-acb9-4d77-a451-d8b6fa2e90b8.png)已应用样式给每个帖子，使它们看起来像卡片

1.  我们几乎完成了这个应用程序。我们唯一剩下的事情就是将卡片水平排列。这可以通过 flexbox 在三个简单的步骤中实现：

```jsx
        content: { 
          flexDirection: 'row', 
          flexWrap: 'wrap', 
          justifyContent: 'space-around', 
        }, 
```

第一步是通过`ListView`组件中的`contentContainerStyle`属性应用这些`content`样式。在内部，`ListView`组件将这些样式应用于包裹所有子视图的内容容器。

然后我们将`flexDirection`设置为`row`。这将水平对齐列表上的卡片；然而，这提出了一个新问题：我们只能看到一行帖子。为了解决这个问题，我们需要包裹这些项目。我们通过将`flexWrap`属性设置为`wrap`来实现这一点，这将自动将不适合视图的项目移动到下一行。最后，我们使用`justifyContent`属性并将其设置为`center`，这将使我们的`ListView`居中在应用程序的中间。

1.  我们现在有一个响应灵敏的应用程序，在横向模式下在平板电脑上看起来很好：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/cbd691f2-e7a5-484e-8381-4db14dd7ad36.png)

横向模式下 iPad 和 Android 平板电脑截图的并排比较

并且在纵向模式下看起来也很好：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/07bd3013-a9eb-4d81-9bd5-240d3731943b.png)纵向模式下 iPad 和 Android 平板电脑截图的并排比较

# 还有更多...

Expo 还提供了一个`ScreenOrientation`助手，用于更改应用程序的方向配置。该助手还允许更精细的方向设置（例如`ALL_BUT_UPSIDE_DOWN`或`LANDSCAPE_RIGHT`）。如果您的应用程序需要动态、细粒度的屏幕方向控制，请参阅`ScreenOrientation`Expo 文档获取信息：[`docs.expo.io/versions/v24.0.0/sdk/screen-orientation.html`](https://docs.expo.io/versions/v24.0.0/sdk/screen-orientation.html)。

# 另请参阅

有关静态图像资源和`<Image>`组件的官方文档可以在[ https://facebook.github.io/react-native/docs/images.html](https://facebook.github.io/react-native/docs/images.html)找到。

# 包括自定义字体

在某个时候，我们可能会想要使用自定义字体系列显示文本。到目前为止，我们一直在使用默认字体，但我们可以使用任何其他我们喜欢的字体。

在 Expo 之前，添加自定义字体的过程更加困难，需要使用原生代码，并且需要在 iOS 和 Android 中实现不同的方式。幸运的是，通过使用 Expo 的字体助手库，这一切都变得简化和简化了。

在这个示例中，我们将导入一些字体，然后使用每个导入的字体系列显示文本。我们还将使用不同的字体样式，如**粗体**和*斜体*。

# 准备工作

为了在这个示例上工作，我们需要一些字体。你可以使用任何你喜欢的字体。我建议去 Google Fonts（[`fonts.google.com/`](https://fonts.google.com/)）下载你喜欢的字体。在这个示例中，我们将使用 Josefin Sans 和 Raleway 字体。

一旦你下载了字体，让我们创建一个空的应用程序并将其命名为`custom-fonts`。当我们使用 Expo 创建一个空白应用程序时，它会在项目的根目录中创建一个`assets`文件夹，用于放置所有资产（图像、字体等），因此我们将遵循标准，并将我们的字体添加到此文件夹中。让我们创建`/assets/fonts`文件夹并将从 Google Fonts 下载的自定义字体文件添加到此文件夹中。

从 Google Fonts 下载字体时，你会得到一个包含每个字体系列变体的`.ttf`文件的`.zip`文件。我们将使用常规、**粗体**和*斜体*变体，因此将每个系列的对应`.ttf`文件复制到我们的`/assets/fonts`文件夹中。

# 如何做...

1.  放置好我们的字体文件后，第一步是打开`App.js`并添加我们需要的导入：

```jsx
import React from 'react';
import { Text, View, StyleSheet } from 'react-native';
import { Font } from 'expo';
```

1.  接下来，我们将添加一个简单的组件来显示一些我们想要用我们自定义字体样式的文本。我们将从一个`Text`元素开始，显示 Roboto 字体的常规变体：

```jsx
export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.josefinSans}>
          Hello, Josefin Sans!
        </Text>
      </View>
    );
  }
}
```

1.  让我们也为我们刚刚创建的组件添加一些初始样式。现在，我们只会增加我们的`josefinSans`类样式的字体大小：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  josefinSans: {
    fontSize: 40,
  }
});
```

1.  如果我们现在在模拟器中打开应用程序，我们将看到“Hello, Josefin Sans!”文本以默认字体显示在屏幕中央：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/29a14fb0-a5c0-4208-acb2-eb0a0221f62a.png)

1.  让我们加载我们的`JosefinSans-Regular.ttf`字体文件，以便我们可以用它来样式化我们的文本。我们将使用 React Native 提供的`componentDidMount`生命周期钩子来告诉我们的应用程序何时开始加载字体：

```jsx
export default class App extends React.Component {

 componentDidMount() {
    Font.loadAsync({
      'josefin-sans-regular': require('./assets/fonts/JosefinSans-Regular.ttf'),
    });
  }

  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.josefinSans}>
          Hello, Josefin Sans!
        </Text>
      </View>
    );
  }
}
```

1.  接下来，我们将添加我们正在加载的字体到应用于我们的`Text`元素的样式中：

```jsx
const styles = StyleSheet.create({
  // Other styles from step 3
  josefinSans: {
    fontSize: 40,
 fontFamily: 'josefin-sans-regular'
  }
});
```

1.  我们现在有样式了，对吗？嗯，并不完全是。如果我们回头看看我们的模拟器，我们会看到我们得到了一个错误：

```jsx
console.error: "fontFamily 'josefin-sans-regular' is not a system font and has not been loaded through Expo.Font.loadAsync"
```

1.  但是我们刚刚通过`Expo.Font.loadAsync`加载了字体！怎么回事？事实证明我们面临一个竞争条件。我们为`Text`元素定义的`josefinSans`样式被应用在 Josefin Sans 字体加载之前。为了解决这个问题，我们需要使用组件的`state`来跟踪字体的加载状态：

```jsx
export default class App extends React.Component {
 state = {
    fontLoaded: false
  };
```

1.  现在，我们的组件有了一个`state`，一旦字体加载完成，我们就可以将状态的`fontLoaded`属性更新为`true`。使用 ES6 特性`async`/`await`使这变得简洁而直接。让我们在我们的`componentDidMount`代码块中这样做：

```jsx
  async componentDidMount() {
    await Font.loadAsync({
      'josefin-sans-regular': require('./assets/fonts/JosefinSans-
      Regular.ttf'),
    });
  }
```

1.  由于我们现在正在等待`Font.loadAsync()`调用，一旦调用完成，我们可以将`fontLoaded`的状态设置为`true`：

```jsx
  async componentDidMount() {
    await Font.loadAsync({
      'josefin-sans-regular': require('./assets/fonts/JosefinSans-
      Regular.ttf'),
    });

 this.setState({ fontLoaded: true });
  }
```

1.  现在要做的就是更新我们的`render`方法，只有在`fontLoaded`状态属性为`true`时才渲染依赖于自定义字体的`Text`元素：

```jsx
      <View style={styles.container}>
 {
          this.state.fontLoaded ? (
            <Text style={styles.josefinSans}>
              Hello, Josefin Sans!
            </Text>
          ) : null
        }
      </View>
```

1.  现在，当我们在模拟器中查看我们的应用程序时，我们应该看到我们的自定义字体被应用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/2702c3c8-c45a-4a87-8f45-0d1e93006668.png)

1.  让我们加载其余的字体，这样我们也可以在应用程序中使用它们：

```jsx
    await Font.loadAsync({
      'josefin-sans-regular': require('./assets/fonts/JosefinSans-
      Regular.ttf'),
 'josefin-sans-bold': require('./assets/fonts/JosefinSans-
      Bold.ttf'),
      'josefin-sans-italic': require('./assets/fonts/JosefinSans-
      Italic.ttf'),
      'raleway-regular': require('./assets/fonts/Raleway-
      Regular.ttf'),
      'raleway-bold': require('./assets/fonts/Raleway-Bold.ttf'),
      'raleway-italic': require('./assets/fonts/Raleway-
      Italic.ttf'),
    });
```

1.  我们还需要`Text`元素来显示每个新字体系列/变体中的文本。请注意，由于 JSX 表达式要求只有一个父节点，我们还需要将所有的`Text`元素包装在另一个`View`元素中。我们现在还将`style`属性传递给一个样式数组，以便在下一步中应用`fontSize`和`padding`样式：

```jsx
  render() {
    return (
      <View style={styles.container}>
 {
          this.state.fontLoaded ? (
            <View style={styles.container}>
              <Text style={[styles.josefinSans, 
              styles.textFormatting]}>
                Hello, Josefin Sans!
              </Text>
              <Text style={[styles.josefinSansBold,
              styles.textFormatting]}>
                Hello, Josefin Sans!
              </Text>
              <Text style={[styles.josefinSansItalic, 
              styles.textFormatting]}>
                Hello, Josefin Sans!
              </Text>
              <Text style={[styles.raleway, styles.textFormatting]}>
                Hello, Raleway!
              </Text>
              <Text style={[styles.ralewayBold, 
              styles.textFormatting]}>
                Hello, Raleway!
              </Text>
              <Text style={[styles.ralewayItalic, 
              styles.textFormatting]}>
                Hello, Raleway!
              </Text>
            </View>
          ) : null
        }
      </View>
    );
  }
```

1.  剩下的就是将我们的自定义字体应用到`StyleSheet`中的新样式：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  josefinSans: {
    fontFamily: 'josefin-sans-regular',
  },
  josefinSansBold: {
    fontFamily: 'josefin-sans-bold',
  },
  josefinSansItalic: {
    fontFamily: 'josefin-sans-italic',
  },
  raleway: {
    fontFamily: 'raleway-regular',
  },
  ralewayBold: {
    fontFamily: 'josefin-sans-bold'
  },
  ralewayItalic: {
    fontFamily: 'josefin-sans-italic',
  },
  textFormatting: {
    fontSize: 40,
    paddingBottom: 20
  }
});
```

1.  现在，在我们的应用程序中，我们将看到六个不同的文本元素，每个都使用自己的自定义字体样式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/ea1e48cb-17e9-490d-bd1a-2eca8180b23c.png)

# 工作原理...

在*步骤 5*和*步骤 6*中，我们使用了`componentDidMount` React 生命周期钩子来告诉我们的应用程序何时完成加载。虽然使用`componentWillMount`可能很诱人，但这也会引发错误，因为`componentWillMount`不能保证等待我们的`Font.loadAsync`完成。通过使用`componentDidMount`，我们还可以确保不阻止应用程序的初始渲染。

在*步骤 9*中，我们使用了 ES6 特性`async`/`await`。如果您是 Web 开发人员，您可能已经熟悉了这种模式，但如果您想了解更多信息，我在本教程末尾的*另请参阅*部分中包含了一篇来自[ponyfoo.com](http://ponyfoo.com)的精彩文章，该文章很好地解释了`async`/`await`的工作原理。

在*步骤 11*中，我们使用了一个三元语句，如果加载了我们的自定义字体样式的`Text`元素，则渲染它，如果没有加载，则返回`null`。

通过 Expo 加载的字体目前不支持`fontWeight`或`fontStyle`属性-您需要加载字体的这些变体，并按名称指定它们，就像我们在这里使用粗体和斜体一样。

# 另请参阅

关于`async`/`await`的一篇很棒的文章可以在[`ponyfoo.com/articles/understanding-javascript-async-await`](https://ponyfoo.com/articles/understanding-javascript-async-await)找到。

# 使用字体图标

图标是几乎任何应用程序的必不可少的部分，特别是在导航和按钮中。与上一章中介绍的 Expo 字体助手类似，Expo 还有一个图标助手，使添加图标字体比使用原始的 React Native 要方便得多。在这个示例中，我们将看到如何使用图标助手模块与流行的`FontAwesome`和`Ionicons`图标字体库。

# 准备工作

我们需要为这个示例创建一个新项目。让我们将这个项目命名为`font-icons`。

# 操作步骤

1.  我们将首先打开`App.js`并导入构建应用程序所需的依赖项：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { FontAwesome, Ionicons } from '@expo/vector-icons';
```

1.  接下来，我们可以添加应用程序的外壳，我们将在其中显示图标：

```jsx
export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
      </View>
    );
  }
}
```

1.  在`View`元素内，让我们再添加两个`View`元素来容纳每个图标集中的图标：

```jsx
export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
 <View style={styles.iconRow}>

        </View>
        <View style={styles.iconRow}>

        </View>
      </View>
    );
  }
}
```

1.  现在，让我们为我们声明的每个元素添加样式。正如我们在之前的示例中看到的，`container`样式使用`flex: 1`填充屏幕，并使用`alignItems`和`justifyContent`将项目居中设置为`center`。`iconRow`属性将`flexDirection`设置为`row`，这样我们的图标将排成一行：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconRow: {
    flexDirection: 'row',
  },
});
```

1.  现在我们的应用程序的基本结构已经就位，让我们添加我们的图标。在第一行图标中，我们将使用四个`FontAwesome`组件来显示`FontAwesome`字体库中的四个图标。`name`属性确定应该使用哪个图标，`size`属性设置图标的像素大小，`color`设置图标的颜色：

```jsx
<View style={styles.iconRow}>
 <FontAwesome style={styles.iconPadding} name="glass" size={48} color="green" />
  <FontAwesome style={styles.iconPadding} name="beer" size={48} color="red" />
  <FontAwesome style={styles.iconPadding} name="music" size={48} color="blue" />
  <FontAwesome style={styles.iconPadding} name="taxi" size={48} color="#1CB5AD" />
</View>
```

就像在 CSS 中一样，`color`属性可以是 CSS 规范中定义的颜色关键字（您可以在 MDN 文档的完整列表中查看[`developer.mozilla.org/en-US/docs/Web/CSS/color_value`](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value)），也可以是给定颜色的十六进制代码。

1.  在接下来的`View`元素中，我们将添加来自`Ionicons`字体库的图标。正如您所看到的，`Ionicons`元素接受与上一步中使用的`FontAwesome`元素相同的属性：

```jsx
<View style={styles.iconRow}>
 <Ionicons style={styles.iconPadding} name="md-pizza" size={48} color="orange" />
  <Ionicons style={styles.iconPadding} name="md-tennisball" size={48} color="maroon" />
  <Ionicons style={styles.iconPadding} name="ios-thunderstorm" size={48} color="purple" />
  <Ionicons style={styles.iconPadding} name="ios-happy" size={48} color="#DF7977" />
</View>
```

1.  这个配方的最后一步是添加剩下的样式`iconPadding`，它只是为每个图标添加一些填充，以均匀地间隔开每个图标：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconRow: {
    flexDirection: 'row',
  },
 iconPadding: {
    padding: 8,
  }
});
```

1.  就是这样！当我们查看我们的应用程序时，将会有两行图标，每一行分别展示来自`FontAwesome`和`Ionicons`的图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/f7371449-caec-4c4a-9993-256cecd34e81.png)

# 它是如何工作的...

Expo 提供的`vector-icons`包可以访问 11 个完整的图标集。你所需要做的就是导入相关的组件（例如，`FontAwesome`组件用于 Font Awesome 图标），并为其提供与你想要使用的图标集中相对应的图标名称。你可以在`vector-icons`目录中找到一个完整的、可搜索的图标列表，该目录托管在[`expo.github.io/vector-icons/`](https://expo.github.io/vector-icons/)。只需将元素的`name`属性设置为目录中列出的图标名称，添加`size`和`color`属性，就完成了！

正如 GitHub 上`vector-icons`的 README 所述，这个库是为了在 Expo 中使用`react-native-vector-icons`包提供的图标而创建的兼容层。你可以在[`github.com/oblador/react-native-vector-icons`](https://github.com/oblador/react-native-vector-icons)找到这个包。如果你正在构建一个没有 Expo 的 React Native 应用程序，你可以使用`react-native-vector-icons`库来获得相同的功能。

# 另请参阅

`vector-icons`库中所有可用图标的目录可以在[`expo.github.io/vector-icons/`](https://expo.github.io/vector-icons/)找到。
