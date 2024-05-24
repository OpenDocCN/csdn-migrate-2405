# React 和 ReactNative 第二版（四）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：为什么选择 React Native？

Facebook 创建了 React Native 来构建其移动应用程序。这样做的动机源于 React 在 Web 上非常成功的事实。如果 React 是如此适合 UI 开发的工具，并且您需要一个本机应用程序，那么为什么要反对呢？只需使 React 与本机移动操作系统 UI 元素配合工作即可！

在本章中，您将了解使用 React Native 构建本机移动 Web 应用程序的动机。

# 什么是 React Native？

在本书的前面，我介绍了渲染目标的概念-React 组件渲染到的东西。就 React 程序员而言，渲染目标是抽象的。例如，在 React 中，渲染目标可以是字符串，也可以是 DOM。这就是为什么您的组件从不直接与渲染目标进行交互的原因，因为您永远不能假设渲染发生的位置。

移动平台具有开发人员可以利用的 UI 小部件库，以构建该平台的应用程序。在 Android 上，开发人员实现 Java 应用程序，而在 iOS 上，开发人员实现 Swift 应用程序。如果您想要一个功能齐全的移动应用程序，您将不得不选择一个。但是，您需要学习两种语言，因为仅支持两个主要平台中的一个对于成功来说是不现实的。

对于 React 开发人员来说，这不是问题。您构建的相同 React 组件可以在各个地方使用，甚至可以在移动浏览器上使用！必须学习两种新编程语言来构建和发布移动应用程序是成本和时间上的障碍。解决此问题的方法是引入一个支持新渲染目标-本机移动 UI 小部件的新 React。

React Native 使用一种技术，该技术对底层移动操作系统进行异步调用，该操作系统调用本机小部件 API。有一个 JavaScript 引擎，React API 与 Web 上的 React 大部分相同。不同之处在于目标；而不是 DOM，这里有异步 API 调用。该概念在这里可视化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/8a6ec01c-eda8-4eea-8f2e-683980afcb04.png)

这过于简化了底层发生的一切，但基本思想如下：

+   在 Web 上使用的 React 库与 React Native 使用的相同，并在 JavaScriptCore 中运行

+   发送到本机平台 API 的消息是异步的，并且为了性能目的而批处理

+   React Native 附带了为移动平台实现的组件，而不是 HTML 元素的组件

有关 React Native 的历史和机制的更多信息，请访问[`code.facebook.com/posts/1014532261909640`](https://code.facebook.com/posts/1014532261909640)。

# React 和 JSX 很熟悉

为 React 实现一个新的渲染目标并不简单。这本质上就像在 iOS 和 Android 上发明一个新的 DOM。那么为什么要经历这么多麻烦呢？

首先，移动应用程序的需求非常大。原因是移动网络浏览器的用户体验不如原生应用程序体验好。其次，JSX 是构建用户界面的绝佳工具。与其学习新技术，使用自己已经掌握的知识要容易得多。

后一点对你来说最相关。如果你正在阅读这本书，你可能对在 Web 应用程序和原生移动应用程序中使用 React 感兴趣。我无法用言语表达 React 在开发资源方面有多么宝贵。与其有一个团队做 Web UI，一个团队做 iOS，一个团队做 Android 等等，只需要一个了解 React 的 UI 团队。

# 移动浏览器体验

移动浏览器缺乏许多移动应用程序的功能。这是因为浏览器无法复制与 HTML 元素相同的本机平台小部件。你可以尝试这样做，但通常最好只使用本机小部件，而不是尝试复制它。部分原因是这样做需要更少的维护工作，部分原因是使用与平台一致的小部件意味着它们与平台的其他部分一致。例如，如果应用程序中的日期选择器看起来与用户在手机上与之交互的所有日期选择器不同，这不是一件好事。熟悉是关键，使用本机平台小部件使熟悉成为可能。

移动设备上的用户交互与通常为 Web 设计的交互基本不同。例如，Web 应用程序假设存在鼠标，并且按钮上的点击事件只是一个阶段。但是，当用户用手指与屏幕交互时，事情变得更加复杂。移动平台有所谓的手势系统来处理这些。React Native 比 Web 上的 React 更适合处理手势，因为它处理了在 Web 应用程序中不必过多考虑的这些类型的事情。

随着移动平台的更新，您希望您的应用程序的组件也保持更新。这对于 React Native 来说并不是问题，因为它们使用的是来自平台的实际组件。一次，一致性和熟悉度对于良好的用户体验至关重要。因此，当您的应用程序中的按钮看起来和行为方式与设备上的其他每个应用程序中的按钮完全相同时，您的应用程序就会感觉像设备的一部分。

# Android 和 iOS，不同但相同

当我第一次听说 React Native 时，我自动地认为它会是一种跨平台解决方案，可以让您编写一个单一的 React 应用程序，可以在任何设备上本地运行。在开始使用 React Native 之前，请摆脱这种思维方式。iOS 和 Android 在许多基本层面上是不同的。甚至它们的用户体验理念也不同，因此试图编写一个可以在两个平台上运行的单一应用程序是完全错误的。

此外，这并不是 React Native 的目标。目标是*React 组件无处不在*，而不是一次编写，随处运行。在某些情况下，您可能希望您的应用程序利用 iOS 特定的小部件或 Android 特定的小部件。这为特定平台提供了更好的用户体验，并应该超越组件库的可移植性。

在后面的章节中，您将学习有关组织特定于平台的模块的不同策略。

iOS 和 Android 之间有几个领域存在重叠，差异微不足道。这两个小部件旨在以大致相同的方式为用户完成相同的事情。在这些情况下，React Native 将为您处理差异并提供统一的组件。

# 移动 Web 应用的情况

在上一章中，您学会了如何实现移动优先的 React 组件。您的用户中并非每个人都愿意安装应用程序，特别是如果您的下载量和评分还不高的话。通过 Web 应用程序，用户的准入门槛要低得多——用户只需要一个浏览器。

尽管无法复制原生平台 UI 所提供的一切，但您仍然可以在移动 Web UI 中实现出色的功能。也许拥有一个良好的 Web UI 是提高移动应用程序下载量和评分的第一步。

理想情况下，您应该瞄准以下目标：

+   标准 Web（笔记本/台式机浏览器）

+   移动 Web（手机/平板浏览器）

+   移动应用（手机/平板原生平台）

在这三个领域中投入同样的努力可能并不明智，因为你的用户可能更偏爱其中一个领域。一旦你知道，例如，相对于 Web 版本，你的移动应用程序需求非常高，那么你就应该在那里投入更多的努力。

# 总结

在本章中，你了解到 React Native 是 Facebook 的一项努力，旨在重用 React 来创建本机移动应用程序。React 和 JSX 非常擅长声明 UI 组件，而现在对移动应用程序的需求非常大，因此使用你已经了解的 Web 知识是有意义的。

移动应用程序比移动浏览器更受欢迎的原因是它们的体验更好。Web 应用程序缺乏处理移动手势的能力，而且通常在外观和感觉上不像移动体验的一部分。

React Native 并不试图实现一个组件库，让你可以构建一个在任何移动平台上运行的单个 React 应用程序。iOS 和 Android 在许多重要方面都有根本的不同。在有重叠的地方，React Native 确实尝试实现共同的组件。现在我们可以使用 React 进行本地构建，那么我们是否会放弃移动 Web 应用程序？这可能永远不会发生，因为用户只能安装那么多应用程序。

现在你知道了 React Native 的主要目标是什么以及它的优势，接下来你将在下一章学习如何开始新的 React Native 项目。

# 测试你的知识

1.  React Native 的主要目标是什么？

1.  消除构建移动 Web 应用程序的需求。

1.  使 React 开发人员能够轻松将他们已经了解的构建 UI 组件的知识应用于构建本机移动应用程序。

1.  提供统一的用户体验跨所有移动平台。

1.  React Native 在 iOS 和 Android 上提供完全相同的体验吗？

1.  不，iOS 和 Android 有根本不同的用户体验。

1.  是的，你希望你的应用在 iOS 和 Android 上的功能完全相同。

1.  React Native 是否消除了对移动 Web 应用程序的需求？

1.  是的，如果你可以构建本机移动应用程序，就不需要移动 Web 应用程序。

1.  不，总会有移动 Web 应用程序的需求。当你需要本机移动应用程序时，React Native 就在那里。

# 进一步阅读

访问以下链接以获取更多信息：

+   [`facebook.github.io/react-native/`](https://facebook.github.io/react-native/)

+   [`code.facebook.com/posts/1014532261909640`](https://code.facebook.com/posts/1014532261909640)


# 第十三章：启动 React Native 项目

在本章中，您将开始使用 React Native。幸运的是，`create-react-native-app`命令行工具已经为您处理了创建新项目所涉及的大部分样板。我将解释当您初始化一个空项目时实际为您创建了什么。然后，我将向您展示如何在 iOS 和 Android 模拟器上运行项目。

# 安装和使用`create-react-native-app`

创建 React Native 项目的首选工具是`create-react-native-app`。这个命令行工具是由 React Native 开发者社区创建的，并且遵循了`create-react-app`工具的步伐。`create-react-app`和`create-react-native-app`的目标是使开发人员能够快速启动他们的项目。您应该能够发出一个命令，生成运行您的 React 或 React Native 应用程序所必需的所有样板。

没有这种类型的工具，您最终会花费大量时间来配置项目的各个方面。首先，开发人员想要构建应用程序。您可以稍后进行配置和优化。

您应该全局安装`create-react-native-app`，因为这个工具不是针对您正在工作的任何一个项目的特定工具——它为您启动了项目。以下是您可以这样做的方法：

```jsx
npm install -g create-react-native-app
```

安装完成后，您将在终端中获得一个新的`create-react-native-app`命令。您可以使用这个命令来启动您的新 React Native 项目。

# 创建一个 React Native 应用程序

使用`create-react-native-app`启动一个新的 React Native 项目涉及调用`create-react-native-app`命令，并将应用程序的名称作为参数传递进去。例如：

```jsx
create-react-native-app my-project
```

这将导致创建一个`my-project`目录。这里将包含`create-react-native-app`为您创建的所有样板代码和其他文件。这也是您将找到`node_modules`目录的地方，其中安装了所有的依赖项。

当您运行此命令时，您将看到类似于以下内容的输出：

```jsx
Creating a new React Native app in Chapter13/my-project. Using package manager as npm with npm interface. Installing packages. This might take a couple minutes. Installing react-native-scripts... + react-native-scripts@1.14.0 added 442 packages from 477 contributors and audited 1178 packages in 19.128s Installing dependencies using npm... Success! Created my-project at Chapter13/my-project Inside that directory, you can run several commands:
  npm start
 Starts the development server so you can open your app in the Expo app on your phone.  npm run ios
 (Mac only, requires Xcode) Starts the development server and loads your app in an iOS simulator.  npm run android
 (Requires Android build tools) Starts the development server and loads your app on a connected Android device or emulator.  npm test
 Starts the test runner.  npm run eject
 Removes this tool and copies build dependencies, configuration files and scripts into the app directory. If you do this, you can’t go back! We suggest that you begin by typing:
  cd my-project
  npm start Happy hacking!
```

输出显示了安装依赖项时正在进行的操作，以及准备立即运行的命令。此时，您已经准备好启动您的应用程序。

# 运行您的应用程序

当您使用`create-react-native-app`来引导您的 React Native 项目时，会将几个命令添加到您的`package.json`文件中。这些列在命令输出中（请参阅前一节，了解此输出的外观）。您将使用的最常见的命令是`start`：

```jsx
npm start
```

这个命令将启动打包进程。当您更新源代码时，此过程将构建原生 UI 组件。它不会为实际的目标平台执行本机构建，因为这在性能上会太昂贵。相反，它将高效地构建您的应用程序，以便与各种模拟器一起使用开发：

```jsx
Here's what the output of npm start looks like:
Starting packager... Packager started!
Your app is now running at URL: exp://192.168.86.21:19000 View your app with live reloading:
 Android device:
    -> Point the Expo app to the QR code above.
       (You'll find the QR scanner on the Projects tab of the app.)
  iOS device:
    -> Press s to email/text the app URL to your phone.   Emulator:
    -> Press a (Android) or i (iOS) to start an emulator. Your phone will need to be on the same local network as this computer.
For links to install the Expo app, please visit https://expo.io. Logs from serving your app will appear here. Press Ctrl+C at any time to stop.
 › Press a to open Android device or emulator, or i to open iOS emulator.
 › Press s to send the app URL to your phone number or email address
 › Press q to display QR code.  › Press r to restart packager, or R **to restart packager and clear cache.**
 **› Press d to toggle development mode. (current mode: development)** 
```

有许多选项可供您模拟您的原生应用程序。默认情况下，您处于开发模式 - 您可能会保持在开发模式。在前面的输出中没有显示的是，输出还包括一个 QR 码，您可以使用 Expo 移动应用程序扫描。

# 安装和使用 Expo

**Expo**移动应用程序是一个工具，您可以用它来辅助 React Native 开发。`npm start`命令启动 React Native 包，它与 Expo 无缝集成（前提是设备与打包程序在同一网络上）。这使您能够在开发过程中在真实移动设备上查看和交互您的应用程序。当您对源代码进行更改时，它甚至支持实时重新加载。

Expo 与移动设备模拟器不同，它使您能够以与用户体验相同的方式体验应用程序。虚拟设备模拟器给出了一个粗略的近似值，但这并不等同于手持设备。此外，并非每个人都有 Macbook，这是模拟 iOS 设备的要求。

您可以通过在 Android 设备上搜索 Play 商店或在 iOS 设备上搜索 App Store 来找到 Expo 应用程序。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d389303d-8906-4520-a9c1-205e194ba327.png)

当您启动 Expo 时，您将看到一个扫描 QR 码的选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/ae8eb031-06bd-4f40-98b5-86322bc29d3f.png)

当您选择扫描 QR 码时，您手机的摄像头可以扫描终端中打印的 QR 码。这是您将计算机上运行的 React Native 打包程序与您的设备连接的方式。如果您无法扫描 QR 码，您可以通过电子邮件将 Expo 链接发送到您的手机上，在手机上点击它与扫描 QR 码是一样的。

当在 Expo 中打开`my-project`应用程序时，应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/0f74de79-cef9-49d8-b99e-1d2193c6d270.png)

让我们来看看由`create-react-native-app`为您创建的`App.js`模块：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text>Open up App.js to start working on your app!</Text>
        <Text>Changes you make will automatically reload.</Text>
        <Text>Shake your phone to open the developer menu.</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center'
  }
});
```

这个`App`组件将在屏幕上呈现三行文本，并对`View`组件应用一些样式。让我们对第一行进行更改，使文本加粗：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

export default class App extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.bold}>
          Open up App.js to start working on your app!
        </Text>
        <Text>Changes you make will automatically reload.</Text>
        <Text>Shake your phone to open the developer menu.</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center'
  },
  bold: {
    fontWeight: 'bold'
  }
});
```

现在样式中有一个加粗样式，并且这被应用到了第一个`Text`组件的样式属性上。如果您再次查看手机，您会注意到应用程序已更新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c0049bfd-f6e0-4637-b169-f8196c8caa87.png)

更改立即反映在您设备上的应用程序中。

# 使用模拟器

您并不总是随身携带手机，事实上，在开发过程中并不总是需要在物理移动设备上查看您的应用程序。另一个选择是使用模拟物理移动设备的虚拟设备模拟器。React Native 打包程序与模拟器通信的方式与其与 Expo 应用程序通信的方式相同，以支持实时重新加载。

# iOS 模拟器

启动 React Native 打包程序后，按“i”键即可启动 iOS 模拟器。您将看到类似于这样的输出：

```jsx
2:06:04 p.m.: Starting iOS... 2:06:22 p.m.: Finished building JavaScript bundle in 1873ms 2:06:23 p.m.: Running app on Adam in development mode
```

然后，您将看到一个新窗口打开，模拟设备正在运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/ff024621-8f4c-4072-b20f-b641740ce8db.png)

对应用程序源的实时更新与 Expo 应用程序的工作方式相同。更改会在模拟器中自动反映。 

# Android 模拟器

Android 模拟器的启动方式与 iOS 模拟器相同。在运行 React Native 打包程序的终端中，按“A”键。但是，有一个警告 - 您必须在启动 React Native 包内的应用程序之前启动 Android 设备模拟器。如果不这样做，当您按“A”键时，您将看到类似于这样的消息：

```jsx
2:37:02 p.m.: Starting Android... Error running adb: No Android device found.
```

这在过去一直是 Android 上难以做到的。现在，借助 Android Studio 的帮助，启动 Android 设备模拟器变得简单得多。一旦安装了 Android Studio，您可以打开 Android 虚拟设备管理器并添加任何您喜欢的设备：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e0b89db2-5eea-44f2-9db5-09afe20e5144.png)

您可以单击“创建虚拟设备”按钮来创建一个新设备：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/32508eb6-7b8d-421b-8f76-b94920225d13.png)

一旦您创建了要在其上测试 React Native 应用程序的设备，您可以单击绿色播放按钮。这将启动模拟器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e2d4adbc-dc2a-412e-8048-d9875f9ff279.png)

如果你回到运行 React Native 打包程序的终端并按下"a"，你应该会看到以下输出：

```jsx
2:49:07 p.m.: Starting Android... 2:49:08 p.m.: Finished building JavaScript bundle in 17ms 2:49:10 p.m.: Running app on Android SDK built for x86 in development mode
```

如果你回到你的 Android 模拟器，你的 React Native 应用应该已经启动了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/aaffe1fa-d76d-4399-8b6a-17a26009339a.png)

就像 Expo 应用程序和 iOS 模拟器一样，这个模拟器将随着应用程序源代码的更改而实时重新加载，这要归功于 React Native 打包程序。

# 总结

在本章中，你学会了如何使用`create-react-native-app`工具启动你的 React。你学会了如何在系统上安装该工具，并使`create-react-native-app`命令对你创建的任何 React Native 项目可用。然后，你使用该命令启动了一个基本项目。接下来，你在项目中启动了 React Native 打包程序进程。

你学会了如何在移动设备上安装 Expo 应用程序以及如何将其与 React Native 打包程序连接。然后，你进行了代码更改，以演示实时重新加载的工作原理。最后，你学会了如何使用 React Native 打包程序启动 iOS 和 Android 模拟器。

在下一章中，你将学习如何在 React Native 应用程序中构建灵活的布局。

# 测试你的知识

1.  `create-react-native-app`工具是由 Facebook 创建的

1.  是的，`create-react-native-app`从一开始就存在

1.  不，这是一个社区支持的工具，跟随**`create-react-app`**的脚步

1.  为什么你应该全局安装`create-react-native-app`？

1.  因为没有办法在本地安装它

1.  你不应该。只在本地安装它

1.  因为这是一个用于生成项目样板的工具，实际上并不是项目的一部分

1.  一切都应该全局安装。

1.  Expo 应用程序在移动设备上的作用是什么？

1.  这是一个增强 React Native 应用程序的库

1.  这是一个帮助开发人员在开发过程中在移动设备上运行他们的应用程序的工具，开销非常小

1.  这是一个可以在目标设备上本地构建项目并安装的工具

1.  React Native 打包程序能够模拟 iOS 和 Android 设备

1.  它不会这样做，但它会与 iOS 和 Android 模拟器通信以运行应用程序

1.  是的，模拟器是 React Native 的一部分

# 进一步阅读

查看以下链接以了解更多信息：

+   [`developer.apple.com/xcode/`](https://developer.apple.com/xcode/)

+   [`developer.android.com/studio/`](https://developer.android.com/studio/)

+   [`expo.io/`](https://expo.io/)

+   [`github.com/react-community/create-react-native-app`](https://github.com/react-community/create-react-native-app)


# 第十四章：使用 Flexbox 构建响应式布局

在本章中，您将体会到在移动设备屏幕上布局组件的感觉。幸运的是，React Native 为许多您过去可能在 Web 应用程序中使用的 CSS 属性提供了 polyfill。您将学习如何使用 flexbox 模型来布局我们的 React Native 屏幕。

在深入实现布局之前，您将简要介绍 flexbox 和在 React Native 应用程序中使用 CSS 样式属性——这与常规 CSS 样式表不太一样。然后，您将使用 flexbox 实现几个 React Native 布局。

# Flexbox 是新的布局标准

在 CSS 引入灵活的盒子布局模型之前，用于构建布局的各种方法都感觉很巧妙，并且容易出错。Flexbox 通过抽象化许多通常需要提供的属性来修复这一问题，以使布局正常工作。

实质上，flexbox 就是其字面意思——一个灵活的盒子模型。这就是 flexbox 的美妙之处——它的简单性。您有一个充当容器的盒子，以及该盒子内的子元素。容器和子元素在屏幕上的呈现方式都是灵活的，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b21c0689-a915-41fe-b299-69805fde62e8.png)

Flexbox 容器有一个方向，可以是列（上/下）或行（左/右）。当我第一次学习 flexbox 时，这实际上让我感到困惑：我的大脑拒绝相信行是从左到右移动的。行是堆叠在彼此上面的！要记住的关键是，这是盒子伸展的方向，而不是盒子在屏幕上放置的方向。

有关 flexbox 概念的更深入的处理，请查看此页面：[`css-tricks.com/snippets/css/a-guide-to-flexbox/`](https://css-tricks.com/snippets/css/a-guide-to-flexbox/)。

# 介绍 React Native 样式

是时候实现您的第一个 React Native 应用程序了，超出了`create-react-native-app`生成的样板。我希望在您开始在下一节中实现 flexbox 布局之前，您能够确保在使用 React Native 样式表时感到舒适。以下是 React Native 样式表的样子：

```jsx
import { Platform, StyleSheet, StatusBar } from 'react-native';

// Exports a "stylesheet" that can be used
// by React Native components. The structure is
// familiar for CSS authors.
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'ghostwhite',
    ...Platform.select({
      ios: { paddingTop: 20 },
      android: { paddingTop: StatusBar.currentHeight }
    })
  },

  box: {
    width: 100,
    height: 100,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'lightgray'
  },

  boxText: {
    color: 'darkslategray',
    fontWeight: 'bold'
  }
});

export default styles; 
```

这是一个 JavaScript 模块，而不是 CSS 模块。如果要声明 React Native 样式，需要使用普通对象。然后，调用`StyleSheet.create()`并从样式模块导出它。

正如你所看到的，这个样式表有三种样式：`container`、`box`和`boxText`。在容器样式中，有一个调用`Platform.select()`的方法：

```jsx
...Platform.select({
  ios: { paddingTop: 20 },
  android: { paddingTop: StatusBar.currentHeight }
})
```

这个函数将根据移动设备的平台返回不同的样式。在这里，你正在处理顶层容器视图的顶部填充。你可能会在大多数应用中使用这段代码，以确保你的 React 组件不会渲染在设备的状态栏下面。根据平台的不同，填充将需要不同的值。如果是 iOS，`paddingTop`是`20`。如果是 Android，`paddingTop`将是`StatusBar.currentHeight`的值。

前面的`Platform.select()`代码是一个例子，说明你需要为平台的差异实现一个解决方法。例如，如果`StatusBar.currentHeight`在 iOS 和 Android 上都可用，你就不需要调用`Platform.select()`。

让我们看看这些样式是如何被导入并应用到 React Native 组件的：

```jsx
import React from 'react';
import { Text, View } from 'react-native';

// Imports the "styles" stylesheet from the
// "styles" module.
import styles from './styles';

// Renders a view with a square in the middle, and
// some text in the middle of that. The "style" property
// is passed a value from the "styles" stylesheet.
export default () => (
  <View style={styles.container}>
    <View style={styles.box}>
      <Text style={styles.boxText}>I'm in a box</Text>
    </View>
  </View>
); 
```

这些样式通过`style`属性分配给每个组件。你正在尝试渲染一个带有一些文本的框在屏幕中间。让我们确保这看起来和我们期望的一样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3f0c5355-7581-40c7-8bd7-016d6b588d90.png)

太棒了！现在你已经知道如何在 React Native 元素上设置样式，是时候开始创建一些屏幕布局了。

# 构建 flexbox 布局

在这一部分，你将了解在 React Native 应用中可以使用的几种潜在布局。我想远离一个布局比其他布局更好的想法。相反，我会向你展示 flexbox 布局模型对于移动屏幕有多么强大，这样你就可以设计最适合你的应用的布局。

# 简单的三列布局

首先，让我们实现一个简单的布局，其中有三个部分在列的方向上弹性伸缩（从上到下）。让我们先来看一下结果屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cfc50f9a-7cda-4907-813c-a7ee6061392b.png)

这个例子的想法是，你已经为三个屏幕部分设置了样式和标签，使它们突出显示。换句话说，在真实应用中，这些组件不一定会有任何样式，因为它们用于在屏幕上排列其他组件。

让我们来看一下用于创建此屏幕布局的组件：

```jsx
import React from 'react';
import { Text, View } from 'react-native';

import styles from './styles';

// Renders three "column" sections. The "container"
// view is styled so that it's children flow from
// the top of the screen, to the bottom of the screen.
export default () => (
  <View style={styles.container}>
    <View style={styles.box}>
      <Text style={styles.boxText}>#1</Text>
    </View>
    <View style={styles.box}>
      <Text style={styles.boxText}>#2</Text>
    </View>
    <View style={styles.box}>
      <Text style={styles.boxText}>#3</Text>
    </View>
  </View>
); 
```

容器视图（最外层的 `<View>` 组件）是列，子视图是行。`<Text>` 组件用于标记每一行。在 HTML 元素方面，`<View>` 类似于 `<div>`，而 `<Text>` 类似于 `<p>`。

也许这个例子本来可以被称为“三行布局”，因为它有三行。但与此同时，三个布局部分都在其所在的列的方向上伸展。使用对你来说最有概念意义的命名约定。

现在让我们看一下用于创建此布局的样式：

```jsx
import { Platform, StyleSheet, StatusBar } from 'react-native';

// Exports a "stylesheet" that can be used
// by React Native components. The structure is
// familiar for CSS authors.
export default StyleSheet.create({
  // The "container" for the whole screen.
  container: {
    // Enables the flexbox layout model...
    flex: 1,
    // Tells the flexbox to render children from
    // top to bottom...
    flexDirection: 'column',
    // Aligns children to the center on the container...
    alignItems: 'center',
    // Defines the spacing relative to other children...
    justifyContent: 'space-around',
    backgroundColor: 'ghostwhite',
    ...Platform.select({
      ios: { paddingTop: 20 },
      android: { paddingTop: StatusBar.currentHeight }
    })
  },

  box: {
    width: 300,
    height: 100,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'lightgray',
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: 'darkslategray'
  },

  boxText: {
    color: 'darkslategray',
    fontWeight: 'bold'
  }
}); 
```

`container` 的 `flex` 和 `flexDirection` 属性使得行的布局从上到下流动。`alignItems` 和 `justifyContent` 属性将子元素对齐到容器的中心，并在它们周围添加空间。

让我们看看当你将设备从竖屏旋转到横屏时，这个布局是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/84f1fc09-2559-449a-adda-0ca301c252fa.png)

flexbox 自动找到了如何为你保留布局。但是，你可以稍微改进一下。例如，横屏模式现在左右有很多浪费的空间。你可以为渲染的盒子创建自己的抽象。

# 改进后的三列布局

我认为你可以从上一个例子中改进一些东西。让我们修复样式，使得 flexbox 的子元素能够充分利用可用空间。还记得上一个例子中，当你将设备从竖屏旋转到横屏时发生了什么吗？有很多空间被浪费了。让组件自动调整会很好。下面是新样式模块的样子：

```jsx
import { Platform, StyleSheet, StatusBar } from 'react-native';

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'column',
    backgroundColor: 'ghostwhite',
    alignItems: 'center',
    justifyContent: 'space-around',
    ...Platform.select({
      ios: { paddingTop: 20 },
      android: { paddingTop: StatusBar.currentHeight }
    })
  },

  box: {
    height: 100,
    justifyContent: 'center',
    // Instead of given the flexbox child a width, we
    // tell it to "stretch" to fill all available space.
    alignSelf: 'stretch',
    alignItems: 'center',
    backgroundColor: 'lightgray',
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: 'darkslategray'
  },

  boxText: {
    color: 'darkslategray',
    fontWeight: 'bold'
  }
});

export default styles; 
```

这里的关键变化是 `alignSelf` 属性。这告诉具有 `box` 样式的元素改变宽度或高度（取决于其容器的 `flexDirection`）以填充空间。此外，`box` 样式不再定义 `width` 属性，因为现在将动态计算它。在竖屏模式下，各个部分的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b6823803-9c64-4f2a-a7a1-aaa4d3d62f35.png)

现在每个部分都占据了屏幕的整个宽度，这正是你希望发生的。浪费空间的问题实际上在横屏模式下更为突出，所以让我们旋转设备，看看这些部分现在会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/09165861-0bf5-4c97-8afe-d797fba4d9e8.png)

现在你的布局利用了整个屏幕的宽度，不管方向如何。最后，让我们实现一个适当的`Box`组件，可以被`App.js`使用，而不是在原地重复样式属性。`Box`组件的样子如下：

```jsx
import React from 'react';
import { PropTypes } from 'prop-types';
import { View, Text } from 'react-native';

import styles from './styles';

// Exports a React Native component that
// renders a "<View>" with the "box" style
// and a "<Text>" component with the "boxText"
// style.
const Box = ({ children }) => (
  <View style={styles.box}>
    <Text style={styles.boxText}>{children}</Text>
  </View>
);

Box.propTypes = {
  children: PropTypes.node.isRequired
};

export default Box; 
```

现在你已经有了一个不错的布局的开端。接下来，你将学习如何在另一个方向上进行弹性布局——从左到右。

# 灵活的行

在这一节中，你将学习如何使屏幕布局部分从上到下延伸。为此，你需要一个灵活的行。这个屏幕的样式如下：

```jsx
import { Platform, StyleSheet, StatusBar } from 'react-native';

const styles = StyleSheet.create({
  container: {
    flex: 1,
    // Tells the child elements to flex from left to
    // right...
    flexDirection: 'row',
    backgroundColor: 'ghostwhite',
    alignItems: 'center',
    justifyContent: 'space-around',
    ...Platform.select({
      ios: { paddingTop: 20 },
      android: { paddingTop: StatusBar.currentHeight }
    })
  },

  box: {
    width: 100,
    justifyContent: 'center',
    alignSelf: 'stretch',
    alignItems: 'center',
    backgroundColor: 'lightgray',
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: 'darkslategray'
  },

  boxText: {
    color: 'darkslategray',
    fontWeight: 'bold'
  }
});

export default styles; 
```

这是`App`组件，使用了你在上一节中实现的`Box`组件：

```jsx
import React from 'react';
import { Text, View, StatusBar } from 'react-native';

import styles from './styles';
import Box from './Box';

// Renders a single row with two boxes that stretch
// from top to bottom.
export default () => (
  <View style={styles.container}>
    <Box>#1</Box>
    <Box>#2</Box>
  </View>
); 
```

这是纵向模式下的屏幕效果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f56cfffc-2dad-426c-8f05-f7c053f4acf0.png)

这两列从屏幕顶部一直延伸到屏幕底部，这是因为`alignSelf`属性，它实际上并没有指定要延伸的方向。这两个`Box`组件从上到下延伸，因为它们显示在一个弹性行中。注意这两个部分之间的间距是从左到右的吗？这是因为容器的`flexDirection`属性，它的值是`row`。

现在让我们看看当屏幕旋转到横向方向时，这种弹性方向对布局的影响：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/30184fb5-cf9d-4b9d-bc98-cd5a0a89c051.png)

由于弹性盒模型具有`justifyContent`样式属性值为`space-around`，空间被比例地添加到左侧、右侧和部分之间。

# 灵活的网格

有时，你需要一个像网格一样流动的屏幕布局。例如，如果你有几个宽度和高度相同的部分，但你不确定会渲染多少个这样的部分呢？弹性盒模型使得从左到右流动的行的构建变得容易，直到屏幕的末端。然后，它会自动继续从左到右在下一行渲染元素。

这是纵向模式下的一个布局示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1d539b72-e514-486e-aaa9-def0393fd2fe.png)

这种方法的美妙之处在于，你不需要提前知道每一行有多少列。每个子元素的尺寸决定了每一行可以容纳多少个元素。让我们来看一下用于创建这个布局的样式：

```jsx
import { Platform, StyleSheet, StatusBar } from 'react-native';

export default StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
    flexWrap: 'wrap',
    backgroundColor: 'ghostwhite',
    alignItems: 'center',
    ...Platform.select({
      ios: { paddingTop: 20 },
      android: { paddingTop: StatusBar.currentHeight }
    })
  },

  box: {
    height: 100,
    width: 100,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'lightgray',
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: 'darkslategray',
    margin: 10
  },

  boxText: {
    color: 'darkslategray',
    fontWeight: 'bold'
  }
}); 
```

这是渲染每个部分的`App`组件：

```jsx
import React from 'react';
import { View, StatusBar } from 'react-native';

import styles from './styles';
import Box from './Box';

// An array of 10 numbers, representing the grid
// sections to render.
const boxes = new Array(10).fill(null).map((v, i) => i + 1);

export default () => (
  <View style={styles.container}>
    <StatusBar hidden={false} />
    {/* Renders 10 "<Box>" sections */}
    {boxes.map(i => <Box key={i}>#{i}</Box>)}
  </View>
); 
```

最后，让我们确保横向方向与这个布局兼容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/6cb2d557-480d-462f-a4f9-928a1420ea5b.png)你可能已经注意到右侧有一些多余的空间。请记住，这些部分只在本书中可见，因为我们希望它们可见。在真实的应用中，它们只是其他 React Native 组件的分组。但是，如果屏幕右侧的空间成为问题，请尝试调整子组件的边距和宽度。

# 灵活的行和列

在本章的最后一节中，您将学习如何将行和列组合在一起，为应用程序创建复杂的布局。例如，有时您需要能够在行内嵌套列或在列内嵌套行。让我们看看一个应用程序的`App`组件，它在行内嵌套列：

```jsx
import React from 'react';
import { View, StatusBar } from 'react-native';

import styles from './styles';
import Row from './Row';
import Column from './Column';
import Box from './Box';

export default () => (
  <View style={styles.container}>
    <StatusBar hidden={false} />
    {/* This row contains two columns. The first column
        has boxes "#1" and "#2". They will be stacked on
        top of one another. The next column has boxes "#3"
        and "#4", which are also stacked on top of one
        another */}
    <Row>
      <Column>
        <Box>#1</Box>
        <Box>#2</Box>
      </Column>
      <Column>
        <Box>#3</Box>
        <Box>#4</Box>
      </Column>
    </Row>
    <Row>
      <Column>
        <Box>#5</Box>
        <Box>#6</Box>
      </Column>
      <Column>
        <Box>#7</Box>
        <Box>#8</Box>
      </Column>
    </Row>
    <Row>
      <Column>
        <Box>#9</Box>
        <Box>#10</Box>
      </Column>
      <Column>
        <Box>#11</Box>
        <Box>#12</Box>
      </Column>
    </Row>
  </View>
); 
```

你已经为布局部分（`<Row>`和`<Column>`）和内容部分（`<Box>`）创建了抽象。让我们看看这个屏幕是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/6c90900f-bf41-4d07-b50a-802aaf13428c.png)

这个布局可能看起来很熟悉，因为你在本章中已经做过了。关键区别在于这些内容部分的排序方式。例如，#2 不会放在#1 的左侧，而是放在下面。这是因为我们将#1 和#2 放在了`<Column>`中。#3 和#4 也是一样。这两列放在了一行中。然后下一行开始，依此类推。

通过嵌套行 flexbox 和列 flexbox，您可以实现许多可能的布局之一。现在让我们看看`Row`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View } from 'react-native';

import styles from './styles';

// Renders a "View" with the "row" style applied to
// it. It's "children" will flow from left to right.
const Row = ({ children }) => (
  <View style={styles.row}>{children}</View>
);

Row.propTypes = {
  children: PropTypes.node.isRequired
};

export default Row; 
```

这个组件将`<View>`组件应用了`row`样式。最终结果是在创建复杂布局时，`App`组件中的 JSX 标记更清晰。最后，让我们看看`Column`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View } from 'react-native';

import styles from './styles';

// Renders a "View" with the "column" style applied
// to it. It's children will flow from top-to-bottom.
const Column = ({ children }) => (
  <View style={styles.column}>{children}</View>
);

Column.propTypes = {
  children: PropTypes.node.isRequired
};

export default Column; 
```

这看起来就像`Row`组件，只是应用了不同的样式。它也和`Row`有相同的作用 - 为其他组件的布局提供更简单的 JSX 标记。

# 总结

本章向您介绍了 React Native 中的样式。虽然您可以使用许多您习惯的 CSS 样式属性，但在 Web 应用程序中使用的 CSS 样式表看起来非常不同。换句话说，它们由普通的 JavaScript 对象组成。

然后，您学习了如何使用主要的 React Native 布局机制 - flexbox。这是如今布局大多数 Web 应用程序的首选方式，因此能够在原生应用中重用这种方法是有意义的。您创建了几种不同的布局，并看到它们在纵向和横向方向上的外观。

在接下来的章节中，你将开始为你的应用实现导航。

# 测试你的知识

1.  CSS 样式和 React Native 组件使用的样式有什么区别？

1.  React Native 与 CSS 共享许多样式属性。样式属性在 React Native 中以普通对象属性的形式表达

1.  没有区别——你可以像其他 React 组件一样样式化 React Native 组件

1.  它们完全不同——React Native 不与 CSS 共享任何样式属性

1.  为什么在设计布局时需要考虑状态栏？

1.  你不需要考虑状态栏

1.  因为状态栏可能会干扰你的 iOS 组件

1.  因为状态栏可能会干扰你的 Android 组件

1.  什么是弹性盒模型？

1.  它是用于控制 View 组件如何伸缩以占据布局中的水平空间的模型

1.  它提供了灵活的列，可以响应屏幕方向的变化

1.  弹性盒布局模型用于以一种抽象方式布置组件，并在布局变化时自动伸缩

1.  在考虑布局选项时，屏幕方向是否是一个因素？

1.  是的，你总是需要确保在开发过程中，横向或纵向方向没有意外

1.  不，方向细节会被处理，这样你就可以专注于应用功能

# 进一步阅读

点击以下链接获取更多信息：

+   [`facebook.github.io/react-native/docs/flexbox`](https://facebook.github.io/react-native/docs/flexbox)

+   [`facebook.github.io/react-native/docs/statusbar`](https://facebook.github.io/react-native/docs/statusbar)

+   [`facebook.github.io/react-native/docs/stylesheet`](https://facebook.github.io/react-native/docs/stylesheet)


# 第十五章：在屏幕之间导航

本章的重点是在 React Native 应用程序中导航到组成应用程序的屏幕之间。原生应用程序中的导航与 Web 应用程序中的导航略有不同——主要是因为用户没有任何 URL 的概念。在之前的 React Native 版本中，有原始的导航器组件，可以用来控制屏幕之间的导航。这些组件存在一些挑战，导致需要更多的代码来完成基本的导航任务。

最近的 React Native 版本鼓励你使用`react-navigation`包，这将是本章的重点，尽管还有其他几个选项。你将学习导航基础知识，向屏幕传递参数，更改标题内容，使用选项卡和抽屉导航，以及处理导航状态。

# 导航基础知识

让我们从使用`react-navigation`进行从一个页面到另一个页面的基础知识开始。`App`组件的外观如下：

```jsx
import { createStackNavigator } from 'react-navigation';
import Home from './Home';
import Settings from './Settings';

export default createStackNavigator(
  {
    Home,
    Settings
  },
  { initialRouteName: 'Home' }
);
```

`createStackNavigator()`函数是设置导航所需的全部内容。这个函数的第一个参数是一个屏幕组件的映射，可以进行导航。第二个参数是更一般的导航选项——在这种情况下，你告诉导航器`Home`应该是默认的屏幕组件。

`Home`组件的外观如下：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

export default ({ navigation }) => (
  <View style={styles.container}>
    <Text>Home Screen</Text>
    <Button
      title="Settings"
      onPress={() => navigation.navigate('Settings')}
    />
  </View>
);
```

这是您典型的功能性 React 组件。你可以在这里使用基于类的组件，但没有必要，因为没有生命周期方法或状态。它呈现了一个应用了容器样式的`View`组件。接下来是一个标记屏幕的`Text`组件，后面是一个`Button`组件。屏幕可以是任何你想要的东西——它只是一个常规的 React Native 组件。导航器组件为你处理路由和屏幕之间的过渡。

这个按钮的`onPress`处理程序在点击时导航到`Settings`屏幕。这是通过调用`navigation.navigate('Settings')`来实现的。`navigation`属性是由`react-navigation`传递给屏幕组件的，并包含你需要的所有路由功能。与在 React web 应用程序中使用 URL 不同，在这里你调用导航器 API 函数并传递屏幕的名称。

接下来，让我们来看看`Settings`组件：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

export default ({ navigation }) => (
  <View style={styles.container}>
    <Text>Settings Screen</Text>
    <Button
      title="Home"
      onPress={() => navigation.navigate('Home')}
    />
  </View>
);
```

这个组件就像`主页`组件一样，只是文本不同，当点击按钮时，您会被带回到`主页`屏幕。

这就是`主页`屏幕的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5afc73f6-11a8-472b-996b-4cc346c11553.png)

您可以单击**设置**按钮，然后将被带到`设置`屏幕，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7e83075d-2129-490c-b77a-7d0147bd1aee.png)

这个屏幕看起来几乎和`主页`屏幕一样。它有不同的文本和一个不同的按钮，当点击时会带您回到`主页`屏幕。但是，还有另一种方法可以回到`主页`屏幕。看一下屏幕顶部，您会注意到一个白色的导航栏。在导航栏的左侧，有一个返回箭头。这就像 Web 浏览器中的返回按钮一样，会带您回到上一个屏幕。`react-navigation`的好处在于它会为您渲染这个导航栏。

有了这个导航栏，您不必担心布局样式如何影响状态栏。您只需要担心每个屏幕内的布局。

如果您在 Android 上运行此应用程序，您将在导航栏中看到相同的返回按钮。但您也可以使用大多数 Android 设备上应用程序外部找到的标准返回按钮。

# 路由参数

当您开发 React Web 应用程序时，一些路由中有动态数据。例如，您可以链接到一个详情页面，在 URL 中，您会有某种标识符。然后组件就有了渲染特定详细信息所需的内容。相同的概念也存在于`react-navigation`中。您不仅可以指定要导航到的屏幕的名称，还可以传递额外的数据。

让我们看看路由参数的实际应用，从`App`组件开始：

```jsx
import { createStackNavigator } from 'react-navigation';
import Home from './Home';
import Details from './Details';

export default createStackNavigator(
  {
    Home,
    Details
  },
  { initialRouteName: 'Home' }
);
```

这看起来和前面的例子一样，只是没有`设置`页面，而是有一个`详情`页面。这是您想要动态传递数据的页面，以便它可以呈现适当的信息。首先，让我们看看`主页`屏幕组件：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

export default ({ navigation }) => (
  <View style={styles.container}>
    <Text>Home Screen</Text>
    <Button
      title="First Item"
      onPress={() =>
        navigation.navigate('Details', { title: 'First Item' })
      }
    />
    <Button
      title="Second Item"
      onPress={() =>
        navigation.navigate('Details', { title: 'Second Item' })
      }
    />
    <Button
      title="Third Item"
      onPress={() =>
        navigation.navigate('Details', { title: 'Third Item' })
      }
    />
  </View>
);
```

“主页”屏幕有三个`Button`组件，每个都导航到“详情”屏幕。注意`navigation.navigate()`的调用。除了屏幕名称，它们每个都有第二个参数。这些是包含特定数据的对象，这些数据将传递给“详情”屏幕。接下来，让我们看看“详情”屏幕，并了解它如何使用这些路由参数：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

export default ({ navigation }) => (
  <View style={styles.container}>
    <Text>{navigation.getParam('title')}</Text>
  </View>
);
```

尽管此示例只传递了一个参数—`title`—您可以根据需要向屏幕传递尽可能多的参数。您可以使用`navigator.getParam()`函数来查找值来访问这些参数。

渲染时，“主页”屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cb6a4cf6-cf5d-414e-b14f-03ed7cba50eb.png)

如果您点击**第一项**按钮，您将进入使用路由参数数据呈现的详情屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e48783cb-16e4-4ef1-90d5-7b221e56b9dd.png)

在导航栏中，您可以点击返回按钮返回到“主页”屏幕。如果您点击“主页”屏幕上的任何其他按钮，您将被带回到带有更新数据的“详情”屏幕。路由参数是必要的，以避免编写重复的组件。您可以将参数传递给`navigator.navigate()`，就像将 props 传递给 React 组件一样。

# 导航头

到目前为止，在本章中创建的导航栏都有点普通。这是因为您还没有配置它们执行任何操作，所以`react-navigation`只会渲染一个带有返回按钮的普通栏。您创建的每个屏幕组件都可以配置特定的导航头内容。

让我们在之前使用按钮导航到详情页面的示例上进行扩展。`App`组件保持不变，所以让我们先看看`Home`组件：

```jsx
import React from 'react';
import { View, Button } from 'react-native';

import styles from './styles';

const Home = ({ navigation }) => (
  <View style={styles.container}>
    <Button
      title="First Item"
      onPress={() =>
        navigation.navigate('Details', {
          title: 'First Item',
          content: 'First Item Content',
          stock: 1
        })
      }
    />
    <Button
      title="Second Item"
      onPress={() =>
        navigation.navigate('Details', {
          title: 'Second Item',
          content: 'Second Item Content',
          stock: 0
        })
      }
    />
    <Button
      title="Third Item"
      onPress={() =>
        navigation.navigate('Details', {
          title: 'Third Item',
          content: 'Third Item Content',
          stock: 200
        })
      }
    />
  </View>
);

Home.navigationOptions = {
  title: 'Home'
};

export default Home;
```

您将注意到的第一件事是，每个按钮都向“详情”组件传递了更多的路由参数：`content`和`stock`。您马上就会明白为什么。正是`Home.navigationOptions`的值为您配置了导航头。在这种情况下，“主页”屏幕正在设置“标题”。

“主页”屏幕是一个功能性组件，所以您可以将`navigationOptions`设置为函数的属性。如果您的组件是基于类的，因为它具有生命周期方法的状态，您可以将其定义为静态类属性：

`class MyScreen extends Component { static navigationOptions = {...} ... }`

接下来，让我们看看“详情”组件：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

const Details = ({ navigation }) => (
  <View style={styles.container}>
    <Text>{navigation.getParam('content')}</Text>
  </View>
);

Details.navigationOptions = ({ navigation }) => ({
  title: navigation.getParam('title'),
  headerRight: (
    <Button
      title="Buy"
      onPress={() => {}}
      disabled={navigation.getParam('stock') === 0}
    />
  )
});

export default Details;
```

这一次，`Details`组件呈现内容路由参数。像`Home`组件一样，它也有一个`navigationOptions`属性。在这种情况下，它是一个函数，而不是一个对象。这是因为您根据传递给屏幕的参数动态更改导航头内容。该函数传递了一个`navigation`属性 - 这与传递给`Details`组件的值相同。您可以调用`navigation.getParam()`来获取标题，以根据路由参数更改导航头。 

接下来，使用`headerRight`选项将`Button`组件添加到导航栏的右侧。这就是股票参数发挥作用的地方。如果这个值是 0，因为没有任何库存，你想要禁用**购买**按钮。

现在让我们看看所有这些是如何工作的，从“主页”屏幕开始：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f21a99d6-558c-453b-ab3d-d0d302eedd96.png)

导航栏中的标题文本是由“主页”屏幕组件设置的。接下来，尝试点击**第一项**按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3a484181-14ba-4b58-859d-f6131d6b9e5d.png)

导航栏中的标题是根据传递给`Details`组件的`title`参数设置的。导航栏右侧呈现的**购买**按钮也由`Details`组件呈现。它是启用的，因为`stock`参数值为 1。现在尝试返回到“主页”屏幕，并点击**第二项**按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/9228ad78-b384-4c73-8b65-2bd246a2a282.png)

标题和页面内容都反映了传递给`Details`的新参数值。但**购买**按钮也是如此。它处于禁用状态，因为股票参数值为 0，这意味着它无法购买。

# 选项卡和抽屉导航

到目前为止，本章中的每个示例都使用了`Button`组件来链接到应用程序中的其他屏幕。您可以使用`react-navigation`中的函数，根据您提供的屏幕组件自动为您创建选项卡或抽屉导航。

让我们创建一个示例，在 iOS 上使用底部选项卡导航，在 Android 上使用抽屉导航。

您不仅限于在 iOS 上使用选项卡导航或在 Android 上使用抽屉导航。我只是选择这两个来演示如何根据平台使用不同的导航模式。如果您愿意，您可以在两个平台上使用完全相同的导航模式。这是`App`组件的外观：

```jsx
import {
  createBottomTabNavigator,
  createDrawerNavigator
} from 'react-navigation';
import { Platform } from 'react-native';
import Home from './Home';
import News from './News';
import Settings from './Settings';

const { createNavigator } = Platform.select({
  ios: { createNavigator: createBottomTabNavigator },
  android: { createNavigator: createDrawerNavigator }
});

export default createNavigator(
  {
    Home,
    News,
    Settings
  },
  { initialRouteName: 'Home' }
);
```

不要使用`createStackNavigator()`函数来创建你的导航器，而是从`react-navigation`中导入`createBottomTabNavigator()`和`createDrawerNavigator()`函数：

```jsx
import {
  createBottomTabNavigator,
  createDrawerNavigator
} from 'react-navigation';
```

然后，你使用`react-native`中的`Platform`实用程序来决定使用这两个函数中的哪一个。根据平台的不同，结果被分配给`createNavigator()`：

```jsx
const { createNavigator } = Platform.select({
  ios: { createNavigator: createBottomTabNavigator },
  android: { createNavigator: createDrawerNavigator }
});
```

现在你可以调用`createNavigator()`并将其传递给你的屏幕。生成的选项卡或抽屉导航将被创建和渲染给你：

```jsx
export default createNavigator(
  {
    Home,
    News,
    Settings
  },
  { initialRouteName: 'Home' }
);
```

接下来，让我们看一下`Home`屏幕组件：

```jsx
import React from 'react';
import { View, Text } from 'react-native';

import styles from './styles';

const Home = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Home Content</Text>
  </View>
);

Home.navigationOptions = {
  title: 'Home'
};

export default Home;
```

它在导航栏中设置`title`并呈现一些基本内容。`News`和`Settings`组件本质上与`Home`相同。

iOS 上的底部选项卡导航如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/9b570d61-e6ec-48af-9168-3ad8fe4d209e.png)

组成你的应用程序的三个屏幕在底部列出。当前屏幕被标记为活动状态，你可以点击其他选项卡来移动。

现在，让我们看看 Android 上的抽屉布局是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/16c598d2-9a7b-47c4-9ea2-eeacf04e432d.png)

要打开抽屉，你需要从屏幕的左侧滑动。一旦打开，你将看到按钮，可以带你到应用程序的各个屏幕。

从屏幕左侧滑动打开抽屉是默认模式。你可以配置抽屉从任何方向滑动打开。

# 处理状态

React 应用程序具有传递给呈现功能并需要状态数据的组件的状态。例如，想象一下，你正在设计一个使用`react-navigation`的应用程序，不同的屏幕依赖于相同的状态数据。你如何将状态数据传递给这些屏幕组件？它们如何更新应用程序状态？

首先，让我们考虑将应用程序状态放在哪里。最自然的地方是`App`组件。到目前为止，在本章中，示例直接导出了对`createStackNavigator()`的调用。这个函数是一个高阶函数 - 它返回一个新的 React 组件。这意味着你可以在由`createStackNavigator()`返回的导航组件周围包装自己的有状态组件。

为了说明这个想法，让我们重新访问之前的例子，其中你有一个列出导航到`Details`屏幕的项目按钮的`Home`屏幕。下面是新的`App`组件的样子：

```jsx
import React, { Component } from 'react';
import { createStackNavigator } from 'react-navigation';
import Home from './Home';
import Details from './Details';

const Nav = createStackNavigator(
  {
    Home,
    Details
  },
  { initialRouteName: 'Home' }
);

export default class App extends Component {
  state = {
    stock: {
      first: 1,
      second: 0,
      third: 200
    }
  };

  updateStock = id => {
    this.setState(({ stock }) => ({
      stock: {
        ...stock,
        [id]: stock[id] === 0 ? 0 : stock[id] - 1
      }
    }));
  };

  render() {
    const props = {
      ...this.state,
      updateStock: this.updateStock
    };

    return <Nav screenProps={props} />;
  }
}
```

首先，你使用`createStackNavigator()`函数来创建你的导航器组件：

```jsx
const Nav = createStackNavigator(
  {
    Home,
    Details
  },
  { initialRouteName: 'Home' }
);
```

现在您有一个可以渲染的`Nav`组件。接下来，您可以创建一个带有状态的常规 React 组件：

```jsx
export default class App extends Component {
  state = {
    stock: {
      first: 1,
      second: 0,
      third: 200
    }
  };
  ...
}
```

这个组件中使用的状态表示每个物品可供购买的数量。接下来，您有`updateStock()`函数，用于更新给定物品 ID 的库存状态：

```jsx
updateStock = id => {
  this.setState(({ stock }) => ({
    stock: {
      ...stock,
      [id]: stock[id] === 0 ? 0 : stock[id] - 1
    }
  }));
};
```

传递给这个函数的 ID 的库存状态会减少 1，除非已经为 0。当单击物品的“购买”按钮时，可以使用这个函数来检查其库存数量是否减少 1。最后，您有`render()`方法，它可以渲染`Nav`组件：

```jsx
render() {
  const props = {
    ...this.state,
    updateStock: this.updateStock
  };

  return <Nav screenProps={props} />;
}
```

`App`的状态作为 props 传递给`Nav`。还将`updateStock()`函数作为 prop 传递，以便屏幕组件可以使用它。现在让我们来看一下`Home`屏幕：

```jsx
import React from 'react';
import { View, Button } from 'react-native';

import styles from './styles';

const Home = ({ navigation, screenProps: { stock } }) => (
  <View style={styles.container}>
    <Button
      title={`First Item (${stock.first})`}
      onPress={() =>
        navigation.navigate('Details', {
          id: 'first',
          title: 'First Item',
          content: 'First Item Content'
        })
      }
    />
    <Button
      title={`Second Item (${stock.second})`}
      onPress={() =>
        navigation.navigate('Details', {
          id: 'second',
          title: 'Second Item',
          content: 'Second Item Content'
        })
      }
    />
    <Button
      title={`Third Item (${stock.third})`}
      onPress={() =>
        navigation.navigate('Details', {
          id: 'third',
          title: 'Third Item',
          content: 'Third Item Content'
        })
      }
    />
  </View>
);

Home.navigationOptions = {
  title: 'Home'
};

export default Home;
```

再次，您有三个`Button`组件，用于导航到`Details`屏幕并传递路由参数。在这个版本中添加了一个新参数：`id`。每个按钮的标题都反映了给定物品的库存数量。这个值是应用程序状态的一部分，并通过属性传递给屏幕组件。然而，所有这些属性都是通过`screenProps`属性访问的。

**经验法则**：如果将 prop 传递给导航组件，则可以通过`screenProps`属性访问它。如果通过`navigator.navigate()`将值传递给屏幕，则可以通过调用`navigator.getParam()`来访问它。

接下来让我们来看一下`Details`组件：

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';

import styles from './styles';

const Details = ({ navigation }) => (
  <View style={styles.container}>
    <Text>{navigation.getParam('content')}</Text>
  </View>
);

Details.navigationOptions = ({
  navigation,
  screenProps: { stock, updateStock }
}) => {
  const id = navigation.getParam('id');
  const title = navigation.getParam('title');

  return {
    title,
    headerRight: (
      <Button
        title="Buy"
        onPress={() => updateStock(id)}
        disabled={stock[id] === 0}
      />
    )
  };
};

export default Details;
```

`id`和`title`路由参数用于操作导航栏中的内容。`title`参数设置标题。`id`被“Buy”按钮的`onPress`处理程序使用，通过将其传递给`updateStock()`，当按钮被按下时，适当的物品库存数量会更新。`disabled`属性也依赖于`id`参数来查找库存数量。就像`Home`屏幕一样，从`App`组件传递下来的库存和`updateStock()`props 都可以通过 screenProps 应用程序访问。

这是`Home`屏幕在首次渲染时的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e65820bb-e4dd-4577-8eb5-e7c5d5197054.png)

每个物品按钮上的库存数量都反映了一个数字。让我们按下“First Item”按钮并导航到`Details`页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5ecc1b4f-ddf5-4704-9f37-c89bf6490359.png)

导航栏中的**购买**按钮已启用，因为库存数量为 1。让我们继续按下购买按钮，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c3a28b61-dd7d-4742-8ec8-bc4d61924787.png)

按下**购买**按钮后，它变为禁用状态。这是因为该商品的库存值为 1。通过按下**购买**按钮，你调用了`updateStock()`函数，将该值更新为 0。由于状态改变，`App`组件重新渲染了`Nav`组件，进而使用新的属性值重新渲染了你的`Details`屏幕组件。

让我们回到“主页”屏幕，看看由于状态更新而发生了什么变化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/6c5b95b7-850b-41e2-a085-88e42f8546fa.png)

正如预期的那样，**第一项**按钮文本旁边呈现的库存数量为 0，反映了刚刚发生的状态变化。

这个例子表明，你可以让顶层的`App`组件处理应用程序状态，同时将其传递给各个应用程序屏幕，以及发出状态更新的函数。

# 总结

在本章中，你学会了移动 web 应用程序和 web 应用程序一样需要导航。尽管有所不同，但是移动应用程序和 web 应用程序的导航有足够的概念上的相似之处，使得移动应用程序的路由和导航不必成为一个麻烦。

早期版本的 React Native 尝试提供组件来帮助管理移动应用程序中的导航，但这些从未真正生效。相反，React Native 社区主导了这一领域。其中一个例子就是`react-navigation`库，本章的重点。

你学会了如何使用 react-navigation 进行基本导航。然后，你学会了如何控制导航栏中的标题组件。接下来，你学会了选项卡和抽屉导航。这两个导航组件可以根据屏幕组件自动渲染应用的导航按钮。最后，你学会了如何在保持导航的同时，仍然能够从顶层应用向屏幕组件传递状态数据。

在下一章中，你将学习如何渲染数据列表。

# 测试你的知识

1.  在 React web 应用和 React Native 应用中，导航的主要区别是什么？

1.  在导航方面，Web 应用和移动应用之间没有实质性的区别。

1.  Web 应用程序依赖 URL 作为移动的中心概念。原生应用程序没有这样的概念，所以开发人员和他们使用的导航库来管理他们的屏幕。

1.  原生应用代码与 web 应用程序一样使用 URL，但这些 URL 对用户来说是不可见的。

1.  应该使用什么函数来导航到新的屏幕？

1.  屏幕组件会被传递一个导航属性。你应该使用**`navigation.navigate()`**来切换到另一个屏幕。

1.  屏幕组件会自动添加导航方法。

1.  有一个全局导航对象，其中包含可以使用的导航方法。

1.  react-navigation 是否为你处理返回按钮功能？

1.  是的。包括在安卓系统上内置的返回按钮。

1.  不，你必须自己实现所有返回按钮的行为。

1.  你如何将数据传递给屏幕？

1.  你可以将一个普通对象作为**`navigation.navigate()`**的第二个参数。然后可以通过**`navigation.getParam()`**在屏幕上访问这些属性。

1.  你必须重新渲染屏幕组件，将从导航中作为属性获取的参数传递给它。

1.  你不会将数据传递给屏幕。设置应用级别的状态是将数据传递给屏幕组件的唯一方法。

# 进一步阅读

查看以下链接获取更多信息：

+   [`reactnavigation.org/`](https://reactnavigation.org/)


# 第十六章：渲染项目列表

在本章中，你将学习如何处理项目列表。列表是常见的 Web 应用程序组件。虽然使用`<ul>`和`<li>`元素构建列表相对比较简单，但在原生移动平台上做类似的事情要复杂得多。

幸运的是，React Native 提供了一个隐藏所有复杂性的项目列表接口。首先，通过一个例子来了解项目列表的工作原理。然后，学习如何构建改变列表中显示的数据的控件。最后，你将看到一些从网络获取项目的例子。

# 渲染数据集合

让我们从一个例子开始。你将用来渲染列表的 React Native 组件是`FlatList`，它在 iOS 和 Android 上的工作方式相同。列表视图接受一个`data`属性，它是一个对象数组。这些对象可以有任何你喜欢的属性，但它们确实需要一个键属性。这类似于在`<ul>`元素内部渲染`<li>`元素时对键属性的要求。这有助于列表在列表数据发生变化时高效地渲染列表。

现在让我们实现一个基本的列表。以下是渲染基本 100 个项目列表的代码：

```jsx
import React from 'react';
import { Text, View, FlatList } from 'react-native';

import styles from './styles';

const data = new Array(100)
  .fill(null)
  .map((v, i) => ({ key: i.toString(), value: `Item ${i}` }));

export default () => (
  <View style={styles.container}>
    <FlatList
      data={data}
      renderItem={({ item }) => (
        <Text style={styles.item}>{item.value}</Text>
      )}
    />
  </View>
); 
```

让我们从这里开始，首先是`data`常量。这是一个包含 100 个项目的数组。它是通过用 100 个空值填充一个新数组，然后将其映射到一个你想要传递给`<FlatList>`的新数组来创建的。每个对象都有一个键属性，因为这是一个要求。其他任何东西都是可选的。在这种情况下，你决定添加一个值属性，这个值稍后会被使用或在列表被渲染时使用。

接下来，你渲染`<FlatList>`组件。它位于一个`<View>`容器内，因为列表视图需要一个高度才能正确地进行滚动。`data`和`renderItem`属性被传递给`<FlatList>`，最终确定了渲染的内容。

乍一看，似乎`FlatList`组件并没有做太多事情。你必须弄清楚项目的外观？是的，`FlatList`组件应该是通用的。它应该擅长处理更新，并为我们嵌入滚动功能到列表中。以下是用于渲染列表的样式：

```jsx
import { StyleSheet } from 'react-native';

export default StyleSheet.create({
  container: {
    // Flexing from top to bottom gives the
    // container a height, which is necessary
    // to enable scrollable content.
    flex: 1,
    flexDirection: 'column',
    paddingTop: 20,
  },

  item: {
    margin: 5,
    padding: 5,
    color: 'slategrey',
    backgroundColor: 'ghostwhite',
    textAlign: 'center',
  },
}); 
```

在这里，你正在为列表中的每个项目设置样式。否则，每个项目将只是文本，并且很难区分其他列表项目。`container`样式通过将`flexDirection`设置为`column`来给列表设置高度。没有高度，你将无法正确滚动。

现在让我们看看这个东西现在是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b1df327b-1ba5-44b7-9a53-88ed9cc2b210.png)

如果你在模拟器中运行这个例子，你可以点击并按住鼠标按钮在屏幕的任何地方，就像手指一样，然后通过项目上下滚动。

# 对列表进行排序和过滤

现在你已经学会了`FlatList`组件的基础知识，包括如何向它们传递数据，让我们在之前实现的列表中添加一些控件。`FlatList`组件帮助你为列表控件渲染固定位置的内容。你还将看到如何操作数据源，最终驱动屏幕上的渲染内容。

在实现列表控件组件之前，可能有必要回顾一下这些组件的高层结构，以便代码有更多的上下文。以下是你将要实现的组件结构的示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5b76e388-d516-49b1-8f18-0caa854e062e.png)

这些组件各自负责什么：

+   `ListContainer`: 列表的整体容器；它遵循熟悉的 React 容器模式

+   `List`: 一个无状态组件，将相关的状态片段传递给`ListControls`和 React Native 的`ListView`组件

+   `ListControls`: 一个包含改变列表状态的各种控件的组件

+   `ListFilter`: 用于过滤项目列表的控件

+   `ListSort`: 用于改变列表排序顺序的控件

+   `FlatList`: 实际的 React Native 组件，用于渲染项目

在某些情况下，像这样拆分列表的实现可能有些过度。然而，我认为如果你的列表需要控件，你可能正在实现一些将受益于有一个经过深思熟虑的组件架构的东西。

现在，让我们深入到这个列表的实现中，从`ListContainer`组件开始：

```jsx
import React, { Component } from 'react';

import List from './List';

const mapItems = items =>
  items.map((value, i) => ({ key: i.toString(), value }));

// Performs sorting and filtering on the given "data".
const filterAndSort = (data, text, asc) =>
  data
    .filter(
      i =>
        // Items that include the filter "text" are returned.
        // Unless the "text" argument is an empty string,
        // then everything is included.
        text.length === 0 || i.includes(text)
    )
    .sort(
      // Sorts either ascending or descending based on "asc".
      asc
        ? (a, b) => (b > a ? -1 : a === b ? 0 : 1)
        : (a, b) => (a > b ? -1 : a === b ? 0 : 1)
    );

class ListContainer extends Component {
  state = {
    data: filterAndSort(
      new Array(100).fill(null).map((v, i) => `Item ${i}`),
      '',
      true
    ),
    asc: true,
    filter: ''
  };

  render() {
    return (
      <List
        data={mapItems(this.state.data)}
        asc={this.state.asc}
        onFilter={text => {
          // Updates the "filter" state, the actualy filter text,
          // and the "source" of the list. The "data" state is
          // never actually touched - "filterAndSort()" doesn't
          // mutate anything.
          this.setState({
            filter: text,
            data: filterAndSort(this.state.data, text, this.state.asc)
          });
        }}
        onSort={() => {
          this.setState({
            // Updates the "asc" state in order to change the
            // order of the list. The same principles as used
            // in the "onFilter()" handler are applied here,
            // only with diferent arguments passed to
            // "filterAndSort()"
            asc: !this.state.asc,
            data: filterAndSort(
              this.state.data,
              this.state.filter,
              !this.state.asc
            )
          });
        }}
      />
    );
  }
}

export default ListContainer;

```

如果这看起来有点多，那是因为确实如此。这个容器组件有很多状态需要处理。它还有一些需要提供给其子组件的非平凡行为。如果从封装状态的角度来看，它会更容易理解。它的工作是使用状态数据填充列表并提供操作此状态的函数。

在理想的情况下，此容器的子组件应该很简单，因为它们不必直接与状态进行交互。让我们接下来看一下`List`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Text, FlatList } from 'react-native';

import styles from './styles';
import ListControls from './ListControls';

const List = ({ Controls, data, onFilter, onSort, asc }) => (
  <FlatList
    data={data}
    ListHeaderComponent={<Controls {...{ onFilter, onSort, asc }} />}
    renderItem={({ item }) => (
      <Text style={styles.item}>{item.value}</Text>
    )}
  />
);

List.propTypes = {
  Controls: PropTypes.func.isRequired,
  data: PropTypes.array.isRequired,
  onFilter: PropTypes.func.isRequired,
  onSort: PropTypes.func.isRequired,
  asc: PropTypes.bool.isRequired
};

List.defaultProps = {
  Controls: ListControls
};

export default List; 
```

此组件将`ListContainer`组件的状态作为属性，并呈现`FlatList`组件。相对于之前的示例，这里的主要区别是`ListHeaderComponent`属性。这会呈现列表的控件。这个属性特别有用的地方在于它在可滚动的列表内容之外呈现控件，确保控件始终可见。

还要注意，您正在将自己的`ListControls`组件指定为`controls`属性的默认值。这样可以方便其他人传入自己的列表控件。接下来让我们看一下`ListControls`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View } from 'react-native';

import styles from './styles';
import ListFilter from './ListFilter';
import ListSort from './ListSort';

// Renders the "<ListFilter>" and "<ListSort>"
// components within a "<View>". The
// "styles.controls" style lays out the controls
// horizontally.
const ListControls = ({ onFilter, onSort, asc }) => (
  <View style={styles.controls}>
    <ListFilter onFilter={onFilter} />
    <ListSort onSort={onSort} asc={asc} />
  </View>
);

ListControls.propTypes = {
  onFilter: PropTypes.func.isRequired,
  onSort: PropTypes.func.isRequired,
  asc: PropTypes.bool.isRequired
};

export default ListControls; 
```

此组件将`ListFilter`和`ListSort`控件组合在一起。因此，如果要添加另一个列表控件，可以在此处添加。现在让我们来看一下`ListFilter`的实现：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, TextInput } from 'react-native';

import styles from './styles';

// Renders a "<TextInput>" component which allows the
// user to type in their filter text. This causes
// the "onFilter()" event handler to be called.
// This handler comes from "ListContainer" and changes
// the state of the list data source.
const ListFilter = ({ onFilter }) => (
  <View>
    <TextInput
      autoFocus
      placeholder="Search"
      style={styles.filter}
      onChangeText={onFilter}
    />
  </View>
);

ListFilter.propTypes = {
  onFilter: PropTypes.func.isRequired
};

export default ListFilter; 
```

过滤控件是一个简单的文本输入，当用户输入时过滤项目列表。处理此操作的`onChange`函数来自`ListContainer`组件。

接下来让我们看一下`ListSort`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Text } from 'react-native';

// The arrows to render based on the state of
// the "asc" property. Using a Map let's us
// stay declarative, rather than introducing
// logic into the JSX.
const arrows = new Map([[true, '▼'], [false, '▲']]);

// Renders the arrow text. When clicked, the
// "onSort()" function that's passed down from
// the container.
const ListSort = ({ onSort, asc }) => (
  <Text onPress={onSort}>{arrows.get(asc)}</Text>
);

ListSort.propTypes = {
  onSort: PropTypes.func.isRequired,
  asc: PropTypes.bool.isRequired
};

export default ListSort; 
```

以下是生成的列表的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cacc3fa3-ede7-43c6-b429-fb47d99b6a1c.png)

默认情况下，整个列表按升序排列。当用户尚未提供任何内容时，您可以看到占位文本**搜索**。让我们看看当您输入过滤器并更改排序顺序时的效果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/77ef4539-1c12-42fc-a461-30ca2672cb62.png)

此搜索包括其中包含 1 的项目，并按降序排序结果。请注意，您可以先更改顺序，也可以先输入过滤器。过滤器和排序顺序都是`ListContainer`状态的一部分。

# 获取列表数据

通常，你会从某个 API 端点获取列表数据。在本节中，你将学习如何从 React Native 组件中发出 API 请求。好消息是，`fetch()` API 在 React Native 中是由 React Native 进行了填充，因此你的移动应用程序中的网络代码应该看起来和感觉上很像在 Web 应用程序中一样。

首先，让我们使用返回 promise 的函数构建一个模拟 API 来处理我们的列表项，就像`fetch()`一样。

```jsx
import fetchMock from 'fetch-mock';
import querystring from 'querystring';

// A mock item list...
const items = new Array(100).fill(null).map((v, i) => `Item ${i}`);

// The same filter and sort functionality
// as the previous example, only it's part of the
// API now, instead of part of the React component.
const filterAndSort = (data, text, asc) =>
  data
    .filter(i => text.length === 0 || i.includes(text))
    .sort(
      asc
        ? (a, b) => (b > a ? -1 : a === b ? 0 : 1)
        : (a, b) => (a > b ? -1 : a === b ? 0 : 1)
    );

export const fetchItems = (filter, asc) =>
  new Promise(resolve => {
    resolve({
      json: () =>
        Promise.resolve({
          items: filterAndSort(items, filter, asc)
        })
    });
  }); 
```

有了模拟 API 函数，让我们对列表容器组件进行一些更改。现在可以使用`fetchItems()`函数从 API 模拟中加载数据，而不是使用本地数据源：

```jsx
import React, { Component } from 'react';

import { fetchItems } from './api';
import List from './List';

const mapItems = items =>
  items.map((value, i) => ({ key: i.toString(), value }));

class ListContainer extends Component {
  // The "source" state is empty because we need
  // to fetch the data from the API.
  state = {
    asc: true,
    filter: '',
    data: []
  };

  // When the component is first mounted, fetch the initial
  // items from the API, then
  componentDidMount() {
    fetchItems(this.state.filter, this.state.asc)
      .then(resp => resp.json())
      .then(({ items }) => {
        this.setState({ data: mapItems(items) });
      });
  }

  render() {
    return (
      <List
        data={this.state.data}
        asc={this.state.asc}
        onFilter={text => {
          // Makes an API call when the filter changes...
          fetchItems(text, this.state.asc)
            .then(resp => resp.json())
            .then(({ items }) =>
              this.setState({
                filter: text,
                data: mapItems(items)
              })
            );
        }}
        onSort={() => {
          // Makes an API call when the sort order changes...
          fetchItems(this.state.filter, !this.state.asc)
            .then(resp => resp.json())
            .then(({ items }) =>
              this.setState({
                asc: !this.state.asc,
                data: mapItems(items)
              })
            );
        }}
      />
    );
  }
}

export default ListContainer; 
```

任何修改列表状态的操作都需要调用`fetchItems()`，并在 promise 解析后设置适当的状态。

# 懒加载列表

在本节中，你将实现一种不同类型的列表，即无限滚动的列表。有时，用户实际上并不知道他们在寻找什么，因此过滤或排序是没有帮助的。想想当你登录你的 Facebook 账户时看到的新闻动态；这是应用程序的主要功能，很少有你在寻找特定的东西。你需要通过滚动列表来看看发生了什么。

要使用`FlatList`组件实现这一点，需要在用户滚动到列表末尾时能够获取更多的 API 数据。为了了解这是如何工作的，你需要大量的 API 数据来进行操作。生成器非常适合这个！所以让我们修改你在上一个示例中创建的模拟，使其只是不断地响应新数据：

```jsx
// Items...keep'em coming!
function* genItems() {
  let cnt = 0;

  while (true) {
    yield `Item ${cnt++}`;
  }
}

const items = genItems();

export const fetchItems = () =>
  Promise.resolve({
    json: () =>
      Promise.resolve({
        items: new Array(20).fill(null).map(() => items.next().value)
      })
  }); 
```

有了这个，现在你可以在列表末尾到达时每次发出 API 请求获取新数据。嗯，最终当内存用尽时这将失败，但我只是想以一般的术语向你展示你可以采取的方法来在 React Native 中实现无限滚动。`ListContainer`组件如下所示：

```jsx
import React, { Component } from 'react';

import * as api from './api';
import List from './List';

class ListContainer extends Component {
  state = {
    data: [],
    asc: true,
    filter: ''
  };

  fetchItems = () =>
    api
      .fetchItems()
      .then(resp => resp.json())
      .then(({ items }) =>
        this.setState(state => ({
          data: [...state.data, ...items.map((value, i) => ({
            key: i.toString(),
            value
          }))]
        })
      );

  // Fetches the first batch of items once the
  // component is mounted.
  componentDidMount() {
    this.fetchItems();
  }

  render() {
    return (
      <List data={this.state.data} fetchItems={this.fetchItems} />
    );
  }
}

export default ListContainer; 
```

每次调用`fetchItems()`时，响应都会与`data`数组连接起来。这将成为新的列表数据源，而不是像之前的示例中那样替换它。现在，让我们看看`List`组件如何响应到达列表末尾：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Text, FlatList } from 'react-native';

import styles from './styles';

// Renders a "<FlatList>" component, and
// calls "fetchItems()" and the user scrolls
// to the end of the list.
const List = ({ data, fetchItems }) => (
  <FlatList
    data={data}
    renderItem={({ item }) => (
      <Text style={styles.item}>{item.value}</Text>
    )}
    onEndReached={fetchItems}
  />
);

List.propTypes = {
  data: PropTypes.array.isRequired,
  fetchItems: PropTypes.func.isRequired
};

export default List; 
```

如果你运行这个示例，你会发现当你滚动到屏幕底部时，列表会不断增长。

# 总结

在本章中，您了解了 React Native 中的`FlatList`组件。该组件是通用的，因为它不会对呈现的项目施加任何特定的外观。相反，列表的外观取决于您，而`FlatList`组件有助于高效地呈现数据源。`FlatList`组件还为其呈现的项目提供了可滚动的区域。

您实现了一个利用列表视图中的部分标题的示例。这是呈现静态内容（如列表控件）的好地方。然后，您了解了在 React Native 中进行网络调用；这就像在任何其他 Web 应用程序中使用`fetch()`一样。最后，您实现了无限滚动的懒加载列表，只有在滚动到已呈现内容的底部后才加载新项目。

在下一章中，您将学习如何显示诸如网络调用之类的进度。

# 测试你的知识

1.  `FlatList`组件可以呈现什么类型的数据？

1.  `FlatList`期望一个对象数组。`renderItem`属性接受一个负责呈现每个项目的函数。

1.  `FlatList`期望一个对象。

1.  它期望一个返回可迭代对象的函数。

1.  为什么`key`属性是传递给`FlatList`的每个数据项的要求？

1.  这不是一个要求。

1.  这样列表就知道如何对数据值进行排序。

1.  这样列表就可以进行高效的相等性检查，有助于在列表数据更新期间提高渲染性能。

1.  如何在滚动期间保持固定位置的列表控件呈现？

1.  通过将自定义控件组件作为`FlatList`的子组件。

1.  您可以使用`FlatList`的`ListHeaderComponent`属性。

1.  您不能拥有静态定位的列表控件。

1.  当用户滚动列表时，如何懒加载更多数据？

1.  您可以为`FlatList`的`onEndReached`属性提供一个函数。当用户接近列表的末尾时，将调用此函数，并且该函数可以使用更多数据填充列表数据。

1.  您必须扩展`FlatList`类并响应滚动事件，以确定列表的末尾是否已经到达。

# 进一步阅读

点击以下链接了解更多信息：

+   [`facebook.github.io/react-native/docs/flatlist`](https://facebook.github.io/react-native/docs/flatlist)
