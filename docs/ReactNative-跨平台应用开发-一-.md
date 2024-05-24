# ReactNative 跨平台应用开发（一）

> 原文：[`zh.annas-archive.org/md5/6A2675D80E0FE70F7D8BA886F2160D60`](https://zh.annas-archive.org/md5/6A2675D80E0FE70F7D8BA886F2160D60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

React Native 帮助 Web 和移动开发人员构建性能与任何其他原生开发应用程序相同的跨平台应用程序。使用这个库可以构建的应用程序范围很广。从电子商务到游戏，由于其灵活性和可扩展性，React Native 非常适合任何移动项目。毫无疑问，React Native 不仅是原生开发的一个很好的替代方案，而且也是将 Web 开发人员引入移动项目的一个很好的方式。

# 对我有什么好处？

地图对于您的旅程至关重要，特别是当您在另一个大陆度假时。在学习时，路线图可以帮助您确定前进目标的明确路径。因此，在开始旅程之前，我们为您提供了一份路线图。

本书经过精心设计和开发，旨在为您提供有关 React Native 的所有正确和相关信息。我们为您创建了这个学习路径，其中包括四堂课。

第 1 课，项目 1 - 汽车预订应用程序，解释了如何使用 React Native 开发一些最受欢迎的共享汽车应用程序。

第 2 课，项目 2 - 图像分享应用，教你如何使用 React Native 创建基于图像分享的社交网络的基础知识。

第 3 课，项目 3 - 消息应用程序，向您展示如何构建一个包括推送通知和基于云的存储的功能齐全的消息应用程序。

第 4 课，项目 4 - 游戏，向您展示了如何使用 React Native 开发 2D 游戏的基础知识。

# 我将从这本书中得到什么？

+   构建 React Native 项目以便于维护和扩展

+   优化项目以加快开发速度

+   使用外部模块加快项目的开发和维护

+   探索用于 iOS 和 Android 的不同 UI 和代码模式

+   了解在 React Native 中构建应用程序时的最佳实践

# 先决条件

本书适用于希望使用 React Native 构建令人惊叹的跨平台应用程序的开发人员。在开始阅读本书之前，需要具备以下一些先决条件：

+   需要基本的 HTML、CSS 和 JavaScript 知识

+   假设有 React 的先前工作知识


# 第一章：项目 1 - 汽车预订应用程序

考虑到 React 框架的成功，Facebook 最近推出了一个名为 React Native 的新移动开发框架。通过 React Native 对混合移动开发的颠覆性方法，您可以使用 JavaScript 构建更强大、更交互式、更快速的本机移动应用程序。

在本课程中，我们将把重点放在功能开发上，而不是构建用户界面，通过将我们应用程序的样式委托给原生库，如 native-base，并花更多时间构建自定义 UI 组件和屏幕。

我们要构建的应用是一个汽车预订应用程序，用户可以选择想要被接送的位置以及想要预订的车辆类型。由于我们想要专注于用户界面，我们的应用程序只会有两个屏幕，并且需要一些状态管理。相反，我们将更深入地研究诸如动画、组件布局、使用自定义字体或显示外部图像等方面。

该应用程序将适用于 iOS 和 Android 设备，由于所有用户界面都将是定制的，因此在两个平台之间将重复使用 100%的代码。我们将只使用两个外部库：

+   `React-native-geocoder`：这将把坐标转换成人类可读的位置

+   `React-native-maps`：这将轻松显示地图和显示可预订汽车位置的标记

由于其性质，大多数汽车预订应用程序将其复杂性放在后端代码中，以有效地连接司机和乘客。我们将跳过这种复杂性，并在应用程序中模拟所有这些功能，以便专注于构建美观和可用的界面。

# 概览

在构建移动应用程序时，我们需要确保将界面复杂性降至最低，因为在打开应用程序后强制向用户呈现侵入式手册或工具提示通常是不利的。让我们的应用程序自解释是一个好习惯，这样用户就可以通过浏览应用程序屏幕来理解使用方法。这就是为什么使用标准组件，如抽屉菜单或标准列表，总是一个好主意，但并非总是可能的（就像我们当前的应用程序一样），因为我们想要向用户呈现的数据类型。

在我们的情况下，我们将所有功能放在主屏幕和一个模态框中。让我们看看 iOS 设备上的应用程序将会是什么样子：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_01.jpg)

我们主屏幕的背景是地图组件本身，在地图中我们将显示所有可用的汽车作为标记。在地图上，我们将显示三个组件：

+   显示所选取的取货地点的取货地点框

+   位置图钉，可以在地图上拖动以选择新位置

+   用户想要预订的汽车类型选择器。我们将显示三个选项：`经济`，`特别` 和 `高级`

由于大多数组件都是自定义构建的，这个屏幕在任何 Android 设备上看起来都会非常相似：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_02.jpg)

iOS 版本和 Android 版本之间的主要区别将是地图组件。虽然 iOS 将默认使用 Apple 地图，但 Android 使用 Google 地图。我们将保留这个设置，因为每个平台都有自己优化的地图组件，但知道我们可以通过配置我们的组件来切换 iOS 版本以使用 Google 地图是很好的。

一旦用户选择了取货地点，我们将显示一个模态框来确认预订并联系最近的司机取货：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_03.jpg)

与主屏幕一样，这个屏幕也使用了自定义组件：我们甚至决定创建自己的动画活动指示器。因此，Android 版本看起来会非常相似：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_04.jpg)

由于我们的应用程序不会连接到任何外部 API，它应该被视为 React Native 的视觉能力的纯粹展示，尽管通过添加状态管理库和匹配的 API 可以很容易地进行扩展。

让我们来看看本课程的主题：

+   在我们的应用程序中使用地图

+   React Native 中的样式表

+   React Native 中的 Flexbox

+   在 React Native 应用程序中使用外部图像

+   添加自定义字体

+   React Native 中的动画

+   使用模态框

+   使用阴影和不透明度

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将被命名为 `carBooking`，并将可用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.49.3" carBooking
```

在这个应用程序中，只有一个屏幕，因此代码的文件夹结构应该非常简单。由于我们将使用外部图像和字体，我们将这些资源组织在两个单独的文件夹中：`img` 和 `fonts`，都在根文件夹下。

用于构建此应用程序的图像和字体可以从一些图像和字体库网站免费下载。我们将使用的字体名称是 **Blair ITC**。

我们还将以下图像存储在 `img` 文件夹中：

+   `car.png`：一辆汽车的简单图画，代表地图上可预订的汽车。

+   `class.png`：汽车的轮廓，显示在类别选择按钮内部

+   `classBar.png`：类别选择按钮将滑动以更改类别的条形。

+   `loading.png`：我们自定义的旋转器。它将被存储为静态图像，并通过代码进行动画处理。

最后，让我们来看看我们的`package.json`文件：

```jsx
{
    "name": "carBooking",
    "version": "0.0.1",
    "private": true,
    "scripts": {
        "start": "node node_modules/react-native/local-cli/cli.js start",
        "test": "jest"
    },
    "dependencies": {
        "react": "16.0.0-beta.5",
        "react-native": "0.49.3",
"react-native-geocoder": " 0.4.8",
        "react-native-maps": " 0.15.2"
    },
    "devDependencies": {
        "babel-jest": "20.0.3",
        "babel-preset-react-native": "1.9.2",
        "jest": "20.0.4",
        "react-test-renderer": "16.0.0-alpha.6"
    },
    "jest": {
        "preset": "react-native"
    },
 "rnpm": {
        "assets": ["./fonts"]
    }
}
```

我们只使用两个 npm 模块：

+   `react-native-geocoder`：这将坐标转换为人类可读的位置

+   `react-native-maps`：这很容易显示地图和显示可预订汽车位置的标记

为了允许应用程序使用自定义字体，我们需要确保它们可以从本地端访问。为此，我们需要向`package.json`添加一个名为`rnpm`的新键。这个键将存储一个`assets`数组，在其中我们将定义我们的`fonts`文件夹。在构建时，React Native 将把字体复制到一个位置，从那里它们将在本地可用，因此可以在我们的代码中使用。这仅适用于字体和一些特殊资源，而不适用于图像。

## 由 React Native 的 CLI 创建的文件和文件夹

让我们利用这个应用程序中简单的文件夹结构的机会，展示通过`react-native init <projectName>`初始化项目时，React Native 的 CLI 创建了哪些其他文件和文件夹。

### __tests__/

React Native 的 CLI 包括 Jest 作为开发人员依赖项，并且为了开始测试，它包括一个名为`__tests__`的文件夹，其中可以存储所有测试。默认情况下，React Native 的 CLI 添加一个测试文件：`index.js`，代表初始一组测试。开发人员可以为应用程序中的任何组件添加后续测试。React Native 还在我们的`package.json`中添加了一个`test`脚本，因此我们可以从一开始就运行`npm run test`。

Jest 已准备好与通过 CLI 初始化的每个项目一起使用，当涉及到测试 React 组件时，它绝对是最简单的选择，尽管也可以使用其他库，如 Jasmine 或 Mocha。

### android/ 和 ios/

这两个文件夹分别为两个平台本地构建的应用程序。这意味着我们可以在这里找到我们的`.xcodeproj`和`java`文件。每当我们需要对应用程序的本地代码进行更改时，我们都需要修改这两个目录中的一些文件。

在这些文件夹中查找和修改文件的最常见原因是：

+   通过更改`Info.plist`（iOS）或`AndroidManifest.xml`（Android）修改权限（推送通知，访问位置服务，访问指南针等）。

+   更改任何平台的构建设置

+   为原生库添加 API 密钥

+   添加或修改要从我们的 React Native 代码中使用的原生库

### node_modules/

这个文件夹对大多数使用`npm`的 JavaScript 开发人员来说应该很熟悉，因为它是`npm`存储在我们项目中标记为依赖项的所有模块的地方。在这个文件夹内修改任何内容的必要性并不常见，因为一切都应该通过 npm 的 CLI 和我们的`package.json`文件来处理。 

### 根文件夹中的文件

React Native 的 CLI 在项目的根目录中创建了许多文件；让我们来看看最重要的文件：

+   `.babelrc`：Babel 是 React Native 中用于编译包含 JSX 和 ES6（例如，语法转换为大多数 JavaScript 引擎能够理解的纯 JavaScript）的默认库。在这里，我们可以修改这个编译器的配置，例如，可以使用`@`语法作为装饰器，就像在 React 的早期版本中所做的那样。

+   `.buckconfig`：Buck 是 Facebook 使用的构建系统。这个文件用于配置使用 Buck 时的构建过程。

+   `.watchmanconfig`：Watchman 是一个监视项目中文件的服务，以便在文件发生更改时触发重新构建。在这个文件中，我们可以添加一些配置选项，比如应该被忽略的目录。

+   `app.json`：这个文件被`react-native eject`命令用来配置原生应用程序。它存储了在每个平台上标识应用程序的名称，以及在设备的主屏幕上安装应用程序时将显示的名称。

+   `yarn.lock`：`package.json`文件描述了原始作者期望的版本，而`yarn.lock`描述了给定应用程序的最后已知良好配置。

## react-native link

一些应用程序依赖具有原生功能的库，在 React Native CLI 之前，开发人员需要将原生库文件复制到原生项目中。这是一个繁琐和重复的项目，直到`react-native link`出现才得以解决。在这节课中，我们将使用它来从`react-native-maps`复制库文件，并将自定义字体从我们的`/fonts`文件夹链接到编译后的应用程序。

通过在项目的根文件夹中运行`react-native link`，我们将触发链接步骤，这将使那些原生能力和资源可以从我们的 React Native 代码中访问。

# 在模拟器中运行应用程序

在`package.json`文件中具有依赖项和所有初始文件就位后，我们可以运行以下命令（在项目的根文件夹中）完成安装：

```jsx
**npm install**

```

然后，所有依赖项都应该安装在我们的项目中。一旦 npm 完成安装所有依赖项，我们就可以在 iOS 模拟器中启动我们的应用程序：

```jsx
**react-native run-ios**

```

或者在 Android 模拟器中使用以下命令：

```jsx
**react-native run-android**

```

当 React Native 检测到应用程序在模拟器中运行时，它会启用一个隐藏菜单中可用的开发人员工具集，可以通过快捷键*command* + *D*（在 iOS 上）或*command* + *M*（在 Android 上）来访问（在 Windows 上应使用*Ctrl*而不是*command*）。这是 iOS 中开发人员菜单的外观：

在模拟器中运行应用程序

这是在 Android 模拟器中的外观：

![在模拟器中运行应用程序](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_07.jpg)

## 开发人员菜单

在构建 React Native 应用程序的过程中，开发人员将有调试需求。React Native 通过在 Chrome 开发人员工具或外部应用程序（如 React Native Debugger）中远程调试我们的应用程序来满足这些需求。错误、日志甚至 React 组件都可以像在普通 Web 环境中一样轻松调试。

除此之外，React Native 还提供了一种在每次更改时自动重新加载我们的应用程序的方式，从而节省了开发人员手动重新加载应用程序的任务（可以通过按*command* + *R*或*Ctrl* + *R*来实现）。当我们设置我们的应用程序进行自动重新加载时，有两个选项。

+   实时重新加载检测到我们在应用程序代码中所做的任何更改，并在重新加载后将应用程序重置为其初始状态。

+   热重新加载还会检测更改并重新加载应用程序，但会保持应用程序的当前状态。当我们正在实现用户流程以节省开发人员重复每个步骤（例如登录或注册测试用户）时，这非常有用。

+   最后，我们可以启动性能监视器来检测在执行复杂操作（例如动画或数学计算）时可能出现的性能问题。

# 创建我们应用程序的入口点

让我们通过创建我们应用的入口点 `index.js` 来开始我们的应用代码。我们在这个文件中导入 `src/main.js`，以便为我们的代码库使用一个共同的根组件。此外，我们将使用名称 `carBooking` 注册应用程序：

```jsx
/*** index.js ***/

import { AppRegistry } from 'react-native';
import App from './src/main';
AppRegistry.registerComponent('carBooking', () => App);
```

让我们通过添加地图组件来开始构建我们的 `src/main.js`：

```jsx
/*** src/main.js ** */

import React from 'react';
import { View, StyleSheet } from 'react-native';
import MapView from 'react-native-maps';

export default class Main extends React.Component {
  constructor(props) {
    super(props);
    this.initialRegion = {
      latitude: 37.78825,
      longitude: -122.4324,
      latitudeDelta: 0.00922,
      longitudeDelta: 0.00421,
    };
  }

  render() {
    return (
      <View style={{ flex: 1 }}>
        <MapView
          style={styles.fullScreenMap}
          initialRegion={this.initialRegion}
        />
      </View>
    );
  }
}

const styles = StyleSheet.create({
fullScreenMap: {
    position: 'absolute',
    top: 0,
    bottom: 0,
    left: 0,
    right: 0,
  },
});
```

我们将使用 `StyleSheet` 来创建自己的样式，而不是使用样式库，`StyleSheet` 是一个 React Native API，类似于 CSS 样式表的抽象。使用 `StyleSheet`，我们可以通过对象（通过 `create` 方法）创建样式表，然后在组件中通过引用每个样式的 ID 来使用它们。

这样，我们可以重用样式代码，并通过使用有意义的名称来引用每个样式（例如，`<Text style={styles.title}>Title 1</Text>`）使代码更易读。

在这一点上，我们只会创建一个由键 `fullScreenMap` 引用的样式，并通过将 `top`、`bottom`、`left` 和 `right` 坐标添加到零来使其成为绝对位置，覆盖全屏大小。除此之外，我们需要为容器视图添加一些样式，以确保它填满整个屏幕：`{flex: 1}`。将 `flex` 设置为 `1`，我们希望我们的视图填满其父级占用的所有空间。由于这是主视图，`{flex: 1}` 将占据整个屏幕。

对于我们的地图组件，我们将使用 `react-native-maps`，这是由 Airbnb 创建的一个开放模块，使用原生地图功能支持 Google 和 Apple 地图。`react-native-maps` 是一个非常灵活的模块，维护得非常好，并且功能齐全，因此它已经成为 React Native 的事实地图模块。正如我们将在本课程的后面看到的那样，`react-native-maps` 需要开发人员运行 `react-native link` 才能正常工作。

除了样式之外，`<MapView/>` 组件将以 `initialRegion` 作为属性，将地图居中在一组特定的坐标上，这些坐标应该是用户的当前位置。出于一致性的原因，我们将把地图的中心定位在旧金山，在那里我们还将放置一些可预订的汽车。

```jsx
/** * src/main.js ** */

import React from 'react';
import { View, Animated, Image, StyleSheet } from 'react-native';
import MapView from 'react-native-maps';

export default class Main extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
carLocations: [
        {
          rotation: 78,
          latitude: 37.78725,
          longitude: -122.4318,
        },
        {
          rotation: -10,
          latitude: 37.79015,
          longitude: -122.4318,
        },
        {
          rotation: 262,
          latitude: 37.78525,
          longitude: -122.4348,
        },
      ],
    };
    this.initialRegion = {
      latitude: 37.78825,
      longitude: -122.4324,
      latitudeDelta: 0.00922,
      longitudeDelta: 0.00421,
    };
  }

  render() {
    return (
      <View style={{ flex: 1 }}>
        <MapView
          style={styles.fullScreenMap}
          initialRegion={this.initialRegion}
        >
          {this.state.carLocations.map((carLocation, i) => (
            <MapView.Marker key={i} coordinate={carLocation}>
              <Animated.Image
                style={{
                  transform: [{ rotate: `${carLocation.rotation}deg` }],
                }}
                source={require('../img/car.png')}
              />
            </MapView.Marker>
          ))}
        </MapView>
      </View>
    );
  }
}

...
```

我们已经添加了一个`carLocations`数组，以在地图上显示为标记。在我们的`render`函数中，我们将遍历这个数组，并将相应的`<MapView.Marker/>`放置在提供的坐标中。在每个标记内，我们将添加车辆的图像，并通过特定角度旋转它，以匹配街道方向。旋转图像必须使用`Animated` API 完成，这将在本课程的后面更好地解释。

让我们在我们的状态中添加一个新属性，用于存储地图中心位置的可读位置：

```jsx
/** * src/main.js ** */

import GeoCoder from 'react-native-geocoder';

export default class Main extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      position: null,

      ...

    };

    ...

  }

_onRegionChange(region) {
    this.setState({ position: null });
    const self = this;
    if (this.timeoutId) clearTimeout(this.timeoutId);
    this.timeoutId = setTimeout(async () => {
      try {
        const res = await GeoCoder.geocodePosition({
          lat: region.latitude,
          lng: region.longitude,
        });
        self.setState({ position: res[0] });
      } catch (err) {
        console.log(err);
      }
    }, 2000);
  }
componentDidMount() {
    this._onRegionChange.call(this, this.initialRegion);
  }

  render() {
    <View style={{ flex: 1 }}>
      <MapView
        style={styles.fullScreenMap}
        initialRegion={this.initialRegion}
onRegionChange={this._onRegionChange.bind(this)}
      >

      ...

      </MapView>
    </View>;
  }
}

...
```

为了填充这个状态变量，我们还创建了一个`_onRegionChange`函数，它使用`react-native-geocoder`模块。该模块使用 Google Maps 的逆地理编码服务将一些坐标转换为可读位置。因为这是一个 Google 服务，我们可能需要添加一个 API 密钥来验证我们的应用程序与服务的身份。有关完全安装此模块的所有说明可以在其存储库 URL [`github.com/airbnb/react-native maps/blob/master/docs/installation.md`](https://github.com/airbnb/react-native%20maps/blob/master/docs/installation.md) 中找到。

我们希望这个状态变量在主组件挂载时就可用，因此我们将在`componentDidMount`中调用`_onRegionChange`，以便初始位置的名称也存储在状态中。此外，我们将在我们的`<MapView/>`上添加`onRegionChange`属性，以确保每次地图移动以显示不同区域时，位置的名称都会重新计算，这样我们的`position`状态变量中始终有地图中心位置的名称。

作为此屏幕的最后一步，我们将添加所有子视图和另一个确认预订请求的函数：

```jsx
/** * src/main.js ** */

...

import LocationPin from './components/LocationPin';
import LocationSearch from './components/LocationSearch';
import ClassSelection from './components/ClassSelection';
import ConfirmationModal from './components/ConfirmationModal';

export default class Main extends React.Component {
  ...

_onBookingRequest() {
    this.setState({
      confirmationModalVisible: true,
    });
  }

  render() {
    return (
      <View style={{ flex: 1 }}>
        ...

<LocationSearch
          value={
            this.state.position &&
            (this.state.position.feature ||
              this.state.position.formattedAddress)
          }
        />
        <LocationPin onPress={this._onBookingRequest.bind(this)} />
        <ClassSelection />
        <ConfirmationModal
          visible={this.state.confirmationModalVisible}
          onClose={() => {
            this.setState({ confirmationModalVisible: false });
          }}
        />
      </View>
    );
  }
}

...
```

我们添加了四个子视图：

+   `LocationSearch`: 我们将在此组件中向用户显示地图中心的位置，以便她知道她准确请求接送的位置名称。

+   `LocationPin`: 地图中心的标记，用户可以在地图上看到她将请求接送的位置。它还会显示一个确认接送的按钮。

+   `ClassSelection`: 用户可以在其中选择接送车辆类型（经济型、特殊型或高级型）的条形图。

+   `ConfirmationModal`: 显示请求确认的模态框。

`_onBookingRequest`方法将负责在请求预订时弹出确认模态框。

## 向我们的应用程序添加图像

React Native 处理图像的方式与网站类似：图像应放置在项目文件夹结构内的一个文件夹中，然后可以通过`<Image />`（或`<Animated.Image />`）的`source`属性引用它们。让我们看一个来自我们应用程序的例子：

+   `car.png`：这个文件放在我们项目根目录的`img/`文件夹内

+   然后通过使用`source`属性创建一个`<Image/>`组件来显示图像：

```jsx
       <Image source={require('../img/car.png')} />
```

注意`source`属性不接受字符串，而是`require('../img/car.png')`。这是 React Native 中的一个特殊情况，可能会在将来的版本中改变。

# 位置搜索

这应该是一个简单的文本框，显示地图中心的位置的可读名称。让我们看一下代码：

```jsx
/*** src/components/LocationSearch.js ** */

import React from 'react';
import {
  View,
  Text,
  TextInput,
  ActivityIndicator,
  StyleSheet,
} from 'react-native';

export default class LocationSearch extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>PICKUP LOCATION</Text>
        {this.props.value && (
          <TextInput style={styles.location} value={this.props.value} />
        )}
        {!this.props.value && <ActivityIndicator style={styles.spinner} />}
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: 'white',
    margin: 20,
    marginTop: 40,
    height: 60,
    padding: 10,
    borderColor: '#ccc',
    borderWidth: 1,
  },
  title: {
    alignSelf: 'center',
    fontSize: 12,
    color: 'green',
    fontWeight: 'bold',
  },
  location: {
    height: 40,
    textAlign: 'center',
    fontSize: 13,
  },
  spinner: {
    margin: 10,
  },
});
```

它只接收一个属性：`value`（要显示的位置的名称）。如果没有设置，它将显示一个旋转器来显示活动。

因为在这个组件中有许多不同的样式要应用，所以使用`StyleSheet` API 将样式组织在一个键/值对象中，并从我们的`render`方法中引用它是有益的。逻辑和样式之间的分离有助于代码的可读性，也使代码重用成为可能，因为样式可以被级联到子组件中。

## 对齐元素

React Native 使用 Flexbox 来设置应用程序中元素的布局。这通常很简单，但有时在对齐元素时可能会令人困惑，因为有四个属性可以用于此目的：

+   `justifyContent:` 它通过主轴定义子元素的对齐方式

+   `alignItems`：它通过交叉轴定义子元素的对齐方式

+   `alignContent`：当交叉轴上有额外空间时，它会对齐 flex 容器的行

+   `alignSelf`：它允许为单个 flex 项覆盖默认对齐（或由`alignItems`指定的对齐方式）

前三个属性应该分配给容器元素，而第四个属性将应用于子元素，以防我们想要覆盖默认对齐方式。

在我们的情况下，我们只希望一个元素（标题）居中对齐，所以我们可以使用`alignSelf: 'center'`。在本课程的后面，我们将看到不同`align`属性的其他用途。

# 位置图钉

在这一部分，我们将专注于构建指向地图中心的图钉，以直观确认取货位置。这个图钉还包含一个按钮，可以用来触发取货请求：

```jsx
/** * src/components/LocationPin.js ** */

import React from 'react';
import {
  View,
  Text,
Dimensions,
  TouchableOpacity,
  StyleSheet,
} from 'react-native';

const { height, width } = Dimensions.get('window');

export default class LocationPin extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <View style={styles.banner}>
          <Text style={styles.bannerText}>SET PICKUP LOCATION</Text>
<TouchableOpacity
            style={styles.bannerButton}
            onPress={this.props.onPress}
          >
            <Text style={styles.bannerButtonText}>{'>'}</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.bannerPole} />
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
top: height / 2 - 60,
    left: width / 2 - 120,
  },
  banner: {
flexDirection: 'row',
    alignSelf: 'center',
    justifyContent: 'center',
    borderRadius: 20,
    backgroundColor: '#333',
    padding: 10,
    paddingBottom: 10,
shadowColor: '#000000',
    shadowOffset: {
      width: 0,
      height: 3,
    },
    shadowRadius: 5,
    shadowOpacity: 1.0,
  },
  bannerText: {
    alignSelf: 'center',
    color: 'white',
    marginRight: 10,
    marginLeft: 10,
    fontSize: 18,
  },
  bannerButton: {
    borderWidth: 1,
    borderColor: '#ccc',
    width: 26,
    height: 26,
    borderRadius: 13,
  },
  bannerButtonText: {
    color: 'white',
    textAlign: 'center',
backgroundColor: 'transparent',
    fontSize: 18,
  },
  bannerPole: {
    backgroundColor: '#333',
    width: 3,
    height: 30,
    alignSelf: 'center',
  },
});
```

这个组件在功能上又非常轻量，但具有很多自定义样式。让我们深入一些样式细节。

## flexDirection

默认情况下，React Native 和 Flexbox 会垂直堆叠元素：

![flexDirection](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_08.jpg)

对于我们图钉上的横幅，我们希望将每个元素水平堆叠在一起：

![flexDirection](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/01_09.jpg)

这可以通过将以下样式添加到包含元素`flexDirection: 'row'`来实现。`flexDirection`的其他有效选项是：

+   `row-reverse`

+   `column`（默认）

+   `column-reverse`

## Dimensions

在这个组件中的第一行代码中，从设备中提取了高度和宽度到两个变量中：

```jsx
const {height, width} = Dimensions.get('window');
```

获取设备的高度和宽度使我们开发人员能够绝对定位一些元素，确信它们将正确对齐。例如，我们希望我们图钉的横幅对齐在屏幕中心，所以它指向地图的中心。我们可以通过在我们的样式表中的`banner`样式中添加`{top: (height/2), left: (width/2)}`来实现这一点。当然，这会将其对齐到左上角，所以我们需要从每个属性中减去横幅大小的一半，以确保它在元素中间居中。每当我们需要对齐一个与组件树中的任何其他元素无关的元素时，都可以使用这个技巧，尽管在可能的情况下建议使用相对定位。

## Shadows

让我们专注于我们横幅的样式，特别是`shadows`属性：

```jsx
banner: {
  ...
  shadowColor: '#000000',
  shadowOffset: {
    width: 0,
    height: 3
  },
  shadowRadius: 5,
  shadowOpacity: 1.0
}
```

为了给组件添加阴影，我们需要添加四个属性：

+   `shadowColor`：这添加了我们想要为组件设置的十六进制或 RGBA 颜色值

+   `shadowOffset`：这显示了我们希望阴影投射多远

+   `shadowRadius`：这显示了阴影角落的半径值

+   `shadowOpacity`：这显示了我们希望阴影有多深

这就是我们的`LocationPin`组件。

# ClassSelection

在这个组件中，我们将探索在 React Native 中使用`Animated` API 来开始动画。此外，我们将使用自定义字体来改善用户体验，并增加我们应用程序中的定制感。

```jsx
/*** src/components/ClassSelection.js ** */

import React from 'react';
import {
  View,
  Image,
  Dimensions,
  Text,
  TouchableOpacity,
Animated,
  StyleSheet,
} from 'react-native';

const { height, width } = Dimensions.get('window');

export default class ClassSelection extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
classButtonPosition: new Animated.Value(15 + width * 0.1),
    };
  }

  _onClassChange(className) {
    if (className === 'superior') {
Animated.timing(this.state.classButtonPosition, {
        toValue: width * 0.77,
        duration: 500,
      }).start();
    }

    if (className === 'special') {
Animated.timing(this.state.classButtonPosition, {
        toValue: width * 0.5 - 20,
        duration: 500,
      }).start();
    }

    if (className === 'economy') {
Animated.timing(this.state.classButtonPosition, {
        toValue: 15 + width * 0.1,
        duration: 500,
      }).start();
    }
  }

  render() {
    return (
      <View style={styles.container}>
        <Image
          style={styles.classBar}
          source={require('../../img/classBar.png')}
        />
<Animated.View
          style={[styles.classButton, { left: this.state.classButtonPosition }]}
        >
          <Image
            style={styles.classButtonImage}
            source={require('../../img/class.png')}
          />
        </Animated.View>
        <TouchableOpacity
          style={[
            styles.classButtonContainer,
            {
              width: width / 3 - 10,
              left: width * 0.11,
            },
          ]}
          onPress={this._onClassChange.bind(this, 'economy')}
        >
          <Text style={styles.classLabel}>economy</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[
            styles.classButtonContainer,
            { width: width / 3, left: width / 3 },
          ]}
          onPress={this._onClassChange.bind(this, 'special')}
        >
          <Text style={[styles.classLabel, { textAlign: 'center' }]}>
            Special
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[
            styles.classButtonContainer,
            { width: width / 3, right: width * 0.11 },
          ]}
          onPress={this._onClassChange.bind(this, 'superior')}
        >
          <Text style={[styles.classLabel, { textAlign: 'right' }]}>
            Superior
          </Text>
        </TouchableOpacity>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    height: 80,
    backgroundColor: 'white',
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    paddingBottom: 10,
  },
  classBar: {
width: width * 0.7,
    left: width * 0.15,
    resizeMode: 'contain',
    height: 30,
    top: 35,
  },
  classButton: {
    top: 30,
    justifyContent: 'center',
    borderRadius: 20,
    borderColor: '#ccc',
    borderWidth: 1,
    position: 'absolute',
    backgroundColor: 'white',
    height: 40,
    width: 40,
  },
  classButtonImage: {
    alignSelf: 'center',
    resizeMode: 'contain',
    width: 30,
  },
  classButtonContainer: {
    backgroundColor: 'transparent',
    position: 'absolute',
    height: 70,
    top: 10,
  },
  classLabel: {
    paddingTop: 5,
    fontSize: 12,
  },
});
```

这个简单的组件由五个子组件组成：

+   `classBar`：这是显示条和每个类别停止点的图像

+   `classButton`：这是圆形按钮，用户按下特定类别后将移动到所选类别

+   `classButtonContainer`：这是检测用户想要选择的类的可触摸组件

+   `classLabel`：这些是要显示在条的顶部的每个类别的标题

让我们先看一下样式，因为我们可以找到图像组件的一个新属性：`resizeMode`，它确定当框架与原始图像尺寸不匹配时如何调整图像大小。从五种可能的值（`cover`、`contain`、`stretch`、`repeat`和`center`）中，我们选择了`contain`，因为我们希望均匀缩放图像（保持图像的纵横比），以便图像的两个尺寸都等于或小于视图的相应尺寸。我们在`classBar`和`classButtonImage`中都使用了这些属性，这是我们需要在此视图中调整大小的两个图像。

## 添加自定义字体

React Native 包含默认可用的跨平台字体的长列表。字体列表可以在[`github.com/react-native-training/react-native-fonts`](https://github.com/react-native-training/react-native-fonts)上查看。

尽管如此，添加自定义字体是开发应用程序时的常见需求，特别是当设计师参与其中时，因此我们将使用我们的汽车预订应用程序作为测试此功能的游乐场。

将自定义字体添加到我们的应用程序是一个三步任务：

1.  将字体文件（`.ttf`）添加到项目内的一个文件夹中。我们在这个应用程序中使用`fonts/`。

1.  将以下行添加到我们的`package.json`中：

```jsx
      "rnpm": {
          "assets": ["./fonts"]
      }
```

1.  在终端中运行以下命令：

```jsx
 **react-native link**

```

就是这样，React Native 的 CLI 将一次性处理`fonts`文件夹及其文件在 iOS 和 Android 项目中的插入。我们的字体将通过它们的字体名称（可能与文件名不同）可用。在我们的样式表中，我们有`fontFamily: 'Blair ITC'`。

现在我们可以修改`ClassSelection`组件中的`classLabel`样式，以包含新的字体：

```jsx
...

classLabel: {
    fontFamily: 'Blair ITC',
    paddingTop: 5,
    fontSize: 12,
},

...
```

## 动画

React Native 的`Animated` API 旨在以非常高效的方式简洁地表达各种有趣的动画和交互模式。动画侧重于输入和输出之间的声明关系，中间有可配置的转换，并且有简单的`start`/`stop`方法来控制基于时间的动画执行。

我们在应用程序中要做的是，当用户按下她想要预订的班级时，将`classButton`移动到特定位置。让我们更仔细地看看我们在应用程序中如何使用这个 API：

```jsx
/** * src/components/ClassSelection ***/

...

export default class ClassSelection extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classButtonPosition: new Animated.Value(15 + width * 0.1),
    };
  }

  _onClassChange(className) {
    if (className === 'superior') {
      Animated.timing(this.state.classButtonPosition, {
        toValue: width * 0.77,
        duration: 500,
      }).start();
    }

    ...

  }

  render() {
    return (
      ...

      <Animated.View style={{ left: this.state.classButtonPosition }}>
        <Image
          style={styles.classButtonImage}
          source={require('../../img/class.png')}
        />
      </Animated.View>

      ...

      <TouchableOpacity
        onPress={this._onClassChange.bind(this, 'superior')}
      >
        <Text>Superior</Text>
      </TouchableOpacity>

      ...
    );
  }
}

...
```

为了使这种移动正确发生，我们需要将`classButtonImage`包装在`Animated.View`中，并为其提供一个初始的`Animated.Value`作为左坐标。为此，我们将使用`this.state.classButtonPosition`，这样当用户选择特定班级时我们可以改变它。

我们准备开始我们的动画。它将由`_onClassChange`方法触发，因为当用户按下`classButtonContainer`（`<TouchableOpacity/>`）时，它被调用。这个方法调用`Animated.timing`函数传递两个参数：

+   驱动动画的动画值（`this.state.classButtonPosition`）

+   包含动画的结束值和持续时间的对象

调用`Animated.timing`将导致一个包含`start()`方法的对象，我们立即调用该方法来启动动画。然后 React Native 将知道`Animated.View`的`left`坐标需要根据提供的参数慢慢改变。

由于这可能对于简单的移动动画来说有点复杂，但它允许广泛的定制，如链接动画或修改缓动函数。我们将在本课程的后面看到旋转动画。

# ConfirmationModal

我们的最后一个组件是一个模态视图，当用户按下“设置取货位置”按钮时将打开该视图。我们将显示模态视图和自定义活动指示器，它将使用复杂的动画设置来持续旋转在其位置：

```jsx
/** * src/components/ConfirmationModal.js ***/

import React from 'react';
import {
Modal,
  View,
  Text,
  Animated,
  Easing,
  TouchableOpacity,
  StyleSheet,
} from 'react-native';

export default class ConfirmationModal extends React.Component {
  componentWillMount() {
    this._animatedValue = new Animated.Value(0);
  }

cycleAnimation() {
    Animated.sequence([
      Animated.timing(this._animatedValue, {
        toValue: 100,
        duration: 1000,
        easing: Easing.linear,
      }),
      Animated.timing(this._animatedValue, {
        toValue: 0,
        duration: 0,
      }),
    ]).start(() => {
      this.cycleAnimation();
    });
  }

componentDidMount() {
    this.cycleAnimation();
  }

  render() {
const interpolatedRotateAnimation = this._animatedValue.interpolate({
      inputRange: [0, 100],
      outputRange: ['0deg', '360deg'],
    });

    return (
<Modal
        animationType={'fade'}
        visible={this.props.visible}
        transparent={true}
      >
        <View style={styles.overlay}>
          <View style={styles.container}>
            <Text style={styles.title}>Contacting nearest car...</Text>
<Animated.Image
              style={[
                styles.spinner,
                { transform: [{ rotate: interpolatedRotateAnimation }] },
              ]}
              source={require('../../img/loading.png')}
            />
            <TouchableOpacity
              style={styles.closeButton}
              onPress={this.props.onClose}
            >
              <Text style={styles.closeButtonText}>X</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    );
  }
}

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: '#0006',
    justifyContent: 'center',
  },
  container: {
    backgroundColor: 'white',
    alignSelf: 'center',
    padding: 20,
    borderColor: '#ccc',
    borderWidth: 1,
  },
  title: {
    textAlign: 'right',
    fontFamily: 'Blair ITC',
    paddingTop: 5,
    fontSize: 12,
  },
  spinner: {
    resizeMode: 'contain',
    height: 50,
    width: 50,
    margin: 50,
    alignSelf: 'center',
  },
  closeButton: {
    backgroundColor: '#333',
    width: 40,
    height: 40,
    borderRadius: 20,
    justifyContent: 'center',
    alignSelf: 'center',
  },
  closeButtonText: {
    color: 'white',
    alignSelf: 'center',
    fontSize: 20,
  },
});
```

对于这个组件，我们使用了 React Native 中可用的`<Modal />`组件，以利用其淡入淡出动画和可见性功能。属性`this.props.visible`将驱动此组件的可见性，因为父级知道用户的取货请求。

让我们再次关注动画，因为我们想为显示活动的旋转器设置一个更复杂的设置。我们想要显示一个无休止旋转的动画，所以我们需要系统地调用我们的`start()`动画方法。为了实现这一点，我们创建了一个`cycleAnimation()`方法，它在组件挂载时被调用（以启动动画），并且从返回的`Animated.timing`对象中调用，因为它被作为回调传递以在每次动画结束时被调用。

我们还使用`Animated.sequence`来连接两个动画：

+   从 0 度移动到 360 度（在一秒钟内使用线性缓动）

+   从 360 度移动到 0 度（在 0 秒内）

这是为了在每个周期结束时重复第一个动画。

最后，我们定义了一个名为`interpolatedRotateAnimation`的变量，用于存储从 0 度到 360 度的插值，因此可以将其传递给`transform`/`rotate`样式，定义在动画我们的`Animated.Image`时可用的旋转值。

作为一个实验，我们可以尝试用另一张图片替换 loading.png，看看它是如何被动画化的。这可以通过替换我们的`<Animated.Image />`组件中的`source`属性来轻松实现：

```jsx
...            

            <Animated.Image
              style={[
                styles.spinner,
                { transform: [{ rotate: interpolatedRotateAnimation }] },
              ]}
source={require('../../img/spinner.png')}
            />

...
```

# 总结

使用诸如`native-base`或`react-native-elements`之类的 UI 库在构建应用程序时节省了大量时间和维护麻烦，但结果最终呈现出标准风格，这在用户体验方面并不总是理想的。这就是为什么学习如何操纵我们应用程序的样式总是一个好主意，特别是在设计由 UX 专家或应用程序设计师提供的团队中。

在这节课中，我们深入研究了 React Native 的 CLI 在初始化项目时创建的文件夹和文件。此外，我们熟悉了开发者菜单及其调试功能。在构建我们的应用程序时，我们专注于布局和组件样式，还学习了如何添加和操纵动画，使我们的界面更具吸引力。我们研究了 Flexbox 布局系统以及如何在组件中堆叠和居中元素。API，如 dimensions，用于检索设备的宽度和高度，以便对一些组件进行定位。您学会了如何将字体和图像添加到我们的应用程序，并如何显示它们以改善用户体验。

现在我们知道如何构建更多定制的界面，让我们在下一课中构建一个图像分享应用程序，其中设计起着关键作用。

# 评估

1.  为什么`react-native-geocoder`模块使用 Google 地图的逆地理编码服务？

1.  存储地图中心位置的人类可读位置

1.  将一些坐标转换为人类可读的位置

1.  添加 API 密钥以便用服务对我们的应用进行身份验证

1.  确保每次地图移动以显示不同区域时重新计算位置的名称。

1.  以下哪个属性用于对齐元素？

1.  `justifyContent`

1.  `alignLeft`

1.  `alignRight`

1.  `alignJustify`

1.  默认情况下，React Native 和 Flexbox 堆叠元素。

1.  对角线

1.  反向

1.  垂直地

1.  水平地

1.  以下哪行代码从设备中提取高度和宽度到两个变量中？

1.  `const {height, width} = Dimensions.get('height, width');`

1.  `constant {height, width} = Dimensions.get('window');`

1.  `const {height, width} = Dimensions.get('window');`

1.  `const {height, width} = Dimensions.get('window');`

1.  按顺序添加阴影到组件的四个属性是什么？


# 第二章：项目 2 - 图像分享应用程序

到目前为止，我们知道如何创建一个具有自定义界面的功能齐全的应用程序。您甚至学会了如何添加一个状态管理库来控制我们应用程序中的共享数据，以便代码库保持可维护和可扩展。

在本课程中，我们将专注于使用不同的状态管理库（Redux）构建应用程序，利用相机功能，编写特定于平台的代码，并深入构建自定义用户界面，既吸引人又可用。图像分享应用程序将作为这些功能的一个很好的示例，并且还将为理解如何在 React Native 上构建大型应用程序奠定基础。

我们将重用我们的大部分代码，这个应用程序将可用于两个平台：iOS 和 Android。尽管我们的大部分用户界面将是自定义的，但我们将使用`native-base`来简化 UI 元素，如图标。对于导航，我们将再次使用`react-navigation`，因为它为每个平台提供了最常用的导航：iOS 的选项卡导航和 Android 的抽屉菜单导航。最后，我们将使用`react-native-camera`来处理与设备相机的交互。这不仅会减少实现复杂性，还会为我们提供一大堆免费的功能，我们可以在将来扩展我们的应用程序时使用。

对于这个应用程序，我们将模拟一些 API 调用，这样我们就不需要构建后端。当构建连接的应用程序时，这些调用应该很容易被真实的 API 替换。

# 概览

构建图像分享应用程序的主要要求之一是具有吸引人的设计。我们将遵循一些最流行的图像分享应用程序的设计模式，为每个平台调整这些模式，同时尽量重用尽可能多的代码，利用 React Native 的跨平台能力。

让我们首先来看一下 iOS 中的用户界面：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_01.jpg)

主屏幕显示一个简单的标题和图像列表，包括用户图片、姓名和一个**更多**图标以分享图像。在底部，选项卡导航显示三个图标，代表三个主要屏幕：**所有图像**、**我的图像**和**相机**。

### 注意

此示例应用程序中使用的所有图像都可以以任何形式使用。

当用户按下特定图像的**更多**图标时，将显示**分享**菜单：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_02.jpg)

这是一个标准的 iOS 组件。在模拟器上使用它并没有太多意义，最好在实际设备上进行测试。

让我们来看看第二个屏幕，**我的图片**：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_03.jpg)

这是当前用户上传的所有图片的网格表示，可以通过下一个屏幕**相机**进行更新：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_04.jpg)

iOS 模拟器不包括对任何相机的支持，因此这个功能最好在实际设备上进行测试，尽管`react-native-camera`是完全可用的，并且在访问时将返回虚假数据。我们将使用静态图像进行测试。

这就是 iOS 的全部内容；现在让我们转向 Android 版本：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_05.jpg)

由于 Android 鼓励使用抽屉式导航而不是选项卡，我们将在页眉中包括一个抽屉菜单图标，并且还将通过不同的图标使相机可用。

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_06.jpg)

与 iOS 的**分享**菜单一样，Android 有自己的控制器，因此我们将利用这一功能，并在用户点击特定图像上的**更多**图标时包含它：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_07.jpg)

当用户点击抽屉菜单图标时，菜单将显示出来，显示三个可用屏幕。从这里，用户可以导航到**我的图片**屏幕：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_08.jpg)

最后，相机屏幕也可以通过抽屉菜单访问：

![概览](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_09.jpg)

Android 模拟器包括一个由彩色移动方块组成的相机模拟，可以用于测试。但出于一致性原因，我们将继续使用 iOS 版本中使用的固定图像。

本课程将涵盖以下主题：

+   React Native 中的 Redux

+   使用相机

+   特定平台的代码

+   抽屉和选项卡导航

+   与其他应用程序共享数据

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将命名为`imageShare`，并将适用于 iOS 和 Android 设备：

```jsx
**react-native init --version="0.44.0" imageShare**

```

为了在此应用程序中使用一些包，我们将使用特定版本的 React Native（`0.44.0`）。

我们将为我们的应用程序使用 Redux，因此我们将创建一个文件夹结构，其中可以容纳我们的`reducers`、`actions`、`components`、`screens`和`api`调用：

此外，我们已经在`img`文件夹中添加了`logo.png`。至于其余部分，我们有一个非常标准的 React Native 项目。入口点将是`index.ios.js`用于 iOS 和`index.android.js`用于 Android：

```jsx
/*** index.ios.js and index.android.js ***/ 

import { AppRegistry } from 'react-native';
import App from './src/main';

AppRegistry.registerComponent('imageShare', () => App);
```

我们对两个文件的实现是相同的，因为我们希望使用`src/main.js`作为两个平台的通用入口点。

让我们跳转到我们的`package.json`文件，了解我们的应用程序将有哪些依赖项：

```jsx
/*** package.json ***/

{
        "name": "imageShare",
        "version": "0.0.1",
        "private": true,
        "scripts": {
                "start": "node node_modules/react-native/
                local-cli/cli.js start",
                "test": "jest"
        },
        "dependencies": {
                "native-base": "².1.5",
                "react": "16.0.0-alpha.6",
                "react-native": "0.44.0",
                "react-native-camera": "⁰.8.0",
                "react-navigation": "¹.0.0-beta.9",
                "react-redux": "⁵.0.5",
                "redux": "³.6.0",
                "redux-thunk": "².2.0"
        },
        "devDependencies": {
                "babel-jest": "20.0.3",
                "babel-preset-react-native": "1.9.2",
                "jest": "20.0.3",
                "react-test-renderer": "16.0.0-alpha.6"
        },
        "jest": {
                "preset": "react-native"
        }
}
```

一些依赖项，如`react-navigation`或`native-base`，是以前课程中的老朋友。其他一些，如`react-native-camera`，将在本课程中首次介绍。其中一些与我们将在此应用程序中使用的状态管理库 Redux 密切相关：

+   `redux`：这就是状态管理库本身

+   `react-redux`：这些是 Redux 的 React 处理程序

+   `redux-thunk`：这是处理异步操作执行的 Redux 中间件

为了完成安装，我们需要链接`react-native-camera`，因为它需要对我们应用程序的本地部分进行一些更改：

```jsx
react-native link react-native-camera
```

在 iOS 10 及更高版本中，我们还需要修改我们的`ios/imageShare/Info.plist`以添加一个**相机使用说明**，这应该显示以请求权限在应用程序内启用相机。我们需要在最后的`</dict></plist>`之前添加这些行：

```jsx
<key>NSCameraUsageDescription</key>
<string>imageShare requires access to the camera on this device to perform this action</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>imageShare requires access to the image library on this device to perform this action</string>
```

# Redux

Redux 是一个基于简单原则的 JavaScript 应用程序的可预测状态容器：

+   您应用程序的整个状态存储在一个**store**内的对象树中

+   改变状态树的唯一方法是发出一个**action**，一个描述发生了什么的对象

+   为了指定操作如何转换状态树，您需要编写纯**reducers**

它的流行程度来自于在任何类型的代码库（前端或后端）中使用它所能产生的一致性、可测试性和开发人员体验。由于其严格的单向数据流，它也很容易理解和掌握：

![Redux](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_11.jpg)

用户触发和由**Reducers**处理的**Actions**，这些**Reducers**只是应用基于该**Action**的状态变化的纯函数。生成的状态保存在一个**Store**中，该**Store**由我们应用程序中的**View**使用，以显示应用程序的当前状态。

Redux 是一个复杂的主题，超出了本书的范围，但它将在本书的一些课程中广泛使用，因此可能有益于查看它们的官方文档([`redux.js.org/`](http://redux.js.org/))，以熟悉这个状态管理库的基本概念。

Redux 的一些基本概念将在我们的`src/main.js`文件中使用：

```jsx
/*** src/main.js ***/

import React from 'react';
import { DrawerNavigator,TabNavigator } from 'react-navigation';
import { Platform } from 'react-native';

import { Provider } from 'react-redux';
import { createStore, combineReducers, applyMiddleware } from 'redux';
import thunk from 'redux-thunk';
import imagesReducer from './reducers/images';

import ImagesList from './screens/ImagesList.js';
import MyImages from './screens/MyImages.js';
import Camera from './screens/Camera.js';

let Navigator;
if(Platform.OS === 'ios'){
  Navigator = TabNavigator({
    ImagesList: { screen: ImagesList },
    MyImages: { screen: MyImages },
    Camera: { screen: Camera }
  }, {
    tabBarOptions: {
      inactiveTintColor: '#aaa',
      activeTintColor: '#000',
      showLabel: false
    }
  });
} else {
  Navigator = DrawerNavigator({
    ImagesList: { screen: ImagesList },
    MyImages: { screen: MyImages },
    Camera: { screen: Camera }
  });
}let store = createStore(combineReducers({ imagesReducer }), applyMiddleware(thunk));

export default class App extends React.Component {
  render() {
    return (
      <Provider store={store}>
        <Navigator/>
      </Provider>
    )
  }
}
```

让我们首先关注 Redux 的仪式。`let store = createStore(combineReducers({ imagesReducer }), applyMiddleware(thunk));`通过组合导入的 reducer（我们这个应用程序只有一个 reducer，所以这只是信息性的）并应用**Thunk**中间件来设置存储，这将使我们的应用程序能够使用异步操作。我们将模拟几个 API 调用，这些调用将返回异步承诺，因此需要这个中间件来正确处理这些承诺的解析。

然后，我们有我们的`render`方法：

```jsx
<Provider store={store}>
   <Navigator/>
</Provider>
```

这在大多数使用 React 的 Redux 应用程序中都是标准的。我们用一个`<Provider />`组件包装根组件`(<Navigator />`在我们的例子中)来确保我们将从我们应用程序的根部分获得`store`。Redux 的`connect`方法将在我们继续本课程时在我们的容器或屏幕中可用。

我们将使用一个`<Navigator />`组件作为我们应用程序的根，但它将根据运行的平台的不同而具有不同的性质：

```jsx
let Navigator;
if(Platform.OS === 'ios'){
  Navigator = TabNavigator({

    ...

  });
} else {
  Navigator = DrawerNavigator({

    ...

  });
}
```

`Platform`是一个 React Native API，主要用于识别我们的应用程序正在运行的平台。我们可以通过用`if(Platform.OS === 'ios'){ ... }`括起来的代码来编写特定于 iOS 的代码，对于 Android 也是一样：`if(Platform.OS === 'android'){ ... }`。

在这种情况下，我们将在 iOS 上使用它来构建一个选项卡导航器，在 Android 上使用它来构建一个抽屉导航器，这些都是这些平台上的**事实**导航模式。在这两个导航器上，我们将把`ImagesList`、`MyImages`和`Camera`设置为我们应用程序中的三个主要屏幕。

# ImagesList

我们应用程序中的主屏幕是从后端检索的图像列表。我们将显示这些图像以及它们对应的上传者个人资料图片和名称。对于每个图像，我们将显示`更多`，可以用于与用户设备上的其他应用程序共享图像，例如消息应用程序或社交网络。这个屏幕的大部分 UI 将从`<Gallery />`组件派生，因此我们将专注于将屏幕与 Redux 存储连接起来，添加自定义标题，并添加一个滚动视图使画廊可滚动，并添加一个活动指示器来警告用户有网络活动：

```jsx
/*** src/components/ImagesList ***/

import React from 'react';
import { View, ScrollView } from 'react-native';

import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import * as Actions from '../actions';
import { Icon } from 'native-base';

import Header from '../components/Header';
import Gallery from '../components/Gallery';
import ActivityIndicator from '../components/ActivityIndicator';

class ImagesList extends React.Component {
  static navigationOptions = {
    tabBarIcon: ({ tintColor }) => (
      <Icon name='list' style={{fontSize: 40, color: tintColor}}/>
    ),
    drawerLabel: 'All Images'
  };

  componentWillMount() {
    this.props.fetchImages();
  }

  componentWillReceiveProps(nextProps) {
    if(!this.props.addingImage && nextProps.addingImage) {
      this.scrollable.scrollTo({y: 0});
    }
  }

  render() {
    return (
      <View style={{flex: 1}}>
        <Header onMenuButtonPress={() => 
        this.props.navigation.navigate('DrawerOpen')}
        onCameraButtonPress={() => 
        this.props.navigation.navigate('Camera')}/>
<ScrollView ref={(scrollable) => {
            this.scrollable = scrollable;
          }}>
          { this.props.addingImage && <ActivityIndicator 
            message='Adding image' /> }
          <Gallery imageList={this.props.images} loading=
          {this.props.fetchingImages}/>
        </ScrollView>
      </View>
    );
  }
}

function mapStateToProps(state) { return { images: state.imagesReducer.images, addingImage: state.imagesReducer.addingImage, fetchingImages: state.imagesReducer.fetchingImages } }
function mapStateActionsToProps(dispatch) { return bindActionCreators(Actions, dispatch) }

export default connect(mapStateToProps, mapStateActionsToProps)(ImagesList);
```

由于大多数 React 应用程序使用 Redux，我们需要将我们的组件与状态和操作连接起来。我们将创建两个函数（`mapStateToProps`和`mapStateActionsToProps`）来装饰我们的`<ImageList />`组件，以映射组件感兴趣的操作和状态的部分：

+   `images`：这是我们将在`<Gallery />`中用于呈现的图像列表

+   `addingImage`：这是一个标志，当上传图像时我们将设置为`true`

+   `fetchingImages`：当应用程序请求从后端获取图像列表以更新存储时，此标志将设置为`true`

在这个屏幕上，我们唯一需要的操作是`fetchImages`，它可以通过`propscomponent`访问，因为我们将`Actions`中的操作列表连接到我们的`<ImagesList />`组件。同样，我们通过`props`还可以访问三个状态变量（`images`，`addingImage`和`fetchingImages`）,这要归功于相同的`connect`调用：

```jsx
function mapStateToProps(state) {
  return {
    images: state.imagesReducer.images,
    addingImage: state.imagesReducer.addingImage,
    fetchingImages: state.imagesReducer.fetchingImages
  };
}
function mapStateActionsToProps(dispatch) {
  return bindActionCreators(Actions, dispatch);
}

export default connect(mapStateToProps, mapStateActionsToProps)(ImagesList);
```

这就是我们从 Redux 需要的全部。我们将在其他屏幕中看到这种模式，因为它是连接 React 组件与存储部分和操作列表的常见解决方案。

`fetchImages`动作在`componentWillMount`上调用，作为要呈现的图像列表的初始检索：

```jsx
componentWillMount() { 
   this.props.fetchImages(); 
}
```

我们还添加了一种方法来检测`addingImage`标志何时设置为`true`以显示活动指示器：

```jsx
componentWillReceiveProps(nextProps) {
  if(!this.props.addingImage && nextProps.addingImage) {
    this.scrollable.scrollTo({y: 0});
  }
}
```

这个方法将在`<Scrollview />`中调用`scrollTo`，以确保它显示顶部部分，因此`<ActivityIndicator />`对用户可见。这次我们使用了自定义的`<ActivityIndicator />`（从`src/components/ActivityIndicator`导入），因为我们不仅想显示旋转器，还想显示消息。

最后，我们将添加两个组件：

+   `<Header />`：显示标志和（在 Android 版本中）两个图标，用于导航到抽屉菜单和相机屏幕

+   `<Gallery />`：这显示了格式化的图片列表和上传者

在转移到另一个屏幕之前，让我们看一下我们在这个屏幕中包含的三个自定义组件：`<ActivityIndicator />`、`<Header />` 和 `<Gallery />`。

# Gallery

Gallery 包含了所有图片列表的渲染逻辑。它依赖于 `native-base`，更具体地说，依赖于它的两个组件，`<List />` 和 `<ListItem />`：

```jsx
/*** src/components/Gallery ***/

import React from 'react';
import { List, ListItem, Text, Icon, Button, Container, Content }
 from 'native-base';
import { Image, Dimensions, View, Share, ActivityIndicator, StyleSheet } from 'react-native';

var {height, width} = Dimensions.get('window');

export default class Gallery extends React.Component {
  _share(image) {
   Share.share({message: image.src, title: 'Image from: ' + 
                image.user.name}) 
  }

  render() {
    return (
      <View>
        <List style={{margin: -15}}>
          {
            this.props.imageList && this.props.imageList.map((image) =>  
            {
              return (
                <ListItem 
                    key={image.id} 
                    style={{borderBottomWidth: 0, 
                    flexDirection: 'column', marginBottom: -20}}>
                  <View style={styles.user}>
                    <Image source={{uri: image.user.pic}} 
                     style={styles.userPic}/>
                    <Text style={{fontWeight: 'bold'}}>
                    {image.user.name}</Text>
                  </View>
                  <Image source={{uri: image.src}} 
                  style={styles.image}/>
                  <Button style={{position: 'absolute', right: 15, 
                  top: 25}} transparent 
                  onPress={this._share.bind(this, image)}>
                    <Icon name='ios-more' style={{fontSize: 20, 
                    color: 'black'}}/>
                  </Button>
                </ListItem>
              );
            })
          }
        </List>
        {
          this.props.loading &&
          <View style={styles.spinnerContainer}>
            <ActivityIndicator/>
          </View>
        }
      </View>
    );
  }
}

const styles = StyleSheet.create({
  user: {
    flexDirection: 'row',
    alignSelf: 'flex-start',
    padding: 10
  },
  userPic: {
    width: 50,
    height: 50,
    resizeMode: 'cover',
    marginRight: 10,
    borderRadius: 25
  },
  image: {
    width: width,
    height: 300,
    resizeMode: 'cover'
  },
  spinnerContainer: {
    justifyContent: 'center',
    height: (height - 50)
  }
});
```

这个组件从它的父组件中获取两个 props：`loading` 和 `imageList`。

`loading` 用于显示标准的 `<ActivityIndicator />`，显示用户的网络活动。这次我们使用标准的指示器，而不是自定义指示器，因为应该很清楚网络活动表示的是什么。

`imageList` 是存储图片列表的数组，它将在我们的 `<Gallery />` 中一次渲染一个 `<ListItem />`。每个 `<ListItem />` 都包含一个带有 `onPress={this._share.bind(this, image)` 的 `<Button />`，用于与其他应用程序共享图片。让我们看一下 `_share` 函数：

```jsx
_share(image) {
  Share.share({message: image.src, title: 'Image from: ' 
               + image.user.name}) 
}
```

`Share` 是一个用于分享文本内容的 React Native API。在我们的情况下，我们将分享图片的 URL（`img.src`）以及一个简单的标题。分享文本是在应用程序之间共享内容的最简单方式，因为许多应用程序都会接受文本作为共享格式。

值得注意的是我们对图片应用的样式，使其占据整个宽度并具有固定高度（`300`），这样即使显示的图片大小不同，我们也能获得稳定的布局。为了实现这一设置，我们使用了 `resizeMode: 'cover'`，这样图片在任何维度上都不会被拉伸。这意味着我们可能会裁剪图片，但这样可以保持统一性。另一个选项是使用 `resizeMode: contain`，如果我们不想裁剪任何内容，而是想要将图片适应这些边界并可能缩小它们。

# Header

我们想要在多个屏幕之间重用一个自定义的标题。这就是为什么最好为它创建一个单独的组件，并在这些屏幕中导入它的原因：

```jsx
/*** src/components/Header ***/

import React from 'react';
import { View, Image, StyleSheet } from 'react-native';
import { Icon, Button } from 'native-base';
import { Platform } from 'react-native';

export default class Header extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        {
          Platform.OS === 'android' &&
          <Button transparent onPress={this.props.onMenuButtonPress}>
            <Icon android='md-menu' style={styles.menuIcon}/>
          </Button>
        }
        <Image source={require('../../img/logo.png')} 
          style={styles.logo} />
        {
          Platform.OS === 'android' &&
          <Button onPress={this.props.onCameraButtonPress} transparent>
            <Icon name='camera' style={styles.cameraIcon}/>
          </Button>
        }
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    paddingTop: 20,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-around',
    borderBottomWidth: 1,
    borderBottomColor: '#ccc'
  },
  menuIcon: {
    fontSize: 30,
    color: 'black'
  },
  logo: {
    height: 25,
    resizeMode: 'contain',
    margin: 10
  },
  cameraIcon: {
    fontSize: 30,
    color: 'black'
  }
});
```

我们再次使用 `Platform` API 来检测安卓设备，并且只在该平台上显示抽屉菜单按钮和相机按钮。我们决定这样做是为了使这些功能更加突出，从而减少需要按下的按钮数量，以便安卓用户更容易地使用这些功能。按下按钮时要执行的操作是通过父组件通过两个 props 传递的：

+   `onMenuButtonPress`

+   `onCameraButtonPress`

这两个属性调用两个单独的函数，调用导航器的`navigate`方法：

+   `this.props.navigation.navigate('DrawerOpen')`

+   `this.props.navigation.navigate('Camera')`

最后要注意的是我们如何设置这个组件中容器的布局。我们使用`justifyContent: 'space-around'`，这是告诉 Flexbox 均匀分布项目在行中，并在它们周围有相等的空间。请注意，从视觉上看，这些空间并不相等，因为所有项目在两侧都有相等的空间。第一个项目将在容器边缘有一个单位的空间，但下一个项目之间将有两个单位的空间，因为下一个项目有自己的间距。

![Header](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/xplat-app-dev-react/img/02_12.jpg)

# ActivityIndicator

我们的自定义`ActivityIndicator`是一个非常简单的组件：

```jsx
/*** src/components/ActivityIndicator ***/

import React from 'react';
import { ActivityIndicator, View, Text, StyleSheet } 
from 'react-native';

export default class CustomActivityIndicator extends React.Component {
  render() {
    return (
      <View style={styles.container}>
        <ActivityIndicator style={{marginRight: 10}}/>
        <Text>{this.props.message}</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    justifyContent: 'center',
    padding: 10,
    backgroundColor: '#f0f0f0'
  }
});
```

它接收一个消息作为属性，并将其显示在标准旋转器旁边。我们还添加了自定义背景颜色（`#f0f0f0`）以使其在白色背景上更加可见。

现在让我们转移到相机屏幕，将我们的图像添加到列表中。

# 相机

在使用`react-native-camera`时，大部分拍照逻辑可以被抽象出来，因此我们将专注于在我们的组件中使用这个模块，并确保通过 Redux 操作将其连接到我们应用程序的状态：

```jsx
/*** src/screens/Camera ***/

import React, { Component } from 'react';
import {
  Dimensions,
  StyleSheet,
  Text,
  TouchableHighlight,
  View
} from 'react-native';
import { Button, Icon } from 'native-base';
import Camera from 'react-native-camera';
import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import * as Actions from '../actions';

class CameraScreen extends Component {
  static navigationOptions = {
    tabBarIcon: ({ tintColor }) => (
      <Icon name='camera' style={{fontSize: 40, color: tintColor}}/>
    ),
  };

  render() {
    return (
      <View style={styles.container}>
        <Camera
          ref={(cam) => {
            this.camera = cam;
          }}
          style={styles.preview}
          aspect={Camera.constants.Aspect.fill}>
          <Button onPress={this.takePicture.bind(this)} 
          style={styles.cameraButton} transparent>
            <Icon name='camera' style={{fontSize: 70,
            color: 'white'}}/>
          </Button>
        </Camera>
        <Button onPress={() => 
         this.props.navigation.navigate('ImagesList')} 
         style={styles.backButton} transparent>
          <Icon ios='ios-arrow-dropleft' android='md-arrow-dropleft' 
           style={{fontSize: 30, color: 'white'}}/>
        </Button>
      </View>
    );
  }

  takePicture() {
    const options = {};
    this.camera.capture({metadata: options})
      .then((data) => {
        this.props.addImage(data);
        this.props.navigation.navigate('ImagesList');
      })
      .catch(err => console.error(err));
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
  },
  preview: {
    flex: 1,
    justifyContent: 'flex-end',
    padding: 20
  },
  capture: {
    flex: 0,
    backgroundColor: '#fff',
    borderRadius: 5,
    color: '#000',
    padding: 10,
    margin: 40
  },
  cameraButton: {
    flex: 0, 
    alignSelf: 'center'
  },
  backButton: {
    position: 'absolute',
    top:20
  }
});

function mapStateToProps(state) { return {} }
function mapStateActionsToProps(dispatch) { return bindActionCreators(Actions, dispatch) }

export default connect(mapStateToProps, mapStateActionsToProps)(CameraScreen);
```

`react-native-camera`的工作方式是通过提供一个我们可以包含在屏幕中的组件，并通过引用，我们可以调用它的`capture`方法，该方法返回一个我们可以使用的承诺，以调用`addImage`将我们的图像上传到应用程序的后端。

让我们更仔细地看一下`<Camera />`组件：

```jsx
<Camera
   ref={(cam) => {
     this.camera = cam;
   }}
   style={styles.preview}
   aspect={Camera.constants.Aspect.fill}>

...

</Camera>
```

`<Camera />`组件有三个属性：

+   `ref`：这在父组件中为`<Camera />`组件设置一个引用，以便调用捕获方法。

+   `样式`：这允许开发人员指定应用程序中组件的外观。

+   `aspect`：这允许您定义视图渲染器在显示相机视图时的行为。有三个选项：`fill`，`fit`和`stretch`。

当用户按下相机按钮时，`takePicture`函数将被调用：

```jsx
takePicture() {
    const options = {};
    this.camera.capture({metadata: options})
    .then((data) => {
      this.props.addImage(data);
      this.props.navigation.navigate('ImagesList');
    })
    .catch(err => console.error(err));
}
```

我们将使用保存的相机引用来调用其`capture`方法，我们可以传递一些元数据（例如，拍摄照片的位置）。这个方法返回一个 promise，将使用这个数据调用`addImage`动作将这个数据发送到后端，这样图片就可以添加到`imagesList`中。在将图像发送到后端后，我们将使应用程序导航回`ImagesList`屏幕。`addImage`方法将设置`addingImages`标志，因此`ImageList`屏幕可以显示相应消息的活动指示器。

让我们继续看看我们应用程序中的最后一个屏幕：`MyImages`。

# MyImages

这个屏幕显示了已登录用户上传的所有图像。我们在这个屏幕上使用虚假图像来预先填充这个屏幕，但更多的图像可以通过相机屏幕添加。

大部分渲染逻辑将被移动到一个名为`<ImagesGrid />`的单独组件中：

```jsx
/*** src/screens/MyImages ***/

import React from 'react';
import { 
  Image,
  TouchableOpacity,
  Text,
  View,
  ActivityIndicator,
  Dimensions 
} from 'react-native';

import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import * as Actions from '../actions';
import { Icon } from 'native-base';

import Header from '../components/Header';
import ImagesGrid from '../components/ImagesGrid';

var {height, width} = Dimensions.get('window');

class MyImages extends React.Component {
  static navigationOptions = {
    drawerLabel: 'My Images',
    tabBarIcon: ({ tintColor }) => (
      <Icon name='person' style={{fontSize: 40, color: tintColor}}/>
    )
  };

  componentWillMount() {
    this.props.fetchImages(this.props.user.name);
  }

  render() {
    return (
      <View>
        <Header onMenuButtonPress={() => 
        this.props.navigation.navigate('DrawerOpen')} 
        onCameraButtonPress={() => 
        this.props.navigation.navigate('Camera')}/>
        {
          this.props.fetchingImages &&
          <View style={{justifyContent: 'center', 
           height: (height - 50)}}>
            <ActivityIndicator/>
          </View>
        }
        <ImagesGrid images={this.props.images}/>
      </View>
    );
  }
}

function mapStateToProps(state) { return { images: state.imagesReducer.userImages, user: state.imagesReducer.user, fetchingImages: state.imagesReducer.fetchingUserImages } }
function mapStateActionsToProps(dispatch) { return bindActionCreators(Actions, dispatch) }

export default connect(mapStateToProps, mapStateActionsToProps)(MyImages);
```

这个组件的第一件事是调用`fetchImages`动作，但与`<ImagesList />`组件不同的是，它只传递用户名来仅检索已登录用户的图片。当我们创建这个动作时，我们需要考虑到这一点，并接收一个可选的`userName`参数来过滤我们将检索的图像列表。

除此之外，这个组件将大部分行为委托给`<ImageGrid />`，这样我们可以重用渲染能力给其他用户。让我们继续看看`<ImageGrid />`。

# ImageGrid

一个简单的滚动视图和图像列表。这个组件就是这么简单，但它配置成可以让图像以网格的方式轻松流动：

```jsx
/*** src/components/ImageGrid ***/

import React from 'react';
import { 
  Image,
  TouchableOpacity, 
  ScrollView, 
  Dimensions, 
  View,
  StyleSheet
} from 'react-native';

var {height, width} = Dimensions.get('window');

export default class ImagesGrid extends React.Component {
  render() {
    return (
      <ScrollView>
        <View style={styles.imageContainer}>
          {
            this.props.images && 
            this.props.images.map(img => {
              return (<Image style={styles.image} 
              key={img.id} source={{uri: img.src}}/>);
            })
          }
        </View>
      </ScrollView>
    );
  }
}

const styles = StyleSheet.create({
  imageContainer: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    flexWrap: 'wrap'
  },
  image: {
    width: (width/3 - 2),
    margin: 1,
    height: (width/3 - 2),
    resizeMode: 'cover'
  }
});
```

在设置容器样式时，我们使用`flexWrap`：'wrap'来确保图像不仅在`row`方向上流动，而且当设备宽度覆盖一行图像时也会扩展到新行。通过为每个图像设置`width`和`height`为`width/3 - 2`，我们确保容器可以每行容纳三个图像，包括两个像素的小间距。

还有一些通过`npm`可用的网格模块，但我们决定为此构建我们自己的组件，因为我们不需要网格中的额外功能，并且以这种方式可以获得灵活性。

这些就是我们在图像分享应用中需要的所有屏幕和视觉组件。现在让我们来看看让它们一起工作的粘合剂，即动作和减速器。

# 动作

正如我们在屏幕上看到的，这个应用只需要两个操作，`fetchImages`（对所有用户或特定用户）和`addImage`：

```jsx
/*** src/actions/index ***/

import api from '../api';

export function fetchImages(userId = null) {
  let actionName, actionNameSuccess, actionNameError;
  if(userId) {
    actionName = 'FETCH_USER_IMAGES';
    actionNameSuccess = 'FETCH_USER_IMAGES_SUCCESS';
    actionNameError = 'FETCH_USER_IMAGES_ERROR';
  } else {
    actionName = 'FETCH_IMAGES';
    actionNameSuccess = 'FETCH_IMAGES_SUCCESS';
    actionNameError = 'ADD_IMAGE_ERROR';
  }

  return dispatch => {
    dispatch({ type: actionName });
    api
      .fetchImages(userId)
      .then(images => {
        dispatch({ 
          type: actionNameSuccess,
          images
        })  
      })
      .catch(error => {
        dispatch({ 
          type: actionNameError,
          error
        });  
      });
  };
}

export function addImage(data = null) {
  return dispatch => {
    dispatch({ type: 'ADD_IMAGE' });
    api
      .addImage()
      .then(imageSrc => {
        dispatch({ 
          type: 'ADD_IMAGE_SUCCESS',
          imageSrc
        });  
      })
      .catch(error => {
        dispatch({ 
          type: 'ADD_IMAGE_ERROR',
          error
        });  
      });
  };
}
```

Redux 操作只是描述事件的简单对象，包括其有效负载。由于我们使用了`redux-thunk`，我们的**action creators**将返回一个函数，在这个函数中将调用 Redux 的`dispatch`函数，传递操作。让我们更仔细地看看我们的`addImage`操作：

```jsx
export function addImage(data = null) {
  return dispatch => {
    dispatch({ type: 'ADD_IMAGE' });
    api
      .addImage()
      .then(imageSrc => {
        dispatch({ 
          type: 'ADD_IMAGE_SUCCESS',
          imageSrc
        }); 
      })
      .catch(error => {
        dispatch({ 
          type: 'ADD_IMAGE_ERROR',
          error
        }); 
      });
  };
}
```

我们返回的函数首先通过不带有效负载的操作`ADD_IMAGE`来调度一个操作，因为我们只是想让 Redux 知道我们准备好发起网络请求将图像上传到我们的后端。然后，我们使用我们的`api`进行该请求（稍后我们将模拟这个调用）。这个请求将返回一个 promise，所以我们可以附加`.then`和`.catch`回调来处理响应。如果响应是积极的（图像被正确上传），我们将调度一个`ADD_IMAGE_SUCCESS`操作，传递上传图像的 URL。如果出现错误，我们将调度一个`ADD_IMAGE_ERROR`操作，涵盖所有可能的状态。

大多数 action creators 在**Redux**和**Thunk**中进行网络请求时都是以类似的方式工作。事实上，我们的 action `fetchImages`与`addImage`非常相似，只有一个例外：它需要检查是否传递了`userId`，并发出一组不同的操作，以便 reducers 可以相应地修改状态。让我们来看一下将处理所有这些操作的 reducers。

# Reducers

在 Redux 中，reducers 是负责在发生新操作时更新状态的函数。它们接收当前的`state`和操作（包括任何有效负载），并返回一个新的状态对象。我们不会深入研究 reducers 的工作原理，我们只需要了解它们的基本结构：

```jsx
/*** src/reducers/index ***/

const initialState = {
  images: null,
  userImages: null,
  error: null,
  user: {
    id: 78261,
    name: 'Sharer1',
    pic: 'https://cdn.pixabay.com/photo/2015/07/20/12/53/
          man-852762_960_720.jpg'
  }
}

export default function (state = initialState, action) {
  switch(action.type){
    case 'FETCH_IMAGES': 
      return Object.assign({}, state, {
        images: [],
        fetchingImages: true,
        error: null
      });
    case 'FETCH_IMAGES_SUCCESS': 
      return Object.assign({}, state, {
        fetchingImages: false,
        images: action.images,
        error: null
      });
    case 'FETCH_IMAGES_ERROR': 
      return Object.assign({}, state, {
        fetchingImages: false,
        images: null,
        error: action.error
      });
    case 'FETCH_USER_IMAGES': 
      return Object.assign({}, state, {
        userImages: [],
        fetchingUserImages: true,
        error: null
      });
    case 'FETCH_USER_IMAGES_SUCCESS': 
      return Object.assign({}, state, {
        fetchingUserImages: false,
        userImages: action.images,
        error: null
      });
    case 'FETCH_USER_IMAGES_ERROR': 
      return Object.assign({}, state, {
        fetchingUserImages: false,
        userImages: null,
        error: action.error
      });
    case 'ADD_IMAGE': 
      return Object.assign({}, state, {
        addingImage: true,
        error: null
      });
    case 'ADD_IMAGE_SUCCESS': 
      let image = {
        id: Math.floor(Math.random() * 99999999),
        src: action.imageSrc, 
        user: state.user
      }
      return Object.assign({}, state, {
        addingImage: false,
        images: [image].concat(state.images),
        userImages: [image].concat(state.images),
        error: null
      });
    case 'ADD_IMAGE_ERROR': 
      return Object.assign({}, state, {
        addingImage: false,
        error: action.error
      });
    default:
      return state;
  }
}
```

让我们来分解一下：

```jsx
const initialState = {
  images: null,
  userImages: null,
  error: null,
  user: {
    id: 78261,
    name: 'Sharer1',
    pic: 'https://cdn.pixabay.com/photo/2015/07/20/12/53/
          man-852762_960_720.jpg'
  }
}
```

我们从一个初始状态开始，其中所有属性都将设置为`null`，除了`user`，它将包含模拟用户数据。这个初始状态默认在启动时由 reducer 注入：

```jsx
export default function (state = initialState, action) {

  ...

}
```

在后续的调用中，Redux 将在应用任何操作后注入实际状态。在这个函数内部，我们有一个`switch`来评估每个触发的操作的类型，以根据该操作及其有效负载修改状态。例如，让我们来看一下`FETCH_IMAGES_SUCCESS`操作：

```jsx
case 'FETCH_IMAGES_SUCCESS': 
  return Object.assign({}, state, {
    fetchingImages: false,
    images: action.images,
    error: null
  });
```

Redux 中的一个规则是，减速器不应该改变状态，而是在触发动作后返回一个新对象。使用`Object.assign`，我们返回一个包含当前状态加上基于刚刚发生的动作的所需更改的新对象。在这种情况下，我们将`fetchingImages`标志设置为`false`，以便让我们的组件知道它们可以隐藏与获取图像动作相关的任何活动指示器。我们还将收到的图像列表（来自`actions.images`）设置在我们状态的`images`键中，以便它们可以被注入到需要它们的组件中。最后，我们将`error`标志设置为`null`，以隐藏由于先前状态而显示的任何错误。

正如我们之前提到的，每个异步操作都应该分成三个单独的动作来表示三种不同的状态：异步请求挂起，成功和出错。这样，我们将为我们的应用程序有三组动作：

+   `FETCH_IMAGES`，`FETCH_IMAGES_SUCCESS`和`FETCH_IMAGES_ERROR`

+   `FETCH_USER_IMAGES`，`FETCH_USER_IMAGES_SUCCESS`和`FETCH_USER_IMAGES_ERROR`

+   `ADD_IMAGE`，`ADD_IMAGE_SUCCESS`和`ADD_IMAGE_ERROR`

重要的是要注意，我们为`FETCH_IMAGES`和`FETCH_USER_IMAGES`有单独的情况，因为我们希望同时保留两个不同的图像列表：

+   包含用户正在关注的所有人的图像的通用列表

+   用户上传的图片列表

最后缺失的部分是从动作创建者调用的 API 调用。

# API

在现实世界的应用程序中，我们会将所有对后端的调用放在一个单独的`api`文件夹中。出于教育目的，我们只是模拟了对我们应用程序核心的两个 API 调用，`addImage`和`fetchImages`：

```jsx
/*** src/api/index ***/

export default {
  addImage: function(image) {
    return new Promise((resolve, reject) => {
      setTimeout(()=>{
        resolve( '<imgUrl>' );
      }, 3000)
    })
  },
  fetchImages: function(user = null){
    const images = [

      {id: 1, src: '<imgUrl>', user: {pic: '<imgUrl>', name: 'Naia'}},
      {id: 2, src: '<imgUrl>', user: {pic: '<imgUrl>', 
       name: 'Mike_1982'}},
      {id: 5, src: '<imgUrl>', user: {pic: '<imgUrl>', 
       name: 'Sharer1'}},
      {id: 3, src: '<imgUrl>', user: {pic: '<imgUrl>', name: 'Naia'}},
      {id: 6, src: '<imgUrl>', user: {pic: '<imgUrl>', 
       name: 'Sharer1'}},
      {id: 4, src: '<imgUrl>', user: {pic: '<imgUrl>', 
       name: 'Sharer1'}},
      {id: 7, src: '<imgUrl>', user: {pic: '<imgUrl>', 
       name: 'Sharer1'}}

    ]
    return new Promise((resolve, reject) => {
      setTimeout(()=>{
        resolve( images.filter(img => !user || user === img.user.name)   
      );
      }, 1500);
    })
  }
}
```

为了模拟网络延迟，我们添加了一些`setTimeouts`，这将有助于测试我们设置的用于显示用户网络活动的活动指示器。我们还使用了 promise 而不是普通的回调来使我们的代码更易于阅读。我们还在这些示例中跳过了图像 URL，以使其更简洁。

# 摘要

我们在这个应用程序中使用了 Redux，并且这塑造了我们使用的文件夹结构。虽然使用 Redux 需要一些样板代码，但它有助于以合理的方式拆分我们的代码库，并消除容器或屏幕之间的直接依赖关系。当我们需要在屏幕之间保持共享状态时，Redux 绝对是一个很好的补充，因此我们将在本书的其余部分继续使用它。在更复杂的应用程序中，我们需要构建更多的减速器，并可能按领域将它们分开并使用 Redux `combineReducers`。此外，我们需要添加更多的操作，并为每组操作创建单独的文件。例如，我们需要登录、注销和注册的操作，我们可以将它们放在名为`src/actions/user.js`的文件夹中。然后，我们应该将我们与图像相关的操作（目前在`index.js`中）移动到`src/actions/images.js`，这样我们就可以修改`src/actions/index.js`以将其用作用户和图像操作的组合器，以便在需要一次性导入所有操作时使用。

Redux 还有助于测试，因为它将应用程序的业务逻辑隔离到减速器中，因此我们可以专注于对其进行彻底测试。

模拟 API 调用使我们能够为我们的应用程序构建一个快速原型。当后端可用时，我们可以重用这些模型进行测试，并用真正的 HTTP 调用替换`src/api/index.js`。无论如何，最好为我们所有的 API 调用建立一个单独的文件夹，这样如果后端发生任何更改，我们就可以轻松地替换它们。

您还学会了如何构建特定平台的代码（在我们的案例中是特定于 Android），这对大多数应用程序来说是非常有用的功能。一些公司更喜欢为每个平台编写单独的应用程序，并且只重用它们的业务逻辑代码，在任何基于 Redux 的应用程序中都应该非常容易，因为它驻留在减速器中。

在 React Native 中没有特定的 API 来控制设备的相机，但我们可以使用`react-native-camera`模块来实现。这是一个访问 iOS 和 Android 本地 API 并在 React Native JavaScript 世界中公开它们的库的示例。

在我们的下一课中，我们将通过构建一个消息应用程序来探索和跨越 React Native 应用程序中本地和 JavaScript 世界之间的桥梁。

# 评估

1.  由 ______ 处理的操作只是纯函数，根据该操作对状态进行更改。

1.  查看器

1.  减速器

1.  导航器

1.  中间件

1.  Gallery 包含了所有图像列表的渲染逻辑。它依赖于 _____，更具体地说，依赖于它的两个组件，<List /> 和 <ListItem />。

1.  `native-base`

1.  `base-native`

1.  `resizeMode`

1.  `header`

1.  判断以下陈述是真还是假：每当在 Firebase 中存储新消息时，`this.selectedChatMessages` 将被同步以反映它。

1.  以下哪个是 `<TextInput/>` 的属性，当用户按下键盘上的 **Return** 或 **Next** 按钮时将被调用？

1.  `this.refs.loginPassword.focus()`

1.  `React.Component`

1.  `onSubmitEditing`

1.  `onChangeText`

1.  在将登录屏幕分成两个表单：<LoginForm /> 和 <RegistrationForm /> 时，需要传递哪三个属性组件？
