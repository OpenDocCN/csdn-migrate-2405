# React 全栈项目（五）

> 原文：[`zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB`](https://zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：开发基于 Web 的 VR 游戏

**虚拟现实**（**VR**）和**增强现实**（**AR**）技术的出现正在改变用户与软件以及周围世界的互动方式。VR 和 AR 的可能应用数不胜数，尽管游戏行业是早期采用者，但这些快速发展的技术有潜力在多个学科和行业中改变范式。

为了演示 MERN 堆栈与 React 360 如何轻松地为任何 Web 应用程序添加 VR 功能，我们将在本章和下一章中讨论和开发一个动态的基于 Web 的 VR 游戏。

通过涵盖以下主题，本章将重点定义 VR 游戏的特性，并使用 React 360 开发游戏视图：

+   VR 游戏规格

+   开发 3D VR 应用的关键概念

+   开始使用 React 360

+   定义游戏数据

+   实现游戏视图

+   将 React 360 代码捆绑以与 MERN 骨架集成

# MERN VR 游戏

MERN VR 游戏 Web 应用程序将通过扩展 MERN 骨架并使用 React 360 集成 VR 功能来开发。这将是一个动态的、基于 Web 的 VR 游戏应用程序，注册用户可以制作自己的游戏，任何访问应用程序的访客都可以玩这些游戏。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/7e939bf7-7e64-4628-851e-1699529a9d3e.png)

游戏本身的特性将足够简单，以展示将 VR 引入基于 MERN 的应用程序的能力，而不深入探讨 React 360 的高级概念，这些概念可能用于实现更复杂的 VR 功能。

使用 React 360 实现 VR 游戏功能的代码可在 GitHub 上找到，网址为[github.com/shamahoque/MERNVR](https://github.com/shamahoque/MERNVR)。您可以克隆此代码，并在本章的其余部分中阅读代码解释时运行应用程序。

# 游戏特性

MERN VR 游戏中的每个游戏基本上都是一个不同的 VR 世界，用户可以在 360 度全景世界中的不同位置与 3D 对象进行交互。

游戏玩法将类似于寻宝游戏，为了完成每个游戏，用户必须找到并收集与每个游戏的线索或描述相关的 3D 对象。这意味着游戏世界将包含一些可以被玩家收集的 VR 对象，以及一些无法被收集的 VR 对象，但可能被游戏制作者放置为道具或提示。

# 本章重点

在这一章中，我们将使用 React 360 构建游戏功能，重点关注实现之前定义的功能的相关概念。一旦游戏功能准备就绪，我们将讨论如何捆绑和准备 React 360 代码，以便与第十一章中开发的 MERN 应用程序代码集成，*使用 MERN 使 VR 游戏动态化*。

# React 360

React 360 使得可以使用 React 中相同的声明式和基于组件的方法构建 VR 体验。React 360 的底层技术利用了 Three.js JavaScript 3D 引擎，在任何兼容的 Web 浏览器中使用 WebGL 渲染 3D 图形，并且还可以通过 Web VR API 访问 VR 头显。

尽管 React 360 是建立在 React 和应用程序在浏览器中运行的基础上，但 React 360 与 React Native 有很多共同之处，因此使得 React 360 应用程序可以跨平台。这也意味着 React Native 的概念也适用于 React 360。涵盖所有 React 360 的概念超出了本书的范围，因此我们将专注于构建游戏和将其与 MERN 堆栈 Web 应用程序集成所需的概念。

# 开始使用 React 360

React 360 提供了开发工具，可以轻松开始开发新的 React 360 项目。开始的步骤在 React 360 文档中有详细说明，因此我们只会总结这些步骤，并指出与开发游戏相关的文件。

由于我们已经安装了用于 MERN 应用程序的 Node，我们可以开始安装 React 360 CLI 工具：

```jsx
npm install -g react-360-cli
```

使用这个 React 360 CLI 工具创建一个新的应用程序并安装所需的依赖。

```jsx
react-360 init MERNVR
```

这将在当前目录中的一个名为`MERNVR`的文件夹中添加所有必要的文件。最后，我们可以在命令行中进入这个文件夹，并运行应用程序：

```jsx
npm start
```

`start`命令将初始化本地开发服务器，并且默认的 React 360 应用程序可以在浏览器中查看，网址为`http://localhost:8081/index.html`。

为了更新起始应用程序并实现我们的游戏功能，我们将主要修改`index.js`文件中的代码，并在`MERNVR`项目文件夹中的`client.js`文件中进行一些小的更新。

起始应用程序中`index.js`中的默认代码应该如下，它在浏览器中的 360 世界中呈现了一个“欢迎来到 React 360”的文本：

```jsx
import React from 'react'
import { AppRegistry, StyleSheet, Text, View } from 'react-360'

export default class MERNVR extends React.Component {
  render() {
    return (
      <View style={styles.panel}>
        <View style={styles.greetingBox}>
          <Text style={styles.greeting}>
            Welcome to React 360
          </Text>
        </View>
      </View>
    )
  }
}

const styles = StyleSheet.create({
  panel: {
    // Fill the entire surface
    width: 1000,
    height: 600,
    backgroundColor: 'rgba(255, 255, 255, 0.4)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  greetingBox: {
    padding: 20,
    backgroundColor: '#000000',
    borderColor: '#639dda',
    borderWidth: 2,
  },
  greeting: {
    fontSize: 30,
  }
})

AppRegistry.registerComponent('MERNVR', () => MERNVR)
```

这个`index.js`文件包含了应用的内容和主要代码。`client.js`中的代码包含了将浏览器连接到`index.js`中的 React 应用程序的样板。在起始项目文件夹中的默认`client.js`应该如下所示：

```jsx
import {ReactInstance} from 'react-360-web'

function init(bundle, parent, options = {}) {
  const r360 = new ReactInstance(bundle, parent, {
    // Add custom options here
    fullScreen: true,
    ...options,
  })

  // Render your app content to the default cylinder surface
  r360.renderToSurface(
    r360.createRoot('MERNVR', { /* initial props */ }),
    r360.getDefaultSurface()
  )

  // Load the initial environment
  r360.compositor.setBackground(r360.getAssetURL('360_world.jpg'))
}

window.React360 = {init}
```

这段代码基本上执行了`index.js`中定义的 React 代码，实质上创建了 React 360 的一个新实例，并通过将其附加到 DOM 来加载 React 代码。

在默认的 React 360 项目设置完成之后，在修改代码以实现游戏之前，我们将首先了解一些与开发 3D VR 体验相关的关键概念，以及这些概念如何在 React 360 中应用。

# 开发 VR 游戏的关键概念

在为游戏创建 VR 内容和交互式 360 度体验之前，首先要了解虚拟世界的一些关键方面，以及 React 360 组件如何与这些 VR 概念一起使用。

# 等距矩形全景图像

游戏的 VR 世界将由一个全景图像组成，该图像将被添加到 React 360 环境中作为背景图像。

全景图像通常是投影到完全环绕观众的球体上的 360 度图像或球形全景图像。360 度全景图像的常见和流行格式是等距矩形格式。React 360 目前支持等距矩形图像的单眼和立体格式。

要了解有关 React 360 中 360 度图像和视频支持的更多信息，请参考 React 360 文档，网址为[facebook.github.io/react-360/docs/setup.html](https://facebook.github.io/react-360/docs/setup.html)。

这里显示的图像是一个等距矩形的 360 度全景图像的示例。为了在 MERN VR 游戏中设置游戏的世界背景，我们将使用这种类型的图像。

等距矩形全景图像由一个宽高比为 2:1 的单个图像组成，其中宽度是高度的两倍。这些图像是用特殊的 360 度相机创建的。等距矩形图像的一个很好的来源是 Flickr，您只需要搜索“等距矩形”标签。

通过在 React 360 环境中使用等距投影图像来设置背景场景，可以使 VR 体验更加沉浸，将用户带到虚拟位置。为了增强这种体验并有效地在这个 VR 世界中添加 3D 对象，我们需要更多地了解与 3D 空间相关的布局和坐标系统。

# 3D 位置 - 坐标和变换

我们需要了解 VR 世界空间中的位置和方向，以便将 3D 对象放置在所需位置，并使 VR 体验更加真实。

# 3D 坐标系统

为了在 3D 空间中进行映射，React 360 使用了类似于 OpenGL® 3D 坐标系统的三维米制坐标系统，允许单独的组件相对于其父组件的布局进行变换、移动或旋转。

React 360 中使用的 3D 坐标系统是右手坐标系。这意味着正 x 轴在右侧，正 y 轴向上，正 z 轴向后。这与世界空间中常见的坐标系统有更好的映射。

如果我们试图可视化 3D 空间，用户从下一张图中所示的**X-Y-Z**轴的中心开始。**Z**轴指向用户前方，用户朝着**-Z**轴方向观看。**Y**轴上下运行，而**X**轴从一侧到另一侧运行。

图像中的弯曲箭头显示了正旋转值的方向：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/df215bc6-9a8f-4dfa-8e14-65b6d6f120d0.png)

# 变换

在以下两个图像中，通过改变渲染 3D 对象的 React 360 `Entity`组件的样式属性中的`transform`属性，将 3D 书籍对象放置在两个不同的位置和方向。这里的变换是基于 React 的变换样式，React 360 将其扩展为完全的 3D，考虑 X-Y-Z 轴：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c060ac74-3a84-4efe-8860-83ea3c525d15.png)

`transform`属性被添加到`style`属性中的组件中，形式如下的键和值数组：

```jsx
style={{ ...
          transform: [ 
            {TRANSFORM_COMMAND: TRANSFORM_VALUE},
         ...
    ] 
... }}
```

与我们游戏中放置的 3D 对象相关的变换命令和值是`translate [x, y, z]`，单位为米，`rotate [x, y, z]`，单位为度，以及`scale`，用于确定对象在所有轴上的大小。我们还将利用矩阵命令，它接受一个由表示平移、旋转和缩放值的 16 个数字组成的数组作为值。

要了解更多关于 React 360 3D 坐标和变换的信息，请查看 React 360 文档[facebook.github.io/react-360/docs/setup.html](https://facebook.github.io/react-360/docs/setup.html)。

# React 360 组件

React 360 提供了一系列组件，可以直接用来创建游戏的 VR 用户界面。接下来，我们将总结将用于构建游戏功能的特定组件。

# 核心组件

React 360 的核心组件包括 React Native 内置的组件：`Text`和`View`。在游戏中，我们将使用这两个组件来添加游戏世界中的内容。

# 视图

`View`组件是在 React Native 中构建用户界面最基本的组件，它直接映射到 React Native 运行平台上的本地视图等效物。在我们的情况下，在浏览器上将是`<div>`：

```jsx
<View>
  <Text>Hello</Text>
</View>
```

`View`组件通常用作其他组件的容器，它可以嵌套在其他视图中，并且可以有零到多个任何类型的子元素。

我们将使用`View`组件来容纳游戏世界的视图，并向游戏中添加 3D 对象实体和文本。

# 文本

`Text`组件是一个用于显示文本的 React Native 组件，我们将使用它在 3D 空间中呈现字符串，通过将`Text`组件放置在`View`组件中：

```jsx
<View>
      <Text>Welcome to the MERN VR Game</Text>
</View>
```

# 用于 3D VR 体验的组件

React 360 提供了一组自己的组件来创建 VR 体验。具体来说，我们将使用`Entity`组件来添加 3D 对象，使用`VrButton`组件来捕获用户的点击。

# 实体

为了将 3D 对象添加到游戏世界中，我们将使用`Entity`组件，它允许我们在 React 360 中渲染 3D 对象：

```jsx
<Entity
  source={{
           obj: {uri: "http://linktoOBJfile.obj "},
           mtl: {uri: "http://linktoMTLfile.obj "}
        }}
/>
```

包含特定 3D 对象信息的文件被添加到`Entity`组件中，使用`source`属性。源属性接受一个键值对对象，将资源文件类型映射到它们的位置。React 360 支持 Wavefront OBJ 文件格式，这是一种常见的 3D 模型表示。因此，在源属性中，`Entity`组件支持以下键：

+   `obj`：OBJ 格式模型的位置

+   `mtl`：MTL 格式材质的位置（OBJ 的伴侣）

`obj`和`mtl`属性的值指向这些文件的位置，可以是静态字符串，`asset()`调用，`require()`语句或 URI 字符串。

OBJ（或.OBJ）是由 Wavefront Technologies 首次开发的几何定义文件格式。它是一种简单的数据格式，将 3D 几何表示为顶点和纹理顶点的列表。OBJ 坐标没有单位，但 OBJ 文件可以包含人类可读的注释行中的比例信息。在[paulbourke.net/dataformats/obj/](http://paulbourke.net/dataformats/obj/)了解更多关于这种格式的信息。MTL（或.MTL）是包含一个或多个材质定义的材质库文件，每个材质定义都包括单个材质的颜色、纹理和反射贴图。这些应用于对象的表面和顶点。在[paulbourke.net/dataformats/mtl/](http://paulbourke.net/dataformats/mtl/)了解更多关于这种格式的信息。

`Entity`组件还在`style`属性中接受`transform`属性值，因此可以将对象放置在所需的位置和方向上的 3D 世界空间中。在我们的 MERN VR 游戏应用中，制作者将为游戏中的每个`Entity`对象添加指向 VR 对象文件（`.obj`和`.mtl`）的 URL，并指定`transform`属性值，以指示 3D 对象应该在游戏世界中放置在何处以及如何放置。

3D 对象的一个很好的来源是[`clara.io/`](https://clara.io/)，提供多种文件格式可供下载和使用。

# VrButton

在 React 360 中，`VrButton`组件将帮助实现简单的、按钮样式的`onClick`行为，这些按钮将被添加到游戏中。`VrButton`默认情况下在视图中不可见，只会作为一个包装器来捕获事件，但它可以以与`View`组件相同的方式进行样式设置：

```jsx
<VrButton onClick={this.clickHandler}>
        <View>
            <Text>Click me to make something happen!</Text>
        </View>
 </VrButton>
```

该组件是一个辅助工具，用于管理用户在不同输入设备上的点击类型交互。将触发点击事件的输入事件包括键盘上的空格键按下，鼠标上的左键单击以及屏幕上的触摸。

# React 360 API

除了之前讨论的 React 360 组件，我们还将利用 React 360 提供的 API 来实现功能，比如设置背景场景、播放音频、处理外部链接、添加样式、捕捉用户视图的当前方向，以及使用静态资源文件。

# 环境

我们将使用`Environment` API 来从 React 代码中改变背景场景，使用它的`setBackgroundImage`方法：

```jsx
Environment.setBackgroundImage( {uri: 'http://linktopanoramaimage.jpg' } )
```

这个方法使用指定 URL 的资源来设置当前背景图像。当我们将 React 360 游戏代码与包含游戏应用后端的 MERN 堆栈集成时，我们可以使用这个方法来动态设置游戏世界图像，使用用户提供的图像链接。

# 本地模块

React 360 中的本地模块提供了访问主浏览器环境中可用功能的能力。在游戏中，我们将使用本地模块中的`AudioModule`来响应用户活动播放声音，以及`Location`模块来处理浏览器中的`window.location`以处理外部链接。这些模块可以在`index.js`中如下访问：

```jsx
import {
    ...
  NativeModules
} from 'react-360'

const { AudioModule, Location } = NativeModules
```

# AudioModule

当用户与 3D 对象交互时，我们将根据对象是否可以收集以及游戏是否已经完成来播放声音。本地模块中的`AudioModule`允许将声音添加到 VR 世界中，作为背景环境音频、一次性音效和空间音频。在我们的游戏中，我们将使用环境音频和一次性音效。

+   **环境音频**：为了在游戏成功完成时循环播放音频并设置心情，我们将使用`playEnvironmental`方法，它需要一个音频文件路径作为`source`，并且`loop`选项作为`playback`参数：

```jsx
AudioModule.playEnvironmental({
    source: asset('happy-bot.mp3'),
    loop: true
})
```

+   **音效**：为了在用户点击 3D 对象时播放一次单一声音，我们将使用`playOneShot`方法，它需要一个音频文件路径作为`source`：

```jsx
AudioModule.playOneShot({
    source: asset('clog-up.mp3'),
})
```

传递给`playEnvironmental`和`playOneShot`的选项中的`source`属性需要一个资源文件位置来加载音频。它可以是一个`asset()`语句，或者是一个资源 URL 声明，形式为`{uri: 'PATH'}`。

# Location

在我们将 React 360 代码与包含游戏应用后端的 MERN 堆栈集成后，VR 游戏将从 MERN 服务器在包含特定游戏 ID 的声明路由上启动。然后，一旦用户完成游戏，他们还可以选择离开 VR 空间，转到包含其他游戏列表的 URL。为了处理 React 360 代码中的这些传入和传出应用链接，我们将利用本地模块中的`Location`模块。

`Location`模块本质上是浏览器中只读的`window.location`属性返回的`Location`对象。我们将使用`Location`对象中的`replace`方法和`search`属性来实现与外部链接相关的功能。

+   **处理传出链接**：当我们想要将用户从 VR 应用程序引导到另一个链接时，我们可以在`Location`中使用`replace`方法：

```jsx
Location.replace(url)
```

+   **处理传入链接**：当 React 360 应用从外部 URL 启动并在注册的组件挂载后，我们可以访问 URL 并使用`Location`中的`search`属性检索其查询字符串部分：

```jsx
componentDidMount = () => {
   let queryString = Location.search
   let gameId = queryString.split('?id=')[1]
}
```

为了将这个 React 360 组件与 MERN VR 游戏集成，并动态加载游戏详情，我们将捕获这个初始 URL，从查询参数中解析游戏 ID，然后使用它来调用 MERN 应用服务器的读取 API。这个实现在第十一章中有详细说明，*使用 MERN 使 VR 游戏动态化*。

# StyleSheet

React Native 中的 StyleSheet API 也可以在 React 360 中使用，以便在一个地方定义多个样式，而不是将样式添加到单个组件中：

```jsx
const styles = StyleSheet.create({
  subView: {
    width: 10,
    borderColor: '#d6d7da',
  },
  text: {
    fontSize: '1em',
    fontWeight: 'bold',
  }
})
```

定义的样式可以根据需要添加到组件中：

```jsx
<View style={styles.subView}>
  <Text style={styles.text}>hello</Text>
</View>
```

在 React 360 中，用于 CSS 属性（如宽度和高度）的默认距离单位是米，而在 2D 界面中（如 React Native 中），默认距离单位是像素。

# VrHeadModel

`VrHeadModel`是 React 360 中的一个实用模块，它简化了获取头盔当前方向的操作。由于用户在 VR 空间中移动，当所需功能需要将对象或文本放置在用户当前方向的前面或相对于用户当前方向时，有必要知道用户当前凝视的确切位置。

在 MERN VR 游戏中，我们将使用它在用户的视野前显示游戏完成消息，无论他们从初始位置转向何处。

例如，用户可能在收集最终对象时向上或向下看，完成消息应该在用户注视的位置弹出。为了实现这一点，我们将使用`VrHeadModel`中的`getHeadMatrix()`将当前头部矩阵作为数字数组检索出来，并将其设置为包含游戏完成消息的`View`的样式属性中的`transform`属性的值。

# 资产

在 React 360 中，`asset()`功能允许我们检索外部资源文件，如音频和图像文件。我们将把游戏的声音音频文件放在`static_assets`文件夹中，以便使用`asset()`检索每个添加到游戏中的音频：

```jsx
AudioModule.playOneShot({
    source: asset('collect.mp3'),
})
```

# React 360 输入事件

为了使游戏界面具有交互性，我们将利用 React 360 中暴露的一些输入事件处理程序。输入事件来自鼠标、键盘、触摸和游戏手柄交互，还有 VR 头盔上的`凝视`按钮点击。我们将处理的具体输入事件是`onEnter`、`onExit`和`onClick`事件。

+   **onEnter**：每当平台光标开始与组件相交时，就会触发此事件。我们将捕获此事件用于游戏中的 VR 对象，这样当平台光标进入特定对象时，对象就可以开始围绕 Y 轴旋转。

+   **onExit**：每当平台光标停止与组件相交时，就会触发此事件。它具有与`onEnter`事件相同的属性，我们将使用它来停止旋转刚刚退出的 VR 对象。

+   **onClick**：`onClick`事件与`VrButton`组件一起使用，当与`VrButton`进行点击交互时触发。我们将使用它在 VR 对象上设置点击事件处理程序，还有在游戏完成消息上，以将用户重定向到包含游戏列表的链接，从而退出 VR 应用程序。

通过本节讨论的与 VR 相关的概念和 React 360 组件，我们已经准备好定义游戏数据细节并开始实现完整的 VR 游戏。

# 游戏详情

MERN VR 游戏中的每个游戏都将在一个通用数据结构中定义，当渲染各个游戏细节时，React 360 应用程序也将遵循这一结构。

# 游戏数据结构

游戏数据结构将保存游戏名称、指向游戏世界等距投影图像位置的 URL，以及包含每个 VR 对象的详细信息的两个数组：

+   **name**：表示游戏名称的字符串

+   **world**：一个字符串，其中包含指向等距投影图像的 URL，可以是存储在云存储、CDN 上的文件，或存储在 MongoDB 上的文件

+   **answerObjects**：包含可以被玩家收集的 VR 对象详细信息的对象数组

+   **wrongObjects**：包含其他 VR 对象详细信息的对象数组，这些对象将放置在 VR 世界中，玩家无法收集

# VR 对象的详细信息

`answerObjects`数组将包含可以被收集的 3D 对象的详细信息，`wrongObjects`数组将包含无法被收集的 3D 对象的详细信息。每个对象将包含到 3D 数据资源文件和`transform`样式属性值的链接。

# OBJ 和 MTL 链接

VR 对象的 3D 数据信息资源将添加在`objUrl`和`mtlUrl`键中：

+   **objUrl**：3D 对象的`.obj`文件的链接

+   **mtlUrl**：附带的`.mtl`文件的链接

`objUrl`和`mtlUrl`链接可能指向存储在云存储、CDN 上的文件，或存储在 MongoDB 上的文件。对于 MERN VR 游戏，我们将假设制作者将向他们自己托管的 OBJ、MTL 和等距投影图像文件添加 URL。

# 平移数值

VR 对象在 3D 空间中的位置将由以下键中的`translate`值定义：

+   **translateX**：对象沿 X 轴的平移值

+   **translateY**：对象沿 Y 轴的平移值

+   **translateZ**：对象沿 Z 轴的平移值

所有平移数值都是以米为单位的数字。

# 旋转数值

3D 对象的方向将由以下键中的`rotate`值定义：

+   **rotateX**：绕 X 轴的旋转值，换句话说，将对象向上或向下旋转

+   **rotateY**：绕 Y 轴的旋转值，将对象向左或向右旋转

+   **rotateZ**：绕 Z 轴的旋转值，使对象向前或向后倾斜

所有旋转数值都以度数的数字或字符串表示。

# 比例值

`scale`值将定义 3D 对象的相对大小外观：

**scale**：定义所有轴上的均匀比例的数字值

# 颜色

如果 3D 对象的材质纹理没有在 MTL 文件中提供，颜色值可以定义对象的默认颜色。

**color**：表示 CSS 中允许的颜色值的字符串值

有了这个游戏数据结构，能够保存游戏及其 VR 对象的详细信息，我们可以相应地使用示例数据值在 React 360 中实现游戏。

# 静态数据与动态数据

在下一章中，我们将更新 React 360 代码，以动态从后端数据库获取游戏数据。目前，我们将从定义的游戏数据结构中设置虚拟游戏数据到`state`中开始在这里开发游戏功能。

# 示例数据

为了初始开发目的，以下示例游戏数据可以设置为状态以在游戏视图中呈现：

```jsx
game: {
  name: 'Space Exploration',
  world: 'https://s3.amazonaws.com/mernbook/vrGame/milkyway.jpg',
  answerObjects: [
    { 
      objUrl: 'https://s3.amazonaws.com/mernbook/vrGame/planet.obj',
      mtlUrl: 'https://s3.amazonaws.com/mernbook/vrGame/planet.mtl',
      translateX: -50,
      translateY: 0,
      translateZ: 30,
      rotateX: 0,
      rotateY: 0,
      rotateZ: 0,
      scale: 7,
      color: 'white'
    }
  ],
  wrongObjects: [
    { 
      objUrl: 'https://s3.amazonaws.com/mernbook/vrGame/tardis.obj',
      mtlUrl: 'https://s3.amazonaws.com/mernbook/vrGame/tardis.mtl',
      translateX: 0,
      translateY: 0,
      translateZ: 90,
      rotateX: 0,
      rotateY: 20,
      rotateZ: 0,
      scale: 1,
      color: 'white'
    }
  ]
}
```

# 在 React 360 中构建游戏视图

我们将应用 React 360 的概念，并使用游戏数据结构来通过更新`index.js`和`client.js`中的代码来实现游戏功能。为了获得一个可工作的版本，我们将从上一节中使用示例游戏数据初始化状态开始。

`/MERNVR/index.js`：

```jsx
export default class MERNVR extends React.Component {

    constructor() {
        super()
        this.state = {
                game: sampleGameData
                ...
            }
    }

...
}
```

# 更新 client.js 并挂载到 Location

`client.js`中的默认代码将在 React 360 应用中将在`index.js`中声明的挂载点附加到默认表面上，其中表面是用于放置 2D UI 的圆柱形图层。为了在 3D 空间中使用基于 3D 米的坐标系进行布局，我们需要挂载到`Location`而不是表面。因此，更新`client.js`以用`renderToLocation`替换`renderToSurface`。

`/MERNVR/client.js`：

```jsx
  r360.renderToLocation(
    r360.createRoot('MERNVR', { /* initial props */ }),
    r360.getDefaultLocation()
  )
```

您还可以通过更新`client.js`中的代码`r360.compositor.setBackground(**r360.getAssetURL('360_world.jpg')**)`来使用您想要的图像来自定义初始背景场景。

# 使用 StyleSheet 定义样式

在`index.js`中，我们将使用我们自己的 CSS 规则更新使用`StyleSheet.create`创建的默认样式，以用于游戏中的组件。

`/MERNVR/index.js`：

```jsx
const styles = StyleSheet.create({
                 completeMessage: {
                      margin: 0.1,
                      height: 1.5,
                      backgroundColor: 'green',
                      transform: [ {translate: [0, 0, -5] } ]
                 },
                 congratsText: {
                      fontSize: 0.5,
                      textAlign: 'center',
                      marginTop: 0.2
                 },
                 collectedText: {
                      fontSize: 0.2,
                      textAlign: 'center'
                 },
                 button: {
                      margin: 0.1,
                      height: 0.5,
                      backgroundColor: 'blue',
                      transform: [ { translate: [0, 0, -5] } ]
                 },
                 buttonText: {
                      fontSize: 0.3,
                      textAlign: 'center'
                 }
              }) 
```

# 世界背景

为了设置游戏的 360 度世界背景，我们将使用`componentDidMount`中的`Environment` API 的`setBackgroundImage`方法来更新当前背景场景。

`/MERNVR/index.js`：

```jsx
componentDidMount = () => {
    Environment.setBackgroundImage(
      {uri: this.state.game.world}
    )
}
```

这将用我们从云存储中获取的示例游戏世界图像替换起始 React 360 项目中的默认 360 背景。如果您正在编辑默认的 React 360 应用程序并且它正在运行，刷新浏览器上的`http://localhost:8081/index.html`链接应该显示一个外太空背景，可以使用鼠标在周围移动：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/84ae5823-42b5-4dae-b5d9-9cfb878804ee.png)

为了生成上述截图，还更新了默认代码中的`View`和`Text`组件，使用自定义 CSS 规则在屏幕上显示这个 hello 文本。

# 添加 3D VR 对象

我们将使用`Entity`组件和`answerObjects`和`wrongObjects`数组中的示例对象详细信息向游戏世界添加 3D 对象。

首先，我们将在`componentDidMount`中连接`answerObjects`和`wrongObjects`数组，形成一个包含所有 VR 对象的单个数组。

`/MERNVR/index.js`：

```jsx
componentDidMount = () => {
  let vrObjects = this.state.game.answerObjects.concat(this.state.game.wrongObjects)
  this.setState({vrObjects: vrObjects}) 
    ...
}
```

然后在主视图中，我们将遍历`vrObjects`数组，添加每个对象的`Entity`组件详细信息。

`/MERNVR/index.js`：

```jsx
{this.state.vrObjects.map((vrObject, i) => {
     return (
                <Entity key={i} style={this.setModelStyles(vrObject, i)}
                  source={{
                    obj: {uri: vrObject.objUrl},
                    mtl: {uri: vrObject.mtlUrl}
                  }}
                 />
            )
    })
}
```

`obj`和`mtl`文件链接被添加到`source`中，并且`transform`样式细节在`Entity`组件的样式中应用`setModelStyles(vrObject, index)`。

`/MERNVR/index.js`：

```jsx
setModelStyles = (vrObject, index) => {
    return {
        display: this.state.collectedList[index] ? 'none' : 'flex',
        color: vrObject.color,
        transform: [
          {
            translateX: vrObject.translateX
          }, { 
            translateY: vrObject.translateY
          }, {
            translateZ: vrObject.translateZ
          }, {
            scale: vrObject.scale
          }, {
            rotateY: vrObject.rotateY
          }, {
            rotateX: vrObject.rotateX
          }, {
            rotateZ: vrObject.rotateZ
          }
        ]
      }
  }
```

`display`属性将允许我们根据玩家是否已经收集了对象来显示或隐藏对象。

`translate`和`rotate`值将在 VR 世界中呈现所需位置和方向的 3D 对象。

接下来，我们将进一步更新`Entity`代码，以使用户可以与 3D 对象进行交互。

# 与 VR 对象交互

为了使 VR 游戏对象具有交互性，我们将使用 React 360 事件处理程序，如`onEnter`和`onExit`与`Entity`，以及`VrButton`的`onClick`，添加旋转动画和游戏行为。

# 旋转

我们希望添加一个功能，当玩家关注 3D 对象时，即平台光标开始与渲染特定 3D 对象的`Entity`相交时，开始围绕其 Y 轴旋转 3D 对象。

我们将更新上一节中的`Entity`组件，添加`onEnter`和`onExit`处理程序。

`/MERNVR/index.js`：

```jsx
<Entity 
     ... 
    onEnter={this.rotate(i)}
    onExit={this.stopRotate}
/>
```

当进入对象时，对象将开始旋转，并且当平台光标退出对象并且不再处于玩家的焦点时，对象将停止旋转。

# 使用 requestAnimationFrame 进行动画

在`rotate(index)`和`stopRotate()`方法中，我们将使用`requestAnimationFrame`实现旋转动画行为，以实现浏览器上的流畅动画。

`window.requestAnimationFrame()`方法要求浏览器在下一次重绘之前调用指定的回调函数来更新动画。使用`requestAnimationFrame`，浏览器优化动画，使其更流畅和更节省资源。

使用`rotate`方法，我们将使用`requestAnimationFrame`在一定的时间间隔内以稳定的速率更新给定对象的`rotateY`变换值。

`/MERNVR/index.js`：

```jsx
this.lastUpdate = Date.now() 
rotate = index => event => {
    const now = Date.now()
    const diff = now - this.lastUpdate
    const vrObjects = this.state.vrObjects
    vrObjects[index].rotateY = vrObjects[index].rotateY + diff / 200
    this.lastUpdate = now
    this.setState({vrObjects: vrObjects})
    this.requestID = requestAnimationFrame(this.rotate(index)) 
}
```

`requestAnimationFrame`将以`rotate`方法作为递归回调函数，然后执行它以重新绘制旋转动画的每一帧，并依次更新屏幕上的动画。

`requestAnimateFrame`方法返回一个`requestID`，我们将在`stopRotate`中使用它来取消`stopRotate`方法中的动画。

`/MERNVR/index.js`：

```jsx
stopRotate = () => {
  if (this.requestID) {
    cancelAnimationFrame(this.requestID) 
    this.requestID = null 
  }
}
```

这将实现仅当 3D 对象处于观看者焦点时才对其进行动画处理。如下图所示，3D 魔方在焦点时沿其 Y 轴顺时针旋转：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/964de90f-5066-4af4-a817-058f9b65989a.png)虽然这里没有涉及，但值得探索的是 React 360 动画库，它可以用于组合不同类型的动画。核心组件可以使用此库本地进行动画处理，并且可以使用`createAnimatedComponent()`使其他组件可动画化。该库最初是从 React Native 实现的，要了解更多信息，可以参考 React Native 文档。

# 点击 3D 对象

为了在游戏中注册对添加到游戏中的每个 3D 对象的点击行为，我们需要用`VrButton`组件包装`Entity`组件，以便调用`onClick`处理程序。

我们将更新`vrObjects`数组迭代代码中添加的`Entity`组件，以用`VrButton`组件包装它。当单击时，`VrButton`将调用`collectItem`方法，并传递当前对象的详细信息。

`/MERNVR/index.js`：

```jsx
<VrButton onClick={this.collectItem(vrObject)} key={i}>
    <Entity … />
</VrButton>
```

当单击 3D 对象时，`collectItem`方法需要执行以下与游戏功能相关的操作：

+   检查单击的对象是`answerObject`还是`wrongObject`

+   根据对象类型播放相关的声音

+   如果对象是`answerObject`，则应收集并从视图中消失

+   更新收集的对象列表

+   检查是否成功收集了所有`answerObject`的实例

+   如果是，向玩家显示游戏完成消息，并播放游戏完成的声音

因此，`collectItem`方法将具有以下结构和步骤：

```jsx
collectItem = vrObject => event => {
  if (vrObject is an answerObject) {
     ... update collected list ...
     ... play sound for correct object collected ...
     if (all answer objects collected) {
         ... show game completed message in front of user ...
         ... play sound for game completed ...
     }
  } else {
     ... play sound for wrong object clicked ...
  }
}
```

接下来，我们将看一下这些步骤的实现。

# 点击收集正确的对象

当用户点击 3D 对象时，我们首先需要检查点击的对象是否是一个答案对象。如果是，这个*收集*对象将从视图中隐藏，并且收集对象的列表将被更新，以及用于跟踪用户在游戏中进度的总数。

为了检查点击的 VR 对象是否是`answerObject`，我们将使用`indexOf`方法在`answerObjects`数组中查找匹配项：

```jsx
let match = this.state.game.answerObjects.indexOf(vrObject) 
```

如果`vrObject`是`answerObject`，`indexOf`将返回匹配对象的数组索引，否则如果找不到匹配项，则返回`-1`。

为了跟踪游戏中收集的对象，我们还将在`collectedList`中维护一个布尔值数组，并在`collectedNum`中记录到目前为止收集的对象总数：

```jsx
let updateCollectedList = this.state.collectedList 
let updateCollectedNum = this.state.collectedNum + 1 
updateCollectedList[match] = true 
this.setState({collectedList: updateCollectedList, 
                collectedNum: updateCollectedNum}) 
```

使用`collectedList`数组，我们还将确定哪个`Entity`组件应该从视图中隐藏，因为相关的对象已被收集。`Entity`的`display`样式属性将根据`collectedList`数组中相应索引的布尔值进行设置，同时使用`setModelStyles`方法设置`Entity`组件的样式，就像在*添加 3D VR 对象*部分中所示的那样：

```jsx
display: this.state.collectedList[index] ? 'none' : 'flex'
```

在下图中，宝箱可以被点击收集，因为它是一个`answerObject`，而花盆不能被收集，因为它是一个`wrongObject`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a24e207b-ab10-4470-a0e4-4aa47c33fc0a.png)

当点击宝箱时，宝箱从视图中消失，因为`collectedList`被更新，我们还使用`AudioModule.playOneShot`播放收集的声音效果：

```jsx
AudioModule.playOneShot({
    source: asset('collect.mp3'),
}) 
```

但是当花盆被点击，并且被确定为错误对象时，我们会播放另一个声音效果，指示它不能被收集：

```jsx
AudioModule.playOneShot({
     source: asset('clog-up.mp3'),
})
```

由于花盆被确定为错误对象，`collectedList`没有被更新，它仍然显示在屏幕上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c8f40ddb-babd-44cf-8270-3966e0440f1d.png)

当点击对象时，`collectItem`方法中执行所有这些步骤的完整代码将如下所示。

`/MERNVR/index.js`：

```jsx
  collectItem = vrObject => event => {
    let match = this.state.game.answerObjects.indexOf(vrObject)
    if (match != -1) {
      let updateCollectedList = this.state.collectedList
      let updateCollectedNum = this.state.collectedNum + 1
      updateCollectedList[match] = true
      this.checkGameCompleteStatus(updateCollectedNum)
          AudioModule.playOneShot({
            source: asset('collect.mp3'),
          })
      this.setState({collectedList: updateCollectedList, collectedNum: updateCollectedNum})
    } else {
      AudioModule.playOneShot({
        source: asset('clog-up.mp3'),
      })
    }
  }
```

在收集了一个点击的对象之后，我们还将检查是否已收集了所有的`answerObjects`，并且游戏是否已经完成了`checkGameCompleteStatus`方法，如下一节所讨论的那样。

# 游戏完成状态

每次收集一个`answerObject`时，我们将检查收集的物品总数是否等于`answerObjects`数组中的物品总数，以确定是否通过调用`checkGameCompleteStatus`完成游戏。

`/MERNVR/index.js`：

```jsx
 if (collectedTotal == this.state.game.answerObjects.length) {
    AudioModule.playEnvironmental({
       source: asset('happy-bot.mp3'),
       loop: true
    })
    this.setState({hide: 'flex', hmMatrix: VrHeadModel.getHeadMatrix()})
 }
```

如果游戏确实已经完成，我们将执行以下操作：

+   播放游戏完成的音频，使用`AudioModule.playEnvironmental`

+   使用`VrHeadModel`获取当前的`headMatrix`值，以便将其设置为包含游戏完成消息的`View`组件的变换矩阵值

+   将消息`View`的`display`样式属性设置为`flex`，以便消息呈现给观众

包含祝贺玩家完成游戏的`View`组件将被添加到父`View`组件中，如下所示。

`/MERNVR/index.js`：

```jsx
<View style={this.setGameCompletedStyle}>
   <View style={this.styles.completeMessage}>
      <Text style={this.styles.congratsText}>Congratulations!</Text>
      <Text style={this.styles.collectedText}>
            You have collected all items in {this.state.game.name}
      </Text>
   </View>
   <VrButton onClick={this.exitGame}>
      <View style={this.styles.button}>
          <Text style={this.styles.buttonText}>Play another game</Text>
      </View>
   </VrButton>
</View>
```

调用“setGameCompletedStyle（）”方法将为带有更新的`display`值和`transform`矩阵值的消息`View`设置样式。

`/MERNVR/index.js`：

```jsx
setGameCompletedStyle = () => {
    return {
        position: 'absolute',
        display: this.state.hide,
        layoutOrigin: [0.5, 0.5],
        width: 6,
        transform: [{translate: [0, 0, 0]}, {matrix: this.state.hmMatrix}]
      }
}
```

这将在用户当前视图的中心呈现带有完成消息的`View`，无论他们是向上、向下、向后还是向前在 360 度 VR 世界中看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/895c5e99-6682-46fc-8b56-062dfd0f2fbf.png)

`View`消息中的最终文本将作为按钮，因为我们将这个`View`包装在一个`VrButton`组件中，当点击时调用`exitGame`方法。

`/MERNVR/index.js`：

```jsx
exitGame = () => {
    Location.replace('/') 
}
```

`exitGame`方法将使用`Location.replace`方法将用户重定向到可能包含游戏列表的外部 URL。

`replace`方法可以传递任何有效的 URL，一旦这个 React 360 游戏代码与第十一章中的 MERN VR 游戏应用集成，`replace('/')`将把用户带到应用程序的主页。

# 生产捆绑和与 MERN 集成

现在我们已经实现了 VR 游戏的功能，并且使用了示例游戏数据，我们可以为生产做准备，并将其添加到我们的 MERN 基础应用程序中，以查看 VR 如何添加到现有的 Web 应用程序中。

React 360 工具提供了一个脚本，将所有 React 360 应用程序代码捆绑成几个文件，我们可以将其放在 MERN web 服务器上，并在指定路由上作为内容提供。

# 捆绑 React 360 文件

要创建捆绑文件，我们可以从 React 360 项目目录中运行以下命令：

```jsx
npm run bundle
```

这将在名为`build`的文件夹中生成 React 360 应用程序文件的编译版本。编译的捆绑文件是`client.bundle.js`和`index.bundle.js`。这两个文件，加上`index.html`和`static-assets/`文件夹，构成了整个 React 360 应用程序的生产版本：

```jsx
-- static_assets/

-- index.html

-- index.bundle.js

-- client.bundle.js
```

# 与 MERN 应用程序集成

我们需要将这三个文件和`static_assets`文件夹添加到我们的 MERN 应用程序中，然后确保`index.html`中的捆绑文件引用准确，并最终在 Express 应用程序中的指定路由加载`index.html`。

# 添加 React 360 生产文件

考虑到 MERN 骨架应用程序中的文件夹结构，我们将把`static_assets`文件夹和捆绑文件添加到`dist/`文件夹中，以保持我们的 MERN 代码有序，并将所有捆绑文件放在同一个位置。`index.html`文件将放在`server`文件夹中的一个名为`vr`的新文件夹中：

```jsx
-- ... 
-- client/
-- dist/
     --- static_assets/
     --- ...
     --- client.bundle.js
     --- index.bundle.js
-- ...
-- server/
     --- ...
     --- vr/
          ---- index.html
-- ...
```

# 在 index.html 中更新引用

生成的`index.html`文件如下所示，引用捆绑文件，期望这些文件在同一个文件夹中：

```jsx
<html>
  <head>
    <title>MERNVR</title>
    <style>body { margin: 0 }</style>
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
  </head>
  <body>
    <!-- Attachment point for your app -->
    <div id="container"></div>
    <script src="./client.bundle.js"></script>
    <script>
      // Initialize the React 360 application
      React360.init(
        'index.bundle.js',
        document.getElementById('container'),
        {
          assetRoot: 'static_assets/',
        }
      ) 
    </script>
  </body>
</html>
```

我们需要更新`index.html`，以便引用`client.bundle.js`、`index.bundle.js`和`static_assets`文件夹的正确位置。

首先，更新对`client.bundle.js`的引用如下：

```jsx
<script src="/dist/client.bundle.js" type="text/javascript"></script>
```

然后，更新`React360.init`，正确引用`index.bundle.js`和将`assetRoot`设置为`static_assets`文件夹的正确位置：

```jsx
React360.init(
 './../dist/index.bundle.js',
        document.getElementById('container'),
 { assetRoot: '/dist/static_assets/' }
    ) 
```

`assetRoot`将告诉 React 360 在使用`asset()`设置组件资源时从哪里查找资源文件。

现在，如果我们在 MERN 应用程序中设置一个 Express 路由来返回响应中的`index.html`文件，那么在浏览器中访问该路由将呈现 React 360 游戏。

# 尝试集成

要测试这个集成，我们可以设置一个示例路由，如下所示：

```jsx
router.route('/game/play')
   .get((req, res) => {
      res.sendFile(process.cwd()+'/server/vr/index.html') 
}) 
```

然后运行 MERN 服务器，并在浏览器中打开`localhost:3000/game/play`路由。这应该在我们的 MERN 应用程序中呈现本章中实现的 React 360 游戏。

# 总结

在本章中，我们使用 React 360 开发了一个基于 Web 的 VR 游戏，可以轻松集成到 MERN 应用程序中。

我们首先为游戏定义了简单的 VR 功能，然后设置了 React 360 进行开发，并研究了 360 度 VR 世界中的关键 VR 概念，如等距全景图像、3D 位置和坐标系统。我们探索了 React 360 组件和 API，以实现游戏功能，包括诸如`View`、`Text`、`Entity`和`VrButton`等组件，以及`Environment`、`VrHeadModel`和`NativeModules`API。

最后，我们更新了起始的 React 360 项目中的代码，以使用示例游戏数据实现游戏，然后捆绑了代码文件，并讨论了如何将这些编译后的文件添加到现有的 MERN 应用程序中。

在下一章中，我们将开发 MERN VR 游戏应用程序，包括游戏数据库和 API，以便我们可以通过从 MongoDB 中的游戏集合中获取数据，使本章开发的游戏动态化。


# 第十一章：使用 MERN 使 VR 游戏动态化

在本章中，我们将扩展 MERN 骨架应用程序，构建 MERN VR 游戏应用程序，并使用它来使上一章中开发的静态 React 360 游戏动态化，通过直接从 MERN 服务器获取游戏细节来替换示例游戏数据。

为了使 MERN VR 游戏成为一个完整和动态的游戏应用程序，我们将实现以下内容：

+   在 MongoDB 中存储游戏细节的游戏模型模式

+   游戏 CRUD 操作的 API

+   用于游戏创建、编辑、列表和删除的 React 视图

+   更新 React 360 游戏以从 API 获取数据

+   加载具有动态游戏数据的 VR 游戏

# 动态 MERN VR 游戏

在 MERN VR 游戏上注册的用户将能够通过提供游戏世界的等距图像和 VR 对象资源（包括要放置在游戏世界中的每个对象的变换属性值）来制作和修改自己的游戏。任何访问应用程序的访客都可以浏览制作者添加的所有游戏，并玩任何游戏以找到并收集与每个游戏的线索或描述相关的游戏世界中的 3D 对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/7805f18a-fdd7-43b7-acd5-6651f78976de.png)完整的 MERN VR 游戏应用程序的代码可在 GitHub 上找到：[github.com/shamahoque/mern-vrgame](https://github.com/shamahoque/mern-vrgame)。您可以克隆此代码，并在阅读本章其余部分的代码解释时运行该应用程序。

为了实现与创建、编辑和列出 VR 游戏相关的功能所需的视图，我们将通过扩展和修改 MERN 骨架应用程序中的现有 React 组件来开发。下图显示了构成本章中开发的 MERN VR 游戏前端的所有自定义 React 组件的组件树：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a646f3f9-7903-4376-8e5f-69707ef64ea7.jpg)

# 游戏模型

在第十章中，《开发基于 Web 的 VR 游戏》，*游戏数据结构*部分详细介绍了为了实现游戏中定义的寻宝功能所需的每个游戏的细节。我们将根据游戏的具体细节、其 VR 对象以及游戏制作者的参考设计游戏模式。

# 游戏模式

在`game.model.js`中为游戏模型定义的 Mongoose 模式中，我们将添加以下字段：

+   游戏的名称

+   世界图像 URL

+   线索文本

+   包含要添加为可收集答案对象的 VR 对象详细信息的数组

+   包含无效对象详细信息的数组，无法收集

+   指示游戏创建和更新的时间戳

+   制作游戏的用户的引用

`GameSchema`将定义如下。

`mern-vrgame/server/models/game.model.js`：

```jsx
const GameSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: 'Name is required'
  },
  world: {
    type: String, trim: true,
    required: 'World image is required'
  },
  clue: {
    type: String,
    trim: true
  },
  answerObjects: [VRObjectSchema],
  wrongObjects: [VRObjectSchema],
  updated: Date,
  created: {
    type: Date,
    default: Date.now
  },
  maker: {type: mongoose.Schema.ObjectId, ref: 'User'}
})
```

# VRObject 模式

游戏模式中的`answerObjects`和`wrongObjects`字段都将是 VRObject 文档的数组，VRObject Mongoose 模式将单独定义，包括存储 OBJ 文件和 MTL 文件的 URL 字段，以及每个 VR 对象的 React 360 `transform`值，`scale`值和`color`值。

`mern-vrgame/server/models/game.model.js`：

```jsx
const VRObjectSchema = new mongoose.Schema({
  objUrl: {
    type: String, trim: true,
    required: 'ObJ file is required'
  },
  mtlUrl: {
    type: String, trim: true,
    required: 'MTL file is required'
  },
  translateX: {type: Number, default: 0},
  translateY: {type: Number, default: 0},
  translateZ: {type: Number, default: 0},
  rotateX: {type: Number, default: 0},
  rotateY: {type: Number, default: 0},
  rotateZ: {type: Number, default: 0},
  scale: {type: Number, default: 1},
  color: {type: String, default: 'white'}
}) 
```

当新的游戏文档保存到数据库时，`answerObjects`和`wrongObjects`数组将填充符合此模式定义的 VRObject 文档。

# 游戏模式中的数组长度验证

在保存到游戏集合中时，游戏文档中的`answerObjects`和`wrongObjects`数组必须至少包含一个 VRObject 文档。为了为游戏模式添加最小数组长度的验证，我们将在`GameSchema`中的`answerObjects`和`wrongObjects`路径中添加以下自定义验证检查。

`mern-vrgame/server/models/game.model.js`：

```jsx
GameSchema.path('answerObjects').validate(function(v) {
  if (v.length == 0) {
    this.invalidate('answerObjects',
   'Must add alteast one VR object to collect')
  }
}, null) 
```

```jsx
GameSchema.path('wrongObjects').validate(function(v) {
  if (v.length == 0) {
    this.invalidate('wrongObjects', 
    'Must add alteast one other VR object') 
  }
}, null) 
```

这些模式定义将满足根据 MERN VR 游戏规范开发动态 VR 游戏的所有要求。

# 游戏 API

MERN VR 游戏中的后端将公开一组 CRUD API，用于在前端应用程序中使用，包括在 React 360 游戏实现中使用 fetch 调用创建、编辑、读取、列出和删除游戏。

# 创建 API

已登录应用程序的用户将能够使用`create`API 在数据库中创建新游戏。

# 路由

在后端，我们将在`game.routes.js`中添加一个`POST`路由，验证当前用户是否已登录并获得授权，然后使用请求中传递的游戏数据创建新游戏。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/games/by/:userId')
    .post(authCtrl.requireSignin,authCtrl.hasAuthorization, gameCtrl.create)
```

为了处理`:userId`参数并从数据库中检索相关联的用户，我们将利用用户控制器中的`userByID`方法。我们还将在游戏路由中添加以下内容，以便用户在`request`对象中作为`profile`可用。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.param('userId', userCtrl.userByID)
```

`game.routes.js`文件将与`user.routes`文件非常相似，并且为了在 Express 应用程序中加载这些新路由，我们需要在`express.js`中挂载游戏路由，就像我们为 auth 和 user 路由所做的那样。

`mern-vrgame/server/express.js`：

```jsx
app.use('/', gameRoutes)
```

# 控制器

当收到`'/api/games/by/:userId'`的 POST 请求并且请求体包含新游戏数据时，将执行`create`控制器方法。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const create = (req, res, next) => {
  const game = new Game(req.body)
  game.maker= req.profile
  game.save((err, result) => {
    if(err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.status(200).json(result)
  })
}
```

在这个`create`方法中，使用游戏模式创建一个新的游戏文档，并使用从客户端传递的请求体中的数据。然后在将用户引用设置为游戏制造商后，将此文档保存在`Game`集合中。

# 获取

在前端，我们将在`api-game.js`中添加相应的`fetch`方法，通过传递从已登录用户收集的表单数据来向`create`API 发起`POST`请求。

`mern-vrgame/client/game/api-game.js`：

```jsx
const create = (params, credentials, game) => {
  return fetch('/api/games/by/'+ params.userId, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + credentials.t
      },
      body: JSON.stringify(game)
    })
    .then((response) => {
      return response.json();
    }).catch((err) => console.log(err)) 
}
```

# 列表 API

可以通过使用列表 API 从后端获取`Game`集合中所有游戏的列表。

# 路由

我们将在游戏路由中添加一个 GET 路由，以检索存储在数据库中的所有游戏。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/games')
    .get(gameCtrl.list)
```

对`/api/games`的`GET`请求将执行`list`控制器方法。

# 控制器

`list`控制器方法将查询数据库中的`Game`集合，以返回响应给客户端的所有游戏。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const list = (req, res) => {
  Game.find({}).populate('maker', '_id name')
 .sort('-created').exec((err, games) => {
    if(err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(games)

  })
}
```

# 获取

在前端，为了使用这个列表 API 获取游戏，我们将在`api-game.js`中设置一个`fetch`方法。

`mern-vrgame/client/game/api-game.js`：

```jsx
const list = () => {
  return fetch('/api/games', {
    method: 'GET',
  }).then(response => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
```

# 按制造商列表 API

该应用程序还将允许我们使用制造商列表 API 获取特定用户制作的游戏。

# 路由

在游戏路由中，我们将添加一个`GET`路由，以检索特定用户制作的游戏。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/games/by/:userId')
    .get(gameCtrl.listByMaker)
```

对这个路由的`GET`请求将执行游戏控制器中的`listByMaker`方法。

# 控制器

`listByMaker`控制器方法将查询数据库中的 Game 集合，以获取匹配的游戏。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const listByMaker = (req, res) => {
  Game.find({maker: req.profile._id}, (err, games) => {
    if(err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(games)
  }).populate('maker', '_id name')
}
```

在对 Game 集合的查询中，我们找到所有制造商字段与`req.profile`中指定的用户匹配的游戏。

# 获取

在前端，为了使用制造商列表 API 获取特定用户的游戏，我们将在`api-game.js`中添加一个`fetch`方法。

`mern-vrgame/client/game/api-game.js`：

```jsx
const listByMaker = (params) => {
  return fetch('/api/games/by/'+params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json'
    }
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

# 读取 API

将使用`'/api/game/:gameId'`的`read` API 从数据库中检索单个游戏数据。

# 路由

在后端，我们将添加一个`GET`路由，查询带有 ID 的`Game`集合，并在响应中返回游戏。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/game/:gameId')
    .get(gameCtrl.read)
```

路由 URL 中的`:gameId`参数将首先被处理，以从数据库中检索单个游戏。因此，我们还将在游戏路由中添加以下内容：

```jsx
router.param('gameId', gameCtrl.gameByID)
```

# 控制器

对 read API 的请求中的`:gameId`参数将调用`gameByID`控制器方法，该方法类似于`userByID`控制器方法。它将从数据库中检索游戏并将其附加到`request`对象中，以在`next`方法中使用。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const gameByID = (req, res, next, id) => {
  Game.findById(id).populate('maker', '_id name').exec((err, game) => {
    if (err || !game)
      return res.status('400').json({
        error: "Game not found"
      })
    req.game = game
    next()
  })
}
```

在这种情况下，`next`方法，即`read`控制器方法，简单地将这个`game`对象返回给客户端的响应。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const read = (req, res) => {
  return res.json(req.game)
}
```

# 获取

在前端代码中，我们将添加一个`fetch`方法来利用这个 read API 根据其 ID 检索单个游戏的详细信息。

`mern-vrgame/client/game/api-game.js`：

```jsx
const read = (params, credentials) => {
  return fetch('/api/game/' + params.gameId, {
    method: 'GET'
  }).then((response) => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
```

这个`read` API 将用于 React 视图获取游戏详情，还将用于 React 360 游戏视图，该视图将呈现游戏界面。

# 编辑 API

已登录并且也是特定游戏的制作者的授权用户将能够使用`edit` API 编辑该游戏的详细信息。

# 路由

在后端，我们将添加一个`PUT`路由，允许授权用户编辑他们的游戏之一。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/games/:gameId')
    .put(authCtrl.requireSignin, gameCtrl.isMaker, gameCtrl.update)
```

向`'/api/games/:gameId'`发送 PUT 请求将首先执行`gameByID`控制器方法，以检索特定游戏的详细信息。还将调用`requireSignin`身份验证控制器方法，以确保当前用户已登录。然后`isMaker`控制器方法将确定当前用户是否是该特定游戏的制作者，最后运行游戏`update`控制器方法来修改数据库中的游戏。

# 控制器

`isMaker`控制器方法确保已登录用户实际上是正在编辑的游戏的制作者。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const isMaker = (req, res, next) => {
  let isMaker = req.game && req.auth && req.game.maker._id == req.auth._id
  if(!isMaker){
    return res.status('403').json({
      error: "User is not authorized"
    })
  }
  next()
}
```

游戏控制器中的`update`方法将获取现有的游戏详情和请求体中接收到的表单数据，合并更改，并将更新后的游戏保存到数据库中的 Game 集合中。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const update = (req, res) => {
  let game = req.game
  game = _.extend(game, req.body)
  game.updated = Date.now()
  game.save((err) => {
    if(err) {
      return res.status(400).send({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(game)
  })
}
```

# 获取

在视图中调用`edit` API 时，使用`fetch`方法获取表单数据，并将其与用户凭据一起发送到后端。

`mern-vrgame/client/game/api-game.js`：

```jsx
const update = (params, credentials, game) => {
  return fetch('/api/games/' + params.gameId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(game)
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

# 删除 API

经过身份验证和授权的用户将能够使用`delete`游戏 API 删除他们在应用程序中制作的任何游戏。

# 路由

在后端，我们将添加一个`DELETE`路由，允许授权的制作者删除他们自己的游戏之一。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/api/games/:gameId')
    .delete(authCtrl.requireSignin, gameCtrl.isMaker, gameCtrl.remove)
```

在收到`'api/games/:gameId'`的 DELETE 请求后，控制器方法在服务器上的执行流程将类似于编辑 API，最终调用`remove`控制器方法而不是`update`。

# 控制器

当收到`'/api/games/:gameId'`的 DELETE 请求并验证当前用户是给定游戏的原始制作者时，`remove`控制器方法将从数据库中删除指定的游戏。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const remove = (req, res) => {
  let game = req.game
  game.remove((err, deletedGame) => {
    if(err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(deletedGame)
  })
}
```

# 获取

我们将在`api-game.js`中添加相应的`remove`方法，以便向删除 API 发出`delete`请求。

`mern-vrgame/client/game/api-game.js`：

```jsx
const remove = (params, credentials) => {
  return fetch('/api/games/' + params.gameId, {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

有了这些游戏 API，我们可以构建应用程序的 React 视图，并更新 React 360 游戏视图代码以获取和呈现动态游戏详情。

# 创建和编辑游戏

在 MERN VR Game 上注册的用户将能够在应用程序内制作新游戏并修改这些游戏。我们将添加 React 组件，允许用户修改每个游戏的游戏详情和 VR 对象详情。

# 创建新游戏

当用户登录应用程序时，他们将在菜单中看到一个 MAKE GAME 链接，该链接将引导他们到包含创建新游戏表单的`NewGame`组件。

# 更新菜单

我们将更新导航菜单，添加 MAKE GAME 按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c554d5ac-420f-4762-8084-6a88044afb1f.png)

在`Menu`组件中，我们将在用户经过身份验证时渲染的部分中，在 MY PROFILE 链接之前，为`NewGame`组件的路由添加`Link`。

`mern-vrgame/client/core/Menu.js`：

```jsx
<Link to="/game/new">
   <Button style={isActive(history, "/game/new")}>
       <AddBoxIcon color="secondary"/> Make Game
   </Button>
</Link>
```

# NewGame 组件

`NewGame`组件使用`GameForm`组件来渲染用户将填写以创建新游戏的表单元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a825261e-e98e-497a-b21e-17a07727bdfd.png)

`GameForm`包含所有表单字段，并从`NewGame`组件中获取`onSubmit`方法（用户提交表单时应执行的方法），以及任何服务器返回的错误消息。

`mern-vrgame/client/game/NewGame.js`：

```jsx
<GameForm onSubmit={this.clickSubmit} errorMsg={this.state.error}/>
```

`clickSubmit`方法使用`api-game.js`中的创建`fetch`方法，向`create`API 发出 POST 请求，携带游戏表单数据和用户详情。

`mern-vrgame/client/game/NewGame.js`：

```jsx
  clickSubmit = game => event => {
    const jwt = auth.isAuthenticated() 
    create({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, game).then((data) => {
      if (data.error) {
        this.setState({error: data.error}) 
      } else {
        this.setState({error: '', redirect: true}) 
      }
    }) 
  }
```

我们将在`MainRouter`中添加一个`PrivateRoute`，以便`NewGame`组件在浏览器中加载，路径为`/game/new`。

`mern-vrgame/client/MainRouter.js`：

```jsx
<PrivateRoute path="/game/new" component={NewGame}/>
```

# 编辑游戏

用户将能够使用`EditGame`组件编辑他们创建的游戏，该组件将呈现预填充现有游戏详情的游戏表单字段。

# EditGame 组件

就像在`NewGame`组件中一样，`EditGame`组件也将使用`GameForm`组件来呈现表单元素，但这次字段将显示游戏字段的当前值，并且用户将能够更新这些值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/2742c2b7-045f-4230-8734-f6eb3b5fc639.png)

在`EditGame`组件的情况下，`GameForm`将接受给定游戏的 ID 作为属性，以便获取游戏详情，以及`onSubmit`方法和服务器生成的错误消息（如果有）。

`mern-vrgame/client/game/EditGame.js`：

```jsx
<GameForm gameId={this.match.params.gameId} onSubmit={this.clickSubmit} errorMsg={this.state.error}/>
```

编辑表单的`clickSubmit`方法将使用`api-game.js`中的`update`获取方法，向编辑 API 发出 PUT 请求，携带表单数据和用户详情。

`mern-vrgame/client/game/EditGame.js`：

```jsx
clickSubmit = game => event => {
    const jwt = auth.isAuthenticated() 
    update({
      gameId: this.match.params.gameId
    }, {
      t: jwt.token
    }, game).then((data) => {
      if (data.error) {
        this.setState({error: data.error}) 
      } else {
        this.setState({error: '', redirect: true}) 
      }
    }) 
  }
```

`EditGame`组件将在浏览器中加载，路径为`/game/edit/:gameId`，在`MainRouter`中声明为`PrivateRoute`。

`mern-vrgame/client/MainRouter.js`：

```jsx
<PrivateRoute path="/game/edit/:gameId" component={EditGame}/>
```

# GameForm 组件

`GameForm`组件在`NewGame`和`EditGame`组件中都使用，包含允许用户输入游戏详情和单个游戏的 VR 对象详情的元素。它可以从空白游戏对象开始，或在`componentDidMount`中加载现有游戏。

`mern-vrgame/client/game/GameForm.js`：

```jsx
state = {
    game: {name: '', clue:'', world:'', answerObjects:[], wrongObjects:[]},
    redirect: false,
    readError: ''
  }
```

如果`GameForm`组件从父组件（如`EditGame`组件）接收到`gameId`属性，则它将使用读取 API 来检索游戏的详情并将其设置为状态以在表单视图中呈现。

`mern-vrgame/client/game/GameForm.js`：

```jsx
componentDidMount = () => {
    if(this.props.gameId){
      read({gameId: this.props.gameId}).then((data) => {
        if (data.error) {
          this.setState({readError: data.error}) 
        } else {
          this.setState({game: data}) 
        }
      }) 
    }
}
```

`GameForm`组件中的表单视图基本上分为两部分，一部分是接受简单的游戏细节，比如名称、世界图片链接和线索文本作为输入，另一部分允许用户向答案对象数组或错误对象数组中添加可变数量的 VR 对象。

# 输入简单的游戏细节

简单的游戏细节部分将主要是使用 Material-UI 的`TextField`组件添加的文本输入，并传递给`onChange`的更改处理方法。

# 表单标题

表单标题将是“新游戏”或“编辑游戏”，具体取决于是否将现有游戏 ID 作为 prop 传递给`GameForm`。

`mern-vrgame/client/game/GameForm.js`：

```jsx
<Typography type="headline" component="h2">
    {this.props.gameId? 'Edit': 'New'} Game
</Typography>
```

# 游戏世界图片

我们将在顶部的`img`元素中渲染背景图片 URL，以显示用户添加的游戏世界图片 URL。

`mern-vrgame/client/game/GameForm.js`：

```jsx
<img src={this.state.game.world}/>
<TextField id="world" label="Game World Equirectangular Image (URL)" 
value={this.state.game.world} onChange={this.handleChange('world')}/>
```

# 游戏名称

游戏名称将添加在一个默认类型为`text`的单个`TextField`中。

`mern-vrgame/client/game/GameForm.js`：

```jsx
<TextField id="name" label="Name" value={this.state.game.name} onChange={this.handleChange('name')}/>
```

# 线索文本

线索文本将添加到多行`TextField`组件中。

`mern-vrgame/client/game/GameForm.js`：

```jsx
<TextField id="multiline-flexible" label="Clue Text" multiline rows="2" value={this.state.game.clue} onChange={this.handleChange('clue')}/>
```

# 处理输入

所有输入更改将由`handleChange`方法处理，该方法将使用用户输入更新状态中的游戏数值。

`mern-vrgame/client/game/GameForm.js`：

```jsx
handleChange = name => event => {
    const newGame = this.state.game 
    newGame[name] = event.target.value 
    this.setState({game: newGame}) 
}
```

# 修改 VR 对象数组

为了允许用户修改他们希望添加到他们的 VR 游戏中的`answerObjects`和`wrongObjects`数组，`GameForm`将遍历每个数组，并为每个对象渲染一个`VRObjectForm`组件。通过这样做，将可以从`GameForm`组件中添加、删除和修改 VR 对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c9d59097-561d-4b45-97e0-aab65d9c09f7.png)

# 迭代和渲染对象细节表单

使用 Material-UI 的`ExpansionPanel`组件，我们将添加先前看到的表单界面，以为给定游戏中的每种类型的 VR 对象数组创建一个可修改的数组。

在`ExpansionPanelDetails`组件中，我们将迭代`answerObjects`数组或`wrongObjects`数组，为每个 VR 对象渲染一个`VRObjectForm`组件。

`mern-vrgame/client/game/GameForm.js`：

```jsx
<ExpansionPanel>
   <ExpansionPanelSummary expandIcon={<ExpandMoreIcon/>}>
      <Typography>VR Objects to collect</Typography>
   </ExpansionPanelSummary>
   <ExpansionPanelDetails>{
      this.state.game.answerObjects.map((item, i) => {
 return <div key={i}>
                  <VRObjectForm index={i} type={'answerObjects'}
 vrObject={item}
 handleUpdate={this.handleObjectChange} 
 removeObject={this.removeObject}/>
               </div> })}
      <Button color="primary" variant="raised" onClick={this.addObject('answerObjects')}>
          <AddBoxIcon color="secondary"/> Add Object
      </Button>
   </ExpansionPanelDetails>
</ExpansionPanel>
```

每个`VRObjectForm`将作为 props 接受`vrObject`本身，数组中的当前`index`，对象数组的类型，以及在`VRObjectForm`组件内部通过更改细节或删除对象时更新`GameForm`状态的两种方法。

# 向数组中添加一个新对象

添加对象的按钮将允许用户添加一个新的`VRObjectForm`组件，以获取新的 VR 对象的细节。

`mern-vrgame/client/game/GameForm.js`：

```jsx
addObject = name => event => {
    const newGame = this.state.game 
    newGame[name].push({}) 
    this.setState({game: newGame}) 
} 
```

这基本上只会向正在迭代的数组中添加一个空对象，并使用名称值中指定的数组类型调用`addObject`方法。

# 从数组中移除对象

每个`VRObjectForm`组件也可以被删除，以从给定数组中移除对象。`GameForm`将会传递一个`removeObject`方法给`VRObjectForm`组件作为属性，这样当用户点击特定`VRObjectForm`上的`delete`时，数组就可以在状态中更新。

`mern-vrgame/client/game/GameForm.js`：

```jsx
removeObject = (type, index) => event => {
    const newGame = this.state.game 
    newGame[type].splice(index, 1) 
    this.setState({game: newGame}) 
}
```

对象将通过在指定名称的数组中的给定`index`处进行切片来从数组中移除。

# 处理对象细节变化

当用户更改任何`VRObjectForm`字段中的输入值时，`VR`对象的细节将在`GameForm`组件状态中更新。为了注册这个更新，`GameForm`将`handleObjectChange`方法传递给`VRObjectForm`组件。

`mern-vrgame/client/game/GameForm.js`：

```jsx
handleObjectChange = (index, type, name, val) => {
    var newGame = this.state.game 
    newGame[type][index][name] = val 
    this.setState({game: newGame}) 
}
```

`handleObjectChange`方法会更新数组中特定对象的字段值，使用给定的`type`和`index`，因此它会在`GameForm`中存储的游戏对象状态中反映出来。

# VRObjectForm 组件

`VRObjectForm`组件将渲染输入字段，以修改单个 VR 对象的细节，该对象被添加到`GameForm`组件中的`answerObjects`和`wrongObjects`数组中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/101c7142-c187-4ade-a62b-416575acbfef.png)

它可以从一个空的 VR 对象开始，或者在`componentDidMount`中加载现有的 VR 对象的细节。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
state = {
      objUrl: '', mtlUrl: '',
      translateX: 0, translateY: 0, translateZ: 0, 
      rotateX: 0, rotateY: 0, rotateZ: 0,
      scale: 1, color:'white'
} 
```

在`componentDidMount`中，状态将被设置为从`GameForm`组件传递的`vrObject`的细节。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
componentDidMount = () => {
    if(this.props.vrObject && 
    Object.keys(this.props.vrObject).length != 0){
        const vrObject = this.props.vrObject 
        this.setState({
          objUrl: vrObject.objUrl,
          mtlUrl: vrObject.mtlUrl,
          translateX: Number(vrObject.translateX),
          translateY: Number(vrObject.translateY),
          translateZ: Number(vrObject.translateZ),
          rotateX: Number(vrObject.rotateX),
          rotateY: Number(vrObject.rotateY),
          rotateZ: Number(vrObject.rotateZ),
          scale: Number(vrObject.scale),
          color:vrObject.color
        }) 
    }
}
```

使用 Material-UI 的`TextField`组件来添加修改这些值的输入字段。

# 3D 对象文件输入

OBJ 和 MTL 文件链接将作为文本输入添加到每个 VR 对象中，使用`TextField`组件。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<TextField
    id="obj"
    label=".obj url"
    value={this.state.objUrl}
    onChange={this.handleChange('objUrl')}
/><br/>
<TextField
    id="mtl"
    label=".mtl url"
    value={this.state.mtlUrl}
    onChange={this.handleChange('mtlUrl')}
/>
```

# 翻译值输入

VR 对象在 X、Y 和 Z 轴上的翻译值将在`number`类型的`TextField`组件中输入。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<TextField
    value={this.state.translateX}
    label="TranslateX"
    onChange={this.handleChange('translateX')}
    type="number"
/>
<TextField
    value={this.state.translateY}
    label="TranslateY"
    onChange={this.handleChange( 'translateY')}
    type="number"
/>
<TextField
    value={this.state.translateZ}
    label="TranslateZ"
    onChange={this.handleChange('translateZ')}
    type="number"
/>
```

# 旋转值输入

VR 对象围绕 X、Y 和 Z 轴的“旋转”值将在“数字”类型的 TextField 组件中输入。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<TextField
    value={this.state.rotateX}
    label="RotateX"
    onChange={this.handleChange('rotateX')}
    type="number"
/>
<TextField
    value={this.state.rotateY}
    label="RotateY"
    onChange={this.handleChange('rotateY')}
    type="number"
/>
<TextField
    value={this.state.rotateZ}
    label="RotateZ"
    onChange={this.handleChange('rotateZ')}
    type="number"
/>
```

# 比例值输入

VR 对象的“比例”值将在“数字”类型的 TextField 组件中输入。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<TextField
    value={this.state.scale}
    label="Scale"
    onChange={this.handleChange('scale')}
    type="number"
/>
```

# 对象颜色输入

VR 对象的颜色值将在“文本”类型的 TextField 组件中输入：

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<TextField
    value={this.state.color}
    label="Color"
    onChange={this.handleChange('color')}
/>
```

# 删除对象按钮

`VRObjectForm`将包含一个“删除”按钮，该按钮将执行从`GameForm`props 表单中接收到的`removeObject`方法：

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
<Button onClick={this.props.removeObject(this.props.type, this.props.index)}>
     <Icon>cancel</Icon> Delete
</Button>
```

`removeObject`方法将获取对象数组类型的值和要删除的数组索引位置，从`GameForm`状态中删除相关 VR 对象数组中的给定对象。

# 处理输入更改

当输入字段中的任何 VR 对象细节发生更改时，`handleChange`方法将更新`VRObjectForm`组件的状态，并使用从`GameForm`传递的`handleUpdate`方法来更新`GameForm`状态中的 VR 对象的更改值。

`mern-vrgame/client/game/VRObjectForm.js`：

```jsx
handleChange = name => event => {
    this.setState({[name]: event.target.value}) 
    this.props.handleUpdate(this.props.index, 
                            this.props.type, 
                            name, 
                            event.target.value) 
}
```

通过这种实现，创建和编辑游戏表单已经就位，包括用于不同大小数组的 VR 对象输入表单。任何注册用户都可以使用这些表单在 MERN VR 游戏应用程序上添加和编辑游戏。

# 游戏列表视图

访问 MERN VR 游戏的访问者将从主页和个人用户资料页面上呈现的列表中访问应用程序中的游戏。主页将列出应用程序中的所有游戏，特定制作者的游戏将列在其用户资料页面上。列表视图将通过使用“列表”API 获取的游戏数据进行迭代，并在`GameDetail`组件中呈现每个游戏的详细信息。

# 所有游戏

`Home`组件将在组件挂载时使用列表 API 获取游戏集合中所有游戏的列表。

`mern-vrgame/client/core/Home.js`：

```jsx
componentDidMount = () => {
    list().then((data) => {
      if (data.error) {
        console.log(data.error) 
      } else {
        this.setState({games: data}) 
      }
    })
}
```

从服务器检索到的游戏列表将设置为状态，并进行迭代以呈现每个列表中的`GameDetail`组件。

`mern-vrgame/client/core/Home.js`：

```jsx
{this.state.games.map((game, i) => {
     return <GameDetail key={i} game={game} updateGames={this.updateGames}/>
})}
```

`GameDetail`组件将传递游戏详情和`updateGames`方法。

`mern-vrgame/client/core/Home.js`：

```jsx
updateGames = (game) => {
    const updatedGames = this.state.games 
    const index = updatedGames.indexOf(game) 
    updatedGames.splice(index, 1) 
    this.setState({games: updatedGames}) 
}
```

`updateGames`方法将在用户从`GameDetail`组件中删除他们的游戏时更新`Home`组件中的列表，该组件呈现了游戏制作者的`edit`和`delete`选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/f7fa0681-c359-45f1-98a2-7b5fb4dc9256.png)

# 制作者的游戏

用户`Profile`组件将使用制作者 API 获取给定用户制作的游戏列表。我们将更新`Profile`组件中的`init`方法，在检索到用户详细信息后调用`listByMaker`获取方法。

`mern-vrgame/client/user/Profile.js`：

```jsx
  init = (userId) => {
    const jwt = auth.isAuthenticated() 
    read({
      userId: userId
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        this.setState({redirectToSignin: true}) 
      } else {
        this.setState({user: data}) 
 listByMaker({userId: data._id}).then((data) => {
 if (data.error) {
 console.log(data.error) 
 } else {
 this.setState({games: data}) 
 }
 })
      }
    }) 
  }
```

类似于在`Home`组件中呈现游戏列表的方式，我们将在`Profile`组件中将从服务器检索到的游戏列表设置为状态，并在视图中对其进行迭代以呈现`GameDetail`组件，该组件将传递个别游戏详情和`updateGames`方法。

`mern-vrgame/client/user/Profile.js`：

```jsx
{this.state.games.map((game, i) => {
    return <GameDetail key={i} game={game} updateGames={this.updateGames}/>
})}
```

这将为特定用户制作的每个游戏呈现一个`GameDetail`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/e63a7011-94eb-420a-bd20-13ad86f97746.png)

# 游戏详情组件

`GameDetail`组件以游戏对象作为属性，并呈现游戏的详细信息，以及一个链接到 VR 游戏视图的 PLAY GAME 按钮。如果当前用户是游戏制作者，则还会显示`edit`和`delete`按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/1bc66f95-a3b4-48e3-af8b-7f82d69f4381.png)

# 游戏详情

游戏详情，如名称、世界图片、线索文本和制作者名称，都会被呈现，以便用户对游戏有一个概览。

`mern-vrgame/client/game/GameDetail.js`：

```jsx
<Typography type="headline" component="h2">
     {this.props.game.name}
</Typography>
<CardMedia image={this.props.game.world} 
           title={this.props.game.name}/>
<Typography type="subheading" component="h4">
     <em>by</em>
     {this.props.game.maker.name}
</Typography>
<CardContent>
     <Typography type="body1" component="p">
          {this.props.game.clue}
     </Typography>
</CardContent>
```

# Play Game 按钮

`GameDetail`组件中的`Play Game`按钮将简单地是一个指向打开 React 360 生成的`index.html`路由的`Link`组件（服务器上此路由的实现在*玩 VR 游戏*部分讨论）。

`mern-vrgame/client/game/GameDetail.js`：

```jsx
<Link to={"/game/play?id=" + this.props.game._id} target='_self'>
   <Button variant="raised" color="secondary">
      Play Game
   </Button>
</Link>
```

游戏视图的路由将以游戏 ID 作为`query`参数。我们在`Link`上设置`target='_self'`，这样 React Router 就会跳过转换到下一个状态，让浏览器处理这个链接。这样做的效果是允许浏览器直接在此路由发出请求，并在响应此请求时渲染服务器发送的`index.html`文件。

# 编辑和删除按钮

`GameDetail`组件只会在当前登录用户也是正在呈现的游戏的制作者时显示`edit`和`delete`选项。

`mern-vrgame/client/game/GameDetail.js`：

```jsx
{auth.isAuthenticated().user 
    && auth.isAuthenticated().user._id == this.props.game.maker._id && 
    (<div>
       <Link to={"/game/edit/" + this.props.game._id}>
          <Button variant="raised" color="primary" 
         className={classes.editbutton}>
              Edit
          </Button>
       </Link>
       <DeleteGame game={this.props.game} 
       removeGame={this.props.updateGames}/>
    </div>)}
```

如果已登录用户的用户 ID 与游戏中的制作者 ID 匹配，则在视图中显示链接到编辑表单视图的`edit`按钮和`DeleteGame`组件。

# 删除游戏

已登录用户将能够通过点击`GameDetail`组件中制作者可见的`delete`按钮来删除他们制作的特定游戏。`GameDetail`组件使用`DeleteGame`组件添加了这个`delete`选项。

# DeleteGame 组件

`DeleteGame`组件添加到每个游戏的`GameDetail`组件中，从`GameDetail`中获取游戏详情和`removeGame`方法作为 props，该方法更新了`GameDetail`所属的父组件。

`mern-vrgame/client/game/GameDetail.js`：

```jsx
<DeleteGame game={this.props.game} removeGame={this.props.updateGames}/>
```

这个`DeleteGame`组件基本上是一个按钮，当点击时，会打开一个确认对话框，询问用户是否确定要删除他们的游戏：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/7d45088a-0e4c-4071-bbb9-a143748b71c8.png)

对话框是使用 Material-UI 的`Dialog`组件实现的。

`mern-vrgame/client/game/DeleteGame.js`：

```jsx
<Button variant="raised" onClick={this.clickButton}>
   Delete
</Button>
<Dialog open={this.state.open} onClose={this.handleRequestClose}>
   <DialogTitle>{"Delete "+this.props.game.name}</DialogTitle>
   <DialogContent>
      <DialogContentText>
         Confirm to delete your game {this.props.game.name}.
      </DialogContentText>
   </DialogContent>
   <DialogActions>
      <Button onClick={this.handleRequestClose} color="primary">
         Cancel
      </Button>
      <Button onClick={this.deleteGame} color="secondary" 
      autoFocus="autoFocus">
         Confirm
      </Button>
   </DialogActions>
</Dialog>
```

成功删除后，对话框将关闭，并通过调用作为 prop 传递的`removeGame`方法更新包含`GameDetail`组件的父组件。

`mern-vrgame/client/game/DeleteGame.js`：

```jsx
deleteGame = () => {
    const jwt = auth.isAuthenticated() 
    remove({
      gameId: this.props.game._id
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        console.log(data.error) 
      } else {
        this.props.removeGame(this.props.game) 
        this.setState({open: false}) 
      }
    }) 
  }
```

在这个`deleteGame`处理程序方法中调用的`removeGame`方法更新了父组件的状态，这可能是`Home`组件或用户`Profile`组件，因此已删除的游戏不再显示在视图中。

# 玩 VR 游戏

MERN VR 游戏上的用户将能够在应用程序内打开和玩任何游戏。为了实现这一点，我们将在服务器上设置一个路由，以在以下路径对 GET 请求的响应中呈现使用 React 360 生成的`index.html`：

```jsx
/game/play?id=<game ID>
```

路径以`query`参数作为游戏 ID 值，该值在 React 360 代码中用于使用读取 API 获取游戏详情。

# API 来渲染 VR 游戏视图

打开 React 360 `index.html`页面的 GET 请求将在`game.routes.js`中声明，如下所示。

`mern-vrgame/server/routes/game.routes.js`：

```jsx
router.route('/game/play')
  .get(gameCtrl.playGame)
```

这将执行`playGame`控制器方法，以响应传入请求返回`index.html`页面。

`mern-vrgame/server/controllers/game.controller.js`：

```jsx
const playGame = (req, res) => {
  res.sendFile(process.cwd()+'/server/vr/index.html')
}
```

`playGame`控制器方法将`/server/vr/`文件夹中放置的`index.html`发送给请求的客户端。

在浏览器中，这将呈现 React 360 游戏代码，它将使用读取 API 从数据库中获取游戏详情，并呈现游戏世界以及用户可以与之交互的 VR 对象。

# 更新 React 360 中的游戏代码

在 MERN 应用程序中设置了游戏后端之后，我们可以更新在第十章中开发的 React 360 项目代码，使其直接从数据库中的游戏集合中呈现游戏。

我们将在打开 React 360 应用程序的链接中使用游戏 ID，以在 React 360 代码内部使用读取 API 获取游戏详情，然后将数据设置为状态，以便游戏加载从数据库中检索的详情，而不是我们在第十章中使用的静态示例数据，*开发基于 Web 的 VR 游戏*。

代码更新后，我们可以再次对其进行打包，并将编译后的文件放在 MERN 应用程序中。

# 从链接中获取游戏 ID

在 React 360 项目文件夹的`index.js`文件中，更新`componentDidMount`方法，从传入的 URL 中检索游戏 ID，并调用读取游戏 API 进行获取。

`/MERNVR/index.js`：

```jsx
componentDidMount = () => {
    let gameId = Location.search.split('?id=')[1]
    read({
          gameId: gameId
      }).then((data) => {
        if (data.error) {
          this.setState({error: data.error});
        } else {
          this.setState({
            vrObjects: data.answerObjects.concat(data.wrongObjects),
            game: data
          });
          Environment.setBackgroundImage(
            {uri: data.world}
          )
        }
    })
}
```

`Location.search`让我们可以访问加载`index.html`的传入 URL 中的查询字符串。检索到的查询字符串被`split`以从 URL 中附加的`id`查询参数中获取游戏 ID 值。我们需要这个游戏 ID 值来使用读取 API 从服务器获取游戏详情，并将其设置为游戏和`vrObjects`值的状态。

# 使用读取 API 获取游戏数据

在 React 360 项目文件夹中，我们将添加一个`api-game.js`文件，其中包含一个读取`fetch`方法，用于使用提供的游戏 ID 调用服务器上的读取游戏 API。

`/MERNVR/api-game.js`：

```jsx
const read = (params) => {
  return fetch('/api/game/' + params.gameId, {
    method: 'GET'
  }).then((response) => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
export {
  read
} 
```

这个 fetch 方法在 React 360 入口组件的`componentDidMount`中用于检索游戏详情。

这个更新的 React 360 代码可以在 GitHub 仓库的名为'dynamic-game'的分支中找到：[github.com/shamahoque/MERNVR](https://github.com/shamahoque/MERNVR)。

# 打包和集成更新的代码

将 React 360 代码更新为从服务器动态获取和呈现游戏详情后，我们可以使用提供的打包脚本对此代码进行打包，并将新编译的文件放在 MERN VR 游戏项目目录的`dist`文件夹中。

要从命令行打包 React 360 代码，请转到 React 360 `MERNVR`项目文件夹并运行：

```jsx
npm run bundle
```

这将在`build/`文件夹中生成`client.bundle.js`和`index.bundle.js`捆绑文件，其中包含更新的 React 360 代码。这些文件以及`index.html`和`static_assets`文件夹需要根据第十章中讨论的内容添加到 MERN VR 游戏应用程序代码中，*开发基于 Web 的 VR 游戏*，以集成最新的 VR 游戏代码。

完成了这个集成后，如果我们运行 MERN VR 游戏应用程序，并在任何游戏的“播放游戏”链接上点击，它应该会打开游戏视图，并显示特定游戏的详细信息，允许按照游戏玩法规定与 VR 对象进行交互。

# 摘要

在本章中，我们将 MERN 堆栈技术的功能与 React 360 集成，开发了一个用于 Web 的动态 VR 游戏应用程序。

我们扩展了 MERN 骨架应用程序，以构建一个工作的后端，用于存储 VR 游戏的详细信息，并允许我们进行 API 调用来操作这些详细信息。我们添加了 React 视图，让用户可以修改游戏并浏览游戏，还可以选择在特定路由上启动和玩 VR 游戏，由服务器直接呈现。

最后，我们更新了 React 360 项目代码，通过从传入 URL 检索查询参数，并使用 fetch 来检索游戏 API 的数据，在 MERN 应用程序和 VR 游戏视图之间传递数据。

React 360 代码与 MERN 堆栈应用程序的集成产生了一个完全功能且动态的基于 Web 的 VR 游戏应用程序，展示了 MERN 堆栈技术如何被使用和扩展以创建独特的用户体验。

在下一章中，我们将反思本书中构建的 MERN 应用程序，讨论不仅是遵循的最佳实践，还有改进和进一步发展的空间。
