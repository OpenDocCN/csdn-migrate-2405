# React 项目（五）

> 原文：[`zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0`](https://zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 React Native 和 Expo 构建动画游戏

在本书中创建的大多数项目都侧重于显示数据并使其可以在页面之间进行导航。在上一章中，您探索了创建 Web 和移动应用程序之间的一些差异。构建移动应用程序时的另一个区别是，用户期望动画和手势，因为它们使应用程序的使用变得简单和熟悉。这是本章的重点。

在本章中，您将使用 React Native 的 Animated API、一个名为 Lottie 的包以及 Expo 的`GestureHandler`为 React Native 应用程序添加动画和手势。它们共同使我们能够创建最充分利用移动交互方法的应用程序，这对于像*Tic-Tac-Toe*这样的游戏非常理想。此外，该应用程序将在游戏界面旁边显示此游戏的最高分排行榜。

创建这个游戏时，将涵盖以下主题：

+   使用 React Native Animated API

+   使用 Lottie 进行高级动画

+   使用 Expo 处理原生手势

# 项目概述

在本章中，我们将使用 React Native 和 Expo 创建一个带有基本动画的*Tic-Tac-Toe*游戏，使用 Animated API 添加基本动画，使用 Lottie 添加高级动画，并使用 Expo 的 Gesture Handler 处理原生手势。起点将是创建一个具有基本路由实现的 Expo CLI 应用程序，以便我们的用户可以在游戏界面和此游戏的最高分概述之间切换。

构建时间为 1.5 小时。

# 入门

我们将在本章中创建的项目是基于 GitHub 上的初始版本构建的：[`github.com/PacktPublishing/React-Projects/tree/ch9-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch9-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch10-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch9)。

您需要在移动 iOS 或 Android 设备上安装 Expo Client 应用程序，以在物理设备上运行该项目。或者，您可以在计算机上安装 Xcode 或 Android Studio，以在虚拟设备上运行该应用程序：

+   **对于 iOS**：有关如何设置本地机器以运行 iOS 模拟器的信息，请在此处找到：[`docs.expo.io/versions/v36.0.0/workflow/ios-simulator/`](https://docs.expo.io/versions/v36.0.0/workflow/ios-simulator/)。

+   **对于 Android**：有关如何设置本地机器以从 Android Studio 运行模拟器的信息，请在此处找到：[`docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/`](https://docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/)。运行模拟器时存在已知问题，可以通过确保以下行存在于您的`~/.bash_profile`或`~/.bash_rc`文件中来预防：

```jsx
export ANDROID_SDK=**ANDROID_SDK_LOCATION** export PATH=**ANDROID_SDK_LOCATION**/platform-tools:$PATH export PATH=**ANDROID_SDK_LOCATION**/tools:$PATH
```

`ANDROID_SDK_LOCATION`的值是本地机器上 Android SDK 的路径，可以通过打开 Android Studio 并转到**首选项**|**外观和行为**|**系统设置**|**Android SDK**来找到。路径在声明 Android SDK 位置的框中列出，看起来像这样：`/Users/myuser/Library/Android/sdk`。

本应用程序是使用**Expo SDK 版本 33.0.0**创建的，因此，您需要确保您在本地机器上使用的 Expo 版本是相似的。由于 React Native 和 Expo 经常更新，请确保您使用此版本，以便本章描述的模式表现如预期般。如果您的应用程序无法启动或遇到错误，请参考 Expo 文档，了解有关更新 Expo SDK 的更多信息。

# 检查初始项目

在本章中，您将要处理的应用程序已经为您构建，但我们需要通过添加诸如动画和过渡之类的功能来完成它。下载或克隆项目后，您需要进入项目的根目录，在那里您可以运行以下命令来安装依赖项并启动应用程序：

```jsx
npm install && npm start
```

这将启动 Expo 并使您能够从终端或浏览器启动项目。在终端中，您可以使用 QR 码在移动设备上打开应用程序，或选择在模拟器中打开应用程序。

无论您是在虚拟设备还是物理设备上打开应用程序，在这一点上，应用程序应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/84ec8568-59b9-490c-85a6-8fded3613a7a.jpg)

该应用程序由三个屏幕组成：`Start`，`Game`和`LeaderBoard`。第一个屏幕是`Start`，在那里可以通过点击绿色按钮开始游戏。这将导致`Game`屏幕，该屏幕设置为模态。`Start`屏幕使用选项卡导航，您还可以访问`LeaderBoard`屏幕，该屏幕将显示玩家的分数。

此 React Native 应用程序的项目结构如下。此结构类似于本书中已创建的项目：

```jsx
tic-tac-toe
|-- .expo
|-- assets
    |-- icon.png
    |-- splash.png
    |-- winner.json
|-- Components
    |-- // ...
|-- context
    |-- AppContext.js
|-- node_modules
|-- Screens
    |-- Game.js
    |-- LeaderBoard.js
    |-- Start.js
|-- utils
    |-- arrayContainsArray.js
    |-- checkSlots.js
.gitignore
App.js
AppContainer.js
app.json
babel.config.js
package.json
```

在`assets`目录中，您将找到两个图像：一个将用作应用程序的图标，一旦您在移动设备上安装了该应用程序，它将显示在主屏幕上，另一个将用作启动应用程序时显示的启动画面。还在这里放置了一个 Lottie 动画文件，您将在本章后面使用。应用程序的配置，例如 App Store，放在`app.json`中，而`babel.config.js`保存特定的 Babel 配置。

`App.js`文件是您的应用程序的实际入口点，其中导入并返回`AppContainer.js`文件，该文件在`context/AppContext.js`文件中创建的上下文提供程序中。在`AppContainer`中，定义了此应用程序的所有路由，而`AppContext`将包含应该在整个应用程序中可用的信息。在`utils`目录中，您可以找到游戏的逻辑，即填充*Tic-Tac-Toe*棋盘的函数以及确定哪个玩家赢得了比赛。

此游戏的所有组件都位于`Screens`和`Components`目录中，前者包含由`Start`，`Game`和`LeaderBoard`路由呈现的组件。这些屏幕的子组件可以在`Components`目录中找到，该目录具有以下结构：

```jsx
|-- Components
    |-- Actions
        |-- Actions.js
    |-- Board
        |-- Board.js
    |-- Button
        |-- Button.js
    |-- Player
        |-- Player.js
    |-- Slot
        |-- Slot.js
        |-- Filled.js
```

在前面结构中最重要的组件是`Board`，`Slot`和`Filled`，因为它们构成了大部分游戏。`Board`由`Game`屏幕呈现，并包含一些游戏逻辑，而`Slot`和`Filled`是在此棋盘上呈现的组件。`Actions`组件返回两个`Button`组件，以便我们可以从`Game`屏幕导航离开或重新开始游戏。`Player`显示了轮到哪个玩家或赢得比赛的玩家的名称。

# 使用 React Native 和 Expo 创建动画的井字棋游戏应用程序

手机游戏通常具有引人注目的动画，使用户想要继续玩游戏并使游戏更具互动性。已经运行的 *Tic-Tac-Toe* 游戏到目前为止没有使用任何动画，只是使用了内置的一些过渡效果，这些过渡效果是使用 React Navigation 构建的。在本节中，您将向应用程序添加动画和手势，这将改善游戏界面，并使用户在玩游戏时感到更舒适。

# 使用 React Native Animated API

在 React Native 中使用动画的多种方法之一是使用 Animated API，该 API 可在 React Native 的核心中找到。使用 Animated API，您可以默认为 `react-native` 中的 `View`、`Text`、`Image` 和 `ScrollView` 组件创建动画。或者，您可以使用 `createAnimatedComponent` 方法创建自己的组件。

# 创建基本动画

您可以添加的最简单的动画之一是通过更改元素的不透明度来使元素淡入或淡出。在您之前创建的 *Tic-Tac-Toe* 游戏中，插槽填充了绿色或蓝色，具体取决于哪个玩家填充了该插槽。由于您使用 `TouchableOpacity` 元素创建插槽，这些颜色已经显示了一个小的过渡效果。但是，可以通过使用 Animated API 为其添加自定义过渡效果。要添加动画，必须更改以下代码块：

1.  首先，在 `src/Components/Slot` 目录中创建一个新文件，并将其命名为 `Filled.js`。该文件将包含以下代码，用于构建 `Filled` 组件。在此文件中，添加以下代码：

```jsx
import  React  from  'react'; import { View } from 'react-native'; const  Filled  = ({ filled }) => { return ( <View style={{ position:  'absolute',
            display: filled ? 'block' : 'none', width:  '100%',
  height:  '100%', backgroundColor: filled === 1 ? 'blue' : 'green',  }}
    />
 ); } export  default  Filled; 
```

该组件显示一个 `View` 元素，并使用使用 JSS 语法的样式对象进行样式设置，这是 React Native 的默认语法。由于其位置是绝对的，宽度和高度均为 100%，因此该元素可以用于填充另一个元素。它还接受 `filled` 属性，以便我们可以设置 `backgroundColor` 并确定组件是否显示。

1.  您可以将此组件导入到 `Slot` 组件中，并在任何玩家填充插槽后显示它。而不是为 `SlotWrapper` 组件设置背景颜色，您可以将属于玩家一或玩家二的颜色传递给 `Filled` 组件：

```jsx
import  React  from  'react'; import { TouchableOpacity, Dimensions } from  'react-native'; import  styled  from  'styled-components/native'; + import  Filled  from  './Filled'**;** const  SlotWrapper  =  styled(TouchableOpacity)` width: ${Dimensions.get('window').width * 0.3}; height: ${Dimensions.get('window').width * 0.3}; -   background-color: ${({ filled }) => filled ? (filled === 1 ? 'blue' : 'green') : 'grey'}; + **background-color: grey;**
 border: 1px solid #fff;
`;  const Slot = ({ index, filled, handleOnPress }) => ( - <SlotWrapper filled={filled} onPress={() => !filled && handleOnPress(index)} />
+ <SlotWrapper  onPress={() => !filled && handleOnPress(index)}> + <Filled filled={filled}  />  + </SlotWrapper**>** );  export  default  Slot;
```

1.  现在，每当您单击插槽时，由于您需要先将可点击元素从`TouchableOpacity`元素更改为`TouchableWithoutFeedback`元素，因此不会发生任何可见变化。这样，默认的带不透明度的过渡就会消失，因此您可以用自己的过渡替换它。可以从`react-native`导入`TouchableWithoutFeedback`元素，并将其放置在一个`View`元素周围，该元素将保存插槽的默认样式：

```jsx
import  React  from  'react'; - import { TouchableOpacity, Dimensions } from  'react-native'; + import { TouchableWithoutFeedback, View, Dimensions } from  'react-native'; import  styled  from  'styled-components/native'; import  Filled  from  './Filled'; - const  SlotWrapper  =  styled(TouchableOpacity)` + const  SlotWrapper  =  styled(View)`  width: ${Dimensions.get('window').width * 0.3}; height: ${Dimensions.get('window').width * 0.3};  background-color: grey;
 border: 1px solid #fff;
`;   const Slot = ({ index, filled, handleOnPress }) => ( - <SlotWrapper  onPress={() => !filled && handleOnPress(index)}> + <TouchableWithoutFeedback onPress={() => !filled && handleOnPress(index)}>  +   <SlotWrapper**>**
  <Filled filled={filled} />  </SlotWrapper>
**+ <TouchableWithoutFeedback>** );  export  default  Slot;
```

现在，您刚刚按下的插槽将立即填充为您在`Filled`组件的`backgroundColor`字段中指定的颜色，而无需任何过渡。

1.  要重新创建此过渡，可以使用 Animated API，您将使用它来从插槽渲染时更改`Filled`组件的不透明度。因此，您需要在`src/Components/Slot/Filled.js`中从`react-native`导入`Animated`：

```jsx
import  React  from  'react';
**- import { View } from 'react-native';** **+ import { Animated, View } from 'react-native';** const  Filled  = ({ filled }) => { return (
    ... 
```

1.  使用 Animated API 的新实例是通过指定应在使用 Animated API 创建的动画期间更改的值来开始的。此值应该可以由整个组件的 Animated API 更改，因此您可以将此值添加到组件的顶部。由于您希望稍后可以更改此值，因此应使用`useState` Hook 创建此值：

```jsx
import  React  from  'react'; import { Animated, View } from 'react-native'; const  Filled  = ({ filled }) => {
**+ const [opacityValue] = React.useState(new Animated.Value(0));** return (
    ...
```

1.  现在，可以使用内置的三种动画类型之一（即`decay`、`spring`和`timing`）通过 Animated API 更改此值，其中您将使用 Animated API 的`timing`方法在指定的时间范围内更改动画值。可以从任何函数触发 Animated API，例如与`onPress`事件链接或从生命周期方法触发。由于`Filled`组件应仅在插槽填充时显示，因此可以使用在`filled`属性组件更改时触发的生命周期方法，即具有`filled`属性作为依赖项的`useEffect` Hook。可以删除显示的样式规则，因为当`filled`属性为`false`时，组件的`opacity`将为`0`：

```jsx
import  React  from  'react'; import { Animated, View } from 'react-native'; const  Filled  = ({ filled }) => {
  const [opacityValue] = React.useState(new Animated.Value(0)); **+** **R**eact.useEffect(() => {
+    filled && Animated.timing(
+        opacityValue, 
+ {
+ toValue:  1,
+ duration:  500, +        }
+ ).start();
+ **}, [filled]);** return ( <View style={{ position:  'absolute',
 **-          display: filled ? 'block' : 'none',** width:  '100%',
  height:  '100%', backgroundColor: filled === 1 ? 'blue' : 'green',  }}
    />
 ); } export  default  Filled;
```

`timing`方法使用您在组件顶部指定的`opacityValue`和包含 Animated API 配置的对象。其中一个字段是`toValue`，当动画结束时，它将成为`opacityValue`的值。另一个字段是字段的持续时间，它指定动画应持续多长时间。

`timing`旁边的其他内置动画类型是`decay`和`spring`。`timing`方法随着时间逐渐改变，`decay`类型的动画在开始时变化很快，然后逐渐减慢直到动画结束。使用`spring`，您可以创建动画，使其在动画结束时稍微超出其边缘。

1.  最后，您只需要将`View`元素更改为`Animated.View`元素，并将`opacity`字段和`opacityValue`值添加到`style`对象中：

```jsx
import  React  from  'react';
**- import { Animated, View } from 'react-native';** + import { Animated } from 'react-native';  const  Filled  = ({ filled }) => {

... return (    
**-** **<View**
**+   <Animated.View** style={{ position:  'absolute', width:  '100%',
  height:  '100%', backgroundColor: filled === 1 ? 'blue : 'green',
**+           opacity: opacityValue,**  }}
    />
 ); } export  default  Filled;
```

现在，当您按下任何一个插槽时，`Filled`组件将淡入，因为不透明度值在 500 毫秒内过渡。当您在 iOS 模拟器或运行 iOS 的设备上运行应用程序时，这将使填充的插槽看起来如下。在 Android 上，应用程序应该看起来类似，因为没有添加特定于平台的样式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/2db00402-f380-40e3-acbc-389e11cac37f.png)

为了使动画看起来更加流畅，您还可以向`Animated`对象添加一个`easing`字段。这个字段的值来自`Easing`模块，可以从`react-native`中导入。`Easing`模块有三个标准函数：`linear`，`quad`和`cubic`。在这里，`linear`函数可以用于更平滑的时间动画：

```jsx
import  React  from  'react'; **- import { Animated } from 'react-native';**
**+ import { Animated, Easing } from 'react-native';** const  Filled  = ({ filled }) => {
  const [opacityValue] = React.useState(new Animated.Value(0));  React.useEffect(() => {
    filled && Animated.timing(
        opacityValue, { toValue:  1, duration: 1000, **+           easing: Easing.linear(),**
        } ).start(); }, [filled]);

  return (
    ...
```

通过最后这个改变，动画已经完成，游戏界面已经感觉更加流畅，因为插槽正在使用您自己的自定义动画进行填充。在本节的下一部分中，我们将结合其中一些动画，使这个游戏的用户体验更加先进。

# 使用 Animated API 结合动画

通过改变`Filled`组件的不透明度来进行过渡已经改善了游戏界面。但是我们可以创建更多的动画来使游戏的交互更具吸引力。

我们可以做的一件事是为`Filled`组件的大小添加淡入动画。为了使这个动画与我们刚刚创建的淡入动画配合得很好，我们可以使用 Animated API 中的`parallel`方法。这个方法将在同一时刻开始指定的动画。为了创建这种效果，我们需要做出以下改变：

1.  对于这第二个动画，您希望`Filled`组件不仅具有淡入的颜色，还具有淡入的大小。为了为不透明度设置初始值，您必须为该组件的大小设置初始值：

```jsx
import  React  from  'react'; import { Animated, Easing } from 'react-native'; const  Filled  = ({ filled }) => {
  const [opacityValue] = React.useState(new Animated.Value(0));
**+ const [scaleValue] = React.useState(new Animated.Value(0));**  React.useEffect(() => {
    ...
```

1.  您在`useEffect` Hook 中创建的`Animated.timing`方法需要包装在`Animated.parallel`函数中。这样，您可以在以后添加另一个改变`Filled`组件大小的动画。`Animated.parallel`函数将`Animated`方法的数组作为参数添加，必须像这样添加：

```jsx
import  React  from  'react'; import { Animated, Easing } from  'react-native'; const  Filled  = ({ filled }) => { const [opacityValue]  = React.useState(new  Animated.Value(0)); const [scaleValue]  = React.useState(new  Animated.Value(0));  React.useEffect(() => {
**+ filled &&** Animated.parallel**([
- filled && Animated.timing(**
**+** Animated.timing**(** opacityValue, { toValue:  1, duration:  1000, easing:  Easing.linear(),
 } **-   ).start();
+  ),**
**+** ]).start**();** }, [filled]); return (
 ... 
```

除了`parallel`函数之外，还有三个函数可以帮助您进行动画组合。这些函数是`delay`、`sequence`和`stagger`，它们也可以结合使用。`delay`函数在预定义的延迟之后开始任何动画，`sequence`函数按照您指定的顺序开始动画，并在动画解决之前等待，然后开始另一个动画，`stagger`函数可以按顺序和指定的延迟同时开始动画。

1.  在`parallel`函数中，您需要添加 Animated API 的`spring`方法，该方法可以动画化`Filled`组件的大小。这次，您不会使用`timing`方法，而是使用`spring`方法，它会在动画结束时添加一点弹跳效果。还添加了一个`Easing`函数，使动画看起来更加流畅。

```jsx
...
const  Filled  = ({ filled }) => { const [opacityValue]  = React.useState(new  Animated.Value(0)); const [scaleValue]  = React.useState(new  Animated.Value(0)); React.useEffect(() => {
      filled && Animated.parallel([ Animated.timing( opacityValue, { toValue:  1, duration:  1000, easing:  Easing.linear(),
 } ),
**+       Animated.spring(**
**+         scaleValue,**
**+         {**
**+           toValue: 1,**
**+           easing: Easing.cubic(),**
**+         },**
**+       ),** ]).start(); }, [filled]); return (
        ...
```

1.  这个`spring`动画将会把`scaleValue`的值从`0`改变到`1`，并在动画结束时创建一个小的弹跳效果。`scaleValue`也必须添加到`style`对象中的`Animated.View`组件中，以使动画生效。`scaleValue`将被添加到`transform`字段中的`scale`字段中，这将改变`Filled`组件的大小：

```jsx
... return (    <Animated.View style={{ position:  'absolute', width:  '100%',
  height:  '100%', backgroundColor: filled === 1 ? 'blue' : 'green',            opacity: opacityValue,
**+           transform: [**
**+             {**
**+               scale: scaleValue,**
**+             }**
**+           ],**  }}
    />
 ); } export  default  Filled
```

当您点击任何一个插槽时，`Filled`组件不仅通过改变不透明度而淡入，还会通过改变大小来淡入。动画结束时的弹跳效果为淡入效果增添了一丝美感。

1.  然而，当您点击描绘游戏获胜者的插槽时，动画没有足够的时间结束，而获胜状态由组件渲染。因此，您还需要在设置游戏获胜者的函数中添加一个超时。这个函数可以在`src/Screens/Game.js`中找到，您可以添加一个常量来设置动画持续的毫秒数：

```jsx
import  React  from 'react'; import { View } from  'react-native'; import  styled  from  'styled-components/native'; import  Board  from  '../Components/Board/Board'; import  Actions  from  '../Components/Actions/Actions'; import  Player  from  '../Components/Player/Player'; import  checkSlots  from  '../utils/checkSlots'; import { AppContext } from  '../context/AppContext'; + export  const  ANIMATION_DURATION  =  1000**;**

...
```

这也将包装设置获胜者的函数在一个`setTimeout`函数中，这会延迟这些函数的执行时间，延迟时间与动画持续时间相同：

```jsx
...
const  checkWinner  = (player) => { const  slots  =  state[`player${player}`]; if (slots.length  >=  3) { if (checkSlots(slots)) { + setTimeout(() => { setWinner(player);
 setPlayerWins(player); +     }, ANIMATION_DURATION**);**
 } } return  false;
}

...
```

1.  由于`ANIMATION_DURATION`常量被导出，您可以在`src/Components/Slot/Filled.js`文件中导入这个常量，并在实际动画中使用相同的常量。这样，如果您在某个时候更改了动画的持续时间，您不必对其他组件进行任何更改，这些更改就会可见：

```jsx
import  React  from  'react'; import { Animated, Easing } from  'react-native'; + import { ANIMATION_DURATION } from  '../../Screens/Game';  const  Filled  = ({ filled }) => { const [opacityValue]  = React.useState(new  Animated.Value(0)); const [scaleValue]  = React.useState(new  Animated.Value(0)); React.useEffect(() => {
      filled && Animated.parallel( Animated.timing( opacityValue, { toValue:  1,
**-** duration:  1000**,**
**+           duration: ANIMATION_DURATION,** easing:  Easing.linear(),
 }
```

除了插槽现在填充了一个执行两个并行动画的动画`Filled`组件之外，当您点击其中任何一个时，设置游戏获胜者的函数将等到插槽填充后再触发。

下一节将展示如何处理更高级的动画，比如在任何两个玩家中有一个获胜时显示动画图形。为此，我们将使用 Lottie 包，因为它支持的功能比内置的 Animated API 更多。

# 使用 Lottie 进行高级动画

React Native 动画 API 非常适合构建简单的动画，但构建更高级的动画可能更难。幸运的是，Lottie 通过在 iOS、Android 和 React Native 中实时渲染 After Effects 动画，为我们提供了在 React Native 中创建高级动画的解决方案。Lottie 可以作为一个独立的包使用`npm`安装，但也可以从 Expo 获取。由于 Lottie 仍然是 Expo 的实验性功能的一部分，您可以通过从`DangerZone`命名空间中检索它来使用它。因此，目前最好是从`npm`安装 Lottie，并在要使用它的文件中导入它。

在使用 Lottie 时，您不必自己创建这些 After Effects 动画；有一个完整的资源库，您可以在项目中自定义和使用。这个库叫做`LottieFiles`，可以在`https://lottiefiles.com/`上找到。

由于您已经将动画添加到了棋盘游戏的插槽中，一个很好的地方来添加更高级的动画将是在任何一名玩家赢得比赛时显示的屏幕上。在这个屏幕上，可以显示一个奖杯，而不是棋盘，因为游戏已经结束了。现在让我们来做这个：

1.  要开始使用 Lottie，请运行以下命令，这将安装 Lottie 及其依赖项，并将其添加到您的`package.json`文件中：

```jsx
npm install lottie-react-native
```

1.  安装过程完成后，你可以继续创建一个组件，用来渲染已下载为 Lottie 文件的 After Effects 动画。这个组件可以在新的`src/Components/Winner/Winner.js`文件中创建。在这个文件中，你需要导入 React 和当然是从`lottie-react-native`中导入的 Lottie，这是你刚刚安装的：

```jsx
import React from 'react';
import Lottie from 'lottie-react-native';

const Winner = () => ();

export default Winner;
```

1.  导入的`Lottie`组件可以渲染你自己创建的或者从`LottieFiles`库下载的任何 Lottie 文件。在`assets`目录中，你会找到一个可以在这个项目中使用的 Lottie 文件，名为`winner.json`。当你将它添加到源中时，`Lottie`组件可以渲染这个文件，并且可以通过传递一个样式对象来设置动画的宽度和高度。此外，你应该添加`autoPlay`属性来在组件渲染时启动动画：

```jsx
import React from 'react';
import Lottie from 'lottie-react-native';

const Winner = () => (
+    <Lottie
+        autoPlay
+        style={{
+            width: '100%',
+            height: '100%',
+        }}
+        source={require('../../assets/winner.json')}
+    />
);

export default Winner;
```

1.  该组件现在将开始在包含此组件的任何屏幕中渲染奖杯动画。由于这个动画应该在任一玩家赢得比赛时显示出来，所以`Board`组件是一个很好的地方来添加这个组件，因为你可以使用包装样式来包裹棋盘。`Board`组件可以在`src/Components/Board/Board.js`文件中找到，你可以在这里导入`Winner`组件：

```jsx
import  React  from 'react'; import { View, Dimensions } from  'react-native'; import  styled  from  'styled-components/native'; import  Slot  from  '../Slot/Slot'; + import  Winner  from  '../Winner/Winner'**;**

... const  Board  = ({ slots, winner, setSlot }) => (
    ... 
```

在这个组件的`return`函数中，你可以检查`winner`属性是`true`还是`false`，并根据结果显示`Winner`组件或者遍历`slots`：

```jsx
const Board = ({ slots, winner, setSlot }) => (
 <BoardWrapper>
    <SlotsWrapper>
-    {slots.map((slot, index) =>
+    {
+      winner
+      ? <Winner />
+      : slots.map((slot, index) =>
            <Slot
              key={index}
              index={index}
              handleOnPress={!winner ? setSlot : () => { }}
              filled={slot.filled}
            />
        )
    }
    </SlotsWrapper>
  </BoardWrapper>
);
```

当`Board`组件接收到值为`true`的`winner`属性时，用户将看到渲染的奖杯动画，而不是棋盘。当你在 iOS 模拟器上或者 iOS 设备上运行应用程序时，可以看到这将是什么样子的例子：

![

如果你觉得这个动画的速度太快，可以通过将 Animated API 与 Lottie 结合来进行调整。`Lottie`组件可以接受一个`progress`属性，用来确定动画的速度。通过传递由 Animated API 创建的值，你可以调整动画的速度以满足自己的需求。将这个添加到 Lottie 动画中可以这样做：

1.  首先，你需要导入`Animated`和`Easing`（稍后会用到），并在组件顶部使用`Animated`和`useState` Hook 创建一个新值：

```jsx
import  React  from  'react'; + import { Animated, Easing } from  'react-native'; import  Lottie  from  'lottie-react-native'; - const  Winner  = () => ( + const Winner = () => {
+   const [progressValue]  = React.useState(new  Animated.Value(0**));**
**+   return (** <Lottie autoPlay
        style={{ width:  '100%', height:  '100%' , }} source={  require('../../assets/winner.json') } progress={progressValue} />
  );
+ };

export  default  Winner;
```

1.  在`useEffect` Hook 中，您可以创建`Animated.timing`方法，它将在您使用`duration`字段指定的时间范围内设置`progressValue`。动画应该在组件渲染时立即开始，因此 Hook 的依赖数组应为空。您还可以将`Easing.linear`函数添加到`easing`字段中，以使动画运行更顺畅：

```jsx
...
const  Winner  = () => { const [progressValue]  = React.useState(new  Animated.Value(0));

**+** React.useEffect(() => { +    Animated.timing(progressValue, { +      toValue:  1, +      duration:  4000, +      easing:  Easing.linear,
+ }).start(); **+ }, []);** return (
  ... 
```

1.  现在，`progressValue`值可以传递给`Lottie`组件，这将导致动画的不同行为：

```jsx
...

const Winner = () => {
 const [progressValue]  = React.useState(new  Animated.Value(0));

  ...

  return ( <Lottie autoPlay
      style={{ width:  '100%', height:  '100%' , }} source={  require('../../assets/winner.json') }
**+** progress={progressValue**}** />
  );
};

export  default  Winner;
```

现在，动画正在减速。动画将花费 4,000 毫秒而不是默认的 3,000 毫秒来从头到尾播放。在下一节中，您将通过处理移动设备上可用的手势，为该应用程序的用户体验增加更多复杂性。

# 使用 Expo 处理手势

手势是移动应用程序的重要特性，因为它们将决定平庸和优秀移动应用程序之间的差异。在您创建的*Tic-Tac-Toe*游戏中，可以添加几种手势以使游戏更具吸引力。

以前，您使用了`TouchableOpacity`元素，用户按下该元素后会通过更改元素来获得反馈。您还可以使用`TouchableHighlight`元素来实现这一点。与`TouchableOpacity`一样，它可以被用户按下，但是它会突出显示元素，而不是改变不透明度。这些反馈或突出显示手势让用户对在应用程序中做出决定时会发生什么有所印象，从而提高用户体验。这些手势也可以自定义并添加到其他元素中，使得可以创建自定义的可触摸元素。

为此，您可以使用一个名为`react-native-gesture-handler`的软件包，它可以帮助您在每个平台上访问原生手势。所有这些手势都将在原生线程中运行，这意味着您可以添加复杂的手势逻辑，而无需处理 React Native 手势响应系统的性能限制。它支持的一些手势包括轻触、旋转、拖动和平移手势。使用 Expo CLI 创建的任何项目都可以在不必手动安装软件包的情况下使用`react-native-gesture-handler`中的`GestureHandler`。

您还可以直接从 React Native 中使用手势，而无需使用额外的包。然而，React Native 目前使用的手势响应系统并不在原生线程中运行。这不仅限制了创建和自定义手势的可能性，还可能遇到跨平台或性能问题。因此，建议您使用`react-native-gesture-handler`包，但在 React Native 中使用手势并不需要这个包。

# 处理轻击手势

我们将实现的第一个手势是轻击手势，它将被添加到`Slot`组件中，以便为用户的操作提供更多反馈。用户轻击时不会填充插槽，而是在轻击事件开始时就会收到一些反馈，并在事件完成时收到反馈。在这里，我们将使用`react-native-gesture-handler`中的`TouchableWithoutFeedback`元素，它在原生线程中运行，而不是使用手势响应系统的`react-native`中的`TouchableWithoutFeedback`元素。可以通过以下步骤将`react-native`组件替换为`react-native-gesture-handler`中的组件：

1.  `TouchableWithoutFeedback`可以从`react-native-gesture-handler`中导入到`src/components/Slot.js`文件的顶部：

```jsx
import  React  from  'react'; - import { TouchableWithoutFeedback, View, Dimensions } from  'react-native';
+ import {  View, Dimensions } from  'react-native';  + import **{ Tou**chableWithoutFeedback } from  'react-native-gesture-handler'; import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... const  Slot  = ({ index, filled, handleOnPress }) => ( ...
```

您不必在返回函数中做任何更改，因为`TouchableWithoutFeedback`使用与`react-native`相同的 props。当您轻击插槽时，什么都不会改变。这是因为插槽将由`Filled`组件填充，一旦出现就会显示动画。

1.  当您轻击任何插槽并将手指放在上面时，`handleOnPress`函数还不会被调用。只有当您通过移开手指完成轻击手势时，手势才会结束，并且`handleOnPress`函数将被调用。当您触摸插槽开始轻击手势时，可以使用`TouchableWithoutFeedback`中的`onPressIn`回调来启动动画。一旦轻击事件开始，就需要向`Filled`组件传递一个值，该值指示它应该开始动画。这个值可以使用`useState` Hook 创建，因此您已经有一个可以调用以更改此值的函数。当通过从元素上移开手指结束轻击事件时，应调用`handleOnPress`函数。您可以使用`onPressOut`回调来实现这一点：

```jsx
import  React  from  'react'; import { View, Dimensions } from  'react-native'; import { TapGestureHandler, State } from  'react-native-gesture-handler';  import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... - const  Slot  = ({ index, filled, handleOnPress }) => ( + const  Slot  = ({ index, filled, handleOnPress }) => {  +  const [start, setStart] = React.useState(false);

+  return ( -    <TouchableWithoutFeedback onPress={() => !filled && handleOnPress(index)}> +    <TouchableWithoutFeedback onPressIn={() => setStart()} onPressOut={() => !filled && handleOnPress(index)}>
 <SlotWrapper> - <Filled filled={filled}  /> + <Filled filled={filled} start={start}  />  </SlotWrapper>
 </TouchableWithoutFeedback>  );
};

export default Slot;
```

1.  在`src/Components/Slot/Filled.js`文件中的`Filled`组件中，您需要检查`start`属性，并在此属性的值为`true`时开始动画。由于您不希望在`start`的值为`true`时启动整个动画，只有改变`opacityValue`的动画会开始：

```jsx
import  React  from  'react'; import { Animated, Easing } from  'react-native'; import { ANIMATION_DURATION } from  '../../utils/constants'; - const  Filled  = ({ filled }) => { + const  Filled  = ({ filled, start }) => **{**  const [opacityValue] =  React.useState(new  Animated.Value(0));
**-** const [scaleValue] =  React.useState(new  Animated.Value(0)); + const [scaleValue] =  React.useState(new  Animated.Value(.8**));** + React.useEffect(() => { + start  &&  Animated.timing( + opacityValue, +     { + toValue:  1, + duration:  ANIMATION_DURATION, + easing:  Easing.linear(),
+     } +   ).start(); + }, [start**]);**

  React.useEffect(() => {    ...
```

1.  此外，可以从检查`filled`属性的`useEffect` Hook 中删除改变不透明度的动画。此`useEffect` Hook 仅处理改变比例的动画。应该更改初始的`scaleValue`，否则组件的大小将等于`0`：

```jsx
+ const  Filled  = ({ filled, start }) => **{**  const [opacityValue] =  React.useState(new  Animated.Value(0));
**-** const [scaleValue] =  React.useState(new  Animated.Value(0)); + const [scaleValue] =  React.useState(new  Animated.Value(.8**));** React.useEffect(() => {

... React.useEffect(() => { - filled && Animated.parallel([ -   Animated.timing( -     opacityValue, -     { - toValue:  1, - duration:  ANIMATION_DURATION, - easing:  Easing.linear(),
- } -   ),
-   Animated.spring(
+   filled && Animated.spring**(** scaleValue,
      {
  toValue:  1,
  easing:  Easing.cubic(),
      }
**-    )**
**-  ]).start()**
**+**  ).start();  }, [filled]);

...
```

当您在进行这些更改后轻击任何插槽时，将启动`timing`动画，并且一个正方形将出现在插槽中，这表示正在轻击插槽。一旦您从该插槽释放手指，正方形将改变大小，并且在`spring`动画开始时填充插槽的其余部分，这发生在`onPress`函数改变`filled`的值时。

# 自定义轻击手势

现在，插槽具有不同的动画，取决于轻击事件的状态，这可能对用户在选择哪个插槽时犹豫不决很有用。用户可能会从所选插槽上移开手指，此时轻击事件将遵循不同的状态流。您甚至可以确定用户是否应该长时间点击插槽以使选择变得明确，或者像在某些社交媒体应用程序上喜欢图片一样双击插槽。

要创建更复杂的轻击手势，您需要知道轻击事件经历不同的状态。`TouchableWithoutFeedback`在底层使用`TapGestureHandler`，并且可以经历以下状态：`UNDETERMINED`，`FAILED`，`BEGAN`，`CANCELLED`，`ACTIVE`和`END`。这些状态的命名非常直观，通常情况下，处理程序将具有以下流程：`UNDETERMINED > BEGAN > ACTIVE > END > UNDETERMINED`。当您在`TouchableWithoutFeedback`元素的`onPressIn`回调中添加函数时，此函数在轻击事件处于`BEGAN`状态时被调用。当状态为`END`时，将调用`onPressOut`回调，而默认的`onPress`回调则响应于`ACTIVE`状态。

要创建这些复杂的手势，您可以使用`react-native-gesture-handler`包，通过自己处理事件状态，而不是使用可触摸元素的声明方式：

1.  `TapGestureHandler`可以从`react-native-gesture-handler`中导入，并允许您创建自定义的可触摸元素，您可以自己定义手势。您需要从`react-native-gesture-handler`中导入`State`对象，其中包含您需要用来检查轻触事件状态的常量：

```jsx
import  React  from  'react'; - import { TouchableWithoutFeedback } from  'react-native-gesture-handler'; + import { TapGestureHandler, State } from  'react-native-gesture-handler';import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... const  Slot  = ({ index, filled, handleOnPress }) => (   ...
```

1.  不要像`onPress`那样使用事件处理程序，`TouchableWithoutFeedback`元素有一个名为`onHandlerStateChange`的回调。每当`TapGestureHandler`的状态发生变化时，例如当元素被点击时，都会调用这个函数。通过使用`TapGestureHandler`来创建可触摸元素，您就不再需要`TouchableWithoutFeedback`元素。这个元素的功能可以移动到您将要创建的新元素中：

```jsx
... const  Slot  = ({ index, filled, handleOnPress }) => {
...

return ( - <TouchableWithoutFeedback onPressIn={() => setStart()} onPressOut={() => !filled && handleOnPress(index)}>  + <TapGestureHandler onHandlerStateChange={onTap}**>**
  <SlotWrapper>
  <Filled filled={filled} start={start}  />  </SlotWrapper> - </TouchableWithoutFeedback>
+ </TapGestureHandler**>**
 );
}; ...
```

1.  `onHandlerStateChange`接受`onTap`函数，您仍然需要创建，并检查轻触事件的当前状态。当轻触事件处于`BEGAN`状态时，类似于`onPressIn`处理程序，应该开始`Filled`的动画。轻触事件的完成状态为`END`，类似于`onPressOut`处理程序，在这里您将调用`handleOnPress`函数，该函数会更改有关点击插槽的玩家的属性值。将调用`setStart`函数来重置启动动画的状态。

```jsx
import  React  from  'react'; import { View, Dimensions } from  'react-native'; import { TapGestureHandler, State } from  'react-native-gesture-handler';  import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... const  Slot  = ({ index, filled, handleOnPress }) => {
    const [start, setStart] = React.useState(false);   + const  onTap  = event => { +    if (event.nativeEvent.state === State.BEGAN) {
+       setStart(true);
+    }  + if (event.nativeEvent.state  ===  State.END) {  +       !filled && handleOnPress(index);
+       setStart(false);
+    }
+ }

  return (
    ...
```

当您点击任何一个插槽并将手指放在上面时，`handleOnPress`函数不会被调用。只有当您完成轻触手势并移开手指时，手势才会结束，并调用`handleOnPress`函数。

这些手势甚至可以进行更多的自定义，因为您可以使用组合来拥有多个相互响应的轻触事件。通过创建所谓的**跨处理程序交互**，您可以创建一个支持双击手势和长按手势的可触摸元素。通过设置并传递使用 React `useRef` Hook 创建的引用，您可以让来自`react-native-gesture-handler`的手势处理程序监听其他处理程序的状态生命周期。这样，您可以按顺序响应事件和手势，比如双击事件：

1.  要创建引用，您需要将`useRef` Hook 放在组件顶部，并将此引用传递给`TapGestureHandler`：

```jsx
import  React  from  'react'; import { View, Dimensions } from  'react-native'; import { TapGestureHandler, State } from  'react-native-gesture-handler'; import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... const  Slot  = ({ index, filled, handleOnPress }) => { const [start, setStart] =  React.useState(false); +  const  doubleTapRef  =  React.useRef(null);

   ...  return ( -    <TapGestureHandler onHandlerStateChange={onTap}> + <TapGestureHandler + ref={doubleTapRef} + onHandlerStateChange={onTap} **+    >**
  <SlotWrapper>
  <Filled  filled={filled}  start={start}  />
  </SlotWrapper>
  </TapGestureHandler>
 ); }; export default Slot;
```

1.  现在，您需要设置开始和完成轻击手势所需的轻击次数。由于第一次轻击元素时，不必对`onTap`函数进行任何更改，轻击事件的状态将为`BEGAN`。只有在您连续两次轻击元素后，轻击事件状态才会变为`END`：

```jsx
... return (
 <TapGestureHandler
 ref={doubleTapRef}
 onHandlerStateChange={onTap}
**+   numberOfTaps={2}**
 >  <SlotWrapper>
  <Filled  filled={filled}  start={start}  />
  </SlotWrapper>
  </TapGestureHandler> );  ...
```

1.  要填充一个插槽，用户必须轻击`TapGestureHandler`两次才能完成轻击事件。但是，您还可以在轻击一次`TapGestureHandler`时调用一个函数，方法是添加另一个以现有的一个为其子元素的`TapGestureHandler`。这个新的`TapGestureHandler`应该等待另一个处理程序进行双击手势，它可以使用`doubleTapRef`来检查。`onTap`函数应该重命名为`onDoubleTap`，这样您就有了一个新的`onTap`函数来处理单击：

```jsx
...

const  Slot  = ({ index, filled, handleOnPress }) => {  const [start, setStart] =  React.useState(false);
  const  doubleTapRef  =  React.useRef(null); + const  onTap  =  event  => {**};** - const  onTap  =  event  => { + const  onDoubleTap  =  event  => **{** ... }  return ( + <TapGestureHandler + onHandlerStateChange={onTap} + waitFor={doubleTapRef} + **>**
  <TapGestureHandler
  ref={doubleTapRef} - onHandlerStateChange={onTap} + onHandlerStateChange={onDoubleTap**}**
  numberOfTaps={2}
  > 
 <SlotWrapper>
           <Filled  filled={filled}  start={start}  /> </SlotWrapper>
      </TapGestureHandler>
**+** </TapGestureHandler> ); }

...
```

1.  当您仅单击插槽时，动画将开始，因为`TapGestureHandler`将处于`BEGAN`状态。双击手势上的动画应该只在状态为`ACTIVE`而不是`BEGAN`时开始，这样动画就不会在单击时开始。此外，通过向轻击手势结束时调用的函数添加`setTimeout`，动画看起来会更加流畅，因为否则两个动画会在彼此之后太快地发生：

```jsx
...

const  Slot  = ({ index, filled, handleOnPress }) => {  const [start, setStart] =  React.useState(false);
  const  doubleTapRef  =  React.useRef(null);

  const  onTap  =  event  => {};   const  onDoubleTap  =  event  => { - if (event.nativeEvent.state  ===  State.BEGAN) { +    if (event.nativeEvent.state  ===  State.ACTIVE) {        setStart(true);
 }     
     if (event.nativeEvent.state  ===  State.END) {
**+**  setTimeout(() => **{** !filled  &&  handleOnPress(index);
         setStart(false);
**+**  }, 100**);**
     }  }

...
```

除了具有双击手势来填充插槽之外，具有长按手势也可以改善用户的交互。您可以通过以下步骤添加长按手势：

1.  从`react-native-gesture-handler`导入`LongPressGestureHandler`。

```jsx
import  React  from  'react'; import { View, Dimensions } from  'react-native'; - import { TapGestureHandler, State } from 'react-native-gesture-handler'; + import { LongPressGestureHandler, TapGestureHandler, State } from  'react-native-gesture-handler'**;** import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

...
```

1.  在此处理程序上，您可以设置长按手势的最短持续时间，并设置在此时间段过去后应调用的函数。`LongPressGestureHandler`处理程序具有状态生命周期，您可以与`onDoubleTap`函数一起使用：

```jsx
... const  Slot  = ({ index, filled, handleOnPress }) => {
 ... return ( +  <LongPressGestureHandler + onHandlerStateChange={onDoubleTap} + minDurationMs={500**}**
**+  >** <TapGestureHandler
  onHandlerStateChange={onTap}
  waitFor={doubleTapRef}
  >
 ...  </TapGestureHandler>  +   </LongPressGestureHandler>  ) };

export default Slot;
```

如果您只想创建一个长按手势，可以使用`react-native`和`react-native-gesture-handler`中可用的可触摸元素上的`onLongPress`事件处理程序。建议您使用`react-native-gesture-handler`中的可触摸元素，因为它们将在本机线程中运行，而不是使用 React Native 手势响应系统。

1.  也许并非所有用户都会理解他们需要使用长按手势来填充一个插槽。因此，您可以使用`onTap`函数，在单击时调用，向用户提醒此功能。为此，您可以使用适用于 iOS 和 Android 的`Alert` API，并使用这些平台中的任何一个的本机警报消息。在此警报中，您可以为用户添加一条小消息：

```jsx
import  React  from  'react'; - import { View, Dimensions } from 'react-native'; + import { Alert, View, Dimensions } from  'react-native'**;** import { LongPressGestureHandler, TapGestureHandler, State } from  'react-native-gesture-handler'; import  styled  from  'styled-components/native'; import  Filled  from  './Filled';

... const  Slot  = ({ index, filled, handleOnPress }) => {  const [start, setStart] =  React.useState(false);
  const  doubleTapRef  =  React.useRef(null);

  const  onTap  =  event  => { + if (event.nativeEvent.state  ===  State.ACTIVE) { +     Alert.alert( + 'Hint', + 'You either need to press the slot longer to make your move', +     ); **+   }**
 }

  ... 
```

当用户在棋盘上没有使用长按来移动时，将显示警报，从而使用户更容易理解。通过这些最终的添加，游戏界面得到了进一步改进。用户不仅会看到基于其操作的动画，还将被通知他们可以使用哪些手势。

# 总结

在本章中，我们为使用 React Native 和 Expo 构建的简单*井字棋*游戏添加了动画和手势。动画是使用 React Native Animated API 和 Expo CLI 以及作为单独包的 Lottie 创建的。我们还为游戏添加了基本和更复杂的手势，这得益于`react-native-gesture-handler`包在本地线程中运行。

动画和手势为您的移动应用程序的用户界面提供了明显的改进，我们还可以做更多。但是，我们的应用程序还需要向用户请求和显示数据。

之前，我们在 React 中使用了 GraphQL。我们将在下一章中继续构建。在下一章中，您将创建的项目将使用 WebSockets 和 Apollo 在 React Native 应用程序中处理实时数据。

# 进一步阅读

+   各种 Lottie 文件：[`lottiefiles.com/`](https://lottiefiles.com/)

+   有关 Animated API 的更多信息：[`facebook.github.io/react-native/docs/animated`](https://facebook.github.io/react-native/docs/animated)


# 第十章：使用 React Native 和 Expo 创建实时消息应用程序

与服务器建立实时连接在开发实时消息应用程序时至关重要，因为您希望用户在发送消息后尽快收到消息。您可能在前两章中经历过的是，移动应用程序比 Web 应用程序更直观。当您希望用户来回发送消息时，最好的方法是构建一个移动应用程序，这就是本章将要做的事情。

在这一章中，您将使用 React Native 和 Expo 创建一个实时移动消息应用程序，该应用程序与 GraphQL 服务器连接。通过使用 WebSockets，您可以为 Web 和移动应用程序与服务器创建实时连接，并在应用程序和 GraphQL 服务器之间实现双向数据流。这种连接也可以用于身份验证，使用 OAuth 和 JWT 令牌，这就是您在第七章中所做的事情，*使用 React Native 和 GraphQL 构建全栈电子商务应用程序*。

本章将涵盖以下主题：

+   使用 Apollo 的 React Native 中的 GraphQL

+   React Native 中的身份验证流程

+   GraphQL 订阅

# 项目概述

在本章中，我们将使用 React Native 和 Expo 创建一个移动消息应用程序，该应用程序使用 GraphQL 服务器进行身份验证并发送和接收消息。通过使用 Apollo 创建的 WebSocket，可以实时接收消息，因为使用了 GraphQL 订阅。用户需要登录才能通过应用程序发送消息，为此使用了 React Navigation 和 AsyncStorage 构建了身份验证流程，以将身份验证详细信息存储在持久存储中。

构建时间为 2 小时。

# 入门

我们将在本章中创建的项目是在初始版本的基础上构建的，您可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch10-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch10-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch10`](https://github.com/PacktPublishing/React-Projects/tree/ch10)。

您需要在移动 iOS 或 Android 设备上安装应用程序 Expo Client，以在物理设备上运行该项目。或者，您可以在计算机上安装 Xcode 或 Android Studio，以在虚拟设备上运行应用程序：

+   **对于 iOS**：有关如何设置本地机器以运行 iOS 模拟器的信息，请参见此处：[`docs.expo.io/versions/v36.0.0/workflow/ios-simulator/`](https://docs.expo.io/versions/v36.0.0/workflow/ios-simulator/)。

+   **对于 Android**：有关如何设置本地机器以从 Android Studio 运行模拟器的信息，请参见此处：[`docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/`](https://docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/)。在运行模拟器时存在已知问题，可以通过确保以下行存在于您的`~/.bash_profile`或`~/.bash_rc`文件中来防止该问题：

```jsx
export ANDROID_SDK=**ANDROID_SDK_LOCATION**export PATH=**ANDROID_SDK_LOCATION**/platform-tools:$PATH export PATH=**ANDROID_SDK_LOCATION**/tools:$PATH
```

`ANDROID_SDK_LOCATION`的值是您本地计算机上 Android SDK 的路径，可以通过打开 Android Studio 并转到**首选项**|**外观和行为**|**系统设置**|**Android SDK**来找到。路径在声明 Android SDK 位置的框中列出，看起来像这样：`/Users/myuser/Library/Android/sdk`。

该应用程序是使用 Expo SDK 版本 33.0.0 创建的，因此，您需要确保您在本地机器上使用的 Expo 版本是相似的。由于 React Native 和 Expo 经常更新，请确保您使用此版本，以便本章描述的模式表现如预期。如果您的应用程序无法启动或遇到错误，请参考 Expo 文档以了解有关更新 Expo SDK 的更多信息。

# 检查初始项目

该项目由两部分组成：一个样板 React Native 应用程序和一个 GraphQL 服务器。React Native 应用程序可以在`client`目录中找到，而 GraphQL 服务器可以在`server`目录中找到。对于本章，您需要始终同时运行应用程序和服务器，您只会对`client`目录中的应用程序进行代码更改。

要开始本章，您需要在`client`和`server`目录中运行以下命令，以安装所有依赖项并启动服务器和应用程序：

```jsx
npm install && npm start
```

对于移动应用程序，此命令将在安装依赖项后启动 Expo，并使您能够从终端或浏览器启动项目。在终端中，您可以使用 QR 码在移动设备上打开应用程序，也可以在虚拟设备上打开应用程序。

无论您是使用物理设备还是虚拟 iOS 或 Android 设备打开应用程序，应用程序应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/8dab731f-78bf-46e1-8bdf-21b18befa226.png)

初始应用程序包括五个屏幕：`AuthLoading`、`Conversations`、`Conversation`、`Login`和`Settings`。`Conversations`屏幕将是初始屏幕，并显示加载消息，而`Settings`屏幕包含一个不起作用的注销按钮。目前，`AuthLoading`、`Conversation`和`Login`屏幕尚不可见，因为您将在本章后面为这些屏幕添加路由。

在`client`目录中，此 React Native 应用程序的项目结构如下，结构类似于您在本书中之前创建的项目：

```jsx
messaging
|-- client
    |-- .expo
    |-- assets
        |-- icon.png
        |-- splash.png
    |-- Components
        |-- // ...
    |-- node_modules
    |-- Screens
        |-- AuthLoading.js
        |-- Conversation.js
        |-- Conversations.js
        |-- Login.js
        |-- Settings.js
    |-- .watchmanconfig
    |-- App.js
    |-- AppContainer.js
    |-- app.json
    |-- babel.config.js
    |-- package.json
```

在`assets`目录中，您可以找到用于主屏幕应用程序图标的图像。一旦您在移动设备上安装了此应用程序，启动应用程序时将显示用作启动画面的图像。有关应用程序的详细信息，如名称、描述和版本，都放在`app.json`中，而`babel.config.js`包含特定的 Babel 配置。

`App.js`文件是您的应用程序的实际入口点，其中导入并返回`AppContainer.js`文件。在`AppContainer`中，定义了此应用程序的所有路由，并且`AppContext`将包含应该在整个应用程序中可用的信息。

此应用程序的所有组件都位于`Screens`和`Components`目录中，其中第一个包含由屏幕呈现的组件。这些屏幕的子组件可以在`Components`目录中找到，其结构如下：

```jsx
|-- Components
    |-- Button
        |-- Button.js
    |-- Conversation
        |-- ConversationActions.js
        |-- ConversationItem.js
    |-- Message
        |-- Message.js
    |-- TextInput
        |-- TextInput.js
```

GraphQL 服务器位于：`http://localhost:4000/graphql`，GraphQL Playground 将在此处可见。通过这个 Playground，您可以查看 GraphQL 服务器的模式，并审查所有可用的查询、变异和订阅。虽然您不会对服务器进行任何代码更改，但了解模式及其工作原理是很重要的。

服务器有两个查询，一个是通过使用`userName`参数作为标识符来检索对话列表，另一个是检索单个对话。这些查询将返回`Conversation`类型，其中包括`id`、`userName`和`Message`类型的消息列表。

在这个 GraphQL 服务器上，可以找到两个变异，一个是登录用户，另一个是发送消息。用户可以通过以下方式登录：

+   **用户名**：`test`

+   **密码**：`test`

最后，有一个订阅将检索添加到对话中的消息。这个订阅将增强查询，并可以发送到一个文档中以检索单个对话。

# 使用 React Native 和 Expo 创建实时消息应用程序

移动应用程序受欢迎的原因之一是它们通常提供实时数据，例如更新和通知。使用 React Native 和 Expo，您可以创建能够使用 WebSockets 处理实时数据的移动应用程序，例如与 GraphQL 服务器同步。在本章中，您将向 React Native 应用程序添加 GraphQL，并为该应用程序添加额外功能，使其能够处理实时数据。

# 使用 Apollo 在 React Native 中使用 GraphQL

在[第七章](https://cdp.packtpub.com/react_projects_/wp-admin/post.php?post=33&action=edit#post_30)中，*使用 React Native 和 GraphQL 构建全栈电子商务应用程序*，您已经为 Web 应用程序建立了与 GraphQL 服务器的连接；同样，在本章中，您将为移动应用程序中的数据使用 GraphQL 服务器。要在 React Native 应用程序中使用 GraphQL，您可以使用 Apollo 来使开发人员的体验更加顺畅。

# 在 React Native 中设置 Apollo

`react-apollo`包，你已经在 React web 应用程序中使用过 Apollo，也可以在 React Native 移动应用程序中使用。这与 React 和 React Native 的标语“学一次，随处编写”完美契合。但在将 Apollo 添加到应用程序之前，重要的是要知道，当你在移动设备上使用 Expo 应用程序运行应用程序时，不支持本地主机请求。该项目的本地 GraphQL 服务器正在运行在`http://localhost:4000/graphql`，但为了能够在 React Native 应用程序中使用这个端点，你需要找到你的机器的本地 IP 地址。

要找到你的本地 IP 地址，你需要根据你的操作系统做以下操作：

+   **对于 Windows**：打开终端（或命令提示符）并运行这个命令：

```jsx
ipconfig
```

这将返回一个列表，如下所示，其中包含来自本地机器的数据。在这个列表中，你需要查找**IPv4 Address**字段：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/b0033c76-9caf-4443-9f99-328624f755e8.png)

+   **对于 macOS**：打开终端并运行这个命令：

```jsx
ipconfig getifaddr en0
```

运行这个命令后，你的机器的本地`Ipv4 Address`将被返回，看起来像这样：

```jsx
192.168.1.107
```

获取本地 IP 地址后，你可以使用这个地址来为 React Native 应用程序设置 Apollo 客户端。为了能够使用 Apollo 和 GraphQL，你需要使用以下命令从`npm`安装`npm`中的几个包。你需要在一个单独的终端标签中从`client`目录中执行这个命令：

```jsx
cd client && npm install graphql apollo-client apollo-link-http apollo-cache-inmemory react-apollo
```

在`App.js`文件中，你现在可以使用`apollo-client`来创建你的 GraphQL 客户端，使用`apollo-link-http`来设置与本地 GraphQL 服务器的连接，并使用`apollo-cache-inmemory`来缓存你的 GraphQL 请求。此外，`ApolloProvider`组件将使用你创建的客户端，使 GraphQL 服务器对所有嵌套在此提供程序中的组件可用。必须使用本地 IP 地址来创建`API_URL`的值，前缀为`http://`，后缀为`:4000/graphql`，指向正确的端口和端点，使其看起来像`http://192.168.1.107:4000/graphql`。

为了做到这一点，将以下行添加到`App.js`中：

```jsx
import React from 'react';
import AppContainer from './AppContainer';
+ import { ApolloClient } from 'apollo-client';
+ import { InMemoryCache } from 'apollo-cache-inmemory';
+ import { HttpLink } from 'apollo-link-http';
+ import { ApolloProvider } from 'react-apollo';

+ const API_URL = 'http://192.168.1.107:4000/graphql';

+ const cache = new InMemoryCache();
+ const client = new ApolloClient({
+   link: new HttpLink({
+     uri: API_URL,
+   }),
+   cache
+ });

- const App = () => <AppContainer />;

+ const App = () => (
+  <ApolloProvider client={client}>
+     <AppContainer />
+  </ApolloProvider>
+ );

export default App;
```

现在，您可以从`ApolloProvider`中的任何嵌套组件发送带有查询和变异的文档，但是您还不能在文档中发送订阅。订阅的支持并不是开箱即用的，需要为客户端 React Native 应用程序和 GraphQL 服务器之间的实时双向连接设置 WebSocket。这将在本章后面完成，之后您将为应用程序添加认证。

在本节的下一部分中，您将使用 Apollo 从 GraphQL 服务器获取数据，您刚刚在本节中将其链接到 Apollo Client。

# 在 React Native 中使用 Apollo

如果您查看应用程序，您会看到有两个选项卡；一个显示`Conversations`屏幕，另一个显示`Settings`屏幕。`Conversations`屏幕现在显示文本`Loading...`，应该显示从 GraphQL 服务器返回的对话。用于显示对话的组件已经创建，可以在`client/Components/Conversation`目录中找到，而请求对话的逻辑仍需要创建。

要添加 Apollo，请按照以下步骤：

1.  第一步是从`react-apollo`中导入`Query`组件到`client/Screens/Conversations.js`文件中，您将使用它向 GraphQL 服务器发送文档。这个`Query`组件将使用`GET_CONVERSATIONS`查询，`ConversationItem`组件也必须被导入：

```jsx
import  React  from 'react'; import { FlatList, Text, View } from 'react-native'; import  styled  from 'styled-components/native'; + import { Query } from 'react-apollo';  + import { GET_CONVERSATIONS } from '../constants'; + import  ConversationItem  from '../Components/Conversations/ConversationItem'; ... const  Conversations  = () => (
 ...
```

1.  `Conversations`屏幕现在应该使用`Query`组件请求`GET_CONVERSATIONS`查询。当请求未解决时，将显示加载消息。当向 GraphQL 服务器的请求解决时，样式化的`Flatlist`将返回导入的`ConversationItem`组件列表。样式化的`Flatlist`已经创建，可以在该文件底部的`ConversationsList`组件中找到：

```jsx
...

const  Conversations  = () => (  <ConversationsWrapper> - <ConversationsText>Loading...</ConversationsText> +   <Query query={GET_CONVERSATIONS}> +     {({ loading, data }) => { +       if (loading) { +         return <ConversationsText>Loading...</ConversationsText> +       } +       return ( +         <ConversationsList +           data={data.conversations} +           keyExtractor={item => item.userName} +           renderItem={({ item }) => <ConversationItem item={item} /> } +         /> +       ); +     }} +   </Query>  </ConversationsWrapper> ); export default Conversations;
```

`Conversations`屏幕最初显示加载消息，当发送带有查询的文档时；在查询返回数据后，将显示`ConversationsList`组件。该组件呈现显示查询数据的`ConversationItem`组件。

1.  当您尝试点击任何对话时，除了看到一个改变不透明度的小动画之外，什么也不会发生。这是因为`ConversationItem`组件是一个样式化的`TouchableOpacity`，当您点击它时可以作为一个被调用的函数传递。用于导航到对话的函数可以从`Conversations`屏幕中可用的`navigation`属性中创建。这个属性应该作为一个属性传递给`ConversationItem`。

```jsx
...

- const  Conversations  = () => ( + const  Conversations  = ({ navigation ) => **(** <ConversationsWrapper>
  <ConversationsText>Loading...</ConversationsText>
 <Query query={GET_CONVERSATIONS}> {({ loading, data }) => { if (loading) { return <ConversationsText>Loading...</ConversationsText> } return ( <ConversationsList data={data.conversations} keyExtractor={item => item.userName} -             renderItem={({ item }) => <ConversationItem item={item} /> }
+ renderItem={({ item }) => <ConversationItem item={item} navigation={navigation} />}  /> ); }} </Query>  </ConversationsWrapper> ); export default Conversations;
```

1.  `ConversationItem`组件现在可以在点击`TouchableOpacity`时导航到`Conversation`屏幕；这个组件可以在`client/Components/Conversation/ConversationItem.js`文件中找到，其中应该解构并使用`navigation`属性来调用`onPress`处理程序上的`navigate`函数。这个项目被传递给`navigate`函数，以便这些数据可以在`Conversation`屏幕中使用：

```jsx
import  React  from 'react'; import { Platform, Text, View, TouchableOpacity } from 'react-native'; import { Ionicons }  from '@expo/vector-icons'; import  styled  from 'styled-components/native';

... - const ConversationItem = ({ item }) => ( + const  ConversationItem  = ({ item, navigation }) => ( -   <ConversationItemWrapper> +   <ConversationItemWrapper +     onPress={() =>  navigation.navigate('Conversation', { item })} **+   >**
      <ThumbnailWrapper>
        ... 
```

1.  这将从`client/Screens/Conversation.js`文件中导航到`Conversation`屏幕，其中应该显示完整的对话。要显示对话，您可以使用刚刚传递到此屏幕的项目数据，或者发送另一个包含检索对话的查询的文档到 GraphQL 服务器。为了确保显示最新的数据，`Query`组件可以用来发送一个查询，使用从`navigation`属性中的`userName`字段来检索对话。为了做到这一点，您需要导入`Query`组件、`Query`使用的`GET_CONVERSATION`查询，以及用于显示对话中消息的`Message`组件：

```jsx
import  React  from 'react'; import { Dimensions, ScrollView, Text, FlatList, View } from 'react-native'; + import { Query } from 'react-apollo'; import  styled  from 'styled-components/native'; + import  Message  from '../Components/Message/Message'; + import { GET_CONVERSATION } from '../constants'**;**

... const  Conversation  = () => (  ...
```

1.  在此之后，您可以将`Query`组件添加到`Conversation`屏幕，并让它使用从`navigation`属性中检索到的`userName`与`GET_CONVERSATION`查询。一旦查询解析，`Query`组件将返回一个带有名为`messages`的字段的`data`对象。这个值可以传递给`FlatList`组件。在这个组件中，您可以遍历这个值并返回显示对话中所有消息的`Message`组件。`FlatList`已经被样式化，并且可以在文件底部找到，命名为`MessagesList`：

```jsx
... - const  Conversation  = () => { + const  Conversation  = ({ navigation }) => { +   const  userName  =  navigation.getParam('userName', '');  + return **(** <ConversationWrapper>  -       <ConversationBodyText>Loading...</ConversationBodyText> +       <Query query={GET_CONVERSATION} variables={{ userName }}>        <ConversationBody> +         {({ loading, data }) => { +           if (loading) { +             return <ConversationBodyText>Loading...</ConversationBodyText>; +           } +           const { messages } = data.conversation;
  +           <MessagesList
+ data={messages}
+ keyExtractor={item  =>  String(item.id)}
+ renderItem={({ item }) => (
+ <Message  align={item.userName === 'me' ? 'left' : 'right'}>
+ {item.text}
+ </Message>
+ )}
+ />  +         }}        </ConversationBody>**+     </Query>**  <ConversationActions userName={userName}  />
 </ConversationWrapper>
 ); + }; export default Conversation;
```

现在正在显示来自这次对话的所有接收到的消息，并且可以使用屏幕底部的表单向对话中添加新消息。

根据您运行应用程序的设备，运行 iOS 设备的`Conversation`和`Conversation`屏幕应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/d97e780f-273a-4650-8f51-317bc80ce117.png)

然而，要发送消息，必须向 GraphQL 服务器发送带有突变的文档，并且用户必须经过身份验证。如何处理此突变的身份验证将在下一节中讨论，身份验证流程将被添加。

# React Native 中的身份验证

通常，移动应用程序的身份验证类似于在 Web 应用程序中处理身份验证，尽管存在一些细微差异。在移动应用程序上对用户进行身份验证的流程如下：

1.  用户打开您的应用程序

1.  显示检查持久存储中的任何身份验证信息的加载屏幕

1.  如果经过身份验证，用户将被转发到应用程序的主屏幕；否则，他们将被转发到登录屏幕，用户可以在那里登录

1.  每当用户退出登录时，身份验证详细信息将从持久存储中删除

这种流程的最大缺点之一是移动设备不支持本地存储或会话存储，因为这些持久存储解决方案与浏览器绑定。相反，您需要使用 React Native 中的`AsyncStorage`库在 iOS 和 Android 上实现持久存储。在 iOS 上，它将使用本机代码块为您提供`AsyncStorage`提供的全局持久存储，而在运行 Android 的设备上，将使用基于 RockDB 或 SQLite 的存储。

对于更复杂的用法，建议在`AsyncStorage`的顶层使用抽象层，因为`AsyncStorage`不支持加密。此外，如果要使用`AsyncStorage`为应用程序存储大量信息，键值系统的使用可能会导致性能问题。iOS 和 Android 都会对每个应用程序可以使用的存储量设置限制。

# 使用 React Navigation 进行身份验证

要设置我们之前描述的身份验证流程，你将再次使用 React Navigation 包。之前，你使用了 React Navigation 中的不同类型的导航器，但没有使用`SwitchNavigator`。使用这种导航器类型，你只能一次显示一个屏幕，并且可以使用`navigation`属性导航到其他屏幕。`SwitchNavigator`应该是你的应用程序的主要导航器，其他导航器如`StackNavigator`可以嵌套在其中。

向 React Native 应用程序添加身份验证涉及执行以下步骤：

1.  使用这种导航器类型的第一步是从`react-navigation`导入`createSwitchNavigator`，就像你将其他导航器导入到`client/AppContainer.js`文件中一样。还要导入登录屏幕的屏幕组件，可以在`client/Screens/Login.js`中找到：

```jsx
import  React  from 'react'; import { Platform } from 'react-native'; import { Ionicons }  from '@expo/vector-icons'; import {  + createSwitchContainer,    createAppContainer  } from 'react-navigation'; import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';
import  Conversations  from './Screens/Conversations'; import  Conversation  from './Screens/Conversation'; import  Settings  from './Screens/Settings'; + import  Login  from './Screens/Login'**;** const  ConversationsStack  =  createStackNavigator({
  ... 
```

1.  不要在此文件底部用`createAppContainer`包装`TabNavigator`，而是需要返回`SwitchNavigator`。要创建这个，你需要使用在上一步中导入的`createSwitchNavigator`。这个导航器包含`Login`屏幕和`TabNavigator`，后者是这个应用程序的主屏幕。为了让用户只在经过身份验证时看到主屏幕，`Login`屏幕需要成为初始屏幕：

```jsx
...

+ const SwitchNavigator = createSwitchNavigator( +   { +     Main: TabNavigator, +     Auth: Login +   }, +   { +     initialRouteName: 'Auth', +   } + ); - export default createAppContainer(TabNavigator); + export default createAppContainer(SwitchNavigator);
```

现在在应用程序中显示的`Login`屏幕只有在填写正确的身份验证详细信息时才会切换到`TabNavigator`。

1.  但是，此表单首先需要连接到 GraphQL 服务器，以接收身份验证所需的 JWT 令牌。`Login`屏幕的组件已经有一个表单，但是提交此表单尚未调用任何函数来对用户进行身份验证。因此，你需要使用`react-apollo`中的`Mutation`组件，并让该组件向 GraphQL 服务器发送包含正确变异的文档。需要添加到此组件的变异可以在`constants.js`文件中找到，称为`LOGIN_USER`。要提交表单，应该在用户按下`Button`时调用`Mutation`组件返回的`loginUser`函数：

```jsx
import React from 'react';
import { View, TextInput } from 'react-native';
import styled from 'styled-components/native';
+ import { Mutation } from 'react-apollo';
import Button from '../Components/Button/Button';
+ import { LOGIN_USER } from '../constants';

... const Login = () => {
 const [userName, setUserName] = React.useState('');
 const [password, setPassword] = React.useState('');

 return (
+  <Mutation mutation={LOGIN_USER}>
+    {loginUser => (
       <LoginWrapper>
          <StyledTextInput
            onChangeText={setUserName}
            value={userName}
            placeholder='Your username'
            textContentType='username'
          />
          <StyledTextInput
            onChangeText={setPassword}
            value={password}
            placeholder='Your password'
            textContentType='password'
          />
          <Button
            title='Login'
+           onPress={() => loginUser({ variables: { userName, password } })}
          />
        </LoginWrapper>
+    )}
+  </Mutation>
 );
};

export default Login;
```

两个`TextInput`组件都是受控组件，并使用`useState`钩子来控制它们的值。用于此变异的`userName`和`password`常量都使用两个变量进行身份验证，这两个变量也是`userName`和`password`：

```jsx
... export  const  LOGIN_USER  =  gql`
 mutation loginUser($userName: String!, $password: String!) {
   loginUser(userName: $userName, password: $password) {
     userName
     token
   }
 }
`;
...
```

1.  除了`loginUser`函数之外，该函数发送了一个文档中的变化，`Mutation`组件还会返回由 GraphQL 服务器返回的`loading`、`error`和`data`变量。`loading`变量可用于向用户传达文档已发送到服务器，而当 GraphQL 服务器对此文档做出响应时，将返回`data`和`error`变量：

```jsx
import React from 'react';
import { View, TextInput } from 'react-native';
import styled from 'styled-components/native';
import { Mutation } from 'react-apollo';
import Button from '../Components/Button/Button';
import { LOGIN_USER } from '../constants'; ... const Login = () => {
 const [userName, setUserName] = React.useState('');
 const [password, setPassword] = React.useState('');

 return (
  <Mutation mutation={LOGIN_USER}>
-    {loginUser => (
+    {(loginUser, { loading }) => (  <LoginWrapper>
          <StyledTextInput
            onChangeText={setUserName}
            value={userName}
            placeholder='Your username'
            textContentType='username'
          />
          <StyledTextInput
            onChangeText={setPassword}
            value={password}
            placeholder='Your password'
            textContentType='password'
          />
          <Button
-           title='Login'
+           title={loading ? 'Loading...' : 'Login'}
            onPress={() => loginUser({ variables: { userName, password } })}
          />
       </LoginWrapper>
    }}
   </Mutation>
 );
};

export default Login;
```

当文档发送到 GraphQL 服务器并且尚未返回响应时，这将会改变表单底部按钮的文本为`Loading...`。

1.  要使用`error`变量在填写错误凭据时显示错误消息，您不会从`Mutation`组件的输出中解构该变量。相反，错误变量将从`loginUser`函数返回的`Promise`中检索。为了显示错误，您将使用`error`变量中可用的`graphQLErrors`方法，该方法返回一个数组（因为可能存在多个错误），并在 React Native 的`Alert`组件中呈现错误：

```jsx
import React from 'react';
- import { View, TextInput } from 'react-native';
+ import { Alert, View, TextInput } from 'react-native';
import styled from 'styled-components/native';
import { Mutation } from 'react-apollo';
import Button from '../Components/Button/Button';
import { LOGIN_USER } from '../constants';

...

 <Button
   title={loading ? 'Loading...' : 'Login'}
   onPress={() => {     loginUser({ variables: { userName, password } })
**+** .catch(error  => {
+ Alert.alert(
+         'Error',
+         error.graphQLErrors.map(({ message }) =>  message)[0] +        );
+    });
   }}
 />

...
```

1.  当使用正确的用户名和密码组合时，应使用`data`变量来存储由 GraphQL 服务器返回的 JWT 令牌。就像从`loginUser`函数中检索的`error`变量一样，`data`变量也可以从这个`Promise`中检索。这个令牌可用于`data`变量，并且应该被安全地存储，可以使用`AsyncStorage`库来实现：

```jsx
import  React  from 'react';  - import { Alert, View, TextInput } from 'react-native';
+ import { AsyncStorage, Alert, View, TextInput } from 'react-native';  import  styled  from 'styled-components/native';  import { Mutation } from 'react-apollo';  import  Button  from '../Components/Button/Button';  import { LOGIN_USER } from '../constants'; ... const  Login  = ({ navigation }) => {
  ... 
  <Button
    title={loading ? 'Loading...' : 'Login'}
    onPress={() => {      loginUser({ variables: { userName, password } }) +       .then(({data}) => { +         const { token } = data.loginUser; +         AsyncStorage.setItem('token', token);  +       })
        .catch(error  => {         if (error) {
            Alert.alert(
              'Error',
              error.graphQLErrors.map(({ message }) =>  message)[0], );
          }
        });
      }}
    /> 
    ...
```

1.  存储令牌后，用户应被重定向到主应用程序，该应用程序可以在`Main`路由中找到，并表示与`TabNavigator`相关联的屏幕。要重定向用户，您可以使用`SwitchNavigator`通过传递给`Login`组件的`navigation`属性。由于使用`AsyncStorage`存储东西应该是异步的，因此应该从`AsyncStorage`返回的`Promise`的回调中调用导航函数：

```jsx
import  React  from 'react';  import { AsyncStorage, Alert, View, TextInput } from 'react-native';  import  styled  from 'styled-components/native';  import { Mutation } from 'react-apollo';  import  Button  from '../Components/Button/Button';  import { LOGIN_USER } from '../constants'; ... - const  Login  = () => { + const  Login  = ({ navigation }) => { ... 
<Button
 title={loading ? 'Loading...' : 'Login'}
 onPress={() => { loginUser({ variables: { userName, password } })  .then(({data}) => {    const { token } = data.loginUser;
**-** AsyncStorage.setItem('token', token) +   AsyncStorage.setItem('token', token).then(value  => { +     navigation.navigate('Main'); +   });    })
  .catch(error  => { if (error) { Alert.alert( 'Error', error.graphQLErrors.map(({ message }) =>  message)[0], );
    }
  });
 }} />

...
```

然而，这只完成了认证流程的一部分，因为当应用程序首次渲染时，`Login`屏幕将始终显示。这样，用户始终必须使用他们的认证详细信息登录，即使他们的 JWT 令牌存储在持久存储中。

要检查用户以前是否已登录，必须向`SwitchNavigator`中添加第三个屏幕。这个屏幕将确定用户是否在持久存储中存储了令牌，如果有，用户将立即重定向到`Main`路由。如果用户以前没有登录，则会重定向到你刚刚创建的`Login`屏幕：

1.  确定是否在持久存储中存储了身份验证令牌的中间屏幕，即`AuthLoading`屏幕，应该在`App.js`中添加到`SwitchNavigator`中。这个屏幕也应该成为导航器提供的初始路由：

```jsx
import  React  from 'react';  import { Platform } from 'react-native';  import { Ionicons }  from '@expo/vector-icons';  import {   createSwitchNavigator,
  createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';  import  Conversations  from './Screens/Conversations';  import  Conversation  from './Screens/Conversation';  import  Settings  from './Screens/Settings';  import  Login  from './Screens/Login';  + import  AuthLoading  from './Screens/AuthLoading'; const  ConversationsStack  =  createStackNavigator({

  ...   const  SwitchNavigator  =  createSwitchNavigator(
  {
    Main:  TabNavigator,    Login,
**+   AuthLoading,**
  },
  {
-   initialRouteName: 'Login',
+   initialRouteName: 'AuthLoading',
  }
);export default createAppContainer(SwitchNavigator);
```

1.  在这个`AuthLoading`屏幕中，应该从持久存储中检索身份验证令牌，然后处理导航到`Login`或`Main`屏幕。这个屏幕可以在`client/Screens/AuthLoading.js`文件中找到，那里只添加了一个简单的界面。可以使用`AsyncStorage`库中的`getItem`方法来检索令牌，并且应该从`useEffect` Hook 中调用，以便在首次加载`AuthLoading`屏幕时检索它。从`callback`和`Promise`返回的`getItem`中，使用`navigation`属性的`navigate`函数来实际导航到这些屏幕中的任何一个：

```jsx
import  React  from 'react';  - import { Text, View } from 'react-native'; + import { AsyncStorage, Text, View } from 'react-native'; import  styled  from 'styled-components/native'; ... - const AuthLoading = () => ( + const  AuthLoading  = ({ navigation }) => { + React.useEffect(() => { + AsyncStorage.getItem('token').then(value  => { +       navigation.navigate(value  ? 'Main'  : 'Auth'); +     }); +   }, [navigation]); +   return **(** <AuthLoadingWrapper> <AuthLoadingText>Loading...</AuthLoadingText> </AuthLoadingWrapper>
 ); **+ };**

export default AuthLoading;
```

1.  完成身份验证流程的最后一步是通过从持久存储中删除令牌来为用户添加注销应用的可能性。这是在`client/Screens/Settings.js`文件中完成的。这会呈现`TabNavigator`中的`Settings`屏幕。`Settings`屏幕上有一个绿色按钮，你可以在上面设置`onPress`事件。

`AsyncStorage`的`removeItem`方法可用于从持久存储中删除令牌，并返回`Promise`。在这个`Promise`的回调中，你可以再次处理导航，以返回到`Login`屏幕，因为你不希望未经身份验证的用户在你的应用中。

```jsx
import  React  from 'react';  - import { Text, View } from 'react-native'; + import { AsyncStorage, Text, View } from 'react-native';  import  styled  from 'styled-components/native';  import  Button  from '../Components/Button/Button'; ... - const Settings = () => ( + const  Settings  = ({ navigation }) => **(**
      <SettingsWrapper> - <Button title='Log out' /> +       <Button +         title='Log out' +         onPress={() => { +           AsyncStorage.removeItem('token').then(() =>  navigation.navigate('AuthLoading')); +         }} **+       />**
 </SettingsWrapper>
 );

export default Settings;
```

通过添加注销功能，您已经完成了使用 GraphQL 服务器返回的 JWT 令牌的身份验证流程。这可以通过在“登录”屏幕上填写表单来请求。如果身份验证成功，用户将被重定向到“主”屏幕，并且通过“设置”屏幕上的“注销”按钮，用户可以注销并将被重定向回“登录”屏幕。最终的身份验证流程现在看起来可能是这样的，具体取决于您在哪个操作系统上运行此应用程序。以下屏幕截图是从运行 iOS 的设备上获取的：

！[](assets/22c6656d-d2d5-4501-b80f-804de21ebd29.png)

然而，为了 GraphQL 服务器知道这个用户是否经过身份验证，您需要向其发送一个验证令牌。在本节的下一部分，您将学习如何通过使用 JSON Web Token（JWT）来实现这一点。

# 向 GraphQL 服务器发送身份验证详细信息

现在存储在持久存储中的身份验证详细信息也应该添加到 Apollo Client 中，以便在每个文档中与 GraphQL 服务器一起发送。这可以通过扩展 Apollo Client 的设置与令牌信息来完成。由于令牌是 JWT，因此应该以`Bearer`为前缀：

1.  您需要安装一个 Apollo 包来处理向“上下文”添加值。`setContext`方法来自`apollo-link-context`包，您可以从`npm`安装该包：

```jsx
npm install apollo-link-context
```

1.  应该将`apollo-link-context`包导入到`client/App.js`文件中，其中创建了 Apollo 客户端。您需要分开为客户端创建`HttpLink`对象的构造，因为这个对象需要与创建的上下文结合使用：

```jsx
import  React  from 'react';  import { ApolloClient } from 'apollo-client';  import { InMemoryCache } from 'apollo-cache-inmemory'; **+ import { setContext }  from 'apollo-link-context';** import { HttpLink } from 'apollo-link-http';  import { ApolloProvider } from 'react-apollo';  import  AppContainer  from './AppContainer'; const API_URL = '..'; + const  httpLink  =  new  HttpLink({ + uri: API_URL,**+ });** const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({ - link: new HttpLink({ -   uri: API_URL, - }), + link:  httpLink**,**
 cache, }); const  App  = () => (
 ...
```

1.  之后，您可以使用`setContext()`方法来扩展发送到 GraphQL 服务器的标头，以便还可以包括可以从持久存储中检索的令牌。由于从`AsyncStorage`获取项目也是异步的，因此应该异步使用此方法。将返回的令牌必须以`Bearer`为前缀，因为 GraphQL 服务器期望以该格式接收 JWT 令牌：

```jsx
import React from 'react';
+ import { AsyncStorage } from 'react-native';
import AppContainer from './AppContainer';
import { ApolloClient } from 'apollo-client';
import { InMemoryCache } from 'apollo-cache-inmemory';
import { setContext } from 'apollo-link-context';
import { HttpLink } from 'apollo-link-http';
import { ApolloProvider } from 'react-apollo';

const API_URL = '...';

const  httpLink  =  new  HttpLink({
  uri:  API_URL,  }); 
+ const  authLink  =  setContext(async (_, { headers }) => { +   const  token  =  await  AsyncStorage.getItem('token'); +   return { +     headers: { +       ...headers, +       authorization:  token  ?  `Bearer ${token}`  : '',  +     }
+   };
+ });  ...
```

1.  在创建 Apollo Client 时用于`link`字段的`httpLink`现在应该与`authLink`结合，以便从`AsyncStorage`检索到的令牌在发送请求到 GraphQL 服务器时被添加到标头中：

```jsx
...

const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({ - link: httpLink,
+ link:  authLink.concat(httpLink),  cache }); const  App  = () => (
  ...
```

现在，任何传递给 GraphQL 服务器的文档都可以使用通过应用程序登录表单检索到的令牌，这是在下一节中使用变异发送消息时所需的内容。

# 使用 Apollo 在 React Native 中处理订阅

在您可以继续并发送包含变异的文档到 GraphQL 服务器之前，我们需要设置 Apollo 以便处理订阅。为了处理订阅，需要为您的应用程序设置一个 WebSocket，这样可以在 GraphQL 服务器和您的应用程序之间建立实时的双向连接。这样，当您使用这个移动应用程序发送或接收消息时，您将收到即时反馈。

# 为 GraphQL 订阅设置 Apollo 客户端

要在您的 React Native 应用程序中使用订阅，您需要添加更多的软件包到项目中，例如，使其可能添加 WebSocket。这些软件包如下：

```jsx
npm install apollo-link-ws subscriptions-transport-ws apollo-utilities
```

`apollo-link-ws`软件包帮助您创建到运行订阅的 GraphQL 服务器的链接，就像`apollo-link-http`为查询和变异所做的那样。`subscriptions-transport-ws`是运行`apollo-link-ws`所需的软件包，而`apollo-utilities`被添加以使用这些软件包上可用的方法，以便您可以将有关订阅的请求与查询或变异的请求分开。

安装这些软件包后，您需要按照以下步骤在应用程序中使用订阅：

1.  您可以使用`apollo-link-ws`来添加链接到 GraphQL 服务器的创建。GraphQL 服务器的 URL 应该以`ws://`开头，而不是`http://`，因为它涉及与 WebSocket 的连接。在您的机器上运行的 GraphQL 服务器的 URL 看起来像`ws://192.168.1.107/graphql`，而不是`http://192.168.1.107/graphql`，必须添加到`SOCKET_URL`常量中：

```jsx
import  React  from 'react'; import { AsyncStorage } from 'react-native'; import { ApolloClient } from 'apollo-client';  import { InMemoryCache } from 'apollo-cache-inmemory'; import { setContext } from 'apollo-link-context'; import { HttpLink } from 'apollo-link-http';  + import { split } from 'apollo-link';  import { ApolloProvider } from 'react-apollo';  import  AppContainer  from './AppContainer'; const API_URL = '...';
**+ const SOCKET_URL = 'ws://192.168.1.107/graphql';** ...

+ const  wsLink  =  new  WebSocketLink({ +   uri: SOCKET_URL,  +   options: { +     reconnect:  true, +   },
+ });

...
```

1.  使用`split`和`getMainDefinition`方法，可以通过将查询和变异与订阅分开来区分对 GraphQL 服务器的不同请求。这样，只有包含订阅的文档才会使用 WebSocket 发送，而查询和变异将使用默认流程：

```jsx
import  React  from 'react'; import { AsyncStorage } from 'react-native'; import { ApolloClient } from 'apollo-client';  import { InMemoryCache } from 'apollo-cache-inmemory'; import { setContext } from 'apollo-link-context'; import { HttpLink } from 'apollo-link-http';  import { split } from 'apollo-link'; + import { WebSocketLink } from 'apollo-link-ws';  + import { getMainDefinition } from 'apollo-utilities';  import { ApolloProvider } from 'react-apollo';  import  AppContainer  from './AppContainer'; ... + const  link  =  split( +   ({ query }) => { +     const  definition  =  getMainDefinition(query);
+ +     return ( +       definition.kind  === 'OperationDefinition'  && definition.operation  === 'subscription' +     );
+   },
+   wsLink, +   httpLink,
+ );

const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({ - link: authLink.concat(httpLink),
+ link: authLink.concat(link),
 cache,
});

const  App  = () => (
 ...
```

现在 Apollo 的设置也支持订阅，您将在本节的下一部分中添加，其中`Conversations`屏幕将填充实时数据。

# 将订阅添加到 React Native

在您的本地 GraphQL 服务器上运行的服务器支持查询和订阅，以便您可以从特定用户返回对话。查询将返回完整的对话，而订阅将返回可能已发送或接收到的对话中的任何新消息。目前，`Conversation`屏幕只会发送一个带有查询的文档，如果您点击`Conversations`屏幕上显示的任何对话，它将返回与用户的对话。

订阅可以以多种方式添加到您的应用程序中；使用`react-apollo`中的`Subscription`组件是最简单的方法。但由于您已经使用`client/Screens/Conversation.js`中的`Query`组件检索对话，因此可以扩展`Query`组件以支持订阅：

1.  向`Conversation`屏幕添加订阅的第一步是将屏幕拆分为多个组件。您可以通过在`client/Components/Conversation`目录中创建一个名为`ConversationBody`的新组件来实现这一点。该文件应该被命名为`ConversationBody.js`，并包含以下代码：

```jsx
import  React  from 'react';  import  styled  from 'styled-components/native';  import { Dimensions, ScrollView, FlatList } from 'react-native';  import  Message  from '../Message/Message';  const  ConversationBodyWrapper  =  styled(ScrollView)`
 width: 100%; padding: 2%;
 display: flex; height: ${Dimensions.get('window').height * 0.6}; `; const  MessagesList  =  styled(FlatList)`
 width: 100%; `; const  ConversationBody  = ({  userName, messages }) => {  return ( <ConversationBodyWrapper> <MessagesList data={messages} keyExtractor={item  =>  String(item.id)} renderItem={({ item }) => ( <Message  align={item.userName === 'me' ? 'left' : 'right'}> {item.text} </Message> )} /> </ConversationBodyWrapper>
 ); };  export  default  ConversationBody;
```

1.  创建了这个新组件之后，应该将其导入到`client/Screens/Conversation.js`文件中的`Conversation`屏幕中，以取代该文件中已经存在的`ContainerBody`组件。这也意味着一些导入变得过时，`ContainerBody`样式组件也可以被删除：

```jsx
import  React  from 'react';  - import { Dimensions, ScrollView, Text, FlatList, View } from 'react-native';  + import { Text, View } from 'react-native';  import { Query } from 'react-apollo';  import  styled  from 'styled-components/native';  - import  Message  from '../Components/Message/Message'; + import ConversationBody from '../Components/Conversation/ConversationBody'; import { GET_CONVERSATION } from '../constants';   ... const  Conversation  = ({ navigation }) => { const  userName  =  navigation.getParam('userName', ''); return ( <ConversationWrapper> <Query query={GET_CONVERSATION} variables={{ userName }}> -       <ConversationBody>   {({ loading, data }) => { if (loading) { return <ConversationBodyText>Loading...</ConversationBodyText>; } const { messages } = data.conversation;  -           return ( -             <MessagesList
- data={messages}
- keyExtractor={item  =>  String(item.id)}
- renderItem={({ item }) => (
- <Message  align={item.userName === 'me' ? 'left' : 'right'}>
- {item.text}
- </Message>
- )}
- /> -           ); -         }} +         return <ConversationBody messages={messages} userName={userName} /> }} -     </ConversationBody>   </Query>  <ConversationActions userName={userName}  />
 </ConversationWrapper>
 ); };

export default Conversation;
```

1.  现在，可以将检索订阅的逻辑添加到`Query`组件中，通过从中获取`subscribeToMore`方法。这个方法应该传递给`ConversationBody`组件，在那里它将被调用，从而检索发送或接收到的任何新消息：

```jsx
 ...

  return ( <ConversationWrapper> <Query query={GET_CONVERSATION} variables={{ userName }}> -       {({ loading, data }) => {
+       {({ subscribeToMore, loading, data }) => {
 if (loading) { return <ConversationBodyText>Loading...</ConversationBodyText>; } const { messages } = data.conversation;  -         return <ConversationBody messages={messages} userName={userName} />
+         return (
+           <ConversationBody
+             messages={messages}
+             userName={userName}
+             subscribeToMore={subscribeToMore}
+           /> }} </Query>  <ConversationActions userName={userName}  />
 </ConversationWrapper>
 ); };
```

1.  在`ConversationBody`组件中，现在可以使用`subscribeToMore`方法通过订阅来检索添加到对话中的任何新消息。要使用的订阅称为`MESSAGES_ADDED`，可以在`client/constants.js`文件中找到。它以`userName`作为变量：

```jsx
import  React  from 'react';  import  styled  from 'styled-components/native';  import { Dimensions, ScrollView, FlatList } from 'react-native';  import  Message  from '../Message/Message';  + import { MESSAGE_ADDED } from '../../constants'; ... - const  ConversationBody  = ({  userName, messages }) => { + const  ConversationBody  = ({ subscribeToMore, userName, messages }) => **{**  return ( <ConversationBodyWrapper> <MessagesList data={messages} keyExtractor={item  =>  String(item.id)} renderItem={({ item }) => ( <Message  align={item.userName === 'me' ? 'left' : 'right'}> {item.text} </Message> )} /> </ConversationBodyWrapper>
 ); };

export default ConversationBody;
```

1.  在导入订阅并从 props 中解构`subscribeToMore`方法之后，可以添加检索订阅的逻辑。应该从`useEffect` Hook 中调用`subscribeToMore`，并且仅当`ConversationBody`组件首次挂载时。任何新添加的消息都将导致`Query`组件重新渲染，这将使`ConversationBody`组件重新渲染，因此在`useEffect` Hook 中不需要检查任何更新：

```jsx
... const  ConversationBody  = ({ subscribeToMore, userName, messages }) => { +  React.useEffect(() => { +    subscribeToMore({ +      document:  MESSAGE_ADDED, +      variables: { userName }, +      updateQuery: (previous, { subscriptionData }) => { +        if (!subscriptionData.data) { +          return  previous; +        }
+        const  messageAdded  =  subscriptionData.data.messageAdded;
+ +        return  Object.assign({}, previous, { +          conversation: { +            ...previous.conversation, +            messages: [...previous.conversation.messages, messageAdded] +          }
+        });
+     }
+   });
+ }, []);
   return ( <ConversationBodyWrapper>
 ...
```

`subscribeToMore`方法现在将使用`MESSAGES_ADDED`订阅来检查任何新消息，并将该订阅的结果添加到名为`previous`的对象上的`Query`组件中。本地 GraphQL 服务器将每隔几秒钟返回一条新消息，因此您可以通过打开对话并等待新消息出现在该对话中来查看订阅是否起作用。

除了查询，您还希望能够发送实时订阅。这将在本节的最后部分进行讨论。

# 使用订阅与突变

除了使用订阅来接收对话中的消息，它们还可以用于显示您自己发送的消息。以前，您可以在`Mutation`组件上使用`refetchQueries`属性来重新发送受到您执行的突变影响的任何查询的文档。通过使用订阅，您不再需要重新获取，例如，对话查询，因为订阅将获取您刚刚发送的新消息并将其添加到查询中。

在上一节中，您使用了来自`react-apollo`的`Query`组件向 GraphQL 服务器发送文档，而在本节中，将使用新的 React Apollo Hooks。

React Apollo Hooks 可以从`react-apollo`包中使用，但如果您只想使用 Hooks，可以通过执行`npm install @apollo/react-hooks`来安装`@apollo/react-hooks`。GraphQL 组件，如`Query`或`Mutation`，在`react-apollo`和`@apollo/react-components`包中都可用。使用这些包将减少捆绑包的大小，因为您只导入所需的功能。

这个包中的 Hooks 必须在`ConversationActions`组件中使用。这在`Conversation`屏幕组件中使用，该组件将包括输入消息的输入字段和发送消息的按钮。当您按下此按钮时，什么也不会发生，因为按钮未连接到变异。让我们连接这个按钮，看看订阅如何显示您发送的消息：

1.  `useMutation` Hook 应该被导入到`client/Components/Conversation/ConversationActions.js`文件中，该文件将用于将输入字段中的消息发送到 GraphQL 服务器。还必须导入将包含在您发送的文档中的变异，名为`SEND_MESSAGE`；这可以在`client/constants.js`文件中找到：

```jsx
import  React  from 'react';  import { Platform, Text, View } from 'react-native';  import  styled  from 'styled-components/native';  import { Ionicons }  from '@expo/vector-icons';  + import { useMutation } from 'react-apollo'; import  TextInput  from '../TextInput/TextInput';  import  Button  from '../Button/Button';  + import { SEND_MESSAGE } from '../../constants'; ... const  ConversationActions  = ({ userName }) => {
  ...
```

1.  这个`useMutation` Hook 现在可以用来包裹`TextInput`和`Button`组件，来自 Hook 的`sendMessage`属性可以用来向 GraphQL 服务器发送带有消息的文档。`TextInput`的值由`useState` Hook 创建的`setMessage`函数控制，这个函数可以在发送变异后用来清除`TextInput`：

```jsx
...
const  ConversationActions  = ({ userName }) => { + const [sendMessage] = useMutation(SEND_MESSAGE);   const [message, setMessage] =  React.useState('');
 return ( <ConversationActionsWrapper> + **<>** <TextInput width={75} marginBottom={0} onChangeText={setMessage} placeholder='Your message' value={message} /> <Button width={20} padding={10}
**+** onPress={() => {
+ sendMessage({ variables: { to:  userName, text:  message } });
+ setMessage(''); +         }**}**
 title={ <Ionicons name={`${Platform.OS === 'ios' ? 'ios' : 'md'}-send`} size={42} color='white' /> } /> +     </>  +   </ConversationActionsWrapper**>**
 ); };
```

通过在文本字段中输入值并在之后按下发送按钮来发送消息，现在会更新对话，显示您刚刚发送的消息。但是，您可能会注意到，这个组件会在移动设备屏幕的大小上被键盘遮挡。通过使用`react-native`中的`KeyboardAvoidingView`组件，可以轻松避免这种行为。这个组件将确保输入字段显示在键盘区域之外。

1.  `KeyboardAvoidingView`组件可以从`react-native`中导入，并用于替换当前正在样式化为`ConversationsActionsWrapper`组件的`View`组件：

```jsx
import  React  from 'react';  - import { Platform, Text, View } from 'react-native';  + import { Platform, Text, KeyboardAvoidingView } from 'react-native';  import  styled  from 'styled-components/native';  import { Ionicons }  from '@expo/vector-icons';  import { useMutation } from 'react-apollo';  import  TextInput  from '../TextInput/TextInput';  import  Button  from '../Button/Button';  import { SEND_MESSAGE } from '../../constants';  - const  ConversationActionsWrapper  =  styled(View)` + const  ConversationActionsWrapper  =  styled(KeyboardAvoidingView)**`**
    width: 100%;
    background-color: #ccc;
    padding: 2%;
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-around;
`; const  ConversationActions  = ({ userName }) => {

 ... 
```

1.  根据您的移动设备运行的平台，`KeyboardAvoidingView`组件可能仍然无法在键盘区域之外显示输入字段。但是，`KeyboardAvoidingView`组件可以使用`keyboardVerticalOffset`和`behavior`属性进行自定义。对于 iOS 和 Android，这些属性的值应该不同；一般来说，Android 需要比 iOS 更小的偏移量。在这种情况下，`keyboardVerticalOffset`必须设置为`190`，`behavior`必须设置为`padding`：

```jsx
...

const  ConversationActions  = ({ userName }) => { const [sendMessage] = useMutation(SEND_MESSAGE);
  const [message, setMessage] =  React.useState('');
 return ( -   <ConversationActionsWrapper +   <ConversationActionsWrapper +     keyboardVerticalOffset={Platform.OS === 'ios' ? 190 : 140} +     behavior=;padding' **+   >**
 <Mutation  mutation={SEND_MESSAGE}> ... 
```

`KeyboardAvoidingView`在 Android Studio 模拟器或运行 Android 的设备上可能无法按预期工作，因为可以运行 Android 操作系统的设备有许多不同的可能屏幕尺寸。

当您按下输入字段时，键盘将不再隐藏在键盘后面，您应该能够输入并发送一条消息，该消息将发送一个包含对 GraphQL 服务器的突变的文档。您的消息还将出现在先前显示的对话中。

# 摘要

在本章中，您构建了一个移动消息应用程序，可以用于与 GraphQL 服务器发送和接收消息。通过使用 GraphQL 订阅，消息可以实时接收，通过 WebSocket 接收消息。此外，还添加了移动身份验证流程，这意味着用户必须登录才能发送和接收消息。为此，使用`AsyncStorage`将 GraphQL 服务器返回的 JWT 令牌存储在持久存储中。

您在本章中构建的项目非常具有挑战性，但您将在下一章中创建的项目将更加先进。到目前为止，您已经处理了大多数 React Native 移动应用程序的核心功能，但还有更多内容。下一章将探讨如何使用 React Native 和 GraphQL 构建全栈应用程序，您将向社交媒体应用程序添加通知等功能。

# 进一步阅读

有关本章涵盖的更多信息，请查看以下资源：

+   WebSockets: [`developer.mozilla.org/en-US/docs/Web/API/WebSocket`](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)

+   Apollo React Hooks: [`www.apollographql.com/docs/react/api/react-hooks/`](https://www.apollographql.com/docs/react/api/react-hooks/)


# 第十一章：使用 React Native 和 GraphQL 构建全栈社交媒体应用程序

到目前为止，你几乎可以称自己是 React Native 的专家了，因为你即将开始在 React Native 部分中工作最复杂的应用程序。移动应用程序的一个巨大优势是，你可以直接向安装了你的应用程序的人发送通知。这样，你可以在应用程序中发生重要事件或有人很久没有使用应用程序时，针对用户。此外，移动应用程序可以直接使用设备的相机拍照和录像。

在上一章中，你创建了一个移动消息应用程序，具有身份验证流程和实时数据，并使用 React Native 的 GraphQL。这些模式和技术也将在本章中使用，以创建一个移动社交媒体应用程序，让你将图片发布到社交动态，并允许你对这些帖子进行点赞和评论。在本章中，使用相机不仅是一个重要的部分，还将添加使用 Expo 向用户发送通知的可能性。

本章将涵盖以下主题：

+   使用 React Native 和 Expo 的相机

+   使用 React Native 和 GraphQL 刷新数据

+   使用 Expo 发送移动通知

# 项目概述

一个移动社交媒体应用程序，使用本地 GraphQL 服务器请求和添加帖子到社交动态，包括使用移动设备上的相机。使用本地 GraphQL 服务器和 React Navigation 添加基本身份验证，同时使用 Expo 访问相机（滚动）并在添加新评论时发送通知。

构建时间为 2 小时。

# 入门

我们将在本章中创建的项目基于 GitHub 上的初始版本：[`github.com/PacktPublishing/React-Projects/tree/ch11-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch11-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch11`](https://github.com/PacktPublishing/React-Projects/tree/ch11)。

你需要在移动 iOS 或 Android 设备上安装 Expo Client 应用程序，才能在物理设备上运行项目。

强烈建议使用 Expo Client 应用程序在物理设备上运行本章的项目。目前，仅支持在物理设备上接收通知，并且在 iOS 模拟器或 Android Studio 模拟器上运行项目将导致错误消息。

或者，您可以在计算机上安装 Xcode 或 Android Studio 来在虚拟设备上运行应用程序：

+   **对于 iOS**：可以在这里找到如何设置本地机器以运行 iOS 模拟器的信息：[`docs.expo.io/versions/v36.0.0/workflow/ios-simulator/`](https://docs.expo.io/versions/v36.0.0/workflow/ios-simulator/)。

+   **对于 Android**：可以在这里找到如何设置本地机器以从 Android Studio 运行模拟器的信息：[`docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/`](https://docs.expo.io/versions/v36.0.0/workflow/android-studio-emulator/)。在运行模拟器时存在已知问题，可以通过确保以下行存在于您的`~/.bash_profile`或`~/.bash_rc`文件中来防止这种情况：

```jsx
export ANDROID_SDK=**ANDROID_SDK_LOCATION** export PATH=**ANDROID_SDK_LOCATION**/platform-tools:$PATH export PATH=**ANDROID_SDK_LOCATION**/tools:$PATH
```

`ANDROID_SDK_LOCATION`的值是本地机器上 Android SDK 的路径，可以通过打开 Android Studio 并转到**首选项**|**外观和行为**|**系统设置**|**Android SDK**来找到。路径在声明 Android SDK 位置的框中列出，看起来像这样：`/Users/myuser/Library/Android/sdk`。

该应用程序是使用**Expo SDK 版本 33.0.0**创建的，因此，您需要确保您在本地机器上使用的 Expo 版本类似。由于 React Native 和 Expo 经常更新，请确保您使用此版本，以便本章中描述的模式表现如预期。如果您的应用程序无法启动或遇到错误，请参考 Expo 文档，了解有关更新 Expo SDK 的更多信息。

# 检出初始项目

该项目由两部分组成，一个是样板 React Native 应用程序，另一个是 GraphQL 服务器。 React Native 应用程序位于`client`目录中，而 GraphQL 服务器放置在`server`目录中。在本章中，您需要始终同时运行应用程序和服务器，而只对`client`目录中的应用程序进行代码更改。

要开始，您需要在`client`和`server`目录中运行以下命令，以安装所有依赖项并启动服务器和应用程序：

```jsx
npm install && npm start
```

对于移动应用程序，此命令将在安装依赖项后启动 Expo，并使您能够从终端或浏览器启动项目。在终端中，您现在可以使用 QR 码在移动设备上打开应用程序，或者在模拟器中打开应用程序。

此项目的本地 GraphQL 服务器正在运行`http://localhost:4000/graphql/`，但为了能够在 React Native 应用程序中使用此端点，您需要找到您机器的本地 IP 地址。

要查找本地 IP 地址，您需要根据您的操作系统执行以下操作：

+   **对于 Windows**：打开终端（或命令提示符）并运行此命令：

```jsx
ipconfig
```

这将返回一个类似下面所见的列表，其中包含来自您本地机器的数据。在此列表中，您需要查找字段**IPv4 地址**：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/f91e2398-5dc0-4091-ba7e-90f29bf63aac.png)

+   **对于 macOS**：打开终端并运行此命令：

```jsx
ipconfig getifaddr en0
```

运行此命令后，将返回您机器的本地`Ipv4 地址`，看起来像这样：

```jsx
192.168.1.107
```

必须使用本地 IP 地址来创建文件`client/App.js`中的`API_URL`的值，前缀为`http://`，后缀为`/graphql`，使其看起来像`http://192.168.1.107/graphql`：

```jsx
...

**- const API_URL = '';**
**+ const API_URL = 'http://192.168.1.107/graphql';**

const  httpLink  =  new  HttpLink({
 uri: API_URL,  }); const  authLink  =  setContext(async (_, { headers }) => {

  ...
```

无论您是从虚拟设备还是物理设备打开应用程序，此时应用程序应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/f5b65733-4019-44b8-8c29-afa114d8695f.jpg)

此应用程序是使用**Expo SDK 版本 33.0.0**创建的，因此您需要确保您本地机器上使用的 Expo 版本类似。由于 React Native 和 Expo 经常更新，请确保您使用此版本，以确保本章中描述的模式表现如预期。如果您的应用程序无法启动或收到错误消息，请务必查看 Expo 文档，以了解有关更新 Expo SDK 的更多信息。

初始应用程序由七个屏幕组成：`AddPost`、`AuthLoading`、`Login`、`Notifications`、`Post`、`Posts`和`Settings`。当首次启动应用程序时，您将看到`Login`屏幕，您可以使用以下凭据登录：

+   **用户名**：`test`

+   **密码**：`test`

`Posts` 屏幕将是登录后的初始屏幕，显示一个帖子列表，您可以点击继续到`Post`屏幕，而`Settings`屏幕显示一个无效的注销按钮。目前，`AddPost`和`Notification`屏幕尚不可见，因为您将在本章后面添加到这些屏幕的路由。

React Native 应用程序中的项目结构在`directory` client 中如下，结构类似于您在本书中之前创建的项目：

```jsx
messaging
|-- client
    |-- .expo
    |-- assets
        |-- icon.png
        |-- splash.png
    |-- Components
        |-- // ...
    |-- node_modules
    |-- Screens
        |-- AddPost.js
        |-- AuthLoading.js
        |-- Login.js
        |-- Notifications.js
        |-- Post.js
        |-- Posts.js
        |-- Settings.js
    |-- .watchmanconfig
    |-- App.js
    |-- AppContainer.js
    |-- app.json
    |-- babel.config.js
    |-- package.json
```

在`assets`目录中，您可以找到用作应用程序图标的图像，一旦您在移动设备上安装了该应用程序，它将显示在主屏幕上，以及作为启动画面的图像，当您启动应用程序时显示。例如，应用程序名称的 App Store 配置放在`app.json`中，而`babel.config.js`包含特定的 Babel 配置。

`App.js`文件是您的应用程序的实际入口点，其中导入并返回`AppContainer.js`文件。在`AppContainer`中，定义了该应用程序的所有路由，`AppContext`将包含应该在整个应用程序中可用的信息。

该应用程序的所有组件都位于`Screens`和`Components`目录中，其中第一个包含由屏幕呈现的组件。这些屏幕的子组件可以在`Components`目录中找到，其结构如下：

```jsx
|-- Components
    |-- Button
        |-- Button.js
    |-- Comment
        |-- Comment.js
        |-- CommentForm.js
    |-- Notification
        |-- Notification.js
    |-- Post
        |-- PostContent.js
        |-- PostCount.js
        |-- PostItem.js
    |-- TextInput
        |-- TextInput.js
```

GraphQL 服务器可以在`http://localhost:4000/graphql` URL 找到，GraphQL Playground 将可见。从这个 playground，您可以查看 GraphQL 服务器的模式，并检查所有可用的查询、变异和订阅。虽然您不会对服务器进行任何代码更改，但了解模式及其工作原理是很重要的。

服务器有两个查询，通过使用`userName`参数作为标识符来检索帖子列表或单个帖子。这些查询将返回具有`id`、`userName`、`image`、`stars`和`comments`计数值的`Post`类型，`stars`类型的星星列表，以及具有`Comment`类型的`comments`列表。检索单个帖子的查询将如下所示：

```jsx
export  const  GET_POST  =  gql`
 query getPost($userName: String!) { post(userName: $userName) { id userName image stars { userName } comments { id userName text } } } `;
```

之后，可以在 GraphQL 服务器中找到三个变异，用于登录用户、存储来自 Expo 的推送令牌，或添加帖子。

如果收到错误消息“请提供（有效的）身份验证详细信息”，则需要重新登录应用程序。可能，上一个应用程序的 JWT 仍然存储在 Expo 的`AsyncStorage`中，并且这将无法在本章的 GraphQL 服务器上验证。

# 使用 React Native、Apollo 和 GraphQL 构建全栈社交媒体应用程序

在本章中要构建的应用程序将使用本地 GraphQL 服务器来检索和改变应用程序中可用的数据。该应用程序将显示来自社交媒体动态的数据，并允许您对这些社交媒体帖子进行回复。

# 使用 React Native 和 Expo 的相机

除了显示由 GraphQL 服务器创建的帖子之外，您还可以使用 GraphQL mutation 自己添加帖子，并将文本和图像作为变量发送。将图像上传到您的 React Native 应用程序可以通过使用相机拍摄图像或从相机滚动中选择图像来完成。对于这两种用例，React Native 和 Expo 都提供了 API，或者可以从`npm`安装许多包。对于此项目，您将使用 Expo 的 ImagePicker API，它将这些功能合并到一个组件中。

要向您的社交媒体应用程序添加创建新帖子的功能，需要进行以下更改以创建新的添加帖子屏幕：

1.  可以使用的 GraphQL mutation 用于向您在`Main`屏幕中看到的动态中添加帖子，它将图像变量发送到 GraphQL 服务器。此 mutation 具有以下形式：

```jsx
mutation {
  addPost(image: String!) {
    image
  }
}
```

`image`变量是`String`，是此帖子的图像的绝对路径的 URL。此 GraphQL mutation 需要添加到`client/constants.js`文件的底部，以便稍后可以从`useMutation` Hook 中使用：

```jsx
export  const  GET_POSTS  =  gql`
 ... `; + export  const  ADD_POST  =  gql` +   mutation addPost($image: String!) { +     addPost(image: $image) { +       image  +     } +   } + `;
```

1.  有了`Mutation`，必须将添加帖子的屏幕添加到`client/AppContainer.js`文件中的`SwitchNavigator`。`AddPost`屏幕组件可以在`client/Screens/AddPost.js`文件中找到，并应作为导航器中的模态添加：

```jsx
import  React  from 'react';  import { Platform } from 'react-native';  import { Ionicons }  from '@expo/vector-icons';  import {  createSwitchNavigator,
 createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';  import  Posts  from './Screens/Posts';  import  Post  from './Screens/Post';  import  Settings  from './Screens/Settings';  import  Login  from './Screens/Login';  import  AuthLoading  from './Screens/AuthLoading';  + import  AddPost  from './Screens/AddPost'; ... 
const  SwitchNavigator  =  createSwitchNavigator(
  {
    Main:  TabNavigator, Login, AuthLoading,
**+** **AddPost,**
  },
  {
+   mode: 'modal'**,**
    initialRouteName: 'AuthLoading',
  },
);

export  default  createAppContainer(SwitchNavigator);
```

1.  当然，用户必须能够从应用程序的某个位置打开这个模态框，例如，从屏幕底部的选项卡导航器或标题栏。对于这种情况，您可以在`client/Screens/Posts.js`文件中设置`navigationOptions`来在标题栏中添加导航链接到`AddPost`屏幕：

```jsx
...

**+ Posts**.navigationOptions  = ({ navigation}) => ({ +   headerRight: ( +     <Button  onPress={() =>  navigation.navigate('AddPost')}  title='Add Post'  /> +   ), **+ });** export  default  Posts;
```

通过在`navigationOptions`中设置`headerRight`字段，只会更改标题的右侧部分，而导航器设置的标题将保持不变。现在点击`Add Post`链接将导航到`AddPost`屏幕，显示标题和关闭模态框的按钮。

现在您已经添加了`AddPost`屏幕，Expo 的 ImagePicker API 应该被添加到这个屏幕上。要将`ImagePicker`添加到`AddPost`屏幕上，请按照以下步骤在`client/Screens/AddPost.js`文件中启用从相机滚动中选择照片：

1.  在用户可以从相机滚动中选择照片之前，当用户使用 iOS 设备时，应该为应用程序设置正确的权限。要请求权限，您可以使用 Expo 的权限 API，它应该请求`CAMERA_ROLL`权限。权限 API 曾经直接从 Expo 可用，但现在已经移动到一个名为`expo-permissions`的单独包中，可以通过 Expo CLI 安装，方法是运行以下命令：

```jsx
expo install expo-permissions
```

1.  之后，您可以导入权限 API 并创建函数来检查是否已经为相机滚动授予了正确的权限：

```jsx
import  React  from 'react';  import { Dimensions, TouchableOpacity, Text, View } from 'react-native';  + import { Dimensions, Platform, TouchableOpacity, Text, View } from 'react-native'; import  styled  from 'styled-components/native';  import  Button  from '../Components/Button/Button';  + import * as Permissions from 'expo-permissions'; ...

const AddPost = ({ navigation }) => { +  const  getPermissionAsync  =  async () => { +    if (Platform.OS  === 'ios') { +      const { status } =  await  Permissions.askAsync(Permissions.CAMERA_ROLL);
+ +      if (status  !== 'granted') { +        alert('Sorry, you need camera roll permissions! Go to 'Settings > Expo' to enable these.'); +      } +    } **+ };**   ...
```

1.  这个`getPermissionAsync`函数是异步的，可以从`Button`或`Touchable`元素中调用。在文件底部可以找到`UploadImage`组件，它是一个带有`onPress`函数的样式化`TouchableOpacity`元素。这个组件必须添加到`AddPost`的返回函数中，并在点击时调用`getPermissionAsync`函数：

```jsx
...

const  AddPost  = ({ navigation }) => { const  getPermissionAsync  =  async () => { if (Platform.OS  === 'ios') {
 const { status } =  await  Permissions.askAsync(Permissions.CAMERA_ROLL);

 if (status  !== 'granted') {
 alert('Sorry, you need camera roll permissions! Go to 'Settings > Expo' to enable these.');
 } } };  return ( <AddPostWrapper>
 <AddPostText>Add Post</AddPostText> +     <UploadImage  onPress={() =>  getPermissionAsync()}> +       <AddPostText>Upload image</AddPostText> +     </UploadImage**>**
 <Button  onPress={() =>  navigation.navigate('Main')}  title='Cancel'  />
  </AddPostWrapper>
 ); };

...
```

在 iOS 设备上点击时，将打开一个请求访问相机滚动权限的弹出窗口。如果您不接受请求，就无法从相机滚动中选择照片。

您不能再次要求用户授予权限；相反，您需要手动授予对摄像机滚动的权限。要再次设置这个权限，您应该从 iOS 的设置屏幕进入，并选择 Expo 应用程序。在下一个屏幕上，您可以添加访问摄像机的权限。

1.  当用户已经授予访问摄像机滚动的权限时，您可以调用 Expo 的 ImagePicker API 来打开摄像机滚动。就像权限 API 一样，这曾经是 Expo 核心的一部分，但现在已经移动到一个单独的包中，您可以使用 Expo CLI 安装：

```jsx
expo install expo-image-picker
```

这是一个再次使用异步函数，它接受一些配置字段，比如宽高比。如果用户选择了一张图片，ImagePicker API 将返回一个包含字段 URI 的对象，该字段是用户设备上图片的 URL，可以在`Image`组件中使用。可以通过使用`useState` Hook 创建一个本地状态来存储这个结果，以便稍后将其发送到 GraphQL 服务器：

```jsx
import  React  from 'react';  import { Dimensions, Platform, TouchableOpacity, Text, View } from 'react-native';  import  styled  from 'styled-components/native';  import  Button  from '../Components/Button/Button'; **+ import * as ImagePicker from 'expo-image-picker';** import * as Permissions from 'expo-permissions';  ...

const  AddPost  = ({ navigation }) => { +  const [imageUrl, setImageUrl] = React.useState(false); 
+  const  pickImageAsync  =  async () => { +    const  result  =  await  ImagePicker.launchImageLibraryAsync({ +      mediaTypes:  ImagePicker.MediaTypeOptions.All, +      allowsEditing:  true, +      aspect: [4, 4], +    });
+    if (!result.cancelled) { +      setImageUrl(result.uri); +    }
+  };

 return (
     ... 
```

然后可以从函数中调用`pickImageAsync`函数，以获取用户在摄像机滚动时授予的权限：

```jsx
...

const  AddPost  = ({ navigation }) => { ...

  const  getPermissionAsync  =  async () => { if (Platform.OS  === 'ios') {
 const { status } =  await  Permissions.askAsync(Permissions.CAMERA_ROLL);

 if (status  !== 'granted') {
 alert('Sorry, you need camera roll permissions! Go to 'Settings > Expo' to enable these.');
**+     } else {**
**+       pickImageAsync();**
 } } };  return (
```

1.  现在，由于图片的 URL 已经存储在本地状态中的`imageUrl`常量中，您可以在`Image`组件中显示这个 URL。这个`Image`组件以`imageUrl`作为源的值，并且已经设置为使用 100%的`width`和`height`：

```jsx
...

  return ( <AddPostWrapper>
 <AddPostText>Add Post</AddPostText>

 <UploadImage  onPress={() =>  getPermissionAsync()}>
**+       {imageUrl ? (**
**+** <Image +           source={{ uri:  imageUrl }} +           style={{ width: '100%', height: '100%' }} +         />
+       ) : (
          <AddPostText>Upload image</AddPostText>
**+       )}**
 </UploadImage>
 <Button  onPress={() =>  navigation.navigate('Main')}  title='Cancel'  />
  </AddPostWrapper>
 ); };

...
```

通过这些更改，`AddPost`屏幕应该看起来像下面的截图，这是从运行 iOS 的设备上获取的。如果您使用 Android Studio 模拟器或运行 Android 的设备，这个屏幕的外观可能会有轻微的差异：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/cae322ec-d489-4df3-924c-08de3f1fb3ea.png)

这些更改将使从摄像机滚动中选择照片成为可能，但您的用户还应该能够通过使用他们的摄像机上传全新的照片。使用 Expo 的 ImagePicker，您可以处理这两种情况，因为这个组件还有一个`launchCameraAsync`方法。这个异步函数将启动摄像机，并以与从摄像机滚动中返回图片的 URL 相同的方式返回它。

要添加直接使用用户设备上的摄像机上传图片的功能，可以进行以下更改：

1.  由于用户需要授予您的应用程序访问相机滚动条的权限，因此用户需要做同样的事情来使用相机。可以通过使用`Permissions.askAsync`方法发送`Permissions.CAMERA`来请求使用相机的权限。必须扩展对相机滚动条的授予权限的检查，以便还检查相机权限：

```jsx
...

  const  getPermissionAsync  =  async () => {  if (Platform.OS  === 'ios') { -   const { status } = await Permissions.askAsync(Permissions.CAMERA_ROLL);
-   if (status !== 'granted') {
+     const { status: statusCamera } =  await  Permissions.askAsync(Permissions.CAMERA); +     const { status: statusCameraRoll } =  await  Permissions.askAsync(Permissions.CAMERA_ROLL); +     if (statusCamera  !== 'granted'  ||  statusCameraRoll  !== 'granted'**) {**
        alert(
          `Sorry, you need camera roll permissions! Go to 'Settings > Expo' to enable these.`
        );
      } else {        pickImageAsync();
      }
    }
  };

  return (
    ... 
```

这将在 iOS 上要求用户允许使用相机，也可以通过转到设置| Expo 手动授予权限。

1.  在获得权限后，您可以通过调用`ImagePicker`中的`launchCameraAsync`函数来创建启动相机的功能。该功能与您创建的用于打开相机滚动条的`launchCameraAsync`函数相同；因此，`pickImageAsync`函数也可以编辑为能够启动相机：

```jsx
const  AddPost  = ({ navigation }) => { const [imageUrl, setImageUrl] =  React.useState(false);
 **-  const** pickImageAsync  =  async () => {  +  const addImageAsync  =  async (camera = false) => { -    const  result  =  await  ImagePicker.launchCameraAsync({ -      mediaTypes:  ImagePicker.MediaTypeOptions.All, -      allowsEditing:  true, -      aspect: [4, 4]
-    }); +    const  result  = !camera 
+      ? await  ImagePicker.launchImageLibraryAsync({ +          mediaTypes:  ImagePicker.MediaTypeOptions.All, +          allowsEditing:  true, +          aspect: [4, 4] +        })
+      : await  ImagePicker.launchCameraAsync({  +          allowsEditing:  true, +          aspect: [4, 4] **+        })**
 if (!result.cancelled) { setImageUrl(result.uri);
 } };
```

如果现在向`addImageAsync`函数发送参数，将调用`launchCameraAsync`。否则，用户将被引导到其设备上的相机滚动条。

1.  当用户点击图像占位符时，默认情况下将打开图像滚动条。但您还希望给用户选择使用他们的相机的选项。因此，必须在使用相机或相机滚动条上传图像之间进行选择，这是实现`ActionSheet`组件的完美用例。React Native 和 Expo 都有一个`ActionSheet`组件；建议使用 Expo 中的组件，因为它将在 iOS 上使用本机的`UIActionSheet`组件，在 Android 上使用 JavaScript 实现。`ActionSheet`组件可从 Expo 的`react-native-action-sheet`软件包中获得，您可以从`npm`安装。

```jsx
npm install @expo/react-native-action-sheet
```

之后，您需要在`client/App.js`文件中使用来自该软件包的`Provider`将顶级组件包装起来，这类似于添加`ApolloProvider`：

```jsx
import React from 'react';
import { AsyncStorage } from 'react-native';
import { ApolloClient } from 'apollo-client';
import { InMemoryCache } from 'apollo-cache-inmemory';
import { setContext } from 'apollo-link-context';
import { HttpLink } from 'apollo-link-http';
import { ApolloProvider } from '@apollo/react-hooks';
+ import { ActionSheetProvider } from '@expo/react-native-action-sheet';
import AppContainer from './AppContainer';

...

const  App  = () => (  <ApolloProvider  client={client}> +   <ActionSheetProvider>       <AppContainer  /> +   </ActionSheetProvider**>**
  </ApolloProvider> );

export  default  App;
```

在`client/Screens/AddPost.js`中通过从`react-native-action-sheet`导入`connectActionSheet`函数来创建`ActionSheet`，在导出之前需要将`AddPost`组件包装起来。使用`connectActionSheet()`将`AddPost`组件包装起来，将`showActionSheetWithOptions`属性添加到组件中，你将在下一步中使用它来创建`ActionSheet`：

```jsx
import  React  from 'react';  import { Dimensions,
 Image,
 Platform,
  TouchableOpacity,
  Text,
  View } from 'react-native';  import  styled  from 'styled-components/native';  import  *  as  ImagePicker  from 'expo-image-picker';  import  *  as  Permissions  from 'expo-permissions';  + import { connectActionSheet } from  '@expo/react-native-action-sheet'; import  Button  from '../Components/Button/Button'; ... - const  AddPost  = ({ navigation }) => { + const  AddPost  = ({ navigation, showActionSheetWithOptions }) => **{**

    ... 
- export default AddPost;
+ const  ConnectedApp  =  connectActionSheet(AddPost); + export  default  ConnectedApp;
```

1.  要添加`ActionSheet`，必须添加一个打开`ActionSheet`的函数，并使用`showActionSheetWithOptions`属性和选项来构造`ActionSheet`。选项包括`相机`、`相机相册`和`取消`，选择第一个选项应该调用带有参数的`addImageAsync`函数，第二个选项应该调用不带参数的函数，最后一个选项是关闭`ActionSheet`。打开`ActionSheet`的函数必须添加到`getPermissionsAsync`函数中，并在`相机`和`相机相册`的权限都被授予时调用：

```jsx
...

+  const openActionSheet = () => { +    const  options  = ['Camera', 'Camera roll', 'Cancel']; +    const  cancelButtonIndex  =  2; + 
+    showActionSheetWithOptions( +      {
+        options, +        cancelButtonIndex
+      },
+      buttonIndex  => { +        if (buttonIndex  ===  0  ||  buttonIndex  ===  1) { +          addImageAsync(buttonIndex  ===  0); +        }
+      },
+    );
+   };

  const  getPermissionAsync  =  async () => {    if (Platform.OS  === 'ios') {
      const { status: statusCamera } =  await  Permissions.askAsync(Permissions.CAMERA);
      const { status: statusCameraRoll } =  await  Permissions.askAsync(Permissions.CAMERA_ROLL);

      if (statusCamera  !== 'granted'  ||  statusCameraRoll  !== 'granted') {
        alert(
          `Sorry, you need camera roll permissions! Go to 'Settings > Expo' to enable these.`
        );
      } else { -       pickImageAsync**();**
**+       openActionSheet();**
      }
    }
  };

  return (
    ...
```

点击图像占位符将给用户选择使用`相机`或`相机相册`向`AddPost`组件添加图像的选项。这可以通过`ActionSheet`来实现，在 iOS 和 Android 上看起来会有所不同。在下面的截图中，您可以看到在使用 iOS 模拟器或运行 iOS 的设备时的效果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/341ba1a8-17f2-4761-8fcf-b0f5e3d374ff.png)

1.  然而，这还不是全部，因为图像仍然必须发送到服务器才能出现在应用程序的动态中，通过从`@apollo/react-hooks`中添加`useMutation` Hook，并使用返回的`addPost`函数将`imageUrl`变量发送到 GraphQL 服务器的文档中。在本节的开头已经提到了添加帖子的变异，并可以从`client/constants.js`文件中导入：

```jsx
import  React  from 'react';  import { Dimensions,
 Image,
 Platform,
  TouchableOpacity,
  Text,
  View } from 'react-native';  import  styled  from 'styled-components/native';  import  *  as  ImagePicker  from 'expo-image-picker';  import  *  as  Permissions  from 'expo-permissions';  import { connectActionSheet } from '@expo/react-native-action-sheet';
**+ import { useMutation } from '@apollo/react-hooks';** **+ import { ADD_POST } from '../constants';** import  Button  from '../Components/Button/Button';  
...

const  AddPost  = ({ navigation, showActionSheetWithOptions }) => { + const [addPost] = useMutation(ADD_POST);
  const [imageUrl, setImageUrl] =  React.useState(false); ... 
  return (    <AddPostWrapper>
      <AddPostText>Add Post</AddPostText>
        <UploadImage  onPress={() =>  getPermissionAsync()}> {imageUrl ? ( <Image source={{ uri:  imageUrl }} style={{ width: '100%', height: '100%' }} />
          ) : (
            <AddPostText>Upload image</AddPostText> )} </UploadImage> +       {imageUrl && ( +         <Button +           onPress={() => { +             addPost({ variables: { image:  imageUrl } }).then(() => 
+ navigation.navigate('Main') +             );
+           }} +           title='Submit' +         />
+       )}  <Button  onPress={() =>  navigation.navigate('Main')}  title='Cancel'  /> </AddPostWrapper>
   );
 };

export default AddPost;
```

点击`提交`按钮后，图像将作为帖子添加，并且用户将被重定向到`Main`屏幕。

1.  通过将`refetchQueries`变量上的查询设置为`useMutation` Hook，可以重新加载`Main`屏幕上的帖子，并在此列表中显示您刚刚添加的帖子。可以通过从`client/constants.js`中获取`GET_POSTS`查询来检索帖子：

```jsx
import  React  from 'react';  import { Dimensions,
 Image,
 Platform,
  TouchableOpacity,
  Text,
  View } from 'react-native';  import  styled  from 'styled-components/native';  import  *  as  ImagePicker  from 'expo-image-picker';  import  *  as  Permissions  from 'expo-permissions';  import { connectActionSheet } from '@expo/react-native-action-sheet';
import { useMutation } from '@apollo/react-hooks'; **- import { ADD_POST } from '../constants';** **+ import { ADD_POST, GET_POSTS } from '../constants';** import  Button  from '../Components/Button/Button';  
...

const  AddPost  = ({ navigation, showActionSheetWithOptions }) => { - const [addPost] = useMutation(ADD_POST);
+ const [addPost] =  useMutation(ADD_POST, { +   refetchQueries: [{ query:  GET_POSTS }] + });
  const [imageUrl, setImageUrl] =  React.useState(false);
 ... 
 return (   <AddPostWrapper>
     ...
```

您的帖子现在将显示在`Main`屏幕的顶部，这意味着您已成功添加了帖子，其他用户可以查看、点赞和评论。由于用户可能在应用程序打开时发送帖子，您希望他们能够接收这些帖子。因此，接下来的部分将探讨如何从 GraphQL 实现近实时数据。

# 使用 GraphQL 检索近实时数据

除了消息应用程序之外，您不希望每当您的网络中的任何人发布新帖子时，就重新加载带有帖子的信息流。除了订阅之外，还有其他方法可以使用 GraphQL 和 Apollo 实现（近乎）实时数据流，即轮询。通过轮询，您可以每隔`n`毫秒从`useQuery` Hook 中检索一个查询，而无需设置订阅的复杂性。

轮询可以添加到`client/Screens/Posts.js`中的`useQuery` Hook 中，就像这样。通过在`useQuery` Hook 的对象参数上设置`pollInterval`值，您可以指定多久应该由 Hook 重新发送带有`GET_POSTS`查询的文档：

```jsx
...

const  Posts  = ({ navigation }) => {
**- const { loading, data } = useQuery(GET_POSTS);**
**+ const { loading, data } = useQuery(GET_POSTS, { pollInterval: 2000 });**

  return ( <PostsWrapper> {loading ? (  <PostsText>Loading...</PostsText>;
      ) : ( ...
```

这会导致您的`Posts`组件每 2 秒（2,000 毫秒）发送一个带有`GET_POSTS`查询的文档，由于 GraphQL 服务器返回的是模拟数据，显示的帖子在每次重新获取时都会有所不同。与订阅相比，轮询会重新发送文档以检索帖子，即使没有新数据，这对于显示模拟数据或经常更改的数据的应用程序并不是很有用。

除了在`useQuery` Hook 上设置`pollInterval`变量之外，您还可以手动调用`refetch`函数，该函数会发送一个带有查询的文档。社交媒体信息流的常见交互是能够下拉显示的组件以刷新屏幕上的数据。

通过对`Posts`屏幕组件进行以下更改，也可以将此模式添加到您的应用程序中：

1.  `pollInterval`属性可以设置为`0`，这样就暂时禁用了轮询。除了`loading`和`data`变量之外，还可以从`useQuery` Hook 中检索更多变量。其中一个变量是`refetch`函数，您可以使用它手动将文档发送到服务器：

```jsx
...

const  Posts  = ({ navigation }) => {
**- const { loading, data } = useQuery(GET_POSTS, { pollInterval: 2000 });**
**+ const { loading, data, refetch } = useQuery(GET_POSTS, { pollInterval: 0 });**
  return ( <PostsWrapper> {loading ? (  <PostsText>Loading...</PostsText>;
      ) : ( ...
```

1.  有一个 React Native 组件用于创建下拉刷新交互，称为`RefreshControl`，您应该从`react-native`中导入它。此外，您还应该导入一个`ScrollView`组件，因为`RefreshControl`组件只能与`ScrollView`或`ListView`组件一起使用：

```jsx
import  React  from 'react';  import { useQuery } from '@apollo/react-hooks';  - import { FlatList, Text, View } from 'react-native';  + import { FlatList, Text, View, ScrollView, RefreshControl } from 'react-native';  import  styled  from 'styled-components/native';  import { GET_POSTS } from '../constants';  import  PostItem  from '../Components/Post/PostItem'; ... const  Posts  = ({ navigation }) => {  ...
```

1.  这个`ScrollView`组件应该包裹在`PostsList`组件周围，它是一个经过 GraphQL 服务器创建的帖子进行迭代的样式化`FlatList`组件。作为`refreshControl`属性的值，必须将`RefreshControl`组件传递给这个`ScrollView`，并且必须设置一个`style`属性，将宽度锁定为 100%，以确保只能垂直滚动：

```jsx
const Posts = ({ navigation }) => {
  const { loading, data, refetch } = useQuery(GET_POSTS, { pollInterval: 0 });
  return (
    <PostsWrapper>
      {loading ? (
        <PostsText>Loading...</PostsText>;
      ) : (
+       <ScrollView
+         style={{ width: '100%' }}
+         refreshControl={
+           <RefreshControl />
+         }
+       >
         <PostsList
           data={data.posts}
           keyExtractor={item => String(item.id)}
           renderItem={({ item }) => (
             <PostItem item={item} navigation={navigation} />
           )}
         />
+       </ScrollView>
      )}
    </PostsWrapper>
  );
};
```

1.  如果您现在下拉`Posts`屏幕，屏幕顶部将显示一个不断旋转的加载指示器。通过`refreshing`属性，您可以通过传递由`useState` Hook 创建的值来控制是否应该显示加载指示器。除了`refreshing`属性，还可以将应该在刷新开始时调用的函数传递给`onRefresh`属性。您应该将`refetch`函数传递给此函数，该函数应将`refreshing`状态变量设置为`true`并调用`useQuery` Hook 返回的`refetch`函数。在`refetch`函数解析后，回调可以用于再次将`refreshing`状态设置为`false`：

```jsx
...
const Posts = ({ navigation }) => {
  const { loading, data, refetch } = useQuery(GET_POSTS, { pollInterval: 0 });
+ const [refreshing, setRefreshing] = React.useState(false);

+ const handleRefresh = (refetch) => {
+   setRefreshing(true);
+
+   refetch().then(() => setRefreshing(false));
+ }

  return(
    <PostsWrapper>
    {loading ? (
      <PostsText>Loading...</PostsText>;
    ) : (
      <ScrollView
        style={{ width: '100%' }}
        refreshControl={
-         <RefreshControl />
+         <RefreshControl
+           refreshing={refreshing}
+           onRefresh={() => handleRefresh(refetch)}
+         />
        }
      >
        <PostsList
          ...
```

1.  最后，当您下拉`Posts`屏幕时，从`useQuery` Hook 返回的加载消息会干扰`RefreshControl`的加载指示器。通过在 if-else 语句中还检查`refreshing`的值，可以防止这种行为：

```jsx
...
const Posts = ({ navigation }) => {
  const { loading, data, refetch } = useQuery(GET_POSTS, { pollInterval: 0 });
  const [refreshing, setRefreshing] = React.useState(false);

  const handleRefresh = (refetch) => {
    setRefreshing(true);

    refetch().then(() => setRefreshing(false));
  }

  return(
    <PostsWrapper>
-     {loading ? (
+     {loading && !refreshing ? (
        <PostsText>Loading...</PostsText>      ) : (

        ...
```

在最后这些更改之后，下拉刷新`Posts`屏幕的交互已经实现，使您的用户可以通过下拉屏幕来检索最新数据。当您将 iOS 作为运行应用程序的虚拟或物理设备的操作系统时，它将看起来像这样的截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/b87269bb-aa38-4ac7-b0ee-9295ac618b14.png)

在接下来的部分中，您将使用 Expo 和 GraphQL 服务器向这个社交媒体应用程序添加通知。

# 使用 Expo 发送通知

移动社交媒体应用程序的另一个重要功能是向用户发送重要事件的通知，例如，当他们的帖子被点赞或朋友上传了新帖子。使用 Expo 可以发送通知，并且需要添加服务器端和客户端代码，因为通知是从服务器发送的。客户端需要检索用户设备的本地标识符，称为 Expo 推送代码。这个代码是需要的，以确定哪个设备属于用户，以及通知应该如何发送到 iOS 或 Android。

测试通知只能通过在您的移动设备上使用 Expo 应用程序来完成。iOS 和 Android 模拟器无法接收推送通知，因为它们不在实际设备上运行。

检索推送代码是向用户发送通知的第一步，包括以下步骤：

1.  为了能够发送通知，用户应该允许您的应用程序推送这些通知。要请求此权限，应该使用相同的权限 API 来获取相机的权限。请求此权限的函数可以添加到一个名为`registerForPushNotificationsAsync.js`的新文件中。这个文件必须创建在新的`client/utils`目录中，您可以在其中粘贴以下代码，该代码还使用通知 API 检索推送代码：

```jsx
import { Notifications } from 'expo';  import  *  as  Permissions  from 'expo-permissions';  async  function  registerForPushNotificationsAsync() {
 const { status: existingStatus } =  await  Permissions.getAsync(
 Permissions.NOTIFICATIONS
 ); let  finalStatus  =  existingStatus;
   if (existingStatus  !== 'granted') {
  const { status } =  await  Permissions.askAsync(Permissions.NOTIFICATIONS);
 finalStatus  =  status;
 }  if (finalStatus  !== 'granted') {
 return;
 } const  token  =  await  Notifications.getExpoPushTokenAsync();
 return  token; }

export default registerForPushNotificationsAsync;
```

1.  当您使用 iOS 设备时，应该在应用程序打开时调用`registerForPushNotificationAsync`函数，因为您应该请求权限。在 Android 设备上，用户是否希望您发送通知的请求是在安装过程中发送的。因此，当用户打开应用程序时，应该触发此函数，之后此函数将在 Android 上返回 Expo 推送令牌，或在 iOS 上启动弹出窗口以请求权限。由于您只想要向注册用户请求他们的令牌，因此在`client/Screens/Posts.js`文件中使用`useEffect` Hook 来完成。

```jsx
import React from 'react';
import { useQuery } from '@apollo/react-hooks';
import {
  Button,
  FlatList,
  Text,
  View,
  ScrollView,
  RefreshControl
} from 'react-native';
import styled from 'styled-components/native';
import { GET_POSTS } from '../constants';
import PostItem from '../Components/Post/PostItem';
+ import registerForPushNotificationsAsync from '../utils/registerForPushNotificationsAsync';

... const Posts = ({ navigation }) => {
  const { loading, data, refetch } = useQuery(GET_POSTS, { pollInterval: 0 });
  const [refreshing, setRefreshing] = React.useState(false);
+ React.useEffect(() => {
+   registerForPushNotificationsAsync();
+ });

...
```

如果您看到此错误，“错误：Expo 推送通知服务仅支持 Expo 项目。请确保您已登录到从中加载项目的计算机上的 Expo 开发人员帐户。”，这意味着您需要确保已登录到 Expo 开发人员帐户。通过在终端中运行`expo login`，您可以检查是否已登录，否则它将提示您重新登录。

1.  在终端中，现在将显示此用户的 Expo 推送令牌，看起来像`ExponentPushToken[AABBCC123]`。这个令牌对于这个设备是唯一的，可以用来发送通知。要测试通知的外观，您可以在浏览器中转到`https://expo.io/dashboard/notifications`的 URL 以找到 Expo 仪表板。在这里，您可以输入 Expo 推送令牌以及通知的消息和标题；根据移动操作系统的不同，您可以选择不同的选项，例如以下选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/ff6cbf7e-aa70-4994-82ac-ba1bed1205d8.png)

这将向您的设备发送一个标题为`Test`，正文为`This is a test`的通知，并在发送通知时尝试播放声音。

然而，当应用程序在 iOS 设备上运行并处于前台时，此通知不会显示。因此，当您在苹果设备上使用 Expo 应用程序时，请确保 Expo 应用程序在后台运行。

本节的下一部分将展示如何在应用程序在前台运行时也可以接收通知。

# 处理前台通知

当应用程序处于前台时处理通知更加复杂，需要我们添加一个监听器来检查新通知，然后这些通知应该被存储在某个地方。Expo 的通知 API 提供了一个可用的监听器，可以帮助您检查新通知，而通知可以使用 Apollo 来存储，通过使用本地状态。这个本地状态通过添加监听器发现的任何新通知来扩展 GraphQL 服务器返回的数据。

当通知存储在本地状态中时，可以查询这些数据并在应用程序的组件或屏幕中显示。让我们创建一个通知屏幕，显示这些在应用程序在前台加载时发送的通知。

添加对前台通知的支持需要您进行以下更改：

1.  在`client/App.js`中 Apollo Client 的设置应该被扩展，以便您可以查询通知，并在监听器发现新通知时添加新通知。应该创建一个名为`notifications`的新类型`Query`，返回`Notification`类型的列表。此外，必须在`cache`中添加一个空数组的形式作为这个`Query`的初始值：

```jsx
...

 const  client  =  new  ApolloClient({
  link:  authLink.concat(link),
 cache, +  typeDefs:  ` +    type Notification { +      id: Number! +      title: String! +      body: String! +    } +    extend type Query { +      notifications: [Notification]! +    } +  `
 }); + cache.writeData({ +  data: { +    notifications: [] +  } **+ });** const  App  = () => {

  ...
```

1.  现在，您可以发送一个带有查询的文档，以检索包括`id`、`title`和`body`字段的通知列表。这个查询也必须在`client/constants.js`文件中定义，以便在下一步中从`useQuery` Hook 中使用。

```jsx
...

export  const  ADD_POST  =  gql`
 mutation addPost($image: String!) { addPost(image: $image) { image } } `; + export  const  GET_NOTIFICATIONS  =  gql` +   query getNotifications { +     notifications { +       id @client +       title @client +       body @client +     } +   } + `;
```

1.  在`client/Screens`目录中，可以找到`Notifications.js`文件，必须将其用作用户显示通知的屏幕。此屏幕组件应该在`client/AppContainer.js`文件中导入，其中必须创建一个新的`StackNavigator`对象：

```jsx
import  React  from 'react';  import { Platform } from 'react-native';  import { Ionicons }  from '@expo/vector-icons';  import {   createSwitchNavigator,
 createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';  import  Posts  from './Screens/Posts';  import  Post  from './Screens/Post';  import  Settings  from './Screens/Settings';  import  Login  from './Screens/Login';  import  AuthLoading  from './Screens/AuthLoading';  import  AddPost  from './Screens/AddPost';  + import  Notifications  from './Screens/Notifications';  ...

+ const  NotificationsStack  =  createStackNavigator({ +   Notifications: { +     screen:  Notifications, +     navigationOptions: { title: 'Notifications' }, +   } **+ });**
```

创建`Notifications`屏幕的`StackNavigator`之后，需要将其添加到`TabNavigator`中，以便它将显示在`Posts`和`Settings`屏幕旁边：

```jsx
...

const  TabNavigator  =  createBottomTabNavigator(
 { Posts:  PostsStack, +   Notifications:  NotificationsStack,  Settings }, { initialRouteName: 'Posts',
 defaultNavigationOptions: ({ navigation }) => ({ tabBarIcon: ({ tintColor }) => { const { routeName } =  navigation.state;
  let  iconName;
  if (routeName  === 'Posts') { iconName  =  `${Platform.OS === 'ios' ? 'ios' : 'md'}-home`; } else  if (routeName  === 'Settings') {
 iconName  =  `${Platform.OS === 'ios' ? 'ios' : 'md'}-settings`; +     } else  if (routeName  === 'Notifications') { +       iconName  =  `${Platform.OS === 'ios' ? 'ios' : 'md'}-notifications`; **+     }** return  <Ionicons  name={iconName}  size={20}  color={tintColor}  />;
 },  ...
```

1.  `Notifications`屏幕现在显示在`TabNavigator`中，并显示文本 Empty！因为没有任何通知可显示。要添加已发送给用户的任何通知，需要为 GraphQL 客户端创建本地解析器。此本地解析器将用于创建`Mutation`，用于将任何新通知添加到本地状态。您可以通过将以下代码添加到`client/App.js`来创建本地解析器：

```jsx
...

import AppContainer from './AppContainer';
**+ import { GET_NOTIFICATIONS } from './constants';**

...

const  client  =  new  ApolloClient({
 link:  authLink.concat(link),
 cache, + resolvers: { +   Mutation: { +     addNotification:  async (_, { id, title, body }) => { +       const { data } =  await  client.query({ query:  GET_NOTIFICATIONS })
+ +       cache.writeData({ +         data: { +           notifications: [ +             ...data.notifications, +             { id, title, body, __typename: 'notifications' }, +           ], +         }, +       }); +     } +   } **+ },**
 typeDefs:  `
 type Notification { id: Number! title: String! body: String! } extend type Query { notifications: [Notification]! } ` });

...
```

这将创建`addNotification`变异，该变异接受`id`、`title`和`body`变量，并将这些值添加到`Notification`类型的数据中。当前在本地状态中的通知是使用之前创建的`GET_NOTIFICATIONS`查询来请求的。通过在 GraphQL `client`常量上调用`query`函数，您将向服务器发送包含此查询的文档。连同与变异一起发送的通知以及包含变异的文档，这些将通过`cache.writeData`写入本地状态。

1.  这个变异必须添加到`client/constants.js`文件中，其他 GraphQL 查询和变异也放在那里。同样重要的是要添加`client`应该使用`@client`标签来解决这个变异：

```jsx
...

export  const  GET_NOTIFICATIONS  =  gql`
 query getNotifications { notifications { id @client title @client body @client } } `; + export  const  ADD_NOTIFICATION  =  gql`
+ mutation { +     addNotification(id: $id, title: $title, body: $body) @client +   } + `;
```

1.  最后，从`Notifications` API 中添加的监听器被添加到`client/App.js`文件中，当应用程序处于前台时，它将寻找新的通知。新的通知将使用`client/constants.js`中的前述变异添加到本地状态。在客户端上调用的`mutate`函数将使用来自 Expo 通知的信息并将其添加到变异；变异将确保通过将此信息写入`cache`将其添加到本地状态：

```jsx
...

import { ActionSheetProvider } from '@expo/react-native-action-sheet';  + import { Notifications } from 'expo'; import AppContainer from './AppContainer';
- import { GET_NOTIFICATIONS } from './constants'; + import { ADD_NOTIFICATIONS, GET_NOTIFICATIONS } from './constants'; 
...

const  App  = () => { + React.useEffect(() => { +   Notifications.addListener(handleNotification); + });

+ const  handleNotification  = ({ data }) => { +   client.mutate({ +     mutation:  ADD_NOTIFICATION, +     variables: { +       id:  Math.floor(Math.random() *  500) +  1, +       title:  data.title, +       body:  data.body, +     },
+   });
+ };

  return (

    ...
```

在上一个代码块中，您不能使用`useMutation` Hook 来发送`ADD_NOTIFICATION`变异，因为 React Apollo Hooks 只能从嵌套在`ApolloProvider`中的组件中使用。因此，使用了`client`对象上的`mutate`函数，该函数还提供了发送带有查询和变异的文档的功能，而无需使用`Query`或`Mutation`组件。

1.  通过从 Expo 导入`Notifications` API，`handleNotification`函数可以访问发送的通知中的数据对象。该数据对象与您使用 Expo 仪表板发送的消息标题和消息正文不同，因此在从`https://expo.io/dashboard/notifications`发送通知时，您还需要添加 JSON 数据。可以通过在表单中添加正文来发送测试通知：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/4a6c73cf-01ef-4ed0-bc50-809452135e25.png)

通过提交表单，当应用程序处于前台运行时，将向用户发送标题为`Test`，正文为`This is a test`的通知，但也会在应用程序在后台运行时发送。

在生产中运行的移动应用程序中，您期望通知是从 GraphQL 服务器而不是 Expo 仪表板发送的。处理此应用程序的数据流的本地 GraphQL 服务器已配置为向用户发送通知，但需要用户的 Expo 推送令牌才能发送。该令牌应存储在服务器上并与当前用户关联，因为该令牌对于此设备是唯一的。该令牌应在文档中从变异发送到 GraphQL 服务器，该变异将获取关于用户的信息并从变异的标头中获取：

1.  首先，在`client/constants.js`文件中创建将在 GraphQL 服务器上存储 Expo 推送令牌的变异，以及其他查询和变异。此变异所需的唯一变量是推送令牌，因为发送到 GraphQL 服务器的每个文档的 OAuth 令牌用于标识用户：

```jsx
import  gql  from 'graphql-tag';  export  const  LOGIN_USER  =  gql`
 mutation loginUser($userName: String!, $password: String!) { loginUser(userName: $userName, password: $password) { userName token } } `; + export  const  STORE_EXPO_TOKEN  =  gql` +   mutation storeExpoToken($expoToken: String!) { +     storeExpoToken(expoToken: $expoToken) { +       expoToken +     } +   } + `**;**

...
```

1.  必须从`client/Posts.js`文件中发送带有 Expo 推送令牌的此变异，该文件通过调用`registerForPushNotificationsAsync`函数检索令牌。此函数将返回推送令牌，您可以将其与变异文档一起发送。要发送此文档，可以使用`@apollo/react-hooks`中的`useMutation` Hook，您必须与`STORE_EXPO_TOKEN`常量一起导入：

```jsx
import  React  from 'react';  - import { useQuery } from '@apollo/react-hooks'; **+ import { useQuery, useMutation } from '@apollo/react-hooks';**  ... - import { GET_POSTS } from '../constants';  + import { GET_POSTS, STORE_EXPO_TOKEN } from '../constants';  import  PostItem  from '../Components/Post/PostItem';  import  registerForPushNotificationsAsync  from '../utils/registerForPushNotificationsAsync';  ...
```

在 React Apollo Hooks 可用之前，使用变异是很复杂的，因为只能从`client`对象或`Mutation`组件发送变异。通过导入`ApolloConsumer`组件，可以从 React 组件中访问`client`对象，该组件可以从包装应用程序的`ApolloProvider`中读取客户端值。

1.  现在可以使用`useMutation` Hook 调用`STORE_EXPO_TOKEN`变异，并将`registerForPushNotificationsAsync`中的`expoToken`作为参数，该参数返回一个用于存储令牌的函数称为`storeExpoToken`。可以从异步`registerForPushNotificationsAsync`函数的回调中调用此函数，并将令牌作为变量传递：

```jsx
...

const  Posts  = ({ client, navigation }) => {
**+ const [storeExpoToken] = useMutation(STORE_EXPO_TOKEN);** const [refreshing, setRefreshing] =  React.useState(false);

 React.useEffect(() => { -   registerForPushNotificationsAsync(); +   registerForPushNotificationsAsync().then(expoToken  => { +     return storeExpoToken({ variables: { expoToken } }); +   });  }, []);

...
```

每当“帖子”屏幕被挂载时，Expo 推送令牌将被发送到 GraphQL 服务器，您可以通过在“添加帖子”和“帖子”屏幕之间切换来强制执行此操作。当从 GraphQL 服务器请求“帖子”屏幕的内容时，服务器将向您的应用程序发送一个随机通知，您可以从“通知”屏幕中查看该通知。此外，您仍然可以在 Expo 仪表板上发送任何通知，无论应用程序是在前台还是后台运行。

# 总结

在本章中，您使用 React Native 和 Expo 创建了一个移动社交媒体应用程序，该应用程序使用 GraphQL 服务器发送和接收数据以及进行身份验证。使用 Expo，您学会了如何让应用程序请求访问设备的相机或相机滚动条，以添加新照片到帖子中。此外，Expo 还用于从 Expo 仪表板或 GraphQL 服务器接收通知。这些通知将被用户接收，无论应用程序是在后台还是前台运行。

完成了这个社交媒体应用程序，您已经完成了本书的最后一个 React Native 章节，现在准备开始最后一个章节。在这最后一个章节中，您将探索 React 的另一个用例，即 React 360。使用 React 360，您可以通过编写 React 组件创建 360 度的 2D 和 3D 体验。

# 进一步阅读

+   Expo 相机：[`docs.expo.io/versions/latest/sdk/camera/`](https://docs.expo.io/versions/latest/sdk/camera/)

+   通知：[`docs.expo.io/versions/v33.0.0/sdk/notifications/`](https://docs.expo.io/versions/v33.0.0/sdk/notifications/)
