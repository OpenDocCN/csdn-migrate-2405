# ReactNative 秘籍第二版（三）

> 原文：[`zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce`](https://zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：向您的应用程序添加基本动画

在本章中，我们将涵盖以下教程：

+   创建简单动画

+   运行多个动画

+   创建动画通知

+   展开和折叠容器

+   创建带有加载动画的按钮

# 介绍

为了提供良好的用户体验，我们可能希望添加一些动画来引导用户的注意力，突出特定的操作，或者只是为我们的应用程序增添独特的风格。

正在进行一个倡议，将所有处理从 JavaScript 移至本地端。在撰写本文时（React Native 版本 0.58），我们可以选择使用本地驱动程序在本地世界中运行所有这些计算。不幸的是，这不能用于所有动画，特别是与布局相关的动画，比如 flexbox 属性。在文档中阅读有关使用本地动画时的注意事项的更多信息[`facebook.github.io/react-native/docs/animations#caveats`](http://facebook.github.io/react-native/docs/animations#caveats)。

本章中的所有教程都使用 JavaScript 实现。React Native 团队承诺在将所有处理移至本地端时使用相同的 API，因此我们不需要担心现有 API 的变化。

# 创建简单动画

在这个教程中，我们将学习动画的基础知识。我们将使用一张图片来创建一个简单的线性移动，从屏幕的右侧移动到左侧。

# 准备工作

为了完成这个教程，我们需要创建一个空的应用程序。让我们称之为`simple-animation`。

我们将使用一个云的 PNG 图像来制作这个教程。您可以在 GitHub 上托管的教程存储库中找到该图像[`github.com/warlyware/react-native-cookbook/tree/master/chapter-6/simple-animation/assets/images`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-6/simple-animation/assets/images)。将图像放在`/assets/images`文件夹中以供应用程序使用。

# 如何做...

1.  让我们从打开`App.js`并导入`App`类的依赖项开始。`Animated`类将负责创建动画的值。它提供了一些准备好可以进行动画处理的组件，还提供了几种方法和辅助程序来运行平滑的动画。

`Easing`类提供了几种辅助方法，用于计算运动（如`linear`和`quadratic`）和预定义动画（如`bounce`、`ease`和`elastic`）。我们将使用`Dimensions`类来获取当前设备尺寸，以便在动画初始化时知道在哪里放置元素：

```jsx
import React, { Component } from 'react';
import {
  Animated,
  Easing,
  Dimensions,
  StyleSheet,
  View,
} from 'react-native';
```

1.  我们还将初始化一些我们在应用程序中需要的常量。在这种情况下，我们将获取设备尺寸，设置图像的大小，并`require`我们将要进行动画处理的图像：

```jsx
const { width, height } = Dimensions.get('window');
const cloudImage = require('./assets/images/cloud.png');
const imageHeight = 200;
const imageWidth = 300;
```

1.  现在，让我们创建`App`组件。我们将使用组件生命周期系统中的两种方法。如果您对这个概念不熟悉，请查看相关的 React 文档（[`reactjs.cn/react/docs/component-specs.html`](http://reactjs.cn/react/docs/component-specs.html)）。这个页面还有一个关于生命周期钩子如何工作的非常好的教程：

```jsx
export default class App extends Component { 
  componentWillMount() { 
    // Defined on step 4 
  } 

  componentDidMount() { 
    // Defined on step 7 
  } 

  startAnimation () { 
    // Defined on step 5 
  } 

  render() { 
    // Defined on step 6 
  } 
} 

const styles = StyleSheet.create({ 
  // Defined on step 8 
}); 
```

1.  为了创建动画，我们需要定义一个标准值来驱动动画。`Animated.Value`是一个处理每一帧动画值的类。我们需要在组件创建时创建这个类的实例。在这种情况下，我们使用`componentWillMount`方法，但我们也可以使用`constructor`或者属性的默认值：

```jsx
  componentWillMount() {
    this.animatedValue = new Animated.Value();
  }
```

1.  一旦我们创建了动画值，我们就可以定义动画。我们还通过将`Animated.timing`的`start`方法传递给一个箭头函数来创建一个循环，该箭头函数再次执行`startAnimation`函数。现在，当图像达到动画的末尾时，我们将再次开始相同的动画，以创建一个无限循环的动画：

```jsx
  startAnimation() {
    this.animatedValue.setValue(width);
    Animated.timing(
      this.animatedValue,
      {
        toValue: -imageWidth,
        duration: 6000,
        easing: Easing.linear,
        useNativeDriver: true,
      }
    ).start(() => this.startAnimation());
  }
```

1.  我们已经完成了动画，但目前只是计算了每一帧的值，没有对这些值做任何操作。下一步是在屏幕上渲染图像，并设置我们想要动画的样式属性。在这种情况下，我们想要在*x*轴上移动元素；因此，我们应该更新`left`属性：

```jsx
  render() {
    return (
      <View style={styles.background}>
        <Animated.Image
          style={[
            styles.image,
            { left: this.animatedValue },
          ]}
          source={cloudImage}
        />
      </View>
    );
  }
```

1.  如果我们刷新模拟器，我们将看到图像在屏幕上，但它还没有被动画处理。为了解决这个问题，我们需要调用`startAnimation`方法。我们将在组件完全渲染后开始动画，使用`componentDidMount`生命周期钩子：

```jsx
  componentDidMount() {
    this.startAnimation();
  }
```

1.  如果我们再次运行应用程序，我们将看到图像在屏幕顶部移动，就像我们想要的那样！作为最后一步，让我们为应用程序添加一些基本样式：

```jsx
const styles = StyleSheet.create({
  background: {
    flex: 1,
    backgroundColor: 'cyan',
  },
  image: {
    height: imageHeight,
    position: 'absolute',
    top: height / 3,
    width: imageWidth,
  },
});
```

输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/1dda7b4d-ccd4-4a02-851a-feddfc257ab0.png)

# 工作原理...

在*步骤 5*中，我们设置了动画数值。第一行每次调用此方法时都会重置初始值。在本例中，初始值将是设备的`宽度`，这将把图像移动到屏幕的右侧，这是我们想要开始动画的地方。

然后，我们使用`Animated.timing`函数基于时间创建动画，并传入两个参数。对于第一个参数，我们传入了在*步骤 4*中的`componentWillMount`生命周期钩子中创建的`animatedValue`。第二个参数是一个包含动画配置的对象。在这种情况下，我们将把结束值设置为图像宽度的负值，这将把图像放在屏幕的左侧。动画在那里完成。

配置完毕后，`Animated`类将计算所需的所有帧，以在分配的 6 秒内执行从右向左的线性动画（通过将`duration`属性设置为`6000`毫秒）。

React Native 还提供了另一个与`Animated`配对使用的辅助工具，称为`Easing`。在这种情况下，我们使用`Easing`辅助类的`linear`属性。`Easing`提供其他常见的缓动方法，如`elastic`和`bounce`。查看`Easing`类文档，并尝试为`easing`属性设置不同的值，看看每个值的效果。您可以在[`facebook.github.io/react-native/docs/easing.html`](https://facebook.github.io/react-native/docs/easing.html)找到文档。

动画配置正确后，我们需要运行它。我们通过调用`start`方法来实现这一点。此方法接收一个可选的`callback`函数参数，当动画完成时将执行该函数。在这种情况下，我们递归运行相同的`startAnimation`函数。这将创建一个无限循环，这正是我们想要实现的。

在*步骤 6*中，我们正在渲染图像。如果要对图像进行动画处理，应始终使用`Animate.Image`组件。在内部，此组件将处理动画的值，并将为本机组件上的每个帧设置每个值。这避免了在每个帧上在 JavaScript 层上运行渲染方法，从而实现更流畅的动画。

除了`Image`之外，我们还可以对`View`、`Text`和`ScrollView`组件进行动画处理。这四个组件都有内置的支持，但我们也可以创建一个新组件，并通过`Animated.createAnimatedComponent()`添加动画支持。这四个组件都能处理样式更改。我们所要做的就是将`animatedValue`传递给我们想要动画的属性，这种情况下是`left`属性，但我们也可以在每个组件上使用任何可用的样式。

# 运行多个动画

在这个配方中，我们将学习如何在几个元素中使用相同的动画值。这样，我们可以重复使用相同的值，以及插值，为其余的元素获得不同的值。

这个动画将类似于上一个配方。这次，我们将有两朵云：一朵较小，移动较慢，另一朵较大，移动较快。在屏幕中央，我们将有一架静止的飞机。我们不会给飞机添加任何动画，但移动的云会使它看起来像飞机在移动。

# 准备就绪

让我们通过创建一个名为`multiple-animations`的空应用程序来开始这个配方。

我们将使用三种不同的图像：两个云和一架飞机。您可以从 GitHub 上的配方存储库下载图像，地址为[`github.com/warlyware/react-native-cookbook/tree/master/chapter-6/multiple-animations/assets/images`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-6/multiple-animations/assets/images)。确保将图像放在`/assets/images`文件夹中。

# 如何做...

1.  让我们从打开`App.js`并添加我们的导入开始：

```jsx
import React, { Component } from 'react';
import {
  View,
  Animated,
  Image,
  Easing,
  Dimensions,
  StyleSheet,
} from 'react-native';
```

1.  此外，我们需要定义一些常量，并要求我们将用于动画的图像。请注意，我们将在这个配方中将相同的云图像视为`cloudImage1`和`cloudImage2`，但我们将把它们视为单独的实体：

```jsx
const { width, height } = Dimensions.get('window');
const cloudImage1 = require('./assets/images/cloud.png');
const cloudImage2 = require('./assets/images/cloud.png');
const planeImage = require('./assets/images/plane.gif');
const cloudHeight = 100;
const cloudWidth = 150;
const planeHeight = 60;
const planeWidth = 100;
```

1.  在下一步中，当组件被创建时，我们将创建`animatedValue`实例，然后在组件完全渲染时开始动画。我们正在创建一个在无限循环中运行的动画。初始值将为`1`，最终值将为`0`。如果您对这段代码不清楚，请确保阅读本章的第一个配方：

```jsx
export default class App extends Component { 
  componentWillMount() { 
    this.animatedValue = new Animated.Value(); 
  } 

  componentDidMount() { 
    this.startAnimation(); 
  } 

  startAnimation () { 
    this.animatedValue.setValue(1); 
    Animated.timing( 
      this.animatedValue, 
      { 
        toValue: 0, 
        duration: 6000, 
        easing: Easing.linear, 
      } 
    ).start(() => this.startAnimation()); 
  } 

  render() { 
    // Defined in a later step
  } 
} 

const styles = StyleSheet.create({ 
  // Defined in a later step
}); 
```

1.  在本示例中，`render`方法将与上一个示例有很大不同。在本示例中，我们将使用相同的`animatedValue`来动画两个图像。动画值将返回从`1`到`0`的值；但是，我们希望将云从右向左移动，因此我们需要为每个元素设置`left`值。

为了设置正确的值，我们需要对`animatedValue`进行插值。对于较小的云，我们将把初始的`left`值设为设备的宽度，但对于较大的云，我们将把初始的`left`值设得远离设备的右边缘。这将使移动距离更大，因此移动速度会更快：

```jsx
  render() {
    const left1 = this.animatedValue.interpolate({
      inputRange: [0, 1],
      outputRange: [-cloudWidth, width],
    });

    const left2 = this.animatedValue.interpolate({
      inputRange: [0, 1],
      outputRange: [-cloudWidth*5, width + cloudWidth*5],
    });

    // Defined in a later step
  } 
```

1.  一旦我们有了正确的`left`值，我们需要定义我们想要动画的元素。在这里，我们将把插值值设置为`left`样式属性：

```jsx
  render() {
    // Defined in a later step

    return (
      <View style={styles.background}>
        <Animated.Image
          style={[
            styles.cloud1,
            { left: left1 },
          ]}
          source={cloudImage1}
        />
        <Image
          style={styles.plane}
          source={planeImage}
        />
        <Animated.Image
          style={[
            styles.cloud2,
            { left: left2 },
          ]}
          source={cloudImage2}
        />
      </View>
    );
  }
```

1.  至于最后一步，我们需要定义一些样式，只需设置每朵云的`width`和`height`以及为`top`分配样式即可。

```jsx
const styles = StyleSheet.create({
  background: {
    flex: 1,
    backgroundColor: 'cyan',
  },
  cloud1: {
    position: 'absolute',
    width: cloudWidth,
    height: cloudHeight,
    top: height / 3 - cloudWidth / 2,
  },
  cloud2: {
    position: 'absolute',
    width: cloudWidth * 1.5,
    height: cloudHeight * 1.5,
    top: height/2,
  },
  plane: {
    position: 'absolute',
    height: planeHeight,
    width: planeWidth,
    top: height / 2 - planeHeight,
    left: width / 2 - planeWidth,
  }
});
```

1.  如果我们刷新应用，我们应该能看到动画：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/e752f224-3437-4c01-8bd1-89c74f625a1f.png)

# 工作原理...

在*步骤 4*中，我们定义了插值以获取每朵云的`left`值。`interpolate`方法接收一个具有两个必需配置的对象，`inputRange`和`outputRange`。

`inputRange`配置接收一个值数组。这些值应始终是升序值；您也可以使用负值，只要值是升序的。

`outputRange`应该与`inputRange`中定义的值的数量匹配。这些是我们需要作为插值结果的值。

对于本示例，`inputRange`从`0`到`1`，这些是我们的`animatedValue`的值。在`outputRange`中，我们定义了我们需要的移动的限制。

# 创建动画通知

在本示例中，我们将从头开始创建一个通知组件。在显示通知时，组件将从屏幕顶部滑入。几秒钟后，我们将自动隐藏它，将其滑出。

# 准备工作

我们将创建一个应用。让我们称之为`notification-animation`。

# 如何做...

1.  我们将从`App`组件开始工作。首先，让我们导入所有必需的依赖项：

```jsx
import React, { Component } from 'react';
import {
  Text,
  TouchableOpacity,
  StyleSheet,
  View,
  SafeAreaView,
} from 'react-native';
import Notification from './Notification';
```

1.  一旦我们导入了所有依赖项，我们就可以定义`App`类。在这种情况下，我们将使用`notify`属性等于`false`来初始化`state`。我们将使用此属性来显示或隐藏通知。默认情况下，通知不会显示在屏幕上。为了简化事情，我们将在`state`中定义`message`属性，其中包含我们想要显示的文本：

```jsx
export default class App extends Component {
  state = {
    notify: false,
    message: 'This is a notification!',
  };

  toggleNotification = () => {
    // Defined on later step
  }

  render() {
    // Defined on later step
  }
}

const styles = StyleSheet.create({
    // Defined on later step
});

```

1.  在`render`方法内，我们需要仅在`notify`属性为`true`时显示通知。我们可以通过使用`if`语句来实现这一点：

```jsx
  render() {
    const notify = this.state.notify
      ? <Notification
          autoHide
          message={this.state.message}
          onClose={this.toggleNotification}
        />
    : null;
    // Defined on next step
  }
```

1.  在上一步中，我们只定义了对`Notification`组件的引用，但还没有使用它。让我们定义一个`return`，其中包含此应用程序所需的所有 JSX。为了保持简单，我们只会定义一个工具栏、一些文本和一个按钮，以在按下时切换通知的状态：

```jsx
  render() {
    // Code from previous step
    return (
      <SafeAreaView>
        <Text style={styles.toolbar}>Main toolbar</Text>
        <View style={styles.content}>
          <Text>
            Lorem ipsum dolor sit amet, consectetur adipiscing 
            elit,
            sed do eiusmod tempor incididunt ut labore et 
            dolore magna.
          </Text>
          <TouchableOpacity
            onPress={this.toggleNotification}
            style={styles.btn}
          >
            <Text style={styles.text}>Show notification</Text>
          </TouchableOpacity>
          <Text>
            Sed ut perspiciatis unde omnis iste natus error sit 
            accusantium doloremque laudantium.
          </Text>
          {notify}
        </View>
      </SafeAreaView>
    );
  }
```

1.  我们还需要定义一个方法，用于在`state`上切换`notify`属性，这非常简单：

```jsx
  toggleNotification = () => {
    this.setState({
      notify: !this.state.notify,
    });
  }
```

1.  我们几乎完成了这个类。剩下的只有样式。在这种情况下，我们只会添加基本样式，如`color`、`padding`、`fontSize`、`backgroundColor`和`margin`，没有什么特别的：

```jsx
        const styles = StyleSheet.create({ 
          toolbar: { 
            backgroundColor: '#8e44ad', 
            color: '#fff', 
            fontSize: 22, 
            padding: 20, 
            textAlign: 'center', 
          }, 
          content: { 
            padding: 10, 
            overflow: 'hidden', 
          }, 
          btn: { 
            margin: 10, 
            backgroundColor: '#9b59b6', 
            borderRadius: 3, 
            padding: 10, 
          }, 
          text: { 
            textAlign: 'center', 
            color: '#fff', 
          }, 
        }); 
```

1.  如果我们尝试运行应用程序，我们会看到一个错误，即无法解析`./Notification`模块。让我们通过定义`Notification`组件来解决这个问题。让我们创建一个`Notifications`文件夹，其中包含一个`index.js`文件。然后，我们可以导入我们的依赖项：

```jsx
import React, { Componen } from 'react';
import {
  Animated,
  Easing,
  StyleSheet,
  Text,
} from 'react-native';
```

1.  一旦我们导入了依赖项，让我们定义新组件的 props 和初始状态。我们将定义一些非常简单的东西，只是一个用于接收要显示的消息的属性，以及两个`callback`函数，允许在通知出现在屏幕上和关闭时运行一些操作。我们还将添加一个属性来设置在自动隐藏通知之前显示通知的毫秒数：

```jsx
export default class Notification extends Component {
  static defaultProps = {
    delay: 5000,
    onClose: () => {},
    onOpen: () => {},
  };

  state = {
    height: -1000,
  };
}
```

1.  终于是时候开始处理动画了！我们需要在组件被渲染时立即开始动画。如果以下代码中有什么不清楚的地方，我建议你看一下本章的第一和第二个示例：

```jsx
  componentWillMount() {
    this.animatedValue = new Animated.Value();
  }

  componentDidMount() {
    this.startSlideIn();
  }

  getAnimation(value, autoHide) {
    const { delay } = this.props;
    return Animated.timing(
      this.animatedValue,
      {
        toValue: value,
        duration: 500,
        easing: Easing.cubic,
        delay: autoHide ? delay : 0,
      }
    );
  }
```

1.  到目前为止，我们已经定义了一个获取动画的方法。对于滑入运动，我们需要计算从`0`到`1`的值。动画完成后，我们需要运行`onOpen`回调。如果`autoHide`属性在调用`onOpen`方法时设置为`true`，我们将自动运行滑出动画以删除组件：

```jsx
  startSlideIn () {
    const { onOpen, autoHide } = this.props;

    this.animatedValue.setValue(0);
    this.getAnimation(1)
      .start(() => {
        onOpen();
        if (autoHide){
          this.startSlideOut();
        }
      });
  }
```

1.  与前面的步骤类似，我们需要一个用于滑出运动的方法。在这里，我们需要计算从`1`到`0`的值。我们将`autoHide`值作为参数发送到`getAnimation`方法。这将自动延迟动画，延迟时间由`delay`属性定义（在我们的例子中为 5 秒）。动画完成后，我们需要运行`onClose`回调函数，这将从`App`类中删除组件：

```jsx
  startSlideOut() {
    const { autoHide, onClose } = this.props;

    this.animatedValue.setValue(1);
    this.getAnimation(0, autoHide)
      .start(() => onClose());
  }
```

1.  最后，让我们添加`render`方法。在这里，我们将获取`props`提供的`message`值。我们还需要组件的`height`来将组件移动到动画的初始位置；默认情况下是`-1000`，但我们将在下一步在运行时设置正确的值。`animatedValue`从`0`到`1`或从`1`到`0`，取决于通知是打开还是关闭；因此，我们需要对其进行插值以获得实际值。动画将从组件的负高度到`0`；这将导致一个漂亮的滑入/滑出动画：

```jsx
  render() {
    const { message } = this.props;
    const { height } = this.state;
    const top = this.animatedValue.interpolate({
       inputRange: [0, 1],
       outputRange: [-height, 0],
     });
    // Defined on next step
   }
}
```

1.  为了尽可能简单，我们将返回一个带有一些文本的`Animated.View`。在这里，我们正在使用插值结果设置`top`样式，这意味着我们将对顶部样式进行动画处理。如前所述，我们需要在运行时计算组件的高度。为了实现这一点，我们需要使用视图的`onLayout`属性。此函数将在每次布局更新时调用，并将新的组件尺寸作为参数发送：

```jsx
  render() {
     // Code from previous step
     return (
      <Animated.View
        onLayout={this.onLayoutChange}
        style={[
          styles.main,
          { top }
        ]}
      >
        <Text style={styles.text}>{message}</Text>
      </Animated.View>
    );
   }
}
```

1.  `onLayoutChange`方法将非常简单。我们只需要获取新的`height`并更新`state`。此方法接收一个`event`。从这个对象中，我们可以获取有用的信息。对于我们的目的，我们将在`event`对象的`nativeEvent.layout`中访问数据。`layout`对象包含屏幕的`width`和`height`，以及`Animated.View`调用此函数时屏幕上的*x*和*y*位置：

```jsx
  onLayoutChange = (event) => {
    const {layout: { height } } = event.nativeEvent;
     this.setState({ height });
   }
```

1.  在最后一步，我们将为通知组件添加一些样式。由于我们希望该组件在任何其他内容之上进行动画，我们需要将`position`设置为`absolute`，并将`left`和`right`属性设置为`0`。我们还将添加一些颜色和填充：

```jsx
        const styles = StyleSheet.create({ 
          main: { 
            backgroundColor: 'rgba(0, 0, 0, 0.7)', 
            padding: 10, 
            position: 'absolute', 
            left: 0, 
            right: 0, 
          }, 
          text: { 
            color: '#fff', 
          }, 
       }); 
```

1.  最终应用程序应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/425fcaa8-645a-4ae2-8d6d-8a97778cdde7.png)

# 工作原理...

在*步骤 3*中，我们定义了`Notification`组件。该组件接收三个参数：一个标志，用于在几秒后自动隐藏组件，我们要显示的消息，以及在通知关闭时将执行的`callback`函数。

当`onClose`回调被执行时，我们将切换`notify`属性以移除`Notification`实例并清除内存。

在*步骤 4*中，我们定义了用于渲染应用程序组件的 JSX。重要的是要在其他组件之后渲染`Notification`组件，以便该组件显示在所有其他组件之上。

在*步骤 6*中，我们定义了组件的`state`。`defaultProps`对象为每个属性设置了默认值。如果给定属性没有赋值，这些值将被应用。

我们将每个`callback`的默认值定义为空函数。这样，我们在尝试执行它们之前不必检查这些 props 是否有值。

对于初始的`state`，我们定义了`height`属性。实际的`height`值将根据`message`属性中接收的内容在运行时计算。这意味着我们需要最初将组件远离原始位置进行渲染。由于在计算布局时存在短暂延迟，我们不希望在移动到正确位置之前显示通知。

在*步骤 9*中，我们创建了动画。`getAnimation`方法接收两个参数：要应用的`delay`和`autoHide`布尔值，用于确定通知是否自动关闭。我们在*步骤 10*和*步骤 11*中使用了这个方法。

在*步骤 13*中，我们为该组件定义了 JSX。`onLayout`函数在更新布局时非常有用，可以获取组件的尺寸。例如，如果设备方向发生变化，尺寸将发生变化，这种情况下，我们希望更新动画的初始和最终坐标。

# 还有更多...

当前的实现效果相当不错，但是我们应该解决一个性能问题。目前，`onLayout`方法在每一帧动画上都会被执行，这意味着我们在每一帧上都在更新`state`，这导致组件在每一帧上重新渲染！我们应该避免这种情况，只更新一次以获得实际的高度。

为了解决这个问题，我们可以添加一个简单的验证，只有在当前值与初始值不同时才更新状态。这将避免在每一帧上更新`state`，我们也不会一遍又一遍地强制渲染：

```jsx
onLayoutChange = (event) => { 
  const {layout: { height } } = event.nativeEvent; 
 if (this.state.height === -1000) { 
    this.setState({ height }); 
 } 
} 
```

虽然这对我们的目的有效，但我们也可以进一步确保在方向改变时`height`也会更新。然而，我们会在这里停下，因为这个方法已经相当长了。

# 展开和折叠容器

在这个方法中，我们将创建一个带有`title`和`content`的自定义容器元素。当用户按下标题时，内容将折叠或展开。这个方法将允许我们探索`LayoutAnimation` API。

# 做好准备

让我们从创建一个新的应用程序开始。我们将其称为`collapsable-containers`。

一旦我们创建了应用程序，让我们还创建一个`Panel`文件夹，里面有一个`index.js`文件，用于存放我们的`Panel`组件。

# 如何做...

1.  让我们首先专注于`Panel`组件。首先，我们需要导入我们将在这个类中使用的所有依赖项：

```jsx
import React, { Component } from 'react';
import {
  View,
  LayoutAnimation,
  StyleSheet,
  Text,
  TouchableOpacity,
} from 'react-native';
```

1.  一旦我们有了依赖项，让我们声明`defaultProps`来初始化这个组件。在这个方法中，我们只需要将`expanded`属性初始化为`false`：

```jsx
export default class Panel extends Component {
  static defaultProps = {
    expanded: false
  };
}

const styles = StyleSheet.create({
  // Defined on later step
});
```

1.  我们将使用`state`对象上的`height`属性来展开或折叠容器。这个组件第一次被创建时，我们需要检查`expanded`属性，以设置正确的初始`height`：

```jsx
  state = {
    height: this.props.expanded ? null : 0,
  };
```

1.  让我们为这个组件渲染所需的 JSX 元素。我们需要从`state`中获取`height`的值，并将其设置为内容的样式视图。当按下`title`元素时，我们将执行`toggle`方法（稍后定义）来改变`state`的`height`值：

```jsx
  render() {
    const { children, style, title } = this.props;
    const { height } = this.state;

    return (
      <View style={[styles.main, style]}>
        <TouchableOpacity onPress={this.toggle}>
          <Text style={styles.title}>
            {title}
          </Text>
        </TouchableOpacity>
        <View style={{ height }}>
          {children}
        </View>
      </View>
    );
  }
```

1.  如前所述，当按下`title`元素时，`toggle`方法将被执行。在这里，我们将在`state`上切换`height`并在下一个渲染周期更新样式时调用我们想要使用的动画：

```jsx
  toggle = () => {
    LayoutAnimation.spring();
    this.setState({
      height: this.state.height === null ? 0 : null,
    })
  }
```

1.  为了完成这个组件，让我们添加一些简单的样式。我们需要将`overflow`设置为`hidden`，否则在组件折叠时内容将被显示出来。

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#fff',
    borderRadius: 3,
    overflow: 'hidden',
    paddingLeft: 30,
    paddingRight: 30,
  },
  title: {
    fontWeight: 'bold',
    paddingTop: 15,
    paddingBottom: 15,
  }
```

1.  一旦我们定义了`Panel`组件，让我们在`App`类中使用它。首先，我们需要在`App.js`中要求所有的依赖项：

```jsx
import React, { Component } from 'react';
import {
  Text,
  StyleSheet,
  View,
  SafeAreaView,
  Platform,
  UIManager
} from 'react-native';
import Panel from './Panel';
```

1.  在上一步中，我们导入了`Panel`组件。我们将在 JSX 中声明这个类的三个实例：

```jsx
 export default class App extends Component {
  render() {
    return (
      <SafeAreaView style={[styles.main]}>
        <Text style={styles.toolbar}>Animated containers</Text>
        <View style={styles.content}>
          <Panel
            title={'Container 1'}
            style={styles.panel}
          >
            <Text style={styles.panelText}>
              Temporibus autem quibusdam et aut officiis
              debitis aut rerum necessitatibus saepe
              eveniet ut et voluptates repudiandae sint et
              molestiae non recusandae.
            </Text>
          </Panel>
          <Panel
            title={'Container 2'}
            style={styles.panel}
              >
            <Text style={styles.panelText}>
              Et harum quidem rerum facilis est et expedita 
              distinctio. Nam libero tempore,
              cum soluta nobis est eligendi optio cumque.
            </Text>
          </Panel>
          <Panel
            expanded
            title={'Container 3'}
            style={styles.panel}
           >
            <Text style={styles.panelText}>
              Nullam lobortis eu lorem ut vulputate.
            </Text>
            <Text style={styles.panelText}>
              Donec id elementum orci. Donec fringilla lobortis 
              ipsum, vitae commodo urna.
            </Text>
          </Panel>
        </View>
      </SafeAreaView>
    );
  }
}
```

1.  在这个示例中，我们在 React Native 中使用了`LayoutAnimation` API。在当前版本的 React Native 中，这个 API 在 Android 上默认是禁用的。在`App`组件挂载之前，我们将使用`Platform`助手和`UIManager`在 Android 设备上启用这个功能：

```jsx
  componentWillMount() {
    if (Platform.OS === 'android') {
      UIManager.setLayoutAnimationEnabledExperimental(true);
    }
  }
```

1.  最后，让我们为工具栏和主容器添加一些样式。我们只需要一些你现在可能已经习惯的简单样式：`padding`，`margin`和`color`。

```jsx
const styles = StyleSheet.create({
  main: {
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#3498db',
    color: '#fff',
    fontSize: 22,
    padding: 20,
    textAlign: 'center',
  },
  content: {
    padding: 10,
    backgroundColor: '#ecf0f1',
    flex: 1,
  },
  panel: {
    marginBottom: 10,
  },
  panelText: {
    paddingBottom: 15,
  }
});
```

1.  最终的应用程序应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/6896c6bd-b770-4a25-8423-6aad90ac4964.png)

# 工作原理...

在*步骤 3*中，我们设置了内容的初始`height`。如果`expanded`属性设置为`true`，那么我们应该显示内容。通过将`height`值设置为`null`，布局系统将根据内容计算`height`；否则，我们需要将值设置为`0`，这将在组件折叠时隐藏内容。

在*步骤 4*中，我们为`Panel`组件定义了所有 JSX。这一步中有一些值得介绍的概念。首先，`children`属性是从`props`对象中传入的，当这个组件在`App`类中使用时，它将包含在`<Panel>`和`</Panel>`之间定义的任何元素。这非常有帮助，因为通过使用这个属性，我们允许这个组件接收任何其他组件作为子组件。

在同一步骤中，我们还从`state`对象中获取`height`并将其设置为应用于可折叠内容的`View`的`style`。这将更新`height`，导致组件相应地展开或折叠。我们还声明了`onPress`回调，当按下`title`元素时，它会切换`state`上的`height`。

在*步骤 7*中，我们定义了`toggle`方法，它可以切换`height`值。在这里，我们使用了`LayoutAnimation`类。通过调用`spring`方法，布局系统将在下一次渲染时对布局发生的每一次变化进行动画处理。在这种情况下，我们只改变了`height`，但我们也可以改变任何其他属性，比如`opacity`，`position`或`color`。

`LayoutAnimation`类包含一些预定义的动画。在这个示例中，我们使用了`spring`，但我们也可以使用`linear`或`easeInEaseOut`，或者使用`configureNext`方法创建自己的动画。

如果我们移除`LayoutAnimation`，我们将看不到动画；组件将通过从`0`到总高度跳跃来展开和折叠。但通过添加那一行代码，我们可以轻松地添加一个漂亮、平滑的动画。如果您需要更多对动画的控制，您可能会想使用动画 API。

在*步骤 9*中，我们在`Platform`助手上检查了 OS 属性，它返回了`'android'`或`'ios'`字符串，取决于应用程序运行在哪个设备上。如果应用程序在 Andriod 上运行，我们使用`UIManager`助手的`setLayoutAnimationEnabledExperimental`方法来启用`LayoutAnimation` API。

# 另请参阅

+   `LayoutAnimation` API 文档在[`facebook.github.io/react-native/docs/layoutanimation.html`](https://facebook.github.io/react-native/docs/layoutanimation.html)

+   在[`codeburst.io/a-quick-intro-to-reacts-props-children-cb3d2fce4891`](https://codeburst.io/a-quick-intro-to-reacts-props-children-cb3d2fce4891)快速介绍 React 的`props.children`。

# 创建带有加载动画的按钮

在这个示例中，我们将继续使用`LayoutAnimation`类。在这里，我们将创建一个按钮，当用户按下按钮时，我们将显示一个加载指示器并动画化样式。

# 准备工作

要开始，我们需要创建一个空的应用程序。让我们称之为`button-loading-animation`。

让我们还创建一个`Button`文件夹，里面有一个`index.js`文件，用于我们的`Button`组件。

# 如何做...

1.  让我们从`Button/index.js`文件开始。首先，我们将导入这个组件所需的所有依赖项：

```jsx
import React, { Component } from 'react';
import {
  ActivityIndicator,
  LayoutAnimation,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
```

1.  对于这个组件，我们将只使用四个 props：一个`label`，一个`loading`布尔值，用于切换显示加载指示器或按钮内的标签，一个在按钮被按下时执行的回调函数，以及自定义样式。在这里，我们将`init`默认的`loading`为`false`，并将`handleButtonPress`设置为空函数：

```jsx
export default class Button extends Component {
  static defaultProps = {
    loading: false,
    onPress: () => {},
  };
  // Defined on later steps
}
```

1.  我们将尽可能简化这个组件的`render`方法。我们将根据`loading`属性的值来渲染标签和活动指示器：

```jsx
  render() {
    const { loading, style } = this.props;

    return (
      <TouchableOpacity
        style={[
          styles.main,
          style,
          loading ? styles.loading : null,
        ]}
        activeOpacity={0.6}
        onPress={this.handleButtonPress}
      >
        <View>
          {this.renderLabel()}
          {this.renderActivityIndicator()}
        </View>
      </TouchableOpacity>
    );
  }
```

1.  为了渲染`label`，我们需要检查`loading`属性是否为`false`。如果是，那么我们只返回一个带有从`props`接收到的`label`的`Text`元素：

```jsx
  renderLabel() {
    const { label, loading } = this.props;
    if(!loading) {
      return (
        <Text style={styles.label}>{label}</Text>
      );
    }
  }
```

1.  同样，`renderActivityIndicator`指示器应该只在`loading`属性的值为`true`时应用。如果是这样，我们将返回`ActivityIndicator`组件。我们将使用`ActivityIndicator`的 props 来定义一个小的`size`和白色的`color`(`#fff`)：

```jsx
  renderActivityIndicator() {
    if (this.props.loading) {
      return (
        <ActivityIndicator size="small" color="#fff" />
      );
    }
  }
```

1.  我们的类中还缺少一个方法：`handleButtonPress`。当按钮被按下时，我们需要通知这个组件的父组件，这可以通过调用通过`props`传递给这个组件的`onPress`回调来实现。我们还将使用`LayoutAnimation`在下一次渲染时排队一个动画：

```jsx
  handleButtonPress = () => {
    const { loading, onPress } = this.props;

    LayoutAnimation.easeInEaseOut();
    onPress(!loading);
  }
```

1.  为了完成这个组件，我们需要添加一些样式。我们将定义一些颜色，圆角，对齐，填充等。对于显示加载指示器时将应用的`loading`样式，我们将更新填充以创建一个围绕加载指示器的圆形：

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#e67e22',
    borderRadius: 20,
    padding: 10,
    paddingLeft: 50,
    paddingRight: 50,
  },
  label: {
    color: '#fff',
    fontWeight: 'bold',
    textAlign: 'center',
    backgroundColor: 'transparent',
  },
  loading: {
    padding: 10,
    paddingLeft: 10,
    paddingRight: 10,
  },
});
```

1.  我们已经完成了`Button`组件。现在，让我们来处理`App`类。让我们首先导入所有的依赖项：

```jsx
import React, { Component } from 'react';
import {
  Text,
  StyleSheet,
  View,
  SafeAreaView,
  Platform,
  UIManager
} from 'react-native';
import Button from './Button';
```

1.  `App`类相对简单。我们只需要在`state`对象上定义一个`loading`属性，它将切换`Button`的动画。我们还将渲染一个`toolbar`和一个`Button`：

```jsx
export default class App extends Component {
  state = {
    loading: false,
  };

  // Defined on next step

  handleButtonPress = (loading) => {
    this.setState({ loading });
  }

  render() {
    const { loading } = this.state;

    return (
      <SafeAreaView style={[styles.main, android]}>
        <Text style={styles.toolbar}>Animated containers</Text>
        <View style={styles.content}>
          <Button
            label="Login"
            loading={loading}
            onPress={this.handleButtonPress}
          />
        </View>
      </SafeAreaView>
    );
  }
}
```

1.  与上一个示例一样，我们需要在 Android 设备上手动启用`LayoutAnimation`API：

```jsx
  componentWillMount() {
    if (Platform.OS === 'android') {
      UIManager.setLayoutAnimationEnabledExperimental(true);
    }
  }
```

1.  最后，我们将添加一些`styles`，只是一些颜色，填充和居中对齐按钮在屏幕上：

```jsx
const styles = StyleSheet.create({
  main: {
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#f39c12',
    color: '#fff',
    fontSize: 22,
    padding: 20,
    textAlign: 'center',
  },
  content: {
    padding: 10,
    backgroundColor: '#ecf0f1',
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
```

1.  最终的应用程序应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/4be877c5-963e-4b57-9685-a03b35244a4c.png)

# 工作原理...

在*步骤 3*中，我们为`Button`组件添加了`render`方法。在这里，我们接收了`loading`属性，并根据该值将相应的样式应用于`TouchableOpacity`按钮元素。我们还使用了两种方法：一种用于渲染标签，另一种用于渲染活动指示器。

在*步骤 6*中，我们执行了`onPress`回调。默认情况下，我们声明了一个空函数，因此我们不必检查值是否存在。

这个按钮的父组件应该负责在调用`onPress`回调时更新`loading`属性。从这个组件中，我们只负责在按下此按钮时通知父组件。

`LayoutAnimation.eadeInEaseOut`方法只是将动画排队到下一个渲染阶段，这意味着动画不会立即执行。我们负责更改我们想要动画的样式。如果我们不改变任何样式，那么我们就看不到任何动画。

`Button`组件不知道`loading`属性是如何更新的。这可能是因为获取请求、超时或任何其他操作。父组件负责更新`loading`属性。无论发生任何变化，我们都会将新样式应用于按钮，并进行平滑的动画。

在*步骤 9*中，我们定义了`App`类的内容。在这里，我们使用了我们的`Button`组件。当按下按钮时，`loading`属性的`state`将被更新，这将导致每次按下按钮时动画运行。

# 结论

在本章中，我们已经介绍了如何为您的 React Native 应用程序添加动画的基础知识。这些示例旨在提供有用的实际代码解决方案，并建立如何使用基本构建块，以便您更好地创建适合您的应用程序的动画。希望到目前为止，您应该已经开始熟悉`Animated`和`LayoutAnimation`动画助手。在第七章中，*为您的应用程序添加高级动画*，我们将结合我们在这里学到的东西来构建更复杂和有趣的应用程序 UI 动画。


# 第七章：为您的应用程序添加高级动画

在本章中，我们将涵盖以下配方：

+   从列表组件中删除项目

+   创建 Facebook 反应小部件

+   在全屏显示图像

# 介绍

在上一章中，我们介绍了在 React Native 中使用两个主要动画助手`Animated`和`LayoutAnimation`的基础知识。在本章中，我们将通过构建更复杂的配方来进一步了解这些概念，展示常见的本地 UX 模式。

# 从列表组件中删除项目

在这个配方中，我们将学习如何在`ListView`中创建带有动画侧向滑动的列表项。如果用户将项目滑动超过阈值，项目将被移除。这是许多具有可编辑列表的移动应用程序中的常见模式。我们还将看到如何使用`PanResponder`来处理拖动事件。

# 准备就绪

我们需要创建一个空的应用程序。对于这个配方，我们将其命名为`removing-list-items`。

我们还需要创建一个新的`ContactList`文件夹，并在其中创建两个文件：`index.js`和`ContactItem.js`。

# 如何做...

1.  让我们从导入主`App`类的依赖项开始，如下所示：

```jsx
import React from 'react';
import {
  Text,
  StyleSheet,
  SafeAreaView,
} from 'react-native';
import ContactList from './ContactList';
```

1.  这个组件将很简单。我们只需要渲染一个`toolbar`和我们在上一步中导入的`ContactList`组件，如下所示：

```jsx
const App = () => (
  <SafeAreaView style={styles.main}>
    <Text style={styles.toolbar}>Contacts</Text>
    <ContactList style={styles.content} />
  </SafeAreaView>
);

const styles = StyleSheet.create({
  main: {
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#2c3e50',
    color: '#fff',
    fontSize: 22,
    padding: 20,
    textAlign: 'center',
  },
  content: {
    padding: 10,
    flex: 1,
  },
});

export default App;
```

1.  这就是我们开始实际工作的全部内容。让我们打开`ContactList/index.js`文件，并导入所有依赖项，如下所示：

```jsx
import React, { Component } from 'react';
import {
  ListView,
  ScrollView,
} from 'react-native';
import ContactItem from './ContactItem';
```

1.  然后我们需要定义一些数据。在真实的应用程序中，我们会从 API 中获取数据，但为了保持简单并且只关注拖动功能，让我们在这个相同的文件中定义数据：

```jsx
const data = [
  { id: 1, name: 'Jon Snow' },
  { id: 2, name: 'Luke Skywalker' },
  { id: 3, name: 'Bilbo Baggins' },
  { id: 4, name: 'Bob Labla' },
  { id: 5, name: 'Mr. Magoo' },
];
```

1.  这个组件的`state`只包含两个属性：列表的数据和一个布尔值，在拖动开始或结束时将更新。如果您不熟悉`ListView`的工作原理，请查看第二章中的*显示项目列表*配方，*创建一个简单的 React Native 应用程序*。让我们定义数据如下：

```jsx
export default class ContactList extends Component {
  ds = new ListView.DataSource({
    rowHasChanged: (r1, r2) => r1 !== r2
  });

  state = {
    dataSource: this.ds.cloneWithRows(data),
    swiping: false,
  };
  // Defined in later steps
} 
```

1.  `render`方法只需要显示列表。在`renderScrollComponent`属性中，我们将仅在用户不在列表上滑动项目时启用滚动。如果用户在滑动，我们希望禁用垂直滚动，如下所示：

```jsx
  render() {
    const { dataSource, swiping } = this.state;

    return (
    <ListView
        key={data}
        enableEmptySections
        dataSource={dataSource}
        renderScrollComponent={
        (props) => <ScrollView {...props} scrollEnabled={!swiping}/>
        }
        renderRow={this.renderItem}
      />
    );
  }
```

1.  `renderItem`方法将返回列表中的每个项目。在这里，我们需要将联系信息作为属性发送，以及三个回调函数：

```jsx
  renderItem = (contact) => (
    <ContactItem
      contact={contact}
      onRemove={this.handleRemoveContact}
      onDragEnd={this.handleToggleSwipe}
      onDragStart={this.handleToggleSwipe}
    />
  );
```

1.  我们需要切换`state`对象上的 swiping 属性的值，这将切换列表上的垂直滚动是否被锁定：

```jsx
  handleToggleSwipe = () => {
    this.setState({ swiping: !this.state.swiping });
  }
```

1.  在移除项目时，我们需要找到给定`contact`的`index`，然后从原始列表中将其移除。之后，我们需要更新`state`上的`dataSource`，以使用生成的数据重新渲染列表：

```jsx
  handleRemoveContact = (contact) => {
    const index = data.findIndex(
      (item) => item.id === contact.id
    );
    data.splice(index, 1);

    this.setState({
        dataSource: this.ds.cloneWithRows(data),
    });
  }
```

1.  列表已经完成，现在让我们专注于列表项。让我们打开`ContactList/ContactItem.js`文件，并导入我们需要的依赖项：

```jsx
import React, { Component } from 'react';
import {
  Animated,
  Easing,
  PanResponder,
  StyleSheet,
  Text,
  TouchableHighlight,
  View,
} from 'react-native';
```

1.  我们需要为这个组件定义`defaultProps`。`defaultProps`对象将需要为从父级`ListView`元素传递给它的四个 props 中的每一个都提供一个空函数。当项目被按下时，`onPress`函数将被执行，当联系人被移除时，`onRemove`函数将被执行，而两个拖动函数将监听拖动事件。在`state`上，我们只需要定义一个动画值来保存拖动的 x 和 y 坐标，如下所示：

```jsx
export default class ContactItem extends Component {
  static defaultProps = {
    onPress: () => {},
    onRemove: () => {},
    onDragEnd: () => {},
    onDragStart: () => {},
  };

  state = {
    pan: new Animated.ValueXY(),
  };
```

1.  当组件被创建时，我们需要配置`PanResponder`。我们将在`componentWillMount`生命周期钩子中进行这个操作。`PanResponder`负责处理手势。它提供了一个简单的 API 来捕获用户手指生成的事件，如下所示：

```jsx
  componentWillMount() {
    this.panResponder = PanResponder.create({
      onMoveShouldSetPanResponderCapture: this.handleShouldDrag,
      onPanResponderMove: Animated.event(
        [null, { dx: this.state.pan.x }]
      ),
      onPanResponderRelease: this.handleReleaseItem,
      onPanResponderTerminate: this.handleReleaseItem,
    });
  }
```

1.  现在让我们定义实际的函数，这些函数将在前一步中定义的每个回调中执行。我们可以从`handleShouldDrag`方法开始，如下所示：

```jsx
  handleShouldDrag = (e, gesture) => {
    const { dx } = gesture;
    return Math.abs(dx) > 2;
  }
```

1.  `handleReleaseItem`有点复杂。我们将把这个方法分成两步。首先，我们需要弄清楚当前项目是否需要被移除。为了做到这一点，我们需要设置一个阈值。如果用户将元素滑动超出我们的阈值，我们将移除该项目，如下所示：

```jsx
  handleReleaseItem = (e, gesture) => {
    const { onRemove, contact,onDragEnd } = this.props;
    const move = this.rowWidth - Math.abs(gesture.dx);
    let remove = false;
    let config = { // Animation to origin position
      toValue: { x: 0, y: 0 },
      duration: 500,
    };

    if (move < this.threshold) {
      remove = true;
      if (gesture.dx > 0) {
        config = { // Animation to the right
          toValue: { x: this.rowWidth, y: 0 },
          duration: 100,
        };
      } else {
        config = { // Animation to the left
          toValue: { x: -this.rowWidth, y: 0 },
          duration: 100,
        };
      }
    }
    // Remainder in next step
  }
```

1.  一旦我们对动画进行了配置，我们就准备好移动项目了！首先，我们将执行`onDragEnd`回调，如果项目应该被移除，我们将运行`onRemove`函数，如下所示：

```jsx
  handleReleaseItem = (e, gesture) => {
    // Code from previous step

    onDragEnd();
    Animated.spring(
      this.state.pan,
      config,
    ).start(() => {
      if (remove) {
        onRemove(contact);
      }
    });
  }
```

1.  拖动系统已经完全就绪。现在我们需要定义`render`方法。我们只需要在`TouchableHighlight`元素内显示联系人姓名，包裹在`Animated.View`中，如下所示：

```jsx
  render() {
    const { contact, onPress } = this.props;

    return (
      <View style={styles.row} onLayout={this.setThreshold}>
        <Animated.View
          style={[styles.pan, this.state.pan.getLayout()]}
          {...this.panResponder.panHandlers}
        >
          <TouchableHighlight
            style={styles.info}
            onPress={() => onPress(contact)}
            underlayColor="#ecf0f1"
          >
            <Text>{contact.name}</Text>
          </TouchableHighlight>
        </Animated.View>
      </View>
    );
  }
```

1.  我们需要在这个类上再添加一个方法，这个方法是通过`View`元素的`onLayout`属性在布局改变时触发的。`setThreshold`将获取`row`的当前`width`并设置`threshold`。在这种情况下，我们将其设置为屏幕宽度的三分之一。这些值是必需的，以决定是否移除该项，如下所示：

```jsx
  setThreshold = (event) => {
    const { layout: { width } } = event.nativeEvent;
    this.threshold = width / 3;
    this.rowWidth = width;
  }
```

1.  最后，我们将为行添加一些样式，如下所示：

```jsx
const styles = StyleSheet.create({
  row: {
    backgroundColor: '#ecf0f1',
    borderBottomWidth: 1,
    borderColor: '#ecf0f1',
    flexDirection: 'row',
  },
  pan: {
    flex: 1,
  },
  info: {
    backgroundColor: '#fff',
    paddingBottom: 20,
    paddingLeft: 10,
    paddingTop: 20,
  },
});
```

1.  最终的应用程序应该看起来像这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/55bfe95b-94b3-4398-8c7e-660e00cd7dad.png)

# 它是如何工作的...

在*步骤 5*中，我们在`state`上定义了`swiping`属性。这个属性只是一个布尔值，当拖动开始时设置为`true`，当完成时设置为`false`。我们需要这个信息来锁定列表在拖动项目时的垂直滚动。

在*步骤 7*中，我们定义了列表中每行的内容。`onDragStart`属性接收`handleToggleSwipe`方法，当拖动开始时将执行该方法。当拖动完成时，我们也将执行相同的方法。

在同一步骤中，我们还将`handleRemoveContact`方法发送给每个项目。顾名思义，当用户将其滑出时，我们将从列表中移除当前项目。

在*步骤 11*中，我们为项目组件定义了`defaultProps`和`state`。在过去的示例中，我们一直使用单个值来创建动画，但是在这种情况下，我们需要处理*x*和*y*坐标，所以我们需要一个`Animated.ValueXY`的实例。在内部，这个类处理两个`Animated.Value`实例，因此 API 几乎与我们之前看到的那些相同。

在*步骤 12*中，创建了`PanResponder`。React Native 中的手势系统，就像浏览器中的事件系统一样，在触摸事件时处理手势分为两个阶段：捕获和冒泡。在我们的情况下，我们需要使用捕获阶段来确定当前事件是按压项目还是尝试拖动它。`onMoveShouldSetPanResponderCapture`将捕获事件。然后，我们需要通过返回`true`或`false`来决定是否拖动该项。

`onPanResponderMove`属性将在每一帧从动画中获取值，这些值将被应用于`state`中的`pan`对象。我们需要使用`Animated.event`来访问每一帧的动画值。在这种情况下，我们只需要`x`值。稍后，我们将使用这个值来运行不同的动画，将元素返回到其原始位置或将其从屏幕上移除。

当用户释放物品时，`onPanResponderRelease`函数将被执行。如果由于任何其他原因，拖动被中断，将执行`onPanResponderTerminate`。

在*步骤 13*中，我们需要检查当前事件是简单的按压还是拖动。我们可以通过检查*x*轴上的增量来做到这一点。如果触摸事件移动了超过两个像素，那么用户正在尝试拖动物品，否则，他们正在尝试按下按钮。我们将差异评估为绝对数，因为移动可能是从左到右或从右到左，我们希望适应这两种移动。

在*步骤 14*中，我们需要获取物品相对于设备宽度移动的距离。如果这个距离低于我们在`setThreshold`中定义的阈值，那么我们需要移除这些物品。我们为每个动画定义了`config`对象，否则将返回物品到原始位置。但是，如果我们需要移除物品，我们会检查方向并相应地设置配置。

在*步骤 16*中，我们定义了 JSX。我们在`Animated.View`上设置我们想要动画的样式。在这种情况下，它是`left`属性，但是我们可以从我们在`state.pan`中存储的`Animated.ValueXY`实例中调用`getLayout`方法，而不是手动创建对象，该方法返回具有其现有值的 top 和 left 属性。

在同一步骤中，我们还通过展开`this.panResponder.panHandlers`来为`Animated.View`设置事件处理程序，使用展开运算符将我们在前面步骤中定义的拖动配置绑定到`Animated.View`。

我们还定义了对`props`中的`onPress`回调的调用，传入当前的`contact`信息。

# 另请参阅

您可以在以下网址找到`PanResponder` API 文档：

[`facebook.github.io/react-native/docs/panresponder.html`](https://facebook.github.io/react-native/docs/panresponder.html)

# 创建一个 Facebook 反应小部件

在这个食谱中，我们将创建一个模拟 Facebook 反应小部件的组件。我们将有一个喜欢按钮图像，当按下时，将显示五个图标。图标行将使用交错的滑入动画，同时从`0`增加到`1`的不透明度。

# 准备工作

让我们创建一个名为`facebook-widget`的空应用程序。

我们需要一些图片来显示一个假时间线。一些你的猫的照片就可以了，或者你可以使用 GitHub 上相应存储库中包含的猫的图片（[`github.com/warlyware/react-native-cookbook/tree/master/chapter-7/facebook-widget`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-7/facebook-widget)）。我们还需要五个图标来显示五种反应，比如，生气、笑、心、惊讶，这些也可以在相应的存储库中找到。

首先，我们将在空应用程序中创建两个 JavaScript 文件：`Reactions/index.js`和`Reactions/Icon.js`。我们需要将猫的图片复制到应用程序根目录下的`images/`文件夹中，反应图标应放置在`Reactions/images`中。

# 如何做...

1.  我们将在`App`类上创建一个假的 Facebook 时间线。让我们首先导入依赖项，如下所示：

```jsx
import React from 'react';
import {
  Dimensions,
  Image,
  Text,
  ScrollView,
  StyleSheet,
  SafeAreaView,
} from 'react-native';
import Reactions from './Reactions';
```

1.  我们需要导入一些图片来在我们的时间线中渲染。这一步中的 JSX 非常简单：只是一个`toolbar`，一个带有两个`Image`和两个`Reaction`组件的`ScrollView`，如下所示：

```jsx
const image1 = require('./images/01.jpg');
const image2 = require('./images/02.jpg');
const { width } = Dimensions.get('window');

const App = () => (
  <SafeAreaView style={styles.main}>
    <Text style={styles.toolbar}>Reactions</Text>
    <ScrollView style={styles.content}>
      <Image source={image1} style={styles.image} resizeMode="cover" />
      <Reactions />
      <Image source={image2} style={styles.image} resizeMode="cover" />
      <Reactions />
    </ScrollView>
  </SafeAreaView>
);

export default App;
```

1.  我们需要为这个组件添加一些基本的样式，如下所示：

```jsx
const styles = StyleSheet.create({
  main: {
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#3498db',
    color: '#fff',
    fontSize: 22,
    padding: 20,
    textAlign: 'center',
  },
  content: {
    flex: 1,
  },
  image: {
    width,
    height: 300,
  },
});
```

1.  我们准备开始工作在这个食谱的`Reactions`组件。让我们首先导入依赖项，如下所示。我们将在后续步骤中构建导入的`Icon`组件：

```jsx
import React, { Component } from 'react';
import {
  Image,
  Text,
  TouchableOpacity,
  StyleSheet,
  View,
} from 'react-native';
import Icon from './Icon';
```

1.  让我们定义`defaultProps`和初始`state`。我们还需要要求`like`图标图片以在屏幕上显示它，如下所示：

```jsx
const image = require('./images/like.png');

export default class Reactions extends Component {
  static defaultProps = {
    icons: [
      'like', 'heart', 'angry', 'laughing', 'surprised',
    ],
  };

  state = {
    show: false,
    selected: '',
  };

  // Defined at later steps 
}
```

1.  让我们定义两种方法：一种是将`state`的选定值设置为选定的`reaction`，另一种是切换`state`的`show`值以相应地显示或隐藏反应行，如下所示：

```jsx
  onSelectReaction = (reaction) => {
    this.setState({
      selected: reaction,
    });
    this.toggleReactions();
  }

  toggleReactions = () => {
    this.setState({
      show: !this.state.show,
    });
  };
```

1.  我们将为此组件定义`render`方法。我们将显示一张图片，当按下时，将调用我们之前定义的`toggleReactions`方法，如下所示：

```jsx
  render() {
    const { style } = this.props;
    const { selected } = this.state;

    return (
      <View style={[style, styles.container]}>
        <TouchableOpacity onPress={this.toggleReactions}>
          <Image source={image} style={styles.icon} />
        </TouchableOpacity>
        <Text>{selected}</Text>
        {this.renderReactions()}
      </View>
    );
  }
```

1.  在这一步中，您会注意到我们正在调用`renderReactions`方法。接下来，我们将渲染用户按下主反应按钮时要显示的所有图标，如下所示：

```jsx
  renderReactions() {
    const { icons } = this.props;
    if (this.state.show) {
      return (
        <View style={styles.reactions}>
        { icons.map((name, index) => (
            <Icon
              key={index}
              name={name}
              delay={index * 100}
              index={index}
              onPress={this.onSelectReaction}
            />
          ))
        }
        </View>
      );
    }
  }
```

1.  我们需要为这个组件设置 `styles`。我们将为反应图标图像设置大小并定义一些填充。`reactions` 容器的高度将为 `0`，因为图标将浮动，我们不希望添加任何额外的空间：

```jsx
const styles = StyleSheet.create({
  container: {
    padding: 10,
  },
  icon: {
    width: 30,
    height: 30,
  },
  reactions: {
    flexDirection: 'row',
    height: 0,
  },
});
```

1.  `Icon` 组件目前缺失，所以如果我们尝试在这一点上运行我们的应用程序，它将失败。让我们通过打开 `Reactions/Icon.js` 文件并添加组件的导入来构建这个组件，如下所示：

```jsx
import React, { Component } from 'react';
import {
  Animated,
  Dimensions,
  Easing,
  Image,
  StyleSheet,
  TouchableOpacity,
  View,
} from 'react-native';
```

1.  让我们定义我们将要使用的图标。我们将使用一个对象来存储图标，这样我们可以通过键名轻松检索到每个图像，如下所示：

```jsx
const icons = {
  angry: require('./images/angry.png'),
  heart: require('./images/heart.png'),
  laughing: require('./images/laughing.png'),
  like: require('./images/like.png'),
  surprised: require('./images/surprised.png'),
};
```

1.  现在我们应该为这个组件定义 `defaultProps`。我们不需要定义初始状态：

```jsx
export default class Icon extends Component {
  static defaultProps = {
    delay: 0,
    onPress: () => {},
  };

}
```

1.  图标应该通过动画出现在屏幕上，所以当组件挂载时，我们需要创建并运行动画，如下所示：

```jsx
  componentWillMount() {
    this.animatedValue = new Animated.Value(0);
  }

  componentDidMount() {
    const { delay } = this.props;

    Animated.timing(
      this.animatedValue,
      {
        toValue: 1,
        duration: 200,
        easing: Easing.elastic(1),
        delay,
      }
    ).start();
  }
```

1.  当图标被按下时，我们需要执行 `onPress` 回调来通知父组件已选择了一个反应。我们将反应的名称作为参数发送，如下所示：

```jsx
  onPressIcon = () => {
    const { onPress, name } = this.props;
    onPress(name);
  }
```

1.  拼图的最后一块是 `render` 方法，我们将在这个组件中定义 JSX，如下所示：

```jsx
  render() {
    const { name, index, onPress } = this.props;
    const left = index * 50;
    const top = this.animatedValue.interpolate({
      inputRange: [0, 1],
      outputRange: [10, -95],
    });
    const opacity = this.animatedValue;

    return (
      <Animated.View
        style={[
          styles.icon,
          { top, left, opacity },
        ]}
      >
        <TouchableOpacity onPress={this.onPressIcon}>
          <Image source={icons[name]} style={styles.image} />
        </TouchableOpacity>
      </Animated.View>
    );
  }
```

1.  作为最后一步，我们将为每个 `icon` 添加样式。我们需要图标浮动，所以我们将 `position` 设置为 `absolute`，`width` 和 `height` 设置为 `40` 像素。在这个改变之后，我们应该能够运行我们的应用程序：

```jsx
  icon: {
    position: 'absolute',
  },
  image: {
    width: 40,
    height: 40,
  },
});
```

1.  最终的应用程序应该看起来像这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/6667bd05-b197-4847-85db-88e66021c454.png)

# 它是如何工作的...

在 *步骤 2* 中，我们在时间线中定义了 `Reactions` 组件。现在，我们不专注于处理数据，而是专注于显示用户界面。因此，我们不会通过 `Reactions` 属性发送任何回调来获取所选值。

在 *步骤 5* 中，我们定义了 `defaultProps` 和初始 `state`。

我们的状态中有两个属性：

+   `show` 属性是一个布尔值。我们用它来在用户按下主按钮时切换反应图标。当为 `false` 时，我们隐藏反应，当为 `true` 时，我们运行动画来显示每个图标。

+   `selected` 包含当前的选择。每当选择新的反应时，我们将更新这个属性。

在 *步骤 8* 中，我们渲染图标。在这里，我们需要将图标的名称发送到每个创建的实例。我们还为每个图标发送了 100 毫秒的 `delay`，这将创建一个漂亮的交错动画。`onPress` 属性接收了 *步骤 6* 中定义的 `onSelectReaction` 方法，该方法在 `state` 上设置了所选的反应。

在*步骤 13*中，我们创建了动画。首先，我们使用`Animated.Value`助手定义了`animatedValue`变量，正如在之前的配方中提到的那样，这是负责在动画中每一帧中保存值的类。组件一旦挂载，我们就运行动画。动画的进度从`0`到`1`，持续时间为 200 毫秒，使用弹性缓动函数，并根据接收到的`delay`属性延迟动画。

在*步骤 15*中，我们为`Icon`组件定义了 JSX。在这里，我们对`top`和`opacity`属性进行动画处理。对于`top`属性，我们需要从`animatedValue`中插值出值，以便图标从其原始位置向上移动 95 像素。`opacity`属性所需的值从`0`到`1`，由于我们不需要插值任何内容来完成这一点，因此我们可以直接使用`animatedValue`。

`left`值是根据`index`计算的：我们只是将图标向前一个图标的左侧移动 50 像素，这样可以避免将图标全部渲染在同一个位置。

# 在全屏显示图像

在这个配方中，我们将创建一个图像时间轴。当用户按下任何图像时，它将在黑色背景下全屏显示图像。

我们将为背景使用不透明度动画，并将图像从其原始位置滑入。

# 准备工作

让我们创建一个名为`photo-viewer`的空白应用程序。

此外，我们还将创建`PostContainer/index.js`来显示时间轴中的每个图像，以及`PhotoViewer/index.js`来在全屏显示所选图像。

您可以使用此处配方存储库中托管在 GitHub 上的图像（[`github.com/warlyware/react-native-cookbook/tree/master/chapter-7/photo-viewer`](https://github.com/warlyware/react-native-cookbook/tree/master/chapter-7/photo-viewer)）中包含的图像，也可以使用自己的一些照片。将它们放在项目根目录中的`images`文件夹中。

# 如何做...

1.  我们将在`App`类中显示一个带有图像的时间轴。让我们导入所有依赖项，包括我们稍后将构建的另外两个组件，如下所示：

```jsx
import React, { Component } from 'react';
import {
  Dimensions,
  Image,
  Text,
  ScrollView,
  StyleSheet,
  SafeAreaView,
} from 'react-native';
import PostContainer from './PostContainer';
import PhotoViewer from './PhotoViewer';
```

1.  在这一步中，我们将定义要渲染的数据。这只是一个包含`title`和`image`的对象数组。

```jsx
const image1 = require('./images/01.jpg');
const image2 = require('./images/02.jpg');
const image3 = require('./images/03.jpg');
const image4 = require('./images/04.jpg');

const timeline = [
  { title: 'Enjoying the fireworks', image: image1 },
  { title: 'Climbing the Mount Fuji', image: image2 },
  { title: 'Check my last picture', image: image3 },
  { title: 'Sakuras are beautiful!', image: image4 },
];
```

1.  现在我们需要声明此组件的初始`state`。当按下任何图像时，我们将更新`selected`和`position`属性，如下所示：

```jsx
export default class App extends Component {
  state = {
    selected: null,
    position: null,
  };
  // Defined in following steps
}
```

1.  为了更新`state`，我们将声明两个方法：一个用于设置被按下的图像的值，另一个用于在查看器关闭时删除这些值：

```jsx
  showImage = (selected, position) => {
    this.setState({
      selected,
      position,
    });
  }

  closeViewer = () => {
    this.setState({
      selected: null,
      position: null,
    });
  }
```

1.  现在我们准备开始处理`render`方法。在这里，我们需要在`ScrollView`中渲染每个图像，以便列表可以滚动，如下所示：

```jsx
  render() {
    return (
      <SafeAreaView style={styles.main}>
        <Text style={styles.toolbar}>Timeline</Text>
        <ScrollView style={styles.content}>
        {
          timeline.map((post, index) =>
            <PostContainer key={index} post={post}
            onPress={this.showImage} />
          )
        }
        </ScrollView>
        {this.renderViewer()}
      </SafeAreaView>
    );
  }
```

1.  在上一步中，我们调用了`renderViewer`方法。在这里，我们只会在状态中有一个帖子`selected`时显示查看器组件。我们还会发送初始位置以开始动画和一个关闭查看器的回调，如下所示：

```jsx
  renderViewer() {
    const { selected, position } = this.state;

    if (selected) {
      return (
        <PhotoViewer
          post={selected}
          position={position}
          onClose={this.closeViewer}
        />
      );
    }
  }
```

1.  这个组件的样式非常简单，只有一些颜色和填充，如下所示：

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#ecf0f1',
    flex: 1,
  },
  toolbar: {
    backgroundColor: '#2c3e50',
    color: '#fff',
    fontSize: 22,
    padding: 20,
    textAlign: 'center',
  },
  content: {
    flex: 1,
  },
});
```

1.  时间轴已经完成，但是如果我们尝试运行我们的应用程序，它将失败。让我们开始处理`PostContainer`组件。我们将首先导入依赖项，如下所示：

```jsx
import React, { Component } from 'react';
import {
  Dimensions,
  Image,
  Text,
  TouchableOpacity,
  StyleSheet,
  View,
} from 'react-native';
```

1.  我们只需要两个`props`来定义这个组件。`post`属性将接收图像数据，`title`和`image`，`onPress`属性是一个回调，当图像被按下时我们将执行它，如下所示：

```jsx
const { width } = Dimensions.get('window');

export default class PostContainer extends Component {
  static defaultProps = {
    onPress: ()=> {},
  };
  // Defined on following steps
}
```

1.  这个组件将在`ScrollView`中。这意味着当用户开始滚动内容时，它的位置将会改变。当按下图像时，我们需要获取屏幕上的当前位置并将这些信息发送给父组件，如下所示：

```jsx
  onPressImage = (event) => {
    const { onPress, post } = this.props;
    this.refs.main.measure((fx, fy, width, height, pageX, pageY) => {
      onPress(post, {
        width,
        height,
        pageX,
        pageY,
      });
    });
  }
```

1.  现在是时候为这个组件定义 JSX 了。为了保持简单，我们只会渲染`image`和`title`：

```jsx
  render() {
    const { post: { image, title } } = this.props;

    return (
      <View style={styles.main} ref="main">
        <TouchableOpacity
           onPress={this.onPressImage}
           activeOpacity={0.9}
            >
          <Image
            source={image}
            style={styles.image}
            resizeMode="cover"
          />
        </TouchableOpacity>
        <Text style={styles.title}>{title}</Text>
      </View>
    );
  }
```

1.  和往常一样，我们需要为这个组件定义一些样式。我们将添加一些颜色和填充，如下所示：

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#fff',
    marginBottom: 30,
    paddingBottom: 10,
  },
  content: {
    flex: 1,
  },
  image: {
    width,
    height: 300,
  },
  title: {
    margin: 10,
    color: '#ccc',
  }
});
```

1.  如果现在运行应用程序，我们应该能够看到时间轴，但是如果我们按下任何图像，将会抛出错误。我们需要定义查看器，所以让我们打开`PhotoViewer/index.js`文件并导入依赖项：

```jsx
import React, { Component } from 'react';
import {
  Animated,
  Dimensions,
  Easing,
  Text,
  TouchableOpacity,
  StyleSheet,
} from 'react-native';
```

1.  让我们为这个组件定义`props`。为了将图像居中显示在屏幕上，我们需要知道当前设备的`height`：

```jsx
const { width, height } = Dimensions.get('window');

export default class PhotoViewer extends Component {
  static defaultProps = {
    onClose: () => {},
  };
  // Defined on following steps
}
```

1.  当显示这个组件时，我们希望运行两个动画，因此我们需要在组件挂载后初始化并运行动画。动画很简单：它只是在`400`毫秒内从`0`到`1`进行一些缓动，如下所示：

```jsx
  componentWillMount() {
    this.animatedValue = new Animated.Value(0);
  }

  componentDidMount() {
    Animated.timing(
      this.animatedValue,
      {
        toValue: 1,
        duration: 400,
        easing: Easing.in,
      }
    ).start();
  }
```

1.  当用户按下关闭按钮时，我们需要执行`onClose`回调来通知父组件需要移除这个组件，如下所示：

```jsx
  onPressBtn = () => {
    this.props.onClose();
  }
```

1.  我们将把`render`方法分为两步。首先，我们需要插入动画的值，如下所示：

```jsx
  render() {
    const { post: { image, title }, position } = this.props;
    const top = this.animatedValue.interpolate({
      inputRange: [0, 1],
      outputRange: [position.pageY, height/2 - position.height/2],
    });
    const opacity = this.animatedValue;
    // Defined on next step 
  } 
```

1.  我们只需要定义三个元素：`Animated.View`来动画显示背景，`Animated.Image`来显示图像，以及一个关闭按钮。我们将`opacity`样式设置为主视图，这将使图像背景从透明变为黑色。图像将同时滑入，产生一个很好的效果：

```jsx
// Defined on previous step
  render() {
    return (
      <Animated.View
        style={[
          styles.main,
          { opacity },
        ]}
      >
        <Animated.Image
          source={image}
          style={[
            styles.image,
            { top, opacity }
          ]}
        />
        <TouchableOpacity style={styles.closeBtn}
          onPress={this.onPressBtn}
        >
          <Text style={styles.closeBtnText}>X</Text>
        </TouchableOpacity>
      </Animated.View>
    );
  }
```

1.  我们几乎完成了！这个食谱中的最后一步是定义样式。我们需要将主容器的位置设置为绝对位置，以便图像位于其他所有内容的顶部。我们还将关闭按钮移动到屏幕的右上角，如下所示：

```jsx
const styles = StyleSheet.create({
  main: {
    backgroundColor: '#000',
    bottom: 0,
    left: 0,
    position: 'absolute',
    right: 0,
    top: 0,
  },
  image: {
    width,
    height: 300,
  },
  closeBtn: {
    position: 'absolute',
    top: 50,
    right: 20,
  },
  closeBtnText: {
    fontSize: 20,
    color: '#fff',
    fontWeight: 'bold',
  },
});
```

1.  最终的应用程序应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/83d6acab-c119-4b20-88a1-d986453c805f.png)

# 它是如何工作的...

在*步骤 4*中，我们在`state`中定义了两个属性：`selected`和`position`。`selected`属性保存了按下图像的图像数据，可以是*步骤 3*中定义的`timeline`对象中的任何一个。`position`属性将保存屏幕上的当前*y*坐标，稍后用于将图像从其原始位置动画到屏幕中心。

在*步骤 5*中，我们对`timeline`数组进行`map`操作，以渲染每个`post`。我们为每个 post 使用`PostContainer`元素，发送`post`信息，并使用`onPress`回调来设置按下的图像。

在*步骤 10*中，我们需要图像的当前位置。为了实现这一点，我们使用所需信息的组件的`measure`方法。该方法接收一个回调函数，并检索，除其他属性外，`width`、`height`和屏幕上的当前位置。

我们正在使用引用来访问在下一步的 JSX 中声明的组件。

在*步骤 11*中，我们声明了组件的 JSX。在主包装容器中，我们设置了`ref`属性，用于获取图像的当前位置。每当我们想要在当前类的任何方法中访问组件时，我们都使用引用。我们可以通过简单地设置`ref`属性并为任何组件分配一个名称来创建引用。

在*步骤 18*中，我们插值动画值以获得每一帧的正确顶部值。插值的输出将从图像的当前位置开始，并向屏幕中间进展。这样，根据值是负数还是正数，动画将从底部向顶部运行，或者反之。

我们不需要插值 `opacity`，因为当前的动画值已经从 `0` 到 `1`。

# 另请参阅

Refs 和 DOM 的深入解释可以在以下链接找到：

[`reactjs.org/docs/refs-and-the-dom.html`](https://reactjs.org/docs/refs-and-the-dom.html)。
