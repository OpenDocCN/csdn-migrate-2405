# React 和 ReactNative 第二版（六）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十一章：响应用户手势

到目前为止，您在本书中实现的所有示例都依赖于用户手势。在传统的 Web 应用程序中，您主要处理鼠标事件。然而，触摸屏依赖用户用手指操作元素，这与鼠标完全不同。

本章的目标是向您展示 React Native 内部手势响应系统的工作原理，以及通过组件公开该系统的一些方式。

首先，您将学习有关滚动的内容。除了触摸之外，这可能是最常见的手势。然后，您将学习在用户与您的组件交互时提供适当级别的反馈。最后，您将实现可以被滑动的组件。

# 用手指滚动

在 Web 应用程序中，通过使用鼠标指针来拖动滚动条来进行滚动，或者通过旋转鼠标滚轮来进行滚动。这在移动设备上不起作用，因为没有鼠标。一切都由屏幕上的手势控制。例如，如果您想向下滚动，您可以使用拇指或食指在屏幕上移动手指来将内容向上拉。

像这样滚动是很难实现的，但它变得更加复杂。当您在移动屏幕上滚动时，会考虑拖动动作的速度。您快速拖动屏幕，然后松开，屏幕将根据您移动的速度继续滚动。在此过程中，您也可以触摸屏幕以阻止其滚动。

幸运的是，您不必处理大部分这些内容。`ScrollView`组件为您处理了大部分滚动复杂性。实际上，在第十六章*渲染项目列表*中，您已经使用了`ScrollView`组件。`ListView`组件内置了`ScrollView`。

您可以通过实现手势生命周期方法来突破用户交互的低级部分。您可能永远不需要这样做，但如果您感兴趣，可以在[`facebook.github.io/react-native/releases/next/docs/gesture-responder-system.html`](http://facebook.github.io/react-native/releases/next/docs/gesture-responder-system.html)上阅读相关内容。

您可以在`ListView`之外使用`ScrollView`。例如，如果您只是渲染文本和其他小部件等任意内容，而不是列表，您可以将其包装在`<ScrollView>`中。以下是一个示例：

```jsx
import React from 'react';
import {
  Text,
  ScrollView,
  ActivityIndicator,
  Switch,
  View
} from 'react-native';

import styles from './styles';

export default () => (
  <View style={styles.container}>
    {/* The "<ScrollView>" can wrap any
         other component to make it scrollable.
         Here, we're repeating an arbitrary group
         of components to create some scrollable
         content */}
    <ScrollView style={styles.scroll}>
      {new Array(6).fill(null).map((v, i) => (
        <View key={i}>
          {/* Abitrary "<Text>" component... */}
          <Text style={[styles.scrollItem, styles.text]}>
            Some text
          </Text>

          {/* Arbitrary "<ActivityIndicator>"... */}
          <ActivityIndicator style={styles.scrollItem} size="large" />

          {/* Arbitrary "<Switch>" component... */}
          <Switch style={styles.scrollItem} />
        </View>
      ))}
    </ScrollView>
  </View>
); 
```

`ScrollView`组件本身并没有太多用处——它用于包装其他组件。它需要一个高度才能正确地发挥作用。以下是滚动样式的外观：

```jsx
scroll: { 
  height: 1, 
  alignSelf: 'stretch', 
}, 
```

`height`设置为`1`，但`alignSelf`的`stretch`值允许项目正确显示。以下是最终结果的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3da6eac6-0017-42cc-9dfa-49f283008e8e.png)

当您拖动内容时，屏幕右侧会出现垂直滚动条。如果运行此示例，您可以尝试进行各种手势，例如使内容自动滚动，然后停止。

# 提供触摸反馈

到目前为止，在本书中您已经使用了纯文本来充当按钮或链接的 React Native 示例。在 Web 应用程序中，要使文本看起来像可以点击的东西，只需用适当的链接包装它。移动设备上没有类似的东西，因此您可以将文本样式化为按钮。

尝试在移动设备上将文本样式化为链接的问题在于它们太难按。按钮为手指提供了更大的目标，并且更容易应用触摸反馈。

让我们将一些文本样式化为按钮。这是一个很好的第一步，使文本看起来可以点击。但是当用户开始与按钮交互时，您还希望给予视觉反馈。React Native 提供了两个组件来帮助实现这一点：`TouchableOpacity`和`TouchableHighlight`。但在深入代码之前，让我们先看一下这些组件在用户与它们交互时的外观，首先是`TouchableOpacity`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7a1f8c69-a376-468c-9580-8b5e0a54efc0.png)

这里渲染了两个按钮，顶部的按钮标有“Opacity”当前正在被用户按下。当按下时，按钮的不透明度会变暗，这为用户提供了重要的视觉反馈。让我们看看当按下时`TouchableHighlight`按钮的外观，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f2037baf-4709-4699-83aa-c529aa891e68.png)

当按下时，`TouchableHighlight`组件不会改变不透明度，而是在按钮上添加一个高亮层。在这种情况下，它使用了 slate gray 的更透明的版本来进行高亮显示，slate gray 是字体和边框颜色中使用的颜色。

您使用哪种方法并不重要。重要的是，您为用户提供适当的触摸反馈，以便他们与按钮进行交互。实际上，您可能希望在同一个应用程序中使用两种方法，但用于不同的事物。让我们创建一个`Button`组件，这样可以轻松使用任一方法：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import {
  Text,
  TouchableOpacity,
  TouchableHighlight
} from 'react-native';

import styles from './styles';

// The "touchables" map is used to get the right
// component to wrap around the button. The
// "undefined" key represents the default.
const touchables = new Map([
  ['opacity', TouchableOpacity],
  ['highlight', TouchableHighlight],
  [undefined, TouchableOpacity]
]);

const Button = ({ label, onPress, touchable }) => {
  // Get's the "Touchable" component to use,
  // based on the "touchable" property value.
  const Touchable = touchables.get(touchable);

  // Properties to pass to the "Touchable"
  // component.
  const touchableProps = {
    style: styles.button,
    underlayColor: 'rgba(112,128,144,0.3)',
    onPress
  };

  // Renders the "<Text>" component that's
  // styled to look like a button, and is
  // wrapped in a "<Touchable>" component
  // to properly handle user interactions.
  return (
    <Touchable {...touchableProps}>
      <Text style={styles.buttonText}> {label} </Text>
    </Touchable>
  );
};

Button.propTypes = {
  onPress: PropTypes.func.isRequired,
  label: PropTypes.string.isRequired,
  touchable: PropTypes.oneOf(['opacity', 'highlight'])
};

export default Button; 
```

`touchables`映射用于确定基于`touchable`属性值的哪个 React Native 可触摸组件包装文本。以下是用于创建此按钮的样式：

```jsx
button: { 
  padding: 10, 
  margin: 5, 
  backgroundColor: 'azure', 
  borderWidth: 1, 
  borderRadius: 4, 
  borderColor: 'slategrey', 
}, 

buttonText: { 
  color: 'slategrey', 
} 
```

以下是如何在主应用程序模块中使用这些按钮：

```jsx
import React from 'react';
import { View } from 'react-native';

import styles from './styles';
import Button from './Button';

export default () => (
  <View style={styles.container}>
    {/* Renders a "<Button>" that uses
         "TouchableOpacity" to handle user
         gestures, since that is the default */}
    <Button onPress={() => {}} label="Opacity" />

    {/* Renders a "<Button>" that uses
         "TouchableHighlight" to handle
         user gestures. */}
    <Button
      onPress={() => {}}
      label="Highlight"
      touchable="highlight"
    />
  </View>
); 
```

请注意，`onPress`回调实际上并不执行任何操作，我们传递它们是因为它们是必需的属性。

# 可滑动和可取消

使原生移动应用程序比移动 Web 应用程序更易于使用的部分原因是它们感觉更直观。使用手势，您可以快速掌握事物的工作原理。例如，用手指在屏幕上滑动元素是一种常见的手势，但手势必须是可发现的。

假设您正在使用一个应用程序，并且不确定屏幕上的某些内容是做什么的。因此，您用手指按下并尝试拖动元素。它开始移动。不确定会发生什么，您松开手指，元素又回到原位。您刚刚发现了这个应用程序的一部分是如何工作的。

您将使用`Scrollable`组件来实现可滑动和可取消的行为。您可以创建一个相对通用的组件，允许用户将文本从屏幕上滑走，并在发生这种情况时调用回调函数。让我们先看看呈现滑动组件的代码，然后再看通用组件本身：

```jsx
import React, { Component } from 'react';
import { View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Swipeable from './Swipeable';

export default class SwipableAndCancellable extends Component {
  // The initial state is an immutable list of
  // 8 swipable items.
  state = {
    data: fromJS(
      new Array(8)
        .fill(null)
        .map((v, id) => ({ id, name: 'Swipe Me' }))
    )
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // The swipe handler passed to "<Swipeable>".
  // The swiped item is removed from the state.
  // This is a higher-order function that returns
  // the real handler so that the "id" context
  // can be set.
  onSwipe = id => () => {
    this.data = this.data.filterNot(v => v.get('id') === id);
  };

  render() {
    return (
      <View style={styles.container}>
        {this.data
          .toJS()
          .map(i => (
            <Swipeable
              key={i.id}
              onSwipe={this.onSwipe(i.id)}
              name={i.name}
            />
          ))}
      </View>
    );
  }
} 
```

这将在屏幕上呈现八个`<Swipeable>`组件。让我们看看这是什么样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/5560f4b8-a3f0-4c99-8b7b-c51716fffcb4.png)

现在，如果您开始向左滑动其中一个项目，它将移动。这是它的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/9438e9ef-c3a2-4e73-85b7-d0f08c051c3f.png)

如果您没有滑动足够远，手势将被取消，并且项目将按预期移回原位。如果您将其完全滑动，项目将从列表中完全移除，并且屏幕上的项目将填充空白空间，就像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/674ca464-d0aa-4179-acc7-bfb4ab83faf8.png)

现在让我们来看看`Swipeable`组件本身：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import {
  View,
  ScrollView,
  Text,
  TouchableOpacity
} from 'react-native';

import styles from './styles';

// The "onScroll" handler. This is actually
// a higher-order function that returns the
// actual handler. When the x offset is 200,
// when know that the component has been
// swiped and can call "onSwipe()".
const onScroll = onSwipe => e =>
  e.nativeEvent.contentOffset.x === 200 && onSwipe();

// The static properties used by the "<ScrollView>"
// component.
const scrollProps = {
  horizontal: true,
  pagingEnabled: true,
  showsHorizontalScrollIndicator: false,
  scrollEventThrottle: 10
};

const Swipeable = ({ onSwipe, name }) => (
  <View style={styles.swipeContainer}>
    {/* The "<View>" that wraps this "<ScrollView>"
         is necessary to make scrolling work properly. */}
    <ScrollView {...scrollProps} onScroll={onScroll(onSwipe)}>
      {/* Not strictly necessary, but "<TouchableOpacity>"
           does provide the user with meaningful feedback
           when they initially press down on the text. */}
      <TouchableOpacity>
        <View style={styles.swipeItem}>
          <Text style={styles.swipeItemText}>{name}</Text>
        </View>
      </TouchableOpacity>
      <View style={styles.swipeBlank} />
    </ScrollView>
  </View>
);

Swipeable.propTypes = {
  onSwipe: PropTypes.func.isRequired,
  name: PropTypes.string.isRequired
};

export default Swipeable; 
```

请注意，`<ScrollView>`组件被设置为水平，并且`pagingEnabled`为 true。分页行为会将组件捕捉到位，并提供可取消的行为。这就是为什么在文本组件旁边有一个空白组件的原因。以下是用于此组件的样式：

```jsx
swipeContainer: { 
  flex: 1, 
  flexDirection: 'row', 
  width: 200, 
  height: 30, 
  marginTop: 50, 
}, 

swipeItem: { 
  width: 200, 
  height: 30, 
  backgroundColor: 'azure', 
  justifyContent: 'center', 
  borderWidth: 1, 
  borderRadius: 4, 
  borderColor: 'slategrey', 
}, 

swipeItemText: { 
  textAlign: 'center', 
  color: 'slategrey', 
}, 

swipeBlank: { 
  width: 200, 
  height: 30, 
}, 
```

`swipeBlank`样式与`swipeItem`具有相同的尺寸，但没有其他内容。它是不可见的。

# 总结

在本章中，我们介绍了在原生平台上的手势与移动 web 平台相比的差异。我们首先看了`ScrollView`组件，以及它通过为包装组件提供原生滚动行为而使生活变得更加简单。

接下来，我们花了一些时间实现带有触摸反馈的按钮。这是另一个在移动 web 上很难做到的领域。你学会了如何使用`TouchableOpacity`和`TouchableHighlight`组件。

最后，你实现了一个通用的`Swipeable`组件。滑动是一种常见的移动模式，它允许用户在不感到害怕的情况下发现事物是如何工作的。在下一章中，你将学习如何使用 React Native 来控制图像显示。

# 测试你的知识

1.  web 应用程序和本地移动应用程序之间的用户交互的主要区别是什么？

1.  在 web 和移动应用中，用户交互没有明显的区别。

1.  移动应用程序本质上比其 web 等效版本更快，因此您的代码需要考虑到这一点。

1.  没有鼠标。相反，用户使用手指与您的 UI 进行交互。这是一种与使用鼠标完全不同的体验，需要进行适应。

1.  你如何在 React Native 中为用户提供触摸反馈？

1.  通过将`View`组件传递给`feedback`属性。

1.  通过用`TouchableOpacity`或`TouchableHighlight`组件包装可触摸组件。

1.  你必须在`onPress`处理程序中手动调整视图的样式。

1.  移动应用中的滚动为什么比 web 应用中的滚动复杂得多？

1.  在移动 web 应用中滚动需要考虑诸如速度之类的因素，因为用户是用手指进行交互。否则，交互会感到不自然。

1.  在复杂性上没有真正的区别。

1.  只有当你把它复杂化时，它才会变得复杂。触摸交互可以被实现成与鼠标交互完全相同的行为。

1.  为什么要使用 ScrollView 组件来实现可滑动的行为？

1.  因为这是 Web 应用程序中用户习惯的方式。

1.  因为这是移动 Web 应用程序中用户习惯的方式，以及他们学习 UI 控件的方式。

1.  你不应该实现可滑动的行为。

# 进一步阅读

查看以下链接以获取更多信息：

+   [`facebook.github.io/react-native/docs/scrollview`](https://facebook.github.io/react-native/docs/scrollview)

+   [`facebook.github.io/react-native/docs/touchablehighlight`](https://facebook.github.io/react-native/docs/touchablehighlight)

+   [`facebook.github.io/react-native/docs/touchableopacity`](https://facebook.github.io/react-native/docs/touchableopacity)


# 第二十二章：控制图像显示

到目前为止，本书中的示例在移动屏幕上还没有渲染任何图像。这并不反映移动应用程序的现实情况。Web 应用程序显示大量图像。如果说什么，原生移动应用程序比 Web 应用程序更依赖图像，因为图像是在有限空间下的强大工具。

在本章中，您将学习如何使用 React Native 的`Image`组件，从不同来源加载图像。然后，您将看到如何使用`Image`组件调整图像大小，以及如何为懒加载的图像设置占位符。最后，您将学习如何使用`react-native-vector-icons`包实现图标。

# 加载图像

让我们开始解决如何加载图像的问题。您可以渲染`<Image>`组件并像任何其他 React 组件一样传递属性。但是这个特定的组件需要图像 blob 数据才能发挥作用。让我们看一些代码：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Image } from 'react-native';

import styles from './styles';

// Renders two "<Image>" components, passing the
// properties of this component to the "source"
// property of each image.
const LoadingImages = ({ reactSource, relaySource }) => (
  <View style={styles.container}>
    <Image style={styles.image} source={reactSource} />
    <Image style={styles.image} source={relaySource} />
  </View>
);

// The "source" property can be either
// an object with a "uri" string, or a number
// represending a local "require()" resource.
const sourceProp = PropTypes.oneOfType([
  PropTypes.shape({
    uri: PropTypes.string.isRequired
  }),
  PropTypes.number
]).isRequired;

LoadingImages.propTypes = {
  reactSource: sourceProp,
  relaySource: sourceProp
};

LoadingImages.defaultProps = {
  // The "reactSource" image comes from a remote
  // location.
  reactSource: {
    uri:
      'https://facebook.github.io/react-native/docs/assets/favicon.png'
  },

  // The "relaySource" image comes from a local
  // source.
  relaySource: require('./images/relay.png')
};

export default LoadingImages;
```

有两种方法可以将 blob 数据加载到`<Image>`组件中。第一种方法是从网络加载图像数据。通过将带有`uri`属性的对象传递给`source`来实现。在这个例子中的第二个`<Image>`组件是使用本地图像文件，通过调用`require()`并将结果传递给`source`。

看一下`sourceProp`属性类型验证器。这让您了解可以传递给`source`属性的内容。它要么是一个带有`uri`字符串属性的对象，要么是一个数字。它期望一个数字，因为`require()`返回一个数字。

现在，让我们看看渲染结果如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/91c9947b-0c8f-4e97-be62-ea2a1317bf82.png)

这是与这些图像一起使用的样式：

```jsx
image: { 
  width: 100, 
  height: 100, 
  margin: 20, 
}, 
```

请注意，如果没有`width`和`height`样式属性，图像将不会渲染。在下一节中，您将学习在设置`width`和`height`值时图像调整大小的工作原理。

# 调整图像大小

`Image`组件的`width`和`height`样式属性决定了在屏幕上渲染的大小。例如，您可能会在某个时候需要处理分辨率比您在 React Native 应用程序中想要显示的更大的图像。只需在`Image`上设置`width`和`height`样式属性就足以正确缩放图像。

让我们看一些代码，让您可以使用控件动态调整图像的尺寸，如下所示：

```jsx
import React, { Component } from 'react';
import { View, Text, Image, Slider } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';

export default class ResizingImages extends Component {
  // The initial state of this component includes
  // a local image source, and the width/height
  // image dimensions.
  state = {
    data: fromJS({
      source: require('./images/flux.png'),
      width: 100,
      height: 100
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  render() {
    // The state values we need...
    const { source, width, height } = this.data.toJS();

    return (
      <View style={styles.container}>
        {/* The image is rendered using the
             "source", "width", and "height"
             state values. */}
        <Image source={source} style={{ width, height }} />
        {/* The current "width" and "height"
             values are displayed. */}
        <Text>Width: {width}</Text>
        <Text>Height: {height}</Text>
        {/* This slider scales the image size
             up or down by changing the "width"
             and "height" states. */}
        <Slider
          style={styles.slider}
          minimumValue={50}
          maximumValue={150}
          value={width}
          onValueChange={v => {
            this.data = this.data.merge({
              width: v,
              height: v
            });
          }}
        />
      </View>
    );
  }
} 
```

如果您使用默认的 100 x 100 尺寸，图像的外观如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b40ab7d7-8519-454a-a44d-8edff602c351.png)

这是图像的缩小版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/801928a3-1a5b-425a-b415-11b2c971d59d.png)

最后，这是图像的放大版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/53427742-e4ed-4b55-9369-fdd00facd101.png)`Image`组件可以传递`resizeMode`属性。这确定了缩放图像如何适应实际组件的尺寸。您将在本章的最后一节中看到此属性的作用。

# 延迟加载图像

有时，您不一定希望图像在渲染时立即加载。例如，您可能正在渲染尚未在屏幕上可见的内容。大多数情况下，从网络获取图像源在实际可见之前是完全可以的。但是，如果您正在微调应用程序并发现通过网络加载大量图像会导致性能问题，您可以懒惰地加载源。

我认为在移动环境中更常见的用例是处理渲染一个或多个图像的情况，其中它们是可见的，但网络响应速度很慢。在这种情况下，您可能希望渲染一个占位图像，以便用户立即看到一些东西，而不是空白空间。

要做到这一点，您可以实现一个包装实际图像的抽象，一旦加载完成，您就可以显示它。以下是代码：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { View, Image } from 'react-native';

// The local placeholder image source.
const placeholder = require('./images/placeholder.png');

// The mapping to the "loaded" state that gets us
// the appropriate image component.
const Placeholder = props =>
  new Map([
    [true, null],
    [false, <Image {...props} source={placeholder} />]
  ]).get(props.loaded);

class LazyImage extends Component {
  // The "width" and "height" properties
  // are required. All other properties are
  // forwarded to the actual "<Image>"
  // component.
  static propTypes = {
    style: PropTypes.shape({
      width: PropTypes.number.isRequired,
      height: PropTypes.number.isRequired
    })
  };

  constructor() {
    super();

    // We assume that the source hasn't finished
    // loading yet.
    this.state = {
      loaded: false
    };
  }

  render() {
    // The props and state this component
    // needs in order to render...
    const {
      props: {
        style: { width, height }
      },
      state: { loaded }
    } = this;

    return (
      <View style={{ width, height }}>
        {/* The placeholder image is just a standard
             "<Image>" component with a predefined
             source. It isn't rendered if "loaded" is
             true. */}
        <Placeholder loaded={loaded} {...this.props} />
        {/* The actual image is forwarded props that
             are passed to "<LazyImage>". The "onLoad"
             handler ensures the "loaded" state is true,
             removing the placeholder image. */}
        <Image
          {...this.props}
          onLoad={() =>
            this.setState({
              loaded: true
            })
          }
        />
      </View>
    );
  }
}

export default LazyImage; 
```

此组件呈现一个带有两个`Image`组件的`View`。它还具有一个`loaded`状态，最初为 false。当`loaded`为 false 时，将呈现占位图像。当调用“onLoad（）”处理程序时，`loaded`状态设置为 true。这意味着占位图像被移除，主图像被显示。

现在让我们使用您刚刚实现的`LazyImage`组件。您将渲染没有源的图像，并且应该显示占位图像。让我们添加一个按钮，为懒惰图像提供源，当它加载时，占位图像应该被替换。主应用程序模块的外观如下：

```jsx
import React, { Component } from 'react';
import { View } from 'react-native';

import styles from './styles';
import LazyImage from './LazyImage';
import Button from './Button';

// The remote image to load...
const remote =
  'https://facebook.github.io/react-native/docs/assets/favicon.png';

export default class LazyLoading extends Component {
  state = {
    source: null
  };

  render() {
    return (
      <View style={styles.container}>
        {/* Renders the lazy image. Since there's
             no "source" value initially, the placeholder
             image will be rendered. */}
        <LazyImage
          style={{ width: 200, height: 100 }}
          resizeMode="contain"
          source={this.state.source}
        />
        {/* When pressed, this button changes the
             "source" of the lazy image. When the new
             source loads, the placeholder image is
             replaced. */}
        <Button
          label="Load Remote"
          onPress={() =>
            this.setState({
              source: { uri: remote }
            })
          }
        />
      </View>
    );
  }
} 
```

这是屏幕最初的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1121ca04-d35f-4b1a-8400-9cc5ae289db0.png)

然后，如果单击“加载远程”按钮，最终将看到我们实际想要的图像：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1d6dbeaa-95cf-4594-b1c6-145df85e3d84.png)

你可能会注意到，根据你的网络速度，占位图片在你点击加载远程按钮后仍然可见。这是有意设计的，因为你不希望在确保实际图片准备好显示之前移除占位图片。

# 渲染图标

在本章的最后一节中，你将学习如何在 React Native 组件中渲染图标。使用图标来表示含义使 web 应用更易用。那么，原生移动应用为什么要有所不同呢？

你会想要使用`react-native-vector-icons`包将各种矢量字体包引入到你的 React Native 项目中：

```jsx
npm install --save @expo/vector-icons
```

现在你可以导入`Icon`组件并渲染它们。让我们实现一个示例，根据选择的图标类别渲染几个`FontAwesome`图标：

```jsx
import React, { Component } from 'react';
import { View, Picker, FlatList, Text } from 'react-native';
import Icon from 'react-native-vector-icons/FontAwesome';
import { fromJS } from 'immutable';

import styles from './styles';
import iconNames from './icon-names.json';

export default class RenderingIcons extends Component {
  // The initial state consists of the "selected"
  // category, the "icons" JSON object, and the
  // "listSource" used to render the list view.
  state = {
    data: fromJS({
      selected: 'Web Application Icons',
      icons: iconNames,
      listSource: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // Sets the "listSource" state based on the
  // "selected" icon state. Also sets the "selected"
  // state.
  updateListSource = selected => {
    this.data = this.data
      .update('listSource', listSource =>
        this.data.getIn(['icons', selected])
      )
      .set('selected', selected);
  };

  // Make sure the "listSource" is populated
  // before the first render.
  componentDidMount() {
    this.updateListSource(this.data.get('selected'));
  }

  render() {
    const { updateListSource } = this;

    // Get the state that we need to render the icon
    // category picker and the list view with icons.
    const selected = this.data.get('selected');
    const categories = this.data
      .get('icons')
      .keySeq()
      .toJS();
    const listSource = this.data.get('listSource');

    return (
      <View style={styles.container}>
        <View style={styles.picker}>
          {/* Lets the user select a FontAwesome icon
               category. When the selection is changed,
               the list view is changed. */}
          <Picker
            selectedValue={selected}
            onValueChange={updateListSource}
          >
            {categories.map(c => (
              <Picker.Item key={c} label={c} value={c} />
            ))}
          </Picker>
        </View>
        <FlatList
          style={styles.icons}
          data={listSource
            .map((value, key) => ({ key: key.toString(), value }))
            .toJS()}
          renderItem={({ item }) => (
            <View style={styles.item}>
              {/* The "<Icon>" component is used
                   to render the FontAwesome icon */}
              <Icon name={item.value} style={styles.itemIcon} />
              {/* Shows the icon class used */}
              <Text style={styles.itemText}>{item.value}</Text>
            </View>
          )}
        />
      </View>
    );
  }
} 
```

当你运行示例时，你应该看到类似以下的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/be6fc32f-96f8-416d-b798-42da75a7de63.png)

每个图标的颜色都是以与文本颜色相同的方式指定的，通过样式。

# 总结

在本章中，你学会了如何在 React Native 应用中处理图片。在原生移动应用中，图片和在 web 上下文中一样重要——它们提高了用户体验。

你学会了加载图片的不同方法，然后如何调整它们的大小。你还学会了如何实现一个懒加载图片，使用占位图片来显示，直到实际图片加载完成。最后，你学会了如何在 React Native 应用中使用图标。

在下一章中，你将学习关于 React Native 中的本地存储，这在你的应用离线时非常方便。

# 检验你的知识

1.  `Image`组件的`source`属性接受什么类型的值？

1.  `Image`组件接受本地文件的路径。

1.  `Image`组件接受远程图片 URL 的路径。

1.  `Image`组件接受本地文件和远程图片 URL 的路径。

1.  在图片加载时，你应该使用什么作为占位符？

1.  你应该使用一个在图片使用的上下文中有意义的占位图片。

1.  你应该为屏幕上尚未加载的任何图片使用`ActivityIndicator`组件。

1.  `Image`组件会自动为你处理占位符。

1.  你如何使用`Image`组件来缩放图片？

1.  你必须确保`Image`组件中只使用缩放后的图片。

1.  通过设置`width`和`height`属性，`Image`组件将自动处理图像的缩放。

1.  在移动应用程序中缩放图像会消耗大量 CPU，并且应该避免。

1.  值得为您的应用程序安装`react-native-vector-icons`包吗？

1.  是的，这个包可以为您的应用程序提供数千个图标，并且图标是向用户传达意图的重要工具。

1.  不，这会增加很多额外开销，并且图标在移动应用程序中并不有用。

# 进一步阅读

查看以下链接以获取更多信息：

+   [`facebook.github.io/react-native/docs/image`](https://facebook.github.io/react-native/docs/image)

+   [`github.com/oblador/react-native-vector-icons`](https://github.com/oblador/react-native-vector-icons)


# 第二十三章：离线操作

用户期望应用程序在网络连接不稳定的情况下能够无缝运行。如果您的移动应用程序无法应对瞬时网络问题，那么用户将使用其他应用程序。当没有网络时，您必须在设备上将数据持久保存在本地。或者，也许您的应用程序甚至不需要网络访问，即使是这种情况，您仍然需要在本地存储数据。

在本章中，您将学习如何使用 React Native 执行以下三件事。首先，您将学习如何检测网络连接状态。其次，您将学习如何在本地存储数据。最后，您将学习如何在网络问题导致数据存储后，一旦网络恢复，同步本地数据。

# 检测网络状态

如果您的代码在断开连接时尝试通过`fetch()`进行网络请求，将会发生错误。您可能已经为这些情况设置了错误处理代码，因为服务器可能返回其他类型的错误。然而，在连接问题的情况下，您可能希望在用户尝试进行网络请求之前检测到此问题。

主动检测网络状态有两个潜在原因。您可能会向用户显示友好的消息，指出网络已断开，他们无法做任何事情。然后，您将阻止用户执行任何网络请求，直到检测到网络已恢复。早期检测网络状态的另一个可能好处是，您可以准备在离线状态下执行操作，并在网络重新连接时同步应用程序状态。

让我们看一些使用`NetInfo`实用程序来处理网络状态变化的代码：

```jsx
import React, { Component } from 'react';
import { Text, View, NetInfo } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';

// Maps the state returned from "NetInfo" to
// a string that we want to display in the UI.
const connectedMap = {
  none: 'Disconnected',
  unknown: 'Disconnected',
  wifi: 'Connected',
  cell: 'Connected',
  mobile: 'Connected'
};

export default class NetworkState extends Component {
  // The "connected" state is a simple
  // string that stores the state of the
  // network.
  state = {
    data: fromJS({
      connected: ''
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // When the network state changes, use the
  // "connectedMap" to find the string to display.
  onNetworkChange = connection => {
    this.data = this.data.set(
      'connected',
      connectedMap[connection.type]
    );
  };

  // When the component is mounted, we add a listener
  // that changes the "connected" state when the
  // network state changes.
  componentDidMount() {
    NetInfo.addEventListener(
      'connectionChange',
      this.onNetworkChange
    );
  }

  // Make sure the listener is removed...
  componentWillUnmount() {
    NetInfo.removeEventListener(
      'connectionChange',
      this.onNetworkChange
    );
  }

  // Simply renders the "connected" state as
  // it changes.
  render() {
    return (
      <View style={styles.container}>
        <Text>{this.data.get('connected')}</Text>
      </View>
    );
  }
} 
```

该组件将根据`connectedMap`中的字符串值呈现网络状态。`NetInfo`对象的`connectionChange`事件将导致`connected`状态发生变化。例如，当您首次运行此应用程序时，屏幕可能如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/ad3ce214-c944-440d-b018-3990874045c1.png)

然后，如果您在主机机器上关闭网络，模拟设备上的网络状态也会发生变化，导致我们应用程序的状态如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1d263789-b1cf-4bb8-9360-5a8336a20e83.png)

# 存储应用程序数据

`AsyncStorage` API 在 iOS 和 Android 平台上的工作方式相同。您可以在不需要任何网络连接的应用程序中使用此 API，或者存储数据，一旦网络可用，就会使用 API 端点最终进行同步。

让我们看一些代码，允许用户输入键和值，然后存储它们：

```jsx
import React, { Component } from 'react';
import {
  Text,
  TextInput,
  View,
  FlatList,
  AsyncStorage
} from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Button from './Button';

export default class StoringData extends Component {
  // The initial state of this component
  // consists of the current "key" and "value"
  // that the user is entering. It also has
  // a "source" for the list view to display
  // everything that's been stored.
  state = {
    data: fromJS({
      key: null,
      value: null,
      source: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // Uses "AsyncStorage.setItem()" to store
  // the current "key" and "value" states.
  // When this completes, we can delete
  // "key" and "value" and reload the item list.
  setItem = () =>
    AsyncStorage.setItem(this.data.get('key'), this.data.get('value'))
      .then(() => {
        this.data = this.data.delete('key').delete('value');
      })
      .then(() => this.loadItems());

  // Uses "AsyncStorage.clear()" to empty any stored
  // values. Then, it loads the empty list of
  // items to clear the item list on the screen.
  clearItems = () =>
    AsyncStorage.clear().then(() => this.loadItems());

  // This method is async because awaits on the
  // data store keys and values, which are two
  // dependent async calls.
  async loadItems() {
    const keys = await AsyncStorage.getAllKeys();
    const values = await AsyncStorage.multiGet(keys);

    this.data = this.data.set('source', fromJS(values));
  }

  // Load any existing items that have
  // already been stored when the app starts.
  componentDidMount() {
    this.loadItems();
  }

  render() {
    // The state that we need...
    const { source, key, value } = this.data.toJS();

    return (
      <View style={styles.container}>
        <Text>Key:</Text>
        <TextInput
          style={styles.input}
          value={key}
          onChangeText={v => {
            this.data = this.data.set('key', v);
          }}
        />
        <Text>Value:</Text>
        <TextInput
          style={styles.input}
          value={value}
          onChangeText={v => {
            this.data = this.data.set('value', v);
          }}
        />
        <View style={styles.controls}>
          <Button label="Add" onPress={this.setItem} />
          <Button label="Clear" onPress={this.clearItems} />
        </View>
        <View style={styles.list}>
          <FlatList
            data={source.map(([key, value]) => ({
              key: key.toString(),
              value
            }))}
            renderItem={({ item: { value, key } }) => (
              <Text>
                {value} ({key})
              </Text>
            )}
          />
        </View>
      </View>
    );
  }
} 
```

在我解释这段代码在做什么之前，让我们先看一下以下屏幕，因为它将提供您所需的大部分解释：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/384aaa8d-0697-45d0-9947-2d6832a0b200.png)

如您所见，有两个输入字段和两个按钮。字段允许用户输入新的键和值。添加按钮允许用户在其设备上本地存储此键值对，而清除按钮则清除先前存储的任何现有项目。

`AsyncStorage` API 在 iOS 和 Android 上的工作方式相同。在底层，`AsyncStorage`的工作方式取决于它正在运行的平台。React Native 能够在两个平台上公开相同的存储 API 的原因是因为它的简单性——它只是键值对。比这更复杂的任何操作都留给应用程序开发人员。

在这个示例中，您围绕`AsyncStorage`创建的抽象很少。想法是设置和获取项目。然而，即使是这样简单的操作也值得一个抽象层。例如，您在这里实现的`setItem()`方法将进行异步调用到`AsyncStorage`并在完成后更新`items`状态。加载项目更加复杂，因为您需要将键和值作为两个单独的异步操作获取。

原因是保持 UI 的响应性。如果在将数据写入磁盘时需要进行待处理的屏幕重绘，通过阻止它们发生来阻止会导致用户体验不佳。

# 同步应用程序数据

到目前为止，在本章中，您已经学会了如何检测网络连接的状态，以及如何在 React Native 应用程序中本地存储数据。现在是时候结合这两个概念，并实现一个可以检测网络中断并继续运行的应用程序。

基本思想是只有在确定设备在线时才发出网络请求。如果知道设备不在线，可以在本地存储任何状态更改。然后，当您再次在线时，可以将这些存储的更改与远程 API 同步。

让我们实现一个简化的 React Native 应用程序来实现这一点。第一步是实现一个抽象层，位于 React 组件和存储数据的网络调用之间。我们将称这个模块为`store.js`：

```jsx
import { NetInfo, AsyncStorage } from 'react-native';
import { Map as ImmutableMap } from 'immutable';

// Mock data that would otherwise come from a real
// networked API endpoint.
const fakeNetworkData = {
  first: false,
  second: false,
  third: false
};

// We'll assume that the device isn't "connected"
// by default.
let connected = false;

// There's nothing to sync yet...
const unsynced = [];

// Sets the given "key" and "value". The idea
// is that application that uses this function
// shouldn't care if the network is connected
// or not.
export const set = (key, value) =>
  // The returned promise resolves to true
  // if the network is connected, false otherwise.
  new Promise((resolve, reject) => {
    if (connected) {
      // We're online - make the proper request (or fake
      // it in this case) and resolve the promise.
      fakeNetworkData[key] = value;
      resolve(true);
    } else {
      // We're offline - save the item using "AsyncStorage"
      // and add the key to "unsynced" so that we remember
      // to sync it when we're back online.
      AsyncStorage.setItem(key, value.toString()).then(
        () => {
          unsynced.push(key);
          resolve(false);
        },
        err => reject(err)
      );
    }
  });

// Gets the given key/value. The idea is that the application
// shouldn't care whether or not there is a network connection.
// If we're offline and the item hasn't been synced, read it
// from local storage.
export const get = key =>
  new Promise((resolve, reject) => {
    if (connected) {
      // We're online. Resolve the requested data.
      resolve(key ? fakeNetworkData[key] : fakeNetworkData);
    } else if (key) {
      // We've offline and they're asking for a specific key.
      // We need to look it up using "AsyncStorage".
      AsyncStorage.getItem(key).then(
        item => resolve(item),
        err => reject(err)
      );
    } else {
      // We're offline and they're asking for all values.
      // So we grab all keys, then all values, then we
      // resolve a plain JS object.
      AsyncStorage.getAllKeys().then(
        keys =>
          AsyncStorage.multiGet(keys).then(
            items => resolve(ImmutableMap(items).toJS()),
            err => reject(err)
          ),
        err => reject(err)
      );
    }
  });

// Check the network state when the module first
// loads so that we have an accurate value for "connected".
NetInfo.getConnectionInfo().then(
  connection => {
    connected = ['wifi', 'unknown'].includes(connection.type);
  },
  () => {
    connected = false;
  }
);

// Register a handler for when the state of the network changes.
NetInfo.addEventListener('connectionChange', connection => {
  // Update the "connected" state...
  connected = ['wifi', 'unknown'].includes(connection.type);

  // If we're online and there's unsynced values,
  // load them from the store, and call "set()"
  // on each of them.
  if (connected && unsynced.length) {
    AsyncStorage.multiGet(unsynced).then(items => {
      items.forEach(([key, val]) => set(key, val));
      unsynced.length = 0;
    });
  }
}); 
```

该模块导出了两个函数——`set()`和`get()`。它们的工作分别是设置和获取数据。由于这只是演示如何在本地存储和网络端点之间同步的示例，因此该模块只是用`fakeNetworkData`对象模拟了实际网络。

让我们先看看`set()`函数。这是一个异步函数，它总是返回一个解析为布尔值的 promise。如果为 true，则表示您在线，并且网络调用成功。如果为 false，则表示您离线，并且使用`AsyncStorage`保存了数据。

`get()`函数也采用了相同的方法。它返回一个解析布尔值的 promise，指示网络的状态。如果提供了一个键参数，那么将查找该键的值。否则，将返回所有值，无论是从网络还是从`AsyncStorage`中。

除了这两个函数之外，该模块还做了另外两件事。它使用`NetInfo.getConnectionInfo()`来设置`connected`状态。然后，它添加了一个监听器以侦听网络状态的变化。这就是当您离线时本地保存的项目在再次连接时与网络同步的方式。

现在让我们看一下使用这些函数的主要应用程序：

```jsx
import React, { Component } from 'react';
import { Text, View, Switch, NetInfo } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import { set, get } from './store';

// Used to provide consistent boolean values
// for actual booleans and their string representations.
const boolMap = {
  true: true,
  false: false
};

export default class SynchronizingData extends Component {
  // The message state is used to indicate that
  // the user has gone offline. The other state
  // items are things that the user wants to change
  // and sync.
  state = {
    data: fromJS({
      message: null,
      first: false,
      second: false,
      third: false
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // Generates a handler function bound to a given key.
  save = key => value => {
    // Calls "set()" and depending on the resolved value,
    // sets the user message.
    set(key, value).then(
      connected => {
        this.data = this.data
          .set('message', connected ? null : 'Saved Offline')
          .set(key, value);
      },
      err => {
        this.data = this.data.set('message', err);
      }
    );
  };

  componentDidMount() {
    // We have to call "NetInfo.fetch()" before
    // calling "get()" to ensure that the
    // connection state is accurate. This will
    // get the initial state of each item.
    NetInfo.getConnectionInfo().then(() =>
      get().then(
        items => {
          this.data = this.data.merge(items);
        },
        err => {
          this.data = this.data.set('message', err);
        }
      )
    );
  }

  render() {
    // Bound methods...
    const { save } = this;

    // State...
    const { message, first, second, third } = this.data.toJS();

    return (
      <View style={styles.container}>
        <Text>{message}</Text>
        <View>
          <Text>First</Text>
          <Switch
            value={boolMap[first.toString()]}
            onValueChange={save('first')}
          />
        </View>
        <View>
          <Text>Second</Text>
          <Switch
            value={boolMap[second.toString()]}
            onValueChange={save('second')}
          />
        </View>
        <View>
          <Text>Third</Text>
          <Switch
            value={boolMap[third.toString()]}
            onValueChange={save('third')}
          />
        </View>
      </View>
    );
  }
} 
```

`App`组件的工作是保存三个复选框的状态，当您为用户提供无缝的在线和离线模式切换时，这是困难的。幸运的是，您在另一个模块中实现的`set()`和`get()`抽象层隐藏了大部分细节，使应用功能更加简单。

然而，您会注意到，在尝试加载任何项目之前，您需要在此模块中检查网络状态。如果您不这样做，那么`get()`函数将假定您处于离线状态，即使连接正常。应用程序的外观如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/03d50c1c-606b-4b1b-a8d3-a74aee4df357.png)

请注意，直到您在 UI 中更改了某些内容，您才会实际看到“已保存离线”消息。

# 总结

本章介绍了在 React Native 应用程序中离线存储数据。您希望在设备离线并且您的应用无法与远程 API 通信时，才需要将数据存储在本地。然而，并非所有应用程序都需要 API 调用，`AsyncStorage`可以用作通用存储机制。您只需要围绕它实现适当的抽象。

您还学会了如何在 React Native 应用程序中检测网络状态的变化。了解设备何时离线很重要，这样您的存储层就不会进行无谓的网络调用尝试。相反，您可以让用户知道设备处于离线状态，然后在连接可用时同步应用程序状态。

这就结束了本书的第二部分。您已经了解了如何为 Web 构建 React 组件，以及为移动平台构建 React 组件。在本书的开头，我提出了 React 之美在于渲染目标的概念。React 的声明式编程接口永远不需要更改。将 JSX 元素转换的底层机制是完全可替换的 - 理论上，您可以将 React 渲染到任何地方。

在本书的最后部分，我将讨论 React 应用程序中的状态。状态和管理其在应用程序中流动的策略可以决定 React 架构的成败。

# 测试您的知识

1.  为什么`AsyncStorage` API 中的操作是异步的？

1.  这样您可以同时执行大量存储操作。

1.  为了不干扰 UI 的响应性。

1.  它们不是异步操作，它们只是返回承诺，以保持与其他存储 API 的一致性。

1.  您将使用哪个`AsyncStorage` API 来一次查找多个项目？

1.  `AsyncStorage.getAll()`

1.  `AsyncStorage.filter()`

1.  `AsyncStorage.getAllKeys()`和`AsyncStorage.multiGet()`的组合。

1.  在 React Native 应用程序中如何获取设备的连接状态？

1.  您调用`NetInfo.getConnectionInfo()`并读取结果连接类型。

1.  您调用`NetInfo.getConnectionInfo()`，如果返回 true，则表示已连接。否则，您处于离线状态。

1.  有一个全局的`reactNativeConnectionInfo`对象，您可以随时从中读取以确定连接的状态。

1.  在 React Native 应用程序中如何响应连接状态的变化？

1.  无法响应连接状态的更改。

1.  您可以通过调用`NetInfo.addEventListener('connectionChange', ...)`来监听`connectionChange`事件。

1.  您可以为`NetInfo.onChange()` API 提供回调函数。

# 进一步阅读

访问以下链接以获取更多信息：

+   [`facebook.github.io/react-native/docs/asyncstorage`](https://facebook.github.io/react-native/docs/asyncstorage)

+   [`facebook.github.io/react-native/docs/netinfo`](https://facebook.github.io/react-native/docs/netinfo)


# 第二十四章：处理应用程序状态

在本书的早期，你一直在使用状态来控制你的 React 组件。状态是任何 React 应用程序中的重要概念，因为它控制用户可以看到和交互的内容。没有状态，你只有一堆空的 React 组件。

在本章中，你将学习 Flux 以及它如何作为信息架构的基础。然后，你将学习如何构建最适合 Web 和移动架构的架构。你还将介绍 Redux 库，然后讨论 React 架构的局限性以及如何克服它们。

# 信息架构和 Flux

将用户界面视为信息架构可能很难。更常见的是，你对 UI 应该如何看起来和行为有一个大致的想法，然后你实现它。我一直这样做，这是一个很好的方法，可以让事情开始进行，及早发现你的方法存在的问题等等。但是然后我喜欢退一步，想象没有任何小部件时会发生什么。不可避免的是，我构建的东西在状态通过各种组件流动方面存在缺陷。这没关系；至少现在我有东西可以使用。我只需要确保在构建太多之前解决信息架构的问题。

Flux 是 Facebook 创建的一组模式，它帮助开发人员以与其应用程序自然契合的方式思考他们的信息架构。接下来我将介绍 Flux 的关键概念，这样你就可以将这些想法应用到统一的 React 架构中。

# 单向性

在本书的前面，我介绍了 React 组件的容器模式。容器组件具有状态，但实际上不会呈现任何 UI 元素。相反，它呈现其他 React 组件并将其状态作为属性传递。每当容器状态更改时，子组件都会使用新的属性值重新呈现。这是单向数据流。

Flux 采纳了这个想法，并将其应用于称为存储的东西。**存储**是一个抽象概念，它保存应用程序状态。就我而言，React 容器是一个完全有效的 Flux 存储。我一会儿会详细介绍存储。首先，我希望你理解为什么单向数据流是有利的。

您很可能已经实现了一个改变状态的 UI 组件，但并不总是确定它是如何发生的。它是另一个组件中的某个事件的结果吗？是某个网络调用完成的副作用吗？当发生这种情况时，您会花费大量时间追踪更新的来源。结果往往是一个连续的麻烦游戏。当改变只能来自一个方向时，您可以排除许多其他可能性，从而使整体架构更可预测。

# 同步更新轮次

当您改变 React 容器的状态时，它将重新渲染其子组件，子组件将重新渲染它们的子组件，依此类推。在 Flux 术语中，这称为*更新轮次*。从状态改变到 UI 元素反映这一变化的时间，这就是轮次的边界。能够将应用程序行为的动态部分分组成更大的块是很好的，因为这样更容易理解因果关系。

React 容器组件的一个潜在问题是它们可以交织在一起并以非确定性的顺序进行渲染。例如，如果某个 API 调用完成并导致在另一个更新轮次中的渲染完成之前发生状态更新，会发生什么？如果不认真对待，异步性的副作用会累积并演变成不可持续的架构。

Flux 架构中的解决方案是强制同步更新轮次，并将试图规避更新轮次顺序的尝试视为错误。JavaScript 是一个单线程的、运行至完成的环境，应该通过与之合作而不是对抗来接受它。先更新整个 UI，然后再次更新整个 UI。事实证明，React 是这项工作的一个非常好的工具。

# 可预测的状态转换

在 Flux 架构中，您有一个用于保存应用程序状态的存储。您知道，当状态发生变化时，它是同步和单向的，使整个系统更可预测且更易于理解。然而，还有一件事可以做，以确保不会引入副作用。

你将所有应用程序状态都保存在一个存储中，这很好，但你仍然可以通过在其他地方改变数据来破坏一切。这些变化乍看起来可能无害，但对你的架构来说是有害的。例如，处理`fetch()`调用的回调函数可能在将数据传递给存储之前对数据进行操作。事件处理程序可能生成一些结构并将其传递给存储。可能性是无限的。

在存储之外执行这些状态转换的问题在于你并不一定知道它们正在发生。将数据变异看作蝴蝶效应：一个小的改变会产生不明显的深远影响。解决方案是只在存储中变异状态，没有例外。这样做是可预测的，可以轻松追踪你的 React 架构的因果关系。

我一直在本书的大部分示例中使用`Immutable.js`来管理状态。当你考虑 Flux 架构中的状态转换时，这将会很有用。控制状态转换发生的位置很重要，但状态的不可变性也很重要。它有助于强化 Flux 架构的理念，当我们深入了解 Redux 时，你将更深入地了解这些理念。

# 统一的信息架构

让我们回顾一下到目前为止我们应用程序架构的要素：

+   **React Web**：在 Web 浏览器中运行的应用程序

+   **React Native**：在移动平台上本地运行的应用程序

+   **Flux**：可扩展数据在 React 应用程序中的模式

记住，React 只是一个位于渲染目标之上的抽象。两个主要的渲染目标是浏览器和移动原生应用。这个列表可能会不断增长，所以你需要设计你的架构，以便不排除未来的可能性。挑战在于你不是将一个 Web 应用程序移植到原生移动应用程序；它们是不同的应用程序，但它们有相同的目的。

话虽如此，是否有一种方式可以基于 Flux 的思想仍然拥有某种统一的信息架构，可以被这些不同的应用使用？我能想到的最好答案，不幸的是，是：有点。你不希望让不同的网页和移动用户体验导致在处理状态上采取截然不同的方法。如果应用的目标是相同的，那么必须有一些共同的信息可以使用，使用相同的 Flux 概念。

困难的部分在于网页和原生移动应用是不同的体验，这意味着你的应用状态的形式会有所不同。它必须是不同的；否则，你只是在不同平台之间移植，这违背了使用 React Native 来利用浏览器中不存在的功能的初衷。

# 实现 Redux

你将使用一个叫做 Redux 的库来实现一个演示 Flux 架构的基本应用。Redux 并不严格遵循 Flux 所设定的模式。相反，它借鉴了 Flux 的关键思想，并实现了一个小的 API，使得实现 Flux 变得容易。

应用本身将是一个新闻阅读器，一个你可能从未听说过的时髦读者。这是一个简单的应用，但我想要在实现过程中突出架构上的挑战。即使是简单的应用，在关注数据时也会变得复杂。

你将实现这个应用的两个版本。你将从网页版本开始，然后实现移动——iOS 和 Android 的原生应用。你将看到如何在应用之间共享架构概念。当你需要在多个平台上实现相同的应用时，这降低了概念上的负担。你现在正在实现两个应用，但随着 React 扩展其渲染能力，将来可能会有更多。

我再次敦促你从[`github.com/PacktPublishing/React-and-React-Native-Second-Edition`](https://github.com/PacktPublishing/React-and-React-Native-Second-Edition)下载本书的代码示例。这本书中有很多我无法在书中覆盖的细节，尤其是对于我们即将看到的这些示例应用。

# 初始应用状态

让我们首先看一下 Flux 存储的初始状态。在 Redux 中，应用的整个状态由一个单一的存储表示。它看起来是这样的：

```jsx
import { fromJS } from 'immutable';

// The state of the application is contained
// within an Immutable.js Map. Each key represents
// a "slice" of state.
export default fromJS({
  // The "App" state is the generic state that's
  // always visible. This state is not specific to
  // one particular feature, in other words. It has
  // the app title, and links to various article
  // sections.
  App: {
    title: 'Neckbeard News',
    links: [
      { name: 'All', url: '/' },
      { name: 'Local', url: '/local' },
      { name: 'Global', url: '/global' },
      { name: 'Tech', url: '/tech' },
      { name: 'Sports', url: '/sports' }
    ]
  },

  // The "Home" state is where lists of articles are
  // rendered. Initially, there are no articles, so
  // the "articles" list is empty until they're fetched
  // from the API.
  Home: {
    articles: []
  },

  // The "Article" state represents the full article. The
  // assumption is that the user has navigated to a full
  // article page and we need the entire article text here.
  Article: {
    full: ''
  }
}); 
```

该模块导出一个`Immutable.js Map`实例。稍后您会明白原因。但现在，让我们看看这个状态的组织。在 Redux 中，您通过切片来划分应用程序状态。在这种情况下，这是一个简单的应用程序，因此存储只有三个状态切片。每个状态切片都映射到一个主要的应用程序功能。

例如，`Home`键表示应用程序的`Home`组件使用的状态。初始化任何状态都很重要，即使它是一个空对象或数组，这样您的组件就有了初始属性。现在让我们使用一些 Redux 函数来创建一个用于向您的 React 组件获取数据的存储。

# 创建存储

初始状态在应用程序首次启动时很有用。这足以呈现组件，但仅此而已。一旦用户开始与 UI 交互，您需要一种改变存储状态的方法。在 Redux 中，您为存储中的每个状态切片分配一个减速器函数。因此，例如，您的应用程序将有一个`Home`减速器，一个`App`减速器和一个`Article`减速器。

Redux 中减速器的关键概念是它是纯净的，没有副作用。这就是在状态中使用`Immutable.js`结构有用的地方。让我们看看如何将初始状态与最终改变我们存储状态的减速器函数联系起来：

```jsx
import { createStore } from 'redux';
import { combineReducers } from 'redux-immutable';

// So build a Redux store, we need the "initialState"
// and all of our reducer functions that return
// new state.
import initialState from './initialState';
import App from './App';
import Home from './Home';
import Article from './Article';

// The "createStore()" and "combineReducers()" functions
// perform all of the heavy-lifting.
export default createStore(
  combineReducers({
    App,
    Home,
    Article
  }),
  initialState
); 
```

`App`，`Home`和`Article`函数的命名方式与它们操作的状态片段完全相同。随着应用程序的增长，这使得添加新的状态和减速器函数变得更容易。

现在您有一个准备就绪的 Redux 存储。但您仍然没有将其连接到实际呈现状态的 React 组件。现在让我们看看如何做到这一点。

# 存储提供程序和路由

Redux 有一个`Provider`组件（技术上，它是`react-redux`包提供的），用于包装应用程序的顶级组件。这将确保 Redux 存储数据对应用程序中的每个组件都可用。

在您正在开发的潮流新闻阅读器应用中，您将使用`Provider`组件将`Router`组件包装起来。然后，在构建组件时，您知道存储数据将可用。以下是`Root`组件的外观：

```jsx
import React from 'react';
import { Provider } from 'react-redux';

import store from '../store';
import App from './App';

export default () => (
  <Provider store={store}>
    <App />
  </Provider>
);
```

通过将初始状态与减速器函数组合来创建的存储器被传递给`<Provider>`。这意味着，当你的减速器导致 Redux 存储器改变时，存储器数据会自动传递给每个应用程序组件。接下来我们将看一下`App`组件。

# App 组件

`App`组件包括页面标题和各种文章分类的链接列表。当用户在用户界面中移动时，`App`组件总是被渲染，但每个`<Route>`元素根据当前路由渲染不同的内容。让我们来看一下这个组件，然后我们将分解它的工作原理：

```jsx
import React from 'react';
import {
  BrowserRouter as Router,
  Route,
  NavLink
} from 'react-router-dom';
import { connect } from 'react-redux';

// Components that render application state.
import Home from './Home';
import Article from './Article';

// Higher order component for making the
// various article section components out of
// the "Home" component. The only difference
// is the "filter" property. Having unique JSX
// element names is easier to read than a bunch
// of different property values.
const articleList = filter => props => (
  <Home {...props} filter={filter} />
);

const categoryListStyle = {
  listStyle: 'none',
  margin: 0,
  padding: 0,
  display: 'flex'
};

const categoryItemStyle = {
  padding: '5px'
};

const Local = articleList('local');
const Global = articleList('global');
const Tech = articleList('tech');
const Sports = articleList('sports');

// Routes to the home page, the different
// article sections, and the article details page.
// The "<Provider>" element is how we pass Redux
// store data to each of our components.
export default connect(state => state.get('App').toJS())(
  ({ title, links }) => (
    <Router>
      <main>
        <h1>{title}</h1>
        <ul style={categoryListStyle}>
          {/* Renders a link for each article category.
             The key thing to note is that the "links"
             value comes from a Redux store. */}
          {links.map(l => (
            <li key={l.url} style={categoryItemStyle}>
              <NavLink
                exact
                to={l.url}
                activeStyle={{ fontWeight: 'bold' }}
              >
                {l.name}
              </NavLink>
            </li>
          ))}
        </ul>
        <section>
          <Route exact path="/" component={Home} />
          <Route exact path="/local" component={Local} />
          <Route exact path="/global" component={Global} />
          <Route exact path="/tech" component={Tech} />
          <Route exact path="/sports" component={Sports} />
          <Route exact path="/articles/:id" component={Article} />
        </section>
      </main>
    </Router>
  )
);

```

这个组件需要一个`title`属性和一个`links`属性。这两个值实际上都是来自 Redux 存储器的状态。请注意，它导出了一个使用`connect()`函数创建的高阶组件。这个函数接受一个回调函数，将存储器状态转换为组件需要的属性。

在这个例子中，你需要`App`状态。使用`toJS()`方法将这个映射转换为普通的 JavaScript 对象。这就是 Redux 状态传递给组件的方式。下面是`App`组件的渲染内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/85d4cac5-eed4-49e3-a5d2-3886db1b8c91.png)

暂时忽略这些惊人的文章标题；我们稍后会回到这些。标题和分类链接是由`App`组件渲染的。文章标题是由`<Route>`元素之一渲染的。

注意所有分类都是粗体吗？这是因为它是当前选定的分类。如果选择了本地分类，所有文本将恢复为常规字体，而本地文本将加粗。这一切都是通过 Redux 状态控制的。现在让我们来看一下`App`减速器函数：

```jsx
import { fromJS } from 'immutable';
import initialState from './initialState';

// The initial page heading.
const title = initialState.getIn(['App', 'title']);

// Links to display when an article is displayed.
const articleLinks = fromJS([
  {
    name: 'Home',
    url: '/'
  }
]);

// Links to display when we're on the home page.
const homeLinks = initialState.getIn(['App', 'links']);

// Maps the action type to a function
// that returns new state.
const typeMap = fromJS({
  // The article is being fetched, adjust
  // the "title" and "links" state.
  FETCHING_ARTICLE: state =>
    state.set('title', '...').set('links', articleLinks),

  // The article has been fetched. Set the title
  // of the article.
  FETCH_ARTICLE: (state, payload) =>
    state.set('title', payload.title),

  // The list of articles are being fetched. Set
  // the "title" and the "links".
  FETCHING_ARTICLES: state =>
    state.set('title', title).set('links', homeLinks),

  // The articles have been fetched, update the
  // "title" state.
  FETCH_ARTICLES: state => state.set('title', title)
});

// This reducer relies on the "typeMap" and the
// "type" of action that was dispatched. If it's
// not found, then the state is simply returned.
export default (state, { type, payload }) =>
  typeMap.get(type, () => state)(state, payload); 
```

关于这个减速器逻辑，我想提出两点。首先，你现在可以看到，使用不可变数据结构使得这段代码简洁易懂。其次，对于简单的操作，这里发生了很多状态处理。例如，以`FETCHING_ARTICLE`和`FETCHING_ARTICLES`操作为例。在实际发出网络请求之前，你希望改变 UI。我认为这种明确性是 Flux 和 Redux 的真正价值。你知道为什么某些东西会改变。它是明确的，但不啰嗦。

# 主页组件

Redux 架构中缺少的最后一个重要部分是动作创建函数。这些函数由组件调用，以便向 Redux 存储发送有效负载。调度任何操作的最终结果是状态的改变。然而，有些操作需要去获取状态，然后才能作为有效负载调度到存储中。

让我们来看看`Neckbeard News`应用程序的`Home`组件。它将向您展示如何在将组件连接到 Redux 存储时传递动作创建函数。以下是代码：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Link } from 'react-router-dom';
import { Map } from 'immutable';

// Various styles...
const listStyle = {
  listStyle: 'none',
  margin: 0,
  padding: 0
};

const listItemStyle = {
  margin: '0 5px'
};

const titleStyle = {
  background: 'transparent',
  border: 'none',
  font: 'inherit',
  cursor: 'pointer',
  padding: '5px 0'
};

// What to render when the article list is empty
// (true/false). When it's empty, a single elipses
// is displayed.
const emptyMap = Map()
  .set(true, <li style={listItemStyle}>...</li>)
  .set(false, null);

class Home extends Component {
  static propTypes = {
    articles: PropTypes.arrayOf(PropTypes.object).isRequired,
    fetchingArticles: PropTypes.func.isRequired,
    fetchArticles: PropTypes.func.isRequired,
    toggleArticle: PropTypes.func.isRequired,
    filter: PropTypes.string.isRequired
  };

  static defaultProps = {
    filter: ''
  };

  // When the component is mounted, there's two actions
  // to dispatch. First, we want to tell the world that
  // we're fetching articles before they're actually
  // fetched. Then, we call "fetchArticles()" to perform
  // the API call.
  componentWillMount() {
    this.props.fetchingArticles();
    this.props.fetchArticles(this.props.filter);
  }

  // When an article title is clicked, toggle the state of
  // the article by dispatching the toggle article action.
  onTitleClick = id => () => this.props.toggleArticle(id);

  render() {
    const { onTitleClick } = this;
    const { articles } = this.props;

    return (
      <ul style={listStyle}>
        {emptyMap.get(articles.length === 0)}
        {articles.map(a => (
          <li key={a.id} style={listItemStyle}>
            <button onClick={onTitleClick(a.id)} style={titleStyle}>
              {a.title}
            </button>
            {/* The summary of the article is displayed
                 based on the "display" property. This state
                 is toggled when the user clicks the title. */}
            <p style={{ display: a.display }}>
              <small>
                <span>{a.summary} </span>
                <Link to={`articles/${a.id}`}>More...</Link>
              </small>
            </p>
          </li>
        ))}
      </ul>
    );
  }
}

// The "connect()" function connects this component
// to the Redux store. It accepts two functions as
// arguments...
export default connect(
  // Maps the immutable "state" object to a JavaScript
  // object. The "ownProps" are plain JSX props that
  // are merged into Redux store data.
  (state, ownProps) =>
    Object.assign(state.get('Home').toJS(), ownProps),

  // Sets the action creator functions as props. The
  // "dispatch()" function is when actually invokes
  // store reducer functions that change the state
  // of the store, and cause new prop values to be passed
  // to this component.
  dispatch => ({
    fetchingArticles: () =>
      dispatch({
        type: 'FETCHING_ARTICLES'
      }),

    fetchArticles: filter => {
      const headers = new Headers();
      headers.append('Accept', 'application/json');

      fetch(`/api/articles/${filter}`, { headers })
        .then(resp => resp.json())
        .then(json =>
          dispatch({
            type: 'FETCH_ARTICLES',
            payload: json
          })
        );
    },

    toggleArticle: payload =>
      dispatch({
        type: 'TOGGLE_ARTICLE',
        payload
      })
  })
)(Home); 
```

让我们专注于`connect()`函数，它用于将`Home`组件连接到存储。第一个参数是一个函数，它从存储中获取相关状态，并将其作为此组件的`props`返回。它使用`ownProps`，这样您就可以直接将`props`传递给组件，并覆盖存储中的任何内容。`filter`属性是我们需要这种能力的原因。

第二个参数是一个函数，它将动作创建函数作为`props`返回。`dispatch()`函数是这些动作创建函数能够向存储传递有效负载的方式。例如，`toggleArticle()`函数直接调用了`dispatch()`，并且是响应用户点击文章标题时调用的。然而，`fetchingArticles()`调用涉及异步行为。这意味着直到`fetch()`承诺解决之前，`dispatch()`才会被调用。您需要确保在此期间不会发生意外情况。

让我们通过查看与`Home`组件一起使用的 reducer 函数来结束这些内容：

```jsx
import { fromJS } from 'immutable';

const typeMap = fromJS({
  // Clear any old articles right before
  // we fetch new articles.
  FETCHING_ARTICLES: state =>
    state.update('articles', a => a.clear()),

  // Articles have been fetched. Update the
  // "articles" state, and make sure that the
  // summary display is "none".
  FETCH_ARTICLES: (state, payload) =>
    state.set(
      'articles',
      fromJS(payload)
        .map(a => a.set('display', 'none'))
    ),

  // Toggles the state of the selected article
  // "id". First we have to find the index of
  // the article so that we can update it's
  // "display" state. If it's already hidden,
  // we show it, and vice-versa.
  TOGGLE_ARTICLE: (state, id) =>
    state.updateIn([
      'articles',
      state
        .get('articles')
        .findIndex(a => a.get('id') === id),
      'display',
    ], display =>
      display === 'none' ?
        'block' : 'none'
    ),
});

export default (state, { type, payload }) =>
  typeMap.get(type, s => s)(state, payload); 
```

在这里也使用了使用类型映射根据操作类型改变状态的相同技术。再次强调，这段代码易于理解，但系统中可以发生变化的所有内容都是明确的。

# 移动应用中的状态

在 React Native 移动应用中使用 Redux 怎么样？当然应该，如果您正在为 Web 和原生平台开发相同的应用程序。事实上，我已经在 React Native 中为 iOS 和 Android 都实现了`Neckbeard News`。我鼓励您下载本书的代码，并让这个应用程序在 Web 和原生移动设备上运行。

在移动应用中，实际上使用 Redux 并没有什么不同。唯一的区别在于所使用的状态的形状。换句话说，不要认为你可以在网页和原生应用的版本中使用完全相同的 Redux 存储和减速器函数。想想 React Native 组件。许多事情并没有一种大小适合所有的组件。你有一些组件针对 iOS 平台进行了优化，而其他一些则针对 Android 平台进行了优化。Redux 状态也是同样的道理。以下是移动应用`Neckbeard News`的初始状态：

```jsx
import { fromJS } from 'immutable';

export default fromJS({
  Main: {
    title: 'All',
    component: 'articles',
  },
  Categories: {
    items: [
      {
        title: 'All',
        filter: '',
        selected: true,
      },
      {
        title: 'Local',
        filter: 'local',
        selected: false,
      },
      {
        title: 'Global',
        filter: 'global',
        selected: false,
      },
      {
        title: 'Tech',
        filter: 'tech',
        selected: false,
      },
      {
        title: 'Sports',
        filter: 'sports',
        selected: false,
      },
    ],
  },
  Articles: {
    filter: '',
    items: [],
  },
  Article: {
    full: '',
  },
}); 
```

正如你所看到的，适用于 Web 环境的相同原则在移动环境中同样适用。只是状态本身不同，以支持我们使用的特定组件以及你使用它们实现应用程序的独特方式。

# 架构的扩展

到目前为止，你可能已经对 Flux 的概念、Redux 的机制以及它们如何用于实现 React 应用程序的健全信息架构有了很好的掌握。那么问题就变成了，这种方法有多可持续，它能否处理任意大型和复杂的应用程序？

我认为 Redux 是实现大规模 React 应用程序的好方法。你可以预测任何给定操作的结果，因为一切都是明确的。它是声明式的。它是单向的，没有副作用。但它并非没有挑战。

Redux 的限制因素也是它的核心；因为一切都是明确的，需要扩展功能数量和复杂性的应用程序最终会有更多的移动部分。这并没有什么错；这只是游戏的本质。扩展的不可避免后果是减速。你简单地无法把握足够的全局图景来快速实现事情。

在本书的最后两章中，我们将研究与 Flux 相关但不同的方法：Relay/GraphQL。我认为这种技术可以以 Redux 无法做到的方式扩展。

# 总结

在本章中，你了解了 Flux，一组有助于构建 React 应用程序信息架构的架构模式。Flux 的关键思想包括单向数据流、同步更新轮和可预测的状态转换。

接下来，我将详细介绍 Redux / React 应用程序的实现。Redux 提供了 Flux 思想的简化实现。好处是无论何时都能预测。

然后，您将了解 Redux 是否具备构建可扩展架构的 React 应用程序所需的条件。答案大多数情况下是肯定的。然而，在本书的其余部分，您将探索 Relay 和 GraphQL，以查看这些技术是否能将您的应用程序提升到下一个水平。

# 测试你的知识

1.  以下哪种最能描述 Flux？

1.  Flux 是一种用于增强 DOM 元素属性的架构模式，使得更容易将 API 数据传入 HTML 中。

1.  Flux 是一种用于控制应用程序中数据单向流动的架构模式，使变化更加可预测。

1.  Flux 是一个处理应用程序状态的库。

1.  Flux 和 Redux 之间有什么区别？

1.  没有区别，它们都代表相同的架构模式。

1.  Flux 是处理 React 组件状态的官方方式，而 Redux 是要避免的东西。

1.  Redux 是 Flux 概念的一种有主见的实现，可以帮助管理应用程序中的数据流。

1.  如何将数据从 Redux 存储库传递到组件？

1.  您可以使用`connect()`高阶函数将组件连接到存储库，使用将存储库数据转换为组件属性的函数。

1.  您可以扩展`Redux.Component`以自动在组件上设置来自 Redux 存储库的状态。

1.  您可以随时从全局`store`对象访问状态。

1.  Redux 在 Web 应用程序和原生移动应用程序之间有什么区别？

1.  有一个特定的`redux-react-native`包，你应该使用它。

1.  没有区别。

# 进一步阅读

欲了解更多信息，请查看以下链接：

+   [`redux.js.org/`](https://redux.js.org/)

+   [`facebook.github.io/flux/`](https://facebook.github.io/flux/)
