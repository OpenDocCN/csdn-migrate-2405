# React 和 ReactNative 第二版（五）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：显示进度

本章主要讨论向用户传达进度的问题。React Native 有不同的组件来处理您想要传达的不同类型的进度。首先，您将学习为什么首先需要这样传达进度。然后，您将学习如何实现进度指示器和进度条。之后，您将看到具体的示例，向您展示如何在数据加载时使用进度指示器与导航，以及如何使用进度条来传达一系列步骤中的当前位置。

# 进度和可用性

想象一下，您有一台没有窗户也不发出声音的微波炉。与它互动的唯一方式是按下标有“烹饪”的按钮。尽管这个设备听起来很荒谬，但许多软件用户面临的情况就是如此——没有进度的指示。微波炉在烹饪什么？如果是的话，我们如何知道什么时候会完成？

改善微波炉情况的一种方法是添加声音。这样，用户在按下烹饪按钮后会得到反馈。您已经克服了一个障碍，但用户仍然在猜测——我的食物在哪里？在您破产之前，最好添加某种进度测量显示，比如一个计时器。

并不是 UI 程序员不理解这种可用性问题的基本原则；只是我们有事情要做，这种事情在优先级方面往往被忽略。在 React Native 中，有一些组件可以向用户提供不确定的进度反馈，也可以提供精确的进度测量。如果您想要良好的用户体验，将这些事情作为首要任务总是一个好主意。

# 指示进度

在本节中，您将学习如何使用`ActivityIndicator`组件。顾名思义，当您需要向用户指示发生了某事时，您会渲染此组件。实际进度可能是不确定的，但至少您有一种标准化的方式来显示发生了某事，尽管尚无结果可显示。

让我们创建一个示例，这样你就可以看到这个组件是什么样子的。这里是`App`组件：

```jsx
import React from 'react';
import { View, ActivityIndicator } from 'react-native';

import styles from './styles';

// Renders an "<ActivityIndicator>" component in the
// middle of the screen. It will animate on it's own
// while displayed.
export default () => (
  <View style={styles.container}>
    <ActivityIndicator size="large" />
  </View>
); 
```

`<ActivityIndicator>`组件是跨平台的。在 iOS 上它是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/8030d118-69a1-47ed-853a-6a7124769ee9.png)

它在屏幕中间渲染一个动画旋转器。这是大旋转器，如`size`属性中指定的那样。`ActivityIndicator`旋转器也可以很小，如果你将其渲染在另一个较小的元素内，这更有意义。现在让我们看看这在 Android 设备上是什么样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/afc16e23-452a-47f7-be38-f8f2d646acd8.png)

旋转器看起来不同，这是应该的，但你的应用在两个平台上传达的是同样的事情——你在等待某些东西。

这个例子只是永远旋转。别担心，接下来会有一个更现实的进度指示器示例，向你展示如何处理导航和加载 API 数据。

# 测量进度

指示正在取得进展的缺点是用户看不到尽头。这会导致一种不安的感觉，就像在没有定时器的微波炉中等待食物一样。当你知道已经取得了多少进展，还有多少要做时，你会感觉更好。这就是为什么尽可能使用确定性进度条总是更好的原因。

与`ActivityIndicator`组件不同，React Native 中没有用于进度条的跨平台组件。因此，我们必须自己制作一个。我们将创建一个组件，在 iOS 上使用`ProgressViewIOS`，在 Android 上使用`ProgressBarAndroid`。

首先处理跨平台问题。React Native 知道根据文件扩展名导入正确的模块。下面是`ProgressBarComponent.ios.js`模块的样子：

```jsx
// Exports the "ProgressViewIOS" as the 
// "ProgressBarComponent" component that 
// our "ProgressBar" expects. 
export { 
  ProgressViewIOS as ProgressBarComponent, 
} from 'react-native'; 

// There are no custom properties needed. 
export const progressProps = {}; 
```

你直接从 React Native 中导出了`ProgressViewIOS`组件。你还导出了特定于平台的组件属性。在这种情况下，它是一个空对象，因为没有特定于`<ProgressViewIOS>`的属性。现在，让我们看看`ProgressBarComponent.android.js`模块：

```jsx
// Exports the "ProgressBarAndroid" component as 
// "ProgressBarComponent" that our "ProgressBar" 
// expects. 
export { 
  ProgressBarAndroid as ProgressBarComponent, 
} from 'react-native'; 

// The "styleAttr" and "indeterminate" props are 
// necessary to make "ProgressBarAndroid" look like 
// "ProgressViewIOS". 
export const progressProps = { 
  styleAttr: 'Horizontal', 
  indeterminate: false, 
}; 
```

这个模块使用与`ProgressBarComponent.ios.js`模块完全相同的方法。它导出了特定于 Android 的组件以及传递给它的特定于 Android 的属性。现在，让我们构建应用程序将使用的`ProgressBar`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Text } from 'react-native';

// Imports the "ProgressBarComponent" which is the
// actual react-native implementation. The actual
// component that's imported is platform-specific.
// The custom props in "progressProps" is also
// platform-specific.
import {
  ProgressBarComponent,
  progressProps
} from './ProgressBarComponent';

import styles from './styles';

// The "ProgressLabel" component determines what to
// render as a label, based on the boolean "label"
// prop. If true, then we render some text that shows
// the progress percentage. If false, we render nothing.
const ProgressLabel = ({ show, progress }) =>
  show && (
    <Text style={styles.progressText}>
      {Math.round(progress * 100)}%
    </Text>
  );

// Our generic progress bar component...
const ProgressBar = ({ progress, label }) => (
  <View style={styles.progress}>
    <ProgressLabel show={label} progress={progress} />
    {/* "<ProgressBarComponent>" is really a ""<ProgressViewIOS>"
         or a "<ProgressBarAndroid>". */}
    <ProgressBarComponent
      {...progressProps}
      style={styles.progress}
      progress={progress}
    />
  </View>
);

ProgressBar.propTypes = {
  progress: PropTypes.number.isRequired,
  label: PropTypes.bool.isRequired
};

ProgressBar.defaultProps = {
  progress: 0,
  label: true
};

export default ProgressBar; 
```

让我们逐步了解这个模块中发生了什么，从导入开始。`ProgressBarComponent`和`progressProps`的值是从我们的`ProgressBarComponent`模块中导入的。React Native 确定从哪个模块导入这些值。

接下来，你有`ProgressLabel`实用组件。它根据`show`属性决定为进度条呈现什么标签。如果是`false`，则不呈现任何内容。如果是`true`，它会呈现一个显示进度的`<Text>`组件。

最后，你有`ProgressBar`组件本身，当我们的应用程序导入和使用。这将呈现标签和适当的进度条组件。它接受一个`progress`属性，这是一个介于`0`和`1`之间的值。现在让我们在`App`组件中使用这个组件：

```jsx
import React, { Component } from 'react';
import { View } from 'react-native';

import styles from './styles';
import ProgressBar from './ProgressBar';

export default class MeasuringProgress extends Component {
  // Initially at 0% progress. Changing this state
  // updates the progress bar.
  state = {
    progress: 0
  };

  componentDidMount() {
    // Continuously increments the "progress" state
    // every 300MS, until we're at 100%.
    const updateProgress = () => {
      this.setState({
        progress: this.state.progress + 0.01
      });

      if (this.state.progress < 1) {
        setTimeout(updateProgress, 300);
      }
    };

    updateProgress();
  }

  render() {
    return (
      <View style={styles.container}>
        {/* This is awesome. A simple generic
             "<ProgressBar>" component that works
             on Android and on iOS. */}
        <ProgressBar progress={this.state.progress} />
      </View>
    );
  }
} 
```

最初，`<ProgressBar>`组件以 0%的进度呈现。在`componentDidMount()`方法中，`updateProgress()`函数使用定时器模拟一个真实的进程，你想要显示进度。这是 iOS 屏幕的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/43a111b5-2eca-44c8-9c6f-e931c23859ea.png)

这是相同的进度条在 Android 上的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/ec0a7014-f585-40d4-ab79-b2351815ca52.png)

# 导航指示器

在本章的前面，你已经了解了`ActivityIndicator`组件。在本节中，你将学习在导航加载数据的应用程序中如何使用它。例如，用户从页面（屏幕）一导航到页面二。然而，页面二需要从 API 获取数据来显示给用户。因此，在进行这个网络调用时，显示进度指示器而不是一个缺乏有用信息的屏幕更有意义。

这样做实际上有点棘手，因为你必须确保屏幕所需的数据在用户每次导航到屏幕时都从 API 获取。你的目标应该是以下几点：

+   使`Navigator`组件自动为即将呈现的场景获取 API 数据。

+   使用 API 调用返回的 promise 来显示旋转器，并在 promise 解析后隐藏它。

由于你的组件可能不关心是否显示旋转器，让我们将其实现为一个通用的高阶组件：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { View, ActivityIndicator } from 'react-native';

import styles from './styles';

// Wraps the "Wrapped" component with a stateful component
// that renders an "<ActivityIndicator>" when the "loading"
// state is true.
const loading = Wrapped =>
  class LoadingWrapper extends Component {
    static propTypes = {
      promise: PropTypes.instanceOf(Promise)
    };

    state = {
      loading: true
    };

    // Adds a callback to the "promise" that was
    // passed in. When the promise resolves, we set
    // the "loading" state to false.
    componentDidMount() {
      this.props.promise.then(
        () => this.setState({ loading: false }),
        () => this.setState({ loading: false })
      );
    }

    // If "loading" is true, render the "<ActivityIndicator>"
    // component. Otherwise, render the "<Wrapped>" component.
    render() {
      return new Map([
        [
          true,
          <View style={styles.container}>
            <ActivityIndicator size="large" />
          </View>
        ],
        [false, <Wrapped {...this.props} />]
      ]).get(this.state.loading);
    }
  };

export default loading; 
```

这个`loading()`函数接受一个组件——`Wrapped`参数，并返回一个`LoadingWrapper`组件。返回的包装器接受一个`promise`属性，当它解析或拒绝时，它会将`loading`状态更改为`false`。正如你在`render()`方法中所看到的，`loading`状态决定了是呈现旋转器还是`Wrapped`组件。

有了`loading()`高阶函数，让我们来看看您将与`react-navigation`一起使用的第一个屏幕组件：

```jsx
import React from 'react';
import { View, Text } from 'react-native';

import styles from './styles';
import loading from './loading';

const First = loading(({ navigation }) => (
  <View style={styles.container}>
    <Text
      style={styles.item}
      onPress={() => navigation.navigate('Second')}
    >
      Second
    </Text>
    <Text
      style={styles.item}
      onPress={() => navigation.navigate('Third')}
    >
      Third
    </Text>
  </View>
));

export default First; 
```

该模块导出了一个组件，该组件使用之前创建的`loading()`函数进行包装。它包装了`First`组件，以便在`promise`属性挂起时显示旋转器。最后一步是在用户导航到给定页面时将该 promise 传递到组件中。这发生在`App`组件中的路由配置中：

```jsx
import React from 'react';
import { createStackNavigator } from 'react-navigation';

import First from './First';
import Second from './Second';
import Third from './Third';

export default createStackNavigator(
  {
    First: {
      screen: props => (
        <First
          promise={new Promise(resolve => setTimeout(resolve, 1000))}
          {...props}
        />
      )
    },
    Second: {
      screen: props => (
        <Second
          promise={new Promise(resolve => setTimeout(resolve, 1000))}
          {...props}
        />
      )
    },
    Third: {
      screen: props => (
        <First
          promise={new Promise(resolve => setTimeout(resolve, 1000))}
          {...props}
        />
      )
    }
  },
  { initialRouteName: 'First' }
); 
```

您不是直接将屏幕组件传递给`createStackNavigator()`的路由配置参数，而是为每个屏幕传递一个对象。`screen`属性允许您提供要渲染的实际屏幕组件。在这种情况下，通过调用解析组件所需数据的 API 函数来传递`promise`属性。这就是`loading()`函数能够在等待 promise 解析时显示旋转器的方式。第一个屏幕不必担心显示加载屏幕。

# 步骤进度

在这个最后的例子中，您将构建一个应用程序，该应用程序显示用户在预定义步骤中的进度。例如，将表单分成几个逻辑部分，并以用户完成一个部分后移动到下一步的方式组织它们可能是有意义的。进度条对用户来说将是有用的反馈。

您将在导航栏中插入一个进度条，就在标题下方，以便用户知道他们已经走了多远，还有多远要走。您还将重用在本章中早些时候实现的`ProgressBar`组件。

让我们先看一下结果。这个应用程序中有四个屏幕，用户可以导航到其中。以下是第一页（场景）的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/28469123-c5dc-4323-a57b-74d385d63093.png)

标题下方的进度条反映了用户在导航中已经完成了 25%。让我们看看第三个屏幕是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/4df4b66f-8144-4f5f-b445-0c64f978fe74.png)

进度已更新，以反映用户在路由堆栈中的位置。让我们来看看`App`组件：

```jsx
import React from 'react';
import { createStackNavigator } from 'react-navigation';

import First from './First';
import Second from './Second';
import Third from './Third';
import Fourth from './Fourth';

const routes = [First, Second, Third, Fourth];

export default createStackNavigator(
  routes.reduce(
    (result, route) => ({
      ...result,
      [route.name]: route
    }),
    {}
  ),
  {
    initialRouteName: 'First',
    initialRouteParams: {
      progress: route =>
        (routes.map(r => r.name).indexOf(route) + 1) / routes.length
    }
  }
);

```

这个应用程序有四个屏幕。渲染每个屏幕的组件存储在`routes`常量中，然后使用`createStackNavigator()`配置堆栈导航器。创建`routes`数组的原因是为了让它可以被传递给初始路由(`First`)作为路由参数的`progress()`函数使用。这个函数以当前路由名称作为参数，并查找它在 routes 中的索引位置。例如，`Second`在数字`2`的位置（索引为 1 + 1），数组的长度为`4`。这将把进度条设置为 50%。

让我们看看`First`组件如何使用`progress`函数：

```jsx
import React from 'react';
import { View, Text } from 'react-native';

import styles from './styles';
import ProgressBar from './ProgressBar';

const First = () => (
  <View style={styles.container}>
    <Text style={styles.content}>First Content</Text>
  </View>
);

First.navigationOptions = ({ navigation }) => ({
  headerTitle: (
    <View style={styles.progress}>
      <Text style={styles.title}>First</Text>
      <ProgressBar
        label={false}
        progress={navigation.state.params.progress(
          navigation.state.routeName
        )}
      />
    </View>
  ),
  headerLeft: (
    <Text
      onPress={() =>
        navigation.navigate('Fourth', navigation.state.params)
      }
    >
      Fourth
    </Text>
  ),
  headerRight: (
    <Text
      onPress={() =>
        navigation.navigate('Second', navigation.state.params)
      }
    >
      Second
    </Text>
  )
});

export default First;
```

该函数可以通过`navigation.state.params.progress()`访问。它将`navigation.state.routeName`的值传递给当前页面的进度值。此外，对`navigation.navigate()`的调用必须传递`navigation.state.params`，以便`progress()`函数对屏幕可用。如果不这样做，那么`progress()`将只对第一个屏幕可用，因为它是在`App`组件中使用`initialRouteParams`选项设置的。

# 总结

在本章中，您学习了如何向用户显示一些在幕后发生的事情。首先，我们讨论了为什么显示进度对应用程序的可用性很重要。然后，您实现了一个基本的屏幕，指示进度正在进行。然后，您实现了一个`ProgressBar`组件，用于测量特定的进度量。

指示器适用于不确定的进度，并且您实现了导航，显示了在网络调用挂起时显示进度指示器。在最后一节中，您实现了一个进度条，向用户显示他们在预定义步骤中的位置。

在下一章中，您将看到 React Native 地图和地理位置数据的实际应用。

# 测试你的知识

1.  进度条和活动指示器有什么区别？

1.  进度条是确定的，而进度指示器用于指示不确定的时间量。

1.  没有区别。进度条和进度指示器实际上是相同的东西。

1.  进度条渲染一个水平条，其他所有的都被视为进度指示器。

1.  React Native 的`ActivityIndicator`组件在 iOS 和 Android 上是否工作相同？

1.  不，这个组件不是平台无关的。

1.  是的，这个组件是平台无关的。

1.  如何以平台不可知的方式使用`ProgressViewIOS`和`ProgressBarAndroid`组件？

1.  您可以定义自己的`ProgressBar`组件，导入具有特定于平台的文件扩展名的其他组件。

1.  你不能；你必须在想要使用进度条的每个地方实现平台检查逻辑。

# 进一步阅读

查看以下链接获取更多信息：

+   [`facebook.github.io/react-native/docs/activityindicator`](https://facebook.github.io/react-native/docs/activityindicator)

+   [`facebook.github.io/react-native/docs/progressviewios`](https://facebook.github.io/react-native/docs/progressviewios)

+   [`facebook.github.io/react-native/docs/progressbarandroid`](https://facebook.github.io/react-native/docs/progressbarandroid)


# 第十八章：地理位置和地图

在本章中，您将学习 React Native 的地理位置和地图功能。您将开始学习如何使用地理位置 API；然后您将继续使用`MapView`组件来标记兴趣点和区域。

您将使用`react-native-maps`包来实现地图。本章的目标是介绍 React Native 中用于地理位置和 React Native Maps 中地图的功能。

# 我在哪里？

Web 应用程序用于确定用户位置的地理位置 API 也可以被 React Native 应用程序使用，因为相同的 API 已经进行了 polyfill。除了地图之外，此 API 对于从移动设备的 GPS 获取精确坐标非常有用。然后，您可以使用这些信息向用户显示有意义的位置数据。

不幸的是，地理位置 API 返回的数据本身用处不大；您的代码必须进行一些工作，将其转换为有用的东西。例如，纬度和经度对用户来说毫无意义，但您可以使用这些数据查找对用户有用的信息。这可能只是简单地显示用户当前所在位置。

让我们实现一个示例，使用 React Native 的地理位置 API 查找坐标，然后使用这些坐标从 Google Maps API 查找可读的位置信息：

```jsx
import React, { Component } from 'react';
import { Text, View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';

// For fetching human-readable address info.
const URL = 'https://maps.google.com/maps/api/geocode/json?latlng=';

export default class WhereAmI extends Component {
  // The "address" state is "loading..." initially because
  // it takes the longest to fetch.
  state = {
    data: fromJS({
      address: 'loading...'
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

  // We don't setup any geo data till the component
  // mounts.
  componentDidMount() {
    const setPosition = pos => {
      // This component renders the "coords" data from
      // a geolocation response. This can simply be merged
      // into the state map.
      this.data = this.data.merge(pos.coords);

      // We need the "latitude" and the "longitude"
      // in order to lookup the "address" from the
      // Google maps API.
      const {
        coords: { latitude, longitude }
      } = pos;

      // Fetches data from the Google Maps API then sets
      // the "address" state based on the response.
      fetch(`${URL}${latitude},${longitude}`)
        .then(resp => resp.json(), e => console.error(e))
        .then(({ results: [{ formatted_address }] }) => {
          this.data = this.data.set('address', formatted_address);
        });
    };

    // First, we try to lookup the current position
    // data and update the component state.
    navigator.geolocation.getCurrentPosition(setPosition);

    // Then, we setup a high accuracy watcher, that
    // issues a callback whenever the position changes.
    this.watcher = navigator.geolocation.watchPosition(
      setPosition,
      err => console.error(err),
      { enableHighAccuracy: true }
    );
  }

  // It's always a good idea to make sure that this
  // "watcher" is cleared when the component is removed.
  componentWillUnmount() {
    navigator.geolocation.clearWatch(this.watcher);
  }

  render() {
    // Since we want to iterate over the properties
    // in the state map, we need to convert the map
    // to pairs using "entries()". Then we need to
    // use the spread operator to make the map iterator
    // into a plain array. The "sort()" method simply
    // sorts the map based on it's keys.
    const state = [...this.data.sortBy((v, k) => k).entries()];

    // Iterates over the state properties and renders them.
    return (
      <View style={styles.container}>
        {state.map(([k, v]) => (
          <Text key={k} style={styles.label}>
            {`${k[0].toUpperCase()}${k.slice(1)}`}: {v}
          </Text>
        ))}
      </View>
    );
  }
} 
```

此组件的目标是在屏幕上呈现地理位置 API 返回的属性，并查找用户的特定位置并显示它。如果您查看`componentDidMount()`方法，您会发现这里有大部分有趣的代码。`setPosition()`函数在几个地方用作回调。它的工作是设置组件的状态。

首先，它设置了`coords`属性。通常，您不会直接显示这些数据，但这是一个示例，展示了地理位置 API 的可用数据。其次，它使用`latitude`和`longitude`值来查找用户当前所在位置的名称，使用 Google Maps API。

`setPosition()`回调函数与`getCurrentPosition()`一起使用，当组件挂载时只调用一次。您还在`watchPosition()`中使用`setPosition()`，它会在用户位置发生变化时调用回调函数。

iOS 模拟器和 Android Studio 允许您通过菜单选项更改位置。您不必每次想要测试更改位置时都在物理设备上安装您的应用程序。

让我们看看一旦位置数据加载后，这个屏幕是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/4c40c4e8-4e0b-4f0f-b5e5-ff18f58dbd79.png)

获取的地址信息在应用程序中可能比纬度和经度数据更有用。比物理地址文本更好的是在地图上可视化用户的物理位置；您将在下一节中学习如何做到这一点。

# 周围有什么？

`react-native-maps`中的`MapView`组件是您在 React Native 应用程序中渲染地图时将使用的主要工具。

让我们实现一个基本的`MapView`组件，看看您可以从中得到什么。

```jsx
import React from 'react';
import { View } from 'react-native';
import MapView from 'react-native-maps';

import styles from './styles';

export default () => (
  <View style={styles.container}>
    <MapView
      style={styles.mapView}
      showsUserLocation
      followUserLocation
    />
  </View>
); 
```

您传递给`MapView`的两个布尔属性为您做了很多工作。`showsUserLocation`属性将激活地图上的标记，表示运行此应用程序的设备的物理位置。`followUserLocation`属性告诉地图在设备移动时更新位置标记。让我们看看结果地图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/904b6956-4e7c-4939-96ea-ac5d62ab3341.png)

设备的当前位置在地图上清晰标记。默认情况下，地图上也会显示兴趣点。这些是用户附近的事物，让他们可以看到周围的环境。

通常情况下，当使用`showsUserLocation`时最好使用`followUserLocation`属性。这样地图就会缩放到用户所在的区域。

# 注释兴趣点

到目前为止，您已经看到`MapView`组件如何渲染用户当前位置和用户周围的兴趣点。这里的挑战是，您可能希望显示与您的应用程序相关的兴趣点，而不是默认渲染的兴趣点。

在这一部分，您将学习如何在地图上为特定位置渲染标记，以及渲染地图上的区域。

# 绘制点

让我们标记一些当地的啤酒厂！以下是如何将注释传递给`MapView`组件：

```jsx
import React from 'react';
import { View } from 'react-native';
import MapView from 'react-native-maps';

import styles from './styles';

export default () => (
  <View style={styles.container}>
    <MapView
      style={styles.mapView}
      showsPointsOfInterest={false}
      showsUserLocation
      followUserLocation
    >
      <MapView.Marker
        title="Duff Brewery"
        description="Duff beer for me, Duff beer for you"
        coordinate={{
          latitude: 43.8418728,
          longitude: -79.086082
        }}
      />
      <MapView.Marker
        title="Pawtucket Brewery"
        description="New! Patriot Light!"
        coordinate={{
          latitude: 43.8401328,
          longitude: -79.085407
        }}
      />
    </MapView>
  </View>
); 
```

注释就像它们听起来的那样；在基本地图地理信息的顶部呈现的额外信息。实际上，当您呈现`MapView`组件时，默认情况下会显示注释，因为它们会显示感兴趣的点。在这个例子中，您通过将`showsPointsOfInterest`属性设置为`false`来选择退出此功能。让我们看看这些啤酒厂的位置：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/27add99a-756f-4983-aab4-2d4e4832397e.png)

当您按下显示地图上啤酒厂位置的标记时，会显示标注。您给`<MapView.Marker>`的`title`和`description`属性值用于呈现此文本。

# 绘制叠加层

在本章的最后一节中，您将学习如何渲染区域叠加层。一个点是一个单一的纬度/经度坐标。将区域视为几个坐标的连线图。区域可以有很多用途，比如显示我们更可能找到 IPA 饮酒者与 stout 饮酒者的地方。代码如下所示：

```jsx
import React, { Component } from 'react';
import { View, Text } from 'react-native';
import MapView from 'react-native-maps';
import { fromJS } from 'immutable';

import styles from './styles';

// The "IPA" region coordinates and color...
const ipaRegion = {
  coordinates: [
    { latitude: 43.8486744, longitude: -79.0695283 },
    { latitude: 43.8537168, longitude: -79.0700046 },
    { latitude: 43.8518394, longitude: -79.0725697 },
    { latitude: 43.8481651, longitude: -79.0716377 },
    { latitude: 43.8486744, longitude: -79.0695283 }
  ],
  strokeColor: 'coral',
  strokeWidth: 4
};

// The "stout" region coordinates and color...
const stoutRegion = {
  coordinates: [
    { latitude: 43.8486744, longitude: -79.0693283 },
    { latitude: 43.8517168, longitude: -79.0710046 },
    { latitude: 43.8518394, longitude: -79.0715697 },
    { latitude: 43.8491651, longitude: -79.0716377 },
    { latitude: 43.8486744, longitude: -79.0693283 }
  ],
  strokeColor: 'firebrick',
  strokeWidth: 4
};

export default class PlottingOverlays extends Component {
  // The "IPA" region is rendered first. So the "ipaStyles"
  // list has "boldText" in it, to show it as selected. The
  // "overlays" list has the "ipaRegion" in it.
  state = {
    data: fromJS({
      ipaStyles: [styles.ipaText, styles.boldText],
      stoutStyles: [styles.stoutText],
      overlays: [ipaRegion]
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

  // The "IPA" text was clicked...
  onClickIpa = () => {
    this.data = this.data
      // Makes the IPA text bold...
      .update('ipaStyles', i => i.push(styles.boldText))
      // Removes the bold from the stout text...
      .update('stoutStyles', i => i.pop())
      // Replaces the stout overlay with the IPA overlay...
      .update('overlays', i => i.set(0, ipaRegion));
  };

  // The "stout" text was clicked...
  onClickStout = () => {
    this.data = this.data
      // Makes the stout text bold...
      .update('stoutStyles', i => i.push(styles.boldText))
      // Removes the bold from the IPA text...
      .update('ipaStyles', i => i.pop())
      // Replaces the IPA overlay with the stout overlay...
      .update('overlays', i => i.set(0, stoutRegion));
  };

  render() {
    const { ipaStyles, stoutStyles, overlays } = this.data.toJS();

    return (
      <View style={styles.container}>
        <View>
          {/* Text that when clicked, renders the IPA
               map overlay. */}
          <Text style={ipaStyles} onPress={this.onClickIpa}>
            IPA Fans
          </Text>

          {/* Text that when clicked, renders the stout
               map overlay. */}
          <Text style={stoutStyles} onPress={this.onClickStout}>
            Stout Fans
          </Text>
        </View>

        {/* Renders the map with the "overlays" array. There
             will only ever be a single overlay in this
             array. */}
        <MapView
          style={styles.mapView}
          showsPointsOfInterest={false}
          showsUserLocation
          followUserLocation
        >
          {overlays.map((v, i) => (
            <MapView.Polygon
              key={i}
              coordinates={v.coordinates}
              strokeColor={v.strokeColor}
              strokeWidth={v.strokeWidth}
            />
          ))}
        </MapView>
      </View>
    );
  }
} 
```

区域数据由几个纬度/经度坐标组成，定义了区域的形状和位置。其余的代码大部分是关于在按下两个文本链接时处理状态。默认情况下，IPA 区域被渲染：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/020d02e4-fbe2-4f3c-9ae6-9c3874f959f3.png)

当按下`stout`文本时，地图上将删除 IPA 叠加层，并添加 stout 区域：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f0a99b8a-63de-4988-8042-cc3913a41ecb.png)

# 总结

在本章中，您了解了 React Native 中的地理位置和地图。地理位置 API 的工作方式与其 Web 对应物相同。在 React Native 应用程序中使用地图的唯一可靠方式是安装第三方`react-native-maps`包。

您看到了基本配置`MapView`组件，以及它如何跟踪用户的位置，并显示相关的兴趣点。然后，您看到了如何绘制自己的兴趣点和兴趣区域。

在下一章中，您将学习如何使用类似 HTML 表单控件的 React Native 组件收集用户输入。

# 测试你的知识

1.  在 React Native 中找到的地理位置 API 与 Web 浏览器中找到的地理位置 API 的工作方式相同。

1.  是的，它是相同的 API。

1.  不，React Native API 具有其自己独特的特性。

1.  React Native 应用程序中地理位置 API 的主要目的是什么？

1.  计算从一个位置到另一个位置的距离。

1.  查找设备的纬度和经度坐标，并将这些值与其他 API 一起使用，以查找有用信息，如地址。

1.  查找地址和有关这些地址的其他信息。

1.  `MapView`组件能够显示用户附近的兴趣点吗？

1.  是的，默认情况下启用了这个功能。

1.  不，您必须手动绘制和标记所有内容。

1.  是的，但您必须使用`showsPointsOfInterest`属性。

1.  如何在地图上标记点？

1.  通过将纬度/经度数组数据作为属性传递给`MapView`组件。

1.  通过将坐标传递给`MapView.Marker`组件。

# 进一步阅读

请查看以下网址以获取更多信息：

+   [`facebook.github.io/react-native/docs/geolocation`](https://facebook.github.io/react-native/docs/geolocation)

+   [`github.com/react-community/react-native-maps`](https://github.com/react-community/react-native-maps)


# 第十九章：收集用户输入

在 Web 应用程序中，您可以从标准 HTML 表单元素中收集用户输入，这些元素在所有浏览器上看起来和行为类似。对于原生 UI 平台，收集用户输入更加微妙。

在本章中，您将学习如何使用各种 React Native 组件来收集用户输入。这些包括文本输入、从选项列表中选择、复选框和日期/时间选择器。您将看到 iOS 和 Android 之间的区别，以及如何为您的应用程序实现适当的抽象。

# 收集文本输入

实施文本输入时，原来有很多要考虑的事情。例如，它是否应该有占位文本？这是不应该在屏幕上显示的敏感数据吗？在用户移动到另一个字段时，您应该如何处理文本？

与传统的 Web 文本输入相比，移动文本输入的显着区别在于前者有自己内置的虚拟键盘，您可以对其进行配置和响应。让我们构建一个示例，渲染几个`<TextInput>`组件的实例：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Text, TextInput, View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';

// A Generic "<Input>" component that we can use in our app.
// It's job is to wrap the "<TextInput>" component in a "<View>"
// so that we can render a label, and to apply styles to the
// appropriate components.
const Input = props => (
  <View style={styles.textInputContainer}>
    <Text style={styles.textInputLabel}>{props.label}</Text>
    <TextInput style={styles.textInput} {...props} />
  </View>
);

Input.propTypes = {
  label: PropTypes.string
};

export default class CollectingTextInput extends Component {
  // This state is only relevant for the "input events"
  // component. The "changedText" state is updated as
  // the user types while the "submittedText" state is
  // updated when they're done.
  state = {
    data: fromJS({
      changedText: '',
      submittedText: ''
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
    const { changedText, submittedText } = this.data.toJS();

    return (
      <View style={styles.container}>
        {/* The simplest possible text input. */}
        <Input label="Basic Text Input:" />

        {/* The "secureTextEntry" property turns
             the text entry into a password input
             field. */}
        <Input label="Password Input:" secureTextEntry />

        {/* The "returnKeyType" property changes
             the return key that's displayed on the
             virtual keyboard. In this case, we want
             a "search" button. */}
        <Input label="Return Key:" returnKeyType="search" />

        {/* The "placeholder" property works just
             like it does with web text inputs. */}
        <Input label="Placeholder Text:" placeholder="Search" />

        {/* The "onChangeText" event is triggered as
             the user enters text. The "onSubmitEditing"
             event is triggered when they click "search". */}
        <Input
          label="Input Events:"
          onChangeText={e => {
            this.data = this.data.set('changedText', e);
          }}
          onSubmitEditing={e => {
            this.data = this.data.set(
              'submittedText',
              e.nativeEvent.text
            );
          }}
          onFocus={() => {
            this.data = this.data
              .set('changedText', '')
              .set('submittedText', '');
          }}
        />

        {/* Displays the captured state from the
             "input events" text input component. */}
        <Text>Changed: {changedText}</Text>
        <Text>Submitted: {submittedText}</Text>
      </View>
    );
  }
} 
```

我不会深入讨论每个`<TextInput>`组件正在做什么 - 代码中有注释。让我们看看这些组件在屏幕上是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/45409a22-50c1-4dac-926f-1d2208fe5804.png)

纯文本输入显示已输入的文本。密码字段不会显示任何字符。当输入为空时，占位文本会显示。还显示了更改的文本状态。您没有看到提交的文本状态，因为在我截屏之前我没有按下虚拟键盘上的提交按钮。

让我们来看看输入元素的虚拟键盘，您可以通过`returnKeyType`属性更改返回键文本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d54505b7-a055-4b4e-af99-41528e8bb530.png)

当键盘返回键反映用户按下它时会发生什么时，用户会更加与应用程序保持一致。

# 从选项列表中进行选择

在 Web 应用程序中，通常使用`<select>`元素让用户从选项列表中进行选择。React Native 带有一个`<Picker>`组件，可以在 iOS 和 Android 上使用。根据用户所在的平台对此组件进行样式处理有一些技巧，因此让我们将所有这些隐藏在一个通用的`Select`组件中。这是`Select.ios.js`模块：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Picker, Text } from 'react-native';
import styles from './styles';

// The "<Select>" component provides an
// abstraction around the "<Picker>" component.
// It actually has two outer views that are
// needed to get the styling right.
const Select = props => (
  <View style={styles.pickerHeight}>
    <View style={styles.pickerContainer}>
      {/* The label for the picker... */}
      <Text style={styles.pickerLabel}>{props.label}</Text>
      <Picker style={styles.picker} {...props}>
        {/* Maps each "items" value to a
             "<Picker.Item>" component. */}
        {props.items.map(i => <Picker.Item key={i.label} {...i} />)}
      </Picker>
    </View>
  </View>
);

Select.propTypes = {
  items: PropTypes.array,
  label: PropTypes.string
};

export default Select; 
```

这对于一个简单的`Select`组件来说有很多额外的开销。事实证明，样式化 React Native 的`<Picker>`组件实际上是相当困难的。以下是`Select.android.js`模块：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Picker, Text } from 'react-native';
import styles from './styles';

// The "<Select>" component provides an
// abstraction around the "<Picker>" component.
// It actually has two outer views that are
// needed to get the styling right.
const Select = props => (
  <View>
    {/* The label for the picker... */}
    <Text style={styles.pickerLabel}>{props.label}</Text>
    <Picker {...props}>
      {/* Maps each "items" value to a
           "<Picker.Item>" component. */}
      {props.items.map(i => <Picker.Item key={i.label} {...i} />)}
    </Picker>
  </View>
);

Select.propTypes = {
  items: PropTypes.array,
  label: PropTypes.string
};

export default Select;
```

以下是样式的样子：

```jsx
import { StyleSheet } from 'react-native'; 

export default StyleSheet.create({ 
  container: { 
    flex: 1, 
    flexDirection: 'row', 
    flexWrap: 'wrap', 
    justifyContent: 'space-around', 
    alignItems: 'center', 
    backgroundColor: 'ghostwhite', 
  }, 

  // The outtermost container, needs a height. 
  pickerHeight: { 
    height: 175, 
  }, 

  // The inner container lays out the picker 
  // components and sets the background color. 
  pickerContainer: { 
    flex: 1, 
    flexDirection: 'column', 
    alignItems: 'center', 
    marginTop: 40, 
    backgroundColor: 'white', 
    padding: 6, 
    height: 240, 
  }, 

  pickerLabel: { 
    fontSize: 14, 
    fontWeight: 'bold', 
  }, 

  picker: { 
  width: 100, 
    backgroundColor: 'white', 
  }, 

  selection: { 
    width: 200, 
    marginTop: 230, 
    textAlign: 'center', 
  }, 
}); 
```

现在你可以渲染你的`<Select>`组件：

```jsx
import React, { Component } from 'react';
import { View, Text } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Select from './Select';

export default class SelectingOptions extends Component {
  // The state is a collection of "sizes" and
  // "garments". At any given time there can be
  // selected size and garment.
  state = {
    data: fromJS({
      sizes: [
        { label: '', value: null },
        { label: 'S', value: 'S' },
        { label: 'M', value: 'M' },
        { label: 'L', value: 'L' },
        { label: 'XL', value: 'XL' }
      ],
      selectedSize: null,
      garments: [
        { label: '', value: null, sizes: ['S', 'M', 'L', 'XL'] },
        { label: 'Socks', value: 1, sizes: ['S', 'L'] },
        { label: 'Shirt', value: 2, sizes: ['M', 'XL'] },
        { label: 'Pants', value: 3, sizes: ['S', 'L'] },
        { label: 'Hat', value: 4, sizes: ['M', 'XL'] }
      ],
      availableGarments: [],
      selectedGarment: null,
      selection: ''
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
    const {
      sizes,
      selectedSize,
      availableGarments,
      selectedGarment,
      selection
    } = this.data.toJS();

    // Renders two "<Select>" components. The first
    // one is a "size" selector, and this changes
    // the available garments to select from.
    // The second selector changes the "selection"
    // state to include the selected size
    // and garment.
    return (
      <View style={styles.container}>
        <Select
          label="Size"
          items={sizes}
          selectedValue={selectedSize}
          onValueChange={size => {
            this.data = this.data
              .set('selectedSize', size)
              .set('selectedGarment', null)
              .set(
                'availableGarments',
                this.data
                  .get('garments')
                  .filter(i => i.get('sizes').includes(size))
              );
          }}
        />
        <Select
          label="Garment"
          items={availableGarments}
          selectedValue={selectedGarment}
          onValueChange={garment => {
            this.data = this.data.set('selectedGarment', garment).set(
              'selection',
              this.data.get('selectedSize') +
                ' ' +
                this.data
                  .get('garments')
                  .find(i => i.get('value') === garment)
                  .get('label')
            );
          }}
        />
        <Text style={styles.selection}>{selection}</Text>
      </View>
    );
  }
} 
```

这个例子的基本思想是，第一个选择器中选择的选项会改变第二个选择器中的可用选项。当第二个选择器改变时，标签会显示所选的尺寸和服装。以下是屏幕的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e00386aa-aaed-4619-ab70-16ef408d81b0.png)

# 在关闭和打开之间切换

在 Web 表单中，你会看到另一个常见的元素是复选框。React Native 有一个`Switch`组件，可以在 iOS 和 Android 上使用。幸运的是，这个组件比`Picker`组件更容易样式化。以下是一个简单的抽象，你可以实现为你的开关提供标签：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Text, Switch } from 'react-native';

import styles from './styles';

// A fairly straightforward wrapper component
// that adds a label to the React Native
// "<Switch>" component.
const CustomSwitch = props => (
  <View style={styles.customSwitch}>
    <Text>{props.label}</Text>
    <Switch {...props} />
  </View>
);

CustomSwitch.propTypes = {
  label: PropTypes.string
};

export default CustomSwitch; 
```

现在，让我们看看如何使用一对开关来控制应用程序状态：

```jsx
import React, { Component } from 'react';
import { View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Switch from './Switch';

export default class TogglingOnAndOff extends Component {
  state = {
    data: fromJS({
      first: false,
      second: false
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
    const { first, second } = this.state.data.toJS();

    return (
      <View style={styles.container}>
        {/* When this switch is turned on, the
             second switch is disabled. */}
        <Switch
          label="Disable Next Switch"
          value={first}
          disabled={second}
          onValueChange={v => {
            this.data = this.data.set('first', v);
          }}
        />

        {/* When this switch is turned on, the
             first switch is disabled. */}
        <Switch
          label="Disable Previous Switch"
          value={second}
          disabled={first}
          onValueChange={v => {
            this.data = this.data.set('second', v);
          }}
        />
      </View>
    );
  }
} 
```

这两个开关简单地切换彼此的`disabled`属性。以下是 iOS 上屏幕的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f05182b4-03e9-4d1c-85fe-ff151c2be0a0.png)

以下是 Android 上相同屏幕的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/531afc4e-9505-45db-b0d8-4e33aea963f5.png)

# 收集日期/时间输入

在本章的最后一节中，你将学习如何实现日期/时间选择器。React Native 为 iOS 和 Android 分别提供了独立的日期/时间选择器组件，这意味着你需要处理组件之间的跨平台差异。 

所以，让我们从 iOS 的日期选择器组件开始：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Text, View, DatePickerIOS } from 'react-native';

import styles from './styles';

// A simple abstraction that adds a label to
// the "<DatePickerIOS>" component.
const DatePicker = props => (
  <View style={styles.datePickerContainer}>
    <Text style={styles.datePickerLabel}>{props.label}</Text>
    <DatePickerIOS mode="date" {...props} />
  </View>
);

DatePicker.propTypes = {
  label: PropTypes.string
};

export default DatePicker; 
```

这个组件并不复杂；它只是向`DatePickerIOS`组件添加了一个标签。日期选择器的 Android 版本需要更多的工作。让我们看一下实现：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { Text, View, DatePickerAndroid } from 'react-native';

import styles from './styles';

// Opens the "DatePickerAndroid" dialog and handles
// the response. The "onDateChange" function is
// a callback that's passed in from the container
// component and expects a "Date" instance.
const pickDate = (options, onDateChange) => {
  DatePickerAndroid.open(options).then(date =>
    onDateChange(new Date(date.year, date.month, date.day))
  );
};

// Renders a "label" and the "date" properties.
// When the date text is clicked, the "pickDate()"
// function is used to render the Android
// date picker dialog.
const DatePicker = ({ label, date, onDateChange }) => (
  <View style={styles.datePickerContainer}>
    <Text style={styles.datePickerLabel}>{label}</Text>
    <Text onPress={() => pickDate({ date }, onDateChange)}>
      {date.toLocaleDateString()}
    </Text>
  </View>
);

DatePicker.propTypes = {
  label: PropTypes.string,
  date: PropTypes.instanceOf(Date),
  onDateChange: PropTypes.func.isRequired
};

export default DatePicker; 
```

两个日期选择器之间的关键区别是，Android 版本不使用 React Native 组件，比如`DatePickerIOS`。相反，我们必须使用命令式的`DatePickerAndroid.open()` API。当用户按下我们组件渲染的日期文本时，这将被触发，并打开一个日期选择器对话框。好消息是，我们的这个组件将这个 API 隐藏在一个声明性组件后面。

我还实现了一个遵循这个确切模式的时间选择器组件。因此，我建议您从[`github.com/PacktPublishing/React-and-React-Native-Second-Edition`](https://github.com/PacktPublishing/React-and-React-Native-Second-Edition)下载本书的代码，这样您就可以看到微妙的差异并运行示例。

现在，让我们看看如何使用我们的日期和时间选择器组件：

```jsx
import React, { Component } from 'react';
import { View } from 'react-native';

import styles from './styles';

// Imports our own platform-independent "DatePicker"
// and "TimePicker" components.
import DatePicker from './DatePicker';
import TimePicker from './TimePicker';

export default class CollectingDateTimeInput extends Component {
  state = {
    date: new Date(),
    time: new Date()
  };

  render() {
    return (
      <View style={styles.container}>
        <DatePicker
          label="Pick a date, any date:"
          date={this.state.date}
          onDateChange={date => this.setState({ date })}
        />
        <TimePicker
          label="Pick a time, any time:"
          date={this.state.time}
          onTimeChange={time => this.setState({ time })}
        />
      </View>
    );
  }
} 
```

太棒了！现在我们有两个简单的组件，可以在 iOS 和 Android 上使用。让我们看看在 iOS 上选择器的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/b92c203b-0980-47c4-9c49-6f056649bb9a.png)

正如您所看到的，iOS 的日期和时间选择器使用了您在本章中学到的`Picker`组件。Android 选择器看起来大不相同-让我们现在看看它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e8208396-bca8-4529-89e2-f992075ec7ca.png)

# 总结

在本章中，您了解了各种类似于您习惯的 Web 表单元素的 React Native 组件。您首先学习了文本输入，以及每个文本输入都有自己的虚拟键盘需要考虑。接下来，您了解了`Picker`组件，允许用户从选项列表中选择项目。然后，您了解了`Switch`组件，类似于复选框。

在最后一节中，您学会了如何实现通用的日期/时间选择器，可以在 iOS 和 Android 上使用。在下一章中，您将学习有关 React Native 中模态对话框的内容。

# 测试您的知识

1.  为什么要更改文本输入的虚拟键盘上的返回键？

1.  您永远不应该更改返回键

1.  因为在某些情况下，有意义的是有一个搜索按钮或其他更符合输入上下文的内容

1.  您只应该更改搜索输入或密码输入的返回键

1.  应该使用哪个`TextInput`属性来标记输入为密码字段？

1.  **`secureTextEntry`**

1.  `password`

1.  `securePassword`

1.  `secureText`

1.  为什么要为选择元素创建抽象？

1.  因为 iOS 和 Android 的组件完全不同

1.  因为两个平台之间的样式挑战

1.  您不需要创建一个抽象。

1.  为什么要为日期和时间选择器创建抽象？

1.  因为 iOS 和 Android 的组件完全不同

1.  因为两个平台之间的样式挑战

1.  您不需要创建一个抽象

# 进一步阅读

访问以下链接获取更多信息：

+   https://facebook.github.io/react-native/docs/handling-text-input

+   https://facebook.github.io/react-native/docs/switch

+   https://facebook.github.io/react-native/docs/picker

+   https://facebook.github.io/react-native/docs/datepickerios

+   https://facebook.github.io/react-native/docs/datepickerandroid.html


# 第二十章：警报、通知和确认

本章的目标是向你展示如何以不干扰当前页面的方式向用户呈现信息。页面使用`View`组件，并直接在屏幕上呈现。然而，有时候有重要信息需要用户看到，但你不一定希望将他们从当前页面中踢出去。

你将首先学习如何显示重要信息。了解重要信息是什么以及何时使用它，你将看到如何获得用户的确认，无论是错误还是成功的情况。然后，你将实现被动通知，向用户显示发生了某事。最后，你将实现模态视图，向用户显示后台正在发生某事。

# 重要信息

在你开始实施警报、通知和确认之前，让我们花几分钟时间思考一下这些项目各自的含义。我认为这很重要，因为如果你只是被动地通知用户发生了错误，很容易被忽视。以下是我对你需要显示的信息类型的定义：

+   **警报**：发生了重要的事情，你需要确保用户看到发生了什么。可能用户需要确认警报。

+   **通知**：发生了某事，但不重要到完全阻止用户正在做的事情。这些通常会自行消失。

确认实际上是警报的一部分。例如，如果用户刚刚执行了一个操作，然后想要确保操作成功后才继续进行，他们必须确认已经看到了信息才能关闭模态框。确认也可以存在于警报中，警告用户即将执行的操作。

关键是要尝试在信息是好知道但不是关键的情况下使用通知。只有在没有用户确认发生的情况下功能的工作流程无法继续进行时才使用确认。在接下来的章节中，你将看到警报和通知用于不同目的的示例。

# 获得用户确认

在本节中，您将学习如何显示模态视图以从用户那里获得确认。首先，您将学习如何实现成功的情景，其中一个操作生成了您希望用户知晓的成功结果。然后，您将学习如何实现错误情景，其中出现了问题，您不希望用户在未确认问题的情况下继续前进。

# 成功确认

让我们首先实现一个模态视图，作为用户成功执行操作的结果显示出来。以下是用于显示用户成功确认的`Modal`组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Text, Modal } from 'react-native';

import styles from './styles';

// Uses "<Modal>" to display the underlying view
// on top of the current view. Properties passed to
// this component are also passed to the modal.
const ConfirmationModal = props => (
  <Modal {...props}>
    {/* Slightly confusing, but we need an inner and
         an outer "<View>" to style the height of the
         modal correctly. */}
    <View style={styles.modalContainer}>
      <View style={styles.modalInner}>
        {/* The confirmation message... */}
        <Text style={styles.modalText}>Dude, srsly?</Text>

        {/* The confirmation and the cancel buttons. Each
             button triggers a different callback function
             that's passed in from the container
             component. */}
        <Text
          style={styles.modalButton}
          onPress={props.onPressConfirm}
        >
          Yep
        </Text>
        <Text
          style={styles.modalButton}
          onPress={props.onPressCancel}
        >
          Nope
        </Text>
      </View>
    </View>
  </Modal>
);

ConfirmationModal.propTypes = {
  visible: PropTypes.bool.isRequired,
  onPressConfirm: PropTypes.func.isRequired,
  onPressCancel: PropTypes.func.isRequired
};

ConfirmationModal.defaultProps = {
  transparent: true,
  onRequestClose: () => {}
};

export default ConfirmationModal;
```

传递给`ConfirmationModal`的属性被转发到 React Native 的`Modal`组件。一会儿您就会明白为什么。首先，让我们看看这个确认模态框是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f808d094-c51e-475a-a818-84690e98995c.png)

用户完成操作后显示的模态框具有我们自己的样式和确认消息。它还有两个操作，但根据确认是在操作前还是操作后，可能只需要一个。以下是用于此模态框的样式：

```jsx
modalContainer: { 
  flex: 1, 
  justifyContent: 'center', 
  alignItems: 'center', 
}, 

modalInner: { 
  backgroundColor: 'azure', 
  padding: 20, 
  borderWidth: 1, 
  borderColor: 'lightsteelblue', 
  borderRadius: 2, 
  alignItems: 'center', 
}, 

modalText: { 
  fontSize: 16, 
  margin: 5, 
  color: 'slategrey', 
}, 

modalButton: { 
  fontWeight: 'bold', 
  margin: 5, 
  color: 'slategrey', 
}, 
```

使用 React Native 的`Modal`组件，您基本上可以自行决定您希望确认模态视图的外观。将它们视为常规视图，唯一的区别是它们是在其他视图之上渲染的。

很多时候，您可能不在意样式化自己的模态视图。例如，在 Web 浏览器中，您可以简单地调用`alert()`函数，它会在浏览器样式的窗口中显示文本。React Native 有类似的功能：`Alert.alert()`。这里的棘手之处在于这是一个命令式 API，并且您不一定希望直接在应用程序中公开它。

相反，让我们实现一个警报确认组件，隐藏这个特定的 React Native API 的细节，以便您的应用程序可以将其视为任何其他组件：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Alert } from 'react-native';

// The "actions" Map will map the "visible"
// property to the "Alert.alert()" function,
// or to a noop function.
const actions = new Map([[true, Alert.alert], [false, () => {}]]);

class ConfirmationAlert extends Component {
  state = { visible: false, title: '', message: '', buttons: [] };

  static getDerivedStateFromProps(props) {
    return props;
  }

  render() {
    actions.get(this.state.visible)(
      this.state.title,
      this.state.message,
      this.state.buttons
    );

    return null;
  }
}

ConfirmationAlert.propTypes = {
  visible: PropTypes.bool.isRequired,
  title: PropTypes.string,
  message: PropTypes.string,
  buttons: PropTypes.array
};

export default ConfirmationAlert;
```

这个组件有两个重要方面。首先，看一下`actions`映射。它的键——`true`和`false`——对应于`visible`状态值。值对应于命令式的`alert()`API 和一个`noop`函数。这是将我们所熟悉和喜爱的声明式 React 组件接口转换为隐藏视图的关键。

其次，注意`render()`方法不需要渲染任何东西，因为这个组件专门处理命令式的 React Native 调用。但是，对于使用`ConfirmationAlert`的人来说，感觉就像有东西被渲染出来了。

这是 iOS 上警报的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/f69d9dd3-e933-4cf8-ab2e-727fb3fd8a94.png)

在功能上，这里并没有真正的不同。有一个标题和下面的文本，但如果你想的话，这很容易添加到模态视图中。真正的区别在于这个模态看起来像一个 iOS 模态，而不是应用程序样式的东西。让我们看看这个警报在 Android 上是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c197f225-866f-4310-91f0-066850b67a75.png)

这个模态看起来像一个 Android 模态，而你不需要对它进行样式设置。我认为大多数情况下，使用警报而不是模态是一个更好的选择。让它看起来像 iOS 的一部分或 Android 的一部分是有意义的。然而，有时候你需要更多地控制模态的外观，比如显示错误确认。以下是用于显示模态和警报确认对话框的代码：

```jsx
import React, { Component } from 'react';
import { View, Text } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import ConfirmationModal from './ConfirmationModal';
import ConfirmationAlert from './ConfirmationAlert';

export default class SuccessConfirmation extends Component {
  // The two pieces of state used to control
  // the display of the modal and the alert
  // views.
  state = {
    data: fromJS({
      modalVisible: false,
      alertVisible: false
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

  // A "modal" button was pressed. So show
  // or hide the modal based on its current state.
  toggleModal = () => {
    this.data = this.data.update('modalVisible', v => !v);
  };

  // A "alert" button was pressed. So show
  // or hide the alert based on its current state.
  toggleAlert = () => {
    this.data = this.data.update('alertVisible', v => !v);
  };

  render() {
    const { modalVisible, alertVisible } = this.data.toJS();

    const { toggleModal, toggleAlert } = this;

    return (
      <View style={styles.container}>
        {/* Renders the "<ConfirmationModal>" component,
             which is hidden by default and controlled
             by the "modalVisible" state. */}
        <ConfirmationModal
          animationType="fade"
          visible={modalVisible}
          onPressConfirm={toggleModal}
          onPressCancel={toggleModal}
        />

        {/* Renders the "<ConfirmationAlert>" component,
             which doesn't actually render anything since
             it controls an imperative API under the hood.
             The "alertVisible" state controls this API. */}
        <ConfirmationAlert
          title="Are you sure?"
          message="For realz?"
          visible={alertVisible}
          buttons={[
            {
              text: 'Nope',
              onPress: toggleAlert
            },
            {
              text: 'Yep',
              onPress: toggleAlert
            }
          ]}
        />

        {/* Shows the "<ConfirmationModal>" component
             by changing the "modalVisible" state. */}
        <Text style={styles.text} onPress={toggleModal}>
          Show Confirmation Modal
        </Text>

        {/* Shows the "<ConfirmationAlert>" component
             by changing the "alertVisible" state. */}
        <Text style={styles.text} onPress={toggleAlert}>
          Show Confimation Alert
        </Text>
      </View>
    );
  }
} 
```

渲染模态的方法与渲染警报的方法不同。然而，它们都是根据属性值的变化而改变的声明式组件。

# 错误确认

在前面部分学到的所有原则在需要用户确认错误时都是适用的。如果你需要更多地控制显示，使用模态。例如，你可能希望模态是红色和令人恐惧的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/603ecf14-5931-4273-b97e-5f3121260cd3.png)

以下是用于创建这种外观的样式。也许你想要更加低调的东西，但重点是你可以根据自己的喜好来定制这种外观：

```jsx
import { StyleSheet } from 'react-native'; 

export default StyleSheet.create({ 
  container: { 
    flex: 1, 
    justifyContent: 'center', 
    alignItems: 'center', 
    backgroundColor: 'ghostwhite', 
  }, 

  text: { 
    color: 'slategrey', 
  }, 

  modalContainer: { 
    flex: 1, 
    justifyContent: 'center', 
    alignItems: 'center', 
  }, 

  modalInner: { 
    backgroundColor: 'azure', 
    padding: 20, 
    borderWidth: 1, 
    borderColor: 'lightsteelblue', 
    borderRadius: 2, 
    alignItems: 'center', 
  }, 

  modalInnerError: { 
    backgroundColor: 'lightcoral', 
    borderColor: 'darkred', 
  }, 

  modalText: { 
    fontSize: 16, 
    margin: 5, 
    color: 'slategrey', 
  }, 

  modalTextError: { 
    fontSize: 18, 
    color: 'darkred', 
  }, 

  modalButton: { 
    fontWeight: 'bold', 
    margin: 5, 
    color: 'slategrey', 
  }, 

  modalButtonError: { 
    color: 'black', 
  }, 
}); 
```

你用于成功确认的相同模态样式仍然在这里。这是因为错误确认模态需要许多相同的样式。以下是如何将它们都应用到`Modal`组件中的方法：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Text, Modal } from 'react-native';

import styles from './styles';

// Declares styles for the error modal by
// combining regular modal styles with
// error styles.
const innerViewStyle = [styles.modalInner, styles.modalInnerError];

const textStyle = [styles.modalText, styles.modalTextError];

const buttonStyle = [styles.modalButton, styles.modalButtonError];

// Just like a success modal, accept for the addition of
// error styles.
const ErrorModal = props => (
  <Modal {...props}>
    <View style={styles.modalContainer}>
      <View style={innerViewStyle}>
        <Text style={textStyle}>Epic fail!</Text>
        <Text style={buttonStyle} onPress={props.onPressConfirm}>
          Fix it
        </Text>
        <Text style={buttonStyle} onPress={props.onPressCancel}>
          Ignore it
        </Text>
      </View>
    </View>
  </Modal>
);

ErrorModal.propTypes = {
  visible: PropTypes.bool.isRequired,
  onPressConfirm: PropTypes.func.isRequired,
  onPressCancel: PropTypes.func.isRequired
};

ErrorModal.defaultProps = {
  transparent: true,
  onRequestClose: () => {}
};

export default ErrorModal; 
```

样式在传递给`style`属性之前会被组合成数组。错误样式总是最后出现的，因为冲突的样式属性，比如`backgroundColor`，会被数组中后面出现的样式覆盖。

除了错误确认中的样式，您可以包含任何您想要的高级控件。这取决于您的应用程序如何让用户处理错误；例如，可能有几种可以采取的行动。

然而，更常见的情况是出了问题，你无能为力，除了确保用户意识到情况。在这些情况下，您可能只需显示一个警报：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7f627ed7-5e3c-4786-9d7d-99bad334d539.png)

# 被动通知

到目前为止，在本章中您所检查的通知都需要用户输入。这是有意设计的，因为这是您强制用户查看的重要信息。然而，您不希望过度使用这一点。对于重要但如果被忽略不会改变生活的通知，您可以使用被动通知。这些通知以比模态框更不显眼的方式显示，并且不需要任何用户操作来解除。

在本节中，您将创建一个`Notification`组件，该组件使用 Android 的 Toast API，并为 iOS 创建一个自定义模态框。它被称为 Toast API，因为显示的信息看起来像是弹出的一片吐司。以下是 Android 组件的样子：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { ToastAndroid } from 'react-native';
import { Map } from 'immutable';

// Toast helper. Always returns "null" so that the
// output can be rendered as a React element.
const show = (message, duration) => {
  ToastAndroid.show(message, duration);
  return null;
};

// This component will always return null,
// since it's using an imperative React Native
// interface to display popup text. If the
// "message" property was provided, then
// we display a message.
const Notification = ({ message, duration }) =>
  Map([[null, null], [undefined, null]]).get(
    message,
    show(message, duration)
  );

Notification.propTypes = {
  message: PropTypes.string,
  duration: PropTypes.number.isRequired
};

Notification.defaultProps = {
  duration: ToastAndroid.LONG
};

export default Notification;
```

再次，您正在处理一个命令式的 React Native API，您不希望将其暴露给应用程序的其他部分。相反，这个组件将命令式的`ToastAndroid.show()`函数隐藏在一个声明性的 React 组件后面。无论如何，这个组件都会返回`null`，因为它实际上不会渲染任何内容。以下是`ToastAndroid`通知的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/c0351dbf-71f6-4b1a-a9ed-cfe831306c88.png)

发生了某事的通知显示在屏幕底部，并在短暂延迟后移除。关键是通知不会打扰。

iOS 通知组件涉及更多，因为它需要状态和生命周期事件，使模态视图的行为类似于瞬态通知。以下是代码：

```jsx
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { View, Modal, Text } from 'react-native';
import { Map } from 'immutable';

import styles from './styles';

class Notification extends Component {
  static propTypes = {
    message: PropTypes.string,
    duration: PropTypes.number.isRequired
  };

  static defaultProps = {
    duration: 1500
  };

  static getDerivedStateFromProps(props) {
    // Update the "visible" state, based on whether
    // or not there's a "message" value.
    return {
      ...this.state,
      visible: Map([[null, false], [undefined, false]]).get(
        props.message,
        true
      )
    };
  }

  // The modal component is either "visible", or not.
  // The "timer" is used to hide the notification
  // after some predetermined amount of time.
  state = { visible: false };
  timer = null;

  componentWillUnmount() {
    clearTimeout(this.timer);
  }

  render() {
    const modalProps = {
      animationType: 'fade',
      transparent: true,
      visible: this.state.visible
    };

    this.timer = Map([
      [null, () => null],
      [undefined, () => null]
    ]).get(this.props.message, () =>
      setTimeout(
        () => this.setState({ visible: false }),
        this.props.duration
      )
    )();

    return (
      <Modal {...modalProps}>
        <View style={styles.notificationContainer}>
          <View style={styles.notificationInner}>
            <Text>{this.props.message}</Text>
          </View>
        </View>
      </Modal>
    );
  }
}

Notification.propTypes = {
  message: PropTypes.string,
  duration: PropTypes.number.isRequired
};

Notification.defaultProps = {
  duration: 1500
};

export default Notification; 
```

您必须设计模态框以显示通知文本，以及用于在延迟后隐藏通知的状态。以下是 iOS 的最终结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/48be01c3-93cb-46f1-a098-2aac63f8b625.png)

与`ToastAndroid` API 相同的原则适用于这里。您可能已经注意到，除了显示通知按钮之外，还有另一个按钮。这是一个简单的计数器，重新渲染视图。实际上，演示这个看似晦涩的功能是有原因的，您马上就会看到。这是主应用视图的代码：

```jsx
import React, { Component } from 'react';
import { Text, View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Notification from './Notification';

export default class PassiveNotifications extends Component {
  // The initial state is the number of times
  // the counter button has been clicked, and
  // the notification message.
  state = {
    data: fromJS({
      count: 0,
      message: null
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
    const { count, message } = this.data.toJS();

    return (
      <View style={styles.container}>
        {/* The "Notification" component is
             only displayed if the "message" state
             has something in it. */}
        <Notification message={message} />

        {/* Updates the count. Also needs to make
             sure that the "message" state is null,
             even if the message has been hidden
             already. */}
        <Text
          onPress={() => {
            this.data = this.data
              .update('count', c => c + 1)
              .set('message', null);
          }}
        >
          Pressed {count}
        </Text>

        {/* Displays the notification by
             setting the "message" state. */}
        <Text
          onPress={() => {
            this.data = this.data.set(
              'message',
              'Something happened!'
            );
          }}
        >
          Show Notification
        </Text>
      </View>
    );
  }
}
```

按下计数器的整个目的是要证明，即使`Notification`组件是声明性的，并在状态改变时接受新的属性值，当改变其他状态值时，仍然必须将消息状态设置为 null。原因是，如果重新渲染组件并且消息状态仍然包含字符串，它将一遍又一遍地显示相同的通知。

# 活动模态

在本章的最后一节中，您将实现一个显示进度指示器的模态。想法是显示模态，然后在 promise 解析时隐藏它。以下是显示带有活动指示器的模态的通用`Activity`组件的代码：

```jsx
import React from 'react';
import PropTypes from 'prop-types';
import { View, Modal, ActivityIndicator } from 'react-native';

import styles from './styles';

// The "Activity" component will only display
// if the "visible" property is try. The modal
// content is an "<ActivityIndicator>" component.
const Activity = props => (
  <Modal visible={props.visible} transparent>
    <View style={styles.modalContainer}>
      <ActivityIndicator size={props.size} />
    </View>
  </Modal>
);

Activity.propTypes = {
  visible: PropTypes.bool.isRequired,
  size: PropTypes.string.isRequired
};

Activity.defaultProps = {
  visible: false,
  size: 'large'
};

export default Activity; 
```

您可能会想要将 promise 传递给组件，以便在 promise 解析时自动隐藏自己。我认为这不是一个好主意，因为这样你就必须将状态引入到这个组件中。此外，它将依赖于 promise 才能正常工作。通过您实现这个组件的方式，您可以仅基于`visible`属性来显示或隐藏模态。这是 iOS 上活动模态的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/7331738d-0be0-4f4a-bc12-393db27a661e.png)

模态上有一个半透明的背景，覆盖在带有获取内容...链接的主视图上。以下是在`styles.js`中创建此效果的方法：

```jsx
modalContainer: { 
  flex: 1, 
  justifyContent: 'center', 
  alignItems: 'center', 
  backgroundColor: 'rgba(0, 0, 0, 0.2)', 
}, 
```

与其将实际的`Modal`组件设置为透明，不如在`backgroundColor`中设置透明度，这样看起来就像是一个覆盖层。现在，让我们来看看控制这个组件的代码：

```jsx
import React, { Component } from 'react';
import { Text, View } from 'react-native';
import { fromJS } from 'immutable';

import styles from './styles';
import Activity from './Activity';

export default class ActivityModals extends Component {
  // The state is a "fetching" boolean value,
  // and a "promise" that is used to determine
  // when the fetching is done.
  state = {
    data: fromJS({
      fetching: false,
      promise: Promise.resolve()
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

  // When the fetch button is pressed, the
  // promise that simulates async activity
  // is set, along with the "fetching" state.
  // When the promise resolves, the "fetching"
  // state goes back to false, hiding the modal.
  onPress = () => {
    this.data = this.data.merge({
      promise: new Promise(resolve => setTimeout(resolve, 3000)).then(
        () => {
          this.data = this.data.set('fetching', false);
        }
      ),
      fetching: true
    });
  };

  render() {
    return (
      <View style={styles.container}>
        {/* The "<Activity>" modal is only visible
             when the "fetching" state is true. */}
        <Activity visible={this.data.get('fetching')} />
        <Text onPress={this.onPress}>Fetch Stuff...</Text>
      </View>
    );
  }
} 
```

当按下获取链接时，将创建一个模拟异步网络活动的新 promise。然后，当 promise 解析时，将`fetching`状态更改回 false，以便隐藏活动对话框。

# 摘要

在本章中，您了解到向移动用户显示重要信息的必要性。有时，这需要用户的明确反馈，即使只是对消息的确认。在其他情况下，被动通知效果更好，因为它们比确认模态更不显眼。

有两种工具可用于向用户显示消息：模态和警报。模态更灵活，因为它们就像常规视图一样。警报适用于显示纯文本，并且它们会为您处理样式问题。在 Android 上，您还有额外的 `ToastAndroid` 接口。您看到这在 iOS 上也是可能的，但这需要更多的工作。

在下一章中，我们将深入研究 React Native 中的手势响应系统，这比浏览器能提供更好的移动体验。

# 测试你的知识

1.  警报和模态之间有什么区别？

1.  警报用于不重要的信息，而模态用于不太重要的信息。

1.  它们用途相同，使用哪一个都无所谓。

1.  警报很擅长继承移动环境的外观和感觉，而模态框是常规的 React Native 视图，您可以完全控制其样式。

1.  哪个 React Native 组件可用于创建覆盖屏幕上其他组件的模态视图？

1.  没有办法做到这一点。

1.  `Modal` 组件。

1.  `Modal.open()` 函数用于此目的。

1.  在 Android 系统上显示被动通知的最佳方法是什么？

1.  React Native 有一个通知 API 用于此目的。

1.  您可以使用 `ToastAndroid` React Native API。在 iOS 上，没有不涉及自己编写代码的好的替代方法。

1.  React Native 仅支持 iOS 上的被动通知。

1.  React Native 警报 API 仅在 iOS 上可用。

1.  真

1.  假

# 进一步阅读

查看以下链接以获取更多信息：

+   [`facebook.github.io/react-native/docs/modal`](https://facebook.github.io/react-native/docs/modal)

+   [`facebook.github.io/react-native/docs/alert`](https://facebook.github.io/react-native/docs/alert)

+   [`facebook.github.io/react-native/docs/toastandroid`](https://facebook.github.io/react-native/docs/toastandroid)
