# ReactNative 秘籍第二版（二）

> 原文：[`zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce`](https://zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：实现复杂用户界面-第二部分

本章将涵盖更多使用 React Native 构建 UI 的技巧。我们将首次了解如何链接到其他应用程序和网站，处理设备方向的变化，以及如何构建用于收集用户输入的表单。

在本章中，我们将涵盖以下技巧：

+   处理通用应用程序

+   检测方向变化

+   使用 WebView 嵌入外部网站

+   链接到网站和其他应用程序

+   创建一个表单组件

# 处理通用应用程序

使用 React Native 的好处之一是它能够轻松创建通用应用程序。我们可以在手机和平板应用程序之间共享大量代码。布局可能会根据设备而改变，但我们可以在布局之间重用代码片段。

在这个示例中，我们将构建一个可以在手机和平板上运行的应用程序。平板版本将包括不同的布局，但我们将重用相同的内部组件。

# 准备工作

对于这个示例，我们将展示一个联系人列表。目前，我们将从`.json`文件中加载数据。我们将在以后的章节中探讨如何从**表述性状态转移**（**REST**）API 中加载远程数据。

让我们打开以下 URL 并将生成的 JSON 复制到名为`data.json`的文件中，放在项目的根目录。我们将使用这些数据来渲染联系人列表。它返回一个假用户数据的 JSON 对象，网址是[`api.randomuser.me/?results=20`](http://api.randomuser.me/?results=20)。

让我们创建一个名为`universal-app`的新应用。

# 如何做...

1.  让我们打开`App.js`并导入我们在上一节“准备工作”中创建的依赖项以及我们的`data.json`文件。我们还将从`./utils/Device`导入`Device`实用程序，我们将在以后的步骤中构建它：

```jsx
import React, { Component } from 'react';
import { StyleSheet, View, Text } from 'react-native';
import Device from './utils/Device';

import data from './data.json';
```

1.  在这里，我们将创建主要的`App`组件及其基本布局。这个顶层组件将决定是渲染手机还是平板 UI。我们只渲染两个`Text`元素。`renderDetail`文本应该只在平板上显示，而`renderMaster`文本应该在手机和平板上显示：

```jsx
export default class App extends Component {
  renderMaster() {
    return (
      <Text>Render on phone and tablets!!</Text>
    );
  }

  renderDetail() {
    if (Device.isTablet()) {
      return (
        <Text>Render on tablets only!!</Text>
      );
    }
  }

  render() {
    return (
      <View style={styles.content}>
        {this.renderMaster()}
        {this.renderDetail()}
      </View>
    );
  }
}
```

1.  在`App`组件下，我们将添加一些基本样式。这些样式临时包括`paddingTop: 40`，以便我们渲染的文本不会被设备的系统栏覆盖：

```jsx
const styles = StyleSheet.create({
  content: {
    paddingTop: 40,
    flex: 1,
    flexDirection: 'row',
  },
});
```

1.  如果我们尝试按原样运行我们的应用程序，它将失败，并显示错误，告诉我们找不到`Device`模块，所以让我们创建它。这个实用程序类的目的是根据屏幕尺寸计算当前设备是手机还是平板电脑。它将有一个`isTablet`方法和一个`isPhone`方法。我们需要在项目的根目录中创建一个`utils`文件夹，并添加一个`Device.js`作为实用程序。现在我们可以添加实用程序的基本结构：

```jsx
import { Dimensions, Alert } from 'react-native';

// Tablet portrait dimensions
const tablet = {
  width: 552,
  height: 960,
};

class Device {
  // Added in next steps
}

const device = new Device();
export default device;
```

1.  让我们开始构建实用程序，通过创建两种方法：一个用于获取纵向尺寸，另一个用于获取横向尺寸。根据设备旋转，`width`和`height`的值将改变，这就是为什么我们需要这两种方法始终获取正确的值，无论设备是`landscape`还是`portrait`：

```jsx
class Device {
 getPortraitDimensions() {
    const { width, height } = Dimensions.get("window");

    return {
      width: Math.min(width, height),
      height: Math.max(width, height),
    };
  }

  getLandscapeDimensions() {
    const { width, height } = Dimensions.get("window");

    return {
      width: Math.max(width, height),
      height: Math.min(width, height),
    };
  }
}
```

1.  现在让我们创建我们的应用程序将用来确定应用程序是在平板电脑上运行还是在手机上运行的两种方法。为了计算这一点，我们需要获取纵向模式下的尺寸，并将它们与我们为平板电脑定义的尺寸进行比较：

```jsx
  isPhone() {
    const dimension = this.getPortraitDimensions();
    return dimension.height < tablet.height;
  }

  isTablet() {
    const dimension = this.getPortraitDimensions();
    return dimension.height >= tablet.height;
  }
```

1.  现在，如果我们打开应用程序，我们应该看到两种不同的文本被呈现，取决于我们是在手机上还是在平板上运行应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/4b04e46d-e2f8-4753-b51a-2a5053e3f3a2.png)

1.  实用程序按预期工作！让我们回到主`App.js`的`renderMaster`方法上。我们希望这个方法渲染存储在`data.json`文件中的联系人列表。让我们导入一个新的组件，我们将在接下来的步骤中构建它，并更新`renderMaster`方法以使用我们的新组件：

```jsx
import UserList from './UserList';

export default class App extends Component {
 renderMaster() {
    return (
      <UserList contacts={data.results} />
    );
  }

  //...
}
```

1.  让我们创建一个新的`UserList`文件夹。在这个文件夹里，我们需要为新组件创建`index.js`和`styles.js`文件。我们需要做的第一件事是将依赖项导入到新的`index.js`中，创建`UserList`类，并将其导出为`default`：

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  View,
  Text,
  ListView,
  Image,
  TouchableOpacity,
} from 'react-native';
import styles from './styles';

export default class UserList extends Component {
 // Defined in the following steps 
}
```

1.  我们已经介绍了如何创建列表。如果您不清楚`ListView`组件的工作原理，请阅读第二章中的*显示项目列表*配方，*创建一个简单的 React Native 应用程序*。在类的构造函数中，我们将创建`dataSource`，然后将其添加到`state`中：

```jsx
export default class UserList extends Component {
 constructor(properties) {
    super(properties);
    const dataSource = new ListView.DataSource({
      rowHasChanged: (r1, r2) => r1 !== r2
    });

    this.state = {
      dataSource: dataSource.cloneWithRows(properties.contacts),
    };
  }

  //...
}
```

1.  `render`方法也遵循了在第二章中介绍的`ListView`配方中引入的相同模式，*显示项目列表*：

```jsx
render() {
 return (
  <View style={styles.main}>
   <Text style={styles.toolbar}>
   My contacts!
   </Text>
   <ListView dataSource={this.state.dataSource}
    renderRow={this.renderContact}
    style={styles.main} />
  </View> );
 }
```

1.  正如您所看到的，我们需要定义`renderContact`方法来呈现每一行。我们正在使用`TouchableOpacity`组件作为主要包装器，这将允许我们在列表项被按下时执行一些操作的回调函数。目前，当按钮被按下时我们并没有做任何事情。我们将在第九章中学习如何使用 Redux 在组件之间进行通信，*实现 Redux*：

```jsx
        renderContact = (contact) => { 
          return ( 
            <TouchableOpacity style={styles.row}> 
              <Image source={{uri: `${contact.picture.large}`}} style=
              {styles.img} /> 
              <View style={styles.info}> 
                <Text style={styles.name}> 
                  {this.capitalize(contact.name.first)} 
                  {this.capitalize(contact.name.last)} 
                </Text> 
                <Text style={styles.phone}>{contact.phone}</Text> 
              </View> 
            </TouchableOpacity> 
          ); 
        }
```

1.  我们没有使用样式来使文本大写，所以我们需要使用 JavaScript。`capitalize`函数非常简单，它将给定字符串的第一个字母设置为大写：

```jsx
  capitalize(value) {
    return value[0].toUpperCase() + value.substring(1);
  }
```

1.  我们几乎完成了这个组件。剩下的只有`styles`。让我们打开`/UserList/styles.js`文件，并为主容器和工具栏添加样式：

```jsx
import { StyleSheet } from 'react-native';

export default StyleSheet.create({
  main: {
    flex: 1,
    backgroundColor: '#dde6e9',
  },
  toolbar: {
    backgroundColor: '#2989dd',
    color: '#fff',
    paddingTop: 50,
    padding: 20,
    textAlign: 'center',
    fontSize: 20,
  },
  // Remaining styles added in next step.
});
```

1.  现在，对于每一行，我们希望在左边呈现每个联系人的图像，右边是联系人的姓名和电话号码：

```jsx
  row: {
    flexDirection: 'row',
    padding: 10,
  },
  img: {
    width: 70,
    height: 70,
    borderRadius: 35,
  },
  info: {
    marginLeft: 10,
  },
  name: {
    color: '#333',
    fontSize: 22,
    fontWeight: 'bold',
  },
  phone: {
    color: '#aaa',
    fontSize: 16,
  },
```

1.  让我们切换到`App.js`文件，并删除我们在*步骤 7*中用于使文本可读的`paddingTop`属性；要删除的行已用粗体显示：

```jsx
const styles = StyleSheet.create({
  content: {
 paddingTop: 40,
    flex: 1,
    flexDirection: 'row',
  },
});
```

1.  如果我们尝试运行我们的应用程序，我们应该能够在手机和平板上看到一个非常漂亮的列表，并且在两个不同的设备上看到相同的组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/3a0e3972-6f01-4526-855d-67962d131503.png)

1.  我们已经根据当前设备显示了两种不同的布局！现在我们需要在`UserDetail`视图上进行工作，它将显示所选的联系人。让我们打开`App.js`，导入`UserDetail`视图，并更新`renderDetail`方法，如下所示：

```jsx
import UserDetail from './UserDetail'; 
export default class App extends Component {
  renderMaster() {
    return (
      <UserList contacts={data.results} />
    );
  }

 renderDetail() {
    if (Device.isTablet()) {
      return (
        <UserDetail contact={data.results[0]} />
      );
    }
  }
}
```

如前所述，在这个食谱中，我们不专注于从一个组件向另一个组件发送数据，而是专注于在平板电脑和手机上呈现不同的布局。因此，对于这个食谱，我们将始终将第一条记录发送到用户详细信息视图。

1.  为了简化事情并尽可能缩短食谱，对于用户详细信息视图，我们将只显示一个工具栏和一些显示给定记录的名字和姓氏的文本。我们将在这里使用一个无状态组件：

```jsx
import React from 'react';
import {
  View,
  Text,
} from 'react-native';
import styles from './styles';

const UserList = ({ contact }) => (
  <View style={styles.main}>
    <Text style={styles.toolbar}>Details should go here!</Text>
    <Text>
      This is the detail view:{contact.name.first} {contact.name.last}
    </Text>
  </View>
);

export default UserList;
```

1.  最后，我们需要为这个组件设置样式。我们希望将屏幕的四分之三分配给详细页面，四分之一分配给主列表。这可以通过使用 flexbox 轻松实现。由于`UserList`组件具有`flex`属性为`1`，我们可以将`UserDetail`的`flex`属性设置为`3`，允许`UserDetail`占据屏幕的 75%。以下是我们将添加到`/UserDetail/styles.js`文件的样式：

```jsx
import { StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  main: {
    flex: 3,
    backgroundColor: '#f0f3f4',
  },
  toolbar: {
    backgroundColor: '#2989dd',
    color: '#fff',
    paddingTop: 50,
    padding: 20,
    textAlign: 'center',
    fontSize: 20,
  },
});

export default styles;
```

1.  如果我们再次尝试运行我们的应用程序，我们会发现在平板上，它将呈现一个漂亮的布局，显示列表视图和详细视图，而在手机上，它只显示联系人列表。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/b50ed65a-c2a9-4d6a-bb60-d8c18e038932.png)

# 工作原理...

在`Device`实用程序中，我们导入了 React Native 提供的名为`Dimension`的依赖项，用于获取当前设备的尺寸。我们还在`Device`实用程序中定义了一个名为`tablet`的常量，它是一个包含`width`和`height`的对象，用于与`Dimension`一起计算设备是否为平板电脑。这个常量的值是基于市场上最小的 Android 平板电脑。

在*步骤 5*中，我们通过调用`Dimensions.get("window")`方法获得了宽度和高度，然后根据我们想要的方向获得了最大值和最小值。

在*步骤 12*中，重要的是要注意我们使用箭头函数来定义`renderContact`方法。使用箭头函数可以保持正确的绑定范围，否则，在调用`this.capitalize`时，`this`将绑定到错误的范围。查看*另请参阅*部分，了解有关`this`关键字和箭头函数工作原理的更多信息。

# 另请参阅

+   从 ponyfoo 的[https://ponyfoo.com/articles/es6-arrow-functions-in-depth]中获得了对 ES6 箭头函数的良好解释。

+   Kyle Simpson 在[https://github.com/getify/You-Dont-Know-JS/blob/master/this%20%26%20object%20prototypes/ch2.md]深入探讨了 JavaScript 中`this`的工作原理。

# 检测方向变化

在构建复杂的界面时，根据设备的方向渲染不同的 UI 组件是非常常见的。这在处理平板电脑时尤其如此。

在这个示例中，我们将根据屏幕方向渲染菜单。在横向时，我们将渲染一个带有图标和文本的扩展菜单，而在纵向时，我们只会渲染图标。

# 准备工作

为了支持方向变化，我们将使用 Expo 的辅助工具`ScreenOrientation`。

我们还将使用 Expo 软件包`@expo/vector-icons`提供的`FontAwesome`组件。第二章中的*使用字体图标*一节描述了如何使用这个组件。

在开始之前，让我们创建一个名为`screen-orientation`的新应用程序。我们还需要对 Expo 在目录根目录中创建的`app.json`文件进行微调。这个文件有一些 Expo 在构建应用程序时使用的基本设置。其中之一是`orientation`，它自动设置为`portrait`，用于每个新应用程序。此设置确定应用程序允许的方向，并且可以设置为`portrait`、`landscape`或`default`。如果我们将其更改为`default`，我们的应用程序将允许纵向和横向方向。

要看到这些更改生效，请确保重新启动 Expo 项目。

# 如何做...

1.  我们将首先打开`App.js`并添加我们将使用的导入：

```jsx
import React from 'react';
import {
  Dimensions,
  StyleSheet,
  Text,
  View
} from 'react-native';
```

1.  接下来，我们将添加空的`App`组件类，以及一些基本样式：

```jsx
export default class App extends React.Component {

}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#fff'
  },
  text: {
    fontSize: 40,
  }
});
```

1.  在我们的应用程序框架就位后，我们现在可以添加`render`方法。在`render`方法中，您会注意到我们使用了`View`组件，并使用了`onLayout`属性，这将在设备方向发生变化时触发。然后`onLayout`将运行`this.handleLayoutChange`，我们将在下一步中定义。在`Text`元素中，我们只是显示`state`对象上`orientation`的值：

```jsx
export default class App extends React.Component {
 render() {
    return (
      <View
        onLayout={() => this.handleLayoutChange}
        style={styles.container}
      >
        <Text style={styles.text}>
          {this.state.orientation}
        </Text>
      </View>
    );
  }
}
```

1.  让我们创建组件的`handleLayoutChange`方法，以及`handleLayoutChange`方法调用的`getOrientation`函数。`getOrientation`函数使用 React Native 的`Dimensions`工具来获取屏幕的宽度和高度。如果`height > width`，我们就知道设备处于纵向方向，如果不是，那么它就是横向方向。通过更新`state`，将启动重新渲染，并且`this.state.orientation`的值将反映方向：

```jsx
  handleLayoutChange() {
    this.getOrientation();
  }

  getOrientation() {
    const { width, height } = Dimensions.get('window');
    const orientation = height > width ? 'Portrait' : 'Landscape';
    this.setState({
      orientation
    });
  }
```

1.  如果我们此时运行应用程序，将会得到错误类型错误：null 不是对象：（评估'this.state.orientation'）。这是因为`render`方法试图在`this.state.orientation`值甚至被定义之前读取它。我们可以通过 React 生命周期`componentWillMount`钩子在`render`首次运行之前轻松解决这个问题来获取方向：

```jsx
  componentWillMount() {
    this.getOrientation();
  }
```

1.  这就是我们寻找的基本功能所需的全部内容！再次运行应用程序，您应该看到显示的文本反映了设备的方向。旋转设备，方向文本应该更新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/23ba5cc4-36e7-4728-ac3a-3bc00b4846fa.png)

1.  现在`orientation`状态值已经正确更新，我们可以专注于 UI。如前所述，我们将创建一个菜单，根据当前方向稍微不同地呈现选项。让我们导入一个`Menu`组件，我们将在接下来的步骤中构建它，并更新我们的`App`组件的`render`方法以使用新的`Menu`组件。请注意，我们现在将`this.state.orientation`传递给`Menu`组件的`orientation`属性：

```jsx
import Menu from './Menu';

export default class App extends React.Component {

  // ...

  render() {
    return (
      <View
        onLayout={() => {this.handleLayoutChange()}}
        style={styles.container}
      >
        <Menu orientation={this.state.orientation} />
        <View style={styles.main}>
          <Text>Main Content</Text>
        </View>
      </View>
    );
  }
}
```

1.  让我们也更新我们的`App`组件的样式。您可以用以下代码替换*步骤 2*中的样式。通过在`container`样式上将`flexDirection`设置为`row`，我们将能够水平显示两个组件：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
  },
  main: {
    flex: 1,
    backgroundColor: '#ecf0f1',
    justifyContent: 'center',
    alignItems: 'center',
  }
});
```

1.  接下来，让我们构建`Menu`组件。我们需要创建一个新的`/Menu/index.js`文件，其中将定义`Menu`类。这个组件将接收`orientation`属性，并根据`orientation`值决定如何呈现菜单选项。让我们首先导入这个类的依赖项：

```jsx
import React, { Component } from 'react';
import { StyleSheet, View, Text } from 'react-native';
import { FontAwesome } from '@expo/vector-icons';
```

1.  现在我们可以定义`Menu`类。在`state`对象上，我们将定义一个`options`数组。这些`option`对象将用于定义图标。如前一章中的*使用字体图标*中讨论的，我们可以通过关键字来定义图标，如在[`expo.github.io/vector-icons/`](https://expo.github.io/vector-icons/)中的矢量图标目录中定义的那样：

```jsx
export default class Menu extends Component {
  state = {
    options: [
      {title: 'Dashboard', icon: 'dashboard'},
      {title: 'Inbox', icon: 'inbox'},
      {title: 'Graphs', icon: 'pie-chart'},
      {title: 'Search', icon: 'search'},
      {title: 'Settings', icon: 'gear'},
    ],
  };

  // Remainder defined in following steps
}
```

1.  这个组件的`render`方法循环遍历`state`对象中的`options`数组：

```jsx
  render() {
    return (
      <View style={styles.content}>
        {this.state.options.map(this.renderOption)}
      </View>
    );
  }
```

1.  正如您在上一步中的 JSX 中所看到的，有一个对`renderOption`的调用。在这个方法中，我们将为每个选项呈现图标和标签。我们还将使用方向值来切换显示标签，并更改图标的大小：

```jsx
  renderOption = (option, index) => {
    const isLandscape = this.properties.orientation === 'Landscape';
    const title = isLandscape
      ? <Text style={styles.title}>{option.title}</Text>
      : null;
    const iconSize = isLandscape ? 27 : 35;

    return (
      <View key={index} style={[styles.option, styles.landscape]}>
        <FontAwesome name={option.icon} size={iconSize} color="#fff" />
        {title}
      </View>
    );
  }
```

在上一个代码块中，请注意我们正在定义`key`属性。在动态创建新组件时，我们总是需要设置`key`属性。该属性对于每个项目应该是唯一的，因为它在内部被 React 使用。在这种情况下，我们使用循环迭代的索引。这样，我们可以确保每个项目都有一个唯一的`key`值，因为数据是静态的。您可以在官方文档中阅读更多关于它的信息[`reactjs.org/docs/lists-and-keys.html`](https://reactjs.org/docs/lists-and-keys.html)。

1.  最后，我们将为菜单定义样式。首先，我们将把`backgroundColor`设置为深蓝色，然后，对于每个选项，我们将改变`flexDirection`以水平渲染图标和标签。其余的样式添加边距和填充，以便菜单项之间有很好的间距：

```jsx
const styles = StyleSheet.create({
  content: {
    backgroundColor: '#34495e',
    paddingTop: 50,
  },
  option: {
    flexDirection: 'row',
    paddingBottom: 15,
  },
  landscape: {
    paddingRight: 30,
    paddingLeft: 30,
  },
  title: {
    color: '#fff',
    fontSize: 16,
    margin: 5,
    marginLeft: 20,
  },
});
```

1.  如果我们现在运行我们的应用程序，它将根据屏幕的方向不同显示菜单 UI。旋转设备，布局将自动更新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/12a5ad38-0756-4ed5-a189-2f3e4412e2c1.png)

# 还有更多...

在这个示例中，我们查看了作为每个 Expo 项目一部分存在的`app.json`文件。在这个文件中有许多有用的设置，可以调整这些设置会影响项目的构建过程。您可以使用这个文件来调整方向锁定，定义应用程序图标，并设置启动画面，以及其他许多设置。您可以在 Expo 配置文档中查看`app.json`支持的所有设置，托管在[`docs.expo.io/versions/latest/guides/configuration.html`](https://docs.expo.io/versions/latest/guides/configuration.html)。

Expo 还提供了`ScreenOrientation`实用程序，可以用来声明应用程序的允许方向。使用实用程序的主要方法`ScreenOrientation.allow(orientation)`，将覆盖`app.json`中的相应设置。该实用程序还提供比`app.json`中设置更精细的选项，例如`ALL_BUT_UPSIDE_DOWN`和`LANDSCAPE_RIGHT`。有关此实用程序的更多信息，您可以阅读文档[`docs.expo.io/versions/latest/sdk/screen-orientation.html`](https://docs.expo.io/versions/latest/sdk/screen-orientation.html)。

# 使用 WebView 嵌入外部网站

对于许多应用程序，需要访问和在应用程序中显示外部链接是必需的。这可以用于显示第三方网站、在线帮助以及使用您的应用程序的条款和条件等。

在这个教程中，我们将看到如何在我们的应用程序中通过点击按钮打开一个 WebView，并动态设置 URL 值。我们还将在这个教程中使用`react-navigation`包来创建基本的堆栈导航。请查看第三章中的*设置和使用导航*教程，深入了解构建导航。

如果您的应用程序更适合通过设备浏览器加载外部网站，请参阅下一个教程*链接到网站和其他应用程序*。

# 准备工作

我们需要为基于 WebView 的教程创建一个新的应用程序。让我们将我们的新应用命名为`web-view`。我们还将使用`react-navigation`，所以一定要安装这个包。您可以使用`yarn`或`npm`来安装这个包。在项目的根目录中，运行以下命令：

```jsx
yarn add react-navigation
```

或者，使用`npm`进行安装：

```jsx
npm install --save react-navigation
```

# 如何做...

1.  让我们从打开`App.js`文件开始。在这个文件中，我们将使用`react-navigation`包提供的`StackNavigator`组件。首先，让我们添加在这个文件中将要使用的导入。`HomeScreen`是我们将在本教程中稍后构建的一个组件：

```jsx
import React, { Component } from 'react';
import { StackNavigator } from 'react-navigation';

import HomeScreen from './HomeScreen';
```

1.  现在我们有了导入，让我们使用`StackNavigator`组件来定义第一个路由；我们将使用一个带有链接的`Home`路由，这些链接应该使用 React Native 的`WebView`组件显示。`navigationOptions`属性允许我们定义要在导航标题中显示的标题：

```jsx
const App = StackNavigator({
  Home: {
    screen: HomeScreen,
    navigationOptions: ({ navigation }) => ({
      title: 'Home'
    }),
  },
});

export default App;
```

1.  现在我们准备好创建`HomeScreen`组件了。让我们在项目的根目录中创建一个名为`HomeScreen`的新文件夹，并在文件夹中添加一个`index.js`文件。和往常一样，我们可以从导入开始：

```jsx
import React, { Component } from 'react';
import {
  TouchableOpacity,
  View,
  Text,
  SafeAreaView,
} from 'react-native';

import styles from './styles';
```

1.  现在我们可以声明我们的`HomeScreen`组件。让我们还向组件添加一个`state`对象，其中包含一个`links`数组。这个数组中有一个对象，代表我们将在这个组件中使用的每个链接。我已经为您提供了四个`links`供您使用；但是，您可以编辑每个`links`数组对象中的`title`和`url`到任何您喜欢的网站：

```jsx
export default class HomeScreen extends Component {
  state = {
    links: [
      {
        title: 'Smashing Magazine',
        url: 'https://www.smashingmagazine.com/articles/'
      },
      {
        title: 'CSS Tricks',
        url: 'https://css-tricks.com/'
      },
      {
        title: 'Gitconnected Blog',
        url: 'https://medium.com/gitconnected'
      },
      {
        title: 'Hacker News',
        url: 'https://news.ycombinator.com/'
      }
     ],
  };
}
```

1.  我们准备向该组件添加一个`render`函数。在这里，我们使用`SafeAreaView`作为容器元素。这与普通的`View`元素一样工作，但也考虑了 iPhone X 上的刘海区域，以便我们的布局不会被设备边框遮挡。您会注意到我们正在使用`map`来遍历上一步中的`links`数组，将每个传递给`renderButton`函数：

```jsx
  render() {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.buttonList}>
          {this.state.links.map(this.renderButton)}
        </View>
      </SafeAreaView>
    );
  }
```

1.  现在我们已经定义了`render`方法，我们需要创建它正在使用的`renderButton`方法。该方法将每个链接作为名为`button`的参数，并且我们将使用`index`作为`key`的唯一标识符，用于`renderButton`创建的每个元素。有关此点的更多信息，请参见本章第二个食谱中*检测方向更改*的*步骤 12*中的*提示*。

当按下`TouchableOpacity`按钮元素时，将触发`this.handleButtonPress(button)`：

```jsx
  renderButton = (button, index) => {
    return (
      <TouchableOpacity
        key={index}
        onPress={() => this.handleButtonPress(button)}
        style={styles.button}
      >
        <Text style={styles.text}>{button.title}</Text>
      </TouchableOpacity>
    );
  }
```

1.  现在我们需要创建`handleButtonPress`方法，该方法在上一步中使用。此方法使用传入的`button`参数的`url`和`title`属性。然后，我们可以在调用`this.properties.navigation.navigate()`时使用这些属性，传递要导航到的路由的名称和应传递到该路由的参数。我们可以访问名为`navigation`的`property`，因为我们正在使用`StackNavigator`，这是我们在*步骤 2*中设置的：

```jsx
  handleButtonPress(button) {
    const { url, title } = button;
    this.properties.navigation.navigate('Browser', { url, title });
  }
```

1.  `HomeScreen`组件已经完成，除了样式。让我们在`HomeScreen`文件夹中添加一个`styles.js`文件来定义这些样式：

```jsx
import { StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  buttonList: {
    flex: 1,
    justifyContent: 'center',
  },
  button: {
    margin: 10,
    backgroundColor: '#c0392b',
    borderRadius: 3,
    padding: 10,
    paddingRight: 30,
    paddingLeft: 30,
  },
  text: {
    color: '#fff',
    textAlign: 'center',
  },
});

export default styles;
```

1.  现在，如果我们打开应用程序，我们应该看到`HomeScreen`组件呈现为带有四个链接按钮的列表，并且在每个设备上以本机样式呈现标题为 Home。然而，由于我们的`StackNavigator`中没有`Browser`路由，当按下按钮时实际上不会发生任何事情：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/b705e213-90c2-4eb1-b741-7a9a48c1835f.png)

1.  让我们返回`App.js`文件并添加`Browser`路由。首先，我们需要导入`BrowserScreen`组件，我们将在接下来的步骤中创建：

```jsx
import BrowserScreen from './BrowserScreen';
```

1.  现在`BrowserScreen`组件已经被导入，我们可以将它添加到`StackNavigator`对象中，以创建一个`Browser`路由。在`navigationOptions`中，我们正在根据传递给路由的参数定义动态标题。这些参数与我们在*步骤 7*中作为第二个参数传递给`navigation.navigate()`调用的对象相同：

```jsx
const App = StackNavigator({
  Home: {
    screen: HomeScreen,
    navigationOptions: ({ navigation }) => ({
      title: 'Home'
    }),
  },
 Browser: {
    screen: BrowserScreen,
    navigationOptions: ({ navigation }) => ({
      title: navigation.state.params.title
    }),
  },
});
```

1.  我们准备创建`BrowserScreen`组件。让我们在项目的根目录中创建一个名为`BrowserScreen`的新文件夹，并在其中添加一个新的`index.js`文件，然后添加此组件所需的导入：

```jsx
import React, { Component } from 'react';
import { WebView } from 'react-native';
```

1.  `BrowserScreen`组件非常简单。它只包括一个渲染方法，该方法从传递给`navigation.state`属性的`params`属性中读取，以调用在*步骤 7*中定义的`this.properties.navigation.navigate`，当按下按钮时触发。我们只需要渲染`WebView`组件并将其`source`属性设置为具有`uri`属性设置为`params.url`的对象：

```jsx
export default class BrowserScreen extends Component {
  render() {
    const { params } = this.properties.navigation.state;

    return(
      <WebView
        source={{uri: params.url}}
      />
    );
  }
}
```

1.  现在，如果我们回到模拟器中运行的应用程序，我们可以看到我们的 WebView 在运行！

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/9fedd5d4-07d4-46c1-bfe4-2d0069f7c5e1.png)Hacker News 和 Smashing Magazine 从我们的应用程序中访问

# 它是如何工作的...

使用`WebView`打开外部网站是让用户在我们的应用程序中消费外部网站的好方法。许多应用程序都这样做，允许用户轻松返回到应用程序的主要部分。

在*步骤 6*中，我们使用箭头函数将`onPress`属性中的函数绑定到当前类实例的范围，因为我们在循环遍历链接数组时使用了这个函数。

在*步骤 7*中，每当按下按钮时，我们使用绑定到该按钮的标题和 URL，将它们作为参数传递，当我们导航到`Browser`屏幕时。 *步骤 11*中的`navigationOptions`使用相同的标题值作为屏幕的标题。`navigationOptions`接受一个函数，其第一个参数是包含`navigation`的对象，该对象在导航时使用参数。在*步骤 11*中，我们从这个对象中构造导航，以便我们可以将视图的标题设置为`navigation.state.params.title`。

由于`react-navigation`提供的`StackNavigator`组件，我们得到了一个具有特定于操作系统的动画和内置返回按钮的标题。您可以阅读`StackNavigation`文档，了解有关此组件的更多信息[`reactnavigation.org/docs/stack-navigator.html`](https://reactnavigation.org/docs/stack-navigator.html)。

*第 13 步*使用传递给`BrowserScreen`组件的 URL 来使用 WebView，在 WebView 的`source`属性中使用 URL 来呈现。您可以在官方文档中找到所有可用的 WebView 属性列表，位于[`facebook.github.io/react-native/docs/webview.html`](https://facebook.github.io/react-native/docs/webview.html)。

# 链接到网站和其他应用程序

我们已经学会了如何使用`WebView`将第三方网站呈现为我们应用程序的嵌入部分。然而，有时候，我们可能希望使用原生浏览器打开网站，链接到其他原生系统应用程序（如电子邮件、电话和短信），甚至深层链接到一个完全独立的应用程序。

在这个配方中，我们将通过原生浏览器和应用程序内的浏览器模态链接到外部网站，创建到电话和消息应用程序的链接，并创建一个深层链接，将打开 Slack 应用程序并自动加载[gitconnected.com](http://gitconnected.com) Slack 群中的#general 频道。

您需要在真实设备上运行此应用程序，以便在此应用程序中打开使用设备系统应用程序的链接，例如电子邮件、电话和短信链接。根据我的经验，这在模拟器中是行不通的。

# 准备工作

让我们为这个配方创建一个新的应用程序。我们将其称为`linking-app`。

# 如何做到...

1.  让我们从打开`App.js`并添加我们将要使用的导入开始：

```jsx
import React from 'react';
import { StyleSheet, Text, View, TouchableOpacity, Platform } from 'react-native';
import { Linking } from 'react-native';
import { WebBrowser } from 'expo';
```

1.  接下来，让我们添加一个`App`组件和一个`state`对象。在这个应用程序中，`state`对象将包含我们在这个配方中将使用的所有链接，放在一个名为`links`的数组中。请注意，每个`links`对象中的`url`属性都附有一个协议（`tel`、`mailto`、`sms`等）。设备使用这些协议来正确处理每个链接：

```jsx
export default class App extends React.Component {
  state = {
    links: [
      {
        title: 'Call Support',
        url: 'tel:+12025550170',
        type: 'phone'
      },
      {
        title: 'Email Support',
        url: 'mailto:support@email.com',
        type: 'email',
      },
      {
        title: 'Text Support',
        url: 'sms:+12025550170',
        type: 'text message',
      },
      {
        title: 'Join us on Slack',
        url: 'slack://channel?team=T5KFMSASF&id=C5K142J57',
        type: 'slack deep link',
      },
      {
        title: 'Visit Site (internal)',
        url: 'https://google.com',
        type: 'internal link'
      },
      {
        title: 'Visit Site (external)',
        url: 'https://google.com',
        type: 'external link'
      }
    ]
  }

}
```

在文本支持和呼叫支持按钮中使用的电话号码是在撰写时未使用的号码，由[`fakenumber.org/`](https://fakenumber.org/)生成。这个号码很可能仍然未被使用，但这可能会发生变化。请随意为这些链接使用不同的虚假号码，只需确保保持协议不变。

1.  接下来，让我们为我们的应用程序添加`render`函数。这里的 JSX 很简单：我们从上一步中的`state.links`数组中映射，将每个传递给我们在下一步中定义的`renderButton`函数：

```jsx
  render() {
    return(
      <View style={styles.container}>
        <View style={styles.buttonList}>
          {this.state.links.map(this.renderButton)}
        </View>
      </View>
    );
  }
```

1.  让我们来构建上一步中使用的`renderButton`方法。对于每个链接，我们使用`TouchableOpacity`创建一个按钮，并将`onPress`属性设置为执行`handleButtonPress`并传递`button`属性：

```jsx
  renderButton = (button, index) => {
    return(
      <TouchableOpacity
        key={index}
        onPress={() => this.handleButtonPress(button)}
        style={styles.button}
      >
        <Text style={styles.text}>{button.title}</Text>
      </TouchableOpacity>
    );
  }
```

1.  接下来，我们可以构建`handleButtonPress`函数。在这里，我们将使用`links`数组中每个对象中添加的`type`属性。如果类型是`'internal link'`，我们希望使用 Expo 的`WebBrowser`组件的`openBrowserAsync`方法在我们的应用程序中打开 URL，并且对于其他所有情况，我们将使用 React Native 的`Linking`组件的`openURL`方法。

如果`openURL`调用出现问题，并且 URL 使用了`slack://`协议，这意味着设备不知道如何处理该协议，可能是因为 Slack 应用未安装。我们将使用`handleMissingApp`函数来处理这个问题，我们将在下一步中添加它：

```jsx
  handleButtonPress(button) {
    if (button.type === 'internal link') {
      WebBrowser.openBrowserAsync(button.url);
    } else {
      Linking.openURL(button.url).catch(({ message }) => {
        if (message.includes('slack://')) {
          this.handleMissingApp();
        }
      });
    }
  }
```

1.  现在我们可以创建我们的`handleMissingApp`函数。在这里，我们使用 React Native 助手`Platform`，它提供有关应用程序运行的平台的信息。`Platform.OS`将始终返回操作系统，对于手机，应该始终解析为`'ios'`或`'android'`。您可以在官方文档中阅读有关`Platform`功能的更多信息[`facebook.github.io/react-native/docs/platform-specific-code.html`](https://facebook.github.io/react-native/docs/platform-specific-code.html)。

如果 Slack 应用的链接不像预期那样工作，我们将再次使用`Linking.openURL`，这次是为了在适合设备的应用商店中打开应用程序：

```jsx
  handleMissingApp() {
    if (Platform.OS === 'ios') {
      Linking.openURL(`https://itunes.apple.com/us/app/id618783545`);
    } else {
      Linking.openURL(
        `https://play.google.com/store/applications/details?id=com.Slack`
      );
    }
  }
```

1.  我们的应用程序还没有任何样式，所以让我们添加一些。这里没有什么花哨的东西，只是将按钮居中对齐在屏幕中，着色和居中文本，并在每个按钮上提供填充：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    justifyContent: 'center',
    alignItems: 'center',
  },
  buttonList: {
    flex: 1,
    justifyContent: 'center',
  },
  button: {
    margin: 10,
    backgroundColor: '#c0392b',
    borderRadius: 3,
    padding: 10,
    paddingRight: 30,
    paddingLeft: 30,
  },
  text: {
    color: '#fff',
    textAlign: 'center',
  },
});
```

1.  这就是这个应用程序的全部内容。一旦我们加载应用程序，应该会有一列按钮，代表我们的每个链接。`Call Support`和`Email Support`按钮在 iOS 模拟器上不起作用。在真实设备上运行此示例，以查看所有链接正常工作。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/1890e7a8-6817-493e-8dc8-4b1be726e421.png)

# 它是如何工作的...

在*步骤 2*中，我们定义了应用程序使用的所有链接。每个链接对象都有一个`type`属性，我们在*步骤 5*中定义的`handleButtonPress`方法中使用它。

这个 `handleButtonPress` 函数使用链接的类型来确定将使用两种策略中的哪一种。如果链接的类型是 `'internal link'`，我们希望在应用程序内部弹出一个模态框，使用设备浏览器打开链接。为此，我们可以使用 Expo 的 `WebBrowser` 助手，将 URL 传递给它的 `openBrowserAsync` 方法。如果链接的类型是 `'external link'`，我们将使用 React Native 的 `Linking` 助手打开链接。这让您可以看到从应用程序中打开网站的不同方式。

`Linking` 助手还可以处理除了 HTTP 和 HTTPS 之外的其他协议。通过在传递给 `Linking.openURL` 的链接中简单地使用适当的协议，我们可以打开电话 (`tel:`)、短信 (`sms:`) 或电子邮件 (`mailto:`)。

`Linking.openURL` 也可以处理到其他应用程序的深层链接，只要您要链接到的应用程序具有相应的协议，例如我们如何使用 `slack://` 协议打开 Slack。有关 Slack 的深层链接协议以及您可以使用它做什么的更多信息，请访问他们的文档 [`api.slack.com/docs/deep-linking`](https://api.slack.com/docs/deep-linking)。

在 *步骤 5* 中，我们通过调用 `Linking.openURL` 引起的任何错误，检查错误是否是由 Slack 协议引起的 `message.includes('slack://')`，如果是，我们知道 Slack 应用程序未安装在设备上。在这种情况下，我们触发 `handleMissingApp`，使用由 `Platform.OS` 确定的适当链接打开 Slack 的应用商店链接。

# 另请参阅

`Linking` 模块的官方文档可以在 [`docs.expo.io/versions/latest/guides/linking.html`](https://docs.expo.io/versions/latest/guides/linking.html) 找到。

# 创建一个表单组件

大多数应用程序都需要一种输入数据的方式，无论是一个简单的注册和登录表单，还是一个具有许多输入字段和控件的更复杂的组件。

在这个示例中，我们将创建一个表单组件来处理文本输入。我们将使用不同的键盘收集数据，并显示包含结果信息的警报消息。

# 准备工作

我们需要创建一个空的应用。让我们把它命名为 `user-form`。

# 如何做...

1.  让我们首先打开 `App.js` 并添加我们的导入。导入包括我们稍后将构建的 `UserForm` 组件：

```jsx
import React from 'react';
import {
 Alert,
 StyleSheet,
 ScrollView,
 SafeAreaView,
 Text,
 TextInput,
} from 'react-native';

import UserForm from './UserForm';
```

1.  由于这个组件将非常简单，我们将为我们的`App`创建一个无状态组件。我们将只在`UserForm`组件的`ScrollView`中渲染一个顶部工具栏：

```jsx
const App = () => (
  <SafeAreaView style={styles.main}>
    <Text style={styles.toolbar}>Fitness App</Text>
    <ScrollView style={styles.content}>
      <UserForm />
    </ScrollView>
  </SafeAreaView>
);

const styles = StyleSheet.create({
  // Defined in a later step
});

export default App; 
```

1.  我们需要为这些组件添加一些样式。我们将添加一些颜色和填充，还将把`main`类设置为`flex: 1`，以填充屏幕的其余部分：

```jsx
const styles = StyleSheet.create({
  main: {
    flex: 1,
    backgroundColor: '#ecf0f1',
  },
  toolbar: {
    backgroundColor: '#1abc9c',
    padding: 20,
    color: '#fff',
    fontSize: 20,
  },
  content: {
    padding: 10,
  },
});
```

1.  我们已经定义了主要的`App`组件。现在让我们开始实际的表单工作。让我们在项目的基础上创建一个名为`UserForm`的新目录，并添加一个`index.js`文件。然后，我们将为这个类导入所有的依赖项：

```jsx
import React, { Component } from 'react';
import {
  Alert,
  StyleSheet,
  View,
  Text,
  TextInput,
  TouchableOpacity,
} from 'react-native';
```

1.  这个类将渲染输入并跟踪数据。我们将把数据保存在`state`对象上，所以我们将从初始化`state`作为空对象开始：

```jsx
export default class UserForm extends Component { 
  state = {}; 

  // Defined in a later step
} 

const styles = StyleSheet.create({ 
 // Defined in a later step
});
```

1.  在`render`方法中，我们将定义我们想要显示的组件，这种情况下是三个文本输入和一个按钮。我们将定义一个`renderTextfield`方法，它接受一个配置对象作为参数。我们将定义字段的`name`、`placeholder`和应该在输入上使用的`keyboard`类型。此外，我们还调用一个`renderButton`方法，它将渲染保存按钮：

```jsx
  render() {
    return (
      <View style={styles.panel}>
        <Text style={styles.instructions}>
          Please enter your contact information
        </Text>
        {this.renderTextfield({ name: 'name', placeholder: 'Your 
        name' })}
        {this.renderTextfield({ name: 'phone', placeholder: 'Your
        phone number', keyboard: 'phone-pad' })}
        {this.renderTextfield({ name: 'email', placeholder: 'Your 
        email address', keyboard: 'email-address'})}
        {this.renderButton()}
      </View>
    );
  }
```

1.  要渲染文本字段，我们将在`renderTextfield`方法中使用`TextInput`组件。这个`TextInput`组件由 React Native 提供，在 iOS 和 Android 上都可以使用。`keyboardType`属性允许我们设置要使用的键盘。在两个平台上有四种可用的键盘，分别是`default`、`numeric`、`email-address`和`phone-pad`：

```jsx
  renderTextfield(options) {
    return (
      <TextInput
        style={styles.textfield}
        onChangeText={(value) => this.setState({ [options.name]: 
        value })}
        placeholder={options.label}
        value={this.state[options.name]}
        keyboardType={options.keyboard || 'default'}
      />
    );
  }
```

1.  我们已经知道如何渲染按钮并响应`Press`操作。如果这不清楚，我建议阅读第三章中的*使用主题支持创建可重用按钮*配方，*实现复杂用户界面-第一部分*：

```jsx
  renderButton() {
    return (
      <TouchableOpacity
        onPress={this.handleButtonPress}
        style={styles.button}
      >
        <Text style={styles.buttonText}>Save</Text>
      </TouchableOpacity>
    );
  }
```

1.  我们需要定义`onPressButton`回调。为简单起见，我们将只显示一个带有我们在`state`对象上的输入数据的警报：

```jsx
  handleButtonPress = () => {
    const { name, phone, email } = this.state;

    Alert.alert(`User's data`,`Name: ${name}, Phone: ${phone}, 
    Email: ${email}`);
  }
```

1.  我们几乎完成了这个配方！我们需要做的就是应用一些样式-一些颜色、填充和边距；真的没什么花哨的：

```jsx
const styles = StyleSheet.create({
 panel: {
  backgroundColor: '#fff',
  borderRadius: 3,
  padding: 10,
  marginBottom: 20,
 },
 instructions: {
  color: '#bbb',
  fontSize: 16,
  marginTop: 15,
  marginBottom: 10,
 },
 textfield: {
  height: 40,
  marginBottom: 10,
 },
 button: {
  backgroundColor: '#34495e',
  borderRadius: 3,
  padding: 12,
  flex: 1,
 },
 buttonText: {
  textAlign: 'center',
  color: '#fff',
  fontSize: 16,
 },
});
```

1.  如果我们运行我们的应用程序，我们应该能够看到一个在 Android 和 iOS 上都使用本机控件的表单，这是预期的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d8fe94c6-7280-457d-9e40-bd332add30b9.png)当在模拟器上运行应用程序时，您可能无法看到由`keyboardType`定义的键盘。在真实设备上运行应用程序，以确保`keyboardType`正确地为每个`TextInput`更改键盘。

# 工作原理...

在*步骤 8*中，我们定义了`TextInput`组件。在 React（和 React Native）中，我们可以使用两种类型的输入：受控和未受控组件。在这个示例中，我们正在使用受控输入组件，这是 React 团队推荐的。

受控组件将有一个`value`属性，并且组件将始终显示`value`属性的内容。这意味着我们需要一种方法在用户开始输入时更改值。如果我们不更新该值，那么输入框中的文本永远不会改变，即使用户尝试输入东西。

为了更新`value`，我们可以使用`onChangeText`回调并设置新值。在这个例子中，我们使用状态来跟踪数据，并在状态上设置一个新的键，其中包含输入的内容。

另一方面，一个未受控制的组件将不会有一个分配的`value`属性。我们可以使用`defaultValue`属性分配一个初始值。未受控制的组件有它们自己的状态，我们可以使用`onChangeText`回调来获取它们的值，就像我们可以使用受控组件一样。


# 第五章：实施复杂用户界面-第三部分

在本章中，我们将涵盖以下示例：

+   创建地图应用程序

+   创建音频播放器

+   创建图像轮播

+   将推送通知添加到您的应用程序

+   实施基于浏览器的身份验证

# 介绍

在本章中，我们将介绍您可能需要添加到应用程序的一些更高级功能。本章中我们将构建的应用程序包括构建完全功能的音频播放器，地图集成以及实施基于浏览器的身份验证，以便您的应用程序可以连接到开发人员的公共 API。

# 创建地图应用程序

使用移动设备是一种便携式体验，因此地图是许多 iOS 和 Android 应用程序的常见部分并不奇怪。您的应用程序可能需要告诉用户他们在哪里，他们要去哪里，或者其他用户实时在哪里。

在这个示例中，我们将制作一个简单的应用程序，该应用程序在 Android 上使用 Google Maps，在 iOS 上使用 Apple 的地图应用程序，以显示以用户位置为中心的地图。我们将使用 Expo 的`Location`辅助库来获取用户的纬度和经度，并将使用这些数据来使用 Expo 的`MapView`组件渲染地图。`MapView`是由 Airbnb 创建的 react-native-maps 包的 Expo 版本，因此您可以期望 react-native-maps 文档适用，该文档可以在[`github.com/react-community/react-native-maps`](https://github.com/react-community/react-native-maps)找到。

# 准备工作

我们需要为这个示例创建一个新的应用程序。让我们称之为`map-app`。由于此示例中的用户图标将使用自定义图标，因此我们还需要一个图像。我使用了 Maico Amorim 的图标 You Are Here，您可以从[`thenounproject.com/term/you-are-here/12314/`](https://thenounproject.com/term/you-are-here/12314/)下载。随意使用任何您喜欢的图像来代表用户图标。将图像保存到项目根目录的`assets`文件夹中。

# 如何做...

1.  我们将首先打开`App.js`并添加我们的导入：

```jsx
import React from 'react';
import {
  Location,
  Permissions,
  MapView,
  Marker
} from 'expo';
import {
  StyleSheet,
  Text,
  View,
} from 'react-native';
```

1.  接下来，让我们定义`App`类和初始`state`。在这个示例中，`state`只需要跟踪用户的`位置`，我们将其初始化为`null`：

```jsx
export default class App extends Component {
  state = {
    location: null
  }
  // Defined in following steps
}
```

1.  接下来，我们将定义`componentDidMount`生命周期钩子，它将要求用户授予访问设备地理位置的权限。如果用户授予应用程序使用其位置的权限，返回的对象将具有一个值为`'granted'`的`status`属性。如果授予了权限，我们将使用`this.getLocation`获取用户的位置，这是在下一步中定义的：

```jsx
  async componentDidMount() {
    const permission = await Permissions.askAsync(Permissions.LOCATION);
    if (permission.status === 'granted') {
      this.getLocation();
    }
  }
```

1.  `getLocation`函数很简单。它使用`Location`组件的`getCurrentPositionAsync`方法从设备的 GPS 中获取位置信息，然后将该位置信息保存到`state`中。该信息包含用户的纬度和经度，在渲染地图时我们将使用它：

```jsx
  async getLocation() {
    let location = await Location.getCurrentPositionAsync({});
    this.setState({
      location
    });
  }
```

1.  现在，让我们使用该位置信息来渲染我们的地图。首先，我们将检查`state`上是否保存了一个`location`。如果是，我们将渲染`MapView`，否则渲染`null`。我们需要设置的唯一属性来渲染地图是`initialRegion`属性，它定义了地图在首次渲染时应该显示的位置。我们将在具有保存到`state`的纬度和经度的对象上传递这个属性，并使用`latitudeDelta`和`longitudeDelta`定义一个起始缩放级别：

```jsx
  renderMap() {
    return this.state.location ?
      <MapView
        style={styles.map}
        initialRegion={{
          latitude: this.state.location.coords.latitude,
          longitude: this.state.location.coords.longitude,
          latitudeDelta: 0.09,
          longitudeDelta: 0.04,
        }}
      >
        // Map marker is defined in next step
      </MapView> : null
  }
```

1.  在`MapView`中，我们需要在用户当前位置添加一个标记。`Marker`组件是`MapView`的父组件的一部分，所以在 JSX 中，我们将定义`MapView.Marker`作为`MapView`元素的子元素。这个元素需要用户的位置、标题和描述以在图标被点击时显示，以及通过`image`属性定义一个自定义图像：

```jsx
      <MapView
        style={styles.map}
        initialRegion={{
          latitude: this.state.location.coords.latitude,
          longitude: this.state.location.coords.longitude,
          latitudeDelta: 0.09,
          longitudeDelta: 0.04,
        }}
      >
 <MapView.Marker
 coordinate={this.state.location.coords}
 title={"User Location"}
 description={"You are here!"}
 image={require('./assets/you-are-here.png')}
 />
      </MapView> : null
```

1.  现在，让我们定义我们的`render`函数。它简单地在一个包含的`View`元素中渲染地图：

```jsx
 render() {
  return (
   <View style={styles.container}>
    {this.renderMap()}
   </View>
  );
 }
```

1.  最后，让我们添加我们的样式。我们将在容器和地图上都将`flex`设置为`1`，以便两者都填满屏幕：

```jsx
const styles = StyleSheet.create({
 container: {
  flex: 1,
 backgroundColor: '#fff',
 },
 map: {
  flex: 1
 }
});
```

1.  现在，如果我们打开应用程序，我们将看到一个地图在设备提供的位置上渲染了我们自定义的用户图标！不幸的是，Google 地图集成可能无法在 Android 模拟器中工作，因此可能需要一个真实的设备来测试应用程序的 Android 实现。查看本食谱末尾的*还有更多...*部分以获取更多信息。不要惊讶，iOS 应用程序在模拟器上运行时显示用户的位置在旧金山；这是由于 Xcode 位置默认设置的工作方式。在真实的 iOS 设备上运行它，以查看它是否渲染了你的位置：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d2f4cb86-df1e-47df-bab4-248b6f2f34a3.png)

# 工作原理...

通过利用 Expo 提供的`MapView`组件，在你的 React Native 应用中实现地图现在比以前简单直接得多。

在*步骤 3*中，我们利用了`Permissions`帮助库。`Permissions`有一个叫做`askAsync`的方法，它接受一个参数，定义了你的应用想要从用户那里请求什么类型的权限。`Permissions`还为你可以从用户那里请求的每种类型的权限提供了常量。这些权限类型包括`LOCATION`，`NOTIFICATIONS`（我们将在本章后面使用），`CAMERA`，`AUDIO_RECORDING`，`CONTACTS`，`CAMERA_ROLL`和`CALENDAR`。由于我们在这个示例中需要位置，我们传入了常量`Permissions.LOCATION`。一旦`askAsync`返回 promise 解析，返回对象将有一个`status`属性和一个`expiration`属性。如果用户已经允许了请求的权限，`status`将被设置为`'granted'`字符串。如果被授予，我们将触发我们的`getLocation`方法。

在*步骤 4*中，我们定义了从设备 GPS 获取位置的函数。我们调用`Location`组件的`getCurrentPositionAsync`方法。这个方法将返回一个带有`coords`属性和`timestamp`属性的对象。`coords`属性让我们可以访问`latitude`和`longitude`，以及`altitude`，`accuracy`（位置的不确定性半径，以米为单位测量），`altitudeAccuracy`（高度值的精度，以米为单位（仅限 iOS）），`heading`和`speed`。一旦接收到，我们将位置保存到`state`中，这样`render`函数将被调用，我们的地图将被渲染。

在*步骤 5*中，我们定义了`renderMap`方法来渲染地图。首先，我们检查是否有位置，如果有，我们渲染`MapView`元素。这个元素只需要我们定义一个属性的值：`initialRegion`。这个属性接受一个带有四个属性的对象：`latitude`，`longitude`，`latitudeDelta`和`longitudeDelta`。我们将`latitude`和`longitude`设置为`state`对象中的值，并为`latitudeDelta`和`longitudeDelta`提供初始值。这两个属性决定了地图应该以什么初始缩放级别进行渲染；这个数字越大，地图就会显示得越远。我建议尝试这两个值，看看它们如何影响渲染的地图。

在*步骤 6*中，我们通过将`MapView.Marker`元素作为`MapView`元素的子元素添加到地图上。我们通过将保存在`state`（`state.location.coords`）上的信息传递给`coords`属性来定义坐标，并在被点击时为标记的弹出窗口设置了`title`和`description`。我们还可以通过在`image`属性中使用`require`语句内联我们的自定义图像来轻松定义自定义图钉。

# 还有更多...

如前所述，您可以阅读 react-native-maps 项目的文档，了解这个优秀库的更多功能（[`github.com/react-community/react-native-maps`](https://github.com/react-community/react-native-maps)）。例如，您可以使用 Google 地图样式向导（[`mapstyle.withgoogle.com/`](https://mapstyle.withgoogle.com/)）轻松自定义 Google 地图的外观，生成`mapStyle` JSON 对象，然后将该对象传递给`MapView`组件的`customMapStyle`属性。或者，您可以使用`Polygon`和`Circle`组件向地图添加几何形状。

一旦您准备部署您的应用程序，您需要采取一些后续步骤来确保地图在 Android 上正常工作。您可以阅读 Expo 文档中有关如何使用`MapView`组件部署到独立 Android 应用程序的详细信息：[`docs.expo.io/versions/latest/sdk/map-view#deploying-to-a-standalone-app-on-android`](https://docs.expo.io/versions/latest/sdk/map-view#deploying-to-a-standalone-app-on-android)。

在 Android 模拟器中渲染 Google 地图可能会出现问题。您可以参考以下 GitHub 链接获取更多信息：[`github.com/react-native-community/react-native-maps/issues/942`](https://github.com/react-native-community/react-native-maps/issues/942)。

# 创建音频播放器

音频播放器是许多应用程序内置的常见界面。无论您的应用程序需要在设备上本地播放音频文件还是从远程位置流式传输音频，Expo 的`Audio`组件都可以帮助您。

在这个食谱中，我们将构建一个功能齐全的基本音频播放器，具有播放/暂停、下一曲和上一曲功能。为简单起见，我们将硬编码我们将使用的曲目信息，但在现实世界的情况下，您可能会使用类似我们定义的对象：一个带有曲目标题、专辑名称、艺术家名称和远程音频文件 URL 的对象。我从互联网档案馆的现场音乐档案中随机选择了三个现场曲目（[`archive.org/details/etree`](https://archive.org/details/etree)）。

# 准备工作

我们需要为这个食谱创建一个新的应用。让我们称之为`audio-player`。

# 如何做...

1.  让我们从打开`App.js`并添加我们需要的依赖开始：

```jsx
import React, { Component } from 'react';
import { Audio } from 'expo';
import { Feather } from '@expo/vector-icons';
import {
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
  Dimensions
} from 'react-native';
```

1.  音频播放器需要音频来播放。我们将创建一个`playlist`数组来保存音频曲目。每个曲目由一个带有`title`、`artist`、`album`和`uri`的对象表示：

```jsx
const playlist = [
  {
    title: 'People Watching',
    artist: 'Keller Williams',
    album: 'Keller Williams Live at The Westcott Theater on 2012-09-22',
    uri: 'https://ia800308.us.archive.org/7/items/kwilliams2012-09-22.at853.flac16/kwilliams2012-09-22at853.t16.mp3'
  },
  {
   title: 'Hunted By A Freak',
   artist: 'Mogwai',
   album: 'Mogwai Live at Ancienne Belgique on 2017-10-20',
   uri: 'https://ia601509.us.archive.org/17/items/mogwai2017-10-20.brussels.fm/Mogwai2017-10-20Brussels-07.mp3'
  },
  {
    title: 'Nervous Tic Motion of the Head to the Left',
    artist: 'Andrew Bird',
    album: 'Andrew Bird Live at Rio Theater on 2011-01-28',
    uri: 'https://ia800503.us.archive.org/8/items/andrewbird2011-01-28.early.dr7.flac16/andrewbird2011-01-28.early.t07.mp3'
  }
];
```

1.  接下来，我们将定义我们的`App`类和初始的`state`对象，其中包含四个属性：

+   `isPlaying`用于定义播放器是正在播放还是暂停

+   `playbackInstance`用于保存`Audio`实例

+   `volume`和`currentTrackIndex`用于当前播放的曲目

+   `isBuffering`用于在曲目在播放开始时缓冲时显示`缓冲中...`消息

如下所示的代码：

```jsx
export default class App extends Component {
  state = {
    isPlaying: false,
    playbackInstance: null,
    volume: 1.0,
    currentTrackIndex: 0,
    isBuffering: false,
  }

 // Defined in following steps
}
```

1.  让我们接下来定义`componentDidMount`生命周期钩子。我们将使用这个方法通过`setAudioModeAsync`方法配置`Audio`组件，传入一个带有一些推荐设置的`options`对象。这些将在食谱末尾的*它是如何工作...*部分进行更多讨论。之后，我们将使用`loadAudio`加载音频，定义在下一步中：

```jsx
 async componentDidMount() {
    await Audio.setAudioModeAsync({
      allowsRecordingIOS: false,
      playThroughEarpieceAndroid: true,
      interruptionModeIOS: Audio.INTERRUPTION_MODE_IOS_DO_NOT_MIX,
      playsInSilentModeIOS: true,
      shouldDuckAndroid: true,
      interruptionModeAndroid: 
      Audio.INTERRUPTION_MODE_ANDROID_DO_NOT_MIX,
    });
    this.loadAudio();
  }
```

1.  `loadAudio`函数将处理我们播放器的音频加载。首先，我们将创建一个新的`Audio.Sound`实例。然后，我们将在我们的新`Audio`实例上调用`setOnPlaybackStatusUpdate`方法，传入一个处理程序，每当实例内的播放状态发生变化时将被调用。最后，我们在实例上调用`loadAsync`，传入一个来自`playlist`数组的源，以及一个带有音量和`state`的`isPlaying`值的`shouldPlay`属性的状态对象。第三个参数决定我们是否希望在播放之前等待文件下载完成，因此我们传入`false`：

```jsx
async loadAudio() {
    const playbackInstance = new Audio.Sound();
    const source = {
      uri: playlist[this.state.currentTrackIndex].uri
    }
    const status = {
      shouldPlay: this.state.isPlaying,
      volume: this.state.volume,
    };
    playbackInstance
      .setOnPlaybackStatusUpdate(
        this.onPlaybackStatusUpdate
      );
    await playbackInstance.loadAsync(source, status, false);
    this.setState({
      playbackInstance
    });
  }
```

1.  我们仍然需要定义处理状态更新的回调。在这个函数中，我们需要做的就是将从`setOnPlaybackStatusUpdate`函数调用中传入的`status`参数上的`isBuffering`值设置到`state`上的`isBuffering`值：

```jsx
  onPlaybackStatusUpdate = (status) => {
    this.setState({
      isBuffering: status.isBuffering
    });
  }
```

1.  我们的应用现在知道如何从`playlist`数组中加载音频文件，并更新`state`中加载的音频文件的当前缓冲状态，我们稍后将在`render`函数中使用它向用户显示消息。现在剩下的就是为播放器本身添加行为。首先，我们将处理播放/暂停状态。`handlePlayPause`方法检查`this.state.isPlaying`的值，以确定是否应播放或暂停曲目，并相应地调用`playbackInstance`上的关联方法。最后，我们需要更新`state`中的`isPlaying`的值：

```jsx
  handlePlayPause = async () => {
    const { isPlaying, playbackInstance } = this.state;
    isPlaying ? await playbackInstance.pauseAsync() : await playbackInstance.playAsync();
    this.setState({
      isPlaying: !isPlaying
    });
  }
```

1.  接下来，让我们定义处理跳转到上一首曲目的函数。首先，我们通过调用`unloadAsync`从`playbackInstance`中清除当前曲目。然后，我们将`state`中的`currentTrackIndex`值更新为当前值减一，或者如果我们在`playlist`数组的开头，则更新为`0`。然后，我们将调用`this.loadAudio`来加载正确的曲目：

```jsx
  handlePreviousTrack = async () => {
    let { playbackInstance, currentTrackIndex } = this.state;
    if (playbackInstance) {
      await playbackInstance.unloadAsync();
      currentTrackIndex === 0 ? currentTrackIndex = playlist.length
      - 1 : currentTrackIndex -= 1;
      this.setState({
        currentTrackIndex
      });
      this.loadAudio();
    }
  }
```

1.  毫不奇怪，`handleNextTrack`与前面的函数相同，但这次我们要么将当前索引加`1`，要么如果我们在`playlist`数组的末尾，则将索引设置为`0`：

```jsx
  handleNextTrack = async () => {
    let { playbackInstance, currentTrackIndex } = this.state;
    if (playbackInstance) {
      await playbackInstance.unloadAsync();
      currentTrackIndex < playlist.length - 1 ? currentTrackIndex +=
      1 : currentTrackIndex = 0;
      this.setState({
        currentTrackIndex
      });
      this.loadAudio();
    }
  } 
```

1.  现在是时候定义我们的`render`函数了。在我们的 UI 中，我们需要三个基本部分：当曲目正在播放但仍在缓冲时显示“缓冲中…”的消息，用于显示当前曲目信息的部分，以及用于保存播放器控件的部分。当且仅当`this.state.isBuffering`和`this.state.isPlaying`都为`true`时，“缓冲中…”消息才会显示。歌曲信息是通过`renderSongInfo`方法呈现的，我们将在*步骤 12*中定义：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Text style={[styles.largeText, styles.buffer]}>
          {this.state.isBuffering && this.state.isPlaying ? 
          'Buffering...' : null}
        </Text>
        {this.renderSongInfo()}
        <View style={styles.controls}>

          // Defined in next step.

        </View>
      </View>
    );
  }
```

1.  播放器控件由三个`TouchableOpacity`按钮元素组成，每个按钮都有来自 Feather 图标库的相应图标。您可以在第三章中找到有关使用图标的更多信息，*实现复杂用户界面-第一部分*。根据`this.state.isPlaying`的值，我们将确定是显示播放图标还是暂停图标：

```jsx
        <View style={styles.controls}>
 <TouchableOpacity
 style={styles.control}
 onPress={this.handlePreviousTrack}
 >
 <Feather name="skip-back" size={32} color="#fff"/>
 </TouchableOpacity>
 <TouchableOpacity
 style={styles.control}
 onPress={this.handlePlayPause}
 >
 {this.state.isPlaying ?
 <Feather name="pause" size={32} color="#fff"/> :
 <Feather name="play" size={32} color="#fff"/>
 }
 </TouchableOpacity>
 <TouchableOpacity
 style={styles.control}
 onPress={this.handleNextTrack}
 >
 <Feather name="skip-forward" size={32} color="#fff"/>
 </TouchableOpacity>
        </View>
```

1.  `renderSongInfo` 方法返回用于显示当前播放的曲目相关元数据的基本 JSX：

```jsx
  renderSongInfo() {
    const { playbackInstance, currentTrackIndex } = this.state;
    return playbackInstance ?
    <View style={styles.trackInfo}>
      <Text style={[styles.trackInfoText, styles.largeText]}>
        {playlist[currentTrackIndex].title}
      </Text>
      <Text style={[styles.trackInfoText, styles.smallText]}>
        {playlist[currentTrackIndex].artist}
      </Text>
      <Text style={[styles.trackInfoText, styles.smallText]}>
        {playlist[currentTrackIndex].album}
      </Text>
    </View>
    : null;
  }
```

1.  现在剩下的就是添加样式。这里定义的样式现在已经是老生常谈了，不超出居中、颜色、字体大小以及添加填充和边距的范围：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#191A1A',
    alignItems: 'center',
    justifyContent: 'center',
  },
  trackInfo: {
    padding: 40,
    backgroundColor: '#191A1A',
  },
  buffer: {
    color: '#fff'
  },
  trackInfoText: {
    textAlign: 'center',
    flexWrap: 'wrap',
    color: '#fff'
  },
  largeText: {
    fontSize: 22
  },
  smallText: {
    fontSize: 16
  },
  control: {
    margin: 20
  },
  controls: {
    flexDirection: 'row'
  }
});
```

1.  您现在可以在模拟器中查看您的应用，应该有一个完全正常工作的音频播放器！请注意，Android 模拟器中的音频播放速度可能太慢，无法正常工作，并且可能听起来非常杂乱。在真实的 Android 设备上打开应用程序以听到音轨正常播放：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/21780eb9-bf05-4182-bad9-c53978ff19b1.png)

# 工作原理...

在*步骤 4*中，一旦应用程序完成加载，我们就在`componentDidMount`方法中对`Audio`组件进行了初始化。`Audio`组件的`setAudioModeAsync`方法将一个选项对象作为其唯一参数。

让我们回顾一些我们在这个配方中使用的选项：

+   `interruptionModeIOS` 和 `interruptionModeAndroid` 设置了您的应用中的音频应该如何与设备上其他应用程序的音频进行交互。我们分别使用了`Audio`组件的`INTERRUPTION_MODE_IOS_DO_NOT_MIX`和`INTERRUPTION_MODE_ANDROID_DO_NOT_MIX`枚举来声明我们的应用音频应该中断任何其他正在播放音频的应用程序。

+   `playsInSilentModeIOS` 是一个布尔值，用于确定当设备处于静音模式时，您的应用是否应该播放音频。

+   `shouldDuckAndroid` 是一个布尔值，用于确定当另一个应用的音频中断您的应用时，您的应用的音频是否应该降低音量（减小）。虽然此设置默认为`true`，但我已将其添加到配方中，以便您知道这是一个选项。

在*步骤 5*中，我们定义了`loadAudio`方法，该方法在这个示例中承担了大部分工作。首先，我们创建了`Audio.Sound`类的新实例，并将其保存到`playbackInstance`变量中以供以后使用。接下来，我们设置将传递到`playbackInstance`的`loadAsync`函数的`source`和`status`变量，用于实际加载音频文件。在`source`对象中，我们将`uri`属性设置为`playlist`数组中对象中的相应`uri`属性的索引存储在`this.state.currentTrackIndex`中。在`status`对象中，我们将音量设置为`state`上保存的`volume`值，并将`shouldPlay`设置为一个布尔值，用于确定音频是否应该播放，最初设置为`this.state.isPlaying`。由于我们希望流式传输远程 MP3 文件而不是等待整个文件下载，因此我们将第三个参数`downloadFirst`设置为`false`。

在调用`loadAsync`方法之前，我们首先调用了`playbackInstance`的`setOnPlaybackStatusUpdate`，它接受一个回调函数，当`playbackInstance`的状态发生变化时应该被调用。我们在*步骤 6*中定义了该处理程序。该处理程序简单地将回调的`status`参数中的`isBuffering`值保存到`state`的`isBuffering`属性中，这将触发重新渲染，相应地更新 UI 中的'缓冲中...'消息。

在*步骤 7*中，我们定义了`handlePlayPause`函数，用于在应用程序中切换播放和暂停功能。如果有曲目正在播放，`this.state.isPlaying`将为`true`，因此我们将在`playbackInstance`上调用`pauseAsync`函数，否则，我们将调用`playAsync`来重新开始播放音频。一旦我们播放或暂停，我们就会更新`state`上的`isPlaying`的值。

在*步骤 8*和*步骤 9*中，我们创建了处理跳转到下一首和上一首曲目的函数。每个函数根据需要增加或减少`this.state.currentTrackIndex`的值，因此在每个函数底部调用`this.loadAudio`时，它将加载与`playlist`数组中对象相关联的曲目的新索引。

# 还有更多...

我们当前应用程序的功能比大多数音频播放器更基本，但您可以利用所有工具来构建功能丰富的音频播放器。例如，您可以通过在`setOnPlaybackStatusUpdate`回调中利用`status`参数上的`positionMillis`属性在 UI 中显示当前曲目时间。或者，您可以使用 React Native 的`Slider`组件允许用户调整音量或播放速率。Expo 的`Audio`组件提供了构建出色音频播放器应用程序的所有基本组件。

# 创建图像轮播

有各种应用程序使用图像轮播。每当有一组图像，您希望用户能够浏览时，轮播很可能是实现任务的最有效的 UI 模式之一。

在 React Native 社区中有许多软件包用于处理轮播的创建，但根据我的经验，没有一个比 react-native-snap-carousel ([`github.com/archriss/react-native-snap-carousel`](https://github.com/archriss/react-native-snap-carousel))更稳定或更多功能。该软件包为自定义轮播的外观和行为提供了出色的 API，并支持 Expo 应用程序开发，无需弹出。您可以通过 Carousel 组件的`layout`属性轻松更改幻灯片在轮播框架中滑入和滑出时的外观，截至 3.6 版本，您甚至可以创建自定义插值！

虽然您不仅限于使用此软件包显示图像，但我们将构建一个仅显示图像的轮播，以及一个标题，以保持配方简单。我们将使用优秀的免费许可照片网站[unsplash.com](http://www.unsplash.com)通过托管在[source.unsplash.com](http://source.unsplash.com)的 Unsplash Source 项目获取用于在我们的轮播中显示的随机图像。Unsplash Source 允许您轻松地从 Unsplash 请求随机图像，而无需访问官方 API。您可以访问 Unsplash Source 网站以获取有关其工作原理的更多信息。

# 准备工作

我们需要为这个配方创建一个新的应用程序。让我们把这个应用叫做“轮播”。

# 如何做...

1.  我们将从打开`App.js`并导入依赖项开始：

```jsx
import React, { Component } from 'react';
import {
  SafeAreaView,
  StyleSheet,
  Text,
  View,
  Image,
  TouchableOpacity,
  Picker,
  Dimensions,
} from 'react-native';
import Carousel from 'react-native-snap-carousel';
```

1.  接下来，让我们定义 `App` 类和初始 `state` 对象。`state` 有三个属性：一个布尔值，用于指示我们当前是否正在显示轮播图，一个 `layoutType` 属性，用于设置我们轮播图的布局样式，以及一个我们稍后将用于从 Unsplash Source 获取图像的 `imageSearchTerms` 数组。请随意更改 `imageSearchTerms` 数组：

```jsx
export default class App extends React.Component {
  state = {
    showCarousel: false,
    layoutType: 'default',
    imageSearchTerms: [
      'Books',
      'Code',
      'Nature',
      'Cats',
    ]
  }

  // Defined in following steps
}
```

1.  接下来，让我们定义 `render` 方法。我们只需检查 `this.state.showCorousel` 的值，然后相应地显示轮播图或控件：

```jsx
  render() {
    return (
      <SafeAreaView style={styles.container}>
        {this.state.showCarousel ?
          this.renderCarousel() :
          this.renderControls()
        }
      </SafeAreaView>
    );
  }
```

1.  接下来，让我们创建 `renderControls` 函数。这将是用户在首次打开应用程序时看到的布局，包括用于在轮播图中选择布局类型的 React Native `Picker` 和用于打开轮播图的按钮。`Picker` 有三个可用选项：默认、tinder 和 stack：

```jsx
  renderControls = () => {
    return(
      <View style={styles.container}>
        <Picker
          selectedValue={this.state.layoutType}
          style={styles.picker}
          onValueChange={this.updateLayoutType}
        >
          <Picker.Item label="Default" value="default" />
          <Picker.Item label="Tinder" value="tinder" />
          <Picker.Item label="Stack" value="stack" />
        </Picker>
        <TouchableOpacity
          onPress={this.toggleCarousel}
          style={styles.openButton}
        >
          <Text style={styles.openButtonText}>Open Carousel</Text>
        </TouchableOpacity>
      </View>
    )
  } 
```

1.  让我们定义 `toggleCarousel` 函数。该函数只是将 `state` 上的 `showCarousel` 的值设置为其相反值。通过定义一个切换函数，我们可以使用相同的函数来打开和关闭轮播图：

```jsx
  toggleCarousel = () => {
    this.setState({
      showCarousel: !this.state.showCarousel
    });
  }
```

1.  类似地，`updateLayoutType` 方法只是更新 `state` 上的 `layoutType` 到从 `Picker` 组件传入的 `layoutType` 值：

```jsx
  updateLayoutType = (layoutType) => {
    this.setState({
      layoutType
    });
  }
```

1.  `renderCarousel` 函数返回轮播图的标记。它由一个用于关闭轮播图的按钮和 `Carousel` 组件本身组成。该组件接受一个 `layout` 属性，由 `Picker` 设置。它还有一个 `data` 属性，用于接收应该循环播放每个轮播幻灯片的数据，以及一个 `renderItem` 回调函数，用于处理每个单独幻灯片的渲染：

```jsx
 renderCarousel = () => {
  return(
   <View style={styles.carouselContainer}>
    <View style={styles.closeButtonContainer}>
     <TouchableOpacity
      onPress={this.toggleCarousel}
      style={styles.button}
     >
      <Text style={styles.label}>x</Text>
     </TouchableOpacity>
   </View>
   <Carousel
    layout={this.state.layoutType}
    data={this.state.imageSearchTerms}
    renderItem={this.renderItem}
    sliderWidth={350}
    itemWidth={350}
   >
   </Carousel>
  </View>
  );
 }
```

1.  我们仍然需要处理每个幻灯片的渲染的函数。该函数接收一个对象参数，其中包含传递给 `data` 属性的数组中的下一个项目。我们将返回一个使用 `item` 参数值从 Unsplash Source 获取 `350x350` 大小的随机项目的 `Image` 组件。我们还将添加一个 `Text` 元素来显示正在显示的图像类型：

```jsx
  renderItem = ({item}) => {
    return (
      <View style={styles.slide}>
        <Image
          style={styles.image}
          source={{ uri: `https://source.unsplash.com/350x350/?
          ${item}`}}
        />
        <Text style={styles.label}>{item}</Text>
      </View>
    );
  }
```

1.  我们需要的最后一件事是一些样式来布局我们的 UI。`container`样式适用于主要包装`SafeAreaView`元素，因此我们将`justifyContent`设置为`'space-evenly'`，以便`Picker`和`TouchableOpacity`组件填满屏幕。为了在屏幕右上角显示关闭按钮，我们将`flexDirection: 'row`和`justifyContent: 'flex-end'`应用于包装元素。其余的样式只是尺寸、颜色、填充、边距和字体大小：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'column',
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'space-evenly',
  },
  carouselContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#474747'
  },
  closeButtonContainer: {
    width: 350,
    flexDirection: 'row',
    justifyContent: 'flex-end'
  },
  slide: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  image: {
    width:350,
    height: 350,
  },
  label: {
    fontSize: 30,
    padding: 40,
    color: '#fff',
    backgroundColor: '#474747'
  },
  openButton: {
    padding: 10,
    backgroundColor: '#000'
  },
  openButtonText: {
    fontSize: 20,
    padding: 20,
    color: '#fff',
  },
  closeButton: {
    padding: 10
  },
  picker: {
    height: 150,
    width: 100,
    backgroundColor: '#fff'
  }
});
```

1.  我们已经完成了我们的轮播应用程序。它可能不会赢得任何设计奖，但它是一个具有流畅、本地感觉行为的工作轮播应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/611a73a0-ec0a-4a09-bf88-c819dbece914.png)

# 它是如何工作的...

在*步骤*4 中，我们定义了`renderControls`函数，该函数在应用程序首次启动时呈现 UI。这是我们第一次使用`Picker`组件的示例。它是 React Native 核心库的一部分，并提供下拉类型选择器，用于在许多应用程序中选择选项。`selectedValue`属性是与选择器中当前选定项目绑定的值。通过将其设置为`this.state.layoutType`，我们将默认选择为“默认”布局，并在选择不同的`Picker`项目时保持值同步。选择器中的每个项目都由`Picker.Item`组件表示。其`label`属性定义了项目的显示文本，`value`属性表示项目的字符串值。由于我们将`onValueChange`属性与`updateLayoutType`函数一起使用，每当选择新项目时都会调用它，从而相应地更新`this.state.layoutType`。

在*步骤*7 中，我们定义了轮播图的 JSX。轮播图的`data`和`renderItem`属性是必需的，并且一起工作以呈现轮播图中的每个幻灯片。当实例化轮播图时，传递到`data`属性的数组将被循环处理，并且`renderItem`回调函数将针对区域中的每个项目调用，该项目作为参数传递到`renderItem`中。我们还设置了`sliderWidth`和`itemWidth`属性，这些属性对于水平轮播图是必需的。

在*步骤 8*中，我们定义了`renderItem`函数，该函数对传递到`data`中的数组中的每个条目调用。我们将返回的`Image`组件的源设置为 Unsplash 源 URL，该 URL 将返回所请求类型的随机图像。

# 还有更多...

有一些事情我们可以做来改进这个配方。我们可以利用`Image.prefetch()`方法在打开轮播图之前下载第一张图片，这样图片就可以立即准备好，或者添加一个输入框，允许用户选择自己的图片搜索词。

react-native-snap-carousel 包为 React Native 应用程序提供了一个很好的构建多媒体轮播图的方式。我们在这里没有时间涵盖的一些功能包括视差图片和自定义分页。对于有冒险精神的开发人员，该包提供了一种创建自定义插值的方式，使您可以创建超出三种内置布局之外的自定义布局。

# 将推送通知添加到您的应用程序

推送通知是提供应用程序和用户之间持续反馈循环的一种很好的方式，不断提供与用户相关的应用程序特定数据。消息应用程序在有新消息到达时发送通知。提醒应用程序显示通知以提醒用户在特定时间或位置执行任务。播客应用程序可以使用通知通知用户新的一集已经发布。购物应用程序可以使用通知提醒用户查看限时优惠。

推送通知是增加用户互动和留存的一种有效方式。如果您的应用程序使用与时间敏感或基于事件的数据，推送通知可能是一项有价值的资产。在这个配方中，我们将使用 Expo 的推送通知实现，它简化了一些在原生 React Native 项目中所需的设置。如果您的应用程序需要非 Expo 项目，我建议考虑使用 react-native-push-notification 包 [`github.com/zo0r/react-native-push-notification`](https://github.com/zo0r/react-native-push-notification)。

在这个配方中，我们将制作一个非常简单的消息应用程序，并添加推送通知。我们将请求适当的权限，然后将推送通知令牌注册到我们将构建的 Express 服务器上。我们还将渲染一个`TextInput`，让用户输入消息。当用户按下发送按钮时，消息将被发送到我们的服务器，服务器将通过 Expo 的推送通知服务器向所有已在我们的 Express 服务器上注册令牌的设备发送来自应用程序的消息的推送通知。

由于 Expo 内置的推送通知服务，为每个本机设备创建通知的复杂工作被转移到了 Expo 托管的后端。我们在这个教程中构建的 Express 服务器只会将每个推送通知的 JSON 对象传递给 Expo 后端，其余工作都会被处理。Expo 文档中的以下图表([`docs.expo.io/versions/latest/guides/push-notifications`](https://docs.expo.io/versions/latest/guides/push-notifications))说明了推送通知的生命周期：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c8f284dd-63b9-47fe-8645-0c9a31c52862.png)图片来源：[`docs.expo.io/versions/latest/guides/push-notifications/`](https://docs.expo.io/versions/latest/guides/push-notifications/)

虽然使用 Expo 实现推送通知比起其他方式少了一些设置工作，但技术的要求仍然意味着我们需要运行一个服务器来处理注册和发送通知，这意味着这个教程会比大多数教程长一些。让我们开始吧！

# 准备工作

在这个应用程序中，我们需要做的第一件事是请求设备允许使用推送通知。不幸的是，推送通知权限在模拟器中无法正常工作，因此需要一个真实设备来测试这个应用程序。

我们还需要能够从本地主机之外的地址访问推送通知服务器。在真实环境中，推送通知服务器已经有一个公共 URL，但在开发环境中，最简单的解决方案是创建一个隧道，将开发推送通知服务器暴露给互联网。为此目的，我们将使用 ngrok 工具，因为它是一个成熟、强大且非常易于使用的解决方案。您可以在[`ngrok.com`](https://ngrok.com)了解更多关于该软件的信息。

首先，使用以下命令通过`npm`全局安装`ngrok`：

```jsx
npm i -g ngrok
```

安装完成后，您可以通过使用`ngrok`和`https`参数在互联网和本地机器上的端口之间创建隧道：

```jsx
ngrok https [port-to-expose]
```

我们将在本教程中稍后使用这个命令来暴露开发服务器。

让我们为这个教程创建一个新的应用程序。我们将其命名为`push-notifications`。我们将需要三个额外的 npm 包来完成这个教程：`express`用于推送通知服务器，`esm`用于在服务器上使用 ES6 语法支持，`expo-server-sdk`用于处理推送通知。使用`yarn`安装它们：

```jsx
yarn add express esm expo-server-sdk
```

或者，使用`npm`安装它们：

```jsx
npm install express esm expo-server-sdk --save
```

# 如何做...

1.  让我们从构建`App`开始。我们将通过向`App.js`添加我们需要的依赖项来开始：

```jsx
import React from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity
} from 'react-native';
import { Permissions, Notifications } from 'expo';
```

1.  我们将在服务器上声明两个 API 端点的常量，但是`url`将在教程后面运行服务器时由`ngrok`生成，因此我们将在那时更新这些常量的值：

```jsx
const PUSH_REGISTRATION_ENDPOINT = 'http://generated-ngrok-url/token';
const MESSAGE_ENPOINT = 'http://generated-ngrok-url/message';
```

1.  让我们创建`App`组件并初始化`state`对象。我们需要一个`notification`属性来保存`Notifications`侦听器接收到的通知，我们将在后面的步骤中定义：

```jsx
export default class App extends React.Component {
  state = {
    notification: null,
    messageText: ''
  }

 // Defined in following steps
}
```

1.  让我们定义一个方法来处理将推送通知令牌注册到服务器。我们将通过`Permissions`组件上的`askAsync`方法向用户请求通知权限。如果获得了权限，就从`Notifications`组件的`getExpoPushTokenAsync`方法获取设备上的令牌：

```jsx
  registerForPushNotificationsAsync = async () => {
    const { status } = await Permissions.askAsync(Permissions.NOTIFICATIONS);
    if (status !== 'granted') {
      return;
    }
    let token = await Notifications.getExpoPushTokenAsync();

    // Defined in following steps
  }
```

1.  一旦我们获得了适当的令牌，我们将将其发送到推送通知服务器进行注册。然后，我们将向`PUSH_REGISTRATION_ENDPOINT`发出`POST`请求，发送`token`对象和`user`对象到请求体中。我已经在用户对象中硬编码了值，但在真实应用中，这将是您为当前用户存储的元数据：

```jsx
  registerForPushNotificationsAsync = async () => {
    // Defined in above step

 fetch(PUSH_REGISTRATION_ENDPOINT, {
 method: 'POST',
 headers: {
 'Accept': 'application/json',
 'Content-Type': 'application/json',
 },
 body: JSON.stringify({
 token: {
 value: token,
 },
 user: {
 username: 'warly',
 name: 'Dan Ward'
 },
 }),
 });

    // Defined in next step
  }
```

1.  注册令牌后，我们将设置一个事件侦听器来监听应用程序在打开和前台运行时发生的任何通知。在某些情况下，我们需要手动处理来自传入推送通知的信息显示。查看本教程末尾的*工作原理...*部分，了解为什么需要这样做以及如何利用它。我们将在下一步中定义处理程序：

```jsx
  registerForPushNotificationsAsync = async () => {
    // Defined in above steps

    this.notificationSubscription = 
    Notifications.addListener(this.handleNotification);
  }
```

1.  每当收到新通知时，`handleNotification`方法将被运行。我们将只是将传递给此回调的新通知存储在`state`对象中，以便稍后在`render`函数中使用：

```jsx
handleNotification = (notification) => {
  this.setState({ notification });
}
```

1.  我们希望我们的应用程序在启动时请求使用推送通知的权限，并注册推送通知令牌。我们将利用`componentDidMount`生命周期钩子来运行我们的`registerForPushNotificationsAsync`方法：

```jsx
  componentDidMount() {
    this.registerForPushNotificationsAsync();
  }
```

1.  UI 将非常简单，以保持教程简单。它由一个用于消息文本的`TextInput`，一个用于发送消息的发送按钮，以及一个用于显示通知的`View`组成：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <TextInput
          value={this.state.messageText}
          onChangeText={this.handleChangeText}
          style={styles.textInput}
        />
        <TouchableOpacity
          style={styles.button}
          onPress={this.sendMessage}
        >
          <Text style={styles.buttonText}>Send</Text>
        </TouchableOpacity>
        {this.state.notification ?
          this.renderNotification()
        : null}
      </View>
    );
  }
```

1.  在上一步中定义的`TextInput`组件缺少其`onChangeText`属性所需的方法。让我们接下来创建这个方法。它只是将用户输入的文本保存到`this.state.messageText`中，以便可以被`value`属性和其他地方使用。

```jsx
  handleChangeText = (text) => {
    this.setState({ messageText: text });
  }
```

1.  `TouchableOpacity`组件的`onPress`属性调用`sendMessage`方法，在用户按下按钮时发送消息文本。在这个函数中，我们将获取消息文本并将其`POST`到我们推送通知服务器上的`MESSAGE_ENDPOINT`。服务器将处理后续操作。消息发送后，我们将清除`state`中的`messageText`属性。

```jsx
  sendMessage = async () => {
    fetch(MESSAGE_ENPOINT, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        message: this.state.messageText,
      }),
    });
    this.setState({ messageText: '' });
  } 
```

1.  `App`所需的最后一部分是样式。这些样式很简单，现在应该都很熟悉了。

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#474747',
    alignItems: 'center',
    justifyContent: 'center',
  },
  textInput: {
    height: 50,
    width: 300,
    borderColor: '#f6f6f6',
    borderWidth: 1,
    backgroundColor: '#fff',
    padding: 10
  },
  button: {
    padding: 10
  },
  buttonText: {
    fontSize: 18,
    color: '#fff'
  },
  label: {
    fontSize: 18
  }
});
```

1.  React Native 应用程序部分完成后，让我们继续进行服务器部分。首先，在项目的根目录中创建一个新的`server`文件夹，并在其中创建一个`index.js`文件。让我们首先导入`express`来运行服务器，以及`expo-server-sdk`来处理注册和发送推送通知。我们将创建一个 Express 服务器应用并将其存储在`app`常量中，以及一个 Expo 服务器 SDK 的新实例存储在`expo`常量中。我们还将添加一个`savedPushTokens`数组来存储在 React Native 应用中注册的任何令牌，以及一个`PORT_NUMBER`常量来指定服务器要运行的端口号。

```jsx
import express from 'express';
import Expo from 'expo-server-sdk';

const app = express();
const expo = new Expo();

let savedPushTokens = [];
const PORT_NUMBER = 3000;

```

1.  我们的服务器需要公开两个端点（一个用于注册令牌，一个用于接受来自 React Native 应用的消息），因此我们将创建两个函数，当命中这些路由时将执行这些函数。首先我们将定义`saveToken`函数。它只是获取一个令牌，检查它是否存储在`savedPushTokens`数组中，如果尚未存储，则将其推送到数组中。

```jsx
const saveToken = (token) => {
  if (savedPushTokens.indexOf(token === -1)) {
    savedPushTokens.push(token);
  }
}
```

1.  我们服务器需要的另一个函数是在接收来自 React Native 应用的消息时发送推送通知的处理程序。我们将遍历所有保存在`savedPushTokens`数组中的令牌，并为每个令牌创建一个消息对象。每个消息对象的标题为`收到消息！`，这将以粗体显示在推送通知中，消息文本作为通知的正文。

```jsx
const handlePushTokens = (message) => {
  let notifications = [];
  for (let pushToken of savedPushTokens) {
    if (!Expo.isExpoPushToken(pushToken)) {
      console.error(`Push token ${pushToken} is not a valid Expo push token`);
      continue;
    }
    notifications.push({
      to: pushToken,
      sound: 'default',
      title: 'Message received!',
      body: message,
      data: { message }
    })
  }

  // Defined in following step
}
```

1.  一旦我们有了消息数组，我们可以将它们发送到 Expo 的服务器，然后 Expo 的服务器将把推送通知发送到所有注册设备。我们将通过 expo 服务器的`chunkPushNotifications`和`sendPushNotificationsAsync`方法发送消息数组，并根据情况将成功收据或错误记录到服务器控制台上。关于这个工作原理的更多信息，请参阅本教程末尾的*工作原理...*部分：

```jsx
const handlePushTokens = (message) => {
  // Defined in previous step

 let chunks = expo.chunkPushNotifications(notifications);

 (async () => {
 for (let chunk of chunks) {
 try {
 let receipts = await expo.sendPushNotificationsAsync(chunk);
 console.log(receipts);
 } catch (error) {
 console.error(error);
 }
 }
 })();
}
```

1.  现在我们已经定义了处理推送通知和消息的函数，让我们通过创建 API 端点来公开这些函数。如果您对 Express 不熟悉，它是一个在 Node 中运行 Web 服务器的强大且易于使用的框架。您可以通过基本路由文档快速了解基本路由的基础知识：[`expressjs.com/en/starter/basic-routing.html`](https://expressjs.com/en/starter/basic-routing.html)。

我们将使用 JSON 数据，因此第一步将是使用`express.json()`调用应用 JSON 解析器中间件：

```jsx
app.use(express.json());
```

1.  尽管我们实际上不会使用服务器的根路径(`/`)，但定义一个是个好习惯。我们将只回复一条消息，表示服务器正在运行：

```jsx
app.get('/', (req, res) => {
  res.send('Push Notification Server Running');
});
```

1.  首先，让我们实现保存推送通知令牌的端点。当向`/token`端点发送`POST`请求时，我们将把令牌值传递给`saveToken`函数，并返回一个声明已收到令牌的响应：

```jsx
app.post('/token', (req, res) => {
  saveToken(req.body.token.value);
  console.log(`Received push token, ${req.body.token.value}`);
  res.send(`Received push token, ${req.body.token.value}`);
});
```

1.  同样，`/message`端点将从请求体中获取`message`并将其传递给`handlePushTokens`函数进行处理。然后，我们将发送一个响应，表示已收到消息：

```jsx
app.post('/message', (req, res) => {
  handlePushTokens(req.body.message);
  console.log(`Received message, ${req.body.message}`);
  res.send(`Received message, ${req.body.message}`);
});
```

1.  服务器的最后一部分是对服务器实例调用 Express 的`listen`方法，这将启动服务器：

```jsx
app.listen(PORT_NUMBER, () => {
  console.log('Server Online on Port ${PORT_NUMBER}');
});
```

1.  我们需要一种启动服务器的方法，因此我们将在`package.json`文件中添加一个名为 serve 的自定义脚本。打开`package.json`文件并更新它，使其具有一个新的`serve`脚本的 scripts 对象。添加了这个之后，我们可以通过`yarn run serve`命令或`npm run serve`命令使用 yarn 运行服务器或使用 npm 运行服务器。`package.json`文件应该看起来像这样：

```jsx
{
  "main": "node_modules/expo/AppEntry.js",
  "private": true,
  "dependencies": {
    "esm": "³.0.28",
    "expo": "²⁷.0.1",
    "expo-server-sdk": "².3.3",
    "express": "⁴.16.3",
    "react": "16.3.1",
    "react-native": "https://github.com/expo/react-native/archive/sdk-27.0.0.tar.gz"
  },
 "scripts": {
 "serve": "node -r esm server/index.js"
 }
}
```

1.  我们已经把所有的代码放在了一起，让我们来使用它吧！如前所述，推送通知权限在模拟器上无法正常工作，因此需要一个真实设备来测试推送通知功能。首先，我们将通过运行以下命令来启动我们新创建的服务器：

```jsx
 yarn run serve
 npm run serve
```

应该会看到我们在*步骤 21*中定义的`listen`方法调用中定义的`Server Online`消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/410ec457-c70d-469f-a885-07a9b98c66bc.png)

1.  接下来，我们需要运行`ngrok`来将我们的服务器暴露到互联网上。打开一个新的终端窗口，并使用以下命令创建一个`ngrok`隧道：

```jsx
 ngrok http 3000
```

您应该在终端中看到`ngrok`界面。这显示了`ngrok`生成的 URL。在这种情况下，`ngrok`正在将我的位于`http://localhost:3000`的服务器转发到 URL`http://ddf558bd.ngrok.io`。让我们复制该 URL：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/bd7818a2-f122-4c7c-8107-9b599085a897.png)

1.  您可以通过在浏览器中访问生成的 URL 来测试服务器是否正在运行并且可以从互联网访问。直接导航到此 URL 的行为与导航到`http://localhost:3000`完全相同，这意味着我们在上一步中定义的`GET`端点应该运行。该函数返回`Push Notification Server Running`字符串，并应在浏览器中显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/9261690a-6d72-4e3d-8fb6-f9295621a921.png)

1.  现在我们已经确认服务器正在运行，让我们更新 React Native 应用程序以使用正确的服务器 URL。在*步骤 2*中，我们添加了常量来保存我们的 API 端点，但是我们还没有正确的 URL。让我们更新这些 URL 以反映`ngrok`生成的隧道 URL：

```jsx
const PUSH_REGISTRATION_ENDPOINT = 'http://ddf558bd.ngrok.io/token';
const MESSAGE_ENPOINT = 'http://ddf558bd.ngrok.io/message';
```

1.  如前所述，您需要在真实设备上运行此应用程序，以便权限请求能够正确工作。一旦您打开应用程序，设备应该会提示您是否要允许该应用程序发送通知：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/767c5400-2b08-4fdb-a32d-b8c7d958b410.jpg)

1.  一旦选择了“允许”，推送通知令牌将被发送到服务器的`/token`端点以进行保存。这也应该在服务器终端中打印出相关的`console.log`语句与保存的令牌。在这种情况下，我的 iPhone 的推送令牌是字符串。

`ExponentPushToken[g5sIEbOm2yFdzn5VdSSy9n]`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d7795f23-8301-4b8a-a9b2-194f92f7d37e.png)

1.  此时，如果您有第二个 Android 或 iOS 设备，请继续在该设备上打开 React Native 应用程序。如果没有，不用担心。还有另一种简单的方法可以测试我们的推送通知功能是否正常工作，而无需使用第二个设备。

1.  您可以使用 React Native 应用程序的文本输入向其他注册设备发送消息。如果您有第二个已向服务器注册令牌的设备，它应该会收到与新发送的消息相对应的推送通知。您还应该在服务器上看到两个新的`console.log`实例：一个显示接收到的消息，另一个显示从 Expo 服务器返回的`receipts`数组。数组中的每个 receipt 对象都将具有一个`status`属性，如果操作成功，则该属性的值为`'ok'`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/edda5d92-00c3-4943-a4b3-f253ab9fe1a2.png)

1.  如果您没有第二个设备进行测试，可以使用 Expo 的推送通知工具，托管在[`expo.io/dashboard/notifications`](https://expo.io/dashboard/notifications)。只需从服务器终端复制`push token`并将其粘贴到标有 EXPO PUSH TOKEN（来自您的应用程序）的输入中。要模拟从我们的 React Native 应用程序发送的消息，请将 MESSAGE TITLE 设置为`Message received!`，将 MESSAGE BODY 设置为您想要发送的消息文本，并选中 Play Sound 复选框。如果愿意，还可以通过提供具有`"message"`键和您的消息文本值的 JSON 对象来模拟`data`对象，例如`{ "message": "This is a test message." }`。然后接收到的消息应该看起来像这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/02ed0e2b-79a7-4e72-a36c-8281d44c2e37.jpg)

# 它是如何工作的...

我们在这里构建的配方有点牵强，但请求权限、注册令牌、接受应用程序数据以及响应应用程序数据发送推送通知所需的核心概念都在这里。

在*步骤 4*中，我们定义了`registerForPushNotificationsAsync`函数的第一部分。我们首先通过`Permissions.askAsync`方法询问用户是否允许我们通过`Permissions.NOTIFICATIONS`常量发送通知。然后我们保存了解析后的`return`对象的`status`属性，如果用户授予权限，则该属性的值将为`'granted'`。如果我们没有获得权限，我们将立即`return`；否则，我们通过调用`getExpoPushTokenAsync`从 Expo 的`Notifications`组件中获取令牌。此函数返回一个令牌字符串，格式如下：

```jsx
 ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]
```

在*步骤 5*中，我们定义了对服务器注册端点（`/token`）的`POST`调用。此函数将令牌发送到请求正文中，然后使用在*步骤 14*中定义的`saveToken`函数在服务器上保存。

在*步骤 6*中，我们创建了一个事件监听器，用于监听任何新的推送通知。这是通过调用`Notifications.addListener`并传入一个回调函数来实现的，每次接收到新通知时都会执行该函数。在 iOS 设备上，系统设计为仅在发送推送通知的应用程序未打开并处于前台时才产生推送通知。这意味着如果您尝试在用户当前使用您的应用程序时发送推送通知，他们将永远不会收到。

为了解决这个问题，Expo 建议手动在应用程序内显示推送通知数据。`Notifications.addListener`方法就是为了满足这个需求而创建的。当接收到推送通知时，传递给`addListener`的回调将被执行，并将新的通知对象作为参数接收。在*步骤 7*中，我们将此通知保存到`state`中，以便相应地重新渲染 UI。在本教程中，我们只在`Text`组件中显示了消息文本，但您也可以使用模态框进行更类似通知的呈现。

在*步骤 11*中，我们创建了`sendMessage`函数，该函数将存储在`state`中的消息文本发布到服务器的`/message`端点。这将执行在*步骤 15*中定义的`handlePushToken`服务器函数。

在*步骤 13*中，我们开始在服务器上使用 Express 和 Expo 服务器 SDK。通过直接调用`express()`创建一个新的服务器，通常按惯例将其命名为`app`。我们能够使用`new Expo()`创建一个新的 Expo 服务器 SDK 实例，并将其存储在`expo`常量中。稍后我们使用 Expo 服务器 SDK 使用`expo`发送推送通知，在*步骤 17*到*步骤 20*中使用`app`定义路由，并在*步骤 22*中通过调用`app.listen()`启动服务器。

在*步骤 14*中，我们定义了`saveToken`函数，当 React Native 应用程序使用`/token`端点注册令牌时将执行该函数。此函数将传入的令牌保存到`savedPushTokens`数组中，以便稍后在用户发送消息时使用。在真实的应用程序中，这通常是您希望将令牌保存到持久性数据库（如 SQL、MongoDB 或 Firebase 数据库）的地方。

在*步骤 15*中，我们开始定义`handlePushTokens`函数，当 React Native 应用程序使用`/message`端点时运行。该函数循环处理`savedPushTokens`数组。使用 Expo 服务器 SDK 的`isExpoPushToken`方法检查每个令牌的有效性，该方法接受一个令牌并返回`true`如果令牌有效。如果无效，我们将在服务器控制台上记录错误。如果有效，我们将在下一步的批处理中将新的通知对象推送到本地`notifications`数组中。每个通知对象都需要一个`to`属性，其值设置为有效的 Expo 推送令牌。所有其他属性都是可选的。我们设置的可选属性如下：

+   **声音**：可以默认播放默认通知声音，或者对于无声音为`null`

+   **标题**：推送通知的标题，通常以粗体显示

+   **正文**：推送通知的正文

+   **数据**：自定义数据 JSON 对象

在*步骤 16*中，我们使用 Expo 服务器 SDK 的`chunkPushNotifications`实例方法创建了一个优化发送到 Expo 推送通知服务器的数据块数组。然后我们循环遍历这些块，并通过`expo.sendPushNotificationsAsync`方法将每个块发送到 Expo 的推送通知服务器。它返回一个解析为每个推送通知的收据数组的 promise。如果过程成功，数组中将有一个`{ status: 'ok' }`对象。

这个端点的行为比真实服务器可能要简单，因为大多数消息应用程序处理消息的方式可能更复杂。至少，可能会有一个接收者列表，指定注册设备将接收特定推送通知。逻辑被故意保持简单，以描绘基本流程。

在*步骤 18*中，我们在服务器上定义了第一个可访问的路由，即根（`/`）路径。Express 提供了`get`和`post`辅助方法，用于轻松地创建`GET`和`POST`请求的 API 端点。回调函数接收请求对象和响应对象作为参数。所有服务器 URL 都需要响应请求；否则，请求将超时。响应通过响应对象上的`send`方法发送。这个路由不处理任何数据，所以我们只返回指示我们的服务器正在运行的字符串。

在*步骤 19*和*步骤 20*中，我们为`/token`和`/message`定义了`POST`端点，分别执行`saveToken`和`handlePushTokens`。我们还在每个端点中添加了`console.log`语句，以便在服务器终端上记录令牌和消息，便于开发。

在*步骤 21*中，我们在 Express 服务器上定义了`listen`方法，启动了服务器。第一个参数是要监听请求的端口号，第二个参数是回调函数，通常用于在服务器终端上`console.log`一条消息，表示服务器已启动。

在*步骤 22*中，我们在项目的`package.json`文件中添加了一个自定义脚本。可以通过在`package.json`文件中添加一个`scripts`键，将可以在终端中运行的任何命令设置为自定义 npm 脚本，其键是自定义脚本的名称，值是运行该自定义脚本时应执行的命令。在这个示例中，我们定义了一个名为`serve`的自定义脚本，运行`node -r esm server/index.js`命令。这个命令使用我们在本示例开始时安装的`esm` npm 包在 Node 中运行我们的服务器文件（`server/index.js`）。自定义脚本可以使用`npm`执行：

```jsx
npm run [custom-script-name]
```

也可以使用`yarn`执行：

```jsx
yarn run [custom-script-name]
```

# 还有更多...

推送通知可能会很复杂，但幸运的是，Expo 以多种方式简化了这个过程。Expo 的推送通知服务有很好的文档，涵盖了通知定时、其他语言中的 Expo 服务器 SDK 以及如何通过 HTTP/2 实现通知的具体内容。我鼓励你在[`docs.expo.io/versions/latest/guides/push-notifications`](https://docs.expo.io/versions/latest/guides/push-notifications)上阅读更多。

# 实现基于浏览器的身份验证

在第八章的*使用 Facebook 登录*示例中，我们将介绍使用 Expo 的`Facebook`组件创建登录工作流程，以提供用户的基本 Facebook 账户信息给我们的应用程序。Expo 还提供了一个`Google`组件，用于获取用户的 Google 账户信息的类似功能。但是，如果我们想要创建一个使用来自不同网站的账户信息的登录工作流程，我们该怎么办呢？在这种情况下，Expo 提供了`AuthSession`组件。

`AuthSession` 是建立在 Expo 的 `WebBrowser` 组件之上的，我们在第四章 *实现复杂用户界面 - 第二部分* 中已经使用过。典型的登录流程包括四个步骤：

1.  用户启动登录流程

1.  网页浏览器打开到登录页面

1.  认证提供程序在成功登录时提供重定向

1.  React Native 应用程序处理重定向

在这个应用程序中，我们将使用 Spotify API 通过用户登录来获取我们应用程序的 Spotify 账户信息。前往 [`beta.developer.spotify.com/dashboard/applications`](https://beta.developer.spotify.com/dashboard/applications) 创建一个新的 Spotify 开发者账户（如果你还没有），以及一个新的应用。应用可以取任何你喜欢的名字。创建完应用后，你会在应用信息中看到一个客户端 ID 字符串。在构建 React Native 应用程序时，我们将需要这个 ID。

# 准备就绪

我们需要一个新的应用程序来完成这个教程。让我们将应用命名为 `browser-based-auth`。

重定向 URI 也需要在之前创建的 Spotify 应用中列入白名单。重定向应该是 `https://auth.expo.io/@YOUR_EXPO_USERNAME/YOUR_APP_SLUG` 的形式。由于我的 Expo 用户名是 `warlyware`，并且由于我们正在构建的这个 React Native 应用程序名为 `browser-based-auth`，我的重定向 URI 是 `https://auth.expo.io/@warlyware/browser-based-auth`。请确保将其添加到 Spotify 应用的设置中的重定向 URI 列表中。

# 如何做...

1.  我们将从打开 `App.js` 并导入我们将要使用的依赖项开始。

```jsx
import React, { Component } from 'react';
import { TouchableOpacity, StyleSheet, Text, View } from 'react-native';
import { AuthSession } from 'expo';
import { FontAwesome } from '@expo/vector-icons';
```

1.  让我们也声明 `CLIENT_ID` 为一个常量，以便以后使用。复制之前创建的 Spotify 应用的客户端 ID，以便我们可以将其保存在 `CLIENT_ID` 常量中：

```jsx
const CLIENT_ID = Your-Spotify-App-Client-ID;
```

1.  让我们创建 `App` 类和初始 `state`。`userInfo` 属性将保存我们从 Spotify API 收到的用户信息，`didError` 是一个布尔值，用于跟踪登录过程中是否发生错误：

```jsx
export default class App extends React.Component {
  state = {
    userInfo: null,
    didError: false
  };

  // Defined in following steps
}
```

1.  接下来，让我们定义将用户登录到 Spotify 的方法。 `AuthSession`组件的`getRedirectUrl`方法提供了在登录后返回到 React Native 应用程序所需的重定向 URL，这是我们在本示例的*准备就绪*部分中保存在 Spotify 应用程序中的相同重定向 URI。 然后，我们将在登录请求中使用重定向 URL，我们将使用`AuthSession.startAsync`方法启动登录请求，传入一个选项对象，其中`authUrl`属性设置为用于授权用户数据的 Spotify 端点。 有关此 URL 的更多信息，请参阅本示例末尾的*它是如何工作...*部分：

```jsx
  handleSpotifyLogin = async () => {
    let redirectUrl = AuthSession.getRedirectUrl();
    let results = await AuthSession.startAsync({
      authUrl:
      `https://accounts.spotify.com/authorize?client_id=${CLIENT_ID}
      &redirect_uri=${encodeURIComponent(redirectUrl)}
      &scope=user-read-email&response_type=token`
    });

    // Defined in next step
  };
```

1.  我们将点击 Spotify 端点以进行用户身份验证的结果保存在本地`results`变量中。 如果结果对象上的`type`属性返回的不是`'success'`，那么就会发生错误，因此我们将相应地更新`state`的`didError`属性。 否则，我们将使用从授权接收到的访问令牌点击`/me`端点以获取用户信息，然后将其保存到`this.state.userInfo`中：

```jsx
  handleSpotifyLogin = async () => {

    if (results.type !== 'success') {
      this.setState({ didError: true });
    } else {
      const userInfo = await axios.get(`https://api.spotify.com/v1/me`, {
        headers: {
          "Authorization": `Bearer ${results.params.access_token}`
        }
      });
      this.setState({ userInfo: userInfo.data });
    }
  };
```

1.  现在`auth`相关的方法已经定义，让我们创建`render`函数。 我们将使用`FontAwesome` Expo 图标库来显示 Spotify 标志，添加一个按钮允许用户登录，并添加渲染错误或用户信息的方法，具体取决于`this.state.didError`的值。 一旦在`state`的`userInfo`属性上保存了数据，我们还将禁用登录按钮：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <FontAwesome
          name="spotify"
          color="#2FD566"
          size={128}
        />
        <TouchableOpacity
          style={styles.button}
          onPress={this.handleSpotifyLogin}
          disabled={this.state.userInfo ? true : false}
        >
          <Text style={styles.buttonText}>
            Login with Spotify
          </Text>
        </TouchableOpacity>
        {this.state.didError ?
          this.displayError() :
          this.displayResults()
        }
      </View>
    );
  }
```

1.  接下来，让我们定义处理错误的 JSX。 模板只是显示一个通用的错误消息，表示用户应该再试一次：

```jsx
  displayError = () => {
    return (
      <View style={styles.userInfo}>
        <Text style={styles.errorText}>
          There was an error, please try again.
        </Text>
      </View>
    );
  }
```

1.  `displayResults`函数将是一个`View`组件，如果`state`中保存了`userInfo`，则显示用户的图像，用户名和电子邮件地址，否则它将提示用户登录：

```jsx
  displayResults = () => {
    { return this.state.userInfo ? (
      <View style={styles.userInfo}>
        <Image
          style={styles.profileImage}
          source={ {'uri': this.state.userInfo.images[0].url} }
        />
        <View>
          <Text style={styles.userInfoText}>
            Username:
          </Text>
          <Text style={styles.userInfoText}>
            {this.state.userInfo.id}
          </Text>
          <Text style={styles.userInfoText}>
            Email:
          </Text>
          <Text style={styles.userInfoText}>
            {this.state.userInfo.email}
          </Text>
        </View>
      </View>
    ) : (
      <View style={styles.userInfo}>
        <Text style={styles.userInfoText}>
          Login to Spotify to see user data.
        </Text>
      </View>
    )}
  }
```

1.  这个示例的样式非常简单。 它使用了列式弹性布局，应用了 Spotify 的黑色和绿色配色方案，并添加了字体大小和边距：

```jsx
const styles = StyleSheet.create({
 container: {
  flexDirection: 'column',
  backgroundColor: '#000',
  flex: 1,
  alignItems: 'center',
  justifyContent: 'space-evenly',
 },
 button: {
  backgroundColor: '#2FD566',
  padding: 20
 },
 buttonText: {
  color: '#000',
  fontSize: 20
 },
 userInfo: {
  height: 250,
  width: 200,
  alignItems: 'center',
 },
 userInfoText: {
  color: '#fff',
  fontSize: 18
 },
 errorText: {
  color: '#fff',
  fontSize: 18
 },
 profileImage: {
  height: 64,
  width: 64,
  marginBottom: 32
 }
});
```

1.  现在，如果我们查看应用程序，我们应该能够登录到 Spotify，并看到与用于登录的帐户关联的图像，用户名和电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/5d4f47b5-36b9-4733-87ff-2fa6f8554563.png)

# 它是如何工作的...

在*步骤 4*中，我们创建了处理 Spotify 登录过程的方法。`AuthSession.startAsync`方法只需要一个`authUrl`，这是由 Spotify 开发者文档提供的。所需的四个部分是`Client-ID`，用于处理来自 Spotify 的响应的重定向 URI，指示应用程序请求的用户信息范围的`scope`参数，以及`response_type`参数为`token`。我们只需要用户的基本信息，因此我们请求了`user-read-email`的范围类型。有关所有可用范围的信息，请查看[`beta.developer.spotify.com/documentation/general/guides/scopes/`](https://beta.developer.spotify.com/documentation/general/guides/scopes/)上的文档。

在*步骤 5*中，我们完成了 Spotify 登录处理程序。如果登录不成功，我们相应地更新了`state`上的`didError`。如果成功，我们使用该响应访问 Spotify API 端点以获取用户数据（[`api.spotify.com/v1/me`](https://api.spotify.com/v1/me)）。我们根据 Spotify 的文档，使用`Bearer ${results.params.access_token}`定义了`GET`请求的`Authorization`标头来验证请求。在此请求成功后，我们将返回的用户数据存储在`userInfo` `state`对象中，这将重新呈现 UI 并显示用户信息。

深入了解 Spotify 的认证过程，您可以在[`beta.developer.spotify.com/documentation/general/guides/authorization-guide/`](https://beta.developer.spotify.com/documentation/general/guides/authorization-guide/)找到指南。

# 另请参阅

+   Expo 权限文档：[`docs.expo.io/versions/latest/sdk/permissions`](https://docs.expo.io/versions/latest/sdk/permissions)

+   Expo `MapView`文档：[`docs.expo.io/versions/latest/sdk/map-view`](https://docs.expo.io/versions/latest/sdk/map-view)

+   Airbnb 的 React Native Maps 包：[`github.com/react-community/react-native-maps`](https://github.com/react-community/react-native-maps)

+   Expo 音频文档：[`docs.expo.io/versions/latest/sdk/audio`](https://docs.expo.io/versions/latest/sdk/audio)

+   React Native Image Prefetch 文档：[`facebook.github.io/react-native/docs/image.html#prefetch`](https://facebook.github.io/react-native/docs/image.html#prefetch)

+   React Native Snap Carousel 自定义插值文档：[`github.com/archriss/react-native-snap-carousel/blob/master/doc/CUSTOM_INTERPOLATIONS.md`](https://github.com/archriss/react-native-snap-carousel/blob/master/doc/CUSTOM_INTERPOLATIONS.md)

+   Expo 推送通知文档：[`docs.expo.io/versions/latest/guides/push-notifications`](https://docs.expo.io/versions/latest/guides/push-notifications)

+   Express 基本路由指南：[`expressjs.com/en/starter/basic-routing.html`](https://expressjs.com/en/starter/basic-routing.html)

+   esm 软件包：[`github.com/standard-things/esm`](https://github.com/standard-things/esm)

+   用于 Node 的 Expo 服务器 SDK：[`github.com/expo/exponent-server-sdk-node`](https://github.com/expo/exponent-server-sdk-node)

+   ngrok 软件包：[`github.com/inconshreveable/ngrok`](https://github.com/inconshreveable/ngrok)
