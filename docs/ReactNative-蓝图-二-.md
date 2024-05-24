# ReactNative 蓝图（二）

> 原文：[`zh.annas-archive.org/md5/70729A755431D37E9DA3E2FBADC90F35`](https://zh.annas-archive.org/md5/70729A755431D37E9DA3E2FBADC90F35)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：图像分享应用

到目前为止，我们知道如何创建一个具有自定义界面的功能齐全的应用程序。您甚至学会了如何添加状态管理库来控制我们应用程序中的共享数据，以便代码库保持可维护和可扩展。

在本章中，我们将专注于使用不同的状态管理库（Redux）构建应用程序，利用相机功能，编写特定于平台的代码，并深入构建既吸引人又可用的自定义用户界面。图像分享应用将作为这些功能的一个很好的示例，并且还将为理解如何在 React Native 上构建大型应用程序奠定基础。

我们将在这个应用程序可用的两个平台上重用大部分代码：iOS 和 Android。虽然我们的大部分用户界面将是自定义的，但我们将使用`native-base`来简化 UI 元素，如图标。对于导航，我们将再次使用`react-navigation`，因为它为每个平台提供了最常用的导航：iOS 的选项卡导航和 Android 的抽屉菜单导航。最后，我们将使用`react-native-camera`来处理与设备相机的交互。这不仅会减少实现复杂性，还会为我们提供一大堆免费的功能，我们可以用来在未来扩展我们的应用程序。

对于这个应用程序，我们将模拟多个 API 调用，这样我们就不需要构建后端。当构建连接的应用程序时，这些调用应该很容易被真实的 API 替换。

# 概述

构建图像分享应用的主要要求之一是吸引人的设计。我们将遵循一些最流行的图像分享应用的设计模式，为每个平台调整这些模式，同时尽量重用尽可能多的代码，利用 React Native 的跨平台能力。

让我们首先看一下 iOS 中的用户界面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/534ac716-db52-4990-b73a-8c361ff77836.png)

主屏幕显示一个简单的标题和图像列表，包括用户图片、姓名和一个更多图标来分享图像。在底部，选项卡导航显示三个图标，代表三个主要屏幕：所有图像、我的图像和相机。

本示例应用程序中使用的所有图像都可以以任何形式使用。

当用户按下特定图像的更多图标时，将显示分享菜单。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/fadf2e92-9517-46af-8eb5-21b63152f26a.png)

这是一个标准的 iOS 组件。在模拟器上使用它并没有太多意义，最好在实际设备上进行测试。

让我们来看看第二个屏幕，我的图片：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/64fdf900-eb2c-4fc6-b9a3-77491c2b4006.png)

这是当前用户上传的所有图像的网格表示，可以通过下一个屏幕“相机”进行更新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/0a539caf-2470-4f79-970c-fc944bc37dab.png)

iOS 模拟器不支持任何相机，因此这个功能最好还是在实际设备上进行测试，尽管`react-native-camera`是完全可用的，并且在访问时会返回虚假数据。我们将使用静态图像进行测试。

这就是 iOS 的全部内容；现在让我们转到 Android 版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/93231a03-7b45-4469-add2-43c8f67841a5.png)

由于 Android 鼓励使用抽屉式导航而不是选项卡，我们将在标题中包含一个抽屉菜单图标，并且还将通过不同的图标使相机可用。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/ed1294ce-6c58-4d6a-af55-028d9624b177.png)

与 iOS 共享菜单一样，Android 也有自己的控制器，因此我们将利用这一功能，并在用户点击特定图像上的“更多”图标时包含它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/1ee3a31a-cb70-47f9-8a09-493f57fb21c0.png)

当用户点击抽屉菜单图标时，菜单将显示出来，显示三个可用屏幕。从这里，用户可以导航到我的图片屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/d60a7940-aae9-4eca-9d0f-dc1fca4de373.png)

最后，相机屏幕也可以通过抽屉菜单访问：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/5af16407-cf78-419b-9bd5-9aa948986459.png)

Android 模拟器包括一个彩色移动的正方形相机模拟，可以用于测试。然而，出于一致性的原因，我们将继续使用 iOS 版本中使用的固定图像。

在本章中，我们将涵盖以下主题：

+   React Native 中的 Redux

+   使用相机

+   特定平台的代码

+   抽屉和选项卡导航

+   与其他应用程序共享数据

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将被命名为`imageShare`，并且将可用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.44.0" imageShare
```

为了在此应用程序中使用一些包，我们将使用特定版本的 React Native（`0.44.0`）。

我们将在我们的应用程序中使用 Redux，因此我们将创建一个文件夹结构，其中可以容纳我们的`reducers`、`actions`、`components`、`screens`和`api`调用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/0a1d1a18-734d-4640-a728-d25e107c4dae.png)

此外，我们在`img`文件夹中添加了`logo.png`。对于其余部分，我们有一个非常标准的 React Native 项目。入口点将是`index.ios.js`用于 iOS 和`index.android.js`用于 Android：

```jsx
/*** index.ios.js and index.android.js ***/ 

import { AppRegistry } from 'react-native';
import App from './src/main';

AppRegistry.registerComponent('imageShare', () => App);
```

我们对这两个文件的实现是相同的，因为我们希望使用`src/main.js`作为两个平台的通用入口点。

让我们跳转到我们的`package.json`文件，了解我们应用中将有哪些依赖项：

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
                "native-base": "².1.5", "react": "16.0.0-alpha.6",
                "react-native": "0.44.0", "react-native-camera": "⁰.8.0",
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

一些依赖项，如`react-navigation`或`native-base`，是前几章的老朋友。其他依赖项，如`react-native-camera`，将在本章中首次介绍。其中一些与我们将在此应用程序中使用的状态管理库 Redux 密切相关：

+   `redux`：这是状态管理库本身

+   `react-redux`：这些是 Redux 的 React 处理程序

+   `redux-thunk`：这是处理异步操作执行的 Redux 中间件

完成安装后，我们需要链接`react-native-camera`，因为它需要在我们应用的本地部分进行一些更改：

```jsx
react-native link react-native-camera
```

在 iOS 10 及更高版本中，我们还需要修改我们的`ios/imageShare/Info.plist`以添加*相机使用说明*，这应该显示以请求在应用程序中启用相机的权限。我们需要在最后一个`</dict></plist>`之前添加这些行：

```jsx
<key>NSCameraUsageDescription</key>
<string>imageShare requires access to the camera on this device to perform this action</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>imageShare requires access to the image library on this device to perform this action</string>
```

# Redux

Redux 是基于简单原则的 JavaScript 应用程序的可预测状态容器：

+   您应用的整个状态存储在单个*存储*内的对象树中

+   更改状态树的唯一方法是发出*操作*，描述发生了什么的对象

+   为了指定操作如何转换状态树，您编写纯*减速器*

它的流行程度来自于在任何类型的代码库（前端或后端）中使用它所能产生的一致性、可测试性和开发人员体验的程度。由于其严格的单向数据流，它也很容易理解和掌握：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/3feb47a7-9010-42ab-b959-93af23628c9b.png)

用户触发和**操作**由**减速器**处理，这只是应用基于该**操作**的更改的纯函数。生成的状态保存在一个**存储**中，该存储由我们应用中的**视图**使用，以显示应用程序的当前状态。

Redux 是本书范围之外的一个复杂主题，但它将在本书的一些章节中广泛使用，因此可能有益于查看它们的官方文档（[`redux.js.org/`](http://redux.js.org/)）以熟悉这个状态管理库的基本概念。

Redux 的一些基本概念将在我们的`src/main.js`文件中使用。

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
}

let store = createStore(combineReducers({ imagesReducer }), applyMiddleware(thunk));

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

让我们首先关注 Redux 的仪式。`let store = createStore(combineReducers({ imagesReducer }), applyMiddleware(thunk));`通过组合导入的 reducer（我们这个应用只有一个 reducer，所以这只是信息性的）并应用*Thunk*中间件来设置存储，这将使我们的应用能够使用异步操作。我们将模拟几个 API 调用，这些调用将返回异步承诺，因此需要这个中间件来正确处理这些承诺的解析。

然后，我们有我们的`render`方法：

```jsx
<Provider store={store}>
   <Navigator/>
</Provider>
```

这在大多数使用 React 的 Redux 应用中都是标准的。我们将根组件（在我们的情况下是`<Navigator />`）与`<Provider />`组件包装在一起，以确保我们可以从应用的根部获取`store`。Redux 的`connect`方法将在本章中继续使用在我们的容器或屏幕中。

我们将使用`<Navigator />`组件作为我们应用的根，但它将根据运行的平台具有不同的性质：

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

`Platform`是一个 React Native API，主要用于识别我们的应用正在运行的平台。我们可以通过将代码包装在`if(Platform.OS === 'ios'){ ... }`中来编写特定于 iOS 的代码，对于 Android 也是一样：`if(Platform.OS === 'android'){ ... }`。

在这种情况下，我们使用它来在 iOS 上构建一个选项卡导航器，在 Android 上构建一个抽屉导航器，这些是这些平台的*事实*导航模式。在这两个导航器上，我们将设置`ImagesList`，`MyImages`和`Camera`作为我们应用程序中的三个主要屏幕。

# ImagesList

我们应用程序中的主屏幕是从后端检索的图像列表。我们将显示这些图像以及它们对应的上传者个人资料图片和名称。对于每个图像，我们将显示更多，可以用于与用户设备上的其他应用程序共享图像，例如消息应用程序或社交网络。这个屏幕的大部分 UI 将来自`<Gallery />`组件，因此我们将专注于将屏幕与 Redux 存储连接起来，添加自定义标题，并添加一个滚动视图使画廊可滚动，并添加一个活动指示器来警告用户有网络活动：

```jsx
/*** src/components/ImagesList ***/

import React from 'react';
import { View, ScrollView } from 'react-native';

import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import * as Actions from '../actions'; import { Icon } from 'native-base';

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

由于大多数 React 应用程序使用 Redux，我们需要将我们的组件与状态和操作连接起来。我们将创建两个函数（`mapStateToProps`和`mapStateActionsToProps`）来装饰我们的`<ImageList />`组件，以映射组件感兴趣的状态和部分操作：

+   `images`：这是我们将在`<Gallery />`中使用的图像列表

+   `addingImage`：这是在上传图像时将设置为`true`的标志

+   `fetchingImages`：当应用程序请求从后端获取图像列表以更新存储时，将设置为`true`的标志

在这个屏幕上我们唯一需要的操作是`fetchImages`，通过`props`组件可访问，因为我们将操作列表在`Actions`中连接到我们的`<ImagesList />`组件。同样，通过`props`，我们可以访问三个状态变量（`images`，`addingImage`和`fetchingImages`），这要归功于相同的`connect`调用：

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

这就是我们从 Redux 需要的一切。我们将在其他屏幕中看到这种模式，因为这是连接 React 组件与存储部分和操作列表的常见解决方案。

`fetchImages`操作在`componentWillMount`上调用，作为要呈现的图像列表的初始检索：

```jsx
componentWillMount() { 
   this.props.fetchImages(); 
}
```

我们还添加了一种方法来检测`addingImage`标志设置为`true`时显示活动指示器。

```jsx
componentWillReceiveProps(nextProps) {
  if(!this.props.addingImage && nextProps.addingImage) {
    this.scrollable.scrollTo({y: 0});
  }
}
```

此方法将在`<Scrollview />`中调用`scrollTo`，以确保显示顶部部分，因此用户可以看到`<ActivityIndicator />`。这次我们使用自定义的`<ActivityIndicator />`（从`src/components/ActivityIndicator`导入），因为我们不仅想显示旋转器，还想显示消息。

最后，我们将添加两个组件：

+   `<Header />`：显示标志和（在 Android 版本中）两个图标，用于导航到抽屉菜单和相机屏幕

+   `<Gallery />`：显示格式化的图片列表和上传者

在转移到另一个屏幕之前，让我们看一下我们在其中包含的三个自定义组件：`<ActivityIndicator />`、`<Header />`和`<Gallery />`。

# 画廊

Gallery 包含了所有图片列表的渲染逻辑。它依赖于`native-base`，更具体地说，依赖于它的两个组件，`<List />`和`<ListItem />`。

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

这个组件从其父组件中获取两个 props：`loading`和`imageList`。

`loading`用于显示标准的`<ActivityIndicator />`，显示用户的网络活动。这次我们使用标准的指示器，而不是自定义指示器，因为应该很清楚网络活动表示的是什么。

`imageList`是存储图片列表的数组，这些图片将在我们的`<Gallery />`中一次一个`<ListenItem />`地呈现。每个`<ListItem />`都包含一个`<Button />`，其中`onPress={this._share.bind(this, image)`用于与其他应用程序共享图片。让我们看一下`_share`函数：

```jsx
_share(image) {
  Share.share({message: image.src, title: 'Image from: ' 
               + image.user.name}) 
}
```

`分享`是一个用于分享文本内容的 React Native API。在我们的情况下，我们将分享图片的 URL（`img.src`）以及一个简单的标题。分享文本是在应用程序之间共享内容的最简单方式，因为许多应用程序都会接受文本作为共享格式。

值得注意的是我们对图片应用的样式，使其占据整个宽度并具有固定高度（`300`），因此即使显示的图片大小不同，我们也有一个稳定的布局。对于这种设置，我们使用`resizeMode: 'cover'`，这样图片在任何维度上都不会被拉伸。这意味着我们可能会裁剪图片，但这可以弥补不同尺寸图片的统一性。另一个选项是使用`resizeMode: contain`，如果我们不想裁剪任何东西，而是想要将图片适应这些边界，甚至可能缩小它们。

# 标题

我们想要在几个屏幕之间重用一个自定义标题。这就是为什么最好为它创建一个单独的组件，并在这些屏幕中导入它的原因：

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

我们再次使用`Platform` API 来检测 Android 设备，并且只在该平台上显示抽屉菜单按钮和相机按钮。我们决定这样做是为了使这些功能更加突出，这些功能是应用程序的核心，通过减少需要按下的按钮数量来使 Android 用户更加突出。按下按钮时执行的操作通过父组件通过两个 props 传递：

+   `onMenuButtonPress`

+   `onCameraButtonPress`

这两个属性调用了两个单独的函数，调用了导航器的`navigate`方法：

+   `this.props.navigation.navigate('DrawerOpen')`

+   `this.props.navigation.navigate('Camera')`

最后要注意的是我们如何在这个组件中设置容器的布局。我们使用`justifyContent: 'space-around'`，这是告诉 Flexbox 均匀分布项目在行中，周围有相等的空间。请注意，从视觉上看，这些空间并不相等，因为所有项目在两侧都有相等的空间。第一个项目将在容器边缘有一个单位的空间，但在下一个项目之间有两个单位的空间，因为下一个项目有自己的间距。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/04762b2b-ae90-489a-bb86-ea78f7b6d11b.png)

# 活动指示器

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

它接收一个消息作为属性，并在标准旋转器旁边显示它。我们还添加了自定义背景颜色（`#f0f0f0`）以使其在白色背景上更加可见。

现在让我们转移到相机屏幕，将我们的图像添加到列表中。

# 相机

在使用`react-native-camera`时，大部分拍照逻辑可以被抽象化，因此我们将专注于在我们的组件中使用这个模块，并确保通过 Redux 操作将其连接到我们应用的状态：

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

`react-native-camera`的工作方式是通过提供一个我们可以包含在屏幕中的组件，并且通过引用，我们可以调用它的`capture`方法，该方法返回一个我们可以使用的 promise，以调用`addImage`将我们的图像上传到应用的后端。

让我们更仔细地看看`<Camera />`组件：

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

+   `ref`：这在父组件中为`<Camera />`组件设置一个引用，以便调用`capture`方法。

+   `style`：这允许开发人员指定应用中组件的外观。

+   `aspect`：这允许您定义视图渲染器在显示相机视图时的行为。有三个选项：`fill`，`fit`和`stretch`。

当用户按下相机按钮时，将调用`takePicture`函数：

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

我们将使用保存的相机引用来调用它的`capture`方法，我们可以传递一些元数据（例如，照片拍摄的位置）。这个方法返回一个 promise，将以图像数据解析，因此我们将使用这些数据调用`addImage`动作将这些数据发送到后端，以便将图片添加到`imagesList`。在将图片发送到后端后，我们将使应用程序导航回`ImagesList`屏幕。`addImage`方法将设置`addingImages`标志，因此`ImageList`屏幕可以显示相应消息的活动指示器。

让我们继续看看我们应用程序中的最后一个屏幕：`MyImages`。

# MyImages

这个屏幕显示了已登录用户上传的所有图片。我们在这个屏幕上使用虚假图片来预先填充这个屏幕，但更多的图片可以通过相机屏幕添加。

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

这个组件的第一件事是调用`fetchImages`动作，但与`<ImagesList />`组件不同的是，它只传递用户名以仅检索已登录用户的图片。当我们创建这个动作时，我们需要考虑这一点，并接收一个可选的`userName`参数来过滤我们将检索的图片列表。

除此之外，这个组件将大部分行为委托给`<ImageGrid />`，以便我们可以重用渲染能力用于其他用户。让我们继续看`<ImageGrid />`。

# 图片网格

一个简单的滚动视图和一系列图片。这个组件就是这么简单，但它的配置方式使得图片可以像网格一样轻松地流动：

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

在样式化容器时，我们使用`flexWrap: 'wrap'`来确保图片不仅在`row`方向上流动，而且当设备宽度覆盖一行图片时也扩展到新行。通过为每个图像设置`width`和`height`为`width/3 - 2`，我们确保容器可以每行容纳三张图片，包括两个像素的小间距。

通过 npm 还有几个网格模块可用，但我们决定为此构建我们自己的组件，因为我们不需要网格中的额外功能，并且以这种方式可以获得灵活性。

这些就是我们在图片分享应用程序中需要的所有屏幕和视觉组件。现在让我们来看看让它们一起工作的粘合剂，即动作和减速器。

# 动作

正如我们在屏幕上看到的，这个应用只需要两个动作，`fetchImages`（对所有用户或特定用户）和`addImage`：

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

Redux 的 actions 只是描述事件的简单对象，包括其有效负载。由于我们正在使用`redux-thunk`，我们的*action creators*将返回一个函数，在该函数中 Redux 的`dispatch`函数将被调用，传递 action。让我们更仔细地看看我们的`addImage`动作：

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

我们返回的函数首先通过分发一个名为`ADD_IMAGE`的动作来开始，没有有效负载，因为我们只是想让 Redux 知道我们准备好发起网络请求将图像上传到我们的后端。然后，我们使用我们的`api`进行该请求（稍后我们将模拟这个调用）。这个请求将返回一个 promise，所以我们可以附加`.then`和`.catch`回调来处理响应。如果响应是积极的（图像被正确上传），我们将分发一个`ADD_IMAGE_SUCCESS`动作，传递上传图像的 URL。如果出现错误，我们将分发一个`ADD_IMAGE_ERROR`动作，涵盖所有可能的状态。

大多数 action creators 在*Redux*和*Thunk*中进行网络请求时都以类似的方式工作。事实上，我们的 action `fetchImages`与`addImage`非常相似，只有一个例外：它需要检查是否传递了`userId`，并发出不同的一组动作，以便 reducers 可以相应地修改状态。让我们来看看将处理所有这些动作的 reducers。

# Reducers

在 Redux 中，reducers 是负责在发生新动作时更新状态的函数。它们接收当前状态和动作（包括任何有效负载），并返回一个新的`state`对象。我们不会深入研究 reducers 的工作原理，我们只需要了解它们的基本结构：

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

我们从一个初始状态开始，其中所有属性都将设置为`null`，除了`user`，它将包含模拟用户数据。这个初始状态默认注入到启动时的 reducer 中：

```jsx
export default function (state = initialState, action) {

  ...

}
```

在后续调用中，Redux 将在应用任何动作后注入实际状态。在这个函数内部，我们有一个`switch`来评估每个触发的动作类型，以根据该动作及其有效负载修改状态。让我们以`FETCH_IMAGES_SUCCESS`动作为例：

```jsx
case 'FETCH_IMAGES_SUCCESS': 
  return Object.assign({}, state, {
    fetchingImages: false,
    images: action.images,
    error: null
  });
```

Redux 中的一个规则是 reducers 不应该改变状态，而是在触发动作后返回一个新对象。使用`Object.assign`，我们返回一个包含当前状态和基于刚刚发生的动作的所需更改的新对象。在这种情况下，我们将`fetchingImages`标志设置为`false`，以便让我们的组件知道它们可以隐藏与获取图像相关的任何活动指示器。我们还将从`actions.images`中接收到的图像列表设置为我们状态的`images`键，以便将它们注入到需要它们的组件中。最后，我们将`error`标志设置为`null`，以隐藏由于先前状态而显示的任何错误。

正如我们之前提到的，每个异步操作都应该分成三个单独的动作来表示三种不同的状态：异步请求挂起，成功和出错。这样，我们的应用将有三组动作：

+   `FETCH_IMAGES`，`FETCH_IMAGES_SUCCESS`和`FETCH_IMAGES_ERROR`

+   `FETCH_USER_IMAGES`，`FETCH_USER_IMAGES_SUCCESS`和`FETCH_USER_IMAGES_ERROR`

+   `ADD_IMAGE`，`ADD_IMAGE_SUCCESS`和`ADD_IMAGE_ERROR`

重要的是要注意，我们为`FETCH_IMAGES`和`FETCH_USER_IMAGES`有单独的情况，因为我们希望同时保留两个不同的图像列表：

+   一个包含用户正在关注的所有人的图片的通用图片

+   用户已上传的图片列表

最后缺失的部分是从动作创建者调用的 API 调用。

# API

在真实的应用程序中，我们会将所有对后端的调用放在一个单独的`api`文件夹中。出于教育目的，我们只是模拟了我们应用程序的核心的两个 API 调用，`addImage`和`fetchImages`：

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

为了模拟网络延迟，我们添加了一些`setTimeouts`，这将有助于测试我们设置的用于显示用户网络活动的活动指示器。我们还使用了 promise 而不是普通的回调来使我们的代码更易于阅读。在这些示例中，我们还跳过了图像 URL，以使其更简洁。

# 总结

我们在这个应用程序中使用了 Redux，并且这塑造了我们使用的文件夹结构。虽然使用 Redux 需要一些样板代码，但它有助于以合理的方式拆分我们的代码库，并消除容器或屏幕之间的直接依赖关系。当我们需要在屏幕之间保持共享状态时，Redux 绝对是一个很好的补充，因此在本书的其余部分我们将继续使用它。在更复杂的应用程序中，我们需要构建更多的 reducers，并可能按领域将它们分开，并使用 Redux `combineReducers`。此外，我们需要添加更多的操作，并为每组操作创建单独的文件。例如，我们需要登录、注销和注册的操作，我们可以将它们放在名为`src/actions/user.js`的文件夹中。然后，我们应该将我们与图像相关的操作（目前在`index.js`中）移动到`src/actions/images.js`中，这样我们就可以修改`src/actions/index.js`，以便在需要一次性导入所有操作时将其用作用户和图像操作的组合器。

Redux 还有助于测试，因为它将应用程序的业务逻辑隔离到 reducers 中，因此我们可以专注于对它们进行彻底的测试。

模拟 API 调用使我们能够为我们的应用程序快速建立原型。当后端可用时，我们可以重用这些模型进行测试，并用真正的 HTTP 调用替换`src/api/index.js`。无论如何，最好为我们所有的 API 调用建立一个单独的文件夹，这样如果后端发生任何更改，我们就可以轻松地替换它们。

您还学会了如何构建特定平台的代码（在我们的案例中是特定于 Android），这对大多数应用程序来说是非常有用的功能。一些公司更喜欢为每个平台编写单独的应用程序，并且只重用它们的业务逻辑代码，在任何基于 Redux 的应用程序中都应该非常容易，因为它驻留在 reducers 中。

在 React Native 中没有特定的 API 来控制设备的相机，但我们可以使用`react-native-camera`模块来实现。这是一个访问 iOS 和 Android 原生 API 并将其暴露在 React Native JavaScript 世界中的库的示例。在我们的下一章中，我们将通过构建吉他调音器应用程序来探索并跨越 React Native 应用程序中原生和 JavaScript 世界之间的桥梁。


# 第五章：吉他调音器

React Native 涵盖了 iOS 和 Android 中大部分可用的组件和 API。诸如 UI 组件、导航或网络等点可以完全在我们的 JavaScript 代码中使用 React Native 组件进行设置，但并非所有平台的功能都已从本地世界映射到 JavaScript 世界。尽管如此，React Native 提供了一种编写真正的本地代码并访问平台全部功能的方法。如果 React Native 不支持您需要的本地功能，您应该能够自己构建它。

在本章中，我们将利用 React Native 的能力，使我们的 JavaScript 代码能够与自定义的本地代码进行通信；具体来说，我们将编写一个本地模块来检测来自设备麦克风的频率。这些能力不应该是 React Native 开发人员日常任务的一部分，但最终，我们可能需要使用仅在 Objective-C、Swift 或 Java 上可用的模块或 SDK。

在本章中，我们将专注于 iOS，因为我们需要编写超出本书范围的本地代码。将此应用程序移植到 Android 应该相当简单，因为我们可以完全重用 UI，但我们将在本章中将其排除在外，以减少编写的本地代码量。由于我们只关注 iOS，我们将涵盖构建应用程序的所有方面，添加启动画面和图标，使其准备好提交到 App Store。

我们将需要一台 Mac 和 XCode 来为这个项目添加和编译本地代码。

# 概述

理解吉他的调音概念应该很简单：吉他的六根弦在开放状态下（即没有按下任何品）发出特定频率的声音。调音意味着拉紧弦直到发出特定频率的声音。以下是每根弦应该发出的标准频率列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/1b31ca6f-97f7-4c10-966f-b8b470bdc6a3.png)

吉他调音的数字过程将遵循以下步骤：

1.  记录通过设备麦克风捕获的频率的实时样本。

1.  找到该样本中最突出的频率。

1.  计算出前表中最接近的频率，以检测正在演奏的是哪根弦。

1.  计算发出的频率与该弦的标准调音频率之间的差异，以便让用户纠正弦的张力。

我们还需要克服一些障碍，比如忽略低音量，这样我们就不会因为检测到不是来自琴弦的声音的频率而混淆用户。

在这个过程中，我们将使用原生代码，不仅因为我们需要处理 React Native API 中不可用的功能（例如，通过麦克风录音），而且因为我们可以以更有效的方式进行复杂的计算。我们将在这里使用的算法来检测从麦克风获取的样本中的主频率被称为**快速傅里叶变换**（**FFT**）。我们不会在这里详细介绍，但我们将使用一个原生库来执行这些计算。

这个应用程序的用户界面应该非常简单，因为我们只有一个屏幕来展示给用户。复杂性将存在于逻辑中，而不是展示一个漂亮的界面，尽管我们将使用一些图像和动画使其更具吸引力。重要的是要记住，界面是使应用程序在应用商店中吸引人的因素，所以我们不会忽视这一方面。

这就是我们的应用程序完成后的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/16b23a5e-a1dc-4f05-bc79-fc4c5a4ac11c.png)

在屏幕顶部，我们的应用程序显示一个“模拟”调谐器，显示吉他弦发出的频率。一个红色指示器将在调谐器内移动，以显示吉他弦是否接近调谐频率。如果指示器在左侧，意味着吉他弦的频率较低，需要调紧。因此，用户应该尝试使指示器移动到调谐器的中间，以确保琴弦调谐。这是一种非常直观的方式来显示琴弦的调谐情况。

然而，我们需要让用户知道她试图调谐的是哪根琴弦。我们可以通过检测最接近的调谐频率来猜测这一点。一旦我们知道是哪根琴弦被按下，我们将在屏幕底部向用户显示它，那里有每根琴弦的表示，以及调谐后应该演奏的音符。我们将改变相应音符的边框颜色为绿色，以通知用户应用程序检测到了特定音符。

让我们回顾一下本章将涵盖的主题列表：

+   从 JavaScript 运行原生代码

+   动画图像

+   `<StatusBar />`

+   `propTypes`

+   添加启动画面

+   添加图标

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。该项目将命名为`guitarTuner`，并且将专门用于 iOS：

```jsx
react-native init --version="0.45.1" guitarTuner
```

由于这是一个单屏应用程序，我们不需要像 Redux 或 MobX 这样的状态管理库，因此，我们将使用一个简单的文件夹结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/7e89eb67-4d3d-4a0d-85e3-83a06350ba56.png)

我们有三张图片来支持我们的自定义界面：

+   `indicator.jpg`：指示弦音调的红色条

+   `tuner.jpg`：指示器将移动的背景

+   `string.jpg`：吉他弦的表示

我们的`src/`文件夹包含两个子文件夹：

+   `components/`：这里存储了`<Strings/>`组件和`<Tuner/>`组件

+   `utils/`：这里保存了将在我们应用的几个部分中使用的函数和常量列表

最后，我们应用程序的入口点将是`index.ios.js`，因为我们将专门为 iOS 平台构建我们的应用程序。

让我们看看我们的`package.json`，以确定我们将有哪些依赖项：

```jsx
/*** package.json ***/

{
        "name": "guitarTuner",
        "version": "0.0.1",
        "private": true,
        "scripts": {
                "start": "node node_modules/react-native/
                local-cli/cli.js start",
                "test": "jest"
        },
        "dependencies": {
                "react": "16.0.0-alpha.12",
                "react-native": "0.45.1"
        },
        "devDependencies": {
                "babel-jest": "20.0.3",
                "babel-preset-react-native": "2.0.0",
                "jest": "20.0.4",
                "react-test-renderer": "16.0.0-alpha.12"
        },
        "jest": {
                "preset": "react-native"
        }
}
```

可以看到，除了由 React Native 的 CLI 在运行`init`脚本时创建的`react`和`react-native`之外，没有其他依赖项。

为了获得从麦克风录制的权限，我们还需要修改我们的`ios/guitarTuner/Info.plist`，添加一个*Microphone Usage Description*，这是一个要显示给用户的消息，请求在她的设备上访问麦克风。我们需要在最后的`</dict></plist>`之前添加这些行：

```jsx
<key>NSMicrophoneUsageDescription</key><key>NSMicrophoneUsageDescription</key> 
<string>This app uses the microphone to detect what guitar 
         string is being pressed.
</string>
```

通过这最后一步，我们应该已经准备好开始编写应用程序的 JavaScript 部分。但是，我们仍然需要设置我们将用于录制和频率检测的原生模块。

# 编写原生模块

我们需要 XCode 来编写原生模块，该模块将使用麦克风录制样本，并分析这些样本以计算主频率。由于我们对这些计算方式不感兴趣，我们将使用一个开源库来委托大部分录制和 FFT 计算。该库名为`SCListener`，其分支可以在[`github.com/emilioicai/sc_listener`](https://github.com/emilioicai/sc_listener)找到。

我们需要下载该库，并按照以下步骤将其文件添加到项目中：

1.  导航到我们的 iOS 项目所在的文件夹：`<project_folder>/ios/`。

1.  双击`guitarTuner.xcodeproj`，这将打开 XCode。

1.  右键单击`guitarTuner`文件夹，然后单击“添加文件到"guitarTuner"...”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/26810fae-4e6f-4c4c-976f-c5d605f2d75b.png)

1.  选择从下载的`SCListener`库中选择所有文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/07f1b66c-4963-41ee-ac32-695895d0e59a.png)

1.  单击 Accept。您应该在 XCode 中得到一个类似于这样的文件结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/78683d6d-fdf2-4100-b7b0-1252a051f8b9.png)

1.  `SCListener`需要安装 AudioToolbox 框架。我们可以通过在 XCode 中点击项目的根目录来实现这一点。

1.  选择 Build Phases 选项卡。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/7dd608bd-8cfb-46cb-8a99-0aae7f1b9bd7.png)

1.  转到 Link Binary with Libraries。

1.  单击+图标。

1.  选择 AudioToolbox.framework。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/eef7db93-952a-45c8-88c6-7db97c63eb08.png)

1.  现在，让我们添加一个将使用`SCListener`并将数据发送到 React Native 的模块。右键单击`guitarTuner`文件夹，然后单击 New File。

1.  添加一个名为`FrequencyDetector.h`的头文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/3fcd3014-4554-4c19-a97d-77e261f99732.png)

1.  让我们重复这个过程，为我们的模块添加一个实现文件：右键单击`guitarTuner`文件夹，然后单击 New File。

1.  添加一个名为`FrequencyDetector.m`的 Objective-C 文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/73cc358f-ed17-446b-971a-bcf177a31955.png)

我们的模块`FrequencyDetector`现在已经准备好实现了。让我们看看`FrequencyDetector.h`应该是什么样子：

```jsx
/*** FrequencyDetector.h ***/

#import <React/RCTBridgeModule.h>
#import <Accelerate/Accelerate.h>

@interface FrequencyDetector : NSObject 
@end
```

它只导入了两个模块：`Accelerate`用于进行傅立叶变换计算，`RCTBridgeModule`用于使我们的本地模块与应用的 JavaScript 代码进行交互。现在，让我们来实现这个模块：

```jsx
/*** FrequencyDetector.m ***/

#import "FrequencyDetector.h"
#import "SCListener.h"

NSString *freq = @"";

@implementation FrequencyDetector

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(getFrequency:(RCTResponseSenderBlock)callback)
{
  double power = [[SCListener sharedListener] averagePower];
  if(power < 0.03) { //ignore low volumes
    freq = @"0";
  } else {
    freq = [NSString stringWithFormat:@"%0.3f",
           [[SCListener sharedListener] frequency]];
  }
  callback(@[[NSNull null], freq]);
}

RCT_EXPORT_METHOD(initialise)
{
  [[SCListener sharedListener] listen];
}

@end
```

即使对于非 Objective-C 开发人员，这段代码也应该很容易理解：

1.  首先，我们导入`SCListener`，这个模块暴露了从设备麦克风录制和计算录制样本的 FFT 的方法

1.  然后，我们公开了两种方法：`getFrequency`和`initialise`

`getFrequency`的实现也非常简单。我们只需要通过调用我们的 SCListener 共享实例上的`averagePower`来读取麦克风上检测到的音量。如果音量足够强，我们就认为弹了一根吉他弦，所以我们更新一个名为`freq`的变量，它将被传递到我们 JavaScript 代码提供的回调中。请注意，由于本地代码和 JavaScript 代码之间的桥接的性质，只能通过回调（或承诺）将数据发送回 JavaScript。

我们将本地世界中的方法暴露到 JavaScript 世界的方式是使用`RCTBridgeModule`提供的宏`RCT_EXPORT_METHOD`。我们还需要让 React Native 知道这个模块可以从我们的 JavaScript 代码中使用。我们通过调用另一个宏来做到这一点：`RCT_EXPORT_MODULE`。这就是我们需要的全部；从这一刻起，我们可以使用这个模块的方法：

```jsx
import { NativeModules } from 'react-native';
var FrequencyDetector = NativeModules.FrequencyDetector;

FrequencyDetector.initialise();
FrequencyDetector.getFrequency((res, freq) => {});
```

正如我们所看到的，我们将一个回调传递给`getFrequency`，其中将接收当前记录的频率。我们现在可以使用这个值来计算按下了哪根弦以及它的调谐情况。让我们看看我们将如何在我们应用程序的 JavaScript 组件中使用这个模块。

# index.ios.js

我们已经看到了我们如何访问我们从本地模块`FrequencyDetector`中暴露的方法。现在让我们看看如何在我们的组件树中使用它来更新我们应用程序的状态：

```jsx
/*** index.ios.js ***/

...

var FrequencyDetector = NativeModules.FrequencyDetector;

export default class guitarTuner extends Component {

  ...

  componentWillMount() {
 FrequencyDetector.initialise();
    setInterval(() => {
      FrequencyDetector.getFrequency((res, freq) => {
        let stringData = getClosestString(parseInt(freq));
        if(!stringData) {
          this.setState({
            delta: null,
            activeString: null
          });
        } else {
          this.setState({
            delta: stringData.delta,
            activeString: stringData.number
          });
        }
      });
    }, 500);
  }

 ...

});

AppRegistry.registerComponent('guitarTuner', () => guitarTuner);
```

大部分逻辑将放在我们的入口文件的`componentWillMount`方法中。我们需要初始化`FrequencyDetector`模块，从设备的麦克风开始监听，然后我们调用`setInterval`来重复（每 0.5 秒）调用`FrequencyDetector`的`getFrequency`方法来获取更新的显著频率。每次我们获得一个新的频率，我们将通过调用一个名为`getClosestString`的支持函数来检查最可能被按下的吉他弦，并将返回的数据保存在我们的组件状态中。我们将把这个函数存储在我们的`utils`文件中。

# utils

在继续`index.ios.js`之前，让我们看看我们位于`src/utils/index.js`中的`utils`文件：

```jsx
/*** src/utils/index.js ***/

const stringFrequencies = [
  { min: 287, max: 371, tuned: 329 },
  { min: 221, max: 287, tuned: 246 },
  { min: 171, max: 221, tuned: 196 },
  { min: 128, max: 171, tuned: 146 },
  { min: 96, max: 128, tuned: 110 },
  { min: 36, max: 96, tuned: 82}
];

export function getClosestString(freq) {
  let stringData = null;
  for(var i = 0; i < stringFrequencies.length; i++) {
    if(stringFrequencies[i].min < freq && stringFrequencies[i].max 
       >= freq){
      let delta = freq - stringFrequencies[i].tuned; //absolute delta
      if(delta > 0){
        delta = Math.floor(delta * 100 / (stringFrequencies[i].max - 
                           stringFrequencies[i].tuned));
      } else {
        delta = Math.floor(delta * 100 / (stringFrequencies[i].tuned - 
                           stringFrequencies[i].min));
      }
      if(delta > 75) delta = 75; //limit deltas
      if(delta < -75) delta = -75;
      stringData = { number: 6 - i, delta } //relative delta
      break;
    }
  }
  return stringData;
}

export const colors = {
  black: '#1f2025',
  yellow: '#f3c556',
  green: '#3bd78b'
}

```

`getClosestString`是一个函数，根据提供的频率，将返回一个包含两个值的 JavaScript 对象：

+   `number`：这是最可能被按下的吉他弦的数字

+   `delta`：这是提供的频率与最可能被按下的吉他弦的调谐频率之间的差异

我们还将导出一组颜色及其十六进制表示，这将被一些用户界面组件使用，以保持整个应用程序的一致性。

在调用`getClosestString`之后，我们有足够的信息来构建我们应用程序的状态。当然，我们需要将这些数据提供给调谐器（显示吉他弦的调谐情况）和弦的表示（显示哪根吉他弦被按下）。让我们看看整个根组件，看看这些数据是如何在组件之间传播的：

```jsx
/*** index.ios.js ***/

import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  Image,
  View,
  NativeModules,
  Animated,
  Easing,
  StatusBar,
  Text
} from 'react-native';
import Tuner from './src/components/Tuner';
import Strings from './src/components/Strings';
import { getClosestString, colors } from './src/utils/';

var FrequencyDetector = NativeModules.FrequencyDetector;

export default class guitarTuner extends Component {
  state = {
 delta: null,
    activeString: null
  }

  componentWillMount() {
    FrequencyDetector.initialise();
    setInterval(() => {
      FrequencyDetector.getFrequency((res, freq) => {
        let stringData = getClosestString(parseInt(freq));
        if(!stringData) {
          this.setState({
            delta: null,
            activeString: null
          });
        } else {
          this.setState({
            delta: stringData.delta,
            activeString: stringData.number
          });
        }
      });
    }, 500);
  }

  render() {
    return (
      <View style={styles.container}>
 <StatusBar barStyle="light-content"/>
        <Tuner delta={this.state.delta} />
        <Strings activeString={this.state.activeString}/>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.black,
    flex: 1
  }
});

AppRegistry.registerComponent('guitarTuner', () => guitarTuner);
```

我们将使用两个组件来渲染当前按下的弦（`<Strings/>`）以及按下的弦的调谐程度（`<Tuner/>`）。

除此之外，我们还使用了一个名为`<StatusBar/>`的 React Native 组件。`<StatusBar/>`允许开发人员选择应用程序在顶部栏中显示的颜色，其中显示运营商、时间、电池电量等：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/0566a8ca-a023-47d3-a9f9-2d2b6aed1ffb.png)

因为我们希望我们的应用有一个黑色的背景，我们决定使用`light-content`的 bar 样式。这个组件允许我们完全隐藏 bar，改变其背景颜色（仅限 Android），或隐藏网络活动，等等。

现在让我们转向显示所有视觉组件的组件。我们将从`<Tuner/>`开始。

# 调谐器

我们的`<Tuner/>`组件包括两个元素：一个背景图像将屏幕分成几个部分，以及一个指示器，它将根据弹奏的吉他弦的音调移动。为了使其用户友好，我们将使用动画来移动指示器，类似于模拟调谐器的行为：

```jsx
/*** src/components/Tuner/index ***/

import React, { Component } from 'react';
import {
  StyleSheet,
  Image,
  View,
  Animated,
  Easing,
  Dimensions
} from 'react-native';

import { colors } from '../utils/';

var {height, width} = Dimensions.get('window');

export default class Tuner extends Component {
  state = {
 xIndicator:  new Animated.Value(width/2)
  }

  static propTypes = {
    delta: React.PropTypes.number
  }

  componentWillReceiveProps(newProps) {
    if(this.props.delta !== newProps.delta) {
      Animated.timing(
        this.state.xIndicator,
        {
          toValue: (width/2) + (newProps.delta*width/2)/100,
          duration: 500,
          easing: Easing.elastic(2)
        }
      ).start();
    }
  }

  render() {
    let { xIndicator } = this.state;

    return (
      <View style={styles.tunerContainer}>
        <Image source={require('../../img/tuner.jpg')} 
         style={styles.tuner}/>
 <Animated.Image source={require('../../img/indicator.jpg')} 
         style={[styles.indicator, {left: xIndicator}]}/>
      </View>
    )
  }
}

const styles = StyleSheet.create({
  tunerContainer: {
    flex: 1,
    backgroundColor: colors.black,
    marginTop: height * 0.05
  },
  tuner: {
    width,
    resizeMode: 'contain'
  },
  indicator: {
    position: 'absolute',
    top: 10
  }
});
```

我们将使用组件的`state`变量来进行动画命名为`xIndicator`，它将以动画方式存储指示器应该在的位置的值。记住，越接近中心，弦的音调就会调得越好。我们将使用`componentWillReceiveProps`方法和`Animated.timing`函数每次从父组件接收到新的`delta`属性时更新这个值，以确保图像是动画的。为了使其更加逼真，我们还添加了一个缓动函数，这将使指示器像真正的模拟指示器一样弹跳。

我们还为我们的类添加了一个`propTypes`静态属性进行类型检查。这样我们就可以确保我们的组件以正确的格式接收到一个 delta。

最后，还记得我们在`utils`文件中导出了颜色列表及其十六进制值吗？我们在这里使用它来显示这个组件的背景颜色是什么。

# 弦

最后一个组件是吉他的六根弦的表示。当我们的`FrequencyDetector`原生模块检测到弹奏的频率时，我们将通过将音符容器的边框更改为绿色来显示具有发射最接近频率的弦：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/e630770d-b6c7-4104-a222-bf0cc2a38363.png)

因此，我们需要从其父组件接受一个属性：活动吉他弦的编号。让我们来看一下这个简单组件的代码：

```jsx
/*** src/components/Strings ***/

import React, { Component } from 'react';
import {
  StyleSheet,
  Image,
  View,
  Text
} from 'react-native';

import { colors } from '../utils/';

const stringNotes = ['E','A','D','G','B','E'];

export default class Strings extends Component {
 static propTypes = {
    activeString: React.PropTypes.number
  }

  render() {
    return (
      <View style={styles.stringsContainer}>
        {
          stringNotes.map((note, i) => {
            return (
              <View key={i} style={styles.stringContainer}>
                <Image source={require('../../img/string.jpg')} 
                 style={styles.string}/>
                <View style={[styles.noteContainer, 
                 {borderColor: (this.props.activeString === (i+1))
                  ? '#3bd78b' : '#f3c556'}]}>
                  <Text style={styles.note}>
                    {note}
                  </Text>
                </View>
              </View>
            )
          })
        }
      </View>
    );
  }
}

const styles = StyleSheet.create({
  stringsContainer: {
    borderTopColor: colors.green,
    borderTopWidth: 5,
 justifyContent: 'space-around',
    flexDirection: 'row'
  },
  stringContainer: {
    alignItems: 'center'
  },
  note: {
    color: 'white',
    fontSize: 19,
    textAlign: 'center'
  },
  noteContainer: {
    top: 50,
    height: 50,
    width: 50,
    position: 'absolute',
    padding: 10,
    borderColor: colors.yellow,
    borderWidth: 3,
    borderRadius: 25,
    backgroundColor: colors.black
  }
});
```

我们正在渲染六个图像，每个代表一根吉他弦，并使用`space-around`来使它们在整个设备屏幕上分布，留下两个小空间。我们使用一个包含吉他每根弦音符的常量数组将它们映射到字符串表示中。我们还将使用从其父级接收到的`activeString`属性来决定是否应该为每个音符显示黄色边框还是绿色边框。

我们再次使用`propTypes`来检查所提供的属性的类型（在这种情况下是一个数字）。

这就是我们构建吉他调音器所需的所有代码。现在让我们添加一个图标和一个启动画面，使应用程序准备好提交到 App Store。

# 添加图标

一旦我们设计好图标并将其保存为大图像，我们需要将其调整为苹果要求的所有格式。一般来说，这些是所需的尺寸：

+   20 x 20 px（iPhone Notification 2x）

+   60 x 60 px（iPhone Notification 3x）

+   58 x 58 px（iPhone Spotlight - iOS 5,6 2x）

+   67 x 67 px（iPhone Spotlight - iOS 5,6 3x）

+   80 x 80 px（iPhone Spotlight - iOS 7-10 2x）

+   120 x 120 px（iPhone Spotlight - iOS 7-10 3x && iPhone App ios 7-10 2x）

+   180 x 180 px（iPhone App ios 7-10 3x）

由于这是一个非常繁琐的过程，我们可以使用在线工具之一，通过提供足够大的图像来自动完成所有调整大小的任务。最受欢迎的工具之一可以在[`resizeappicon.com/`](https://resizeappicon.com/)找到。

一旦我们有了适当尺寸的图标，我们需要将它们添加到我们的 XCode 项目中。我们可以通过在 XCode 中点击`Images.xcassets`，并将每个图像与其相应的尺寸添加到此窗口中的每个资产来实现这一点：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/fa33b930-7d57-4042-bc25-51dd05c758d4.png)

下次编译我们的应用程序时，我们将在模拟器中看到我们的新图标（使用*command* + *Shift* + *H*来显示主屏幕）。

# 添加启动画面

启动画面是 iOS 在应用程序加载时显示的图像。有几种技术可以使这个介绍对用户愉快，比如显示用户界面的预览，用户一旦加载应用程序就会看到。然而，我们将采用更简单的方法：我们将显示带有标题的应用程序标志。

最简单和更灵活的方法是使用 XCode 中的界面构建器，通过点击`LaunchScreen.xib`来实现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/55e8eaaa-b928-41b9-9a97-e2eefc21cf09.png)

我们需要取消勾选左横向和右横向选项，以便在所有情况下只允许纵向模式。

# 总结

这个应用程序的主要挑战是从我们的 JavaScript 代码访问用 Objective-C 编写的本地模块。幸运的是，React Native 有手段可以用相对较少的代码轻松实现这两个世界之间的通信。

我们只专注于 iOS 应用程序，但现实情况是，在 Android 中构建相同的应用程序应该遵循非常相似的过程，考虑到我们应该用 Java 而不是 Objective-C 构建我们的本地模块。此外，我们学会了在应用程序中包含图标和启动屏幕的过程，以完成发布前的开发周期。

由于我们的应用程序只有一个屏幕，我们选择不使用任何路由或状态管理库，这使我们能够将重点放在我们的 JavaScript 代码和我们实现的本地模块之间的通信上。

我们还创建了一些动画来模拟模拟调谐器，为这个应用程序增添了吸引人和有趣的外观。

除了图标和启动屏幕外，我们还注意到了另一个在许多应用程序中很重要的视觉元素：状态栏。我们看到了根据我们的应用程序外观轻松更改其内容颜色有多容易。在这种情况下，我们选择了深色背景，因此我们需要在状态栏中使用浅色内容，尽管一些应用程序（如游戏）可能在没有状态栏的情况下看起来更好。

在下一章中，我们将转向一种不同类型的应用程序：即消息应用程序。


# 第六章：消息应用

一对一通信是手机的主要用途，尽管短信已经很快被直接消息应用所取代。在本章中，我们将使用 React Native 和 Firebase 构建一个消息应用，Firebase 是一个移动后端服务，可以使我们摆脱为应用构建整个后端的工作。相反，我们将专注于完全从前端处理应用的状态。当然，这可能会有安全方面的影响，需要最终解决，但为了保持本书对 React Native 功能的关注，我们将坚持在应用内部保留所有逻辑的方法。

Firebase 是一个建立在自同步数据集合上的实时数据库，它与 MobX 非常搭配，所以我们将再次使用它来控制应用的状态。但在本章中，我们将更深入地挖掘，因为我们将构建更大的数据存储，这些数据将通过`mobx-react`连接器注入到我们的组件树中。

我们将构建该应用，使其可以在 iOS 和 Android 上使用，为导航编写一些特定于平台的代码（我们将在 iOS 上使用选项卡导航，在 Android 上使用抽屉导航）。

为了减少代码的大小，在本章中，我们将专注于功能而不是设计。大部分用户界面将是简单明了的，但我们会尽量考虑可用性。此外，我们将在我们的聊天屏幕上使用`react-native-gifted` chat--一个预先构建的 React Native 组件，用于根据消息列表渲染聊天室。

# 概述

消息应用需要比我们在前几章中审查的应用更多的工作，因为它需要一个用户管理系统，包括登录、注册和退出登录。我们将使用 Firebase 作为后端来减少构建此系统的复杂性。除了用户管理系统，我们还将使用他们的推送通知系统，在新消息发送给用户时通知用户。Firebase 还提供了分析平台、lambda 函数服务和免费的存储系统，但我们将从中获益最多的功能是他们的实时数据库。我们将在那里存储用户的个人资料、消息和聊天数据。

让我们看看我们的应用将会是什么样子，以便心中有个印象，我们将要构建的屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/7328e6c2-0078-4b7b-bcfa-e96e749a29da.png)

第一个屏幕将是登录/注册屏幕，因为我们需要用户提供姓名和一些凭据，以将他们的设备连接到特定帐户，这样他们就可以接收每条消息的推送通知。这两种身份验证方法都使用 Firebase 的 API 进行验证，成功后将显示聊天屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/a525bb6f-9022-4004-b99a-c726f0fc082f.png)

在联系人列表中按下一个联系人时，应用程序将在聊天屏幕中显示与所选联系人的对话：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/9729a17b-e713-482a-a9b8-4cc6c7d19af1.png)

聊天屏幕将显示所有为登录用户启动的聊天。最初，这个屏幕将是空的，因为用户还没有开始任何聊天。要开始对话，用户应该去搜索屏幕以找到一些联系人：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/0385f83f-b196-44dd-9543-92b74b2b9eb5.png)

这是一个简单的屏幕，用户可以在其中输入联系人姓名以在数据库中搜索。如果联系人的姓名匹配，用户将能够点击它开始对话。从那时起，对话将显示在聊天屏幕中。

最后一个屏幕是个人资料屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/5e03b5e4-8945-4c4e-bcb1-087c85575919.png)

这个屏幕只是用来注销当前用户的。在扩展应用程序时，我们可以添加更多功能，比如更改头像或用户名。

虽然安卓上的应用程序看起来非常相似，但导航将被抽屉取代，从抽屉中可以访问所有屏幕。让我们来看看安卓版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c9a8db8a-c522-493e-9c1b-d5adeb8a31f3.png)

登录/注册屏幕具有标准的文本输入和按钮组件用于安卓：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c3032531-f6b3-4b07-b0eb-e3cb1f21bc27.png)

用户登录后，可以通过滑动手指手势打开抽屉来浏览所有屏幕。默认登录后打开的屏幕是聊天屏幕，我们将列出用户拥有的所有打开对话的列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/9d64041f-16fd-4ed5-bf4f-8b52e7cacc61.png)

从这个屏幕上，用户可以按下特定的对话来列出其中的消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/15526fdd-df16-41c1-a055-ab14122f49a8.png)

接下来的屏幕是搜索屏幕，用于搜索其他用户并与他们开始对话：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/8c7259a1-9e7b-4491-a03b-f18e0f6f9a73.png)

最后一个屏幕是个人资料屏幕，可以在其中找到 LOGOUT 按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c275ce0e-2d78-4a68-8f94-34115a0cc9ee.png)

该应用程序将在横向和纵向模式下在两个平台上运行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/b6098c83-2578-4a1d-8304-481ddc987cc2.png)

正如我们可以想象的那样，这个应用程序将需要一个强大的后端环境来存储我们的用户、消息和状态。此外，我们将需要一个推送通知平台，在用户收到任何消息时通知他们。由于本书专注于 React Native，我们将把所有这些后端工作委托给移动世界中最流行的移动后端服务之一：Firebase。

在开始编码之前，我们将花一些时间设置我们的 Firebase 推送通知服务和实时数据库，以更好地了解我们的应用程序将要处理的数据类型。

总之，本章我们将涉及以下主题：

+   React Native 中的复杂 Redux

+   Firebase 实时数据库

+   Firebase 推送通知

+   Firebase 用户管理

+   表单

让我们首先回顾一下我们将使用的数据模型以及我们的应用程序如何与 Firebase 连接以同步其数据。

# Firebase

Firebase 是一种**移动后端服务**（**MBaaS**），这意味着它为移动开发人员提供了所有后端必需品，如用户管理、无 SQL 数据库和推送通知服务器。它通过官方的 node 包轻松集成到 React Native 中，这为数据库连接提供了免费的服务。不幸的是，Firebase 并没有为他们的推送通知服务提供 JavaScript SDK，但有几个 React Native 库通过将 Firebase 的 iOS 和 Java SDK 与 JavaScript 接口进行桥接来填补这一空白。我们将使用`react-native-fcm`，因为它在这一领域最成熟。

在 Firebase MBaaS 上构建应用程序之前，您需要为其创建一个项目。这是一个免费的过程，可以在 Firebase 的网站[`firebase.google.com/`](https://firebase.google.com/)上找到解释。虽然这个过程与 React Native 没有直接相关，但这是一个很好的起点，可以帮助我们了解如何为我们的应用程序设置和使用 MBaaS。通过遵循 Firebase 文档网站上提供的教程，大部分配置可以在几分钟内完成。设置这个 MBaaS 的好处使得这几分钟的时间和初始麻烦都是值得的。

要设置 Firebase 并将我们的应用连接到正确的项目，我们需要使用在 Firebase 项目仪表板内的设置屏幕中找到的`web 配置`片段。我们将此初始化片段添加到`src/firebase.js`中：

```jsx
import firebase from 'firebase';

var firebaseConfig = {
  apiKey: "<Your Firebase API key>",
  authDomain: "<Your Firebase Auth domain>",
  databaseURL: "<Your Firebase database URL>",
  projectId: "<Your Firebase projectId>",
  storageBucket: "<Your Firebase storageBucket>",
  messagingSenderId: "<Your messaging SenderId>"
};

export const firebaseApp = firebase.initializeApp(firebaseConfig);
```

项目设置完成后，我们可以开始查看我们的数据库将如何被构建。

# 实时数据库

Firebase 允许移动开发人员使用云托管的 noSQL 数据库在用户和设备之间存储和同步数据。更新后的数据在毫秒内同步到连接的设备上，如果应用程序离线，数据仍然可用，无论网络连接如何，都提供了良好的用户体验。

在考虑一对一通信应用程序应处理的基本数据时，涉及三个数据模型：

+   `users`：这将存储头像、名称和推送通知令牌。这里不需要存储身份验证数据，因为它是通过不同的 Firebase API（身份验证 API）处理的。

+   `messages`：我们将在每个聊天室中单独保存每条消息，以便使用聊天室 ID 作为键进行轻松检索。

+   `chats`：所有有关已打开聊天的信息都将存储在这里。

为了了解我们将如何请求和使用我们应用程序中的数据，让我们看一下我们实际可以用于测试的示例数据的要点：

```jsx
{
  "chats" : {
    "--userId1--" : {
      "--userId2----userId1--" : {
        "contactId" : "--userId2--",
        "image" : "https://images.com/person2.jpg",
        "name" : "Jason"
      }
    },
    "--userId2--" : {
      "--userId2----userId1--" : {
        "contactId" : "--userId1--",
        "image" : "https://images.com/person1.jpg",
        "name" : "John"
      }
    }
  },
  "messages" : {
    "--userId2----userId1--" : {
      "-KpEwU8sr01vHSy3qvRY" : {
        "_id" : "2367ad00-301d-46b5-a7b5-97cb88781489",
        "createdAt" : 1500284842672,
        "text" : "Hey man!",
        "user" : {
          "_id" : "--userId2--",
          "name" : "Jason"
        }
      }
    }
  },
  "users" : {
    "--userId1--" : {
      "name" : "John",
      "notificationsToken" : ""
    },
    "--userId2--" : {
      "name" : "Jason",
      "notificationsToken" : "--notificationsId1--"
    }
  }
}
```

我们以一种易于消息应用程序检索和同步的方式组织我们的数据。我们没有对数据结构进行规范化，而是引入了一些数据重复，以增加数据检索速度，并将前端代码简化到最大程度。

`users`集合使用用户 ID 作为键（`--user1--`和`--user2--`）保存用户数据。这些用户 ID 在注册/登录期间由 Firebase 自动检索。每个用户都有一个通知令牌，这是用户登录的设备的标识符，用于推送通知服务。当用户注销时，通知令牌将被删除，因此发送给该用户的消息将被存储，但不会通知到任何设备。

`chats`集合通过用户 ID 存储每个用户的聊天列表。每个聊天都有自己的 ID（两个用户 ID 的连接），并且将被复制，因为该聊天中的每个用户都应该有聊天数据的副本。在每个副本中，有足够的信息供另一个用户构建他们的聊天屏幕。

`messages`集合存储在一个单独的集合中，可以通过该 ID 引用。每个聊天 ID 指向一个消息列表（在本例中只有一个），其中存储了聊天屏幕所需的所有数据。在这个集合中也存在一些重复，因为一些用户数据与每条消息一起存储，以减少构建聊天屏幕时所需的请求数量。

在他们的网站上可以找到有关如何在 Firebase 的实时数据库中读写数据的完整教程（[`firebase.google.com/docs/database/`](https://firebase.google.com/docs/database/)），但是我们将快速浏览一下我们在本章中将使用的方法。

# 从 Firebase 的数据库中读取数据

有两种从 Firebase 的数据库中检索数据的方法。第一种设置一个监听器，每当数据更改时都会被调用，因此我们只需要为我们应用程序的整个生命周期设置一次：

```jsx
firebaseApp.database().ref('/users/' + userId).on('value', (snapshot) => {
  const userObj = snapshot.val();
  this.name = userObj.name;
  this.avatar = userObj.avatar;
});

```

正如我们所看到的，为了检索数据的快照，我们需要在我们的`src/firebase.js`文件中创建的`firebaseApp`对象中调用`database()`方法。然后，我们将拥有一个`database`对象，我们可以在其上调用`ref('<uri>')`，传递数据存储的 URI。这将返回一个由该 URI 指向的数据片段的引用。我们可以使用`on('value', callback)`方法，它将附加一个回调，传递数据的快照。Firebase 总是将对象返回为快照，因此我们需要自己将它们转换为普通数据。在这个例子中，我们想要检索一个具有两个键（`name`和`avatar`）的对象，所以我们只需要在快照上调用`val()`方法来检索包含数据的普通对象。

如果我们不需要检索的数据在每次更新时自动同步，我们可以使用`once()`方法代替`on()`：

```jsx
import firebase from 'firebase';
import { firebaseApp } from '../firebase';

firebaseApp.database().ref('/users/' + userId).once('value')
.then((snapshot) => {
  const userObj = snapshot.val();
  this.name = userObj.name;
  this.avatar = userObj.avatar;
});
```

接收快照的回调只会被调用一次。

# 更新 Firebase 数据库中的数据

在 Firebase 数据库中写入数据也可以通过两种不同的方式完成：

```jsx
firebaseApp.database().ref('/users/' + userId).update({
  name: userName
});
```

`update()`根据作为参数传递的键和值更改由提供的 URI 引用的对象。对象的其余部分保持不变。

另一方面，`set()`将用我们提供的参数替换数据库中的对象：

```jsx
firebaseApp.database().ref('/users/' + userId).set({
  name: userName,
  avatar: avatarURL
});
```

最后，如果我们想要添加一个新的数据快照，但是我们希望 Firebase 为其生成一个 ID，我们可以使用`push`方法：

```jsx
firebaseApp.database().ref('/messages/' + chatId).push().set(message);
```

# 身份验证

我们将使用 Firebase 身份验证服务，因此我们不需要担心存储登录凭据、处理忘记的密码或验证电子邮件。 这些以及其他相关任务都可以通过 Firebase 身份验证服务免费完成。

为了通过电子邮件和密码激活登录和注册，我们需要在 Firebase 仪表板中将此方法作为会话登录方法启用。 有关如何执行此操作的更多信息，请访问 Firebase 网站上的[`firebase.google.com/docs/auth/web/password-auth`](https://firebase.google.com/docs/auth/web/password-auth)。

在我们的应用中，我们只需要使用提供的 Firebase SDK 进行登录：

```jsx
firebase.auth().signInWithEmailAndPassword(username, password)
  .then(() => {
        //user is logged in
  })
  .catch(() => {
        //error logging in
  })
})

```

对于注册，我们可以使用以下代码：

```jsx
firebase.auth().createUserWithEmailAndPassword(email, password)
.then((user) => {
   //user is registered
})
.catch((error) => {
   //error registering
})
```

所有令牌处理将由 Firebase 处理，我们只需要添加一个监听器来确保我们的应用在身份验证状态更改时得到更新：

```jsx
firebase.auth().onAuthStateChanged((user) => {
  //user has logged in or out
}
```

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。 该项目将被命名为`messagingApp`，并将可用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.45.1" messagingApp
```

我们将使用 MobX 来管理我们应用的状态，因此我们将需要一个用于我们存储的文件夹。 其余的文件夹结构对大多数 React 应用程序来说是标准的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/a7683572-2298-4276-b416-676f563b0335.png)

我们需要五个屏幕（`Chats`，`Chat`，`Login`，`Profile`和`Search`），一个组件（`ListItem`）和两个存储（`chats`和`users`），这些将通过`stores/index.js`文件可用。 我们还将使用两个辅助程序来支持我们的应用：

+   `notifications.js`：与推送通知相关的所有逻辑将存储在此文件中

+   `firebase.js`：这包括 Firebase SDK 的配置和初始化

由于我们将使用 MobX 和其他几个依赖项，让我们查看一下我们的`package.json`文件，以了解我们将使用哪些包：

```jsx
/*** package.json ***/

{
        "name": "messagingApp",
        "version": "0.0.1",
        "private": true,
        "scripts": {
                "start": "node node_modules/react-native/local-cli
                         /cli.js start",
                "test": "jest"
        },
        "dependencies": {
                "firebase": "⁴.1.3",
                "mobx": "³.2.0",
                "mobx-react": "⁴.2.2",
                "react": "16.0.0-alpha.12",
                "react-native": "0.45.1",
                "react-native-fcm": "⁷.1.0",
                "react-native-gifted-chat": "⁰.2.0",
                "react-native-keyboard-aware-scroll-view": "⁰.2.9",
                "react-native-vector-icons": "⁴.2.0",
                "react-navigation": "¹.0.0-beta.11"
        },
        "devDependencies": {
                "babel-jest": "20.0.3",
                "babel-plugin-transform-decorators-legacy": "¹.3.4",
                "babel-preset-react-native": "2.1.0",
                "jest": "20.0.4",
                "react-test-renderer": "16.0.0-alpha.12"
        },
        "jest": {
                "preset": "react-native"
        }
}
```

我们将使用的一些 npm 包是：

+   `firebase`：Firebase 的身份验证和数据库连接的 SDK

+   `mobx`：MobX 将处理我们的应用状态

+   `react-native-fcm`：Firebase 的推送消息 SDK

+   `react-native-gifted-chat`：用于渲染聊天室的库，包括日期分隔、头像和许多其他功能

+   `react-native-keyboard-aware-scroll-view`：一个库，确保在处理表单时屏幕键盘不会隐藏任何焦点文本输入

+   `react-native-vector-icons`：我们将在此应用中使用 Font Awesome 图标

+   `react-navigation`：我们将有一个抽屉，一个选项卡和一个堆栈导航器来处理我们应用程序中的屏幕

+   `babel-plugin-transform-decorators-legacy`：这个库允许我们使用装饰器（使用传统的@语法），在使用 MobX 时非常有用

运行`npm install`后，我们的应用程序将准备好开始编码。与以前的应用程序一样，我们的消息应用程序的入口点将在`index.ios.js`（iOS）和`index.android.js`（Android）中是相同的代码：

```jsx
/*** index.ios.js and index.android.js ***/ 

import React from 'react'
import { AppRegistry } from 'react-native';
import App from './src/main';

import { Provider } from 'mobx-react/native';
import { chats, users } from './src/stores';

class MessagingApp extends React.Component {
  render() {
    return (
      <Provider users={users} chats={chats}>
        <App/>
      </Provider>
    )
  }
}

AppRegistry.registerComponent('messagingApp', () => MessagingApp);
```

这是一种使用 MobX 启动 React Native 应用程序的标准方式--`<Provider />`作为根元素提供，以将两个商店（`users`和`chats`）注入到我们应用程序的屏幕中。所有初始化和导航逻辑都已延迟到`src/main.js`文件中：

```jsx
/*** src/main.js ***/

import React from 'react'
import { DrawerNavigator,TabNavigator } from 'react-navigation'
import { Platform, View } from 'react-native'
import { observer, inject } from 'mobx-react/native'

import Login from './screens/Login'
import Chats from './screens/Chats'
import Profile from './screens/Profile'
import Search from './screens/Search'
import { users, chats } from './stores'

let Navigator;
if(Platform.OS === 'ios'){
  Navigator = TabNavigator({
    Chats: { screen: Chats },
    Search: { screen: Search },
    Profile: { screen: Profile }
  }, {
    tabBarOptions: {
      inactiveTintColor: '#aaa',
      activeTintColor: '#000',
      showLabel: true
    }
  });
} else {
  Navigator = DrawerNavigator({
    Chats: { screen: Chats },
    Search: { screen: Search },
    Profile: { screen: Profile }
  });
}

@inject('users') @observer
export default class App extends React.Component {
  constructor() {
    super();
  }

  render() {
 if(this.props.users.isLoggedIn){
      return <Navigator/>
    } else {
      return <Login/>
    }
  }
}
```

在`src/main.js`文件中我们可以看到的第一件事是，我们将使用不同的导航器，取决于我们运行应用程序的平台：iOS 将打开一个选项卡导航器，而 Android 将打开一个基于抽屉的导航器。

然后，我们看到我们将在应用程序中的许多组件中重复的一行：

```jsx
@inject('users') @observer
```

这是告诉 MobX 这个组件需要接收`users`商店的方式。然后 MobX 将其作为属性传递给这个组件，因此我们可以使用它所持有的所有方法和属性。在这种情况下，我们对`isLoggedIn`属性感兴趣，以便在用户尚未登录时向用户呈现`<Login />`屏幕。由于 MobX 将这个属性注入为我们组件的属性，访问它的正确方式将是`this.props.users.isLoggedIn`。

在继续构建组件之前，让我们看一下我们将在本章中使用的商店，以更好地了解可用的数据和操作。

# 用户商店

这个商店负责保存所有围绕用户的数据和逻辑，但也帮助`chats`商店在用户登录时初始化：

```jsx
/*** src/stores/users.js ***/

import {observable, computed, map, toJS, action} from 'mobx';
import chats from './chats'
import firebase from 'firebase';
import { firebaseApp } from '../firebase';
import notifications from '../notifications'

class Users {
        @observable id = null;
        @observable isLoggedIn = false;
        @observable name = null;
        @observable avatar = null;
        @observable notificationsToken = null;
        @observable loggingIn = false;
        @observable registering = false;
        @observable loggingError = null;
        @observable registeringError = null;

        @action login = function(username, password) {
                //login with Firebase email/password method
        }

        @action logout = function() {
                //logout from Firebase authentication service
        }

        @action register = function(email, password, name) {
                //register through firebase authentication service
        }

        @action setNotificationsToken(token) {
                //store the notifications token for this device
        }

        searchUsers(name) {
                //helper for searching users by name in the database
        }

        constructor() {
                this.bindToFirebase();
        }

        bindToFirebase() {
                //Initialise connection to Firebase user 
                //authentication status and data
        }
}

const users = new Users();

export default users;
```

这些都是我们在这个商店中需要的所有属性和方法。有几个标志（那些包含动词-ing 形式的属性）需要注意网络活动。现在让我们实现每个方法：

```jsx
@action login = function(username, password) {
        this.loggingIn = true;
        this.loggingError = null;
        firebase.auth().signInWithEmailAndPassword(username, password)
        .then(() => {
                this.loggingIn = false;
                notifications.init((notificationsToken) => {
                        this.setNotificationsToken(notificationsToken);
                });
        })
        .catch((error) => {
                this.loggingIn = false;
                this.loggingError = error.message;
        });
}
```

使用 Firebase 登录就像在他们的身份验证 SDK 上调用`signInWithEmailAndPassword`一样简单。如果登录成功，我们将初始化通知模块以使设备能够接收推送通知。在注销时，我们将遵循相反的路径：

```jsx
@action logout = function() {
        notifications.unbind();
        this.setNotificationsToken('');
        firebase.auth().signOut();
}
```

在注册操作中，除了设置网络活动的适当标志之外，我们还需要验证用户输入了名称，初始化通知，并将名称存储在数据库中：

```jsx
@action register = function(email, password, name) {
        if(!name || name == '') {
                this.registering = false;
                this.registeringError = 'Name was not entered';
                return;
        }
        this.registering = true;
        this.registeringError = null;
        firebase.auth().createUserWithEmailAndPassword(email, password)
        .then((user) => {
                this.registering = false;
                notifications.init((notificationsToken) => {
                        this.setNotificationsToken(notificationsToken);
                });
                firebaseApp.database().ref('/users/' + user.uid).set({
                        name: name
                });
        })
        .catch((error) => {
                this.registering = false;
                this.registeringError = error.message;
        })
}
```

设置通知令牌只是数据库中的简单更新：

```jsx
@action setNotificationsToken(token) {
        if(!this.id) return;
        this.notificationsToken = token;
        firebaseApp.database().ref('/users/' + this.id).update({
                notificationsToken: token
        });
}
```

`searchUsers()`没有标记为`@action`，因为它不会修改我们应用程序的状态，而只是在数据库中搜索并返回具有提供的名称的用户列表：

```jsx
searchUsers(name) {
        return new Promise(function(resolve) {
                firebaseApp.database().ref('/users/').once('value')
                .then(function(snapshot) {
                        let foundUsers = [];
                        const users = snapshot.val();
                        for(var id in users) {
                                if(users[id].name === name) {
                                        foundUsers.push({
                                                name: users[id].name,
                                                avatar: 
                                                users[id].avatar,
                                                notificationsToken:  
                                                users[id].
                                                notificationsToken,
                                                id
                                        });
                                }
                        }
                        resolve(foundUsers);
                });
        });
}
```

由于我们正在进行的请求的异步性质，我们将结果作为一个 promise 返回。

最后，`bindToFirebase()`将把此存储中的属性附加到 Firebase 数据库中的数据快照上。此方法由构造函数调用，因此它用作用户数据的初始化。重要的是要注意，当身份验证状态更改时，此数据将被更新，以始终反映用户的最新数据：

```jsx
bindToFirebase() {
  return firebase.auth().onAuthStateChanged((user) => {
    if(this.chatsBind && typeof this.chatsBind.off === 'function')  
      this.chatsBind.off();
    if(this.userBind && typeof this.userBind.off === 'function') 
      this.userBind.off();

    if (user) {
      this.id = user.uid;
      this.isLoggedIn = true;
      this.chatsBind = chats.bindToFirebase(user.uid);
      this.userBind = firebaseApp.database().ref('/users/' + this.id).
                                             on('value', (snapshot) =>  
    {
        const userObj = snapshot.val();
        if(!userObj) return;
        this.name = userObj.name;
        this.avatar = userObj.avatar;
      });
    } else {
      this.id = null;
      this.isLoggedIn = false;
      this.userBind = null;
      this.name = null;
      this.avatar = null;
    }
  });
}
```

我们将存储聊天数据的监听器（作为`this.chatsBind`）和用户数据的监听器（作为`this.userBind`），这样我们就可以在每次`auth`状态更改之前删除它们（通过调用`off()`方法），然后附加新的监听器。

# 聊天存储

这个存储负责保存所有与聊天和消息相关的数据和逻辑，但它还有助于在用户登录时初始化`chats`存储：

```jsx
/*** src/stores/chats.js ***/

import { observable, computed, map, toJS, action } from 'mobx';
import { AsyncStorage } from 'react-native'

import { firebaseApp } from '../firebase'
import notifications from '../notifications'

class Chats {
  @observable list;
  @observable selectedChatMessages;
  @observable downloadingChats = false;
  @observable downloadingChat = false;

  @action addMessages = function(chatId, contactId, messages) {
    //add a list of messages to a chat
  }

  @action selectChat = function(id) {
    //set a chat as selected and retrieve all the messages for it
  }

  @action add(user1, user2) {
    //add a new chat to the list of chats for the users in it
  }

  bindToFirebase(userId) {
    //listen for the list of chats in Firebase to update the 
    @observable list
  }
}

const chats = new Chats()
export default chats;
```

我们将在`@observable list`中存储用户拥有的所有打开聊天的列表。当用户选择一个聊天时，我们将下载并同步该聊天上的消息列表到`@observable selectedChatMessages`。然后，我们将有一些标志，让用户知道我们正在从 Firebase 数据库下载数据。

让我们逐个查看每个方法。我们将从`addMessages`开始：

```jsx
@action addMessages = function(chatId, contactId, messages) {
  if(!messages || messages.length < 1) return;

  messages.forEach((message) => {
    let formattedMessage = {
      _id: message._id,
      user: {
        _id: message.user._id,
      }
    };
    if(message.text) formattedMessage.text = message.text;
    if(message.createdAt) formattedMessage.createdAt = 
      message.createdAt/1;
    if(message.user.name) formattedMessage.user.name = 
      message.user.name;
    if(message.user.avatar) formattedMessage.user.avatar = 
      message.user.avatar;
    if(message.image) formattedMessage.image = message.image;

    //add the message to the chat
    firebaseApp.database().ref('/messages/' + 
      chatId).push().set(formattedMessage);

    //notify person on the chat room
    firebaseApp.database().ref('/users/' + contactId).once('value')
    .then(function(snapshot) {
      var notificationsToken = snapshot.val().notificationsToken;
      notifications.sendNotification(notificationsToken, {
        sender: message.user.name,
        text: message.text,
        image: message.user.image,
        chatId
      });
    });
  });
}
```

此方法接收三个参数：

+   `chatId`：要添加消息的聊天的 ID。

+   `contactId`：我们要发送消息的用户的 ID。这将用于向用户的联系人发送通知。

+   `messages`：这是我们想要添加到聊天中的所有消息的数组。

我们将循环遍历消息列表，按照我们想要存储的方式格式化消息。然后，我们将在数据库引用上调用`set()`方法，将新消息保存在 Firebase 的数据库中。最后，我们需要向我们的联系人发送通知，所以我们通过查询`users`集合的`contactId`来检索他们的通知令牌。

通常由后端处理发送通知，但由于我们正在将所有逻辑设置在应用程序本身上，因此我们需要构建一个发送通知的函数。我们已经在我们的通知`module: notifications.sendNotification(notificationsToken, data);`中完成了这个。

让我们看看当我们选择一个聊天来显示它的消息时会发生什么：

```jsx
@action selectChat = function(id) {
  this.downloadingChat = true;
  if(this.chatBind && typeof this.chatBind.off === 'function') 
  this.chatBind.off();
  this.chatBind = firebaseApp.database().ref('/messages/' + id)
  .on('value', (snapshot) => {
    this.selectedChatMessages = [];
    this.downloadingChat = false;
    const messagesObj = snapshot.val();
    for(var id in messagesObj) {
      this.selectedChatMessages.push({
        _id: id,
        text: messagesObj[id].text,
        createdAt: messagesObj[id].createdAt,
        user: {
          _id: messagesObj[id].user._id,
          name: messagesObj[id].user.name,
          avatar: messagesObj[id].user.avatar
        },
        image: messagesObj[id].image
      });
    }
  });
}
```

这里的主要功能是将监听器附加到消息/聊天 ID 集合，它将使用数据库中所选聊天的消息列表与`this.selectedChatMessages` observable 同步。这意味着每当新消息存储在 Firebase 中时，`this.selectedChatMessages`将同步反映出来。这就是 Firebase SDK 中`on()`方法的工作原理：我们传递一个回调，我们可以使用它来将实时数据库与我们应用程序的状态同步。

使用`add()`方法将添加新的聊天：

```jsx
@action add(user1, user2) {
  return new Promise(function(resolve, reject) {
    firebaseApp.database().ref('/chats/' + user1.id + '/' + user1.id + 
    user2.id).set({
      name: user2.name,
      image: user2.avatar,
      contactId: user2.id
    }).then(() => {
      firebaseApp.database().ref('/chats/' + user2.id + '/'
                                 + user1.id + 
      user2.id).set({
        name: user1.name,
        image: user1.avatar,
        contactId: user1.id
      }).then(() => {
        resolve();
      })
    })
  });
}
```

在这里，我们正在构建并返回一个承诺，当两个聊天（每个用户参与聊天一个）更新时将解决。这两个数据库更新可以看作是数据的复制，但它也将减少数据结构的复杂性，因此减少我们代码库的可读性。

这个存储中的最后一个方法是`bindToFirebase()`：

```jsx
bindToFirebase(userId) {
  this.downloadingChats = true;
  return firebaseApp.database().ref('/chats/' + userId).
                                on('value', (snapshot) => {
    this.downloadingChats = false;
    const chatsObj = snapshot.val();
    this.list = [];
    for(var id in chatsObj) {
      this.list.push({
        id,
        name: chatsObj[id].name,
        image: chatsObj[id].image,
        contactId: chatsObj[id].contactId
      });
    }
  });
}
```

正如我们在`users`存储中看到的，当用户登录并将监听器附加到`chats/<userId>`数据快照时，将调用此方法，以便将所有聊天数据与`this.list`属性上的数据库同步。

为了方便起见，我们将两个存储都分组在`src/stores/index.js`中，这样我们可以在一行代码中导入它们。

```jsx
/*** src/stores/index.js ***/

import users from './users';
import chats from './chats';

export {
  users,
  chats
};
```

这就是我们将要使用的存储。正如我们所看到的，大部分业务逻辑都在这里处理，因此可以进行彻底的测试。现在让我们转到我们将用于通知的辅助程序。

# 使用 Firebase 进行推送通知

Firebase 集成了 iOS 和 Android 的推送通知服务，但不幸的是，它没有提供任何 JavaScript SDK 来使用它。为此，创建了一个开源库，将 Objective-C 和 Java SDK 桥接到 React Native 模块中：`react-native-fcm`。

我们不会在本书中涵盖此模块的安装，因为这是一个不断变化的过程，最好在其存储库上进行跟踪[`github.com/evollu/react-native-fcm.`](https://github.com/evollu/react-native-fcm)

我们决定将此模块的逻辑抽象到我们的`src/notifications.js`文件中，以便在保持可维护性的同时为每个组件提供可用性。让我们来看一下这个文件：

```jsx
/*** src/notifications.js ***/

import {Platform} from 'react-native';
import FCM, {FCMEvent, RemoteNotificationResult, WillPresentNotificationResult, NotificationType} from 'react-native-fcm';

let notificationListener = null;
let refreshTokenListener = null;
const API_URL = 'https://fcm.googleapis.com/fcm/send';
const FirebaseServerKey = '<Your Firebase Server Key>';

const init = (cb) => {
  FCM.requestPermissions();
  FCM.getFCMToken().then(token => {
    cb(token)
  });
  refreshTokenListener = FCM.on(FCMEvent.RefreshToken, (token) => {
    cb(token);
  });
}

const onNotification = (cb) => {
  notificationListener = FCM.on(FCMEvent.Notification, (notif) => {
      cb(notif);

      if(Platform.OS ==='ios'){
        switch(notif._notificationType){
          case NotificationType.Remote:
            notif.finish(RemoteNotificationResult.NewData)
            break;
          case NotificationType.NotificationResponse:
            notif.finish();
            break;
          case NotificationType.WillPresent:
            notif.finish(WillPresentNotificationResult.All)
            break;
        }
      }
  })
}

const unbind = () => {
  if(notificationListener) notificationListener.remove();
  if(refreshTokenListener) refreshTokenListener.remove();
}

const sendNotification = (token, data) => {
  let body = JSON.stringify({
    "to": token,
    "notification": {
                "title": data.sender || '',
                "body": data. text || '',
                "sound": "default"
        },
    "data": {
      "name": data.sender,
      "chatId": data.chatId,
      "image": data.image
    },
        "priority": 10
  });

  let headers = new Headers({
                "Content-Type": "application/json",
                "Content-Length": parseInt(body.length),
                "Authorization": "key=" + FirebaseServerKey
  });

  fetch(API_URL, { method: "POST", headers, body })
        .then(response => console.log("Send response", response))
        .catch(error => console.log("Error sending ", error));
}

export default { init, onNotification, sendNotification, unbind }
```

此模块中公开了四个函数：

+   `init`: 请求接收推送通知的权限（如果尚未授予），并请求设备令牌或在更改时刷新它。

+   `onNotification`: 当收到通知时，调用提供的回调函数。在 iOS 中，它还调用通知上的适当方法来关闭循环。

+   `unbind`: 停止监听推送通知。

+   `sendNotification`: 这将格式化并发送推送通知到特定设备，使用提供的通知令牌。

在 Firebase 中发送通知可以使用他们的 HTTP API，所以我们将使用`fetch`来发送带有适当标头和主体数据的`POST`请求。

现在，我们拥有了构建屏幕和组件所需的所有逻辑。

# 登录

`<Login />`组件在逻辑上严重依赖于`users`存储，因为它主要用于呈现登录和注册两个表单。所有表单的验证都由 Firebase 完成，所以我们只需要专注于呈现 UI 元素和调用适当的存储方法。

在这个屏幕中，我们将使用`react-native-keyboard-aware-scroll`视图，这是一个提供自动滚动`<Scrollview />`的模块，它会对任何聚焦的`<TextInput />`做出反应，以便在键盘弹出时它们不会被隐藏。

让我们来看一下代码：

```jsx
/*** src/screens/Login.js ***/

import React, { PropTypes } from 'react'
import {
  ScrollView,
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';
import { observer, inject } from 'mobx-react/native'
import Icon from 'react-native-vector-icons/FontAwesome'
import { KeyboardAwareScrollView } from 'react-native-keyboard-aware-scroll-view'

import LoginForm from '../components/LoginForm'
import RegistrationForm from '../components/RegistrationForm'

@inject('users') @observer
class Login extends React.Component {
  onLogin(email, password) {
    this.props.users.login(email, password);
  }

  onPressRegister(email, password, name) {
    this.props.users.register(email, password, name);
  }

  render() {
    return (
      <KeyboardAwareScrollView style={{padding: 20, marginTop: 20, 
        backgroundColor: '#eee'}}>
        <Icon name="comments" size={60} color='#ccc' 
          style={{alignSelf: 'center', paddingBottom: 20}}/>
        <View style={{alignItems: 'center', marginBottom: 20}}>
          <Text>- please, login to continue -</Text>
        </View>
        <LoginForm
          onPress={this.onLogin.bind(this)}
          busy={this.props.users.loggingIn}
          loggingError={this.props.users.loggingError}
        />
        <View style={{alignItems: 'center', marginTop: 20, 
                      marginBottom: 20}}>
          <Text>- or register -</Text>
        </View>
        <RegistrationForm
          onPress={this.onPressRegister.bind(this)}
          busy={this.props.users.registering}
          registeringError={this.props.users.registeringError}
        />
      </KeyboardAwareScrollView>
    )
  }
}

export default Login;
```

我们将登录屏幕分为两个表单：`<LoginForm />`和`<RegistrationForm />`。这两个组件都需要传递三个 props：

+   `onPress`: 当按下“发送”按钮时组件需要执行的操作。

+   `busy`: 我们是否在等待远程数据？

+   `loginError`/`registrationError`: 登录/注册时发生的错误的描述（如果发生了）。

我们将整个屏幕包裹在`<KeyboardAwareScrollView />`中，以确保焦点时没有`<TextInput />`被键盘隐藏。现在让我们来看一下`LoginForm`：

```jsx
/*** src/components/LoginForm.js ***/

import React, { PropTypes } from 'react'
import {
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';

class LoginForm extends React.Component {
  state= {
    loginEmail: '',
    loginPassword: ''
  }

  onPressLogin() {
    this.props.onPress(this.state.loginEmail, 
    this.state.loginPassword);
  }

  render() {
    return (
        <View style={{backgroundColor: 'white', padding: 15, 
                      borderRadius: 10}}>
          {
            this.props.loggingError &&
            <View style={{backgroundColor: '#fcc', borderRadius: 5, 
              alignItems: 'center', marginBottom: 10}}>
              <Text>{this.props.loggingError}</Text>
            </View>
          }
          <TextInput
            autoCapitalize='none'
            autoCorrect={false}
            keyboardType='email-address'
            returnKeyType='next'
            style={{height: 40}}
            onChangeText={(loginEmail) => this.setState({loginEmail})}
            value={this.state.loginEmail}
            placeholder='email'
            onSubmitEditing={(event) => {
              this.refs.loginPassword.focus();
            }}
          />
          <TextInput
            ref='loginPassword'
            style={{height: 40}}
            onChangeText={(loginPassword) => 
            this.setState({loginPassword})}
            value={this.state.loginPassword}
            secureTextEntry={true}
            placeholder='password'
          />
          {
            this.props.busy ?
            <ActivityIndicator/>
            :
            <Button
              onPress={this.onPressLogin.bind(this)}
              title='Login'
            />
          }
        </View>
      )
  }
}

export default LoginForm;
```

对于包含电子邮件的`<TextInput />`元素，我们设置了`keyboardType='email-address'`属性，以便`@`符号在软键盘上易于访问。还有其他选项，比如数字键盘，但我们只会在这个应用中使用`'email-address'`。

`<TextInput />`的另一个有用的属性是`returnKeyType`。我们为那些不是最后一个的表单输入设置`returnKeyType='next'`，以便在键盘中显示`Next`按钮，这样用户就知道他们可以通过点击该按钮进入下一个输入。这个属性与以下属性一起使用：

```jsx
onSubmitEditing={(event) => {
  this.refs.loginPassword.focus();
}}
```

`onSubmitEditing`是一个`<TextInput />`属性，当用户在键盘上按下`Return`或`Next`按钮时将被调用。我们使用它来聚焦到下一个`<TextInput />`，在处理表单时非常用户友好。为了获取下一个`<TextInput />`的引用，我们使用`ref`，这并不是最安全的方式，但对于简单的表单来说已经足够好了。为了使其工作，我们需要将相应的`ref`分配给下一个`<TextInput />`：`ref='loginPassword'`。

`RegistrationForm`是一个非常类似的表单：

```jsx
/*** src/components/RegistrationForm ***/

import React, { PropTypes } from 'react'
import {
  ScrollView,
  TextInput,
  Button,
  Text,
  View,
  Image,
  ActivityIndicator
} from 'react-native';

class RegisterForm extends React.Component {
  state= {
    registerEmail: '',
    registerPassword: '',
    registerName: ''
  }

  onPressRegister() {
    this.props.onPress(this.state.registerEmail, 
    this.state.registerPassword, this.state.registerName);
  }

  render() {
    return (
      <View style={{backgroundColor: 'white', padding: 15, 
                    borderRadius: 10}}>
        {
          this.props.registeringError &&
          <View style={{backgroundColor: '#fcc', borderRadius: 5, 
            alignItems: 'center', marginBottom: 10}}>
            <Text>{this.props.registeringError}</Text>
          </View>
        }
        <TextInput
          autoCapitalize='none'
          autoCorrect={false}
          keyboardType='email-address'
          returnKeyType='next'
          style={{height: 40}}
          onChangeText={(registerEmail) => 
          this.setState({registerEmail})}
          value={this.state.registerEmail}
          placeholder='email'
          onSubmitEditing={(event) => {
            this.refs.registerName.focus();
          }}
        />
        <TextInput
          ref='registerName'
          style={{height: 40}}
          onChangeText={(registerName) => 
          this.setState({registerName})}
          returnKeyType='next'
          value={this.state.registerName}
          placeholder='name'
          onSubmitEditing={(event) => {
            this.refs.registerPassword.focus();
          }}
        />
        <TextInput
          ref='registerPassword'
          style={{height: 40}}
          onChangeText={(registerPassword) => 
          this.setState({registerPassword})}
          value={this.state.registerPassword}
          secureTextEntry={true}
          placeholder='password'
        />
        {
          this.props.busy ?
          <ActivityIndicator/>
          :
          <Button
            onPress={this.onPressRegister.bind(this)}
            title='Register'
          />
        }
      </View>
    )
  }
}

export default RegisterForm;
```

# 聊天

这是显示打开聊天列表的屏幕。这里需要注意的特殊之处是，我们使用第二个导航器在聊天列表的顶部显示选定的聊天。这意味着我们的`Chats`组件中需要一个`StackNavigator`，其中包含两个屏幕：`ChatList`和`Chat`。当用户从`ChatList`中点击一个聊天时，`StackNavigator`将在`ChatList`的顶部显示选定的聊天，通过标题栏中的标准`< back`按钮使聊天列表可用。

为了列出聊天，我们将使用`<FlatList />`，这是一个用于呈现简单、平面列表的高性能界面，支持大多数`<ListView />`的功能：

```jsx
/*** src/screens/Chats.js ***/

import React, { PropTypes } from 'react'
import { View, Text, FlatList, ActivityIndicator } from 'react-native'
import { observer, inject } from 'mobx-react/native'
import { StackNavigator } from 'react-navigation'
import Icon from 'react-native-vector-icons/FontAwesome'
import notifications from '../notifications'

import ListItem from '../components/ListItem'
import Chat from './Chat'

@inject('chats') @observer
class ChatList extends React.Component {
  imgPlaceholder = 
  'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                    2160923_960_720.png'

  componentWillMount() {
    notifications.onNotification((notif)=>{
      this.props.navigation.goBack();
      this.props.navigation.navigate('Chat', {
        id: notif.chatId,
        name: notif.name || '',
        image: notif.image || this.imgPlaceholder
      })
    });
  }

  render () {
    return (
      <View>
        {
          this.props.chats.list &&
          <FlatList
            data={this.props.chats.list.toJS()}
            keyExtractor={(item, index) => item.id}
            renderItem={({item}) => {
              return (
                <ListItem
                  text={item.name}
                  image={item.image || this.imgPlaceholder}
                  onPress={() => this.props.navigation.navigate('Chat', 
                  {
                    id: item.id,
                    name: item.name,
                    image: item.image || this.imgPlaceholder,
                    contactId: item.contactId
                  })}
                />
              )
            }}
          />
        }
        {
          this.props.chats.downloadingChats &&
          <ActivityIndicator style={{marginTop: 20}}/>
        }
      </View>
    )
  }
}

const Navigator = StackNavigator({
  Chats: {
    screen: ChatList,
    navigationOptions: ({navigation}) => ({
      title: 'Chats',
    }),
  },
  Chat: {
    screen: Chat
  }
});

export default class Chats extends React.Component {
  static navigationOptions = {
    tabBarLabel: 'Chats',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="comment-o" size={30} color={tintColor}/>
    )
  };

  render() {
      return <Navigator />
  }
}
```

我们注意到的第一件事是，我们正在注入`chats`存储，其中保存了聊天列表：`@inject('chats') @observer`。我们需要这样做来构建我们的`<FlatList />`，基于`this.props.chats.list`，但由于聊天列表是一个可观察的 MobX 对象，我们需要使用它的`toJS()`方法来将其转换为 JavaScript 数组。

在`componentWillMount()`函数中，我们将在通知模块上调用`onNotification`，以便在用户每次按下设备上的推送通知时打开相应的聊天。因此，我们将在导航器上使用`navigate()`方法来打开适当的聊天屏幕，包括联系人的姓名和头像。

# ListItem

聊天列表依赖于`<ListItem />`来呈现列表中的每个特定聊天。这个组件是我们创建的一个自定义 UI 类，用于减少`ChatList`组件的复杂性：

```jsx
/*** src/components/ListItem.js ***/

import React, { PropTypes } from 'react'
import { View, Image, Text, TouchableOpacity } from 'react-native'
import Icon from 'react-native-vector-icons/FontAwesome'

const ListItem = (props) => {
  return (
    <TouchableOpacity onPress={props.onPress}>
      <View style={{height: 60, borderColor: '#ccc', 
                    borderBottomWidth: 1, 
        marginLeft: 10, flexDirection: 'row'}}>
        <View style={{padding: 15, paddingTop: 10}}>
          <Image source={{uri: props.image}} style={{width: 40, 
                                                     height: 40, 
            borderRadius: 20, resizeMode: 'cover'}}/>
        </View>
        <View style={{padding: 15, paddingTop: 20}}>
          <Text style={{fontSize: 15}}>{ props.text }</Text>
        </View>
        <Icon name="angle-right" size={20} color="#aaa" 
          style={{position: 'absolute', right: 20, top: 20}}/>
      </View>
    </TouchableOpacity>
  )
}

export default ListItem
```

这个组件上有很少的逻辑，它只接收一个名为`onPress()`的 prop，当`<ListItem />`被按下时将被调用，正如我们在这个组件的父组件中看到的，它将打开聊天屏幕，显示特定聊天中的消息列表。让我们来看看`chat`屏幕，那里渲染了特定聊天的所有消息。

# Chat

为了保持我们的代码简洁和可维护，我们将使用`GiftedChat`来渲染聊天中的所有消息，但是我们仍然需要做一些工作来正确渲染这个屏幕：

```jsx
/*** src/screens/Chat.js ***/

import React, { PropTypes } from 'react'
import { View, Image, ActivityIndicator } from 'react-native';
import { observer, inject } from 'mobx-react/native'
import { GiftedChat } from 'react-native-gifted-chat'

@inject('chats', 'users') @observer
class Chat extends React.Component {
  static navigationOptions = ({ navigation, screenProps }) => ({
    title: navigation.state.params.name,
    headerRight: <Image source={{uri: navigation.state.params.image}} 
    style={{
      width: 30,
      height: 30,
      borderRadius: 15,
      marginRight: 10,
      resizeMode: 'cover'
    }}/>
  })

  onSend(messages) {
    this.props.chats.addMessages(this.chatId, this.contactId, 
    messages);
  }

  componentWillMount() {
 this.contactId = this.props.navigation.state.params.contactId;
    this.chatId = this.props.navigation.state.params.id;
    this.props.chats.selectChat(this.chatId);
  }

  render () {
    var messages = this.props.chats.selectedChatMessages;
    if(this.props.chats.downloadingChat) {
      return <View><ActivityIndicator style={{marginTop: 20}}/></View>
    }

    return (
      <GiftedChat
        onSend={(messages) => this.onSend(messages)}
        messages={messages ? messages.toJS().reverse() : []}
        user={{
          _id: this.props.users.id,
          name: this.props.users.name,
          avatar: this.props.users.avatar
        }}
      />
    )
  }
}

export default Chat;
```

我们还需要为我们的`<Chat />`组件注入一些存储。这一次，我们需要`users`和`chats`存储，它们将作为组件内的 props 可用。该组件还期望从导航器接收两个参数：`chatId`（聊天的 ID）和`contactId`（用户正在聊天的人的 ID）。

当组件准备挂载（`onComponentWillMount()`）时，我们在组件内部保存`chatId`和`contactId`到更方便的变量中，并在`chats`存储上调用`selectChat()`方法。这将触发一个请求到 Firebase 数据库，以获取所选聊天的消息，这些消息将通过`chats`存储进行同步，并通过`this.props.chats.selectedChatMessages`在组件中访问。MobX 还将更新一个`downloadingChat`属性，以确保我们让用户知道数据正在从 Firebase 中检索。

最后，我们需要为`GiftedChat`添加一个`onSend()`函数，它将在每次按下`发送`按钮时调用`chats`存储上的`addMessages()`方法，以将消息发布到 Firebase。

`GiftedChat`在很大程度上帮助我们减少了为了渲染聊天消息列表而需要做的工作。另一方面，我们需要按照`GiftedChat`的要求格式化消息，并提供一个`onSend()`函数，以便在需要将消息发布到我们的后端时执行。

# 搜索

搜索屏幕分为两部分：一个`<TextInput />`用于用户搜索姓名，一个`<FlatList />`用于显示输入姓名找到的联系人列表。

```jsx
import React, { PropTypes } from 'react'
import { View, TextInput, Button, FlatList } from 'react-native'
import Icon from 'react-native-vector-icons/FontAwesome'
import { observer, inject } from 'mobx-react/native'

import ListItem from '../components/ListItem'

@inject('users', 'chats') @observer
class Search extends React.Component {
  imgPlaceholder = 'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                   2160923_960_720.png'

  state = {
    name: '',
    foundUsers: null
  }

  static navigationOptions = {
    tabBarLabel: 'Search',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="search" size={30} color={tintColor}/>
    )
  };

  onPressSearch() {
    this.props.users.searchUsers(this.state.name)
    .then((foundUsers) => {
      this.setState({ foundUsers });
    });
  }

  onPressUser(user) {
    //open a chat with the selected user
  }

  render () {
    return (
      <View>
        <View style={{padding: 20, marginTop: 20, 
                      backgroundColor: '#eee'}}>
          <View style={{backgroundColor: 'white', padding: 15, 
                        borderRadius: 10}}>
            <TextInput
              style={{borderColor: 'gray', borderBottomWidth: 1, 
                      height: 40}}
              onChangeText={(name) => this.setState({name})}
              value={this.state.name}
              placeholder='Name of user'
            />
            <Button
              onPress={this.onPressSearch.bind(this)}
              title='Search'
            />
          </View>
        </View>
        {
          this.state.foundUsers &&
          <FlatList
            data={this.state.foundUsers}
            keyExtractor={(item, index) => index}
            renderItem={({item}) => {
              return (
                <ListItem
                  text={item.name}
                  image={item.avatar || this.imgPlaceholder}
                  onPress={this.onPressUser.bind(this, item)}
                />
              )
            }}
          />
        }
      </View>
    )
  }
}

export default Search;
```

这个组件需要注入两个存储（`users`和`chats`）。`users`存储用于在用户点击`搜索`按钮时调用`searchUsers()`方法。这个方法不会修改状态，因此我们需要提供一个回调来接收找到的用户列表，最终将该列表设置为组件的状态。

第二个存储`chats`将用于通过从`onPressUser()`函数调用`add()`在 Firebase 中存储打开的聊天：

```jsx
onPressUser(user) {
  this.props.chats.add({
    id: this.props.users.id,
    name: this.props.users.name,
    avatar: this.props.users.avatar || this.imgPlaceholder,
    notificationsToken: this.props.users.notificationsToken || ''
  }, {
    id: user.id,
    name: user.name,
    avatar: user.avatar || this.imgPlaceholder,
    notificationsToken: user.notificationsToken || ''
  });

  this.props.navigation.navigate('Chats', {});
}
```

`chats`存储中的`add()`方法需要传递两个参数：每个用户在新打开的聊天中。这些数据将被正确存储在 Firebase 中，因此两个用户将在应用程序的聊天列表中看到聊天。添加新聊天后，我们将导航应用程序到聊天屏幕，以便用户可以看到添加是否成功。

# 个人资料

个人资料屏幕显示用户的头像、姓名和“注销”按钮以退出登录：

```jsx
import React, { PropTypes } from 'react'
import { View, Image, Button, Text } from 'react-native'
import { observer, inject } from 'mobx-react/native'
import Icon from 'react-native-vector-icons/FontAwesome'

import notifications from '../notifications'

@inject('users') @observer
class Profile extends React.Component {
  static navigationOptions = {
    tabBarLabel: 'Profile',
    tabBarIcon: ({ tintColor }) => (
      <Icon name="user" size={30} color={tintColor}/>
    ),
  };

  imgPlaceholder = 
  'https://cdn.pixabay.com/photo/2017/03/21/02/00/user-
                    2160923_960_720.png'

  onPressLogout() {
 this.props.users.logout();
  }

  render () {
    return (
        <View style={{ padding: 20 }}>
          {
              this.props.users.name &&
              <View style={{ flexDirection: 'row', alignItems: 'center' 
          }}>
                <Image
                  source={{uri: this.props.users.avatar || 
                  this.imgPlaceholder}}
                  style={{width: 100, height: 100, borderRadius: 50, 
                          margin: 20, resizeMode: 'cover'}}
                />
                <Text style={{fontSize: 25}}>{this.props.users.name}
               </Text>
              </View>
          }
          <Button
            onPress={this.onPressLogout.bind(this)}
            title="Logout"
          />
        </View>
    )
  }
}

export default Profile;
```

注销过程是通过在`users`存储上调用`logout()`方法来触发的。由于我们在`src/main.js`文件中控制了身份验证状态，当注销成功时，应用程序将自动返回到登录或注册屏幕。

# 摘要

我们涵盖了大多数现代企业应用程序的几个重要主题：用户管理、数据同步、复杂的应用程序状态和处理表单。这是一个完整的应用程序，我们设法用一个小的代码库和 MobX 和 Firebase 的帮助来修复它。

Firebase 非常有能力在生产中处理这个应用程序，拥有大量用户，但构建我们自己的后端系统不应该是一个复杂的任务，特别是如果我们有使用`socket.io`和实时数据库的经验。

这一章节中有一些方面是缺失的，比如处理安全性（可以完全在 Firebase 内完成），或者为超过两个用户创建聊天室。无论如何，这些方面都超出了 React Native 的环境，所以它们被有意地省略了。

完成本章后，我们应该能够在 Firebase 和 MobX 之上构建任何应用程序，因为我们涵盖了这两种技术的最常用的用户案例。当然，还有一些更复杂的情况被省略了，但通过对本章中解释的基础知识有很好的理解，它们可以很容易地学会。

在下一章中，我们将构建一种非常不同的应用程序：一个用 React Native 编写的游戏。
