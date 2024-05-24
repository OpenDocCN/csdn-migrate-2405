# ReactNative 蓝图（一）

> 原文：[`zh.annas-archive.org/md5/70729A755431D37E9DA3E2FBADC90F35`](https://zh.annas-archive.org/md5/70729A755431D37E9DA3E2FBADC90F35)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

React Native 帮助 Web 和移动开发人员构建与任何其他本地开发的应用性能相同的 iOS 和 Android 应用程序。使用这个库可以构建的应用范围非常广泛。从电子商务到游戏，React Native 都是任何移动项目的良好选择，因为它具有灵活性和可扩展性。它具有良好的性能，可以重用 React 知识，具有导入 npm 包的能力，并且在 iOS 和 Android 上使用相同的代码库。毫无疑问，React Native 不仅是本地开发的一个很好的替代方案，而且也是将 Web 开发人员引入移动项目的一个很好的方式。本书旨在让 JavaScript 和 React 开发人员了解如何使用 React Native 从头开始构建市场上一些最流行的应用。我们将在 iOS 和 Android 上构建所有应用，除非这些应用只在其中一个平台上有意义。

# 本书所需的内容

本书中构建的大多数应用程序将在 Android 和 iOS 上运行，因此需要运行 Linux、Windows 或 OSX 的计算机，尽管我们建议使用任何一台苹果电脑（运行 OSX 10 或更高版本）同时运行两个移动平台，因为一些示例将需要在 XCode 上工作，而 XCode 只能安装在 OSX 上。

我们在示例中将使用的其他软件包括：

+   XCode

+   Android Studio

+   一个 React-ready 的 IDE（如 Atom，VS Code 和 SublimeText）

当然，我们还需要安装 React Native 和 React Native CLI（[`facebook.github.io/react-native/docs/getting-started.html`](https://facebook.github.io/react-native/docs/getting-started.html)）。

# 本书适合的读者是谁？

本书的目标读者是试图了解如何使用 React Native 构建不同类型应用的 JavaScript 开发人员。他们将找到一套可以应用于构建任何类型应用的最佳实践和经过验证的架构策略。

尽管本书不会解释 React 的一些基本概念，但并不需要特定的 React 技能来跟随，因为我们不会深入研究复杂的 React 模式。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们必须创建一个`src`文件夹，我们将在其中存储所有的 React 代码。”

此外，在大的代码块中，当一些代码片段不相关或在不同的地方进行了审查时，它们将被省略号（...）替换。

代码块设置如下：

```jsx
/*** index.js ***/

import { AppRegistry } from 'react-native';
import App from './src/main';
AppRegistry.registerComponent('GroceriesList', () => App);
```

任何命令行输入或输出都以以下方式书写：

```jsx
react-native run-ios
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“在添加产品屏幕上的返回按钮。”

提示和重要说明会出现在这样的框中。技巧和窍门会以这种方式出现。


# 第一章：购物清单

大多数现代语言和框架用于展示待办事项清单作为它们的示例应用程序。这是了解框架基础知识的绝佳方式，如用户交互、基本导航或代码结构。我们将以更加务实的方式开始：构建一个购物清单应用程序。

您将能够使用 React Native 代码开发此应用程序，为 iOS 和 Android 构建它，并最终安装在您的手机上。这样，您不仅可以向朋友展示您所构建的内容，还可以了解您可以自己构建的缺失功能，思考用户界面改进，最重要的是，激励自己继续学习 React Native，感受其真正的潜力。

在本章结束时，您将已经构建了一个完全功能的购物清单，可以在手机上使用，并且拥有创建和维护简单有状态应用程序所需的所有工具。

# 概述

React Native 的最强大功能之一是其跨平台能力；我们将为 iOS 和 Android 构建我们的购物清单应用程序，重用我们代码的 99%。让我们来看看这个应用在两个平台上的样子：

iOS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/80e9e967-6d95-4ece-9618-9315dca63086.png)

添加更多产品后，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/7209e648-c819-45e5-bf3c-90ebf6db1325.png)

Android：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/a7448887-adee-415c-a4fa-e6bff040a8eb.png)

添加更多产品后，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/b40260c4-d53a-4e30-b84b-6fa59943bc99.png)

该应用程序在两个平台上的用户界面非常相似，但我们不需要过多关注差异（例如，“添加产品”屏幕上的返回按钮），因为它们将由 React Native 自动处理。

重要的是要理解每个平台都有自己的用户界面模式，并且遵循它们是一个好的做法。例如，iOS 通常通过选项卡来处理导航，而 Android 更喜欢抽屉菜单，因此如果我们希望在两个平台上都有满意的用户，我们应该构建这两种导航模式。无论如何，这只是一个建议，任何用户界面模式都可以在每个平台上构建。在后面的章节中，我们将看到如何在同一代码库中以最有效的方式处理两种不同的模式。

该应用包括两个屏幕：您的购物清单和可以添加到您的购物清单的产品列表。用户可以通过圆形蓝色按钮从购物清单屏幕导航到“添加产品”屏幕，然后通过<返回按钮返回。我们还将在购物清单屏幕上构建一个清除按钮（圆形红色按钮），以及在“添加产品”屏幕上添加和删除产品的功能。

在本章中，我们将涵盖以下主题：

+   基本 React Native 项目的文件夹结构

+   React Native 的基本 CLI 命令

+   基本导航

+   JS 调试

+   实时重新加载

+   使用 NativeBase 进行样式设置

+   列表

+   基本状态管理

+   处理事件

+   `AsyncStorage`

+   提示弹出

+   分发应用

# 设置我们的项目

React Native 具有非常强大的 CLI，我们需要安装它才能开始我们的项目。要安装，只需在命令行中运行以下命令（如果权限不够，可能需要使用`sudo`）：

```jsx
npm install -g react-native-cli
```

安装完成后，我们可以通过输入`react-native`来开始使用 React Native CLI。要启动我们的项目，我们将运行以下命令：

```jsx
react-native init --version="0.49.3" GroceriesList
```

此命令将创建一个名为`GroceriesList`的基本项目，其中包含构建 iOS 和 Android 应用所需的所有依赖项和库。一旦 CLI 完成安装所有软件包，您应该有一个类似于此的文件夹结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/127ee358-1f61-464c-8cdd-dc51619f81ab.png)

我们项目的入口文件是`index.js`。如果您想在模拟器上看到您的初始应用程序运行，可以再次使用 React Native 的 CLI：

```jsx
react-native run-ios
```

或者

```jsx
react-native run-android
```

假设您已经安装了 XCode 或 Android Studio 和 Android 模拟器，编译后您应该能够在模拟器上看到一个示例屏幕：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c08290d0-ef33-4138-b3b6-e44a8b34946c.png)

我们已经准备好设置开始实现我们的应用程序，但为了轻松调试并在模拟器中看到我们的更改，我们需要启用另外两个功能：远程 JS 调试和实时重新加载。

为了调试，我们将使用*React Native Debugger*，这是一个独立的应用程序，基于 React Native 的官方调试器，其中包括 React Inspector 和 Redux DevTools。它可以通过按照其 GitHub 存储库上的说明进行下载（[`github.com/jhen0409/react-native-debugger`](https://github.com/jhen0409/react-native-debugger)）。为了使这个调试器正常工作，我们需要在应用程序内部启用远程 JS 调试，方法是在模拟器中通过按下 iOS 上的*command* + *ctrl* + *Z*或 Android 上的*command* + *M*来打开 React Native 开发菜单。

如果一切顺利，我们应该看到以下菜单出现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/269055ed-9910-4a00-bba6-c43fe50bcd98.png)

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/67e2584e-18b2-48b8-8b05-c0c966e79b18.png)

现在，我们将按下两个按钮：Debug Remote JS 和 Enable Live Reload。完成后，我们的开发环境已经准备好开始编写 React 代码。

# 设置文件夹结构

我们的应用程序只包括两个屏幕：购物清单和添加产品。由于这样一个简单应用的状态应该很容易管理，我们不会添加任何状态管理库（例如 Redux），因为我们将通过导航组件发送共享状态。这应该使我们的文件夹结构相当简单：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/3e58d766-c67e-4b38-bffe-fb0b5d6b6875.png)

我们必须创建一个`src`文件夹，我们将在其中存储所有我们的 React 代码。自创建的文件`index.js`将包含以下代码：

```jsx
/*** index.js ***/

import { AppRegistry } from 'react-native';
import App from './src/main';
AppRegistry.registerComponent('GroceriesList', () => App);
```

简而言之，这些文件将导入我们应用程序的通用根代码，将其存储在名为`App`的变量中，然后通过`registerComponent`方法将这个变量传递给`AppRegistry`。`AppRegistry`是我们应该注册我们的根组件的组件。一旦我们这样做，React Native 将为我们的应用程序生成一个 JS 捆绑包，然后通过调用`AppRegistry.runApplication`在准备就绪时运行应用程序。

我们将写的大部分代码都将放在`src`文件夹中。对于这个应用程序，我们将在这个文件夹中创建我们的根组件（`main.js`），以及一个`screens`子文件夹，我们将在其中存储我们的两个屏幕（`ShoppingList`和`AddProduct`）。

现在让我们在继续编码之前安装应用程序的所有初始依赖项。在我们项目的根文件夹中，我们需要运行以下命令：

```jsx
npm install
```

运行该命令将为每个 React Native 项目安装所有基本依赖项。现在让我们安装这个特定应用程序将使用的三个软件包：

```jsx
npm install **native-base --save**
**npm install react-native-prompt-android --save**
**npm install react-navigation --save** 
```

在本章的后面，我们将解释每个包将被用于什么。

# 添加导航组件

大多数移动应用程序由多个屏幕组成，因此我们需要能够在这些屏幕之间“切换”。为了实现这一点，我们需要一个`Navigation`组件。React Native 自带了`Navigator`和`NavigatorIOS`组件，尽管 React 的维护者建议使用社区构建的外部导航解决方案`react-navigation`（[`github.com/react-community/react-navigation`](https://github.com/react-community/react-navigation)），这个解决方案非常高效，维护良好，并且功能丰富，所以我们将在我们的应用程序中使用它。

因为我们已经安装了导航模块（`react-navigation`），我们可以在`main.js`文件中设置和初始化我们的`Navigation`组件：

```jsx
/*** src/main.js ***/

import React from 'react';
import { StackNavigator } from 'react-navigation';
import ShoppingList from './screens/ShoppingList.js';
import AddProduct from './screens/AddProduct.js';

const Navigator = StackNavigator({
  ShoppingList: { screen: ShoppingList },
  AddProduct: { screen: AddProduct }
});

export default class App extends React.Component {
  constructor() {
    super();
  }

  render() {
    return <Navigator />;
  }
}
```

我们的根组件导入了应用程序中的两个屏幕（`ShoppingList`和`AddProduct`）并将它们传递给`StackNavigator`函数，该函数生成了`Navigator`组件。让我们深入了解一下`StackNavigator`的工作原理。

`StackNavigator`提供了一种让任何应用程序在屏幕之间进行过渡的方式，其中每个新屏幕都放置在堆栈的顶部。当我们请求导航到一个新屏幕时，`StackNavigator`将从右侧滑动新屏幕，并在 iOS 中的右上角放置一个`< Back`按钮，以返回到上一个屏幕，或者在 Android 中，新屏幕将从底部淡入，同时放置一个`<-`箭头以返回。使用相同的代码库，我们将在 iOS 和 Android 中触发熟悉的导航模式。`StackNavigator`也非常简单易用，因为我们只需要将我们应用程序中的屏幕作为哈希映射传递，其中键是我们想要为我们的屏幕设置的名称，值是导入的屏幕作为 React 组件。结果是一个`<Navigator/>`组件，我们可以渲染来初始化我们的应用程序。

# 使用 NativeBase 为我们的应用程序设置样式

React Native 包括一种强大的方式来使用 Flexbox 和类似 CSS 的 API 来为我们的组件和屏幕设置样式，但是对于这个应用程序，我们想要专注于功能方面，所以我们将使用一个包括基本样式组件的库，如按钮、列表、图标、菜单、表单等。它可以被视为 React Native 的 Twitter Bootstrap。

有几个流行的 UI 库，NativeBase 和 React Native 元素是最受欢迎和最受支持的两个。在这两者中，我们将选择 NativeBase，因为它对初学者来说稍微更清晰一些。

您可以在他们的网站上找到有关 NativeBase 如何工作的详细文档（[`docs.nativebase.io/`](https://docs.nativebase.io/)），但是在本章中，我们将介绍安装和使用其中一些组件的基础知识。我们之前通过`npm install`将`native-base`安装为项目的依赖项，但 NativeBase 包括一些对等依赖项，需要链接并包含在我们的 iOS 和 Android 本机文件夹中。幸运的是，React Native 已经有一个工具来查找这些依赖项并将它们链接起来；我们只需要运行：

```jsx
react-native link
```

在这一点上，我们的应用程序中已经完全可用来自 NativeBase 的所有 UI 组件。因此，我们可以开始构建我们的第一个屏幕。

# 构建 ShoppingList 屏幕

我们的第一个屏幕将包含我们需要购买的物品清单，因此它将包含每个我们需要购买的物品的一个列表项，包括一个按钮来标记该物品已购买。此外，我们需要一个按钮来导航到`AddProduct`屏幕，这将允许我们向我们的列表中添加产品。最后，我们将添加一个按钮来清除产品列表，以防我们想要开始一个新的购物清单：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/81cbfccf-1b8f-48e0-9035-b47acaf9030e.jpg)

让我们从在`screens`文件夹内创建`ShoppingList.js`开始，并从`native-base`和`react-native`导入我们将需要的所有 UI 组件（我们将使用警告弹出窗口在清除所有项目之前警告用户）。我们将使用的主要 UI 组件是`Fab`（蓝色和红色的圆形按钮），`List`，`ListItem`，`CheckBox`，`Text`和`Icon`。为了支持我们的布局，我们将使用`Body`，`Container`，`Content`和`Right`，这些是我们其余组件的布局容器。

拥有所有这些组件，我们可以创建一个简单版本的`ShoppingList`组件：

```jsx
/*** ShoppingList.js ***/

import React from 'react';
import { Alert } from 'react-native';
import {
  Body,
  Container,
  Content,
  Right,
  Text,
  CheckBox,
  List,
  ListItem,
  Fab,
  Icon
} from 'native-base';

export default class ShoppingList extends React.Component {
  static navigationOptions = {
    title: 'My Groceries List'
  };
  /*** Render ***/
  render() {
    return (
      <Container>
        <Content>
          <List>
            <ListItem>
              <Body>
                <Text>'Name of the product'</Text>
              </Body>
              <Right>
                <CheckBox
                  checked={false}
                />
              </Right>
            </ListItem>
          </List>
        </Content>
        <Fab
          style={{ backgroundColor: '#5067FF' }}
          position="bottomRight"
        >
          <Icon name="add" />
        </Fab>
        <Fab
          style={{ backgroundColor: 'red' }}
          position="bottomLeft"
        >
          <Icon ios="ios-remove" android="md-remove" />
        </Fab>
      </Container>
    );
  }
}

```

这只是一个愚蠢的组件，静态显示我们将在此屏幕上使用的组件。需要注意的一些事情：

+   `navigationOptions`是一个静态属性，将被`<Navigator>`用来配置导航的行为。在我们的情况下，我们希望将“我的杂货清单”显示为此屏幕的标题。

+   为了使`native-base`发挥其作用，我们需要使用`<Container>`和`<Content>`来正确地形成布局。

+   `Fab`按钮放置在`<Content>`之外，因此它们可以浮动在左下角和右下角。

+   每个`ListItem`包含一个`<Body>`（主要文本）和一个`<Right>`（右对齐的图标）。

由于我们在最初的步骤中启用了实时重新加载，所以在保存新创建的文件后，我们应该看到应用程序重新加载。现在所有的 UI 元素都已经就位，但它们还没有功能，因为我们还没有添加任何状态。这应该是我们下一步要做的事情。

# 在我们的屏幕上添加状态

让我们在`ShoppingList`屏幕上添加一些初始状态，以用实际动态数据填充列表。我们将首先创建一个构造函数，并在那里设置初始状态：

```jsx
/*** ShoppingList.js ***/

...
constructor(props) {
  super(props);
  this.state = {
    products: [{ id: 1, name: 'bread' }, { id: 2, name: 'eggs' }]
  };
}
...
```

现在，我们可以在`<List>`（在`render`方法内部）中呈现该状态：

```jsx
/*** ShoppingList.js ***/

...
<List>
 {
   this.state.products.map(p => {
     return (
       <ListItem
         key={p.id}
       >
         <Body>
           <Text style={{ color: p.gotten ? '#bbb' : '#000' }}>
             {p.name}
           </Text>
         </Body>
         <Right>
           <CheckBox
             checked={p.gotten}
            />
         </Right>
       </ListItem>
     );
   }
  )}
</List>
...
```

我们现在依赖于组件状态中的产品列表，每个产品存储一个`id`、一个`name`和`gotten`属性。在修改此状态时，我们将自动重新呈现列表。

现在，是时候添加一些事件处理程序，这样我们就可以根据用户的命令修改状态或导航到`AddProduct`屏幕。

# 添加事件处理程序

所有与用户的交互都将通过 React Native 中的事件处理程序进行。根据控制器的不同，我们将有不同的可以触发的事件。最常见的事件是`onPress`，因为每次我们按下按钮、复选框或一般视图时都会触发它。让我们为屏幕中可以被按下的所有组件添加一些`onPress`处理程序：

```jsx
/*** ShoppingList.js ***/

...
render() {
 return (
   <Container>
     <Content>
       <List>
        {this.state.products.map(p => {
          return (
            <ListItem
              key={p.id}
              onPress={this._handleProductPress.bind(this, p)}
            >
              <Body>
                <Text style={{ color: p.gotten ? '#bbb' : '#000' }}>
                  {p.name}
                </Text>
              </Body>
              <Right>
                <CheckBox
                  checked={p.gotten}
                  onPress={this._handleProductPress.bind(this, p)}
                />
              </Right>
            </ListItem>
          );
       })}
       </List>
     </Content>
     <Fab
       style={{ backgroundColor: '#5067FF' }}
       position="bottomRight"
       onPress={this._handleAddProductPress.bind(this)}
     >
       <Icon name="add" />
     </Fab>
     <Fab
       style={{ backgroundColor: 'red' }}
       position="bottomLeft"
       onPress={this._handleClearPress.bind(this)}
     >
       <Icon ios="ios-remove" android="md-remove" />
     </Fab>
   </Container>
   );
 }
...
```

请注意，我们添加了三个`onPress`事件处理程序：

+   在`<ListItem>`上，当用户点击列表中的一个产品时做出反应

+   在`<CheckBox>`上，当用户点击列表中每个产品旁边的复选框图标时做出反应

+   在两个`<Fab>`按钮上

如果你了解 React，你可能明白为什么我们在所有的处理程序函数中使用`.bind`，但是，如果你有疑问，`.bind`将确保我们可以在处理程序的定义中使用`this`作为对组件本身的引用，而不是全局范围。这将允许我们在组件内调用方法，如`this.setState`或读取我们组件的属性，比如`this.props`和`this.state`。

对于用户点击特定产品的情况，我们还绑定产品本身，这样我们可以在事件处理程序中使用它们。

现在，让我们定义将作为事件处理程序的函数：

```jsx
/*** ShoppingList.js ***/

...
_handleProductPress(product) {
 this.state.products.forEach(p => {
   if (product.id === p.id) {
     p.gotten = !p.gotten;
   }
   return p;
 });

 this.setState({ products: this.state.products });
}
...
```

首先，让我们为用户点击购物清单中的产品或其复选框时创建一个处理程序。我们希望将产品标记为“已购得”（或者如果已经“已购得”，则取消标记），因此我们将使用正确地标记产品来更新状态。

接下来，我们将为蓝色的`<Fab>`按钮添加一个处理程序，以导航到`AddProduct`屏幕：

```jsx
/*** ShoppingList.js ***/

...
_handleAddProductPress() {
  this.props.navigation.navigate('AddProduct', {
    addProduct: product => {
      this.setState({
        products: this.state.products.concat(product)
      });
    },
    deleteProduct: product => {
      this.setState({
        products: this.state.products.filter(p => p.id !== product.id)
      });
    },
    productsInList: this.state.products
  });
}
...
```

这个处理程序使用了`this.props.navigation`，这是一个由`react-navigation`中的`Navigator`组件自动传递的属性。这个属性包含一个名为`navigate`的方法，接收应用程序应该导航到的屏幕的名称，以及一个可以作为全局状态使用的对象。在这个应用程序的情况下，我们将存储三个键：

+   `addProduct`：一个函数，允许`AddProduct`屏幕修改`ShoppingList`组件的状态，以反映向购物清单添加新产品的操作。

+   `deleteProduct`：一个函数，允许`AddProduct`屏幕修改`ShoppingList`组件的状态，以反映从购物清单中删除产品的操作。

+   `productsInList`：一个变量，保存着已经在购物清单上的产品列表，这样`AddProducts`屏幕就可以知道哪些产品已经添加到购物清单中，并将它们显示为“已添加”，防止重复添加物品。

在导航中处理状态应该被视为简单应用程序的一种解决方法，其中包含有限数量的屏幕。在更大的应用程序中（正如我们将在后面的章节中看到的），应该使用状态管理库，比如 Redux 或 MobX，来保持纯数据和用户界面处理之间的分离。

接下来，我们将为蓝色的`<Fab>`按钮添加最后一个处理程序，这样用户就可以清空购物清单中的所有项目，以便开始一个新的清单：

```jsx
/*** ShoppingList.js ***/

...
_handleClearPress() {
  Alert.alert('Clear all items?', null, [
    { text: 'Cancel' },
    { text: 'Ok', onPress: () => this.setState({ products: [] }) }
  ]);
}
...
```

我们正在使用`Alert`来在清空购物清单中的所有元素之前提示用户确认。一旦用户确认了这个操作，我们将清空组件状态中的`products`属性。

# 把所有东西放在一起

让我们看看当把所有方法放在一起时，整个组件的结构会是什么样子：

```jsx
/*** ShoppingList.js ***/

import React from 'react';
import { Alert } from 'react-native';
import { ... } from 'native-base';

export default class ShoppingList extends React.Component {
 static navigationOptions = {
   title: 'My Groceries List'
 };

 constructor(props) {
   ...
 }

 /*** User Actions Handlers ***/
 _handleProductPress(product) {
   ...
 }

 _handleAddProductPress() {
   ...
 }

 _handleClearPress() {
   ...
 }

 /*** Render ***/
 render() {
   ...
 }
}
```

React Native 组件的结构非常类似于普通的 React 组件。我们需要导入 React 本身，然后一些组件来构建我们的屏幕。我们还有几个事件处理程序（我们已经用下划线作为纯粹的约定），最后是一个`render`方法来使用标准的 JSX 显示我们的组件。

与 React web 应用程序唯一的区别是，我们使用 React Native UI 组件而不是 DOM 组件。

# 构建 AddProduct 屏幕

由于用户需要向购物清单中添加新产品，我们需要构建一个屏幕，可以提示用户输入要添加的产品的名称，并将其保存在手机的存储中以供以后使用。

# 使用 AsyncStorage

在构建 React Native 应用程序时，了解移动设备如何处理每个应用程序使用的内存是很重要的。我们的应用程序将与设备中的其他应用程序共享内存，因此，最终，我们的应用程序使用的内存将被另一个应用程序占用。因此，我们不能依赖将数据放在内存中以供以后使用。如果我们想确保数据在我们的应用程序的用户之间可用，我们需要将数据存储在设备的持久存储中。

React Native 提供了一个 API 来处理与移动设备中的持久存储的通信，这个 API 在 iOS 和 Android 上是相同的，因此我们可以舒适地编写跨平台代码。

API 的名称是`AsyncStorage`，我们可以在从 React Native 导入后使用它：

```jsx
import { AsyncStorage } from 'react-native';
```

我们只会使用`AsyncStorage`的两个方法：`getItem`和`setItem`。例如，我们将在我们的屏幕内创建一个本地函数来处理将产品添加到产品列表中的操作。

```jsx
/*** AddProduct ***/

...
async addNewProduct(name) {
  const newProductsList = this.state.allProducts.concat({
    name: name,
    id: Math.floor(Math.random() * 100000)
  });

  await AsyncStorage.setItem(
    '@allProducts',
    JSON.stringify(newProductsList)
  );

  this.setState({
    allProducts: newProductsList
  });
 }
...
```

这里有一些有趣的事情需要注意：

+   我们正在使用 ES7 的特性，比如`async`和`await`来处理异步调用，而不是使用 promises 或回调函数。理解 ES7 不在本书的范围之内，但建议学习和了解`async`和`await`的使用，因为这是一个非常强大的特性，在本书中我们将广泛使用它。

+   每当我们向`allProducts`添加一个产品时，我们还会调用`AsyncStorage.setItem`来永久存储产品在设备的存储中。这个操作确保用户添加的产品即使在操作系统清除我们的应用程序使用的内存时也是可用的。

+   我们需要向`setItem`（以及`getItem`）传递两个参数：一个键和一个值。它们都必须是字符串，所以如果我们想存储 JSON 格式的数据，我们需要使用`JSON.stringify`。

# 向我们的屏幕添加状态

正如我们刚刚看到的，我们将在组件状态中使用一个名为`allProducts`的属性，其中将包含用户可以添加到购物清单中的完整产品列表。

我们可以在组件的构造函数中初始化这个状态，以便在应用程序的第一次运行期间给用户一个概述，让他/她看到这个屏幕上的内容（这是许多现代应用程序用来引导用户的技巧，通过伪造一个“已使用”状态）：

```jsx
/*** AddProduct.js ***/

...
constructor(props) {
  super(props);
  this.state = {
    allProducts: [
      { id: 1, name: 'bread' },
      { id: 2, name: 'eggs' },
      { id: 3, name: 'paper towels' },
      { id: 4, name: 'milk' }
    ],
    productsInList: []
  };
}
...
```

除了`allProducts`，我们还将有一个`productsInList`数组，其中包含已经添加到当前购物清单中的所有产品。这将允许我们将产品标记为“已经在购物清单中”，防止用户尝试在列表中两次添加相同的产品。

这个构造函数对我们应用程序的第一次运行非常有用，但一旦用户添加了产品（因此将它们保存在持久存储中），我们希望这些产品显示出来，而不是这些测试数据。为了实现这个功能，我们应该从`AsyncStorage`中读取保存的产品，并将其设置为我们状态中的初始`allProducts`值。我们将在`componentWillMount`上执行这个操作。

```jsx
/*** AddProduct.js ***/

...
async componentWillMount() {
  const savedProducts = await AsyncStorage.getItem('@allProducts');
  if(savedProducts) {
    this.setState({
      allProducts: JSON.parse(savedProducts)
    }); 
  }

  this.setState({
    productsInList: this.props.navigation.state.params.productsInList
  });
}
...
```

一旦屏幕准备好被挂载，我们就会更新状态。首先，我们将通过从持久存储中读取它来更新`allProducts`值。然后，我们将根据“购物清单”屏幕在“导航”属性中设置的状态更新产品列表`productsInList`。

有了这个状态，我们可以构建我们的产品列表，这些产品可以添加到购物清单中：

```jsx
/*** AddProduct ***/

...
render(){
  <List>
    {this.state.allProducts.map(product => {
       const productIsInList = this.state.productsInList.find(
         p => p.id === product.id
       );
       return (
         <ListItem key={product.id}>
           <Body>
             <Text
               style={{
                color: productIsInList ? '#bbb' : '#000'
               }}
             >
               {product.name}
             </Text>
             {
               productIsInList &&
               <Text note>
                 {'Already in shopping list'}
               </Text>
             }
          </Body>
        </ListItem>
      );
    }
 )}
 </List>
}
...
```

在我们的`render`方法中，我们将使用`Array.map`函数来迭代和打印每个可能的产品，检查产品是否已经添加到当前购物清单中以显示一个提示，警告用户：“已经在购物清单中”。

当然，我们仍然需要为所有可能的用户操作添加更好的布局、按钮和事件处理程序。让我们开始改进我们的`render`方法，将所有功能放在适当的位置。

# 添加事件监听器

就像“购物清单”屏幕一样，我们希望用户能够与我们的`AddProduct`组件进行交互，因此我们将添加一些事件处理程序来响应一些用户操作。

我们的`render`方法应该看起来像这样：

```jsx
/*** AddProduct.js ***/

...
render() {
  return (
    <Container>
      <Content>
        <List>
          {this.state.allProducts.map(product => {
            const productIsInList = this.state.productsInList.
            find(p => p.id === product.id);
            return (
              <ListItem
                key={product.id}
                onPress={this._handleProductPress.bind
                (this, product)}
              >
                <Body>
                  <Text
                    style={{ color: productIsInList? '#bbb' : '#000' }}
                  >
                    {product.name}
                  </Text>
                 {
                   productIsInList &&
                   <Text note>
                     {'Already in shopping list'}
                   </Text>
                 }
                 </Body>
                 <Right>
                   <Icon
                     ios="ios-remove-circle"
                     android="md-remove-circle"
                     style={{ color: 'red' }}
                     onPress={this._handleRemovePress.bind(this, 
                     product )}
                   />
                 </Right>
               </ListItem>
             );
           })}
         </List>
       </Content>
     <Fab
       style={{ backgroundColor: '#5067FF' }}
       position="bottomRight"
       onPress={this._handleAddProductPress.bind(this)}
     >
       <Icon name="add" />
     </Fab>
   </Container>
   );
 }
...
```

在这个组件中，有三个事件处理程序响应三个按压事件：

+   在蓝色的`<Fab>`按钮上，负责向产品列表中添加新产品

+   在每个`<ListItem>`上，这将把产品添加到购物清单中

+   在每个`<ListItem>`内的删除图标上，以将此产品从可以添加到购物清单中的产品列表中移除

让我们在用户按下`<Fab>`按钮时开始向可用产品列表中添加新产品：

```jsx
/*** AddProduct.js ***/

...
_handleAddProductPress() {
  prompt(
    'Enter product name',
    '',
    [
      { text: 'Cancel', style: 'cancel' },
      { text: 'OK', onPress: this.addNewProduct.bind(this) }
    ],
    {
      type: 'plain-text'
    }
  );
}
...
```

我们在这里使用了`react-native-prompt-android`模块的`prompt`函数。尽管它的名称是这样，但它是一个跨平台的弹出式提示库，我们将使用它通过我们之前创建的`addNewProduct`函数来添加产品。在使用之前，我们需要导入`prompt`函数，如下所示：

```jsx
import prompt from 'react-native-prompt-android';
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/80a2b8e1-ff09-4493-a4ef-41a52d6ecd3e.png)![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c1729134-4da3-4dcd-bf9a-f5ae93639a81.png)

一旦用户输入产品名称并按下确定，产品将被添加到列表中，这样我们就可以转到下一个事件处理程序，当用户点击产品名称时将产品添加到购物清单中：

```jsx
/*** AddProduct.js ***/

...
_handleProductPress(product) {
  const productIndex = this.state.productsInList.findIndex(
    p => p.id === product.id
  );
  if (productIndex > -1) {
    this.setState({
      productsInList: this.state.productsInList.filter(
        p => p.id !== product.id
      )
    });
    this.props.navigation.state.params.deleteProduct(product);
  } else {
    this.setState({
      productsInList: this.state.productsInList.concat(product)
    });
    this.props.navigation.state.params.addProduct(product);
 }
}
...
```

此处理程序检查所选产品是否已在购物清单上。如果是，它将通过调用导航状态中的`deleteProduct`和通过调用`setState`从组件状态中删除它。否则，它将通过调用导航状态中的`addProduct`将产品添加到购物清单，并通过调用`setState`刷新本地状态。

最后，我们将为每个`<ListItems>`上的删除图标添加事件处理程序，以便用户可以从可用产品列表中删除产品：

```jsx
/*** AddProduct.js ***/

...
async _handleRemovePress(product) {
  this.setState({
    allProducts: this.state.allProducts.filter(p => p.id !== product.id)
  });
  await AsyncStorage.setItem(
    '@allProducts',
    JSON.stringify(
      this.state.allProducts.filter(p => p.id !== product.id)
    )
  );
}
...
```

我们需要从组件的本地状态和`AsyncStorage`中删除产品，这样在应用程序的后续运行中就不会显示。

# 将所有内容整合在一起

我们已经拥有构建`AddProduct`屏幕的所有组件，所以让我们来看一下这个组件的一般结构：

```jsx
import React from 'react';
import prompt from 'react-native-prompt-android';
import { AsyncStorage } from 'react-native';
import {
 ...
} from 'native-base';

export default class AddProduct extends React.Component {
  static navigationOptions = {
    title: 'Add a product'
  };

  constructor(props) {
   ...
  }

  async componentWillMount() {
    ...
  }

  async addNewProduct(name) {
    ...
  }

  /*** User Actions Handlers ***/
  _handleProductPress(product) {
   ...
  }

  _handleAddProductPress() {
    ...
  }

  async _handleRemovePress(product) {
    ...
  }

  /*** Render ***/
  render() {
    ....
  }
}
```

我们的结构与我们为`ShoppingList`构建的结构非常相似：构建初始状态的`navigatorOptions`构造函数，用户操作处理程序和`render`方法。在这种情况下，我们添加了一对异步方法，作为处理`AsyncStorage`的便捷方式。

# 安装和分发应用程序

在模拟器/仿真器上运行我们的应用程序是感受应用程序在移动设备上行为的非常可靠的方法。当在模拟器/仿真器中工作时，我们可以模拟触摸手势、网络连接不佳的环境，甚至内存问题。但最终，我们希望将应用程序部署到物理设备上，这样我们就可以进行更深入的测试。

有几种选项可以安装或分发使用 React Native 构建的应用程序，直接连接电缆是最简单的方法。Facebook 在 React Native 的网站上保持了一份更新的指南，介绍了如何实现在设备上的直接安装（[`facebook.github.io/react-native/docs/running-on-device.html`](https://facebook.github.io/react-native/docs/running-on-device.html)），但是当分发应用程序给其他开发人员、测试人员或指定用户时，还有其他选择。

# Testflight

Testflight（[`developer.apple.com/testflight/`](https://developer.apple.com/testflight/)）是一个很棒的工具，用于将应用程序分发给测试人员和开发人员，但它有一个很大的缺点——它只适用于 iOS。它非常容易设置和使用，因为它集成在 iTunes Connect 中，苹果认为它是在开发团队内分发应用程序的官方工具。此外，它是完全免费的，使用限制相当大：

+   最多 25 名团队成员进行测试

+   每个测试人员团队最多 30 台设备

+   最多 2,000 名团队外的外部测试人员（具有分组功能）

简而言之，Testflight 是在只针对 iOS 设备时选择的平台。

由于在本书中，我们希望专注于跨平台开发，我们将介绍其他分发我们的应用程序到 iOS 和 Android 设备的替代方案。

# Diawi

Diawi（[`diawi.com`](http://diawi.com)）是一个网站，开发人员可以在上面上传他们的`.ipa`和`.apk`文件（已编译的应用程序），并与任何人分享链接，因此该应用程序可以在连接到互联网的任何 iOS 或 Android 设备上下载和安装。这个过程很简单：

1.  在 XCode/Android studio 中构建`.ipa`（iOS）/`.apk`（Android）。

1.  将生成的`.ipa`/`.apk`文件拖放到 Diawi 的网站上。

1.  通过电子邮件或其他方式与测试人员列表共享 Diawi 创建的链接。

链接是私有的，可以为那些需要更高安全性的应用程序设置密码保护。主要缺点是测试设备的管理，因为一旦链接分发，Diawi 就失去了对它们的控制，因此开发人员无法知道哪些版本被下载和测试。如果手动管理测试人员列表是一个选择，Diawi 是 Testflight 的一个很好的替代方案。

# Installr

如果我们需要管理分发给哪些测试人员的版本以及他们是否已经开始测试应用程序，我们应该尝试使用 Installr（[`www.installrapp.com`](https://www.installrapp.com)），因为在功能上它与 Diawi 相当类似，但它还包括一个仪表板，用于控制用户是谁，哪些应用程序已经单独发送给他们，以及测试设备上应用程序的状态（未安装、已安装或已打开）。这个仪表板非常强大，当我们的要求之一是对测试人员、设备和构建有良好的可见性时，它绝对是一个重要的优势。

Installr 的缺点是其免费计划仅覆盖每次构建的三个测试设备，尽管他们提供了一个廉价的一次性付费方案，以防我们真的想增加那个数字。当我们需要可见性和跨平台分发时，这是一个非常合理的选择。

# 总结

在本章的过程中，我们学会了如何启动 React Native 项目，构建一个包括基本导航和处理多个用户交互的应用程序。我们看到了如何使用导航模块处理持久数据和基本状态，以便我们可以在项目中的屏幕之间进行过渡。

所有这些模式都可以用来构建许多简单的应用程序，但在下一章中，我们将深入探讨更复杂的导航模式以及如何通信和处理从互联网获取的外部数据，这将使我们能够为应用程序的增长进行结构化和准备。除此之外，我们将使用 JavaScript 库 MobX 进行状态管理，这将以一种非常简单和有效的方式使我们的领域数据可用于应用程序中的所有屏幕。


# 第二章：RSS 阅读器

在本章中，我们将创建一个应用程序，能够获取、处理和显示用户多个 RSS 订阅。RSS 是一种 Web 订阅，允许用户以标准化和计算机可读的格式访问在线内容的更新。它们通常用于新闻网站、新闻聚合器、论坛和博客，以表示更新的内容，并且非常适合移动世界，因为我们可以通过在一个应用程序中输入订阅的 URL 来获取来自不同博客或报纸的所有内容。

一个 RSS 订阅阅读器将作为一个示例，演示如何获取外部数据，存储它，并向用户显示它，但同时，它将给我们的状态树增加一些复杂性；我们需要存储和管理订阅、条目和帖子的列表。除此之外，我们将引入 MobX 作为一个库来管理所有这些状态模型，并根据用户的操作更新我们的视图。因此，我们将介绍行为和存储的概念，这在一些最流行的状态管理库中被广泛使用，比如 Redux 或 MobX。

与上一章一样，因为我们将在这个应用程序中需要的 UI 模式在两个平台上非常相似，我们将致力于在 iOS 和 Android 上共享 100%的代码。

# 概述

为了更好地理解我们的 RSS 阅读器，让我们看看完成后应用程序将会是什么样子。

iOS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/9b2159fe-4103-49bb-8d26-884e73c431a3.png)

Android：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/dc295cc7-7640-46fc-a27a-68b8e27fb961.png)

主屏幕将显示用户已添加的订阅列表。导航标题还会显示一个(+)按钮，用于向列表中添加新的订阅。当按下该按钮时，应用程序将导航到添加订阅屏幕。

iOS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/ab44b43d-3ec3-4384-9ffe-7635078d3540.png)

Android：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/9ab48440-ae80-4472-a992-572019522f21.png)

一旦添加了新的订阅，它将显示在主屏幕上，用户只需点击即可打开它。

iOS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/2cff312d-358f-40a2-ac98-e25c7a4443de.png)

Android：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/2241542d-5f29-487d-9eb7-670f212020da.png)

在这个阶段，应用程序将检索所选订阅的更新条目列表，并在列表上显示它。在导航标题中，一个垃圾桶图标将允许用户从应用程序中删除该订阅。如果用户对任何条目感兴趣，她可以点击它以显示该条目的完整内容。

iOS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/80a7cfb4-2ce0-4e5f-a2b0-98354da60e05.png)

Android：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/6e7a138d-9aed-48ec-9bf9-c1cc862b49d7.png)

这个最后的屏幕基本上是一个 WebView，默认情况下在 URL 中打开的轻量级浏览器，其中包含所选条目的内容。用户将能够浏览子部分并完全与此屏幕中打开的网站进行交互，还可以通过在导航标题中点击返回箭头来返回到源的详细信息。

在本章中，我们将涵盖以下主题：

+   使用 MobX 进行状态管理

+   从 URL 获取外部数据

+   WebView

+   将基本链接模块与本地资源链接起来

+   添加图标

+   ActivityIndicator

# 设置文件夹结构

就像我们在第一章中所做的那样，我们需要通过 React Native 的 CLI 初始化一个新的 React Native 项目。这次，我们将把我们的项目命名为`RSSReader`：

```jsx
react-native init --version="0.49.3" RSSReader
```

对于这个应用程序，我们将需要总共四个屏幕：

+   `FeedList`：这是一个包含已添加到应用程序中的源标题的列表，按它们被添加的时间排序。

+   `AddFeed`：这是一个简单的表单，允许用户通过发送其 URL 来添加源。我们将在这里检索源的详细信息，最终将它们添加并保存在我们的应用程序中以供以后使用。

+   `FeedDetail`：这是一个包含所选源的最新条目（在挂载屏幕之前检索）的列表。

+   `EntryDetail`：这是一个 WebView，显示所选条目的内容。

除了屏幕之外，我们还将包括一个`actions.js`文件，其中包含修改应用程序状态的所有用户操作。虽然我们将在后面的部分中审查状态的管理，但重要的是要注意，除了这个`actions.js`文件之外，我们还需要一个`store.js`文件来包含状态结构和修改它的方法。

最后，正如在大多数 React Native 项目中一样，我们将需要一个`index.js`文件（已经由 React Native 的 CLI 创建）和一个`main.js`文件作为我们应用程序组件树的入口点。

所有这些文件将被组织在`src/`和`src/screens/`文件夹中，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/644ee843-3dc1-458f-9c92-d422f1c7f8e5.png)

# 添加依赖项

对于这个项目，我们将使用几个 npm 模块来节省开发时间，并将重点放在 RSS 阅读器本身的功能方面，而不是处理自定义状态管理框架、自定义 UI 或数据处理。对于这些问题，我们将使用以下`package.json`文件：

```jsx
{ 
  "name":"rssReader",
  "version":"0.0.1",
  "private":true,
  "scripts":{ 
  "start":"node node_modules/react-native/local-cli/cli.js start",
  "test":"jest"
  },
  "dependencies":{ 
  "mobx":"³.1.9",
  "mobx-react":"⁴.1.8",
  "native-base":"².1.3",
  "react":"16.0.0-beta.5",
    "react-native": "0.49.3",
  "react-native-vector-icons":"⁴.1.1",
  "react-navigation":"¹.0.0-beta.9",
  "simple-xml2json":"¹.2.3"
  },
  "devDependencies":{ 
  "babel-jest":"20.0.0",
  "babel-plugin-transform-decorators-legacy":"¹.3.4",
  "babel-preset-react-native":"1.9.1",
  "babel-preset-react-native-stage-0":"¹.0.1",
  "jest":"20.0.0",
  "react-test-renderer":"16.0.0-alpha.6"
  },
  "jest":{ 
  "preset":"react-native"
  }
}
```

正如在这个文件中所看到的，我们将与标准的 React Native 模块一起使用以下 npm 模块：

+   `mobx`：这是我们将使用的状态管理库

+   `mobx-react`：这是 MobX 的官方 React 绑定

+   `native-base`：与上一章一样，我们将使用 NativeBase 的 UI 库

+   `react-native-vector-icons`：NativeBase 需要这个模块来显示图形图标

+   `react-navigation`：我们将再次使用 React Native 的社区导航库

+   `simple-xml2json`：一个轻量级库，用于将 XML（RSS 订阅的标准格式）转换为 JSON，以便在我们的代码中轻松管理 RSS 数据

有了这个`package.json`文件，我们可以在项目的根文件夹中运行以下命令来完成安装：

```jsx
npm install
```

一旦 npm 完成安装所有依赖项，我们就可以在 iOS 模拟器中启动我们的应用程序：

```jsx
react-native run-ios
```

或者在 Android 模拟器中：

```jsx
react-native run-android
```

# 使用矢量图标

对于这个应用程序，我们将使用两个图标：一个加号用于添加订阅，一个垃圾桶用于删除它们。React Native 默认不包括要使用的图标列表，因此我们需要添加一个。在我们的情况下，由于我们正在使用`native-base`作为我们的 UI 库，使用`react-native-vector-icons`非常方便，因为它在`native-base`中受到原生支持，但需要一个额外的配置步骤：

```jsx
react-native link
```

一些库使用额外的原生功能，这些功能在 React Native 中不存在。在`react-native-vector-icons`的情况下，我们需要包含存储在库中的一些矢量图标，可以在原生中访问。对于这些类型的任务，React Native 包括`react-native link`，这是一个脚本，可以自动链接提供的库，准备所有原生代码和资源，这些资源在我们的应用程序中需要访问此库。许多库将需要这一额外步骤，但由于 React Native 的 CLI，这是一个非常简单的步骤，过去需要在项目之间移动文件并处理配置选项。

# 使用 MobX 管理我们的状态

MobX 是一个库，通过透明地应用函数式响应式编程，使状态管理变得简单和可扩展。MobX 背后的哲学非常简单：*任何可以从应用程序状态派生出来的东西，都应该自动派生。*这个哲学适用于 UI、数据序列化和服务器通信。

在其网站[`mobx.js.org/,`](https://mobx.js.org/)上可以找到大量关于使用 MobX 的文档和示例，尽管在本节中我们将对其进行简要介绍，以便在本章中充分理解我们应用的代码。

# 商店

MobX 使用“observable”属性的概念。我们应该声明一个包含我们一般应用状态的对象，它将保存和声明这些 observable 属性。当我们修改其中一个属性时，MobX 会自动更新所有订阅的观察者。这是 MobX 背后的基本原则，让我们看一个示例代码：

```jsx
/*** src/store.js ***/

import {observable} from 'mobx';

class Store {
 @observable feeds;

 ...

 constructor() {
   this.feeds = [];
 }

 addFeed(url, feed) {
   this.feeds.push({ 
     url, 
     entry: feed.entry,
     title: feed.title,
     updated: feed.updated
   });
   this._persistFeeds();
 }

 ...

}

const store = new Store()
export default store
```

我们有一个被标记为`@observable`的属性`feeds`，这意味着任何组件都可以订阅它，并在值发生变化时得到通知。这个属性在类构造函数中被初始化为空数组。

最后，我们还创建了`addFeed`方法，它将新的订阅推送到`feeds`属性中，因此将自动触发所有观察者的更新。为了更好地理解 MobX 观察者，让我们看一个观察订阅列表的示例组件：

```jsx
import React from 'react';
import { Container, Content, List, ListItem, Text } from 'native-base';
import { observer } from 'mobx-react/native';

@observer
export default class FeedsList extends React.Component {

 render() {
  const { feeds } = this.props.screenProps.store;
  return (
    <Container>
      <Content>
        <List>
          {feeds &&
            feeds.map((f, i) => (
              <ListItem key={i}>
                <Text>{f.title}</Text>
              </ListItem>
            ))}
        </List>
      </Content>
    </Container>
  );
 }
}

```

我们注意到的第一件事是需要使用`@observer`装饰器标记我们的组件，以确保当我们商店中的任何`@observable`属性发生变化时它会被更新。

默认情况下，React Native 的 Babel 配置不支持`@<decorator>`语法。为了使其工作，我们需要修改我们项目根目录中的`.babelrc`文件，并将`transform-decorator-legacy`添加为插件。

另一个需要注意的事情是需要将存储作为属性传递给组件。在这种情况下，由于我们使用`react-navigation`，我们将在`screenProps`中传递它，这是在`react-navigation`中在`<Navigator>`和其子屏幕之间共享属性的标准方式。

MobX 还有许多其他功能，但我们将把这些留给更复杂的应用程序，因为本章的一个目标是展示在构建小型应用程序时简单状态管理可以是多么简单。

# 设置商店

在了解了 MobX 的工作原理之后，我们准备创建我们的商店：

```jsx
/*** src/store.js ** */

import { observable } from 'mobx';
import { AsyncStorage } from 'react-native';

class Store {
  @observable feeds;
  @observable selectedFeed;
  @observable selectedEntry;

  constructor() {
    AsyncStorage.getItem('@feeds').then(sFeeds => {
      this.feeds = JSON.parse(sFeeds) || [];
    });
  }

  _persistFeeds() {
    AsyncStorage.setItem('@feeds', JSON.stringify(this.feeds));
  }

  addFeed(url, feed) {
    this.feeds.push({
      url,
      entry: feed.entry,
      title: feed.title,
      updated: feed.updated,
    });
    this._persistFeeds();
  }

  removeFeed(url) {
    this.feeds = this.feeds.filter(f => f.url !== url);
    this._persistFeeds();
  }

  selectFeed(feed) {
    this.selectedFeed = feed;
  }

  selectEntry(entry) {
    this.selectedEntry = entry;
  }
}

const store = new Store();
export default store;
```

我们已经在本章的 MobX 部分看到了该文件的基本结构。现在，我们将添加一些方法来修改订阅列表，并在用户在我们应用的订阅/条目列表中点击它们时选择特定的订阅/条目。

我们还利用`AsyncStorage`来在`addFeed`或`removeFeed`修改时持久化订阅列表。

# 定义动作

在我们的应用程序中将有两种类型的动作：影响特定组件状态的动作和影响一般应用程序状态的动作。我们希望将后者存储在组件代码之外的某个地方，这样我们可以重用并轻松维护它们。在 MobX（以及 Redux 或 Flux）应用程序中的一种常见做法是创建一个名为`actions.js`的文件，我们将在其中存储修改应用程序业务逻辑的所有动作。

在我们的 RSS 阅读器中，业务逻辑围绕订阅源和条目展开，因此我们将在此文件中捕获处理这些模型的所有逻辑。

```jsx
/*** actions.js ** */

import store from './store';
import xml2json from 'simple-xml2json';

export async function fetchFeed(url) {
  const response = await fetch(url);
  const xml = await response.text();
  const json = xml2json.parser(xml);
  return {
    entry:
      (json.feed && json.feed.entry) || (json.rss && 
      json.rss.channel.item),
    title:
      (json.feed && json.feed.title) || (json.rss && 
      json.rss.channel.title),
    updated: (json.feed && json.feed.updated) || null,
  };
}

export function selectFeed(feed) {
  store.selectFeed(feed);
}

export function selectEntry(entry) {
  store.selectEntry(entry);
}

export function addFeed(url, feed) {
  store.addFeed(url, feed);
}

export function removeFeed(url) {
  store.removeFeed(url);
}
```

由于操作修改了应用程序的一般状态，它们将需要访问存储。让我们分别看看每个动作：

+   `fetchFeed`：当用户想要将订阅源添加到 RSS 阅读器时，他将需要传递 URL，以便应用程序可以下载该订阅源的详细信息（订阅源标题、最新条目列表以及上次更新时间）。此动作负责从提供的 URL 检索此数据（格式化为 XML 文档），并将该数据转换为应用程序的标准格式的 JSON 对象。从提供的 URL 获取数据将由 React Native 中的内置库`fetch`执行，该库用于向任何 URL 发出 HTTP 请求。由于`fetch`支持 promises，我们将使用 async/await 来处理异步行为并简化我们的代码。一旦检索到包含订阅源数据的 XML 文档，我们将使用`simple-xml2json`将该数据转换为 JSON 对象，这是一种非常轻量级的库，用于这种需求。最后，该动作返回一个仅包含我们在应用程序中真正需要的数据（标题、条目和最后更新时间）的 JSON 对象。

+   `selectFeed`：一旦用户向阅读器添加了一个或多个订阅源，她应该能够选择其中一个以获取该订阅源的最新条目列表。此动作只是将特定订阅源的详细信息保存在存储中，以便任何对显示与该订阅源相关的数据感兴趣的屏幕（即`FeedDetail`屏幕）可以使用它。

+   `selectEntry`：类似于`selectFeed`，用户应该能够选择订阅源中的条目之一，以获取该特定条目的详细信息。在这种情况下，显示该数据的屏幕将是`EntryDetail`，我们将在后面的部分中看到。

+   `addFeed`：这个动作需要两个参数：订阅的 URL 和订阅的详细信息。这些参数将用于将订阅存储在保存的订阅列表中，以便在我们的应用中全局可用。在这个应用的情况下，我们决定使用 URL 作为存储订阅详细信息的键，因为它是任何 RSS 订阅的唯一属性。

+   `removeFeed`：用户还可以决定他们不再想在 RSS 阅读器中看到特定的订阅，因此我们需要一个动作来从订阅列表中移除该订阅。这个动作只需要传递订阅的 URL 作为参数，因为我们使用 URL 作为 ID 来唯一标识订阅。

# React Native 中的网络操作

大多数移动应用需要从外部 URL 获取和更新数据。在 React Native 中可以使用几个 npm 模块来通信和下载远程资源，比如 Axios 或 SuperAgent。如果你熟悉特定的 HTTP 库，你可以在 React Native 项目中使用它（只要不依赖于任何特定于浏览器的 API），尽管一个安全和熟练的选择是使用`Fetch`，这是 React Native 中内置的网络库。

`Fetch`非常类似于`XMLHttpRequest`，因此对于任何需要从浏览器执行 AJAX 请求的 web 开发人员来说都会感到熟悉。除此之外，`Fetch`支持 promises 和 ES2017 的 async/await 语法。

`Fetch` API 的完整文档可以在 Mozilla 开发者网络网站上找到[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)。

默认情况下，iOS 将阻止任何未使用 SSL 加密的请求。如果您需要从明文 URL（以`http`开头而不是`https`）获取数据，您首先需要添加一个**App Transport Security**（**ATS**）异常。如果您事先知道需要访问哪些域名，为这些域名添加异常更安全；如果域名直到运行时才知道，您可以完全禁用 ATS。然而，请注意，从 2017 年 1 月起，苹果的 App Store 审核将要求合理的理由来禁用 ATS。更多信息请参阅苹果的文档。

# 创建我们应用的入口点

所有的 React Native 应用都有一个入口文件：`index.js`，我们将把组件树的根委托给我们的`src/main.js`文件：

```jsx
/*** index.js ***/

import { AppRegistry } from 'react-native';
import App from './src/main';
AppRegistry.registerComponent('rssReader', () => App);
```

我们还将在操作系统中注册我们的应用。

现在，让我们看一下 `src/main.js` 文件，了解我们将如何设置导航并启动我们的组件树：

```jsx
/** * src/main.js ***/

import React from 'react';
import { StackNavigator } from 'react-navigation';

import FeedsList from './screens/FeedsList.js';
import FeedDetail from './screens/FeedDetail.js';
import EntryDetail from './screens/EntryDetail.js';
import AddFeed from './screens/AddFeed.js';

import store from './store';

const Navigator = StackNavigator({
  FeedsList: { screen: FeedsList },
  FeedDetail: { screen: FeedDetail },
  EntryDetail: { screen: EntryDetail },
  AddFeed: { screen: AddFeed },
});

export default class App extends React.Component {
  constructor() {
    super();
  }

  render() {
    return <Navigator screenProps={{ store }} />;
  }
}
```

我们将使用 `react-navigation` 作为我们的导航库，`StackNavigator` 作为我们的导航模式。将每个屏幕添加到 `StackNavigator` 函数中以生成我们的 `<Navigator>`。所有这些都与我们在第一章中使用的导航模式非常相似，但我们对其进行了改进：我们将 `store` 作为 `<Navigator>` 的 `screenProps` 属性传递，而不是直接传递属性和方法来修改我们应用程序的状态。这简化和清理了代码库，并且正如我们将在后面的部分中看到的那样，它将使我们摆脱每次状态更改时通知导航的负担。所有这些改进都是由于 MobX 而免费获得的。

# 构建 FeedsList 屏幕

feeds 列表将作为此应用的主屏幕使用，因此让我们专注于构建 feeds 标题列表：

```jsx
/** * src/screens/FeedsList.js ***/

import React from 'react';
import { Container, Content, List, ListItem, Text } from 'native-base';

export default class FeedsList extends React.Component {
  render() {
    const { feeds } = this.props.screenProps.store;
    return (
      <Container>
        <Content>
          <List>
            {feeds &&
              feeds.map((f, i) => (
              <ListItem key={i}>
              <Text>{f.title}</Text>
              </ListItem>
             ))
          </List>
        </Content>
      </Container>
    );
  }
}
```

该组件期望从 `this.props.screenProps.store` 接收 feeds 列表，然后遍历该列表构建一个 NativeBase `<List>`，显示存储中每个 feed 的标题。

让我们现在介绍一些 MobX 的魔法。由于我们希望当 feeds 列表发生变化时（添加或删除 feed 时）我们的组件能够重新渲染，因此我们必须使用 `@observer` 装饰器标记我们的组件。MobX 将自动在任何更新时强制组件重新渲染。现在让我们看看如何将装饰器添加到我们的组件中：

```jsx
...

@observer
export default class FeedsList extends React.Component {

...
```

就是这样。现在，我们的组件将在存储更改时收到通知，并将触发重新渲染。

# 添加事件处理程序

让我们添加一个事件处理程序，当用户点击 feed 标题时，将在新屏幕（`FeedDetail`）上显示该 feed 的条目列表：

```jsx
/** * src/screens/FeedsList.js ***/

...

@observer
export default class FeedsList extends React.Component {
  _handleFeedPress(feed) {
    selectFeed(feed);
    this.props.navigation.navigate('FeedDetail', { feedUrl: feed.url });
  }

  render() {
    const { feeds } = this.props.screenProps.store;
    return (
      <Container>
        <Content>
          <List>
            {feeds &&
              feeds.map((f, i) => (
              <ListItem key={i} onPress=
              {this._handleFeedPress.bind(this, f)}>
              <Text>{f.title}</Text>
              </ListItem>
             ))
            }
          </List>
        </Content>
      </Container>
    );
  }
}

...
```

为此，我们在组件中添加了一个名为 `_handleFeedPress` 的方法，该方法将接收 feed 的详细信息作为参数。当调用此方法时，它将运行 `selectFeed` 动作，并将传递 feed 的 URL 作为属性触发导航事件，以便下一个屏幕（`FeedDetail`）可以根据该 URL 包含一个删除 feed 的按钮。

最后，我们将添加 `navigationOptions`，包括导航标题和添加 feed 的按钮：

```jsx
/** * src/screens/FeedsList.js ***/

...

@observer
export default class FeedsList extends React.Component {
  static navigationOptions = props => ({
    title: 'My Feeds',
    headerRight: (
      <Button transparent onPress={() => 
      props.navigation.navigate('AddFeed')}>
        <Icon name="add" />
      </Button>
    ),
  });

...

}
```

按下`AddFeed`按钮将导航到`AddFeed`屏幕。通过将它作为名为`headerRight`的属性传递给`navigationOptions`，该按钮将显示在导航标题的右侧。

让我们看看这个组件是如何一起的：

```jsx
/*** src/screens/FeedsList.js ** */

import React from 'react';
import {
  Container,
  Content,
  List,
  ListItem,
  Text,
  Icon,
  Button,
} from 'native-base';
import { observer } from 'mobx-react/native';
import { selectFeed, removeFeed } from '../actions';

@observer
export default class FeedsList extends React.Component {
  static navigationOptions = props => ({
    title: 'My Feeds',
    headerRight: (
      <Button transparent onPress={() => 
       props.navigation.navigate('AddFeed')}>
        <Icon name="add" />
      </Button>
    ),
  });

  _handleFeedPress(feed) {
    selectFeed(feed);
    this.props.navigation.navigate('FeedDetail', { feedUrl: feed.url });
  }

  render() {
    const { feeds } = this.props.screenProps.store;
    return (
      <Container>
        <Content>
          <List>
            {feeds &&
              feeds.map((f, i) => (
              <ListItem key={i} onPress=
              {this._handleFeedPress.bind(this, f)}>
              <Text>{f.title}</Text>
              </ListItem>
             ))
          </List>
        </Content>
      </Container>
    );
  }
}
```

现在我们的 feeds 列表功能完全可用，让我们允许用户通过`AddFeed`屏幕添加一些 feeds。

# 构建 AddFeed 屏幕

该屏幕包括一个基本表单，包括一个用于从 feed 获取 URL 的`<Input>`和一个用于从提供的 URL 检索 feed 信息以后将 feed 的详细信息存储在我们的存储中的`<Button>`。

我们需要导入两个操作（`addFeed`和`fetchFeed`），这两个操作将在按下`Add`按钮时被调用：

```jsx
/*** src/screens/AddFeed.js ** */

import React from 'react';
import {
  Container,
  Content,
  Form,
  Item,
  Input,
  Button,
  Text,
} from 'native-base';
import { addFeed, fetchFeed } from '../actions';
import { Alert, ActivityIndicator } from 'react-native';

export default class AddFeed extends React.Component {
  static navigationOptions = {
    title: 'Add feed',
  };

  constructor(props) {
    super(props);
    this.state = {
      url: '',
      loading: false,
    };
  }

  _handleAddPress() {
    if (this.state.url.length > 0) {
      this.setState({ loading: true });
      fetchFeed(this.state.url)
        .then(feed => {
          addFeed(this.state.url, feed);
          this.setState({ loading: false });
          this.props.navigation.goBack();
        })
        .catch(() => {
          Alert.alert("Couldn't find any rss feed on that url");
          this.setState({ loading: false });
        });
    }
  }

  render() {
    return (
      <Container style={{ padding: 10 }}>
        <Content>
          <Form>
            <Item>
              <Input
                autoCapitalize="none"
                autoCorrect={false}
                placeholder="feed's url"
                onChangeText={url => this.setState({ url })}
              />
            </Item>
            <Button
              block
              style={{ marginTop: 20 }}
              onPress={this._handleAddPress.bind(this)}
            >
              {this.state.loading && (
                <ActivityIndicator color="white" style={{ margin: 10 }}  
                />
              )}
              <Text>Add</Text>
            </Button>
          </Form>
        </Content>
      </Container>
    );
  }
}
```

这个组件中大部分功能都在`_handleAddPress`中，因为它是处理程序，一旦按下`Add`按钮就会被触发。这个处理程序负责四个任务：

+   检查是否存在 URL 以检索数据

+   从提供的 URL 检索 feed 数据（通过`fetchFeed`操作）

+   将数据保存到应用程序状态中（通过`addFeed`操作）

+   在获取或保存数据时，向用户发出警告。

需要注意的一件重要的事情是`fetchFeed`操作的使用方式。由于它是用`async`语法声明的，我们可以将它用作一个 promise，并将它附加到其监听器的结果上，用于`then`和`catch`。

# ActivityIndicator

在每次应用程序需要等待 HTTP 请求的响应时显示一个旋转器是一个很好的做法。iOS 和 Android 都有标准的活动指示器来显示这种行为，两者都可以通过 React Native 模块中的`<ActivityIndicator>`组件获得。

显示这个指示器的最简单方法是在组件状态中保持一个`loading`标志。由于这个标志只被我们的组件用来显示这个`<ActivityIndicator>`，所以把它放在组件的状态中而不是移动到通用的应用程序状态中是有意义的。然后，它可以在`render`函数中使用：

```jsx
{ this.state.loading && <ActivityIndicator color='white' style={{margin: 10}}/>}
```

这种语法在 React 应用程序中非常常见，用于根据标志或简单条件显示或隐藏组件。它利用了 JavaScript 评估`&&`操作的方式：检查第一个操作数的真实性，如果为真，则返回第二个操作数；否则，返回第一个操作数。这种语法在一种非常常见的指令上节省了代码行数，因此它将在本书中广泛使用。

# 构建`FeedDetail`屏幕

让我们回顾一下当用户在`FeedsList`屏幕上点击一个 feed 时发生了什么：

```jsx
_handleFeedPress(feed) {
  selectFeed(feed);
  this.props.navigation.navigate('FeedDetail', { feedUrl: feed.url });
}
```

在`navigation`属性上调用了`navigate`方法，以打开`FeedDetail`屏幕。作为参数，`_handleFeedPress`函数传递了`feedUrl`，这样它就可以检索 feed 数据并显示给用户。这是一个必要的步骤，因为我们在存储中为所选的 feed 拥有的数据可能已经过时。因此，在向用户显示之前，最好重新获取数据，以确保它是 100%更新的。我们也可以进行更复杂的检查，而不是每次用户选择 feed 时都检索整个 feed，但为了保持这个应用程序的简单性，我们将坚持采用给定的方法。

让我们从`componentWillMount`方法中检索更新后的条目列表开始：

```jsx
/*** src/screens/FeedDetail.js ***/

import React from 'react';
import { observer } from 'mobx-react/native';
import { fetchFeed} from '../actions';

@observer
export default class FeedDetail extends React.Component {
 ... 

 constructor (props) {
  super(props);
  this.state = {
    loading: false,
    entry: null
  }
 }

 componentWillMount() {
  this.setState({ loading: true });
  fetchFeed(this.props.screenProps.store.selectedFeed.url)
   .then((feed) => {
    this.setState({ loading: false });
    this.setState({ entry: feed.entry});
  });
 }

 ...

}
```

我们将把我们的组件标记为`@observer`，这样它就会在所选的 feed 改变时得到更新。然后，我们需要一个具有两个属性的状态：

+   `loading`：这是一个标志，用来向用户表示我们正在获取更新的数据

+   `entry`：这是要显示给用户的条目列表

然后，在组件挂载之前，我们想要开始检索更新后的条目。为此，我们可以重用在`AddFeed`屏幕中使用的`fetchFeed`操作。当接收到 feed 数据时，组件状态中的`loading`标志被设置为`false`，这将隐藏`<ActivityIndicator>`，并且条目列表将被设置在组件状态中。现在我们有了一个条目列表，让我们看看我们将如何向用户显示它：

```jsx
/** * src/screens/FeedDetail.js ** */

import React from 'react';
import {
  Container,
  Content,
  List,
  ListItem,
  Text,
  Button,
  Icon,
  Spinner,
} from 'native-base';
import { observer } from 'mobx-react/native';
import { fetchFeed } from '../actions';
import { ActivityIndicator } from 'react-native';

@observer
export default class FeedDetail extends React.Component {

  ...

  render() {
    const { entry } = this.state;

    return (
      <Container>
        <Content>
          {this.state.loading && <ActivityIndicator style=
          {{ margin: 20 }} />}
          <List>
            {entry &&
              entry.map((e, i) => (
                <ListItem key={i}>
                  <Text>{e.title}</Text>
                </ListItem>
              ))}
          </List>
        </Content>
      </Container>
    );
  }
}
```

`&&` 语法再次被用来显示`<ActivityIndicator>`，直到数据被检索出来。一旦数据可用并且正确存储在组件状态的`entry`属性中，我们将渲染包含所选字段条目标题的列表项。

现在，我们将添加一个事件处理程序，当用户点击条目标题时将被触发：

```jsx
/** * src/screens/FeedDetail.js ** */

import React from 'react';
import {
  Container,
  Content,
  List,
  ListItem,
  Text,
  Button,
  Icon,
  Spinner,
} from 'native-base';
import { observer } from 'mobx-react/native';
import { selectEntry, fetchFeed } from '../actions';
import { ActivityIndicator } from 'react-native';

@observer
export default class FeedDetail extends React.Component {

  ...

  _handleEntryPress(entry) {
    selectEntry(entry);
    this.props.navigation.navigate('EntryDetail');
  }

  render() {
    const { entry } = this.state;

    return (
      <Container>
        <Content>
          {this.state.loading && <ActivityIndicator style=
          {{ margin: 20 }} />}
          <List>
            {entry &&
              entry.map((e, i) => (
                <ListItem
                  key={i}
                  onPress={this._handleEntryPress.bind(this, e)}
                >
                  <Text>{e.title}</Text>
                </ListItem>
              ))}
          </List>
        </Content>
      </Container>
    );
  }
}
```

这个处理程序被命名为`_handleEntryPress`，负责两个任务：

+   将点击的条目标记为已选

+   导航到`EntryDetail`

最后，让我们通过`navigationOptions`方法添加导航标题：

```jsx
/** * src/screens/FeedDetail.js ** */

...

@observer
export default class FeedDetail extends React.Component {
  static navigationOptions = props => ({
    title: props.screenProps.store.selectedFeed.title,
    headerRight: (
      <Button
        transparent
        onPress={() => {
          removeFeed(props.navigation.state.params.feedUrl);
          props.navigation.goBack();
        }}
      >
        <Icon name="trash" />
      </Button>
    ),
  });

  ...

}
```

除了为这个屏幕添加标题（feed 的标题）之外，我们还希望为用户的导航栏添加一个图标，以便用户能够从应用程序中存储的 feed 列表中删除该 feed。我们将使用`native-base`的`trash`图标来实现这个目的。当按下时，将调用`removeFeed`动作，传递当前 feed URL，以便可以从存储中删除，然后将强制导航返回到`FeedList`屏幕。

让我们来看看完成的组件：

```jsx
/*** src/screens/FeedDetail.js ** */

import React from 'react';
import {
  Container,
  Content,
  List,
  ListItem,
  Text,
  Button,
  Icon,
  Spinner,
} from 'native-base';
import { observer } from 'mobx-react/native';
import { selectEntry, fetchFeed, removeFeed } from '../actions';
import { ActivityIndicator } from 'react-native';

@observer
export default class FeedDetail extends React.Component {
  static navigationOptions = props => ({
    title: props.screenProps.store.selectedFeed.title,
    headerRight: (
      <Button
        transparent
        onPress={() => {
          removeFeed(props.navigation.state.params.feedUrl);
          props.navigation.goBack();
        }}
      >
        <Icon name="trash" />
      </Button>
    ),
  });

  constructor(props) {
    super(props);
    this.state = {
      loading: false,
      entry: null,
    };
  }

  componentWillMount() {
    this.setState({ loading: true });
    fetchFeed(this.props.screenProps.store.selectedFeed.url).
    then(feed => {
      this.setState({ loading: false });
      this.setState({ entry: feed.entry });
    });
  }

  _handleEntryPress(entry) {
    selectEntry(entry);
    this.props.navigation.navigate('EntryDetail');
  }

  render() {
    const { entry } = this.state;

    return (
      <Container>
        <Content>
          {this.state.loading && <ActivityIndicator style=
          {{ margin: 20 }} />}
          <List>
            {entry &&
              entry.map((e, i) => (
              <ListItem key={i} onPress=
              {this._handleEntryPress.bind(this, e)}>
              <Text>{e.title}</Text>
          </ListItem>
          ))
          </List>
        </Content>
      </Container>
    );
  }
}
```

现在，让我们继续到最后一个屏幕：`EntryDetail`。

# 构建 EntryDetail 屏幕

`EntryDetail`屏幕只是一个 WebView：一个能够在原生视图中呈现 web 内容的组件。您可以将 WebView 视为一个轻量级的 web 浏览器，显示提供的 URL 的网站内容：

```jsx
import React from 'react';
import { Container, Content } from 'native-base';
import { WebView } from 'react-native';

export default class EntryDetail extends React.Component {
  render() {
    const entry = this.props.screenProps.store.selectedEntry;
    return <WebView source={{ uri: entry.link.href || entry.link }} />;
  }
}
```

这个组件中的`render`方法只是返回一个新的`WebView`组件，加载存储中所选条目的 URL。就像我们在前面的部分中对 feed 的数据所做的那样，我们需要从`this.props.screenProps.store`中检索`selectedEntry`数据。URL 可以以两种不同的方式存储，这取决于 feed 的 RSS 版本：在链接属性中或者在`link.href`中再深一层。

# 总结

当应用程序的复杂性开始增长时，每个应用程序都需要一个状态管理库。作为一个经验法则，当应用程序由四个以上的屏幕组成并且它们之间共享信息时，添加状态管理库是一个好主意。对于这个应用程序，我们使用了 MobX，它简单但足够强大，可以处理所有的订阅和条目数据。在本章中，您学习了 MobX 的基础知识以及如何与`react-navigation`一起使用它。重要的是要理解动作和存储的概念，因为我们将在未来的应用程序中使用它们，不仅建立在 MobX 周围，还建立在 Redux 周围。

您还学会了如何从远程 URL 获取数据。这是大多数移动应用程序中非常常见的操作，尽管我们只涵盖了它的基本用法。在接下来的章节中，我们将深入研究`Fetch` API。此外，我们还看到了如何处理和格式化获取的数据，以便在我们的应用程序中加以规范化。

最后，我们回顾了什么是 WebView 以及如何将 web 内容插入到我们的原生应用程序中。这可以通过本地 HTML 字符串或通过 URL 远程完成，因此这是移动开发人员用来重用或访问仅限于 web 的内容的一个非常强大的技巧。


# 第三章：汽车预订应用

在之前的章节中，我们将重点放在功能开发上，而不是在构建用户界面上，将我们应用的样式委托给 UI 库，如`native-base`。在本章中，我们将做相反的事情，花更多的时间来构建自定义 UI 组件和屏幕。

我们要构建的应用是一个汽车预订应用，用户可以选择想要被接送的位置以及想要预订的车辆类型。由于我们想要专注于用户界面，我们的应用只会有两个屏幕，并且需要一些状态管理。相反，我们将更深入地研究诸如动画、组件布局、使用自定义字体或显示外部图像等方面。

该应用将适用于 iOS 和 Android 设备，由于所有用户界面都将是定制的，因此代码的 100%将在两个平台之间重复使用。我们只会使用两个外部库：

+   - `React-native-geocoder`：这将把坐标转换为人类可读的位置

+   - `React-native-maps`：这将轻松显示地图和显示可预订汽车位置的标记

由于其性质，大多数汽车预订应用将其复杂性放在后端代码中，以有效地连接司机和乘客。我们将跳过这种复杂性，并在应用程序本身中模拟所有这些功能，以便专注于构建美观和可用的界面。

# 概述

在构建移动应用程序时，我们需要确保将界面复杂性降至最低，因为一旦应用程序打开，向用户呈现侵入式手册或工具提示通常是有害的。让我们的应用自解释是一个好习惯，这样用户就可以通过浏览应用屏幕来理解使用方法。这就是为什么使用标准组件，如抽屉菜单或标准列表，总是一个好主意，但并非总是可能的（就像我们当前的应用中发生的情况），因为我们想要向用户呈现的数据类型。

在我们的情况下，我们将所有功能放在主屏幕和一个模态框中。让我们来看看这款应用在 iOS 设备上的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/3b60528e-707c-4170-bc36-c41da3500304.png)

我们主屏幕的背景是地图组件本身，我们将在地图中显示所有可用的汽车作为标记。在地图上，我们将显示三个组件：

+   - 选择位置框，显示所选的接送位置

+   - 位置图钉，可以在地图上拖动以选择新位置

+   用户想要预订的汽车类型的选择器。我们将显示三个选项：经济型，特别型和高级型

由于大多数组件都是自定义构建的，因此此屏幕在任何 Android 设备上看起来都非常相似：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/8880df9a-f99d-44ff-99c7-febbba8e5f7e.png)

iOS 和 Android 版本之间的主要区别将是地图组件。虽然 iOS 将默认使用 Apple 地图，但 Android 使用 Google 地图。我们将保留此设置，因为每个平台都有其自己优化的地图组件，但值得知道的是，我们可以通过配置我们的组件将 iOS 版本切换到使用 Google 地图。

一旦用户选择了取货地点，我们将显示一个模态框来确认预订并联系最近的司机接送。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/83e52b8a-aa1a-4ffb-8038-1674d218a04e.png)

与主屏幕一样，此屏幕使用自定义组件：我们甚至决定创建自己的动画活动指示器。因此，Android 版本将看起来非常相似：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/e0509761-3ae7-411e-b42d-3950dd862706.png)

由于我们的应用程序不会连接到任何外部 API，它应该被视为 React Native 的视觉能力的纯粹展示，尽管可以通过添加状态管理库和匹配的 API 轻松扩展。

在本章中，我们将涵盖以下主题：

+   在我们的应用程序中使用地图

+   React Native 中的样式表

+   React Native 中的 Flexbox

+   在 React Native 应用程序中使用外部图像

+   添加自定义字体

+   React Native 中的动画

+   使用模态框

+   处理阴影和不透明度

# 设置文件夹结构

让我们使用 React Native 的 CLI 初始化一个 React Native 项目。 该项目将被命名为`carBooking`，并将适用于 iOS 和 Android 设备：

```jsx
react-native init --version="0.49.3" carBooking
```

在此应用程序中，只有一个屏幕，因此代码的文件夹结构应该非常简单。由于我们将使用外部图像和字体，我们将这些资源组织在两个单独的文件夹中：`img`和`fonts`，都在根文件夹下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/0053ce62-8087-4ee6-a811-f71a3793b29a.jpg)

用于构建此应用程序的图像和字体可以从一些图像和字体库网站免费下载。我们将使用的字体名称是*Blair ITC*。

我们还将以下图像存储在`img`文件夹中：

+   `car.png`：一辆汽车的简单图画，用于表示地图上可预订的汽车。

+   `class.png`：一辆汽车的轮廓，显示在类别选择按钮内部。

+   `classBar.png`：用于滑动更改班级选择按钮的栏。

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
        "react-native-geocoder": "⁰.4.8",
 "react-native-maps": "⁰.15.2"
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

+   `react-native-geocoder`：这将坐标转换为可读的位置

+   `react-native-maps`：这可以轻松显示地图和显示可预订汽车位置的标记

为了允许应用程序使用自定义字体，我们需要确保它们可以从本机端访问。为此，我们需要在`package.json`中添加一个名为`rnpm`的新键。这个键将存储一个`assets`数组，在其中我们将定义我们的`fonts`文件夹。在构建时，React Native 将把字体复制到一个位置，从那里它们将在本机端可用，因此可以在我们的代码中使用。这仅对字体和一些特殊资源是必需的，但不适用于图像。

# 由 React Native 的 CLI 创建的文件和文件夹

让我们利用这个应用程序中的简单文件夹结构来展示通过`react-native init <projectName>`初始化项目时 React Native 的 CLI 创建的其他文件和文件夹。

# __ 测试 __/

React Native 的 CLI 包括 Jest 作为开发人员依赖项，并且为了开始测试，它包括一个名为`__tests__`的文件夹，其中可以存储所有测试。默认情况下，React Native 的 CLI 添加一个测试文件：`index.js`，代表初始一组测试。开发人员可以为应用程序中的任何组件添加后续测试。React Native 还在我们的`package.json`中添加了一个`test`脚本，因此我们可以从一开始就运行`npm run test`。

Jest 已准备好与通过 CLI 初始化的每个项目一起使用，当涉及到测试 React 组件时，它绝对是最简单的选择，尽管也可以使用其他库，如 Jasmine 或 Mocha。

# android/和 ios/

这两个文件夹分别保存了两个平台的原生构建应用程序。这意味着我们可以在这里找到我们的`.xcodeproj`和`.java`文件。每当我们需要对应用程序的本机代码进行更改时，我们都需要修改这两个目录中的一些文件。

在这些文件夹中查找和修改文件的最常见原因是：

+   通过更改`Info.plist`（iOS）或`AndroidManifest.xml`（Android）来修改权限（推送通知，访问位置服务，访问指南针等）

+   更改任何平台的构建设置

+   为原生库添加 API 密钥

+   添加或修改原生库，以便从我们的 React Native 代码中使用

# node_modules/

这个文件夹对大多数使用 npm 的 JavaScript 开发人员来说应该很熟悉，因为 npm 将所有标记为项目依赖项的模块存储在这里。在这个文件夹内修改任何内容的必要性并不常见，因为一切都应该通过 npm 的 CLI 和我们的`package.json`文件来处理。

# 根文件夹中的文件

React Native 的 CLI 在项目的根目录中创建了许多文件；让我们来看看最重要的文件：

+   `.babelrc`：Babel 是 React Native 中用于编译包含 JSX 和 ES6（例如，语法的 JavaScript 文件的默认库，可以转换为大多数 JavaScript 引擎能够理解的普通 JavaScript）。在这里，我们可以修改这个编译器的配置，例如，我们可以使用`@`语法作为装饰器，就像在 React 的最初版本中所做的那样。

+   `.buckconfig`：Buck 是 Facebook 使用的构建系统。这个文件用于配置使用 Buck 时的构建过程。

+   `.watchmanconfig`：Watchman 是一个监视项目中文件的服务，以便在文件发生变化时触发重新构建。在这个文件中，我们可以添加一些配置选项，比如应该被忽略的目录。

+   `app.json`：这个文件被`react-native eject`命令用来配置原生应用程序。它存储了在每个平台上标识应用程序的名称，以及在设备的主屏幕上安装应用程序时将显示的名称。

+   `yarn.lock`：`package.json`文件描述了原始作者期望的版本，而`yarn.lock`描述了给定应用程序的最后已知的良好配置。

# react-native link

一些应用程序依赖具有原生能力的库，在 React Native CLI 之前，开发人员需要将原生库文件复制到原生项目中。这是一个繁琐和重复的工作，直到`react-native link`出现才得以解救。在本章中，我们将使用它来从`react-native-maps`复制库文件，并将自定义字体从我们的`/fonts`文件夹链接到编译后的应用程序。

通过在项目的根文件夹中运行`react-native link`，我们将触发链接步骤，这将使那些原生能力和资源可以从我们的 React Native 代码中访问。

# 在模拟器中运行应用程序

在`package.json`文件中具有依赖项并且所有初始文件就位后，我们可以运行以下命令（在项目的根文件夹中）来完成安装：

```jsx
npm install
```

然后，所有依赖项都应该安装在我们的项目中。一旦 npm 完成安装所有依赖项，我们就可以在 iOS 模拟器中启动我们的应用程序：

```jsx
react-native run-ios
```

或者在 Android 模拟器中使用以下命令：

```jsx
react-native run-android
```

当 React Native 检测到应用程序在模拟器中运行时，它会通过一个隐藏菜单启用开发人员工具集，可以通过快捷键*command* + *D*（在 iOS 上）或*command* + *M*（在 Android 上，Windows 上应使用*Crtl*而不是*command*）访问。这是 iOS 中开发人员菜单的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/ca86bd23-ab53-45fb-9b9b-88a40471d7a0.png)

这是在 Android 模拟器中的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/91050c83-c0e0-4ae1-bf22-dfbaf6c3e5b7.png)

# 开发人员菜单

在构建 React Native 应用程序的过程中，开发人员将需要调试。React Native 通过能够在 Chrome 开发者工具或外部应用程序（如 React Native Debugger）中远程调试我们的应用程序来满足这些需求。错误、日志甚至 React 组件都可以像在普通的 Web 环境中一样轻松地进行调试。

此外，React Native 提供了一种自动重新加载应用程序的方式，每次进行更改时都会重新加载应用程序，从而节省了开发人员手动重新加载应用程序的任务（可以通过按*command* + *R*或*Ctrl* + *R*来实现）。当我们为自动重新加载设置应用程序时，有两个选项：

+   实时重新加载检测到我们在应用程序代码中进行的任何更改，并在重新加载后将应用程序重置为其初始状态。

+   热重载还可以检测更改并重新加载应用程序，但保持应用程序的当前状态。当我们正在实现用户流程以节省开发人员重复每个步骤时（例如，登录或注册测试用户）时，这非常有用。

最后，我们可以启动性能监视器来检测执行复杂操作（如动画或数学计算）时可能出现的性能问题。

# 创建我们应用程序的入口点

让我们通过创建我们应用程序的入口点`index.js`来开始我们的应用程序代码。我们在这个文件中导入`src/main.js`，以便为我们的代码库使用一个公共根组件。此外，我们将使用名称`carBooking`注册应用程序：

```jsx
/*** index.js ***/

import { AppRegistry } from 'react-native';
import App from './src/main';
AppRegistry.registerComponent('carBooking', () => App);
```

让我们通过添加地图组件来开始构建我们的`src/main.js`：

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

我们将使用`StyleSheet`来创建自己的样式，而不是使用样式库，`StyleSheet`是一个类似于 CSS 样式表的抽象的 React Native API。使用`StyleSheet`，我们可以从对象中创建样式表（通过`create`方法），然后通过引用每个样式的 ID 在我们的组件中使用它们。

这样，我们可以重用样式代码，并使代码更易读，因为我们将使用有意义的名称来引用每个样式（例如，`<Text style={styles.title}>Title 1</Text>`）。

在这一点上，我们只会创建一个由键`fullScreenMap`引用的样式，并通过将`top`、`bottom`、`left`和`right`坐标添加到零来将其设置为绝对位置，覆盖全屏大小。除此之外，我们需要为我们的容器视图添加一些样式，以确保它填满整个屏幕：`{flex: 1}`。将`flex`设置为`1`，我们希望我们的视图填满其父级占用的所有空间。由于这是主视图，`{flex: 1}`将占据整个屏幕。

对于我们的地图组件，我们将使用`react-native-maps`，这是由 Airbnb 创建的一个开放模块，利用了 Google 和 Apple 地图的本地地图功能。`react-native-maps`是一个非常灵活的模块，得到了很好的维护，并且功能齐全，因此它已经成为 React Native 的*事实标准*地图模块。正如我们将在本章后面看到的，`react-native-maps`要求开发人员运行`react-native link`才能正常工作。

除了样式，`<MapView/>`组件将以`initialRegion`作为属性，将地图居中在特定的坐标上，这应该是用户当前位置。出于一致性原因，我们将把地图的中心定位在旧金山，在那里我们还将放置一些可预订的汽车：

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

我们已经添加了一个`carLocations`数组，以便在地图上显示为标记。在我们的`render`函数中，我们将遍历这个数组，并在提供的坐标中放置相应的`<MapView.Marker/>`。在每个标记内，我们将添加汽车的图像，并将其旋转特定角度，以使其与街道方向匹配。旋转图像必须使用`Animated`API 完成，这将在本章后面更好地解释。

让我们在我们的状态中添加一个新属性，用于存储地图所居中的位置的可读位置：

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

为了填充这个状态变量，我们还创建了一个名为`_onRegionChange`的函数，它使用`react-native-geocoder`模块。该模块使用 Google Maps 的逆地理编码服务将一些坐标转换为可读的位置。因为这是一个 Google 服务，我们可能需要添加一个 API 密钥来验证我们的应用程序与该服务的身份。可以在其存储库 URL 中找到完全安装此模块的所有说明[`github.com/airbnb/react-native-maps/blob/master/docs/installation.md`](https://github.com/airbnb/react-native-maps/blob/master/docs/installation.md)。

我们希望这个状态变量从主组件的第一个挂载就可用，所以我们将在`componentDidMount`中调用`_onRegionChange`，以便初始位置的名称也存储在状态中。此外，我们将在我们的`<MapView/>`上添加`onRegionChange`属性，以确保位置的名称在地图移动到显示不同区域时重新计算，这样我们总是可以在我们的`position`状态变量中拥有地图中心的位置名称。

作为屏幕的最后一步，我们将添加所有子视图和另一个函数来确认预订请求：

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

+   `LocationSearch`：在这个组件中，我们将向用户显示地图中心的位置，以便她可以知道她确切请求接送的位置的名称。

+   `LocationPin`：一个指向地图中心的图钉，这样用户可以在地图上看到她将要请求接送的位置。它还将显示一个确认接送的按钮。

+   `ClassSelection`：用户可以在其中选择接送车辆类型（经济、特殊或高级）的条形图。

+   `ConfirmationModal`：显示请求确认的模态框。

`_onBookingRequest`方法将负责在请求预订时弹出确认模态框。

# 向我们的应用程序添加图像

React Native 处理图像的方式与网站类似：图像应放在项目文件夹结构内的一个文件夹中，然后可以通过`<Image/>`（或`<Animated.Image/>`）的`source`属性引用它们。让我们看一个来自我们应用程序的例子：

+   `car.png`：这个文件放在我们项目根目录的`img/`文件夹中

+   然后，通过使用`source`属性创建一个`<Image/>`组件来显示图像：

```jsx
       <Image source={require('../img/car.png')} />
```

请注意`source`属性不接受字符串，而是`require('../img/car.png')`。这在 React Native 中是一个特殊情况，可能会在将来的版本中更改。

# LocationSearch

这应该是一个简单的文本框，显示地图中心的可读名称。让我们看一下代码：

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

它只接收一个属性：`value`（要显示的位置名称）。如果未设置，它将显示一个旋转器以显示活动。

由于在此组件中需要应用许多不同的样式，因此最好使用`StyleSheet` API 将样式组织在键/值对象中，并从我们的`render`方法中引用它。逻辑和样式之间的分离有助于代码的可读性，还可以使代码重用，因为样式可以级联到子组件。

# 对齐元素

React Native 使用 Flexbox 来设置应用程序中元素的布局。这通常很简单，但有时在对齐元素时可能会令人困惑，因为有四个属性可用于此目的：

+   `justifyContent`：它定义了子元素沿着主轴的对齐方式

+   `alignItems`：它定义了子元素沿着交叉轴的对齐方式

+   `alignContent`：当交叉轴上有额外空间时，它会对齐 flex 容器的行

+   `alignSelf`：它允许覆盖单个 flex 项的默认对齐方式（或由`alignItems`指定的对齐方式）

前三个属性应分配给容器元素，而第四个属性将应用于子元素，以便在需要覆盖默认对齐方式时使用。

在我们的情况下，我们只希望一个元素（标题）居中对齐，因此我们可以使用`alignSelf: 'center'`。在本章的后面，我们将看到不同的`align`属性的其他用途。

# LocationPin

在本节中，我们将专注于构建指向地图中心的标记，以直观确认取货位置。此标记还包含一个按钮，可用于触发取货请求：

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

就功能而言，这个组件再次非常轻量级，但具有许多自定义样式。让我们深入了解一些样式细节。

# flexDirection

默认情况下，React Native 和 Flexbox 会垂直堆叠元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/c5c3d64c-719f-48ba-946a-848bbac061a3.png)

对于我们的标记中的横幅，我们希望将每个元素水平堆叠在一起，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-bp/img/55123e3b-a34e-4653-a40f-0074b5150823.png)

这可以通过向包含元素添加以下样式来实现`flexDirection: 'row'`。`flexDirection`的其他有效选项是：

+   row-reverse

+   `column`（默认）

+   `column-reverse`

# 尺寸

在这个组件中的代码的第一行从设备中提取高度和宽度到两个变量中：

```jsx
const {height, width} = Dimensions.get('window');
```

获取设备的高度和宽度使我们开发人员能够绝对定位一些元素，确信它们将正确对齐显示。例如，我们希望我们的图钉的横幅对齐在屏幕中央，所以它指向地图的中心。我们可以在样式表中的`banner`样式中添加`{top: (height/2), left: (width/2)}`来实现这一点。当然，这会将其对齐到左上角，所以我们需要从每个属性中减去横幅大小的一半，以确保它在元素的中间得到居中。每当我们需要对齐一个与组件树中的任何其他元素无关的元素时，都可以使用这个技巧，尽管在可能的情况下建议使用相对定位。

# 阴影

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
 shadowOpacity: 1.0 }
```

为了给组件添加阴影，我们需要添加四个属性：

+   `shadowColor`：这添加了我们组件所需的颜色的十六进制或 RGBA 值

+   `shadowOffset`：这显示了我们希望阴影投射多远

+   `shadowRadius`：这显示了阴影在角落的半径值

+   `shadowOpacity`：这显示了我们希望阴影有多深

这就是我们的`LocationPin`组件的全部内容。

# 类选择

在这个组件中，我们将探索 React Native 中的`Animated` API，以开始使用动画。此外，我们将使用自定义字体来改善用户体验，并增加我们应用程序中的定制感：

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

+   `classBar`：这是显示条和每个类的停靠点的图像

+   `classButton`：这是圆形按钮，一旦用户按下特定的类，它将移动到所选的类

+   `classButtonContainer`：这是可触摸组件，用于检测用户想要选择的类

+   `classLabel`：这些是每个类的标题，将显示在条的顶部

让我们从样式开始，因为我们可以在图像组件中找到一个新的属性：`resizeMode`，它确定当框架与原始图像尺寸不匹配时如何调整图像大小。从五种可能的值（`cover`，`contain`，`stretch`，`repeat`和`center`）中，我们选择了`contain`，因为我们希望均匀缩放图像（保持图像的纵横比），以便图像的两个尺寸都等于或小于视图的相应尺寸。我们在`classBar`和`classButtonImage`中都使用了这些属性，这是我们在这个视图中需要调整大小的两个图像。

# 添加自定义字体

React Native 默认包含一长串跨平台字体。字体列表可以在[`github.com/react-native-training/react-native-fonts`](https://github.com/react-native-training/react-native-fonts)上查看。

然而，添加自定义字体是开发应用程序时的常见需求，特别是涉及到设计师时，因此我们将使用我们的汽车预订应用程序作为测试这一功能的场所。

添加自定义字体到我们的应用程序是一个三步任务：

1.  将字体文件（.ttf）添加到项目内的一个文件夹中。我们在这个应用程序中使用了`fonts/`。

1.  将以下行添加到我们的`package.json`：

```jsx
      “rnpm”: {
          “assets”: [“./fonts”]
      }
```

1.  在终端中运行以下命令：

```jsx
 react-native link
```

就是这样，React Native 的 CLI 将一次性处理`fonts`文件夹及其文件的插入到 iOS 和 Android 项目中。我们的字体将通过它们的字体名称（可能与文件名不同）可用。在我们的情况下，我们在样式表中有`fontFamily: 'Blair ITC'`。

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

# 动画

React Native 的`Animated` API 旨在以高性能的方式，简洁地表达各种有趣的动画和交互模式。动画侧重于输入和输出之间的声明关系，中间有可配置的转换，并且有简单的`start`/`stop`方法来控制基于时间的动画执行。

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

为了使这种移动正确发生，我们需要将`classButtonImage`包装在`Animated.View`中，并为其提供一个初始的`Animated.Value`作为左坐标。我们将使用`this.state.classButtonPosition`来做到这一点，这样当用户选择特定的类别时我们可以改变它。

我们准备开始我们的动画。它将由`_onClassChange`方法触发，因为当用户按下`classButtonContainer`（`<TouchableOpacity/>`）时，它被调用。这个方法调用`Animated.timing`函数传递两个参数：

+   驱动动画的动画值（`this.state.classButtonPosition`）

+   包含动画的结束值和持续时间的对象

调用`Animated.timing`将导致一个包含`start()`方法的对象，我们立即调用它来启动动画。然后 React Native 将知道`Animated.View`的`left`坐标需要根据提供的参数慢慢改变。

由于这可能对于简单的移动动画来说有点复杂，但它允许广泛的定制，如链接动画或修改缓动函数。我们将在本章后面看到旋转动画。

# ConfirmationModal

我们的最后一个组件是一个模态视图，当用户按下“设置取货位置”按钮时，它将被打开。我们将显示模态和自定义活动指示器，它将使用复杂的动画设置来持续在其位置旋转：

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

对于这个组件，我们使用 React Native 中可用的`<Modal />`组件来利用其淡入淡出动画和可见性功能。属性`this.props.visible`将驱动此组件的可见性，因为它是知道用户的取货请求的父组件。

让我们再次专注于动画，因为我们想为显示活动的旋转器做一个更复杂的设置。我们想要显示一个无休止的旋转动画，所以我们需要系统地调用我们的`start()`动画方法。为了实现这一点，我们创建了一个`cycleAnimation()`方法，它在组件挂载时被调用（以启动动画），并且从返回的`Animated.timing`对象中调用，因为它作为回调传递以在每次动画结束时被调用。

我们还使用`Animated.sequence`来连接两个动画：

+   从 0 度移动到 360 度（在一秒钟内使用线性缓动）

+   从 360 度移动到 0 度（在 0 秒内）

这是为了在每个周期结束时重复第一个动画。

最后，我们定义了一个名为`interpolatedRotateAnimation`的变量，用于存储从 0 度到 360 度的插值，因此可以将其传递给`transform`/`rotate`样式，定义了在动画我们的`Animated.Image`时可用的旋转值。

作为一个实验，我们可以尝试用替代图像更改 loading.png，并看看它如何被动画化。这可以通过替换我们的<Animated.Image />组件中的源属性轻松实现。

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

使用诸如`native-base`或`react-native-elements`之类的 UI 库在构建应用程序时节省了大量时间和维护麻烦，但结果最终呈现出一种标准风格，这在用户体验方面并不总是理想的。这就是为什么学习如何操纵我们应用程序的样式总是一个好主意，特别是在由 UX 专家或应用程序设计师提供设计的团队中。

在本章中，我们深入研究了使用 React Native 的 CLI 初始化项目时创建的文件夹和文件。此外，我们熟悉了开发人员菜单及其调试功能。

在构建我们的应用程序时，我们专注于布局和组件样式，还学习了如何添加和操纵动画，使我们的界面对用户更具吸引力。我们研究了 Flexbox 布局系统以及如何在组件中堆叠和居中元素。诸如尺寸之类的 API 被用来检索设备的宽度和高度，以在某些组件上执行定位技巧。

您学会了如何将字体和图像添加到我们的应用程序中，并如何显示它们以改善用户体验。

既然我们知道如何构建更多定制的界面，让我们在下一章中构建一个图像分享应用程序，其中设计起着关键作用。
