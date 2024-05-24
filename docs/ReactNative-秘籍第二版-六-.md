# ReactNative 秘籍第二版（六）

> 原文：[`zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce`](https://zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：添加本机功能-第二部分

在本章中，我们将涵盖以下食谱：

+   对应用程序状态变化做出反应

+   复制和粘贴内容

+   通过触摸 ID 或指纹传感器进行身份验证

+   在多任务处理时隐藏应用程序内容

+   在 iOS 上进行后台处理

+   在 Android 上进行后台处理

+   在 iOS 上播放音频文件

+   在 Android 上播放音频文件

# 介绍

在本章中，我们将继续介绍更多的食谱，涉及编写与本机 iOS 和 Android 代码交互的 React Native 应用程序的不同方面。我们将涵盖利用内置和社区创建的模块的示例应用程序。这些食谱涵盖了一系列主题，从渲染基本按钮到创建不阻塞主应用程序线程的多线程进程。

# 对应用程序状态变化做出反应

普通移动设备用户通常会经常使用几个应用程序。理想情况下，除了其他社交媒体应用程序、游戏、媒体播放器等，用户还将使用您的 React Native 应用程序。任何特定的用户可能会在每个应用程序中花费很短的时间，因为他们在多任务处理。如果我们想要在用户离开我们的应用程序并重新进入时做出反应怎么办？我们可以利用这个机会与服务器同步数据，或者告诉用户我们很高兴看到他们回来，或者礼貌地要求在应用商店上对应用程序进行评分。

这个食谱将涵盖应用程序状态变化的基础知识，也就是说，对应用程序处于前台（活动）、后台或非活动状态时做出反应。

对于这个食谱，让我们创建一个名为`AppStateApp`的新的纯 React Native 应用程序。

# 如何做...

1.  幸运的是，React Native 提供了对应用程序状态变化的支持，通过`AppState`模块监听。让我们通过向`App.js`文件添加依赖项来开始构建应用程序，如下所示：

```jsx
import React, { Component } from 'react';
import {
  AppState,
  StyleSheet,
  Text,
  View
} from 'react-native';
```

1.  在这个食谱中，我们将跟踪先前的状态，以查看用户来自何处。如果这是他们第一次进入应用程序，我们将欢迎他们，如果他们返回，我们将改为欢迎他们。为此，我们需要保留对先前和当前应用程序状态的引用。我们将使用实例变量`previousAppState`和`currentAppStates`来代替使用状态，只是为了避免潜在的命名混淆。我们将使用`state`来保存向用户的状态消息，如下所示：

```jsx
export default class App extends Component {
  previousAppState = null;
  currentAppState = 'active';
  state = {
    statusMessage: 'Welcome!'
  }
  // Defined on following steps
}
```

1.  当组件挂载时，我们将使用`AppState`组件添加一个`change`事件的监听器。每当应用程序的状态发生变化（例如，当应用程序被置于后台时），将触发`change`事件，然后我们将触发下一步中定义的`handleAppStateChange`处理程序，如下所示：

```jsx
  componentWillMount() {
    AppState.addEventListener('change', this.handleAppStateChange);
  }
```

1.  `handleAppStateChange`方法将接收`appState`作为参数，我们可以期望它是三个字符串中的一个：如果应用程序从内存中卸载，则为`inactive`，如果应用程序在内存中并处于后台，则为`background`，如果应用程序在前台，则为`active`。我们将使用`switch`语句相应地更新`state`上的`statusMessage`：

```jsx
  handleAppStateChange = (appState) => {
    let statusMessage;

    this.previousAppState = this.currentAppState;
    this.currentAppState = appState;
    switch(appState) {
      case 'inactive':
        statusMessage = "Good Bye.";
        break;
      case 'background':
        statusMessage = "App Is Hidden...";
        break;
      case 'active':
        statusMessage = 'Welcome Back!'
        break;
    }
    this.setState({ statusMessage });
  }
```

1.  `render`方法在这个示例中非常基础，因为它只需要向用户显示状态消息，如下所示：

```jsx
 render() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>
          {this.state.statusMessage}
        </Text>
      </View>
    );
  }
```

1.  该应用程序的样式很基础，包括字体大小、颜色和边距，如下所示：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#fff',
  },
  welcome: {
    fontSize: 40,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
});
```

1.  完成的应用程序现在应该根据设备上应用程序的状态显示适当的状态消息。

# 工作原理...

在这个示例中，我们利用了内置的`AppState`模块。该模块监听 Android 上的`Activity`事件，在 iOS 上使用`NSNotificationCenter`在各种`UIApplication`事件上注册监听器。请注意，两个平台都支持`active`和`background`状态；然而，`inactive`状态是 iOS 独有的概念。由于 Android 的多任务处理实现，它不明确支持`inactive`状态，因此只在`background`和`active`状态之间切换应用程序。要在 Android 上实现等效于 iOS 不活动状态的效果，请参见本章后面的*在多任务处理时隐藏应用程序内容*示例。

# 复制和粘贴内容

在桌面和移动操作系统中最常用的功能之一是用于复制和粘贴内容的剪贴板。在移动设备上的常见情况是使用长文本填写表单，例如长电子邮件地址或密码。与其打字并出现几个拼写错误，不如直接打开您的联系人应用程序，从那里复制电子邮件并粘贴到您的`TextInput`字段中会更容易。

这个示例将展示在 Android 和 iOS 上如何在 React Native 应用程序中复制和粘贴文本的基本示例。在我们的示例应用程序中，我们将有一个静态的`Text`视图和一个`TextInput`字段，您可以使用它来将其内容复制到剪贴板。此外，还将有一个按钮，用于将剪贴板的内容输出到视图中。

# 准备工作

对于这个示例，我们将创建一个名为 `CopyPasteApp` 的纯 React Native 应用程序。

在这个示例中，我们将再次使用 `react-native-button`。使用 `npm` 安装它：

```jsx
npm install react-native-button
```

或者，我们可以使用 `yarn`：

```jsx
yarn add react-native-button
```

# 如何做...

1.  让我们首先创建一个 `ClipboardText` 组件，它既使用 `Text` 组件来显示文本，又提供了通过长按将其内容复制到剪贴板的功能。在项目的根目录下创建一个 `component` 文件夹，并在其中创建一个 `ClipboardText.js` 文件。我们将首先导入依赖项，如下所示：

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  Text,
  View,
  Clipboard,
  TextInput
} from 'react-native';
import Button from 'react-native-button';
```

1.  接下来，我们将定义 `App` 类和初始的 `state`。我们将使用 `state` 上的 `clipboardContent` 属性来存储从剪贴板粘贴到 UI 中的文本，如下所示：

```jsx
export default class App extends Component {
  state = {
    clipboardContent: null
  }
  // Defined in following steps
}
```

1.  UI 将有一个 `Text` 组件，其文本可以通过长按进行复制。让我们定义 `copyToClipboard` 方法。我们将通过它的 `ref`（稍后我们将定义）获取输入，并通过其 `props.children` 属性访问组件的文本。一旦文本被存储在一个本地变量中，我们只需将其传递给 `Clipboard` 的 `setString` 方法，以将文本复制到剪贴板，如下所示：

```jsx
  copyToClipboard = () => {
    const sourceText = this.refs.sourceText.props.children;
    Clipboard.setString(sourceText);
  }
```

1.  同样，我们还需要一个方法，它将从剪贴板中粘贴文本到应用的 UI 中。这个方法将使用 `Clipboard` 的 `getString` 方法，并将返回的字符串保存到 `state` 的 `clipboardContent` 属性中，重新渲染应用的 UI 以反映粘贴的文本，如下所示：

```jsx
  getClipboardContent = async () => {
    const clipboardContent = await Clipboard.getString();
    this.setState({
      clipboardContent
    });
  }
```

1.  `render` 方法将由两个部分组成：第一部分是要复制的内容，第二部分是从剪贴板粘贴文本到 UI 的方法。让我们从第一部分开始，它包括一个 `Text` 输入，其 `onLongPress` 属性连接到我们在 *步骤 3* 中创建的 `copyToClipboard` 方法，以及一个用于正常本地复制/粘贴的文本输入：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.instructions}>
          Tap and Hold the next line to copy it to the Clipboard:
        </Text>
        <Text
          ref="sourceText"
          onLongPress={this.copyToClipboard}
        >
          React Native Cookbook
        </Text>
        <Text style={styles.instructions}>
          Input some text into the TextInput below and Cut/Copy as
          you normally would:
        </Text>
        <TextInput style={styles.textInput} />

        // Defined on next step
      </View>
    );
  }
```

1.  UI 的第二部分包括一个 `Text` 组件，用于显示保存在 `state` 的 `clipboardContent` 中的当前值，并一个按钮，将使用我们在 *步骤 4* 中定义的 `getClipboardContent` 方法从剪贴板中粘贴：

```jsx
  render() {
    return (
      <View style={styles.container}>
        // Defined in previous step
 <View style={styles.row}>
 <Text style={styles.rowText}>
 Clipboard Contents:
 </Text>
 </View>
 <View style={styles.row}>
 <Text style={styles.content}>
 {this.state.clipboardContent}
 </Text>
 </View>
 <Button
 containerStyle={styles.buttonContainer}
 style={styles.buttonStyle}
 onPress={this.getClipboardContent}
 >
 Paste Clipboard
 </Button>
      </View>
    );
  }
```

最终的应用程序应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/77ae1f65-21d0-463c-8387-4dea842f92ce.png)

# 它是如何工作的...

在这个示例中，我们通过使用 React Native 提供的`Clipboard`API 构建了一个简单的复制粘贴应用程序。`Clipboard`模块目前仅支持`String`类型的内容，尽管设备可以复制更复杂的数据。这个模块使得使用剪贴板就像调用`setString`和`getString`方法一样简单。

# 通过指纹识别或指纹传感器进行认证

安全在软件中是一个重要的问题，特别是在任何形式的认证时。数据泄露和密码泄露已经成为日常新闻的一部分，各种规模的公司都在意识到需要在他们的应用程序中实施额外的安全措施。移动设备中的一种措施是生物识别认证，它使用指纹扫描或面部识别技术提供补充的身份验证方法。

这个示例介绍了如何添加指纹扫描和面部识别安全功能。由于`react-native-touch-id`库的存在，这个过程在 React Native 应用程序开发中变得简化和流畅。

# 准备工作

对于这个示例，我们需要一个新的纯 React Native 应用。让我们称之为`BiometricAuth`。

我们将使用`react-native-button`和`react-native-touch-id`库。使用`npm`安装它们：

```jsx
npm install react-native-button react-native-touch-id --save
```

或者，我们可以使用`yarn`：

```jsx
yarn add react-native-button react-native-touch-id
```

安装完成后，`react-native-touch-id` 需要进行链接，所以请务必跟进：

```jsx
react-native link
```

权限也需要手动调整。对于 Android 权限，请在项目中找到`AndroidManifest.xml`文件，应该在`BiometricAuth/android/app/src/main/AndroidManifest.xml`。除了这个文件中的其他权限，你还需要添加以下内容：

```jsx
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

对于 iOS 权限，你需要在文本编辑器中更新`Info.plist`文件。`Info.plist`可以在`BiometricAuth/ios/BiometricAuth/Info.plist`找到。除了所有其他条目，添加以下内容：

```jsx
<key>NSFaceIDUsageDescription</key>
<string>Enabling Face ID allows you quick and secure access to your account.</string>
```

# 如何做...

1.  让我们首先在`App.js`文件中添加依赖项，如下所示：

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  Text,
  View
} from 'react-native';
import Button from 'react-native-button';
import TouchID from 'react-native-touch-id';
```

1.  接下来，我们将定义`App`类和初始`state`。我们将在`state`的`authStatus`属性上跟踪认证状态，如下所示：

```jsx
export default class App extends Component {
  state = {
    authStatus: null
  }
  // Defined in following steps
}
```

1.  让我们定义`authenticate`方法，它将在按钮按下时触发，并在设备上启动认证。我们可以通过执行`TouchID`组件的`authenticate`方法来启动认证。这个方法的第一个参数是一个可选的字符串，解释请求的原因，如下所示：

```jsx
  authenticate = () => {
    TouchID.authenticate('Access secret information!')
      .then(this.handleAuthSuccess)
      .catch(this.handleAuthFailure);
  }
```

1.  这个方法在成功时触发`handleAuthSuccess`方法。让我们现在来定义它。这个方法简单地将`state`的`authStatus`属性更新为字符串`Authenticated`，如下所示：

```jsx
  handleAuthSuccess = () => {
    this.setState({
      authStatus : 'Authenticated'
    });
  }
```

1.  同样，如果身份验证失败，将调用`handleAuthFailure`函数，该函数将更新相同的`state.authStatus`为字符串`Not Authenticated`，如下所示：

```jsx
  handleAuthFailure = () => {
    this.setState({
      authStatus : 'Not Authenticated'
    });
  }
```

1.  `render`方法将需要一个按钮来发起身份验证请求，以及两个`Text`组件：一个用于标签，一个用于显示身份验证状态，如下所示：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Button
          containerStyle={styles.buttonContainer}
          style={styles.button}
          onPress={this.authenticate}>
            Authenticate
        </Button>
        <Text style={styles.label}>Authentication Status</Text>
        <Text style={styles.welcome}>{this.state.authStatus}</Text>
      </View>
    );
  }
```

1.  最后，我们将添加样式来设置 UI 的颜色、大小和布局，如下所示：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#fff',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  label: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
  buttonContainer: {
    width: 150,
    padding: 10,
    margin: 5,
    height: 40,
    overflow: 'hidden',
    backgroundColor: '#FF5722'
  },
  button: {
    fontSize: 16,
    color: 'white'
  }
});
```

# 工作原理...

这个教程演示了将原生指纹和面部识别安全性简单地整合到 React Native 应用程序中的方法。调用`TouchID.authenticate`还需要一个可选的选项对象参数，其中包括三个属性：`title`用于确认对话框的标题（仅限 Android），`color`用于对话框的颜色（仅限 Android），以及`fallbackLabel`用于编辑默认的“显示密码”标签（仅限 iOS）。

# 在多任务处理时隐藏应用程序内容

保持应用程序安全主题的进行，有时我们必须警惕不速之客触摸我们的设备，可能获取对我们应用程序的访问权限。为了保护用户在查看敏感信息时免受窥视，我们可以在应用程序隐藏但仍处于活动状态时对应用程序进行遮罩。一旦用户返回到应用程序，我们只需移除遮罩，用户就可以继续正常使用应用程序。这在银行或密码应用程序中隐藏敏感信息时是一个很好的使用案例。

这个教程将向你展示如何渲染一个图像来遮罩你的应用程序，并在应用程序返回到前台或活动状态时将其移除。我们将涵盖 iOS 和 Android；然而，实现方式完全不同。对于 iOS，我们采用纯 Objective-C 实现以获得最佳性能。对于 Android，我们需要对`MainActivity`进行一些修改，以便向 JavaScript 层发送应用程序失去焦点的事件。我们将在那里处理图像遮罩的渲染。

# 准备工作

当应用程序不在前台时，我们需要一个图像来用作遮罩。我选择使用了一张 iPhone 壁纸，你可以在这里找到：

[`www.hdiphone7wallpapers.com/2016/09/white-squares-iphone-7-and-7-plus-wallpapers.html`](http://www.hdiphone7wallpapers.com/2016/09/white-squares-iphone-7-and-7-plus-wallpapers.html)

该图像是一种风格化的马赛克图案。它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/a329bd35-49fe-44b3-bcc3-a6e257a9ed5a.jpg)

当然，您可以使用任何您喜欢的图像。在这个示例中，图像文件将被命名为`hidden.jpg`，因此请相应地重命名您的图像。

我们需要一个新的纯 React Native 应用程序。让我们称之为`HiddenContentApp`。

# 如何做...

1.  让我们首先将面具图像添加到应用程序的 iOS 部分。我们需要在新的 React Native 应用程序的`ios/`目录中的 Xcode 中打开项目的`ios`文件夹。

1.  我们可以通过将图像拖放到 Xcode 项目的`Images.xcassets`文件夹中来将`hidden.jpg`图像添加到项目中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7a2e117f-9a1d-4c3f-952c-282f501c07f5.png)

1.  接下来，我们将向`AppDelegate.m`文件添加一个新的实现和两种方法。可以在下面找到整个文件，包括生成的代码。为了清晰起见，我们添加的代码已用粗体标记。我们正在扩展`applicationWillResignActive`方法，每当给定应用程序从前台变为后台时，它都会触发，以添加一个带有`hidden.jpg`作为其图像的`imageView`。同样，我们还需要扩展相反的方法`applicationDidBecomeActive`，以在应用程序重新进入前台时删除图像：

```jsx
#import "AppDelegate.h"

#import <React/RCTBundleURLProvider.h>
#import <React/RCTRootView.h>

@implementation AppDelegate {
 UIImageView *imageView;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
  NSURL *jsCodeLocation;

  jsCodeLocation = [[RCTBundleURLProvider sharedSettings] jsBundleURLForBundleRoot:@"index" fallbackResource:nil];

  RCTRootView *rootView = [[RCTRootView alloc] initWithBundleURL:jsCodeLocation
                                                      moduleName:@"HiddenContentApp"
                                               initialProperties:nil
                                                   launchOptions:launchOptions];
  rootView.backgroundColor = [[UIColor alloc] initWithRed:1.0f green:1.0f blue:1.0f alpha:1];

  self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
  UIViewController *rootViewController = [UIViewController new];
  rootViewController.view = rootView;
  self.window.rootViewController = rootViewController;
  [self.window makeKeyAndVisible];
  return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
 imageView = [[UIImageView alloc] initWithFrame:[self.window frame]];
 [imageView setImage:[UIImage imageNamed:@"hidden.jpg"]];
 [self.window addSubview:imageView];
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
 if(imageView != nil) {
 [imageView removeFromSuperview];
 imageView = nil;
 }
}

@end
```

1.  通过前面的三个步骤，iOS 应用程序中显示面具所需的所有工作已经完成。让我们通过在 Android Studio 中打开项目的 Android 部分来继续进行。在 Android Studio 中，选择打开现有的 Android Studio 项目，并打开项目的`android`目录。

1.  我们需要更新 Android 项目中的唯一本地代码位于`MainActivity.java`中，位于此处：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/752fe834-c63d-4a90-8d38-b145c84a551a.png)

我们需要添加一个方法，以及方法使用的来自 React 的三个导入。下面是完整的`MainActivity.java`文件，加粗标记的是添加的代码。我们正在定义一个扩展基本方法功能的`onWindowFocusChanged`方法。基本的`onWindowFocusChanged` Android 方法在给定应用程序的焦点发生变化时触发，传递一个表示应用程序是否具有焦点的`hasFocus`布尔值。我们的扩展将通过我们命名为`focusChange`的事件有效地将该`hasFocus`布尔值从父方法传递到 React Native 层，如下所示：

```jsx
package com.hiddencontentapp;

import com.facebook.react.ReactActivity;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

public class MainActivity extends ReactActivity {

  /**
  * Returns the name of the main component registered from JavaScript.
  * This is used to schedule rendering of the component.
  */
  @Override
  protected String getMainComponentName() {
    return "HiddenContentApp";
  }

 @Override
 public void onWindowFocusChanged(boolean hasFocus) {
 super.onWindowFocusChanged(hasFocus);
 if (getReactNativeHost().getReactInstanceManager().getCurrentReactContext() != null) {
 WritableMap params = Arguments.createMap();
 params.putBoolean("appHasFocus", hasFocus);

 getReactNativeHost().getReactInstanceManager()
 .getCurrentReactContext()
 .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
 .emit("focusChange", params);
 }
 }
}
```

1.  要在 Android 中使用`hidden.jpg`遮罩图像，我们还需要将其添加到 React Native 项目中。让我们在 React Native 项目的根目录中创建一个新的`assets`文件夹，并将`hidden.jpg`图像文件添加到新文件夹中。

1.  有了原生部分的基础，我们现在准备转向应用程序的 JavaScript 部分。让我们在`App.js`中添加我们将使用的导入，如下所示：

```jsx
import React, {Component} from 'react';
import {
  StyleSheet,
  Text,
  View,
  DeviceEventEmitter,
  Image
} from 'react-native';
```

1.  接下来，让我们创建`App`类和初始`state`。`state`只需要一个`showMask`布尔值，它将决定是否显示遮罩，如下所示：

```jsx
export default class App extends Component {
  state = {
    showMask: null
  }
  // Defined in following steps
}
```

1.  当组件挂载时，我们希望注册一个事件监听器，以便使用`DeviceEventEmitter`的`addListener`方法监听从原生 Android 层发出的事件，将字符串`focusChange`作为要监听的事件的名称作为第一个参数，并将要执行的回调作为第二个参数。您可能还记得，`focusChange`是我们在`MainActivity.java`中的`onWindowFocusChange`方法中分配的事件名称，在*步骤 5*中注册事件监听器如下：

```jsx
  componentWillMount() {
    this.subscription = DeviceEventEmitter.addListener(
      'focusChange',
      this.onFocusChange
    );
  }
```

1.  在这一步中，我们将把事件监听器保存到类成员`this.subscription`中。这将允许在组件卸载时清理事件监听器。我们只需在组件卸载时通过`componentWillUnmount`生命周期钩子调用`this.subscription`上的`remove`方法，如下所示：

```jsx
  componentWillUnmount() {
    this.subscription.remove();
  }
```

1.  让我们定义在*步骤 9*中使用的`onFocusChange`处理程序。该方法接收一个`params`对象，其中包含通过*步骤 5*中定义的`onWindowFocusChanged`方法从原生层传递的`appHasFocus`布尔值。通过将`state`上的`showMask`布尔值设置为`appHasFocus`布尔值的相反值，我们可以在`render`函数中使用它来切换显示`hidden.jpg`图像，如下所示：

```jsx
  onFocusChange = (params) => {
    this.setState({showMask: !params.appHasFocus})
  }
```

1.  `render`方法的主要内容在这个示例中并不重要，但我们可以使用它来在`state`的`showMask`属性为`true`时应用`hidden.jpg`蒙版图像，如下所示：

```jsx
  render() {
    if(this.state.showMask) {
      return (<Image source={require('./assets/hidden.jpg')} />);
    }
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>Welcome to React Native!</Text>
      </View>
    );
  }
```

1.  应用程序已经完成。一旦应用程序加载完成，您应该能够转到应用程序选择视图（在 iOS 上双击 home，或在 Android 上按方形按钮），并在应用程序不在前台时看到应用的蒙版图像。请注意，Android 模拟器可能无法按预期正确应用蒙版，因此这个功能可能需要使用 Android 设备进行测试。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c97ae150-6166-44ee-a686-c3758bc11c7f.png)

# 工作原理...

在这个示例中，我们看到了需要使用两种不同的方法来完成相同的任务。对于 iOS，我们在本地层中独占地处理显示图像蒙版，而不需要 React Native 层。对于 Android，我们使用 React Native 来处理图像蒙版。

在*步骤 3*中，我们扩展了两个 Objective-C 方法：`applicationWillResignActive`，当应用程序从前台切换时触发，以及`applicationDidBecomeActive`，当应用程序进入前台时触发。对于每个事件，我们简单地切换显示在 Xcode 项目的`Images.xcassettes`文件夹中存储的`hidden.jpg`图像的`imageView`。

在*步骤 5*中，我们使用了 React 类`RCTDeviceEventEmitter`从`DeviceEventManagerModule`来发出一个名为`focusChange`的事件，传递一个带有`appHasFocus`布尔值的`params`对象到 React Native 层，如下所示：

```jsx
     getReactNativeHost().getReactInstanceManager()
       .getCurrentReactContext()
       .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
       .emit("focusChange", params);
     }
```

在*步骤 9*中，我们定义了`componentWillMount`生命周期钩子，为从本地 Android 层发出的`focusChange`事件设置了一个事件侦听器，触发`onFocusChange`方法，该方法将根据本地`appHasFocus`值更新`state`的`showMask`值，触发重新渲染，适当地显示蒙版。

# iOS 上的后台处理

在过去的几年里，移动设备的处理能力大大增加。用户要求更丰富的体验，实现在现代移动设备上改进性能的一种方法是通过多线程。大多数移动设备今天都由多核处理器驱动，它们的操作系统现在为开发人员提供了在后台执行代码的简单抽象，而不会干扰应用程序 UI 的性能。

这个示例将涵盖 iOS 的**Grand Central Dispatch**（**GCD**）的使用，以在新线程上执行异步后台处理，并在处理完成时与 React Native 层进行通信。

# 准备工作

对于这个示例，我们需要一个新的纯 React Native 应用程序。让我们将其命名为`MultiThreadingApp`。

我们还将使用`react-native-button`库。使用`npm`安装它：

```jsx
npm install react-native-button --save
```

或者，我们可以使用`yarn`：

```jsx
yarn add react-native-button --save
```

# 如何做...

1.  我们将首先在新的 React Native 应用程序的`ios`目录中打开 Xcode 中的 iOS 项目。

1.  让我们添加一个名为`BackgroundTaskManager`的新的 Cocoa 类文件，其子类为`NSObject`。有关在 Xcode 中执行此操作的更多详细信息，请参考本章中的*公开自定义 iOS 模块*示例。

1.  接下来，让我们将新模块连接到 React 的`RCTBrideModule`，在新模块的头文件`BackgroundTaskManager.h`中。要添加的代码在以下片段中用粗体标记出来：

```jsx
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import "RCTBridgeModule.h"

@interface BackgroundTaskManager : NSObject <RCTBridgeModule> {
 dispatch_queue_t backgroundQueue;
}

@end
```

1.  我们将在`BackgroundTaskManager.m`文件中实现本机模块。同样，我们要添加的新代码在以下片段中用粗体标记出来：

```jsx
#import "BackgroundTaskManager.h"
#import "RCTBridge.h"
#import "RCTEventDispatcher.h"

@implementation BackgroundTaskManager

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(loadInBackground) {
 backgroundQueue = dispatch_queue_create("com.moduscreate.bgqueue", NULL);

 dispatch_async(backgroundQueue, ^{
 NSLog(@"processing background");
 [self.bridge.eventDispatcher sendAppEventWithName:@"backgroundProgress" body:@{@"status": @"Loading"}];
 [NSThread sleepForTimeInterval:5];
 NSLog(@"slept");
 dispatch_async(dispatch_get_main_queue(), ^{
 NSLog(@"Done processing; main thread");
 [self.bridge.eventDispatcher sendAppEventWithName:@"backgroundProgress" body:@{@"status": @"Done"}];
 });
 });
}

@end
```

1.  接下来让我们转向 JavaScript 层。我们将首先在`App.js`文件中添加依赖项。作为依赖项的一部分，我们还需要导入在*步骤 3*和*步骤 4*中定义的`BackgroundTaskManager`本机模块，如下所示：

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  Text,
  View,
  NativeModules,
  NativeAppEventEmitter
} from 'react-native';
import Button from 'react-native-button'; 

const BackgroundTaskManager = NativeModules.BackgroundTaskManager;
```

1.  让我们定义`App`类，初始状态为`backgroundTaskStatus`设置为字符串`Not Started`，并且`doNothingCount`属性初始化为`0`，如下所示：

```jsx
 export default class App extends Component {
  state = {
    backgroundTaskStatus: 'Not Started',
    counter: 0
  }
  // Defined in following steps
}
```

1.  我们需要监听从我们在*步骤 3*和*步骤 4*中创建的自定义模块的本机 iOS 层发出的`backgroundProcess`事件。让我们使用`NativeAppEventEmitter` React Native 组件设置事件监听器，将`state`的`backgroundTaskStatus`属性设置为从本机事件接收到的事件对象上的`status`值，如下所示：

```jsx
  componentWillMount = () => {
    this.subscription = NativeAppEventEmitter.addListener(
      'backgroundProgress',
      event => this.setState({ backgroundTaskStatus: event.status })
    );
  }
```

1.  当组件卸载时，我们需要从上一步中删除事件监听器，如下所示：

```jsx
  componentWillUnmount = () => {
    this.subscription.remove();
  }
```

1.  UI 将有两个按钮，每个按钮在按下时都需要调用一个方法。`runBackgroundTask`将运行我们在本机 iOS 层上定义并导出的`loadInBackground`方法，该方法位于`BackgroundTaskManager`自定义本机模块上。`increaseCounter`按钮将简单地通过`1`增加`state`上的`counter`属性，以显示主线程未被阻塞的情况，如下所示：

```jsx
  runBackgroundTask = () => {
    BackgroundTaskManager.loadInBackground();
  }

  increaseCounter = () => {
    this.setState({
      counter: this.state.counter + 1
    });
  }
```

1.  应用的 UI 将包括两个按钮来显示`Button`组件，以及一个`Text`组件来显示在`state`上保存的值。“Run Task”按钮将执行`runBackgroundTask`方法来启动后台进程，并且`this.state.backgroundTaskStatus`将更新以显示进程的新状态。在后台进程运行的五秒钟内，按下“Increase Counter”按钮仍然会增加计数器 1，证明后台进程是非阻塞的，如下面的代码片段所示：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Button
          containerStyle={styles.buttonContainer}
          style={styles.buttonStyle}
          onPress={this.runBackgroundTask}>
            Run Task
        </Button>
        <Text style={styles.instructions}>
          Background Task Status:
        </Text>
        <Text style={styles.welcome}>
          {this.state.backgroundTaskStatus}
        </Text>
        <Text style={styles.instructions}>
          Pressing "Increase Conter" button shows that the task is
          not blocking the main thread
        </Text>
        <Button
          containerStyle={[
            styles.buttonContainer,
            styles.altButtonContainer
          ]}
          style={styles.buttonStyle}
          onPress={this.increaseCounter}
        >
            Increase Counter
        </Button>
        <Text style={styles.instructions}>
          Current Count:
        </Text>
        <Text style={styles.welcome}>
          {this.state.counter}
        </Text>
      </View>
    );
  }
```

1.  作为最后一步，让我们使用样式块来布局和设计应用，如下所示：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
    marginLeft: 20,
    marginRight: 20
  },
  buttonContainer: {
    width: 150,
    padding: 10,
    margin: 5,
    height: 40,
    overflow: 'hidden',
    borderRadius: 4,
    backgroundColor: '#FF5722'
  },
  altButtonContainer : {
    backgroundColor : '#CDDC39',
    marginTop : 30
  },
  buttonStyle: {
    fontSize: 16,
    color: 'white'
  }
});
```

# 工作原理...

在这个示例中，我们创建了一个类似于本章前面*暴露自定义 iOS 模块*示例中涵盖的模块的本地模块。我们定义了本地模块来在 React Native 应用的后台执行任意操作。在这个示例中，后台进程由以下三个步骤组成：

1.  创建一个新的线程。

1.  在新线程上睡眠五秒钟。

1.  在五秒的睡眠后（模拟运行后台进程的结束），从 iOS 层向 React Native 层分发一个事件，让它知道进程已经完成。这是通过操作系统的 GCD API 实现的。

这个应用的 UI 的目的是展示多线程已经实现。如果后台进程在 React Native 层执行，由于 JavaScript 的单线程特性，应用在后台进程运行时会被锁定五秒钟。当您按下按钮时，桥被调用，然后消息可以被发布到本地层。如果本地线程当前正在忙于睡眠，那么我们无法处理这条消息。通过将处理转移到新线程，两者可以同时执行。

# 在 Android 上进行后台处理

在这个示例中，我们将构建一个 Android 版本的前一个示例的等价物。这个示例还将使用原生的 Android 层来创建一个新的进程，通过睡眠五秒钟来保持该进程运行，并允许用户通过按钮进行交互，以展示应用的主处理线程没有被阻塞。

虽然最终结果将是非常相似的，但在 Android 项目中生成一个新进程与 iOS 处理方式有些不同。这个示例将利用本地的`AsyncTask`函数，专门用于处理短期后台进程，以允许在 React Native 层执行而不阻塞主线程。

# 准备工作

对于这个示例，我们需要创建一个新的纯 React Native 应用。让我们命名它为`MultiThreadingApp`。

我们还将使用`react-native-button`库。使用`npm`安装它：

```jsx
npm install react-native-button --save
```

另外，我们可以使用`yarn`：

```jsx
yarn add react-native-button
```

# 如何做到…

1.  首先在 Android Studio 中打开 Android 项目。在 Android Studio 中，选择打开现有的 Android Studio 项目，并打开新项目的`android`目录。

1.  我们需要两个新的 Java 类：`BackgroundTaskManager`和`BackgroundTaskPackage`。

1.  现在这两个类都已创建，让我们打开`BackgroundTaskManager.java`并开始实现将包装`AsyncTask`操作的本地模块，从导入和定义类开始。此外，像任何其他本地 Android 模块一样，我们需要定义`getName`方法，用于为模块提供一个名称给 React Native，如下所示：

```jsx
package com.multithreadingapp;   import android.os.AsyncTask;   import com.facebook.react.bridge.Arguments; import com.facebook.react.bridge.ReactApplicationContext; import com.facebook.react.bridge.ReactContextBaseJavaModule; import com.facebook.react.bridge.ReactMethod; import com.facebook.react.bridge.WritableMap; import com.facebook.react.modules.core.DeviceEventManagerModule;

public class BackgroundTaskManager extends ReactContextBaseJavaModule {
  public BackgroundTaskManager(ReactApplicationContext reactApplicationContext) {
    super(reactApplicationContext);
  }

  @Override
  public String getName() {
    return "BackgroundTaskManager";
  }

  // Defined in following steps
}
```

1.  为了执行`AsyncTask`，它需要由一个私有类进行子类化。我们需要为此添加一个新的私有内部`BackgroundLoadTask`子类。在我们定义它之前，让我们首先添加一个`loadInBackground`方法，最终将被导出到 React Native 层。这个方法简单地创建一个`BackgroundLoadTask`的新实例并调用它的`execute`方法，如下所示：

```jsx
public class BackgroundTaskManager extends ReactContextBaseJavaModule {
 // Defined in previous step
  @ReactMethod
 public void loadInBackground() {
 BackgroundLoadTask backgroundLoadTask = new BackgroundLoadTask();
 backgroundLoadTask.execute();
 }
}
```

1.  `BackgroundLoadTask`子类还将使用一个辅助函数来来回发送事件，以跨越 React Native 桥通信后台进程的状态。`sendEvent`方法接受`eventName`和`params`作为参数，然后使用 React Native 的`RCTDeviceEventEmitter`类来`emit`事件，如下所示：

```jsx
public class BackgroundTaskManager extends ReactContextBaseJavaModule {
  // Defined in steps above

 private void sendEvent(String eventName, WritableMap params) {
 getReactApplicationContext().getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class).emit(eventName, params);
 }
}
```

1.  现在让我们继续定义`BackgroundLoadTask`子类，它继承自`AsyncTask`。子类将由三个方法组成：`doInBackground`用于启动一个新线程并让其休眠五分钟，`onProgressUpdate`用于向 React Native 层发送`"Loading"`状态，以及`onPostExecute`用于在后台任务完成时发送`"Done"`状态，如下所示：

```jsx
public class BackgroundTaskManager extends ReactContextBaseJavaModule {
  // Defined in above steps

 private class BackgroundLoadTask extends AsyncTask<String, String, String> {
 @Override
 protected String doInBackground(String... params) {
 publishProgress("Loading");
 try {
 Thread.sleep(5000);
 } catch (Exception e) {
 e.printStackTrace();
 }
 return "Done";
 }

 @Override
 protected void onProgressUpdate(String... values) {
 WritableMap params = Arguments.createMap();
 params.putString("status", "Loading");
 sendEvent("backgroundProgress", params);
 }

 @Override
 protected void onPostExecute(String s) {
 WritableMap params = Arguments.createMap();
 params.putString("status", "Done");
 sendEvent("backgroundProgress", params);
 }
 }
}
```

1.  由于 iOS 实现和 Android 实现之间的唯一区别存在于配方的本机层中，因此您可以按照上一个配方中的*步骤 5*至*步骤 11*来实现应用程序的 JavaScript 部分。

1.  最终的应用程序应该在行为和外观上（除了设备上的差异）与上一个配方中的应用程序相同：

！[](assets/cbc6bfc5-4e0f-4d49-ae41-27748267819a.png)

# 它是如何工作的...

在这个配方中，我们模仿了我们在 Android 上创建的*在 iOS 上进行后台处理*配方中创建的功能。我们创建了一个 Android 本机模块，其中一个方法在调用时在后台执行任意操作（休眠五秒）。当进程完成时，它会向 React Native 层发出事件，然后我们更新应用程序 UI 以反映后台进程的状态。Android 有多个选项可以在本机执行多线程操作。在这个配方中，我们使用了`AsyncTask`，因为它适用于短期运行（几秒钟）的进程，相对简单实现，并且操作系统为我们管理线程创建和资源分配。您可以在官方文档中阅读更多关于`AsyncTask`的信息：

[`developer.android.com/reference/android/os/AsyncTask`](https://developer.android.com/reference/android/os/AsyncTask)

# 在 iOS 上播放音频文件

在*实现复杂用户界面-第三部分*章节中，我们使用 Expo SDK 提供的`Audio`组件在*创建音频播放器*配方中构建了一个相对复杂的小型音频播放器。然而，Expo 的`Audio`组件的一个缺点是它无法在应用程序被置于后台时播放音频。目前使用本机层是实现这一点的唯一方法。

在这个配方中，我们将创建一个本机模块来显示 iOS MediaPicker，然后选择要播放的音乐文件。所选文件将通过本机 iOS 媒体播放器播放，允许在应用程序被置于后台时播放音频，并允许用户通过本机 iOS 控制中心控制音频。

# 准备工作

对于这个配方，我们需要创建一个新的纯 React Native 应用。让我们称之为`AudioPlayerApp`。

我们还将使用`react-native-button`库，可以使用`npm`安装：

```jsx
npm install react-native-button --save
```

或者，我们可以使用`yarn`：

```jsx
yarn add react-native-button
```

这是一个只能在真实设备上预期工作的示例。您还需要确保您的 iOS 设备上同步了音乐并且在媒体库中可用。

# 如何做...

1.  让我们首先在新的 React Native 应用程序的`ios`目录中打开 Xcode 中的 iOS 项目。

1.  接下来，我们将创建一个名为`MediaManager`的新的 Objective-C Cocoa 类。

1.  在`MediaManager`头文件（`.h`）中，我们需要导入`MPMediaPickerController`和`MPMusicPlayerController`，以及 React Native 桥（`RCTBridgeModule`），如下所示：

```jsx
#import <Foundation/Foundation.h>
#import <MediaPlayer/MediaPlayer.h>

#import <React/RCTBridgeModule.h>
#import <React/RCTEventDispatcher.h>

@interface MediaManager : NSObject<RCTBridgeModule, MPMediaPickerControllerDelegate>

@property (nonatomic, retain) MPMediaPickerController *mediaPicker;
@property (nonatomic, retain) MPMusicPlayerController *musicPlayer;

@end
```

1.  首先，我们需要开始添加原生`MediaPicker`到`MediaManager`的实现（`MediaManager.m`）中。首先的方法将是用于显示和隐藏`MediaPicker`的：`showMediaPicker`和`hideMediaPicker`，如下所示：

```jsx
#import "MediaManager.h"
#import "AppDelegate.h"

@implementation MediaManager
RCT_EXPORT_MODULE();

@synthesize bridge = _bridge;
@synthesize musicPlayer;

#pragma mark private-methods

-(void)showMediaPicker {
 if(self.mediaPicker == nil) {
 self.mediaPicker = [[MPMediaPickerController alloc] initWithMediaTypes:MPMediaTypeAnyAudio];

 [self.mediaPicker setDelegate:self];
 [self.mediaPicker setAllowsPickingMultipleItems:NO];
 [self.mediaPicker setShowsCloudItems:NO];
 self.mediaPicker.prompt = @"Select song";
 }

 AppDelegate *delegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];

 [delegate.window.rootViewController presentViewController:self.mediaPicker animated:YES completion:nil];
}

void hideMediaPicker() {
 AppDelegate *delegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
 [delegate.window.rootViewController dismissViewControllerAnimated:YES completion:nil];
}

// Defined on following steps

@end
```

1.  接下来，我们将实现`mediaPicker`需要的两个操作：`didPickMediaItems`用于选择媒体项目，以及`mediaPickerDidCancel`用于取消操作，如下所示：

```jsx
-(void) mediaPicker:(MPMediaPickerController *)mediaPicker didPickMediaItems:(MPMediaItemCollection *)mediaItemCollection {
  MPMediaItem *mediaItem = mediaItemCollection.items[0];
  NSURL *assetURL = [mediaItem valueForProperty:MPMediaItemPropertyAssetURL];

  [self.bridge.eventDispatcher sendAppEventWithName:@"SongPlaying"
                                               body:[mediaItem valueForProperty:MPMediaItemPropertyTitle]];

  if(musicPlayer == nil) {
    musicPlayer = [MPMusicPlayerController systemMusicPlayer];
  }

  [musicPlayer setQueueWithItemCollection:mediaItemCollection];
  [musicPlayer play];

  hideMediaPicker();
}

-(void) mediaPickerDidCancel:(MPMediaPickerController *)mediaPicker {
  hideMediaPicker();
}
```

1.  接下来，我们需要将我们的`MediaManager`暴露给 React Native 桥，并创建一个将被调用以显示`MediaPicker`的方法，如下所示：

```jsx
RCT_EXPORT_MODULE(); 
RCT_EXPORT_METHOD(showSongs) { 
  [self showMediaPicker]; 
} 
```

1.  我们准备继续进行 JavaScript 部分。让我们首先在`App.js`中添加依赖项。我们还需要使用`NativeModules`组件导入我们在*步骤 3*到*步骤 6*中创建的`MediaManager`原生模块，如下所示：

```jsx
import React, { Component } from 'react';
import {
  StyleSheet,
  Text,
  View,
  NativeModules,
  NativeAppEventEmitter
} from 'react-native';
import Button from 'react-native-button';
const MediaManager = NativeModules.MediaManager;
```

1.  让我们定义`App`类和初始`state`。`currentSong`属性将保存当前播放歌曲的曲目信息，如从原生层传递的那样：

```jsx
export default class App extends Component {
  state = {
    currentSong: null
  }

  // Defined on following steps
}
```

1.  当组件挂载时，我们将订阅从原生层发出的`SongPlaying`事件，当歌曲开始播放时。我们将事件监听器保存到本地的`subscription`类变量中，以便在组件卸载时使用`remove`方法清除它，如下所示：

```jsx
  componentWillMount() {
    this.subscription = NativeAppEventEmitter.addListener(
      'SongPlaying',
      this.updateCurrentlyPlaying
    );
  }

  componentWillUnmount = () => {
    this.subscription.remove();
  }
```

1.  我们还需要一种方法来更新`state`上的`currentSong`值，并且需要一种方法来调用我们在*步骤 3*到*步骤 6*中定义的原生`MediaManager`模块上的`showSongs`方法，如下所示：

```jsx
  updateCurrentlyPlaying = (currentSong) => {
    this.setState({ currentSong });
  }

  showSongs() {
    MediaManager.showSongs();
  }
```

1.  `render`方法将由一个`Button`组件组成，用于在按下时执行`showSongs`方法，以及用于显示当前播放歌曲信息的`Text`组件，如下所示：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Button
          containerStyle={styles.buttonContainer}
          style={styles.buttonStyle}
          onPress={this.showSongs}>
            Pick Song
        </Button>
        <Text style={styles.instructions}>Song Playing:</Text>
        <Text style={styles.welcome}>{this.state.currentSong}</Text>
      </View>
    );
  }
```

1.  最后，我们将添加我们的样式来布局和设计应用程序，如下所示：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
  buttonContainer: {
    width: 150,
    padding: 10,
    margin: 5,
    height: 40,
    overflow: 'hidden',
    borderRadius: 4,
    backgroundColor: '#3B5998'
  },
  buttonStyle: {
    fontSize: 16,
    color: '#fff'
  }
});
```

# 它是如何工作的...

在这个教程中，我们介绍了如何在 iOS 中使用`Media Player`，通过将其功能封装在一个本地模块中。媒体播放器框架允许我们访问本机 iPod 库，并使用与本机 iOS 音乐应用相同的功能在设备上播放库中的音频文件。

# 在 Android 上播放音频文件

谷歌喜欢宣称 Android 相对于 iOS 具有处理文件存储的灵活性。Android 设备支持外部 SD 卡，可以存储媒体文件，并不需要像 iOS 那样需要专有的方法来添加多媒体文件。

在这个教程中，我们将使用 Android 的本机`MediaPicker`，它是从一个意图开始的。然后我们将能够选择一首歌并通过我们的应用程序播放它。

# 准备工作

对于这个教程，我们将创建一个名为`AudioPlayer`的 React Native 应用程序。

在这个教程中，我们将使用`react-native-button`库。要安装它，请在项目根目录的终端中运行以下命令：

```jsx
 $ npm install react-native-button --save
```

确保您的 Android 设备或模拟器的`Music/`目录中有音乐文件可用。

# 如何做...

1.  让我们首先使用 Android Studio 打开 Android 项目。在 Android Studio 中，选择“打开现有的 Android Studio 项目”，然后打开项目的`android`目录。

1.  对于这个教程，我们将需要两个新的 Java 类：`MediaManager`和`MediaPackage`。

1.  我们的`MediaManager`将使用意图来显示`mediaPicker`，`MediaPlayer`来播放音乐，以及`MediaMetadataRetriever`来解析音频文件的元数据信息并发送回 JavaScript 层。让我们首先在`MediaManager.java`文件中导入我们需要的所有依赖项，如下所示：

```jsx
import android.app.Activity;
import android.content.Intent;
import android.media.AudioManager;
import android.media.MediaMetadataRetriever;
import android.media.MediaPlayer;
import android.net.Uri;
import android.provider.MediaStore;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
```

1.  `showSongs`，`getName`，`playSong`，`mediaPlayer`，`onActivityResult`，`mediaMetadataRetreiver`和`SongPlaying`应该以代码格式显示。替换为：

```jsx
public class MediaManager extends ReactContextBaseJavaModule implements ActivityEventListener {
  private MediaPlayer mediaPlayer = null;
  private MediaMetadataRetriever mediaMetadataRetriever = null;

  public MediaManager(ReactApplicationContext reactApplicationContext) {
    super(reactApplicationContext);
    reactApplicationContext.addActivityEventListener(this);
  }

  @Override
  public String getName() {
    return "MediaManager";
  }

  @Override
  public void onCatalystInstanceDestroy() {
    super.onCatalystInstanceDestroy();
    mediaPlayer.stop();
    mediaPlayer.release();
    mediaPlayer = null;
  }

  @ReactMethod
  public void showSongs() {
    Activity activity = getCurrentActivity();
    Intent intent = new Intent(Intent.ACTION_PICK, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI);
    activity.startActivityForResult(intent, 10);
  }

  @Override
  public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
    if (data != null) {
      playSong(data.getData());
    }
  }

  @Override
  public void onNewIntent(Intent intent) {
  }

  private void playSong(Uri uri) {
    try {
      if (mediaPlayer != null) {
        mediaPlayer.stop();
        mediaPlayer.reset();
      } else {
        mediaMetadataRetriever = new MediaMetadataRetriever();
        mediaPlayer = new MediaPlayer();
        mediaPlayer.setAudioStreamType(AudioManager.STREAM_MUSIC);
      }

      mediaPlayer.setDataSource(getReactApplicationContext(), uri);

      mediaPlayer.prepare();
      mediaPlayer.start();

      mediaMetadataRetriever.setDataSource(getReactApplicationContext(), uri);
      String artist = mediaMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_ARTIST);
      String songTitle = mediaMetadataRetriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_TITLE);

      WritableMap params = Arguments.createMap();
      params.putString("songPlaying", artist + " - " + songTitle);

      getReactApplicationContext()
        .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
        .emit("SongPlaying", params);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }
}
```

1.  自定义模块还需要添加到`MainApplication.java`文件中的`getPackages`数组中，如下所示：

```jsx
    protected List<ReactPackage> getPackages() {
      return Arrays.<ReactPackage>asList(
          new MainReactPackage(),
 new MediaPackage()
      );
    }
```

1.  正如本章前面的*暴露自定义 Android 模块*教程中所介绍的，我们必须为我们的`MediaManager`自定义模块添加必要的样板，以便将其导出到 React Native 层。有关更详细的解释，请参考该教程。按照以下步骤添加必要的样板：

```jsx
import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MediaPackage implements ReactPackage {
  @Override
  public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
    return Collections.emptyList();
  }

  @Override
  public List<NativeModule> createNativeModules(ReactApplicationContext reactContext) {
    List<NativeModule> modules = new ArrayList<>();

    modules.add(new MediaManager(reactContext));

    return modules;
  }
}
```

1.  Android 应用程序的 JavaScript 层与之前的 iOS 教程中的相同。使用本教程的*步骤 7*到*步骤 12*来完成应用程序的最后部分。


# 第十三章：与原生应用集成

在这一章中，我们将涵盖以下的配方：

+   将 React Native 应用和原生 iOS 应用结合

+   从 iOS 应用到 React Native 的通信

+   从 React Native 到 iOS 应用容器的通信

+   处理外部 iOS 应用的调用

+   将 React Native 应用和原生 Android 应用结合

+   从 Android 应用到 React Native 的通信

+   从 React Native 到 Android 应用容器的通信

+   处理外部 Android 应用的调用

# 介绍

React Native 被引入作为使用 JavaScript 构建原生应用的解决方案，目标是让更多的开发人员能够为多个平台构建真正的原生应用。作为一个团队构建 React Native 应用的结果，JavaScript 开发人员和原生开发人员密切合作是很常见的。

React Native 能够渲染原生 UI 视图的一个优势是它们可以轻松地嵌入到现有的原生应用中。公司已经拥有关键的原生应用对于他们的业务至关重要并不罕见。如果应用程序没有出现问题，可能没有立即需要将整个代码库重写为 React Native。在这种情况下，JavaScript 和原生开发人员都可以利用 React Native 编写的代码，将其集成到现有应用中。

本章将专注于在现有的原生 iOS 和 Android 应用中使用 React Native。我们将涵盖在原生应用中渲染 React Native 应用，如何在 React Native 应用和其原生父应用之间进行通信，以及我们的 React Native 应用如何在用户设备上与其他应用一起调用。

在处理 Android 配方时，建议您在 Android Studio 中启用自动导入设置，或使用*Alt*+*Enter*执行快速修复代码完成类导入。

# 将 React Native 应用和原生 iOS 应用结合

如果您在一家公司工作，或者有一个客户在世界上使用着一个活跃的 iOS 应用，重写它可能并不明智，特别是如果它构建良好，经常被使用，并受到用户的赞扬。如果您只想使用 React Native 构建新功能，React Native 应用可以嵌入并在现有的原生 iOS 应用中渲染。

本教程将介绍如何创建一个空白的 iOS 应用程序，并将其添加到 React Native 应用程序中，以便这两个层可以相互通信。我们将介绍两种呈现 React Native 应用程序的方法：嵌入在应用程序中作为嵌套视图，以及作为全屏实现的另一种方法。本教程讨论的步骤将作为呈现 React Native 应用程序以及原生 iOS 应用程序的基线。

# 准备工作

本教程将引用一个名为`EmbeddedApp`的原生 iOS 应用程序。我们将在本节中介绍如何创建示例 iOS 应用程序。如果您已经有一个打算与 React Native 集成的 iOS 应用程序，可以直接跳转到教程说明。但是，您需要确保已安装`cocoapods`。这个库是 Xcode 项目的包管理器。可以使用以下命令通过 Homebrew 安装它：

```jsx
brew install cocoapods
```

安装了`cocoapods`后，下一步是在 Xcode 中创建一个新的原生 iOS 项目。可以通过打开 Xcode 并选择文件|新建|项目来完成。在随后的窗口中，选择默认的单视图应用程序 iOS 模板开始，并点击下一步。

在新项目的选项屏幕中，确保将产品名称字段设置为`EmbeddedApp`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/86748b32-0ee0-44e1-82c2-bfb91772e34f.png)

# 如何操作...

1.  我们将首先创建一个新的原始 React Native 应用程序，作为我们项目的根。让我们将新项目命名为`EmbedApp`。您可以使用以下命令使用 CLI 创建新的 React Native 应用程序：

```jsx
react-native init EmbedApp
```

1.  通过使用 CLI 创建新应用程序，`ios`和`android`子文件夹将自动为我们创建，其中包含每个平台的原生代码。让我们将我们在“准备工作”部分中创建的原生应用程序移动到`ios`文件夹中，以便它位于`/EmbedApp/ios/EmbeddedApp`。

1.  现在我们已经为应用程序准备好了基本结构，我们需要添加一个 Podfile。这是一个文件，类似于 Web 开发中的`package.json`，用于跟踪项目中使用的所有 cocoapod 依赖项（称为 pods）。Podfile 应始终位于原始 iOS 项目的根目录中，在我们的情况下是`/EmbedApp/ios/EmbeddedApp`。在终端中，`cd`进入此目录并运行`pod init`命令。这将为您生成一个基本的 Podfile。

1.  接下来，在您喜欢的 IDE 中打开 Podfile。我们将向该文件添加应用程序所需的 pods。以下是最终 Podfile 的内容，其中新增的 React Native 依赖项已用粗体标出：

```jsx
target 'EmbeddedApp' do
  # Uncomment the next line if you're using Swift or would like to use dynamic frameworks
  # use_frameworks!

  # Pods for EmbeddedApp

  target 'EmbeddedAppTests' do
    inherit! :search_paths
    # Pods for testing
  end

  target 'EmbeddedAppUITests' do
    inherit! :search_paths
    # Pods for testing
  end

 # Pods that will be used in the app
 pod 'React', :path => '../../node_modules/react-native', :subspecs => [
 'Core',
 'CxxBridge', # Include this for RN >= 0.47
 'DevSupport', # Include this to enable In-App Devmenu if RN >= 0.43
 'RCTText',
 'RCTNetwork',
 'RCTWebSocket', # Needed for debugging
 'RCTAnimation', # Needed for FlatList and animations running on native UI thread
 # Add any other subspecs you want to use in your project
 ]

 # Explicitly include Yoga if you are using RN >= 0.42.0
 pod 'yoga', :path => '../../node_modules/react-native/ReactCommon/yoga'

 # Third party deps podspec link
 pod 'DoubleConversion', :podspec => '../../node_modules/react-native/third-party-podspecs/DoubleConversion.podspec'
 pod 'glog', :podspec => '../../node_modules/react-native/third-party-podspecs/glog.podspec'
 pod 'Folly', :podspec => '../../node_modules/react-native/third-party-podspecs/Folly.podspec'

end
```

请注意，我们正在添加的 React Native 依赖项中列出的每个路径都指向 React Native 项目的`/node_modules`文件夹。如果您的本地项目（在我们的情况下是`EmbeddedApp`）位于不同的位置，则必须相应地更新对`/node_modules`的引用。 

1.  有了 Podfile，安装 pod 本身就像在终端中运行`pod install`命令一样容易，我们在创建 Podfile 的同一目录中运行。

1.  接下来，让我们回到项目的根目录`/EmbedApp`中的 React Native 应用程序。我们将首先删除`index.js`中生成的代码，并用我们自己的简单的 React Native 应用程序替换它。在文件底部，我们将在`AppRegistry`组件上使用`registerComponent`方法将`EmbedApp`注册为 React Native 应用程序的根组件。这将是一个非常简单的应用程序，只是渲染文本`Hello in React Native`，以便在后续步骤中可以与本地层区分开来：

```jsx
import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  View,
  Text
} from 'react-native';

class EmbedApp extends Component {
  render() {
    return (
      <View style={styles.container}>
        <Text>Hello in React Native</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  }
});

AppRegistry.registerComponent('EmbedApp', () => EmbedApp);
```

1.  现在我们有了一个 React Native 应用程序，我们可以转到本地代码。当我们在*步骤 3*中初始化 cocoapods 时，它还生成了一个新的`.xcworkspace`文件。确保在 Xcode 中关闭`EmbeddedApp`项目，然后使用`EmbeddedApp.xcworkspace`文件重新在 Xcode 中打开它。

1.  在 Xcode 中，让我们打开`Main.storyboard`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/8137ae79-365d-4021-92fb-a3bbea5710bb.png)

1.  在 Storyboard 中，我们需要添加两个按钮：一个标记为 Open React Native App，另一个标记为 Open React Native App（Embedded）。我们还需要在两个按钮下方添加一个新的容器视图。最终的 Storyboard 应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/a5422254-5435-4d34-b043-6a2d199e9c7b.png)

1.  接下来，我们需要一个新的 Cocoa Touch 类。这可以通过菜单选择`File | New | File`来创建。我们将类命名为`EmbeddedViewController`，并将其分配为`UIViewController`的子类：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/0a544b69-116a-491e-baa8-7f3c3e89db2c.png)

1.  让我们回到`Main.storyboard`。在通过上一步添加类创建的新场景（第二个 View Controller 场景）中，选择 View Controller 子项。确保身份检查器在右侧面板中是打开的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/25acdbd3-b7a1-4297-8988-fdcfb99b9742.png)

选择 View Controller 后，将`Class`值更改为我们新创建的类`EmbeddedViewController`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/b1431a9d-3d22-43cb-90ac-a676db65613a.png)

1.  接下来，在顶部 View Controller Scene 中，选择 Embed segue 对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/83a215de-c779-4dc6-892d-c75beede2ef1.png)

1.  选择 segue 后，从右侧面板中选择属性检查器，并将标识符字段更新为 embed 值。我们将使用此标识符将 React Native 层嵌入到原生应用程序中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/00ca967c-3df7-4d4c-8e6b-45e58d03b7ab.png)

1.  我们准备构建`ViewController`的实现。打开`ViewController.m`文件。我们将从导入开始：

```jsx
#import "ViewController.h"
#import "EmbeddedViewController.h"
#import <React/RCTRootView.h>
```

1.  在导入下面，我们可以添加一个接口定义，指向我们在*步骤 10*中创建的`EmbeddedViewController`：

```jsx
@interface ViewController () {
 EmbeddedViewController *embeddedViewController;
}

@end
```

1.  接下来是`@interface`，我们将向`@implementation`添加我们需要的方法。第一个方法`openRNAppButtonPressed`将连接到我们在故事板中创建的第一个按钮，标有“打开 React Native 应用程序”。同样，`openRNAppEmbeddedButtonPressed`方法将连接到第二个按钮“打开 React Native 应用程序（嵌入式）”。

您可能会注意到，这两种方法几乎是相同的，第二种方法引用了`embeddedViewController`，与我们在第 10 步中创建的`EmbeddedViewController`类相同（`[embeddedViewController setView:rootView];`）。这两种方法都使用`jsCodeLocation`定义了值为`http://localhost:8081/index.bundle?platform=ios`的 URL，这是 React Native 应用程序将被提供的 URL。另外，请注意，这两种方法中的`moduleName`属性都设置为`EmbedApp`，这是 React Native 应用程序的导出名称，我们在*步骤 6*中定义了它：

```jsx
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)openRNAppButtonPressed:(id)sender {
 NSURL *jsCodeLocation = [NSURL
 URLWithString:@"http://localhost:8081/index.bundle?platform=ios"];
 RCTRootView *rootView =
 [[RCTRootView alloc] initWithBundleURL : jsCodeLocation
 moduleName : @"EmbedApp"
 initialProperties : nil
 launchOptions : nil];

 UIViewController *vc = [[UIViewController alloc] init];
 vc.view = rootView;
 [self presentViewController:vc animated:YES completion:nil];
}
- (IBAction)openRNAppEmbeddedButtonPressed:(id)sender {
 NSURL *jsCodeLocation = [NSURL
 URLWithString:@"http://localhost:8081/index.bundle?platform=ios"];
 RCTRootView *rootView =
 [[RCTRootView alloc] initWithBundleURL : jsCodeLocation
 moduleName : @"EmbedApp"
 initialProperties : nil
 launchOptions : nil];

 [embeddedViewController setView:rootView];
}

// Defined in next step

@end
```

1.  我们还需要定义`prepareForSegue`方法。在这里，您可以看到`segue.identifier isEqualToString:@"embed"`，这是指我们在*步骤 13*中给 segue 的嵌入标识符：

```jsx
// Defined in previous steps - (void) prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
 if([segue.identifier isEqualToString:@"embed"]) {
 embeddedViewController = segue.destinationViewController;
 }
}

@end
```

1.  在我们的`ViewController`实现就位后，现在我们需要将按钮操作连接到按钮本身。让我们返回到`Main.storyboard`。*Ctrl +*单击第一个按钮以获取可分配给按钮的操作菜单，通过从 Touch Up Inside 返回到故事板，将按钮映射到我们在*步骤 15*中定义的`openRNAppButtonPressed`方法。对于第二个按钮，重复这些步骤，将其链接到`openRNAppEmbeddedButtonPressed`方法：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7d82272a-9878-4c24-900c-86db62b70e71.png)

1.  为了使 React Native 层能够与原生层通信，我们还需要添加一个安全异常，这将允许我们的代码与`localhost`通信。右键单击`Info.plist`文件，然后选择打开为|源代码。在基本`<dict>`标签内，添加以下条目：

```jsx
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSExceptionDomains</key>
  <dict>
    <key>localhost</key>
    <dict>
      <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
      <true/>
    </dict>
  </dict>
</dict>
```

1.  我们的应用程序完成了！从`/EmbedApp`根目录，使用以下命令通过 CLI 启动 React Native 应用程序：

```jsx
react-native start
```

1.  随着 React Native 应用程序的运行，让我们也从 Xcode 运行原生应用程序`EmbeddedApp`。现在，按下打开 React Native 应用程序按钮应该会全屏打开我们在*步骤 6*中创建的 React Native 应用程序，并且在按下打开 React Native 应用程序（嵌入式）按钮时，相同的 React Native 应用程序应该在我们在*步骤 9*中创建的容器视图中打开。

# 工作原理...

在这个教程中，我们介绍了通过两种不同的方法在原生 iOS 应用程序中渲染 React Native 应用程序。第一种方法是用 React Native 应用程序替换应用程序的主`UIViewController`实例，在原生代码中称为`RCTRootView`。这是在`openRNAppButtonPressed`方法中完成的。第二种方法稍微复杂一些，是将 React Native 应用程序与原生应用程序内联渲染。这是通过创建一个容器视图来实现的，该容器视图链接到不同的`UIViewController`实例。在这种情况下，我们用我们的`RCTRootView`实例替换了`embedViewController`的内容。这就是`openRNAppEmbeddedButtonPressed`方法触发时发生的事情。

# 另见

为了更好地理解 cocoapods 在 Xcode/React Native 开发中的作用，我建议观看 Google 的*Route 85 Show*在 YouTube 上涵盖该主题的视频。视频可以在[`www.youtube.com/watch?v=iEAjvNRdZa0`](https://www.youtube.com/watch?v=iEAjvNRdZa0)找到。

# 从 iOS 应用程序到 React Native 的通信

在上一个教程中，我们学习了如何将 React Native 应用程序渲染为较大的原生 iOS 应用程序的一部分。除非您正在构建一个华丽的应用程序容器或门户，否则您可能需要在原生层和 React Native 层之间进行通信。这将是接下来两个教程的主题，每个教程都涉及通信的一个方向。

在这个示例中，我们将介绍从本地层到 React Native 层的通信，通过在 iOS 应用程序中使用`UITextField`将数据发送到我们嵌入的 React Native 应用程序。

# 准备工作

由于这个示例需要一个嵌套的 React Native 应用程序的本地应用程序，我们将从上一个示例的结尾开始，有效地接着上次离开的地方。这将帮助您了解基本的跨层通信如何工作，以便您可以在自己的本地应用程序中使用相同的原则，这可能已经存在并具有复杂的功能。因此，跟随这个示例的最简单方法是使用上一个示例的终点作为起点。

# 如何做...

1.  让我们从更新本地层的`ViewController.m`实现文件开始。确保通过上一个示例中项目中`/ios/EmbeddApp`目录中放置的`EmbeddedApp`的`.xcworkspace`文件在 Xcode 中打开项目。我们将从导入开始：

```jsx
#import "ViewController.h"
#import "EmbeddedViewController.h"
#import <React/RCTRootView.h>
#import <React/RCTBridge.h>
#import <React/RCTEventDispatcher.h>
```

1.  下一步是通过`ViewController`接口添加对 React Native 桥的引用，有效地将本地控制器与 React Native 代码链接起来：

```jsx
@interface ViewController () <RCTBridgeDelegate> {
    EmbeddedViewController *embeddedViewController;
    RCTBridge *_bridge;
    BOOL isRNRunning;
}
```

1.  我们还需要一个`@property`引用`userNameField`，我们将在后面的步骤中将其连接到`UITextField`：

```jsx
@property (weak, nonatomic) IBOutlet UITextField *userNameField;

@end
```

1.  在这个参考下面，我们将开始定义类方法。我们将从`sourceURLForBridge`方法开始，该方法定义了 React Native 应用程序的服务位置。在我们的情况下，应用程序的 URL 应该是`http://localhost:8081/index.bundle?platform=ios`，这指向了 React Native 应用程序的`index.js`文件，一旦它使用`react-native start`命令运行：

```jsx
- (NSURL *)sourceURLForBridge:(RCTBridge *)bridge {
    NSURL *jsCodeLocation = [NSURL
                             URLWithString:@"http://localhost:8081/index.bundle?platform=ios"];
    return jsCodeLocation;
}
```

1.  我们将保留`viewDidLoad`和`didReveiveMemoryWarning`方法不变：

```jsx
- (void)viewDidLoad {
    [super viewDidLoad];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
```

1.  接下来，我们需要更新`openRNAppEmbeddedButtonPressed`方法。注意`moduleName`属性设置为`FromNativeToRN`。这是我们导出 React Native 应用程序时给出的名称的引用，我们将在后面的步骤中定义。这次，我们还定义了一个`userName`属性，用于向 React Native 层传递数据：

```jsx
- (IBAction)openRNAppEmbeddedButtonPressed:(id)sender {
    NSString *userName = _userNameField.text;
    NSDictionary *props = @{@"userName" : userName};

    if(_bridge == nil) {
        _bridge = [[RCTBridge alloc] initWithDelegate:self 
        launchOptions:nil];
    }

    RCTRootView *rootView =
    [[RCTRootView alloc] initWithBridge :_bridge
                             moduleName : @"FromNativeToRN"
                      initialProperties : props];

    isRNRunning = true;
    [embeddedViewController setView:rootView];
}
```

1.  我们还需要一个`onUserNameChanged`方法。这是将数据实际发送到 React Native 层的方法。我们在这里定义的事件名称是`UserNameChanged`，我们将在后面的步骤中在 React Native 层中引用它。这也将传递当前文本输入中的文本，该文本将被命名为`userNameField`：

```jsx
- (IBAction)onUserNameChanged:(id)sender {
    if(isRNRunning == YES && _userNameField.text.length > 3) {
        [_bridge.eventDispatcher sendAppEventWithName:@"UserNameChanged" body:@{@"userName" : _userNameField.text}];
    }
}
```

1.  我们还需要`prepareForSegue`来配置`embeddedViewController`，就在它显示之前：

```jsx
- (void) prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if([segue.identifier isEqualToString:@"embed"]) {
        embeddedViewController = segue.destinationViewController;
    }
}
@end
```

1.  回到`Main.storyboard`，让我们添加一个文本字段，以及一个定义输入用途的标签。您还可以将输入命名为 User Name Field，以便在视图控制器场景中更容易识别：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c44f2cfe-f832-489c-8dcf-543f805b85c6.png)

1.  接下来，我们需要为`User Name Field`文本输入的文本更改事件和引用出口进行连接，以便视图控制器知道如何引用它。这两者都可以通过连接检查器完成，连接检查器可以通过右侧面板顶部的最后一个按钮（图标是一个右指向箭头在一个圆圈中）访问。选择文本输入后，从`Editing Changed`拖动到视图控制器（通过主故事板表示），并选择我们在*步骤 7*中定义的`onUserNameChange`方法。然后，通过将项目拖动到`ViewController`来创建以下连接。类似地，通过从新引用出口拖动到视图控制器，这次选择我们在*步骤 7*中定位的 userNameField 值，添加一个新的引用出口。您的连接检查器设置现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/e423f6dc-291d-448b-aef0-95862640aa3a.png)

1.  我们现在已经完成了原生应用程序中所需的步骤。让我们继续进行 React Native 层。回到`index.js`文件，我们将从导入开始。请注意，我们现在包括了`NativeAppEventEmitter`。

1.  将以下函数放在类定义内部：

```jsx
import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  View,
  Text,
  NativeAppEventEmitter
} from 'react-native';
```

1.  我们将应用程序命名为`FromNativeToRN`，以匹配我们在*步骤 6*中定义的原生层中的模块名称，使用`AppRegistry.registerComponent`来注册具有相同名称的应用程序。我们还将保留基本样式。

```jsx
class FromNativeToRN extends Component {
 // Defined in following steps
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  }
});

AppRegistry.registerComponent('FromNativeToRN', () => FromNativeToRN);
```

1.  我们将设置一个初始的`state`对象，其中包含一个`userName`字符串属性，用于存储和显示从原生层接收到的文本：

```jsx
class FromNativeToRN extends Component {
 state = {
 userName: ''
 }

 // Defined in following steps
}
```

1.  传递到 React Native 层的`userName`值将作为属性接收。当组件挂载时，我们希望做两件事：如果原生层已经定义了`userName`状态属性，则设置`userName`状态属性，并将事件监听器连接到在原生层中更新`userName`时更新`userName`。回想一下，在*步骤 7*中，我们定义了事件的名称为`UserNameChanged`，这就是我们要监听的事件。当接收到事件时，我们将更新`state.userName`为事件传递的文本：

```jsx
  componentWillMount() {
    this.setState({
      userName : this.props.userName
    });

    NativeAppEventEmitter.addListener('UserNameChanged', (body) => {
        this.setState({userName : body.userName});
    });
  }
```

1.  最后，我们可以添加`render`函数，它简单地渲染`state.userName`中存储的值：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Text>Hello {this.state.userName}</Text>
      </View>
    );
  }
```

1.  是时候运行我们的应用程序了！首先，在项目的根目录中，我们可以使用以下命令通过 React Native CLI 启动 React Native 应用程序：

```jsx
react-native start
```

接着我们通过 Xcode 在模拟器中运行原生应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/f917a790-b142-4636-b6e0-b547fae1b21f.png)

# 从 React Native 通信到 iOS 应用程序容器

上一个示例涵盖了在原生到 React Native 方向上的层间通信。在这个示例中，我们将涵盖在相反方向上的通信：从 React Native 到原生。这次，我们将在 React Native 应用程序中渲染一个用户输入元素，并设置从 React Native 到在原生应用程序中渲染的 UI 组件的单向绑定。

# 准备工作

就像上一个示例一样，这个示例取决于本章第一个应用程序的最终产品，在*将 React Native 应用程序和原生 iOS 应用程序组合*示例中。要跟着做，请确保你已经完成了那个示例。

# 如何做...

1.  让我们从原生层开始。通过`.xcworkspace`文件在 Xcode 中打开`EmbeddedApp`原生应用程序。我们首先要在`ViewController.m`中添加导入：

```jsx
#import "ViewController.h"
#import "EmbeddedViewController.h"
#import <React/RCTRootView.h>
#import <React/RCTBridge.h>
#import <React/RCTEventDispatcher.h>
```

1.  与上一个示例一样，我们需要通过`ViewController`接口添加对 React Native 桥的引用，提供原生控制器和 React Native 代码之间的桥接：

```jsx
@interface ViewController () <RCTBridgeDelegate> {
    EmbeddedViewController *embeddedViewController;
    RCTBridge *_bridge;
    BOOL isRNRunning;
}
```

1.  我们还需要一个`@property`引用`userNameField`，我们将在后面的步骤中将其连接到`UITextField`：

```jsx
@property (weak, nonatomic) IBOutlet UITextField *userNameField;

@end
```

1.  让我们继续定义`@implementation`。同样，我们必须提供 React Native 应用程序的源，它将从`localhost`提供：

```jsx
@implementation ViewController

- (NSURL *)sourceURLForBridge:(RCTBridge *)bridge {
    NSURL *jsCodeLocation = [NSURL
                             URLWithString:@"http://localhost:8081/index.bundle?platform=ios"];
    return jsCodeLocation;
}
```

1.  使用`viewDidLoad`方法，我们还可以将控制器连接到在容器视图中打开 React Native 应用程序的方法(`openRNAppEmbeddedButtonPressed`)。我们将保持`didReveiveMemoryWarning`方法不变：

```jsx
- (void)viewDidLoad {
    [super viewDidLoad];
 [self openRNAppEmbeddedButtonPressed:nil];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}
```

1.  与上一个配方一样，我们需要更新`openRNAppEmbeddedButtonPressed`方法。这次，`moduleName`属性设置为`FromRNToNative`，以反映我们在导出时将给 React Native 应用程序的名称，如后面的步骤中定义的。我们还定义了一个`userName`属性，用于向 React Native 层传递数据：

```jsx
- (IBAction)openRNAppEmbeddedButtonPressed:(id)sender {
    if(_bridge == nil) {
        _bridge = [[RCTBridge alloc] initWithDelegate:self launchOptions:nil];
    }

    RCTRootView *rootView =
    [[RCTRootView alloc] initWithBridge :_bridge
                      moduleName : @"FromRNToNative"
                      initialProperties : nil];

    isRNRunning = true;
    [embeddedViewController setView:rootView];
}
```

1.  我们在这个文件中还需要的最后两个方法是`prepareForSegue`，用于在显示之前配置`embeddedViewController`，以及一个`updateUserNameField`方法，当我们在本地层的文本输入中使用用户的新文本更新时将被触发：

```jsx
- (void) prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if([segue.identifier isEqualToString:@"embed"]) {
        embeddedViewController = segue.destinationViewController;
    }
}

-(void) updateUserNameField:(NSString *)userName {
    [_userNameField setText:userName];
}
@end
```

1.  与上一个配方不同，我们还需要更新`ViewController`头文件（`ViewController.h`）。在这里引用的方法`updateUserNameField`将在我们定义`ViewController`实现时使用：

```jsx
#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
- (void) updateUserNameField:(NSString *)userName;

@end
```

1.  接下来，我们需要创建一个新的`UserNameManager`本地模块。首先，创建一个名为`UserNameManager`的 Cocoa Touch 类。创建后，让我们打开实现文件（`UserNameManger.m`）并添加我们的导入：

```jsx
#import "UserNameManager.h"
#import "AppDelegate.h"
#import "ViewController.h"
#import <React/RCTBridgeModule.h>
```

要深入了解创建本地模块，请参阅第十一章中的*公开自定义 iOS 模块*配方。

1.  接下来，我们将定义类实现。这里的主要要点是`setUserName`方法，这是我们从本地层导出供 React Native 应用程序使用的方法。我们将在 React Native 应用程序中使用此方法来更新本地文本字段中的值。然而，由于我们正在更新本地 UI 组件，操作必须在主线程上执行。这就是`methodQueue`函数的目的，它指示模块在主线程上执行：

```jsx
@implementation UserNameManager
RCT_EXPORT_MODULE();

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_METHOD(setUserName: (NSString *)userName) {
    AppDelegate *delegate = (AppDelegate *)[[UIApplication sharedApplication] delegate];
    ViewController *controller = (ViewController *)delegate.window.rootViewController;

    [controller updateUserNameField:userName];
}
@end
```

1.  我们还需要更新`UserNameMangager.h`头文件以使用 React Native 桥接模块：

```jsx
#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>

@interface UserNameManager : NSObject <RCTBridgeModule>

@end
```

1.  与上一个配方一样，我们需要为用户名输入添加一个文本字段和标签：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/5e24e43a-1913-49b0-b7c5-0c78dceebc4e.png)

1.  我们还需要从上一组中创建的文本字段到我们的`userNameField`属性添加一个引用输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/0d70c124-06e7-4132-b78a-985abbe8592c.png)如果您需要更多关于如何创建引用输出的信息，请查看上一个配方的*步骤 10*。

1.  我们已经完成了这个项目的本地部分，现在让我们转向我们的 React Native 代码。让我们打开项目根目录下的`index.js`文件。我们将从导入开始：

```jsx
import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  View,
  Text,
  TextInput,
  NativeModules
} from 'react-native';
```

1.  让我们使用名称`FromRNToNative`来定义应用程序，以便与我们在原生代码中*步骤 6*中声明的`moduleName`对齐，并使用相同名称注册组件。`state`对象只需要一个`userName`字符串属性来保存保存到`TextInput`组件的值，我们将在组件的`render`函数中添加它：

```jsx
class FromRNToNative extends Component {
  state = {
    userName: ''
  }

  // Defined on next step
}

AppRegistry.registerComponent('FromRNToNative', () => FromRNToNative);
```

1.  应用程序的`render`函数使用`TextInput`组件从用户那里获取输入，然后通过 React Native 桥将其发送到原生应用程序。它通过在`TextInput`的值改变时调用`onUserNameChange`方法来实现这一点：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Text>Enter User Name</Text>
        <TextInput
          style={styles.userNameField}
          onChangeText={this.onUserNameChange}
          value={this.state.userName}
        />
      </View>
    );
  }
```

1.  我们需要做的最后一件事是定义`onUserNameChange`方法，该方法由我们在上一步中定义的`TextInput`组件的`onChangeText`属性使用。此方法将`state.userName`更新为文本输入中的值，并通过 React Native 中的`NativeModules`组件将该值发送到原生代码。`NativeModules`具有我们在原生层*步骤 9*中定义为 Cocoa Touch 类的`UserNameManager`类。我们在*步骤 10*中调用了我们在类中定义的`setUserName`方法，将该值传递到原生层，在那里它将显示在我们在*步骤 12*中创建的文本字段中：

```jsx
  onUserNameChange = (userName) => {
    this.setState({userName});
    NativeModules.UserNameManager.setUserName(userName);
  }
```

1.  应用程序完成了！返回到项目的根目录，使用以下命令启动 React Native 应用程序：

```jsx
react-native start
```

然后，启动 React Native 应用程序后，从 Xcode 运行原生`EmbeddedApp`项目。现在，React Native 应用程序中的输入应该将其值传递给父原生应用程序中的输入：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/02a70ade-cb5a-4dd8-bd2e-13ea02e8a899.png)

# 它是如何工作的...

为了从我们的 React Native 应用程序通信到父原生应用程序，我们创建了一个名为`UserNameManager`的原生模块，其中包含一个`setUserName`方法，我们从原生层导出，并在 React Native 应用程序中使用，在其`onUserNameChange`方法中。这是从 React Native 到原生通信的推荐方式。

# 处理被外部 iOS 应用程序调用

原生应用程序之间通过链接进行通信也是一种常见行为，并且通常提示用户使用短语“在...中打开”，以及更好地处理操作的应用程序的名称。这是通过使用特定于您的应用程序的协议来完成的。就像任何网站链接都有`http://`或`https://`的协议一样，我们也可以创建一个自定义协议，允许任何其他应用程序打开并向我们的应用程序发送数据。

在这个教程中，我们将创建一个名为`invoked://`的自定义协议。通过使用`invoked://`协议，任何其他应用程序都可以使用它来运行我们的应用程序并向其传递数据。

# 准备工作

对于这个教程，我们将从一个新的原生 React Native 应用程序开始。让我们将其命名为`InvokeFromNative`。

# 如何操作...

1.  首先，让我们在 Xcode 中打开新项目的本地层。我们需要做的第一件事是调整项目的构建设置。这可以通过在左侧面板中选择根项目，然后选择中间面板顶部的构建设置选项卡来完成：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d0e90cd7-0f3c-4270-85a1-05792d34f948.png)

1.  我们需要向`Header Search Paths`字段添加一个新条目：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/3e1e1fb4-601b-4bbf-94f1-554e18e332da.png)

为了使项目知道 React Native JavaScript 的位置，它需要`$(SRCROOT)/../node_modules/react-native/Libraries`的值。让我们将其添加为递归条目：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/068fa616-dda9-4c8c-b4ce-d540f1217b06.png)

1.  我们还需要注册我们的自定义协议，这将被其他应用程序使用。打开`Info.plist`文件作为源代码（右键单击然后选择`Open As | Source Code`）。让我们向文件添加一个条目，以注册我们的应用程序在`invoked://`协议下：

```jsx
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>invoked</string>
    </array>
  </dict>
</array>
```

1.  接下来，我们需要将`RCTLinkingManager`添加到`AppDelegate`实现中，它位于`AppDelegate.m`中，并将其连接到我们的应用程序：

```jsx
#import "AppDelegate.h"

#import <React/RCTBundleURLProvider.h>
#import <React/RCTRootView.h>
#import <React/RCTLinkingManager.h>

@implementation AppDelegate

// The rest of the AppDelegate implementation

- (BOOL)application:(UIApplication *)application
 openURL:(NSURL *)url
 options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options
{
 return [RCTLinkingManager application:application openURL:url options:options];
}

@end
```

1.  现在，让我们继续进行 React Native 层。在`index.js`中，我们将添加我们的导入，其中包括`Linking`组件：

```jsx
import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  Text,
  View,
  Linking
} from 'react-native';
```

1.  接下来，我们将创建类定义并将组件注册为`InvokeFromNative`。我们还将定义一个初始的`state`对象，其中包含一个`status`字符串属性，其值为`'App Running'`：

```jsx
class InvokeFromNative extends Component {
 state = {
 status: 'App Running'
 }

 // Defined on following steps
}

AppRegistry.registerComponent('InvokeFromNative', () => InvokeFromNative);
```

1.  现在，我们将使用挂载和卸载生命周期钩子来`add`/`remove`对`invoked://`协议的事件监听器。当事件被听到时，将触发下一步中定义的`onAppInvoked`方法：

```jsx
  componentWillMount() {
    Linking.addEventListener('url', this.onAppInvoked);
  }

  componentWillUnmount() {
    Linking.removeEventListener('url', this.onAppInvoked);
  }
```

1.  `onAppInvoked`函数简单地接受事件监听器的事件并更新`state.status`以反映发生了调用，通过`event.url`显示协议：

```jsx
  onAppInvoked = (event) => {
    this.setState({
      status: `App Invoked by ${ event.url }`
    });
  }
```

1.  在这个教程中，`render`方法的唯一真正目的是在状态上呈现`status`属性：

```jsx
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.instructions}>
          App Status:
        </Text>
        <Text style={styles.welcome}>
          {this.state.status}
        </Text>
      </View>
    );
  }
```

1.  我们还将添加一些基本样式来居中和调整文本的大小：

```jsx
const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
});
```

1.  我们的应用程序已经完成。一旦您开始运行应用程序，您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/d62bd623-bd8b-495d-a7c1-39a95eedbec4.png)

1.  应用程序运行时，我们可以模拟另一个应用程序打开我们的 React Native 应用程序的操作，使用`invoked://`协议可以通过以下终端命令完成：

```jsx
 xcrun simctl openurl booted invoked://
```

一旦调用，应用程序应更新以反映调用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c8a2362a-570a-4888-a103-c418c6f76378.png)

# 工作原理…

在这个配方中，我们介绍了如何注册自定义协议（或 URL 模式），以允许我们的应用程序被其他应用程序调用。这个配方的目的是尽可能简单地保持我们的示例，因此我们没有构建通过链接机制传递给应用程序的数据处理。但是，如果您的应用程序需要，完全可以这样做。要深入了解`Linking`组件，请查看官方文档[`facebook.github.io/react-native/docs/linking`](https://facebook.github.io/react-native/docs/linking)。

# 结合 React Native 应用程序和本机 Android 应用程序

由于 Android 平台仍然在智能手机市场占据主导地位，您可能希望为 Android 和 iOS 构建应用程序。React Native 开发的一个重大优势是使这一过程更加容易。但是，当您想要使用 React Native 为已经发布的 Android 应用程序编写新功能时会发生什么？幸运的是，React Native 也可以实现这一点。

本文将介绍在现有 Android 应用程序中嵌入 React Native 应用程序的过程，方法是在容器视图中显示 React Native 应用程序。这些步骤将作为后续配方的基线，这些配方涉及与 React Native 应用程序的通信。

# 准备工作

在本节中，我们将使用 Android Studio 创建一个名为`EmbedApp`的示例 Android 应用程序。如果您有一个基本的 Android 应用程序要使用，可以跳过这些步骤并继续进行实际实现：

1.  打开 Android Studio 并创建一个新项目（文件|新项目）

1.  将应用程序名称设置为`EmbeddedApp`并填写您的公司域。按“下一步”

1.  保留“空活动”作为默认选择，然后按“下一步”

1.  将 Activity 属性保留为默认值，然后按“完成”

# 如何做…

1.  此时，我们的应用程序没有与 React Native 相关的引用，因此我们将从安装它开始。在应用程序的根文件夹中，在终端中使用`yarn`命令安装 React Native：

```jsx
yarn add react-native
```

或者，您可以使用`npm`：

```jsx
 npm install react-native --save
```

1.  我们还需要一个用于启动 React Native 应用程序的 Node.js 脚本。让我们打开`package.json`并将以下属性添加为`scripts`对象的成员：

```jsx
 "start": "node node_modules/react-native/local-cli/cli.js start"
```

1.  对于这个示例，我们只需要一个非常简单的 React Native 应用程序。让我们创建一个带有以下样板应用程序的`index.android.js`文件：

```jsx
import React, { Component } from 'react';
import { AppRegistry, StyleSheet, View, Text } from 'react-native';

export default class EmbedApp extends Component {
  render() {
    return (<View style={styles.container}>
      <Text>Hello in React Native</Text>
    </View>);
  }
}

const styles = StyleSheet.create({
 container: {
   flex: 1,
   justifyContent: 'center',
   alignItems: 'center', backgroundColor: '#F5FCFF'
  }
});

AppRegistry.registerComponent('EmbedApp', () => EmbedApp);
```

将此文件命名为`index.android.js`表示对 React Native 来说，此代码仅适用于此应用程序的 Android 版本。这是官方文档推荐的做法，当平台特定的代码更复杂时。您可以在[`facebook.github.io/react-native/docs/platform-specific-code#platform-specific-extensions`](https://facebook.github.io/react-native/docs/platform-specific-code#platform-specific-extensions)了解更多信息。

1.  让我们返回到 Android Studio 并打开`build.gradle`文件（来自`app`模块），并将以下内容添加到`dependencies`中：

```jsx
dependencies {
    implementation fileTree(dir: "libs", include: ["*.jar"]) 
    implementation "com.android.support:appcompat-v7:27.1.1"
    implementation "com.facebook.react:react-native:+" // From node_modules
}   
```

1.  我们还需要一个对本地 React Native maven 目录的引用。打开另一个`build.gradle`文件，并将以下行添加到`allprojects.repositories`对象中：

```jsx
allprojects {
  repositories {
    mavenLocal()
      maven {
        url "$rootDir/../node_modules/react-native/android"
      }
    google()
    jcenter()
  }
}
```

1.  接下来，让我们更新应用程序的权限以使用互联网和系统警报窗口。我们将打开`AndroidManifest.xml`并将以下权限添加到`<manifest>`节点：

```jsx
<?xml version="1.0" encoding="utf-8"?>
 <manifest 
    package="com.warlyware.embeddedapp">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>

    <application
        android:name=".EmbedApp" 
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

 </manifest>
```

1.  我们准备更新`MainApplication` Java 类。这里的`getUseDeveloperSupport`方法将启用开发菜单。`getPackages`方法是应用程序使用的包的列表，只包括`MainReactPackage()`，因为我们只使用主要的 React 包。`getJSMainModuleName`方法返回`index.android`字符串，它指的是 React Native 层中的`index.android.js`文件：

```jsx
import android.app.Application;

import com.facebook.react.ReactApplication;
import com.facebook.react.ReactNativeHost;
import com.facebook.react.ReactPackage;
import com.facebook.react.shell.MainReactPackage;

import java.util.Arrays;
import java.util.List;

public class MainApplication extends Application implements ReactApplication {
  private final ReactNativeHost mReactNativeHost = new ReactNativeHost(this) {
    @Override
    public boolean getUseDeveloperSupport() {
      return BuildConfig.DEBUG;
    }

    @Override
    protected List<ReactPackage> getPackages() {
      return Arrays.<ReactPackage>asList(
        new MainReactPackage()
      );
    }
  };

  @Override
  public ReactNativeHost getReactNativeHost() {
    return mReactNativeHost;
  }
  @Override
  protected String getJSMainModuleName() {
    return "index.android";
  }
}
```

1.  接下来，让我们创建另一个名为`ReactFragment`的新 Java 类。这个类需要三个方法：`OnAttach`在片段附加到主活动时调用，`OnCreateView`实例化片段的视图，`OnActivityCreated`在活动被创建时调用：

```jsx
import android.app.Fragment;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.ViewGroup;

import com.facebook.react.ReactInstanceManager;
import com.facebook.react.ReactRootView;

public abstract class ReactFragment extends Fragment {
  private ReactRootView mReactRootView;
  private ReactInstanceManager mReactInstanceManager;

  // This method returns the name of our top-level component to show
  public abstract String getMainComponentName();

  @Override
  public void onAttach(Context context) {
    super.onAttach(context);
    mReactRootView = new ReactRootView(context);
    mReactInstanceManager =
      ((EmbedApp) getActivity().getApplication())
        .getReactNativeHost()
        .getReactInstanceManager();
  }

  @Override
  public ReactRootView onCreateView(LayoutInflater inflater, ViewGroup group, Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    return mReactRootView;
  }

  @Override
  public void onActivityCreated(Bundle savedInstanceState) {
    super.onActivityCreated(savedInstanceState);
    mReactRootView.startReactApplication(
      mReactInstanceManager,
      getMainComponentName(),
      getArguments()
    );
  }
}
```

1.  最后，创建一个名为`EmbedFragment`的 Java 类，它将扩展`ReactFragment`：

```jsx
import android.os.Bundle;

public class EmbedFragment extends ReactFragment {
  @Override
  public String getMainComponentName() {
    return "EmbedApp";
  }
}
```

1.  让我们打开`MainActivity.java`并在类定义中添加`implements DefaultHardwareBackBtnHandler`以处理硬件返回按钮事件。您可以在此处查看此 React Native 类的带注释源代码：[`github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/modules/core/DefaultHardwareBackBtnHandler.java`](https://github.com/facebook/react-native/blob/master/ReactAndroid/src/main/java/com/facebook/react/modules/core/DefaultHardwareBackBtnHandler.java)。

1.  我们还将向类中添加一些方法。`onCreate`方法将把内容视图设置为主活动，并添加一个 FAB 按钮，当点击时，将实例化我们在*步骤 10*中定义的`EmbedFragment`的新实例。`EmbedFragment`的这个实例由片段管理器用于将 React Native 应用添加到视图中。其余方法处理设备系统按钮被按下时发生的事件（如返回、暂停和恢复按钮）：

```jsx
import android.app.Fragment;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.KeyEvent;
import android.view.View;

import com.facebook.react.ReactInstanceManager;
import com.facebook.react.modules.core.DefaultHardwareBackBtnHandler;

public class MainActivity extends AppCompatActivity implements DefaultHardwareBackBtnHandler {
  private ReactInstanceManager mReactInstanceManager;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
    setSupportActionBar(toolbar);

    FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
    fab.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View view) {
        Fragment viewFragment = new EmbedFragment();
        getFragmentManager().beginTransaction().add(R.id.reactnativeembed, viewFragment).commit(); }
    });

    mReactInstanceManager = ((EmbedApp) getApplication()).getReactNativeHost().getReactInstanceManager();
  }

  @Override
  public void invokeDefaultOnBackPressed() {
    super.onBackPressed();
  }

  @Override
  protected void onPause() {
    super.onPause();

    if (mReactInstanceManager != null) {
      mReactInstanceManager.onHostPause(this);
    }
  }

  @Override
  protected void onResume() {
    super.onResume();

    if (mReactInstanceManager != null) {
      mReactInstanceManager.onHostResume(this, this);
    }
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();

    if (mReactInstanceManager != null) {
      mReactInstanceManager.onHostDestroy(this);
    }
  }

  @Override
  public void onBackPressed() {
    if (mReactInstanceManager != null) {
      mReactInstanceManager.onBackPressed();
    } else {
      super.onBackPressed();
    }
  }

  @Override
  public boolean onKeyUp(int keyCode, KeyEvent event) {
    if (keyCode == KeyEvent.KEYCODE_MENU && mReactInstanceManager != null) {
      mReactInstanceManager.showDevOptionsDialog();
      return true;
    }
    return super.onKeyUp(keyCode, event);
  }
}
```

1.  最后一步是在片段加载时添加一些布局设置。我们需要编辑位于`/res`文件夹中的`content_main.xml`文件。这是视图的主要内容。它包含我们将附加片段的容器视图（`FrameLayout`），以及其他本机元素应该显示的内容：

```jsx
 <FrameLayout
    android:layout_width="match_parent"
    android:layout_height="300dp"
    android:layout_centerVertical="true"
    android:layout_alignParentStart="true"
    android:id="@+id/reactnativeembed"
    android:background="#FFF">
</FrameLayout>
```

1.  在终端中运行以下命令：

```jsx
 react-native start 
```

这将构建和托管 React Native 应用。现在，我们可以在 Android 模拟器中打开应用。按下 FAB 按钮后，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/6f5ee6bb-0ec1-4474-9748-606437b3d2c8.png)

# 工作原理...

为了在我们的 Android 应用程序中呈现 React Native，我们需要执行一些步骤。首先，我们需要定义一个实现`ReactApplication`接口的`Application`类。然后，我们需要创建一个负责实例化和呈现`ReactRootView`的`Fragment`。通过片段，我们能够在我们的`MainActivity`中呈现 React Native 视图。在这个教程中，我们将片段添加到我们的片段容器视图中。这实质上用 React Native 应用程序替换了所有应用程序内容。

在这个教程中，我们涵盖了大量的集成代码。要更深入地了解每个部分的工作原理，您可以阅读官方文档[`facebook.github.io/react-native/docs/integration-with-existing-apps.html`](https://facebook.github.io/react-native/docs/integration-with-existing-apps.html)。

# 从 Android 应用程序到 React Native 的通信

现在我们已经介绍了如何在*将 React Native 应用程序和本机 Android 应用程序结合*的教程中渲染我们的 React Native 应用程序，我们准备迈出下一步。我们的 React Native 应用程序应该不仅仅是一个虚拟 UI。它应该能够对其父应用程序中正在进行的操作做出反应。

在这个教程中，我们将完成从我们的 Android 应用程序发送数据到我们嵌入的 React Native 应用程序。当 React Native 应用程序首次实例化时，它可以接受数据，然后在运行时。我们将介绍如何完成这两种方法。这个教程将在 Android 应用程序中使用`EditText`，并设置单向绑定到 React Native 应用程序。

# 准备工作

对于这个教程，请确保您有一个嵌入了 React Native 应用程序的 Android 应用程序。如果您需要指导来完成这一点，请完成*将 React Native 应用程序和本机 Android 应用程序结合*的教程。

# 如何做...

1.  在 Android Studio 中，打开 React Native 应用程序的 Android 部分。首先，我们需要编辑`content_main.xml`。

1.  对于这个应用程序，我们只需要一个非常简单的布局。您可以通过按下底部的“文本”选项卡来编辑文件，打开源编辑器并添加/替换以下节点：

```jsx
<TextView android: layout_width = "wrap_content"
android: layout_height = "wrap_content"
android: text = "Press the Mail Icon to start the React Native application"
android: id = "@+id/textView" />
<FrameLayout android: layout_width = "match_parent"
android: layout_height = "300dp"
android: layout_centerVertical = "true"
android: layout_alignParentStart = "true"
android: id = "@+id/reactnativeembed"
android: background = "#FFF" >
</FrameLayout>
<LinearLayout android:orientation="horizontal"
android:layout_width="match_parent"
android:layout_height="75dp"
android:layout_below="@+id/textView"
android:layout_centerHorizontal="true">
  <TextView
  android:layout_width="wrap_content"
  android:layout_height="wrap_content"
  android:text="User Name:"
  android:id="@ + id / textView2"
  android:layout_weight="0.14 " />
  <EditText android:layout_width="wrap_content"
  android:layout_height="wrap_content"
  android:id="@ + id / userName"
  android:layout_weight="0.78"
  android:inputType="text"
  android:singleLine="true"
  android:imeOptions="actionDone"/>
</LinearLayout>
```

1.  打开`MainActivity.java`并添加以下类字段：

```jsx
private ReactInstanceManager mReactInstanceManager;
private EditText userNameField;
private Boolean isRNRunning = false;
```

1.  在“onCreate”方法中，使用以下代码设置`userNameField`属性：

```jsx
  userNameField = (EditText) findViewById(R.id.userName);
```

1.  我们将使用 FAB 按钮来更新 Android 应用程序的内容为我们的 React Native 应用程序。我们需要用以下内容替换`FloatingActionButtononClickListener`：

```jsx
fab.setOnClickListener(new View.OnClickListener() {
  @Override public void onClick(View view) {
    Fragment viewFragment = new EmbedFragment();
    if (userNameField.getText().length() > 0) {
      Bundle launchOptions = new Bundle();
      launchOptions.putString("userName", 
      userNameField.getText().toString());
      viewFragment.setArguments(launchOptions);
    }
    getFragmentManager().beginTransaction().add(R.id.reactnativeembed, viewFragment).commit();
    isRNRunning = true;
  }
});
```

1.  接下来，我们需要在`onCreate`方法中为我们的`userNameField`添加一个`TextChangedListener`：

```jsx
userNameField.addTextChangedListener(new TextWatcher() {
  @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
  @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
  @Override public void afterTextChanged(Editable s) {
    if (isRNRunning) {
      sendUserNameChange(s.toString());
    }
  }
});
```

1.  我们需要为我们的`Activity`做的最后一项更改是添加方法，将事件发送到 React Native 桥接中：

```jsx
private void sendUserNameChange(String userName) {
  WritableMap params = Arguments.createMap();
  params.putString("userName", userName);
  sendReactEvent("UserNameChanged", params);
}

private void sendReactEvent(String eventName, WritableMap params) {
  mReactInstanceManager.getCurrentReactContext()
    .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
    .emit(eventName, params);
}
```

1.  让我们回到 JavaScript 层。我们将使用`NativeAppEventEmitter`组件的`addListener`方法来监听从本机 Android 代码发送的`UserNameChanged`事件，并使用事件中的数据更新`state.userName`：

```jsx
import React, { Component } from 'react';
import {
  AppRegistry,
  StyleSheet,
  View,
  Text,
  NativeAppEventEmitter
} from 'react-native';

export default class EmbedApp extends Component<{}> {
  componentWillMount() {
    this.setState({
      userName : this.props.userName
    });

    NativeAppEventEmitter.addListener('UserNameChanged', (body) => {
        this.setState({userName : body.userName});
    });
  }
  render() {
    return (
      <View style={styles.container}>
        <Text>Hello {this.state.userName}</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
});

AppRegistry.registerComponent('EmbedApp', () => EmbedApp);
```

1.  现在，如果您运行应用程序，您可以在“用户名”字段中输入文本，并启动 React Native 应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/8eed73c3-6777-48bd-81f6-965e890169aa.png)

# 它是如何工作的...

在这个示例中，我们将片段呈现为内联视图。在*步骤 2*中，我们添加了一个空的`FrameLayout`，我们在*步骤 5*中将其定位为呈现片段。通过使用 React Native 桥接器`RCTDeviceEventEmitter`来实现绑定功能。这最初是设计用于与本地模块一起使用的，但只要您可以访问`ReactContext`实例，就可以将其用于与 React Native JavaScript 层的任何通信。

# 从 React Native 通信到 Android 应用程序容器

正如我们在上一个示例中讨论的那样，让我们的嵌入式应用程序了解其周围发生的事情是非常有益的。我们还应该努力让我们的 Android 父应用程序了解 React Native 应用程序内部发生的事情。应用程序不仅应能执行业务逻辑-还应能更新其 UI 以反映嵌入应用程序中的更改。

这个示例向我们展示了如何利用本地模块来更新在 Android 应用程序内部创建的本地 UI。我们的 React Native 应用程序中将有一个文本字段，用于更新在主机 Android 应用程序中呈现的文本字段。

# 准备工作

对于这个示例，请确保您有一个嵌入了 React Native 应用程序的 Android 应用程序。如果您需要指导来完成这个任务，请完成*组合 React Native 应用程序和本地 Android 应用程序*示例。

# 如何做...

1.  打开 Android Studio 到您的项目并打开`content_main.xml`。

1.  按底部的 Text 标签打开源编辑器，并添加/替换以下节点：

```jsx
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout 

  android:layout_width="match_parent"
  android:layout_height="match_parent"
  android:paddingBottom="@dimen/activity_vertical_margin"
  android:paddingLeft="@dimen/activity_horizontal_margin"
  android:paddingRight="@dimen/activity_horizontal_margin"
  android:paddingTop="@dimen/activity_vertical_margin"
  app:layout_behavior="@string/appbar_scrolling_view_behavior"
  tools:context="com.embedapp.MainActivity"
  tools:showIn="@layout/activity_main">

  <TextView
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="Press the Mail Icon to start the React Native application"
    android:id="@+id/textView" />

  <FrameLayout
    android:layout_width="match_parent"
    android:layout_height="300dp"
    android:layout_centerVertical="true"
    android:layout_alignParentStart="true"
    android:id="@+id/reactnativeembed"
    android:background="#FFF"></FrameLayout>

  <LinearLayout
    android:orientation="horizontal"
    android:layout_width="match_parent"
    android:layout_height="75dp"
    android:layout_below="@+id/textView"
    android:layout_centerHorizontal="true">

    <TextView
      android:layout_width="wrap_content"
      android:layout_height="wrap_content"
      android:text="User Name:"
      android:id="@+id/textView2"
      android:layout_weight="0.14" />

      <EditText
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:id="@+id/userName"
        android:layout_weight="0.78"
        android:inputType="text"
        android:singleLine="true"
        android:imeOptions="actionDone"/>
  </LinearLayout>
</RelativeLayout>
```

1.  创建一个名为`UserNameManager`的 Java 类。这将是一个本地模块，用于更新我们添加到布局中的`EditTextfield`的目的。

如果您不熟悉为 React Native 创建本地模块，请参阅第十一章中的*公开自定义 Android 模块*示例，*添加本地功能*。

1.  `UserNameManager.java`中的大部分工作都是在`setUserName`方法中完成的。在这里，Android 层根据从 React Native 层发送的内容更新视图的文本内容。React 方法不一定会在主 UI 线程上运行，因此我们使用`mainActivity.runOnUiThread`在主 UI 线程准备好时更新视图：

```jsx
public class UserNameManager extends ReactContextBaseJavaModule {
  public UserNameManager(ReactApplicationContext reactApplicationContext) {
    super(reactApplicationContext);
  }
  @Override public String getName() {
    return "UserNameManager";
  }
  @ReactMethod public void setUserName(final String userName) {
    Activity mainActivity = getReactApplicationContext().getCurrentActivity();
    final EditText userNameField = (EditText) mainActivity.findViewById(R.id.userName);
    mainActivity.runOnUiThread(new Runnable() {
      @Override public void run() {
        userNameField.setText(userName);
      }
    });
  }
}
```

1.  要导出`UserNameManager`模块，我们需要编辑`UserNamePackage` Java 类。我们可以通过调用`modules.add`将其导出到 React Native 层，传入一个以`reactContext`为参数的新`UserNameManager`：

```jsx
public class UserNamePackage implements ReactPackage {
  @Override public List < Class << ? extends JavaScriptModule >> createJSModules() {
      return Collections.emptyList();
  }
  @Override public List < ViewManager > createViewManagers(ReactApplicationContext reactContext) {
      return Collections.emptyList();
  }
  @Override public List < NativeModule > createNativeModules(ReactApplicationContext reactContext) {
      List < NativeModule > modules = new ArrayList < > ();
 modules.add(new UserNameManager(reactContext));
      return modules;
  }
}
```

1.  在`MainApplication`的`getPackages`方法中添加`UserNamePackage`：

```jsx
 @Override
 protected List<ReactPackage> getPackages() {
  return Arrays.<ReactPackage>asList(
   new MainReactPackage(),
   new UserNamePackage()
  );
 }
```

1.  现在，我们需要让我们的 React Native UI 渲染一个`TextField`并调用我们的`UserNameManager`本地模块。打开`index.android.js`并从`'react-native'`导入`TextInput`和`NativeModules`模块。

1.  为`UserNameManager`创建一个变量引用：

```jsx
       const UserNameManager = NativeModules.UserNameManager;
```

1.  React Native 应用程序只需要一个`TextInput`来操作`state`对象上的`userName`属性：

```jsx
let state = {
  userName: ''
}

onUserNameChange = (userName) => {
  this.setState({
    userName
  });

  UserNameManager.setUserName(userName);
}

render() {
  return (
    <View style={styles.container}>
      <Text>Embedded RN App</Text>
      <Text>Enter User Name</Text>
      <TextInput style={styles.userNameField}
        onChangeText={this.onUserNameChange}
        value={this.state.userName}
      />
    </View>
  );
}
```

1.  运行应用程序，启动 React Native 嵌入式应用程序，并向文本字段添加文本，您应该看到类似于以下截图所示的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c3c111f9-4a0b-455c-8784-1e859f69db12.png)

# 工作原理...

为了使我们的 React Native 应用程序更新本机应用程序容器，我们创建了一个本机模块。这是从 JavaScript 通信到本机层的推荐方式。但是，由于我们必须更新本机 UI 组件，因此操作必须在主线程上执行。这是通过获取对`MainActivity`的引用并调用`runOnUiThread`方法来实现的。这是在*步骤 4*的`setUserName`方法中完成的。

# 处理外部 Android 应用程序调用

在本章的前面，我们介绍了如何在 iOS 中处理外部应用程序的调用，在*处理外部 Android 应用程序调用*中。在这个配方中，我们将介绍 Android 中深度链接的相同概念。

# 如何做...

1.  让我们首先在 Android Studio 中打开 React Native Android 项目，并导航到`AndroidManifest.xml`。

1.  对于我们的示例，我们将在`invoked://scheme`下注册我们的应用程序。我们将更新`<activity>`节点如下：

```jsx
<activity
android:name=".MainActivity"
android:label="@string/app_name"
android:configChanges="keyboard|keyboardHidden|orientation|screenSize"
android:windowSoftInputMode="adjustResize"
android:launchMode="singleTask">
  <intent-filter>
    <action android:name="android.intent.action.MAIN" />
    <category android:name="android.intent.category.LAUNCHER" />
  </intent-filter>
</activity>
```

有关此`intent-filter`的工作原理的更多信息，请参阅官方 Android 文档[`developer.android.com/training/app-links/deep-linking`](https://developer.android.com/training/app-links/deep-linking)。

1.  接下来，我们需要创建一个简单的 React Native 应用程序，其 UI 对被调用做出反应。让我们打开`index.android.js`文件。我们将从`'react-native'`的`import`块中导入`Linking`模块：

```jsx
import React from 'react';
import { Platform, Text, Linking } from 'react-native';
```

1.  让我们为 React Native 应用构建`App`类。当组件挂载时，我们将使用一个名为`url`的事件注册一个`Linking`事件监听器。当这个事件发生时，`onAppInvoked`将被触发，更新状态的`status`属性，以及传递给回调函数的事件：

```jsx
export default class App extends React.Component {
  state = {
    status: 'App Running'
  }

  componentWillMount() {
    Linking.addEventListener('url', this.onAppInvoked);
  }

  componentWillUnmount() {
    Linking.removeEventListener('url', this.onAppInvoked);
  }

  onAppInvoked = (event) => {
    this.setState({ status: `App Invoked by ${event.url}` });
  }

  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.instructions}>
          App Status:
        </Text>
        <Text style={styles.welcome}>
          {this.state.status}
        </Text>
      </View>
    );
  } 
}
```

1.  运行应用程序并从另一个应用程序调用它将看起来像这样： 

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/3c740e41-fd02-4b2a-8be2-32e7a7935dfc.png)

# 工作原理...

在这个教程中，我们通过编辑*步骤 2*中的`AndroidManifest.xml`文件来注册我们的 URL 模式以进行链接。需要注意的一点是将`launchMode`更改为`singleTask`。这可以防止操作系统创建我们的 React 活动的多个实例。如果你想要能够正确捕获随意图传递的数据，这一点非常重要。
