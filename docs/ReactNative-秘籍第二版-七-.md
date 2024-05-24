# ReactNative 秘籍第二版（七）

> 原文：[`zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce`](https://zh.annas-archive.org/md5/12592741083b1cbc7e657e9f51045dce)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：部署您的应用程序

在本章中，我们将介绍以下配方：

+   将开发构建部署到 iOS 设备

+   将开发构建部署到 Android 设备

+   将测试构建部署到 HockeyApp

+   将 iOS 测试构建部署到 TestFlight

+   将生产构建部署到 Apple 应用商店

+   将生产构建部署到 Google Play 商店

+   部署空中更新

+   优化 React Native 应用程序大小

# 介绍

如果您是独立开发者，您可能会经历几个不同的开发阶段。第一阶段将使您在个人 iOS 或 Android 设备上测试您的应用程序。在耗尽这个阶段之后，您可能会想要与一小部分人分享它，以获得用户反馈。最终，您将达到一个可以通过应用商店发布应用程序的阶段。本章将逐个介绍这些阶段，并涵盖推送更新到您的应用程序以及一些优化技巧。

# 将开发构建部署到 iOS 设备

在开发过程中，您可能会花费大部分时间使用 Xcode 安装的 iOS 模拟器测试您的 iOS 应用程序。虽然 iOS 模拟器是迄今为止性能最好且最接近在 iOS 设备上运行应用程序的方法，但它仍然不同于真实设备。iOS 模拟器使用计算机的 CPU 和 GPU 来渲染模拟的操作系统，因此根据您的开发机器，它可能表现得比实际设备更好（或更差）。

幸运的是，Expo 能够在实际设备上测试运行代码，这让我们离真正的最终产品更近了一步，但最终应用程序和在 Expo 中运行的开发应用程序之间仍然存在差异。如果您正在构建纯 React Native 应用程序，您将无法像使用 Expo 那样轻松地在设备上运行应用程序。

无论如何，您最终都希望在实际设备上测试真正的应用程序，以便体验最终产品的实际用户体验和性能。

在本配方中，我们将指导您将 React Native 应用程序部署到 iPhone 或 iPad。

# 准备工作

我们只需要一个新的纯 React Native 应用程序，我们将其命名为`TestDeployApp`。您可以通过以下命令创建该应用程序：

```jsx
 react-native init 
```

另外，请确保您的 iOS 设备通过 USB 连接到开发机器。

# 如何做...

1.  让我们首先在 Xcode 中打开新创建的 React Native iOS 项目。通过在左侧面板中选择项目的根目录来打开项目编辑器。

1.  在项目编辑器的“常规”选项卡下，在左侧的“目标”部分中选择 iOS 应用程序。在“签名”部分下，选择您的团队，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/17f1f486-4562-4110-8a55-a7129058c416.png)

1.  对于“目标”列表中的每个条目，重复此步骤两次。

1.  在目标选择器中选择您的设备，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/b959d5eb-7689-4e8e-8475-3f6e9afcb951.png)

1.  要在连接的设备上开始运行应用程序，只需按下播放按钮。您必须确保您的设备已插入，已解锁，并且已信任，才能在 Xcode 的设备列表中显示出来。如果这是您在此设备上首次运行您开发的应用程序，您还需要调整设置以信任来自您的开发者帐户的应用程序。在 iOS 设备上，此设置可以在“设置”|“常规”|“设备管理”中找到。

# 它是如何工作的...

将我们的开发构建部署到设备上只涉及指定一个团队，然后像在 Xcode 模拟器上使用一样运行应用程序，但是将目标设备更改为已插入的设备。我们使用本地主机打包程序来创建我们的捆绑文件。然后将此文件保存在设备上以供将来使用。请注意，由于这是开发构建，因此代码尚未像在最终发布时那样进行优化。在转到生产版本时，您将看到显着的性能提升。

# 将开发构建部署到 Android 设备

在开发 Android 应用程序时，您最有可能会在 Android 模拟器上运行应用程序。虽然方便，但与真实的 Android 设备相比，模拟器的性能较差。

测试应用程序的最佳方法是使用实际的 Android 设备。本教程将介绍将 React Native 应用程序部署到实际的 Android 设备。

# 准备就绪

我们只需要一个新的纯 React Native 应用程序，我们将其命名为`TestDeployApp`。您可以通过以下命令创建该应用程序：

```jsx
react-native init
```

此外，请确保您的 iOS 设备通过 USB 连接到开发计算机。

# 如何做...

1.  让我们首先在 Android Studio 中打开我们的 React Native Android 项目。

1.  接下来，按照以下步骤按下运行按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7c3b453b-faae-4e88-9c3f-0c2b632fdd57.png)

1.  确保选择“选择运行设备”单选按钮，并且您的设备显示在列表中。按 OK 继续，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/e716a726-e91d-46c2-b09c-2cd2946e7c81.png)

# 还有更多...

当您运行应用程序时，React Native 打包程序应该会启动。如果没有，您将需要手动启动打包程序。如果您看到一个带有消息“无法获取 BatchedBridge”的错误屏幕，请确保您的捆绑包正确打包，或者“无法连接到开发服务器”，您应该能够通过在终端中运行以下命令来解决这个问题：

```jsx
adb reverse tcp:8081 tcp:8081
```

# 工作原理...

与 Xcode 类似，我们可以通过简单地插入一个真实的设备，按下运行，然后选择应用程序应该运行的设备来运行我们的应用程序。可能出现的唯一复杂情况是设置设备和开发机之间的通信。这些问题通常可以通过以下命令解决：

```jsx
adb reverse
```

这将从设备到主机计算机建立一个端口转发。这是一个开发版本，代码还没有优化，所以一旦应用程序作为生产版本构建，性能将会提高。

# 将测试版本部署到 HockeyApp

在将应用程序发布到市场之前，重要的是对应用程序进行压力测试，并在可能的情况下获得用户反馈。为了实现这一点，您需要创建一个签名的应用程序构建，可以与一组测试用户共享。对于一个强大的测试构建，您需要两样东西：应用程序性能的分析/报告，以及交付的机制。HockeyApp 为 iOS 和 Android 上的测试构建提供了这些以及更多功能。虽然苹果应用商店和谷歌 Play 商店的官方平台都提供了测试和分析功能，但 HockeyApp 提供了一个统一的处理这些问题的地方，以及度量、崩溃报告等的第二来源。

值得注意的是，HockeyApp 最近被微软收购。他们宣布 HockeyApp 产品将在 2019 年 11 月停止，并转而使用微软的 App Center。您可以在产品过渡页面上阅读更多信息[`hockeyapp.net/transition`](https://hockeyapp.net/transition)。本食谱将介绍如何将 React Native 应用程序部署到 HockeyApp 进行测试。我们将介绍 iOS 和 Android 版本的发布。

# 准备就绪

对于这个食谱，我们将使用上两个食谱中的相同的空的、纯净的 React Native 应用，我们将其命名为`TestDeployApp`。对于 iOS 部署，您需要加入苹果开发者计划，并且需要安装`cocoapods`。安装`cocoapods`的最简单方法是使用 homebrew，通过以下命令：

```jsx
 brew install cocoapods
```

您还需要拥有 HockeyApp 帐户，您可以在他们的网站 [`hockeyapp.net/`](https://hockeyapp.net/) 上注册。

# 如何做到...

1.  首先，我们需要在我们的应用程序中安装 `react-native-hockeyapp` 模块。打开终端，转到应用程序的根项目目录，并输入以下命令：

```jsx
        npm install react-native-hockeyapp --save
```

1.  进入你的 `ios/` 目录并初始化你的 Podfile：

```jsx
        pod init
```

1.  打开你的 Podfile 并在你的目标中添加 `pod "HockeySDK"`。

1.  回到终端，按照以下步骤安装 Podfile：

```jsx
        pod install
```

1.  现在，让我们打开 Xcode 并打开我们的 React Native 项目：(`ios/TestDeployApp.xcodeproj`)。

1.  我建议将您的 Bundle 标识符更改为比默认值更有意义的内容，请在常规设置对话框中更改如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/dcb61823-96a7-4a23-9fae-8ec0ceb79d7c.png)

1.  将 `./ios/Pods/Pods.xcodeproj` 拖放到项目导航器中的 Libraries 组中，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/a9faaea8-c68a-4626-85a4-a77f0bb0f697.png)

1.  将位于 `./node_modules/react-native-hockeyapp/RNHockeyApp/RNHockeyApp` 的 `RNHockeyApp.h` 和 `RNHockeyApp.m` 文件拖放到相同的 Libraries 组中。

1.  接下来，我们将转到 HockeyApp 网站并在那里创建我们的应用程序。登录并点击新应用。

1.  由于我们的构建还没有准备好，所以在下一个模态中点击手动，而不是上传构建？创建应用程序。

1.  在创建应用程序表单中填写字段时，请确保与我们在 *步骤 6* 中定义的标题和 Bundle 标识符匹配，然后点击保存，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/7c49595c-2cde-4474-9626-6ed48f719a08.png)

1.  记下应用程序 ID，因为我们将在下一步中使用它。

1.  打开 `App.js` 并添加以下代码：

```jsx
        import HockeyApp from 'react-native-hockeyapp'; 

        export default class 
        TestDeployApp extends Component { 
          componentWillMount() { 
            HockeyApp.configure(YOUR_APP_ID_HERE, true); 
          } 

          componentDidMount() { 
            HockeyApp.start(); 
            HockeyApp.checkForUpdate(); 
          } 
        } 
```

1.  回到 Xcode，将通用 iOS 设备设置为目标目标并构建（Product | Build）应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c8579b2c-6812-44fa-b86b-aa9288275ef3.png)

1.  现在，我们需要创建我们的 `.ipa` 文件。这可以通过 Xcode 菜单中的 Product | Archive 完成。

1.  这将打开归档列表。点击分发应用程序按钮开始创建 `.ipa` 的过程。

1.  选择开发选项并点击下一步。

1.  您的配置团队应该会自动选择。选择正确的团队后，点击下一步。

1.  保留默认的导出设置并点击下一步。在摘要页面上，也点击下一步。

1.  选择目标目录并点击导出。

1.  回到 *HockeyApp* 浏览器窗口，点击添加版本。

1.  将刚刚导出的`.ipa`文件拖放到模态窗口中。

1.  我们可以将设置保留为默认设置，所以继续按下一步，直到最后一个模态屏幕，然后在摘要屏幕上按下完成。这就是 iOS 应用的全部内容。您可以向*HockeyApp*应用添加用户，然后您的测试人员应该能够下载您的应用。让我们转到 Android 端。打开 Android Studio，然后打开 React Native 中的 Android 文件夹。

1.  重复*步骤 8*到*步骤 11*，将平台更改为 Android，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/dc9b38e8-c6ac-4821-8f03-b3dfe396616b.png)

1.  现在，我们需要构建我们的`.apk`文件。您可以在 React Native 文档中找到构建`.apk`的最新方法，位于：

[`facebook.github.io/react-native/docs/signed-apk-android.html`](https://facebook.github.io/react-native/docs/signed-apk-android.html)

1.  重复从我们的 Android 项目生成的`.apk`的*步骤 21*和*步骤 22*。

# 它是如何工作的...

对于这个教程，我们使用*HockeyApp*的两个主要功能：其 beta 分发和其 HockeySDK（支持崩溃报告、指标、反馈、身份验证和更新通知）。对于 iOS，beta 分发是通过*HockeyApp*托管的 OTA 企业分发机制完成的。当您签署您的应用时，您可以控制哪些设备可以打开它。*HockeyApp*只是发送通知并提供 URL 供 beta 测试人员通过其企业应用商店下载您的应用。Android 更简单，因为不需要担心应用是如何传输的。这意味着*HockeyApp*将`.apk`文件托管在测试人员可以下载和安装的 Web 服务器上。

有关在 Android 上设置*HockeyApp*的更多信息，您可以阅读官方文档[`support.hockeyapp.net/kb/client-integration-android/hockeyapp-for-android-sdk`](https://support.hockeyapp.net/kb/client-integration-android/hockeyapp-for-android-sdk)。

# 将 iOS 测试构建部署到 TestFlight

在*HockeyApp*出现之前，用于测试移动应用程序的最流行的服务是 TestFlight。事实上，它在这方面做得非常好，以至于苹果收购了其母公司并将其整合到了 iTunes Connect 中。TestFlight 现在作为苹果的官方应用程序测试平台。TestFlight 和*HockeyApp*之间有一些区别需要考虑。首先，TestFlight 在被苹果收购后变成了仅适用于 iOS。其次，在 TestFlight 中有两种测试样式：内部和外部。**内部测试**涉及与团队的开发人员或管理员角色成员共享应用程序，并将分发限制为每个设备 10 个设备上的 25 个测试人员。**外部测试**允许您邀请最多 2,000 名不必是您组织成员的测试人员。这也意味着这些测试人员不会使用您的设备配额。外部测试应用程序需要经过苹果进行的**Beta App Review**，这并不像苹果对将应用程序发布到 App Store 的审查那样严格，但这是一个很好的第一步。

本食谱侧重于将我们的 React Native 应用程序部署到 TestFlight 进行测试构建。我们将设置一个内部测试，因为我们不希望苹果审查我们的示例 React Native 应用程序，但是内部和外部测试的程序是相同的。

# 准备工作

对于这个食谱，我们将使用之前食谱中的相同的 React Native 应用程序模板，我们将其命名为`TestDeployApp`。您还需要加入苹果开发者计划，需要在 Xcode 中设置开发和分发证书，并且您的应用程序需要设置其 AppIcon。

# 操作步骤...

1.  让我们首先通过`ios/TestDeployApp.xcodeproj`文件在 Xcode 中打开我们的项目。

1.  正如上一篇食谱中所述，我还建议将您的 Bundle Identifier 更改为比默认值更有意义的内容，例如：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/6fc38221-6cfa-4128-94c1-667c5811eab1.png)

1.  接下来，让我们登录到苹果开发者计划，并转到位于[https//:developer.apple.com/account/ios/identifier/bundle](https://developer.apple.com/account/ios/identifier/bundle)的 App ID 注册页面。

1.  在这里，填写项目的名称和 Bundle ID，然后按下“继续”按钮，接着按“注册”按钮，最后按“完成”按钮完成应用程序的注册。

1.  接下来，我们将登录到位于[`itunesconnect.apple.com`](https://itunesconnect.apple.com)的 iTunes Connect 网站。

1.  在 iTunes Connect 中，导航到“我的应用程序”，然后按“加号（+）”按钮并选择“新应用程序”以添加新应用程序。

1.  在新应用程序对话框中，填写名称和语言。选择与之前创建的 Bundle ID 匹配的 Bundle ID，并在 SKU 字段中添加一个唯一的应用程序引用，然后按“创建”。

1.  接下来，导航到您的应用程序的 TestFlight 部分，并确保填写本地化信息部分。

1.  让我们返回 Xcode 创建`.ipa`文件。选择通用 iOS 设备作为活动方案，然后通过 Xcode 菜单（产品|存档）创建文件。这将打开存档列表，您可以按“上传到 App Store”按钮上传应用程序。

1.  您的配置团队应该自动选择。确保选择正确的团队，然后按“选择”。创建存档后，按“上传”按钮。

1.  上传应用程序后，您需要等待直到收到来自 iTunes Connect 的电子邮件，通知您构建已完成处理。处理完成后，您可以返回 iTunes Connect 页面并打开内部测试视图。

1.  在内部测试部分，单击“选择要测试的版本”，然后选择您的构建，然后单击“下一步”按钮。在“导出合规性”屏幕上，按“确定”。

1.  我们准备添加内部测试人员。选择您想要测试该应用程序的用户，然后单击“开始测试”按钮，并在随后的模态中确认您的选择。您的用户现在应该收到邀请邮件来测试您的应用程序！

# 工作原理...

TestFlight 在 App Store 发布流程中扮演着一流的角色。苹果已经将其支持应用程序测试分发的支持直接集成到 iTunes Connect 中，为开发人员创建了一个流畅无缝的流程。这个过程与部署到 App Store 基本相同，只是在使用 iTunes Connect 时，您必须启用和配置测试。

对于测试人员来说，这也是一个无缝的体验。一旦您在 iTunes Connect 中添加了测试用户，他们将收到安装 TestFlight 应用程序的通知，从而可以轻松访问他们可以测试的应用程序。TestFlight 还通过不需要开发人员添加任何额外的第三方库或代码来支持 TestFlight，使开发人员的流程更加简单，而这在使用*HockeyApp*时是必需的。

# 将生产版本部署到苹果应用商店

一旦您彻底测试了您的应用程序，您就可以继续进行下一个（可能也是最激动人心的）步骤：发布到 Apple 应用商店。

这个步骤将指导您准备生产版本并将其提交到 Apple 应用商店。我们实际上不会将应用提交到商店，因为我们使用的是示例应用而不是生产就绪的应用。然而，流程的最后几个步骤非常简单。

# 准备工作

对于这个步骤，我们将再次使用之前的示例应用程序`TestDeployApp`。当然，您还需要加入苹果开发者计划，并在 Xcode 中设置开发和分发证书，就像本章前面讨论的那样。对于真正的生产应用程序部署，您还需要设置 AppIcon 并准备用于 iTunes 的应用程序截图。

# 如何做...

1.  让我们从使用`ios/TestDeployApp.xcodeproj`文件打开 Xcode 开始。

1.  如前所述，建议您将 Bundle Identifier 更改为比默认值更有意义的内容，因此请务必在“常规设置”对话框中更改它。

1.  在设备上以生产模式测试应用程序也是一个好主意。这可以通过将应用程序方案的构建配置（通过“产品”|“方案”|“编辑方案”菜单找到）更改为 Release 来完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/af39d72a-9c2b-48f2-a5c4-9b56602d1a30.png)

1.  接下来，您需要在 App ID 注册页面上注册应用，该页面位于：

[`developer.apple.com/account/ios/identifier/bundle`](https://developer.apple.com/account/ios/identifier/bundle)

这一步需要一个活跃的苹果开发者计划账户。

1.  填写项目的名称和 Bundle ID 字段，然后按 Continue 按钮。

1.  接下来，我们将登录到位于[`itunesconnect.apple.com`](https://itunesconnect.apple.com)的 iTunes Connect 网站。在“My Apps”部分，按加号(+)按钮，然后选择“新建应用”。

1.  您需要在以下对话框中填写名称和语言，然后选择与之前在步骤中创建的 Bundle ID 相匹配的 Bundle ID。此外，添加一个唯一的应用程序引用 SKU，并按 Create 按钮。

1.  让我们返回 Xcode 并创建`.ipa`文件。选择 Generic iOS Device 作为活动方案，并通过菜单（产品|存档）创建文件，这将打开存档列表。最后，按“上传到 App Store”。

1.  选择您的配置团队，然后按“选择”。

1.  一旦存档创建完成，按“上传”按钮。一旦构建完成，您将收到来自 iTunes Connect 的电子邮件。

1.  应用程序处理完毕后，返回到 iTunes Connect。在 App Store 部分，打开 App 信息并选择您的应用所适合的类别。

1.  在 iOS APP 下的 1.0 准备提交部分中打开。填写所有必填字段，包括应用程序截图、描述、关键字和支持 URL。

1.  接下来，在“构建”部分，选择我们在第 8 步中构建的`.ipa`。

1.  最后，填写版权和应用程序审查信息部分，然后点击“提交审核”按钮。

# 它是如何工作的...

在这个食谱中，我们介绍了将 iOS 应用程序发布到 App Store 的标准流程。在这种情况下，我们不需要遵循任何 React Native 特定的步骤，因为最终产品（`.ipa`文件）包含了运行 React Native 打包程序所需的所有代码，这将进而以发布模式构建`main.jsbundle`文件。

# 将生产版本部署到 Google Play 商店

本食谱将介绍准备我们的应用程序的生产版本并将其提交到 Google Play 商店的过程。与上一个食谱一样，我们将在实际提交到 App Store 之前停下来，因为这只是一个示例 React Native 应用程序，但是这个过程的其余部分也很简单。

# 准备工作

对于这个食谱，我们将使用本章节中一直使用的相同简单的 React Native 应用程序`TestDeployApp`。您需要拥有 Google Play 开发者帐户才能将应用程序提交到商店，并且如果您想要实际发布应用程序，还需要准备好所有的图标和 Play 商店的截图。

# 如何做...

1.  让我们从在 Android Studio 中打开 React Native 项目开始。第一步是构建`.apk`文件。正如本章前面提到的，从 React Native 项目创建生产 Android 应用程序的过程是复杂的，而且容易发生变化。访问 React Native 文档以获取有关创建`.apk`的信息：[`facebook.github.io/react-native/docs/signed-apk-android.html`](https://facebook.github.io/react-native/docs/signed-apk-android.html)。

1.  接下来，让我们在 Web 浏览器中打开 Google Play 开发者控制台，网址是[`play.google.com/apps/publish/`](https://play.google.com/apps/publish/)。

1.  让我们通过点击“添加新应用程序”来开始这个过程。填写标题字段，然后点击“上传 APK”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/2082ac1f-1326-45f1-bb3a-2ba990af147a.png)

1.  接下来，您将看到发布屏幕的 APK 部分。点击“上传您的第一个 APK 到生产”，然后拖放（或选择）您的`.apk`文件。

1.  接下来将出现一系列不言自明的模态。浏览左侧侧边菜单中的每个类别（商店列表、内容评级等），并相应地填写所有信息。

1.  一旦满足所有要求，点击“发布应用程序”按钮。

# 它是如何工作的...

在这个教程中，我们介绍了将 Android 应用程序发布到 Google Play 商店的过程。通过按照*步骤*2 中链接的说明，您的 React Native 应用程序将经历 Gradle `assembleRelease`过程。`assemble`过程运行打包程序以创建 JavaScript 捆绑文件，编译 Java 类，将它们与适当的资源打包在一起，最后允许您将应用程序签名为`.apk`。

# 部署 Over-The-Air 更新

我们的 React Native 应用程序以 JavaScript 编写的一个有用的副作用是，代码是在运行时加载的，这类似于 Cordova 混合应用程序的工作方式。我们可以利用这个功能来使用**OTA**（Over-The-Air）推送更新到我们的应用程序。这允许添加功能和修复错误，而无需经过应用商店的批准流程。对于 React Native 的 OTA 更新的唯一限制是，我们不能推送编译的（Objective-C 或 Java）代码，这意味着更新代码必须仅在 JavaScript 层中。有一些流行的服务提供基于云的 OTA 应用程序更新。我们将重点介绍微软的服务`CodePush`。

这个教程将涵盖在 iOS 和 Android 上为我们的 React Native 应用程序设置和推送更新使用`CodePush`。

# 准备工作

对于这个教程，我们将使用相同的简单的 React Native 应用程序，我们在本章中一直在使用的`TestDeployApp`。我们将把应用程序部署到以生产/发布模式运行的物理设备上，这将允许应用程序从 CodePush 服务器接收更新。

# 如何做...

1.  为了使用 CodePush，我们需要安装 CodePush CLI 并创建一个免费帐户。这可以通过在终端中运行以下两个命令来完成：

```jsx
npm install -g code-push-cli
code-push register
```

1.  下一步是向 CodePush 注册我们的应用程序。记下通过运行`code-push register`输出提供的应用程序的部署密钥。我们将在这个示例中使用**暂存密钥**。文档建议为每个平台添加一个应用程序，每个应用程序都带有`-IOS`或`-Android`后缀。要将应用程序添加到 CodePush，请使用此命令：

```jsx
code-push app add TestDeployApp**-IOS**
**code-push app add TestDeployApp-Android** 
```

1.  我们还需要在 React Native 项目目录中安装 React Native CodePush 模块。可以使用`npm`完成这个操作，如下所示：

```jsx
npm install --save react-native-code-push
```

或者，使用`yarn`：

```jsx
yarn add react-native-code-push
```

1.  下一步是将 CodePush 本机模块与我们的项目进行链接。在提示输入 Android 和 iOS 的部署密钥时，请使用*步骤 2*中讨论的暂存密钥。可以使用以下命令链接本机模块：

```jsx
react-native link react-native-code-push
```

1.  接下来，我们需要设置我们的 React Native 应用程序以使用 CodePush。在`index.js`中，我们需要添加三个东西：CodePush 导入，一个选项对象，以及在通过`AppRegistry.registerComponent`注册应用程序时调用导入的`codePush`模块。设置应用程序如下：

```jsx
import {AppRegistry} from 'react-native';
import App from './App';
import codePush from 'react-native-code-push'; 

const codePushOptions = { 
 updateDialog : true 
} 

AppRegistry.registerComponent('TestDeployApp',
 () => codePush(codePushOptions)(App)
)
```

1.  为了测试我们在 iOS 应用程序中的更改，让我们部署到我们的 iOS 设备。在 Xcode 中打开 React Native 项目，将方案的构建配置（产品|方案|编辑方案...）更改为 Release，然后按照以下步骤运行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/0b2c207c-df88-4ee7-9e38-3b1022ab7b51.png)

1.  接下来，在应用程序中对 React Native 代码进行某种任意更改，然后在终端中运行以下命令以使用新代码更新应用程序：

```jsx
code-push release-react TestDeployApp ios -m --description "Updating using CodePush"
```

1.  接下来，在您的 iOS 设备上关闭并重新打开应用程序。您应该会看到以下提示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/c759c174-a9f6-49de-b2b5-de304a017076.png)

1.  继续通过提示后，应用程序将自动更新到最新版本！

1.  让我们还在 Android 上测试一下这个功能。您需要按照 React Native 文档中[`facebook.github.io/react-native/docs/signed-apk-android.html`](https://facebook.github.io/react-native/docs/signed-apk-android.html)中概述的步骤将您的 Android 应用程序制作成`.apk`文件。

1.  将 Android 设备连接到开发计算机后，在`android/`目录中运行以下命令：

```jsx
adb install 
app/build/outputs/apk/app-release.apk
```

1.  接下来，对 React Native JavaScript 代码进行更改。只要添加了新代码，我们就可以使用该更改的代码来更新应用程序。然后，在终端中运行以下命令：

```jsx
code-push release-react TestDeployApp android -m --description "Updating using CodePush"
```

1.  再次在 Android 设备上关闭并重新打开应用程序，以获得以下提示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/321c9e80-f6db-4c2a-8ad3-7dee57827d17.png)

1.  在继续操作提示之后，应用程序将自行更新到最新版本。

# 它是如何工作的...

CodePush（以及其他云托管的 OTA 更新平台）的工作原理与 React Native 自诞生以来一直存在的技术相同。当应用程序初始化时，React Native 会加载一个 JavaScript 捆绑包。在开发过程中，此捆绑包从`localhost:3000`加载。然而，一旦我们部署了一个应用程序，它将寻找一个名为`main.jsbundle`的文件，该文件已包含在最终产品中。通过在*步骤 5*中的`registerComponent`中添加对`codePush`的调用，应用程序将与 CodePush API 进行检查以查看是否有更新。如果有新的更新，它将提示用户。接受提示会下载新的`jsbundle`文件并重新启动应用程序，从而更新代码。

# 优化 React Native 应用程序大小

在将我们的应用程序部署到生产环境之前，将应用程序捆绑包的大小缩小到尽可能小的文件是一个很好的主意，我们可以利用几种技术来实现这一点。这可能涉及支持更少的设备或压缩包含的资产。

这个配方将涵盖一些限制 iOS 和 Android React Native 应用程序生产包文件大小的技术。

# 准备工作

对于这个配方，我们将使用本章节中一直使用的相同简单的 React Native 应用程序，`TestDeployApp`。您还需要在 iOS 上使用代码签名，并且能够创建`.apk`文件，就像在之前的配方中介绍的那样。

# 如何做...

1.  我们将从对我们捆绑的资产进行一些简单的优化开始，这通常包括图像和外部字体：

+   对于 PNG 和 JPEG 压缩，您可以使用诸如[`www.tinypng.com`](http://www.tinypng.com)之类的服务来减小文件大小，几乎不会降低图像质量。

+   如果您使用`react-native-vector-icons`库，您会注意到它捆绑了八种不同的字体图标集。建议您删除应用程序未使用的任何图标字体库。

+   SVG 文件也可以进行压缩和优化。用于此目的的一个服务是[`compressor.io`](http://compressor.io)。

+   打包到您的应用程序中的任何音频资产应该使用可以利用高质量压缩的文件格式，例如 MP3 或 AAC。

1.  对于 iOS，除了默认启用的发布方案设置外，几乎没有什么可以进一步减小文件大小的方法。这些设置包括为应用瘦身启用 Bitcode 和将编译器优化设置为 Fastest, Smallest [-Os]。

1.  对于 Android，有两件事情可以改善文件大小：

+   在 Android Studio 中，打开`android/app/build.gradle`文件，找到以下行，然后将它们的值更新为以下内容：

```jsx
def enableSeparateBuildPerCPUArchitecture = true 
def enableProguardInReleaseBuilds = true 
```

1.  如果您只打算针对基于 ARM 架构的 Android 设备，我们可以完全阻止其构建 x86 支持。在`build.gradle`文件中，找到`splits abi`对象，并添加以下行以不包括 x86 支持：

```jsx
include "armeabi-v7a" 
```

您可以在 Android 文档中阅读有关 ABI 管理的更多信息：

[`developer.android.com/ndk/guides/abis`](https://developer.android.com/ndk/guides/abis)

# 工作原理...

在这个教程中，我们介绍了可以用来减小应用文件大小的技术。JavaScript 捆绑包越小，JavaScript 解释器就能更快地解析代码，从而实现更快的应用加载时间和更快的 OTA 更新。我们能够保持`.ipa`和`.apk`文件越小，用户就能越快地下载应用。


# 第十五章：优化您的应用的性能

在本章中，我们将涵盖以下配方：

+   优化我们的 JavaScript 代码

+   优化自定义 UI 组件的性能

+   保持动画以 60 FPS 运行

+   充分利用 ListView

+   提升我们应用的性能

+   优化原生 iOS 模块的性能

+   优化原生 Android 模块的性能

+   优化原生 iOS UI 组件的性能

+   优化原生 Android UI 组件的性能

# 介绍

性能是软件开发中几乎每一个技术的关键要求。React Native 被引入是为了解决混合应用中存在的性能不佳的问题，这些混合应用将 Web 应用程序包装在本地容器中。React Native 具有既灵活又出色性能的架构。

在考虑 React Native 应用的性能时，重要的是要考虑 React Native 的工作方式的整体情况。React Native 应用有三个主要部分，它们的相对性能如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/5e5d3840-ef23-43ba-b367-5883966d71e8.png)

本章的配方侧重于使用占用更少内存并具有更少操作的低级函数，从而降低任务完成所需的时间。

# 优化我们的 JavaScript 代码

可以说，您的 React Native 应用可能主要是用 JavaScript 编写的。可能会有一些原生模块和自定义 UI 组件，但大部分视图和业务逻辑可能都是用 JSX 和 JavaScript 编写的。如果您使用现代 JavaScript 开发技术，您还将使用 ES6、ES7 及更高版本引入的语言构造。这些可能作为 React Native 捆绑的 JavaScript 解释器（JavaScriptCore）的一部分本地可用，也可能由 Babel 转译器进行填充。由于 JavaScript 可能构成任何给定的 React Native 应用的大部分，这应该是我们优化的第一部分，以便从应用中挤出额外的性能。

这个配方将提供一些有用的提示，以优化 JavaScript 代码，使其尽可能高效。

# 准备工作

这个技巧不一定依赖于 React Native，因为它侧重于用于编写任何 React 应用程序的 JavaScript。其中一些建议是微优化，可能只会提高旧版/较慢设备的性能。根据您打算支持的设备，一些技巧会比其他技巧更有效。

# 如何做...

1.  要考虑的第一个优化是加快迭代速度。通常，您可能会使用将迭代器函数作为参数的函数（`forEach`，`filter`和`map`）。一般来说，这些方法比使用标准的`for`循环要慢。如果您要迭代的集合非常大，这可能会有所不同。以下是一个更快的 filter 函数的示例：

```jsx
let myArray = [1,2,3,4,5,6,7];
let newArray;

// Slower: 
function filterFn(element) { 
  return element > 2; 
} 
newArray = myArray.filter(filterFn); 

// Faster: 
function filterArray(array) { 
  var length = array.length, 
    myNewArray = [], 
    element, 
    i; 

  for(i = 0; i < length; i++) { 
    element = array[i]; 
    if(element > 2) { 
      myNewArray.push(array[i]); 
    } 
  } 
  return myNewArray; 
} 

newArray = filterArray(myArray); 
```

1.  在优化迭代时，还可以更有效地确保将您正在访问的变量存储在迭代附近的某个地方：

```jsx
function findInArray(propertyerties, appConfig) { 
  for (let i = 0; i < propertyerties.length; i++) { 
    if (propertyerties[i].somepropertyerty ===
    appConfig.userConfig.permissions[0]) { 
      // do something 
    } 
  } 
} 

function fasterFindInArray(propertyerties, appConfig) { 
  let matchPermission = appConfig.userConfig.permissions[0];
  let length = propertyerties.length;
  let i = 0; 

  for (; i < length; i++) { 
    if (propertyerties[i].somepropertyerty === matchPermission) { 
      // do something 
    } 
  } 
} 
```

1.  您还可以优化逻辑表达式。将执行速度最快且最接近的语句放在左边：

```jsx
function canViewApp(user, isSuperUser) { 
  if (getUserPermissions(user).canView || isSuperUser) { 
      return true; 
  } 
} 

function canViewApp(user, isSuperUser) { 
  if (isSuperUser || getUserPermissions(user).canView) { 
      return true; 
  } 
}
```

1.  虽然现代 JavaScript（ES6，ES7 等）构造可能更容易开发，但它们的一些特性执行速度比它们的 ES5 对应物要慢。这些特性包括`for of`，`generators`，`Object.assign`等。有关性能比较的良好参考资料可以在[`kpdecker.github.io/six-speed/`](https://kpdecker.github.io/six-speed/)找到。

1.  避免使用`try-catch`语句可能会有所帮助，因为它们会影响解释器的优化（就像在 V8 中一样）。

1.  数组应该有相同类型的成员。如果需要一个类型可以变化的集合，可以使用对象。

# 工作原理...

JavaScript 性能是一个不断争论的话题。由于谷歌、苹果、Mozilla 和全球开源社区一直在努力改进他们的 JavaScript 引擎，因此有时很难跟上最新的性能指标。对于 React Native，我们关注的是 WebKit 的 JavaScriptCore。

# 优化自定义 UI 组件的性能

在构建 React Native 应用程序时，可以肯定会创建自定义 UI 组件。这些组件可以是由几个其他组件组成的，也可以是在现有组件的基础上构建并添加更多功能的组件。随着功能的增加，复杂性也会增加。这种增加的复杂性会导致更多的操作，从而可能导致减速。幸运的是，有一些方法可以确保我们的自定义 UI 组件性能最佳。本文介绍了几种技术，以便充分利用我们的组件。

# 准备工作

本文要求您有一个带有一些自定义组件的 React Native 应用程序。由于这些性能建议可能对您的应用程序提供或不提供价值，请谨慎选择是否将其应用于您的代码。

# 如何做到...

1.  我们应该首先查看的优化是跟踪给定组件的`state`对象中的内容。我们应该确保`state`中的所有对象都被使用，并且每个对象都可能发生变化，从而引起所需的重新渲染。

1.  查看每个组件的`render`函数。总体目标是使该函数尽可能快地执行，因此请尽量确保其中不会发生长时间运行的过程。如果可以的话，缓存计算和常量值，使其在`render`函数之外不会每次实例化。

1.  如果在`render`函数中可能返回条件性 JSX，请尽早`return`。以下是一个微不足道的例子：

```jsx
// unoptimized 
render() { 
  let output; 
  const isAdminView = this.propertys.isAdminView; 

  if(isAdminView) { 
    output = (<AdminButton/>); 
  } else { 
    output = ( 
      <View style={styles.button}> 
        <Text>{this.propertys.buttonLabel}</Text> 
      </View> 
    ); 
  } 
  return output; 
} 

// optimized 
render() { 
  const isAdminView = this.propertys.isAdminView; 

  if (isAdminView) { 
    return (<AdminButton/>); 
  } 
  return ( 
    <View style={styles.button}> 
      <Text>{this.propertys.buttonLabel}</Text> 
    </View> 
  ); 
} 
```

1.  我们可以进行的最重要的优化是如果不需要，可以完全跳过`render`方法。这是通过实现`shouldComponentUpdate`方法并从中返回`false`来实现的，使其成为纯组件。以下是如何使组件成为`PureComponent`的方法：

```jsx
import React, { PureComponent } from 'react'; 

export default class Button extends PureComponent {

} 
```

# 工作原理...

大多数 React Native 应用程序将由自定义组件组成。将有一些有状态和无状态的组件。正如在*步骤 2*中所强调的，总体目标是以尽可能短的时间渲染我们的组件。如果一个组件只需要渲染一次，然后保持不变，那么也可以实现另一个收益，就像在*步骤 4*中介绍的那样。有关纯组件的使用方法和其益处的更多信息，请访问[`60devs.com/pure-component-in-react.html`](https://60devs.com/pure-component-in-react.html)。

# 另请参阅

您可以在官方文档[`reactjs.org/docs/optimizing-performance.html`](https://reactjs.org/docs/optimizing-performance.html)中找到有关 React 组件性能优化的更多信息。

# 保持动画以 60FPS 运行

任何高质量移动应用程序的重要方面是用户界面的流畅性。动画用于提供丰富的用户体验，任何卡顿或抖动都可能对此产生负面影响。动画可能会用于各种交互，从在视图之间切换到对组件上的用户触摸交互做出反应。创建高质量动画的最重要因素之一是确保它们不会阻塞 JavaScript 线程。为了保持动画流畅并且不中断 UI 交互，渲染循环必须在 16.67 毫秒内渲染每一帧，以便实现 60FPS。

在这个教程中，我们将介绍几种改善动画性能的技术。这些技术特别关注于防止 JavaScript 执行中断主线程。

# 准备工作

对于这个教程，我们假设您有一个定义了一些动画的 React Native 应用程序。

# 如何做...

1.  首先，在调试 React Native 中的动画性能时，我们需要启用性能监视器。要这样做，显示开发菜单（摇动设备或从模拟器中使用*cmd* + *D*）并点击显示性能监视器。

在 iOS 中的输出将类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/736fdab4-9302-4864-919c-976104b70754.png)

在 Android 中的输出将类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/rn-cb-2e/img/4bccef67-4132-4af7-a859-3cacb76cf832.png)

1.  如果您想要对组件的过渡（`opacity`）或尺寸（`width`，`height`）进行动画处理，则确保使用`LayoutAnimation`。您可以在第六章的*向您的应用程序添加基本动画*中找到使用`LayoutAnimation`的示例，在*展开和折叠容器*的教程中。

如果您想在 Android 上使用`LayoutAnimation`，则需要在应用程序启动时添加以下代码：`UIManager.setLayoutAnimationEnabledExperimental && UIManager.setLayoutAnimationEnabledExperimental(true)`。

1.  如果您需要对动画有限的控制，建议您使用 React Native 附带的`Animated`库。该库允许您将所有动画工作卸载到本地 UI 线程上。为此，我们必须将`useNativeDriver`属性添加到我们的`Animated`调用中。让我们以一个示例`Animated`示例并将其卸载到本地线程：

```jsx
componentWillMount() { 
  this.setState({ 
    fadeAnimimation: new Animated.Value(0) 
  }); 
} 

componentDidMount() { 
  Animated.timing(this.state.fadeAnimimation, { 
    toValue: 1, 
    useNativeDriver: true 
  }).start(); 
}
```

目前，仅动画库的部分功能支持本地卸载。请参考*还有更多...*部分以获取兼容性指南。

1.  如果您无法将动画工作卸载到本地线程上，仍然有解决方案可以提供流畅的体验。我们可以使用`InteractionManager`在动画完成后执行任务：

```jsx
componentWillMount() { 
  this.setState({ 
    isAnimationDone: false 
  }); 
} 
componentWillUpdate() { 
  LayoutAnimation.easeInAndOut(); 
} 

componentDidMount() { 
  InteractionManager.runAfterInteractions(() => { 
    this.setState({ 
      isAnimationDone: true 
    }); 
  }) 
} 

render() { 
  if (!this.state.isAnimationDone) { 
    return this.renderPlaceholder(); 
  } 
  return this.renderMainScene(); 
} 
```

1.  最后，如果您仍然遇到性能问题，您将不得不重新考虑您的动画策略，或者在目标平台上将性能不佳的视图实现为自定义 UI 视图组件。这意味着使用 iOS 和/或 Android SDK 本地实现您的视图和动画。在第十一章中，*添加本地功能*，我们介绍了在*渲染自定义 iOS 视图组件*和*渲染自定义 Android 视图组件*中创建自定义 UI 组件的方法。

# 工作原理...

本食谱中的提示侧重于防止 JavaScript 线程锁定的简单目标。一旦我们的 JavaScript 线程开始丢帧（锁定），即使只有一小部分时间，我们也失去了与应用程序交互的能力。这似乎微不足道，但敏锐的用户立即就能感受到影响。本食谱中的提示的重点是将动画卸载到 GPU 上。当动画在主线程上运行（由 GPU 渲染的本地层），用户可以自由地与应用程序交互，而不会出现卡顿、挂起、抖动或颤动。

# 还有更多...

这里是`useNativeDriver`可用的快速参考：

| **功能** | **iOS** | **Android** |
| --- | --- | --- |
| `style`, `value`, `propertys` | **√** | **√** |
| `decay` |  | **√** |
| `timing` | **√** | **√** |
| `spring` |  | **√** |
| `add` | **√** | **√** |
| `multiply` | **√** | **√** |
| `modulo` | **√** |  |
| `diffClamp` | **√** | **√** |
| `interpoloate` | **√** | **√** |
| `event` |  | **√** |
| `division` | **√** | **√** |
| `transform` | **√** | **√** |

# 充分利用 ListView

React Native 提供了一个非常高性能的列表组件。它非常灵活，支持在其中渲染几乎任何您可以想象的组件，并且渲染速度相当快。如果您想阅读更多关于如何使用`ListView`的示例，本书中有一些示例，包括第二章中的*显示项目列表*，*创建一个简单的 React Native 应用程序*。React Native 的`ListView`是建立在`ScrollView`之上的，以实现使用任何视图组件呈现可变高度行的灵活性。

`ListView`组件的主要性能和资源缺点是当您使用非常大的列表时发生。当用户滚动列表时，下一页的行在底部被渲染。顶部的不可见行可以设置为从渲染树中删除，我们将很快介绍。但是，只要组件被挂载，行的引用仍然在内存中。当我们的组件使用可用内存时，将会减少快速访问存储给即将到来的组件的空间。这个示例将涵盖处理一些潜在的性能和内存资源问题。

# 准备工作

对于这个示例，我们假设您有一个使用`ListView`的 React Native 应用程序，最好是使用大型数据集。

# 如何做...

1.  "在某些情况下，该功能可能存在错误（内容丢失）-使用时需自担风险。"

1.  接下来，如果每行中呈现的组件不复杂，我们可以增加`pageSize`。

1.  另一个优化是将`scrollRenderAheadDistance`设置为舒适的值。如果您可以预期用户很少会滚动到初始视口之外，或者他们可能会滚动得很慢，那么您可以降低该值。这可以防止`ListView`提前渲染太多行。

1.  最后，我们可以利用`removeClippedSubviews`属性进行最后的优化。然而，官方文档指出：

让我们从对我们的原始`ListView`组件进行一些优化开始。如果我们将`initialListSize`属性设置为`1`，我们可以加快初始渲染。

1.  *步骤 1 到步骤 4*的组合可以在以下示例代码中看到：

```jsx
renderRow(row) { 
  return ( 
    <View style={{height:44, overflow:'hidden'}}> 
      <Text>Item {row.index}</Text> 
    </View> 
  ) 
} 

render() { 
  return ( 
    <View style={{flex:1}}> 
      <ListView 
        dataSource={this.state.dataSource} 
        renderRow={this.renderRow} 
        pageSize={10} 
        initialListSize={1} 
        pageSize={10} 
        scrollAheadDistance={200} 
        /> 
    </View> 
  ) 
} 
```

# 它是如何工作的...

与开发任何应用一样，某样东西越灵活和复杂，性能就越慢。`ListView`就是这个概念的一个很好的例子。它非常灵活，因为它可以在一行中呈现任何`View`，但如果不小心使用，它可能会迅速使您的应用停滞不前。在*步骤 1*到*步骤 4*中定义的优化结果将根据您正在呈现的内容和`ListView`使用的数据结构在不同情况下有所不同。您应该尝试这些值，直到找到一个良好的平衡。作为最后的手段，如果您仍然无法达到所需的性能基准，可以查看一些提供新的`ListView`实现或替代方案的社区模块。

# 另请参阅

以下是一些第三方`ListView`实现的列表，承诺提高性能：

+   `recyclerlistview`：这个库是`ListView`的最强大的替代品，拥有一长串的改进和功能，包括支持交错网格布局、水平模式和页脚支持。存储库位于[`github.com/Flipkart/recyclerlistview`](https://github.com/Flipkart/recyclerlistview)。

+   `react-native-sglistview`：这将`removeClippedSubviews`提升到一个新的水平，当屏幕外的行从渲染树中移除时，会刷新内存。存储库位于[`github.com/sghiassy/react-native-sglistview`](https://github.com/sghiassy/react-native-sglistview)。

# 提升我们应用的性能

React Native 存在的原因是使用 JavaScript 构建原生应用。这与 Ionic 或 Cordova 混合应用等类似框架不同，后者包装了用 JavaScript 编写的 Web 应用，并尝试模拟原生应用行为。这些 Web 应用只能访问原生 API 来执行处理，但无法在应用内部呈现原生视图。这是 React Native 应用的一个主要优势，因此使它们本质上比混合应用更快。由于它的性能在开箱即用时更高，我们通常不必像处理混合 Web 应用那样担心整体性能。不过，通过一点额外的努力，可能可以实现性能的轻微改进。本文将提供一些快速的方法，可以用来构建更快的 React Native 应用。

# 如何做…

1.  我们可以做的最简单的优化是不输出任何语句到控制台。执行`console.log`语句并不像您想象的那样简单，因此建议在准备捆绑最终应用程序时删除所有控制台语句。

1.  如果您在开发过程中使用了大量控制台语句，您可以使用`transform-remove-console`插件让 Babel 在创建捆绑时自动删除它们。这可以通过使用`yarn`在终端中将其安装到项目中。

```jsx
yarn add babel-plugin-transform-remove-console
```

1.  或者，您可以使用`npm`：

```jsx
npm install babel-plugin-transform-remove-console --save 
```

安装了该软件包后，您可以通过添加包含以下代码的`.babelrc`文件将其添加到项目中：

```jsx
{ 
  "presets": ["react-native"], 
  "env": { 
    "production": { 
        "plugins": ["transform-remove-console"] 
    } 
  } 
} 
```

1.  接下来，请确保在分析性能时，您的应用程序处于生产模式下运行，最好在设备上。如果您想了解如何做到这一点，您可以参考第十三章*部署我们的应用程序*中的*将测试构建部署到 HockeyApp*的配方。

1.  有时，当您在动画化`View`的位置或布局时，您可能会注意到 UI 线程的性能下降。您可以通过将`shouldRasterizeIOS`和`renderToHardwareTextureAndroid`属性设置为 iOS 和 Android 平台的 true 来减轻这种情况。请注意，这可能会显著增加内存使用量，因此请确保在这些更改后测试性能。

1.  如果您发现需要在执行同步的、潜在的长时间运行的过程的同时进行视图转换，这可能会成为性能瓶颈。当构建`ListView`的`DataSource`或转换数据以支持即将到来的视图时，通常会发生这种情况。您应该尝试仅处理数据的初始子集，足以快速渲染 UI。一旦页面转换之间的动画完成，您可以使用`InteractionManager`来加载其余的数据。您可以参考*保持动画以 60 FPS 运行*的配方，了解如何使用`InteractionManager`的更多信息。

1.  最后，如果您已经确定了减慢应用程序速度的特定组件或任务，并且找不到可行的解决方案，那么您应该考虑通过创建本机模块或本机 UI 组件将其移动到本机线程来实现这一功能。

# 它是如何工作的...

这个教程涵盖了一些更高级和更广泛的适用于所有 React Native 应用程序的技巧。您可能会从这些技巧中看到的最显著的性能提升是将组件移动到本地层，如*步骤 7*中所述。

# 优化原生 iOS 模块的性能

在构建 React Native 应用程序时，通常需要使用原生 Android 和 iOS 代码。您可能已经构建了这些原生模块，以公开本地 API 提供的一些额外功能，或者您的应用程序需要执行密集的后台任务。

正如之前提到的，工作在本地层确实允许您充分利用设备的容量。但这并不意味着我们编写的代码将自动成为最快的。总是有优化和实现性能提升的空间。

在这个教程中，我们将提供一些关于如何使用 iOS SDK 使您的 Objective-C 代码运行得更快的技巧。我们还将考虑 React Native 和 React Native 桥接，它用于在 JavaScript 和本地层之间进行通信，如何融入更大的画面。

# 准备工作

对于这个教程，您应该有一个使用为 iOS 创建的原生模块的 React Native 应用程序。如果您需要帮助编写原生模块，请查看第十一章中的*暴露自定义 iOS 模块*教程，*添加原生功能*。

# 如何做...

1.  首先，当使用原生模块时，我们必须注意通过 React Native 桥传递的数据。始终保持跨桥事件和回调中的数据最少化是目标，因为 Objective-C 和 JavaScript 之间的数据序列化非常缓慢。

1.  如果您需要将数据缓存在内存中，以便原生模块使用，可以将其存储在本地属性或字段变量中。原生模块是单例。这样做可以避免返回一个大对象以存储在 React Native 组件中。

1.  有时，我们必须利用因功能集而强大而庞大的类。对于 Objective-C 和 iOS 方面的事情，与其每次通过`RCT_EXPORT_METHOD`公开功能时在您的方法中实例化类似`NSDateFormatter`，不如将该类的引用存储为属性或实例变量。

1.  此外，诸如`NSDateFormatter`之类的原生方法通常非常耗费资源，因此在可能的情况下应避免使用它们。例如，如果您的应用程序只能处理 UNIX 时间戳，那么您可以轻松地使用以下函数从时间戳获取`NSDate`对象：

```jsx
- (NSDate*)dateFromUnixTimestamp:(NSTimeInterval)timestamp {
  return [NSDate dateWithTimeIntervalSince1970:timestamp]; 
} 
```

1.  如果情况允许，您可以进行最重要的性能优化，即生成异步后台线程来处理密集处理。React Native 非常适合这种模型，因为它使用异步消息/事件系统在 JavaScript 和原生线程之间进行通信。当后台进程完成时，您可以调用回调/承诺，或者触发一个事件供 JavaScript 线程处理。要了解如何在 React Native iOS 原生模块中创建和利用后台进程，请查看第十一章的*在 iOS 上进行后台处理*。

# 它是如何工作的...

Objective-C 代码执行非常快 - 几乎和纯 C 一样快。因此，我们进行的优化与执行任务的方式无关，而是与实例化方式和不阻塞原生线程有关。您将看到的最大性能提升是通过使用**Grand Central Dispatch**（**GCD**）生成后台进程，如*步骤 5*中所述。

# 优化原生 Android 模块的性能

在开发 React Native 应用程序时，您可能会发现自己编写原生 Android 模块，以创建跨平台功能（在 iOS 和 Android 上）或者利用尚未作为一方模块包装的 Android 原生 API。希望您在第十一章的*添加原生功能*中找到了一些有用的关于使用原生模块的建议。

在这个配方中，我们将介绍几种加快 React Native Android 原生模块速度的技术。其中许多技术仅限于 Android 上的一般开发，还有一些将涉及与 React Native JavaScript 层的通信。

# 准备工作

对于这个配方，您应该有一个使用您为 Android 创建的原生模块的 React Native 应用程序。如果您需要帮助编写原生模块，请查看第十一章的*暴露自定义 Android 模块*配方。

# 如何做...

1.  首先，与 iOS 原生模块一样，您需要限制通过 React Native 桥传输的数据量。将事件和回调中的数据保持最少将有助于避免由 Java 和 JavaScript 之间的序列化引起的减速。此外，与 iOS 一样，尽量将数据缓存在内存中供原生模块使用；将其存储在私有字段中。原生模块是单例。这应该被利用，而不是返回一个大对象存储在 React Native 组件中。

1.  在为 Android 编写 Java 代码时，您应尽量避免创建短期对象。如果可能的话，尤其是对于数组等数据集，使用基本类型。

1.  最好重用对象，而不是依赖垃圾收集器来回收未使用的引用并实例化一个新对象。

1.  Android SDK 提供了一种内存高效的数据结构，用于替代`Map`的使用，它将整数映射到对象，称为`SparseArray`。使用它可以减少内存使用并提高性能。以下是一个例子：

```jsx
     SparseArray<SomeType> map = new SparseArray<SomeType>(); 
     map.put(1, myObjectInstance); 
```

还有`SparseIntArray`，它将整数映射到整数，以及`SparseBooleanArray`，它将整数映射到布尔值。

1.  虽然对于习惯于在 Java 中进行面向对象编程的开发人员来说可能听起来有些反直觉，但是通过直接访问实例字段来避免使用 getter 和 setter 也可以提高性能。

1.  如果您曾经使用`String`连接，可以使用`StringBuilder`。

1.  最后，如果可能的话，您可以进行最重要的性能优化，即通过利用 React Native 的异步消息/事件系统在 JavaScript 和本地线程之间进行通信，从而生成异步后台线程来执行繁重的计算。当后台进程完成时，您可以调用回调/承诺，或者触发一个事件，让 JavaScript 线程接手。要了解如何在 React Native Android 原生模块中创建后台进程，请阅读第十一章中的*在 Android 上进行后台处理*。

# 工作原理...

这个配方中的大部分提示都围绕着高效的内存管理。Android 操作系统使用类似桌面 Java 虚拟机的传统垃圾收集器。当垃圾收集器启动时，释放内存可能需要 100-200 毫秒。*步骤 3-6*都提供了减少应用程序内存使用的建议。

# 优化原生 iOS UI 组件的性能

React Native 为我们提供了一个优秀的基础，可以使用内置组件和样式构建几乎任何类型的用户界面。使用 Objective-C 使用 iOS SDK、OpenGL 或其他绘图库构建的组件通常比使用 JSX 组合预构建组件性能更好。在使用这些原生视图组件时，可能会有一些用例对应用程序性能产生负面影响。

这个配方将专注于在渲染自定义视图时充分利用 iOS UIKit SDK。我们的目标是尽可能快地渲染所有内容，以使我们的应用程序以 60 FPS 运行。

# 准备工作

对于这个配方，你应该有一个渲染你为 iOS 编写的自定义原生 UI 组件的 React Native 应用程序。如果你需要帮助在 React Native 中包装 UI 组件，请查看第十一章中的*暴露自定义 iOS 视图组件*配方，*添加原生功能*。

# 如何做...

1.  如前所述，只有在无法避免的情况下才通过 React Native 桥传递数据，因为 Objective-C 和 JavaScript 类型之间的数据序列化速度很慢。

1.  如果有数据需要在不久的将来引用，最好将其存储在你初始化的原生类中。根据你的应用程序，你可以将其存储为`ViewManager`的属性，为`View`的实例提供服务的单例，或者`View`本身的属性。

1.  如果你的视图组件涉及将多个`UIView`实例渲染为父`UIView`容器的子级，请确保所有实例的`opaque`属性设置为`true`。

1.  如果你在视图组件内部渲染图像（而不是使用 React Native 的`Image`组件），那么将图像设置为与`UIImageView`组件相同的尺寸可以提高性能。缩放和其他图像转换是影响帧率的重操作。

1.  在编写 iOS 视图组件时，避免离屏渲染是最有影响力的调整之一。如果可能的话，避免使用 SDK 功能进行以下操作：

+   使用以**Core Graphics**（**CG**）库开头的类

+   覆盖`UIView`的`drawRect`实现

+   设置`shouldRasterize=YES`，或者在`UIView`实例的`layer`属性上使用`setMasksToBounds`或`setShadow`

+   使用`CGContext`进行自定义绘图

1.  如果您需要向视图添加阴影，请确保设置`shadowPath`以防止离屏渲染。以下是初始化和阴影定义的示例应该如何看起来：

```jsx
RCT_EXPORT_MODULE() 

- (UIView *)view { 
  UIView *view = [[UIView alloc] init]; 

  view.layer.masksToBounds = NO; 
  view.layer.shadowColor = [UIColor blackColor].CGColor; 
  view.layer.shadowOffset = CGSizeMake(0.0f, 5.0f); 
  view.layer.shadowOpacity = 0.5f; 

  view.layer.shadowPath = [[UIBezierPath bezierPathWithRect:view.bounds] CGPath]; 

  return view; 
} 
```

# 它是如何工作的...

这个教程侧重于一些有用的技巧，可以让 GPU 尽可能多地完成工作。第二部分讨论了如何尽可能减少 GPU 的负荷。在*步骤 3*中强制执行`opaque`属性告诉 GPU 不要担心检查其他组件的可见性，以便它可以计算透明度。*步骤 5*和*步骤 6*防止了离屏渲染。离屏渲染使用 CPU 生成位图图像（这是一个缓慢的过程），更重要的是，它会使 GPU 在生成图像之前无法渲染视图。

# 优化本地 Android UI 组件的性能

在过去的几年里，Android 本地 UI 性能有了显著改善。这主要是由于其使用 GPU 硬件加速来渲染组件和布局的能力。在您的 React Native 应用程序中，您可能会发现自己使用自定义视图组件，特别是如果您想使用尚未作为 React Native 组件包装的内置 Android 功能。尽管 Android 平台已经有意增加了其 UI 的性能，但组件的渲染方式很快就会抵消所有这些好处。

在这个教程中，我们将讨论一些方法，以获得我们自定义 Android 视图组件的最佳性能。

# 准备工作

对于这个教程，您应该有一个 React Native 应用程序，用于渲染您为 Android 编写的自定义本地 UI 组件。如果您需要帮助在 React Native 中包装 UI 组件，请查看第十一章中的*公开自定义 Android 视图组件*教程，*添加本地功能*。

# 如何做...

1.  如前所述，只有在必要时才通过 React Native 桥传递数据。将数据保留在事件和回调中最小化，因为 Java 和 JavaScript 之间的数据序列化很慢。

1.  如果有数据需要在不久的将来进行引用存储，最好将其存储在您初始化的原生类中。根据您的应用程序，您可以将其存储为`SimpleViewManager`上的属性，这是一个为`View`的实例提供服务的单例，或者是`View`本身的属性。

1.  在构建视图时，请考虑组件通常由其他子组件组成。这些组件以布局的层次结构保存。过度嵌套布局可能会变得非常昂贵。如果您正在使用多级嵌套的 LinearLayout 实例，请尝试用单个 RelativeLayout 替换它们。

1.  您可以使用 HierarchyViewer 工具来分析布局的效率，该工具已捆绑在 Android 设备监视器中。要从 Android 设备监视器中打开它，请单击窗口|打开透视图...|层次结构视图，然后选择确定。

1.  如果您在 Java 中原生执行自定义视图上的重复动画（而不是使用 React Native Animated API），那么您可以利用硬件层来提高性能。只需在 animate 调用中添加 withLayer 方法调用。例如：

```jsx
myView.animate() 
  .alpha(0.0f) 
  .withLayer() 
  .start(); 
```

# 它是如何工作的...

不幸的是，当涉及到渲染 Android UI 组件时，你可以执行的优化并不多。它们通常围绕着不要过度嵌套布局，因为这会增加复杂性数倍。当您遇到布局性能问题时，应用程序很可能受到 GPU 的过度使用或过度绘制的影响。过度绘制发生在 GPU 在已经渲染的现有视图上渲染新视图时。您可以在 Android 开发者设置菜单中启用 GPU 过度绘制调试。过度绘制的严重程度顺序为无颜色 -> 蓝色 -> 绿色 -> 浅红色 -> 深红色。

在*步骤 5*中，我们提供了一个快速提示，用于改善动画的性能。这对于重复动画特别有效，因为它会将动画输出缓存到 GPU 上并重放。
