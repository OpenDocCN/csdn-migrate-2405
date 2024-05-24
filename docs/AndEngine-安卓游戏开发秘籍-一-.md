# AndEngine 安卓游戏开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A`](https://zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

AndEngine 是一个卓越的、功能齐全的、免费的、开源的 Android 平台 2D 框架。它是少数几个持续被独立开发者和专业开发者用来创建时尚有趣游戏的 Android 平台 2D 框架之一，甚至一些市场上最成功的游戏也使用了它。然而，要取得成功，仅仅使用特定的框架是不够的。

*AndEngine for Android Game Development Cookbook* 提供了许多关于 AndEngine 最重要方面的信息性演练，这些方面属于一般游戏编程级别。这本书涵盖了从 AndEngine 游戏的生命周期到在场景中放置精灵并移动它们，一直到创建可破坏物体和光线投射技术等内容。更重要的是，这本书完全基于 AndEngine 最新的、最高效的 Anchor-Center 分支。

# 这本书涵盖的内容。

第一章，*AndEngine 游戏结构*，涵盖了使用 AndEngine 进行游戏开发的重要方面，关于大多数游戏需要生存的核心组件。从音频、纹理、AndEngine 生命周期、保存/加载游戏数据等，这一章都有所涉及。

第二章，*使用实体*，开始让我们熟悉 AndEngine 的 `Entity` 类及其子类型，如精灵、文本、基元等。`Entity` 类是 AndEngine 的核心组件，它允许代码中的对象在屏幕上显示。更具体地说，这一章包括 `Entity` 类中最重要方法的列表，以使我们能够完全控制实体的行为、反应或它们的外观。

第三章，*设计你的菜单*，介绍了一些移动游戏中菜单设计较常见的方面。本章涵盖的主题包括创建按钮，为菜单添加主题音乐，创建视差背景和菜单屏幕导航。本章中的主题很容易被用在游戏的其他区域。

第四章，*使用摄像头*，讨论了 AndEngine 中包含的各种关于游戏摄像头和引擎如何查看游戏场景的选项。我们从不同的摄像头对象开始，以便让我们正确理解每种摄像头的优点，从而做出有见地的决定。然后，我们继续涵盖摄像头的移动和缩放，创建超大背景，创建抬头显示，甚至介绍分屏游戏引擎以应对更复杂的游戏设计。

第五章，*场景和图层管理*，展示了如何创建一个健壮的场景管理框架，该框架包含特定场景的加载屏幕和动画图层。本章中的管理场景使用资源管理器，并且非常易于定制。

第六章，*物理学的应用*，探索了使用 Box2D 物理扩展创建 AndEngine 物理模拟的各种技术。本章的内容涵盖了 Box2D 物理世界的基本设置：体类型、类别过滤、具有多个固定装置的物体、基于多边形的物体、力、关节、布娃娃、绳索、碰撞事件、可破坏物体和光线投射。

第七章，*使用更新处理器*，展示了每次引擎更新时调用的更新处理器的使用方法。本章的内容展示了如何注册基于实体的更新处理器、条件更新和创建游戏计时器。

第八章，*最大化性能*，介绍了一些在提高任何 Android 游戏性能时最有效的高级实践。本章涵盖了涉及音频、图形/渲染和一般内存管理的优化技术，以帮助在必要时减轻性能问题。

第九章，*AndEngine 扩展概述*，在这一章中我们讨论了一些更受欢迎的 AndEngine 扩展，根据游戏的不同，这些扩展可能对项目有益。这些扩展并非适合所有人，但对于感兴趣的人来说，本章包含了我们如何着手创建动态壁纸、通过网络服务器和客户端实现多人组件、创建高分辨率 SVG 纹理以及色彩映射纹理的见解。

第十章，*更深入了解 AndEngine*，提供了几个有用的食谱，这些食谱扩展了前几章介绍的概念。本章的内容包括批量纹理加载、纹理网格、自动阴影、移动平台和绳索桥梁。

附录 A，*MagneTank 的源代码*，概述了 MagneTank 游戏，通过逐类描述来展示如何设置用 AndEngine 制作完整的游戏。该游戏包括贯穿各章节的许多食谱，并且附带的代码中提供了源代码。

*附录 B，附加食谱*，书中未包含，但可以通过以下链接免费下载：[`downloads.packtpub.com/sites/default/files/downloads/8987OS_AppB_Final.pdf`](http://downloads.packtpub.com/sites/default/files/downloads/8987OS_AppB_Final.pdf)。

# 你需要为这本书准备什么

《*AndEngine for Android Game Development Cookbook*》对大多数 AndEngine 开发者都有用。从最初的几章开始，读者将开始学习 AndEngine 的基础知识，即使是中级开发者也能在这些章节中找到有用的提示。随着读者章节的深入，将涉及更难的话题，因此初学者不要跳过。此外，那些尚未过渡到 AndEngine 最新开发分支的中级开发者，在整个书中都能找到关于 GLES1/GLES2 分支与本书讨论的 Anchor-Center 分支之间的差异的有用信息。

建议具备 Java 编程语言的基本理解。

为了执行本书中的各种主题，所需的软件包括用于构建和编译代码的 Eclipse IDE，用于图像绘制/编辑的 GIMP，以及用于 SVG 绘制/编辑的 Inkscape。如果您对它们更熟悉，请随意使用这些产品的替代品。此外，本书假设读者在开始使用食谱之前已经获得了所需的库，包括 AndEngine 及其各种扩展。

# 本书适合的读者

《*AndEngine for Android Game Development Cookbook*》面向那些对使用最新版本的 AndEngine 感兴趣的开发者，该版本采用了全新的 GLES 2.0 Anchor-Center 分支。这本书将帮助那些试图进入移动游戏市场，打算发布有趣且刺激的游戏，同时减少进入 AndEngine 开发时不可避免的学习曲线的开发者。

# 约定

在这本书中，您会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字如下所示："以最基础的`Entity`方法为例，我们将一个`Entity`对象附加到一个`Scene`对象上。"

代码块设置如下：

```kt
  float baseBufferData[] = {
      /* First Triangle */
      0, BASE_HEIGHT, UNUSED, /* first point */
      BASE_WIDTH, BASE_HEIGHT, UNUSED, /* second point */
      BASE_WIDTH, 0, UNUSED, 	/* third point */

      /* Second Triangle */
      BASE_WIDTH, 0, UNUSED, /* first point */
      0, 0, UNUSED, /* second point */
      0, BASE_HEIGHT, UNUSED, /* third point */
  };
```

### 注意

警告或重要注意事项会像这样出现在一个框里。

### 提示

提示和技巧会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们您对这本书的看法——您喜欢或可能不喜欢的内容。读者的反馈对我们来说很重要，可以帮助我们开发出您真正能从中获得最大收益的标题。

如需向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您已经拥有了 Packt 的一本书，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您的账户[`www.PacktPub.com`](http://www.PacktPub.com)下载您购买的所有 Packt 书籍的示例代码文件。如果您在别处购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会直接将文件通过电子邮件发送给您。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能向我们报告，我们将不胜感激。这样做，您可以避免其他读者感到沮丧，并帮助我们改进本书的后续版本。如果您发现任何勘误信息，请通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，选择您的书籍，点击**勘误提交表单**链接，并输入您的勘误详情。一旦您的勘误信息得到验证，您的提交将被接受，勘误信息将被上传到我们的网站，或添加到该标题下的现有勘误列表中。任何现有的勘误信息可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看。

## 盗版

互联网上版权资料的盗版问题在所有媒体中持续存在。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供我们该位置地址或网站名称，以便我们可以寻求补救措施。

如果您有疑似盗版资料的链接，请联系`<copyright@packtpub.com>`。

我们感谢您帮助保护我们的作者，以及我们为您带来有价值内容的能力。

## 问题

如果您在书的任何方面遇到问题，可以联系`<questions@packtpub.com>`，我们将尽力解决。


# 第一章：AndEngine 游戏结构

在本章中，我们将了解构建**AndEngine**游戏中所需的主要组成部分。主题包括：

+   了解生命周期

+   选择我们的引擎类型

+   选择分辨率策略

+   创建对象工厂

+   创建游戏管理器

+   引入声音和音乐

+   使用不同类型的纹理

+   应用纹理选项

+   使用 AndEngine 字体资源

+   创建资源管理器

+   保存和加载游戏数据

# 引言

AndEngine 最吸引人的方面是创建游戏的极大便捷性。在首次接触 AndEngine 后，在几周内设计和编码一个游戏并非遥不可及，但这并不意味着它将是一个完美的游戏。如果我们不理解引擎的工作原理，编码过程可能会很繁琐。为了创建精确、有序且可扩展的项目，了解 AndEngine 的主要构建块和游戏结构是一个好主意。

在本章中，我们将介绍 AndEngine 和一般游戏编程中最必要的几个组成部分。我们将查看一些类，这些类将帮助我们快速高效地创建各种游戏的基础。此外，我们还将介绍资源和对象类型之间的区别，这些区别在塑造游戏的整体外观和感觉方面起着最重要的作用。如果需要，建议将本章作为参考资料保存。

# 了解生命周期

在初始化游戏时，了解操作的顺序是很重要的。游戏的基本需求包括创建引擎、加载游戏资源、以及设置初始屏幕和设置。这就是创建 AndEngine 游戏基础所需的一切。但是，如果我们计划在游戏中实现更多多样性，那么了解 AndEngine 中包含的完整生命周期是明智的。

## 准备就绪

请参考代码包中名为`PacktRecipesActivity`的类。

## 如何操作…

AndEngine 生命周期包括我们直接负责定义的几个方法。这些方法包括创建`EngineOptions`对象，创建`Scene`对象，以及用子实体填充场景。这些方法的调用顺序如下：

1.  定义`onCreateEngineOptions()`方法：

    ```kt
    @Override
    public EngineOptions onCreateEngineOptions() {

      // Define our mCamera object
      mCamera = new Camera(0, 0, WIDTH, HEIGHT);

      // Declare & Define our engine options to be applied to our Engine object
      EngineOptions engineOptions = new EngineOptions(true,
          ScreenOrientation.LANDSCAPE_FIXED, new FillResolutionPolicy(),
          mCamera);

      // It is necessary in a lot of applications to define the following
      // wake lock options in order to disable the device's display
      // from turning off during gameplay due to inactivity
      engineOptions.setWakeLockOptions(WakeLockOptions.SCREEN_ON);

      // Return the engineOptions object, passing it to the engine
      return engineOptions;
    }
    ```

1.  定义`onCreateResources()`方法：

    ```kt
    @Override
    public void onCreateResources(
        OnCreateResourcesCallback pOnCreateResourcesCallback) {

      /* We should notify the pOnCreateResourcesCallback that we've finished
        * loading all of the necessary resources in our game AFTER they are loaded.
        * onCreateResourcesFinished() should be the last method called.  */
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    ```

1.  定义`onCreateScene()`方法：

    ```kt
    @Override
    public void onCreateScene(OnCreateSceneCallback pOnCreateSceneCallback) {
      // Create the Scene object
      mScene = new Scene();

      // Notify the callback that we're finished creating the scene, returning
      // mScene to the mEngine object (handled automatically)
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    ```

1.  定义`onPopulateScene()`方法：

    ```kt
    @Override
    public void onPopulateScene(Scene pScene,
      OnPopulateSceneCallback pOnPopulateSceneCallback) {

      // onPopulateSceneFinished(), similar to the resource and scene callback
      // methods, should be called once we are finished populating the scene.
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    ```

## 工作原理…

在此食谱类中找到的代码是任何 AndEngine 游戏的基础。我们设置了一个主活动类，作为进入我们应用程序的入口点。活动包含 AndEngine 活动生命周期中我们负责的四个主要方法，从创建`EngineOptions`选项开始，创建资源，创建场景，以及填充场景。

在第一步中，我们覆盖了引擎的`onCreateEngineOptions()`方法。在这个方法内部，我们主要关注实例化`Camera`对象和`EngineOptions`对象。这两个对象的构造函数允许我们定义应用程序的显示属性。此外，通过调用`engineOptions.setWakeLockOptions(WakeLockOptions.SCREEN_ON)`方法，我们阻止了在应用程序不活动期间屏幕自动关闭。

在第二步中，我们继续覆盖`onCreateResources()`方法，该方法为我们提供了一个特定方法，用于创建和设置游戏所需的所有资源。这些资源可能包括纹理、声音和音乐以及字体。在这一步和接下来的两步中，我们需要调用相应的方法回调，以继续应用程序的生命周期。对于`onCreateResources()`方法，我们必须在方法的最后包含调用`pOnCreateResourcesCallback.onCreateResourcesFinished()`。

第三步涉及实例化和设置`Scene`对象。设置场景可以像本食谱中显示的那么简单，或者对于更复杂的项目，它可能包括设置触摸事件监听器、更新处理器等。完成场景设置后，我们必须调用`pOnCreateSceneCallback.onCreateSceneFinished(mScene)`方法，将我们新创建的`mScene`对象传递给引擎，以便在设备上显示。

最后需要处理的步骤包括定义`onPopulateScene()`方法。此方法专门用于将子实体附加到场景。与之前的两个步骤一样，我们必须调用`pOnPopulateSceneCallback.onPopulateSceneFinished()`以继续剩余的 AndEngine 生命周期调用。

在以下列表中，我们将按照从活动启动到终止时调用的顺序介绍生命周期方法。

启动期间的生命周期调用如下：

+   `onCreate`：此方法是 Android SDK 的原生应用程序入口点。在 AndEngine 开发中，此方法只需调用我们`BaseGameActivity`类中的`onCreateEngineOptions()`方法，然后将返回的选项应用到游戏引擎中。

+   `onResume`：这是 Android SDK 的另一个原生方法。在这里，我们从`EngineOptions`对象获取唤醒锁设置，然后为引擎的`RenderSurfaceView`对象调用`onResume()`方法。

+   `onSurfaceCreated`：此方法将在我们活动的初始启动过程中调用`onCreateGame()`，或者如果活动之前已经部署，则将布尔变量注册为`true`以重新加载资源。

+   `onReloadResources`：如果我们的应用程序从最小化状态恢复到焦点状态，此方法将重新加载游戏资源。在应用程序首次执行时不会调用此方法。

+   `onCreateGame`：这是为了处理 AndEngine 生命周期中接下来三个回调的执行顺序。

+   `onCreateResources`：这个方法允许我们声明和定义在启动活动时应用所需的最初资源。这些资源包括但不限于纹理、声音和音乐以及字体。

+   `onCreateScene`：在这里，我们处理活动场景对象的初始化。在这个方法中可以附加实体到场景，但为了保持组织性，通常最好在`onPopulateScene()`中附加实体。

+   `onPopulateScene`：在生命周期中的`onPopulateScene()`方法里，我们几乎完成了场景的设置，尽管还有一些生命周期调用会由引擎自动处理。这个方法应该用来定义应用首次启动时场景的视觉结果。注意，此时场景已经被创建并应用到引擎中。如果此时没有加载屏幕或启动画面，并且有许多实体需要附加到场景中，那么在某些情况下可能会看到实体被附加到场景上。

+   `onGameCreated`：这表明`onCreateGame()`序列已经完成，如有必要，重新加载资源，否则什么都不做。是否重新加载资源取决于在五个生命周期调用之前的`onSurfaceCreated`方法中简要提到的布尔变量。

+   `onSurfaceChanged`：每次应用的方向从横屏模式变为竖屏模式，或者从竖屏模式变为横屏模式时，都会调用这个方法。

+   `onResumeGame`：这是在活动启动周期中最后一个调用的方法。如果我们的活动在没有问题的情况下到达这一点，将调用引擎的`start()`方法，使游戏的更新线程活跃起来。

在最小化/终止过程中的生命周期调用如下：

+   `onPause`：活动最小化或结束时首先调用的方法。这是原生安卓的暂停方法，它调用`RenderSurfaceView`对象的暂停方法，并恢复游戏引擎应用的唤醒锁设置。

+   `onPauseGame`：接下来，AndEngine 的`onPause()`实现，它只是简单地在引擎上调用`stop()`方法，导致引擎的所有更新处理器以及更新线程停止。

+   `onDestroy`：在`onDestroy()`方法中，AndEngine 会清除由引擎管理类持有的`ArrayList`对象中包含的所有图形资源。这些管理类包括`VertexBufferObjectManager`类、`FontManager`类、`ShaderProgramManager`类，以及最后的`TextureManager`类。

+   `onDestroyResources`：这个方法名称可能有些误导，因为我们已经在`onDestroy()`中卸载了大部分资源。这个方法真正的作用是，通过调用相应管理器的`releaseAll()`方法，释放所有存储在其中的声音和音乐对象。

+   `onGameDestroyed`：最后，我们到达在整个 AndEngine 生命周期中需要调用的最后一个方法。在这个方法中没有太多动作发生。AndEngine 只是将用于 Engine 的`mGameCreated`布尔变量设置为`false`，表示活动不再运行。

在以下图片中，我们可以看到当创建游戏、最小化或销毁游戏时，生命周期的实际表现：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_01_01.jpg)

### 注意

由于 AndEngine 生命周期的异步性质，在单个启动实例期间可能会多次执行某些方法。这些事件的发生在设备之间是不同的。

## 还有更多…

在本食谱的前一部分中，我们已经介绍了主要的`BaseGameActivity`类。以下类可以作为`BaseGameActivity`类的替代品，每个类都有自己的一些细微差别。

### `LayoutGameActivity`类

`LayoutGameActivity`类是一个有用的活动类，它允许我们将 AndEngine 场景图视图集成到普通的 Android 应用程序中。另一方面，使用这个类，我们还可以将原生的 Android SDK 视图，如按钮、滑动条、下拉列表、附加布局或其他任何视图包含到我们的游戏中。然而，使用这种活动最流行的原因是便于在游戏中实现广告，作为一种获取收益的手段。

为`LayoutGameActivity`类设置需要几个额外的步骤。

1.  在项目的默认布局 XML 文件中添加以下行。这个文件通常称为`main.xml`。以下代码段将 AndEngine `RenderSurfaceView`类添加到我们的布局文件中。这是将在设备上显示我们游戏的视图：

    ```kt
    <org.andengine.opengl.view.RenderSurfaceView
    android:id="@+id/gameSurfaceView"
    android:layout_width="fill_parent"
    android:layout_height="fill_parent"/>
    ```

1.  这种活动类型的第二个也是最后一个额外步骤是在第一步中引用布局 XML 文件和`RenderSurfaceView`，在`LayoutGameActivity`重写方法中。以下代码假设布局文件在`res/layout/`文件夹中称为`main.xml`；在这种情况下，可以在完成第一步后将其复制/粘贴到我们的`LayoutGameActivity`类中：

    ```kt
    @Override
    protected int getLayoutID() {
      return R.layout.main;
    }

    @Override
    protected int getRenderSurfaceViewID() {
      return R.id.gameSurfaceView;
    }
    ```

### `SimpleBaseGameActivity`和`SimpleLayoutGameActivity`类

如建议的那样，`SimpleBaseGameActivity`和`SimpleLayoutGameActivity`类使重写生命周期方法变得更容易处理。它们不要求我们重写`onPopulateScene()`方法，而且，在我们定义完重写的方法后，我们也不需要调用方法回调。使用这些活动类型，我们可以简单地添加未实现的生命周期方法，AndEngine 会为我们处理回调。

### `SimpleAsyncGameActivity`类

我们将要讨论的最后一个游戏活动类是`SimpleAsyncGameActivity`类。这个类包括三个可选的生命周期方法：`onCreateResourcesAsync()`、`onCreateSceneAsync()`和`onPopulateSceneAsync()`，以及通常的`onCreateEngineOptions()`方法。这个活动与其他活动的主要区别在于，它为每个"Async"方法提供了加载进度条。以下代码片段展示了当纹理加载时我们如何增加加载进度条：

```kt
@Override
public void onCreateResourcesAsync(IProgressListener pProgressListener)
    throws Exception {

  // Load texture number one
  pProgressListener.onProgressChanged(10);

  // Load texture number two
  pProgressListener.onProgressChanged(20);

  // Load texture number three
  pProgressListener.onProgressChanged(30);

  // We can continue to set progress to whichever value we'd like
  // for each additional step through onCreateResourcesAsync...
}
```

### 提示

**下载示例代码**

你可以从你在[`www.PacktPub.com`](http://www.PacktPub.com)的账户中下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会将文件直接通过电子邮件发送给你。

# 选择我们的引擎类型

在我们开始编程游戏之前，最好先确定游戏所需的性能需求。AndEngine 包含几种不同类型的引擎供我们选择使用，每种都有其自身的优势。当然，这些优势取决于我们计划创建的游戏类型。

## 准备工作

执行本章中的*了解生命周期*食谱，以在我们的 IDE 中设置一个基本的 AndEngine 项目，然后继续到*如何操作…*部分。

## 如何操作…

为了正确地为我们的游戏定义一个特定的`Engine`对象，我们必须重写`onCreateEngine()`方法，这是 AndEngine 启动过程的一部分。在任意基础的 AndEngine 活动中添加以下代码，以手动处理引擎的创建：

```kt
/* The onCreateEngine method allows us to return a 'customized' Engine object
* to the Activity which for the most part affects the way frame updates are 
* handled. Depending on the Engine object used, the overall feel of the 
* gameplay can alter drastically. 
*/
@Override
public Engine onCreateEngine(EngineOptions pEngineOptions) {
  return super.onCreateEngine(pEngineOptions);
  /* The returned super method above simply calls:
      return new Engine(pEngineOptions);
  */
}
```

## 工作原理…

以下是 AndEngine 中可用的各种`Engine`对象的概览，以及一个简短的代码片段，展示如何设置每个`Engine`对象：

+   `Engine`：首先，我们有一个普通的`Engine`对象。对于大多数游戏开发来说，`Engine`对象并不理想，因为它在每秒帧数上没有任何限制。在两个不同的设备上，你很可能会注意到游戏速度的差异。一个思考方式是，如果两个不同的设备同时开始观看同一个视频，较快的设备可能会先完成视频观看，而不是同时完成。因此，在运行较慢的设备上可能会出现明显的问题，尤其是在物理是游戏重要部分的情况下。将这种类型的引擎集成到我们的游戏中不需要额外的步骤。

+   `FixedStepEngine`：我们可用的第二种引擎是`FixedStepEngine`。这是游戏开发中理想的引擎，因为它强制游戏循环以恒定速度更新，而与设备无关。这是通过根据经过的时间更新游戏，而不是根据设备执行代码的能力来实现的。`FixedStepEngine`要求我们按顺序传递`EngineOptions`对象和一个`int`值。这个`int`值定义了每秒引擎将强制运行的步数。以下代码创建了一个以恒定`60`步每秒运行的引擎：

    ```kt
    @Override
    public Engine onCreateEngine(EngineOptions pEngineOptions) {
      // Create a fixed step engine updating at 60 steps per second
        return new FixedStepEngine(pEngineOptions, 60);
      }
    ```

+   `LimitedFPSEngine`：`LimitedFPSEngine`引擎允许我们设置引擎运行的每秒帧数限制。这将导致引擎进行一些内部计算，如果首选 FPS 与引擎当前实现的 FPS 之间的差值大于预设值，引擎将会等待一小段时间后再进行下一次更新。`LimitedFPSEngine`在构造函数中需要两个参数，包括`EngineOptions`对象和一个指定最大每秒帧数的`int`值。以下代码创建了一个最大以 60 帧每秒运行的引擎：

    ```kt
    @Override
    public Engine onCreateEngine(EngineOptions pEngineOptions) {
      // Create a limited FPS engine, which will run at a maximum of 60 FPS
      return new LimitedFPSEngine(pEngineOptions, 60);
    }
    ```

+   `SingleSceneSplitScreenEngine`和`DoubleSceneSplitScreenEngine`：`SingleSceneSplitScreenEngine`引擎和`DoubleSceneSplitScreenEngine`引擎允许我们创建带有两个独立摄像头的游戏，可以是单个场景，通常用于单人游戏，也可以是两个场景，用于单个设备上的多人游戏。这些只是示例，然而，这两个引擎可以具有广泛的应用，包括迷你地图、多重视角、菜单系统等等。更多关于设置这些类型`Engine`对象的详细信息，请参见第四章，*创建分屏游戏*。

# 选择分辨率策略

选择分辨率策略可能是一个敏感的话题，特别是考虑到我们正在处理的平台目前主要运行在从 3 英寸显示屏到 10.1 英寸的设备上。通常，开发者和用户都希望游戏能够占据设备显示的完整宽度和高度，但在某些情况下，我们可能需要仔细选择分辨率策略，以便按照我们开发者的意愿正确显示场景。在本节中，我们将讨论 AndEngine 中包含的各种分辨率策略，这将帮助我们决定哪种策略可能最适合我们应用程序的需求。

## 如何操作…

我们选择遵循的分辨率策略必须作为参数包含在`EngineOptions`构造函数中，该函数是在 AndEngine 生命周期中的`onCreateEngineOptions()`方法里创建的。以下代码使用`FillResolutionPolicy`类创建我们的`EngineOptions`对象，这一部分将在本章后面进行解释：

```kt
EngineOptions engineOptions = new EngineOptions(true,
    ScreenOrientation.LANDSCAPE_FIXED, new FillResolutionPolicy(),
    mCamera); 
```

我们只需向构造函数传递另一个分辨率策略类变体，就可以选择不同的分辨率策略。

## 它的工作原理…

以下是 AndEngine 的`BaseResolutionPolicy`子类型的概述。这些策略用于指定 AndEngine 如何根据各种因素处理应用程序的显示宽度和高度：

+   `FillResolutionPolicy`：如果我们只是希望应用程序占据显示器的全部宽度和高度，`FillResolutionPolicy`类是典型的分辨率策略。虽然此策略允许应用程序以真正的全屏模式运行，但它可能会导致场景为了占据显示器的全部可用尺寸而在某些部分产生明显的拉伸。我们只需在`EngineOptions`构造函数中的分辨率策略参数中包含`new FillResolutionPolicy()`，即可选择此分辨率策略。

+   `FixedResolutionPolicy`：`FixedResolutionPolicy`类允许我们为应用程序应用固定的显示尺寸，无论设备显示尺寸或`Camera`对象尺寸如何。此策略可以通过`new FixedResolutionPolicy(pWidth, pHeight)`传递给`EngineOptions`，其中`pWidth`定义了应用程序视图将覆盖的最终宽度，而`pHeight`定义了应用程序视图将覆盖的最终高度。例如，如果我们向此策略类型的构造函数传递 800 的宽度和 480 的高度，在一个分辨率为 1280 x 752 的平板电脑上，由于分辨率策略与实际显示尺寸之间没有补偿，我们将得到一个空白黑色区域。

+   `RatioResolutionPolicy`：如果需要在不扭曲精灵的情况下获得最大显示尺寸，`RatioResolutionPolicy`类是最佳的分辨率策略选择。另一方面，由于 Android 设备范围广泛，涵盖了许多显示尺寸，某些设备可能会在显示的顶部和底部，或左右两侧看到“黑边”。此分辨率策略的构造函数可以传递一个`float`值，用于定义显示尺寸的首选比率值，或者传递宽度和高度参数，从中通过宽度除以高度来提取比率值。例如，`new RatioResolutionPolicy(1.6f)`来定义一个比率，或者`new RatioResolutionPolicy(mCameraWidth, mCameraHeight)`，假设`mCameraWidth`和`mCameraHeight`是定义的`Camera`对象尺寸。

+   `RelativeResolutionPolicy`：这是最终的分辨率策略。该策略允许我们根据缩放因子对整个应用程序视图进行放大或缩小，`1f`是默认值。我们可以使用构造函数对视图应用一般缩放——`new RelativeResolutionPolicy(1.5f)`——这将使宽度和高度都增加`1.5`倍；或者我们可以指定单独的宽度和高度缩放比例，例如，`new RelativeResolutionPolicy(1.5f, 0.5f)`。需要注意的是，在使用此策略时，我们必须小心缩放因子，因为过大的缩放会导致应用程序在无警告的情况下关闭。尽量保持缩放因子小于`1.8f`；否则，请确保在各种设备上进行大量测试。

# 创建对象工厂

对象工厂是在编程的各个领域中都有使用的有用设计模式。特别是在游戏开发中，工厂可能被用来生成敌人对象、生成子弹对象、粒子效果、物品对象等等。实际上，AndEngine 在创建声音、音乐、纹理和字体等时也使用了工厂模式。在这个示例中，我们将了解如何创建一个对象工厂，并讨论如何在我们自己的项目中使用它们来简化对象创建。

## 准备工作

请参考代码包中名为`ObjectFactory`的类。

## 如何操作…

在这个示例中，我们使用`ObjectFactory`类作为我们轻松创建和返回`BaseObject`类子类型的方式。然而，在实际项目中，工厂通常不会包含内部类。

1.  在我们创建对象工厂之前，我们应该创建我们的基类以及至少几个扩展基类的子类型：

    ```kt
    public static class BaseObject {

      /* The mX and mY variables have no real purpose in this recipe, however in
       * a real factory class, member variables might be used to define position,
       * color, scale, and more, of a sprite or other entity.   */
      private int mX;
      private int mY;

      // BaseObject constructor, all subtypes should define an mX and mY value on creation
      BaseObject(final int pX, final int pY){
        this.mX = pX;
        this.mY = pY;
      }
    }
    ```

1.  一旦我们拥有一个带有任意数量的子类型的基类，我们现在可以开始考虑实现工厂设计模式。`ObjectFactory`类包含处理创建并返回类型为`LargeObject`和`SmallObject`对象的方法：

    ```kt
    public class ObjectFactory {

      // Return a new LargeObject with the defined 'x' and 'y' member variables.
      public static LargeObject createLargeObject(final int pX, final int pY){
        return new LargeObject(pX, pY);
      }
      // Return a new SmallObject with the defined 'x' and 'y' member variables.
      public static SmallObject createSmallObject(final int pX, final int pY){
        return new SmallObject(pX, pY);
      }
    }
    ```

## 它的工作原理是…

在这个示例的第一步中，我们创建了一个`BaseObject`类。这个类包括两个成员变量`mX`和`mY`，如果我们处理的是 AndEngine 实体，可以想象它们将定义设备显示上的位置。一旦我们设置好了基类，就可以开始创建基类的子类型。这个示例中的`BaseObject`类有两个内部类扩展它，一个名为`LargeObject`，另一个名为`SmallObject`。对象工厂的工作是确定我们需要创建的基类的哪个子类型，以及定义对象的属性，或者在这个实例中是`mX`和`mY`成员变量。

在第二步中，我们将查看`ObjectFactory`代码。这个类应该包含与工厂处理的具体对象类型相关的任何对象创建的变化。在这种情况下，两个独立的对象仅需要一个定义了`mX`和`mY`变量的变量。在现实世界中，我们可能会发现创建一个`SpriteFactory`类很有帮助。这个类可能包含几种不同的方法，用于通过`SpriteFactory.createSprite()`、`SpriteFactory.createButtonSprite()`和`SpriteFactory.createTiledSprite()`创建普通精灵、按钮精灵或平铺精灵。此外，这些方法可能还需要定义位置、缩放、纹理区域、颜色等参数。这个类最重要的方面是它的方法返回一个对象的新子类型，因为这是工厂类背后的整个目的。

# 创建游戏管理器

游戏管理器是大多数游戏的重要组成部分。游戏管理器是一个类，应该包含与游戏玩法相关的数据；包括但不限于跟踪分数、信用/货币、玩家健康和其他一般游戏信息。在本主题中，我们将研究一个游戏管理器类，以了解它们如何融入我们的游戏结构。

## 准备就绪

请参考代码包中名为`GameManager`的类。

## 如何操作…

我们将要介绍的游戏管理器将遵循单例设计模式。这意味着在整个应用程序生命周期中，我们只创建类的单个实例，并且可以在整个项目中访问其方法。按照以下步骤操作：

1.  创建游戏管理器单例：

    ```kt
    private static GameManager INSTANCE;

    // The constructor does not do anything for this singleton
    GameManager(){
    }

    public static GameManager getInstance(){
      if(INSTANCE == null){
        INSTANCE = new GameManager();
      }
      return INSTANCE;
    }
    ```

1.  创建成员变量以及相应的获取器和设置器，以跟踪游戏数据：

    ```kt
    // get the current score
    public int getCurrentScore(){
      return this.mCurrentScore;
    }

    // get the bird count
    public int getBirdCount(){
      return this.mBirdCount;
    }

    // increase the current score, most likely when an enemy is destroyed
    public void incrementScore(int pIncrementBy){
      mCurrentScore += pIncrementBy;
    }

    // Any time a bird is launched, we decrement our bird count
    public void decrementBirdCount(){
      mBirdCount -= 1;
    }
    ```

1.  创建一个重置方法，将所有数据恢复到它们的初始值：

    ```kt
    // Resetting the game simply means we must revert back to initial values.
    public void resetGame(){
      this.mCurrentScore = GameManager.INITIAL_SCORE;
      this.mBirdCount = GameManager.INITIAL_BIRD_COUNT;
      this.mEnemyCount = GameManager.INITIAL_ENEMY_COUNT;
    }
    ```

## 它是如何工作的…

根据创建的游戏类型，游戏管理器肯定有不同的任务。这个示例的`GameManager`类旨在模仿某个情感鸟品牌的类。我们可以看到，这个特定`GameManager`类中的任务有限，但随着游戏玩法的复杂化，游戏管理器通常会增长，因为它需要跟踪更多信息。

在这个配方的第一步中，我们将`GameManager`类设置为单例模式。单例是一种设计模式，旨在确保整个应用程序生命周期中只存在一个静态的此类实例。由于其静态特性，我们可以全局调用游戏管理器的方法，这意味着我们可以在项目中任何类中访问其方法，而无需创建新的`GameManager`类。为了获取`GameManager`类的实例，我们可以在项目的任何类中调用`GameManager.getInstance()`。这样做将会在`GameManager`类尚未被引用的情况下，为其分配一个新的`GameManager`类给`INSTANCE`。然后返回`INSTANCE`对象，这样我们就可以调用`GameManager`类中的数据修改方法，例如`GameManager.getInstance().getCurrentScore()`。

在第二步中，我们创建了用于修改和获取存储在`GameManager`类中的数据的 getter 和 setter 方法。这个配方中的`GameManager`类包含三个`int`值，用于跟踪重要的游戏数据：`mCurrentScore`（当前得分）、`mBirdCount`（鸟类计数）和`mEnemyCount`（敌人计数）。这些变量各自都有对应的 getter 和 setter，使我们能够轻松地修改游戏数据。在游戏过程中，如果有一个敌人被摧毁，我们可以调用`GameManager.getInstance().decrementEnemyCount()`以及`GameManager.getInstance().incrementScore(pValue)`，其中`pValue`可能由被摧毁的敌人对象提供。

设置这个游戏管理器的最后一步是提供一个重置游戏数据的方法。由于我们使用的是单例模式，无论我们是从小游戏转到主菜单、商店还是其他任何场景，`GameManager`类的数据都不会自动恢复到默认值。这意味着每次重置关卡时，我们也必须重置游戏管理器的数据。在`GameManager`类中，我们设置了一个名为`resetGame()`的方法，其作用是简单地将数据恢复到原始值。

当开始一个新关卡时，我们可以调用`GameManager.getInstance().resetGame()`以快速将所有数据恢复到初始值。然而，这是一个通用的`GameManager`类，具体哪些数据应该在关卡重置或加载时重置完全由开发者决定。如果`GameManager`类存储了信用/货币数据，例如在商店中使用时，最好不要将这个特定变量重置回默认值。

# 引入声音和音乐。

声音和音乐在游戏玩法中对用户起着重要作用。如果使用得当，它们可以给游戏带来额外的优势，让玩家在玩游戏时能够完全沉浸其中。另一方面，如果使用不当，它们也可能引起烦恼和不满。在这个配方中，我们将深入探讨 AndEngine 中的`Sound`和`Music`对象，涵盖从加载它们到修改它们的速率等内容。

## 准备工作

完成本章提供的*了解生命周期*配方，以便我们在 IDE 中设置一个基本的 AndEngine 项目。此外，我们应在项目的`assets/`文件夹中创建一个新的子文件夹。将此文件夹命名为`sfx`，并添加一个名为`sound.mp3`的声音文件，以及另一个名为`music.mp3`的文件。完成这些操作后，继续阅读*如何操作…*部分。

## 如何操作…

执行以下步骤，设置游戏以使用`Sound`和`Music`对象。请注意，`Sound`对象用于声音效果，例如爆炸、碰撞或其他短音频播放事件。而`Music`对象用于长时间音频播放事件，如循环菜单音乐或游戏音乐。

1.  第一步是确保我们的`Engine`对象认识到我们计划在游戏中使用`Sound`和`Music`对象。在创建`EngineOptions`对象之后，在我们的活动生命周期的`onCreateEngineOptions()`方法中添加以下几行：

    ```kt
    engineOptions.getAudioOptions().setNeedsMusic(true);
    engineOptions.getAudioOptions().setNeedsSound(true);
    ```

1.  在第二步中，我们将为声音和音乐工厂设置资源路径，然后加载`Sound`和`Music`对象。`Sound`和`Music`对象是资源，所以你可能已经猜到，以下代码可以放入我们活动生命周期的`onCreateResources()`方法中：

    ```kt
    /* Set the base path for our SoundFactory and MusicFactory to
      * define where they will look for audio files.
     */
    SoundFactory.setAssetBasePath("sfx/");
    MusicFactory.setAssetBasePath("sfx/");

    // Load our "sound.mp3" file into a Sound object
    try {
      Sound mSound = SoundFactory.createSoundFromAsset(getSoundManager(), this, "sound.mp3");
    } catch (IOException e) {
      e.printStackTrace();
    }

    // Load our "music.mp3" file into a music object
    try {
      Music mMusic = MusicFactory.createMusicFromAsset(getMusicManager(), this, "music.mp3");
    } catch (IOException e) {
      e.printStackTrace();
    }
    ```

1.  一旦`Sound`对象被加载到`SoundManager`类中，我们就可以根据需要通过调用`play()`来播放它们，无论是碰撞时、按钮点击还是其他情况：

    ```kt
    // Play the mSound object
    mSound.play();
    ```

1.  `Music`对象应该与`Sound`对象以不同的方式处理。在大多数情况下，如果我们的`Music`对象应该在游戏中持续循环，我们应在活动生命周期内处理所有的`play()`和`pause()`方法：

    ```kt
    /* Music objects which loop continuously should be played in
    * onResumeGame() of the activity life cycle
    */
    @Override
    public synchronized void onResumeGame() {
      if(mMusic != null && !mMusic.isPlaying()){
        mMusic.play();
      }

      super.onResumeGame();
    }

    /* Music objects which loop continuously should be paused in
    * onPauseGame() of the activity life cycle
    */
    @Override
    public synchronized void onPauseGame() {
      if(mMusic != null && mMusic.isPlaying()){
        mMusic.pause();
      }

      super.onPauseGame();
    }
    ```

## 工作原理…

在这个配方的第一步，我们需要让引擎知道我们是否将利用 AndEngine 播放`Sound`或`Music`对象的能力。如果忽略这一步，将导致应用程序出现错误，因此在我们将音频实现到游戏中之前，请确保在`onCreateEngineOptions()`方法中返回`EngineOptions`之前完成这一步。

在第二步中，我们访问应用程序生命周期的`onCreateResources()`方法。首先，我们设置了`SoundFactory`和`MusicFactory`的基路径。如*准备就绪*部分所述，我们应在项目的`assets/sfx`文件夹中为我们的音频文件保留一个文件夹，其中包含所有音频文件。通过在两个用于音频的工厂类上调用`setAssetBasePath("sfx/")`，我们现在指向了查找音频文件的正确文件夹。完成此操作后，我们可以通过使用`SoundFactory`类加载`Sound`对象，以及通过使用`MusicFactory`类加载`Music`对象。`Sound`和`Music`对象要求我们传递以下参数：根据我们正在加载的音频对象类型选择`mEngine.getSoundManager()`或`mEngine.getMusicManager()`，`Context`类即`BaseGameActivity`，或者是这个活动，以及音频文件名称的字符串格式。

在第三步中，我们现在可以对希望播放的音频对象调用`play()`方法。但是，这个方法应该在`onCreateResources()`回调通知所有资源都已加载之后才能调用。为了安全起见，我们只需在 AndEngine 生命周期的`onCreateResources()`部分之后，不再播放任何`Sound`或`Music`对象。

在最后一步中，我们设置`Music`对象，以便在活动启动时以及从生命周期中调用`onResumeGame()`时调用其`play()`方法。在另一端，在`onPauseGame()`期间，调用`Music`对象的`pause()`方法。在大多数情况下，最好以这种方式设置我们的`Music`对象，特别是由于应用程序中断的最终不可避免性，例如电话或意外弹出点击。这种方法将允许我们的`Music`对象在应用程序失去焦点时自动暂停，并在我们从最小化返回后重新开始执行。

### 注意事项

在这个配方和其他与资源加载相关的配方中，文件名已经被硬编码到代码片段中。这样做是为了增加简单性，但建议使用我们项目的`strings.xml` Android 资源文件，以保持字符串的组织和易于管理。

## 还有更多…

AndEngine 使用 Android 原生的声音类为我们的游戏提供音频娱乐。除了`play()`和`pause()`方法之外，这些类还包含一些额外的方法，允许我们在运行时对音频对象有更多的控制。

### 音乐对象

以下列表包括为`Music`对象提供的方法：

+   `seekTo`：`seekTo(pMilliseconds)`方法允许我们定义特定`Music`对象的音频播放应从哪里开始。`pMilliseconds`等于音频轨道的位置（毫秒），我们希望在调用`Music`对象的`play()`时从此位置开始播放。为了获取`Music`对象的持续时间（毫秒），我们可以调用`mMusic.getMediaPlayer().getDuration()`。

+   `setLooping`：`setLooping(pBoolean)`方法简单定义了`Music`对象在到达持续时间末端后是否应从开始处重新播放。如果`setLooping(true)`，则`Music`对象会持续重复，直到应用程序关闭或调用`setLooping(false)`为止。

+   `setOnCompletionListener`：此方法允许我们在`Music`对象中应用一个监听器，这给了我们待音频完成时执行函数的机会。这是通过向我们的`Music`对象添加`OnCompletionListener`来完成的，如下所示：

    ```kt
    mMusic.setOnCompletionListener(new OnCompletionListener(){
      /* In the event that a Music object reaches the end of its duration,
      * the following method will be called
      */
      @Override
      public void onCompletion(MediaPlayer mp) {
      // Do something pending Music completion
      }
    });
    ```

+   `setVolume`：使用`setVolume(pLeftVolume, pRightVolume)`方法，我们可以独立调整左和右立体声通道。音量控制的最低和最高范围等于`0.0f`（无音量）和`1.0f`（全音量）。

### Sound 对象

以下列表包括为`Sound`对象提供的方法： 

+   `setLooping`：具体详情请参阅上文`Music`对象的`setLooping`方法的描述。此外，`Sound`对象允许我们使用`mSound.setLoopCount(pLoopCount)`设置音频轨道循环的次数，其中`pLoopCount`是一个定义循环次数的`int`值。

+   `setRate`：`setRate(pRate)`方法允许我们定义`Sound`对象的播放速率或速度，其中`pRate`等于浮点值表示的速率。默认速率为`1.0f`，降低速率会降低音频音调，提高速率会增加音频音调。请注意，Android API 文档指出，速率接受的范围在`0.5f`至`2.0f`之间。超出此范围可能会在播放时产生错误。

+   `setVolume`：具体详情请参阅上文`Music`对象的`setVolume`方法的描述。

### 注意

对于那些不擅长音频创作的我们来说，有许多免费资源可供使用。网上有许多免费的音频数据库，我们可以在公共项目中使用，例如[`www.soundjay.com`](http://www.soundjay.com)。请注意，大多数免费使用的数据库要求对使用的文件进行署名。

# 处理不同类型的纹理

了解如何管理纹理应该是每位游戏开发者的主要优先任务之一。当然，仅了解纹理的基础知识也是可以制作游戏的，但长远来看，这很可能会导致性能问题、纹理溢出和其他不希望出现的结果。在本教程中，我们将探讨如何将纹理构建到游戏中，以提供效率，同时减少纹理填充问题出现的可能性。

## 准备工作

执行本章中给出的*了解生命周期*教程，以便我们在 IDE 中设置了一个基本的 AndEngine 项目。此外，此教程需要三个 PNG 格式的图像。第一个矩形命名为`rectangle_one.png`，宽 30 像素，高 40 像素。第二个矩形命名为`rectangle_two.png`，宽 40 像素，高 30 像素。最后一个矩形命名为`rectangle_three.png`，宽 70 像素，高 50 像素。将这些矩形图像添加到项目的`assets/gfx/`文件夹后，继续进行*如何操作…*部分。

## 如何操作…

在 AndEngine 中构建纹理时涉及两个主要组成部分。在以下步骤中，我们将创建一个所谓的纹理图集，它将存储在*准备工作*部分提到的三个矩形 PNG 图像中的三个纹理区域。

1.  此步骤是可选的。我们将`BitmapTextureAtlasTextureRegionFactory`类指向我们的图像所在的文件夹。默认情况下，工厂指向`assets/`文件夹。通过在工厂的默认基本路径后附加`gfx/`，现在它将在`assets/gfx/`中查找我们的图像：

    ```kt
    BitmapTextureAtlasTextureRegionFactory.setAssetBasePath("gfx/");
    ```

1.  接下来，我们将创建`BitmapTextureAtlas`。纹理图集可以看作是包含许多不同纹理的地图。在这种情况下，我们的“地图”或`BitmapTextureAtlas`的大小将为 120 x 120 像素：

    ```kt
    // Create the texture atlas at a size of 120x120 pixels
    BitmapTextureAtlas mBitmapTextureAtlas = new BitmapTextureAtlas(mEngine.getTextureManager(), 120, 120);
    ```

1.  当我们有了`BitmapTextureAtlas`可以使用时，现在可以创建我们的`ITextureRegion`对象，并将它们放置在`BitmapTextureAtlas`纹理中的特定位置。我们将使用`BitmapTextureAtlasTextureRegionFactory`类，它帮助我们绑定 PNG 图像到特定的`ITextureRegion`对象，并在我们上一步创建的`BitmapTextureAtlas`纹理图集中定义一个位置来放置`ITextureRegion`对象：

    ```kt
    /* Create rectangle one at position (10, 10) on the mBitmapTextureAtlas */
    ITextureRegion mRectangleOneTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, this, "rectangle_one.png", 10, 10);

    /* Create rectangle two at position (50, 10) on the mBitmapTextureAtlas */
    ITextureRegion mRectangleTwoTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, this, "rectangle_two.png", 50, 10);

    /* Create rectangle three at position (10, 60) on the mBitmapTextureAtlas */
    ITextureRegion mRectangleThreeTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, this, "rectangle_three.png", 10, 60);
    ```

1.  最后一步是将我们的`ITextureRegion`对象加载到内存中。我们可以通过调用包含所述`ITextureRegion`对象的`BitmapTextureAtlas`图集来实现这一点：

    ```kt
    mBitmapTextureAtlas.load();
    ```

## 工作原理…

在 AndEngine 开发中，为了给我们的项目创建纹理，我们将使用两个主要组件。第一个组件被称为`BitmapTextureAtlas`，可以将其视为一个具有最大宽度和高度的平面，可以在其宽度和高度范围内存储子纹理。这些子纹理被称为纹理区域，或者具体到 AndEngine 中是`ITextureRegion`对象。`ITextureRegion`对象的目的仅是作为对内存中特定纹理的引用，该纹理位于`BitmapTextureAtlas`图集中的 x 和 y 位置。看待这两个组件的一种方式是想象一块空白的画布，这代表纹理图集，以及一把贴纸，这些将代表纹理区域。画布会有一个最大尺寸，在这个区域内我们可以将贴纸放在任何我们想要的地方。有了这个想法，我们在画布上放置了一把贴纸。现在，我们所有的贴纸都整齐地摆放在这个画布上，我们可以随时取用并放置到任何我们想要的地方。还有一些更细节的内容，但这会在稍后介绍。

了解了`BitmapTextureAtlas`和`ITextureRegion`对象的基础知识之后，创建我们纹理的步骤现在应该更有意义了。如第一步所述，设置`BitmapTextureAtlasTextureRegionFactory`类的基路径是完全可选的。我们包含这一步只是因为它让我们无需在创建`ITextureRegion`对象时重复说明我们的图像位于哪个文件夹。例如，如果我们不设置基路径，我们就必须以`gfx/rectangle_one.png`、`gfx/rectangle_two.png`等方式引用我们的图像。

在第二步中，我们创建`BitmapTextureAtlas`对象。这一步相当直接，因为我们只需指定引擎的`TextureManager`对象来处理纹理加载，以及纹理图集的宽度和高度，按此顺序。由于在这些步骤中我们只处理三个小图像，120x120 像素就非常合适。

关于纹理图集，有一点非常重要，那就是永远不要创建过多的纹理图集；比如，不要为了存放一个 32x32 像素的单个图像而创建一个 256x256 的图集。另一个重要点是，避免创建超过 1024x1024 像素的纹理图集。安卓设备在最大纹理尺寸上各不相同，尽管有些设备可能能够存储高达 2048x2048 像素的纹理，但大量设备的最大限制是 1024x1024。超过最大纹理尺寸将会导致在启动时强制关闭，或者在特定设备上无法正确显示纹理。如果没有其他选择，确实需要大图像，请参考第四章中的*背景拼接*部分，*使用摄像头*。

在这个食谱的第三步中，我们正在创建我们的`ITextureRegion`对象。换句话说，我们正在将指定的图像应用到`mBitmapTextureAtlas`对象上，并定义该图像在图集中的确切位置。使用`BitmapTextureAtlasTextureRegionFactory`类，我们可以调用`createFromAsset(pBitmapTextureAtlas, pContext, pAssetPath, pTextureX, pTextureY)`方法，这使得创建纹理区域变得轻而易举。从左到右列出参数的顺序，`pBitmapTextureAtlas`参数指定了希望存储`ITextureRegion`对象的纹理图集。`pContext`参数允许类从`gfx/`文件夹中打开图像。`pAssetPath`参数定义了我们正在寻找的特定文件的名称，例如`rectangle_one.png`。最后的两个参数，`pTextureX`和`pTextureY`，定义了放置`ITextureRegion`对象的纹理图集上的位置。以下图像表示在第三步中定义的三个`ITextureRegion`对象的样子。请注意，代码和图像之间的位置是一致的：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_01_2.jpg)

在前一个图像中，请注意，每个矩形与纹理边缘之间至少有 10 个像素的间隔。`ITextureRegion`对象并不是像这样间隔开来以使事物更易于理解，尽管这样做有帮助。实际上，它们是间隔开来的，以便添加所谓的**纹理图集源间隔**。这种间隔的作用是防止在将纹理应用到精灵时发生纹理重叠。这种重叠被称为**纹理溢出**。尽管按照本食谱创建的纹理并不能完全消除纹理溢出的可能性，但在将某些纹理选项应用于纹理图集时，它确实降低了这个问题发生的可能性。

想了解更多关于纹理选项的信息，请参阅本章中提供的*应用纹理选项*食谱。此外，本主题中的*还有更多...*部分描述了创建纹理图集的另一种方法，这种方法完全解决了纹理溢出的问题！强烈推荐。

## 还有更多内容…

当涉及到将纹理添加到我们的游戏时，我们可以采取多种不同的方法。它们都有自己的优点，有些甚至涉及到负面因素。

### BuildableBitmapTextureAtlas

`BuildableBitmapTextureAtlas`对象是一种将`ITextureRegion`对象实现到我们的纹理图集中的便捷方式，无需手动定义位置。`BuildableBitmapTextureAtlas`纹理图集的目的是通过将它们放置到最方便的坐标上来自动放置其`ITextureRegion`对象。这种创建纹理的方法是最简单且最高效的，因为当构建包含许多纹理图集的大型游戏时，这种方法可能会节省时间，有时甚至可以避免错误。除了`BuildableBitmapTextureAtlas`的自动化之外，它还允许开发者定义纹理图集源的透明边距，从而消除纹理溢出的任何情况。这是 AndEngine 的 GLES 1.0 分支中最突出的视觉问题之一，因为当时没有内置方法为纹理图集提供边距。

使用`BuildableBitmapTextureAtlas`图集与`BitmapTextureAtlas`路径略有不同。以下是使用`BuildableBitmapTextureAtlas`图集的此食谱代码：

```kt
/* Create a buildable bitmap texture atlas - same parameters required
* as with the original bitmap texture atlas */
BuildableBitmapTextureAtlas mBuildableBitmapTextureAtlas = new BuildableBitmapTextureAtlas(mEngine.getTextureManager(), 120, 120);

/* Create the three ITextureRegion objects. Notice that when using 
 * the BuildableBitmapTextureAtlas, we do not need to include the final
 * two pTextureX and pTextureY parameters. These are handled automatically! */
ITextureRegion mRectangleOneTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBuildableBitmapTextureAtlas, this, "rectangle_one.png");
ITextureRegion mRectangleTwoTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBuildableBitmapTextureAtlas, this, "rectangle_two.png");
ITextureRegion mRectangleThreeTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBuildableBitmapTextureAtlas, this, "rectangle_three.png");

// Buildable bitmap texture atlases require a try/catch statement
try {
  /* Build the mBuildableBitmapTextureAtlas, supplying a BlackPawnTextureAtlasBuilder
    * as its only parameter. Within the BlackPawnTextureAtlasBuilder's parameters, we
    * provide 1 pixel in texture atlas source space and 1 pixel for texture atlas source
    * padding. This will alleviate the chance of texture bleeding.
    */
  mBuildableBitmapTextureAtlas.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 1, 1));
} catch (TextureAtlasBuilderException e) {
  e.printStackTrace();
}

// Once the atlas has been built, we can now load
mBuildableBitmapTextureAtlas.load();
```

如此代码所示，`BuildableBitmapTextureAtlas`与`BitmapTextureAtlas`图集之间存在一些细微差别。首先要注意的是，在创建我们的`ITextureRegion`对象时，我们不再需要指定纹理区域应在纹理图集上的放置位置。使用`BuildableBitmapTextureAtlas`替代方案时的第二个小变化是，在调用`load()`方法之前，我们必须在`mBuildableBitmapTextureAtlas`上调用`build(pTextureAtlasBuilder)`方法。在`build(pTextureAtlasBuilder)`方法中，我们必须提供一个`BlackPawnTextureAtlasBuilder`类，定义三个参数。按顺序，这些参数是`pTextureAtlasBorderSpacing`、`pTextureAtlasSourceSpacing`和`pTextureAtlasSourcePadding`。在上述代码片段中，我们几乎可以消除所有情况下的纹理溢出可能性。然而，在极端情况下，如果仍有纹理溢出，只需增加第三个参数，这将有助于解决任何问题。

### 纹理区域块

纹理区域块本质上与普通纹理区域是相同的对象。两者的区别在于，纹理区域块允许我们传递一个图像文件并从中创建一个精灵表。这是通过指定我们精灵表中的列数和行数来完成的。从此，AndEngine 将自动将纹理区域块均匀分布成段。这将允许我们在`TiledTextureRegion`对象中导航每个段。这就是纹理区域块如何表现为创建具有动画的精灵的样子。

![纹理区域块](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_01_3.jpg)

### 注意

实际的精灵表不应该在每列和每行周围有轮廓。在上一张图片中它们是为了显示如何将精灵表划分为等分段。

假设前面的图像宽度为 165 像素，高度为 50 像素。由于我们有 11 个单独的列和单行，我们可以像这样创建`TiledTextureRegion`对象：

```kt
TiledTextureRegion mTiledTextureRegion = BitmapTextureAtlasTextureRegionFactory.createTiledFromAsset(mBitmapTextureAtlas, context,"sprite_sheet.png",11,1);
```

这段代码的作用是告诉 AndEngine 将`sprite_sheet.png`图像划分为`11`个独立的部分，每个部分宽度为 15 像素（因为 165 像素除以 11 个部分等于 15）。现在我们可以使用这个分块纹理区域对象实例化一个带有动画的精灵。

### 压缩纹理

除了更常见的图像类型（`.bmp`、`.jpeg`和`.png`），AndEngine 还内置了对 PVR 和 ETC1 压缩纹理的支持。使用压缩纹理的主要好处是它对减少加载时间和可能在游戏过程中提高帧率的影响。就此而言，使用压缩纹理也有缺点。例如，ETC1 不支持在其纹理中使用 alpha 通道。压缩纹理也可能导致纹理质量明显下降。这些类型纹理的使用应与压缩纹理所表示的对象的重要性相关。你很可能不希望将整个游戏的纹理格式基于压缩纹理，但对于大量微妙的图像，使用压缩纹理可以为你的游戏带来明显的性能提升。

## 另请参阅

+   本章中的*创建资源管理器*。

+   本章中的*应用纹理选项*。

# 应用纹理选项

我们已经讨论了 AndEngine 提供的不同类型的纹理；现在让我们看看我们可以为纹理提供哪些选项。这个主题的内容往往会对我们游戏的质量和性能产生显著影响。

## 准备就绪

执行本章中提供的*处理不同类型的纹理*的步骤，以便我们使用`BitmapTextureAtlas`或`BuildableBitmapTextureAtlas`加载，设置了一个基本的 AndEngine 项目。

## 如何操作…

为了修改纹理图集的选项和/或格式，我们需要根据是否要定义选项、格式或两者都定义，向`BitmapTextureAtlas`构造函数中添加一个或两个参数。以下是修改纹理格式和纹理选项的代码：

```kt
BitmapTextureAtlas mBitmapTextureAtlas = new BitmapTextureAtlas(mEngine.getTextureManager(), 1024, 1024, BitmapTextureFormat.RGB_565, TextureOptions.BILINEAR);
```

从这里开始，放置在此特定纹理图集中的所有纹理区域都将应用定义的纹理格式和选项。

## 工作原理…

AndEngine 允许我们为纹理图集应用纹理选项和格式。应用于纹理图集的各种选项和格式的组合将影响精灵对我们游戏的整体质量和性能影响。当然，如果提到的精灵使用了与修改后的`BitmapTextureAtlas`图集相关的`ITextureRegion`对象，情况也是如此。

AndEngine 中可用的基本纹理选项如下：

+   **最近邻**：此纹理选项默认应用于纹理图集。这是我们能够应用在纹理图集中的最快性能的纹理选项，但也是质量最差的。这个选项意味着纹理将通过获取与像素最近的纹理元素颜色来应用构成显示的像素的混合。类似于像素代表数字图像的最小元素，**纹理元素（texel）**代表纹理的最小元素。

+   **双线性**：AndEngine 中的第二个主要的纹理过滤选项称为双线性纹理过滤。这种方法在性能上会有所下降，但缩放后精灵的质量将提高。双线性过滤获取每个像素的四个最近的纹理元素，以提供更平滑的屏幕图像混合。

请查看以下图表，以比较双线性过滤和最近邻过滤：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_01_4.jpg)

这两张图像以最高的位图格式渲染。在这种情况下，最近邻与双线性过滤之间的区别非常明显。在图像的左侧，双线性星星几乎看不到锯齿边缘，颜色非常平滑。在右侧，我们得到了一个使用最近邻过滤渲染的星星。由于锯齿边缘更加明显，质量水平受到影响，如果仔细观察，颜色也不够平滑。

以下是几个额外的纹理选项：

**重复**：重复纹理选项允许精灵“重复”纹理，假设精灵的大小超出了`ITextureRegion`对象的宽度和高度。在大多数游戏中，地形通常是通过创建重复纹理并拉伸精灵的大小来生成的，而不是创建许多独立的精灵来覆盖地面。

让我们看看如何创建一个重复纹理：

```kt
    /* Create our repeating texture. Repeating textures require width/height which are a power of two */
    BuildableBitmapTextureAtlas texture = new BuildableBitmapTextureAtlas(engine.getTextureManager(), 32, 32, TextureOptions.REPEATING_BILINEAR);

    // Create our texture region - nothing new here
    mSquareTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(texture, context, "square.png");

    try {
      // Repeating textures should not have padding
      texture.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 0, 0));
      texture.load();

    } catch (TextureAtlasBuilderException e) {
      Debug.e(e);
    }
```

之前的代码基于一个 32 x 32 像素的方形图像。创建重复纹理时需要注意的两点是：

+   使用重复纹理选项格式的纹理图集需要尺寸为 2 的幂（2, 4, 8, 16 等）

+   如果你使用的是可构建的纹理图集，在`build()`方法中不要应用填充或间距，因为这在纹理的重复中会被考虑在内，破坏了重复纹理的第一个规则。

接下来，我们需要创建一个使用这种重复纹理的精灵：

```kt
/* Increase the texture region's size, allowing repeating textures to stretch up to 800x480 */
ResourceManager.getInstance().mSquareTextureRegion.setTextureSize(800, 480);
// Create a sprite which stretches across the full screen
Sprite sprite = new Sprite(0, 0, 800, 480, ResourceManager.getInstance().mSquareTextureRegion, mEngine.getVertexBufferObjectManager());
```

我们在这里所做的的是将纹理区域的尺寸增加到 800 x 480 像素。这并不会改变应用了重复选项的纹理图像的大小，而是允许图像最多重复至 800 x 480 像素。这意味着，如果我们创建了一个精灵并提供了重复纹理，我们可以将精灵的尺寸缩放到 800 x 480 像素，同时仍然显示重复效果。然而，如果精灵超出了纹理区域的宽度或高度尺寸，超出区域将不应用纹理。

这是来自设备截图的结果：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_01_5.jpg)

**预乘透明度**：最后，我们有一个选项可以将预乘透明度纹理选项添加到我们的纹理中。这个选项的作用是将每个 RGB 值乘以指定的透明通道，然后在最后应用透明通道。这个选项的主要目的是让我们能够修改颜色的不透明度而不会损失颜色。请记住，直接修改带有预乘透明度值的精灵的透明度值可能会产生不想要的效果。当这个选项应用于透明度为`0`的精灵时，精灵可能不会完全透明。

当将纹理选项应用到我们的纹理图集时，我们可以选择最近邻或双线性纹理过滤选项。除了这些纹理过滤选项，我们还可以选择重复选项、预乘透明度选项，或者两者都选。

## 还有更多…

除了纹理选项，AndEngine 还允许我们设置每个纹理图集的纹理格式。纹理格式，类似于纹理选项，通常根据其用途来决定。纹理的格式可以极大地影响图像的性能和质量，甚至比纹理选项更明显。纹理格式允许我们选择纹理图集中 RGB 值的可用颜色范围。根据所使用的纹理格式，我们还可能允许或不允许精灵具有任何透明度值，这会影响纹理的透明度。

纹理格式的命名约定并不复杂。所有格式的名称类似于**RGBA_8888**，下划线左侧指的是纹理可用的颜色或透明通道。下划线右侧指的是每个颜色通道可用的位数。

### 纹理格式

以下是可以使用的纹理格式：

+   `RGBA_8888`：允许纹理使用红色、绿色、蓝色和透明通道，每个通道分配 8 位。由于我们有 4 个通道，每个通道分配 8 位（4 x 8），我们得到一个 32 位的纹理格式。这是这四种格式中最慢的纹理格式。

+   `RGBA_4444`：允许纹理使用红色、绿色、蓝色和透明通道，每个通道分配 4 位。按照与前一个格式相同的规则，我们得到一个 16 位的纹理格式。与`RGBA_8888`相比，你会注意到这个格式的改进，因为我们保存的信息量只有 32 位格式的一半。质量将明显受损；请看以下图片：![纹理格式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_01_6.jpg)

    在这张图片中，我们比较了两种纹理格式的差异。两颗星星都使用默认的纹理选项（最近邻）进行渲染，这与图像的 RGBA 格式无关。我们更感兴趣的是两颗星星的颜色质量。左侧的星星以全 32 位颜色能力进行渲染，右侧的则是 16 位。两颗星星之间的差异相当明显。

+   `RGB_565`：这是另一种 16 位的纹理格式，不过它不包括透明通道；使用这种纹理格式的纹理将不支持透明度。由于缺乏透明度，这种格式的需求有限，但它仍然很有价值。这种纹理格式的一个使用场景是显示全屏图像，如背景。背景不需要透明度，因此在引入背景时，记住这种格式是明智的。这样节省的性能相当明显。

    ### 提示

    `RGB_565`格式的颜色质量与之前展示的`RGBA_4444`星形图像大致相同。

+   `A_8`：最后，我们来看最后一种纹理格式，它是 8 位的透明通道（不支持颜色）。这也是一种使用范围有限的格式；A_8 格式通常用作具有颜色的精灵的透明遮罩（叠加）。这种格式的一个使用例子是，通过简单地叠加这种纹理的精灵，然后随着时间的推移改变透明度，使屏幕渐变出现或消失。

在创建纹理图集时，考虑哪些类型的精灵将使用哪种类型的纹理区域，并据此将它们打包到纹理图集中是一个好主意。对于较重要的精灵，我们很可能会选择使用`RGBA_8888`纹理格式，因为这些精灵将是我们游戏的主要焦点。这些对象可能包括前景精灵、主角精灵或屏幕上任何视觉上更突出的物体。背景覆盖了设备整个表面区域，所以我们很可能不需要透明度。对于这些精灵，我们将使用`RGB_565`以移除透明通道，这将有助于提高性能。最后，我们有那些可能颜色不多、可能较小或只是不需要太多视觉吸引力的物体。对于这类精灵，我们可以使用`RGBA_4444`纹理格式，以减少这些纹理所需的内存一半。

## 参见

+   本章了解*生命周期*。

+   本章介绍*不同类型的纹理*的处理方法。

+   在第二章中，*使用实体*，介绍了如何通过精灵使场景*生动起来*。

# 使用 AndEngine 字体资源

AndEngine 字体设置简单，可以包含在我们的`Text`对象中使用，显示在屏幕上。我们可以选择预设字体，也可以通过`assets`文件夹添加自己的字体。

## 准备就绪

执行本章提供的*了解生命周期*的步骤，这样我们就可以在 IDE 中设置基本的 AndEngine 项目，然后继续阅读*如何操作…*部分。

## 如何操作…

下面的代码片段展示了创建预设、自定义资源、预设描边和自定义资源描边字体对象的四种不同选项。字体创建应该在`BaseGameActivity`类的`onCreateResources()`方法中进行。

+   预设字体的`create()`方法如下：

    ```kt
    Font mFont = FontFactory.create(mEngine.getFontManager(), mEngine.getTextureManager(), 256, 256, Typeface.create(Typeface.DEFAULT, Typeface.NORMAL),  32f, true, org.andengine.util.adt.color.Color.WHITE_ABGR_PACKED_INT)

    mFont.load();
    ```

+   自定义字体的`createFromAsset()`方法如下：

    ```kt
    Font mFont = FontFactory.createFromAsset(mEngine.getFontManager(), mEngine.getTextureManager(), 256, 256, this.getAssets(), "Arial.ttf", 32f, true, org.andengine.util.adt.color.Color.WHITE_ABGR_PACKED_INT); 

    mFont.load();
    ```

+   描边字体的`createStroke()`和`createStrokeFromAsset()`方法如下：

    ```kt
    BitmapTextureAtlas mFontTexture = new BitmapTextureAtlas(mEngine.getTextureManager(), 256, 256, TextureOptions.BILINEAR);

    Font mFont = FontFactory.createStroke(mEngine.getFontManager(), mFontTexture, Typeface.create(Typeface.DEFAULT, Typeface.BOLD), 32, true, org.andengine.util.adt.color.Color.WHITE_ABGR_PACKED_INT, 3, org.andengine.util.adt.color.Color.BLACK_ABGR_PACKED_INT);

    mFont.load();
    ```

## 工作原理…

如我们所见，根据我们希望字体呈现的效果，我们可以采取不同的方法来创建我们的`Font`对象。然而，所有字体都需要我们定义纹理宽度和纹理高度，无论是直接作为`FontFactory`类`create`方法的参数，还是通过使用`BitmapTextureAtlas`对象间接定义。在之前的代码片段中，我们使用宽度为`256`像素、高度为`256`像素的纹理大小创建了所有三个`Font`对象。不幸的是，目前还没有简单的方法在运行时自动确定所需的纹理大小，以支持不同的语言、文本大小、描边值或字体样式。

目前，最常见的方法是将纹理宽度和高度设置为大约`256`像素，然后向上或向下进行小调整，直到纹理大小刚好合适，不会在`Text`对象中产生伪影。字体大小在确定`Font`对象所需的最终纹理大小中起着最重要的作用，因此非常大的字体，例如 32 及以上，可能需要更大的纹理大小。

### 注意

所有`Font`对象在能够正确显示`Text`对象中的字符之前，都需要调用`load()`方法。

让我们看看*如何操作…*部分中介绍的各种方法是如何工作的：

+   `create()`方法：`create()`方法不允许太多自定义。从第五个参数开始，这个方法的参数包括提供字体样式、字体大小、抗锯齿选项和颜色。我们使用的是 Android 原生字体类，它只支持几种不同的字体和样式。

+   `createFromAsset()`方法：我们可以使用这个方法将自定义字体引入到我们的项目中，通过我们的`assets`文件夹。假设我们有一个叫做`Arial.ttf`的真类型字体位于项目的`assets`文件夹中。我们可以看到，一般的创建过程是相同的。在这个方法中，我们必须传递活动的`AssetManager`类，这可以通过我们活动的`getAssets()`方法获得。接下来的参数是我们想要导入的真类型字体。

+   `createStroke()`和`createStrokeFromAsset()`方法：最后，我们有了描边字体。描边字体使我们能够为`Text`对象中的字符添加轮廓。在这些情况下，当我们希望我们的文本“突出”时，这些字体很有用。为了创建描边字体，我们需要提供一个纹理图集作为第二个参数，而不是传递引擎的纹理管理器。从这个点开始，我们可以通过字体类型或通过我们的`assets`文件夹来创建描边字体。此外，我们还提供了定义两个新颜色值的选项，这两个值作为最后两个参数添加。有了这些新参数，我们能够调整轮廓的厚度以及颜色。

## 还有更多…

`Font`类目前的设置，最好预加载我们期望通过`Text`对象显示的字符。不幸的是，AndEngine 目前在还有新字母要绘制时仍然调用垃圾回收器，因此为了避免`Text`对象首次“熟悉”字母时的卡顿，我们可以调用以下方法：

```kt
mFont.prepareLetters("abcdefghijklmnopqrstuvwxyz".toCharArray())
```

此方法调用将准备从 a 到 z 的小写字母。这个方法应该在游戏加载屏幕期间的某个时刻被调用，以避免任何可察觉的垃圾回收。在离开`Font`对象的话题之前，还有一个重要的类我们应该讨论。AndEngine 包含一个名为`FontUtils`的类，它允许我们通过`measureText(pFont, pText)`方法获取关于`Text`对象在屏幕上的宽度的信息。在处理动态变化的字符串时，这很重要，因为它为我们提供了重新定位`Text`对象的选项，假设字符串的宽度或高度（以像素为单位）已经改变。

## 另请参阅

+   *了解本章中的生命周期*。

+   在本章中*处理不同类型的纹理*。

+   在第二章《*使用实体*》中，将文本应用到图层。

# 创建资源管理器

在本主题中，我们最终将从更大的角度查看我们的资源。有了资源管理器，我们将能够轻松地通过单一、方便的位置，调用如`loadTextures()`、`loadSounds()`或`loadFonts()`等方法，来加载游戏需要的不同类型的资源。

## 准备就绪

请参考代码包中名为`ResourceManager`的类。

## 如何操作…

`ResourceManager`类是以单例设计模式为理念设计的。这允许我们通过简单的调用`ResourceManager.getInstance()`来全局访问我们游戏的所有资源。`ResourceManager`类的主要目的是存储资源对象，加载资源，以及卸载资源。以下步骤展示了我们如何使用`ResourceManager`来处理我们游戏场景之一的纹理。

1.  声明将在我们游戏的不同场景中使用的所有资源：

    ```kt
    /* The variables listed should be kept public, allowing us easy access
    to them when creating new Sprites, Text objects and to play sound files */
    public ITextureRegion mGameBackgroundTextureRegion;
    public ITextureRegion mMenuBackgroundTextureRegion;
    public Sound  mSound;

    public Font  mFont;
    ```

1.  提供处理在`ResourceManager`类中声明的音频、图形和字体资源加载的`load`方法：

    ```kt
    public synchronized void loadGameTextures(Engine pEngine, Context pContext){
    // Set our game assets folder in "assets/gfx/game/"
        BitmapTextureAtlasTextureRegionFactory.setAssetBasePath("gfx/game/");

    BuildableBitmapTextureAtlas mBitmapTextureAtlas = new BuildableBitmapTextureAtlas(pEngine.getTextureManager(), 800, 480);

    mGameBackgroundTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, pContext, "game_background.png");

    try {
      mBitmapTextureAtlas.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 1, 1));
      mBitmapTextureAtlas.load();
    } catch (TextureAtlasBuilderException e) {
      Debug.e(e);
    }
    }
    ```

1.  第三步涉及提供一个与我们的`ResourceManager`类的`load`方法相对应的所有资源的卸载方法：

    ```kt
    public synchronized void unloadGameTextures(){
      // call unload to remove the corresponding texture atlas from memory
      BuildableBitmapTextureAtlas mBitmapTextureAtlas = (BuildableBitmapTextureAtlas) mGameBackgroundTextureRegion.getTexture();
      mBitmapTextureAtlas.unload();

      // ... Continue to unload all textures related to the 'Game' scene

      // Once all textures have been unloaded, attempt to invoke the Garbage Collector
      System.gc();
    }
    ```

## 它是如何工作的…

通过在项目中实现一个`ResourceManager`类，我们可以轻松地完全独立地加载各种场景资源。因此，我们必须确保我们的`public`类方法是同步的，以确保我们在一个线程安全的环境中运行。这对于单例的使用尤为重要，因为我们只有一个类实例，有多个线程访问它的可能性。除此之外，现在我们只需要一行代码即可加载场景资源，这极大地帮助我们的主活动类保持更有条理。以下是使用资源管理器时，我们的`onCreateResources()`方法应该看起来像什么样子：

```kt
@Override
public void onCreateResources(
    OnCreateResourcesCallback pOnCreateResourcesCallback) {

  // Load the game texture resources
  ResourceManager.getInstance().loadGameTextures(mEngine, this);

  // Load the font resources
  ResourceManager.getInstance().loadFonts(mEngine);

  // Load the sound resources
  ResourceManager.getInstance().loadSounds(mEngine, this);

  pOnCreateResourcesCallback.onCreateResourcesFinished();
}
```

在第一步中，我们声明了所有的资源，包括`Font`对象，`ITextureRegion`对象，以及`Sound`/`Music`对象。在这个特定的示例中，我们只处理有限数量的资源，但在一个功能齐全的游戏中，这个类可能包括 50、75，甚至超过 100 个资源。为了从我们的`ResourceManager`类中获取资源，我们只需在任何类中包含以下代码行：

`ResourceManager.getInstance().mGameBackgroundTextureRegion`。

在第二步中，我们创建了`loadGameTextures(pEngine, pContext)`方法，用于加载`Game`场景的纹理。对于游戏中的每个附加场景，我们应该有一个单独的`load`方法。这使得可以轻松地动态加载资源。

在最后一步中，我们创建`unload`方法，处理与每个`load`方法相对应的资源卸载。然而，如果有任何数量的资源在我们的游戏多个场景中使用，可能需要创建一个没有伴随`unload`方法的`load`方法。

## 还有更多…

在较大的项目中，有时我们可能会发现自己频繁地将主要对象传递给类。资源管理器的另一个用途是存储一些更重要的游戏对象，如`Engine`或`Camera`。这样我们就不必不断地将这些对象作为参数传递，而可以调用相应的`get`方法以获取游戏的`Camera`、`Engine`或我们将在类中引用的任何其他特定对象。

## 另请参阅

+   在本章中*引入声音和音乐*。

+   在本章中*处理不同类型的纹理*。

+   在本章中*使用 AndEngine 字体资源*。

# 保存和加载游戏数据

在游戏结构章节的最后一个主题中，我们将设置一个可以在项目中使用的类来管理和设置数据。我们必须保存的更明显的游戏数据应该包括角色状态、高分和其他可能在我们的游戏中包含的各种数据。我们还应该跟踪游戏可能具有的某些选项，例如用户是否静音、血腥效果等。在这个示例中，我们将使用一个名为`SharedPreferences`的类，它将允许我们轻松地将数据保存到设备上，以便在稍后的时间检索。

### 注意

`SharedPreferences`类是快速存储和检索原始数据类型的一种很好的方式。然而，随着数据量的增加，我们用来存储数据的方法的需求也会增加。如果我们的游戏确实需要存储大量数据，可以考虑使用 SQLite 数据库来存储数据。

## 准备工作

请参考代码包中名为`UserData`的类。

## 如何操作…

在这个示例中，我们设置了一个名为`UserData`的类，该类将存储一个布尔变量以决定是否静音，以及一个`int`变量，该变量将定义用户已解锁的最高级别。根据游戏的需求，可能需要在类中包含更多或更少的数据类型，无论是最高分、货币还是其他与游戏相关的数据。以下步骤描述了如何设置一个类，在用户的设备上包含和存储用户数据：

1.  第一步涉及声明我们的常量`String`变量，这些变量将保存对我们偏好文件的引用，以及保存对偏好文件内部数据引用的“键”名称，以及相应的“值”变量。此外，我们还声明了`SharedPreferences`对象以及一个编辑器：

    ```kt
    // Include a 'filename' for our shared preferences
    private static final String PREFS_NAME = "GAME_USERDATA";

    /* These keys will tell the shared preferences editor which
      data we're trying to access */

    private static final String UNLOCKED_LEVEL_KEY = "unlockedLevels";
    private static final String SOUND_KEY = "soundKey";

    /* Create our shared preferences object & editor which will
     be used to save and load data */
    private SharedPreferences mSettings;
    private SharedPreferences.Editor mEditor;

    // keep track of our max unlocked level
    private int mUnlockedLevels;

    // keep track of whether or not sound is enabled
    private boolean mSoundEnabled;
    ```

1.  为我们的`SharedPreferences`文件创建一个初始化方法。这个方法将在我们的游戏首次启动时被调用，如果不存在，则为我们的游戏创建一个新文件，如果存在，则从偏好文件加载现有值：

    ```kt
    public synchronized void init(Context pContext) {
      if (mSettings == null) {
        /* Retrieve our shared preference file, or if it's not yet
          * created (first application execution) then create it now
          */
        mSettings = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        /* Define the editor, used to store data to our preference file
         */
        mEditor = mSettings.edit();

        /* Retrieve our current unlocked levels. if the UNLOCKED_LEVEL_KEY
          * does not currently exist in our shared preferences, we'll create
          * the data to unlock level 1 by default
          */
        mUnlockedLevels = mSettings.getInt(UNLOCKED_LEVEL_KEY, 1);

        /* Same idea as above, except we'll set the sound boolean to true
          * if the setting does not currently exist
          */
        mSoundEnabled = mSettings.getBoolean(SOUND_KEY, true);
      }
    }
    ```

1.  接下来，我们将为那些打算存储在`SharedPreferences`文件中的每个值提供获取方法，以便我们可以在整个游戏中访问数据：

    ```kt
    /* retrieve the max unlocked level value */
    public synchronized int getMaxUnlockedLevel() {
      return mUnlockedLevels;
    }
    ```

1.  最后，我们必须为那些打算存储在`SharedPreferences`文件中的每个值提供设置方法。设置方法将负责将数据保存到设备上：

    ```kt
    public synchronized void unlockNextLevel() {
      // Increase the max level by 1
      mUnlockedLevels++;

      /* Edit our shared preferences unlockedLevels key, setting its
       * value our new mUnlockedLevels value
        */
      mEditor.putInt(UNLOCKED_LEVEL_KEY, mUnlockedLevels);

      /* commit() must be called by the editor in order to save
        * changes made to the shared preference data
       */
      mEditor.commit();
    }
    ```

## 工作原理…

这个类展示了我们如何通过使用`SharedPreferences`类轻松地存储和检索游戏的数据和选项。`UserData`类的结构相当直接，可以以相同的方式使用，以便适应我们可能想要在游戏中包含的各种其他选项。

在第一步中，我们只是开始声明所有必要的常量和成员变量，这些变量我们将用于处理游戏中的不同类型的数据。对于常量，我们有一个名为`PREFS_NAME`的`String`变量，它定义了游戏的偏好文件的名称，还有另外两个`String`变量，它们将分别作为对偏好文件中单个原始数据类型的引用。对于每个键常量，我们应该声明一个相应的变量，当数据第一次加载时，偏好文件数据将存储到这个变量中。

在第二步中，我们提供了从游戏的偏好文件中加载数据的方法。这个方法只需要在游戏启动过程中调用一次，以将`SharedPreferences`文件中的数据加载到`UserData`类的成员变量中。首先调用`context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)`，我们检查是否有针对我们的应用程序在`PREFS_NAME`字符串下的`SharedPreference`文件，如果没有，那么我们将创建一个新的文件——`MODE_PRIVATE`，意味着该文件对其他应用程序不可见。

一旦完成，我们可以从偏好文件中调用获取器方法，如`mUnlockedLevels = mSettings.getInt(UNLOCKED_LEVEL_KEY, 1)`。这将偏好文件中`UNLOCKED_LEVEL_KEY`键的数据传递给`mUnlockedLevels`。如果游戏的偏好文件当前没有为定义的键保存任何值，那么默认值`1`将被传递给`mUnlockedLevels`。这将针对`UserData`类处理的每种数据类型继续进行。在这种情况下，只是关卡和声音。

在第三步中，我们设置了对`UserData`类处理的每种数据类型相对应的获取器方法。这些方法可以在游戏中的任何地方使用；例如，在关卡加载时，我们可以调用`UserData.getInstance().isSoundMuted()`，以确定是否应该对`Music`对象调用`play()`。

在第四步中，我们创建了将数据保存到设备的方法。这些方法非常直接，无论我们处理哪种数据，它们都应该相当相似。我们可以从参数中获取一个值，如`setSoundMuted(pEnableSound)`，或者简单地递增，如`unlockNextLevel()`中所示。

当我们最终想要将数据保存到设备上时，我们使用`mEditor`对象，使用适合我们要存储的原始数据类型的方法，指定存储数据的键以及值。例如，对于关卡解锁，我们使用方法`mEditor.putInt(UNLOCKED_LEVEL_KEY, mUnlockedLevels)`，因为我们正在存储一个`int`变量。对于`boolean`变量，我们调用`putBoolean(pKey, pValue)`，对于`String`变量，我们调用`putString(pKey, pValue)`，依此类推。

## 还有更多...

不幸的是，在客户端设备上存储数据时，无法保证用户不会访问数据以进行操纵。在 Android 平台上，大多数用户无法访问保存我们游戏数据的`SharedPreferences`文件，但是拥有 root 权限的用户则能够查看该文件并根据需要做出修改。为了解释的方便，我们使用了明显的键名，比如`soundKey`和`unlockedLevels`。使用某种形式的混淆可以帮助让文件对于偶然在 root 设备上发现游戏数据的普通用户来说更像是一堆乱码。

如果我们想要进一步保护游戏数据，那么更为安全的做法是对偏好设置文件进行加密。Java 的`javax.crypto.*`包是一个不错的起点，但请记住，加密和解密确实需要时间，这可能会增加游戏加载时间。


# 第二章：使用实体

在本章中，我们将开始探讨如何在屏幕上显示对象以及我们可以处理这些对象的多种方式。主题包括：

+   理解 AndEngine 实体

+   将原始图形应用到图层

+   使用精灵为场景注入生命

+   将文本应用到图层

+   使用相对旋转

+   重写`onManagedUpdate`方法

+   使用修饰符和实体修饰符

+   使用粒子系统

# 引言

在本章中，我们将开始使用 AndEngine 中包含的所有精彩的实体。实体为我们提供了一个基础，游戏世界中显示的每个对象都将依赖它，无论是分数文本、背景图像、玩家的角色、按钮以及所有其他内容。可以这样想，通过 AndEngine 的坐标系统，我们游戏中任何可以放置的对象在最基本的层面上都是一个实体。在本章中，我们将开始使用`Entity`对象及其许多子类型，以便在我们的游戏中充分利用它们。

# 理解 AndEngine 实体

AndEngine 游戏引擎遵循**实体-组件**模型。实体-组件设计在当今许多游戏引擎中非常普遍，这有充分的理由。它易于使用，模块化，并且在所有游戏对象都可以追溯到单一的、最基本的`Entity`对象的程度上非常有用。实体-组件模型可以被认为是游戏引擎对象系统最基本级别的“实体”部分。`Entity`类只处理我们游戏对象依赖的最基本数据，比如位置、旋转、颜色、与场景的附加和分离等。而“组件”部分指的是`Entity`类的模块化子类型，比如`Scene`、`Sprite`、`Text`、`ParticleSystem`、`Rectangle`、`Mesh`以及所有可以放入我们游戏中的其他对象。组件旨在处理更具体的任务，而实体则作为所有组件依赖的基础。

## 如何操作...

为了从最基础的`Entity`方法开始，我们将一个`Entity`对象附加到`Scene`对象上：

创建并将一个`Entity`对象附加到`Scene`对象只需要以下两行代码：

```kt
Entity layer = new Entity();
mScene.attachChild(layer);
```

## 工作原理...

这里给出的两行代码允许我们创建一个基本的`Entity`对象并将其附加到我们的`Scene`对象上。正如本食谱中*如何操作...*一节所定义的，一个`Entity`对象通常被用作图层。接下来几段将会讨论图层的用途。

实体在游戏开发中非常重要。在 AndEngine 中，事实是，我们场景上显示的所有对象都源自实体（包括`Scene`对象本身！）。在大多数情况下，我们可以假设实体要么是场景上视觉显示的对象，如`Sprite`、`Text`或`Rectangle`对象，要么是一个层，如`Scene`对象。由于`Entity`类的广泛性，我们将分别讨论实体的两种用途，好像它们是不同的对象。

实体的第一个，也可能是最重要的方面是分层能力。在游戏设计中，层是一个非常简单的概念；然而，由于游戏在游戏过程中倾向于支持大量的实体，在初次了解它们时，事情可能会很快变得混乱。我们必须将层视为一个具有一个父级和无限数量的子级的对象，除非另有定义。顾名思义，层的目的在于以有组织的方式将我们的各种实体对象应用到场景上，幸运的是，这也使我们能够对层执行一个会影响其所有子级一致的动作，例如，重新定位和施加某些实体修饰符。我们可以假设，如果我们有一个背景、一个中景和一个前景，那么我们的游戏将会有三个独立的层。这三个层将根据它们附加到场景的顺序以特定的顺序出现，就像将纸张堆叠在一起一样。如果我们从上往下看这个堆叠的纸张，最后添加到堆栈中的纸张将出现在其余纸张的前面。对于附加到`Scene`对象的`Entity`对象，同样的规则适用；这在前面的图片中显示：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_02_01.jpg)

前面的图片描绘了一个由三个`Entity`对象层组成的基本游戏场景。这三个层都有特定的目的，即按照深度存储所有相关实体。首先应用到场景的是背景层，包括一个包含蓝天和太阳的精灵。接着应用到场景的是中景层。在这个层上，我们会找到与玩家相关的对象，包括玩家行走的景观、可收集的物品、敌人等等。最后，我们有了前景层，用于在设备的显示屏上显示最前面的实体。在所展示的图中，前景层用于显示用户界面，包括一个按钮和两个`Text`对象。

让我们再次看看一个带有子实体附加层的场景可能是什么样子：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_02_03.jpg)

这张图显示了场景如何在屏幕上显示实体的深度/层次。在图的底部，我们有设备的显示。我们可以看到**背景层**首先附属于**场景**，然后是**玩家层**。这意味着附属于背景的实体将位于**玩家层**子实体的后面。记住这一点，这个规则同样适用于子实体。首先附着在层上的子实体在深度上将会位于任何随后附着物体的后面。

最后，关于一般 AndEngine 实体的一个最后一个关键主题是实体组合。在继续之前，我们应该了解的一个事实是*子实体继承父实体的值！*这是许多新的 AndEngine 开发者在设置游戏中的多层时遇到问题的地方。从倾斜、缩放、位置、旋转、可见性等所有属性，当父实体的属性发生变化时，子实体都会考虑在内。查看下面的图，它展示了 AndEngine 中实体的**位置**组合：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_04.jpg)

首先，我们应该了解在 AndEngine 的锚点中心分支中，坐标系统是从实体的左下角开始的。增加 x 值会将实体位置向右移动，增加 y 值会将实体位置向上移动。减少 x/y 值则会产生相反的效果。有了这个概念，我们可以看到附属于**场景**的较大矩形在**场景**上的位置被设定为坐标**（6, 6）**。由于较小矩形附属于较大矩形，而不是相对于**场景**的坐标系统，它实际上是使用大矩形的坐标系统。这意味着小矩形的锚点中心位置将直接位于大矩形坐标系统的**（0, 0）**位置上。正如我们在前一张图片中看到的，大矩形坐标系统上的**（0, 0）**位置是其左下角。

### 注意

旧的 AndEngine 分支与 AndEngine 最新的锚点中心分支之间的主要区别在于，定位实体不再意味着我们将实体的左上角设置在坐标系统上的一个位置。相反，实体的中心点将被放置在定义的位置上，这也在前面的图中有所展示。

## 还有更多...

AndEngine 中的 `Entity` 对象包含许多不同的方法，这些方法影响实体的许多方面。这些方法在塑造 `Entity` 对象的整体特性方面发挥着至关重要的作用，无论实体的子类型如何。为了完全控制实体的外观、反应、存储信息等，了解如何操作实体是一个好主意。使用以下列表来熟悉 `Entity` 对象的一些最重要的方法及其相应的获取方法。本章及后续章节将详细介绍此列表中未提及的方法。

+   `setVisible(pBoolean)` 和 `isVisible()`: 这个方法可以用来设置实体是否在场景中可见。将这些方法设置为 `true` 将允许实体渲染，设置为 `false` 将禁用渲染。

+   `setChildrenVisible(pBoolean)` 和 `isChildrenVisible()`: 类似于 `setVisible(pBoolean)` 方法，不同之处在于它定义了调用实体的子实体的可见性，而不是自身。

+   `setCullingEnabled(pBoolean)` 和 `isCullingEnabled()`: 实体剔除可能是一种非常有前景的性能优化技术。更多详情请参见第八章中的*通过实体剔除禁用渲染*，*最大化性能*。

+   `collidesWith(pOtherEntity)`: 这个方法用于检测调用此方法的实体与作为此方法参数提供的`Entity`对象发生碰撞或重叠时。如果实体正在碰撞，此方法将返回 `true`。

+   `setIgnoreUpdate(pBoolean)` 和 `isIgnoreUpdate()`: 忽略实体更新可以提供明显的性能提升。更多详情请参见第八章中的*忽略实体更新*，*最大化性能*。

+   `setChildrenIgnoreUpdate(pBoolean)` 和 `isChildrenIgnoreUpdate()`: 类似于 `setIgnoreUpdate(pBoolean)` 方法，不同之处在于它只影响调用实体的子实体，而不是自身。

+   `getRootEntity()`: 这个方法将遍历实体的父实体，直到找到根父实体。找到根父实体后，此方法将返回根 `Entity` 对象；在大多数情况下，根是我们的游戏 `Scene` 对象。

+   `setTag(pInt)` 和 `getTag()`: 这个方法可以用来在实体中存储整数值。通常用于为实体设置标识值。

+   `setParent(pEntity)` 和 `hasParent()`: 将父实体设置为调用此方法的实体。`hasParent()` 方法根据调用实体是否有父实体返回 `true` 或 `false` 值。

+   `setZIndex(pInt)` 和 `getZIndex()`: 设置调用实体的 `Z` 索引。值较大的实体将出现在值较小的实体前面。默认情况下，所有实体的 `Z` 索引都是 `0`，这意味着它们将按照附加的顺序出现。更多详情请参见下面的 `sortChildren()` 方法。

+   `sortChildren()`: 在对实体或实体组的 `Z` 索引进行修改后，必须在它们的父对象上调用此方法，修改后的效果才能在屏幕上显示。

+   `setPosition(pX, pY)` 或 `setPosition(pEntity)`: 此方法用于将实体的位置设置为特定的 x/y 值，或者可以用来设置到另一个实体的位置。此外，我们可以使用 `setX(pX)` 和 `setY(pY)` 方法仅对单个轴的位置进行更改。

+   `getX()` 和 `getY()`: 这些方法用于获取实体的本地坐标位置；即相对于其父对象的位置。

+   `setWidth(pWidth)` 和 `setHeight(pHeight)` 或 `setSize(pWidth, pHeight)`: 这些方法用于设置调用实体的宽度和高度。此外，我们还可以使用 `getWidth()` 和 `getHeight()` 方法，它们将返回各自值作为浮点数据类型。

+   `setAnchorCenter(pAnchorCenterX, pAnchorCenterY)`: 此方法用于设置实体的锚点中心。锚点中心是 `Entity` 对象内部的一个位置，实体将围绕它旋转、倾斜和缩放。此外，修改锚点中心值将重新定位实体的“定位”锚点，从默认的中心点移动。例如，如果我们把锚点中心位置移动到实体的左上角，调用 `setPosition(0,0)` 将会把实体的左上角放置在位置 `(0,0)`。

+   `setColor(pRed, pGreen, pBlue)` 和 `getColor()`: 此方法用于设置实体的颜色，颜色值从 `0.0f`（无颜色）到 `1.0f`（全颜色）不等。

+   `setUserData(pObject)` 和 `getUserData()`: 这两个方法在开发 AndEngine 游戏时非常有用。它们允许我们在实体中存储我们选择的任何对象，并在任何时刻修改或检索它。用户数据存储的一个可能用途是确定玩家角色持有什么类型的武器。充分利用这些方法吧！

# 将原始图形应用于图层

AndEngine 的原始类型包括 `Line`、`Rectangle`、`Mesh` 和 `Gradient` 对象。在本主题中，我们将重点关注 `Mesh` 类。Mesh 对象对于创建游戏中更为复杂的形状非常有用，其应用场景无限广阔。在本教程中，我们将使用 `Mesh` 对象来构建如下所示的房屋：

![将原始图形应用于图层](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_05.jpg)

## 准备工作…

请参考代码包中名为 `ApplyingPrimitives` 的类。

## 如何操作…

为了创建一个`Mesh`对象，我们需要比典型的`Rectangle`或`Line`对象做更多的工作。使用`Mesh`对象有很多好处。它们可以帮助我们加强 OpenGL 坐标系统的技能，我们可以创建形状奇特的原始物体，并且能够改变单个顶点的位置，这对于某些类型的动画来说非常有用。

1.  创建`Mesh`对象的第一步是创建我们的缓冲数据，这些数据用于指定构成网格形状的点：

    ```kt
      float baseBufferData[] = {
          /* First Triangle */
          0, BASE_HEIGHT, UNUSED, /* first point */
          BASE_WIDTH, BASE_HEIGHT, UNUSED, /* second point */
          BASE_WIDTH, 0, UNUSED, 	/* third point */

          /* Second Triangle */
          BASE_WIDTH, 0, UNUSED, /* first point */
          0, 0, UNUSED, /* second point */
          0, BASE_HEIGHT, UNUSED, /* third point */
      };
    ```

1.  一旦缓冲数据配置完成，我们就可以继续创建`Mesh`对象。

    ```kt
    Mesh baseMesh = new Mesh((WIDTH * 0.5f) - (BASE_WIDTH * 0.5f), 0, baseBufferData, baseBufferData.length / POINTS_PER_TRIANGLE, DrawMode.TRIANGLES, mEngine.getVertexBufferObjectManager());
    ```

## 它是如何工作的…

让我们进一步分解这个过程，以了解我们是如何使用原始`Mesh`对象制作房屋的。

在第一步中，我们创建`baseMesh`对象的缓冲数据。这个缓冲数据用于存储 3D 空间中的点。缓冲数据中每三个值，由换行符分隔，构成 3D 世界中的一个顶点。但是，应该明白，由于我们使用的是 2D 游戏引擎，第三个值，即`Z`索引，对我们来说是没有用的。因此，我们将每个顶点的第三个值定义为该食谱类中声明的`UNUSED`常量，等于`0`。每个三角形的点表示为`(x, y, z)`，以避免混淆顺序。请参阅以下图表，了解第一步中定义的点如何绘制到网格上的矩形：

![它的工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_06.jpg)

前一个图表展示了在*如何操作…*部分第一步中看到的`baseMesh`对象的缓冲数据，或者说是绘制点。黑色线条代表第一组点：

```kt
      0, BASE_HEIGHT, UNUSED, /* first point */
      BASE_WIDTH, BASE_HEIGHT, UNUSED, /* second point */
      BASE_WIDTH, 0, UNUSED,  /* third point */
```

`baseMesh`对象缓冲数据中的第二组点由灰色线条表示：

```kt
      BASE_WIDTH, 0, UNUSED, /* first point */
      0, 0, UNUSED, /* second point */
      0, BASE_HEIGHT, UNUSED, /* third point */
```

由于`BASE_HEIGHT`等于`200`且`BASE_WIDTH`等于`400`，我们可以读取到第一个三角形的第一个点`(0, BASE_HEIGHT)`位于矩形形状的左上角。顺时针移动，第一个三角形的第二个点位于`(BASE_WIDTH, BASE_HEIGHT)`的位置，这将是矩形形状的右上角。显然，一个三角形由三个点组成，所以这让我们还有一个顶点要绘制。我们第一个三角形的最后一个顶点位于`(BASE_WIDTH, 0)`的位置。作为一个个人挑战，使用前一个图中的场景图，找出灰色三角形的绘制点与缓冲数据相比如何！

在第二步中，我们将`baseMesh`对象的缓冲区数据用来构建`Mesh`对象。`Mesh`对象是`Entity`类的一个子类型，因此一旦我们创建了`Mesh`对象，就可以对其进行重新定位、缩放、旋转以及进行其他必要的调整。按照构造函数中出现的顺序，参数如下：x 轴位置、y 轴位置、缓冲区数据、顶点数量、绘制模式和顶点缓冲对象管理器。前两个参数和最后一个参数对所有实体都是典型的，但缓冲区数据、顶点数量和绘制模式对我们来说是新的。缓冲区数据是数组，它指定了已绘制的顶点，这在第一步中已经介绍过。顶点数量只是缓冲区数据中包含的顶点数。我们缓冲数据中的每一个 x、y、z 坐标组成一个单独的顶点，这就是为什么我们用`baseBufferData.length`值除以三来得到这个参数。最后，`DrawMode`定义了`Mesh`对象将如何解释缓冲区数据，这可以极大地改变网格的最终形状。不同的`DrawMode`类型和用途可以在本主题的*还有更多...*部分中找到。

在继续之前，您可能会注意到“门”，或者更确切地说，代表门的蓝色线条并不是以与屋顶和基础`Mesh`对象相同的方式创建的。相反，我们使用线条而不是三角形来绘制门的外框。请查看以下代码，它来自`doorBufferData`数组，定义了线条连接的点：

```kt
      0, DOOR_HEIGHT, UNUSED, /* first point */
      DOOR_WIDTH, DOOR_HEIGHT, UNUSED, /* second point */
      DOOR_WIDTH, 0, UNUSED, /* third point */
      0, 0, UNUSED, /* fourth point */
      0, DOOR_HEIGHT, UNUSED /* fifth point */
```

再次，如果我们绘制一个场景图，并像之前代表`baseMesh`对象点的图那样标出这些点，我们实际上可以连接这些点，线条将形成一个矩形形状。一开始可能会让人感到困惑，尤其是在试图在脑海中创建形状时。从定义的顶点开始绘制自定义形状的诀窍是，在您喜欢的文档或图像编辑软件中保存一个空白场景图。创建一个类似于`baseMesh`对象缓冲数据表示图的场景图，并使用它来标出点，然后简单地将点复制到代码中！

### 注意事项

需要特别记住的是，在之前场景图中的`(0,0)`位置代表了`Mesh`对象的中心。由于我们是向上和向右构建网格顶点，网格的锚定中心位置将不代表手动绘制的形状的中心！在构建`Mesh`对象时，这一点非常重要。

## 还有更多...

对于初学者来说，创建网格可能是一个相当令人畏惧的主题，但有很多原因让我们习惯它们。AndEngine 开发者们的一个主要原因是它可以帮助我们理解 OpenGL 在较低层次上如何将形状绘制到显示上，这反过来又使我们更容易掌握更高层次的游戏开发功能。以下图片包含了 AndEngine 为我们提供的各种`DrawMode`类型，以便以不同方式创建`Mesh`对象：

![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_08.jpg)

前图展示了我们的缓冲数据中的顶点将如何根据所选的`DrawMode`类型由`Mesh`对象绘制到场景中。此图中的每个**p#**代表我们缓冲数据数组中的`顶点（x，y 和 z 值）`。以下是每个`DrawMode`类型的图像表示的解释：

+   `DrawMode.POINTS`：这种选择允许我们在网格的缓冲数据中为每个顶点绘制单独的点。这些点不会由任何线条连接；它们仅仅在网格上为每个点显示一个点。

+   `DrawMode.LINES`：这种选择允许我们在网格上绘制单独的线条。每两个顶点将由线条连接。

+   `DrawMode.LINE_STRIP`：这种选择允许我们在网格上绘制点，第一个点之后的每个点都连接到前一个点。例如，**p1**将连接到**p0**，**p2**将连接到**p1**，依此类推。

+   `DrawMode.LINE_LOOP`：这种选择与`DrawMode.LINE_STRIP`类型类似，但是，第一个点与最后一个点也会由线条连接。这允许我们通过线条创建闭合的形状。

+   `DrawMode.TRIANGLES`：这种选择允许我们在网格上为缓冲数据中定义的每组三个顶点绘制单独的三角形。这种绘制模式要求我们将顶点保持在三的倍数。

+   `DrawMode.TRIANGLE_FAN`：这种选择允许我们绘制锥形或金字塔形状的网格。正如在之前的图中可以看到的，我们首先指定一个点，定义锥形的顶部点，然后继续指定形状的底部点。这种绘制模式需要定义三个或更多的顶点在缓冲数据中。

+   `DrawMode.TRIANGLE_STRIP`：这种选择使我们能够轻松创建自定义的多边形网格。在初始化三角形的第三个顶点之后，缓冲数据中定义的每个顶点都会生成一个新的三角形，创建一个新的“带”。请参阅图表示例。这种绘制模式需要定义三个或更多的顶点在缓冲数据中。

## 另请参阅

+   本章节中提供的*了解 AndEngine 实体*。

# 使用精灵为场景带来生机

我们在这里讨论的可能是创建任何 2D 游戏最必要的一个方面。精灵（Sprites）允许我们在场景中显示 2D 图像，这些图像可以用来展示按钮、角色/化身、环境主题、背景以及游戏中可能需要通过图像文件来表示的任何其他实体。在本教程中，我们将介绍 AndEngine 的`Sprite`实体的各个方面，这将为我们提供在以后更复杂的情况下继续使用`Sprite`对象所需的信息。

## 准备工作...

在深入了解精灵如何创建的内部工作机制之前，我们需要了解如何创建和管理 AndEngine 的`BitmapTextureAtlas`/`BuildableBitmapTextureAtlas`对象以及`ITextureRegion`对象。更多信息，请参考第一章，*AndEngine 游戏结构*中的教程，*使用不同类型的纹理*和*应用纹理选项*。

阅读完这些教程后，创建一个新的空 AndEngine 项目，使用`BaseGameActivity`类，提供一个尺寸最大为 1024 x 1024 像素的 PNG 格式图像，将其命名为`sprite.png`并放在项目的`assets/gfx/`文件夹中，然后继续本教程的*如何操作...*部分。

## 如何操作...

我们只需几个快速步骤就可以创建并将精灵应用到我们的`Scene`对象中。我们首先必须设置精灵将使用的必要纹理资源，创建`Sprite`对象，然后必须将`Sprite`对象附加到我们的`Scene`对象。以下步骤将提供更多详细信息：

1.  我们将从在`BaseGameActivity`类的`onCreateResources()`方法中创建纹理资源开始。确保`mBitmapTextureAtlas`和`mSpriteTextureRegion`对象是全局变量，这样它们就可以在活动的各种生命周期方法中被访问：

    ```kt
      BitmapTextureAtlasTextureRegionFactory.setAssetBasePath("gfx/");

        /* Create the bitmap texture atlas for the sprite's texture region */
        BuildableBitmapTextureAtlas mBitmapTextureAtlas = new BuildableBitmapTextureAtlas(mEngine.getTextureManager(), 256, 256, TextureOptions.BILINEAR);

        /* Create the sprite's texture region via the BitmapTextureAtlasTextureRegionFactory */
        mSpriteTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, this, "sprite.png");

        /* Build the bitmap texture atlas */
        try {
          mBitmapTextureAtlas.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 1, 1));
        } catch (TextureAtlasBuilderException e) {
          e.printStackTrace();
        }
        /* Load the bitmap texture atlas into the device's gpu memory */
        mBitmapTextureAtlas.load();
    ```

1.  接下来，我们将创建`Sprite`对象。我们可以在活动的`onCreateScene()`或`onPopulateScene()`方法中创建并附加`Sprite`对象到`Scene`对象。在它的构造函数中需要提供的参数包括，按此顺序，精灵的初始 x 坐标、初始 y 坐标、`ITextureRegion`对象，最后是`mEngine`对象的顶点缓冲区管理器：

    ```kt
        final float positionX = WIDTH * 0.5f;
        final float positionY = HEIGHT * 0.5f;

        /* Add our marble sprite to the bottom left side of the Scene initially */
        Sprite mSprite = new Sprite(positionX, positionY, mSpriteTextureRegion, mEngine.getVertexBufferObjectManager());
    The last step is to attach our Sprite to the Scene, as is necessary in order to display any type of Entity on the device's display:
        /* Attach the marble to the Scene */
        mScene.attachChild(mSpriteTextureRegion);
    ```

## 它的工作原理...

如前一部分的步骤所示，实际上设置`mBitmapTextureAtlas`和`mSpriteTextureRegion`对象比专门创建和设置`mSprite`对象需要更多的工作。因此，建议在开始之前先完成*入门...*部分提到的两个教程。

在第一步中，我们将创建适合我们`sprite.png`图像需求的`mBitmapTextureAtlas`和`mSpriteTextureRegion`对象。在这一步中，请随意使用任何纹理选项或纹理格式。很好地了解它们是非常有想法的。

一旦我们创建了`ITextureRegion`对象并且它已经准备好使用，我们可以进入第二步，创建`Sprite`对象。创建一个精灵是一个直接的任务。前两个参数将用于定义精灵的初始位置，相对于其中心点。对于第三个参数，我们将传递在第一步中创建的`ITextureRegion`对象，以便为场景中的精灵提供图像外观。最后，我们传递`mEngine.getVertexBufferObjectManager()`方法，这是大多数实体子类型所必需的。

一旦我们的`Sprite`对象被创建，我们必须在它能在设备上显示之前将它附加到`Scene`对象，或者我们可以将它附加到已经连接到`Scene`对象的另一个`Entity`对象上。关于实体组合、放置以及其他各种必须了解的`Entity`对象方面，请参阅本章中提供的*了解 AndEngine 实体*食谱。

## 还有更多内容...

没有某种形式的精灵动画，游戏是不完整的。毕竟，玩家只能在游戏中返回这么多次，之后就会对那些角色在屏幕上滑动而不动脚、攻击敌人时不挥舞武器，或者手榴弹只是消失而不是产生漂亮的爆炸效果的游戏感到厌倦。在这个时代，人们想要玩看起来和感觉都很棒的游戏，而像黄油般平滑的动画精灵没有什么能比得上“好极了！”，不是吗？

在第一章，*AndEngine 游戏结构*中的*使用不同类型的纹理*食谱中，我们介绍了如何创建一个`TiledTextureRegion`对象，该对象允许我们将可用的精灵表作为纹理导入到游戏中。现在让我们找出如何使用`TiledTextureRegion`对象与`AnimatedSprite`对象为游戏的精灵添加动画。在这个演示中，代码将处理一个尺寸为 300 x 50 像素的图像。精灵表可以是如图所示的那样简单，以了解如何创建动画：

![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_09.jpg)

前图中的精灵表可用于创建一个有 12 列 1 行的`TiledTextureRegion`对象。为这个精灵表创建`BuildableBitmapTextureAtlas`和`TiledTextureRegion`对象可以使用以下代码。但是，在导入这段代码之前，请确保在测试项目中全局声明纹理区域—`TiledTextureRegion mTiledTextureRegion`。

```kt
    /* Create the texture atlas at the same dimensions as the image (300x50)*/
    BuildableBitmapTextureAtlas mBitmapTextureAtlas = new BuildableBitmapTextureAtlas(mEngine.getTextureManager(), 300, 50, TextureOptions.BILINEAR);

    /* Create the TiledTextureRegion object, passing in the usual parameters,
     * as well as the number of rows and columns in our sprite sheet for the 
     * final two parameters */
    mTiledTextureRegion = BitmapTextureAtlasTextureRegionFactory.createTiledFromAsset(mBitmapTextureAtlas, this, "gfx/sprite_sheet.png", 12, 1);

    /* Build and load the mBitmapTextureAtlas object */
    try {
      mBitmapTextureAtlas.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 0, 0));
    } catch (TextureAtlasBuilderException e) {
      e.printStackTrace();
    }
    mBitmapTextureAtlas.load();
```

既然我们的项目中已经有了可以操作的`mTiledTextureRegion`精灵表，我们可以创建并动画化`AnimatedSprite`对象。如果你使用的是如图所示带有黑色圆圈的精灵表，别忘了将`Scene`对象的颜色改为非黑色，这样我们才能看到`AnimatedSprite`对象：

```kt
    /* Create a new animated sprite in the center of the scene */
    AnimatedSprite animatedSprite = new AnimatedSprite(WIDTH * 0.5f, HEIGHT * 0.5f, mTiledTextureRegion, mEngine.getVertexBufferObjectManager());

    /* Length to play each frame before moving to the next */
    long frameDuration[] = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200};

    /* We can define the indices of the animation to play between */
    int firstTileIndex = 0;
    int lastTileIndex = mTiledTextureRegion.getTileCount();

    /* Allow the animation to continuously loop? */
    boolean loopAnimation = true;

    * Animate the sprite with the data as set defined above */
    animatedSprite.animate(frameDuration, firstTileIndex, lastTileIndex, loopAnimation, new IAnimationListener(){

      @Override
      public void onAnimationStarted(AnimatedSprite pAnimatedSprite,
          int pInitialLoopCount) {
        /* Fired when the animation first begins to run*/
      }

      @Override
      public void onAnimationFrameChanged(AnimatedSprite pAnimatedSprite,
          int pOldFrameIndex, int pNewFrameIndex) {
         /* Fired every time a new frame is selected to display*/
      }

      @Override
      public void onAnimationLoopFinished(AnimatedSprite pAnimatedSprite,
          int pRemainingLoopCount, int pInitialLoopCount) {
        /* Fired when an animation loop ends (from first to last frame) */
      }

      @Override
      public void onAnimationFinished(AnimatedSprite pAnimatedSprite) {
        /* Fired when an animation sequence ends */
      }
      );

    mScene.attachChild(animatedSprite);
```

创建`AnimatedSprite`对象可以按照本食谱中创建常规`Sprite`对象的步骤进行。一旦创建完成，我们就可以设置其动画数据，包括单个帧的持续时间、要动画化的第一块和最后一块图块索引，以及是否要连续循环动画。注意，`frameDuration`数组必须等于帧数！不遵循此规则将导致抛出`IllegalArgumentException`异常。数据设置完成后，我们可以在`AnimatedSprite`对象上调用`animate()`方法，提供所有数据，并在需要时添加`IAnimationListener`监听器。正如监听器中的注释所示，通过 AndEngine 的`AnimatedSprite`类，我们对动画的控制能力得到了大幅提升。

### 使用 OpenGL 的抖动功能

在移动平台上开发视觉上吸引人的游戏时，我们很可能会希望图像中包含一些渐变，特别是在处理 2D 图形时。渐变非常适合创建光照效果、阴影以及许多其他无法应用于完整 2D 世界的对象。问题在于，我们是为移动设备开发，因此不幸的是，我们无法使用无限量的资源。因此，AndEngine 默认将表面视图的颜色格式下采样为`RGB_565`。无论我们在纹理中定义的纹理格式如何，它们在设备上显示之前总是会被下采样。我们可以更改应用于 AndEngine 表面视图的颜色格式，但在开发包含许多精灵的大型游戏时，性能损失可能不值得。

这里，我们有两张具有渐变纹理的简单精灵的独立屏幕截图；这两种纹理都使用了`RGBA_8888`纹理格式和`BILINEAR`纹理过滤（最高质量）。

![使用 OpenGL 的抖动功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_07.jpg)

右侧的图像未经任何修改就应用到了`Scene`对象上，而左侧的图像启用了 OpenGL 的抖动功能。这两张其他方面相同的图像之间的差异立即显而易见。抖动是我们对抗表面视图应用的降采样的一种很好的方法，而无需依赖最大颜色质量格式。简而言之，通过在图像颜色中加入低级别的随机噪声，结果得到了更平滑的完成效果，如左侧的图像所示。

在 AndEngine 中，为我们的实体应用抖动很简单，但与所有事物一样，明智的做法是选择哪些纹理应用抖动。该算法确实增加了一点额外的开销，如果使用过于频繁，可能会导致比简单地将我们的表面视图恢复为`RGBA_8888`更大的性能损失。在以下代码中，我们在`preDraw()`方法中启用抖动，在`postDraw()`方法中禁用它：

```kt
@Override
protected void preDraw(GLState pGLState, Camera pCamera) {
  // Enable dithering
  pGLState.enableDither();
  super.preDraw(pGLState, pCamera);
}

@Override
protected void postDraw(GLState pGLState, Camera pCamera) {
  // Disable dithering
  pGLState.disableDither();
  super.postDraw(pGLState, pCamera);
}
```

晕染可以应用于 AndEngine 的`Shape`类的任何子类型（`Sprites`、`Text`、基元等）。

### 注意

有关 OpenGL ES 2.0 以及如何使用所有不同函数的更多信息，请访问[`www.khronos.org/opengles/sdk/docs/man/`](http://www.khronos.org/opengles/sdk/docs/man/)。

## 另请参阅

+   在第一章中*处理不同类型的纹理*，*处理实体*

+   在第一章中*应用纹理选项*，*处理实体*。

+   在本章中*了解 AndEngine 实体*。

# 将文本应用到图层

文本是游戏开发的重要组成部分，因为它可以用来动态显示积分系统、教程、描述等。AndEngine 还允许我们通过指定自定义的`Font`对象来创建更适合个别游戏类型的文本样式。在本教程中，我们将创建一个`Text`对象，它会随当前系统时间更新自身，并在字符串长度增长或缩短时调整其位置。这将为我们需要显示分数、时间和其他非特定动态字符串情况下的`Text`对象使用做好准备。

## 准备就绪…

将`Text`对象应用到我们的`Scene`对象需要了解 AndEngine 的字体资源。请执行第一章中的教程，*使用 AndEngine 字体资源*，然后继续本教程的*如何操作…*部分。参考与此食谱活动代码捆绑中的名为`ApplyingText`的类。

## 如何操作…

当我们将`Text`对象应用到我们的`Scene`对象上时，需要创建一个`Font`对象来定义文本的样式，并创建`Text`对象本身。以下步骤将说明我们必须采取的具体操作，以便在我们的场景上正确显示`Text`对象：

1.  创建任何`Text`对象的第一步是为自己准备一个`Font`对象。`Font`对象将作为定义`Text`对象样式的资源。此外，我们还需要准备我们计划让`Text`对象显示的字母：

    ```kt
        mFont = FontFactory.create(mEngine.getFontManager(),
            mEngine.getTextureManager(), 256, 256,
            Typeface.create(Typeface.DEFAULT, Typeface.NORMAL), 32f, true,
            Color.WHITE);
        mFont.load();

        /*
         * Prepare the mFont object for the most common characters used. This
         * will eliminate the need for the garbage collector to run when using a
         * letter/number that's never been used before
         */
          mFont.prepareLetters("Time: 1234567890".toCharArray());
    Once we've got our Font object created and ready for use, we can create the Text:
        /* Create the time Text object which will update itself as time passes */
        Text mTimeText = new Text(0, timeTextHeight, mFont, TIME_STRING_PREFIX
            + TIME_FORMAT, MAX_CHARACTER_COUNT, mEngine.getVertexBufferObjectManager()) {

          // Overridden methods as seen in step 3...
        };
    ```

1.  如果我们处理的是可能永远不会改变的最终字符串，那么只需要涵盖前两个步骤。然而，在本教程中，我们将需要覆盖`Text`实体的`onManagedUpdate()`方法，以便随时间对其字符串进行调整。在本例中，每经过一秒钟，我们就会更新字符串的时间值：

    ```kt
        int lastSecond = 0;

        @Override
        protected void onManagedUpdate(float pSecondsElapsed) {

          Calendar c = Calendar.getInstance();

          /*
          * We will only obtain the second for now in order to verify
           * that it's time to update the Text's string
          */
          final int second = c.get(Calendar.SECOND);

          /*
           * If the last update's second value is not equal to the
          * current...
           */
          if (lastSecond != second) {

          /* Obtain the new hour and minute time values */
            final int hour = c.get(Calendar.HOUR);
            final int minute = c.get(Calendar.MINUTE);

            /* also, update the latest second value */
            lastSecond = second;

             /* Build a new string with the current time */
            final String timeTextSuffix = hour + ":" + minute + ":"
               + second;

            /* Set the Text object's string to that of the new time */
            this.setText(TIME_STRING_PREFIX + timeTextSuffix);

            /*
              * Since the width of the Text will change with every change
             * in second, we should realign the Text position to the
              * edge of the screen minus half the Text's width
            */
            this.setX(WIDTH - this.getWidth() * 0.5f);
          }

          super.onManagedUpdate(pSecondsElapsed);
        }
    Finally, we can make color adjustments to the Text and then attach it to the Scene or another Entity:
        /* Change the color of the Text to blue */
        mTimeText.setColor(0, 0, 1);

        /* Attach the Text object to the Scene */
        mScene.attachChild(mTimeText);
    ```

## 它是如何工作的…

在这一点上，我们应该已经了解了如何创建`Font`对象，因为我们在第一章中已经讨论过。如果还不知道如何创建`Font`对象，请访问第一章中的教程，*使用 AndEngine 字体资源*，*处理实体*。

在第一步中，我们只是创建了一个基本的`Font`对象，它将为我们的`Text`对象创建一个相当通用的样式。创建`Font`对象后，我们只准备`Text`对象在其生命周期内将显示的必要字符，使用`mFont.prepareLetters()`方法。这样做可以避免在`Font`对象内调用垃圾收集器。这个配方中使用的值显然是从`0`到`9`，因为我们处理的是时间，以及组成字符串`Time:`的单个字符。

完成第一步后，我们可以进入第二步，创建`Text`对象。`Text`对象需要我们指定其在屏幕上的初始位置（x 和 y 坐标），使用的`Font`对象样式，要显示的初始字符串，其最大字符数，以及所有`Entity`对象所需的顶点缓冲对象管理器。然而，由于我们处理的这个`Text`对象有一个动态更新的`String`值，这将需要调整 x 轴，包括 x 坐标以及初始字符串在内的参数并不重要，因为它们将在更新`Text`对象时频繁调整。最重要的参数是最大字符数。如果`Text`对象的最大字符数超过了此参数内指定的值，将导致应用程序接收到`ArrayIndexOutOfBoundsException`异常，很可能会需要终止。因此，我们在以下代码片段中累加最大字符串的长度：

```kt
  private static final String TIME_STRING_PREFIX = "Time: ";
  private static final String TIME_FORMAT = "00:00:00";

  /* Obtain the maximum number of characters that our Text 
   * object will need to display*/
  private static final int MAX_CHARACTER_COUNT = TIME_STRING_PREFIX.length() + TIME_FORMAT.length();
```

在第三步中，我们覆盖了`Text`对象的`onManagedUpdate()`方法，以便在每秒过去后对`Text`对象的字符串应用更改。首先，我们只需获取设备的当前秒值，用它来与上一次调用`Text`对象的`onManagedUpdate()`方法中的秒值进行比较。这样，我们可以避免在每次更新时都使用系统时间更新`Text`对象。如果`Text`对象字符串上次更新的秒值与新的秒值不同，那么我们继续通过`Calendar.getInstance().get(HOUR)`方法和`MINUTE`变体获取当前的分钟和小时值。现在我们已经获得了所有的值，我们构建了一个包含更新时间的新字符串，并在`Text`对象上调用`setText(pString)`来更改它将在设备上显示的字符串。

然而，由于每个单独的字符宽度可能具有不同的值，我们也需要调整位置，以保持整个`Text`对象在屏幕上。默认情况下，锚点位置被设置为`Entity`对象的中心，因此通过调用`this.setX(WIDTH - this.getWidth() * 0.5f)`（其中`this`指的是`Text`对象），我们将实体最中心的点定位在屏幕最大宽度右侧，然后减去实体宽度的一半。这将允许文本即使在其字符改变了`Text`对象的宽度后，也能沿着屏幕边缘正确显示。

## 还有更多...

有时我们的游戏可能需要对`Text`对象的字符串进行一些格式化处理。在我们需要调整`Text`对象的水平对齐方式、如果字符串超出一定宽度则对文本应用自动换行，或者在文本前添加一个空格的情况下，我们可以使用一些非常易于使用的方法。以下方法可以直接在`Text`对象上调用；例如，`mText.setLeading(3)`：

+   `setAutoWrap(pAutoWrap)`: 这个方法允许我们定义`Text`实体是否执行自动换行，以及如何执行。我们可以为参数选择的选项包括`AutoWrap.NONE`、`AutoWrap.LETTERS`、`AutoWrap.WORDS`和`AutoWrap.CJK`。使用`LETTERS`时，行中断不会在空白前等待，而`WORDS`会等待。`CJK`变体是允许对中、日、韩字符进行自动换行的选项。这个方法应该与`setAutoWrapWidth(pWidth)`一起使用，其中`pWidth`定义了`Text`对象字符串中任意单行的最大宽度，在需要时导致换行。

+   `setHorizontalAlign(pHorizontalAlign)`: 这个方法允许我们定义`Text`对象字符串应遵循的对齐类型。参数包括`HorizontalAlign.LEFT`、`HorizontalAlign.CENTER`和`HorizontalAlign.RIGHT`。其结果类似于我们在文本编辑器内设置对齐时看到的效果。

+   `setLeading(pLeading)`: 这个方法允许我们在`Text`对象字符串的开始处设置一个前置空间。所需的参数是一个浮点值，它定义了字符串的前导宽度。

## 另请参阅

+   在第一章中*使用 AndEngine 字体资源*，*处理实体*。

+   在本章中*覆盖 onManagedUpdate 方法*。

# 使用相对旋转

在 2D 空间中相对于其他实体的位置旋转实体是一个很棒的功能。相对旋转的使用是无限的，并且似乎总是移动游戏开发新手中的“热门话题”。这种技术被广泛应用的一个较为突出的例子是在塔防游戏中，它允许塔的炮塔朝向敌人（非玩家角色）行走的方向。在这个示例中，我们将介绍一种旋转我们的`Entity`对象的方法，以便它们指向给定的 x/y 位置。以下图像展示了我们如何在场景上创建一个箭头，它会自动指向圆形图像的位置，无论它移动到哪里：

![使用相对旋转](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_02_02.jpg)

## 准备工作…

这个示例我们需要包含两个图像；一个名为`marble.png`，尺寸为 32x32 像素，另一个名为`arrow.png`，宽 31 像素，高 59 像素。弹珠可以是任何图像，我们只需随意在场景中拖动这个图像。箭头图像应该呈箭头形状，图像上的箭头直接朝上。请参考引言中的屏幕截图以了解需要包含的图像示例。将这些资源包含在空的`BaseGameActivity`测试项目中，然后请参考代码包中的名为`RelativeRotation`的类。

## 如何操作…

按照以下步骤操作：

1.  在`BaseGameActivity`类中实现`IOnSceneTouchListener`监听器：

    ```kt
    public class RelativeRotation extends BaseGameActivity implements IOnSceneTouchListener{
    ```

1.  在`onCreateScene()`方法中设置`Scene`对象的`onSceneTouchListener`：

    ```kt
    mScene.setOnSceneTouchListener(this);
    ```

1.  使用弹珠和小箭头的图像填充`Scene`对象。小箭头图像位于场景中心，而弹珠的位置会更新为任意触摸事件位置的坐标：

    ```kt
        /* Add our marble sprite to the bottom left side of the Scene initially */
        mMarbleSprite = new Sprite(mMarbleTextureRegion.getWidth(), mMarbleTextureRegion.getHeight(), mMarbleTextureRegion, mEngine.getVertexBufferObjectManager());

        /* Attach the marble to the Scene */
        mScene.attachChild(mMarbleSprite);

        /* Create the arrow sprite and center it in the Scene */
        mArrowSprite = new Sprite(WIDTH * 0.5f, HEIGHT * 0.5f, mArrowTextureRegion, mEngine.getVertexBufferObjectManager());

        /* Attach the arrow to the Scene */
        mScene.attachChild(mArrowSprite);
    ```

1.  第四步介绍了`onSceneTouchEvent()`方法，它通过设备显示上的触摸事件处理弹珠图像的移动：

    ```kt
      @Override
      public boolean onSceneTouchEvent(Scene pScene, TouchEvent pSceneTouchEvent) {
        // If a user moves their finger on the device
        if(pSceneTouchEvent.isActionMove()){

          /* Set the marble's position to that of the touch even coordinates */
         mMarbleSprite.setPosition(pSceneTouchEvent.getX(), pSceneTouchEvent.getY());

          /* Calculate the difference between the two sprites x and y coordinates */
          final float dX = mMarbleSprite.getX() - mArrowSprite.getX();
          final float dY = mMarbleSprite.getY() - mArrowSprite.getY();

          /* Calculate the angle of rotation in radians*/
          final float angle = (float) Math.atan2(-dY, dX);
          /* Convert the angle from radians to degrees, adding the default image rotation */
          final float rotation = MathUtils.radToDeg(angle) + DEFAULT_IMAGE_ROTATION;

          /* Set the arrow's new rotation */
          mArrowSprite.setRotation(rotation);

          return true;
        }

        return false;
      }
    ```

## 工作原理…

在这个类中，我们创建了一个由箭头图像表示的精灵，并将其放置在屏幕正中心，自动指向由弹珠表示的另一个精灵。通过在`BaseGameActivity`类中实现`IOnSceneTouchListener`监听器，弹珠可以拖动。然后，我们将触摸监听器注册到`mScene`对象。在实体根据另一个实体的位置进行旋转的情况下，我们不得不在某个持续更新的方法中包含旋转功能，否则我们的箭头不会持续反应。我们可以通过更新线程来实现这一点，但在这个实例中，我们将在重写的`onSceneTouchEvent()`方法中包含该功能，因为直到我们触摸场景，“目标”实际上不会移动。

在第一步中，我们通过实现`IOnSceneTouchListener`接口，允许我们的活动重写`onSceneTouchEvent()`方法。一旦我们实现了触摸监听器，就可以进行第二步，让`Scene`对象接收触摸事件，并根据活动重写的`onSceneTouchEvent()`方法中的代码做出响应。这是通过`setOnSceneTouchListener(pSceneTouchListener)`方法完成的。

在第四步中，`if(pSceneTouchEvent.isActionMove())`条件语句判断是否有一个手指在场景上移动，更新大理石的位置，并在条件语句返回`true`时计算箭头精灵的新旋转。

我们首先通过以下代码段中看到的`setPosition(pX, pY)`方法，将大理石的位置更新到触摸的位置：

```kt
mMarbleSprite.setPosition(pSceneTouchEvent.getX(), pSceneTouchEvent.getY());
```

接下来，我们从目标的 x/y 坐标中减去指针的 x/y 坐标。这为我们提供了每个精灵坐标之间的差值，这将用于计算两个位置之间的角度。在这种情况下，指针是`mArrowSprite`对象，目标是`mMarbleSprite`对象：

```kt
/* Calculate the difference between the two sprites x and y coordinates */
final float dX = mMarbleSprite.getX() - mArrowSprite.getX();
final float dY = mMarbleSprite.getY() - mArrowSprite.getY();

/* Calculate the angle of rotation in radians*/
final float angle = (float) Math.atan2(-dY, dX);
```

最后，由于 AndEngine 的`setRotation(pRotation)`方法使用度数，而`atan2(pY, pX)`方法返回弧度，我们必须进行简单的转换。我们将使用 AndEngine 的`MathUtils`类，其中包括一个`radToDeg(pRadian)`方法，将我们的角度值从弧度转换为度数。一旦我们获得了正确的度数角度，我们将设置`mArrowSprite`对象的旋转：

```kt
/* Convert the angle from radians to degrees, adding the default image rotation */
final float rotation = MathUtils.radToDeg(angle) + DEFAULT_IMAGE_ROTATION;

/* Set the arrow's new rotation */
mArrowSprite.setRotation(rotation);
```

需要注意的最后一点是，`DEFAULT_IMAGE_ROTATION`值是一个表示`90`度的`int`值。这个值仅用于偏移`mArrowSprite`精灵的旋转，否则我们将需要在我们的图像编辑软件中适当旋转图像。如果自定义图像中的指针没有指向图像的最顶部，这个值可能需要调整，以便将指针与目标对齐。

# 重写`onManagedUpdate`方法

重写`Entity`对象的`onManagedUpdate()`方法在所有类型的情况下都非常有用。这样做，我们可以让我们的实体在每次通过更新线程更新实体时执行代码，每秒发生多次，除非实体被设置为忽略更新。可能性非常多，包括动画化我们的实体，检查碰撞，产生定时事件等等。使用我们的`Entity`对象的`onManagedUpdate()`方法还可以节省我们为单一实体创建和注册新的定时处理器以处理基于时间的事件。

## 准备就绪…

这个示例需要具备对 AndEngine 中`Entity`对象的基本了解。请阅读本章提供的*了解 AndEngine 实体*的整个示例，然后创建一个新的空 AndEngine 项目，包含一个`BaseGameActivity`类，并参考代码包中名为`OverridingUpdates`的类。

## 如何操作…

在这个示例中，我们将创建两个`Rectangle`对象。一个矩形将保持场景中心位置，持续旋转。第二个矩形将在场景中从左到右、从下到上连续移动，当到达右侧时重置回左侧，当到达场景顶部时重置回底部。此外，移动的矩形在与中心矩形碰撞时将变为绿色。所有这些移动和条件判断都将通过每个对象重写的`onManagedUpdate(pSecondsElapsed)`方法来应用和执行。

1.  重写第一个`Rectangle`对象的`onManagedUpdate()`方法，以实现连续旋转：

    ```kt
        /* Value which defines the rotation speed of this Entity */
        final int rotationIncrementalFactor = 25;

        /* Override the onManagedUpdate() method of this Entity */
        @Override
        protected void onManagedUpdate(float pSecondsElapsed) {

          /* Calculate a rotation offset based on time passed */
          final float rotationOffset = pSecondsElapsed * rotationIncrementalFactor;

          /* Apply the rotation offset to this Entity */
          this.setRotation(this.getRotation() + rotationOffset);

          /* Proceed with the rest of this Entity's update process */
          super.onManagedUpdate(pSecondsElapsed);
        }
    ```

1.  重写第二个`Rectangle`对象的`onManagedUpdate()`方法，以实现连续的位置更新、条件检查和碰撞检测：

    ```kt
        /* Value to increment this rectangle's position by on each update */
        final int incrementXValue = 5;

        /* Obtain half the Entity's width and height values */
        final float halfWidth = this.getWidth() * 0.5f;
        final float halfHeight = this.getHeight() * 0.5f;

        /* Override the onManagedUpdate() method of this Entity */
        @Override
        protected void onManagedUpdate(float pSecondsElapsed) {

          /* Obtain the current x/y values */
          final float currentX = this.getX();
          final float currentY = this.getY();

          /* obtain the max width and next height, used for condition checking */
          final float maxWidth = currentX + halfWidth;
          final float nextHeight = currentY + halfHeight;

          // On every update...
          /* Increment the x position if this Entity is within the camera WIDTH */
           if(maxWidth <= WIDTH){
            /* Increase this Entity's x value by 5 pixels */
            this.setX(currentX + incrementXValue);
          } else {
            /* Reset the Entity back to the bottom left of the Scene if it exceeds the mCamera's
            * HEIGHT value */
            if(nextHeight >= HEIGHT){
            this.setPosition(halfWidth, halfHeight);
            } else {
              /* if this Entity reaches the WIDTH value of our camera, move it
               * back to the left side of the Scene and slightly increment its y position */
              this.setPosition(halfWidth, nextHeight);
            }
          }

           /* If the two rectangle's are colliding, set this rectangle's color to GREEN */
          if(this.collidesWith(mRectangleOne) && this.getColor() != org.andengine.util.adt.color.Color.GREEN){
          this.setColor(org.andengine.util.adt.color.Color.GREEN);

          /* If the rectangle's are no longer colliding, set this rectangle's color to RED */
          } else if(this.getColor() != org.andengine.util.adt.color.Color.RED){
          this.setColor(org.andengine.util.adt.color.Color.RED);
          }

          /* Proceed with the rest of this Entity's update process */
          super.onManagedUpdate(pSecondsElapsed);
       }
    ```

## 工作原理…

在我们创建的第一个`Rectangle`对象中，我们重写其`onManagedUpdate(pSecondsElapsed)`方法，以持续更新旋转到新值。对于第二个`Rectangle`对象，我们使其从屏幕最左侧连续移动到最右侧。当第二个矩形到达屏幕最右侧时，它会被重新定位到左侧，并将场景中的`Rectangle`对象提高半个`Rectangle`对象的高度。此外，当两个矩形重叠时，移动的矩形将改变颜色为绿色，直到它们不再接触。

第一步的代码允许我们在每次实体更新时创建一个事件。在这个特定的重写方法中，我们基于自上次更新以来经过的秒数计算`Rectangle`对象的旋转偏移量。因为实体每秒更新多次，具体取决于设备能够达到的每秒帧数，我们将`pSecondsElapsed`乘以`25`以稍微增加旋转速度。否则，我们每次更新时将使实体沿`0.01`度旋转，那样物体以该速率完成一次完整旋转将需要相当长的时间。我们可以在处理更新时利用`pSecondsElapsed`更新，以便基于自上次更新以来经过的时间对事件进行修改。

第二步比第一步要复杂一些。在第二步中，我们覆盖了第二个矩形的`onManagedUpdate()`方法，以便在每次实体更新时执行位置检查、碰撞检查以及更新矩形的定位。首先，我们声明了一些变量，这些变量将包含如实体当前位置、实体的半宽和半高值以便从锚点中心正确偏移，以及用于检查位置的下一个更新位置等值。这样做可以减少实体更新过程中所需计算的数量。如果在更新线程中应用了优化不佳的代码，很快就会导致帧率降低。尽可能多地使用方法调用和计算是很重要的；例如，在`onManagedUpdate()`方法中多次获取`currentX`值，比多次调用`this.getX()`更为理想。

继续第二步中的位置检查和更新，我们首先确定矩形的锚点中心加上其半宽（由`maxWidth`变量表示）是否小于或等于表示显示最右侧坐标的`WIDTH`值。如果为真，我们会将矩形的 x 坐标增加`incrementXValue`，即 5 个像素。另一方面，如果`nextHeight`值大于或等于摄像机的`HEIGHT`值，我们会将矩形对象重置回场景的左下角；或者如果矩形还没有到达显示顶部，只需将矩形的宽度增加其半宽并返回到左侧。

最后，我们在第二个`Rectangle`对象的`onManagedUpdate()`方法中拥有了碰撞检查方法。通过调用`this.collidesWith(mRectangleOne)`，我们可以确定`this`对象是否与指定对象（在本例中是`mRectangleOne`）发生重叠。然后我们会进行一个额外的检查，以确定如果检测到碰撞，颜色是否已经等于我们打算将`Rectangle`对象改变成的颜色；如果条件返回`true`，则将`Rectangle`对象设置为绿色。然而，如果每个更新都由多个`Entity`对象执行，`collidesWith()`可能是一个相当昂贵的碰撞检查方法！在这个示例中，我们纯粹是将此碰撞检查方法作为示例。一个可以考虑的选项是在执行碰撞检测之前，对两个对象进行轻量级的距离检测。

## 还有更多…

如前所述，*所有子对象都会从其父对象接收到更新调用*。在这种情况下，子实体也继承了父级修改后的`pSecondsElapsed`值。我们甚至可以通过重写其`onManagedUpdate()`方法并减少`pSecondsElapsed`值，来减慢整个`Scene`对象及其所有子对象的运行速度，如下所示：

```kt
super.onManagedUpdate(pSecondsElapsed * 0.5f);
```

将等于`pSecondsElapsed`值一半的返回值传递给`super`方法，将导致所有附加到该`Scene`对象的实体在各个方面都减慢一半。这是在考虑游戏暂停或创建慢动作效果选项时需要记住的一点小技巧。

# 使用修改器和实体修改器

AndEngine 为我们提供了所谓的**修改器**和**实体修改器**。通过使用这些修改器，我们可以非常轻松地为实体应用整洁的效果。这些修改器在定义的时间范围内对`Entity`对象应用特定的变化，如移动、缩放、旋转等。此外，我们还可以为实体修改器包含监听器和缓动函数，以完全控制它们的工作方式，这使得它们成为在我们的`Scene`对象中应用某些类型动画的最强大方法之一。

### 注意

在继续之前，我们应该提到 AndEngine 中的修改器和实体修改器是两个不同的对象。修改器是直接应用于实体，随时间修改实体的属性，如缩放、移动和旋转。而实体修改器则用作任何数量的修改器的容器，处理一组修改器的执行顺序。这将在本食谱的后续内容中进一步讨论。

## 准备就绪…

此食谱需要了解 AndEngine 中`Entity`对象的基础知识。请阅读本章提供的*了解 AndEngine 实体*的整个食谱，然后创建一个新的空 AndEngine 项目，包含一个`BaseGameActivity`类，然后参考此食谱中的*如何操作…*部分。

## 如何操作…

在此食谱中，我们将介绍 AndEngine 的实体修改器，包括修改器监听器和缓动函数，以应用平滑的过渡效果。如果这听起来令人困惑，不必害怕！AndEngine 的修改器实际上非常易于使用，只需几个基本步骤就可以为我们的`Entity`对象应用不同类型的动画。以下步骤涵盖了设置具有移动修改器的`Entity`对象，这将引导我们进一步讨论实体修改器。将这些步骤中的代码导入到活动的`onPopulateScene()`方法中：

1.  创建并附加任何类型的实体到`Scene`对象。我们将为这个实体应用实体修改器：

    ```kt
    /* Define the rectangle's width/height values */
    final int rectangleDimensions = 80;

    /* Define the initial rectangle position in the bottom 
     * left corner of the Scene */
    final int initialPosition = (int) (rectangleDimensions * 0.5f);

    /* Create the Entity which we will apply modifiers to */
    Rectangle rectangle = new Rectangle(initialPosition, initialPosition, rectangleDimensions, rectangleDimensions, mEngine.getVertexBufferObjectManager());

    /* Set the rectangle's color to white so we can see it on the Scene */
    rectangle.setColor(org.andengine.util.adt.color.Color.WHITE);

    /* Attach the rectangle to the Scene */
    mScene.attachChild(rectangle);
    ```

1.  一旦我们在`Scene`对象上放置了一个实体，我们就可以开始创建我们的修改器了。在这一步中，我们将创建一个`MoveModifier`对象，它允许我们随时间对实体的位置进行更改。但首先，我们将定义其值：

    ```kt
    /* Define the movement modifier values */
    final float duration = 3;
    final float fromX = initialPosition;
    final float toX = WIDTH - rectangleDimension * 0.5f;
    final float fromY = initialPosition;
    final float toY = HEIGHT - rectangleDimension * 0.5f;

    /* Create the MoveModifier with the defined values */
    MoveModifier moveModifier = new MoveModifier(duration, fromX, fromY, toX, toY);
    ```

1.  现在我们已经创建并设置好了`moveModifier`对象，我们可以通过以下调用将此修改器注册到我们希望的任何实体上，这将开始移动效果：

    ```kt
    /* Register the moveModifier to our rectangle entity */
    rectangle.registerEntityModifier(moveModifier);
    ```

## 它的工作原理是……

实体修改器的话题相当广泛，因此我们将从步骤开始深入。从那里，我们将使用这些步骤作为基础，以便进一步深入到关于实体修改器使用更复杂的讨论和示例。

在第一步中，我们只是创建了一个`Entity`对象，在这个案例中是一个`Rectangle`，我们将用它作为应用修改器的测试对象。只需将此步骤中的代码添加到`onPopulateScene()`方法中；在接下来的修改器和实体修改器“实验”中，这段代码将保持不变。

在第二步中，我们将开始使用最基本的修改器之一，当然是`MoveModifier`。这个修改器允许我们定义移动的起始位置、结束位置以及从起点到终点移动所需的秒数。正如我们所看到的，这非常简单，修改器最值得注意的是，在大多数情况下，这就是设置大多数修改器所需的全部内容。所有修改器真正需要的是一个“from”值、一个“to”值以及定义“from-to”发生秒数的时长。记住这一点，在大多数情况下，使用修改器将会非常轻松！

接下来，在第三步中，我们只需通过`registerEntityModifier(pModifier)`方法将我们新创建的`moveModifier`对象应用到`rectangle`对象上。这将使`moveModifier`效果应用到矩形上，首先将其定位到“from”坐标，然后在 3 秒的时间内移动到“to”坐标。

我们知道，要向`Entity`对象注册修改器或实体修改器，可以调用`entity.registerEntityModifier(pEntityModifier)`，但我们也应该知道，一旦完成修改器，我们应该将其从`Entity`对象中移除。我们可以通过调用`entity.unregisterEntityModifier(pEntityModifier)`来实现，或者如果我们想移除附加到`Entity`对象的所有实体修改器，可以调用`entity.clearEntityModifiers()`。另一方面，如果一个修改器或实体修改器运行了完整的时长，而我们还没有准备好从实体中移除它，我们必须调用`modifier.reset()`以重新播放效果。或者，如果我们想在重新播放效果之前对修改器进行微调，可以调用`modifier.reset(duration, fromValue, toValue)`。其中`reset`方法中的参数将相对于我们要重置的修改器类型。

`moveModifier`对象有效，但它非常无聊！毕竟，我们只是在将一个矩形从场景的左下角移动到右上角。幸运的是，这只是修改器应用表面的刮擦。以下小节包含了 AndEngine 能够应用到我们的`Entity`对象的所有修改器的参考，必要时还提供了示例。

### AndEngine 的修改器

以下是我们可以应用到实体上的所有 AndEngine 修改器的集合。更高级的修改器将提供一个快速示例代码片段。在介绍它们时，请随意在您的测试项目中尝试：

+   `AlphaModifier`：使用这个修改器，可以随时间调整实体的透明度值。构造函数的参数包括持续时间、起始透明度和结束透明度，依次排列。

+   `ColorModifier`：使用这个修改器，可以随时间调整实体的颜色值。构造函数的参数包括持续时间、起始红色、结束红色、起始绿色、结束绿色、起始蓝色和结束蓝色，依次排列。

+   `DelayModifier`：这个修改器旨在分配给实体修改器对象，以便在一个修改器被执行和另一个修改器被执行之间提供延迟。参数包括持续时间。

+   `FadeInModifier`：基于`AlphaModifier`类，`FadeInModifier`修改器在定义的持续时间内在构造函数中提供，将实体的透明度值从`0.0f`更改为`1.0f`。

+   `FadeOutModifier`：与`FadeOutModifier`类似，只不过透明度值被交换了。

+   `JumpModifier`：这个修改器可以用来向实体应用“跳跃”动作。参数包括持续时间、起始 X、结束 X、起始 Y、结束 Y 和跳跃高度。这些值将定义在定义的持续时间内在视觉上实体跳跃的距离和高度。

+   `MoveByModifier`：这个修改器允许我们偏移实体的位置。参数包括持续时间、X 偏移和 Y 偏移，依次排列。例如，指定一个偏移量为`-15`将使实体在场景上向左移动 15 个单位。

+   `MoveXModifier`和`MoveYModifier`：这些修改器与`MoveModifier`类似，允许我们向实体提供移动。然而，这些方法只根据方法名称确定在单个轴上应用移动。参数包括持续时间、起始坐标和结束坐标，依次排列。

+   `RotationAtModifier`：这个修改器允许我们在偏移旋转中心的同时向实体应用旋转。参数包括持续时间、起始旋转、结束旋转、旋转中心 X 和旋转中心 Y。

+   `RotationByModifier`：这个修改器允许我们偏移实体的当前旋转值。参数包括持续时间和旋转偏移值。例如，提供一个旋转偏移值为`90`将使实体顺时针旋转九十度。

+   `RotationModifier`：这个修改器允许我们从一个特定值旋转实体到另一个特定值。参数包括持续时间、起始旋转和目标旋转。

+   `ScaleAtModifier`：这个修改器允许我们在缩放时偏移缩放中心来缩放实体。参数包括持续时间、起始缩放、目标缩放、缩放中心 x 和缩放中心 y。

+   `ScaleModifier`：这个修改器允许我们从一个特定值缩放实体到另一个特定值。参数包括持续时间、起始缩放和目标缩放，按此顺序。

+   `SkewModifier`：这个修改器允许我们随时间改变实体的 x 和 y 值。参数包括持续时间、起始斜切 x、目标斜切 x、起始斜切 y 和目标斜切 y，顺序是特定的。

+   `PathModifier`：这个修改器相对于`MoveModifier`，不过我们可以添加任意多的“到”坐标。这使得我们可以在`Scene`对象上为实体创建一个路径，通过为`PathModifier`修改器指定 x/y 坐标对来跟随。在以下步骤中，我们将了解如何为我们的实体创建一个`PathModifier`修改器：

    1.  定义路径的航点。x 和 y 坐标的航点数组应该具有相同数量的点，因为它们将按顺序配对以形成`PathModifier`的单个 x/y 坐标。我们必须在每个数组中至少设置两个点，因为我们需要至少一个起始点和结束点：

        ```kt
            /* Create a list which specifies X coordinates to follow */
            final float pointsListX[] = {
                initialPosition, /* First x position */
                WIDTH - initialPosition, /* Second x position */
                WIDTH - initialPosition, /* Third x position */
                initialPosition, /* Fourth x position */
                initialPosition /* Fifth x position */
            };

            /* Create a list which specifies Y coordinates to follow */
            final float pointsListY[] = {
                initialPosition, /* First y position */
                HEIGHT - initialPosition, /* Second y position */
                initialPosition, /* Third y position */
                HEIGHT - initialPosition, /* Fourth y position */
                initialPosition /* Fifth y position */
            };
        ```

    1.  创建一个`Path`对象，我们将使用它将分开数组中的各个点配对成航点。我们通过遍历数组并在`path`对象上调用`to(pX, pY)`方法来实现这一点。请注意，每次我们调用这个方法，我们都在`path`对象中添加一个额外的航点：

        ```kt
            /* Obtain the number of control points we have */
            final int controlPointCount = pointsListX.length;

            /* Create our Path object which we will pair our x/y coordinates into */
            org.andengine.entity.modifier.PathModifier.Path path = new Path(controlPointCount);

            /* Iterate through our point lists */
            for(int i = 0; i < controlPointCount; i++){
              /* Obtain the coordinates of the control point at the index */
              final float positionX = pointsListX[i];
              final float positionY = pointsListY[i];

              /* Setup a new way-point by pairing together an x and y coordinate */
              path.to(positionX, positionY);
            }
        ```

    1.  最后，一旦我们定义了航点，就可以创建`PathModifier`对象，提供持续时间以及我们的`path`对象作为参数：

        ```kt
            /* Movement duration */
            final float duration = 3;
            /* Create the PathModifier */
            PathModifier pathModifier = new PathModifier(duration, path);

            /* Register the pathModifier object to the rectangle */
            rectangle.registerEntityModifier(pathModifier);
        ```

+   `CardinalSplineMoveModifier`：这是我们最后要讨论的修改器。这个修改器与`PathModifier`修改器相对相似，不过我们可以对`Entity`对象的移动施加张力。这允许在接近拐角或改变方向时实现更流畅和平滑的移动，实际上看起来相当不错。在以下步骤中，我们将了解如何为我们的实体创建一个`CardinalSplineMoveModifier`修改器：

    1.  第一步与`PathModifier`修改器类似，是创建我们的点数组。在这个例子中，我们可以从`PathModifier`示例的第一步复制代码。然而，这个修改器与`PathModifier`对象的一个区别在于，我们需要至少 4 个单独的 x 和 y 点。

    1.  第二步是确定控制点的数量，定义张力，并创建一个`CardinalSplineMoveModifierConfig`对象。这是`CardinalSplineMoveModifier`修改器的`PathModifier`修改器中`Path`对象的等价物。张力可以在`-1`到`1`之间，不能多也不能少。张力为`-1`将使`Entity`对象的移动非常松散，在转角和方向变化时非常松散；而张力为`1`将非常像`PathModifier`修改器，在移动上非常严格：

        ```kt
            /* Obtain the number of control points we have */
            final int controlPointCount = pointsListX.length;

            /* Define the movement tension. Must be between -1 and 1 */
            final float tension = 0f;

            /* Create the cardinal spline movement modifier configuration */
            CardinalSplineMoveModifierConfig config = new CardinalSplineMoveModifierConfig(controlPointCount, tension);
        ```

    1.  在第三步中，与`PathModifier`修改器非常相似，我们必须将 x/y 坐标配对在我们的点数组中，不过在这个情况下，我们是将它们存储在`config`对象中：

        ```kt
            /* Iterate through our control point indices */
            for(int index = 0; index < controlPointCount; index++){

              /* Obtain the coordinates of the control point at the index */
              final float positionX = pointsListX[index];
              final float positionY = pointsListY[index];

              /* Set position coordinates at the current index in the config object */
              config.setControlPoint(index, positionX, positionY);
            }
        ```

    1.  接下来，我们只需简单地定义移动的持续时间，创建`CardinalSplineMoveModifier`修改器，提供持续时间和`config`对象作为参数，并最终将修改器注册到`Entity`对象上：

        ```kt
            /* Movement duration */
            final float duration = 3;

            /* Create the cardinal spline move modifier object */
            CardinalSplineMoveModifier cardinalSplineMoveModifier = new CardinalSplineMoveModifier(duration, config);

            /* Register the cardinalSplineMoveModifier object to the rectangle object */
            rectangle.registerEntityModifier(cardinalSplineMoveModifier);
        ```

现在我们已经对可以应用到实体上的各个修改器有了深入的理解，我们将介绍 AndEngine 中的三个主要实体修改器以及它们的用途。

### AndEngine 的实体修改器

AndEngine 包含三种实体修改器对象，用于通过将两个或更多修改器组合成一个单一事件或序列，为我们的`Entity`对象构建复杂的动画。这三种不同的实体修改器包括`LoopEntityModifier`、`ParallelEntityModifier`和`SequenceEntityModifier`对象。接下来，我们将描述这些实体修改器的具体细节和示例，展示如何将它们组合成单一动画事件。

+   `LoopEntityModifier`：这个实体修改器允许我们无限次数或指定次数（如果提供了第二个`int`参数）循环指定的修改器。这是最简单的实体修改器。一旦我们设置好了`LoopEntityModifier`，就可以直接将其应用于`Entity`对象：

    ```kt
        /* Define the move modifiers properties */
        final float duration = 3;
        final float fromX = 0;
        final float toX = 100;

        /* Create the move modifier */
        MoveXModifier moveXModifier = new MoveXModifier(duration, fromX, toX);

        /* Create a loop entity modifier, which will loop the move modifier
         *  indefinitely, or until unregistered from the rectangle.
         *  If we want to provide a loop count, we can add a second int parameter 
         *  to this constructor */
        LoopEntityModifier loopEntityModifier = new LoopEntityModifier(moveXModifier);

        /* register the loopEntityModifier to the rectangle */
        rectangle.registerEntityModifier(loopEntityModifier);

    ```

+   `ParallelEntityModifier`：这个实体修改器允许我们将无限数量的修改器组合成一个单一动画。这个实体修改器提供的参数中的修改器将同时运行在`Entity`对象上。这使得我们可以在旋转时缩放修改器，例如，在以下示例中可以看到。欢迎在示例中添加更多修改器进行练习：

    ```kt
        /* Scale modifier properties */
        final float scaleDuration = 2;
        final float fromScale = 1;
        final float toScale = 2;
        /* Create a scale modifier */
        ScaleModifier scaleModifier = new ScaleModifier(scaleDuration, fromScale, toScale);

        /* Rotation modifier properties */
        final float rotateDuration = 3;
        final float fromRotation = 0;
        final float toRotation = 360 * 4;
        /* Create a rotation modifier */
        RotationModifier rotationModifier = new RotationModifier(rotateDuration, fromRotation, toRotation);

        /* Create a parallel entity modifier */
        ParallelEntityModifier parallelEntityModifier = new ParallelEntityModifier(scaleModifier, rotationModifier);

        /* Register the parallelEntityModifier to the rectangle */
        rectangle.registerEntityModifier(parallelEntityModifier);

    ```

+   `SequenceEntityModifier`：这个实体修改器允许我们将修改器串联起来，在单个`Entity`对象上按顺序执行。这个修改器是在之前提到的修改器列表中使用`DelayModifier`对象的理想实体修改器。以下示例显示了一个从屏幕左下角移动到屏幕中心的`Entity`对象，暂停`2`秒，然后缩小到比例因子为`0`：

    ```kt
        /* Move modifier properties */
        final float moveDuration = 2;
        final float fromX = initialPosition;
        final float toX = WIDTH * 0.5f;
        final float fromY = initialPosition;
        final float toY = HEIGHT * 0.5f;
        /* Create a move modifier */
        MoveModifier moveModifier = new MoveModifier(moveDuration, fromX, fromY, toX, toY);

        /* Create a delay modifier */
        DelayModifier delayModifier = new DelayModifier(2);

        /* Scale modifier properties */
        final float scaleDuration = 2;
        final float fromScale = 1;
        final float toScale = 0;
        /* Create a scale modifier */
        ScaleModifier scaleModifier = new ScaleModifier(scaleDuration, fromScale, toScale);

        /* Create a sequence entity modifier */
        SequenceEntityModifier sequenceEntityModifier = new SequenceEntityModifier(moveModifier, delayModifier, scaleModifier);

        /* Register the sequenceEntityModifier to the rectangle */
       rectangle.registerEntityModifier(sequenceEntityModifier);
    ```

更重要的是要知道我们可以将`SequenceEntityModifier`修改器添加到`ParallelEntityModifier`修改器中，将`ParallelEntityModifier`修改器添加到`LoopEntityModifier`修改器中，或者是我们能想到的任何其他组合！这使得修改器和实体修改器的可能性变得极其广泛，并允许我们以相当大的便利性为实体创建极其复杂的动画。

## 还有更多内容...

在继续下一个主题之前，我们应该看看为实体修改器包含的额外特性。还有两个参数我们可以传递给实体修改器，我们之前还没有讨论过；那就是修改器监听器和缓动函数。这两个类可以帮助我们使修改器比我们在*如何工作...*部分看到的更加定制化。

`IEntityModifierListener`监听器可以用来在修改器开始和结束时触发事件。在以下代码段中，我们只是简单地向 logcat 打印日志，以通知我们修改器何时开始和结束。

```kt
IEntityModifierListener entityModifierListener = new IEntityModifierListener(){

  // When the modifier starts, this method is called
  @Override
  public void onModifierStarted(IModifier<IEntity> pModifier,
      IEntity pItem) {
    Log.i("MODIFIER", "Modifier started!");
  }

  // When the modifier finishes, this method is called
  @Override
  public void onModifierFinished(final IModifier<IEntity> pModifier,
      final IEntity pItem) {
    Log.i("MODIFIER", "Modifier started!");
  }
};

modifier.addModifierListener();
```

之前的代码展示了一个带有基本日志输出的修改器监听器的框架。在更接近游戏开发的场景中，一旦修改器完成，我们可以调用`pItem.setVisible(false)`。例如，这可以用于处理场景中细微的落叶或雨滴，这些落叶或雨滴离开了摄像头的视野。然而，我们决定用监听器来做什么完全取决于我们自己的判断。

最后，我们将快速讨论 AndEngine 中的缓动函数。缓动函数是给实体修改器添加额外“酷炫”层次的好方法。习惯了修改器之后，缓动函数可能会真正吸引你，因为它们给修改器带来了所需的额外动力，以产生完美效果。解释缓动函数的最好方法是想象一个游戏，菜单按钮从屏幕顶部落下并“弹跳”到位。这里的弹跳就是我们的缓动函数产生效果的情况。

```kt
    /* Move modifier properties */
    final float duration = 3;
    final float fromX = initialPosition;
    final float toX = WIDTH - initialPosition;
    final float fromY = initialPosition;
    final float toY = HEIGHT - initialPosition;

    /* Create a move modifier with an ease function */
    MoveModifier moveModifier = new MoveModifier(duration, fromX, fromY, toX, toY, org.andengine.util.modifier.ease.EaseElasticIn.getInstance());

    rectangle.registerEntityModifier(moveModifier);
```

正如我们在这里看到的，给修改器应用缓动函数只需在修改器的构造函数中添加一个额外的参数即可。通常最困难的部分是选择使用哪一个，因为缓动函数列表相当长。花些时间查看`org.andengine.util.modifier.ease`包提供的各种缓动函数。只需将前一段代码中的`EaseElasticIn`替换为你想要测试的缓动函数，然后重新构建项目以查看效果！

### 提示

**缓动函数参考**

从 Google Play 将**AndEngine – Examples**应用程序下载到你的设备上。打开应用程序并找到**Using EaseFunctions**的例子。尽管与最新的 AndEngine 分支相比，示例应用程序相当过时，但缓动函数示例仍然是一个绝对有效的工具，用于确定哪些缓动函数最适合我们游戏的需求！

## 另请参阅

+   本章节中*了解 AndEngine 实体*。

# 使用粒子系统

**粒子系统**可以为我们的游戏提供非常吸引人的效果，涵盖游戏中的许多不同事件，如爆炸、火花、血腥、雨等。在本章中，我们将介绍 AndEngine 的`ParticleSystem`类，这将用于创建定制化的粒子效果，满足我们的各种需求。

## 准备工作…

本食谱需要了解 AndEngine 中`Sprite`对象的基础知识。请阅读第一章中的整个食谱，*使用不同类型的纹理*以及本章中给出的*了解 AndEngine 实体*。接下来，创建一个带有`BaseGameActivity`类的新的空 AndEngine 项目，并从代码包中的`WorkingWithParticles`类导入代码。

## 如何操作…

为了开始在 AndEngine 中创建粒子效果，我们需要至少三个对象。这些对象包括代表生成的单个粒子的`ITextureRegion`对象，一个`ParticleSystem`对象和一个`ParticleEmitter`对象。一旦我们有了这些，我们就可以开始向我们的粒子系统添加所谓的粒子初始化器和粒子修改器，以创建我们自己的个性化效果。以下步骤将指导如何设置一个基本的粒子系统，以便在此基础上进行构建。

1.  第一步涉及决定我们希望粒子系统生成的图像。这可以是任何图像、任何颜色和任何大小。随意创建一个图像，并设置`BuildableBitmapTextureAtlas`和`ITextureRegion`来将图像加载到测试项目的资源中。为了保持事情简单，请将图像的尺寸控制在 33x33 像素以下以适应本食谱。

1.  创建`ParticleEmitter`对象。现在我们将使用`PointParticleEmitter`对象子类型：

    ```kt
        /* Define the center point of the particle system spawn location */
        final int particleSpawnCenterX = (int) (WIDTH * 0.5f);
        final int particleSpawnCenterY = (int) (HEIGHT * 0.5f);

        /* Create the particle emitter */
        PointParticleEmitter particleEmitter = new PointParticleEmitter(particleSpawnCenterX, particleSpawnCenterY);
    ```

1.  创建`ParticleSystem`对象。我们将使用`BatchedSpriteParticleSystem`对象实现，因为它是 AndEngine 中包含的最新和最好的`ParticleSystem`对象子类型。它允许我们创建大量粒子，同时大大降低典型`SpriteParticleSystem`对象的开销：

    ```kt
        /* Define the particle system properties */
        final float minSpawnRate = 25;
        final float maxSpawnRate = 50;
        final int maxParticleCount = 150;

        /* Create the particle system */
        BatchedSpriteParticleSystem particleSystem = new BatchedSpriteParticleSystem(
            particleEmitter, minSpawnRate, maxSpawnRate, maxParticleCount,
            mTextureRegion,
            mEngine.getVertexBufferObjectManager());
    ```

1.  在创建粒子系统的最后一步中，我们将添加任意组合的粒子发射器和粒子修改器，然后将粒子系统附加到`Scene`对象上：

    ```kt
        /* Add an acceleration initializer to the particle system */
        particleSystem.addParticleInitializer(new AccelerationParticleInitializer<UncoloredSprite>(25f, -25f, 50f, 100f));

        /* Add an expire initializer to the particle system */
        particleSystem.addParticleInitializer(new ExpireParticleInitializer<UncoloredSprite>(4));

        /* Add a particle modifier to the particle system */
        particleSystem.addParticleModifier(new ScaleParticleModifier<UncoloredSprite>(0f, 3f, 0.2f, 1f));

        /* Attach the particle system to the Scene */
        mScene.attachChild(particleSystem);
    ```

## 它是如何工作的…

对于许多新的 AndEngine 开发者来说，处理粒子似乎是一个相当困难的课题，但实际上恰恰相反。在 AndEngine 中创建粒子效果非常简单，但如往常一样，我们应该学会走再尝试飞！在本食谱的步骤中，我们设置了一个相当基础的粒子系统。随着话题的深入，我们将讨论并插入粒子系统的其他模块化组件，以拓宽我们对构成复杂粒子系统效果各个部分的知识。

在第一步中，我们需要建立一个`ITextureRegion`对象来为我们的粒子系统提供资源。`ITextureRegion`对象将视觉上代表每个生成的独立粒子。纹理区域可以是任何大小，但通常它们会在 2 x 2 到 32 x 32 像素之间。请记住，粒子系统旨在生成大量的对象，因此`ITextureRegion`对象越小，就粒子系统而言性能会越好。

在第二步中，我们创建了一个粒子发射器并将其置于`Scene`对象的中心。粒子发射器是粒子系统中的一个组件，它控制着粒子的初始生成位置。在本食谱中，我们使用的是`PointParticleEmitter`对象类型，它会简单地在场景上以`particleSpawnCenterX`和`particleSpawnCenterY`变量定义的相同坐标生成所有粒子。AndEngine 还包括其他四种粒子发射器类型，我们稍后会进行讨论。

当我们创建并适当地设置好粒子发射器后，我们可以进入第三步并创建`BatchedSpriteParticleSystem`对象。我们需要按顺序向`BatchedSpriteParticleSystem`对象传递的参数包括：粒子发射器、粒子的最小生成速率、最大生成速率、可以同时显示的最大粒子数量、粒子应视觉代表的`ITextureRegion`对象，以及`mEngine`对象的顶点缓冲区对象管理器。

最后，在第四步中，我们添加了一个`AccelerationParticleInitializer`对象，它将为粒子提供加速运动，使它们不仅仅停留在它们产生的地方。我们还添加了一个`ExpireParticleInitializer`对象，用于在定义的时间后销毁粒子。如果没有某种初始化器或修改器移除粒子，`BatchedParticleSystem`对象最终会达到其最大粒子限制，并停止产生粒子。最后，我们向粒子系统添加了一个`ScaleParticleModifier`对象，它将随时间改变每个粒子的缩放比例。这些粒子初始化器和粒子修改器将稍作深入解释，现在只需知道这是我们应用它们到粒子系统的步骤。添加完我们选择的初始化器和修改器后，我们将`particleSystem`对象附加到`Scene`对象上。

完成这四个步骤后，粒子系统将开始产生粒子。然而，我们可能并不总是希望粒子从特定的粒子系统中产生。要禁用粒子产生，可以调用`particleSystem.setParticlesSpawnEnabled(false)`，或者设置为`true`以重新启用粒子产生。除了这个方法，`BatchedSpriteParticleSystem`对象还包含`Entity`对象的所有普通功能和方法。

有关粒子系统的各个组成部分的更多信息，请参见以下子主题。这些主题包括粒子发射器、粒子初始化器和粒子修改器。

### 粒子发射器的选择

AndEngine 包含五种可立即使用的粒子发射器，它们可以改变场景上粒子的初始放置，这不应与定义粒子发射器位置混淆。有关每个粒子发射器的工作原理，请查看粒子发射器列表。请随时在步骤二的配方中用以下列表中的粒子发射器替换粒子发射器。

+   `PointParticleEmitter`：这是最基础的粒子发射器；这种粒子发射器使所有产生的粒子在场景上同一定义的位置产生。粒子产生的位置不会有任何变化。然而，可以通过调用`pointParticleEmitter.setCenter(pX, pY)`方法来改变粒子发射器的位置，其中`pX`和`pY`定义了产生粒子的新坐标。

+   `CircleOutlineParticleEmitter`：这种粒子发射器子类型将使粒子在圆形轮廓的位置产生。这个发射器构造函数中需要包含的参数包括 x 坐标、y 坐标和一个定义圆形轮廓整体大小的半径。请看以下示例：

    ```kt
        /* Define the center point of the particle system spawn location */
        final int particleSpawnCenterX = (int) (WIDTH * 0.5f);
        final int particleSpawnCenterY = (int) (HEIGHT * 0.5f);

        /* Define the radius of the circle for the particle emitter */
        final float particleEmitterRadius = 50;

        /* Create the particle emitter */
        CircleOutlineParticleEmitter particleEmitter = new CircleOutlineParticleEmitter(particleSpawnCenterX, particleSpawnCenterY, particleEmitterRadius);
    ```

+   `CircleParticleEmitter`：这种粒子发射器子类型允许粒子在`CircleOutlineParticleEmitter`对象仅限于边缘轮廓的圆形区域内任何位置生成。`CircleParticleEmitter`对象在其构造函数中需要与`CircleOutlineParticleEmitter`对象相同的参数。要测试这种粒子发射器子类型，只需将`CircleOutlineParticleEmitter`示例中的对象重构为使用`CircleParticleEmitter`对象即可。

+   `RectangleOutlineParticleEmitter`：这种粒子发射器子类型将导致粒子从由构造函数参数定义大小的矩形的四个角生成。与`CircleOutlineParticleEmitter`对象不同，这种粒子发射器不允许粒子围绕矩形的整个边缘生成。请参阅以下示例：

    ```kt
        /* Define the center point of the particle system spawn location */
        final int particleSpawnCenterX = (int) (WIDTH * 0.5f);
        final int particleSpawnCenterY = (int) (HEIGHT * 0.5f);

        /* Define the width and height of the rectangle particle emitter */
        final float particleEmitterWidth = 50;
        final float particleEmitterHeight = 100;

        /* Create the particle emitter */
        RectangleOutlineParticleEmitter particleEmitter = new RectangleOutlineParticleEmitter(particleSpawnCenterX, particleSpawnCenterY, particleEmitterWidth, particleEmitterHeight);
    ```

+   `RectangleParticleEmitter`：这种粒子发射器子类型允许粒子在由构造函数参数定义的矩形形状的边界区域内任何位置生成。要测试这种粒子发射器子类型，只需将`RectangleOutlineParticleEmitter`示例中的对象重构为使用`RectangleParticleEmitter`对象即可。

### 粒子初始化器选择

粒子初始化器对粒子系统至关重要。它们为我们提供了对最初生成的每个单独粒子执行操作的可能性。这些粒子初始化器最棒的一点是，它们允许我们提供最小/最大值，这使我们有机会随机化生成粒子的属性。以下列出了 AndEngine 提供的所有粒子初始化器及其使用示例。请随意用此列表中的粒子初始化器替换配方中的那些。

### 注意

以下粒子初始化器可以通过简单的调用`particleSystem.addParticleInitializer(pInitializer)`添加，此外，还可以通过`particleSystem.removeParticleInitializer(pInitializer)`移除。

+   `ExpireParticleInitializer`：我们将从列表中最必要的粒子初始化器开始。`ExpireParticleInitializer`对象提供了一种移除存活时间过长的粒子的方法。如果我们不包括某种形式的粒子过期机制，那么随着所有粒子系统在任意给定时间都有可以激活的粒子数量的限制，我们的粒子很快就会没有粒子可以生成。以下示例创建了一个`ExpireParticleModifier`对象，该对象使单个粒子在`2`到`4`秒之间过期：

    ```kt
        /* Define min/max particle expiration time */
        final float minExpireTime = 2;
        final float maxExpireTime = 4;
        ExpireParticleInitializer<UncoloredSprite> expireParticleInitializer = new ExpireParticleInitializer<UncoloredSprite>(minExpireTime, maxExpireTime);
    ```

+   `AccelerationParticleInitializer`：这个初始化器允许我们以加速度的形式应用移动，使得生成的粒子在达到定义的速度之前会加速。x 轴或 y 轴上的正值将使粒子向上向右移动，而负值将使粒子向下向左移动。在以下示例中，将为粒子赋予最小/最大值，这将导致粒子的移动方向是随机的：

    ```kt
        /* Define the acceleration values */
        final float minAccelerationX = -25;
        final float maxAccelerationX = 25;
        final float minAccelerationY = 25;
        final float maxAccelerationY = 50;

        AccelerationParticleInitializer<UncoloredSprite> accelerationParticleInitializer = new AccelerationParticleInitializer<UncoloredSprite>(minAccelerationX, maxAccelerationX, minAccelerationY, maxAccelerationY);
    ```

+   `AlphaInitializer`：`AlphaInitializer`对象非常基础。它仅允许我们使用未确定的 alpha 值初始化粒子。以下示例将导致每个单独的粒子以`0.5f`到`1f`之间的 alpha 值生成：

    ```kt
        /* Define the alpha values */
        final float minAlpha = 0.5f;
        final float maxAlpha = 1;

        AlphaParticleInitializer<UncoloredSprite> alphaParticleInitializer = new AlphaParticleInitializer<UncoloredSprite>(minAlpha, maxAlpha);
    ```

+   `BlendFunctionParticleInitializer`：这个粒子初始化器允许我们生成应用了特定 OpenGL 混合函数的粒子。关于混合函数及其结果的更多信息，可以在网上找到许多资源。以下是使用`BlendFunctionParticleInitializer`对象的示例：

    ```kt
        BlendFunctionParticleInitializer<UncoloredSprite> blendFunctionParticleInitializer = new BlendFunctionParticleInitializer<UncoloredSprite>(GLES20.GL_ONE, GLES20.GL_ONE_MINUS_SRC_ALPHA);
    ```

+   `ColorParticleInitializer`：`ColorParticleInitializer`对象允许我们为精灵提供最小/最大值之间的颜色。这使得我们可以随机化每个生成粒子的颜色。以下示例将生成具有完全不同随机颜色的粒子：

    ```kt
        /* Define min/max values for particle colors */
        final float minRed = 0f;
        final float maxRed = 1f;
        final float minGreen = 0f;
        final float maxGreen = 1f;
        final float minBlue = 0f;
        final float maxBlue = 1f;

        ColorParticleInitializer<UncoloredSprite> colorParticleInitializer = new ColorParticleInitializer<UncoloredSprite>(minRed, maxRed, minGreen, maxGreen, minBlue, maxBlue);
    ```

+   `GravityParticleInitializer`：这个粒子初始化器允许我们生成像遵循地球重力规则一样的粒子。`GravityParticleInitializer`对象在其构造函数中不需要参数：

    ```kt
        GravityParticleInitializer<UncoloredSprite> gravityParticleInitializer = new GravityParticleInitializer<UncoloredSprite>();
    ```

+   `RotationParticleInitializer`：`RotationParticleInitializer`对象允许我们定义粒子生成时的旋转最小/最大值。以下示例将导致每个单独的粒子以`0`到`359`度之间的任意角度生成：

    ```kt
        /* Define min/max values for the particle's rotation */
        final float minRotation = 0;
        final float maxRotation = 359;

        RotationParticleInitializer<UncoloredSprite> rotationParticleInitializer = new RotationParticleInitializer<UncoloredSprite>(minRotation, maxRotation);
    ```

+   `ScaleParticleInitializer`：`ScaleParticleInitializer`对象允许我们定义粒子生成时的缩放最小/最大值。以下示例将允许粒子以`0.5f`到`1.5f`之间的任意比例因子生成：

    ```kt
        /* Define min/max values for the particle's scale */
        final float minScale = 0.5f;
        final float maxScale = 1.5f;
        ScaleParticleInitializer<UncoloredSprite> scaleParticleInitializer = new ScaleParticleInitializer<UncoloredSprite>(minScale, maxScale);
    ```

+   `VelocityParticleInitializer`：这个最后的粒子初始化器，与`AccelerationParticleInitializer`对象类似，允许我们在生成粒子时为它们提供移动。然而，这个初始化器使粒子以恒定速度移动，并且除非手动配置，否则不会随时间增加或减少速度：

    ```kt
        /* Define min/max velocity values of the particles */
        final float minVelocityX = -25;
        final float maxVelocityX = 25;
        final float minVelocityY = 25;
        final float maxVelocityY = 50;

        VelocityParticleInitializer<UncoloredSprite> velocityParticleInitializer = new VelocityParticleInitializer<UncoloredSprite>(minVelocityX, maxVelocityX, minVelocityY, maxVelocityY);
    ```

有关 AndEngine 的粒子修改器列表，请参阅以下部分。

### 粒子修改器选择

AndEngine 的粒子修改器在开发复杂的粒子系统时非常有用。它们允许我们根据粒子存活的时间为单个粒子提供变化。与实体修改器类似，粒子修改器是“从时间到时间，从值到值”的格式。再次强调，请随意将列表中的任何粒子修改器添加到您当前测试项目中。

### 注意

以下粒子修改器可以通过简单的调用`particleSystem.addParticleModifier(pModifier)`添加，并且可以通过`particleSystem.removeParticleModifier(pModifier)`移除。

+   `AlphaParticleModifier`：这个修改器允许粒子在其生命周期内，在两个时间点之间改变 alpha 值。以下示例中，修改器将在`1`秒内从 alpha 值`1`过渡到`0`。修改器将在粒子生成后`1`秒生效：

    ```kt
        /* Define the alpha modifier's properties */
        final float fromTime = 1;
        final float toTime = 2;
        final float fromAlpha = 1;
        final float toAlpha = 0;
        AlphaParticleModifier<UncoloredSprite> alphaParticleModifier = new AlphaParticleModifier<UncoloredSprite>(fromTime, toTime, fromAlpha, toAlpha);
    ```

+   `ColorParticleModifier`：这个修改器允许粒子在其生命周期内，在两个时间点之间改变颜色。以下修改器将导致粒子在两秒内从绿色变为红色，从时间`0`开始。这意味着过渡将在粒子生成后立即开始：

    ```kt
        /* Define the color modifier's properties */
        final float fromTime = 0;
        final float toTime = 2;
        final float fromRed = 0;
        final float toRed = 1;
        final float fromGreen = 1;
        final float toGreen = 0;
        final float fromBlue 0;
        final float toBlue = 0;

        ColorParticleModifier<UncoloredSprite> colorParticleModifier = new ColorParticleModifier<UncoloredSprite>(fromTime, toTime, fromRed, toRed, fromGreen, toGreen, fromBlue, toBlue);
    ```

+   `OffCameraExpireParticleModifier`：将此修改器添加到粒子系统中，离开`Camera`对象视野的粒子将被销毁。我们可以将此作为`ExpireParticleInitializer`对象的替代，但任何粒子系统至少应该激活这两者之一。需要提供给这个修改器的唯一参数是我们的`Camera`对象：

    ```kt
        OffCameraExpireParticleModifier<UncoloredSprite> offCameraExpireParticleModifier = new OffCameraExpireParticleModifier<UncoloredSprite>(mCamera);
    ```

+   `RotationParticleModifier`：这个修改器允许我们在粒子的生命周期内，在两个时间点之间改变粒子的旋转角度。以下示例将导致粒子在其生命周期的`1`到`4`秒之间旋转`180`度：

    ```kt
        /* Define the rotation modifier's properties */
        final float fromTime = 1;
        final float toTime = 4;
        final float fromRotation = 0;
        final float toRotation = 180;

        RotationParticleModifier<UncoloredSprite> rotationParticleModifier = new RotationParticleModifier<UncoloredSprite>(fromTime, toTime, fromRotation, toRotation);
    ```

+   `ScaleParticleModifier`：`ScaleParticleModifier`对象允许我们在粒子的生命周期内，在两个时间点之间改变粒子的缩放比例。以下示例将导致粒子在其生命周期的`1`到`3`秒之间，从缩放比例`0.5f`增长到`1.5f`：

    ```kt
        /* Define the scale modifier's properties */
        final float fromTime = 1;
        final float toTime = 3;
        final float fromScale = 0.5f;
        final float toScale = 1.5f;

        ScaleParticleModifier<UncoloredSprite> scaleParticleModifier = new ScaleParticleModifier<UncoloredSprite>(fromTime, toTime, fromScale, toScale);
    ```

+   `IParticleModifier`：最后，我们有了粒子修改器接口，它允许我们在粒子初始化时或通过更新线程对每个粒子进行更新时，对单个粒子进行自定义修改。以下示例展示了如何通过在粒子到达`Scene`对象坐标系下`20`以下值时，禁用 y 轴上的移动来模拟粒子着陆。我们可以使用这个接口，根据需要虚拟地对粒子进行任何更改：

    ```kt
        IParticleModifier<UncoloredSprite> customParticleModifier = new IParticleModifier<UncoloredSprite>(){

          /* Fired only once when a particle is first spawned */
          @Override
          public void onInitializeParticle(Particle<UncoloredSprite> pParticle) {
              * Make customized modifications to a particle on initialization */
          }

          /* Fired on every update to a particle in the particle system */
          @Override
          public void onUpdateParticle(Particle<UncoloredSprite> pParticle) {
              * Make customized modifications to a particle on every update to the particle */
                    Entity entity = pParticle.getEntity();
              * Obtain the particle's position and movement properties */
            final float currentY = entity.getY();
            final float currentVelocityY = pParticle.getPhysicsHandler().getVelocityY();
            final float currentAccelerationY = pParticle.getPhysicsHandler().getAccelerationY();

            /* If the particle is close to the bottom of the Scene and is moving... */
            if(entity.getY() < 20 && currentVelocityY != 0 || currentAccelerationY != 0){

              /* Restrict movement on the Y axis. Simulates landing on the ground */
              pParticle.getPhysicsHandler().setVelocityY(0);
              pParticle.getPhysicsHandler().setAccelerationY(0);
            }
            }

        };
    ```

既然我们已经介绍了所有的粒子发射器、粒子初始化器和粒子修改器，尝试通过组合你想要的初始化器和修改器，创建更复杂的粒子系统吧！

## 另请参阅

+   在第一章，*AndEngine 游戏结构*中*使用不同类型的纹理*。

+   本章节中的*了解 AndEngine 实体*。
