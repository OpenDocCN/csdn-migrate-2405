# AndEngine 安卓游戏开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A`](https://zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：设计你的菜单

在本章中，我们将开始了解如何使用 AndEngine 创建一个易于管理的菜单系统。主题包括：

+   向菜单添加按钮

+   为菜单添加音乐

+   应用背景

+   使用视差背景创建透视效果

+   创建我们的关卡选择系统

+   隐藏和检索图层

# 引言

游戏中的菜单系统本质上是游戏提供的场景或活动的地图。在游戏中，菜单应该看起来吸引人，并微妙地提示在游戏过程中可以期待什么。菜单应该组织有序，便于玩家理解。在本章中，我们将看看我们可以应用到自己游戏中的各种选项，以创建适用于任何类型游戏的实用且吸引人的菜单。

# 向菜单添加按钮

在 AndEngine 中，我们可以使用任何`Entity`对象或`Entity`对象子类型创建触摸响应的按钮。然而，AndEngine 包含一个名为`ButtonSprite`的类，其纹理表示取决于`Entity`对象是被按下还是未被按下。在本教程中，我们将利用 AndEngine 的`ButtonSprite`类并覆盖其`onAreaTouched()`方法，以便向我们的菜单和/或游戏的`Scene`对象添加触摸响应按钮。此外，本教程关于触摸事件的代码可以应用于游戏中的任何其他`Entity`对象。

## 准备就绪…

本教程需要你对 AndEngine 中的`Sprite`对象有基本的了解。请通读第一章中的*使用不同类型的纹理*教程，特别是关于图块纹理区域的部分。接下来，访问第二章中的*通过精灵使场景生动*教程，*使用实体*。

一旦涵盖了关于纹理和精灵的教程，请创建一个带有空的`BaseGameActivity`类的新的 AndEngine 项目。最后，我们需要创建一个名为`button_tiles.png`的精灵表，其中包含两个图像，并将其放置在项目中的`assets/gfx/`文件夹中；一个用于“未按下”按钮的表示，另一个用于“按下”按钮的表示。请参考以下图片以了解图像应有的样子。以下图片是 300 x 50 像素，或者每个图块 150 x 50 像素：

![准备就绪…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_03_01.jpg)

请参考代码捆绑包中名为`CreatingButtons`的类，并将代码导入到你的项目中。

## 如何操作…

`ButtonSprite`类非常方便，因为它为我们处理了图块纹理区域与按钮状态变化之间的关系。以下步骤概述了设置`ButtonSprite`对象所需执行的任务：

1.  声明一个全局的`ITiledTextureRegion`对象，命名为`mButtonTextureRegion`，然后在`BaseGameActivity`类的`onCreateResources()`方法中，创建一个新的适用于您的`button_tiles.png`图像的`BuildableBitmapTextureAtlas`对象。构建并加载纹理区域和纹理图集对象，以便我们稍后可以使用它们来创建`ButtonSprite`对象。

1.  为了使`ButtonSprite`对象按预期工作，我们应在`mScene`对象上设置适当的触摸区域绑定。将以下代码复制到活动的`onCreateScene()`方法中：

    ```kt
    mScene.setTouchAreaBindingOnActionDownEnabled(true);
    ```

1.  创建`ButtonSprite`对象，为其提供`mButtonTextureRegion`对象并重写其`onAreaTouched()`方法：

    ```kt
    /* Create the buttonSprite object in the center of the Scene */
    ButtonSprite buttonSprite = new ButtonSprite(WIDTH * 0.5f,
        HEIGHT * 0.5f, mButtonTextureRegion,
        mEngine.getVertexBufferObjectManager()) {
      /* Override the onAreaTouched() event method */
      @Override
      public boolean onAreaTouched(TouchEvent pSceneTouchEvent,
          float pTouchAreaLocalX, float pTouchAreaLocalY) {
        /* If buttonSprite is touched with the finger */
        if(pSceneTouchEvent.isActionDown()){
          /* When the button is pressed, we can create an event 
           * In this case, we're simply displaying a quick toast */
          CreatingButtons.this.runOnUiThread(new Runnable(){
            @Override
            public void run() {
              Toast.makeText(getApplicationContext(), "Button Pressed!", Toast.LENGTH_SHORT).show();
            }
          });
        }
        /* In order to allow the ButtonSprite to swap tiled texture region 
         * index on our buttonSprite object, we must return the super method */
        return super.onAreaTouched(pSceneTouchEvent, pTouchAreaLocalX, pTouchAreaLocalY);
      }
    };
    ```

1.  最后一步是注册触摸区域并将`buttonSprite`对象附加到`mScene`对象：

    ```kt
    /* Register the buttonSprite as a 'touchable' Entity */
    mScene.registerTouchArea(buttonSprite);
    /* Attach the buttonSprite to the Scene */
    mScene.attachChild(buttonSprite);
    ```

## 它的工作原理是…

本食谱使用了`ButtonSprite`对象与`ITiledTextureRegion`对象来展示两个独立的按钮状态。其中一个图块将作为按钮未被按下时的纹理，另一个则作为当手指触摸显示上的`Entity`对象时按钮被按下的纹理。

在第一步中，我们创建纹理资源以应用于`ButtonSprite`对象，这将在接下来的步骤中实现。`ButtonSprite`类需要一个具有两个索引的`ITiledTextureRegion`对象，或者在本文档的*入门...* 部分所示的图中可以看到两个图块。`ITiledTextureRegion`对象的第一索引应包含按钮未被按下的表示，这将默认应用于`ButtonSprite`对象。第二个`ITiledTextureRegion`索引应表示`ButtonSprite`对象的按下状态。`ButtonSprite`类会根据`ButtonSprite`对象当前处于的状态自动在这两个`ITiledTextureRegion`索引之间切换；分别是`ButtonSprite.State.NORMAL`表示未被按下，将`ButtonSprite`对象的当前图块索引设置为`0`，以及`ButtonSprite.State.PRESSED`，是的，你猜对了，表示按下状态，将`ButtonSprite`对象的当前图块索引设置为`1`。

在第二步中，为了让`ButtonSprite`对象按预期工作，我们需要在`mScene`对象内对按下动作启用触摸区域绑定。我们在活动生命周期的`onCreateScene()`方法中启用此功能，在创建`mScene`对象之后立即进行。这样做可以允许我们的`ButtonSprite`对象在我们将手指拖离`ButtonSprite`触摸区域时注册为未按下状态。如果忽略这一步，那么当我们将手指按在`Entity`对象的触摸区域并拖离时，`ButtonSprite`对象将保持按下状态，这对于玩家来说可能会被认为是“有缺陷”的。在第三步中，我们创建`ButtonSprite`对象，并将其置于场景中心。理想情况下，我们可以创建`ButtonSprite`对象并将其放置在场景上，它应该就能正常工作。然而，`ButtonSprite`毕竟是一个按钮，因此当它被按下时应该触发一个事件。我们可以通过重写`onAreaTouched()`超方法并根据`ButtonSprite`对象的触摸区域是否被按下、手指是否在其上拖动或者手指是否从显示区域内释放来创建事件。在本教程中，我们仅在`ButtonSprite`对象的`pSceneTouchEvent`注册了`isActionDown()`方法时显示一个`Toast`消息。在游戏开发的真实场景中，这个按钮同样可以允许/禁止声音静音、开始新游戏，或者我们为其选择的任何其他动作。用于触摸事件状态检查的其他两个方法是`pSceneTouchEvent.isActionMove()`和`pSceneTouchEvent.isActionUp()`。

最后，一旦创建了`buttonSprite`对象，我们将需要注册触摸区域并将`Entity`对象附加到`mScene`对象上。此时，我们应该清楚，为了在场景上显示一个实体，我们首先必须将其附加。同样，为了让`buttonSprite`对象的`onAreaTouched()`超方法能够执行，我们必须记得调用`mScene.registerTouchArea(buttonSprite)`。对于任何我们希望提供触摸事件的其它`Entity`对象也是如此。

## 另请参阅

+   在第一章中了解*使用不同类型的纹理*，*AndEngine 游戏结构*。

+   在第二章中了解*AndEngine 实体*，*使用实体*。

+   在第二章中了解如何通过精灵使场景生动，*使用实体*。

# 向菜单中添加音乐

在本主题中，我们将创建一个静音按钮，用于控制菜单主题音乐。按下静音按钮将导致音乐如果当前暂停则播放，如果当前播放则暂停。这种静音音乐和声音的方法也可以应用于游戏内的选项和其他允许声音和音乐播放的游戏区域。与之前的教程不同，我们将使用一个`TiledSprite`对象，它允许我们根据声音是否播放或暂停来设置`Sprite`对象的图块索引。请记住，这个教程不仅适用于启用和禁用菜单音乐。我们还可以在游戏过程中遵循同样的方法处理许多其他可切换的选项和状态。

## 准备工作…

本教程要求你对 AndEngine 中的`Sprite`对象以及使用触摸事件执行操作有基本了解。此外，由于我们将在本教程中整合`Music`对象，我们应当了解如何将`Sound`和`Music`对象加载到游戏资源中。请阅读整个教程，第一章中的*处理不同类型的纹理*，特别是关于图块纹理区域的部分。接下来，查看第一章中的*AndEngine 游戏结构*中的引入声音和音乐教程。最后，我们将处理精灵，因此我们应当快速浏览第二章中的*使用精灵为场景注入生命*教程。

在覆盖了纹理、声音和精灵的相关主题后，创建一个带有空的`BaseGameActivity`类的新的 AndEngine 项目。我们需要创建一个名为`sound_button_tiles.png`的精灵表，其中包含两个图像，并将其放置在项目的`assets/gfx/`文件夹中；一个用于“非静音”按钮表示，另一个用于“静音”按钮表示。以下是一个图像的示例，以了解图像应该是什么样子。以下图像是 100 x 50 像素，或者每个图块 50 x 50 像素：

![准备就绪…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_02.jpg)

我们还需要在项目的`assets/sfx/`文件夹中包含一个 MP3 格式的声音文件。声音文件可以是为你执行此教程目的而选择的任何喜欢的音乐曲目。

请参考代码包中名为`MenuMusic`的类，并将代码导入到你的项目中。

## 如何操作…

本教程介绍了一系列 AndEngine 功能的组合。我们将音乐、纹理、精灵、图块纹理区域和触摸事件整合到一个便捷的小包中。结果是一个切换按钮，可以控制`Music`对象的播放。按照以下步骤，看看我们是如何创建这个切换按钮的。

1.  在第一步中，我们将使用两个全局对象；`mMenuMusic`是一个`Music`对象，`mButtonTextureRegion`是一个`ITiledTextureRegion`对象。在活动的`onCreateResources()`方法中，我们使用`assets/*`文件夹中的相应资源创建这些对象。如果需要，请参考*入门…*部分提到的教程，了解更多关于创建这些资源的信息。

1.  接下来，我们可以直接跳转到活动的`onPopulateScene()`方法，在这里我们将使用`TiledSprite`类创建`mMuteButton`对象。我们需要重写`mMuteButton`对象的`onAreaTouched()`方法，以便在按下按钮时暂停或播放音乐：

    ```kt
    /* Create the music mute/unmute button */
    TiledSprite mMuteButton = new TiledSprite(buttonX, buttonY,
        mButtonTextureRegion, mEngine.getVertexBufferObjectManager()) {

      /* Override the onAreaTouched() method allowing us to define custom
      * actions */
      @Override
      public boolean onAreaTouched(TouchEvent pSceneTouchEvent,
          float pTouchAreaLocalX, float pTouchAreaLocalY) {
        /* In the event the mute button is pressed down on... */
        if (pSceneTouchEvent.isActionDown()) {
          if (mMenuMusic.isPlaying()) {
            /*  If music is playing, pause it and set tile index to  MUTE  */
            this.setCurrentTileIndex(MUTE);
            mMenuMusic.pause();
          } else {
            /* If music is paused, play it and set tile index to UNMUTE */
            this.setCurrentTileIndex(UNMUTE);
            mMenuMusic.play();
          }
          return true;
        }
        return super.onAreaTouched(pSceneTouchEvent, pTouchAreaLocalX,
            pTouchAreaLocalY);
      }
    };
    ```

1.  创建按钮后，我们需要初始化`mMuteButton`和`mMenuMusic`对象的初始状态。这一步包括将`mMuteButton`对象的图块索引设置为`UNMUTE`常量值，该值等于`1`，注册并将`mMuteButton`对象附加到`mScene`对象，设置`mMenuMusic`为循环播放，并最终在`mMenuMusic`对象上调用`play()`方法：

    ```kt
    /* Set the current tile index to unmuted on application startup */
    mMuteButton.setCurrentTileIndex(UNMUTE);

    /* Register and attach the mMuteButton to the Scene */
    mScene.registerTouchArea(mMuteButton);
    mScene.attachChild(mMuteButton);

    /* Set the mMenuMusic object to loop once it reaches the track's end */
    mMenuMusic.setLooping(true);
    /* Play the mMenuMusic object */
    mMenuMusic.play();
    ```

1.  在处理任何`Music`对象时，最后一步是确保在应用最小化时暂停音乐，否则它将在后台继续播放。在本教程中，我们将最小化时暂停`mMenuMusic`对象。然而，如果用户返回应用程序，只有当应用最小化时`mMuteButton`对象的图块索引等于`UNMUTE`常量值，音乐才会播放：

    ```kt
    @Override
    public synchronized void onResumeGame() {
      super.onResumeGame();

      /* If the music and button have been created */
      if (mMenuMusic != null && mMuteButton != null) {
        /* If the mMuteButton is set to unmuted on resume... */
        if(mMuteButton.getCurrentTileIndex() == UNMUTE){
          /* Play the menu music */
          mMenuMusic.play();
        }
      }
    }

    @Override
    public synchronized void onPauseGame() {
      super.onPauseGame();

      /* Always pause the music on pause */
      if(mMenuMusic != null && mMenuMusic.isPlaying()){
        mMenuMusic.pause();
      }
    }
    ```

## 它是如何工作的…

这个特定的教程在游戏开发中非常有用；不仅适用于声音和音乐的静音，还适用于各种切换按钮。虽然本教程专门处理`Music`对象的播放，但它包含了开始使用各种其他切换按钮所需的所有必要代码，这些按钮可能更适合我们游戏的具体需求。

在第一步中，我们必须为`mMenuMusic`对象和`mMuteButton`对象设置必要的资源。`mMenuMusic`对象将加载名为`menu_music.mp3`的音频文件，该文件可以是任何 MP3 文件，最好是音乐轨道。`mMuteButton`对象将加载名为`sound_button_tiles.png`的图块表，其中包含两个单独的图块。这些对象都在`BaseGameActivity`对象生命周期的`onCreateResourceS()`方法中处理。关于这些资源的创建，可以在本教程的*入门…*部分提到的教程中找到更多信息。

在第二步中，我们设置了`mMuteButton`对象，该对象属于`TiledSprite`类型。`TiledSprite`类允许我们使用`ITiledTextureRegion`对象，这使得我们可以设置`mMuteButton`对象将在场景中显示的当前图块索引。在重写的`onAreaTouched()`方法中，我们通过`if (pSceneTouchEvent.isActionDown())`语句检查`mMuteButton`对象是否被按下。然后，我们通过`Music`对象的`isPlaying()`方法继续判断`mMenuMusic`对象是否正在播放。如果音乐正在播放，那么在`mMuteButton`按钮上按下手指将导致`mMenuMusic`对象调用`pause()`方法，并将`mMuteButton`对象的当前图块索引恢复为`MUTE`常量值，即`0`。如果音乐没有播放，那么我们执行相反操作，在`mMenuMusic`对象上调用`play()`方法，并将`mMuteButton`对象的图块索引恢复为`UNMUTE`，即`1`。

在第三步中，我们设置了`mMenuMusic`和`mMuteButton`对象的默认状态，即播放音乐并将当前图块索引设置为`UNMUTE`。这将导致应用程序每次启动时播放音乐。设置好默认按钮和音乐状态后，我们继续注册`mMuteButton`对象的触摸区域，并将`Entity`对象附加到`Scene`对象。这一步可以进一步操作，以保存`mMuteButton`对象的状态到设备，从而根据用户过去的偏好加载音乐静音的默认状态。有关保存/加载数据和状态的信息，请参阅第一章中的*保存和加载游戏数据*菜谱，*AndEngine 游戏结构*。

最后一步非常重要，处理`Music`对象时应该始终包含这一步。这一步的目的是在第一章中的*引入声音和音乐*菜谱中详细解释的。但是，这个菜谱在`onResumeGame()`方法中的代码有一个小变化。在应用程序最小化的情况下，用户可能期望他们的游戏状态在等待，就像他们最后将其焦点返回时一样。因此，在应用程序最大化时触发`onResumeGame()`时，我们不是播放`mMenuMusic`对象，而是判断在游戏窗口最小化之前`mMuteButton`按钮的图块索引是否设置为`UNMUTE`。如果是这样，那么我们可以对`mMenuMusic`对象调用`play()`方法，否则我们可以忽略它，直到用户决定再次按下`mMuteButton`播放音乐。

## 另请参阅

+   第一章中的*处理不同类型的纹理*，*AndEngine 游戏结构*。

+   在第一章，*AndEngine 游戏结构*中，引入声音和音乐。

+   在第二章，*使用实体*中，了解 AndEngine 实体。

+   在第二章，*使用实体*中，介绍如何通过精灵使场景生动起来。

# 应用背景

AndEngine 的`Scene`对象允许我们为其应用静态背景。背景可以用来显示纯色、实体、精灵或重复精灵，这些都不会受到`Camera`对象位置或缩放因子变化的影响。在本食谱中，我们将看看如何将不同类型的背景应用到我们的`Scene`对象上。

## 如何操作…

在 AndEngine 中，`Background`对象是我们`Scene`对象最基本的背景类型。这个对象允许场景以纯色视觉展示。我们首先会设置`Scene`对象以显示`Background`对象，以便熟悉如何将背景应用到场景中。在本食谱的后面，我们将介绍大部分剩余的`Background`对象子类型，以涵盖所有关于将背景应用到场景的选项。为`Scene`对象设置背景只需以下两个步骤：

1.  定义并创建`Background`对象的属性：

    ```kt
    /* Define background color values */
    final float red = 0;
    final float green = 1;
    final float blue = 1;
    final float alpha = 1;

    /* Create a new background with the specified color values */
    Background background = new Background(red, green, blue, alpha);
    ```

1.  将`Background`对象设置到`Scene`对象上，并启用背景功能：

    ```kt
    /* Set the mScene object's background */
    mScene.setBackground(background);

    /* Set the background to be enabled */
    mScene.setBackgroundEnabled(true);
    ```

## 工作原理…

在决定使用 AndEngine 的默认背景之前，我们必须确定背景是否需要考虑相机移动。我们可以将这些背景视为“粘附”在相机视图中。这意味着对相机所做的任何移动都不会影响背景的位置。对于任何其他形式的相机重新定位，包括缩放，也同样适用。因此，我们不应该在背景上包含任何需要随相机移动而滚动的对象。这是应用到`Scene`对象的`Background`对象与附加到`Scene`对象的`Entity`对象之间的区别。任何应该随相机移动而看似移动的“背景”，都应该作为`Entity`对象附加到`Scene`对象上，以作为“背景层”，所有表示背景图像的精灵都将附着在上面。

现在我们已经了解了`Background`对象与`Entity`对象之间的区别，接下来将继续介绍本食谱的步骤。从本食谱的步骤中我们可以看到，设置一个枯燥、老旧的有色背景是一项简单的任务。然而，了解它仍然是有用的。在第一步中，我们将定义`Background`对象的属性，并创建一个`Background`对象，将所述属性作为参数传入。对于基本的`Background`对象，这些参数仅包括三个颜色值以及`Background`对象颜色的 alpha 值。但是，正如我们稍后将讨论的，不同类型的背景将根据类型需要不同的参数。当我们讨论到这一点时，为了方便起见，将会概述这些差异。

在`Scene`对象上设置`Background`对象的第二步将始终是相同的两个方法调用，无论我们应用的是哪种类型的背景。我们必须通过`setBackground(pBackground)`设置场景的背景，并通过调用`setBackgroundEnabled(true)`确保场景的背景已启用。另一方面，我们也可以通过向后者方法提供一个`false`参数来禁用背景。

这就是在我们的`Scene`对象上设置背景的全部内容。然而，在我们自己的游戏中，我们很可能会对基本的有色背景感到不满意。请参阅本食谱的*还有更多...*部分，了解各种`Background`对象子类型的列表和示例。

## 还有更多...

在以下各节中，我们将介绍我们可以在游戏中使用的不同类型的静态背景。所有的`Background`对象子类型都允许我们为未被`Sprite`实体、`Rectangle`实体或其他方式覆盖的背景部分指定背景颜色。这些背景都遵循在*工作原理...*部分提到的相同"静态"规则，即它们在摄像头移动时不会移动。

### EntityBackground 类

`EntityBackground`类允许我们应用单个`Entity`对象，或整个`Entity`对象的图层作为我们场景的背景。这可以用于将多个`Entity`对象组合到一个`Background`对象中，以便在场景上显示。在以下代码中，我们将两个矩形附加到`Entity`对象的图层上，然后使用`Entity`对象作为背景：

```kt
    /* Create a rectangle in the bottom left corner of the Scene */
    Rectangle rectangleLeft = new Rectangle(100, 100, 200, 200,
        mEngine.getVertexBufferObjectManager());

    /* Create a rectangle in the top right corner of the Scene */
    Rectangle rectangleRight = new Rectangle(WIDTH - 100, HEIGHT - 100, 200, 200,
        mEngine.getVertexBufferObjectManager());
    /* Create the entity to be used as a background */
    Entity backgroundEntity = new Entity();

    /* Attach the rectangles to the entity which will be applied as a background */
    backgroundEntity.attachChild(rectangleLeft);
    backgroundEntity.attachChild(rectangleRight);

    /* Define the background color properties */
    final float red = 0;
    final float green = 0;
    final float blue = 0;

    /* Create the EntityBackground, specifying its background color & entity to represent the background image */
    EntityBackground background = new EntityBackground(red, green, blue, backgroundEntity);

    /* Set & enable the background */
    mScene.setBackground(background);
    mScene.setBackgroundEnabled(true);
```

`EntityBackground`对象的参数包括`red`、`green`和`blue`颜色值，最后是作为背景显示的`Entity`对象或图层。一旦创建了`EntityBackground`对象，我们只需按照本食谱中*如何操作...*部分的第二步进行操作，我们的`EntityBackground`对象将准备好显示我们选择附加到`backgroundEntity`对象上的任何内容！

### SpriteBackground 类

`SpriteBackground`类允许我们将单个`Sprite`对象作为背景图像附加到场景中。请注意，为了适应显示的大小，这个精灵不会被拉伸或扭曲。为了使精灵在相机的视野中横跨整个宽度和高度，我们必须在考虑相机宽度和高度的情况下创建`Sprite`对象。使用以下代码，我们可以将单个`Sprite`对象作为场景的背景图像。假设`mBackgroundTextureRegion`对象的尺寸与以下代码中的`WIDTH`和`HEIGHT`值相同，这些值表示相机的宽度和高度值：

```kt
/* Create the Sprite object */
Sprite sprite = new Sprite(WIDTH * 0.5f, HEIGHT * 0.5f, mBackgroundTextureRegion,
    mEngine.getVertexBufferObjectManager());

/* Define the background color values */
final float red = 0;
final float green = 0;
final float blue = 0;

/* Create the SpriteBackground object, specifying 
 * the color values & Sprite object to display*/
SpriteBackground background = new SpriteBackground(red, green, blue, sprite);

/* Set & Enable the background */
mScene.setBackground(background);
mScene.setBackgroundEnabled(true);
```

我们可以像创建其他对象一样创建`Sprite`对象。在创建`SpriteBackground`对象时，我们传递常规颜色参数以及我们希望在背景上显示的`Sprite`对象。

### 注意

当使用`SpriteBackground`和`RepeatingSpriteBackground`时，将`BitmapTextureFormat.RGB_565`应用到纹理图集上是一个好主意。由于背景可能会横跨整个显示，我们通常不需要 alpha 通道，这可以提高在低端设备上游戏的性能。

### RepeatingSpriteBackground 类

`RepeatingSpriteBackground`类非常适合创建地形纹理图或仅仅用纹理填充场景中的空白空间。我们可以轻松地将以下 128 x 128 像素的纹理转换成背景，使其在整个显示长度上重复纹理：

![RepeatingSpriteBackground 类](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_03_03.jpg)

使用前面纹理创建`RepeatingSpriteBackground`对象后，得到的背景图像尺寸为 1280 x 752 像素，如下所示：

![RepeatingSpriteBackground 类](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_03_03b.jpg)

创建`RepeatingSpriteBackground`对象需要比之前的`Background`对象子类型多做一点工作。我们将重复的图像文件加载到`AssetBitmapTexture`对象中，然后将其提取为`ITextureRegion`对象供背景使用。由于我们要将纹理用于在`RepeatingSpriteBackground`中重复，我们必须在`AssetBitmapTexture`构造函数中提供`TextureOptions.REPEATING_BILINEAR`或`TextureOptions.REPEATING_NEAREST`纹理选项。此外，在处理重复纹理时，我们的图像文件尺寸必须保持为 2 的幂次方。OpenGL 的环绕模式要求纹理尺寸为 2 的幂次方，以正确地重复纹理。不遵循此规则将导致重复的精灵显示为黑色形状。将以下代码放入测试活动的`onCreateResources()`方法中。`mRepeatingTextureRegion`对象必须声明为全局`ITextureRegion`对象：

```kt
AssetBitmapTexture mBitmapTexture = null;

try {
  /* Create the AssetBitmapTexture with the REPEATING_* texture option */
  mBitmapTexture = new AssetBitmapTexture(mEngine.getTextureManager(), this.getAssets(), "gfx/grass.png", BitmapTextureFormat.RGB_565,TextureOptions.REPEATING_BILINEAR);
} catch (IOException e) {
  e.printStackTrace();
}
/* Load the bitmap texture */
mBitmapTexture.load();

/* Extract the bitmap texture into an ITextureRegion */
mRepeatingTextureRegion = TextureRegionFactory.extractFromTexture(mBitmapTexture);
```

下一步是创建`RepeatingSpriteBackground`对象。我们将此代码包含在我们的活动生命周期的`onCreateScene()`方法中：

```kt

/* Define the RepeatingSpriteBackground sizing parameters */
final float cameraWidth = WIDTH;
final float cameraHeight = HEIGHT;
final float repeatingScale = 1f;

/* Create the RepeatingSpriteBackground */
RepeatingSpriteBackground background = new RepeatingSpriteBackground(cameraWidth, cameraHeight, mRepeatingTextureRegion, repeatingScale,
    mEngine.getVertexBufferObjectManager());

/* Set & Enable the background */
mScene.setBackground(background);
mScene.setBackgroundEnabled(true);
```

`RepeatingSpriteBackground`对象的前两个参数定义了重复纹理将覆盖的最大区域，从显示的左下角开始。在本例中，我们覆盖了整个显示区域。我们传递的第三个纹理是作为重复纹理使用的`ITextureRegion`对象。如前所述，这个纹理区域必须遵循二的幂次维度规则。第四个参数是重复纹理的缩放因子。默认缩放为`1`；增加缩放会使重复纹理放大，这可能使重复模式更容易看到。减少缩放因子会缩小每个重复的纹理，有时可以帮助隐藏重复纹理中的明显瑕疵。请记住，调整重复纹理的缩放不会影响根据前两个参数定义的`RepeatingSpriteBackground`对象的整体大小，因此可以自由调整，直到纹理看起来正确为止。

## 参见以下内容

+   在第一章，*AndEngine 游戏结构*中，*使用不同类型的纹理*。

+   在第二章，*使用实体*中，*用精灵让场景生动起来*。

# 使用视差背景创建透视效果

将**视差**背景应用于游戏可以产生视觉上令人愉悦的透视效果。尽管我们使用的是 2D 引擎，但我们可以创建一个通过使用视差值来产生深度错觉的背景，这些视差值根据相机移动确定精灵的运动速度。本主题将介绍视差背景以及如何使用它们为完全 2D 的世界添加深度感。我们将使用的类是`ParallaxBackground`和`AutoParallaxBackground`。

## 准备就绪…

此食谱需要具备 AndEngine 中`Sprite`对象的基本知识。请通读第一章，*AndEngine 游戏结构*中的整个食谱，*使用不同类型的纹理*。接下来，请访问第二章，*使用实体*中的食谱，*用精灵让场景生动起来*。

在介绍了纹理和精灵的相关方法之后，创建一个带有空的`BaseGameActivity`类的新的 AndEngine 项目。最后，我们需要在项目的`assets/gfx/`文件夹中创建一个名为`hill.png`的图像。这个图像的尺寸应为 800 x 150 像素。图像可以类似于以下图形：

![准备就绪…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_04.jpg)

请参考代码包中名为`UsingParallaxBackgrounds`的类，并将代码导入到您的项目中。

## 如何操作…

`ParallaxBackground`对象是 AndEngine 中最先进的`Background`对象子类型。它需要比所有`Background`对象子类型更多的设置，但如果分解成小步骤，实际上并不那么困难。执行以下步骤，了解如何设置一个与相机移动相关的`ParallaxBackground`对象。为了简洁起见，我们将省略可以在活动生命周期的`onCreateEngineOptions()`方法中找到的自动相机移动代码：

1.  创建`Sprite`对象的`ITextureRegion`对象的第一个步骤通常是创建我们的`BuildableBitmapTextureAtlas`。纹理图集应足够大以容纳`hill.png`图像，其宽度为 800 像素，高度为 150 像素。创建纹理图集后，继续创建`ITextureRegion`对象，然后像往常一样构建和加载纹理图集。这应该都在活动生命周期的`onCreateResources()`方法内完成。

1.  剩余的步骤将在活动生命周期的`onCreateScene()`方法内进行。首先，我们需要创建所有将出现在背景上的`Sprite`对象。在此教程中，我们将应用三个`Sprite`对象，以便方便地放置在背景上，以增强不同精灵之间的距离错觉：

    ```kt
    final float textureHeight = mHillTextureRegion.getHeight();

    /* Create the hill which will appear to be the furthest
    * into the distance. This Sprite will be placed higher than the 
     * rest in order to retain visibility of it */
    Sprite hillFurthest = new Sprite(WIDTH * 0.5f, textureHeight * 0.5f + 50, mHillTextureRegion,
        mEngine.getVertexBufferObjectManager());

    /* Create the hill which will appear between the furthest and closest
     * hills. This Sprite will be placed higher than the closest hill, but
    * lower than the furthest hill in order to retain visibility */
    Sprite hillMid = new Sprite(WIDTH * 0.5f, textureHeight * 0.5f + 25, mHillTextureRegion,
        mEngine.getVertexBufferObjectManager());

    /* Create the closest hill which will not be obstructed by any other hill 
    * Sprites. This Sprite will be placed at the bottom of the Scene since
    * nothing will be covering its view */
    Sprite hillClosest = new Sprite(WIDTH * 0.5f, textureHeight * 0.5f, mHillTextureRegion,
        mEngine.getVertexBufferObjectManager());
    ```

1.  接下来，我们将创建`ParallaxBackground`对象。构造函数的三个参数通常定义背景颜色。更重要的是，我们必须重写`ParallaxBackground`对象的`onUpdate()`方法，以处理在背景上等待任何相机移动时`Sprite`对象移动：

    ```kt
    /* Create the ParallaxBackground, setting the color values to represent 
    * a blue sky */
    ParallaxBackground background = new ParallaxBackground(0.3f, 0.3f, 0.9f) {

      /* We'll use these values to calculate the parallax value of the background */
      float cameraPreviousX = 0;
      float parallaxValueOffset = 0;

      /* onUpdates to the background, we need to calculate new 
       * parallax values in order to apply movement to the background
      * objects (the hills in this case) */
      @Override
      public void onUpdate(float pSecondsElapsed) {
        /* Obtain the camera's current center X value */
        final float cameraCurrentX = mCamera.getCenterX();

        /* If the camera's position has changed since last 
         * update... */
        if (cameraPreviousX != cameraCurrentX) {

          /* Calculate the new parallax value offset by 
           * subtracting the previous update's camera x coordinate
           * from the current update's camera x coordinate */
          parallaxValueOffset +=  cameraCurrentX - cameraPreviousX;

          /* Apply the parallax value offset to the background, which 
           * will in-turn offset the positions of entities attached
           * to the background */
          this.setParallaxValue(parallaxValueOffset);

          /* Update the previous camera X since we're finished with this 
           * update */
          cameraPreviousX = cameraCurrentX;
        }
        super.onUpdate(pSecondsElapsed);
      }
    };
    ```

1.  创建`ParallaxBackground`对象后，我们现在必须将`ParallaxEntity`对象附加到`ParallaxBackground`对象上。`ParallaxEntity`对象要求我们为实体定义一个视差因子以及一个用于视觉表示的`Sprite`对象，在这种情况下将是山丘：

    ```kt
    background.attachParallaxEntity(new ParallaxEntity(5, hillFurthest));
    background.attachParallaxEntity(new ParallaxEntity(10, hillMid));
    background.attachParallaxEntity(new ParallaxEntity(15, hillClosest));
    ```

1.  最后，像所有`Background`对象一样，我们必须将其应用到`Scene`对象并启用它：

    ```kt
    /* Set & Enabled the background */
    mScene.setBackground(background);
    mScene.setBackgroundEnabled(true);
    ```

## 它是如何工作的…

在此教程中，我们将设置一个`ParallaxBackground`对象，其中包含三个独立的`ParallaxEntity`对象。这三个`ParallaxEntity`对象将代表我们场景背景中的山丘。通过使用视差因子和视差值，`ParallaxBackground`对象允许每个`ParallaxEntity`对象在`Camera`对象改变其位置时以不同的速度偏移它们的位置。这使得`ParallaxEntity`对象能够产生透视效果。众所周知，离我们更近的物体会比远处的物体看起来移动得更快。

在“*如何操作...*”部分的第一步是创建我们的`Sprite`对象的基本且必要的任务。在这个食谱中，我们使用一个单一的纹理区域/图像来表示所有三个将附加到背景的精灵。然而，请随意修改这个食谱，以便让三个`Sprite`对象中的每一个都能使用自己的定制图像。实践将有助于进一步理解如何操作`ParallaxBackground`对象，在游戏中创建整洁的场景。

在第二步中，我们设置三个将作为`ParallaxEntity`对象附加到背景的`Sprite`对象。我们将它们都放置在场景中心的 x 坐标处。`ParallaxBackground`类仅用于将透视应用于 x 坐标移动，因此，随着摄像机的移动，背景上的精灵位置将离开初始 x 坐标。也就是说，重要的是要知道`ParallaxBackground`对象将不断地将附加到背景的每个`ParallaxEntity`对象的副本拼接在一起，以补偿可能离开摄像机视野的背景对象。以下是`ParallaxBackground`对象如何将背景对象端对端拼接的可视化表示：

![工作原理](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_05.jpg)

由于`ParallaxEntity`对象在`ParallaxBackground`对象上的拼接方式，为了创建可能不会在背景上经常出现的对象，我们必须在图像文件本身中包含透明填充。

至于定义精灵的 y 坐标，最好是将精灵分散开，以便能够区分背景上最近和最远的山丘。为了创建最佳的透视效果，最远的物体在场景中应该显得更高，因为从层次上讲，它们将隐藏在更近的对象后面。

在第三步中，我们创建`ParallaxBackground`对象。构造函数与所有其他`Background`对象子类型一样，定义了背景颜色。真正的魔法发生在`ParallaxBackground`对象的覆盖`onUpdate()`方法中。我们有两个变量；`cameraPreviousX`和`cameraCurrentX`，它们将首先被测试以确保两者之间存在差异，以减少任何不必要的代码执行。如果这两个值不相等，我们将累积先前和当前摄像机位置之间的差异到一个`parallaxValueOffset`变量中。通过在`ParallaxBackground`对象上调用`setParallaxValue(parallaxValueOffset)`，我们基本上只是告诉背景摄像机已经改变了位置，现在是更新所有`ParallaxEntity`对象位置以进行补偿的时候了。增加视差值将导致`ParallaxEntity`对象向左平移，而减少它则导致它们向右平移。

在第四步中，我们最终创建`ParallaxEntity`对象，为每个对象提供一个视差因子和一个`Sprite`对象。视差因子将定义`Sprite`对象基于摄像头移动的速度是快还是慢。为了创建更逼真的风景，距离较远的对象应该具有比近处对象更小的值。此外，`attachParallaxEntity(pParallaxEntity)`方法类似于将`Entity`对象附加到`Scene`对象，因为第二个附加的对象将出现在第一个前面，第三个将出现在第二个前面，依此类推。因此，我们从最远的对象开始将`ParallaxEntity`对象附加到`ParallaxBackground`，然后逐步靠近最近的物体。

完成所有前面的步骤后，我们可以简单地将`ParallaxBackground`应用到`Scene`对象并启用它。从现在开始，任何摄像头的移动都将决定背景景物中对象的位置！

## 还有更多…

AndEngine 还包括一个`AutoParallaxBackground`类，它和`ParallaxBackground`类在设置视觉效果方面类似。两者的区别在于，`AutoParallaxBackground`类允许我们指定一个恒定速率，在该速率下，无论摄像头是否移动，`ParallaxEntity`对象都会在屏幕上移动。这种类型的背景对于需要看起来不断移动的游戏很有用，比如赛车游戏或任何快节奏的横版滚动游戏。另一方面，`AutoParallaxBackground`类也可以用于在游戏过程中创建简单的效果，例如云层在屏幕上持续滚动，即使是在`Camera`和`Scene`对象位置看似静态的游戏中也是如此。

我们可以通过对这一食谱活动的简单调整来创建一个`AutoParallaxBackground`对象。用以下代码片段替换当前的`ParallaxBackground`对象创建。注意，`autoParallaxSpeed`变量定义了`ParallaxEntity`对象在背景上的移动速度，因为它们不再基于摄像头的移动：

```kt
/* Define the speed that the parallax entities will move at.
 * 
* Set to a negative value for movement in the opposite direction */
final float autoParallaxSpeed = 3;

/* Create an AutoParallaxBackground */
AutoParallaxBackground background = new AutoParallaxBackground(0.3f, 0.3f, 0.9f, autoParallaxSpeed);
```

此外，移除所有与`mCamera`对象的`onUpdate()`方法相关的代码，因为它将不再影响`ParallaxEntity`对象的位置。

下图展示了将三个不同高度的丘陵层附加到`ParallaxBackground`或`AutoParallaxBackground`对象的结果，当然，这里没有考虑移动：

![还有更多…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_06.jpg)

## 另请参阅

+   在第一章《AndEngine 游戏结构》中*处理不同类型的纹理*。

+   在第二章《使用实体》中*用精灵为场景赋予生命*。

+   本章节提供的*应用背景*。

# 创建我们的关卡选择系统

如果你曾经玩过带有多个关卡的移动游戏，那么你可能已经知道我们将在本章中处理什么。我们将创建一个类，为游戏提供一个包含关卡瓦片的网格，以便用户可以选择一个关卡进行游戏。这个类非常易于管理，并且高度可定制，从按钮纹理、列数、行数等，都可以轻松设置。最终结果将如下所示：

![创建我们的关卡选择系统](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/978-1-849518-98-7_03_04a.jpg)

### 注意

`LevelSelector`类的这个实现扩展了 AndEngine 的`Entity`对象。这使得应用实体修改器和基于触摸事件的滚动变得相当简单。

## 准备就绪…

`LevelSelector`类高度依赖于 AndEngine 的`Entity`、`Sprite`和`Text`对象的使用。为了理解`LevelSelector`是如何工作的，请花时间阅读关于这些对象的相关内容。这些内容包括第二章中的*理解 AndEngine 实体*，*使用实体*，*用精灵使场景生动*，以及*将文本应用到图层*。

`LevelSelector`对象需要一个带有图像文件引用的`ITextureRegion`对象。可以自由创建一个表示 50x50 像素尺寸的方形按钮的图像，如本食谱介绍中的图所示。虽然这个`ITextureRegion`对象在`LevelSelector`类内部并不需要，但在本食谱末尾在空的`BaseGameActivity`测试项目中测试`LevelSelector`类时需要它。

请参考代码包中名为`LevelSelector`的类，以获取此食谱的工作代码。请随意使用这个类，并根据你的游戏需求进行修改！

## 如何操作…

尽管其规模可能相当大，但`LevelSelector`类实际上非常易于使用。在这个食谱中，我们将介绍两个类；第一个是处理关卡瓦片（或按钮）如何在场景上形成网格的`LevelSelector`类。第二个是`LevelSelector`的内部类，称为`LevelTile`。`LevelTile`类允许我们轻松添加或删除可能对游戏有用的额外数据。为了保持简单，我们将分别讨论这两个类，从`LevelSelector`类开始。

以下步骤解释了`LevelSelector`类如何以网格格式在场景上排列`LevelTile`对象：

1.  创建`LevelSelector`构造函数，初始化所有变量。这个构造函数很直接，直到我们必须通过`mInitialX`和`mInitialY`变量指定第一个`LevelTile`对象的位置：

    ```kt
    final float halfLevelSelectorWidth = ((TILE_DIMENSION * COLUMNS) + TILE_PADDING
        * (COLUMNS - 1)) * 0.5f;
    this.mInitialX = (this.mCameraWidth * 0.5f) - halfLevelSelectorWidth;

    /* Same math as above applies to the Y coordinate */
    final float halfLevelSelectorHeight = ((TILE_DIMENSION * ROWS) + TILE_PADDING
        * (ROWS - 1)) * 0.5f;
    this.mInitialY = (this.mCameraHeight * 0.5f) + halfLevelSelectorHeight;
    ```

1.  接下来，我们必须创建一个方法，用于构建`LevelSelector`对象的瓦片网格。我们正在创建一个名为`createTiles(pTextureRegion, pFont)`的方法，通过循环一定的`ROWS`和`COLUMNS`值，将瓦片放置在预定的坐标中，从而完全自动化创建关卡瓦片网格：

    ```kt
    public void createTiles(final ITextureRegion pTextureRegion,
        final Font pFont) {

      /* Temp coordinates for placing level tiles */
      float tempX = this.mInitialX + TILE_DIMENSION * 0.5f;
      float tempY = this.mInitialY - TILE_DIMENSION * 0.5f;

      /* Current level of the tile to be placed */
      int currentTileLevel = 1;

      /* Loop through the Rows, adjusting tempY coordinate after each
       * iteration */
      for (int i = 0; i < ROWS; i++) {

        /* Loop through the column positions, placing a LevelTile in each
         * column */
        for (int o = 0; o < COLUMNS; o++) {

          final boolean locked;

          /* Determine whether the current tile is locked or not */
          if (currentTileLevel <= mMaxLevel) {
            locked = false;
          } else {
            locked = true;
          }

          /* Create a level tile */
          LevelTile levelTile = new LevelTile(tempX, tempY, locked,
              currentTileLevel, pTextureRegion, pFont);

          /* Attach the level tile's text based on the locked and
          * currentTileLevel variables pass to its constructor */
          levelTile.attachText();

          /* Register & Attach the levelTile object to the LevelSelector */
          mScene.registerTouchArea(levelTile);
          this.attachChild(levelTile);

          /* Increment the tempX coordinate to the next column */
          tempX = tempX + TILE_DIMENSION + TILE_PADDING;

          /* Increment the level tile count */
          currentTileLevel++;
        }

        /* Reposition the tempX coordinate back to the first row (far left) */
        tempX = mInitialX + TILE_DIMENSION * 0.5f;

        /* Reposition the tempY coordinate for the next row to apply tiles */
        tempY = tempY - TILE_DIMENSION - TILE_PADDING;
      }
    }
    ```

1.  `LevelSelector`类的第三步也是最后一步是包含两个方法；一个用于显示`LevelSelector`类的网格，另一个用于隐藏`LevelSelector`类的网格。为了简单起见，我们将这些方法称为`show()`和`hide()`，不带参数：

    ```kt
    /* Display the LevelSelector on the Scene. */
    public void show() {

      /* Register as non-hidden, allowing touch events */
      mHidden = false;

      /* Attach the LevelSelector the the Scene if it currently has no parent */
      if (!this.hasParent()) {
        mScene.attachChild(this);
      }

      /* Set the LevelSelector to visible */
      this.setVisible(true);
    }

    /* Hide the LevelSelector on the Scene. */
    public void hide() {

      /* Register as hidden, disallowing touch events */
      mHidden = true;

      /* Remove the LevelSelector from view */
      this.setVisible(false);
    }
    ```

现在，我们继续讨论`LevelTile`类的步骤。`LevelTile`内部类是 AndEngine 的`Sprite`对象的扩展。我们实现自己的`LevelTile`类的原因是让每个瓦片存储自己的数据，例如瓦片表示的关卡是否锁定，用于显示瓦片关卡编号的`Font`和`Text`对象，瓦片的关卡编号本身等等。这个类可以很容易地被修改以存储更多信息，例如特定关卡的用户的最高分，关卡颜色主题，或者我们想要包含的任何其他内容。以下步骤将引导我们创建`LevelTile`内部类：

1.  创建`LevelTile`构造函数：

    ```kt
    public LevelTile(float pX, float pY, boolean pIsLocked,
        int pLevelNumber, ITextureRegion pTextureRegion, Font pFont) {
      super(pX, pY, LevelSelector.this.TILE_DIMENSION,
        LevelSelector.this.TILE_DIMENSION, pTextureRegion,
        LevelSelector.this.mEngine.getVertexBufferObjectManager());

      /* Initialize the necessary variables for the LevelTile */
      this.mFont = pFont;
      this.mIsLocked = pIsLocked;
      this.mLevelNumber = pLevelNumber;
    }
    ```

1.  为`LevelTile`类创建必要的 getter 方法。对于这样一个基本的`LevelTile`类，我们只需要访问有关瓦片表示的关卡编号的锁定状态以及瓦片表示的关卡编号的数据：

    ```kt
    /* Method used to obtain whether or not this level tile represents a
     * level which is currently locked */
    public boolean isLocked() {
      return this.mIsLocked;
    }

    /* Method used to obtain this specific level tiles level number */
    public int getLevelNumber() {
      return this.mLevelNumber;
    }
    ```

1.  为了在每个`LevelTile`对象上显示关卡编号，我们将创建一个`attachText()`方法，以在创建每个`LevelTile`对象后处理将`Text`对象应用到它们上面：

    ```kt
    public void attachText() {
      String tileTextString = null;

      /* If the tile's text is currently null... */
      if (this.mTileText == null) {
        /* Determine the tile's string based on whether it's locked or
        * not */
        if (this.mIsLocked) {
          tileTextString = "Locked";
        } else {
          tileTextString = String.valueOf(this.mLevelNumber);
        }
        /* Setup the text position to be placed in the center of the tile */
        final float textPositionX = LevelSelector.this.TILE_DIMENSION * 0.5f;
        final float textPositionY = textPositionX;

        /* Create the tile's text in the center of the tile */
        this.mTileText = new Text( textPositionX,
            textPositionY, this.mFont,
            tileTextString, tileTextString.length(),
            LevelSelector.this.mEngine.getVertexBufferObjectManager());

        /* Attach the Text to the LevelTile */
        this.attachChild(mTileText);
      }
    }
    ```

1.  最后但同样重要的是，我们将重写`LevelTile`类的`onAreaTouched()`方法，以便在瓦片被按下时提供一个默认操作。执行的的事件应根据`mIsLocked`布尔值的不同而有所不同：

    ```kt
    @Override
    public boolean onAreaTouched(TouchEvent pSceneTouchEvent,
        float pTouchAreaLocalX, float pTouchAreaLocalY) {
      /* If the LevelSelector is not hidden, proceed to execute the touch
       * event */
      if (!LevelSelector.this.mHidden) {
        /* If a level tile is initially pressed down on */
        if (pSceneTouchEvent.isActionDown()) {
          /* If this level tile is locked... */
          if (this.mIsLocked) {
            /* Tile Locked event... */
        LevelSelector.this.mScene.getBackground().setColor(
            org.andengine.util.adt.color.Color.RED);
          } else {
            /* Tile unlocked event... This event would likely prompt
             * level loading but without getting too complicated we
             * will simply set the Scene's background color to green */
        LevelSelector.this.mScene.getBackground().setColor(
                org.andengine.util.adt.color.Color.GREEN);

            /**
             * Example level loading:
             *     LevelSelector.this.hide();
             * SceneManager.loadLevel(this.mLevelNumber);
             */
          }
          return true;
        }
      }
      return super.onAreaTouched(pSceneTouchEvent, pTouchAreaLocalX,
          pTouchAreaLocalY);
    }
    ```

## 它是如何工作的…

这种`LevelSelector`类的实现允许我们通过在活动中添加少量的代码来创建可选择关卡瓦片的网格。在我们讨论将`LevelSelector`类实现到我们的活动中之前，让我们看看这个类是如何工作的，以便我们了解如何可能修改这个类以更好地满足一系列不同游戏的具体需求。正如*如何做…*部分根据这个食谱中使用的两个类将步骤分为两段一样，我们也将分两个部分解释每个类是如何工作的。我们将再次从`LevelSelector`类开始。

### 解释`LevelSelector`类

首先，`LevelSelector`类包含了许多成员变量，我们需要了解这些变量，才能充分利用这个对象。以下是在此类中使用变量的列表以及每个变量的描述：

+   `COLUMNS`：`LevelSelector`类网格水平轴上显示的`LevelTile`对象数量。

+   `ROWS`：`LevelSelector`类网格垂直轴上显示的`LevelTile`对象数量。

+   `TILE_DIMENSION`：每个单独的`LevelTile`对象的宽度和高度值。

+   `TILE_PADDING`：`LevelSelector`类网格上每个`LevelTile`对象之间的间距（以像素为单位）。

+   `mChapter`：此值定义了`LevelSelector`类的章节值。这个变量可以让我们通过为每个`LevelSelector`对象指定不同的章节值，创建代表游戏内不同章节/世界/区域的一系列`LevelSelector`对象。

+   `mMaxLevel`：此值定义了用户在我们游戏中当前已达到的最高解锁等级。这个变量将会与每个被触碰的`LevelTile`对象的等级数字进行测试。不应该允许用户进入大于此变量的等级。

+   `mCameraWidth`/`mCameraHeight`：这些值仅用于帮助将`LevelSelector`和`LevelTile`对象正确对齐在场景中心。

+   `mInitialX`：此变量用于保存`LevelSelector`类网格每一行的初始 x 坐标的引用。每次网格的一整行布局完成后，下一行的第一个`LevelTile`对象将返回到这个 x 坐标。

+   `mInitialY`：此变量仅用于定义第一个`LevelTile`对象的 y 坐标。由于我们是按照从左到右、从上到下的方式构建`LevelSelector`类的网格，因此在后续的瓷砖放置中，我们无需返回到初始的 y 坐标。

+   `mHidden`：此变量的布尔值确定`LevelTile`对象是否响应触摸事件。如果`LevelSelector`对象在场景中不可见，此变量设置为`true`，否则为`false`。

所有成员变量都处理完毕后，理解`LevelSelector`类的工作原理就会变得轻而易举！在第一步中，我们创建`LevelSelector`构造函数以初始化所有类变量。构造函数应该很容易理解，直到我们定义`mInitialX`和`mInitialY`变量的那一点。我们所做的就是基于列数、行数、瓦片尺寸和瓦片间隔来计算`LevelSelector`类网格的整体宽度和高度的一半。为了计算总宽度，我们需要将`COLUMNS`值乘以每个`LevelTile`对象的宽度。由于我们在每个瓦片之间包括间隔，我们还必须计算间隔将占用的空间。然而，间隔只会在瓦片之间发生，这意味着在最后一列不需要计算间隔，因此我们可以从间隔计算中减去一列。然后我们将这个值除以一半，以得出整个网格宽度的一半。最后，从`Camera`对象的中心位置减去整个网格宽度的一半，将给我们第一个`LevelTile`对象的 x 坐标！同样的数学方法适用于计算初始 y 坐标，除了 y 轴处理行而不是列，因此我们需要在计算`mInitialY`变量时进行相应的调整，以获得正确的 y 坐标。

`LevelSelector`类的第二步介绍了`LevelTile`对象创建和放置的方法。这是网格制作的魔法开始的地方。在我们开始迭代之前，我们声明并定义了临时的坐标，这些坐标将用于在网格上放置每个`LevelTile`对象，并在放置每个瓦片后相应地增加它们的值。`TILE_DIMENSION * 0.5f`的计算仅仅是为了适应 AndEngine 的`Entity`对象的锚点，或者说是依赖于`Entity`对象中心的放置坐标。此外，我们初始化了一个名为`currentTileLevel`的临时关卡数，将其初始化为`1`，这表示第一关的瓦片。每次在网格上放置一个关卡瓦片时，这个变量都会增加 1。定义了初始关卡瓦片的值后，我们继续创建`for`循环，它将遍历构成网格的行和列的每个位置。从第一行开始，我们将遍历 N 列，每次放置瓦片后，通过加上`TILE_DIMENSION`和`TILE_PADDING`来增加`tempX`变量，这将给我们下一个位置。当我们达到最大列数时，我们通过加上`TILE_DIMENSION`和`TILE_PADDING`来减少`tempY`变量，以便下降到下一行进行填充。这个过程一直持续到没有更多的行需要填充。

`LevelSelector`类中最后一步包括调用`setVisible(pBoolean)`的代码，在`LevelSelector`对象上设置，如果调用`show()`方法则启用可见性，如果调用`hide()`方法则禁用可见性。第一次`LevelSelector`对象调用`show()`时，它将被附加到`Scene`对象上。此外，`mHidden`变量将根据`LevelSelector`对象的可见性进行调整。

### 解释`LevelTile`类。

与`LevelSelector`类一样，我们将从概述`LevelTile`类不同成员变量的目的开始。以下是此类别中使用的变量列表以及每个变量的描述：

+   `mIsLocked`：`mIsLocked`布尔变量由`LevelTile`构造函数中的参数定义。此变量定义了此`LevelTile`对象的触摸事件是否应该产生积极事件，如加载关卡，或消极事件，如通知关卡已锁定。

+   `mLevelNumber`：这个变量简单地保存了`LevelTile`对象级别编号的值。该值是根据其在网格上的位置确定的；例如，放置在网格上的第一个瓦片将代表第 1 关，第二个瓦片将代表第 2 关，依此类推。

+   `mFont`和`mTileText`：`mFont`和`mTileText`对象用于在每个`LevelTile`上显示`Text`对象。如果`LevelTile`对象被认为是锁定的，那么瓦片上将会显示单词**locked**，否则将显示瓦片的关卡编号。

在`LevelTile`类的第一步中，我们只是介绍了构造函数。这里没有什么特别之处。但需要注意的是，构造函数确实依赖于常量`TILE_DIMENSION`值来指定瓦片的宽度/高度尺寸，而不需要指定参数。这是为了保持`LevelSelector`和`LevelTile`类之间的一致性。

在第二步中，我们引入了两个 getter 方法，可以用来获取`LevelTile`类的更重要值。尽管我们目前在任何一个类中都没有使用这些方法，但当`LevelSelector`/`LevelTile`对象被实现到一个需要如关卡编号等数据在游戏中传递的全功能游戏中时，它们可能变得很重要。

第三步介绍了一种方法，用于将`Text`对象附加到`LevelTile`，称为`attachText()`。此方法将`mTileText`对象放置在`LevelTile`对象的正中心，其字符串取决于`LevelTile`对象的锁定状态。如`mFont`和`mTileText`变量解释中所述，`mTileText`对象的`String`变量将显示**locked**（锁定）或瓦片的关卡编号。

最后一步要求我们覆盖`LevelTile`对象的`onAreaTouched()`方法。在我们考虑对任何瓷砖上的触摸事件做出响应之前，我们首先要确定包含`LevelTile`对象的`LevelSelector`对象是否可见。如果不可见，就没有必要处理任何触摸事件；但如果`LevelSelector`对象可见，那么我们就继续检查瓷砖是否被按下。如果按下了`LevelTile`对象，我们接着检查瓷砖是锁定还是解锁。在类的当前状态下，我们只是设置场景背景的颜色，以表示按下的瓷砖是否锁定。然而，在实际应用中，当前锁定事件可以替换为基本通知，表明选定的瓷砖已锁定。如果瓷砖没有锁定，那么触摸事件应该根据`LevelTile`对象的`mLevelNumber`变量将用户带到选定的关卡。如果游戏包含多个章节/世界/区域，那么我们可以根据游戏加载关卡的方式，采用以下伪代码实现：

```kt
LevelSelector.this.hide();
SceneManager.loadLevel(this.mLevelNumber, LevelSelector.this.mChapter);
```

## 还有更多…

一旦我们将`LevelSelector`类包含在我们选择的任何项目中，我们就可以轻松地将工作级别的选择网格实现到我们的`BaseGameActivity`中。为了正确创建`LevelSelector`对象并在我们的场景中显示它，我们需要确保已经创建了`ITextureRegion`对象和字体对象，以便在为`LevelSelector`类创建`LevelTile`对象时使用。我们将省略资源创建代码，以保持`LevelSelector`类的示例简洁。如有需要，请访问第一章中的食谱，*处理不同类型的纹理*以及*使用 AndEngine 字体资源*，了解更多关于如何为这个类设置必要资源的信息。

下面的代码展示了如何创建`LevelSelector`对象，可以在创建必要的`ITextureRegion`和字体`objects`之前，将其复制到任何活动的`onCreateScene()`方法中：

```kt
/* Define the level selector properties */
final int maxUnlockedLevel = 7;
final int levelSelectorChapter = 1;
final int cameraWidth = WIDTH;
final int cameraHeight = HEIGHT

/* Create a new level selector */
LevelSelector levelSelector = new LevelSelector(maxUnlockedLevel, levelSelectorChapter, cameraWidth, cameraHeight, mScene, mEngine);

/* Generate the level tiles for the levelSelector object */
levelSelector.createTiles(mTextureRegion, mFont);

/* Display the levelSelector object on the scene */
levelSelector.show();
```

这个`LevelSelector`类的一个很好的特性是它是一个`Entity`对象子类型。如果我们希望对其应用花哨的过渡效果，以便根据需要进出摄像头的视野，我们可以简单地调用`levelSelector.registerEntityModifier(pEntityModifier)`。由于在调用`createTiles()`方法时，`LevelTile`对象附加到`LevelSelector`对象上，因此`LevelSelector`对象位置的任何变化也会同步影响所有`LevelTile`对象。这也使得在处理多个章节时，创建可滚动的关卡选择器实现变得非常容易添加。

## 参见

+   在第二章中了解*AndEngine 实体*，*使用实体*。

+   在第二章中，通过精灵使场景生动起来，*使用实体*。

+   在第二章中将文本应用到图层中，*使用实体*。

# 隐藏和检索图层

在我们的游戏中，屏幕管理有几个不同的选项；屏幕可以是菜单屏幕、加载屏幕、游戏玩法屏幕等等。我们可以使用多个活动来充当每个屏幕，我们可以使用更明显的`Scene`对象来充当游戏中的每个屏幕，或者我们可以使用`Entity`对象来充当每个屏幕。尽管大多数开发者倾向于跟随使用多个活动或多个`Scene`对象来充当不同的游戏屏幕，但我们将快速查看使用`Entity`对象来充当游戏中的不同屏幕。

使用`Entity`对象作为我们游戏中的各种屏幕，相较于前述两种方法有许多好处。实体方法允许我们同时向游戏中应用许多不同的屏幕或图层。与使用多个活动或`Scene`对象作为游戏中的不同屏幕不同，我们可以使用`Entity`对象在设备上可视化显示多个屏幕。这非常有用，因为我们可以应用进入或离开游戏玩法时的过渡效果，并根据需要轻松加载和卸载资源。

下面的图片展示了此配方代码的实际应用。我们看到的是两个带有多个`Rectangle`子对象的`Entity`图层，在相机的视野中交替进行过渡进入和过渡移出。这表示我们可以如何使用`Entity`对象来处理一组或多组子对象之间的过渡效果：

![隐藏和检索图层](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_07.jpg)

## 准备就绪…

此配方需要了解`Entity`对象以及它们如何被用作图层来包含一组子对象。此外，我们通过使用实体修改器为这些图层添加过渡效果。在继续此配方之前，请确保阅读第二章中的整个配方，*了解 AndEngine 实体*，*使用实体*，*覆盖 onManagedUpdate() 方法*，以及*使用修改器和实体修改器*。

请参考代码包中名为`HidingAndRetrievingLayers`的类，以获取此配方的有效代码，并将其导入一个空的 AndEngine `BaseGameActivity`类。

## 如何操作…

以下步骤概述了如何使用实体修改器来处理游戏内不同屏幕/层次之间的过渡效果。这个食谱包括一个处理层次转换的简单方法，然而在实际应用中，这项任务通常是由屏幕/层次管理类完成的。层次之间的交换是基于经过的时间，仅用于自动化演示的目的。

1.  创建并将层次/屏幕定义为`Entity`对象，以及使用`ParallelEntityModifier`对象的过渡效果。这些对象应该是全局的：

    ```kt
    /* These three Entity objects will represent different screens */
    private final Entity mScreenOne = new Entity();
    private final Entity mScreenTwo = new Entity();
    private final Entity mScreenThree = new Entity();

    /* This entity modifier is defined as the 'transition-in' modifier
     * which will move an Entity/screen into the camera-view */
    private final ParallelEntityModifier mMoveInModifier = new ParallelEntityModifier(
      new MoveXModifier(3, WIDTH, 0),
      new RotationModifier(3, 0, 360),
      new ScaleModifier(3, 0, 1));

    /* This entity modifier is defined as the 'transition-out' modifier
     * which will move an Entity/screen out of the camera-view */
    private final ParallelEntityModifier mMoveOutModifier = new ParallelEntityModifier(
      new MoveXModifier(3, 0, -WIDTH),
      new RotationModifier(3, 360, 0),
      new ScaleModifier(3, 1, 0));
    ```

1.  创建`mScene`对象，重写其`onManagedUpdate()`方法以便处理调用下一步引入的`setLayer(pLayerIn, pLayerOut)`方法。此外，我们将在创建`mScene`对象后附加我们的`Entity`对象层次：

    ```kt
    mScene = new Scene() {
      /* Variable which will accumulate time passed to
       * determine when to switch screens */
      float timeCounter = 0;

      /* Define the first screen indices to be transitioned in and out */
      int layerInIndex = 0;
      int layerOutIndex = SCREEN_COUNT - 1;

      /* Execute the code below on every update to the mScene object */
      @Override
      protected void onManagedUpdate(float pSecondsElapsed) {

        /* If accumulated time is equal to or greater than 4 seconds */
        if (timeCounter >= 4) {

         /* Set screens to be transitioned in and out */
          setLayer(mScene.getChildByIndex(layerInIndex),
              mScene.getChildByIndex(layerOutIndex));

          /* Reset the time counter */
          timeCounter = 0;

          /* Setup the next screens to be swapped in and out */
          if (layerInIndex >= SCREEN_COUNT - 1) {
            layerInIndex = 0;
           layerOutIndex = SCREEN_COUNT - 1;
          } else {
            layerInIndex++;
            layerOutIndex = layerInIndex - 1;
          }

        }
        /* Accumulate seconds passed since last update */
        timeCounter += pSecondsElapsed;
        super.onManagedUpdate(pSecondsElapsed);
      }
    };

    /* Attach the layers to the scene.
     * Their layer index (according to mScene) is relevant to the
     * order in which they are attached */
    mScene.attachChild(mScreenOne); // layer index == 0
    mScene.attachChild(mScreenTwo); // layer index == 1
    mScene.attachChild(mScreenThree); // layer index == 2
    ```

1.  最后，我们将创建一个`setLayer(pLayerIn, pLayerOut)`方法，我们可以用它来处理将实体修改器注册到适当的`Entity`对象，根据它是否应该进入或离开相机视角：

    ```kt
    /* This method is used to swap screens in and out of the camera-view */
    private void setLayer(IEntity pLayerIn, IEntity pLayerOut) {

      /* If the layer being transitioned into the camera-view is invisible,
       * set it to visibile */
      if (!pLayerIn.isVisible()) {
       pLayerIn.setVisible(true);
      }

      /* Global modifiers must be reset after each use */
      mMoveInModifier.reset();
      mMoveOutModifier.reset();

      /* Register the transitional effects to the screens */
      pLayerIn.registerEntityModifier(mMoveInModifier);
      pLayerOut.registerEntityModifier(mMoveOutModifier);
    }
    ```

## 它是如何工作的…

这个食谱涵盖了与`Entity`层次转换相关的一个简单但有用的系统。更大的游戏可能会涉及更多变量来考虑层次交换，但这个概念对于所有项目规模中的实体/屏幕索引和创建屏幕转换方法都是相关的。

在第一步中，我们将创建全局对象。三个`Entity`对象将代表游戏内的不同屏幕。在此食谱中，三个`Entity`对象都包含四个`Rectangle`子对象，这使我们能够可视化屏幕过渡，然而我们可以将每个`Entity`对象解释为不同的屏幕，如菜单屏幕、加载屏幕和游戏玩法屏幕。我们还创建了两个全局`ParallelEntityModifier`实体修改器，以处理屏幕的位置变化。`mMoveInModifier`修改器将把注册的屏幕从相机视角右侧外部移动到相机视角中心。`mMoveOutModifier`修改器将把注册的屏幕从相机视角中心移动到相机视角左侧外部。这两个修改器都包括一个简单的旋转和缩放效果，以产生“滚动”过渡效果。

在下一步中，我们将创建`mScene`对象并将全局声明的`Entity`对象附加到它上面。在这个食谱中，我们设置`mScene`对象根据经过的时间处理屏幕交换，然而在讨论`mScene`对象的`onManagedUpdate()`方法如何处理屏幕交换之前，让我们看看如何获取`Entity`对象的索引，因为它们将用于确定哪些屏幕将被转换：

```kt
mScene.attachChild(mScreenOne); // layer index == 0
mScene.attachChild(mScreenTwo); // layer index == 1
mScene.attachChild(mScreenThree); // layer index == 2
```

如这段代码所示，我们根据名称以数字顺序附加屏幕。一旦`Entity`对象被附加到`Scene`对象，我们就可以在父对象上调用`getChildByIndex(pIndex)`方法，以通过其索引获取`Entity`对象。子项的索引由它们附加到另一个对象的顺序决定。我们在`mScene`对象的`onManagedUpdate()`方法中使用这些索引，以确定每四秒需要交换到摄像机视野中以及需要从视野中移出的实体/屏幕。

在初始化`mScene`对象期间，我们实例化了两个`int`变量，用于确定哪些屏幕需要进出摄像机的视野。最初，我们将`layerInIndex`定义为值`0`，这等于`mScreenOne`对象的索引，并将`layerOutIndex`定义为值`SCREEN_COUNT – 1`，这等于按附加到`Scene`对象的顺序`mScreenThree`对象的索引。在`mScene`对象的`onManagedUpdate()`方法中每四秒，我们会调用`setLayer(pLayerIn, pLayerOut)`方法来开始屏幕过渡，将`timeCounter`变量重置为累积下一个四秒，并确定下一个需要进出摄像机视野的`Entity`对象。虽然这个例子并不完全适用于大多数游戏，但它旨在让我们了解如何使用子索引来通过`setLayer(pLayerIn,pLayerOut)`方法进行过渡调用。

在最后一步中，我们引入了`setLayer(pLayerIn, pLayerOut)`方法，它处理将实体修改器应用于通过参数传递的`Entity`对象。这个方法有三个目标；首先，如果当前不可见，它将设置正在过渡到视图中的层为可见，它重置我们的`mMoveInModifier`和`mMoveOutModifier`对象，以便它们可以为`Entity`对象提供完整的过渡效果，最后，它在`pLayerIn`和`pLayerOut`参数上调用`registerEntityModifier(pEntityModifier)`，在`Entity`对象上启动过渡效果。

## 还有更多...

这个方法仅适用于在游戏中使用多个`Entity`对象作为不同屏幕的游戏结构。然而，如何在屏幕之间处理过渡完全取决于开发者。在做出决定之前，了解我们处理游戏中多个屏幕的不同选择的好坏是明智的。请查看以下列表，了解不同方法的优缺点：

+   **活动/屏幕**：

    +   优点：通过简单调用活动的`finish()`方法，Android 操作系统将为我们处理资源卸载，使得资源管理变得非常简单。

    +   缺点：每个屏幕过渡都会在启动新活动/屏幕时显示短暂的黑色屏幕。

    +   缺点：必须为每个活动加载各自的资源。这意味着预加载资源不是一个选项，这可能会增加整体加载时间，尤其是考虑到可能在所有屏幕上使用的资源，如字体或音乐播放资源。

    +   缺点：由于 Android 的内存管理功能，被视为后台进程的活动可能会在任何时候被杀死，假设设备内存不足。这会在我们离开一个应该保持暂停状态直到用户返回的活动时造成问题。有可能当我们需要时，从任何活动转换而来的状态可能无法以相同的状态返回。

+   **场景/屏幕**：

    +   优点：有可能预加载可能跨多个屏幕使用的必要资源。这可以大大帮助减少加载时间，具体取决于可预加载资源的数量。

    +   优点：我们能够在游戏中引入加载屏幕，而不是在资源加载时显示空白屏幕。

    +   优点/缺点：必须开发一个屏幕和资源管理系统，以便处理资源的加载/卸载和屏幕的切换。根据特定游戏的大小和需求，这可能是一个相当大的任务。然而，这种方法可以在屏幕间移动时实现无缝过渡，因为我们可以更方便地加载/卸载资源，而不是在用户决定切换屏幕时立即进行。

    +   缺点：通常一次只能将一个`Scene`对象应用到我们的 Engine 对象上，这意味着屏幕过渡在动画/流畅性方面将会有所不足。设置的屏幕将简单地替换之前的屏幕。

+   **实体/屏幕**：

    +   优点：当处理`Entity`对象作为屏幕时，我们可以将任意数量的对象附加到一个`Scene`对象。这使我们能够获得场景/屏幕方法的所有优点，同时增加了能够添加基于时间的过渡效果的好处，例如从菜单屏幕“滑动”到加载屏幕，再到游戏屏幕。这正是本教程代码所展示的。

    +   优点/缺点：与场景/屏幕方法一样，我们需要自己处理所有屏幕和资源的清理。优点大于缺点，但是与活动/屏幕方法相比，根据项目的大小，某些人可能会认为需要屏幕/资源管理系统是一个缺点。

在结束这个教程之前，还有一个重要的话题在本教程中没有讨论。请看下面的图，它展示了这个教程在设备上的显示结果可能的样子：

![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/Image_03_08.jpg)

前图展示了用户在游戏内不同屏幕间导航时典型的过渡事件。我们讲解过这种导航是如何通过将新屏幕带入摄像机视野来实现的。更重要的是，这些过渡事件还应该处理资源的加载和卸载。毕竟，没有理由在**菜单屏幕**未展示给用户时还让它占用设备宝贵的资源。在理想情况下，如果我们如前图所示从**菜单屏幕**移动到**游戏玩法屏幕**，在**T1**阶段，**游戏玩法屏幕**将开始加载其资源。一旦达到**T2**阶段，意味着**加载屏幕**成为游戏当前的主屏幕，此时会卸载**菜单屏幕**的所有必要资源，并将其从`Scene`对象中分离，以移除不必要的开销。

这只是关于如何在游戏中处理屏幕间过渡以实现流畅过渡和减少过渡间的加载时间的一个简要概述。关于屏幕管理的内部工作原理的更深入信息，请参见第五章《场景和图层管理》。

## 另请参阅

+   在第二章《使用实体》中的*了解 AndEngine 实体*。

+   在第二章《使用实体》中*覆盖 onManagedUpdate()方法*。

+   在第二章《使用实体》中的*使用修饰符和实体修饰符*。


# 第四章：使用摄像机

本章将介绍 AndEngine 的各种摄像机对象和高级摄像机控制。主题包括：

+   引入摄像机对象

+   使用边界摄像机限制摄像机区域

+   使用缩放摄像机更近距离观察

+   使用平滑摄像机创建平滑移动

+   捏合缩放摄像机功能

+   拼接背景

+   为摄像机应用 HUD

+   将控制器附加到显示

+   坐标转换

+   创建分屏游戏

# 引言

AndEngine 包括三种类型的摄像机，不包括基础的`Camera`对象，这允许我们更具体地控制摄像机的行为。摄像机在游戏中可以扮演许多不同的角色，在某些情况下，我们可能需要不止一个摄像机。这一章将介绍我们可以使用 AndEngine 的`Camera`对象的不同目的和方式，以便在我们的游戏中应用更高级的摄像机功能。

# 引入摄像机对象

在设计大型游戏时，摄像机可以有许多用途，但它的主要目标是将在游戏世界的特定区域显示在设备的屏幕上。这一主题将介绍基础的`Camera`类，涵盖摄像机的一般方面，以便为将来的摄像机使用提供参考。

## 如何操作...

在游戏开发中，摄像机的重要性在于它决定了我们在设备上能看到什么。创建我们的摄像机就像下面的代码一样简单：

```kt
final int WIDTH = 800;
final int HEIGHT = 480;

// Create the camera
Camera mCamera = new Camera(0, 0, WIDTH, HEIGHT);
```

`WIDTH`和`HEIGHT`值将定义游戏场景的区域，该区域将在设备上显示。

## 它是如何工作的...

重要的是要了解摄像机的主要功能，以便在我们的项目中充分利用它。所有不同的摄像机都继承了本主题中找到的方法。让我们看看在 AndEngine 开发中一些最必要的摄像机方法：

**摄像机定位**：

`Camera`对象遵循与实体相同的坐标系。例如，将摄像机的坐标设置为`(0,0)`，将设置摄像机的中心点为定义的坐标。此外，增加 x 值将摄像机向右移动，增加 y 值将摄像机向上移动。减少这些值将产生相反的效果。为了将摄像机重新定位到定义的位置中心，我们可以调用以下方法：

```kt
// We can position the camera anywhere in the game world
mCamera.setCenter(WIDTH / 2, HEIGHT / 2);
```

上述代码对默认的摄像机位置没有任何影响（假设`WIDTH`和`HEIGHT`值用于定义摄像机的宽度和高度）。这将设置摄像机的中心到我们场景的“中心”，当创建`Camera`对象时，这自然等于摄像机`WIDTH`和`HEIGHT`值的一半。在需要将摄像机重置回初始位置的情况下，可以使用前面的方法调用，这在摄像机在游戏过程中移动，但在用户返回菜单时应返回初始位置时很有用。

不设置特定坐标而移动摄像头可以通过`offsetCenter(x,y)`方法实现，其中`x`和`y`值定义了在场景坐标中偏移摄像头的距离。此方法将指定的参数值添加到摄像头的当前位置：

```kt
// Move the camera up and to the right by 5 pixels
mCamera.offsetCenter(5, 5);
// Move the camera down and to the left by 5 pixels
mCamera.offsetCenter(-5, -5);
```

此外，我们可以通过以下方法获取摄像头的中心坐标（x 和 y）：

```kt
mCamera.getCenterX();
mCamera.getCenterY();
```

**调整摄像头的宽度和高度**：

可以通过摄像头的`set()`方法调整摄像头的初始宽度和高度。我们还可以通过调用如`setXMin()`/`setXMax()`和`setYMin()`/`setYMax()`等方法来设置摄像头的最小/最大 x 和 y 值。以下代码将使摄像头宽度减半，同时保持初始的摄像头高度：

```kt
// Shrink the camera by half its width
mCamera.set(0, 0, mCamera.getWidth() / 2, mCamera.getHeight());
```

需要注意的是，在缩小摄像头宽度的同时，我们会失去在定义区域之外的像素和任何实体的可见性。此外，缩小或扩展摄像头的宽度和高度可能会导致实体看起来被拉伸或压缩。通常，在开发典型游戏时，修改摄像头的宽度和高度并不是必要的。

`Camera`对象还允许我们通过调用`getXMin()`/`getXMax()`和`getYMin()`/`getYMax()`获取摄像头的当前最小/最大宽度和高度值。

**可见性检查**：

`Camera`类允许我们检查特定的`Entity`对象是否在摄像头的视野内可见。`Entity`对象子类型包括但不限于`Line`和`Rectangle`基元，`Sprite`和`Text`对象，以及它们的子类型，如`TiledSprite`和`ButtonSprite`对象等。可以通过以下方法进行可见性检查：

```kt
// Check if entity is visible. true if so, false otherwise
mCamera.isEntityVisible(entityObject);
```

可见性检查对于许多游戏来说非常有用，例如，重用可能离开摄像头视野的对象，这样就可以限制在可能产生大量对象并最终离开摄像头视野的情况下创建对象的总数。相反，我们可以重用离开摄像头视野的对象。

**追逐实体功能**：

在很多游戏中，常常需要摄像头跟随屏幕上的`Entity`对象移动，例如在横向卷轴游戏中。我们可以通过调用一个简单的方法轻松设置摄像头跟随游戏世界中任何地方的实体移动。

```kt
mCamera.setChaseEntity(entityObject);
```

之前的代码将在每次更新摄像头时将摄像头位置应用到指定实体的位置上。这确保了实体始终处于摄像头的中心。

### 注意：由于原文最后一行只有一个单词"Note"，并没有提供足够的信息来进行翻译，因此在这里保留原文。如果需要进一步的翻译，请提供完整的句子或段落。

在本书的多数食谱中，我们指定了 800 像素的摄像头宽度和 480 像素的摄像头高度。然而，这些值完全取决于开发者，并且应由游戏的需求来定义。选择这些特定的值是因为它们相对适合小屏幕和大屏幕设备。

# 使用边界摄像头限制摄像头区域

`BoundCamera`对象允许我们定义摄像机区域的具体边界，限制摄像机在 x 轴和 y 轴上可以移动的距离。当摄像机需要跟随玩家但又不超出关卡边界时（例如用户靠近墙壁时），这种摄像机非常有用。

## 如何操作...

创建`BoundCamera`对象需要与普通`Camera`对象相同的参数：

```kt
BoundCamera mCamera = new BoundCamera(0, 0, WIDTH, HEIGHT);
```

## 它是如何工作的...

`BoundCamera`对象扩展了普通的`Camera`对象，为我们提供了本章中*摄像机对象介绍*一节描述的所有原始摄像机功能。实际上，除非我们在`BoundCamera`对象上配置了一个有边界的区域，否则我们实际上是在使用基本的`Camera`对象。

在摄像机对其可移动区域应用限制之前，我们必须定义摄像机可以自由移动的可用区域：

```kt
// WIDTH = 800;
// HEIGHT = 480;
// WIDTH and HEIGHT are equal to the camera's width and height
mCamera.setBounds(0, 0, WIDTH * 4, HEIGHT);

// We must call this method in order to apply camera bounds
mCamera.setBoundsEnabled(true);
```

上述代码将从场景坐标`(0,0)`的位置开始设置摄像机边界，一直到`(3200,480)`，因为我们把摄像机的宽度放大了四倍作为最大 x 区域，允许摄像机滚动四倍于其宽度。由于边界高度设置为与摄像机高度相同的值，摄像机将不会响应 y 轴上的变化。

## 另请参阅

+   本章节提供的*摄像机对象介绍*。

# 用缩放摄像机更近距离地观察

AndEngine 的`BoundCamera`和`Camera`对象默认不支持放大和缩小。如果我们想要允许摄像机缩放，可以创建一个扩展了`BoundCamera`类的`ZoomCamera`对象。这个对象包括其继承类所有的功能，包括创建摄像机边界。

## 如何操作...

`ZoomCamera`对象与`BoundCamera`类似，在创建摄像机时不需要定义额外的参数：

```kt
ZoomCamera mCamera = new ZoomCamera(0, 0, WIDTH, HEIGHT);
```

## 它是如何工作的…

为了向摄像机应用缩放效果，我们可以调用`setZoomFactor(factor)`方法，其中`factor`是我们想要应用到`Scene`对象的放大倍数。通过以下代码可以实现放大和缩小：

```kt
// Divide the camera width/height by 1.5x (Zoom in)
mCamera.setZoomFactor(1.5f);

// Divide the camera width and height by 0.5x (Zoom out)
mCamera.setZoomFactor(0.5f);
```

在处理摄像机的缩放因子时，我们必须知道`1`的因子等于`Camera`类的默认因子。大于`1`的缩放因子将摄像机向场景内缩放，而任何小于`1`的值将使摄像机向外缩放。

处理缩放因子的数学运算非常基础。摄像机只需将缩放因子除以我们摄像机的`WIDTH`和`HEIGHT`值，有效实现摄像机的“缩放”。如果我们的摄像机宽度是`800`，那么`1.5f`的缩放因子将使摄像机向内缩放，最终将摄像机的宽度设置为`533.3333`，这将限制场景显示的区域面积。

### 注意

在应用了缩放因子（不等于 1）的情况下，`ZoomCamera`对象返回的`getMinX()`、`getMaxX()`、`getMinY()`、`getMaxY()`、`getWidth()`和`getHeight()`值会自动被缩放因子除。

## 还有更多…

在缩放摄像头中启用不等于 1 的因子的边界，将对摄像头能够平移的总可用区域产生影响。假设边界的最小和最大 x 值从 0 设置为 800，如果摄像头宽度等于 800，那么在 x 轴上将不允许有任何移动。如果我们放大摄像头，摄像头的宽度将减小，从而允许摄像头移动时有更多的余地。

### 注意

如果定义了一个缩放因子，导致摄像头的宽度或高度超出摄像头边界，那么将应用缩放因子到摄像头，但超出轴将不允许移动。

## 另请参阅

+   *本章中提供的摄像头对象介绍*。

+   *本章中提供的限制摄像头区域的边界摄像头*。

# 使用平滑摄像头创建平滑移动

`SmoothCamera`对象是四种可选摄像头中最先进的一个。这个摄像头支持所有不同的摄像头功能类型（边界、缩放等），并新增了一个选项，即在为摄像头设置新位置时，可以给摄像头的移动速度应用一个定义好的速度。这样做的结果是，摄像头在移动时看起来会“平滑”地进入和退出，从而实现相当微妙的摄像头移动。

## 如何操作…

这种摄像头类型是四种中唯一需要在构造函数中定义额外参数的一个。这些额外的参数包括摄像头可以移动的最大 x 和 y 速度以及处理摄像头缩放速度的最大缩放因子变化。让我们看看创建这种摄像头的样子：

```kt
// Camera movement speeds
final float maxVelocityX = 10;
final float maxVelocityY = 5;
// Camera zoom speed
final float maxZoomFactorChange = 5;

// Create smooth camera
mCamera = new SmoothCamera(0, 0, WIDTH, HEIGHT, maxVelocityX, maxVelocityY, maxZoomFactorChange);
```

## 工作原理…

在这个示例中，我们将创建一个摄像头，为摄像头的移动和缩放应用平滑的过渡效果。与其他三种摄像头类型不同，不是直接使用`setCenter(x,y)`将摄像头中心设置到定义的位置，而是使用`maxVelocityX`、`maxVelocityY`和`maxZoomFactorChange`变量来定义摄像头从点 A 到点 B 的移动速度。增加速度会使摄像头移动更快。

对于`SmoothCamera`类，无论是摄像头移动还是缩放，都有两种选择。我们可以通过调用这些任务的默认摄像头方法（`camera.setCenter()`和`camera.setZoomFactor()`）使摄像头平滑移动或缩放。另一方面，有时我们需要立即重新定位摄像头。这可以通过分别调用`camera.setCenterDirect()`和`camera.setZoomFactorDirect()`方法来实现。这些方法通常用于重置平滑摄像头的位置。

## 另请参阅

+   本章节中提供的*相机对象介绍*。

+   本章节中提到的*限制相机区域的边界相机*。

+   本章节中提供的*通过缩放相机近距离观察*。

# 捏合缩放相机功能

AndEngine 包含一系列“检测器”类，可以与场景触摸事件结合使用。本主题将介绍如何使用`PinchZoomDetector`类，以便通过在屏幕上按两指，并让它们靠近或分开来调整缩放因子，从而允许相机的缩放。

## 开始操作…

请参考代码包中名为`ApplyingPinchToZoom`的类。

## 如何操作…

按照以下步骤进行操作，以设置捏合缩放功能。

1.  我们首先要做的是将适当的监听器实现到我们的类中。由于我们将处理触摸事件，因此需要包含`IOnSceneTouchListener`接口。此外，我们还需要实现`IPinchZoomDetectorListener`接口，以处理相机缩放因子在等待触摸事件时的变化：

    ```kt
    public class ApplyingPinchToZoom extends BaseGameActivity implements
        IOnSceneTouchListener, IPinchZoomDetectorListener {
    ```

1.  在`BaseGameActivity`类的`onCreateScene()`方法中，将`Scene`对象的触摸监听器设置为`this`活动，因为我们让`BaseGameActivity`类实现触摸监听器类。我们还将在此方法中创建并启用`mPinchZoomDetector`对象：

    ```kt
    /* Set the scene to listen for touch events using
    * this activity's listener */
    mScene.setOnSceneTouchListener(this);

    /* Create and set the zoom detector to listen for 
     * touch events using this activity's listener */
    mPinchZoomDetector = new PinchZoomDetector(this);

    // Enable the zoom detector
    mPinchZoomDetector.setEnabled(true);
    ```

1.  在`BaseGameActivity`类的实现的`onSceneTouchEvent()`方法中，我们必须将触摸事件传递给`mPinchZoomDetector`对象：

    ```kt
    @Override
    public boolean onSceneTouchEvent(Scene pScene, TouchEvent pSceneTouchEvent) {
      // Pass scene touch events to the pinch zoom detector
      mPinchZoomDetector.onTouchEvent(pSceneTouchEvent);
      return true;
    }
    ```

1.  接下来，当`mPinchZoomDetector`对象检测到用户在屏幕上使用两指操作时，我们将获取`ZoomCamera`对象的初始缩放因子。我们将使用通过`IPinchZoomDetectorListener`接口实现的`onPinchZoomStarted()`方法：

    ```kt
    /* This method is fired when two fingers press down
    * on the display */
    @Override
    public void onPinchZoomStarted(PinchZoomDetector pPinchZoomDetector,
        TouchEvent pSceneTouchEvent) {
      // On first detection of pinch zooming, obtain the initial zoom factor
      mInitialTouchZoomFactor = mCamera.getZoomFactor();
    }
    ```

1.  最后，在检测到屏幕上出现捏合动作时，我们将更改`ZoomCamera`对象的缩放因子。这段代码将放在`onPinchZoom()`和`onPinchZoomFinished()`方法中：

    ```kt
    @Override
    public void onPinchZoom(PinchZoomDetector pPinchZoomDetector,
        TouchEvent pTouchEvent, float pZoomFactor) {

      /* On every sub-sequent touch event (after the initial touch) we offset
      * the initial camera zoom factor by the zoom factor calculated by
      * pinch-zooming */
      final float newZoomFactor = mInitialTouchZoomFactor * pZoomFactor;

      // If the camera is within zooming bounds
      if(newZoomFactor < MAX_ZOOM_FACTOR && newZoomFactor > MIN_ZOOM_FACTOR){
        // Set the new zoom factor
        mCamera.setZoomFactor(newZoomFactor);
      }
    }
    ```

## 工作原理…

在此食谱中，我们覆盖了发生在我们场景上的场景触摸事件，将这些触摸事件传递给`PinchZoomDetector`对象，该对象将处理`ZoomCamera`对象的缩放功能。以下步骤将引导我们了解捏合缩放的工作原理。由于在此活动中我们将使用缩放因子，因此我们需要使用`ZoomCamera`类或`SmoothCamera`类的实现。

在这个配方的第一步和第二步中，我们正在实现所需的监听器，并将它们注册到`mScene`对象和`mPinchZoomDetector`对象。由于`ApplyingPinchToZoom`活动正在实现监听器，我们可以将代表我们`BaseGameActivity`类的`this`传递给`mScene`对象作为触摸监听器。我们还可以将此活动作为捏合检测监听器。一旦创建了捏合检测器，我们可以通过调用`setEnabled(pSetEnabled)`方法来启用或禁用它。

在第三步中，我们将`pSceneTouchEvent`对象传递给捏合检测器的`onTouchEvent()`方法。这样做可以让捏合检测器获取特定的触摸坐标，这些坐标将在内部用于根据手指位置计算缩放因子。

当在屏幕上按下两个手指时，捏合检测器将触发第四步中显示的代码片段。我们必须在此时获取相机的初始缩放因子，以便在触摸坐标改变时正确偏移缩放因子。

最后一步涉及计算偏移缩放因子并将其应用于`ZoomCamera`对象。通过将初始缩放因子与`PinchZoomDetector`对象计算的缩放因子变化相乘，我们可以成功偏移相机的缩放因子。一旦我们计算了`newZoomFactor`对象的值，我们调用`setZoomFactor(newZoomFactor)`以改变我们相机的缩放级别。

将缩放因子限制在特定范围内只需添加一个`if`语句，指定我们需要的最大和/或最小缩放因子即可。在这种情况下，我们的相机不能缩放比`0.5f`更小，或者比`1.5f`更大。

## 另请参阅

+   本章提供了*使用缩放相机近距离观察*的内容。

# 拼接背景

尽管 AndEngine 的`Scene`对象允许我们为场景设置背景，但这并不总是我们项目的可行解决方案。为了使背景能够进行平移和缩放，我们可以把多个纹理区域拼接在一起，并将其直接应用到场景中作为精灵。这一主题将要讲述如何将两个 800 x 480 的纹理区域拼接在一起，以创建一个更大的可平移和可缩放的背景。背景拼接背后的想法是允许场景的部分以较小的块显示。这为我们提供了创建较小纹理尺寸的机会，以避免超过大多数设备 1024 x 1024 的最大纹理尺寸限制。此外，我们可以启用剪裁，以便在屏幕上不显示场景部分时，不绘制它们，以提高性能。以下图展示了结果：

![拼接背景](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_04_01.jpg)

## 开始使用...

执行本章给出的食谱*捏合缩放相机功能*，以了解捏合缩放的工作原理。此外，我们还需要准备两张单独的 800 x 480 像素的图片，类似于本食谱引言中的前一个图像，以 PNG 格式保存，然后在代码包中引用名为`StitchedBackground`的类。

## 如何操作…

背景拼接是一个简单的概念，它涉及将两个或更多的精灵直接并排放置，重叠放置，或者上下放置，以形成看似拥有一个单一的、大精灵的效果。在本食谱中，我们将介绍如何做到这一点，以避免可怕的纹理溢出效应。按照以下步骤操作：

1.  首先，我们需要创建我们的`BuildableBitmapTextureAtlas`和`ITextureRegion`对象。非常重要的一点是，纹理图集的大小必须与我们的图片文件完全相同，以避免纹理溢出。同时，在构建纹理图集的过程中，我们绝不能包含任何填充或间隔。以下代码将创建左侧的纹理图集和纹理区域，同样的代码也适用于右侧：

    ```kt
    /* Create the background left texture atlas */
    BuildableBitmapTextureAtlas backgroundTextureLeft = new BuildableBitmapTextureAtlas(
        mEngine.getTextureManager(), 800, 480);

    /* Create the background left texture region */
    mBackgroundLeftTextureRegion = BitmapTextureAtlasTextureRegionFactory
        .createFromAsset(backgroundTextureLeft, getAssets(),
            "background_left.png");

    /* Build and load the background left texture atlas */
    try {
      backgroundTextureLeft
          .build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(
              0, 0, 0));
      backgroundTextureLeft.load();
    } catch (TextureAtlasBuilderException e) {
      e.printStackTrace();
    }
    ```

1.  一旦纹理资源就位，我们就可以移动到活动的`onPopulateScene()`方法中，在那里我们将创建并将精灵应用到`Scene`对象上：

    ```kt
    final int halfTextureWidth = (int) (mBackgroundLeftTextureRegion.getWidth() * 0.5f);
    final int halfTextureHeight = (int) (mBackgroundLeftTextureRegion.getHeight() * 0.5f);

    // Create left background sprite
    mBackgroundLeftSprite = new Sprite(halfTextureWidth, halfTextureHeight, mBackgroundLeftTextureRegion,
        mEngine.getVertexBufferObjectManager())
    ;
    // Attach left background sprite to the background scene
    mScene.attachChild(mBackgroundLeftSprite);

    // Create the right background sprite, positioned directly to the right of the first segment
    mBackgroundRightSprite = new Sprite(mBackgroundLeftSprite.getX() + mBackgroundLeftTextureRegion.getWidth(),
        halfTextureHeight, mBackgroundRightTextureRegion,
        mEngine.getVertexBufferObjectManager());

    // Attach right background sprite to the background scene
    mScene.attachChild(mBackgroundRightSprite);
    ```

## 它是如何工作的…

背景拼接可以在许多不同的场景中使用，以避免某些问题。这些问题包括导致某些设备不兼容的过大纹理尺寸，不响应相机位置或缩放因子变化的静态背景，以及性能问题等。在本食谱中，我们创建了一个大背景，这是通过将两个`Sprite`对象并排放置拼接而成的，每个代表不同的`TextureRegion`对象。结果是形成一个大于相机宽度两倍的大背景，尺寸为 1600 x 480 像素。

在处理允许场景滚动的拼接背景的大多数情况下，我们将需要启用一些相机边界，以防止在相机试图超出背景区域时更新相机位置。我们可以使用`ZoomCamera`对象来实现这一点，将边界设置为背景预定的尺寸。由于我们处理的是两个各为 800 x 480 像素的 PNG 图片并排拼接，可以肯定地说，坐标`(0,0)`到`(1600, 480)`足以作为相机边界。

如第一步所述，使用这种方法创建大型背景时，我们必须遵循一些规则。图像大小必须与`BuildableBitmapTextureAtlas`纹理图集大小完全相同！不遵循此规则可能会导致精灵之间周期性地出现伪影，这对玩家来说是非常分散注意力的。这也意味着我们不应该在用于背景拼接的`BuildableBitmapTextureAtlas`对象中包含超过一个`ITextureRegion`对象。在这种情况下，我们还应该避免使用填充和间距功能。然而，遵循这些规则，我们仍然可以对纹理图集应用`TextureOptions.BILINEAR`纹理过滤，并且不会导致问题。

在第二步中，我们继续创建`Sprite`对象。这里没有特别之处；我们只是在给定位置创建一个`Sprite`对象，然后在第一个旁边直接设置下一个精灵。对于极其庞大和多样的背景，将纹理拼接在一起的方法可以帮助显著降低应用程序的性能成本，允许我们停止渲染不再可见的背景较小部分。这个特性称为**剔除**。有关如何实现这一点，请参见第八章，*最大化性能*中的*通过实体剔除禁用渲染*。

## 参见 also（此处的"also"似乎是原文的残留，若不需要翻译请忽略）

+   在第二章，*设计您的菜单*中，介绍*使用精灵让场景生动*。

+   本章节提供*通过缩放相机更近距离观察*。

+   本章节介绍*捏合缩放相机功能*。

+   在第八章，*最大化性能*中，介绍*通过实体剔除禁用渲染*。

# 向相机应用 HUD。

即使是最简单的游戏，**HUD（抬头显示）**也可能是一个非常实用的组件。HUD 的目的是包含一组按钮、文本或任何其他`Entity`对象，以便为用户提供界面。HUD 有两个关键点：第一，无论相机是否改变位置，HUD 的子对象始终会在屏幕上显示；第二，HUD 的子对象始终会显示在场景子对象的前面。在本章中，我们将向相机应用 HUD，以便在游戏过程中为用户提供界面。

## 如何操作...

将以下代码导入您选择的任何`BaseGameActivity`的`onCreateEngineOptions()`方法中，如果需要，请替换此代码片段中的相机类型：

```kt
@Override
public EngineOptions onCreateEngineOptions() {

  // Create the camera
  Camera mCamera = new Camera(0, 0, WIDTH, HEIGHT);

  // Create the HUD
  HUD mHud = new HUD();

  // Attach the HUD to the camera
  mCamera.setHUD(mHud);

  EngineOptions engineOptions = new EngineOptions(true,
      ScreenOrientation.LANDSCAPE_FIXED, new FillResolutionPolicy(),
      mCamera);

  return engineOptions;
}
```

## 它是如何工作的…

使用`HUD`类通常是一项非常简单的任务。根据所创建的游戏类型，`HUD`类的实用性可能会有很大差异，但无论如何，在决定使用这个类之前，我们必须了解一些事情：

+   `HUD`实体在相机移动时不会改变位置。一旦定义了它们的位置，实体将保持在该屏幕位置，除非通过`setPosition()`方法进行设置。

+   `HUD`实体将始终出现在任何`Scene`实体的顶部，无论 z-index、应用顺序或任何其他场景如何。

+   在任何情况下都不应将剔除应用于要附加到`HUD`类的实体。剔除以相同的方式影响`HUD`类上的`Entity`对象，就像它会影响`Scene`对象上的`Entity`对象一样，即使`Entity`对象似乎没有移出屏幕。这将导致看似随机消失的`HUD`实体。只是不要这么做！

在*如何操作...*部分的代码中，我们可以看到设置`HUD`类非常简单。创建并应用`HUD`对象到相机只需以下两行代码即可完成：

```kt
  // Create the HUD
  HUD mHud = new HUD();

  // Attach the HUD to the camera
  mCamera.setHUD(mHud);
```

从这一点开始，我们可以将`HUD`对象视为游戏中任何其他层的实体应用。

# 将控制器应用于显示

根据我们正在创建的游戏类型，玩家互动有许多可能的解决方案。AndEngine 包含两个独立的类，其中一个模拟方向控制板，称为`DigitalOnScreenControl`，另一个模拟摇杆，称为`AnalogOnScreenControl`。本主题将介绍 AndEngine 的`AnalogOnScreenControl`类，但使用这个类将给我们足够的信息去使用任一控制器。

## 开始吧...

此配方需要两个独立的资源，它们将作为控制器的基础和旋钮。在继续*如何操作...*部分之前，请将名为`controller_base.png`和`controller_knob.png`的图片包含到您选择的项目中的`assets/gfx`文件夹中。这些图片可能看起来像下面的图，基础为 128 x 128 像素，旋钮为 64 x 64 像素：

![开始吧...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_04_02.jpg)

## 如何操作...

一旦我们为控制器准备好了两个必要的资源，我们就可以开始编码了。首先，我们可以开始创建保存控制器资源的`ITextureRegion`和`BuildableBitmapTextureAtlas`对象。对于控制器纹理图集或纹理区域没有特殊步骤；像创建普通精灵一样创建它们。像往常一样，在您选择的活动中的`onCreateResources()`方法中完成此操作。

一旦`ITextureRegion`对象被编码并准备好在活动内使用，我们可以在活动对象的`onCreateScene()`方法中创建`AnalogOnScreenControl`类，如下所示：

```kt
// Position the controller in the bottom left corner of the screen
final float controllerX = mControllerBaseTextureRegion.getWidth();
final float controllerY = mControllerBaseTextureRegion.getHeight();

// Create the controller
mController = new AnalogOnScreenControl(controllerX, controllerY, mCamera, mControllerBaseTextureRegion, mControllerKnobTextureRegion, 0.1f, mEngine.getVertexBufferObjectManager(), new IAnalogOnScreenControlListener(){
  /* The following method is called every X amount of seconds,
  * where the seconds are determined by the pTimeBetweenUpdates
  * parameter in the controller's constructor  */
  @Override
  public void onControlChange(
      BaseOnScreenControl pBaseOnScreenControl, float pValueX,
      float pValueY) {
    mCamera.setCenter(mCamera.getCenterX() + (pValueX * 10), mCamera.getCenterY() + (pValueY * 10));
    Log.d("Camera", String.valueOf(mCamera.getCenterX()));
  }

  // Fired when the knob is simply pressed
  @Override
  public void onControlClick(
      AnalogOnScreenControl pAnalogOnScreenControl) {
    // Do nothing
  }

});

// Initialize the knob to its center position
mController.refreshControlKnobPosition();

// Set the controller as a child scene
mScene.setChildScene(mController);
```

## 工作原理...

如我们所见，一些参数与我们创建`Sprite`对象时定义的参数并无不同。前五个参数是自解释的。第六个参数`(0.1f)`是“更新之间的时间”参数。这个值控制`onControlChange()`方法内的事件被触发的频率。对于 CPU 密集型代码，增加更新之间的时间可能有益，而对于复杂性较低的代码，非常低的更新时间可能没有问题。

控制器构造函数中必须包含的最后一个参数是`IanalogOnScreenControlListener`，它处理基于控制器是被简单点击还是被按住并保持在一个偏移位置的事件。

正如我们在`onControlChange()`事件中所见，我们可以通过`pValueX`和`pValueY`变量获取控制器旋钮的当前位置。这些值包含了控制器的 x 和 y 偏移量。在本示例中，我们使用旋钮的 x 和 y 偏移量来移动摄像头的位置，这也让我们了解到如何使用这些变量来移动其他实体，例如玩家的精灵。

# 坐标转换

在某些场景对象依赖于多个实体作为游戏精灵的基础层的场景中，坐标转换可能非常有用。在包含许多父对象，每个父对象都有自己的子对象集合的游戏中，需要获取子对象相对于`Scene`对象的位置是常有的事。在所有层在整个游戏中始终保持相同的（0, 0）坐标的情况下，这不是问题。另一方面，当我们的层开始移动时，子对象的位置会随父对象移动，但它们在层上的坐标保持不变。本主题将涵盖将场景坐标转换为局部坐标，以允许嵌套实体在场景上正确定位。

## 如何操作…

将以下代码导入你选择的任何`BaseGameActivity`的`onCreateScene()`方法中。

1.  本方法的第一个步骤是创建一个`Rectangle`对象并将其应用到`Scene`对象上。这个`Rectangle`对象将作为另一个`Rectangle`对象的父实体。我们将它的颜色设置为蓝色，以便当两个矩形重叠时可以区分，因为父`Rectangle`对象将不断移动：

    ```kt
    /* Create a rectangle on the Scene that will act as a layer */
    final Rectangle rectangleLayer = new Rectangle(0, HEIGHT * 0.5f, 200, 200, mEngine.getVertexBufferObjectManager()){

      /* Obtain the half width of this rectangle */
      int halfWidth = (int) (this.getWidth() * 0.5f);

      /* Boolean value to determine whether to pan left or right */
      boolean incrementX = true;

      @Override
      protected void onManagedUpdate(float pSecondsElapsed) {

        float currentX = this.getX();

        /* Determine whether or not the layer should pan left or right */
        if(currentX + halfWidth > WIDTH){
          incrementX = false;
        }
        else if (currentX - halfWidth < 0){
          incrementX = true;
        }
        /* Increment or decrement the layer's position based on incrementX */
        if(incrementX){
          this.setX(currentX + 5f);
        } else {
          this.setX(currentX - 5f);
        }

        super.onManagedUpdate(pSecondsElapsed);
      }
    };

    rectangleLayer.setColor(0, 0, 1);

    // Attach the layer to the scene
    mScene.attachChild(rectangleLayer);
    ```

1.  接下来，我们将子`Rectangle`对象添加到我们先前创建的第一个`Rectangle`对象中。这个`Rectangle`对象不会移动；相反，它将保持在屏幕中心，而其父对象继续在周围移动。这个`Rectangle`对象将利用坐标转换来保持其位置：

    ```kt
    /* Create a smaller, second rectangle and attach it to the first */
    Rectangle rectangle = new Rectangle(0, 0, 50, 50, mEngine.getVertexBufferObjectManager()){

      /* Obtain the coordinates in the middle of the Scene that we will
       * convert to everytime the parent rectangle moves */
      final float convertToMidSceneX = WIDTH * 0.5f;
      final float convertToMidSceneY = HEIGHT * 0.5f;

      @Override
      protected void onManagedUpdate(float pSecondsElapsed) {

        /* Convert the specified x/y coordinates into Scene coordinates,
          * passing the resulting coordinates into the convertedCoordinates array */
        final float convertedCoordinates[] = rectangleLayer.convertSceneCoordinatesToLocalCoordinates(convertToMidSceneX, convertToMidSceneY);

        /* Since the parent is moving constantly, we must adjust this rectangle's
         * position on every update as well. This will keep in in the center of the 
         * display at all times */
        this.setPosition(convertedCoordinates[0], convertedCoordinates[1]);

        super.onManagedUpdate(pSecondsElapsed);
      }

    };

    /* Attach the second rectangle to the first rectangle */
    rectangleLayer.attachChild(rectangle);
    ```

## 它是如何工作的…

上面的`onCreateScene()`方法创建了一个包含两个独立`Rectangle`实体的`Scene`对象。第一个`Rectangle`实体将直接附加到`Scene`对象上。第二个`Rectangle`实体将附加到第一个`Rectangle`实体上。名为`rectangleLayer`的第一个`Rectangle`实体将会持续地从左向右和从右向左移动。通常，这会导致其子实体的位置跟随相同的移动模式，但在这个示例中，我们使用坐标转换，以允许子`Rectangle`实体在其父实体移动时保持静止。

在此示例中，`rectangle`对象包括两个名为`convertToMidSceneX`和`convertToMidSceneY`的变量。这些变量简单地保存了我们想要将局部坐标转换到的`Scene`坐标中的位置。正如我们所看到的，它们的坐标被定义在场景的中间。在`rectangle`对象的`onManagedUpdate()`方法中，我们然后使用`rectangleLayer.convertSceneCoordinatesToLocalCoordinates(convertToMidSceneX, convertToMidSceneY)`方法，将结果坐标传递给一个浮点数组。这样做的基本上是询问`rectangleLayer`对象：“在你看来，场景上的位置 x/y 在哪里？”由于`rectangleLayer`对象直接附加到`Scene`对象，它可以轻松地确定特定`Scene`坐标的位置，因为它依赖于原生的`Scene`坐标系统。

当尝试访问返回的坐标时，我们可以通过`convertedCoordinates[0]`获取转换后的 x 坐标，并使用`convertedCoordinates[1]`获取转换后的 y 坐标。

在将`Scene`坐标转换为局部`Entity`坐标的基础上，我们还可以将局部`Entity`坐标转换为`Scene`坐标、触摸事件坐标、摄像头坐标以及许多其他选项。然而，一旦我们从这个示例开始，对坐标转换有了基本的了解，其余的转换方法将看起来非常相似。

# 创建一个分屏游戏

本示例将介绍`DoubleSceneSplitScreenEngine`类，该类通常用于允许多个玩家在显示器的每一半上玩他们自己的游戏实例的游戏中。`DoubleSceneSplitScreenEngine`类使我们能够为设备的显示器的每一半提供自己的`Scene`和`Camera`对象，从而让我们完全控制显示器每一半将看到的内容。

## 开始使用…

请参考代码包中名为`SplitScreenExample`的类。

## 如何操作…

要使我们的游戏支持两个独立的`Scene`对象，我们需要在最初设置`BaseGameActivity`类时采取略有不同的方法。然而，一旦我们设置好了独立的`Scene`对象，管理它们实际上与只处理一个场景非常相似，除了每个场景只有原始显示空间的一半这一点。执行以下步骤以了解如何设置`DoubleSceneSplitScreenEngine`类。

1.  我们首先需要将`WIDTH`值减半，因为每个相机将需要设备显示的一半空间。试图将 800 像素的宽度适配到每个相机将导致每个场景上的对象出现明显的扭曲。在声明变量时，我们还将设置两个`Scene`对象和两个`Camera`对象，这些将用于`DoubleSceneSplitScreenEngine`的实现：

    ```kt
      public static final int WIDTH = 400;
      public static final int HEIGHT = 480;

    /* We'll need two Scene's for the DoubleSceneSplitScreenEngine */
      private Scene mSceneOne;
      private Scene mSceneTwo;

      /* We'll also need two Camera's for the DoubleSceneSplitScreenEngine */
      private SmoothCamera mCameraOne;
      private SmoothCamera mCameraTwo;
    ```

1.  然后，我们将在`BaseGameActivity`类的`onCreateEngineOptions()`方法中创建两个独立的`SmoothCamera`对象。这些相机将用于为显示的每一半提供独立的视图。在这个示例中，我们应用了自动缩放，以展示`DoubleSceneSplitScreenEngine`的结果：

    ```kt
    /* Create the first camera (Left half of the display) */
    mCameraOne = new SmoothCamera(0, 0, WIDTH, HEIGHT, 0, 0, 0.4f){
      /* During each update to the camera, we will determine whether
       * or not to set a new zoom factor for this camera */
      @Override
      public void onUpdate(float pSecondsElapsed) {
        final float currentZoomFactor = this.getZoomFactor();
        if(currentZoomFactor >= MAX_ZOOM_FACTOR){
          this.setZoomFactor(MIN_ZOOM_FACTOR);
        }
        else if(currentZoomFactor <= MIN_ZOOM_FACTOR){
          this.setZoomFactor(MAX_ZOOM_FACTOR);
        }
        super.onUpdate(pSecondsElapsed);
      }
    };
    /* Set the initial zoom factor for camera one*/
    mCameraOne.setZoomFactor(MAX_ZOOM_FACTOR);

    /* Create the second camera (Right half of the display) */
    mCameraTwo = new SmoothCamera(0, 0, WIDTH, HEIGHT, 0, 0, 1.2f){
      /* During each update to the camera, we will determine whether
       * or not to set a new zoom factor for this camera */
      @Override
      public void onUpdate(float pSecondsElapsed) {
        final float currentZoomFactor = this.getZoomFactor();
        if(currentZoomFactor >= MAX_ZOOM_FACTOR){
          this.setZoomFactor(MIN_ZOOM_FACTOR);
        }
        else if(currentZoomFactor <= MIN_ZOOM_FACTOR){
          this.setZoomFactor(MAX_ZOOM_FACTOR);
        }
        super.onUpdate(pSecondsElapsed);
      }
    };
    /* Set the initial zoom factor for camera two */
    mCameraTwo.setZoomFactor(MIN_ZOOM_FACTOR);
    ```

1.  在我们`BaseGameActivity`类的`onCreateEngineOptions()`方法中还需要处理一个任务，就是创建`EngineOptions`对象，将`mCameraOne`对象作为主相机传递。另外，场景可能需要同时处理触摸事件，因此我们也将启用多点触控：

    ```kt
    /* The first camera is set via the EngineOptions creation, as usual */
    EngineOptions engineOptions = new EngineOptions(true,
        ScreenOrientation.LANDSCAPE_FIXED, new FillResolutionPolicy(),
        mCameraOne);

    /* If users should be able to control each have of the display
     *  simultaneously with touch events, we'll need to enable 
     *  multi-touch in the engine options */
    engineOptions.getTouchOptions().setNeedsMultiTouch(true);
    ```

1.  在第四步中，我们将覆盖`BaseGameActivity`类的`onCreateEngine()`方法，以创建一个`DoubleSceneSplitScreenEngine`对象，而不是默认的`Engine`对象：

    ```kt
    @Override
    public Engine onCreateEngine(EngineOptions pEngineOptions) {

      /* Return the DoubleSceneSplitScreenEngine, passing the pEngineOptions
      * as well as the second camera object. Remember, the first camera has
      * already been applied to the engineOptions which in-turn applies the
      * camera to the engine. */
      return new DoubleSceneSplitScreenEngine(pEngineOptions, mCameraTwo);
    }
    ```

1.  接下来，在`onCreateScene()`方法中，我们将创建两个`Scene`对象，按照我们的选择设置它们，并最终将每个`Scene`对象设置到`DoubleSceneSplitScreenEngine`对象中：

    ```kt
    @Override
    public void onCreateScene(OnCreateSceneCallback pOnCreateSceneCallback) {

      /* Create and setup the first scene */
      mSceneOne = new Scene();
      mSceneOne.setBackground(new Background(0.5f, 0, 0));

      /* In order to keep our camera's and scenes organized, we can
       * set the Scene's user data to store its own camera */
      mSceneOne.setUserData(mCameraOne);

      /* Create and setup the second scene */
      mSceneTwo = new Scene();
      mSceneTwo.setBackground(new Background(0,0,0.5f));

      /* Same as the first Scene, we set the second scene's user data
       * to hold its own camera */
      mSceneTwo.setUserData(mCameraTwo);

      /* We must set the second scene within mEngine object manually.
       * This does NOT need to be done with the first scene as we will
       * be passing it to the onCreateSceneCallback, which passes it
       * to the Engine object for us at the end of onCreateScene()*/
      ((DoubleSceneSplitScreenEngine) mEngine).setSecondScene(mSceneTwo);

      /* Pass the first Scene to the engine */
      pOnCreateSceneCallback.onCreateSceneFinished(mSceneOne);
    }
    ```

1.  既然我们的两个`Camera`对象已经设置好了，两个`Scene`对象也已经设置好并附加到引擎上，我们可以开始根据需要将`Entity`对象附加到每个`Scene`对象上，只需像往常一样指定要附加到的`Scene`对象。这段代码应该放在`BaseGameActivity`类的`onPopulateScene()`方法中：

    ```kt
        /* Apply a rectangle to the center of the first scene */
        Rectangle rectangleOne = new Rectangle(WIDTH * 0.5f, HEIGHT * 0.5f, rectangleDimensions, rectangleDimensions, mEngine.getVertexBufferObjectManager());
        rectangleOne.setColor(org.andengine.util.adt.color.Color.BLUE);
        mSceneOne.attachChild(rectangleOne);

        /* Apply a rectangle to the center of the second scene */
        Rectangle rectangleTwo = new Rectangle(WIDTH * 0.5f, HEIGHT * 0.5f, rectangleDimensions, rectangleDimensions, mEngine.getVertexBufferObjectManager());
        rectangleTwo.setColor(org.andengine.util.adt.color.Color.RED);
        mSceneTwo.attachChild(rectangleTwo);
    ```

## 它的工作原理...

使用`DoubleSceneSplitScreenEngine`类时，如果我们要为多人游戏进行设置，可以假设我们的项目将需要两套所有的东西。更具体地说，我们需要为屏幕的每一半各设置两个`Scene`对象以及两个`Camera`对象。由于我们将每个`Camera`对象的观看区域一分为二，我们将把相机的`WIDTH`值减半。大多数情况下，400 像素宽和 480 像素高的相机尺寸是合理的，这使我们能够保持实体的适当透视。

在第二步中，我们设置了两个`SmoothCamera`对象，它们将自动对各自场景进行放大和缩小，以为此食谱提供视觉结果。然而，`DoubleSceneSplitScreenEngine`类可以使用任何`Camera`对象的变体，包括最基本类型而不会导致任何问题。

在第三步中，我们继续创建`EngineOptions`对象。我们提供了`mCameraOne`对象作为`EngineOptions`构造函数中的`pCamera`参数，就像我们在任何普通实例中所做的那样。此外，我们在`EngineOptions`对象中启用了多点触控，以允许同时为每个`Scene`对象注册触摸事件。忽略多点触控设置将导致每个场景必须等待另一个场景没有被按下时才能注册触摸事件。

在第四步中，我们创建了`DoubleSceneSplitScreenEngine`对象，传入上一步创建的`pEngineOptions`参数以及第二个`Camera`对象—`mCameraTwo`。在代码的这个阶段，我们已经将两个摄像头注册到引擎中；第一个是在`EngineOptions`对象中注册的，第二个作为参数传递给`DoubleSceneSplitScreenEngine`类。

第五步包括`BaseGameActivity`类的`onCreateScene()`方法，在这里我们将创建并设置两个`Scene`对象。在最基本的层面上，这涉及到创建`Scene`对象，启用并设置或禁用场景的背景，将场景的用户数据设置为存储其相应的摄像头，并最终将`Scene`对象传递给我们的`mEngine`对象。虽然第二个`Scene`对象需要我们调用`mEngine`对象的`setSecondScene(mSceneTwo)`方法，但`mSceneOne`对象是像在任何`BaseGameActivity`中一样传递给`Engine`对象的；在`pOnCreateSceneCallback.onCreateSceneFinished(mSceneOne)`方法中。

在第六步中，我们可以说已经“走出困境”。在这一点上，我们已经完成了引擎、场景和摄像头的设置，现在可以开始按照我们的喜好填充每个场景。在这一点上，我们可以做的事情的可能性非常广泛，包括将第二个场景用作小地图、多人游戏的视角、对第一个场景的另一种视角等等。此时，选择要附加`Entity`对象的`Scene`对象会非常简单，只需调用`mSceneOne.attachChild(pEntity)`或`mSceneTwo.attachChild(pEntity)`即可。


# 第五章：场景和图层管理

管理场景和图层对于使用菜单和多个游戏级别的游戏来说是一个必要条件。本章将介绍以下主题的场景管理器的创建和使用：

+   创建场景管理器

+   为场景资源设置资源管理器

+   定制管理的场景和图层

+   设置一个活动以使用场景管理器

# 简介

创建一个管理游戏菜单和场景的过程是提高框架速度的最快方法之一。一个设计良好的游戏通常依赖于强大且定制化的场景管理器来处理菜单和游戏内的关卡。定制场景管理器的方法有很多，但基础通常包括：

+   在场景之间切换

+   自动加载和卸载场景资源和元素

+   在处理场景资源和构建场景时显示加载屏幕

除了场景管理器的核心功能之外，我们还将创建一种在场景之上显示图层的方法，这样我们就可以为游戏添加另一层可用性。

# 创建场景管理器

创建一个仅替换引擎当前场景为另一个场景的场景管理器相当简单，但这种做法对玩家来说并不具有图形上的吸引力。在资源加载和场景构建时显示加载屏幕已经成为游戏设计中的一种广泛接受的做法，因为它让玩家知道游戏在进行的工作不仅仅只是闲置。

## 准备就绪...

打开本章代码包中的`SceneManager.java`类。同时，也请打开`ManagedScene.java`和`ManagedLayer.java`类。我们将在本食谱的讨论中引用这三个类。类内的内联注释提供了关于本食谱讨论内容的额外信息。

## 如何操作...

按照以下步骤了解`SceneManager`类的功能，以便我们可以为未来的项目创建一个定制版的场景管理器：

1.  首先，请注意`SceneManager`类是作为单例创建的，这样我们就可以从项目的任何地方访问它。此外，它使用我们的`ResourceManager`类提供的`getEngine()`引用来存储对引擎对象的本地引用，但如果我们选择不使用资源管理器，这个引用可以在创建`SceneManager`类时设置。

1.  其次，注意在`getInstance()`方法之后创建的变量。前两个变量`mCurrentScene`和`mNextScene`保存了对当前已加载场景和将要加载的场景的引用。`mEngine`变量保存了对引擎的引用。我们将使用这个引擎引用来设置我们的管理场景，以及注册/注销`mLoadingScreenHandler`更新处理器。整型变量`mNumFramesPassed`在更新处理器中计算已渲染的帧数，以确保加载屏幕至少显示了一帧。通过下一个变量`mLoadingScreenHandler`实现显示加载屏幕的功能，我们将在下一步中更详细地了解它。其余变量用于管理图层，并跟踪图层处理过程的状态或保存与图层处理过程相关的实体引用。

1.  第三，查看`mLoadingScreenHandler IUpdateHandler`更新处理器中的`onUpdate()`方法。请注意，这里有两个条件块——第一个在卸载上一个场景并随后加载下一个场景之前等待一帧，而第二个则等待直到下一个场景的加载屏幕至少显示最短时间之后，它才隐藏加载屏幕并重置更新处理器使用的变量。更新处理器中的整个这个过程使得在`ManagedScene`加载和构建自身时可以使用加载屏幕。

1.  类中的下一个方法是`showScene()`方法，当我们想要从当前场景导航到一个后续场景时，我们将调用它。它首先将引擎相机的位置和大小重置为其起始位置和大小，以防止之前的任何相机调整破坏新场景的展示。接下来，我们通过`ManagedScene`类的`hasLoadingScreen`属性检查新场景是否将显示加载屏幕。

    如果新的`ManagedScene`类将显示加载屏幕，我们将它的子场景设置为`onLoadingScreenLoadAndShown()`方法返回的场景，并暂停`ManagedScene`类的所有渲染、更新和触摸事件。下面的`if`块确保如果场景已经在加载阶段，可以加载新场景。这种情况应该很少见，但如果从 UI 线程调用显示新场景，则可能会发生。然后，将`mNextScene`变量设置为新的`ManagedScene`类，以供`mLoadingScreenHandler`更新处理器和引擎的场景使用。

    如果新的`ManagedScene`类不显示加载屏幕，我们将`mNextScene`变量设置为新的`ManagedScene`类，将新的`ManagedScene`类设置为引擎的场景，卸载之前显示的场景，并加载新场景。如果没有显示加载屏幕，`showScene()`方法仅用于将新场景替换为之前显示的场景。

1.  接下来，看看`showLayer()`方法。由于我们的层是在游戏中其他所有内容之上显示的，因此我们将它们作为相机`HUD`对象的子场景进行附加。该方法首先确定相机是否有`HUD`对象来附加子场景。如果有，它将`mCameraHadHud`布尔值设置为`true`。如果没有，我们将创建一个占位符 HUD 对象并将其设置为相机的`HUD`对象。接下来，如果`showLayer()`方法被调用以暂停底层`ManagedScene`的渲染、更新或触摸事件，我们将设置一个占位符场景作为`ManagedScene`场景的子场景，并传递给`showLayer()`方法的模态属性。最后，我们将层的相机设置为引擎的相机，缩放层以匹配相机的屏幕依赖性缩放，并将局部层相关变量设置为下一步引用的`hideLayer()`方法使用。

1.  `hideLayer()`方法首先检查当前是否有层正在显示。如果有，将清除相机`HUD`对象的子场景，从`ManagedScene`类中清除占位符子场景，并重置层显示系统。

按以下步骤了解`ManagedScene`和`ManagedLayer`类的构建方式：

1.  查看`ManagedScene`类，注意类开始部分列出的变量。`hasLoadingScreen`布尔值、`minLoadingScreenTime`浮点数和`elapsedLoadingScreenTime`浮点数变量由`SceneManager`类在处理`ManagedScene`类的加载屏幕时使用。`isLoaded`布尔值反映了`ManagedScene`类构建的完成状态。第一个构造函数是在不需要加载屏幕的情况下的便捷构造函数。第二个构造函数根据传递的值设置加载屏幕变量，这决定了加载屏幕应显示的最短时间。构造函数后面的公共方法由`SceneManager`类调用，并调用适当的抽象方法，这些方法列在类的底部。

1.  `ManagedLayer`类与`ManagedScene`类非常相似，但其固有的功能和缺少加载屏幕使其更容易创建。构造函数根据传递的`pUnloadOnHidden`布尔变量设置层在隐藏后是否应该卸载。构造函数后面的公共方法调用下面的适当抽象方法。

## 它的工作原理...

场景管理器存储对引擎当前场景的引用。当告诉场景管理器显示一个新场景时，它会先隐藏并卸载当前场景，然后将新场景设置为当前场景。然后，如果场景有的话，它会加载并显示新场景的加载屏幕。为了在加载场景其余部分之前显示加载屏幕，我们必须允许引擎渲染一帧。`mNumFramesPassed`整数值跟踪自过程开始以来发生的更新次数，也就是场景渲染次数。

在显示加载屏幕之后，或者如果不需要使用加载屏幕，场景管理器通过调用`onLoadManagedScene()`让场景自行加载。加载完成后，如果存在加载屏幕，并且已经显示至少一定时间，则隐藏加载屏幕并显示场景。如果加载屏幕没有显示足够的时间，我们会暂停场景的更新，这样场景就不会在加载屏幕隐藏之前开始。要了解更多关于这个场景管理器如何处理场景切换的信息，请参考`SceneManager.java`补充代码中的内联注释。

为了便于使用图层，场景管理器利用摄像头的 HUD 确保图层绘制在所有其他内容之上。如果摄像头已经有了 HUD，我们在应用图层之前先保存它，这样在图层隐藏后可以恢复原始的 HUD。此外，我们可以通过使用占位符场景来暂停底层场景的更新、渲染和触摸区域。占位符场景作为子场景附加到底层场景，因此我们必须保存底层场景已经附加的任何子场景。场景管理器通过同一方法调用来处理图层的加载和显示，让图层的子类确定是否需要重新加载，或者是否只需加载一次以减少性能负担重的加载。

## 另请参阅...

+   *在本章中自定义管理场景和图层*。

+   *在本章中设置一个活动以使用场景管理器*。

+   *在第四章中为摄像头应用 HUD*，*使用摄像头*。

# 为场景资源设置资源管理器。

为了便于菜单和游戏场景加载资源，必须首先设置资源管理器来处理这些资源。当我们调用资源管理器的`loadMenuResources()`或`loadGameResources()`方法时，它会自动加载相应的资源。同样，对于使用大量内存的菜单或游戏场景，卸载资源只需调用资源管理器的`unloadMenuResources()`、`unloadGameResources()`或`unloadSharedResources()`方法。

## 准备就绪...

打开本章代码包中的`ResourceManager.java`类，因为我们将参考它来完成这个配方。同时，也请查看该类的内联注释，以获取有关代码特定部分更多信息。

## 如何操作...

按照以下步骤了解`ResourceManager`类是如何被设置以与我们的管理场景一起使用的：

1.  注意`ResourceManager`类中定义的公共非静态变量。当加载纹理时，这个类会使用引擎和上下文变量，但它们也为我们提供了一种在整个项目中访问这些重要对象的方法。`cameraWidth`、`cameraHeight`、`cameraScaleFactorX`和`cameraScaleFactorY`变量在此类中未使用，但将在整个项目中用于相对于屏幕放置和缩放实体。

1.  找到`setup()`方法。这个方法会设置前一步中引用的非静态变量，并在我们的活动类中覆盖的`onCreateResources()`方法中被调用。重要的是，在调用`ResourceManager`类的任何其他方法之前先调用`setup()`，因为其他每个方法和变量都依赖于引擎和上下文变量。

1.  接下来，看看静态资源变量。这些变量将由我们的场景用于实体或声音，并且必须在调用之前设置。还要注意，带有游戏或菜单前缀的静态变量将分别由我们的游戏或菜单场景使用，而没有前缀的静态变量将在两种类型之间共享。

1.  现在找到`loadGameResources()`和`loadMenuResources()`方法。当我们的管理游戏和菜单场景首次启动时，将调用这些方法。这些方法的重要职责是调用后续的`ResourceManager`方法，这些方法设置前一步中引用的静态变量。相反，`unloadGameResources()`和`unloadMenuResources()`卸载其各自场景的资源，并且当应用程序流程完成资源使用后应调用它们。

## 工作原理...

在最基本的层面上，资源管理器提供了加载和卸载资源的手段。除此之外，我们定义了一系列变量，包括引擎和上下文对象，这让我们在创建场景中的实体时能够轻松访问游戏的某些常见元素。这些变量也可以放在游戏管理器或对象工厂中，但由于大多数对资源管理器的调用都接近于创建实体的代码，因此我们将其包含在资源管理器中。

## 另请参阅...

+   在第一章，*AndEngine 游戏结构*中*创建资源管理器*。

+   在第一章，*AndEngine 游戏结构*中*创建游戏管理器*。

+   在第一章，*AndEngine 游戏结构*中*创建对象工厂*。

# 定制管理场景和图层

场景管理器的主要目的是处理我们游戏中的管理场景。这些管理场景是高度可定制的，但我们希望尽可能避免重写我们的代码。为了完成这项任务，我们将使用两个扩展了 `ManagedScene` 类的类，`ManagedGameScene` 和 `ManagedMenuScene`。通过这种方式构建我们的场景类，我们将拥有共享通用基础的菜单和游戏场景。

## 准备就绪...

打开本章代码包中的以下类：`ManagedMenuScene.java`、`ManagedGameScene.java`、`MainMenu.java`、`GameLevel.java` 和 `OptionsLayer.java`。我们将在本食谱中多次引用这些类。

## 如何操作...

按照以下步骤了解 `ManagedMenuScene` 和 `ManagedGameScene` 类是如何基于 `ManagedScene` 类构建的，以创建可定制的、可扩展的场景，并将其传递给 `SceneManager` 类：

1.  查看 `ManagedMenuScene` 类。它只包含两个简单的构造函数和一个重写的 `onUnloadManagedScene()` 方法。重写的方法防止了 `isLoaded` 布尔值被设置，因为我们将不会利用场景管理器的自动卸载菜单场景功能。

1.  现在，我们将注意力转向 `ManagedGameScene` 类。这个类首先创建了一个游戏内 `HUD` 对象、一个加载屏幕 `Text` 对象以及一个加载屏幕 `Scene` 对象。`ManagedGameScene` 类的主构造函数首先将场景的触摸事件绑定设置设为真。接下来，设置场景的缩放以镜像摄像机的屏幕依赖性缩放，并将场景的位置设为摄像机的底部中心。最后，构造函数设置 HUD 的缩放以匹配摄像机的缩放。

    `ManagedGameScene` 类重写了 `ManagedScene` 类的 `onLoadingScreenLoadAndShown()` 和 `onLoadingScreenUnloadAndHidden()` 方法，以显示和隐藏一个简单的加载屏幕，该屏幕显示一个单一的 `Text` 对象。

    `ManagedScene` 类的 `onLoadScene()` 方法被重写，以构建一个表示游戏内部分的场景，该场景包含一个背景和两个按钮，允许玩家返回 `MainMenu` 或显示 `OptionsLayer`。

按照以下步骤了解如何扩展 `ManagedMenuScene` 和 `ManagedGameScene` 类以创建 `MainMenu` 和 `GameLevel` 场景：

1.  `MainMenu`类被设计为单例模式，以防止创建类的多个实例从而占用宝贵的内存空间。同时，它省略了加载屏幕，因为它几乎是瞬间加载和创建的。构成`MainMenu`类的所有实体都被定义为类级别变量，包括背景、按钮、文本和移动的实体。`MainMenu`类从`ManagedScene`类继承的场景流程方法有`onLoadScene()`、`onShowScene()`、`onHideScene()`和`onUnloadScene()`，其中只有`onLoadScene()`方法包含代码。`onLoadScene()`方法加载并构建了一个场景，包括一个背景、20 个水平移动的云朵、一个标题和两个按钮。注意，每个按钮都会调用场景管理器——播放按钮显示`GameLevel`场景，选项按钮显示`OptionsLayer`。

1.  `GameLevel`类扩展了`ManagedGameScene`类，并只覆盖了`onLoadScene()`方法，在场景中创建并随机定位一个正方形矩形。这表明`ManagedGameScene`类构成了`GameLevel`类的大部分内容，而且不同级别之间的元素仍然可以使用由`ManagedGameScene`类创建的相同基础。

按照以下步骤了解`OptionsLayer`类是如何扩展`ManagedLayer`类的层功能的：

1.  关于`OptionsLayer`类，首先注意它被定义为单例，这样在首次创建后它将保留在内存中。接下来，注意两个更新处理器`SlideIn`和`SlideOut`。这些处理器在显示或隐藏层时为层添加动画效果，并为游戏提供额外的图形兴趣层。更新处理器只是简单地将层移动到`onUpdate()`方法的`pSecondsElapsed`参数成比例的特定位置，以使移动平滑。

1.  从`ManagedLayer`类继承的`onLoadLayer()`方法被覆盖，以创建一个作为层背景的黑色矩形和两个显示标题和退出层方式的`Text`对象。`onShowLayer()`和`onHideLayer()`方法向引擎注册适当的更新处理器。当层滑出屏幕时，注意`SlideOut`更新处理器调用场景管理器隐藏层——这就是使用这个特定场景管理器的框架实现结束动画的方式。

## 它是如何工作的...

`ManagedMenuScene`类的唯一目的是覆盖从`ManagedScene`类继承的`onUnloadManagedScene()`方法，以防止场景内实体的重新创建。注意在扩展`ManagedMenuScene`的`MainMenu`类中覆盖的`onUnloadScene()`方法，我们将其留空以确保`MainMenu`类保留在内存中，这样我们可以从游戏场景和其他菜单快速切换回它。

### 注意

在运行此项目时，如果主菜单中有任何动画，请注意，当另一个场景正在显示时，动画会暂停，但一旦主菜单再次显示，动画就会恢复。这是因为尽管主菜单仍然加载在内存中，但它不会作为引擎的当前场景进行更新。

`ManagedGameScene`类使用一个`HUD`对象，允许游戏关卡拥有一组与引擎摄像机一起移动的控件。尽管在这个例子中我们将按钮添加到`GameHud`对象，但 HUD 上可以使用任何控件。我们为`ManagedGameScene`类使用的构造函数设置了加载屏幕的持续时间、触摸选项以及游戏场景和`GameHud`的比例，以提升游戏在不同设备上的视觉吸引力。对于游戏场景，我们利用场景管理器启用的加载屏幕。对于加载屏幕，我们创建了一个简单的场景，显示文本**Loading...**，但可以使用任何非动画实体的排列。当显示加载屏幕时，我们加载游戏资源并创建游戏场景。在这种情况下，一个简单的背景由单个精灵构建，屏幕上的控件被添加到`GameHud`对象。请注意，添加到`GameHud`对象的控件会被缩放到摄像机比例因子的倒数。这是必要的，因为我们要使它们在所有设备上具有相同的物理尺寸。在`ManagedGameScene`类中定义的最后一个方法是`onUnloadScene()`，用于卸载场景。

### 备注

注意，我们所有的卸载操作都是在更新线程中完成的。这样做可以防止引擎尝试处理在当前线程中早已移除的实体，并防止抛出`ArrayIndexOutOfBoundsException`异常。

对于主菜单，我们不需要加载屏幕，因此在`onLoadingScreenLoadAndShown()`方法中直接返回`null`。在为主菜单创建简单的精灵背景时，我们必须将其缩放以填满屏幕。注意主菜单在创建精灵和按钮时是如何使用`ResourceManager`类中的菜单资源的。同样，注意点击按钮时，我们会调用`SceneManager`类来加载下一个场景或显示一个图层。以下两张截图展示了主菜单在两个不同设备上的显示效果，以演示摄像机缩放如何与场景组合一起工作。第一张截图是在 10.1 英寸的摩托罗拉 Xoom 上：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_05_01.jpg)

第二张是在 5.3 英寸的三星 Galaxy Note 上：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_05_02.jpg)

我们的`GameLevel`类与其超类`ManagedGameScene`相比相对较小，这是因为我们希望每个关卡只包含各自所需的信息。以下屏幕截图展示了`GameLevel`类在实际中的使用情况：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_05_03.jpg)

`OptionsLayer`类可以从任何场景中显示，如下两张截图所示。第一张是在主菜单上：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_05_04.jpg)

当第二个游戏级别加载了`GameLevel`类时：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_05_05.jpg)

## 另请参阅...

+   在本章中*创建场景管理器*。

+   在第四章，*使用相机工作*中*连接控制器到显示*。

# 设置活动以使用场景管理器

由于我们的场景管理器的工作方式，将其实例化以供扩展了 AndEngine 的`BaseGameActivity`类的`Activity`类使用需要很少的努力。我们还将实现一个精确的屏幕分辨率缩放方法，以确保所有设备上的外观一致性。`SceneManager`类和`ManagedScenes`类依赖在`ResourceManager`类中定义的变量来注册更新处理程序和创建实体。在查看这个指南时，请注意我们在使用`SceneManager`类的任何功能之前设置`ResourceManager`类。

## 准备工作...

创建一个扩展了 AndEngine 的`BaseGameActivity`类的新活动，或者加载你已经创建的一个。将现有活动适配为使用场景管理器需要与新建活动相同的步骤，因此不必担心重新开始一个项目以实现场景管理器。

## 如何操作...

按以下步骤准备一个活动以使用我们的场景管理器：

1.  在你的活动中定义以下变量以处理精确的屏幕分辨率缩放。这样做可以使屏幕元素在所有安卓设备上几乎物理上一致：

    ```kt
    static float DESIGN_SCREEN_WIDTH_PIXELS = 800f;
    static float DESIGN_SCREEN_HEIGHT_PIXELS = 480f;
    static float DESIGN_SCREEN_WIDTH_INCHES = 4.472441f;
    static float DESIGN_SCREEN_HEIGHT_INCHES = 2.805118f;
    static float MIN_WIDTH_PIXELS = 320f, MIN_HEIGHT_PIXELS = 240f;
    static float MAX_WIDTH_PIXELS = 1600f, MAX_HEIGHT_PIXELS = 960f;
    public float cameraWidth;
    public float cameraHeight;
    public float actualScreenWidthInches;
    public float actualScreenHeightInches;
    ```

1.  在活动类的相应位置添加以下方法来处理**返回**按钮：

    ```kt
    public boolean onKeyDown(final int keyCode, final KeyEvent event) 
    {
      if (keyCode == KeyEvent.KEYCODE_BACK
        && event.getAction() == KeyEvent.ACTION_DOWN) {
        if(ResourceManager.getInstance().engine!=null){
          if(SceneManager.getInstance().isLayerShown)
            SceneManager.getInstance().
              currentLayer.onHideLayer();
          else if( SceneManager.getInstance().
              mCurrentScene.getClass().
              getGenericSuperclass().
              equals(ManagedGameScene.class) || 
              (SceneManager.getInstance().
              mCurrentScene.getClass().
              getGenericSuperclass().
              equals(ManagedMenuScene.class) &!
              SceneManager.getInstance().
              mCurrentScene.getClass().
              equals(MainMenu.class)))
              SceneManager.getInstance().
              showMainMenu();
          else
            System.exit(0);
        }
        return true;
      } else {
        return super.onKeyDown(keyCode, event);
      }
    }
    ```

1.  接下来，用以下代码填充`onCreateEngineOptions()`方法：

    ```kt
    actualScreenWidthInches = getResources().
      getDisplayMetrics().widthPixels /
      getResources().getDisplayMetrics().xdpi;
    actualScreenHeightInches = getResources().
      getDisplayMetrics().heightPixels / 
      getResources().getDisplayMetrics().ydpi;
    cameraWidth = Math.round(
      Math.max(
        Math.min(
          DESIGN_SCREEN_WIDTH_PIXELS * 
          (actualScreenWidthInches / 
            DESIGN_SCREEN_WIDTH_INCHES),
        MAX_WIDTH_PIXELS),
      MIN_WIDTH_PIXELS));
    cameraHeight = Math.round(
      Math.max(
        Math.min(
          DESIGN_SCREEN_HEIGHT_PIXELS * 
          (actualScreenHeightInches /
            DESIGN_SCREEN_HEIGHT_INCHES),
        MAX_HEIGHT_PIXELS),
      MIN_HEIGHT_PIXELS));
    EngineOptions engineOptions = new EngineOptions(true,
      ScreenOrientation.LANDSCAPE_SENSOR,
      new FillResolutionPolicy(), 
      new Camera(0, 0, cameraWidth, cameraHeight));
    engineOptions.getAudioOptions().setNeedsSound(true);
    engineOptions.getAudioOptions().setNeedsMusic(true);
    engineOptions.getRenderOptions().setDithering(true);
    engineOptions.getRenderOptions().
      getConfigChooserOptions().setRequestedMultiSampling(true);
    engineOptions.setWakeLockOptions(WakeLockOptions.SCREEN_ON);
    return engineOptions;
    ```

1.  在`onCreateResources()`方法中放置以下行：

    ```kt
    ResourceManager.getInstance().setup(this.getEngine(),
      this.getApplicationContext(),
      cameraWidth, cameraHeight,
      cameraWidth/DESIGN_SCREEN_WIDTH_PIXELS,
      cameraHeight/DESIGN_SCREEN_HEIGHT_PIXELS);
    ```

1.  最后，在`onCreateScene()`方法中添加以下代码：

    ```kt
    SceneManager.getInstance().showMainMenu();
    pOnCreateSceneCallback.onCreateSceneFinished(
      MainMenu.getInstance());
    ```

## 工作原理...

我们首先定义开发设备屏幕的属性，以便我们可以进行计算，确保所有玩家尽可能接近我们看待游戏的方式。实际上，计算是在第三步中展示的`onCreateEngineOptions()`方法中处理的。对于引擎选项，我们启用了声音、音乐、平滑渐变的抖动处理、平滑边缘的多重采样以及防止玩家短暂切换到其他应用时游戏资源被销毁的唤醒锁定。

在第 4 步中，我们通过传递`Engine`对象、`Context`、当前相机宽度和高度以及当前相机尺寸与设计设备屏幕尺寸的比例来设置`ResourceManager`类。最后，我们告诉`SceneManager`类显示主菜单，并通过`pOnCreateSceneCallback`参数将`MainMenu`类作为引擎的场景传递。

## 另请参阅...

+   在本章中*创建场景管理器*。

+   在第一章，*AndEngine 游戏结构*中了解*生命周期*。
