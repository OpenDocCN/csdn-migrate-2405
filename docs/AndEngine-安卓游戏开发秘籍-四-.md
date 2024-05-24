# AndEngine 安卓游戏开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A`](https://zh.annas-archive.org/md5/DC9ACC22F79E7DA8DE93ED0AD588BA9A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：最大化的性能

在本章中，我们将介绍一些提高 AndEngine 应用程序性能的最佳实践。包括以下主题：

+   忽略实体更新

+   禁用背景窗口渲染

+   限制同时播放的音轨数量

+   创建精灵池

+   使用精灵组减少渲染时间

+   禁用实体剔除的渲染

# 引言

游戏优化在 Google Play 上游戏成功中起着关键作用。如果游戏在用户设备上运行不佳，用户很可能会给出负面评价。不幸的是，由于存在许多不同的设备，而且无法在 Google Play 上有效地大规模限制低端设备，因此最好尽可能优化 Android 游戏。忽略评分，可以公平地说，如果游戏在中端设备上的表现不佳，那么在下载和活跃用户方面将无法达到其全部潜力。本章将介绍一些与 AndEngine 性能问题相关的最有帮助的解决方案。这将帮助我们提高中低端设备的性能，无需牺牲质量。

### 注意

尽管本章中的方法可以大幅提高我们游戏的性能，但重要的是要记住，清晰高效的代码同样重要。游戏开发是一项非常注重性能的任务，与所有语言一样，有许多小事要做或避免。网上有许多资源涵盖了关于 Java 通用实践以及 Android 特定技巧的好坏话题。

# 忽略实体更新

在优化游戏方面，游戏开发最重要的规则之一是，*不要做不需要做的工作！*。在本节中，我们将讨论如何使用`setIgnoreUpdate()`方法在我们的实体上，以限制更新线程只更新应该更新的内容，而不是不断更新所有实体，不管我们是否使用它们。

## 如何操作…

以下`setIgnoreUpdate(boolean)`方法允许我们控制哪些实体将通过引擎的更新线程进行更新：

```kt
Entity entity = new Entity();

// Ignore updates for this entity
entity.setIgnoreUpdate(true);

// Allow this entity to continue updating
entity.setIgnoreUpdate(false);
```

## 工作原理…

如前几章所述，每个子对象的`onUpdate()`方法都是通过其父对象调用的。引擎首先更新，调用主`Scene`对象的更新方法。然后场景继续调用其所有子对象的更新方法。接下来，场景的子对象将分别调用其子对象的更新方法，依此类推。考虑到这一点，通过在主 Scene 对象上调用`setIgnoreUpdate()`，我们可以有效地忽略场景上所有实体的更新。

忽略未使用实体的更新，或者除非发生特定事件否则不做出反应的实体，可以节省大量的 CPU 时间。这对于包含大量实体的场景尤为如此。这可能看起来工作量不大，但请记住，对于每个带有实体修改器或更新处理器的实体，这些对象也必须更新。除此之外，每个实体的子实体也会因为父/子层次结构而继续更新。

最佳实践是为所有屏幕外的或不需要持续更新的实体设置`setIgnoreUpdate(true)`。对于可能根本不需要任何更新的精灵，比如场景的背景精灵，我们可以无限期地忽略更新，而不会造成任何问题。在实体需要更新，但不是非常频繁的情况下，例如从炮塔发射的子弹，我们可以在子弹从炮塔飞向目标的过程中启用更新，在不再需要时禁用它。

## 另请参阅

+   第二章中的*了解 AndEngine 实体*部分，*使用实体*

# 禁用后台窗口渲染

在大多数游戏中，开发者通常更倾向于使用全屏模式。虽然从视觉上看我们并没有发现明显的差异，但安卓操作系统并不会识别哪些应用程序是在全屏模式下运行的。这意味着除非在`AndroidManifest.xml`中另外指定，否则后台窗口将继续在我们的应用程序下方绘制。在本主题中，我们将介绍如何禁用后台渲染以提高应用程序的帧率，这主要有利于低端设备。

## 准备工作...

为了停止后台窗口的渲染，我们首先需要为应用程序创建一个主题。我们将在项目的`res/values/`文件夹中添加一个名为`theme.xml`的新 xml 文件来实现这一点。

用以下代码覆盖默认 xml 文件中的所有内容，并保存文件：

```kt
<?xml version="1.0" encoding="UTF-8"?>
<resources>
    <style name="Theme.NoBackground" parent="android:Theme">
        <item name="android:windowBackground">@null</item>
    </style>
</resources>
```

## 如何操作...

创建并填写完`theme.xml`文件后，我们可以在项目的`AndroidManifest.xml`文件中，将主题应用于我们的应用程序标签，从而禁用后台窗口渲染。应用程序标签的属性可能看起来类似于这样：

```kt
<application
        android:theme="@style/Theme.NoBackground"
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name" 
        >
```

请注意，我们也可以将主题应用于特定的活动，而不是在整个应用程序范围内应用，只需在各个活动标签中添加`android:theme="@style/Theme.NoBackground"`代码即可。这对于需要同时使用 AndEngine 视图和原生安卓视图的混合游戏来说最为相关，这些视图跨越了多个活动。

## 工作原理...

禁用背景窗口渲染是一个简单的任务，主要在旧设备上可以提供一些百分比的性能提升。负责背景窗口的主要代码在`theme.xml`文件中找到。通过将`android:windowBackground`项设置为 null，我们通知设备，我们希望完全移除背景窗口的渲染，而不是绘制它。

# 限制同时播放的音轨数量

在 AndEngine 中，声音播放通常不会成为游戏性能的问题。然而，在某些情况下，大量声音可能在非常短的时间内播放，这可能会在旧设备上有时甚至在新设备上造成明显的延迟，这取决于同时播放的声音数量。默认情况下，AndEngine 允许同一`Sound`对象在任何给定时间同时播放五个音轨。在本主题中，我们将通过操作`EngineOptions`来更改同时播放的音轨数量，以更好地满足我们应用程序的需求。

## 如何操作...

为了增加或减少每个`Sound`对象的同时播放音轨数量，我们必须在活动的`onCreateEngineOptions()`方法中对`EngineOptions`进行简单的调整：

```kt
@Override
public EngineOptions onCreateEngineOptions() {
  mCamera = new Camera(0, 0, 800, 480);

  EngineOptions engineOptions = new EngineOptions(true,
                ScreenOrientation.LANDSCAPE_FIXED, new 
                FillResolutionPolicy(),mCamera);

  engineOptions.getAudioOptions().setNeedsSound(true);
  engineOptions.getAudioOptions().getSoundOptions().setMaxSimultaneousStreams(2);

  return engineOptions;
}
```

## 工作原理…

默认情况下，`Engine`对象的`AudioOptions`设置为每个`Sound`对象允许同时播放五个音轨。在大多数情况下，这对于不重度依赖声音播放的应用程序来说，不会造成明显的性能损失。另一方面，倾向于在碰撞或施加力时产生声音的游戏可能会同时播放大量音轨，特别是在任何给定时间场景中有超过 100 个精灵的游戏中。

限制同时播放的音轨数量是一个容易完成的任务。只需在我们的`EngineOptions`上调用`getAudioOptions().getSoundOptions().setMaxSimultaneousStreams(n)`，其中`n`是每个`Sound`对象的最大音轨数量，我们就可以减少在游戏过程中不适宜的时候播放的不必要声音。

## 另请参阅

+   第一章中的*引入声音和音乐*部分，*AndEngine 游戏结构*

# 创建精灵池

`GenericPool`类在考虑到移动平台在硬件资源上的限制时，是 AndEngine 游戏设计中极其重要的部分。在 Android 游戏开发中，要实现长时间游戏体验的流畅，关键在于尽可能少地创建对象。这并不意味着我们应该将屏幕上的对象限制在四个或五个，而是应该考虑回收已经创建的对象。这时对象池就派上用场了。

## 开始操作…

请参考代码包中名为`SpritePool`的类。

## 如何操作…

`GenericPool`类使用了一些有用的方法，使得回收对象以供后续使用变得非常简单。我们将在这里介绍主要使用的方法。

构造`SpritePool`类：

```kt
public SpritePool(ITextureRegion pTextureRegion, VertexBufferObjectManager pVertexBufferObjectManager){
  this.mTextureRegion = pTextureRegion;
  this.mVertexBufferObjectManager = pVertexBufferObjectManager;
}
```

1.  分配池项目：

    ```kt
    @Override
    protected Sprite onAllocatePoolItem() {
      return new Sprite(0, 0, this.mTextureRegion, this.mVertexBufferObjectManager);
    }
    ```

1.  获取池项目：

    ```kt
    public synchronized Sprite obtainPoolItem(final float pX, final float pY) {
      Sprite sprite = super.obtainPoolItem();

      sprite.setPosition(pX, pY);
      sprite.setVisible(true);
      sprite.setIgnoreUpdate(false);  
      sprite.setColor(1,1,1);

      return sprite;
    }
    ```

1.  回收池项目：

    ```kt
    @Override
    protected void onHandleRecycleItem(Sprite pItem) {
      super.onHandleRecycleItem(pItem);

      pItem.setVisible(false);
      pItem.setIgnoreUpdate(true);
      pItem.clearEntityModifiers();
      pItem.clearUpdateHandlers();
    }
    ```

## 工作原理...

`GenericPool`类的理念非常简单。当我们需要对象时，不是创建新对象并在用完后丢弃它们，而是可以告诉池分配有限数量的对象并存储起来以供后续使用。我们现在可以从池中调用`obtainPoolItem()`方法，以获取存储分配的对象之一，在我们的关卡中使用，例如作为敌人。一旦这个敌人被玩家摧毁，我们现在可以调用`recyclePoolItem(pItem)`将这个敌人对象送回池中。这使我们能够避免垃圾收集的调用，并有可能大大减少新对象所需的内存。

在*如何操作...*部分中的四种方法，对于使用普通池来说已经足够。显然，我们必须在使用之前创建池。然后，以下三种方法定义了对象分配、获取对象使用以及对象回收时会发生什么，或者在我们用完后将其送回池中存储，直到我们需要新对象。尽管对象池不仅仅用于精灵对象的回收，但我们会更深入地了解每个方法的用途、工作原理以及原因，从构造函数开始。

在第一步中，我们必须传递给池对象构造函数所需的任何对象。在这种情况下，我们需要获取`TextureRegion`和`VertexBufferObjectManager`以创建 Sprite 对象。这并不是什么新知识，但请记住，`GenericPool`类不仅限于创建精灵的池。我们可以为任何类型的对象或数据类型创建池。关键是要使用池的构造函数作为获取传递给池对象分配所需参数的方法。

在第二步中，我们覆盖了`onAllocatePoolItem()`方法。当池需要分配新对象时，它将调用此方法。两种情况是：池最初没有对象，或者所有回收的对象都已获取并在使用中。我们在这个方法中需要处理的是返回对象的新实例。

第三步涉及到使用`obtain`方法从对象池中获取一个对象，以便在我们的游戏中使用。我们可以看到，在这种情况下，`obtainPoolItem()`方法要求我们传入`pX`和`pY`参数，这些参数将被精灵的`setPosition(pX, pY)`方法使用，以重新定位精灵。然后我们将精灵的`visibility`设置为`true`，允许更新精灵，以及将颜色设置回初始值白色。在任何情况下，此方法应用于将对象的值重置为默认状态，或者定义对象必要的*新*属性。在代码中，我们可能会像以下代码片段所示从对象池中获取一个新的精灵：

```kt
// obtain a sprite and attach it to the scene at position (10, 10)
Sprite sprite = pool.obtainPoolItem(10, 10);
mScene.attachChild(sprite);
```

在最后的方法中，我们将从`GenericPool`类中使用`recyclePoolItem(pItem)`方法，其中`pItem`是要回收回对象池中的对象。此方法应处理与禁用游戏内使用的对象相关的所有方面。对于精灵来说，为了在精灵存储在池中时提高性能，我们将可见性设置为 false，忽略对精灵的更新，清除任何实体修饰符和更新处理器，这样在我们获取新精灵时它们就不会仍在运行。

### 注意

即使不使用对象池，也可以考虑在不再需要的`Entity`上使用`setVisible(false)`和`setIgnoreUpdate(true)`。不断附加和分离`Entity`对象可能会给垃圾收集器运行提供机会，并可能在游戏过程中引起帧率的明显卡顿。

## 还有更多…

创建对象池以处理对象回收对于减少性能卡顿非常重要，但是当游戏首次初始化时，池中不会有任何可用的对象。这意味着，根据池需要在整个关卡中分配以满足最大对象数的对象数量，玩家可能会在游戏的前几分钟内注意到帧率的突然中断。为了避免此类问题，最好在关卡加载时预分配池对象，以避免在游戏过程中创建对象。

为了在加载期间分配大量池对象，我们可以对任何扩展`GenericPool`的类调用`batchAllocatePoolItems(pCount)`，其中`pCount`是我们希望分配的项数。请记住，加载比我们需要的更多的物品是资源的浪费，但如果分配的物品不足，也可能会引起帧率卡顿。例如，为了确定我们的游戏中应分配多少敌方对象，我们可以制定一个公式，比如默认敌方数量乘以关卡难度。然而，所有游戏都是不同的，因此所需的对象创建公式也将不同。

## 另请参阅

+   第二章中关于*使用精灵为场景注入生命*的部分

# 使用精灵组减少渲染时间

精灵组是任何需要在任何时刻处理场景上数百个可见精灵的 AndEngine 游戏的一个很好的补充。`SpriteGroup`类允许我们将许多精灵渲染调用分组到有限的 OpenGL 调用中，从而消除大量开销。如果一个校车只接一个孩子，把他们送到学校，然后再接下一个孩子，直到所有的孩子都到学校，这个过程完成所需的时间会更长。使用 OpenGL 绘制精灵也是同样的道理。

## 开始操作…

请参考代码包中名为`ApplyingSpriteGroups`的类。这个示例需要一个名为`marble.png`的图像，该图像的宽度为 32 像素，高度为 32 像素。

## 如何操作…

当在我们的游戏中创建一个`SpriteGroup`时，我们可以将它们视为专门用于`Sprite`对象的`Entity`层。以下步骤说明如何创建并将`Sprite`对象附加到`SpriteGroup`。

1.  创建一个精灵组可以使用以下代码实现：

    ```kt
      // Create a new sprite group with a maximum sprite capacity of 500
      mSpriteGroup = new SpriteGroup(0, 0, mBitmapTextureAtlas, 500,     mEngine.getVertexBufferObjectManager());

      // Attach the sprite group to the scene
      mScene.attachChild(mSpriteGroup);
    ```

1.  将精灵附加到精灵组同样是一个简单的任务：

    ```kt
      // Create new sprite
      Sprite sprite = new Sprite(tempX, tempY, spriteWidth, spriteHeight, mTextureRegion, mEngine.getVertexBufferObjectManager());

      // Attach our sprite to the sprite group
      mSpriteGroup.attachChild(sprite);
    ```

## 工作原理…

在这个示例中，我们设置了一个场景，将大约 375 个精灵应用到我们的场景中，所有这些都是通过使用`mSpriteGroup`对象绘制的。一旦创建了精灵组，我们基本上可以将其视为一个普通实体层，根据需要附加精灵。

+   在我们活动的`onCreateResources(`方法中为我们的精灵创建一个`BuildableBitmapTextureAtlas`：

    ```kt
    // Create texture atlas
    mBitmapTextureAtlas = new BuildableBitmapTextureAtlas(mEngine.getTextureManager(), 32, 32, TextureOptions.BILINEAR);

    // Create texture region
    mTextureRegion = BitmapTextureAtlasTextureRegionFactory.createFromAsset(mBitmapTextureAtlas, getAssets(), "marble.png");

    // Build/load texture atlas
    mBitmapTextureAtlas.build(new BlackPawnTextureAtlasBuilder<IBitmapTextureAtlasSource, BitmapTextureAtlas>(0, 0, 0));
    mBitmapTextureAtlas.load();
    ```

    创建用于`SpriteGroup`中的纹理可以像处理普通 Sprite 一样处理。

+   构造我们的`mSpriteGroup`对象并将其应用到场景中：

    ```kt
    // Create a new sprite group with a maximum sprite capacity of 500
    mSpriteGroup = new SpriteGroup(0, 0, mBitmapTextureAtlas, 500, mEngine.getVertexBufferObjectManager());

    // Attach the sprite group to the scene
    mScene.attachChild(mSpriteGroup);
    ```

    `SpriteGroup`需要两个我们尚未处理的新参数。`SpriteGroup`是`Entity`的一个子类型，因此我们知道前两个参数是用于定位`SpriteGroup`的 x 和 y 坐标。第三个参数，我们传递了一个`BitmapTextureAtlas`。*精灵组只能包含与精灵组共享相同纹理图的精灵！*第四个参数是`SpriteGroup`能够绘制的最大容量。如果容量是 400，那么我们可以将最多 400 个精灵应用到`SpriteGroup`。将容量限制为我们希望绘制的最大精灵数非常重要。*超出限制将导致应用程序强制关闭*。

+   最后一步是将精灵应用到精灵组。

在这个示例中，我们设置了一个循环，以便将精灵应用到屏幕上的各个位置。然而，在这里我们真正关心的是以下用于创建`Sprite`并将其附加到`SpriteGroup`的代码：

```kt
Sprite sprite = new Sprite(tempX, tempY, spriteWidth, spriteHeight, mTextureRegion, mEngine.getVertexBufferObjectManager());

// Attach our sprite to the sprite group
mSpriteGroup.attachChild(sprite);
```

我们可以像创建任何其他精灵一样创建我们的精灵。我们可以像平常一样设置位置、缩放和纹理区域。现在要做好准备迎接棘手的部分！我们必须调用`mSpriteGroup.attachChild(sprite)`，以允许`mSpriteGroup`对象处理精灵对象的绘制。这就完成了！

按照这些步骤，我们可以在性能下降之前成功让我们的精灵组在屏幕上绘制许多精灵。与使用单独缓冲区单独绘制精灵相比，差异是巨大的。在许多情况下，用户声称在使用包含大量实体同时出现在场景中的游戏时，可以实现高达 50%的性能提升。

## 还有更多…

现在还不是将所有项目转换为使用精灵组的时候！使用精灵组的好处不言而喻，但这并不意味着没有负面影响。`SpriteGroup`类并不直接得到 OpenGL 的支持。这个类或多或少是一个'hack'，它让我们在额外的渲染调用中节省一些时间。在更复杂的项目中设置精灵组可能会因为'副作用'而变得麻烦。

在多次附着和分离利用了 alpha 修饰符和修改了可见性的许多精灵后，有时会出现一些情况，导致精灵组中的某些精灵出现'闪烁'。在越来越多的精灵被附着和分离，或者多次设置为不可见/可见之后，这种结果最为明显。有一种方法可以绕过这个问题，而且不会过多影响性能，即移动精灵使其离开屏幕，而不是从图层中分离它们或设置为不可见。然而，对于只利用一个活动并且根据当前关卡切换场景的大型游戏来说，将精灵移出屏幕可能会带来未来的问题。

在决定使用精灵组之前，要考虑这一点并明智地计划。在将精灵组整合到游戏中之前，测试你打算如何使用精灵的精灵组可能也会有所帮助。精灵组不总会引起问题，但这是需要记住的一点。此外，AndEngine 是一个开源项目，它正在不断更新和改进。关注最新修订版以获取修复或改进。

## 另请参阅

+   第二章中的*了解 AndEngine 实体*部分，*使用实体*

+   第二章中的*用精灵为场景注入生命*部分，*使用实体*

## 使用实体剔除来禁用渲染

剔除实体是一种防止不必要的实体被渲染的方法。在精灵在 AndEngine `Camera`的视图中不可见的情况下，这可以提高性能。

## 如何操作…

对任何预先存在的`Entity`或`Entity`子类型进行以下方法调用：

```kt
entity.setCullingEnabled(true);
```

## 它是如何工作的…

剔除实体会根据它们在场景中的位置相对于摄像机可见场景部分来禁止某些实体被渲染。当我们场景上有许多精灵可能会偶尔移出摄像机视野时，这非常有用。启用剔除后，那些在摄像机视图之外的实体将不会被渲染，以避免我们进行不必要的 OpenGL 调用。

请注意，剔除只发生在那些完全在摄像机视野之外的实体上。这考虑了实体的整个区域，从左下角到右上角。如果实体的部分在摄像机视野之外，不会应用剔除。

## 还有更多内容...

**剔除**只会停止渲染那些移出摄像机视野的实体。因此，对所有那些经常移出`Camera`区域的 游戏对象（如物品、敌人等）启用剔除并不是一个坏主意。对于由较小纹理组成的大型背景实例，剔除也可以显著提高性能，尤其是考虑到背景图像的大小。

剔除确实可以帮助我们节省渲染时间，但这并不意味着我们应该对所有实体启用剔除。毕竟，默认不启用它是有一个原因的。在 HUD 实体上启用剔除是一个糟糕的主意。对于暂停菜单或其他可能进出摄像机视野的大型实体来说，包含它似乎是一个可行的选择，但这可能会导致在移动摄像机时出现问题。AndEngine 的工作方式是 HUD 实际上永远不会随着摄像机移动，所以如果我们对 HUD 实体启用剔除，然后将摄像机向右移动 800 像素（假设我们的摄像机宽度是 800 像素），我们的 HUD 实体仍然会在物理上响应它们在屏幕上的正确位置，但它们不会渲染。它们仍然会响应触摸事件和其他各种场景，但我们就是看不到它们在屏幕上。

此外，在实体被绘制在场景上之前，剔除还需要进行一层额外的可见性检查。因此，较旧的设备在启用实体剔除时，如果这些实体没有被剔除，可能会有性能损失。这可能听起来不多，但当我们在仅能勉强运行 30 帧每秒的设备上有玩家运行时，对例如 200 个精灵进行额外的可见性检查可能会足以使游戏体验变得不便。

## 参见：

+   第二章中关于*理解 AndEngine 实体*的部分，*使用实体*。


# 第九章：AndEngine 扩展概述

在本章中，我们将介绍一些 AndEngine 最受欢迎的扩展的目的和用法。本章包括以下主题：

+   创建动态壁纸

+   使用多人游戏扩展进行网络通信

+   使用**可伸缩矢量图形**（**SVG**）创建高分辨率图形

+   使用 SVG 纹理区域进行颜色映射

# 简介

在扩展概述章节中，我们将开始使用一些 AndEngine 没有打包的类。有许多扩展可以编写，以添加各种改进或额外功能到任何默认的 AndEngine 游戏。在本章中，我们将使用三个主要扩展，它们将允许我们使用 AndEngine 创建动态壁纸，创建允许多个设备直接相互连接或连接到专用服务器的在线游戏，并最终将 SVG 文件作为纹理区域整合到我们的游戏中，从而在游戏中实现高分辨率和可伸缩的图形。

AndEngine 包含一个相对较长的扩展列表，我们可以将这些扩展包含在项目中，以便使某些任务更容易完成。不幸的是，由于扩展的数量和一些扩展的当前状态，我们限制在本章中包含的扩展数量。然而，大多数 AndEngine 扩展相对容易使用，并且包含可以从 Nicolas Gramlich 的公共 GitHub 仓库获取的示例项目——[`github.com/nicolasgramlich`](https://github.com/nicolasgramlich)。以下是其他 AndEngine 扩展的列表以及简短的用途描述：

+   `AndEngineCocosBuilderExtension`：这个扩展允许开发者通过使用**所见即所得**（**WYSIWYG**）的概念来创建游戏。这种方法允许开发者在使用 CocosBuilder 软件为桌面电脑的 GUI 拖放环境中构建应用程序。这个扩展可以帮助将菜单和关卡设计简化为在屏幕上放置对象，并将设置导出到一个可以通过`AndEngineCocosBuilderExtension`扩展读取的文件。

+   `AndEngineAugmentedRealityExtension`：增强现实扩展允许开发者轻松地将一个普通的 AndEngine 活动转换为一个增强现实活动，它将在屏幕上显示设备的物理摄像头视图。然后我们能够将实体附着在屏幕上显示的摄像头视图之上。

+   `AndEngineTexturePackerExtension`：这个扩展允许开发者导入通过 TexturePacker 程序为桌面电脑创建的精灵表。这个程序通过让我们将图片拖放到程序中，将完成的精灵表导出为 AndEngine 可读取的格式，然后使用`AndEngineTexturePackerExtension`扩展简单地将它加载到我们的项目中，使得创建精灵表变得非常简单。

+   `AndEngineTMXTiledMapExtensions`：这个扩展可以在基于图块地图样式的游戏中大大提高生产力。使用 TMX 图块地图编辑器，开发者只需将精灵/图块拖放到基于网格的关卡编辑器中即可创建关卡。一旦在编辑器中创建了一个关卡，只需将其导出为 `.tmx` 文件格式，然后使用 `AndEngineTMXTiledMapExtension` 将关卡加载到我们的项目中。

# 创建动态壁纸

动态壁纸扩展是 AndEngine 提供的 Android 开发资源中的一个很好的补充。使用这个扩展，我们可以轻松地通过使用我们习惯于游戏开发的所有普通 AndEngine 类来创建壁纸。在本主题中，我们将创建一个包含简单粒子系统的动态壁纸，该粒子系统在屏幕顶部生成粒子。壁纸设置将包括一个允许用户增加粒子移动速度的值。

### 注意

本教程假设您至少具备 Android SDK 的 `Activity` 类的基本知识，以及对 Android 视图对象（如 `SeekBars` 和 `TextViews`）的一般了解。

## 准备就绪

动态壁纸不是典型的 Android 活动。相反，它们是一个服务，在项目设置方面需要略有不同的方法。在访问代码之前，让我们继续创建动态壁纸所需的文件夹和文件。

### 注意

参考代码捆绑包中名为 `LiveWallpaperExtensionExample` 的项目。

我们将在下一节介绍每个文件中驻留的代码：

1.  在 `res/layout` 文件夹中创建或覆盖当前的 `main.xml` 文件，将其命名为 `settings_main.xml`。这个布局文件将用于创建用户调整壁纸属性设置活动的布局。

1.  在 `res` 文件夹中创建一个名为 `xml` 的新文件夹。在这个文件夹内，创建一个新的 `xml` 文件，并将其命名为 `wallpaper.xml`。这个文件将用作壁纸图标的引用，以及描述和设置活动的引用，该设置活动将用于修改壁纸属性。

## 如何操作…

我们将从填充所有 XML 文件开始，以便容纳一个动态壁纸服务。这些文件包括 `settings_main.xml`、`wallpaper.xml`，最后是 `AndroidManifest.xml`。

1.  创建 `settings_main.xml` 布局文件：

    第一步涉及将 `settings_main.xml` 文件定义为壁纸设置活动的布局。没有限制开发者使用特定布局样式的规则，但对于动态壁纸来说，最常见的方法是使用一个简单的 `TextView` 和相应的 `Spinner` 来提供修改动态壁纸可调整值的方式。

1.  打开 `res/xml/` 文件夹中的 `wallpaper.xml` 文件。将以下代码导入 `wallpaper.xml`：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <wallpaper 
        android:settingsActivity="com.Live.Wallpaper.Extension.Example.LiveWallpaperSettings"
        android:thumbnail="@drawable/ic_launcher"/>
    ```

1.  修改 `AndroidManifest.xml` 以满足壁纸服务的需求：

    在第三步中，我们必须修改`AndroidManifest.xml`，以便允许我们的项目作为壁纸服务运行。在项目的`AndroidManifest.xml`文件中，替换`<manifest>`标签内的所有代码，使用以下内容：

    ```kt
    <uses-feature android:name="android.software.live_wallpaper" />

    <application android:icon="@drawable/ic_launcher" >
        <service
            android:name=".LiveWallpaperExtensionService"
            android:enabled="true"
            android:icon="@drawable/ic_launcher"
            android:label="@string/service_name"
            android:permission="android.permission.BIND_WALLPAPER" >
            <intent-filter android:priority="1" >
                <action android:name="android.service.wallpaper.WallpaperService" />
            </intent-filter>

            <meta-data
                android:name="android.service.wallpaper"
                android:resource="@xml/wallpaper" />
        </service>

        <activity
            android:name=".LiveWallpaperSettings"
            android:exported="true"
            android:icon="@drawable/ic_launcher"
            android:label="@string/live_wallpaper_settings"
            android:theme="@android:style/Theme.Black" >
        </activity>
    ```

处理完这三个 xml 文件后，我们可以创建实时壁纸所需的类。我们将使用三个类来处理实时壁纸的执行。这些类是`LiveWallpaperExtensionService.java`、`LiveWallpaperSettings.java`和`LiveWallpaperPreferences.java`，在以下步骤中将会介绍：

1.  创建实时壁纸偏好设置类：

    `LiveWallpaperPreferences.java`类与我们在第一章，*AndEngine 游戏结构*中讨论的偏好设置类相似。在这种情况下，偏好设置类的主要目的是处理生成的粒子的速度值。以下方法用于保存和加载粒子的速度值。请注意，我们取反了`mParticleSpeed`值，因为我们希望粒子向屏幕底部移动：

    ```kt
    // Return the saved value for the mParticleSpeed variable
    public int getParticleSpeed(){
      return -mParticleSpeed;
    }

    // Save the mParticleSpeed value to the wallpaper's preference file
    public void setParticleSpeed(int pParticleSpeed){
      this.mParticleSpeed = pParticleSpeed;
      this.mSharedPreferencesEditor.putInt(PARTICLE_SPEED_KEY, mParticleSpeed);
      this.mSharedPreferencesEditor.commit();
    }
    ```

1.  创建实时壁纸设置活动：

    实时壁纸的设置活动扩展了 Android SDK 的`Activity`类，使用`settings_main.xml`文件作为活动的布局。此活动的目的是根据`SeekBar`对象的进度为`mParticleSpeed`变量获取一个值。一旦退出设置活动，`mParticleSpeed`值就会被保存到我们的偏好设置中。

1.  创建实时壁纸服务：

    为设置实时壁纸而涉及的最终步骤是创建`LiveWallpaperExtensionService.java`类，其中包含实时壁纸服务的代码。为了指定我们希望该类使用实时壁纸扩展类，我们只需在`LiveWallpaperExtensionService.java`声明中添加`extends BaseLiveWallpaperService`。完成这一步后，我们可以看到，设置`BaseLiveWallpaperService`类与从这时起设置`BaseGameActivity`类非常相似，这使我们能够加载资源、应用精灵，或我们已经习惯的任何其他常见的 AndEngine 任务。

## 工作原理…

如果我们从整个项目来看，这个“配方”相当大，但幸运的是，与类文件相关的代码在之前的章节中已经讨论过了，所以不必担心！为了简洁起见，我们将省略在之前章节中已经讨论过的类。如果需要复习，请查看*查看更多...*小节中提到的主题。

在第一步中，我们要做的就是创建一个最小的 Android `xml`布局，用于设置活动。完全有可能跳过这一步，使用 AndEngine 的`BaseGameActivity`作为设置活动，但为了简化问题，我们采用了非常基本的`TextView/SeekBar`方法。这对开发人员来说节省了时间，对用户来说也更加方便。尽量保持这个屏幕简洁，因为它应该是一个简单屏幕，有简单的目的。

在第二步中，我们将创建一个`wallpaper.xml`文件，该文件将作为`AndroidManifest.xml`文件中动态壁纸服务所需的一些规范的引用。这个文件仅仅用于存储服务的属性，这些属性包括包和类名，或者按下壁纸预览中的**设置...**按钮时要启动的设置活动的“链接”。`wallpaper.xml`还包括对壁纸选择窗口中要使用的图标的引用。

在第三步中，我们正在修改`AndroidManifest.xml`文件，以便将动态壁纸服务作为本项目的主组件运行，而不是启动一个活动。在`<service>`标签内，我们为壁纸服务包含了`name`、`icon`和`label`属性。这些属性与活动中的属性具有相同的目的。另外两个属性是`android:enabled="true"`，这意味着我们希望默认启用壁纸服务，以及`android:permission="android.permission.BIND_WALLPAPER"`属性，这意味着只有 Android 操作系统可以绑定到该服务。活动的属性与此类似，只是我们包括了`exported`和`theme`属性，并排除了`enabled`和`permission`属性。`android:exported="true"`属性表示活动可以通过外部进程启动，而主题属性将改变设置活动 UI 的外观。

第四步涉及创建我们将用于存储用户可调整值的偏好设置类。在这个食谱中，我们在偏好设置类中包含了一个名为`mParticleSpeed`的单个值，并带有相应的获取器和设置器方法。在一个更复杂的动态壁纸中，我们可以在此基础上构建这个类，使我们能够轻松添加或移除变量，为壁纸提供尽可能多的自定义属性。

在第五步中，我们创建了一个`Activity`类，当用户在动态壁纸预览屏幕上按下**设置...**按钮时显示。在这个特定的`Activity`中，我们获取了`settings_main.xml`文件作为我们的布局，其中包含两个用于显示标签和相应值的`TextView`视图类型，以及一个允许操作壁纸可调整值的`SeekBar`。这个`Activity`最重要的任务是当用户选择理想的速度后，能够将设置保存到偏好文件中。这是通过在`SeekBar`意识到用户移动了`SeekBar`滑块时调整`mParticleSpeed`变量来完成的：

```kt
// OnProgressChanged represents a movement on the slider
  @Override
  public void onProgressChanged(SeekBar seekBar, int progress,
      boolean fromUser) {
    // Set the mParticleSpeed depending on the SeekBar's position(progress)
    mParticleSpeed = progress;
```

在此事件中，除了更新`mParticleSpeed`值，相关的`TextView`也会被更新。然而，这个值实际上只有在用户离开设置活动时才会保存到偏好文件中，以避免不必要地覆盖偏好文件。为了将新值保存到偏好文件，我们可以在`Activity`类最小化时从`LiveWallpaperPreferences`单例调用`setParticleSpeed(mParticleSpeed)`：

```kt
@Override
protected void onPause() {
  // onPause(), we save the current value of mParticleSpeed to the preference file.
  // Anytime the wallpaper's lifecycle is executed, the mParticleSpeed value is loaded
  LiveWallpaperPreferences.getInstance().setParticleSpeed(mParticleSpeed);
  super.onPause();
}
```

在第六步也是最后一步中，我们终于可以开始编写动态壁纸的视觉部分。在这款特定的壁纸中，我们在视觉吸引力方面保持了简单，但我们确实涵盖了开发壁纸所需的所有必要信息。如果我们查看`LiveWallpaperExtensionService`类，需要关注的一些关键变量包括以下内容：

```kt
  private int mParticleSpeed;

  // These ratio variables will be used to keep proper scaling of entities
  // regardless of the screen orientation
  private float mRatioX;
  private float mRatioY;
```

尽管在其他类解释中我们已经讨论了`mParticleSpeed`变量，但此时应该很清楚，我们将使用这个变量来最终确定粒子的速度，因为这是将处理`ParticleSystem`对象的类。上面声明的另外两个'比例'变量是为了帮助我们保持实体的适当缩放比例。这些变量在用户将设备从横屏倾斜到竖屏或反之亦然时是必需的，这样我们就可以根据表面视图的宽度和高度计算粒子的比例，以防止实体在方向改变时被拉伸或扭曲。跳到这个类的底部覆盖方法，以下代码确定了`mRatioX`和`mRatioY`的值：

```kt
@Override
public void onSurfaceChanged(GLState pGLState, int pWidth, int pHeight) {

  if(pWidth > pHeight){
      mRatioX = 1;
      mRatioY = 1;
    } else {
      mRatioX = ((float)pHeight) / pWidth;
      mRatioY = ((float)pWidth) / pHeight;
    }

    super.onSurfaceChanged(pGLState, pWidth, pHeight);
  }
```

我们可以在这里看到，`if`语句正在检查设备是否处于横屏或竖屏模式。如果`pWidth`大于`pHeight`，这意味着当前的方向是横屏模式，将 x 和 y 的比例尺设置为默认值 1。另一方面，如果设备设置为竖屏模式，那么我们必须重新计算粒子实体的比例尺。

当处理完`onSurfaceChanged()`方法后，我们继续讨论剩余的关键点，下一个是偏好设置管理。处理偏好设置是一项相当琐碎的任务。首先，我们应该初始化偏好设置文件，以防这是第一次启动壁纸。我们通过在`onCreateEngineOptions()`中的`LiveWallpaperPreferences`实例调用`initPreferences(this)`方法来实现这一点。我们还需要重写`onResume()`方法，以便通过从`LiveWallpaperPreferences`实例调用`getParticleSpeed()`方法，用偏好设置文件中存储的值加载`mParticleSpeed`变量。

最后，我们来到实时壁纸设置的最后一个步骤，即设置粒子系统。这个特定的粒子系统并不特别花哨，但它包括一个`ParticleModifier`对象，其中有一些需要注意的点。由于我们将`IParticleModifier`接口添加到粒子系统中，因此我们可以在每次更新每个粒子时访问由系统生成的单个粒子。在`onUpdateParticle()`方法中，我们将根据从偏好设置文件中加载的`mParticleSpeed`变量设置粒子的速度：

```kt
  // speed set by the preferences...
  if(currentVelocityY != mParticleSpeed){
    // Adjust the particle's velocity to the proper value
    particlePhysicsHandler.setVelocityY(mParticleSpeed);
  }
```

如果粒子的比例不等于`mRatioX/mRatioY`值，我们还必须调整粒子的比例，以补偿设备方向：

```kt
  // If the particle's scale is not equal to the current ratio
  if(entity.getScaleX() != mRatioX){
    // Re-scale the particle to better suit the current screen ratio
    entity.setScale(mRatioX, mRatioY);
  }
```

这样就完成了使用 AndEngine 设置实时壁纸的全部工作！尝试玩转粒子系统，在设置中添加新的可自定义值，看看你能想出什么。使用这个扩展，你将能够快速上手，立即创建新的实时壁纸！

## 另请参阅…

+   第一章中的*保存和加载游戏数据*部分，*AndEngine 游戏结构*。

+   第二章中的*使用粒子系统*部分，*使用实体*。

# 使用多人游戏扩展进行网络编程

这里无疑是最受欢迎的游戏设计方面。这当然是多人游戏。在这个项目配方中，我们将使用 AndEngine 的多玩家扩展，以便直接在移动设备上创建一个完全功能性的客户端和服务器。一旦我们介绍了这个扩展包括的类和特性，以简化网络编程，你将能够将你的在线游戏想法变为现实！

## 准备就绪

创建一个多人游戏可能需要相当多的组件，以满足项目的可读性。

### 注意

请参考代码包中的名为`MultiplayerExtensionExample`的项目。

因此，我们将把这些不同的组件分为五个类别。

创建一个名为`MultiplayerExtensionExample`的新 Android 项目。项目准备就绪后，创建四个具有以下名称的新类文件：

+   `MultiplayerExtensionExample.java`：本食谱的`BaseGameActivity`类

+   `MultiplayerServer.java`：包含主要服务器组件的类

+   `MultiplayerClient.java`：包含主要客户端组件的类

+   `ServerMessages.java`：包含旨在从服务器发送到客户端的消息的类

+   `ClientMessages.java`：包含旨在从客户端发送到服务器的消息的类

打开项目的`AndroidManifest.xml`文件，并添加以下两个`<uses-permission>`属性：

```kt
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
<uses-permission android:name="android.permission.INTERNET"/>
```

## 如何操作...

为了保持本食谱中内容的相对性，我们将按照*准备就绪*部分提到的顺序，依次处理每个类，从`MultiplayerExtensionExample`类开始。

1.  为`mMessagePool`声明并注册服务器/客户端消息：

    ```kt
    this.mMessagePool.registerMessage(ServerMessages.SERVER_MESSAGE_ADD_POINT, AddPointServerMessage.class);
    this.mMessagePool.registerMessage(ClientMessages.CLIENT_MESSAGE_ADD_POINT, AddPointClientMessage.class);  
    ```

1.  配置场景触摸监听器，以允许与服务器之间的消息发送和接收：

    ```kt
    if (pSceneTouchEvent.getAction() == TouchEvent.ACTION_MOVE) {
      if (mServer != null) {

        if(mClient != null){
          // Obtain a ServerMessage object from the mMessagePool
          AddPointServerMessage message = (AddPointServerMessage) MultiplayerExtensionExample.this.mMessagePool.obtainMessage(ServerMessages.SERVER_MESSAGE_ADD_POINT);
          // Set up the message with the device's ID, touch coordinates and draw color
          message.set(SERVER_ID, pSceneTouchEvent.getX(), pSceneTouchEvent.getY(), mClient.getDrawColor());
          // Send the client/server's draw message to all clients
          mServer.sendMessage(message);
          // Recycle the message back into the message pool
          MultiplayerExtensionExample.this.mMessagePool.recycleMessage(message);
        return true;
        }
        // If device is running as a client...
      } else if(mClient != null){
        /* Similar to the message sending code above, except
         * in this case, the client is *not* running as a server.
         * This means we have to first send the message to the server
         * via a ClientMessage rather than ServerMessage
         */
        AddPointClientMessage message = (AddPointClientMessage) MultiplayerExtensionExample.this.mMessagePool.obtainMessage(ClientMessages.CLIENT_MESSAGE_ADD_POINT);
        message.set(CLIENT_ID, pSceneTouchEvent.getX(), pSceneTouchEvent.getY(), mClient.getDrawColor());
        mClient.sendMessage(message);
        MultiplayerExtensionExample.this.mMessagePool.recycleMessage(message);

        return true;
      }  
    }
    ```

1.  创建一个*开关*对话框，提示用户选择作为服务器或客户端。如果选择了服务器或客户端组件，我们将初始化这两个组件中的一个：

    ```kt
    mServer = new MultiplayerServer(SERVER_PORT);
    mServer.initServer();

    // or...

    mClient = new MultiplayerClient(mServerIP,SERVER_PORT, mEngine, mScene);
    mClient.initClient();
    ```

1.  重写活动的`onDestroy()`方法，在活动被销毁时终止服务器和客户端组件：

    ```kt
    @Override
    protected void onDestroy() {
      // Terminate the client and server socket connections
      // when the application is destroyed
      if (this.mClient != null)
        this.mClient.terminate();

      if (this.mServer != null)
        this.mServer.terminate();
      super.onDestroy();
    }
    ```

    一旦所有主要活动的功能就位，我们可以继续编写服务器端代码。

1.  创建服务器的初始化方法——创建处理服务器客户端连接的`SocketServer`对象：

    ```kt
    // Create the SocketServer, specifying a port, client listener and 
    // a server state listener (listeners are implemented in this class)
    MultiplayerServer.this.mSocketServer = new SocketServer<SocketConnectionClientConnector>(
        MultiplayerServer.this.mServerPort,
        MultiplayerServer.this, MultiplayerServer.this) {

          // Handle client connection here...
    };
    ```

1.  处理客户端连接到服务器。这涉及到注册客户端消息并定义如何处理它们：

    ```kt
      // Called when a new client connects to the server...
    @Override
    protected SocketConnectionClientConnector newClientConnector(
      SocketConnection pSocketConnection)
      throws IOException {
        // Create a new client connector from the socket connection
        final SocketConnectionClientConnector clientConnector = new       SocketConnectionClientConnector(pSocketConnection);

        // Register the client message to the new client
      clientConnector.registerClientMessage(ClientMessages.CLIENT_MESSAGE_ADD_POINT, AddPointClientMessage.class, new IClientMessageHandler<SocketConnection>(){

        // Handle message received by the server...
        @Override
        public void onHandleMessage(         ClientConnector<SocketConnection> pClientConnector,
            IClientMessage pClientMessage)
            throws IOException {
          // Obtain the client message
          AddPointClientMessage incomingMessage = (AddPointClientMessage) pClientMessage;

          // Create a new server message containing the contents of the message received
          // from a client
          AddPointServerMessage outgoingMessage = new AddPointServerMessage(incomingMessage.getID(), incomingMessage.getX(), incomingMessage.getY(), incomingMessage.getColorId());

          // Reroute message received from client to all other clients
          sendMessage(outgoingMessage);
        }
      });

      // Return the new client connector
      return clientConnector;
    }
    ```

1.  声明并初始化了`SocketServer`对象后，我们需要调用其`start()`方法：

    ```kt
    // Start the server once it's initialized
    MultiplayerServer.this.mSocketServer.start();
    ```

1.  创建`sendMessage()`服务器广播方法：

    ```kt
    // Send broadcast server message to all clients
    public void sendMessage(ServerMessage pServerMessage){
      try {
        this.mSocketServer.sendBroadcastServerMessage(pServerMessage);
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    ```

1.  创建`terminate()`方法以关闭连接：

    ```kt
    // Terminate the server socket and stop the server thread
    public void terminate(){
      if(this.mSocketServer != null)
      this.mSocketServer.terminate();
    }
    ```

    服务器端代码完成后，我们将在`MultiplayerClient`类中继续实现客户端代码。这个类与`MultiplayerServer`类非常相似，因此我们将省略不必要的客户端步骤。

1.  创建`Socket`、`SocketConnection`，最后创建`ServerConnector`以与服务器建立连接：

    ```kt
    // Create the socket with the specified Server IP and port
    Socket socket = new Socket(MultiplayerClient.this.mServerIP, MultiplayerClient.this.mServerPort);
    // Create the socket connection, establishing the input/output stream
    SocketConnection socketConnection = new SocketConnection(socket);
    // Create the server connector with the specified socket connection
    // and client connection listener
    MultiplayerClient.this.mServerConnector = new SocketConnectionServerConnector(socketConnection, MultiplayerClient.this);
    ```

1.  处理从服务器接收到的消息：

    ```kt
    // obtain the class casted server message
    AddPointServerMessage message = (AddPointServerMessage) pServerMessage;

    // Create a new Rectangle (point), based on values obtained via the server
    // message received
    Rectangle point = new Rectangle(message.getX(), message.getY(), 3, 3, mEngine.getVertexBufferObjectManager());

    // Obtain the color id from the message
    final int colorId = message.getColorId();
    ```

1.  创建客户端和服务器消息：

    `ClientMessage`和`ServerMessage`旨在作为数据包，能够被发送到服务器和客户端，以及从服务器和客户端接收。在这个食谱中，我们将为客户端和服务器创建一个消息，以处理发送关于在客户端设备上绘制点的信息。这些消息中存储的变量包括：

    ```kt
    // Member variables to be read in from the server and sent to clients
    private int mID;
    private float mX;
    private float mY;
    private int mColorId;
    ```

    读取和写入通信数据就像以下这样简单：

    ```kt
    // Apply the read data to the message's member variables
    @Override
    protected void onReadTransmissionData(DataInputStream pDataInputStream)
        throws IOException {
      this.mID = pDataInputStream.readInt();
      this.mX = pDataInputStream.readFloat();
      this.mY = pDataInputStream. readFloat();
      this.mColorId = pDataInputStream.readInt();
    }

    // Write the message's member variables to the output stream
    @Override
    protected void onWriteTransmissionData(
        DataOutputStream pDataOutputStream) throws IOException {
      pDataOutputStream.writeInt(this.mID);
      pDataOutputStream.writeFloat(this.mX);
      pDataOutputStream.writeFloat(this.mY);
      pDataOutputStream.writeInt(mColorId);
    }
    ```

## 工作原理...

在本食谱实现的服务器/客户端通信中，我们构建了一个允许直接在移动设备上部署服务器的应用程序。从这里，其他移动设备可以作为客户端连接到前述的移动服务器。一旦服务器与至少一个客户端建立连接，如果任何客户端创建了触摸事件，服务器将开始向所有客户端中继消息，在所有连接的客户端屏幕上绘制点。如果这听起来有些令人困惑，不用害怕，很快一切就会变得清晰。

在前五个步骤中，我们将编写`BaseGameActivity`类。这个类是服务器和客户端的入口点，同时也提供了触摸事件功能，使客户端能够在屏幕上绘图。

在第一步中，我们需要将必要的`ServerMessage`和`ClientMessage`对象注册到我们的`mMessagePool`中。`mMessagePool`对象是 AndEngine 中`MultiPool`类的扩展。关于如何使用`MessagePool`类回收通过网络发送和接收的消息，请参阅第八章《最大化性能》中的*创建精灵池*部分。

在第二步中，我们通过设置一个场景触摸监听器接口来建立场景，该接口的目的是发送跨网络的消息。在触摸监听器内部，我们可以使用简单的条件语句来检查设备是否作为客户端或服务器运行，通过`if(mServer != null)`这行代码，如果设备作为服务器运行则返回 true。此外，我们可以调用`if(mClient != null)`来检查设备是否作为客户端运行。在服务器检查中嵌套的客户端检查，如果设备同时作为客户端和服务器运行，将返回 true。如果设备作为客户端运行，发送消息只需从`mMessagePool`获取一条新消息，在消息上调用`set(device_id, touchX, touchY, colorId)`方法，然后调用`mClient.sendMessage(message)`。消息发送后，我们应该始终将其回收至池中，以免浪费内存。在继续之前，最后要提到的一点是，在嵌套的客户端条件中，我们发送的是服务器消息而不是客户端消息。这是因为在这种情况下，客户端同时也是服务器。这意味着我们可以跳过向服务器发送客户端消息，因为服务器已经包含了触摸事件数据。

第三步对于大多数开发者来说可能并不是理想的情况，因为我们使用对话框作为选择设备是作为服务器还是客户端的手段。这个场景仅用于展示如何初始化组件，所以对话框并不一定重要。选择用户是否能够主持游戏取决于游戏类型和开发者的想法，但这个方案至少涵盖了如何设置服务器（如果需要的话）。请记住，在初始化服务器时，我们只需要知道**端口号**。另一方面，客户端需要知道有效的**服务器 IP**和服务器端口才能建立连接。一旦使用这些参数构建了`MultiplayerServer`和/或`MultiplayerClient`类，我们就可以初始化组件。初始化的目的将在不久后介绍。

对于`BaseGameActivity`类的第四步也是最后一步，是允许活动在调用`onDestroy()`时终止`MultiplayerServer`和`MultiplayerClient`的连接。这将关闭通信线程和套接字，在应用程序被销毁之前。

接下来，我们看看第五步中的`MultiplayerServer`代码，了解服务器的初始化。在创建服务器用来监听新客户端连接的`SocketServer`对象时，我们必须传入服务器的端口号，以及一个`ClientConnectorListener`和一个`SocketServerListener`。`MultiplayerServer`类实现了这两个监听器，记录服务器启动、停止、客户端连接到服务器以及客户端断开连接时的日志。

在第六步中，我们正在实施处理服务器如何响应传入连接以及如何处理客户端接收到的消息的系统。以下是按应实施顺序涉及的过程：

+   当新客户端连接到服务器时，将调用`protected SocketConnectionClientConnector newClientConnector(...)`。

+   创建一个新的`SocketConnectionClientConnector`供客户端用作新客户端与服务器之间的通信手段。

+   通过`registerClientMessage(flag, message.class, messageHandlerInterface)`注册你希望服务器识别的`ClientMessages`。

+   在`messageHandlerInterface`接口的`onHandleMessage()`方法中，我们处理从网络接收到的任何消息。在这种情况下，服务器只是将客户端的消息中继回所有连接的客户端。

+   返回新的`clientConnector`对象。

这些点概述了服务器/客户端通信的主要功能。在这个示例中，我们使用单一消息在客户端设备上绘制点，但对于更广泛的消息范围，只要标志参数与我们在`onHandleMessage()`接口中获得的消息类型匹配，我们就可以继续调用`registerClientMessage()`方法。一旦注册了所有适当的消息，并且我们完成了客户端处理代码，我们可以继续第七步，在`mSocketServer`对象上调用`start()`。

在第八步中，我们为服务器创建了`sendMessage(message)`方法。服务器的`sendMessage(message)`版本通过简单地遍历客户端连接器列表，向每个连接器调用`sendServerMessage(message)`，向所有客户端发送广播消息。如果我们希望向单个客户端发送服务器消息，可以直接在单个`ClientConnector`上调用`sendServerMessage(message)`。在另一端，我们有客户端版本的`sendMessage(message)`。客户端的`sendMessage()`方法实际上并不向其他客户端发送消息；实际上，客户端根本不与其他客户端通信。客户端的工作是与服务器通信，然后服务器再与其他客户端通信。查看以下图表以更好地了解我们的网络通信是如何工作的：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_09_01.jpg)

在前述图中，流程由数字标出。首先，客户端将消息发送到服务器。一旦服务器接收到消息，它将遍历其客户端列表中的每个`ClientConnector`对象，向所有客户端发送广播。

创建`MultiplayerServer`组件的最后一步是创建一个用于终止`mSocketServer`的方法。此方法由我们主活动中的`onDestroy()`调用，以便在我们使用完毕后销毁通信线程。

服务器端的所有代码准备就绪后，我们可以继续编写客户端代码。`MultiplayerClient`的代码与服务器端有些相似，但存在一些差异。在与服务器建立连接时，我们必须比服务器初始化时更具体一些。首先，我们必须创建一个新的 Socket，指定要连接的 IP 地址以及服务器端口号。然后，我们将`Socket`传递给一个新的`SocketConnection`对象，用于在 socket 上建立输入/输出流。完成此操作后，我们可以创建我们的`ServerConnector`，其目的是在客户端和服务器之间建立最终的连接。

现在我们已经接近一个完整的客户端/服务器通信项目了！第 11 步是真正的魔法发生的地方——客户端接收服务器消息。为了接收服务器消息，类似于服务器接收消息的实现，我们只需调用`mServerConnector.registerServerMessage(...)`，这会给我们一个填充`onHandleMessage(serverConnector, serverMessage)`接口的机会。同样，类似于服务器端的实现，我们可以将`serverMessage`对象强制转换为`AddPointServerMessage`类，这样我们就能获取到消息中存储的自定义值。

现在，我们已经将所有服务器和客户端代码处理完毕，来到了最后一步。这当然就是创建将用于`MessagePool`的消息，以及我们一直在到处发送和接收的对象。我们需要了解两种不同类型的消息对象。第一种是`ServerMessage`，它包括那些*从客户端发送并由服务器接收/读取*的消息。另一种消息，你已经猜到了，是`ClientMessage`，它用于*从服务器发送并由客户端接收/读取*。通过创建我们自己的消息类，我们可以轻松地将由基本数据类型表示的数据块打包并发送到网络中。基本数据类型包括`int`、`float`、`long`、`boolean`等。

在这个食谱中使用的消息里，我们存储了一个 ID，用以标识消息是来自客户端还是服务器，每个客户端触摸事件的 x 和 y 坐标，以及当前选定的绘图颜色 ID。每个值都应该有其对应的*获取*方法，这样我们在接收到消息时就能获取到消息的详细信息。此外，通过覆盖客户端或服务器消息，我们必须实现`onReadTransmissionData(DataInputStream)`方法，它允许我们从输入流中获取数据类型并将它们复制到我们的成员变量中。我们还必须实现`onWriteTransmissionData(DataOutputStream)`方法，用于将成员变量写入数据流并发送到网络中。在创建服务器和客户端消息时，我们需要注意的一个问题是，接收到的成员变量中的数据是以它们发送时的顺序获取的。请看我们服务器消息的读写方法的顺序：

```kt
  // write method
  pDataOutputStream.writeInt(this.mID);
  pDataOutputStream.writeFloat(this.mX);
  pDataOutputStream.writeFloat(this.mY);
  pDataOutputStream.writeInt(this.mColorId);

  // read method
  this.mID = pDataInputStream.readInt();
  this.mX = pDataInputStream.readFloat();
  this.mY = pDataInputStream. readFloat();
  this.mColorId = pDataInputStream.readInt();
```

在记住前面的代码的前提下，我们可以确信，如果我们向输出流中写入包含`int`、`float`、`int`、`boolean`和一个`float`的消息，任何接收该消息的设备将分别读取一个`int`、`float`、`int`、`boolean`和一个`float`。

# 使用 SVG 创建高分辨率图形

将**可缩放矢量图形**（**SVG**）集成到我们的移动游戏中，对于开发来说是一个巨大的优势，尤其是在与 Android 平台合作时。最大的好处，也是我们将在本主题中讨论的内容，是 SVG 可以根据运行我们应用的设备进行缩放。不再需要为更大的显示屏创建多个 PNG 图片集，更重要的是，不再需要在大型屏幕设备上处理严重的像素化图形！在本主题中，我们将使用`AndEngineSVGTextureRegionExtension`扩展来为我们的精灵创建高分辨率纹理区域。请看下面的截图，左侧是标准分辨率图像的缩放，右侧是 SVG 的效果：

![使用 SVG 创建高分辨率图形](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_09_02.jpg)

尽管 SVG 资源在创建多种屏幕尺寸的高分辨率图形时可能非常有说服力，但在`SVG`扩展当前的状态下，也存在一些缺点。`SVG`扩展不会渲染所有可用的元素，例如文本和 3D 形状。然而，大多数必要的元素都是可用的，并且在运行时可以正确加载，如路径、渐变、填充颜色和一些形状。在 SVG 加载过程中未能加载的元素将通过 Logcat 显示。

从 SVG 文件中移除不受`SVG`扩展支持的元素是一个明智的选择，因为它们可能会影响加载时间，这是使用`SVG`扩展的另一个负面因素。由于 SVG 纹理在加载到内存之前必须先转换为 PNG 格式，因此它们的加载时间将比 PNG 文件长得多。根据每个 SVG 中包含的元素数量，SVG 纹理的加载时间可能会达到等效 PNG 图像的两到三倍。最常见的解决方法是，在应用程序首次启动时将 SVG 纹理以 PNG 格式保存到设备上。随后的每次启动都会加载 PNG 图像，以减少加载时间，同时保持设备特定的图像分辨率。

## 准备工作

请参考代码包中名为`WorkingWithSVG`的项目。

## 如何操作...

使用 SVG 纹理区域是一个简单易行且效果显著的任务。

1.  与普通的`TextureRegion`类似，首先我们需要一个`BuildableBitmapTextureAtlas`：

    ```kt
    // Create a new buildable bitmap texture atlas to build and contain texture regions
    BuildableBitmapTextureAtlas bitmapTextureAtlas = new BuildableBitmapTextureAtlas(mEngine.getTextureManager(), 1024, 1024, TextureOptions.BILINEAR);
    ```

1.  现在我们已经设置好了纹理图集，可以通过使用`SVGBitmapTextureAtlasTextureRegionFactory`单例来创建 SVG 纹理区域：

    ```kt
    // Create a low-res (32x32) texture region of svg_image.svg
    mLowResTextureRegion = SVGBitmapTextureAtlasTextureRegionFactory.createFromAsset(bitmapTextureAtlas, this, "svg_image.svg", 32,32);

    // Create a med-res (128x128) texture region of svg_image.svg
    mMedResTextureRegion = SVGBitmapTextureAtlasTextureRegionFactory.createFromAsset(bitmapTextureAtlas, this, "svg_image.svg", 128, 128);

    // Create a high-res (256x256) texture region of svg_image.svg
    mHiResTextureRegion = SVGBitmapTextureAtlasTextureRegionFactory.createFromAsset(bitmapTextureAtlas, this, "svg_image.svg", 256,256);    
    ```

## 工作原理...

如我们所见，创建一个`SVG`纹理区域与普通的`TextureRegion`并没有太大区别。两者在实例化方面的唯一真正区别在于，我们必须输入一个`width`和`height`值作为最后两个参数。这是因为，与平均的栅格图像格式不同，由于固定的像素位置，其宽度和高度或多或少是硬编码的，`SVG`像素位置可以按我们喜欢的任何大小进行放大或缩小。如果我们缩放`SVG`纹理区域，向量的坐标将简单地调整自己以继续生成清晰、精确的图像。一旦构建了`SVG`纹理区域，我们就可以像应用其他任何纹理区域一样将其应用于精灵。

了解如何创建`SVG`纹理区域是很好的，但它的意义远不止于此。毕竟，在游戏中使用 SVG 图像的美妙之处在于能够根据设备显示大小来缩放图像。这样，我们就不需要为小屏幕设备加载大图像以适应平板电脑，也不需要通过创建小的纹理区域来节省内存，让平板用户受苦。`SVG`扩展实际上使我们能够非常简单地处理根据显示大小进行缩放的概念。以下代码展示了我们如何为所有创建的`SVG`纹理区域实现大规模缩放因子。这将使我们避免手动根据显示大小创建不同大小的纹理区域：

```kt
float mScaleFactor = 1;

// Obtain the device display metrics (dpi)
DisplayMetrics displayMetrics = this.getResources().getDisplayMetrics();

int deviceDpi = displayMetrics.densityDpi;

switch(deviceDpi){
case DisplayMetrics.DENSITY_LOW:
  // Scale factor already set to 1
  break;

case DisplayMetrics.DENSITY_MEDIUM:
  // Increase scale to a suitable value for mid-size displays
  mScaleFactor = 1.5f;
  break;

case DisplayMetrics.DENSITY_HIGH:
  // Increase scale to a suitable value for larger displays
  mScaleFactor = 2;
  break;

case DisplayMetrics.DENSITY_XHIGH:
  // Increase scale to suitable value for largest displays
  mScaleFactor = 2.5f;
  break;

default:
  // Scale factor already set to 1
  break;
}

SVGBitmapTextureAtlasTextureRegionFactory.setScaleFactor(mScaleFactor);
```

上述代码可以复制并粘贴到活动的`onCreateEngineOptions()`方法中。需要做的就是决定您希望根据设备大小为 SVG 应用哪些缩放因子！从这一点开始，我们可以创建一个单一的`SVG`纹理区域，根据显示大小，纹理区域将相应地缩放。例如，我们可以加载如下纹理区域：

```kt
  mLowResTextureRegion = SVGBitmapTextureAtlasTextureRegionFactory.createFromAsset(bitmapTextureAtlas, this, "svg_image.svg", 32,32);
```

我们可以将纹理区域的宽度和高度值定义为`32`，但是通过在工厂类中调整缩放因子，对于`DENSITY_XHIGH`显示，纹理区域会通过将指定值与缩放因子相乘来构建成`80x80`。处理具有自动缩放因子的纹理区域时要小心。缩放还会增加它们在`BuildableBitmapTextureAtlas`对象中占用的空间，如果超出限制，可能会像其他任何`TextureRegion`一样导致错误。

## 参见……

+   在第一章，*AndEngine 游戏结构*中的*不同类型的纹理*部分。

# 使用 SVG 纹理区域进行色彩映射

`SVG` 纹理区域的一个有用特点是，我们可以轻松地映射纹理的颜色。这种技术在允许用户为其角色的角色选择自定义颜色的游戏中很常见，无论是服装和配饰颜色、发色、肤色、地形主题等等。在本主题中，我们将在构建 `SVG` 纹理区域时使用 `ISVGColorMapper` 接口，为我们的精灵创建自定义颜色集。

## 准备工作

在我们开始颜色映射的编码工作之前，需要创建一个带有预设颜色的 SVG 图像。我们可以将这些预设颜色视为我们的*映射图*。许多开发者中最受欢迎的 SVG 编辑器之一是**Inkscape**，它是一款免费、易于使用且功能齐全的编辑器。可以从以下链接下载 Inkscape，[`inkscape.org/download/`](http://inkscape.org/download/)，或者你也可以选择使用其他你喜欢的 SVG 编辑器。

## 如何操作...

颜色映射听起来可能是一项繁琐的工作，但实际上非常容易完成。我们需要做的是保持 `SVG` 图像与代码之间的一点点一致性。牢记这一点，创建多颜色的单一源纹理可以是一个非常快速的任务。以下步骤包括从绘制 `SVG` 图像以方便颜色映射，到编写将颜色映射到应用程序中 `SVG` 图像特定区域的代码的过程。

+   绘制我们的 `SVG` 图像：

    为了在运行时轻松地将颜色映射到 `SVG` 纹理区域，我们需要在选择的编辑器中绘制一个 `SVG` 图像。这涉及到为我们的 `ISVGColorMapper` 接口容易识别而将图像的不同部分进行颜色编码。下图显示了一个带有定义颜色值的形状，这些颜色值显示在图的左侧。

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_09_03.jpg)

+   实现 `ISVGColorMapper` 接口：

    在通过 `SVGBitmapTextureAtlasTextureRegionFactory` 创建 `SVG` 纹理区域之前，我们将根据我们的 `SVG` 图像定义 `ISVGColorMapper` 接口。如果我们查看以下代码中的条件语句，我们可以看到我们正在检查前一个图中找到的相同颜色值：

    ```kt
    ISVGColorMapper svgColorMapper = new ISVGColorMapper(){
      @Override
      public Integer mapColor(final Integer pColor) {
        // If the path contains no color channels, return null
        if(pColor == null) {
          return null;
        }

        // Obtain color values from 0-255
        int alpha = Color.alpha(pColor);
        int red = Color.red(pColor);
        int green = Color.green(pColor);
        int blue = Color.blue(pColor);

        // If the SVG image's color values equal red, or ARGB{0,255,0,0}
        if(red == 255 && green == 0 && blue == 0){
          // Return a pure blue color
          return Color.argb(0, 0, 0, 255);

        // If the SVG image's color values equal green, or ARGB{0,0,255,0}
        } else if(red == 0 && green == 255 && blue == 0){
          // Return a pure white
          return Color.argb(0, 255, 255, 255);

        // If the SVG image's color values equal blue, or ARGB{0,0,0,255}
        } else if(red == 0 && green == 0 && blue == 255){
          // Return a pure blue color
          return Color.argb(0, 0, 0, blue);

        // If the SVG image's color values are white, or ARGB{0,254,254,254}
        } else if(red == 254 && blue == 254 && green == 254){
          // Return a pure red color
          return Color.argb(0, 255, 0, 0);

        // If our "custom color" conditionals do not apply...
        } else {

          // Return the SVG image's default color values
          return Color.argb(alpha, red, green, blue);
        }
      }
    };

    // Create an SVG texture region
    mSVGTextureRegion = SVGBitmapTextureAtlasTextureRegionFactory.createFromAsset(bitmapTextureAtlas, this, "color_mapping.svg", 256,256, svgColorMapper); 
    ```

+   最后，一旦定义了接口，我们可以在创建纹理区域时将其作为最后一个参数传入。完成这一步后，使用 `SVG` 纹理区域创建新的精灵将产生颜色映射器中定义的颜色值。

## 工作原理…

在开始之前，先简单介绍一下颜色知识；如果你在看这个食谱的代码，并对我们为条件语句和颜色结果选择的*随机*值感到困惑，这非常简单。每个颜色成分（红色、绿色和蓝色）可以提供 0 到 255 之间的任何颜色值。将 0 值传递给颜色成分将导致该颜色没有贡献，而传递 255 则被认为是*完全*颜色贡献。考虑到这一点，我们知道如果所有颜色成分返回 0 值，我们将把黑色传递给纹理区域的路径。如果我们给红色成分传递 255 值，同时绿色和蓝色都传递 0，我们知道纹理区域的路径将会是明亮的红色。

如果我们回顾一下*如何操作...*部分中的图表，我们可以看到**alpha、红色、绿色和蓝色**（**ARGB**）的颜色值，以及指向它们代表的圆圈区域的箭头。这些不会直接影响我们纹理区域颜色的最终结果；它们的存在仅仅是为了让我们可以在颜色映射器界面中引用圆圈的每一部分。注意，圆圈最外层的部分是明亮的红色，值为 255。考虑到这一点，请看我们颜色映射器中的以下条件：

```kt
    // If the SVG image's color values equal red, or ARGB{0,255,0,0}
    } else if(red == 255 && green == 0 && blue == 0){
      // Return a pure blue color
      return Color.argb(0, 0, 0, 255);

    // If the SVG image's color values equal green, or ARGB{0,0,255,0}
    }
```

前一段代码中的条件语句将会检查`SVG`图像中是否包含没有任何绿色或蓝色贡献的纯红色值，并以纯蓝色替代。这就是颜色交换的原理，也是我们如何将颜色映射到图像中的方法！了解到这一点，我们完全有可能为我们的`SVG`图像创建许多不同的颜色集合，但针对每一组颜色，我们必须提供一个独立的纹理区域。

需要特别注意的一个重要关键是，我们应该包含一个返回值，当我们的条件都不满足时，它会返回默认路径的颜色值。这允许我们省略一些条件，比如`SVG`图像的轮廓或其他颜色等小细节，而是在我们喜欢的`SVG`编辑器中打开图像时按出现的颜色填充。这应该作为颜色映射器中的最后一个`else`语句包含：

```kt
    // If our "custom color" conditionals do not apply...
    } else {
      // Return the SVG image's default color values
      return Color.argb(alpha, red, green, blue);
    }
```

## 还有更多…

在本食谱的*工作原理...*部分，我们介绍了如何改变静态`SVG`图像路径的颜色。如果不深入考虑上述提到的创建颜色主题的想法，这听起来像是创建更多对象、地形、角色等的终极方法。但事实上，在当今时代，许多游戏需要变化以创造吸引人的资源。所谓的变化，当然是指渐变。回想我们上面编写的条件语句，我们在返回自定义颜色之前检查绝对的颜色值。

幸运的是，处理渐变并不太困难，因为我们可以调整渐变的**停止颜色**，而颜色之间的插值将自动为我们处理！我们可以将*停止点*视为定义渐变颜色的点，随着距离的增加，它在其他*停止点*之间进行插值。这就是产生渐变混合效果的原因，这也在通过本食谱中描述的相同方法创建颜色主题时发挥作用。以下是开始为纯红色`RGB{255, 0, 0}`，到纯绿色`RGB{0, 255, 0}`，最后到蓝色`RGB{0, 0, 255}`的渐变的屏幕截图：

![还有更多…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_09_04.jpg)

如果我们要在`SVG`图像中使用上述渐变，只需简单修改每个停止点的特定颜色位置，就可以轻松应用颜色映射以及颜色停止点之间的适当插值。以下代码将改变渐变，使其呈现红色、绿色和黄色，而不是将蓝色作为第三个颜色停止点：

```kt
    } else if(red == 0 && green == 0 && blue == 255){
      // Return a pure blue color
      return Color.argb(0, 255, 255, 0);
       }
```

## 另请参阅…

+   *使用 SVG 创建高分辨率图形*部分。


# 第十章：从 AndEngine 获取更多内容

本章将介绍比前几章更具体应用的附加食谱。这些食谱包括：

+   从文件夹加载所有纹理

+   使用纹理网格

+   应用基于精灵的阴影

+   创建基于物理的移动平台

+   创建基于物理的绳索桥梁

# 从文件夹加载所有纹理

当创建一个包含大量纹理的游戏时，逐个加载每个纹理可能会变得繁琐。在这种游戏中创建加载和检索纹理的方法不仅可以节省开发时间，还可以减少运行时的整体加载时间。在本食谱中，我们将创建一种使用单行代码加载大量纹理的方法。

## 准备就绪...

首先，创建一个名为`TextureFolderLoadingActivity`的新活动类，继承自`BaseGameActivity`类。接下来，在`assets/gfx/`文件夹中创建一个名为`FolderToLoad`的文件夹。最后，将五张图片放入`assets/gfx/FolderToLoad/`文件夹中，分别命名为：`Coin1`、`Coin5`、`Coin10`、`Coin50`和`Coin100`。

## 如何操作...

按照以下步骤填写我们的`TextureFolderLoadingActivity`活动类：

1.  在我们的活动中放置以下简单的代码使其功能化：

    ```kt
    @Override
    public EngineOptions onCreateEngineOptions() {
      return new EngineOptions(true,
        ScreenOrientation.LANDSCAPE_SENSOR, 
        new FillResolutionPolicy(), 
        new Camera(0, 0, 800, 480))
        .setWakeLockOptions(WakeLockOptions.SCREEN_ON);
    }
    @Override
    public void onCreateResources(OnCreateResourcesCallback
        pOnCreateResourcesCallback) {
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    @Override
    public void onCreateScene(OnCreateSceneCallback 
        pOnCreateSceneCallback) {
      Scene mScene = new Scene();
      mScene.setBackground(new Background(0.9f,0.9f,0.9f));
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    @Override
    public void onPopulateScene(Scene pScene, 
        OnPopulateSceneCallback pOnPopulateSceneCallback) {
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    ```

1.  接下来，将这个`ArrayList`变量和`ManagedStandardTexture`类放在活动内：

    ```kt
    public final ArrayList<ManagedStandardTexture> loadedTextures = 
      new ArrayList<ManagedStandardTexture>();
    public class ManagedStandardTexture {
      public ITextureRegion textureRegion;
      public String name;
      public ManagedStandardTexture(String pName, 
          final ITextureRegion pTextureRegion) {
        name = pName;
        textureRegion = pTextureRegion;
      }
      public void removeFromMemory() {
        loadedTextures.remove(this);
        textureRegion.getTexture().unload();
        textureRegion = null;
        name = null;
      }
    }
    ```

1.  然后，将下面两个方法添加到活动类中，以便我们通过只传递`TextureOptions`参数和文件名来加载纹理：

    ```kt
    public ITextureRegion getTextureRegion(TextureOptions 
          pTextureOptions, String pFilename) {
      loadAndManageTextureRegion(pTextureOptions,pFilename);
      return loadedTextures.get(
        loadedTextures.size()-1).textureRegion;
    }
    public void loadAndManageTextureRegion(TextureOptions 
          pTextureOptions, String pFilename) {
      AssetBitmapTextureAtlasSource cSource = 
        AssetBitmapTextureAtlasSource.create(
        this.getAssets(), pFilename);  
      BitmapTextureAtlas TextureToLoad = 
        new BitmapTextureAtlas(mEngine.getTextureManager(), 
          cSource.getTextureWidth(), 
          cSource.getTextureHeight(), 
          pTextureOptions);
      TextureRegion TextureRegionToLoad = 
        BitmapTextureAtlasTextureRegionFactory.
          createFromAsset(TextureToLoad, this, 
            pFilename, 0, 0);     
      TextureToLoad.load();
      loadedTextures.add(new ManagedStandardTexture(
        pFilename.substring(
          pFilename.lastIndexOf("/")+1, 
          pFilename.lastIndexOf(".")),
        TextureRegionToLoad));
    }
    ```

1.  现在，插入以下方法，允许我们加载单个或多个文件夹内的所有纹理：

    ```kt
    public void loadAllTextureRegionsInFolders(TextureOptions 
        pTextureOptions, String... pFolderPaths) {
      String[] listFileNames;
      String curFilePath;
      String curFileExtension;
      for (int i = 0; i < pFolderPaths.length; i++)
        try {
          listFileNames = this.getAssets().
            list(pFolderPaths[i].substring(0, 
            pFolderPaths[i].lastIndexOf("/")));
          for (String fileName : listFileNames) {
            curFilePath = 
              pFolderPaths[i].concat(fileName);
            curFileExtension = 
              curFilePath.substring(
              curFilePath.lastIndexOf("."));
            if(curFileExtension.
              equalsIgnoreCase(".png")
              || curFileExtension.
              equalsIgnoreCase(".bmp")
              || curFileExtension.
              equalsIgnoreCase(".jpg"))
              loadAndManageTextureRegion(
                pTextureOptions, 
                curFilePath);
          }
        } catch (IOException e) {
          System.out.print("Failed to load textures
            from folder!");
          e.printStackTrace();
          return;
        }
    }
    ```

1.  接着，将以下方法放入活动中，让我们可以卸载所有的`ManagedStandardTexture`类或通过其短文件名检索纹理：

    ```kt
    public void unloadAllTextures() {
      for(ManagedStandardTexture curTex : loadedTextures) {
        curTex.removeFromMemory();
        curTex=null;
        loadedTextures.remove(curTex);
      }
      System.gc();
    }

    public ITextureRegion getLoadedTextureRegion(String pName) {
      for(ManagedStandardTexture curTex : loadedTextures)
        if(curTex.name.equalsIgnoreCase(pName))
          return curTex.textureRegion;
      return null;
    }
    ```

1.  既然我们的活动类中已经有了所有方法，请在`onCreateResources()`方法中放置以下代码行：

    ```kt
    this.loadAllTextureRegionsInFolders(TextureOptions.BILINEAR, "gfx/FolderToLoad/");
    ```

1.  最后，在`onPopulateScene()`方法中添加以下代码，以展示我们如何通过名称检索已加载的纹理：

    ```kt
    pScene.attachChild(new Sprite(144f, 240f, 
      getLoadedTextureRegion("Coin1"), 
      this.getVertexBufferObjectManager()));
    pScene.attachChild(new Sprite(272f, 240f, 
      getLoadedTextureRegion("Coin5"), 
      this.getVertexBufferObjectManager()));
    pScene.attachChild(new Sprite(400f, 240f, 
      getLoadedTextureRegion("Coin10"), 
      this.getVertexBufferObjectManager()));
    pScene.attachChild(new Sprite(528f, 240f, 
      getLoadedTextureRegion("Coin50"), 
      this.getVertexBufferObjectManager()));
    pScene.attachChild(new Sprite(656f, 240f, 
      getLoadedTextureRegion("Coin100"), 
      this.getVertexBufferObjectManager()));
    ```

## 工作原理...

在第一步中，我们通过实现大多数 AndEngine 游戏使用的标准覆盖`BaseGameActivity`方法来设置我们的`TextureFolderLoadingActivity`活动类。有关为 AndEngine 设置活动更多信息，请参见第一章中的*了解生命周期*食谱，*AndEngine 游戏结构*。

在第二步中，我们创建一个`ManagedStandardTexture`对象的`ArrayList`变量，这个定义紧跟在`ArrayList`变量的定义之后。`ManagedStandardTextures`是简单的容器，它持有一个指向`ITextureRegion`区域的指针和一个表示`ITextureRegion`对象名称的字符串变量。`ManagedStandardTexture`类还包括一个卸载`ITextureRegion`的方法，并准备在下次垃圾收集时从内存中移除这些变量。

第三步包括两个方法，`getTextureRegion()`和`loadAndManageTextureRegion()`：

+   `getTextureRegion()`方法调用了`loadAndManageTextureRegion()`方法，并从第二步中定义的名为`loadedTextures`的`ArrayList`变量返回最近加载的纹理。

+   `loadAndManageTextureRegion()`方法创建了一个名为`cSource`的`AssetBitmapTextureAtlasSource`源，它仅用于在以下`BitmapTextureAtlas`对象`TextureToLoad`的定义中传递纹理的宽度和高度。

`TextureRegion`对象`TextureRegionToLoad`是通过调用`BitmapTextureAtlasTextureRegionFactory`对象的`createFromAsset()`方法创建的。然后加载`TextureToLoad`，并通过创建一个新的`ManagedStandardTexture`类，将`TextureRegionToLoad`对象添加到`loadedTextures` `ArrayList`变量中。有关纹理的更多信息，请参见第一章中的*不同类型的纹理*食谱，*AndEngine 游戏结构*。

在第四步中，我们创建了一个方法，该方法解析通过`pFolderPaths`数组传递的每个文件夹中的文件列表，并使用`TextureOptions`参数将图像文件加载为纹理。`listFileNames`字符串数组保存了`pFolderPaths`文件夹中每个文件夹的文件列表，`curFilePath`和`curFileExtension`变量用于存储文件路径及其相对扩展名，以便确定哪些文件是 AndEngine 支持的图像。第一个`for`循环简单地对每个给定的文件夹路径执行解析和加载过程。`getAssets().list()`方法抛出`IOException`异常，因此需要将其包含在`try-catch`块中。它用于获取通过传递的`String`参数中的所有文件列表。第二个`for`循环将`curFilePath`设置为当前`i`值的文件夹路径与`listFileNames`数组中的当前文件名拼接而成。接下来，`curFileExtension`字符串变量被设置为`curFilePath`变量的最后一个"。"索引，以返回扩展名，使用`substring()`方法。然后，我们检查以确保当前文件的扩展名等于 AndEngine 支持的扩展名，并在为`true`时调用`loadAndManageTextureRegion()`方法。最后，我们通过向日志发送消息并打印来自`IOException`异常的`StackTrace`消息来捕获`IOException`异常。

第五步包括两个方法，`unloadAllTextures()`和`getLoadedTextureRegion()`，它们协助我们管理通过我们之前的方法加载的纹理：

+   `unloadAllTextures()`方法遍历`loadedTextures` `ArrayList`对象中的所有`ManagedStandardTextures`，并使用`removeFromMemory()`方法卸载它们，在从`loadedTextures`中移除它们并请求系统进行垃圾回收之前。

+   `getLoadedTextureRegion()`方法检查`loadedTextures`变量中的每个`ManagedStandardTexture`，与`pName`字符串参数进行对比，如果名称相等，则返回当前`ManagedStandardTexture`类的`ITextureRegion`区域，否则如果没有匹配，则返回`null`。

第六步通过传递一个`BILINEAR` `TextureOption`参数和我们的`FolderToLoad`文件夹的资产文件夹路径，从`onCreateResources()`活动方法内部调用`loadAllTextureRegionsInFolders()`方法。有关`TextureOptions`的更多信息，请参见第一章，*AndEngine 游戏结构*中的*向我们的纹理应用选项*食谱。

在最后一步中，我们在`onPopulateScene()`活动方法内部将五个精灵附加到我们的场景中。每个精灵构造函数都调用`getLoadedTextureRegion()`方法，并传递精灵图像文件的相应简称。每个精灵的位置将它们放置在屏幕上的一条水平线上。一次性加载纹理的精灵显示应类似于以下图像。有关创建精灵的更多信息，请参见第二章，*使用实体*中的*向层中添加精灵*食谱。

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_01.jpg)

## 另请参阅

+   在第一章，*AndEngine 游戏结构*中的*理解生命周期*。

+   在第一章，*AndEngine 游戏结构*中的*不同类型的纹理*。

+   在第一章，*AndEngine 游戏结构*中的*向我们的纹理应用选项*。

+   在第二章，*使用实体*中的*向层中添加精灵*。

# 使用纹理网格

**纹理网格**，即简单应用了纹理的三角剖分多边形，在移动游戏中越来越受欢迎，因为它们允许创建和非矩形形状的操作。具有处理纹理网格的能力通常创建了一个额外的游戏机制层，这些机制以前实现起来成本过高。在本食谱中，我们将学习如何从一组预定的三角形创建纹理网格。

## 准备就绪...

首先，创建一个名为`TexturedMeshActivity`的新活动类，继承自`BaseGameActivity`。接下来，将一个名为`dirt.png`的无缝拼接纹理，尺寸为 512 x 128，放在我们项目的`assets/gfx/`文件夹中。最后，将代码包中的`TexturedMesh.java`类导入到我们的项目中。

## 如何操作...

按照以下步骤构建我们的`TexturedMeshActivity`活动类：

1.  在我们的活动中放置以下代码，以获得一个标准的 AndEngine 活动：

    ```kt
    @Override
    public EngineOptions onCreateEngineOptions() {
      return new EngineOptions(true,
        ScreenOrientation.LANDSCAPE_SENSOR, 
        new FillResolutionPolicy(), 
        new Camera(0, 0, 800, 480))
        .setWakeLockOptions(WakeLockOptions.SCREEN_ON);
    }
    @Override
    public void onCreateResources(OnCreateResourcesCallback
        pOnCreateResourcesCallback) {
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    @Override
    public void onCreateScene(OnCreateSceneCallback 
        pOnCreateSceneCallback) {
      Scene mScene = new Scene();
      mScene.setBackground(new Background(0.9f,0.9f,0.9f));
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    @Override
    public void onPopulateScene(Scene pScene, 
        OnPopulateSceneCallback pOnPopulateSceneCallback) {
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    ```

1.  在`onPopulateScene()`方法中添加以下代码片段：

    ```kt
    BitmapTextureAtlas texturedMeshT = new BitmapTextureAtlas(
      this.getTextureManager(), 512, 128, 
      TextureOptions.REPEATING_BILINEAR);
    ITextureRegion texturedMeshTR = 
      BitmapTextureAtlasTextureRegionFactory.
      createFromAsset(texturedMeshT, this, "gfx/dirt.png", 0, 0);
    texturedMeshT.load();
    float[] meshTriangleVertices = {
        24.633111f,37.7835047f,-0.00898f,113.0324447f,
        -24.610162f,37.7835047f,0.00387f,-37.7900953f,
        -103.56176f,37.7901047f,103.56176f,37.7795047f,
        0.00387f,-37.7900953f,-39.814736f,-8.7311953f,
        -64.007044f,-83.9561953f,64.00771f,-83.9621953f,
        39.862562f,-8.7038953f,0.00387f,-37.7900953f};
    float[] meshBufferData = new float[TexturedMesh.VERTEX_SIZE * 
      (meshTriangleVertices.length/2)];
    for( int i = 0; i < meshTriangleVertices.length/2; i++) {
      meshBufferData[(i * TexturedMesh.VERTEX_SIZE) + 
        TexturedMesh.VERTEX_INDEX_X] = 
        meshTriangleVertices[i*2];
      meshBufferData[(i * TexturedMesh.VERTEX_SIZE) + 
        TexturedMesh.VERTEX_INDEX_Y] = 
        meshTriangleVertices[i*2+1];
    }
    TexturedMesh starTexturedMesh = new TexturedMesh(400f, 225f, 
      meshBufferData, 12, DrawMode.TRIANGLES, texturedMeshTR, 
      this.getVertexBufferObjectManager());
    pScene.attachChild(starTexturedMesh);
    ```

## 工作原理...

在第一步中，我们准备`TexturedMeshActivity`类，通过插入大多数 AndEngine 游戏使用的标准的重写`BaseGameActivity`方法。有关使用 AndEngine 设置活动的更多信息，请参见第一章，*Understanding the life cycle*部分。

在第二步中，我们首先定义了`texturedMeshT`，这是一个`BitmapTextureAtlas`对象，构造函数的最后一个参数是`REPEATING_BILINEAR` `TextureOption`，用于创建一个在构成我们纹理网格的三角形中无缝平铺的纹理。有关`TextureOptions`的更多信息，请参见第一章，*Applying options to our textures*部分。

创建了`texturedMeshTR` `ITextureRegion`对象并加载了我们的`texturedMeshT`对象之后，我们定义了一个浮点数数组，用于指定构成我们纹理网格的每个三角形的每个顶点的相对连续的 x 和 y 位置。以下图片将更好地展示如何在纹理网格中使用三角形的顶点：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_02.jpg)

接下来，我们创建`meshBufferData`浮点数组，并将其大小设置为`TexturedMesh`类的顶点大小乘以`meshTriangleVertices`数组中的顶点数——一个顶点在数组中占用两个索引，`X`和`Y`，因此我们必须将长度除以`2`。然后，对于`meshTriangleVertices`数组中的每个顶点，我们将顶点的位置应用到`meshBufferData`数组中。最后，我们创建名为`starTexturedMesh`的`TexturedMesh`对象。`TexturedMesh`构造函数的参数如下：

+   构造函数的前两个参数是`400f`，`225f`的 x 和 y 位置。

+   接下来的两个参数是`meshBufferData`缓冲数据和我们在`meshBufferData`数组中放置的顶点数，`12`。

+   `TexturedMesh`构造函数的最后三个参数是`Triangles`的`DrawMode`、网格的`ITextureRegion`和我们`VertexBufferObjectManager`对象。

有关创建`Meshes`的更多信息，从中派生出`TexturedMesh`类，请参见第二章，*Applying primitives to a layer*部分。

## 参见以下内容

+   在第一章，*AndEngine 游戏结构*中，了解生命周期，即*Understanding the life cycle*。

+   在第一章，*AndEngine 游戏结构*中，我们讨论了如何将选项应用到我们的纹理中，即*Applying options to our textures*。

+   在第二章，*Working with Entities*中，我们讨论了如何将图元应用到图层，即*Applying primitives to a layer*。

# 应用基于精灵的阴影

在游戏中添加阴影可以增加视觉深度，使游戏更具吸引力。简单地在对象下方放置一个带有阴影纹理的精灵是一种快速有效的处理阴影创建的方法。在本章中，我们将学习如何保持阴影与其父对象正确对齐的同时完成这一工作。

## 准备就绪...

首先，创建一个名为`SpriteShadowActivity`的新活动类，该类继承自`BaseGameActivity`并实现`IOnSceneTouchListener`。接下来，将大小为 256 x 128 且名为`shadow.png`的阴影图像放入`assets/gfx/`文件夹中。最后，将大小为 128 x 256 且名为`character.png`的角色图像放入`assets/gfx/`文件夹中。

## 如何操作...

按照以下步骤构建我们的`SpriteShadowActivity`活动类：

1.  在我们的活动类中放入以下标准的 AndEngine 活动代码：

    ```kt
    @Override
    public EngineOptions onCreateEngineOptions() {
      EngineOptions engineOptions = new EngineOptions(true, 
        ScreenOrientation.LANDSCAPE_SENSOR, 
        new FillResolutionPolicy(), 
        new Camera(0, 0, 800, 480))
        .setWakeLockOptions(WakeLockOptions.SCREEN_ON);
      engineOptions.getRenderOptions().setDithering(true);
      return engineOptions;
    }
    @Override
    public void onCreateResources(OnCreateResourcesCallback 
        pOnCreateResourcesCallback) {
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    @Override
    public void onCreateScene(OnCreateSceneCallback 
        pOnCreateSceneCallback) {
      Scene mScene = new Scene();
      mScene.setBackground(new Background(0.8f,0.8f,0.8f));
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    @Override
    public void onPopulateScene(Scene pScene, OnPopulateSceneCallback 
        pOnPopulateSceneCallback) {
      pScene.setOnSceneTouchListener(this);
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    @Override
    public boolean onSceneTouchEvent(Scene pScene, 
        TouchEvent pSceneTouchEvent) {
      return true;
    }
    ```

1.  接下来，在我们的活动中放置这些变量，以便我们具体控制阴影：

    ```kt
    Static final float CHARACTER_START_X = 400f;
    static final float CHARACTER_START_Y = 128f;
    static final float SHADOW_OFFSET_X = 0f;
    static final float SHADOW_OFFSET_Y = -64f;
    static final float SHADOW_MAX_ALPHA = 0.75f;
    static final float SHADOW_MIN_ALPHA = 0.1f;
    static final float SHADOW_MAX_ALPHA_HEIGHT = 200f;
    static final float SHADOW_MIN_ALPHA_HEIGHT = 0f;
    static final float SHADOW_START_X = CHARACTER_START_X + SHADOW_OFFSET_X;
    static final float SHADOW_START_Y = CHARACTER_START_Y + SHADOW_OFFSET_Y;
    static final float CHARACTER_SHADOW_Y_DIFFERENCE = 
      CHARACTER_START_Y - SHADOW_START_Y;
    static final float SHADOW_ALPHA_HEIGHT_DIFFERENCE = 
      SHADOW_MAX_ALPHA_HEIGHT - SHADOW_MIN_ALPHA_HEIGHT;
    static final float SHADOW_ALPHA_DIFFERENCE = 
      SHADOW_MAX_ALPHA - SHADOW_MIN_ALPHA;
    Sprite shadowSprite;
    Sprite characterSprite;
    ```

1.  现在，将以下方法放入我们的活动中，使阴影的 alpha 值与角色与阴影的距离成反比：

    ```kt
    public void updateShadowAlpha() {
      shadowSprite.setAlpha(MathUtils.bringToBounds(
        SHADOW_MIN_ALPHA, SHADOW_MAX_ALPHA, 
        SHADOW_MAX_ALPHA - ((((characterSprite.getY()-
        CHARACTER_SHADOW_Y_DIFFERENCE)-SHADOW_START_Y) / 
        SHADOW_ALPHA_HEIGHT_DIFFERENCE) * 
        SHADOW_ALPHA_DIFFERENCE)));
    }
    ```

1.  在`onSceneTouchEvent()`方法中插入以下代码片段：

    ```kt
    if(pSceneTouchEvent.isActionDown() || 
        pSceneTouchEvent.isActionMove()) {
      characterSprite.setPosition(
        pSceneTouchEvent.getX(), 
        Math.max(pSceneTouchEvent.getY(), 
          CHARACTER_START_Y));
    }
    ```

1.  最后，用以下代码片段填充`onPopulateScene()`方法：

    ```kt
    BitmapTextureAtlas characterTexture = 
      new BitmapTextureAtlas(this.getTextureManager(), 128, 256, 
        TextureOptions.BILINEAR);
    TextureRegion characterTextureRegion = 
      BitmapTextureAtlasTextureRegionFactory.createFromAsset(
        characterTexture, this, "gfx/character.png", 0, 0);
    characterTexture.load();
    BitmapTextureAtlas shadowTexture = 
      new BitmapTextureAtlas(this.getTextureManager(), 256, 128, 
        TextureOptions.BILINEAR);
    TextureRegion shadowTextureRegion = 
      BitmapTextureAtlasTextureRegionFactory.createFromAsset(
        shadowTexture, this, "gfx/shadow.png", 0, 0);
    shadowTexture.load();
    shadowSprite = new Sprite(SHADOW_START_X, SHADOW_START_Y, 
      shadowTextureRegion,this.getVertexBufferObjectManager());
    characterSprite = new Sprite(CHARACTER_START_X, CHARACTER_START_Y, 
      characterTextureRegion,this.getVertexBufferObjectManager()) 
      {
      @Override
      public void setPosition(final float pX, final float pY) {
        super.setPosition(pX, pY);
        shadowSprite.setPosition(
          pX + SHADOW_OFFSET_X, shadowSprite.getY());
        updateShadowAlpha();
      }
    };
    pScene.attachChild(shadowSprite);
    pScene.attachChild(characterSprite);
    updateShadowAlpha();
    ```

## 它是如何工作的...

在第一步中，我们通过实现大多数 AndEngine 游戏使用的标准覆盖`BaseGameActivity`方法来设置我们的`SpriteShadowActivity`活动类。有关使用 AndEngine 设置活动的更多信息，请参见第一章中的*了解生命周期*部分，*AndEngine 游戏结构*。

下图展示了这个方法是如何将我们的阴影精灵放置在角色精灵的关系位置上的：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_03.jpg)

在第二步中，我们定义了几个常量，这些常量将控制阴影精灵`shadowSprite`与角色精灵`characterSprite`的对齐方式：

+   前两个常量`CHARACTER_START_X`和`CHARACTER_START_Y`设置了`characterSprite`的初始位置。

+   接下来的两个常量`SHADOW_OFFSET_X`和`SHADOW_OFFSET_Y`控制了阴影与角色精灵在 x 和 y 轴上的初始位置距离。

+   `SHADOW_OFFSET_X`常量也用于在移动角色精灵时更新阴影精灵的位置。

接下来的四个常量控制了`shadowSprite`精灵的 alpha 值如何被控制以及控制到什么程度：

+   `SHADOW_MAX_ALPHA`和`SHADOW_MIN_ALPHA`设置了 alpha 值的绝对最大和最小值，这会根据角色与阴影在 y 轴上的距离而改变。距离越远，`shadowSprite`的 alpha 值越低，直至达到最低水平。

+   `SHADOW_MAX_ALPHA_HEIGHT`常量表示角色与阴影的距离在影响`shadowSprite`的 alpha 值之前，可以达到的最大距离，之后默认为`SHADOW_MIN_ALPHA`。

+   `SHADOW_MIN_ALPHA_HEIGHT` 常量表示角色距离阴影的最小距离，该距离会影响阴影的透明度变化。如果 `SHADOW_MIN_ALPHA_HEIGHT` 大于 `0`，当角色距离阴影低于 `SHADOW_MIN_ALPHA_HEIGHT` 时，阴影的透明度将处于最大值。

剩余的常量会从之前的集合中自动计算得出。`SHADOW_START_X` 和 `SHADOW_START_Y` 代表 `shadowSprite` 图像的起始位置。它们是通过将阴影的偏移值加到角色的起始位置来计算的。`CHARACTER_SHADOW_Y_DIFFERENCE` 常量表示角色与阴影在 y 轴上的初始起始距离。`SHADOW_ALPHA_HEIGHT_DIFFERENCE` 常量表示最小高度和最大高度之间的差，用于在运行时调节阴影的透明度。最后的常量 `SHADOW_ALPHA_DIFFERENCE` 表示 `shadowSprite` 图像的最小和最大透明度水平之间的差。与 `SHADOW_ALPHA_HEIGHT_DIFFERENCE` 常量类似，它在运行时用于确定阴影的透明度水平。

在第二步中的最后两个变量 `shadowSprite` 和 `characterSprite` 分别代表我们场景中的阴影和角色。

在第三步中，我们创建一个方法来更新阴影的透明度。我们调用 `shadowSprite.setAlpha()` 方法，并以 `MathUtils.bringToBounds()` 方法作为参数。`MathUtils.bringToBounds()` 方法接受一个最小值和最大值，确保第三个值在这个范围内。我们将 `SHADOW_MIN_ALPHA` 和 `SHADOW_MAX_ALPHA` 常量作为 `bringToBounds()` 方法的头两个参数传递。

第三个参数是基于 `characterSprite` 图像与 `shadowSprite` 图像之间的距离确定阴影透明度的算法。该算法首先从角色的 y 轴位置减去 `CHARACTER_SHADOW_Y_DIFFERENCE` 常量。这为我们提供了当前影响阴影透明度的 y 值的上限。接下来，我们从 y 轴上的阴影起始位置减去该值，以得到当前角色与阴影的理想距离。然后，我们将该距离除以 `SHADOW_ALPHA_HEIGHT_DIFFERENCE`，以得到约束距离到透明度的单位比率，并将该比率乘以 `SHADOW_ALPHA_DIFFERENCE` 常量，以得到约束距离到约束透明度的单位比率。目前，我们的比率是倒置的，随着距离的增加会提高透明度，这与我们随着角色移动更远而降低透明度的目标相反，因此我们从 `SHADOW_MAX_ALPHA` 常量中减去它，以得到随着距离增加而降低透明度的正确比率。完成算法后，我们使用 `bringToBounds()` 方法确保算法产生的透明度值被限制在 `SHADOW_MIN_ALPHA` 到 `SHADOW_MAX_ALPHA` 的范围内。

第四步通过检查触摸事件的 `isActionDown()` 和 `isActionMove()` 属性，设置在屏幕首次触摸或触摸移动时 `characterSprite` 精灵的位置。在这种情况下，`setPosition()` 方法简单地将 x 值设置为触摸的 x 值，将 y 值设置为触摸的 y 值或角色的起始 y 值，以较大者为准。

在最后一步中，我们加载 `TextureRegions`、`characterTextureRegion` 和 `shadowTextureRegion` 对象，用于角色和阴影。关于 `TextureRegions` 的更多信息，请参见第一章，*AndEngine 游戏结构*中的*不同类型的纹理*食谱。然后，我们使用它们的起始常量作为构造函数中的位置创建 `shadowSprite` 和 `characterSprite` 精灵。对于 `characterSprite`，我们重写 `setPosition()` 方法，也设置偏移 x 后的 `shadowSprite` 精灵的位置，然后调用 `updateShadowAlpha()` 方法，以在角色移动后为阴影设置适当的 alpha 值。最后，我们将 `shadowSprite` 和 `characterSprite` 精灵附加到我们的场景中，并调用 `updateShadowAlpha()` 方法设置阴影的初始 alpha 值。以下图片显示了阴影的 alpha 级别如何相对于角色距离的变化而改变：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_04.jpg)

## 另请参阅

+   在第一章，*AndEngine 游戏结构*中了解*生命周期*。

+   在第一章，*AndEngine 游戏结构*中了解*不同类型的纹理*。

# 创建基于物理的移动平台

大多数平台风格的游戏都有某种移动平台，这挑战玩家以准确的时机着陆。从开发者的角度来看，平台只是一个从一处移动到另一处的物理启用的物体。在本教程中，我们将了解如何创建一个水平移动的平台。

## 准备就绪...

创建一个名为 `MovingPhysicsPlatformActivity` 的新活动类，该类继承自 `BaseGameActivity`。

## 如何操作...

按照以下步骤构建我们的 `MovingPhysicsPlatformActivity` 活动类：

1.  在我们的活动中插入以下代码段以使其功能正常：

    ```kt
    @Override
    public Engine onCreateEngine(final EngineOptions pEngineOptions) {
      return new FixedStepEngine(pEngineOptions, 60);
    }
    @Override
    public EngineOptions onCreateEngineOptions() {
      return new EngineOptions(true, 
        ScreenOrientation.LANDSCAPE_SENSOR, 
        new FillResolutionPolicy(), 
        new Camera(0, 0, 800, 480)
        ).setWakeLockOptions(WakeLockOptions.SCREEN_ON);
    }
    @Override
    public void onCreateResources(OnCreateResourcesCallback 
        pOnCreateResourcesCallback) {
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    @Override
    public void onCreateScene(OnCreateSceneCallback 
        pOnCreateSceneCallback) {
      Scene mScene = new Scene();
      mScene.setBackground(new Background(0.9f,0.9f,0.9f));
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    @Override
    public void onPopulateScene(Scene pScene, OnPopulateSceneCallback 
        pOnPopulateSceneCallback) {
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    ```

1.  在 `onPopulateScene()` 方法中添加以下代码段：

    ```kt
    FixedStepPhysicsWorld mPhysicsWorld = 
      new FixedStepPhysicsWorld(60, 
      new Vector2(0,-SensorManager.GRAVITY_EARTH*2f), 
      false, 8, 3); 
    pScene.registerUpdateHandler(mPhysicsWorld);
    Rectangle platformRect = new Rectangle(400f, 200f, 250f, 20f, 
      this.getVertexBufferObjectManager());
    platformRect.setColor(0f, 0f, 0f);
    final FixtureDef platformFixtureDef = 
      PhysicsFactory.createFixtureDef(20f, 0f, 1f);
    final Body platformBody = PhysicsFactory.createBoxBody( 
      mPhysicsWorld, platformRect, BodyType.KinematicBody, 
      platformFixtureDef);
    mPhysicsWorld.registerPhysicsConnector(
      new PhysicsConnector(platformRect, platformBody));
    pScene.attachChild(platformRect);
    float platformRelativeMinX = -200f;
    float platformRelativeMaxX = 200f;
    final float platformVelocity = 3f;
    final float platformMinXWorldCoords = 
      (platformRect.getX() + platformRelativeMinX) / 
      PhysicsConstants.PIXEL_TO_METER_RATIO_DEFAULT;
    final float platformMaxXWorldCoords = 
      (platformRect.getX() + platformRelativeMaxX) / 
      PhysicsConstants.PIXEL_TO_METER_RATIO_DEFAULT;
    platformBody.setLinearVelocity(platformVelocity, 0f);
    ```

1.  在 `onPopulateScene()` 方法中的前一行代码下面直接插入以下代码：

    ```kt
    pScene.registerUpdateHandler(new IUpdateHandler() {
      @Override
      public void onUpdate(float pSecondsElapsed) {
        if(platformBody.getWorldCenter().x > 
            platformMaxXWorldCoords) {
          platformBody.setTransform(
            platformMaxXWorldCoords,
            platformBody.getWorldCenter().y,
            platformBody.getAngle());
          platformBody.setLinearVelocity(
            -platformVelocity, 0f);
        } else if(platformBody.getWorldCenter().x < 
            platformMinXWorldCoords) {
          platformBody.setTransform(
            platformMinXWorldCoords,
            platformBody.getWorldCenter().y,
            platformBody.getAngle());
          platformBody.setLinearVelocity(
            platformVelocity, 0f);
        }
      }
      @Override
      public void reset() {}
    });
    ```

1.  在 `onPopulateScene()` 方法中完成我们的活动，通过在前一行代码之后放置以下代码来创建一个在平台上休息的物理启用的盒子：

    ```kt
    Rectangle boxRect = new Rectangle(400f, 240f, 60f, 60f, 
      this.getVertexBufferObjectManager());
    boxRect.setColor(0.2f, 0.2f, 0.2f);
    FixtureDef boxFixtureDef = 
      PhysicsFactory.createFixtureDef(200f, 0f, 1f);
    mPhysicsWorld.registerPhysicsConnector(
      new PhysicsConnector(boxRect,
        PhysicsFactory.createBoxBody( mPhysicsWorld, boxRect, 
        BodyType.DynamicBody, boxFixtureDef)));
    pScene.attachChild(boxRect);
    ```

## 工作原理...

在第一步中，我们准备`MovingPhysicsPlatformActivity`类，通过向其中插入大多数 AndEngine 游戏使用的标准覆盖`BaseGameActivity`方法。关于如何为 AndEngine 设置活动的更多信息，请参见第一章中的*了解生命周期*一节，*AndEngine 游戏结构*。以下图片展示了我们的平台如何在单轴上移动，在本例中是向右移动，同时保持上面的盒子：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_05.jpg)

在第二步中，我们首先创建一个`FixedStepPhysicsWorld`对象，并将其注册为场景的更新处理器。然后，我们创建一个名为`platformRect`的`Rectangle`对象，它将代表我们的移动平台，并将其放置在屏幕中心附近。接下来，我们使用`setColor()`方法将`platformRect`矩形的颜色设置为黑色，红色、绿色和蓝色的浮点参数值为`0f`。然后，我们为平台创建一个固定装置定义。注意，摩擦力设置为`1f`，以防止物体在平台移动时滑动过多。

接下来，我们为平台创建一个名为`platformBody`的`Body`对象。然后，我们注册一个`PhysicsConnector`类，将`platformRect`矩形连接到`platformBody`对象。将`platformRect`附加到我们的场景后，我们声明并设置将控制移动平台的变量：

+   `platformRelativeMinX`和`platformRelativeMaxX`变量表示平台从其起始位置向左和向右移动的场景单位距离。

+   `platformVelocity`变量表示我们物理平台物体的速度，单位为每秒米。

+   接下来的两个变量`platformMinXWorldCoords`和`platformMaxXWorldCoords`表示`platformRelativeMinX`和`platformRelativeMaxX`变量的绝对位置，并从平台的初始 x 位置按默认的`PIXEL_TO_METER_RATIO_DEFAULT`比例计算得出。

+   最后，我们将`platformBody`的初始速度设置为`platformVelocity`变量，以使物体在场景首次绘制时立即主动移动。关于创建物理模拟的更多信息，请参见第六章中的*Box2D 物理扩展介绍*和*了解不同的物体类型*一节。

第三步，我们向场景注册一个新的`IUpdateHandler`处理器。在`onUpdate()`方法中，我们测试平台的位置是否超出了之前定义的绝对边界`platformMinXWorldCoords`和`platformMaxXWorldCoords`。根据达到的绝对边界，我们将`platformBody`的位置设置到达到的边界，并将其速度设置为远离边界。关于条件更新处理器的更多信息，请参见第七章中的*更新处理器与条件*部分。

在第四步中，我们创建并附加一个盒子物体，使其在平台上休息。关于如何创建具有物理效果的盒子，请参考第六章中的*了解不同的物体类型*部分。

## 另请参阅

+   在第一章中了解*生命周期*。

+   在第六章中查看*Box2D 物理扩展介绍*。

+   在第六章中了解*不同的物体类型*。

+   在第七章中查看*更新处理器与条件*。

# 创建基于物理的绳索桥梁

使用 Box2D 物理扩展，创建复杂的物理效果元素很简单。一个这样的复杂元素例子就是能对碰撞做出反应的绳索桥梁。在本教程中，我们将看到如何实现一个根据特定参数创建绳索桥梁的方法，这些参数控制着桥梁的大小和物理属性。

## 准备工作...

创建一个名为`PhysicsBridgeActivity`的新活动类，该类继承自`BaseGameActivity`。

## 如何操作...

按照以下步骤构建我们的`PhysicsBridgeActivity`活动类：

1.  在我们的活动中放置以下代码，以获得标准的 AndEngine 活动：

    ```kt
    @Override
    public Engine onCreateEngine(final EngineOptions pEngineOptions) {
      return new FixedStepEngine(pEngineOptions, 60);
    }
    @Override
    public EngineOptions onCreateEngineOptions() {
      return new EngineOptions(true, 
        ScreenOrientation.LANDSCAPE_SENSOR,
        new FillResolutionPolicy(), 
        new Camera(0, 0, 800, 480))
        .setWakeLockOptions(WakeLockOptions.SCREEN_ON);
    }
    @Override
    public void onCreateResources(OnCreateResourcesCallback 
        pOnCreateResourcesCallback) {
      pOnCreateResourcesCallback.onCreateResourcesFinished();
    }
    @Override
    public void onCreateScene(OnCreateSceneCallback 
        pOnCreateSceneCallback) {
      Scene mScene = new Scene();
      mScene.setBackground(new Background(0.9f,0.9f,0.9f));
      pOnCreateSceneCallback.onCreateSceneFinished(mScene);
    }
    @Override
    public void onPopulateScene(Scene pScene, OnPopulateSceneCallback 
        pOnPopulateSceneCallback) {
      pOnPopulateSceneCallback.onPopulateSceneFinished();
    }
    ```

1.  接下来，在我们的活动中放置以下不完整的方法。这个方法将有助于我们创建桥梁：

    ```kt
    public void createBridge(Body pGroundBody,
        final float[] pLeftHingeAnchorPoint, 
        final float pRightHingeAnchorPointX, 
        final int pNumSegments, 
        final float pSegmentsWidth, 
        final float pSegmentsHeight,
        final float pSegmentDensity, 
        final float pSegmentElasticity,
        final float pSegmentFriction, 
        IEntity pScene, PhysicsWorld pPhysicsWorld, 
        VertexBufferObjectManager 
          pVertexBufferObjectManager) {
      final Rectangle[] BridgeSegments = 
        new Rectangle[pNumSegments];
      final Body[] BridgeSegmentsBodies = new Body[pNumSegments];
      final FixtureDef BridgeSegmentFixtureDef =
        PhysicsFactory.createFixtureDef(
        pSegmentDensity, pSegmentElasticity, 
        pSegmentFriction);
      final float BridgeWidthConstant = pRightHingeAnchorPointX – 
        pLeftHingeAnchorPoint[0] + pSegmentsWidth;
      final float BridgeSegmentSpacing = (
        BridgeWidthConstant / (pNumSegments+1) – 
        pSegmentsWidth/2f);
      for(int i = 0; i < pNumSegments; i++) {

      }
    }
    ```

1.  在上述`createBridge()`方法中的`for`循环内插入以下代码：

    ```kt
    BridgeSegments[i] = new Rectangle(
      ((BridgeWidthConstant / (pNumSegments+1))*i) + 
        pLeftHingeAnchorPoint[0] + BridgeSegmentSpacing, 
      pLeftHingeAnchorPoint[1]-pSegmentsHeight/2f,
      pSegmentsWidth, pSegmentsHeight, 
      pVertexBufferObjectManager);
    BridgeSegments[i].setColor(0.97f, 0.75f, 0.54f);
    pScene.attachChild(BridgeSegments[i]);
    BridgeSegmentsBodies[i] = PhysicsFactory.createBoxBody(
      pPhysicsWorld, BridgeSegments[i], BodyType.DynamicBody, 
      BridgeSegmentFixtureDef);
    BridgeSegmentsBodies[i].setLinearDamping(1f);
    pPhysicsWorld.registerPhysicsConnector(
      new PhysicsConnector(BridgeSegments[i], 
        BridgeSegmentsBodies[i]));
    final RevoluteJointDef revoluteJointDef = new RevoluteJointDef();
    if(i==0) {
      Vector2 anchorPoint = new Vector2(
        BridgeSegmentsBodies[i].getWorldCenter().x – 
          (BridgeSegmentSpacing/2 + pSegmentsWidth/2)/ 
          PhysicsConstants.PIXEL_TO_METER_RATIO_DEFAULT, 
        BridgeSegmentsBodies[i].getWorldCenter().y);
      revoluteJointDef.initialize(pGroundBody, 
        BridgeSegmentsBodies[i], anchorPoint);
    } else {
      Vector2 anchorPoint = new Vector2(
        (BridgeSegmentsBodies[i].getWorldCenter().x + 
          BridgeSegmentsBodies[i-1]
          .getWorldCenter().x)/2, 
        BridgeSegmentsBodies[i].getWorldCenter().y);
      revoluteJointDef.initialize(BridgeSegmentsBodies[i-1], 
        BridgeSegmentsBodies[i], anchorPoint);
    }
    pPhysicsWorld.createJoint(revoluteJointDef);
    if(i==pNumSegments-1) {
      Vector2 anchorPoint = new Vector2(BridgeSegmentsBodies[i].getWorldCenter().x + (BridgeSegmentSpacing/2 + pSegmentsWidth/2)/PhysicsConstants.PIXEL_TO_METER_RATIO_DEFAULT, BridgeSegmentsBodies[i].getWorldCenter().y);
      revoluteJointDef.initialize(pGroundBody, BridgeSegmentsBodies[i], anchorPoint);
      pPhysicsWorld.createJoint(revoluteJointDef);
    }
    ```

1.  最后，在我们的`onPopulateScene()`方法内添加以下代码：

    ```kt
    final FixedStepPhysicsWorld mPhysicsWorld = new FixedStepPhysicsWorld(60, new Vector2(0,-SensorManager.GRAVITY_EARTH), false, 8, 3);
    pScene.registerUpdateHandler(mPhysicsWorld);

    FixtureDef groundFixtureDef = PhysicsFactory.createFixtureDef(0f, 0f, 0f);
    Body groundBody = PhysicsFactory.createBoxBody(mPhysicsWorld, 0f, 0f, 0f, 0f, BodyType.StaticBody, groundFixtureDef);

    createBridge(groundBody, new float[] {0f,240f}, 800f, 16, 40f, 10f, 4f, 0.1f, 0.5f, pScene, mPhysicsWorld, this.getVertexBufferObjectManager());

    Rectangle boxRect = new Rectangle(100f,400f,50f,50f,this.getVertexBufferObjectManager());
    FixtureDef boxFixtureDef = PhysicsFactory.createFixtureDef(25f, 0.5f, 0.5f);
    mPhysicsWorld.registerPhysicsConnector(new PhysicsConnector(boxRect, PhysicsFactory.createBoxBody(mPhysicsWorld, boxRect, BodyType.DynamicBody, boxFixtureDef)));
    pScene.attachChild(boxRect);
    ```

## 工作原理...

在第一步中，我们通过实现大多数 AndEngine 游戏使用的标准覆盖`BaseGameActivity`方法来设置`PhysicsBridgeActivity`活动类。关于如何为 AndEngine 设置活动，请参考第一章中的*了解生命周期*部分。以下图片展示了我们带有物理效果的桥梁，以及一个带有物理效果的方块在其上休息的样子：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_10_06.jpg)

在第二步中，我们实现了一个名为`createBridge()`的方法的开头，该方法将创建具有物理效果的桥。第一个参数`pGroundBody`是桥将附加到的地面`Body`对象。第二个参数`pLeftHingeAnchorPoint`表示桥左上侧的 x 和 y 位置。第三个参数`pRightHingeAnchorPointX`表示桥右侧的 x 位置。接下来的三个参数`pNumSegments`、`pSegmentsWidth`和`pSegmentsHeight`表示桥将由多少个桥段组成以及每个桥段的宽度和高度。`pSegmentDensity`、`pSegmentElasticity`和`pSegmentFriction`参数将直接传递给一个夹具定义，该定义将应用于桥的桥段。有关夹具定义的更多信息，请参见第六章，*物理应用*中的*Box2D 物理扩展介绍*食谱。接下来的两个参数`pScene`和`pPhysicsWorld`告诉我们的方法桥段矩形和桥段实体应该附加到什么上。最后一个参数是我们的`VertexBufferObjectManager`对象，它将被传递给表示我们桥每个段的矩形。

在`createBridge()`方法中定义的前两个变量，`BridgeSegments`和`BridgeSegmentsBodies`，是用于保存桥段矩形和桥段实体的数组。它们的长度由`pNumSegments`参数传递定义。下一个变量，`BridgeSegmentFixtureDef`，是每个桥段将拥有的夹具定义。`BridgeWidthConstant`变量表示桥的宽度，通过计算左侧和右侧锚点加上桥的单个桥段宽度之差得出。最后一个变量，`BridgeSegmentSpacing`，表示每个桥段之间应有的空间，通过将桥的宽度除以桥段数量加一，然后减去桥段半宽度得出。然后我们创建一个`for`循环，该循环将根据`pNumSegments`参数传递的数量创建并定位桥段。

在第三步中，我们填充之前创建的`for`循环。首先，我们创建当前桥段的矩形`BridgeSegments[i]`，它将作为桥段的视觉表示。我们将其放置在 x 轴上，使用`BridgeWidthConstant`变量除以桥段数量加一，然后乘以当前桥段编号，并加上左侧铰链的 x 位置`pLeftHingeAnchorPoint[0]`和桥段之间的间距`BridgeSegmentSpacing`。对于当前桥段矩形的 y 轴位置，我们将其放置在左侧铰链的 y 位置减去桥段高度除以`2f`的位置，使其与铰链位置平齐。

接下来，我们将每个段落的颜色设置为浅橙色，红色`0.97f`，绿色`0.75f`，蓝色`0.54f`。将`Rectangle`对象附加到传递的场景后，通过将段落的矩形和`BodyType`值`Dynamic`传递给标准的`PhysicsFactory.CreateBoxBody()`方法来创建当前段落的刚体。然后，我们将线性阻尼设置为`1f`，以平滑由碰撞引起的节奏性运动。接下来，我们注册一个`PhysicsConnector`类，将当前段落的矩形连接到当前段落的刚体。

既然我们已经为每个段落建立了位置并创建了相应的矩形和刚体，我们创建一个`RevoluteJointDef`对象`revoluteJointDef`，通过旋转关节将每个段落连接到桥梁。我们测试当前段落是否是第一个，如果是，则将段落连接到地面`Body`对象，而不是前一个段落。对于第一个桥梁段落，`Vector2 anchorPoint`的定义将`RevoluteJointDef`定义的锚点放置在段落的 x 值`BridgeSegmentsBodies[i].getWorldCenter().x`减去段落间距`BridgeSegmentSpacing`除以`2`，加上段落宽度`pSegmentsWidth`除以`2`，并缩放到`PIXEL_TO_METER_RATIO_DEFAULT`默认值的位置。第一个段落锚点的 y 位置简单地是当前段落的 y 值`BridgeSegmentsBodies[i].getWorldCenter().y`。对于其余的段落，通过计算当前段落的 x 位置与上一个段落的 x 位置的均值来确定锚点的 x 位置。

然后，使用`initialize()`方法初始化`revoluteJointDef`，第一个刚体设置为地面刚体`pGroundBody`，如果当前段落是第一个；如果不是第一个，则设置为前一段的刚体`BridgeSegmentsBodies[i-1]`。`revoluteJointDef`的第二个刚体设置为当前段落的刚体，并在退出`if`语句后，使用`pPhysicsWorld`对象的`createJoint()`方法创建关节。然后我们测试当前段落是否将是最后一个创建的，如果是，则使用与第一个段落相似的锚点 x 位置公式，在段落的右侧创建另一个旋转关节，将段落连接到地面刚体。有关物理模拟的更多信息，请参见第六章，*物理应用*中的*Box2D 物理扩展介绍*和*了解不同的刚体类型*食谱。

在最后一步中，我们首先在`onPopulateScene()`方法内部创建一个`FixedStepPhysicsWorld`对象，并将其注册为场景的更新处理器。然后，我们创建一个地面物体，我们的桥梁将附着在上面。接下来，我们通过调用`createBridge()`方法来创建桥梁。我们传递`groundBody`作为第一个参数，一个表示屏幕左中部的位置`0f,240f`作为左锚点，以及代表屏幕右侧的 x 位置作为右锚点。然后，我们传递一个整数`16`作为要创建的段数，以及一个段宽和高度为`40f`和`10f`。接下来，我们传递一个段密度`4f`，一个段弹性`0.1f`，一个段摩擦`0.5f`，我们的场景，将段矩形将附着其上，我们的物理世界，以及我们的`VertexBufferObjectManager`对象。现在我们的桥梁已经创建好了，我们创建了一个简单的盒子物体，以显示桥梁能够正确地反应碰撞。

## 另请参阅

+   在第一章，*AndEngine 游戏结构*中了解*生命周期*。

+   在第六章，*应用物理*中介绍*Box2D 物理扩展*。

+   在第六章，*应用物理*中理解*不同的物体类型*。


# 附录 A. MagneTank 的源代码

本章为游戏**MagneTank**中使用的所有类别提供了简短的描述和参考资料。MagneTank 可在谷歌 Play 商店([`play.google.com/store/apps/details?id=ifl.games.MagneTank`](http://play.google.com/store/apps/details?id=ifl.games.MagneTank))上找到，以前称为**Android Market**，本书代码捆绑包中可以找到源代码。游戏玩法包括通过触摸炮塔应该指向的位置来瞄准坦克的炮塔，并在同一位置轻敲以发射炮塔。为了展示物理启用的车辆，可以通过首先触摸坦克，然后向所需方向滑动，将坦克拉到左侧或右侧。

游戏的类别分布在以下主题中：

+   游戏关卡类别

+   输入类别

+   图层类别

+   管理类别

+   菜单类别

+   活动和引擎类别

以下图片是 MagneTank 第二关的游戏内截图：

![MagneTank 的源代码](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_01.jpg)

# 游戏关卡类别

这些类别出现在游戏的可玩部分：

## ManagedGameScene.java

MagneTank 的`ManagedGameScene`类别在第五章，*场景和图层管理*中呈现的`ManagedGameScene`类别的基础上，通过添加分步加载屏幕来显示每个关卡加载的内容。使用加载步骤背后的想法与在加载游戏之前显示一帧加载屏幕类似，就像`SceneManager`类别在显示新场景时的功能一样，但是加载屏幕会在每个加载步骤更新，而不仅仅是第一次显示加载屏幕时更新一次。

这个类别基于以下配方：

+   在第二章，*使用实体*中*将文本应用于图层*

+   在第五章，*场景和图层管理*中*创建场景管理器*

+   在第七章，*使用更新处理器*中*更新处理器是什么？*

## GameLevel.java

`GameLevel`类别将所有其他游戏内类别汇集在一起，形成了 MagneTank 的可玩部分。它处理每个实际游戏关卡的构建和执行。它扩展了一个自定义的`ManagedGameScene`类别，该类别包含一系列`LoadingRunnable`对象，这些对象分步骤创建关卡，允许关卡构建的每个进度在屏幕上显示。`GameLevel`类别还使用`GameManager`类别来确定每个游戏关卡的完成或失败，以测试胜利或失败条件。

这个类别基于以下配方：

+   在第二章，*使用实体*中*了解 AndEngine 实体*

+   在第二章中，*处理实体*一节讲述了*使用精灵使场景生动*。

+   在第二章中，*处理实体*一节介绍了*给图层应用文本*。

+   在第二章中，*处理实体*一节介绍了*重写 onManagedUpdate 方法*。

+   在第二章中，*处理实体*一节讲解了*使用修改器和实体修改器*。

+   在第三章中，*设计你的菜单*一节解释了*使用视差背景创造透视感*。

+   在第四章中，*处理相机*一节引入了*相机对象*。

+   在第四章中，*处理相机*一节通过*使用边界相机限制相机区域*进行了说明。

+   在第四章中，*处理相机*一节通过*使用缩放相机近距离观察*进行了阐述。

+   在第四章中，*处理相机*一节介绍了*给相机应用 HUD*。

+   在第五章中，*场景和图层管理*一节讲述了*自定义管理和图层*。

+   在第六章中，*应用物理*一节介绍了 Box2D 物理扩展的*入门知识*。

+   在第七章中，*处理更新处理器*一节解释了*更新处理器是什么*。

+   在第八章中，*最大化性能*一节讲解了*创建精灵池*。

## LoadingRunnable.java

`LoadingRunnable`类在作为`Runnable`对象的同时，也会在`ManagedGameScene`类中更新加载屏幕。每个`ManagedGameScene`类中都存在一个`LoadingRunnable`对象的`ArrayList`类型，以便开发者可以控制玩家看到的加载进度。需要注意的是，虽然在 MagneTank 中更新加载屏幕不会占用太多处理器资源，但更复杂、图形复杂的加载屏幕可能会大大增加每个关卡的加载时间。

## Levels.java

`Levels`类保存了游戏中可以玩的所有关卡数组，以及帮助获取特定关卡的辅助方法。

## BouncingPowerBar.java

`BouncingPowerBar`类向玩家显示一个弹跳指示器，指示每次从车辆射击的威力大小。它将指示器的可见位置转换为一个分数值，然后应用一个立方曲线，使得在尝试实现最强大射击时更具挑战性。以下图片展示了由三张独立图片构建完成后的力量条的样子：

![BouncingPowerBar.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_02.jpg)

`BouncingPowerBar`类的实现基于以下方法：

+   在第二章的*处理实体*中*理解 AndEngine 实体*

+   在第二章的*处理实体*中*使用精灵为场景注入生命*

+   在第二章的*处理实体*中*重写 onManagedUpdate 方法*

+   在第二章的*处理实体*中*将 HUD 应用到相机上*

## MagneTank.java

`MagneTank`类创建并控制游戏基于的车辆。它使用关节将 Box2D 刚体组合起来，创建具有物理效果的车辆，并通过`BoundTouchInputs`获取玩家输入，控制车辆每个部分的运动和功能。以下图片展示了 MagneTank 构建前后的样子：

![MagneTank.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_03.jpg)

`MagneTank`类基于以下配方：

+   在第二章的*处理实体*中*理解 AndEngine 实体*

+   在第二章的*处理实体*中*使用精灵为场景注入生命*

+   在第二章的*处理实体*中*使用相对旋转*

+   在第二章的*处理实体*中*重写 onManagedUpdate 方法*

+   在第四章的*处理相机*中*使用边界相机限制摄像机区域*

+   在第六章的*物理应用*中*介绍 Box2D 物理扩展*

+   在第六章的*物理应用*中*理解不同的刚体类型*

+   在第六章的*物理应用*中*通过指定顶点创建独特的刚体*

+   在第六章的*物理应用*中*使用力、速度和扭矩*

+   在第六章的*物理应用*中*处理关节工作*

+   在第七章的*处理更新处理器*中*更新处理器是什么？*

+   在第十章的*深入了解 AndEngine*中*应用基于精灵的阴影*

## MagneticCrate.java

`MagneticCrate`类扩展了`MagneticPhysObject`类。它创建并处理了 MagneTank 车辆可发射的各种类型的箱子。每个箱子以平铺精灵的形式显示，平铺精灵的图像索引设置为箱子的类型。`MagneticCrate`类利用了物理世界的`ContactListener`中的 Box2D 的`postSolve()`方法。以下图片展示了游戏中可用的各种大小和类型的箱子：

![MagneticCrate.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_04.jpg)

`MagneticCrate`类基于以下食谱：

+   *在第二章中了解 AndEngine 实体*，*使用实体*

+   *在第二章中使用精灵为场景注入生命*，*使用实体*

+   *重写第二章中的`onManagedUpdate`方法*，*使用实体*

+   *在第六章中介绍 Box2D 物理扩展*，*物理应用*

+   *在第六章中了解不同的物体类型*，*物理应用*

+   *在第六章中使用 preSolve 和 postSolve*，*物理应用*

+   *在第七章中更新处理程序是什么？*，*使用更新处理程序*

## MagneticOrb.java

`MagneticOrb`类会在 MagneTank 当前弹射体周围创建视觉效果。它让两张旋涡图像（见下图的图像）以相反的方向旋转，以产生球形力的错觉。当装填并发射弹射体时，`MagneticOrb`类会形成并逐渐消失。

![MagneticOrb.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_05.jpg)

`MagneticOrb`类基于以下食谱：

+   *在第二章中了解 AndEngine 实体*，*使用实体*

+   *在第二章中使用精灵为场景注入生命*，*使用实体*

+   *在第二章中使用相对旋转*，*使用实体*

+   *在第二章中重写`onManagedUpdate`方法*，*使用实体*

## MagneticPhysObject.java

`MagneticPhysObject`类扩展了`PhysObject`类，允许物体被 MagneTank 车辆抓取或释放。被抓取时，物体不仅会受到反重力作用，还会受到向 MagneTank 炮塔方向拉扯物体的力。

`MagneticPhysObject`类基于以下食谱：

+   *在第六章中介绍 Box2D 物理扩展*，*物理应用*

+   *在第六章中了解不同的物体类型*，*物理应用*

+   *在第六章中使用力、速度和扭矩*，*物理应用*

+   *在第六章中将反重力应用于特定物体第六章 物理应用*

+   *在第六章中更新处理程序是什么？*，*使用更新处理程序*

## MechRat.java

`MechRat`类扩展了`PhysObject`类，以利用在与其他物理启用的对象碰撞时调用的`postSolve()`方法。如果力足够大，MechRat 就会被摧毁，并且之前加载的粒子效果会立即显示。MechRat 还有关节连接的轮子，这增加了摧毁它的挑战性。以下图片展示了 MechRat 的视觉组成：

![MechRat.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_06.jpg)

这个类基于以下食谱：

+   *理解 AndEngine 实体*在章节 2，*处理更新处理器*

+   *使用精灵为场景注入生命*在章节 2，*处理更新处理器*

+   *重写`onManagedUpdate`方法*在章节 2，*处理更新处理器*

+   *在章节 2 中处理粒子系统*，*处理更新处理器*

+   *Box2D 物理扩展介绍*在第章节 6，*物理学的应用*

+   *理解不同的物体类型*在第章节 6，*物理学的应用*

+   *通过指定顶点创建独特的物体*在第章节 6，*物理学的应用*

+   *处理关节*在第章节 6，*物理学的应用*

+   *使用 preSolve 和 postSolve*在第章节 6，*物理学的应用*

+   *创建可破坏的物体*在第章节 6，*物理学的应用*

+   *更新处理器是什么？*在第章节 7，*使用更新处理器*

## MetalBeamDynamic.java

这个类代表了游戏中看到的非静态、物理启用的梁。由于它的重复纹理，每根梁的长度可以设置。

`MetalBeamDynamic`类基于以下食谱：

+   *理解 AndEngine 实体*在章节 2，*使用更新处理器*

+   *使用精灵为场景注入生命*在章节 2，*处理更新处理器*

+   *在章节 2 中使用相对旋转*，*使用实体*

+   *重写`onManagedUpdate`方法*在章节 2，*使用实体*

+   *Box2D 物理扩展介绍*在第章节 6，*物理学的应用*

+   *理解不同的物体类型*在第章节 6，*物理学的应用*

## MetalBeamStatic.java

与上面的`MetalBeamDynamic`类相似，这个类也代表一个桁架，但这个对象的`BodyType`选项设置为`Static`，以创建一个静止的屏障。

`MetalBeamStatic`类基于以下食谱：

+   *在第二章，*使用实体*中，了解 AndEngine 实体*

+   *在第二章，*使用实体*中，让场景通过精灵生动起来*

+   *在第二章，*使用实体*中使用相对旋转*

+   *在第六章，*物理应用*中，介绍 Box2D 物理扩展*

+   *在第六章，*物理应用*中，了解不同的身体类型*

## ParallaxLayer.java

由本书的合著者 Jay Schroeder 编写并发布的`ParallaxLayer`类，使得创建`ParallaxEntity`对象变得简单，这些对象在`Camera`对象在场景中移动时能产生深度感知。可以设置视差效果的程度，`ParallaxLayer`类负责正确渲染每个`ParallaxEntity`对象。以下图片展示了 MagneTank 的背景层，它们附着在一个`ParallaxLayer`类上：

![ParallaxLayer.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_07.jpg)

`ParallaxLayer`类基于以下食谱：

+   *在第二章，*使用实体*中，了解 AndEngine 实体* （注意：这一行与第四行重复，根据注意事项，这里不重复翻译）

+   *在第二章，*使用实体*中，使用 OpenGL*

+   *在第二章，*使用实体*中，重写 onManagedUpdate 方法*

+   *在第三章，*设计你的菜单*中使用视差背景创造透视感*

## PhysObject.java

`PhysObject`类在 MagneTank 中用于委派从物理世界的`ContactListener`接收到的接触。它还提供了一个`destroy()`方法，使得销毁物理对象更加容易。

`PhysObject`类基于以下食谱：

+   *在第二章，*使用实体*中，了解 AndEngine 实体*

+   *在第六章，*物理应用*中，介绍 Box2D 物理扩展*

+   *在第六章，*物理应用*中，了解不同的身体类型*

+   *在第六章，*物理应用*中使用 preSolve 和 postSolve*

+   *更新处理程序是什么？* 在第七章，*使用更新处理程序*

## RemainingCratesBar.java

`RemainingCratesBar` 类为玩家提供了视觉表示，显示还有哪些箱子需要被 MagneTank 射击。每个级别剩余的箱子的大小、类型和数量从 `GameLevel` 类中获取，并且会从一级到另一级发生变化。当一个箱子被击中时，`RemainingCratesBar` 类会动画化以反映游戏状态的变化。

这个类基于以下食谱：

+   第二章中的*理解 AndEngine 实体*，*使用实体*

+   第二章中的*使用精灵为场景注入生命*，*使用实体*

+   第二章中的*使用 OpenGL*，*使用实体*

+   第二章中的*覆盖 onManagedUpdate 方法*，*使用实体*

+   第二章中的*使用修改器和实体修改器*，*使用实体*

## TexturedBezierLandscape.java

`TexturedBezierLandscape` 类创建了两个纹理网格和一个物理体，代表关卡的地面。顾名思义，该景观由贝塞尔曲线组成，以展示上升或下降的斜坡。纹理网格由重复的纹理制成，以避免景观区域之间的可见缝隙。以下图片展示了创建景观所使用的两种纹理以及应用贝塞尔斜坡后组合网格的外观示例：

![TexturedBezierLandscape.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_08.jpg)

`TexturedBezierLandscape` 类基于以下食谱：

+   第二章中的*理解 AndEngine 实体*，*使用实体*

+   第二章中的*使用 OpenGL*，*使用实体*

+   第六章中的*Box2D 物理扩展介绍*，*物理应用*

+   第六章中的*理解不同的物体类型*，*物理应用*

+   第六章中的*通过指定顶点创建独特的物体*，*物理应用*

+   第十章中的*纹理网格*，*深入了解 AndEngine*

## TexturedMesh.java

这个类与第十章中*纹理网格*的食谱中找到的 `TexturedMesh` 类相同。

## WoodenBeamDynamic.java

这个类与 `MetalBeam` 类相似，但增加了一个健康方面，一旦其健康值达到零，就会用粒子效果替换 `WoodenBeamDynamic` 类。

`WoodenBeamDynamic` 类基于以下食谱：

+   在第二章，*处理实体*中*理解 AndEngine 实体*（注意：这里原文重复，根据注意事项，译文不应重复）

+   在第二章，*处理实体*中*使用精灵为场景注入生命*

+   在第二章，*处理实体*中*使用相对旋转*

+   在第二章，*处理实体*中*覆盖 onManagedUpdate 方法*

+   在第二章，*处理实体*中*使用粒子系统*

+   在第六章，*物理应用*中*Box2D 物理扩展介绍*

+   在第六章，*物理应用*中*理解不同的身体类型*

+   在第六章，*物理应用*中*使用 preSolve 和 postSolve*

+   在第七章，*使用更新处理器*中*更新处理器是什么？*

# 输入类

这些类中的每一个都处理游戏中使用的特定输入方法：

## BoundTouchInput.java

`BoundTouchInput` 类便于输入的委托，然后这些输入绑定到 `BoundTouchInput` 类。这可以在游戏中轻松看到，例如移动 MagneTank 以瞄准炮塔时。当触摸进入另一个可触摸区域时，它仍保持与原始区域的绑定。

## GrowButton.java

`GrowButton` 类仅显示一个图像，当玩家触摸它时，它会增长到特定的比例，并在触摸抬起或丢失时恢复到原始比例。

本类基于以下食谱：

+   在第二章，*处理实体*中*理解 AndEngine 实体*

+   在第二章，*处理实体*中*使用精灵为场景注入生命*

+   在第二章，*处理实体*中*覆盖 onManagedUpdate 方法*

+   在第二章，*处理实体*中*使用修改器和实体修改器*

## GrowToggleButton.java

本类基于 `GrowButton` 类，并增加了根据条件状态显示一个或两个 `TiledTextureRegion` 索引的功能。

`GrowToggleButton` 类基于以下食谱：

+   在第二章，*处理实体*中*理解 AndEngine 实体*

+   在第二章，*处理实体*中*使用精灵为场景注入生命*

+   在第二章，*处理实体*中*覆盖 onManagedUpdate 方法*

+   在第二章，*处理实体*中*使用修改器和实体修改器*

## GrowToggleTextButton.java

基于`GrowToggleButton`类，这个类使用`Text`对象而不是`TiledTextureRegion`对象来显示条件的状态。

`GrowToggleTextButton`类基于以下配方：

+   在第二章，*处理实体*中*理解 AndEngine 实体*

+   在第二章，*处理实体*中*使用精灵让场景生动起来*

+   在第二章，*处理实体*中*将文本应用到层上*

+   在第二章，*处理实体*中*覆盖 onManagedUpdate 方法*

+   在第二章，*处理实体*中*使用修饰符和实体修饰符*

# 层类

这些类表示游戏内存在的层：

## LevelPauseLayer.java

`LevelPauseLayer`类表示当关卡暂停时显示给玩家的层。它显示当前的关卡号码、分数和最高分，以及返回游戏、返回关卡选择屏幕、重新开始关卡或跳转到下一关卡的按钮。

这个类基于以下配方：

+   在第二章，*处理实体*中*理解 AndEngine 实体*

+   在第二章，*处理实体*中*使用精灵让场景生动起来*

+   在第二章，*处理实体*中*将文本应用到层上*

+   在第五章，*场景和层管理*中*自定义管理场景和层*

+   在第七章，*处理更新处理器*中*更新处理器是什么？*

## LevelWonLayer.java

`LevelWonLayer`类表示当玩家成功完成一个关卡时显示给玩家的层。它显示当前的关卡号码、分数和最高分，以及玩家获得的星级评价。还包括返回关卡选择屏幕、重玩关卡或进入下一关卡的按钮。以下图片展示了`LevelWonLayer`类的纹理以及它们在游戏中组合起来的样子：

![LevelWonLayer.java](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/adng-andr-gm-dev-cb/img/8987OS_11_09.jpg)

`LevelWonLayer`类基于以下配方：

+   在第二章，*处理实体*中*理解 AndEngine 实体*

+   在第二章，*处理实体*中*使用精灵让场景生动起来*

+   在第二章，*处理实体*中*将文本应用到层上*

+   在第二章，*处理实体*中*使用修饰符和实体修饰符*

+   *在第五章中自定义管理场景和图层*，*场景和图层管理*

+   *第七章中的更新处理器是什么？*，*使用更新处理器*

## ManagedLayer.java

这个类与在第五章中*创建场景管理器*的食谱中找到的`ManagedLayer`类是相同的，*场景和图层管理*。

## OptionsLayer.java

这个图层可以从`MainMenu`场景访问，允许玩家启用或禁用音乐和声音，以及选择图形质量或重置他们已完成的关卡完成数据。

`OptionsLayer`类基于以下食谱：

+   *在第二章中了解 AndEngine 实体*，*使用实体*

+   *在第二章中使用精灵使场景生动*，*使用实体*

+   *在第二章中将文本应用于图层*，*使用实体*

+   *在第五章中自定义管理场景和图层*，*场景和图层管理*

+   *第七章中的更新处理器是什么？*，*使用更新处理器*

# 管理类

这些类各自管理游戏的一个特定方面：

## GameManager.java

`GameManager`类简单地为检查两个条件以确定一个关卡是否完成或失败提供便利。使用该信息，游戏管理器随后调用在`GameLevel`类中设置的正确方法。

这个类基于以下食谱：

+   *在第一章中创建游戏管理器*，*AndEngine 游戏结构*

+   *第七章中的更新处理器是什么？*，*使用更新处理器*

## ResourceManager.java

`ResourceManager`类与在第一章中找到的类非常相似，*AndEngine 游戏结构*，但它增加了如果需要可以使用一组低质量纹理的能力。它还包括用于确定精确字体纹理大小的方法，以防止浪费宝贵的纹理内存。

这个类基于以下食谱：

+   *在第一章中应用纹理选项*，*AndEngine 游戏结构*

+   *在第一章中使用 AndEngine 字体资源*，*AndEngine 游戏结构*

+   *在第一章中创建资源管理器*，*AndEngine 游戏结构*

+   *在第二章中*使用 OpenGL*，*使用实体*

+   在第五章的*场景和图层管理*部分，设置场景资源的资源管理器*《为场景资源设置资源管理器》*

## `SceneManager.java`

这个类与第五章中的*创建场景管理器*食谱中的`SceneManager`类完全相同*《场景和图层管理》*

## `SFXManager.java`

这个简单的类处理音乐和声音的播放以及它们的静音状态。

`SFXManager`类基于以下食谱：

+   在第一章的*AndEngine 游戏结构*部分，介绍声音和音乐*《介绍声音和音乐》*

# 菜单类

这些类仅用于游戏中的菜单。

## `LevelSelector.java`

这个类与第三章中的菜单设计中的关卡选择器类似，但使用一系列`LevelSelectorButton`对象代替了精灵*《设计你的菜单》*

这个类基于以下食谱：

+   在第二章的*使用实体工作*部分，了解`AndEngine`实体*《了解 AndEngine 实体》*

+   在第二章的*使用实体工作*部分，*《使用精灵使场景生动》*

+   在第三章的*设计你的菜单*部分，创建我们的关卡选择系统*《创建我们的关卡选择系统》*

## `LevelSelectorButton.java`

`LevelSelectorButton`类通过视觉向玩家展示一个关卡的当前状态，是锁定还是解锁，如果关卡已解锁，还会显示获得的星星数量。

这个类基于以下食谱：

+   在第二章的*使用实体工作*部分，了解`AndEngine`实体*《了解 AndEngine 实体》*

+   在第二章的*使用实体工作*部分，*《使用精灵使场景生动》*

+   在第二章的*使用实体工作*部分，将文本应用到图层*《将文本应用到图层》*

+   在第二章的*使用实体工作*部分，覆盖`onManagedUpdate`方法*《覆盖 onManagedUpdate 方法》*

+   在第二章的*使用实体工作*部分，使用修改器和实体修改器*《使用修改器和实体修改器》*

## `MainMenu.java`

`MainMenu`类包含两个`Entity`对象，一个代表标题屏幕，另一个代表关卡选择屏幕。两个屏幕之间的切换是通过实体修改器实现的。在首次显示主菜单时，会显示加载屏幕，同时加载游戏的资源。

`MainMenu`类基于以下食谱：

+   在第二章的*使用实体工作*部分，了解`AndEngine`实体*《了解 AndEngine 实体》*

+   在第二章的*使用实体工作*部分，介绍如何通过精灵使场景生动*《使用精灵使场景生动》*

+   在第二章的*使用实体工作*部分，覆盖`onManagedUpdate`方法*《覆盖 onManagedUpdate 方法》*

+   在第二章，*处理实体*中*使用修改器和实体修改器*。

+   在第五章，*场景和图层管理*中*自定义管理场景和图层*。

## ManagedMenuScene.java

这个类与第五章，*场景和图层管理*中*创建场景管理器*食谱中呈现的`ManagedMenuScene`类相同。

## ManagedSplashScreen.java

这个类基于第五章*场景和图层管理*中*自定义管理场景和图层*食谱中找到的`ManagedMenuScene`类。它添加了代码，在隐藏启动画面后卸载`Entity`对象。

## SplashScreens.java

`SplashScreen`类使用实体修改器和与分辨率无关的定位来显示游戏的启动画面。每个标志都是可点击的，并启动与标志相关的意图。

这个类基于以下食谱：

+   在第二章，*处理实体*中*使用精灵让场景生动*。

+   在第二章，*处理实体*中*将文本应用到图层*。

+   在第二章，*处理实体*中*使用修改器和实体修改器*。

+   在第五章，*场景和图层管理*中*自定义管理场景和图层*。

+   在第七章，*处理更新处理器*中*更新处理器是什么？*。

## 活动和引擎类

这些类是游戏的核心。

## MagneTankActivity.java

这个活动类基于标准的 AndEngine `BaseGameActivity`类，通过在`onCreateEngineOptions()`方法中添加广告和一些高级分辨率缩放以及共享首选项方法来保存和恢复选项和分数。

这个类基于以下食谱：

+   在第一章，*AndEngine 游戏结构*中*了解生命周期*。

+   在第一章，*AndEngine 游戏结构*中*选择我们的引擎类型*。

+   在第一章，*AndEngine 游戏结构*中*保存和加载游戏数据*。

+   在第五章，*场景和图层管理*中*设置活动以使用场景管理器*。

## MagneTankSmoothCamera.java

这个类扩展了`SmoothCamera`对象，但包括在指定时间内平移到敌方基地以及跟踪`MagneTank`对象的能力。

这个类基于以下食谱：

+   在第四章，*使用相机*中*介绍相机对象*。

+   在第四章的*使用平滑摄像头创建平滑移动*部分，*使用摄像头*

+   在第七章的*什么是更新处理器？*部分，*使用更新处理器*

## ManagedScene.java

这个类与第五章中*创建场景管理器*一节中介绍的是同一个`ManagedScene`类，*场景和图层管理*

## SwitchableFixedStepEngine.java

当调用了`EnableFixedStep()`方法时，这个`Engine`对象的行为与`FixedStepEngine`对象完全一样。

这个类基于以下食谱：

+   在第一章的*选择我们的引擎类型*部分，*AndEngine 游戏结构*

+   在第七章的*什么是更新处理器？*部分，*使用更新处理器*
