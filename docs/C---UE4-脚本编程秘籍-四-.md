# C++ UE4 脚本编程秘籍（四）

> 原文：[`zh.annas-archive.org/md5/244B225FA5E3FFE01C9887B1851E5B64`](https://zh.annas-archive.org/md5/244B225FA5E3FFE01C9887B1851E5B64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：用户界面-UI 和 UMG

在本章中，我们将涵盖以下主题：

+   使用 Canvas 进行绘图

+   将 Slate 小部件添加到屏幕上

+   为 UI 创建适应屏幕大小的缩放

+   在游戏中显示和隐藏一组 UMG 元素

+   将函数调用附加到 Slate 事件

+   使用数据绑定与 Unreal Motion Graphics

+   使用样式控制小部件外观

+   创建自定义的 SWidget/UWidget

# 介绍

向玩家显示反馈是游戏设计中最重要的元素之一，这通常涉及到 HUD 或至少游戏中的菜单。

在之前的 Unreal 版本中，有简单的 HUD 支持，允许您在屏幕上绘制简单的形状和文本。然而，从美学角度来看，它在某种程度上有一定的限制，因此，诸如 Scaleform 之类的解决方案变得常见，以解决这些限制。Scaleform 利用 Adobe 的 Flash 文件格式来存储矢量图像和 UI 脚本。然而，对于开发人员来说，它也有自己的缺点，尤其是成本方面-它是一个第三方产品，需要（有时昂贵的）许可证。

因此，Epic 为 Unreal 4 编辑器和游戏内 UI 框架开发了 Slate。Slate 是一组小部件（UI 元素）和一个框架，允许在编辑器中进行跨平台界面。它也可用于游戏中绘制小部件，例如滑块和按钮，用于菜单和 HUD。

Slate 使用声明性语法，允许以本机 C++中的层次结构的 xml 样式表示用户界面元素。它通过大量使用宏和运算符重载来实现这一点。

话虽如此，并不是每个人都想要让他们的程序员设计游戏的 HUD。在 Unreal 3 中使用 Scaleform 的一个重要优势是能够使用 Flash 可视化编辑器开发游戏 UI 的视觉外观，因此视觉设计师不需要学习编程语言。程序员可以单独插入逻辑和数据。这与 Windows Presentation Framework（WPF）的范例相同。

类似地，Unreal 提供了 Unreal Motion Graphics（UMG）。UMG 是 Slate 小部件的可视化编辑器，允许您以可视化方式样式化、布局和动画化用户界面。UI 小部件（或控件，如果您来自 Win32 背景）的属性可以通过蓝图代码（在 UMG 窗口的图形视图中编写）或通过 C++来控制。本章主要涉及显示 UI 元素、创建小部件层次结构和创建可以在 UMG 中进行样式化和使用的基本 SWidget 类。

# 使用 Canvas 进行绘图

Canvas 是在 Unreal 3 中实现的简单 HUD 的延续。虽然它在发货游戏中并不常用，大多被 Slate/UMG 取代，但在您想要在屏幕上绘制文本或形状时，它非常简单易用。Canvas 绘图仍然广泛用于用于调试和性能分析的控制台命令，例如`stat game`和其他`stat`命令。有关创建自己的控制台命令的方法，请参阅第八章，*集成 C++和 Unreal Editor*。

## 如何操作...

1.  打开您的<Module>.build.cs 文件，并取消注释/添加以下行：

```cpp
PrivateDependencyModuleNames.AddRange(new string[] { "Slate", "SlateCore" });
```

1.  使用编辑器类向导创建一个名为 CustomHUDGameMode 的新 GameMode。如果需要刷新此操作，请参阅第四章，*Actors and Components*。

1.  在类中添加一个构造函数：

```cpp
ACustomHUDGameMode();
```

1.  将以下内容添加到构造函数实现中：

```cpp
ACustomHUDGameMode::ACustomHUDGameMode()
:AGameMode()
{
  HUDClass = ACustomHUD::StaticClass();
}
```

1.  使用向导创建一个名为 CustomHUD 的新 HUD 子类。

1.  将`override`关键字添加到以下函数：

```cpp
public:
virtual void DrawHUD() override;
```

1.  现在实现函数：

```cpp
voidACustomHUD::DrawHUD()
{
  Super::DrawHUD();
  Canvas->DrawText(GEngine->GetSmallFont(), TEXT("Test string to be printed to screen"), 10, 10);
  FCanvasBoxItemProgressBar(FVector2D(5, 25), FVector2D(100, 5));
  Canvas->DrawItem(ProgressBar);
  DrawRect(FLinearColor::Blue, 5, 25, 100, 5);
}
```

1.  编译您的代码，并启动编辑器。

1.  在编辑器中，从“设置”下拉菜单中打开“世界设置”面板：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00212.jpeg)

1.  在**世界设置**对话框中，从**游戏模式覆盖**列表中选择`CustomHUDGameMode`：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00213.jpeg)

1.  播放并验证您的自定义 HUD 是否绘制到屏幕上：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00214.jpeg)

## 工作原理...

1.  这里的所有 UI 示例都将使用 Slate 进行绘制，因此我们需要在我们的模块和 Slate 框架之间添加依赖关系，以便我们可以访问在该模块中声明的类。

1.  将自定义 Canvas 绘制调用放入游戏 HUD 的最佳位置是在`AHUD`的子类中。

1.  为了告诉引擎使用我们的自定义子类，我们需要创建一个新的`GameMode`，并指定我们自定义类的类型。

1.  在自定义游戏模式的构造函数中，我们将新 HUD 类型的`UClass`分配给`HUDClass`变量。这个`UClass`在每个玩家控制器生成时传递给它们，并且控制器随后负责创建它创建的`AHUD`实例。

1.  由于我们的自定义`GameMode`加载了我们的自定义 HUD，我们需要实际创建所述的自定义 HUD 类。

1.  `AHUD`定义了一个名为`DrawHUD()`的虚函数，每帧调用该函数以允许我们向屏幕上绘制元素。

1.  因此，我们重写了该函数，并在实现内部执行绘制操作。

1.  首先使用的方法如下：

```cpp
floatDrawText(constUFont* InFont, constFString&InText, float X, float Y, float XScale = 1.f, float YScale = 1.f, constFFontRenderInfo&RenderInfo = FFontRenderInfo());
```

1.  `DrawText`需要一个字体来绘制。引擎代码中`stat`和其他 HUD 绘制命令使用的默认字体实际上存储在`GEngine`类中，并且可以使用`GetSmallFont`函数访问，该函数返回一个`UFont`的实例指针。

1.  我们使用的剩余参数是要渲染的实际文本以及应该绘制文本的像素偏移量。

1.  `DrawText`是一个允许您直接传入要显示的数据的函数。

1.  通用的`DrawItem`函数是一个访问者实现，允许您创建一个封装有关要绘制的对象的信息的对象，并在多个绘制调用中重用该对象。

1.  在本示例中，我们创建了一个用于表示进度条的元素。我们将关于框的宽度和高度的所需信息封装到一个`FCanvasBoxItem`中，然后将其传递给我们的 Canvas 上的`DrawItem`函数。

1.  我们绘制的第三个元素是一个填充的矩形。此函数使用在 HUD 类中定义的便利方法，而不是在 Canvas 本身上定义的方法。填充的矩形放置在与我们的`FCanvasBox`相同的位置，以便它可以表示进度条内的当前值。

# 将 Slate 小部件添加到屏幕上

之前的示例使用了`FCanvas` API 来绘制屏幕。然而，`FCanvas`有一些限制，例如，动画很难实现，绘制图形到屏幕上涉及创建纹理或材质。`FCanvas`还没有实现任何小部件或窗口控件，使得数据输入或其他形式的用户输入比必要的复杂。本示例将向您展示如何使用 Slate 开始在屏幕上创建 HUD 元素，Slate 提供了许多内置控件。

## 准备工作

如果您还没有这样做，请将`Slate`和`SlateCore`添加到您的模块依赖项中（有关如何执行此操作，请参见*使用 Canvas 进行绘制*的示例）。

## 操作步骤...

1.  创建一个名为`ACustomHUDPlayerController`的新的`PlayerController`子类。

1.  在你的新子类中重写`BeginPlay` `virtual`方法：

```cpp
public:
virtual void BeginPlay() override;
```

1.  在子类的实现中添加以下代码以覆盖`BeginPlay()`：

```cpp
void ACustomHUDPlayerController::BeginPlay()
{
  Super::BeginPlay();
  TSharedRef<SVerticalBox> widget = SNew(SVerticalBox)
  + SVerticalBox::Slot()
  .HAlign(HAlign_Center)
  .VAlign(VAlign_Center)
  [
    SNew(SButton)
    .Content()
    [
      SNew(STextBlock)
      .Text(FText::FromString(TEXT("Test button")))
    ]
  ];
  GEngine->GameViewport->AddViewportWidgetForPlayer(GetLocalPlayer(),widget, 1);
}
```

1.  如果您现在尝试编译，您将得到一些关于未定义类的错误。这是因为我们需要包含它们的头文件：

```cpp
#include "SlateBasics.h"
#include "SButton.h"
#include "STextBlock.h"
```

1.  创建一个名为`SlateHUDGameMode`的新的`GameMode`：

1.  在游戏模式中添加一个构造函数：

```cpp
ASlateHUDGameMode();
```

1.  使用以下代码实现构造函数：

```cpp
ASlateHUDGameMode::ASlateHUDGameMode()
:Super()
{
  PlayerControllerClass = ACustomHUDPlayerController::StaticClass();
}
```

1.  在实现文件中添加以下包含：

```cpp
#include "CustomHudPlayerController.h"
```

1.  在实现文件中添加包含后，编译游戏。

1.  在编辑器中，从工具栏打开**世界设置**：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00215.jpeg)

1.  在**世界设置**中，覆盖关卡的游戏模式为我们的`SlateHUDGameMode`。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00216.jpeg)

1.  播放关卡，看到新的 UI 显示在屏幕上：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00217.jpeg)

## 它是如何工作的...

1.  为了在我们的代码中引用 Slate 类或函数，我们的模块必须与`Slate`和`SlateCore`模块链接，因此我们将它们添加到模块依赖项中。

1.  我们需要在游戏运行时加载的类中实例化我们的 UI，因此在这个示例中，我们使用我们的自定义`PlayerController`在`BeginPlay`函数中作为创建 UI 的位置。

1.  在`BeginPlay`的实现中，我们使用`SNew`函数创建一个新的`SVerticalBox`。我们为我们的框添加一个小部件的插槽，并将该插槽设置为水平和垂直居中。

1.  在我们使用方括号访问的插槽内，我们创建一个内部有`Textblock`的按钮。

1.  在`Textblock`中，将`Text`属性设置为字符串字面值。

1.  现在创建了 UI，我们调用`AddViewportWidgetForPlayer`在本地玩家的屏幕上显示此小部件。

1.  准备好我们的自定义`PlayerController`后，现在我们需要创建一个自定义的`GameMode`来指定它应该使用我们的新`PlayerController`。

1.  在游戏开始时加载自定义的`PlayerController`，当调用`BeginPlay`时，我们的 UI 将显示出来。

1.  在这个屏幕尺寸下，UI 非常小。请参考下一个示例了解如何根据游戏窗口的分辨率进行适当的缩放。

# 为 UI 创建适应屏幕大小的缩放

如果您按照前面的示例操作，您会注意到当您使用**在编辑器中播放**时，加载的按钮非常小。

这是由 UI 缩放引起的，该系统允许您根据屏幕大小缩放用户界面。用户界面元素以像素表示，通常是绝对值（按钮应该是 10 个像素高）。

问题在于，如果您使用更高分辨率的面板，10 个像素可能会更小，因为每个像素的大小更小。

## 准备工作

虚幻引擎中的 UI 缩放系统允许您控制全局缩放修饰符，该修饰符将根据屏幕分辨率缩放屏幕上的所有控件。根据前面的示例，您可能希望调整按钮的大小，以便在较小的屏幕上查看 UI 时其表面大小保持不变。本示例演示了两种不同的方法来改变缩放率。

## 如何操作...

1.  创建一个自定义的`PlayerController`子类，将其命名为`ScalingUIPlayerController`。

1.  在该类中，覆盖`BeginPlay`：

```cpp
virtual void BeginPlay() override;
```

1.  在该函数的实现中添加以下代码：

```cpp
Super::BeginPlay();
TSharedRef<SVerticalBox> widget = SNew(SVerticalBox)
+ SVerticalBox::Slot()
.HAlign(HAlign_Center)
.VAlign(VAlign_Center)
[
  SNew(SButton)
  .Content()
  [
    SNew(STextBlock)
    .Text(FText::FromString(TEXT("Test button")))
  ]
];
GEngine->GameViewport->AddViewportWidgetForPlayer(GetLocalPlayer(), widget, 1);
```

1.  创建一个名为`ScalingUIGameMode`的新的`GameMode`子类，并给它一个默认构造函数：

```cpp
ScalingUIGameMode();
```

1.  在默认构造函数中，将默认的玩家控制器类设置为`ScalingUIPlayerController`：

```cpp
AScalingUIGameMode::AScalingUIGameMode()
:AGameMode()
{
  PlayerControllerClass = ACustomHUDPlayerController::StaticClass();
}
```

1.  这应该给您一个类似于前一个示例的用户界面。请注意，如果您在编辑器中播放，UI 会非常小：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00218.jpeg)

1.  要改变 UI 缩放的速率，我们需要改变缩放曲线。我们可以通过两种不同的方法来实现。

### 编辑器中的方法

1.  启动虚幻引擎，然后通过**编辑**菜单打开**项目设置**对话框：![编辑器中的方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00219.jpeg)

1.  在**用户界面**部分，有一个曲线可以根据屏幕的短边来改变 UI 缩放因子：![编辑器中的方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00220.jpeg)

1.  点击图表上的第二个点或关键点。

1.  将其输出值更改为 1。![编辑器中的方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00221.jpeg)

### 配置文件方法

1.  浏览到项目目录，并查看`Config`文件夹中的内容：![配置文件方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00222.jpeg)

1.  在您选择的文本编辑器中打开`DefaultEngine.ini`。

1.  在`[/Script/Engine.UserInterfaceSettings]`部分中找到：

```cpp
[/Script/Engine.UserInterfaceSettings]
RenderFocusRule=NavigationOnly
DefaultCursor=None
TextEditBeamCursor=None
CrosshairsCursor=None
GrabHandCursor=None
GrabHandClosedCursor=None
SlashedCircleCursor=None
ApplicationScale=1.000000
UIScaleRule=ShortestSide
CustomScalingRuleClass=None
UIScaleCurve=(EditorCurveData=(PreInfinityExtrap=RCCE_Constant,PostInfinityExtrap=RCCE_Constant,Keys=((Time=480.000000,Value=0.444000),(Time=720.000000,Value=1.000000),(Time=1080.000000,Value=1.000000),(Time=8640.000000,Value=8.000000)),DefaultValue=340282346638528859811704183484516925440.000000),ExternalCurve=None)
```

1.  在该部分中查找名为`UIScaleCurve`的关键字。

1.  在该键的值中，您会注意到许多`(Time=x,Value=y)`对。编辑第二对，使其`Time`值为`720.000000`，`Value`为`1.000000`。

1.  如果您已经打开了编辑器，请重新启动编辑器。

1.  启动编辑器中的“Play In Editor”预览，以确认您的 UI 现在在**PIE**屏幕的分辨率下保持可读（假设您使用的是 1080p 显示器，因此 PIE 窗口以 720p 或类似分辨率运行）：![配置文件方法](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00223.jpeg)

1.  如果您使用**新的编辑器窗口**预览游戏，还可以看到缩放是如何工作的。

1.  要这样做，请单击工具栏上**播放**右侧的箭头。

1.  选择**新的编辑器窗口**。

1.  在这个窗口中，您可以使用控制台命令`r.setreswidthxheight`来改变分辨率，并观察由此产生的变化。

## 工作原理...

1.  通常情况下，当我们想要使用自定义的`PlayerController`时，我们需要一个自定义的`GameMode`来指定使用哪个`PlayerController`。

1.  我们创建了一个自定义的`PlayerController`和`GameMode`，并在`PlayerController`的`BeginPlay`方法中放置了一些`Slate`代码，以便绘制一些 UI 元素。

1.  因为在 Unreal 编辑器中，主游戏视口通常非常小，所以 UI 最初以缩小的方式显示。

1.  这旨在使游戏 UI 在较小的分辨率显示器上占用更少的空间，但如果窗口没有被拉伸以适应全屏，可能会导致文本非常难以阅读。

1.  Unreal 存储应在会话之间保持的配置数据，但不一定硬编码到可执行文件中的配置文件中。

1.  配置文件使用扩展版本的`.ini`文件格式，这个格式通常用于 Windows 软件。

1.  配置文件使用以下语法存储数据：

```cpp
[Section Name]
Key=Value
```

1.  Unreal 有一个名为`UserInterfaceSettings`的类，其中有一个名为`UIScaleCurve`的属性。

1.  该`UPROPERTY`被标记为配置，因此 Unreal 将该值序列化到`.ini`文件中。

1.  结果，它将`UIScale`数据存储在`DefaultEngine.ini`文件的`Engine.UserInterfaceSettings`部分中。

1.  数据使用文本格式存储，其中包含一个关键点列表。编辑`Time`，`Value`对会改变或添加新的关键点到曲线中。

1.  **项目设置**对话框是直接编辑`.ini`文件的简单前端界面，对于设计师来说，这是一种直观的编辑曲线的方式。然而，将数据以文本形式存储允许程序员潜在地开发修改`UIScale`等属性的构建工具，而无需重新编译游戏。

1.  `Time`指的是输入值。在这种情况下，输入值是屏幕的较窄维度（通常是高度）。

1.  `Value`是应用于 UI 的通用缩放因子，当屏幕的较窄维度大约等于`Time`字段中的值的高度时。

1.  因此，要将 UI 设置为在 1280x720 分辨率下保持正常大小，请将时间/输入因子设置为 720，比例因子设置为 1。

## 另请参阅

+   您可以参考 UE4 文档以获取有关配置文件的更多信息

# 在游戏中显示和隐藏一组 UMG 元素

因此，我们已经讨论了如何将小部件添加到视口中，这意味着它将在玩家的屏幕上呈现。

然而，如果我们希望根据其他因素（例如与某些角色的接近程度、玩家按住某个键或者希望在指定时间后消失的 UI）切换 UI 元素，该怎么办呢？

## 如何操作...

1.  创建一个名为`ToggleHUDGameMode`的新`GameMode`类。

1.  覆盖`BeginPlay`和`EndPlay`。

1.  添加以下`UPROPERTY`：

```cpp
UPROPERTY()
FTimerHandle HUDToggleTimer;
```

1.  最后添加这个成员变量：

```cpp
TSharedPtr<SVerticalBox> widget;
```

1.  在方法体中使用以下代码实现`BeginPlay`：

```cpp
void AToggleHUDGameMode::BeginPlay()
{
  Super::BeginPlay();
  widget = SNew(SVerticalBox)
  + SVerticalBox::Slot()
  .HAlign(HAlign_Center)
  .VAlign(VAlign_Center)
  [
    SNew(SButton)
    .Content()
    [
      SNew(STextBlock)
      .Text(FText::FromString(TEXT("Test button")))
    ]
  ];
  GEngine->GameViewport->AddViewportWidgetForPlayer(GetWorld()->GetFirstLocalPlayerFromController(), widget.ToSharedRef(), 1);

  GetWorld()->GetTimerManager().SetTimer(HUDToggleTimer, FTimerDelegate::CreateLambda
  ([this] 
  {
    if (this->widget->GetVisibility().IsVisible())
    {
      this->widget->SetVisibility(EVisibility::Hidden);
    }
    else
    {
      this->widget->SetVisibility(EVisibility::Visible);
    }
  }), 5, true);
}
```

1.  实现`EndPlay`：

```cpp
void AToggleHUDGameMode::EndPlay(constEEndPlayReason::Type EndPlayReason)
{
  Super::EndPlay(EndPlayReason);
  GetWorld->GetTimerManager().ClearTimer(HUDToggleTimer);
}
```

1.  **编译**您的代码，并启动编辑器。

1.  在编辑器中，从工具栏打开**World Settings**：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00224.jpeg)

1.  在**World Settings**中，覆盖关卡的**Game Mode**为我们的`AToggleHUDGameMode`：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00225.jpeg)

1.  玩游戏关卡，并验证 UI 每 5 秒切换可见性。

## 工作原理...

与本章中的大多数其他示例一样，我们使用自定义的`GameMode`类在玩家的视口上显示单人 UI 以方便操作：

1.  我们重写`BeginPlay`和`EndPlay`以便正确处理将为我们切换 UI 的计时器。

1.  为了实现这一点，我们需要将计时器的引用存储为`UPROPERTY`，以确保它不会被垃圾回收。

1.  在`BeginPlay`中，我们使用`SNew`宏创建一个新的`VerticalBox`，并将一个按钮放在其第一个槽中。

1.  按钮有`Content`，可以是其他小部件，如`SImage`或`STextBlock`。

1.  在这个示例中，我们将`STextBlock`放入`Content`槽中。文本块的内容不重要，只要足够长，我们就能正确看到按钮。

1.  在初始化小部件层次结构后，我们将根小部件添加到玩家的视口中，以便他们可以看到它。

1.  现在，我们设置一个计时器来切换小部件的可见性。我们使用计时器来简化这个示例，而不是实现用户输入和输入绑定，但原理是相同的。

1.  为此，我们获取游戏世界的引用和其关联的计时器管理器。

1.  有了计时器管理器，我们可以创建一个新的计时器。

1.  然而，我们需要实际指定计时器到期时要运行的代码。一种简单的方法是使用`lambda`函数来切换 hud 函数。

1.  `lambda`是匿名函数。将它们视为文字函数。

1.  要将`lambda`函数链接到计时器，我们需要创建一个`timer`委托。

1.  `FTimerDelegate::CreateLambda`函数旨在将`lambda`函数转换为委托，计时器可以在指定的间隔调用它。

1.  `lambda`需要从其包含对象（即我们的`GameMode`）访问`this`指针，以便它可以更改我们创建的小部件实例上的属性。

1.  为了给它所需的访问权限，我们在`lambda`声明中使用`[]`运算符，它将变量封装在`lambda`中，并在其中可访问。

1.  然后，花括号将函数体与普通函数声明的方式括起来。

1.  在函数内部，我们检查小部件是否可见。如果可见，则使用`SWidget::SetVisibility`隐藏它。

1.  如果小部件不可见，则使用相同的函数调用将其打开。

1.  在对`SetTimer`的其余调用中，我们指定调用计时器的间隔（以秒为单位），并设置计时器循环。

1.  但是，我们需要小心的是，在两个计时器调用之间，我们的对象可能被销毁，如果对我们的对象的引用被悬空，则可能导致崩溃。

1.  为了修复这个问题，我们需要移除计时器。

1.  鉴于我们在`BeginPlay`中设置了计时器，清除计时器在`EndPlay`中是有意义的。

1.  `EndPlay`将在`GameMode`结束游戏或被销毁时调用，因此我们可以在其实现期间安全地取消计时器。

1.  将`GameMode`设置为默认游戏模式后，UI 将在游戏开始播放时创建，并且计时器委托每 5 秒执行一次，以在小部件之间切换可见性。

1.  当你关闭游戏时，`EndPlay`会清除计时器引用，避免任何问题。

# 将函数调用附加到 Slate 事件

虽然创建按钮很好，但目前，无论用户点击它，屏幕上添加的任何 UI 元素都只是静静地存在。目前我们没有将事件处理程序附加到 Slate 元素，因此鼠标点击等事件实际上不会导致任何事情发生。

## 准备工作

此示例向您展示如何将函数附加到这些事件，以便在事件发生时运行自定义代码。

## 操作步骤...

1.  创建一个名为`AClickEventGameMode`的新的`GameMode`子类。

1.  将以下`private`成员添加到类中：

```cpp
private:
TSharedPtr<SVerticalBox> Widget;
TSharedPtr<STextBlock> ButtonLabel;
```

1.  添加以下`public`函数，注意`BeginPlay()`的重写：

```cpp
public:
virtual void BeginPlay() override;
FReplyButtonClicked();
```

1.  在`.cpp`文件中，添加`BeginPlay`的实现：

```cpp
void AClickEventGameMode::BeginPlay()
{
  Super::BeginPlay();
  Widget = SNew(SVerticalBox)
  + SVerticalBox::Slot()
  .HAlign(HAlign_Center)
  .VAlign(VAlign_Center)
  [
    SNew(SButton)
    .OnClicked(FOnClicked::CreateUObject(this, &AClickEventGameMode::ButtonClicked))
    .Content()
    [
      SAssignNew(ButtonLabel, STextBlock)
      .Text(FText::FromString(TEXT("Click me!")))
    ]
  ];
  GEngine->GameViewport->AddViewportWidgetForPlayer(GetWorld()->GetFirstLocalPlayerFromController(), Widget.ToSharedRef(), 1);
  GetWorld()->GetFirstPlayerController()->bShowMouseCursor = true;
  GEngine->GetFirstLocalPlayerController(GetWorld())->
  SetInputMode(FInputModeUIOnly().SetLockMouseToViewport(false).SetWidgetToFocus(Widget));
}
```

1.  还要为`ButtonClicked()`添加一个实现：

```cpp
FReplyAClickEventGameMode::ButtonClicked()
{
  ButtonLabel->SetText(FString(TEXT("Clicked!")));
  returnFReply::Handled();
}
```

1.  **编译**代码并启动编辑器。

1.  在**世界设置**中覆盖游戏模式为`AClickEventGameMode`：

1.  在编辑器中预览，并验证 UI 是否显示一个按钮，当您使用鼠标光标单击它时，按钮会从**Click Me!**更改为**Clicked!**。

## 工作原理...

1.  与本章中的大多数示例一样，我们使用`GameMode`来创建和显示 UI，以最小化需要创建的与示例目的无关的类的数量。

1.  在我们的新游戏模式中，我们需要保留对我们创建的 Slate 小部件的引用，以便在创建后与它们进行交互。

1.  因此，我们在`GameMode`中创建了两个共享指针作为成员数据，一个指向我们 UI 的整体父级或根部件，另一个指向我们按钮上的标签，因为我们将在运行时更改标签文本。

1.  我们重写`BeginPlay`，因为它是在游戏开始后创建 UI 的方便位置，并且我们将能够获得对玩家控制器的有效引用。

1.  我们还创建了一个名为`ButtonClicked`的函数。它返回`FReply`，一个指示是否处理了事件的`struct`。`ButtonClicked`的函数签名由我们将在下一步中使用的委托`FOnClicked`的签名确定。

1.  在我们的`BeginPlay`实现中，我们首先调用我们要重写的实现，以确保类适当地初始化。

1.  然后，像往常一样，我们使用`SNew`函数创建`VerticalBox`，并向其添加一个居中的插槽。

1.  我们在该插槽内创建一个新的`Button`，并向其添加一个值，该值包含在`OnClicked`属性中。

1.  `OnClicked`是一个委托属性。这意味着`Button`将在某个事件发生时广播`OnClicked`委托（正如在此示例中的名称所暗示的那样，当单击按钮时）。

1.  要订阅或监听委托，并在事件发生时收到通知，我们需要将委托实例分配给属性。

1.  我们可以使用标准的委托函数（如`CreateUObject`、`CreateStatic`或`CreateLambda`）来实现这一点。其中任何一个都可以工作 - 我们可以绑定`UObject`成员函数、静态函数、lambda 和其他函数。

### 注意

请查看第五章，*处理事件和委托*，了解更多关于委托的内容，以了解我们可以绑定到委托的其他类型的函数。

1.  `CreateUObject`期望一个指向类实例的指针，并且一个指向该类中定义的成员函数的指针来调用。

1.  该函数必须具有与委托的签名可转换的签名：

```cpp
/** The delegate to execute when the button is clicked */
FOnClickedOnClicked;
```

1.  如此所示，`OnClicked`委托类型为`FOnClicked` - 这就是为什么我们声明的`ButtonClicked`函数具有与`FOnClicked`相同的签名的原因。

1.  通过传入指向此对象实例的指针和要调用的函数的指针，当单击按钮时，引擎将在此特定对象实例上调用该函数。

1.  设置委托后，我们使用`Content()`函数，该函数返回对按钮应包含的任何内容的单个插槽的引用。

1.  然后，我们使用`SAssignNew`来创建我们按钮的标签，使用`TextBlock`小部件。

1.  `SAssignNew`很重要，因为它允许我们使用 Slate 的声明性语法，并且将变量分配给指向层次结构中特定子小部件的指针。

1.  `SAssignNew`的第一个参数是我们要将小部件存储在其中的变量，第二个参数是该小部件的类型。

1.  现在，`ButtonLabel`指向我们按钮的`TextBlock`，我们可以将其`Text`属性设置为静态字符串。

1.  最后，我们使用`AddViewportWidgetForPlayer`将小部件添加到玩家的视口中，该函数期望`LocalPlayer`作为参数添加小部件，小部件本身和深度值（较高的值在前面）。

1.  要获取`LocalPlayer`实例，我们假设我们在没有分屏的情况下运行，因此第一个玩家控制器将是唯一的控制器，即玩家的控制器。`GetFirstLocalPlayerFromController`函数是一个方便函数，它只是获取第一个玩家控制器，并返回其本地玩家对象。

1.  我们还需要将焦点放在小部件上，以便玩家可以点击它，并显示一个光标，以便玩家知道鼠标在屏幕上的位置。

1.  我们从上一步知道我们可以假设第一个本地玩家控制器是我们感兴趣的控制器，所以我们可以访问它并将其`ShowMouseCursor`变量更改为`true`。这将导致光标在屏幕上呈现。

1.  `SetInputMode`允许我们专注于一个小部件，以便玩家可以与其交互，以及其他与 UI 相关的功能，例如将鼠标锁定到游戏的视口。

1.  它使用一个`FInputMode`对象作为其唯一参数，我们可以使用`builder`模式构造具有我们希望包含的特定元素的对象。

1.  `FInputModeUIOnly`类是一个`FInputMode`子类，指定我们希望所有输入事件重定向到 UI 层，而不是玩家控制器和其他输入处理。

1.  `builder`模式允许我们在将对象实例作为参数发送到函数之前，链接方法调用以自定义对象实例。

1.  我们链式调用`SetLockMouseToViewport(false)`来指定玩家的鼠标可以离开游戏屏幕的边界，并使用`SetWidgetToFocus(Widget)`指定我们的顶级小部件作为游戏应该将玩家输入指向的小部件。

1.  最后，我们有了我们的实际实现`ButtonClicked`，我们的事件处理程序。

1.  当由于点击按钮而运行该函数时，我们将按钮的标签更改为指示它已被点击。

1.  然后，我们需要返回一个`FReply`的实例给调用者，以让 UI 框架知道事件已经被处理，并且不要继续向上传播事件。

1.  `FReply::Handled()`返回设置为指示给框架的`FReply`。

1.  我们本可以使用`FReply::Unhandled()`，但这将告诉框架点击事件实际上不是我们感兴趣的事件，它应该寻找其他可能对事件感兴趣的对象。

# 使用虚幻运动图形进行数据绑定

到目前为止，我们一直将静态值分配给 UI 小部件的属性。然而，如果我们想要在小部件内容或参数（如边框颜色）方面更加动态，怎么办？我们可以使用一个称为数据绑定的原则，将我们的 UI 的属性与更广泛的程序中的变量动态链接起来。

虚幻使用属性系统允许我们将属性的值绑定到函数的返回值，例如。这意味着更改这些变量将自动导致 UI 根据我们的意愿进行更改。

## 如何做到...

1.  创建一个名为`AAtributeGameMode`的新的`GameMode`子类。

1.  将以下`private`成员添加到类中：

```cpp
private:
TSharedPtr<SVerticalBox> Widget;
```

1.  添加以下`public`函数，注意`BeginPlay()`的重写：

```cpp
public:
virtual void BeginPlay() override;
FTextGetButtonLabel() const ;
```

1.  在`.cpp`文件中添加`BeginPlay`的实现：

```cpp
voidAClickEventGameMode::BeginPlay()
{
  Super::BeginPlay();
  Widget = SNew(SVerticalBox)
  + SVerticalBox::Slot()
  .HAlign(HAlign_Center)
  .VAlign(VAlign_Center)
  [
    SNew(SButton)
    .Content()
    [
      SNew(STextBlock)
      .Text( TAttribute<FText>::Create(TAttribute<FText>::FGetter::CreateUObject(this, &AAttributeGameMode::GetButtonLabel)))
    ]
  ];
  GEngine->GameViewport->AddViewportWidgetForPlayer(GetWorld()->GetFirstLocalPlayerFromController(), Widget.ToSharedRef(), 1);
}
```

1.  还要为`GetButtonLabel()`添加一个实现：

```cpp
FTextAAttributeGameMode::GetButtonLabel() const
{
  FVectorActorLocation = GetWorld()->GetFirstPlayerController()->GetPawn()->GetActorLocation();
  returnFText::FromString(FString::Printf(TEXT("%f, %f, %f"), ActorLocation.X, ActorLocation.Y, ActorLocation.Z));
}
```

1.  编译你的代码，并启动编辑器。

1.  在**世界设置**中覆盖游戏模式为`AAtributeGameMode`。

1.  请注意，在编辑器中播放时，UI 按钮上的值会随着玩家在场景中移动而改变。

## 工作原理...

1.  就像本章中几乎所有其他示例一样，我们首先需要创建一个游戏模式作为我们 UI 的方便宿主。我们以与其他示例相同的方式创建 UI，通过将`Slate`代码放在游戏模式的`BeginPlay()`方法中。

1.  这个示例的有趣之处在于我们如何设置按钮的标签文本的值：

```cpp
.Text( TAttribute<FText>::Create(TAttribute<FText>::FGetter::CreateUObject(this, &AAttributeGameMode::GetButtonLabel)))
```

1.  前面的语法非常冗长，但实际上它所做的事情相对简单。我们将某个值赋给`Text`属性，该属性的类型是`FText`。我们可以将`TAttribute<FText>`赋给该属性，每当 UI 想要确保`Text`的值是最新的时候，`TAttribute Get()`方法就会被调用。

1.  要创建`TAttribute`，我们需要调用静态的`TAttribute<VariableType>::Create()`方法。

1.  该函数期望一个委托的某种描述。根据传递给`TAttribute::Create`的委托类型，`TAttribute::Get()`调用不同类型的函数来检索实际值。

1.  在这个示例的代码中，我们调用了`UObject`的一个成员函数。这意味着我们知道我们将在某个委托类型上调用`CreateUObject`函数。

### 请注意

我们可以使用`CreateLambda`、`CreateStatic`或`CreateRaw`来分别在原始的 C++类上调用`lambda`、`static`或`member`函数。这将为我们提供属性的当前值。

1.  但是我们想要创建哪种委托类型的实例呢？因为我们在实际变量类型上对`TAttribute`类进行了模板化，所以我们需要一个委托，该委托的返回值也是以变量类型为模板的。

1.  也就是说，如果我们有`TAttribute<FText>`，与之连接的委托需要返回一个`FText`。

1.  我们在`TAttribute`中有以下代码：

```cpp
template<typenameObjectType>
classTAttribute
{
  public:
  /**
   * Attribute 'getter' delegate
   *
   * ObjectTypeGetValue() const
   *
   * @return The attribute's value
   */
  DECLARE_DELEGATE_RetVal(ObjectType, FGetter);
  (…)
}
```

1.  `FGetter`委托类型在`TAttribute`类内声明，因此它的返回值可以在`TAttribute`模板的`ObjectType`参数上进行模板化。

1.  这意味着`TAttribute<Typename>::FGetter`自动定义了一个具有正确返回类型`Typename`的委托。

1.  因此，我们需要创建一个类型和签名为`TAttribute<FText>::FGetter`的`UObject`绑定的委托。

1.  一旦我们有了那个委托，我们就可以在委托上调用`TAttribute::Create`，将委托的返回值与我们的`TextBlock`成员变量`Text`关联起来。

1.  在定义了我们的 UI 并将`Text`属性、`TAttribute<FText>`和返回`FText`的委托绑定之后，我们现在可以将 UI 添加到玩家的屏幕上，以便它可见。

1.  每一帧，游戏引擎都会检查所有属性，看它们是否与`TAttributes`相关联。

1.  如果存在连接，则调用`TAttribute`的`Get()`函数，调用委托，并返回委托的返回值，以便 Slate 可以将其存储在小部件的相应成员变量中。

1.  在我们演示这个过程时，`GetButtonLabel`检索游戏世界中第一个玩家角色的位置。

1.  然后我们使用`FString::Printf`将位置数据格式化为可读的字符串，并将其包装在`FText`中，以便将其存储为`TextBlock`的文本值。

# 使用样式控制小部件的外观

到目前为止，在本章中，我们一直在创建使用默认可视化表示的 UI 元素。本示例向您展示了如何在 C++中创建一个可以在整个项目中用作常见外观的样式。

## 操作步骤如下：

1.  在你的项目中创建一个新的类头文件。将文件命名为`"CookbookStyle.h"`。

1.  将以下代码添加到文件中：

```cpp
#pragma once
#include "SlateBasics.h"
#include "SlateExtras.h"
classFCookbookStyle
{
  public:
  static void Initialize();
  static void Shutdown();
  static void ReloadTextures();
  staticconstISlateStyle& Get();
  staticFNameGetStyleSetName();
  private:
  staticTSharedRef<class FSlateStyleSet> Create();
  private:
  staticTSharedPtr<class FSlateStyleSet>CookbookStyleInstance;
};
```

1.  为这个类创建一个相应的实现 cpp 文件，并将以下代码添加到其中：

```cpp
#include "UE4Cookbook.h"
#include "CookbookStyle.h"
#include "SlateGameResources.h"
TSharedPtr<FSlateStyleSet>FCookbookStyle::CookbookStyleInstance = NULL;
voidFCookbookStyle::Initialize()
{
  if (!CookbookStyleInstance.IsValid())
  {
    CookbookStyleInstance = Create();
    FSlateStyleRegistry::RegisterSlateStyle(*CookbookStyleInstance);
  }
}

voidFCookbookStyle::Shutdown()
{
  FSlateStyleRegistry::UnRegisterSlateStyle(*CookbookStyleInstance);
  ensure(CookbookStyleInstance.IsUnique());
  CookbookStyleInstance.Reset();
}
FNameFCookbookStyle::GetStyleSetName()
{
  staticFNameStyleSetName(TEXT("CookbookStyle"));
  returnStyleSetName;
}
#define IMAGE_BRUSH(RelativePath, ... ) FSlateImageBrush( FPaths::GameContentDir() / "Slate"/ RelativePath + TEXT(".png"), __VA_ARGS__ )
#define BOX_BRUSH(RelativePath, ... ) FSlateBoxBrush( FPaths::GameContentDir() / "Slate"/ RelativePath + TEXT(".png"), __VA_ARGS__ )
#define BORDER_BRUSH(RelativePath, ... ) FSlateBorderBrush( FPaths::GameContentDir() / "Slate"/ RelativePath + TEXT(".png"), __VA_ARGS__ )
#define TTF_FONT(RelativePath, ... ) FSlateFontInfo( FPaths::GameContentDir() / "Slate"/ RelativePath + TEXT(".ttf"), __VA_ARGS__ )
#define OTF_FONT(RelativePath, ... ) FSlateFontInfo( FPaths::GameContentDir() / "Slate"/ RelativePath + TEXT(".otf"), __VA_ARGS__ )

TSharedRef<FSlateStyleSet>FCookbookStyle::Create()
{
  TSharedRef<FSlateStyleSet>StyleRef = FSlateGameResources::New(FCookbookStyle::GetStyleSetName(), "/Game/Slate", "/Game/Slate");
  FSlateStyleSet& Style = StyleRef.Get();
  Style.Set("NormalButtonBrush", 
  FButtonStyle().
  SetNormal(BOX_BRUSH("Button", FVector2D(54,54),FMargin(14.0f/54.0f))));
  Style.Set("NormalButtonText",
  FTextBlockStyle(FTextBlockStyle::GetDefault())
  .SetColorAndOpacity(FSlateColor(FLinearColor(1,1,1,1))));
  returnStyleRef;
}
#undef IMAGE_BRUSH
#undef BOX_BRUSH
#undef BORDER_BRUSH
#undef TTF_FONT
#undef OTF_FONT

voidFCookbookStyle::ReloadTextures()
{
  FSlateApplication::Get().GetRenderer()->ReloadTextureResources();
}
constISlateStyle&FCookbookStyle::Get()
{
  return *CookbookStyleInstance;
}
```

1.  创建一个新的游戏模式子类`StyledHUDGameMode`，并将以下代码添加到其声明中：

```cpp
#pragma once
#include "GameFramework/GameMode.h"
#include "StyledHUDGameMode.generated.h"
/**
 * 
 */
UCLASS()
class UE4COOKBOOK_API AStyledHUDGameMode : public AGameMode
{
  GENERATED_BODY()
  TSharedPtr<SVerticalBox> Widget;
  public:
  virtual void BeginPlay() override;
};
```

1.  同样，实现`GameMode`：

```cpp
#include "UE4Cookbook.h"
#include "CookbookStyle.h"
#include "StyledHUDGameMode.h"
voidAStyledHUDGameMode::BeginPlay()
{
  Super::BeginPlay();
  Widget = SNew(SVerticalBox)
  + SVerticalBox::Slot()
  .HAlign(HAlign_Center)
  .VAlign(VAlign_Center)
  [
    SNew(SButton)
    .ButtonStyle(FCookbookStyle::Get(), "NormalButtonBrush")
    .ContentPadding(FMargin(16))
    .Content()
    [
      SNew(STextBlock)
      .TextStyle(FCookbookStyle::Get(), "NormalButtonText")
      .Text(FText::FromString("Styled Button"))
    ]
  ];
  GEngine->GameViewport->AddViewportWidgetForPlayer(GetWorld()->GetFirstLocalPlayerFromController(), Widget.ToSharedRef(), 1);
}
```

1.  最后，创建一个 54x54 像素的 png 文件，周围有一个边框用于我们的按钮。将其保存到`Content`|`Slate`文件夹中，名称为`Button.png`：！如何做...！如何做...

1.  最后，我们需要设置我们的游戏模块以在加载时正确初始化样式。在游戏模块的实现文件中，确保它看起来像这样：

```cpp
class UE4CookbookGameModule : public FDefaultGameModuleImpl
{
  virtual void StartupModule() override
  {
    FCookbookStyle::Initialize();
  };
  virtual void ShutdownModule() override
  {
    FCookbookStyle::Shutdown();
  };
};
```

1.  **编译**代码，并将游戏模式覆盖设置为本章中所做的其他示例中的新游戏模式。

1.  当你玩游戏时，你会看到你的自定义边框在按钮周围，并且文本是白色而不是黑色。！如何做...

## 它的工作原理是...

1.  为了创建可以在多个 Slate 小部件之间共享的样式，我们需要创建一个对象来包含这些样式并使它们保持在范围内。

1.  Epic 为此提供了`FSlateStyleSet`类。FSlateStyleSet 包含了许多样式，我们可以在 Slate 的声明语法中访问这些样式来为小部件设置皮肤。

1.  然而，将我们的`StyleSet`对象的多个副本散布在程序中是低效的。我们实际上只需要一个这样的对象。

1.  因为`FSlateStyleSet`本身不是一个单例，也就是说，一个只能有一个实例的对象，我们需要创建一个管理我们的`StyleSet`对象并确保我们只有一个实例的类。

1.  这就是为什么我们有`FCookbookStyle`类的原因。

1.  它包含一个`Initialize()`函数，我们将在模块的启动代码中调用它。

1.  在`Initialize()`函数中，我们检查是否有我们的`StyleSet`的实例。

1.  如果我们没有一个有效的实例，我们调用私有的`Create()`函数来实例化一个。

1.  然后，我们使用`FSlateStyleRegistry`类注册样式。

1.  当我们的模块被卸载时，我们需要撤销这个注册过程，然后擦除指针，以防止其悬空。

1.  现在，我们有了一个类的实例，在模块初始化时通过调用`Create()`来创建。

1.  您会注意到，`Create`被一些具有相似形式的宏包围。

1.  这些宏在函数之前定义，在函数之后取消定义。

1.  这些宏使我们能够通过消除我们的样式可能需要使用的所有图像资源的路径和扩展名来简化`Create`函数中所需的代码。

1.  在`Create`函数内部，我们使用函数`FSlateGameResources::New()`创建一个新的`FSlateStyleSet`对象。

1.  `New()`需要一个样式的名称，以及我们想要在这个样式集中搜索的文件夹路径。

1.  这使我们能够声明多个指向不同目录的样式集，但使用相同的图像名称。它还允许我们通过切换到其他基本目录中的样式集来简单地为整个 UI 设置皮肤或重新设置样式。

1.  `New()`返回一个共享引用对象，所以我们使用`Get()`函数检索实际的`FStyleSet`实例。

1.  有了这个引用，我们可以创建我们想要的样式集。

1.  要将样式添加到集合中，我们使用`Set()`方法。

1.  Set 期望样式的名称，然后是一个样式对象。

1.  可以使用`builder`模式自定义样式对象。

1.  我们首先添加一个名为`"NormalButtonBrush"`的样式。名称可以任意选择。

1.  因为我们想要使用这个样式来改变按钮的外观，所以我们需要使用第二个参数`FButtonStyle`。

1.  为了根据我们的要求自定义样式，我们使用 Slate 构建器语法，链接我们需要在样式上设置属性的任何方法调用。

1.  对于这个样式集中的第一个样式，我们只是在按钮没有被点击或处于非默认状态时改变其外观。

1.  这意味着我们希望在按钮处于正常状态时更改使用的画刷，因此我们使用的函数是`SetNormal()`。

1.  使用`BOX_BRUSH`宏，我们告诉 Slate 我们要使用`Button.png`，这是一个 54x54 像素大小的图像，并且我们要保持每个角的 14 像素不拉伸，以用于九切片缩放。

### 提示

要更直观地了解九切片缩放功能，请查看引擎源代码中的`SlateBoxBrush.h`。

1.  在我们的样式集中的第二个样式中，我们创建了一个名为`"NormalButtonText"`的样式。对于这个样式，我们不想改变样式中的所有默认值，我们只想改变一个属性。

1.  结果，我们访问默认的文本样式，并使用拷贝构造函数进行克隆。

1.  使用我们的默认样式的新副本后，我们将文本的颜色更改为白色，首先创建一个线性颜色 R=1 G=1 B=1 A=1，然后将其转换为 Slate 颜色对象。

1.  配置了我们的样式集并使用我们的两个新样式，然后我们可以将其返回给调用函数`Initialize`。

1.  `Initialize`存储了我们的样式集引用，并消除了我们创建进一步实例的需要。

1.  我们的样式容器类还有一个`Get()`函数，用于检索用于 Slate 的实际`StyleSet`。

1.  因为`Initialize()`已经在模块启动时被调用，所以`Get()`只是返回在该函数内创建的`StyleSet`实例。

1.  在游戏模块中，我们添加了实际调用`Initialize`和`Shutdown`的代码。这确保了在我们的模块加载时，我们始终有一个有效的 Slate 样式引用。

1.  与往常一样，我们创建一个游戏模式作为我们 UI 的主机，并重写`BeginPlay`以便在游戏开始时创建 UI。

1.  创建 UI 的语法与我们在之前的示例中使用的完全相同-使用`SNew`创建`VerticalBox`，然后使用 Slate 的声明性语法填充该框中的其他小部件。

1.  重要的是注意以下两行：

```cpp
.ButtonStyle(FCookbookStyle::Get(), "NormalButtonBrush")
.TextStyle(FCookbookStyle::Get(), "NormalButtonText")
```

1.  上述行是我们按钮的声明性语法的一部分，以及作为其标签的文本。

1.  当我们使用`<Class>Style()`方法为我们的小部件设置样式时，我们传入两个参数。

1.  第一个参数是我们实际的样式集，使用`FCookbookStyle::Get()`检索，第二个参数是一个字符串参数，其中包含我们要使用的样式的名称。

1.  通过这些小改动，我们重写了小部件的样式，以使用我们的自定义样式，这样当我们将小部件添加到播放器的视口时，它们会显示我们的自定义内容。

# 创建自定义的 SWidget/UWidget

到目前为止，本章的示例已经向您展示了如何使用现有的基本小部件创建 UI。

有时，开发人员使用组合来方便地将多个 UI 元素收集在一起，例如，定义一个按钮类，自动具有`TextBlock`作为标签，而不是每次手动指定层次结构。

此外，如果您在 C++中手动指定层次结构，而不是声明由子小部件组成的复合对象，您将无法使用 UMG 将这些小部件作为一组实例化。

## 准备工作

本示例向您展示了如何创建一个复合的`SWidget`，其中包含一组小部件，并公开新属性以控制这些子小部件的元素。它还将向您展示如何创建一个`UWidget`包装器，该包装器将新的复合`SWidget`类公开给 UMG 供设计师使用。

## 操作步骤如下：

1.  我们需要将 UMG 模块添加到我们模块的依赖项中。

1.  打开`<YourModule>.build.cs`，并将 UMG 添加到以下位置：

```cpp
PrivateDependencyModuleNames.AddRange(new string[] { "Slate", "SlateCore", "UMG" });
```

1.  创建一个名为`CustomButton`的新类，并将以下代码添加到其声明中：

```cpp
#pragma once
#include "SCompoundWidget.h"
class UE4COOKBOOK_API SCustomButton : public SCompoundWidget
{
  SLATE_BEGIN_ARGS(SCustomButton)
  : _Label(TEXT("Default Value"))
  , _ButtonClicked()
  {}
  SLATE_ATTRIBUTE(FString, Label)
  SLATE_EVENT(FOnClicked, ButtonClicked)
  SLATE_END_ARGS()
  public:
  void Construct(constFArguments&InArgs);
  TAttribute<FString> Label;
  FOnClickedButtonClicked;
};
```

1.  在相应的 cpp 文件中实现以下类：

```cpp
#include "UE4Cookbook.h"
#include "CustomButton.h"
voidSCustomButton::Construct(constFArguments&InArgs)
{
  Label = InArgs._Label;
  ButtonClicked = InArgs._ButtonClicked;
  ChildSlot.VAlign(VAlign_Center)
  .HAlign(HAlign_Center)
  [SNew(SButton)
  .OnClicked(ButtonClicked)
  .Content()
  [
  SNew(STextBlock)
  .Text_Lambda([this] {return FText::FromString(Label.Get()); })
  ]
  ];
}
```

1.  创建第二个类，这次基于`UWidget`，名为`UCustomButtonWidget`。

1.  添加以下包含：

```cpp
#include "Components/Widget.h"
#include "CustomButton.h"
#include "SlateDelegates.h"
```

1.  在类声明之前声明以下委托：

```cpp
DECLARE_DYNAMIC_DELEGATE_RetVal(FString, FGetString);
DECLARE_DYNAMIC_MULTICAST_DELEGATE(FButtonClicked);
```

1.  添加以下受保护成员：

```cpp
protected:
TSharedPtr<SCustomButton>MyButton;
virtualTSharedRef<SWidget>RebuildWidget() override;
```

1.  还添加以下公共成员：

```cpp
public:
UCustomButtonWidget();
UPROPERTY(BlueprintAssignable)
FButtonClickedButtonClicked;
FReplyOnButtonClicked();
UPROPERTY(BlueprintReadWrite, EditAnywhere)
FString Label;
UPROPERTY()
FGetStringLabelDelegate;
virtual void SynchronizeProperties() override;
```

1.  现在创建`UCustomButtonWidget`的实现：

```cpp
#include "UE4Cookbook.h"
#include "CustomButtonWidget.h"
TSharedRef<SWidget>UCustomButtonWidget::RebuildWidget()
{
  MyButton = SNew(SCustomButton)
  .ButtonClicked(BIND_UOBJECT_DELEGATE(FOnClicked, OnButtonClicked));
  returnMyButton.ToSharedRef();
}
UCustomButtonWidget::UCustomButtonWidget()
:Label(TEXT("Default Value"))
{
}

FReplyUCustomButtonWidget::OnButtonClicked()
{
  ButtonClicked.Broadcast();
  returnFReply::Handled();
}
voidUCustomButtonWidget::SynchronizeProperties()
{
  Super::SynchronizeProperties();
  TAttribute<FString>LabelBinding = OPTIONAL_BINDING(FString, Label);
  MyButton->Label = LabelBinding;
}
```

1.  通过右键单击**内容浏览器**，选择**用户界面**，然后选择**小部件蓝图**来创建一个新的小部件蓝图：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00229.jpeg)

1.  通过双击打开您的新**小部件蓝图**。

1.  在小部件面板中找到**自定义按钮小部件**：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00230.jpeg)

1.  将其拖动到主区域中的一个实例。

1.  选择实例后，在**详细信息**面板中更改**标签**属性：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00231.jpeg)

1.  验证您的按钮是否已更改其标签。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00232.jpeg)

1.  现在我们将创建一个绑定，以证明我们可以将任意蓝图函数链接到小部件上的标签属性，从而驱动小部件的文本块标签。

1.  点击**标签**属性右侧的**绑定**，然后选择**创建绑定**：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00233.jpeg)

1.  在现在显示的图表中，放置一个**获取游戏时间（以秒为单位）**节点：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00234.jpeg)

1.  将获取游戏时间节点的返回值链接到函数中的**返回值**引脚：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00235.jpeg)

1.  将自动为您插入一个将浮点数转换为字符串的节点：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00236.jpeg)

1.  接下来，通过单击任务栏上的**蓝图**按钮，然后选择**打开关卡蓝图**来打开**关卡蓝图**：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00237.jpeg)

1.  将构造小部件节点放入图表中：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00238.jpeg)

1.  选择要生成的小部件类作为我们刚刚在编辑器中创建的新小部件蓝图：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00239.jpeg)

1.  从创建小部件节点上的“拥有玩家”引脚上点击并拖动，然后放置一个“获取玩家控制器”节点：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00240.jpeg)

1.  同样，从创建小部件节点的返回值上点击并拖动，然后放置一个“添加到视口”节点：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00241.jpeg)

1.  最后，将`BeginPlay`节点链接到创建小部件节点上的执行引脚。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00242.jpeg)

1.  预览游戏，并验证我们在屏幕上显示的小部件是我们的新自定义按钮，其标签绑定到游戏开始后经过的秒数：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00243.jpeg)

## 工作原理...

1.  为了使用`UWidget`类，我们的模块需要将 UMG 模块作为其依赖项之一，因为`UWidget`在 UMG 模块内定义。

1.  然而，我们需要创建的第一个类是我们实际的`SWidget`类。

1.  因为我们想要将两个小部件聚合到一个复合结构中，所以我们将我们的新小部件创建为`CompoundWidget`子类。

1.  `CompoundWidget`允许您将小部件层次结构封装为小部件本身。

1.  在类内部，我们使用`SLATE_BEGIN_ARGS`和`SLATE_END_ARGS`宏在我们的新`SWidget`上声明一个名为`FArguments`的内部结构。

1.  在`SLATE_BEGIN_ARGS`和`SLATE_END_ARGS`之间，使用了`SLATE_ATTRIBUTE`和`SLATE_EVENT`宏。

1.  `SLATE_ATTRIBUTE`为我们提供的类型创建`TAttribute`。

1.  在这个类中，我们声明了一个名为`_Label`的`TAttribute`，更具体地说，它是一个`TAttribute<FString>`。

1.  `SLATE_EVENT`允许我们创建成员委托，当小部件内部发生某些事情时可以广播。

1.  在`SCustomButton`中，我们声明了一个具有`FOnClicked`签名的委托，名为`ButtonClicked`。

1.  `SLATE_ARGUMENT`是另一个宏，在本示例中未使用，它创建一个带有您提供的类型和名称的内部变量，并在变量名前面添加下划线。

1.  `Construct()`是小部件在实例化时实现的自我初始化函数。

1.  您会注意到我们还创建了一个没有下划线的`TAttribute`和`FOnClicked`实例，这些是我们对象的实际属性，之前声明的参数将被复制到其中。

1.  在`Construct`的实现中，我们检索传递给我们的参数，并将它们存储在此实例的实际成员变量中。

1.  我们根据传入的内容分配`Label`和`ButtonClicked`，然后实际创建我们的小部件层次结构。

1.  我们使用与通常相同的语法，但需要注意的是，我们使用`Text_Lambda`来设置内部文本块的文本值。

1.  我们使用`lambda`函数使用`Get()`来检索我们的`Label` `TAttribute`的值，然后将其转换为`FText`，并将其存储为我们文本块的`Text`属性。

1.  现在我们已经声明了我们的`SWidget`，我们需要创建一个包装器`UWidget`对象，将这个小部件暴露给 UMG 系统，以便设计师可以在**所见即所得**编辑器中使用该小部件。

1.  这个类将被称为`UCustomButtonWidget`，它继承自`UWidget`而不是`SWidget`。

1.  `UWidget`对象需要引用它拥有的实际`SWidget`，所以我们在类中放置了一个受保护的成员，将其存储为共享指针。

1.  声明了一个构造函数，还声明了一个可以在蓝图中设置的`ButtonClicked`委托。我们还镜像了一个被标记为`BlueprintReadWrite`的`Label`属性，以便可以在 UMG 编辑器中设置它。

1.  因为我们希望能够将按钮的标签绑定到一个委托上，所以我们添加了最后一个成员变量，这是一个返回`String`的委托。

1.  `SynchronizeProperties`函数将在我们链接的`SWidget`上应用在`UWidget`类中被镜像的属性。

1.  `RebuildWidget`重新构建与此`UWidget`关联的本地小部件。它使用`SNew`来构造我们的`SCustomButton`小部件的实例，并使用 Slate 声明语法将 UWidget 的`OnButtonClicked`方法绑定到本地小部件内部的`ButtonClicked`委托。

1.  这意味着当本地小部件被点击时，`UWidget`将通过调用`OnButtonClicked`来接收通知。

1.  `OnButtonClicked`通过 UWidget 的`ButtonClicked`委托重新广播来自本地按钮的点击事件。

1.  这意味着 UObjects 和 UMG 系统可以在没有对本地按钮小部件的引用的情况下被通知到按钮被点击的事件。我们可以绑定到`UCustomButtonWidget::ButtonClicked`来接收通知。

1.  `OnButtonClicked`然后返回`FReply::Handled()`，表示事件不需要进一步传播。

1.  在`SynchronizeProperties`中，我们调用父类的方法，以确保父类中的任何属性也能正确同步。

1.  我们使用`OPTIONAL_BINDING`宏将我们`UWidget`类中的`LabelDelegate`委托与`TAttribute`和本地按钮的标签进行关联。重要的是要注意，`OPTIONAL_BINDING`宏期望委托被称为`NameDelegate`，基于宏的第二个参数。

1.  `OPTIONAL_BINDING`允许通过 UMG 进行的绑定覆盖值，但前提是 UMG 绑定是有效的。

1.  这意味着当`UWidget`被告知更新自身时，例如，因为用户在 UMG 中的**详细信息**面板中自定义了一个值，它将在必要时重新创建本地`SWidget`，然后通过`SynchronizeProperties`复制在蓝图/UMG 中设置的值，以确保一切正常工作。


# 第十章：控制 NPC 的 AI

在游戏中，"人工智能"（AI）的角色非常重要。在本章中，我们将介绍以下用于控制 NPC 角色的 AI 的配方：

+   放置导航网格

+   遵循行为

+   将行为树连接到角色

+   构建任务节点

+   使用装饰器进行条件判断

+   使用周期性服务

+   使用复合节点-选择器、序列和简单并行

+   近战攻击者的 AI

# 介绍

AI 包括游戏的 NPC 以及玩家行为的许多方面。AI 的一般主题包括寻路和 NPC 行为。通常，我们将 NPC 在游戏中的一段时间内所做的选择称为行为。

UE4 中的 AI 得到了很好的支持。编辑器内部提供了许多构造，允许进行基本的 AI 编程。如果引擎内提供的 AI 不符合您的需求，还可以使用 C++进行自定义 AI 编程。

# 放置导航网格

导航网格（也称为"Nav Mesh"）基本上是 AI 控制单位认为可通过的区域的定义（即，"AI 控制"单位被允许进入或穿越的区域）。导航网格不包括如果玩家试图穿过它移动的几何体。

## 准备就绪

根据场景的几何形状构建导航网格在 UE4 中相当简单。从一些障碍物周围开始，或者使用一个地形。

## 如何做到这一点...

要构建导航网格，只需执行以下步骤：

1.  转到"模式" | "体积"。

1.  将导航网格边界体拖放到视口中。

### 提示

按下 P 键查看您的导航网格。

1.  将导航网格的范围扩大到允许使用导航网格的角色可以导航和路径规划的区域。

## 它是如何工作的...

导航网格不会阻止玩家角色（或其他实体）踩在特定的几何体上，但它可以指导 AI 控制的实体在哪里可以去，哪里不能去。

# 遵循行为

最基本的 AI 控制跟随行为可以作为一个简单的函数节点使用。您只需要执行以下步骤，就可以让一个 AI 控制的单位跟随一个单位或对象。

## 准备就绪

准备一个 UE4 项目，其中包含一个简单的地形或一组地形-理想情况下，地形中有一个"死胡同"，用于测试 AI 移动功能。在这个地形上创建一个导航网格，以便"AIMoveTo"函数可以按照前面的配方描述的方式工作。

## 如何做到这一点...

1.  根据前面的步骤，为您的关卡几何体创建一个导航网格，即"放置导航网格"中所述。

1.  通过在"类查看器"中找到"Character"类，右键单击它，并选择"创建蓝图类..."，创建一个从"Character"派生的蓝图类。

1.  将您的蓝图类命名为"BP_Follower"。

1.  双击"BP_Follower"类以编辑其蓝图。

1.  在"Tick"事件中，添加一个"AIMoveTo"节点，该节点向玩家角色（或任何其他单位）移动，如下所示：![如何做到这一点...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00244.jpeg)

## 它是如何工作的...

如果有可用的导航网格，"AIMoveTo"节点将自动使用导航网格。如果没有可用的导航网格，NPC 单位将不会移动。

## 还有更多...

如果您不希望单位使用导航网格进行路径规划移动，只需使用"移动到位置或角色"节点即可。

![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00245.jpeg)

即使在几何体上没有导航网格，"移动到位置或角色"节点也可以工作。

# 将行为树连接到角色

在任何给定的时间点，"行为树"会选择一个 AI 控制单位要展示的行为。行为树相对简单，但需要进行大量的设置才能运行。您还必须熟悉用于构建"行为树"的组件，以便有效地进行设置。

行为树非常有用，可以定义 NPC 的行为，使其比仅仅向对手移动（如前面的`AIMoveTo`示例）更加多样化。

## 准备就绪

设置控制角色的行为树的过程相当复杂。我们首先需要一个`Character`类派生类的蓝图来进行控制。然后，我们需要创建一个自定义的 AI 控制器对象，该对象将运行我们的行为树来控制我们的近战攻击者角色。我们的蓝图中的`AIController`类将运行我们的行为树。

![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00246.jpeg)

行为树本身包含一个非常重要的数据结构，称为**黑板**。黑板类似于一个黑板，用于存储行为树的变量值。

行为树包含六种不同类型的节点，如下所示：

1.  **任务**：任务节点是行为树中的紫色节点，包含要运行的蓝图代码。这是 AI 控制的单位必须要做的事情（代码方面）。任务必须返回`true`或`false`，取决于任务是否成功（通过在末尾提供`FinishExecution()`节点）。![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00247.jpeg)

1.  **修饰器**：修饰器只是节点执行的布尔条件。它检查一个条件，通常在选择器或序列块中使用。![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00248.jpeg)

1.  **服务**：在每次执行时运行一些蓝图代码。这些节点的执行间隔是可调节的（可以比每帧执行慢，例如每 10 秒执行一次）。您可以使用这些节点查询场景更新，或者追逐新的对手等等。黑板可以用来存储查询到的信息。服务节点在末尾没有`FinishExecute()`调用。在前面的图表中的序列节点中有一个示例服务节点。

1.  **选择器**：从左到右运行所有子树，直到遇到成功。遇到成功后，执行返回到树的上层。

1.  **序列**：从左到右运行子树，直到遇到失败。遇到失败后，执行返回到树的上层。![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00249.jpeg)

### 注意

选择器节点尝试执行节点，直到成功（然后返回），而序列节点执行所有节点，直到遇到失败（然后返回）。

请记住，如果您的任务没有调用`FinishExecute()`，选择器和序列将无法连续运行多个任务。

1.  **简单并行**：在并行运行一个任务（紫色）和一个子树（灰色）。![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00250.jpeg)

## 如何操作...

1.  首先，在 UE4 中为您的近战单位创建一个蓝图。您可以通过从`Character`派生一个自定义蓝图来实现。要这样做，请转到**类查看器**，输入`Character`，然后右键单击。从出现的上下文菜单中选择**创建蓝图...**，并将您的蓝图类命名为`BP_MeleeCharacter`。

1.  要使用行为树，我们需要首先为我们的`Character`类派生类设置一个自定义 AI 控制器。转到**内容浏览器**，从`AIController`类派生一个蓝图，确保首先关闭**过滤器** | **仅限角色**！

### 注意

非 actor 类的派生类默认情况下不显示在**类查看器**中！要显示`AIController`类，您需要转到**过滤器**菜单并取消选中**仅限角色**菜单选项。

1.  通过在**内容浏览器**中右键单击并选择**人工智能** | **行为树**和**人工智能** | **黑板**来创建您的行为树和黑板对象。

1.  打开**行为树**对象，在**详细信息**面板的**黑板资产**下，选择您创建的黑板。黑板包含用于行为树的键和值（命名变量）。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00251.jpeg)

1.  打开您的`BP_AIMeleeController`类派生类并转到事件图。在**事件 BeginPlay**下，选择并添加一个**运行行为树**节点到图表中。在`BTAsset`下，确保选择您的`BehaviorTree_FFA_MeleeAttacker`资源。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00252.jpeg)

## 工作原理...

行为树连接到 AI 控制器，而 AI 控制器连接到角色的蓝图。我们将通过在图表中输入任务和服务节点来通过行为树控制`Character`的行为。

# 构建任务节点

任务节点类似于函数块。您构建的每个任务节点都将允许您将一些蓝图代码捆绑在一起，以在行为树中满足某些条件时执行。

任务有三个不同的事件：接收 Tick（带有 AI 版本），接收执行（AI）和接收中止（AI）。您可以在任务的蓝图中响应这三个事件中的任何一个。通常，您应该响应任务的接收执行（AI 版本）。

## 准备工作

要创建一个任务节点，您应该已经准备好一个行为树，并将其附加到适当的 AI 控制器和蓝图角色上（参见前面的示例）。

## 操作步骤...

1.  要在任务节点中构建可执行的蓝图代码，您必须从我们的行为树蓝图编辑器的菜单栏中选择**新任务**。从出现的下拉菜单中，选择以`BTTask_BlueprintBase`为基础的**新任务**。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00253.jpeg)

### 提示

与行为树或黑板创建不同，没有直接从**内容浏览器**创建**新任务**的方法。

1.  双击打开刚刚创建的行为树任务以进行编辑。覆盖任何可用事件（在**我的蓝图**选项卡下的**函数**子标题中列出）：

1.  **接收 Tick AI**：行为树任务的`Tick`事件的 AI 版本。当您需要任务与包含它的角色一起进行`Tick`时，应该覆盖此函数。如果您只希望任务在行为树调用它时执行（而不是在游戏引擎进行 Tick 时执行），请不要覆盖此函数。

1.  **接收执行 AI**：您要覆盖的主要函数。接收执行 AI 允许您在从行为树图表中调用任务节点时运行一些蓝图代码。

1.  **接收中止 AI**：当任务被中止时调用的行为树任务中止。当蓝图图表中的`FinishAbort()`节点调用时，应该覆盖此函数。

### 提示

前面的函数还有非 AI 版本，它们只是参数有所不同：在`*AI`版本中，所有者对象被强制转换为`Pawn`，并且有一个所有者控制器传递给事件调用。

# 使用装饰器进行条件判断

**装饰器**是一种允许您在评估另一个节点时输入条件表达式的节点。它们的命名相当奇怪，但它们被称为装饰器，因为它们倾向于为执行节点添加执行条件。例如，在下面的图表中，只有在满足装饰器条件时才会执行`MoveTo`函数：

![使用装饰器进行条件判断](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00254.jpeg)

UE4 附带了几个预打包的装饰器，包括黑板（变量检查），**比较黑板条目**，**锥体检查**，**冷却时间**，**路径是否存在**等等。在本示例中，我们将探索使用其中一些条件来控制行为树的不同分支的执行。

## 准备工作

只有在现有**行为树**的菜单栏中才能创建装饰器。

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00255.jpeg)

### 注意

**新装饰器**按钮位于现有**行为树**的菜单栏中，因此要找到它，您必须打开现有的**行为树**。

## 操作步骤...

1.  在现有**行为树**的菜单栏中，选择**新装饰器**。以现有蓝图`BTDecorator_BlueprintBase`为基础。

1.  组装您的蓝图图表，确定装饰器的条件在`PerformConditionCheck`函数覆盖下是否成功。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00256.jpeg)

1.  装饰器的内部检查是否跟随黑板中的目标是否在某个半径的边界球内。如果装饰器的条件满足（并且依赖于装饰器的块执行），则返回`true`，否则返回`false`（并且依赖于装饰器的块不执行）。

## 工作原理...

装饰器就像`if`语句一样；唯一的区别是它们在行为树中直接在它们下面放置一个条件来执行节点。

# 使用周期性服务

**服务**是包含要定期执行的蓝图代码的节点。服务与任务非常相似，但它们没有`FinishExecute()`的调用。

## 准备工作

将服务添加到行为树中对于周期性检查非常重要，例如检查是否有任何新的敌方单位在范围内，或者当前目标是否离开焦点。您可以创建自己的服务。在本教程中，我们将组装一个服务，该服务将检查您正在跟随的对手是否仍然是可见锥体内最近的对手。如果不是，则对手将更改。

服务节点有四个主要事件（除了 Tick）：

1.  **接收激活 AI**：当行为树启动并且节点首次激活时触发。

1.  **接收搜索开始 AI**：当行为树进入底层分支时触发。

1.  **接收 Tick AI**：在调用服务的每一帧触发。大部分工作在这里完成。

1.  **接收停用 AI**：当行为树关闭并且节点停用时触发。

## 如何操作...

1.  首先，通过**行为树**菜单栏中的**新服务**按钮将**新服务**添加到**行为树**中：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00257.jpeg)

1.  将您的服务命名为描述其功能的名称，例如`BehaviorTree_Service_CheckTargetStillClosest`。

1.  双击服务以开始编辑其蓝图。

1.  在编辑器中，添加一个接收 Tick AI 节点，并对您需要的黑板进行任何更新。

## 工作原理...

服务节点在一些规律的时间间隔（可以有偏差选项）执行一些蓝图代码。在服务节点内部，通常会更新您的黑板。

# 使用复合节点 - 选择器、序列和简单并行

复合节点形成行为树中的树节点，并包含多个要在其中执行的内容。有三种类型的复合节点：

+   **选择器**：从左到右遍历子节点，寻找成功的节点。如果一个节点失败，它会尝试下一个节点。当成功时，节点完成，我们可以返回树。

+   **序列**：从左到右执行，直到节点失败。如果节点成功，则执行下一个节点。如果节点失败，则返回树。

+   **简单并行**：将单个任务（紫色）与某个子树（灰色）并行执行。

## 准备工作

使用复合节点非常简单。您只需要一个行为树就可以开始使用它们。

## 如何操作...

1.  在行为树图中的空白处右键单击。

1.  选择**复合** | **选择器或复合** | **序列**。

+   **选择器**：按顺序执行所有任务，直到成功执行一个任务。

+   **序列**：按顺序执行所有任务，直到一个任务失败。

1.  根据需要将一系列任务或其他复合节点附加到节点上。

# 近战攻击者的 AI

我们可以使用行为树构建具有近战攻击行为的 NPC。近战攻击者将具有以下行为：

1.  每 10 秒搜索最佳对手进行攻击。最佳对手是范围内最近的对手。我们将使用一个服务来实现这一点。将我们正在攻击的对手记录在近战攻击者的行为树黑板中。

1.  朝着我们正在攻击的对手移动（由黑板指示）。

1.  如果我们与对手的距离小于`AttackRadius`单位，则每隔`AttackCooldown`秒对正在攻击的对手造成伤害。

### 提示

这只是使用`BehaviorTree`攻击对手的一种方式。你会发现你也可以在近战攻击者的攻击动画中进行攻击，在这种情况下，你只需在接近对手的`AttackRadius`范围内指示播放动画。

## 准备工作

准备一个近战攻击者角色的蓝图。我称之为`BP_Melee`。准备`BP_Melee`角色的 AI 控制器，以使用我们接下来将创建的新行为树。

## 如何操作...

1.  从根节点开始，如果失败则立即返回。在其中创建一个名为`BehaviorTree_Service_FindOpponent`的新序列节点。将节点的间隔设置为 10 秒。

1.  按照以下步骤构建`BehaviorTree_Service_FindOpponent`节点：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00258.jpeg)

1.  在另一个行为树节点中，指示每帧朝着跟随目标移动：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00259.jpeg)

1.  最后，当玩家在对手的`AttackRadius`范围内时，我们希望对对手造成伤害。当玩家在`AttackRadius`范围内时，你可以开始播放攻击动画（这可能会触发对对手的伤害事件），运行一个伤害服务（每隔`AttackCooldown`秒），或者如下截图所示简单地进行**冷却**和**对对手造成伤害**：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00260.jpeg)


# 第十一章：自定义材质和着色器

UE4 中的材质定义和创建工具非常出色，更不用说其实时渲染性能了。当您看到您的第一个闪闪发光的金色着色器时，您会对 UE4 的材质着色能力感到惊讶，这是通过一些数学计算实现的。我们将通过以下教程向您展示如何使用这些工具：

+   使用基本材质修改颜色

+   使用材质修改位置

+   通过自定义节点的着色器代码

+   材质函数

+   着色器参数和材质实例

+   闪烁

+   叶子和风

+   与观察角度有关的反射

+   随机性-柏林噪声

+   给景观着色

# 介绍

在计算机图形学中，**着色器**用于给某物上色。传统上，着色器之所以被称为着色器，是因为它们根据原始颜色和光源位置定义了物体的阴影。

现在，着色器不再被认为是为对象提供阴影，而是提供纹理和最终颜色。

![介绍](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00261.jpeg)

### 注意

着色器是关于确定物体的最终颜色的，给定光源、几何位置和初始颜色（包括纹理，以及更昂贵的材质属性）。

着色器有两种类型：顶点着色器和像素着色器。

+   **顶点着色器**：顶点（网格中的点）的颜色，并且从一个三维点平滑着色到另一个三维点。

+   **像素着色器**：像素（屏幕上的点）的颜色。使用一些简单的数学计算来计算像素（也称为片段）的三维物理位置。

在 UE4 中，我们将着色器称为材质。材质将顶点和片段处理管线抽象为可编程块函数，因此您无需考虑 GPU 或编码即可获得所需的图形输出。您只需以块和图片的形式思考。您可以构建材质并构建 GPU 着色功能，而无需编写一行**高级着色语言**（**HLSL**）、**OpenGL 着色语言**（**GLSL**）或 Cg（用于图形）代码！

### 提示

您通常会听到三种主要的 GPU 编程语言：HLSL、GLSL 和 Cg。GLSL 是 OpenGL 的 GPU 编程语言，而 HLSL 是微软的产品。在 90 年代和 21 世纪的第一个十年中，Cg 诞生了，试图将所有 GPU 编程统一起来。Cg 仍然很受欢迎，但 GLSL 和 HLSL 也仍然广泛使用。

# 使用基本材质修改颜色

材质的主要用途是使表面呈现您想要的颜色。在您的场景中，您将拥有光源和表面。表面上涂有反射和折射光线的材质，您可以通过相机的眼睛看到。材质的基本操作是修改表面的颜色。

### 提示

不要忽视调整光源以使材质看起来符合您的期望的重要性！

熟悉材质编辑器需要一些练习，但一旦您熟悉了它，您可以用它做出令人惊叹的事情。在本教程中，我们将只使用一些非常基本的功能来构建一个木质纹理材质。

### 提示

纹理与材质的区别：请记住，纹理和材质这两个术语之间有很大的区别。纹理只是一个图像文件（例如一张名为`wood.png`的照片）；而材质则是一组纹理、颜色和数学公式的组合，用于描述表面在光线下的外观。材质将考虑表面的属性，如颜色吸收、反射和光泽度，而纹理只是一组有色像素（或者 GPU 称之为纹素）。

着色器的编程方式与普通的 C++代码相同，只是限制更多。有几种参数类型可供选择。其中大多数将是浮点数或以向量格式排列的浮点数包（`float`，`float2`，`float3`，`float4`）。对于位置和颜色等内容，您将使用`float3`或`float4`；对于纹理坐标等内容，您将使用`float2`。

## 准备工作

您需要一个干净的 UE4 项目，将其中放置您的新材质。在 UE4 项目中安装来自 UE4 市场（Epic Games Launcher 应用程序）的**GameTexture Materials**包。它包含我们在本教程中需要的一些必需纹理。您还需要一个简单的几何体来显示着色器的结果。

## 如何操作...

1.  要创建一个基本材质，在**内容浏览器**中右键单击，并创建一个**材质**（在前四个基本资产元素中可用）。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00262.jpeg)

1.  为您的材质命名（例如`GoldenMaterial`），然后双击它进行编辑。

1.  欢迎来到材质编辑器：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00263.jpeg)

1.  您可以通过右侧的材质输出节点来判断它是材质编辑器。左侧是一个 3D 渲染的球体，展示了您的材质的外观。材质最初是一种类似煤炭的黑色半光泽材质。我们可以调整所有材质参数，从像太阳一样发光的材质，到水，或者到单位装甲的纹理。让我们从调整材质的输出颜色开始，创建一个金色的金属材质。

1.  通过右键单击材质编辑器窗口中的任何空白处，并选择**Constant3Vector**（表示 RGB 颜色）将**基础颜色**更改为黄色。通过双击节点并拖动颜色样本的值来调整颜色。将 Constant3Vector 的输出连接到**基础颜色**，等待左侧的 3D 图片重新加载以显示您的新材质外观。将 Constant3Vector 的输出连接到**基础颜色**，使材质呈现黄色，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00264.jpeg)

1.  通过将一个常量值附加到**金属**输入并将其设置为 1，为所有通道选择一个金属度级别。1 表示非常金属，0 表示完全不金属（因此看起来像下一个截图中显示的材质一样塑料）。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00265.jpeg)

1.  为材质选择一个**高光**值，同样在 0 到 1 之间。**高光**材质是有光泽的，而非高光材质则没有。

1.  为材质选择一个**粗糙度**值。**粗糙度**指的是镜面高光的扩散程度。如果**粗糙度**很高（接近 1.0），则表面类似于黏土，几乎没有镜面高光。镜面高光在 0.7 或 0.8 附近的值附近呈现出较宽的形状。当粗糙度接近 0 时，镜面高光非常锐利而细小（极其光亮/镜面般的表面）。

![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00266.jpeg)

### 注意

左侧的材质的粗糙度为 0，右侧的材质的粗糙度为 1。

1.  通过单击并拖动材质到您想要应用材质的模型网格上，将材质应用于场景中的对象。或者，通过名称在**详细信息**面板中选择一个模型网格组件和您创建的新材质。

1.  最后，在场景中创建一个光源以进一步检查材质的响应属性。没有光源，每个材质都会显示为黑色（除非它是自发光材质）。通过**模式** | **灯光**添加一个光源。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00267.jpeg)

# 使用材质修改位置

不常见的是使用材质来修改对象的位置。这通常在水着色器等方面使用。我们使用材质输出中的**世界位置偏移**节点来实现这一点。

![使用材质修改位置](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00268.jpeg)

我们可以使用一些 GPU 数学来调制顶点的输出位置。这样做可以显著减轻 CPU 渲染逼真水体的负担。

## 准备工作

在你的世界中创建一个几何体。构建一个名为`Bob`的新着色器，我们将编辑它以产生一个简单的上下浮动的运动效果，用于渲染使用该材质的对象。

## 操作步骤...

1.  在你的新材质（名为`Bob`）中，右键单击并添加**Texcoord**和**Time Input**节点。

1.  通过对`sin()`函数调用级联**Texcoord**（用于空间）和**Time Input**节点的总和，创建一些波浪位移。将`sin()`函数的输出乘以并作为 Z 输入传递给**World Displacement**。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00269.jpeg)

### 注意

给出在`Chapter11`代码中的简单水体着色器的一部分，它产生位移。

1.  在**Tessellation** | **D3D11Tessellation Mode**下选择**PN Triangles**，并将材质中的**Tessellation Multiplier**设置为 1.0。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00270.jpeg)

### 提示

通常情况下，UE4 着色器中无法同时使用高光和半透明效果。然而，表面每像素（实验性，功能有限）光照模式允许你同时启用两者。除了选择这种光照模式外，你还必须记住确保按下`` ` `` 并在状态控制台窗口中输入`r.ForwardLighting 1`。

# Shader code via Custom node

If you prefer code to diagrammatic blocks, you're in luck. You can write your own HLSL code to deploy to the GPU for the shading of some vertices in your project. We can construct **Custom** nodes that simply contain math code working on named variables to perform some generic computation. In this recipe, we'll write a custom math function to work with.

## Getting ready

You need a material shader, and a general mathematical function to implement. As an example, we'll write a **Custom** node that returns the square of all inputs.

## How to do it...

1.  In order to create a custom material expression, simply right-click anywhere on the canvas, and select **Custom**.![How to do it...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00271.jpeg)
2.  With your new **Custom** block selected, go to the **Details** panel on the left side of your Material Editor window (choose **Window** | **Details** if your **Details** panel is not displayed).
3.  Under **Description**, name your **Custom** block. For example, `Square3`, because we plan to square three float inputs and return a `float3`.
4.  Click the **+** icon as many times you need to generate as many inputs as you need to serve. In this case, we're going to serve three float inputs.
5.  Name each input. We've named ours *x*, *y,* and *z* in the diagram that follows. To use each input in the calculation, you must name it.
6.  Select the output type. Here we chose to output a `float3`.
7.  Enter the computation in the **Code** section at the top using the named variables you have created. The code we return here is as follows:

```

return float3( x*x, y*y, z*z );

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00272.jpeg)

### 提示

这样做的作用是构建一个 3 个浮点数的向量，并将*X*的平方返回到`x`值中，将*Y*的平方返回到`y`值中，将*Z*的平方返回到`z`值中。

为了返回向量类型的*X*、*Y*、*Z*分量的不同值，我们必须返回对`float3`或`float4`构造函数的调用。如果你不返回向量类型，你可以只使用一个`return`语句（不调用`float`构造函数）。

## 工作原理...

自定义节点实际上只是一段 HLSL 代码。任何有效的 HLSL 代码都可以在代码文本字段中使用。顶点或像素着色器程序中有几个标准输入。这些标准输入已经定义了很长时间，它们是你可以用来改变几何体渲染方式的参数。

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00273.jpeg)

HLSL 和 Cg 有一个称为语义的概念，它将一种具体的类型与一个浮点数关联起来。这样做是为了外部调用着色器的程序在调用顶点或像素着色程序时知道在哪里放置哪个输入。

在下面的 Cg 函数签名中，除了是一个`float`变量之外，`inPosition`在语义上是一个`POSITION`类型的变量，`inTexcoord`是一个`TEXCOORD`类型的变量，`inColor`是一个`COLOR`类型的变量。在着色器内部，你可以将这些变量用于任何你想要的目的，语义只是为了将正确的输入路由到正确的变量（以确保颜色通过`COLOR`类型的变量输入，否则我们将不得不跟踪参数的指定顺序或其他操作！）

函数的输出参数指定了如何解释着色器的输出。解释仅适用于程序的输出数据的接收者（渲染管线中的下一步）。在着色器程序内部，你知道你只是将一堆浮点数写入着色器管线。没有什么禁止你在着色器内部混合不同类型的语义。一个`COLOR`语义变量可以乘以一个`POSITION`语义输入，并作为`TEXCOORD`语义输出发送出去，如果你愿意的话。

# 材质函数

一如既往，**模块化**是编程中的最佳实践之一。材质着色器也不例外：如果你的着色器块是模块化的，并且可以被封装并标识为命名函数，那将更好。这样，不仅你的着色器块更清晰，而且它们还可以在多个材质着色器中重复使用，甚至可以导出到本地 UE4 库中以供将来在其他项目中使用。

## 准备工作

可以将可重用的着色器功能块从自定义材质着色器程序中分离出来。在本示例中，我们将编写一个简单的函数系列——`Square`、`Square2`、`Square3`和`Square4`——来对输入值进行平方。通过打开 UE4 项目并导航到**内容浏览器**，准备好在本教程中执行工作。

## 如何操作...

1.  在**内容浏览器**中右键单击，然后选择**Materials & Textures** | **Material Function**。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00274.jpeg)

1.  将您的**材质函数**命名为`Square`。

1.  双击**材质函数**。

1.  一旦打开**材质函数**，通过在材质编辑器的空白画布空间中的任何位置左键单击，取消选择**输出结果**节点。查看**详细信息**面板，并注意函数对 UE4 库的暴露是可选的：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00275.jpeg)

1.  当在**材质函数**编辑器屏幕中没有选择节点时，**详细信息**面板中会出现**暴露到库**复选框。

1.  在**材质函数**编辑器的空白处右键单击，然后选择**输入**。为您的输入命名。请注意，**输入**节点仅在**材质函数**编辑器中可用，而不在普通的材质编辑视图中可用。

1.  从任何常规材质中，通过以下方式之一调用您的函数：

1.  在空白处右键单击，然后选择`MaterialFunction`，然后从下拉菜单中选择您的`MaterialFunction`。

1.  右键单击并输入您的**材质函数**的名称（这要求您先前已经暴露了您的**材质函数**）。

1.  如果您不想将您的**材质函数**暴露给 UE4 库，则必须使用`MaterialFunction`块来调用您的自定义函数。

1.  在**材质函数**编辑器的任何位置右键单击，然后选择**输出**。

## 它是如何工作的...

**材质函数**是您可以创建的最有用的块之一。通过使用它们，您可以将着色器代码模块化，使其更整洁、紧凑和可重用。

## 还有更多...

将功能迁移到着色器库是一个好主意。通过在着色器的根部选择**暴露到库**，您可以使自定义函数出现在函数库中（前提是在材质编辑器窗口中没有选择任何内容）。

在开发**材质函数**时，有时将材质预览节点更改为输出节点以外的节点会很有帮助。通过右键单击任何节点的输出插孔并选择**开始预览节点**来预览特定节点的输出。

![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00276.jpeg)

材质编辑器左上角的窗口现在将显示您正在预览的节点的输出。此外，如果您正在预览的节点不是最终输出节点，则会在您正在预览的节点上添加文本**正在预览**。确保在材质编辑器顶部的菜单栏中启用了**实时预览**。通常，您希望预览最终输出。

# 着色器参数和材质实例

着色器的参数将成为该着色器的变量输入。您可以配置标量或矢量作为您的着色器的输入参数。UE4 中的某些材质预先编程了暴露的材质参数。

## 准备工作

为了设置着色器的参数，您首先需要一个带有您想要使用变量修改的内容的着色器。一个好的用变量修改的东西是角色的服装颜色。我们可以将服装的颜色作为着色器参数暴露出来，然后将其与服装颜色相乘。

## 如何操作...

1.  构建一个新的材质。

1.  在材质中创建一个`VectorParameter`。给参数一个名称，例如`Color`。给它一个默认值，例如蓝色或黑色。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00277.jpeg)

1.  关闭材质。

1.  在**内容浏览器**中，右键单击具有参数的材质，并选择**创建材质实例**。

1.  双击您的材质实例。勾选您的`VectorParameter`名称旁边的复选框，完成！您的`VectorParameter`可以自定义，而不会进一步影响材质的基本功能。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00278.jpeg)

1.  此外，如果您更改了材质的基本功能，材质实例将继承这些更改，而无需进行任何进一步的配置。

## 工作原理...

材质参数允许您编辑发送到材质的变量的值，而无需编辑材质本身。此外，您还可以轻松地从 C++代码更改材质实例的值。这对于诸如团队颜色之类的事物非常有用。

# 闪烁

通过在 UE4 材质编辑器中使用标准节点，可以轻松访问一些着色器功能。您可以构建一些漂亮的斑点效果，例如我们在下一个示例中展示的闪闪发光的金色着色器。这个示例的目的是让您熟悉材质编辑器的基本功能，以便您可以学会构建自己的材质着色器。

## 准备工作

创建一个您想要发光的资产（例如一个宝箱），或者打开`Chapter11`的源代码包以找到`treasureChest.fbx`模型。

我们要做的是在物体上移动一个厚度为*W*的平面。当平面经过几何体时，发射颜色通道被激活，从而在宝藏上创建出闪烁效果。

我们公开了几个参数来控制闪烁，包括**速度**，**周期**（闪烁之间的时间），**宽度**，**增益**，**平面方向**，最后是**颜色**。

## 如何操作...

1.  通过在**内容浏览器**中右键单击并选择**材质**来创建一个新的材质。

1.  按照以下图像所示添加输入参数，引入一个`Time`输入，并通过使用时间周期调用`Fmod`使其成为周期性的：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00279.jpeg)

1.  使用周期的`Fmod`将使时间遵循锯齿形模式。读取的时间值不会超过**周期**，因为我们将使用`fmod`操作将其保持为 0。

1.  在一个单独的文件中提供`OnPlane`函数。`OnPlane`函数使用平面方程*Ax + By + Cz + D = 0*来确定输入点是否在平面上。将`LocalPosition`坐标传递到`OnPlane`函数中，以确定在给定帧中，是否应该在几何体中用发光突出显示此部分。

## 工作原理...

一个想象中的光平面以指定的速度通过几何体。光平面每隔**周期**秒从一个边界框的角落开始，沿着**平面方向**指定的方向移动。当平面随时间向前移动时，它总是从盒子的角落开始，当平面通过整个体积时，它将通过整个体积。

# 树叶和风

在这个示例中，我们将编写一个简单的粒子着色器，演示如何在风中创建树叶。我们可以使用一个**粒子发射器**结合一个材质着色器来实现这一点，通过"着色"我们的树叶，使它们看起来像在风中飘动。

![树叶和风](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00280.jpeg)

## 准备工作

首先，您需要一个树叶纹理以及一个放置落叶的场景。在`Chapter11`代码包中，您会找到一个名为`LeavesAndTree`的场景，其中包含一个落叶树，您可以使用它。

## 如何操作...

1.  通过在**内容浏览器**中右键单击并选择**粒子系统**来创建一个新的粒子发射器。

1.  通过在**内容浏览器**中右键单击并选择**材质**来构建一个新的材质着色器。您的叶子材质应该包含一个叶子的纹理在`BaseColor`组件中。我们将在后面的步骤中编辑叶子的**世界位置**，以表示由风引起的运动中的抖动。

1.  添加一些参数来修改树叶粒子发射器：

1.  **生成**应该有一个很高的速率，大约为 100。

1.  **初始位置**可以在每边 100 个单位的立方体中分布。

1.  **生命周期**可以是 4-5 秒。

1.  **初始速度**应该是从(-50,-50,-100)到(25,25,-10)之间的某个值。

1.  **初始颜色**可以是一个分布向量，其值为绿色、黄色和红色。

1.  **加速度**可以是(0,0,-20)。

1.  **初始旋转速率**可以是 0.25（最大值）。

1.  可以添加一个带有分布（0,0,0）到（0,10,10）的**轨道**参数。

1.  **风**：通过在**内容浏览器**的空白处右键单击，然后选择**新建材质参数集合**，创建一个**材质参数集合**（**MPC**）。

1.  双击编辑您的新材质参数集合，并输入一个新的参数`TheWind`。给它初始值`(1, 1, 1)`。

1.  在您的关卡蓝图（**蓝图** | **关卡蓝图**）中，创建一个名为`TheWind`的客户端变量。在事件`BeginPlay`中将`TheWind`变量初始化为`(1, 1, 1)`，然后在每帧将此变量发送到 GPU。

1.  在事件`Tick`中，根据自己的喜好修改风力。在我的版本中，我将每帧的风力乘以一个三维随机向量，其值在[-1,1]之间。这样可以使风力每帧都有一个不错的颤动效果。

1.  通过在修改风向量后立即选择一个**设置矢量参数值**节点，将风变量更新发送到 GPU。**设置矢量参数值**必须引用材质参数集合内的变量，因此引用在*步骤 4*中创建的材质参数集合内的`TheWind`变量。

1.  通过每帧修改`WorldPositionOffset`的`TheWind`的某个倍数。由于`TheWind`变量变化缓慢，每帧呈现的修改将是上一帧呈现的修改的轻微变化，从而产生平滑的叶子运动。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00281.jpeg)

## 它是如何工作的...

叶子以大致恒定的速率下落，但受到着色器内部不断变化的风向量的牵引。

# 反射率取决于观察角度

材质的反射率依赖于观察角度的倾向被称为**Fresnel**效应。材质在接近水平角度时可能比在正对角度时更具镜面反射性。

![反射率取决于观察角度](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00282.jpeg)

### 注意

Fresnel 效果在接近水平角度时具有较大的幅度。由于使用了 Fresnel 效果，前面截图中的水材质在接近水平角度时具有较高的镜面反射和不透明度。

UE4 具有专门的内置功能来处理这个问题。我们将构建一个水材质，其中透明度具有视角依赖性，以便实际演示如何使用 Fresnel 效果。

## 准备工作

您需要一个要添加 Fresnel 效果的新材质。最好选择一个在观察角度不同的情况下看起来有些不同的材质。

## 如何操作...

1.  在材质内部，通过 Fresnel 节点的输出来驱动一个通道（不透明度、镜面反射或漫反射颜色）。

1.  Fresnel 节点的参数指数和基础反射分数可以调整如下：

1.  **指数**：描述材质的 Fresnel 程度。较高的值会夸大 Fresnel 效果。

1.  **基础反射分数**：较低的数值会夸大 Fresnel 效果。对于值为 1.0，Fresnel 效果不会显现。

## 它是如何工作的...

实现 Fresnel 效果背后有很多数学知识，但在材质中使用它来驱动组件相对较简单，并且可以帮助您创建一些非常漂亮的材质。

# 随机性 - 柏林噪声

一些着色器可以从使用随机值中受益。每个材质都有一些节点可以帮助给着色器添加随机性。可以使用**Perlin**噪声纹理的随机性来生成看起来有趣的材质，比如大理石材质。这种噪声还可以用于驱动凹凸贴图、高度贴图和位移场，产生一些炫酷的效果。

## 准备工作

选择一个你想要添加一些随机性的材质。在材质编辑器中打开该材质，并按照以下步骤进行操作。

## 如何操作...

1.  将一个**Noise**节点插入到你的材质编辑器窗口中。

1.  对你要添加噪声的对象的坐标进行归一化。你可以使用以下数学公式来实现：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00283.jpeg)

1.  从系统中的每个处理过的顶点中减去最小值，使对象位于原点。

1.  将顶点除以对象的大小，将对象放入一个单位盒子中。

1.  将顶点值乘以 2，将单位盒子从 1x1 扩展到 2x2。

1.  将顶点值减去 1，将单位移动到以原点为中心，值从*[-1,-1,-1]*到*[+1,+1,+1]*。

1.  选择一个值来绘制噪声。请记住，噪声在输入值在![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00284.jpeg)之间时效果非常好。在这个范围之外，Perlin 噪声在缩小时会出现雪花状的外观（因为输出值在输入*x*上的变化太大）。

## 工作原理...

Perlin 噪声可以帮助你产生一些美丽的大理石纹理和图案。除了在图形中使用它，你还可以使用 Perlin 噪声以一种自然的方式驱动运动和其他现象。

# 给景观着色

构建景观着色器相对较容易。它们允许你为一个非常大的自定义几何体（称为景观）指定多重纹理。

## 准备工作

景观对象非常适合用作游戏世界级别的地面平面。你可以使用景观选项卡在同一级别中构建多个景观。通过点击**模式**面板中的山的图片，访问**景观**调色板，如下图所示：

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00285.jpeg)

## 如何操作...

1.  通过点击**模式** | **景观**来构建一个新的景观对象。在**新景观**标题下，选择**创建新的**单选按钮。你将看到一个绿色的线框覆盖层，提供了新的景观。你可以使用**区块大小**和**每个组件的区块数**设置来调整其大小。

### 提示

当我们最终进行纹理贴图时，景观将以**区块大小** * **每个组件的区块数** * **组件的数量**的倍数平铺所选的纹理。如果你想让景观纹理平铺次数更少，可以记下这个数字，然后将馈送给纹理的 UV 坐标除以前一行计算出的数字。

1.  暂时不要点击对话框中的其他任何内容，因为我们还需要构建我们的景观材质。这在以下步骤中进行了概述。

1.  导航到**内容浏览器**，为你的景观创建一个新的材质。将其命名为`LandscapeMaterial`。

1.  通过双击编辑你的`LandscapeMaterial`。在空白处右键单击，选择一个`LandscapeCoordinate`节点，将 UV 坐标传递到我们即将应用的纹理中。

+   为了减少景观上的平铺效果，你需要将`LandscapeCoordinate`节点的输出除以景观的总大小（**区块大小** * **每个组件的区块数** * **组件的数量**）（如*步骤 1*中的提示所述）。

1.  在画布上添加一个`LandscapeLayerBlend`节点。将节点的输出导向**基本颜色**图层。

1.  点击`LandscapeLayerBlend`节点，在**详细信息**选项卡中为元素添加几个图层。这将允许你使用**纹理绘制**来在纹理之间进行混合。为每个图层命名，并从以下选项中选择混合方法：

+   通过绘制权重（LB 权重混合）。

+   通过纹理内的 alpha 值（LB Alpha 混合）。

+   按高度（LB 高度混合）。

1.  根据需要设置每个添加的`LandscapeLayer`的其他参数。

1.  为每个景观混合层提供纹理。

1.  通过将恒定的 0 输入添加到镜面输入中，将景观的高光减少到 0。

1.  保存并关闭您的材质。

1.  现在，转到**模式** | 景观选项卡，并在下拉菜单中选择您新创建的`LandscapeMaterial`。

1.  在**图层**部分，点击每个可用的景观图层旁边的**+**图标。为每个景观图层创建并保存一个目标图层对象。

1.  最后，向下滚动到景观选项卡，点击**创建**按钮。

1.  点击绘画选项卡，选择画笔大小和纹理，开始绘制景观纹理。

## 工作原理…

景观材质可以通过高度或手工艺进行混合，如本教程所示。


# 第十二章：使用 UE4 API

应用程序编程接口（API）是您作为程序员指示引擎和 PC 要执行的操作的方式。UE4 的所有功能都封装在模块中，包括非常基本和核心的功能。每个模块都有一个 API。要使用 API，有一个非常重要的链接步骤，在其中必须在`ProjectName.Build.cs`文件中列出您将在构建中使用的所有 API，该文件位于**Solution Explorer**窗口中。

### 提示

不要将任何 UE4 项目命名为与 UE4 API 名称完全相同的名称！

![使用 UE4 API](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00286.jpeg)

UE4 引擎中有各种 API，可以向其各个重要部分公开功能。本章中我们将探索一些有趣的 API，包括以下内容：

+   Core/Logging API – 定义自定义日志类别

+   Core/Logging API – 使用`FMessageLog`将消息写入**Message Log**

+   Core/Math API – 使用`FRotator`进行旋转

+   Core/Math API – 使用`FQuat`进行旋转

+   Core/Math API – 使用`FRotationMatrix`进行旋转，使一个对象面向另一个对象

+   Landscape API – 使用 Perlin 噪声生成地形

+   Foliage API – 在您的关卡中以程序化方式添加树木

+   Landscape and Foliage APIs – 使用 Landscape 和 Foliage APIs 生成地图

+   GameplayAbilities API – 使用游戏控制触发角色的游戏能力

+   GameplayAbilities API – 使用`AttributeSet`实现统计数据

+   GameplayAbilities API – 使用`GameplayEffect`实现增益效果

+   GameplayTags API – 将`GameplayTags`附加到角色

+   GameplayTasks API – 使用`GameplayTasks`实现游戏任务

+   HTTP API – 网络请求

+   HTTP API – 进度条

# 介绍

UE4 引擎在编辑器中提供的基本功能非常广泛。C++代码的功能实际上被分组到称为 API 的小节中。UE4 代码库中的每个重要功能都有一个单独的 API 模块。这样做是为了保持代码库高度组织和模块化。

### 提示

使用不同的 API 可能需要在您的`Build.cs`文件中进行特殊链接！如果出现构建错误，请确保检查与正确的 API 的链接是否存在！

完整的 API 列表位于以下文档中：[`docs.unrealengine.com/latest/INT/API/`](https://docs.unrealengine.com/latest/INT/API/)。

# Core/Logging API – 定义自定义日志类别

UE4 本身定义了几个日志类别，包括`LogActor`等类别，其中包含与`Actor`类相关的任何日志消息，以及`LogAnimation`，用于记录有关动画的消息。一般来说，UE4 为每个模块定义了一个单独的日志类别。这允许开发人员将其日志消息输出到不同的日志流中。每个日志流的名称作为前缀添加到输出的消息中，如引擎中的以下示例日志消息所示：

```cpp
LogContentBrowser: Native class hierarchy updated for 'HierarchicalLODOutliner' in 0.0011 seconds. Added 1 classes and 2 folders.
LogLoad: Full Startup: 8.88 seconds (BP compile: 0.07 seconds)
LogStreaming:Warning: Failed to read file '../../../Engine/Content/Editor/Slate/Common/Selection_16x.png' error.
LogExternalProfiler: Found external profiler: VSPerf
```

以上是引擎中的示例日志消息，每个消息前都有其日志类别的前缀。警告消息以黄色显示，并在前面添加了**Warning**。

您在互联网上找到的示例代码往往使用`LogTemp`作为 UE4 项目自己的消息，如下所示：

```cpp
UE_LOG( LogTemp, Warning, TEXT( "Message %d" ), 1 );
```

我们实际上可以通过定义自己的自定义`LogCategory`来改进这个公式。

## 准备工作

准备一个 UE4 项目，您想要定义一个自定义日志。打开一个将在几乎所有使用此日志的文件中包含的头文件。

## 操作步骤...

1.  打开您的项目的主头文件；例如，如果您的项目名称是`Pong`，则打开`Pong.h`。在`#include Engine.h`之后添加以下代码行：

```cpp
DECLARE_LOG_CATEGORY_EXTERN( LogPong, Log, All ); // Pong.h
```

在`AssertionMacros.h`中定义了此声明的三个参数，如下所示：

+   `CategoryName`：这是正在定义的日志类别名称（这里是`LogPong`）

+   `DefaultVerbosity`：这是要在日志消息上使用的默认详细程度

+   `CompileTimeVerbosity`：这是编译代码中的详细程度

1.  在项目的主`.cpp`文件中，包含以下代码行：

```cpp
DEFINE_LOG_CATEGORY( LogPong ); // Pong.cpp
```

1.  使用各种显示类别的日志，如下所示：

```cpp
UE_LOG( LogPong, Display, TEXT( "A display message, log is working" ) ); // shows in gray
UE_LOG( LogPong, Warning, TEXT( "A warning message" ) );
UE_LOG( LogPong, Error, TEXT( "An error message " ) );
```

![操作步骤](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00287.jpeg)

## 工作原理

日志通过将消息输出到“输出日志”（“窗口”|“开发者工具”|“输出日志”）以及文件中来工作。所有输出到“输出日志”的信息也会复制到项目的`/Saved/Logs`文件夹中的一个简单文本文件中。日志文件的扩展名为`.log`，其中最新的一个被命名为`YourProjectName.log`。

## 还有更多...

您可以使用以下控制台命令在编辑器中启用或禁止特定日志通道的日志消息：

```cpp
Log LogName off // Stop LogName from displaying at the output
Log LogName Log // Turn LogName's output on again
```

如果您想编辑一些内置日志类型的输出级别的初始值，可以使用 C++类来对`Engine.ini`配置文件进行更改。您可以在`engine.ini`配置文件中更改初始值。有关更多详细信息，请参见[`wiki.unrealengine.com/Logs,_Printing_Messages_To_Yourself_During_Runtime`](https://wiki.unrealengine.com/Logs,_Printing_Messages_To_Yourself_During_Runtime)。

## 另请参阅

+   `UE_LOG`将其输出发送到“输出窗口”。如果您还想使用更专门的“消息日志”窗口，您可以使用`FMessageLog`对象来编写输出消息。`FMessageLog`同时写入“消息日志”和“输出窗口”。有关详细信息，请参见下一个教程。

# 核心/日志 API - 使用 FMessageLog 将消息写入消息日志

`FMessageLog`是一个对象，允许您将输出消息同时写入“消息日志”（“窗口”|“开发者工具”|“消息日志”）和“输出日志”（“窗口”|“开发者工具”|“输出日志”）。

## 准备工作

准备好您的项目和一些要记录到“消息日志”的信息。在 UE4 编辑器中显示“消息日志”。以下屏幕截图是“消息日志”的样子：

![准备就绪](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00288.jpeg)

## 操作步骤

1.  在您的主头文件（`ProjectName.h`）中添加`#define`，将`LOCTEXT_NAMESPACE`定义为您的代码库中的某个唯一值：

```cpp
#define LOCTEXT_NAMESPACE "Chapter12Namespace"
```

这个`#define`被`LOCTEXT()`宏使用，我们用它来生成`FText`对象，但在输出消息中看不到它。

1.  通过在非常全局的位置构建您的`FMessageLog`来声明它。您可以在`ProjectName.h`文件中使用`extern`。考虑以下代码片段作为示例：

```cpp
extern FName LoggerName;
extern FMessageLog Logger;
```

1.  然后，在`.cpp`文件中定义并使用`MessageLogModule`注册您的`FMessageLog`。在构建时，请确保为您的记录器提供一个清晰且唯一的名称。它是您的日志类别将出现在“输出日志”中的日志消息左侧的位置。例如，`ProjectName.cpp`：

```cpp
#define FTEXT(x) LOCTEXT(x, x)
FName LoggerName( "Chapter12Log" );
FMessageLog CreateLog( FName name )
{
  FMessageLogModule& MessageLogModule = 
  FModuleManager::LoadModuleChecked<FMessageLogModule>
  ("MessageLog");
  FMessageLogInitializationOptions InitOptions;
  InitOptions.bShowPages = true;// Don't forget this!
  InitOptions.bShowFilters = true;
  FText LogListingName = FTEXT( "Chapter 12's Log Listing" );
  MessageLogModule.RegisterLogListing( LoggerName, LogListingName, InitOptions );
}
// Somewhere early in your program startup
// (eg in your GameMode constructor)
AChapter12GameMode::AChapter12GameMode()
{
  CreateLogger( LoggerName );
  // Retrieve the Log by using the LoggerName.
  FMessageLog logger( LoggerName );
  logger.Warning(
  FTEXT( "A warning message from gamemode ctor" ) );
}
```

### 提示

`KEY`到`LOCTEXT`（第一个参数）必须是唯一的，否则您将得到一个先前散列的字符串。如果您愿意，您可以包含一个`#define`，将参数重复两次传递给`LOCTEXT`，就像我们之前做的那样。

```cpp
#define FTEXT(x) LOCTEXT(x, x)
```

1.  使用以下代码记录您的消息：

```cpp
Logger.Info( FTEXT( "Info to log" ) );
Logger.Warning( FTEXT( "Warning text to log" ) );
Logger.Error( FTEXT( "Error text to log" ) );
```

此代码利用了之前定义的`FTEXT()`宏。请确保它在您的代码库中。

### 提示

在初始化后重新构建消息日志可以检索到原始消息日志的副本。例如，在代码的任何位置，您可以编写以下代码：

```cpp
FMessageLog( LoggerName ).Info( FTEXT( "An info message" ) );
```

# 核心/数学 API - 使用 FRotator 进行旋转

在 UE4 中，旋转有着完整的实现，因此很难选择如何旋转您的对象。有三种主要方法——`FRotator`、`FQuat`和`FRotationMatrix`。本教程概述了这三种不同方法之一——`FRotator`的构建和使用。使用这个方法和下面的两个教程，您可以一目了然地选择一个用于旋转对象的方法。

## 准备工作

有一个 UE4 项目，其中有一个你可以使用 C++接口的对象。例如，你可以构造一个从`Actor`派生的 C++类 Coin 来测试旋转。重写`Coin::Tick()`方法来应用你的旋转代码。或者，你可以在蓝图中的`Tick`事件中调用这些旋转函数。

在这个例子中，我们将以每秒一度的速度旋转一个物体。实际的旋转将是物体创建后累积的时间。为了获得这个值，我们只需调用`GetWorld()->TimeSeconds`。

## 如何做到这一点...

1.  创建一个名为`Coin`的自定义 C++派生类，继承自`Actor`类。

1.  在 C++代码中，重写`Coin`派生类的`::Tick()`函数。这将允许你在每一帧中对角色进行更改。

1.  构造你的`FRotator`。`FRotators`可以使用标准的俯仰、偏航和滚转构造函数来构造，如下例所示：

```cpp
FRotator( float InPitch, float InYaw, float InRoll );
```

1.  你的`FRotator`将按以下方式构造：

```cpp
FRotator rotator( 0, GetWorld()->TimeSeconds, 0 );
```

1.  在 UE4 中，对象的标准方向是前方朝下的*+X*轴。右侧是*+Y*轴，上方是*+Z*轴。![如何做到这一点...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00289.jpeg)

1.  俯仰是绕*Y*轴（横向）旋转，偏航是绕*Z*轴（上下）旋转，滚转是绕*X*轴旋转。这在以下三点中最容易理解：

+   **俯仰**：如果你想象一个 UE4 标准坐标系中的飞机，*Y*轴沿着翼展（俯仰将其向前和向后倾斜）

+   **偏航**：*Z*轴直上直下（偏航将其左右旋转）

+   **滚转**：*X*轴沿着飞机机身直线（滚转进行卷筒翻滚）

### 提示

你应该注意，在其他约定中，*X*轴是俯仰，*Y*轴是偏航，*Z*轴是滚转。

1.  使用`SetActorRotation`成员函数将你的`FRotator`应用到你的角色上，如下所示：

```cpp
FRotator rotator( 0, GetWorld()->TimeSeconds, 0 );
SetActorRotation( rotation );
```

# 核心/数学 API - 使用 FQuat 进行旋转

四元数听起来很吓人，但它们非常容易使用。你可能想通过以下视频来了解它们背后的理论数学：

+   Numberphile 的《奇妙的四元数》- [`www.youtube.com/watch?v=3BR8tK-LuB0`](https://www.youtube.com/watch?v=3BR8tK-LuB0)

+   Jim Van Verth 的《理解四元数》- [`gdcvault.com/play/1017653/Math-for-Game-Programmers-Understanding`](http://gdcvault.com/play/1017653/Math-for-Game-Programmers-Understanding)

然而，在这里我们不会涉及数学背景！实际上，你不需要对四元数的数学背景有太多的了解就能极其有效地使用它们。

## 准备工作

准备一个项目和一个具有重写`::Tick()`函数的`Actor`，我们可以在其中输入 C++代码。

## 如何做到这一点...

1.  构造四元数时，最好使用以下构造函数：

```cpp
FQuat( FVector Axis, float AngleRad );
```

### 注意

**例如，定义一个扭曲旋转**：

四元数还定义了四元数加法、四元数减法、乘以标量和除以标量等运算，以及其他函数。它们非常有用，可以将物体以任意角度旋转，并将物体指向彼此。

## 它是如何工作的...

四元数有点奇怪，但使用它们非常简单。如果*v*是旋转的轴，![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00290.jpeg)是旋转角度的大小，那么我们可以得到以下四元数分量的方程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00291.jpeg)

因此，例如，绕![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00292.jpeg)旋转![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00293.jpeg)角度将具有以下四元数分量：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00294.jpeg)

四元数的四个分量中的三个分量（*x*、*y*和*z*）定义了旋转的轴（乘以旋转角度一半的正弦值），而第四个分量（*w*）只有旋转角度一半的余弦值。

## 还有更多...

四元数本身是向量，可以进行旋转。只需提取四元数的(*x*, *y*, *z*)分量，进行归一化，然后旋转该向量。使用所需旋转角度构造一个新的四元数，该四元数由该新单位向量构成。

将四元数相乘表示一系列连续发生的旋转。例如，绕*X*轴旋转 45º，然后绕*Y*轴旋转 45º将由以下组成：

```cpp
FQuat( FVector( 1, 0, 0 ), PI/4.f ) *
FQuat( FVector( 0, 1, 0 ), PI/4.f );
```

# 核心/数学 API-使用 FRotationMatrix 进行旋转，使一个对象面向另一个对象

`FRotationMatrix`提供了使用一系列`::Make*`例程进行矩阵构造的功能。它们易于使用，对于使一个对象面向另一个对象非常有用。假设您有两个对象，其中一个对象跟随另一个对象。我们希望跟随者的旋转始终面向其所跟随的对象。`FRotationMatrix`的构造方法使这一点变得容易。

## 准备好了

在场景中有两个演员，其中一个应该面向另一个演员。

## 如何做到这一点...

1.  在跟随者的`Tick()`方法中，查看`FRotationMatrix`类下可用的构造函数。提供了一系列构造函数，可以通过重新定位一个或多个*X*、*Y*、*Z*轴来指定对象的旋转，命名为`FRotationMatrix::Make*()`模式。

1.  假设您的演员具有默认的初始方向（前进沿着*+X*轴向下，向上沿着*+Z*轴向上），请找到从跟随者到他所跟随的对象的向量，如下所示：

```cpp
FVector toFollow = target->GetActorLocation() - GetActorLocation();
FMatrix rotationMatrix = FRotationMatrix::MakeFromXZ( toTarget, GetActorUpVector() );
SetActorRotation( rotationMatrix.Rotator() );
```

## 它是如何工作的...

使一个对象看向另一个对象，并具有所需的上向量，可以通过调用正确的函数来完成，具体取决于对象的默认方向。通常，您希望重新定位*X*轴（前进），同时指定*Y*轴（右）或*Z*轴（上）向量（`FRotationMatrix::MakeFromXY()`）。例如，要使一个演员沿着`lookAlong`向量朝向，其右侧面向右侧，我们可以构造并设置其`FRotationMatrix`如下：

```cpp
FRotationMatrix rotationMatrix = FRotationMatrix::MakeFromXY( lookAlong, right );
actor->SetActorRotation( rotationMatrix.Rotator() );
```

# 景观 API-使用 Perlin 噪声生成景观

如果您在场景中使用`ALandscape`，您可能希望使用代码而不是手动刷入来编程设置其高度。要在代码中访问`ALandscape`对象及其函数，您必须编译和链接`Landscape`和`LandscapeEditor`API。

![景观 API-使用 Perlin 噪声生成景观](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00295.jpeg)

## 准备好了

生成景观并不是非常具有挑战性。您需要链接`Landscape`和`LandscapeEditor`API，并且还需要以编程方式设置地图上的高度值。在本示例中，我们将展示如何使用 Perlin 噪声来实现这一点。

以前，您可能已经看到过 Perlin 噪声用于着色，但这并不是它的全部用途。它也非常适用于地形高度。您可以将多个 Perlin 噪声值相加，以获得美丽的分形噪声。值得简要研究 Perlin 噪声，以了解如何获得良好的输出。

## 如何做到这一点...

1.  从[`webstaff.itn.liu.se/~stegu/aqsis/aqsis-newnoise/`](http://webstaff.itn.liu.se/~stegu/aqsis/aqsis-newnoise/)检索 Perlin 噪声模块。您需要的两个文件是`noise1234.h`和`noise1234.cpp`（或者您可以从此存储库中选择另一对噪声生成文件）。将这些文件链接到您的项目中，并确保在`noise1234.cpp`中`#include YourPrecompiledHeader.h`。

1.  在您的`Project.Build.cs`文件中链接`Landscape`和`LandscapeEditor`API。

1.  使用 UMG 构建一个界面，允许您点击一个**生成**按钮来调用一个 C++函数，最终用 Perlin 噪声值填充当前景观。您可以按照以下步骤进行操作：

+   右键单击**内容浏览器**，选择**用户界面** | **小部件蓝图**。

+   使用一个单独的按钮填充**Widget Blueprint**，该按钮启动一个单独的`Gen()`函数。`Gen()`函数可以附加到你的`Chapter12GameMode`派生类对象上，因为从引擎中检索它很容易。`Gen()`函数必须是`BlueprintCallable UFUNCTION()`。（有关如何执行此操作的详细信息，请参见第二章中的*创建 UFUNCTION*部分，*创建类*。）![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00296.jpeg)

+   确保通过在其中一个启动蓝图中创建并将其添加到视口来显示你的 UI；例如，在你的 HUD 的`BeginPlay`事件中。

![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00297.jpeg)

1.  使用 UE4 编辑器创建一个景观。假设景观将保持在屏幕上。我们只会使用代码修改它的值。

1.  在你的地图生成例程中，使用以下代码修改你的`ALandscape`对象：

+   通过搜索`Level`中的所有对象来找到级别中的`Landscape`对象。我们使用一个返回级别中所有`Landscape`实例的`TArray`的 C++函数来实现这一点：

```cpp
TArray<ALandscape*> AChapter12GameMode::GetLandscapes()
{
  TArray<ALandscape*> landscapes;
  ULevel *level = GetLevel();
  for( int i = 0; i < level->Actors.Num(); i++ )
  if( ALandscape* land = Cast<ALandscape>(level->Actors[i]) )
  landscapes.Push( land );
  return landscapes;
}
```

+   使用以下非常重要的行初始化世界的`ULandscapeInfo`对象，如下所示：

```cpp
ULandscapeInfo::RecreateLandscapeInfo( GetWorld(), 1 );
```

### 注意

上一行代码非常重要。如果没有它，`ULandscapeInfo`对象将不会被初始化，你的代码将无法工作。令人惊讶的是，这是`ULandscapeInfo`类的静态成员函数，因此它会初始化级别中的所有`ULandscapeInfo`对象。

+   获取你的`ALandscape`对象的范围，以便我们可以计算需要生成的高度值的数量。

+   创建一组高度值来替换原始值。

+   调用`LandscapeEditorUtils::SetHeightmapData( landscape, data );`将新的地形高度值放入你的`ALandscape`对象中。

例如，使用以下代码：

```cpp
// a) REQUIRED STEP: Call static function
// ULandscapeInfo::RecreateLandscapeInfo().
// What this does is populate the Landscape object with
// data values so you don't get nulls for your 
// ULandscapeInfo objects on retrieval.
ULandscapeInfo::RecreateLandscapeInfo( GetWorld(), 1 );

// b) Assuming landscape is your landscape object pointer,
// get extents of landscape, to compute # height values
FIntRect landscapeBounds = landscape->GetBoundingRect();

// c) Create height values.
// LandscapeEditorUtils::SetHeightmapData() adds one to 
// each dimension because the boundary edges may be used.
int32 numHeights = (rect.Width()+1)*(rect.Height()+1);
TArray<uint16> Data;
Data.Init( 0, numHeights );
for( int i = 0; i < Data.Num(); i++ ) {
  float nx = (i % cols) / cols; // normalized x value
  float ny = (i / cols) / rows; // normalized y value
  Data[i] = PerlinNoise2D( nx, ny, 16, 4, 4 );
}

// d) Set values in with call:
LandscapeEditorUtils::SetHeightmapData( landscape, Data );
```

### 提示

当地图完全平坦时，`heightmap`的初始值将全部为`32768`（`SHRT_MAX`（或`USHRT_MAX/2+1`））。这是因为地图使用无符号短整数（`uint16`）作为其值，使其无法取负值。为了使地图低于`z=0`，程序员将默认值设为`heightmap`的最大值的一半。

## 它是如何工作的…

Perlin 噪声函数用于为（*x*，*y*）坐标对生成高度值。使用 2D 版本的 Perlin 噪声，以便我们可以根据 2D 空间坐标获取 Perlin 噪声值。

## 还有更多内容…

你可以使用地图的空间坐标来玩弄 Perlin 噪声函数，并将地图的高度分配给 Perlin 噪声函数的不同组合。你将希望使用多个 Octave 的 Perlin 噪声函数的总和来获得更多的地形细节。

`PerlinNoise2D`生成函数如下所示：

```cpp
uint16 AChapter12GameMode::PerlinNoise2D( float x, float y,
  float amp, int32 octaves, int32 px, int32 py )
{
  float noise = 0.f;
  for( int octave = 1; octave < octaves; octave *= 2 )
  {
    // Add in fractions of faster varying noise at lower 
    // amplitudes for higher octaves. Assuming x is normalized, 
    // WHEN octave==px  you get full period. Higher frequencies 
    // will go out and also meet period.
    noise += Noise1234::pnoise( x*px*octave, y*py*octave, px, py ) / octave;
  }
  return USHRT_MAX/2.f + amp*noise;
}
```

`PerlinNoise2D`函数考虑到函数的中间值（海平面或平地）应该具有`SHRT_MAX`（`32768`）的值。

# Foliage API - 使用代码将树木程序化地添加到你的级别中

**Foliage** API 是使用代码填充级别中的树木的好方法。如果你这样做，那么你可以获得一些不错的结果，而不必手动产生自然的随机性。

我们将根据 Perlin 噪声值与植被的放置位置相关联，以便在 Perlin 噪声值较高时在给定位置放置树木的机会更大。

## 准备工作

在使用 Foliage API 的代码接口之前，你应该尝试使用编辑器中的功能来熟悉该功能。之后，我们将讨论使用代码接口在级别中放置植被。

### 提示

重要！请记住，`FoliageType`对象的材质必须在其面板中选中**Used with Instanced Static Meshes**复选框。如果不这样做，那么该材质将无法用于着色植被材质。

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00298.jpeg)

确保为您在`FoliageType`上使用的材质勾选**与实例化静态网格一起使用**复选框，否则您的植被将显示为灰色。

## 操作步骤如下：

### 手动

1.  从**模式**面板中，选择带有叶子的小型植物的图片![手动](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00299.jpeg)。

1.  单击**+ 添加植被类型**下拉菜单，并选择构建一个新的`Foliage`对象。

1.  按您希望的名称保存`Foliage`对象。

1.  双击以编辑您的新`Foliage`对象。从项目中选择网格，最好是树形状的对象，以在景观中绘制植被。

1.  调整画笔大小和绘画密度以适合您的喜好。左键单击开始在植被中绘画。

1.  *Shift* + 单击以擦除您放置的植被。擦除密度值告诉您在擦除时要留下多少植被。

### 程序化

如果您希望引擎为您在关卡中分布植被，您需要完成以下几个步骤：

1.  转到**内容浏览器**，右键单击创建一些`FoliageType`对象以在关卡中进行程序化分布。

1.  点击**编辑** | **编辑器首选项**。

1.  点击**实验**选项卡。

1.  启用**程序化植被**复选框。这允许您从编辑器中访问**程序化植被**类。

1.  返回**内容浏览器**，右键单击并创建**杂项** | **程序化植被生成器**。

1.  双击打开您的**程序化植被生成器**，并选择在步骤 1 中创建的`FoliageTypes`。

1.  将您的**程序化植被生成器**拖放到关卡中，并调整大小，使其包含您想要布置程序化植被的区域。

1.  从画笔菜单中，拖动几个程序化植被阻挡体积。将其中几个放置在**程序化植被生成器**体积内，以阻止植被出现在这些区域。

1.  向下打开菜单，点击**模拟**。**程序化植被生成器**应该会填充植被。

1.  尝试不同的设置以获得您喜欢的植被分布。

## 另请参阅

+   前面的示例在游戏开始前生成植被。如果您对运行时程序化植被生成感兴趣，请参阅下一个示例，*Landscape and Foliage API - 使用 Landscape 和 Foliage API 进行地图生成*。

# Landscape and Foliage API - 使用 Landscape 和 Foliage API 进行地图生成

我们可以使用前面提到的地形生成代码创建一个地形，并使用程序化植被功能在其上随机分布一些植被。

结合 Landscape API 和 Foliage API 的功能，您可以程序化生成完整的地图。在本示例中，我们将概述如何实现这一点。

我们将使用代码编程创建一个地形，并使用代码填充植被。

![Landscape and Foliage API - 使用 Landscape 和 Foliage API 进行地图生成](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00300.jpeg)

## 准备工作

为了准备执行此示例，我们需要一个 UE4 项目，其中包含一个`Generate`按钮来启动生成。您可以参考*Landscape API - 使用 Perlin 噪声生成地形*示例来了解如何做到这一点。您只需要创建一个小的 UMG UI 小部件，其中包含一个`Generate`按钮。将您的`Generate`按钮的`OnClick`事件连接到 C++全局对象中的一个 C++ `UFUNCTION()`，例如您的`Chapter12GameMode`对象，该对象将用于生成地形。

## 操作步骤如下：

1.  进入一个循环，尝试放置*N*棵树，其中*N*是要随机放置的树木数量，由`Chapter12GameMode`对象的`UPROPERTY()`指定。

1.  从包围地形对象的 2D 框中获取随机 XY 坐标。

1.  获取 Perlin 噪声值`@(x, y)`。您可以使用与用于确定植被放置的地形高度的 Perlin 噪声公式不同的 Perlin 噪声公式。

1.  生成一个随机数。如果生成的数字在 Perlin 噪声函数的单位范围内，则使用`SpawnFoliageInstance`函数放置一棵树。否则，不要在那里放置一棵树。

### 提示

您应该注意到，我们使用所选择的位置的底层随机性来覆盖位置的随机性。在那里放置一棵树的实际机会取决于那里的 Perlin 噪声值，以及它是否在`PerlinTreeValue`的单位范围内。

非常密集的树分布将看起来像地图上的等值线。等值线的宽度是单位的范围。

## 它是如何工作的...

Perlin 噪声通过生成平滑的噪声来工作。对于区间中的每个位置（比如[-1, 1]），都有一个平滑变化的 Perlin 噪声值。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00301.jpeg)

Perlin 噪声值在 2D 纹理上进行采样。在每个像素（甚至在像素之间），我们可以得到一个非常平滑变化的噪声值。

在跨越 Perlin 噪声函数的距离上添加八度（或整数倍）到某个变量中，可以得到锯齿状的效果；例如，云朵中的小丛和山脉中的岩壁是通过更宽间隔的样本获得的，这些样本给出了更快变化的噪声。

为了获得漂亮的 Perlin 噪声输出，我们只需对采样的 Perlin 噪声值应用数学函数；例如，sin 和 cos 函数可以为您生成一些很酷的大理石效果。

### 提示

通过此处链接的实现提供的 Perlin 噪声函数，Perlin 噪声变得周期性，即可平铺。默认情况下，Perlin 噪声不是周期性的。如果您需要 Perlin 噪声是周期性的，请注意调用哪个库函数。

基本的 Perlin 噪声函数是一个确定性函数，每次调用它时都会返回相同的值。

## 还有更多...

您还可以在`Chapter12GameMode`对象派生类中设置滑块，以影响植被和地形的生成，包括以下参数：

+   地形的振幅

+   植被密度

+   植被的等值线水平

+   植被高度或比例的方差

# GameplayAbilities API - 使用游戏控制触发角色的游戏能力

**GameplayAbilities** API 可用于将 C++函数附加到特定按钮推送上，在游戏单位在游戏中对按键事件的响应中展示其能力。在本教程中，我们将向您展示如何做到这一点。

## 准备工作

枚举并描述游戏角色的能力。您需要知道您的角色对按键事件的响应以编码此处的代码。

这里有几个我们需要使用的对象，它们如下：

+   `UGameplayAbility`类 - 这是为了派生 C++类的`UGameplayAbility`类实例，每个能力都有一个派生类。

+   通过重写可用函数（如`UGameplayAbility::ActivateAbility`、`UGameplayAbility::InputPressed`、`UGameplayAbility::CheckCost`、`UGameplayAbility::ApplyCost`、`UGameplayAbility::ApplyCooldown`等）在`.h`和`.cpp`中定义每个能力的功能。

+   `GameplayAbilitiesSet` - 这是一个`DataAsset`派生对象，包含一系列枚举的命令值，以及定义该特定输入命令行为的`UGameplayAbility`派生类的蓝图。每个 GameplayAbility 都由按键或鼠标点击触发，这在`DefaultInput.ini`中设置。

## 操作步骤...

在接下来的内容中，我们将为`Warrior`类对象实现一个名为`UGameplayAbility_Attack`的`UGameplayAbility`派生类。我们将把这个游戏功能附加到输入命令字符串`Ability1`上，然后在鼠标左键点击时激活它。

1.  在`ProjectName.Build.cs`文件中链接`GameplayAbilities` API。

1.  从`UGameplayAbility`派生一个 C++类。例如，编写一个 C++ `UCLASS UGameplayAbility_Attack`。

1.  至少，您需要重写以下内容：

+   使用`UGameplayAbility_Attack::CanActivateAbility`成员函数来指示角色何时可以调用该能力。

+   使用`UGameplayAbility_Attack::CheckCost`函数来指示玩家是否能够负担得起使用能力。这非常重要，因为如果返回 false，能力调用应该失败。

+   使用`UGameplayAbility_Attack::ActivateAbility`成员函数，并编写当`Warrior`激活他的`Attack`能力时要执行的代码。

+   使用`UGameplayAbility_Attack::InputPressed`成员函数，并响应分配给该能力的按键输入事件。

1.  在 UE4 编辑器中从您的`UGameplayAbility_Attack`对象派生一个蓝图类。

1.  在编辑器中，导航到**内容浏览器**并创建一个`GameplayAbilitiesSet`对象：

+   右键单击**内容浏览器**，选择**杂项** | **数据资产**

+   在随后的对话框中，选择`GameplayAbilitySet`作为数据资产类

### 提示

实际上，`GameplayAbilitySet`对象是一个`UDataAsset`派生类。它位于`GameplayAbilitySet.h`中，并包含一个单一的成员函数`GameplayAbilitySet::GiveAbilities()`，我强烈建议您不要使用，原因将在后面的步骤中列出。

![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00302.jpeg)

1.  将您的`GameplayAbilitySet`数据资产命名为与`Warrior`对象相关的名称，以便我们知道要将其选择到`Warrior`类中（例如，`WarriorGameplayAbilitySet`）。

1.  双击打开并编辑新的`WarriorAbilitySet`数据资产。通过在其中的`TArray`对象上点击**+**，将一系列`GameplayAbility`类派生蓝图堆叠在其中。您的`UGameplayAbility_Attack`对象必须出现在下拉列表中。

1.  将`UPROPERTY UGameplayAbilitySet* gameplayAbilitySet`成员添加到您的`Warrior`类中。编译、运行，并在**内容浏览器**中选择`WarriorAbilitySet`（在步骤 5 到 7 中创建）作为此`Warrior`能够使用的能力。

1.  确保您的`Actor`类派生类也派生自`UAbilitySystemInterface`接口。这非常重要，以便对`(Cast<IAbilitySystemInterface>(yourActor))->GetAbilitySystemComponent()`的调用成功。

1.  在构建角色之后的某个时候，调用`gameplayAbilitySet->GiveAbilities(abilitySystemComponent);`或进入一个循环，如下一步所示，在其中为您的`gameplayAbilitySet`中列出的每个能力调用`abilitySystemComponent->GiveAbility()`。

1.  为`AWarrior::SetupPlayerInputComponent(UInputComponent* Input)`编写一个重写，将输入控制器连接到 Warrior 的 GameplayAbility 激活。这样做后，迭代每个在您的 GameplayAbilitySet 的**Abilities**组中列出的 GameplayAbility。

### 提示

不要使用`GameplayAbilitySet::GiveAbilities()`成员函数，因为它不会给您访问实际上需要绑定和调用能力到输入组件的一组`FGameplayAbilitySpecHandle`对象。

```cpp
void AWarrior::SetupPlayerInputComponent( UInputComponent* Input )
{
  Super::SetupPlayerInputComponent( Input );
  // Connect the class's AbilitySystemComponent
  // to the actor's input component
  AbilitySystemComponent->BindToInputComponent( Input );

  // Go thru each BindInfo in the gameplayAbilitySet.
  // Give & try and activate each on the AbilitySystemComponent.
  for( const FGameplayAbilityBindInfo& BindInfo : 
  gameplayAbilitySet->Abilities )
  {
    // BindInfo has 2 members:
    //   .Command (enum value)
    //   .GameplayAbilityClass (UClass of a UGameplayAbility)
    if( !BindInfo.GameplayAbilityClass )
    {
      Error( FS( "GameplayAbilityClass %d not set",
      (int32)BindInfo.Command ) );
      continue;
    }

    FGameplayAbilitySpec spec(
    // Gets you an instance of the UClass
    BindInfo.GameplayAbilityClass->
    GetDefaultObject<UGameplayAbility>(),
    1, (int32)BindInfo.Command ) ;

 // STORE THE ABILITY HANDLE FOR LATER INVOKATION
 // OF THE ABILITY
    FGameplayAbilitySpecHandle abilityHandle = 
    AbilitySystemComponent->GiveAbility( spec );

    // The integer id that invokes the ability 
    // (ith value in enum listing)
    int32 AbilityID = (int32)BindInfo.Command;

    // CONSTRUCT the inputBinds object, which will
    // allow us to wire-up an input event to the
    // InputPressed() / InputReleased() events of
    // the GameplayAbility.
    FGameplayAbiliyInputBinds inputBinds(
      // These are supposed to be unique strings that define
      // what kicks off the ability for the actor instance.
      // Using strings of the format 
      // "ConfirmTargetting_Player0_AbilityClass"
      FS( "ConfirmTargetting_%s_%s", *GetName(), 
        *BindInfo.GameplayAbilityClass->GetName() ),
      FS( "CancelTargetting_%s_%s", *GetName(), 
        *BindInfo.GameplayAbilityClass->GetName() ),
      "EGameplayAbilityInputBinds", // The name of the ENUM that 
      // has the abilities listing (GameplayAbilitySet.h).
      AbilityID, AbilityID
    );
 // MUST BIND EACH ABILITY TO THE INPUTCOMPONENT, OTHERWISE
 // THE ABILITY CANNOT "HEAR" INPUT EVENTS.
    // Enables triggering of InputPressed() / InputReleased() 
    // events, which you can in-turn use to call 
    // TryActivateAbility() if you so choose.
    AbilitySystemComponent->BindAbilityActivationToInputComponent(
      Input, inputBinds
    );

    // Test-kicks the ability to active state.
    // You can try invoking this manually via your
    // own hookups to keypresses in this Warrior class
    // TryActivateAbility() calls ActivateAbility() if
    // the ability is indeed invokable at this time according
    // to rules internal to the Ability's class (such as cooldown
    // is ready and cost is met)
    AbilitySystemComponent->TryActivateAbility( 
      abilityHandle, 1 );
  }
}
```

## 它是如何工作的...

您必须通过一系列对`UAbilitySystemComponent::GiveAbility(spec)`的调用，将一组`UGameplayAbility`对象子类化并链接到您的角色的`UAbilitySystemComponent`对象中，其中包括适当构造的`FGameplayAbilitySpec`对象。这样做的目的是为您的角色装备这一组`GameplayAbilities`。每个`UGameplayAbility`的功能、成本、冷却和激活都被整洁地包含在您将构建的`UGameplayAbility`类派生类中。

## 还有更多...

您将需要仔细编写一堆其他可在`GameplayAbility.h`头文件中使用的函数，包括以下实现：

+   `SendGameplayEvent`：这是一个通知 GameplayAbility 发生了一些常规游戏事件的函数。

+   `CancelAbility`：这是一个函数，用于在使用能力过程中停止能力，并给予能力中断状态。

+   请记住，在`UGameplayAbility`类声明的底部附近有一堆现有的`UPROPERTY`，它们在添加或删除某些`GameplayTags`时激活或取消能力。有关详细信息，请参阅以下*GameplayTags API - 将 GameplayTags 附加到 Actor*的示例。

+   还有更多！探索 API 并在代码中实现那些您认为有用的功能。

## 另请参阅

+   `GameplayAbilities` API 是一系列丰富且巧妙交织的对象和函数。真正探索`GameplayEffects`，`GameplayTags`和`GameplayTasks`以及它们如何与`UGameplayAbility`类集成，以充分探索库所提供的功能。

# GameplayAbilities API - 使用 UAttributeSet 实现统计信息

`GameplayAbilities` API 允许您将一组属性（即`UAttributeSet`）与 Actor 关联起来。`UAttributeSet`描述了适用于该 Actor 的游戏属性的属性，例如`Hp`，`Mana`，`Speed`，`Armor`，`AttackDamage`等等。您可以定义一个适用于所有 Actor 的单个全局游戏属性集，或者适用于不同类别的 Actor 的几个不同的属性集。

## 准备就绪

`AbilitySystemComponent`是您需要添加到 Actor 中的第一件事，以使其能够使用*GameAbilities API*和`UAttributeSet`。要定义自定义的`UAttributeSet`，您只需从`UAttributeSet`基类派生，并使用自己的一系列`UPROPERTY`成员扩展基类。之后，您必须将自定义的`AttributeSet`注册到`Actor`类的`AbilitySystemComponent`中。

## 如何做...

1.  在`ProjectName.Build.cs`文件中链接到`GameplayAbilities` API。

1.  在自己的文件中，从`UAttributeSet`类派生，并使用一组`UPROPERTY`装饰该类，这些属性将在每个 Actor 的属性集中使用。例如，您可能希望声明类似于以下代码片段的`UAttributeSet`派生类：

```cpp
#include "Runtime/GameplayAbilities/Public/AttributeSet.h"
#include "GameUnitAttributeSet.generated.h"

UCLASS(Blueprintable, BlueprintType)
class CHAPTER12_API UGameUnitAttributeSet : public UAttributeSet
{
  GENERATED_BODY()
  public:
  UGameUnitAttributeSet( const FObjectInitializer& PCIP );
  UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = GameUnitAttributes )  float Hp;
  UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = GameUnitAttributes )  float Mana;
  UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = GameUnitAttributes )  float Speed;
};
```

### 提示

如果您的代码是网络化的，您可能希望在`UPROPERTY`的每个副本声明中启用复制。

1.  通过调用以下代码将`GameUnitAttributeSet`与`Actor`类中的`AbilitySystemComponent`连接起来：

```cpp
AbilitySystemComponent->InitStats( 
  UGameUnitAttributeSet::StaticClass(), NULL );
```

您可以将此调用放在`PostInitializeComponents()`的某个位置，或者在稍后调用的代码中。

1.  一旦您注册了`UAttributeSet`，您可以继续下一个步骤，并将`GameplayEffect`应用于属性集中的某些元素。

1.  确保您的`Actor`类对象通过从其派生来实现`IAbilitySystemInterface`。这非常重要，因为`UAbilitySet`对象将尝试将其转换为`IAbilitySystemInterface`，以在代码的各个位置调用`GetAbilitySystemComponent()`。

## 工作原理...

`UAttributeSets`只是允许您枚举和定义不同 Actor 的属性。`GameplayEffects`将是您对特定 Actor 的属性进行更改的手段。

## 还有更多...

您可以编写`GameplayEffects`的定义，这些定义将对 AbilitySystemComponent 的`AttributeSet`集合产生影响。您还可以编写`GameplayTasks`，用于在特定时间或事件运行的通用函数，甚至是响应标签添加（`GameplayTagResponseTable.cpp`）。您可以定义`GameplayTags`来修改 GameplayAbility 的行为，并在游戏过程中选择和匹配游戏单位。

# GameplayAbilities API - 使用 GameplayEffect 实现增益效果

A buff is just an effect that introduces a temporary, permanent, or recurring change to a game unit's attributes from its `AttributeSet`. Buffs can either be good or bad, supplying either bonuses or penalties. For example, you might have a hex buff that slows a unit to half speed, an angel wing buff that increases unit speed by 2x, or a cherub buff that recovers `5 hp` every five seconds for three minutes. A `GameplayEffect` affects an individual gameplay attributes in the `UAttributeSet` attached to an `AbilitySystemComponent` of an Actor.

## Getting ready

Brainstorm your game units' effects that happen during the game. Be sure that you've created an `AttributeSet`, shown in the previous recipe, with gameplay attributes that you'd like to affect. Select an effect to implement and follow the succeeding steps with your example.

### Tip

You may want to turn `LogAbilitySystem` to a `VeryVerbose` setting by going to the **Output Log** and typing ```cpp, and then `Log LogAbilitySystem` `All`.

This will display much more information from `AbilitySystem` in the **Output Log**, making it easier to see what's going on within the system.

## How to do it…

In the following steps, we'll construct a quick `GameplayEffect` that heals `50 hp` to the selected unit's `AttributeSet`:

1.  Construct your `UGameplayEffect` class object using the `CONSTRUCT_CLASS` macro with the following line of code:

    ```

// Create GameplayEffect recovering 50 hp one time only to unit

CONSTRUCT_CLASS( UGameplayEffect, RecoverHP );

```cpp

2.  Use the `AddModifier` function to change the `Hp` field of `GameUnitAttributeSet`, as follows:

```

AddModifier( RecoverHP,

GET_FIELD_CHECKED( UGameUnitAttributeSet, Hp ),

EGameplayModOp::Additive, FScalableFloat( 50.f ) );

```cpp

3.  Fill in the other properties of `GameplayEffect`, including fields such as `DurationPolicy` and `ChanceToApplyToTarget` or any other fields that you'd like to modify, as follows:

```

RecoverHP->DurationPolicy = EGameplayEffectDurationType::HasDuration;

RecoverHP->DurationMagnitude = FScalableFloat( 10.f );

RecoverHP->ChanceToApplyToTarget = 1.f;

RecoverHP->Period = .5f;

```cpp

4.  Apply the effect to an `AbilitySystemComponent` of your choice. The underlying `UAttributeSet` will be affected and modified by your call, as shown in the following piece of code:

```

FActiveGameplayEffectHandle recoverHpEffectHandle =

AbilitySystemComponent->ApplyGameplayEffectToTarget( RecoverHP,

AbilitySystemComponent, 1.f );

```cpp

## How it works…

`GameplayEffects` are simply little objects that effect changes to an actor's `AttributeSet`. `GameplayEffects` can occur once, or repeatedly, in intervals over a `Period`. You can program-in effects pretty quickly and the `GameplayEffect` class creation is intended to be inline.

## There's more…

Once the `GameplayEffect` is active, you will receive an `FActiveGameplayEffectHandle`. You can use this handle to attach a function delegate to run when the effect is over using the `OnRemovedDelegate` member of the `FActiveGameplayEffectHandle`. For example, you might call:

```

FActiveGameplayEffectHandle recoverHpEffectHandle =

AbilitySystemComponent->ApplyGameplayEffectToTarget( RecoverHP,

AbilitySystemComponent, 1.f );

if( recoverHpEffectHandle ) {

recoverHpEffectHandle->AddLambda( []() {

Info( "RecoverHp Effect has been removed." );

} );

}

```cpp

# GameplayTags API – Attaching GameplayTags to an Actor

`GameplayTags` are just small bits of text that describes states (or buffs) for the player or attributes that can attach to things such as `GameplayAbilities` and also to describe `GameplayEffects`, as well as states that clear those effects. So, we can have `GameplayTags`, such as `Healing` or `Stimmed`, that trigger various `GameplayAbilities` or `GameplayEffects` to our liking. We can also search for things via `GameplayTags` and attach them to our `AbilitySystemComponents` if we choose.

## How to do it…

There are several steps to getting `GameplayTags` to work correctly inside your engine build; they are as follows:

1.  First, we will need to create a Data Table asset to carry all of our game's tag names. Right-click on **Content Browser** and select **Miscellaneous** | **Data Table**. Select a table class structure deriving from `GameplayTagTableRow`.![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00303.jpeg)

List all tags available inside your game under that data structure.

2.  Add `UPROPERTY() TArray<FString>` to your `GameMode` object to list the names of the `TagTableNames` that you want to load into the `GameplayTags` module manager:

```

UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = GameplayTags )

TArray<FString> GameplayTagTableNames;

```cpp

3.  In your GameMode's `PostInitializeComponents` function, or later, load the tags in the tables of your choice using `GetGameplayTagsManager`:

```

IGameplayTagsModule::Get().GetGameplayTagsManager().

LoadGameplayTagTable( GameplayTagTableNames );

```cpp

4.  Use your `GameplayTags`. Inside each of your GameplayAbility objects, you can modify the blockedness, cancelability, and activation requirements for each GameplayAbility using tag attachment or removal.![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00304.jpeg)

You do have to rebuild your engine in order to get your tags to load within the editor. The patch to the engine source that is proposed allows you to hook in a call to `IGameplayTagsModule::Get().GetGameplayTagsManager().LoadGameplayTagTable( GameplayTagTableNames )`.

To get this call embedded into the editor's startup, you will need to edit the engine's source.

# GameplayTasks API – Making things happen with GameplayTasks

`GameplayTasks` are used to wrap up some gameplay functionality in a reusable object. All you have to do to use them is derive from the `UGameplayTask` base class and override some of the member functions that you prefer to implement.

## Getting ready

Go in the UE4 Editor and navigate to **Class Viewer**. Ensure that you have linked in the `GameplayTasks` API into your `ProjectName.Build.cs` file and search with **Actors Only** tickbox off for the `GameplayTask` object type.

## How to do it…

1.  Ensure that you have linked `GameplayTasks` API into your `ProjectName.Build.cs` file.
2.  Click on **File** | **Add C++ Class…** Choose to derive from `GameplayTask`. To do so, you must first tick **Show All Classes**, and then type `gameplaytask` into the filter box. Click on **Next**, name your C++ class (something like `GameplayTask_TaskName` is the convention) then add the class to your project. The example spawns a particle emitter and is called `GameplayTask_CreateParticles`.
3.  Once your `GameplayTask_CreateParticles.h` and `.cpp` pair are created, navigate to the `.h` file and declare a static constructor that creates a `GameplayTask_CreateParticles` object for you:

```

// Like a constructor.

UGameplayTask_CreateParticles* UGameplayTask_CreateParticles::ConstructTask(

TScriptInterface<IGameplayTaskOwnerInterface> TaskOwner,

UParticleSystem* particleSystem,

FVector location )

{

UGameplayTask_CreateParticles* task =

NewTask<UGameplayTask_CreateParticles>( TaskOwner );

// Fill fields

if( task )

{

task->ParticleSystem = particleSystem;

task->Location = location;

}

return task;

}

```cpp

4.  Override the `UGameplayTask_CreateEmitter::Activate()` function, which contains code that runs when `GameplayTask` is effected, as follows:

```

void UGameplayTask_CreateEmitter::Activate()

{

Super::Activate();

UGameplayStatics::SpawnEmitterAtLocation( GetWorld(),

ParticleSystem->GetDefaultObject<UParticleSystem>(),

Location );

}

```cpp

5.  Add `GameplayTasksComponent` to your `Actor` class derivative, which is available in the **Components** dropdown of the **Components** tab in the Blueprint editor.
6.  Create and add an instance of your `GameplayTask` inside your `Actor` derivative instance using the following code:

```

UGameplayTask_CreateParticles* task =

UGameplayTask_CreateParticles::ConstructTask( this,

particleSystem, FVector( 0.f, 0.f, 200.f ) );

if( GameplayTasksComponent )

{

GameplayTasksComponent->AddTaskReadyForActivation( *task );

}

```cpp

7.  This code runs anywhere in your `Actor` class derivative, any time after `GameplayTasksComponent` is initialized (any time after `PostInitializeComponents()`).

## How it works…

`GameplayTasks` simply register with the `GameplayTasksComponent` situated inside an `Actor` class derivative of your choice. You can activate any number of `GameplayTasks` at any time during gameplay to trigger their effects.

`GameplayTasks` can also kick off `GameplayEffects` to change attributes of `AbilitySystemsComponents` if you wish.

## There's more…

You can derive `GameplayTasks` for any number of events in your game. What's more is that you can override a few more virtual functions to hook into additional functionality.

# HTTP API – Web request

When you're maintaining scoreboards or other such things that require regular HTTP request access to servers, you can use the HTTP API to perform such web request tasks.

## Getting ready

Have a server to which you're allowed to request data via HTTP. You can use a public server of any type to try out HTTP requests if you'd like.

## How to do it…

1.  Link to the HTTP API in your `ProjectName.Build.cs` file.
2.  In the file in which you will send your web request, include the `HttpModule.h` header file, the `HttpManager.h` header file, and the `HttpRetrySystem.h` file, as shown in the following code snippet:

```

#include "Runtime/Online/HTTP/Public/HttpManager.h"

#include "Runtime/Online/HTTP/Public/HttpModule.h"

#include "Runtime/Online/HTTP/Public/HttpRetrySystem.h"

```cpp

3.  Construct an `IHttpRequest` object from `FHttpModule` using the following code:

```

TSharedRef<IHttpRequest> http=FHttpModule::Get().CreateRequest();

```cpp

### Tip

`FHttpModule` is a singleton object. One copy of it exists for the entire program that you are meant to use for all interactions with the `FHttpModule` class.

4.  Attach your function to run to the `IHttpRequest` object's `FHttpRequestCompleteDelegate`, which has a signature as follows:

```

void HttpRequestComplete( FHttpRequestPtr request,

FHttpResponsePtr response, bool success );

```cpp

5.  The delegate is found inside of the `IHttpRequest` object as `http->OnProcessRequestComplete()`:

```

FHttpRequestCompleteDelegate& delegate = http->OnProcessRequestComplete();

```cpp

    There are a few ways to attach a callback function to the delegate. You can use the following:

    *   A lambda using `delegate.BindLambda()`:

```

委托.BindLambda(

// Anonymous, inlined code function (aka lambda)

[]( FHttpRequestPtr request, FHttpResponsePtr response, bool success ) -> void

{

UE_LOG( LogTemp, Warning, TEXT( "Http Response: %d, %s" ),

request->GetResponse()->GetResponseCode(),

*request->GetResponse()->GetContentAsString() );

});

```cpp

    *   Any UObject's member function:

```

delegate.BindUObject( this, &AChapter12GameMode::HttpRequestComplete );

```cpp

### Tip

You cannot attach to `UFunction` directly here as the `.BindUFunction()` command requests arguments that are all `UCLASS`, `USTRUCT` or `UENUM`.

    *   Any plain old C++ object's member function using `.BindRaw`:

```

PlainObject* plainObject = new PlainObject();

delegate.BindRaw( plainObject, &PlainObject::httpHandler );

// plainObject cannot be DELETED Until httpHandler gets called..

```cpp

### Tip

You have to ensure that your `plainObject` refers to a valid object in memory at the time the HTTP request completes. This means that you cannot use `TAutoPtr` on `plainObject`, because that will deallocate `plainObject` at the end of the block in which it is declared, but that may be before the HTTP request completes.

    *   A global C-style static function:

```

// C-style function for handling the HTTP response:

void httpHandler( FHttpRequestPtr request,

FHttpResponsePtr response, bool success )

{

Info( "static: Http req handled" );

}

delegate.BindStatic( &httpHandler );

```cpp

### Note

When using a delegate callback with an object, be sure that the object instance that you're calling back on lives on at least until the point at which the `HttpResponse` arrives back from the server. Processing the `HttpRequest` takes real time to run. It is a web request after all—think of waiting for a web page to load.

You have to be sure that the object instance on which you're calling the callback function has not deallocated on you between the time of the initial call and the invocation of your `HttpHandler` function. The object must still be in memory when the callback returns after the HTTP request completes.

You cannot simply expect that the `HttpResponse` function happens immediately after you attach the callback function and call `ProcessRequest()`! Using a reference counted `UObject` instance to attach the `HttpHandler` member function is a good idea to ensure that the object stays in memory until the HTTP request completes.

6.  Specify the URL of the site you'd like to hit:

```

http->SetURL( TEXT( "http://unrealengine.com" ) );

```cpp

7.  Process the request by calling `ProcessRequest`:

```

http->ProcessRequest();

```cpp

## How it works…

The HTTP object is all you need to send off HTTP requests to a server and get HTTP responses. You can use the HTTP request/response for anything that you wish; for example, submitting scores to a high scores table or to retrieve text to display in-game from a server.

They are decked out with a URL to visit and a function callback to run when the request is complete. Finally, they are sent off via `FManager`. When the web server responds, your callback is called and the results of your HTTP response can be shown.

## There's more…

You can set additional HTTP request parameters via the following member functions:

*   `SetVerb()` to change whether you are using the `GET` or `POST` method in your HTTP request
*   `SetHeaders()` to modify any general header settings you would like

# HTTP API – Progress bars

The `IHttpRequest` object from HTTP API will report HTTP download progress via a callback on a `FHttpRequestProgressDelegate` accessible via `OnRequestProgress()`. The signature of the function we can attach to the `OnRequestProgress()` delegate is as follows:

```

HandleRequestProgress( FHttpRequestPtr request, int32 sentBytes, int32 receivedBytes )

```cpp

The three parameters of the function you may write include: the original `IHttpRequest` object, the bytes sent, and the bytes received so far. This function gets called back periodically until the `IHttpRequest` object completes, which is when the function you attach to `OnProcessRequestComplete()` gets called. You can use the values passed to your `HandleRequestProgress` function to advance a progress bar that you will create in UMG.

## Getting ready

You will need an internet connection to use this recipe. We will be requesting a file from a public server. You can use a public server or your own private server for your HTTP request if you'd like.

In this recipe, we will bind a callback function to just the `OnRequestProgress()` delegate to display the download progress of a file from a server. Have a project ready where we can write a piece of code that will perform `IHttpRequest,` and a nice interface on which to display percentage progress.

## How to do it…

1.  Link to the `UMG` and `HTTP` APIs in your `ProjectName.Build.cs` file.
2.  Build a small UMG UI with `ProgressBar` to display your HTTP request's progress.
3.  Construct an `IHttpRequest` object using the following code:

```

TSharedRef<IHttpRequest> http = HttpModule::Get().CreateRequest();

```cpp

4.  Provide a callback function to call when the request progresses, which updates a visual GUI element:

```

http->OnRequestProgress().BindLambda( []( FHttpRequestPtr request, int32 sentBytes, int32 receivedBytes ) -> void

{

int32 totalLen = request->GetResponse()->GetContentLength();

float perc = (float)receivedBytes/totalLen;

如果（HttpProgressBar）

HttpProgressBar->SetPercent( perc );

} );

```

1.  使用`http->ProcessRequest()`处理您的请求。

## 它是如何工作的...

`OnRequestProgress()`回调会定期触发，显示已发送和已接收的字节的 HTTP 进度。我们将通过计算`(float)receivedBytes/totalLen`来计算下载完成的总百分比，其中`totalLen`是 HTTP 响应的总字节长度。使用我们附加到`OnRequestProgress()`委托回调的 lambda 函数，我们可以调用 UMG 小部件的`.SetPercent()`成员函数来反映下载的进度。
