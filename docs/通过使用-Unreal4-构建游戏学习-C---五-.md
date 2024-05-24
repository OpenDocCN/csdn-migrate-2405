# 通过使用 Unreal4 构建游戏学习 C++（五）

> 原文：[`annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27`](https://annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：通过 UMG 和音频改进 UI 反馈

在游戏中，用户反馈非常重要，因为用户需要了解游戏中发生的情况（得分、生命值、显示库存等）。在以前的章节中，我们创建了一个非常简单的 HUD 来显示文本和库存中的物品，但是如果您想要一个看起来专业的游戏，您将需要一个比那更好得多的**用户界面**（**UI**）！

幸运的是，现在有更简单的方法来使用虚幻动态图形 UI 设计师（UMG）构建 UI，这是 UE4 附带的系统，专门用于此目的。本章将向您展示如何使用它来接管我们之前所做的工作，并制作看起来更好并具有更多功能的东西。我们将开始更新库存窗口，并我将提出您可以继续该过程并更新其余 UI 的建议。

通过音频提供反馈的另一种方法是，无论是在游戏本身还是通过 UI 与其交互时，我们还将介绍如何播放声音。

我们将要涵盖的主题如下：

+   UMG 是什么？

+   更新库存窗口

+   布局您的 UI

+   更新您的 HUD 并添加生命条

+   播放音频

# UMG 是什么？

您可能已经注意到，我们用来在屏幕上绘制的代码非常复杂。每个元素都需要手动放置在屏幕上。您可能会问自己是否有更简单的方法。有！那就是虚幻动态图形 UI 设计师，或者 UMG。

UMG 通过使用特殊蓝图简化了创建 UI 的过程，允许您以可视方式布局界面。这也可以让您让精通技术的艺术家为您设计布局，而您则将一切连接起来。我们将使用这个，但由于这是一本 C++书，我们将在 C++中处理大部分幕后功能。

要使用 UMG，首先需要在 Visual Studio 项目中找到`GoldenEgg.Build.cs`文件。`.cs`文件通常是 C#，而不是 C++，但您不必担心，因为我们只会对此文件进行轻微更改。找到这一行：

```cpp
PublicDependencyModuleNames.AddRange(new string[] { "Core", "CoreUObject", "Engine", "InputCore" });
```

并将以下内容添加到列表中：

```cpp
, "UMG", "Slate", "SlateCore"
```

您可能需要在这样做后重新启动引擎。然后您将准备好在 UMG 中编码！

# 更新库存窗口

我们将从更新库存窗口开始。我们现在拥有的不是一个真正的窗口，只是在屏幕上绘制的图像和文本，但现在您将看到如何轻松创建看起来更像真正窗口的东西——带有背景和关闭按钮，代码将更简单。

# WidgetBase 类

要为 UMG 小部件创建 C++类，您需要基于`UserWidget`创建一个新类。在添加新的 C++类时，需要检查显示所有类并搜索它以找到它： 

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bf64bda7-1e63-4817-b4d7-48e14dd54e41.png)

将您的类命名为`WidgetBase`。这将是您派生任何其他小部件类的基类。这使您可以在此类中放置将在许多不同小部件中重复使用的功能。在这种情况下，我在那里放置了`CloseButton`的功能。并非所有小部件都需要一个，但是如果您想要一个标准窗口，通常是一个好主意。

这是`WidgetBase.h`的代码：

```cpp
#include "CoreMinimal.h"
#include "Blueprint/UserWidget.h"
#include "UMG/Public/Components/Button.h"
#include "WidgetBase.generated.h"

/**
 * WidgetBase.h
 */
UCLASS()
class GOLDENEGG_API UWidgetBase : public UUserWidget
{
    GENERATED_BODY()

public:
    UPROPERTY(meta = (BindWidgetOptional))
    UButton* CloseButton;

    bool isOpen;

    bool Initialize();
    void NativeConstruct();

    UFUNCTION(BlueprintCallable)
    void CloseWindow();
};
```

这将设置允许您使用按钮关闭窗口的所有代码。`CloseButton`将是我们在设计蓝图中创建的按钮的名称。

行`UPROPERTY(meta = (BindWidgetOptional))`应自动将`CloseWindow`变量链接到稍后将在蓝图中创建的具有相同名称的`Button`对象。如果您知道小部件将始终存在，则可以改用`UPROPERTY(meta = (BindWidget))`，但在这种情况下，可能存在不需要关闭窗口的按钮的情况。

这里是`WidgetBase.cpp`：

```cpp
#include "WidgetBase.h"
#include "Avatar.h"
#include "Kismet/GameplayStatics.h"

bool UWidgetBase::Initialize()
{
    bool success = Super::Initialize();
    if (!success)  return false;

    if (CloseButton != NULL)
    {
        CloseButton->OnClicked.AddDynamic(this, &UWidgetBase::CloseWindow);
    }

    return true;
}

void UWidgetBase::NativeConstruct()
{
    isOpen = true;
}

void UWidgetBase::CloseWindow()
{
    if (isOpen)
    {
        AAvatar *avatar = Cast<AAvatar>(
            UGameplayStatics::GetPlayerPawn(GetWorld(), 0));

        avatar->ToggleInventory();
        isOpen = false;
    }
}
```

如果本章中包含的 UMG 对您不起作用，您可能需要在路径前面添加`Runtime/`。但它们应该像这样工作（并且在我的项目中确实工作）。

以下行是将`OnClicked`事件设置为调用特定函数的内容：

```cpp
CloseButton->OnClicked.AddDynamic(this, &UWidgetBase::CloseWindow);
```

我们不再需要像以前那样在输入设置中设置所有内容，因为 UMG 按钮已经设置好处理`OnClicked`，您只需要告诉它要调用哪个函数。如果由于某种原因它不起作用，我将向您展示如何通过稍后在蓝图中设置`OnClicked`来解决问题。由于`CloseButton`是可选的，您确实需要检查它以确保它未设置为`NULL`以避免错误。

`isOpen`变量用于处理常见的 UI 问题，有时点击（或按键）会注册多次，导致函数被调用多次，这可能会导致错误。通过将`isOpen`设置为 true，第一次调用`OnClicked`函数时，您确保它不会运行多次，因为它只会在值为 false 时运行。当然，您还需要确保在重新打开窗口时重置该值，这就是`NativeConstruct()`函数的作用。

# 库存小部件类

现在，您将要创建一个专门处理库存小部件的类，该类派生自`WidgetBase`。如果由于某种原因找不到`WidgetBase`以通常的方式创建类，则在过滤器下取消选中仅限于演员。将其命名为`InventoryWidget`。

创建了该类后，您可以开始添加代码。首先，这是`InventoryWidget.h`：

```cpp
#include "CoreMinimal.h"
#include "WidgetBase.h"
#include "UMG/Public/Components/Image.h"
#include "UMG/Public/Components/TextBlock.h"
#include "UMG/Public/Components/Button.h"
#include "InventoryWidget.generated.h"

/**
 * 
 */
UCLASS()
class GOLDENEGG_API UInventoryWidget : public UWidgetBase
{
    GENERATED_BODY()

public:
    const int kNumWidgets = 2;
    //image widgets
    UPROPERTY(meta = (BindWidget))
        UImage* InventoryImage1;

    UPROPERTY(meta = (BindWidget))
        UImage* InventoryImage2;

    //text widgets
    UPROPERTY(meta = (BindWidget))
        UTextBlock* InventoryText1;

    UPROPERTY(meta = (BindWidget))
        UTextBlock* InventoryText2;

    //Invisible Buttons
    UPROPERTY(meta = (BindWidget))
        UButton* InventoryButton1;

    UPROPERTY(meta = (BindWidget))
        UButton* InventoryButton2;

    bool Initialize();

    void HideWidgets();
    void AddWidget(int idx, FString name, UTexture2D* img);

    UFUNCTION(BlueprintCallable)
    void MouseClicked1();
    UFUNCTION(BlueprintCallable)
    void MouseClicked2();
};
```

这个文件要复杂得多。我们再次使用`BindWidget`来在蓝图中设置对象。虽然您可以像以前一样在代码中布置小部件（但您应该能够创建包括图像、文本和按钮的子小部件），但为了保持简单，我只在屏幕上布置了两个小部件，并分别引用它们。您随时可以自己添加更多以供练习。

因此，在这种特殊情况下，我们为两个图像、两个文本块和两个按钮设置了小部件。有一个`Initialize`函数来设置它们，以及用于添加小部件、隐藏所有小部件以及每个按钮的鼠标点击处理程序的函数。

然后，我们需要编写`InventoryWidget.cpp`。首先，在文件顶部添加包含：

```cpp
#include "InventoryWidget.h"
#include "MyHUD.h"
#include "Runtime/UMG/Public/Components/SlateWrapperTypes.h"
```

然后设置`Initialize`函数：

```cpp
bool UInventoryWidget::Initialize()
{
    bool success = Super::Initialize();
    if (!success)  return false;

    if (InventoryButton1 != NULL)
    {
        InventoryButton1->OnClicked.AddDynamic(this, &UInventoryWidget::MouseClicked1);
    }
    if (InventoryButton2 != NULL)
    {
        InventoryButton2->OnClicked.AddDynamic(this, &UInventoryWidget::MouseClicked2);
    }

    return true;
}
```

此函数为按钮设置了`OnClicked`函数。然后添加处理小部件的函数：

```cpp
void UInventoryWidget::HideWidgets()
{
    InventoryImage1->SetVisibility(ESlateVisibility::Hidden);
    InventoryText1->SetVisibility(ESlateVisibility::Hidden);
    InventoryImage2->SetVisibility(ESlateVisibility::Hidden);
    InventoryText2->SetVisibility(ESlateVisibility::Hidden);
}

void UInventoryWidget::AddWidget(int idx, FString name, UTexture2D* img)
{
    if (idx < kNumWidgets)
    {
        switch (idx)
        {
        case 0:
            InventoryImage1->SetBrushFromTexture(img);
            InventoryText1->SetText(FText::FromString(name));
            InventoryImage1->SetVisibility(ESlateVisibility::Visible);
            InventoryText1->SetVisibility(ESlateVisibility::Visible);
            break;
        case 1:
            InventoryImage2->SetBrushFromTexture(img);
            InventoryText2->SetText(FText::FromString(name));
            InventoryImage2->SetVisibility(ESlateVisibility::Visible);
            InventoryText2->SetVisibility(ESlateVisibility::Visible);
            break;
        }

    }
}
```

`HideWidgets`隐藏窗口中的所有小部件，因此如果没有任何内容，它们将不会显示出来。`AddWidget`接受索引、名称和图像本身的纹理，然后为该索引设置小部件。文本小部件具有`SetText`函数，允许您传递`FText`（`FText::FromString`将其从`FString`转换为`FText`）。图像小部件具有`SetBrushFromTexture`，用于设置图像。

最后，您需要设置`MouseClicked`函数：

```cpp
void UInventoryWidget::MouseClicked1()
{
    // Get the controller & hud 
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
    hud->MouseClicked(0);
}

void UInventoryWidget::MouseClicked2()
{
    // Get the controller & hud 
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
    hud->MouseClicked(1);
}
```

这些只是使用 HUD 的`MouseClicked`函数调用按钮的索引（提示：在更新 HUD 函数以接受索引之前，这不会编译）。如果您想进一步实验，稍后可以研究另一种根据单击的按钮获取索引的方法，以便您可以为所有按钮使用相同的函数。

# 设置小部件蓝图

接下来，您需要设置蓝图。由于这是一种特殊类型的蓝图，因此使用其自己的类设置一个蓝图有点棘手。您不能只创建该类的蓝图，否则您将没有设计蓝图。相反，您必须首先创建设计蓝图，然后更改父级。

要做到这一点，请进入内容浏览器，选择要放置的目录，然后选择添加新项|用户界面|小部件蓝图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/21cb9202-5a8a-4914-b4d2-865824109afb.png)

将其重命名为`BP_InventoryWidget`，然后双击打开它。您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e677d439-c58d-4973-a2ef-31d64e6b4f4d.png)

在中心，您将直观地布置屏幕，方框代表您所瞄准的理论屏幕的边缘。在左侧，调色板向您展示了可以添加到屏幕上的基本 UI 对象。您将看到许多常见的对象，例如图像、文本字段、进度条、按钮、复选框和滑块。这基本上是您免费获得的许多功能。一旦您开始为游戏设置设置窗口，其中许多功能将派上用场。

但首先，我们需要更改此处的父类。在右上角选择图表，顶部工具栏上的类设置，然后在详细信息下查找类选项，并选择父类旁边的下拉菜单。在那里选择 InventoryWidget：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b60f8599-1131-4736-8ba9-13aa326477a4.png)

现在我们要回到设计师，开始布置屏幕！

屏幕上应该已经有一个画布面板。您可以单击右下角并拖动以使其成为所需的大小。画布通常应该是整个屏幕的大小。所有其他 UI 小部件都将放在画布内。当您拖动时，它将显示您所瞄准的各种分辨率。您将要选择与您所瞄准的分辨率类似的分辨率。

然后在调色板下选择边框，并将其拖出到屏幕上。这将是窗口的背景。您可以单击角落并将其拖动到所需的大小。您还可以在右侧找到颜色条（在详细信息下的外观>刷子颜色旁边），单击它以打开颜色选择器选择背景的颜色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0ec86d68-7381-4e7b-8928-d64953fd59c6.png)

您还可以在详细信息下重命名对象。一旦您完成了这些操作，点击并拖动一个按钮到屏幕上，并将其定位在背景的右上角。如果它试图填满整个边框对象，请确保您在层次结构中选择了画布面板，或者将其拖到边框对象之外，然后将其拖到其上方。确保将其命名为`CloseButton`。如果您想使其看起来更像关闭按钮，还可以在其中放置一个带有字母 X 的文本对象。您应该在详细信息中的行为下取消选中“已启用”，以便它不会阻止鼠标点击。

接下来，您将要定位两个图像对象和两个文本对象（稍后可以添加更多）。确保名称与您在代码中使用的名称完全匹配，否则它们将无法工作。在文本字段中，设置字体会更容易。在详细信息|外观下，您将找到字体选项，就像您在任何文字处理器中习惯的那样，并且您可以使用计算机上已有的字体（尽管，如果您仍然想要下载字体，没有任何阻止您的东西）。您还可以使用之前添加的字体。

另外，对于`OnClicked`，您将要添加一个按钮。您可以只在下面添加一个，但我使用了一种常见的 UI 方法：隐形按钮。拖动一个按钮出来，让它覆盖一个图像和一个文本。然后进入背景颜色并将 alpha（A）设置为`0`。Alpha 是颜色透明度的度量，`0`表示您根本看不到它。

如果以后点击按钮时遇到麻烦，可能会有其他对象挡住了。尝试将它们拖到按钮后面，或者研究一下如何禁用这些对象上的点击。

最后，您应该有类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3c7d7aed-0bfc-4ded-88be-e5c08bb2d320.png)

还要仔细注意在选择边框时右侧的内容选项。这是您可以设置水平和垂直对齐的地方。始终尝试设置这些，因此如果您希望某些内容始终位于屏幕的左上角，对齐将设置为水平对齐左侧和垂直对齐顶部。如果您没有为每个对象设置对齐，不同屏幕分辨率下的结果可能是不可预测的。稍后我会更详细地介绍这一点。

但现在，这将是你的库存窗口。它不一定要看起来和我的一样，所以玩得开心，尝试一下视觉布局！尽管记住，你可能不希望它占据整个屏幕，这样你就可以在点击后看到施放的咒语（尽管你可以在以后点击咒语时关闭窗口）。

# AMyHUD 更改

但这还不是全部！我们仍然需要修改我们现有的类来支持这个新的小部件，首先是`AMyHud`类。为了简化事情，我们不会在这里复制所有以前的功能。相反，我们将设置`OnClicked`函数来施放咒语，因为在游戏中这将比在屏幕上拖动物品更有用。右键点击不会被 UMG 自动处理，但如果你想以后添加它，你可以自己更深入地了解一下，你也可以查看以前的点击和拖动功能，所以如果你认为以后可能会用到它，你可能会想注释掉旧的代码而不是删除它。

目前，`MouseMoved`和`MouseRightClicked`函数已经消失，`MouseClicked`函数现在接受一个`int`索引。我们还有新的函数`OpenInventory`和`CloseInventory`，所以`MyHUD.h`现在应该是这样的：

```cpp
    void MouseClicked(int idx);

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Widgets") 
        TSubclassOf<class UUserWidget> wInventory;

    UInventoryWidget* Inventory;

    void OpenInventory();
    void CloseInventory();
```

还要在文件顶部添加#include "InventoryWidget.h"。一些其他函数也将被修改。所以，现在我们将看一下`AMyHUD.cpp`，你将看到新版本的函数有多么简单。以下是处理小部件的新函数：

```cpp
void AMyHUD::DrawWidgets()
{
    for (int c = 0; c < widgets.Num(); c++)
    {
        Inventory->AddWidget(c, widgets[c].icon.name, widgets[c].icon.tex);
    }
}

void AMyHUD::addWidget(Widget widget)
{
    widgets.Add(widget);
}

void AMyHUD::clearWidgets()
{
    widgets.Empty();
}
```

我们还需要将`MouseClicked`函数更新为这样：

```cpp
void AMyHUD::MouseClicked(int idx)
{
    AAvatar *avatar = Cast<AAvatar>(
        UGameplayStatics::GetPlayerPawn(GetWorld(), 0));
    if (widgets[idx].bpSpell)
    {
        avatar->CastSpell(widgets[idx].bpSpell);
    }

}
```

这将根据传入的索引施放咒语。然后有新的函数来打开和关闭库存：

```cpp
void AMyHUD::OpenInventory()
{
    if (!Inventory)
    {
        Inventory = CreateWidget<UInventoryWidget>(GetOwningPlayerController(), wInventory);
    }
    Inventory->AddToViewport();
    Inventory->HideWidgets();
}

void AMyHUD::CloseInventory()
{
    clearWidgets();
    if (Inventory)
    {
        Inventory->HideWidgets();
        Inventory->RemoveFromViewport();
    }
}
```

主要部分是向`Viewport`添加或删除新的小部件。我们还希望在视觉上隐藏小部件，以防止空的小部件显示，并在关闭窗口时清除所有小部件。

我们还改变了`struct Widget`以删除所有的定位信息。对它的任何引用都应该被删除，但如果你以后遇到任何错误（在你修改 Avatar 类之前，你将无法编译），确保`MouseMoved`和`MouseRightClicked`已经消失或被注释掉，并且没有其他东西在引用它们。新的、更简单的小部件应该看起来像这样：

```cpp
struct Widget
{
    Icon icon;
    // bpSpell is the blueprint of the spell this widget casts 
    UClass *bpSpell;
    Widget(Icon iicon)
    {
        icon = iicon;
    }
};
```

# AAvatar 更改

在`AAvatar`中，我们主要将修改`ToggleInventory`函数。新的函数将如下所示：

```cpp

void AAvatar::ToggleInventory()
{
    // Get the controller & hud 
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());

    // If inventory is displayed, undisplay it. 
    if (inventoryShowing)
    {
        hud->CloseInventory();
        inventoryShowing = false;
        PController->bShowMouseCursor = false;
        return;
    }

    // Otherwise, display the player's inventory 
    inventoryShowing = true;
    PController->bShowMouseCursor = true;
    hud->OpenInventory();
    for (TMap<FString, int>::TIterator it =
        Backpack.CreateIterator(); it; ++it)
    {
        // Combine string name of the item, with qty eg Cow x 5 
        FString fs = it->Key + FString::Printf(TEXT(" x %d"), it->Value);
        UTexture2D* tex;
        if (Icons.Find(it->Key))
        {
            tex = Icons[it->Key];
            Widget w(Icon(fs, tex));
            w.bpSpell = Spells[it->Key];
            hud->addWidget(w);
        }    
    }
    hud->DrawWidgets();
}
```

正如你所看到的，许多相同的 HUD 函数被重用，但现在从这里调用`OpenInventory`和`CloseInventory`的新函数，所以 HUD 可以在添加小部件之前显示窗口，并在关闭窗口时删除窗口。

还要从`Yaw`和`Pitch`函数中删除以下行：

```cpp
        AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
        hud->MouseMoved();
```

还要从`MouseRightClicked`中删除以下行（或删除该函数，但如果你这样做，请确保你也从`SetupPlayerInputComponent`中删除它）：

```cpp
        AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
        hud->MouseRightClicked();
```

最后，从`MouseClicked`中删除这些行（因为你不希望在点击不属于库存的地方时意外触发一个咒语）：

```cpp
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
    hud->MouseClicked();
```

现在你应该能够编译了。一旦你这样做了，进入 BP_MyHUD 并将类默认值>小部件>W 库存下拉菜单更改为 BP_InventoryWidget。

# 关于 OnClicked 的说明

可能你的`OnClicked`函数可能无法正常工作（我自己遇到了这个问题）。如果你找不到解决办法，你可以通过蓝图绕过，这就是为什么我把所有的鼠标点击函数都设置为蓝图可调用的原因。

如果这种情况发生在你身上，进入你的小部件蓝图的设计师，对于每个按钮点击它并找到详细信息下的事件，然后点击旁边的绿色+按钮。这将为该按钮添加`OnClicked`到图表并切换到该按钮。然后，从节点中拖出并添加你想要的功能。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/168d8986-d61f-4867-82fa-656e1ce75423.png)

# 布局您的 UI

当您布局 UI 时，有一些重要的事情需要牢记，UMG 有工具可以让这更容易。其中最重要的一点是，您的游戏不会总是以相同的分辨率运行。如果您在做移动游戏，可能会有许多不同分辨率的设备，您希望您的游戏在所有设备上看起来基本相同。即使是游戏机也不再免于这个问题，因为 Xbox One 和 PS4 现在都有 4K 选项。因此，您的游戏需要以一种可以实现这一点的方式设置。

如果您将所有的小部件都设置为特定的像素大小，然后在分辨率更高的情况下运行，它可能会变得非常小，看起来难以阅读，按钮可能也很难点击。在较低的分辨率下，它可能太大而无法适应屏幕。所以，请记住这一点。

您之前设置的画布面板将直观地显示您所追求的大小。但是对于所需大小的变化，您需要牢记几件事情。

首先，始终使用锚点。在详细信息下，您将看到一个锚点的下拉列表。打开它，您应该会看到类似这样的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/fc965460-7745-4f64-b872-a92b8a533d53.png)

蓝线左上角的九个选项是用来对齐对象的。行对齐到屏幕的顶部、中部和底部，而列对齐到屏幕的左侧、中部和右侧。因此，如果您希望某些内容始终出现在屏幕的左上角（比如得分或生命条），您将选择左上角的选项。如果您希望其他内容水平和垂直居中，请选择第二行、第二列。小白色方块基本上显示了您的定位。

剩下的选项可以让您在整个屏幕上拉伸某些内容（无论大小如何）。因此，如果您希望在顶部、中部或底部水平拉伸某些内容，请查看右列。对于垂直方向，请查看底部行。如果您希望窗口横跨整个屏幕，请查看右下角的选项。

您还可以从调色板中添加一个比例框，如果您希望其中的所有内容都按比例缩放以适应屏幕大小。虽然如果您有一些希望保持固定大小的东西，比如一张图片，您可以勾选“大小自适应内容”来防止它自动调整大小。

如果您想要更高级一点，您可以添加代码来检查屏幕大小并交换部分或整个 UI，但这超出了本书的范围，所以如果您想在自己的项目中稍后尝试，请记住这一点！

您的 UI 的另一个重要事项是本地化。如果您希望在自己国家之外的任何地方发布游戏，您将需要进行本地化。这意味着您不仅要习惯于不直接编写文本，而是使用内置的本地化系统来添加您设置的字符串 ID，而不是直接编写文本。代码将寻找特定的 ID，并将其替换为相应的本地化文本。您可以在这里了解内置的本地化系统：[`docs.unrealengine.com/en-us/Gameplay/Localization`](https://docs.unrealengine.com/en-us/Gameplay/Localization)。

这也会影响您布局 UI 的方式。当您第一次将游戏本地化为德语时，您会发现一切都变成了两倍长！虽然您可能能让翻译人员想出更短的表达方式，但您可能会希望使文本块比您认为需要的更长，或者考虑找到使文本收缩以适应或滚动的方法。

# 更新您的 HUD 并添加生命条

我不会在这里给出完整的说明，但以下是一些关于更新 HUD 的提示。一旦您这样做，它将进一步简化您的代码！

# 创建一个 HUD 类

您需要创建一个从 WidgetBase 派生的新类，用于您的新 HUD。在这种情况下，您将需要 Canvas Panel，但不需要背景。确保所有内容都会延伸到整个屏幕。

您将希望将大部分 UI 放在角落里，因此您可以在屏幕的左上角添加一个进度条小部件来显示健康。此外，考虑添加一个文本小部件来告诉它是什么，和/或在屏幕上显示实际数字。

对于消息，您可以将文本小部件对齐到屏幕的顶部中间，并使用它们来显示文本。

# 添加健康条

如果您已添加了推荐的进度条小部件，您会发现绘制健康条现在更容易了。您需要像其他小部件一样获取对它的引用。然后，您所需要做的就是调用`SetPercent`来显示当前的健康值（并在健康值改变时重置它）。

您不再需要自己绘制整个东西，但是您可以使用`SetFillColorAndOpacity`来自定义外观！

# 播放音频

我们将回到您的代码，做最后一件真正有助于您的游戏反馈的事情，但是在创建游戏时，这似乎总是最后一个人会考虑到的事情：音频。

音频可以真正增强您的游戏，从在单击按钮时播放声音到添加音效、对话、背景音乐和环境音效。如果您在夜晚独自在树林中行走，蟋蟀的鸣叫声、您自己的脚步声和不祥的音乐可以真正营造氛围。或者，您可以播放鸟鸣和愉快的音乐，营造完全不同的氛围。这都取决于您！

我们将在你施放暴风雪咒语时添加一个声音。因此，请寻找一个免费的风声。有很多网站提供免版税的声音文件。其中一些要求您在使用它们时在您的制作人员名单中提到他们。对于这个，我在一个名为[SoundBible.com](http://www.soundbible.com)的网站上找到了一个公共领域的声音，这意味着任何人都可以使用它。但是请寻找您喜欢的声音。

有些网站可能会要求您注册以下载声音。如果您感到有雄心壮志，甚至可以自己录制一个！

我使用了.wav 文件，这是一种标准格式，尽管其他格式可能也有效。但是对于小声音，您可能希望坚持使用.wav，因为 MP3 使用了压缩，这可能会稍微减慢游戏速度，因为它需要对其进行解压缩。

一旦您找到喜欢的文件，请为声音创建一个文件夹，并从文件管理器将声音文件拖入其中。然后在同一文件夹中右键单击并选择 Sounds | Sound Cue：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2b52b6f2-364a-4485-8585-a519d7ae5a5e.png)

将其重命名为 WindCue，然后双击它以在蓝图编辑器中打开它。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/131d3ae3-3a8b-4994-a0da-109a867a4541.png)

声音提示是我们设置声音的地方。首先，右键单击任何位置，然后选择 Wave Player 添加一个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/500545b1-f0ba-4555-8f2f-fdea977a5965.png)

然后，选择 Wave Player。在详细信息中，您将看到一个名为 Sound Wave 的选项。选择下拉列表并搜索您添加的.wav 文件以选择它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/279db068-abc1-4cde-8025-315c2bb495c0.png)

然后，从 Wave Player 的输出处拖动并放入输出（带有小扬声器图像）。这将连接它。要测试它，您可以选择播放提示，然后您应该听到声音，并且看到线条变成橙色，表示声音被传输到输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9be39afa-c610-4f29-aa53-d6ea16ec7fc1.png)

如果您不喜欢声音的方式，请尝试详细信息下的选项。我使用的声音对我想要的效果太安静了，所以我增加了音量倍增器使其响亮得多。

现在我们已经设置好声音，是时候将其添加到代码中了。在这种情况下，我们将更新`AMyHUD`类。首先，在`MyHUD.h`的顶部添加以下行：

```cpp
#include "Sound/SoundCue.h"
```

此外，在同一文件中添加以下内容：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Sound")
    USoundCue* audioCue;
```

您将希望将`SoundCue`引用存储在蓝图中以便于更新。

现在，转到`MyHUD.cpp`并在`MouseClicked`函数中的`CastSpell`调用之后添加以下行：

```cpp
        UGameplayStatics::PlaySound2D(this, audioCue);
```

这将实际播放声音。确保在该文件中包含`#include "Kismet/GameplayStatics.h"`才能正常工作。对于这种情况，因为它在玩家附近每当您施放它时，2D 声音就可以了。如果您希望环境中的事物（如怪物）发出自己的声音，您将需要研究 3D 声音。UE4 将让您做到这一点！

现在，返回编辑器并编译所有内容，然后返回 HUD 蓝图。您需要将创建的`SoundCue`添加到蓝图中。

您可以从下拉列表中选择它，并像这样搜索它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0e38e675-aeb7-418a-b880-9cc392463579.png)

现在，保存、编译并运行游戏。四处奔跑，直到您捡起了一个暴风雪咒语并按*I*打开库存。点击暴风雪咒语。您不仅应该看到咒语施放，还应该听到它！

# 摘要

现在，您已经深入了解了如何使用 UMG 创建用户界面，以及如何添加音频以进一步增强您的体验！还有很多工作要做，但请考虑练习！

我们已经完成了这部分的代码，但书还没有完成。接下来，我们将看看如何将我们所拥有的内容在虚拟现实中查看！我会给你一些建议，然后我们将以 UE4 中的一些其他高级功能概述结束。


# 第十五章：虚拟现实及更多内容

除非你一直住在山洞里，你可能已经听说过虚拟现实（VR）。VR 是目前游戏界最热门的趋势之一，还有增强现实（AR），这将在本章后面进行介绍。由于诸如超便宜的谷歌 Cardboard 和类似设备的创新，让你可以在最新的智能手机上查看基本的 VR，所以很容易获得 VR 技术的访问权限。

无论你只有一个谷歌 Cardboard，还是你有一个更高端的设备，比如 Oculus Rift 或 HTC VIVE，UE4 都可以轻松为 VR 编程。当然，如果你有 PlayStation VR，你需要成为索尼的官方开发者才能为其编程（就像为 PlayStation 编程其他内容一样），所以除非你在一家正在开发 PSVR 标题的公司工作，否则你可能无法做到这一点。

在这里，你将获得关于 VR 和 UE4 的概述，这应该可以帮助你入门。以下是我们将要涵盖的内容：

+   为 VR 做好准备

+   使用 VR 预览和 VR 模式

+   VR 中的控制

+   VR 开发的技巧

我还将介绍 UE4 的一些更高级的功能。我们将首先看看目前的另一个热门技术 AR，然后转向其他技术。以下是我们将要涵盖的内容：

+   增强现实

+   过程式编程

+   使用插件和附加组件扩展功能

+   移动，游戏机和其他平台

# 为 VR 做好准备

现在是一个激动人心的时刻，开始进行 VR 开发。也许你正在尝试进入最新的热门技术。或者，就像我一样，你在威廉·吉布森、尼尔·斯蒂芬森、威尔海尔米娜·贝尔德和布鲁斯·贝思克等作家的赛博朋克书籍中读到 VR 几十年，现在它终于出现了。无论哪种情况，以下是你可以为进入 VR 编程之旅做好准备的方法。

要开始使用 Oculus Rift 或 HTC Vive 进行 VR，首先你需要一台 VR-ready 的电脑。Oculus 在他们的网站上有一个免费的程序可以下载[`ocul.us/compat-tool`](https://ocul.us/compat-tool)，或者去他们的支持页面，它会告诉你是否有图形卡的问题。

即使你有一台最新的电脑，除非你专门购买了一个标记为 VR-ready 的电脑，你很可能需要一张新的显卡。VR 需要极高的图形性能，因此需要一张相当高端（通常也相当昂贵）的显卡。

当然，如果你只想在手机上进行 VR，你可能可以不用它，但你将不得不在手机上进行所有测试，并且无法使用 UE4 的许多很酷的功能，比如 VR 编辑。

一旦你有一台可以处理的电脑，你可能会想要购买 Oculus Rift 或 HTC Vive（或者两者都有，如果你真的很认真并且有足够的钱投入其中，因为两者都不便宜）。无论你选择哪种设备，都会在设置过程中安装你所需的所有驱动程序。

然后，进入 UE4，转到编辑|插件，并确保你拥有你所拥有设备的插件（你可以搜索它们）。根据你的 VR 硬件，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/566d5501-f7d1-476d-94bd-bd88596fd6df.png)

另外，请确保你的 VR 软件正在运行（当你打开 UE4 时，它可能会自动启动，这取决于你的 VR 硬件）。

# 使用 VR 预览和 VR 模式

如果你想在 VR 中查看某些内容，好消息是你不需要编写任何新内容！只需进入现有项目，点击播放按钮旁边的箭头，然后选择 VR 预览：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4c5602ad-8138-4d8f-bdfd-3f4299a861c1.png)

现在，只需戴上你的 VR 头盔，你就可以在 VR 中看到游戏了！

一旦你运行游戏，你就可以看到游戏世界。你无法四处移动（在 VR 中看不到键盘或鼠标），但你可以转动头部四处观看。

如果你容易晕动病，一定要非常小心。这在 VR 中是一个严重的问题，尽管有方法可以减轻游戏中的影响，我们稍后会谈到。在你习惯了它并知道它对你的影响之前，你可能不想在 VR 模式下待太久。

UE4 还有另一个工具可以帮助你，那就是 VR 模式。这允许你实际在 VR 中查看和编辑游戏，这样你就可以在进行更改时看到它们的效果。这可能非常有帮助，因为许多东西在 VR 中看起来与非 VR 游戏中不一样。

要激活 VR 模式，可以在工具栏中点击 VR 模式，或者按下*Alt* + *V*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/35549f17-a3f4-4eab-9206-20c89a971d69.png)

你可以四处张望，在 VR 模式下，你将能够使用你的运动控制器

在游戏中，你可能想在开始之前查找你需要的控制方式。

第一次进入 VR 模式。在 Unreal 网站上有关 VR 模式和你可以在其中使用的控制的详细说明：[`docs.unrealengine.com/en-us/Engine/Editor/VR`](https://docs.unrealengine.com/en-us/Engine/Editor/VR)。

如果你想进一步，通过为特定的 VR 系统编程，比如 Oculus Rift、Vive、Steam VR 或其他系统，Unreal 网站上有许多不同 VR 系统的详细说明。你可以在这里找到它们：[`docs.unrealengine.com/en-us/Platforms/VR`](https://docs.unrealengine.com/en-us/Platforms/VR)。

# VR 中的控制

你可能会注意到，在 VR 模式下，通常的控制方式不起作用。你甚至看不到戴着 VR 头显的键盘和鼠标，这使得使用它们非常困难。幸运的是，高端设备有自己的控制器可用，UE4 有一个运动控制器组件，你可以添加到你的玩家角色中，这样你就可以用它指向东西，而不是用鼠标。

如果你从一开始就知道你的目标是 VR，UE4 有专门针对 VR 的类和模板可供使用，这将自动添加一些你需要的功能。还有一个非常有用的 VR 扩展插件，如果你不是一个庞大的开发团队，你真的应该考虑一下。你可以在这里找到它：[`forums.unrealengine.com/development-discussion/vr-ar-development/89050-vr-expansion-plugin`](https://forums.unrealengine.com/development-discussion/vr-ar-development/89050-vr-expansion-plugin)

在 VR 中，用户界面非常棘手，许多人仍在努力找出最佳的方法。你最好的选择可能是玩很多现有的游戏，看看你认为哪种方式最适合你。而且一定要尽可能多地进行实验，因为这是了解什么方法有效的最佳方式！

# VR 开发的一些建议

VR 是一项新的令人兴奋的技术。人们仍在摸索有效的方法，因此有很多的实验空间，也有很多实验正在进行。但你仍然需要牢记一些最佳实践，因为你不希望玩你的游戏的人有糟糕的体验，甚至在玩你的游戏时感到恶心。如果他们这样做了，他们可能不会再玩这个游戏，并且不太可能购买你的下一个游戏。所以，你希望每个人的体验都是好的。

VR 最大的问题是模拟晕动病（或晕动病）。有些人受到的影响比其他人更大，但如果你不小心，即使平时不容易晕动病的人也会有问题。因此，非常重要要小心。而且一定要让其他人测试你的游戏，因为虽然你可能习惯了，但这并不意味着其他人不会有麻烦。

最重要的考虑之一是保持非常高的帧率。不同的设备对于最低帧率有不同的建议，如果低于这些帧率，人们可能会开始出现问题。

总的来说，保持尽可能高的质量非常重要。任何看起来虚假或糟糕的东西都可能使人感到不适，并引起晕动病。因此，如果您尝试实现的任何效果看起来不如您预期的那样，可以尝试做其他事情。

您可能会注意到许多 VR 游戏在游戏中几乎不让玩家移动，或者让他们坐在移动的车辆中。这是避免模拟晕动病的另一种方式。移动是最大的问题，特别是垂直移动，比如跳跃，或者通过控制器旋转而不是只转动头部。基本上，您的大脑认为您在移动，但您的身体得到了矛盾的信息，因为它没有感受到移动。如果您认为自己坐在车上，您的身体就不会期望感受到移动，所以这就是为什么它似乎效果更好。尽管如此，如果玩家在玩游戏时站着，他们可能会遇到更少的问题。

关于 VR 和最佳实践的信息在网上有很多。Unreal 网站上有一篇关于最佳实践的页面，其中包含一些非常好的 UE4 特定信息。我建议在开始项目之前先阅读一遍，因为从一开始就牢记最佳实践比在项目结束时发现一些事情不起作用或效果不好要好得多。

正如我之前所说，让人们来测试它非常重要。VR 技术是如此新颖

您需要确保它能够尽可能地适用于更多的人。

# AR

AR 与 VR 类似，只是在这种情况下，您看到的是放置在真实世界中的虚拟物体（通过摄像头查看）。这可以通过头戴式设备实现，例如微软的 HoloLens 或 Magic Leap。但由于这些设备都是新的，目前只能作为面向开发人员的昂贵设备，因此您主要会通过移动设备看到 AR。

移动设备上流行的 AR 游戏包括 Pokemon Go，您可以在其中捕捉 Pokemon 并在您周围的世界中查看它们。在 AR 模式下，您必须四处张望，直到找到 Pokemon（它会显示需要转向的方向）并捕捉它。您甚至可以拍照，这会产生一些有趣的图像。它的前身 Ingress 让您在游戏中去真实世界的地点，但 Pokemon Go 真的扩展了这一点。

由于该游戏的成功，移动 AR 游戏现在非常受欢迎。由于您正在处理无法控制的现实世界物体，这可能涉及一些复杂的计算机视觉，但幸运的是，UE4 具有内置功能来帮助您。

UE4 支持的两种主要移动 AR 系统是 iOS 的 ARKit 和 Android 的 ARCore。您可以在 Unreal 网站上找到有关 AR 编程和每种类型的先决条件的更详细信息。要启动任何一个，您都需要使用手持 AR 模板创建一个新项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/18e0180d-0637-4b27-b536-badb415b48eb.png)

如前面的屏幕截图所示，您的设置应该是移动/平板电脑，可扩展的 3D 或 2D，没有初始内容。创建项目后，您可以将手机连接到计算机，如果完全设置好（取决于您的手机，您可能需要在计算机上安装软件才能看到它），当您单击“启动”旁边的箭头时，您应该会在设备下看到它。否则，您仍然可以在播放下使用移动预览 ES2（PIE）。

虽然您可能不会很快为 Magic Leap 编程，但 Unreal 网站上提供了早期访问文档：[`docs.unrealengine.com/en-us/Platforms/AR/MagicLeap`](https://docs.unrealengine.com/en-us/Platforms/AR/MagicLeap)。

# 程序化编程

最近，游戏中的过程式编程非常受欢迎。如果您玩过《Minecraft》、《无人之境》或《孢子》，您就玩过过程式游戏。过程游戏的历史可以追溯到几十年前，到旧的基于文本的游戏，如 Moria、Angband 和 NetHack。类似 Rogue 的游戏（以最初的 Rogue 命名）仍然是一种使用过程技术生成随机关卡的流行游戏类型，因此每次玩都会得到完全不同的游戏。因此，过程式编程增加了难以通过手工建造关卡获得的可重复性。

过程式编程可以让您通过代码中的规则和算法创建游戏的部分，无论是环境、关卡，甚至是音频。基本上，代码会为您设置每一个细节，而不是由人类设置。

结果可能是不可预测的，特别是在 3D 中，这比在 2D 文本字符中绘制房间和路径要复杂得多。因此，有时，过程级别是提前创建的，以便设计人员可以在将它们添加到游戏之前选择他们喜欢的级别。

有许多不同的技术可以帮助进行过程式编程。其中之一是使用**体素**，它可以让您以一种简单的方式引用 3D 空间中的点，基于它们与其他体素的关系。体素已经在许多项目中使用，包括现在已经停止运营的游戏 Landmark（我曾参与其中），并且原本计划在现在取消的 EverQuest Next 中使用。UE4 通过插件支持体素，例如 Voxel Plugin（[`voxelplugin.com/`](https://voxelplugin.com/)）。

过程式编程也可以用于音乐。有一些项目已经对特定类型的音乐进行了神经网络训练，并以类似风格创作了一些非常出色的音乐。您还可以根据游戏中发生的情况修改播放的音乐。Spore 在这方面做了一些非常令人印象深刻的事情。

如果您有兴趣了解更多信息，请查找 David Cope，他是一位研究人员，已经撰写了几本关于这个主题的书。或者，您可以查看 Unreal 的开发人员在这里对过程音频所做的工作：[`proceduralaudionow.com/aaron-mcleran-and-dan-reynolds-procedural-audio-in-the-new-unreal-audio-engine/`](http://proceduralaudionow.com/aaron-mcleran-and-dan-reynolds-procedural-audio-in-the-new-unreal-audio-engine/)。您还可以找到 UE4 的附加组件，例如我过去使用过的过程 MIDI 插件。

# 通过插件和附加组件扩展功能

我们已经看到了一些插件和其他附加组件的示例，以及它们如何可以扩展 UE4，从为您特定的 VR 头显添加 VR 功能到添加支持体素或过程音乐功能。但是还有很多其他可用的插件。

对于插件，您可以转到编辑|插件，并按类别查看所有已经可用的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e98ff7d3-2450-4583-bf19-640225a53e22.png)

这些是内置插件。

但是，如果您想了解更多信息，您需要查看 Epic Games Launcher 中的市场：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a651bb48-ffdc-4cd3-8032-fab9709bb77e.png)

虽然您将看到的大部分是图形和模型，但有很多可用的功能可以添加。其中一些是免费的，而另一些则需要付费。例如，这是对过程式的搜索：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ca744b78-3900-4962-947e-fcff46050c11.png)

UE4 是一个非常受欢迎的游戏引擎，所以如果有任何您需要的东西，很有可能其他人已经为其开发了附加组件。您还可以在互联网上找到许多项目，其中许多是开源的，开发人员乐意帮助您实施。但是这可能需要额外的工作来实施，并且您需要小心并确切知道您正在下载和安装的内容。

# 移动、控制台和其他平台

正如我们提到 AR 时所看到的，你可以在 UE4 中为移动设备开发，并在计算机或手机上预览你的游戏。UE4 的一个很棒的特点是它支持许多不同的平台。

许多 AAA 游戏工作室使用 UE4，因此它绝对支持所有主要游戏主机（Xbox One、PS4、Switch，甚至包括 3DS 和 Vita 等移动主机）。对于这些主机的技巧是，通常你不能只是为它们开发游戏——你需要成为授权开发者，并且通常需要在 DevKit 上花费大量资金（DevKit 是专门用于开发的主机版本，可以让你在主机上进行调试）。

幸运的是，随着主机独立游戏市场的发展，现在开发者获取权限的门槛比过去低得多。但在你开始研究这个之前，你可能还需要更多的经验和已发布的游戏标题。

与此同时，你的游戏还有许多不同的选择和平台。一旦你为一个平台开发了游戏，将这个游戏移植到另一个平台就会变得更容易（UE4 使这一切变得非常容易！）。

主要的区别将是控制方式，因为你可能会使用触摸屏、控制器、运动控制器（在 VR 中）或键盘和鼠标。每种方式都有不同的要求，会稍微改变游戏玩法。但只要你从一开始就记住你要瞄准的平台，你就能够规划你的游戏，使其适用于所有平台。

# 总结

在这本书中，我们涵盖了很多内容，但现在我们已经到了尽头。我们学习了 C++的基础知识，并在 UE4 中创建了一个非常简单的游戏，包括一些基本的人工智能、部分 UI 包括库存，以及使用粒子系统施放法术的能力。我们还了解了 VR、AR 和其他新兴技术，UE4 可以帮助你应对这些技术。

你现在已经学到了足够的知识来开始制作自己的游戏。如果你需要更多关于特定主题的信息，还有许多其他高级书籍和网站可以供你参考，但是现在你应该对你正在研究的内容有了更清晰的认识。

希望你们喜欢这次的旅程。祝你们未来的项目好运！
