# 使用 HTML5 和 JavaScript 开发 Windows 商店应用（二）

> 原文：[`zh.annas-archive.org/md5/8F13EC8AC7BDB8535E7218C5DDB48475`](https://zh.annas-archive.org/md5/8F13EC8AC7BDB8535E7218C5DDB48475)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使应用具有响应性

在本章中，我们将学习应用程序可能存在的不同视图状态以及我们如何使应用程序适应这些视图状态以及各种外形因素和显示尺寸。Windows 8 针对不同的平台，并在具有不同尺寸的各种设备上运行，从大型高清显示器和大笔记本电脑到 10 英寸宽屏平板电脑和 4 英寸宽智能手机。因此，为了遵守 Windows 8 用户体验指南，当用户在这些不同设备上查看应用程序时，他们翻转屏幕以在纵向和横向之间切换，他们放大或缩小，或者应用程序在各种视图状态之间切换，应用程序应该保持相同的视觉感受和功能。应用程序应提供流畅灵活的布局，使其用户界面能够优雅地重新流动并适应这些变化。

在本章中，我们将学习如何使应用程序具有响应性，以便它能够处理屏幕大小和视图状态的变化，并响应放大和缩小。我们首先介绍应用视图状态的概念，然后学习如何使用 CSS 和 JavaScript 处理视图状态的变化。最后，我们将学习有关应用中的语义缩放的概念。

# 介绍应用视图状态

视图状态代表了用户可以选择以显示应用程序的方式。有四种可能的应用程序视图状态；它们在这里列出，每个的描述如下：

+   **全屏横向视图**：使用这种模式，应用会填满整个屏幕，这是所有 Windows 商店应用的默认状态。![介绍应用视图状态](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_01.jpg)

+   **全屏纵向视图**：使用这种模式，应用会再次填满整个屏幕，但这次是纵向的。![介绍应用视图状态](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_02.jpg)

+   **吸附视图**：使用这种模式，应用程序填满整个屏幕的狭窄区域（320px），位于屏幕的左侧或右侧；因此，屏幕将同时显示两个应用程序。![介绍应用视图状态](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_03.jpg)

+   **填充视图**：使用这种模式，应用程序会与一个“吸附”的应用程序并排运行，并填充屏幕上未被该应用程序占据的区域；因此，屏幕将再次同时显示两个应用程序。![介绍应用视图状态](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_04.jpg)

如果我们观察前面的图片，将会看到两个应用程序并排运行；一个处于“吸附”视图，另一个处于填充视图。用户通过将另一个应用程序（天气应用）或窗口拖到屏幕上，将一个应用程序（必应新闻）“吸附”到一边。第二个应用程序将成为当前运行的应用程序，并具有填充视图状态，而之前的全屏应用程序将被吸附到一边。现在，用户可以通过按下 Windows 键和句点（*.*）来切换这些应用程序的视图状态，在“吸附”和“填充”之间切换。

应用程序“吸附”后，其大小会被调整为 320 像素宽，这使得它可以与其他应用程序共享屏幕，从而实现同时显示两个应用程序，使用户能够多任务操作。

### 注意

只能在水平分辨率大于或等于 1366 相对像素的显示器上拥有吸附和填充视图。这是因为吸附视图将占用屏幕两侧的 320 像素。所以，剩下的 1046 像素将分配给分隔符（22 像素）和填充视图中的应用，填充视图中的应用必须始终具有 1024 相对像素或更大的水平分辨率。因此，1366 x 768 的大小被认为是参考点。

应用总是可以被手动或自动吸附，手动吸附是指用户将其吸附到屏幕的任一侧，自动吸附是指响应另一个应用被拖入全屏模式。因此，你不能阻止应用进入吸附视图。由于用户可以将每个应用吸附起来，如果你没有为应用的吸附视图状态设计，系统将会无论如何调整你的应用大小，可能会裁剪内容，使应用的外观变得混乱。

另一方面，旋转不是强制的，你可以选择让应用支持或不支持。所以，如果你的应用不支持纵向旋转，用户把设备翻转过来，你的应用也不会有任何变化；也就是说，应用不会随着新设备的旋转而旋转。话说回来，当然，为了拥有一个满意的用户，强烈建议支持旋转，毕竟，用户才是应用的目标。

当你点击并打开`package_appmanifest`文件时，你可以设置应用程序 UI 的选项；这些选项之一是**支持的旋转**，这是一个可选设置，表示应用的朝向偏好，有四个值：**横向**、**纵向**、**横向翻转**和**纵向翻转**，如下面的屏幕截图所示：

![介绍应用视图状态](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_05.jpg)

# 处理视图状态

为了适应吸附视图，有两种方法：使用 CSS3 媒体查询或使用 JavaScript 布局变化事件，有时两者都需要。我们用媒体查询来处理可以通过 CSS 样式的元素大小、元素显示（内联、块）和元素可见性来解决的布局变化。通过使用 CSS 媒体查询，可以非常容易地定义不同的样式，这些样式将根据应用的视图状态应用。你可以为每个视图状态使用一个单独的媒体查询，或者通过结合多个媒体查询将相同的样式集应用于多个视图状态。下面的代码展示了匹配不同视图状态的媒体查询的语法；第一个匹配吸附视图状态，第二个匹配视图状态的组合。

```js
@media screen and (-ms-view-state: snapped) {
}
@media screen and (-ms-view-state: fullscreen-landscape), 
  screen and (-ms-view-state: fullscreen-portrait), 
  screen and (-ms-view-state: filled) {
}
```

所以，如果我们有一组类和其他选择器在 UI 中指定样式，我们可以用每个媒体查询改变这些样式。例如，下面的代码显示了定义为 CSS 网格的两列的页面包装`div`；一旦进入`media`查询中的视图状态`snapped`，它就变成了单列布局：

```js
.appGrid {
display: -ms-grid;
-ms-grid-columns: 120px 1fr; /* 2 columns */
-ms-grid-rows: 120px 1fr;
width: 100vw;
height: 100vh;
margin-left: 120px;
}

@media (-ms-view-state: snapped) {
 /*styles that will be applied when in snapped view state*/
  .appGrid {
    display: -ms-grid;-ms-grid-columns: 1fr; /* 1 column fills the available space */
    -ms-grid-rows: 120px 1fr;
    width: 100%; height: 100%;
    margin-left: 20px; /* margin decreased from 120 to 20 px*/
}
}
```

前述代码中为宽度值和高度值设置的单位`vw`和`vh`分别代表视图宽度和视图高度，它们指定了应用占用的完整宽度和高度分辨率。

前面的代码示例展示了 CSS 网格的使用，这是实现流体和适应性 UI 布局的一种非常方便的方法，该布局可以处理视图状态的变化。这是因为网格会自动扩展以分配内容和填充可用空间，并且允许你仅通过 CSS 来指定其内部的元素位置，而与它们在 HTML 标记中的指定顺序无关。这使得指定不同屏幕大小或不同视图状态下的元素不同排列变得容易。

处理窗口大小变化的第二种方法是使用 JavaScript 事件，当需要处理行为和属性的变化时，这是最好的选择，这些变化不能用 CSS 样式来指定，比如`WinJS`列表视图控制器的滚动方向和控件变化（例如，将水平按钮列表更改为下拉列表控件）。如果我们以列表视图控制器为例，它使用网格模式以填充容器元素和可用空间的方式垂直和水平显示项目，当应用处于横屏、竖屏或填满状态。但是当应用被 snapped 时，列表视图控制器应该重新排列并仅垂直显示项目，以避免使用列表模式进行水平滚动。列表和网格模式不能在 CSS 中指定，因为它们是在`data-win-options`属性中定义的，如下所示：

```js
data-win-options="{ layout: {type: WinJS.UI.GridLayout} }
```

这里就是 JavaScript 事件发挥作用的地方，通过注册一个窗口大小变化事件的监听器，我们可以创建特定于视图的布局，该监听器查询由 WinRT 提供的`ViewManagement.ApplicationView.value`属性，直接查询应用的当前视图状态。下面的示例展示了窗口大小变化事件的监听器的代码：

```js
window.addEventListener("resize", function (e) {
   var viewState = Windows.UI.ViewManagement.ApplicationView.value;
   var snapped = Windows.UI.ViewManagement.ApplicationViewState.snapped;

   if (viewState === snapped) {
        that.listView.layout = new WinJS.UI.ListLayout();    
}
   else if (viewState!== snapped)
    {        
     that.listView.layout = new WinJS.UI.GridLayout(); 
}
});
```

### 注意

列表视图（ListView）和网格（Grid）是灵活的控制组件，它们能以最小的开发工作提供对用户界面的最大控制，因为两者都支持内置的灵活布局，并能自动安排和分布其内容。你应尽可能地尝试使用它们。

# 理解语义缩放

根据 Windows Store 应用的 UX 指南，内容是水平流动的，用户可以通过鼠标或触摸，从左向右或从右向左滚动内容（在某些语言中）。但想象一个场景，你有一个包含大量数据的内容，比如电话簿或者新闻文章列表，在这种情况下，滚动内容以导航变得对用户来说很繁琐。在电话簿应用中，联系人按字母顺序组织，用户必须滚动到最后才能找到一个以字母 z 开头的联系人；也就是说，在列表的末尾，而用户可以缩放到只列出字母的视图级别，并找到那个字母下具体的一个联系人。

同样的，对于一个按类别组织项目/文章的目录应用或新闻应用也适用；不必长时间滚动滚动条以达到所需内容，特别是那些恰巧位于列表末尾的类别，用户可以缩放到类别级别。下面的屏幕快照分别显示了 Windows 8 上的 People 应用和 Bing News 应用的“缩放出”视图：

![理解语义缩放](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_06.jpg)

以下是 Bing News 应用在 Windows 8 中的语义缩放视图：

![理解语义缩放](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_06_07.jpg)

### 注意

语义缩放交互是触摸优化的，因此可以通过捏合和拉伸手势来执行。另外，用户可以通过鼠标滚轮滚动或按住*Ctrl*键并按加号（+）或减号（-）键使用键盘来进行缩放。

这种技术称为**语义缩放**，Windows Store 应用使用它来在单个视图中呈现大量相关内容的两个详细级别，并提供更快的导航。这种技术使用同一内容的两个缩放级别来组织数据：一个“缩放进”的详细视图，这是应用显示的默认模式，以及一个“缩放出”视图，它根据某些元数据将项目分组显示。

为了给应用提供语义缩放功能，我们将需要定义这两种语义级别的模式。幸运的是，`WinJS.UI`为我们提供了使用`WinJS.UI.SemanticZoom`对象的最佳方式，该对象将渲染一个语义缩放控件，使用户能够缩放同一内容的两个不同的视图。缩放控件使用两个子控件来渲染这两个不同的视图；第一个子控件将提供缩放出视图，另一个将提供缩放进视图或相反。如以下代码所示，声明语义缩放控件在标记或脚本中非常简单：

在 HTML 中：

```js
<div data-win-control="WinJS.UI.SemanticZoom">
  <!-- zoomed-in view -->
  <!-- zoomed-out view -->
</div>
```

在 JavaScript 中：

```js
var object = new WinJS.UI.SemanticZoom(element, options);
```

定义了`SemanticZoom`控件之后，让我们向其中添加两个子控件，以容纳两个视图。

请注意，子控件应通过实现`IZoomableView`接口来支持语义缩放功能，这样控件就可以作为`SemanticZoom`控件的放大或缩小视图暴露出来。目前，Windows 库 for JavaScript 提供的唯一支持此功能的控件是 ListView 控件。因此，两个子控件将是两个 ListView 控件的实例，如下面的代码所示：

```js
<!-- zoomed-in view -->
  <div data-win-control="WinJS.UI.SemanticZoom">
    <div id="zoomedInView" data-win-control="WinJS.UI.ListView" >
    </div>

<!-- zoomed-out view -->
    <div id="zoomedOutView" data-win-control="WinJS.UI.ListView">
    </div>
  </div>
```

现在我们需要一些数据来在这些两个视图中显示。你还记得我们在第四章《使用 JavaScript 开发应用程序》中创建的数据数组吗？当我们开始介绍 ListView 控件时。好吧，让我们再次使用它并添加更多名称。随意添加你喜欢的任何内容；以下是为了参考再次给出的数据：

```js
var dataArray = [
    { name: "John Doe", country: "England", age: "28" },
    { name: "Jane Doe", country: "England", age: "20" },
    { name: "Mark Wallace", country: "USA", age: "34" },
    { name: "Rami Rain", country: "Lebanon", age: "18" },
    { name: "Ryan Air", country: "England", age: "18" },
    { name: "Foster Mane", country: "England", age: "18" },
    { name: "Doe Jane", country: "England", age: "18" },
    { name: "Bow Arrow", country: "England", age: "18" },
    { name: "Amy Sparrow", country: "Italy", age: "18" },
    { name: "Jean Trops", country: "France", age: "56" }

    ];
//create a list object from the array    
var bindingList = new WinJS.Binding.List(dataArray);
```

现在，我们需要创建一个包含分组信息的此数据源的版本。我们可以使用`createGrouped`方法来实现，该方法允许我们创建列表的组版本。我们在上一章学习了类似的方法，`createdFiltered`和`createSorted`。`createGrouped`方法在列表上创建一个分组投影，并接受以下三个函数参数：

+   `getGroupKey`：此方法接收列表中的一个项目，并返回该项目所属的分组键。

+   `getGroupData`：此方法接收列表中的一个项目，并返回代表该项目所属分组的对象的数据。

+   `compareGroups`：如果第一个组的价值小于第二个组，则返回负值；如果两个组的价值相同，则返回零；如果第一个组的价值大于第二个组，则返回正值。

以下代码将创建一个包含我们`bindingList`对象的组版本，该对象使用每个项目名称的第一个字母来定义元数据：

```js
// Sort the group
function compareGroups(leftKey, rightKey) {
return leftKey.charCodeAt(0) - rightKey.charCodeAt(0);   
}

// Get the group key that an item belongs to.
function getGroupKey(dataItem) {
return dataItem.name.toUpperCase().charAt(0);   
}

// Get a title for a group
function getGroupData(dataItem) {
return {
    title: dataItem.name.toUpperCase().charAt(0);
}; 
}
// Create the groups for the ListView from the item data and the grouping functions
    var groupedItemsList = bindingList.createGrouped(getGroupKey, getGroupData, compareGroups);
```

为了将分组数据绑定到放大视图的`ListView`控件上，我们将它的`itemDataSource`属性设置为`groupedItemsList.groups.dataSource`，它包含分组信息，并将放大视图的`ListView`控件的`itemDataSource`属性设置为`groupedItemsList.dataSource`，它包含要显示的项目，如下所示：

```js
var zoomedInView = document.getElementById("zoomedOutView").winControl;
var zoomedOutView = document.getElementById("zoomedOutView").winControl;

zoomedInView.itemDataSource = groupedItemsList.dataSource;

zoomedOutView.itemDataSource = groupedItemsList.groups.dataSource;
```

有了这些知识，你可以按照我们在第四章《使用 JavaScript 开发应用程序》中学到的内容，为视图创建模板，以便更好地展示数据。

# 总结

在本章中，我们介绍了用户可以选择显示应用程序的不同视图状态。然后，我们学习了如何通过 CSS 和媒体查询或使用检测窗口大小的 JavaScript 事件处理程序来适应这些视图状态的变化。

最后，我们学习了语义缩放以及如何轻松地将此功能集成到应用程序中。

在下一章节中，我们将学习关于动态磁贴的知识，如何向应用图标添加磁贴和徽章，以及如何使磁贴具有动态效果，并从应用向用户发送通知。


# 第七章： 用磁贴和通知让应用上线

Windows 8 的**开始**屏幕上闪烁着磁贴，这些磁贴不仅仅是与特定应用相关的大图标。在本章中，我们将学习应用磁贴的概念、磁贴类型以及每个磁贴的用途。此外，我们还将了解如何为应用定义这些磁贴。然后，我们将介绍通知以及不同的通知方法，并编写代码创建并实现应用的简单通知。

# 介绍磁贴、徽章和通知

Windows 8 应用的独特特性之一就是磁贴的概念。而且，正是这些磁贴使得 Windows 8 应用与众不同。应用用色彩的盛宴、标志和信息装饰**开始**屏幕。磁贴是应用在**开始**屏幕上的图形表示。另外，应用磁贴是应用的启动点；点击磁贴将启动应用程序，这与我们桌面上的 Windows 应用快捷方式类似。

以下是一张来自全新安装后的**开始**屏幕的截图，显示了几块应用磁贴：

![介绍磁贴、徽章和通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_01.jpg)

每个已安装的应用都有一个默认磁贴，在安装后立即添加到**开始**屏幕上。这个默认磁贴有一个默认的标志图像，代表应用标志或任何其他品牌来识别应用。默认情况下，磁贴上显示静态内容，包含指定应用名称的文本和代表标志的图像。之前的截图展示了 Windows 8**开始**屏幕上基本应用磁贴的例子。你可以在之前的截图中注意到磁贴有两种尺寸：正方形（150x150）px 和矩形（310x150）px。按照 Windows 8 的命名约定，这两种尺寸分别是正方形和宽磁贴。正如你所看到的，这两种尺寸都显示文本和图像以及一个通知徽章来显示某种状态；我们稍后会看到徽章是什么。所有应用都默认支持正方形磁贴；支持宽磁贴是可选的。如果一个应用没有为默认磁贴提供宽标志图像，用户将无法从**开始**屏幕菜单中把应用磁贴放大。另外，如果应用包括了宽标志图像，Windows 8 会默认以宽格式显示磁贴。

用户可以通过切换宽磁贴和正方形磁贴来个性化他们的**开始**屏幕，只要应用磁贴包含两个版本。如果一个应用没有包含宽标志，用户将无法把磁贴放大。用户可以右键点击应用，**开始**屏幕应用栏将出现。从那里，用户可以点击**放大**选项来更改磁贴的大小。下面的截图展示了用户如何将**商店**应用的磁贴从正方形更改为宽磁贴。

![介绍磁贴、徽章和通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_02.jpg)

Windows 8 只要没有通知要显示，就会显示默认磁贴图像，当通知到期时，或者当用户关闭实时通知时，它会恢复到默认图像。磁贴的大小和其他图像（如**小标志**，显示在搜索结果旁边应用名称旁边，和**商店标志**，显示在 Windows 商店上）都包含在应用包中，并在应用清单中的**应用 UI**面板的**磁贴图像和标志**设置下指定。在清单编辑器中，我们可以为磁贴指定背景颜色，显示在磁贴上的文本颜色，以及应用的简称；更重要的是，我们可以浏览（并选择）不同磁贴大小的图片，如下面的屏幕截图所示：

![介绍磁贴、徽章和通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_03.jpg)

如果你检查你在前几章中创建的**开始**屏幕上的`test`应用，你会看到应用磁贴显示 150x150 像素默认标志的图片；它填满了方形磁贴，无法放大。尝试选择一个**宽标志**来运行应用，然后将应用磁贴放大以查看更改。磁贴的内容是基于 Windows 提供的一套模板在 XML 中定义的，以保持 Windows 8 的外观和感觉。磁贴的内容可以在这些模板中定义，通过提供相应的文本或图片，或者两者都有。磁贴还显示徽标或简称。

除了默认磁贴外，还有辅助磁贴，它允许用户在**开始**屏幕上显示特定应用的内容。辅助磁贴是通过应用栏中的**固定到开始**选项创建的，用户可以选择将应用的特定位置或内容固定到**开始**屏幕上。当从辅助磁贴启动应用时，用户会被引导到应用中的特定位置。例如，我们可以将**人**应用中的一个联系人固定下来，辅助磁贴会个性化**开始**屏幕，显示该联系人的更新信息；或者，也许我们可以固定一个城市的**天气**。辅助磁贴允许用户个性化对他们重要的**开始**屏幕信息。下面的屏幕截图显示了天气应用的两个磁贴；左边是显示当前位置**天气**的默认磁贴，右边是显示伦敦市天气的固定内容的辅助磁贴：

![介绍磁贴、徽章和通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_04.jpg)

应用图块可以在应用未运行时传达与应用相关的状态信息，使用一个通知徽章来表达总结或状态信息，数值在 1 到 99 之间（数值大于 99 将显示为 99+）或者它可以是一组 Windows 提供的图像符号，称为**图标**。徽章出现在图块的右下角，并且可以同时在正方形和宽图块上展示。

应用的另一个与 UI 相关的概念是提示通知；这是一个出现在屏幕右上角的弹出通知。提示通知允许当应用不在屏幕上运行时，即使用户正在使用另一个应用，或者当在桌面而不是 Windows 8 的**开始**屏幕上时，应用向用户发送信息。

### 提示

需要注意的是，应用图块不应作为广告表面使用。根据 Windows 商店应用的条款，在大多数情况下，使用图块来展示广告是不允许的。

## 使用动态图块

应用图块是您应用的核心部分；很可能是它是最常被看到的部分。这就是为什么您应该利用这个图块来吸引用户注意力，并通过实现一个动态图块让他们回到应用中。动态图块是吸引用户到您应用的理想方式之一，通过展示显示应用内部最佳情况的的重要信息。例如，Windows 8 中的**人**应用有一个动态图块，它会定期间隔更改联系人的图片。

与静态图块显示不同，默认内容通常是一个完整的图块标志图像和指示应用名称的文本，动态图块可以更新默认图块以显示新内容。动态图块可以用来让用户了解他们的联系人，显示事件信息，或显示最新消息。此外，动态图块可以显示应用更新的摘要，例如未读邮件的数量，从而给用户一个启动应用的理由。

# 发送通知

图块、次要图块、锁屏图块和提示可以通过多种类型的通知进行更新。这些通知可以通过本地 API 调用或从运行在云上的某些服务调用生成。此外，有四种不同的通知传递方法可以发送图块和徽章更新以及提示通知。这些方法包括以下内容：

+   **本地**：当应用在屏幕上或后台运行时发送通知，以更新应用图块或徽章，或者弹出一个提示通知。

+   **定时发送**：在已知的时间发送通知，例如，即将到来的约会的提醒。

+   **周期性**：通过定期轮询固定时间间隔从云服务器获取新内容的方式发送通知；例如，每 12 小时更新一次天气。周期性通知与图块和徽章一起工作，但不适用于提示。

+   **推送通知**：它即使应用程序没有运行，也能直接从云服务器向屏幕发送通知。推送通知非常适合于包括实时数据的情况，比如社交网络更新或时间敏感信息，如即时消息或突发新闻。此通知方法可用于磁贴、徽章和弹出式通知。

默认情况下，本地磁贴通知不会过期，但可以给予并且理想情况下应该给予一个过期时间；然而，推送、周期性和计划性通知在提供后三天过期。通过指定一个过期时间，应用程序可以在磁贴在达到过期时间时仍然显示时，从磁贴中删除通知内容。

选择通知方法主要取决于您想要传递的信息以及应用程序的性质和内容。

### 小贴士

请记住，用户可以随时关闭或打开磁贴通知，因此要小心不要因不必要的弹出式通知而让用户感到困扰。

为了实现通知功能并允许应用程序传输弹出式通知，我们必须在清单文件中将应用程序声明为支持弹出式通知。一旦应用程序被声明为支持弹出式通知，它将被添加到**PC**设置中**通知**部分的 app 列表中。下面的屏幕截图显示了如何更改**支持弹出式通知**设置：

![发送通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_05.jpg)

现在让我们编写一些代码来创建一个简单的本地弹出式通知。我们将需要非常频繁地使用`Windows.UI.Notifications`命名空间；因此，为了简化，让我们声明一个命名空间变量，如下所示：

```js
var notifications = Windows.UI.Notifications;
```

接下来，我们需要通过从 Windows 提供的模板中选择一个来提供`ToastTemplateType`；这些模板确保应用程序在弹出式通知中保持预期的 Windows 8 外观和感觉。有文本模板，如：**toastText01**、**toastText02**、**toastText03**、**toastText04**。图像和文本模板有：**toastImageAndText01**、**toastImageAndText02**、**toastImageAndText03**、**toastImageAndText04**。

`WinJS`为这些模板提供 IntelliSense，当我们对通知变量调用`ToastTemplateType`枚举时，这些模板将被列出，如下面的屏幕截图所示：

![发送通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_06.jpg)

在这个例子中，我们将选择`toastText01`，它只包含一个文本字符串，最多跨越三行。如果文本超过三行，它将被截断。然后我们将获取一个 XML 文档的模板内容，如下面的代码所示：

```js
var template = notifications.ToastTemplateType.toastText01;
var templateXML = notifications.ToastNotificationManager.getTemplateContent(template);
```

`templateContent`变量将包含以下 XML 骨架：

```js
<toast>
  <visual>
    <binding template="toastText01">
      <text id="1"> </text>
    </binding>
  </visual>
</toast>
```

接下来我们需要做的是填充这个 XML 模板的内容，因此我们需要检索具有标签名`text`的元素，如下面的代码所示：

```js
var toastTextElements = templateContent.getElementsByTagName("text");
toastTextElements[0].appendChild(templateXML.createTextNode("This is a new toast notification"));
```

然后我们根据刚刚指定的 XML 内容创建弹出式通知，如下所示：

```js
var newToast = new notifications.ToastNotification(templateXML);
```

最后，我们将创建一个`toastNotifier`变量，它将把我们在以下代码中定义的`newToast`通知发送到屏幕：

```js
var toastNotifier = notifications.ToastNotificationManager.createToastNotifier();
toastNotifier.show(newToast);
```

在`WinJS.UI.processAll()`方法上调用`then()`函数时编写要执行的代码；因此，当应用程序启动时，就会出现弹出通知。如果我们现在运行应用程序，屏幕右上角将弹出以下通知：

![发送通知](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_07_07.jpg)

### 提示

请注意，应用于通知的背景颜色是应用程序清单中为应用程序磁贴声明的颜色。

之前的代码允许我们实现一个最小的通知；您可以尝试使用其他的通知模板并比较结果。

# 总结

在本章中，我们介绍了磁贴、徽章和通知的概念，并学习了它们之间的区别以及我们可以使用它们的地方。

我们还学习了如何发送通知，并编写了一个示例代码，实现了向屏幕发送一个非常简单的通知。

在下一章中，我们将学习如何使用 Windows Live 服务来实现用户认证，并允许用户使用他们的电子邮件 ID 登录。


# 第八章．用户登录

一个 Windows 商店应用可以针对登录应用的个人用户进行个性化设置；因此，使得认证过程非常简单是非常重要的。Windows 8 允许用户使用 Microsoft 账户登录他们的设备，从而使开发者更容易为应用用户提供单点登录体验。此外，Windows 8 提供了一个**软件开发工具包**（**SDK**）和一组 API，以便 Windows 商店应用能够使用 Microsoft 账户实现单点登录，并与 Microsoft SkyDrive、Outlook.com 和 Windows Live Messenger 中的信息集成。在本章中，我们将学习关于 Live Connect API 以及如何使用此 API 登录用户并获取用户资料信息。我们将学习如何开始使用 Live Connect 集成应用，并展示一些代码，介绍 Live Connect API 可以执行的一些基本功能。

# 介绍 Live Connect

有很多场景，应用需要认证用户并访问他们的资料信息，从简单地显示带有用户姓名的欢迎信息，到访问他们的资料信息，并为用户提供个性化体验。此外，你可以通过与允许与文档和媒体协作并访问云上文件或与 Outlook 协作处理联系人和日历的产品和服务集成，构建提供强大功能的应用。你的应用需要与 Microsoft 账户集成认证的场景可以总结如下：

+   应用需要用户登录才能运行，例如，一个联系人应用

+   应用可以在用户不登录的情况下运行，但对于登录的用户，它能提供更加个性化的体验；例如，一个天气或新闻应用

+   应用包含一些与 SkyDrive 或 Hotmail 集成的功能，因此需要 Microsoft 账户登录

认证过程以及与 Microsoft 云服务（如 Microsoft SkyDrive 和 Outlook）的集成使用 Live Connect 实现。Live Connect 是一组 API，允许将应用与这些兼容服务集成。这些 API 由 Live SDK 提供，它是开发应用的 Microsoft 软件开发工具包之一。Live Connect API 利用一个开放标准，使你能够专注于实现功能，而不是在学习新概念上花费时间，而你想要做的只是实现由这个新概念引入的功能。例如，你可以使用**开放认证**（**OAuth**）标准与 Facebook 和其他社交网络 API 的认证服务集成，而无需了解这些社交网络 API 内部认证过程的工作原理；更重要的是，你可以使用你熟悉的编程语言进行调用。Live Connect 使用的开放标准包括以下内容：

+   **OAuth 2.0**：这是 OAuth 协议的最新版本，是一个开放标准，用于验证用户的凭据。包括 Live Connect 在内的社交网络 API 已采用 OAuth 作为其认证标准。OAuth 基本上允许用户使用 Live Connect 授权 Web 服务进行认证，而无需将他们的机密登录凭据与应用程序共享。

+   **代表性状态转换（REST）**：这是一种在实现网络服务时流行的架构风格。在 Windows 商店开发中，REST 允许我们通过 Live Connect API 轻松请求用户信息。这个 REST 实现支持标准的 HTTP 方法，如 GET、PUT、POST 和 DELETE。

+   **JSON**：这是**JavaScript 对象表示法**的缩写，是一种用于表示网络服务中信息的轻量级数据交换格式。Live Connect 以 JSON 格式交换用户信息。例如，当函数请求用户个人资料信息时，该信息将以包含`first_name`、`last_name`等字段的响应对象的形式返回。

在 Windows 8 中，用户可以通过使用他们的微软账户（Hotmail、Live 和 Outlook）登录设备，因此，应用程序可以利用这一功能提供单点登录体验。例如，Windows 8 的主要应用程序，如人脉、邮件和信息，以及微软网站，如 Outlook 和 Bing，都可以利用单点登录，所以用户在登录到电脑后不需要再登录这些应用程序和网站；这些过程将由系统代为完成。我们开发的应用程序可以通过实现 Live Connect API 的功能来实现相同的效果，这样如果用户已经登录到设备，他们就可以直接在我们的应用程序中进行认证。

在我们开始使用 Live Connect 功能之前，有两个先决条件：

+   在 Windows 商店注册应用程序

+   在 Windows 商店仪表板中为 Windows 商店应用程序配置 Live Connect 设置

首先，我们需要在 Windows 商店仪表板中注册应用程序，该仪表板可以通过以下链接访问：

[`appdev.microsoft.com/StorePortals/en-us/Home/Index`](https://appdev.microsoft.com/StorePortals/en-us/Home/Index)

登录到商店仪表板；为此你需要微软账户的凭据，然后你会看到以下屏幕：

![介绍 Live Connect](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_01.jpg)

这是您的整个应用列表的主页。同时也是新用户首次看到的屏幕。为了让应用开始使用 Live Connect API，必须对其进行注册并相应地配置其设置。此外，对于要使用 Live Connect 的 Windows Store 应用，它需要有一个包含包名和发布者的包身份，这将唯一标识该应用。要获取包身份，我们需要提交应用；这基本上是为您的应用预留一个名称，添加其描述，并提交认证。在这个阶段，我们不需要将应用提交到 Windows Store 进行认证；我们只需要在 Windows Store 开发者账户中为其输入一个名称。为此，我们将首先点击**提交应用**链接，这是您在上一个屏幕快照中注意到的左侧菜单下**仪表盘**下的第一个链接。您将被引导到**提交应用**页面，如下面的屏幕快照所示：

![Introducing Live Connect](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_02.jpg)

点击**应用名称**为应用提供一个唯一的名称，仅为此应用保留；其他应用不能使用它。如果应用没有完全提交到商店，预留将持续一年。请确保您有权使用该名称，因为应用将在 Windows Store 中以该名称列出。请注意，应用名称应与在应用清单文件中的**DisplayName**字段中输入的名称相同。要继续，请在提供的文本框中输入一个值，然后点击**预留应用名称**；现在名称已被预留；点击**保存**返回应用摘要页面。现在，应用将在仪表板上以包含**删除**和**编辑**链接的磁贴状框中列出。下面的屏幕快照显示了一个用于示例的测试应用：

![Introducing Live Connect](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_03.jpg)

接下来我们需要为应用配置 Live 服务。为此，请按照以下步骤操作：

1.  如果您在仪表板页面，找到您的应用并点击**编辑**。您将被引导到应用摘要页面。

1.  点击**高级功能**。

1.  点击**推送通知和 Live Connect 服务信息**。

1.  您将被引导到**推送通知和 Live Connect 服务信息页面**，并需要遵循标题下**如果您的应用使用 Live Connect 服务，请审查**的步骤。包括以下步骤：

    +   识别您的应用

    这包括在应用的清单中定义正确的身份值。这些值在我们预留应用名称时创建。我们可以用两种方式设置这些值：

    1.  我们可以通过使用 Visual Studio 2012 中的**商店**菜单为 Windows 8 应用设置应用的身份值。在一个打开的项目中，在顶部菜单中点击**项目**；然后从出现的菜单中选择**商店**，导航到子菜单，并点击**将应用与商店关联**。跟随并完成向导，该过程在下方的屏幕截图中说明：![介绍 Live Connect](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_04.jpg)

        在向导的第一个步骤中，如前屏幕截图中数字 2 所标记的，你将会被提示使用你的 Microsoft 账号进行登录。

    1.  另外，我们也可以在应用清单文件中手动设置应用的包身份。用文本编辑器打开你的应用的 `AppManifest.xml` 文件，并使用 `Name` 和 `Publisher` 值设置 `<identity>` 元素的这些属性。当你在 Windows Store 上预留你的应用名称时，Windows Store 创建了这些值，你可以从 Windows Store 仪表板中获取。下面的代码显示了包含这些值的 XML 设置节的语法：

        ```js
        <Identity Name="19474XXX.BookTestApp" Publisher="CN=F0476225-496D-4EDF-946E-46F6247D5B9A"" />
        ```

        +   认证你的服务

    这一步骤包括获取客户端密钥值。Live Connect 服务使用客户端密钥来认证从你的服务器发出的通信，以保护你的应用的安全。下面将显示以下客户端密钥：

    **zqMKo4G0t3ICZe1h06ofrKYZ1/hVuZXn**。

    请注意，你总是可以回到该页面并创建一个新的客户端密钥，如果有需要的话。

    +   向 Live Connect 用户代表你的应用

        这是配置 Live Connect 服务信息的最后一步，涉及指定 Live Connect 服务用来提示用户授权访问和交互他们数据的意图对话框的设置。在这一步中，你可以提供他们到你自己的服务条款和隐私政策的链接，并上传你的应用标志在授权对话框中显示。

这就完成了在 Windows Store 上应用的注册和配置过程。现在进入编码部分；我们将看看如何实现基本的登录和认证功能。

# 将用户登录到应用

为了开始编码登录功能，我们需要在我们的应用解决方案中引用 Live Connect API；为此，我们首先应该下载并安装 Live SDK for Windows，如果你还没有安装的话。它可以通过以下链接从 *Live Connect 开发者中心* 找到并下载：

[`msdn.microsoft.com/en-us/live/ff621310.aspx`](http://msdn.microsoft.com/en-us/live/ff621310.aspx)

在那页面上，你也可以找到支持 Android 和 iOS 的 Live SDK 版本的下载链接。或者，你可以在 Visual Studio 中直接使用 NuGet 包管理器找到并安装 Live SDK 到你打开的解决方案中。

为此，打开在 Visual Studio 中的应用解决方案，从**解决方案资源管理器**中右键点击解决方案，然后点击**管理 NuGet 包…**

将出现一个对话框，在对话框顶部右上角提供的搜索文本框中输入`livesdk`；包管理器将在线搜索所有包含`livesdk`的相关匹配项。从搜索结果中找到**Live SDK**并单击**安装**。这将安装 Live SDK 包并将其包括在引用中。

下面的屏幕快照显示了屏幕上的**管理 NuGet 包**对话框：

![将用户登录到应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_09.jpg)

接下来，我们在项目中添加对 Live Connect APIs 的引用。为此，请按照以下步骤操作：

1.  从**解决方案资源管理器**中，右键单击**References**，然后单击**添加引用**。

1.  点击**Windows** | **Extension SDKs** | **Live SDK**。

1.  点击**添加**，然后点击**关闭**。

一旦我们添加了对 Live SDK 的引用，解决方案中就会添加 JavaScript 文件`wl.js`。为了方便，我建议您将此文件复制并粘贴到您的`js`文件夹中。然后我们添加一个指向新添加的`wl.js`的`<script>`元素，这样我们就可以在`default.html`页面中使用 Microsoft IntelliSense for this API，如下面的代码所示：

```js
<script src="img/wl.js"></script>
```

请注意，为`src`属性设置的文件路径包含`///`；我们使用三个反斜杠（\）的原因是因为需要通过三个目录层次结构来到达位于`References`下的`LiveSDKHTML`下的`js`目录中的`wl.js`文件。

添加对此脚本文件的引用将在引用的 HTML 文件中启用 Microsoft IntelliSense。

此外，如果您想要在 JavaScript 层面启用 intelliSense，请在调用此 API 方法的头部的 JavaScript 文件中添加引用，如下面的代码所示：

```js
/// <reference path="///LiveSDKHTML/js/wl.js" />
```

### 提示

建议您将使用`wl.js`的代码写在单独的 JavaScript 文件中。这将使修改和调试应用程序更加容易。

让我们添加一个按钮，当点击时，将提示用户登录并响应同意对话框。

以下标记将添加一个具有 ID`signIn`的`button`和一个具有 ID`log`的`div`。这个`div`将用于在屏幕上显示点击**登录**按钮时发生的内容：

```js
<div id="liveSDK">
  <h1>Windows Live Connect</h1>
<div>
<div>
  The authentication in this section uses the Windows Live connect.
  <br />
  Sign in to your Microsoft account by clicking on the below button:
</div>
<button id="signIn">Sign in</button><br /><br />
<div id="log"><br /></div>
</div> 
</div>
```

首先，通过调用`WL.init`方法初始化 Live Connect APIs（应用程序必须在每页上都调用此函数，然后再调用库中的其他函数），然后在页面加载时订阅`auth.login`事件，如下面的代码所示：

```js
WL.init();
WL.Event.subscribe("auth.login", function () {
  if (WL.getSession()){
    log("You are now signed in!");
  }
});
```

在`auth.login`事件的回调函数中，我们使用`WL.getSession()`方法检查当前会话对象的状态；如果存在，则用户已登录。

接下来，我们将为按钮的点击和日志功能添加登录功能：

```js
document.querySelector("#signIn").onclick = function (e) {
  if (WL.getSession()){ 
    log("You are already signed in!");
}
  else {
    WL.login({ scope: "wl.signin" });
  }
};
//log what is happening
function log(info) {
  var message = document.createTextNode(info);
  var logDiv = document.querySelector("#log");
  logDiv.appendChild(message);
  logDiv.appendChild(document.createElement("br"));
}
```

在用户点击登录按钮时，我们首先检查是否有会话，以及用户是否已经登录。如果没有会话，我们尝试通过调用`WL.login`方法登录用户；这个方法需要一个参数`scope: "wl.signin"`。像`"wl.signin"`或`"wl.skydrive"`这样的作用域值用来表示如果用户同意，应用将能够访问用户数据的哪些部分。

在前面的代码行中，我们使用此格式定义了一个作用域：`scope: "wl.signin"`，这是一个字符串参数。我们也可以定义多个作用域，但格式略有不同，使用字符串值的数组，如下面的代码行所示：

```js
scope: ["wl.signin", "wl.skydrive", "wl.basics"]
```

作用域也可以在初始化库时设置，通过将其作为可选参数传递给`WL.init`方法。此外，`login`方法中输入的作用域值将覆盖并扩展在`init`方法中定义的作用域列表。而且，`WL.init`的作用域值在没有由`login`方法提供的作用域时使用。

`WL.login`函数只能在用户动作响应时调用，比如我们例子中的点击按钮，因为该函数可能导致启动同意页面提示。

`log`函数只接受文本，简单地将它追加到 ID 为`log`的`div`内容中，这样我们就可以获取发生了什么的状态信息。

现在运行应用。您将看到以下截图，提示您登录；随后会出现同意对话框：

![将用户登录到应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_06.jpg)

按照前一个截图出现的步骤操作。最后，应用将显示消息：**您已登录！**

## 获取用户信息

`login`函数返回一个承诺对象，使我们能够在成功的情况下适当反应，即用户成功登录。我们的目标是获取用户的个人资料信息。因此，我们需要修改之前展示的`WL.login`调用，并请求额外的作用域，如`wl.basic`、`wl.birthday`和`wl.emails`，这将允许我们检索基本个人资料信息，如名字和姓氏，同时也获取用户的生日和电子邮件。在登录方法的成功的回调中，我们然后执行对`WL.api`函数的调用，它返回我们所需的用户个人资料信息。从技术上讲，`WL.api`函数对 Live Connect Representational State Transfer (REST) API 进行调用。`WL.api`调用的语法如下面的代码所示：

```js
WL.api({
    path: "me" ,
    method: "GET"
});
```

在前面的代码示例中，我们传递了`me`快捷方式以请求有关已登录用户的信息。路径参数指定了到 REST API 对象的路径，在本例中为对象`me`，它包含诸如`first_name`和`last_name`的属性；`WL.api`返回一个承诺对象，因此我们可以对其调用`then()`，并在成功回调中请求用户的名字和姓氏，这些信息由作用域`"wl.basic"`提供。代码如下所示：

```js
WL.api({
  path: "me" , method: "GET"
  }).then(
  function (response) {
    log("First Name: " + response.first_name);
    log("Last Name: " + response.last_name);
    log("Email: " + response.emails.preferred);
    log("Birthday: " + response.birth_day + "/" + response.birth_month);
}
```

将之前的代码添加到登录按钮点击处理程序中调用的 `WL.login` 的 `then` 方法中，完整的代码如下：

```js
document.querySelector("#signIn").onclick = function (e) {
  WL.login({
    scope: ["wl.signin", "wl.basic", "wl.birthday", "wl.emails"]
    }).then(
    function (response) {
      WL.api({
         path: "me", method: "GET"
         }).then(
         function (response) {
           log("First Name: " + response.first_name);
           log("Last Name: " + response.last_name);
           log("Emails: " + response.emails.preferred);
           log("Birthday: " + response.birth_day + "/" + response.birth_month);
           }
         );
     }
  );
};
```

现在运行应用，你会注意到同意对话将更改，请求访问有关你的出生日期和电子邮件地址的信息，如下面的屏幕截图所示：

![获取用户信息](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_07.jpg)

当你批准同意提示后，点击**登录**按钮，应用将显示所请求的信息，如下面的屏幕截图所示：

![获取用户信息](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_08_08.jpg)

### 提示

为了遵守微软为 Windows 商店应用设置的指南，你不应该在应用中的任何地方显示 Microsoft 账户登录或登出选项，除了**设置弹出**控件或任务的一部分。用户期望账户管理选项在设置磁贴中，改变其位置会导致用户体验不一致和意外。

# 摘要

在本章中，我们介绍了 Live Connect，并学习了其核心概念，还看到了我们可以使用这些 API 做些什么，应用启动调用 API 所需的设置，以及如何编写基本的代码来调用 API。

我们还涵盖了如何在商店中注册应用，以及如何在 Visual Studio 中与商店通信。

然后我们利用 Live Connect API 登录用户到应用。此外，我们还学会了在用户同意后如何获取会话信息。

在下一章中，我们将学习关于应用栏的知识，如何为应用创建一个应用栏，以及如何向其中添加菜单按钮。


# 第九章：添加菜单和命令

在本章中，我们将学习关于应用栏的知识，并了解它是如何工作的，以及在哪里可以找到应用栏。此外，我们还将介绍如何声明应用栏以及向其添加控件。

# 了解应用栏

当你运行一个 Windows 商店应用时，你所看到的就是一个全屏应用，它让你能够沉浸在应用的内容中；然而，这时你可能自己会想所有的按钮和控件都去哪了。它们都包含并隐藏在应用栏中——当然，直到你需要它们为止——以避免分散注意力，并让屏幕上的每个像素都用于应用的内容。

应用栏位于屏幕底部，当用户触发时会出现。这可以通过触摸手势（通过从底部边缘向上轻触或滑动，或从顶部边缘向下轻触），使用鼠标（通过右键点击），或使用键盘（通过 Windows + *Z*快捷键）来完成。应用栏通常包含与当前屏幕相关的控件。默认情况下，控件在屏幕的左右两侧平均分配。左侧包含当前在应用中显示内容的特定命令，而右侧包含适用于应用所有页面的全局命令。应用栏也可以包含特定于应用中单个元素的命令。

让我们来看一个应用栏的示例。下面的屏幕截图显示了 Microsoft Bing 应用的应用栏，其中包含四个命令，分别是**复制链接**、**复制**、**另存为**和**设为锁屏背景**：

![了解应用栏](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_09_01.jpg)

应用栏的隐藏机制使用户能够集中精力并沉浸在内容中，同时将干扰降到最低。它在用户需要时提供一致且易于访问的命令，并且他们可以轻松地显示或隐藏应用栏。

当我们尝试使用鼠标、触摸或键盘显示应用栏时，另一个栏会同时出现在屏幕顶部。这是导航栏，虽然它可能看起来很相似，但它并不是应用栏。导航栏用于显示帮助我们导航应用程序不同部分的控制器。

如果存在应用栏，它应该始终对用户可用，并因此适应用户界面在 snapped 和 portrait 视图之间的变化。例如，如果你在 snapped 视图上看不到所有的命令，你可以尝试将它们组合成菜单并提供命令的提示，尽管 Windows 会自动隐藏标签并相应地调整内边距。

### 提示

强烈建议你不要更改由`WinJS`提供的默认布局应用的按钮的大小或内边距，因为它是为了在所有支持屏幕大小上适配 10 个命令而设计的；更重要的是，它还支持触摸手势。因此，更改布局可能会打乱这种行为。

应用栏是由`WinJS`库使用`WinJS.UI.AppBar`对象提供的。

在标记中声明应用栏非常简单。我们从通过指定`data-win-control`属性中的`WinJS.UI.AppBar`控制来从一个简单的`div`元素创建一个应用栏开始。语法如下：

```js
<div id="testAppBar" data-win-control="WinJS.UI.AppBar"> </div>
```

前面的语法将创建一个空的应用于当通过鼠标或向上滑动触发时显示的应用栏。

应用栏是用来包含命令按钮的，所以让我们在应用栏中添加一个命令按钮。为了创建一个应用栏命令按钮，我们将使用一个`button`元素，并指定其`data-win-control`属性为`AppBarCommand`，如下面的代码所示：

```js
<div id="testAppBar" data-win-control="WinJS.UI.AppBar">
  <button data-win-control="WinJS.UI.AppBarCommand"></button>
</div>
```

前面的语法将在应用中显示一个空的命令按钮。我们可以通过在`data-win-options`属性中指定一些选项来给这个命令按钮添加功能。这些选项如下：

+   `type`：此选项用于从以下值指示命令的类型 - `button`、`toggle`、`separator`和`flyout`。

+   `Id`：此选项用于指定命令的 ID。

+   `label`：此选项用于指定应用栏上显示的文本。

+   `Icon`：此选项用于指定用于显示命令的图标，可以通过从 Windows 提供的`AppBarIcon`列表中选择一个值，例如`pin`、`unpin`、`accept`、`cancel`和`delete`，或者通过指定自定义 PNG 图像文件的路径来指定。

+   `section`：此选项用于指示命令所属的部分，可以是`selection`或`global`。`selection`部分会将命令放在应用栏的左侧，这是为上下文命令或页面特定命令保留的位置，而`global`部分会将命令放在应用栏的右侧，这是为全局命令或应用级别命令保留的位置。

+   `tooltip`：此选项用于指定当用户将鼠标悬停在命令上时显示的信息工具提示（提示）。

以下代码显示了在添加这些选项后，我们声明的前一个示例中的命令按钮的语法将如何：

```js
<button data-win-control="WinJS.UI.AppBarCommand" 
data-win-options="{type:'button', id:'testCmd', label:'Test Command', icon:'placeholder', section:'global', tooltip: 'Command Tooltip' }">
</button>
```

运行应用，您将看到一个应用栏，如图所示：

![了解应用栏](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_09_02.jpg)

如您在前面的屏幕截图中所见，应用栏包含一个带有占位符图标的按钮，标记为**Test Command**；当鼠标悬停在上面时，将显示工具提示**Command Tooltip**。

## 为命令添加功能

我们刚刚创建的应用栏目前还不能做什么，所以让我们添加另一个命令并检查其他类型。但在那之前，我们需要在两个命令之间添加一个分隔符；可以通过应用栏默认包含的`hr`元素来创建它，除了命令按钮之外。

`hr`元素还需要设置`data-win-control="WinJS.UI.AppBarCommand"`属性。创建分隔符的语法如下所示：

```js
<hr data-win-control="WinJS.UI.AppBarCommand"data-win-options="{type:'separator', section:'global'}" />
```

在分隔符之后，我们将添加一个新的按钮命令，这次我们选择固定图标；语法将如下所示：

```js
<div id="testAppBar" data-win-control="WinJS.UI.AppBar">
<button data-win-control="WinJS.UI.AppBarCommand" data-win-options="{ type:'button', id:'pinCmd', label:'Pin to start', icon:'pin', section:'global', tooltip: 'Pin the app'}">
</button>
<hr data-win-control="WinJS.UI.AppBarCommand" data-win-options="{type:'separator', section:'global'}" />
<button data-win-control="WinJS.UI.AppBarCommand" data-win-options="{type:'button', id:'testCmd', label:'Test Command', icon:'placeholder', section:'global', tooltip: 'Command Tooltip' }">
</button>
</div>
```

现在运行应用，你应该会看到两个命令按钮，一个带有固定图标，另一个带有占位符图标，以及这两个之间的分隔符，看起来像一个`hr`元素。以下是当用户悬停在标有**固定到启动**的命令上时应用栏的结果屏幕快照：

![为命令添加功能](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_09_03.jpg)

这些命令在应用栏上看起来很不错，但点击后仍然什么也不做，所以让我们给**固定到启动**命令按钮添加一些功能并开始应用固定。

为了给命令按钮添加一些功能，我们需要从应用栏中获取它们，并为它们添加一个`click`事件处理程序。以下代码获取应用栏并将其设置为变量。然后，它使用应用栏的`Id`属性获取该应用栏中的特定命令，并将其点击事件附加到函数上：

```js
//get the appbar control
var appbar = document.getElementById("testAppBar").winControl;
//get the command and add an event handler to it
appbar.getCommandById("pinCmd").addEventListener("click", clickPin, false);
//function to be called when the command is clicked
function clickPin() {
var dialog = new Windows.UI.Popups.MessageDialog("The pin command in the bar has been clicked.");
dialog.showAsync();
}
```

现在运行应用，并点击**固定到启动**命令按钮；屏幕上将出现一个弹出消息对话框。

应用栏默认位于应用的底部，可以改为位于屏幕顶部；然而，它应该包含导航元素，以将用户移至不同的页面。根据 Windows 8 的 UX 指南，顶部的应用栏是一个导航栏。回到代码，我们可以通过简单地设置应用栏控件的`data-win-options`属性的`placement`属性的值，将应用栏的位置从底部更改为顶部，如下面的代码所示：

```js
<div id="testAppBar" data-win-control="WinJS.UI.AppBar" data-win-options="{placement:'top'}">
```

但是，再次说明，根据 UX 指南，默认和推荐的行为是将应用栏放在底部，因为顶部栏留给了导航命令。

在前面的示例中，我们已经将应用栏添加到了主页面`default.html`，但实际上我们应该选择包含我们应用栏的页面并不是随意的，它取决于其范围，如下所述：

+   如果应用栏包含全局命令，并且应该对所有页面可用，请将其添加到`default.html`页面。

+   如果某个页面（一个`PageControl`对象）包含特定于该页面的命令，并且与其他页面不同，那么请将应用栏添加到该页面。

另外，我们可以在主`default.html`文件中定义一个默认应用栏，然后在该特定页面的加载事件上对应用栏进行所需的修改，这需要与默认命令不同的命令。

# 总结

在本章中，我们了解了应用栏是什么以及我们可以在哪里放置应用的命令和控件。我们还学习了应用栏和导航栏之间的区别。我们看到了应用栏命令是什么以及它们可以持有的不同选项。然后，我们看到了如何创建一个包含命令和分隔符的简单应用栏。

最后，我们了解了如何向应用栏上的任何命令类型添加基本功能。

在下一章，我们将到达 Windows Store 应用的最终目的地；那就是，提交到商店本身，我们将学习如何从 Visual Studio 将应用发布到商店，并在仪表板上处理应用配置。


# 第十章：打包和发布

Windows Store 就像一个大型购物中心，你的应用一旦发布到商店，就会像购物中心里的一家小店；Windows Store 仪表板是你将为店铺设置所有品牌、广告和营销材料的地方。Visual Studio 是你的生产环境，商店是你的目的地，两者之间的所有内容都在 Windows Store 仪表板中。在本章中，我们将介绍商店，并学习如何使应用通过所有阶段进入发布。同时，我们还将了解如何在 Visual Studio 内部与商店进行交互。

# 介绍 Windows Store

开发 Windows Store 应用不仅仅是关于设计、编码和标记。导致应用成功的非常关键的一个过程是在 Windows Store 仪表板上完成的。这里是提交应用、为应用铺平市场道路以及监控其在市场上表现的地方。同时，你也可以在这里获取关于你现有应用的所有信息，并计划你的下一个应用。我们在第八章*用户登录*中已经预览了仪表板，当时我们学习了如何添加认证和登录功能。提交过程分为七个阶段，在第八章*用户登录*中，我们在发布概要页完成了第一步，即预留一个应用名称并向 Windows Store 注册应用。为了提交应用以进行认证，还有六个步骤需要完成。如果你还没有打开一个 Windows Store 开发者账户，现在就是打开它的时候，因为你需要它来访问你的仪表板。在注册之前，确保你有一张信用卡。即使你有 entitles you to a free registration 的注册码，Windows Store 也要求使用信用卡来开设开发者账户。

登录后，在主页面**进行中的应用**部分找到你的应用，并点击**编辑**。这将引导你到发布概要页，应用将被命名为**AppName: 发布 1**。每次为同一应用提交新版本时，发布编号将自动递增。发布概要页列出了为你的应用准备 Windows Store 认证的步骤。在这个页面上，你可以输入关于你的 Windows Store 应用的所有信息，并上传其用于认证的包。此刻，你将注意到页面底部的两个按钮，分别为**查看发布信息**和**提交应用以进行认证**，目前这两个按钮是禁用的，并且除非之前的所有步骤都标记为**完成**，否则它们将保持禁用状态。提交进度可以随时保存，以便以后继续，所以这不一定是一次性的任务。我们将逐一介绍这些步骤：

1.  **应用名称**：这是第一步，包括为应用预留一个独特的名称。

1.  **销售详情**：此步骤包括选择以下内容：

    +   **应用程序价格层**：此选项设置应用程序的价格（例如，免费或 1.99 美元）。

    +   **免费试用期**：这是客户可以在开始支付使用费用之前使用应用程序的天数。只有当**应用程序价格层**设置为**免费**时，此选项才启用。

    +   **市场**：在这里，你可以选择你希望应用程序在 Windows 商店中列表的**市场**。请注意，如果你的应用程序不是免费的，你的开发者账户必须为每个你选择的 国家/地区拥有有效的税务档案。

    +   **发布日期**：此选项指定了应用程序在 Windows 商店中列表的最早日期。默认选项是应用程序一旦通过认证就立即发布。

    +   **应用程序类别和子类别**：此选项表明你的应用程序将在商店中列出，进而将应用程序列在**类别**下。

    +   **硬件要求**：此选项将指定 DirectX 功能级别的最低要求以及系统 RAM。

    +   **可访问性**：这是一个复选框，当选中时，表示应用程序已经过测试，符合可访问性指南。

1.  **服务**：在这一步，你可以向你的应用程序添加服务，比如 Windows Azure 移动服务和 Live 服务（正如我们在第八章，*用户登录*中所做的那样）。你还可以提供客户可以在应用程序内购买的产品和功能，称为应用内购买。

1.  **年龄分级和评级证书**：在这一步，你可以从可用的 Windows 商店年龄分级中为应用程序设置一个年龄分级。另外，如果你的应用程序是一款游戏，你还可以上传特定于国家/地区的评级证书。

1.  **加密学**：在这一步，你需要指定你的应用程序是否调用、支持并包含或使用密码学或加密。以下是一些应用程序可能应用密码学或加密的示例：

    +   使用数字签名，如身份验证或完整性检查。

    +   对您的应用程序使用或访问的任何数据或文件进行加密。

    +   密钥管理、证书管理或与公钥基础设施交互的任何内容

    +   使用诸如 NTLM、Kerberos、**安全套接字层**（**SSL**）或**传输层安全**（**TLS**）等安全通信通道。

    +   对密码或其他信息安全形式进行加密。

    +   版权保护或**数字版权管理**（**DRM**）。

    +   防病毒保护

1.  **包**：在这一步，你可以通过上传在 Visual Studio 中创建包过程中创建的`.appxupload`文件，将应用程序上传到商店。我们很快就会看到如何创建一个应用程序包。最新的上传将在发布摘要页的包框中显示，并应标记为**验证完成**。

1.  **描述**：在此步骤中，您可以添加一个简要描述（必填）您的应用程序为客户做什么。描述有 10,000 个字符的限制，并将显示在应用程序列表在 Windows Store 中的**详情**页面。除了描述之外，此步骤还包括以下功能：

    +   **应用功能**：此功能为可选。它允许您列出应用程序的最多 20 个关键功能。

    +   **截图**：此功能为必填项，需要提供至少一张`.png`文件图片；第一张可以是代表您应用程序的图形，但所有其他图片必须是带有标题的直接从应用程序中截取的屏幕快照。

    +   **备注**：此功能为可选。输入您认为客户需要知道的其他信息；例如，更新中的变化。

    +   **推荐硬件**：此功能为可选。列出应用程序运行所需的硬件配置。

    +   **关键词**：此功能为可选。输入与应用程序相关的关键词，以帮助其在搜索结果中出现。

    +   **版权和商标信息**：此功能为必填项。输入将在应用程序列表页面向客户展示的版权和商标信息。

    +   **其他许可条款**：此功能为可选。输入任何对**标准应用程序许可条款**的更改，客户在获取此应用程序时需要接受。

    +   **推广图片**：此功能为可选。添加编辑用于在商店中展示应用程序的图片。

    +   **网站**：此功能为可选。如果有的话，输入描述应用程序的网页 URL。

    +   **支持联系方式**：此功能为必填项。输入支持联系的电子邮件地址或网页 URL，您的客户可以通过该地址寻求帮助。

    +   **隐私政策**：此功能为可选。输入包含隐私政策的网页 URL。

1.  **给测试人员的备注**：这是最后一步，包括添加关于此特定版本的备注，给那些将从 Windows Store 团队审查您应用程序的人。这些信息将帮助测试人员理解和使用此应用程序，以便快速完成测试并为您应用程序在 Windows Store 进行认证。

每个步骤将保持禁用状态，直到完成前一个步骤，并且正在进行中的步骤会被标记上大约需要完成的时间（分钟）。每当一个步骤的工作完成时，在摘要页面上会标记为**已完成**，如下面的屏幕快照所示：

![Windows Store 简介](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_01.jpg)

## 提交应用程序以进行认证

在所有步骤都被标记为**完成**后，您可以提交应用程序进行认证。一旦您点击“**提交以进行认证**”，您将收到电子邮件通知，Windows 商店已经收到了您的应用程序进行认证。仪表板将提交应用程序，然后会将您引导到“**认证状态**”页面。在那里，您可以在应用程序进行认证过程中查看其进度，包括以下步骤：

+   **预处理**：这一步将检查您是否已经输入了所有发布应用程序所需的必要详细信息。

+   **安全测试**：这一步将您的应用程序测试是否含有病毒和恶意软件。

+   **技术合规性**：这一步使用 Windows 应用程序认证工具包来检查应用程序是否符合技术政策。同样的评估可以在本地使用 Visual Studio 运行，我们稍后会看到，在您上传包之前，可以进行此评估。

+   **内容合规性**：这一步由商店团队的质量保证人员完成，他们会检查应用程序中的内容是否符合由微软制定的内容政策。

+   **发布**：这一步涉及发布应用程序；除非您在**销售详情**中指定的发布日期是未来的，否则这个过程不会花费太多时间，在这种情况下，应用程序将保持在这个阶段直到那个日期到来。

+   **签名和发布**：这是认证过程的最后一步。在这个阶段，您提交的包将使用与您开发者账户技术细节相匹配的可信证书进行签名，从而向潜在的客户和观众保证该应用程序已通过 Windows 商店认证。

下面的屏幕快照显示了在 Windows Store 仪表板上的认证过程：

![提交应用程序进行认证](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_02.jpg)

无需在那页等待；您可以点击“**前往仪表板**”按钮，您将被重定向到“**我的应用**”页面。在包含您刚刚提交的应用程序的框中，您会注意到“**编辑**”和“**删除**”链接已经消失，取而代之的只有“**状态**”链接，它将带您到“**认证状态**”页面。此外，这个页面将出现一个“**通知**”部分，并列出关于您刚刚提交的应用程序的状态通知，例如：

**BookTestApp: 发布 1 版已提交进行认证。6/4/2013**

当认证过程完成后，您将通过电子邮件收到通知。同时，在仪表板的主页上将添加一个通知，显示认证的结果，无论是失败还是成功，并带有指向认证报告的链接。如果应用程序失败，认证报告将显示需要重新审查的部分。此外，还有一些资源可以帮助您在认证过程中识别和修复可能出现的问题和错误；这些资源可以在以下位置找到：Windows Dev Center 页面的 Windows Store 应用程序部分：

[`msdn.microsoft.com/en-us/library/windows/apps/jj657968.aspx`](http://msdn.microsoft.com/en-us/library/windows/apps/jj657968.aspx)

此外，您随时可以通过仪表板检查应用在认证过程中的状态。

成功完成认证过程后，应用包将被发布到商店，其中包含所有相关数据，这些数据将显示在您的应用列表页面上。用户可以通过这个页面访问数百万 Windows 8 用户，他们可以找到、安装和使用您的应用。

一旦应用被发布到商店并且运行正常，您就可以开始收集遥测数据，了解它在商店中的表现；这些指标包括应用被启动的次数、运行时间以及是否发生崩溃或遇到 JavaScript 异常。一旦您启用了遥测数据收集，商店就会为您应用检索这些信息，分析它们，并在您仪表板上的非常具有信息性的报告中总结它们。

现在我们已经涵盖了将您的应用提交到 Windows 商店所需了解的几乎所有内容，让我们看看在 Visual Studio 中需要做些什么。

# Visual Studio 中的商店

您可以通过**商店**菜单从 Visual Studio 内部访问 Windows 商店。并非我们仪表板上完成的所有事情都可以在这里完成；创建应用包等一些非常重要的功能是由此菜单提供的。在 Visual Studio 2012 Ultimate 中，**商店**菜单位于菜单栏下的**项目**项下，如果您使用的是 Visual Studio 2012 Express，则可以直接在菜单栏中找到它，仅当您在 Windows 商店项目或解决方案上工作时，它才会出现。

我们将详细查看**商店**菜单提供的命令，以下屏幕截图展示了菜单的外观：

![Visual Studio 中的商店](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_03.jpg)

**商店**菜单中的命令选项如下：

+   **打开开发者账户...**：此选项将打开一个网页，引导您前往*Windows 开发者中心*，以获取 Windows 商店应用的开发者账户。

+   **保留应用名称...**：此选项将引导您前往 Windows 商店仪表板，并具体指向**提交应用**页面，您可以开始第一步，即保留我们之前在第八章中看到的*签名用户*一节中提到的应用名称。

+   **获取开发者许可证...**：此选项将打开一个对话窗口，提示您使用您的 Microsoft 账户登录；登录后，如果您的账户已经有许可证，它将检索或续签您的开发者许可证。

+   **编辑应用清单**：此选项将打开带有清单设计器的标签页，以便您可以编辑应用清单文件中的设置。

+   **将应用与商店关联...**：此选项将在 Visual Studio 中打开一个类似向导的窗口，其中包含将应用与商店关联所需的步骤。第一步将提示您登录；之后，向导将检索您用于登录的 Microsoft 帐户注册的应用。选择一个应用，向导将自动将以下值下载到本地计算机上当前项目的应用清单文件中：

    +   包的显示名称

    +   包的名称

    +   发布者 ID

    +   发布者的显示名称

+   **捕获屏幕截图...**：此选项将构建当前的应用程序项目并在模拟器中启动，而不是在启动屏幕上。一旦模拟器打开，你可以在模拟器侧边栏上使用**复制屏幕截图**按钮。这个按钮将用于捕获正在运行的应用程序的屏幕截图，并将其保存为`.png`文件。

+   **创建应用包...**：此选项将打开一个包含**创建应用包**向导的窗口，我们稍后会看到。

+   **上传应用包...**：此选项将打开一个浏览器，如果您设置了 Store 账户并且注册了应用，它将引导您到 Windows Store 仪表板的发布摘要页面。否则，它只会带您到登录页面。在发布摘要页面，您可以选择**包**，并从那里上传您的应用包。

## 创建应用包

在**商店**菜单中，最实用的工具之一是应用包创建，它将构建并创建一个我们可以稍后上传到商店的应用包。这个包包含了商店所需的所有与应用和开发者特定的详细信息。此外，开发者不必担心整个包创建过程的复杂性，这一切都为我们抽象化，并通过一个向导链接窗口提供。

在**创建应用包**向导中，我们可以直接为 Windows 商店创建应用包，或者创建用于测试或本地分发的应用包。此向导将提示您为应用包指定元数据。

以下屏幕截图显示了此过程的前两个步骤：

![创建应用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_04.jpg)

在第一步中，向导将询问您是否想要构建上传到 Windows 商店的包；如果您想为商店构建包，请选择**是**，如果您想为测试和本地使用构建包，请选择**否**。考虑第一种情况，点击**登录**以继续并使用您的 Microsoft 帐户完成登录过程。

成功登录后，向导将提示您**选择应用名称**（前一个屏幕的步骤 2）， either by clicking on the apps listed in the wizard or choosing the **Reserve Name** link that will direct you to the Windows Store Dashboard to complete the process and reserve a new app name. The following screenshot shows step 3 and step 4:

![创建应用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_05.jpg)

第 3 步包含**选择和配置包**部分，在这一部分我们将选择**输出位置**，它指的是包文件将被创建的地方。此外，在这一部分我们还可以为这个包输入一个版本号，或者选择使其每次打包应用时自动递增。此外，我们还可以从**通用**、**ARM**、**x64**和**x86**选项中选择我们希望为包设置的构建配置，默认情况下，将选择当前活动项目平台，并为所选的每个配置类型生成一个包。

本节最后的选项是**包括公共符号文件**。选择此选项将生成公共符号文件（*.pdb）并添加到包中，这将帮助商店后来分析你的应用，并将用于映射你的应用崩溃。最后，点击**创建**，等待包装处理完成。完成后，出现**包创建完成**部分（第 4 步），并将显示**输出位置**作为一个链接，将引导你到包文件。此外，还有一个直接启动**Windows 应用认证工具包**的按钮。**Windows 应用认证工具包**将根据商店要求验证应用包并生成验证报告。

下面的屏幕截图显示了包含**Windows 应用认证工具包**过程的窗口：

![创建应用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_06.jpg)

另外，还有一种创建应用包的第二种场景，但更多的是针对测试，除了在向导的第一页必须选择**否**，且不需要使用 Microsoft 账户登录之外，与刚刚看到的流程完全相同。这种选项将在包创建完成后结束向导并显示输出文件夹的链接，但你将无法启动**Windows 应用认证工具包**。使用这种选项创建的包只能在与安装了开发者许可证的计算机上使用。由于商店的包最好先在本地测试，所以这种场景会经常使用。在为测试或本地分发创建应用包之后，你可以在本地计算机或设备上安装它。

让我们在本地安装这个包。启动**创建应用包**向导；在第一步选择**否**，完成向导，然后在指定包位置的输出文件夹中找到刚刚创建的应用包文件。将此文件夹命名为`PackageName_Test`。这个文件夹将包含一个`.appx`文件、一个安全证书、一个 Windows PowerShell 脚本和其他文件。与应用包一起生成的 Windows PowerShell 脚本将用于测试安装包。导航到**输出**文件夹并安装应用包。定位并选择名为`Add-AppDevPackage`的脚本文件，然后右键点击，选择**以 PowerShell 运行**，如下图所示：

![创建应用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_07.jpg)

运行脚本后，它将执行以下步骤：

1.  它显示有关**执行策略更改**的信息，并询问是否更改执行策略。输入`Y`以继续。

1.  它检查你是否拥有开发者许可证；如果没有脚本，它会提示你获取一个。

1.  它检查并验证应用包和所需证书是否已存在；如果缺少任何项目，你将在安装开发包之前被通知安装它们。

1.  它检查并安装任何依赖包，如`WinJS`库。

1.  它显示消息**成功：您的包已成功安装**。

1.  按下*Enter*键继续，窗口将关闭。

上述步骤显示在以下屏幕截图中：

![创建应用包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_10_08.jpg)

一旦脚本成功完成，你可以在**开始**屏幕上寻找你的应用并启动它。

### 提示

请注意，对于那些位于网络中且没有权限访问`Add-AppDevPackage` PowerShell 脚本文件所在目录的用户，可能会出现错误信息。这个问题可以通过在运行脚本之前将`output`文件夹的内容复制到本地机器来简单解决。另外，对于任何安全相关的问题，你可能需要咨询 Windows 开发者中心以获取解决方案。

# 总结

在本章中，我们了解了 Windows 商店仪表板的所有细节，并涵盖了将应用提交到商店的步骤。我们还学习了 Visual Studio 中的**商店**菜单以及它提供的与仪表板交互的选项。此外，我们还学习了如何创建应用包以及如何将应用本地下载以供测试。

在下一章中，我们将窥视硬币的另一面，使用 XAML 开发 Windows 8 应用，并了解它与使用 JavaScript 开发应用的相似之处，从而向您展示使用多种编程语言开发 Windows 8 应用的力量。


# 第十一章：使用 XAML 开发应用程序

开发 Windows 商店应用程序不仅限于 HTML5 和 JavaScript。微软提供了使用可扩展应用程序标记语言（XAML）和.NET 的其他选择，从而将更广泛的开发者和专业知识吸引到商店开发。无论你的背景如何，是网页还是 Windows 开发，都有一个适合你的地方——一个起点——因为无论你选择哪种编程语言，通往 Windows 商店的道路都是一样的。在前几章中，我们学习了如何使用 HTML5 和 JavaScript 开发应用程序和功能。但在本章中，我们将学习其他平台和编程语言，以及使用 XAML/C#创建应用程序的基础知识。

# 使用不同平台创建应用程序

Windows 8 最重要的进步之一是，你可以使用多种框架和编程语言开发应用程序，面向网页和 Windows 开发者。此外，开发者可以构建并利用他们现有的编程技能和知识来创建 Windows 商店应用，不一定需要掌握一套全新的技能。

网页开发者将能够利用他们的 HTML5、CSS3 和 JavaScript 技能，甚至可以轻松地将现有网站移植到商店应用中，而熟悉微软.NET 框架和 Silverlight 的 Windows 开发者可以运用他们的 XAML、C#和 Visual Basic 技能付诸实践。此外，Windows 8 针对熟悉 C++语法和本地库的开发者，通过提供使用 Visual C++/XAML 创建 Windows 商店应用的机会。而且，使用 C++，你可以创建 Direct2D 和 Direct3D 应用。总之，我们有 XAML 标记和 C#、VB.NET、C++，更不用说，Visual Studio 2012 为所有这些编程语言提供了项目模板和 Intellisense 支持。

同一个应用程序可以用 XAML 或 HTML5 来构建，部署和运行时，两个版本将以相同的方式运行。我们在前面的章节中学到的所有用 JavaScript 和 HTML5 为 Windows 商店应用程序编写的功能和特性，都可以用 C#、VB.Net 和 XAML 来实现。选择使用哪种编程语言是基于个人喜好、背景经验以及语言熟悉度，而不是其他因素。两种选择都需要一定的学习水平。熟悉 HTML 标记、使用 CSS 进行样式设计和使用 JavaScript 实现功能的网页开发者，需要学习 WinJS 特定的 JavaScript 函数和 HTML 数据属性及类。此外，有 XAML 经验的开发者会发现与 WPF 和 Silverlight 有很多相似之处，但需要学习为 Windows 商店设计和功能开发。然而，如我所说，当你从熟悉的领域开始 Windows 商店开发时，学习曲线是最小的。

# 介绍 XAML 应用程序

使用 XAML 开发的 Windows 商店应用的路线图与使用 JavaScript 开发的商店应用相同，从工具开始，通过设计指南获取开发者许可证，规划应用，最后进行打包并将应用发布到商店。

让我们使用 XAML 创建一个基本的 Windows 商店应用，并将其与使用 HTML5 创建的应用进行比较。在 Visual Studio 中，从顶部菜单，导航到 **文件** | **新建项目**。在 **新建项目** 对话框中，从左侧窗格下的 **已安装** | **模板** 中选择您喜欢的编程语言，然后选择 **Windows 商店**。接下来，我们选择一个列表中的 Windows 商店应用项目模板，并在 **名称** 文本框中为其输入一个名字。我将为这个演示选择 **Visual C#**；您也可以选择 **Visual Basic** 或 **Visual C++**。最后，点击 **确定** 创建项目：以下屏幕快照显示了刚刚讨论的过程：

![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_01.jpg)

前一个屏幕快照显示了随 XAML 提供的以下 Windows 商店应用模板：**空白应用 (XAML)**，**网格应用 (XAML)**，以及**分割应用 (XAML)**。

+   **空白应用 (XAML)**：此模板提供了一个空的 Windows 商店应用，它可以编译并运行，但其中没有用户界面控件或数据。当基于这个模板运行一个应用时，它将只显示一个包含占位符文本的黑屏。

+   **网格应用 (XAML)**：此模板提供了一个应用，使用户能够浏览不同的分类，并深入查看每个分类下的内容细节。此模板的好例子包括购物应用、新闻应用以及图片或视频应用。**网格应用 (XAML)** 模板从一块着陆主页开始，该主页将展示一系列组或分类。一个单独的组是一组命名项的集合；例如，一组名为“体育新闻”的新闻文章。当用户选择一个组时，应用将打开组详情页，该页面的右侧将显示该组包含的项列表。因此，当用户在主页或组详情页上选择一个单独的项时，应用将打开一个显示项详情的页面。

    以下屏幕快照显示了**网格应用 (XAML)** 的示例主页：

    ![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_08.jpg)

+   **分栏应用（XAML）**：此模板提供了一个允许用户浏览类别以找到特定内容的应用，与**网格应用（XAML）**模板类似；然而，使用**分栏应用（XAML）**模板，用户可以在同一页面的双栏分隔视图中查看项目列表和项目详细信息。这种分隔视图允许所有用户快速切换项目。此模板的使用示例包括新闻阅读器或电子邮件应用。此模板从显示组列表的起始主页开始，当用户选择一个组时，应用将打开一个分隔视图页面。下面的屏幕截图显示了一个示例分隔视图页面：![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_09.jpg)

这三个项目模板与 Windows 商店 JavaScript 项目中提供的模板类似，但后者提供了两个额外的模板，分别是**固定布局应用**和**导航应用**。

我们将从**空白应用（XAML）**模板开始，该模板包含了运行应用所需的最小项目文件。**空白应用（XAML）**模板创建了一个空的 Windows 商店应用，其中没有用户界面，但可以编译并运行。创建空白应用后，导航到 Visual Studio 右侧的**解决方案资源管理器**，展开项目文件列表，以查看与此模板一起创建的默认文件。

下面的屏幕截图显示了**解决方案资源管理器**右侧的内容和打开在 XAML 文本编辑器中的`MainPage.xaml`文件，位于左侧：

![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_02.jpg)

我们刚刚创建的项目包含以下必需的文件夹和文件，这些文件对于所有使用 C#或 Visual Basic 的 Windows 商店应用来说是不可缺少的：

+   `Properties`：此文件夹包含应用程序汇编信息。

+   `References`：此文件夹包含项目引用文件，默认情况下，有以下两个 SDK 引用：**.NET 用于 Windows 商店应用**和**Windows**。

+   `Assets`：此文件夹包含以下图像：

    +   分别尺寸为 150 x 150 像素和 30 x 30 像素的大和小 logo 图像。

    +   **SplashScreen** 图像。

    +   尺寸为 50 x 50 像素的**商店 Logo**图像。

+   `Common`：此文件夹包含应用中的常用共享资源，如`StandardStyles.xaml`文件，该文件提供了一组默认样式，赋予了应用 Windows 8 的外观和感觉。此外，此文件夹还将包含实用工具和帮助器类的文件。

此模板还包括以下`.xaml`页面文件：

+   `App.xaml`：这是必需的主要应用文件，用于显示用户界面，在应用运行时首先加载。此页面声明了跨整个应用共享的资源，如样式，并为内容宿主提供标记。这个页面类似于在使用 JavaScript 的应用中`default.html`页面所代表的内容。

+   `App.xaml.cs`：这是`App.xaml`的代码隐藏文件，包含处理全局应用特定行为和事件的代码，例如应用的启动和挂起。这个文件与使用 JavaScript 的 app 中的`default.js`文件类似。

+   `MainPage.xaml`：这是应用的默认启动页面，并包含实例化页面的最小 XAML 标记和代码。

+   `MainPage.xaml.cs`：这是与`MainPage.xaml`文件对应的代码隐藏文件。

最后，还有`Package.appxmanifest`这个清单文件，它包含了与 JavaScript 模板中相同的应用程序描述和设置。

### 注意

微软建议不要删除`Common`文件夹中的文件。此外，它也不能重命名或修改，因为这会导致构建错误。如果需要修改这些文件，你可以创建原始文件的副本并进行修改。

那些之前没有听说过 XAML 的人可能会对刚才在应用和`MainPage.xaml`文件中看到的语法感到困惑。XAML 基于 XML 构建了一套基本的语法。当剥离掉冗余的部分，一个 XAML 文件就是一个显示对象之间层次关系的 XML 文档，并且为了被认为是有效的，它也必须是一个有效的 XML 文档。XAML 文件有一个`.xaml`文件扩展名，每个 XAML 文件都与其一个代码隐藏文件相关联，这个代码隐藏文件包含处理事件、操作在 XAML 中创建或声明的对象和 UI 元素的代码。代码隐藏文件与 XAML 页面的部分类结合构成了一个完整的类。这与 ASP.NET 网页的概念类似，`.aspx`文件包含标记和代码隐藏文件，后缀为`.cs`或`.vb`。此外，XAML 文件可以在 Microsoft Expression Blend 中打开和编辑。如果你是 XAML 的新手，不必太担心语法，因为 Visual Studio 会通过提供自动完成提示和建议列表来帮助你编写有效的标记，你会在学习过程中了解语法。

使用 XAML 标记，我们可以像使用 HTML 一样创建 UI 元素，但语法有所不同。让我们在`MainPage.xaml`文件中的`Grid`元素内使用以下语法添加以下 UI 元素：

```js
<TextBlock x:Name="pageTitle" Text="Test XAML App" ></TextBlock>
<TextBox Text="Input text here..." />
<CheckBox Content="Yes"/>
```

前面的代码列表显示了以下属性：`x:Name`，它指定了分配给`TextBlock`元素的名称；`Text`，它指定了作为文本的数据，将填充此元素；`Content`，它与`Text`类似，但指定作为文本的数据，将显示在`CheckBox`元素的旁边。

代码列表中的第一行声明了一个基本的`TextBlock`元素，它与 HTML 中的`label`元素类似。我们给这个元素一个名字，并为其`Text`属性输入一个值。第二个元素是`Textbox`，带有`Text`值，第三个元素是一个带有`Content`值的`Checkbox`元素。您可以手动编写语法，也可以从**工具箱**面板中选择一个控件，并将其直接拖到 XAML 文本编辑器或设计表面，这两个都在分屏视图中可见。

在设计窗口中，您可以操作这些 UI 控件，并按照以下屏幕截图所示安排它们在窗口中的位置：

![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_03.jpg)

您会注意到，在**设计**面板中操作控件会在下方的**XAML**面板中反映出来，因为正在为元素设置新的属性并更改现有的属性。如果您现在运行应用程序，您将看到一个包含我们刚刚添加到`MainPage.xaml`文件中的三个元素的黑色屏幕。

`MainPage.xaml`文件包含运行页面所需的最小标记和代码，但缺少所有实现 Windows Store 应用重要功能的附加代码和类，例如适应用户界面变化和处理应用程序的不同状态。幸运的是，Visual Studio 提供的其他页面模板，例如基本页面模板，包含了帮助您实现这些功能的代码和帮助类。为此目的，我们通常在处理空白应用程序（XAML）项目时，将那个空的`MainPage`模板替换为其他页面模板之一。要替换`MainPage.xaml`文件，请在**解决方案资源管理器**中右键点击它，然后点击**删除**。然后，在项目根节点上右键点击，点击**添加新项目项**，这将打开一个对话框窗口。从那里，在下拉列表中选择**Visual C#**（或如果您在示例开始时选择了不同的模板，选择 Visual Basic）下的**Windows Store**模板类型。接下来，选择**基本页面**，并将其命名为`MainPage.xaml`，否则项目将无法正确构建。以下屏幕截图说明了该过程：

![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_04.jpg)

然后，点击**添加**。如果这是您第一次将不同于**空白页面**模板的新页面添加到**空白应用（XAML）**模板中，将会显示一个带有警告的消息对话框，内容为**此添加依赖于项目中缺失的文件**。点击**是**以自动添加缺失的文件。此页的 XAML 和代码后置文件被添加到项目中，如果您展开`Common`文件夹，会发现原本只包含一个文件`StandardStyles.xaml`的文件夹现在包含了包含多个帮助器和实用类别的代码文件。新添加的页面在您构建项目/解决方案之前不会在设计器中显示，因此它会编译页面依赖的帮助类。让我们看看这次更改后应用的样子；按*F5*以构建并在调试模式下运行应用。

运行后，应用将显示为一个黑色屏幕，包含标题**我的应用**，如下图所示：

![介绍 XAML 应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_05.jpg)

这里需要注意的是，此页面默认符合 Windows 8 的设计指南，而我们无需添加任何样式或标记。正如你所看到的，标题似乎是相同的字体大小，并且按照*Windows 8 应用商店应用的 Windows 8 UX 指南*页面中指定的确切边距进行定位：（[`www.microsoft.com/en-in/download/details.aspx?id=30704`](http://www.microsoft.com/en-in/download/details.aspx?id=30704)）。

## 添加标题、主题颜色和内容

让我们通过添加标题并更改其主题颜色来修改这个最小应用。然后，我们将添加一个简单的文本，并编写一些代码来处理基本按钮点击事件。

1.  要更改此应用的标题，请执行以下步骤：

    1.  打开`MainPage.xaml`文件。

    1.  在**XAML**设计面板中，选择标题**我的应用**，然后右键点击选择**编辑文本**，或者在**属性**窗口下`Common`中更改`Text`属性。如果默认情况下没有显示，**属性**窗口应该位于 Visual Studio 左侧，低于**解决方案资源管理器**面板。

1.  要更改此应用的主题颜色，请执行以下步骤。与使用 JavaScript 的应用程序类似，我们也可以在这里切换深色和浅色主题。在 JavaScript 应用程序中，`default.html`页面引用了两个 CSS 文件，`ui-dark.css`和`ui-light.css`。在 XAML 应用程序中，在`App.xaml`文件中如下进行主题切换：

    1.  打开`App.xaml`文件。

    1.  转到`<Application>`标签并在闭合标签之前添加`RequestedTheme`属性。

    1.  在标签的引号内点击，Visual Studio 的 Intellisense 将提示您两个属性值：**Light**和**Dark**。选择**Light**，`<Application>`标签将如下所示：

        ```js
        <Application
        x:Class="App1.App"

           RequestedTheme="Light">
        ```

    1.  运行应用以查看差异。

1.  现在要添加一些 UI 内容，打开`MainPage.xaml`文件，定位根`Grid`元素和它内部的`<VisualStateManager.VisualStateGroups>`标签。在这个标签之前添加以下 XAML 代码片段：

    ```js
    <StackPanel Grid.Row="1" Margin="120,30,0,0">
      <TextBlock Text="Is this your first XAML App?"/>
      <StackPanel Orientation="Horizontal" Margin="0,20,0,20">
        <TextBox x:Name="answerInput" Width="360"HorizontalAlignment="Left"/>
        <Button Content="Post My Answer"/>
      </StackPanel>
      <TextBlock x:Name="myAnswer"/>
    </StackPanel>
    ```

    上述 XAML 代码声明了一个`StackPanel`控件，该控件内部包含 UI 控件（可以把它想象成一个`div`元素）。在这个控件内部，我们添加了一个`TextBlock`元素并为其`Text`属性赋值，然后我们在父级`StackPanel`控件内嵌套了一个`StackPanel`控件（一个`div`内的`div`元素）。这个`StackPanel`元素将包含两个控件：一个`TextBox`元素用于输入我们为其`width`和`HorizontalAlignment`属性赋值的输入值，以及一个`Button`控件，我们为其`Content`属性赋值。最后，在内部`StackPanel`元素的外部添加另一个空的`TextBlock`元素。

    运行应用程序，它将看起来像以下屏幕快照：

    ![添加标题、主题颜色和内容](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_06.jpg)

1.  最后，让我们通过为在标记中声明的按钮添加事件处理程序来添加一些功能，具体步骤如下：

    1.  在 XAML 设计器或文本编辑器中点击**发布我的答案**按钮，它将在**属性**窗口中显示。

    1.  在**属性**窗口中，定位并点击左上角的**事件**按钮。

    1.  在列表顶部找到**Click**事件，双击或在文本框中按*Enter*键。

    这将创建事件处理方法。在文件`MainPage.xaml.cs`的代码编辑器中显示它。

    以下屏幕快照显示了该过程：

    ![添加标题、主题颜色和内容](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_11_07.jpg)

    自动生成的事件处理程序名字为`Button_Click`（如果按钮有一个为其`name`属性赋值，事件处理程序看起来可能像`ButtonName_Click`）。该方法将如下所示：

    ```js
    private void Button_Click(object sender, RoutedEventArgs e)
    {
    }
    ```

    让我们添加一些简单的代码，获取输入文本框中输入的文本并在名为`myAnswer`的空`TextBlock`中显示它。代码将如下所示：

    ```js
    private void Button_Click(object sender, RoutedEventArgs e)
    {
      myAnswer.Text = answerInput.Text;
    }

    ```

    如果我们回到 XAML 编辑器，我们会看到`Click`事件处理程序已经这样添加到了`Button`元素中：

    ```js
    <Button Content="Post My Answer" Click="Button_Click"/>
    ```

    现在，运行应用程序，在文本框中输入一些文本，并测试按钮。点击后，它将在屏幕上显示文本框内的任何内容。

XAML 的魅力远不止这个简单的演示，之前的例子仅仅展示了我们如何从一个非常基础的应用程序开始，逐步构建内容和功能。一旦我们熟悉了 XAML，它并不那么难；与其他编程语言一样，我们需要进行实践。然而，选择 XAML 还是 HTML5 完全取决于你。

使用 XAML 开发 Windows Store 应用的一个优点是，您可以使用微软提供的指南将**Windows Phone 7**应用迁移到 Windows 8。同样，微软也提供了一个指南，帮助您将现有的 Silverlight 或 WPF/XAML 代码通过 XAML 转换为 Windows Store 应用。这两个指南都可以在*Windows Phone Dev Center*页面找到([`developer.windowsphone.com/en-us`](http://developer.windowsphone.com/en-us))。

# 总结

在本章中，我们了解到了 Windows 8 为开发者提供的不同选择。此外，我们还介绍了 Windows Store 应用中的 XAML 语言和语法。

我们还介绍了如何使用 XAML 开始开发 Windows Store 应用，以及它与使用 JavaScript 开发的不同之处，这让我们对使用任一语言开发有了预期。

最后，我们创建了一个最小的应用，并向其添加了一些基本的 UI 内容和功能，使用了 XAML 标记语言。

在这本书中，我们介绍了 HTML5 和 CSS3 的新特性，并学习了这些特性如何在 Windows Store 应用中实现。我们还介绍了专为 Windows Store 应用设计的 JavaScript 控件功能。之后，我们学习了如何创建一个基本的 JavaScript 应用，以及如何使用 JavaScript 快速开始开发 Windows Store 应用。进一步地，我们了解了一些应用的重要特性以及如何实现这些特性。我们首先通过 WinJS 控件检索和显示数据。然后，我们介绍了应用的视图状态以及如何使应用响应这些视图状态的变化。之后，我们了解了 Windows 8 中的磁贴，并学习了如何添加动态磁贴并向应用发送通知。此外，我们还学习了如何将应用与 Windows Live 服务集成，以使用户能够使用他们的电子邮件账户进行认证和登录。我们还学习了 Windows Store 应用中的应用栏以及如何向其添加按钮。最后，我们介绍了 Windows Store，并学习了有关将应用打包并发布到商店的所有内容。
