# Unity 2020 游戏开发实用指南（二）

> 原文：[`zh.annas-archive.org/md5/36713AD44963422C9E116C94116EA8B8`](https://zh.annas-archive.org/md5/36713AD44963422C9E116C94116EA8B8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 URP 和着色器图的材质和效果

欢迎来到*第二部分*的第一章！我非常激动，因为你已经到达了这本书的这一部分，因为在这里，我们将深入研究 Unity 的不同图形和音频系统，以显着改善游戏的外观和感觉。我们将从这一部分开始，本章将讨论材质的着色器是什么，以及如何创建我们自己的着色器来实现一些无法使用默认 Unity 着色器实现的自定义效果。我们将创建一个简单的水动画效果来学习这个新概念。

在本章中，我们将研究以下着色器概念：

+   着色器介绍

+   使用着色器图创建着色器

# 介绍着色器

在上一章中，我们创建了材质，但我们从未讨论过它们内部是如何工作的，以及为什么着色器属性非常重要。在本章的第一部分，我们将探讨着色器的概念，作为编程视频卡以实现自定义视觉效果的一种方式。

在这一部分，我们将涵盖与着色器相关的以下概念：

+   着色器管道

+   渲染管道和 URP

+   URP 内置着色器

让我们从讨论着色器如何修改着色器管道以实现效果开始。

## 着色器管道

每当显卡渲染 3D 模型时，它需要输入数据进行处理，例如网格、纹理、对象的变换（位置、旋转和缩放）以及影响该对象的光源。有了这些数据，显卡必须将对象的像素输出到后备缓冲区，即视频卡将绘制我们对象的图像的地方。当 Unity 完成渲染所有对象（和一些效果）以显示完成的场景时，将显示该图像。基本上，后备缓冲区是显卡逐步渲染的图像，在绘制完成时显示出来（此时，它变成前置缓冲区，与之前的缓冲区交换）。

这是渲染对象的常规方式，但在输入数据和像素输出之间发生的事情可以通过许多不同的方式和技术来处理，这取决于您希望对象的外观如何；也许您希望它看起来很逼真或看起来像全息图，也许对象需要一个解体效果或卡通效果——可能有无尽的可能性。指定我们的显卡将如何处理对象的渲染的方式是通过着色器。

着色器是用特定的显卡语言编写的程序，例如 CG、HLSL 或 GLSL，它配置渲染过程的不同阶段，有时不仅配置它们，还用完全自定义的代码替换它们，以实现我们想要的精确效果。渲染的所有阶段形成了我们所说的着色器管道，一系列应用于输入数据的修改，直到它被转换为像素。

重要说明

有时，在本书中我们所说的着色器管道也可以在其他文献中被称为渲染管道，而后者也是正确的，在 Unity 中，渲染管道这个术语指的是不同的东西，所以让我们坚持这个名字。

管道的每个阶段负责不同的修改，根据显卡着色器模型的不同，这个管道可能会有很大的变化。在下一个图表中，您可以找到一个简化的渲染管道，跳过了现在不重要的高级/可选阶段：

![图 6.1 – 常见着色器管道](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.01_B14199.jpg)

图 6.1 – 常见着色器管道

让我们讨论每个阶段：

+   **输入组装器**：这里是所有网格数据的组装地方，例如顶点位置、UV 和法线，准备好进行下一阶段。在这里你不能做太多事情；这个过程几乎总是一样的。

+   **顶点着色器**：过去，这个阶段仅限于应用对象的变换、相机的位置和透视以及一些简单但有限的光照计算。使用现代 GPU，您可以自行决定。这个阶段接收要渲染的对象的每一个顶点，并输出一个修改过的顶点，因此基本上您有机会在这里修改对象的几何形状。这里的通常代码基本上与旧视频卡的代码相同，应用对象的变换，但您可以进行多种效果，比如沿着法线膨胀对象以应用旧的卡通效果技术，或者应用一些扭曲效果以制作全息效果（看看*死亡搁浅*中的全息效果）。还有机会计算下一个阶段的数据，但我们暂时不会深入讨论。

+   **裁剪**：对于大多数要渲染的模型，您永远不会看到模型面的背面。以立方体为例；无论如何都无法看到任何一面的背面或内侧，因为它们会被其他面自动遮挡。因此，渲染立方体每个面的两面，即使看不到背面，也是没有意义的，幸运的是，这个阶段会处理这个问题。裁剪将根据面的方向确定是否需要渲染面，从而节省了遮挡面的大量像素计算。您可以根据特定情况更改这一行为；例如，我们可以创建一个需要透明的玻璃箱，以便看到箱子的所有侧面。

+   **光栅化器**：现在我们已经计算出了修改过的可见几何模型，是时候将其转换为像素了。光栅化器为我们的网格三角形创建所有像素。这里发生了很多事情，但我们对此几乎没有控制权；通常的光栅化方式是在网格三角形的边缘内创建所有像素。我们还有其他模式，只渲染边缘上的像素以实现线框效果，但这通常用于调试目的：

![图 6.2 - 光栅化的图例](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.02_B14199.jpg)

图 6.2 - 光栅化的图例

+   **片段着色器**：这是所有阶段中最可定制的阶段之一。它的目的很简单：确定光栅化器生成的每个片段（像素）的颜色。在这里，可以发生很多事情，从简单地输出纯色或对纹理进行采样到应用复杂的光照计算，比如法线贴图和 PBR。此外，您还可以使用这个阶段创建特殊效果，比如水动画、全息图、扭曲、解体和其他需要修改像素外观的特殊效果。我们将在本章的后续部分探讨如何使用这个阶段。

+   **深度测试**：在将像素视为完成之前，我们需要检查像素是否可见。这个阶段检查像素的深度是在之前渲染的像素的后面还是前面，确保无论对象的渲染顺序如何，相机最近的像素始终位于其他像素的顶部。同样，通常情况下，这个阶段保持默认状态，优先考虑靠近相机的像素，但有些效果需要不同的行为。例如，在下一个截图中，您可以看到一种效果，它允许您看到其他对象后面的对象，比如*帝国时代*中的单位和建筑：

![图 6.3 - 渲染角色的遮挡部分](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.03_B14199.jpg)

图 6.3 - 渲染角色的遮挡部分

+   **混合**：一旦确定了像素的颜色，并且我们确定像素没有被前一个像素遮挡，最后一步就是将其放入后备缓冲区（正在绘制的帧或图像）。通常的做法是覆盖该位置的任何像素（因为我们的像素更接近相机），但是如果考虑透明物体，我们需要将我们的像素与前一个像素结合起来，以产生透明效果。透明度除了混合之外还有其他要考虑的事情，但主要思想是混合控制像素将如何与后备缓冲区中先前渲染的像素结合。

着色器管线是一个需要整本书来讨论的主题，但在本书的范围内，前面的描述将让您对着色器的功能以及可能实现的效果有一个很好的了解。现在我们已经讨论了着色器如何渲染单个对象，值得讨论的是 Unity 如何使用渲染管线渲染所有对象。

## 渲染管线和 URP

我们已经介绍了视频卡如何渲染对象，但 Unity 负责要求视频卡对每个对象执行其着色器管线。为此，Unity 需要进行大量的准备和计算，以确定每个着色器需要何时以及如何执行。负责执行此操作的是 Unity 所谓的渲染管线。

渲染管线是绘制场景中对象的一种方式。起初，听起来似乎应该只有一种简单的方法来做到这一点，例如只需迭代场景中的所有对象，并使用每个对象材质中指定的着色器执行着色器管线，但实际上可能比这更复杂。通常，一个渲染管线与另一个之间的主要区别在于光照和一些高级效果的计算方式，但它们也可能在其他方面有所不同。

在以前的 Unity 版本中，只有一个单一的渲染管线，现在称为内置渲染管线。它是一个具有您在各种项目中所需的所有可能功能的管线，从移动 2D 图形和简单 3D 图形到主机或高端 PC 上可以找到的尖端 3D 图形。这听起来很理想，但实际上并非如此；拥有一个单一的巨大渲染器，需要高度可定制以适应所有可能情况，会产生大量的开销和限制，导致比创建自定义渲染管线更头疼。幸运的是，Unity 的最新版本引入了**可编程渲染管线**（SRP），一种为您的项目创建适用的渲染管线的方法。

幸运的是，Unity 不希望您为每个项目创建自己的渲染管线（这是一项复杂的任务），因此它为您创建了两个定制的管线，可以立即使用：URP（以前称为 LWRP），代表通用渲染管线，以及 HDRP，代表高清晰度渲染管线。其想法是您必须根据项目要求选择其中一个（除非您真的需要创建自己的）。URP 是我们为游戏创建项目时选择的一个渲染管线，适用于大多数不需要大量高级图形功能的游戏，例如移动游戏或简单的 PC 游戏，而 HDRP 则具有许多高级渲染功能，适用于高质量游戏。后者需要高端硬件才能运行，而 URP 可以在几乎所有相关目标设备上运行。值得一提的是，您可以随时在内置渲染器、HDRP 和 URP 之间切换，包括在创建项目后（不建议）：

![图 6.4 – 项目向导显示 HDRP 和 URP 模板](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.04_B14199.jpg)

图 6.4 – 项目向导显示 HDRP 和 URP 模板

我们可以讨论每个着色器是如何实现的以及它们之间的区别，但是这可能会填满整整一章；现在，这一部分的想法是让你知道为什么我们在创建项目时选择了 URP，因为它有一些限制，我们将在本书中遇到这些限制，所以了解为什么我们接受了这些限制是很重要的（为了在所有相关的硬件上运行我们的游戏）。此外，我们需要知道我们选择了 URP 是因为它支持 Shader Graph，这是 Unity 工具，我们将在本章中使用它来创建自定义效果。以前的 Unity 内置管线没有为我们提供这样的工具（除了第三方插件）。最后，介绍 URP 的概念的另一个原因是它带有许多内置的着色器，我们需要在创建自己的着色器之前了解这些着色器，以避免重复造轮子，并且要适应这些着色器，因为如果你来自以前的 Unity 版本，你所了解的着色器在这里不起作用，实际上这正是我们将在本书的下一部分讨论的内容：不同 URP 内置着色器之间的区别。

## URP 内置着色器

现在我们知道了 URP 和其他管线之间的区别，让我们讨论一下哪些着色器集成到了 URP 中。让我们简要描述一下这个管线中最重要的三个着色器：

+   **Lit**：这是旧的 Standard Shader 的替代品。当创建各种真实的物理材料时，比如木头、橡胶、金属、皮肤以及它们的组合（比如皮肤和金属盔甲的角色）时，这个着色器非常有用。它支持法线贴图、遮挡、金属和高光工作流程以及透明度。

+   **Simple Lit**：这是旧的 Mobile/Diffuse Shader 的替代品。顾名思义，这个着色器是 Lit 的简化版本，意味着它的光照计算是光照工作的简化近似，比其对应物少了一些功能。基本上，当你有简单的图形而没有真实的光照效果时，这是最好的选择。

+   **Unlit**：这是旧的 Unlit/Texture Shader 的替代品。有时，你需要没有任何光照的对象，在这种情况下，这就是适合你的着色器。没有光照并不意味着没有光或完全黑暗；实际上，这意味着对象根本没有阴影，并且完全可见而没有任何阴影。一些简单的图形可以使用这个，依赖于阴影被烘焙在纹理中，这意味着纹理带有阴影。这是非常高效的，特别是对于移动电话等低端设备。此外，你还有其他情况，比如光管或屏幕，这些对象不能接收阴影，因为它们发出光，所以即使在完全黑暗中也会以全彩色显示。在下面的截图中，你可以看到一个使用 Unlit Shader 的 3D 模型。它看起来像是被照亮了，但实际上只是模型的纹理在对象的不同部分应用了较浅和较深的颜色：

![图 6.5 - 使用无光效果模拟廉价照明的 Pod](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.05_B14199.jpg)

图 6.5 - 使用无光效果模拟廉价照明的 Pod

让我们使用 Simple Lit Shader 做一个有趣的分解效果来展示它的能力。你必须做以下操作：

1.  从任何搜索引擎下载并导入**Cloud Noise**纹理：![图 6.6 - 噪音纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.06_B14199.jpg)

图 6.6 - 噪音纹理

1.  在项目面板中选择最近导入的纹理。

1.  在检查器中，将**Alpha Source**属性设置为**From Gray Scale**。这意味着纹理的 alpha 通道将根据图像的灰度计算：![图 6.7 - 从灰度纹理生成 Alpha 纹理设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.07_B14199.jpg)

图 6.7 - 从灰度纹理生成 Alpha 纹理设置

重要提示

颜色的 Alpha 通道通常与透明度相关联，但您会注意到我们的物体不会是透明的。Alpha 通道是额外的颜色数据，可以在进行效果时用于多种目的。在这种情况下，我们将使用它来确定哪些像素首先被解体。

1.  通过单击项目视图中的**+**图标并选择**Material**来创建一个材质：![图 6.8 – 材质创建按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.08_B14199.jpg)

图 6.8 – 材质创建按钮

1.  使用 Unity 顶部菜单中的**GameObject | 3d Object | Cube**选项创建一个立方体：![图 6.9 – 创建立方体原语](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.09_B14199.jpg)

图 6.9 – 创建立方体原语

1.  从项目窗口将创建的材质拖动到立方体上应用材质。

1.  单击检查器中 Shader 属性右侧的下拉菜单，并搜索**Universal Render Pipeline | Simple Lit**选项：![图 6.10 – 简单光照着色器选择](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.10_B14199.jpg)

图 6.10 – 简单光照着色器选择

1.  选择**Material**，在**Base Map**中设置最近下载的 Cloud Noise Texture。

1.  检查`0.5`：![图 6.11 阿尔法剪裁阈值材质滑块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.11_B14199.jpg)

图 6.11 Alpha Clipping 阈值材质滑块

1.  当您移动 Alpha Clipping 滑块时，您会看到物体开始崩解。Alpha Clipping 会丢弃比样式值具有更低 Alpha 强度的像素：![图 6.12 带有 Alpha Clipping 的崩解效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.12_B14199.jpg)

图 6.12 带有 Alpha Clipping 的崩解效果

1.  最后，将**Render Face**设置为**Both**以关闭**Culling Shader Stage**并查看立方体面的两侧：![图 6.13 双面 Alpha Clipping](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.13_B14199.jpg)

图 6.13 双面 Alpha Clipping

1.  请注意，创建纹理的艺术家可以手动配置 Alpha 通道，而不是从灰度计算，只是为了精确控制崩解效果的外观，而不考虑纹理的颜色分布。

本节的目的不是全面介绍所有 URP Shader 的所有属性，而是让您了解当正确配置 Shader 时 Shader 可以做什么，以及何时使用每个集成 Shader。有时，您可以通过使用现有的 Shader 来实现所需的效果。实际上，在简单的游戏中，您可能可以在 99%的情况下使用现有的 Shader。因此，请尽量坚持使用它们。但是，如果确实需要创建自定义 Shader 来创建非常特定的效果，下一节将教您如何使用名为 Shader Graph 的 URP 工具。

# 使用 Shader Graph 创建 Shader

现在我们知道了 Shader 的工作原理以及 URP 中现有的 Shader，我们对何时需要创建自定义 Shader 以及何时不需要有了基本概念。如果确实需要创建一个，本节将介绍使用 Shader Graph 创建效果的基础知识，Shader Graph 是一种使用可视化节点编辑器创建效果的工具，在您不习惯编码时使用起来非常方便。

在本节中，我们将讨论 Shader Graph 的以下概念：

+   创建我们的第一个 Shader Graph

+   使用纹理

+   组合纹理

+   应用透明度

让我们开始看看如何创建和使用 Shader Graph。

## 创建我们的第一个 Shader Graph 资产

Shader Graph 是一种工具，允许我们使用基于节点的系统创建自定义效果。Shader Graph 中的效果可能看起来像以下截图，您可以看到创建全息效果所需的节点：

![图 6.14 带有节点的 Shader Graph 以创建自定义效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.14_B14199.jpg)

图 6.14 Shader Graph 带有节点以创建自定义效果

我们稍后将讨论这些节点的作用，并进行逐步的效果示例，但在屏幕截图中，您可以看到作者创建并连接了几个节点，这些节点是相互连接的框，每个节点都执行特定的过程以实现效果。使用 Shader Graph 创建效果的想法是学习您需要哪些特定节点以及如何正确连接它们，以创建一个“算法”或一系列有序的步骤来实现特定的结果。这类似于我们编写游戏玩法的方式，但这个图表是专门为效果目的而调整和简化的。

要创建和编辑我们的第一个 Shader Graph 资产，请执行以下操作：

1.  在项目窗口中，单击**+**图标，然后找到**Shader | PBR Graph**选项。这将使用 PBR 模式创建一个 Shader Graph，这意味着这个 Shader 将支持照明效果（不像 Unlit Graphs）:![图 6.15 PBR Shader Graph 创建](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.15_B14199.jpg)

图 6.15 PBR Shader Graph 创建

1.  将其命名为`WaterGraph`。如果您错过了重命名资产的机会，请记住您可以选择资产，右键单击，然后选择**重命名**：![图 6.16 Shader Graph 资产](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.16_B14199.jpg)

图 6.16 Shader Graph 资产

1.  创建一个名为`WaterMaterial`的新材质，并将**Shader**设置为**Shader Graphs/Water**。如果由于某种原因 Unity 不允许您这样做，请尝试右键单击**WaterGraph**，然后单击**Reimport**。正如您所看到的，创建的 Shader Graph 资产现在显示为材质中的 Shader，这意味着我们已经创建了一个自定义 Shader:![图 6.17 将 Shader Graph 设置为材质 Shader](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.17_B14199.jpg)

图 6.17 将 Shader Graph 设置为材质 Shader

1.  使用**GameObject | 3d Object | Plane**选项创建一个平面。

1.  将**材质**拖动到**平面**上应用它。

现在，您已经创建了您的第一个自定义 Shader 并将其应用于材质。到目前为止，它看起来一点也不有趣——它只是一个灰色的效果，但现在是时候编辑图表以释放其全部潜力了。正如图表的名称所暗示的，本章中我们将创建一个水效果，以说明 Shader Graph 工具集的几个节点以及如何连接它们，因此让我们从讨论主节点开始。当您双击打开图表时，您将看到以下内容:

![图 6.18 具有计算对象外观所需的所有属性的主节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.18_B14199.jpg)

图 6.18 具有计算对象外观所需的所有属性的主节点

所有节点都有输入引脚，它们需要的数据，以及输出引脚，这是其过程的结果。例如，在求和运算中，我们将有两个输入数字和一个输出数字，即求和的结果。在这种情况下，您可以看到主节点只有输入，这是因为进入主节点的所有数据将被 Unity 用于计算对象的渲染和照明，诸如所需的对象颜色或纹理（反照率输入引脚），它有多光滑（光滑度输入引脚），或者它含有多少金属（金属输入引脚），因此它们都是将影响照明如何应用于对象的属性。在某种意义上，这个节点的输入是整个图的输出数据，也是我们需要填充的数据。

让我们开始探索如何通过以下方式更改输出数据:

1.  双击**Shader Graph**以打开其编辑窗口。

1.  单击**Albedo**输入引脚左侧的灰色矩形:![图 6.19 反照率主节点输入引脚](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.19_B14199.jpg)

图 6.19 反照率主节点输入引脚

1.  在颜色选择器中，选择浅蓝色，就像水一样。选择选择器周围的蓝色部分，然后在中间矩形中选择该颜色的一种色调:![图 6.20 颜色选择器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.20_B14199.jpg)

图 6.20 颜色选择器

1.  设置`0.9`：![图 6.21 光滑度 PBR 主节点输入引脚](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.21_B14199.jpg)

图 6.21 光滑度 PBR 主节点输入引脚

1.  单击窗口左上角的**保存资源**按钮：![图 6.22 Shader Graph 保存选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.22_B14199.jpg)

图 6.22 Shader Graph 保存选项

1.  返回到场景视图，检查平面是否为浅蓝色，并且有太阳的反射：

![图 6.23 初始 Shader Graph 结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.23_B14199.jpg)

图 6.23 初始 Shader Graph 结果

如您所见，着色器的行为根据您在主节点中设置的属性而变化，但到目前为止，这与创建无光着色器并设置其属性没有什么不同；Shader Graph 的真正威力在于当您使用执行特定计算的节点作为主节点的输入时。我们将开始看到纹理节点，它们允许我们将纹理应用到我们的模型上。

# 使用纹理

使用纹理的想法是以一种方式将图像应用于模型，这意味着我们可以用不同的颜色涂抹模型的不同部分。请记住，模型有 UV 映射，这使得 Unity 知道纹理的哪个部分将应用于模型的哪个部分：

![图 6.24 左侧是面部纹理；右侧是应用于面部网格的相同纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.24_B14199.jpg)

图 6.24 左侧是面部纹理；右侧是应用于面部网格的相同纹理

我们有几个节点来执行此任务，其中之一是 Sample Texture 2D，这是一个具有两个主要输入的节点。首先，它要求我们提供要对模型进行采样或应用的纹理，然后是 UV。您可以在以下截图中看到它：

![图 6.25 Sample Texture 节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.25_B14199.jpg)

图 6.25 Sample Texture 节点

如您所见，纹理输入节点的默认值为**None**，因此默认情况下没有纹理，我们需要手动指定。对于 UV，默认值为 UV0，这意味着默认情况下，节点将使用模型的主 UV 通道，是的，一个模型可以设置多个 UV，但现在我们将坚持使用主要的 UV。让我们尝试这个节点，执行以下操作：

1.  从互联网上下载并导入**可平铺的水纹理**：![图 6.26 可平铺的水纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.26_B14199.jpg)

图 6.26 可平铺的水纹理

1.  选择纹理，并确保纹理的**包裹模式**属性为**重复**，这将允许我们像在地形中那样重复纹理，因为想法是使用此着色器覆盖大水域：![图 6.27 纹理重复模式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.27_B14199.jpg)

图 6.27 纹理重复模式

1.  在**水着色器图**中，在**Shader Graph**的空白区域右键单击并选择**创建节点**：![图 6.28 Shader Graph 创建节点选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.28_B14199.jpg)

图 6.28 Shader Graph 创建节点选项

1.  在搜索框中，写入`Sample texture`，所有的示例节点都会显示出来。双击选择**Sample Texture 2D**：![图 6.29 Sample texture 节点搜索](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.29_B14199.jpg)

图 6.29 Sample texture 节点搜索

1.  单击 Sample Texture 2D 节点的纹理输入引脚左侧的圆圈。这将允许我们选择要采样的纹理—只需选择水纹理。您可以看到纹理可以在节点的底部部分预览：![图 6.30 带有输入引脚中纹理的 Sample Texture 节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.30_B14199.jpg)

图 6.30 带有输入引脚中纹理的 Sample Texture 节点

1.  将**Sample Texture 2D**节点的**RGBA**输出引脚拖动到主节点的**Albedo**输入引脚：![图 6.31 连接纹理采样的结果与主节点的反照率引脚](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.31_B14199.jpg)

图 6.31 连接纹理采样的结果与主节点的反照率引脚

1.  单击 Shader Graph 编辑器左上角的**保存资源**按钮，查看场景视图中的更改：

![图 6.32 应用纹理在我们的 Shader Graph 中的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.32_B14199.jpg)

图 6.32 应用纹理在我们的着色器图中的结果

如你所见，纹理已经正确应用到了模型，但是如果考虑到默认平面的大小是 10x10 米，水波似乎太大了，所以让我们平铺纹理！为此，我们需要改变模型的 UV，使它们变大。更大的 UV 听起来意味着纹理也应该变大，但要考虑到我们并没有使物体变大；我们只是修改了 UV，所以相同的物体大小将读取更多的纹理，这意味着更大的纹理采样区域将使纹理重复，并将它们放在相同的物体大小内，因此将被压缩在模型区域内。为此，请按照以下步骤进行：

1.  右键单击任何空白区域，然后单击**新建节点**来搜索 UV 节点：![图 6.33 寻找 UV 节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.33_B14199.jpg)

图 6.33 寻找 UV 节点

1.  使用相同的方法创建一个**乘以**节点。

1.  设置`4`,`4`,`4`,`4`):![图 6.34 将 UV 乘以 4](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.34_B14199.jpg)

图 6.34 将 UV 乘以 4

1.  将 UV 节点的**Out**引脚拖动到**乘以**节点的**A**引脚上连接它们。

1.  将**乘以**节点的**Out**引脚拖动到**采样纹理 2D**节点的**UV**引脚上连接它们：![图 6.35 使用乘以后的 UV 来采样纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.35_B14199.jpg)

图 6.35 使用乘以后的 UV 来采样纹理

1.  如果你保存了图表并返回到场景视图，你会看到现在涟漪变小了，因为我们已经平铺了模型的 UV。你还可以在**采样纹理 2D**节点的预览中看到：

![图 6.36 模型 UV 乘法的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.36_B14199.jpg)

图 6.36 模型 UV 乘法的结果

现在我们可以做另一个有趣的效果，就是对纹理应用偏移来移动它。即使平面实际上并没有移动，我们也会通过移动纹理来模拟水流动，只是移动纹理。记住，确定纹理的哪一部分应用到模型的哪一部分的责任属于 UV，所以如果我们给 UV 坐标添加值，我们将移动它们，产生纹理滑动效果。为此，让我们按照以下步骤进行：

1.  在**乘以**节点的右侧创建一个**Add**节点。

1.  将 UV 的**Out**引脚连接到**Add**节点的**A**引脚：![图 6.37 给 UV 添加值](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.37_B14199.jpg)

图 6.37 给 UV 添加值

1.  在**Add**节点的左侧创建一个**Time**节点。

1.  将**Time**节点连接到**Add**节点的**B**引脚：![图 6.38 给 UV 添加时间](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.38_B14199.jpg)

图 6.38 给 UV 添加时间

1.  将**Add**节点的**Out**引脚连接到**乘以**节点的**A**输入引脚：![图 6.39 添加和乘以 UV 作为采样纹理的输入](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.39_B14199.jpg)

图 6.39 添加和乘以 UV 作为采样纹理的输入

1.  保存并在场景视图中看到水流动。

1.  如果你觉得水流动得太快，尝试使用乘法节点使时间变小。我建议你在查看下一个屏幕截图之前自己尝试一下，那里有答案：![图 6.40 时间乘法以加快移动速度](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.40_B14199.jpg)

图 6.40 时间乘法以加快移动速度

1.  如果你觉得图表开始变得更大，尝试通过点击预览上出现的上箭头来隐藏一些节点的预览：

![图 6.41 隐藏图表节点的预览和未使用的引脚](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.41_B14199.jpg)

图 6.41 隐藏图表节点的预览和未使用的引脚

因此，简而言之，首先我们将时间添加到 UV 中以移动它，然后将移动后的 UV 的结果乘以使其变大以平铺纹理。值得一提的是，有一个平铺和偏移节点可以为我们完成所有这些工作，但我想向您展示一个简单的乘法来缩放 UV 和一个加法操作来移动它是如何产生一个不错的效果的；您无法想象使用其他简单数学节点可以实现的所有可能效果！实际上，让我们在下一节中探索数学节点的其他用途，以组合纹理。

# 组合纹理

尽管我们使用了节点，但我们并没有创建任何不能使用常规着色器创建的东西，但这将发生改变。到目前为止，我们可以看到水在移动，但它看起来仍然是静态的，这是因为涟漪总是相同的。我们有几种生成涟漪的技术，最简单的一种是将两个以不同方向移动的水纹理组合在一起以混合它们的涟漪，实际上，我们可以简单地使用相同的纹理，只是翻转了一下，以节省一些内存。为了组合这些纹理，我们将它们相加，然后除以 2，所以基本上，我们正在计算纹理的平均值！让我们通过以下方式来做到这一点:

1.  选择**时间**和**采样器 2D**之间的所有节点（包括它们），通过单击图表中的任何空白处创建一个选择矩形，按住并拖动单击，然后在所有目标节点都被覆盖时释放:![图 6.42 选择多个节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.42_B14199.jpg)

图 6.42 选择多个节点

1.  右键单击并选择**复制**，然后再次右键单击并选择**粘贴**，或使用经典的*Ctrl* + *C*，*Ctrl* + *V*命令（Mac 中为*command* + *C*，*command* + *V*），或只需*Ctrl* + *D*（*command* + *D*）。

1.  将复制的节点移动到原始节点下方:![图 6.43 节点的复制](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.43_B14199.jpg)

图 6.43 节点的复制

1.  对于复制的节点，设置为`-4`,`-4`,`-4`,`-4`)。您可以看到纹理已经翻转了。

1.  还要设置为`-0.1`:![图 6.44 值的乘法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.44_B14199.jpg)

图 6.44 值的乘法

1.  在两个采样器纹理 2D 节点的右侧创建一个**加法**节点，并将这些节点的输出连接到**加法**节点的**A**和**B**输入引脚:![图 6.45 添加两个纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.45_B14199.jpg)

图 6.45 添加两个纹理

1.  您可以看到，由于我们对两种纹理的强度进行了求和，所以得到的组合太亮了，让我们通过乘以`0.5,0.5,0.5,0.5`来修复这个问题，这将把每个结果颜色通道除以 2，从而平均颜色:![图 6.46 将两个纹理的总和除以得到平均值](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.46_B14199.jpg)

图 6.46 将两个纹理的总和除以得到平均值

1.  将**乘法**节点的**输出**引脚连接到主节点的**反照率**引脚，以将所有这些计算应用为对象的颜色。

1.  保存**资产**并在场景视图中查看结果:

![图 6.47 纹理混合的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.47_B14199.jpg)

图 6.47 纹理混合的结果

您可以继续添加节点以使效果更加多样化，例如使用正弦节点应用非线性运动等，但我会让您自己通过实验来学习。现在，我们就到这里。一如既往，这个主题值得一本完整的书，本章的目的是让您对这个强大的 Unity 工具有一个初步了解。我建议您在互联网上寻找其他 Shader Graph 示例，以了解相同节点的其他用法，当然还有新节点。需要考虑的一件事是，我们刚刚做的一切基本上都应用于我们之前讨论的 Shader Pipeline 的片段着色器阶段。现在，让我们使用混合着色器阶段为水应用一些透明度。

# 应用透明度

在宣布我们的效果完成之前，我们可以做一个小小的添加，让水变得稍微透明一点。记住，Shader Pipeline 有一个混合阶段，负责将我们模型的每个像素混合到当前帧渲染的图像中。我们的 Shader Graph 的想法是修改这个阶段，应用 Alpha 混合，根据我们模型的 Alpha 值将我们的模型与先前渲染的模型进行混合。为了实现这个效果，执行以下步骤：

1.  点击主节点右上角的轮子。

1.  将**表面属性**设置为**透明**。

1.  如果**Blend**属性不是 Alpha，请将其设置为**Alpha**：![图 6.48 PBR 主节点设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.48_B14199.jpg)

图 6.48 PBR 主节点设置

1.  将`0.5`设置为：![图 6.49 设置主节点的 Alpha](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.49_B14199.jpg)

图 6.49 设置主节点的 Alpha

1.  保存图表，查看透明度在场景视图中的应用。如果你看不到效果，只需在水中放一个立方体，使效果更加明显：![图 6.50 水的阴影应用到立方体上](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.50_B14199.jpg)

图 6.50 水的阴影应用到立方体上

1.  你可以看到水投射在我们立方体上的阴影。这是因为 Unity 没有检测到对象是透明的，所以它认为必须投射阴影，所以让我们禁用它们。点击水平面，在检视器中查找 Mesh Renderer 组件。

1.  在**照明**部分，将**投射阴影**设置为**关闭**；这将禁用平面的阴影投射：

![图 6.51 禁用投射阴影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.51_B14199.jpg)

图 6.51 禁用投射阴影

添加透明度是一个简单的过程，但也有其注意事项，比如阴影问题，在更复杂的场景中可能会有其他问题，所以我建议除非必要，否则避免使用透明度。实际上，我们的水可以不透明，特别是当我们将这种水应用到基地周围的河盆时，因为我们不需要看到水下的东西，但是我希望你知道所有的选择。在下一个截图中，你可以看到我们在基地下方放了一个巨大的平面，足够大以覆盖整个盆地：

![图 6.52 在主场景中使用我们的水](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_6.52_B14199.jpg)

图 6.52 在主场景中使用我们的水

# 总结

在本章中，我们讨论了 Shader 如何利用 GPU 工作，以及如何创建我们的第一个简单 Shader 来实现一个漂亮的水效果。使用 Shader 是一项复杂而有趣的工作，在团队中通常有一名或多名负责创建所有这些效果的人，这个职位被称为技术艺术家；所以，你可以看到，这个话题可以扩展成一个完整的职业。请记住，本书的目的是让你对行业中可能承担的各种角色有一点点了解，所以如果你真的喜欢这个角色，我建议你开始阅读专门讨论 Shader 的书籍。你面前有一条漫长但非常有趣的道路。

但现在先不谈 Shader 了，让我们转到下一个话题，讨论如何通过粒子系统改善图形并创建视觉效果！


# 第七章：使用粒子系统和 VFX 图进行视觉效果

在这里，我们将继续学习关于我们游戏的视觉效果。我们将讨论粒子系统，一种模拟火、瀑布、烟雾和各种流体的方法。此外，我们将看到两种 Unity 粒子系统来创建这些效果，**Shuriken**和**VFX Graph**，后者比前者更强大，但需要更多的硬件。

在本章中，我们将讨论以下与粒子相关的概念：

+   粒子系统简介

+   创建流体模拟

+   使用 VFX 图创建复杂模拟

# 粒子系统简介

到目前为止，我们创建的所有图形和效果都使用静态网格，即无法扭曲、弯曲或以任何方式变形的 3D 模型。火和烟等**流体**显然不能用这种网格来表示，但实际上，我们可以通过静态网格的组合来模拟这些效果，这就是粒子系统有用的地方。

**粒子系统**是发射和动画大量**粒子**或**广告牌**的对象，这些广告牌是朝向摄像机的简单四边形网格。每个粒子都是一个静态网格，但渲染、动画和组合大量粒子可以产生流体的错觉。在下图中，您可以在左侧看到使用粒子系统的烟雾效果，右侧是相同粒子的**线框**视图。在那里，您可以看到创建烟雾错觉的四边形，这是通过将烟雾纹理应用到每个粒子并使它们在底部生成并朝着随机方向移动来实现的：

![图 7.1-左侧，烟雾粒子系统；右侧，相同系统的线框图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.01_B14199.jpg)

图 7.1-左侧，烟雾粒子系统；右侧，相同系统的线框图

在本节中，我们将涵盖与粒子相关的以下概念：

+   创建基本粒子系统

+   使用高级模块

让我们开始讨论如何创建我们的第一个粒子系统。

## 创建基本粒子系统

为了说明粒子系统的创建，让我们创建一个爆炸效果。想法是一次产生大量粒子并将它们朝各个方向扩散。让我们开始创建粒子系统并配置它提供的基本设置以更改其默认行为。为此，请按照以下步骤操作：

1.  选择**GameObject** | **Effects** | **Particle System**选项：![图 7.2-粒子系统创建按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.02_B14199.jpg)

图 7.2-粒子系统创建按钮

1.  您应该在以下截图中看到效果。默认行为是一列粒子向上移动，就像之前显示的烟雾效果一样。让我们改变一下：![图 7.3-默认粒子系统外观](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.03_B14199.jpg)

图 7.3-默认粒子系统外观

1.  单击场景中创建的对象，查看检查器。

1.  通过单击标题打开**形状**部分。

1.  将**形状**属性更改为**球体**。现在粒子应该在所有可能的方向上移动，而不是遵循默认的锥形：![图 7.4-形状属性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.04_B14199.jpg)

图 7.4-形状属性

1.  在粒子系统`10`中。这将使粒子移动得更快。

1.  在相同的模块中，设置`0.5`。这指定了粒子的寿命。在这种情况下，我们给了半秒的寿命。结合速度（每秒 10 米），这使得粒子在移动 5 米后消失：![图 7.5-主粒子系统模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.05_B14199.jpg)

图 7.5-主粒子系统模块

1.  打开`0`。这个属性指定每秒将发射多少粒子，但对于爆炸，实际上我们需要一团粒子，所以在这种情况下我们不会持续不断地发射粒子。

1.  在`100`中：![图 7.6-发射模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.06_B14199.jpg)

图 7.6-发射模块

1.  在主模块（标题为`1`）中取消选中**循环**。在我们的情况下，爆炸不会不断重复；我们只需要一个爆炸：![图 7.7 – 循环复选框](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.07_B14199.jpg)

图 7.7 – 循环复选框

1.  现在粒子不再循环，您需要手动点击**粒子效果**窗口右下角的**播放**按钮来查看系统：![图 7.8 – 粒子系统播放控件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.08_B14199.jpg)

图 7.8 – 粒子系统播放控件

1.  将**停止动作**设置为**销毁**。当**持续时间**过去时，这将销毁对象。这只在游戏运行时有效，因此您可以在编辑场景时安全地使用此配置：![图 7.9 – 停止动作设置为销毁](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.09_B14199.jpg)

图 7.9 – 停止动作设置为销毁

1.  设置`3`。这将使粒子变大，看起来更密集：![图 7.10 – 粒子系统开始大小](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.10_B14199.jpg)

图 7.10 – 粒子系统开始大小

1.  单击主模块的**开始旋转**属性右侧的向下箭头，并选择**两个常数之间的随机值**。

1.  在上一步骤之后出现的两个输入值中设置`0`和`360`。这样可以使粒子在生成时具有随机旋转，使它们看起来略有不同：![图 7.11 – 随机开始旋转](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.11_B14199.jpg)

图 7.11 – 随机开始旋转

1.  现在粒子的行为符合预期，但外观不符合预期。让我们改变一下。通过点击`爆炸`创建一个新材质。

1.  将其着色器设置为`Universal Render Pipeline/Particles/Unlit`。这是一种特殊的着色器，用于将纹理应用到 Shuriken 粒子系统：![图 7.12 – 粒子系统材质着色器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.12_B14199.jpg)

图 7.12 – 粒子系统材质着色器

1.  从互联网或**资产商店**下载烟雾粒子纹理。在这种情况下，重要的是下载带有黑色背景的纹理；忽略其他的：![图 7.13 – 烟雾粒子纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.13_B14199.jpg)

图 7.13 – 烟雾粒子纹理

1.  将此纹理设置为材质的**基本贴图**。

1.  将**表面类型**设置为**透明**，**混合模式**设置为**加法**。这样做将使粒子相互混合，而不是相互绘制，以模拟一大团烟雾而不是单个烟雾。我们使用**加法**模式，因为我们的纹理有黑色背景，而且我们想要创建一种光照效果（爆炸会照亮场景）：![图 7.14 – 粒子的表面选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.14_B14199.jpg)

图 7.14 – 粒子的表面选项

1.  将您的材质拖到**渲染器**模块的**材质**属性中：![图 7.15 – 粒子材质设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.15_B14199.jpg)

图 7.15 – 粒子材质设置

1.  现在您的系统应该是这样的：

![图 7.16 – 前面设置的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.16_B14199.jpg)

图 7.16 – 前面设置的结果

在前面的步骤中，我们已经改变了粒子或广告牌的生成方式（使用发射模块），它们将朝向哪个方向移动（使用形状模块），它们将以多快的速度移动，它们将持续多久，它们将有多大（使用主模块），以及它们将看起来像什么（使用渲染器模块）。创建粒子系统就是正确配置它们不同设置的简单情况。当然，正确地做这件事本身就是一门艺术；它需要创造力和对如何使用它们提供的所有设置和配置的知识。因此，为了增加我们的配置工具箱，让我们讨论一些高级模块。

## 使用高级模块

我们的系统看起来不错，但我们可以大大改进它，所以让我们启用一些新模块来提高其质量：

1.  点击**颜色随生命周期**模块左侧的复选框以启用它：![图 7.17 - 启用颜色随生命周期模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.17_B14199.jpg)

图 7.17 - 启用颜色随生命周期模块

1.  通过点击标题打开模块，并点击**颜色**属性右侧的白色条。这将打开渐变编辑器。

1.  点击白色标记栏的左上方略微向右侧，创建一个新的标记。同时，点击白色标记的右上方略微向左侧，创建第四个标记。这些标记将允许我们在粒子生命周期中指定透明度：![图 7.18 - 颜色随生命周期渐变编辑器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.18_B14199.jpg)

图 7.18 - 颜色随生命周期渐变编辑器

1.  如果创建了不需要的标记，只需将它们拖到窗口外即可删除。

1.  点击左上角的标记（不是我们创建的那个，而是已经存在的那个）并设置为`0`。对右上角的标记也做同样的操作，如下图所示。现在你应该看到粒子在爆炸结束时淡出而不是突然消失：![图 7.19 - 渐变淡入和淡出](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.19_B14199.jpg)

图 7.19 - 渐变淡入和淡出

1.  通过点击其复选框启用**限制生命周期内的速度**模块。

1.  设置为`0.1`。这将使粒子慢慢停止而不是继续移动：![图 7.20 - 减弱速度以使粒子停止](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.20_B14199.jpg)

图 7.20 - 减弱速度以使粒子停止

1.  启用`-90`和`90`。记住，你应该通过点击属性右侧的向下箭头来设置**两个常数之间的随机值**。现在粒子在它们的生命周期中应该稍微旋转，以模拟更多的运动：

![图 7.21 - 随机旋转速度](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.21_B14199.jpg)

图 7.21 - 随机旋转速度

正如你所看到的，有许多额外的模块可以启用和禁用，以在现有模块之上添加行为层，因此，再次创造性地使用它们来创建各种效果。记住，你可以创建这些系统的预制件，以在整个场景中复制它们。我还建议在资产商店搜索和下载粒子效果，看看其他人如何使用相同的系统来创建惊人的效果。这是学习如何创建它们的最佳方式，看到各种不同的系统，这实际上也是我们将在下一节中要做的事情，创建更多的系统！

# 创建流体模拟

正如我们所说，学习如何创建粒子系统的最佳方式是继续寻找已经创建的粒子系统，并探索人们如何使用各种系统设置来创建完全不同的模拟。

在本节中，我们将看到如何使用粒子系统创建以下效果：

+   瀑布效果

+   篝火效果

让我们从最简单的瀑布效果开始。

## 创建瀑布效果

为了做到这一点，请按照以下步骤进行：

1.  创建一个新的粒子系统（**GameObject** | **Effects** | **Particle System**）。

1.  将**形状**设置为**边缘**，并将**半径**设置为**5**在**形状**模块中。这将使粒子沿着一个发射线产生：![图 7.22 - 边缘形状](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.22_B14199.jpg)

图 7.22 - 边缘形状

1.  设置为`50`。

1.  设置为`3`和`3`：![图 7.23 - 主模块设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.23_B14199.jpg)

图 7.23 - 主模块设置

1.  设置为`0.5`。这将使粒子下落：![图 7.24 - 主模块中的重力修饰器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.24_B14199.jpg)

图 7.24 - 主模块中的重力修饰器

1.  使用我们之前为这个系统创建的`爆炸`材质：![图 7.25 - 爆炸粒子材质](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.25_B14199.jpg)

图 7.25 - 爆炸粒子材质

1.  启用**颜色随生命周期**并打开**渐变**编辑器。

1.  单击右下角的标记，这次你应该看到一个颜色选择器，而不是一个透明度滑块。顶部的标记允许您随时间改变透明度，而底部的标记则随时间改变粒子的颜色。在这个标记中设置浅蓝色：

![图 7.26 – 从白色到浅蓝色的渐变](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.26_B14199.jpg)

图 7.26 – 从白色到浅蓝色的渐变

作为挑战，我建议您在这个结束的地方添加一个小的粒子系统，以创建一些水花，模拟水与湖底碰撞。现在我们可以将这个粒子系统添加到我们场景中的一个山丘上进行装饰，就像下面的截图一样。我已经调整了系统，使其在这种情况下看起来更好。我挑战你自己调整它，使它看起来像这样：

![图 7.27 – 应用到我们当前场景中的瀑布粒子系统](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.27_B14199.jpg)

图 7.27 – 应用到我们当前场景中的瀑布粒子系统

现在，让我们创建另一个效果，一个篝火。

## 创建篝火效果

为了创建它，做以下操作：

1.  创建一个粒子系统。

1.  在互联网或资产商店上寻找**火焰粒子纹理表**纹理。这种纹理应该看起来像一个不同火焰纹理的网格。想法是将火焰动画应用到我们的粒子上，交换所有这些小纹理：![图 7.28 – 粒子纹理精灵表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.28_B14199.jpg)

图 7.28 – 粒子纹理精灵表

1.  创建一个粒子材质，并将此纹理设置为**基本贴图**。将**基本贴图**右侧的颜色设置为白色。然后将此材质设置为粒子材质。记得将**表面类型**设置为**透明**，**混合模式**设置为**叠加**：![图 7.29 – 带有粒子精灵表的材质](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.29_B14199.jpg)

图 7.29 – 带有粒子精灵表的材质

1.  在**Y**中启用`4`中的`4`。之后，您应该看到粒子交换纹理：![图 7.30 – 启用纹理表动画](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.30_B14199.jpg)

图 7.30 – 启用纹理表动画

1.  在主模块中设置`0`和`1.5`。

1.  在**形状**中设置`0.5`。

1.  创建第二个粒子系统，并将其设置为火系统的子对象：![图 7.31 – 粒子系统的父子关系](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.31_B14199.jpg)

图 7.31 – 粒子系统的父子关系

1.  应用爆炸示例中的烟雾材质。

1.  在**形状**中设置`0`和`0.5`。

1.  系统应该看起来像这样：

![图 7.32 – 结合火和烟粒子系统的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.32_B14199.jpg)

图 7.32 – 结合火和烟粒子系统的结果

正如您所看到的，您可以组合多个粒子系统来创建单个效果。在这样做时要小心，因为很容易发射太多的粒子并影响游戏的性能。粒子并不便宜，如果不小心使用，可能会导致游戏的**FPS（每秒帧数）**下降。

到目前为止，我们已经探索了 Unity 系统中的一个用于创建这种效果的系统，虽然这个系统对于大多数情况来说已经足够了，但 Unity 最近发布了一个新的系统，可以生成更复杂的效果，称为**VFX Graph**。让我们看看如何使用它，以及它与 Shuriken 有何不同。

# 使用 VFX Graph 创建复杂的模拟

到目前为止，我们使用的粒子系统称为 Shuriken，它在 CPU 中处理所有计算。这既有优点也有缺点。优点是它可以在 Unity 支持的所有设备上运行，而不受它们的能力限制（它们都有 CPU），但缺点是如果我们不小心发射太多粒子，很容易超出 CPU 的能力。现代游戏需要更复杂的粒子系统来生成可信的效果，而这种基于 CPU 的粒子系统解决方案已经开始达到极限。这就是 VFX Graph 的用武之地：

![图 7.33 – 左侧是一个大型粒子系统，右侧是 VFX 图的示例](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.33_B14199.jpg)

图 7.33 – 左侧是一个大型粒子系统，右侧是 VFX 图的示例

**VFX 图（视觉效果图）**是基于 GPU 的粒子系统解决方案，这意味着系统在视频卡上执行，而不是在 CPU 上执行。这是因为视频卡在执行许多小模拟方面要高效得多，就像系统的每个粒子所需的模拟一样，因此我们可以使用 GPU 比使用 CPU 实现更高数量级的粒子。这里的缺点是我们需要一个具有**计算着色器**功能的相当现代的 GPU 来支持此系统，因此我们将使用此系统排除某些目标平台（忘记大多数手机），因此只有在您的目标平台支持它时才使用它（中高端 PC、游戏机和一些高端手机）。

在本节中，我们将讨论 VFX 图的以下概念：

+   安装 VFX 图

+   创建和分析 VFX 图

+   创建雨效果

让我们开始看看如何在我们的项目中添加对 VFX 图的支持。

## 安装 VFX 图

到目前为止，我们已经使用了许多 Unity 功能，这些功能已经安装在我们的项目中，但是 Unity 可以通过各种官方和第三方插件进行扩展。VFX 图是其中之一，如果您使用**通用渲染管线（URP）**，则需要单独安装该功能。我们可以使用包管理器来完成这一点，包管理器是一个专门用于管理官方 Unity 插件的 Unity 窗口。

在安装这些软件包时需要考虑的一点是，每个软件包或插件都有自己的版本，与 Unity 版本无关。这意味着您可以安装 Unity 2020.1，但 VFX 图可以是 7.1.5 或 7.1.2 或任何您想要的版本，并且您实际上可以将软件包更新到新版本，而无需升级 Unity。这很重要，因为这些软件包的某些版本需要 Unity 的最低版本。此外，某些软件包依赖于其他软件包，实际上是这些软件包的特定版本，因此我们需要确保我们拥有每个软件包的正确版本以确保兼容性。需要明确的是，软件包的依赖关系会自动安装，但有时我们可以单独安装它们，因此在这种情况下，我们需要检查所需的版本。听起来很复杂，但实际上比听起来简单。

在撰写本书时，我正在使用 VFX 图版本 8.2.0，与 URP 相同的版本。是的，URP 是另一个您需要使用包管理器安装的功能，但是由于我们使用了 URP 模板创建项目，它已经为我们安装好了。关于版本，一个建议：在制作游戏期间，除非确有必要，否则永远不要更新 Unity 版本或软件包版本。升级通常会带来许多兼容性版本，这意味着在升级后，您的游戏的某些部分可能需要修复以符合这些软件包的新版本的工作方式。此外，请考虑一些软件包具有已验证标签，这意味着它已在我们的 Unity 版本中进行了测试，因此建议使用它。

现在，让我们按照以下步骤安装 VFX 图：

1.  在 Unity 的顶部菜单中，转到**窗口** | **包管理器**：![图 7.34 – 包管理器位置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.34_B14199.jpg)

图 7.34 – 包管理器位置

1.  在窗口左侧查找**视觉效果图**软件包。确保选择 8.2.0 或更高版本：![图 7.35 – 视觉效果图软件包](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.35_B14199.jpg)

图 7.35 – 视觉效果图软件包

1.  点击窗口右下角的**安装**按钮，等待软件包安装：![图 7.36 – 安装软件包按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.36_B14199.jpg)

图 7.36 – 安装软件包按钮

1.  建议在安装包后重新启动 Unity，所以保存你的更改并重新启动 Unity。

现在我们已经安装了 VFX 图形，让我们使用它来创建我们的第一个粒子系统。

## 创建和分析 VFX 图形

使用 VFX 图形创建粒子系统的理念与常规粒子系统类似。我们将链接和配置模块作为粒子行为的一部分，每个模块都添加一些特定的行为，但我们的做法与 Shuriken 有很大不同。首先，我们需要创建一个**视觉效果图形**，这是一个包含所有模块和配置的资产，然后让一个游戏对象播放这个图形。让我们按照以下步骤来做：

1.  在项目窗口中，点击**+**按钮，查找**视觉效果** | **视觉效果图形**：![图 7.37 - 视觉效果图形](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.37_B14199.jpg)

图 7.37 - 视觉效果图形

1.  使用**游戏对象** | **创建空**选项创建一个空游戏对象：![图 7.38 - 创建空游戏对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.38_B14199.jpg)

图 7.38 - 创建空游戏对象

1.  选择创建的对象并查看检查器。

1.  使用**添加组件**搜索栏，查找**可视效果**组件并点击它以将其添加到对象中：![图 7.39 - 向视觉效果图形添加组件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.39_B14199.jpg)

图 7.39 - 向视觉效果图形添加组件

1.  将我们创建的 VFX 资产拖到我们游戏对象的**可视效果**组件的**资产模板**属性中：![图 7.40 - 使用先前创建的 VFX 资产的可视效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.40_B14199.jpg)

图 7.40 - 使用先前创建的 VFX 资产的可视效果

1.  你应该看到时钟粒子从我们的对象中发射出来：

![图 7.41 - 默认 VFX 资产结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.41_B14199.jpg)

图 7.41 - 默认 VFX 资产结果

现在我们有了一个基本效果，让我们创建一些需要大量粒子的东西，比如密集的雨。在这样做之前，让我们探索一些 VFX 图形的核心概念。如果你双击可视效果资产，你会看到以下编辑器：

![图 7.42 - 可视效果图形编辑器窗口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.42_B14199.jpg)

图 7.42 - 可视效果图形编辑器窗口

这个窗口由几个相互连接的节点组成，生成要执行的操作流。起初，它似乎类似于着色器图，但它的工作方式有点不同，所以让我们研究一下默认图的每个部分。

要探索的第一个区域是包含三个节点的虚线区域。这就是 Unity 所谓的**系统**。系统是一组定义粒子行为的节点，你可以有任意多个，这相当于有几个粒子系统对象。每个系统由**上下文**组成，即虚线区域内的节点，在这种情况下，我们有**初始化粒子**、**更新粒子**和**输出粒子四边形**。每个上下文代表粒子系统逻辑流的不同阶段，所以让我们定义一下我们图中的每个上下文做什么：

+   **初始化粒子**：这定义了每个发射粒子的初始数据，如位置、颜色、速度和大小。这类似于本章开头看到的粒子系统的主模块中的起始属性。这个节点中的逻辑只有在发射新粒子时才会执行。

+   **更新粒子**：在这里，我们可以对活动粒子的数据应用修改。我们可以改变粒子数据，比如当前速度或大小，所有帧都可以。这类似于先前粒子系统的随时间节点。

+   **输出粒子四边形**：这个上下文将在需要渲染粒子时执行。它将读取粒子数据，看到在哪里渲染，如何渲染，使用哪个纹理和颜色，以及不同的视觉设置。这类似于先前粒子系统的渲染器模块。

除了一些基本配置外，我们可以在每个上下文中添加**块**。每个块都是在上下文中执行的操作。我们有一些可以在任何上下文中执行的操作，然后是一些特定的上下文操作。例如，我们可以在初始化粒子上下文中使用添加位置块来移动初始粒子位置，但如果我们在更新粒子上下文中使用相同的块，它将不断地移动粒子。因此，上下文是粒子生命周期中发生的不同情况，而块是在这些情况下执行的操作：

![图 7.43 – 在初始化粒子上下文中的设置速度随机块。这将设置粒子的初始速度](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.43_B14199.jpg)

图 7.43 – 在初始化粒子上下文中的设置速度随机块。这将设置粒子的初始速度

此外，我们可以有**独立上下文**，即系统之外的上下文，例如**生成**。这个上下文负责告诉系统需要创建一个新粒子。我们可以添加块来指定上下文何时告诉系统创建粒子，例如在固定时间内以固定速率、突发等。生成将根据其块创建粒子，而系统负责根据我们在每个上下文中设置的块来初始化、更新和渲染每个粒子。

因此，我们可以看到与 Shuriken 有很多相似之处，但在这里创建系统的方式是完全不同的。让我们通过创建一个雨效果来加强这一点，这将需要大量粒子，这是 VFX 图形的一个很好的使用案例。

## 创建雨效果

为了创建这种效果，执行以下操作：

1.  设置`10000`：![图 7.44 – 初始化粒子上下文](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.44_B14199.jpg)

图 7.44 – 初始化粒子上下文

1.  设置`10000`：![图 7.45 – 常量生成率块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.45_B14199.jpg)

图 7.45 – 常量生成率块

1.  在**初始化粒子**上下文中的**设置速度随机块**中分别设置`0`，`-50`，`0`）和（`0`，`-75`，`0`）。这将为我们的粒子设置一个指向下方的随机速度：![图 7.46 – 设置速度随机块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.46_B14199.jpg)

图 7.46 – 设置速度随机块

1.  单击**初始化粒子**标题以选择上下文，一旦突出显示，按空格键显示**添加块**窗口。

1.  搜索**设置位置随机**块并单击它：![图 7.47 – 添加块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.47_B14199.jpg)

图 7.47 – 添加块

1.  将`-50`，`0`，`-50`）和（`50`，`0`，`50`）分别设置。这将定义一个初始区域，以在其中随机生成粒子。

1.  单击`0`，`-12.5`，`0`）和（`100`，`25`，`100`）左侧的箭头。这将定义粒子应该存在的区域。粒子实际上可以移出这个区域，但这对系统正常工作很重要（在互联网上搜索`视锥体剔除`以获取更多信息）。

1.  选择执行系统的 GameObject，并在场景视图的右下窗口中选中**显示边界**复选框，以查看先前定义的边界：![图 7.48 – 视觉效果播放控制](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.48_B14199.jpg)

图 7.48 – 视觉效果播放控制

1.  将对象位置设置为覆盖整个基础区域。在我的案例中，位置是（`100`，`37`，`100`）。请记住，您需要更改**变换**组件的**位置**：![图 7.49 – 设置变换位置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.49_B14199.jpg)

图 7.49 – 设置变换位置

1.  设置`0.5`。这将使粒子的寿命更短，确保它们始终在边界内：![图 7.50 – 设置寿命随机块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.50_B14199.jpg)

图 7.50 – 设置寿命随机块

1.  将**输出粒子四边形**上下文的**主纹理**属性更改为另一个纹理。在这种情况下，之前下载的烟雾纹理可以在这里使用，即使它不是水，因为我们将在一会儿修改它的外观。另外，如果你愿意，你也可以尝试下载水滴纹理:![图 7.51 - VFX 图主纹理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.51_B14199.jpg)

图 7.51 - VFX 图主纹理

1.  将**输出粒子四边形**上下文的**混合模式**设置为**附加**：![图 7.52 - VFX 图的附加模式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.52_B14199.jpg)

图 7.52 - VFX 图的附加模式

1.  如果你看不到最后的更改被应用，点击窗口左上角的**编译**按钮。另外，你可以使用*Ctrl* + *S*（Mac 上为*Command* + *S*）保存你的更改:![图 7.53 - VFX 资产保存控制](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.53_B14199.jpg)

图 7.53 - VFX 资产保存控制

1.  现在我们需要稍微拉伸我们的粒子，使其看起来像真正的雨滴而不是下落的球。为此，首先我们需要改变粒子的方向，使它们不总是指向摄像机。为了做到这一点，右键单击**输出粒子四边形**上下文中的**定向块**，然后选择**删除**（或在 PC 上按*Delete*，在 Mac 上按*Command* + *Backspace*）:![图 7.54 - 删除块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.54_B14199.jpg)

图 7.54 - 删除块

1.  我们想根据它们的速度方向拉伸我们的粒子。为此，选择**输出粒子四边形**上下文的标题，然后按空格键查找要添加的块。在这种情况下，我们需要搜索**沿速度定向**块。

1.  添加`0.25`，`1.5`，`0.25`)。这将拉伸粒子，使其看起来像落下的水滴:![图 7.55 - 设置比例块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.55_B14199.jpg)

图 7.55 - 设置比例块

1.  再次点击窗口左上角的**编译**按钮，以查看更改。你的系统应该看起来像这样：

![图 7.56 - 雨结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_7.56_B14199.jpg)

图 7.56 - 雨结果

从这里开始，你可以根据自己的意愿向上下文中添加和删除块进行实验，我再次建议你寻找已经创建的视觉效果图，以找到其他系统的创意。实际上，你可以通过查看 Shuriken 中制作的效果并使用类似的块来获得 VFX 图的创意。另外，我建议你查看 VFX 图文档[`docs.unity3d.com/Packages/com.unity.visualeffectgraph@7.1/manual/index.html`](https://docs.unity3d.com/Packages/com.unity.visualeffectgraph@7.1/manual/index.html)以了解更多关于这个系统的信息。

# 总结

在本章中，我们讨论了使用 Shuriken 和 VFX 图创建粒子系统的两种不同方法。我们用它们来模拟不同的流体现象，如火、瀑布、烟雾和雨。这个想法是将粒子系统与网格相结合，生成场景所需的所有可能道具。另外，正如你可以想象的，专业地创建这些效果需要你深入了解。如果你想专注于这一点（技术艺术家的另一部分工作），你需要学会如何创建自己的粒子纹理，以获得你想要的精确外观和感觉，编写控制系统某些方面的代码脚本，以及粒子创建的其他几个方面。再次强调，这超出了本书的范围。

现在我们的场景中有了一些雨，我们可以看到天空和场景中的光线并不真正反映出雨天，所以让我们在下一章中解决这个问题！


# 第八章：使用通用渲染管线进行照明

**照明**是一个复杂的主题，有几种可能的处理方式，每种方式都有其优缺点。为了在最佳性能下获得最佳质量，您需要确切了解您的渲染器如何处理它，这正是我们将在本章中要做的。我们将讨论 Unity 的**通用渲染管线**（**URP**）中如何处理照明，以及如何正确配置它以适应我们场景的氛围和适当的照明效果。

在本章中，我们将研究以下照明概念：

+   应用照明

+   应用阴影

+   优化照明

# 应用照明

在讨论游戏中处理照明的方式时，我们可以使用两种主要方式，称为**前向渲染**和**延迟渲染**。两者以不同的顺序处理照明，具有不同的技术、要求、优缺点。前向渲染通常推荐用于性能，而延迟渲染通常推荐用于质量。后者被 Unity 的**高清晰度渲染管线**使用，这是用于高端设备高质量图形的渲染器。在撰写本书时，Unity 正在为 URP 开发一个高性能版本。此外，在 Unity 中，前向渲染有两种类型：**多通道前向**，用于内置渲染器（旧的 Unity 渲染器），以及**单通道前向**，用于 URP。同样，每种方法都有其优缺点。

重要信息

实际上，还有其他可用的选项，包括官方和第三方的选项，比如**顶点光照**，但暂时我们将专注于三种主要的选项 - 您 95%的时间使用的选项。

选择其中一种取决于您正在创建的游戏类型以及您需要在哪个目标平台上运行游戏。由于您应用照明到场景的方式，您选择的选项将发生很大变化，因此您必须了解您正在处理的系统。

在本节中，我们将讨论以下实时照明概念：

+   讨论照明方法

+   使用天空盒配置环境光照

+   在 URP 中配置照明

让我们开始比较先前提到的照明方法。

## 讨论照明方法

总之，我们提到了三种主要的处理照明的方式：

+   前向渲染（单通道）

+   前向渲染（多通道）

+   延迟渲染

在我们讨论它们之间的差异之前，让我们谈谈它们共同的特点。这三种渲染器都通过确定相机可以看到哪些对象来开始绘制场景；也就是说，那些落在相机截锥体内的对象，并在选择相机时提供一个巨大的金字塔。

![图 8.1 - 相机的截锥体只显示可以看到的对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.01_B14199.jpg)

图 8.1 - 相机的截锥体只显示可以看到的对象

之后，Unity 将按照距离相机最近到最远的顺序对它们进行排序（透明对象处理方式略有不同，但暂时忽略）。这样做是因为更有可能靠近相机的对象将覆盖大部分相机，因此它们将遮挡其他对象，防止我们浪费资源计算被遮挡的像素。

最后，Unity 将尝试按照这个顺序渲染对象。这就是光照方法之间开始出现差异的地方，所以让我们开始比较这两种前向渲染变体。对于每个对象，单次渲染将在一个绘制调用中计算对象的外观，包括所有影响对象的光源，或者我们称之为**绘制调用**。绘制调用是 Unity 要求显卡实际渲染指定对象的确切时刻。之前的所有工作只是为了这一刻做准备。在多次渲染前向渲染器的情况下，简化一点实际逻辑，Unity 将为影响对象的每个光源渲染一次对象。因此，如果对象受到三个光源的照明，Unity 将渲染对象三次，这意味着将发出三个绘制调用，并将执行渲染过程的 GPU 进行三次调用：

![图 8.2 – 左图，多次渲染中受两个光源影响的球体的第一个绘制调用；中间图，球体的第二个绘制调用；右图，两个绘制调用的组合](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.02_B14199(Merged).jpg)

图 8.2 – 左图，多次渲染中受两个光源影响的球体的第一个绘制调用；中间图，球体的第二个绘制调用；右图，两个绘制调用的组合

现在你可能在想，“为什么我要使用多次渲染？单次渲染更高效！”是的，你是对的！单次渲染比多次渲染更高效，这就是其中的好处。GPU 中的绘制调用有一定数量的操作可以执行，因此绘制调用的复杂度有限。计算对象的外观和所有影响它的光源是非常复杂的，为了使其适应一个绘制调用，单次渲染执行了简化版本的光照计算，这意味着光照质量和功能较少。它们还有一个限制，即一次只能处理多少个光源，目前写作本书时，每个对象的限制是八个（低端设备为四个）。这听起来像是一个小数字，但通常足够了。

另一方面，多次渲染可以应用任意数量的光源，并且可以为每个光源执行不同的逻辑。假设我们的物体受到四个光源的影响，但有两个光源对其影响很大，因为它们更近或强度更高，而其余的光源对物体的影响只是足够让人注意到。在这种情况下，我们可以使用更高质量的方式渲染前两个光源，而用廉价的计算渲染其余的光源——没有人能够察觉到区别。在这种情况下，多次渲染可以使用像素光照计算前两个光源，而使用顶点光照计算其余的光源。它们的区别在于它们的名称；像素光照按对象像素计算光照，而顶点光照按对象顶点计算光照，并填充这些顶点之间的像素，从而在顶点之间插值信息。您可以清楚地看到以下图像中的区别：

![图 8.3 – 左图，使用顶点光照渲染的球体；右图，使用像素光照渲染的球体)](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.03_B14199(Merged).jpg)

图 8.3 – 左图，使用顶点光照渲染的球体；右图，使用像素光照渲染的球体)

在单次渲染中，将所有内容都计算在一个绘制调用中会迫使你使用顶点光照或像素光照；你不能将它们结合起来。

因此，总结一下单通道和多通道之间的区别，在单通道中，性能更好，因为每个对象只绘制一次，但你只能应用有限数量的光照，而在多通道中，你需要多次渲染对象，但没有光照数量的限制，并且你可以为每个光源指定精确的质量。还有其他需要考虑的事情，比如绘制调用的实际成本（一个绘制调用可能比两个简单的绘制更昂贵），以及特殊的光照效果，比如卡通着色，但让我们保持简单。

最后，让我们简要讨论一下延迟渲染。尽管我们不打算使用它，但了解为什么我们不这样做是很有趣的。在确定哪些对象落在视锥体内并对它们进行排序之后，延迟将渲染对象而不进行任何光照，生成所谓的**G-Buffer**。G-Buffer 是一组包含有关场景对象的不同信息的图像，例如其像素的颜色（不带光照），每个像素的方向（称为**法线**），以及离摄像机的距离。你可以在以下图中看到 G-Buffer 的典型示例：

![图 8.4 - 左图，对象的纯色；中图，每个像素的深度；右图，像素的法线](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.04_B14199(Merged).jpg)

图 8.4 - 左图，对象的纯色；中图，每个像素的深度；右图，像素的法线

重要信息

法线是方向，方向的（X，Y，Z）分量被编码在颜色的 RGB 分量中。

在渲染场景中的所有对象之后，Unity 将迭代所有可以在相机中看到的光源，从而在 G-Buffer 上应用一层光照，从中获取信息来计算特定的光照。在所有光源都被处理之后，你将得到以下结果：

![图 8.5 - 应用于上一图像中的 G-Buffer 的三种光的组合](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.05_B14199.jpg)

图 8.5 - 应用于上一图像中的 G-Buffer 的三种光的组合

正如你所看到的，这种方法的延迟部分来自于将照明计算作为渲染过程的最后阶段的想法。这样做更好，因为你不会浪费资源计算可能被遮挡的物体的照明。如果在前向渲染中首先渲染图像的底部，那么其余物体将遮挡的像素就是徒劳的计算。此外，延迟只计算光照能够到达的确切像素。例如，如果你使用手电筒，Unity 只会在手电筒锥体内的像素中计算光照。缺点是，一些相对较旧的显卡不支持延迟，而且你无法使用顶点光照质量来计算照明，因此你将需要付出像素光照的代价，这在低端设备上不被推荐（甚至在简单的图形游戏中也不需要）。

那么，为什么我们要使用 URP 和单通道前向渲染？因为它在性能、质量和简单性之间提供了最佳平衡。在这个游戏中，我们不会使用太多的光源，所以我们不会担心单通道的光源数量限制，而且我们也不会充分利用延迟的好处，所以使用更多的硬件来运行游戏是没有意义的。

现在我们对 URP 处理光照的基本概念有了一个非常基本的了解，让我们开始使用它吧！

## 配置天空盒的环境光照

有不同的光源可以影响场景，如太阳、火炬、灯泡等。这些被称为**直接光**；也就是说，发射光线的物体。然后，我们有**间接光**，通常代表直接光的反射。然而，如果要让游戏以至少 30 FPS（或者只是运行）运行，计算所有光线发射的所有光线的所有反射是不可能的。问题在于没有间接光会产生不真实的结果，因为我们当前的场景照明中，你可以观察到阳光无法到达的地方完全黑暗，因为没有光从其他阳光照射的地方反射过来：

![图 8.6 – 没有环境光的山上投影的阴影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.06_B14199.jpg)

图 8.6 – 没有环境光的山上投影的阴影

为了解决这个问题，我们可以使用这些反弹的近似值。这就是我们所说的**环境光**。这代表了通常根据天空的颜色施加一点点光的基础光照层，但你可以选择任何你想要的颜色。例如，在晴朗的夜晚，我们可以选择深蓝色来代表月光的色调。

默认情况下，Unity 不会从天空计算环境光，因此我们需要手动进行以下操作：

1.  在层次结构中选择地形，并在检查器的右上角取消选择“静态”。稍后我们会解释为什么要这样做：![图 8.7 – 层次结构中的地形](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.07_B14199.jpg)

图 8.7 – 层次结构中的地形

1.  点击**窗口** | **渲染** | **灯光设置**。这将打开**场景灯光设置**窗口：![图 8.8 – 灯光设置位置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.08_B14199.jpg)

图 8.8 – 灯光设置位置

1.  点击窗口底部的**生成灯光**按钮。如果到目前为止你还没有保存场景，会提示你保存，这是必要的：![图 8.9 – 生成灯光按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.09_B14199.jpg)

图 8.9 – 生成灯光按钮

1.  查看 Unity 窗口右下角的进度计算栏，以检查进程何时完成：![图 8.10 – 灯光生成进度条](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.010_B14199.jpg)

图 8.10 – 灯光生成进度条

1.  现在你可以看到完全黑暗的区域现在有了一点光的效果：

![图 8.11 – 带环境光的阴影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.011_B14199.jpg)

图 8.11 – 带环境光的阴影

现在，通过这样做，我们有了更好的照明，但它看起来仍然像是一个晴天。记住，我们想要有雨天的天气。为了做到这一点，我们需要改变默认的天空，使其多云。你可以通过下载一个**天空盒**来实现。你可以在场景周围看到的当前天空只是一个包含每一面纹理的大立方体，这些纹理具有特殊的投影，以防止我们检测到立方体的边缘。我们可以为立方体的每一面下载六张图像并应用它们，以获得任何我们想要的天空，所以让我们这样做：

1.  你可以从任何你想要的地方下载天空盒纹理，但在这里，我会选择资产商店。通过**窗口** | **资产商店** 打开它，并转到资产商店网站。

1.  在右侧的类别列表中查找**2D** | **纹理和材质** | **天空**。请记住，如果看不到类别列表，需要扩大窗口宽度：![图 8.12 – 天空盒类别](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.012_B14199.jpg)

图 8.12 – 天空盒类别

1.  记得在**定价**部分勾选**免费资产**复选框：![图 8.13 – 免费资产过滤](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.013_B14199.jpg)

图 8.13 – 免费资产过滤

1.  选择任何你喜欢的天空盒来模拟雨天。请注意，天空盒有不同的格式。我们使用的是六图格式，所以在下载之前要检查一下。在我的例子中，我选择了下图中显示的天空盒包。下载并导入它，就像我们在*第五章**，导入和整合资源*中所做的那样：![图 8.14 – 为本书选择的天空盒套装](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.014_B14199.jpg)

图 8.14 – 为本书选择的天空盒套装

1.  通过在**Project**窗口中使用**+**图标并选择**Material**来创建一个新的材质。

1.  将该材质的**Shader**选项设置为**Skybox/6 sided**。记住，天空盒只是一个立方体，所以我们可以应用一个材质来改变它的外观。天空盒着色器已经准备好应用这六个纹理。

1.  将六个纹理拖到材质的**Front**、**Back**、**Left**、**Right**、**Up**和**Down**属性中。这六个下载的纹理将有描述性的名称，这样你就知道哪些纹理应该放在哪里：![图 8.15 – 天空盒材质设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.015_B14199.jpg)

图 8.15 – 天空盒材质设置

1.  将材质直接拖到场景视图中的天空中。确保你不要把材质拖到一个物体上，因为材质会被应用到它上面。

1.  重复环境光计算的*步骤 1*到*4*（**Lighting Settings** | **Generate Lighting**）以根据新的天空盒重新计算。在下图中，你可以看到目前我的项目的结果：

![图 8.16 – 应用的天空盒](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.016_B14199.jpg)

图 8.16 – 应用的天空盒

现在我们有了一个良好的基础光照层，我们可以开始添加光源对象了。

## 在 URP 中配置光照

我们可以在场景中添加三种主要类型的直射光：

+   **Directional Light**：这是代表太阳的光。这个对象会向着它所面对的方向发出光线，而不受位置的影响；太阳向右移动 100 米不会有太大的影响。举个例子，如果你慢慢旋转这个对象，你可以生成一个昼夜循环：

![图 8.17 – 定向光结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.017_B14199(Merged).jpg)

图 8.17 – 定向光结果

+   **点光源**：这种光代表了一个发射光线的灯泡，以全向方式发出光线。它对太阳的影响与太阳不同，因为它的位置很重要，因为它更接近。此外，因为它是一个较弱的光源，这种光的强度会根据距离而变化，所以它的效果有一个范围 – 距离光源越远，接收到的强度就越弱：

![图 8.18 – 点光结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.018_B14199(Merged).jpg)

图 8.18 – 点光结果

+   **Spotlight**：这种光代表了光锥，就像手电筒发出的光一样。它的行为类似于点光源，其位置和方向很重要，光强度会随着一定距离的衰减：

![图 8.19 – 聚光灯结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.019_B14199(Merged).jpg)

图 8.19 – 聚光灯结果

到目前为止，我们有了一个不错的、多雨的环境光照，但是我们场景中唯一的直射光，定向光，看起来不像这样，所以让我们改变一下：

1.  在**Hierarchy**窗口中选择**Directional Light**对象，然后查看**Inspector**窗口。

1.  点击**Colour**属性以打开颜色选择器。

1.  选择深灰色来实现部分被云层遮挡的阳光。

1.  将**Shadow Type**设置为**No Shadows**。现在我们有了多云的天气，太阳不会投射清晰的阴影，但我们稍后会更多地讨论阴影：

![图 8.20 – 没有阴影的柔和定向光](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.020_B14199.jpg)

图 8.20 – 没有阴影的柔和定向光

现在场景变暗了，我们可以添加一些灯光来照亮场景，如下所示：

1.  通过转到**GameObject** | **Light** | **Spotlight**创建一个聚光灯：![图 8.21 – 创建聚光灯](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.021_B14199.jpg)

图 8.21 – 创建聚光灯

1.  选择它。然后，在`90`和`120`中，这将增加锥体的角度。

1.  设置为`50`，表示光可以达到 50 米，沿途衰减。

1.  设置为`1000`：![图 8.22 – 聚光灯设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.022_B14199.jpg)

图 8.22 – 聚光灯设置

1.  将光源放在基座的一个角落，指向中心：![图 8.23 – 聚光灯放置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.023_B14199.jpg)

图 8.23 – 聚光灯放置

1.  通过选择光源并按下*Ctrl + D*（Mac 上为*command + D*）来复制该光源。

1.  将其放在基座的对角线上：

![图 8.24 – 两个聚光灯的效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.024_B14199.jpg)

图 8.24 – 两个聚光灯的效果

你可以继续向场景中添加光源，但要注意不要走得太远——记住光源的限制。此外，你可以下载一些灯柱放在光源位置，以视觉上证明光的来源。现在我们已经实现了适当的照明，我们可以谈论阴影了。

# 应用阴影

也许你会认为我们的场景中已经有阴影了，但实际上并没有。物体的较暗区域，也就是不面向光源的区域，没有阴影——它们没有被照亮，这与阴影是完全不同的。在这种情况下，我们指的是从一个物体投射到另一个物体的阴影；例如，玩家在地板上投射的阴影，或者从山上到其他物体的阴影。阴影可以提高我们场景的质量，但计算成本也很高，因此我们有两个选择：不使用阴影（建议用于移动设备等低端设备）或根据我们的游戏和目标设备在性能和质量之间找到平衡。在第一种情况下，你可以跳过整个部分，但如果你想要实现高性能的阴影，尽可能地继续阅读。

在本节中，我们将讨论有关阴影的以下主题：

+   理解阴影计算

+   配置高性能阴影

让我们先讨论 Unity 如何计算阴影。

## 理解阴影计算

在游戏开发中，众所周知，阴影在性能方面是昂贵的，但为什么呢？当光线射到另一个物体后再到达物体时，物体会产生阴影。在这种情况下，该像素不会受到来自该光源的照明。问题在于，这与环境光模拟的光照存在相同的问题——计算所有可能的光线及其碰撞将成本过高。因此，我们需要一个近似值，这就是阴影贴图发挥作用的地方。

阴影贴图是从光的视角渲染的图像，但不是绘制带有所有颜色和光照计算的完整场景，而是以灰度渲染所有物体，其中黑色表示像素距离摄像机很远，白色表示像素距离摄像机较近。如果你仔细想一想，每个像素都包含了光线的碰撞信息。通过了解光的位置和方向，你可以使用阴影贴图计算出每个“光线”碰撞的位置。在下图中，你可以看到我们定向光的阴影贴图：

![图 8.25 – 我们场景中定向光生成的阴影贴图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.025_B14199.jpg)

图 8.25 – 我们场景中定向光生成的阴影贴图

每种类型的光都会稍微不同地计算阴影贴图，尤其是点光源。由于它是全向的，它需要在所有方向（前、后、上、下、左、右）渲染场景多次，以收集关于它发射的所有光线的信息。不过，我们不会在这里详细讨论这个问题，因为我们可能会谈论一整天。

现在，这里需要强调的一点是，阴影图是纹理，因此它们有分辨率。分辨率越高，我们的阴影图计算的“光线”就越多。您可能想知道当低分辨率阴影图中只有少量光线时会是什么样子。看看下图，看看一个低分辨率阴影图是什么样子：

![图 8.26 - 使用低分辨率阴影图渲染的硬阴影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.026_B14199.jpg)

图 8.26 - 使用低分辨率阴影图渲染的硬阴影

问题在于光线数量较少会生成更大的阴影像素，导致像素化阴影。在这里，我们有第一个要考虑的配置：我们的阴影的理想分辨率是多少？您可能会诱惑地增加它，直到阴影看起来平滑，但当然，这将增加计算所需的时间，因此除非您的目标平台可以处理它（移动设备肯定不能），否则它将大大影响性能。在这里，我们可以使用**软阴影**技巧，在阴影上应用模糊效果以隐藏像素化的边缘，如下图所示：

![图 8.27 - 使用低分辨率阴影图渲染的软阴影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.027_B14199.jpg)

图 8.27 - 使用低分辨率阴影图渲染的软阴影

当然，模糊效果并不是免费的，但是如果您接受其模糊结果，并将其与低分辨率阴影图结合使用，可以在质量和性能之间达到良好的平衡。

现在，低分辨率阴影图还有另一个问题，称为**阴影痤疮**。这是您可以在下图中看到的照明错误：

![图 8.28 - 低分辨率阴影图的阴影痤疮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.028_B14199.jpg)

图 8.28 - 低分辨率阴影图的阴影痤疮

低分辨率阴影图会产生假阳性，因为计算的“光线”较少。需要在光线之间进行插值以对光线进行着色的像素需要从最近的光线中插值信息。阴影图的分辨率越低，光线之间的间隔就越大，这意味着精度越低，假阳性就越多。一种解决方法是增加分辨率，但同样会出现性能问题（一如既往）。我们有一些聪明的解决方案，比如使用**深度偏差**。可以在下图中看到这种情况的一个例子：

![图 8.29 - 两个远处的“光线”之间的假阳性。突出显示的区域认为光线在到达之前就击中了物体。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.029_B14199.jpg)

图 8.29 - 两个远处的“光线”之间的假阳性。突出显示的区域认为光线在到达之前就击中了物体。

**深度偏差**的概念很简单 - 如此简单，以至于看起来像是一个大的欺骗，实际上确实如此，但游戏开发中充满了这些欺骗！为了防止假阳性，我们“推”光线再多一点，足以使插值光线达到击中表面：

![图 8.30 - 具有深度偏差的光线以消除假阳性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.030_B14199.jpg)

图 8.30 - 具有深度偏差的光线以消除假阳性

当然，正如您可能期望的那样，它们不能轻松解决这个问题而没有任何警告。推动深度会在其他区域产生假阴性，如下图所示。看起来立方体在漂浮，但实际上它是与地面接触的 - 假阴性产生了它漂浮的错觉：

![图 8.31 - 由于深度偏差导致的假阴性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.031_B14199.jpg)

图 8.31 - 由于深度偏差导致的假阴性

当然，我们有一个对这种情况的反对技巧，称为**法线偏差**。它仍然推动物体，但沿着它们面对的方向。这有点棘手，所以我们不会在这里详细介绍，但是想法是结合一点深度偏差和另一点法线偏差将减少错误的阳性，但不会完全消除它们。因此，我们需要学会如何与之共存，并通过巧妙地定位物体来隐藏它：

![图 8.32-减少假阴性，这是深度和法线偏差相结合的结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.032_B14199.jpg)

图 8.32-减少假阴性，这是深度和法线偏差相结合的结果

还有其他几个影响阴影图工作方式的方面，其中之一是光范围。光范围越小，阴影覆盖的区域就越小。相同的阴影图分辨率可以为该区域添加更多细节，因此尽量减少光范围。

我可以想象你现在的表情，是的，照明很复杂，我们只是刚刚触及到表面！但保持你的精神！在稍微调整设置后，你会更好地理解它。我们将在下一节中做到这一点。

重要信息

如果您真的对学习阴影系统的内部更多信息感兴趣，我建议您查看**阴影级联**的概念，这是有关定向光和阴影图生成的高级主题。

## 配置高性能阴影

因为我们的目标是中端设备，所以我们将尝试在这里实现质量和性能的良好平衡，因此让我们开始仅为聚光灯启用阴影。定向光的阴影不会那么明显，实际上，雨天的天空不会产生清晰的阴影，因此我们将借此借口不计算那些阴影。为了做到这一点，请执行以下操作：

1.  通过在层次结构中单击它们并同时按下*Ctrl*（Mac 上的*Command*）来选择两个点光源。这将确保**检查器**窗口中所做的任何更改都将应用于两者：![图 8.33-选择多个对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.033_B14199.jpg)

图 8.33-选择多个对象

1.  在**检查器**窗口中，将**阴影类型**设置为**软阴影**。我们将在这里使用低分辨率阴影图：![图 8.34-软阴影设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.034_B14199.jpg)

图 8.34-软阴影设置

1.  选择**定向光**并将**阴影类型**设置为**无阴影**以防止其投射阴影：![图 8.35-无阴影设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.035_B14199.jpg)

图 8.35-无阴影设置

1.  创建一个立方体（**GameObject** | **3D Object** | **Cube**）并将其放在灯光附近，以便我们可以在其上投射阴影进行测试。

现在我们有了一个基本的测试场景，让我们调整阴影图分辨率设置，同时防止阴影痤疮：

1.  转到**编辑** | **项目设置**。

1.  在左侧列表中，查找**图形**并单击它：![图 8.36-图形设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.036_B14199.jpg)

图 8.36-图形设置

在选择此选项后出现的属性中，单击下面的**可编写渲染管线设置**框中的一个名称。在我的情况下，这是**LWRP-HighQuality**，但由于您使用的 Unity 版本不同，您的情况可能不同：

![图 8.37-当前渲染管线设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.037_B14199.jpg)

图 8.37-当前渲染管线设置

1.  这样做将在项目窗口中突出显示一个资产，因此在选择之前，请确保该窗口可见。选择突出显示的资产：![图 8.38-突出显示当前管道](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.038_B14199.jpg)

图 8.38-突出显示当前管道

1.  这个资产有几个与 URP 如何处理其渲染相关的图形设置，包括照明和阴影。展开**照明**部分以显示其设置：![图 8.39 – 管道照明设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.039_B14199.jpg)

图 8.39 – 管道照明设置

1.  `Main Light`）。如果它的值还不是**1024**，将其设置为**1024**。

1.  在`0.25`下，为了尽量减少它们，我们需要在移除阴影痤疮之前尽可能减少它们：![图 8.40 – 光影设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.040_B14199.jpg)

图 8.40 – 光影设置

1.  这与阴影没有直接关联，但在这里，你可以更改**每个对象光**限制，以增加或减少可以影响对象的光的数量（不超过八个）。

1.  如果你之前遵循了阴影级联提示，可以稍微调整**级联**值，以启用定向光的阴影以观察效果。请记住，这些阴影设置仅适用于定向光。

1.  将两个灯光的范围设置为 40 米。看看在更改前后阴影的质量如何改善：

![图 8.41 – 偏差设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.041_B14199.jpg)

图 8.41 – 偏差设置

请记住，这些值只适用于我的情况，所以尝试稍微调整这些值，看看结果如何改变 – 你可能会找到更适合你的 PC 的设置。同时，请记住，不使用阴影始终是一个选择，所以在你的游戏运行时低于 FPS 时（并且没有其他性能问题潜伏）时，始终要考虑这一点。

你可能认为这就是我们在照明性能方面所能做的一切，但幸运的是，情况并非如此！我们还有另一个资源可以用来进一步改善，即静态照明。

# 优化照明

我们之前提到不计算照明对性能有好处，但是不计算灯光，但仍然拥有它们呢？是的，这听起来太美好了，但实际上是可能的（当然，也很棘手）。我们可以使用一种称为静态照明或烘焙的技术，它允许我们计算一次照明并使用缓存的结果。

在本节中，我们将涵盖与静态照明相关的以下概念：

+   理解静态照明

+   烘焙光照图

+   将静态照明应用于动态对象

## 理解静态照明

这个想法非常简单：只需进行一次照明计算，保存结果，然后使用这些结果，而不是一直计算照明。你可能会想为什么这不是默认的技术。这是因为它有一些限制，其中最大的限制是动态对象。**预计算阴影**意味着一旦计算出来就不能改变，但如果投射阴影的对象移动了，阴影仍然会在那里，因此需要考虑的主要事情是你不能在移动对象上使用这种技术。相反，你需要为静态对象混合**静态**或**烘焙照明**，对于动态（移动）对象使用**实时照明**。此外，需要考虑的是，除了这种技术只适用于静态对象，它也只适用于静态光源。同样，如果光源移动，预先计算的数据就会变得无效。

你需要考虑的另一个限制是，预先计算的数据可能会对内存产生巨大影响。这些数据占用了 RAM 的空间，也许有数百 MB，因此你需要考虑你的目标平台是否有足够的空间。当然，你可以降低预先计算的照明质量以减小数据的大小，但你需要考虑失去的质量是否会过分恶化你的游戏的外观和感觉。就像所有关于优化的选项一样，你需要平衡两个因素：性能和质量。

在我们的过程中有几种预先计算的数据，但最重要的是我们所谓的**光照贴图**。光照贴图是一种纹理，其中包含场景中所有对象的阴影和光照，因此当 Unity 应用预先计算或烘焙的数据时，它将查看此纹理，以了解静态对象的哪些部分受到照明，哪些部分没有。您可以在以下图中看到光照贴图的示例：

![图 8.42 - 左边是没有光照的场景；中间是包含来自该场景的预先计算数据的光照贴图；右边是将光照贴图应用到场景中](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.042_B14199.jpg)

图 8.42 - 左边是没有光照的场景；中间是包含来自该场景的预先计算数据的光照贴图；右边是将光照贴图应用到场景中

无论如何，光照贴图也有其自身的好处。烘焙过程在 Unity 中执行，游戏发货给用户之前，因此您可以花费大量时间计算无法在运行时执行的内容，例如改进的准确性、光线反射、角落中的光遮挡以及来自发光对象的光线。然而，这也可能是一个问题。请记住，动态对象仍然需要依赖实时光照，而该光照看起来与静态光照非常不同，因此我们需要对其进行大量调整，以使用户注意不到差异。

现在我们对静态光照有了基本概念，让我们深入了解如何使用它。

## 烘焙光照贴图

要使用光照贴图，我们需要对 3D 模型进行一些准备工作。记住，网格有**UV**，其中包含有关将纹理的哪个部分应用于模型的每个部分的信息。有时，为了节省纹理内存，您可以将相同的纹理片段应用于不同的部分。例如，在汽车的纹理中，您不会有四个车轮，只会有一个，您可以将相同的纹理片段应用于所有车轮。问题在于静态光照以相同的方式使用纹理，但在这里，它将应用光照贴图来照亮对象。在车轮的情况下，问题在于如果一个车轮接收阴影，所有车轮都会有阴影，因为所有车轮共享相同的纹理空间。通常的解决方案是在模型中有第二组 UV，其中没有共享纹理空间，仅用于光照贴图。

有时，下载的模型已经准备好进行光照贴图，有时没有，但幸运的是，Unity 在这些情况下为我们提供了帮助。为了确保模型能够正确计算光照贴图，让我们通过以下步骤让 Unity 自动生成**光照贴图 UV**集：

1.  在**项目**窗口中选择网格资产（FBX）。

1.  在**模型**选项卡中，查找底部的**生成光照贴图**复选框并选中它。

1.  单击底部的**应用**按钮：![图 8.43 - 生成光照贴图设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.043_B14199.jpg)

图 8.43 - 生成光照贴图设置

1.  对每个模型重复此过程。从技术上讲，您只能在烘焙光照贴图后在模型中出现伪影和奇怪结果时才能这样做，但现在，让我们在所有模型中都这样做以防万一。

准备好模型进行光照贴图后，下一步是告诉 Unity 哪些对象不会移动。要做到这一点，按照以下步骤进行：

1.  选择不会移动的对象。

1.  在**检视器**窗口的右上角选中**静态**复选框：![图 8.44 - 静态复选框](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.044_B14199.jpg)

图 8.44 - 静态复选框

1.  对每个静态对象重复此过程（对灯光不需要这样做；我们稍后会处理）。

请注意，您可能不希望每个对象，即使是静态的，都被烘焙，因为您烘焙的对象越多，您就需要更多的纹理大小。例如，地形太大，将占用大部分烘焙的大小。通常情况下，这是必要的，但在我们的情况下，聚光灯几乎没有触及地形。在这里，我们有两个选择：将地形保留为动态，或者更好地直接告诉聚光灯不要影响地形，因为一个只受环境光和定向光（不投射阴影）照亮。请记住，这是我们可以做的事情，因为我们的场景类型；然而，在其他情况下，您可能需要在其他情景中使用其他设置。您可以通过以下方式从实时和静态照明计算中排除对象：

1.  选择要排除的对象。

1.  在**检视器**窗口中，单击**图层**下拉菜单，然后单击**添加图层**：![图 8.45 – 图层创建按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.045_B14199.jpg)

图 8.45 – 图层创建按钮

1.  在这里，您可以创建一个图层，这是一个用于识别哪些对象不会受到照明影响的对象组。在**图层**列表中，查找一个空白空间，并键入这些类型对象的任何名称。在我的情况下，我只会排除地形，所以我只是将其命名为**地形**：![图 8.46 – 图层列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.046_B14199.jpg)

图 8.46 – 图层列表

1.  再次选择地形，转到**图层**下拉菜单，并选择在上一步中创建的图层。这样，您可以指定该对象属于该组对象：![图 8.47 – 更改游戏对象的图层](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.047_B14199.jpg)

图 8.47 – 更改游戏对象的图层

1.  选择所有聚光灯，查找**检视器**窗口中的**剔除蒙版**，单击它，并取消选中之前创建的图层。这样，您可以指定这些灯不会影响该组对象：![图 8.48 – 光照剔除蒙版](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.048_B14199.jpg)

图 8.48 – 光照剔除蒙版

1.  现在，您可以看到那些选定的灯不会照亮或对地形应用阴影。

现在，是时候处理灯光了，因为**静态**复选框对它们不起作用。对于它们，我们有以下三种模式：

+   **实时**：实时模式下的光会影响所有对象，包括静态和动态对象，使用实时照明，这意味着没有预先计算。这对于不是静态的灯光非常有用，比如玩家的手电筒，因为风而移动的灯等等。

+   **烘焙**：与实时相反，这种类型的光只会影响具有光照贴图的静态对象。这意味着如果玩家（动态）在街道上的烘焙光下移动，街道看起来会被照亮，但玩家仍然会很暗，并且不会在街道上投下任何阴影。这个想法是在不影响任何动态对象的灯光上使用它，或者在它们上几乎不可察觉的灯光上使用它，这样我们就可以通过不计算它们来提高性能。

+   **混合**：如果不确定要使用哪种模式，则这是首选模式。这种类型的光会为静态对象计算光照贴图，但也会影响动态对象，将其实时照明与烘焙照明结合在一起（就像实时光也会做的那样）。

在我们的情况下，我们的定向光只会影响地形，而且因为我们没有阴影，在 URP 中应用照明相对便宜，所以我们可以将定向光保留在实时模式，这样它就不会占用任何光照贴图区域。我们的聚光灯影响了基地，但实际上，它们只是对其应用照明 - 我们没有阴影，因为我们的基地是空的。在这种情况下，最好根本不计算光照贴图，但出于学习目的，我将添加一些障碍物作为基地的阴影，并证明使用光照贴图，如下图所示：

![图 8.49 – 添加对象以投射光线](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.049_B14199.jpg)

图 8.49 – 向项目添加对象以投射光线

在这里，您可以看到我们的关卡原始设计在游戏开发过程中不断变化，这是您无法避免的事情 - 游戏的更大部分将随时间改变。现在，我们已经准备好设置光照模式并执行烘焙过程，如下所示：

1.  选择**定向光**。

1.  将`检视器`窗口设置为**实时**（如果尚未处于该模式）。

1.  选择两个聚光灯。

1.  将它们的**渲染模式**设置为**混合**：![图 8.50 – 混合光照设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.050_B14199.jpg)

图 8.50 – 混合光照设置

1.  打开**照明设置**窗口（**窗口** | **渲染** | **照明设置**）。

1.  单击**生成照明**，这是我们之前用来生成环境光照的相同按钮。

1.  等待进程完成。您可以通过检查 Unity 编辑器右下角的进度条来完成此操作。请注意，这个过程可能需要几个小时才能完成，所以请耐心等待：![图 8.51 – 烘焙进度条](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.051_B14199.jpg)

图 8.51 – 烘焙进度条

1.  我们想要更改烘焙过程的一些设置。为了启用此控件，单击**新照明设置**按钮。这将创建一个具有光照设置的资源，可以应用于多个场景，以便我们多次共享相同的设置：![图 8.52 – 创建照明设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.052_B14199.jpg)

图 8.52 – 创建照明设置

1.  降低光照质量，以加快进程。只需迭代，通过使用**光照贴图分辨率**、**直接**、**间接**和**环境样本**等设置，可以轻松降低照明。在我的情况下，我已经应用了这些设置，如下图所示。请注意，即使减少这些设置也需要时间；由于模块化关卡设计，我们的场景中有太多对象：![图 8.53 – 场景光照设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.053_B14199.jpg)

图 8.53 – 场景光照设置

1.  进程完成后，您可以检查**照明设置**窗口的底部，您可以看到需要生成多少个光照贴图。我们有最大光照贴图分辨率，所以我们可能需要生成几个光照贴图来覆盖整个场景。此外，它还告诉我们它们的大小，以便我们可以考虑它们对 RAM 的影响。最后，您可以查看**烘焙光照贴图**部分来查看它们：![图 8.54 – 生成的光照贴图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.054_B14199.jpg)

图 8.54 – 生成的光照贴图

1.  现在，根据结果，您可以移动对象，修改光强度，或者进行任何您需要的修正，以使场景看起来符合您的要求，并在需要时重新计算照明。在我的情况下，这些设置给我带来了足够好的结果，您可以在下图中看到：

![图 8.55 – 光照贴图结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.055_B14199.jpg)

图 8.55 – 光照贴图结果

我们仍有许多小设置要处理，但我会让您通过试错或阅读 Unity 关于光照贴图的文档来发现这些设置。阅读 Unity 手册是获取知识的好途径，我建议您开始使用它 - 任何经验丰富的好开发人员都应该阅读手册。

## 将静态光照应用于静态对象

当在场景中将对象标记为静态时，您可能已经发现场景中的所有对象都不会移动，因此您可能已经为每个对象都勾选了静态复选框。这没问题，但您应该始终将一个动态对象放入场景中，以确保一切正常 - 没有游戏完全静态。尝试添加一个胶囊体并将其移动以模拟我们的玩家，如下图所示。如果您留意，您会注意到一些奇怪的事情 - 光照贴图过程生成的阴影未应用于我们的动态对象：

![图 8.56 - 动态物体在烘焙阴影下](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.056_B14199.jpg)

图 8.56 - 动态物体在烘焙阴影下

你可能会认为混合光模式应该影响动态和静态物体，这正是它所做的。问题在于，与静态物体相关的所有内容都预先计算到那些光照图纹理中，包括它们投射的阴影，因为我们的胶囊是动态的，在预计算过程执行时并不存在。所以，在这种情况下，因为投射阴影的对象是静态的，它的阴影不会影响任何动态物体。

在这里，我们有几种解决方案。第一种是改变静态和实时混合算法，使相机附近的所有东西都使用实时照明，并防止这个问题（至少在玩家的注意焦点附近），这对性能会有很大影响。另一种选择是使用**光探头**。当我们烘焙信息时，我们只在光照图上做了这个，这意味着我们只有表面上的光照信息，而不是空白空间中的光照信息。因为我们的玩家正在穿越这些表面之间的空白空间，我们不知道这些空间的光照会是什么样子，比如走廊中间。光探头是在这些空白空间中的一组点，Unity 也会预先计算信息，所以当一些动态物体经过时，它会从中采样信息。在下图中，你可以看到一些应用到我们场景中的光探头。你会注意到那些在阴影中的光探头会变暗，而那些暴露在光线下的光探头会有更大的强度。这种效果将应用到我们的动态物体上：

![图 8.57 - 代表光探头的球体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.057_B14199.jpg)

图 8.57 - 代表光探头的球体

如果你现在在场景中移动你的物体，它将对阴影做出反应，就像下面两张图片中所示，你可以看到一个动态物体在烘焙阴影外被照亮，而在内部变暗：

![图 8.58 - 动态物体接收来自光探头的烘焙照明](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.058_B14199(Merged).jpg)

图 8.58 - 动态物体接收来自光探头的烘焙照明

为了创建光探头，进行以下操作：

1.  通过转到**GameObject** | **Light** | **Light Probe Group**来创建一组**光**探头：![图 8.59 - 创建光探头组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.059_B14199.jpg)

图 8.59 - 创建光探头组

1.  幸运的是，我们有一些关于如何定位它们的指导方针。建议将它们放在光照变化的地方，比如在内部和外部阴影边界。然而，这相当复杂。最简单和推荐的方法是在可玩区域上放置一个光探头网格。为此，你可以简单地多次复制和粘贴光网格组，以覆盖整个基地：![图 8.60 - 光探头网格](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.060_B14199.jpg)

图 8.60 - 光探头网格

1.  另一种方法是选择一组并点击**编辑光探头**按钮进入光探头编辑模式：![图 8.61 - 光探头组编辑按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_8.061_B14199.jpg)

图 8.61 - 光探头组编辑按钮

1.  点击**全选**按钮，然后点击**复制所选**按钮，复制所有先前存在的探针。

1.  使用平移小工具，将它们移动到先前的位置旁边，同时扩展网格。请考虑到探针越近，你需要更多的探针来覆盖地形，这将产生更多的数据。然而，光探头数据相对便宜，所以你可以有很多。

1.  重复*步骤 4*至*5*，直到覆盖整个区域。

1.  使用**光照设置**中的**生成照明**按钮重新生成照明。

有了这个，你就预先计算了影响我们动态物体的光探头上的照明，将两个世界结合起来，获得了连贯的照明。

# 总结

在本章中，我们讨论了几个照明主题，比如 Unity 如何计算光线、阴影，如何处理不同的光源，比如直接和间接照明，如何配置阴影，如何烘焙照明以优化性能，以及如何结合动态和静态照明，使光线不脱离影响其所在世界的环境。这是一个很长的章节，但照明值得如此。这是一个复杂的主题，可以显著改善场景的外观和感觉，同时大大降低性能。这需要大量的实践，我们在这里试图总结出你开始尝试的所有重要知识。对这个主题要有耐心；很容易得到不正确的结果，但你可能只差一个复选框就能解决问题。

现在我们已经在场景设置中做了所有可以改进的事情，在下一章中，我们将使用 Unity 后期处理堆栈应用最终的图形效果，这将应用全屏图像效果-这些效果将给我们带来当今所有游戏都具有的电影般的外观和感觉。


# 第九章：使用后期处理的全屏效果

到目前为止，我们已经创建了不同的对象来改变场景的视觉效果，例如网格、粒子和灯光。我们可以在这里和那里调整这些对象的设置，以改善我们的场景质量，但是当与现代游戏场景进行比较时，您总会感到缺少某些东西，即全屏或后期处理效果。在本章中，您将学习如何将效果应用于最终渲染的帧，这将改变整个场景的外观。

+   在本章中，我们将研究以下图像效果概念：

+   ](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.03_B14199.jpg)

+   使用高级效果

# 使用后期处理

**后期处理**是 Unity 的一个功能，允许我们应用多种效果（一堆效果）叠加在一起，这将改变图像的最终外观。每个效果都会影响完成的帧，根据不同的标准改变其中的颜色。在以下截图中，您可以看到应用图像效果之前和之后的场景。您会注意到明显的差异，但是该场景的对象，包括灯光、粒子或网格，都没有任何变化。应用的效果是基于像素分析的。在这里看看两个场景：

![图 9.1 没有图像效果的场景（左）和具有效果的相同场景（右）](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.01_B14199(merged).jpg)

图 9.1-没有图像效果的场景（左）和具有效果的相同场景（右）

需要考虑的是，以前的后期处理解决方案**postprocessing Stack version 2**（**PPv2**）在**Universal Render Pipeline**（**URP**）上无法使用；它有自己的后期处理实现，因此我们将在本章中看到它。无论如何，它们非常相似，因此即使您使用 PPv2，您仍然可以从本章中获得一些东西。

在本节中，我们将讨论以下 URP 后期处理概念：

+   设置配置文件

+   使用基本效果

让我们开始准备我们的场景应用效果。

## 设置配置文件

要开始应用效果，我们需要创建一个**Profile**，它是一个包含我们想要应用的所有效果和设置的资产。出于与材质相同的原因，这是一个单独的资产，因为我们可以在不同的场景和场景部分之间共享相同的后期处理配置文件。当我们提到场景的部分时，我们指的是应用了某些效果的体积或游戏区域。我们可以定义一个全局区域，无论玩家的位置如何都会应用效果，或者我们可以应用不同的效果-例如，当我们在室外或室内时。

在这种情况下，我们将使用全局体积，我们将使用它来应用我们的第一个效果配置文件，方法如下：

1.  创建一个新的空游戏对象（**GameObject** | **Create Empty**）。

1.  将其命名为`PP Volume`（表示后期处理体积）。

1.  将**Volume**组件添加到其中。

1.  确保**Mode**设置为**Global**。

1.  单击**Profile**设置右侧的**New**按钮，这将生成一个名为我们对象的新配置文件资产（PPVolume Profile）。您可以稍后将其移动到自己的文件夹中，这是为了资产组织目的而推荐的。该过程如下截图所示：![图 9.2 体积组件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.02_B14199.jpg)

图 9.2-体积组件

1.  要测试体积是否起作用，让我们添加一个效果。单击**Add Override**按钮，然后选择**postprocessing** | **Chromatic Aberration**选项。

1.  检查`0.5`，如下截图所示：![图 9.3 色差效果使用后期处理图 9.3-色差效果 1.  现在，您将看到图像的角落应用了一种像差效果。请记住在场景面板中查看这一点；我们将在下一步中将效果应用于游戏视图。这在以下截图中有所说明：![图 9.4 应用于场景的色差](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.04_B14199.jpg)

图 9.4 - 应用到场景中的色差

1.  现在，如果你点击`Main Camera`，你会发现效果没有被应用，这是因为我们需要勾选`Main Camera`，如下面的截图所示：

![图 9.5 启用后期处理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.05_B14199.jpg)

图 9.5 - 启用后期处理

因此，我们创建了一个全局体积，它将将指定的效果作为覆盖应用到整个场景，而不管玩家的位置如何。

现在我们已经准备好使用后期处理来准备我们的场景，我们可以开始尝试不同的效果。让我们从下一节中最简单的效果开始。

## 使用基本效果

现在我们在场景中有了后期处理，唯一需要做的就是开始添加效果并设置它们，直到我们得到期望的外观和感觉。为了做到这一点，让我们探索系统中包含的几种简单效果。

让我们从**色差**开始，这是我们刚刚使用的效果，与大多数图像效果一样，它试图复制特定的真实效果。所有游戏引擎渲染系统都使用了眼睛视觉真实工作的简单数学近似，因此我们没有一些发生在人眼或相机镜头中的效果。真实的相机镜头通过弯曲光线来将其指向相机传感器，但在一些镜头中（有时是故意的），这种弯曲并不完美，因此你会看到一些失真，如下面的截图所示：

![图 9.6 没有色差的图像（左）和有色差的相同图像（右）](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.06_B14199(merged).jpg)

图 9.6 - 没有色差的图像（左）和有色差的相同图像（右）

这个效果将是我们添加的几个效果之一，以在游戏中产生一种电影感，模拟真实相机的使用。当然，这种效果并不适合每种类型的游戏；也许简单的卡通风格不会从中受益，但你永远不知道：艺术是主观的，所以这是一个试错的过程。

此外，我们在上一个例子中夸大了强度，以使效果更加明显，但我建议在这种情况下使用强度为 0.25。通常建议对效果的强度要温和；强烈的效果很诱人，但当你添加了很多效果之后，图像会变得臃肿，扭曲太多。因此，尽量添加一些微妙的效果，而不是少量强烈的效果。但是，这取决于你所追求的目标风格；在这里没有绝对的真理（但常识仍然适用）。

最后，在讨论其他效果之前，如果你习惯使用其他类型的后期处理效果框架，你会注意到这个版本的色差设置较少，这是因为 URP 版本追求性能，所以尽可能简单。

接下来我们要讨论的效果是**晕影**。这是另一个相机镜头的缺陷，图像强度在镜头边缘会丢失。这不仅可以用来模拟旧相机，还可以吸引用户的注意力集中在相机的中心，比如在电影中。此外，如果你正在开发**虚拟现实**（**VR**）应用程序，这可以通过减少玩家的外围视觉来减轻晕动病。在下面的截图中，你可以看到一个旧相机上晕影的例子：

![图 9.7 使用旧相机拍摄的照片，边缘有晕影](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.07_B14199.jpg)

图 9.7 - 使用旧相机拍摄的照片，边缘有晕影

只是试试，让我们通过以下方式向我们的场景应用一些晕影：

1.  选择`PP Volume`游戏对象。

1.  通过点击**添加覆盖**按钮添加**后期处理** | **晕影**效果。

1.  检查`0.3`，增加效果。

1.  检查`0.5`；这将增加效果的扩散。您可以在下面的截图中看到结果：

![图 9.8 晕影效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.08_B14199.jpg)

图 9.8 – 晕影效果

如果您愿意，您可以通过勾选`Center`和`Rounded`，以`Particles`的方式工作。您可以通过调整数值来创建漂亮的效果。

我们将在这个基础部分中审查的另一个效果是**运动模糊**，再次模拟相机的工作方式。相机有一个曝光时间，它需要捕捉光子以获得每一帧。当一个物体移动得足够快时，在那短暂的曝光时间内，同一个物体会处于不同的位置，因此它会显得模糊不清。在下面的截图中，您可以看到该效果应用到我们的场景中。在这张图片中，我们快速上下旋转相机，得到以下结果：

![图 9.9 将运动模糊应用到我们的场景中](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.09_B14199.jpg)

图 9.9 将运动模糊应用到我们的场景中

需要考虑的一件事是，这种模糊只会应用于相机的移动，而不是物体的移动（静止相机，移动物体），因为 URP 目前不支持运动矢量。

要使用此效果，请按照以下步骤进行：

1.  使用**Post-processing** | **Motion Blur**覆盖，点击**Add override**按钮。

1.  检查`0.5`。

1.  在查看游戏视图时旋转相机（而不是场景视图）。您可以单击并拖动相机的**Transform**的**X**属性（不是值，而是**X**标签），如下面的截图所示：

![图 9.10 改变旋转](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.10_B14199.jpg)

图 9.10 – 改变旋转

正如您所看到的，这种效果在场景视图中是看不到的，其他效果也是如此，因此在得出效果不起作用的结论之前，请考虑这一点。Unity 之所以这样做，是因为在场景中工作时，拥有这种效果会非常恼人。

最后，我们将简要讨论两个最终简单的效果，**胶片颗粒**和**白平衡**。第一个非常简单：添加它，将强度设置为 1，您将得到老电影中著名的颗粒效果。您可以通过不同大小的**Type**来使其更加微妙或明显。白平衡允许您改变色温，根据您的配置使颜色变得更温暖或更凉爽。在我们的情况下，我们正在处理一个寒冷的黑暗场景，因此您可以添加它并将温度设置为-20，稍微调整外观，改善这种场景的外观和感觉。

既然我们已经看到了一些简单的效果，让我们来看看剩下的一些受一些高级渲染特性影响的效果。

# 使用高级效果

我们将在本节中看到的效果与之前的效果并没有太大的区别；它们只是有点棘手，需要一些背景知识才能正确使用它们。所以，让我们深入了解它们！

在本节中，我们将看到高级效果概念

**高动态范围**（**HDR**）和深度图。

## 高级效果

让我们首先讨论一些这些效果正常工作所需的要求。

### HDR 和深度图

有些效果不仅适用于渲染图像，还需要额外的数据。我们首先讨论**深度图**，这是我们在上一章中已经讨论过的概念。简而言之，深度图是从相机的视角渲染的图像，但它不是生成场景的最终图像，而是渲染场景对象的深度，以灰度渲染对象。颜色越深，像素距离相机越远，反之亦然。在下面的截图中，您可以看到深度图的一个示例：

![图 9.11 – 几何图形的深度图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.11_B14199.jpg)

图 9.11 – 几何图形的深度图

我们将看到一些效果，比如**景深**，它会根据相机的距离模糊图像的某些部分，但它可以用于自定义效果的几个目的（不在基本 URP 包中）。

这里要讨论的另一个概念会改变颜色的处理方式，因此也会改变一些效果的工作方式，那就是 HDR。在旧的硬件中，颜色通道（红色、绿色和蓝色）被编码在 0 到 1 的范围内，0 表示没有强度，1 表示完全强度（每个通道），因此所有照明和颜色计算都是在该范围内进行的。这似乎没问题，但并不反映光的实际工作方式。您可以看到一张纸被阳光照射时呈现全白（所有通道设置为 1），当您直接看灯泡时也会看到全白，但即使光和纸都是相同的颜色，后者首先会在一段时间后刺激眼睛，其次，由于光线过多，会有一些过亮。问题在于最大值（1）不足以表示最强烈的颜色，因此，如果您有一个高强度的光和另一个甚至更高强度的光，由于计算无法超过 1，两者都将生成相同的颜色（每个通道中的 1）。这就是为什么创建了**HDR 渲染**。

HDR 是一种使颜色超出 0.1 范围的方式，因此基于颜色强度工作的照明和效果在此模式下具有更好的准确性。这与具有相同名称的新电视功能的想法相同，尽管在这种情况下，Unity 将以 HDR 进行计算，但最终图像仍将使用先前的颜色空间（0 到 1，或**低动态范围（LDR）**），因此不要将 Unity 的**HDR 渲染**与**显示的 HDR**混淆。要将 HDR 计算转换回 LDR，Unity（以及电视）使用了一个称为**色调映射**的概念。您可以在以下屏幕截图中看到一个 LDR 渲染的场景和色调映射在 HDR 场景中的应用示例：

![图 9.12 左边是 LDR 渲染的场景，右边是使用色调映射校正过亮的 HDR 场景](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.12_B14199(Merged).jpg)

图 9.12-左边是 LDR 渲染的场景，右边是使用色调映射校正过亮的 HDR 场景

色调映射是一种将颜色从 0.1 范围之外带回到其中的方法。它基本上使用一些公式和曲线来确定如何映射每个颜色通道。您可以在典型的从暗到亮的场景转换中清楚地看到这一点，比如当您走出没有窗户的建筑物，走到明亮的一天。有一段时间，您会看到一切变得更亮，直到一切恢复正常。这里的想法是，当您在建筑物内外时，计算并不不同；建筑物内的白墙将具有接近 1 强度的颜色，而外面的同样白墙将具有更高的值（由于阳光）。不同之处在于，当您在建筑物外时，色调映射将把高于 1 的颜色带回到 1，并且根据您的设置，如果整个场景较暗，可能会增加建筑物内墙壁的照明。

即使 HDR 默认启用，让我们看看如何通过以下方式检查：

1.  转到**编辑** | **项目设置**。

1.  单击左侧面板中的**图形设置**部分。

1.  单击**脚本渲染管线设置**属性下引用的资产。

1.  单击项目面板中突出显示的资产。在单击**图形**设置中的属性之前，请确保此面板可见。

1.  在**质量**部分，确保**HDR**已被选中，如下面的屏幕截图所示：

![图 9.13 启用 HDR](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.13_B14199.jpg)

图 9.13-启用 HDR

当然，HDR 是可切换的，这意味着有些情况下您可能不想使用它。正如您可以猜到的，不是所有的硬件都支持 HDR，并且使用它会带来性能开销，所以请考虑这一点。幸运的是，大多数效果都适用于 HDR 和 LDR 颜色范围，因此如果您启用了 HDR 但用户设备不支持它，您不会遇到任何错误，只是会得到不同的结果。

既然我们确定已启用 HDR，让我们探索一些使用这个和深度映射的高级效果。

让我们看看一些使用先前描述的技术的特定效果，首先是常用的 Bloom。这种效果通常模拟相机镜头或甚至人眼周围发生的强烈照明物体的过度发光。在下面的截图中，您可以看到我们场景的默认版本和夸张的 Bloom 版本之间的差异。您可以观察到效果只应用于我们场景最明亮的区域。在这里看看这两种效果：

![图 9.14 默认场景（左）和相同场景的高强度 Bloom（右）](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.14_B14199(Merged).jpg)

图 9.14 - 默认场景（左）和相同场景的高强度 Bloom（右）

这种效果实际上非常普遍和简单，但我认为它是高级的，因为结果受到 HDR 的影响很大。这种效果依赖于计算每个像素的颜色强度，以便检测可以应用它的区域。在 LDR 中，我们可能有一个白色的物体，实际上并不是过亮的，但由于这种颜色范围的限制，Bloom 可能会在其上产生过度发光。在 HDR 中，由于其增加的颜色范围，我们可以检测物体是否是白色，或者物体可能是浅蓝色但只是过亮，产生了它是白色的错觉（比如在高强度灯附近的物体）。在下面的截图中，您可以看到我们的场景在启用 HDR 和未启用 HDR 时的区别。您会注意到 LDR 版本会在不一定是过亮的区域产生过度发光。差异可能非常微妙，但请注意细节以注意到差异。记住，我在这里夸大了效果。在这里看看两个场景：

![图 9.15 - LDR 场景中的 Bloom（左）和 HDR 场景中的 Bloom（右）。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.15_B14199(Merged).jpg)

图 9.15 - LDR 场景中的 Bloom（左）和 HDR 场景中的 Bloom（右）。请注意，Bloom 设置已更改，以尽量接近它们

现在，让我们继续使用场景的 HDR 版本。为了启用 Bloom，执行以下操作：

1.  像往常一样，将**Bloom**覆盖添加到配置文件中。

1.  启用`1.5`。这控制着将应用多少过度发光。

1.  启用`0.7`。这个值表示颜色需要具有的最小强度，才能被认为是过度发光。在我们的情况下，我们的场景有点暗，所以我们需要在 Bloom 效果设置中减少这个值，以包括更多的像素。通常情况下，这些值需要根据您的具体情况进行调整。

1.  您会注意到差异非常微妙，但再次记住，您将有几种效果，所以所有这些小差异将累积起来。您可以在以下截图中看到这两种效果：

![图 9.16 - Bloom 效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.16_B14199(Merged).jpg)

图 9.16 - Bloom 效果

像往常一样，建议您调整其他值。我建议您测试一些有趣的设置，比如**Dirt Texture**和**Dirt Intensity**值。

现在，让我们转移到另一个常见的效果，**景深**。这个效果依赖于我们之前讨论过的深度图。肉眼并不那么明显，但当你专注于视野内的一个物体时，周围的物体会变得模糊，因为它们失焦了。我们可以利用这一点来在游戏玩法的关键时刻引起玩家的注意。这个效果将对深度图进行采样，以查看物体是否在焦点范围内；如果是，就不会应用模糊效果，反之亦然。为了使用它，做如下操作：

1.  这个效果取决于你的游戏摄像机定位。在这种情况下，我们将把摄像机放在柱子附近，以尝试专注于特定物体，如下截图所示：![图 9.17 – 摄像机定位](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.17_B14199.jpg)

图 9.17 – 摄像机定位

1.  添加**景深**覆盖。

1.  启用并将**模式**设置为**高斯**：这是最简单的模式。

1.  在我的情况下，我设置了`10`和`20`，这将使效果从目标物体后面的一定距离开始。**结束**设置将控制模糊的强度增加，达到最大值时距离为 20 米。记得根据你的情况调整这些值。

1.  如果你想稍微夸张效果，设置为`1.5`。结果如下截图所示：

![图 9.18 夸张效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.18_B14199.jpg)

图 9.18 – 夸张效果

这里需要考虑的一点是，我们的特定游戏将采用俯视视角，与第一人称摄像机不同，你可以看到远处的物体，而在这里，物体足够近以至于不会注意到效果，所以我们可以将这个效果限制在剧情场景中使用。

现在，剩下的大部分效果都是改变场景实际颜色的不同方式。思路是，真实的颜色有时并不能给你想要的精确外观和感觉。也许你需要让暗区域更暗，以加强恐怖氛围的感觉，或者你想做相反的事情：增加暗区域的亮度，以代表一个开放的场景。也许你想给高光着色一点，以获得霓虹效果，如果你正在创建一个未来主义游戏，或者也许你想暂时使用棕褐色效果，进行一个回忆。我们有无数种方法可以做到这一点，在这种情况下，我将使用一个简单但强大的效果，叫做**阴影、中间色调、高光**。

这个效果将对**阴影**、**中间色调**和**高光**应用不同的颜色校正，这意味着我们可以分别修改较暗、较亮和中等区域。让我们尝试一下：

1.  添加**阴影、中间色调、高光**覆盖。

1.  让我们开始做一些测试。勾选三个**阴影**、**中间色调**和**高光**复选框。

1.  将**阴影**和**中间色调**滑块全部向左移动，将**高光**的滑块向右移动。这将减少阴影和中间色调的强度，并增加高光的强度。我们这样做是为了让你看到**高光**会根据其强度改变的区域（这在恐怖游戏中也可能是一个有趣的效果）。你可以用其他滑块做同样的操作来检查其他两个区域。你可以在下面的截图中看到结果：![图 9.19 – 高光隔离](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.19_B14199.jpg)

图 9.19 – 高光隔离

1.  此外，你可以尝试移动彩色圆圈中心的白色圆圈，对这些区域进行轻微着色。将滑块稍微向左移动以减少高光的强度，使着色效果更加明显。你可以在下面的截图中看到结果：![图 9.20 – 高光着色](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.20_B14199.jpg)

图 9.20 – 高光着色

1.  通过这样做，您可以探索这些控件的工作方式，但当然，这些极端值对于某些边缘情况是有用的。在我们的场景中，您可以在下面的屏幕截图中看到的设置对我来说效果最好。一如既往，最好使用更微妙的值，以不要过度扭曲原始结果，如下所示：![图 9.21 – 微妙的变化](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.21_B14199.jpg)

图 9.21 – 微妙的变化

1.  以下是屏幕截图中的前后效果：

![图 9.22 – 前后效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_9.22_B14199(Merged).jpg)

图 9.22 – 前后效果

您还有其他更简单的选项，比如**分割调色**，它做的事情类似，但只涉及阴影和高光，或者**颜色曲线**，它可以让您更高级地控制场景的每个颜色通道将如何映射，但其思想是相同的——即改变结果场景的实际颜色，以赋予您的场景特定的色彩氛围。如果您还记得电影系列*黑客帝国*，当角色在矩阵中时，一切都带有微妙的绿色色调，而在外面时，色调是蓝色的。

请记住，使用 HDR 和不使用它对于这些效果的结果是重要的，因此最好尽早决定是否使用 HDR，排除某些目标平台（这可能对您的目标受众不重要），或者不使用它（使用 LDR）并且对场景的光照水平控制较少。

还要考虑到，也许您需要调整一些对象的设置，比如光强度和材质属性，因为有时我们使用后期处理来修复可能由错误设置的对象引起的图形错误，这是不好的。例如，增加场景中的环境光照会大大改变效果的输出，我们可以利用这一点来增加整体亮度，而不是使用效果，如果我们发现场景太暗。

这涵盖了要使用的主要图像效果。请记住，不是使用每一个效果，而是使用您认为对您的场景有贡献的效果；它们在性能方面并不是免费的（尽管不是那么资源密集），所以要明智地使用它们。此外，您可以查看已创建的配置文件，将它们应用到您的游戏中，看看微小的变化如何产生巨大的影响。

# 总结

在本章中，我们讨论了在我们的场景中应用的基本和高级全屏效果，使其在相机镜头效果方面看起来更真实，在颜色扭曲方面更时尚。我们还讨论了 HDR 和深度图的内部结构，以及在使用这些效果时它们的重要性，这可以立即提高您游戏的图形质量，而付出的努力却很少。

现在我们已经涵盖了 Unity 系统中常见的大部分图形，让我们开始看看如何通过声音增强我们场景的沉浸感。


# 第十章：声音和音乐集成

我们刚刚达到了足够好的图形质量，但我们缺少游戏美学的一个重要部分：声音。声音经常被排在游戏开发的最后一步，但它是那种如果存在，你不会注意到它的存在，但如果你没有它，你会感觉到缺少了什么。它将帮助你加强你在游戏中想要的氛围，并且必须与图形设置相匹配。

在本章中，我们将讨论以下声音概念：

+   导入音频

+   集成和混合音频

# 导入音频

与图形资产一样，正确设置音频资产的导入设置非常重要，如果不正确的话可能会消耗大量资源。

在本节中，我们将讨论以下音频导入概念：

+   音频类型

+   配置导入设置

让我们开始讨论我们可以使用的不同类型的音频。

## 音频类型

视频游戏中存在不同类型的音频，包括以下内容：

+   **音乐**：用于根据情况增强玩家体验的音乐。

+   **音效（SFX）**：作为对玩家或 NPC 行为的反应发生的声音，例如点击按钮、行走、打开门和开枪。

+   **环境声音**：一个只有作为事件反应的声音的游戏会感觉空荡。如果你正在重建城市中的公寓，即使玩家只是闲置在房间中什么也不做，应该听到很多声音，大部分声音的来源都在房间外，比如飞机在头顶飞过，两个街区外的建筑工地，和街上的汽车。创建看不见的对象是资源的浪费。相反，我们可以在整个场景中放置单独的声音来重新创建所需的氛围，但这将消耗大量的 CPU 和 RAM 来实现可信的结果。考虑到这些声音通常是用户注意力的第二个平面，我们可以将它们全部合并成一个循环轨道，只播放一个音频，这正是环境声音。如果你想创建一个咖啡馆场景，你可以简单地去一个真正的咖啡馆录制几分钟的音频，将其用作你的环境声音。

对于几乎所有的游戏，我们至少需要一条音乐曲目，一条环境曲目和几个 SFX 来开始音频的制作。和往常一样，我们有不同的音频资产来源，但我们将使用资产商店。它有三个音频类别，可以搜索到我们需要的资产：

![图 10.1 - 资产商店中的音频类别](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.01_B14199.jpg)

图 10.1 - 资产商店中的音频类别

在我的情况下，我还使用了搜索栏来进一步过滤类别，搜索天气以找到雨的效果。有时，你无法单独找到确切的音频；在这种情况下，你需要深入**包和库**，所以在这里要有耐心。在我的情况下，我选择了你可以在下图中看到的三个包，但是导入其中一些包含的声音，所有这些声音在项目中都会占用很大的空间。对于环境声音，我选择了雨。然后，我选择了**音乐 - 伤感希望**作为音乐，对于 SFX，我选择了一个枪声音效包，用于我们未来的玩家英雄角色。当然，你可以选择其他包以更好地满足你的游戏需求：

![图 10.2 - 我们游戏的包](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.02_B14199.jpg)

图 10.2 - 我们游戏的包

请记住，当你阅读这篇文章时，这些确切的包可能不可用。在这种情况下，你可以下载其他包，或者从 GitHub 仓库中选择我使用的文件。现在我们有了必要的音频包，让我们讨论如何导入它们。

## 配置导入设置

我们有几个可以调整的导入设置，但问题是我们需要考虑音频的使用情况才能正确设置它，所以让我们看看每种情况的理想设置。要查看导入设置，像往常一样，您可以选择资产并在检查器面板中查看它，如下面的截图所示：

![图 10.3 - 音频导入设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.03_B14199.jpg)

图 10.3 - 音频导入设置

让我们讨论最重要的几个，首先是**强制转换为单声道**。一些音频可能带有立体声声道，这意味着我们左耳和右耳分别有一个声音。这意味着一段音频实际上可以包含两个不同的音轨。立体声音对于不同的效果和乐器空间化在音乐的情况下是有用的，所以在这些情况下我们希望有这种效果，但也有其他情况下立体声并不有用。考虑 3D 音效，比如射击枪声或步行声音。在这些情况下，我们需要听到声音来自源头的方向。如果枪声发生在我的左边，我需要听到它来自我的左边。在这些情况下，我们可以通过在音频导入设置中勾选**强制转换为单声道**复选框来将立体声音转换为单声道音频。这将使 Unity 将两个声道合并为一个声道，将音频的大小通常减少到几乎一半（有时更多，有时更少，这取决于各种因素）。

您可以在音频资产检查器底部验证该设置和其他设置的影响，您可以在那里看到导入的音频大小：

![图 10.4 - 左：未强制转换为单声道的音频。右：相同的音频强制转换为单声道](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.04_B14199.jpg)

图 10.4 - 左：未强制转换为单声道的音频。右：相同的音频强制转换为单声道

接下来要讨论的设置是**加载类型**，这是一个重要的设置。为了播放一些音频，Unity 需要从磁盘读取音频，解压缩，然后播放。加载类型改变了这三个过程的处理方式。我们在这里有以下三个选项：

+   **加载时解压缩**：最占用内存的选项。这种模式将使 Unity 在场景加载时将音频解压缩到内存中。这意味着音频将占用大量 RAM 空间，因为我们已经加载了未压缩的版本。使用这种模式的优势在于播放音频更容易，因为我们已经准备好在 RAM 中播放原始音频数据。

+   **流式传输**：与**加载时解压缩**完全相反。这种模式从不在 RAM 中加载音频。相反，当音频播放时，Unity 会从磁盘读取音频资产的一部分，解压缩它，播放它，然后重复这个过程，对于每个正在**流式传输**播放的音频部分运行一次。这意味着这种模式将会占用大量 CPU 资源，但几乎不会消耗 RAM 字节。

+   **内存中的压缩**：中间地带。这种模式将在场景加载时从磁盘加载音频，但将保持其在内存中的压缩状态。当 Unity 需要播放音频时，它只会从 RAM 中取一部分，解压缩并播放。请记住，从 RAM 中读取音频资产的部分比从磁盘读取要快得多。

也许如果您是一位经验丰富的开发者，您可以轻松确定哪种模式更适合哪种类型的音频，但如果这是您第一次接触视频游戏，可能会感到困惑，所以让我们讨论不同情况下的最佳模式：

+   **频繁的短音频**：这可能是射击枪声或脚步声等持续时间不到 1 秒的声音，但可能会在多个实例中发生并同时播放。在这种情况下，我们可以使用加载时解压缩。未压缩的短音频与其压缩版本的大小差异不大。而且，由于这是性能最佳的 CPU 选项，有多个实例不会对性能产生巨大影响。

+   **不经常的大型音频**：这包括音乐、环境声音和对话。这些类型的音频通常只有一个实例在播放，而且它们通常很大。这些情况更适合于流媒体模式，因为在低端设备（如移动设备）中对它们进行压缩或解压缩可能会产生巨大影响（在 PC 上，有时我们可以使用内存中的压缩）。CPU 可以处理两三个音频位在流媒体中播放，但尽量不要超过这个数量。

+   **频繁的中等音频**：这包括多人游戏中预制的语音对话、角色表情、长时间的爆炸声音，或者任何超过 500KB 的音频（这不是一个严格的规则——这个数字在很大程度上取决于目标设备）。将这种类型的音频解压缩到 RAM 中可能会对性能产生明显影响，但由于这种音频相对较小，通常不会对我们的游戏产生巨大影响，并且我们将避免浪费 CPU 资源从磁盘读取。

还有其他情况需要考虑，但这些可以根据前面的情况进行推断。请记住，前面的分析是根据标准游戏的要求进行的，但这可能会根据您的游戏和目标设备而有很大不同。也许你正在制作一个不会消耗大量 RAM 但在 CPU 资源方面非常密集的游戏，在这种情况下，你可以将所有内容都放在加载时解压缩。重要的是要考虑游戏的所有方面，并根据资源进行平衡。

最后，还有一件要考虑的事情是压缩格式，这将改变 Unity 在发布游戏时对音频进行编码的方式。不同的压缩格式将以不同的压缩比率换取与原始音频的保真度较低或更高的解压缩时间，所有这些都根据音频模式和长度而有很大不同。我们有三种压缩格式：

+   **PCM**：无压缩格式将为您提供最高的音频质量，没有噪音伪影，但会导致更大的资产文件大小。

+   **ADPCM**：以这种方式压缩音频可以减小文件大小并产生快速的解压缩过程，但这可能会引入在某些类型的音频中会明显的噪音伪影。

+   **Vorbis**：一种高质量的压缩格式，几乎不会产生任何伪影，但解压时间较长，因此播放 Vorbis 音频会比其他格式稍微更加密集。它还提供了一个质量滑块，可以选择精确的压缩程度。

你应该使用哪一个？同样，这取决于你的音频特性。短平滑的音频可以使用 PCM，而长嘈杂的音频可以使用 ADPCM；这种格式引入的伪影将被隐藏在音频本身中。也许长平滑的音频在压缩伪影明显时使用 Vorbis 会更好。有时，这只是一个试错的问题。也许默认使用 Vorbis，当性能降低时，尝试切换到 ADPCM，如果那导致故障，就切换到 PCM。当然，问题在于确保音频处理确实是导致性能问题的原因——也许将所有音频切换到 ADPCM 并检查是否有所不同是检测的一个好方法，但更好的方法是使用 Profiler，这是一个性能测量工具，我们将在本书后面看到。

我们还有其他设置，比如采样率设置，再次，通过一些试错，你可以找到最佳设置。

我已经设置了从资产商店下载的音频，如下截图所示。第一张截图显示了我是如何设置音乐和环境音频文件的（大文件）：

![图 10.5 – 音乐和环境设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.05_B14199.jpg)

图 10.5 – 音乐和环境设置

应该是立体声（未选中强制转换为单声道），使用**流式加载类型**，因为它们很大，只会有一个实例播放，并且使用**ADPCM 压缩格式**，因为 Vorbis 并没有产生巨大的大小差异。

第二个截图显示了我如何设置 SFX 文件（小文件）：

![图 10.6–射击 SFX 设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.06_B14199.jpg)

图 10.6–射击 SFX 设置

将是 3D 声音，因此应该选中强制转换为单声道。将是短暂的，因此在加载时解压缩加载类型效果更好。Vorbis 压缩格式将 ADPCM 大小减少了一半以上

现在我们的音频片段已经正确配置，我们可以开始在场景中使用它们了。

# 集成和混音音频

我们可以简单地将我们的音频片段拖到场景中开始使用它，但是我们可以深入挖掘一下，探索将它们配置到每种可能的场景中的最佳方法。 

在本节中，我们将研究以下音频集成概念：

+   使用 2D 和 3D AudioSources

+   使用音频混音器

让我们开始探索 AudioSources，这些对象负责音频播放。

## 使用 2D 和 3D AudioSources

**AudioSources**是可以附加到 GameObject 的组件。它们负责根据**AudioClips**发出游戏中的声音，这些将是我们之前下载的音频资产。重要的是要区分**AudioClip**和**AudioSource**：我们可以有一个单一的爆炸**AudioClip**，但有很多**AudioSources**播放它，模拟多个爆炸。这样，**AudioSource**可以被视为**AudioClip**的一个实例。

创建**AudioSource**的最简单方法是选择一个**AudioClip**（音频资产）并将其拖到**Hierarchy**窗口中。尽量避免将音频拖到现有对象中；相反，将其拖动到对象之间，这样 Unity 将创建一个带有**AudioSource**的新对象，而不是将其添加到现有对象中（有时，您可能希望现有对象具有**AudioSource**，但现在让我们保持简单）：

![图 10.7–将音频剪辑拖到层次结构窗口之间的对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.07_B14199.jpg)

图 10.7–将音频剪辑拖到层次结构窗口之间的对象

下面的截图显示了通过将音乐资产拖到场景中生成的**AudioSource**。您可以看到**AudioClip**字段引用了拖动的音频：

![图 10.8–配置为播放我们的音乐资产的 AudioSource](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.08_B14199.jpg)

图 10.8–配置为播放我们的音乐资产的 AudioSource

正如您所看到的，**AudioSource**有几个设置，让我们在以下列表中回顾常见的设置：

+   **播放时唤醒**：确定游戏启动时音频是否自动开始播放。我们可以取消选中该选项，并通过脚本播放音频，也许是玩家射击或跳跃时（有关详细信息，请参阅本书的第三部分）。

+   **循环**：当音频播放完毕时会自动重复。请记住始终在音乐和环境音频剪辑上检查此设置。很容易忘记这一点，因为这些曲目很长，我们可能永远不会在测试中达到它们的结尾。

+   **音量**：控制音频强度。

+   **音调**：控制音频速度。这对于模拟慢动作或引擎转速增加等效果非常有用。

+   **空间混合**：控制我们的音频是 2D 还是 3D。在 2D 模式下，音频将在所有距离上以相同的音量听到，而 3D 将使音频音量随着距离增加而减小。

在我们的音乐曲目的情况下，我已经按照下面的截图所示进行了配置。您可以拖动环境雨声以将其添加到场景中，并使用与这些相同的设置，因为我们希望所有场景中都具有相同的环境效果。但是，在复杂的场景中，您可以在整个场景中散布不同的 3D 环境声音，以根据当前环境改变声音：

![图 10.9 – 音乐和环境设置。这将循环播放，设置为唤醒时播放，是 2D](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.09_B14199.jpg)

图 10.9 – 音乐和环境设置。这将循环播放，设置为唤醒时播放，是 2D

现在，您可以拖动射击效果并按照以下截图所示进行配置。正如您所看到的，这种情况下音频不会循环，因为我们希望射击效果每发一颗子弹就播放一次。请记住，在我们的情况下，子弹将是一个预制件，每次按下射击键时都会生成一个子弹，因此每颗子弹都将有自己的**AudioSource**在创建子弹时播放。此外，子弹设置为 3D **空间混合**，这意味着效果将根据音频源相对于摄像机位置的位置而通过不同的扬声器传输：

![图 10.10 – 音效设置。这不会循环，是一个 3D 声音](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.10_B14199.jpg)

图 10.10 – 音效设置。这不会循环，是一个 3D 声音

在处理 3D 声音时需要考虑的一点是**音量衰减**设置，它位于 3D 声音设置部分。此设置控制声音随着到相机的距离而衰减的方式。默认情况下，您可以看到此设置设置为**对数衰减**，这是现实生活中声音的工作方式，但有时您不希望现实生活中的声音衰减，因为现实生活中的声音通常即使源头非常遥远也会被轻微听到。

一个选项是切换到**线性衰减**并使用**最大距离**设置来配置确切的最大距离：

![图 10.11 – 最大距离为 10 米的 3D 声音，使用线性衰减](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.11_B14199.jpg)

图 10.11 – 最大距离为 10 米的 3D 声音，使用线性衰减

现在我们可以配置单独的音频片段，让我们看看如何使用**音频混音器**对音频实例组应用效果。

## 使用音频混音器

我们将在整个游戏中播放几个音频实例：角色的脚步声，射击声，篝火声，爆炸声，雨声等等。根据情况精确控制哪些声音应该更响或更轻，并应用效果来加强某些情况，比如因附近爆炸而受到震惊，这就是音频混音 - 将几种声音以一种连贯和受控的方式混合在一起的过程。

在 Unity 中，我们可以创建一个音频混音器，这是一个我们可以用来定义声音组的资产。对组的所有更改都将影响其中的所有声音，可能是通过提高或降低音量，或者应用效果。您可以拥有 SFX 和音乐组来分别控制声音 - 例如，您可以在**暂停**菜单中降低 SFX 音量，但不降低音乐音量。此外，组是以层次结构组织的，其中一个组还可以包含其他组，因此对组的更改也将应用于其子组。事实上，您创建的每个组都将始终是主组的子组，这个组将影响游戏中使用该混音器的每一个声音。

让我们创建一个带有 SFX 和音乐组的混音器：

1.  在项目窗口中，使用`主混音器`。

1.  双击创建的资产以打开**音频混音器**窗口：![图 10.12 – 音频混音器窗口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.12_B14199.jpg)

图 10.12 – 音频混音器窗口

1.  点击`SFX`：![图 10.13 – 组创建](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.13_B14199.jpg)

图 10.13 – 组创建

1.  点击`音乐`。记得在点击**+**按钮之前选择**主**组，因为如果选择了其他组，新组将成为该组的子组。无论如何，您可以通过在**层次结构**窗口中拖动来重新排列组的子父关系：![图 10.14 – 主、SFX 和音乐组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.14_B14199.jpg)

图 10.14 – 主、SFX 和音乐组

1.  在**层次**窗口中选择**音乐**GameObject，并在检视器窗口中查找**AudioSource**组件。

1.  单击**输出**属性右侧的圆圈，并在**音频混音器**组选择器中选择**音乐**组。这将使该**AudioSource**受到指定混音器组的设置的影响：![图 10.15 - 使一个 AudioSource 属于一个音频混音器组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.15_B14199.jpg)

图 10.15 - 使一个 AudioSource 属于一个音频混音器组

1.  如果您现在玩游戏，您会看到音频混音器中的音量表开始移动，表明音乐正在通过**音乐**组。您还会看到**主**组音量表也在移动，表明通过**音乐**组传递的声音也会通过**主**组（**音乐**组的父级）传递到计算机的声卡：![图 10.16 - 组音量级别](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.16_B14199.jpg)

图 10.16 - 组音量级别

1.  重复*步骤 5*和*6*，使环境和射击声音属于**SFX**组。

现在我们已经将我们的声音分成组，我们可以开始调整组的设置。但是，在这样做之前，我们需要考虑这样一个事实，即我们不希望始终使用相同的设置，就像之前提到的暂停菜单情况一样，其中 SFX 音量应该更低。为了处理这些情况，我们可以创建快照，这些快照是我们混音器的预设，可以在游戏过程中通过脚本激活。我们将在本书的第三部分处理脚本步骤，但是我们可以为游戏设置创建一个正常快照和一个暂停快照。

如果您检查**快照**列表，您会看到已经创建了一个快照 - 那可以是我们的正常快照。因此，让我们通过以下方式创建一个暂停快照：

1.  单击`暂停`。记得停止游戏以编辑混音器，或者单击**在 Playmode 中编辑**选项允许 Unity 在播放过程中更改混音器。如果选择后者，请记住更改将在停止游戏时保留，不像对游戏对象的更改。实际上，如果您在播放模式下更改其他资产，这些更改也将保留 - 只有游戏对象的更改会被还原（以及我们现在不讨论的一些其他特定情况）：![图 10.17 - 快照创建](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.17_B14199.jpg)

图 10.17 - 快照创建

1.  选择**暂停**快照并降低**SFX**组的音量滑块：![图 10.18 - 降低暂停快照的音量](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.18_B14199.jpg)

图 10.18 - 降低暂停快照的音量

1.  玩游戏，听听声音是否仍然保持正常音量。这是因为原始快照是默认的 - 您可以通过检查其右侧的星号来看到。您可以右键单击任何快照，并使用**设置为起始快照**选项将其设置为默认快照。

1.  单击**在 Playmode 中编辑**以在运行时启用**音频混音器**修改。

1.  单击**暂停**快照以启用它，并听听**射击**和**环境**声音的音量是否已经减小。

正如您所看到的，混音器的主要用途之一是控制组音量，特别是当您看到组音量超过 0 标记时，表明该组太响了。无论如何，混音器还有其他用途，比如应用效果。如果您玩过任何战争游戏，您会注意到每当附近有炸弹爆炸时，您会在一段时间内以不同的方式听到声音，就好像声音在另一个房间里一样。这可以通过一种称为低通的效果来实现，它会阻止高频声音，这正是在这些情景中发生的：爆炸产生的高音量声音刺激了我们的耳朵，使它们在一段时间内对高频率的声音变得不那么敏感。

我们可以向任何通道添加效果，并根据当前快照进行配置，就像我们为音量所做的那样，方法如下：

1.  点击**主**组底部的**添加...**按钮，并选择**低通简单**：![图 10.19 - 通道的效果列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.19_B14199.jpg)

图 10.19 - 通道的效果列表

1.  选择正常快照（名为**快照**）进行修改。

1.  选择**主**组并查看检查器面板，在那里您将看到通道及其效果的设置。

1.  设置`22000`）；这将禁用该效果。

1.  对**暂停**快照重复*步骤 3*和*4*；我们不希望在该快照中出现这种效果。

1.  创建一个名为**炸弹震慑**的新快照并选择它进行编辑。

1.  设置`1000`：![图 10.20 - 设置低通简单效果的截止频率](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_10.20_B14199.jpg)

图 10.20 - 设置低通简单效果的截止频率

1.  玩游戏并在快照之间切换以检查差异。

除了低通滤波器，您还可以应用其他几种滤波器，比如回声，以创建一种近乎梦幻的效果，或者使用发送、接收和减弱的组合来根据另一个组的强度降低其音量（例如，您可能希望在对话发生时降低 SFX 音量）。我邀请您尝试这些和其他效果，并检查结果以确定潜在用途。

# 摘要

在本章中，我们讨论了如何导入和集成声音，考虑它们的内存影响并应用效果以生成不同的场景。声音是实现所需游戏体验的重要组成部分，因此请花足够的时间来做好它。

现在我们已经涵盖了游戏中几乎所有重要的美学方面，让我们创建另一种形式的视觉沟通，用户界面。


# 第十一章：用户界面设计

在屏幕上显示的一切并通过计算机的扬声器传达的都是一种形式的沟通。在之前的章节中，我们使用三维模型让用户知道他们在山中的基地，并通过适当的声音和音乐加强了这个想法。但对于我们的游戏，我们需要传达其他信息，比如用户剩余的生命值、当前得分等，有时很难使用游戏内图形来表达这些信息（有一些成功的案例可以做到这一点，比如*死亡空间*，但让我们保持简单）。为了传达这些信息，我们将在我们的场景顶部添加另一层图形，通常称为**用户界面**（**UI**）或**抬头显示**（**HUD**）。

这将包含不同的视觉元素，如文本字段、条形图和按钮，以便用户可以根据诸如生命值低时逃到安全地方等情况做出知情决策：

![图 11.1 – 角色创建 UI 显示有关角色统计信息的数字](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.01_B14199.jpg)

图 11.1 – 角色创建 UI 显示有关角色统计信息的数字

在本章中，我们将研究以下 UI 概念：

+   理解**Canvas**和**RectTransform**

+   Canvas 对象类型

+   创建响应式 UI

在本章结束时，您将能够使用 Unity UI 系统创建能够通知用户游戏状态并允许他们通过按按钮来采取行动的界面。让我们开始讨论 Unity UI 系统的基本概念之一——RectTransform。

# 理解 Canvas 和 RectTransform

目前，Unity 中有三种不同用途的 UI 系统：

+   **UI 元素**：用于扩展 Unity 编辑器的系统，具有自定义窗口和工具。它使用了一些 Web 概念，如样式表和基于 XML 的语言来布局您的 UI。将来，它将可用于游戏中使用。

+   **Unity UI**：基于 GameObject 的 UI 仅适用于游戏内 UI（不是编辑器扩展）。您可以像编辑其他对象一样使用 GameObject 和组件来创建它。

+   **IMGUI**：一种完全使用脚本创建的遗留代码 UI。很久以前，这是编辑器和游戏内 UI 中唯一使用的 UI 系统。如今，它只用于扩展编辑器，并很快将被 UI 元素完全取代。

在本章中，我们只关注游戏内 UI，以向玩家传达有关游戏状态的不同信息，因此我们将使用 Unity UI。在撰写本书时，有计划用 UI 元素替换 Unity UI，但尚无预计的时间。无论如何，即使 Unity 很快发布 UI 元素作为游戏内 UI 系统，Unity UI 仍将存在一段时间，并且完全能够处理您需要创建的所有类型的 UI。

如果您要使用 Unity UI，首先需要了解它的两个主要概念——Canvas 和**RectTransform**。Canvas 是将包含和渲染我们的 UI 的主对象，而 RectTransform 是负责在屏幕上定位和调整每个 UI 元素的功能。

在这一部分，我们将研究以下 Unity UI 概念：

+   使用 Canvas 创建 UI

+   使用 RectTransform 定位元素

让我们开始使用 Canvas 组件来创建我们的 UI。

## 使用 Canvas 创建 UI

在 Unity UI 中，你在 UI 中看到的每个图像、文本和元素都是一个 GameObject，具有一组适当的组件，但为了让它们工作，它们必须是带有 Canvas 组件的主 GameObject 的子对象。这个组件负责触发 UI 生成并在每个子对象上进行绘制迭代。我们可以配置这个组件来指定这个过程的工作方式，并使其适应不同的可能要求。

首先，您可以通过**GameObject** | **UI** | **Canvas**选项简单地创建一个画布。这样做后，您将在场景中看到一个矩形，代表用户屏幕，因此您可以在其中放置元素，并预览它们相对于用户监视器的位置。您可以在以下截图中看到这个矩形的示例：

![图 11.2 - 画布屏幕矩形](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.02_B14199.jpg)

图 11.2 - 画布屏幕矩形

您可能会想到两件事。首先，“为什么矩形在场景中间？我希望它始终显示在屏幕上！”。不用担心，因为情况确实如此。当您编辑 UI 时，您将把它视为级别的一部分，作为其中的一个对象，但当您玩游戏时，它将始终投影到屏幕上，覆盖在每个对象的顶部。此外，您可能会想知道为什么矩形如此巨大，这是因为屏幕上的一个像素在场景上对应一米。所以不用担心这一点；当您在游戏视图中看到游戏时，您将看到所有 UI 元素在用户屏幕上的正确大小和位置。

在向 UI 添加元素之前，值得注意的是，当您创建 UI 时，会在画布旁边创建第二个对象，称为事件系统。这个对象对于渲染 UI 并不是必要的，但如果您希望 UI 可以交互，也就是包括点击按钮、在字段中输入文本或使用摇杆导航 UI 等操作，那么它就是必要的。**EventSystem**组件负责对用户输入进行采样，比如键盘、鼠标或摇杆，并将数据发送给 UI 以做出相应反应。我们可以更改与 UI 交互的确切按钮，但默认值现在可以接受，所以只需知道如果要与 UI 交互，就需要这个对象。如果出于某种原因删除了该对象，可以在**GameObject** | **UI** | **Event System**中重新创建它。

现在我们有了创建 UI 的基本对象，让我们向其中添加元素。

## 使用 RectTransform 定位元素

在 Unity UI 中，您在 UI 中看到的每个图像、文本和元素都是一个 GameObject，具有一组适合其用途的组件，但您会发现它们大多数都有一个共同的组件-**RectTransform**。UI 的每个部分本质上都是一个填充有文本或图像的矩形，并且具有不同的行为，因此了解**RectTransform**组件的工作原理以及如何编辑它是很重要的。

为了尝试这个组件，让我们通过以下步骤创建和编辑 UI 的一个简单白色矩形元素的位置：

1.  转到**GameObject** | **UI** | **Image**。之后，您将看到在**Canvas**元素内创建了一个新的 GameObject。Unity 会负责将任何新的 UI 元素设置为**Canvas**的子元素；在外面，该元素将不可见：![图 11.3 - 默认图像 UI 元素-白色框](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.03_B14199.jpg)

图 11.3 - 默认图像 UI 元素-白色框

1.  单击**场景**视图顶部栏中的 2D 按钮。这将只是改变场景视图的透视，以更适合编辑 UI（以及二维游戏）：![图 11.4 - 2D 按钮位置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.04_B14199.jpg)

图 11.4 - 2D 按钮位置

1.  双击**层次结构**窗口中的画布，使 UI 完全适应场景视图。这将使我们能够清楚地编辑 UI。您还可以使用鼠标滚轮导航 UI 进行缩放，并单击并拖动滚轮以平移相机：![图 11.5 - 2D 编辑模式下的场景视图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.05_B14199.jpg)

图 11.5 - 2D 编辑模式下的场景视图

1.  禁用**PPVolume**对象以禁用后期处理。最终的 UI 不会有后期处理，但编辑器视图仍然会应用它。记得稍后重新启用它：![图 11.6 - 禁用游戏对象-在这种情况下是后期处理体积](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.06_B14199.jpg)

图 11.6 – 禁用游戏对象—在这种情况下是后期处理体积

1.  启用（如果尚未启用）**RectTrasform**工具，这是 Unity 编辑器左上部的第五个按钮（或按*T*键）。这将启用矩形标尺，允许您移动、旋转和缩放二维元素。您可以使用通常的变换、旋转和缩放标尺，这些是我们在 3D 模式下使用的标尺，但矩形标尺会带来更少的麻烦，特别是在缩放方面:![图 11.7 – 矩形标尺按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.07_B14199.jpg)

图 11.7 – 矩形标尺按钮

1.  使用矩形标尺，拖动对象以移动它，使用蓝点改变其大小，或者将鼠标放在靠近蓝点的棘手位置以旋转它。请注意，使用这个标尺调整对象的大小并不等同于缩放对象，但稍后会详细介绍:![图 11.8 – 用于编辑二维元素的矩形标尺](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.08_B14199.jpg)

图 11.8 – 用于编辑二维元素的矩形标尺

1.  在检视器窗口中，注意在更改 UI 元素的大小后，`1`，`1`，`1`），但是您可以看到**宽度**和**高度**属性已经改变。**Rect Transform**本质上是一个经典的变换，但增加了**宽度**和**高度**（以及其他稍后要探索的属性）。您可以在这里设置以像素表示的确切值:

![图 11.9 – 矩形变换属性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.09_B14199.jpg)

图 11.9 – 矩形变换属性

现在我们知道了如何定位任何 UI 对象的基础知识，让我们来探索可以添加到画布中的不同类型的元素。

# 画布对象类型

到目前为止，我们已经使用了最简单的画布对象类型—白色框，但是还有很多其他对象类型可以使用，比如图像、按钮、文本等等。它们都使用**RectTransform**来定义它们的显示区域，但每种对象都有自己的概念和配置需要理解。

在本节中，我们将探索以下画布对象的概念：

+   集成 UI 资产

+   创建 UI 控件

让我们首先开始探索如何集成图像和字体，以便在画布中使用它们，这样我们就可以使用图像和文本 UI 对象类型将它们集成到我们的 UI 中。

## 集成 UI 资产

在使我们的 UI 使用漂亮的图形资产之前，我们需要像往常一样将它们正确地集成到 Unity 中。在下面的截图中，您将找到我们在*第一章*中提出的 UI 设计，*从头开始设计游戏*:

![图 11.10 – 第一章的 UI 设计](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.10_B14199.jpg)

图 11.10 – 第一章的 UI 设计

除此之外，我们还将添加一个暂停菜单，当用户按下*Esc*键时将被激活。它将如下截图所示：

![图 11.11 – 暂停菜单设计](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.11_B14199.jpg)

图 11.11 – 暂停菜单设计

基于这些设计，我们可以确定我们将需要以下资产：

+   英雄的头像图像

+   生命值条图像

+   暂停菜单背景图像

+   暂停菜单按钮图像

+   文本的字体

像往常一样，我们可以在互联网上或者资产商店上找到所需的资产。在我的情况下，我会混合使用两者。让我们从最简单的一个开始—头像。采取以下步骤:

1.  从互联网上下载你想要的头像:![图 11.12 – 下载的头像资产](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.12_B14199.jpg)

图 11.12 – 下载的头像资产

1.  将其添加到你的项目中，可以通过将其拖放到项目窗口中，或者使用`Sprites`文件夹。

1.  选择纹理，在检视器窗口中，将**纹理类型**设置为**精灵（2D 和 UI）**。所有纹理默认都准备用于 3D。此选项准备好所有用于 2D 的内容。

对于条形、按钮和窗口背景，我将使用资产商店寻找 UI 包。在我的情况下，我发现以下截图中的包是一个很好的开始我的 UI。通常情况下，请记住这个确切的包现在可能不可用。在这种情况下，请记住寻找另一个类似的包，或者从 GitHub 存储库中选择精灵：

![图 11.13 - 选择的 UI 包](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.13_B14199.jpg)

图 11.13 - 选择的 UI 包

首先，包含许多以精灵形式配置的图像，但我们可以进一步修改导入设置以实现高级行为，这是我们在按钮中需要的。按钮资产具有固定大小，但如果需要更大的按钮怎么办？一种选择是使用不同尺寸的其他按钮资产，但这将导致大量重复的按钮和其他资产，例如不同大小的背景用于不同的窗口，这将消耗不必要的 RAM。另一种选择是使用九片方法，这种方法包括将图像分割，使角落与其他部分分离。这允许 Unity 拉伸图像的中间部分以适应不同的大小，保持角落的原始大小，当与巧妙的图像结合时，可以用来创建几乎任何所需的大小。在下图中，您可以看到左下角有九片的形状，在同一图中的右下角，您可以看到形状被拉伸但保持其角落的原始大小。右上角显示了拉伸的形状没有片。您可以看到非切片版本被扭曲，而切片版本没有被扭曲：

![图 11.14 - 切片与非切片图像拉伸](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.14_B14199.jpg)

图 11.14 - 切片与非切片图像拉伸

在这种情况下，我们可以将九片应用于按钮和面板背景图像，以在游戏的不同部分使用它们。为了做到这一点，请执行以下操作：

1.  使用**窗口** | **包管理器**选项打开包管理器。

1.  验证`Unity Registry`：![图 11.15 - 包管理器中显示所有包](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.15_B14199.jpg)

图 11.15 - 包管理器中显示所有包

1.  安装**2D Sprite**包以启用精灵编辑工具（如果尚未安装）：![图 11.16 - 包管理器中的 2D Sprite 包](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.16_B14199.jpg)

图 11.16 - 包管理器中的 2D Sprite 包

1.  在**项目**窗口中选择按钮精灵，然后单击**检查器**窗口中的**精灵编辑器**按钮：![图 11.17 - 检查器窗口中的精灵编辑器按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.17_B14199.jpg)

图 11.17 - 检查器窗口中的精灵编辑器按钮

1.  在**精灵编辑器**窗口中，找到并拖动图像边缘的绿点以移动切片标尺。尝试确保切片不位于按钮边缘的中间。需要注意的一件事是，在我们的情况下，我们将使用三个切片而不是九个，因为我们的按钮不会在垂直方向上拉伸。

1.  单击窗口右上角的**应用**按钮，然后关闭它：![图 11.18 - 精灵编辑器窗口中的九片](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.18_B14199.jpg)

图 11.18 - 精灵编辑器窗口中的九片

1.  对**背景**面板重复相同的步骤。在我的情况下，您可以在以下截图中看到，这个背景并没有考虑到九片，因为图像的所有中间区域都可以变小，如果使用九片方法来拉伸它们，它们看起来会一样。因此，我们可以使用任何图像编辑工具对其进行编辑，或者暂时使用它：

![图 11.19 - 精灵编辑器窗口中的九片](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.19_B14199.jpg)

图 11.19 - 精灵编辑器窗口中的九片

现在我们已经准备好我们的精灵，我们可以找到一个字体，这是一个非常简单的任务。只需下载任何`.ttf`或`.otf`格式的字体并将其导入 Unity，就可以了，无需进一步配置。您可以在互联网上找到许多好的免费字体网站。我习惯于使用经典的[DaFont.com](http://DaFont.com)网站，但还有很多其他网站可以使用。在我的情况下，我将使用以下字体：

![图 11.20 - 我从 DaFont.com 选择的用于项目的字体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.20_B14199.jpg)

图 11.20 - 我从 DaFont.com 选择的用于项目的字体

如果压缩文件包含多个字体文件，您可以将它们全部拖入 Unity，然后使用您最喜欢的字体。同样，尝试将字体放在名为“字体”的文件夹中。

现在我们已经准备好创建 UI 所需的所有资产，让我们探索不同类型的组件以创建所有所需的 UI 元素。

## 创建 UI 控件

几乎 UI 的每个部分都将是巧妙配置的图像和文本的组合。在本节中，我们将探索以下组件：

+   `图像`

+   `文本`

+   `按钮`

让我们开始探索**图像**。实际上，我们的 UI 中已经有一个图像 - 我们在本章前面创建的白色矩形。如果选择它并查看检查器窗口，您会注意到它有一个图像组件，就像以下截图中的一个：

![图 11.21 - 图像组件的检查器窗口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.21_B14199.jpg)

图 11.21 - 图像组件的检查器窗口

让我们开始探索该组件的不同设置，从我们的英雄头像开始。采取以下步骤：

1.  使用矩形图标，将白色矩形定位在 UI 的左上角：![图 11.22 - 位于 UI 左上角的白色矩形](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.22_B14199.jpg)

图 11.22 - 位于 UI 左上角的白色矩形

1.  在“源图像”属性中选择并拾取下载的英雄头像精灵：![图 11.23 - 设置我们的图像组件的精灵](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.23_B14199.jpg)

图 11.23 - 设置我们的图像组件的精灵

1.  我们需要校正图像的纵横比以防止失真。做到这一点的一种方法是单击“图像”组件，使图像使用与原始精灵相同的大小。但是，通过这样做，图像可能会变得太大，因此您可以按*Shift*减小图像大小以修改“宽度”和“高度”值。另一种选择是选中“保持纵横比”复选框，以确保图像适合矩形而不会拉伸。在我的情况下，我将两者都使用：

![图 11.24 - 保持纵横比和设置原生大小图像选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.24_B14199.jpg)

图 11.24 - 保持纵横比和设置原生大小图像选项

现在，让我们通过以下步骤创建生命条：

1.  使用“GameObject”|“UI”|“图像”选项创建另一个“图像”组件。

1.  将“源图像”属性设置为您下载的生命条图像：![图 11.25 - 头像和生命条](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.25_B14199.jpg)

图 11.25 - 头像和生命条

1.  将“图像类型”属性设置为“填充”。

1.  将“填充方法”属性设置为“水平”。

1.  拖动“填充量”滑块，查看根据滑块值切割条的方式。当我们在书的第三部分编写生命系统时，我们将通过脚本更改该值，那里我们将编写自己的脚本：![图 11.26 - 填充量滑块，将图像宽度切割为其大小的 73%](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.26_B14199.jpg)

图 11.26 - 填充量滑块，将图像宽度切割为其大小的 73%

1.  在我的情况下，条图像也带有条框，因此我将创建另一个图像，设置精灵，并将其定位在生命条顶部以形成框架。请记住，**层次结构**窗口中对象的顺序决定了它们绘制的顺序。因此，在我的情况下，我需要确保框架游戏对象在生命条图像下方：![图 11.27 – 将一个图像放在另一个图像上创建框架效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.27_B14199.jpg)

图 11.27 – 将一个图像放在另一个图像上创建框架效果

1.  重复步骤 1 至 6，创建底部的基本条，或者只需复制并粘贴条和框架，并将其定位在屏幕底部：![图 11.28 – 两个条](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.28_B14199.jpg)

图 11.28 – 两个条

1.  在**项目**窗口中单击“+”按钮，然后选择**Sprites** | **Square**选项。这将创建一个简单的方形精灵。这与下载一个*4 x 4*分辨率的全白图像并将其导入 Unity 相同。

1.  将精灵设置为基本条，而不是下载的条精灵。这一次，我们将使用一个纯白色的图像作为条的背景，因为在我的情况下，原始图像是红色的，将红色图像改为绿色是不可能的。然而，白色图像可以很容易地着色。考虑原始条的细节，例如，我的原始条中的小阴影在这里不会出现，但如果您想保留它，您应该获得一个带有该细节的白色条。

1.  选择基本生命条并将“颜色”属性设置为绿色：![图 11.29 – 带有方形精灵和绿色色调的条](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.29_B14199.jpg)

图 11.29 – 带有方形精灵和绿色色调的条

1.  一个可选的步骤是将条框图像转换为九切片图像，以便我们可以更改原始宽度以适应屏幕。

现在，让我们通过以下方式为得分、子弹、剩余波数和剩余敌人标签添加文本字段：

1.  使用**GameObject** | **UI** | **Text**选项创建一个文本标签。这将是得分标签。

1.  将标签定位在屏幕的右上角。

1.  在“得分：0”中。

1.  设置为`20`。

1.  通过单击**Font**属性右侧的圆圈并选择所需的字体来应用下载的字体。

1.  检查“对齐”属性的水平对齐选项（最右边的选项）和垂直选项的中心选项：![图 11.30 – 文本标签的设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.30_B14199.jpg)

图 11.30 – 文本标签的设置

1.  重复步骤 1 至 6，创建其他三个标签（或者只需将得分复制并粘贴三次）。对于“剩余波数”标签，您可以使用左对齐选项来更好地匹配原始设计：![图 11.31 – 我们 UI 的所有标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.31_B14199.jpg)

图 11.31 – 我们 UI 的所有标签

1.  将所有标签的颜色设置为白色，因为我们的场景主要是黑暗的。

现在我们已经完成了原始的 UI 设计，让我们通过以下方式创建暂停菜单：

1.  为菜单的背景创建一个“图像”组件（**GameObject** | **UI** | **Image**）。

1.  使用我们之前制作的九切片设置**Background**面板精灵。

1.  如果尚未这样做，请将“图像类型”属性设置为“切片”。此模式将应用九切片方法以防止角落拉伸。

1.  有可能图像会在任何情况下拉伸角落，这是因为有时角落相对于精灵的“每单位像素”值来说相当大，这将减小原始图像的比例，同时保留其分辨率。

在接下来的两个屏幕截图中，您可以看到背景图像的“每单位像素”值为`100`，然后再次为`700`。请记住，只有对于九切片或平铺图像类型，或者如果您没有艺术家为您调整它时，才能这样做：

![图 11.32 - 顶部是一个小的 RectTransform 组件中的大九宫格图像，足够小以缩小角落，底部是将每单位像素设置为 700 的相同图像](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.32_B14199.jpg)

图 11.32 - 顶部是一个小的 RectTransform 组件中的大九宫格图像，足够小以缩小角落，底部是将每单位像素设置为 700 的相同图像

1.  创建一个`文本`字段，将其放置在您的图表中想要暂停标签的位置，将其设置为显示暂停文本，并设置字体。请记住，您可以使用`Color`属性更改文本颜色。

1.  将文本字段拖放到背景图像上。**Canvas**中的父子关系系统工作原理相同 - 如果移动父级，则子级将随之移动。这样做的想法是，如果我们禁用面板，它也将禁用按钮和所有其内容：![图 11.33 - 暂停标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.33_B14199.jpg)

图 11.33 - 暂停标签

1.  通过转到**GameObject** | **UI** | **Button**来创建两个按钮。将它们放置在背景图像上的所需位置。

1.  通过将它们在**层次结构**窗口中拖动到**暂停**背景图像中，将它们设置为**暂停**背景图像的子级。

1.  选择按钮，并将它们的图像组件的`Source Image`属性设置为我们之前下载的按钮精灵。如果您遇到与之前相同的问题，请记住我们之前的**每单位像素**修复。

1.  您会注意到按钮本质上是一个带有子文本对象的图像。将两个按钮的文本分别更改为`恢复`和`退出`：![图 11.34 - 暂停菜单实现](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.34_B14199.jpg)

图 11.34 - 暂停菜单实现

1.  请记住，您可以通过取消顶部**检查器**窗口对象名称右侧复选框旁边的复选框来隐藏面板：

![图 11.35 - 禁用游戏对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.35_B14199.jpg)

图 11.35 - 禁用游戏对象

正如您所看到的，您可以通过使用图像和文本组件来创建几乎任何类型的 UI。当然，还有更高级的组件可以让您创建按钮、文本字段、复选框、列表等，但让我们先从基础知识开始。需要注意的一点是，我们已经创建了按钮，但到目前为止它们什么也没做。在本书的*第三部分*中，我们将看到如何编写脚本使它们具有功能。

在本节中，我们讨论了如何导入图像和字体，通过图像、文本和按钮组件进行集成，以创建丰富和信息丰富的 UI。做到这一点后，让我们讨论如何使它们适应不同的设备。

# 创建响应式 UI

如今，几乎不可能在单一分辨率下设计 UI，我们的目标受众显示设备可能差异很大。PC 具有各种不同分辨率的显示器（如 1080p、4k 等）和不同的宽高比（如 16:9、16:10、超宽等），移动设备也是如此。我们需要准备我们的 UI 以适应最常见的显示器，Unity UI 具有所需的工具来实现这一点。

在本节中，我们将探讨以下 UI 响应性概念：

+   调整对象的位置

+   调整对象的大小

我们将探讨如何使用 Canvas 和**RectTransform**组件的高级功能（如锚点和缩放器）使 UI 元素能够适应不同的屏幕尺寸和位置。

## 调整对象的位置

现在，如果我们玩我们的游戏，我们会看到 UI 如何很好地适应我们的屏幕。但是，如果由于某种原因我们改变了**游戏**视图大小，我们会看到对象开始从屏幕上消失。在以下截图中，您可以看到不同大小的游戏窗口以及 UI 在一个窗口中看起来很好，但在其他窗口中看起来很糟糕：

![图 11.36 - 相同的 UI 但在不同的屏幕尺寸上](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.36_B14199.jpg)

图 11.36 - 相同的 UI 但在不同的屏幕尺寸上

问题在于我们使用编辑器中的任何分辨率创建了 UI，但一旦我们稍微改变它，UI 就会保留先前分辨率的设计。此外，如果你仔细观察，你会注意到 UI 总是居中，比如在中间的图像中，UI 在两侧被裁剪，或者第三个图像中，屏幕边缘可见额外空间。这是因为 UI 中的每个元素都有自己的锚点，当你选择一个对象时，你可以看到一个小交叉点，就像下面的截图中所示：

![图 11.37 - 位于屏幕右下部分的锚点交叉属于到屏幕的左上部分的英雄角色](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.37_B14199.jpg)

图 11.37 - 位于屏幕右下部分的英雄角色的锚点交叉

对象的 X 和 Y 位置是相对于该锚点的距离，而锚点相对于屏幕有一个位置，其默认位置是在屏幕的中心。这意味着在 800 x 600 的屏幕上，锚点将放置在 400 x 300 的位置，在 1920 x 1080 的屏幕上，锚点将位于 960 x 540 的位置。如果元素（RectTransform 中的元素）的 X 和 Y 位置为 0，则对象将始终与中心的距离为 0。在前三个示例的中间截图中，英雄角色超出了屏幕，因为它与中心的距离大于屏幕的一半，并且当前距离是基于先前更大的屏幕尺寸计算的。那么，我们能做些什么呢？移动锚点！

通过设置相对位置，我们可以将锚点放在屏幕的不同部分，并使屏幕的该部分成为我们的参考位置。对于我们的英雄角色，我们可以将锚点放在屏幕的左上角，以确保我们的角色与该角落的距离固定。我们可以通过以下方式实现：

1.  选择你的英雄角色。

1.  用鼠标将锚点交叉拖动到屏幕的左上角。如果由于某种原因，当你拖动它时锚点会分裂成几部分，撤消更改（按*Ctrl* + *Z*，或者在 macOS 上按*Command* + *Z*）并尝试通过点击中心来拖动它。我们稍后会打破锚点：![图 11.38 - 一个带有锚点的图像，位于屏幕的左上角](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.38_B14199.jpg)

图 11.38 - 一个带有锚点的图像，位于屏幕的左上角

1.  将**生命条**对象和其框架的锚点放在同一位置。我们希望该条始终与该角落保持相同的距离，以便在屏幕大小改变时，它将随着英雄角色一起移动。

1.  对于**Boss Bar**对象，将锚点放在屏幕底部中心位置，这样它将始终居中。稍后，我们将调整其大小。

1.  将**剩余波数**标签放在左下角，**剩余敌人**放在右下角：![图 11.39 - 生命条和标签的锚点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.39_B14199.jpg)

图 11.39 - 生命条和标签的锚点

1.  将**得分**和**子弹**锚点放在右上角：![图 11.40 - 得分和子弹标签的锚点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.40_B14199.jpg)

图 11.40 - 得分和子弹标签的锚点

1.  选择任何元素，并用鼠标拖动 Canvas 矩形的边缘，以预览元素将如何适应它们的位置。请注意，你必须选择 Canvas 的直接子对象；按钮内的文本将没有这个选项：

![图 11.41 - 预览画布调整大小](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.41_B14199.jpg)

图 11.41 - 预览画布调整大小

现在我们的 UI 元素已经适应了它们的位置，让我们考虑对象大小必须适应的情况。

## 调整对象的大小

处理不同宽高比的第一件事是，我们的屏幕元素可能不仅会从它们的原始设计位置移动（我们在上一节中固定了），而且它们可能不适合原始设计。在我们的 UI 中，我们有生命条的情况，当我们在更宽的屏幕上预览时，条明显不适应屏幕宽度。我们可以通过打破我们的锚点来解决这个问题。

当我们打破我们的锚点时，对象的位置和大小被计算为相对于不同锚点部分的距离。如果我们水平分割锚点，我们将有左和右属性，而不是 X 和宽度属性，它们代表到左和右锚点的距离。我们可以这样使用：

1.  选择生命条，将锚点的左部分拖到屏幕的左部分，右部分拖到屏幕的右部分。

1.  对于生命条框架也是一样的：![图 11.42 - 生命条中的分隔锚点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.42_B14199.jpg)

图 11.42 - 生命条中的分隔锚点

1.  在检视器窗口中检查**Rect Transform**设置的**左**和**右**属性，它们代表当前到各自锚点的距离。如果你愿意，你可以添加一个特定的值，特别是如果你的生命条显示在屏幕外：

![图 11.43 - 分隔锚点的左右属性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.43_B14199.jpg)

图 11.43 - 分隔锚点的左右属性

这样，对象将始终保持相对于屏幕的固定距离，即屏幕的两侧。如果你正在处理一个子对象，比如按钮的文本和图像组件，锚点是相对于父对象的。如果你注意到文本的锚点，它们不仅在水平方向上分割，而且在垂直方向上也分割。这允许文本根据按钮的大小调整位置，这样你就不必手动更改它：

![图 11.44 - 按钮文本的分隔锚点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.44_B14199.jpg)

图 11.44 - 按钮文本的分隔锚点

现在，这种解决方案并不适用于所有情况。让我们考虑一个情况，英雄头像显示的分辨率比它设计的要高。即使头像被正确放置，它也会显示得更小，因为屏幕的像素密度比其他分辨率更高。你可以考虑使用分隔锚点，但是在不同宽高比的屏幕上，宽度和高度锚点可能会以不同的比例进行缩放，所以原始图像会变形。相反，我们可以使用画布缩放器组件。

画布缩放器组件定义了在我们的场景中 1 像素的含义。如果我们的 UI 设计分辨率是 1080p，但我们在 4k 显示器上看到它（这是 1080p 分辨率的两倍），我们可以缩放 UI，使得一个像素变为 2，调整其大小以保持与原始设计相同的比例大小。基本上，这个想法是，如果屏幕更大，我们的元素也应该更大。

我们可以通过以下方式使用这个组件：

1.  选择**Canvas**对象，并在**检视器**窗口中找到**Canvas Scaler**组件。

1.  将**UI Scale Mode**属性设置为**Scale with Screen Size**。

1.  这对我们来说并不是问题，但是如果将来你和一个艺术家合作，将参考分辨率设置为艺术家创建 UI 的分辨率，记住它必须是最高目标设备分辨率。在我们的情况下，我们不确定下载资产的艺术家有没有考虑过分辨率，所以我们可以设置为`1920 x 1080`，这是全高清分辨率大小，现在非常常见。

1.  在这种情况下设置“宽度”值，因为屏幕的宽度可能会非常宽，比如超宽屏，如果我们选择了那个选项，那些屏幕会不必要地缩放 UI。另一个选项是将此值设置为`0.5`以考虑这两个值，但在 PC 上，这并没有太多意义。在移动设备上，您应该根据游戏的方向选择这个值，为横向模式设置高度，为纵向模式设置宽度。尝试预览更宽和更高的屏幕，看看这个设置是如何工作的：

![图 11.45 - 带有标准 PC 游戏正确设置的画布缩放器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.45_B14199.jpg)

图 11.45 - 带有标准 PC 游戏正确设置的画布缩放器

您会发现您的 UI 比原始设计要小，这是因为我们应该在之前设置这些属性。现在，唯一的解决办法是重新调整大小。下次尝试这个练习时要考虑到这一点；我们只是按照这个顺序进行学习。

在继续之前，请记得重新激活后期处理体积对象以再次显示这些效果。您会注意到 UI 在游戏视图中不受它们的影响。

重要提示：

如果您希望您的 UI 受到后期处理效果的影响，您可以设置为“-相机”。将主摄像机拖动到“渲染相机”属性，并将“平面距离”设置为`5`。这将使 UI 与其他对象一起放置在世界中，与相机视图对齐，距离为 5 米。

![图 11.46 - 画布渲染模式设置为相机模式以接收后期处理效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-unity20-gm-dev/img/Figure_11.46_B14199.jpg)

图 11.46 - 画布渲染模式设置为相机模式以接收后期处理效果

有了这些知识，现在您已经准备好开始自己创建您的第一个 UI 了。

# 总结

在本章中，我们介绍了 UI 的基础知识，理解了“图像”和“文本”，为我们的 UI 布局赋予生命，并使其对用户具有吸引力。最后，我们讨论了如何使 UI 对象适应不同的分辨率和宽高比，使我们的 UI 适应不同的屏幕尺寸，即使我们无法预测用户将在哪种显示器上玩游戏。

在下一章中，我们将开始看如何向我们的游戏中添加动画角色。
