# UE4 VR 项目（三）

> 原文：[`zh.annas-archive.org/md5/3F4ADC3F92B633551D2F5B3D47CE968D`](https://zh.annas-archive.org/md5/3F4ADC3F92B633551D2F5B3D47CE968D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：与虚拟世界交互-第二部分

在上一章中，我们设置了我们的手并学习了如何对它们进行动画。正如我们之前提到的，仅仅这一点就可以代表我们的应用程序建立存在感的重要一步。现在，让我们迈出下一步，开始使用它们。

在本章中，我们将学习以下主题：

+   如何使用蓝图接口为各种蓝图添加功能

+   如何使用附件来拾取和放下物理角色

+   如何指示玩家何时可以与物体交互

+   如何创建触觉反馈效果以提供更多触觉反馈给用户

# 创建一个可以拾取的物体

我们将首先制作一些可以拾取的物体。让我们从一个简单的立方体开始：

1.  在内容浏览器中右键单击项目的`Blueprints`目录，然后选择“Create Basic Asset | Blueprint Class”。

1.  这次，不要选择其中一个常见类作为其父类，而是展开“Pick Parent Class”对话框底部的“All Classes”条目。

1.  选择“Static Mesh Actor”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6241c46a-6ddd-4d3e-b5d1-b4ab61cea61c.png)

1.  将其命名为`BP_PickupCube`。

1.  打开`BP_PickupCube`。

您可以看到它继承了一个`Static Mesh Component`。

我们也可以创建一个`Actor`蓝图并添加一个`Static Mesh`组件，但是当您构建新资产时，选择适当的父类是一个好习惯。如果不必要，不要重新发明轮子。

1.  将`Static Mesh Component`的“Static Mesh”属性设置为`Engine Content/Basic Shapes/Cube1`。

1.  将其“Scale”设置为`0.2, 0.2, 0.2`。

1.  将其“Materials | Element 0”设置为`Content/SoulCity/Environment/Materials/Props/MI_Glow`。（或者您喜欢的其他任何东西，但这个在地图中很容易看到。）

现在，我们希望立方体模拟物理效果，所以让我们设置一些值来实现这一点：

1.  将其“Physics | Simulate Physics”标志设置为`True`。

1.  将其“Collision | Simulation Generates Hit Events”设置为`True`。

1.  将其“Collision | Generate Overlap Events”设置为`True`。

1.  确保其“Collision | Collision Presets”设置为`PhysicsActor`。（当您将“Simulate Physics”设置为 true 时，这应该会自动设置。）

1.  将其“Collision | Can Ever Affect Navigation”设置为`False`。（这将在“Collision”部分的高级属性中隐藏。）

我们现在创建了一个小的发光立方体，它会自然地对物理作出反应，但在移动世界时不会阻碍我们的导航网格。

现在，我们需要让它具备被拾取的能力。我们可以通过几种方式来实现这一点。我们可以直接在`BP_PickupCube`的蓝图中编写`Pickup`和`Drop`方法，但我们需要能够从外部调用这些函数。

正如我们之前所见，如果您想从蓝图外部调用一个函数，您必须确保您正在与包含该函数的类进行交流，我们通过将引用转换为该类来实现这一点。如果我们只预期拾取立方体，那么这样做就可以了，但是如果我们希望能够轻松拾取其他对象呢？我们不希望每次添加一个新类型的可拾取物体时都要重写我们的`BP_VRHand`蓝图，所以这不是一个很好的解决方案。

我们可以从一个实现了`Pickup`和`Drop`方法的共同父类派生出`BP_PickupCube`，然后将我们的引用转换为该父类。这样做更好，但仍然不完美。`BP_PickupCube`继承自`StaticMeshActor`，但如果我们想让从`SkeletalMeshActor`继承的物体也能被拾取怎么办？在这种情况下，我们没有简单的方法来创建一个共同的父类。

解决这个困境的答案是*蓝图接口*。接口是一个蓝图对象，允许我们定义可以在实现接口的任何对象上调用的函数，无论该对象从哪个类派生。它是一个可以附加到任何对象的类，并且它作为一个承诺，附加到它的对象将实现接口中包含的每个函数。例如，如果我创建一个声明了`Pickup`和`Drop`函数的接口，并将该接口应用于我的`BP_PickupCube`，我可以在不必先转换对象的情况下调用`Pickup`和`Drop`方法。这是一个强大的模式。通过巧妙地使用接口，您可以使您的代码非常灵活和易于扩展。

如果这还不完全清楚，不要担心。一旦我们构建它，它会变得更加清晰。

# 为拾取对象创建一个蓝图接口

要创建一个蓝图接口，请按照给定的步骤进行操作：

1.  在项目的“蓝图”目录中右键单击，选择“创建高级资产|蓝图|蓝图接口”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/0f6892a9-d00b-4158-9223-4d6c0676b2bf.png)

1.  将其命名为`BPI_PickupActor`。

当你打开它时，你会看到它包含一个函数列表，除此之外什么都没有。你会注意到图表无法编辑。这是因为接口只是一个函数列表，附加对象必须实现这些函数，但这些函数不会在接口中编写。

1.  默认情况下，它为您创建了一个新的函数声明。将其命名为`Pickup`。

1.  在函数的详细信息|输入下，添加一个新的输入。将其类型设置为场景组件|对象引用，并将其命名为`AttachTo`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/a302c11e-2af7-4586-a1b8-a1a1c1c400ad.png)

1.  添加另一个函数，并将其命名为`Drop`。这个函数不需要任何输入。

1.  编译、保存并关闭接口。

现在，让我们将这个新接口应用到`BP_PickupCube`上：

1.  打开`BP_PickupCube`，并点击工具栏上的“类设置”项。

1.  在详细信息|接口下，点击“已实现的接口”下的添加按钮。

1.  选择`BPI_PickupActor`。

# 实现拾取和放下函数

现在，我们已经将这个接口添加到`BP_PickupCube`类中，我们可以在事件图中实现我们在该接口中声明的函数。让我们开始吧：

1.  在事件图中，右键单击并选择“事件拾取”来创建一个拾取事件。现在，这个蓝图类上存在这个事件，因为我们附加了一个声明它的接口。你会看到这个事件表明它是来自`BPI_PickupActor`的接口事件。

1.  以相同的方式创建一个`Drop`事件。

现在，我们已经为来自接口的两个事件创建了处理程序，让我们让它们起作用。

当拾取这个物体时，我们希望关闭它的物理模拟，这样它就不会从我们的手中掉下来，并且我们希望将它附加到拾取它的手上的一个场景组件上。

1.  将对“静态网格组件”的引用拖动到事件图中。

1.  调用`Set Simulate Physics`并将 Simulate 设置为`False`。

1.  在图表中右键单击并选择“获取根组件”。

1.  从根组件引用拖动一个连接器，并选择“附加到组件”。你会看到有两个选项。将鼠标悬停在上面并选择那个工具提示为“目标是场景组件”的选项，因为我们将要附加到一个场景组件上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/430b3db9-2269-42d6-9e4b-54f0e9c46095.png)

1.  将“事件拾取”的“附加到”输出拖动到“附加到组件”节点上的父级输入。

1.  在“附加到组件”节点上，将位置、旋转和缩放规则设置为“保持世界”，并将焊接模拟体设置为`False`。

您完成的拾取实现应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/9bcdbd11-2638-42b6-98ec-65ae2a89d680.png)

当我们放下这个物体时，我们希望将其物理重新打开并将其从我们拾取时附加的场景组件上分离出来。

1.  选择您的“静态网格组件”引用和`Set Simulate Physics`调用，并按下*Ctrl* + *W*进行复制。

1.  将事件 Drop 引脚的执行连接到复制的`Set Simulate Physics`调用。

1.  将模拟设置为 True，以便我们重新开启物理效果。

1.  右键单击并创建一个`Detach From Actor`节点。

1.  将位置、旋转和缩放规则设置为`Keep World`，就像我们在 Attach 节点上所做的那样。

您完成的 Drop 实现应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/75e40a5e-6086-496e-a676-0fba59a592f4.png)

这就是我们的`Pickup Cube`角色的全部内容。我们可以关闭蓝图了。

# 设置 VRHand 以拾取物体

现在，我们准备好抓取这些物体了。

# 创建一个函数来查找最近的可拾取对象

我们需要做的下一件事是找出哪些物体离我们的手足够近，可以被拾取。让我们创建一个函数来完成这个任务：

1.  在`BP_VRHand`中，创建一个名为`FindNearestPickupObject`的新函数。

1.  将其类别设置为`Grabbing`，将其访问限定符设置为`Private`。

1.  在其实现图中，右键单击创建一个`Get All Actors with Interface`节点，并将其接口值设置为`BPI_PickupActor`。

这将为我们提供场景中实现`BPI_PickupActor`接口的每个演员的数组。

1.  从 Out Actors 输出拖出一个连接器并创建一个`For Each Loop`节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/93f533aa-f514-4685-9588-adf98fe18ba8.png)

我们将遍历可能被拾取的演员，忽略任何距离太远而无法考虑的演员，然后返回最接近的剩余合格演员。

1.  从`For Each Loop`的 Array Element 输出中拖出一个连接器并调用`Get Actor Location`。

1.  将`Hand Mesh`的引用拖到图表上并调用`Get World Location`。

1.  从数组元素的角色位置中减去手部网格的世界位置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/2b1f079b-6e50-42a3-85c4-95fb275647eb.png)

1.  获取结果向量的`Vector Length Squared`。

1.  拖出其结果并选择提升为本地变量。将新变量命名为`LocalCurrentActorDistSquared`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/4d29b514-f173-4531-91f5-9e9fd8b773e1.png)

1.  将 Loop Body 执行线连接到本地变量的设置器。

1.  拖动本地变量设置器的输出并创建一个`<=`测试，以查看它是否等于或短于我们要给它的值。

我们在这里创建一个本地变量的原因是，如果在我们的测试半径内有多个可抓取的角色，我们将需要再次使用此值，并且我们不希望浪费时间重新计算距离，因此我们将其存储在这里以便以后使用。

1.  创建一个浮点变量并将其命名为`GrabRadius`。编译蓝图并将其值设置为 32.0。 （稍后，您可以根据自己的感觉调整此值。）

1.  按住 Ctrl 键并将`GrabRadius`拖到图表上。

1.  从其输出拖出一个连接器并对其进行`Square`操作。

1.  将平方的结果连接到`<=`测试的第二个输入：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/2e705634-cc56-4bd7-a55b-81af28f08578.png)

记住，当我们提到实际距离检查很昂贵时？这是一个重要的地方，因为我们将在`Tick`事件上调用此函数。由于我们只想看看演员是否在提供的半径内，但我们不关心它实际上有多远，所以在平方值上进行此测试更便宜。

1.  从我们的`<=`测试的输出创建一个`Branch`节点。

如果我们的演员通过了`<=`测试，我们就知道它在抓取范围内。现在，我们需要看看它是否是该范围内最近的对象。

1.  在本地变量列表中，创建一个名为`ClosestRange`的新的本地变量，并将其变量类型设置为`Float`。将其默认值设置为`10000.0`。

局部变量是仅存在于声明它们的函数中的变量。它们不能从函数外部读取。在函数中使用局部变量来存储仅由该函数使用的值是一个好主意，这样它们不会混乱周围的对象。局部变量在每次运行函数时都会重置为其默认值，因此您不必担心来自先前函数调用的奇怪值。

1.  按住 Ctrl 键并将`LocalCurrentActorDistSquared`拖动到图表上以获取其值。

1.  从其输出处拖动一个连接器，并从中创建一个`<`测试。

1.  将`Closest Range`局部变量拖动到测试的第二个输入中。

1.  使用`<`测试结果创建一个 Branch：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/8c110ea9-24eb-4e36-92b0-20436c5f7893.png)

如果此测试返回 true，则表示我们找到了一个新的最近演员。我们想保存对它的引用并将其距离记录为新的最近距离。

1.  按住 Alt 键并将`Closest Range`拖动到图表上，并将`LocalCurrentActorDistSquared`拖动到其输入中。

1.  从分支的 True 输出中设置此值。

1.  创建一个名为`NearestPickupActor`的新的局部变量，并将其类型设置为 Actor | Object Reference。

1.  按住 Alt 键并将其拖动到图表上以设置其值。

1.  将其值设置为`For Each Loop`的 Array Element。（这将是一个很长的连接。考虑创建一些重定向节点以使其更易读。）

1.  将其连接到`Set Closest Range`节点的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/bd6496a1-cab8-4094-ac19-8f186c17a12a.png)

最后，一旦我们遍历了所有可能的对象并找到了最佳的可拾取候选对象（如果存在），我们希望保存该值，以便我们的拾取方法可以使用它。

1.  创建一个新的变量（这次不是局部变量 - 我们希望在外部读取此值），命名为`AvailablePickupActor`，并将其类型设置为`Actor > Object Reference`。

1.  按住 Alt 键并将其拖动到`For Each Loop`的 Completed 输出附近的事件图上。

1.  将`For Each Loop`的 Completed 输出连接到`Available Pickup Actor`的 Set 输入。

1.  将`Nearest Pickup Actor`局部变量拖动到 setter 的输入中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/4865f89c-0d42-4cd8-9091-e8b89c5f71d4.png)

这样做的目的是将一个可外部读取的`Available Pickup Actor`变量设置为我们在遍历可能的演员列表时找到的演员（如果有的话）。如果我们没有找到任何演员，那么`Nearest Pickup Actor`将为`Null`。

# 在 Tick 事件上调用 Find Nearest Pickup Object

现在，是时候调用我们的新函数了，以便我们知道何时能够拾取一个对象。然而，如果我们已经拿着一个对象，我们不希望这样做，所以我们应该存储对任何我们已经拿着的对象的引用。让我们开始吧：

1.  返回到`BP_VRHand`的事件图中，找到`Event Tick`。

1.  在`Event Tick`附近创建一个`Sequence`节点。

1.  我们希望在查找可以抓取的对象之后才更新手部动画，因此按住 Ctrl 键并将来自“Event Tick”的执行引脚的输出拖动到 Sequence 节点的 Then 1 输出上。

1.  将“Event Tick”的执行引脚连接到 Sequence 节点的输入。

1.  选择与 Sequence 节点的 Then 1 输出连接的节点网络，并将它们拖动到下方，以便有足够的空间进行操作：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/948645f5-41bf-4f3d-944c-1742a040e197.png)

1.  创建一个新的变量，命名为`HeldActor`，并将其变量类型设置为`Actor > Object Reference`。

1.  按住 Ctrl 键并将`HeldActor`拖动到事件图中以获取其值。

1.  右键单击它并选择`Convert to Validated Get`。

1.  将一个调用 Find Nearest Pickup Object 的节点拖动到图表上，并从 Held Actor getter 的 Is Not Valid 输出中调用它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/7c4c66f1-d743-4cf8-9015-4af48453a5d1.png)

这样，只有在我们还没有拿起一个对象时，我们才会检查可拾取的演员。

# 拾取一个演员

现在我们正在寻找可以拾取的演员，让我们在尝试抓取它们时实现这一点。让我们开始吧：

1.  打开`BP_VRHand`中的`Grab Actor`函数。

1.  我们不再需要这里的`Print String`节点，所以我们可以将其删除。

1.  按住*Ctrl*并将`HeldActor`的 getter 拖动到图表上，右键单击它，并将其转换为已验证的获取。

1.  将`bWantsToGrip`setter 的执行输出连接到`HeldActor`getter 的输入。

1.  按住*Ctrl*并将`AvailablePickupActor`的 getter 拖动到图表上，并将其也设置为已验证的获取。

1.  将`Held Actor`获取的 Is Not Valid 输出连接到此 getter 的输入，因为我们只对如果我们还没有拿着物体感兴趣。

1.  从`Available Pickup Actor`拖出一个连接器并调用`Pickup (Message)`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/5b7a1fbf-1474-4f7b-a4ff-a0fc14c84f34.png)

这就是为什么蓝图接口如此有用。我们不需要将拾取角色强制转换为任何特定的类来调用接口方法。我们只需进行调用，如果对象实现了接口并知道如何处理它，调用将起作用。如果对象没有实现接口，它将什么也不做。

如果您需要找出给定的角色是否实现了一个接口，请在其上调用`Does Implement Interface`。如果在对象上找到接口，它将返回 true。在这种特殊情况下，进行此调用将是多余的，因为我们知道`Available Pickup Actor`将始终实现 BPI_PickupActor 接口。当我们在`Find Nearest Pickup Object`函数中查找对象时，我们使用该接口作为过滤器。

1.  将 Motion Controller 组件拖动到您的 Pickup 节点的 Attach To 输入上。

1.  将`Held Actor`变量拖动到`Available Pickup Actor`的输出上，将其设置为该值。

1.  将“返回节点”添加到您的退出点。(您不必这样做，但是如果您养成这个习惯，您的代码在长期运行中将更易读。)

您完成的`Grab Actor`图应如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/60d8fcc5-e09b-43dc-b1de-c05f624e1cb5.png)

总结一下这里发生的情况，当调用`Grab Actor`时，将`bWantsToGrip`设置为 true，然后我们检查是否已经拿着一个物体。如果是，我们不做任何其他操作。如果不是，我们检查是否在`Event Tick`上找到了一个我们可以拾取的对象。如果没有，就没有其他事情要做。如果找到了，我们通过其接口向其发送`Pickup`消息，其中包含对我们的`Motion Controller`组件的引用作为它应该附加到的对象，并将其存储为我们的`Held Actor`。

# 释放一个角色

由于我们现在可以拾取一个角色，我们也希望能够再次放下它。现在让我们来做这个：

1.  打开`Release Actor`函数。

1.  从中删除`Print String`节点-我们已经完成了它。

1.  按住*Ctrl*并将`Held Actor`拖动到图表上，右键单击它，并将其转换为已验证的获取。

1.  在设置`bWantsToGrip`之后调用已验证的获取。

1.  将返回节点连接到其 Is Not Valid 输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/44d80e44-3f0e-47ca-9c83-be8832b4f2ee.png)

如果我们没有拿着任何东西，我们不需要做任何其他操作。如果我们拿着东西，我们应该确保演员仍然认为我们是拿着它的人(因为我们可能用另一只手抓住它)，如果它仍然是我们的对象，就将其放下。

1.  从`Held Actor`拖出一个连接器并获取其`Root Component`。

1.  在根组件上调用`Get Attach Parent`。

1.  从`Get Attach Parent`的“Return Value”拖出一个连接器并创建一个`==`测试。

1.  将`Motion Controller`组件拖动到测试的另一个输入上。

1.  使用此测试的结果创建一个`Branch`作为其条件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/c6ecad42-83ce-4719-93c8-a62ca4ac567a.png)

1.  从分支的 True 输出中，调用`Drop`在`Held Actor`上。

1.  按住*Alt*并将`Held Actor`拖动到图表上以创建一个 setter。

1.  将其连接到`Drop`调用的执行输出和`Branch`节点的 False 输出，以便在任何情况下都清除该值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/e35f0d9b-4de9-4ece-b48a-7f6e118ecfbe.png)

您完成的图应如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/37bd944a-c500-4aeb-897e-376f18e2d8b5.png)

简要回顾一下这里发生的情况，当调用`Release Actor`时，我们首先将`bWantsToGrip`设置为 false。然后，我们检查是否正在拿着任何东西。如果没有，就没有其他事情要做了。如果我们认为我们正在拿着某个东西，我们检查一下我们认为我们正在拿着的物体是否仍然将我们的动作控制器视为其父级，因为我们可能用另一只手抓住它。如果我们真的拿着这个物体，我们就放下它并清除`Held Actor`变量。如果事实证明我们不再拿着这个物体，我们清除`Held Actor`变量，这样我们就不再认为我们在拿着它了。

# 测试抓取和释放

让我们在地图中测试一下：

1.  从编辑器的模式面板中，选择“放置|基本|立方体”，并将其拖入场景中。将其位置设置为 X=-2580，Y=310，Z=40，以便它位于玩家起始点附近。

1.  从内容浏览器中选择`BP_PickupCube`，并将其放置在刚刚放置的立方体上。您可以使用*End*键将其放到下面的表面上。（`X=-2600，Y=340，Z=100`可能是一个不错的位置。）

1.  按住 Alt 键并拖动更多的`BP_PickupCubes`并将它们堆叠在立方体上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/528238fa-1aaf-43f9-9971-90f334e09cef.png)

启动 VR 预览。走到立方体上的物体旁边，使用扳机来拾取、放下、扔掉和手到手移动它们。

还不错，但是这里有几个问题需要修复。

# 修复立方体碰撞

首先，最重要的是，它们与 VRPawn 的碰撞胶囊发生碰撞并将我们推开。我们最好修复一下：

1.  打开`BP_PickupCube`蓝图并选择其`Static Mesh Component`。

1.  在其详细信息|碰撞下，将其碰撞预设从`PhysicsActor`更改为`Custom`。

1.  这个对象的个别碰撞响应通道现在可以编辑了。将 Pawn 的碰撞响应设置为`Overlap`而不是`Block`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f03374d8-d06f-4f7d-9de2-d9fe79f35efa.png)

这样，我们仍然可以检测到与 Pawn 的碰撞，如果我们对它们感兴趣的话，但它们不会阻止玩家四处移动。

# 让玩家知道何时可以拾取物品

其次，我们没有给玩家任何视觉提示，告诉他们他们可以拾取物品。让我们改进一下。

首先，让我们向我们的`EGripState`枚举器添加另一个状态：

1.  打开项目的“蓝图”目录中的`EGripState`。

1.  在其枚举器列表下，点击“新建”以添加另一个条目。将其命名为`CanGrab`。

1.  关闭并保存它。

现在，我们需要告诉我们的动画蓝图该怎么做。

1.  打开`ABP_MannequinHand_Right`动画蓝图并打开其“事件图表”。

1.  在“事件蓝图更新动画”下，您会看到`Grip State``Select`节点已自动更新以反映我们添加的新的`Can Grab`枚举器。将其值设置为`0.5`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6cdbd564-b00b-479b-a391-f2b9296a3e77.png)

通过编译并在动画预览编辑器中更改 Grip State 来尝试一下。当 Grip State 设置为`Can Grab`时，手应该处于半开状态。

1.  保存并关闭动画蓝图。

接下来，我们需要让`BP_VRHand`蓝图在检测到玩家可以抓取物体时将`Grip State`设置为`Can Grab`。让我们创建一个纯函数来确定我们的`Grip State`应该是什么。

1.  打开`BP_VRHand`的“事件图表”并找到“事件 Tick”。

1.  选择`bWantsToGrip`引用和与其连接的`Select`节点，并将它们折叠成一个函数。

1.  将函数命名为`DetermineGripState`，将其类别设置为“Grabbing”，将其访问限定符设置为“Private”，将纯度设置为“True”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/5c7a0977-18fe-4325-a3df-da60e3ef5d1a.png)

1.  打开`DetermineGripState`。

1.  按住 Ctrl 键并将`Held Actor`拖到图表中，并将其转换为已验证的获取。

1.  将其连接到函数输入并从其 IsValid 输出添加一个新的`Return Node`。

1.  将此节点的返回值设置为`Gripping`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/5b424d48-a4b6-43f2-a8d9-f25762d896bd.png)

如果我们拿着一个物体，我们不会关心其他任何事情-我们只需要将其动画化到抓握状态。

1.  在图表中添加一个“分支”节点。

1.  将`bWantsToGrip`的值拖动到其条件中。

1.  将其 True 分支连接到我们刚刚创建的`Gripping`“返回节点”。

1.  按住 Ctrl 键并将`AvailablePickupActor`拖动到图表中，并将其转换为已验证的获取。

1.  在其“合法”输出上添加另一个连接到“返回节点”，并将其返回值设置为`Can Grab`。

1.  在其“不合法”输出中添加另一个“返回节点”，其值为 Open：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/536a1608-bb13-48fd-a6ec-3b7b2089e5a6.png)

让我们来测试一下。现在，当检测到可以抓取的物体时，您应该看到手的姿势发生变化。

# 添加触觉反馈

还有一件事情我们应该做的是，在玩家与物体接触时为手部添加一些反馈。这可能看起来像是一件小事，但实际上对于唤起存在感的过程非常重要。目前我们没有太多的方法来模拟物理感觉，但是任何与事件或动作配对的感觉都可以在很大程度上使虚拟世界感觉不那么“虚幻”而更加真实。

让我们学习如何为我们的控制器添加一点震动。

# 创建触觉反馈效果曲线

首先，我们需要创建要播放的触觉效果：

1.  在项目的“蓝图”目录中右键单击，选择“创建高级资产”|“杂项”|“触觉反馈效果曲线”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/d1f14b93-71a3-4087-869f-34b2d4fe91fc.png)

1.  将其命名为`FX_ControllerRumble`。

1.  打开刚刚创建的触觉反馈效果曲线。

您会看到在触觉反馈效果|触觉详情下有两个曲线：频率和振幅。我们将在这里创建一个非常简单的效果，但是通过尝试这些曲线并找出如何创建令人信服的反馈效果是非常值得的。

1.  右键单击频率曲线的时间轴附近的 0.0 时间，并选择“添加关键帧到无”。

1.  将其时间和值设置修正为每个都为`0.0`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/1e8b2ce2-e5f4-41aa-8206-f41e9a90b243.png)

1.  再次右键单击时间轴，添加另一个关键帧。将此关键帧的时间设置为`0.5`，值设置为`1.0`。

1.  在曲线上创建第三个关键帧，时间为`1.0`，值为`0.0`。

1.  为振幅曲线创建相同的三个关键帧：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/16145565-fb02-4512-aba4-465cd9a261aa.png)

您完成的曲线应该看起来像前面的截图所示。

1.  保存并关闭新的触觉效果曲线。

# 按命令播放触觉效果

现在我们已经创建了一个触觉反馈效果曲线，让我们设置一个播放它的方法：

1.  打开`BP_VRHand`的事件图表，右键单击。选择“添加事件”|“添加自定义事件”。将新事件命名为`RumbleController`。

1.  为此事件创建一个输入。将其命名为`Intensity`，并将其类型设置为`Float`。

1.  右键单击并创建一个“获取玩家控制器”节点。

1.  从`GetPlayerController`拖动连接器并创建一个“播放触觉效果”节点。

1.  选择刚刚创建的触觉效果。

1.  将`Hand`变量拖动到 Hand 输入中。

1.  将事件的强度输出拖动到比例输入中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/cf89b216-3ece-4f85-870d-1b119b557c34.png)

现在，每当我们接触到一个新的可拾取物体时，让我们调用这个触觉效果。

1.  打开`BP_VRHand`的“查找最近的拾取物体”函数。

看到我们在`Available Pickup Actor`中设置为`Nearest Pickup Actor`中找到的值吗？让我们在放入新值时检测到，并在发生时触发效果。

1.  右键单击`Nearest Pickup Actor`获取器，并将其转换为已验证的获取。

1.  按住 Ctrl 键并将执行输入拖动到`Set Available Pickup Actor`上，然后将其放在`Get Nearest Pickup Actor`获取器的执行输入上。

1.  从“最近的拾取物体”获取器的值拖动连接器，并创建一个“！=”（不等于）节点。

1.  从变量列表中将对`Available Pickup Actor`的引用拖动到“不等于”节点的另一个输入中。

1.  从其输出创建一个“分支”。

1.  将`Nearest Pickup Actor`的 Is Valid 执行引脚拖动到`Branch`输入中。

1.  从其 True 输出调用`Rumble Controller`并将其强度设置为`0.8`。

1.  将`Rumble Controller`的输出拖动到`Available Pickup Actor`的输入中。

1.  将`Nearest Pickup Actor`的 Is Not Valid 输出拖动到`Available Pickup Actor`的 setter 中。

1.  在`Set Available Pickup Actor`之后和`Not Equal`测试的`False`分支之后添加返回节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/cd15ad1a-8fc6-4fe5-a98a-73e5fcf518ee.png)

简要回顾一下这里发生的情况，一旦我们完成了对可能拾取的对象的迭代，我们需要检查是否找到了一个对象。如果没有找到，我们只需将`Available Pickup Actor`设置为 null 值，以便在先前包含值的情况下清除它。如果我们找到了一个可以拾取的对象，我们检查它是否与当前的`Available Pickup Actor`不同。如果是，我们在设置`Available Pickup Actor`为新值之前会使控制器震动。

# 进一步

我们可以进一步改进我们在这里所做的几种方法：

+   首先，通过距离检测可抓取对象会给我们带来模糊的结果。它没有考虑到对象的大小。使用一个球体来代表我们的抓取手，并针对该球体进行重叠测试将给我们更准确的结果。如果您想重构此代码以使用该方法，VR 模板项目中包含一个很好的示例。

+   其次，我们的触觉反馈效果感觉不够明显。它均匀地淡入淡出，并没有提供太多的物理感觉。通过编辑这些曲线以提供更锐利的攻击可以使效果更加令人信服。

# 总结

本章继续上一章的内容，让我们有机会开始拾取物体。我们学会了如何使用蓝图接口来使各种对象能够进行函数调用，以及如何检测我们可以拾取的演员并使用附件来拾取和放下它们。最后，我们还学会了如何创建触觉反馈效果，以指示玩家何时与可以拾取的对象接触。

正如我们在上一章的开头提到的，手的存在是 VR 中产生整体存在感的重要因素。在现实生活中，我们始终意识到自己的手，将它们带入虚拟世界也会让我们在空间中感到存在。此外，直接使用手来操纵物体的能力是我们在 VR 中可以做的关键事情之一，而在其他任何媒介中都无法做到。 （要了解这一点的一个例子，请查看**EntroPi Games**的*Vinyl Reality*（[`vinyl-reality.com/`](https://vinyl-reality.com/)），然后想象一下尝试使用游戏手柄或键盘做同样的事情。）手在 VR 中非常重要，它们是 VR 的独特之处。在您的应用程序中花时间将它们处理正确。

在下一章中，我们将学习如何在 VR 中创建用户界面以显示信息，并使用户能够在 3D 空间中进行交互。


# 第七章：在 VR 中创建用户界面

在前一章中，我们学习了如何通过动作控制器创建虚拟手。这使得我们的用户不仅可以环顾四周并在其中移动，还可以开始与之互动。在本章中，我们将进一步学习如何创建传达信息并接受输入的用户界面（UI）。

您应该认真考虑您的应用程序是否真的需要图形用户界面。并不是所有应用程序都需要图形用户界面，虚拟界面元素可能会破坏沉浸感。在构建用户界面元素时，尝试找出如何将它们有意义地融入到世界中，使其看起来像是属于那里的一部分。也不要过于迷恋按钮。它们在 2D 用户界面设计中常用，因为它们与鼠标配合使用效果很好，但是 VR 手柄提供了更广泛的潜在操作方式。要超越按钮的限制。

我们为 VR 开发的大多数应用程序都需要某种形式的图形用户界面（GUI），但是 VR 中的用户界面提出了我们在平面屏幕上没有遇到的新挑战。大多数情况下，当我们构建平面屏幕用户界面时，我们可以简单地将 2D 用户界面元素叠加在我们的 3D 环境之上，使用 HUD 读取鼠标、游戏手柄或键盘输入来允许用户与之交互。但是在 VR 中这种方法行不通。

如果我们简单地在每只眼睛的视图上绘制一个 2D 界面，它的位置对于每只眼睛来说都是相同的。这样做的问题是，我们的立体视觉会将两只眼睛看到的相同物体解释为无限远。这意味着，当世界中的 3D 物体出现在屏幕上的 UI 后面时，这些物体将看起来比 UI 更近，即使 UI 是绘制在它们上面。这看起来很糟糕，几乎肯定会让用户感到不舒服。

解决方案是将用户界面元素融入到 3D 世界中，但仅仅在玩家面前创建一个 HUD 面板并投射到上面是不够的（我们将在本章后面讨论为什么）。无论如何，你都必须重新思考 VR 中的用户界面。将你所做的视为重新创建与之交互的真实世界对象，而不是重新创建平面屏幕世界的 2D 隐喻。

我们还需要重新思考在 3D 世界中如何与用户界面进行交互。在 VR 中，我们无法使用鼠标光标（对我们来说也不适用，因为它是一个 2D 输入设备），键盘命令也不是一个好主意，因为用户看不到键盘。我们需要新的方式来将输入传达到系统中。幸运的是，虚幻提供了一套强大的工具，可以很好地处理 VR 中的 3D 用户界面。

在本章中，我们将通过创建一个简单的 AI 控制的伴侣角色，并在其上显示当前 AI 状态的指示器，以及在玩家角色上创建一个控制界面，来介绍在 VR 中创建功能性 UI 所需的各种元素的过程。

具体来说，我们将涵盖以下主题：

+   创建一个 AI 控制的角色并赋予其简单的行为

+   使用虚幻运动图形（UMG）UI 设计师在 3D 空间中创建界面以显示信息

+   将用户界面元素附加到世界中的对象上

+   使用小部件交互组件与这些界面进行交互并影响世界中的对象

+   向用户显示小部件交互组件

让我们开始吧！

# 入门

对于这个项目，我们将从上一章的项目开始，创建一个新的副本。在之前的章节中，我们已经探索了一些使用其他项目材料创建新项目的方法。简单地复制和重命名一个项目通常是最简单的方法，如果你正在对之前的项目所做的工作进行扩展，那么这种方法是合适的（如果你愿意，也可以继续使用本章的工作从之前的项目中继续工作）。

# 从现有项目创建一个新的虚幻项目

通过复制创建一个新项目时，实际上并不需要做很多事情。只需要简单地执行以下操作即可：

+   复制旧项目目录。

+   重命名新目录和`.uproject`文件。

+   删除旧项目中生成的文件。

让我们使用我们在第五章中的项目作为本章工作的起点：

1.  关闭虚幻编辑器，找到之前章节的虚幻项目的位置。

1.  复制项目目录并给它一个新的名称。

1.  在新目录中，重命名`.uproject`文件。你不需要将项目文件的名称与包含它的目录名称匹配，但这是一个好的做法。

1.  从新项目目录中删除`Intermediate`和`Saved`目录。当你打开新项目时，它们将被重新生成，而旧项目中残留的杂乱数据可能会引起问题。最好始终从干净的状态开始。

1.  打开新的`.uproject`文件。你会看到刚刚删除的`Intermediate`和`Saved`目录已经为新项目重新生成。项目应该会打开到上一章中设置的默认地图（`LV_Soul_Slum_Mobile`）。

1.  点击工具栏的构建按钮以重新构建其光照。

通过启动 VR 预览来测试项目。一切应该与之前的项目一样正常工作。

正如我们之前提到的，从上一章的项目继续工作也是可以的。无论哪种方式，我们现在准备添加我们要控制的 AI 角色。

# 我们并不孤单-添加一个 AI 角色

从头开始创建一个 AI 控制的角色将使我们进入超出本书范围的领域，因此我们将重新使用第三人称模板中的标准玩家角色并改变其控制方式。

如果你已经有一个使用第三人称模板创建的项目，请打开它。如果没有，请创建一个：

+   选择“文件 | 新建项目”，使用第三人称模板创建一个新的蓝图项目。可以将其他设置保留为默认值-它们不会影响我们正在做的任何事情。

# 迁移第三人称角色蓝图

无论是使用现有的第三人称模板项目还是创建一个新项目，我们现在要做的是迁移`ThirdPersonCharacter`蓝图：

1.  在第三人称项目的内容浏览器中，导航到`Content/ThirdPersonBP/Blueprints`，并选择`ThirdPersonCharacter`蓝图。

1.  右键单击并选择“资产操作 | 迁移”。将角色迁移到本章项目的`Content`目录中。

现在，我们可以关闭这个并返回到我们的工作项目。我们的内容迁移应该已经添加了一个新的`ThirdPersonBP`目录。

1.  导航到`Content/ThirdPersonBP/Blueprints`，找到`ThirdPersonCharacter`蓝图。打开它。

# 清理第三人称角色蓝图

这里有一些我们不需要的东西，我们可以安全地清除：

1.  首先，在事件图中选择所有内容并删除。我们不需要任何这些输入处理程序。

1.  我们还不需要组件列表中的 FollowCamera 和 CameraBoom 项目，所以删除它们：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/26ac5371-fd6a-4677-8fe5-d71edc52666b.png)

现在，我们有一个干净的角色，它将很好地完成我们需要它做的工作。

# 检查动画蓝图

尽管我们采取了捷径并迁移了我们的角色，但看一下它是如何工作的仍然不是一个坏主意。

选择角色的`Mesh`组件，并查看详细面板的动画部分。您会看到这个角色使用一个名为`ThirdPerson_AnimBP`的动画蓝图进行动画化。使用 Anim Class 属性旁边的放大镜导航到动画蓝图，然后打开它以查看内部内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/67893e0a-85fe-48dd-8de3-3547e971d6e5.png)

讨论动画蓝图的深入内容超出了本书的范围，但是总的来说，您应该了解它们与受控手部一样，负责确定骨骼网格如何根据其动画的各种因素进行动画化。

您看到了一个简单的示例，其中动画蓝图驱动手部姿势。这个示例执行了类似的工作，但驱动了一个角色骨架。花点时间浏览一下这个蓝图，看看它是如何工作的，这不是一个坏主意。您可以在[`docs.unrealengine.com/en-us/Engine/Animation/AnimBlueprints`](https://docs.unrealengine.com/en-us/Engine/Animation/AnimBlueprints)找到更多文档。当您完成浏览后，可以随意关闭动画蓝图。我们不需要在这里做任何更改。

# 创建一个伙伴角色子类

由于我们将向该角色添加新的行为和组件，所以为我们创建一个新的角色蓝图并从这个蓝图派生出来是个好主意。

1.  右键单击`ThirdPersonCharacter`蓝图并从上下文菜单中选择创建子蓝图类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/8310bb3d-981c-4cff-8f0c-bfb772449939.png)

1.  让我们将新类命名为`BP_CompanionCharacter`并将其移动到`Content`文件夹内的项目子目录中。

1.  现在，我们可以将`BP_CompanionCharacter`的一个实例拖入关卡中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f282d4aa-a474-4282-8cda-61891cd94e7e.png)

将您的伙伴角色放置在导航网格覆盖的位置。之前，我们使用导航网格来允许我们指示地图上哪些区域是有效的传送目的地。现在，除此之外，我们还将使用它来实现其预期的目的。导航网格提供了地图可行走空间的简化模型，可以供 AI 控制的角色在其中找到路径。请记住，您可以使用*P*键显示和隐藏导航网格，以检查其覆盖范围。

# 为我们的伙伴角色添加跟随行为

让我们给角色一个简单的行为。我们让他跟随玩家：

1.  打开`BP_CompanionCharacter`事件图，并找到或创建一个 Event Tick 节点。

1.  在图表中右键单击并创建一个 Simple Move to Actor 节点。

1.  创建一个 Get Controller 节点，并将其输出连接到 Simple Move to Actor 节点的 Controller 输入。

1.  创建一个 Get Player Pawn 节点，并将其输出连接到 Simple Move to Actor 节点的 Goal 输入：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/d10b4777-1653-4a5d-a080-e48631baef1c.png)

启动您的地图。我们的伙伴角色应该跑到您的位置（如果他没有，请验证他是否在导航网格上启动，并且他站立的导航网格部分可以访问您的 PlayerStart 位置）。

# 检查 AI 控制器

让我们花一点时间来讨论这里发生的事情：

1.  关闭游戏会话，选择 Simple Move to Actor 节点，并按下*F9*键在那里设置一个**断点**。

断点是一种调试工具，它指示蓝图解释器在达到您设置的点时暂停执行。在暂停状态下，您可以将鼠标悬停在变量和函数输出上，以查看它们包含的内容，并可以逐步执行代码以查看其执行方式。我们将在后面的章节中详细介绍使用断点和调试工具。

再次运行地图，但不需要戴上 VR 头盔-我们只想看看断点被触发时会发生什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/0df23c33-35f0-45b5-b8e7-146128ad30b5.png)

1.  当执行停在断点处时，将鼠标悬停在“获取控制器”节点的输出上。你会看到这个角色当前由一个自动为其创建的 AI 控制器控制。

在执行命令之前，你的关卡中的任何角色或者角色必须被一个控制器**控制**。作为玩家控制的角色或者角色是由一个玩家控制器控制的。预期自主行为的角色需要被一个 AI 控制器控制。

1.  如果 Simple Move to Actor 节点已经取消选择，请再次选择它，并按下 F9 清除断点。

1.  点击工具栏上的“恢复”按钮返回正常执行。

角色应该跑到你的位置。

在蓝图中设置断点是调试它们和查看它们如何运行的有价值的方式。如果你正在使用另一个开发者编写的蓝图，设置一个断点并逐步执行可以帮助你弄清楚它的工作原理。你可以通过按下*F9*来设置和清除断点，并通过使用*F10*来逐步执行。*F11*和*Alt* + *Shift* + *F11*允许你在蓝图中进入和退出子方法。你可以通过将鼠标悬停在输入和输出连接器上来查看当前设置在蓝图中的值。

如果我们查看`BP_CompanionCharacter`类的**Details** | **Pawn**，我们可以看到 Auto Possess AI 被设置为 Placed in World，这意味着如果这个角色被放置在世界中，指定的 AI 控制器将自动控制这个角色。这里的其他选项允许我们指定 AI 控制器在角色生成时应该控制角色，或者根本不自动控制。AI Controller Class 指定了哪个 AI 控制器类将控制这个角色。如果需要的话，我们可以在这里选择一个新的 AI 控制器类。在我们的情况下，我们不需要这样做，因为默认的控制器可以做我们需要它做的一切：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/71c8a8c7-94b3-4bc2-a6c9-753f70df0505.png)

与动画蓝图的深度讨论一样，AI 控制器和决策树的深入讨论超出了本书的范围，但如果你想进一步了解，可以在[`docs.unrealengine.com/en-us/Gameplay/AI`](https://docs.unrealengine.com/en-us/Gameplay/AI)上查阅文档是值得的。

花一些时间来研究这些元素是值得的。如果你正在开发涉及可见非玩家角色的应用程序，学习动画蓝图和 AI 控制器的时间绝对是值得的。

# 改进伙伴的跟随行为

现在我们让角色跟随我们，让我们改进它的行为。它倾向于有点拥挤，如果我们的伙伴只在我们离他一定距离时尝试跟随我们，情况会有所改善。

首先，为了组织起来，我们应该将我们的移动行为捆绑到一个函数中：

1.  选择 Simple Move to Actor 节点和 Get Controller 和 Get Player Pawn 节点，并将它们连接到它。

1.  右键单击并将它们折叠到名为`FollowPlayer`的函数中。

现在，让我们改进它的工作方式：

1.  打开新的函数。

1.  从 GetPlayerPawn 拖动一个输出，并选择 Promote to local variable。将新变量命名为 LocalPlayerPawn。

在函数中使用局部变量，每当你访问一个需要花费时间重新收集的信息时。由于我们知道在这个函数中我们将需要多次使用玩家角色，所以获取它一次并保存值比每次需要时重新获取它要快。

1.  将自动为您创建的 setter 连接到函数输入。

1.  从 Local Player Pawn 节点的输出创建一个 Get Squared Distance To 节点。

1.  右键单击，选择 Get a reference to self，并将 Self 输入到 Get Squared Distance To 节点的 Other Actor 输入中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/db569b7e-4ce8-43d9-92bf-93b148ea384e.png)

1.  创建一个名为`FollowDistance`的浮点变量，编译并将其值设置为`320.0`。（一旦行为运行起来，可以随时调整该值。）

1.  对`FollowDistance`进行平方（记住平方节点将在图表中显示为²），并测试 Get Squared Distance To 的结果是否大于跟随距离的平方。从结果创建一个分支节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/4414527d-b81c-4e45-a86e-6ff173b1bd2f.png)

回想一下，我们之前提到过计算平方根是昂贵的，所以当你只是比较距离但不关心实际距离时，使用平方距离代替。

当我们距离伴侣角色超过跟随距离时，该分支节点将返回 True，而在该距离内时返回 False。

1.  将分支节点的 True 输出连接到 Simple Move To Actor 节点。

1.  将 False 输出连接到`Return Node`，因为如果我们在跟随距离内，我们不需要做任何事情。

1.  获取一个`LocalPlayerPawn`的实例，并将其插入 Simple Move to Actor 节点的 Goal 输入。

1.  `Get Controller`仍然连接到你的 Simple Move to Actor 节点的 Controller 输入。

1.  在 Simple Move to Actor 节点的退出处添加一个`Return Node`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6b76d0b9-d613-4edb-bd7f-464d6f8e9099.png)

试一下。伴侣角色现在应该在你离开他超过 320 个单位之前等待再次跟随你：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/98c3c24e-3060-48b8-b711-0c9ca019717d.png)

还不错。这是一个非常简单的行为，但是这是一个好的开始。

对于任何有意义的复杂 AI 行为或需要由许多角色同时执行的行为，最好使用**行为树**来实现，而不是使用蓝图的 tick 操作。行为树允许我们以清晰、可读的方式构建非常复杂的行为，并且比 tick 事件上的简单蓝图操作运行得更高效。我们在这里使用蓝图构建了角色的行为，以避免走得太远，但是行为树实际上是一个更好的结构来使用的。

现在我们的伴侣角色正在执行行为，是时候进入本章的真正内容了，即向世界添加 UI 元素。

# 向伴侣角色添加一个 UI 指示器

现在我们的角色正在世界中移动，我们将给它添加另一个行为状态，并允许玩家指示它等待。

然而，在我们创建这个新状态之前，我们首先要创建一个简单的 UI 元素来指示伴侣角色的当前状态。我们将首先构建它作为一个占位符，因为我们还没有创建它的新状态，然后一旦我们创建了它，我们将更新它以反映真实的基础数据。

# 使用 UMG 创建一个 UI 小部件

Unreal 提供了一个强大的工具来构建 UI 元素。UMG 允许开发人员在可视化布局工具上布置 UI 元素，并将蓝图行为直接与布局中的对象关联起来。我们称之为 UI 元素**小部件**。让我们学习如何创建它们：

1.  在项目的`Content`目录中，右键创建一个新资产。选择 UI | Widget Blueprint：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/b6e5473a-a891-40ea-a379-ce8e72826c13.png)

1.  将其命名为`WBP_CompanionIndicator`并打开它。

你将看到 UMG UI Designer。

Unreal 提供了两个用于创建 UI 的工具集。原始的称为**Slate**，只能在本机 C++中使用。编辑器本身的大部分是使用 Slate 编写的，一些较旧的游戏示例（如 ShooterGame）也使用 Slate 实现其界面。**UMG**提供了一种更灵活和用户友好的方法来创建虚幻引擎中的 UI 对象，这是我们将用来构建界面元素的方法。

UMG 是一个非常强大和深入的系统。您可以使用它创建几乎任何类型的界面元素。在这个例子中，我们无法涵盖 UMG 的所有功能，所以当您准备进一步时，我们鼓励您探索文档：[`docs.unrealengine.com/en-us/Engine/UMG`](https://docs.unrealengine.com/en-us/Engine/UMG)：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/46c345c3-6c78-4bf2-ae93-5311e9538478.png)

首先，请注意 UMG 设计器由两个选项卡组成：设计师和图形。设计师选项卡是您的布局工具。图形选项卡与虚幻引擎中的其他上下文一样，用于指定小部件的行为。

让我们先设置一个简单的用户界面，这样我们就可以把所有的部分放到正确的位置上：

1.  在设计师窗口的右上角，找到 Fill Screen 下拉菜单，并将其设置为 Custom。

在平面屏幕应用程序中，设计一个可以根据屏幕自动缩放的 UI 小部件非常常见，但在 VR 中这不是可行的方法，因为我们的 UI 元素需要存在于 3D 空间中。将此值设置为 Custom 允许我们明确指定 UI 小部件的尺寸。

1.  将自定义尺寸设置为宽度=320，高度=100（您也可以使用小部件轮廓右下角的调整工具来调整）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/8566f2e7-6b97-4f71-a801-5e44e9b5fc97.png)

1.  从 Palette 中获取一个 Common | Text 对象，并将其拖放到 Canvas Panel 的层次结构面板中作为子对象。

您可以通过将元素直接拖放到设计师工作区或将其拖放到层次结构面板中来向画布添加元素。

让我们将这个文本对象居中在我们的面板中。

1.  如果尚未选择，请在层次结构中选择`Text`对象。

1.  将其名称设置为`txt_StateIndicator`。

您不必为小部件命名，但如果您创建了一个复杂的 UI，并且所有内容都被命名为`TextBlock_128327`，那么在大纲中找到您要查找的内容将会很困难。当您创建时，给您的东西起一个合理的名称是一个好习惯。

1.  从锚点下拉菜单中选择居中的锚点并单击它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/cedb97bd-cbf4-45e4-8efa-63d041e679b5.png)

1.  将其 Position X 和 Position Y 属性设置为 0.0。您将看到文本对象移动，使其左上角与中心锚点对齐。

1.  将其对齐方式设置为 X=0.5，Y=0.5。您将看到文本对象移动，使其中心与中心锚点对齐。

1.  将其 Size 设置为 Content 为 true。

1.  将其对齐方式设置为居中对齐文本。

1.  将其文本设置为“Following”（我们稍后会动态设置）。

锚点是使用 UMG 构建 UI 时必须掌握的重要概念。当一个对象放置在画布面板上时，它的位置被认为是相对于其锚点的。对于不改变大小的 UI 画布，这可能并不重要 - 您可以简单地将所有内容锚定在左上角，但是一旦您开始改变 UI 的大小，锚点就很重要了。最好习惯于使用适当的锚点来确定对象的出现位置。这样您将节省很多重新工作的时间。

对象的对齐方式确定其认为原点在哪里，范围从（0,0）到（1,1），因此对齐方式为（0,0）将原点放在对象的左上角，而对齐方式为（1,1）将其放在右下角。 （0.5,0.5）将原点居中于对象。

在选择锚点时，您可以使用 Ctrl +单击和 Shift +单击来自动设置对象的位置和对齐值。

请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/b8fc1921-692d-4b1f-af16-0c826d499219.png)

因此，简要回顾一下，在将对象放置在 UMG 画布上时，选择一个锚点，确定对象在布局板上将位置（0,0）视为何处。这可能因对象而异，这是一个强大的功能。接下来，确定对象在其自身原点上应该考虑其自身原点的位置，使用其对齐设置。最后，设置其位置。

在 UMG 中设计界面时，如果您将自己的工作视为在面板上设置对象如何排列的规则，而不是明确设置其位置，那么您将更容易。 UMG 旨在使创建与不同小部件和屏幕尺寸正确缩放的界面，并对驱动它们的数据动态响应变得容易。它做得很好，但对于新用户来说可能会感到困惑，直到您将思维方式从静态布局转变为动态规则系统。

我们暂时完成了这个对象，所以我们可以关闭它。

# 将 UI 小部件添加到角色

现在我们已经创建了指示器小部件，是时候将其添加到伴侣角色中了：

1.  打开`BP_CompanionCharacter`，并从其组件面板中选择+添加组件| UI | Widget。

1.  将新组件命名为“指示器小部件”。

1.  在其详细信息| UI 下，将其小部件类设置为我们刚刚创建的`WBP_CompanionIndicator`类。

1.  将其绘制大小设置为与我们为小部件布局设置的自定义大小相匹配：（X=320，Y=100）。

1.  如果您还没有在视口中，请跳转到视口。

现在，您应该看到您的小部件与角色一起显示，但它太大了，而且位置不正确。

在以 3D 空间显示的 UI 小部件中，如果以构建时的 100％比例显示，它们往往会显得模糊。最好的做法是将小部件构建得比实际需要的尺寸大，然后在将其附加到角色时缩小它。这将使其以比构建较小并以全尺寸显示的小部件更高的分辨率显示。

1.  将其位置设置为（X=0.0，Y=0.0，Z=100.0）。

1.  将其比例设置为（X=0.3，Y=0.3，Z=0.3）：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/9a45f9cd-abf4-444d-b575-032b74ed1d7d.png)

指示器小部件附加到角色的胶囊组件上，并将随角色移动。

让我们在关卡中进行测试。不错，但有一个问题-指示器面向角色的方向，因此如果伴侣角色没有面向您，很难或不可能阅读。我们可以解决这个问题。

# 将指示器小部件定位到玩家

我们将创建一个函数，将指示器定位到相机。

1.  在我的蓝图|函数下，创建一个名为`AlignUI`的新函数。

1.  将其类别设置为 UI，将其访问说明符设置为 Private（设置类别和访问说明符不是必需的，但这是一个非常好的实践。当您的项目变得更大时，这将使您的生活更轻松）。

1.  打开它。

# 实现 Align UI 函数

在此函数的主体中，我们将找到玩家相机的位置，并将指示器小部件定位到面向相机：

1.  从组件列表中将指示器小部件拖动到函数图中。

1.  在指示器小部件上调用 SetWorldRotation，并将函数的执行输入连接到此调用。

1.  从指示器小部件中拖动另一个连接器，并在其上调用 GetWorldLocation。

1.  创建一个获取玩家相机管理器节点，并在结果上调用 GetActorLocation。

1.  创建一个查找朝向旋转节点，并将指示器小部件的位置馈入 Start 输入，将相机管理器节点的位置馈入其 Target。

1.  将其结果馈入`SetWorldRotation`函数的 New Rotation 输入。

1.  给函数一个`Return Node`：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f1aba3d1-bddd-4646-be40-99ad3b7d9bbc.png)

通过获取玩家摄像机管理器的位置，我们已经得到了玩家从场景中观察的位置。`Find Look at Rotation`方法返回一个旋转器，其前向矢量从起始位置（小部件所在位置）指向目标位置（相机所在位置）。使用此旋转器调用`SetWorldRotation`会使 UI 小部件面向相机。

# 从 Tick 事件中调用 Align UI

现在让我们在 Event Tick 上调用`AlignUI`函数：

1.  跳回到您的事件图。

1.  从 Event Tick 拖动一个新的执行线，并在释放时输入`seq`。从结果列表中选择 Sequence 并创建一个 Sequence 节点。

Sequence 节点将自动插入到 Event Tick 和之前连接到它的 Follow Player 调用之间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/06cced41-b278-4559-905d-9a589a5e0547.png)

1.  从 Sequence 节点的 Then 1 输出调用`Align UI`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/311ae60c-298f-4017-92dd-5ac2db00d2c7.png)

在关卡中试一试。无论伴侣棋子朝向何处，UI 指示器现在都应该面向相机：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/dab471d4-72a4-459e-8489-375b9d3e98e5.png)

很好。我们为伴侣棋子创建了一个简单的 UI 元素。当然，由于棋子只有一个状态，它还没有做太多事情，但我们现在准备解决这个问题。

# 向伴侣棋子添加一个新的 AI 状态

首先，让我们给伴侣棋子一种知道自己处于什么状态的方法。这些信息最好存储在一个枚举中：

1.  在内容浏览器中，无论您将`BP_CompanionCharacter`保存在何处，右键单击以添加一个新对象，并选择蓝图|枚举。将其命名为`ECompanionState`。

1.  打开它并向枚举器添加两个项目，分别命名为 Following 和 Waiting，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/3e73f313-24d4-4002-8711-99cb1d089741.png)

1.  保存并关闭新的枚举器。

# 实现一个简单的 AI 状态

现在，我们已经创建了一个枚举器来命名角色的 AI 状态，让我们将我们已经创建的行为定义为角色的`Following`状态：

1.  打开`BP_CompanionCharacter`并创建一个新的变量。将其名称设置为`CompanionState`，类型设置为我们刚刚创建的`ECompanionState`枚举。

1.  在事件图中找到 Event Tick。

1.  按住*Ctrl*并将`CompanionState`变量拖动到图表中。

1.  从其输出拖动一个连接器，并在搜索框中输入`sw`以将搜索结果过滤为`Switch on ECompanionState`。添加节点。

1.  按住*Ctrl*并拖动执行输入，将其从该节点的输入移动到新的 switch 语句的执行输入。

1.  将 switch 语句的 Following 输出连接到您的`Follow Player`调用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/a18fd849-1bcc-4d25-b762-64c1a2d03b71.png)

现在，当您的伴侣棋子的`Companion State`设置为`Following`时，它将执行跟随行为，但如果该状态设置为`Waiting`，则不会执行。

# 使用 UI 指示器指示 AI 状态

在继续创建角色的下一个 AI 状态之前，让我们更新我们的 UI 元素以反映角色所处的状态。当我们开始更改它时，我们很快就会需要它。

由于我们希望指示器 UI 显示与其附加的棋子相关的信息，我们需要告诉它关于该棋子的信息：

1.  打开`WBP_CompanionIndicator`并从设计面板或层次结构选项卡中选择`txt_StateIndicator`。

1.  将其 Is Variable 属性设置为 true：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/e204d01d-fd34-4e88-b2de-188cefce2824.png)

通过将`txt_StateIndicator`设置为变量，我们可以在此小部件的事件图中访问该对象，因此我们可以获取对它的引用并更改其值。

1.  切换到图表选项卡。

1.  创建一个新的函数并命名为`UpdateDisplayedState`。

1.  向函数添加一个名为`NewState`的输入，并将其类型设置为`ECompanionState`。

1.  打开该函数。

1.  `txt_StateIndicator`现在应该在您的变量列表中可见。按住*Ctrl*并将其拖动到函数的图表中。

1.  从`txt_StateIndicator`拖动一个连接器，并调用`SetText`。

1.  从 NewState 输入拖动连接器，并在搜索框中键入`se`。应该会出现一个 Select 节点。将其放置在图表中如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/37a8cd47-19f0-4262-8d18-721396065f8e.png)

您新创建的 Select 节点将自动填充每个`ECompanionState`枚举值的选项。Select 语句可用于选择各种数据类型。要设置其类型，只需将其连接到任何其他函数或变量的输入或输出，它将采用您连接到它的任何内容的类型。

1.  将`Select`语句的返回值连接到 Set Text 节点的 In Text 输入。

您会发现`Select`语句现在已经采用了文本数据类型，您现在可以为 Following 和 Waiting 选项输入值。

1.  使用适当状态的名称填充选择语句的文本输入。

1.  将函数的执行输入与 SetText 节点连接起来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/7758f824-4d0e-4eb2-b293-43ac93e65e4f.png)

现在，每当我们在此 UI 元素上调用`Update Displayed State`时，它将根据我们在新提供的状态的`Select`语句中输入的内容更新显示的文本。

您在此示例中以及之前看到了如何使用枚举器使用 switch 语句和 select 语句。这些是有价值的技术，值得记住，因为它们易于阅读，并且如果您向枚举器添加或删除值，它们将自动更新。枚举器、switch 语句和 select 语句是您的朋友。

值得注意的是，我们还可以通过另一种方法更新此 UI，这是一种常见的教学方法。我们可以将拥有此小部件的角色的引用存储在变量中，然后使用 Bind 方法设置文本元素的实时更新：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/370c8818-9c5f-4f06-9b8c-a631c8c28b5c.png)

这是一个讨论 UI 开发中几个重要考虑因素的好机会，并解释为什么在这种情况下我们没有使用 Bind。

# 使用事件进行更新，而不是轮询。

首先，Bind 方法会在每次 UI 更新时更新。对于连续变化的值，这是您想要的，但对于像角色的 AI 状态这样只在偶尔变化，且仅在执行更改它的操作时才变化的值，每次都检查是否需要显示新值是很浪费的。尽可能地，您应该在只有在您知道要更新的值时才更新 UI，而不是让 UI 轮询底层数据以查看其显示的内容是否仍然准确。如果您构建了一个具有许多不同元素的界面，并且每个元素都在每一帧更新，那么这将真正开始变得重要。在 UI 中考虑效率会带来回报。

# 注意避免循环引用

我们要小心的另一个原因有点微妙，但很重要。如果我们将对小部件蓝图的 pawn 的引用存储在小部件蓝图上，并同时将对小部件蓝图的引用存储在 pawn 上，那么我们就引入了可能的循环引用（有时也称为循环依赖）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/905f0f08-e6b4-491a-94ca-2cee1b5d8ea8.png)

循环引用：类 A 在 B 构建之前无法编译，但类 B 在 A 构建之前无法编译

循环引用是指一个类在构建之前需要了解另一个类，但是那个类在构建之前需要了解第一个类。这是一种糟糕的情况，可能会导致非常难以找到的错误。

在小部件蓝图和角色之间存在循环引用的情况下，小部件蓝图可能无法正确编译，因为它需要先编译角色，但是角色可能无法正确编译，因为它需要先编译小部件蓝图（我们说“可能不会”是因为许多其他因素可能会影响对象构建的顺序，因此有时可能会工作。您可能不会立即意识到自己创建了循环引用，因为在一段时间内可能会工作，然后在更改某些看似无关的东西时停止工作）。您不需要对此过于担心。虚幻引擎的构建系统非常擅长确定构建对象的正确顺序，但是如果您尝试保持引用的单向性，您将避免遇到非常具有挑战性的错误。

使用我们设置的事件驱动结构，小部件蓝图不需要了解角色的任何信息。只有角色需要了解小部件蓝图，因此编译器可以轻松确定在构建另一个对象之前需要构建哪个对象，从而避免循环引用。

# 确保在状态更改时更新 UI

现在，因为我们选择使用事件驱动模型而不是轮询模型来驱动我们的指示器 UI，我们必须确保每当`BP_CompanionCharacter`类的`Companion State`发生变化时，UI 都会更新。

为了做到这一点，我们希望将变量设置为私有，并强制任何其他更改此值的对象使用事件或函数调用来更改它。通过强制外部对象使用函数调用来更改此值，我们可以确保在函数或事件的实现中包含任何其他需要在该值更改时发生的操作。因为我们将变量设置为私有，所以我们阻止任何其他人在不调用此函数的情况下更改它。

这是软件开发中的一种常见做法，也是一个很好的内化。如果有可能需要根据变量的值执行操作，请不要让外部对象直接更改它。将变量设置为私有，并只允许其他对象通过公共函数调用来更改它。如果您养成这样的习惯，当项目变得庞大时，将会节省很多麻烦。

让我们创建一个函数来处理设置伴侣状态，并将变量设置为私有，以便开发人员在想要更改 AI 状态时被迫使用它：

1.  选择`BP_CompanionCharacter`类的`Companion State`变量，并在其详细信息中将其私有标志设置为 true。

1.  在事件图中，创建一个新的自定义事件，并将其命名为`SetNewCompanionState`。

1.  向此事件添加一个输入。将其命名为`NewState`，并将其类型设置为`ECompanionState`。

1.  按住*Alt*并将`CompanionState`设置器拖动到图表上，并将其执行和新值连接到新事件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/62d9d79e-07e9-4039-aab5-42d722424fb7.png)

现在我们需要告诉指示器小部件状态已经改变。

1.  将对`IndicatorWidget`组件的引用拖动到图表上。

1.  在`IndicatorWidget`引用上调用`Get User Widget Object`（记住`IndicatorWidget`不是对小部件本身的引用，而是对持有它的组件的引用）。

1.  将`Get User Widget Object`组件的返回值转换为`WBP_CompanionIndicator`。

1.  在转换结果上调用`Update Displayed State`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/2095000f-c2ad-430d-8912-d80fac6b4434.png)

现在，因为`Companion State`是私有的，只能通过调用`SetNewCompanionState`来更改它，并且我们可以确保每当发生更改时，UI 指示器将被更新。

# 添加一个交互式 UI

现在是时候为自己提供一种改变伴侣角色状态的方法了。为此，我们将向玩家角色添加一个小部件组件，以及一个我们可以用来与其交互的小部件交互组件：

1.  在内容浏览器中，找到`BP_VRPawn`（我们的玩家角色）的位置。

1.  在相同的目录中，创建一个 UI | Widget Blueprint，并将其命名为`WBP_CompanionController`。

1.  保存并打开它。

1.  在其设计窗口中，将`Fill Screen`更改为`Custom`，就像我们之前的小部件一样。

1.  将其大小设置为 Width=300，Height=300。

1.  从 Palette 中，选择 Panel | Vertical Box，并将其作为 Canvas Panel 的子项拖放到层次面板中：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f8f8a41f-9d72-42f7-9c3b-bb3130589db3.png)

1.  通过选择右下角的选项（除了管理放置规则外，锚点还可以管理拉伸规则），将其锚定填充整个面板：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/633a251b-e5f7-45d6-802d-70bd7450390d.png)

1.  将其 Offset Left，Offset Top，Offset Right 和 Offset Bottom 设置为`0.0`。

1.  从 Palette 中，选择 Common | Button，并将其拖放到 Vertical Box 中。将其命名为`btn_Follow`。

1.  将另一个按钮拖放到同一个 Vertical Box 中，并将其命名为`btn_Wait`：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/67212a86-052b-46e5-b491-a0dfbe21d3b1.png)

1.  将一个 Common | Text 小部件拖放到`btn_Follow`上。将其文本设置为`Follow`。

1.  将另一个 Common | Text 小部件拖放到`btn_Wait`上，并将其文本设置为`Wait`。

您可能已经注意到，我们在创建按钮时给它们起了有意义的名称，但我们没有费心为文本块重新命名。原因是这些按钮是变量，我们将在小部件蓝图的图表中引用它们，而文本标签不会在其他任何地方引用，因此它们的名称并不重要。在选择要明确命名的项目时，您可以根据自己的判断进行选择，但通常，您的规则应该是，如果您将在其他任何地方引用该对象，则应该有一个有意义的名称。您不希望在数月后返回到小部件蓝图，发现图表中引用了 Button376 的一片引用。

我们的按钮非常小，并且在小部件上放置得不好。让我们进行一些布局工作来修复这个问题。

1.  在层次面板上右键单击`btn_Follow`，然后选择 Wrap With... | Size Box。

1.  在层次面板中选择刚刚出现的 Size Box，并将其 Height Override 设置为 80.0：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/eb650566-22e9-49d8-8f12-2c97792a9d7d.png)

**Size Box**用于设置 UMG 小部件的特定大小。如果不使用 Size Box，小部件将根据其规则自动缩放。使用 Size Box 包装它可以允许您覆盖这些规则并显式设置选定的尺寸，同时仍然允许其余部分自动缩放。

1.  使用 Size Box 包装`btn_Wait`，并将其 Height Override 设置为 80.0。

现在，让我们在面板上垂直居中这些按钮。我们将通过添加间隔器来实现这一点。

1.  从 Palette 中，将一个 Primitive | Spacer 拖放到层次面板中的 Vertical Box 上。将其放置在围绕`btn_Follow`的 Size Box 之前。

1.  将其大小设置为`Fill`。

1.  在 Size Box 围绕`btn_Wait`之后，再次将一个 Spacer 拖放到 Vertical Box 中，并将其大小设置为 Fill：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/60c6a912-7c1a-4b93-a74e-6927d27801f9.png)

让我们再添加一个间隔器来稍微分隔一下按钮。

1.  在 Size Box 围绕`btn_Wait`之前，再次将一个 Spacer 拖放到层次面板上。将其大小保持为 Auto，并将其 Padding 设置为 4.0。

在这里，我们看到了使用间隔器告诉布局如何处理未被其他小部件占用的空间的示例，还可以强制在小部件之间添加一些间隔。通过在按钮之前和之后放置 Fill 间隔器，我们使它们在垂直框中居中，并通过在按钮之间放置 Auto 间隔器，我们将它们分隔了一个固定的距离。

# 调整按钮颜色

这些默认按钮颜色在我们相当暗的场景中看起来太亮，无法阅读。我们可以通过调整其背景颜色属性来解决这个问题：

1.  选择`btn_Follow`，点击其 Details | Appearance | Background Color 的颜色样本。

1.  在结果颜色选择器的 HSV 输入中，将其 Value 设置为 0.05。

1.  对于`btn_Wait`也执行相同的操作：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/11f409af-9bd2-4420-8ff0-1bd48dd243b8.png)

这将使按钮的背景变暗，以便我们可以在环境的照明下清楚地阅读它。

# 为我们的按钮添加事件处理程序

现在，让我们在按钮被点击时执行一些操作：

1.  选择 btn_Follow，并在其 Details | Events 中，点击 On Clicked 事件的+按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6f5854ab-daf3-4c3f-bed9-ec8239f7da27.png)

您将进入小部件的事件图表，其中创建了一个名为 On Clicked (btn_Follow)的新事件。

1.  在图表中创建一个 Get All Actors of Class 节点，并将其 Actor Class 设置为 BP_CompanionCharacter。

1.  从其 Out Actors 数组中拖动一个连接器，并创建一个 ForEachLoop。

1.  从 ForEachLoop 的 Array Element 输出拖动一个连接器，并调用我们在 BP_CompanionCharacter 上创建的 Set New Companion State 事件。将状态设置为 Following：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6708b737-a7ac-4ce5-b2ea-78ed6c804cb4.png)

让我们对 btn_Wait 做同样的事情。

1.  再次从 Designer 选项卡中选择 btn_Wait，并为其创建一个 On Clicked 事件。

1.  选择与 On Clicked (btn_Follow)事件连接的节点，并按下 Ctrl + W 进行复制。

1.  将我们设置的伴侣状态更改为 Waiting。

# 将 UI 元素附加到玩家角色

现在，就像我们对伴侣角色的顶部指示器所做的那样，我们需要将此 UI 放置在世界中的某个位置。

对于习惯于设计平面应用程序的人来说，自然的反应是遵循他们已经了解的设计原则，并创建一些在头戴式显示器中显示的 HUD。这不是一个好主意。

首先，您附加到头戴式显示器的任何 UI 都会附加到玩家的头部。当他们转动头部看它时，它只会继续移动。这很快就会变得无聊，并且可能会引起一些用户的晕动病。这个问题的复杂性在于 VR 头戴式显示器的菲涅耳透镜在边缘处的清晰度要比中心处的清晰度低得多，因此玩家视野边缘的 UI 元素将很难阅读。最后，我们面临的问题是没有简单的方法与我们额头上的 UI 元素进行交互。

更好的解决方案是将 UI 附加到玩家可以控制的东西上，比如他们的手腕。现在让我们这样做：

1.  打开 BP_VRPawn，并在其组件列表中找到 Hand_L。

1.  将一个小部件组件作为 Hand_L 的子级。将其命名为 CompanionController。

1.  将 WBP_CompanionController 设置为小部件的 Widget Class。

1.  将其绘制大小设置为(X=300，Y=300)，以与创建时的大小匹配。

现在让我们将其附加。

1.  找到您的 BP_VRPawn 玩家的 BeginPlay 事件。

1.  从 BeginPlay 拖动一个新的连接器，并创建一个 Sequence 节点。我们的 Set Tracking Origin 调用应自动连接到 Sequence 节点的 Then 0 输出。

1.  将刚刚添加到角色中的 CompanionController 小部件的引用拖动到图表中。

1.  从它拖动一个连接器并创建一个 Attach to Component 节点。

请记住，此节点有两个变体：目标是 Actor 和目标是 Scene Component。选择与场景组件一起使用的节点。

1.  从 Sequence 节点的 Then 1 输出中拖动一个执行线到 Attach to Component 节点的执行输入。

我们也可以简单地从 Set Tracking Origin 输出拖动一个连接器到 GetHand_L 调用，但是将不相关的操作保持在单独的执行线上是更好的做法，这样更容易看出真正属于一起的内容。通过将 Set Tracking Origin 放在一个序列输出上，将 GetHand_L 调用放在另一个序列输出上，我们向读者清楚地表明这是两个独立的任务。

1.  拖出我们之前创建的`Get Hand Mesh for Hand`方法的一个实例（如果您想为左撇子玩家设置，将其 Hand 值更改为 Right；否则保持默认的 Left）。

1.  将结果手部网格输入到 AttachToComponent 节点的 Parent 输入中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f7b876fd-1ed8-474b-8208-a45bd83c0f42.png)

让我们运行它。它很大，但还没有正确对齐，但它会随着我们的左手移动。

1.  从`CompanionController`拖动另一个连接器，并在其上调用`Set Relative Transform`。

1.  右键单击 New Transform 输入并拆分结构引脚。

1.  输入以下值：

+   新的变换位置：（X=0.0，Y=-10.0，Z=0.0）

+   新的变换旋转：（X=0.0，Y=0.0，Z=90.0）

+   新的变换比例：（X=-0.05，Y=0.05，Z=0.05）

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/10f117cb-6c25-46e3-8a98-33038de7b8cc.png)

请注意，我们在这里否定了比例的 X 值。如果您还记得，我们通过反转其比例来翻转了左手网格。由于我们要附加到翻转的网格，我们在这里需要否定比例，否则我们的小部件将显示为镜像（如果我们将其附加到右手，则将比例的 X 值设置为正 0.05，并将旋转的 Z 值设置为正 90.0）。

再次运行它，我们会看到手腕菜单现在与我们的手腕更好地对齐了。

接下来的挑战是：我们如何按下其中一个按钮？

# 使用小部件交互组件

虚拟现实中的用户界面存在一个重大问题：我们如何允许用户与其进行交互？早期的解决方案通常使用凝视控制。用户通过凝视固定时间来按下按钮。是的，它就像听起来的那样笨拙。幸运的是，随着手部控制的出现，我们不再需要以这种方式进行操作。

在虚幻引擎中，我们最常使用**小部件交互组件**与 VR 中的 UI 元素进行交互，它在场景中充当指针，并且在与 UMG 小部件一起使用时可以模拟鼠标交互。

让我们在右手上添加一个：

1.  打开`BP_VRPawn`，并将 Widget Interaction 组件添加到其组件列表中（默认名称即可）。

1.  在其详细信息面板中，将其 Show Debug 标志设置为`True`。

1.  在我们的事件图中，找到`Begin Play`事件上的 Sequence 节点，并使用 Add pin 按钮添加一个新的输出：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/43a112d4-f84c-440f-a530-6aea644b1d48.png)

1.  将对我们的`Widget Interaction`组件的引用拖到图表上。

1.  从`Widget Interaction`引用中拖动一个连接器，并创建一个“Attach To Component (Scene Component)”节点，将`Widget Interaction`作为其目标。

1.  将`Get Hand Mesh for Hand`函数调用拖到图表上，并将其 Hand 属性设置为 Right（如果您将 UI 附加到右手，则设置为 Left）。

1.  将其 Hand Mesh 输出馈入“Attach To Component”节点的 Parent 输入：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/30984984-90ff-46fc-bb32-f8386aa7412c.png)

现在，我们将控制器 UI 附加到左手，将小部件交互组件附加到右手。

现在，让我们测试一下：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/7288effe-f791-4319-b942-89c744d18f83.png)

很好。小部件交互组件的默认放置和对齐效果不错。如果我们想要调整它，可以使用`Set Relative Transform`调用，但对于我们在这里要做的事情来说，这样就可以了。

设置我们附加到另一个对象的对象的放置的另一种方法是在目标对象的骨架上放置一个插座。如果您向骨架添加插座，只需将其名称放在“Attach to Component”节点的“Socket Name”属性中。为了保持主题的连贯性，我们将坚持使用简单的“Set Relative Transform”调用，但如果您想探索使用插座，可以参考[`docs.unrealengine.com/en-us/Engine/Content/Types/SkeletalMeshes/Sockets`](https://docs.unrealengine.com/en-us/Engine/Content/Types/SkeletalMeshes/Sockets)上的说明。

既然我们已经将小部件交互组件连接到手上，我们准备通过它传递输入。

# 通过小部件交互组件发送输入

首先，我们需要选择什么输入来驱动我们的小部件交互。由于我们只使用扳机来抓取对象，所以将我们的小部件交互添加到这些相同的输入中应该可以正常工作：

1.  在`BP_VRPawn`玩家的事件图中找到`InputAction_GrabLeft`和`GrabRight`事件处理程序。

1.  将对`Widget Interaction`组件的引用拖动到图表中。

1.  从`Widget Interaction`组件拖动一个连接，并从连接中调用`Press Pointer Key`。将其键下拉菜单设置为`Left Mouse Button`。

1.  从`Widget Interaction`拖动另一个连接，并调用`Release Pointer Key`。将此键下拉菜单设置为`Left Mouse Button`。

1.  如果您将`Widget Interaction`组件附加到右手，请在`InputAction_GrabRight`组件的 Pressed 事件链的末尾调用`Press Pointer Key`，在`Grab Actor`调用之后调用它（如果交互组件在左手上，请改为从`GrabLeft`调用）。

1.  在`InputAction_GrabRight`组件的 Released 链中调用`Release Pointer Key`，在`Release Actor`调用之后：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/b0373e21-74e9-46c5-9dfe-6a8c3b95cd54.png)

我们在这里所做的是告诉小部件交互组件，让它与小部件通信，就像用户将鼠标指针移动到上面并按下左键一样。这是一个强大而灵活的系统 - 您可以重新创建几乎任何输入事件并通过交互组件传递它。

让我们来测试一下。现在，您应该能够将小部件交互组件对准手腕控制器并按下扳机以激活按钮。尝试在关卡中四处奔跑，并在跟随和等待状态之间切换您的伴侣。

# 为我们的交互组件创建一个更好的指针

在结束之前，我们应该改进一下小部件交互组件上那个显眼的调试光束。让我们花点时间用更好看的东西来替换它。

1.  在`BP_VRPawn`中，选择`Widget Interaction`组件并关闭其 Show Debug 标志。

1.  在组件面板中，将一个静态网格组件添加为`WidgetInteraction`的子组件。将其命名为`InteractionBeam`。

1.  将其静态网格属性设置为`/Engine/BasicShapes/Cylinder`。

1.  将其位置设置为（X=50.0，Y=0.0，Z=0.0）。

1.  将其旋转设置为（Roll=0.0，Pitch=-90.0，Yaw=0.0）。请记住，`Pitch`在 UI 中映射到 Y。

1.  将其比例设置为`(X=0.005，Y=0.005，Z=1.0)`。

1.  将其碰撞|可以踩上的角色设置为`No`，将其碰撞预设设置为`NoCollision`。

如果您在手上添加了 UI 或其他附加元素，并突然发现您的移动被阻止，请检查是否已关闭其碰撞。

试一下。现在我们有一个灰色的圆柱体表示我们的交互组件。我们应该给它一个更合适的材质。

# 创建一个交互光束材质

我们将为交互光束提供一个简单的半透明材质。我们希望能在世界中看到它，但又不希望它过于显眼，分散我们对世界的注意力：

1.  找到我们保存了用于传送的`M_Indicator`材质的`Content`目录中的位置。

1.  在此目录中创建一个新的材质，并将其命名为`M_WidgetInteractionBeam`。

1.  打开它并将其混合模式设置为`Translucent`。（记住：要设置材质属性，请选择输出节点。）

1.  按住*V*键并单击以创建一个矢量参数节点。将其命名为`BaseColor`。

1.  将 BaseColor 节点的默认值设置为纯白色 - （R=1.0，G=1.0，B=1.0，A=0.0）。

1.  将其输出连接到 BaseColor 和 EmissiveColor 材质输入。

1.  在材质图中右键单击并创建一个纹理坐标节点。

1.  右键单击并创建一个线性渐变节点，将纹理坐标的输出连接到其 UV 通道输入。

1.  按住*M*键并单击以创建一个乘法节点。

1.  将线性渐变节点的 VGradient 输出连接到乘法节点的 A 输入。

1.  按住*S*键并单击以创建一个标量参数。将其命名为`OpacityMultiplier`。

1.  将其滑块最大值设置为 1.0，将其默认值设置为 0.25。

1.  将其输出连接到 Multiply 节点的 B 输入。

1.  将 Multiply 节点的结果连接到材质的不透明度输入：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/ef34f7fa-d2a4-400b-9e53-080eaf6ca526.png)

我们需要调整这个材质以适应我们的环境。通过创建**材质实例**，我们可以更轻松地完成工作。材质实例是从材质派生出来的，但只能更改在父材质中公开的那些参数。因为材质实例不包括对材质图的任何更改，只有值的更改，所以当进行这些更改时，它们不需要重新编译。在材质实例中更改值比在材质中更改值要快得多。

1.  右键单击`M_WidgetInteractionBeam`，选择 Material Actions | Create Material Instance。

1.  将新实例命名为`MI_WidgetInteractionBeam`。

1.  将`MI_WidgetInteractionBeam`分配给`BP_VRPawn`上的`InteractionBeam`静态网格组件。

运行地图。它仍然很亮。

1.  打开`MI_WidgetInteractionBeam`并将其 OpacityMultiplier 设置为 0.01。 （在您计划更改的值旁边打勾。）

再次运行。好多了。

# 创建一个碰撞效果

现在我们需要一个碰撞效果来显示光束与目标的交叉点。

1.  创建一个新的静态网格组件，作为`BP_VRPawn`玩家的根组件（`Capsule Component`）的子组件。

1.  将其命名为`InteractionBeamTarget`。

1.  将其静态网格属性设置为`Engine/BasicShapes/Sphere`。

1.  将其缩放设置为`(X=0.01, Y=0.01, Z=0.01)`。

1.  将其碰撞| Can Character Step Up On 设置为`No`，将其碰撞预设设置为`NoCollision`。

这个目标球体也需要一个材质。为此，我们将创建一个带有深色轮廓的自发光材质，以便在明亮和暗背景上清晰显示。

1.  创建一个名为`M_WidgetInteractionTarget`的新材质。

1.  按住*V*键并点击创建一个矢量参数。将其命名为`BaseColor`并将其默认值设置为纯白色。

1.  从`BaseColor`拖动一个输出并点击`-`创建一个 Subtract 节点。

1.  将 Subtract 节点的结果输入到材质的 Base Color 和 Emissive 输入中。

1.  右键单击并创建一个 Fresnel 节点。

1.  按住 1 键并点击创建一个标量材质表达式常量。将其值设置为 15。

1.  将其输入到 Fresnel 节点的 ExponentIn 中。

1.  按下*Ctrl*+*W*进行复制，将新常量的值设置为 0，并将其输入到 Fresnel 节点的 BaseReflectFractionIn 中。

1.  按住*M*并点击创建一个 Multiply 节点。

1.  将 Fresnel 节点的结果输入到 Multiply 节点的 A 输入中。

1.  按住*S*并点击创建一个标量参数。将其命名为`OutlineThickness`并将其默认值设置为 10。

1.  将 OutlineThickness 输入到 Multiply 节点的 B 输入中。

1.  将 Multiply 节点的结果输入到 Subtract 节点的 B 输入中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/cc745b2c-0a82-4319-bf08-367821dc9dc3.png)

1.  在内容浏览器中，从该材质创建一个名为`MI_WidgetInteractionTarget`的材质实例。

1.  将`MI_WidgetInteractionTarget`分配给我们在`BP_VRPawn`上创建的`InteractionBeamTarget`球体。

最后，我们需要将其位置设置为交互组件的碰撞位置。

1.  在`BP_VRPawn`玩家的事件图中，找到`Event Tick`并在`Event Tick`和`UpdateTeleport_Implementation`折叠图之间创建一个 Sequence 节点。

1.  将对`WidgetInteraction`的引用拖动到图中，并在其输出上调用`Get Last Hit Result`。

1.  右键单击返回值并选择拆分结构引脚。

1.  将对`InteractionBeamTarget`静态网格组件的引用拖动到图中。

1.  在其上调用`SetWorldLocation`，并将`Get Last Hit Result`的返回值 Impact Point 输入到其新位置中。

1.  将 Sequence 节点的 Then 1 输出连接到 SetWorldLocation 节点的执行输入中。

1.  选择这些新节点，右键单击，选择折叠节点。将折叠的图命名为`UpdateWidgetInteractionTarget_Implementation`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/b67c8a4a-f236-46ce-b2d4-22c8447fcffd.png)

1.  打开折叠的图并进行清理。

折叠的图应该是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f32f3377-898b-403b-8158-7d3e6d6e8e22.png)

测试一下。光束不错，目标点也很容易找到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6efd78d1-54b6-4d5c-9558-b34744d49593.png)

我们还可以做很多其他事情，比如在光束碰到小部件时切断它，并根据它与玩家视图的接近程度调整目标球的比例，但我们在这里已经有了一个非常好的起点。这个系统功能强大，并且可以很容易地扩展和改进。

探索关卡并尝试使用伴侣控制器。虽然我们在这里所做的相当简化，但它包含了我们可能想要做的很多事情的基础。

# 总结

在本章中，我们为我们的开发工具库添加了一个重要的剩余部分，并为我们的项目添加了功能性的 UI 元素。

在本章中，我们学习了如何创建一个简单的 AI 控制角色并对其进行动画处理，还学习了如何使用 UMG 在 3D 空间中创建 UI，这也使我们能够改变角色的 AI 状态。

在下一章中，我们将继续从创建角色和界面转向探索创建用于 VR 的环境。


# 第八章：构建世界并针对 VR 进行优化

在本书迄今为止的工作过程中，我们大部分时间都专注于玩家角色。这是有道理的-虚拟现实极大地改变了玩家与世界互动的方式。我们需要学习新的方法来让玩家四处移动，使用手来与世界互动，以及构建用户界面的新方法。

这是一项不小的成就，所以恭喜你走到了这一步！

现在，我们要稍微改变一下焦点，开始关注我们周围的环境。到目前为止，我们一直在使用现有的环境，但现在是时候开始建立我们自己的环境了。在这个过程中，我们将会发现 VR 环境带来了一些需要解决的挑战。光照、物体比例和视线都比平面屏幕更重要，并且性能是一个重要考虑因素。

在本章中，我们将学习如何利用我们手头的工具和技术来解决这些挑战。我们将学习如何使用 VR 编辑器在头戴式显示器中布置环境，并在构建过程中实际查看其在 VR 中的外观，还将学习如何对这些环境进行性能分析和优化，以确保我们能够满足帧率要求。

在本章中，我们将探讨以下主题：

+   使用 VR 编辑器构建和照明场景

+   对场景进行性能分析以识别瓶颈

+   使用静态网格实例化、LOD、网格组合和光照更改来优化场景

+   优化的项目设置

+   移动 VR 的特殊考虑和技术要求

让我们开始吧，给自己一个玩耍的地方。

# 设置项目并收集资产

对于本章的工作，让我们使用以下模板选项创建一个新项目：

+   一个空白的蓝图模板

+   针对移动/平板硬件进行优化

+   可扩展的 2D 或 3D

+   没有起始内容

创建项目后，打开其项目设置并设置以下菜单选项：

+   项目 | 描述 | 设置 | 在 VR 中启动：True

+   引擎 | 渲染 | 正向渲染器 | 正向着色：True

+   引擎 | 渲染 | 默认设置 | 环境遮蔽静态分数：False

+   引擎 | 渲染 | 默认设置 | 抗锯齿方法：MSAA

+   引擎 | 渲染 | VR | 实例化立体声：True

+   引擎 | 渲染 | VR | 循环轮询遮挡查询：True

在设置完所有这些设置后，允许项目重新启动。

项目重新启动后，打开文件菜单并使用它加载上一章的项目。就像上次一样，我们将使用迁移工具获取之前创建的元素并将它们带入新项目中。

# 将蓝图迁移到新项目中

从之前的项目中，选择内容资源管理器中的 BP_VRGameMode，右键点击它，选择资源操作 | 迁移。将你的新项目的`Content`目录作为目标内容文件夹。因为 GameMode 引用了 BP_VRPawn，而 BP_VRPawn 引用了 BP_CompanionCharacter，所有这些对象及其所需的支持资产都应该被迁移过来。

迁移完成后，还有一件事情需要做。我们在之前的项目中设置了一些自定义输入，我们在新项目中也需要它们。导航到上一章的项目目录，并将`Config/DefaultInput.ini`文件复制到新项目的配置目录中。

# 验证迁移的内容

重新打开新项目。这里我们要做的第一件事是验证我们带入的所有内容是否正常工作：

1.  选择文件 | 新建关卡 | VR 基础，创建一个起始的 VR 地图。

1.  将一个导航网格边界体放置在地图上，并确保它围绕着地板。将其位置设置为(X=0.0，Y=0.0，Z=0.0)，将其缩放设置为(X=10.0，Y=10.0，Z=2.0)即可。记得按下“P”键来可视化你的导航网格，并确保它正常生成。

1.  保存这个关卡（我们将其命名为 VRModePractice，并放置在`Content/C07/Maps`中）。

1.  打开设置|项目设置|地图和模式|默认模式，并将默认游戏模式设置为我们从其他项目迁移的 BP_VRGameMode。将编辑器启动地图和游戏默认地图也设置为这个地图。

1.  在关卡上放置一个 BP_CompanionCharacter 的实例。

在 VR 预览中测试地图。你应该能够移动和传送，你的伴侣角色应该跟随你：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/fc9c3181-0e37-4c0e-941c-dce2a397c9fb.png)

这张地图非常适合用于学习虚幻编辑器的 VR 模式-它易于操作，并且提供了许多我们可以在界面上练习时操作的部件。让我们充分利用它。

# 使用 VR 编辑器

虚幻引擎配备了一个非常强大的虚拟现实编辑器，可以让你完全在虚拟环境中构建场景。几乎任何你可能需要执行的编辑操作都可以在不离开 VR 的情况下完成。

然而，当你第一次遇到 VR 模式编辑器时，可能会认为它只是一个花招。毕竟，现有的编辑器有什么问题呢？没有问题，但是这里有一点需要注意：虚拟现实不是一个平面屏幕。深度是存在的。视线是不同的。颜色的渲染也不同。通过使用平面屏幕进行虚拟现实开发会给你的设计过程增加一层抽象。当你能够直接在目标媒介中工作时，你会更加了解并获得更好的结果。

在实践中，你可能会发现两种编辑模式都很有用。就像在平面屏幕编辑器视图中很难看清楚一个场景在 VR 中的真实样子一样，在 VR 模式下放置物体时很难达到精确。当你熟悉工具时，你会发现自己的工作流程，并发现你更喜欢在哪个领域进行哪些操作。然而，这里的重点是，将 VR 模式视为 VR 场景布局工作流程的重要组成部分是值得的。花时间熟悉它，这样当需要时就可以依赖它。

VR 编辑的一个好的实践是在 VR 中进行初始的块状布局。以一种能够传达你想要表达的空间感的方式放置物体，然后转到传统的平面编辑来进一步完善你的布局并填充它。最后，返回到 VR 编辑中进行最后的调整，这样你就可以清楚地看到你将要得到的结果。

让我们激活 VR 编辑器，看看我们可以用它做些什么。由于你在戴头盔时无法阅读这本书，我们将介绍一些基本原则，让你尝试一下，然后再回到这里探索更多内容。

首先要知道的是如何进入和退出 VR 编辑器。

# 进入和退出 VR 模式

你可以通过使用 VR 模式工具栏按钮来激活 VR 编辑器。要退出 VR 模式，请激活径向菜单（稍后会详细介绍）并选择“系统|退出”。不过，最简单的方法是习惯使用*Alt* + *V*来进入和退出 VR 模式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f2ae6c39-2220-4e8a-9a50-b632e84f25e1.png)

还可以将 VR 模式配置为在编辑器运行时自动进入头戴式显示器时自动进入。要做到这一点，选择“编辑|编辑器首选项|常规|VR 模式”，并将“启用 VR 模式自动进入”设置为 True。是否这样做取决于你的选择，但是在实践中，它往往很难确定何时关闭自身，因此使用*Alt* + *V*进入和退出通常是一个更好的主意。

如果你更喜欢使用左手进行交互，你可以在 VR 模式首选项中选择此选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/a392086e-d933-429b-a2c3-4f1bf5fc4f12.png)

VR 模式的设置可以在“编辑”|“编辑器首选项”|“常规”|“VR 模式”下找到。

如果你愿意，可以设置其中任何一个选项。我们将保留这些选项的默认设置。

我们还需要解决的另一件事是如何移动和观察周围。

# 在 VR 模式下导航

在 VR 编辑器中，通过挤压握持按钮来激活移动模式。当移动模式激活时，移动网格将出现，交互光束将变为绿色。

VR 编辑器中的交互光束会改变颜色以指示其所处的模式。红色表示标准交互模式，绿色表示移动模式，黄色表示你当前选择了一个角色，蓝色表示你处于 UI 交互模式。

在 VR 编辑器中，移动的隐喻是**推动**和**拉动**世界。这是相当直观的。在大多数情况下，当你的移动模式处于活动状态时，世界会按照你的手的移动方式移动。

# 在世界中移动

如果你在握持按钮的同时移动控制器，世界会移动，就像你在拉动它，或者在其中游泳一样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f2dc78f9-a553-4565-8de0-6e296858c517.png)

如果你在移动控制器时松开握持按钮，移动会继续一段时间，就像你从一个物体上推开并且现在漂离它一样。这需要一些练习，但一旦你掌握了它，它就会变得相当直观。再次挤压握持按钮会停止你的移动。

移动网格显示了你真实世界跟踪体积中地板的位置。将其与场景中的地板对齐，以查看从站在地板上的人的视角看物体的真实样子。

# 通过世界传送

要通过世界传送，挤压你主手控制器上的握持按钮并按下扳机。将控制器对准一个物体或目的地，释放时你将传送到那里：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/8b12e78c-502a-4277-b5a6-c0cf29469f4c.png)

通过传送和拖动的组合，你可以很好地在世界中移动。

# 旋转世界

当你需要旋转视角时，握住两个手柄的握持按钮，将手柄彼此旋转，就像你试图旋转世界一样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6670d6e8-9842-40d5-8e06-93375f97a53f.png)

你在旋转轴上看到的数字是世界当前的比例。我们也可以操纵它。

# 缩放世界

要缩放世界，挤压握持按钮并将控制器向彼此移动以缩小世界，或将其远离彼此以扩大世界：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f9f14b1e-e254-4ebe-8ede-68b9a207c0ba.png)

将场景缩小到看起来像桌子上的微型场景真是一种奇妙的满足感。

将控制器彼此靠近会缩小世界。将它们远离彼此会扩大世界。这对于布局很有用，因为你可以将世界组装成微型，然后传送回地面并恢复其正常比例，以查看你所做的事情。

在 VR 模式下，最快的方法之一是缩小世界，然后使用传送动作（握住+扳机）在地图上传送到新的位置。当你传送时，世界会恢复到默认大小。

# 练习移动

现在花点时间用你的控制器练习在世界中导航。使用*Alt* + *V*进入 VR 模式，当你想退出时再次按下*Alt* + *V*。使用握持按钮在世界中移动、传送、旋转和改变其比例。玩弄它直到感觉自然。这需要一些细微的技巧，但一旦你熟悉了，它就是一个非常有用的工具。

# 修改 VR 模式下的世界

现在你已经练习了一下在世界中移动，让我们开始学习一些在 VR 中进行场景构图所需的技巧。

# 移动、旋转和缩放对象

要选择一个对象，只需将光束对准它并拉动触发器。您的交互光束将变为黄色，表示您已进入选择模式。将出现一个 Gizmo，允许您移动对象。默认情况下，这将是一个平移 Gizmo，允许您在选定的对象周围移动（我们将在一会儿看到如何切换到其他类型的 Gizmo）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/80c407e4-b9b3-4693-bf34-7108cdaaa4c5.png)

如果您想移动所选对象，请释放触发器，然后再次拉动触发器，同时指向对象或变换 Gizmo。您可以使用变换 Gizmo 的箭头和平面来限制移动，或者直接与对象交互以自由移动它。当使用交互光束直接移动对象时，您可以使用触摸板将其靠近或远离您。

请注意，带有碰撞的隐藏对象有时会干扰 VR 模式下的选择。如果您的选择光束似乎穿过您想要选择的对象，请移动到不同的视角点来选择它。

通常最好使用 Gizmo 来移动对象，因为使用任何精度将对象在深度上移动是相当困难的。

可以使用径向菜单界面将默认的变换 Gizmo 切换到其他模式。要激活径向菜单，请触摸非交互手上的触摸板或拇指杆，并指向您想要选择的菜单选项。使用触发器进行选择。您的控制器菜单按钮将带您退出子菜单，或者如果您已经在顶级菜单，则关闭径向菜单：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/dab60762-c626-49ee-97e7-5d65f28008b3.png)

选择 Gizmo 子菜单可以在变换 Gizmo 选项之间切换：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/155452c0-31cd-40fa-a1d4-61ddd45c5fbf.png)

通用 Gizmo 提供了一个单一的 Gizmo 上的平移、旋转和缩放控制。平移、旋转和缩放 Gizmo 为这些操作提供了单独的工具。将变换模式切换为局部空间时，对象沿着自己的轴旋转、缩放和移动，而世界空间模式则沿着世界轴变换对象。

# 使用两个控制器旋转和缩放对象

您可能还注意到，每当您选择一个对象并将触发器放在对象本身上（而不是 Gizmo 手柄上）时，您的非主手控制器上会出现第二个交互光束。如果您将第二个交互光束对准对象并按下触发器，您可以同时使用它们来翻转和拉伸对象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/b2e8f473-afa4-4b7c-a554-b2fc53f4fd6a.png)

这是一个探索即兴布局的好工具。它直观并邀请您与环境中的对象进行自然互动。这是一个用于探索和即兴布局的好工具。您可能会发现将物体放在您想要的位置可能会很困难，但如果您使用此工具进行粗略布局，然后在平面编辑器中进行清理，您可以获得良好的结果。

# 练习移动对象

现在试试吧。按下*Alt* + *V*进入 VR 模式，并且除了练习在世界中移动之外，还要练习使用变换 Gizmo 和自由移动来移动世界中的对象。记得使用径向菜单来改变移动模式，并使用菜单按钮返回到主菜单。花些时间练习一下。一开始控制可能会感到陌生，但一旦掌握了它们，用 VR 进行世界构建将是一种有益的体验。

完成后，按下*Alt* + *V*再次退出 VR 模式，如果需要，在平面编辑中清理对象对齐。

现在我们准备开始组合一个场景，为此，我们将使用 VR 模式菜单。

# 在 VR 模式中组合新场景

现在我们已经学会了 VR 模式编辑器的基本操作，让我们深入了解一下如何将其用作场景组合工具。首先，我们需要一些要使用的资产。免费的无尽之剑：草地包将为我们提供一些可以玩耍的东西。

打开您的 Epic Games Launcher（在此过程中可以保留您现有的项目打开），导航到 Unreal Engine | Marketplace | Free 选项卡，并搜索 Infinity Blade: Grass Lands。点击“添加到项目”并选择您的新项目作为目标项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/de76f21f-15b8-4547-aea8-0b70bc57d246.png)

一旦资产下载和安装完成，让我们强制编译新的着色器。打开`Content/InfinityBladeGrassLands/Maps/Overview`，并让着色器编译。在这些着色器编译时，可以使用*Alt* + *V*进入 VR 模式，并在概览地图中导航，看看我们可以使用的资产。

在构建了您的着色器之后，我们可以使用这些资产来组合一个场景。对于这个练习，我们将从一个现有的地图开始并进行修改。

首先，我们需要学习如何在 VR 中导航编辑器菜单。

# 导航径向菜单

VR 编辑器中的菜单交互主要是通过附加到控制器的一系列径向菜单来处理的。实际上，这些菜单使用起来相当直观，因为它们清晰地映射到手柄上的触摸板或拇指杆输入。让我们看看它们是如何工作的：

1.  选择`Content/InfinityBladeGrassLands/Maps/ElvenRuins`并打开它。

1.  如果您愿意，您还可以更改您的项目设置|地图和模式|默认地图以自动打开此地图。

1.  使用*Alt* + *V*进入 VR 模式，当您处于此模式时，触摸左侧的触摸板或拇指杆以激活径向菜单。

1.  要进入菜单，请将交互光束对准它并按下扳机或使用菜单手柄的触控板选择选项。

1.  要退出子菜单，请使用非主导手的菜单按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/d0ebaa31-c31e-4b5a-af82-d439d01952b0.png)

您可以使用交互光束或菜单手柄的触控板在 VR 模式下导航菜单

让我们进入 VR 模式并探索菜单。您可以从主菜单中选择八个主要菜单类别。

# Gizmo

我们已经探索了 Gizmo 菜单，所以我们不会在这里详细介绍。请记住，它用于在编辑器中切换移动工具的行为。

# 对齐

对齐菜单是 Gizmo 菜单的紧密伙伴。其中大多数的行为与平面编辑器中的行为相同，但智能对齐选项特别值得了解：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/0d9a5d14-bdee-44c3-b3f7-0d9b4a6d0ab6.png)

启用智能对齐后，您在场景中移动的对象将尝试在移动时与其他对象对齐。由于在 VR 模式下很难实现精确的定位，这是一个很大的帮助。

使用“设置目标”选项选择一个特定的对象，您希望其他对象对齐到该对象，并使用“重置目标”选项清除它。

# 窗口

Windows 子菜单提供了访问您在组合场景时将使用的各个调色板和菜单：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/08e0c5ff-bf84-4ffe-b5f7-6106e96a719d.png)

每个按钮都会打开其关联的面板。这些面板与平面编辑器中的面板相同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/1c3a8eb8-99ed-4ec7-b102-ad48fb8b989e.png)

在编辑器的 VR 模式中看到的内容浏览器

要移动一个窗口，将交互光束对准其下方的大条。您可以将其放置和角度调整为任何您想要的方式。移动条左侧的朝下箭头将窗口固定在原位。当它被激活时，窗口将保持在您放置的位置，无论您如何在世界中移动。当它未固定时，窗口将随您的移动而移动。条右侧的 X 形按钮关闭窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/356e00a5-a2bb-40f3-b05e-b134d6f70583.png)

您可以移动活动窗口以创建一个虚拟工作空间来进行工作

这些窗口的工作方式与平面编辑器中的窗口相同。在使用它们时，一个有效的做法是只打开您需要的窗口，并将它们排列在您周围的虚拟工作空间中以完成您正在进行的任务。

在实践中，很多时候，将内容浏览器和详细信息窗格保持打开状态会很有用。

# 编辑

编辑菜单允许您在场景中复制、删除和对齐对象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/4488086f-c2ca-40b5-b0c8-61c05d031518.png)

大多数选项应该都很容易理解，并且符合您对编辑菜单的期望。对齐到地板是一个例外，所以值得记住它在这里。您会经常使用它。

# 工具

工具菜单主要用于管理编辑器中的模拟。在这里，您可以启动、暂停和恢复模拟，并将其结果保存回编辑器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/5892c6f2-95f1-45d8-8bee-99f8bff1de4e.png)

这里还包含了两个与模拟无关的选项。截图工具可以捕捉标准分辨率的截图，但请注意，截图将包括菜单，所以如果您想要一个干净的截图，请将其移出视线。手电筒工具对于在黑暗场景中找到方向非常有用，特别是如果您正在进行场景照明的中途。

# 模式

模式面板允许您放置诸如灯光、体积和基元等演员；管理植被；进入地形雕刻模式；以及绘制纹理和顶点颜色，就像在平面编辑器中一样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/64bd219b-1806-4c61-bd7c-c849fa96e31f.png)

选择其中一个选项将带出一个模式面板，然后可以将其放置在世界中，并以与 Windows 菜单中提供的其他面板相同的方式使用。

# 操作和系统

目前，系统菜单只提供了退出 VR 模式的方法。在撰写本文时，它没有其他功能。操作菜单的行为取决于上下文。

# 对场景进行更改

现在我们已经学会了如何在 VR 模式下操作，让我们将这些学习应用到实践中。我们将在 VR 模式下修改 Elven Ruins 地图。

我们要做的第一件事是改变白天的时间。让我们看看这些废墟在黎明时会是什么样子。

使用*Alt* + *V*进入 VR 模式，用非交互手的触摸板或拇指杆触摸来呼出径向菜单。使用菜单按钮导航返回主页，如果当前处于子菜单中，请选择 Windows 菜单，然后激活 World Outliner。

使用交互光束拖动菜单底部的移动框。将其放在您的侧面稍微下方。

我们要找到在这个场景中充当太阳的定向光。要找到它，点击类型列的标题，按类型对演员列表进行排序，然后使用触摸板滚动列表，找到名为 Light Source 的定向光：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/140918b5-9f61-407c-9946-f1c8c0a90074.png)

不幸的是，在 VR 模式下没有简单的方法输入文本。径向菜单提供了一个数字键盘，您可以在设置值时使用，但如果您想搜索光源，您必须使用传统键盘进行输入。对于这种类型的工作，排序、滚动和选择功能非常好用。

选择定向光后，使用径向菜单激活详细信息面板。使用面板下方的条形图将其拖动到一个可以阅读和交互的位置，但仍然可以看到天空：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/f3da5d9f-2324-46c8-b3c8-f9ef685ac4a7.png)

在这张从 VR 头盔中拍摄的照片中，你可以看到我们通过在 3D 空间中操作面板来创建了一个虚拟工作空间。

将交互光束对准光源的 Rotation Y 值，并在盒子上来回拖动以改变其值。你会看到太阳在头顶上变化。它的初始值大约为-48。将其拖动到大约 210（或者你喜欢的任何位置），可以创建一些漂亮的戏剧性阴影。

现在，选择 BP_SkySphere。在其详细信息面板中，打开 Colors Determined by Sun Position，并勾选 Refresh Material 复选框以改变天空的颜色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/e22807ac-9bb1-4709-8745-a18250d6ae31.png)

这样很好，对吧？像这样的光照变化通常最好在 VR 模式编辑器中进行，因为头戴式显示器中的光照和颜色与平面屏幕上的显示非常不同。

通常最好在平面屏幕编辑器中构建地图中的新元素。VR 模式非常适合检查视线和调整物体位置，但在实践中，它仍然存在一些问题，这可能会使物体选择变得困难：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/c765d94a-f495-4905-81c7-2f95b9da01af.png)

以下是在 VR 模式下工作的几种有效方法，以发挥其优势并解决其弱点：

+   通过缩小世界规模来移动，然后使用传送来到达目的地

+   在 VR 模式中进行粗略的光照调整，以便您可以看到它们对世界的真实影响

+   在传统编辑器中构建几何体，但使用 VR 模式来尝试其位置

养成经常使用*Alt* + *V*来在 VR 中检查环境的习惯，以便在构建时了解哪些调整在 VR 模式下是有意义的，哪些在传统编辑器中效果最好。

最重要的是，我们在本节中想要传达的是，VR 模式绝非奢侈品或花招，而应被视为 VR 场景构建工作流程中的必备工具。

# 为 VR 优化场景

现在我们已经谈了很多关于使用 VR 模式编辑场景的内容，让我们谈谈 VR 开发中一个非常关键的主题-保持可接受的帧率。

我们之前已经多次讨论了在虚拟现实中保持帧率的至关重要性。这是至关重要的，也是具有挑战性的。在本章的剩余部分，我们将讨论一些可以加快场景速度并找出导致速度变慢的原因的方法。

# 测试当前性能

在评估场景性能时，您需要做的第一件事是找出当前运行速度有多快。我们将看一些可以用于此的命令。

从编辑器中，点击**`**（反引号）键。它位于键盘上 1 键的左边，Tab 键的上方。将出现一个控制台输入框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/9b17c2c8-c708-4a46-b879-a20869b57de7.png)

可以在此处输入各种控制台命令。我们将讨论您在优化场景时最有可能使用的命令。

# Stat FPS

在控制台命令行中输入`stat fps`。编辑器窗口中将出现一个帧率计数器，显示两个值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/11449d96-431c-4d3b-8911-fce9fbf607fe.png)

第一个是每秒帧数（FPS）。第二个值告诉您绘制帧所花费的毫秒数，这是您应该训练自己关注的值。帧率是玩家所感知到的，但在开发和尝试解决影响帧率的问题时，如果您训练自己以毫秒为单位思考，那么您在思考所做更改如何影响性能时会更容易。帧率描述了您期望的结果，但您在渲染帧的每个部分上花费的毫秒数是原因。在修复场景时，您需要查看每个操作的单独成本，这些成本以毫秒为单位表示。

# 确定您的帧时间预算

如果我们要以毫秒为单位思考，首先要做的是确定我们可以花多少毫秒来绘制帧并仍然达到目标帧率。这很简单。

要找到应用程序的帧时间预算，将 1,000 除以目标帧率。

这给出了您必须绘制帧的毫秒数以实现此帧率。例如，如果您的目标是刷新率为 90 FPS 的头戴式显示器（大多数头戴式显示器都是如此），我们可以这样找到我们的帧预算：

*1000 / 90 = 11.11*

这给我们一个大约 11 毫秒的帧预算。如果你在 11 毫秒或更短的时间内交付帧，你的 VR 应用程序将以 90 FPS 刷新。这不是很多时间，所以我们需要在大多数场景中做一些工作来实现这一点。

# 关于性能分析的警告

在我们深入性能优化的兔子洞之前，让我们记住几个重要的事情。

首先，平面屏幕上报告的帧时间对于 VR 来说不准确。它是一个可以用来大致了解你的情况的基准值，但当你激活 VR 时，你的帧率会下降。

如果你在平面屏幕值和 VR 值之间看到了明显的帧率下降，请检查你的项目设置，确保已经打开了实例化立体。如果关闭了（这是默认设置），你将支付渲染整个场景两次的全部成本，这绝对是你不想做的。

确保你不仅仅在平面屏幕上检查数值。经常在 VR 中进行测试。一种快速检查 VR 性能的方法是从 VR 模式中读取 stat fps 的值。

+   在可见的 stat fps 下激活 VR 模式。从头戴式显示器中可能无法读取文本，但你可以从平面屏幕输出中读取。

使用这种方法来检查你的环境。在地图中移动并使用 VR 模式检查问题区域。

另一个重要的事情要考虑的是，因为我们是在编辑器中进行测试，所以我们的数字受到编辑器本身的影响。我们需要支付渲染编辑器显示的所有窗口以及游戏场景的成本。为了获得准确的值，我们必须在独立会话中运行游戏。在编辑器中检查你的数字是一个好的实践，可以看到你所做的更改是好还是坏，但你应该记住它们并不能准确描述你打包的应用程序会做什么。

我们还需要记住，当我们在编辑器中测试帧时间时，我们实际上只是在看渲染性能，但我们没有得到关于应用程序的其他部分成本的任何信息。这在大多数情况下都没问题，因为你的问题很可能在渲染方面，但你仍然应该确保测试正在运行的应用程序，以确保你没有一个失控的蓝图或太多的动画角色拖累你。

最后，我们应该谈一下系统规格。不同的硬件配置会有不同的性能表现。如果你计划向公众发布一个应用程序，你应该确保你在最低规格的硬件上进行测试，以及在开发机器上进行测试。仅仅因为你的应用程序在一台配备全新高端显卡的怪物上运行良好，并不意味着它在旧硬件上也会运行得很好。如果你可以在最低规格的目标上进行测试，那就这样做。如果不能，要意识到你的开发机器与最低规格相差多远，并确保在帧时间预算中留出足够的余地来适应这一点。

现在我们已经谈了一些可能影响我们测量结果的因素，让我们深入了解如何获得比仅仅使用 stat fps 更好的信息。

# Stat unit

检查我们的帧率是有用的，也是一个重要的频繁操作，但仅仅这样并不能告诉我们太多信息。它可能告诉我们有问题，但它不会给我们提供找出问题所在或如何修复问题的指导。为此，我们还有一些更有用的命令可以使用。

stat unit 命令以毫秒为单位分解了帧的成本，并显示了我们渲染场景所花费的成本和应用程序中其他活动（如动画和 AI）所花费的成本。

现在试试。点击**`**(反引号)键以打开控制台命令窗口，然后输入 stat unit 以在帧率信息下添加此额外信息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/5122dfe5-e217-4074-91b6-280a4a5dedf2.png)

stat unit 命令显示四个主要信息：

+   帧：这是绘制帧所花费的总时间。这与我们在 stat fps 结果中看到的值相同。

+   Game：这告诉您游戏线程在 CPU 上花费了多长时间。这包括动画更新、AI 和 CPU 必须解决的其他任何事情，以更新帧。如果蓝图在 Tick 事件上执行效率低下的操作，这将增加该值。

+   Draw：这告诉您 CPU 花费了多长时间来准备渲染场景。这里的高值可能意味着您进行了过多的遮挡剔除或在光照或阴影上花费了太多时间。

+   GPU：这个值告诉您 GPU 绘制帧所花费的时间。这里的高值可能意味着您绘制了太多的多边形，使用了太多的材质，或者您的材质过于复杂。大多数情况下，您的问题将出现在这里。

这些值不是累加的。您的游戏线程将等待渲染线程完成，因此，如果游戏时间与 GPU 时间匹配，那么实际上告诉您的是您的 CPU 没有拖慢您的速度，并且您的帧时间是由渲染驱动的。

除了这四个基本值之外，我们还有两个高级信息，您现在不需要担心：

+   RHIT：这是您的渲染硬件接口线程。实际上，除非您使用高级渲染硬件或视频游戏主机，并且在专用线程上运行渲染硬件接口调用，否则您不会在这里看到与 GPU 值差异很大的值。除非您正在进行一个带有专门的工程团队的高级项目，否则这可能不适用于您。

+   DynRes：这表示您的应用程序是否支持或正在使用动态分辨率。实际上，这仅在视频游戏主机上支持，所以您不需要在这里担心它。如果您感兴趣，可以在[`docs.unrealengine.com/en-us/Engine/Rendering/DynamicResolution`](https://docs.unrealengine.com/en-us/Engine/Rendering/DynamicResolution)找到更多信息。

我们从 stat unit 信息中感兴趣的是我们是否在 Game CPU、Game 渲染操作或 GPU 上花费了大部分时间。我们寻找最大的数字，因为这将告诉我们需要修复的问题。

在开发过程中，您应该养成几乎一直保持 stat fps 和 stat unit 的习惯。如果您引入了新的场景，会导致帧率下降，那么发现问题的最佳时间就是在放入场景时。如果您很长时间才发现问题，那么您将需要做更多的工作来找出问题的原因。

查看统计单位值随时间变化的情况通常是值得的，无论是在应用程序中发生的事情（这对于找到卡顿很有用）还是在场景中移动时。要获取这些信息，请使用 stat unitgraph 来显示场景性能指标随时间变化的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/971499d0-346e-437d-b48f-f10bb04678da.png)

您将看到您的 stat unit 值现在已经被彩色编码以对应图表上的线条。

如前所述，大多数情况下，您的问题将与 GPU 艺术品有关，这些艺术品太重而无法适应您的场景。

当然，如果您在 Tick 上做了荒谬的事情，您的 CPU 可能会被杀死，这种情况下，您将希望寻找可以重构以响应事件或数据变化而不是使用 Tick 的蓝图。但是，大多数情况下，您可能会遇到 GPU 的问题。

# 对 GPU 进行分析

优化场景时，您应该学会使用的第一个工具是 GPU 分析器。您可以在控制台中输入 profilegpu 来激活它，但由于您将经常使用它，最好记住快捷键：Ctrl + Shift + ,（逗号）。现在按下它，让我们看看数字：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/97c0ff5f-9d7a-462c-a3b4-3a2ee3630f01.png)

此配置文件报告的最重要部分是场景标题下的图表。将鼠标悬停在图表上，您将看到工具提示告诉您每个块代表什么。最大的两个块通常是您的 BasePass 和 PostProcessing pass。基本传递表示绘制场景中的所有内容的行为。后处理处理在场景绘制完成后处理的任何内容，例如屏幕空间环境遮挡、颜色校正和其他效果。

点击场景标题左侧的展开器，以获取更多关于场景渲染的详细信息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/ae6955a0-d425-4afa-8eb5-9d33ee1045fa.png)

在这里，我们可以看到更详细的细分，了解绘制帧所花费的时间。光照看起来很好，透明度也很好。我们的 BasePass 相当大，但这是可以预料的。

通过深入研究 BasePass，您不会获得太多更多的信息，但是通过深入研究 PostProcessing 操作，您可以学到一些有用的东西。使用 PostProcessing 标题旁边的三角形进行深入研究，然后单击 PostProcessing 操作中的大块以查看它们是什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/d6640a19-f716-4575-8685-0433e7722b89.png)

在这种情况下，这些后续数字看起来相当不错。我们没有任何一个持续时间过长的问题。

确保在游戏运行时进行分析，否则您将看到许多来自编辑器的操作。

我们在这里没有足够的空间来深入研究渲染过程和其含义的所有内容，但总的来说，您要寻找的是可能不必要地影响帧率的大型项目。当您发现看起来可疑的东西时，在虚幻论坛上搜索它，您可能会找到关于它的讨论以及如何处理它的方法。

随着您越来越多地使用这个工具，您会逐渐对健康的外观和问题区域的外观有所了解。经常使用它来清楚地了解您的应用程序正在做什么。

现在，让我们看一些其他有用的命令，我们可以用来调试我们的场景。

# Stat scenerendering

在 GPU 分析器之后，您下一个最有用的命令可能是 stat scenerendering。该命令会详细列出系统在渲染场景时所采取的步骤及其相关的时间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6087c36f-4f15-4688-b71f-292166f05f8a.png)

在这里特别值得一看的是您的动态阴影设置和透明度绘制。

如果您在阴影设置中看到较高的值，请查看是否有一个或多个灯光正在执行过多的阴影级联或具有过长的阴影距离。您可以在此主题的[`docs.unrealengine.com/en-us/Platforms/Mobile/Lighting/HowTo/CascadedShadow`](https://docs.unrealengine.com/en-us/Platforms/Mobile/Lighting/HowTo/CascadedShadow)上找到更多信息。

如果您的透明度绘制很高，请激活编辑器的 Quad Overdraw 优化视图模式，并查找互相堆叠的透明对象。如果您在这里有问题，您可以尝试使用遮罩材质而不是透明材质，或者注意它们在视图中的重叠情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/acd1e832-c2fe-4486-89d3-c317d9df8bd0.png)

在此列表的底部有一些非常重要的数字：网格绘制调用和静态列表绘制调用。我们应该谈谈这些。

# 绘制调用

影响场景性能的最大因素之一是将信息传输到 GPU 所需的绘制调用次数。我们在这里讨论什么？情况如下：你希望显卡绘制的所有内容都必须复制到该显卡的内存中。向显卡发送一组指令的行为称为绘制调用，或称为绘制原语调用（有时缩写为 DPC）。假设你的场景中出现了一个静态网格，上面有三个材质。这将需要四个绘制调用来设置它在显卡上的绘制：一个用于网格，每个材质一个。你应该尽量减少场景中的绘制调用次数。实际上，对于 VR 场景，2000 个绘制调用可能是你的限制。在移动 VR 中，如 Oculus Go 或 Quest，这个数字更低。

这对你意味着什么？首先，尽量少地在物体上使用材质；理想情况下，每个物体只使用一个材质。只需添加一个额外的材质槽，你就增加了加载该物体到视频硬件的成本的三分之一，如果该物体在场景中频繁出现，这个成本会迅速累积。

我们很快会讨论如何处理高绘制调用次数的方法，但现在你需要知道的是，如果这些数字很高，说明你向显卡发送了太多的单独指令，这会减慢速度。也许你的物体上有太多的材质槽，或者有太多单独发送的物体，但在所有情况下，这都是你需要解决的问题。

# Stat RHI

另一个与之密切相关的经常使用的命令是 stat rhi。RHI 代表渲染硬件接口，它告诉你具体影响渲染性能的是什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/bc2c62aa-340e-407c-99c4-2d67ef13d687.png)

在这里你最关心的两个值是绘制的三角形数量和绘制原语调用次数。养成查看这些值的习惯，并寻找三角形数量或绘制调用次数过高的视图。对于桌面 VR 头显上的 VR 场景，你希望将绘制的三角形数量保持在 200 万以下，并且将绘制调用次数保持在 2000 以下。

在这里你还应该关注的另一个值是内存消耗。在实时场景中，使用过大的纹理也会导致场景运行非常缓慢。不要将 4K 纹理放在小石子上。我们见过这种情况发生。

`Stat rhi`是获取场景在预算内的整体感觉最有用的命令之一。

# 统计内存

当你需要更多关于内存预算超支的信息时，可以使用 stat memory：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/d76c5890-822a-441f-9c67-8ade3e67b798.png)

大多数情况下，如果你的内存消耗过高，罪魁祸首往往是纹理。要注意使用过大的纹理。一个巨大的物体或主角角色可能需要一个 2048x2048 的纹理。其他任何东西都应该是 1024x1024 或更小。在 VR 中，使用 4K 纹理可能在任何情况下都不合理。在考虑如何减少纹理时，看看场景中的物体。它有多大？玩家能走多近？玩家真的在意看它吗？很容易在玩家几乎看不到的物体上花费太多。开始考虑在重要的地方使用纹理和多边形预算，并在可以节省的地方节约。

# 优化视图模式

除了统计命令之外，我们还有一些优化视图模式，可以用来找出场景中的问题。这些模式可以从编辑器视口的视图模式菜单中访问。我们这里只讨论其中的两个。

着色器复杂度视图显示了可能导致性能下降的材质位置。当您找到一个可疑的对象时，选择它，并查看其材质中发生了什么。您的材质是否过于复杂或进行了昂贵的计算？考虑以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/2e5b4544-4e4d-4bb0-87b6-e97ca675ea5a.png)

在上面的截图中，草和树被识别为昂贵的材质。当我们选择它们的对象并查看这些材质时，我们可以看到推高成本的原因是它们使用了世界位置偏移输入来模拟风。这是昂贵的，但是这是一个很好的效果，如果我们关闭它，玩家会注意到，所以我们可以不管它，因为我们场景的其余部分运行得相当高效。

使用此视图搜索可能会消耗大量资源但对场景没有太多价值的材质。

如果您在延迟渲染模型下使用动态光源，那么光照复杂度视图就会起作用。因为我们在这里使用的是正向渲染和静态光源，所以在这个场景中不会显示任何内容。当您使用动态光源和延迟渲染时，这个视图可以显示您的光源引起的问题所在。

# CPU 分析

如果您的 CPU 时间有问题，您可以使用 CPU 分析来找出问题所在，就像我们之前使用 GPU 分析器一样。

要激活 CPU 分析，在游戏运行时，打开控制台命令并键入`stat startfile`开始分析。分析会生成大量数据，所以您不希望在整个会话中运行分析器-只捕获您感兴趣的内容，比如“为什么当角色警报敌人时游戏会变得如此缓慢？”

在捕获到您要查找的内容后，键入`stat stopfile`以关闭分析。分析器将把捕获的数据保存到项目的`\Saved\Profiling\UnrealStats\`目录下的`.ue4stats`文件中。

现在，打开您的虚幻引擎安装目录，在其中的`Binaries\Win64`文件夹中找到`UnrealFrontend.exe`应用程序。启动它并使用选项卡选择 Session | Frontend | Profiler。使用分析器的加载按钮打开刚刚生成的`.ue4stats`文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/79471103-c543-4e39-80c6-7eaf659f054e.png)

CPU 分析器显示了每个帧调用的操作所花费的时间。

就像我们在 GPU 分析器中所做的那样，您可以使用此工具来查看昂贵的函数调用并了解发生了什么。在这本书的范围之外，我们无法深入介绍如何在此处使用 CPU 分析器-它是一个非常有用和强大的工具，但需要一些时间来学习如何从中获取有用的信息。我们建议您探索有关此主题的详细信息，可以在[`www.unrealengine.com/en-US/blog/how-to-improve-game-thread-cpu-performance`](https://www.unrealengine.com/en-US/blog/how-to-improve-game-thread-cpu-performance)找到。

# 打开和关闭功能

尽管听起来很原始，但是找出导致帧率下降的原因最有效的方法之一就是打开和关闭相关统计信息显示的功能（通常，`stat unit`是您想要的）。使用视口的显示菜单打开和关闭单个元素，特别是如果您通过 GPU 分析或统计信息确定该元素可能会引起问题。如果从您的关卡中删除对象（只要您有备份或它在源代码控制下），并查看是否有特定对象会产生很大的变化，这也可能会有所帮助。

# 解决帧率问题

现在我们已经学会了如何找到场景中的问题，让我们谈谈如何处理这些问题。

# 清理蓝图的 Tick 事件

如果你在 CPU 上看到很高的数字，你要寻找的第一个罪魁祸首之一就是在 Tick 事件上执行操作的蓝图。这是一个非常常见的问题。请记住，Tick 事件在每一帧都会发生，所以如果你在 Tick 上做了很多工作，你就会影响到每一帧的绘制。寻找将这个工作分散到多个帧上的方法，或者避免使用 Tick，只在发生变化时使用事件来改变对象的状态。

# 管理骨骼动画

如果你有很多骨骼网格在进行动画，确保它们的骨架中没有荒谬的骨骼数量，并确保它们没有使用大量的混合空间动画。最好的做法是使用骨骼网格的细节层次（LOD），只在玩家能看到时包含细节，或者在电影中使用单独的骨骼网格，其中高度详细的面部动画很重要，并且在游戏中使用骨骼数量较低的骨骼网格。有关设置骨骼网格 LOD 的更多信息，请从以下链接开始查看：[`docs.unrealengine.com/en-US/Engine/Content/ImportingContent/ImportingSkeletalLODs`](https://docs.unrealengine.com/en-US/Engine/Content/ImportingContent/ImportingSkeletalLODs)。

# 合并演员

这是一个重要的问题。还记得不久前我们提到过绘制调用数量对帧率有很大影响吗？将多个网格合并成一个单一的网格是降低绘制调用数量的最便宜和最简单的方法之一。这不仅会将你选择的多个单独网格创建为一个单一网格，还会为该网格创建一个合并的材质，其中包含每个子网格的材质。这是一个重要的事情。

假设你在房间的一个角落里有一堆碎片；大约有 25 个物体，每个物体使用一个材质槽。这样一来，你就会有 50 个绘制调用，而你整个场景可用的绘制调用总数可能是 2000 个。这是一个很大的负担。通过将它们合并成一个单一的物体，你可以将 50 个绘制调用减少到两个。这是你可以减少绘制调用数量的最快和最有效的方法之一。

不过，这里有一个需要注意的地方：还记得在本书前面我们提到过 Kent Beck 的建议“让它工作，让它正确，让它快”吗？这是其中一个适用的领域。一旦你将所有这些物体合并成一个单一的物体，你就不再有重新排列各个组件的自由，所以先让场景看起来符合你的要求，然后合并你的演员以控制事物。

以下是如何操作：

选择窗口 | 开发者工具 | 合并演员。合并演员窗口将出现。选择要合并的演员。一般来说，合并那些靠近并且可能在同一视图中的演员是一个好主意。一旦它们被合并，即使只有其中一个在镜头中，所有它们都将被绘制，所以合并那些大部分时间都会同时出现在镜头中的物体：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/050ceecf-612a-4b08-a493-794364c8321a.png)

在视口后面看到多个选定演员的合并演员对话框

如果选择替换源演员，则在场景中选择的演员将被合并模型替换。有关合并演员的更多信息，请从以下链接开始：[`docs.unrealengine.com/en-us/Engine/Actors/Merging`](https://docs.unrealengine.com/en-us/Engine/Actors/Merging)。

# 使用网格 LOD

在场景中绘制的三角形数量（通常称为多边形数量）是决定场景渲染速度的另一个重要因素。

当然，对抗高面数的第一道防线是建模。使用像 Pixologic 的 ZBrush 这样的应用程序，从高细节模型中烘焙法线贴图，并将其应用于导入游戏引擎的低细节网格。大部分时间，你的玩家都不会注意到区别。虚拟现实对使用法线贴图模拟几何细节的宽屏显示器不太宽容，因为玩家有时会看到深度不是真实的，但你仍然应该在任何可以使用这种技术的地方使用它。

然而，一旦你在游戏中有了一个网格，你就有一个强大的 LOD 工具可用于管理你绘制的三角形数量。LOD 的工作原理如下：它们存储了同一模型的几个版本，其面数逐渐减小。随着模型在屏幕上变小，系统会将高细节网格替换为低细节网格，因为玩家无法看到远离的细节。

以下是如何设置 LOD：

1.  选择一个静态网格，并从内容浏览器中打开静态网格编辑器。

1.  在其详细信息下，找到 LOD 设置部分。

1.  找到 LOD 数量条目，并将其设置为大于 1 的值。（对于此测试，只需将其设置为 2 以创建 2 个 LOD。）

1.  点击“应用更改”。现在将创建一个或多个额外的 LOD 模型，并将其添加到静态网格资源中。

1.  在 LOD 选择器部分，找到 LOD 条目，并使用它选择一个新的 LOD。

LOD 0 是原始模型。大部分时间你会保持不变。LOD 1 是 LOD 0 之后的第一个 LOD。

1.  选择一个新的 LOD，比如 LOD 1，打开其 LOD 详细部分的减少设置条目并进行修改。

这里有很多选项，但大部分时间，你将管理三角形百分比值。如果在这里进行更改，请点击“应用更改”以查看结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/6a7ebedb-cecd-4c70-af01-6fdb195e3d3e.png)

你会在视口中看到修改后的网格。为了看到它在真实视距下的样子，将 LOD 选择器切换回 LOD 自动，并移动视图以查看对象在 LOD 之间切换时的变化。LOD 生成器非常出色。

有关创建和使用 LOD 的更多信息，请首先查看[`docs.unrealengine.com/en-us/Engine/Content/Types/StaticMeshes/HowTo/LODs`](https://docs.unrealengine.com/en-us/Engine/Content/Types/StaticMeshes/HowTo/LODs)。

# 静态网格实例化

还记得我们刚才关注的绘制调用吗？还有另一种强大的方法可以减少它们的数量并大大加快渲染速度。

假设你有一个大的集合，其中大部分是相同的资产，比如一个重复使用相同树木网格数百次的森林。如果你只是单独将这些网格放置在环境中，每一个都会生成至少两个绘制调用，如果使用更多材质则会更多。这是一个幻灯片的制作方法。相反，你想要做的是**实例化**这个几何体。实例化是一种告诉你的 GPU 的方法，即使它即将绘制几百个网格，它们实际上都是相同的网格，只是具有不同的变换。因此，系统不是为每棵树都进行单独的绘制调用，而是进行一组绘制调用，并向视频硬件提供一个位置、方向和缩放的列表来绘制它们。这比将每个项目作为单独的项目传递要快得多。

在虚幻中，默认情况下实例化对象的最简单方法是使用植被工具。虽然它通常用于植被，但正如其名称所示，您也可以在许多其他情境中使用它来重复使用对象，比如城市街道上的路灯。您可以在[`docs.unrealengine.com/en-us/Engine/Foliage`](https://docs.unrealengine.com/en-us/Engine/Foliage)上找到有关植被实例化的更多信息。

在场景之外实例化静态网格是一个稍微复杂的话题，但是可以做到，并且如果您正在以程序化方式生成包含大量单独静态网格的角色，这可能是一个好主意。然而，大多数情况下，当您在场景中实例化对象时，请使用植被工具来完成。

# 本地化蓝图

蓝图已经以惊人的速度进行解释，但通过自动将它们转换为 C++，然后允许系统编译它们，可以使它们变得更快。

要打开此选项，请打开“项目设置 | 项目 | 打包 | 蓝图”，并使用“蓝图本地化方法”选择器选择**包含**或**独占**本地化。

+   **包含**本地化将在编译时将所有蓝图转换为 C++。

+   **独占**本地化只会转换那些您设置了本地化标志的蓝图。

如果您使用独占本地化，请通过打开它们的“类设置”来选择要本地化的蓝图，并在其“详细信息 | 打包”面板中打开“本地化”选项。如果您使用包含本地化，则不需要这样做。在这种情况下，每个蓝图都会被本地化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-vr-pj/img/ff134984-41b9-4db7-a36c-3ae3e9514914.png)

如果您计划在桌面 VR 上发布应用程序，包含本地化可能是可以的，但如果您计划部署到移动 VR，比如 Oculus Go 或 Quest，最好使用独占本地化来选择要本地化的蓝图，因为包含所有蓝图可能会增加可执行文件的大小。

这是一个比较高级的话题。一般来说，如果您的蓝图在 Tick 事件上做了很多工作，或者总体上做了很多工作，您将会看到一些好处。如果您的蓝图相当简单，无论如何都不会看到差异。由于速度对于 VR 开发非常关键，所以了解这个选项是很好的。

如果您计划这样做，请在项目开发的早期打开本地化，并经常在烹饪的构建上进行测试。本地化非常好，但有时仍可能导致意外的副作用。

# 总结

在本章中，我们学到了如何使用虚幻的 VR 模式编辑器在 VR 中组合环境，并学习了如何分析和优化场景以查看性能瓶颈所在。

在下一章中，我们将暂时离开在 VR 中构建实时 3D 世界的内容，转而看另一个常见的应用程序——电影和沉浸式摄影。
