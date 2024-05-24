# C++ 游戏动画编程实用指南（四）

> 原文：[`annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b`](https://annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：动画之间的混合

从一个动画过渡到另一个动画可能会很突兀。想象一下，如果一个角色正在进行一次拳击，玩家决定开始奔跑。如果动画直接从跳跃片段切换到奔跑片段，过渡将会很生硬和不自然。

动画混合可以通过生成两个动画的平均中间帧来修复这个问题。这种淡入通常很短——不到一秒钟。这种短混合产生的平滑动画过渡提供了更好的观感体验。

本章探讨了如何实现动画混合和附加动画混合，以及如何设置交叉淡入淡出控制器来管理混合队列。将涵盖以下主题：

+   姿势混合

+   交叉淡入淡出动画

+   附加混合

# 姿势混合

动画混合是在每个关节的本地空间中两个姿势之间的线性混合。可以将其视为`lerp`或`mix`函数，但应用于整个姿势。这种技术不是混合动画片段；而是混合这些片段被采样到的姿势。

在混合两个姿势时，不需要整个姿势都进行混合。假设有两个动画——奔跑循环和攻击。如果玩家按下攻击按钮，攻击姿势的上半部分在短时间内混合进来，保持在整个动画中的权重为`1`，然后在动画结束时淡出。

这是一个使用姿势混合来创建奔跑攻击动画的示例，而无需对攻击动画的腿部进行动画处理。攻击动画可以在行走动画的基础上混合。动画混合可用于平滑地过渡动画或将多个动画组合成一个新动画。

在接下来的部分，您将为`Pose`类声明一个`Blend`函数。这个`Blend`函数将在两个姿势之间进行线性插值，类似于向量`lerp`的工作方式。该函数需要两个姿势和一个插值值，通常表示为`t`，其范围为`0`到`1`。

## 声明混合函数

`Blend`函数接受两个姿势——混合值和根节点作为参数。当混合值为`0`时，`Blend`函数返回第一个姿势，当为`1`时，返回第二个姿势。对于介于`0`和`1`之间的任何值，姿势都会被混合。根节点决定了第二个动画的哪个节点（及其子节点）应该混合到第一个动画中。

为了适应指定从哪个骨骼节点开始混合，需要一种方法来检查一个节点是否在另一个节点的层次结构中。`IsInHierarchy`函数接受一个`Pose`类，一个作为根节点的节点和一个作为搜索节点的节点。如果搜索节点是根节点的后代，则函数返回`true`：

```cpp
bool IsInHierarchy(Pose& pose, unsigned int root, 
                   unsigned int search);
void Blend(Pose& output,Pose& a,Pose& b,float t,int root);
```

当混合两个姿势时，假设这些姿势是相似的。相似的姿势具有相同数量的关节，并且每个关节在姿势之间具有相同的父级索引。在接下来的部分，您将实现`Blend`函数。

## 实现混合功能

为了使混合有效，它必须在本地空间中进行，这对于在两个姿势之间进行混合非常方便。循环遍历输入姿势中的所有关节，并在正在混合的两个姿势中插值关节的本地变换。对于位置和比例，使用向量`lerp`函数，对于旋转，使用四元数`nlerp`函数。

为了支持动画根节点，检查当前变换是否是混合根的后代。如果是，进行混合。如果不是，则跳过混合，并保持第一个输入姿势的变换值。按照以下步骤实现层次结构检查和`Blend`函数：

1.  要检查一个关节是否是另一个关节的后代，沿着后代关节一直向上遍历层次结构，直到根节点。如果在这个层次结构中遇到的任何节点都是您要检查的节点，则返回`true`：

```cpp
bool IsInHierarchy(Pose& pose, unsigned int parent, 
                   unsigned int search) {
    if (search == parent) {
        return true;
    }
    int p = pose.GetParent(search);
    while (p >= 0) {
        if (p == (int)parent) {
            return true;
        }
        p = pose.GetParent(p);
    }
    return false;
}
```

1.  为了将两个姿势混合在一起，循环遍历每个姿势的关节。如果当前关节不在混合根的层次结构中，则不进行混合。否则，使用您在*第五章*中编写的`mix`函数来混合`Transform`对象。`mix`函数考虑四元数邻域：

```cpp
void Blend(Pose& output, Pose& a, Pose& b, 
           float t, int root) {
    unsigned int numJoints = output.Size();
    for (unsigned int i = 0; i < numJoints; ++i) {
        if (root >= 0) {
            if (!IsInHierarchy(output, root, i)) {
                continue;
            }
        }
        output.SetLocalTransform(i, mix(
              a.GetLocalTransform(i), 
              b.GetLocalTransform(i), t)
        );
    }
}
```

如果使用整个层次结构混合两个动画，则`Blend`的根参数将为负数。对于混合根的负关节，`Blend`函数会跳过`IsInHierarchy`检查。在接下来的部分，您将探索如何在两个动画之间进行淡入淡出以实现平滑过渡。

# 淡入淡出动画

混合动画的最常见用例是在两个动画之间进行淡入淡出。**淡入淡出**是从一个动画快速混合到另一个动画。淡入淡出的目标是隐藏两个动画之间的过渡。

一旦淡入淡出完成，活动动画需要被正在淡入的动画替换。如果您正在淡入多个动画，则它们都会被评估。最先结束的动画首先被移除。请求的动画被添加到列表中，已经淡出的动画被从列表中移除。

在接下来的部分，您将构建一个`CrossFadeController`类来处理淡入淡出逻辑。这个类提供了一个简单直观的 API，只需一个函数调用就可以简单地在动画之间进行淡入淡出。

## 创建辅助类

当将动画淡入到已经采样的姿势中时，您需要知道正在淡入的动画是什么，它的当前播放时间，淡入持续时间的长度以及淡入的当前时间。这些值用于执行实际的混合，并包含有关混合状态的数据。

创建一个新文件并命名为`CrossFadeTarget.h`，以实现`CrossFadeTarget`辅助类。这个辅助类包含了之前描述的变量。默认构造函数应将所有值设置为`0`。还提供了一个方便的构造函数，它接受剪辑指针、姿势引用和持续时间：

```cpp
struct CrossFadeTarget {
   Pose mPose;
   Clip* mClip;
   float mTime;
   float mDuration;
   float mElapsed;
   inline CrossFadeTarget() 
          : mClip(0), mTime(0.0f), 
            mDuration(0.0f), mElapsed(0.0f) { }
   inline CrossFadeTarget(Clip* target,Pose& pose,float dur) 
          : mClip(target), mTime(target->GetStartTime()), 
            mPose(pose), mDuration(dur), mElapsed(0.0f) { }
};
```

`CrossFadeTarget`辅助类的`mPose`、`mClip`和`mTime`变量在每一帧都用于采样正在淡入的动画。`mDuration`和`mElapsed`变量用于控制动画应该淡入多少。

在下一节中，您将实现一个控制动画播放和淡入淡出的类。

## 声明淡入淡出控制器

跟踪当前播放的剪辑并管理淡入淡出是新的`CrossFadeController`类的工作。创建一个新文件`CrossFadeController.h`，声明新的类。这个类需要包含一个骨架、一个姿势、当前播放时间和一个动画剪辑。它还需要一个控制动画混合的`CrossFadeTarget`对象的向量。

`CrossFadeController`和`CrossFadeTarget`类都包含指向动画剪辑的指针，但它们不拥有这些指针。因为这两个类都不拥有指针的内存，所以生成的构造函数、复制构造函数、赋值运算符和析构函数应该可以正常使用。

`CrossFadecontroller`类需要函数来设置当前骨架、检索当前姿势和检索当前剪辑。当前动画可以使用`Play`函数设置。可以使用`FadeTo`函数淡入新动画。由于`CrossFadeController`类管理动画播放，它需要一个`Update`函数来采样动画剪辑：

```cpp
class CrossFadeController {
protected:
    std::vector<CrossFadeTarget> mTargets;
    Clip* mClip;
    float mTime;
    Pose mPose;
    Skeleton mSkeleton;
    bool mWasSkeletonSet;
public:
    CrossFadeController();
    CrossFadeController(Skeleton& skeleton);
    void SetSkeleton(Skeleton& skeleton);
    void Play(Clip* target);
    void FadeTo(Clip* target, float fadeTime);
    void Update(float dt);
    Pose& GetCurrentPose();
    Clip* GetcurrentClip();
};
```

整个`mTargets`列表在每一帧都会被评估。每个动画都会被评估并混合到当前播放的动画中。

在接下来的部分，您将实现`CrossFadeController`类。

## 实现淡出控制器

创建一个新文件，`CrossFadeController.cpp`。在这个新文件中实现`CrossFadeController`。按照以下步骤实现`CrossFadeController`：

1.  在默认构造函数中，为当前剪辑和时间设置默认值`0`，并将骨骼标记为未设置。还有一个方便的构造函数，它接受一个骨骼引用。方便的构造函数应调用`SetSkeleton`函数：

```cpp
CrossFadeController::CrossFadeController() {
    mClip = 0;
    mTime = 0.0f;
    mWasSkeletonSet = false;
}
CrossFadeController::CrossFadeController(Skeleton& skeleton) {
    mClip = 0;
    mTime = 0.0f;
    SetSkeleton(skeleton);
}
```

1.  实现`SetSkeleton`函数，将提供的骨骼复制到`CrossFadeController`中。它标记该类的骨骼已设置，并将静止姿势复制到交叉淡出控制器的内部姿势中：

```cpp
void CrossFadeController::SetSkeleton(
                          Skeleton& skeleton) {
    mSkeleton = skeleton;
    mPose = mSkeleton.GetRestPose();
    mWasSkeletonSet = true;
}
```

1.  实现`Play`函数。此函数应清除任何活动的交叉淡出。它应设置剪辑和播放时间，但还需要将当前姿势重置为骨骼的静止姿势：

```cpp
void CrossFadeController::Play(Clip* target) {
    mTargets.clear();
    mClip = target;
    mPose = mSkeleton.GetRestPose();
    mTime = target->GetStartTime();
}
```

1.  实现`FadeTo`函数，该函数应检查请求的淡出目标是否有效。淡出目标仅在不是淡出列表中的第一个或最后一个项目时才有效。假设满足这些条件，`FadeTo`函数将提供的动画剪辑和持续时间添加到淡出列表中：

```cpp
void CrossFadeController::FadeTo(Clip* target, 
                                 float fadeTime) {
    if (mClip == 0) {
        Play(target);
        return;
    }
    if (mTargets.size() >= 1) {
        Clip* clip=mTargets[mTargets.size()-1].mClip;
        if (clip == target) {
            return;
        }
    }
    else {
        if (mClip == target) {
            return;
        }
    }
    mTargets.push_back(CrossFadeTarget(target, 
           mSkeleton.GetRestPose(), fadeTime));
}
```

1.  实现`Update`函数以播放活动动画并混合任何在淡出列表中的其他动画：

```cpp
void CrossFadeController::Update(float dt) {
    if (mClip == 0 || !mWasSkeletonSet) {
        return;
    }
```

1.  将当前动画设置为目标动画，并在动画淡出完成时移除淡出对象。每帧只移除一个目标。如果要移除所有已淡出的目标，请将循环改为反向：

```cpp
    unsigned int numTargets = mTargets.size();
    for (unsigned int i = 0; i < numTargets; ++i) {
        float duration = mTargets[i].mDuration;
        if (mTargets[i].mElapsed >= duration) {
            mClip = mTargets[i].mClip;
            mTime = mTargets[i].mTime;
            mPose = mTargets[i].mPose;
            mTargets.erase(mTargets.begin() + i);
            break;
        }
    }
```

1.  将淡出列表与当前动画混合。需要对当前动画和淡出列表中的所有动画进行采样：

```cpp
    numTargets = mTargets.size();
    mPose = mSkeleton.GetRestPose();
    mTime = mClip->Sample(mPose, mTime + dt);
    for (unsigned int i = 0; i < numTargets; ++i) {
        CrossFadeTarget& target = mTargets[i];
        target.mTime = target.mClip->Sample(
                     target.mPose, target.mTime + dt);
        target.mElapsed += dt;
        float t = target.mElapsed / target.mDuration;
        if (t > 1.0f) { t = 1.0f; }
        Blend(mPose, mPose, target.mPose, t, -1);
    }
}
```

1.  使用`GetCurrentPose`和`GetCurrentclip`辅助函数完成`CrossFadeController`类的实现。这些都是简单的 getter 函数：

```cpp
Pose& CrossFadeController::GetCurrentPose() {
    return mPose;
}
Clip* CrossFadeController::GetcurrentClip() {
    return mClip;
}
```

现在，您可以创建`CrossFadeController`的实例来控制动画播放，而不是手动控制正在播放的动画。`CrossFadeController`类在开始播放新动画时会自动淡出到新动画。在下一部分中，您将探索加法动画混合。

# 加法混合

加法动画用于通过添加额外的关节运动来修改动画。一个常见的例子是向左倾斜。如果有一个向左倾斜的动画，它只是简单地弯曲了角色的脊柱，它可以添加到行走动画中，以创建一个边走边倾斜的动画，奔跑动画，或者任何其他类型的动画。

并非所有动画都适合作为加法动画。加法动画通常是专门制作的。我已经在本章的示例代码中提供的`Woman.gltf`文件中添加了一个`Lean_Left`动画。这个动画是为了加法而制作的。它只弯曲了脊柱关节中的一个。

加法动画通常不是根据时间播放，而是根据其他输入播放。以向左倾斜为例——它应该由用户的操纵杆控制。操纵杆越靠近左侧，倾斜的动画就应该越进。将加法动画的播放与时间以外的其他内容同步是很常见的。

## 声明加法动画

加法混合的函数声明在`Blending.h`中。第一个函数`MakeAditivePose`在时间`0`处对加法剪辑进行采样，生成一个输出姿势。这个输出姿势是用来将两个姿势相加的参考。

`Add`函数执行两个姿势之间的加法混合过程。加法混合公式为*result pose* = *input pose* + (*additive pose – additive base pose*)。前两个参数，即输出姿势和输入姿势，可以指向同一个姿势。要应用加法姿势，需要加法姿势和加法姿势的引用：

```cpp
Pose MakeAdditivePose(Skeleton& skeleton, Clip& clip);
void Add(Pose& output, Pose& inPose, Pose& addPose, 
         Pose& additiveBasePose, int blendroot);
```

`MadeAdditivePose`辅助函数生成`Add`函数用于其第四个参数的附加基础姿势。该函数旨在在初始化时调用。在下一节中，您将实现这些函数。

## 实现附加动画

在`Blending.cpp`中实现`MakeAdditivePose`函数。该函数仅在加载时调用。它应在剪辑的开始时间对提供的剪辑进行采样。该采样的结果是附加基础姿势：

```cpp
Pose MakeAdditivePose(Skeleton& skeleton, Clip& clip) {
    Pose result = skeleton.GetRestPose();
    clip.Sample(result, clip.GetStartTime());
    return result;
}
```

附加混合的公式为*结果姿势* = *输入姿势* + (*附加姿势 - 附加基础姿势*)。减去附加基础姿势只应用于动画的第一帧和当前帧之间的附加动画增量。因此，您只能对一个骨骼进行动画，比如脊柱骨骼之一，并实现使角色向左倾斜的效果。

要实现附加混合，需要循环遍历每个姿势的关节。与常规动画混合一样，需要考虑`blendroot`参数。使用每个关节的本地变换，按照提供的公式进行操作：

```cpp
void Add(Pose& output, Pose& inPose, Pose& addPose, 
         Pose& basePose, int blendroot) {
   unsigned int numJoints = addPose.Size();
   for (int i = 0; i < numJoints; ++i) {
      Transform input = inPose.GetLocalTransform(i);
      Transform additive = addPose.GetLocalTransform(i);
      Transform additiveBase=basePose.GetLocalTransform(i);
      if (blendroot >= 0 && 
          !IsInHierarchy(addPose, blendroot, i)) {
         continue;
       }
       // outPose = inPose + (addPose - basePose)
       Transform result(input.position + 
           (additive.position - additiveBase.position),
            normalized(input.rotation * 
           (inverse(additiveBase.rotation) * 
            additive.rotation)),
            input.scale + (additive.scale - 
            additiveBase.scale)
        );
        output.SetLocalTransform(i, result);
    }
}
```

重要信息

四元数没有减法运算符。要从四元数*A*中移除四元数*B*的旋转，需要将*B*乘以*A*的逆。四元数的逆应用相反的旋转，这就是为什么四元数乘以其逆的结果是单位。

附加动画通常用于创建新的动画变体，例如，将行走动画与蹲姿混合以创建蹲行动画。所有动画都可以与蹲姿进行附加混合，以在程序中创建动画的蹲姿版本。

# 总结

在本章中，您学会了如何混合多个动画。混合动画可以混合整个层次结构或只是一个子集。您还构建了一个系统，用于管理在播放新动画时动画之间的淡入淡出。我们还介绍了附加动画，可以在给定关节角度的情况下用于创建新的运动。

本章的可下载材料中包括四个示例。`Sample00`是本书到目前为止的所有代码。`Sample01`演示了如何使用`Blend`函数，通过定时器在行走和奔跑动画之间进行混合。`Sample02`演示了交叉淡入淡出控制器的使用，通过交叉淡入淡出到随机动画。`Sample03`演示了如何使用附加动画混合。

在下一章中，您将学习逆向运动学。逆向运动学允许您根据角色的末端位置来确定角色的肢体应该弯曲的方式。想象一下将角色的脚固定在不平整的地形上。


# 第十三章：实现逆运动学

**逆运动学**（**IK**）是解决一组关节应该如何定位以达到世界空间中指定点的过程。例如，您可以为角色指定一个触摸的点。通过使用 IK，您可以找出如何旋转角色的肩膀、肘部和手腕，使得角色的手指始终触摸特定点。

常用于 IK 的两种算法是 CCD 和 FABRIK。本章将涵盖这两种算法。通过本章结束时，您应该能够做到以下事情：

+   理解 CCD IK 的工作原理

+   实现 CCD 求解器

+   理解 FABRIK 的工作原理

+   实现 FABRIK 求解器

+   实现球和套约束

+   实现铰链约束

+   了解 IK 求解器在动画流水线中的位置和方式

# 创建 CCD 求解器

在本节中，您将学习并实现 CCD IK 算法。**CCD**代表**循环坐标下降**。该算法可用于以使链条上的最后一个关节尽可能接近触摸目标的方式来摆放一系列关节。您将能够使用 CCD 来创建需要使用目标点解决链条的肢体和其他 IK 系统。

CCD 有三个重要概念。首先是**目标**，即您试图触摸的空间点。接下来是**IK 链**，它是需要旋转以达到目标的所有关节的列表。最后是**末端执行器**，它是链条中的最后一个关节（需要触摸目标的关节）。

有了目标、链和末端执行器，CCD 算法的伪代码如下：

```cpp
// Loop through all joints in the chain in reverse, 
// starting with the joint before the end effecor
foreach joint in ikchain.reverse() {
    // Find a vector from current joint to end effector
    jointToEffector = effector.position - joint.position
    // Find a vector from the current joint to the goal
    jointToGoal = goal.position - joint.position
    // Rotate the joint so the joint to effector vector 
    // matches the orientation of the joint to goal vector
    joint.rotation = fromToRotation(jointToEffector, 
                        jointToGoal) * joint.rotation
}
```

CCD 算法看起来很简单，但它是如何工作的呢？从末端执行器前面的关节开始。旋转执行器对链条没有影响。找到从执行器前面的关节到目标的向量，然后找到从关节到执行器的向量。旋转相关的关节，使得这两个向量对齐。对每个关节重复此过程，直到基本关节为止。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.1_B16191.jpg)

图 13.1：CCD 算法的可视化

观察*图 13.1*，末端执行器没有触摸目标。为什么？CCD 是一个迭代算法，前面的步骤描述了一个迭代。需要多次迭代才能实现收敛。在接下来的章节中，我们将学习如何声明 CCD 求解器，这将引导我们实现`CCDSolver`类。

## 声明 CCD 求解器

在本节中，您将声明 CCD 求解器。这将让您有机会在实现之前，熟悉 API 并了解类在高层次上的工作方式。

创建一个新文件`CCDSolver.h`，`CCDSolver`类将在此文件中声明。`CCDSolver`类应包含组成 IK 链的变换向量。假设 IK 链具有父子关系，其中每个索引都是前一个索引的子级，使 0 成为我们的根节点。因此，IK 链中的每个变换都是在本地空间中声明的。按照以下步骤声明 CCD IK 求解器：

1.  首先声明`CCDSolver`类，包含三个变量：用于形成 IK 链的变换列表、要执行的迭代次数和可以用来控制目标与目标之间的距离的小增量。同时声明默认构造函数：

```cpp
class CCDSolver {
protected:
    std::vector<Transform> mIKChain;
    unsigned int mNumSteps;
    float mThreshold;
public:
    CCDSolver();
```

1.  为 IK 链的大小、步数和阈值值实现 getter 和 setter 函数。声明要使用的`[] operator`来获取和设置本地关节变换。声明`GetGlobalTransform`函数，它将返回关节的全局变换：

```cpp
    unsigned int Size();
    void Resize(unsigned int newSize);
    Transform& operator[](unsigned int index);
    Transform GetGlobalTransform(unsigned int index);
    unsigned int GetNumSteps();
    void SetNumSteps(unsigned int numSteps);
    float GetThreshold();
    void SetThreshold(float value);
```

1.  声明`Solve`函数，用于解决 IK 链。提供一个变换，但只使用变换的位置分量。如果链被解决，则`Solve`函数返回`true`，否则返回`false`：

```cpp
    bool Solve(const Transform& target);
};
```

`mNumSteps`变量用于确保求解器不会陷入无限循环。不能保证末端执行器会达到目标。限制迭代次数有助于避免潜在的无限循环。在接下来的部分，您将开始实现 CCD 求解器。

## 实现 CCD 求解器

创建一个名为`CCDSolver.cpp`的新文件，用于实现 CCD 求解器。按照以下步骤实现 CCD 求解器：

1.  定义默认构造函数，为步数和阈值赋值。使用小阈值，如`0.0001f`。默认步数为`15`：

```cpp
CCDSolver::CCDSolver() {
    mNumSteps = 15;
    mThreshold = 0.00001f;
}
```

1.  实现`Size`和`Resize`函数，控制 IK 链的大小，`[]运算符`包含链中每个关节的值：

```cpp
unsigned int CCDSolver::Size() {
    return mIKChain.size();
}
void CCDSolver::Resize(unsigned int newSize) {
    mIKChain.resize(newSize);
}
Transform& CCDSolver::operator[](unsigned int index) {
    return mIKChain[index];
}
```

1.  为求解器包含的步数和阈值实现获取器和设置器函数：

```cpp
unsigned int CCDSolver::GetNumSteps() {
    return mNumSteps;
}
void CCDSolver::SetNumSteps(unsigned int numSteps) {
    mNumSteps = numSteps;
}
float CCDSolver::GetThreshold() {
    return mThreshold;
}
void CCDSolver::SetThreshold(float value) {
    mThreshold = value;
}
```

1.  实现`GetGlobalTransform`函数，这可能看起来很熟悉。它将指定关节的变换与所有父关节的变换连接起来，并返回指定关节的全局变换：

```cpp
Transform CCDSolver::GetGlobalTransform(unsigned int x) {
    unsigned int size = (unsigned int)mIKChain.size();
    Transform world = mIKChain[x];
    for (int i = (int) x - 1; i >= 0; --i) {
        world = combine(mIKChain[i], world);
    }
    return world;
}
```

1.  通过确保链的大小有效并存储最后一个元素的索引和目标位置的向量来实现`Solve`函数：

```cpp
bool CCDSolver::Solve(const Transform& target) {
    unsigned int size = Size();
    if (size == 0) { return false; }
    unsigned int last = size - 1;
    float thresholdSq = mThreshold * mThreshold;
    vec3 goal = target.position;
```

1.  循环从`0`到`mNumSteps`，执行正确数量的迭代。在每次迭代中，获取末端执行器的位置，并检查它是否足够接近目标。如果足够接近，提前返回：

```cpp
    for (unsigned int i = 0; i < mNumSteps; ++i) {
        vec3 effector = GetGlobalTransform(last).position;
        if (lenSq(goal - effector) < thresholdSq) {
            return true;
        }
```

1.  在每次迭代中，循环遍历整个 IK 链。从`size - 2`开始迭代；因为`size - 1`是最后一个元素，旋转最后一个元素对任何骨骼都没有影响：

```cpp
        for (int j = (int)size - 2; j >= 0; --j) {
```

1.  对于 IK 链中的每个关节，获取关节的世界变换。找到从关节位置到末端执行器位置的向量。找到从当前关节位置到目标位置的另一个向量：

```cpp
            effector=GetGlobalTransform(last).position;
            Transform world = GetGlobalTransform(j);
            vec3 position = world.position;
            quat rotation = world.rotation;
            vec3 toEffector = effector - position;
            vec3 toGoal = goal - position;
```

1.  接下来，找到一个四元数，将位置到末端执行器的向量旋转到位置到目标向量。有一种特殊情况，指向末端执行器或目标的向量可能是零向量：

```cpp
            quat effectorToGoal;
            if (lenSq(toGoal) > 0.00001f) {
                effectorToGoal = fromTo(toEffector, 
                                        toGoal);
            }
```

1.  使用这个向量将关节旋转到世界空间中的正确方向。通过关节的上一个世界旋转的逆来旋转关节的世界空间方向，将四元数移回关节空间：

```cpp
            quat worldRotated =rotation * 
                               effectorToGoal;
            quat localRotate = worldRotated * 
                               inverse(rotation);
            mIKChain[j].rotation = localRotate * 
                               mIKChain[j].rotation;
```

1.  随着关节的移动，检查末端执行器在每次迭代中移动到目标的距离。如果足够接近，从函数中提前返回，返回值为`true`：

```cpp
            effector=GetGlobalTransform(last).position;
            if (lenSq(goal - effector) < thresholdSq) {
                return true;
            }
         }
    }
```

1.  如果未达到目标，则 IK 链无法解决，至少不是在指定的迭代次数内。简单地返回`false`以表示函数未能达到目标：

```cpp
    return false;
} // End CCDSolver::Solve function
```

这个 CCD 求解器可以用来解决具有一个起点和一个末端执行器的单链。然而，处理 IK 链的更高级方法是，一个单链可以有多个末端执行器。然而，由于额外的实现复杂性，这些方法要少得多。在下一节中，您将开始探索另一种 IK 算法，FABRIK。

# 创建一个 FABRIK 求解器

**FABRIK**（**前向和后向逆运动学**）具有更自然、类人的收敛性。与 CCD 一样，FABRIK 处理具有基础、末端执行器和要达到的目标的 IK 链。与 CCD 不同，FABRIK 处理的是位置，而不是旋转。FABRIK 算法更容易理解，因为它可以仅使用向量来实现。

在许多方面，FABRIK 可以被用作 CCD 的替代品。这两种算法解决了同样的问题，但它们采取了不同的方法来解决。FABRIK 倾向于更快地收敛，并且对于人形动画效果更好，因此您可能会将其用作角色肢体的求解器。

在处理人形角色绑定时，使用位置而不是旋转将无法很好地工作，因为需要通过旋转关节来进行动画。这可以通过向算法添加预处理和后处理步骤来解决。预处理步骤将把 IK 链中的所有变换转换为世界空间位置向量。后处理步骤将把这些向量转换为旋转数据。

FABRIK 算法有两个部分。首先，从末端执行器向基座进行反向迭代。在进行反向迭代时，将执行器移动到目标位置。接下来，移动每根骨骼，使它们相对于执行器保持不变；这将保持链的完整性。然后，将基座移回原始位置，并将每根骨骼相对于基座移动，以保持链的完整性。

在伪代码中，FABRIK 算法如下所示：

```cpp
void Iterate(const Transform& goal) {
    startPosition = chain[0]
    // Iterate backwards
    chain[size - 1] = goal.position;
    for (i = size - 2; i >= 0; --i) {
        current = chain[i]
        next = chain[i + 1]
        direction = normalize(current - next)
        offset = direction * length[i + 1]
        chain[i] = next + offset
    }
    // Iterate forwards
    chain[0] = startPosition
    for (i  = 1; i < size; ++i) {
        current = chain[i]
        prev = chain[i - 1]
        direction = normalize(current - prev)
        offset = direction * length[i]
        chain[i] = prev + offset
    }
}
```

要可视化 FABRIK，将末端执行器设置到目标位置。找到从末端执行器到最后一个关节的向量。将最后一个关节移动到沿着这个向量的位置，保持其与末端执行器的距离。对每个关节重复此操作，直到达到基座。这将使基座关节移出位置。

要进行正向迭代，将基座放回原来的位置。找到到下一个关节的向量。将下一个关节放在这个向量上，保持其与基座的距离。沿着整个链重复这个过程：

![图 13.2 可视化 FABRIK 算法](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.2_B16191.jpg)

图 13.2：可视化 FABRIK 算法

FABRIK 和 CCD 都会尝试解决 IK 链，但它们以不同的方式收敛到目标。CCD 倾向于卷曲，而 FABRIK 倾向于拉伸。FABRIK 通常为人形动画生成更自然的结果。在接下来的部分，您将开始声明`FABRIKSolver`类，然后实现该类。

## 声明 FABRIK 求解器

FABRIK 求解器将需要更多的内存来运行，因为它必须将本地关节变换转换为全局位置。该算法可以分解为几个步骤，所有这些步骤都可以作为受保护的辅助函数实现。

创建一个新文件，`FABRIKSolver.h`。这个文件将用于声明`FABRIKSolver`类。按照以下步骤声明`FABRIKSolver`类：

1.  首先声明`FABRIKSolver`类，该类需要跟踪 IK 链、最大步数和一些距离阈值。声明一个世界空间位置向量和一个关节长度向量。这些向量是必需的，因为 FABRIK 算法不考虑旋转：

```cpp
class FABRIKSolver {
protected:
    std::vector<Transform> mIKChain;
    unsigned int mNumSteps;
    float mThreshold;
    std::vector<vec3> mWorldChain;
    std::vector<float> mLengths;
```

1.  声明辅助函数，将 IK 链复制到世界位置向量中，进行正向迭代，进行反向迭代，并将最终的世界位置复制回 IK 链中：

```cpp
protected:
    void IKChainToWorld();
    void IterateForward(const vec3& goal);
    void IterateBackward(const vec3& base);
    void WorldToIKChain();
```

1.  声明默认构造函数，获取器和设置器函数用于链的大小、解决链所需的迭代次数以及末端关节需要与目标的距离的 epsilon 值：

```cpp
public:
    FABRIKSolver();
    unsigned int Size();
    void Resize(unsigned int newSize);
    unsigned int GetNumSteps();
    void SetNumSteps(unsigned int numSteps);
    float GetThreshold();
    void SetThreshold(float value);
```

1.  声明用于存储 IK 链中本地变换的获取器和设置器函数。声明一个函数来检索关节的全局变换。最后，声明`Solve`函数，当给定一个目标时解决 IK 链：

```cpp
    Transform GetLocalTransform(unsigned int index);
    void SetLocalTransform(unsigned int index, 
                           const Transform& t);
    Transform GetGlobalTransform(unsigned int index);
    bool Solve(const Transform& target);
};
```

FABRIK 算法的实现比 CCD 算法更复杂，但步骤更容易分解为函数。在接下来的部分，您将开始实现`FABRIKSolver`类的函数。

## 实现 FABRIK 求解器

FABRIK 算法基于世界空间位置。这意味着，每次迭代时，IK 链都需要将本地关节变换转换为世界位置并存储结果。解决链条后，世界位置向量需要转换回相对偏移并存储回 IK 链中。

创建一个新文件`FABRIKSolver.cpp`；`FABRIKSolver`类将在这个文件中实现。按照以下步骤实现`FABRIKSolver`类：

1.  实现`FABRIKSolver`类的构造函数。需要将步数和阈值设置为默认值：

```cpp
FABRIKSolver::FABRIKSolver() {
    mNumSteps = 15;
    mThreshold = 0.00001f;
}
```

1.  实现步数和阈值值的简单 getter 和 setter 函数：

```cpp
unsigned int FABRIKSolver::GetNumSteps() {
    return mNumSteps;
}
void FABRIKSolver::SetNumSteps(unsigned int numSteps) {
    mNumSteps = numSteps;
}
float FABRIKSolver::GetThreshold() {
    return mThreshold;
}
void FABRIKSolver::SetThreshold(float value) {
    mThreshold = value;
}
```

1.  实现链条大小的 getter 和 setter 函数。setter 函数需要设置链条的大小、世界链条和长度向量：

```cpp
unsigned int FABRIKSolver::Size() {
    return mIKChain.size();
}
void FABRIKSolver::Resize(unsigned int newSize) {
    mIKChain.resize(newSize);
    mWorldChain.resize(newSize);
    mLengths.resize(newSize);
}
```

1.  实现获取和设置 IK 链中元素的本地变换的方法：

```cpp
Transform FABRIKSolver::GetLocalTransform(
                        unsigned int index) {
    return mIKChain[index];
}
void FABRIKSolver::SetLocalTransform(unsigned int index,
                                   const Transform& t) {
    mIKChain[index] = t;
}
```

1.  实现获取函数以检索全局变换，并将所有变换连接到根：

```cpp
Transform FABRIKSolver::GetGlobalTransform(
                        unsigned int index) {
    unsigned int size = (unsigned int)mIKChain.size();
    Transform world = mIKChain[index];
    for (int i = (int)index - 1; i >= 0; --i) {
        world = combine(mIKChain[i], world);
    }
    return world;
}
```

1.  实现`IKChainToWorld`函数，将 IK 链复制到世界变换向量中并记录段长度。长度数组存储了关节与其父节点之间的距离。这意味着根关节将始终包含长度`0`。对于非根关节，索引`i`处的距离是关节`i`和`i-1`之间的距离：

```cpp
void FABRIKSolver::IKChainToWorld() {
    unsigned int size = Size();
    for (unsigned int i = 0; i < size; ++i) {
        Transform world = GetGlobalTransform(i);
        mWorldChain[i] = world.position;
        if (i >= 1) {
            vec3 prev = mWorldChain[i - 1];
            mLengths[i] = len(world.position - prev);
        }
    }
    if (size > 0) {
        mLengths[0] = 0.0f;
    }
}
```

1.  接下来实现`WorldToIKChain`函数，它将把世界位置 IK 链转换回本地空间变换。循环遍历所有关节。对于每个关节，找到当前关节和下一个关节的世界空间变换。缓存当前关节的世界空间位置和旋转：

```cpp
void FABRIKSolver::WorldToIKChain() {
    unsigned int size = Size();
    if (size == 0) { return; }
    for (unsigned int i = 0; i < size - 1; ++i) {
        Transform world = GetGlobalTransform(i);
        Transform next = GetGlobalTransform(i + 1);
        vec3 position = world.position;
        quat rotation = world.rotation;
```

1.  创建一个向量，指向当前关节到下一个关节的位置。这是当前节点和下一个节点之间的旋转：

```cpp
        vec3 toNext = next.position - position;
        toNext = inverse(rotation) * toNext;
```

1.  构造一个向量，指向下一个关节的世界空间 IK 链到当前位置的位置。这是当前节点和下一个节点之间的旋转：

```cpp
        vec3 toDesired = mWorldChain[i + 1] - position;
        toDesired = inverse(rotation) * toDesired;
```

1.  使用`fromTo`四元数函数将这两个向量对齐。将最终的增量旋转应用于当前关节的 IK 链旋转：

```cpp
        quat delta = fromTo(toNext, toDesired);
        mIKChain[i].rotation = delta * 
                               mIKChain[i].rotation;
    }
}
```

1.  接下来，实现`IterateBackward`函数，将链条中的最后一个元素设置为目标位置。这会打破 IK 链。使用存储的距离调整所有其他关节，以保持链条完整。执行此函数后，末端执行器始终位于目标位置，初始关节可能不再位于基底位置：

```cpp
void FABRIKSolver::IterateBackward(const vec3& goal) {
    int size = (int)Size();
    if (size > 0) {
        mWorldChain[size - 1] = goal;
    }
    for (int i = size - 2; i >= 0; --i) {
        vec3 direction = normalized(mWorldChain[i] - 
                                    mWorldChain[i + 1]);
        vec3 offset = direction * mLengths[i + 1];
        mWorldChain[i] = mWorldChain[i + 1] + offset;
    }
}
```

1.  实现`IterateForward`函数。此函数重新排列 IK 链，使第一个链接从链的原点开始。此函数需要将初始关节设置为基底，并迭代所有其他关节，调整它们以保持 IK 链完整。执行此函数后，如果链条可解并且迭代次数足够，末端执行器可能位于目标位置：

```cpp
void FABRIKSolver::IterateForward(const vec3& base) {
    unsigned int size = Size();
    if (size > 0) {
        mWorldChain[0] = base;
    }
    for (int i = 1; i < size; ++i) {
        vec3 direction = normalized(mWorldChain[i] - 
                                    mWorldChain[i - 1]);
        vec3 offset = direction * mLengths[i];
        mWorldChain[i] = mWorldChain[i - 1] + offset;
    }
}
```

1.  通过将 IK 链复制到世界位置向量并填充长度向量来开始实现`Solve`函数。可以使用`IKChainToWorld`辅助函数完成。缓存基础和目标位置：

```cpp
bool FABRIKSolver::Solve(const Transform& target) {
    unsigned int size = Size();
    if (size == 0) { return false; }
    unsigned int last = size - 1;
    float thresholdSq = mThreshold * mThreshold;

    IKChainToWorld();
    vec3 goal = target.position;
    vec3 base = mWorldChain[0];
```

1.  从`0`迭代到`mNumSteps`。对于每次迭代，检查目标和末端执行器是否足够接近以解决链条问题。如果足够接近，则使用`WorldToIKChain`辅助函数将世界位置复制回链条，并提前返回。如果它们不够接近，则通过调用`IterateBackward`和`IterateForward`方法进行迭代：

```cpp
    for (unsigned int i = 0; i < mNumSteps; ++i) {
        vec3 effector = mWorldChain[last];
        if (lenSq(goal - effector) < thresholdSq) {
            WorldToIKChain();
            return true;
        }
        IterateBackward(goal);
        IterateForward(base);
    }
```

1.  迭代循环后，无论求解器是否能够解决链条问题，都将世界位置向量复制回 IK 链。最后再次检查末端执行器是否已经达到目标，并返回适当的布尔值：

```cpp
    WorldToIKChain();
    vec3 effector = GetGlobalTransform(last).position;
    if (lenSq(goal - effector) < thresholdSq) {
        return true;
    }
    return false;
}
```

FABRIK 算法很受欢迎，因为它往往会快速收敛到最终目标，对于人形角色来说结果看起来不错，并且该算法易于实现。在下一节中，您将学习如何向 FABRIK 或 CCD 求解器添加约束。

# 实施约束

CCD 和 FABRIK 求解器都能产生良好的结果，但都不能产生可预测的结果。在本节中，您将学习约束是什么，IK 求解器约束可以应用在哪里，以及如何应用约束。这将让您构建更加逼真的 IK 求解器。

考虑一个应该代表腿的 IK 链。您希望确保每个关节的运动是可预测的，例如，膝盖可能不应该向前弯曲。

这就是约束有用的地方。膝盖关节是一个铰链；如果应用了铰链约束，腿的 IK 链看起来会更逼真。使用约束，您可以为 IK 链中的每个关节设置规则。

以下步骤将向您展示在 CCD 和 FABRIK 求解器中应用约束的位置：

1.  约束可以应用于 CCD 和 FABRIK 求解器，并且必须在每次迭代后应用。对于 CCD，这意味着在这里插入一小段代码：

```cpp
bool CCDSolver::Solve(const vec3& goal) {
    // Local variables and size check
    for (unsigned int i = 0; i < mNumSteps; ++i) {
        // Check if we've reached the goal
        for (int j = (int)size - 2; j >= 0; --j) {
           // Iteration logic
           // -> APPLY CONSTRAINTS HERE!
            effector = GetGlobalTransform(last).position;
            if (lenSq(goal - effector) < thresholdSq) {
                return true;
            }
         }
    }
    // Last goal check
}
```

1.  将约束应用于 FABRIK 求解器更加复杂。约束应用于每次迭代，并且 IK 链需要在每次迭代时在世界位置链和 IK 链之间转换。在将数据复制到变换链后，每次迭代都应用约束：

```cpp
bool FABRIKSolver::Solve(const vec3& goal) {
    // Local variables and size check
    IKChainToWorld();
    vec3 base = mWorldChain[0];
    for (unsigned int i = 0; i < mNumSteps; ++i) {
        // Check if we've reached the goal
        IterateBackward(goal);
        IterateForward(base);
        WorldToIKChain();//NEW, NEEDED FOR CONSTRAINTS
        // -> APPLY CONSTRAINTS HERE!
        IKChainToWorld();//NEW, NEEDED FOR CONSTRAINTS
    }
    // Last goal check
}
```

`Solve`函数是虚拟的原因是您可以将每个`IKChain`类扩展为特定类型的链，例如`LegIKChain`或`ArmIKChain`，并直接将约束代码添加到解决方法中。在接下来的几节中，您将探索常见类型的约束。

## 球和插座约束

球和插座关节的工作原理类似于肩关节。关节可以在所有三个轴上旋转，但有一个角度约束阻止它自由旋转。*图 13.3*显示了球和插座约束的外观：

![图 13.3 可视化的球和插座约束](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.3_B16191.jpg)

图 13.3：可视化的球和插座约束

要构建球和插座约束，您需要知道当前关节及其父关节的旋转。您可以从这些四元数构造前向矢量，并检查前向矢量的角度。如果角度大于提供的限制，需要调整旋转。

为了限制旋转，找到旋转轴。两个前向方向的叉乘垂直于两者；这是旋转轴。创建一个四元数，将角度限制沿着这个轴带入当前关节的局部空间，并将该四元数设置为关节的旋转：

```cpp
void ApplyBallSocketConstraint(int i, float limit) { 
    quat parentRot = i == 0 ? mOffset.rotation : 
                     GetWorldTransform(i - 1).rotation;
    quat thisRot = GetWorldTransform(i).rotation;
    vec3 parentDir = parentRot * vec3(0, 0, 1);
    vec3 thisDir = thisRot * vec3(0, 0, 1);
    float angle = ::angle(parentDir, thisDir);
    if (angle > limit * QUAT_DEG2RAD) {
        vec3 correction = cross(parentDir, thisDir);
        quat worldSpaceRotation = parentRot * 
            angleAxis(limit * QUAT_DEG2RAD, correction);
        mChain[i].rotation = worldSpaceRotation * 
                             inverse(parentRot);
    }
}
```

球和插座约束通常应用于角色的髋部或肩部关节。这些也往往是肢体 IK 链的根关节。在下一节中，您将探索另一种类型的约束，即铰链约束。

## 铰链约束

铰链约束类似于肘部或膝盖。它只允许在一个特定轴上旋转。*图 13.4*展示了铰链关节的外观： 

![图 13.4 可视化的铰链约束](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.4_B16191.jpg)

图 13.4：可视化的铰链约束

要实施铰链约束，您需要知道当前关节和父关节的世界空间旋转。将轴法线分别乘以旋转四元数，并找到两者之间的四元数；这是您需要旋转以约束关节到一个轴的量。将此旋转带回关节空间并应用旋转：

```cpp
void ApplyHingeSocketConstraint(int i, vec3 axis) { 
    Transform joint = GetWorldTransform(i);
    Transform parent = GetWorldTransform(i - 1);
    vec3 currentHinge = joint.rotation * axis;
    vec3 desiredHinge = parent.rotation * axis;
    mChain[i].rotation = mChain[i].rotation * 
                         fromToRotation(currentHinge, 
                                        desiredHinge);
}
```

铰链约束通常用于肘部或膝盖关节。在下一节中，您将探讨如何使用 IK 将角色的脚对齐到地面。

# 使用 IK 将角色的脚对齐到地面

在本节中，您将学习如何使用 IK 来修改动画，使其看起来更加正确。具体来说，您将学习如何使用 IK 在行走时阻止角色的脚穿过不平整的地面。

现在，您可以使用 CCD 或 FABRIK 来解决 IK 链，让我们探讨这些求解器如何使用。IK 的两个常见用途是定位手部或脚部。在本节中，您将探讨在角色行走时如何将角色的脚夹紧在地面上的方法。

解决脚部夹紧问题，可以检查脚的最后全局位置与当前全局位置是否相符。如果脚部运动在途中碰到任何东西，就将脚固定在地面上。即使最琐碎的解决方案也有边缘情况：如果上升运动距离太远会发生什么？在动画循环的哪个时刻可以在固定和非固定位置之间进行插值？

为了使实现更容易，本章的地面夹紧策略将保持简单。首先，检查脚部是否与其上方的任何东西发生碰撞，例如穿过地形。为此，从角色的臀部到脚踝投射一条射线。

如果射线击中了任何东西，击中点将成为腿部 IK 链的目标。如果射线没有击中任何东西，则角色脚踝的当前位置将成为腿部 IK 链的目标。接下来，进行相同的射线投射，但不要停在角色的脚踝处；继续向下。

如果这条射线击中了任何东西，击中点将成为未来的 IK 目标。如果射线没有击中任何东西，则将未来的 IK 目标设置为当前的 IK 目标。现在有两个目标，一个自由运动，一个固定在地面上。

如果使用当前目标，角色的脚可能会突然贴在地面上。如果使用未来目标，角色将无法行走——它只会在地面上拖着脚。相反，您必须通过某个值在两个目标之间进行插值。

插值值应该来自动画本身。当角色的脚着地时，应使用当前目标；当脚抬起时，应使用未来目标。当角色的脚被抬起或放下时，目标位置应该进行插值。

有了 IK 目标后，IK 求解器可以计算出如何弯曲角色的腿。一旦腿部关节处于世界空间中，我们就调整脚的位置，使其始终在地形上，采取与解决腿部相似的步骤。

在接下来的章节中，您将更详细地探讨这里描述的每个步骤。然而，有一个小问题。大部分需要的值都是特定于用于渲染的模型的；不同的角色将需要不同调整的值。

## 寻找脚的目标

从角色的臀部下方一点到脚踝下方一点向下投射一条射线。这条射线应该直直地向下，沿着脚踝的位置。然而，射线应该从哪里开始，脚踝下方应该走多远，这取决于模型的具体情况：

![图 13.5 射线投射以找到脚的目标](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.5_B16191.jpg)

图 13.5：射线投射以找到脚的目标

记录这条射线投射的结果，无论击中点有多远。这一点将被视为 IK 目标，始终被夹紧在地面上。检查射线是否击中了其起点和脚踝底部之间的任何东西。如果击中了，那将是脚踝的目标。如果没有击中，脚踝的目标将是脚踝的位置。

重要的是要记住，定位的是角色的脚踝，而不是脚底。因此，目标点需要上移脚踝到地面的距离：

![图 13.6 偏移以定位角色的脚踝](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.6_B16191.jpg)

图 13.6：偏移以定位角色的脚踝

这些脚部目标将控制 IK 系统如何覆盖动画。在行走时，如果脚部运动没有受到阻碍，IK 系统就不应该被注意到。在下一节中，您将学习如何控制脚部在动画和固定目标点之间的插值。

## 插值脚部目标

为了在当前和未来的 IK 目标之间进行插值，您需要了解当前播放的动画片段。具体来说，您需要知道腿处于什么阶段；它是着地的，被抬起的，悬停的，还是被放置的？编码这些信息的常见方法是使用标量曲线。

想法是创建两条标量曲线，一条用于左腿，一条用于右腿。这些曲线对应于当前步伐的幅度。例如，当左脚离开地面时，左曲线的值需要为 0。如果左脚着地，左曲线的值需要为 1。曲线看起来像这样：

![图 13.7 步行循环幅度表示为标量曲线](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.7_B16191.jpg)

图 13.7：步行循环幅度表示为标量曲线

根据当前的归一化播放时间对这些曲线进行采样。结果值将在 0 和 1 之间。使用这个 0 到 1 的值作为混合权重，将非 IK 调整的动画和 IK 调整的动画混合在一起。这条曲线通常是通过使用曲线编辑器进行手动编写的。该曲线是特定于当前播放的动画的。

在下一节中，您将探讨如何调整 IK 角色的垂直位置，以避免过度伸展肢体。

## 垂直角色定位

接下来，角色需要垂直定位，以便看起来好看。如果角色放得太高，它会以过度伸展的状态结束。太低，IK 系统会过度弯曲腿：

![图 13.8 IK 过度伸展与采样动画比较](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.8_B16191.jpg)

图 13.8：IK 过度伸展与采样动画比较

角色的定位是相对于建模时的情况。如果角色是在假定（0, 0, 0）是地面上的中心点进行建模的，您可以将其放在下方的表面上，并将其稍微陷入表面。

角色需要稍微陷入表面，以便 IK 系统能够进行一些工作并避免过度伸展。这带来了一个问题：角色的脚需要与哪个表面对齐？对齐位置可以来自碰撞/物理系统，或者在一个更简单的例子中，只是从角色正下方向下进行射线投射。

碰撞表面和视觉表面并不相同。考虑一个楼梯：碰撞几何通常是一个坡道。显示几何是看起来像实际楼梯的样子。在这种情况下，角色的位置应该是相对于碰撞几何的，但 IK 目标应该是相对于视觉几何定位的。

如果只有一个几何用于碰撞和视觉，该怎么办？在这种情况下，将角色放置在夹紧的 IK 目标之一，无论哪一个更低。这将确保地面始终可以到达，而不会过度伸展。

## IK 传递

现在是解决腿部 IK 链的时候了。在这之前，将动画姿势中的关节复制到 IK 求解器中。对于每条腿，将髋关节的全局变换复制到 IK 求解器的根部。将膝盖的局部变换复制到关节 1，将脚踝的局部变换复制到关节 2。然后，运行 IK 求解器。求解器将把角色的脚放在目标点上，并将其夹紧在地面上。

## 脚部对齐

在这一点上，夹紧的脚部动画是平滑的，脚部将不再在地面内部剪切。但是只有角色的腿看起来正确，而脚没有。看看角色在非平坦表面上的脚部-仍然有相当多的剪切发生：

![图 13.9：腿被夹紧到地面，但脚的方向错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.9_B16191.jpg)

图 13.9：腿被夹紧到地面，但脚的方向错误

为了解决这个问题，创建一个脚尖射线。脚尖射线将位于角色的踝关节处，并沿着角色的前向轴一定距离。这将确保脚尖目标始终朝前，即使在动画中脚尖指向下。调整脚尖射线的垂直位置，使其从膝盖上方射到脚尖以下一点的位置：

![图 13.10：即使脚尖朝下，也要向前投射偏移](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_13.10_B16191.jpg)

图 13.10：即使脚尖朝下，也要向前投射偏移

将脚尖定位类似于腿的定位。找到一个目标，即当前脚尖的位置，被夹紧到地面上。通过动画的当前归一化时间在夹紧到地面的目标和活动动画目标之间插值。

这个脚尖目标将用于旋转脚。找到从踝到当前脚尖位置的向量。找到从踝到目标脚尖位置的向量。创建一个在这两个向量之间旋转的四元数。用这个四元数旋转踝部。

在本节中，您学习了如何找到脚目标，在它们之间插值，并使用这些目标和 IK 系统将角色的脚对齐到地面。地面对齐只是 IK 求解器的用例之一。类似的系统可以用于手臂抓取物体或整个身体创建一个布娃娃系统。

# 摘要

在本章中，您实现了 CCD 和 FABRIK IK 求解器。这两个求解器都可以解决 IK 链，但它们的收敛方式不同。哪种算法更好很大程度上取决于上下文。

您还学习了如何使用约束来限制特定关节的运动范围。通过正确的约束，IK 系统修改当前动画，使其与环境互动。您探讨了如何在本章的脚着地部分实现这一点。

本书的可下载内容中，本章有 4 个样本。`Sample00` 包含到目前为止的代码。`Sample01` 演示了如何使用 CCD 求解器，`Sample02` 演示了如何使用 FABRIK 求解器。`Sample03` 演示了角色沿着路径行走时的脚夹和地面对齐。

在下一章中，您将学习如何使用双四元数进行蒙皮。当网格弯曲或旋转时，双四元数蒙皮比线性混合蒙皮更好地保持了网格的体积。

# 进一步阅读

除了 FABRIK 和 CCD，IK 链有时会用解析方法或雅可比矩阵来求解：

+   有关分析 IK 求解器的更多信息，请访问[此处](http://theorangeduck.com/page/simple-two-joint)。

+   完整的雅可比求解器实现在*游戏编程宝石 4*中有介绍。


# 第十四章：使用双四元数进行蒙皮

当前的蒙皮实现在皮肤权重之间线性混合，这称为**线性混合蒙皮（LBS）**或有时称为**线性皮肤混合**。线性混合皮肤不保持模型的体积，这会引入蒙皮伪影。可视化这种伪影的简单方法是将矩形的一端扭曲 180 度，如下面的屏幕截图所示：

![图 14.1：比较线性混合和双四元数蒙皮](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_14.1_B16191.jpg)

图 14.1：比较线性混合和双四元数蒙皮

线性皮肤混合的替代方法是**双四元数皮肤混合**。使用双四元数时，模型的体积得以保持。在本章中，您将实现双四元数网格蒙皮。在本章结束时，您应该能够使用双四元数对动画角色进行蒙皮。本章涵盖以下主题：

+   引入双四元数

+   实现双四元数

+   使用双四元数进行蒙皮

+   了解如何使用双四元数蒙皮

# 引入双四元数

双四元数将线性和旋转变换结合到一个变量中。这个单一变量可以进行插值、变换和连接。双四元数可以用两个四元数或八个浮点数表示。

双数就像复数一样。复数有实部和虚部，双数有实部和虚部。假设![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_001.png)是双重运算符，双数可以表示为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_002.png)，其中![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_003.png)和![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_004.png)。

双数的运算是作为虚数进行的，其中虚部和实部必须分别操作。例如，双四元数的加法可以表示为：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_005.png)

注意实部和虚部是独立添加的。

重要说明

如果您对双四元数背后更正式的数学感兴趣，请查看 Ben Kenwright 的*A Beginner's Guide to Dual-Quaternions*，[网址 https://cs.gmu.edu/~jmlien/teaching/cs451/uploads/Main/dual-quaternion](https://cs.gmu.edu/~jmlien/teaching/cs451/uploads/Main/dual-quaternion.pdf).pdf。

双四元数只是双数的扩展。实部和虚部由四元数代替标量值表示，大多数数学运算都是有效的。在下一节中，您将开始在代码中实现双四元数。

# 实现双四元数

在本节中，您将在代码中实现双四元数。在本节结束时，您将已经实现了一个双四元数结构，以及使用双四元数进行网格蒙皮所需的所有数学函数。

双四元数需要被实现为结构，类似于变换或矩阵。创建两个新文件，`DualQuaternion.h`和`DualQuaternion.cpp`。您将在这些文件中实现与双四元数相关的数学。

首先声明一个`DualQuaternion`结构。这个结构将允许您以两个四元数或八个数字的浮点数组的形式访问双四元数结构中的数据。构造函数应该将双四元数设置为单位。单位双四元数的实部是单位四元数，虚部是零四元数，如下面的代码块所示：

```cpp
struct DualQuaternion {
    union {
        struct {
            quat real;
            quat dual;
        };
        float v[8];
    };
    inline DualQuaternion() : real(0, 0, 0, 1), dual(0, 0, 0, 0) { }
    inline DualQuaternion(const quat& r, const quat& d) :
        real(r), dual(d) { }
};
```

双四元数的实部保存旋转数据，虚部保存位置数据。双四元数不处理缩放。在下一节中，您将声明并实现常见的双四元数操作，如加法和乘法。

在*实现双四元数操作*子节中，您将实现诸如加法、缩放、乘法和比较运算符之类的平凡双四元数运算符。在*测量、归一化和求逆双四元数*部分，您将学习如何为双四元数实现点积，如何测量双四元数以及如何求逆。在*转换变换和双四元数*部分，您将学习如何在`DualQuaternion`和`Transform`结构之间进行转换。最后，在*变换向量和点*部分，您将学习如何使用双四元数来变换向量和点，就像变换或矩阵一样。

## 实现双四元数操作

您需要定义一些数学运算符来处理双四元数。这些函数是加法、标量乘法、双四元数乘法和相等比较运算符。

通过乘法将两个双四元数组合在一起。与矩阵和四元数不同，双四元数从左到右相乘。按照以下步骤实现双四元数操作：

1.  在`DualQuaternion.h`中声明加法、标量乘法、双四元数乘法和相等比较运算符，就像这样：

```cpp
DualQuaternion operator+(const DualQuaternion &l, 
                         const DualQuaternion &r);
DualQuaternion operator*(const DualQuaternion &dq, 
                         float f);
// Multiplication order is left to right
// This is the OPPOSITE of matrices and quaternions
DualQuaternion operator*(const DualQuaternion &l, 
                         const DualQuaternion &r);
bool operator==(const DualQuaternion &l, 
                const DualQuaternion &r);
bool operator!=(const DualQuaternion &l, 
                const DualQuaternion &r);
```

1.  实现加法、标量乘法和比较函数。它们都是逐分量操作。分别在双四元数的实部和双部上执行逐分量操作，如下所示：

```cpp
DualQuaternion operator+(const DualQuaternion &l,
                        const DualQuaternion &r) {
   return DualQuaternion(l.real+r.real,l.dual+r.dual);
}
DualQuaternion operator*(const DualQuaternion &dq, 
                         float f) {
    return DualQuaternion(dq.real * f, dq.dual * f);
}
bool operator==(const DualQuaternion &l, 
                const DualQuaternion &r) {
    return l.real == r.real && l.dual == r.dual;
}
bool operator!=(const DualQuaternion &l, 
                const DualQuaternion &r) {
    return l.real != r.real || l.dual != r.dual;
}
```

1.  首先确保两个双四元数都归一化，然后开始实现双四元数乘法：

```cpp
// Remember, multiplication order is left to right. 
// This is the opposite of matrix and quaternion 
// multiplication order
DualQuaternion operator*(const DualQuaternion &l, const DualQuaternion &r) {
    DualQuaternion lhs = normalized(l);
    DualQuaternion rhs = normalized(r);
```

1.  将两个归一化四元数的实部合并在一起。双部更复杂，因为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_14_006.png)必须等于`0`。通过将两个四元数的双部和实部相乘并将结果相加来满足此要求，就像这样：

```cpp
    return DualQuaternion(lhs.real * rhs.real, 
                          lhs.real * rhs.dual + 
                          lhs.dual * rhs.real);
}
```

大多数情况下，常见的双四元数运算符是直观的，但是双四元数的乘法顺序与惯例相反，这使它们有点难以处理。在下一节中，您将了解双四元数的点积和正常实现。

## 测量、归一化和求逆双四元数

点积测量两个双四元数的相似程度。双四元数点积的规则与向量和四元数点积相同。点积的结果是一个标量值，具有以下属性：

+   如果双四元数指向相同方向，则为正。

+   如果双四元数指向相反方向，则为负。

+   如果双四元数垂直，则为零。

非单位双四元数可能会引入不需要的扭曲，这是由双四元数表示的变换引起的。要归一化双四元数，实部和双部都需要除以实部的长度。

归一化双四元数就像归一化常规四元数一样，主要操作在实部上。首先，找到双四元数的实部的长度，然后将实部和双部都除以长度。这将实部和双部都归一化为实部的长度。

由于点积只考虑方向，双四元数的虚部不会被使用。找到两个双四元数的实部的点积。双四元数`共轭`操作是四元数共轭的扩展，分别找到实部和双部的共轭。

按照以下步骤实现`点积`、`求逆`和`归一化`函数：

1.  在`DualQuaternion.h`中声明双四元数点积、共轭和归一化函数，如下所示：

```cpp
float dot(const DualQuaternion& l, 
          const DualQuaternion& r);
DualQuaternion conjugate(const DualQuaternion& dq);
DualQuaternion normalized(const DualQuaternion& dq);
void normalize(DualQuaternion& dq);
```

1.  通过找到两个双四元数的实部的四元数点积来实现点积，并返回它们的结果，就像这样：

```cpp
float dot(const DualQuaternion& l, 
          const DualQuaternion& r) {
    return dot(l.real, r.real);
}
```

1.  通过分别对实部和双部取四元数共轭来实现`conjugate`函数，如下所示：

```cpp
DualQuaternion conjugate(const DualQuaternion& dq) {
    return DualQuaternion(conjugate(dq.real), 
                          conjugate(dq.dual));
}
```

1.  通过找到实部的长度并将双部和实部都缩放为长度的倒数来实现`normalized`函数，如下所示：

```cpp
DualQuaternion normalized(const DualQuaternion& dq) {
    float magSq = dot(dq.real, dq.real);
    if (magSq  < 0.000001f) {
        return DualQuaternion();
    }
    float invMag = 1.0f / sqrtf(magSq);
    return DualQuaternion(dq.real * invMag, 
                          dq.dual * invMag);
}
```

1.  实现`normalize`函数。与`normalized`不同，`normalize`函数接受双四元数引用并就地对其进行规范化，如下所示：

```cpp
void normalize(DualQuaternion& dq) {
    float magSq = dot(dq.real, dq.real);
    if (magSq  < 0.000001f) {
        return;
    }
    float invMag = 1.0f / sqrtf(magSq);
    dq.real = dq.real * invMag;
    dq.dual = dq.dual * invMag;
}
```

如果双四元数随时间变化，由于浮点误差可能变得非规范化。如果双四元数的实部长度不是`1`，则需要对双四元数进行规范化。而不是检查长度是否等于一，这将涉及平方根运算，您应该检查平方长度是否为`1`，这样操作速度更快。在接下来的部分，您将学习如何在变换和双四元数之间转换。

## 转换变换和双四元数

双四元数包含与变换类似的数据，但没有缩放分量。可以在两者之间进行转换，但会丢失缩放。

将变换转换为双四元数时，双四元数的实部映射到变换的旋转。要计算双部分，从变换的平移向量创建一个纯四元数。然后，将这个纯四元数乘以变换的旋转。结果需要减半——除以二或乘以 0.5。

将双四元数转换为变换时，变换的旋转仍然映射到双四元数的实部。要找到位置，将双部乘以二并将结果与变换的旋转的倒数组合。这将产生一个纯四元数。这个纯四元数的向量部分就是新的位置。

按照以下步骤实现在`Transform`和`DualQuaternion`对象之间转换的代码：

1.  在`DualQuaternion.h`中声明函数，将双四元数转换为变换和将变换转换为双四元数，如下所示：

```cpp
DualQuaternion transformToDualQuat(const Transform& t);
Transform dualQuatToTransform(const DualQuaternion& dq);
```

1.  实现`transformToDualQuat`函数。生成的双四元数不需要被规范化。以下代码中可以看到这个过程：

```cpp
DualQuaternion transformToDualQuat(const Transform& t) {
    quat d(t.position.x, t.position.y, t.position.z, 0);
    quat qr = t.rotation;
    quat qd = qr * d * 0.5f;
    return DualQuaternion(qr, qd);
}
```

1.  实现`dualQuatToTransform`函数。假定输入的双四元数已经被规范化。以下代码中可以看到这个过程：

```cpp
Transform dualQuatToTransform(const DualQuaternion& dq){
    Transform result;
    result.rotation = dq.real;
    quat d = conjugate(dq.real) * (dq.dual * 2.0f);
    result.position = vec3(d.x, d.y, d.z);
    return result;
}
```

双四元数也可以转换为矩阵，反之亦然；然而，通常不使用该操作。双四元数用于替换蒙皮流程中的矩阵，因此矩阵转换并不是必要的。在接下来的部分，您将探讨双四元数如何转换向量或点。

## 变换向量和点

双四元数包含刚性变换数据。这意味着双四元数可以用于变换向量和点。要通过双四元数变换点，将双四元数分解为旋转和位置分量，然后以变换的方式变换向量，但不包括缩放。

按照以下步骤声明和实现使用双四元数对向量和点进行变换的`transform`函数：

1.  在`DualQuaternion.h`中声明`transformVector`和`transformPoint`函数，如下所示：

```cpp
vec3 transformVector(const DualQuaternion& dq, 
                     const vec3& v);
vec3 transformPoint(const DualQuaternion& dq, 
                    const vec3& v);
```

1.  通过双四元数旋转向量是微不足道的。由于双四元数的实部包含旋转，将向量乘以双四元数的实部，如下所示：

```cpp
vec3 transformVector(const DualQuaternion& dq, 
                     const vec3& v) {
    return dq.real * v;
}
```

1.  要通过双四元数变换点，将双四元数转换为旋转和平移分量。然后，将这些平移和旋转分量应用于向量：`旋转 * 向量 + 平移`。这个公式的工作方式与变换移动点的方式相同，但没有缩放分量。以下代码中可以看到这个过程：

```cpp
vec3 transformPoint(const DualQuaternion& dq, 
                    const vec3& v) {
    quat d = conjugate(dq.real) * (dq.dual * 2.0f);
    vec3 t = vec3(d.x, d.y, d.z);
    return dq.real * v + t;
}
```

现在可以使用双四元数类代替`Transform`类。双四元数可以按层次结构排列，并使用乘法进行组合，通过这些新函数，双四元数可以直接转换点或矢量。

在本节中，您在代码中实现了双四元数。您还实现了所有需要使用双四元数的函数。在下一节中，您将学习如何使用双四元数进行网格蒙皮。

# 使用双四元数进行蒙皮

在本节中，您将学习如何修改蒙皮算法，使其使用双四元数而不是矩阵。具体来说，您将用双四元数替换蒙皮矩阵，这将同时转换顶点位置和法线位置。

双四元数解决的问题是矩阵的线性混合，目前在顶点着色器中实现。具体来说，这是引入蒙皮伪影的代码段：

```cpp
mat4 skin;
skin  = (pose[joints.x] * invBindPose[joints.x]) * weights.x;
skin += (pose[joints.y] * invBindPose[joints.y]) * weights.y;
skin += (pose[joints.z] * invBindPose[joints.z]) * weights.z;
skin += (pose[joints.w] * invBindPose[joints.w]) * weights.w;
```

在动画流水线中有三个阶段，可以用双四元数替换矩阵。每个阶段都会产生相同的结果。应该实现双四元数的三个地方如下所示：

1.  在顶点着色器中将矩阵转换为双四元数。

1.  将当前姿势的矩阵转换为双四元数，然后将双四元数传递给顶点着色器。

1.  将当前姿势的每个变换转换为双四元数，然后累积世界变换为双四元数。

在本章中，您将实现第三个选项，并向`Pose`类添加`GetDualQuaternionPalette`函数。您还将为`Skeleton`类的`GetInvBindPose`函数添加一个重载。在接下来的部分中，您将开始修改`Skeleton`类以支持双四元数蒙皮动画。

## 修改姿势类

`Pose`类需要两个新函数——一个用于检索指定关节的世界双四元数（即`GetGlobalDualQuaternion`），另一个用于将姿势转换为双四元数调色板。按照以下步骤声明和实现这些函数：

1.  在`Pose.h`中的`Pose`类中添加`GetDualQuaternionPalette`和`GetGlobalDualQuaternion`函数的声明，如下所示：

```cpp
class Pose {
// Existing functions and interface
public: // NEW
void GetDualQuaternionPalette(vector<DualQuaternion>& o);
DualQuaternion GetGlobalDualQuaternion(unsigned int i); 
};
```

1.  实现`GetGlobalDualQuaternion`函数以返回关节的世界空间双四元数，如下所示：

```cpp
DualQuaternion Pose::GetGlobalDualQuaternion(
                        unsigned int index) {
    DualQuaternion result = transformToDualQuat(
                            mJoints[index]);
    for (int p = mParents[index]; p >= 0; 
         p = mParents[p]) {
        DualQuaternion parent = transformToDualQuat(
                                mJoints[p]);
        // Remember, multiplication is in reverse!
        result = result * parent;    
    }
    return result;
}
```

1.  实现`GetDualQuaternionPalette`函数，该函数应该循环遍历当前姿势中存储的所有关节，并将它们的世界空间双四元数存储在输出向量中，如下所示：

```cpp
void Pose::GetDualQuaternionPalette(
           vector<DualQuaternion>& out) {
    unsigned int size = Size();
    if (out.size() != size) {
        out.resize(size);
    }
    for (unsigned int i = 0; i < size; ++i) {
        out[i] = GetGlobalDualQuaternion(i);
    }
}
```

双四元数转换发生在关节本地空间中，因此您不需要向`Pose`类添加任何额外的数据，而是能够添加两个新函数。在下一节中，您将修改`Skeleton`类以提供双四元数的逆绑定姿势。

## 修改骨骼类

为了使用双四元数对网格进行蒙皮，网格的逆绑定姿势也需要用双四元数表示。在本节中，您将为`GetInvBindPose`函数添加一个重载，该函数将填充一个双四元数对象的引用。按照以下步骤实现新的`GetInvBindPose`函数：

1.  在`Skeleton`类中声明一个额外的`GetInvBindPose`函数，该函数将以双四元数向量的引用作为参数。当函数完成时，它将填充向量与逆绑定姿势双四元数。可以在以下片段中看到此代码：

```cpp
class Skeleton {
// Existing functions and interface
public: // GetInvBindPose is new
    void GetInvBindPose(vector<DualQuaternion>& pose);
};
```

1.  在`Skeleton.cpp`中重写`GetInvBindPose`函数。调整输入向量的大小与绑定姿势一样大。对于每个关节，获取关节的全局双四元数表示。最后，将每个世界空间双四元数的共轭存储在输出向量中。可以在以下片段中看到此代码：

```cpp
void Skeleton::GetInvBindPose(std::vector<DualQuaternion>& 
    outInvBndPose) {
    unsigned int size = mBindPose.Size();
    outInvBndPose.resize(size);
    for (unsigned int i = 0; i < size; ++i) {
        DualQuaternion world = 
             mBindPose.GetGlobalDualQuaternion(i);
        outInvBndPose[i] = conjugate(world);
    }
}
```

现在可以将骨骼的动画姿势和逆绑定姿势转换为双四元数数组。 但是，为了在着色器中使用这些双四元数，它们需要以某种方式传递到该着色器。 在下一节中，您将实现一个新的双四元数统一类型来执行此操作。

## 创建新的统一类型

为了将双四元数作为矩阵的替代品，需要一种方法将它们用作着色器统一变量。 双四元数可以被视为 2x4 矩阵，并且可以使用`glUniformMatrix2x4fv`函数进行设置。

使用`DualQuaternion`为`Uniform`类声明模板特化。 需要实现`Set`函数。 它应该使用`glUniformMatrix2x4fv`函数将双四元数数组上传为 2x4 矩阵。 实现新的`Set`函数，如下面的代码片段所示：

```cpp
template Uniform<DualQuaternion>;
template<>
void Uniform<DualQuaternion>::Set(unsigned int slot, 
                                  DualQuaternion* inputArray, 
                                  unsigned int arrayLength) {
    glUniformMatrix2x4fv(slot, arrayLength, 
                         false, inputArray[0].v);
}
```

由于`Set`函数是模板化的，因此不需要在头文件中声明； 它只是函数的专门实例。 在下一节中，您将探讨如何实现使用双四元数进行蒙皮的顶点着色器。

## 创建双四元数着色器

为了支持双四元数蒙皮，唯一剩下的事情就是实现顶点着色器。 新的顶点着色器将类似于其线性混合蒙皮对应物。 此着色器将不再具有用于矩阵调色板的两个`mat4`统一数组，而是具有用于双四元数的两个`mat2x4`统一数组。

着色器将不得不混合双四元数。 每当两个四元数（双四元数的实部）混合时，都有可能混合发生在错误的邻域，并且四元数以长方式插值。 在混合时需要牢记邻域。

按照以下步骤实现新的顶点着色器：

1.  开始声明着色器与`model`，`view`和`projection`统一变量，如下所示：

```cpp
#version 330 core
uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;
```

1.  声明顶点结构。 顶点的输入值如下：`position`，`normal`，纹理坐标，权重和关节影响。 每个顶点应该有最多四个权重和影响。 可以在以下代码片段中看到此代码：

```cpp
in vec3 position;
in vec3 normal;
in vec2 texCoord;
in vec4 weights;
in ivec4 joints;
```

1.  声明传递给片段着色器的输出值。 这些是顶点法线，世界空间中的片段位置和`uv`坐标，如下面的代码片段所示：

```cpp
out vec3 norm;
out vec3 fragPos;
out vec2 uv;
```

1.  声明蒙皮统一变量。 这些不再是`mat4`数组； 它们现在是`mat2x4`数组。 `mat2x4`有两列四行。 对`mat2x4`进行下标，索引`0`是双四元数的实部，索引`1`是双部。 代码可以在以下代码片段中看到：

```cpp
uniform mat2x4 pose[120];
uniform mat2x4 invBindPose[120];
```

1.  实现四元数乘法函数。 这个函数的代码与*第四章*中创建的代码相同，可以在以下代码片段中看到：

```cpp
vec4 mulQ(vec4 Q1, vec4 Q2) {
    return vec4(
        Q2.x*Q1.w + Q2.y*Q1.z - Q2.z*Q1.y + Q2.w*Q1.x,
       -Q2.x*Q1.z + Q2.y*Q1.w + Q2.z*Q1.x + Q2.w*Q1.y,
        Q2.x*Q1.y - Q2.y*Q1.x + Q2.z*Q1.w + Q2.w*Q1.z,
       -Q2.x*Q1.x - Q2.y*Q1.y - Q2.z*Q1.z + Q2.w*Q1.w
    );
}
```

1.  实现`normalize`双四元数函数。 通过将其实部和双部分都除以实部的大小来规范化双四元数。 代码可以在以下代码片段中看到：

```cpp
mat2x4 normalizeDq(mat2x4 dq) {
    float invMag = 1.0 / length(dq[0]);
    dq[0] *= invMag;
    dq[1] *= invMag;
    return dq;
}
```

1.  实现双四元数乘法函数以组合双四元数，如下所示：

```cpp
mat2x4 combineDq(mat2x4 l, mat2x4 r) {
    l = normalizeDq(l);
    r = normalizeDq(r);
    vec4 real = mulQ(l[0], r[0]);
    vec4 dual = mulQ(l[0], r[1]) + mulQ(l[1], r[0]);
    return mat2x4(real, dual);
}
```

1.  实现一个通过双四元数变换向量的函数，如下所示：

```cpp
vec4 transformVector(mat2x4 dq, vec3 v) {
  vec4 real = dq[0];
  vec3 r_vector = real.xyz;
  float r_scalar = real.w;

  vec3 rotated = r_vector * 2.0f * dot(r_vector, v) +
   v * (r_scalar * r_scalar - dot(r_vector, r_vector))+
   cross(r_vector, v) * 2.0f * r_scalar;
  return vec4(rotated, 0);
}
```

1.  实现一个通过双四元数变换点的函数，如下所示：

```cpp
vec4 transformPoint(mat2x4 dq, vec3 v) {
    vec4 real = dq[0];
    vec4 dual = dq[1];
    vec3 rotated = transformVector(dq, v).xyz;
    vec4 conjugate = vec4(-real.xyz, real.w);
    vec3 t = mulQ(conjugate, dual * 2.0).xyz;

    return vec4(rotated + t, 1);
}
```

1.  实现顶点着色器的主要方法。 通过将关节 1、2 和 3（`joints.y`，`joints.z`，`joints.w`）邻近到关节 0（`joints.x`）来开始实现：

```cpp
void main() {
    vec4 w = weights;
    // Neighborhood all of the quaternions correctly
    if (dot(pose[joints.x][0], pose[joints.y][0]) < 0.0)
       { w.y *= -1.0; }
    if (dot(pose[joints.x][0], pose[joints.z][0]) < 0.0)
       { w.z *= -1.0; }
    if (dot(pose[joints.x][0], pose[joints.w][0]) < 0.0)
       { w.w *= -1.0; }
```

1.  将每个关节的世界空间双四元数与相同关节的逆绑定姿势双四元数相结合。 记住：双四元数乘法是从左到右的。 将每次乘法的结果存储在一个新变量中。 代码可以在以下代码片段中看到：

```cpp
    // Combine
    mat2x4 dq0 = combineDq(invBindPose[joints.x], 
                           pose[joints.x]);
    mat2x4 dq1 = combineDq(invBindPose[joints.y], 
                           pose[joints.y]);
    mat2x4 dq2 = combineDq(invBindPose[joints.z], 
                           pose[joints.z]);
    mat2x4 dq3 = combineDq(invBindPose[joints.w], 
                           pose[joints.w]);
```

1.  将四个蒙皮双四元数混合在一起。使用双四元数标量乘法和双四元数加法实现混合。不要忘记对皮肤双四元数进行归一化。代码可以在以下片段中看到：

```cpp
    mat2x4 skinDq = w.x * dq0 + w.y * dq1 + 
                    w.z * dq2 + w.w * dq3;
    skinDq = normalizeDq(skinDq);
```

1.  使用`transformPoint`函数和皮肤双四元数对顶点进行蒙皮。将结果的`vec4`通过正常的模型视图投影管线，如下所示：

```cpp
    vec4 v = transformPoint(skinDq, position);
    gl_Position = projection * view * model * v;
    fragPos = vec3(model * v);
```

1.  类似地转换法线。不要忘记将`uv`坐标传递给片段着色器。代码可以在以下片段中看到：

```cpp
    vec4 n = transformVector(skinDq, normal);
    norm = vec3(model * n);
    uv = texCoord;
}
```

任何涉及缩放的动画都无法使用这种方法。这种双四元数实现不支持缩放。可以在双四元数之上实现缩放支持，但涉及的工作量超过了其性能上的好处。

在本节中，您学习了如何使用双四元数实现蒙皮。这包括修改姿势数据和`Skeleton`类，创建新的统一变量，并构建新的着色器。在接下来的部分中，您将探讨如何使用迄今为止编写的双四元数代码。

# 了解如何使用双四元数蒙皮

本节将探讨如何将迄今为止编写的双四元数蒙皮代码应用于现有应用程序。此代码仅供参考；您无需跟随它。

使用双四元数蒙皮着色器非常简单；在运行时轻松切换蒙皮方法。以下步骤演示了如何使用双四元数着色器或线性蒙皮着色器来对同一模型进行动画化。

跟踪双四元数姿势调色板和反向绑定姿势调色板，以及线性混合姿势调色板和反向绑定姿势调色板。看一下以下代码：

```cpp
// For dual quaternion skinning
std::vector<DualQuaternion> mDqPosePalette;
std::vector<DualQuaternion> mDqInvBindPalette;
// For linear blend skinning
std::vector<mat4> mLbPosePalette;
std::vector<mat4> mLbInvBindPalette;
```

应用程序初始化时，将反向绑定姿势缓存为矩阵向量和双四元数向量，如下所示：

```cpp
mCurrentPose = mSkeleton.GetRestPose();
mCurrentPose.GetDualQuaternionPalette(mDqPosePalette);
mSkeleton.GetInvBindPose(mDqInvBindPalette);
mCurrentPose.GetMatrixPalette(mLbPosePalette);
mLbInvBindPalette = mSkeleton.GetInvBindPose();
```

在对动画进行采样时，将生成的姿势调色板转换为双四元数和线性混合版本，如下所示：

```cpp
mPlayTime = mClips[mClip].Sample(mCurrentPose, 
                                 mPlayTime + dt);
mCurrentPose.GetDualQuaternionPalette(mDqPosePalette);
mCurrentPose.GetMatrixPalette(mLbPosePalette);
```

在渲染动画时，请确保使用正确的统一变量，如下所示：

```cpp
if (mSkinningMethod == SkinningMethod::DualQuaternion) {
   Uniform<DualQuaternion>::Set(
           shader->GetUniform("pose"), mDqPosePalette);
   Uniform<DualQuaternion>::Set(
   shader->GetUniform("invBindPose"), mDqInvBindPalette);
}
else {
   Uniform<mat4>::Set(shader->GetUniform("pose"), 
                      mLbPosePalette);
   Uniform<mat4>::Set(shader->GetUniform("invBindPose"),
                      mLbInvBindPalette);
}
```

在此示例中，轻松切换线性混合蒙皮和双四元数蒙皮着色器只需更改`mSkinningMethod`变量的值。这是因为两种着色器之间唯一的区别是姿势调色板统一变量。

# 总结

在本章中，您学习了双四元数背后的数学知识，并实现了双四元数类。您发现了线性混合蒙皮可能产生的一些问题，并了解了如何使用双四元数来避免这些问题。本章中实现的双四元数蒙皮着色器可以用来替换线性混合蒙皮着色器。

如果您在本书的可下载材料中查看`Chapter14`，会发现有两个示例。`Sample00`包含到目前为止的所有代码。`Sample01`将相同的扭曲立方体模型渲染两次。第一个立方体使用线性混合蒙皮着色器进行渲染。第二个使用双四元数着色器进行渲染。

在下一章中，您将探讨如何使用索引绘制来对大型人群进行动画化。这很有趣，因为它涉及将姿势生成移动到**图形处理单元**（**GPU**）并在顶点着色器中执行整个蒙皮动画管线。


# 第十五章：渲染实例化人群

这最后一章探讨了如何使用实例化来渲染大型人群。人群渲染是一个有趣的话题，因为它将姿势生成（采样）和混合移动到了 GPU 上，使整个动画流水线在顶点着色器中运行。

将姿势生成移动到顶点着色器中，需要将动画信息编码到纹理中。本章的重点将是将动画数据编码到纹理中，并使用该纹理创建动画姿势。

没有实例化，绘制大量人群意味着需要进行大量的绘制调用，这将影响帧率。使用实例化，一个网格可以被多次绘制。如果只有一个绘制调用，人群中每个角色的动画姿势将需要不同的生成。

在本章中，您将探讨将动画采样移动到顶点着色器中以绘制大型人群。本章将涵盖以下主题：

+   在纹理中存储任意数据

+   从纹理中检索任意数据

+   将动画烘焙到纹理中

+   在顶点着色器中对动画纹理进行采样

+   优化人群系统

# 在纹理中存储数据

在 GPU 上进行动画采样并不是一件简单的事情。有很多循环和函数，这使得在 GPU 上进行动画采样成为一个困难的问题。解决这个问题的一种方法是简化它。

与实时采样动画不同，可以在设定的时间间隔内进行采样。在设定的时间间隔内对动画进行采样并将结果数据写入文件的过程称为烘焙。

动画数据烘焙后，着色器就不再需要采样实际的动画片段。相反，它可以根据时间查找最近的采样姿势。那么，这些动画数据烘焙到哪里呢？动画可以烘焙到纹理中。纹理可以用作数据缓冲区，并且已经有一种简单的方法在着色器中读取纹理数据。

通常，纹理中的存储类型和信息都是由着色器中的采样函数抽象出来的。例如，GLSL 中的`texture2D`函数以归一化的`uv`坐标作为参数，并返回一个四分量向量，其值范围从`0`到`1`。

但是纹理中的信息并不是这样的。当使用`glTexImage2D`创建纹理时，它需要一个内部纹理格式（`GL_RGBA`），一个源格式（通常再次是`GL_RGBA`）和一个数据类型（通常是`GL_UNSIGNED_BYTE`）。这些参数用于将底层数据类型转换为`texture2D`返回的归一化值。

在将任意数据存储在纹理中时，存在两个问题。第一个是数据的粒度。在`GL_RGBA`的情况下，每个采样的浮点分量只有 256 个唯一值。第二，如果需要存储的值不是归一化到`0`到`1`范围内的呢？

这就是浮点纹理的用武之地。您可以创建一个具有`GL_RGBA32F`格式的四分量浮点纹理。这个纹理会比其他纹理大得多，因为每个像素将存储四个完整的 32 位浮点数。

浮点纹理可以存储任意数据。在接下来的部分，您将学习如何从浮点纹理中检索任意数据。之后，您将探讨着色器如何从浮点纹理中读取数据。

# 从纹理中读取数据

本节探讨了如何在着色器中检索存储在纹理中的动画数据。在本节中，您将学习如何对纹理进行采样以及在采样纹理时应该使用哪些采样器状态。

一旦数据格式正确，对其进行采样就成为下一个挑战。`glTexImage2D`函数期望归一化的`uv`坐标并返回一个归一化值。另一方面，`texelFetch`函数可以用于使用像素坐标对纹理进行采样并返回这些坐标处的原始数据。

`texelFetch` glsl 接受三个参数：一个采样器，一个`ivec2`和一个整数。`ivec2`是被采样的像素的*x*和*y*坐标，以像素空间为单位。最后一个整数是要使用的 mip 级别，对于本章来说，将始终为`0`。

mipmap 是同一图像的逐渐降低分辨率版本的链。当 mip 级别缩小时，数据会丢失。这种数据丢失会改变动画的内容。避免为动画纹理生成 mip。

因为需要以与写出时完全相同的方式读取数据，任何插值也会破坏动画数据。确保使用最近邻采样来对动画纹理进行采样。

使用`texelFetch`而不是`glTexImage2D`来对纹理进行采样应该返回正确的数据。纹理可以在顶点着色器或片段着色器中进行采样。在下一节中，您将探索这些浮点纹理中应该存储什么动画数据。

# 编码动画数据

现在你知道如何读取和写入数据到纹理了，下一个问题是，纹理中需要写入什么数据？你将把动画数据编码到纹理中。每个动画片段将在设定的间隔内进行采样。所有这些样本的结果姿势将存储在纹理中。

为了编码这些数据，纹理的*x*轴将表示时间。纹理的*y*轴将表示正在进行动画的骨骼。每个骨骼将占用三行：一个用于位置，一个用于旋转，一个用于缩放。

动画片段将在设定的间隔内进行采样，以确保纹理的宽度有多少个样本。例如，对于一个*256x256*的动画纹理，动画片段将需要被采样 256 次。

在对动画片段进行采样以将其编码到纹理中时，对于每个样本，您将找到每个骨骼的世界空间变换并将其写入纹理。*y*坐标将是`joint_index * 3 + component`，其中有效的组件是`position = 0`，`rotation = 1`和`scale = 3`。

一旦这些值被写入纹理，就将纹理上传到 GPU 并使用它。在下一节中，您将探索着色器如何评估这个动画纹理。

# 探索每个实例数据

在渲染大量人群时，人群中的每个演员都有特定的属性。在本节中，您将探索每个实例数据是什么，以及如何将其传递给着色器。这将大大减少每帧上传到 GPU 的统一数组的数据量。

将蒙皮管道移动到顶点着色器并不能完全消除需要将与人群相关的统一数据传递给着色器。人群中的每个演员都需要一些数据上传到 GPU。每个实例数据比使用姿势调色板矩阵上传的数据要小得多。

人群中的每个演员都需要位置、旋转和缩放来构建模型矩阵。演员需要知道当前帧进行采样以及当前帧和下一帧之间的时间来进行混合。

每个演员实例数据的总大小是 11 个浮点数和 2 个整数。每个实例只有 52 个字节。每个实例数据将始终使用统一数组传递。数组的大小是人群包含的演员数量。数组的每个元素代表一个独特的演员。

着色器将负责从每个实例数据和动画纹理构建适当的矩阵。当前帧和下一帧之间的混合是可选的；混合可能不会 100%正确，但它应该看起来还不错。

在下一节中，您将实现一个`AnimationTexture`类，它将让您在代码中使用动画纹理。

# 创建动画纹理

在这一节中，您将实现所有需要在`AnimTexture`类中使用浮点纹理的代码。每个`AnimTexture`对象将包含一个 32 位浮点 RGBA 纹理。这些数据将有两份：一份在 CPU 上，一份上传到 GPU 上。

CPU 缓冲区保留下来，以便在保存到磁盘之前或上传到 OpenGL 之前轻松修改纹理的内容。这样做可以简化 API，但会增加一些额外的内存。

没有标准的 32 位纹理格式，因此保存和写入磁盘将简单地将`AnimTexture`类的二进制内容转储到磁盘上。在下一节中，您将开始实现`AnimTexture`类。这个类将提供一个易于使用的接口，用于实现 32 位浮点纹理。

## 声明 AnimTexture 类

动画纹理被假定总是正方形的；宽度和高度不需要分别跟踪。使用单个大小变量应该足够了。`AnimTexture`类将始终在内存中同时拥有两份纹理，一份在 CPU 上，一份在 GPU 上。

创建一个名为`AnimTexture.h`的新文件，并在这个文件中声明`AnimTexture`类。按照以下步骤声明`AnimTexture`类：

1.  声明`AnimTexture`类。它有三个成员变量：一个浮点数组，一个纹理大小的整数，以及一个指向 OpenGL 纹理对象的句柄：

```cpp
class AnimTexture {
protected:
    float* mData;
    unsigned int mSize;
    unsigned int mHandle;
```

1.  声明`AnimTexture`具有默认构造函数、复制构造函数、赋值运算符和析构函数：

```cpp
public:
    AnimTexture();
    AnimTexture(const AnimTexture&);
    AnimTexture& operator=(const AnimTexture&);
    ~AnimTexture();
```

1.  声明函数，以便将`AnimTexture`保存到磁盘并再次加载：

```cpp
    void Load(const char* path);
    void Save(const char* path);
```

1.  声明一个函数，将数据从`mData`变量上传到 OpenGL 纹理：

```cpp
    void UploadTextureDataToGPU();
```

1.  声明`AnimTexture`包含的 CPU 端数据的 getter 和 setter 函数：

```cpp
    unsigned int Size();
    void Resize(unsigned int newSize);
    float* GetData();
```

1.  声明`GetTexel`，它接受*x*和*y*坐标并返回一个`vec4`，以及一个`SetTexel`函数来设置`vec3`或`quat`对象。这些函数将写入纹理的数据：

```cpp
    void SetTexel(unsigned int x, unsigned int y, 
                  const vec3& v);
    void SetTexel(unsigned int x, unsigned int y, 
                  const quat& q);
    vec4 GetTexel(unsigned int x, unsigned int y);
```

1.  声明绑定和解绑纹理以进行渲染的函数。这将与`Texture`类的`Set`和`Unset`函数的方式相同：

```cpp
   void Set(unsigned int uniform, unsigned int texture);
   void UnSet(unsigned int textureIndex);
   unsigned int GetHandle();
};
```

`AnimTexture`类是一种方便的处理浮点纹理的方式。`get`和`SetTexel`方法可以使用直观的 API 读取和写入纹理。在下一节中，您将开始实现`AnimTexture`类。

## 实现`AnimTexture`类

在这一节中，您将实现`AnimTexture`类，其中包含用于处理浮点纹理的 OpenGL 代码，并提供一个易于使用的 API。如果您想使用除了 OpenGL 之外的图形 API，那么这个类将需要使用该 API 进行重写。

当`AnimTexture`保存到磁盘时，整个`mData`数组将作为一个大的二进制块写入文件。这个大的纹理数据占用了相当多的内存；例如，一个*512x512*的纹理大约占用 4MB。纹理压缩不适用，因为动画数据需要精确。

`SetTexel`函数是我们将要写入动画纹理数据的主要方式。这些函数接受*x*和*y*坐标，以及`vec3`或四元数值。函数需要根据给定的*x*和*y*坐标找出`mData`数组中的正确索引，然后相应地设置像素值。

创建一个名为`AnimTexture.cpp`的新文件。在这个新文件中实现`AnimTexture`类。现在，按照以下步骤实现`AnimTexture`类：

1.  实现默认构造函数。它应该将数据和大小设置为零，并生成一个新的 OpenGL 着色器句柄：

```cpp
AnimTexture::AnimTexture() {
    mData = 0;
    mSize = 0;
    glGenTextures(1, &mHandle);
}
```

1.  实现复制构造函数。它应该做与默认构造函数相同的事情，并使用赋值运算符来复制实际的纹理数据：

```cpp
AnimTexture::AnimTexture(const AnimTexture& other) {
    mData = 0;
    mSize = 0;
    glGenTextures(1, &mHandle);
    *this = other;
}
```

1.  实现赋值运算符。它只需要复制 CPU 端的数据；OpenGL 句柄可以不变：

```cpp
AnimTexture& AnimTexture::operator=(
                          const AnimTexture& other) {
    if (this == &other) {
        return *this;
    }
    mSize = other.mSize;
    if (mData != 0) {
        delete[] mData;
    }
    mData = 0;
    if (mSize != 0) {
        mData = new float[mSize * mSize * 4];
        memcpy(mData, other.mData, 
            sizeof(float) * (mSize * mSize * 4));
    }
    return *this;
}
```

1.  实现`AnimTexture`类的析构函数。它应该删除内部浮点数组，并释放类所持有的 OpenGL 句柄：

```cpp
AnimTexture::~AnimTexture() {
    if (mData != 0) {
        delete[] mData;
    }
    glDeleteTextures(1, &mHandle);
}
```

1.  实现`Save`函数。它应该将`AnimTexture`的大小写入文件，并将`mData`的内容作为一个大的二进制块写入：

```cpp
void AnimTexture::Save(const char* path) {
    std::ofstream file;
    file.open(path, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        cout << "Couldn't open " << path << "\n";
    }
    file << mSize;
    if (mSize != 0) {
        file.write((char*)mData, 
             sizeof(float) * (mSize * mSize * 4));
    }
    file.close();
}
```

1.  实现`Load`函数，将序列化的动画数据加载回内存：

```cpp
void AnimTexture::Load(const char* path) {
    std::ifstream file;
    file.open(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        cout << "Couldn't open " << path << "\n";
    }
    file >> mSize;
    mData = new float[mSize * mSize * 4];
    file.read((char*)mData, 
         sizeof(float) * (mSize * mSize * 4));
    file.close();
    UploadTextureDataToGPU();
}
```

1.  实现`UploadDataToGPU`函数。它的实现方式与`Texture::Load`非常相似，但使用的是`GL_RGBA32F`而不是`GL_FLOAT`：

```cpp
void AnimTexture::UploadTextureDataToGPU() {
    glBindTexture(GL_TEXTURE_2D, mHandle);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA32F, mSize, 
                  mSize, 0, GL_RGBA, GL_FLOAT, mData);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, 
                    GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, 
                    GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, 
                    GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, 
                    GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);
}
```

1.  实现大小、OpenGL 句柄和浮点数据获取函数：

```cpp
unsigned int AnimTexture::Size() {
    return mSize;
}
unsigned int AnimTexture::GetHandle() {
    return mHandle;
}
float* AnimTexture::GetData() {
    return mData;
}
```

1.  实现`resize`函数，它应该设置`mData`数组的大小。这个函数的参数是动画纹理的宽度或高度：

```cpp
void AnimTexture::Resize(unsigned int newSize) {
    if (mData != 0) {
        delete[] mData;
    }
    mSize = newSize;
    mData = new float[mSize * mSize * 4];
}
```

1.  实现`Set`函数。它的工作方式类似于`Texture::Set`：

```cpp
void AnimTexture::Set(unsigned int uniformIndex, unsigned int textureIndex) {
    glActiveTexture(GL_TEXTURE0 + textureIndex);
    glBindTexture(GL_TEXTURE_2D, mHandle);
    glUniform1i(uniformIndex, textureIndex);
}
```

1.  实现`UnSet`函数。它的工作方式类似于`Texture::UnSet`：

```cpp
void AnimTexture::UnSet(unsigned int textureIndex) {
    glActiveTexture(GL_TEXTURE0 + textureIndex);
    glBindTexture(GL_TEXTURE_2D, 0);
    glActiveTexture(GL_TEXTURE0);
}
```

1.  实现`SetTexel`函数，它以矢量`3`作为参数。这个函数应该将像素的未使用的 A 分量设置为`0`：

```cpp
void AnimTexture::SetTexel(unsigned int x, 
                  unsigned int y, const vec3& v) {
    unsigned int index = (y * mSize * 4) + (x * 4);
    mData[index + 0] = v.x;
    mData[index + 1] = v.y;
    mData[index + 2] = v.z;
    mData[index + 3] = 0.0f;
}
```

1.  实现`SetTexel`函数，它以四元数作为参数：

```cpp
void AnimTexture::SetTexel(unsigned int x, 
                  unsigned int y, const quat& q) {
    unsigned int index = (y * mSize * 4) + (x * 4);
    mData[index + 0] = q.x;
    mData[index + 1] = q.y;
    mData[index + 2] = q.z;
    mData[index + 3] = q.w;
}
```

1.  实现`GetTexel`函数。这个函数将始终返回一个`vec4`，其中包含像素的每个分量：

```cpp
vec4 AnimTexture::GetTexel(unsigned int x, 
                           unsigned int y) {
    unsigned int index = (y * mSize * 4) + (x * 4);
    return vec4(
        mData[index + 0],
        mData[index + 1],
        mData[index + 2],
        mData[index + 3]
    );
}
```

在本节中，您学会了如何创建一个 32 位浮点纹理并管理其中的数据。`AnimTexture`类应该让您使用直观的 API 来处理浮点纹理，而不必担心任何 OpenGL 函数。在下一节中，您将创建一个函数，该函数将对动画剪辑进行采样，并将结果的动画数据写入纹理。

# 动画烘焙器

在本节中，您将学习如何将动画剪辑编码到动画纹理中。这个过程称为烘焙。

使用一个辅助函数实现纹理烘焙。这个`Bake`函数将在设定的间隔内对动画进行采样，并将每个采样的骨骼层次结构写入浮点纹理中。

对于参数，`Bake`函数需要一个骨架、一个动画剪辑，以及一个要写入的`AnimTexture`的引用。骨架很重要，因为它提供了静止姿势，这将用于动画剪辑中不存在的任何关节。骨架的每个关节都将被烘焙到纹理中。让我们开始吧：

1.  创建一个名为`AnimBaker.h`的新文件，并在其中添加`BakeAnimationToTexture`函数的声明：

```cpp
void BakeAnimationToTexture(Skeleton& skel, Clip& clip, 
                            AnimTexture& outTex);
```

1.  创建一个名为`AnimBaker.cpp`的新文件。开始在这个文件中实现`BakeAnimationToTexture`函数：

```cpp
void BakeAnimationToTexture(Skeleton& skel, Clip& clip, 
                            AnimTexture& tex) {
    Pose& bindPose = skel.GetBindPose();
```

1.  要将动画烘焙到纹理中，首先创建一个动画将被采样到的姿势。然后，循环遍历纹理的*x*维度，即时间：

```cpp
    Pose pose = bindPose;
    unsigned int texWidth = tex.Size();
    for (unsigned int x = 0; x < texWidth; ++x) {
```

1.  对于每次迭代，找到迭代器的归一化值（迭代器索引/（大小-1））。将归一化时间乘以剪辑的持续时间，然后加上剪辑的开始时间。在当前像素的这个时间点对剪辑进行采样：

```cpp
        float t = (float)x / (float)(texWidth - 1);
        float start = clip.GetStartTime();
        float time = start + clip.GetDuration() * t;
        clip.Sample(pose, time);
```

1.  一旦剪辑被采样，就循环遍历绑定姿势中的所有关节。找到当前关节的全局变换，并使用`SetTexel`将数据写入纹理：

```cpp
        for (unsigned int y = 0;y<pose.Size()*3;y+=3) {
           Transform node=pose.GetGlobalTransform(y/3);
           tex.SetTexel(x, y + 0, node.position);
           tex.SetTexel(x, y + 1, node.rotation);
           tex.SetTexel(x, y + 2, node.scale);
        }
```

1.  在`Bake`函数返回之前，调用提供的动画纹理上的`UploadTextureDataToGPU`函数。这将使纹理在被烘焙后立即可用：

```cpp
    } // End of x loop
    tex.UploadTextureDataToGPU();
}
```

在高层次上，动画纹理被用作时间轴，其中*x*轴是时间，*y*轴是该时间点上动画关节的变换。在下一节中，您将创建人群着色器。人群着色器使用`BakeAnimationToTexture`烘焙到纹理中的数据来采样动画的当前姿势。

# 创建人群着色器

要呈现一个群众，您需要创建一个新的着色器。群众着色器将具有投影和视图统一，但没有模型统一。这是因为所有演员都是用相同的投影和视图矩阵绘制的，但需要一个独特的模型矩阵。着色器将有三个统一数组：一个用于位置，一个用于旋转，一个用于比例，而不是模型矩阵。

将放入这些数组的值是一个实例索引-当前正在呈现的网格的索引。每个顶点都通过内置的`glsl`变量`gl_InstanceID`获得其网格实例的副本。每个顶点将使用位置、旋转和比例统一数组构造一个模型矩阵。

反向绑定姿势就像一个矩阵统一数组，具有常规的蒙皮，但动画姿势不是。要找到动画姿势，着色器将不得不对动画纹理进行采样。由于每个顶点被绑定到四个顶点，所以必须为每个顶点找到四次动画姿势。

创建一个名为`crowd.vert`的新文件。群众着色器将在此文件中实现。按照以下步骤实现群众着色器：

1.  通过定义两个常量来开始实现着色器：一个用于骨骼的最大数量，一个用于支持的实例的最大数量：

```cpp
#version 330 core
#define MAX_BONES 60
#define MAX_INSTANCES 80
```

1.  声明所有群众演员共享的制服。这包括视图和投影矩阵，反向绑定姿势调色板和动画纹理：

```cpp
uniform mat4 view;
uniform mat4 projection;
uniform mat4 invBindPose[MAX_BONES];
uniform sampler2D animTex;
```

1.  声明每个群众演员独有的统一。这包括演员的变换，当前和下一帧，以及混合时间：

```cpp
uniform vec3 model_pos[MAX_INSTANCES];
uniform vec4 model_rot[MAX_INSTANCES];
uniform vec3 model_scl[MAX_INSTANCES];
uniform ivec2 frames[MAX_INSTANCES];
uniform float time[MAX_INSTANCES];
```

1.  声明顶点结构。每个顶点的数据与任何蒙皮网格的数据相同：

```cpp
in vec3 position;
in vec3 normal;
in vec2 texCoord;
in vec4 weights;
in ivec4 joints;
```

1.  声明群众着色器的输出值：

```cpp
out vec3 norm;
out vec3 fragPos;
out vec2 uv;
```

1.  实现一个函数，该函数将一个向量和一个四元数相乘。这个函数将与您在[*第四章*]（B16191_04_Final_JC_ePub.xhtml#_idTextAnchor069）*实现四元数*中构建的`transformVector`函数具有相同的实现，只是它在着色器中运行：

```cpp
vec3 QMulV(vec4 q, vec3 v) {
    return q.xyz * 2.0f * dot(q.xyz, v) +
           v * (q.w * q.w - dot(q.xyz, q.xyz)) +
           cross(q.xyz, v) * 2.0f * q.w;
}
```

1.  实现`GetModel`函数。给定一个实例索引，该函数应该从动画纹理中采样并返回一个*4x4*变换矩阵：

```cpp
mat4 GetModel(int instance) {
    vec3 position = model_pos[instance];
    vec4 rotation = model_rot[instance];
    vec3 scale = model_scl[instance];
    vec3 xBasis = QMulV(rotation, vec3(scale.x, 0, 0));
    vec3 yBasis = QMulV(rotation, vec3(0, scale.y, 0));
    vec3 zBasis = QMulV(rotation, vec3(0, 0, scale.z));
    return mat4(
        xBasis.x, xBasis.y, xBasis.z, 0.0,
        yBasis.x, yBasis.y, yBasis.z, 0.0,
        zBasis.x, zBasis.y, zBasis.z, 0.0,
        position.x, position.y, position.z, 1.0
    );
}
```

1.  使用关节和实例实现`GetPose`函数，该函数应返回关节的动画世界矩阵。通过找到 x 和 y 位置来采样动画纹理开始实现：

```cpp
mat4 GetPose(int joint, int instance) {
    int x_now = frames[instance].x;
    int x_next = frames[instance].y;
    int y_pos = joint * 3;
```

1.  从动画纹理中采样当前帧的位置、旋转和比例：

```cpp
    vec4 pos0 = texelFetch(animTex, ivec2(x_now, 
                          (y_pos + 0)), 0);
    vec4 rot0 = texelFetch(animTex, ivec2(x_now, 
                          (y_pos + 1)), 0);
    vec4 scl0 = texelFetch(animTex, ivec2(x_now, 
                          (y_pos + 2)), 0);
```

1.  从动画纹理中采样下一帧的位置、旋转和比例：

```cpp
    vec4 pos1 = texelFetch(animTex, ivec2(x_next, 
                          (y_pos + 0)), 0);
    vec4 rot1 = texelFetch(animTex, ivec2(x_next, 
                          (y_pos + 1)), 0);
    vec4 scl1 = texelFetch(animTex, ivec2(x_next, 
                          (y_pos + 2)), 0);
```

1.  在两个帧之间进行插值：

```cpp
    if (dot(rot0, rot1) < 0.0) { rot1 *= -1.0; }
    vec4 position = mix(pos0, pos1, time[instance]);
    vec4 rotation = normalize(mix(rot0, 
                              rot1, time[instance]));
    vec4 scale = mix(scl0, scl1, time[instance]);
```

1.  使用插值的位置、旋转和比例返回一个 4x4 矩阵：

```cpp
    vec3 xBasis = QMulV(rotation, vec3(scale.x, 0, 0));
    vec3 yBasis = QMulV(rotation, vec3(0, scale.y, 0));
    vec3 zBasis = QMulV(rotation, vec3(0, 0, scale.z));
    return mat4(
        xBasis.x, xBasis.y, xBasis.z, 0.0,
        yBasis.x, yBasis.y, yBasis.z, 0.0,
        zBasis.x, zBasis.y, zBasis.z, 0.0,
        position.x, position.y, position.z, 1.0
    );
}
```

1.  通过找到着色器的主函数来实现着色器的主要功能，找到所有四个动画姿势矩阵，以及群众中当前演员的模型矩阵。使用`gl_InstanceID`来获取当前绘制的演员的 ID：

```cpp
void main() {
    mat4 pose0 = GetPose(joints.x, gl_InstanceID);
    mat4 pose1 = GetPose(joints.y, gl_InstanceID);
    mat4 pose2 = GetPose(joints.z, gl_InstanceID);
    mat4 pose3 = GetPose(joints.w, gl_InstanceID);
    mat4 model = GetModel(gl_InstanceID);
```

1.  通过找到顶点的`skin`矩阵来继续实现主函数：

```cpp
    mat4 skin = (pose0*invBindPose[joints.x])*weights.x;
    skin += (pose1 * invBindPose[joints.y]) * weights.y;
    skin += (pose2 * invBindPose[joints.z]) * weights.z;
    skin += (pose3 * invBindPose[joints.w]) * weights.w;
```

1.  通过将位置和法线通过蒙皮顶点的变换管道来完成实现主函数：

```cpp
    gl_Position = projection * view * model * 
                  skin * vec4(position, 1.0);
    fragPos = vec3(model * skin * vec4(position, 1.0));
    norm = vec3(model * skin * vec4(normal, 0.0f));
    uv = texCoord;
}
```

在本节中，您实现了群众着色器。这个顶点着色器使用动画纹理来构建正在呈现的每个顶点的动画姿势。它将蒙皮管道的姿势生成部分移动到了 GPU 上。该着色器旨在呈现实例化的网格；它使用`gl_InstanceID`来确定当前正在呈现的实例。

这个着色器是一个很好的起点，但总有改进的空间。该着色器目前使用了大量的统一索引。一些低端机器可能提供不了足够的统一。本章末尾将介绍几种优化策略。在下一节中，您将实现一个`Crowd`类来帮助管理 Crowd 着色器需要的所有数据。

# 创建 Crowd 实用程序类

在这一部分，您将构建`Crowd`类。这是一个实用类，可以使用易于使用的 API 渲染大量人群。`Crowd`类封装了人群的状态。

`Crowd`类必须维护类中每个演员的实例数据。为了适应这一点，您需要声明一个最大演员数量。然后，所有特定于演员的信息可以存储在结构数组中，其中索引是演员 ID。

特定于演员的数据包括演员的世界变换，以及与其动画播放相关的数据。动画数据是哪些帧正在插值，插值值，以及当前和下一帧的关键时间。

创建一个名为`Crowd.h`的新文件。`Crowd`类将在此文件中声明。按照以下步骤声明`Crowd`类：

1.  将人群演员的最大数量定义为`80`：

```cpp
#define CROWD_MAX_ACTORS 80
```

1.  通过为所有实例数据创建向量来声明`Crowd`类。这包括每个演员的变换、动画帧和时间的数据，以及帧插值信息：

```cpp
struct Crowd {
protected:
    std::vector<vec3> mPositions;
    std::vector<quat> mRotations;
    std::vector<vec3> mScales;
    std::vector<ivec2> mFrames;
    std::vector<float> mTimes;
    std::vector<float> mCurrentPlayTimes;
    std::vector<float> mNextPlayTimes;
```

1.  声明`AdjustTime`、`UpdatePlaybackTimes`、`UpdateFrameIndices`和`UpdateInterpolationTimes`函数。`AdjustTime`函数类似于`Clip::AdjustTimeToFitRange`；它确保给定时间是有效的：

```cpp
protected:
    float AdjustTime(float t, float start, 
                float end, bool looping);
    void UpdatePlaybackTimes(float dt, bool looping, 
                float start, float end);
    void UpdateFrameIndices(float start, 
                float duration, unsigned int texWidth);
    void UpdateInterpolationTimes(float start, 
                float duration, unsigned int texWidth);
```

1.  为人群的大小和每个演员的`Transform`属性声明 getter 和 setter 函数：

```cpp
public:
    unsigned int Size();
    void Resize(unsigned int size);
    Transform GetActor(unsigned int index);
    void SetActor(unsigned int index, 
                  const Transform& t);
```

1.  最后，声明`Update`和`SetUniforms`函数。这些函数将推进当前动画并更新每个实例的着色器 uniforms：

```cpp
    void Update(float deltaTime, Clip& mClip, 
                unsigned int texWidth);
    void SetUniforms(Shader* shader);
};
```

`Crowd`类为管理人群中每个演员的每个实例信息提供了直观的接口。在下一节中，您将开始实现`Crowd`类。

## 实现 Crowd 类

`Crowd`类为您提供了一种方便的方式来管理人群中的所有演员。这个类的大部分复杂性在于计算正确的播放信息。这项工作在`Update`函数中完成。`Update`函数使用三个辅助函数，即`UpdatePlaybackTimes`、`UpdateFrameIndices`和`UpdateInterpolateionTimes`来工作。

人群中每个演员的当前动画播放时间将存储在`mCurrentPlayTimes`向量中。`mNextPlayTimes`向量是动画的预计下一个时间，这允许两个采样帧进行插值。`UpdatePlaybackTimes`函数将更新这两个向量。

猜测下一帧的播放时间很重要，因为动画纹理的采样率是未知的。例如，如果动画以 240 FPS 编码，并以 60 FPS 播放，那么下一帧将相隔四个采样。

`mFrames`向量包含两个组件整数向量。第一个组件是当前动画帧的`u`纹理坐标。第二个组件是下一帧中将显示的动画帧的`v`纹理坐标。`v`纹理坐标是关节索引。

`UpdateFrameIndex`函数负责更新这个向量。要找到当前帧的*x*坐标，需要对帧时间进行归一化，然后将归一化的帧时间乘以纹理的大小。可以通过从开始时间减去帧时间并将结果除以剪辑的持续时间来归一化帧的时间。

着色器需要在当前动画姿势和下一个动画姿势之间进行插值。为此，它需要知道两个姿势帧之间的当前归一化时间。这存储在`mTimes`变量中。

`mTimes`变量由`UpdateInterpolationTimes`函数更新。该函数找到当前帧的持续时间，然后将播放时间相对于当前帧归一化到该持续时间。

要更新`Crowd`类，您必须按顺序调用`UpdatePlaybackTimes`、`UpdateFrameIndices`和`UpdateInterpolateionTimes`函数。完成后，`Crowd`类可以使用`SetUniforms`函数设置其 uniform 值。

创建一个名为`Crowd.cpp`的新文件。`Crowd`类将在此文件中实现。按照以下步骤实现`Crowd`类：

1.  实现大小的获取器和设置器函数。设置器函数需要设置`Crowd`类中包含的所有向量的`size`：

```cpp
unsigned int Crowd::Size() {
    return mCurrentPlayTimes.size();
}
void Crowd::Resize(unsigned int size) {
    if (size > CROWD_MAX_ACTORS) {
        size = CROWD_MAX_ACTORS;
    }
    mPositions.resize(size);
    mRotations.resize(size);
    mScales.resize(size, vec3(1, 1, 1));
    mFrames.resize(size);
    mTimes.resize(size);
    mCurrentPlayTimes.resize(size);
    mNextPlayTimes.resize(size);
}
```

1.  实现演员变换的获取器和设置器函数。位置、旋转和缩放保存在单独的向量中；演员的获取器和设置器函数隐藏了该实现，而是使用`Transform`对象：

```cpp
Transform Crowd::GetActor(unsigned int index) {
    return Transform(
        mPositions[index],
        mRotations[index],
        mScales[index] );
}
void Crowd::SetActor(unsigned int index, 
                     const Transform& t) {
    mPositions[index] = t.position;
    mRotations[index] = t.rotation;
    mScales[index] = t.scale;
}
```

1.  实现`AdjustTime`函数；它类似于`Clip::AdjustTimeToFitRange`函数：

```cpp
float Crowd::AdjustTime(float time, float start, 
                        float end, bool looping) {
    if (looping) {
        time = fmodf(time - start, end - start);
        if (time < 0.0f) {
            time += end - start;
        }
        time = time + start;
    }
    else {
        if (time < start) { time = start; }
        if (time > end) { time = end; }
    }
    return time;
}
```

1.  实现`UpdatePlaybackTimes`辅助函数。该函数将按照增量时间推进所有演员的播放时间：

```cpp
void Crowd::UpdatePlaybackTimes(float deltaTime, 
            bool looping, float start, float end) {
    unsigned int size = mCurrentPlayTimes.size();
    for (unsigned int i = 0; i < size; ++i) {
        float time = mCurrentPlayTimes[i] + deltaTime;
        mCurrentPlayTimes[i] = AdjustTime(time, start,
                                        end, looping);
        time = mCurrentPlayTimes[i] + deltaTime;
        mNextPlayTimes[i] = AdjustTime(time, start, 
                                      end, looping);
    }
}
```

1.  实现`UpdateFrameIndices`函数。该函数将当前播放时间转换为沿动画纹理*x*轴的像素坐标：

```cpp
void Crowd::UpdateFrameIndices(float start, float duration, unsigned int texWidth) {
    unsigned int size = mCurrentPlayTimes.size();
    for (unsigned int i = 0; i < size; ++i) {
        float thisNormalizedTime = 
             (mCurrentPlayTimes[i] - start) / duration;
        unsigned int thisFrame = 
             thisNormalizedTime * (texWidth - 1);
        float nextNormalizedTime = 
             (mNextPlayTimes[i] - start) / duration;
        unsigned int nextFrame = 
             nextNormalizedTime * (texWidth - 1);
        mFrames[i].x = thisFrame;
        mFrames[i].y = nextFrame;
    }
}
```

1.  实现`UpdateInterpolationTimes`函数。该函数应该找到当前和下一个动画帧之间的插值时间：

```cpp
void Crowd::UpdateInterpolationTimes(float start, 
          float duration, unsigned int texWidth) {
    unsigned int size =  mCurrentPlayTimes.size();
    for (unsigned int i = 0; i < size; ++i) {
        if (mFrames[i].x == mFrames[i].y) {
            mTimes[i] = 1.0f;
            continue;
        }
        float thisT = (float)mFrames[i].x / 
                      (float)(texWidth - 1);
        float thisTime = start + duration * thisT;
        float nextT = (float)mFrames[i].y / 
                      (float)(texWidth - 1);
        float nextTime = start + duration * nextT;
        if (nextTime < thisTime) {
            nextTime += duration;
        }
        float frameDuration = nextTime - thisTime;
        mTimes[i] = (mCurrentPlayTimes[i] - thisTime) /
                    frameDuration;
    }
}
```

1.  实现`Update`方法。该方法依赖于`UpdatePlaybackTimes`、`UpdateFrameIndices`和`UpdateInterpolationTimes`辅助函数：

```cpp
void Crowd::Update(float deltaTime, Clip& mClip, 
                        unsigned int texWidth) {
   bool looping = mClip.GetLooping();
   float start = mClip.GetStartTime();
   float end = mClip.GetEndTime();
   float duration = mClip.GetDuration();

   UpdatePlaybackTimes(deltaTime, looping, start, end);
   UpdateFrameIndices(start, duration, texWidth);
   UpdateInterpolationTimes(start, duration, texWidth);
}
```

1.  实现`SetUniforms`函数，将`Crowd`类中包含的向量传递给人群着色器作为 uniform 数组：

```cpp
void Crowd::SetUniforms(Shader* shader) {
    Uniform<vec3>::Set(shader->GetUniform("model_pos"),
                       mPositions);
    Uniform<quat>::Set(shader->GetUniform("model_rot"), 
                       mRotations);
    Uniform<vec3>::Set(shader->GetUniform("model_scl"), 
                       mScales);
    Uniform<ivec2>::Set(shader->GetUniform("frames"), 
                       mFrames);
    Uniform<float>::Set(shader->GetUniform("time"), 
                       mTimes);
}
```

使用`Crowd`类应该是直观的：创建一个人群，设置其演员的播放时间和模型变换，然后绘制人群。在下一节中，您将探讨如何使用`Crowd`类来绘制大型人群的示例。

## 使用 Crowd 类

使用`Crowd`类应该是直观的，但渲染代码可能不会立即显而易见。人群着色器的非实例 uniform，如视图或投影矩阵，仍然需要手动设置。`Crowd`类的`Set`函数设置的唯一 uniform 是每个演员的 uniform。

不要使用`Mesh`类的`Draw`方法进行渲染，而是使用`DrawInstanced`方法。对于实例数量参数，传递人群的大小。以下代码片段显示了如何绘制人群的最小示例：

```cpp
void Render(float aspect) {
    mat4 projection = perspective(60.0f, aspect, 0.01f, 100);
    mat4 view=lookAt(vec3(0,15,40), vec3(0,3,0), vec3(0,1,0));
    mCrowdShader->Bind();
    int viewUniform = mCrowdShader->GetUniform("view")
    Uniform<mat4>::Set(viewUniform, view);
    int projUniform = mCrowdShader->GetUniform("projection")
    Uniform<mat4>::Set(projUniform, projection);
    int lightUniform = mCrowdShader->GetUniform("light");
    Uniform<vec3>::Set(lightUniform, vec3(1, 1, 1));
    int invBind = mCrowdShader->GetUniform("invBindPose");
    Uniform<mat4>::Set(invBind, mSkeleton.GetInvBindPose());
    int texUniform = mCrowdShader->GetUniform("tex0");
    mDiffuseTexture->Set(texUniform, 0);
    int animTexUniform = mCrowdShader->GetUniform("animTex");
    mCrowdTexture->Set(animTexUniform, 1);
    mCrowd.SetUniforms(mCrowdShader);
    int pAttrib = mCrowdShader->GetAttribute("position");
    int nAttrib = mCrowdShader->GetAttribute("normal");
    int tAttrib = mCrowdShader->GetAttribute("texCoord");
    int wAttrib = mCrowdShader->GetAttribute("weights");
    int jAttrib = mCrowdShader->GetAttribute("joints");
    mMesh.Bind(pAttrib, nAttrib, uAttrib, wAttrib, jAttrib);
    mMesh.DrawInstanced(mCrowd.Size());
    mMesh.UnBind(pAttrib, nAttrib, uAttrib, wAttrib, jAttrib);
    mCrowdTexture->UnSet(1);
    mDiffuseTexture->UnSet(0);
    mCrowdShader->UnBind();
}
```

在大多数情况下，代码看起来与常规蒙皮网格相似。这是因为`Crowd`类的`SetUniforms`函数设置了特定实例的 uniform 值。其他 uniform 的设置方式与以前相同。在下一节中，您将探讨如何在顶点着色器中混合两个动画。

在本节中，您创建了一个`Crowd`类，它提供了一个易于使用的接口，以便您可以设置`Crowd`着色器所需的 uniform。还介绍了如何使用`Crowd`类来渲染大型人群的演示。

# 混合动画

在顶点着色器中可以在两个动画之间进行混合。有两个原因可能会导致你不希望在顶点着色器中进行动画混合。首先，这样做会使着色器的 texel 获取量翻倍，使着色器更加昂贵。

这种 texel 获取的激增发生是因为您必须检索姿势矩阵的两个副本 - 每个动画一个 - 然后在它们之间进行混合。执行此操作的着色器代码可能如下代码片段所示：

```cpp
    mat4 pose0a = GetPose(animTexA, joints.x, instance);
    mat4 pose1a = GetPose(animTexA, joints.y, instance);
    mat4 pose2a = GetPose(animTexA, joints.z, instance);
    mat4 pose3a = GetPose(animTexA, joints.w, instance);
    mat4 pose0b = GetPose(animTexB, joints.x, instance);
    mat4 pose1b = GetPose(animTexB, joints.y, instance);
    mat4 pose2b = GetPose(animTexB, joints.z, instance);
    mat4 pose3b = GetPose(animTexB, joints.w, instance);
    mat4 pose0 = pose0a * (1.0 - fade) + pose0b * fade;
    mat4 pose1 = pose1a * (1.0 - fade) + pose1b * fade;
    mat4 pose2 = pose2a * (1.0 - fade) + pose2b * fade;
    mat4 pose3 = pose3a * (1.0 - fade) + pose3b * fade;
```

另一个原因是混合在技术上不正确。着色器在世界空间中进行线性混合。结果混合的骨架看起来不错，但与在本地空间中进行插值的关节不同。

如果你在两个姿势之间进行淡入淡出，混合是短暂的，只是为了隐藏过渡。在大多数情况下，过渡是否在技术上正确并不像过渡看起来平滑那样重要。在下一节中，您将探索使用替代纹理格式。

# 探索纹理格式

动画纹理目前以 32 位浮点纹理格式存储。这是一种容易存储动画纹理的格式，因为它与源数据的格式相同。这种方法在移动硬件上效果不佳。从主内存到图块内存的内存带宽是一种稀缺资源。

为了针对移动平台，考虑从`GL_RGBA32F`更改为带有`GL_UNSIGNED_BYTE`存储类型的`GL_RGBA`。切换到标准纹理格式确实意味着丢失一些数据。使用`GL_UNSIGNED_BYTE`存储类型，颜色的每个分量都限制在 256 个唯一值。这些值在采样时被标准化，并将返回在 0 到 1 的范围内。

如果任何动画信息存储值不在 0 到 1 的范围内，数据将需要被标准化。标准化比例因子将需要作为统一传递给着色器。如果你的目标是移动硬件，你可能只想存储旋转信息，这些信息已经在 0 到 1 的范围内。

在下一节中，您将探索如何将多个动画纹理合并成单个纹理。这减少了需要绑定的纹理数量，以便人群播放多个动画。

# 合并动画纹理

将许多较小的纹理合并成一个较大的纹理的行为称为纹理合并。包含多个较小纹理的大纹理通常称为纹理图集。纹理合并的好处是需要使用较少的纹理采样器。

本章介绍的人群渲染系统有一个主要缺点：虽然人群可以以不同的时间偏移播放动画，但他们只能播放相同的动画。有一个简单的方法可以解决这个问题：将多个动画纹理合并到一个大纹理上。

例如，一个*1024x1024*的纹理可以包含 16 个较小的*256x256*纹理。这意味着人群中的任何成员都可以播放 16 种动画中的一种。着色器的每个实例数据都需要添加一个额外的“偏移”统一。这个偏移统一将是一个`MAX_INSTANCES`大小的数组。

对于每个被渲染的角色，`GetPose`函数在检索动画纹素之前必须应用偏移。在下一节中，您将探索不同的技术，可以使用这些技术来通过最小化纹素获取来优化人群着色器。

# 优化纹素获取

即使在游戏 PC 上，渲染超过 200 个人群角色将花费超过 4 毫秒的时间，这是一个相当长的时间，假设您有 16.6 毫秒的帧时间。那么，为什么人群渲染如此昂贵呢？

每次调用`GetPose`辅助函数时，着色器执行 6 个纹素获取。由于每个顶点都被蒙皮到四个影响，每个顶点需要 24 个纹素获取！即使是低多边形模型，这也是大量的纹素获取。优化这个着色器将归结为最小化纹素获取的数量。

以下部分介绍了您可以使用的不同策略，以最小化每个顶点的纹素获取数量。

## 限制影响

优化纹素获取的一种天真的方法是在着色器代码中添加一个分支。毕竟，如果矩阵的权重为 0，为什么要获取姿势呢？这种优化可以实现如下：

```cpp
    mat4 pose0 = (weights.x < 0.0001)? 
        mat4(1.0) : GetPose(joints.x, instance);
    mat4 pose1 = (weights.y < 0.0001)? 
        mat4(1.0) : GetPose(joints.y, instance);
    mat4 pose2 = (weights.z < 0.0001)? 
        mat4(1.0) : GetPose(joints.z, instance);
    mat4 pose3 = (weights.w < 0.0001)? 
        mat4(1.0) : GetPose(joints.w, instance);
```

在最理想的情况下，这可能会节省一点时间。在最坏的情况下（每个骨骼恰好有四个影响），这实际上会给着色器增加额外的成本，因为现在每个影响都带有一个条件分支。

限制纹理获取的更好方法是限制骨骼影响。Blender、3DS Max 或 Maya 等 3DCC 工具具有导出选项，可以限制每个顶点的最大骨骼影响数量。您应该将最大骨骼影响数量限制为 1 或 2。

通常，在人群中，很难看清个别演员的细节。因此，将骨骼影响降低到 1，有效地使人群的皮肤刚性化，通常是可行的。在接下来的部分，您将探讨如何通过限制动画组件的数量来帮助减少每个顶点的纹理获取次数。

## 限制动画组件

考虑一个动画的人类角色。人类关节只旋转；它们永远不会平移或缩放。如果您知道一个动画只对每个关节进行一到两个组件的动画，`GetPose`函数可以被编辑以采样更少的数据。

这里还有一个额外的好处：可以将编码到动画纹理中的骨骼数量增加。如果您编码位置、旋转和缩放，最大关节数为`纹理大小/3`。如果您只编码一个组件，可以编码的关节数就是纹理的大小。

这种优化将使*256x256*纹理能够编码 256 个旋转，而不是 85 个变换。在下一节中，您将探讨是否需要在帧之间进行插值。

## 不进行插值

考虑动画纹理。它以设定的增量对动画进行采样，以填充纹理的每一列。在 256 个样本中，您可以在 60 FPS 下编码 3.6 秒的动画。

是否需要插值将取决于动画纹理的大小和被编码的动画长度。对于大多数游戏角色动画，如奔跑、行走、攻击或死亡，不需要帧插值。

通过这种优化，发送到 GPU 的数据量大大减少。帧统一可以从`ivec2`变为`int`，将数据大小减半。这意味着时间统一可以完全消失。

在下一节中，您将探讨您刚刚学到的三种优化的综合效果。

## 结合这些优化

让我们探讨这些优化可能产生的影响，假设以下三种优化都已实施：

+   将骨骼影响的数量限制为 2。

+   只对变换的旋转组件进行动画。

+   不要在帧之间进行插值。

这将把每个顶点的纹理获取次数从 24 减少到 2。可以编码到动画纹理中的关节数量将增加，并且每帧传输到 GPU 的数据量将大大减少。

# 总结

在本章中，您学会了如何将动画数据编码到纹理中，以及如何在顶点着色器中解释数据。还介绍了通过改变动画数据编码方式来改善性能的几种策略。将数据写入纹理的这种技术可以用于烘焙任何类型的采样数据。

要烘焙动画，您需要将其剪辑到纹理中。这个剪辑是在设定的间隔内采样的。每个骨骼的全局位置在每个间隔都被记录并写入纹理。在这个动画纹理中，每个关节占据三行：一个用于位置，一个用于旋转，一个用于缩放。

您使用实例化渲染了人群网格，并创建了一个可以从统一数组中读取每个实例数据的着色器。人群演员的每个实例数据，如位置、旋转和缩放，都作为统一数组传递给着色器，并使用实例 ID 作为这些数组的索引进行解释。

最后，您创建了`Crowd`类。这个实用类提供了一个易于使用的界面，用于管理人群中的演员。这个类将自动填充人群着色器的每个实例统一。使用这个类，您可以轻松地创建大型、有趣的人群。

本书的可下载内容中有本章的两个示例。`Sample00`是本章中我们编写的所有代码。另一方面，`Sample01`演示了如何在实践中使用这些代码来渲染大规模人群。
