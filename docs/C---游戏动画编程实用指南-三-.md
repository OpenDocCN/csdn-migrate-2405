# C++ 游戏动画编程实用指南（三）

> 原文：[`annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b`](https://annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：实现动画片段

动画片段是`TransformTrack`对象的集合。动画片段在时间上对一组变换进行动画处理，被动画处理的变换集合称为姿势。将姿势视为动画角色在特定时间点的骨架。姿势是一组变换的层次结构。每个变换的值都会影响其所有子节点。

让我们来看看生成游戏角色动画一帧的姿势需要做些什么。当对动画片段进行采样时，结果是一个姿势。动画片段由动画轨道组成，每个动画轨道由一个或多个帧组成。这种关系看起来像这样：

![图 9.1：生成姿势的依赖关系。](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_9.1_B16191.jpg)

图 9.1：生成姿势的依赖关系

在本章结束时，您应该能够从 glTF 文件中加载动画片段，并将这些片段采样为姿势。

# 实现姿势

为了存储变换之间的父子层次关系，需要维护两个并行向量——一个填充有变换，另一个填充有整数。整数数组包含每个关节的父变换的索引。并非所有关节都有父节点；如果一个关节没有父节点，其父节点值为负数。

在考虑骨骼或姿势时，很容易想到一个具有一个根节点和许多分支节点的层次结构。实际上，拥有两个或三个根节点并不罕见。有时，文件格式以骨骼的第一个节点作为根节点，但也有一个所有蒙皮网格都是其子节点的根节点。这些层次结构通常看起来像这样：

![图 9.2：一个文件中的多个根节点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_9.2_B16191.jpg)

图 9.2：一个文件中的多个根节点

动画角色有三种常见的姿势——当前姿势、绑定姿势和静止姿势。静止姿势是所有骨骼的默认配置。动画描述了每个骨骼随时间的变换。在时间上对动画进行采样会得到当前姿势，用于对角色进行蒙皮。绑定姿势将在下一章中介绍。

并非所有动画都会影响角色的每根骨骼或关节；这意味着有些动画可能不会改变关节的值。请记住，在这种情况下，关节表示为`Transform`对象。如果动画`1`播放了，但动画**B**没有？以下列表显示了结果：

+   如果只播放**A**或**B**，一切都很好。

+   如果先播放**B**，然后播放**A**，一切都很好。

+   如果先播放**A**，然后播放**B**，情况会有点混乱。

在上一个示例中，播放动画`1`会保持其从动画`Pose`类中最后修改的变换。

## 声明 Pose 类

`Pose`类需要跟踪要动画的角色骨架中每个关节的变换。它还需要跟踪每个关节的父关节。这些数据保存在两个并行向量中。

在对新的动画片段进行采样之前，需要将当前角色的姿势重置为静止姿势。`Pose`类实现了复制构造函数和赋值运算符，以尽可能快地复制姿势。按照以下步骤声明`Pose`类：

1.  创建一个新的头文件`Pose.h`。在这个文件中添加`Pose`类的定义，从关节变换和它们的父节点的并行向量开始：

```cpp
class Pose {
protected:
    std::vector<Transform> mJoints;
    std::vector<int> mParents;
```

1.  添加默认构造函数和复制构造函数，并重载赋值运算符。`Pose`类还有一个方便的构造函数，它以关节数作为参数：

```cpp
public:
    Pose();
    Pose(const Pose& p);
    Pose& operator=(const Pose& p);
    Pose(unsigned int numJoints);
```

1.  为姿势的关节数添加获取器和设置器函数。当使用设置器函数时，需要调整`mJoints`和`mParents`向量的大小：

```cpp
    void Resize(unsigned int size);
    unsigned int Size();
```

1.  为关节的父级添加获取和设置函数。这两个函数都需要以关节的索引作为参数：

```cpp
    int GetParent(unsigned int index);
    void SetParent(unsigned int index, int parent);
```

1.  `Pose`类需要提供一种获取和设置关节的本地变换的方法，以及检索关节的全局变换。重载`[]运算符`以返回关节的全局变换：

```cpp
    Transform GetLocalTransform(unsigned int index);
    void SetLocalTransform(unsigned int index, 
                           const Transform& transform);
    Transform GetGlobalTransform(unsigned int index);
    Transform operator[](unsigned int index);
```

1.  要将`Pose`类传递给 OpenGL，需要将其转换为矩阵的线性数组。`GetMatrixPalette`函数执行此转换。该函数接受矩阵向量的引用，并用姿势中每个关节的全局变换矩阵填充它：

```cpp
    void GetMatrixPalette(std::vector<mat4>& out);
```

1.  通过重载等式和不等式运算符完成`Pose`类的设置：

```cpp
    bool operator==(const Pose& other);
    bool operator!=(const Pose& other);
};
```

`Pose`类用于保存动画层次结构中每个骨骼的变换。将其视为动画中的一帧；`Pose`类表示给定时间的动画状态。在接下来的部分中，您将实现`Pose`类。

## 实现 Pose 类

创建一个新文件，`Pose.cpp`。您将在此文件中实现`Pose`类。采取以下步骤来实现`Pose`类：

1.  默认构造函数不必执行任何操作。复制构造函数调用赋值运算符。方便构造函数调用`Resize`方法：

```cpp
Pose::Pose() { }
Pose::Pose(unsigned int numJoints) {
    Resize(numJoints);
}
Pose::Pose(const Pose& p) {
    *this = p;
}
```

1.  赋值运算符需要尽快复制姿势。您需要确保姿势没有分配给自己。接下来，确保姿势具有正确数量的关节和父级。然后，进行内存复制以快速复制所有父级和姿势数据：

```cpp
Pose& Pose::operator=(const Pose& p) {
    if (&p == this) {
        return *this;
    }
    if (mParents.size() != p.mParents.size()) {
        mParents.resize(p.mParents.size());
    }
    if (mJoints.size() != p.mJoints.size()) {
        mJoints.resize(p.mJoints.size());
    }
    if (mParents.size() != 0) {
        memcpy(&mParents[0], &p.mParents[0], 
               sizeof(int) * mParents.size());
    }
    if (mJoints.size() != 0) {
        memcpy(&mJoints[0], &p.mJoints[0], 
               sizeof(Transform) * mJoints.size());
    }
    return *this;
}
```

1.  由于父级和关节向量是平行的，`Resize`函数需要设置两者的大小。`size`获取函数可以返回任一向量的大小：

```cpp
void Pose::Resize(unsigned int size) {
    mParents.resize(size);
    mJoints.resize(size);
}
unsigned int Pose::Size() {
    return mJoints.size();
}
```

1.  本地变换的获取和设置方法很简单：

```cpp
Transform Pose::GetLocalTransform(unsigned int index) {
    return mJoints[index];
}
void Pose::SetLocalTransform(unsigned int index, const Transform& transform) {
    mJoints[index] = transform;
}
```

1.  从当前变换开始，`GetGlobalTransform`方法需要将所有变换组合到父级链中，直到达到根骨骼。请记住，变换连接是从右到左进行的。重载的`[]运算符`应被视为`GetGlobalTransform`的别名：

```cpp
Transform Pose::GetGlobalTransform(unsigned int i) {
    Transform result = mJoints[i];
    for (int p = mParents[i]; p >= 0; p = mParents[p]) {
        result = combine(mJoints[p], result);
    }
    return result;
}
Transform Pose::operator[](unsigned int index) {
    return GetGlobalTransform(index);
}
```

1.  要将`Pose`类转换为矩阵的向量，请循环遍历姿势中的每个变换。对于每个变换，找到全局变换，将其转换为矩阵，并将结果存储在矩阵的向量中。此函数尚未经过优化；您将在以后的章节中对其进行优化：

```cpp
void Pose::GetMatrixPalette(std::vector<mat4>& out) {
    unsigned int size = Size();
    if (out.size() != size) {
        out.resize(size);
    }
    for (unsigned int i = 0; i < size; ++i) {
        Transform t = GetGlobalTransform(i);
        out[i] = transformToMat4(t);
    }
}
```

1.  父关节索引的获取和设置方法很简单：

```cpp
int Pose::GetParent(unsigned int index) {
    return mParents[index];
}
void Pose::SetParent(unsigned int index, int parent) {
    mParents[index] = parent;
}
```

1.  在比较两个姿势时，您需要确保两个姿势中的所有关节变换和父索引都是相同的：

```cpp
bool Pose::operator==(const Pose& other) {
    if (mJoints.size() != other.mJoints.size()) {
        return false;
    }
    if (mParents.size() != other.mParents.size()) {
        return false;
    }
    unsigned int size = (unsigned int)mJoints.size();
    for (unsigned int i = 0; i < size; ++i) {
        Transform thisLocal = mJoints[i];
        Transform otherLocal = other.mJoints[i];
        int thisParent = mParents[i];
        int otherParent = other.mParents[i];
        if (thisParent != otherParent) { return false; }
        if (thisLocal.position != otherLocal.position) {
        return false; }
        if (thisLocal.rotation != otherLocal.rotation {
        return false; }
        if (thisLocal.scale != otherLocal.scale { 
        return false; } 
    }
    return true;
}
bool Pose::operator!=(const Pose& other) {
    return !(*this == other);
}
```

一个动画角色通常会有多个活动姿势并不罕见。考虑一个角色同时奔跑和开枪的情况。很可能会播放两个动画——一个影响下半身的**run**动画，一个影响上半身的**shoot**动画。这些姿势混合在一起形成最终姿势，用于显示动画角色。这种动画混合在*第十二章*中有所涵盖，*动画之间的混合*。

在接下来的部分中，您将实现动画剪辑。动画剪辑包含姿势中所有动画关节的动画随时间的变化。`Clip`类用于对动画进行采样并生成用于显示的姿势。

# 实现剪辑

动画剪辑是动画轨道的集合；每个轨道描述了一个关节随时间的运动，所有轨道组合描述了动画模型随时间的运动。如果对动画剪辑进行采样，您将得到一个姿势，该姿势描述了动画剪辑中每个关节在指定时间的配置。

对于基本的剪辑类，您只需要一个`Clip`类的向量，该类还应该跟踪元数据，例如剪辑的名称，剪辑是否循环，以及有关剪辑的时间或持续时间的信息。

## 声明 Clip 类

`Clip`类需要维护一个变换轨迹的向量。这是剪辑包含的最重要的数据。除了轨迹之外，剪辑还有一个名称、开始时间和结束时间，剪辑应该知道它是否循环。

`Clip`类的循环属性可以转移到管道中更深的构造（例如动画组件或类似物）。但是，在实现基本的动画系统时，这是放置循环属性的好地方：

1.  创建一个新文件，`Clip.h`，并开始声明`Clip`类：

```cpp
class Clip {
protected:
    std::vector<TransformTrack> mTracks;
    std::string mName;
    float mStartTime;
    float mEndTime;
    bool mLooping;
```

1.  剪辑的采样方式与轨迹的采样方式相同。提供的采样时间可能超出剪辑的范围。为了处理这个问题，您需要实现一个辅助函数，调整提供的采样时间，使其在当前动画剪辑的范围内：

```cpp
protected:
    float AdjustTimeToFitRange(float inTime);
```

1.  `Clip`类需要一个默认构造函数来为其某些成员分配默认值。在这里，编译器生成的析构函数、复制构造函数和赋值运算符应该是可以的：

```cpp
public:
    Clip();
```

1.  `Clip`类应提供一种获取剪辑包含的关节数量以及特定轨迹索引的关节 ID 的方法。您还需要有一个基于剪辑中关节索引的关节 ID 设置器：

```cpp
    unsigned int GetIdAtIndex(unsigned int index);
    void SetIdAtIndex(unsigned int idx, unsigned int id);
    unsigned int Size();
```

1.  从剪辑中检索数据可以通过两种方式之一完成。`[]运算符`返回指定关节的变换轨迹。如果指定关节没有轨迹，则会创建一个并返回。`Sample`函数接受`Pose`引用和时间，并返回一个也是时间的`float`值。此函数在提供的时间内对动画剪辑进行采样，并将结果分配给`Pose`引用：

```cpp
    float Sample(Pose& outPose, float inTime);
    TransformTrack& operator[](unsigned int index);
```

1.  我们需要一个公共辅助函数来确定动画剪辑的开始和结束时间。`RecalculateDuration`函数循环遍历所有`TransformTrack`对象，并根据组成剪辑的轨迹设置动画剪辑的开始/结束时间。此函数旨在由从文件格式加载动画剪辑的代码调用。

```cpp
    void RecalculateDuration();
```

1.  最后，`Clip`类需要简单的 getter 和 setter 函数：

```cpp
    std::string& GetName();
    void SetName(const std::string& inNewName);
    float GetDuration();
    float GetStartTime();
    float GetEndTime();
    bool GetLooping();
    void SetLooping(bool inLooping);
};
```

此处实现的`Clip`类可用于对任何内容进行动画化；不要觉得自己受限于人类和类人动画。在接下来的部分，您将实现`Clip`类。

## 实现 Clip 类

创建一个新文件，`Clip.cpp`。您将在这个新文件中实现`Clip`类。按照以下步骤实现`Clip`类：

1.  默认构造函数需要为`Clip`类的成员分配一些默认值：

```cpp
Clip::Clip() {
    mName = "No name given";
    mStartTime = 0.0f;
    mEndTime = 0.0f;
    mLooping = true;
}
```

1.  要实现`Sample`函数，请确保剪辑有效，并且时间在剪辑范围内。然后，循环遍历所有轨迹。获取轨迹的关节 ID，对轨迹进行采样，并将采样值分配回`Pose`引用。如果变换的某个组件没有动画，将使用引用组件提供默认值。然后函数返回调整后的时间：

```cpp
float Clip::Sample(Pose& outPose, float time) {
    if (GetDuration() == 0.0f) {
        return 0.0f;
    }
    time= AdjustTimeToFitRange(time);
    unsigned int size = mTracks.size();
    for (unsigned int i = 0; i < size; ++i) {
        unsigned int j = mTracks[i].GetId(); // Joint
        Transform local = outPose.GetLocalTransform(j);
        Transform animated = mTracks[i].Sample(
                             local, time, mLooping);
        outPose.SetLocalTransform(j, animated);
    }
    return time;
}
```

1.  `AdjustTimeToFitRange`函数应该循环，其逻辑与您为模板化的`Track`类实现的`AdjustTimeToFitTrack`函数相同：

```cpp
float Clip::AdjustTimeToFitRange(float inTime) {
    if (mLooping) {
        float duration = mEndTime - mStartTime;
        if (duration <= 0) { 0.0f; }
        inTime = fmodf(inTime - mStartTime, 
                       mEndTime - mStartTime);
        if (inTime < 0.0f) {
            inTime += mEndTime - mStartTime;
        }
        inTime = inTime + mStartTime;
    }
    else {
        if (inTime < mStartTime) {
            inTime = mStartTime;
        }
        if (inTime > mEndTime) {
            inTime = mEndTime;
        }
    }
    return inTime;
}
```

1.  `RecalculateDuration`函数将`mStartTime`和`mEndTime`设置为`0`的默认值。接下来，这些函数循环遍历动画剪辑中的每个`TransformTrack`对象。如果轨迹有效，则检索轨迹的开始和结束时间。存储最小的开始时间和最大的结束时间。剪辑的开始时间可能不是`0`；可能有一个从任意时间点开始的剪辑：

```cpp
void Clip::RecalculateDuration() {
    mStartTime = 0.0f;
    mEndTime = 0.0f;
    bool startSet = false;
    bool endSet = false;
    unsigned int tracksSize = mTracks.size();
    for (unsigned int i = 0; i < tracksSize; ++i) {
        if (mTracks[i].IsValid()) {
            float startTime = mTracks[i].GetStartTime();
            float endTime = mTracks[i].GetEndTime();
            if (startTime < mStartTime || !startSet) {
                mStartTime = startTime;
                startSet = true;
            }
            if (endTime > mEndTime || !endSet) {
                mEndTime = endTime;
                endSet = true;
            }
        }
    }
}
```

1.  `[] operator`用于检索剪辑中特定关节的`TransformTrack`对象。此函数主要由从文件加载动画剪辑的任何代码使用。该函数通过所有轨道进行线性搜索，以查看它们中的任何一个是否针对指定的关节。如果找到符合条件的轨道，则返回对其的引用。如果找不到符合条件的轨道，则创建并返回一个新的：

```cpp
TransformTrack& Clip::operator[](unsigned int joint) {
    for (int i = 0, s = mTracks.size(); i < s; ++i) {
        if (mTracks[i].GetId() == joint) {
            return mTracks[i];
        }
    }
    mTracks.push_back(TransformTrack());
    mTracks[mTracks.size() - 1].SetId(joint);
    return mTracks[mTracks.size() - 1];
}
```

1.  `Clip`类的其余 getter 函数都很简单：

```cpp
std::string& Clip::GetName() {
    return mName;
}
unsigned int Clip::GetIdAtIndex(unsigned int index) {
    return mTracks[index].GetId();
}
unsigned int Clip::Size() {
    return (unsigned int)mTracks.size();
}
float Clip::GetDuration() {
    return mEndTime - mStartTime;
}
float Clip::GetStartTime() {
    return mStartTime;
}
float Clip::GetEndTime() {
    return mEndTime;
}
bool Clip::GetLooping() {
    return mLooping;
}
```

1.  同样，`Clip`类的其余 setter 函数都很简单：

```cpp
void Clip::SetName(const std::string& inNewName) {
    mName = inNewName;
}
void Clip::SetIdAtIndex(unsigned int index, unsigned int id) {
    return mTracks[index].SetId(id);
}
void Clip::SetLooping(bool inLooping) {
    mLooping = inLooping;
}
```

动画剪辑始终修改相同的关节。没有必要重新设置每帧采样到的姿势，使其成为绑定姿势。但是，当切换动画时，不能保证两个剪辑将对相同的轨道进行动画。最好在切换动画剪辑时重置每帧采样到的姿势，使其成为绑定姿势！

在接下来的部分中，您将学习如何从 glTF 文件中加载角色的静止姿势。静止姿势很重要；这是角色在没有动画时的姿势。

# glTF - 加载静止姿势

在本书中，我们将假设一个 glTF 文件只包含一个动画角色。可以安全地假设 glTF 文件的整个层次结构可以视为模型的骨架。这使得加载静止姿势变得容易，因为静止姿势成为其初始配置中的层次结构。

在加载静止姿势之前，您需要创建几个帮助函数。这些函数是 glTF 加载器的内部函数，不应在头文件中公开。在`GLTFLoader.cpp`中创建一个新的命名空间，并将其命名为`GLTFHelpers`。所有帮助函数都在此命名空间中创建。

按照以下步骤实现加载 glTF 文件中静止姿势所需的帮助函数：

1.  首先，实现一个帮助函数来获取`cgltf_node`的本地变换。节点可以将其变换存储为矩阵或单独的位置、旋转和缩放组件。如果节点将其变换存储为矩阵，请使用`mat4ToTransform`分解函数；否则，根据需要创建组件：

```cpp
// Inside the GLTFHelpers namespace
Transform GLTFHelpers::GetLocalTransform(cgltf_node& n){
    Transform result;
    if (n.has_matrix) {
        mat4 mat(&n.matrix[0]);
        result = mat4ToTransform(mat);
    }
    if (n.has_translation) {
        result.position = vec3(n.translation[0], 
             n.translation[1], n.translation[2]);
    }
    if (n.has_rotation) {
        result.rotation = quat(n.rotation[0], 
          n.rotation[1], n.rotation[2], n.rotation[3]);
    }
    if (n.has_scale) {
        result.scale = vec3(n.scale[0], n.scale[1], 
                            n.scale[2]);
    }
    return result;
}
```

1.  接下来，实现一个帮助函数，从数组中获取`cgltf_node`的索引。`GLTFNodeIndex`函数可以通过循环遍历`.gltf`文件中的所有节点来执行简单的线性查找，并返回您正在搜索的节点的索引。如果找不到索引，则返回`-1`以表示无效索引：

```cpp
// Inside the GLTFHelpers namespace
int GLTFHelpers::GetNodeIndex(cgltf_node* target, 
    cgltf_node* allNodes, unsigned int numNodes) {
    if (target == 0) {
        return -1;
    }
    for (unsigned int i = 0; i < numNodes; ++i) {
        if (target == &allNodes[i]) {
            return (int)i;
        }
    }
    return -1;
}
```

1.  有了这些帮助函数，加载静止姿势需要很少的工作。循环遍历当前 glTF 文件中的所有节点。对于每个节点，将本地变换分配给将返回的姿势。您可以使用`GetNodeIndex`帮助函数找到节点的父节点，如果节点没有父节点，则返回`-1`：

```cpp
Pose LoadRestPose(cgltf_data* data) {
    unsigned int boneCount = data->nodes_count;
    Pose result(boneCount);
    for (unsigned int i = 0; i < boneCount; ++i) {
        cgltf_node* node = &(data->nodes[i]);
        Transform transform = 
        GLTFHelpers::GetLocalTransform(data->nodes[i]);
        result.SetLocalTransform(i, transform);
        int parent = GLTFHelpers::GetNodeIndex(
                     node->parent, data->nodes, 
                     boneCount);
        result.SetParent(i, parent);
    }
    return result;
}
```

在接下来的部分中，您将学习如何从 glTF 文件中加载关节名称。这些关节名称按照静止姿势关节的顺序出现。了解关节名称可以帮助调试骨骼的外观。关节名称还可以用于通过其他方式而不是索引来检索关节。本书中构建的动画系统不支持按名称查找关节，只支持索引。

# glTF - 加载关节名称

在某个时候，您可能想要知道每个加载的关节分配的名称。这可以帮助更轻松地进行调试或构建工具。要加载与静止姿势中加载关节的顺序相同的每个关节的名称，请循环遍历关节并使用名称访问器。

在`GLTFLoader.cpp`中实现`LoadJointNames`函数。不要忘记将函数声明添加到`GLTFLoader.h`中：

```cpp
std::vector<std::string> LoadJointNames(cgltf_data* data) {
    unsigned int boneCount = (unsigned int)data->nodes_count;
    std::vector<std::string> result(boneCount, "Not Set");
    for (unsigned int i = 0; i < boneCount; ++i) {
        cgltf_node* node = &(data->nodes[i]);
        if (node->name == 0) {
            result[i] = "EMPTY NODE";
        }
        else {
            result[i] = node->name;
        }
    }
    return result;
}
```

关节名称对于调试非常有用。它们让您将关节的索引与名称关联起来，这样您就知道数据代表什么。在接下来的部分中，您将学习如何从 glTF 文件中加载动画剪辑。

# glTF - 加载动画剪辑

要在运行时生成姿势数据，您需要能够加载动画剪辑。与静止姿势一样，这需要一些辅助函数。

您需要实现的第一个辅助函数`GetScalarValues`读取`gltf`访问器的浮点值。这可以通过`cgltf_accessor_read_float`辅助函数完成。

下一个辅助函数`TrackFromChannel`承担了大部分的重活。它将 glTF 动画通道转换为`VectorTrack`或`QuaternionTrack`。glTF 动画通道的文档位于[`github.com/KhronosGroup/glTF-Tutorials/blob/master/gltfTutorial/gltfTutorial_007_Animations.md`](https://github.com/KhronosGroup/glTF-Tutorials/blob/master/gltfTutorial/gltfTutorial_007_Animations.md)。

`LoadAnimationClips`函数应返回剪辑对象的向量。这并不是最佳的做法；这样做是为了使加载 API 更易于使用。如果性能是一个问题，请考虑将结果向量作为引用传递。

按照以下步骤从 glTF 文件中加载动画：

1.  在`GLTFLoader.cpp`文件的`GLTFHelpers`命名空间中实现`GetScalarValues`辅助函数：

```cpp
// Inside the GLTFHelpers namespace
void GLTFHelpers::GetScalarValues( vector<float>& out, 
                  unsigned int compCount, 
                  const cgltf_accessor& inAccessor) {
    out.resize(inAccessor.count * compCount);
    for (cgltf_size i = 0; i < inAccessor.count; ++i) {
        cgltf_accessor_read_float(&inAccessor, i, 
                                  &out[i * compCount], 
                                  compCount);
    }
}
```

1.  在`GLTFLoader.cpp`中实现`TrackFromChannel`辅助函数。通过设置`Track`插值来开始函数的实现。为此，请确保轨迹的`Interpolation`类型与采样器的`cgltf_interpolation_type`类型匹配：

```cpp
// Inside the GLTFHelpers namespace
template<typename T, int N>
void GLTFHelpers::TrackFromChannel(Track<T, N>& result,
              const cgltf_animation_channel& channel) {
    cgltf_animation_sampler& sampler = *channel.sampler;
    Interpolation interpolation = 
                  Interpolation::Constant;
    if (sampler.interpolation ==
        cgltf_interpolation_type_linear) {
        interpolation = Interpolation::Linear;
    }
    else if (sampler.interpolation ==
             cgltf_interpolation_type_cubic_spline) {
        interpolation = Interpolation::Cubic;
    }
    bool isSamplerCubic = interpolation == 
                          Interpolation::Cubic;
    result.SetInterpolation(interpolation);
```

1.  采样器输入是动画时间轴的访问器。采样器输出是动画值的访问器。使用`GetScalarValues`将这些访问器转换为浮点数的线性数组。帧的数量等于采样器输入中的元素数量。每帧的组件数量（`vec3`或`quat`）等于值元素数量除以时间轴元素数量。调整轨迹的大小以存储所有帧：

```cpp
    std::vector<float> time; // times
    GetScalarValues(time, 1, *sampler.input);
    std::vector<float> val; // values
    GetScalarValues(val, N, *sampler.output);
    unsigned int numFrames = sampler.input->count; 
    unsigned int compCount = val.size() / time.size();
    result.Resize(numFrames);
```

1.  将`time`和`value`数组解析为帧结构，循环遍历采样器中的每一帧。对于每一帧，设置时间，然后读取输入切线、值，然后输出切线。如果采样器是立方的，则输入和输出切线是可用的；如果不是，则应默认为`0`。需要使用本地`offset`变量来处理立方轨迹，因为输入和输出切线的大小与组件的数量一样大：

```cpp
    for (unsigned int i = 0; i < numFrames; ++i) {
        int baseIndex = i * compCount;
        Frame<N>& frame = result[i];
        int offset = 0;
        frame.mTime = time[i];
        for (int comp = 0; comp < N; ++comp) {
            frame.mIn[comp] = isSamplerCubic ? 
                  val[baseIndex + offset++] : 0.0f;
        }
        for (int comp = 0; comp < N; ++comp) {
            frame.mValue[comp] = val[baseIndex + 
                                 offset++];
        }
        for (int comp = 0; comp < N; ++comp) {
            frame.mOut[comp] = isSamplerCubic ? 
                  val[baseIndex + offset++] : 0.0f;
        }
    }
} // End of TrackFromChannel function
```

1.  在`GLTFLoader.cpp`中实现`LoadAnimationClips`函数；不要忘记将该函数的声明添加到`GLTFLoader.h`中。循环遍历提供的`gltf_data`中的所有剪辑。对于每个剪辑，设置其名称。循环遍历剪辑中的所有通道，并找到当前通道影响的节点的索引：

```cpp
std::vector<Clip> LoadAnimationClips(cgltf_data* data) {
    unsigned int numClips = data->animations_count;
    unsigned int numNodes = data->nodes_count;
    std::vector<Clip> result;
    result.resize(numClips);
    for (unsigned int i = 0; i < numClips; ++i) {
        result[i].SetName(data->animations[i].name);
        unsigned int numChannels = 
                 data->animations[i].channels_count;
        for (unsigned int j = 0; j < numChannels; ++j){
            cgltf_animation_channel& channel = 
                      data->animations[i].channels[j];
            cgltf_node* target = channel.target_node;
            int nodeId = GLTFHelpers::GetNodeIndex(
                         target, data->nodes, numNodes);
```

1.  glTF 文件的每个通道都是一个动画轨迹。一些节点可能只会动画它们的位置，而其他节点可能会动画位置、旋转和缩放。检查解析的通道类型，并调用`TrackFromChannel`辅助函数将其转换为动画轨迹。`Track`类的`[]操作符`可以检索当前轨迹或创建一个新的轨迹。这意味着正在解析的节点的`TransformTrack`函数始终有效：

```cpp
            if (channel.target_path == 
                 cgltf_animation_path_type_translation){
               VectorTrack& track = 
                 result[i][nodeId].GetPositionTrack();
               GLTFHelpers::TrackFromChannel<vec3, 3>
                            (track, channel);
            }
            else if (channel.target_path == 
                     cgltf_animation_path_type_scale) {
                VectorTrack& track = 
                      result[i][nodeId].GetScaleTrack();
                GLTFHelpers::TrackFromChannel<vec3, 3>
                            (track, channel);
            }
            else if (channel.target_path == 
                   cgltf_animation_path_type_rotation) {
                QuaternionTrack& track = 
                   result[i][nodeId].GetRotationTrack();
                GLTFHelpers::TrackFromChannel<quat, 4>
                             (track, channel);
            }
        } // End num channels loop
```

1.  在剪辑中的所有轨迹都被填充后，调用剪辑的`ReclaculateDuration`函数。这确保了播放发生在适当的时间范围内：

```cpp
        result[i].RecalculateDuration();
    } // End num clips loop
    return result;
} // End of LoadAnimationClips function
```

能够加载动画剪辑并将其采样为姿势是动画编程中约一半的工作。您可以加载动画剪辑，在应用程序更新时对其进行采样，并使用调试线来绘制姿势。结果是一个动画骨架。在下一章中，您将学习如何使用这个动画骨架来变形网格。

# 总结

在本章中，您实现了`Pose`和`Clip`类。您学会了如何从 glTF 文件中加载静止姿势，以及如何加载动画剪辑。您还学会了如何对动画剪辑进行采样以生成姿势。

本书的可下载内容可以在 GitHub 上找到：[`github.com/PacktPublishing/Game-Animation-Programming`](https://github.com/PacktPublishing/Game-Animation-Programming)。第九章的示例`Chapter09/Sample01`加载了一个 glTF 文件，并使用`DebugDraw`函数来绘制静止姿势和当前动画姿势。要使用调试线绘制骨骼，请从关节的位置绘制一条线到其父级的位置。

请记住，并非所有剪辑都会使每个姿势的关节发生动画。每当您正在采样的动画剪辑发生变化时，它被采样到的姿势都需要被重置。重置姿势很容易——将其赋值为静止姿势的值。这在本章的代码示例中有所展示。

在下一章中，您将学习如何对动画网格进行蒙皮。一旦您知道如何对网格进行蒙皮，您就能够显示一个动画模型。


# 第十章：网格皮肤

将网格变形以匹配动画姿势称为皮肤。为了实现皮肤，首先需要声明一个网格类。一旦声明了网格类，就可以使用着色器（GPU 皮肤）或仅使用 C++代码（CPU 皮肤）对其进行变形。本章涵盖了这两种皮肤方法。在本章结束时，您应该能够做到以下事情：

+   理解有皮肤的网格与无皮肤的网格有何不同

+   理解整个皮肤管道

+   实现骨架类

+   从 glTF 文件加载骨架的绑定姿势

+   实现一个有皮肤的网格类

+   从 glTF 文件加载有皮肤的网格

+   实现 CPU 皮肤

+   实现 GPU 皮肤

# 探索网格

一个网格由多个顶点组成。通常，每个顶点至少有一个位置、一个法线，也许还有一个纹理坐标。这是一个简单静态网格的顶点定义。这个定义有以下顶点组件：

+   位置（`vec3`）

+   法线（`vec3`）

+   纹理坐标（`vec2`）

重要信息：

本章中用于演示皮肤的模型是来自 GDQuest 的 Godot 模特。这是一个 MIT 许可的模型，您可以在 GitHub 上找到它[a t https://github.com/GDQuest/godot-3d-mannequ](https://github.com/GDQuest/godot-3d-mannequin)in。

当一个网格被建模时，它是在特定的姿势中建模的。对于角色来说，这通常是*T*形或*A*形。建模的网格是静态的。下图显示了 Godot 模特的*T*形姿势：

![图 10.1：Godot 模特的 T 形姿势](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.1_B16191.jpg)

图 10.1：Godot 模特的 T 形姿势

当一个网格被建模时，骨架被创建在网格中。网格中的每个顶点都分配给骨架的一个或多个骨骼。这个过程称为装配。骨架是在适合网格内的姿势中创建的；这是模型的**绑定姿势**。

![图 10.2：可视化网格和骨架的绑定姿势](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.2_B16191.jpg)

图 10.2：可视化网格和骨架的绑定姿势

绑定姿势和静止姿势通常是相同的，但并非总是如此。在本书中，我们将把这两者视为不同的姿势。前面的图显示了骨架的绑定姿势渲染在角色网格的顶部。在下一节中，您将探索如何对这样的网格进行皮肤处理。

# 理解皮肤

皮肤是指定哪个顶点应该由哪个骨骼变形的过程。一个顶点可以受到多个骨骼的影响。刚性皮肤是指将每个顶点与一个骨骼关联。平滑皮肤将顶点与多个骨骼关联。

通常，顶点到骨骼的映射是按顶点进行的。这意味着每个顶点都知道它属于哪些骨骼。一些文件格式以相反的方式存储这种关系，其中每个骨骼包含它影响的顶点列表。这两种方法都是有效的；在本书的其余部分，映射是按顶点进行的。

为了（刚性）皮肤一个网格，将每个顶点分配给一个骨骼。要在代码中为顶点分配关节，需要为每个顶点添加一个新属性。这个属性只是一个保存着变形顶点的骨骼索引的整数。在下图中，所有应该分配给左下臂骨骼的三角形都比网格的其余部分颜色更深：

![图 10.3：隔离下臂](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.3_B16191.jpg)

图 10.3：隔离下臂

让我们花点时间更详细地审查一下顶点变换管道。在这里，引入了**空间**的概念。空间指的是通过矩阵对顶点进行变换。例如，如果有一个投影矩阵，它会将一个顶点变换为 NDC 空间。顶点变换管道如下：

+   当一个网格被创建时，它的所有顶点都处于所谓的模型空间中。

+   模型空间顶点乘以模型矩阵，将其放入世界空间中。

+   世界空间顶点乘以视图矩阵，将其放入相机空间。

+   相机空间顶点乘以投影矩阵，将其移动到 NDC 空间。

要对网格进行蒙皮，需要在顶点变换流程中添加一个新的蒙皮步骤。蒙皮步骤将顶点从皮肤空间移动到模型空间。这意味着新步骤在变换流程中位于任何其他步骤之前。

如果将皮肤空间顶点乘以当前动画姿势，则可以将其移回模型空间。这个转换在本章的*实现 CPU 蒙皮*部分中有详细介绍。一旦顶点回到模型空间，它应该已经被动画化。动画姿势矩阵转换实际上进行了动画。动画化顶点转换流程如下：

+   加载一个网格，所有顶点都在模型空间中。

+   模型空间顶点乘以皮肤矩阵，将其移动到皮肤空间。

+   皮肤空间顶点乘以姿势矩阵，将其移回模型空间。

+   模型空间顶点乘以模型矩阵，将其放入世界空间。

+   世界空间顶点乘以视图矩阵，将其放入相机空间。

+   相机空间顶点乘以投影矩阵，将其移动到 NDC 空间。

要对网格进行蒙皮，需要将每个顶点转换为皮肤空间。当皮肤空间中的顶点通过其所属关节的世界变换进行变换时，假设使用的姿势是绑定姿势，顶点应该最终位于模型空间中。

在接下来的部分中，您将通过实际示例探索蒙皮流程。

## 探索刚性蒙皮

要对网格进行蒙皮，需要将每个顶点乘以其所属关节的逆绑定姿势变换。要找到关节的逆绑定姿势变换，需要找到关节的世界变换，然后对其求逆。当矩阵（或变换）乘以其逆时，结果总是单位矩阵。

将皮肤空间网格的顶点乘以绑定姿势中关节的世界空间变换可以撤消原始的逆绑定姿势乘法，`逆绑定姿势 * 绑定姿势 = 单位矩阵`。然而，乘以不同的姿势会导致顶点相对于绑定姿势的偏移。

让我们看看顶点如何在皮肤空间中移动。例如，将 Godot 模特前臂中的所有顶点乘以前臂骨骼的逆绑定姿势，只将前臂三角形放入皮肤空间。这使得网格看起来如下图所示：

![图 10.4：逆绑定姿势转换的下臂网格](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.4_B16191.jpg)

图 10.4：逆绑定姿势转换的下臂网格

要将顶点从皮肤空间转换回模型空间，需要依次应用姿势中每个骨骼的变换，直到达到目标骨骼。下图演示了从根骨骼到前臂骨骼需要进行的六个步骤：

![图 10.5：可视化到下臂的变换链](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.5_B16191.jpg)

图 10.5：可视化到下臂的变换链

在代码中，可以使用矩阵乘法累积需要进行的所有变换。或者，如果使用`Transform`结构，可以使用 combine 方法。将顶点移回模型空间只需使用累积的矩阵或变换一次。

通过将每个顶点乘以其所属关节的逆绑定姿势来将网格转换为皮肤空间。如何获得骨骼的逆绑定姿势矩阵？使用绑定姿势，找到骨骼的世界变换，将其转换为矩阵，然后求逆矩阵。

下图显示了 Godot 模型在皮肤空间中的情况。看到这样的网格表明了蒙皮管道中的错误。出现这种网格的最常见原因是逆绑定姿势和动画姿势的乘法顺序出现错误：

![图 10.6：整个网格乘以逆绑定姿势](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.6_B16191.jpg)

图 10.6：整个网格乘以逆绑定姿势

到目前为止讨论的蒙皮实现称为刚性蒙皮。使用刚性蒙皮时，每个顶点只受一个骨骼的影响。在接下来的部分中，您将开始探索平滑蒙皮，通过将多个骨骼的影响分配给单个顶点来使蒙皮网格看起来更好。

## 刚性蒙皮管道

让我们探索每个顶点必须经历的管道。下图显示了静态网格与刚性蒙皮网格的变换管道。以下图中的步骤顺序从左到右，沿着箭头进行：

![图 10.7：顶点蒙皮管道](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.7_B16191.jpg)

图 10.7：顶点蒙皮管道

在前面的图中显示的**刚性蒙皮顶点管道**的工作方式如下：

+   通过将顶点乘以其所分配的关节的逆绑定姿势矩阵将其移动到皮肤空间中。

+   将蒙皮顶点乘以动画关节的世界矩阵。这将导致顶点再次处于本地空间，但它会被变形到动画姿势。

+   一旦顶点处于动画本地位置，就将其通过正常的模型视图投影变换。

+   探索平滑蒙皮

刚性蒙皮的问题在于弯曲关节。由于每个顶点属于一个骨骼，因此在肘部等关节处的顶点不会自然弯曲。在肘部等关节处的网格断裂可以通过将三角形的不同顶点分配给不同的骨骼来避免。由此产生的网格无法很好地保持其体积，并且看起来很尴尬。

刚性蒙皮并不是免费的；它为每个顶点引入了额外的矩阵乘法。这可以优化为只有一个额外的乘法，这将在下一章中介绍。在接下来的部分中，您将探索平滑蒙皮。

## 探索平滑蒙皮

刚性蒙皮的主要问题是它可能在网格中产生视觉断裂，如下图所示。即使这些伪影得到了解决，平滑蒙皮时可弯曲关节周围的变形看起来也不好：

![图 10.8：刚性蒙皮的可见伪影](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.8_B16191.jpg)

图 10.8：刚性蒙皮的可见伪影

平滑蒙皮比刚性蒙皮具有更少的伪影，并且能更好地保持其体积。平滑蒙皮的理念是一个顶点可以受到多个骨骼的影响。每个影响还有一个权重。权重用于将蒙皮顶点混合成一个组合的最终顶点。所有权重必须加起来等于 1。

将顶点视为在网格上进行多次蒙皮并混合结果。一个骨骼可以有多少影响在这里有很大的影响。一般来说，超过四根骨骼后，每根额外的骨骼的影响就不可见了。这很方便，因为它可以让您使用`ivec4`和`vec4`结构向顶点添加影响和权重。

下图显示了一个网格，其中中间顶点附在左侧的顶部骨骼和右侧的底部骨骼上。这是需要混合的两个蒙皮位置。如果每个姿势的权重为`0.5`，最终插值顶点位置将在两个顶点之间。这在下图的中间图中显示：

![图 10.9：将多个关节分配给一个顶点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_10.9_B16191.jpg)

图 10.9：将多个关节分配给一个顶点

在顶点上平均关节影响被称为平滑蒙皮，或线性混合蒙皮（LBS）。它有一些缺陷，但这是皮肤角色的标准方式。目前，LBS 是实现蒙皮动画最流行的方式。

在添加对平滑蒙皮的支持后，最终的顶点结构现在如下所示：

+   位置（`vec3`）

+   法线（`vec3`）

+   纹理坐标（`vec2`）

+   关节影响（`ivec4`）

+   影响权重（`vec4`）

重要信息

glTF 支持将蒙皮网格附加到任意节点，并且这些节点可以进行动画。这增加了计算蒙皮矩阵的额外步骤。为了避免这一额外步骤，我们将忽略网格中心点，并假设所有网格节点的全局变换都在原点。只要假定单个 glTF 文件只包含一个蒙皮网格，这就是一个安全的假设。

平滑蒙皮目前是游戏动画中使用的标准形式。大多数游戏每个顶点使用四个骨骼，并且与本章中将要实现的方式类似。在接下来的部分，你将实现一个`Skeleton`类来帮助跟踪皮肤网格所需的一些不同数据。

# 实现骨骼

在对模型进行动画时，有几件事情需要跟踪，比如动画姿势或逆绑定姿势。骨骼的概念是将在动画模型之间共享的数据组合成一个单一的结构。

角色的绑定姿势和逆绑定姿势在所有角色实例之间共享。也就是说，如果屏幕上有 15 个角色，它们每个都有一个独特的动画姿势，但它们都共享相同的静止姿势、绑定姿势、逆绑定姿势和关节名称。

在接下来的部分，你将实现一个新的类——`Skeleton`类。这个`Skeleton`类包含两个动画网格可能需要的所有共享数据。它还跟踪静止姿势、绑定姿势、逆绑定姿势和关节名称。一些引擎将骨骼称为骨架或绑定。

## 骨骼类声明

`Skeleton`类包含角色的静止姿势和绑定姿势，角色的每个关节的名称，以及最重要的逆绑定姿势。由于逆绑定姿势涉及矩阵求逆，因此应该只计算一次。按照以下步骤声明新的`Skeleton`类：

1.  创建一个新文件`Skeleton.h`。在这个文件中声明`Skeleton`类。在`Skeleton`类中添加当前动画模型的静止姿势、绑定姿势、逆绑定姿势和关节名称。逆绑定姿势应该实现为一个矩阵的向量：

```cpp
class Skeleton {
protected:
    Pose mRestPose;
    Pose mBindPose;
    std::vector<mat4> mInvBindPose;
    std::vector<std::string> mJointNames;
```

1.  添加一个辅助函数`UpdateInverseBindPose`。这个函数在设置绑定姿势时更新逆绑定姿势矩阵：

```cpp
protected:
    void UpdateInverseBindPose();
```

1.  声明一个默认构造函数和一个便利构造函数。还要声明方法来设置骨骼的静止姿势、绑定姿势和关节名称，以及辅助函数来检索骨骼的所有变量的引用：

```cpp
public:
    Skeleton();
    Skeleton(const Pose& rest, const Pose& bind, 
             const std::vector<std::string>& names);
    void Set(const Pose& rest, const Pose& bind, 
             const std::vector<std::string>& names);
    Pose& GetBindPose();
    Pose& GetRestPose();
    std::vector<mat4>& GetInvBindPose();
    std::vector<std::string>& GetJointNames();
    std::string& GetJointName(unsigned int index);
}; // End Skeleton class
```

将`Skeleton`类视为一个辅助类——它将绑定姿势、逆绑定姿势、静止姿势和关节名称放入一个易于管理的对象中。骨骼是共享的；你可以有许多角色，每个角色都有一个独特的动画姿势，但它们都可以共享相同的骨骼。在接下来的部分，你将实现`Skeleton`类。

## 骨骼类的实现

逆绑定姿势存储在骨骼中作为矩阵数组。每当骨骼的绑定姿势更新时，逆绑定姿势也应该重新计算。要找到逆绑定姿势，找到骨骼中每个关节的世界空间矩阵，然后求逆世界空间关节矩阵。创建一个新文件`Skeleton.cpp`。然后，实现骨骼构造函数。采取以下步骤来实现：

1.  创建两个构造函数——默认构造函数不执行任何操作。另一个便利构造函数接受一个静止姿势、一个绑定姿势和关节名称。它调用`Set`方法：

```cpp
Skeleton::Skeleton() { }
Skeleton::Skeleton(const Pose& rest, const Pose& bind,
                const std::vector<std::string>& names) {
    Set(rest, bind, names);
}
```

1.  创建`Set`方法，应该设置骨骼的内部姿势、绑定姿势和关节名称。一旦绑定姿势设置好，调用`UpdateInverseBindPose`函数来填充逆绑定姿势矩阵调色板：

```cpp
void Skeleton::Set(const Pose& rest, const Pose& bind, 
                 const std::vector<std::string>& names) {
    mRestPose = rest;
    mBindPose = bind;
    mJointNames = names;
    UpdateInverseBindPose();
}
```

1.  接下来实现`UpdateInverseBindPose`函数。确保矩阵向量的大小正确，然后循环遍历绑定姿势中的所有关节。获取每个关节的世界空间变换，将其转换为矩阵，并对矩阵进行反转。这个反转的矩阵就是关节的逆绑定姿势矩阵：

```cpp
void Skeleton::UpdateInverseBindPose() {
  unsigned int size = mBindPose.Size();
  mInvBindPose.resize(size);
  for (unsigned int i = 0; i < size; ++i) {
    Transform world = mBindPose.GetGlobalTransform(i);
    mInvBindPose[i] = inverse(transformToMat4(world));
  }
}
```

1.  在`Skeleton`类中实现简单的 getter 和 setter 函数：

```cpp
Pose& Skeleton::GetBindPose() {
    return mBindPose;
}
Pose& Skeleton::GetRestPose() {
    return mRestPose;
}
std::vector<mat4>& Skeleton::GetInvBindPose() {
    return mInvBindPose;
}
std::vector<std::string>& Skeleton::GetJointNames() {
    return mJointNames;
}
std::string& Skeleton::GetJointName(unsigned int idx) {
    return mJointNames[idx];
}
```

通过提供显式的 getter 函数来避免返回引用是可能的，比如`Transform GetBindPoseTransform(unsigned int index)`。在你学习如何优化动画数据的下一章之后再这样做更有意义。现在，能够访问这些引用并且不修改它们更有价值。

生成逆绑定姿势矩阵时，你不必将变换转换为矩阵然后再反转它；你可以反转变换然后将其转换为矩阵。两者之间的性能差异是微不足道的。

`Skeleton`类跟踪动画模型的绑定姿势、逆绑定姿势和关节名称。这些数据可以在模型的所有动画实例之间共享。在下一节中，你将实现从 glTF 文件加载绑定姿势。glTF 格式不存储实际的绑定姿势。

# glTF - 加载绑定姿势

现在你已经准备好从 glTF 文件中加载绑定姿势了，但是有一个问题。glTF 文件不存储绑定姿势。相反，对于 glTF 文件包含的每个蒙皮，它存储一个矩阵数组，其中包含影响蒙皮的每个关节的逆绑定姿势矩阵。

像这样存储逆绑定姿势矩阵对于优化是有好处的，这在下一章中会更有意义，但现在我们必须处理这个问题。那么，如何获取绑定姿势呢？

获取绑定姿势，加载休息姿势并将休息姿势中的每个变换转换为世界空间变换。这样可以确保如果皮肤没有为关节提供逆绑定姿势矩阵，就可以使用一个良好的默认值。

接下来，循环遍历`.gltf`文件中的每个蒙皮网格。对于每个蒙皮网格，反转每个关节的逆绑定姿势矩阵。反转逆绑定姿势矩阵会得到绑定姿势矩阵。将绑定姿势矩阵转换为可以在绑定姿势中使用的变换。

这样做是有效的，但是所有关节变换都是在世界空间中。你需要将每个关节转换为相对于其父级的位置。按照以下步骤实现`GLTFLoader.cpp`中的`LoadBindPose`函数：

1.  通过构建一个变换向量来开始实现`LoadBindPose`函数。用休息姿势中每个关节的全局变换填充变换向量：

```cpp
Pose LoadBindPose(cgltf_data* data) {
    Pose restPose = LoadRestPose(data);
    unsigned int numBones = restPose.Size();
    std::vector<Transform> worldBindPose(numBones);
    for (unsigned int i = 0; i < numBones; ++i) {
      worldBindPose[i] = restPose.GetGlobalTransform(i);
    }
```

1.  循环遍历 glTF 文件中的每个蒙皮网格。将`inverse_bind_matrices`访问器读入一个大的浮点值向量中。该向量需要包含`contain numJoints * 16`个元素，因为每个矩阵都是一个 4x4 矩阵：

```cpp
    unsigned int numSkins = data->skins_count;
    for (unsigned int i = 0; i < numSkins; ++i) {
        cgltf_skin* skin = &(data->skins[i]);
        std::vector<float> invBindAccessor;
        GLTFHelpers::GetScalarValues(invBindAccessor, 
                     16, *skin->inverse_bind_matrices);
```

1.  对于蒙皮中的每个关节，获取逆绑定矩阵。反转逆绑定姿势矩阵以获得绑定姿势矩阵。将绑定姿势矩阵转换为变换。将这个世界空间变换存储在`worldBindPose`向量中：

```cpp
        unsigned int numJoints = skin->joints_count;
        for (int j = 0; j < numJoints; ++j) { 
            // Read the ivnerse bind matrix of the joint
            float* matrix = &(invBindAccessor[j * 16]);
            mat4 invBindMatrix = mat4(matrix);
            // invert, convert to transform
            mat4 bindMatrix = inverse(invBindMatrix);
            Transform bindTransform = 
                            mat4ToTransform(bindMatrix);
            // Set that transform in the worldBindPose.
            cgltf_node* jointNode = skin->joints[j];
            int jointIndex = GLTFHelpers::GetNodeIndex(
                       jointNode, data->nodes, numBones);
            worldBindPose[jointIndex] = bindTransform;
        } // end for each joint
    } // end for each skin
```

1.  将每个关节转换为相对于其父级的位置。将一个关节移动到另一个关节的空间中，即使它相对于另一个关节，将关节的世界变换与其父级的逆世界变换相结合：

```cpp
    //Convert the world bind pose to a regular bind pose
    Pose bindPose = restPose;
    for (unsigned int i = 0; i < numBones; ++i) {
        Transform current = worldBindPose[i];
        int p = bindPose.GetParent(i);
        if (p >= 0) { // Bring into parent space
            Transform parent = worldBindPose[p];
            current = combine(inverse(parent), current);
        }
        bindPose.SetLocalTransform(i, current);
    }
    return bindPose;
} // End LoadBindPose function
```

重建绑定姿势并不理想，但这是 glTF 的一个怪癖，你必须处理它。通过使用休息姿势作为默认关节值，任何没有逆绑定姿势矩阵的关节仍然具有有效的默认方向和大小。

在本节中，您学习了如何从 glTF 文件中加载动画网格的初始姿势。在下一节中，您将创建一个方便的函数，通过一个函数调用从 glTF 文件中加载骨骼。

# glTF——加载骨骼

我们需要实现另一个加载函数——`LoadSkeleton`函数。这是一个方便的函数，可以在不调用三个单独函数的情况下加载骨架。

在`GLTFLoader.cpp`中实现`LoadSkeleton`函数。不要忘记将函数声明添加到`GLTFLoader.h`中。该函数通过调用现有的`LoadPose`、`LoadBindPose`和`LoadJointNames`函数返回一个新的骨骼：

```cpp
Skeleton LoadSkeleton(cgltf_data* data) {
    return Skeleton(
        LoadRestPose(data),
        LoadBindPose(data),
        LoadJointNames(data)
    );
}
```

`LoadSkeleton`函数只是一个辅助函数，允许您通过一个函数调用初始化骨骼。在下一节中，您将实现一个`Mesh`类，它将允许您显示动画网格。

# 实现网格

网格的定义取决于实现它的游戏（或引擎）。在本书的范围之外实现一个全面的网格类。相反，在本节中，您将声明一个简单版本的网格，它在 CPU 和 GPU 上存储一些数据，并提供一种将两者同步的方法。

## Mesh 类声明

网格的最基本实现是什么？每个顶点都有一个位置、一个法线和一些纹理坐标。为了对网格进行蒙皮，每个顶点还有四个可能影响它的骨骼和权重来确定每个骨骼对顶点的影响程度。网格通常使用索引数组，但这是可选的。

在本节中，您将同时实现 CPU 和 GPU 蒙皮。要在 CPU 上对网格进行蒙皮，您需要保留姿势和法线数据的额外副本，以及一个用于蒙皮的矩阵调色板。

创建一个新文件`Mesh.h`，声明`Mesh`类。按照以下步骤声明新的`Mesh`类：

1.  开始声明`Mesh`类。它应该在 CPU 和 GPU 上都维护网格数据的副本。存储位置、法线、纹理坐标、权重和影响力的向量来定义每个顶点。包括一个可选的索引向量：

```cpp
class Mesh {
protected:
    std::vector<vec3> mPosition;
    std::vector<vec3> mNormal;
    std::vector<vec2> mTexCoord;
    std::vector<vec4> mWeights;
    std::vector<ivec4> mInfluences;
    std::vector<unsigned int> mIndices;
```

1.  前面代码中列出的每个向量也需要设置适当的属性。为每个创建`Attribute`指针，以及一个索引缓冲区指针：

```cpp
protected:
    Attribute<vec3>* mPosAttrib;
    Attribute<vec3>* mNormAttrib;
    Attribute<vec2>* mUvAttrib;
    Attribute<vec4>* mWeightAttrib;
    Attribute<ivec4>* mInfluenceAttrib;
    IndexBuffer* mIndexBuffer;
```

1.  添加一个额外的姿势和法线数据的副本，以及一个用于 CPU 蒙皮的矩阵调色板：

```cpp
protected:
    std::vector<vec3> mSkinnedPosition;
    std::vector<vec3> mSkinnedNormal;
    std::vector<mat4> mPosePalette;
```

1.  为构造函数、拷贝构造函数和赋值运算符以及析构函数添加声明：

```cpp
public:
    Mesh();
    Mesh(const Mesh&);
    Mesh& operator=(const Mesh&);
    ~Mesh();
```

1.  为网格包含的所有属性声明 getter 函数。这些函数返回向量引用。向量引用不是只读的；在加载网格时使用这些引用来填充网格数据：

```cpp
    std::vector<vec3>& GetPosition();
    std::vector<vec3>& GetNormal();
    std::vector<vec2>& GetTexCoord();
    std::vector<vec4>& GetWeights();
    std::vector<ivec4>& GetInfluences();
    std::vector<unsigned int>& GetIndices();
```

1.  声明`CPUSkin`函数，应用 CPU 网格蒙皮。要对网格进行蒙皮，您需要骨架和动画姿势。声明`UpdateOpenGLBuffers`函数，将持有数据的向量同步到 GPU：

```cpp
    void CPUSkin(Skeleton& skeleton, Pose& pose);
    void UpdateOpenGLBuffers();
    void Bind(int position, int normal, int texCoord, 
              int weight, int influence);
```

1.  声明绑定、绘制和解绑网格的函数：

```cpp
    void Draw();
    void DrawInstanced(unsigned int numInstances);
    void UnBind(int position, int normal, int texCoord, 
                int weight, int influence);
};
```

这个`Mesh`类还不是生产就绪的，但它很容易使用，并且将在本书的其余部分中使用。在下一节中，您将开始实现`Mesh`类。

## Mesh 类实现

`Mesh`类包含相同数据的两个副本。它在 CPU 端使用向量保留所有顶点数据，并在 GPU 端使用顶点缓冲对象。这个类的预期用途是编辑 CPU 端的顶点，然后使用`UpdateOpenGLBuffers`函数将更改同步到 GPU。

创建一个新文件`Mesh.cpp`；您将在此文件中实现`Mesh`类。按照以下步骤实现`Mesh`类：

1.  实现默认构造函数，需要确保所有属性（和索引缓冲区）都被分配：

```cpp
Mesh::Mesh() {
    mPosAttrib = new Attribute<vec3>();
    mNormAttrib = new Attribute<vec3>();
    mUvAttrib = new Attribute<vec2>();
    mWeightAttrib = new Attribute<vec4>();
    mInfluenceAttrib = new Attribute<ivec4>();
    mIndexBuffer = new IndexBuffer();
}
```

1.  实现拷贝构造函数。以与构造函数相同的方式创建缓冲区，然后调用赋值运算符：

```cpp
Mesh::Mesh(const Mesh& other) {
    mPosAttrib = new Attribute<vec3>();
    mNormAttrib = new Attribute<vec3>();
    mUvAttrib = new Attribute<vec2>();
    mWeightAttrib = new Attribute<vec4>();
    mInfluenceAttrib = new Attribute<ivec4>();
    mIndexBuffer = new IndexBuffer();
    *this = other;
}
```

1.  实现赋值运算符，它将复制 CPU 端的成员（所有向量），然后调用`UpdateOpenGLBuffers`函数将属性数据上传到 GPU：

```cpp
Mesh& Mesh::operator=(const Mesh& other) {
    if (this == &other) {
        return *this;
    }
    mPosition = other.mPosition;
    mNormal = other.mNormal;
    mTexCoord = other.mTexCoord;
    mWeights = other.mWeights;
    mInfluences = other.mInfluences;
    mIndices = other.mIndices;
    UpdateOpenGLBuffers();
    return *this;
}
```

1.  实现析构函数，确保删除构造函数分配的所有数据：

```cpp
Mesh::~Mesh() {
    delete mPosAttrib;
    delete mNormAttrib;
    delete mUvAttrib;
    delete mWeightAttrib;
    delete mInfluenceAttrib;
    delete mIndexBuffer;
}
```

1.  实现`Mesh`获取函数。这些函数返回向量的引用。预期在返回后对这些引用进行编辑：

```cpp
std::vector<vec3>& Mesh::GetPosition() {
    return mPosition;
}
std::vector<vec3>& Mesh::GetNormal() {
    return mNormal;
}
std::vector<vec2>& Mesh::GetTexCoord() {
    return mTexCoord;
}
std::vector<vec4>& Mesh::GetWeights() {
    return mWeights;
}
std::vector<ivec4>& Mesh::GetInfluences() {
    return mInfluences;
}
std::vector<unsigned int>& Mesh::GetIndices() {
    return mIndices;
}
```

1.  通过在每个属性对象上调用`Set`函数来实现`UpdateOpenGLBuffers`函数。如果 CPU 端的向量之一的大小为`0`，则没有需要设置的内容：

```cpp
void Mesh::UpdateOpenGLBuffers() {
    if (mPosition.size() > 0) {
        mPosAttrib->Set(mPosition);
    }
    if (mNormal.size() > 0) {
        mNormAttrib->Set(mNormal);
    }
    if (mTexCoord.size() > 0) {
        mUvAttrib->Set(mTexCoord);
    }
    if (mWeights.size() > 0) {
        mWeightAttrib->Set(mWeights);
    }
    if (mInfluences.size() > 0) {
        mInfluenceAttrib->Set(mInfluences);
    }
    if (mIndices.size() > 0) {
        mIndexBuffer->Set(mIndices);
    }
}
```

1.  实现`Bind`函数。这需要绑定槽索引的整数。如果绑定槽有效（即为`0`或更大），则调用属性的`BindTo`函数：

```cpp
void Mesh::Bind(int position, int normal, int texCoord, 
                int weight, int influcence) {
    if (position >= 0) {
        mPosAttrib->BindTo(position);
    }
    if (normal >= 0) {
        mNormAttrib->BindTo(normal);
    }
    if (texCoord >= 0) {
        mUvAttrib->BindTo(texCoord);
    }
    if (weight >= 0) {
        mWeightAttrib->BindTo(weight);
    }
    if (influcence >= 0) {
        mInfluenceAttrib->BindTo(influcence);
    }
}
```

1.  实现`Draw`和`DrawInstanced`函数，这些函数调用适当的全局`::Draw`和`::DrawInstanced`函数：

```cpp
void Mesh::Draw() {
    if (mIndices.size() > 0) {
        ::Draw(*mIndexBuffer, DrawMode::Triangles);
    }
    else {
        ::Draw(mPosition.size(), DrawMode::Triangles);
    }
}
void Mesh::DrawInstanced(unsigned int numInstances) {
    if (mIndices.size() > 0) {
        ::DrawInstanced(*mIndexBuffer, 
          DrawMode::Triangles, numInstances);
    }
    else {
        ::DrawInstanced(mPosition.size(), 
          DrawMode::Triangles, numInstances);
    }
}
```

1.  实现`UnBind`函数，该函数还接受整数绑定槽作为参数，但在属性对象上调用`UnBindFrom`：

```cpp
void Mesh::UnBind(int position, int normal, int texCoord, 
                  int weight, int influence) {
    if (position >= 0) {
        mPosAttrib->UnBindFrom(position);
    }
    if (normal >= 0) {
        mNormAttrib->UnBindFrom(normal);
    }
    if (texCoord >= 0) {
        mUvAttrib->UnBindFrom(texCoord);
    }
    if (weight >= 0) {
        mWeightAttrib->UnBindFrom(weight);
    }
    if (influcence >= 0) {
        mInfluenceAttrib->UnBindFrom(influence);
    }
}
```

`Mesh`类包含用于保存 CPU 数据的向量和用于将数据复制到 GPU 的属性。它提供了一个简单的接口来渲染整个网格。在接下来的部分中，您将学习如何实现 CPU 蒙皮以对网格进行动画处理。

### 实现 CPU 蒙皮

通过首先在 CPU 上实现蒙皮，而无需担心着色器，可以更容易地理解蒙皮。在本节中，您将创建一个 CPU 蒙皮参考实现。GPU 蒙皮将在本章后面介绍。

重要信息：

如果您正在开发的平台具有有限数量的统一寄存器或小的统一缓冲区，则 CPU 蒙皮非常有用。

在实现 CPU 蒙皮时，您需要保留动画网格的两个副本。`mPosition` 和 `mNormal` 向量不会改变。蒙皮后的位置和法线的结果存储在 `mSkinnedPosition` 和 `mSkinnedNormal` 中。然后将这些向量同步到位置和法线属性以进行绘制。

要对顶点进行蒙皮，您需要计算蒙皮变换。蒙皮变换需要通过逆绑定姿势对顶点进行变换，然后再通过当前的动画姿势进行变换。您可以通过在绑定姿势变换上调用逆函数，然后将其与姿势变换组合来实现这一点。

对于每个顶点，存储在`mInfluences`向量中的`ivec4`包含影响顶点的关节 ID。您需要通过所有四个关节对顶点进行变换，这意味着您需要对影响顶点的每个骨骼进行四次蒙皮。

并非每个关节对最终顶点的贡献都相同。对于每个顶点，存储在`mWeights`中的`vec4`包含一个从`0`到`1`的标量值。这些值用于混合蒙皮顶点。如果一个关节不影响顶点，则其权重为`0`，对最终蒙皮网格没有影响。

权重的内容预期被归一化，以便如果所有权重相加，它们等于`1`。这样，权重可以用于混合，因为它们总和为`1`。例如，(`0.5`, `0.5`, `0`, `0`) 是有效的，但 (`0.6`, `0.5`, `0`, `0`) 不是。

按照以下步骤实现 CPU 蒙皮：

1.  开始实现`CPUSkin`函数。确保蒙皮向量有足够的存储空间，并从骨骼获取绑定姿势。接下来，循环遍历每个顶点：

```cpp
void Mesh::CPUSkin(Skeleton& skeleton, Pose& pose) {
    unsigned int numVerts = mPosition.size();
    if (numVerts == 0) { return;  }
    mSkinnedPosition.resize(numVerts);
    mSkinnedNormal.resize(numVerts);
    Pose& bindPose = skeleton.GetBindPose();
    for (unsigned int i = 0; i < numVerts; ++i) {
        ivec4& joint = mInfluences[i];
        vec4& weight = mWeights[i];
```

1.  计算蒙皮变换。对第一个顶点和法线影响进行变换：

```cpp
        Transform skin0 = combine(pose[joint.x], 
                          inverse(bindPose[joint.x]));
        vec3 p0 = transformPoint(skin0, mPosition[i]);
        vec3 n0 = transformVector(skin0, mNormal[i]);
```

1.  对可能影响当前顶点的其他三个关节重复此过程：

```cpp
        Transform skin1 = combine(pose[joint.y], 
                          inverse(bindPose[joint.y]));
        vec3 p1 = transformPoint(skin1, mPosition[i]);
        vec3 n1 = transformVector(skin1, mNormal[i]);

        Transform skin2 = combine(pose[joint.z], 
                          inverse(bindPose[joint.z]));
        vec3 p2 = transformPoint(skin2, mPosition[i]);
        vec3 n2 = transformVector(skin2, mNormal[i]);

        Transform skin3 = combine(pose[joint.w], 
                          inverse(bindPose[joint.w]));
        vec3 p3 = transformPoint(skin3, mPosition[i]);
        vec3 n3 = transformVector(skin3, mNormal[i]);
```

1.  到这一步，您已经对顶点进行了四次蒙皮——分别对每个影响它的骨骼进行一次。接下来，您需要将这些合并成最终的顶点。

1.  使用`mWeights`混合蒙皮位置和法线。将位置和法线属性设置为新更新的蒙皮位置和法线：

```cpp
        mSkinnedPosition[i] = p0 * weight.x + 
                              p1 * weight.y + 
                              p2 * weight.z + 
                              p3 * weight.w;
        mSkinnedNormal[i] = n0 * weight.x + 
                            n1 * weight.y + 
                            n2 * weight.z + 
                            n3 * weight.w;
    }
    mPosAttrib->Set(mSkinnedPosition);
    mNormAttrib->Set(mSkinnedNormal);
}
```

让我们解释一下这里发生了什么。这是基本的蒙皮算法。每个顶点都有一个名为权重的`vec4`值和一个名为影响的`ivec4`值。每个顶点有四个影响它的关节和四个权重。如果关节对顶点没有影响，权重可能是`0`。

`ivec4`的`x`、`y`、`z`和`w`分量影响动画姿势和逆绑定姿势矩阵数组中的索引。`vec4`的`x`、`y`、`z`和`w`分量是要应用于`ivec4`影响的相同分量的标量权重。

循环遍历所有顶点。对于每个顶点，通过影响该顶点的每个关节的蒙皮变换，变换顶点的位置和法线。蒙皮变换是逆绑定姿势和姿势变换的组合。这意味着你最终会对顶点进行四次蒙皮。按关节的权重缩放每个变换后的位置或法线，并将所有四个值相加。得到的总和就是蒙皮后的位置或法线。

这就是蒙皮算法；无论如何表达，它都是相同的。有几种表示关节变换的方式，比如使用`Transform`对象、矩阵和双四元数。无论表示是什么，算法都是一样的。在接下来的部分，你将学习如何使用矩阵而不是`Transform`对象来实现蒙皮算法。

### 使用矩阵进行蒙皮

对顶点进行蒙皮的常见方法是将矩阵线性混合成单个蒙皮矩阵，然后通过这个蒙皮矩阵变换顶点。为此，使用存储在骨骼中的逆绑定姿势，并从姿势中获取矩阵调色板。

要构建一个蒙皮矩阵，将姿势矩阵乘以逆绑定姿势。记住，顶点应该先被逆绑定姿势变换，然后是动画姿势。通过从右到左的乘法，这将把逆绑定姿势放在右侧。

对影响当前顶点的每个关节的矩阵进行相乘，然后按顶点的权重对结果矩阵进行缩放。一旦所有矩阵都被缩放，将它们相加。得到的矩阵就是可以用来变换顶点位置和法线的蒙皮矩阵。

以下代码重新实现了使用矩阵调色板蒙皮的`CPUSkin`函数。这段代码与你需要实现的在 GPU 上运行蒙皮的着色器代码非常相似：

```cpp
void Mesh::CPUSkin(Skeleton& skeleton, Pose& pose) {
    unsigned int numVerts = (unsigned int)mPosition.size();
    if (numVerts == 0) { return; }
    mSkinnedPosition.resize(numVerts);
    mSkinnedNormal.resize(numVerts);
    pose.GetMatrixPalette(mPosePalette);
    vector<mat4> invPosePalette = skeleton.GetInvBindPose();
    for (unsigned int i = 0; i < numVerts; ++i) {
        ivec4& j = mInfluences[i];
        vec4& w = mWeights[i];
        mat4 m0=(mPosePalette[j.x]*invPosePalette[j.x])*w.x;
        mat4 m1=(mPosePalette[j.y]*invPosePalette[j.y])*w.y;
        mat4 m2=(mPosePalette[j.z]*invPosePalette[j.z])*w.z;
        mat4 m3=(mPosePalette[j.w]*invPosePalette[j.w])*w.w;
        mat4 skin = m0 + m1 + m2 + m3;
        mSkinnedPosition[i]=transformPoint(skin,mPosition[i]);
        mSkinnedNormal[i] = transformVector(skin, mNormal[i]);
    }
    mPosAttrib->Set(mSkinnedPosition);
    mNormAttrib->Set(mSkinnedNormal);
}
```

使用矩阵进行蒙皮的代码看起来有点不同，但蒙皮算法仍然是相同的。不再是对每个顶点进行四次变换并缩放结果，而是对矩阵进行缩放并相加。结果是一个单一的蒙皮矩阵。

即使顶点只被变换一次，也引入了四次新的矩阵乘法。所需操作的数量大致相同，那么为什么要实现矩阵调色板蒙皮？当你实现 GPU 蒙皮时，使用 GLSL 的内置矩阵就很容易了。

在这一部分，你实现了一个`Mesh`类。Mesh 类使用以下顶点格式：

+   位置（`vec3`）

+   普通（`vec3`）

+   纹理坐标（`vec2`）

+   影响（`ivec4`）

+   权重（`vec4`）

有了这个定义，你可以渲染一个蒙皮网格。在接下来的部分，你将学习如何从 glTF 文件中加载网格。

# glTF - 加载网格

现在你有了一个功能性的`Mesh`类，理论上，你可以在 CPU 上对网格进行蒙皮。然而，有一个问题——你实际上还不能从 glTF 文件中加载网格。让我们接下来解决这个问题。

首先创建一个新的辅助函数`MeshFromAttributes`。这只是一个辅助函数，所以不需要将其暴露给头文件。glTF 将网格存储为一组基元，每个基元都是一组属性。这些属性包含与我们的属性类相同的信息，如位置、法线、权重等。

`MeshFromAttribute`辅助函数接受一个网格和一个`cgltf_attribute`函数，以及解析所需的一些附加数据。该属性包含我们网格组件之一，例如位置、法线、UV 坐标、权重或影响。此属性提供适当的网格数据。

所有值都以浮点数形式读取，但影响顶点的关节影响以整数形式存储。不要直接将浮点数转换为整数；由于精度问题，转换可能会返回错误的数字。相反，通过加上 0.5 然后进行转换，将浮点数转换为整数。这样，整数截断总是将其带到正确的数字。

gLTF 将影响关节的索引存储为相对于正在解析的皮肤的关节数组，而不是节点层次结构。而“关节”数组又是指向节点的指针。您可以使用此节点指针，并使用`GetNodeIndex`函数将其转换为节点层次结构中的索引。

按照以下步骤从 glTF 文件中实现网格加载：

1.  在`GLTFHelpers`命名空间中实现`MeshFromAttribute`函数。通过确定当前组件具有多少属性来开始实现：

```cpp
// In the GLTFHelpers namespace
void GLTFHelpers::MeshFromAttribute(Mesh& outMesh, 
                  cgltf_attribute& attribute, 
                  cgltf_skin* skin, cgltf_node* nodes, 
                  unsigned int nodeCount) {
    cgltf_attribute_type attribType = attribute.type;
    cgltf_accessor& accessor = *attribute.data;
    unsigned int componentCount = 0;
    if (accessor.type == cgltf_type_vec2) {
        componentCount = 2;
    }
    else if (accessor.type == cgltf_type_vec3) {
        componentCount = 3;
    }
    else if (accessor.type == cgltf_type_vec4) {
        componentCount = 4;
    }
```

1.  使用`GetScalarValues`辅助函数从提供的访问器中解析数据。创建对网格的位置、法线、纹理坐标、影响和权重向量的引用；`MeshFromAttribute`函数将写入这些引用：

```cpp
    std::vector<float> values;
    GetScalarValues(values, componentCount, accessor);
    unsigned int acessorCount = accessor.count;
    std::vector<vec3>& positions = outMesh.GetPosition();
    std::vector<vec3>& normals = outMesh.GetNormal();
    std::vector<vec2>& texCoords = outMesh.GetTexCoord();
    std::vector<ivec4>& influences = 
                             outMesh.GetInfluences();
    std::vector<vec4>& weights = outMesh.GetWeights();
```

1.  循环遍历当前访问器中的所有值，并根据访问器类型将它们分配到适当的向量中。通过从值向量中读取数据并直接将其分配到网格中的适当向量中，可以找到位置、纹理坐标和权重分量：

```cpp
    for (unsigned int i = 0; i < acessorCount; ++i) {
        int index = i * componentCount;
        switch (attribType) {
        case cgltf_attribute_type_position:
            positions.push_back(vec3(values[index + 0], 
                                    values[index + 1],
                                    values[index + 2]));
            break;
        case cgltf_attribute_type_texcoord:
            texCoords.push_back(vec2(values[index + 0], 
                                    values[index + 1]));
            break;
        case cgltf_attribute_type_weights:
            weights.push_back(vec4(values[index + 0], 
                                   values[index + 1], 
                                   values[index + 2], 
                                   values[index + 3]));
            break;
```

1.  在读取法线后，检查其平方长度。如果法线无效，则返回有效向量并考虑记录错误。如果法线有效，则在将其推入法线向量之前对其进行归一化：

```cpp
        case cgltf_attribute_type_normal:
        {
            vec3 normal = vec3(values[index + 0], 
                               values[index + 1], 
                               values[index + 2]);
            if (lenSq(normal) < 0.000001f) {
                normal = vec3(0, 1, 0);
            }
            normals.push_back(normalized(normal));
        }
        break;
```

1.  读取影响当前顶点的关节。这些关节存储为浮点数。将它们转换为整数：

```cpp
        case cgltf_attribute_type_joints:
        {
            // These indices are skin relative.  This 
            // function has no information about the
            // skin that is being parsed. Add +0.5f to 
            // round, since we can't read integers
            ivec4 joints(
                (int)(values[index + 0] + 0.5f),
                (int)(values[index + 1] + 0.5f),
                (int)(values[index + 2] + 0.5f),
                (int)(values[index + 3] + 0.5f)
            );
```

1.  使用`GetNodeIndex`辅助函数将关节索引转换，使其从相对于“关节”数组变为相对于骨骼层次结构：

```cpp
                joints.x = GetNodeIndex(
                           skin->joints[joints.x], 
                           nodes, nodeCount);
                joints.y = GetNodeIndex(
                           skin->joints[joints.y], 
                           nodes, nodeCount);
                joints.z = GetNodeIndex(
                           skin->joints[joints.z], 
                           nodes, nodeCount);
                joints.w = GetNodeIndex(
                           skin->joints[joints.w], 
                           nodes, nodeCount);
```

1.  确保即使无效节点也具有`0`的值。任何负关节索引都会破坏蒙皮实现：

```cpp
                joints.x = std::max(0, joints.x);
                joints.y = std::max(0, joints.y);
                joints.z = std::max(0, joints.z);
                joints.w = std::max(0, joints.w);
            influences.push_back(joints);
        }
        break;
        }
    }
}// End of MeshFromAttribute function
```

gLTF 中的**网格**由**原始**组成。原始包含诸如位置和法线之类的属性。自从迄今为止创建的框架中没有子网格的概念，因此 glTF 中的每个原始都表示为网格。

现在`MeshFromAttribute`函数已完成，接下来实现`LoadMeshes`函数。这是用于加载实际网格数据的函数；它需要在`GLTFLoader.h`中声明，并在`GLTFLoader.cpp`中实现。按照以下步骤实现`LoadMeshes`函数：

1.  要实现`LoadMeshes`函数，首先循环遍历 glTF 文件中的所有节点。只处理具有网格和皮肤的节点；应跳过任何其他节点：

```cpp
std::vector<Mesh> LoadMeshes(cgltf_data* data) {
    std::vector<Mesh> result;
    cgltf_node* nodes = data->nodes;
    unsigned int nodeCount = data->nodes_count;
    for (unsigned int i = 0; i < nodeCount; ++i) {
        cgltf_node* node = &nodes[i];
        if (node->mesh == 0 || node->skin == 0) {
            continue;
        }
```

1.  循环遍历 glTF 文件中的所有原始。为每个原始创建一个新网格。通过调用`MeshFromAttribute`辅助函数循环遍历原始中的所有属性，并通过调用`MeshFromAttribute`辅助函数填充网格数据：

```cpp
        int numPrims = node->mesh->primitives_count;
        for (int j = 0; j < numPrims; ++j) {
            result.push_back(Mesh());
            Mesh& mesh = result[result.size() - 1];
            cgltf_primitive* primitive = 
                       &node->mesh->primitives[j];
            unsigned int ac=primitive->attributes_count;
            for (unsigned int k = 0; k < ac; ++k) {
                cgltf_attribute* attribute = 
                         &primitive->attributes[k];
                GLTFHelpers::MeshFromAttribute(mesh,
                           *attribute, node->skin, 
                           nodes, nodeCount);
            }
```

1.  检查原始是否包含索引。如果是，网格的索引缓冲区也需要填充：

```cpp
            if (primitive->indices != 0) {
                int ic = primitive->indices->count;
                std::vector<unsigned int>& indices = 
                                   mesh.GetIndices();
                indices.resize(ic);
                for (unsigned int k = 0; k < ic; ++k) {
                   indices[k]=cgltf_accessor_read_index(
                              primitive->indices, k);
                }
            }
```

1.  网格已完成。调用`UpdateOpenGLBuffers`函数以确保网格可以呈现，并返回结果网格的向量：

```cpp
            mesh.UpdateOpenGLBuffers();
        }
    }
    return result;
} // End of the LoadMeshes function
```

由于 glTF 存储整个场景，而不仅仅是一个网格，它支持多个网格——每个网格由原语组成，原语是实际的三角形。在 glTF 中，原语可以被视为子网格。这里介绍的 glTF 加载器假设一个文件只包含一个模型。在下一节中，您将学习如何使用着色器将网格蒙皮从 CPU 移动到 GPU。

# 实现 GPU 蒙皮

您在*第六章*中创建了一些基本的着色器，*构建抽象渲染器和 OpenGL*——`static.vert`着色器和`lit.frag`着色器。`static.vert`着色器可用于显示静态的、未经蒙皮的网格，该网格是使用`LoadMeshes`函数加载的。`static.vert`着色器甚至可以显示 CPU 蒙皮网格。

创建一个新文件，`skinned.vert`。按照以下步骤实现一个可以执行矩阵调色板蒙皮的顶点着色器。代码与用于`static.vert`的代码非常相似；不同之处已经突出显示：

1.  每个顶点都会得到两个新的分量——影响顶点的关节索引和每个关节的权重。这些新的分量可以存储在`ivec4`和`vec4`中：

```cpp
#version 330 core
uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;
in vec3 position;
in vec3 normal;
in vec2 texCoord;
in vec4 weights;
in ivec4 joints;
```

1.  接下来，在着色器中添加两个矩阵数组——每个数组的长度为`120`。这个长度是任意的；着色器只需要与蒙皮网格的关节数量一样多的新统一矩阵。您可以通过在代码中每次加载具有新骨骼数量的骨架时生成新的着色器字符串来自动配置这一点：

```cpp
uniform mat4 pose[120];
uniform mat4 invBindPose[120];
out vec3 norm;
out vec3 fragPos;
out vec2 uv;
```

1.  当着色器的主函数运行时，计算一个蒙皮矩阵。蒙皮矩阵的生成方式与 CPU 蒙皮示例的蒙皮矩阵相同。它使用相同的逻辑，只是在 GPU 上执行的着色器中：

```cpp
void main() {
mat4 skin =(pose[joints.x]* invBindPose[joints.x]) 
                  * weights.x;
skin+=(pose[joints.y] * invBindPose[joints.y]) 
                  * weights.y;
         skin+=(pose[joints.z] * invBindPose[joints.z])
                  * weights.z;
skin+=(pose[joints.w] * invBindPose[joints.w]) 
                  * weights.w;
```

1.  网格在放置在世界之前应该发生变形。在应用模型矩阵之前，将顶点位置和法线乘以蒙皮矩阵。所有相关的代码都在这里突出显示：

```cpp
    gl_Position= projection * view * model * 
                 skin * vec4(position,1.0);

    fragPos = vec3(model * skin * vec4(position, 1.0));
    norm = vec3(model * skin * vec4(normal, 0.0f));
    uv = texCoord;
}
```

要将蒙皮支持添加到顶点着色器中，您需要为每个顶点添加两个新属性，表示最多四个可以影响顶点的关节。通过使用关节和权重属性，构建一个蒙皮矩阵。要对网格进行蒙皮，需要在应用顶点变换管线的其余部分之前，将顶点或法线乘以蒙皮矩阵。

# 摘要

在本章中，您学习了绑定姿势和静止姿势之间的区别。您还创建了一个包含它们两者的`Skeleton`类。您了解了蒙皮的一般概念——刚性（每个顶点一个骨骼）和平滑（每个顶点多个骨骼）蒙皮。

在本章中，我们实现了一个基本的原始网格类，并介绍了在 CPU 和 GPU 上对网格进行蒙皮的过程，以及从不存储绑定姿势数据的 glTF 文件中加载绑定姿势。

您现在可以应用所学的技能。完成蒙皮代码后，您可以显示完全动画的模型。这些模型可以从 glTF 文件中加载，这是一种开放的文件格式规范。

本书的可下载示例中，`Chapter10/Sample01`包含一个示例，绘制了静止姿势、绑定姿势和当前动画姿势。`Chapter10/Sample02`演示了如何同时使用 GPU 和 CPU 蒙皮。

在下一章中，您将学习如何优化动画流水线的各个方面。这包括姿势生成和蒙皮以及缓存变换父级查找步骤。


# 第十一章：优化动画管线

到目前为止，您已经编写了一个完整的动画系统，可以加载标准文件格式 gLT，并在 CPU 或 GPU 上执行皮肤。动画系统对于大多数简单的动画表现得足够好。

在本章中，您将探讨优化动画系统的方法，使其更快且资源消耗更少。这涉及探索执行皮肤的替代方法，提高采样动画片段的速度，并重新审视如何生成矩阵调色板。

每个主题都是单独探讨的，您可以选择实现尽可能少或尽可能多的这些优化。所有这些都很简单，可以轻松地用来替换不太优化的管线版本。

本章将涵盖以下主题：

+   预生成皮肤矩阵

+   将皮肤调色板存储在纹理中

+   更快的采样

+   姿势调色板生成

+   探索`Pose::GetGlobalTransform`

# 预生成皮肤矩阵

`mat4`对象的一个较大问题是占用了四个统一槽位，而经过处理的顶点着色器目前有两个具有 120 个元素的矩阵数组。总共是 960 个统一槽位，这是过多的。

顶点着色器中的这两个矩阵数组会发生什么？它们会相互相乘，如下所示：

```cpp
mat4 skin=(pose[joints.x]*invBindPose[joints.x])*weights.x;
  skin += (pose[joints.y]*invBindPose[joints.y])*weights.y;
  skin += (pose[joints.z]*invBindPose[joints.z])*weights.z;
  skin += (pose[joints.w]*invBindPose[joints.w])*weights.w;
```

这里的一个简单优化是将`pose * invBindPose`相乘，以便着色器只需要一个数组。这确实意味着一些皮肤过程被移回到了 CPU，但这个改变清理了 480 个统一槽位。

## 生成皮肤矩阵

生成皮肤矩阵不需要 API 调用-它很简单。使用`Pose`类的`GetMatrixPalette`函数从当前动画姿势生成矩阵调色板。然后，将调色板中的每个矩阵与相同索引的逆绑定姿势矩阵相乘。

显示网格的代码负责计算这些矩阵。例如，一个简单的更新循环可能如下所示：

```cpp
void Sample::Update(float deltaTime) {
    mPlaybackTime = mAnimClip.Sample(mAnimatedPose, 
                         mPlaybackTime + deltaTime);
    mAnimatedPose.GetMatrixPalette(mPosePalette);
    vector<mat4>& invBindPose = mSkeleton.GetInvBindPose();
    for (int i = 0; i < mPosePalette.size(); ++i) {
        mPosePalette[i] = mPosePalette[i] * invBindPose[i];
    }
    if (mDoCPUSkinning) {
        mMesh.CPUSkin(mPosePalette);
    }
}
```

在前面的代码示例中，动画片段被采样到一个姿势中。姿势被转换为矩阵向量。该向量中的每个矩阵然后与相同索引的逆绑定姿势矩阵相乘。结果的矩阵向量就是组合的皮肤矩阵。

如果网格是 CPU 皮肤，这是调用`CPUSkin`函数的好地方。这个函数需要重新实现以适应组合的皮肤矩阵。如果网格是 GPU 皮肤，需要编辑着色器以便只使用一个矩阵数组，并且需要更新渲染代码以便只传递一个统一数组。

在接下来的部分，您将探讨如何重新实现`CPUSkin`函数，使其与组合的皮肤矩阵一起工作。这将稍微加快 CPU 皮肤过程。

## CPU 皮肤

您需要一种新的皮肤方法，该方法尊重预乘的皮肤矩阵。此函数接受一个矩阵向量的引用。每个位置都由影响它的四个骨骼的组合皮肤矩阵进行变换。然后，这四个结果被缩放并相加。

将以下 CPU 皮肤函数添加到`Mesh.cpp`。不要忘记将函数声明添加到`Mesh.h`中：

1.  通过确保网格有效来开始实现`CPUSkin`函数。有效的网格至少有一个顶点。确保`mSkinnedPosition`和`mSkinnedNormal`向量足够大，可以容纳所有顶点：

```cpp
void Mesh::CPUSkin(std::vector<mat4>& animatedPose) {
    unsigned int numVerts = mPosition.size();
    if (numVerts == 0) { 
        return; 
    }
    mSkinnedPosition.resize(numVerts);
    mSkinnedNormal.resize(numVerts);
```

1.  接下来，循环遍历网格中的每个顶点：

```cpp
    for (unsigned int i = 0; i < numVerts; ++i) {
        ivec4& j = mInfluences[i];
        vec4& w = mWeights[i];
```

1.  将每个顶点按动画姿势变换四次，即每个影响顶点的关节变换一次。要找到经过处理的顶点，请将每个变换后的顶点按适当的权重进行缩放并将结果相加：

```cpp
        vec3 p0 = transformPoint(animatedPose[j.x], 
                                 mPosition[i]);
        vec3 p1 = transformPoint(animatedPose[j.y], 
                                 mPosition[i]);
        vec3 p2 = transformPoint(animatedPose[j.z], 
                                 mPosition[i]);
        vec3 p3 = transformPoint(animatedPose[j.w],
                                 mPosition[i]);
        mSkinnedPosition[i] = p0 * w.x + p1 * w.y + 
                              p2 * w.z + p3 * w.w;
```

1.  以相同的方式找到顶点的经过处理的法线：

```cpp
        vec3 n0 = transformVector(animatedPose[j.x], 
                                  mNormal[i]);
        vec3 n1 = transformVector(animatedPose[j.y], 
                                  mNormal[i]);
        vec3 n2 = transformVector(animatedPose[j.z], 
                                  mNormal[i]);
        vec3 n3 = transformVector(animatedPose[j.w], 
                                  mNormal[i]);
        mSkinnedNormal[i] = n0 * w.x + n1 * w.y + 
                            n2 * w.z + n3 * w.w;
    }
```

1.  通过将经过处理的顶点位置和经过处理的顶点法线上传到位置和法线属性来完成函数：

```cpp
    mPosAttrib->Set(mSkinnedPosition);
    mNormAttrib->Set(mSkinnedNormal);
}
```

核心的皮肤算法保持不变；唯一改变的是如何生成变换后的位置。现在，这个函数可以直接使用已经组合好的矩阵，而不必再组合动画姿势和逆绑定姿势。

在下一节中，您将探索如何将这个皮肤函数移入顶点着色器。动画和逆绑定姿势的组合仍然在 CPU 上完成，但实际顶点的皮肤可以在顶点着色器中实现。

## GPU 皮肤

在顶点着色器中实现预乘皮肤矩阵皮肤很简单。用新的预乘皮肤姿势替换姿势和逆绑定姿势的输入统一变量。使用这个新的统一数组生成皮肤矩阵。就是这样——其余的皮肤流程保持不变。

创建一个新文件`preskinned.vert`，来实现新的预皮肤顶点着色器。将`skinned.vert`的内容复制到这个新文件中。按照以下步骤修改新的着色器：

1.  旧的皮肤顶点着色器具有姿势和逆绑定姿势的统一变量。这两个统一变量都是矩阵数组。删除这些统一变量：

```cpp
uniform mat4 pose[120];
uniform mat4 invBindPose[120];
```

1.  用新的`animated`统一替换它们。这是一个矩阵数组，数组中的每个元素都包含`animated`姿势和逆绑定姿势矩阵相乘的结果。

```cpp
uniform mat4 animated[120];
```

1.  接下来，找到生成皮肤矩阵的位置。生成皮肤矩阵的代码如下：

```cpp
mat4 skin = (pose[joints.x] * invBindPose[joints.x]) *
             weights.x;
    skin += (pose[joints.y] * invBindPose[joints.y]) * 
             weights.y;
    skin += (pose[joints.z] * invBindPose[joints.z]) * 
             weights.z;
    skin += (pose[joints.w] * invBindPose[joints.w]) * 
             weights.w;
```

1.  用新的`animated`统一替换这个。对于影响顶点的每个关节，按适当的权重缩放`animated`统一矩阵并求和结果：

```cpp
mat4 skin = animated[joints.x] * weights.x +
            animated[joints.y] * weights.y +
            animated[joints.z] * weights.z +
            animated[joints.w] * weights.w;
```

着色器的其余部分保持不变。您需要更新的唯一内容是着色器接受的统一变量以及如何生成`skin`矩阵。在渲染时，`animated`矩阵可以设置如下：

```cpp
// mPosePalette Generated in the Update method!
int animated = mSkinnedShader->GetUniform("animated")
Uniform<mat4>::Set(animated, mPosePalette);
```

您可能已经注意到 CPU 皮肤实现和 GPU 皮肤实现是不同的。CPU 实现将顶点转换四次，然后缩放和求和结果。GPU 实现缩放和求和矩阵，只转换顶点一次。这两种实现都是有效的，它们都产生相同的结果。

在接下来的部分中，您将探索如何避免使用统一矩阵数组进行皮肤。

# 在纹理中存储皮肤调色板

预生成的皮肤矩阵可以减少所需的统一槽数量，但可以将所需的统一槽数量减少到一个。这可以通过在纹理中编码预生成的皮肤矩阵并在顶点着色器中读取该纹理来实现。

到目前为止，在本书中，您只处理了`RGB24`和`RGBA32`纹理。在这些格式中，每个像素的三个或四个分量使用每个分量 8 位编码。这只能容纳 256 个唯一值。这些纹理无法提供存储浮点数所需的精度。

这里还有另一种可能有用的纹理格式——`FLOAT32`纹理。使用这种纹理格式，向量的每个分量都得到一个完整的 32 位浮点数支持，给您完整的精度。这种纹理可以通过一个特殊的采样器函数进行采样，该函数不对数据进行归一化。`FLOAT32`纹理可以被视为 CPU 可以写入而 GPU 可以读取的缓冲区。

这种方法的好处是所需的统一槽数量变成了一个——所需的统一槽是`FLOAT32`纹理的采样器。缺点是速度。对每个顶点进行纹理采样比快速统一数组查找更昂贵。请记住，每次采样查找都需要返回几个 32 位浮点数。这是大量的数据要传输。

我们不会在这里涵盖存储皮肤矩阵的纹理的实现，因为在*第十五章*“使用实例渲染大规模人群”中有一个专门讨论这个主题的大节，其中包括完整的代码实现。

# 更快的采样

当前的动画剪辑采样代码表现良好，只要每个动画持续时间不超过 1 秒。但是，对于多个长达一分钟的动画剪辑，比如过场动画，动画系统的性能开始受到影响。为什么随着动画时间的增长性能会变差呢？罪魁祸首是`Track::FrameIndex`函数中的以下代码：

```cpp
    for (int i = (int)size - 1; i >= 0; --i) {
        if (time >= mFrames[i].mTime) {
            return i;
        }
    }
```

所呈现的循环遍历了轨道中的每一帧。如果动画有很多帧，性能就会变差。请记住，这段代码是针对动画剪辑中每个动画骨骼的每个动画组件执行的。

这个函数目前进行的是线性搜索，但可以通过更有效的搜索进行优化。由于时间只会增加，执行二分搜索是一个自然的优化。然而，二分搜索并不是最好的优化方法。可以将这个循环转换为常量查找。

采样动画的播放成本是统一的，不受长度的影响。它们在已知的采样间隔时间内计时每一帧，并且找到正确的帧索引只是将提供的时间归一化并将其移动到采样间隔范围内。不幸的是，这样的动画采样占用了大量内存。

如果你仍然按照给定的间隔对动画轨道进行采样，但是每个间隔不再包含完整的姿势，而是指向其左右的关键帧呢？采用这种方法，额外的内存开销是最小的，找到正确的帧是恒定的。

## 优化 Track 类

有两种方法可以优化`Track`类。你可以创建一个具有大部分`Track`类功能并维护已知采样时间的查找表的新类，或者扩展`Track`类。本节采用后一种方法——我们将扩展`Track`类。

`FastTrack`子类包含一个无符号整数向量。`Track`类以统一的时间间隔进行采样。对于每个时间间隔，播放头左侧的帧（即时间之前的帧）被记录到这个向量中。

所有新代码都添加到现有的`Track.h`和`Track.cpp`文件中。按照以下步骤实现`FastTrack`类：

1.  找到`Track`类的`FrameIndex`成员函数，并将其标记为`virtual`。这个改变允许新的子类重新实现`FrameIndex`函数。更新后的声明应该是这样的：

```cpp
template<typename T, int N>
class Track {
// ...
        virtual int FrameIndex(float time, bool looping);
// ...
```

1.  创建一个新类`FastTrack`，它继承自`Track`。`FastTrack`类包含一个无符号整数向量，重载的`FrameIndex`函数和一个用于填充无符号整数向量的函数：

```cpp
template<typename T, int N>
class FastTrack : public Track<T, N> {
protected:
    std::vector<unsigned int> mSampledFrames;
    virtual int FrameIndex(float time, bool looping);
public:
    void UpdateIndexLookupTable();
};
```

1.  为了使`FastTrack`类更易于使用，使用 typedef 为标量、向量和四元数类型创建别名：

```cpp
typedef FastTrack<float, 1> FastScalarTrack;
typedef FastTrack<vec3, 3> FastVectorTrack;
typedef FastTrack<quat, 4> FastQuaternionTrack;
```

1.  在`.cpp`文件中，为标量、向量和四元数的快速轨道添加模板声明：

```cpp
template FastTrack<float, 1>;
template FastTrack<vec3, 3>;
template FastTrack<quat, 4>;
```

由于`FastTrack`类是`Track`的子类，现有的 API 都可以不变地工作。通过以这种方式实现轨道采样，当涉及的动画帧数更多时，性能提升更大。在下一节中，你将学习如何构建索引查找表。

### 实现 UpdateIndexLookupTable

`UpdateIndexLookupTable`函数负责填充`mSampledFrames`向量。这个函数需要以固定的时间间隔对动画进行采样，并记录每个间隔的动画时间之前的帧。

`FastTrack`类应包含多少个样本？这个问题非常依赖于上下文，因为不同的游戏有不同的要求。对于本书的上下文来说，每秒 60 个样本应该足够了：

1.  通过确保轨道有效来开始实现`UpdateIndexLookupTable`函数。有效的轨道至少有两帧：

```cpp
template<typename T, int N>
void FastTrack<T, N>::UpdateIndexLookupTable() {
    int numFrames = (int)this->mFrames.size();
    if (numFrames <= 1) {
        return;
    }
```

1.  接下来，找到所需的样本数。由于每秒动画类有`60`个样本，将持续时间乘以`60`：

```cpp
    float duration = this->GetEndTime() - 
                     this->GetStartTime();
    unsigned int numSamples = duration * 60.0f;
    mSampledFrames.resize(numSamples);
```

1.  对于每个样本，找到沿着轨道的样本时间。要找到时间，将标准化迭代器乘以动画持续时间，并将动画的起始时间加上去：

```cpp
    for (unsigned int i = 0; i < numSamples; ++i) {
        float t = (float)i / (float)(numSamples - 1);
        float time = t*duration+this->GetStartTime();
```

1.  最后，是时候为每个给定的时间找到帧索引了。找到在此迭代中采样时间之前的帧，并将其记录在`mSampledFrames`向量中。如果采样帧是最后一帧，则返回最后一个索引之前的索引。请记住，`FrameIndex`函数永远不应返回最后一帧：

```cpp
        unsigned int frameIndex = 0;
        for (int j = numFrames - 1; j >= 0; --j) {
            if (time >= this->mFrames[j].mTime) {
                frameIndex = (unsigned int)j;
                if ((int)frameIndex >= numFrames - 2) {
                    frameIndex = numFrames - 2;
                }
                break;
            }
        }
        mSampledFrames[i] = frameIndex;
    }
}
```

`UpdateIndexLookupTable`函数旨在在加载时调用。通过记住内部`j`循环的上次使用的索引，可以优化它，因为在每次`i`迭代时，帧索引只会增加。在下一节中，您将学习如何实现`FrameIndex`以使用`mSampledFrames`向量。

### 实现 FrameIndex

`FrameIndex`函数负责找到给定时间之前的帧。优化的`FastTrack`类使用查找数组而不是循环遍历轨道的每一帧。所有输入时间的性能成本非常相似。按照以下步骤重写`FastTrack`类中的`FrameIndex`函数：

1.  通过确保轨道有效来开始实现`FrameIndex`函数。有效的轨道必须至少有两帧或更多：

```cpp
template<typename T, int N>
int FastTrack<T,N>::FrameIndex(float time,bool loop){
    std::vector<Frame<N>>& frames = this->mFrames;
    unsigned int size = (unsigned int)frames.size();
    if (size <= 1) { 
        return -1; 
}
```

1.  接下来，确保请求的采样时间落在轨道的起始时间和结束时间之间。如果轨道循环，使用`fmodf`来保持在有效范围内：

```cpp
    if (loop) {
        float startTime = this->mFrames[0].mTime;
        float endTime = this->mFrames[size - 1].mTime;
        float duration = endTime - startTime;
        time = fmodf(time - startTime, 
                     endTime - startTime);
        if (time < 0.0f) {
            time += endTime - startTime;
        }
        time = time + startTime;
    }
```

1.  如果轨道不循环，将其夹紧到第一帧或倒数第二帧：

```cpp
    else {
        if (time <= frames[0].mTime) {
            return 0;
        }
        if (time >= frames[size - 2].mTime) {
            return (int)size - 2;
        }
    }
```

1.  找到标准化的采样时间和帧索引。帧索引是标准化的采样时间乘以样本数。如果索引无效，则返回`-1`；否则返回索引指向的帧：

```cpp
    float duration = this->GetEndTime() - 
                     this->GetStartTime();
    float t = time / duration;
    unsigned int numSamples = (duration * 60.0f);
    unsigned int index = (t * (float)numSamples);
    if (index >= mSampledFrames.size()) {
        return -1;
    }
    return (int)mSampledFrames[index];
}
```

`FrameIndex`函数几乎总是在有效时间调用，因为它是一个受保护的辅助函数。这意味着找到帧索引所需的时间是均匀的，不管轨道中有多少帧。在下一节中，您将学习如何将未优化的`Track`类转换为优化的`FastTrack`类。

## 转换轨道

现在`FastTrack`存在了，如何创建它呢？您可以创建一个新的加载函数，加载`FastTrack`类而不是`Track`。或者，您可以创建一个将现有的`Track`类转换为`FastTrack`类的函数。本章采用后一种方法。按照以下步骤创建一个将`Track`对象转换为`FastTrack`对象的函数：

1.  在`FastTrack.h`中声明`OptimizeTrack`函数。该函数是模板化的。它接受与`Track`相同的模板类型：

```cpp
template<typename T, int N>
FastTrack<T, N> OptimizeTrack(Track<T, N>& input);
```

1.  在`FastTrack.cpp`中声明`OptimizeTrack`函数的模板特化，以适用于跟踪到`FastTrack`的所有三种类型。这意味着声明适用于标量、三维向量和四元数轨道的特化：

```cpp
template FastTrack<float, 1> 
OptimizeTrack(Track<float, 1>& input);
template FastTrack<vec3, 3> 
OptimizeTrack(Track<vec3, 3>& input);
template FastTrack<quat, 4> 
OptimizeTrack(Track<quat, 4>& input);
```

1.  要实现`OptimizeTrack`函数，调整结果轨道的大小，使其与输入轨道的大小相同并匹配插值。可以使用重载的`[]`运算符函数来复制每帧的数据：

```cpp
template<typename T, int N>
FastTrack<T, N> OptimizeTrack(Track<T, N>& input) {
    FastTrack<T, N> result;
    result.SetInterpolation(input.GetInterpolation());
    unsigned int size = input.Size();
    result.Resize(size);
    for (unsigned int i = 0; i < size; ++i) {
        result[i] = input[i];
    }
    result.UpdateIndexLookupTable();
    return result;
}
```

仅仅将`Track`类优化为`FastTrack`还不够。`TransformTrack`类也需要改变。它需要包含新的、优化的`FastTrack`类。在下一节中，您将更改`TransformTrack`类，使其成为模板，并且可以包含`Track`或`FastTrack`。

## 创建 FastTransformTrack

使用`Track`类的高级结构，如`TransformTrack`，需要适应新的`FastTrack`子类。`FastTrack`类与`Track`类具有相同的签名。因为类的签名相同，很容易将`TransformTrack`类模板化，以便它可以使用这两个类中的任何一个。

在这一部分，您将把`TransformTrack`类的名称更改为`TTransformTrack`并对类进行模板化。然后，您将将模板特化 typedef 为`TransformTrack`和`FastTransformTrack`。这样，`TransformTrack`类保持不变，优化的变换轨迹使用相同的代码：

1.  将`TransformTrack`类的名称更改为`TTransformTrack`并对类进行模板化。模板接受两个参数——要使用的矢量轨迹的类型和四元数轨迹的类型。更新`mPosition`、`mRotation`和`mScale`轨迹以使用新的模板类型：

```cpp
template <typename VTRACK, typename QTRACK>
class TTransformTrack {
protected:
   unsigned int mId;
   VTRACK mPosition;
   QTRACK mRotation;
   VTRACK mScale;
public:
   TTransformTrack();
   unsigned int GetId();
   void SetId(unsigned int id);
   VTRACK& GetPositionTrack();
   QTRACK& GetRotationTrack();
   VTRACK& GetScaleTrack();
   float GetStartTime();
   float GetEndTime();
   bool IsValid();
   Transform Sample(const Transform& r,float t,bool l);
};
```

1.  将这个类 typedef 为`TransformTrack`，使用`VectorTrack`和`QuaternionTrack`作为参数。再次将其 typedef 为`FastTransformTrack`，使用`FastVectorTrack`和`FastQuaternionTrack`作为模板参数：

```cpp
typedef TTransformTrack<VectorTrack, 
    QuaternionTrack> TransformTrack;
typedef TTransformTrack<FastVectorTrack, 
    FastQuaternionTrack> FastTransformTrack;
```

1.  声明将`TransformTrack`转换为`FastTransformTrack`的优化函数：

```cpp
FastTransformTrack OptimizeTransformTrack(
                   TransformTrack& input);
```

1.  在`TransformTrack.cpp`中为`typedef`函数添加模板规范：

```cpp
template TTransformTrack<VectorTrack, QuaternionTrack>;
template TTransformTrack<FastVectorTrack, 
                         FastQuaternionTrack>;
```

1.  实现`OptimizeTransformTrack`函数。复制轨迹 ID，然后通过值复制各个轨迹：

```cpp
FastTransformTrack OptimizeTransformTrack(
                   TransformTrack& input) {
    FastTransformTrack result;
    result.SetId(input.GetId());
    result.GetPositionTrack()= OptimizeTrack<vec3, 3> (
                             input.GetPositionTrack());
    result.GetRotationTrack() = OptimizeTrack<quat, 4>(
                             input.GetRotationTrack());
    result.GetScaleTrack()  =  OptimizeTrack<vec3, 3> (
                                input.GetScaleTrack());
    return result;
}
```

因为`OptimizeTransformTrack`通过值复制实际轨迹数据，所以它可能会有点慢。这个函数打算在初始化时调用。在下一节中，您将对`Clip`类进行模板化，类似于您对`Transform`类的操作，以创建`FastClip`。

## 创建 FastClip

这个动画系统的用户与`Clip`对象进行交互。为了适应新的`FastTrack`类，`Clip`类同样被模板化并分成了`Clip`和`FastClip`。您将实现一个函数来将`Clip`对象转换为`FastClip`对象。按照以下步骤对`Clip`类进行模板化：

1.  将`Clip`类的名称更改为`TClip`并对类进行模板化。模板只接受一种类型——`TClip`类包含的变换轨迹的类型。更改`mTracks`的类型和`[] operator`的返回类型，使其成为模板类型：

```cpp
template <typename TRACK>
class TClip {
protected:
    std::vector<TRACK> mTracks;
    std::string mName;
    float mStartTime;
    float mEndTime;
    bool mLooping;
public:
    TClip();
    TRACK& operator[](unsigned int index);
// ...
```

1.  使用`TransformTrack`类型将`TClip`typedef 为`Clip`。使用`FastTransformTrack`类型将`TClip`typedef 为`FastClip`。这样，`Clip`类不会改变，而`FastClip`类可以重用所有现有的代码：

```cpp
typedef TClip<TransformTrack> Clip;
typedef TClip<FastTransformTrack> FastClip;
```

1.  声明一个将`Clip`对象转换为`FastClip`对象的函数：

```cpp
FastClip OptimizeClip(Clip& input);
```

1.  在`Clip.cpp`中声明这些 typedef 类的模板特化：

```cpp
template TClip<TransformTrack>;
template TClip<FastTransformTrack>;
```

1.  要实现`OptimizeClip`函数，复制输入剪辑的名称和循环值。对于剪辑中的每个关节，调用其轨迹上的`OptimizeTransformTrack`函数。在返回副本之前，不要忘记计算新的`FastClip`对象的持续时间：

```cpp
FastClip OptimizeClip(Clip& input) {
    FastClip result;
    result.SetName(input.GetName());
    result.SetLooping(input.GetLooping());
    unsigned int size = input.Size();
    for (unsigned int i = 0; i < size; ++i) {
        unsigned int joint = input.GetIdAtIndex(i);
        result[joint] = 
              OptimizeTransformTrack(input[joint]);
    }
    result.RecalculateDuration();
    return result;
}
```

与其他转换函数一样，`OptimizeClip`只打算在初始化时调用。在接下来的部分，您将探讨如何优化`Pose`调色板的生成。

# 姿势调色板生成

您应该考虑的最终优化是从`Pose`生成矩阵调色板的过程。如果您查看`Pose`类，下面的代码将一个姿势转换为矩阵的线性数组：

```cpp
void Pose::GetMatrixPalette(std::vector<mat4>& out) {
    unsigned int size = Size();
    if (out.size() != size) {
        out.resize(size);
    }
    for (unsigned int i = 0; i < size; ++i) {
        Transform t = GetGlobalTransform(i);
        out[i] = transformToMat4(t);
    }
}
```

单独看，这个函数并不太糟糕，但`GetGlobalTransform`函数会循环遍历每个关节，一直到根关节的指定关节变换链。这意味着该函数会浪费大量时间来查找在上一次迭代期间已经找到的变换矩阵。

要解决这个问题，您需要确保`Pose`类中关节的顺序是升序的。也就是说，所有父关节在`mJoints`数组中的索引必须低于它们的子关节。

一旦设置了这个顺序，你可以遍历所有的关节，并知道当前索引处的关节的父矩阵已经找到。这是因为所有的父元素的索引都比它们的子节点小。为了将该关节的局部矩阵与其父关节的全局矩阵合并，你只需要将之前找到的世界矩阵和局部矩阵相乘。

不能保证输入数据可以信任地按照特定顺序列出关节。为了解决这个问题，你需要编写一些代码来重新排列`Pose`类的关节。在下一节中，你将学习如何改进`GetMatrixPalette`函数，使其在可能的情况下使用优化的方法，并在不可能的情况下退回到未优化的方法。

## 改变 GetMatrixPalette 函数

在本节中，你将修改`GetMatrixPalette`函数，以便在当前关节的父索引小于关节时预缓存全局矩阵。如果这个假设被打破，函数需要退回到更慢的计算模式。

`GetMatrixPalette`函数中将有两个循环。第一个循环找到并存储变换的全局矩阵。如果关节的父节点索引小于关节，就使用优化的方法。如果关节的父节点不小，第一个循环中断，并给第二个循环一个运行的机会。

在第二个循环中，每个关节都会退回到调用缓慢的`GetWorldTransform`函数来找到它的世界变换。如果优化的循环执行到最后，这个第二个循环就不会执行：

```cpp
void Pose::GetMatrixPalette(std::vector<mat4>& out) {
    int size = (int)Size();
    if ((int)out.size() != size) { out.resize(size); }
    int i = 0;
    for (; i < size; ++i) {
        int parent = mParents[i];
        if (parent > i) { break; }
        mat4 global = transformToMat4(mJoints[i]);
        if (parent >= 0) {
            global = out[parent] * global;
        }
        out[i] = global;
    }
    for (; i < size; ++i) {
        Transform t = GetGlobalTransform(i);
        out[i] = transformToMat4(t);
    }
}
```

这个改变对`GetMatrixPalette`函数的开销非常小，但很快就能弥补。它使得矩阵调色板计算运行快速，如果可能的话，但即使不可能也会执行。在接下来的部分，你将学习如何重新排列加载模型的关节，以便`GetMatrixPalette`函数始终采用快速路径。

## 重新排序关节

并非所有的模型都会格式良好；因此，它们不都能够利用优化的`GetMatrixPalette`函数。在本节中，你将学习如何重新排列模型的骨骼，以便它可以利用优化的`GetMatrixPalette`函数。

创建一个新文件`RearrangeBones.h`。使用一个字典，其键值对是骨骼索引和重新映射的骨骼索引。`RearrangeSkeleton`函数生成这个字典，并重新排列骨骼的绑定、逆绑定和静止姿势。

一旦`RearrangeSkeleton`函数生成了`BoneMap`，你可以使用它来处理任何影响当前骨骼的网格或动画片段。按照以下步骤重新排序关节，以便骨骼始终可以利用优化的`GetMatrixPalette`路径：

1.  将以下函数声明添加到`RearrangeBones.h`文件中：

```cpp
typedef std::map<int, int> BoneMap;
BoneMap RearrangeSkeleton(Skeleton& skeleton);
void RearrangeMesh(Mesh& mesh, BoneMap& boneMap);
void RearrangeClip(Clip& clip, BoneMap& boneMap);
void RearrangeFastclip(FastClip& clip, BoneMap& boneMap);
```

1.  在一个新文件`ReearrangeBones.cpp`中开始实现`RearrangeSkeleton`函数。首先，创建对静止和绑定姿势的引用，然后确保你要重新排列的骨骼不是空的。如果是空的，就返回一个空的字典：

```cpp
BoneMap RearrangeSkeleton(Skeleton& skeleton) {
    Pose& restPose = skeleton.GetRestPose();
    Pose& bindPose = skeleton.GetBindPose();
    unsigned int size = restPose.Size();
    if (size == 0) { return BoneMap(); }
```

1.  接下来，创建一个二维整数数组（整数向量的向量）。外部向量的每个元素代表一个骨骼，该向量和绑定或静止姿势中的`mJoints`数组的索引是平行的。内部向量表示外部向量索引处的关节包含的所有子节点。循环遍历静止姿势中的每个关节：

```cpp
    std::vector<std::vector<int>> hierarchy(size);
    std::list<int> process;
    for (unsigned int i = 0; i < size; ++i) {
        int parent = restPose.GetParent(i);
```

1.  如果一个关节有父节点，将该关节的索引添加到父节点的子节点向量中。如果一个节点是根节点（没有父节点），直接将其添加到处理列表中。稍后将使用该列表来遍历地图深度：

```cpp
        if (parent >= 0) {
            hierarchy[parent].push_back((int)i);
        }
        else {
            process.push_back((int)i);
        }
    }
```

1.  要弄清楚如何重新排序骨骼，你需要保留两个映射——一个从旧配置映射到新配置，另一个从新配置映射回旧配置：

```cpp
    BoneMap mapForward;
    BoneMap mapBackward;
```

1.  对于每个元素，如果它包含子元素，则将子元素添加到处理列表中。这样，所有的关节都被处理，层次结构中较高的关节首先被处理：

```cpp
    int index = 0;
    while (process.size() > 0) {
        int current = *process.begin();
        process.pop_front();
        std::vector<int>& children = hierarchy[current];
        unsigned int numChildren = children.size();
        for (unsigned int i = 0; i < numChildren; ++i) {
            process.push_back(children[i]);
        }
```

1.  将正向映射的当前索引设置为正在处理的关节的索引。正向映射的当前索引是一个原子计数器。对于反向映射也是同样的操作，但是要交换键值对。不要忘记将空节点（`-1`）添加到两个映射中：

```cpp
        mapForward[index] = current;
        mapBackward[current] = index;
        index += 1;
    }
    mapForward[-1] = -1;
    mapBackward[-1] = -1;
```

1.  现在映射已经填充，您需要构建新的静止和绑定姿势，使其骨骼按正确的顺序排列。循环遍历原始静止和绑定姿势中的每个关节，并将它们的本地变换复制到新的姿势中。对于关节名称也是同样的操作：

```cpp
    Pose newRestPose(size);
    Pose newBindPose(size);
    std::vector<std::string> newNames(size);
    for (unsigned int i = 0; i < size; ++i) {
        int thisBone = mapForward[i];
        newRestPose.SetLocalTransform(i, 
                restPose.GetLocalTransform(thisBone));
        newBindPose.SetLocalTransform(i, 
                bindPose.GetLocalTransform(thisBone));
        newNames[i] = skeleton.GetJointName(thisBone);
```

1.  为每个关节找到新的父关节 ID 需要两个映射步骤。首先，将当前索引映射到原始骨架中的骨骼。这将返回原始骨架的父关节。将此父索引映射回新骨架。这就是为什么有两个字典，以便进行快速映射：

```cpp
        int parent = mapBackward[bindPose.GetParent(
                                         thisBone)];
        newRestPose.SetParent(i, parent);
        newBindPose.SetParent(i, parent);
    }
```

1.  一旦找到新的静止和绑定姿势，并且关节名称已经相应地重新排列，通过调用公共的`Set`方法将这些数据写回骨架。骨架的`Set`方法还会计算逆绑定姿势矩阵调色板：

```cpp
    skeleton.Set(newRestPose, newBindPose, newNames);
    return mapBackward;
} // End of RearrangeSkeleton function
```

`RearrangeSkeleton`函数重新排列骨架中的骨骼，以便骨架可以利用`GetMatrixPalette`的优化版本。重新排列骨架是不够的。由于关节索引移动，引用该骨架的任何剪辑或网格现在都是损坏的。在下一节中，您将实现辅助函数来重新排列剪辑中的关节。

## 重新排序剪辑

要重新排列动画剪辑，循环遍历剪辑中的所有轨道。对于每个轨道，找到关节 ID，然后使用`RearrangeSkeleton`函数返回的（反向）骨骼映射转换该关节 ID。将修改后的关节 ID 写回到轨道中：

```cpp
void RearrangeClip(Clip& clip, BoneMap& boneMap) {
    unsigned int size = clip.Size();
    for (unsigned int i = 0; i < size; ++i) {
        int joint = (int)clip.GetIdAtIndex(i);
        unsigned int newJoint = (unsigned int)boneMap[joint];
        clip.SetIdAtIndex(i, newJoint);
    }
}
```

如果您之前在本章中实现了`FastClip`优化，`RearrangeClip`函数应该仍然有效，因为它是`Clip`的子类。在下一节中，您将学习如何重新排列网格中的关节，这将是使用此优化所需的最后一步。

## 重新排序网格

要重新排列影响网格蒙皮的关节，循环遍历网格的每个顶点，并重新映射该顶点的影响属性中存储的四个关节索引。关节的权重不需要编辑，因为关节本身没有改变；只是其数组中的索引发生了变化。

以这种方式更改网格只会编辑网格的 CPU 副本。调用`UpdateOpenGLBuffers`将新属性上传到 GPU：

```cpp
void RearrangeMesh(Mesh& mesh, BoneMap& boneMap) {
    std::vector<ivec4>& influences = mesh.GetInfluences();
    unsigned int size = (unsigned int)influences.size();
    for (unsigned int i = 0; i < size; ++i) {
        influences[i].x = boneMap[influences[i].x];
        influences[i].y = boneMap[influences[i].y];
        influences[i].z = boneMap[influences[i].z];
        influences[i].w = boneMap[influences[i].w];
    }
    mesh.UpdateOpenGLBuffers();
}
```

实现了`RearrangeMesh`函数后，您可以加载一个骨架，然后调用`RearrangeSkeleton`函数并存储它返回的骨骼映射。使用这个骨骼映射，您还可以使用`RearrangeClip`和`RearrangeMesh`函数修复引用骨架的任何网格或动画剪辑。经过这种方式处理后，`GetMatrixPalette`始终采用优化路径。在下一节中，您将探索在层次结构中缓存变换。

# 探索 Pose::GetGlobalTransform

`Pose`类的`GetGlobalTransform`函数的一个特点是它总是计算世界变换。考虑这样一种情况，您请求一个节点的世界变换，然后立即请求其父节点的世界变换。原始请求计算并使用父节点的世界变换，但一旦下一个请求被发出，同样的变换就会再次计算。

解决这个问题的方法是向`Pose`类添加两个新数组。一个是世界空间变换的向量，另一个包含脏标志。每当设置关节的本地变换时，关节的脏标志需要设置为`true`。

当请求世界变换时，会检查变换及其所有父级的脏标志。如果该链中有脏变换，则重新计算世界变换。如果脏标志未设置，则返回缓存的世界变换。

本章不会实现这个优化。这个优化会给`Pose`类的每个实例增加大量的内存。除了逆向运动学的情况，`GetGlobalTransform`函数很少被使用。对于蒙皮，`GetMatrixPalette`函数用于检索世界空间矩阵，而该函数已经被优化过了。

# 总结

在本章中，你探索了如何针对几种情况优化动画系统。这些优化减少了顶点蒙皮着色器所需的统一变量数量，加快了具有许多关键帧的动画的采样速度，并更快地生成了姿势的矩阵调色板。

请记住，没有一种大小适合所有的解决方案。如果游戏中的所有动画都只有几个关键帧，那么通过查找表优化动画采样所增加的开销可能不值得额外的内存。然而，改变采样函数以使用二分查找可能是值得的。每种优化策略都存在类似的利弊；你必须选择适合你特定用例的方案。

在查看本章的示例代码时，`Chapter11/Sample00`包含了本章的全部代码。`Chapter11/Sample01`展示了如何使用预蒙皮网格，`Chapter11/Sample02`展示了如何使用`FastTrack`类进行更快的采样，`Chapter11/Sample03`展示了如何重新排列骨骼以加快调色板的生成。

在下一章中，你将探索如何混合动画以平滑地切换两个动画。本章还将探讨修改现有动画的混合技术。
