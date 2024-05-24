# C++ 游戏动画编程实用指南（二）

> 原文：[`annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b`](https://annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：实现变换

在本章中，您将实现一个包含位置、旋转和缩放数据的结构。这个结构就是一个变换。变换将一个空间映射到另一个空间。位置、旋转和缩放也可以存储在 4x4 矩阵中，那么为什么要使用显式的变换结构而不是矩阵？答案是插值。矩阵的插值效果不好，但变换结构可以。

在两个矩阵之间进行插值是困难的，因为旋转和缩放存储在矩阵的相同组件中。因此，在两个矩阵之间进行插值不会产生您期望的结果。变换通过分别存储位置、旋转和缩放组件来解决了这个问题。

在本章中，您将实现一个变换结构以及您需要执行的常见操作。在本章结束时，您应该能够做到以下事情：

+   理解什么是变换

+   理解如何组合变换

+   在变换和矩阵之间进行转换

+   理解如何将变换应用到点和向量

重要信息

在本章中，您将实现一个表示位置、旋转和缩放的变换结构。要了解更多关于变换，它们与矩阵的关系以及它们如何适应游戏层次结构，请访问[`gabormakesgames.com/transforms.html`](http://gabormakesgames.com/transforms.html)。

# 创建变换。

变换是简单的结构。一个变换包含一个位置、旋转和缩放。位置和缩放是向量，旋转是四元数。变换可以按层次结构组合，但这种父子关系不应该是实际变换结构的一部分。以下步骤将指导您创建一个变换结构：

1.  创建一个新文件，`Transform.h`。这个文件是必需的，用来声明变换结构。

1.  在这个新文件中声明`Transform`结构。从变换的属性—`position`、`rotation`和`scale`开始：

```cpp
struct Transform {
    vec3 position;
    quat rotation;
    vec3 scale;
```

1.  创建一个构造函数，它接受一个位置、旋转和缩放。这个构造函数应该将这些值分配给`Transform`结构的适当成员：

```cpp
Transform(const vec3& p, const quat& r, const vec3& s) :
    position(p), rotation(r), scale(s) {}
```

1.  空变换不应该有位置或旋转，缩放为 1。默认情况下，`scale`组件将被创建为`(0, 0, 0)`。为了解决这个问题，`Transform`结构的默认构造函数需要将`scale`初始化为正确的值：

```cpp
    Transform() :
        position(vec3(0, 0, 0)),
        rotation(quat(0, 0, 0, 1)),
        scale(vec3(1, 1, 1))
    {}
}; // End of transform struct
```

`Transform`结构非常简单；它的所有成员都是公共的。一个变换有一个位置、旋转和缩放。默认构造函数将位置向量设置为*0*，将旋转四元数设置为单位，将缩放向量设置为*1*。默认构造函数创建的变换没有效果。

在下一节中，您将学习如何以与矩阵或四元数类似的方式组合变换。

# 组合变换

以骨架为例。在每个关节处，您可以放置一个变换来描述关节的运动。当您旋转肩膀时，连接到该肩膀的肘部也会移动。要将肩部变换应用于所有连接的关节，必须将每个关节上的变换与其父关节的变换相结合。

变换可以像矩阵和四元数一样组合，并且两个变换的效果可以组合成一个变换。为保持一致，组合变换应保持从右到左的组合顺序。与矩阵和四元数不同，这个`combine`函数不会被实现为一个乘法函数。

组合两个变换的缩放和旋转很简单—将它们相乘。组合位置有点困难。组合位置需要受到`rotation`和`scale`组件的影响。在找到组合位置时，记住变换的顺序：先缩放，然后旋转，最后平移。

创建一个新文件，`Transform.cpp`。实现`combine`函数，并不要忘记将函数声明添加到`Transform.h`中：

```cpp
Transform combine(const Transform& a, const Transform& b) {
    Transform out;
    out.scale = a.scale * b.scale;
    out.rotation = b.rotation * a.rotation;
    out.position = a.rotation * (a.scale * b.position);
    out.position = a.position + out.position;
    return out;
}
```

在后面的章节中，`combine`函数将用于将变换组织成层次结构。在下一节中，你将学习如何反转变换，这与反转矩阵和四元数类似。

# 反转变换

你已经知道变换将一个空间映射到另一个空间。可以反转该映射，并将变换映射回原始空间。与矩阵和四元数一样，变换也可以被反转。

在反转缩放时，请记住 0 不能被反转。缩放为 0 的情况需要特殊处理。

在`Transform.cpp`中实现`inverse`变换方法。不要忘记在`Transform.h`中声明该方法：

```cpp
Transform inverse(const Transform& t) {
    Transform inv;
    inv.rotation = inverse(t.rotation);
    inv.scale.x = fabs(t.scale.x) < VEC3_EPSILON ? 
                  0.0f : 1.0f / t.scale.x;
    inv.scale.y = fabs(t.scale.y) < VEC3_EPSILON ? 
                  0.0f : 1.0f / t.scale.y;
    inv.scale.z = fabs(t.scale.z) < VEC3_EPSILON ? 
                  0.0f : 1.0f / t.scale.z;
    vec3 invTrans = t.position * -1.0f;
    inv.position = inv.rotation * (inv.scale * invTrans);
    return inv;
}
```

反转变换可以消除一个变换对另一个变换的影响。考虑一个角色在关卡中移动。一旦关卡结束，你可能希望将角色移回原点，然后开始下一个关卡。你可以将角色的变换乘以它的逆变换。

在下一节中，你将学习如何将两个或多个变换混合在一起。

# 混合变换

你有代表两个特定时间点的关节的变换。为了使模型看起来动画化，你需要在这些帧的变换之间进行插值或混合。

可以在向量和四元数之间进行插值，这是变换的构建块。因此，也可以在变换之间进行插值。这个操作通常被称为混合。当将两个变换混合在一起时，线性插值输入变换的位置、旋转和缩放。

在`Transform.cpp`中实现`mix`函数。不要忘记在`Transform.h`中声明该函数：

```cpp
Transform mix(const Transform& a,const Transform& b,float t){
    quat bRot = b.rotation;
    if (dot(a.rotation, bRot) < 0.0f) {
        bRot = -bRot;
    }
    return Transform(
        lerp(a.position, b.position, t),
        nlerp(a.rotation, bRot, t),
        lerp(a.scale, b.scale, t));
}
```

能够将变换混合在一起对于创建动画之间的平滑过渡非常重要。在这里，你实现了变换之间的线性混合。在下一节中，你将学习如何将`transform`转换为`mat4`。

# 将变换转换为矩阵

着色器程序与矩阵配合得很好。它们没有本地表示变换结构。你可以将变换代码转换为 GLSL，但这不是最好的解决方案。相反，你可以在将变换提交为着色器统一之前将变换转换为矩阵。

由于变换编码了可以存储在矩阵中的数据，因此可以将变换转换为矩阵。要将变换转换为矩阵，需要考虑矩阵的向量。

首先，通过将全局基向量的方向乘以变换的旋转来找到基向量。接下来，通过变换的缩放来缩放基向量。这将产生填充上 3x3 子矩阵的最终基向量。位置直接进入矩阵的最后一列。

在`Transform.cpp`中实现`from Transform`方法。不要忘记将该方法声明到`Transform.h`中：

```cpp
mat4 transformToMat4(const Transform& t) {
    // First, extract the rotation basis of the transform
    vec3 x = t.rotation * vec3(1, 0, 0);
    vec3 y = t.rotation * vec3(0, 1, 0);
    vec3 z = t.rotation * vec3(0, 0, 1);
    // Next, scale the basis vectors
    x = x * t.scale.x;
    y = y * t.scale.y;
    z = z * t.scale.z;
    // Extract the position of the transform
    vec3 p = t.position;
    // Create matrix
    return mat4(
        x.x, x.y, x.z, 0, // X basis (& Scale)
        y.x, y.y, y.z, 0, // Y basis (& scale)
        z.x, z.y, z.z, 0, // Z basis (& scale)
        p.x, p.y, p.z, 1  // Position
    );
}
```

图形 API 使用矩阵而不是变换。在后面的章节中，变换将在发送到着色器之前转换为矩阵。在下一节中，你将学习如何做相反的操作，即将矩阵转换为变换。

# 将矩阵转换为变换

外部文件格式可能将变换数据存储为矩阵。例如，glTF 可以将节点的变换存储为位置、旋转和缩放，或者作为单个 4x4 矩阵。为了使变换代码健壮，你需要能够将矩阵转换为变换。

将矩阵转换为变换比将变换转换为矩阵更困难。提取矩阵的旋转很简单；你已经实现了将 4x4 矩阵转换为四元数的函数。提取位置也很简单；将矩阵的最后一列复制到一个向量中。提取比例尺更困难。

回想一下，变换的操作顺序是先缩放，然后旋转，最后平移。这意味着如果你有三个矩阵——*S*、*R*和*T*——分别代表缩放、旋转和平移，它们将组合成一个变换矩阵*M*，如下所示：

*M = SRT*

要找到比例尺，首先忽略矩阵的平移部分*M*（将平移向量归零）。这样你就得到*M = SR*。要去除矩阵的旋转部分，将*M*乘以*R*的逆。这样应该只剩下比例尺部分。嗯，并不完全是这样。结果会留下一个包含比例尺和一些倾斜信息的矩阵。

我们从这个比例尺-倾斜矩阵中提取比例尺的方法是简单地将主对角线作为比例尺-倾斜矩阵。虽然这在大多数情况下都有效，但并不完美。获得的比例尺应该被视为有损的比例尺，因为该值可能包含倾斜数据，这使得比例尺不准确。

重要提示

将矩阵分解为平移、旋转、缩放、倾斜和行列式的符号是可能的。然而，这种分解是昂贵的，不太适合实时应用。要了解更多，请查看 Ken Shoemake 和 Tom Duff 的*Matrix Animation and Polar Decomposition* [`research.cs.wisc.edu/graphics/Courses/838-s2002/Papers/polar-decomp.pdf`](https://research.cs.wisc.edu/graphics/Courses/838-s2002/Papers/polar-decomp.pdf)。

在`Transform.cpp`中实现`toTransform`函数。不要忘记将函数声明添加到`Transform.h`中：

```cpp
Transform mat4ToTransform(const mat4& m) {
    Transform out;
    out.position = vec3(m.v[12], m.v[13], m.v[14]);
    out.rotation = mat4ToQuat(m);
    mat4 rotScaleMat(
        m.v[0], m.v[1], m.v[2], 0,
        m.v[4], m.v[5], m.v[6], 0,
        m.v[8], m.v[9], m.v[10], 0,
        0, 0, 0, 1
    );
    mat4 invRotMat = quatToMat4(inverse(out.rotation));
    mat4 scaleSkewMat = rotScaleMat * invRotMat;
    out.scale = vec3(
        scaleSkewMat.v[0], 
        scaleSkewMat.v[5], 
        scaleSkewMat.v[10]
    );
    return out;
}
```

能够将矩阵转换为变换是很重要的，因为你并不总是能控制你处理的数据以什么格式呈现。例如，一个模型格式可能存储矩阵而不是变换。

到目前为止，你可能已经注意到变换和矩阵通常可以做相同的事情。在下一节中，你将学习如何使用变换来对点和向量进行变换，类似于使用矩阵的方式。

# 变换点和向量

`Transform`结构可用于在空间中移动点和向量。想象一个球上下弹跳。球的弹跳是由`Transform`结构派生的，但你如何知道每个球的顶点应该移动到哪里？你需要使用`Transform`结构（或矩阵）来正确显示球的所有顶点。

使用变换来修改点和向量就像组合两个变换。要变换一个点，首先应用缩放，然后旋转，最后是变换的平移。要变换一个向量，遵循相同的步骤，但不要添加位置：

1.  在`Transform.cpp`中实现`transformPoint`函数。不要忘记将函数声明添加到`Transform.h`中：

```cpp
vec3 transformPoint(const Transform& a, const vec3& b) {
    vec3 out;
    out = a.rotation * (a.scale * b);
    out = a.position + out;
    return out;
}
```

1.  在`Transform.cpp`中实现`transformVector`函数。不要忘记将函数声明添加到`Transform.h`中：

```cpp
vec3 transformVector(const Transform& a, const vec3& b) {
    vec3 out;
    out = a.rotation * (a.scale * b);
    return out;
}
```

`transformPoint`函数做的就是一个一个步骤地将矩阵和点相乘。首先应用`scale`，然后是`rotation`，最后是`translation`。当处理向量而不是点时，同样的顺序适用，只是忽略了平移。

# 总结

在本章中，你学会了将变换实现为一个包含位置、旋转和比例尺的离散结构。在许多方面，`Transform`类保存了你通常会存储在矩阵中的相同数据。

你学会了如何组合、反转和混合变换，以及如何使用变换来移动点和旋转向量。变换在未来将是至关重要的，因为它们用于动画游戏模型的骨骼或骨架。

你需要一个显式的`Transform`结构的原因是矩阵不太容易插值。对变换进行插值对于动画非常重要。这是你创建中间姿势以显示两个给定关键帧的方式。

在下一章中，你将学习如何在 OpenGL 之上编写一个轻量级的抽象层，以使未来章节中的渲染更容易。


# 第六章：构建抽象渲染器

本书侧重于动画，而不是渲染。然而，渲染动画模型是很重要的。为了避免陷入任何特定的图形 API 中，在本章中，您将在 OpenGL 之上构建一个抽象层。这将是一个薄的抽象层，但它将让您在后面的章节中处理动画，而无需执行任何特定于 OpenGL 的操作。

本章中您将实现的抽象渲染器非常轻量。它没有很多功能，只有您需要显示动画模型的功能。这应该使得将渲染器移植到其他 API 变得简单。

在本章结束时，您应该能够使用您创建的抽象渲染代码在窗口中渲染一些调试几何体。在更高的层次上，您将学到以下内容：

+   如何创建着色器

+   如何在缓冲区中存储网格数据

+   如何将这些缓冲区绑定为着色器属性

+   如何向着色器发送统一数据

+   如何使用索引缓冲区进行渲染

+   如何加载纹理

+   基本的 OpenGL 概念

+   创建和使用简单的着色器

# 技术要求

对 OpenGL 的一些了解将使本章更容易理解。OpenGL、光照模型和着色器技巧不在本书的范围之内。有关这些主题的更多信息，请访问[`learnopengl.com/`](https://learnopengl.com/)。

# 使用着色器

抽象层中最重要的部分是`Shader`类。要绘制某物，您必须绑定一个着色器并将一些属性和统一附加到它上。着色器描述了被绘制的东西应该如何变换和着色，而属性定义了正在被绘制的内容。

在本节中，您将实现一个`Shader`类，它可以编译顶点和片段着色器。`Shader`类还将返回统一和属性索引。

## 着色器类声明

在实现`Shader`类时，您需要声明几个受保护的辅助函数。这些函数将保持类的公共 API 清晰；它们用于诸如将文件读入字符串或调用 OpenGL 代码来编译着色器的操作：

1.  创建一个新文件来声明`Shader`类，命名为`Shader.h`。`Shader`类应该有一个指向 OpenGL 着色器对象的句柄，以及属性和统一索引的映射。这些字典有一个字符串作为键（属性或统一的名称）和一个`unsigned int`作为值（统一或属性的索引）：

```cpp
class Shader {
private:
    unsigned int mHandle;
    std::map<std::string, unsigned int> mAttributes;
    std::map<std::string, unsigned int> mUniforms;
```

1.  `Shader`类的复制构造函数和赋值运算符应该被禁用。`Shader`类不打算通过值进行复制，因为它持有一个 GPU 资源的句柄：

```cpp
private:
    Shader(const Shader&);
    Shader& operator=(const Shader&);
```

1.  接下来，您需要在`Shader`类中声明辅助函数。`ReadFile`函数将文件内容读入`std::string`中。`CompileVertexShader`和`CompileFragmentShader`函数编译着色器源代码并返回 OpenGL 句柄。`LinkShader`函数将两个着色器链接成一个着色器程序。`PopulateAttribute`和`PopulateUniform`函数将填充属性和统一字典：

```cpp
private:
    std::string ReadFile(const std::string& path);
    unsigned int CompileVertexShader(
                     const std::string& vertex);
    unsigned int CompileFragmentShader(
                     const std::string& fragment);
    bool LinkShaders(unsigned int vertex, 
                     unsigned int fragment);
    void PopulateAttributes();
    void PopulateUniforms();
```

1.  类的默认构造函数将创建一个空的`Shader`对象。重载构造函数将调用`Load`方法，从文件加载着色器并编译它们。析构函数将释放`Shader`类持有的 OpenGL 着色器句柄：

```cpp
public:
    Shader();
    Shader(const std::string& vertex, 
           const std::string& fragment);
    ~Shader();
    void Load(const std::string& vertex, 
              const std::string& fragment);
```

1.  在使用着色器之前，需要使用`Bind`函数绑定它。同样，在不再使用时，可以使用`UnBind`函数解绑它。`GetAttribute`和`GetUniform`函数在适当的字典中执行查找。`GetHandle`函数返回着色器的 OpenGL 句柄：

```cpp
    void Bind();
    void UnBind();
    unsigned int GetAttribute(const std::string& name);
    unsigned int GetUniform(const std::string& name);
    unsigned int GetHandle();
};
```

现在`Shader`类声明完成后，您将在下一节中实现它。

## 实现着色器类

创建一个新文件`Shader.cpp`，来实现`Shader`类。`Shader`类的实现几乎将所有实际的 OpenGL 代码隐藏在调用者之外。因为大多数 OpenGL 调用都是通过这种方式抽象的，在后面的章节中，您只需要调用抽象层，而不是直接调用 OpenGL 函数。

本书中始终使用统一数组。当在着色器中遇到统一数组（例如`modelMatrices[120]`），`glGetActiveUniform`返回的统一名称是数组的第一个元素。在这个例子中，那将是`modelMatrices[0]`。当遇到统一数组时，您希望循环遍历所有数组索引，并为每个元素获取显式的统一索引，但您还希望存储没有任何下标的统一名称：

1.  两个`Shader`构造函数必须通过调用`glCreateProgram`创建一个新的着色器程序句柄。接受两个字符串的构造函数变体调用`Load`函数处理这些字符串。由于`mHandle`始终是一个程序句柄，析构函数需要删除该句柄：

```cpp
Shader::Shader() {
    mHandle = glCreateProgram();
}
Shader::Shader(const std::string& vertex, 
               const std::string& fragment) {
    mHandle = glCreateProgram();
    Load(vertex, fragment);
}
Shader::~Shader() {
    glDeleteProgram(mHandle);
}
```

1.  `ReadFile`辅助函数使用`std::ifstream`将文件转换为字符串，以读取文件的内容到`std::stringstream`中。字符串流可用于将文件内容作为字符串返回：

```cpp
std::string Shader::ReadFile(const std::string& path) {
    std::ifstream file;
    file.open(path);
    std::stringstream contents;
    contents << file.rdbuf();
    file.close();
    return contents.str();
}
```

1.  `CompileVertexShader`函数是用于编译 OpenGL 顶点着色器的样板代码。首先，使用`glCreateShader`创建着色器对象，然后使用`glShaderSource`为着色器设置源。最后，使用`glCompileShader`编译着色器。使用`glGetShaderiv`检查错误：

```cpp
unsigned int Shader::CompileVertexShader(
                               const string& vertex) {
    unsigned int v = glCreateShader(GL_VERTEX_SHADER);
    const char* v_source = vertex.c_str();
    glShaderSource(v, 1, &v_source, NULL);
    glCompileShader(v);
    int success = 0;
    glGetShaderiv(v, GL_COMPILE_STATUS, &success);
    if (!success) {
        char infoLog[512];
        glGetShaderInfoLog(v, 512, NULL, infoLog);
        std::cout << "Vertex compilation failed.\n";
        std::cout << "\t" << infoLog << "\n";
        glDeleteShader(v);
        return 0;
    };
    return v;
}
```

1.  `CompileFragmentShader`函数与`CompileVertexShader`函数几乎完全相同。唯一的真正区别是`glCreateShader`的参数，表明您正在创建一个片段着色器，而不是顶点着色器：

```cpp
unsigned int Shader::CompileFragmentShader(
                          const std::string& fragment) {
    unsigned int f = glCreateShader(GL_FRAGMENT_SHADER);
    const char* f_source = fragment.c_str();
    glShaderSource(f, 1, &f_source, NULL);
    glCompileShader(f);
    int success = 0;
    glGetShaderiv(f, GL_COMPILE_STATUS, &success);
    if (!success) {
        char infoLog[512];
        glGetShaderInfoLog(f, 512, NULL, infoLog);
        std::cout << "Fragment compilation failed.\n";
        std::cout << "\t" << infoLog << "\n";
        glDeleteShader(f);
        return 0;
    };
    return f;
}
```

1.  `LinkShaders`辅助函数也是样板。将着色器附加到构造函数创建的着色器程序句柄。通过调用`glLinkProgram`链接着色器，并使用`glGetProgramiv`检查错误。一旦着色器被链接，您只需要程序；可以使用`glDeleteShader`删除各个着色器对象：

```cpp
bool Shader::LinkShaders(unsigned int vertex, 
                         unsigned int fragment) {
    glAttachShader(mHandle, vertex);
    glAttachShader(mHandle, fragment);
    glLinkProgram(mHandle);
    int success = 0;
    glGetProgramiv(mHandle, GL_LINK_STATUS, &success);
    if (!success) {
        char infoLog[512];
        glGetProgramInfoLog(mHandle, 512, NULL, infoLog);
        std::cout << "ERROR: Shader linking failed.\n";
        std::cout << "\t" << infoLog << "\n";
        glDeleteShader(vertex);
        glDeleteShader(fragment);
        return false;
    }
    glDeleteShader(vertex);
    glDeleteShader(fragment);
    return true;
}
```

1.  `PopulateAttributes`函数枚举存储在着色器程序中的所有属性，然后将它们存储为键值对，其中键是属性的名称，值是其位置。您可以使用`glGetProgramiv`函数计算着色器程序中活动属性的数量，将`GL_ACTIVE_ATTRIBUTES`作为参数名称传递。然后，通过索引循环遍历所有属性，并使用`glGetActiveAttrib`获取每个属性的名称。最后，调用`glGetAttribLocation`获取每个属性的位置：

```cpp
void Shader::PopulateAttributes() {
    int count = -1;
    int length;
    char name[128];
    int size;
    GLenum type;
    glUseProgram(mHandle);
    glGetProgramiv(mHandle, GL_ACTIVE_ATTRIBUTES, 
                   &count);
    for (int i = 0; i < count; ++i) {
        memset(name, 0, sizeof(char) * 128);
        glGetActiveAttrib(mHandle, (GLuint)i, 128, 
                          &length, &size, &type, name);
        int attrib = glGetAttribLocation(mHandle, name);
        if (attrib >= 0) {
            mAttributes[name] = attrib;
        }
    }
    glUseProgram(0);
}
```

1.  `PopulateUniforms`辅助函数与`PopulateAttributes`辅助函数非常相似。`glGetProgramiv`需要以`GL_ACTIVE_UNIFORMS`作为参数名称，并且您需要调用`glGetActiveUniform`和`glGetUniformLocation`：

```cpp
void Shader::PopulateUniforms() {
    int count = -1;
    int length;
    char name[128];
    int size;
    GLenum type;
    char testName[256];
    glUseProgram(mHandle);
    glGetProgramiv(mHandle, GL_ACTIVE_UNIFORMS, &count);
    for (int i = 0; i < count; ++i) {
        memset(name, 0, sizeof(char) * 128);
        glGetActiveUniform(mHandle, (GLuint)i, 128, 
                           &length, &size, &type, name);
        int uniform=glGetUniformLocation(mHandle, name);
        if (uniform >= 0) { // Is uniform valid?
```

1.  当遇到有效的统一时，您需要确定该统一是否是一个数组。为此，在统一名称中搜索数组括号（`[`）。如果找到括号，则该统一是一个数组：

```cpp
std::string uniformName = name;
// if name contains [, uniform is array
std::size_t found = uniformName.find('[');
if (found != std::string::npos) {
```

1.  如果遇到一个统一数组，从`[`开始擦除字符串中的所有内容。这将使您只剩下统一的名称。然后，进入一个循环，尝试通过将`[ + index + ]`附加到统一名称来检索数组中的每个索引。一旦找到第一个无效的索引，就打破循环：

```cpp
uniformName.erase(uniformName.begin() + 
     found, uniformName.end());
     unsigned int uniformIndex = 0;
     while (true) {
           memset(testName,0,sizeof(char)*256);
               sprintf(testName, "%s[%d]", 
                           uniformName.c_str(), 
                           uniformIndex++);
                   int uniformLocation = 
                           glGetUniformLocation(
                           mHandle, testName);
                   if (uniformLocation < 0) {
                      break;
                   }
                   mUniforms[testName]=uniformLocation;
                }
            }
```

1.  此时，`uniformName`包含统一的名称。如果该统一是一个数组，则名称的`[0]`部分已被移除。按名称将统一索引存储在`mUniforms`中：

```cpp
            mUniforms[uniformName] = uniform;
        }
    }
    glUseProgram(0);
}
```

1.  最后一个辅助函数是`Load`函数，负责加载实际的着色器。此函数接受两个字符串，可以是文件名或内联着色器定义。一旦读取了着色器，调用`Compile`、`Link`和`Populate`辅助函数来加载着色器：

```cpp
void Shader::Load(const std::string& vertex, 
                  const std::string& fragment) {
    std::ifstream f(vertex.c_str());
    bool vertFile = f.good();
    f.close();
    f = std::ifstream(vertex.c_str());
    bool fragFile = f.good();
    f.close();
    std::string v_source = vertex;
    if (vertFile) {
        v_source = ReadFile(vertex);
    }
    std::string f_source = fragment;
    if (fragFile) {
        f_source = ReadFile(fragment);
    }
    unsigned int vert = CompileVertexShader(v_source);
    unsigned int f = CompileFragmentShader(f_source);
    if (LinkShaders(vert, frag)) {
        PopulateAttributes();
        PopulateUniforms();
    }
}
```

1.  `Bind`函数需要将当前着色器程序设置为活动状态，而`UnBind`应确保没有活动的`Shader`对象。`GetHandle`辅助函数返回`Shader`对象的 OpenGL 句柄：

```cpp
void Shader::Bind() {
    glUseProgram(mHandle);
}
void Shader::UnBind() {
    glUseProgram(0);
}
unsigned int Shader::GetHandle() {
    return mHandle;
}
```

1.  最后，您需要一种方法来检索属性和统一的绑定槽。`GetAttribute`函数将检查给定的属性名称是否存在于属性映射中。如果存在，则返回表示它的整数。如果没有，则返回`0`。`0`是有效的属性索引，因此在出现错误的情况下，还会记录错误消息：

```cpp
unsigned int Shader::GetAttribute(
                        const std::string& name) {
    std::map<std::string, unsigned int>::iterator it =
                                mAttributes.find(name);
    if (it == mAttributes.end()) {
        cout << "Bad attrib index: " << name << "\n";
        return 0;
    }
    return it->second;
}
```

1.  `GetUniform`函数的实现几乎与`GetAttribute`函数相同，只是它不是在属性映射上工作，而是在统一映射上工作：

```cpp
unsigned int Shader::GetUniform(const std::string& name){
    std::map<std::string, unsigned int>::iterator it =
                                  mUniforms.find(name);
    if (it == mUniforms.end()) {
        cout << "Bad uniform index: " << name << "\n";
        return 0;
    }
    return it->second;
}
```

`Shader`类有方法来检索统一和属性的索引。在下一节中，您将开始实现一个`Attribute`类来保存传递给着色器的顶点数据。

# 使用缓冲区（属性）

属性是图形管道中的每个顶点数据。一个顶点由属性组成。例如，一个顶点有一个位置和一个法线，这两个都是属性。最常见的属性如下：

+   位置：通常在局部空间中

+   法线：顶点指向的方向

+   UV 或纹理坐标：纹理上的标准化（*x*，*y*）坐标

+   颜色：表示顶点颜色的`vector3`

属性可以具有不同的数据类型。在本书中，您将实现对整数、浮点数和矢量属性的支持。对于矢量属性，将支持二维、三维和四维向量。

## `Attribute`类声明

创建一个新文件`Attribute.h`。`Attribute`类将在这个新文件中声明。`Attribute`类将被模板化。这将确保如果一个属性被认为是`vec3`，您不能意外地将`vec2`加载到其中：

1.  属性类将包含两个成员变量，一个用于 OpenGL 属性句柄，一个用于计算`Attribute`类包含的数据量。由于属性数据存储在 GPU 上，您不希望有多个句柄指向相同的数据，因此应禁用复制构造函数和`赋值运算符`：

```cpp
template<typename T>
class Attribute {
protected:
    unsigned int mHandle;
    unsigned int mCount;
private:
    Attribute(const Attribute& other);
    Attribute& operator=(const Attribute& other);
```

1.  `SetAttribPointer`函数很特殊，因为它需要为每种支持的属性类型实现一次。这将在`.cpp`文件中明确完成：

```cpp
void SetAttribPointer(unsigned int slot);
```

1.  将`Attribute`类的构造函数和析构函数声明为公共函数：

```cpp
public:
    Attribute();
    ~Attribute();
```

1.  `Attribute`类需要一个`Set`函数，它将数组数据上传到 GPU。数组中的每个元素表示一个顶点的属性。我们需要一种从着色器定义的绑定槽中绑定和解绑属性的方法，以及属性的计数和句柄的访问器：

```cpp
    void Set(T* inputArray, unsigned int arrayLength);
    void Set(std::vector<T>& input);
    void BindTo(unsigned int slot);
    void UnBindFrom(unsigned int slot);
    unsigned int Count();
    unsigned int GetHandle();
};
```

现在您已经声明了`Attribute`类，您将在下一节中实现它。

## 实现`Attribute`类

创建一个新文件`Attribtue.cpp`。您将在此文件中实现`Attribute`类如下：

1.  `Attribute`类是模板的，但它的函数都没有标记为内联。每种属性类型的模板特化将存在于`Attribute.cpp`文件中。为整数、浮点数、`vec2`、`vec3`、`vec4`和`ivec4`类型添加特化：

```cpp
template Attribute<int>;
template Attribute<float>;
template Attribute<vec2>;
template Attribute<vec3>;
template Attribute<vec4>;
template Attribute<ivec4>;
```

1.  构造函数应生成一个 OpenGL 缓冲区并将其存储在`Attribute`类的句柄中。析构函数负责释放`Attribute`类持有的句柄：

```cpp
template<typename T>
Attribute<T>::Attribute() {
    glGenBuffers(1, &mHandle);
    mCount = 0;
}
template<typename T>
Attribute<T>::~Attribute() {
    glDeleteBuffers(1, &mHandle);
}
```

1.  `Attribute`类有两个简单的 getter，一个用于检索计数，一个用于检索 OpenGL 句柄。计数表示总共有多少个属性：

```cpp
template<typename T>
unsigned int Attribute<T>::Count() {
    return mCount;
}
template<typename T>
unsigned int Attribute<T>::GetHandle() {
    return mHandle;
}
```

1.  `Set`函数接受一个数组和一个长度。然后绑定`Attribute`类持有的缓冲区，并使用`glBufferData`填充缓冲区数据。有一个方便的`Set`函数，它接受一个向量引用而不是数组。它调用实际的`Set`函数：

```cpp
template<typename T>
void Attribute<T>::Set(T* inputArray, 
                       unsigned int arrayLength) {
    mCount = arrayLength;
    unsigned int size = sizeof(T);
    glBindBuffer(GL_ARRAY_BUFFER, mHandle);
    glBufferData(GL_ARRAY_BUFFER, size * mCount, 
                 inputArray, GL_STREAM_DRAW);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}
template<typename T>
void Attribute<T>::Set(std::vector<T>& input) {
    Set(&input[0], (unsigned int)input.size());
}
```

1.  `SetAttribPointer`函数包装了`glVertesAttribPointer`或`glVertesAttribIPointer`。根据`Attribute`类的类型，参数和要调用的函数是不同的。为了消除任何歧义，为所有支持的模板类型提供显式实现。首先实现`int`、`ivec4`和`float`类型：

```cpp
template<>
void Attribute<int>::SetAttribPointer(unsigned int s) {
   glVertexAttribIPointer(s, 1, GL_INT, 0, (void*)0);
}
template<>
void Attribute<ivec4>::SetAttribPointer(unsigned int s){
   glVertexAttribIPointer(s, 4, GL_INT, 0, (void*)0);
}
template<>
void Attribute<float>::SetAttribPointer(unsigned int s){
   glVertexAttribPointer(s,1,GL_FLOAT,GL_FALSE,0,0);
}
```

1.  接下来实现`vec2`、`vec3`和`vec4`类型。这些都与`float`类型非常相似。唯一的区别是`glVertexAttribPointer`的第二个参数：

```cpp
template<>
void Attribute<vec2>::SetAttribPointer(unsigned int s) {
   glVertexAttribPointer(s,2,GL_FLOAT,GL_FALSE,0,0);
}
template<>
void Attribute<vec3>::SetAttribPointer(unsigned int s){
   glVertexAttribPointer(s,3,GL_FLOAT,GL_FALSE,0,0);
}
template<>
void Attribute<vec4>::SetAttribPointer(unsigned int s){
   glVertexAttribPointer(s,4,GL_FLOAT,GL_FALSE,0,0);
}
```

1.  `Attribute`类的最后两个函数需要将属性绑定到`Shader`类中指定的槽位，并解除绑定。由于`Attribute`类的模板类型不同，`Bind`将调用`SetAttribPointer`辅助函数：

```cpp
template<typename T>
void Attribute<T>::BindTo(unsigned int slot) {
    glBindBuffer(GL_ARRAY_BUFFER, mHandle);
    glEnableVertexAttribArray(slot);
    SetAttribPointer(slot);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}
template<typename T>
void Attribute<T>::UnBindFrom(unsigned int slot) {
    glBindBuffer(GL_ARRAY_BUFFER, mHandle);
    glDisableVertexAttribArray(slot);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}
```

`Attribute`数据每个顶点都会发生变化。您需要设置另一种类型的数据：uniforms。与属性不同，uniforms 在着色器程序执行期间保持不变。您将在下一节中实现 uniforms。

# 使用 uniforms

与属性不同，uniforms 是常量数据；它们只设置一次。uniform 的值对所有处理的顶点保持不变。uniforms 可以创建为数组，这是您将在后续章节中用来实现网格蒙皮的功能。

与`Attribute`类一样，`Uniform`类也将是模板化的。但与属性不同，永远不会有`Uniform`类的实例。它只需要公共静态函数。对于每种 uniform 类型，有三个函数：一个用于设置单个 uniform 值，一个用于设置一组 uniform 值，一个便利函数用于设置一组值，但使用向量作为输入。

## Uniform 类声明

创建一个新文件，`Uniform.h`。您将在这个新文件中实现`Uniform`类。`Uniform`类永远不会被实例化，因为不会有这个类的实例。禁用构造函数和复制构造函数、赋值运算符和析构函数。该类将具有三个静态`Set`函数的重载。`Set`函数需要为每种模板类型指定：

```cpp
template <typename T>
class Uniform {
private:
  Uniform();
  Uniform(const Uniform&);
  Uniform& operator=(const Uniform&);
  ~Uniform();
public:
  static void Set(unsigned int slot, const T& value);
  static void Set(unsigned int slot,T* arr,unsigned int len);
  static void Set(unsigned int slot, std::vector<T>& arr);
};
```

您刚刚完成了`Uniform`类的声明。在下一节中，您将开始实现`Uniform`类。

## 实现 Uniform 类

创建一个新文件，`Uniform.cpp`。您将在这个新文件中实现`Uniform`类。与`Attribute`类一样，`Uniform`类也是模板化的。

在 OpenGL 中，uniforms 是使用`glUniform***`系列函数设置的。有不同的函数用于整数、浮点数、向量、矩阵等。您希望为每种类型的`Set`方法提供实现，但避免编写几乎相同的代码。

为了避免编写几乎相同的代码，您将声明一个`#define`宏。这个宏将接受三个参数——要调用的 OpenGL 函数，Uniform 类的模板类型和 OpenGL 函数的数据类型：

1.  添加以下代码以定义支持的 uniform 类型的模板规范：

```cpp
template Uniform<int>;
template Uniform<ivec4>;
template Uniform<ivec2>;
template Uniform<float>;
template Uniform<vec2>;
template Uniform<vec3>;
template Uniform<vec4>;
template Uniform<quat>;
template Uniform<mat4>;
```

1.  您只需要为每种类型实现一个`Set`方法，即接受数组和长度的方法。其他`Set`方法重载是为了方便起见。实现两个便利重载——一个用于设置单个 uniform，另一个用于设置向量。两个重载应该只调用`Set`函数：

```cpp
template <typename T>
void Uniform<T>::Set(unsigned int slot,const T& value){
    Set(slot, (T*)&value, 1);
}
template <typename T>
void Uniform<T>::Set(unsigned int s,std::vector<T>& v){
    Set(s, &v[0], (unsigned int)v.size());
}
```

1.  创建一个`UNIFORM_IMPL`宏。第一个参数是要调用的 OpenGL 函数，第二个是正在使用的结构类型，最后一个参数是相同结构的数据类型。`UNIFORM_IMPL`宏将这些信息组装成一个函数声明：

```cpp
#define UNIFORM_IMPL(gl_func, tType, dType) \
template<> void Uniform<tType>::Set(unsigned int slot,\
                   tType* data, unsigned int length) {\
    gl_func(slot, (GLsizei)length, (dType*)&data[0]); \
}
```

1.  为每种 uniform 数据类型调用`UNIFORM_IMPL`宏以生成适当的`Set`函数。这种方法无法适用于`mat4`数据类型：

```cpp
UNIFORM_IMPL(glUniform1iv, int, int)
UNIFORM_IMPL(glUniform4iv, ivec4, int)
UNIFORM_IMPL(glUniform2iv, ivec2, int)
UNIFORM_IMPL(glUniform1fv, float, float)
UNIFORM_IMPL(glUniform2fv, vec2, float)
UNIFORM_IMPL(glUniform3fv, vec3, float)
UNIFORM_IMPL(glUniform4fv, vec4, float)
UNIFORM_IMPL(glUniform4fv, quat, float)
```

1.  矩阵的`Set`函数需要手动指定；否则，`UNIFORM_IMPL`宏将无法工作。这是因为`glUniformMatrix4fv`函数需要一个额外的布尔参数，询问矩阵是否应该被转置。将转置布尔值设置为`false`：

```cpp
template<> void Uniform<mat4>::Set(unsigned int slot, 
        mat4* inputArray, unsigned int arrayLength) {
    glUniformMatrix4fv(slot, (GLsizei)arrayLength, 
                       false, (float*)&inputArray[0]);
}
```

在本节中，你在统一的概念上构建了一个抽象层。在下一节中，你将实现类似属性的索引缓冲区。

# 使用索引缓冲区

索引缓冲区是一种属性。与属性不同，索引缓冲区绑定到`GL_ELEMENT_ARRAY_BUFFER`，可以用于绘制基本图元。因此，你将在它们自己的类中实现索引缓冲区，而不是重用`Attribute`类。

## IndexBuffer 类声明

创建一个新文件，`IndexBuffer.h`。你将在这个新文件中添加`IndexBuffer`类的声明。像`Attribute`对象一样，`IndexBuffer`将包含一个 OpenGL 句柄和一个计数，同时有 getter 函数。

为了避免多个`IndexBuffer`对象引用同一个 OpenGL 缓冲区，需要禁用复制构造函数和赋值运算符。`Set`函数接受一个无符号整数数组和数组的长度，但也有一个方便的重载，接受一个向量：

```cpp
class IndexBuffer {
public:
    unsigned int mHandle;
    unsigned int mCount;
private:
    IndexBuffer(const IndexBuffer& other);
    IndexBuffer& operator=(const IndexBuffer& other);
public:
    IndexBuffer();
    ~IndexBuffer();
    void Set(unsigned int* rr, unsigned int len);
    void Set(std::vector<unsigned int>& input);
    unsigned int Count();
    unsigned int GetHandle();
};
```

在本节中，你声明了一个新的`IndexBuffer`类。在下一节中，你将开始实现实际的索引缓冲区。

## 实现 IndexBuffer 类

索引缓冲区允许你使用索引几何体渲染模型。想象一个人体模型；网格中几乎所有的三角形都是相连的。这意味着许多三角形可能共享一个顶点。而不是存储每个单独的顶点，只存储唯一的顶点。索引到唯一顶点列表的缓冲区，即索引缓冲区，用于从唯一顶点创建三角形，如下所示：

1.  创建一个新文件，`IndexBuffer.cpp`。你将在这个文件中实现`IndexBuffer`类。构造函数需要生成一个新的 OpenGL 缓冲区，析构函数需要删除该缓冲区：

```cpp
IndexBuffer::IndexBuffer() {
    glGenBuffers(1, &mHandle);
    mCount = 0;
}
IndexBuffer::~IndexBuffer() {
    glDeleteBuffers(1, &mHandle);
}
```

1.  `IndexBuffer`对象内部的计数和 OpenGL 句柄的 getter 函数是微不足道的：

```cpp
unsigned int IndexBuffer::Count() {
    return mCount;
}
unsigned int IndexBuffer::GetHandle() {
    return mHandle;
}
```

1.  `IndexBuffer`类的`Set`函数需要绑定`GL_ELEMENT_ARRAY_BUFFER`。除此之外，逻辑与属性的逻辑相同：

```cpp
void IndexBuffer::Set(unsigned int* inputArray, unsigned int arrayLengt) {
    mCount = arrayLengt;
    unsigned int size = sizeof(unsigned int);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mHandle);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, size * mCount, inputArray, GL_STATIC_DRAW);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
}
void IndexBuffer::Set(std::vector<unsigned int>& input) {
    Set(&input[0], (unsigned int)input.size());
}
```

在本节中，你围绕索引缓冲区构建了一个抽象。在下一节中，你将学习如何使用索引缓冲区和属性来渲染几何体。

# 渲染几何体

你已经有了处理顶点数据、统一和索引缓冲区的类，但没有任何代码来绘制它们。绘制将由四个全局函数处理。你将有两个`Draw`函数和两个`DrawInstanced`函数。你将能够使用或不使用索引缓冲区来绘制几何体。

创建一个新文件，`Draw.h`。你将在这个文件中实现`Draw`函数，如下所示：

1.  声明一个`enum`类，定义绘制时应该使用的基本图元。大多数情况下，你只需要线、点或三角形，但有些额外的类型可能也会有用：

```cpp
enum class DrawMode {
    Points,
    LineStrip,
    LineLoop,
    Lines,
    Triangles,
    TriangleStrip,
    TriangleFan
};
```

1.  接下来，声明`Draw`函数。`Draw`函数有两个重载——一个接受索引缓冲区和绘制模式，另一个接受顶点数量和绘制模式：

```cpp
void Draw(IndexBuffer& inIndexBuffer, DrawMode mode);
void Draw(unsigned int vertexCount, DrawMode mode);
```

1.  像`Draw`一样，声明两个`DrawInstanced`函数。这些函数具有类似的签名，但多了一个参数——`instanceCount`。这个`instanceCount`变量控制着几何体的实例数量将被渲染：

```cpp
void DrawInstanced(IndexBuffer& inIndexBuffer, 
         DrawMode mode, unsigned int instanceCount);
void DrawInstanced(unsigned int vertexCount, 
         DrawMode mode, unsigned int numInstances);
```

创建一个新文件，`Draw.cpp`。你将在这个文件中实现与绘制相关的功能，如下所示：

1.  你需要能够将`DrawMode`枚举转换为`GLenum`。我们将使用一个静态辅助函数来实现这一点。这个函数唯一需要做的事情就是弄清楚输入的绘制模式是什么，并返回适当的`GLenum`值：

```cpp
static GLenum DrawModeToGLEnum(DrawMode input) {
    switch (input) {
        case DrawMode::Points: return  GL_POINTS;
        case DrawMode::LineStrip: return GL_LINE_STRIP;
        case DrawMode::LineLoop: return  GL_LINE_LOOP;
        case DrawMode::Lines: return  GL_LINES;
        case DrawMode::Triangles: return  GL_TRIANGLES;
        case DrawMode::TriangleStrip: 
                       return  GL_TRIANGLE_STRIP;
        case DrawMode::TriangleFan: 
                       return   GL_TRIANGLE_FAN;
    }
    cout << "DrawModeToGLEnum unreachable code hit\n";
    return 0;
}
```

1.  接受顶点数的`Draw`和`DrawInstanced`函数很容易实现。`Draw`需要调用`glDrawArrays`，而`DrawInstanced`需要调用`glDrawArraysInstanced`：

```cpp
void Draw(unsigned int vertexCount, DrawMode mode) {
    glDrawArrays(DrawModeToGLEnum(mode), 0, vertexCount);
}
void DrawInstanced(unsigned int vertexCount, 
     DrawMode mode, unsigned int numInstances) {
    glDrawArraysInstanced(DrawModeToGLEnum(mode), 
                          0, vertexCount, numInstances);
}
```

1.  接受索引缓冲区的`Draw`和`Drawinstanced`函数需要将索引缓冲区绑定到`GL_ELEMENT_ARRAY_BUFFER`，然后调用`glDrawElements`和`glDrawElementsInstanced`：

```cpp
void Draw(IndexBuffer& inIndexBuffer, DrawMode mode) {
    unsigned int handle = inIndexBuffer.GetHandle();
    unsigned int numIndices = inIndexBuffer.Count();
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, handle);
    glDrawElements(DrawModeToGLEnum(mode), 
                   numIndices, GL_UNSIGNED_INT, 0);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
}
void DrawInstanced(IndexBuffer& inIndexBuffer, 
         DrawMode mode, unsigned int instanceCount) {
    unsigned int handle = inIndexBuffer.GetHandle();
    unsigned int numIndices = inIndexBuffer.Count();
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, handle);
    glDrawElementsInstanced(DrawModeToGLEnum(mode),
        numIndices, GL_UNSIGNED_INT, 0, instanceCount);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
}
```

到目前为止，您已经编写了加载着色器、创建和绑定 GPU 缓冲区以及将统一变量传递给着色器的代码。现在绘图代码也已实现，您可以开始显示几何图形了。

在下一节中，您将学习如何使用纹理使渲染的几何图形看起来更有趣。

# 使用纹理

本书中编写的所有着色器都假定正在渲染的漫反射颜色来自纹理。纹理将从`.png`文件加载。所有图像加载都将通过`stb_image`完成。

`Stb`是一组单文件公共领域库。我们只会使用图像加载器；您可以在 GitHub 上找到整个`stb`集合[`github.com/nothings/stb`](https://github.com/nothings/stb)。

## 添加 stb_image

您将使用`stb_image`加载纹理。您可以从[`github.com/nothings/stb/blob/master/stb_image.h`](https://github.com/nothings/stb/blob/master/stb_image.h)获取头文件的副本。将`stb_image.h`头文件添加到项目中。

创建一个新文件`stb_image.cpp`。这个文件只需要声明`stb_image`实现宏并包含头文件。它应该是这样的：

```cpp
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
```

## 纹理类声明

创建一个新文件`Texture.h`。您将在这个文件中声明`Texture`类。`Texture`类只需要一些重要的函数。它需要能够从文件加载纹理，将纹理索引绑定到统一索引，并取消激活纹理索引。

除了核心函数之外，该类还应该有一个默认构造函数、一个方便的构造函数（接受文件路径）、一个析构函数和一个获取`Texture`类内包含的 OpenGL 句柄的 getter。复制构造函数和赋值运算符应该被禁用，以避免两个`Texture`类引用相同的 OpenGL 纹理句柄：

```cpp
class Texture {
protected:
    unsigned int mWidth;
    unsigned int mHeight;
    unsigned int mChannels;
    unsigned int mHandle;
private:
    Texture(const Texture& other);
    Texture& operator=(const Texture& other);
public:
    Texture();
    Texture(const char* path);
    ~Texture();
    void Load(const char* path);
    void Set(unsigned int uniform, unsigned int texIndex);
    void UnSet(unsigned int textureIndex);
    unsigned int GetHandle();
};
```

## 实现纹理类

创建一个新文件`Texture.cpp`。`Texture`类的定义将放在这个文件中。`Texture`类的默认构造函数需要将所有成员变量设置为`0`，然后生成一个 OpenGL 句柄。

`Load`函数可能是`Texture`类中最重要的函数；它负责加载图像文件。图像文件的实际解析将由`stbi_load`处理：

1.  方便的构造函数生成一个新的句柄，然后调用`Load`函数，该函数将初始化`Texture`类的其余成员变量，因为`Texture`类的每个实例都持有一个有效的纹理句柄：

```cpp
Texture::Texture() {
    mWidth = 0;
    mHeight = 0;
    mChannels = 0;
    glGenTextures(1, &mHandle);
}
Texture::Texture(const char* path) {
    glGenTextures(1, &mHandle);
    Load(path);
}
Texture::~Texture() {
    glDeleteTextures(1, &mHandle);
}
```

1.  `stbi_load`需要一个图像文件的路径以及图像的宽度、高度和通道数的引用。最后一个参数指定每个像素的组件数。通过将其设置为`4`，所有纹理都将以 RGBA 通道加载。接下来，使用`glTexImage2D`将纹理上传到 GPU，并使用`glGenerateMipmap`生成图像的适当 mipmap。将包装模式设置为重复：

```cpp
void Texture::Load(const char* path) {
    glBindTexture(GL_TEXTURE_2D, mHandle);
    int width, height, channels;
    unsigned char* data = stbi_load(path, &width, 
                                    &height, 
                                    &channels, 4);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, 
       height, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
    glGenerateMipmap(GL_TEXTURE_2D);
    stbi_image_free(data);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, 
                    GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, 
                    GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,
                    GL_NEAREST_MIPMAP_LINEAR);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,
                    GL_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);
    mWidth = width;
    mHeight = height;
    mChannels = channels;
}
```

1.  `Set`函数需要激活一个纹理单元，将`Texture`类包含的句柄绑定到该纹理单元，然后将指定的统一索引设置为当前绑定的纹理单元。`Unset`函数取消绑定指定纹理单元的当前纹理：

```cpp
void Texture::Set(unsigned int uniformIndex, 
                  unsigned int textureIndex) {
    glActiveTexture(GL_TEXTURE0 + textureIndex);
    glBindTexture(GL_TEXTURE_2D, mHandle);
    glUniform1i(uniformIndex, textureIndex);
}
void Texture::UnSet(unsigned int textureIndex) {
    glActiveTexture(GL_TEXTURE0 + textureIndex);
    glBindTexture(GL_TEXTURE_2D, 0);
    glActiveTexture(GL_TEXTURE0);
}
```

1.  `GetHandle`获取函数很简单：

```cpp
unsigned int Texture::GetHandle() {
    return mHandle;
}
```

`Texture`类将始终使用相同的 mipmap 级别和包装参数加载纹理。对于本书中的示例，这应该足够了。您可能希望尝试为这些属性添加 getter 和 setter。

在下一节中，您将实现顶点和片段着色器程序，这是绘制所需的最后一步。

# 简单的着色器

渲染抽象已完成。在绘制任何东西之前，您需要编写着色器来指导绘制的方式。在本节中，您将编写一个顶点着色器和一个片段着色器。片段着色器将在本书的其余部分中使用，而本书后面部分使用的顶点着色器将是这里介绍的一个变体。

## 顶点着色器

顶点着色器负责将模型的每个顶点通过模型、视图和投影管道，并将任何所需的光照数据传递给片段着色器。创建一个新文件，`static.vert`。您将在这个文件中实现顶点着色器。

顶点着色器需要三个 uniform 变量——模型、视图和投影矩阵。这些 uniform 变量需要用来转换顶点。每个单独的顶点由三个属性组成——位置、法线和一些纹理坐标。

顶点着色器将三个变量输出到片段着色器中，即世界空间中的法线和片段位置，以及纹理坐标：

```cpp
#version 330 core
uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;
in vec3 position;
in vec3 normal;
in vec2 texCoord;
out vec3 norm;
out vec3 fragPos;
out vec2 uv;
void main() {
    gl_Position = projection * view * model * 
                  vec4(position, 1.0);

    fragPos = vec3(model * vec4(position, 1.0));
    norm = vec3(model * vec4(normal, 0.0f));
    uv = texCoord;
}
```

这是一个最小的顶点着色器；它只将顶点通过模型视图和投影管道。这个着色器可以用来显示静态几何图形或 CPU 蒙皮网格。在下一节中，您将实现一个片段着色器。

## 片段着色器

创建一个新文件，`lit.frag`。这个文件中的片段着色器将在本书的其余部分中使用。一些章节将介绍新的顶点着色器，但片段着色器始终保持不变。

片段着色器从纹理中获取对象的漫反射颜色，然后应用单向光。光照模型只是*N*点*L*。由于光没有环境项，模型的某些部分可能会呈现全黑：

```cpp
#version 330 core
in vec3 norm;
in vec3 fragPos;
in vec2 uv;
uniform vec3 light;
uniform sampler2D tex0;
out vec4 FragColor;
void main() {
    vec4 diffuseColor = texture(tex0, uv);
    vec3 n = normalize(norm);
    vec3 l = normalize(light);
    float diffuseIntensity = clamp(dot(n, l), 0, 1);
    FragColor = diffuseColor * diffuseIntensity;
}
```

重要信息：

想了解更多关于 OpenGL 中光照模型的知识？请访问[`learnopengl.com/Lighting/Basic-Lighting`](https://learnopengl.com/Lighting/Basic-Lighting)。

这是一个简单的片段着色器；漫反射颜色是通过对纹理进行采样获得的，强度是一个简单的定向光。

# 总结

在本章中，您学会了如何在 OpenGL API 的顶层编写一个抽象层。在本书的大部分时间里，您将使用这些类来绘制东西，但是一些零散的 OpenGL 调用可能会在我们的代码中找到它们的位置。

以这种方式抽象化 OpenGL 将让未来的章节专注于动画，而不必担心底层 API。将这个 API 移植到其他后端也应该很简单。

本章有两个示例——`Chapter06/Sample00`，这是到目前为止使用的代码，以及`Chapter06/Sample01`，显示一个简单的纹理和光照平面在原地旋转。`Sample01`是如何使用到目前为止编写的代码的一个很好的例子。

`Sample01`还包括一个实用类`DebugDraw`，本书不会涉及。该类位于`DebugDraw.h`和`DebugDraw.cpp`中。`DebugDraw`类可以用于快速绘制调试线，具有简单的 API。`DebugDraw`类效率不高；它只用于调试目的。

在下一章中，您将开始探索 glTF 文件格式。glTF 是一种可以存储网格和动画数据的标准格式。这是本书其余部分将使用的格式。


# 第七章：探索 glTF 文件格式

在本章中，我们将探索 glTF，这是一个包含显示动画模型所需的一切的文件格式。这是大多数三维内容创建应用程序可以导出的标准格式，并允许您加载任意模型。

本章重点介绍文件格式本身。后续章节将重点介绍实现加载 glTF 文件部分，以使其变得相关。通过本章结束时，您应该对 glTF 文件格式有扎实的理解。

本章将专注于构建以下技能：

+   了解 glTF 文件中的数据

+   使用 cgltf 实现 glTF 加载

+   学习如何从 Blender 导出 glTF 文件

# 技术要求

本章将涵盖您需要加载和显示动画模型的 glTF 文件的每个概念。然而，本章不是文件格式的完整指南。在阅读本章之前，请花几分钟时间通过阅读[`www.khronos.org/files/gltf20-reference-guide.pdf`](https://www.khronos.org/files/gltf20-reference-guide.pdf)上的参考指南来熟悉 glTF 格式。

您将使用 cgltf ([`github.com/jkuhlmann/cgltf`](https://github.com/jkuhlmann/cgltf))来解析 glTF 文件。如果 glTF 文件显示不正常，可能是一个坏文件。如果您怀疑文件可能有问题，请在[`gltf-viewer.donmccurdy.com/`](https://gltf-viewer.donmccurdy.com/)上检查 glTF 参考查看器。

# 探索 glTF 文件的存储方式

glTF 文件存储为纯文本 JSON 文件或更紧凑的二进制表示。纯文本变体通常具有`.gltf`扩展名，而二进制变体通常具有`.glb`扩展名。

可能会有多个文件。glTF 文件可以选择嵌入大块的二进制数据，甚至纹理，或者可以选择将它们存储在外部文件中。这在下面的 Blender3D 的 glTF 导出选项的截图中反映出来：

![图 7.1：Blender3D 的 glTF 导出选项](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_7.1_B16191.jpg)

图 7.1：Blender3D 的 glTF 导出选项

本书提供的可下载内容的示例文件存储为 glTF 嵌入文件（`.gltf`）。这是可以用任何文本编辑器检查的纯文本变体。更重要的是，它是一个要跟踪的单个文件。尽管本书提供的文件是以 glTF 嵌入格式提供的，但最终的代码将支持加载二进制格式和单独的文件（`.bin`）。

现在您已经探索了 glTF 文件存储的不同方式，让我们准备好学习 glTF 文件内部存储的内容。glTF 文件旨在存储整个场景，而不仅仅是单个模型。在下一节中，您将探索 glTF 文件的预期用途。

## glTF 文件存储场景，而不是模型

重要的是要知道，glTF 文件旨在表示整个三维场景，而不仅仅是单个动画模型。因此，glTF 支持您不需要用于动画的功能，例如相机和 PBR 材质。对于动画，我们只关心使用受支持功能的一个小子集。让我们概述一下它们是什么。

glTF 文件可以包含不同类型的网格。它包含静态网格，例如道具。这些网格只能通过它们附加到的节点的动画来移动；它可以包含变形目标。变形动画可以用于诸如面部表情之类的事物。

glTF 文件也可以包含蒙皮网格。这些是您将用来为角色设置动画的网格。蒙皮网格描述了模型的顶点如何受到模型的变换层次结构（或骨骼）的影响。使用蒙皮网格，网格的每个顶点可以绑定到层次结构中的一个关节。随着层次结构的动画，网格会被变形。

glTF 旨在描述一个场景，而不是单个模型，这将使一些加载代码变得有些棘手。在下一节中，您将开始从高层次的角度探索 glTF 文件的实际内容。

# 探索 glTF 格式

glTF 文件的根是场景。一个 glTF 文件可以包含一个或多个场景。一个场景包含一个或多个节点。一个节点可以附加皮肤、网格、动画、相机、光线或混合权重。网格、皮肤和动画在缓冲区中存储大量信息。要访问缓冲区，它们包含一个包含缓冲区的缓冲区视图，缓冲区视图又包含缓冲区。

通过文本提供的描述可能很难理解。以下图表说明了所描述的文件布局。由于 glTF 是一种场景描述格式，有许多数据类型我们不必关心。下一节将探讨这些内容：

![图 7.2：glTF 文件的内容](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_7.2_B16191.jpg)

图 7.2：glTF 文件的内容

现在您已经了解了 glTF 文件中存储的内容，接下来的部分将探讨蒙皮动画所需的文件格式部分。

## 需要用于动画的部分

使用 glTF 文件加载动画模型时，文件的必需组件是场景、节点、网格和皮肤。这是一个要处理的小子集；以下图表突出显示了这些部分及其关系。这些数据类型之间的关系可以描述如下：

![图 7.3：用于蒙皮动画的 glTF 文件的部分](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_7.3_B16191.jpg)

图 7.3：用于蒙皮动画的 glTF 文件的部分

前面的图省略了每个数据结构中的大部分数据，而是只关注您需要实现蒙皮动画的内容。在下一节中，我们将探讨 glTF 文件中不需要用于蒙皮动画的部分。

## 不需要用于动画的部分

要实现蒙皮动画，您不需要灯光、相机、材质、纹理、图像和采样器。在下一节中，您将探索如何从 glTF 文件中实际读取数据。

## 访问数据

访问数据有点棘手，但并不太困难。网格、皮肤和动画对象都包含一个 glTF 访问器。这个**访问器**引用一个**缓冲区视图**，而缓冲区视图引用一个**缓冲区**。以下图表展示了这种关系：

![图 7.4：访问 glTF 文件中的数据](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_7.4_B16191.jpg)

图 7.4：访问 glTF 文件中的数据

在这三个单独的步骤中，如何访问缓冲区数据？在下一节中，您将学习如何使用缓冲区视图和最终访问器从缓冲区中解释数据。

### 缓冲区

将缓冲区视为 OpenGL 缓冲区。它只是一个大的、线性的值数组。这类似于您在第六章《构建抽象渲染器》中构建的`Attributes`类。`Attributes`类的`Set`函数调用`glBufferData`，其签名如下：

```cpp
void glBufferData(GLenum target, GLsizeiptr size, 
                  void * data, GLenum usage);
```

glTF 中的缓冲区包含调用`glBufferData`函数所需的所有信息。它包含大小、void 指针和可选的偏移量，这些偏移量只修改源指针和大小。将 glTF 缓冲区视为填充 OpenGL 缓冲区所需的所有内容。

在下一节中，您将学习如何将缓冲区视图与缓冲区一起使用。

### 缓冲区视图

缓冲区只是一些大块的数据。没有上下文来描述缓冲区内存储的内容。这就是缓冲区视图的作用。缓冲区视图描述了缓冲区中的内容。如果缓冲区包含`glBufferData`的信息，那么缓冲区视图包含调用`glVertexAttribPointer`的一些参数。`glVertexAttribPointer`函数的签名如下：

```cpp
void glVertexAttribPointer(GLuint index, GLint size, 
                           GLenum type, GLboolean normalized,
                           GLsizei stride, void * pointer);
```

缓冲区视图包含`type`，它确定视图是顶点缓冲区还是索引缓冲区。这很重要，因为顶点缓冲区绑定到`GL_ARRAY_BUFFER`，而索引缓冲区绑定到`GL_ELEMENT_ARRAY_BUFFER`。在*第六章*，*构建抽象渲染器*中，我们为这些不同的缓冲区类型构建了两个不同的类。

与缓冲区一样，缓冲区视图还包含一些可选的偏移量，进一步修改源指针的位置和大小。在接下来的部分中，您将探讨如何使用描述缓冲区视图内容的 accessor。

### accessor

accessor 存储更高级别的信息。最重要的是，accessor 描述了您正在处理的数据类型，比如`scalar`、`vec2`、`vec3`或`vec4`。使用这些数据来确定`glVertexAttribPointer`的`size`参数。

accessor 回答了诸如数据是否规范化以及数据的存储模式是什么等问题。accessor 还包含了关于缓冲区和缓冲区视图已经包含的附加偏移量、大小和步幅信息。

下一节将演示如何从 glTF 文件中将数据加载到线性标量数组中。

### 例子

即使 accessor、buffer view 和 buffer 的关系已经确定，解析数据可能仍然有点混乱。为了尝试澄清一下，让我们探讨一下如何将 accessor 转换为浮点值的平面列表。以下代码旨在作为示例；它将不会在本书的其余部分中使用：

```cpp
vector<float> GetPositions(const GLTFAccessor& accessor) {
    // Accessors and sanity checks
    assert(!accessor.isSparse);
    const GLTFBufferView& bufferView = accessor.bufferView;
    const GLTFBuffer& buffer = bufferView.buffer;
    // Resize result
    // GetNumComponents Would return 3 for a vec3, etc.
    uint numComponents = GetNumComponents(accessor); 
    vector<float> result;
    result.resize(accessor.count * numComponents);
    // Loop trough every element in the accessor
    for (uint i = 0; i < accessor.count; ++i) {
        // Find where in the buffer the data actually starts
        uint offset = accessor.offset + bufferView.offset;
        uint8* data = buffer.data;
        data += offset + accessor.stride * i;
        // Loop trough every component of current element
        float* target = result[i] * componentCount;
        for (uint j = 0; j < numComponents; ++j) {
            // Omitting normalization 
            // Omitting different storage types
            target[j] = data + componentCount * j;
        } // End loop of every component of current element
    } // End loop of every accessor element
    return result;
}
```

解析 glTF 文件的代码可能会变得冗长；在前面的代码示例中，glTF 文件已经被解析。加载 glTF 文件的大部分工作实际上是解析二进制或 JSON 数据。在下一节中，我们将探讨如何使用 cgltf 库来解析 glTF 文件。

# 探索 cgltf

在上一节中，我们探讨了将 glTF accessor 转换为浮点数的线性数组需要做些什么。代码省略了一些更复杂的任务，比如规范化数据或处理不同的存储类型。

提供的示例代码还假定数据已经从 JSON（或二进制）格式中解析出来。编写 JSON 解析器不在本书的范围内，但处理 glTF 文件是在范围内的。

为了帮助管理加载 glTF 文件的一些复杂性，以及避免从头开始编写 JSON 解析器，下一节将教您如何使用 cgltf 加载 JSON 文件。Cgltf 是一个单头文件的 glTF 加载库；您可以在 GitHub 上找到它[`github.com/jkuhlmann/cgltf`](https://github.com/jkuhlmann/cgltf)。在下一节中，我们将开始将 cgltf 集成到我们的项目中。

## 集成 cgltf

要将 cgltf 集成到项目中，从 GitHub 上下载头文件[`github.com/jkuhlmann/cgltf/blob/master/cgltf.h`](https://github.com/jkuhlmann/cgltf/blob/master/cgltf.h)。然后，将此头文件添加到项目中。接下来，向项目添加一个新的`.c`文件，并将其命名为`cgltf.c`。该文件应包含以下代码：

```cpp
#pragma warning(disable : 26451)
#define _CRT_SECURE_NO_WARNINGS
#define CGLTF_IMPLEMENTATION
#include "cgltf.h"
```

CGLTF 现在已经集成到项目中。在本章中，您将实现解析 glTF 文件的代码。如何将 glTF 文件的内容加载到运行时数据将在以后的章节中进行覆盖，因为那时的运行时数据的代码已经编写好了。在接下来的部分，我们将学习如何实现 glTF 解析代码。

### 创建一个 glTF 加载器

在本节中，我们将探讨如何使用 cgltf 加载 glTF 文件。将文件加载到运行时数据结构`cgltf_data`中的代码很简单。在以后的章节中，您将学习如何解析这个`cgltf_data`结构的内容。

要加载一个文件，你需要创建一个`cgltf_options`的实例。你不需要设置任何选项标志；只需用`0`实例化`cgltf_options`结构的所有成员值。接下来，声明一个`cgltf_data`指针。这个指针的地址将被传递给`cgltf_parse_file`。在`cgltf_parse_file`填充了`cgltf_data`结构之后，你就可以解析文件的内容了。要稍后释放`cgltf_data`结构，调用`cgltf_free`：

1.  创建一个新文件`GLTFLoader.h`，其中包括`cgltf.h`。为`LoadGLTFFile`和`FreeGLTFFile`函数添加函数声明：

```cpp
#ifndef _H_GLTFLOADER_
#define _H_GLTFLOADER_
#include "cgltf.h"
cgltf_data* LoadGLTFFile(const char* path);
void FreeGLTFFile(cgltf_data* handle);
#endif
```

1.  创建一个新文件`GLTFLoader.cpp`。这个函数接受一个路径并返回一个`cgltf_data`指针。在内部，该函数调用`cgltf_parse_file`从文件中加载 glTF 数据。`cgltf_load_buffers`用于加载任何外部缓冲区数据。最后，`cgltf_validate`确保刚刚加载的 glTF 文件是有效的：

```cpp
cgltf_data* LoadGLTFFile(const char* path) {
    cgltf_options options;
    memset(&options, 0, sizeof(cgltf_options));
    cgltf_data* data = NULL;
    cgltf_result result = cgltf_parse_file(&options, 
                                        path, &data);
    if (result != cgltf_result_success) {
        cout << "Could not load: " << path << "\n";
        return 0;
    }
    result = cgltf_load_buffers(&options, data, path);
    if (result != cgltf_result_success) {
        cgltf_free(data);
        cout << "Could not load: " << path << "\n";
        return 0;
    }
    result = cgltf_validate(data);
    if (result != cgltf_result_success) {
        cgltf_free(data);
        cout << "Invalid file: " << path << "\n";
        return 0;
    }
    return data;
}
```

1.  在`GLTFLoader.cpp`中实现`FreeGLTFFile`函数。这个函数很简单；如果输入指针不是`null`，它需要调用`cgltf_free`：

```cpp
void FreeGLTFFile(cgltf_data* data) {
    if (data == 0) {
        cout << "WARNING: Can't free null data\n";
    }
    else {
        cgltf_free(data);
    }
}
```

在后面的章节中，你将通过引入加载网格、姿势和动画的函数来扩展 glTF `Loader`函数。在下一节中，你将探索如何从 Blender3D 导出 glTF 文件。

# 探索示例资产

你将在本书中使用的示例文件是来自 Quaternius 的 CC0、公共领域许可的资产。你可以在[`quaternius.com/assets.html`](http://quaternius.com/assets.html)找到类似风格的其他资产。

此外，后面的章节还包括了 GDQuest 的开放式三维 Mannequin 的屏幕截图，这些屏幕截图在[`github.com/GDQuest/godot-3d-mannequin`](https://github.com/GDQuest/godot-3d-mannequin)以 MIT 许可证的形式提供。

一些资产已经以 glTF 格式提供，但有些可能是`.blend`、`.fbx`或其他格式。当发生这种情况时，很容易将模型导入 Blender 并导出 glTF 文件。下一节将指导你如何从 Blender 导出 glTF 文件。

## 从 Blender 导出

Blender 是一个免费的三维内容创作工具。你可以从[`www.blender.org/`](https://www.blender.org/)下载 Blender。以下说明是针对 Blender 2.8 编写的，但在更新的版本中也应该可以使用。

如果你要导入的模型已经是`.blend`文件，只需双击它，它就会在 Blender 中加载。

如果模型是以不同的格式，比如`.DAE`或`.FBX`，你需要导入它。要这样做，打开 Blender，你应该看到默认场景加载。这个默认场景有一个立方体、一个灯光和一个摄像头：

![图 7.5：默认的 Blender3D 场景](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_7.5_B16191.jpg)

图 7.5：默认的 Blender3D 场景

通过左键单击选择立方体，然后悬停在三维视口上，按下*删除*键删除立方体。左键单击选择摄像头，然后按下*删除*键删除摄像头。对于灯光也是一样。

现在你应该有一个空场景。从**文件**菜单中，选择**文件**|**导入**，然后选择适当的模型格式进行导入。找到你的文件，双击导入它。一旦模型被导入，选择**文件**|**导出 glTF 2.0**。将导出格式设置为 glTF（文本文件）或 glb（二进制文件）。

# 总结

在本章中，你了解了什么是 glTF 文件，glTF 格式的哪些部分对于蒙皮动画是有用的，以及如何使用 cglTF 来加载 glTF 文件。如果这个格式还有点令人困惑，不要担心；当你开始解析 cgltf 文件中的各种数据时，它会变得更加清晰。使用 cgltf 将让你专注于将 glTF 数据转换为有用的运行时结构，而不必担心手动解析 JSON 文件。在下一章中，你将开始实现动画的构建块，包括曲线、帧和轨道。


# 第八章：创建曲线、帧和轨道

在 21 世纪初，游戏通常会采用在 3D 内容创建工具（如 Blender 或 Maya）中制作的动画，播放动画，并在设置的间隔内对动画中每个关节的变换进行采样。一旦对动画进行了采样，游戏的运行时会在采样帧之间进行线性插值。

虽然这种方法可行（并且可以在 glTF 文件中实现），但这并不是播放动画的最准确方式。它通过包含实际上不需要存在的帧来浪费内存。在 3D 内容创建工具中，动画是使用曲线创建的，例如以下截图中显示的曲线：

![图 8.1：Blender 3D 曲线编辑器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.1_B16191.jpg)

图 8.1：Blender 3D 曲线编辑器

现代游戏和动画系统直接评估这些曲线。直接评估动画曲线可以节省内存，但在处理能力方面曲线会更昂贵一些。在本章结束时，您应该能够做到以下几点：

+   了解立方 Bézier 样条以及如何评估它们

+   了解立方 Hermite 样条以及如何评估它们

+   了解常见的插值方法

+   能够创建立方、线性和恒定关键帧

+   了解关键帧如何组成立方、线性或恒定轨道

+   能够评估立方、线性和恒定轨道

+   能够将三个独立轨道合并为一个变换轨道

# 了解立方 Bézier 样条

要实现游戏动画，您需要对曲线有一定的了解。让我们从基础知识开始——立方 Bézier 样条。Bézier 样条有两个要插值的点和两个控制点，帮助生成曲线。这就是立方 Bézier 样条的样子：

![图 8.2：立方 Bézier 样条](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.2_B16191.jpg)

图 8.2：立方 Bézier 样条

给定两个点和两个控制点，如何生成曲线？让我们探索为给定时间**t**插值曲线。首先从**P1**到**C1**画一条线，从**C1**到**C2**，从**C2**到**P2**。然后，沿着这些线线性插值值**t**：

![图 8.3：在点和控制点之间进行线性插值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.3_B16191.jpg)

图 8.3：在点和控制点之间进行线性插值

从**P1**到**C1**的插值点是**A**，从**C2**到**P2**是**B**，从**C1**到**C2**是**C**。接下来，您需要重复这个过程，画线并从**A**到**C**和从**C**到**B**进行插值。让我们称这些新插值点为 E 和 F：

![图 8.4：线性插值图 8.3 的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.4_B16191.jpg)

图 8.4：线性插值图 8.3 的结果

重复一次，从**E**到**F**画一条线，并且也按照**t**在该线上进行插值。让我们称得到的点为**R**。这个点**R**在 Bézier 样条上的某个位置。如果您计算从*t=0*到*t=1*的所有点，您可以绘制出曲线：

![图 8.5：线性插值图 8.4 的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.5_B16191.jpg)

图 8.5：线性插值图 8.4 的结果

让我们探索绘制 Bézier 样条所需的代码。本书中不会在其他地方使用 Bézier 样条，因此不需要实现以下代码来跟随本书的其余部分：

1.  首先，您需要定义什么是 Bézier 样条。创建一个包含两个点和两个控制点的新模板类：

```cpp
template<typename T>
class Bezier {
public:
    T P1; // Point 1
    T C1; // Control 1
    T P2; // Point 2
    T C2; // Control 2
};
```

1.  接下来，实现`Interpolate`函数。该函数接受一个 Bézier 样条引用和一个值`t`，用于插值样条。假设`t`大于或等于`0`且小于或等于`1`：

```cpp
template<typename T>
inline T Interpolate(Bezier<T>& curve, float t) {
    T A = lerp(curve.P1, curve.C1, t);
    T B = lerp(curve.C2, curve.P2, t);
    T C = lerp(curve.C1, curve.C2, t);
    T D = lerp(A, C, t);
    T E = lerp(C, B, t);
    T R = lerp(D, E, t);
    return R;
}
```

以下代码示例演示了如何使用 Bezier 类和`Interpolate`函数来绘制 Bézier 样条：

1.  首先，您需要创建将要绘制的数据：

```cpp
Bezier<vec3> curve;
curve.P1 = vec3(-5, 0, 0);
curve.P2 = vec3(5, 0, 0);
curve.C1 = vec3(-2, 1, 0);
curve.C2 = vec3(2, 1, 0);

vec3 red = vec3(1, 0, 0);
vec3 green = vec3(0, 1, 0);
vec3 blue = vec3(0, 0, 1);
vec3 magenta = vec3(1, 0, 1);
```

1.  接下来，绘制点和控制点：

```cpp
// Draw all relevant points
DrawPoint(curve.P1, red);
DrawPoint(curve.C1, green);
DrawPoint(curve.P2, red);
DrawPoint(curve.C2, green);
// Draw handles
DrawLine(curve.P1, curve.C1, blue);
DrawLine(curve.P2, curve.C2, blue);
```

1.  最后，绘制样条线：

```cpp
// Draw the actual curve
// Resolution is 200 steps since last point is i + 1
for (int i = 0; i < 199; ++i) {
    float t0 = (float)i / 199.0f;
    float t1 = (float)(i + 1) / 199.0f;
    vec3 thisPoint = Interpolate(curve, t0);
    vec3 nextPoint = Interpolate(curve, t1);
    DrawLine(thisPoint, nextPoint, magenta);
}
```

在前面的示例代码中，您可以看到可以通过使用六次线性插值来实现 Bézier`Interpolate`函数。要理解 Bézier 样条的工作原理，您需要将`lerp`函数扩展到实际情况。线性插值，`lerp(a, b, t)`，扩展为`(1-t) * a + t * b`：

1.  重写`Interpolate`函数，以便展开所有的`lerp`调用：

```cpp
template<typename T>
inline T Interpolate(const Bezier<T>& curve, float t) {
    T A = curve.P1 * (1.0f - t) + curve.C1 * t;
    T B = curve.C2 * (1.0f - t) + curve.P2 * t;
    T C = curve.C1 * (1.0f - t) + curve.C2 * t;
    T D = A * (1.0f - t) + C * t;
    T E = C * (1.0f - t) + B * t;
    T R = D * (1.0f - t) + E * t;
    return R;
}
```

1.  没有改变，但您不再需要调用`lerp`函数。只要定义了`T operator*(const T& t, float f)`，这对于任何数据类型`T`都适用。让我们试着在数学上简化这个。不要使用`A`、`B`、`C`、`D`、`E`和`R`变量，将这些方程展开为以下形式：

```cpp
((P1 * (1 - t) + C1 * t) * (1 - t) + (C1 * (1 - t) 
+ C2 * t) * t) * (1 - t) + ((C1 * (1 - t) + C2 * t) 
* (1 - t) + (C2 * (1 - t) + P2 * t) * t) * t
```

1.  这相当于手动内联所有的`lerp`函数。结果代码有点难以阅读：

```cpp
template<typename T>
inline T Interpolate(const Bezier<T>& c, float t) {
   return 
     ((c.P1 * (1.0f - t) + c.C1 * t) * (1.0f - t) + 
     (c.C1 * (1.0f - t) + c.C2 * t) * t) * (1.0f - t) 
     + ((c.C1 * (1.0f - t) + c.C2 * t) * (1.0f - t) + 
     (c.C2 * (1.0f - t) + c.P2 * t) * t) * t;
}
```

1.  为什么要费这么大劲？为了开始简化数学，让我们从合并类似项开始：

```cpp
-P1t3 + 3P1t2 - 3P1t + P1 + 3C1t3 - 6C1t2 + 3C1t - 3C2t3 + 3C2t2 + P2t3
```

1.  现在这开始看起来像一个方程了！这个简化的方程也可以用代码表示：

```cpp
template<typename T>
inline T Interpolate(const Bezier<T>& curve, float t) {
    return
        curve.P1 * (t * t * t) * -1.0f +
        curve.P1 * 3.0f * (t * t) -
        curve.P1 * 3.0f * t +
        curve.P1 +
        curve.C1 * 3.0f * (t * t * t) -
        curve.C1 * 6.0f * (t * t) +
        curve.C1 * 3.0f * t -
        curve.C2 * 3.0f * (t * t * t) +
        curve.C2 * 3.0f * (t * t) +
        curve.P2 * (t * t * t);
}
```

1.  通过隔离一些项来进一步简化这个简化：

```cpp
P1( -t3 + 3t2 - 3t + 1) +
C1( 3t3 - 6t2 + 3t)+
C2(-3t3 + 3t2)+
P2(  t3)
```

1.  在代码中，这表示为：

```cpp
template<typename T>
inline T Interpolate(const Bezier<T>& c, float t) {
    float ttt = t * t * t;
    float tt = t * t;
    return 
    c.P1 * (-1.0f * ttt + 3.0f * tt - 3.0f * t + 1.0f) +
    c.C1 * (3.0f * ttt - 6.0f * tt + 3.0f * t) +
    c.C2 * (-3.0f * ttt + 3.0f * tt) +
    c.P2 * ttt;
}
```

1.  再次简化函数：

```cpp
P1((1-t)3) +
C1(3(1-t)2t) +
C2(3(1-t)t2) +
P2(t3)
```

1.  最终简化的代码如下所示：

```cpp
template<typename T>
inline T Interpolate(const Bezier<T>& curve, float t) {
    return curve.P1 * ((1 - t) * (1 - t) * (1 - t)) +
            curve.C1 * (3.0f * ((1 - t) * (1 - t)) * t) +
            curve.C2 * (3.0f * (1 - t) * (t * t)) +
            curve.P2 *(t * t * t);
}
```

如果将这些最终方程用*t*从`0`到`1`绘制出来，您将得到以下图形：

![图 8.6：Bézier 样条的基础函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.6_B16191.jpg)

图 8.6：Bézier 样条的基础函数

这些是三次 Bézier 样条的点基础函数。它们表达了样条值随时间的变化。例如，P1 的影响随时间减小；在*t=0*时，影响是完整的—它的值为 1。然而，到了*t=1*，P1 的影响消失了—它的值为 0。

在本节中，您经历了简化 Bézier 样条评估函数的练习，以得到样条的基础函数。对于 Bézier 样条，很容易遵循这种逻辑，因为您可以从一个易于理解的实现开始，该实现只使用六个 lerp 函数。对于其他曲线，没有一个容易的起点。

在下一节中，我们将探讨另一种三次样条——三次 Hermite 样条。使用本节学到的知识，您将能够仅使用基础函数图实现 Hermite 评估函数。

# 理解三次 Hermite 样条

在游戏动画中最常用的样条类型是**三次 Hermite 样条**。与 Bézier 不同，Hermite 样条不使用空间中的点作为控制点；相反，它使用样条上的点的切线。您仍然有四个值，就像 Bézier 样条一样，但它们的解释方式不同。

对于 Hermite 样条，您不是有两个点和两个控制点；相反，您有两个点和两个斜率。这些斜率也被称为切线—在本章的其余部分，斜率和切线术语将互换使用。Hermite 样条的点基础函数如下所示：

![图 8.7：Hermite 样条的点基础函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.7_B16191.jpg)

图 8.7：Hermite 样条的点基础函数

当给定点基础函数时，您可以实现类似于实现 Bézier 插值函数的样条评估函数：

```cpp
template<typename T>
T Hermite(float t, T& p1, T& s1, T& p2, T& s2) {
   return 
      p1 * ((1.0f + 2.0f * t) * ((1.0f - t) * (1.0f - t))) +
      s1 * (t * ((1.0f - t) * (1.0f - t))) +
      p2 * ((t * t) * (3.0f - 2.0f * t)) +
      s2 * ((t * t) * (t - 1.0f));
}
```

可以在 Bézier 和 Hermite 样条之间切换，但这超出了您需要了解的动画范围。一些 3D 内容创建应用程序，如 Maya，允许动画师使用 Hermite 样条创建动画，而其他应用程序，如 Blender 3D，使用 Bézier 曲线。

了解这些函数的工作原理是有用的，无论哪种函数驱动您的动画系统。当然，还有更多的曲线类型，但 Bézier 和 Hermite 是最常见的。

glTF 文件格式支持常数、线性和三次插值类型。您刚刚学会了如何进行三次插值，但仍需要实现常数和线性插值。

# 插值类型

通常，在定义动画曲线时，遵循三种插值方法之一——常数、线性或三次。三次曲线可以使用任何三次方程来表示，例如 Bézier 曲线（Blender 使用的方法）或 Hermite 样条线（Maya 使用的方法）。本书使用 Hermite 样条线来表示三次曲线。

**常数曲线**保持其值不变，直到下一个关键帧。有时，这种类型的曲线被称为阶跃曲线。在视觉上，常数曲线如下所示：

![图 8.8：常数曲线](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.8_B16191.jpg)

图 8.8：常数曲线

**线性曲线**以线性方式在两个帧之间进行插值（即直线）。正如您之前在采样曲线近似示例中看到的那样，如果线性轨迹的样本足够接近，它也可以开始近似其他类型的曲线。线性曲线如下所示：

![图 8.9：线性曲线](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.9_B16191.jpg)

图 8.9：线性曲线

**三次曲线**允许您根据值和切线定义曲线。三次曲线的好处是您可以用很少的数据表示复杂的曲线。缺点是插值变得有点昂贵。三次曲线如下所示（切线是从关键帧出来的线）：

![图 8.10：三次曲线](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.10_B16191.jpg)

图 8.10：三次曲线

插值类型可以表示为简单的`enum`类。创建一个新文件—`Interpolation.h`。添加头文件保护并添加以下`enum`类声明：

```cpp
enum class Interpolation { 
    Constant, 
    Linear, 
    Cubic 
};
```

这也是 glTF 支持的三种插值类型。在下一节中，您将开始通过创建`Frame`结构来存储关键帧数据来实现动画轨迹。

# 创建 Frame 结构

数据帧是什么？这取决于插值类型。如果插值是常数（阶跃）或线性的，则帧只是时间和值。当插值为三次时，您还需要存储切线。

Hermite 曲线是通过连接 Hermite 样条线制成的。每个控制点由时间、值、入射切线和出射切线组成。如果使用控制点与其前面的点进行评估，则使用入射切线。如果使用控制点与其后面的点进行评估，则使用出射切线。

帧中存储的时间值是标量的，但数据和切线呢？这些值应该是标量、矢量还是四元数？要做出这个决定，您必须考虑如何将一组帧组织成曲线。

有两种选择策略。您可以创建一个标量曲线对象，其中数据和切线是标量值。然后，当您需要一个矢量曲线时，可以将几个标量曲线对象组合成一个矢量曲线对象。

具有标量轨道并从中合成高阶轨道的优势在于矢量或四元数曲线的每个分量可以以不同的方式进行插值。它还可以节省内存，因为曲线的每个分量可以具有不同数量的帧。缺点是额外的实现工作。

另一种策略是使用专门的帧和曲线类型，例如标量帧、矢量帧和四元数帧。同样，您可以创建单独的类来表示标量曲线、矢量曲线和四元数曲线。

使用专门的帧和曲线的优势在于其易于实现。您可以利用使用模板来避免编写重复的代码。glTF 文件也以这种方式存储动画轨迹。缺点是内存；曲线的每个分量都需要具有相同数量的关键帧。

在本书中，你将实现显式帧和曲线（轨迹）。`Frame`类将包含时间、值和入射和出射切线。如果插值类型不需要切线，你可以简单地忽略它们。帧可以是任意大小（如标量、二维向量、三维向量、四元数等）。它包含的时间始终是标量，但值和切线长度可以是任何值：

1.  创建一个新文件`Frame.h`。将`Frame`类的声明添加到这个新文件中。`Frame`类需要值和入射和出射切线的数组，以及一个时间标量。使用模板来指定每个帧的大小：

```cpp
template<unsigned int N>
class Frame {
public:
    float mValue[N];
    float mIn[N];
    float mOut[N];
    float mTime;
};
```

1.  为常见的帧类型创建`typedef`数据类型：

```cpp
typedef Frame<1> ScalarFrame;
typedef Frame<3> VectorFrame;
typedef Frame<4> QuaternionFrame;
```

你刚刚实现的`Frame`类用于存储动画轨迹中的关键帧。动画轨迹是关键帧的集合。在下一节中，你将学习如何实现`Track`类。

# 创建 Track 类

`Track`类是一组帧。对轨迹进行插值返回轨迹的数据类型；结果是轨迹在特定时间点上定义的曲线上的值。轨迹必须至少有两个帧进行插值。

如*创建 Frame 结构*部分所述，通过遵循本书中的示例，你将实现显式的帧和轨迹类型。将为标量、向量和四元数轨迹创建单独的类。这些类是模板的，以避免编写重复的代码。例如，`vec3`轨迹包含`Frame<3>`类型的帧。

因为轨迹有一个明确的类型，所以你不能在`vec3`轨迹的*X*分量中创建关键帧，而不同时为*Y*和*Z*分量添加关键帧。

这可能会占用更多的内存，如果你有一个不变的组件。例如，注意在下图中，*Z*组件有许多帧，即使它是一条直线，两个应该足够了。这并不是一个很大的折衷；所占用的额外内存是微不足道的：

![图 8.11：vec3 轨迹的组件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_8.11_B16191.jpg)

图 8.11：vec3 轨迹的组件

对于蒙皮网格渲染，动画轨迹总是对关节变换进行动画。然而，动画轨迹也可以用于在游戏中动画其他值，比如光的强度或在二维精灵之间切换以产生翻书效果。在下一节中，你将创建一个新的头文件并开始声明实际的`Track`类。

## 声明 Track 类

轨迹是一组帧。`Frame`类是模板的，所以`Track`类也需要是模板的。`Track`类需要两个模板参数——第一个是类型（预期是`float`、`vec3`、`quat`等），另一个是类型包含的组件数：

1.  `Track`类只需要两个成员——帧的向量和插值类型。创建一个新文件`Track.h`，并将`Track`类的声明添加到这个文件中：

```cpp
template<typename T, int N>
class Track {
protected:
    std::vector<Frame<N>> mFrames;
    Interpolation mInterpolation;
```

1.  `Track`类只需要一个默认构造函数来初始化`mInterpolation`变量。生成的复制构造函数、赋值运算符和析构函数都很好：

```cpp
public:
    Track();
```

1.  为轨迹的帧数、插值类型以及起始和结束时间创建获取器和设置器函数：

```cpp
    void Resize(unsigned int size);
    unsigned int Size();
    Interpolation GetInterpolation();
    void SetInterpolation(Interpolation interp);
    float GetStartTime();
    float GetEndTime();
```

1.  `Track`类需要一种在给定时间采样轨迹的方法。这个`Sample`方法应该接受一个时间值和轨迹是否循环的参数。重载`[]运算符`以检索帧的引用：

```cpp
    T Sample(float time, bool looping);
    Frame<N>& operator[](unsigned int index);
```

1.  接下来，你需要声明一些辅助函数。轨迹可以是常量、线性或立方体。只需要一个`Sample`函数来处理这三种情况。不要创建一个庞大、难以阅读的函数，为每种插值类型创建一个辅助函数：

```cpp
protected:
    T SampleConstant(float time, bool looping);
    T SampleLinear(float time, bool looping);
    T SampleCubic(float time, bool looping);
```

1.  添加一个辅助函数来评估 Hermite 样条：

```cpp
    T Hermite(float time, const T& p1, const T& s1, 
              const T& p2, const T& s2);
```

1.  添加一个函数来检索给定时间的帧索引。这是请求的时间之前的最后一帧。另外，添加一个辅助函数，该函数接受轨道范围之外的输入时间，并将其调整为轨道上的有效时间：

```cpp
    int FrameIndex(float time, bool looping);
    float AdjustTimeToFitTrack(float t, bool loop);
```

1.  您需要一种将浮点数组（帧内的数据）转换为轨道模板类型的方法。该函数针对每种类型的轨道进行了专门化：

```cpp
    T Cast(float* value); // Will be specialized
};
```

1.  与`Frame`类一样，为常见的`Track`类型添加`typedef`数据类型：

```cpp
typedef Track<float, 1> ScalarTrack;
typedef Track<vec3, 3> VectorTrack;
typedef Track<quat, 4> QuaternionTrack;
```

`Track`类的 API 很小，这使得该类易于使用。但是，`Track`类存在许多隐藏的复杂性；毕竟，这个类是您正在构建的动画系统的核心。在下一节中，您将开始实现实际的`Track`类。

## 实现 Track 类

`Track`类是模板化的，但不打算在动画系统之外使用。在`Track.cpp`中为`float`、`vec3`和`quat`轨道添加模板定义。这样做可以使编译器在 CPP 文件中生成这些模板的代码：

```cpp
template Track<float, 1>;
template Track<vec3, 3>;
template Track<quat, 4>;
```

对于角色动画，`vec3`和`quat`轨道类型就足够了。如果需要添加新类型的轨道，请不要忘记将模板类型添加到`Track.cpp`文件中。在接下来的部分中，您将开始实现加载轨道数据的辅助函数。

### 实现辅助函数

`Track`类是模板化的，以避免为所有轨道类型编写重复的代码。但是，某些功能需要特定于`Track`类的类型。除了`Cast`函数之外，所有特定于类型的函数都驻留在一个新的命名空间`TrackHelpers`中。

这些辅助函数不是`Track`类的一部分；它们依赖于函数重载，以确保调用正确版本的辅助函数。这些辅助类的关键职责之一是确保四元数被归一化并处于正确的邻域。因为这段代码插值四元数，所以邻域是一个关注点：

1.  要使轨道进行线性插值，您需要为每种轨道类型创建插值函数。在`Track.cpp`中添加以下辅助函数，为轨道可能包含的每种数据类型提供正确的插值方法。这些函数属于`TrackHelpers`命名空间。

```cpp
namespace TrackHelpers {
   inline float Interpolate(float a, float b, float t) {
       return a + (b - a) * t;
   }
   inline vec3 Interpolate(const vec3& a, const vec3& b,
                           float t) {
       return lerp(a, b, t);
   }
   inline quat Interpolate(const quat& a, const quat& b,
                           float t) {
       quat result = mix(a, b, t);
       if (dot(a, b) < 0) { // Neighborhood
           result = mix(a, -b, t);
       }
       return normalized(result); //NLerp, not slerp
   }
```

1.  当插值 Hermite 样条时，如果输入类型是四元数，则结果需要被归一化。您可以创建仅归一化四元数的辅助函数，而不是提供 Hermite 函数的四元数规范：

```cpp
   inline float AdjustHermiteResult(float f) {
      return f;
   }
   inline vec3 AdjustHermiteResult(const vec3& v) {
      return v;
   }
   inline quat AdjustHermiteResult(const quat& q) {
      return normalized(q);
   }
```

1.  还需要一个常见的`Neighborhood`操作，以确保两个四元数处于正确的邻域。该函数对其他数据类型应该不做任何操作：

```cpp
   inline void Neighborhood(const float& a, float& b){}
   inline void Neighborhood(const vec3& a, vec3& b){}
   inline void Neighborhood(const quat& a, quat& b) {
      if (dot(a, b) < 0) {
         b = -b;
      }
   }
}; // End Track Helpers namespace
```

这些辅助函数存在的原因是为了避免制作插值函数的专门版本。相反，通用插值函数调用这些辅助方法，并且函数重载确保调用正确的函数。这意味着如果添加新类型的轨道，则需要添加新的辅助函数。在下一节中，您将开始实现一些`Track`函数。

### 实现 Track 函数

在本节中，您将开始实现`Track`类的成员函数。`Track`类有几个不重要的函数，要么需要调用辅助函数，要么只是获取器和设置器函数。首先使用这些函数开始实现`Track`类：

1.  `Track`构造函数需要设置轨道的插值类型。轨道的开始和结束时间的获取器和设置器函数很简单：

```cpp
template<typename T, int N>
Track<T, N>::Track() {
    mInterpolation = Interpolation::Linear;
}
template<typename T, int N>
float Track<T, N>::GetStartTime() {
    return mFrames[0].mTime;
}
template<typename T, int N>
float Track<T, N>::GetEndTime() {
    return mFrames[mFrames.size() - 1].mTime;
}
```

1.  `Sample`函数需要调用`SampleConstant`、`SampleLinear`或`SampleCubic`，具体取决于轨道类型。`[]` `operator`返回对指定帧的引用：

```cpp
template<typename T, int N>
T Track<T, N>::Sample(float time, bool looping) {
    if (mInterpolation == Interpolation::Constant) {
        return SampleConstant(time, looping);
    }
    else if (mInterpolation == Interpolation::Linear) {
        return SampleLinear(time, looping);
    }
    return SampleCubic(time, looping);
}
template<typename T, int N>
Frame<N>& Track<T, N>::operator[](unsigned int index) {
    return mFrames[index];
}
```

1.  `Resize`和`Size`函数是围绕帧向量的大小的简单获取器和设置器：

```cpp
template<typename T, int N>
void Track<T, N>::Resize(unsigned int size) {
    mFrames.resize(size);
}
template<typename T, int N>
unsigned int Track<T, N>::Size() {
    return mFrames.size();
}
```

1.  轨道的插值类型也有简单的获取器和设置器函数：

```cpp
template<typename T, int N>
Interpolation Track<T, N>::GetInterpolation() {
    return mInterpolation;
}
template<typename T, int N>
void Track<T, N>::SetInterpolation(Interpolation interpolation) {
    mInterpolation = interpolation;
}
```

1.  `Hermite`函数实现了本章*理解三次 Hermite 样条*部分涵盖的基本函数。第二点可能需要通过`Neighborhood`辅助函数取反。四元数也需要被归一化。邻域化和归一化都是由辅助函数执行的：

```cpp
template<typename T, int N>
T Track<T, N>::Hermite(float t, const T& p1, const T& s1,
                       const T& _p2, const T& s2) {
    float tt = t * t;
    float ttt = tt * t;
    T p2 = _p2;
    TrackHelpers::Neighborhood(p1, p2);
    float h1 = 2.0f * ttt - 3.0f * tt + 1.0f;
    float h2 = -2.0f * ttt + 3.0f * tt;
    float h3 = ttt - 2.0f * tt + t;
    float h4 = ttt - tt;
    T result = p1 * h1 + p2 * h2 + s1 * h3 + s2 * h4;
    return TrackHelpers::AdjustHermiteResult(result);
}
```

在接下来的几节中，您将实现`Track`类的一些更难的函数，从`FrameIndex`函数开始。

### 实现`FrameIndex`函数

`FrameIndex`函数以时间作为参数；它应该返回该时间之前的帧（在左侧）。这种行为取决于轨道是否打算循环采样。按照以下步骤实现`FrameIndex`函数：

1.  如果轨道只有一帧或更少，那么它是无效的。如果遇到无效的轨道，返回`-1`：

```cpp
template<typename T, int N>
int Track<T, N>::FrameIndex(float time, bool looping) {
    unsigned int size = (unsigned int)mFrames.size();
    if (size <= 1) {
        return -1;
    }
```

1.  如果轨道被循环采样，输入时间需要调整，使其落在起始和结束帧之间。这意味着您需要知道轨道第一帧的时间、轨道帧的时间和轨道的持续时间：

```cpp
    if (looping) {
        float startTime = mFrames[0].mTime;
        float endTime = mFrames[size - 1].mTime;
        float duration = endTime - startTime;
```

1.  由于轨道循环，`time`需要调整，使其在有效范围内。为此，通过从起始时间中减去`time`并将结果与持续时间取模来使`time`相对于持续时间。如果`time`为负数，则加上持续时间。不要忘记将起始时间加回`time`中：

```cpp
        time = fmodf(time - startTime, 
                     endTime - startTime);
        if (time < 0.0f) {
            time += endTime - startTime;
        }
        time = time + startTime;
    }
```

1.  如果轨道不循环，任何小于起始帧的`time`值应该被夹到`0`，任何大于倒数第二帧的`time`值应该被夹到倒数第二帧的索引：

```cpp
    else {
        if (time <= mFrames[0].mTime) {
            return 0;
        }
        if (time >= mFrames[size - 2].mTime) {
            return (int)size - 2;
        }
    }
```

1.  现在时间在有效范围内，循环遍历每一帧。最接近时间的帧（但仍然较小）是应该返回的帧的索引。可以通过向后循环遍历轨道的帧并返回第一个时间小于查找时间的索引来找到这一帧：

```cpp
    for (int i = (int)size - 1; i >= 0; --i) {
        if (time >= mFrames[i].mTime) {
            return i;
        }
    }
    // Invalid code, we should not reach here!
    return -1;
} // End of FrameIndex
```

如果一个轨道不循环并且时间大于最后一帧的时间，则使用倒数第二帧的索引。为什么使用倒数第二帧而不是最后一帧？`Sample`函数总是需要当前帧和下一帧，下一帧是通过将`FrameIndex`函数的结果加`1`来找到的。当`time`等于最后一帧的时间时，需要插值的两帧仍然是倒数第二帧和最后一帧。

在下一节中，您将实现`AdjustTimeToFitTrack`函数。这个函数用于确保任何采样的时间都有一个有效的值。有效的值是指在轨道的起始时间和结束时间之间的任何时间。

### 实现`AdjustTimeToFitTrack`函数

要实现的下一个函数是`AdjustTimeToFitTrack`。给定一个时间，这个函数需要调整时间，使其落在轨道的起始/结束帧的范围内。当然，这取决于轨道是否循环。按照以下步骤实现`AdjustTimeToFitTrack`函数：

1.  如果一个轨道少于一帧，那么这个轨道是无效的。如果使用了无效的轨道，返回`0`：

```cpp
template<typename T, int N>
float Track<T, N>::AdjustTimeToFitTrack(float time, 
                                        bool looping) {
    unsigned int size = (unsigned int)mFrames.size();
    if (size <= 1) { 
        return 0.0f; 
    }
```

1.  找到轨道的起始时间、结束时间和持续时间。起始时间是第一帧的时间，结束时间是最后一帧的时间，持续时间是两者之间的差异。如果轨道持续时间为`0`，则无效——返回`0`：

```cpp
    float startTime = mFrames[0].mTime;
    float endTime = mFrames[size - 1].mTime;
    float duration = endTime - startTime;
    if (duration <= 0.0f) { 
        return 0.0f; 
    }
```

1.  如果轨道循环，通过轨道的持续时间调整时间：

```cpp
    if (looping) {
        time = fmodf(time - startTime, 
                     endTime - startTime);
        if (time < 0.0f) {
            time += endTime - startTime;
        }
        time = time + startTime;
    }
```

1.  如果轨道不循环，将时间夹到第一帧或最后一帧。返回调整后的时间：

```cpp
    else {
        if (time <= mFrames[0].mTime) { 
            time = startTime;  
        }
        if (time >= mFrames[size - 1].mTime) { 
            time = endTime; 
        }
    }
    return time;
}
```

`AdjustTimeToFitTrack`函数很有用，因为它保持了动画采样时间在范围内。这个函数旨在在动画播放时间改变时调用。考虑以下例子：

```cpp
Track<float, 1> t;
float mAnimTime = 0.0f;
void Update(float dt) { // dt: delta time of frame
    mAnimTime = t. AdjustTimeToFitTrack (mAnimTime + dt);
}
```

在示例中每次调用`Update`函数时，`mAnimTime`变量都会增加`frame`的`deltaTime`。然而，由于增加的时间在分配之前传递给`AdjustTimeToFitTrack`，因此它永远不会有无效的动画时间值。

在接下来的部分中，您将实现`Track`类的`Cast`函数。`Cast`函数用于接受一个浮点数组，并将其转换为`Track`类的模板类型。

### 实现 Cast 函数

`Cast`函数是专门的；需要为每种类型的轨迹提供一个实现。`Cast`函数接受一个浮点数组，并返回`Track`类的模板类型`T`。支持的类型有`float`、`vec3`和`quat`：

```cpp
template<> float Track<float, 1>::Cast(float* value) {
    return value[0];
}
template<> vec3 Track<vec3, 3>::Cast(float* value) {
    return vec3(value[0], value[1], value[2]);
}
template<> quat Track<quat, 4>::Cast(float* value) {
    quat r = quat(value[0], value[1], value[2], value[3]);
    return normalized(r);
}
```

这个`Cast`函数很重要，因为它可以将存储在`Frame`类中的`float`数组转换为`Frame`类表示的数据类型。例如，`Frame<3>`被转换为`vec3`。在接下来的部分中，您将使用`Cast`函数来返回采样`Track`类时的正确数据类型。

### 常量轨迹采样

在本节中，您将为`Track`类实现三个采样函数中的第一个——`FrameIndex`辅助函数。确保帧是有效的，然后将该帧的值转换为正确的数据类型并返回：

```cpp
template<typename T, int N>
T Track<T, N>::SampleConstant(float t, bool loop) {
    int frame = FrameIndex(t, loop);
    if (frame < 0 || frame >= (int)mFrames.size()) {
        return T();
    }
    return Cast(&mFrames[frame].mValue[0]);
}
```

常量采样通常用于诸如可见标志之类的东西，其中一个变量的值从一帧到下一帧的变化没有任何实际的插值是有意义的。在接下来的部分中，您将学习如何实现线性轨迹采样。线性采样非常常见；大多数内容创建应用程序提供了一个“采样”导出选项，可以导出线性插值的轨迹。

### 线性轨迹采样

第二种采样类型，`FrameIndex`函数，你永远不应该处于当前帧是轨迹的最后一帧且下一帧无效的情况。

一旦你知道了当前帧、下一帧以及它们之间的时间差，你就可以进行插值。调用`AdjustTimeToFitTrack`确保时间有效，从第一帧的时间中减去它，并将结果除以帧间隔。这将得到插值值`t`。

知道插值值后，调用`TrackHelpers::Interpolate`函数进行插值：

```cpp
template<typename T, int N>
T Track<T, N>::SampleLinear(float time, bool looping) {
    int thisFrame = FrameIndex(time, looping);
    if (thisFrame < 0 || thisFrame >= mFrames.size() - 1) {
        return T();
    }
    int nextFrame = thisFrame + 1;
    float trackTime = AdjustTimeToFitTrack(time, looping);
    float thisTime = mFrames[thisFrame].mTime;
    float frameDelta = mFrames[nextFrame].mTime – thisTime;
    if (frameDelta <= 0.0f) {
        return T();
    }
    float t = (trackTime - thisTime) / frameDelta;
    T start = Cast(&mFrames[thisFrame].mValue[0]);
    T end = Cast(&mFrames[nextFrame].mValue[0]);
    return TrackHelpers::Interpolate(start, end, t);
}
```

线性采样通常用于许多 3D 内容创建应用程序，这些应用程序提供了一个选项，可以通过在固定间隔处对动画曲线进行采样来近似。在接下来的部分中，您将学习如何进行曲线的三次插值。三次插值存储的数据比线性插值少，但计算成本更高。

### 三次轨迹采样

最后一种采样类型，`Hermite`辅助函数进行插值。

如果你把`time`想象成轨道上的播放头，它在第一个点的右边和第二个点的左边。因此，你需要第一个点的外斜率（因为播放头正在远离它），以及第二个点的内斜率（因为播放头正在朝向它）。两个斜率都需要乘以帧间隔：

```cpp
template<typename T, int N>
T Track<T, N>::SampleCubic(float time, bool looping) {
    int thisFrame = FrameIndex(time, looping);
    if (thisFrame < 0 || thisFrame >= mFrames.size() - 1) {
        return T();
    }
    int nextFrame = thisFrame + 1;
    float trackTime = AdjustTimeToFitTrack(time, looping);
    float thisTime = mFrames[thisFrame].mTime;
    float frameDelta = mFrames[nextFrame].mTime - thisTime;
    if (frameDelta <= 0.0f) {
        return T();
    }
    float t = (trackTime - thisTime) / frameDelta;
    size_t fltSize = sizeof(float);
    T point1 = Cast(&mFrames[thisFrame].mValue[0]);
    T slope1;// = mFrames[thisFrame].mOut * frameDelta;
    memcpy(&slope1, mFrames[thisFrame].mOut, N * fltSize);
    slope1 = slope1 * frameDelta;
    T point2 = Cast(&mFrames[nextFrame].mValue[0]);
    T slope2;// = mFrames[nextFrame].mIn[0] * frameDelta;
    memcpy(&slope2, mFrames[nextFrame].mIn, N * fltSize);
    slope2 = slope2 * frameDelta;
    return Hermite(t, point1, slope1, point2, slope2);
}
```

为什么斜率使用`memcpy`而不是`Cast`函数？这是因为`Cast`函数会对四元数进行归一化，这是不好的，因为斜率不应该是四元数。使用`memcpy`而不是`Cast`直接复制值，避免了归一化。

在下一节中，您将学习如何将矢量和四元数轨迹合并成一个`TransformTrack`。实际的动画框架将在`TransformTrack`类上工作，这些类将不是模板化的。

# 创建 TransformTrack 类

对于任何动画变换，您不希望维护单独的向量和四元数轨道；相反，您构建一个更高级的结构——变换轨道。变换轨道封装了三个轨道——一个用于位置，一个用于旋转，一个用于缩放。您可以在任何点对变换轨道进行采样，并获得完整的变换，即使组件轨道的持续时间或开始时间不同。

要考虑的一件事是如何将这些变换轨道与动画模型相关联。模型的骨架包含几个骨骼。您可以存储一个变换轨道的向量——每个骨骼一个——或者您可以将骨骼 ID 添加为变换轨道的成员，并且只存储所需数量的骨骼。

这很重要，因为一个角色可能有很多骨骼，但并非所有动画都会对所有这些骨骼进行动画。如果为每个骨骼存储一个变换轨道，会浪费内存，但对动画进行采样会更快。如果只存储所需数量的变换轨道，采样会变得更昂贵，但内存消耗会减少。

实现选择往往最终成为内存与速度之间的权衡。在现代系统上，任一轴上的增量应该是微不足道的。在本节中，您将为变换轨道添加一个骨骼 ID，并且只存储所需数量的轨道。

## 声明 TransformTrack 类

`TransformTrack`类将需要保存一个表示轨道将影响哪个骨骼（关节）的整数。它还需要实际的位置、旋转和缩放轨道。这四个信息应该足以对关节的位置、旋转和缩放进行动画。

与`Track`类一样，`TransformTrack`类有获取和设置变换轨道的开始和结束时间的函数。变换轨道的开始和结束时间取决于其组件轨道。组件轨道是位置、旋转和缩放轨道。

在三个轨道中，最低的开始时间被用作变换轨道的开始时间。三个轨道中最大的结束时间被用作变换轨道的结束时间。

变换轨道中的不是所有组件轨道都需要有效。例如，如果只有变换的位置是动画的，那么旋转和缩放组件轨道可以保持无效。只要其组件轨道中至少有一个有效，变换轨道就是有效的。

因为不是所有组件轨道都保证有效，`TransformTrack`类的`Sample`函数需要获取一个引用变换。采取以下步骤声明`TransformTrack`类：

1.  创建一个新文件`TransformTrack.h`，并开始通过定义成员变量来添加`TransformTrack`的定义：

```cpp
class TransformTrack {
protected:
    unsigned int mId;
    VectorTrack mPosition;
    QuaternionTrack mRotation;
    VectorTrack mScale;
```

1.  公共 API 很简单。您需要默认构造函数来为轨道的关节 ID 分配默认值。您还需要获取 ID、组件轨道、开始/结束时间、持续时间和有效性的函数，以及 ID 需要一个设置函数；组件获取函数返回可变引用：

```cpp
public:
    TransformTrack();
    unsigned int GetId();
    void SetId(unsigned int id);
    VectorTrack& GetPositionTrack();
    QuaternionTrack& GetRotationTrack();
    VectorTrack& GetScaleTrack();
    float GetStartTime();
    float GetEndTime();
    bool IsValid();
    Transform Sample(const Transform& ref, float time, bool looping);
};
```

在下一节中，您将开始实现`TransfromTrack`的函数。

## 实现 TransformTrack 类

按照以下步骤实现`TransformTrack`类：

1.  创建一个新文件`TransformTrack.cpp`，以实现`TransformTrack`类。`TransformTrack`类的构造函数并不重要；为变换轨道表示的关节分配一个默认值。轨道 ID 的获取和设置函数也很简单：

```cpp
TransformTrack::TransformTrack() {
    mId = 0;
}
unsigned int TransformTrack::GetId() {
    return mId;
}
void TransformTrack::SetId(unsigned int id) {
    mId = id;
}
```

1.  接下来，实现函数来访问存储在变换轨道中的不同组件轨道。这些函数需要返回一个引用，以便您可以改变返回的轨道：

```cpp
VectorTrack& TransformTrack::GetPositionTrack() {
    return mPosition;
}
QuaternionTrack& TransformTrack::GetRotationTrack() {
    return mRotation;
}
VectorTrack& TransformTrack::GetScaleTrack() {
    return mScale;
}
```

1.  `IsValid`辅助函数只有在存储在`TransformTrack`类中的组件轨道中至少有一个有效时才应返回`true`。要使轨道有效，需要有两个或更多帧：

```cpp
bool TransformTrack::IsValid() {
    return mPosition.Size() > 1 || 
           mRotation.Size() > 1 || 
           mScale.Size() > 1;
}
```

1.  `GetStartTime`函数应该返回三个组件轨道中最小的开始时间。如果没有一个组件是有效的（即它们都只有一个或没有帧），那么`TransformTrack`就无效。在这种情况下，只需返回`0`：

```cpp
float TransformTrack::GetStartTime() {
    float result = 0.0f;
    bool isSet = false;
    if (mPosition.Size() > 1) {
        result = mPosition.GetStartTime();
        isSet = true;
    }
    if (mRotation.Size() > 1) {
        float rotationStart = mRotation.GetStartTime();
        if (rotationStart < result || !isSet) {
            result = rotationStart;
            isSet = true;
        }
    }
    if (mScale.Size() > 1) {
        float scaleStart = mScale.GetStartTime();
        if (scaleStart < result || !isSet) {
            result = scaleStart;
            isSet = true;
        }
    }
    return result;
}
```

1.  `GetEndTime`函数类似于`GetStartTime`函数。唯一的区别是这个函数寻找最大的轨道结束时间：

```cpp
float TransformTrack::GetEndTime() {
    float result = 0.0f;
    bool isSet = false;
    if (mPosition.Size() > 1) {
        result = mPosition.GetEndTime();
        isSet = true;
    }
    if (mRotation.Size() > 1) {
        float rotationEnd = mRotation.GetEndTime();
        if (rotationEnd > result || !isSet) {
            result = rotationEnd;
            isSet = true;
        }
    }
    if (mScale.Size() > 1) {
        float scaleEnd = mScale.GetEndTime();
        if (scaleEnd > result || !isSet) {
            result = scaleEnd;
            isSet = true;
        }
    }
    return result;
}
```

1.  `Sample`函数只在其组件轨道有两个或更多帧时对其进行采样。由于`TransformTrack`类只能对一个组件进行动画，比如位置，因此这个函数需要将一个参考变换作为参数。如果变换轨道没有对其中一个变换组件进行动画，那么将使用参考变换的值：

```cpp
Transform TransformTrack::Sample(const Transform& ref,
                              float time, bool loop) {
    Transform result = ref; // Assign default values
    if (mPosition.Size() > 1) { // Only if valid
       result.position = mPosition.Sample(time, loop);
    }
    if (mRotation.Size() > 1) { // Only if valid
       result.rotation = mRotation.Sample(time, loop);
    }
    if (mScale.Size() > 1) { // Only if valid
       result.scale = mScale.Sample(time, loop);
    }
    return result;
}
```

因为并非所有动画都包含相同的轨道，重置正在采样的姿势是很重要的。这可以确保参考变换始终是正确的。要重置姿势，将其分配为与休息姿势相同。

# 总结

在本章中，您了解了动画的基本组件，一个数据帧中包含什么，几个帧如何组成一个轨道，以及几个轨道如何使一个变换发生动画。您探索了不同的插值方法，用于插值动画轨道，并使这些方法适用于标量、向量和四元数轨道。

本章中构建的类将作为下一章中创建动画剪辑的基本组件。在下一章中，您将实现动画剪辑和姿势。动画剪辑将由`TransformTrack`对象组成。这些轨道是现代动画系统的核心。

本书的可下载内容的`Chapter08`文件夹中有两个示例。`Sample00`包含到目前为止在书中使用的所有代码，`Sample01`创建了几个轨道并将它们全部绘制在屏幕上。在视觉上绘制轨道是一个好主意，因为它可以帮助及早解决调试问题。
